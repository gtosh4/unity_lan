//! OS hardening for on-disk secret files.
//!
//! Unix callers restrict secrets with `chmod 0600` directly at each call site. This module is the
//! Windows counterpart: [`restrict_to_owner`] locks a freshly-created secret file down to its owner
//! plus the local superuser accounts (SYSTEM + Administrators) — the parallel to Unix's "owner +
//! root". Crucially it also **strips inherited ACEs**, so a secret written under a world-readable
//! parent (e.g. the service's state dir beneath `C:\ProgramData`, where files inherit `Users: Read`)
//! is not left group/world-readable. Used for the engine's WG private key, device token, and relay
//! secret, and the coordinator's signing-seed DB.
//!
//! On non-Windows this is a no-op — Unix call sites apply `0600` themselves and never call here.

use std::ffi::OsString;
use std::path::Path;

/// Restrict `path` to its owner + SYSTEM + Administrators, removing inherited access. No-op on
/// non-Windows targets.
#[cfg(windows)]
pub fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::process::Command;

    let grants = owner_grants(std::env::var_os("USERNAME"), std::env::var_os("USERDOMAIN"));

    // `/inheritance:r` drops inherited ACEs (the `Users: Read` a ProgramData file inherits);
    // `/grant:r` replaces any explicit ACE for each principal with exactly the one given; `/q`
    // suppresses the per-file success chatter.
    let mut cmd = Command::new("icacls");
    cmd.arg(path).arg("/inheritance:r").arg("/q");
    for g in &grants {
        cmd.arg("/grant:r").arg(g);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "icacls failed to restrict {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Build the `icacls /grant:r` principals for a restricted secret file.
///
/// Always grants the locale-independent well-known SIDs NT AUTHORITY\SYSTEM and BUILTIN\Administrators
/// — the Windows analogue of "root can always read it" under a Unix 0600. Then, so the account that
/// created the file isn't locked out once inheritance is stripped, it grants that account too — *unless*
/// it's a **machine account** (`USERNAME` ending in `$`, which is what a LocalSystem/LocalService/
/// NetworkService process reports). That case is deliberately skipped: it's already covered by the
/// SYSTEM SID, and on a non-domain (workgroup) machine the reported `WORKGROUP\<HOST>$` does not resolve
/// through `icacls` ("No mapping between account names and security IDs was done"), which would fail the
/// whole restriction and, in turn, every secret write the service makes. Kept pure (env passed in) so the
/// grant list is unit-testable without a real process identity.
#[cfg(windows)]
fn owner_grants(username: Option<OsString>, userdomain: Option<OsString>) -> Vec<String> {
    let mut grants: Vec<String> = vec![
        "*S-1-5-18:(F)".to_string(),     // SYSTEM (the service identity)
        "*S-1-5-32-544:(F)".to_string(), // Administrators
    ];
    if let Some(user) = username {
        // A machine account (`<HOST>$`) is the service-identity case: covered by SYSTEM above, and its
        // name doesn't resolve on a workgroup box — so don't add (and thus don't fail on) it.
        let is_machine_account = user.to_string_lossy().ends_with('$');
        if !user.is_empty() && !is_machine_account {
            let principal = match userdomain {
                Some(dom) if !dom.is_empty() => {
                    let mut p = dom;
                    p.push("\\");
                    p.push(&user);
                    p
                }
                _ => user,
            };
            let mut ace = principal;
            ace.push(":(F)");
            grants.push(ace.to_string_lossy().into_owned());
        }
    }
    grants
}

/// No-op on non-Windows: Unix call sites apply `chmod 0600` themselves.
#[cfg(not(windows))]
pub fn restrict_to_owner(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::process::Command;

    /// End-to-end on real `icacls`: after restriction the file must carry no inherited ACEs and no
    /// broad principal (Users / Everyone / Authenticated Users). Guards against arg-order or SID
    /// mistakes — `std::process::Command` passes `/inheritance:r` verbatim (no shell mangling).
    #[test]
    fn restrict_strips_inheritance_and_broad_access() {
        let dir = std::env::temp_dir().join(format!("unitylan-winsec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.key");
        std::fs::write(&path, b"topsecret").unwrap();

        restrict_to_owner(&path).expect("restrict_to_owner should succeed");

        let out = Command::new("icacls").arg(&path).output().unwrap();
        assert!(out.status.success(), "icacls query failed");
        let acl = String::from_utf8_lossy(&out.stdout);

        // No inherited ACEs survive (icacls marks inherited entries with "(I)").
        assert!(!acl.contains("(I)"), "inherited ACEs not stripped:\n{acl}");
        // No broad principal can read it. Anchor on the ACE `principal:(perms)` form so the check
        // can't be fooled by the file path itself (which contains "C:\Users\...").
        for broad in ["Everyone:(", "Users:(", "Authenticated Users:("] {
            assert!(!acl.contains(broad), "{broad} still has access:\n{acl}");
        }
        // SYSTEM must retain access (the service identity).
        assert!(acl.contains("SYSTEM"), "SYSTEM lost access:\n{acl}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // A LocalSystem service on a non-domain box reports USERNAME="<HOST>$", USERDOMAIN="WORKGROUP".
    // That name doesn't resolve through icacls, so the grant list must NOT include it — otherwise every
    // secret write the service makes (wg.key, token, relay secret) fails and the daemon exits.
    #[test]
    fn machine_account_grant_is_skipped() {
        let g = owner_grants(Some("DESKTOP-O699522$".into()), Some("WORKGROUP".into()));
        assert_eq!(
            g,
            vec!["*S-1-5-18:(F)".to_string(), "*S-1-5-32-544:(F)".to_string()],
            "machine account must not be added as a principal"
        );
        assert!(
            !g.iter().any(|s| s.contains('$')),
            "no unresolvable machine-account principal: {g:?}"
        );
    }

    // An interactive user is granted access (domain-qualified) so stripping inheritance doesn't lock
    // them out of a secret they created during a dev `run`.
    #[test]
    fn interactive_user_gets_domain_qualified_grant() {
        let g = owner_grants(Some("Gordon".into()), Some("DESKTOP-O699522".into()));
        assert!(
            g.contains(&"DESKTOP-O699522\\Gordon:(F)".to_string()),
            "interactive user grant missing: {g:?}"
        );
    }

    // With no USERDOMAIN we fall back to the bare user name rather than dropping the grant.
    #[test]
    fn user_without_domain_falls_back_to_bare_name() {
        let g = owner_grants(Some("Gordon".into()), None);
        assert!(
            g.contains(&"Gordon:(F)".to_string()),
            "bare-name grant missing: {g:?}"
        );
    }
}
