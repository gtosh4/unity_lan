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

use std::path::Path;

/// Restrict `path` to its owner + SYSTEM + Administrators, removing inherited access. No-op on
/// non-Windows targets.
#[cfg(windows)]
pub fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::process::Command;

    // Locale-independent well-known SIDs: NT AUTHORITY\SYSTEM and BUILTIN\Administrators — the
    // Windows analogue of "root can always read it" under a Unix 0600.
    let mut grants: Vec<String> = vec![
        "*S-1-5-18:(F)".to_string(),     // SYSTEM (the service identity)
        "*S-1-5-32-544:(F)".to_string(), // Administrators
    ];
    // Also keep the account that runs the process (and thus created the file) able to read it. For a
    // service running as LocalSystem this is already covered by SYSTEM above; for an interactive dev
    // run it's the logged-in user, who would otherwise be locked out once inheritance is stripped.
    if let Some(user) = std::env::var_os("USERNAME") {
        if !user.is_empty() {
            let principal = match std::env::var_os("USERDOMAIN") {
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
}
