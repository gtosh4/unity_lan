//! Local WireGuard key custody + trust-anchor pinning.

use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context};
use common::crypto::{gen_wg_keypair, wg_public_from_private, WgPrivateKey, WgPublicKey};
use common::rotation::walk_chain;
use common::wire::Signed;

/// Create `dir` (and any missing parents) and restrict it to the owner. On unix the directory is set
/// to 0700, tightening it even if it already existed at a looser mode — the state dir holds the WG
/// private key, device token, relay secret, and pinned anchors, none of which any other local user
/// should be able to list or read. Windows inherits the service profile's ACLs. Best-effort on the
/// permission step so a filesystem that can't represent the mode (rare) doesn't block startup.
///
/// An existing group-execute bit is preserved: the control socket defaults to living *inside* the
/// state dir, and `control::grant_dir_traversal` sets `root:<control_group>` 0710 so a frontend can
/// reach it. Clearing that bit here would revoke the grant the next time any state file is written
/// (the relay secret is created per enrollment), silently cutting off the GUI. Group-execute alone
/// grants traversal to a named path, not listing — and every secret in the dir is 0600.
pub fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    // Whether the dir predates this call. A dir we create ourselves gets `0777 & ~umask` from mkdir,
    // which usually carries a group-execute bit that means nothing — only a bit found on an existing
    // dir can be the deliberate grant below.
    #[cfg(unix)]
    let existed = dir.is_dir();
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let traverse = if existed {
            std::fs::metadata(dir)
                .map(|m| m.permissions().mode() & 0o010)
                .unwrap_or(0)
        } else {
            0
        };
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700 | traverse))
            .with_context(|| format!("restricting permissions on {}", dir.display()))?;
    }
    Ok(())
}

/// Load the persisted WG keypair, or generate + persist one (0600).
pub fn load_or_generate_keypair(state_dir: &Path) -> anyhow::Result<(WgPrivateKey, WgPublicKey)> {
    create_private_dir(state_dir)?;
    let priv_path = state_dir.join("wg.key");
    let priv_bytes: [u8; 32] = if priv_path.exists() {
        std::fs::read(&priv_path)?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("wg.key is not 32 bytes"))?
    } else {
        let (priv_k, _pub_k) = gen_wg_keypair();
        write_secret(&priv_path, &priv_k)?;
        priv_k
    };
    Ok((priv_bytes, wg_public_from_private(&priv_bytes)))
}

/// Pin one guild's anchor on first sight (design.md §3.1: keys are per-guild). On a later change,
/// accept it only if that guild's rotation chain proves a signed path from our pinned anchor to the
/// new one (§9); otherwise refuse (possible MITM, or a key lost past recovery → re-pin manually).
pub fn pin_anchor(
    state_dir: &Path,
    guild_id: u64,
    anchor: &[u8; 32],
    rotation_chain: &[String],
) -> anyhow::Result<()> {
    let dir = state_dir.join("anchors");
    create_private_dir(&dir)?;
    let path = dir.join(format!("{guild_id}.pub"));
    let Ok(existing) = std::fs::read(&path) else {
        write_private_atomic(&path, anchor)?;
        tracing::info!(guild_id, "pinned guild trust anchor");
        return Ok(());
    };
    let pinned: [u8; 32] = existing
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("pinned anchor file for guild {guild_id} is not 32 bytes"))?;
    if pinned == *anchor {
        return Ok(());
    }
    // Anchor changed: follow this guild's rotation chain. A malformed cert can't advance the walk.
    let chain: Vec<Signed> = rotation_chain
        .iter()
        .filter_map(|c| Signed::from_base64(c).ok())
        .collect();
    if walk_chain(pinned, *anchor, &chain) {
        write_private_atomic(&path, anchor)?;
        tracing::warn!(
            guild_id,
            "guild anchor rotated — re-pinned via rotation chain"
        );
        Ok(())
    } else {
        bail!("guild {guild_id} trust anchor changed with no valid rotation path — refusing (possible MITM)");
    }
}

/// Load a guild's pinned anchor bytes. Errors if that guild is unpinned or corrupt. Every response
/// is gated through [`pin_anchor`] before we verify any attestation, so by the time we verify a
/// grant/seed the pin exists and this is the key we verify against — never the response's anchor.
pub fn load_anchor(state_dir: &Path, guild_id: u64) -> anyhow::Result<[u8; 32]> {
    let path = state_dir.join("anchors").join(format!("{guild_id}.pub"));
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading pinned anchor for guild {guild_id}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("pinned anchor file for guild {guild_id} is not 32 bytes"))
}

/// Every pinned `(guild_id, anchor)`, the guild id parsed from the `{guild_id}.pub` filename. Used to
/// verify an attestation whose signing guild isn't known from a coordinator response — a peer-direct
/// (p2p) pull, where `verify_against_pinned` needs the guild id to bind the signature.
pub fn load_all_pinned(state_dir: &Path) -> Vec<(u64, [u8; 32])> {
    let Ok(entries) = std::fs::read_dir(state_dir.join("anchors")) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            let guild_id: u64 = path.file_stem()?.to_str()?.parse().ok()?;
            let anchor = <[u8; 32]>::try_from(std::fs::read(&path).ok()?.as_slice()).ok()?;
            Some((guild_id, anchor))
        })
        .collect()
}

/// Load the persisted device token, if any.
pub fn load_token(state_dir: &Path) -> Option<String> {
    std::fs::read_to_string(state_dir.join("token"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Persist the device token (0600) when the coordinator issues one.
pub fn save_token(state_dir: &Path, token: &str) -> anyhow::Result<()> {
    write_secret(&state_dir.join("token"), token.as_bytes())
}

/// Load this device's persisted relay HMAC secret, generating and persisting one (0600) on first
/// use. Stable across restarts so a re-registering relay keeps validating credentials the
/// coordinator already minted against it.
pub fn load_or_create_relay_secret(state_dir: &Path) -> anyhow::Result<String> {
    let path = state_dir.join("relay_secret");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return Ok(s);
        }
    }
    create_private_dir(state_dir)?;
    let secret = common::relay::generate_secret();
    write_secret(&path, secret.as_bytes())?;
    Ok(secret)
}

/// Discard local enrollment on logout: delete the device token and the WG private key, so the next
/// enrollment generates a *fresh* key (the old one is never reused). The pinned coordinator anchor
/// is kept — logging out doesn't change who we trust. Missing files are not an error.
pub fn clear_enrollment(state_dir: &Path) -> anyhow::Result<()> {
    for name in ["token", "wg.key"] {
        match std::fs::remove_file(state_dir.join(name)) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context(format!("removing {name}")),
        }
    }
    Ok(())
}

/// Wipe *all* local engine state — WG key, token, pinned anchors, relay secret, and local settings —
/// by removing the state dir. Unlike [`clear_enrollment`] (logout, keeps the pinned anchors), this
/// is the "forget me" path for `uninstall --purge` / a package purge: nothing about this device's
/// identity or trust survives. A missing dir is not an error.
pub fn purge_state(state_dir: &Path) -> anyhow::Result<()> {
    match std::fs::remove_dir_all(state_dir) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context(format!("wiping state dir {}", state_dir.display())),
    }
}

fn write_secret(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    write_private_atomic(path, bytes)
}

/// Atomically replace `path` with a regular owner-only file. The temporary file is created beside
/// the destination so rename stays atomic; restrictive permissions are installed before any secret
/// bytes are written, and rename replaces a destination symlink rather than following it.
fn write_private_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("secret");
    let mut opened = None;
    for _ in 0..16 {
        let tmp = parent.join(format!(
            ".{stem}.{}.tmp",
            common::crypto::gen_enrollment_key()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&tmp) {
            Ok(file) => {
                opened = Some((tmp, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("creating {}", tmp.display())),
        }
    }
    let (tmp, mut file) = opened.context("could not allocate a unique secret temporary file")?;

    let result = (|| -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        common::winsec::restrict_to_owner(&tmp)
            .with_context(|| format!("restricting permissions on {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        install_private_file(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(unix)]
fn install_private_file(tmp: &Path, path: &Path) -> anyhow::Result<()> {
    std::fs::rename(tmp, path)
        .with_context(|| format!("installing private file {}", path.display()))
}

#[cfg(windows)]
fn install_private_file(tmp: &Path, path: &Path) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let wide = |p: &Path| {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
    };
    let from = wide(tmp);
    let to = wide(path);
    // SAFETY: both pointers reference live, NUL-terminated UTF-16 buffers for the duration of the
    // call. MOVEFILE_REPLACE_EXISTING atomically replaces an existing file rather than following it.
    let ok = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("installing private file {}", path.display()));
    }
    Ok(())
}

// Unix-only: the sole test here exercises symlink/permission behavior that doesn't apply on Windows.
// Gating the whole module (not just the test) keeps `use super::*` from reading as an unused import on
// Windows, where `clippy -D warnings` would otherwise fail.
#[cfg(all(test, unix))]
mod security_tests {
    use super::*;

    #[test]
    fn private_dir_tightens_but_keeps_the_control_traversal_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "unitylan-private-dir-{}-{}",
            std::process::id(),
            common::crypto::gen_enrollment_key()
        ));
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        // A fresh dir is owner-only.
        create_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);

        // A dir left group/world-readable is tightened back down — every read and list bit goes,
        // including the group's; only its traversal bit is spared (see below).
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o710);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o744)).unwrap();
        create_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);

        // But the traversal bit `grant_dir_traversal` sets survives, or writing any state file
        // (e.g. the per-enrollment relay secret) would revoke the frontend's path to the socket.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o710)).unwrap();
        create_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o710);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn private_write_is_owner_only_and_replaces_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = std::env::temp_dir().join(format!(
            "unitylan-secret-write-{}-{}",
            std::process::id(),
            common::crypto::gen_enrollment_key()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"unchanged").unwrap();
        let secret = dir.join("token");
        symlink(&victim, &secret).unwrap();

        write_secret(&secret, b"private").unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"unchanged");
        assert_eq!(std::fs::read(&secret).unwrap(), b"private");
        assert_eq!(
            std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
