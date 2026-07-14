//! Local WireGuard key custody + trust-anchor pinning.

use std::path::Path;

use anyhow::{bail, Context};
use common::crypto::{gen_wg_keypair, wg_public_from_private, WgPrivateKey, WgPublicKey};
use common::rotation::walk_chain;
use common::wire::Signed;

/// Load the persisted WG keypair, or generate + persist one (0600).
pub fn load_or_generate_keypair(state_dir: &Path) -> anyhow::Result<(WgPrivateKey, WgPublicKey)> {
    std::fs::create_dir_all(state_dir)?;
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

/// Pin the coordinator's anchor on first sight. On a later change, accept it only if the rotation
/// chain proves a signed path from our pinned anchor to the new one (design.md §9); otherwise
/// refuse (possible MITM, or a key lost past recovery → the operator must have the user re-pin).
pub fn pin_anchor(
    state_dir: &Path,
    anchor: &[u8; 32],
    rotation_chain: &[String],
) -> anyhow::Result<()> {
    let path = state_dir.join("anchor.pub");
    let Ok(existing) = std::fs::read(&path) else {
        std::fs::write(&path, anchor)?;
        tracing::info!("pinned coordinator trust anchor");
        return Ok(());
    };
    let pinned: [u8; 32] = existing
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("pinned anchor file is not 32 bytes"))?;
    if pinned == *anchor {
        return Ok(());
    }
    // Anchor changed: follow the rotation chain. A malformed cert simply can't advance the walk.
    let chain: Vec<Signed> = rotation_chain
        .iter()
        .filter_map(|c| Signed::from_base64(c).ok())
        .collect();
    if walk_chain(pinned, *anchor, &chain) {
        std::fs::write(&path, anchor)?;
        tracing::warn!("coordinator anchor rotated — re-pinned via rotation chain");
        Ok(())
    } else {
        bail!("coordinator trust anchor changed with no valid rotation path — refusing (possible MITM)");
    }
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

fn write_secret(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
