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
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{guild_id}.pub"));
    let Ok(existing) = std::fs::read(&path) else {
        std::fs::write(&path, anchor)?;
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
        std::fs::write(&path, anchor)?;
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

/// Every pinned guild anchor's bytes. Used where the signing guild isn't known up front — the
/// release manifest is signed by one guild key the caller holds, so the verifier tries each pin.
pub fn load_all_anchors(state_dir: &Path) -> Vec<[u8; 32]> {
    let Ok(entries) = std::fs::read_dir(state_dir.join("anchors")) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| std::fs::read(e.path()).ok())
        .filter_map(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
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
    std::fs::create_dir_all(state_dir)?;
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

fn write_secret(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
