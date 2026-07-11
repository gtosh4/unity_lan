//! Local WireGuard key custody + trust-anchor pinning.

use std::path::Path;

use anyhow::{bail, Context};
use common::crypto::{gen_wg_keypair, wg_public_from_private, WgPrivateKey, WgPublicKey};

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

/// Pin the coordinator's anchor on first sight; reject if it later changes.
pub fn pin_anchor(state_dir: &Path, anchor: &[u8; 32]) -> anyhow::Result<()> {
    let path = state_dir.join("anchor.pub");
    if path.exists() {
        let existing = std::fs::read(&path).context("reading pinned anchor")?;
        if existing.as_slice() != anchor.as_slice() {
            bail!("coordinator trust anchor changed — refusing (possible MITM or key rotation)");
        }
    } else {
        std::fs::write(&path, anchor)?;
        tracing::info!("pinned coordinator trust anchor");
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
