//! Signed release manifest for the auto-update path (design phase 3).
//!
//! A [`ReleaseManifest`] is signed by the **dedicated release key** ([`release_pubkey`]) — a trust
//! root deliberately separate from the per-guild attestation keys, its private half held offline in
//! the release pipeline and never on a coordinator, so a leaked guild key can't sign a binary update.
//! The coordinator serves the pre-signed blob verbatim in [`crate::api::RegisterResp::release_signed`];
//! a client with the release key baked in verifies against it alone. A client offers the update only
//! when the manifest names a strictly-newer version *and* carries an artifact for its platform. The
//! artifact's SHA-256 is bound into the signed manifest, so the (large) artifact is fetched over plain
//! HTTPS from any host and still proven exactly what the key blessed — the coordinator never carries
//! the bytes.
//!
//! For the migration, the coordinator also still signs the manifest per-request under a **guild** key
//! the caller holds ([`crate::api::RegisterResp::release`]); a client with no release key baked in
//! (dev/CI) verifies that against its pinned anchor. That legacy path is what the release key exists
//! to replace and is retired once the fleet has the key baked in.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// The dedicated release-signing **public** key, baked into the binary at build time from the
/// `UNITYLAN_RELEASE_PUBKEY` env var (a 64-char hex Ed25519 public key). Its private half is held
/// **offline** by the release pipeline and never touches a coordinator — so a leaked *guild* signing
/// key can no longer sign a binary update (the update trust root is this key alone, not any pinned
/// guild anchor).
///
/// `None` in dev/CI builds where the var is unset: the auto-update path then falls back to the legacy
/// guild-anchor-signed manifest, so nothing here is load-bearing until a real release sets the var.
/// A malformed value yields `None` too — a build with a bad key just declines the strong path rather
/// than shipping an unverifiable one.
pub fn release_pubkey() -> Option<VerifyingKey> {
    let hex = option_env!("UNITYLAN_RELEASE_PUBKEY")?;
    let bytes = parse_hex32(hex)?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Parse exactly 64 hex chars into 32 bytes, or `None` on any malformed input.
fn parse_hex32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A target platform for a release artifact — one per artifact CI publishes.
///
/// Postcard (the signed-payload format) encodes this by variant index, so **only append** new
/// variants; reordering would break verification against already-signed manifests. The string names
/// are for the coordinator's TOML/JSON config only.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    #[serde(rename = "linux-amd64")]
    LinuxAmd64,
    #[serde(rename = "windows-amd64")]
    WindowsAmd64,
}

/// The platform this build runs on, or `None` on a target we publish no artifact for (in which case
/// no auto-update is offered — the client just shows the version notice).
pub fn current_platform() -> Option<Platform> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some(Platform::LinuxAmd64),
        ("windows", "x86_64") => Some(Platform::WindowsAmd64),
        _ => None,
    }
}

/// One downloadable artifact for a platform: where to fetch it and how to verify it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseArtifact {
    pub platform: Platform,
    /// HTTPS URL to the artifact: a `.tar.gz` bundle of `unitylan-engine`(+`gui`) on both Linux and
    /// Windows (the file-swap update), or on Windows a legacy `.msi` still accepted as a fallback.
    /// Admin-controlled (it comes from the signed manifest), so not an SSRF vector.
    pub url: String,
    /// SHA-256 of the artifact bytes, bound into the signed manifest and re-checked after download.
    pub sha256: [u8; 32],
    /// Artifact size in bytes — a sanity bound so a client can refuse an oversized download.
    pub size: u64,
}

/// A signed statement of the latest release and how to fetch it per platform. Transported as a
/// base64 [`crate::wire::Signed`] on [`crate::api::RegisterResp::release`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    /// The release version (semver). A client applies only when this is strictly newer than its own
    /// [`crate::VERSION`].
    pub version: String,
    pub artifacts: Vec<ReleaseArtifact>,
}

impl ReleaseManifest {
    /// The artifact for `platform`, if this manifest carries one.
    pub fn artifact_for(&self, platform: Platform) -> Option<&ReleaseArtifact> {
        self.artifacts.iter().find(|a| a.platform == platform)
    }
}

/// Decode the inner manifest of a base64 [`crate::wire::Signed`] release blob **without verifying**
/// its signature. Only for a coordinator to sanity-check a `signed_blob` it will serve verbatim — the
/// coordinator holds no release key, so it can't verify; the *client* does, against its baked-in key.
/// This is never a trust decision.
pub fn peek_signed_manifest(blob: &str) -> Result<ReleaseManifest, crate::wire::WireError> {
    let signed = crate::wire::Signed::from_base64(blob)?;
    Ok(postcard::from_bytes(&signed.payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CoordinatorKey;
    use crate::wire::Signed;

    fn manifest() -> ReleaseManifest {
        ReleaseManifest {
            version: "0.2.0".into(),
            artifacts: vec![
                ReleaseArtifact {
                    platform: Platform::LinuxAmd64,
                    url: "https://example.test/unitylan-linux-amd64.tar.gz".into(),
                    sha256: [1u8; 32],
                    size: 1024,
                },
                ReleaseArtifact {
                    platform: Platform::WindowsAmd64,
                    url: "https://example.test/unitylan.msi".into(),
                    sha256: [2u8; 32],
                    size: 2048,
                },
            ],
        }
    }

    #[test]
    fn manifest_signs_and_verifies_against_anchor() {
        let key = CoordinatorKey::generate();
        let m = manifest();
        let signed = Signed::sign(&key, &m).unwrap();
        let out: ReleaseManifest = signed.verify(&key.anchor()).unwrap();
        assert_eq!(m, out);
    }

    #[test]
    fn manifest_from_a_different_anchor_is_rejected() {
        let key = CoordinatorKey::generate();
        let attacker = CoordinatorKey::generate();
        let signed = Signed::sign(&attacker, &manifest()).unwrap();
        // Verified against the pinned anchor (not the attacker's), it must fail.
        let out: Result<ReleaseManifest, _> = signed.verify(&key.anchor());
        assert!(out.is_err());
    }

    #[test]
    fn parse_hex32_roundtrips_and_rejects_malformed() {
        let key = CoordinatorKey::generate();
        let hex: String = key
            .anchor_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(parse_hex32(&hex), Some(key.anchor_bytes()));
        assert_eq!(parse_hex32(""), None);
        assert_eq!(parse_hex32("zz"), None);
        assert_eq!(parse_hex32(&hex[..62]), None); // too short
        assert_eq!(parse_hex32(&format!("{hex}00")), None); // too long
    }

    #[test]
    fn artifact_for_picks_matching_platform() {
        let m = manifest();
        assert_eq!(
            m.artifact_for(Platform::LinuxAmd64).unwrap().url,
            "https://example.test/unitylan-linux-amd64.tar.gz"
        );
        assert_eq!(m.artifact_for(Platform::WindowsAmd64).unwrap().size, 2048);
    }
}
