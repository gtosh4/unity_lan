//! Signed release manifest for the auto-update path (design phase 3).
//!
//! The coordinator signs a [`ReleaseManifest`] with its trust anchor — the same Ed25519 key that
//! signs attestations, so there is **no new trust root** — and hands it to clients on the long-poll
//! ([`crate::api::RegisterResp::release`]). A client verifies it against its pinned anchor, then
//! offers the update only when the manifest names a strictly-newer version *and* carries an artifact
//! for the client's own platform. The artifact's SHA-256 is bound into the signed manifest, so the
//! (large) artifact itself can be fetched over plain HTTPS from any host and still be proven to be
//! exactly what the anchor blessed — the coordinator never carries the bytes.

use serde::{Deserialize, Serialize};

/// A target platform for a release artifact — one per artifact CI publishes.
///
/// Postcard (the signed-payload format) encodes this by variant index, so **only append** new
/// variants; reordering would break verification against already-signed manifests. The string names
/// are for the coordinator's TOML/JSON config only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// HTTPS URL to the artifact: a raw `unitylan-engine`(+`gui`) tarball on Linux, an `.msi` on
    /// Windows. Admin-controlled (it comes from the signed manifest), so not an SSRF vector.
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
    fn artifact_for_picks_matching_platform() {
        let m = manifest();
        assert_eq!(
            m.artifact_for(Platform::LinuxAmd64).unwrap().url,
            "https://example.test/unitylan-linux-amd64.tar.gz"
        );
        assert_eq!(m.artifact_for(Platform::WindowsAmd64).unwrap().size, 2048);
    }
}
