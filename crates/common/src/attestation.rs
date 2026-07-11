//! The attestation: the coordinator-signed unit of membership (design.md §4.1).
//!
//! Model B: the signed unit is a **device** — one WG key, one IP — not a per-network slot.
//! Which networks (ACL groups) a device belongs to gate *peering*, not addressing.

use std::net::Ipv4Addr;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::netid::sanitize_label;
use crate::wire::{Signed, WireError};
use crate::DNS_SUFFIX;

/// Binds a device (WG key + allocated IP) to its owner + name, for a TTL.
///
/// All signed fields are **stable** — the coordinator need not know a device's live endpoint
/// (that is reported separately, see design.md §4.2). `username`/`device_name` are already
/// sanitized to DNS labels by the coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub user_id: u64,
    /// Owner's global handle, sanitized to a DNS label (the `<user>` in a hostname).
    pub username: String,
    /// Per-user device label, sanitized to a DNS label (the `<device>` in a hostname).
    pub device_name: String,
    /// Whether this is the owner's primary device (gets the `<user>.<community>` alias).
    pub is_primary: bool,
    /// Coordinator-allocated `/32` for this device within 100.64.0.0/10.
    pub wg_ip: Ipv4Addr,
    /// Curve25519 WireGuard public key — the device identity.
    pub wg_pubkey: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Attestation {
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// `<device>.<user>.<community>.internal`. The community name lives at the coordinator and
    /// is passed in (only ids/labels are in the attestation).
    pub fn hostname(&self, community_name: &str) -> String {
        format!(
            "{}.{}.{}.{}",
            self.device_name,
            self.username,
            sanitize_label(community_name),
            DNS_SUFFIX,
        )
    }

    /// `<user>.<community>.internal` — the alias for the owner's primary device; `None` otherwise.
    pub fn primary_alias(&self, community_name: &str) -> Option<String> {
        self.is_primary.then(|| {
            format!(
                "{}.{}.{}",
                self.username,
                sanitize_label(community_name),
                DNS_SUFFIX,
            )
        })
    }
}

/// Verify a signed attestation against the pinned anchor and reject if expired.
pub fn verify_attestation(
    signed: &Signed,
    anchor: &VerifyingKey,
    now: u64,
) -> Result<Attestation, AttestationError> {
    let att: Attestation = signed.verify(anchor)?;
    if att.is_expired(now) {
        return Err(AttestationError::Expired);
    }
    Ok(att)
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("attestation expired")]
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CoordinatorKey;

    fn sample(now: u64) -> Attestation {
        Attestation {
            user_id: 333,
            username: "alice".into(),
            device_name: "laptop".into(),
            is_primary: true,
            wg_ip: Ipv4Addr::new(100, 64, 42, 7),
            wg_pubkey: [1u8; 32],
            issued_at: now,
            expires_at: now + crate::ATTESTATION_TTL_SECS,
        }
    }

    #[test]
    fn valid_attestation_verifies() {
        let key = CoordinatorKey::generate();
        let now = 1_000;
        let signed = Signed::sign(&key, &sample(now)).unwrap();
        let att = verify_attestation(&signed, &key.anchor(), now).unwrap();
        assert_eq!(att.username, "alice");
    }

    #[test]
    fn expired_attestation_rejected() {
        let key = CoordinatorKey::generate();
        let now = 1_000;
        let signed = Signed::sign(&key, &sample(now)).unwrap();
        let later = now + crate::ATTESTATION_TTL_SECS + 1;
        assert!(matches!(
            verify_attestation(&signed, &key.anchor(), later),
            Err(AttestationError::Expired)
        ));
    }

    #[test]
    fn hostname_is_sanitized() {
        let att = sample(0);
        assert_eq!(
            att.hostname("My Community!"),
            "laptop.alice.my-community.internal"
        );
    }
}
