//! The attestation: the coordinator-signed unit of membership (design.md §4.1).

use std::net::Ipv4Addr;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::netid::sanitize_label;
use crate::wire::{Signed, WireError};
use crate::DNS_SUFFIX;

/// Binds an identity to a WireGuard key + allocated IP within a network (role), for a TTL.
///
/// The signed fields are all **stable** — the coordinator need not know a member's live
/// endpoint (that is gossiped separately, see design.md §4.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub guild_id: u64,
    /// The Discord role = the network.
    pub role_id: u64,
    pub user_id: u64,
    /// Guild nickname, already sanitized to a DNS label; unique within the network.
    pub nick: String,
    /// Coordinator-allocated /32 within the role's subnet.
    pub wg_ip: Ipv4Addr,
    /// Curve25519 WireGuard public key.
    pub wg_pubkey: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Attestation {
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// `<nick>.<role>.<guild>.internal`. Role/guild are passed in (their *names* live at the
    /// coordinator; only ids are in the attestation).
    pub fn hostname(&self, role_name: &str, guild_name: &str) -> String {
        format!(
            "{}.{}.{}.{}",
            self.nick,
            sanitize_label(role_name),
            sanitize_label(guild_name),
            DNS_SUFFIX,
        )
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
            guild_id: 111,
            role_id: 222,
            user_id: 333,
            nick: "alice".into(),
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
        assert_eq!(att.nick, "alice");
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
            att.hostname("Minecraft SMP", "My Community!"),
            "alice.minecraft-smp.my-community.internal"
        );
    }
}
