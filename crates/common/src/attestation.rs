//! The attestation: the coordinator-signed unit of membership (design.md §4.1).
//!
//! Model B: the signed unit is a **device** — one WG key, one IP — not a per-network slot.
//! Which networks (ACL groups) a device belongs to gate *peering*, not addressing.

use std::net::Ipv4Addr;

use ed25519_dalek::VerifyingKey;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::wire::{Signed, WireError};
use crate::DNS_SUFFIX;

/// Binds a device (WG key + allocated IP) to its owner + name, for a TTL.
///
/// All signed fields are **stable** — the coordinator need not know a device's live endpoint
/// (that is reported separately, see design.md §4.2). `username`/`device_name` are already
/// sanitized to DNS labels by the coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// The guild (Discord server) this attestation is scoped to. Signed by that guild's own
    /// per-guild key (design.md §3.1), so a compromised/forged key's blast radius is one guild.
    /// The verifier checks this equals the guild it pinned the signing anchor for — load-bearing
    /// defence-in-depth against a cross-tenant signing bug (§4.1).
    pub guild_id: u64,
    /// Owner's Discord user id (snowflake).
    pub user_id: u64,
    /// Owner's global handle, sanitized to a DNS label (the `<user>` in a hostname).
    pub username: String,
    /// Per-user device label, sanitized to a DNS label (the `<device>` in a hostname).
    pub device_name: String,
    /// Whether this is the owner's primary device (gets the bare `<user>.unity.internal` alias).
    pub is_primary: bool,
    /// Coordinator-allocated `/32` for this device, within `wg_net`.
    pub wg_ip: Ipv4Addr,
    /// The deployment's mesh CIDR (`wg_ip` falls inside it). Signed so a client learns the range
    /// from anchor-verified data — a MITM can't claim the client's real LAN as the mesh range and
    /// hijack its traffic. Defaults to the CGNAT `/10`; a coordinator may narrow it (see
    /// `netid::default_cidr`). Every peer's attestation carries the same value.
    pub wg_net: Ipv4Net,
    /// Curve25519 WireGuard public key — the device identity.
    pub wg_pubkey: [u8; 32],
    /// When the coordinator signed this, in unix epoch seconds.
    pub issued_at: u64,
    /// When this attestation stops verifying, in unix epoch seconds (drives all TTL math).
    pub expires_at: u64,
}

impl Attestation {
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// `<device>.<user>.unity.internal`. The `unity` label is the coordinator's namespace; while we
    /// support a single coordinator it is fixed (see `DNS_SUFFIX`). The community/guild is **not** in
    /// the name — a device has one identity and one IP across all the coordinator's guilds it's in
    /// (Model B), so the community would be a redundant label on one machine. It rides on each shared
    /// network instead (`SharedNetwork`), where it's real signal.
    pub fn hostname(&self) -> String {
        format!("{}.{}.{}", self.device_name, self.username, DNS_SUFFIX)
    }

    /// `<user>.unity.internal` — the alias for the owner's primary device; `None` otherwise.
    pub fn primary_alias(&self) -> Option<String> {
        self.is_primary
            .then(|| format!("{}.{}", self.username, DNS_SUFFIX))
    }
}

/// Verify a signed attestation against the pinned anchor for `expected_guild`, and reject if
/// expired or scoped to a different guild. `anchor` must be the key the client pinned **for
/// `expected_guild`** (per-guild keys, design.md §3.1); the `guild_id` check is load-bearing even
/// so — defence in depth against a coordinator cross-signing guild A's member into guild B (§4.1).
pub fn verify_attestation(
    signed: &Signed,
    anchor: &VerifyingKey,
    now: u64,
    expected_guild: u64,
) -> Result<Attestation, AttestationError> {
    let att: Attestation = signed.verify(anchor)?;
    if att.guild_id != expected_guild {
        return Err(AttestationError::GuildMismatch {
            expected: expected_guild,
            got: att.guild_id,
        });
    }
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
    #[error("attestation guild mismatch: expected {expected}, got {got}")]
    GuildMismatch { expected: u64, got: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CoordinatorKey;

    const GUILD: u64 = 42;

    fn sample(now: u64) -> Attestation {
        Attestation {
            guild_id: GUILD,
            user_id: 333,
            username: "alice".into(),
            device_name: "laptop".into(),
            is_primary: true,
            wg_ip: Ipv4Addr::new(100, 64, 42, 7),
            wg_net: "100.64.0.0/10".parse().unwrap(),
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
        let att = verify_attestation(&signed, &key.anchor(), now, GUILD).unwrap();
        assert_eq!(att.username, "alice");
    }

    #[test]
    fn expired_attestation_rejected() {
        let key = CoordinatorKey::generate();
        let now = 1_000;
        let signed = Signed::sign(&key, &sample(now)).unwrap();
        let later = now + crate::ATTESTATION_TTL_SECS + 1;
        assert!(matches!(
            verify_attestation(&signed, &key.anchor(), later, GUILD),
            Err(AttestationError::Expired)
        ));
    }

    #[test]
    fn wrong_guild_rejected() {
        // An attestation scoped to GUILD, verified as if for another guild, is refused even though
        // the signature and TTL are valid — the guild_id check is load-bearing (§4.1).
        let key = CoordinatorKey::generate();
        let now = 1_000;
        let signed = Signed::sign(&key, &sample(now)).unwrap();
        assert!(matches!(
            verify_attestation(&signed, &key.anchor(), now, GUILD + 1),
            Err(AttestationError::GuildMismatch { expected, got })
                if expected == GUILD + 1 && got == GUILD
        ));
    }

    #[test]
    fn other_guild_key_rejected() {
        // A different guild's key cannot vouch for this guild's attestation — cross-tenant forgery
        // fails at the signature check (per-guild keys, §3.1).
        let key = CoordinatorKey::generate();
        let other = CoordinatorKey::generate();
        let now = 1_000;
        let signed = Signed::sign(&key, &sample(now)).unwrap();
        assert!(matches!(
            verify_attestation(&signed, &other.anchor(), now, GUILD),
            Err(AttestationError::Wire(_))
        ));
    }

    #[test]
    fn hostname_has_no_community() {
        let att = sample(0);
        assert_eq!(att.hostname(), "laptop.alice.unity.internal");
    }

    #[test]
    fn primary_alias_is_bare_user() {
        let att = sample(0); // sample() sets is_primary: true
        assert_eq!(att.primary_alias().as_deref(), Some("alice.unity.internal"));
    }
}
