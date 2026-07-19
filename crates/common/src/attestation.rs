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

/// Attestation wire layouts. The signed payload is postcard — positional, not self-describing — so
/// a build can only decode a blob if it knows which layout produced it. Which one is in play is
/// carried **outside** the signature, in `api::GuildAttestation::att_schema`, because that envelope
/// is JSON and can gain a field compatibly; guessing from the postcard bytes cannot be made
/// unambiguous (a small `guild_id`, as fake/test configs use, is indistinguishable from a leading
/// schema tag).
///
/// - `0` = **V1**, the original layout, no tag. What every released client reads.
/// - `1` = **V2**, `schema`-first, so a future layout change is a clean rejection rather than a
///   silent misparse.
///
/// **Rollout (phase 1 of 2).** Clients read both from this release; the coordinator still signs V1
/// only, because a v0.2.0 client handed a V2 blob fails to decode it — its own grant *and* every
/// peer — and peers with nobody. Emission flips to V2 in the release where
/// [`crate::MIN_PROTOCOL_VERSION`] reaches 5, by which point every supported client can read it.
pub const ATTESTATION_SCHEMA_V1: u32 = 0;
pub const ATTESTATION_SCHEMA_V2: u32 = 1;

/// The layout the coordinator signs for a client that has **not** claimed it can read anything
/// newer — i.e. the floor, and what every released client gets. A client advertising
/// [`crate::caps::ATTESTATION_V2`] is served V2 instead.
///
/// Moving this to V2 is the phase-2 step, valid only once the support floor excludes every release
/// that lacked the capability; `coordinator_still_emits_the_layout_old_clients_read` and
/// `a_v0_2_0_client_can_still_read_what_we_emit_by_default` both fail if it moves early.
pub const ATTESTATION_SCHEMA_EMIT: u32 = ATTESTATION_SCHEMA_V1;

/// V2 wire form: identical to [`Attestation`] with a leading schema tag. Private to this module —
/// callers work with `Attestation` and pass a layout, so the tag never leaks into domain code.
#[derive(Serialize, Deserialize)]
struct AttestationV2 {
    schema: u32,
    guild_id: u64,
    user_id: u64,
    username: String,
    device_name: String,
    is_primary: bool,
    wg_ip: Ipv4Addr,
    wg_net: Ipv4Net,
    wg_pubkey: [u8; 32],
    issued_at: u64,
    expires_at: u64,
}

impl From<AttestationV2> for Attestation {
    fn from(v: AttestationV2) -> Self {
        Attestation {
            guild_id: v.guild_id,
            user_id: v.user_id,
            username: v.username,
            device_name: v.device_name,
            is_primary: v.is_primary,
            wg_ip: v.wg_ip,
            wg_net: v.wg_net,
            wg_pubkey: v.wg_pubkey,
            issued_at: v.issued_at,
            expires_at: v.expires_at,
        }
    }
}

impl AttestationV2 {
    fn from_att(a: &Attestation) -> Self {
        AttestationV2 {
            schema: ATTESTATION_SCHEMA_V2,
            guild_id: a.guild_id,
            user_id: a.user_id,
            username: a.username.clone(),
            device_name: a.device_name.clone(),
            is_primary: a.is_primary,
            wg_ip: a.wg_ip,
            wg_net: a.wg_net,
            wg_pubkey: a.wg_pubkey,
            issued_at: a.issued_at,
            expires_at: a.expires_at,
        }
    }
}

/// Sign `att` in the given wire layout (see [`ATTESTATION_SCHEMA_V1`]).
pub fn sign_attestation(
    key: &crate::crypto::CoordinatorKey,
    att: &Attestation,
    schema: u32,
) -> Result<Signed, AttestationError> {
    match schema {
        ATTESTATION_SCHEMA_V1 => Ok(Signed::sign(key, att)?),
        ATTESTATION_SCHEMA_V2 => Ok(Signed::sign(key, &AttestationV2::from_att(att))?),
        other => Err(AttestationError::UnknownSchema { got: other }),
    }
}

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
/// `schema` names the wire layout the blob was signed in, from
/// [`api::GuildAttestation::att_schema`](crate::api::GuildAttestation) — the sender tells us, we
/// never guess (see [`ATTESTATION_SCHEMA_V1`]). An unknown layout is refused rather than attempted:
/// a signature proves the bytes are authentic, not that we'd read them the way the signer wrote them.
pub fn verify_attestation(
    signed: &Signed,
    anchor: &VerifyingKey,
    now: u64,
    expected_guild: u64,
    schema: u32,
) -> Result<Attestation, AttestationError> {
    let att: Attestation = match schema {
        ATTESTATION_SCHEMA_V1 => signed.verify(anchor)?,
        ATTESTATION_SCHEMA_V2 => {
            let v2: AttestationV2 = signed.verify(anchor)?;
            if v2.schema != ATTESTATION_SCHEMA_V2 {
                // The envelope said V2 but the signed bytes disagree — the two are out of step, so
                // we can't trust which layout we just decoded.
                return Err(AttestationError::SchemaMismatch {
                    expected: ATTESTATION_SCHEMA_V2,
                    got: v2.schema,
                });
            }
            v2.into()
        }
        other => return Err(AttestationError::UnknownSchema { got: other }),
    };
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
    #[error("attestation schema {got} disagrees with its envelope (expected {expected})")]
    SchemaMismatch { expected: u32, got: u32 },
    #[error("attestation wire layout {got} is not one this build reads (peer version skew)")]
    UnknownSchema { got: u32 },
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
        let att =
            verify_attestation(&signed, &key.anchor(), now, GUILD, ATTESTATION_SCHEMA_V1).unwrap();
        assert_eq!(att.username, "alice");
    }

    #[test]
    fn expired_attestation_rejected() {
        let key = CoordinatorKey::generate();
        let now = 1_000;
        let signed = Signed::sign(&key, &sample(now)).unwrap();
        let later = now + crate::ATTESTATION_TTL_SECS + 1;
        assert!(matches!(
            verify_attestation(&signed, &key.anchor(), later, GUILD, ATTESTATION_SCHEMA_V1),
            Err(AttestationError::Expired)
        ));
    }

    #[test]
    fn both_layouts_verify_when_the_envelope_names_them() {
        let key = CoordinatorKey::generate();
        let now = 1_000;
        for schema in [ATTESTATION_SCHEMA_V1, ATTESTATION_SCHEMA_V2] {
            let signed = sign_attestation(&key, &sample(now), schema).unwrap();
            let att = verify_attestation(&signed, &key.anchor(), now, GUILD, schema).unwrap();
            assert_eq!(att.username, "alice", "layout {schema}");
            assert_eq!(att.wg_ip, Ipv4Addr::new(100, 64, 42, 7), "layout {schema}");
        }
    }

    /// The reason the layout hint lives outside the signature. A V2 blob read as V1 (or the reverse)
    /// must fail, not silently produce an attestation with shifted values — which is exactly what
    /// postcard's positional encoding does if you guess wrong.
    #[test]
    fn reading_a_blob_in_the_wrong_layout_fails() {
        let key = CoordinatorKey::generate();
        let now = 1_000;

        let v2 = sign_attestation(&key, &sample(now), ATTESTATION_SCHEMA_V2).unwrap();
        assert!(
            verify_attestation(&v2, &key.anchor(), now, GUILD, ATTESTATION_SCHEMA_V1).is_err(),
            "a V2 blob must not decode as V1"
        );

        let v1 = sign_attestation(&key, &sample(now), ATTESTATION_SCHEMA_V1).unwrap();
        assert!(
            verify_attestation(&v1, &key.anchor(), now, GUILD, ATTESTATION_SCHEMA_V2).is_err(),
            "a V1 blob must not decode as V2"
        );
    }

    #[test]
    fn unknown_layout_is_refused_not_attempted() {
        // A future coordinator's layout: authentic signature, but we have no idea how to read it.
        // Refusing beats decoding it as something we do know and trusting the result.
        let key = CoordinatorKey::generate();
        let now = 1_000;
        let signed = sign_attestation(&key, &sample(now), ATTESTATION_SCHEMA_V1).unwrap();
        assert!(matches!(
            verify_attestation(&signed, &key.anchor(), now, GUILD, 99),
            Err(AttestationError::UnknownSchema { got: 99 })
        ));
        assert!(matches!(
            sign_attestation(&key, &sample(now), 99),
            Err(AttestationError::UnknownSchema { got: 99 })
        ));
    }

    /// The compatibility guarantee this release rests on: what the coordinator actually emits must
    /// stay the layout every already-released client can read. Flipping `ATTESTATION_SCHEMA_EMIT`
    /// before the support floor reaches 5 strands every v0.2.0 client — it decodes neither its own
    /// grant nor any peer, and silently peers with nobody.
    /// A v0.2.0 client's struct, byte-for-byte as that release shipped it. Frozen on purpose: it is
    /// the oracle for "can a client already in the field still read what we emit?".
    #[derive(Serialize, Deserialize)]
    struct V0_2_0Attestation {
        guild_id: u64,
        user_id: u64,
        username: String,
        device_name: String,
        is_primary: bool,
        wg_ip: Ipv4Addr,
        wg_net: Ipv4Net,
        wg_pubkey: [u8; 32],
        issued_at: u64,
        expires_at: u64,
    }

    /// The regression test for the bug this design exists to prevent: a released client decoding a
    /// blob signed by a *newer* coordinator. It reads the postcard bytes with its own field list and
    /// ignores the envelope hint entirely, so the only thing keeping it working is that we still emit
    /// the layout it knows. Signing V2 by default failed exactly here — `DeserializeUnexpectedEnd` —
    /// and a real v0.2.0 client would have meshed with nobody while reporting no error.
    #[test]
    fn a_v0_2_0_client_can_still_read_what_we_emit_by_default() {
        let key = CoordinatorKey::generate();
        let now = 1_000;
        let signed = sign_attestation(&key, &sample(now), ATTESTATION_SCHEMA_EMIT).unwrap();
        let old: V0_2_0Attestation = signed
            .verify(&key.anchor())
            .expect("a released client must still decode the default emitted layout");
        assert_eq!(old.username, "alice");
        assert_eq!(old.guild_id, GUILD);
        assert_eq!(old.wg_ip, Ipv4Addr::new(100, 64, 42, 7));
    }

    #[test]
    fn coordinator_still_emits_the_layout_old_clients_read() {
        assert_eq!(
            ATTESTATION_SCHEMA_EMIT, ATTESTATION_SCHEMA_V1,
            "only flip this once MIN_PROTOCOL_VERSION excludes every release without \
             caps::ATTESTATION_V2 — until then a client that advertises nothing still needs V1"
        );
    }

    #[test]
    fn wrong_guild_rejected() {
        // An attestation scoped to GUILD, verified as if for another guild, is refused even though
        // the signature and TTL are valid — the guild_id check is load-bearing (§4.1).
        let key = CoordinatorKey::generate();
        let now = 1_000;
        let signed = Signed::sign(&key, &sample(now)).unwrap();
        assert!(matches!(
            verify_attestation(&signed, &key.anchor(), now, GUILD + 1, ATTESTATION_SCHEMA_V1),
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
            verify_attestation(&signed, &other.anchor(), now, GUILD, ATTESTATION_SCHEMA_V1),
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
