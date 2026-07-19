//! Shared types, wire formats, crypto, and addressing math for UnityLAN.
//!
//! Used by both the coordinator and the client engine. Pure logic only — no network I/O.

pub mod api;
pub mod attestation;
pub mod control;
pub mod crypto;
pub mod netid;
pub mod p2p;
pub mod relay;
pub mod rotation;
pub mod update;
pub mod winsec;
pub mod wire;

use std::time::{SystemTime, UNIX_EPOCH};

/// Highest wire protocol version this build speaks. Bump on a **breaking** change to the
/// coordinator API — one that neither an additive `#[serde(default)]` field nor a capability flag
/// ([`CAPABILITIES`]) can keep compatible. Prefer a capability: a bump costs every client in the
/// mesh a coordinated upgrade, a flag costs nothing.
///
/// Sent as `RegisterReq::proto` (the client's ceiling) and echoed as `RegisterResp::proto` (the
/// version the coordinator **selected** for that exchange, not its own ceiling). A peer sending `0`
/// is pre-versioning and is served without negotiation.
pub const PROTOCOL_VERSION: u32 = 5;

/// Oldest wire protocol version this build still speaks — the floor of the support window.
///
/// Policy: **current + 1 previous**. Each bump moves this to the version being retired, so a client
/// always has one full release cycle to auto-update before a coordinator stops answering it. The
/// coordinator rejects a client whose whole range sits below this with `426 Upgrade Required`
/// rather than serving it a snapshot it will misread.
///
/// This is a promise that costs code: keeping it at `PROTOCOL_VERSION - 1` means every break needs
/// a shim that lets the previous version keep working, plus a golden fixture in `api.rs`'s tests
/// pinning that it still decodes. Don't lower it without writing those.
pub const MIN_PROTOCOL_VERSION: u32 = 4;

/// Named capability flags, exchanged as `RegisterReq::caps` / `RegisterResp::caps`.
///
/// These are how a feature ships **without** a protocol bump: each side advertises what it can do,
/// and the coordinator gates optional behavior on the client's set instead of on a version number.
/// That is what lets coordinator and clients upgrade on independent schedules — a bump is a flag
/// day, a flag is not.
///
/// Strings rather than an enum on purpose: an unknown capability from a newer peer is simply absent
/// from our set, never a decode failure. An empty set (an older client) means "infer from `proto`".
/// Only declare a capability that actually gates behavior — an aspirational list is worse than none.
pub mod caps {
    /// Client understands delta snapshots: it sends `RegisterReq::held` and honors
    /// `RegisterResp::partial` + `removed` instead of treating every response as a full peer list.
    pub const DELTA_SYNC: &str = "delta-sync";
    /// Client runs the userspace ICE agent and can use `Seed::ice` / report `RegisterReq::ice`.
    pub const ICE: &str = "ice";
    /// Client can use a TURN relay (`Seed::relay`) and report `RegisterReq::relay_allocated`.
    pub const RELAY: &str = "relay";
    /// Client serves and consumes peer-direct attestation pulls over the in-tunnel P2P channel
    /// (`docs/gossip-refresh.md`), so it can renew without the coordinator.
    pub const GOSSIP_PULL: &str = "gossip-pull";
}

/// Every capability this build implements — what we advertise on the wire.
pub const CAPABILITIES: &[&str] = &[caps::DELTA_SYNC, caps::ICE, caps::RELAY, caps::GOSSIP_PULL];

/// This build's release version (the shared workspace version, from Cargo). All crates ship from one
/// monorepo tag, so this is simultaneously the coordinator's, engine's, and GUI's version — which is
/// why the coordinator can advertise it as "the latest release the mesh should run".
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Attestation lifetime (design.md §5): bounds outage-tolerance and revocation latency.
pub const ATTESTATION_TTL_SECS: u64 = 30 * 60;

/// Long-poll hold (design.md §5): how long the coordinator parks an up-to-date `/refresh`
/// before returning to renew attestations. ≈ TTL/2 so peers' cached seeds never age past TTL.
pub const LONGPOLL_HOLD_SECS: u64 = ATTESTATION_TTL_SECS / 2;

/// Presence staleness bound (design.md §9): the coordinator reaps a device's presence if it
/// hasn't refreshed within this window. A live client re-registers at least every long-poll hold,
/// so 2× that + slack never evicts a healthy peer; it catches crashed/dropped clients and the old
/// pubkey a re-keyed device abandoned (the reaper backstop to the explicit supersede).
pub const PRESENCE_TTL_SECS: u64 = LONGPOLL_HOLD_SECS * 2 + 60;

/// Private DNS suffix (design.md §6.3): project namespace under ICANN-reserved `.internal`,
/// not `.local`.
///
/// The `unity` label is the **coordinator's** namespace. While we support a single coordinator it
/// is fixed, so a hostname is just `<device>.<user>.unity.internal` — the community/guild is *not*
/// in the name (one device = one identity/IP across all a coordinator's guilds; the guild rides on
/// each shared network instead, see `api::SharedNetwork`).
///
/// TODO(multi-coordinator): when a client can join guilds on **different** coordinators, this label
/// must become per-coordinator (e.g. derived from the coordinator's domain — `unitylan.com` →
/// `unity`) rather than a fixed constant. That per-coordinator label is what disambiguates the same
/// `@handle` / resolves IP-range collisions across coordinators — the role the community label used
/// to play in the hostname. See design.md §6.2.
pub const DNS_SUFFIX: &str = "unity.internal";

/// Lifetime of a minted TURN relay credential (design.md §7.2, M5.4). Comfortably exceeds the
/// long-poll hold (~TTL/2) so a client re-issued creds each coordinator refresh never sees one
/// expire mid-session; the relay's TURN server rejects an allocation past this.
pub const RELAY_CRED_TTL_SECS: u64 = 3600;

/// One-time enrollment-key lifetime (design.md §3.3): a headless-device key is a **bearer secret**,
/// so besides being single-use it is short-lived — a key leaked out-of-band (the main exposure is
/// pasting it through Discord/chat) can't be redeemed indefinitely. The window only needs to cover
/// carrying the key to the box, pasting it into the config, and its first register.
pub const ENROLLMENT_KEY_TTL_SECS: u64 = 15 * 60;

/// Current unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

/// Why a peer's protocol range couldn't be reconciled with ours — which side needs upgrading.
/// Carried in the rejection message so the operator is told what to *do*, not just that it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoReject {
    /// The peer's ceiling is below our floor: the peer is too old and must upgrade.
    PeerTooOld,
    /// The peer's floor is above our ceiling: *we* are too old and must upgrade.
    PeerTooNew,
}

/// Pick the wire version to speak with a peer advertising `[peer_min, peer_max]`.
///
/// Returns the highest version both sides speak, or which side is out of date. `peer_max == 0` is a
/// pre-versioning peer (the field didn't exist): served without negotiation at our own floor, since
/// rejecting a client that predates the mechanism would be a flag day imposed retroactively.
/// `peer_min == 0` means the peer named no floor — an older client that only knows exact match — so
/// its ceiling is treated as its floor.
pub fn negotiate_proto(peer_min: u32, peer_max: u32) -> Result<u32, ProtoReject> {
    if peer_max == 0 {
        return Ok(MIN_PROTOCOL_VERSION);
    }
    let peer_min = if peer_min == 0 { peer_max } else { peer_min };
    if peer_max < MIN_PROTOCOL_VERSION {
        return Err(ProtoReject::PeerTooOld);
    }
    if peer_min > PROTOCOL_VERSION {
        return Err(ProtoReject::PeerTooNew);
    }
    Ok(peer_max.min(PROTOCOL_VERSION))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_window_is_current_plus_one_previous() {
        // The policy the docs promise. If a bump forgets to move the floor, this catches it.
        assert_eq!(MIN_PROTOCOL_VERSION, PROTOCOL_VERSION - 1);
    }

    #[test]
    fn picks_the_highest_common_version() {
        assert_eq!(negotiate_proto(4, 5), Ok(5));
        // Peer ceiling below ours: speak the peer's version, not our own.
        assert_eq!(negotiate_proto(4, 4), Ok(4));
        // Peer ceiling above ours: cap at what we can actually speak.
        assert_eq!(negotiate_proto(5, 99), Ok(PROTOCOL_VERSION));
    }

    #[test]
    fn rejects_when_ranges_do_not_overlap() {
        assert_eq!(negotiate_proto(1, 3), Err(ProtoReject::PeerTooOld));
        assert_eq!(negotiate_proto(99, 100), Err(ProtoReject::PeerTooNew));
    }

    #[test]
    fn pre_versioning_peer_is_served_not_rejected() {
        // proto == 0 predates the field; refusing it would impose a flag day retroactively.
        assert_eq!(negotiate_proto(0, 0), Ok(MIN_PROTOCOL_VERSION));
    }

    #[test]
    fn absent_floor_means_exact_match_only() {
        // An old client that names no floor speaks exactly one version. Ours is above its
        // ceiling here, so we serve that ceiling; below it, that's PeerTooNew.
        assert_eq!(negotiate_proto(0, 4), Ok(4));
        assert_eq!(negotiate_proto(0, 3), Err(ProtoReject::PeerTooOld));
    }
}
