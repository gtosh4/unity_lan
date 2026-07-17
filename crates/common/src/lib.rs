//! Shared types, wire formats, crypto, and addressing math for UnityLAN.
//!
//! Used by both the coordinator and the client engine. Pure logic only — no network I/O.

pub mod api;
pub mod attestation;
pub mod control;
pub mod crypto;
pub mod netid;
pub mod relay;
pub mod rotation;
pub mod update;
pub mod wire;

use std::time::{SystemTime, UNIX_EPOCH};

/// Wire protocol version. Bump on a **breaking** change to the coordinator API or engine control
/// protocol — one that additive `#[serde(default)]` fields alone can't keep compatible. Advertised
/// in `RegisterReq`/`RegisterResp` so a coordinator and engine can detect a hard incompatibility and
/// log it, rather than silently misbehaving. A peer sending `0` is pre-versioning (defaulted field).
pub const PROTOCOL_VERSION: u32 = 2;

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

/// Current unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}
