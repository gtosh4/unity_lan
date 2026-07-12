//! Shared types, wire formats, crypto, and addressing math for UnityLAN.
//!
//! Used by both the coordinator and the client engine. Pure logic only — no network I/O.

pub mod api;
pub mod attestation;
pub mod control;
pub mod crypto;
pub mod netid;
pub mod rotation;
pub mod wire;

use std::time::{SystemTime, UNIX_EPOCH};

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

/// Private DNS suffix (design.md §6.3): ICANN-reserved `.internal`, not `.local`.
pub const DNS_SUFFIX: &str = "internal";

/// Current unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}
