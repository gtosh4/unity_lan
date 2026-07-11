//! Shared types, wire formats, crypto, and addressing math for UnityLAN.
//!
//! Used by both the coordinator and the client engine. Pure logic only — no network I/O.

pub mod api;
pub mod attestation;
pub mod crypto;
pub mod netid;
pub mod wire;

use std::time::{SystemTime, UNIX_EPOCH};

/// Attestation lifetime (design.md §5): bounds outage-tolerance and revocation latency.
pub const ATTESTATION_TTL_SECS: u64 = 30 * 60;

/// Private DNS suffix (design.md §6.3): ICANN-reserved `.internal`, not `.local`.
pub const DNS_SUFFIX: &str = "internal";

/// Current unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}
