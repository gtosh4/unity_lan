//! Test-only helpers shared by the engine's unit tests.
//!
//! The generic ones live in [`common::testutil`] — every crate writes files and feeds parsers in
//! tests — and are re-exported here so the engine's tests have one place to import from. What stays
//! is engine-specific: fixtures for the engine's own types.

use std::net::Ipv4Addr;

use crate::coord::SeedPeer;

/// Deterministic pseudo-random bytes for the parser sweeps — see [`common::testutil::seeded_bytes`],
/// which the coordinator's STUN tests share.
pub use common::testutil::seeded_bytes;

/// A scratch directory that deletes itself on drop — see [`common::testutil::TempDir`].
pub use common::testutil::TempDir;

/// A peer as the coordinator would have handed it to us, with every field a test doesn't care about
/// deliberately inert: no endpoint, no punch target, no relay or ICE overlay, in no networks. A test
/// that sets one of those is then visibly exercising it.
///
/// Meant for struct-update syntax, which keeps the varying fields at the call site and means a new
/// `SeedPeer` field costs nothing here — `rev` and `expires_at` were each added to three separate
/// copies of this fixture that had no interest in them:
///
/// ```ignore
/// let s = SeedPeer { user_id: 3, ip: Ipv4Addr::new(100, 64, 0, 7), ..seed_peer() };
/// ```
pub fn seed_peer() -> SeedPeer {
    SeedPeer {
        pubkey: [0; 32],
        user_id: 1,
        username: "u".into(),
        ip: Ipv4Addr::new(100, 64, 0, 1),
        endpoint: None,
        punch: None,
        hostname: "d.u.unity.internal".into(),
        primary_alias: None,
        networks: Vec::new(),
        relay: None,
        ice: None,
        rev: 0,
        expires_at: 0,
    }
}
