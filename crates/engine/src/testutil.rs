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
/// Stable `(guild_id, role_id)` for a fixture network name.
///
/// Networks are identified on the wire by their ids, not their names, so a test that builds a seed
/// in one module and asserts on a firewall set in another only lines up if both derive the ids the
/// same way. That used to be two copies of this table agreeing by hand — and they had already
/// stopped: `fw`'s copy grew a `mesh` entry `daemon`'s never got.
///
/// `mesh` deliberately shares `minecraft`'s guild with a different role, so the two-networks-in-one-
/// guild case is covered. Unknown names panic rather than inventing an id: a typo should fail the
/// test that made it, not silently address a network nothing else refers to.
pub fn network_ids(name: &str) -> (u64, u64) {
    match name {
        "minecraft" => (900_100, 7001),
        "factorio" => (900_200, 7002),
        "mesh" => (900_100, 7003),
        other => panic!("unknown fixture network {other}"),
    }
}

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
