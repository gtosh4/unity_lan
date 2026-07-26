//! Test-only helpers shared across the workspace's test suites. Behind the `testutil` feature, so
//! none of this reaches a release build.

/// `len` deterministic pseudo-random bytes, for feeding a parser inputs no hand-written case would
/// think of.
///
/// A seeded xorshift64* rather than a `rand`/`proptest` dev-dependency: a parser sweep needs inputs
/// that are *reproducible* from the seed named in the failure, not statistically excellent, and
/// this keeps the sweeps inside the existing `cargo test` gate with nothing new in the dependency
/// tree. Shared here because all three of the workspace's unauthenticated parsers — the LAN beacon,
/// the coordinator's STUN socket, and the mesh resolver — want the same thing.
pub fn seeded_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed.wrapping_mul(2_685_821_657_736_338_717).wrapping_add(1);
    (0..len)
        .map(|_| {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            (s.wrapping_mul(2_685_821_657_736_338_717) >> 56) as u8
        })
        .collect()
}
