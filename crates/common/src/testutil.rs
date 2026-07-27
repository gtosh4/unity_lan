//! Test-only helpers shared across the workspace's test suites. Behind the `testutil` feature, so
//! none of this reaches a release build.

use std::path::{Path, PathBuf};

/// A scratch directory that deletes itself on drop.
///
/// Replaces the hand-rolled "make a temp dir, `remove_dir_all` on the last line" pattern: that leaks
/// the directory whenever a test panics before reaching the cleanup line, and a leaked dir makes the
/// *next* run start from stale state — which is why `new` clears any residue before creating.
///
/// Lives here rather than in one crate's own test module because all three crates write files in
/// tests: the engine's key/state dirs, the coordinator's SQLite database and config files, and
/// `winsec`'s Windows ACL checks.
pub struct TempDir(PathBuf);

impl TempDir {
    /// A fresh, empty `unitylan-<tag>-<pid>` under the system temp dir. `tag` must be unique
    /// among the tests that can run concurrently in one process.
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("unitylan-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // clear residue from an earlier crashed run
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
