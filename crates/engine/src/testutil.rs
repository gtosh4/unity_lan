//! Test-only helpers shared by the engine's unit tests.

use std::path::{Path, PathBuf};

/// A scratch directory that deletes itself on drop.
///
/// Replaces the hand-rolled "make a temp dir, `remove_dir_all` on the last line" pattern: that
/// leaks the directory whenever a test panics before reaching the cleanup line, and a leaked dir
/// makes the *next* run start from stale state.
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
