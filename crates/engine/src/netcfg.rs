//! Local per-network peering opt-out. The client is the source of truth: the disabled set is
//! persisted here and enforced locally (by filtering seeds), so toggling a network works even
//! when the coordinator is unreachable. The set rides along to the coordinator on the next
//! register/refresh, which mirrors it (dropping the device from those networks both ways).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use common::api::NetworkRef;
use tokio::sync::Notify;

pub struct LocalNet {
    disabled: Mutex<HashSet<(u64, u64)>>,
    /// Global "disconnected" (paused) flag, layered *on top of* the per-network opt-out so a
    /// connect/disconnect cycle doesn't clobber individual per-network preferences. Persisted
    /// separately (`paused.json`) and, like the opt-out set, the client is the source of truth.
    paused: Mutex<bool>,
    path: PathBuf,
    paused_path: PathBuf,
    /// Notified whenever the disabled set *or* the paused flag changes, so the daemon re-meshes
    /// (or tears the mesh down) at once.
    pub wake: Notify,
}

impl LocalNet {
    /// Load the persisted opt-out set from `<state_dir>/network_optout.json` (empty if absent) and
    /// the paused flag from `<state_dir>/paused.json` (false if absent).
    pub fn load(state_dir: &Path) -> Self {
        let path = state_dir.join("network_optout.json");
        let disabled = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<(u64, u64)>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let paused_path = state_dir.join("paused.json");
        let paused = std::fs::read(&paused_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<bool>(&b).ok())
            .unwrap_or(false);
        Self {
            disabled: Mutex::new(disabled),
            paused: Mutex::new(paused),
            path,
            paused_path,
            wake: Notify::new(),
        }
    }

    /// Connect (`false`) or disconnect (`true`) the mesh. Persists + wakes the daemon if it changed.
    pub fn set_paused(&self, paused: bool) -> anyhow::Result<bool> {
        let changed = {
            let mut p = self.paused.lock().unwrap();
            let changed = *p != paused;
            *p = paused;
            changed
        };
        if changed {
            std::fs::write(&self.paused_path, serde_json::to_vec(&paused)?)?;
            self.wake.notify_one();
        }
        Ok(changed)
    }

    /// Whether the mesh is currently paused (locally disconnected).
    pub fn is_paused(&self) -> bool {
        *self.paused.lock().unwrap()
    }

    /// Enable/disable peering on a network. Persists + wakes the daemon if it changed anything.
    pub fn set(&self, guild_id: u64, role_id: u64, enabled: bool) -> anyhow::Result<bool> {
        let changed = {
            let mut d = self.disabled.lock().unwrap();
            if enabled {
                d.remove(&(guild_id, role_id))
            } else {
                d.insert((guild_id, role_id))
            }
        };
        if changed {
            self.persist()?;
            self.wake.notify_one();
        }
        Ok(changed)
    }

    pub fn snapshot(&self) -> HashSet<(u64, u64)> {
        self.disabled.lock().unwrap().clone()
    }

    /// The disabled set as API refs, to send in register/refresh.
    pub fn as_refs(&self) -> Vec<NetworkRef> {
        self.disabled
            .lock()
            .unwrap()
            .iter()
            .map(|&(guild_id, role_id)| NetworkRef { guild_id, role_id })
            .collect()
    }

    fn persist(&self) -> anyhow::Result<()> {
        let v: Vec<(u64, u64)> = self.disabled.lock().unwrap().iter().copied().collect();
        std::fs::write(&self.path, serde_json::to_vec(&v)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::LocalNet;

    #[test]
    fn paused_flag_persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!("unitylan-netcfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let ln = LocalNet::load(&dir);
        assert!(!ln.is_paused(), "defaults to connected");

        // First toggle changes; a redundant set does not.
        assert!(ln.set_paused(true).unwrap());
        assert!(!ln.set_paused(true).unwrap());
        assert!(ln.is_paused());

        // A fresh load sees the persisted state; the per-network opt-out is untouched (separate file).
        let reloaded = LocalNet::load(&dir);
        assert!(reloaded.is_paused());
        assert!(reloaded.snapshot().is_empty());

        // Reconnecting clears it.
        assert!(reloaded.set_paused(false).unwrap());
        assert!(!LocalNet::load(&dir).is_paused());

        std::fs::remove_dir_all(&dir).ok();
    }
}
