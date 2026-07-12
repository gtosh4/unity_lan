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
    path: PathBuf,
    /// Notified whenever the disabled set changes, so the daemon re-meshes at once.
    pub wake: Notify,
}

impl LocalNet {
    /// Load the persisted opt-out set from `<state_dir>/network_optout.json` (empty if absent).
    pub fn load(state_dir: &Path) -> Self {
        let path = state_dir.join("network_optout.json");
        let disabled = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<(u64, u64)>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        Self {
            disabled: Mutex::new(disabled),
            path,
            wake: Notify::new(),
        }
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
