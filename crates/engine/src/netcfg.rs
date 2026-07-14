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
    /// Every network we've ever seen the coordinator report. A network absent here is "new" on the
    /// next refresh; `reconcile_new` uses it to apply `disable_new` exactly once per network.
    /// Persisted to `known_networks.json`.
    known: Mutex<HashSet<(u64, u64)>>,
    /// Whether newly-discovered networks default to disabled (opted out). Seeded from config on
    /// first run, then GUI-settable; persisted to `disable_new_networks.json`.
    disable_new: Mutex<bool>,
    path: PathBuf,
    paused_path: PathBuf,
    known_path: PathBuf,
    disable_new_path: PathBuf,
    /// Notified whenever the disabled set *or* the paused flag changes, so the daemon re-meshes
    /// (or tears the mesh down) at once.
    pub wake: Notify,
}

impl LocalNet {
    /// Load the persisted opt-out set from `<state_dir>/network_optout.json` (empty if absent), the
    /// paused flag from `<state_dir>/paused.json` (false if absent), the seen-networks set from
    /// `<state_dir>/known_networks.json` (empty if absent), and the new-network policy from
    /// `<state_dir>/disable_new_networks.json` — falling back to `disable_new_default` (from config)
    /// on first run, so config sets the initial posture and the GUI toggle overrides it thereafter.
    pub fn load(state_dir: &Path, disable_new_default: bool) -> Self {
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
        let known_path = state_dir.join("known_networks.json");
        let known = std::fs::read(&known_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<(u64, u64)>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let disable_new_path = state_dir.join("disable_new_networks.json");
        let disable_new = std::fs::read(&disable_new_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<bool>(&b).ok())
            .unwrap_or(disable_new_default);
        Self {
            disabled: Mutex::new(disabled),
            paused: Mutex::new(paused),
            known: Mutex::new(known),
            disable_new: Mutex::new(disable_new),
            path,
            paused_path,
            known_path,
            disable_new_path,
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

    /// Whether newly-discovered networks default to disabled (opted out of peering).
    pub fn disable_new(&self) -> bool {
        *self.disable_new.lock().unwrap()
    }

    /// Set the new-network default. Persists if changed. Affects only *future* discoveries — it
    /// doesn't touch already-known networks — so no re-mesh (and thus no `wake`) is needed.
    pub fn set_disable_new(&self, disable: bool) -> anyhow::Result<bool> {
        let changed = {
            let mut d = self.disable_new.lock().unwrap();
            let changed = *d != disable;
            *d = disable;
            changed
        };
        if changed {
            std::fs::write(&self.disable_new_path, serde_json::to_vec(&disable)?)?;
        }
        Ok(changed)
    }

    /// Reconcile the coordinator's current network list against what we've seen before. Any network
    /// not yet in the known set is "new": it's recorded, and — when `disable_new` is set — added to
    /// the opt-out set so it doesn't peer until the user enables it. Returns whether the opt-out set
    /// changed (so the caller re-applies state). Idempotent: a network is disabled at most once here,
    /// so a later manual enable sticks.
    pub fn reconcile_new(&self, present: &[(u64, u64)]) -> anyhow::Result<bool> {
        let disable_new = *self.disable_new.lock().unwrap();
        let mut known = self.known.lock().unwrap();
        let mut disabled = self.disabled.lock().unwrap();
        let mut known_changed = false;
        let mut disabled_changed = false;
        for &net in present {
            if known.insert(net) {
                known_changed = true;
                tracing::info!(
                    guild = net.0,
                    role = net.1,
                    disable_new,
                    "reconcile_new: first sighting of network (disabled on discovery = disable_new)"
                );
                if disable_new {
                    disabled_changed |= disabled.insert(net);
                }
            }
        }
        if known_changed {
            let v: Vec<(u64, u64)> = known.iter().copied().collect();
            std::fs::write(&self.known_path, serde_json::to_vec(&v)?)?;
        }
        if disabled_changed {
            let v: Vec<(u64, u64)> = disabled.iter().copied().collect();
            std::fs::write(&self.path, serde_json::to_vec(&v)?)?;
        }
        Ok(disabled_changed)
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

        let ln = LocalNet::load(&dir, true);
        assert!(!ln.is_paused(), "defaults to connected");

        // First toggle changes; a redundant set does not.
        assert!(ln.set_paused(true).unwrap());
        assert!(!ln.set_paused(true).unwrap());
        assert!(ln.is_paused());

        // A fresh load sees the persisted state; the per-network opt-out is untouched (separate file).
        let reloaded = LocalNet::load(&dir, true);
        assert!(reloaded.is_paused());
        assert!(reloaded.snapshot().is_empty());

        // Reconnecting clears it.
        assert!(reloaded.set_paused(false).unwrap());
        assert!(!LocalNet::load(&dir, true).is_paused());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn new_networks_disabled_on_discovery_when_policy_set() {
        let dir = std::env::temp_dir().join(format!("unitylan-netcfg-new-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Policy on: a freshly-seen network is opted out; re-seeing it doesn't re-disable.
        let ln = LocalNet::load(&dir, true);
        assert!(ln.reconcile_new(&[(1, 10)]).unwrap(), "new net disabled");
        assert!(ln.snapshot().contains(&(1, 10)));
        assert!(!ln.reconcile_new(&[(1, 10)]).unwrap(), "already known");

        // A manual enable sticks even though the network stays known (not re-disabled).
        assert!(ln.set(1, 10, true).unwrap());
        assert!(!ln.reconcile_new(&[(1, 10)]).unwrap());
        assert!(!ln.snapshot().contains(&(1, 10)));

        // Known set + policy survive a reload; policy is now GUI-settable.
        assert!(ln.set_disable_new(false).unwrap());
        let reloaded = LocalNet::load(&dir, true);
        assert!(
            !reloaded.disable_new(),
            "persisted policy wins over config default"
        );
        // Policy off: a new network is recorded but left enabled.
        assert!(!reloaded.reconcile_new(&[(2, 20)]).unwrap());
        assert!(!reloaded.snapshot().contains(&(2, 20)));

        std::fs::remove_dir_all(&dir).ok();
    }
}
