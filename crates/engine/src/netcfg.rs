//! Local per-network peering opt-out. The client is the source of truth: the disabled set is
//! persisted here and enforced locally (by filtering seeds), so toggling a network works even
//! when the coordinator is unreachable. The set rides along to the coordinator on the next
//! register/refresh, which mirrors it (dropping the device from those networks both ways).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use common::api::NetworkRef;
use ipnet::Ipv4Net;
use tokio::sync::Notify;

/// Warn if the coordinator's mesh CIDR overlaps a subnet on a local, non-mesh interface — which
/// would risk shadowing (routing over) the user's real LAN. Returns a human-readable warning for
/// the first overlapping interface, or `None` if the mesh range is disjoint from every local
/// subnet. Best-effort: if interface enumeration fails, returns `None` rather than a false alarm.
/// Advisory — per-peer `/32` routes still come from signed attestations, so this flags a
/// misconfigured/ill-fitting range, it doesn't gate the mesh.
pub fn lan_overlap_warning(mesh: Ipv4Net, mesh_iface: &str) -> Option<String> {
    let ifaces = if_addrs::get_if_addrs().ok()?;
    for iface in ifaces {
        if iface.name == mesh_iface || iface.is_loopback() {
            continue;
        }
        let if_addrs::IfAddr::V4(v4) = iface.addr else {
            continue;
        };
        let Ok(prefix) = ipnet::ipv4_mask_to_prefix(v4.netmask) else {
            continue;
        };
        let Ok(subnet) = Ipv4Net::new(v4.ip, prefix) else {
            continue;
        };
        if common::netid::nets_overlap(&mesh, &subnet) {
            return Some(format!(
                "mesh range {mesh} overlaps local interface {} ({})",
                iface.name,
                subnet.trunc()
            ));
        }
    }
    None
}

/// JSON-decode `path` as `T`, falling back to `default` if it's missing, unreadable, or corrupt.
fn read_json_or<T: serde::de::DeserializeOwned>(path: &Path, default: T) -> T {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<T>(&b).ok())
        .unwrap_or(default)
}

/// JSON-encode `value` to `path`.
fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}

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
    /// Whether to always peer with the owner's own other devices (same Discord user), even when they
    /// share no enabled network. Seeded from config on first run, then GUI-settable; persisted to
    /// `peer_own_devices.json`. Rides to the coordinator on each register/refresh.
    peer_own: Mutex<bool>,
    /// Users this device has locally blocked, `user_id -> username` (the handle kept only for
    /// display). A blocked user's peers are filtered out of the mesh regardless of shared networks.
    /// Client is the source of truth (never sent to the coordinator); persisted to
    /// `blocked_users.json`. Keyed by user so a blocked owner can't evade by re-keying a device.
    blocked: Mutex<HashMap<u64, String>>,
    path: PathBuf,
    paused_path: PathBuf,
    known_path: PathBuf,
    disable_new_path: PathBuf,
    peer_own_path: PathBuf,
    blocked_path: PathBuf,
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
    pub fn load(state_dir: &Path, disable_new_default: bool, peer_own_default: bool) -> Self {
        let path = state_dir.join("network_optout.json");
        let disabled = read_json_or(&path, Vec::<(u64, u64)>::new())
            .into_iter()
            .collect();
        let paused_path = state_dir.join("paused.json");
        let paused = read_json_or(&paused_path, false);
        let known_path = state_dir.join("known_networks.json");
        let known = read_json_or(&known_path, Vec::<(u64, u64)>::new())
            .into_iter()
            .collect();
        let disable_new_path = state_dir.join("disable_new_networks.json");
        let disable_new = read_json_or(&disable_new_path, disable_new_default);
        let peer_own_path = state_dir.join("peer_own_devices.json");
        let peer_own = read_json_or(&peer_own_path, peer_own_default);
        let blocked_path = state_dir.join("blocked_users.json");
        let blocked = read_json_or(&blocked_path, Vec::<(u64, String)>::new())
            .into_iter()
            .collect();
        Self {
            disabled: Mutex::new(disabled),
            paused: Mutex::new(paused),
            known: Mutex::new(known),
            disable_new: Mutex::new(disable_new),
            peer_own: Mutex::new(peer_own),
            blocked: Mutex::new(blocked),
            path,
            paused_path,
            known_path,
            disable_new_path,
            peer_own_path,
            blocked_path,
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
            write_json(&self.paused_path, &paused)?;
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
            write_json(&self.disable_new_path, &disable)?;
        }
        Ok(changed)
    }

    /// Whether to always peer with the owner's own other devices, regardless of shared networks.
    pub fn peer_own_devices(&self) -> bool {
        *self.peer_own.lock().unwrap()
    }

    /// Enable/disable own-device peering. Persists + wakes the daemon if it changed: the daemon
    /// re-registers so the coordinator adds (or evicts) this device from its siblings' seeds, then
    /// re-meshes to bring the own-device tunnels up or down.
    pub fn set_peer_own_devices(&self, enabled: bool) -> anyhow::Result<bool> {
        let changed = {
            let mut p = self.peer_own.lock().unwrap();
            let changed = *p != enabled;
            *p = enabled;
            changed
        };
        if changed {
            write_json(&self.peer_own_path, &enabled)?;
            self.wake.notify_one();
        }
        Ok(changed)
    }

    /// Block (`true`) or un-block (`false`) a user by `user_id`. On block the handle is stored for
    /// display. Persists + wakes the daemon (re-mesh drops/re-admits the user's peers) if it changed.
    pub fn set_blocked(
        &self,
        user_id: u64,
        username: String,
        blocked: bool,
    ) -> anyhow::Result<bool> {
        let changed = {
            let mut b = self.blocked.lock().unwrap();
            if blocked {
                b.insert(user_id, username).is_none()
            } else {
                b.remove(&user_id).is_some()
            }
        };
        if changed {
            self.persist_blocked()?;
            self.wake.notify_one();
        }
        Ok(changed)
    }

    /// The blocked set, `user_id -> username`. The keys are the filter; the handles feed the status.
    pub fn blocked_snapshot(&self) -> HashMap<u64, String> {
        self.blocked.lock().unwrap().clone()
    }

    fn persist_blocked(&self) -> anyhow::Result<()> {
        let v: Vec<(u64, String)> = self
            .blocked
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, name)| (id, name.clone()))
            .collect();
        write_json(&self.blocked_path, &v)?;
        Ok(())
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
            write_json(&self.known_path, &v)?;
        }
        if disabled_changed {
            let v: Vec<(u64, u64)> = disabled.iter().copied().collect();
            write_json(&self.path, &v)?;
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
        write_json(&self.path, &v)?;
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

        let ln = LocalNet::load(&dir, true, true);
        assert!(!ln.is_paused(), "defaults to connected");

        // First toggle changes; a redundant set does not.
        assert!(ln.set_paused(true).unwrap());
        assert!(!ln.set_paused(true).unwrap());
        assert!(ln.is_paused());

        // A fresh load sees the persisted state; the per-network opt-out is untouched (separate file).
        let reloaded = LocalNet::load(&dir, true, true);
        assert!(reloaded.is_paused());
        assert!(reloaded.snapshot().is_empty());

        // Reconnecting clears it.
        assert!(reloaded.set_paused(false).unwrap());
        assert!(!LocalNet::load(&dir, true, true).is_paused());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn new_networks_disabled_on_discovery_when_policy_set() {
        let dir = std::env::temp_dir().join(format!("unitylan-netcfg-new-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Policy on: a freshly-seen network is opted out; re-seeing it doesn't re-disable.
        let ln = LocalNet::load(&dir, true, true);
        assert!(ln.reconcile_new(&[(1, 10)]).unwrap(), "new net disabled");
        assert!(ln.snapshot().contains(&(1, 10)));
        assert!(!ln.reconcile_new(&[(1, 10)]).unwrap(), "already known");

        // A manual enable sticks even though the network stays known (not re-disabled).
        assert!(ln.set(1, 10, true).unwrap());
        assert!(!ln.reconcile_new(&[(1, 10)]).unwrap());
        assert!(!ln.snapshot().contains(&(1, 10)));

        // Known set + policy survive a reload; policy is now GUI-settable.
        assert!(ln.set_disable_new(false).unwrap());
        let reloaded = LocalNet::load(&dir, true, true);
        assert!(
            !reloaded.disable_new(),
            "persisted policy wins over config default"
        );
        // Policy off: a new network is recorded but left enabled.
        assert!(!reloaded.reconcile_new(&[(2, 20)]).unwrap());
        assert!(!reloaded.snapshot().contains(&(2, 20)));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn peer_own_devices_persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!("unitylan-netcfg-own-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Defaults to the config-seeded value (enabled).
        let ln = LocalNet::load(&dir, true, true);
        assert!(ln.peer_own_devices());

        // First toggle changes; a redundant set does not.
        assert!(ln.set_peer_own_devices(false).unwrap());
        assert!(!ln.set_peer_own_devices(false).unwrap());
        assert!(!ln.peer_own_devices());

        // The persisted value wins over the config default on reload.
        let reloaded = LocalNet::load(&dir, true, true);
        assert!(!reloaded.peer_own_devices());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn blocked_users_persist_and_reload() {
        let dir =
            std::env::temp_dir().join(format!("unitylan-netcfg-block-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let ln = LocalNet::load(&dir, true, true);
        assert!(ln.blocked_snapshot().is_empty(), "defaults to none blocked");

        // First block changes; blocking the same user again does not.
        assert!(ln.set_blocked(333, "alice".into(), true).unwrap());
        assert!(!ln.set_blocked(333, "alice".into(), true).unwrap());
        assert_eq!(
            ln.blocked_snapshot().get(&333).map(String::as_str),
            Some("alice")
        );

        // The block survives a reload (keyed by user_id, handle kept for display).
        let reloaded = LocalNet::load(&dir, true, true);
        assert_eq!(
            reloaded.blocked_snapshot().get(&333).map(String::as_str),
            Some("alice")
        );

        // Un-blocking changes once, then is a no-op; the persisted set empties.
        assert!(reloaded.set_blocked(333, String::new(), false).unwrap());
        assert!(!reloaded.set_blocked(333, String::new(), false).unwrap());
        assert!(LocalNet::load(&dir, true, true)
            .blocked_snapshot()
            .is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
