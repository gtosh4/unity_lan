//! The live status snapshot the daemon maintains and the control socket serves: the shared `watch`
//! channel, the setters the daemon drives it through, and the snapshot rebuild.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use common::api::NetworkStatus;
use common::control::{BlockedUser, DeviceStatus, PeerStatus, StatusReport};
use tokio::sync::{Notify, RwLock};

use crate::coord::{SeedPeer, SelfDevice};
use crate::fw::Firewall;
use crate::netcfg::LocalNet;

/// What the control server needs to serve status + forward mutations to the coordinator.
#[derive(Clone)]
pub struct Ctx {
    /// The live device status snapshot, served to any authorized frontend on `Status`.
    pub status: Shared,
    pub coordinator: String,
    /// The device token, set once the daemon has registered.
    pub token: Arc<RwLock<Option<String>>>,
    /// The host firewall, if enabled — handles `expose`/`unexpose` locally.
    pub fw: Option<Arc<Firewall>>,
    /// Local per-network peering opt-out — handles the network toggle locally.
    pub localnet: Arc<LocalNet>,
    /// This device's WG public key — used to start interactive login (OAuth). Shared because a
    /// logout re-keys the device: the daemon updates this in place so a later login binds the new key.
    pub pubkey: Arc<RwLock<[u8; 32]>>,
    /// Loopback redirect URI for the interactive-login (PKCE) flow.
    pub oauth_redirect: String,
    /// Signalled on `Logout` to wake the daemon's mesh loop into its teardown + re-key path.
    pub logout: Arc<Notify>,
    /// Signalled when interactive login binds the device — wakes the enrollment loop out of its
    /// `refresh_secs` backoff so the mesh comes up at once instead of on the next poll.
    pub login_done: Arc<Notify>,
    /// The engine state dir — where a staged update artifact is written before it's applied.
    pub state_dir: std::path::PathBuf,
    /// The verified auto-update the daemon has staged (if any), consumed by `ApplyUpdate`.
    pub pending_update: crate::selfupdate::PendingSlot,
}

/// Flip the "needs login" flag the daemon exposes while it's up but not yet enrolled.
pub fn set_needs_login(shared: &Shared, needs: bool) {
    shared.send_if_modified(|s| std::mem::replace(&mut s.needs_login, needs) != needs);
}

/// Flag that the coordinator refused us on wire protocol version, carrying its explanation (which
/// names both ranges and which side is stale). Cleared by passing `None` on the next success.
pub fn set_proto_mismatch(shared: &Shared, why: Option<String>) {
    let why = why.map(String::into_boxed_str);
    shared.send_if_modified(|s| std::mem::replace(&mut s.proto_mismatch, why) != s.proto_mismatch);
}

/// Set the mesh connection state the daemon reports (`true` = connected, `false` = disconnected).
pub fn set_connected(shared: &Shared, connected: bool) {
    shared.send_if_modified(|s| std::mem::replace(&mut s.connected, connected) != connected);
}

/// Set the new-network default the daemon reports, so the GUI reflects it without a full refresh.
pub fn set_disable_new(shared: &Shared, disable: bool) {
    shared.send_if_modified(|s| std::mem::replace(&mut s.disable_new_networks, disable) != disable);
}

/// Set the own-device-peering flag the daemon reports, so the GUI reflects it without a full refresh.
pub fn set_peer_own(shared: &Shared, enabled: bool) {
    shared.send_if_modified(|s| std::mem::replace(&mut s.peer_own_devices, enabled) != enabled);
}

/// Overlay coordinator reachability without rebuilding the snapshot — the mesh runs from cache when
/// a refresh fails, so this flags the health of the last coordinator contact.
pub fn set_coord_online(shared: &Shared, online: bool) {
    shared.send_if_modified(|s| std::mem::replace(&mut s.coordinator_online, online) != online);
}

/// Reset the status to the logged-out state: no device/peers/identity, `needs_login` set so the GUI
/// shows the login screen. Called after a logout tears the mesh down and before we re-register.
pub fn set_logged_out(shared: &Shared) {
    shared.send_replace(StatusReport {
        needs_login: true,
        // Spelled out because logged-out genuinely differs from `Default`'s "nothing specified yet":
        // there is no mesh to be connected to and no coordinator session to be online with. The
        // policy flags (`disable_new_networks`, `peer_own_devices`) are left at their secure
        // defaults — the persisted values in `LocalNet` are the real ones, and they're restored on
        // the next `update` after re-registering.
        connected: false,
        coordinator_online: false,
        ..Default::default()
    });
}

/// Shared, live status the daemon updates and the control socket reads. A `watch` channel so a
/// `Watch` subscription can be woken the instant the status changes, instead of polling. The daemon
/// mutates it through the setters below; each `send_*` notifies every parked `Watch` stream.
pub type Shared = Arc<tokio::sync::watch::Sender<StatusReport>>;

pub fn shared() -> Shared {
    // The initial receiver is dropped; `Watch` streams create their own via `subscribe()`. A
    // `watch::Sender` keeps working (send_* never errors) with zero receivers.
    //
    // `connected`/`coordinator_online` are spelled out as `false`: this is the pre-startup snapshot,
    // before the mesh is up or the coordinator has been reached, so reporting either as live would
    // be a claim the daemon hasn't earned yet. Both are overwritten by the first `update`.
    Arc::new(
        tokio::sync::watch::channel(StatusReport {
            connected: false,
            coordinator_online: false,
            ..Default::default()
        })
        .0,
    )
}

/// Rebuild the status snapshot from the current device + seed peers. `disabled` is the local
/// opt-out set, so the reported per-network `enabled` reflects the local toggle immediately (even
/// before the coordinator has mirrored it).
#[allow(clippy::too_many_arguments)]
pub fn update(
    shared: &Shared,
    device: &SelfDevice,
    seeds: &[SeedPeer],
    disabled: &HashSet<(u64, u64)>,
    blocked: &HashMap<u64, String>,
    connected: bool,
    disable_new_networks: bool,
    peer_own_devices: bool,
    coordinator_online: bool,
) {
    // Capture the update overlay before rebuilding, dropping the read guard before the write below.
    // Also carry each peer's last-known live telemetry (keyed by wg_ip) across the rebuild: this
    // `send_replace` publishes to the watch channel *before* the next `set_live` re-overlays, so
    // rebuilding peers as `up=false` would flash every peer offline in the GUI each refresh — a whole
    // herd of them when a member coming online wakes a burst of refreshes. Preserving prior liveness
    // keeps a steady peer steady; a genuinely-new peer has no prior entry and correctly starts down.
    let (
        prev_update_available,
        prev_update_ready,
        prev_lan_overlap,
        prev_proto_mismatch,
        prev_live,
    ) = {
        let prev = shared.borrow();
        let prev_live: HashMap<Ipv4Addr, PeerStatus> =
            prev.peers.iter().map(|p| (p.wg_ip, p.clone())).collect();
        (
            prev.update_available.clone(),
            prev.update_ready,
            prev.lan_overlap.clone(),
            prev.proto_mismatch.clone(),
            prev_live,
        )
    };
    let report = StatusReport {
        device: Some(DeviceStatus {
            wg_ip: device.wg_ip,
            hostname: device.hostname.clone(),
            is_primary: device.is_primary,
            networks: device.networks.clone(),
        }),
        peers: seeds
            .iter()
            .map(|s| PeerStatus {
                // Show the shortest name: a primary device's bare `<user>.unity.internal` alias when
                // it has one, else its `<device>.<user>` name. Primary changes rarely and callers
                // want whoever is primary anyway, so the bare alias is the friendlier default.
                hostname: s
                    .primary_alias
                    .clone()
                    .unwrap_or_else(|| s.hostname.clone()),
                wg_ip: s.ip,
                endpoint: s.endpoint,
                user_id: s.user_id,
                username: s.username.clone(),
                // Live telemetry: carry the peer's last-known values across the rebuild (so a steady
                // peer doesn't flash offline before the next `set_live` refreshes them), defaulting to
                // down for a peer we've not seen before.
                reach: prev_live
                    .get(&s.ip)
                    .map_or(common::control::PeerReach::Direct, |p| p.reach),
                up: prev_live.get(&s.ip).is_some_and(|p| p.up),
                latency_ms: prev_live.get(&s.ip).and_then(|p| p.latency_ms),
                rx_bytes: prev_live.get(&s.ip).map_or(0, |p| p.rx_bytes),
                tx_bytes: prev_live.get(&s.ip).map_or(0, |p| p.tx_bytes),
                last_handshake_secs: prev_live.get(&s.ip).and_then(|p| p.last_handshake_secs),
                // Own devices (same owner) carry a synthetic "My devices" tag for display, so they
                // group like a network in the peer view — matching the special networks-list row.
                // Display-only: `SeedPeer.networks` stays empty, so firewall/DNS/expose are untouched.
                networks: own_device_networks(s, device.user_id),
            })
            .collect(),
        networks: effective_networks(&device.networks_status, disabled),
        needs_login: false, // a device present means we're enrolled
        connected,
        disable_new_networks,
        peer_own_devices,
        identity: Some(device.username.clone()),
        coordinator_online,
        blocked: blocked_list(blocked),
        engine_version: common::VERSION.to_string(),
        // Both preserved across the rebuild — overlaid from the coordinator's advertised version /
        // verified manifest each refresh, independent of this snapshot's inputs.
        update_available: prev_update_available,
        update_ready: prev_update_ready,
        // Set once at join by `set_lan_overlap`; preserved across snapshot rebuilds.
        lan_overlap: prev_lan_overlap,
        // Owned by the register/refresh loops (set on a 426, cleared on success), so preserve it
        // here rather than letting a snapshot rebuild silently clear a live refusal.
        proto_mismatch: prev_proto_mismatch,
        // Demo-only UI push; the real engine never drives the GUI (see `StatusReport::directive`).
        directive: None,
    };
    shared.send_replace(report);
}

/// The networks shown for a peer: its real shared networks, plus a synthetic "My devices" tag first
/// when the peer is one of the owner's own devices (same `user_id`). Display-only — never fed back
/// to the coordinator or into firewall/DNS grouping.
fn own_device_networks(s: &SeedPeer, self_user_id: u64) -> Vec<common::api::SharedNetwork> {
    let mut nets = s.networks.clone();
    if s.user_id == self_user_id {
        nets.insert(
            0,
            common::api::SharedNetwork {
                guild_id: 0,
                role_id: 0,
                name: common::control::OWN_DEVICES_LABEL.to_string(),
                community: String::new(),
            },
        );
    }
    nets
}

/// Record (or clear) the warning that the coordinator's mesh CIDR overlaps a local interface's
/// subnet. Set once when the mesh comes up; surfaced in the GUI so the user notices a range that
/// could shadow their real LAN.
pub fn set_lan_overlap(shared: &Shared, warning: Option<String>) {
    shared.send_if_modified(|s| {
        if s.lan_overlap == warning {
            false
        } else {
            s.lan_overlap = warning;
            true
        }
    });
}

/// Overlay the coordinator-advertised latest release: set `update_available` iff `latest` is a newer
/// semver than what this engine is running, else clear it. Kept out of [`update`] so the check runs
/// each refresh without rebuilding the snapshot; the empty string (a pre-versioning coordinator)
/// never parses, so it reads as "no update". This is the notice-only signal (phase 2); an actually
/// applyable update is gated by [`set_update_ready`].
pub fn set_update_available(shared: &Shared, latest: &str) {
    let newer = crate::selfupdate::is_newer(latest, common::VERSION);
    let val = newer.then(|| latest.to_string());
    shared.send_if_modified(|s| {
        if s.update_available == val {
            false
        } else {
            s.update_available = val;
            true
        }
    });
}

/// Overlay whether a verified, applyable update is staged (the daemon verified the signed manifest
/// and matched an artifact for this platform). Drives whether the GUI shows an Update button.
pub fn set_update_ready(shared: &Shared, ready: bool) {
    shared.send_if_modified(|s| std::mem::replace(&mut s.update_ready, ready) != ready);
}

/// The blocked map as a sorted (stable order) list of [`BlockedUser`] for the status report.
fn blocked_list(blocked: &HashMap<u64, String>) -> Vec<BlockedUser> {
    let mut v: Vec<BlockedUser> = blocked
        .iter()
        .map(|(&user_id, username)| BlockedUser {
            user_id,
            username: username.clone(),
        })
        .collect();
    v.sort_by(|a, b| a.username.cmp(&b.username).then(a.user_id.cmp(&b.user_id)));
    v
}

/// Mirror a block/un-block into the live status without waiting for the daemon's next re-mesh:
/// rewrite the blocked list and drop any now-blocked user's peers so the GUI updates at once. The
/// daemon's `wake`-triggered re-mesh follows and settles the peer set (adds them back on un-block).
pub fn set_blocked(shared: &Shared, blocked: &HashMap<u64, String>) {
    shared.send_modify(|report| {
        report.peers.retain(|p| !blocked.contains_key(&p.user_id));
        report.blocked = blocked_list(blocked);
    });
}

/// Live per-peer telemetry overlaid onto the status each refresh loop: reachability, liveness, the
/// last measured latency, and the WG byte counters. Keyed by the peer's wg IP in [`set_live`].
pub struct PeerLive {
    pub reach: common::control::PeerReach,
    pub up: bool,
    pub latency_ms: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_secs: Option<u64>,
}

/// Overlay per-peer live telemetry onto the current status without rebuilding it (cheap — no DNS or
/// firewall work), so a stuck hole punch, byte counters, and latency all surface promptly even when
/// nothing else changed. Keyed by the peer's wg IP.
pub fn set_live(shared: &Shared, live: &std::collections::HashMap<std::net::Ipv4Addr, PeerLive>) {
    shared.send_modify(|report| {
        for p in &mut report.peers {
            if let Some(l) = live.get(&p.wg_ip) {
                p.reach = l.reach;
                p.up = l.up;
                p.latency_ms = l.latency_ms;
                p.rx_bytes = l.rx_bytes;
                p.tx_bytes = l.tx_bytes;
                p.last_handshake_secs = l.last_handshake_secs;
            }
        }
    });
}

/// Apply the local opt-out to a network list: a locally-disabled network reports `enabled = false`
/// regardless of what the coordinator said.
fn effective_networks(
    networks: &[NetworkStatus],
    disabled: &HashSet<(u64, u64)>,
) -> Vec<NetworkStatus> {
    networks
        .iter()
        .map(|n| NetworkStatus {
            enabled: n.enabled && !disabled.contains(&(n.guild_id, n.role_id)),
            ..n.clone()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coord::SeedPeer;
    use std::net::Ipv4Addr;

    fn seed(user_id: u64, nets: &[(&str, &str)]) -> SeedPeer {
        SeedPeer {
            pubkey: [0; 32],
            user_id,
            username: "u".into(),
            ip: Ipv4Addr::new(100, 64, 0, 2),
            endpoint: None,
            punch: None,
            hostname: "d.u.unity.internal".into(),
            primary_alias: None,
            networks: nets
                .iter()
                .map(|(n, c)| common::api::SharedNetwork {
                    guild_id: 1,
                    role_id: 2,
                    name: (*n).into(),
                    community: (*c).into(),
                })
                .collect(),
            relay: None,
            ice: None,
            rev: 0,
            expires_at: 0,
        }
    }

    #[test]
    fn own_device_gets_my_devices_tag_prepended() {
        // Same user (7) → "My devices" leads, real networks follow, in display order.
        let mine = seed(7, &[("Engineering", "acme")]);
        let tagged = own_device_networks(&mine, 7);
        assert_eq!(tagged[0].name, common::control::OWN_DEVICES_LABEL);
        assert!(tagged[0].community.is_empty());
        assert_eq!(tagged[1].name, "Engineering");

        // An own device sharing no network still gets the tag (the whole point of the feature).
        let bare = seed(7, &[]);
        assert_eq!(own_device_networks(&bare, 7).len(), 1);
        assert_eq!(
            own_device_networks(&bare, 7)[0].name,
            common::control::OWN_DEVICES_LABEL
        );

        // A different user's peer is untouched — no tag, no leak.
        let other = seed(9, &[("Engineering", "acme")]);
        let untouched = own_device_networks(&other, 7);
        assert_eq!(untouched.len(), 1);
        assert_eq!(untouched[0].name, "Engineering");
    }
}
