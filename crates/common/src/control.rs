//! Control-socket protocol (design.md §3.2, §8): the newline-delimited JSON an unprivileged
//! frontend (CLI, iced GUI) exchanges with the privileged engine daemon.
//!
//! Pure wire types only — the engine owns the server, each frontend its own client transport
//! (Unix socket now, Windows named pipe later). Shared here so frontends need not depend on the
//! engine crate.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::api::{ManageOp, ManageResp, NetworkStatus};

/// The Windows SCM service key the engine installs itself under. Shared so the engine (installer +
/// SCM entry point) and the GUI (status query + start/stop) address the same service.
pub const WINDOWS_SERVICE_NAME: &str = "UnityLANEngine";

/// Display label for the synthetic "own devices" grouping: the pseudo-network the GUI shows for the
/// always-on own-device peering toggle, and the tag on peers that are the owner's other devices. Not
/// a real network (never on the coordinator wire) — a client-side display convention only, so both
/// the engine (peer tagging) and the GUI (the toggle row) name it the same thing.
pub const OWN_DEVICES_LABEL: &str = "My devices";

#[derive(Serialize, Deserialize)]
pub enum ControlRequest {
    Status,
    /// Subscribe to live status: the daemon holds the connection open and writes a fresh
    /// [`ControlResponse::Status`] line every time the status changes (starting with the current
    /// one). Lets a frontend reflect state instantly instead of polling. The stream ends when the
    /// client disconnects or the daemon shuts down.
    Watch,
    Manage(ManageOp),
    /// Firewall port exposure — handled locally by the daemon (not forwarded to the coordinator).
    Expose(ExposeOp),
    /// Enable/disable this device's peering on a network (role@guild). Handled locally (the client
    /// is the source of truth) so it works even when the coordinator is unreachable; the change
    /// rides along to the coordinator on the next register/refresh.
    SetNetwork {
        guild_id: u64,
        role_id: u64,
        enabled: bool,
    },
    /// Begin interactive login: ask the coordinator (via the daemon) for the Discord authorize URL
    /// to open. The daemon's register loop binds the device once the browser completes the flow.
    Login,
    /// Connect (`true`) or disconnect (`false`) the mesh. Disconnect keeps the daemon resident and
    /// still polling the coordinator (so reconnect is instant) but brings the local peer-set down
    /// and withdraws this device from every co-member's seed list — peers see it go offline.
    /// Handled locally (persisted, source of truth), so it works even when the coordinator is
    /// unreachable; the change rides to the coordinator on the next refresh.
    SetConnected {
        connected: bool,
    },
    /// Set the local policy for networks discovered from now on: `disable = true` opts newly-seen
    /// networks out of peering by default (the secure default), `false` enrols them automatically.
    /// Handled locally (persisted, source of truth); returns the updated [`StatusReport`].
    SetNewNetworkDefault {
        disable: bool,
    },
    /// Set whether this device always peers with the owner's own other devices (same Discord user),
    /// even when they share no enabled network. Handled locally (persisted, source of truth); rides
    /// to the coordinator on the next register/refresh. Returns the updated [`StatusReport`].
    SetOwnDevicePeering {
        enabled: bool,
    },
    /// Log out: tear down the mesh (drop every peer, bring the interface down), un-enroll this
    /// device at the coordinator, and discard the local key + token so the next enrollment uses a
    /// fresh key. The daemon stays resident and returns to the not-logged-in state (`needs_login`).
    Logout,
    /// Locally block a peer's owner (by Discord `user_id`): drop every one of their devices from
    /// the mesh and refuse to peer with them, without leaving any shared network. Purely local (the
    /// client is the source of truth) — the coordinator is never told. Keyed by user, not device
    /// key, so it survives the blocked user re-keying or renaming a device. `username` is stored for
    /// display in the blocked list. Returns the updated [`StatusReport`].
    BlockPeer {
        user_id: u64,
        username: String,
    },
    /// Un-block a previously-blocked user (by `user_id`): they re-mesh on the next refresh. Returns
    /// the updated [`StatusReport`].
    UnblockPeer {
        user_id: u64,
    },
    /// Apply the staged auto-update: download the artifact the coordinator's signed manifest named,
    /// re-verify its SHA-256, swap the engine binary (Linux) / launch the MSI upgrade (Windows), and
    /// restart. Only acts when the daemon has a verified update staged (see [`StatusReport::update_ready`]).
    ApplyUpdate,
}

#[derive(Serialize, Deserialize)]
pub enum ControlResponse {
    /// Boxed: the status snapshot dwarfs every other variant (peers, networks, blocked users), so
    /// inlining it would size *every* `ControlResponse` by the largest one. Serializes identically —
    /// `Box` is transparent to serde, so this is not a wire change.
    Status(Box<StatusReport>),
    Manage(ManageResp),
    Expose(ExposeResp),
    Network(NetworkResp),
    Login(LoginResp),
    Connected(ConnectedResp),
    Logout(LogoutResp),
    Update(UpdateResp),
    Error(String),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateResp {
    /// The version being applied.
    pub version: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectedResp {
    /// The mesh connection state after the toggle (`true` = connected).
    pub connected: bool,
    pub message: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LoginResp {
    /// The Discord authorize URL the user opens to complete login.
    pub authorize_url: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogoutResp {
    pub message: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkResp {
    pub message: String,
    /// The device's networks after the toggle, with effective (local) enabled state.
    pub networks: Vec<NetworkStatus>,
}

/// Transport protocol of an exposed port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// A firewall exposure op over the control socket. `net` scopes the exposure to one network's
/// peers (source-IP filtered); `None` opens the port to every peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExposeOp {
    List,
    Add {
        proto: Proto,
        port: u16,
        net: Option<String>,
    },
    Remove {
        proto: Proto,
        port: u16,
        scope: RemoveScope,
    },
}

/// Which exposure(s) a `Remove` closes. `All` drops every scope of that (proto, port); `Exact`
/// drops just the one whose `net` matches — so closing `8082 → net:minecraft` leaves an
/// all-peers `8082` alone (and vice versa).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RemoveScope {
    All,
    Exact(Option<String>),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExposeResp {
    pub message: String,
    pub exposed: Vec<ExposedPort>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExposedPort {
    pub proto: Proto,
    pub port: u16,
    /// The network this port is scoped to, or `None` for all peers.
    pub net: Option<String>,
    /// Whether the exposure is currently reachable. A `--net`-scoped port whose network has no
    /// online peers has an empty source set, so nothing can reach it even though it stays
    /// exposed; unscoped ports are always active.
    pub active: bool,
}

/// A snapshot of the daemon's live mesh state: this device plus the peers it has meshed with.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusReport {
    pub device: Option<DeviceStatus>,
    pub peers: Vec<PeerStatus>,
    /// Every network this device's roles grant (role@guild) + per-device enabled state — the
    /// source for the GUI's peering toggle. Empty when not joined.
    #[serde(default)]
    pub networks: Vec<NetworkStatus>,
    /// True while the daemon is up but the device isn't logged in / enrolled — the GUI shows a
    /// "Log in with Discord" button.
    #[serde(default)]
    pub needs_login: bool,
    /// Whether the mesh is connected (vs. locally disconnected/paused). Defaults to `true` so a
    /// status from an older daemon (no field) reads as connected. Toggled by `SetConnected`.
    #[serde(default = "default_true")]
    pub connected: bool,
    /// Whether networks discovered from now on default to *disabled* (opted out of peering). The
    /// secure default is `true`; the GUI toggles it via `SetNewNetworkDefault`.
    #[serde(default = "default_true")]
    pub disable_new_networks: bool,
    /// Whether this device always peers with the owner's own other devices, regardless of shared
    /// networks. The default is `true`; the GUI toggles it via `SetOwnDevicePeering`. Defaults to
    /// `true` when absent (an older daemon) so the GUI shows the feature as on.
    #[serde(default = "default_true")]
    pub peer_own_devices: bool,
    /// The Discord identity this device is enrolled as (the owner's handle). `None` before login.
    #[serde(default)]
    pub identity: Option<String>,
    /// Whether the last coordinator refresh succeeded — the mesh keeps running from cache when the
    /// coordinator is unreachable, so this is a health signal, distinct from `connected`. Defaults
    /// to `true` (an older daemon with no field reads as reachable).
    #[serde(default = "default_true")]
    pub coordinator_online: bool,
    /// Users this device has locally blocked (by `user_id`): their peers are dropped from the mesh.
    /// Reported separately from `peers` (a blocked user never appears there) so the GUI can list and
    /// un-block them even while they're filtered out.
    #[serde(default)]
    pub blocked: Vec<BlockedUser>,
    /// The engine daemon's own release version (semver, [`crate::VERSION`]) — shown in the GUI's
    /// status/about. Empty from a pre-versioning daemon.
    #[serde(default)]
    pub engine_version: String,
    /// A newer release the coordinator advertises, iff it's a newer semver than `engine_version` —
    /// the GUI shows an "update available" affordance. `None` when up to date or the coordinator is
    /// silent about its version.
    #[serde(default)]
    pub update_available: Option<String>,
    /// A verified, platform-matching, strictly-newer update is staged: the daemon checked the
    /// coordinator's signed manifest against its pinned anchor and can apply it on `ApplyUpdate`. The
    /// GUI shows an Update button only when this is set. `false` when the deployment configured no
    /// `[release]`, the artifact isn't for this platform, or verification failed (notice-only).
    #[serde(default)]
    pub update_ready: bool,
    /// The coordinator refused us on wire protocol version: our range and its range don't overlap
    /// ([`crate::negotiate_proto`]). Carries the coordinator's message, which names both ranges and
    /// which side is stale. Distinct from `coordinator_online` — the coordinator is reachable and
    /// answering, it just won't talk to this build, so the GUI must say "update" rather than show a
    /// connectivity error. `None` in the normal case — boxed for the same reason as `directive`,
    /// so a rarely-set field doesn't grow the largest `ControlResponse` variant.
    #[serde(default)]
    pub proto_mismatch: Option<Box<str>>,
    /// A human-readable warning that the coordinator's mesh CIDR overlaps a local network
    /// interface's subnet (checked at join). Overlap risks shadowing the user's real LAN, so the
    /// GUI surfaces it. `None` when the ranges are disjoint (the expected case). Advisory only —
    /// per-peer `/32` routes still come from signed attestations.
    #[serde(default)]
    pub lan_overlap: Option<String>,
    /// A UI directive the engine can push to drive the GUI (switch tab, open a peer menu, …),
    /// delivered on the status poll. **Only a debug-build GUI acts on it** (`#[cfg(debug_assertions)]`);
    /// a release build ignores it entirely. The real engine never sets this — it exists so
    /// `examples/fake-engine` can script the UI for screenshots / demo video. `None` in normal use.
    /// Boxed so this demo-only field doesn't grow `StatusReport` (the largest control response).
    #[serde(default)]
    pub directive: Option<Box<UiDirective>>,
}

/// A one-shot UI directive pushed from the engine to the GUI over the status poll (demo/testing
/// only — see [`StatusReport::directive`]). `seq` is monotonic: the GUI applies a directive only
/// when `seq` exceeds the last it applied, so re-polling the same status doesn't re-fire it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UiDirective {
    pub seq: u64,
    pub action: UiAction,
}

/// What a [`UiDirective`] tells the GUI to do. Each maps to a UI-only state change the GUI already
/// supports (tab switch, peer menu, block confirm) — nothing that touches mesh state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UiAction {
    /// Switch the visible content tab.
    SelectTab(UiTab),
    /// Open a peer's action menu (kebab dropdown), by that device's WireGuard IP (menus are
    /// per-device, since copy-hostname/IP are device-specific).
    OpenPeerMenu(Ipv4Addr),
    /// Close any open peer menu.
    CloseMenu,
    /// Arm the "block user" confirm for a peer's owner (opens the user-scoped block modal), by the
    /// owner's Discord `user_id`.
    ArmBlockPeer(u64),
    /// Dismiss any armed confirm.
    Cancel,
}

/// The GUI's content tabs, in the wire protocol so a directive can name one without the GUI's
/// internal `Tab` type. Mirrors it 1:1.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum UiTab {
    Networks,
    Peers,
    Manage,
}

/// A locally-blocked user: their Discord `user_id` plus a display handle for the blocked list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockedUser {
    pub user_id: u64,
    pub username: String,
}

/// Written out rather than derived: four fields carry `#[serde(default = "default_true")]`, so a
/// derived `Default` would disagree with how the same struct decodes off the wire — and, for
/// `disable_new_networks`, would hand a caller the *permissive* posture the field's own docs call
/// insecure. `Default` here means "nothing specified yet", matching the serde defaults exactly.
/// Container-level `#[serde(default)]` is deliberately absent, so this impl never affects decoding;
/// it exists only for Rust callers building a report with `..Default::default()`.
impl Default for StatusReport {
    fn default() -> Self {
        Self {
            device: None,
            peers: Vec::new(),
            networks: Vec::new(),
            needs_login: false,
            connected: true,
            disable_new_networks: true,
            peer_own_devices: true,
            identity: None,
            coordinator_online: true,
            blocked: Vec::new(),
            engine_version: String::new(),
            update_available: None,
            update_ready: false,
            proto_mismatch: None,
            lan_overlap: None,
            directive: None,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub wg_ip: Ipv4Addr,
    pub hostname: String,
    pub is_primary: bool,
    pub networks: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub hostname: String,
    pub wg_ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
    /// How this peer is (or isn't) reachable — surfaces a stuck hole punch. Defaults to `Direct`.
    #[serde(default)]
    pub reach: PeerReach,
    /// The peer owner's Discord id + handle — the identity a local block acts on (`BlockPeer`).
    #[serde(default)]
    pub user_id: u64,
    #[serde(default)]
    pub username: String,
    /// Whether WG has a recent handshake for this peer (data plane is live) — distinct from `reach`,
    /// which reports the *path type* and stays `Direct` even for a peer that has gone silent.
    #[serde(default)]
    pub up: bool,
    /// Round-trip latency to the peer's WG IP from the last ICMP echo, in ms. `None` when no reply
    /// (unreachable / probe disabled).
    #[serde(default)]
    pub latency_ms: Option<u32>,
    /// Cumulative bytes received from / sent to this peer, as counted by the WG backend.
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    /// Seconds since the last WireGuard handshake with this peer. `None` if none has happened yet.
    /// Surfaced on hover in the GUI; `up` is just this crossing the freshness threshold.
    #[serde(default)]
    pub last_handshake_secs: Option<u64>,
    /// The networks shared with this peer (the intersection of our memberships), each tagged with the
    /// community (server) it lives in — the ACL groups over which we're mutually reachable. Shown,
    /// grouped by community, on hover over the peer's name.
    #[serde(default)]
    pub networks: Vec<crate::api::SharedNetwork>,
}

/// A peer's data-plane reachability, for status display (§7.2 diagnostics).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerReach {
    /// Connected — reached directly (dialable/forwarded) or a hole punch that completed.
    #[default]
    Direct,
    /// Hole punch in progress: we're dialing the peer's reflexive, no handshake yet.
    Punching,
    /// Hole punch attempted but never completed (no handshake). Likely symmetric NAT on both
    /// ends — not traversable without a relay (§7.2).
    Unreachable,
    /// Reached through a ciphertext relay (§7.2, M5.4): a direct path and a hole punch both failed,
    /// so WG traffic rides a co-member's TURN relay (relay holds no keys — e2e intact).
    Relayed,
    /// Reached via a side-socket ICE agent (§7.2, M5.5, userspace): the ad-hoc punch was replaced by
    /// a real ICE negotiation, whose selected path may be a direct srflx pair or the relay candidate.
    Ice,
}

/// Classify a peer's reachability from whether it needed a hole punch, whether a WG handshake has
/// completed, and how long the punch has been outstanding. Pure, so it's unit-testable.
pub fn classify_reach(punched: bool, connected: bool, punch_age_secs: u64) -> PeerReach {
    if connected || !punched {
        // Connected (directly or via a completed punch), or a normal peer still bootstrapping.
        PeerReach::Direct
    } else if punch_age_secs >= 30 {
        PeerReach::Unreachable
    } else {
        PeerReach::Punching
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_reach, PeerReach, StatusReport};

    /// `Default` and the wire must agree on what "unspecified" means. A derived `Default` would
    /// give `false` for the four `default_true` fields — including `disable_new_networks`, whose
    /// permissive value is the insecure posture — so a caller writing `..Default::default()` would
    /// silently get a report that no daemon would ever have sent.
    #[test]
    fn default_matches_the_wire_defaults() {
        // Only the two fields without a serde default have to be present.
        let decoded: StatusReport =
            serde_json::from_str(r#"{"device":null,"peers":[]}"#).expect("decodes");
        let d = StatusReport::default();
        assert_eq!(decoded.connected, d.connected);
        assert_eq!(decoded.disable_new_networks, d.disable_new_networks);
        assert_eq!(decoded.peer_own_devices, d.peer_own_devices);
        assert_eq!(decoded.coordinator_online, d.coordinator_online);
        assert_eq!(decoded.needs_login, d.needs_login);
        // Spelled out so the secure posture is asserted, not just self-consistency.
        assert!(
            d.disable_new_networks,
            "new networks must default to opted out"
        );
    }

    #[test]
    fn reach_classification() {
        // A directly-reachable / non-punched peer is always Direct.
        assert_eq!(classify_reach(false, false, 0), PeerReach::Direct);
        assert_eq!(classify_reach(false, true, 999), PeerReach::Direct);
        // A punch that completed (handshake seen) reads as Direct regardless of age.
        assert_eq!(classify_reach(true, true, 5), PeerReach::Direct);
        // Punching in progress, within the grace window.
        assert_eq!(classify_reach(true, false, 5), PeerReach::Punching);
        assert_eq!(classify_reach(true, false, 29), PeerReach::Punching);
        // Punch outstanding past the window with no handshake → unreachable (likely symmetric).
        assert_eq!(classify_reach(true, false, 30), PeerReach::Unreachable);
        assert_eq!(classify_reach(true, false, 120), PeerReach::Unreachable);
    }
}
