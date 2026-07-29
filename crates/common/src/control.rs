//! Control-socket protocol (design.md §3.2, §8): the newline-delimited JSON an unprivileged
//! frontend (CLI, iced GUI) exchanges with the privileged engine daemon.
//!
//! Pure wire types only — the engine owns the server, each frontend its own client transport
//! (Unix socket now, Windows named pipe later). Shared here so frontends need not depend on the
//! engine crate.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::api::{ManageOp, ManageResp, NetworkStatus};

mod expose;
pub use expose::{ExposeOp, ExposeResp, ExposeScope, ExposedPort, Proto, RemoveScope};

/// The Windows SCM service key the engine installs itself under. Shared so the engine (installer +
/// SCM entry point) and the GUI (status query + start/stop) address the same service.
pub const WINDOWS_SERVICE_NAME: &str = "UnityLANEngine";

/// The Windows SCM service key the **TLS proxy** is registered under.
///
/// A second service rather than a child process: the engine runs as LocalSystem, and spawning a
/// process as a *different* account from there needs a logon token it has no way to obtain. Letting
/// the SCM own that — the proxy service runs as `NT AUTHORITY\LocalService` — keeps the engine as
/// the supervisor (it starts and stops it) while the platform does the part only it can.
pub const WINDOWS_PROXY_SERVICE_NAME: &str = "UnityLANProxy";

/// The Windows named-pipe name for a control socket path — `unitylan-<file stem>`, which
/// `interprocess` maps to `\\.\pipe\unitylan-<stem>`. The engine derives it from its configured
/// `control_socket`, each frontend from the path it was pointed at; shared here so the two sides
/// can't drift and a default `control.sock` everywhere agrees on `unitylan-control`. `None` (no
/// path configured) yields the same name as an unset default.
pub fn pipe_name(control_socket: Option<&std::path::Path>) -> String {
    let stem = control_socket
        .and_then(|p| p.file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or("control");
    format!("unitylan-{stem}")
}

/// The **read-only** control endpoint beside a control socket path: `control.sock` →
/// `control-ro.sock`.
///
/// The TLS proxy reads its whole configuration off the control channel, and nothing else. It is also
/// the process most likely to be compromised — it parses HTTP sent by mesh peers — so it is pointed
/// at this second endpoint, which answers `Status` and `Watch` and refuses every mutation. The full
/// socket stays reachable only by the control group (unix) / SYSTEM, Administrators and INTERACTIVE
/// (Windows).
///
/// Derived rather than configured so both sides compute it from the one path they already agree on;
/// on Windows [`pipe_name`] of this path gives the matching `unitylan-control-ro` pipe.
pub fn readonly_endpoint(control_socket: &std::path::Path) -> std::path::PathBuf {
    let stem = control_socket
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("control");
    let ext = control_socket.extension().and_then(|s| s.to_str());
    let name = match ext {
        Some(ext) => format!("{stem}-ro.{ext}"),
        None => format!("{stem}-ro"),
    };
    control_socket.with_file_name(name)
}

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
    /// Opt this device in or out of holding a publicly-trusted TLS certificate for its mesh name.
    /// Handled locally (persisted, source of truth); the daemon reconciles on its next tick. Returns
    /// the updated [`StatusReport`].
    ///
    /// Off by default, and deliberately an explicit choice rather than something exposing a port
    /// implies: issuing publishes this device's name to public Certificate Transparency logs
    /// permanently, and turning it back off does not unpublish it.
    SetCertsEnabled {
        enabled: bool,
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

/// This device's TLS certificate state, for the GUI and `ctl cert`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertStatus {
    /// Whether the owner opted this device in ([`ControlRequest::SetCertsEnabled`]). Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// The deployment's certificate domain, when it issues certificates at all. `None` means the
    /// feature does not exist here and the toggle should not be offered.
    #[serde(default)]
    pub domain: Option<String>,
    /// The names the live certificate covers. Empty until one is issued.
    #[serde(default)]
    pub names: Vec<String>,
    /// Where the certificate and its key are on disk — what a headless server needs for its own
    /// config. Empty until one is issued.
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    /// `notAfter` of the live certificate (unix secs); `0` when there is none.
    #[serde(default)]
    pub expires_at: u64,
    /// Why there is no certificate yet, when there isn't one — "no port is exposed", the last error,
    /// or that a retry is backing off. `None` once one is held.
    #[serde(default)]
    pub blocked: Option<String>,
}

/// A snapshot of the daemon's live mesh state: this device plus the peers it has meshed with.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusReport {
    pub device: Option<DeviceStatus>,
    pub peers: Vec<PeerStatus>,
    /// What the TLS proxy should serve, when this device runs one. Empty means nothing to serve, in
    /// which case the proxy should not be holding a port at all.
    #[serde(default)]
    pub proxy_routes: Vec<ProxyRoute>,
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
    /// This device's TLS certificate: whether it is opted in, and what it currently holds. Absent
    /// from an older daemon, which reads as the feature being off.
    #[serde(default)]
    pub cert: CertStatus,
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
    Services,
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
            proxy_routes: Vec::new(),
            networks: Vec::new(),
            needs_login: false,
            connected: true,
            disable_new_networks: true,
            peer_own_devices: true,
            identity: None,
            // Off, matching the serde default: certificates are opt-in because issuing one is a
            // permanent, public disclosure of this device's name.
            cert: CertStatus::default(),
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
    /// The named services this peer announced to us over the tunnel, each already resolved to the
    /// name it answers to (`mc.alice.unity.internal`). Empty for a peer that announces none, that
    /// is offline, or that predates services.
    #[serde(default)]
    pub services: Vec<PeerService>,
}

/// The environment variable naming a listener descriptor the engine bound and handed to the proxy.
///
/// Unix only. There, 443 is privileged and the proxy runs unprivileged — deliberately, since it is
/// the process that parses HTTP from mesh peers — so it cannot take the port itself; the engine
/// binds it while it still can and passes the socket, leaving the proxy with no capability at all.
/// Windows has no privileged-port concept, so the proxy service binds its own listener and this is
/// never set there.
pub const PROXY_LISTEN_FD_VAR: &str = "UNITYLAN_PROXY_LISTEN_FD";

/// The port mesh peers reach web services on.
///
/// Fixed rather than configurable: it is what a browser assumes when someone types a bare name,
/// which is the whole point. Shared so the proxy binds the port the firewall opens.
pub const HTTPS_PORT: u16 = 443;

/// One web service the TLS proxy should serve: which names reach it, where to forward, and who is
/// allowed to.
///
/// Rides the existing [`StatusReport`] push rather than a channel of its own — the proxy needs
/// exactly the events the status already fires on (membership changed, a service was added, a
/// certificate was renewed), and a second subscription would be a second thing to keep in step. The
/// certificate paths are not repeated here: the proxy reads them from [`StatusReport::cert`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRoute {
    /// Every name this route answers to — the certificate-domain name and its `unity.internal`
    /// alias, because a person may type either. Lower-case, no trailing dot.
    pub hostnames: Vec<String>,
    /// The loopback port to forward to. Always loopback: forwarding anywhere else would make this a
    /// relay for whatever the backend can reach.
    pub port: u16,
    /// Who may reach it. `None` means the service's scope restricts nobody, so any mesh peer —
    /// which is anyone who can deliver to the mesh interface at all. `Some(list)` is exactly those
    /// addresses, and an **empty** list is nobody: a scope whose peers are all offline must stay
    /// closed rather than fall open, the same rule the firewall follows.
    #[serde(default)]
    pub allow: Option<Vec<Ipv4Addr>>,
}

/// One of a peer's services, as the frontend needs to show it: the full name it answers to, and
/// where to reach it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerService {
    /// The bare label the peer announced (`mc`).
    pub name: String,
    /// The name this resolves as — `<label>.<user>.unity.internal`, composed by *us* from the
    /// peer's verified user label, never taken from the peer.
    pub hostname: String,
    pub proto: Proto,
    pub port: u16,
    /// What kind of service it is. Decides how the name is *reached*: a `Web` one answers on 443
    /// through the owner's proxy, so `port` below is the loopback backend the proxy forwards to —
    /// a number nobody types. An engine from before this field reports `Port`, which is what every
    /// service was then.
    #[serde(default)]
    pub kind: crate::service::ServiceKind,
    /// False when another of the same owner's devices won this label — the service is announced but
    /// its name points elsewhere, which is worth showing rather than silently hiding.
    #[serde(default)]
    pub shadowed: bool,
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

/// How long a peer may go without a completed handshake before we call its path dead.
pub const STUCK_AFTER_SECS: u64 = 30;

/// Classify a peer's reachability from whether it needed a hole punch, whether a WG handshake has
/// completed, and how long we've been attempting the current path. Pure, so it's unit-testable.
///
/// `attempt_age_secs` counts from when we last had no handshake — for a punched peer that's the age
/// of the punch, for a directly-dialable one the age of the dial. Both go `Unreachable` once they
/// outlive the grace: a dialable endpoint that never handshakes is exactly as stuck as a punch that
/// never lands, and reporting it as `Direct` forever was how two peers behind one NAT whose router
/// won't hairpin ended up with no escalation to ICE and no diagnosis in status.
pub fn classify_reach(punched: bool, connected: bool, attempt_age_secs: u64) -> PeerReach {
    if connected {
        // Connected, directly or via a completed punch.
        PeerReach::Direct
    } else if attempt_age_secs >= STUCK_AFTER_SECS {
        PeerReach::Unreachable
    } else if punched {
        PeerReach::Punching
    } else {
        // A normal peer still bootstrapping, inside the grace window.
        PeerReach::Direct
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_reach, pipe_name, readonly_endpoint, ExposeOp, ExposeScope, PeerReach, Proto,
        RemoveScope, StatusReport,
    };

    /// The engine and every frontend derive the Windows pipe name from their own copy of the socket
    /// path; they only meet if that derivation is identical, so it lives here. The default path on
    /// both sides must land on `unitylan-control`.
    #[test]
    fn pipe_name_agrees_on_the_default_and_strips_the_extension() {
        assert_eq!(pipe_name(None), "unitylan-control");
        assert_eq!(
            pipe_name(Some(std::path::Path::new("control.sock"))),
            "unitylan-control"
        );
        // Only the file stem survives, so a full install path still names the same pipe. Spelled
        // with `/` because `Path` splits on the *host's* separator and this test also runs on unix.
        assert_eq!(
            pipe_name(Some(std::path::Path::new(
                "C:/ProgramData/UnityLAN/control.sock"
            ))),
            "unitylan-control"
        );
        assert_eq!(
            pipe_name(Some(std::path::Path::new("/run/unitylan/dev.sock"))),
            "unitylan-dev"
        );
    }

    /// The engine binds the read-only endpoint and the proxy connects to it, each deriving the name
    /// from the same control path — so they have to agree, on both transports.
    #[test]
    fn the_readonly_endpoint_sits_beside_the_control_socket_and_names_its_own_pipe() {
        let ro = readonly_endpoint(std::path::Path::new("/run/unitylan/control.sock"));
        assert_eq!(ro, std::path::Path::new("/run/unitylan/control-ro.sock"));
        assert_eq!(pipe_name(Some(&ro)), "unitylan-control-ro");
        // A custom socket name carries through, so a non-default deployment still agrees.
        assert_eq!(
            readonly_endpoint(std::path::Path::new("/run/unitylan/dev.sock")),
            std::path::Path::new("/run/unitylan/dev-ro.sock")
        );
        // No extension is a valid socket name too, and must not produce `control-ro.` .
        assert_eq!(
            readonly_endpoint(std::path::Path::new("/tmp/control")),
            std::path::Path::new("/tmp/control-ro")
        );
    }

    /// The scope a frontend sends must be the scope the engine acts on. Both spellings of each
    /// legacy scope decode, and every scope round-trips.
    #[test]
    fn expose_scope_round_trips_and_reads_the_legacy_spellings() {
        for scope in [
            ExposeScope::AllPeers,
            ExposeScope::OwnDevices,
            ExposeScope::Net {
                guild_id: 900_100,
                role_id: 7001,
            },
            ExposeScope::Unresolved {
                guild: None,
                name: "minecraft".into(),
            },
            ExposeScope::Unresolved {
                guild: Some("acme".into()),
                name: "minecraft".into(),
            },
        ] {
            let json = serde_json::to_string(&scope).expect("encodes");
            let back: ExposeScope = serde_json::from_str(&json).expect("decodes");
            assert_eq!(scope, back, "round-trip via {json}");
        }

        // What a pre-`ExposeScope` frontend puts on the wire.
        let all: ExposeScope = serde_json::from_str("null").expect("decodes legacy null");
        assert_eq!(all, ExposeScope::AllPeers);
        let net: ExposeScope = serde_json::from_str(r#""minecraft""#).expect("decodes legacy name");
        assert_eq!(
            net,
            ExposeScope::Unresolved {
                guild: None,
                name: "minecraft".into()
            }
        );
    }

    /// A network name is a Discord role's display name, so it may be any string — including one
    /// that collides with a scope keyword. The legacy forms are `null`/string and the modern one is
    /// an object, so a role named `own_devices` stays a *network*, not the own-device scope.
    #[test]
    fn a_role_named_like_a_keyword_is_still_a_network() {
        let scope: ExposeScope = serde_json::from_str(r#""own_devices""#).expect("decodes");
        assert_eq!(
            scope,
            ExposeScope::Unresolved {
                guild: None,
                name: "own_devices".into()
            }
        );
    }

    /// The compat contract with an engine that predates `ExposeScope`, asserted from that engine's
    /// point of view: it reads the `net` field as an `Option<String>`.
    ///
    /// `AllPeers`/`Net` must still parse there and mean the same thing. `OwnDevices` must **not**
    /// parse — an old engine has no own-device scope, and the only shape it could parse (`null`)
    /// would open the port to every peer, which is the opposite of what the user asked for. So the
    /// request has to be rejected rather than silently widened.
    #[test]
    fn own_devices_is_unparseable_to_an_old_engine_rather_than_silently_widened() {
        /// `ExposeOp::Add` as it was before this change.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct OldAdd {
            proto: Proto,
            port: u16,
            net: Option<String>,
        }

        let encode = |scope: ExposeScope| {
            let op = ExposeOp::Add {
                proto: Proto::Tcp,
                port: 8080,
                scope,
                name: None,
                kind: crate::service::ServiceKind::Port,
            };
            // Reach past the `ExposeOp` enum tag to the payload the old struct would see.
            let v = serde_json::to_value(&op).expect("encodes");
            v["Add"].clone()
        };

        let all = encode(ExposeScope::AllPeers);
        assert_eq!(all["net"], serde_json::Value::Null);
        assert!(serde_json::from_value::<OldAdd>(all)
            .expect("old engine parses all-peers")
            .net
            .is_none());

        let net = encode(ExposeScope::Unresolved {
            guild: None,
            name: "minecraft".into(),
        });
        assert_eq!(
            serde_json::from_value::<OldAdd>(net)
                .expect("old engine parses a network scope")
                .net
                .as_deref(),
            Some("minecraft"),
        );

        let own = encode(ExposeScope::OwnDevices);
        assert!(
            serde_json::from_value::<OldAdd>(own).is_err(),
            "an old engine must reject the own-device scope, not read it as all-peers",
        );

        // A guild-qualified network is likewise unrepresentable to an old engine. Degrading it to
        // the bare role name would re-introduce exactly the over-exposure the guild removes: that
        // engine keys its source set on the name, so it would admit every guild's same-named role.
        let qualified = encode(ExposeScope::Net {
            guild_id: 900_100,
            role_id: 7001,
        });
        assert!(
            serde_json::from_value::<OldAdd>(qualified).is_err(),
            "an old engine must reject a guild-qualified scope, not widen it to every guild",
        );
    }

    /// `Remove` carries a scope too, and an old *frontend* closing a port must keep working —
    /// failing to close is the unsafe direction (the port stays open).
    #[test]
    fn remove_reads_the_legacy_scope_spellings() {
        let all: RemoveScope =
            serde_json::from_str(r#"{"Exact":null}"#).expect("decodes legacy all-peers");
        assert!(matches!(all, RemoveScope::Exact(ExposeScope::AllPeers)));
        let net: RemoveScope =
            serde_json::from_str(r#"{"Exact":"minecraft"}"#).expect("decodes legacy network");
        assert!(matches!(
            net,
            RemoveScope::Exact(ExposeScope::Unresolved { guild: None, name }) if name == "minecraft"
        ));
    }

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
        // A *dialable* peer that never handshakes is stuck too — the same-NAT/no-hairpin case. It
        // reads Direct inside the grace, then Unreachable, which is what escalates it to ICE.
        assert_eq!(classify_reach(false, false, 29), PeerReach::Direct);
        assert_eq!(classify_reach(false, false, 30), PeerReach::Unreachable);
        assert_eq!(classify_reach(false, false, 600), PeerReach::Unreachable);
    }
}
