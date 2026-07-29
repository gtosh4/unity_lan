//! UnityLAN GUI (M4): an unprivileged iced desktop app driving the engine over its control
//! socket. Shows live mesh status (this device + peers) and manages the owner's devices
//! (rename / set-primary / remove). Auto-refreshes every 2s. The mesh keeps running when the
//! window closes — this is a viewer/controller, not the engine.
//!
//! Usage: `unitylan-gui [control.sock]` (default: `control.sock` in the working directory).
//! Also surfaces per-network peering toggles, port expose/unexpose, and Discord OAuth login —
//! all over the same control socket.

// Release Windows builds detach from the console so launching the GUI (shortcut/Explorer) doesn't
// flash a terminal. Debug keeps the console for logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ctl;
mod instance;
mod tray;
mod view;
mod widgets;

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::api::{DeviceInfo, ManageOp, ManageResp};
use common::control::{
    ConnectedResp, ExposeOp, ExposeResp, ExposeScope, ExposedPort, LoginResp, NetworkResp, Proto,
    RemoveScope, StatusReport,
};
use common::service::ServiceKind;
use iced::window;
use iced::{Subscription, Task, Theme};
use tokio::sync::mpsc::UnboundedReceiver;
use tray::TrayMsg;
use view::parse_port;

/// The app icon (titlebar + taskbar/dock while running), rendered from the shared squircle SVG via
/// resvg. Straight-alpha RGBA is what winit's `from_rgba` wants; `None` if rendering ever fails so a
/// missing icon never blocks the window from opening.
fn app_icon() -> Option<window::Icon> {
    use resvg::{tiny_skia, usvg};

    const SVG: &str = include_str!("../../../assets/icon.svg");
    const N: u32 = 256;

    let tree = usvg::Tree::from_str(SVG, &usvg::Options::default()).ok()?;
    let mut pixmap = tiny_skia::Pixmap::new(N, N)?;
    let scale = N as f32 / 100.0; // icon.svg is a 0..100 viewBox
    resvg::render(
        &tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );

    let mut px = pixmap.take();
    for p in px.chunks_exact_mut(4) {
        let a = p[3] as u32;
        for c in &mut p[..3] {
            *c = (*c as u32 * 255).checked_div(a).map_or(0, |v| v.min(255)) as u8;
        }
    }
    window::icon::from_rgba(px, N, N).ok()
}

/// The main window's settings. `exit_on_close_request(false)` so the close button hits our
/// `CloseRequested` handler (hide-to-tray) instead of destroying the window out from under us.
fn window_settings() -> window::Settings {
    #[allow(unused_mut)]
    let mut settings = window::Settings {
        size: iced::Size::new(440.0, 640.0),
        position: window::Position::Centered,
        exit_on_close_request: false,
        icon: app_icon(),
        ..Default::default()
    };
    // On Wayland the compositor derives the titlebar/taskbar icon from the window's app_id → the
    // matching `.desktop` file (client-set icons are a no-op there), so this must equal the
    // installed `unitylan-gui.desktop` basename. Harmless on X11/Windows, which use `icon` above.
    #[cfg(target_os = "linux")]
    {
        settings.platform_specific.application_id = "unitylan-gui".to_string();
    }
    settings
}

fn main() -> iced::Result {
    #[cfg(windows)]
    clean_stale_gui();
    let socket = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "control.sock".to_string()),
    );
    // Single-instance guard: only one GUI per engine socket. A second launch signals the running
    // one to surface its window (below) and exits here without opening a duplicate.
    let activate_rx = match instance::start(&socket) {
        instance::Startup::AlreadyRunning => return Ok(()),
        instance::Startup::Primary(rx) => Some(rx),
        instance::Startup::Unsupported => None,
    };
    // Spawn the system tray on its own thread before iced takes over the main event loop; it drives
    // connect/disconnect + reflects status over the socket itself, and hands window/quit requests
    // back to us over this channel.
    let tray_rx = tray::spawn(socket.clone());
    // `daemon` (not `application`) so the process survives with zero windows: hide-to-tray destroys
    // the window and show reopens a fresh one — the only way to truly leave the taskbar on Wayland,
    // where winit can't unmap a surface. Quit (from the tray) is the real exit.
    iced::daemon("UnityLAN", App::update, App::view)
        .subscription(App::subscription)
        .theme(|_, _| Theme::Dark)
        .run_with(move || {
            let mut app = App::new(socket);
            *app.tray_rx.lock().unwrap() = tray_rx;
            *app.activate_rx.lock().unwrap() = activate_rx;
            let open = app.open_window();
            let init = Task::batch([open, app.reload()]);
            (app, init)
        })
}

/// Launch a fresh GUI process onto the updated binary (the caller then exits, handing over). Passes
/// the same socket argument this instance runs with, so the successor talks to the same engine.
///
/// The privileged engine has already put the new bytes on disk by the time we're prompted to
/// restart: on Unix it swapped `unitylan-gui` in place, and on Windows it renamed the running
/// `unitylan-gui.exe` aside to `.old.exe` and moved the new binary into the canonical name (the GUI
/// can't do this itself — the install dir is admin-only). So we relaunch the **canonical path**, not
/// `current_exe()`: on Windows our own image may now be the renamed-aside `.old.exe`, and spawning
/// that would just relaunch the old version.
fn relaunch_successor(socket: &Path) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    #[cfg(windows)]
    let exe = exe
        .parent()
        .map(|d| d.join("unitylan-gui.exe"))
        .unwrap_or(exe);
    std::process::Command::new(&exe).arg(socket).spawn()?;
    Ok(())
}

/// Best-effort cleanup of the image the engine renamed aside when it promoted our replacement — only
/// deletable once we're no longer running from it, i.e. from the successor at startup.
#[cfg(windows)]
fn clean_stale_gui() {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let _ = std::fs::remove_file(dir.join("unitylan-gui.old.exe"));
        }
    }
}

struct App {
    socket: PathBuf,
    status: Option<StatusReport>,
    devices: Vec<DeviceInfo>,
    exposed: Vec<ExposedPort>,
    /// Draft text for the device-rename field, and whether the rename is armed. Armed turns this
    /// device's row in the device list *into* the field, so the thing being renamed and the box
    /// you type in are the same row.
    rename_input: String,
    renaming: bool,
    /// Which service's "offer it to another network" picker is open, if any. One at a time, by name.
    widening: Option<String>,
    /// Draft text for the expose port field.
    expose_port_input: String,
    /// Draft protocol for the exposure being composed.
    expose_proto: Proto,
    /// Scopes ticked for the exposure being composed. One `Add` op is sent per scope — the wire
    /// carries one scope per exposure, and keeping them separate is what lets the user close one
    /// later without touching the others.
    expose_scopes: Vec<ExposeScope>,
    /// Whether the scope picker is expanded.
    expose_scope_open: bool,
    /// Whether the user has chosen a tab themselves. Until they do, [`App::settle_tab`] moves it as
    /// the mesh's state arrives.
    tab_picked: bool,
    /// Whether the service being composed is a web service — its name goes into this device's
    /// certificate, and so into public Certificate Transparency logs, permanently.
    service_web: bool,
    /// Draft name for the service being composed. Shares the port/proto/scope drafts with the
    /// exposure form: a service *is* an exposure with a name, and two parallel drafts of the same
    /// thing would only be two things to keep in step.
    service_name_input: String,
    /// The Discord authorize URL after the user clicks "Log in", shown for them to open.
    login_url: Option<String>,
    /// A mesh connect/disconnect is in flight — disables the button meanwhile.
    connect_busy: bool,
    /// A pending destructive action awaiting a second confirming click (remove device / log out).
    confirm: Option<Confirm>,
    /// Which peer's action menu (kebab dropdown) is open, by that device's WireGuard IP; `None` when
    /// closed.
    menu_open: Option<Ipv4Addr>,
    /// Which content tab is showing (below the always-visible status strip).
    tab: Tab,
    /// Peer groups the user has collapsed (click the group header to toggle). Seeded with `Offline`
    /// so a large mesh's dead peers stay folded away by default.
    collapsed_groups: HashSet<PeerGroup>,
    /// Smoothed (EWMA) latency per peer, keyed by WG IP, used *only* to order the peer list. The
    /// number shown in the row stays the latest raw RTT — ordering off that raw value reshuffled
    /// near-equal peers every poll as per-probe jitter crossed them, so the list flickered.
    latency_ewma: HashMap<Ipv4Addr, u32>,
    /// The last action error, shown as a banner until the next action clears it.
    error: Option<String>,
    /// Window/quit requests from the tray thread, consumed once by the subscription (`None` when
    /// there's no tray on this platform / system).
    tray_rx: Arc<Mutex<Option<UnboundedReceiver<TrayMsg>>>>,
    /// "Show yourself" nudges from a second launch that found us already running, consumed once by
    /// the subscription (`None` when single-instance isn't supported here).
    activate_rx: Arc<Mutex<Option<UnboundedReceiver<()>>>>,
    /// The main window's id while it's open; `None` while hidden to the tray (the window is
    /// destroyed, not just hidden — see [`window_settings`]). Show reopens a fresh one.
    window: Option<window::Id>,
    /// Highest engine UI-directive `seq` already applied, so a re-poll of the same status doesn't
    /// re-fire it. Debug builds only — release builds don't honor directives (see
    /// [`common::control::StatusReport::directive`]).
    #[cfg(debug_assertions)]
    last_directive_seq: u64,
}

/// Content tabs shown under the persistent connection header. Networks = the ACL groups this
/// device peers on; Peers = this device + the live mesh members; Manage = device + port admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Networks,
    Peers,
    /// Named ports across the mesh — what people actually came to reach.
    Services,
    Manage,
}

/// The three collapsible groups the peers list is split into. "My devices" is the owner's other
/// devices (peered via own-device peering); the rest are co-members, split by liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PeerGroup {
    Mine,
    Online,
    Offline,
}

impl PeerGroup {
    fn title(self) -> &'static str {
        match self {
            PeerGroup::Mine => "my devices",
            PeerGroup::Online => "online",
            PeerGroup::Offline => "offline",
        }
    }
}

/// A destructive action armed by a first click; the second click on the confirm control runs it.
#[derive(Debug, Clone, PartialEq)]
enum Confirm {
    RemoveDevice(String),
    Logout,
    /// Block a peer's owner (all their devices) — armed by `user_id`, shown as a modal. `username`
    /// is carried for the modal's prompt.
    BlockPeer {
        user_id: u64,
        username: String,
    },
}

#[derive(Debug, Clone)]
enum Message {
    /// Timer tick → refetch status + device list + exposed ports.
    Tick,
    StatusFetched(Result<StatusReport, String>),
    /// Result of a `List` (or any manage op) → the owner's devices.
    DevicesFetched(Result<ManageResp, String>),
    /// Result of an expose/unexpose/list → the exposed ports.
    ExposesFetched(Result<ExposeResp, String>),
    /// Arm the rename, seeded with the current name so editing beats retyping.
    StartRename(String),
    CancelRename,
    RenameInput(String),
    RenameSubmit,
    SetPrimary(String),
    Remove(String),
    ExposePortInput(String),
    /// Pick TCP or UDP for the exposure being composed.
    ExposeProto(Proto),
    /// Open/close the scope picker.
    ExposeScopeToggleOpen,
    /// Tick (`true`) or untick a scope. Several may be ticked at once — one `Add` op is sent per
    /// scope. There is no all-peers entry to be exclusive with any more; see `selectable_scopes`.
    ExposeScopeToggle(ExposeScope, bool),
    ServiceNameInput(String),
    ServiceWeb(bool),
    ServiceSubmit,
    RemoveService(String),
    /// Open the "offer this to another network" picker for a service, or close it. Carries the
    /// service name, so opening one closes any other — two open pickers under different services
    /// would leave no way to tell which network you were about to hand a service to.
    WidenOpen(Option<String>),
    /// Offer an existing service to one more scope, on every port it already runs on.
    Widen {
        name: String,
        scope: ExposeScope,
    },
    Unexpose {
        proto: Proto,
        port: u16,
        /// Which exposure(s) of that port to close: one scope's chip, or the whole row.
        scope: RemoveScope,
    },
    /// Toggle this device's peering on a network (role@guild).
    ToggleNetwork {
        guild_id: u64,
        role_id: u64,
        enabled: bool,
    },
    NetworkToggled(Result<NetworkResp, String>),
    /// Start interactive login; the daemon returns the Discord authorize URL to open.
    Login,
    LoginStarted(Result<LoginResp, String>),
    /// Log out: tear down the mesh, un-enroll, and re-key. The daemon returns to not-logged-in.
    Logout,
    LoggedOut(Result<String, String>),
    /// Apply the staged auto-update: the engine downloads + verifies + swaps + restarts.
    ApplyUpdate,
    /// The apply request was acked (or failed) — the engine restarts shortly after on success.
    UpdateStarted(Result<String, String>),
    /// Close this window and re-exec our (now-swapped) binary, finishing an update that already
    /// replaced the engine + GUI on disk. Only offered once we detect the engine runs a newer version.
    Relaunch,
    /// Open a URL in the default browser (re-open the authorize link on demand).
    OpenUrl(String),
    /// Copy arbitrary text to the clipboard (an authorize link, a peer's hostname + IP).
    CopyText(String),
    /// Connect (`true`) / disconnect (`false`) the mesh over the control socket.
    SetConnected(bool),
    /// A mesh connect/disconnect finished → refresh.
    ConnectedDone(Result<ConnectedResp, String>),
    /// Set whether networks discovered from now on default to disabled (secure) or enabled.
    SetNewNetworkDefault(bool),
    /// The new-network default was set → the daemon returns the updated status.
    NewNetworkDefaultSet(Result<StatusReport, String>),
    /// Set whether this device always peers with the owner's own other devices.
    SetOwnDevicePeering(bool),
    /// Own-device peering was set → the daemon returns the updated status.
    OwnDevicePeeringSet(Result<StatusReport, String>),
    /// Opt this device in or out of holding a publicly-trusted TLS certificate for its mesh name.
    SetCertsEnabled(bool),
    /// Certificate opt-in was set → the daemon returns the updated status.
    CertsEnabledSet(Result<StatusReport, String>),
    /// Locally block a peer's owner (all their devices) by Discord `user_id`.
    BlockPeer {
        user_id: u64,
        username: String,
    },
    /// Un-block a previously-blocked user.
    UnblockPeer {
        user_id: u64,
    },
    /// A block/un-block finished → the daemon returns the updated status.
    BlockDone(Result<StatusReport, String>),
    /// Arm a destructive action: show its inline confirm/cancel controls.
    AskConfirm(Confirm),
    /// Dismiss the armed destructive action without running it.
    CancelConfirm,
    /// Toggle a peer's action menu (kebab dropdown) open/closed, keyed by that device's WireGuard IP.
    ToggleMenu(Ipv4Addr),
    /// Close any open peer action menu (a click landed outside it).
    CloseMenu,
    /// Dismiss the current error banner.
    DismissError,
    /// Switch the visible content tab.
    SelectTab(Tab),
    /// Collapse/expand a peer group (my devices / online / offline).
    TogglePeerGroup(PeerGroup),
    /// A window/quit request from the system tray.
    Tray(TrayMsg),
    /// A second launch asked us (the running instance) to surface our window.
    Activate,
    /// The window's close button was pressed → hide to the tray instead of exiting.
    CloseRequested,
    /// A freshly-opened window finished opening → focus it.
    WindowOpened(window::Id),
}

impl App {
    fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            status: None,
            devices: Vec::new(),
            exposed: Vec::new(),
            rename_input: String::new(),
            renaming: false,
            widening: None,
            expose_port_input: String::new(),
            expose_proto: Proto::Tcp,
            expose_scopes: Vec::new(),
            service_name_input: String::new(),
            service_web: false,
            expose_scope_open: false,
            tab_picked: false,
            login_url: None,
            connect_busy: false,
            confirm: None,
            menu_open: None,
            tab: Tab::default(),
            collapsed_groups: HashSet::from([PeerGroup::Offline]),
            latency_ewma: HashMap::new(),
            error: None,
            tray_rx: Arc::new(Mutex::new(None)),
            activate_rx: Arc::new(Mutex::new(None)),
            window: None,
            #[cfg(debug_assertions)]
            last_directive_seq: 0,
        }
    }

    /// Apply a UI directive the engine pushed on the status poll (demo/testing only — a real engine
    /// never sets one). Debug builds only; release builds don't compile this. Each directive fires
    /// once, guarded by its monotonic `seq`. Maps to UI-only state, never mesh state.
    #[cfg(debug_assertions)]
    fn apply_directive(&mut self, s: &StatusReport) {
        use common::control::{UiAction, UiTab};
        let Some(d) = &s.directive else { return };
        if d.seq <= self.last_directive_seq {
            return;
        }
        self.last_directive_seq = d.seq;
        match &d.action {
            UiAction::SelectTab(t) => {
                // A directive is the script standing in for a person, so it counts as a choice:
                // without this, `settle_tab` would pull the tour's selection straight back to
                // whatever the fixtures rank highest, and the recording would fight itself.
                self.tab_picked = true;
                self.tab = match t {
                    UiTab::Networks => Tab::Networks,
                    UiTab::Peers => Tab::Peers,
                    UiTab::Services => Tab::Services,
                    UiTab::Manage => Tab::Manage,
                }
            }
            UiAction::OpenPeerMenu(ip) => self.menu_open = Some(*ip),
            UiAction::CloseMenu => self.menu_open = None,
            UiAction::ArmBlockPeer(id) => {
                self.menu_open = None;
                let username = s
                    .peers
                    .iter()
                    .find(|p| p.user_id == *id)
                    .map(|p| p.username.clone())
                    .unwrap_or_default();
                self.confirm = Some(Confirm::BlockPeer {
                    user_id: *id,
                    username,
                });
            }
            UiAction::Cancel => self.confirm = None,
        }
    }

    /// Fold each peer's latest RTT into its EWMA (α = 1/4) so the sort order settles instead of
    /// chasing per-poll jitter, and drop peers no longer in the report. Peers with no reply this
    /// poll keep their last smoothed value; ones that never replied simply have no entry.
    fn smooth_latencies(&mut self, s: &StatusReport) {
        let live: HashSet<Ipv4Addr> = s.peers.iter().map(|p| p.wg_ip).collect();
        self.latency_ewma.retain(|ip, _| live.contains(ip));
        for p in &s.peers {
            if let Some(ms) = p.latency_ms {
                self.latency_ewma
                    .entry(p.wg_ip)
                    .and_modify(|e| *e = (*e * 3 + ms) / 4)
                    .or_insert(ms);
            }
        }
    }

    /// Open the main window, recording its id. Used at boot and to restore from the tray.
    fn open_window(&mut self) -> Task<Message> {
        let (id, task) = window::open(window_settings());
        self.window = Some(id);
        task.map(Message::WindowOpened)
    }

    /// Hide to the tray by destroying the window (the only way off the taskbar on Wayland). The
    /// process stays alive because we run as an iced `daemon`. No-op if already hidden.
    fn hide_window(&mut self) -> Task<Message> {
        match self.window.take() {
            Some(id) => window::close(id),
            None => Task::none(),
        }
    }

    /// Open on the tab that has something to show, until the user picks one themselves.
    ///
    /// Networks is the right landing spot for someone who has just joined and has nothing else yet,
    /// but it is the least interesting tab for everyone else — a settled mesh wants Peers, and a
    /// device that serves or reaches services wants Services. The state that decides this does not
    /// all arrive at once (a peer's services take a poll to show up), so this runs on each update.
    ///
    /// **Only ever moves up the ranking.** Re-deciding freely would let a tab slide out from under
    /// someone mid-read as a late poll lands, and worse, oscillate when a peer drops. Monotonic
    /// means it settles once and stays.
    fn settle_tab(&mut self) {
        if self.tab_picked {
            return;
        }
        let rank = |t: Tab| match t {
            Tab::Services => 2,
            Tab::Peers => 1,
            _ => 0,
        };
        let peers = self.status.as_ref().is_some_and(|s| !s.peers.is_empty());
        let services = self.exposed.iter().any(|e| e.name.is_some())
            || self
                .status
                .as_ref()
                .is_some_and(|s| s.peers.iter().any(|p| !p.services.is_empty()));
        let want = match (services, peers) {
            (true, _) => Tab::Services,
            (false, true) => Tab::Peers,
            (false, false) => Tab::Networks,
        };
        if rank(want) > rank(self.tab) {
            self.tab = want;
        }
    }

    /// Fetch the device list + exposed ports concurrently. Status isn't polled here — it arrives
    /// over the live `watch_status` subscription (see [`Self::status_subscription`]), which pushes a
    /// fresh snapshot the instant the engine's state changes.
    fn reload(&self) -> Task<Message> {
        Task::batch([
            Task::perform(
                ctl::manage(self.socket.clone(), ManageOp::List),
                Message::DevicesFetched,
            ),
            Task::perform(
                ctl::expose(self.socket.clone(), ExposeOp::List),
                Message::ExposesFetched,
            ),
        ])
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => return self.reload(),
            Message::StatusFetched(Ok(s)) => {
                #[cfg(debug_assertions)]
                self.apply_directive(&s);
                self.smooth_latencies(&s);
                self.status = Some(s);
                self.error = None;
                self.settle_tab();
            }
            Message::StatusFetched(Err(e)) => self.error = Some(e),
            Message::DevicesFetched(Ok(r)) => {
                self.devices = r.devices;
                self.error = None;
            }
            Message::DevicesFetched(Err(e)) => self.error = Some(e),
            Message::ExposesFetched(Ok(r)) => {
                self.exposed = r.exposed;
                self.error = None;
                self.settle_tab();
            }
            Message::ExposesFetched(Err(e)) => self.error = Some(e),
            Message::ExposePortInput(s) => self.expose_port_input = s,
            Message::ExposeProto(p) => self.expose_proto = p,
            Message::ExposeScopeToggleOpen => {
                self.expose_scope_open = !self.expose_scope_open;
            }
            Message::ExposeScopeToggle(scope, on) => {
                self.expose_scopes.retain(|s| *s != scope);
                if on {
                    self.expose_scopes.push(scope);
                }
            }
            Message::ServiceNameInput(s) => self.service_name_input = s,
            Message::ServiceWeb(v) => self.service_web = v,
            Message::ServiceSubmit => {
                let name = self.service_name_input.trim().to_string();
                if !common::service::valid_label(&name) {
                    self.error = Some(common::service::label_error(&name));
                    return Task::none();
                }
                let port = match parse_port(self.expose_port_input.trim()) {
                    Ok(p) => p,
                    Err(e) => {
                        self.error = Some(e);
                        return Task::none();
                    }
                };
                if self.expose_scopes.is_empty() {
                    self.error = Some("pick who can reach this service".into());
                    return Task::none();
                }
                let proto = self.expose_proto;
                let socket = self.socket.clone();
                let kind = if self.service_web {
                    ServiceKind::Web
                } else {
                    ServiceKind::Port
                };
                let ops: Vec<Task<Message>> = self
                    .expose_scopes
                    .drain(..)
                    .map(|scope| {
                        Task::perform(
                            ctl::expose(
                                socket.clone(),
                                ExposeOp::Add {
                                    proto,
                                    port,
                                    scope,
                                    name: Some(name.clone()),
                                    kind,
                                },
                            ),
                            Message::ExposesFetched,
                        )
                    })
                    .collect();
                self.expose_port_input.clear();
                self.service_name_input.clear();
                self.service_web = false;
                self.expose_scope_open = false;
                return Task::batch(ops);
            }
            Message::RemoveService(name) => {
                return Task::perform(
                    ctl::expose(self.socket.clone(), ExposeOp::RemoveNamed { name }),
                    Message::ExposesFetched,
                );
            }
            Message::WidenOpen(name) => self.widening = name,
            Message::Widen { name, scope } => {
                // Closes on the way out: the picker offers scopes the service lacks, and the one
                // just picked is about to stop being one of them.
                self.widening = None;
                return Task::perform(
                    ctl::expose(self.socket.clone(), ExposeOp::AddScopeNamed { name, scope }),
                    Message::ExposesFetched,
                );
            }
            Message::Unexpose { proto, port, scope } => {
                return Task::perform(
                    ctl::expose(self.socket.clone(), ExposeOp::Remove { proto, port, scope }),
                    Message::ExposesFetched,
                );
            }
            Message::ToggleNetwork {
                guild_id,
                role_id,
                enabled,
            } => {
                return Task::perform(
                    ctl::set_network(self.socket.clone(), guild_id, role_id, enabled),
                    Message::NetworkToggled,
                )
            }
            Message::NetworkToggled(Ok(_)) => {
                self.error = None;
                return self.reload(); // pull the updated networks + peers immediately
            }
            Message::NetworkToggled(Err(e)) => self.error = Some(e),
            Message::Login => {
                return Task::perform(ctl::login(self.socket.clone()), Message::LoginStarted)
            }
            Message::LoginStarted(Ok(r)) => {
                if !cfg!(test) {
                    let _ = open::that(&r.authorize_url); // best-effort auto-open; link stays for manual use
                }
                self.login_url = Some(r.authorize_url);
                self.error = None;
            }
            Message::LoginStarted(Err(e)) => self.error = Some(e),
            Message::Logout => {
                self.confirm = None; // consume the armed confirmation
                self.login_url = None; // drop any stale authorize link
                return Task::perform(ctl::logout(self.socket.clone()), Message::LoggedOut);
            }
            Message::LoggedOut(res) => {
                self.error = res.err();
                return self.reload(); // pull the settled (logged-out) state once teardown lands
            }
            Message::ApplyUpdate => {
                self.confirm = None; // consume the armed confirmation
                return Task::perform(
                    ctl::apply_update(self.socket.clone()),
                    Message::UpdateStarted,
                );
            }
            Message::UpdateStarted(res) => {
                // On success the engine restarts shortly (socket drops → the poll reconnects onto the
                // new version). Surface only a failure; success needs no banner.
                self.error = res.err();
            }
            Message::Relaunch => {
                // Launch a fresh GUI onto the new binary, then exit this old process. Best-effort — if
                // it fails, keep the window up and report it rather than quitting into nothing.
                match relaunch_successor(&self.socket) {
                    Ok(()) => return iced::exit(),
                    Err(e) => self.error = Some(format!("could not relaunch: {e}")),
                }
            }
            Message::OpenUrl(url) => {
                if !cfg!(test) {
                    let _ = open::that(&url);
                }
            }
            Message::CopyText(s) => {
                self.menu_open = None; // copied from the peer menu → dismiss it
                return iced::clipboard::write(s);
            }
            Message::SetConnected(connected) => {
                self.connect_busy = true;
                return Task::perform(
                    ctl::set_connected(self.socket.clone(), connected),
                    Message::ConnectedDone,
                );
            }
            Message::ConnectedDone(res) => {
                self.connect_busy = false;
                self.error = res.err();
                return self.reload(); // pull the settled connection state + peers
            }
            Message::SetNewNetworkDefault(disable) => {
                return Task::perform(
                    ctl::set_new_network_default(self.socket.clone(), disable),
                    Message::NewNetworkDefaultSet,
                )
            }
            Message::NewNetworkDefaultSet(Ok(s)) => {
                self.status = Some(s);
                self.error = None;
            }
            Message::NewNetworkDefaultSet(Err(e)) => self.error = Some(e),
            Message::SetOwnDevicePeering(enabled) => {
                return Task::perform(
                    ctl::set_own_device_peering(self.socket.clone(), enabled),
                    Message::OwnDevicePeeringSet,
                )
            }
            Message::OwnDevicePeeringSet(Ok(s)) => {
                self.status = Some(s);
                self.error = None;
            }
            Message::OwnDevicePeeringSet(Err(e)) => self.error = Some(e),
            Message::SetCertsEnabled(enabled) => {
                return Task::perform(
                    ctl::set_certs_enabled(self.socket.clone(), enabled),
                    Message::CertsEnabledSet,
                )
            }
            Message::CertsEnabledSet(Ok(s)) => {
                self.status = Some(s);
                self.error = None;
            }
            Message::CertsEnabledSet(Err(e)) => self.error = Some(e),
            Message::BlockPeer { user_id, username } => {
                self.confirm = None; // consume the armed confirmation
                return Task::perform(
                    ctl::block_peer(self.socket.clone(), user_id, username),
                    Message::BlockDone,
                );
            }
            Message::UnblockPeer { user_id } => {
                return Task::perform(
                    ctl::unblock_peer(self.socket.clone(), user_id),
                    Message::BlockDone,
                )
            }
            Message::BlockDone(Ok(s)) => {
                self.status = Some(s);
                self.error = None;
                return self.reload(); // pull the settled peer set once the re-mesh lands
            }
            Message::BlockDone(Err(e)) => self.error = Some(e),
            Message::Tray(TrayMsg::ToggleWindow) => {
                // Toggle: destroy the window if shown, reopen it if hidden to the tray.
                return if self.window.is_some() {
                    self.hide_window()
                } else {
                    self.open_window()
                };
            }
            Message::Tray(TrayMsg::Quit) => return iced::exit(),
            Message::Activate => {
                // A duplicate launch wants the existing window shown. Never hide (unlike the tray's
                // toggle). If it was hidden to the tray, reopen it. If it's already up, un-minimize
                // and ask to focus + flag for attention: X11/Windows raise it outright, while
                // Wayland refuses a cross-process raise (focus-stealing prevention) and instead
                // highlights the taskbar entry for the user to click — the standard behavior there.
                return match self.window {
                    None => self.open_window(),
                    Some(id) => Task::batch([
                        window::minimize(id, false),
                        window::gain_focus(id),
                        window::request_user_attention(id, Some(window::UserAttention::Critical)),
                    ]),
                };
            }
            Message::CloseRequested => return self.hide_window(),
            Message::WindowOpened(id) => return window::gain_focus(id),
            Message::StartRename(current) => {
                self.rename_input = current;
                self.renaming = true;
            }
            Message::CancelRename => {
                self.renaming = false;
                self.rename_input.clear();
            }
            Message::RenameInput(s) => self.rename_input = s,
            Message::RenameSubmit => {
                let name = self.rename_input.trim().to_string();
                if !name.is_empty() {
                    self.rename_input.clear();
                    self.renaming = false;
                    return Task::perform(
                        ctl::manage(self.socket.clone(), ManageOp::Rename { new_name: name }),
                        Message::DevicesFetched,
                    );
                }
            }
            Message::SetPrimary(device_name) => {
                return Task::perform(
                    ctl::manage(self.socket.clone(), ManageOp::SetPrimary { device_name }),
                    Message::DevicesFetched,
                )
            }
            Message::Remove(device_name) => {
                self.confirm = None; // consume the armed confirmation
                return Task::perform(
                    ctl::manage(self.socket.clone(), ManageOp::Remove { device_name }),
                    Message::DevicesFetched,
                );
            }
            Message::AskConfirm(c) => {
                self.menu_open = None; // an action was chosen from the menu (or elsewhere)
                self.confirm = Some(c);
            }
            Message::CancelConfirm => self.confirm = None,
            Message::ToggleMenu(id) => {
                self.menu_open = if self.menu_open == Some(id) {
                    None
                } else {
                    Some(id)
                };
            }
            Message::CloseMenu => self.menu_open = None,
            Message::DismissError => self.error = None,
            Message::SelectTab(t) => {
                self.tab = t;
                // From here the tab is theirs; nothing arriving later moves it.
                self.tab_picked = true;
            }
            Message::TogglePeerGroup(g) => {
                if !self.collapsed_groups.remove(&g) {
                    self.collapsed_groups.insert(g);
                }
            }
        }
        Task::none()
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            // Status is pushed live over `watch_status`; the timer only refreshes the device list
            // and exposed ports (which change rarely and aren't part of the status snapshot).
            iced::time::every(Duration::from_secs(2)).map(|_| Message::Tick),
            self.status_subscription(),
            window::close_requests().map(|_| Message::CloseRequested),
            self.tray_subscription(),
            self.instance_subscription(),
        ])
    }

    /// Live status push: a long-lived `Watch` subscription that emits a `StatusFetched` every time
    /// the engine's status changes (and reconnects itself if the engine restarts), so the UI
    /// reflects connect/peer/login changes instantly instead of on the next poll.
    fn status_subscription(&self) -> Subscription<Message> {
        use iced::futures::StreamExt;
        Subscription::run_with_id(
            "unitylan-status",
            ctl::watch_status(self.socket.clone()).map(Message::StatusFetched),
        )
    }

    /// Bridge the tray thread's channel into the iced runtime. The receiver is taken once (on the
    /// first call); later calls return an empty stream with the same id, so iced keeps the original
    /// running instead of restarting it.
    fn tray_subscription(&self) -> Subscription<Message> {
        use iced::futures::stream::{self, BoxStream, StreamExt};
        let taken = self.tray_rx.lock().unwrap().take();
        let stream: BoxStream<'static, Message> = match taken {
            Some(rx) => stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|m| (Message::Tray(m), rx))
            })
            .boxed(),
            None => stream::empty().boxed(),
        };
        Subscription::run_with_id("unitylan-tray", stream)
    }

    /// Bridge the single-instance accept thread's channel into the iced runtime, same one-shot-take
    /// pattern as [`Self::tray_subscription`]. Each item is a second launch asking us to surface.
    fn instance_subscription(&self) -> Subscription<Message> {
        use iced::futures::stream::{self, BoxStream, StreamExt};
        let taken = self.activate_rx.lock().unwrap().take();
        let stream: BoxStream<'static, Message> = match taken {
            Some(rx) => stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|()| (Message::Activate, rx))
            })
            .boxed(),
            None => stream::empty().boxed(),
        };
        Subscription::run_with_id("unitylan-instance", stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::{peer_sort_key, shared_networks_by_community};
    use crate::widgets::fmt_bytes;
    use common::control::{DeviceStatus, PeerStatus};
    use std::net::Ipv4Addr;

    fn app() -> App {
        App::new(PathBuf::from("control.sock"))
    }

    #[test]
    fn status_ok_populates_and_clears_error() {
        let mut a = app();
        a.error = Some("stale".into());
        let report = StatusReport {
            device: Some(DeviceStatus {
                wg_ip: Ipv4Addr::new(100, 64, 0, 1),
                hostname: "host-a.alice.unity.internal".into(),
                is_primary: true,
                networks: vec!["mesh".into()],
            }),
            peers: vec![PeerStatus {
                services: Vec::new(),
                hostname: "host-b.bob.unity.internal".into(),
                wg_ip: Ipv4Addr::new(100, 64, 0, 2),
                endpoint: None,
                reach: common::control::PeerReach::Direct,
                user_id: 42,
                username: "bob".into(),
                up: true,
                latency_ms: Some(12),
                rx_bytes: 2048,
                tx_bytes: 512,
                last_handshake_secs: Some(5),
                networks: vec![common::api::SharedNetwork {
                    guild_id: 1,
                    role_id: 2,
                    name: "mesh".into(),
                    community: "acme".into(),
                }],
            }],
            connected: true,
            disable_new_networks: true,
            peer_own_devices: true,
            coordinator_online: true,
            ..Default::default()
        };
        let _ = a.update(Message::StatusFetched(Ok(report)));
        assert!(a.error.is_none());
        assert_eq!(a.status.unwrap().peers.len(), 1);
    }

    /// A web service is reached through the proxy on 443, under a certificate that covers the
    /// deployment's public domain and nothing else. The `.internal` spelling resolves perfectly well
    /// and then fails name validation — so showing it is handing someone a browser warning.
    #[test]
    fn a_web_service_is_shown_under_the_name_a_browser_will_accept() {
        let mut a = app();
        let mut report = StatusReport {
            cert: common::control::CertStatus {
                domain: Some("mesh.example.com".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let _ = a.update(Message::StatusFetched(Ok(report.clone())));
        assert_eq!(
            a.browser_name(true, "wiki.alice.unity.internal"),
            "wiki.alice.mesh.example.com"
        );
        // A plain port is dialled by name and port; nothing certifies it and nothing needs to.
        assert_eq!(
            a.browser_name(false, "mc.bob.unity.internal"),
            "mc.bob.unity.internal"
        );
        // A deployment that issues no certificates has no other name to give.
        report.cert.domain = None;
        let _ = a.update(Message::StatusFetched(Ok(report)));
        assert_eq!(
            a.browser_name(true, "wiki.alice.unity.internal"),
            "wiki.alice.unity.internal"
        );
    }

    #[test]
    fn shared_networks_group_by_community() {
        let net = |name: &str, community: &str| common::api::SharedNetwork {
            guild_id: 1,
            role_id: 2,
            name: name.into(),
            community: community.into(),
        };
        // Two communities, first-seen order preserved; networks joined within each.
        let nets = vec![
            net("Engineering", "acme"),
            net("Gaming", "playhouse"),
            net("Ops", "acme"),
        ];
        assert_eq!(
            shared_networks_by_community(&nets),
            "acme: Engineering, Ops · playhouse: Gaming"
        );
        // A single community still carries its tag (the disambiguator).
        assert_eq!(
            shared_networks_by_community(&[net("mesh", "acme")]),
            "acme: mesh"
        );
        // The synthetic "My devices" group has no community → shown bare, and mixes cleanly with a
        // real (community-tagged) network on the same own-device peer.
        assert_eq!(
            shared_networks_by_community(&[
                net(common::control::OWN_DEVICES_LABEL, ""),
                net("Engineering", "acme"),
            ]),
            "My devices · acme: Engineering"
        );
    }

    #[test]
    fn peer_sort_orders_by_networks_then_latency_then_handle() {
        let mk = |handle: &str, nets: usize, lat: Option<u32>| PeerStatus {
            services: Vec::new(),
            hostname: format!("{handle}.unity.internal"),
            wg_ip: Ipv4Addr::new(100, 64, 0, 9),
            endpoint: None,
            reach: common::control::PeerReach::Direct,
            user_id: 1,
            username: handle.into(),
            up: lat.is_some(),
            latency_ms: lat,
            rx_bytes: 0,
            tx_bytes: 0,
            last_handshake_secs: None,
            networks: (0..nets)
                .map(|i| common::api::SharedNetwork {
                    guild_id: 1,
                    role_id: 2,
                    name: format!("n{i}"),
                    community: "c".into(),
                })
                .collect(),
        };
        // Most shared networks first (zeb, 2 nets); then equal-net peers by latency (amy & bob at
        // 5ms before ann at 80ms); handle breaks the amy/bob tie.
        let a = mk("zeb", 2, Some(50));
        let b = mk("amy", 1, Some(5));
        let c = mk("bob", 1, Some(5));
        let d = mk("ann", 1, Some(80));
        let mut v = [&d, &c, &b, &a];
        v.sort_by_key(|p| peer_sort_key(p, p.latency_ms));
        let order: Vec<&str> = v.iter().map(|p| p.username.as_str()).collect();
        assert_eq!(order, vec!["zeb", "amy", "bob", "ann"]);
    }

    #[test]
    fn offline_group_starts_collapsed_and_toggles() {
        let mut a = app();
        // Secure-against-clutter default: offline folded, the rest open.
        assert!(a.collapsed_groups.contains(&PeerGroup::Offline));
        assert!(!a.collapsed_groups.contains(&PeerGroup::Online));
        // Toggling flips it open, then closed again.
        let _ = a.update(Message::TogglePeerGroup(PeerGroup::Offline));
        assert!(!a.collapsed_groups.contains(&PeerGroup::Offline));
        let _ = a.update(Message::TogglePeerGroup(PeerGroup::Offline));
        assert!(a.collapsed_groups.contains(&PeerGroup::Offline));
        // And an open group folds on toggle.
        let _ = a.update(Message::TogglePeerGroup(PeerGroup::Online));
        assert!(a.collapsed_groups.contains(&PeerGroup::Online));
    }

    #[test]
    fn fmt_bytes_scales_units() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(2048), "2 KB");
        assert_eq!(fmt_bytes(1024 * 1024 + 200 * 1024), "1.2 MB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn tray_toggle_destroys_and_reopens_window() {
        let mut a = app();
        let _ = a.open_window(); // boot opens the window
        assert!(a.window.is_some());
        let _ = a.update(Message::Tray(TrayMsg::ToggleWindow));
        assert!(a.window.is_none()); // first click hides to tray (window destroyed)
        let _ = a.update(Message::Tray(TrayMsg::ToggleWindow));
        assert!(a.window.is_some()); // second click reopens
    }

    #[test]
    fn close_request_hides_to_tray() {
        let mut a = app();
        let _ = a.open_window();
        let _ = a.update(Message::CloseRequested);
        assert!(a.window.is_none()); // the X button hides, doesn't exit
    }

    #[test]
    fn errors_surface_to_ui() {
        let mut a = app();
        let _ = a.update(Message::StatusFetched(Err("no daemon".into())));
        assert_eq!(a.error.as_deref(), Some("no daemon"));
    }

    #[test]
    fn devices_fetched_replaces_list() {
        let mut a = app();
        let resp = ManageResp {
            message: "ok".into(),
            devices: vec![DeviceInfo {
                device_name: "laptop".into(),
                is_primary: true,
                is_self: true,
            }],
        };
        let _ = a.update(Message::DevicesFetched(Ok(resp)));
        assert_eq!(a.devices.len(), 1);
        assert_eq!(a.devices[0].device_name, "laptop");
    }

    #[test]
    fn empty_rename_is_ignored() {
        let mut a = app();
        a.rename_input = "   ".into();
        let _ = a.update(Message::RenameSubmit);
        // whitespace-only rename: input stays, nothing dispatched
        assert_eq!(a.rename_input, "   ");
    }

    #[test]
    fn exposes_fetched_replaces_list() {
        let mut a = app();
        let resp = ExposeResp {
            message: "ok".into(),
            exposed: vec![ExposedPort {
                name: None,
                kind: ServiceKind::Port,
                proto: Proto::Tcp,
                port: 25565,
                scope: ExposeScope::Net {
                    guild_id: 1,
                    role_id: 2,
                },
                label: "mesh @ acme".into(),
                active: true,
            }],
        };
        let _ = a.update(Message::ExposesFetched(Ok(resp)));
        assert_eq!(a.exposed.len(), 1);
        assert_eq!(a.exposed[0].port, 25565);
    }

    /// The landing tab follows what there is to look at, but only ever upward: a late poll must not
    /// slide the tab out from under someone mid-read, and a peer dropping must not bounce it back.
    #[test]
    fn the_tab_settles_upward_and_stops_once_the_user_picks_one() {
        let mut a = app();
        assert_eq!(a.tab, Tab::Networks, "nothing to show yet");

        // A peer appears → Peers.
        let mut report = StatusReport {
            peers: vec![PeerStatus {
                services: Vec::new(),
                hostname: "bob.unity.internal".into(),
                wg_ip: Ipv4Addr::new(100, 64, 0, 2),
                endpoint: None,
                reach: common::control::PeerReach::Direct,
                user_id: 2,
                username: "bob".into(),
                up: true,
                latency_ms: None,
                rx_bytes: 0,
                tx_bytes: 0,
                last_handshake_secs: None,
                networks: Vec::new(),
            }],
            ..Default::default()
        };
        let _ = a.update(Message::StatusFetched(Ok(report.clone())));
        assert_eq!(a.tab, Tab::Peers);

        // That peer turns out to serve something → Services.
        report.peers[0].services = vec![common::control::PeerService {
            name: "jellyfin".into(),
            hostname: "jellyfin.bob.unity.internal".into(),
            proto: Proto::Tcp,
            port: 8096,
            kind: common::service::ServiceKind::Port,
            shadowed: false,
        }];
        let _ = a.update(Message::StatusFetched(Ok(report.clone())));
        assert_eq!(a.tab, Tab::Services);

        // The peer goes away entirely: the tab stays put rather than walking back down.
        let _ = a.update(Message::StatusFetched(Ok(StatusReport::default())));
        assert_eq!(a.tab, Tab::Services, "never moves down");

        // And once the user chooses, later arrivals leave it alone.
        let _ = a.update(Message::SelectTab(Tab::Networks));
        let _ = a.update(Message::StatusFetched(Ok(report)));
        assert_eq!(a.tab, Tab::Networks, "their choice wins");
    }

    /// Arming the rename seeds the field with the current name — the common edit is a tweak, not a
    /// retype — and both finishing and cancelling put the row back.
    #[test]
    fn renaming_arms_from_the_current_name_and_disarms_either_way() {
        let mut a = app();
        let _ = a.update(Message::StartRename("laptop".into()));
        assert!(a.renaming);
        assert_eq!(a.rename_input, "laptop");

        let _ = a.update(Message::CancelRename);
        assert!(!a.renaming);
        assert!(a.rename_input.is_empty());

        let _ = a.update(Message::StartRename("laptop".into()));
        let _ = a.update(Message::RenameInput("workstation".into()));
        let _ = a.update(Message::RenameSubmit);
        assert!(!a.renaming, "submitting closes the editor");
        assert!(a.rename_input.is_empty());
    }

    #[test]
    fn service_submit_clears_the_draft_and_sends_the_name() {
        let mut a = app();
        a.service_name_input = "jellyfin".into();
        a.expose_port_input = "8096".into();
        a.expose_scopes = vec![ExposeScope::AllPeers];
        let _ = a.update(Message::ServiceSubmit);
        assert!(a.service_name_input.is_empty());
        assert!(a.expose_port_input.is_empty());
        assert!(a.expose_scopes.is_empty());
        assert!(a.error.is_none());
    }

    /// The name is checked before anything is sent, so a typo is a message next to the field rather
    /// than a round trip that fails at the daemon.
    #[test]
    fn service_submit_refuses_an_unusable_name_without_touching_the_draft() {
        let mut a = app();
        a.service_name_input = "My Service".into();
        a.expose_port_input = "8096".into();
        a.expose_scopes = vec![ExposeScope::AllPeers];
        let _ = a.update(Message::ServiceSubmit);
        assert!(a.error.is_some());
        assert_eq!(a.service_name_input, "My Service", "draft is kept to fix");
        assert_eq!(a.expose_scopes.len(), 1);
    }

    #[test]
    fn submit_with_a_bad_port_surfaces_the_error_and_keeps_the_input() {
        let mut a = app();
        a.service_name_input = "mc".into();
        a.expose_port_input = "notaport".into();
        a.expose_scopes = vec![ExposeScope::AllPeers];
        let _ = a.update(Message::ServiceSubmit);
        assert!(a.error.is_some());
        assert_eq!(a.expose_port_input, "notaport");
        assert_eq!(
            a.expose_scopes,
            vec![ExposeScope::AllPeers],
            "draft survives"
        );
    }

    /// Submitting with nothing ticked would otherwise send zero ops and look like it worked.
    #[test]
    fn submit_without_a_scope_is_refused() {
        let mut a = app();
        a.service_name_input = "mc".into();
        a.expose_port_input = "8080".into();
        let _ = a.update(Message::ServiceSubmit);
        assert!(a.error.is_some());
        assert!(a.expose_port_input == "8080", "draft survives");
    }

    /// Sharing names who, every time. "Every peer" is not on offer anywhere in the app — it was the
    /// easiest thing to pick and the widest thing the mesh can express, which is the wrong way round
    /// for a decision about who reaches a port on your machine.
    #[test]
    fn sharing_never_offers_every_peer() {
        use common::api::NetworkStatus;
        let mut a = app();
        let _ = a.update(Message::StatusFetched(Ok(StatusReport {
            networks: vec![NetworkStatus {
                guild_id: 1,
                role_id: 2,
                name: "eng".into(),
                guild_name: "acme".into(),
                enabled: true,
            }],
            ..Default::default()
        })));

        let offered = a.selectable_scopes();
        assert!(
            !offered.iter().any(|(s, _)| *s == ExposeScope::AllPeers),
            "creating a service cannot pick every peer: {:?}",
            offered.iter().map(|(s, _)| s).collect::<Vec<_>>()
        );
        // The narrower scopes are all still there — this removes one option, not the feature.
        assert!(offered.iter().any(|(s, _)| *s == ExposeScope::OwnDevices));
        assert!(offered.iter().any(|(s, _)| matches!(
            s,
            ExposeScope::Net {
                guild_id: 1,
                role_id: 2
            }
        )));

        // Several narrow scopes still combine — one `Add` op per tick.
        let net = ExposeScope::Net {
            guild_id: 1,
            role_id: 2,
        };
        let _ = a.update(Message::ExposeScopeToggle(net.clone(), true));
        let _ = a.update(Message::ExposeScopeToggle(ExposeScope::OwnDevices, true));
        assert_eq!(a.expose_scopes.len(), 2);
        let _ = a.update(Message::ExposeScopeToggle(net, false));
        assert_eq!(a.expose_scopes, vec![ExposeScope::OwnDevices]);
    }

    /// An exposure made when every-peer *was* offered keeps working — this removes a choice, not a
    /// capability — and widening it is refused because nothing is wider.
    #[test]
    fn an_existing_every_peer_service_still_shows_and_cannot_widen() {
        let mut a = app();
        a.exposed = vec![ExposedPort {
            proto: Proto::Tcp,
            port: 8096,
            scope: ExposeScope::AllPeers,
            label: String::new(),
            name: Some("jelly".into()),
            kind: Default::default(),
            active: true,
        }];
        assert!(a.widenable_scopes("jelly").is_none());
    }

    /// One `Add` op per ticked scope — the wire carries one scope per exposure.
    #[test]
    fn each_ticked_scope_becomes_its_own_exposure() {
        let mut a = app();
        a.service_name_input = "mc".into();
        a.expose_port_input = "8080".into();
        a.expose_scopes = vec![
            ExposeScope::OwnDevices,
            ExposeScope::Net {
                guild_id: 1,
                role_id: 2,
            },
        ];
        let _ = a.update(Message::ServiceSubmit);
        // The draft is consumed once, not once per scope.
        assert!(a.expose_scopes.is_empty());
        assert!(a.error.is_none());
    }

    /// Widening offers only what would change something. A scope the service already has is a chip
    /// beside the `+`, and `everyone` is a superset — offering it next to narrower scopes would put
    /// a chip on the service implying a restriction the firewall is not enforcing.
    #[test]
    fn widening_offers_only_the_scopes_that_would_change_access() {
        use common::api::NetworkStatus;
        let mut a = app();
        let net = |role_id: u64, name: &str| NetworkStatus {
            guild_id: 1,
            role_id,
            name: name.into(),
            guild_name: "acme".into(),
            enabled: true,
        };
        let _ = a.update(Message::StatusFetched(Ok(StatusReport {
            networks: vec![net(10, "eng"), net(20, "ops")],
            ..Default::default()
        })));
        let exposure = |name: &str, scope: ExposeScope| ExposedPort {
            proto: Proto::Tcp,
            port: 8080,
            scope,
            label: String::new(),
            name: Some(name.into()),
            kind: Default::default(),
            active: true,
        };
        a.exposed = vec![exposure(
            "wiki",
            ExposeScope::Net {
                guild_id: 1,
                role_id: 10,
            },
        )];

        let offered = a.widenable_scopes("wiki").expect("not open to everyone");
        let labels: Vec<&str> = offered.iter().map(|(_, l)| l.as_str()).collect();
        assert!(
            labels.iter().any(|l| l.contains("ops")),
            "a network it lacks is offered: {labels:?}"
        );
        assert!(
            !labels.iter().any(|l| l.contains("eng")),
            "the scope it already has is not re-offered: {labels:?}"
        );
        assert!(
            !offered.iter().any(|(s, _)| *s == ExposeScope::AllPeers),
            "going public is not a widening"
        );
        // Own-devices is a real widening and stays on offer.
        assert!(offered.iter().any(|(s, _)| *s == ExposeScope::OwnDevices));

        // Open to every peer already: nothing to offer at all, rather than a list of no-ops.
        a.exposed = vec![exposure("wiki", ExposeScope::AllPeers)];
        assert!(a.widenable_scopes("wiki").is_none());
    }

    /// The picker closes on the way out — it lists what the service lacks, and the scope just
    /// picked is about to stop being one of them.
    #[test]
    fn widening_a_service_sends_the_op_and_closes_the_picker() {
        let mut a = app();
        a.widening = Some("wiki".into());
        let _ = a.update(Message::Widen {
            name: "wiki".into(),
            scope: ExposeScope::OwnDevices,
        });
        assert!(a.widening.is_none());
        assert!(a.error.is_none());

        // Opening one picker closes any other: two open at once leaves no way to tell which service
        // you are about to hand to a network.
        let _ = a.update(Message::WidenOpen(Some("mc".into())));
        assert_eq!(a.widening.as_deref(), Some("mc"));
        let _ = a.update(Message::WidenOpen(Some("wiki".into())));
        assert_eq!(a.widening.as_deref(), Some("wiki"));
        let _ = a.update(Message::WidenOpen(None));
        assert!(a.widening.is_none());
    }

    #[test]
    fn status_carries_networks_for_the_toggle() {
        use common::api::NetworkStatus;
        let mut a = app();
        let report = StatusReport {
            networks: vec![NetworkStatus {
                guild_id: 1,
                role_id: 20,
                name: "mesh2".into(),
                guild_name: "guild1".into(),
                enabled: false,
            }],
            connected: true,
            disable_new_networks: true,
            peer_own_devices: true,
            coordinator_online: true,
            ..Default::default()
        };
        let _ = a.update(Message::StatusFetched(Ok(report)));
        let nets = &a.status.unwrap().networks;
        assert_eq!(nets.len(), 1);
        assert!(!nets[0].enabled);
    }

    #[test]
    fn set_connected_marks_busy_then_clears_on_done() {
        let mut a = app();
        // Requesting a disconnect marks the connect action in-flight.
        let _ = a.update(Message::SetConnected(false));
        assert!(a.connect_busy);
        // A failed toggle clears busy and surfaces the error.
        let _ = a.update(Message::ConnectedDone(Err("no daemon".into())));
        assert!(!a.connect_busy);
        assert_eq!(a.error.as_deref(), Some("no daemon"));
    }

    #[test]
    fn login_started_shows_authorize_url() {
        let mut a = app();
        let _ = a.update(Message::LoginStarted(Ok(LoginResp {
            authorize_url: "https://discord.com/oauth2/authorize?x".into(),
        })));
        assert_eq!(
            a.login_url.as_deref(),
            Some("https://discord.com/oauth2/authorize?x")
        );
        assert!(a.error.is_none());
    }

    #[test]
    fn logout_drops_stale_login_url() {
        let mut a = app();
        a.login_url = Some("https://discord.com/oauth2/authorize?x".into());
        // Requesting logout clears any lingering authorize link (the daemon re-keys, so it's dead).
        let _ = a.update(Message::Logout);
        assert!(a.login_url.is_none());
        // A failed logout surfaces the error; a success clears it.
        let _ = a.update(Message::LoggedOut(Err("no daemon".into())));
        assert_eq!(a.error.as_deref(), Some("no daemon"));
        let _ = a.update(Message::LoggedOut(Ok("logging out".into())));
        assert!(a.error.is_none());
    }

    #[test]
    fn network_toggle_error_surfaces() {
        let mut a = app();
        let _ = a.update(Message::NetworkToggled(Err("nope".into())));
        assert_eq!(a.error.as_deref(), Some("nope"));
    }

    #[test]
    fn parse_port_takes_a_bare_number_in_range() {
        assert_eq!(parse_port("25565").unwrap(), 25565);
        assert!(parse_port("notaport").is_err());
        assert!(parse_port("70000").is_err());
        assert!(parse_port("0").is_err(), "0 is not a listenable port");
        // The protocol is a separate control now, so the old prefix syntax is not a port.
        assert!(parse_port("udp/34197").is_err());
    }

    #[test]
    fn destructive_action_arms_then_confirms_or_cancels() {
        let mut a = app();
        // First click only arms the confirmation — nothing destructive runs yet.
        let _ = a.update(Message::AskConfirm(Confirm::RemoveDevice("laptop".into())));
        assert_eq!(a.confirm, Some(Confirm::RemoveDevice("laptop".into())));
        // Cancel clears it without acting.
        let _ = a.update(Message::CancelConfirm);
        assert_eq!(a.confirm, None);
        // Re-arming then confirming (the second click) consumes the pending state.
        let _ = a.update(Message::AskConfirm(Confirm::Logout));
        assert_eq!(a.confirm, Some(Confirm::Logout));
        let _ = a.update(Message::Logout);
        assert_eq!(a.confirm, None);
    }

    #[test]
    fn dismiss_error_clears_banner() {
        let mut a = app();
        a.error = Some("boom".into());
        let _ = a.update(Message::DismissError);
        assert!(a.error.is_none());
    }

    #[test]
    fn tab_defaults_to_networks_and_switches() {
        let mut a = app();
        assert_eq!(a.tab, Tab::Networks);
        let _ = a.update(Message::SelectTab(Tab::Peers));
        assert_eq!(a.tab, Tab::Peers);
    }
}
