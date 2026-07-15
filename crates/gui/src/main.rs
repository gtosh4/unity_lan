//! UnityLAN GUI (M4): an unprivileged iced desktop app driving the engine over its control
//! socket. Shows live mesh status (this device + peers) and manages the owner's devices
//! (rename / set-primary / remove). Auto-refreshes every 2s. The mesh keeps running when the
//! window closes — this is a viewer/controller, not the engine.
//!
//! Usage: `unitylan-gui [control.sock]` (default: `control.sock` in the working directory).
//! Scope note: network toggles / expose / OAuth login are deferred until the engine exposes
//! them over the control socket.

mod ctl;
mod tray;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::api::{DeviceInfo, ManageOp, ManageResp};
use common::control::{
    ConnectedResp, ExposeOp, ExposeResp, ExposedPort, LoginResp, NetworkResp, PeerReach, Proto,
    StatusReport,
};
use iced::alignment::Vertical;
use iced::font::Weight;
use iced::widget::{
    button, checkbox, column, container, horizontal_space, row, scrollable, svg, text, text_input,
    toggler, tooltip, Column, Row, Text,
};
use iced::window;
use iced::{Color, Element, Font, Length, Subscription, Task, Theme};
use iced_aw::{drop_down, DropDown};
use tokio::sync::mpsc::UnboundedReceiver;
use tray::TrayMsg;

// Palette — semantic status colors, tuned for the dark theme. `Color` literals are const.
const GREEN: Color = Color::from_rgb(0.30, 0.78, 0.47); // healthy / connected / direct
const AMBER: Color = Color::from_rgb(0.93, 0.69, 0.22); // in-progress / degraded
const RED: Color = Color::from_rgb(0.90, 0.37, 0.37); // failed / unreachable / destructive
const MUTED: Color = Color::from_rgb(0.74, 0.74, 0.80); // secondary text (IPs, endpoints, hints)

/// A section title: slightly larger and semibold so sections read as a hierarchy above their rows.
fn header<'a>(s: impl Into<String>) -> Text<'a> {
    text(s.into()).size(16).font(Font {
        weight: Weight::Semibold,
        ..Font::DEFAULT
    })
}

/// De-emphasized secondary text (endpoints, hints, current-value notes).
fn muted<'a>(s: impl Into<String>) -> Text<'a> {
    text(s.into()).size(13).color(MUTED)
}

/// Human-readable byte count for the per-peer transfer counters (e.g. `1.2 MB`, `340 KB`).
fn fmt_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let n = n as f64;
    if n < KB {
        format!("{} B", n as u64)
    } else if n < KB * KB {
        format!("{:.0} KB", n / KB)
    } else if n < KB * KB * KB {
        format!("{:.1} MB", n / (KB * KB))
    } else {
        format!("{:.1} GB", n / (KB * KB * KB))
    }
}

/// A colored status dot to prefix a state line — reads faster than the word alone. Drawn as a
/// small rounded quad rather than a `●` glyph, which the default font (Fira Sans) renders as tofu.
fn dot<'a>(color: Color) -> Element<'a, Message> {
    container(text(""))
        .width(Length::Fixed(9.0))
        .height(Length::Fixed(9.0))
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(color)),
            border: iced::Border {
                radius: 4.5.into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .into()
}

/// A vertical "kebab" (⋮) glyph, embedded as SVG. Drawn as an icon rather than a text symbol
/// because the default font renders such codepoints as tofu (same reason as [`dot`]). `fill` uses
/// `currentColor`; the widget tints it via [`svg::Style::color`].
const KEBAB_ICON: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>"##;

/// The kebab button that opens a peer's action menu — a borderless icon that toggles the dropdown.
fn kebab_button<'a>(user_id: u64) -> Element<'a, Message> {
    let icon = svg(svg::Handle::from_memory(KEBAB_ICON))
        .width(Length::Fixed(16.0))
        .height(Length::Fixed(16.0))
        .style(|_theme, _status| svg::Style { color: Some(MUTED) });
    button(icon)
        .style(button::text)
        .padding(2)
        .on_press(Message::ToggleMenu(user_id))
        .into()
}

/// One left-aligned, full-width row in a peer's action menu.
fn menu_item<'a>(label: &str, msg: Message) -> Element<'a, Message> {
    button(text(label.to_owned()).size(13))
        .style(button::text)
        .width(Length::Fill)
        .on_press(msg)
        .into()
}

/// Surface style for the floating peer menu: an opaque, bordered card so it reads clearly over the
/// content it overlaps.
fn menu_surface(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(p.background.weak.color.into()),
        border: iced::Border {
            radius: 6.0.into(),
            width: 1.0,
            color: p.background.strong.color,
        },
        ..Default::default()
    }
}

/// A peer's action menu: a kebab button that opens a floating dropdown (copy hostname / copy IP /
/// block). `open` drives whether the overlay is shown; a click outside dismisses it via `CloseMenu`.
fn peer_menu<'a>(hostname: String, ip: String, user_id: u64, open: bool) -> Element<'a, Message> {
    let menu = container(
        column![
            menu_item("copy hostname", Message::CopyText(hostname)),
            menu_item("copy IP", Message::CopyText(ip)),
            menu_item("block", Message::AskConfirm(Confirm::BlockPeer(user_id))),
        ]
        .spacing(2),
    )
    .padding(4)
    .width(Length::Fill)
    .style(menu_surface);
    // Anchor the menu below the kebab, extending left (right edge at the kebab) so it stays inside
    // the narrow window rather than spilling off the right edge. `width` sizes the overlay itself —
    // without it the overlay defaults to the kebab's width and the labels wrap to one char per line.
    DropDown::new(kebab_button(user_id), menu, open)
        .on_dismiss(Message::CloseMenu)
        .alignment(drop_down::Alignment::BottomStart)
        .width(Length::Fixed(160.0))
        .into()
}

/// Wrap a section's contents in a bordered, padded card so sections read as distinct groups
/// instead of one flat stack.
fn card<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(content)
        .padding(14)
        .width(Length::Fill)
        .style(container::rounded_box)
        .into()
}

/// Inline confirm/cancel controls for a destructive action. When `armed`, returns a danger
/// "confirm" button (running `run_msg`) plus a cancel button; otherwise a single arming button
/// (`arm_label`, danger vs. secondary per `arm_danger`) that sends `arm_msg`. The caller pushes
/// the returned elements onto its row.
fn confirm_controls<'a>(
    armed: bool,
    arm_label: &str,
    arm_danger: bool,
    arm_msg: Message,
    confirm_label: &str,
    run_msg: Message,
) -> Vec<Element<'a, Message>> {
    if armed {
        vec![
            button(text(confirm_label.to_owned()).size(13))
                .style(button::danger)
                .on_press(run_msg)
                .into(),
            button(text("cancel").size(13))
                .on_press(Message::CancelConfirm)
                .into(),
        ]
    } else {
        let b = button(text(arm_label.to_owned()).size(13)).on_press(arm_msg);
        let b = if arm_danger {
            b.style(button::danger)
        } else {
            b.style(button::secondary)
        };
        vec![b.into()]
    }
}

/// The main window's settings. `exit_on_close_request(false)` so the close button hits our
/// `CloseRequested` handler (hide-to-tray) instead of destroying the window out from under us.
fn window_settings() -> window::Settings {
    window::Settings {
        size: iced::Size::new(440.0, 640.0),
        position: window::Position::Centered,
        exit_on_close_request: false,
        ..Default::default()
    }
}

fn main() -> iced::Result {
    let socket = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "control.sock".to_string()),
    );
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
            let open = app.open_window();
            let init = Task::batch([open, app.reload()]);
            (app, init)
        })
}

struct App {
    socket: PathBuf,
    status: Option<StatusReport>,
    devices: Vec<DeviceInfo>,
    exposed: Vec<ExposedPort>,
    /// Draft text for the device-rename field.
    rename_input: String,
    /// Draft text for the expose port field.
    expose_port_input: String,
    /// Draft text for the expose network-scope field.
    expose_net_input: String,
    /// The Discord authorize URL after the user clicks "Log in", shown for them to open.
    login_url: Option<String>,
    /// A mesh connect/disconnect is in flight — disables the button meanwhile.
    connect_busy: bool,
    /// A pending destructive action awaiting a second confirming click (remove device / log out).
    confirm: Option<Confirm>,
    /// Which peer's action menu (kebab dropdown) is open, by owner `user_id`; `None` when closed.
    menu_open: Option<u64>,
    /// Which content tab is showing (below the always-visible connection header).
    tab: Tab,
    /// The last action error, shown as a banner until the next action clears it.
    error: Option<String>,
    /// Window/quit requests from the tray thread, consumed once by the subscription (`None` when
    /// there's no tray on this platform / system).
    tray_rx: Arc<Mutex<Option<UnboundedReceiver<TrayMsg>>>>,
    /// The main window's id while it's open; `None` while hidden to the tray (the window is
    /// destroyed, not just hidden — see [`window_settings`]). Show reopens a fresh one.
    window: Option<window::Id>,
}

/// Content tabs shown under the persistent connection header. Networks = the ACL groups this
/// device peers on; Peers = this device + the live mesh members; Manage = device + port admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Networks,
    Peers,
    Manage,
}

/// A destructive action armed by a first click; the second click on the confirm control runs it.
#[derive(Debug, Clone, PartialEq)]
enum Confirm {
    RemoveDevice(String),
    Logout,
    /// Block a peer's owner, armed by the peer's `user_id`.
    BlockPeer(u64),
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
    RenameInput(String),
    RenameSubmit,
    SetPrimary(String),
    Remove(String),
    ExposePortInput(String),
    ExposeNetInput(String),
    ExposeSubmit,
    Unexpose {
        proto: Proto,
        port: u16,
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
    /// Toggle a peer's action menu (kebab dropdown) open/closed, keyed by owner `user_id`.
    ToggleMenu(u64),
    /// Close any open peer action menu (a click landed outside it).
    CloseMenu,
    /// Dismiss the current error banner.
    DismissError,
    /// Switch the visible content tab.
    SelectTab(Tab),
    /// A window/quit request from the system tray.
    Tray(TrayMsg),
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
            expose_port_input: String::new(),
            expose_net_input: String::new(),
            login_url: None,
            connect_busy: false,
            confirm: None,
            menu_open: None,
            tab: Tab::default(),
            error: None,
            tray_rx: Arc::new(Mutex::new(None)),
            window: None,
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

    /// Fetch status + device list + exposed ports concurrently.
    fn reload(&self) -> Task<Message> {
        Task::batch([
            Task::perform(
                ctl::fetch_status(self.socket.clone()),
                Message::StatusFetched,
            ),
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
                self.status = Some(s);
                self.error = None;
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
            }
            Message::ExposesFetched(Err(e)) => self.error = Some(e),
            Message::ExposePortInput(s) => self.expose_port_input = s,
            Message::ExposeNetInput(s) => self.expose_net_input = s,
            Message::ExposeSubmit => match parse_port(self.expose_port_input.trim()) {
                Ok((proto, port)) => {
                    let net = match self.expose_net_input.trim() {
                        "" => None,
                        n => Some(n.to_string()),
                    };
                    self.expose_port_input.clear();
                    self.expose_net_input.clear();
                    return Task::perform(
                        ctl::expose(self.socket.clone(), ExposeOp::Add { proto, port, net }),
                        Message::ExposesFetched,
                    );
                }
                Err(e) => self.error = Some(e),
            },
            Message::Unexpose { proto, port } => {
                return Task::perform(
                    ctl::expose(self.socket.clone(), ExposeOp::Remove { proto, port }),
                    Message::ExposesFetched,
                )
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
            Message::CloseRequested => return self.hide_window(),
            Message::WindowOpened(id) => return window::gain_focus(id),
            Message::RenameInput(s) => self.rename_input = s,
            Message::RenameSubmit => {
                let name = self.rename_input.trim().to_string();
                if !name.is_empty() {
                    self.rename_input.clear();
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
            Message::SelectTab(t) => self.tab = t,
        }
        Task::none()
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            iced::time::every(Duration::from_secs(2)).map(|_| Message::Tick),
            window::close_requests().map(|_| Message::CloseRequested),
            self.tray_subscription(),
        ])
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

    fn view(&self, _window: window::Id) -> Element<'_, Message> {
        let sections = match self.status.as_ref() {
            // Engine reachable — it told us its state. Only offer login when the engine itself says
            // we're not enrolled; otherwise show the live mesh/device UI.
            Some(s) => {
                let mut col = Column::new().spacing(12);
                if s.needs_login {
                    col = col.push(card(self.login_section()));
                } else {
                    // Connection header is always visible; the rest lives under tabs so the peers
                    // list (which can grow) and the rarely-touched ports don't crowd the header.
                    // Tab strip + its content share one bordered panel, so the active tab visibly
                    // owns the surface below it (rather than floating between look-alike cards).
                    let panel = container(column![self.tab_bar(), self.tab_body()].spacing(10))
                        .padding(8)
                        .width(Length::Fill)
                        .style(container::bordered_box);
                    col = col
                        .push_maybe(self.connection_section().map(card))
                        .push(panel);
                }
                col
            }
            // Engine not reachable (socket down / not started yet): don't show the login button — it
            // can't work without the daemon, and the mesh/device sections have no data. The engine
            // runs elsewhere (resident service in a packaged install, or the dev-run script), so the
            // GUI just waits for it — a plain notice, no process control here.
            None => Column::new().spacing(12).push(card(self.engine_notice())),
        };
        // Error banner pinned above the sections so a failure is visible without scrolling. It's
        // dismissible, and every successful fetch already clears `self.error`.
        let body = Column::new()
            .spacing(12)
            .push_maybe(self.error.as_deref().map(error_banner))
            .push(sections)
            .padding(20);
        scrollable(body).into()
    }

    /// The three-tab selector under the connection header. Active tab is the loud primary style,
    /// the others quiet secondary; buttons butt together into one segmented strip. Each fills a
    /// third of the width.
    fn tab_bar(&self) -> Element<'_, Message> {
        let tab = |label: &'static str, t: Tab| {
            let b = button(
                text(label)
                    .size(14)
                    .align_x(iced::alignment::Horizontal::Center),
            )
            .width(Length::Fill)
            .on_press(Message::SelectTab(t));
            if self.tab == t {
                b
            } else {
                b.style(button::secondary)
            }
        };
        row![
            tab("Networks", Tab::Networks),
            tab("Peers", Tab::Peers),
            tab("Manage", Tab::Manage),
        ]
        .spacing(2)
        .into()
    }

    /// Sections for the active tab, rendered borderless — the enclosing tab panel is the surface,
    /// so sections are separated by spacing alone (no nested cards). Networks = the ACL groups;
    /// Peers = this device + mesh members; Manage = devices → exposed ports.
    fn tab_body(&self) -> Element<'_, Message> {
        let col = match self.tab {
            Tab::Networks => Column::new().push(self.networks_section()),
            Tab::Peers => Column::new()
                .push(self.device_section())
                .push(self.peers_section()),
            Tab::Manage => Column::new()
                .push(self.devices_section())
                .push(self.exposed_section()),
        };
        col.spacing(18).padding([2, 6]).into()
    }

    /// Shown when we have no status: the control socket isn't reachable, so the engine is either
    /// still starting or not running. Distinct from "not logged in" — offering login here would
    /// just fail against a dead socket.
    fn engine_notice(&self) -> Element<'_, Message> {
        let msg = if self.error.is_some() {
            "Engine not reachable — is the UnityLAN engine running? Retrying automatically."
        } else {
            "Connecting to engine…"
        };
        column![header("engine"), muted(msg)].spacing(6).into()
    }

    /// Mesh connect/disconnect over the control socket. Disconnect keeps the engine resident and
    /// polling (instant reconnect) but brings the interface's link administratively down and drops
    /// all peers, withdrawing us from co-members' seed lists. Connect brings the link back up.
    /// Hidden until we have a status (need the socket) and only when enrolled (`!needs_login`).
    fn connection_section(&self) -> Option<Element<'_, Message>> {
        let status = self.status.as_ref()?;
        let connected = status.connected;
        let (state, label, target, mesh_color) = if connected {
            ("connected", "disconnect", false, GREEN)
        } else {
            ("disconnected", "connect", true, MUTED)
        };
        // Disconnect is the destructive direction (drops peers, withdraws us from seed lists) →
        // danger style; connect is benign.
        let b = button(text(label).size(13));
        let b = if connected {
            b.style(button::danger)
        } else {
            b
        };
        let b = if self.connect_busy {
            b
        } else {
            b.on_press(Message::SetConnected(target))
        };
        let controls = row![
            dot(mesh_color),
            text(format!("mesh: {state}")).size(14).width(Length::Fill),
            b,
        ]
        .spacing(8)
        .align_y(Vertical::Center);
        // Who we're enrolled as, with a log out control (tears the mesh down, un-enrolls, and
        // re-keys → back to the login screen). Destructive, so it arms an inline confirm first.
        let logging_out = self.confirm == Some(Confirm::Logout);
        let identity = status.identity.as_deref().map(|u| {
            let mut r = row![text(format!("signed in as {u}"))
                .size(14)
                .width(Length::Fill)]
            .spacing(8)
            .align_y(Vertical::Center);
            for e in confirm_controls(
                logging_out,
                "log out",
                true,
                Message::AskConfirm(Confirm::Logout),
                "confirm log out",
                Message::Logout,
            ) {
                r = r.push(e);
            }
            r
        });
        // Whether the coordinator is currently reachable (the mesh keeps running from cache when
        // it isn't, so that's a distinct health line).
        let (coord_color, coord) = if status.coordinator_online {
            (GREEN, "coordinator: online")
        } else {
            (AMBER, "coordinator: offline (mesh running from cache)")
        };
        let coord_line = row![dot(coord_color), text(coord).size(14)]
            .spacing(8)
            .align_y(Vertical::Center);
        Some(
            column![header("connection")]
                .push_maybe(identity)
                .push(coord_line)
                .push(controls)
                .spacing(8)
                .into(),
        )
    }

    fn device_section(&self) -> Element<'_, Message> {
        let inner: Element<'_, Message> = match self.status.as_ref().and_then(|s| s.device.as_ref())
        {
            Some(d) => {
                // Networks are listed (with toggles) in the networks section below — don't repeat
                // them here. Hostname on top, IP as a muted sub-line — same shape as a peer row, so
                // long FQDNs don't get starved into a mid-token wrap by a fixed IP column.
                let primary = if d.is_primary { "  [primary]" } else { "" };
                column![
                    row![
                        dot(GREEN),
                        text(format!("{}{}", d.hostname, primary))
                            .size(14)
                            .width(Length::Fill),
                    ]
                    .spacing(8)
                    .align_y(Vertical::Center),
                    muted(d.wg_ip.to_string()),
                ]
                .spacing(2)
                .into()
            }
            None => row![dot(MUTED), muted("not joined to any network")]
                .spacing(8)
                .align_y(Vertical::Center)
                .into(),
        };
        column![header("this device"), inner].spacing(6).into()
    }

    fn peers_section(&self) -> Element<'_, Message> {
        let peers = self
            .status
            .as_ref()
            .map(|s| s.peers.as_slice())
            .unwrap_or(&[]);
        let inner: Element<'_, Message> = if peers.is_empty() {
            muted("No peers yet — waiting for co-members to come online.").into()
        } else {
            let mut col = Column::new().spacing(8);
            for p in peers {
                let ep = p
                    .endpoint
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "—".to_string());
                let (sc, slabel) = peer_status(p.reach, p.up);
                // Status dot + hostname own the first line so a long FQDN gets the full width. The
                // dot's color is the single health signal (green up / amber connecting / red down);
                // hovering it reveals when WG last handshook — the raw fact behind up/down.
                let hover = match p.last_handshake_secs {
                    Some(s) => format!("last handshake {} ago", fmt_ago(s)),
                    None => "no handshake yet".to_string(),
                };
                // Hostname carries two hovers' worth of context without cluttering the row: the dot
                // shows WG liveness (last handshake), the name shows which shared networks the peer is
                // reachable over (the ACL intersection). The kebab at the end opens the action menu.
                let net_hover = if p.networks.is_empty() {
                    "no shared networks".to_string()
                } else {
                    format!("shared networks: {}", p.networks.join(", "))
                };
                let name_line = row![
                    tooltip(dot(sc), muted(hover), tooltip::Position::Right)
                        .padding(6)
                        .style(container::rounded_box),
                    tooltip(
                        text(p.hostname.clone()).size(14),
                        muted(net_hover),
                        tooltip::Position::Bottom,
                    )
                    .padding(6)
                    .style(container::rounded_box),
                    horizontal_space(),
                    peer_menu(
                        p.hostname.clone(),
                        p.wg_ip.to_string(),
                        p.user_id,
                        self.menu_open == Some(p.user_id),
                    ),
                ]
                .spacing(8)
                .align_y(Vertical::Center);
                // Second line: the status label (same color as the dot, never contradicting it).
                // Blocking a peer is chosen from the kebab menu — it arms an inline confirm here
                // rather than acting immediately, keeping the destructive action a two-step.
                let mut status_line = row![text(slabel).size(13).color(sc).width(Length::Fill)]
                    .spacing(8)
                    .align_y(Vertical::Center);
                if self.confirm == Some(Confirm::BlockPeer(p.user_id)) {
                    status_line = status_line
                        .push(
                            button(text("confirm block").size(13))
                                .style(button::danger)
                                .on_press(Message::BlockPeer {
                                    user_id: p.user_id,
                                    username: p.username.clone(),
                                }),
                        )
                        .push(button(text("cancel").size(13)).on_press(Message::CancelConfirm));
                }
                // Telemetry line: latency (last ICMP RTT, only meaningful while up) + transfer totals.
                let mut metrics = Row::new().spacing(10).align_y(Vertical::Center);
                if p.up {
                    if let Some(ms) = p.latency_ms {
                        metrics = metrics.push(muted(format!("{ms} ms")));
                    }
                }
                metrics = metrics.push(muted(format!(
                    "rx {}  tx {}",
                    fmt_bytes(p.rx_bytes),
                    fmt_bytes(p.tx_bytes)
                )));
                let ip_line = muted(format!("{}   {}", p.wg_ip, ep));
                col = col.push(column![name_line, status_line, ip_line, metrics].spacing(2));
            }
            // Past a handful of peers, cap the list and scroll inside it so a large mesh doesn't
            // push everything else off-screen. Small meshes render at natural height (no scrollbar).
            if peers.len() > 6 {
                scrollable(col).height(Length::Fixed(300.0)).into()
            } else {
                col.into()
            }
        };
        // Blocked users: shown as a separate list (a blocked owner never appears as a peer) so they
        // can be un-blocked even while filtered out of the mesh.
        let blocked = self
            .status
            .as_ref()
            .map(|s| s.blocked.as_slice())
            .unwrap_or(&[]);
        let blocked_section: Option<Element<'_, Message>> = if blocked.is_empty() {
            None
        } else {
            let mut list = Column::new().spacing(6);
            for b in blocked {
                list = list.push(
                    row![
                        text(b.username.clone()).size(14).width(Length::Fill),
                        button(text("unblock").size(13))
                            .style(button::secondary)
                            .on_press(Message::UnblockPeer { user_id: b.user_id }),
                    ]
                    .spacing(8)
                    .align_y(Vertical::Center),
                );
            }
            Some(
                column![header(format!("blocked ({})", blocked.len())), list]
                    .spacing(8)
                    .into(),
            )
        };

        column![header(format!("peers ({})", peers.len())), inner]
            .push_maybe(blocked_section)
            .spacing(8)
            .into()
    }

    fn devices_section(&self) -> Element<'_, Message> {
        let inner: Element<'_, Message> = if self.devices.is_empty() {
            muted("No devices yet.").into()
        } else {
            let mut list = Column::new().spacing(6);
            for d in &self.devices {
                let primary = if d.is_primary { "  [primary]" } else { "" };
                let this = if d.is_self { "  (this device)" } else { "" };
                let mut r = row![text(format!("{}{}{}", d.device_name, primary, this))
                    .size(14)
                    .width(Length::Fill)]
                .spacing(8)
                .align_y(Vertical::Center);
                if !d.is_primary {
                    r = r.push(
                        button(text("set primary").size(13))
                            .style(button::secondary)
                            .on_press(Message::SetPrimary(d.device_name.clone())),
                    );
                }
                if !d.is_self {
                    // Remove is destructive → arm an inline confirm first (one misclick otherwise
                    // drops the device).
                    let removing =
                        self.confirm == Some(Confirm::RemoveDevice(d.device_name.clone()));
                    for e in confirm_controls(
                        removing,
                        "remove",
                        true,
                        Message::AskConfirm(Confirm::RemoveDevice(d.device_name.clone())),
                        "confirm remove",
                        Message::Remove(d.device_name.clone()),
                    ) {
                        r = r.push(e);
                    }
                }
                list = list.push(r);
            }
            list.into()
        };

        // Rename this device. Show the current hostname so it's clear what's being changed.
        let current = self
            .status
            .as_ref()
            .and_then(|s| s.device.as_ref())
            .map(|d| muted(format!("current: {}", d.hostname)));
        let rename = row![
            text_input("new name for this device", &self.rename_input)
                .on_input(Message::RenameInput)
                .on_submit(Message::RenameSubmit),
            button(text("rename").size(13))
                .style(button::secondary)
                .on_press(Message::RenameSubmit),
        ]
        .spacing(8);

        column![header("devices"), inner]
            .push_maybe(current)
            .push(rename)
            .spacing(8)
            .into()
    }

    fn login_section(&self) -> Element<'_, Message> {
        let mut col = column![
            header("Not logged in"),
            muted("Sign in with Discord to join your mesh."),
            button(text("Log in with Discord")).on_press(Message::Login),
        ]
        .spacing(8);
        if let Some(url) = &self.login_url {
            col = col
                .push(muted(
                    "Browser opened — if not, use the buttons below to finish.",
                ))
                .push(
                    row![
                        button(text("Open Discord login").size(13))
                            .on_press(Message::OpenUrl(url.clone())),
                        button(text("Copy link").size(13)).on_press(Message::CopyText(url.clone())),
                    ]
                    .spacing(8),
                );
        }
        col.into()
    }

    fn networks_section(&self) -> Element<'_, Message> {
        let nets = self
            .status
            .as_ref()
            .map(|s| s.networks.as_slice())
            .unwrap_or(&[]);
        // Secure default: newly-discovered networks stay off until enabled here. No status yet
        // (socket not up) → assume the secure posture. Sits at the top of the card: it's a
        // section-wide policy governing the list below, not a per-network control.
        let disable_new = self.status.as_ref().is_none_or(|s| s.disable_new_networks);
        let policy = checkbox("Disable new networks on discovery", disable_new)
            .on_toggle(Message::SetNewNetworkDefault)
            .size(16)
            .text_size(14);
        let inner: Element<'_, Message> = if nets.is_empty() {
            muted("No networks discovered yet.").into()
        } else {
            let mut col = Column::new().spacing(6);
            for n in nets {
                let title = if n.guild_name.is_empty() {
                    n.name.clone()
                } else {
                    format!("{} @ {}", n.name, n.guild_name)
                };
                // A switch (not a button): flipping it applies immediately, and its position shows
                // the current state — no separate on/off label needed. Switch on the left so the
                // interactive controls line up in one column with the policy checkbox above.
                let (guild_id, role_id) = (n.guild_id, n.role_id);
                let r = row![
                    toggler(n.enabled)
                        .width(Length::Shrink)
                        .on_toggle(move |enabled| {
                            Message::ToggleNetwork {
                                guild_id,
                                role_id,
                                enabled,
                            }
                        }),
                    text(title).size(14).width(Length::Fill),
                ]
                .spacing(8)
                .align_y(Vertical::Center);
                col = col.push(r);
            }
            col.into()
        };
        column![header("networks"), policy, inner].spacing(8).into()
    }

    fn exposed_section(&self) -> Element<'_, Message> {
        let inner: Element<'_, Message> = if self.exposed.is_empty() {
            muted("No ports exposed.").into()
        } else {
            let mut list = Column::new().spacing(6);
            for e in &self.exposed {
                let scope = e
                    .net
                    .as_deref()
                    .map(|n| format!("  → net: {n}"))
                    .unwrap_or_default();
                let r = row![
                    text(format!("{}/{}{}", e.proto.as_str(), e.port, scope))
                        .size(14)
                        .width(Length::Fill),
                    button(text("unexpose").size(13)).on_press(Message::Unexpose {
                        proto: e.proto,
                        port: e.port
                    }),
                ]
                .spacing(8)
                .align_y(Vertical::Center);
                list = list.push(r);
            }
            list.into()
        };

        // Add row: port (e.g. `25565` or `udp/34197`) + optional network to scope it to.
        let add = row![
            text_input("port (e.g. 25565 or udp/34197)", &self.expose_port_input)
                .on_input(Message::ExposePortInput)
                .on_submit(Message::ExposeSubmit),
            text_input("net (optional)", &self.expose_net_input)
                .on_input(Message::ExposeNetInput)
                .on_submit(Message::ExposeSubmit),
            button(text("expose").size(13))
                .style(button::secondary)
                .on_press(Message::ExposeSubmit),
        ]
        .spacing(8);

        column![
            header("exposed ports"),
            inner,
            add,
            muted("tcp is the default; write udp/34197 for UDP. Leave net blank to expose on all."),
        ]
        .spacing(8)
        .into()
    }
}

/// Status color + short label for a peer's reachability. Free fn so the palette stays in one place.
/// A peer's status as a single health color plus a label. One color axis: green = the tunnel is up
/// (however it's reached), amber = still connecting, red = down. The label carries the path detail
/// (`direct`/`relayed`/`ice`) or the reason it's not up — so the dot never contradicts the word.
fn peer_status(reach: PeerReach, up: bool) -> (Color, &'static str) {
    match (up, reach) {
        (true, PeerReach::Relayed) => (GREEN, "relayed"),
        (true, PeerReach::Ice) => (GREEN, "ice"),
        (true, _) => (GREEN, "direct"),
        (false, PeerReach::Punching) => (AMBER, "connecting"),
        (false, PeerReach::Unreachable) => (RED, "unreachable"),
        (false, _) => (RED, "down"),
    }
}

/// A compact "time since" for the last-handshake hover, e.g. `12s`, `4m`, `2h`, `3d`.
fn fmt_ago(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// A dismissible error banner, pinned above the sections in `view`.
fn error_banner<'a>(e: &str) -> Element<'a, Message> {
    let content = row![
        dot(RED),
        text(format!("error: {e}"))
            .size(14)
            .color(RED)
            .width(Length::Fill),
        button(text("dismiss").size(12)).on_press(Message::DismissError),
    ]
    .spacing(8)
    .align_y(Vertical::Center);
    container(content)
        .padding(12)
        .width(Length::Fill)
        .style(container::bordered_box)
        .into()
}

/// Parse a port field: `25565` (tcp default) or `tcp/25565` / `udp/34197`.
fn parse_port(s: &str) -> Result<(Proto, u16), String> {
    let (proto, port) = match s.split_once('/') {
        Some((p, n)) => {
            let proto = match p.to_ascii_lowercase().as_str() {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                other => return Err(format!("bad protocol '{other}' (use tcp or udp)")),
            };
            (proto, n)
        }
        None => (Proto::Tcp, s),
    };
    port.parse()
        .map(|p| (proto, p))
        .map_err(|_| format!("bad port '{port}'"))
}

#[cfg(test)]
mod tests {
    use super::*;
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
                hostname: "host-a.alice.lan.unity.internal".into(),
                is_primary: true,
                networks: vec!["mesh".into()],
            }),
            peers: vec![PeerStatus {
                hostname: "host-b.bob.lan.unity.internal".into(),
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
                networks: vec!["mesh".into()],
            }],
            networks: vec![],
            needs_login: false,
            connected: true,
            disable_new_networks: true,
            identity: None,
            coordinator_online: true,
            blocked: vec![],
        };
        let _ = a.update(Message::StatusFetched(Ok(report)));
        assert!(a.error.is_none());
        assert_eq!(a.status.unwrap().peers.len(), 1);
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
                proto: Proto::Tcp,
                port: 25565,
                net: Some("mesh".into()),
            }],
        };
        let _ = a.update(Message::ExposesFetched(Ok(resp)));
        assert_eq!(a.exposed.len(), 1);
        assert_eq!(a.exposed[0].port, 25565);
    }

    #[test]
    fn expose_submit_valid_clears_inputs() {
        let mut a = app();
        a.expose_port_input = "udp/34197".into();
        a.expose_net_input = "mesh".into();
        let _ = a.update(Message::ExposeSubmit); // dispatches the expose task
        assert!(a.expose_port_input.is_empty());
        assert!(a.expose_net_input.is_empty());
        assert!(a.error.is_none());
    }

    #[test]
    fn expose_submit_bad_port_surfaces_error_and_keeps_input() {
        let mut a = app();
        a.expose_port_input = "notaport".into();
        let _ = a.update(Message::ExposeSubmit);
        assert!(a.error.is_some());
        assert_eq!(a.expose_port_input, "notaport");
    }

    #[test]
    fn status_carries_networks_for_the_toggle() {
        use common::api::NetworkStatus;
        let mut a = app();
        let report = StatusReport {
            device: None,
            peers: vec![],
            networks: vec![NetworkStatus {
                guild_id: 1,
                role_id: 20,
                name: "mesh2".into(),
                guild_name: "guild1".into(),
                enabled: false,
            }],
            needs_login: false,
            connected: true,
            disable_new_networks: true,
            identity: None,
            coordinator_online: true,
            blocked: vec![],
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
    fn status_carries_connection_state() {
        let mut a = app();
        let report = StatusReport {
            device: None,
            peers: vec![],
            networks: vec![],
            needs_login: false,
            connected: false,
            disable_new_networks: true,
            identity: None,
            coordinator_online: true,
            blocked: vec![],
        };
        let _ = a.update(Message::StatusFetched(Ok(report)));
        assert!(!a.status.unwrap().connected);
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
    fn parse_port_defaults_tcp_and_reads_proto() {
        assert_eq!(parse_port("25565").unwrap(), (Proto::Tcp, 25565));
        assert_eq!(parse_port("udp/34197").unwrap(), (Proto::Udp, 34197));
        assert!(parse_port("sctp/1").is_err());
        assert!(parse_port("70000").is_err());
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
