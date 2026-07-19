//! A fake engine daemon that speaks the control-socket protocol (`common::control`) with canned,
//! stateful fixtures — no WireGuard, no coordinator, no privilege. Drives the whole GUI for
//! screenshots / demo video without a real mesh. One step: it binds the socket, then launches the
//! `unitylan-gui` binary sitting next to it and exits when that window closes.
//!
//! ```sh
//! cargo run -p unitylan-gui --example fake-engine              # temp socket, opens GUI, auto-plays
//! cargo run -p unitylan-gui --example fake-engine -- /tmp/f.sock         # pick the socket path
//! cargo run -p unitylan-gui --example fake-engine -- --no-gui /tmp/f.sock   # serve only, no GUI
//! cargo run -p unitylan-gui --example fake-engine -- --no-script            # don't drive the UI
//! ```
//!
//! It mirrors the GUI client's socket-name resolution (`ctl.rs::to_name`), so both sides agree on
//! the same unix socket (or Windows named pipe). State is held in memory and mutated by the GUI's
//! ops (connect/disconnect, network toggles, expose, device manage, block), so the demo is
//! interactive; peer byte counters climb over time so traffic looks live on video.
//!
//! It also **drives the GUI**: on a scripted timeline (see [`demo_script`]) it pushes UI directives
//! on the status poll — switch tabs, open a peer menu, arm a block confirm — so a recording plays
//! itself hands-free. Only a debug-build GUI honors those (see [`common::control::StatusReport::directive`]);
//! `--no-script` disables it for manual posing.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use common::api::{DeviceInfo, ManageOp, ManageResp, NetworkStatus, SharedNetwork};
use common::control::{
    BlockedUser, ConnectedResp, ControlRequest, ControlResponse, DeviceStatus, ExposeOp,
    ExposeResp, ExposedPort, LoginResp, LogoutResp, NetworkResp, PeerReach, PeerStatus, Proto,
    StatusReport, UiAction, UiDirective, UiTab, UpdateResp,
};
use interprocess::local_socket::tokio::prelude::*;
#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{ListenerOptions, Name};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Same resolution as the GUI client (`crates/gui/src/ctl.rs`), so both sides agree on the endpoint.
fn to_name(path: &str) -> std::io::Result<Name<'static>> {
    #[cfg(windows)]
    {
        let stem = std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("control")
            .to_string();
        format!("unitylan-{stem}").to_ns_name::<GenericNamespaced>()
    }
    #[cfg(not(windows))]
    {
        path.to_string().to_fs_name::<GenericFilePath>()
    }
}

/// The whole fake daemon's mutable state, shared across connections.
struct State {
    connected: bool,
    disable_new_networks: bool,
    peer_own_devices: bool,
    /// The full peer set, served when `connected`; disconnect returns an empty peer list.
    peers: Vec<PeerStatus>,
    networks: Vec<NetworkStatus>,
    devices: Vec<DeviceInfo>,
    exposed: Vec<ExposedPort>,
    blocked: Vec<BlockedUser>,
    /// When the daemon "started", to animate byte counters on `up` peers.
    started: Instant,
    /// A scripted timeline of `(at_secs, action)` the fake engine pushes to the GUI so a recording
    /// auto-plays: switch tabs, open a peer menu, arm a block confirm, etc. Empty with `--no-script`.
    script: Vec<(u64, UiAction)>,
}

/// The demo timeline: at each `at_secs` mark the GUI is told to do one UI action, once. The peer
/// menu is keyed by device IP — Bob's desktop is 100.64.0.10 (see [`fixture_peers`]) — while a block
/// acts on the owner (`user_id` 2001) and opens the user-scoped modal. Tuned to loop-record in ~30s.
fn demo_script() -> Vec<(u64, UiAction)> {
    vec![
        (3, UiAction::SelectTab(UiTab::Peers)),
        (8, UiAction::OpenPeerMenu(Ipv4Addr::new(100, 64, 0, 10))),
        (12, UiAction::ArmBlockPeer(2001)),
        (16, UiAction::Cancel),
        (18, UiAction::CloseMenu),
        (22, UiAction::SelectTab(UiTab::Manage)),
        (27, UiAction::SelectTab(UiTab::Networks)),
    ]
}

impl State {
    fn new(script: Vec<(u64, UiAction)>) -> Self {
        State {
            script,
            connected: true,
            disable_new_networks: true,
            peer_own_devices: true,
            peers: fixture_peers(),
            networks: fixture_networks(),
            devices: fixture_devices(),
            exposed: vec![
                ExposedPort {
                    proto: Proto::Tcp,
                    port: 8080,
                    net: None,
                    active: true,
                },
                ExposedPort {
                    proto: Proto::Udp,
                    port: 51820,
                    net: Some("Engineering".into()),
                    active: true,
                },
            ],
            blocked: Vec::new(),
            started: Instant::now(),
        }
    }

    /// The directive to push right now: the latest scripted step whose time has passed. `seq` is the
    /// step's 1-based index, so it's monotonic and each step fires exactly once on the GUI side.
    fn directive(&self, secs: u64) -> Option<Box<UiDirective>> {
        self.script
            .iter()
            .enumerate()
            .rfind(|(_, (at, _))| *at <= secs)
            .map(|(i, (_, action))| {
                Box::new(UiDirective {
                    seq: i as u64 + 1,
                    action: action.clone(),
                })
            })
    }

    /// A live status snapshot; byte counters grow with elapsed time so a video shows traffic moving.
    fn status(&self) -> StatusReport {
        let secs = self.started.elapsed().as_secs();
        let peers = if self.connected {
            self.peers
                .iter()
                .cloned()
                .map(|mut p| {
                    if p.up {
                        // ~40 KiB/s down, ~8 KiB/s up per peer, plus a per-peer offset for variety.
                        let base = u64::from(p.wg_ip.octets()[3]);
                        p.rx_bytes = (secs + base) * 40_960;
                        p.tx_bytes = (secs + base) * 8_192;
                    }
                    p
                })
                .collect()
        } else {
            Vec::new()
        };
        StatusReport {
            device: Some(fixture_self()),
            peers,
            networks: self.networks.clone(),
            connected: self.connected,
            disable_new_networks: self.disable_new_networks,
            peer_own_devices: self.peer_own_devices,
            identity: Some("alice#4021".into()),
            coordinator_online: true,
            blocked: self.blocked.clone(),
            engine_version: "0.4.0".into(),
            directive: self.directive(secs),
            ..Default::default()
        }
    }
}

fn fixture_self() -> DeviceStatus {
    DeviceStatus {
        wg_ip: Ipv4Addr::new(100, 64, 0, 1),
        hostname: "laptop.alice.unity.internal".into(),
        is_primary: true,
        networks: vec!["Engineering".into(), "Gaming".into()],
    }
}

#[allow(clippy::too_many_arguments)]
fn peer(
    host: &str,
    last: u8,
    reach: PeerReach,
    up: bool,
    latency: Option<u32>,
    user_id: u64,
    username: &str,
    nets: &[(&str, &str)],
) -> PeerStatus {
    PeerStatus {
        hostname: host.into(),
        wg_ip: Ipv4Addr::new(100, 64, 0, last),
        endpoint: up.then(|| SocketAddr::from(([203, 0, 113, last], 51820))),
        reach,
        user_id,
        username: username.into(),
        up,
        latency_ms: latency,
        rx_bytes: 0,
        tx_bytes: 0,
        last_handshake_secs: up.then_some(4),
        networks: nets
            .iter()
            .map(|(name, community)| SharedNetwork {
                name: (*name).into(),
                community: (*community).into(),
            })
            .collect(),
    }
}

fn fixture_peers() -> Vec<PeerStatus> {
    vec![
        // alice's own second device: same owner, tagged with the synthetic "My devices" group (no
        // shared community) — it peers via own-device peering, not a network.
        peer(
            "desktop.alice.unity.internal",
            2,
            PeerReach::Direct,
            true,
            Some(2),
            1001,
            "alice#4021",
            &[(common::control::OWN_DEVICES_LABEL, "")],
        ),
        // bob's primary device shows the bare `<user>.unity.internal` alias, and shares networks
        // across two communities — the hover groups them by server (`acme: … · playhouse: …`).
        peer(
            "bob.unity.internal",
            10,
            PeerReach::Direct,
            true,
            Some(12),
            2001,
            "bob#1180",
            &[("Engineering", "acme"), ("Gaming", "playhouse")],
        ),
        peer(
            "phone.bob.unity.internal",
            11,
            PeerReach::Ice,
            true,
            Some(38),
            2001,
            "bob#1180",
            &[("Gaming", "playhouse")],
        ),
        peer(
            "server.carol.unity.internal",
            20,
            PeerReach::Relayed,
            true,
            Some(73),
            3044,
            "carol#7788",
            &[("Engineering", "acme")],
        ),
        peer(
            "laptop.dave.unity.internal",
            30,
            PeerReach::Punching,
            false,
            None,
            4055,
            "dave#2093",
            &[("Gaming", "playhouse")],
        ),
        peer(
            "nas.erin.unity.internal",
            40,
            PeerReach::Unreachable,
            false,
            None,
            5066,
            "erin#6610",
            &[("Engineering", "acme")],
        ),
    ]
}

fn fixture_networks() -> Vec<NetworkStatus> {
    let n = |guild_id: u64, guild: &str, role_id: u64, name: &str, enabled: bool| NetworkStatus {
        guild_id,
        role_id,
        name: name.into(),
        guild_name: guild.into(),
        enabled,
    };
    // Two guilds so the Networks tab shows its guild grouping — mirroring the communities the peer
    // hovers list (`acme` / `playhouse`), so a network reads the same in both places.
    vec![
        n(900_100, "acme", 7001, "Engineering", true),
        n(900_100, "acme", 7003, "Ops", false),
        n(900_200, "playhouse", 7002, "Gaming", true),
    ]
}

fn fixture_devices() -> Vec<DeviceInfo> {
    let d = |name: &str, primary: bool, is_self: bool| DeviceInfo {
        device_name: name.into(),
        is_primary: primary,
        is_self,
    };
    vec![
        d("laptop", true, true),
        d("phone", false, false),
        d("desktop", false, false),
    ]
}

/// Turn one control request into a response, mutating shared state where the op is a mutation.
fn handle(state: &Mutex<State>, req: ControlRequest) -> ControlResponse {
    let mut s = state.lock().unwrap();
    match req {
        // Watch is streamed in `serve_conn` and never reaches here; a snapshot is a safe fallback.
        ControlRequest::Status | ControlRequest::Watch => {
            ControlResponse::Status(Box::new(s.status()))
        }

        ControlRequest::Manage(op) => {
            let message = match op {
                ManageOp::List => "devices".into(),
                ManageOp::Rename { new_name } => {
                    if let Some(d) = s.devices.iter_mut().find(|d| d.is_self) {
                        d.device_name = new_name.clone();
                    }
                    format!("renamed to {new_name}")
                }
                ManageOp::SetPrimary { device_name } => {
                    for d in &mut s.devices {
                        d.is_primary = d.device_name == device_name;
                    }
                    format!("{device_name} is now primary")
                }
                ManageOp::Remove { device_name } => {
                    s.devices.retain(|d| d.device_name != device_name);
                    format!("removed {device_name}")
                }
            };
            ControlResponse::Manage(ManageResp {
                message,
                devices: s.devices.clone(),
            })
        }

        ControlRequest::Expose(op) => {
            let message = match op {
                ExposeOp::List => "exposed".into(),
                ExposeOp::Add { proto, port, net } => {
                    s.exposed.retain(|e| !(e.proto == proto && e.port == port));
                    s.exposed.push(ExposedPort {
                        proto,
                        port,
                        net,
                        active: true,
                    });
                    format!("exposed {}/{port}", proto.as_str())
                }
                ExposeOp::Remove { proto, port, .. } => {
                    s.exposed.retain(|e| !(e.proto == proto && e.port == port));
                    format!("unexposed {}/{port}", proto.as_str())
                }
            };
            ControlResponse::Expose(ExposeResp {
                message,
                exposed: s.exposed.clone(),
            })
        }

        ControlRequest::SetNetwork {
            guild_id,
            role_id,
            enabled,
        } => {
            if let Some(n) = s
                .networks
                .iter_mut()
                .find(|n| n.guild_id == guild_id && n.role_id == role_id)
            {
                n.enabled = enabled;
            }
            ControlResponse::Network(NetworkResp {
                message: format!("network {}", if enabled { "enabled" } else { "disabled" }),
                networks: s.networks.clone(),
            })
        }

        ControlRequest::SetConnected { connected } => {
            s.connected = connected;
            ControlResponse::Connected(ConnectedResp {
                connected,
                message: if connected {
                    "connected"
                } else {
                    "disconnected"
                }
                .into(),
            })
        }

        ControlRequest::SetNewNetworkDefault { disable } => {
            s.disable_new_networks = disable;
            ControlResponse::Status(Box::new(s.status()))
        }

        ControlRequest::SetOwnDevicePeering { enabled } => {
            s.peer_own_devices = enabled;
            ControlResponse::Status(Box::new(s.status()))
        }

        ControlRequest::BlockPeer { user_id, username } => {
            s.peers.retain(|p| p.user_id != user_id);
            s.blocked.push(BlockedUser { user_id, username });
            ControlResponse::Status(Box::new(s.status()))
        }

        ControlRequest::UnblockPeer { user_id } => {
            s.blocked.retain(|b| b.user_id != user_id);
            // Restore that user's fixture peers so the demo can toggle repeatedly.
            let restored: Vec<_> = fixture_peers()
                .into_iter()
                .filter(|p| p.user_id == user_id)
                .collect();
            for p in restored {
                if !s.peers.iter().any(|e| e.hostname == p.hostname) {
                    s.peers.push(p);
                }
            }
            ControlResponse::Status(Box::new(s.status()))
        }

        ControlRequest::Login => ControlResponse::Login(LoginResp {
            authorize_url: "https://discord.com/oauth2/authorize?client_id=demo".into(),
        }),

        ControlRequest::Logout => ControlResponse::Logout(LogoutResp {
            message: "logged out".into(),
        }),

        ControlRequest::ApplyUpdate => ControlResponse::Update(UpdateResp {
            version: "0.4.0".into(),
            message: "no update staged".into(),
        }),
    }
}

/// Read one newline-JSON request, reply with one newline-JSON response, then close — matching the
/// GUI client's one-shot-per-request transport. `Watch` is the exception: it holds the connection
/// open and re-pushes the status snapshot periodically (like the real engine's live stream), which
/// also keeps the demo's rotating directive flowing.
async fn serve_conn(stream: impl AsyncReadWrite, state: Arc<Mutex<State>>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
        return;
    }
    let req = match serde_json::from_str::<ControlRequest>(line.trim()) {
        Ok(req) => req,
        Err(e) => {
            let mut bytes =
                serde_json::to_vec(&ControlResponse::Error(format!("bad request: {e}")))
                    .unwrap_or_default();
            bytes.push(b'\n');
            let _ = reader.get_mut().write_all(&bytes).await;
            let _ = reader.get_mut().flush().await;
            return;
        }
    };
    if matches!(req, ControlRequest::Watch) {
        let mut stream = reader.into_inner();
        loop {
            let resp = ControlResponse::Status(Box::new(state.lock().unwrap().status()));
            let mut bytes = serde_json::to_vec(&resp).unwrap_or_default();
            bytes.push(b'\n');
            if stream.write_all(&bytes).await.is_err() || stream.flush().await.is_err() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    let resp = handle(&state, req);
    let mut bytes = serde_json::to_vec(&resp).unwrap_or_default();
    bytes.push(b'\n');
    let _ = reader.get_mut().write_all(&bytes).await;
    let _ = reader.get_mut().flush().await;
}

// interprocess' tokio Stream implements both halves; alias the bound for `serve_conn`.
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> AsyncReadWrite for T {}

/// Launch the `unitylan-gui` binary that sits alongside this example in the target dir, pointed at
/// our socket. Returns the child so the caller can exit the process when the GUI window closes.
fn launch_gui(sock: &str) -> anyhow::Result<std::process::Child> {
    // …/target/<profile>/examples/fake-engine → …/target/<profile>/unitylan-gui
    let exe = std::env::current_exe()?;
    let gui = exe
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("cannot locate target dir from {}", exe.display()))?
        .join(format!("unitylan-gui{}", std::env::consts::EXE_SUFFIX));
    std::process::Command::new(&gui)
        .arg(sock)
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!(
                "launching {} (built? `cargo build -p unitylan-gui`): {e}",
                gui.display()
            )
        })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let no_gui = args.iter().any(|a| a == "--no-gui");
    let no_script = args.iter().any(|a| a == "--no-script");
    let path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "control.sock".into());

    #[cfg(not(windows))]
    let _ = std::fs::remove_file(&path);
    let listener = ListenerOptions::new()
        .name(to_name(&path)?)
        .create_tokio()?;
    let script = if no_script { Vec::new() } else { demo_script() };
    let state = Arc::new(Mutex::new(State::new(script)));
    eprintln!("fake-engine listening on {path}");

    // Bind first, then open the GUI on the same socket, and exit when its window closes so the whole
    // demo is one Ctrl-C-free step. `--no-gui` leaves it serving for a manually-launched frontend.
    if !no_gui {
        let mut child = launch_gui(&path)?;
        std::thread::spawn(move || {
            let _ = child.wait();
            std::process::exit(0);
        });
    }

    loop {
        let stream = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(serve_conn(stream, state));
    }
}
