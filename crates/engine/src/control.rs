//! Local control socket (design.md §3.2, §8): an unprivileged frontend (CLI now, GUI later)
//! talks to the privileged engine daemon over a local socket. Newline-delimited JSON.
//!
//! Transport is `interprocess`'s cross-platform local socket — a Unix-domain socket on unix, a
//! named pipe on Windows — so the same newline-JSON protocol works on both. The endpoint is named
//! by [`crate::config::Config::control_name`] (a filesystem path on unix, a pipe name on Windows).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use common::api::{ManageOp, ManageResp, NetworkStatus};
use common::control::{
    BlockedUser, ConnectedResp, ControlRequest, ControlResponse, DeviceStatus, ExposeOp,
    ExposeResp, LoginResp, LogoutResp, NetworkResp, PeerStatus, StatusReport,
};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::tokio::Stream as LocalStream;
#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{ListenerOptions, Name};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Notify, RwLock};

use crate::coord::{self, SeedPeer, SelfDevice};
use crate::fw::Firewall;
use crate::netcfg::LocalNet;
use crate::oauth;

/// Build the platform local-socket name from a config endpoint string: a filesystem path on unix,
/// a `\\.\pipe\<name>` named pipe on Windows.
fn to_name(endpoint: &str) -> std::io::Result<Name<'_>> {
    #[cfg(windows)]
    {
        endpoint.to_ns_name::<GenericNamespaced>()
    }
    #[cfg(not(windows))]
    {
        endpoint.to_fs_name::<GenericFilePath>()
    }
}

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
}

/// Flip the "needs login" flag the daemon exposes while it's up but not yet enrolled.
pub async fn set_needs_login(shared: &Shared, needs: bool) {
    shared.write().await.needs_login = needs;
}

/// Set the mesh connection state the daemon reports (`true` = connected, `false` = disconnected).
pub async fn set_connected(shared: &Shared, connected: bool) {
    shared.write().await.connected = connected;
}

/// Set the new-network default the daemon reports, so the GUI reflects it without a full refresh.
pub async fn set_disable_new(shared: &Shared, disable: bool) {
    shared.write().await.disable_new_networks = disable;
}

/// Overlay coordinator reachability without rebuilding the snapshot — the mesh runs from cache when
/// a refresh fails, so this flags the health of the last coordinator contact.
pub async fn set_coord_online(shared: &Shared, online: bool) {
    shared.write().await.coordinator_online = online;
}

/// Reset the status to the logged-out state: no device/peers/identity, `needs_login` set so the GUI
/// shows the login screen. Called after a logout tears the mesh down and before we re-register.
pub async fn set_logged_out(shared: &Shared) {
    *shared.write().await = StatusReport {
        needs_login: true,
        ..Default::default()
    };
}

/// Shared, live status the daemon updates and the control socket reads.
pub type Shared = Arc<RwLock<StatusReport>>;

pub fn shared() -> Shared {
    Arc::new(RwLock::new(StatusReport::default()))
}

/// Rebuild the status snapshot from the current device + seed peers. `disabled` is the local
/// opt-out set, so the reported per-network `enabled` reflects the local toggle immediately (even
/// before the coordinator has mirrored it).
#[allow(clippy::too_many_arguments)]
pub async fn update(
    shared: &Shared,
    device: &SelfDevice,
    seeds: &[SeedPeer],
    disabled: &HashSet<(u64, u64)>,
    blocked: &HashMap<u64, String>,
    connected: bool,
    disable_new_networks: bool,
    coordinator_online: bool,
) {
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
                hostname: s.hostname.clone(),
                wg_ip: s.ip,
                endpoint: s.endpoint,
                reach: common::control::PeerReach::Direct, // overlaid by `set_live`
                user_id: s.user_id,
                username: s.username.clone(),
                // Live telemetry — all overlaid by `set_live` on the next refresh loop.
                up: false,
                latency_ms: None,
                rx_bytes: 0,
                tx_bytes: 0,
                last_handshake_secs: None,
                networks: s.networks.clone(),
            })
            .collect(),
        networks: effective_networks(&device.networks_status, disabled),
        needs_login: false, // a device present means we're enrolled
        connected,
        disable_new_networks,
        identity: Some(device.username.clone()),
        coordinator_online,
        blocked: blocked_list(blocked),
    };
    *shared.write().await = report;
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
pub async fn set_blocked(shared: &Shared, blocked: &HashMap<u64, String>) {
    let mut report = shared.write().await;
    report.peers.retain(|p| !blocked.contains_key(&p.user_id));
    report.blocked = blocked_list(blocked);
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
pub async fn set_live(
    shared: &Shared,
    live: &std::collections::HashMap<std::net::Ipv4Addr, PeerLive>,
) {
    let mut report = shared.write().await;
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

/// Serve the control socket until the task is dropped. `endpoint` is the platform local-socket
/// name (see [`crate::config::Config::control_name`]).
// `group` only applies to unix socket ownership (`grant_socket_access`); Windows named pipes
// don't use it.
#[cfg_attr(windows, allow(unused_variables))]
pub async fn serve(endpoint: &str, group: Option<String>, ctx: Ctx) -> anyhow::Result<()> {
    // Clear a stale unix socket file from a previous run (named pipes have no filesystem residue).
    #[cfg(not(windows))]
    let _ = std::fs::remove_file(endpoint);
    let listener = ListenerOptions::new()
        .name(to_name(endpoint)?)
        .create_tokio()
        .with_context(|| format!("binding control socket {endpoint}"))?;
    #[cfg(not(windows))]
    grant_socket_access(endpoint, group.as_deref());
    tracing::info!(socket = %endpoint, "control socket listening");
    loop {
        let stream = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, ctx).await {
                tracing::warn!("control conn: {e:#}");
            }
        });
    }
}

/// Restrict the control socket to authorized callers. It grants full device authority, so it's
/// mode 660 (never world-accessible); ownership decides who beyond root may connect. In order:
///
/// - `control_group` set → `root:<group>`, so group members' frontends can drive the daemon
///   (packaged installs add the intended user to that group).
/// - else launched via sudo → hand it to the invoking user (`$SUDO_UID`), the dev path.
/// - else left root-only.
///
/// All best-effort: a failure only means the frontend can't connect, never a broken daemon.
#[cfg(not(windows))]
fn grant_socket_access(endpoint: &str, group: Option<&str>) {
    use std::os::unix::fs::{chown, PermissionsExt};
    let _ = std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o660));
    match group {
        Some(name) => match group_gid(name) {
            Some(gid) => {
                let _ = chown(endpoint, None, Some(gid));
            }
            None => tracing::warn!(
                group = name,
                "control_group not found; socket left root-only"
            ),
        },
        None => {
            if let Some(uid) = std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok()) {
                let gid = std::env::var("SUDO_GID").ok().and_then(|g| g.parse().ok());
                let _ = chown(endpoint, Some(uid), gid);
            }
        }
    }
}

/// Look up a group's gid by name via `getgrnam`. `None` if the group doesn't exist.
#[cfg(not(windows))]
fn group_gid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: getgrnam returns a pointer into a static buffer; we read gr_gid before returning and
    // make no further libc calls that would clobber it. Single-threaded startup context.
    unsafe {
        let grp = libc::getgrnam(cname.as_ptr());
        grp.as_ref().map(|g| g.gr_gid)
    }
}

async fn handle_conn(stream: LocalStream, ctx: Ctx) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(());
    }
    let req: ControlRequest = serde_json::from_str(line.trim())?;
    let resp = match req {
        ControlRequest::Status => ControlResponse::Status(ctx.status.read().await.clone()),
        ControlRequest::Manage(op) => match ctx.token.read().await.clone() {
            None => ControlResponse::Error("device not enrolled yet".into()),
            Some(token) => match coord::manage(&ctx.coordinator, token, op).await {
                Ok(r) => ControlResponse::Manage(r),
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            },
        },
        ControlRequest::Expose(op) => match &ctx.fw {
            None => ControlResponse::Error("firewall disabled (set firewall = true)".into()),
            Some(fw) => {
                let held = ctx
                    .status
                    .read()
                    .await
                    .device
                    .as_ref()
                    .map(|d| d.networks.clone())
                    .unwrap_or_default();
                match apply_expose(fw, op, &held) {
                    Ok(r) => ControlResponse::Expose(r),
                    Err(e) => ControlResponse::Error(format!("{e:#}")),
                }
            }
        },
        // Local network peering toggle: update the opt-out set (persist + wake the daemon to
        // re-mesh immediately). The daemon carries it to the coordinator on the next refresh.
        ControlRequest::SetNetwork {
            guild_id,
            role_id,
            enabled,
        } => {
            match ctx.localnet.set(guild_id, role_id, enabled) {
                Ok(_) => {
                    // `status.networks` already carries effective (locally-overridden) state, so
                    // only override the row we just toggled; the rest stay as reported.
                    let networks = ctx
                        .status
                        .read()
                        .await
                        .networks
                        .iter()
                        .map(|n| NetworkStatus {
                            enabled: if (n.guild_id, n.role_id) == (guild_id, role_id) {
                                enabled
                            } else {
                                n.enabled
                            },
                            ..n.clone()
                        })
                        .collect();
                    let message = format!(
                        "network {guild_id}/{role_id} peering {} (locally; syncs to coordinator on \
                         next refresh)",
                        if enabled { "enabled" } else { "disabled" }
                    );
                    ControlResponse::Network(NetworkResp { message, networks })
                }
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            }
        }
        // Interactive login (engine-owned PKCE): build the authorize URL and bind a loopback
        // listener, hand the URL to the frontend to open, and finish the exchange in the background.
        // The daemon's register loop brings up the mesh once complete() binds the device.
        ControlRequest::Login => {
            let pubkey = *ctx.pubkey.read().await;
            match oauth::begin(&ctx.coordinator, &ctx.oauth_redirect, pubkey).await {
                Ok(login) => {
                    let authorize_url = login.authorize_url.clone();
                    tokio::spawn(async move {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(300),
                            login.complete(),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => tracing::error!("interactive login failed: {e:#}"),
                            Err(_) => tracing::warn!("interactive login timed out; retry `login`"),
                        }
                    });
                    ControlResponse::Login(LoginResp { authorize_url })
                }
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            }
        }
        // Connect/disconnect the mesh: flip the local paused flag (persist + wake the daemon to
        // re-mesh or tear the mesh down at once). The daemon carries `paused` to the coordinator on
        // the next refresh, which withdraws/re-advertises this device's presence to co-members.
        ControlRequest::SetConnected { connected } => match ctx.localnet.set_paused(!connected) {
            Ok(_) => ControlResponse::Connected(ConnectedResp {
                connected,
                message: format!(
                    "mesh {} (locally; syncs to coordinator on next refresh)",
                    if connected {
                        "connected"
                    } else {
                        "disconnected"
                    }
                ),
            }),
            Err(e) => ControlResponse::Error(format!("{e:#}")),
        },
        // Log out: wake the daemon's mesh loop, which un-enrolls at the coordinator, tears the mesh
        // down (drops every peer + brings the interface down), discards the local key/token, and
        // returns to the not-logged-in state with a fresh key. Fire-and-signal, like `Login`.
        ControlRequest::Logout => {
            ctx.logout.notify_one();
            ControlResponse::Logout(LogoutResp {
                message: "logging out — tearing down the mesh and un-enrolling".into(),
            })
        }
        // Locally block / un-block a user (persist + wake the daemon to re-mesh, dropping or
        // re-admitting their peers). Purely local — never forwarded to the coordinator. Mirror the
        // change into the live status so the GUI reflects it before the re-mesh lands, then return
        // the updated snapshot.
        ControlRequest::BlockPeer { user_id, username } => {
            match ctx.localnet.set_blocked(user_id, username, true) {
                Ok(_) => {
                    set_blocked(&ctx.status, &ctx.localnet.blocked_snapshot()).await;
                    ControlResponse::Status(ctx.status.read().await.clone())
                }
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            }
        }
        ControlRequest::UnblockPeer { user_id } => {
            match ctx.localnet.set_blocked(user_id, String::new(), false) {
                Ok(_) => {
                    set_blocked(&ctx.status, &ctx.localnet.blocked_snapshot()).await;
                    ControlResponse::Status(ctx.status.read().await.clone())
                }
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            }
        }
        // Set the local default for networks discovered from now on (persisted, source of truth).
        // Doesn't touch already-known networks, so no re-mesh; mirror it into the live status so the
        // GUI reflects it at once, then return the updated snapshot.
        ControlRequest::SetNewNetworkDefault { disable } => {
            match ctx.localnet.set_disable_new(disable) {
                Ok(_) => {
                    set_disable_new(&ctx.status, disable).await;
                    ControlResponse::Status(ctx.status.read().await.clone())
                }
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            }
        }
    };
    let mut out = serde_json::to_vec(&resp)?;
    out.push(b'\n');
    let mut stream = reader.into_inner();
    stream.write_all(&out).await?;
    stream.flush().await?; // flush before drop so the named-pipe peer sees the reply
    Ok(())
}

async fn request(endpoint: &str, req: &ControlRequest) -> anyhow::Result<ControlResponse> {
    let stream = LocalStream::connect(to_name(endpoint)?)
        .await
        .with_context(|| {
            format!("connecting to control socket {endpoint} (is the daemon running?)")
        })?;
    let mut reader = BufReader::new(stream);
    let mut bytes = serde_json::to_vec(req)?;
    bytes.push(b'\n');
    reader.get_mut().write_all(&bytes).await?;
    reader.get_mut().flush().await?;
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}

/// Unwrap the expected `ControlResponse` variant, mapping an `Error` reply or any other variant
/// to a bail. Used by every `client_*` wrapper below.
macro_rules! expect_resp {
    ($resp:expr, $variant:path) => {
        match $resp {
            $variant(r) => Ok(r),
            ControlResponse::Error(e) => anyhow::bail!("{e}"),
            _ => anyhow::bail!("unexpected response"),
        }
    };
}

/// Client: fetch the daemon's status snapshot.
pub async fn client_status(endpoint: &str) -> anyhow::Result<StatusReport> {
    expect_resp!(
        request(endpoint, &ControlRequest::Status).await?,
        ControlResponse::Status
    )
}

/// Client: run a device-management op via the daemon (which forwards it to the coordinator).
pub async fn client_manage(endpoint: &str, op: ManageOp) -> anyhow::Result<ManageResp> {
    expect_resp!(
        request(endpoint, &ControlRequest::Manage(op)).await?,
        ControlResponse::Manage
    )
}

/// Apply an expose op to the local firewall and report the resulting exposed set. A `--net` scope
/// must name a network this device actually holds.
fn apply_expose(fw: &Firewall, op: ExposeOp, held_nets: &[String]) -> anyhow::Result<ExposeResp> {
    let (message, exposed) = match op {
        ExposeOp::List => ("exposed ports".to_string(), fw.list()),
        ExposeOp::Add { proto, port, net } => {
            if let Some(n) = &net {
                if !held_nets.iter().any(|h| h == n) {
                    anyhow::bail!(
                        "not a member of network '{n}' (your networks: {})",
                        held_nets.join(", ")
                    );
                }
            }
            let scope = net
                .as_deref()
                .map(|n| format!(" (net: {n})"))
                .unwrap_or_default();
            (
                format!("exposed {}/{port}{scope}", proto.as_str()),
                fw.expose(proto, port, net)?,
            )
        }
        ExposeOp::Remove { proto, port } => (
            format!("closed {}/{port}", proto.as_str()),
            fw.unexpose(proto, port)?,
        ),
    };
    Ok(ExposeResp { message, exposed })
}

/// Client: expose/unexpose/list ports via the daemon's local firewall.
pub async fn client_expose(endpoint: &str, op: ExposeOp) -> anyhow::Result<ExposeResp> {
    expect_resp!(
        request(endpoint, &ControlRequest::Expose(op)).await?,
        ControlResponse::Expose
    )
}

/// Client: start interactive login via the daemon; returns the authorize URL to open.
pub async fn client_login(endpoint: &str) -> anyhow::Result<LoginResp> {
    expect_resp!(
        request(endpoint, &ControlRequest::Login).await?,
        ControlResponse::Login
    )
}

/// Client: connect (`true`) or disconnect (`false`) the mesh.
pub async fn client_set_connected(
    endpoint: &str,
    connected: bool,
) -> anyhow::Result<common::control::ConnectedResp> {
    expect_resp!(
        request(endpoint, &ControlRequest::SetConnected { connected }).await?,
        ControlResponse::Connected
    )
}

/// Client: toggle this device's peering on a network (role@guild).
pub async fn client_set_network(
    endpoint: &str,
    guild_id: u64,
    role_id: u64,
    enabled: bool,
) -> anyhow::Result<NetworkResp> {
    expect_resp!(
        request(
            endpoint,
            &ControlRequest::SetNetwork {
                guild_id,
                role_id,
                enabled,
            },
        )
        .await?,
        ControlResponse::Network
    )
}

/// Client: locally block (`Some(username)`) or un-block (`None`) a user by `user_id`. Returns the
/// updated status.
pub async fn client_set_blocked(
    endpoint: &str,
    user_id: u64,
    username: Option<String>,
) -> anyhow::Result<StatusReport> {
    let req = match username {
        Some(username) => ControlRequest::BlockPeer { user_id, username },
        None => ControlRequest::UnblockPeer { user_id },
    };
    expect_resp!(request(endpoint, &req).await?, ControlResponse::Status)
}
