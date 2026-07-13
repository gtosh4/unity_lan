//! Local control socket (design.md §3.2, §8): an unprivileged frontend (CLI now, GUI later)
//! talks to the privileged engine daemon over a local socket. Newline-delimited JSON.
//!
//! Transport is `interprocess`'s cross-platform local socket — a Unix-domain socket on unix, a
//! named pipe on Windows — so the same newline-JSON protocol works on both. The endpoint is named
//! by [`crate::config::Config::control_name`] (a filesystem path on unix, a pipe name on Windows).

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use common::api::{ManageOp, ManageResp, NetworkStatus};
use common::control::{
    ControlRequest, ControlResponse, DeviceStatus, ExposeOp, ExposeResp, LoginResp, NetworkResp,
    PeerStatus, StatusReport,
};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::tokio::Stream as LocalStream;
#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{ListenerOptions, Name};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;

use crate::coord::{self, SeedPeer, SelfDevice};
use crate::fw::Firewall;
use crate::netcfg::LocalNet;

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
    pub status: Shared,
    pub coordinator: String,
    /// The device token, set once the daemon has registered.
    pub token: Arc<RwLock<Option<String>>>,
    /// The host firewall, if enabled — handles `expose`/`unexpose` locally.
    pub fw: Option<Arc<Firewall>>,
    /// Local per-network peering opt-out — handles the network toggle locally.
    pub localnet: Arc<LocalNet>,
    /// This device's WG public key — used to start interactive login (OAuth).
    pub pubkey: [u8; 32],
}

/// Flip the "needs login" flag the daemon exposes while it's up but not yet enrolled.
pub async fn set_needs_login(shared: &Shared, needs: bool) {
    shared.write().await.needs_login = needs;
}

/// Shared, live status the daemon updates and the control socket reads.
pub type Shared = Arc<RwLock<StatusReport>>;

pub fn shared() -> Shared {
    Arc::new(RwLock::new(StatusReport::default()))
}

/// Rebuild the status snapshot from the current device + seed peers. `disabled` is the local
/// opt-out set, so the reported per-network `enabled` reflects the local toggle immediately (even
/// before the coordinator has mirrored it).
pub async fn update(
    shared: &Shared,
    device: &SelfDevice,
    seeds: &[SeedPeer],
    disabled: &HashSet<(u64, u64)>,
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
                reach: common::control::PeerReach::Direct, // overlaid by `set_reach`
            })
            .collect(),
        networks: effective_networks(&device.networks_status, disabled),
        needs_login: false, // a device present means we're enrolled
    };
    *shared.write().await = report;
}

/// Overlay per-peer reachability onto the current status without rebuilding it (cheap — no DNS or
/// firewall work), so a stuck hole punch surfaces promptly even when nothing else changed. Keyed
/// by the peer's wg IP.
pub async fn set_reach(
    shared: &Shared,
    reach: &std::collections::HashMap<std::net::Ipv4Addr, common::control::PeerReach>,
) {
    let mut report = shared.write().await;
    for p in &mut report.peers {
        if let Some(r) = reach.get(&p.wg_ip) {
            p.reach = *r;
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
        // Interactive login: fetch the authorize URL from the coordinator for this device pubkey.
        // The daemon's register loop binds us once the browser completes the flow.
        ControlRequest::Login => match coord::oauth_start(&ctx.coordinator, ctx.pubkey).await {
            Ok(start) => ControlResponse::Login(LoginResp {
                authorize_url: start.authorize_url,
            }),
            Err(e) => ControlResponse::Error(format!("{e:#}")),
        },
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

/// Client: fetch the daemon's status snapshot.
pub async fn client_status(endpoint: &str) -> anyhow::Result<StatusReport> {
    match request(endpoint, &ControlRequest::Status).await? {
        ControlResponse::Status(s) => Ok(s),
        ControlResponse::Error(e) => anyhow::bail!("{e}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

/// Client: run a device-management op via the daemon (which forwards it to the coordinator).
pub async fn client_manage(endpoint: &str, op: ManageOp) -> anyhow::Result<ManageResp> {
    match request(endpoint, &ControlRequest::Manage(op)).await? {
        ControlResponse::Manage(r) => Ok(r),
        ControlResponse::Error(e) => anyhow::bail!("{e}"),
        _ => anyhow::bail!("unexpected response"),
    }
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
    match request(endpoint, &ControlRequest::Expose(op)).await? {
        ControlResponse::Expose(r) => Ok(r),
        ControlResponse::Error(e) => anyhow::bail!("{e}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

/// Client: start interactive login via the daemon; returns the authorize URL to open.
pub async fn client_login(endpoint: &str) -> anyhow::Result<LoginResp> {
    match request(endpoint, &ControlRequest::Login).await? {
        ControlResponse::Login(r) => Ok(r),
        ControlResponse::Error(e) => anyhow::bail!("{e}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

/// Client: toggle this device's peering on a network (role@guild).
pub async fn client_set_network(
    endpoint: &str,
    guild_id: u64,
    role_id: u64,
    enabled: bool,
) -> anyhow::Result<NetworkResp> {
    match request(
        endpoint,
        &ControlRequest::SetNetwork {
            guild_id,
            role_id,
            enabled,
        },
    )
    .await?
    {
        ControlResponse::Network(r) => Ok(r),
        ControlResponse::Error(e) => anyhow::bail!("{e}"),
        _ => anyhow::bail!("unexpected response"),
    }
}
