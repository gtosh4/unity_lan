//! Local control socket (design.md §3.2, §8): an unprivileged frontend (CLI now, GUI later)
//! talks to the privileged engine daemon over a Unix socket. Newline-delimited JSON.
//!
//! Read-only `status` for now. Mutations (rename / set-primary / remove) land once device
//! control requests are authenticated (set-primary is already available via `/unitylan primary`).
//! Windows named-pipe transport (via `interprocess`) is a later swap — the JSON protocol is
//! transport-agnostic.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use common::api::{ManageOp, ManageResp, NetworkStatus};
use common::control::{
    ControlRequest, ControlResponse, DeviceStatus, ExposeOp, ExposeResp, NetworkResp, PeerStatus,
    StatusReport,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

use crate::coord::{self, SeedPeer, SelfDevice};
use crate::fw::Firewall;
use crate::netcfg::LocalNet;

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
            })
            .collect(),
        networks: effective_networks(&device.networks_status, disabled),
    };
    *shared.write().await = report;
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

/// Serve the control socket until the task is dropped. Recreates the socket file on start.
pub async fn serve(path: &Path, ctx: Ctx) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(path); // clear a stale socket from a previous run
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding control socket {}", path.display()))?;
    tracing::info!(socket = %path.display(), "control socket listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, ctx).await {
                tracing::warn!("control conn: {e:#}");
            }
        });
    }
}

async fn handle_conn(stream: UnixStream, ctx: Ctx) -> anyhow::Result<()> {
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
        ControlRequest::SetNetwork { guild_id, role_id, enabled } => {
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
    };
    let mut out = serde_json::to_vec(&resp)?;
    out.push(b'\n');
    reader.into_inner().write_all(&out).await?;
    Ok(())
}

async fn request(path: &Path, req: &ControlRequest) -> anyhow::Result<ControlResponse> {
    let stream = UnixStream::connect(path).await.with_context(|| {
        format!("connecting to control socket {} (is the daemon running?)", path.display())
    })?;
    let mut reader = BufReader::new(stream);
    let mut bytes = serde_json::to_vec(req)?;
    bytes.push(b'\n');
    reader.get_mut().write_all(&bytes).await?;
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}

/// Client: fetch the daemon's status snapshot.
pub async fn client_status(path: &Path) -> anyhow::Result<StatusReport> {
    match request(path, &ControlRequest::Status).await? {
        ControlResponse::Status(s) => Ok(s),
        ControlResponse::Error(e) => anyhow::bail!("{e}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

/// Client: run a device-management op via the daemon (which forwards it to the coordinator).
pub async fn client_manage(path: &Path, op: ManageOp) -> anyhow::Result<ManageResp> {
    match request(path, &ControlRequest::Manage(op)).await? {
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
            let scope = net.as_deref().map(|n| format!(" (net: {n})")).unwrap_or_default();
            (
                format!("exposed {}/{port}{scope}", proto.as_str()),
                fw.expose(proto, port, net)?,
            )
        }
        ExposeOp::Remove { proto, port } => {
            (format!("closed {}/{port}", proto.as_str()), fw.unexpose(proto, port)?)
        }
    };
    Ok(ExposeResp { message, exposed })
}

/// Client: expose/unexpose/list ports via the daemon's local firewall.
pub async fn client_expose(path: &Path, op: ExposeOp) -> anyhow::Result<ExposeResp> {
    match request(path, &ControlRequest::Expose(op)).await? {
        ControlResponse::Expose(r) => Ok(r),
        ControlResponse::Error(e) => anyhow::bail!("{e}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

/// Client: toggle this device's peering on a network (role@guild).
pub async fn client_set_network(
    path: &Path,
    guild_id: u64,
    role_id: u64,
    enabled: bool,
) -> anyhow::Result<NetworkResp> {
    match request(path, &ControlRequest::SetNetwork { guild_id, role_id, enabled }).await? {
        ControlResponse::Network(r) => Ok(r),
        ControlResponse::Error(e) => anyhow::bail!("{e}"),
        _ => anyhow::bail!("unexpected response"),
    }
}
