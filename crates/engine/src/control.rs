//! Local control socket (design.md §3.2, §8): an unprivileged frontend (CLI now, GUI later)
//! talks to the privileged engine daemon over a Unix socket. Newline-delimited JSON.
//!
//! Read-only `status` for now. Mutations (rename / set-primary / remove) land once device
//! control requests are authenticated (set-primary is already available via `/unitylan primary`).
//! Windows named-pipe transport (via `interprocess`) is a later swap — the JSON protocol is
//! transport-agnostic.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use common::api::{ManageOp, ManageResp};
use common::control::{
    ControlRequest, ControlResponse, DeviceStatus, ExposeOp, ExposeResp, PeerStatus, StatusReport,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

use crate::coord::{self, SeedPeer, SelfDevice};
use crate::fw::Firewall;

/// What the control server needs to serve status + forward mutations to the coordinator.
#[derive(Clone)]
pub struct Ctx {
    pub status: Shared,
    pub coordinator: String,
    /// The device token, set once the daemon has registered.
    pub token: Arc<RwLock<Option<String>>>,
    /// The host firewall, if enabled — handles `expose`/`unexpose` locally.
    pub fw: Option<Arc<Firewall>>,
}

/// Shared, live status the daemon updates and the control socket reads.
pub type Shared = Arc<RwLock<StatusReport>>;

pub fn shared() -> Shared {
    Arc::new(RwLock::new(StatusReport::default()))
}

/// Rebuild the status snapshot from the current device + seed peers.
pub async fn update(shared: &Shared, device: &SelfDevice, seeds: &[SeedPeer]) {
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
    };
    *shared.write().await = report;
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
            Some(fw) => match apply_expose(fw, op) {
                Ok(r) => ControlResponse::Expose(r),
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            },
        },
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

/// Apply an expose op to the local firewall and report the resulting exposed set.
fn apply_expose(fw: &Firewall, op: ExposeOp) -> anyhow::Result<ExposeResp> {
    let (message, exposed) = match op {
        ExposeOp::List => ("exposed ports".to_string(), fw.list()),
        ExposeOp::Add { net: Some(_), .. } => {
            anyhow::bail!("per-network (--net) scoping not yet supported; omit it to expose to all peers")
        }
        ExposeOp::Add { proto, port, net: None } => {
            (format!("exposed {}/{port}", proto.as_str()), fw.expose(proto, port)?)
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
