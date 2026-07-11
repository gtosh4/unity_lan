//! Local control socket (design.md §3.2, §8): an unprivileged frontend (CLI now, GUI later)
//! talks to the privileged engine daemon over a Unix socket. Newline-delimited JSON.
//!
//! Read-only `status` for now. Mutations (rename / set-primary / remove) land once device
//! control requests are authenticated (set-primary is already available via `/unitylan primary`).
//! Windows named-pipe transport (via `interprocess`) is a later swap — the JSON protocol is
//! transport-agnostic.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

use crate::coord::{SeedPeer, SelfDevice};

#[derive(Serialize, Deserialize)]
pub enum ControlRequest {
    Status,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct StatusReport {
    pub device: Option<DeviceStatus>,
    pub peers: Vec<PeerStatus>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub wg_ip: Ipv4Addr,
    pub hostname: String,
    pub is_primary: bool,
    pub networks: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub hostname: String,
    pub wg_ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
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
pub async fn serve(path: &Path, shared: Shared) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(path); // clear a stale socket from a previous run
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding control socket {}", path.display()))?;
    tracing::info!(socket = %path.display(), "control socket listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, shared).await {
                tracing::warn!("control conn: {e:#}");
            }
        });
    }
}

async fn handle_conn(stream: UnixStream, shared: Shared) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(());
    }
    let req: ControlRequest = serde_json::from_str(line.trim())?;
    let resp = match req {
        ControlRequest::Status => shared.read().await.clone(),
    };
    let mut out = serde_json::to_vec(&resp)?;
    out.push(b'\n');
    reader.into_inner().write_all(&out).await?;
    Ok(())
}

/// Client side: connect, request status, return the report.
pub async fn client_status(path: &Path) -> anyhow::Result<StatusReport> {
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to control socket {} (is the daemon running?)", path.display()))?;
    let mut reader = BufReader::new(stream);
    let mut req = serde_json::to_vec(&ControlRequest::Status)?;
    req.push(b'\n');
    reader.get_mut().write_all(&req).await?;
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}
