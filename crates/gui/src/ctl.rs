//! Async control-socket client for the GUI. Same newline-JSON protocol the engine serves
//! (common::control); the GUI is unprivileged and never touches mesh state directly.

use std::path::PathBuf;

use common::api::{ManageOp, ManageResp};
use common::control::{
    ControlRequest, ControlResponse, ExposeOp, ExposeResp, LoginResp, NetworkResp, StatusReport,
};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::tokio::Stream as LocalStream;
#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::Name;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Resolve the socket argument to a platform local-socket name. On unix it's the socket path; on
/// Windows it's a named pipe whose name mirrors the engine's `Config::control_name` (`unitylan-`
/// plus the path's file stem), so a default `control.sock` on both sides agrees on the same pipe.
fn to_name(path: PathBuf) -> std::io::Result<Name<'static>> {
    #[cfg(windows)]
    {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("control");
        format!("unitylan-{stem}").to_ns_name::<GenericNamespaced>()
    }
    #[cfg(not(windows))]
    {
        path.to_fs_name::<GenericFilePath>()
    }
}

/// One request/response round-trip. Errors are stringified for display in the UI.
async fn request(path: PathBuf, req: ControlRequest) -> Result<ControlResponse, String> {
    let name = to_name(path).map_err(|e| e.to_string())?;
    let stream = LocalStream::connect(name)
        .await
        .map_err(|e| format!("connect (is the daemon running?): {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    reader
        .get_mut()
        .write_all(&bytes)
        .await
        .map_err(|e| e.to_string())?;
    reader.get_mut().flush().await.map_err(|e| e.to_string())?;
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::from_str(line.trim()).map_err(|e| e.to_string())
}

pub async fn fetch_status(path: PathBuf) -> Result<StatusReport, String> {
    match request(path, ControlRequest::Status).await? {
        ControlResponse::Status(s) => Ok(s),
        ControlResponse::Error(e) => Err(e),
        _ => Err("unexpected response".into()),
    }
}

pub async fn manage(path: PathBuf, op: ManageOp) -> Result<ManageResp, String> {
    match request(path, ControlRequest::Manage(op)).await? {
        ControlResponse::Manage(r) => Ok(r),
        ControlResponse::Error(e) => Err(e),
        _ => Err("unexpected response".into()),
    }
}

pub async fn expose(path: PathBuf, op: ExposeOp) -> Result<ExposeResp, String> {
    match request(path, ControlRequest::Expose(op)).await? {
        ControlResponse::Expose(r) => Ok(r),
        ControlResponse::Error(e) => Err(e),
        _ => Err("unexpected response".into()),
    }
}

pub async fn set_network(
    path: PathBuf,
    guild_id: u64,
    role_id: u64,
    enabled: bool,
) -> Result<NetworkResp, String> {
    match request(
        path,
        ControlRequest::SetNetwork {
            guild_id,
            role_id,
            enabled,
        },
    )
    .await?
    {
        ControlResponse::Network(r) => Ok(r),
        ControlResponse::Error(e) => Err(e),
        _ => Err("unexpected response".into()),
    }
}

pub async fn login(path: PathBuf) -> Result<LoginResp, String> {
    match request(path, ControlRequest::Login).await? {
        ControlResponse::Login(r) => Ok(r),
        ControlResponse::Error(e) => Err(e),
        _ => Err("unexpected response".into()),
    }
}
