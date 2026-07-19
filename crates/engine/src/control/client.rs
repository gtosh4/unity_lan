//! The frontend side of the control socket: connect, send one `ControlRequest`, read one
//! `ControlResponse`. Used by the engine's own CLI and (over the same protocol) by the GUI.

use anyhow::Context;
use common::api::{ManageOp, ManageResp};
use common::control::{
    ControlRequest, ControlResponse, ExposeOp, ExposeResp, LoginResp, NetworkResp, StatusReport,
    UpdateResp,
};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::tokio::Stream as LocalStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::to_name;

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
    // `Status` is boxed on the wire (see `ControlResponse::Status`); unwrap for the caller.
    expect_resp!(
        request(endpoint, &ControlRequest::Status).await?,
        ControlResponse::Status
    )
    .map(|s| *s)
}

/// Client: run a device-management op via the daemon (which forwards it to the coordinator).
pub async fn client_manage(endpoint: &str, op: ManageOp) -> anyhow::Result<ManageResp> {
    expect_resp!(
        request(endpoint, &ControlRequest::Manage(op)).await?,
        ControlResponse::Manage
    )
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

/// Client: apply the staged auto-update. Fails if no verified update is staged; on success the
/// daemon acks and restarts, so this socket drops.
pub async fn client_apply_update(endpoint: &str) -> anyhow::Result<UpdateResp> {
    expect_resp!(
        request(endpoint, &ControlRequest::ApplyUpdate).await?,
        ControlResponse::Update
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

/// Client: toggle whether this device always peers with the owner's own other devices. Returns the
/// updated status.
pub async fn client_set_own_device_peering(
    endpoint: &str,
    enabled: bool,
) -> anyhow::Result<StatusReport> {
    expect_resp!(
        request(endpoint, &ControlRequest::SetOwnDevicePeering { enabled }).await?,
        ControlResponse::Status
    )
    .map(|s| *s)
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
    expect_resp!(request(endpoint, &req).await?, ControlResponse::Status).map(|s| *s)
}
