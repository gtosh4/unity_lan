//! The daemon side of the control socket: accept connections, dispatch one `ControlRequest` per
//! connection (or stream status for a `Watch`), and apply the local-only mutations.

use anyhow::Context;
use common::api::NetworkStatus;
use common::control::{
    ConnectedResp, ControlRequest, ControlResponse, ExposeOp, ExposeResp, LoginResp, LogoutResp,
    NetworkResp, StatusReport,
};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::tokio::Stream as LocalStream;
use interprocess::local_socket::ListenerOptions;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::status::{set_blocked, set_disable_new, set_peer_own, Ctx};
use super::to_name;
use crate::coord;
use crate::fw::Firewall;
use crate::oauth;

/// Serve the control socket until the task is dropped. `endpoint` is the platform local-socket
/// name (see [`crate::config::Config::control_name`]).
// `group` only applies to unix socket ownership (`grant_socket_access`); Windows named pipes
// don't use it.
#[cfg_attr(windows, allow(unused_variables))]
pub async fn serve(endpoint: &str, group: Option<String>, ctx: Ctx) -> anyhow::Result<()> {
    // Clear a stale unix socket file from a previous run (named pipes have no filesystem residue).
    #[cfg(not(windows))]
    let _ = std::fs::remove_file(endpoint);
    let opts = ListenerOptions::new().name(to_name(endpoint)?);
    // On Windows, pin an explicit DACL (unix ownership is handled by `grant_socket_access` below).
    #[cfg(windows)]
    let opts = {
        use interprocess::os::windows::local_socket::ListenerOptionsExt;
        opts.security_descriptor(control_pipe_sd()?)
    };
    let listener = opts
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

/// The control pipe's DACL (Windows). The default named-pipe security descriptor grants *read* to
/// Everyone and the anonymous account — which leaks the status stream (peers, mesh IPs, networks,
/// block list, device identity) to any local user, other terminal-services sessions, and remote
/// callers — while granting the unprivileged GUI only read, so it couldn't drive a LocalSystem
/// service daemon. Replace it with a protected DACL: `SYSTEM` + `Administrators` full, `INTERACTIVE`
/// users read+write. INTERACTIVE covers the local GUI at any integrity level (elevated or not) and
/// excludes network/anonymous logons — the analogue of the unix `grant_socket_access` gate.
#[cfg(windows)]
fn control_pipe_sd(
) -> anyhow::Result<interprocess::os::windows::security_descriptor::SecurityDescriptor> {
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    // D:P — protected DACL (drops inheritance). FA = full; GRGW = GENERIC_READ|GENERIC_WRITE (write
    // carries FILE_CREATE_PIPE_INSTANCE, which the server needs for each accept). SY=SYSTEM,
    // BA=Administrators, IU=INTERACTIVE.
    let sddl = widestring::U16CString::from_str("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGW;;;IU)")
        .expect("static SDDL contains no interior nul");
    SecurityDescriptor::deserialize(&sddl).context("building control-pipe security descriptor")
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

/// Cap on a single control request. The socket is a privilege boundary (an unprivileged local
/// client → the root daemon); bound the read so a client that never sends a newline can't grow the
/// buffer unbounded and OOM the daemon. A control request is a one-line JSON `ControlRequest`,
/// comfortably under this.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

async fn handle_conn(stream: LocalStream, ctx: Ctx) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = (&mut reader)
        .take(MAX_REQUEST_BYTES)
        .read_line(&mut line)
        .await?;
    if n == 0 {
        return Ok(());
    }
    if n as u64 >= MAX_REQUEST_BYTES {
        anyhow::bail!("control request exceeds {MAX_REQUEST_BYTES}-byte cap");
    }
    let req: ControlRequest = serde_json::from_str(line.trim())?;
    // Watch holds the connection open and streams status changes, so it doesn't fit the
    // one-request/one-response path below — hand off to the streaming loop.
    if let ControlRequest::Watch = req {
        return stream_status(reader.into_inner(), ctx.status.subscribe()).await;
    }
    let resp = match req {
        ControlRequest::Status => ControlResponse::Status(ctx.status.borrow().clone()),
        ControlRequest::Watch => unreachable!("Watch handled above"),
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
                    .borrow()
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
                        .borrow()
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
                    let login_done = ctx.login_done.clone();
                    tokio::spawn(async move {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(300),
                            login.complete(),
                        )
                        .await
                        {
                            // Device bound — wake the enrollment loop so the mesh comes up now, not
                            // on its next `refresh_secs` poll.
                            Ok(Ok(())) => login_done.notify_one(),
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
                    set_blocked(&ctx.status, &ctx.localnet.blocked_snapshot());
                    ControlResponse::Status(ctx.status.borrow().clone())
                }
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            }
        }
        ControlRequest::UnblockPeer { user_id } => {
            match ctx.localnet.set_blocked(user_id, String::new(), false) {
                Ok(_) => {
                    set_blocked(&ctx.status, &ctx.localnet.blocked_snapshot());
                    ControlResponse::Status(ctx.status.borrow().clone())
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
                    set_disable_new(&ctx.status, disable);
                    ControlResponse::Status(ctx.status.borrow().clone())
                }
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            }
        }
        // Own-device peering toggle: update the local policy (persisted, source of truth). Wakes the
        // daemon to re-register — the coordinator adds/evicts this device from its siblings' seeds —
        // then re-mesh. Mirror it into the live status so the GUI reflects it at once.
        ControlRequest::SetOwnDevicePeering { enabled } => {
            match ctx.localnet.set_peer_own_devices(enabled) {
                Ok(_) => {
                    set_peer_own(&ctx.status, enabled);
                    ControlResponse::Status(ctx.status.borrow().clone())
                }
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            }
        }
        // Apply the staged auto-update. The daemon verified the coordinator's signed manifest against
        // the pinned anchor and staged a platform-matching artifact; here we ack immediately, then a
        // background task downloads + re-verifies (SHA-256) + applies, after which the engine restarts
        // (dropping this socket — the GUI reconnects onto the new version).
        ControlRequest::ApplyUpdate => {
            let pending = ctx.pending_update.lock().unwrap().clone();
            match pending {
                None => ControlResponse::Error("no verified update is staged".into()),
                Some(pu) => {
                    let state_dir = ctx.state_dir.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::selfupdate::apply(&pu.artifact, &state_dir).await {
                            tracing::error!("auto-update failed: {e:#}");
                        }
                    });
                    ControlResponse::Update(common::control::UpdateResp {
                        version: pu.version,
                        message: "downloading and applying the update; the engine will restart"
                            .into(),
                    })
                }
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

/// Serve a `Watch` subscription: write the current status, then a fresh `ControlResponse::Status`
/// line every time it changes, until the client disconnects (a write fails) or the daemon drops the
/// sender on shutdown. `borrow_and_update` marks the value seen so `changed()` waits for the *next*
/// change; the first iteration always sends the current snapshot.
async fn stream_status(
    mut stream: LocalStream,
    mut rx: tokio::sync::watch::Receiver<StatusReport>,
) -> anyhow::Result<()> {
    loop {
        let mut out = {
            let report = rx.borrow_and_update();
            serde_json::to_vec(&ControlResponse::Status(report.clone()))?
        };
        out.push(b'\n');
        stream.write_all(&out).await?;
        stream.flush().await?;
        // Park until the next change; Err means every sender was dropped (daemon shutting down).
        if rx.changed().await.is_err() {
            return Ok(());
        }
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

#[cfg(all(test, windows))]
mod tests {
    /// The control-pipe SDDL must parse — a typo would only surface as a runtime bind failure on a
    /// Windows service start, which the Linux-heavy test suite would never catch.
    #[test]
    fn control_pipe_sddl_is_valid() {
        super::control_pipe_sd().expect("control-pipe SDDL should deserialize");
    }
}
