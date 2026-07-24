//! The daemon side of the control socket: accept connections, dispatch one `ControlRequest` per
//! connection (or stream status for a `Watch`), and apply the local-only mutations.

use anyhow::Context;
use common::api::NetworkStatus;
use common::control::{
    ConnectedResp, ControlRequest, ControlResponse, ExposeOp, ExposeResp, ExposeScope, LoginResp,
    LogoutResp, NetworkResp, StatusReport,
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
    // Create the socket owner-only from the start. bind() applies the process umask, so without
    // this the socket file exists at the ambient umask (often group/world-accessible) for the window
    // between bind and the tighten-to-0660 below — a local user could connect and drive the daemon
    // in that gap. 0600 is also the fail-closed default: if `grant_socket_access` later fails to
    // relax + re-own it, the socket stays root-only rather than world-open.
    #[cfg(not(windows))]
    let umask_guard = UmaskGuard::owner_only();
    let listener = opts
        .create_tokio()
        .with_context(|| format!("binding control socket {endpoint}"))?;
    #[cfg(not(windows))]
    {
        drop(umask_guard);
        grant_socket_access(endpoint, group.as_deref());
    }
    tracing::info!(socket = %endpoint, "control socket listening");
    // Bound concurrent connections. The socket is a privilege boundary reachable by an
    // authorized-but-unprivileged local caller (unix group / Windows INTERACTIVE); a flood of
    // connections would otherwise spawn an unbounded number of tasks against the root daemon. A
    // long-lived `Watch` holds its permit for the subscription's lifetime, so the cap is generous —
    // a real host runs one GUI and a handful of `ctl` invocations.
    let conns = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONTROL_CONNS));
    loop {
        let permit = conns
            .clone()
            .acquire_owned()
            .await
            .expect("control connection semaphore is never closed");
        let stream = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_conn(stream, ctx).await {
                tracing::warn!("control conn: {e:#}");
            }
        });
    }
}

/// Sets the process umask to 0177 (so a file is created 0600) for its lifetime, restoring the
/// previous value on drop. Used to bracket the control-socket bind so the socket is never briefly
/// group/world-accessible.
#[cfg(not(windows))]
struct UmaskGuard(libc::mode_t);

#[cfg(not(windows))]
impl UmaskGuard {
    fn owner_only() -> Self {
        // SAFETY: umask is a process-global setter with no memory-safety concerns; startup is
        // single-threaded so the brief window doesn't race other file creation.
        Self(unsafe { libc::umask(0o177) })
    }
}

#[cfg(not(windows))]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: as above; restores the umask we captured.
        unsafe { libc::umask(self.0) };
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

/// Give the same caller `grant_socket_access` authorized traversal (`--x`) of `dir` — the state dir,
/// when the control socket lives inside it (the default, `<state_dir>/control.sock`).
///
/// The state dir is 0700 root: it holds the WG private key, device token, relay secret and pinned
/// anchors. Without an `x` bit on it a group member cannot *reach* the socket at all, however the
/// socket itself is owned — the 0660 `root:<group>` grant is dead letter. 0710 hands out exactly the
/// missing piece: open a path you already know, no listing, no read. Ownership follows the same
/// order as the socket grant so both agree on who the frontend is; unlike the socket the dir keeps
/// `root` as owner, since only the daemon writes here.
///
/// Best-effort, as with the socket: a failure costs the frontend its connection, not the daemon.
#[cfg(not(windows))]
pub fn grant_dir_traversal(dir: &std::path::Path, group: Option<&str>) {
    use std::os::unix::fs::{chown, PermissionsExt};
    let gid = match group {
        Some(name) => group_gid(name),
        None => std::env::var("SUDO_GID").ok().and_then(|g| g.parse().ok()),
    };
    // No authorized non-root caller (no group, no sudo): leave the dir owner-only.
    let Some(gid) = gid else { return };
    if chown(dir, None, Some(gid)).is_ok() {
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o710));
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

/// Cap on concurrent control connections — see the semaphore in [`serve`].
const MAX_CONTROL_CONNS: usize = 256;

/// Deadline for a connection to deliver its one-line request. Without it a caller could connect and
/// send nothing (or a partial line), parking a task and holding a connection permit indefinitely —
/// a slowloris against the daemon. Only the request read is bounded; a `Watch` subscription streams
/// for as long as the client stays connected.
const REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

async fn handle_conn(stream: LocalStream, ctx: Ctx) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = tokio::time::timeout(
        REQUEST_READ_TIMEOUT,
        (&mut reader).take(MAX_REQUEST_BYTES).read_line(&mut line),
    )
    .await
    .context("control request not received within the read timeout")??;
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
        ControlRequest::Status => ControlResponse::Status(Box::new(ctx.status.borrow().clone())),
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
                let held = ctx.status.borrow().networks.clone();
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
                    ControlResponse::Status(Box::new(ctx.status.borrow().clone()))
                }
                Err(e) => ControlResponse::Error(format!("{e:#}")),
            }
        }
        ControlRequest::UnblockPeer { user_id } => {
            match ctx.localnet.set_blocked(user_id, String::new(), false) {
                Ok(_) => {
                    set_blocked(&ctx.status, &ctx.localnet.blocked_snapshot());
                    ControlResponse::Status(Box::new(ctx.status.borrow().clone()))
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
                    ControlResponse::Status(Box::new(ctx.status.borrow().clone()))
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
                    ControlResponse::Status(Box::new(ctx.status.borrow().clone()))
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
                    // Recorded once the swap succeeds, so the restarted engine can confirm the update
                    // took (or warn that it didn't) — see `selfupdate::reconcile_update_marker`.
                    let version = pu.version.clone();
                    // Both platforms: download + verify + swap the binary, then signal the daemon to
                    // tear down fully and restart onto the new version (server.rs never exits the
                    // process itself). Unix re-execs the staged plan (same PID); Windows returns
                    // `RestartService` and the SCM relaunches the service. The one exception is the
                    // legacy Windows MSI fallback, which exits inside `apply` and never returns here.
                    #[cfg(unix)]
                    {
                        let exec_slot = ctx.exec_slot.clone();
                        let restart = ctx.restart_for_update.clone();
                        tokio::spawn(async move {
                            match crate::selfupdate::apply(&pu.artifact, &state_dir).await {
                                Ok(plan) => {
                                    crate::selfupdate::mark_update_pending(&state_dir, &version);
                                    *exec_slot.lock().unwrap() = Some(plan);
                                    restart.notify_one();
                                }
                                // Swap failed — leave the running engine as-is; do not signal a restart.
                                Err(e) => tracing::error!("auto-update failed: {e:#}"),
                            }
                        });
                    }
                    #[cfg(windows)]
                    {
                        let restart = ctx.restart_for_update.clone();
                        tokio::spawn(async move {
                            match crate::selfupdate::apply(&pu.artifact, &state_dir).await {
                                // File-swap bundle: binary swapped in place; signal the daemon to tear
                                // down and let the SCM restart the service onto it. (An MSI artifact
                                // exits inside `apply` and never reaches this arm.)
                                Ok(()) => {
                                    crate::selfupdate::mark_update_pending(&state_dir, &version);
                                    restart.notify_one();
                                }
                                Err(e) => tracing::error!("auto-update failed: {e:#}"),
                            }
                        });
                    }
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
            serde_json::to_vec(&ControlResponse::Status(Box::new(report.clone())))?
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

/// Resolve and validate the scope of an `Add` against the networks this device holds.
///
/// Returns a scope carrying only `(guild_id, role_id)` — names get no further than this function.
/// `OwnDevices` is derived from our own identity and `AllPeers` names nothing, so neither needs a
/// network.
///
/// A name a person typed ([`ExposeScope::Unresolved`], from `ctl expose`, a config seed, or an
/// exposure stored before id-scoping) resolves to the network carrying that role — but only when
/// exactly one does. Two guilds may each have a role of the same name, and picking either would
/// silently expose the port to a community the caller never named, so an ambiguous one is refused
/// with the candidates listed.
fn resolve_scope(scope: ExposeScope, held: &[NetworkStatus]) -> anyhow::Result<ExposeScope> {
    let listing = || held.iter().map(net_label).collect::<Vec<_>>().join(", ");
    match scope {
        ExposeScope::Net { guild_id, role_id } => {
            let known = held
                .iter()
                .any(|n| n.guild_id == guild_id && n.role_id == role_id);
            if !known {
                anyhow::bail!(
                    "not a member of network {guild_id}/{role_id} (your networks: {})",
                    listing()
                );
            }
            Ok(ExposeScope::Net { guild_id, role_id })
        }
        ExposeScope::Unresolved { guild, name } => {
            let hits: Vec<&NetworkStatus> = held
                .iter()
                .filter(|n| n.name == name && guild.as_deref().is_none_or(|g| n.guild_name == g))
                .collect();
            match hits.as_slice() {
                [] => anyhow::bail!(
                    "not a member of network '{name}' (your networks: {})",
                    listing()
                ),
                [only] => Ok(ExposeScope::Net {
                    guild_id: only.guild_id,
                    role_id: only.role_id,
                }),
                many => anyhow::bail!(
                    "network '{name}' is ambiguous — you hold it in {} communities ({}). \
                     Name one with `--guild`.",
                    many.len(),
                    many.iter()
                        .map(|n| n.guild_name.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            }
        }
        other => Ok(other),
    }
}

/// `role @ guild` for a held network — display only.
fn net_label(n: &NetworkStatus) -> String {
    if n.guild_name.is_empty() {
        n.name.clone()
    } else {
        format!("{} @ {}", n.name, n.guild_name)
    }
}

/// Apply an expose op to the local firewall and report the resulting exposed set.
fn apply_expose(
    fw: &Firewall,
    op: ExposeOp,
    held_nets: &[NetworkStatus],
) -> anyhow::Result<ExposeResp> {
    let (message, exposed) = match op {
        ExposeOp::List => ("exposed ports".to_string(), fw.list()),
        ExposeOp::Add { proto, port, scope } => {
            let scope = resolve_scope(scope, held_nets)?;
            let exposed = fw.expose(proto, port, scope.clone())?;
            // Report it the way the caller will recognize it, not as the ids we stored.
            let label = exposed
                .iter()
                .find(|e| e.proto == proto && e.port == port && e.scope == scope)
                .map_or_else(|| scope.fallback_label(), |e| e.label.clone());
            (
                format!("exposed {}/{port} ({label})", proto.as_str()),
                exposed,
            )
        }
        ExposeOp::Remove { proto, port, scope } => {
            let label = match &scope {
                common::control::RemoveScope::Exact(s) => format!(" ({})", s.fallback_label()),
                common::control::RemoveScope::All => String::new(),
            };
            (
                format!("closed {}/{port}{label}", proto.as_str()),
                fw.unexpose(proto, port, scope)?,
            )
        }
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
