//! Supervising the TLS proxy: start it when there is something to serve, stop it when there is not,
//! and never run it with privileges it should not have.
//!
//! The proxy is a separate process precisely so that parsing HTTP from mesh peers happens somewhere
//! the WireGuard keys are not. That only holds if it actually runs unprivileged, so the decision of
//! *whom* to run it as is the part that matters here — and it is a refusal, not a default: an engine
//! running as root with no proxy user configured declines to start it and says what to configure.
//! Silently running it as root would give away the whole point while looking like it worked.

use anyhow::Context as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// What the supervisor should do this reconcile.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Start it: something to serve, nothing running.
    Start,
    /// Stop it: nothing to serve, something running. A proxy holding 443 for no services is a
    /// listener with no reason to exist.
    Stop,
    /// Already in the right state.
    Leave,
}

pub fn decide(has_services: bool, running: bool) -> Action {
    match (has_services, running) {
        (true, false) => Action::Start,
        (false, true) => Action::Stop,
        _ => Action::Leave,
    }
}

/// Who the proxy should run as, or why it must not run at all.
///
/// `euid` is the engine's effective uid; `configured` is `[proxy] user`.
///
/// * A configured user is used, whoever we are.
/// * No user and we are **not** root: run as ourselves — we are already unprivileged, which is the
///   whole requirement. This is the developer's `cargo run`, and a rootless engine has no privileges
///   to hand away.
/// * No user and we **are** root: refuse. Running it as root would quietly undo the isolation the
///   separate process exists for.
pub fn run_as(configured: Option<&str>, euid: u32) -> Result<Option<String>, String> {
    match (configured, euid) {
        (Some(user), _) => Ok(Some(user.to_string())),
        (None, 0) => Err(
            "the TLS proxy would run as root, which is what running it in its own process is \
             meant to avoid. Set `[proxy] user` to an unprivileged account (the packages create \
             `unitylan-proxy`), or set `[proxy] enabled = false` to serve TLS yourself."
                .into(),
        ),
        (None, _) => Ok(None),
    }
}

/// Where the proxy binary is: beside this executable, which is how every packaged install lays the
/// two out, unless the config says otherwise.
pub fn binary(configured: Option<&Path>) -> PathBuf {
    if let Some(path) = configured {
        return path.to_path_buf();
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join(proxy_file_name())))
        .unwrap_or_else(|| PathBuf::from(proxy_file_name()))
}

fn proxy_file_name() -> &'static str {
    if cfg!(windows) {
        "unitylan-proxy.exe"
    } else {
        "unitylan-proxy"
    }
}

/// The descriptor the pre-bound listener is handed over on; the variable naming it is
/// [`common::control::PROXY_LISTEN_FD_VAR`], shared with the proxy.
///
/// **Why the engine binds it.** 443 is privileged, and an unprivileged proxy cannot take it: a child
/// that drops to another uid loses its capabilities, and `NoNewPrivileges` in the systemd unit means
/// file capabilities on the binary would not help either. Handing over an already-bound socket is
/// the standard way out and the better one — the proxy then runs with *no* capability at all, rather
/// than one it has to be trusted with.
const LISTEN_FD: i32 = 3;

/// A running proxy, killed when this is dropped.
///
/// Dropping is the shutdown path: the engine going away must take the proxy with it rather than
/// leaving a process holding 443 and serving whatever it last heard.
pub struct Proxy {
    child: tokio::process::Child,
    /// The address whose listener we handed over. The proxy cannot rebind — it was given a socket,
    /// not the right to make one — so a device that changes mesh address needs a restart, and this
    /// is what notices.
    pub bound_to: std::net::SocketAddr,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl Proxy {
    /// Whether it is still up. A proxy that exited (a crash, a port it could not bind) reports
    /// `false` so the next reconcile starts it again.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

/// Start the proxy on an already-bound listener for `bind`, pointed at the control socket it reads
/// its configuration from.
///
/// Errors are returned rather than logged here so the caller can report them once and not on every
/// reconcile: a missing binary or an unusable user does not get better by retrying in two seconds.
pub fn spawn(
    binary: &Path,
    socket: &Path,
    bind: std::net::SocketAddr,
    run_as: Option<&str>,
) -> anyhow::Result<Proxy> {
    // Bound here, while we still have the capability to take a privileged port, and handed over.
    let listener = std::net::TcpListener::bind(bind)
        .with_context(|| format!("binding {bind} for the TLS proxy"))?;

    let mut cmd = tokio::process::Command::new(binary);
    cmd.arg(socket)
        .env(common::control::PROXY_LISTEN_FD_VAR, LISTEN_FD.to_string())
        .stdin(Stdio::null())
        // Inherit stdout/stderr so the proxy's log lands wherever the engine's does — one place to
        // look, which for a service failing to serve is the difference between a diagnosis and a
        // mystery.
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        if let Some(user) = run_as {
            let (uid, gid) = unix_ids(user)?;
            cmd.uid(uid).gid(gid);
        }
        // Rust marks every socket it opens close-on-exec, so the child would otherwise inherit
        // nothing. `dup2` both duplicates it onto the agreed descriptor and clears that flag.
        let raw = std::os::fd::AsRawFd::as_raw_fd(&listener);
        // SAFETY: runs in the forked child between `fork` and `exec`, where only async-signal-safe
        // calls are allowed — `dup2` is one. `raw` is the listener's descriptor, still open in the
        // child because nothing has closed it, and `LISTEN_FD` is not otherwise in use (stdio has
        // 0..=2, and stdin is replaced above).
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(raw, LISTEN_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    if run_as.is_some() {
        anyhow::bail!(
            "[proxy] user is unix-only; on Windows the proxy runs as its own service account"
        );
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("starting {}", binary.display()))?;
    // Ours is closed on return; the child holds the only copy from here.
    drop(listener);
    Ok(Proxy {
        child,
        bound_to: bind,
    })
}

/// Resolve a user name to its uid and primary gid.
#[cfg(unix)]
fn unix_ids(user: &str) -> anyhow::Result<(u32, u32)> {
    let name = std::ffi::CString::new(user)?;
    // SAFETY: `getpwnam` takes a NUL-terminated string, which `CString` guarantees, and returns a
    // pointer into a static buffer that stays valid until the next call in this thread. The fields
    // are copied out immediately, before anything else can call it.
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        anyhow::bail!("no such user {user:?} for the TLS proxy to run as");
    }
    // SAFETY: checked non-null directly above, and not dereferenced after any further libc call.
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    Ok((uid, gid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_runs_only_while_there_is_something_to_serve() {
        assert_eq!(decide(true, false), Action::Start);
        assert_eq!(decide(false, true), Action::Stop);
        assert_eq!(decide(true, true), Action::Leave);
        assert_eq!(decide(false, false), Action::Leave);
    }

    /// The isolation is the feature. An engine that is root and has not been told who to run the
    /// proxy as must refuse rather than run it as root — that would look like it worked while
    /// giving away exactly what the separate process was for.
    #[test]
    fn a_root_engine_refuses_to_start_an_unconfigured_proxy() {
        let err = run_as(None, 0).expect_err("root with no user must refuse");
        assert!(
            err.contains("[proxy] user"),
            "the message names the fix: {err}"
        );
        assert!(err.contains("enabled = false"), "and the way out: {err}");

        assert_eq!(
            run_as(Some("unitylan-proxy"), 0).unwrap().as_deref(),
            Some("unitylan-proxy")
        );
        // A rootless engine has no privileges to drop, so running as itself is already the goal.
        assert_eq!(run_as(None, 1000).unwrap(), None);
    }

    #[test]
    fn the_binary_sits_beside_the_engine_unless_told_otherwise() {
        let explicit = PathBuf::from("/opt/unitylan/proxy");
        assert_eq!(binary(Some(&explicit)), explicit);
        let found = binary(None);
        assert_eq!(
            found.file_name().and_then(|n| n.to_str()),
            Some(proxy_file_name())
        );
    }
}
