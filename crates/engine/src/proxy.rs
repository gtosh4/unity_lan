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
/// Only the unix path spawns a child; Windows asks the SCM to start a service it does not own.
#[cfg(unix)]
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
/// than one it has to be trusted with. Windows has no privileged port to hand over, so there is
/// nothing to name there.
#[cfg(unix)]
const LISTEN_FD: i32 = 3;

/// A running proxy, stopped when this is dropped.
///
/// Dropping is the shutdown path: the engine going away must take the proxy with it rather than
/// leaving a process holding 443 and serving whatever it last heard.
///
/// Two shapes, because the platforms differ in who can start a process as another user. On unix the
/// engine forks a child and drops it to `[proxy] user`; on Windows LocalSystem cannot spawn as a
/// different account without a logon token it has no way to get, so the proxy is a **second SCM
/// service** running as `NT AUTHORITY\LocalService` and the engine starts and stops it. Either way
/// the engine is the supervisor and the proxy is unprivileged — only the mechanism changes.
pub struct Proxy {
    #[cfg(unix)]
    child: tokio::process::Child,
    /// The address the proxy serves on. On unix this is the listener we bound and handed over — it
    /// cannot rebind, having been given a socket rather than the right to make one — so a device
    /// that changes mesh address needs a restart, and this is what notices.
    pub bound_to: std::net::SocketAddr,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = self.child.start_kill();
        #[cfg(windows)]
        // Best-effort: the engine is usually going down itself here, and a stop that does not land
        // leaves a proxy the SCM will stop with the machine anyway.
        let _ = windows_service_control(false);
    }
}

impl Proxy {
    /// Whether it is still up. A proxy that exited (a crash, a port it could not bind) reports
    /// `false` so the next reconcile starts it again.
    #[cfg(unix)]
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Windows: ask the SCM, which is the only thing that knows.
    #[cfg(windows)]
    pub fn alive(&mut self) -> bool {
        windows_service_running().unwrap_or(false)
    }
}

/// Start the proxy on an already-bound listener for `bind`, pointed at the control socket it reads
/// its configuration from.
///
/// Errors are returned rather than logged here so the caller can report them once and not on every
/// reconcile: a missing binary or an unusable user does not get better by retrying in two seconds.
#[cfg(windows)]
pub fn spawn(
    _binary: &Path,
    _socket: &Path,
    bind: std::net::SocketAddr,
    run_as: Option<&str>,
) -> anyhow::Result<Proxy> {
    if run_as.is_some() {
        // Said rather than ignored: the account is fixed at registration (LocalService), so a
        // `[proxy] user` here would look like it took effect and never have.
        anyhow::bail!(
            "`[proxy] user` has no effect on Windows — the proxy runs as NT AUTHORITY\\LocalService, \
             set when its service was registered. Remove the setting."
        );
    }
    // Nothing to bind or hand over: Windows has no privileged-port concept, so the service binds
    // 443 itself as LocalService. Its command line (including the control pipe to read) was fixed
    // when the installer registered it.
    windows_service_control(true)?;
    Ok(Proxy { bound_to: bind })
}

/// Stop the proxy service, ignoring every failure — used where the caller only needs the binary to
/// stop being in use (an update overwriting it) and a proxy that is already stopped, or not
/// registered at all, is the desired state either way.
#[cfg(windows)]
pub fn stop_windows_service() {
    let _ = windows_service_control(false);
}

/// Start (`true`) or stop (`false`) the proxy service.
#[cfg(windows)]
fn windows_service_control(start: bool) -> anyhow::Result<()> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager")?;
    let service = manager
        .open_service(
            common::control::WINDOWS_PROXY_SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
        )
        .with_context(|| {
            format!(
                "opening the {} service (reinstall to register it)",
                common::control::WINDOWS_PROXY_SERVICE_NAME
            )
        })?;
    let state = service.query_status().context("querying it")?.current_state;
    match (start, state) {
        (true, ServiceState::Running) | (false, ServiceState::Stopped) => Ok(()),
        (true, _) => service
            .start::<std::ffi::OsString>(&[])
            .context("starting it"),
        (false, _) => service.stop().map(|_| ()).context("stopping it"),
    }
}

#[cfg(windows)]
fn windows_service_running() -> anyhow::Result<bool> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        common::control::WINDOWS_PROXY_SERVICE_NAME,
        ServiceAccess::QUERY_STATUS,
    )?;
    Ok(service.query_status()?.current_state == ServiceState::Running)
}

#[cfg(unix)]
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
    // Nothing of the root engine's environment crosses into the less-trusted process. Whatever the
    // administrator, the service manager or a packaging script left in there was addressed to a
    // privileged daemon, and the HTTP parser is the one process on this device assumed to be
    // compromised — so it is handed exactly what it reads and nothing else.
    cmd.env_clear()
        .arg(socket)
        .env(common::control::PROXY_LISTEN_FD_VAR, LISTEN_FD.to_string())
        .stdin(Stdio::null())
        // Inherit stdout/stderr so the proxy's log lands wherever the engine's does — one place to
        // look, which for a service failing to serve is the difference between a diagnosis and a
        // mystery.
        .kill_on_drop(true);
    // The one variable worth carrying across: the proxy filters its log on `RUST_LOG` like every
    // other binary here, and clearing the environment would otherwise make it the only process whose
    // logs cannot be turned up. Passed only when non-empty — an empty filter is not "the default",
    // it is one that matches nothing, so forwarding `RUST_LOG=""` would silence the proxy entirely.
    if let Some(filter) = std::env::var("RUST_LOG").ok().filter(|v| !v.is_empty()) {
        cmd.env("RUST_LOG", filter);
    }
    {
        // Resolved *before* the fork: `getpwnam`/`getgrouplist` allocate and lock, neither of which
        // is allowed between fork and exec. The child only makes syscalls with what we hand it.
        let ids = run_as.map(Ids::lookup).transpose()?;
        // Rust marks every socket it opens close-on-exec, so the child would otherwise inherit
        // nothing. `dup2` both duplicates it onto the agreed descriptor and clears that flag.
        let raw = std::os::fd::AsRawFd::as_raw_fd(&listener);
        // SAFETY: runs in the forked child between `fork` and `exec`, where only async-signal-safe
        // calls are allowed — `setgroups`, `setgid`, `setuid` and `dup2` are. `ids` was resolved
        // before the fork and is only read here. `raw` is the listener's descriptor, still open in
        // the child because nothing has closed it, and `LISTEN_FD` is not otherwise in use (stdio
        // has 0..=2, and stdin is replaced above).
        unsafe {
            cmd.pre_exec(move || {
                if let Some(ids) = &ids {
                    ids.drop_privileges()?;
                }
                if libc::dup2(raw, LISTEN_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
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

/// The credentials the proxy runs under: uid, primary gid, and the **full** group list its account
/// is a member of.
///
/// The group list is the point. `Command::uid`/`gid` alone would be simpler, but std then calls
/// `setgroups(0, NULL)` before `setuid` — the child keeps *no* supplementary groups, so an account
/// that was added to a group in order to reach something (the packaged `unitylan-proxy` account and
/// the certificate key's group) silently cannot. Nothing in std calls `initgroups`, so the drop is
/// done here instead, in the order the kernel requires: groups and gid while still root, uid last.
#[cfg(unix)]
struct Ids {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

#[cfg(unix)]
impl Ids {
    /// Resolve a user name to its uid, primary gid and group list. Called before the fork.
    fn lookup(user: &str) -> anyhow::Result<Self> {
        let name = std::ffi::CString::new(user)?;
        // SAFETY: `getpwnam` takes a NUL-terminated string, which `CString` guarantees, and returns
        // a pointer into a static buffer that stays valid until the next call in this thread. The
        // fields are copied out immediately, before anything else can call it.
        let pw = unsafe { libc::getpwnam(name.as_ptr()) };
        if pw.is_null() {
            anyhow::bail!("no such user {user:?} for the TLS proxy to run as");
        }
        // SAFETY: checked non-null directly above, and not dereferenced after any further libc call.
        let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };

        // `getgrouplist` reports how many groups there are when the buffer is too small, so ask
        // twice rather than guessing a ceiling. A failure is not fatal: the primary group alone is
        // still a correct, tighter-than-intended drop.
        let mut count: libc::c_int = 16;
        let mut groups: Vec<libc::gid_t> = vec![0; count as usize];
        // SAFETY: `name` is NUL-terminated and `groups` has `count` elements; `getgrouplist` writes
        // at most that many and updates `count` with what it needed.
        let rc = unsafe { libc::getgrouplist(name.as_ptr(), gid, groups.as_mut_ptr(), &mut count) };
        if rc == -1 && count > 0 {
            groups = vec![0; count as usize];
            // SAFETY: as above, with the buffer `getgrouplist` just asked for.
            let rc =
                unsafe { libc::getgrouplist(name.as_ptr(), gid, groups.as_mut_ptr(), &mut count) };
            if rc == -1 {
                count = 1;
                groups = vec![gid];
            }
        }
        groups.truncate(count.max(0) as usize);
        if groups.is_empty() {
            groups.push(gid);
        }
        Ok(Self { uid, gid, groups })
    }

    /// Become that user. Runs in the forked child, so it may only make async-signal-safe calls.
    ///
    /// Order matters and is not interchangeable: `setgroups` and `setgid` need the privilege that
    /// `setuid` gives up, so a mistake here either fails outright or — worse — leaves the child
    /// holding root's groups.
    ///
    /// # Safety
    ///
    /// Must be called between `fork` and `exec` in a child that is still privileged.
    unsafe fn drop_privileges(&self) -> std::io::Result<()> {
        // SAFETY: the caller guarantees the fork/exec window; each call is async-signal-safe and
        // reads only `self`, which was populated before the fork.
        unsafe {
            if libc::setgroups(self.groups.len() as _, self.groups.as_ptr()) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(self.gid) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(self.uid) == -1 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// The proxy account's primary group, which the read-only control endpoint is handed to. `None` when
/// no `[proxy] user` is configured — the engine is then unprivileged and the proxy runs as itself.
#[cfg(unix)]
pub fn primary_gid(user: Option<&str>) -> Option<u32> {
    Ids::lookup(user?).ok().map(|ids| ids.gid)
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

    /// The whole point of resolving ids ourselves: the child must keep the groups its account is a
    /// member of. `Command::uid`/`gid` alone would clear them, and the packaged proxy reaches the
    /// certificate key through exactly such a membership.
    #[cfg(unix)]
    #[test]
    fn the_resolved_ids_carry_the_accounts_group_list() {
        let root = Ids::lookup("root").expect("root exists on every unix");
        assert_eq!(root.uid, 0);
        assert!(
            root.groups.contains(&root.gid),
            "the primary group is always in the list, got {:?}",
            root.groups
        );
        assert!(
            !root.groups.is_empty(),
            "an empty list would clear them all"
        );
        assert_eq!(primary_gid(Some("root")), Some(root.gid));
        assert_eq!(primary_gid(None), None);
        // A typo'd `[proxy] user` must fail loudly here rather than at exec time in the child, where
        // the only symptom is a proxy that exits with a status nobody reads.
        assert!(Ids::lookup("no-such-unitylan-user").is_err());
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
