//! Windows Service wrapper for the engine daemon — the packaging that lets a non-technical user
//! run UnityLAN without a terminal. The engine runs as a `LocalSystem` service so it starts at boot
//! with the privilege the daemon needs (WireGuard, the host firewall, NRPT); the unprivileged GUI
//! drives it over the named-pipe control channel.
//!
//! Subcommands (all under `unitylan-engine service …`):
//! - `install [config.toml]` — register an auto-start service (needs an elevated shell).
//! - `start` — start the (already-registered) service now; used by the MSI after a major upgrade so
//!   an auto-update relaunches the engine without waiting for a reboot. Idempotent.
//! - `stop` — stop the running service but leave it registered; the MSI runs this while removing the
//!   old build during a major upgrade, so the exe unlocks for replacement and `install` adopts +
//!   repoints the same registration in place — no delete, hence no marked-for-delete husk. Idempotent.
//! - `uninstall` — stop and remove it (needs an elevated shell).
//! - `run [config.toml]` — the SCM-invoked entry point; not for interactive use. The config path is
//!   baked into the service's command line at install time, so users never pass it themselves.
//!
//! Runtime prerequisite (as for any Windows engine run): the wireguard-nt DLL sits at
//! `resources-windows\binaries\wireguard-amd64.dll` under the engine's install dir (defguard loads
//! it by that relative path; `run` pins the service's working dir to the exe folder so it resolves).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use windows_service::service::{
    Service, ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::Config;
use crate::daemon;
use crate::shutdown;

/// SCM service key (internal name). Referenced by `sc.exe` / `Start-Service`. Shared with the GUI
/// via `common` so both address the same service.
const SERVICE_NAME: &str = common::control::WINDOWS_SERVICE_NAME;
/// Friendly name shown in `services.msc`.
const DISPLAY_NAME: &str = "UnityLAN Engine";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const SERVICE_DESCRIPTION: &str =
    "UnityLAN mesh engine: WireGuard mesh, host firewall, and .unity.internal DNS resolver.";

/// `CreateService` failed because a service of this name is already registered.
const ERROR_SERVICE_EXISTS: i32 = 1073;
/// `CreateService` failed because the name is still reserved by a service that has been deleted but
/// whose last SCM handle hasn't closed yet. Transient — it clears on its own.
const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;
/// `OpenService` failed because no service of this name is registered. Treated as a no-op by [`stop`]
/// (nothing to stop) rather than an error.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// How long to wait for a service to reach `Stopped`, and for a marked-for-delete name to free up.
/// Matches the stop wait hint `run_service` reports to the SCM, since a clean stop tears down the
/// interface, firewall, and NRPT resolver first.
const STOP_WAIT: Duration = Duration::from_secs(30);
const MARKED_FOR_DELETE_WAIT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(300);

/// The raw Win32 code behind a `windows_service` error, when it came from a winapi call.
///
/// Extracted rather than matched on a message so the caller can branch on the specific SCM states
/// that are recoverable ([`ERROR_SERVICE_EXISTS`], [`ERROR_SERVICE_MARKED_FOR_DELETE`]) instead of
/// treating every failure alike.
fn winapi_code(err: &windows_service::Error) -> Option<i32> {
    match err {
        windows_service::Error::Winapi(io) => io.raw_os_error(),
        _ => None,
    }
}

/// Dispatch the `service` subcommand (called from `main` outside any tokio runtime).
pub fn main() -> Result<()> {
    match std::env::args().nth(2).unwrap_or_default().as_str() {
        "install" => install(std::env::args().nth(3)),
        "start" => start(),
        "stop" => stop(),
        "uninstall" => uninstall(),
        "run" => run_dispatch(),
        other => anyhow::bail!(
            "unknown `service` subcommand '{other}' (use: install [config.toml], start, stop, uninstall, run)"
        ),
    }
}

/// Config written to the default path by [`install`] when none exists there — byte-for-byte the
/// shipped Windows `engine.toml` (the same file the MSI installs), so a service bootstrapped this way
/// is identical to a fresh install: hosted coordinator, `%ProgramData%\UnityLAN` state dir,
/// enrollment interactive via the GUI. Embedding the file keeps the two defaults from drifting.
const DEFAULT_SERVICE_CONFIG: &str = include_str!("../../../packaging/windows/engine.toml");

/// Register an auto-start service whose command line carries the (absolute) config path.
fn install(config: Option<String>) -> Result<()> {
    let exe = std::env::current_exe().context("locating the engine executable")?;

    // The service runs with CWD = System32, so the config path baked into its command line must be
    // absolute. An *explicitly* passed path is never second-guessed — a missing one is a typo, so it
    // still errors. For the default path (no arg — how the MSI invokes us) we bootstrap the config in
    // `%ProgramData%\UnityLAN`: migrate a legacy beside-the-exe config, else write the shipped default
    // (see `ensure_config`). The MSI no longer ships `engine.toml` at all, so this is the sole place a
    // fresh install's config is created.
    let config = match config {
        Some(path) => std::fs::canonicalize(&path).with_context(|| {
            format!("config '{path}' not found — create it before installing the service")
        })?,
        None => {
            let path = default_config_path();
            ensure_config(&path)?;
            std::fs::canonicalize(&path)
                .with_context(|| format!("resolving the default config path {}", path.display()))?
        }
    };

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening the service manager (run this from an elevated/Administrator shell)")?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("run"),
            config.clone().into_os_string(),
        ],
        dependencies: vec![],
        account_name: None, // None ⇒ LocalSystem
        account_password: None,
    };
    create_or_adopt(&manager, &info)?;

    // The service keeps the SCM default DACL (control needs elevation). The GUI never drives the
    // SCM — its only on/off is a mesh connect/disconnect over the control socket — so no DACL relax
    // is needed.
    println!("Installed service '{SERVICE_NAME}' (auto-start at boot).");
    println!("  config: {}", config.display());
    println!("  start now:  sc.exe start {SERVICE_NAME}    (or reboot)");
    println!(
        "  ensure the wireguard-nt DLL is at resources-windows\\binaries\\wireguard-amd64.dll next to the engine executable."
    );
    Ok(())
}

/// Register the service, tolerating the two SCM states an upgrade legitimately produces.
///
/// `CreateService` is not idempotent, and the MSI's upgrade path deletes the old service and
/// recreates it under the same name inside one transaction — so both of these are normal here, not
/// errors:
///
/// - **`ERROR_SERVICE_EXISTS`** — a previous registration survived (its uninstall failed, or the
///   user re-ran `service install`). Adopt it and rewrite its config to point at the
///   newly-installed exe, which is what a fresh create would have produced anyway. It's stopped
///   first, because a service left *running* would otherwise keep executing the previous binary —
///   the config change only takes effect on next start, and the MSI's `service start` skips a
///   service that is already running.
/// - **`ERROR_SERVICE_MARKED_FOR_DELETE`** — the old service was deleted moments ago but a
///   still-open SCM handle keeps the name reserved. This clears by itself, so wait for it.
///
/// Both used to abort with a non-zero exit, and the MSI runs this action with `Return="check"` — so
/// a transient SCM state rolled the whole installer back (error 1722 → 1603) and left the machine
/// with a registered-but-broken product that then blocked every later install. Never fail an
/// install for a condition that resolves itself.
fn create_or_adopt(manager: &ServiceManager, info: &ServiceInfo) -> Result<()> {
    let deadline = Instant::now() + MARKED_FOR_DELETE_WAIT;
    loop {
        match manager.create_service(info, ServiceAccess::CHANGE_CONFIG) {
            Ok(service) => {
                let _ = service.set_description(SERVICE_DESCRIPTION);
                return Ok(());
            }
            Err(e) if winapi_code(&e) == Some(ERROR_SERVICE_EXISTS) => {
                let service = manager
                    .open_service(
                        SERVICE_NAME,
                        ServiceAccess::QUERY_STATUS
                            | ServiceAccess::STOP
                            | ServiceAccess::CHANGE_CONFIG,
                    )
                    .context("opening the already-registered service to reconfigure it")?;
                stop_and_wait(&service)?;
                service
                    .change_config(info)
                    .context("repointing the existing service at this installation")?;
                let _ = service.set_description(SERVICE_DESCRIPTION);
                println!("Service '{SERVICE_NAME}' already existed; repointed it at this install.");
                return Ok(());
            }
            // Transient: the name frees up once the last handle to the deleted service closes.
            Err(e)
                if winapi_code(&e) == Some(ERROR_SERVICE_MARKED_FOR_DELETE)
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                let msg = match winapi_code(&e) {
                    // Only reachable once the deadline above has passed, so say what actually
                    // helps: something is still holding a handle to the deleted service.
                    Some(ERROR_SERVICE_MARKED_FOR_DELETE) => format!(
                        "service '{SERVICE_NAME}' was still marked for deletion after {}s — \
                         close services.msc or any tool holding it open, then retry (a reboot \
                         always clears it)",
                        MARKED_FOR_DELETE_WAIT.as_secs()
                    ),
                    _ => format!("creating service '{SERVICE_NAME}' (needs an elevated shell)"),
                };
                return Err(anyhow::Error::new(e).context(msg));
            }
        }
    }
}

/// Ask the service to stop and wait for it to actually reach `Stopped`, bounded by [`STOP_WAIT`].
///
/// Shared by `uninstall` (so `delete` doesn't hit a running service — that only marks it for
/// deletion until the next reboot) and by [`create_or_adopt`] (so an adopted service isn't left
/// running the previous binary). Best-effort: a service that won't stop in the window is left to
/// the caller rather than failing the install.
fn stop_and_wait(service: &Service) -> Result<()> {
    if service.query_status()?.current_state == ServiceState::Stopped {
        return Ok(());
    }
    let _ = service.stop();
    let deadline = Instant::now() + STOP_WAIT;
    while Instant::now() < deadline {
        if service.query_status()?.current_state == ServiceState::Stopped {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Ok(())
}

/// Stop (best-effort) and delete the service. Stopping triggers the SCM Stop control, which latches
/// the daemon's shutdown signal (see `run_service`) so it reverts the interface, firewall, and NRPT
/// resolver on the way out — this leaves the host clean without deleting local state. To also wipe
/// device identity from `%ProgramData%\UnityLAN`, run `unitylan-engine uninstall --purge`.
fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager (run this from an elevated/Administrator shell)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("opening the service (is it installed?)")?;

    // Stop before deleting: deleting a still-running service only marks it for deletion until the
    // next reboot, which then blocks a reinstall's `service install` with
    // ERROR_SERVICE_MARKED_FOR_DELETE.
    stop_and_wait(&service)?;

    service.delete().context("deleting the service")?;
    println!("Uninstalled service '{SERVICE_NAME}'.");
    Ok(())
}

/// Start the service now. `install` only *registers* an auto-start service (which the SCM would
/// otherwise launch at the next boot), so the MSI runs this after a major upgrade to relaunch the
/// engine immediately — otherwise an auto-update would leave the engine down until reboot. Idempotent
/// and best-effort: a service that is already running (or is mid-start) is a success, not an error.
fn start() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager (run this from an elevated/Administrator shell)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        )
        .context("opening the service (is it installed?)")?;

    match service.query_status()?.current_state {
        ServiceState::Stopped => {
            service
                .start::<OsString>(&[])
                .context("starting the service")?;
            println!("Started service '{SERVICE_NAME}'.");
        }
        other => println!("Service '{SERVICE_NAME}' is already {other:?}; nothing to do."),
    }
    Ok(())
}

/// Stop the service but leave it registered — the upgrade counterpart to [`uninstall`]'s stop+delete.
///
/// The MSI runs this while removing the *old* build during a major upgrade: stopping frees the
/// running exe so `RemoveFiles` can replace it, while keeping the registration means the incoming
/// build's `install` finds it via [`create_or_adopt`]'s `ERROR_SERVICE_EXISTS` path and reconfigures
/// it in place. Deleting instead (the pre-adopt design) risked a marked-for-delete husk that wedged
/// the reinstall, and a failed upgrade left no service at all. Idempotent and best-effort: no such
/// service (never installed, or already gone) and an already-stopped one are both success, so a stray
/// stop never fails an install.
fn stop() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager (run this from an elevated/Administrator shell)")?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
    ) {
        Ok(service) => service,
        Err(e) if winapi_code(&e) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
            println!("Service '{SERVICE_NAME}' is not installed; nothing to stop.");
            return Ok(());
        }
        Err(e) => return Err(anyhow::Error::new(e).context("opening the service to stop it")),
    };
    stop_and_wait(&service)?;
    println!("Stopped service '{SERVICE_NAME}' (left registered).");
    Ok(())
}

/// Hand the thread to the SCM dispatcher; it calls `ffi_service_main` and blocks until we stop.
fn run_dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).context(
        "starting the service dispatcher (this subcommand is launched by Windows, not run directly)",
    )?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

/// SCM entry point (runs on an SCM-owned thread). Errors are logged to the service log file since
/// there is no console attached.
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service exited with error: {e:#}");
    }
}

fn run_service() -> Result<()> {
    // The config path was baked into the command line at install time (`service run <config>`).
    let cfg_path = std::env::args()
        .nth(3)
        .unwrap_or_else(|| default_config_path().to_string_lossy().into_owned());

    init_service_logging();
    tracing::info!(config = %cfg_path, "unitylan service starting");

    // The SCM launches services with CWD = System32, but defguard loads wireguard-nt by the
    // *relative* path `resources-windows/binaries/wireguard-amd64.dll` (resolved against CWD). Pin
    // CWD to the install dir (the exe's folder) so that DLL — shipped there by the installer —
    // resolves. The config path was made absolute at install time, so this is safe.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            std::env::set_current_dir(dir)
                .with_context(|| format!("pinning working dir to {}", dir.display()))?;
        }
    }

    // Bootstrap/migrate the config before loading it, so a service whose config went missing (an
    // upgrade off a build that didn't keep it, or a hand-deleted file) still starts on a sane default
    // rather than failing — and a legacy beside-the-exe config is imported to the new ProgramData home.
    ensure_config(Path::new(&cfg_path))
        .with_context(|| format!("ensuring config at {cfg_path}"))?;
    let cfg =
        Config::load(Path::new(&cfg_path)).with_context(|| format!("loading config {cfg_path}"))?;

    let (trigger, shutdown) = shutdown::channel();

    // The status handle, shared into the control handler so a Stop can report STOP_PENDING before
    // the daemon runs its teardown. Populated right after `register` returns (below) — well before
    // any control can arrive, since we announce Running only afterwards.
    let status_slot: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
    let handler_slot = Arc::clone(&status_slot);

    // Translate the SCM Stop/Shutdown controls into our latched shutdown signal.
    let event_handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // Teardown on shutdown (remove the WG adapter, reset the firewall, revert the NRPT
            // resolver) takes seconds. Report STOP_PENDING with a wait hint so the SCM / services.msc
            // / the MSI's `service uninstall` wait for it instead of treating the still-Running
            // service as hung (and, in the uninstall case, deleting it mid-stop → marked-for-delete,
            // which would then fail the reinstall's `service install`).
            if let Some(h) = handler_slot.get() {
                let _ = h.set_service_status(ServiceStatus {
                    service_type: SERVICE_TYPE,
                    current_state: ServiceState::StopPending,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::Win32(0),
                    checkpoint: 0,
                    wait_hint: Duration::from_secs(30),
                    process_id: None,
                });
            }
            trigger.trigger();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("registering the service control handler")?;
    let _ = status_slot.set(status_handle);

    let set_state = |state: ServiceState, accepted: ServiceControlAccept| -> Result<()> {
        status_handle
            .set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: state,
                controls_accepted: accepted,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .context("reporting service status to the SCM")
    };

    // Announce Running (accepting Stop) before the daemon takes over the thread's runtime.
    set_state(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    )?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let result = rt.block_on(daemon::run(cfg, shutdown));

    // Report Stopped regardless of how the daemon exited (the SCM needs a terminal state).
    let stopped = set_state(ServiceState::Stopped, ServiceControlAccept::empty());
    // Then bound cleanup: reqwest's default DNS resolver runs `getaddrinfo` on tokio's *blocking*
    // pool, which can't be cancelled — so a lookup in flight at shutdown would otherwise make the
    // runtime's `Drop` block the service process past its Stopped report for the OS resolver timeout.
    // Abandon such stragglers after a short grace.
    rt.shutdown_timeout(Duration::from_secs(2));
    stopped?;
    // The service never re-execs (Windows updates via msiexec + exit), so any clean outcome is a stop.
    result.map(|_| ())
}

/// The engine service has no console, so append logs to a file next to the executable.
fn init_service_logging() {
    let log_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("unitylan-engine-service.log")))
        .unwrap_or_else(|| PathBuf::from("unitylan-engine-service.log"));
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    // Silence boringtun's HANDSHAKE(REKEY_TIMEOUT) WARN spam for down peers (see main.rs).
                    .unwrap_or_else(|_| "info,defguard_boringtun::noise::timers=error".into()),
            )
            .with_writer(move || file.try_clone().expect("clone service log fd"))
            .try_init();
    }
}

/// `%ProgramData%` (e.g. `C:\ProgramData`), with a literal fallback for the impossible case of the
/// env var being unset — it is always present for a LocalSystem service.
fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

/// Where the engine keeps its config: `%ProgramData%\UnityLAN\engine.toml`, alongside its state and
/// **owned by the engine, not the installer**. Living outside the MSI's file list is deliberate — a
/// major upgrade (or uninstall) never touches it, so the whole class of bug where RemoveExistingProducts
/// deleted `engine.toml` out from under `service install` cannot recur once a build stores it here.
fn default_config_path() -> PathBuf {
    program_data_dir().join("UnityLAN").join("engine.toml")
}

/// The pre-ProgramData location: `engine.toml` beside the executable, where the MSI used to install
/// it. Kept only so [`ensure_config`] can migrate a config an older build left there.
fn legacy_config_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("engine.toml")))
}

/// Guarantee a config exists at `path`, creating it if missing — the engine, not the installer, owns
/// `engine.toml` now, so both `install` and the service's own startup bootstrap it. When it's absent:
///  1. migrate a legacy beside-the-exe config verbatim, so a user's coordinator/enrollment survives
///     the move to ProgramData (this is the general "run an upgrade step in the new binary" hook —
///     add future migrations here);
///  2. otherwise write the shipped [`DEFAULT_SERVICE_CONFIG`].
///
/// Idempotent: an existing `path` is left untouched. Creates the parent directory as needed.
fn ensure_config(path: &Path) -> Result<()> {
    ensure_config_from(path, legacy_config_path().as_deref())
}

/// Testable core of [`ensure_config`] with the legacy source injected.
fn ensure_config_from(path: &Path, legacy: Option<&Path>) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating config directory {}", parent.display()))?;
    }
    if let Some(legacy) = legacy {
        if legacy != path && legacy.is_file() {
            std::fs::copy(legacy, path).with_context(|| {
                format!(
                    "migrating config {} -> {}",
                    legacy.display(),
                    path.display()
                )
            })?;
            println!(
                "Migrated config from {} to {}.",
                legacy.display(),
                path.display()
            );
            return Ok(());
        }
    }
    std::fs::write(path, DEFAULT_SERVICE_CONFIG)
        .with_context(|| format!("writing the default config to {}", path.display()))?;
    println!(
        "No config at {} — wrote the shipped default (edit coordinator/enrollment_key if self-hosting).",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    /// `install` writes [`DEFAULT_SERVICE_CONFIG`] verbatim when a config is missing (an upgrade's
    /// teardown, or a first run), and the service then loads that file at startup — so if the
    /// embedded default ever stopped parsing or failed coordinator validation, a bootstrapped
    /// service would be registered but unable to start. Pin that it round-trips through the real
    /// loader.
    #[test]
    fn ensure_config_writes_default_when_nothing_exists() {
        let dir = TempDir::new("svc-ensure-default");
        // A nested target whose parent does not exist yet — ensure_config must create it.
        let target = dir.join("UnityLAN").join("engine.toml");
        ensure_config_from(&target, None).unwrap();
        assert!(target.is_file());
        Config::load(&target).expect("the written default must load + validate");
    }

    #[test]
    fn ensure_config_migrates_a_legacy_config() {
        let dir = TempDir::new("svc-ensure-migrate");
        let legacy = dir.join("legacy-engine.toml");
        // A distinctive coordinator so we can tell a migration from a default-write.
        std::fs::write(&legacy, "coordinator = \"https://mine.example.com\"\n").unwrap();
        let target = dir.join("pd").join("engine.toml");
        ensure_config_from(&target, Some(&legacy)).unwrap();
        let got = std::fs::read_to_string(&target).unwrap();
        assert!(
            got.contains("mine.example.com"),
            "expected the legacy config migrated verbatim, got: {got}"
        );
    }

    #[test]
    fn ensure_config_leaves_an_existing_config_untouched() {
        let dir = TempDir::new("svc-ensure-idem");
        let target = dir.join("engine.toml");
        std::fs::write(&target, "coordinator = \"https://kept.example.com\"\n").unwrap();
        let legacy = dir.join("legacy.toml");
        std::fs::write(&legacy, "coordinator = \"https://other.example.com\"\n").unwrap();
        ensure_config_from(&target, Some(&legacy)).unwrap();
        let got = std::fs::read_to_string(&target).unwrap();
        assert!(
            got.contains("kept.example.com") && !got.contains("other.example.com"),
            "an existing config must not be overwritten by migration/default, got: {got}"
        );
    }

    #[test]
    fn default_service_config_loads_and_validates() {
        let dir = TempDir::new("svc-default-cfg");
        let path = dir.join("engine.toml");
        std::fs::write(&path, DEFAULT_SERVICE_CONFIG).unwrap();
        Config::load(&path).expect("embedded default config must load + validate");
    }

    /// `create_or_adopt` branches entirely on this classification: misread the code and a
    /// recoverable SCM state becomes a failed custom action, which the MSI (`Return="check"`) turns
    /// into a rolled-back install. Pin that the code survives the `windows_service::Error` wrapper.
    #[test]
    fn winapi_code_extracts_recoverable_scm_states() {
        let exists =
            windows_service::Error::Winapi(std::io::Error::from_raw_os_error(ERROR_SERVICE_EXISTS));
        assert_eq!(winapi_code(&exists), Some(ERROR_SERVICE_EXISTS));

        let marked = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(
            ERROR_SERVICE_MARKED_FOR_DELETE,
        ));
        assert_eq!(winapi_code(&marked), Some(ERROR_SERVICE_MARKED_FOR_DELETE));

        // An unrelated winapi failure classifies as itself, so it falls through to the error arm
        // rather than being silently retried or adopted.
        let denied = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(5));
        assert_eq!(winapi_code(&denied), Some(5));

        // A non-winapi variant has no code — must not be mistaken for a recoverable state.
        assert_eq!(
            winapi_code(&windows_service::Error::LaunchArgumentsNotSupported),
            None
        );
    }

    /// The two constants are Win32 contract values, not arbitrary picks — a typo here would silently
    /// disable the recovery this module exists to provide.
    #[test]
    fn scm_error_constants_match_win32() {
        assert_eq!(ERROR_SERVICE_EXISTS, 1073);
        assert_eq!(ERROR_SERVICE_MARKED_FOR_DELETE, 1072);
        assert_eq!(ERROR_SERVICE_DOES_NOT_EXIST, 1060);
    }
}
