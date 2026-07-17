//! Windows Service wrapper for the engine daemon — the packaging that lets a non-technical user
//! run UnityLAN without a terminal. The engine runs as a `LocalSystem` service so it starts at boot
//! with the privilege the daemon needs (WireGuard, the host firewall, NRPT); the unprivileged GUI
//! drives it over the named-pipe control channel.
//!
//! Subcommands (all under `unitylan-engine service …`):
//! - `install [config.toml]` — register an auto-start service (needs an elevated shell).
//! - `start` — start the (already-registered) service now; used by the MSI after a major upgrade so
//!   an auto-update relaunches the engine without waiting for a reboot. Idempotent.
//! - `uninstall` — stop and remove it (needs an elevated shell).
//! - `run [config.toml]` — the SCM-invoked entry point; not for interactive use. The config path is
//!   baked into the service's command line at install time, so users never pass it themselves.
//!
//! Runtime prerequisite (as for any Windows engine run): the wireguard-nt DLL sits at
//! `resources-windows\binaries\wireguard-amd64.dll` under the engine's install dir (defguard loads
//! it by that relative path; `run` pins the service's working dir to the exe folder so it resolves).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
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

/// DACL applied to the service at install so the *unprivileged* GUI can start it without a UAC
/// prompt. Grants: SYSTEM standard service control, Administrators full control (so `uninstall` and
/// `services.msc` keep working), and Interactive users (`IU` = the logged-on desktop user) query +
/// **start** (`RP`) only. Interactive-only is deliberate — remote/network logons don't get it. Stop
/// is *not* granted: day-to-day on/off is a mesh connect/disconnect over the control socket (no SCM
/// access), and the GUI's only SCM affordance is *start* (bootstrap from a stopped engine), so `WP`
/// (`SERVICE_STOP`) is unneeded — dropping it is least-privilege (stopping a service only ever tears
/// down the mesh, never opens the host, but the interactive user has no reason to hold the right).
const RELAXED_DACL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)\
    (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\
    (A;;CCLCSWRPLOCRRC;;;IU)";

/// Dispatch the `service` subcommand (called from `main` outside any tokio runtime).
pub fn main() -> Result<()> {
    match std::env::args().nth(2).unwrap_or_default().as_str() {
        "install" => install(std::env::args().nth(3)),
        "start" => start(),
        "uninstall" => uninstall(),
        "run" => run_dispatch(),
        other => anyhow::bail!(
            "unknown `service` subcommand '{other}' (use: install [config.toml], start, uninstall, run)"
        ),
    }
}

/// Register an auto-start service whose command line carries the (absolute) config path.
fn install(config: Option<String>) -> Result<()> {
    let exe = std::env::current_exe().context("locating the engine executable")?;
    let config = config.unwrap_or_else(|| default_config_path().to_string_lossy().into_owned());
    // The service runs with CWD = System32, so the config must be an absolute path.
    let config = std::fs::canonicalize(&config).with_context(|| {
        format!("config '{config}' not found — create it before installing the service")
    })?;

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
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .context("creating the service (already installed? run `service uninstall` first)")?;
    let _ = service.set_description(
        "UnityLAN mesh engine: WireGuard mesh, host firewall, and .unity.internal DNS resolver.",
    );

    // Relax the DACL so the unprivileged GUI can start/stop without UAC. Best-effort: on failure the
    // service still works, just controllable only from an elevated shell.
    let acl = match relax_acl() {
        Ok(()) => "GUI can start/stop it without elevation",
        Err(e) => {
            eprintln!("warning: could not relax service permissions ({e:#}); the GUI will need an elevated shell to start/stop");
            "control needs an elevated shell"
        }
    };

    println!("Installed service '{SERVICE_NAME}' (auto-start at boot).");
    println!("  config: {}", config.display());
    println!("  perms:  {acl}");
    println!("  start now:  sc.exe start {SERVICE_NAME}    (or reboot)");
    println!(
        "  ensure the wireguard-nt DLL is at resources-windows\\binaries\\wireguard-amd64.dll next to the engine executable."
    );
    Ok(())
}

/// Apply [`RELAXED_DACL`] to the service via `sc.exe sdset` (matches the shell-out pattern used by
/// the firewall/NRPT backends; the `windows-service` crate doesn't expose the security descriptor).
fn relax_acl() -> Result<()> {
    let out = std::process::Command::new("sc.exe")
        .args(["sdset", SERVICE_NAME, RELAXED_DACL])
        .output()
        .context("spawning sc.exe")?;
    if !out.status.success() {
        anyhow::bail!(
            "sc.exe sdset failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stdout).trim()
        );
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

    // Ask it to stop, then wait briefly so `delete` doesn't leave a marked-for-deletion service
    // lingering until the next reboot.
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }

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

    let cfg =
        Config::load(Path::new(&cfg_path)).with_context(|| format!("loading config {cfg_path}"))?;

    let (trigger, shutdown) = shutdown::channel();

    // Translate the SCM Stop/Shutdown controls into our latched shutdown signal.
    let event_handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            trigger.trigger();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("registering the service control handler")?;

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
    set_state(ServiceState::Stopped, ServiceControlAccept::empty())?;
    result
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
                    .unwrap_or_else(|_| "info".into()),
            )
            .with_writer(move || file.try_clone().expect("clone service log fd"))
            .try_init();
    }
}

/// Default config location when none is baked in: alongside the executable.
fn default_config_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("engine.toml")))
        .unwrap_or_else(|| PathBuf::from("engine.toml"))
}
