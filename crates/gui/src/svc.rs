//! Engine Windows-service *status + start* for the GUI — the engine-process lifecycle, distinct
//! from the mesh connect/disconnect (which rides the control socket; see `ctl::set_connected`).
//!
//! Day-to-day on/off is a mesh connect/disconnect, so the service stays resident and the GUI has no
//! stop/restart here. `start` remains only to bring the engine up from a stopped state (there's no
//! control socket to connect to until it's running).
//!
//! The GUI is unprivileged. Status queries work for any user (the SCM grants `QUERY_STATUS` to
//! authenticated users by default); `start` works because the engine's installer relaxes the
//! service DACL to grant the interactive user `SERVICE_START` (see `engine::service::RELAXED_DACL`).
//! So none of this needs elevation.
//!
//! The SCM calls are blocking, so each public entry point hops onto a blocking thread to avoid
//! stalling iced's async runtime. Off Windows the whole feature is `Unsupported` and the GUI simply
//! hides the section.

/// Coarse engine-service state for the GUI. Platform-independent so `main.rs` stays OS-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// These variants are only constructed by the `#[cfg(windows)]` service-status mapping; on other
// platforms the service model is unsupported, so they're legitimately unused.
#[cfg_attr(not(windows), allow(dead_code))]
pub enum SvcState {
    /// No service registered — the user hasn't run `service install` yet.
    NotInstalled,
    Stopped,
    Running,
    /// A start/stop is in progress (start-pending / stop-pending).
    Pending,
    /// Not a Windows build — no service model.
    Unsupported,
}

impl SvcState {
    /// Human label for the status line.
    pub fn label(self) -> &'static str {
        match self {
            SvcState::NotInstalled => "not installed",
            SvcState::Stopped => "stopped",
            SvcState::Running => "running",
            SvcState::Pending => "…",
            SvcState::Unsupported => "n/a",
        }
    }
}

/// Fetch the current service state.
pub async fn query() -> Result<SvcState, String> {
    run_blocking(imp::query).await
}

/// Start the service (no-op error text if it's already running).
pub async fn start() -> Result<(), String> {
    run_blocking(imp::start).await
}

/// Run a blocking SCM op off the async runtime, flattening join + op errors to a `String`.
async fn run_blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => Err(format!("service task failed: {e}")),
    }
}

#[cfg(windows)]
mod imp {
    use std::time::{Duration, Instant};

    use windows_service::service::{ServiceAccess, ServiceState as WinState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::SvcState;

    const NAME: &str = common::control::WINDOWS_SERVICE_NAME;

    fn manager() -> Result<ServiceManager, String> {
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| format!("opening service manager: {e}"))
    }

    pub fn query() -> Result<SvcState, String> {
        let manager = manager()?;
        let service = match manager.open_service(NAME, ServiceAccess::QUERY_STATUS) {
            Ok(s) => s,
            // A missing service is the expected "not installed yet" case, not an error to surface.
            Err(_) => return Ok(SvcState::NotInstalled),
        };
        let status = service
            .query_status()
            .map_err(|e| format!("querying status: {e}"))?;
        Ok(map_state(status.current_state))
    }

    pub fn start() -> Result<(), String> {
        let service = open(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
        service
            .start::<&std::ffi::OsStr>(&[])
            .map_err(|e| format!("starting service: {e}"))?;
        wait_for(&service, WinState::Running)
    }

    fn open(access: ServiceAccess) -> Result<windows_service::service::Service, String> {
        manager()?
            .open_service(NAME, access)
            .map_err(|e| format!("opening service (installed?): {e}"))
    }

    /// Poll until the service reaches `want` (or ~15s elapses), so the GUI reports the settled state.
    fn wait_for(service: &windows_service::service::Service, want: WinState) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let state = service
                .query_status()
                .map_err(|e| format!("querying status: {e}"))?
                .current_state;
            if state == want {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for service to become {want:?}"));
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    fn map_state(s: WinState) -> SvcState {
        match s {
            WinState::Running => SvcState::Running,
            WinState::Stopped => SvcState::Stopped,
            WinState::StartPending
            | WinState::StopPending
            | WinState::ContinuePending
            | WinState::PausePending
            | WinState::Paused => SvcState::Pending,
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::SvcState;

    pub fn query() -> Result<SvcState, String> {
        Ok(SvcState::Unsupported)
    }
    pub fn start() -> Result<(), String> {
        Err("service control is Windows-only".into())
    }
}
