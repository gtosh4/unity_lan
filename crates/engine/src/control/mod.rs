//! Local control socket (design.md §3.2, §8): an unprivileged frontend (CLI now, GUI later)
//! talks to the privileged engine daemon over a local socket. Newline-delimited JSON.
//!
//! Transport is `interprocess`'s cross-platform local socket — a Unix-domain socket on unix, a
//! named pipe on Windows — so the same newline-JSON protocol works on both. The endpoint is named
//! by [`crate::config::Config::control_name`] (a filesystem path on unix, a pipe name on Windows).
//!
//! Split three ways: [`status`] owns the live snapshot plus the setters the daemon drives it
//! through, [`server`] the daemon-side listener/dispatch, [`client`] the frontend-side wrappers.

mod client;
mod server;
mod status;

pub use client::*;
pub use server::*;
pub use status::*;

use interprocess::local_socket::tokio::prelude::*;
#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::Name;

/// Build the platform local-socket name from a config endpoint string: a filesystem path on unix,
/// a `\\.\pipe\<name>` named pipe on Windows.
fn to_name(endpoint: &str) -> std::io::Result<Name<'_>> {
    #[cfg(windows)]
    {
        endpoint.to_ns_name::<GenericNamespaced>()
    }
    #[cfg(not(windows))]
    {
        endpoint.to_fs_name::<GenericFilePath>()
    }
}
