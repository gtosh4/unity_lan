//! Point the OS resolver at our `.unity.internal` DNS resolver (design.md §6, M6). `dns.rs` serves
//! correct answers on a UDP socket; this makes the OS actually *route* `.unity.internal` queries there.
//!
//! Per-OS backends behind [`ResolverHook`]: Linux drives systemd-resolved (per-link routing
//! domain, [`linux`]); Windows drives NRPT (namespace policy, [`windows`]). macOS (`/etc/resolver`)
//! is a future backend. Where no backend exists, [`platform_hook`] returns `None` and `.unity.internal`
//! names still resolve when queried directly at `dns_bind` — they just aren't wired into the OS
//! resolver automatically.
//!
//! Best-effort: requires privilege (the daemon already runs privileged for the wg link + firewall).
//! A failure only means names don't auto-resolve — it never blocks meshing.

use std::net::SocketAddr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// Hooks the OS resolver to our `.unity.internal` server, and reverts it.
pub trait ResolverHook: Send + Sync {
    /// Route `.unity.internal` queries to our resolver at `server`. `iface` is the wg link (used by
    /// link-scoped backends like systemd-resolved; ignored by namespace-scoped ones like NRPT).
    fn install(&self, iface: &str, server: SocketAddr) -> anyhow::Result<()>;
    /// Undo the resolver config.
    fn revert(&self, iface: &str) -> anyhow::Result<()>;
}

/// The OS resolver backend for this platform, or `None` where we don't hook the resolver yet
/// (e.g. macOS). Linux → systemd-resolved; Windows → NRPT.
pub fn platform_hook() -> Option<Box<dyn ResolverHook>> {
    #[cfg(target_os = "linux")]
    {
        Some(Box::new(linux::ResolvectlHook))
    }
    #[cfg(windows)]
    {
        Some(Box::new(windows::NrptHook))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}
