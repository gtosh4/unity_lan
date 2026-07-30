//! Point the OS resolver at our `.unity.internal` DNS resolver (design.md §6, M6). `dns.rs` serves
//! correct answers on a UDP socket; this makes the OS actually *route* `.unity.internal` queries there.
//!
//! Per-OS backends behind [`ResolverHook`]: Linux drives systemd-resolved (per-link routing
//! domain, `linux.rs`); Windows drives NRPT (namespace policy, `windows.rs`). Named without doc
//! links because each module is `cfg`-gated: whichever one isn't being compiled has no item to
//! resolve to. macOS (`/etc/resolver`)
//! is a future backend. Where no backend exists, [`platform_hook`] returns `None` and `.unity.internal`
//! names still resolve when queried directly at the resolver's mesh IP — they just aren't wired into the OS
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
    ///
    /// `cert_domain` is the deployment's certificate domain (`RegisterResp::dns_domain`) when it has
    /// one, and is routed alongside `.unity.internal` so the alias every mesh name gains under it
    /// resolves too — that alias is the only one a publicly-trusted certificate can name, so without
    /// this a browser sent to `https://jellyfin.alice.<domain>` asks *public* DNS, which by design
    /// carries no `A` records for mesh addresses.
    ///
    /// The tradeoff: routing it means we shadow that whole domain locally. We answer `A` only —
    /// every other query type under it gets empty-NOERROR with no fallback to public DNS, and an
    /// unknown name gets empty-NOERROR rather than NXDOMAIN, since we are not its authority. That is
    /// fine for a subdomain dedicated to the mesh (nothing else lives there, and the CA validates
    /// `_acme-challenge` TXT from *outside* the mesh against the coordinator's zone), and wrong for a
    /// domain carrying real public records — hence `docs/coordinator-setup.md` requires the former.
    fn install(
        &self,
        iface: &str,
        server: SocketAddr,
        cert_domain: Option<&str>,
    ) -> anyhow::Result<()>;
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
