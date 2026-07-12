//! Point the OS resolver at our `.internal` DNS resolver (design.md §6, M6). `dns.rs` serves
//! correct answers on a UDP socket; this makes the OS actually *route* `.internal` queries there.
//!
//! Linux/systemd-resolved backend: per-link config on the wg interface with a `~internal`
//! *routing domain*, so only `*.internal` lookups go to our resolver — global DNS is untouched.
//! The config is scoped to the wg link, so it clears automatically when the link disappears; we
//! also `revert` it on clean shutdown. Windows (NRPT) and macOS (`/etc/resolver`) are future
//! backends behind the same trait.
//!
//! Best-effort: requires privilege (the daemon already runs privileged for `ip link`/nft). A
//! failure only means names don't auto-resolve — it never blocks meshing.

use std::net::SocketAddr;
use std::process::Command;

/// The `.internal` zone we serve. Used as the systemd-resolved routing domain (`~internal`).
const DOMAIN: &str = "internal";

/// Hooks the OS resolver to our `.internal` server on the wg link, and reverts it.
pub trait ResolverHook: Send + Sync {
    /// Route `.internal` queries on `iface` to our resolver at `server`.
    fn install(&self, iface: &str, server: SocketAddr) -> anyhow::Result<()>;
    /// Undo the per-link resolver config.
    fn revert(&self, iface: &str) -> anyhow::Result<()>;
}

/// The OS resolver backend for this platform, or `None` where we don't hook the resolver yet.
///
/// Linux drives systemd-resolved ([`ResolvectlHook`]). Windows would use NRPT
/// (`Add-DnsClientNrptRule -Namespace .internal -NameServers <ip>` / `Remove-DnsClientNrptRule`)
/// and macOS `/etc/resolver/internal`; both are deferred, so `.internal` names still resolve when
/// queried directly at `dns_bind` but aren't wired into the OS resolver automatically there.
pub fn platform_hook() -> Option<Box<dyn ResolverHook>> {
    #[cfg(target_os = "linux")]
    {
        Some(Box::new(ResolvectlHook))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// systemd-resolved backend driving `resolvectl`.
pub struct ResolvectlHook;

impl ResolverHook for ResolvectlHook {
    fn install(&self, iface: &str, server: SocketAddr) -> anyhow::Result<()> {
        run(&dns_args(iface, server))?;
        run(&domain_args(iface))?;
        tracing::info!(%iface, %server, "resolver: routed .internal via systemd-resolved");
        Ok(())
    }

    fn revert(&self, iface: &str) -> anyhow::Result<()> {
        run(&["revert".into(), iface.into()])
    }
}

/// `resolvectl dns <iface> <server>`. systemd-resolved takes a bare IP on port 53, else `ip:port`.
fn dns_args(iface: &str, server: SocketAddr) -> Vec<String> {
    let server = if server.port() == 53 {
        server.ip().to_string()
    } else {
        server.to_string()
    };
    vec!["dns".into(), iface.into(), server]
}

/// `resolvectl domain <iface> ~internal` — a routing domain: only `*.internal` uses our server.
fn domain_args(iface: &str) -> Vec<String> {
    vec!["domain".into(), iface.into(), format!("~{DOMAIN}")]
}

fn run(args: &[String]) -> anyhow::Result<()> {
    let out = Command::new("resolvectl").args(args).output()?;
    if !out.status.success() {
        anyhow::bail!(
            "resolvectl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_args_drops_default_port_keeps_custom() {
        assert_eq!(
            dns_args("unl0", "127.0.0.1:53".parse().unwrap()),
            vec!["dns", "unl0", "127.0.0.1"]
        );
        assert_eq!(
            dns_args("unl0", "127.0.0.1:15353".parse().unwrap()),
            vec!["dns", "unl0", "127.0.0.1:15353"]
        );
    }

    #[test]
    fn domain_is_a_routing_domain() {
        assert_eq!(domain_args("unl0"), vec!["domain", "unl0", "~internal"]);
    }
}
