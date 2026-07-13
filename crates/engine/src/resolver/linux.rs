//! Linux/systemd-resolved backend: per-link config on the wg interface with a `~internal`
//! *routing domain*, so only `*.internal` lookups go to our resolver — global DNS is untouched.
//! The config is scoped to the wg link, so it clears automatically when the link disappears; we
//! also `revert` it on clean shutdown.

use std::net::SocketAddr;
use std::process::Command;

use super::ResolverHook;

/// The `.internal` zone we serve, used as the systemd-resolved routing domain (`~internal`).
const DOMAIN: &str = "internal";

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
