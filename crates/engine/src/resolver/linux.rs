//! Linux/systemd-resolved backend: per-link config on the wg interface with a `~unity.internal`
//! *routing domain*, so only `*.unity.internal` lookups go to our resolver — global DNS is untouched.
//! The config is scoped to the wg link, so it clears automatically when the link disappears; we
//! also `revert` it on clean shutdown.

use std::net::SocketAddr;
use std::process::Command;

use super::ResolverHook;

/// The zone we serve, used as the systemd-resolved routing domain (`~unity.internal`).
const DOMAIN: &str = common::DNS_SUFFIX;

/// systemd-resolved backend driving `resolvectl`.
pub struct ResolvectlHook;

impl ResolverHook for ResolvectlHook {
    fn install(
        &self,
        iface: &str,
        server: SocketAddr,
        cert_domain: Option<&str>,
    ) -> anyhow::Result<()> {
        run(&dns_args(iface, server))?;
        run(&domain_args(iface, cert_domain))?;
        tracing::info!(
            %iface, %server, cert_domain,
            "resolver: routed .unity.internal via systemd-resolved"
        );
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

/// `resolvectl domain <iface> ~unity.internal [~<cert_domain>]` — routing domains: only those
/// suffixes use our server, global DNS is untouched.
///
/// Both go in *one* call because `resolvectl domain` **replaces** the link's whole domain list; a
/// second invocation would drop the first domain rather than add to it.
fn domain_args(iface: &str, cert_domain: Option<&str>) -> Vec<String> {
    let mut args = vec!["domain".into(), iface.into(), format!("~{DOMAIN}")];
    // The certificate domain carries the alias a publicly-trusted cert can name, so it has to route
    // here too — see `ResolverHook::install` for what shadowing it locally costs.
    args.extend(cert_domain.map(|d| format!("~{d}")));
    args
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
        assert_eq!(
            domain_args("unl0", None),
            vec!["domain", "unl0", "~unity.internal"]
        );
    }

    #[test]
    fn certificate_domain_routes_alongside_in_one_call() {
        // One call carrying both: `resolvectl domain` replaces the link's list, so a second call
        // would drop `~unity.internal`.
        assert_eq!(
            domain_args("unl0", Some("mesh.example.com")),
            vec!["domain", "unl0", "~unity.internal", "~mesh.example.com"]
        );
    }
}
