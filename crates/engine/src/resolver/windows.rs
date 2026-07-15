//! Windows NRPT backend: the Name Resolution Policy Table, driven through PowerShell's
//! `DnsClient` module (`Add-DnsClientNrptRule` / `Remove-DnsClientNrptRule`).
//!
//! NRPT is *namespace*-scoped, not link-scoped: a single rule routes every `*.unity.internal` lookup to
//! our resolver, system-wide, while all other names use the OS's normal DNS — the same split-horizon
//! effect systemd-resolved gets from a per-link routing domain. Every rule carries `-Comment
//! UnityLAN`, so `install` first clears any stale UnityLAN rule and then adds a fresh one (idempotent
//! full replace), and `revert` removes exactly the rules we created.
//!
//! Two consequences of NRPT vs. the Linux backend:
//! - **Port 53 only.** NRPT nameservers are IPs queried on port 53 — there is no port field. If the
//!   resolver is bound elsewhere the hook can't honor it, so `install` errors (best-effort: the
//!   daemon logs it and meshes on without auto-resolution). Bind `dns_bind` on `:53` to use it.
//! - **Not auto-cleared.** NRPT rules live in the registry, not on the link, so an unclean exit
//!   leaves the rule behind (pointing at a resolver that's no longer listening → `.unity.internal` names
//!   SERVFAIL until the next run). `install` clears stale rules up front to self-heal; `revert` on
//!   clean shutdown is the normal path.
//!
//! Runtime prerequisite: run elevated (adding/removing NRPT rules requires admin).

use std::net::{IpAddr, SocketAddr};

use super::ResolverHook;

/// The zone we serve. As an NRPT namespace, the leading dot means "this suffix and all
/// subdomains" (a bare `unity.internal` would match only the exact name).
const DOMAIN: &str = common::DNS_SUFFIX;

/// `-Comment` tag on every rule we add, so cleanup only ever touches our own rules.
const COMMENT: &str = "UnityLAN";

/// NRPT backend driving the PowerShell `DnsClient` cmdlets.
pub struct NrptHook;

impl ResolverHook for NrptHook {
    fn install(&self, _iface: &str, server: SocketAddr) -> anyhow::Result<()> {
        if server.port() != 53 {
            anyhow::bail!(
                "NRPT routes to a nameserver IP on port 53 only, but dns_bind is {server}; \
                 bind the resolver on port 53 to enable the Windows resolver hook"
            );
        }
        crate::util::run_powershell(&install_script(server.ip()), "NRPT")?;
        tracing::info!(server = %server.ip(), "resolver: routed .unity.internal via NRPT");
        Ok(())
    }

    fn revert(&self, _iface: &str) -> anyhow::Result<()> {
        crate::util::run_powershell(&remove_script(), "NRPT")
    }
}

/// Clear any stale UnityLAN rule, then add a fresh `.unity.internal → <ip>` rule.
fn install_script(server: IpAddr) -> String {
    format!("{}\n{}", remove_script(), add_rule(server))
}

/// `Add-DnsClientNrptRule -Namespace '.unity.internal' -NameServers '<ip>' -Comment 'UnityLAN'`.
fn add_rule(server: IpAddr) -> String {
    // Namespace and comment are fixed literals; the IP is formatted from `IpAddr` — nothing to
    // escape, so no PowerShell quoting concern.
    format!(
        "Add-DnsClientNrptRule -Namespace '.{DOMAIN}' -NameServers '{server}' \
         -Comment '{COMMENT}' | Out-Null"
    )
}

/// Remove our NRPT rules, matched by both namespace and our comment so nothing else is touched.
/// Tolerant of "no such rules" so it's an idempotent no-op when nothing is installed.
fn remove_script() -> String {
    format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -contains '.{DOMAIN}' \
         -and $_.Comment -eq '{COMMENT}' }} | Remove-DnsClientNrptRule -Force \
         -ErrorAction SilentlyContinue"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn install_clears_then_adds_rule_for_the_namespace() {
        let s = install_script(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        // Clears stale rules first, scoped to our namespace + comment.
        assert!(s.contains("Get-DnsClientNrptRule"));
        assert!(s.contains("$_.Namespace -contains '.unity.internal'"));
        assert!(s.contains("$_.Comment -eq 'UnityLAN'"));
        assert!(s.contains("Remove-DnsClientNrptRule -Force"));
        // Then adds a suffix rule routing .unity.internal at our resolver.
        assert!(s.contains(
            "Add-DnsClientNrptRule -Namespace '.unity.internal' -NameServers '127.0.0.1' \
             -Comment 'UnityLAN'"
        ));
    }

    #[test]
    fn revert_removes_only_our_rules() {
        let s = remove_script();
        assert!(s.contains("$_.Namespace -contains '.unity.internal'"));
        assert!(s.contains("$_.Comment -eq 'UnityLAN'"));
        assert!(s.contains("Remove-DnsClientNrptRule -Force"));
        // Never adds anything on revert.
        assert!(!s.contains("Add-DnsClientNrptRule"));
    }
}
