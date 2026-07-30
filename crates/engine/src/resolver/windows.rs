//! Windows NRPT backend: the Name Resolution Policy Table, driven through PowerShell's
//! `DnsClient` module (`Add-DnsClientNrptRule` / `Remove-DnsClientNrptRule`).
//!
//! NRPT is *namespace*-scoped, not link-scoped: a single rule routes every `*.unity.internal` lookup to
//! our resolver, system-wide, while all other names use the OS's normal DNS — the same split-horizon
//! effect systemd-resolved gets from a per-link routing domain. On a deployment with a certificate
//! domain there is a second rule for it, since the alias a publicly-trusted certificate names lives
//! there. Every rule carries `-Comment UnityLAN`, so `install` first clears *all* UnityLAN rules
//! (whatever namespace — a previous run's certificate domain may differ from this one's) and then adds
//! a fresh set (idempotent full replace); `revert` removes exactly the rules we created.
//!
//! Two consequences of NRPT vs. the Linux backend:
//! - **Port 53 only.** NRPT nameservers are IPs queried on port 53 — there is no port field. If the
//!   resolver is bound elsewhere the hook can't honor it, so `install` errors (best-effort: the
//!   daemon logs it and meshes on without auto-resolution). The daemon always binds `:53`, so this
//!   only bites the `resolver-install` dev command with a non-53 address.
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
    fn install(
        &self,
        _iface: &str,
        server: SocketAddr,
        cert_domain: Option<&str>,
    ) -> anyhow::Result<()> {
        if server.port() != 53 {
            anyhow::bail!(
                "NRPT routes to a nameserver IP on port 53 only, but the resolver bind is {server}; \
                 bind the resolver on port 53 to enable the Windows resolver hook"
            );
        }
        crate::util::run_powershell(&install_script(server.ip(), cert_domain), "NRPT")?;
        tracing::info!(
            server = %server.ip(), cert_domain,
            "resolver: routed .unity.internal via NRPT"
        );
        Ok(())
    }

    fn revert(&self, _iface: &str) -> anyhow::Result<()> {
        crate::util::run_powershell(&remove_script(), "NRPT")
    }
}

/// Clear any stale UnityLAN rules, then add a fresh rule per namespace we route: `.unity.internal`
/// always, and the certificate domain when the deployment has one.
fn install_script(server: IpAddr, cert_domain: Option<&str>) -> String {
    let mut s = remove_script();
    s.push('\n');
    s.push_str(&add_rule(DOMAIN, server));
    if let Some(d) = cert_domain.and_then(routable_domain) {
        s.push('\n');
        s.push_str(&add_rule(d, server));
    }
    s
}

/// The certificate domain if it is safe to interpolate into the script, else `None` (logged).
///
/// Unlike the namespace and comment literals, this one arrives over the wire in
/// `RegisterResp::dns_domain`, and the script runs as LocalSystem — so it is accepted only as a plain
/// ASCII DNS name. A coordinator is our trust anchor for *names*, not for code on our machine.
/// Refusing just this rule (rather than the whole install) keeps `.unity.internal` routed.
fn routable_domain(domain: &str) -> Option<&str> {
    let plain = !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if !plain {
        tracing::warn!(
            ?domain,
            "resolver: certificate domain is not a plain DNS name; not routing it via NRPT"
        );
        return None;
    }
    Some(domain)
}

/// `Add-DnsClientNrptRule -Namespace '.<domain>' -NameServers '<ip>' -Comment 'UnityLAN'`. The
/// leading dot makes it a suffix rule ("this suffix and all subdomains").
fn add_rule(domain: &str, server: IpAddr) -> String {
    format!(
        "Add-DnsClientNrptRule -Namespace '.{domain}' -NameServers '{server}' \
         -Comment '{COMMENT}' | Out-Null"
    )
}

/// Remove our NRPT rules, matched by our comment alone — deliberately *not* by namespace, because we
/// install one rule per routed namespace and the certificate domain is whatever the coordinator
/// published at the time. A namespace filter would leave a previous run's certificate-domain rule
/// behind in the registry, outliving the daemon and pointing at a resolver that is gone. The comment
/// is ours, so nothing else is touched. Tolerant of "no such rules" — an idempotent no-op when
/// nothing is installed.
fn remove_script() -> String {
    format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{COMMENT}' }} \
         | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    #[test]
    fn install_clears_then_adds_rule_for_the_namespace() {
        let s = install_script(LOCAL, None);
        // Clears stale rules first, scoped to our comment.
        assert!(s.contains("Get-DnsClientNrptRule"));
        assert!(s.contains("$_.Comment -eq 'UnityLAN'"));
        assert!(s.contains("Remove-DnsClientNrptRule -Force"));
        // Then adds a suffix rule routing .unity.internal at our resolver.
        assert!(s.contains(
            "Add-DnsClientNrptRule -Namespace '.unity.internal' -NameServers '127.0.0.1' \
             -Comment 'UnityLAN'"
        ));
        // With no certificate domain, that is the *only* rule — exactly the pre-cert behavior.
        assert_eq!(s.matches("Add-DnsClientNrptRule").count(), 1);
    }

    #[test]
    fn certificate_domain_gets_its_own_rule() {
        let s = install_script(LOCAL, Some("mesh.example.com"));
        assert_eq!(s.matches("Add-DnsClientNrptRule").count(), 2);
        assert!(s.contains("-Namespace '.unity.internal' -NameServers '127.0.0.1'"));
        assert!(s.contains("-Namespace '.mesh.example.com' -NameServers '127.0.0.1'"));
        // Same tag on both, so the one comment-scoped remove cleans up the pair.
        assert_eq!(s.matches("-Comment 'UnityLAN'").count(), 2);
        assert!(s.contains("$_.Comment -eq 'UnityLAN'"));
    }

    #[test]
    fn a_domain_that_is_not_a_plain_dns_name_is_not_routed() {
        // The value crosses the wire and the script runs as LocalSystem, so anything that could
        // break out of the quoted namespace is dropped — `.unity.internal` still gets routed.
        for bad in ["mesh.example.com'; Remove-Item C:\\ -Recurse", "nodot", ""] {
            let s = install_script(LOCAL, Some(bad));
            assert_eq!(s.matches("Add-DnsClientNrptRule").count(), 1, "{bad:?}");
            assert!(!s.contains("Remove-Item"), "{bad:?}");
        }
    }

    #[test]
    fn revert_removes_our_rules_in_any_namespace() {
        let s = remove_script();
        assert!(s.contains("$_.Comment -eq 'UnityLAN'"));
        assert!(s.contains("Remove-DnsClientNrptRule -Force"));
        // No namespace filter: a previous run's certificate-domain rule must go too, and its domain
        // is not knowable from here.
        assert!(!s.contains("$_.Namespace"));
        // Never adds anything on revert.
        assert!(!s.contains("Add-DnsClientNrptRule"));
    }
}
