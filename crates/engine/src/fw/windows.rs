//! Windows host-firewall backend, driving Windows Defender Firewall through PowerShell's
//! `NetSecurity` module (`New-NetFirewallRule` / `Remove-NetFirewallRule`).
//!
//! Every rule is an *inbound allow* scoped to the wg interface (`-InterfaceAlias`), so — like the
//! nftables backend — only traffic arriving on the wg adapter is opened, never the host's other
//! interfaces. All rules share `-Group UnityLAN`, so a reset is a single group removal and every
//! `apply` is an idempotent full replace (rebuild = pure function of the exposed set + peer IPs).
//!
//! We rely on two properties of Windows Defender Firewall for the base policy nftables builds
//! explicitly: it is **stateful** (replies to our own outbound connections are auto-allowed, so no
//! established/related rule is needed) and its **default inbound action is Block** (so "nothing is
//! open unless exposed" holds without an explicit default-drop). Caveat: unlike nft's hard
//! `iif`-scoped drop chain, a pre-existing broad allow-inbound rule on the host could still permit
//! an unexposed port on the wg iface — a strict WFP sublayer is a future hardening.
//!
//! Best-effort, like the other backends: every `New-NetFirewallRule` runs with `-ErrorAction
//! SilentlyContinue`, so building the firewall *before* the wg adapter exists is fine. Unlike
//! nftables (which matches an interface by name lazily), `-InterfaceAlias` is validated against
//! present interfaces at creation time and would otherwise error ("interface not found") and set a
//! non-zero exit — aborting startup. Suppressed, those pre-up rules are simply skipped and then
//! (re)created by the first post-up membership `apply`, once `unl0` exists.

use common::control::Proto;

use super::{Exposed, FirewallBackend, PeersByNet};

pub struct WindowsFwBackend;

/// Shared `-Group` tag on every rule, so cleanup is one `Remove-NetFirewallRule -Group`.
const GROUP: &str = "UnityLAN";

impl FirewallBackend for WindowsFwBackend {
    fn apply(
        &self,
        iface: &str,
        exposed: &[Exposed],
        peers_by_net: &PeersByNet,
    ) -> anyhow::Result<()> {
        run_fw_ps(&script(iface, exposed, peers_by_net))
    }

    fn reset(&self) -> anyhow::Result<()> {
        run_fw_ps(&remove_group())
    }
}

/// `Remove-NetFirewallRule -Group 'UnityLAN'`, tolerant of "no such rules" so reset is idempotent.
fn remove_group() -> String {
    format!("Remove-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue")
}

/// Build the PowerShell script: clear our group, then re-add an inbound-allow rule per exposed
/// port (plus ICMPv4 echo for ping/diagnostics), each scoped to the wg interface. A `--net`-scoped
/// expose carries `-RemoteAddress` restricting it to that network's peer IPs; a scoped expose whose
/// network currently has no peers is omitted entirely (reachable by nobody — the default-deny).
fn script(iface: &str, exposed: &[Exposed], peers_by_net: &PeersByNet) -> String {
    let mut s = String::new();
    s.push_str(&remove_group());
    s.push('\n');

    // Ping: liveness/diagnostics only, allowed on the wg iface (parity with nft's echo-request).
    s.push_str(&format!(
        "New-NetFirewallRule -DisplayName 'UnityLAN ICMPv4 echo' -Group '{GROUP}' \
         -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -InterfaceAlias {iface} \
         -ErrorAction SilentlyContinue | Out-Null\n",
        iface = ps_quote(iface),
    ));

    for e in exposed {
        let proto = ps_proto(e.proto);
        let (name, remote) = match &e.net {
            None => (format!("UnityLAN {}/{}", e.proto.as_str(), e.port), None),
            Some(net) => {
                let ips = peers_by_net.get(net).map(Vec::as_slice).unwrap_or(&[]);
                if ips.is_empty() {
                    // Scoped to a network with no current peers → open to nobody; skip the rule.
                    continue;
                }
                let list = ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                (
                    format!("UnityLAN {}/{} net:{net}", e.proto.as_str(), e.port),
                    Some(list),
                )
            }
        };
        s.push_str(&format!(
            "New-NetFirewallRule -DisplayName {name} -Group '{GROUP}' -Direction Inbound \
             -Action Allow -Protocol {proto} -LocalPort {port} -InterfaceAlias {iface}",
            name = ps_quote(&name),
            port = e.port,
            iface = ps_quote(iface),
        ));
        if let Some(list) = remote {
            // IPs are formatted from Ipv4Addr, so no quoting/escaping concern.
            s.push_str(&format!(" -RemoteAddress {list}"));
        }
        s.push_str(" -ErrorAction SilentlyContinue | Out-Null\n");
    }

    s
}

/// Single-quote a string for PowerShell, doubling any embedded single quotes (the PS escape).
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// PowerShell `-Protocol` token for a proto.
fn ps_proto(proto: Proto) -> &'static str {
    match proto {
        Proto::Tcp => "TCP",
        Proto::Udp => "UDP",
    }
}

/// Run a firewall PowerShell script, tolerating its best-effort cmdlets.
///
/// Appends `exit 0`: every rule runs `-ErrorAction SilentlyContinue` on purpose (a pre-up missing
/// `-InterfaceAlias`, or a `Remove-NetFirewallRule` when the group is still empty, is expected and
/// benign). That silences the error text but still leaves `$? = $false`, so powershell would exit 1
/// with empty stderr and we'd abort startup over a best-effort skip. `exit 0` makes the exit code
/// reflect "the script ran", not "every best-effort cmdlet succeeded". A *parse* error still exits
/// non-zero before reaching `exit 0` (surfaced by the bail in `run_powershell`, stderr intact).
fn run_fw_ps(script: &str) -> anyhow::Result<()> {
    crate::util::run_powershell(&format!("{script}\nexit 0\n"), "firewall")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn exp(proto: Proto, port: u16, net: Option<&str>) -> Exposed {
        Exposed {
            proto,
            port,
            net: net.map(String::from),
        }
    }

    #[test]
    fn script_resets_group_and_opens_unscoped_ports() {
        let s = script(
            "unl0",
            &[exp(Proto::Tcp, 25565, None), exp(Proto::Udp, 34197, None)],
            &PeersByNet::new(),
        );
        assert!(s.contains("Remove-NetFirewallRule -Group 'UnityLAN'"));
        assert!(s.contains("-Protocol ICMPv4 -IcmpType 8 -InterfaceAlias 'unl0'"));
        assert!(s.contains("-Action Allow -Protocol TCP -LocalPort 25565 -InterfaceAlias 'unl0'"));
        assert!(s.contains("-Action Allow -Protocol UDP -LocalPort 34197 -InterfaceAlias 'unl0'"));
        // Unscoped exposes reach any peer — no remote-address restriction.
        assert!(!s.contains("-RemoteAddress"));
        // Every New-NetFirewallRule tolerates a missing interface (pre-up install): one
        // `-ErrorAction SilentlyContinue` per rule (ICMP echo + the two ports).
        assert_eq!(
            s.matches("-ErrorAction SilentlyContinue | Out-Null")
                .count(),
            3
        );
    }

    #[test]
    fn scoped_expose_restricts_to_network_peer_ips() {
        let mut peers = PeersByNet::new();
        peers.insert(
            "mesh".into(),
            vec![Ipv4Addr::new(100, 64, 0, 2), Ipv4Addr::new(100, 64, 0, 3)],
        );
        let s = script("unl0", &[exp(Proto::Tcp, 9001, Some("mesh"))], &peers);
        assert!(s.contains(
            "-LocalPort 9001 -InterfaceAlias 'unl0' -RemoteAddress 100.64.0.2,100.64.0.3"
        ));
        assert!(s.contains("net:mesh"));
    }

    #[test]
    fn scoped_expose_with_no_peers_is_omitted() {
        let s = script(
            "unl0",
            &[exp(Proto::Tcp, 9001, Some("mesh"))],
            &PeersByNet::new(),
        );
        // No peers in the network → the port is opened to nobody (relies on default-deny).
        assert!(!s.contains("-LocalPort 9001"));
        assert!(!s.contains("-RemoteAddress"));
    }
}
