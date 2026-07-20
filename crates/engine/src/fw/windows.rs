//! Windows host-firewall backend, driving Windows Defender Firewall through PowerShell's
//! `NetSecurity` module (`New-NetFirewallRule` / `Remove-NetFirewallRule`).
//!
//! Every rule is an *inbound allow*; all but two are scoped to the wg interface (`-InterfaceAlias`),
//! so — like the nftables backend — only traffic arriving on the wg adapter is opened, never the
//! host's other interfaces. The exceptions are the WireGuard listen port (so inbound handshakes
//! reach the tunnel at all) and the LAN discovery beacon port (so a same-segment peer's broadcast is
//! received), both opened host-wide (see [`script`]). All rules share `-Group UnityLAN`, so a
//! reset is a single group removal and every `apply` is an idempotent full replace (rebuild = pure
//! function of the listen port + exposed set + peer IPs).
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

use super::{Exposed, FirewallBackend, PeerSets};

pub struct WindowsFwBackend {
    /// WireGuard's UDP listen port, opened on the host interfaces (see [`script`]).
    pub listen_port: u16,
    /// The LAN discovery beacon's UDP port, opened on the host interfaces like `listen_port` so
    /// inbound broadcasts arrive; `None` when the beacon is disabled.
    pub beacon_port: Option<u16>,
}

/// Shared `-Group` tag on every rule, so cleanup is one `Remove-NetFirewallRule -Group`.
const GROUP: &str = "UnityLAN";

impl FirewallBackend for WindowsFwBackend {
    fn apply(&self, iface: &str, exposed: &[Exposed], peers: &PeerSets) -> anyhow::Result<()> {
        run_fw_ps(&script(
            iface,
            self.listen_port,
            self.beacon_port,
            exposed,
            peers,
        ))
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
/// port (plus ICMPv4 echo for ping/diagnostics), each scoped to the wg interface. A scoped expose
/// carries `-RemoteAddress` restricting it to that scope's peer IPs; a scoped expose whose peers
/// are all offline is omitted entirely (reachable by nobody — the default-deny covers it).
///
/// Two rules are deliberately *not* wg-scoped: `listen_port` (WireGuard's own UDP transport port),
/// opened on the host interfaces so inbound handshakes from off-LAN peers arrive; and `beacon_port`
/// (the LAN discovery beacon), opened the same way so a same-segment peer's broadcast is received —
/// it arrives on the physical NIC, not the wg adapter, which Windows Defender default-denies. Every
/// exposed port governs already-decrypted traffic on the wg adapter; these govern traffic on the
/// physical NIC. Opening the listen port host-wide adds no real surface — WireGuard authenticates
/// every datagram and drops non-peer traffic itself — and mirrors the reference `wireguard.exe`; the
/// beacon likewise only ever triggers an authenticated WG handshake attempt (see `beacon.rs`). Both
/// share the group, so `reset` removes them too.
fn script(
    iface: &str,
    listen_port: u16,
    beacon_port: Option<u16>,
    exposed: &[Exposed],
    peers: &PeerSets,
) -> String {
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

    // Peer-direct attestation refresh (docs/gossip-refresh.md): co-members pull our own attestation
    // from this UDP port over the tunnel. Mesh infrastructure — only an authenticated WG peer reaches
    // the wg iface at all — so it's allowed on the wg iface like ICMP (parity with nft's dport accept);
    // inert when gossip is off (no listener). Without it, Windows' default-deny drops the pull and the
    // peer can never self-serve, forcing every renewal onto the coordinator.
    s.push_str(&format!(
        "New-NetFirewallRule -DisplayName 'UnityLAN p2p {p2p}/udp' -Group '{GROUP}' \
         -Direction Inbound -Action Allow -Protocol UDP -LocalPort {p2p} -InterfaceAlias {iface} \
         -ErrorAction SilentlyContinue | Out-Null\n",
        p2p = common::p2p::P2P_PORT,
        iface = ps_quote(iface),
    ));

    // WireGuard's listen port on the host interfaces (no -InterfaceAlias) — see the fn docs.
    s.push_str(&format!(
        "New-NetFirewallRule -DisplayName 'UnityLAN WireGuard {listen_port}/udp' -Group '{GROUP}' \
         -Direction Inbound -Action Allow -Protocol UDP -LocalPort {listen_port} \
         -ErrorAction SilentlyContinue | Out-Null\n",
    ));

    // The LAN discovery beacon port on the host interfaces (no -InterfaceAlias), when enabled — see
    // the fn docs. Broadcasts arrive on the physical NIC, which Defender default-denies.
    if let Some(beacon_port) = beacon_port {
        s.push_str(&format!(
            "New-NetFirewallRule -DisplayName 'UnityLAN beacon {beacon_port}/udp' -Group '{GROUP}' \
             -Direction Inbound -Action Allow -Protocol UDP -LocalPort {beacon_port} \
             -ErrorAction SilentlyContinue | Out-Null\n",
        ));
    }

    for e in exposed {
        let proto = ps_proto(e.proto);
        let (name, remote) = match peers.sources(&e.scope) {
            // Unscoped: no `-RemoteAddress`, so any peer on the wg interface reaches it.
            None => (format!("UnityLAN {}/{}", e.proto.as_str(), e.port), None),
            Some(ips) => {
                if ips.is_empty() {
                    // Scoped to a set with no current peers → open to nobody. New-NetFirewallRule
                    // has no way to spell an empty -RemoteAddress (unlike nft's empty set), and a
                    // rule with the flag omitted would open the port to *every* peer — so the only
                    // correct rendering is no rule at all, which the default-deny then covers.
                    continue;
                }
                let list = ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                (
                    format!(
                        "UnityLAN {}/{} scope:{}",
                        e.proto.as_str(),
                        e.port,
                        peers.label(&e.scope)
                    ),
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
    use super::super::NetInfo;
    use super::*;
    use common::control::ExposeScope;
    use std::net::Ipv4Addr;

    /// A resolved network scope, matching the ids the `by_net` fixture assigns.
    const MESH: ExposeScope = ExposeScope::Net {
        guild_id: 900_100,
        role_id: 7001,
    };

    fn exp(proto: Proto, port: u16, scope: ExposeScope) -> Exposed {
        Exposed { proto, port, scope }
    }

    fn by_net(name: &str, ips: Vec<Ipv4Addr>) -> PeerSets {
        PeerSets {
            nets: vec![NetInfo {
                guild_id: 900_100,
                role_id: 7001,
                guild: "acme".into(),
                name: name.into(),
                ips,
            }],
            own_devices: Vec::new(),
        }
    }

    #[test]
    fn script_resets_group_and_opens_unscoped_ports() {
        let s = script(
            "unl0",
            51820,
            None,
            &[
                exp(Proto::Tcp, 25565, ExposeScope::AllPeers),
                exp(Proto::Udp, 34197, ExposeScope::AllPeers),
            ],
            &PeerSets::default(),
        );
        assert!(s.contains("Remove-NetFirewallRule -Group 'UnityLAN'"));
        assert!(s.contains("-Protocol ICMPv4 -IcmpType 8 -InterfaceAlias 'unl0'"));
        assert!(s.contains("-Action Allow -Protocol TCP -LocalPort 25565 -InterfaceAlias 'unl0'"));
        assert!(s.contains("-Action Allow -Protocol UDP -LocalPort 34197 -InterfaceAlias 'unl0'"));
        // Unscoped exposes reach any peer — no remote-address restriction.
        assert!(!s.contains("-RemoteAddress"));
        // One `-ErrorAction SilentlyContinue` per rule: ICMP echo, the wg listen port, the two ports
        // (beacon disabled here, so no beacon rule).
        assert_eq!(
            s.matches("-ErrorAction SilentlyContinue | Out-Null")
                .count(),
            4
        );
    }

    /// The wg listen port is opened on the host, *not* scoped to the wg interface, so inbound
    /// handshakes arriving on the physical NIC reach it — the one rule here that is not
    /// `-InterfaceAlias`'d. Without it, Windows Defender's default-deny drops every inbound
    /// handshake and the device is unreachable to the mesh.
    #[test]
    fn script_opens_wg_listen_port_host_wide() {
        let s = script("unl0", 51820, None, &[], &PeerSets::default());
        let line = s
            .lines()
            .find(|l| l.contains("-Protocol UDP -LocalPort 51820"))
            .expect("a rule for the wg listen port");
        assert!(
            !line.contains("-InterfaceAlias"),
            "the listen port must be open on the host, not just the wg iface: {line}"
        );
        assert!(line.contains("-Group 'UnityLAN'"), "so reset() removes it");
    }

    /// The beacon port, when enabled, is opened host-wide (not wg-scoped) so a same-segment peer's
    /// broadcast — which arrives on the physical NIC — is received; disabled, no such rule exists.
    #[test]
    fn script_opens_beacon_port_host_wide_only_when_enabled() {
        let s = script("unl0", 51820, Some(51821), &[], &PeerSets::default());
        let line = s
            .lines()
            .find(|l| l.contains("-Protocol UDP -LocalPort 51821"))
            .expect("a rule for the beacon port");
        assert!(
            !line.contains("-InterfaceAlias"),
            "the beacon port must be open on the host, not just the wg iface: {line}"
        );
        assert!(line.contains("-Group 'UnityLAN'"), "so reset() removes it");

        // Disabled → no beacon rule at all.
        let off = script("unl0", 51820, None, &[], &PeerSets::default());
        assert!(!off.contains("-LocalPort 51821"));
    }

    /// The peer-direct attestation port (51830) is opened on the wg interface — parity with the
    /// nftables backend's `udp dport 51830 accept`. Without it a Windows peer default-denies the
    /// pull and can never self-serve its attestation, forcing every renewal onto the coordinator.
    #[test]
    fn script_opens_p2p_port_wg_scoped() {
        let s = script("unl0", 51820, None, &[], &PeerSets::default());
        let line = s
            .lines()
            .find(|l| l.contains(&format!("-LocalPort {}", common::p2p::P2P_PORT)))
            .expect("a rule for the p2p attestation port");
        assert!(
            line.contains("-Protocol UDP") && line.contains("-InterfaceAlias 'unl0'"),
            "the p2p port must be UDP and wg-scoped: {line}"
        );
        assert!(line.contains("-Group 'UnityLAN'"), "so reset() removes it");
    }

    #[test]
    fn scoped_expose_restricts_to_network_peer_ips() {
        let peers = by_net(
            "mesh",
            vec![Ipv4Addr::new(100, 64, 0, 2), Ipv4Addr::new(100, 64, 0, 3)],
        );
        let s = script("unl0", 51820, None, &[exp(Proto::Tcp, 9001, MESH)], &peers);
        assert!(s.contains(
            "-LocalPort 9001 -InterfaceAlias 'unl0' -RemoteAddress 100.64.0.2,100.64.0.3"
        ));
        assert!(s.contains("scope:mesh"));
    }

    /// The own-device scope restricts to the owner's other devices, which are not in any network —
    /// so a network's peers must not leak into the rule.
    #[test]
    fn own_device_scope_restricts_to_the_owners_devices() {
        let peers = PeerSets {
            nets: vec![NetInfo {
                guild_id: 900_100,
                role_id: 7001,
                guild: "acme".into(),
                name: "mesh".into(),
                ips: vec![Ipv4Addr::new(100, 64, 0, 9)],
            }],
            own_devices: vec![Ipv4Addr::new(100, 64, 0, 2)],
        };
        let s = script(
            "unl0",
            51820,
            None,
            &[exp(Proto::Tcp, 9001, ExposeScope::OwnDevices)],
            &peers,
        );
        assert!(s.contains("-LocalPort 9001 -InterfaceAlias 'unl0' -RemoteAddress 100.64.0.2"));
        assert!(
            !s.contains("100.64.0.9"),
            "a network peer must not be admitted"
        );
    }

    #[test]
    fn scoped_expose_with_no_peers_is_omitted() {
        let s = script(
            "unl0",
            51820,
            None,
            &[exp(Proto::Tcp, 9001, MESH)],
            &PeerSets::default(),
        );
        // No peers in the network → the port is opened to nobody (relies on default-deny).
        assert!(!s.contains("-LocalPort 9001"));
        assert!(!s.contains("-RemoteAddress"));
    }
}
