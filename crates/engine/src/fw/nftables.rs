//! Linux nftables firewall backend. Renders the whole `inet unitylan` table and pipes it to
//! `nft -f -` in one atomic load, so the ruleset is always a pure function of (exposed set,
//! per-network peer IPs).

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use common::control::{ExposeScope, Proto};

use super::{Exposed, FirewallBackend, PeerSets};

pub struct NftBackend;

const TABLE: &str = "inet unitylan";

impl FirewallBackend for NftBackend {
    fn apply(&self, iface: &str, exposed: &[Exposed], peers: &PeerSets) -> anyhow::Result<()> {
        run_nft(&ruleset(iface, exposed, peers))
    }

    fn reset(&self) -> anyhow::Result<()> {
        // `add` first so the following `delete` never fails on a missing table.
        run_nft(&format!("add table {TABLE}\ndelete table {TABLE}\n"))
    }
}

/// nft set name for a scope's peer IPs.
///
/// A resolved network uses its `(guild_id, role_id)`, so the name is exact: no sanitizing, and no
/// way for two networks to land in one set. (An earlier version sanitized the role *name* into an
/// identifier, which silently merged `game-night` and `game_night`.) Only an unresolved scope still
/// sanitizes a name, under a distinct `named_` prefix so it can't collide with a resolved set — and
/// such a scope never carries members anyway.
fn set_name(scope: &ExposeScope) -> String {
    let san = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    };
    match scope {
        ExposeScope::OwnDevices => "own_devices".to_string(),
        // Ids, so the set name is exact — no sanitization, no collision.
        ExposeScope::Net { guild_id, role_id } => format!("net_{guild_id}_{role_id}"),
        // An unresolved name never reaches the ruleset with members (it resolves first, or admits
        // nobody), but it still needs a distinct set to hang the deny on.
        ExposeScope::Unresolved { guild, name } => {
            format!(
                "named_{}_{}",
                san(guild.as_deref().unwrap_or("")),
                san(name)
            )
        }
        // Unscoped: no source set, so no name. Callers filter these out first.
        ExposeScope::AllPeers => String::new(),
    }
}

/// Build the nft script. Only `iif <iface>` traffic is policed; everything else is accepted so
/// the host's other interfaces are untouched.
fn ruleset(iface: &str, exposed: &[Exposed], peers: &PeerSets) -> String {
    let mut s = String::new();
    // Atomic replace: ensure the table exists, drop it, recreate empty.
    s.push_str(&format!("add table {TABLE}\n"));
    s.push_str(&format!("delete table {TABLE}\n"));
    s.push_str(&format!("add table {TABLE}\n"));

    // A named set of source IPs per scope referenced by a scoped expose. Ordered by set name so
    // the script is deterministic (the tests compare it verbatim).
    let scoped: BTreeMap<String, &ExposeScope> = exposed
        .iter()
        .filter(|e| e.scope != ExposeScope::AllPeers)
        .map(|e| (set_name(&e.scope), &e.scope))
        .collect();
    for (name, scope) in &scoped {
        s.push_str(&format!("add set {TABLE} {name} {{ type ipv4_addr ; }}\n"));
        let ips = peers.sources(scope).unwrap_or(&[]);
        if !ips.is_empty() {
            let elems = ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            s.push_str(&format!("add element {TABLE} {name} {{ {elems} }}\n"));
        }
    }

    s.push_str(&format!(
        "add chain {TABLE} input {{ type filter hook input priority 0 ; policy accept ; }}\n"
    ));
    // Leave non-wg interfaces alone.
    s.push_str(&format!(
        "add rule {TABLE} input iifname != \"{iface}\" accept\n"
    ));
    // Return traffic for our own outbound connections.
    s.push_str(&format!(
        "add rule {TABLE} input ct state established,related accept\n"
    ));
    // Ping: liveness/diagnostics only, so allowed by default.
    s.push_str(&format!(
        "add rule {TABLE} input icmp type echo-request accept\n"
    ));
    // Peer-direct attestation refresh (docs/gossip-refresh.md): co-members pull our own attestation
    // from this UDP port over the tunnel. Mesh infrastructure — only an authenticated WG peer reaches
    // the iface at all — so it's allowed by default like icmp; inert when gossip is off (no listener).
    s.push_str(&format!(
        "add rule {TABLE} input udp dport {} accept\n",
        common::p2p::P2P_PORT
    ));

    // Unscoped exposes (any peer — only peers reach the wg iface at all), grouped per proto.
    let tcp = unscoped_ports(exposed, Proto::Tcp);
    let udp = unscoped_ports(exposed, Proto::Udp);
    if !tcp.is_empty() {
        s.push_str(&format!(
            "add rule {TABLE} input tcp dport {{ {tcp} }} accept\n"
        ));
    }
    if !udp.is_empty() {
        s.push_str(&format!(
            "add rule {TABLE} input udp dport {{ {udp} }} accept\n"
        ));
    }
    // Scoped exposes: only peers in the scope's source set reach the port.
    for e in exposed.iter().filter(|e| e.scope != ExposeScope::AllPeers) {
        let name = set_name(&e.scope);
        s.push_str(&format!(
            "add rule {TABLE} input ip saddr @{name} {} dport {} accept\n",
            e.proto.as_str(),
            e.port
        ));
    }

    // Everything else arriving on the wg iface is denied.
    s.push_str(&format!("add rule {TABLE} input drop\n"));
    s
}

fn unscoped_ports(exposed: &[Exposed], proto: Proto) -> String {
    exposed
        .iter()
        .filter(|e| e.scope == ExposeScope::AllPeers && e.proto == proto)
        .map(|e| e.port.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The mesh addresses live in `100.64.0.0/10` (RFC 6598 / CGNAT). Tailscale — and potentially
/// other tools that share this range — install an nftables anti-spoof rule that DROPs any packet
/// whose source is in that block when it arrives on a non-Tailscale interface. That rule silently
/// blackholes *all* UnityLAN traffic on the wg interface (a `drop` in any base chain wins over our
/// `accept`), so peers appear reachable in the coordinator yet every ping is lost.
///
/// Heuristic: an `nft` rule that both drops/rejects and references the CGNAT block, outside our own
/// table (our default-deny is a bare `drop`, so it never matches). Returns the offending line.
fn cgnat_conflict(ruleset: &str) -> Option<String> {
    ruleset
        .lines()
        .map(str::trim)
        .find(|l| (l.contains("drop") || l.contains("reject")) && l.contains("100.64.0.0/10"))
        .map(str::to_string)
}

/// Scan the live nftables ruleset for a foreign rule that would blackhole the mesh CGNAT range and,
/// if found, log an operator warning with remediation. Best-effort: any `nft` failure is ignored.
#[cfg(target_os = "linux")]
pub fn warn_on_cgnat_conflict(iface: &str) {
    let Ok(out) = Command::new("nft").args(["list", "ruleset"]).output() else {
        return;
    };
    let ruleset = String::from_utf8_lossy(&out.stdout);
    if let Some(rule) = cgnat_conflict(&ruleset) {
        tracing::warn!(
            offending_rule = %rule,
            "another firewall (likely Tailscale) drops the mesh range 100.64.0.0/10 on non-mesh \
             interfaces; UnityLAN traffic on {iface} will be silently blackholed. Exempt the mesh \
             interface, e.g. for Tailscale: `nft insert rule ip filter ts-input iifname \"{iface}\" accept`"
        );
    }
}

fn run_nft(script: &str) -> anyhow::Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawning nft (is nftables installed?): {e}"))?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "nft rejected ruleset ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::NetInfo;
    use super::*;
    use std::net::Ipv4Addr;

    fn exp(proto: Proto, port: u16, scope: ExposeScope) -> Exposed {
        Exposed { proto, port, scope }
    }

    const MESH: ExposeScope = ExposeScope::Net {
        guild_id: 900_100,
        role_id: 7001,
    };

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
    fn ruleset_has_default_deny_and_unscoped_ports() {
        let rs = ruleset(
            "unl0",
            &[
                exp(Proto::Tcp, 25565, ExposeScope::AllPeers),
                exp(Proto::Udp, 34197, ExposeScope::AllPeers),
            ],
            &PeerSets::default(),
        );
        assert!(rs.contains("iifname != \"unl0\" accept"));
        assert!(rs.contains("ct state established,related accept"));
        assert!(rs.contains("icmp type echo-request accept"));
        assert!(rs.contains(&format!("udp dport {} accept", common::p2p::P2P_PORT)));
        assert!(rs.contains("tcp dport { 25565 } accept"));
        assert!(rs.contains("udp dport { 34197 } accept"));
        assert!(rs.trim_end().ends_with("input drop"));
    }

    #[test]
    fn scoped_expose_builds_source_set_and_rule() {
        let peers = by_net(
            "mesh",
            vec![Ipv4Addr::new(100, 64, 0, 2), Ipv4Addr::new(100, 64, 0, 3)],
        );
        let rs = ruleset("unl0", &[exp(Proto::Tcp, 9001, MESH)], &peers);
        // Named set populated with the network's peer IPs. The set name is built from the ids, so
        // it needs no sanitizing and cannot collide with another network's.
        assert!(rs.contains("add set inet unitylan net_900100_7001 { type ipv4_addr ; }"));
        assert!(rs.contains("add element inet unitylan net_900100_7001 { 100.64.0.2, 100.64.0.3 }"));
        // Port scoped to that set.
        assert!(rs.contains("ip saddr @net_900100_7001 tcp dport 9001 accept"));
        // Not a global port accept.
        assert!(!rs.contains("tcp dport { 9001 } accept"));
    }

    #[test]
    fn cgnat_conflict_flags_tailscale_drop_but_not_our_own_ruleset() {
        // Tailscale's anti-spoof rule blackholes the mesh range on non-tailscale interfaces.
        let ts = r#"chain ts-input {
            iifname != "tailscale0*" ip saddr 100.64.0.0/10 counter packets 289 bytes 33404 drop
        }"#;
        assert!(cgnat_conflict(ts).unwrap().contains("drop"));

        // Our own ruleset drops with a bare verdict (no CGNAT match) → no false positive.
        let ours = ruleset(
            "unl0",
            &[exp(Proto::Tcp, 25565, ExposeScope::AllPeers)],
            &PeerSets::default(),
        );
        assert!(cgnat_conflict(&ours).is_none());

        // A benign accept referencing the range must not trip it either.
        assert!(cgnat_conflict("ip saddr 100.64.0.0/10 accept").is_none());
    }

    #[test]
    fn scoped_expose_with_no_peers_still_defines_empty_set() {
        let rs = ruleset("unl0", &[exp(Proto::Tcp, 9001, MESH)], &PeerSets::default());
        assert!(rs.contains("add set inet unitylan net_900100_7001 { type ipv4_addr ; }"));
        assert!(!rs.contains("add element")); // no IPs → no elements, port reachable by nobody
        assert!(rs.contains("ip saddr @net_900100_7001 tcp dport 9001 accept"));
    }

    /// The own-device scope gets its own source set, fed from the owner's devices rather than any
    /// network. Set names come from ids now, so a role *named* like the own-device set cannot
    /// collide with it either.
    #[test]
    fn own_device_scope_has_its_own_set_that_a_role_name_cannot_collide_with() {
        let peers = PeerSets {
            nets: vec![NetInfo {
                guild_id: 900_100,
                role_id: 7001,
                guild: "acme".into(),
                name: "own devices".into(),
                ips: vec![Ipv4Addr::new(100, 64, 0, 9)],
            }],
            own_devices: vec![Ipv4Addr::new(100, 64, 0, 2)],
        };
        let rs = ruleset(
            "unl0",
            &[
                exp(Proto::Tcp, 9001, ExposeScope::OwnDevices),
                exp(Proto::Tcp, 9002, MESH),
            ],
            &peers,
        );
        assert!(rs.contains("add element inet unitylan own_devices { 100.64.0.2 }"));
        assert!(rs.contains("add element inet unitylan net_900100_7001 { 100.64.0.9 }"));
        assert!(rs.contains("ip saddr @own_devices tcp dport 9001 accept"));
        assert!(rs.contains("ip saddr @net_900100_7001 tcp dport 9002 accept"));
    }
}
