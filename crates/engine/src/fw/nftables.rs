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

// The mesh addresses live in `100.64.0.0/10` (RFC 6598 / CGNAT). Tailscale — and potentially other
// tools that share this range — install an nftables anti-spoof rule that DROPs any packet whose
// source is in that block when it arrives on a non-Tailscale interface. That rule silently
// blackholes *all* UnityLAN traffic on the wg interface (a `drop` in any base chain wins over our
// `accept`), so peers appear reachable in the coordinator yet every ping is lost.

/// Marks the exemption rule we insert into the *foreign* chain, so we can find it again to avoid
/// duplicates and to remove it on teardown. It is the only handle we have on a rule that isn't ours.
const COMPAT_COMMENT: &str = "unitylan-cgnat-compat";

/// A foreign rule that blackholes the mesh range, and the chain it lives in — we need the location
/// to insert our exemption ahead of it.
#[derive(Debug, PartialEq)]
struct CgnatConflict {
    family: String,
    table: String,
    chain: String,
    rule: String,
}

/// Heuristic: an `nft` rule that both drops/rejects and references the CGNAT block, outside our own
/// table (our default-deny is a bare `drop`, so it never matches). Walks the ruleset tracking the
/// enclosing `table`/`chain` so the caller knows where to insert the exemption.
fn cgnat_conflict(ruleset: &str) -> Option<CgnatConflict> {
    let (mut family, mut table, mut chain) = (String::new(), String::new(), String::new());
    for line in ruleset.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("table ") {
            let mut it = rest.split_whitespace();
            family = it.next().unwrap_or_default().to_string();
            table = it.next().unwrap_or_default().to_string();
        } else if let Some(rest) = l.strip_prefix("chain ") {
            chain = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
        } else if (l.contains("drop") || l.contains("reject")) && l.contains("100.64.0.0/10") {
            return Some(CgnatConflict {
                family: family.clone(),
                table: table.clone(),
                chain: chain.clone(),
                rule: l.to_string(),
            });
        }
    }
    None
}

/// One exemption we want present in the foreign chain: the `nft` arguments that create it, plus a
/// substring unique enough to recognise it again in `nft list` output.
struct CompatRule {
    args: Vec<String>,
    key: String,
}

/// The exemptions the foreign drop makes necessary.
///
/// Two are needed, because mesh traffic reaches us on two different interfaces:
///   * peer traffic arrives on the mesh interface itself;
///   * traffic we send to *our own* mesh address — the `.internal` resolver is the case that bit us
///     — is looped back by the kernel and arrives on `lo`, where an `iifname "unl0"` exemption
///     cannot match. Tailscale hits the identical problem with its own resolver and solves it the
///     same way, with an `ip saddr <its own addr> iifname "lo" accept` sitting just above the drop.
///
/// The loopback rule is scoped to our exact address rather than the whole CGNAT block, so it permits
/// no more than the one host's own traffic.
fn compat_rules(iface: &str, mesh_addr: Option<std::net::Ipv4Addr>) -> Vec<CompatRule> {
    let mut rules = vec![CompatRule {
        args: vec![
            "iifname".into(),
            iface.into(),
            "accept".into(),
            "comment".into(),
            COMPAT_COMMENT.into(),
        ],
        key: format!("iifname \"{iface}\""),
    }];
    if let Some(ip) = mesh_addr {
        rules.push(CompatRule {
            args: vec![
                "ip".into(),
                "saddr".into(),
                ip.to_string(),
                "iifname".into(),
                "lo".into(),
                "accept".into(),
                "comment".into(),
                COMPAT_COMMENT.into(),
            ],
            key: format!("ip saddr {ip} iifname \"lo\""),
        });
    }
    rules
}

/// Whether a given exemption is already installed (so we don't stack duplicates on every reconcile).
fn compat_present(ruleset: &str, key: &str) -> bool {
    ruleset
        .lines()
        .any(|l| l.contains(COMPAT_COMMENT) && l.contains(key))
}

/// Locate every exemption we previously inserted, with the coordinates `nft delete rule` needs.
/// Handles are listed newest-first so deleting in the returned order stays valid.
fn compat_handles(ruleset: &str) -> Vec<(String, String, String, String)> {
    let (mut family, mut table, mut chain) = (String::new(), String::new(), String::new());
    let mut found = Vec::new();
    for line in ruleset.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("table ") {
            let mut it = rest.split_whitespace();
            family = it.next().unwrap_or_default().to_string();
            table = it.next().unwrap_or_default().to_string();
        } else if let Some(rest) = l.strip_prefix("chain ") {
            chain = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
        } else if l.contains(COMPAT_COMMENT) {
            if let Some(h) = l.rsplit("# handle ").next() {
                found.push((
                    family.clone(),
                    table.clone(),
                    chain.clone(),
                    h.trim().to_string(),
                ));
            }
        }
    }
    found
}

fn nft_ruleset(args: &[&str]) -> Option<String> {
    let out = Command::new("nft").args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Scan the live ruleset for a foreign rule that would blackhole the mesh CGNAT range. When `auto`,
/// exempt our interface in that same chain; otherwise just warn with the manual remediation.
///
/// The exemption only re-permits what the foreign rule over-broadly dropped — our own `inet unitylan`
/// table still independently gates that traffic, so both must accept for a packet to land. Re-run on
/// every reconcile because the owner of that chain (Tailscale) rebuilds it on restart, silently
/// dropping our rule; the `compat_present` check keeps that idempotent.
///
/// Best-effort throughout: any `nft` failure degrades to the warning rather than failing the reconcile.
#[cfg(target_os = "linux")]
pub fn ensure_cgnat_compat(iface: &str, mesh_addr: Option<std::net::Ipv4Addr>, auto: bool) {
    let Some(ruleset) = nft_ruleset(&["list", "ruleset"]) else {
        return;
    };
    let Some(c) = cgnat_conflict(&ruleset) else {
        return;
    };
    let missing: Vec<CompatRule> = compat_rules(iface, mesh_addr)
        .into_iter()
        .filter(|r| !compat_present(&ruleset, &r.key))
        .collect();
    if missing.is_empty() {
        return;
    }
    let manual = missing
        .iter()
        .map(|r| {
            // Drop the trailing `comment <marker>` — that's our bookkeeping, not something a human
            // needs to type.
            let body: Vec<&str> = r
                .args
                .iter()
                .map(String::as_str)
                .take_while(|a| *a != "comment")
                .collect();
            format!(
                "nft insert rule {} {} {} {}",
                c.family,
                c.table,
                c.chain,
                body.join(" ")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    if !auto {
        tracing::warn!(
            offending_rule = %c.rule,
            "another firewall (likely Tailscale) drops the mesh range 100.64.0.0/10 on non-mesh \
             interfaces; UnityLAN traffic on {iface} will be silently blackholed. Exempt it: \
             `{manual}` (or set tailscale_compat = true to do this automatically)"
        );
        return;
    }
    let mut inserted = 0usize;
    for r in &missing {
        // Built as argv, never a shell string, so nothing here is subject to quoting.
        let ok = Command::new("nft")
            .args(["insert", "rule", &c.family, &c.table, &c.chain])
            .args(&r.args)
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            inserted += 1;
        }
    }
    if inserted == missing.len() {
        tracing::info!(
            offending_rule = %c.rule,
            "another firewall (likely Tailscale) drops the mesh range 100.64.0.0/10 on non-mesh \
             interfaces; inserted {inserted} exemption(s) for {iface} in {} {} {} (removed on \
             shutdown; set tailscale_compat = false to manage this yourself)",
            c.family, c.table, c.chain
        );
    } else {
        tracing::warn!(
            offending_rule = %c.rule,
            "another firewall (likely Tailscale) drops the mesh range 100.64.0.0/10 on non-mesh \
             interfaces and the automatic exemption failed; UnityLAN traffic on {iface} will be \
             silently blackholed. Run: `{manual}`"
        );
    }
}

/// Remove every exemption we inserted into the foreign chain. Called on teardown — those rules are
/// not in our table, so nothing else would ever clean them up.
#[cfg(target_os = "linux")]
pub fn remove_cgnat_compat() {
    let Some(ruleset) = nft_ruleset(&["-a", "list", "ruleset"]) else {
        return;
    };
    for (family, table, chain, handle) in compat_handles(&ruleset) {
        let _ = Command::new("nft")
            .args(["delete", "rule", &family, &table, &chain, "handle", &handle])
            .status();
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

    /// A realistic slice of `nft list ruleset` with Tailscale's anti-spoof rule in place.
    const TS_RULESET: &str = r#"table ip filter {
	chain ts-input {
		iifname "lo" accept
		iifname != "tailscale0" ip saddr 100.64.0.0/10 counter packets 289 bytes 33404 drop
	}
}"#;

    #[test]
    fn cgnat_conflict_flags_tailscale_drop_but_not_our_own_ruleset() {
        // Tailscale's anti-spoof rule blackholes the mesh range on non-tailscale interfaces.
        let c = cgnat_conflict(TS_RULESET).expect("detects the drop");
        assert!(c.rule.contains("drop"));

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

    /// The auto-fix inserts into someone else's chain, so it has to locate that chain exactly —
    /// a wrong family/table/chain either errors or lands the exemption where it does nothing.
    #[test]
    fn cgnat_conflict_reports_the_enclosing_chain() {
        let c = cgnat_conflict(TS_RULESET).expect("detects the drop");
        assert_eq!(c.family, "ip");
        assert_eq!(c.table, "filter");
        assert_eq!(c.chain, "ts-input");
    }

    /// Idempotency: the reconcile re-runs constantly, and a per-reconcile duplicate would stack
    /// exemptions in a foreign chain without bound.
    #[test]
    fn compat_rule_is_detected_only_for_its_own_interface() {
        let installed = r#"table ip filter {
	chain ts-input {
		iifname "unl0" accept comment "unitylan-cgnat-compat"
		iifname != "tailscale0" ip saddr 100.64.0.0/10 counter drop
	}
}"#;
        assert!(compat_present(installed, "iifname \"unl0\""));
        // A different interface's exemption is not ours.
        assert!(!compat_present(installed, "iifname \"unl1\""));
        assert!(!compat_present(TS_RULESET, "iifname \"unl0\""));
    }

    /// Traffic to our *own* mesh address loops back on `lo`, so an interface-scoped exemption never
    /// matches it — which is how the `.internal` resolver ended up silently blackholed while ping
    /// worked. The loopback rule is scoped to this host's address, not the whole CGNAT block.
    #[test]
    fn compat_rules_cover_loopback_to_our_own_mesh_address() {
        let addr: std::net::Ipv4Addr = "100.73.208.187".parse().unwrap();
        let rules = compat_rules("unl0", Some(addr));
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].key, "ip saddr 100.73.208.187 iifname \"lo\"");
        assert_eq!(
            rules[1].args,
            vec![
                "ip",
                "saddr",
                "100.73.208.187",
                "iifname",
                "lo",
                "accept",
                "comment",
                COMPAT_COMMENT
            ]
        );
        // Not the whole /10 — only this host's own traffic is re-permitted.
        assert!(!rules[1].args.iter().any(|a| a.contains("/10")));
        // Before the interface has an address there is nothing to scope to, so just the iface rule.
        assert_eq!(compat_rules("unl0", None).len(), 1);
    }

    /// Teardown must find *every* rule it inserted, or one outlives the engine in a foreign chain.
    #[test]
    fn compat_handles_locate_all_our_rules_for_deletion() {
        let listed = r#"table ip filter {
	chain ts-input {
		iifname "unl0" accept comment "unitylan-cgnat-compat" # handle 42
		ip saddr 100.73.208.187 iifname "lo" accept comment "unitylan-cgnat-compat" # handle 43
		iifname != "tailscale0" ip saddr 100.64.0.0/10 counter drop # handle 7
	}
}"#;
        let found = compat_handles(listed);
        assert_eq!(found.len(), 2);
        for (family, table, chain, _) in &found {
            assert_eq!(
                (family.as_str(), table.as_str(), chain.as_str()),
                ("ip", "filter", "ts-input")
            );
        }
        let handles: Vec<&str> = found.iter().map(|(_, _, _, h)| h.as_str()).collect();
        assert_eq!(handles, vec!["42", "43"]);
        // Never claims a rule that isn't ours — the drop must survive.
        assert!(compat_handles(TS_RULESET).is_empty());
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
