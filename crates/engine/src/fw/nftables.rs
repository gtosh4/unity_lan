//! Linux nftables firewall backend. Renders the whole `inet unitylan` table and pipes it to
//! `nft -f -` in one atomic load, so the ruleset is always a pure function of the exposed set.

use std::io::Write;
use std::process::{Command, Stdio};

use common::control::Proto;

use super::{Exposed, FirewallBackend};

pub struct NftBackend;

const TABLE: &str = "inet unitylan";

impl FirewallBackend for NftBackend {
    fn apply(&self, iface: &str, exposed: &[Exposed]) -> anyhow::Result<()> {
        run_nft(&ruleset(iface, exposed))
    }

    fn reset(&self) -> anyhow::Result<()> {
        // `add` first so the following `delete` never fails on a missing table.
        run_nft(&format!("add table {TABLE}\ndelete table {TABLE}\n"))
    }
}

/// Build the nft script. Only `iif <iface>` traffic is policed; everything else is accepted so
/// the host's other interfaces are untouched.
fn ruleset(iface: &str, exposed: &[Exposed]) -> String {
    let mut s = String::new();
    // Atomic replace: ensure the table exists, drop it, recreate empty.
    s.push_str(&format!("add table {TABLE}\n"));
    s.push_str(&format!("delete table {TABLE}\n"));
    s.push_str(&format!("add table {TABLE}\n"));
    s.push_str(&format!(
        "add chain {TABLE} input {{ type filter hook input priority 0 ; policy accept ; }}\n"
    ));
    // Leave non-wg interfaces alone.
    s.push_str(&format!("add rule {TABLE} input iifname != \"{iface}\" accept\n"));
    // Return traffic for our own outbound connections.
    s.push_str(&format!("add rule {TABLE} input ct state established,related accept\n"));
    // Ping: liveness/diagnostics only, so allowed by default.
    s.push_str(&format!("add rule {TABLE} input icmp type echo-request accept\n"));
    // Exposed ports (from any peer — only peers can reach the wg iface at all).
    let tcp = ports(exposed, Proto::Tcp);
    let udp = ports(exposed, Proto::Udp);
    if !tcp.is_empty() {
        s.push_str(&format!("add rule {TABLE} input tcp dport {{ {tcp} }} accept\n"));
    }
    if !udp.is_empty() {
        s.push_str(&format!("add rule {TABLE} input udp dport {{ {udp} }} accept\n"));
    }
    // Everything else arriving on the wg iface is denied.
    s.push_str(&format!("add rule {TABLE} input drop\n"));
    s
}

fn ports(exposed: &[Exposed], proto: Proto) -> String {
    exposed
        .iter()
        .filter(|e| e.proto == proto)
        .map(|e| e.port.to_string())
        .collect::<Vec<_>>()
        .join(", ")
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
    use super::*;

    #[test]
    fn ruleset_has_default_deny_and_exposed_ports() {
        let rs = ruleset(
            "unl0",
            &[
                Exposed { proto: Proto::Tcp, port: 25565 },
                Exposed { proto: Proto::Udp, port: 34197 },
            ],
        );
        // Base policy.
        assert!(rs.contains("iifname != \"unl0\" accept"));
        assert!(rs.contains("ct state established,related accept"));
        assert!(rs.contains("icmp type echo-request accept"));
        // Exposed ports, per proto.
        assert!(rs.contains("tcp dport { 25565 } accept"));
        assert!(rs.contains("udp dport { 34197 } accept"));
        // Default-deny is the last rule.
        assert!(rs.trim_end().ends_with("input drop"));
    }

    #[test]
    fn no_exposed_ports_still_default_denies() {
        let rs = ruleset("unl0", &[]);
        assert!(!rs.contains("dport"));
        assert!(rs.contains("input drop"));
    }
}
