//! Addressing math (design.md §6): subnet-per-network, host allocation, DNS-label sanitize.

use std::hash::Hasher;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use siphasher::sip::SipHasher13;

/// Reserved range: 100.64.0.0/10 (RFC 6598 / CGNAT), avoids home-LAN collisions.
const BASE: u32 = 0x6440_0000; // 100.64.0.0
/// Number of /24 subnets in a /10: 2^(22-8) = 16384.
const SUBNET_COUNT: u32 = 1 << 14;

// Fixed SipHash keys → deterministic, cross-platform, stable hashing.
const K0: u64 = 0x554e_4954_594c_414e; // "UNITYLAN"
const K1: u64 = 0x5745_4741_5245_4144; // "WEGAREAD"

fn sip(parts: &[u64]) -> u64 {
    let mut h = SipHasher13::new_with_keys(K0, K1);
    for p in parts {
        h.write_u64(*p);
    }
    h.finish()
}

/// The /24 subnet for a network `(guild_id, role_id)` within 100.64.0.0/10.
pub fn subnet_of(guild_id: u64, role_id: u64) -> Ipv4Net {
    let idx = (sip(&[guild_id, role_id]) % SUBNET_COUNT as u64) as u32; // 0..16383, 14 bits
    let addr = BASE | (idx << 8); // idx occupies bits [8, 22)
    Ipv4Net::new(Ipv4Addr::from(addr), 24).expect("prefix 24 is valid")
}

/// A deterministic first-choice host octet (`.2`..=`.254`) for a user in a network.
/// The coordinator is the authority and resolves collisions; this is just the hint.
pub fn host_hint(user_id: u64) -> u8 {
    (sip(&[user_id]) % 253) as u8 + 2
}

/// Combine a /24 subnet with a host octet into a concrete address.
pub fn host_addr(subnet: Ipv4Net, host: u8) -> Ipv4Addr {
    let base = u32::from(subnet.network());
    Ipv4Addr::from((base & 0xFFFF_FF00) | host as u32)
}

/// Pick a free host octet in `.2..=.254`, starting at `hint` and probing upward (wrapping).
/// Returns `None` if the /24 is full.
pub fn pick_free_host(taken: &std::collections::BTreeSet<u8>, hint: u8) -> Option<u8> {
    let mut host = hint.clamp(2, 254);
    for _ in 0..253 {
        if !taken.contains(&host) {
            return Some(host);
        }
        host = if host >= 254 { 2 } else { host + 1 };
    }
    None
}

/// Lower-case, collapse to `[a-z0-9-]`, trim dashes, cap at a DNS label's 63 chars.
pub fn sanitize_label(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for c in s.chars() {
        let lc = c.to_ascii_lowercase();
        if lc.is_ascii_alphanumeric() {
            out.push(lc);
            prev_dash = false;
        } else if !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("user");
    }
    out.truncate(63);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_within_cgnat_range() {
        let cgnat: Ipv4Net = "100.64.0.0/10".parse().unwrap();
        for (g, r) in [(1u64, 2u64), (999, 1), (u64::MAX, 0), (42, 4242)] {
            let net = subnet_of(g, r);
            assert_eq!(net.prefix_len(), 24);
            assert!(cgnat.contains(&net.network()), "{net} not in 100.64/10");
        }
    }

    #[test]
    fn subnet_is_deterministic() {
        assert_eq!(subnet_of(10, 20), subnet_of(10, 20));
    }

    #[test]
    fn different_networks_usually_differ() {
        assert_ne!(subnet_of(1, 1), subnet_of(1, 2));
    }

    #[test]
    fn host_hint_in_range() {
        for u in 0..1000u64 {
            let h = host_hint(u);
            assert!((2..=254).contains(&h));
        }
    }

    #[test]
    fn host_addr_composes() {
        let net = subnet_of(5, 6);
        let addr = host_addr(net, 7);
        assert!(net.contains(&addr));
        assert_eq!(addr.octets()[3], 7);
    }

    #[test]
    fn pick_free_host_probes() {
        use std::collections::BTreeSet;
        let empty = BTreeSet::new();
        assert_eq!(pick_free_host(&empty, 7), Some(7));

        let mut taken = BTreeSet::new();
        taken.insert(7u8);
        taken.insert(8u8);
        assert_eq!(pick_free_host(&taken, 7), Some(9));

        let full: BTreeSet<u8> = (2..=254).collect();
        assert_eq!(pick_free_host(&full, 7), None);
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_label("Alice 🌸"), "alice");
        assert_eq!(sanitize_label("My Community!"), "my-community");
        assert_eq!(sanitize_label("__weird..name__"), "weird-name");
        assert_eq!(sanitize_label(""), "user");
    }
}
