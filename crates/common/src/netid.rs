//! Addressing math (design.md §6, Model B): one flat `/32` per **device**, allocated from the
//! coordinator's mesh CIDR (default a `/16` within 100.64.0.0/10, see [`default_cidr`]), keyed by
//! the device's WG public key. Networks are pure ACL groups — they no longer carve out subnets.
//! Plus DNS-label sanitize.

use std::collections::BTreeSet;
use std::hash::Hasher;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use siphasher::sip::SipHasher13;

/// Default mesh CIDR prefix: a `/16` (65 534 usable devices) carved out of the CGNAT range by
/// [`default_cidr`]. Small enough that up to 64 deployments get disjoint blocks by hashing.
pub const DEFAULT_PREFIX: u8 = 16;

// Fixed SipHash keys → deterministic, cross-platform, stable hashing.
const K0: u64 = 0x554e_4954_594c_414e; // "UNITYLAN"
const K1: u64 = 0x5745_4741_5245_4144; // "WEGAREAD"

fn sip_bytes(bytes: &[u8]) -> u64 {
    let mut h = SipHasher13::new_with_keys(K0, K1);
    h.write(bytes);
    h.finish()
}

/// The number of host indices in `net`, i.e. `2^(32 - prefix)`. Index 0 (network) and the last
/// index (broadcast) are reserved, so allocatable indices are `1..host_count(net) - 1`.
fn host_count(net: &Ipv4Net) -> u32 {
    1u32 << (32 - net.prefix_len())
}

/// The default mesh CIDR for a deployment: a `/16` inside 100.64.0.0/10, chosen deterministically
/// from the coordinator's trust anchor. Two deployments get disjoint blocks unless their anchors
/// collide mod 64 (~1.6% for two, degrading to switch-between rather than a routing conflict). The
/// anchor is stable per deployment, so the block is stable, so allocated indices stay valid.
pub fn default_cidr(anchor: &[u8; 32]) -> Ipv4Net {
    // 100.64.0.0/10 spans second-octet 64..=127 → 64 candidate /16 blocks.
    let block = (sip_bytes(anchor) % 64) as u8;
    Ipv4Net::new(Ipv4Addr::new(100, 64 + block, 0, 0), DEFAULT_PREFIX).expect("valid /16")
}

/// Whether two IPv4 networks share any address (either contains the other's network address).
pub fn nets_overlap(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// A deterministic first-choice host index (`1..host_count-1`) for a device within `net`, derived
/// from its WG public key. The coordinator is the authority and resolves collisions; this is the
/// hint.
pub fn device_hint(net: &Ipv4Net, wg_pubkey: &[u8; 32]) -> u32 {
    // `host_count - 2` allocatable slots (index 0 and the last are reserved), offset by 1.
    (sip_bytes(wg_pubkey) % (host_count(net) as u64 - 2)) as u32 + 1
}

/// Turn a host index (`1..host_count-1`) into its address within `net`.
pub fn addr_from_index(net: &Ipv4Net, index: u32) -> Ipv4Addr {
    debug_assert!(index >= 1 && index < host_count(net) - 1);
    Ipv4Addr::from(u32::from(net.network()) + index)
}

/// Pick a free host index in `1..host_count-1`, starting at `hint` and probing upward (wrapping).
/// Returns `None` only if `net`'s addresses are exhausted.
pub fn pick_free_index(net: &Ipv4Net, taken: &BTreeSet<u32>, hint: u32) -> Option<u32> {
    let last = host_count(net) - 2; // highest allocatable index (broadcast reserved)
    let mut idx = hint.clamp(1, last);
    for _ in 0..last {
        if !taken.contains(&idx) {
            return Some(idx);
        }
        idx = if idx >= last { 1 } else { idx + 1 };
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
        out.push_str("device");
    }
    out.truncate(63);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    #[test]
    fn addr_within_configured_range() {
        let n = net("100.72.0.0/16");
        for idx in [1u32, 2, 255, 4242, host_count(&n) - 2] {
            let addr = addr_from_index(&n, idx);
            assert!(n.contains(&addr), "{addr} (idx {idx}) not in {n}");
        }
    }

    #[test]
    fn default_cidr_is_in_cgnat_and_a_16() {
        let cgnat: Ipv4Net = "100.64.0.0/10".parse().unwrap();
        let n = default_cidr(&[7u8; 32]);
        assert_eq!(n.prefix_len(), 16);
        assert!(cgnat.contains(&n.network()), "{n} not in 100.64/10");
        // Deterministic.
        assert_eq!(n, default_cidr(&[7u8; 32]));
    }

    #[test]
    fn different_anchors_usually_get_different_blocks() {
        assert_ne!(default_cidr(&[1u8; 32]), default_cidr(&[2u8; 32]));
    }

    #[test]
    fn overlap_detection() {
        assert!(nets_overlap(&net("100.64.0.0/16"), &net("100.64.0.0/24")));
        assert!(nets_overlap(&net("192.168.0.0/16"), &net("192.168.1.0/24")));
        assert!(!nets_overlap(&net("100.64.0.0/16"), &net("100.65.0.0/16")));
        assert!(!nets_overlap(&net("10.0.0.0/8"), &net("192.168.1.0/24")));
    }

    #[test]
    fn hint_is_deterministic_and_in_range() {
        let n = net("100.72.0.0/16");
        let key = [7u8; 32];
        let a = device_hint(&n, &key);
        assert_eq!(a, device_hint(&n, &key));
        assert!((1..host_count(&n) - 1).contains(&a));
    }

    #[test]
    fn different_keys_usually_differ() {
        let n = net("100.72.0.0/16");
        assert_ne!(device_hint(&n, &[1u8; 32]), device_hint(&n, &[2u8; 32]));
    }

    #[test]
    fn pick_free_probes() {
        let n = net("100.72.0.0/16");
        let empty = BTreeSet::new();
        assert_eq!(pick_free_index(&n, &empty, 7), Some(7));

        let mut taken = BTreeSet::new();
        taken.insert(7u32);
        taken.insert(8u32);
        assert_eq!(pick_free_index(&n, &taken, 7), Some(9));
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_label("Alice 🌸"), "alice");
        assert_eq!(sanitize_label("My Community!"), "my-community");
        assert_eq!(sanitize_label("__weird..name__"), "weird-name");
        assert_eq!(sanitize_label(""), "device");
    }
}
