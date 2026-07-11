//! Addressing math (design.md §6, Model B): one flat `/32` per **device** in 100.64.0.0/10,
//! keyed by the device's WG public key. Networks are pure ACL groups — they no longer carve
//! out subnets. Plus DNS-label sanitize.

use std::collections::BTreeSet;
use std::hash::Hasher;
use std::net::Ipv4Addr;

use siphasher::sip::SipHasher13;

/// Reserved range: 100.64.0.0/10 (RFC 6598 / CGNAT), avoids home-LAN collisions.
const BASE: u32 = 0x6440_0000; // 100.64.0.0
/// Host bits in a /10 → 2^22 addresses.
const HOST_BITS: u32 = 22;
/// Number of addressable host indices (0 reserved as the network address).
const HOST_COUNT: u32 = 1 << HOST_BITS;

// Fixed SipHash keys → deterministic, cross-platform, stable hashing.
const K0: u64 = 0x554e_4954_594c_414e; // "UNITYLAN"
const K1: u64 = 0x5745_4741_5245_4144; // "WEGAREAD"

fn sip_bytes(bytes: &[u8]) -> u64 {
    let mut h = SipHasher13::new_with_keys(K0, K1);
    h.write(bytes);
    h.finish()
}

/// A deterministic first-choice host index (`1..HOST_COUNT`) for a device, derived from its
/// WG public key. The coordinator is the authority and resolves collisions; this is the hint.
pub fn device_hint(wg_pubkey: &[u8; 32]) -> u32 {
    (sip_bytes(wg_pubkey) % (HOST_COUNT as u64 - 1)) as u32 + 1
}

/// Turn a host index (`1..HOST_COUNT`) into its address within 100.64.0.0/10.
pub fn addr_from_index(index: u32) -> Ipv4Addr {
    debug_assert!(index < HOST_COUNT);
    Ipv4Addr::from(BASE | (index & (HOST_COUNT - 1)))
}

/// Pick a free host index in `1..HOST_COUNT`, starting at `hint` and probing upward (wrapping).
/// Returns `None` only if the entire /10 is exhausted (4M devices).
pub fn pick_free_index(taken: &BTreeSet<u32>, hint: u32) -> Option<u32> {
    let mut idx = hint.clamp(1, HOST_COUNT - 1);
    for _ in 0..(HOST_COUNT - 1) {
        if !taken.contains(&idx) {
            return Some(idx);
        }
        idx = if idx >= HOST_COUNT - 1 { 1 } else { idx + 1 };
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

    #[test]
    fn addr_within_cgnat_range() {
        let cgnat: ipnet::Ipv4Net = "100.64.0.0/10".parse().unwrap();
        for idx in [1u32, 2, 255, 4242, HOST_COUNT - 1] {
            let addr = addr_from_index(idx);
            assert!(cgnat.contains(&addr), "{addr} (idx {idx}) not in 100.64/10");
        }
    }

    #[test]
    fn hint_is_deterministic_and_in_range() {
        let key = [7u8; 32];
        let a = device_hint(&key);
        assert_eq!(a, device_hint(&key));
        assert!((1..HOST_COUNT).contains(&a));
    }

    #[test]
    fn different_keys_usually_differ() {
        assert_ne!(device_hint(&[1u8; 32]), device_hint(&[2u8; 32]));
    }

    #[test]
    fn pick_free_probes() {
        let empty = BTreeSet::new();
        assert_eq!(pick_free_index(&empty, 7), Some(7));

        let mut taken = BTreeSet::new();
        taken.insert(7u32);
        taken.insert(8u32);
        assert_eq!(pick_free_index(&taken, 7), Some(9));
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_label("Alice 🌸"), "alice");
        assert_eq!(sanitize_label("My Community!"), "my-community");
        assert_eq!(sanitize_label("__weird..name__"), "weird-name");
        assert_eq!(sanitize_label(""), "device");
    }
}
