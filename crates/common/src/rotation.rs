//! Coordinator trust-anchor rotation (design.md §9).
//!
//! The anchor is TOFU-pinned by clients, so a bare key change is indistinguishable from a MITM.
//! To rotate without every client re-pinning by hand, the **old key signs the new one**: each
//! rotation emits a [`RotationCert`] (`prev → new`) signed by `prev`. A client pinned at some
//! earlier anchor walks the ordered chain of certs from its pin to the coordinator's current
//! anchor, verifying every hop's signature under the key it already trusts — so trust extends one
//! provable step at a time, rooted at the pin. A gap the chain can't bridge falls back to a manual
//! re-pin (the old key was lost/compromised and could sign nothing): MITM protection is preserved.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::crypto::anchor_from_bytes;
use crate::wire::Signed;

/// One rotation hop: the coordinator moved its anchor from `prev_anchor` to `new_anchor`. Signed
/// by `prev_anchor`'s key (the outgoing key vouches for its successor).
///
/// **This layout is frozen.** Unlike [`crate::attestation::Attestation`] — which carries a schema
/// tag and can afford to break it, since its blobs expire in 30 minutes — rotation certs are
/// long-lived by design: a client pinned years ago walks the whole chain from its pin forward, so
/// every cert ever issued must still decode. Postcard is positional, so adding, removing, or
/// reordering a field here silently breaks that walk and strands clients on a manual re-pin. If this
/// ever must change, it needs a parallel type and a chain that carries both, not an edit in place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationCert {
    pub prev_anchor: [u8; 32],
    pub new_anchor: [u8; 32],
    pub issued_at: u64,
}

/// The longest rotation chain we'll walk. Each hop re-scans the whole chain (`advance` is O(len)),
/// so the walk is O(len²) Ed25519 verifies — a semi-trusted or MITM'd coordinator could otherwise
/// hand a client a giant chain purely to burn its CPU. A real deployment rotates its anchor rarely;
/// dozens of hops is already implausible, so refusing past this bounds the work at ~64² verifies.
const MAX_ROTATION_CHAIN: usize = 64;

/// Can we extend trust from `pinned` to `target` through `chain`? Starting at the pinned anchor,
/// repeatedly find a cert **signed by the current anchor** advancing it (`prev == current`), until
/// we reach `target`. Each hop is verified cryptographically under the key we already trust, so an
/// attacker without a legitimately-signed successor can't bridge the gap. `chain` is the coordinator's
/// certs oldest→newest, but the walk doesn't rely on their order. Bounded by `chain.len()` hops so a
/// cyclic/forged set can't loop forever, and refused outright past [`MAX_ROTATION_CHAIN`] certs so an
/// oversized chain can't burn CPU. `true` ⇒ the caller may re-pin to `target`.
pub fn walk_chain(pinned: [u8; 32], target: [u8; 32], chain: &[Signed]) -> bool {
    if chain.len() > MAX_ROTATION_CHAIN {
        return false;
    }
    let mut current = pinned;
    // At most one legitimate hop per cert; the bound also caps any adversarial cycle.
    for _ in 0..=chain.len() {
        if current == target {
            return true;
        }
        let Ok(current_key) = anchor_from_bytes(&current) else {
            return false;
        };
        let Some(next) = advance(&current_key, current, chain) else {
            return false; // no cert signed by `current` continues the chain → gap
        };
        current = next;
    }
    current == target
}

/// The anchor `current` vouches for next, if any cert in `chain` is signed by `current` and names
/// it as `prev_anchor`. Verifying under `current_key` is the real check; the `prev_anchor` field
/// match guards against a misfiled cert.
fn advance(current_key: &VerifyingKey, current: [u8; 32], chain: &[Signed]) -> Option<[u8; 32]> {
    for signed in chain {
        if let Ok(cert) = signed.verify::<RotationCert>(current_key) {
            if cert.prev_anchor == current {
                return Some(cert.new_anchor);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CoordinatorKey;

    /// Sign a `prev → new` cert with `prev`'s key.
    fn cert(prev: &CoordinatorKey, new: &CoordinatorKey) -> Signed {
        Signed::sign(
            prev,
            &RotationCert {
                prev_anchor: prev.anchor_bytes(),
                new_anchor: new.anchor_bytes(),
                issued_at: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn same_anchor_needs_no_chain() {
        let a = CoordinatorKey::generate();
        assert!(walk_chain(a.anchor_bytes(), a.anchor_bytes(), &[]));
    }

    #[test]
    fn walks_multiple_hops() {
        let (a, b, c) = (
            CoordinatorKey::generate(),
            CoordinatorKey::generate(),
            CoordinatorKey::generate(),
        );
        let chain = vec![cert(&a, &b), cert(&b, &c)];
        // A pinned client reaches C via A→B→C.
        assert!(walk_chain(a.anchor_bytes(), c.anchor_bytes(), &chain));
        // A B-pinned client reaches C in one hop.
        assert!(walk_chain(b.anchor_bytes(), c.anchor_bytes(), &chain));
    }

    #[test]
    fn rejects_when_chain_cannot_bridge() {
        let (a, b, c) = (
            CoordinatorKey::generate(),
            CoordinatorKey::generate(),
            CoordinatorKey::generate(),
        );
        // Only B→C is retained; a client pinned at A can't get there.
        let chain = vec![cert(&b, &c)];
        assert!(!walk_chain(a.anchor_bytes(), c.anchor_bytes(), &chain));
    }

    #[test]
    fn rejects_forged_cert_signed_by_untrusted_key() {
        let (a, b, attacker) = (
            CoordinatorKey::generate(),
            CoordinatorKey::generate(),
            CoordinatorKey::generate(),
        );
        // Attacker forges A→B but signs with their OWN key, not A's. Verification under A fails.
        let forged = Signed::sign(
            &attacker,
            &RotationCert {
                prev_anchor: a.anchor_bytes(),
                new_anchor: b.anchor_bytes(),
                issued_at: 0,
            },
        )
        .unwrap();
        assert!(!walk_chain(a.anchor_bytes(), b.anchor_bytes(), &[forged]));
    }

    #[test]
    fn rejects_rollback_to_older_anchor() {
        let (a, b) = (CoordinatorKey::generate(), CoordinatorKey::generate());
        // Chain only advances A→B; walking B back to A must fail (no B→A cert).
        let chain = vec![cert(&a, &b)];
        assert!(!walk_chain(b.anchor_bytes(), a.anchor_bytes(), &chain));
    }

    #[test]
    fn rejects_chain_past_the_length_cap() {
        // A genuinely-signed path of MAX+1 hops is refused before any verification, so an oversized
        // chain can't force the O(len²) walk. One hop under the cap still resolves.
        let keys: Vec<_> = (0..=MAX_ROTATION_CHAIN + 1)
            .map(|_| CoordinatorKey::generate())
            .collect();
        let chain: Vec<Signed> = keys.windows(2).map(|w| cert(&w[0], &w[1])).collect();
        let start = keys.first().unwrap().anchor_bytes();
        let end = keys.last().unwrap().anchor_bytes();
        assert!(chain.len() > MAX_ROTATION_CHAIN);
        assert!(!walk_chain(start, end, &chain));
        // Trim to exactly the cap: the same-shaped path now walks.
        assert!(walk_chain(
            start,
            keys[MAX_ROTATION_CHAIN].anchor_bytes(),
            &chain[..MAX_ROTATION_CHAIN]
        ));
    }
}
