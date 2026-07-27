//! Named services: a memorable name for a port a device serves.
//!
//! A service is an exposed port with a **name**, and the name resolves under its owner's user label
//! — `mc.alice.unity.internal` reaches whichever of Alice's devices serves `mc`. That is the whole
//! feature: `jellyfin.alice` and `mc.alice` instead of a port number on a hostname nobody recalls.
//!
//! **Peer-direct, not coordinator-registered.** A device announces its own services over the tunnel
//! ([`crate::p2p::ReqBody::GetServices`]); the coordinator holds no service state and never sees one.
//! That is safe because of where the name is *composed*: a receiver builds `<label>.<peer's own user
//! label>`, and the peer's user label comes from its verified attestation, not from the peer. So a
//! peer cannot express a name outside its owner's namespace — the property the coordinator enforces
//! by derivation for hostnames holds here structurally.
//!
//! Two devices of the *same* owner can still both claim `mc`. That is a genuine conflict rather than
//! an attack, and every device resolves it identically — see the engine's `mesh_services::resolve`.

use serde::{Deserialize, Serialize};

use crate::control::Proto;

/// Longest service label. Short because it is the part a person types and says out loud, and
/// because it shares a DNS label with nothing else.
pub const MAX_LABEL_LEN: usize = 24;

/// How many services one device may announce. Bounds what a peer can make every other device hold
/// in memory and answer DNS for; far above what a home server actually runs.
pub const MAX_SERVICES_PER_DEVICE: usize = 16;

/// Whether `label` is usable as the leftmost DNS label of a service name.
///
/// Deliberately stricter than DNS: lower-case only (a name is compared, cached and displayed in one
/// canonical form), no leading or trailing dash, and never all-numeric — `8080.alice` reads as an
/// address and resolves as a name, which is a confusion not worth allowing.
pub fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
        && !label.bytes().all(|b| b.is_ascii_digit())
}

/// Why a label was refused, phrased for the person who typed it.
pub fn label_error(label: &str) -> String {
    format!(
        "{label:?} is not a usable service name: use lower-case letters, digits and dashes \
         (at most {MAX_LABEL_LEN}), not starting or ending with a dash, and not only digits"
    )
}

/// A service as announced to peers: the label, and where it listens.
///
/// The scope is deliberately absent. A device answers [`crate::p2p::ReqBody::GetServices`] only to
/// peers that may reach the service, so who-can-see-it is enforced where the data lives rather than
/// shipped to every peer to enforce for itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshService {
    pub name: String,
    pub proto: Proto,
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_dns_safe_lower_case_and_not_numbers() {
        for good in ["mc", "jellyfin", "git-2", "a", "x1"] {
            assert!(valid_label(good), "{good} should be usable");
        }
        for bad in [
            "",
            "MC",          // one canonical case, so a name compares and caches the same way
            "my service",  // not a DNS label
            "under_score", // ditto
            "-lead",
            "trail-",
            "8080", // reads as a port, resolves as a name
            "thisnameiswaytoolongforalabel",
        ] {
            assert!(!valid_label(bad), "{bad:?} should be refused");
        }
        assert!(valid_label(&"a".repeat(MAX_LABEL_LEN)));
        assert!(!valid_label(&"a".repeat(MAX_LABEL_LEN + 1)));
    }
}
