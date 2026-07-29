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

/// What a service is, which decides whether its name needs a certificate.
///
/// Only two, and the split is not cosmetic: a `Web` name goes into a publicly-trusted certificate,
/// which means it is registered with the coordinator (the only party that may publish an ACME
/// challenge for it) and published to Certificate Transparency logs **permanently**. A `Port`
/// service is announced peer-to-peer and nowhere else. So this is the field that decides whether a
/// name leaves the mesh at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceKind {
    /// A plain port — a game server, SSH, anything spoken over the mesh by name and port.
    #[default]
    Port,
    /// Something a browser opens. Its name is certified, so it must be registered.
    Web,
}

impl ServiceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::Web => "web",
        }
    }
}

/// A service as announced to peers: the label, what it is, and where it listens.
///
/// The scope is deliberately absent. A device answers [`crate::p2p::ReqBody::GetServices`] only to
/// peers that may reach the service, so who-can-see-it is enforced where the data lives rather than
/// shipped to every peer to enforce for itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshService {
    pub name: String,
    pub proto: Proto,
    pub port: u16,
    /// Absent from an older peer's announcement, which read as a plain port because that is all
    /// there was.
    #[serde(default)]
    pub kind: ServiceKind,
}

/// The name an unnamed port gets: `port-25565`.
///
/// Every exposure carries a name, so "an open port with no name" is not a state the model has — a
/// port opened without one (from `ctl expose`, a config seed, or a state file written before names
/// existed) is given this at load. That keeps one list instead of two, and the name is a real one:
/// `port-25565.alice.unity.internal` resolves like any other, so even a port nobody bothered to name
/// is reachable without an address.
pub fn default_label(port: u16) -> String {
    format!("port-{port}")
}

/// The full name a service answers to, given this device's own hostname and the service's label:
/// `mc.alice.unity.internal` from `laptop.alice.unity.internal` and `mc`.
///
/// **Derived from the hostname, never from the Discord handle.** The `<user>` part of a mesh name is
/// a label the coordinator *allocated* — sanitised to what DNS allows, and suffixed if it would have
/// collided with someone else's. A handle like `alice#4021` is neither, and composing a name from one
/// produces something that will never resolve. The hostname is the only thing on hand that already
/// contains the real label.
///
/// `None` if the hostname is not a mesh name (nothing to take a label from).
pub fn service_name(device_hostname: &str, label: &str) -> Option<String> {
    let rest = device_hostname
        .trim_end_matches('.')
        .strip_suffix(&format!(".{}", crate::DNS_SUFFIX))?
        .split_once('.')
        .map(|(_device, user)| user)?;
    Some(format!("{label}.{rest}.{}", crate::DNS_SUFFIX).to_ascii_lowercase())
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

    /// The name has to come from the *hostname*, not the Discord handle. A handle can carry a
    /// discriminator (`alice#4021`) or characters DNS refuses, and the coordinator may have suffixed
    /// the label to avoid a collision — so a name built from the handle is one that never resolves.
    #[test]
    fn a_service_name_takes_the_user_label_from_the_hostname() {
        assert_eq!(
            service_name("laptop.alice.unity.internal", "mc").as_deref(),
            Some("mc.alice.unity.internal")
        );
        // A collision-suffixed label carries through exactly as allocated.
        assert_eq!(
            service_name("laptop.alice-2.unity.internal", "mc").as_deref(),
            Some("mc.alice-2.unity.internal")
        );
        assert_eq!(
            service_name("Laptop.Alice.unity.internal", "MC").as_deref(),
            Some("mc.alice.unity.internal"),
            "one canonical case, like every other mesh name"
        );
        // Not a mesh name, so there is no label to take.
        assert_eq!(service_name("laptop.alice.example.com", "mc"), None);
        assert_eq!(service_name("alice.unity.internal", "mc"), None);
    }
}
