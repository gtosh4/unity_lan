//! TURN relay credential minting/validation (design.md §7.2, M5.4).
//!
//! When a hole punch fails (symmetric NAT / CGNAT / UDP-blocked), a stuck peer reaches its
//! co-member through a relay-capable peer's embedded TURN server. The coordinator mints a
//! short-lived TURN credential (off the data path); the relay's TURN server validates it *without*
//! contacting the coordinator. Both agree because they share the relay's `relay_secret` and this
//! pure derivation of the credential — the standard coturn `use-auth-secret` / TURN REST scheme.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;

use crate::api::RelayInfo;

/// A fresh 256-bit relay HMAC secret (base64). A relay generates one on first use and persists it;
/// it's shared only with the coordinator, which mints credentials against it.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

/// TURN realm the embedded relay servers present. Fixed across the mesh (identity is carried by
/// the per-relay `relay_secret`, not the realm).
pub const RELAY_REALM: &str = "unitylan";

/// Long-term-credential password for `username`, keyed by the relay's `secret`:
/// base64(HMAC-SHA1(secret, username)). Computed identically by the coordinator (to mint) and the
/// relay's TURN server (to validate).
pub fn relay_credential(secret: &str, username: &str) -> String {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

/// Mint a [`RelayInfo`] for a client to allocate on the relay at `turn_addr`: a username carrying
/// the absolute expiry `now + ttl` (TURN REST `"<expiry>:<id>"` form) and the HMAC credential
/// over it. The relay's server rejects the username once `now` passes the expiry.
pub fn issue_relay_creds(
    turn_addr: std::net::SocketAddr,
    relay_secret: &str,
    now: u64,
    ttl: u64,
) -> RelayInfo {
    // Bare `<expiry>` (unix seconds): the webrtc-rs `LongTermAuthHandler` on the relay parses the
    // whole username as the expiry, so no `:id` suffix.
    let username = (now + ttl).to_string();
    let credential = relay_credential(relay_secret, &username);
    RelayInfo {
        turn_addr,
        username,
        credential,
        realm: RELAY_REALM.to_string(),
        peer_relayed: None,
    }
}

/// The expiry embedded in a REST-style TURN `username` (`"<unix_expiry>:<id>"`), if parseable.
/// The relay's server uses it to reject stale credentials.
pub fn username_expiry(username: &str) -> Option<u64> {
    username.split(':').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn credential_is_deterministic_and_key_sensitive() {
        let u = "1700000000:unitylan";
        assert_eq!(relay_credential("s3cret", u), relay_credential("s3cret", u));
        assert_ne!(relay_credential("s3cret", u), relay_credential("other", u));
        assert_ne!(
            relay_credential("s3cret", u),
            relay_credential("s3cret", "1700000001:unitylan")
        );
    }

    #[test]
    fn issued_creds_verify_and_carry_expiry() {
        let addr: SocketAddr = "203.0.113.7:3478".parse().unwrap();
        let info = issue_relay_creds(addr, "s3cret", 1_000, 3_600);
        assert_eq!(info.turn_addr, addr);
        assert_eq!(info.realm, RELAY_REALM);
        // The credential matches an independent derivation over the minted username.
        assert_eq!(info.credential, relay_credential("s3cret", &info.username));
        assert_eq!(username_expiry(&info.username), Some(4_600));
    }
}
