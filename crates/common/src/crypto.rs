//! Ed25519 (coordinator attestation signing) and Curve25519 (WireGuard key) helpers.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// A raw 32-byte WireGuard (Curve25519) public key.
pub type WgPublicKey = [u8; 32];
/// A raw 32-byte WireGuard (Curve25519) private key. Never leaves the client.
pub type WgPrivateKey = [u8; 32];

/// The coordinator's Ed25519 signing key. Its public half is the guild's trust anchor.
pub struct CoordinatorKey(SigningKey);

impl CoordinatorKey {
    /// Generate a fresh signing key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self(SigningKey::generate(&mut rng))
    }

    /// Load from a persisted 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The 32-byte seed, for persistence (protect at rest).
    pub fn to_seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The public trust anchor clients pin.
    pub fn anchor(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    /// Raw 32-byte anchor bytes (what travels in `RegisterResp`).
    pub fn anchor_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> Signature {
        self.0.sign(msg)
    }
}

/// Parse a 32-byte anchor into a verifying key.
pub fn anchor_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, ed25519_dalek::SignatureError> {
    VerifyingKey::from_bytes(bytes)
}

pub(crate) fn sign_bytes(key: &CoordinatorKey, msg: &[u8]) -> [u8; 64] {
    key.sign(msg).to_bytes()
}

pub(crate) fn verify_bytes(anchor: &VerifyingKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    let sig = Signature::from_bytes(sig);
    anchor.verify(msg, &sig).is_ok()
}

/// Generate a WireGuard keypair; the private key stays local, the public key is attested.
pub fn gen_wg_keypair() -> (WgPrivateKey, WgPublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// Recompute the WireGuard public key from a stored private key.
pub fn wg_public_from_private(private: &WgPrivateKey) -> WgPublicKey {
    let secret = StaticSecret::from(*private);
    PublicKey::from(&secret).to_bytes()
}

/// Lowercase hex-encode `bytes` into `s` (no per-byte allocation).
fn push_hex(s: &mut String, bytes: &[u8]) {
    use std::fmt::Write;
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
}

/// Anonymize a `u64` identifier into a short, stable, opaque label for the admin network graph.
/// Keyed by the deployment seed, so the mapping is deterministic within one deployment (the same
/// user is the same node across a render, and across renders) yet reveals nothing about the
/// underlying Discord snowflake to whoever views the graph. `domain` namespaces the input so a
/// user and a role that share an id map to different labels. This is de-identification, not a
/// security boundary (the graph already sits behind the admin token), so a truncated HMAC-SHA1
/// suffices — 32 bits is ample to avoid collisions at mesh scale.
pub fn anon_label(key: &[u8], domain: &str, id: u64) -> String {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(domain.as_bytes());
    mac.update(&[0]); // separator: ("ab", …) and ("a", "b"…) must not collide
    mac.update(&id.to_le_bytes());
    let tag = mac.finalize().into_bytes();
    let mut s = String::with_capacity(8);
    push_hex(&mut s, &tag[..4]);
    s
}

/// Mint a one-time enrollment key: `unl_` + 32 hex chars (128 bits from the OS CSPRNG).
pub fn gen_enrollment_key() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(4 + 32);
    s.push_str("unl_");
    push_hex(&mut s, &bytes);
    s
}

/// Constant-time byte-slice equality: fold the XOR of every byte pair so a mismatch's timing
/// doesn't leak how long a common prefix ran. Length is not itself a secret here (a differing
/// length short-circuits), but the content comparison — used for bearer tokens — is.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A PKCE `code_verifier`: 64 hex chars from 32 random bytes. Hex is within the allowed
/// `[A-Za-z0-9-._~]` unreserved set and comfortably inside the 43–128 char length bound.
pub fn gen_pkce_verifier() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(64);
    push_hex(&mut s, &bytes);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = CoordinatorKey::generate();
        let anchor = key.anchor();
        let msg = b"hello unitylan";
        let sig = sign_bytes(&key, msg);
        assert!(verify_bytes(&anchor, msg, &sig));
    }

    #[test]
    fn tampered_message_fails() {
        let key = CoordinatorKey::generate();
        let anchor = key.anchor();
        let sig = sign_bytes(&key, b"original");
        assert!(!verify_bytes(&anchor, b"tampered", &sig));
    }

    #[test]
    fn wrong_anchor_fails() {
        let key = CoordinatorKey::generate();
        let other = CoordinatorKey::generate();
        let msg = b"msg";
        let sig = sign_bytes(&key, msg);
        assert!(!verify_bytes(&other.anchor(), msg, &sig));
    }

    #[test]
    fn seed_roundtrip_preserves_anchor() {
        let key = CoordinatorKey::generate();
        let seed = key.to_seed();
        let restored = CoordinatorKey::from_seed(&seed);
        assert_eq!(key.anchor_bytes(), restored.anchor_bytes());
    }

    #[test]
    fn anon_label_is_stable_distinct_and_domain_separated() {
        let key = [7u8; 32];
        // Stable: same (key, domain, id) → same label.
        assert_eq!(anon_label(&key, "user", 42), anon_label(&key, "user", 42));
        // Distinct ids differ; same id in a different domain differs; a different key differs.
        assert_ne!(anon_label(&key, "user", 42), anon_label(&key, "user", 43));
        assert_ne!(anon_label(&key, "user", 42), anon_label(&key, "net", 42));
        assert_ne!(
            anon_label(&key, "user", 42),
            anon_label(&[9u8; 32], "user", 42)
        );
        // Opaque short label: 8 lowercase hex chars, no leak of the raw id.
        let l = anon_label(&key, "user", 42);
        assert_eq!(l.len(), 8);
        assert!(l.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn wg_keypair_is_32_bytes() {
        let (priv_k, pub_k) = gen_wg_keypair();
        assert_eq!(priv_k.len(), 32);
        assert_eq!(pub_k.len(), 32);
        assert_ne!(priv_k, pub_k);
    }
}
