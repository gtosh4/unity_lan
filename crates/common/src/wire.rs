//! Canonical wire format: postcard-serialized payloads wrapped in a signed envelope.
//!
//! Signatures are computed over the **postcard** bytes of the payload (deterministic), never
//! over JSON. The transport form is base64 of the postcard-serialized [`Signed`].

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::VerifyingKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::crypto::{sign_bytes, verify_bytes, CoordinatorKey};

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("signature has wrong length")]
    BadSignatureLength,
    #[error("postcard (de)serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// A signed envelope: `payload` = postcard(T), `sig` = Ed25519 over `payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signed {
    pub payload: Vec<u8>,
    pub sig: Vec<u8>,
}

impl Signed {
    /// Sign a value with the coordinator key.
    pub fn sign<T: Serialize>(key: &CoordinatorKey, value: &T) -> Result<Signed, WireError> {
        let payload = postcard::to_allocvec(value)?;
        let sig = sign_bytes(key, &payload).to_vec();
        Ok(Signed { payload, sig })
    }

    /// Verify against a trust anchor and decode the inner value.
    pub fn verify<T: DeserializeOwned>(&self, anchor: &VerifyingKey) -> Result<T, WireError> {
        let sig: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| WireError::BadSignatureLength)?;
        if !verify_bytes(anchor, &self.payload, &sig) {
            return Err(WireError::BadSignature);
        }
        Ok(postcard::from_bytes(&self.payload)?)
    }

    /// Base64 transport form.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(postcard::to_allocvec(self).expect("Signed is always serializable"))
    }

    /// Parse from the base64 transport form.
    pub fn from_base64(s: &str) -> Result<Signed, WireError> {
        let bytes = STANDARD.decode(s)?;
        Ok(postcard::from_bytes(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CoordinatorKey;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Demo {
        a: u64,
        b: String,
    }

    /// A peer hands us these blobs directly over the tunnel (the p2p attestation pull), so decoding
    /// runs on bytes another device chose, before the signature can reject them. The project's rule
    /// is that peer-supplied data which won't parse costs you *that peer* — which it can't do if
    /// the parse takes the process down instead. Sweep junk base64, junk bytes, and corruptions of
    /// a real envelope; every one must come back `Err`, never panic.
    #[test]
    fn decoding_a_hostile_envelope_errors_rather_than_panicking() {
        for seed in 0..300u64 {
            for len in 0..64 {
                let bytes = crate::testutil::seeded_bytes(seed, len);
                // Junk that is valid base64, so the postcard decoder is what actually sees it. A
                // short run of bytes can legitimately decode to some `Signed`; that's fine — it
                // would still fail to verify. Only a panic is a failure here.
                let _ = Signed::from_base64(&STANDARD.encode(&bytes));
                // ...and junk that mostly isn't, exercising the base64 error path.
                let _ = Signed::from_base64(&String::from_utf8_lossy(&bytes));
            }
        }

        let key = CoordinatorKey::generate();
        let v = Demo {
            a: 9,
            b: "hostile".into(),
        };
        let good = Signed::sign(&key, &v).unwrap().to_base64();
        // Every truncation, and every single-bit flip of the underlying bytes.
        for n in 0..=good.len() {
            let _ = Signed::from_base64(&good[..n]);
        }
        let raw = STANDARD.decode(&good).unwrap();
        for byte in 0..raw.len() {
            for bit in 0..8 {
                let mut m = raw.clone();
                m[byte] ^= 1 << bit;
                // A corrupted envelope either fails to decode, or decodes and fails to verify —
                // both fine. What matters is that neither step panics or is trusted.
                if let Ok(s) = Signed::from_base64(&STANDARD.encode(&m)) {
                    let _: Result<Demo, _> = s.verify(&key.anchor());
                }
            }
        }
        // The untouched envelope still verifies, so the sweep didn't just prove everything fails.
        assert_eq!(
            Signed::from_base64(&good)
                .unwrap()
                .verify::<Demo>(&key.anchor())
                .unwrap(),
            v
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = CoordinatorKey::generate();
        let v = Demo {
            a: 7,
            b: "x".into(),
        };
        let signed = Signed::sign(&key, &v).unwrap();
        let out: Demo = signed.verify(&key.anchor()).unwrap();
        assert_eq!(v, out);
    }

    #[test]
    fn tamper_payload_fails() {
        let key = CoordinatorKey::generate();
        let v = Demo {
            a: 1,
            b: "y".into(),
        };
        let mut signed = Signed::sign(&key, &v).unwrap();
        signed.payload[0] ^= 0xff;
        let out: Result<Demo, _> = signed.verify(&key.anchor());
        assert!(matches!(out, Err(WireError::BadSignature)));
    }

    #[test]
    fn base64_roundtrip() {
        let key = CoordinatorKey::generate();
        let v = Demo {
            a: 42,
            b: "hello".into(),
        };
        let signed = Signed::sign(&key, &v).unwrap();
        let restored = Signed::from_base64(&signed.to_base64()).unwrap();
        let out: Demo = restored.verify(&key.anchor()).unwrap();
        assert_eq!(v, out);
    }
}
