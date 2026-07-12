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
