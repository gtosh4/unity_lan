//! Ed25519 attestation signing. The seed is loaded from the [`crate::store::Store`].

use common::attestation::Attestation;
use common::crypto::{CoordinatorKey, WgPublicKey};
use common::wire::Signed;
use common::{now_unix, ATTESTATION_TTL_SECS};
use ipnet::Ipv4Net;

pub struct Signer {
    key: CoordinatorKey,
    /// The deployment's mesh CIDR, stamped into every attestation (see `Attestation::wg_net`).
    wg_net: Ipv4Net,
}

impl Signer {
    pub fn from_seed(seed: &[u8; 32], wg_net: Ipv4Net) -> Self {
        Self {
            key: CoordinatorKey::from_seed(seed),
            wg_net,
        }
    }

    pub fn anchor_bytes(&self) -> [u8; 32] {
        self.key.anchor_bytes()
    }

    /// The deployment's mesh CIDR — the allocation range and the value stamped into attestations.
    pub fn wg_net(&self) -> Ipv4Net {
        self.wg_net
    }

    /// Build and sign a device attestation with the default TTL.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_attestation(
        &self,
        user_id: u64,
        username: String,
        device_name: String,
        is_primary: bool,
        wg_ip: std::net::Ipv4Addr,
        wg_pubkey: WgPublicKey,
    ) -> anyhow::Result<Signed> {
        let now = now_unix();
        let att = Attestation {
            user_id,
            username,
            device_name,
            is_primary,
            wg_ip,
            wg_net: self.wg_net,
            wg_pubkey,
            issued_at: now,
            expires_at: now + ATTESTATION_TTL_SECS,
        };
        Ok(Signed::sign(&self.key, &att)?)
    }

    /// Sign an arbitrary value with the coordinator key, returning the base64 transport form. Used
    /// for the release manifest (auto-update) — verified client-side against the same pinned anchor.
    pub fn sign_to_base64<T: serde::Serialize>(&self, value: &T) -> anyhow::Result<String> {
        Ok(Signed::sign(&self.key, value)?.to_base64())
    }
}
