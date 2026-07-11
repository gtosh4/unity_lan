//! Ed25519 attestation signing. The seed is loaded from the [`crate::store::Store`].

use common::attestation::Attestation;
use common::crypto::{CoordinatorKey, WgPublicKey};
use common::wire::Signed;
use common::{now_unix, ATTESTATION_TTL_SECS};

pub struct Signer {
    key: CoordinatorKey,
}

impl Signer {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: CoordinatorKey::from_seed(seed),
        }
    }

    pub fn anchor_bytes(&self) -> [u8; 32] {
        self.key.anchor_bytes()
    }

    /// Build and sign an attestation with the default TTL.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_attestation(
        &self,
        guild_id: u64,
        role_id: u64,
        user_id: u64,
        nick: String,
        wg_ip: std::net::Ipv4Addr,
        wg_pubkey: WgPublicKey,
    ) -> anyhow::Result<Signed> {
        let now = now_unix();
        let att = Attestation {
            guild_id,
            role_id,
            user_id,
            nick,
            wg_ip,
            wg_pubkey,
            issued_at: now,
            expires_at: now + ATTESTATION_TTL_SECS,
        };
        Ok(Signed::sign(&self.key, &att)?)
    }
}
