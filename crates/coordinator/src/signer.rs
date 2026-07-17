//! Per-guild Ed25519 attestation signing. Each guild has its own independently-generated key
//! (design.md §3.1) so a compromised/forged key's blast radius is a single guild. Seeds are loaded
//! from the [`crate::store::Store`] and cached per guild by [`GuildKeys`].

use std::collections::HashMap;
use std::sync::Arc;

use common::attestation::Attestation;
use common::crypto::{CoordinatorKey, WgPublicKey};
use common::wire::Signed;
use common::{now_unix, ATTESTATION_TTL_SECS};
use ipnet::Ipv4Net;

use crate::store::Store;

pub struct Signer {
    key: CoordinatorKey,
    /// The guild this key signs for; stamped into every attestation (`Attestation::guild_id`).
    guild_id: u64,
    /// The deployment's mesh CIDR, stamped into every attestation (see `Attestation::wg_net`).
    wg_net: Ipv4Net,
}

impl Signer {
    pub fn from_seed(seed: &[u8; 32], guild_id: u64, wg_net: Ipv4Net) -> Self {
        Self {
            key: CoordinatorKey::from_seed(seed),
            guild_id,
            wg_net,
        }
    }

    pub fn anchor_bytes(&self) -> [u8; 32] {
        self.key.anchor_bytes()
    }

    /// Build and sign a device attestation for this guild with the default TTL.
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
            guild_id: self.guild_id,
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

    /// Sign an arbitrary value with this guild's key, returning the base64 transport form. Used for
    /// the release manifest (auto-update) — verified client-side against this guild's pinned anchor.
    pub fn sign_to_base64<T: serde::Serialize>(&self, value: &T) -> anyhow::Result<String> {
        Ok(Signed::sign(&self.key, value)?.to_base64())
    }
}

/// A guild's signing key plus its rotation chain, loaded once and cached.
pub struct GuildKey {
    pub signer: Signer,
    /// This guild's rotation-cert chain (base64, oldest→newest), served in `RegisterResp` so a
    /// client pinned to a superseded anchor for this guild can re-pin (design.md §9).
    pub rotation_chain: Vec<String>,
}

/// Lazily-populated registry of per-guild signing keys. A guild's key is created on first use
/// (independently generated, §3.1) and cached for the process lifetime — rotation is an offline
/// subcommand that requires a restart, so a cached chain never goes stale at runtime.
pub struct GuildKeys {
    store: Arc<Store>,
    wg_net: Ipv4Net,
    cache: tokio::sync::Mutex<HashMap<u64, Arc<GuildKey>>>,
}

impl GuildKeys {
    pub fn new(store: Arc<Store>, wg_net: Ipv4Net) -> Self {
        Self {
            store,
            wg_net,
            cache: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The deployment's mesh CIDR — the allocation range and the value stamped into attestations.
    pub fn wg_net(&self) -> Ipv4Net {
        self.wg_net
    }

    /// The signing key for `guild_id`, generating + persisting a fresh one on first use.
    pub async fn get(&self, guild_id: u64) -> anyhow::Result<Arc<GuildKey>> {
        let mut cache = self.cache.lock().await;
        if let Some(key) = cache.get(&guild_id) {
            return Ok(key.clone());
        }
        let seed = self.store.load_or_create_seed(guild_id).await?;
        let signer = Signer::from_seed(&seed, guild_id, self.wg_net);
        let rotation_chain = self.store.rotation_chain(guild_id).await?;
        let key = Arc::new(GuildKey {
            signer,
            rotation_chain,
        });
        cache.insert(guild_id, key.clone());
        Ok(key)
    }
}
