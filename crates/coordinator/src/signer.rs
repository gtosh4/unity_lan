//! Per-guild Ed25519 attestation signing. Each guild has its own independently-generated key
//! (design.md §3.1) so a compromised/forged key's blast radius is a single guild. Seeds are loaded
//! from the [`crate::store::Store`] and cached per guild by [`GuildKeys`].

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

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

/// How long a cached signed attestation is reused before it's re-signed. Bounds the worst-case
/// remaining life of a served attestation to `ATTESTATION_TTL_SECS - SIGN_CACHE_TTL_SECS` (25 min
/// here), comfortably above the client's renewal interval so a reused blob never lands expired.
const SIGN_CACHE_TTL_SECS: u64 = 300;

/// A signed attestation held for reuse, plus the peer identity it was signed for. An attestation
/// binds only peer identity + guild (never the caller), so the *same* base64 blob is valid in every
/// snapshot that includes the peer — the whole point of caching. The identity fields are stored so a
/// cache hit re-validates them: a rename / re-IP / primary-flip under the same pubkey invalidates.
struct CachedAtt {
    blob: Arc<str>,
    signed_at: u64,
    ip: Ipv4Addr,
    is_primary: bool,
    username: String,
    device_name: String,
}

/// Per-`(guild, device-pubkey)` cache of signed peer attestations. Without it `build_snapshot` signs
/// each viewer-independent attestation once **per caller** — a herd of `N` long-pollers over `N`
/// shared peers costs `N²` Ed25519 signs. Here each attestation is signed once per
/// `SIGN_CACHE_TTL_SECS` and fanned out to every snapshot, collapsing that to `N`.
pub struct SignCache {
    inner: RwLock<SignCacheInner>,
    /// Serializes the sign-on-miss path so a herd that all misses the same entry signs it **once**
    /// (the winner inserts; the rest re-check and hit) instead of every caller signing in parallel.
    /// A `tokio` mutex because it's held across the async guild-key load + sign. The warm-cache read
    /// path never touches it — it reads `inner` directly, so steady state stays fully concurrent.
    sign_lock: tokio::sync::Mutex<()>,
}

struct SignCacheInner {
    map: HashMap<(u64, [u8; 32]), CachedAtt>,
    /// Last time stale entries (departed devices) were swept. Sweeping is `O(size)`, so it's
    /// time-gated to ~once per `SIGN_CACHE_TTL_SECS` rather than run on every insert.
    last_prune: u64,
}

impl SignCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(SignCacheInner {
                map: HashMap::new(),
                last_prune: 0,
            }),
            sign_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The base64 `Signed<Attestation>` for this peer in this guild, signing it only on a cold/stale
    /// miss. `now` is the caller's already-computed `now_unix()` (shared across the whole snapshot).
    #[allow(clippy::too_many_arguments)]
    pub async fn attestation(
        &self,
        keys: &GuildKeys,
        guild_id: u64,
        user_id: u64,
        username: &str,
        device_name: &str,
        is_primary: bool,
        ip: Ipv4Addr,
        pubkey: WgPublicKey,
        now: u64,
    ) -> anyhow::Result<Arc<str>> {
        let key = (guild_id, pubkey);
        // Fast path: concurrent read, no signing, no async lock.
        if let Some(hit) = self.fresh(&key, now, username, device_name, is_primary, ip) {
            return Ok(hit);
        }
        // Miss: serialize signers so the herd signs this entry once, not N times.
        let _guard = self.sign_lock.lock().await;
        // Re-check — a peer that raced us here may have just filled it.
        if let Some(hit) = self.fresh(&key, now, username, device_name, is_primary, ip) {
            return Ok(hit);
        }
        let gk = keys.get(guild_id).await?;
        let signed = gk.signer.sign_attestation(
            user_id,
            username.to_owned(),
            device_name.to_owned(),
            is_primary,
            ip,
            pubkey,
        )?;
        let blob: Arc<str> = Arc::from(signed.to_base64());
        let mut inner = self.inner.write().unwrap();
        if now.saturating_sub(inner.last_prune) >= SIGN_CACHE_TTL_SECS {
            inner
                .map
                .retain(|_, v| now.saturating_sub(v.signed_at) < SIGN_CACHE_TTL_SECS);
            inner.last_prune = now;
        }
        inner.map.insert(
            key,
            CachedAtt {
                blob: blob.clone(),
                signed_at: now,
                ip,
                is_primary,
                username: username.to_owned(),
                device_name: device_name.to_owned(),
            },
        );
        Ok(blob)
    }

    /// A live cache hit for `key`: present, unexpired, and its stored identity still matches the
    /// current one (else the attestation content changed and must be re-signed).
    fn fresh(
        &self,
        key: &(u64, [u8; 32]),
        now: u64,
        username: &str,
        device_name: &str,
        is_primary: bool,
        ip: Ipv4Addr,
    ) -> Option<Arc<str>> {
        let inner = self.inner.read().unwrap();
        let e = inner.map.get(key)?;
        (now.saturating_sub(e.signed_at) < SIGN_CACHE_TTL_SECS
            && e.ip == ip
            && e.is_primary == is_primary
            && e.username == username
            && e.device_name == device_name)
            .then(|| e.blob.clone())
    }
}

impl Default for SignCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    async fn keys() -> GuildKeys {
        let store = Arc::new(Store::memory().await);
        GuildKeys::new(store, "100.72.0.0/16".parse().unwrap())
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn caches_identical_blob_and_invalidates_on_change() {
        let keys = keys().await;
        let cache = SignCache::new();
        let pk = [7u8; 32];
        let addr = ip("100.72.0.5");
        let sign = |name: &'static str, primary: bool, now: u64| {
            cache.attestation(&keys, 1, 42, "alice", name, primary, addr, pk, now)
        };

        let a = sign("laptop", false, 1_000).await.unwrap();
        let b = sign("laptop", false, 1_100).await.unwrap();
        // Second call within the cache window returns the *same* allocation — proof it was reused,
        // not re-signed (Ed25519 is deterministic, so equal bytes alone wouldn't prove a hit).
        assert!(
            Arc::ptr_eq(&a, &b),
            "a fresh call must reuse the cached blob"
        );

        // A rename under the same pubkey changes the signed content → must re-sign.
        let renamed = sign("desktop", false, 1_100).await.unwrap();
        assert!(!Arc::ptr_eq(&a, &renamed));
        assert_ne!(a.as_ref(), renamed.as_ref());

        // Crossing the cache TTL re-signs even with identical identity (fresh issued_at).
        let later = sign("laptop", false, 1_000 + SIGN_CACHE_TTL_SECS)
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&a, &later));
    }

    #[tokio::test]
    async fn distinct_peers_and_guilds_are_separate_entries() {
        let keys = keys().await;
        let cache = SignCache::new();
        let g1_pk1 = cache
            .attestation(&keys, 1, 1, "a", "d", false, ip("100.72.0.1"), [1u8; 32], 0)
            .await
            .unwrap();
        // Same peer, different guild → different signer → distinct blob.
        let g2_pk1 = cache
            .attestation(&keys, 2, 1, "a", "d", false, ip("100.72.0.1"), [1u8; 32], 0)
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&g1_pk1, &g2_pk1));
        assert_ne!(g1_pk1.as_ref(), g2_pk1.as_ref());
    }
}
