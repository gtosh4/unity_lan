//! Per-guild Ed25519 attestation signing. Each guild has its own independently-generated key
//! (design.md §3.1) so a compromised/forged key's blast radius is a single guild. Seeds are loaded
//! from the [`crate::store::Store`] and cached per guild by [`GuildKeys`].

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use common::attestation::Attestation;
use common::crypto::{CoordinatorKey, WgPublicKey};
use common::now_unix;
use common::wire::Signed;
use ipnet::Ipv4Net;

use crate::store::Store;

/// The device-identity fields an attestation binds (`guild + user + device + ip + wg_pubkey +
/// is_primary`). A borrowed view so signing and the sign-cache's freshness check take one value
/// instead of six positional args, without forcing a clone on the hot cache-hit path.
pub struct AttIdentity<'a> {
    pub user_id: u64,
    pub username: &'a str,
    pub device_name: &'a str,
    pub is_primary: bool,
    pub ip: Ipv4Addr,
    pub pubkey: WgPublicKey,
}

pub struct Signer {
    key: CoordinatorKey,
    /// The guild this key signs for; stamped into every attestation (`Attestation::guild_id`).
    guild_id: u64,
    /// The deployment's mesh CIDR, stamped into every attestation (see `Attestation::wg_net`).
    wg_net: Ipv4Net,
    /// Attestation validity window (seconds) — the deployment's revocation window (config).
    ttl: u64,
}

impl Signer {
    pub fn from_seed(seed: &[u8; 32], guild_id: u64, wg_net: Ipv4Net, ttl: u64) -> Self {
        Self {
            key: CoordinatorKey::from_seed(seed),
            guild_id,
            wg_net,
            ttl,
        }
    }

    pub fn anchor_bytes(&self) -> [u8; 32] {
        self.key.anchor_bytes()
    }

    /// Build and sign a device attestation for this guild with the default TTL.
    pub fn sign_attestation(&self, id: &AttIdentity, schema: u32) -> anyhow::Result<Signed> {
        let now = now_unix();
        let att = Attestation {
            guild_id: self.guild_id,
            user_id: id.user_id,
            username: id.username.to_owned(),
            device_name: id.device_name.to_owned(),
            is_primary: id.is_primary,
            wg_ip: id.ip,
            wg_net: self.wg_net,
            wg_pubkey: id.pubkey,
            issued_at: now,
            expires_at: now + self.ttl,
        };
        // The caller picks the layout from what the *client* said it can read; we tell that client
        // which one it got via `GuildAttestation::att_schema`. Never emit a layout the reader hasn't
        // claimed — the blob is postcard, so it can't tell it guessed wrong.
        Ok(common::attestation::sign_attestation(
            &self.key, &att, schema,
        )?)
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
    /// Attestation TTL (seconds) stamped into every signed attestation (deployment config).
    ttl: u64,
    cache: tokio::sync::Mutex<HashMap<u64, Arc<GuildKey>>>,
}

impl GuildKeys {
    pub fn new(store: Arc<Store>, wg_net: Ipv4Net, ttl: u64) -> Self {
        Self {
            store,
            wg_net,
            ttl,
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
        let signer = Signer::from_seed(&seed, guild_id, self.wg_net, self.ttl);
        let rotation_chain = self.store.rotation_chain(guild_id).await?;
        let key = Arc::new(GuildKey {
            signer,
            rotation_chain,
        });
        cache.insert(guild_id, key.clone());
        Ok(key)
    }
}

/// Default cap on how long a cached signed attestation is reused before it's re-signed. The actual
/// window is `min(this, attestation_ttl / 2)` — it **must** stay below the attestation TTL, or the
/// cache would serve an already-expired blob (peers reject it). For the default 30-min TTL the cap
/// wins (reuse 5 min → served blobs keep ≥25 min of life); a short configured TTL shrinks it.
const SIGN_CACHE_REUSE_CAP_SECS: u64 = 300;

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
/// its reuse window and fanned out to every snapshot, collapsing that to `N`.
pub struct SignCache {
    inner: RwLock<SignCacheInner>,
    /// How long a cached blob is reused before re-signing — `min(SIGN_CACHE_REUSE_CAP_SECS,
    /// attestation_ttl / 2)`, kept below the attestation TTL so a reused blob is never expired.
    reuse_secs: u64,
    /// Serializes the sign-on-miss path so a herd that all misses the same entry signs it **once**
    /// (the winner inserts; the rest re-check and hit) instead of every caller signing in parallel.
    /// A `tokio` mutex because it's held across the async guild-key load + sign. The warm-cache read
    /// path never touches it — it reads `inner` directly, so steady state stays fully concurrent.
    sign_lock: tokio::sync::Mutex<()>,
}

struct SignCacheInner {
    /// Keyed by `(guild, device, attestation layout)`. The layout is part of the key because two
    /// clients can be owed the *same* peer's attestation in different wire layouts during the V2
    /// rollout — the same blob signed twice, not one blob reused. Costs at most one extra entry per
    /// peer, only while both kinds of client are in the field, and collapses back once emission is
    /// uniform.
    map: HashMap<(u64, [u8; 32], u32), CachedAtt>,
    /// Last time stale entries (departed devices) were swept. Sweeping is `O(size)`, so it's
    /// time-gated to ~once per reuse window rather than run on every insert.
    last_prune: u64,
}

impl SignCache {
    /// `attestation_ttl` is the deployment's configured attestation lifetime; the reuse window is
    /// derived from it (and capped) so a cached blob is always re-signed well before it expires.
    pub fn new(attestation_ttl: u64) -> Self {
        Self {
            inner: RwLock::new(SignCacheInner {
                map: HashMap::new(),
                last_prune: 0,
            }),
            reuse_secs: (attestation_ttl / 2).clamp(1, SIGN_CACHE_REUSE_CAP_SECS),
            sign_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The base64 `Signed<Attestation>` for this peer in this guild, signing it only on a cold/stale
    /// miss. `now` is the caller's already-computed `now_unix()` (shared across the whole snapshot).
    pub async fn attestation(
        &self,
        keys: &GuildKeys,
        guild_id: u64,
        id: &AttIdentity<'_>,
        now: u64,
        schema: u32,
    ) -> anyhow::Result<Arc<str>> {
        let key = (guild_id, id.pubkey, schema);
        // Fast path: concurrent read, no signing, no async lock.
        if let Some(hit) = self.fresh(&key, now, id) {
            return Ok(hit);
        }
        // Miss: serialize signers so the herd signs this entry once, not N times.
        let _guard = self.sign_lock.lock().await;
        // Re-check — a peer that raced us here may have just filled it.
        if let Some(hit) = self.fresh(&key, now, id) {
            return Ok(hit);
        }
        let gk = keys.get(guild_id).await?;
        let signed = gk.signer.sign_attestation(id, schema)?;
        let blob: Arc<str> = Arc::from(signed.to_base64());
        let mut inner = self.inner.write().unwrap();
        if now.saturating_sub(inner.last_prune) >= self.reuse_secs {
            inner
                .map
                .retain(|_, v| now.saturating_sub(v.signed_at) < self.reuse_secs);
            inner.last_prune = now;
        }
        inner.map.insert(
            key,
            CachedAtt {
                blob: blob.clone(),
                signed_at: now,
                ip: id.ip,
                is_primary: id.is_primary,
                username: id.username.to_owned(),
                device_name: id.device_name.to_owned(),
            },
        );
        Ok(blob)
    }

    /// A live cache hit for `key`: present, unexpired, and its stored identity still matches the
    /// current one (else the attestation content changed and must be re-signed). `user_id`/`pubkey`
    /// aren't compared — the pubkey is in the key, and it binds the owner.
    fn fresh(
        &self,
        key: &(u64, [u8; 32], u32),
        now: u64,
        id: &AttIdentity<'_>,
    ) -> Option<Arc<str>> {
        let inner = self.inner.read().unwrap();
        let e = inner.map.get(key)?;
        (now.saturating_sub(e.signed_at) < self.reuse_secs
            && e.ip == id.ip
            && e.is_primary == id.is_primary
            && e.username == id.username
            && e.device_name == id.device_name)
            .then(|| e.blob.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use common::attestation::ATTESTATION_SCHEMA_V1 as V1;

    async fn keys() -> GuildKeys {
        let store = Arc::new(Store::memory().await);
        GuildKeys::new(store, "100.72.0.0/16".parse().unwrap(), 1800)
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn caches_identical_blob_and_invalidates_on_change() {
        let keys = keys().await;
        let cache = SignCache::new(1800);
        let pk = [7u8; 32];
        let addr = ip("100.72.0.5");
        let id = |name: &'static str, primary: bool| AttIdentity {
            user_id: 42,
            username: "alice",
            device_name: name,
            is_primary: primary,
            ip: addr,
            pubkey: pk,
        };

        let a = cache
            .attestation(&keys, 1, &id("laptop", false), 1_000, V1)
            .await
            .unwrap();
        let b = cache
            .attestation(&keys, 1, &id("laptop", false), 1_100, V1)
            .await
            .unwrap();
        // Second call within the cache window returns the *same* allocation — proof it was reused,
        // not re-signed (Ed25519 is deterministic, so equal bytes alone wouldn't prove a hit).
        assert!(
            Arc::ptr_eq(&a, &b),
            "a fresh call must reuse the cached blob"
        );

        // A rename under the same pubkey changes the signed content → must re-sign.
        let renamed = cache
            .attestation(&keys, 1, &id("desktop", false), 1_100, V1)
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&a, &renamed));
        assert_ne!(a.as_ref(), renamed.as_ref());

        // Crossing the cache TTL re-signs even with identical identity (fresh issued_at).
        let later = cache
            .attestation(
                &keys,
                1,
                &id("laptop", false),
                1_000 + SIGN_CACHE_REUSE_CAP_SECS,
                V1,
            )
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&a, &later));
    }

    #[tokio::test]
    async fn distinct_peers_and_guilds_are_separate_entries() {
        let keys = keys().await;
        let cache = SignCache::new(1800);
        let id = AttIdentity {
            user_id: 1,
            username: "a",
            device_name: "d",
            is_primary: false,
            ip: ip("100.72.0.1"),
            pubkey: [1u8; 32],
        };
        let g1_pk1 = cache.attestation(&keys, 1, &id, 0, V1).await.unwrap();
        // Same peer, different guild → different signer → distinct blob.
        let g2_pk1 = cache.attestation(&keys, 2, &id, 0, V1).await.unwrap();
        assert!(!Arc::ptr_eq(&g1_pk1, &g2_pk1));
        assert_ne!(g1_pk1.as_ref(), g2_pk1.as_ref());
    }

    /// The same peer owed to two clients on opposite sides of the V2 rollout must be signed once per
    /// layout — sharing one cached blob would hand somebody bytes they can't decode.
    #[tokio::test]
    async fn layout_is_part_of_the_cache_key() {
        let keys = keys().await;
        let cache = SignCache::new(1800);
        let id = AttIdentity {
            user_id: 1,
            username: "a",
            device_name: "d",
            is_primary: false,
            ip: ip("100.72.0.1"),
            pubkey: [1u8; 32],
        };
        let v1 = cache.attestation(&keys, 1, &id, 0, V1).await.unwrap();
        let v2 = cache
            .attestation(&keys, 1, &id, 0, common::attestation::ATTESTATION_SCHEMA_V2)
            .await
            .unwrap();
        assert_ne!(v1.as_ref(), v2.as_ref(), "layouts must not share a blob");
        // …and each layout still caches on its own.
        assert!(Arc::ptr_eq(
            &v1,
            &cache.attestation(&keys, 1, &id, 0, V1).await.unwrap()
        ));
    }
}
