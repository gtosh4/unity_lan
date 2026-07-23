//! SQLite persistence: signing-key seed, network registry, per-device IP allocations.
//!
//! u64 Discord snowflakes are stored as i64 (bit-preserving cast) since SQLite lacks u64.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::Context;
use common::netid::{addr_from_index, device_hint, pick_free_index};
use ipnet::Ipv4Net;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

/// Per-account device cap. A device row is a permanent mesh-IP allocation, so without a ceiling a
/// single role-holding account could loop enrollments with fresh keys and exhaust the mesh `/16`
/// (TM-2). Set well above any realistic fleet (laptops, phones, servers, VMs) so it never bites a
/// legitimate user, only a runaway.
const MAX_DEVICES_PER_USER: u64 = 32;

/// A registered network = a role designated as a UnityLAN network.
#[derive(Clone, Debug)]
pub struct Network {
    pub guild_id: u64,
    pub role_id: u64,
    pub name: String,
}

/// Convert a stored pubkey BLOB into a fixed 32-byte key, erroring on a bad width.
fn pubkey_from_blob(blob: Vec<u8>) -> anyhow::Result<[u8; 32]> {
    blob.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("stored pubkey is not 32 bytes"))
}

/// How a device name resolves against a user's device list.
pub enum DeviceMatch {
    /// Exactly one device — its pubkey.
    One([u8; 32]),
    /// No device by that name.
    None,
    /// The name is ambiguous (more than one device).
    Many,
}

/// Classify how a sanitized `name` matches a user's `(pubkey, name)` device list.
pub fn match_device_by_name(devices: &[([u8; 32], String)], name: &str) -> DeviceMatch {
    let mut it = devices.iter().filter(|(_, n)| n == name).map(|(pk, _)| *pk);
    match (it.next(), it.next()) {
        (Some(pk), None) => DeviceMatch::One(pk),
        (None, _) => DeviceMatch::None,
        (Some(_), Some(_)) => DeviceMatch::Many,
    }
}

/// Restrict the SQLite DB (and its WAL/SHM sidecars, if present) to owner-only `0600`. Fatal on the
/// main file — we must not leave the signing seed in a world-readable file; best-effort on the
/// sidecars, which SQLite may not have created yet. No-op on non-unix (ACL model differs).
#[cfg(unix)]
fn restrict_db_perms(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let owner_only = || std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, owner_only())
        .with_context(|| format!("restricting permissions on {}", path.display()))?;
    for ext in ["-wal", "-shm"] {
        let mut side = path.as_os_str().to_owned();
        side.push(ext);
        let side = std::path::PathBuf::from(side);
        if side.exists() {
            let _ = std::fs::set_permissions(&side, owner_only());
        }
    }
    Ok(())
}

/// Create the database file with owner-only permissions before SQLite opens it. Reject symlinks:
/// this file eventually contains every guild signing seed and must never be redirected elsewhere.
#[cfg(unix)]
fn prepare_db_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_file() {
            anyhow::bail!("sqlite path {} is not a regular file", path.display());
        }
        return restrict_db_perms(path);
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating private sqlite file {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn prepare_db_file(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn restrict_db_perms(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        prepare_db_file(path)?;
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .connect_with(opts)
            .await
            .with_context(|| format!("opening sqlite {}", path.display()))?;
        // Re-assert after SQLite opens it, including any already-existing database.
        restrict_db_perms(path)?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    /// A private in-memory store for tests (single connection, so the `:memory:` db is shared).
    #[cfg(test)]
    pub(crate) async fn memory() -> Self {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = Self { pool };
        store.migrate().await.unwrap();
        store
    }

    async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS guild_signing_keys (
                guild_id INTEGER PRIMARY KEY,  -- one independent Ed25519 seed per guild (§3.1)
                seed     BLOB    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deployment_seed (
                id   INTEGER PRIMARY KEY CHECK (id = 1),  -- one row; not a signing key
                seed BLOB    NOT NULL                     -- random, selects the default mesh /16
            );
            CREATE TABLE IF NOT EXISTS enroll_key (
                id   INTEGER PRIMARY KEY CHECK (id = 1),  -- one row; the X25519 enrollment secret
                seed BLOB    NOT NULL                     -- device possession-proof DH secret
            );
            CREATE TABLE IF NOT EXISTS networks (
                guild_id INTEGER NOT NULL,
                role_id  INTEGER NOT NULL,
                name     TEXT    NOT NULL,
                PRIMARY KEY (guild_id, role_id)
            );
            CREATE TABLE IF NOT EXISTS devices (
                pubkey      BLOB    PRIMARY KEY,
                idx         INTEGER NOT NULL UNIQUE,
                user_id     INTEGER NOT NULL,
                device_name TEXT    NOT NULL,
                token       TEXT             -- per-device bearer token for control mutations
            );
            CREATE TABLE IF NOT EXISTS enrollment_keys (
                key        TEXT    PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                expires_at INTEGER,          -- NULL = never expires
                used_by    BLOB              -- device pubkey that consumed it; NULL = unused
            );
            CREATE TABLE IF NOT EXISTS communities (
                guild_id INTEGER PRIMARY KEY,
                slug     TEXT    NOT NULL     -- the <community> DNS label for this guild
            );
            CREATE TABLE IF NOT EXISTS primary_device (
                user_id INTEGER PRIMARY KEY,  -- one primary per user (the <user>.<community> alias)
                pubkey  BLOB    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oauth_authorized (
                pubkey  BLOB    PRIMARY KEY,  -- device pubkey bound to a user via interactive login
                user_id INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS guild_rotation_certs (
                idx      INTEGER PRIMARY KEY AUTOINCREMENT,  -- issuance order (oldest→newest)
                guild_id INTEGER NOT NULL,                   -- the guild whose key was rotated
                cert     TEXT    NOT NULL                    -- base64 Signed<RotationCert> (prev→new)
            );
            "#,
        )
        .execute(&self.pool)
        .await?;
        // Add the token column to devices tables created before it existed (ignore if present).
        let _ = sqlx::query("ALTER TABLE devices ADD COLUMN token TEXT")
            .execute(&self.pool)
            .await;
        // Retain the historical ratchet column for schema compatibility. Current releases require a
        // valid token for every enrolled row and deliberately ignore this former grace flag.
        let _ =
            sqlx::query("ALTER TABLE devices ADD COLUMN token_proven INTEGER NOT NULL DEFAULT 0")
                .execute(&self.pool)
                .await;
        Ok(())
    }

    /// A deployment-stable random seed, generated + persisted once. Not a signing key — it only
    /// picks the default mesh `/16` (see `netid::default_cidr`) so the range is stable across
    /// restarts now that signing keys are per-guild (§3.1) and no single key spans the deployment.
    pub async fn load_or_create_deployment_seed(&self) -> anyhow::Result<[u8; 32]> {
        if let Some(row) = sqlx::query("SELECT seed FROM deployment_seed WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?
        {
            let seed: Vec<u8> = row.try_get("seed")?;
            return seed
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored deployment seed is not 32 bytes"));
        }
        let seed = common::crypto::CoordinatorKey::generate().to_seed();
        sqlx::query("INSERT INTO deployment_seed (id, seed) VALUES (1, ?)")
            .bind(seed.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(seed)
    }

    /// A deployment-stable X25519 secret for the device enrollment possession proof, generated +
    /// persisted once. Its public half is published (`GET /enroll/pubkey`); a client combines that
    /// with its WG private key to prove possession at enrollment (`common::crypto::enroll_proof`).
    /// Stable across restarts so a proof a client built against a fetched pubkey stays verifiable.
    pub async fn load_or_create_enroll_seed(&self) -> anyhow::Result<[u8; 32]> {
        if let Some(row) = sqlx::query("SELECT seed FROM enroll_key WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?
        {
            let seed: Vec<u8> = row.try_get("seed")?;
            return seed
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored enroll seed is not 32 bytes"));
        }
        let (seed, _) = common::crypto::gen_wg_keypair();
        sqlx::query("INSERT INTO enroll_key (id, seed) VALUES (1, ?)")
            .bind(seed.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(seed)
    }

    /// Load a guild's signing seed, or generate + persist one on first use — so each guild's key is
    /// independently generated on first contact (design.md §3.1), not derived from a shared secret.
    pub async fn load_or_create_seed(&self, guild_id: u64) -> anyhow::Result<[u8; 32]> {
        if let Some(row) = sqlx::query("SELECT seed FROM guild_signing_keys WHERE guild_id = ?")
            .bind(guild_id as i64)
            .fetch_optional(&self.pool)
            .await?
        {
            let seed: Vec<u8> = row.try_get("seed")?;
            return seed
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored signing seed is not 32 bytes"));
        }
        let seed = common::crypto::CoordinatorKey::generate().to_seed();
        sqlx::query("INSERT INTO guild_signing_keys (guild_id, seed) VALUES (?, ?)")
            .bind(guild_id as i64)
            .bind(seed.as_slice())
            .execute(&self.pool)
            .await?;
        tracing::info!(guild_id, "generated new signing key for guild");
        Ok(seed)
    }

    /// Replace a guild's signing seed (trust-anchor rotation). The caller must first append the
    /// `prev → new` rotation cert via [`Store::append_rotation_cert`] so clients can follow.
    pub async fn replace_seed(&self, guild_id: u64, seed: &[u8; 32]) -> anyhow::Result<()> {
        sqlx::query("INSERT OR REPLACE INTO guild_signing_keys (guild_id, seed) VALUES (?, ?)")
            .bind(guild_id as i64)
            .bind(seed.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Append a rotation cert (base64 `Signed<RotationCert>`) to a guild's chain.
    pub async fn append_rotation_cert(&self, guild_id: u64, cert_b64: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO guild_rotation_certs (guild_id, cert) VALUES (?, ?)")
            .bind(guild_id as i64)
            .bind(cert_b64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// A guild's rotation-cert chain (base64), oldest→newest, for clients to re-pin across rotations.
    pub async fn rotation_chain(&self, guild_id: u64) -> anyhow::Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT cert FROM guild_rotation_certs WHERE guild_id = ? ORDER BY idx ASC",
        )
        .bind(guild_id as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("cert"))
            .collect())
    }

    // ---- network registry (managed by admin slash commands; seeded in tests) ----

    pub async fn upsert_network(
        &self,
        guild_id: u64,
        role_id: u64,
        name: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO networks (guild_id, role_id, name) VALUES (?, ?, ?)
             ON CONFLICT (guild_id, role_id) DO UPDATE SET name = excluded.name",
        )
        .bind(guild_id as i64)
        .bind(role_id as i64)
        .bind(name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Used by the `/unitylan network remove` slash-command handler.
    pub async fn remove_network(&self, guild_id: u64, role_id: u64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM networks WHERE guild_id = ? AND role_id = ?")
            .bind(guild_id as i64)
            .bind(role_id as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Used by the `/unitylan network revoke|list` slash-command handlers.
    pub async fn networks_in_guild(&self, guild_id: u64) -> anyhow::Result<Vec<Network>> {
        let rows = sqlx::query("SELECT role_id, name FROM networks WHERE guild_id = ?")
            .bind(guild_id as i64)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| Network {
                guild_id,
                role_id: r.get::<i64, _>("role_id") as u64,
                name: r.get::<String, _>("name"),
            })
            .collect())
    }

    pub async fn all_networks(&self) -> anyhow::Result<Vec<Network>> {
        let rows = sqlx::query("SELECT guild_id, role_id, name FROM networks")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| Network {
                guild_id: r.get::<i64, _>("guild_id") as u64,
                role_id: r.get::<i64, _>("role_id") as u64,
                name: r.get::<String, _>("name"),
            })
            .collect())
    }

    /// Total enrolled devices (persistent registrations across all guilds). Devices aren't
    /// guild-scoped (Model B: one identity across a coordinator's guilds), so this is a single
    /// deployment-wide count. Powers the admin dashboard's "enrolled" figure.
    pub async fn count_devices(&self) -> anyhow::Result<u64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM devices")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("n") as u64)
    }

    /// Guilds this coordinator has ever contacted — one signing-key row is created per guild on
    /// first use (§3.1). The admin dashboard's "servers installed on" figure; a superset of guilds
    /// with registered networks (a guild may have a key but no network yet).
    pub async fn guild_ids(&self) -> anyhow::Result<Vec<u64>> {
        let rows = sqlx::query("SELECT guild_id FROM guild_signing_keys")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<i64, _>("guild_id") as u64)
            .collect())
    }

    // ---- interactive login (OAuth) device binding ----

    /// Bind a device pubkey to a user id (set by the OAuth callback). Idempotent.
    pub async fn bind_oauth(&self, pubkey: &[u8; 32], user_id: u64) -> anyhow::Result<()> {
        sqlx::query("INSERT OR REPLACE INTO oauth_authorized (pubkey, user_id) VALUES (?, ?)")
            .bind(pubkey.as_slice())
            .bind(user_id as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The user a device pubkey was bound to via interactive login, if any.
    pub async fn oauth_user(&self, pubkey: &[u8; 32]) -> anyhow::Result<Option<u64>> {
        let row = sqlx::query("SELECT user_id FROM oauth_authorized WHERE pubkey = ?")
            .bind(pubkey.as_slice())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<i64, _>("user_id") as u64))
    }

    // ---- community slug (the <community> DNS label; admin-set, defaults to guild name) ----

    pub async fn set_community_slug(&self, guild_id: u64, slug: &str) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO communities (guild_id, slug) VALUES (?, ?)
             ON CONFLICT (guild_id) DO UPDATE SET slug = excluded.slug",
        )
        .bind(guild_id as i64)
        .bind(slug)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn community_slug(&self, guild_id: u64) -> anyhow::Result<Option<String>> {
        let row = sqlx::query("SELECT slug FROM communities WHERE guild_id = ?")
            .bind(guild_id as i64)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("slug")))
    }

    // ---- device IP allocation (one /32 per device, keyed by WG pubkey) ----

    /// Return the device's stable `/32` **and its authoritative name**, allocating both on first
    /// sight. The `device_name` argument only *seeds* the name on first enrollment (deduplicated
    /// against the owner's other devices, see [`Store::unique_device_name`]); a known device keeps
    /// its stored name so a `/manage` rename sticks. (Register re-asserts the engine's
    /// config-derived name on every refresh; honoring it here would clobber the rename within one
    /// refresh interval.) Callers should build the attestation/DNS hostname from the returned name,
    /// not the request's, so the two never diverge. After enrollment, `rename_device` is the
    /// authoritative way to change the name.
    pub async fn allocate_device(
        &self,
        net: Ipv4Net,
        pubkey: &[u8; 32],
        user_id: u64,
        device_name: &str,
    ) -> anyhow::Result<(Ipv4Addr, String)> {
        if let Some(row) = sqlx::query("SELECT idx, device_name FROM devices WHERE pubkey = ?")
            .bind(pubkey.as_slice())
            .fetch_optional(&self.pool)
            .await?
        {
            let ip = addr_from_index(&net, row.get::<i64, _>("idx") as u32);
            return Ok((ip, row.get::<String, _>("device_name")));
        }

        // A new row for this pubkey: enforce the per-account cap before consuming an address, so one
        // account can't loop fresh-key enrollments to exhaust the mesh space.
        let owned = sqlx::query("SELECT COUNT(*) AS n FROM devices WHERE user_id = ?")
            .bind(user_id as i64)
            .fetch_one(&self.pool)
            .await?
            .get::<i64, _>("n") as u64;
        if owned >= MAX_DEVICES_PER_USER {
            anyhow::bail!("device limit reached for this account (max {MAX_DEVICES_PER_USER})");
        }

        let taken: BTreeSet<u32> = sqlx::query("SELECT idx FROM devices")
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|r| r.get::<i64, _>("idx") as u32)
            .collect();

        let idx = pick_free_index(&net, &taken, device_hint(&net, pubkey))
            .ok_or_else(|| anyhow::anyhow!("mesh address space {net} exhausted"))?;
        // No existing row for this pubkey yet, so nothing to exclude from the dedup.
        let name = self.unique_device_name(user_id, device_name, None).await?;

        sqlx::query(
            "INSERT INTO devices (pubkey, idx, user_id, device_name, token) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(pubkey.as_slice())
        .bind(idx as i64)
        .bind(user_id as i64)
        .bind(&name)
        .bind(common::crypto::gen_enrollment_key())
        .execute(&self.pool)
        .await?;
        Ok((addr_from_index(&net, idx), name))
    }

    /// Disambiguate `desired` against the owner's *other* devices: return it unchanged if free,
    /// else the first available `desired-2`, `desired-3`, … suffix (kept within the 63-char DNS
    /// label cap by trimming the stem). `exclude` is the device being (re)named — its own current
    /// name never counts as a collision. Keeps names unique per owner so DNS
    /// (`<device>.<user>.<community>`) resolves unambiguously and name-based management never hits
    /// the "multiple devices named …" path. Assumes `desired` is already `sanitize_label`-normalized
    /// (ASCII `[a-z0-9-]`), so byte-slicing the stem is char-boundary safe.
    async fn unique_device_name(
        &self,
        user_id: u64,
        desired: &str,
        exclude: Option<&[u8; 32]>,
    ) -> anyhow::Result<String> {
        let taken: std::collections::HashSet<String> =
            sqlx::query("SELECT pubkey, device_name FROM devices WHERE user_id = ?")
                .bind(user_id as i64)
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .filter(|r| match exclude {
                    Some(ex) => r.get::<Vec<u8>, _>("pubkey").as_slice() != ex.as_slice(),
                    None => true,
                })
                .map(|r| r.get::<String, _>("device_name"))
                .collect();

        if !taken.contains(desired) {
            return Ok(desired.to_string());
        }
        // At most `taken.len()` names are in the way, so a free suffix exists within that many tries.
        for n in 2..=taken.len() + 2 {
            let suffix = format!("-{n}");
            let stem = &desired[..desired.len().min(63 - suffix.len())];
            let candidate = format!("{stem}{suffix}");
            if !taken.contains(&candidate) {
                return Ok(candidate);
            }
        }
        unreachable!("a free suffix always exists within taken.len()+1 candidates")
    }

    /// The device's bearer token (minting one for a legacy row that predates the column).
    pub async fn device_token(&self, pubkey: &[u8; 32]) -> anyhow::Result<Option<String>> {
        let row = sqlx::query("SELECT token FROM devices WHERE pubkey = ?")
            .bind(pubkey.as_slice())
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else { return Ok(None) };
        if let Some(tok) = row.try_get::<Option<String>, _>("token")? {
            return Ok(Some(tok));
        }
        let tok = common::crypto::gen_enrollment_key();
        sqlx::query("UPDATE devices SET token = ? WHERE pubkey = ?")
            .bind(&tok)
            .bind(pubkey.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(Some(tok))
    }

    /// A device's stored bearer token. The outer `None` means no device row; the inner `None` is a
    /// legacy row that must re-enroll. Unlike
    /// [`Store::device_token`] this never mints a token: verification must not create one.
    pub async fn device_auth(&self, pubkey: &[u8; 32]) -> anyhow::Result<Option<Option<String>>> {
        let row = sqlx::query("SELECT token FROM devices WHERE pubkey = ?")
            .bind(pubkey.as_slice())
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(row.try_get("token")?))
    }

    /// Resolve a bearer token to (user_id, device pubkey).
    pub async fn device_by_token(&self, token: &str) -> anyhow::Result<Option<(u64, [u8; 32])>> {
        let row = sqlx::query("SELECT user_id, pubkey FROM devices WHERE token = ?")
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else { return Ok(None) };
        let user_id = row.get::<i64, _>("user_id") as u64;
        let pk = pubkey_from_blob(row.try_get("pubkey")?)?;
        Ok(Some((user_id, pk)))
    }

    /// Rename a device (by pubkey), deduplicating against the owner's other devices. Returns the
    /// name actually stored — `name` as given if free, else an auto-suffixed `name-2`/`name-3`/…
    /// (see [`Store::unique_device_name`]). `user_id` scopes the dedup to this owner.
    pub async fn rename_device(
        &self,
        user_id: u64,
        pubkey: &[u8; 32],
        name: &str,
    ) -> anyhow::Result<String> {
        let name = self.unique_device_name(user_id, name, Some(pubkey)).await?;
        sqlx::query("UPDATE devices SET device_name = ? WHERE pubkey = ?")
            .bind(&name)
            .bind(pubkey.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(name)
    }

    /// Remove a device. If it was the owner's primary, auto-promote another of their devices.
    pub async fn remove_device(&self, user_id: u64, pubkey: &[u8; 32]) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM devices WHERE pubkey = ? AND user_id = ?")
            .bind(pubkey.as_slice())
            .bind(user_id as i64)
            .execute(&self.pool)
            .await?;
        // If that was the primary pointer, promote another device (or clear it).
        if self.primary_pubkey(user_id).await? == Some(*pubkey) {
            match self.user_devices(user_id).await?.first() {
                Some((pk, _)) => self.set_primary(user_id, pk).await?,
                None => {
                    sqlx::query("DELETE FROM primary_device WHERE user_id = ?")
                        .bind(user_id as i64)
                        .execute(&self.pool)
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// The owner of an already-enrolled device, if its pubkey is bound.
    pub async fn device_owner(&self, pubkey: &[u8; 32]) -> anyhow::Result<Option<u64>> {
        let row = sqlx::query("SELECT user_id FROM devices WHERE pubkey = ?")
            .bind(pubkey.as_slice())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<i64, _>("user_id") as u64))
    }

    /// A user's devices, as (pubkey, device_name).
    pub async fn user_devices(&self, user_id: u64) -> anyhow::Result<Vec<([u8; 32], String)>> {
        let rows = sqlx::query("SELECT pubkey, device_name FROM devices WHERE user_id = ?")
            .bind(user_id as i64)
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::new();
        for r in rows {
            let pk = pubkey_from_blob(r.try_get("pubkey")?)?;
            out.push((pk, r.get::<String, _>("device_name")));
        }
        Ok(out)
    }

    // ---- primary device (one per user; backs the <user>.<community> alias) ----

    /// Make `pubkey` this user's primary device only if they don't have one yet (auto-assign on
    /// first enrollment).
    pub async fn ensure_primary(&self, user_id: u64, pubkey: &[u8; 32]) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO primary_device (user_id, pubkey) VALUES (?, ?)
             ON CONFLICT (user_id) DO NOTHING",
        )
        .bind(user_id as i64)
        .bind(pubkey.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Set (reassign) this user's primary device.
    pub async fn set_primary(&self, user_id: u64, pubkey: &[u8; 32]) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO primary_device (user_id, pubkey) VALUES (?, ?)
             ON CONFLICT (user_id) DO UPDATE SET pubkey = excluded.pubkey",
        )
        .bind(user_id as i64)
        .bind(pubkey.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// This user's primary device pubkey, if set.
    pub async fn primary_pubkey(&self, user_id: u64) -> anyhow::Result<Option<[u8; 32]>> {
        let row = sqlx::query("SELECT pubkey FROM primary_device WHERE user_id = ?")
            .bind(user_id as i64)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(pubkey_from_blob(r.try_get("pubkey")?)?)),
        }
    }

    // ---- enrollment keys (one-time; bind a new device's pubkey to its owner) ----

    /// Insert (or refresh) a one-time enrollment key for a user. `expires_at` is optional.
    pub async fn create_enrollment_key(
        &self,
        key: &str,
        user_id: u64,
        expires_at: Option<u64>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO enrollment_keys (key, user_id, expires_at, used_by) VALUES (?, ?, ?, NULL)
             ON CONFLICT (key) DO UPDATE SET user_id = excluded.user_id, expires_at = excluded.expires_at",
        )
        .bind(key)
        .bind(user_id as i64)
        .bind(expires_at.map(|e| e as i64))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Consume a one-time enrollment key for `pubkey`, returning the bound user id. Idempotent if
    /// re-presented by the same device. Errors if unknown, expired, or already used by another.
    pub async fn consume_enrollment_key(
        &self,
        key: &str,
        pubkey: &[u8; 32],
        now: u64,
    ) -> anyhow::Result<u64> {
        let row =
            sqlx::query("SELECT user_id, expires_at, used_by FROM enrollment_keys WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| anyhow::anyhow!("unknown enrollment key"))?;

        let user_id = row.get::<i64, _>("user_id") as u64;

        // Claim the key in one statement, gating on both `used_by IS NULL` and non-expiry so no
        // window exists between reading the key and binding it. SQLite serializes writers, so of two
        // concurrent registers with distinct pubkeys exactly one UPDATE matches a row; the loser
        // matches zero. `rows_affected() == 1` — not the mere fact that the UPDATE ran — is what
        // proves *we* claimed it, which the previous code failed to check (it returned Ok
        // unconditionally, letting a losing racer enrol a second device under the victim's user).
        let claimed = sqlx::query(
            "UPDATE enrollment_keys SET used_by = ? \
             WHERE key = ? AND used_by IS NULL AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(pubkey.as_slice())
        .bind(key)
        .bind(now as i64)
        .execute(&self.pool)
        .await?
        .rows_affected()
            == 1;
        if claimed {
            return Ok(user_id);
        }

        // The claim matched nothing: the key was already bound, or it has expired. Distinguish the
        // two from the row we already read — and stay idempotent when the same device re-presents a
        // key it already holds (checked before expiry, matching the prior behaviour).
        match row.try_get::<Option<Vec<u8>>, _>("used_by")? {
            Some(used) if used.as_slice() == pubkey.as_slice() => Ok(user_id),
            Some(_) => Err(anyhow::anyhow!("enrollment key already used")),
            None => Err(anyhow::anyhow!("enrollment key expired")),
        }
    }
}

#[cfg(all(test, unix))]
mod security_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[tokio::test]
    async fn database_is_created_private_and_symlinks_are_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "unitylan-db-security-{}-{}",
            std::process::id(),
            common::crypto::gen_enrollment_key()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("coordinator.db");
        let store = Store::open(&db).await.unwrap();
        drop(store);
        assert_eq!(
            std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let target = dir.join("target.db");
        std::fs::write(&target, b"untouched").unwrap();
        let link = dir.join("linked.db");
        symlink(&target, &link).unwrap();
        assert!(Store::open(&link).await.is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test mesh CIDR for allocation calls.
    fn tnet() -> Ipv4Net {
        "100.72.0.0/16".parse().unwrap()
    }

    #[tokio::test]
    async fn guild_seeds_are_independent_and_stable() {
        let st = Store::memory().await;
        // First use generates + persists a seed; re-loading returns the same one (stable per guild).
        let a1 = st.load_or_create_seed(1).await.unwrap();
        let a2 = st.load_or_create_seed(1).await.unwrap();
        assert_eq!(a1, a2, "a guild's seed must be stable across loads");
        // A different guild gets an independently-generated seed (§3.1 — not derived from another).
        let b1 = st.load_or_create_seed(2).await.unwrap();
        assert_ne!(a1, b1, "distinct guilds must have distinct seeds");
        // Rotation is scoped to one guild: replacing guild 1's seed leaves guild 2 untouched.
        st.replace_seed(1, &[7u8; 32]).await.unwrap();
        assert_eq!(st.load_or_create_seed(1).await.unwrap(), [7u8; 32]);
        assert_eq!(st.load_or_create_seed(2).await.unwrap(), b1);
    }

    #[tokio::test]
    async fn enrollment_key_is_one_time_and_binds_device() {
        let st = Store::memory().await;
        st.create_enrollment_key("k", 42, None).await.unwrap();
        let dev_a = [1u8; 32];
        let dev_b = [2u8; 32];

        // First device consumes it and gets the owner.
        assert_eq!(st.consume_enrollment_key("k", &dev_a, 0).await.unwrap(), 42);
        // Same device re-presenting is idempotent.
        assert_eq!(st.consume_enrollment_key("k", &dev_a, 0).await.unwrap(), 42);
        // A different device is rejected.
        assert!(st.consume_enrollment_key("k", &dev_b, 0).await.is_err());
        // Unknown key is rejected.
        assert!(st.consume_enrollment_key("nope", &dev_b, 0).await.is_err());
    }

    #[tokio::test]
    async fn expired_key_rejected() {
        let st = Store::memory().await;
        st.create_enrollment_key("k", 7, Some(100)).await.unwrap();
        assert!(st
            .consume_enrollment_key("k", &[3u8; 32], 100)
            .await
            .is_err());
        assert_eq!(
            st.consume_enrollment_key("k", &[3u8; 32], 99)
                .await
                .unwrap(),
            7
        );
    }

    // A one-time key must bind exactly one device even when several registers race it. The three
    // consumes interleave at each connection-acquire await, so the claim has to be atomic: the old
    // SELECT-check-then-UPDATE let every racer that read `used_by IS NULL` before any UPDATE return
    // Ok, enrolling multiple devices from a single key.
    #[tokio::test]
    async fn enrollment_key_claim_is_atomic_under_race() {
        let st = Store::memory().await;
        st.create_enrollment_key("k", 5, None).await.unwrap();
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let (ra, rb, rc) = tokio::join!(
            st.consume_enrollment_key("k", &a, 0),
            st.consume_enrollment_key("k", &b, 0),
            st.consume_enrollment_key("k", &c, 0),
        );
        let oks = [ra, rb, rc].into_iter().filter(Result::is_ok).count();
        assert_eq!(oks, 1, "exactly one racer may claim a one-time key");
    }

    #[tokio::test]
    async fn primary_auto_assigns_then_reassigns() {
        let st = Store::memory().await;
        let a = [1u8; 32];
        let b = [2u8; 32];
        st.allocate_device(tnet(), &a, 9, "laptop").await.unwrap();
        st.allocate_device(tnet(), &b, 9, "phone").await.unwrap();

        // First device auto-becomes primary; enrolling a second doesn't steal it.
        st.ensure_primary(9, &a).await.unwrap();
        st.ensure_primary(9, &b).await.unwrap();
        assert_eq!(st.primary_pubkey(9).await.unwrap(), Some(a));

        // Owner reassigns to the second device.
        st.set_primary(9, &b).await.unwrap();
        assert_eq!(st.primary_pubkey(9).await.unwrap(), Some(b));

        let names: Vec<String> = st
            .user_devices(9)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, n)| n)
            .collect();
        assert_eq!(names.len(), 2);
    }

    #[tokio::test]
    async fn token_auth_rename_and_remove_autopromote() {
        let st = Store::memory().await;
        let a = [1u8; 32];
        let b = [2u8; 32];
        st.allocate_device(tnet(), &a, 5, "laptop").await.unwrap();
        st.allocate_device(tnet(), &b, 5, "phone").await.unwrap();
        st.ensure_primary(5, &a).await.unwrap();

        // Token resolves back to (user, device); unknown token → None.
        let tok_a = st.device_token(&a).await.unwrap().unwrap();
        assert_eq!(st.device_by_token(&tok_a).await.unwrap(), Some((5, a)));
        assert_eq!(st.device_by_token("bogus").await.unwrap(), None);

        // Rename the requesting device.
        st.rename_device(5, &a, "workstation").await.unwrap();
        let names: Vec<String> = st
            .user_devices(5)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, n)| n)
            .collect();
        assert!(names.contains(&"workstation".to_string()));

        // A subsequent register (which re-sends the engine's config-derived name) must NOT clobber
        // the rename — otherwise the GUI rename reverts within one refresh interval.
        st.allocate_device(tnet(), &a, 5, "device").await.unwrap();
        let name = st
            .user_devices(5)
            .await
            .unwrap()
            .into_iter()
            .find(|(pk, _)| *pk == a)
            .map(|(_, n)| n);
        assert_eq!(
            name.as_deref(),
            Some("workstation"),
            "rename must survive re-register"
        );

        // Removing the primary auto-promotes the remaining device.
        st.remove_device(5, &a).await.unwrap();
        assert_eq!(st.primary_pubkey(5).await.unwrap(), Some(b));
        assert_eq!(st.user_devices(5).await.unwrap().len(), 1);

        // Removing the last device clears the primary pointer.
        st.remove_device(5, &b).await.unwrap();
        assert_eq!(st.primary_pubkey(5).await.unwrap(), None);
    }

    #[tokio::test]
    async fn device_auth_reports_token_and_rejectable_legacy_rows() {
        let st = Store::memory().await;
        let a = [7u8; 32];
        st.allocate_device(tnet(), &a, 5, "laptop").await.unwrap();

        // A freshly enrolled device has a token (minted on first read).
        let tok = st.device_token(&a).await.unwrap().unwrap();
        let stored = st.device_auth(&a).await.unwrap().unwrap();
        assert_eq!(stored.as_deref(), Some(tok.as_str()));

        // No such device → None.
        assert!(st.device_auth(&[9u8; 32]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn device_ip_is_stable_per_pubkey() {
        let st = Store::memory().await;
        let (a, _) = st
            .allocate_device(tnet(), &[1u8; 32], 1, "laptop")
            .await
            .unwrap();
        let (a2, _) = st
            .allocate_device(tnet(), &[1u8; 32], 1, "laptop")
            .await
            .unwrap();
        let (b, _) = st
            .allocate_device(tnet(), &[2u8; 32], 1, "phone")
            .await
            .unwrap();
        assert_eq!(a, a2, "same device pubkey → same IP");
        assert_ne!(a, b, "same user's two devices → distinct IPs");
        assert_eq!(st.device_owner(&[1u8; 32]).await.unwrap(), Some(1));
    }

    #[tokio::test]
    async fn device_cap_bounds_a_single_account() {
        let st = Store::memory().await;
        // Fill the account to the cap: each distinct pubkey is a new row + IP.
        for i in 0..MAX_DEVICES_PER_USER {
            let mut pk = [0u8; 32];
            pk[..8].copy_from_slice(&i.to_le_bytes());
            st.allocate_device(tnet(), &pk, 1, "dev").await.unwrap();
        }
        // One more distinct key for the same user is refused, so an account can't loop enrollments
        // to exhaust the mesh space.
        assert!(st
            .allocate_device(tnet(), &[0xff; 32], 1, "dev")
            .await
            .is_err());
        // An already-allocated pubkey still resolves (idempotent, no new row) even at the cap.
        let mut first = [0u8; 32];
        first[..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(st.allocate_device(tnet(), &first, 1, "dev").await.is_ok());
        // A different account is a separate budget — unaffected by the first user's cap.
        assert!(st
            .allocate_device(tnet(), &[0xfe; 32], 2, "dev")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn duplicate_device_names_are_auto_suffixed() {
        let st = Store::memory().await;
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];

        // Two devices of one user asking for the same name: the first keeps it, the rest get a
        // per-owner-unique suffix — so DNS `<device>.<user>…` never collapses two devices to one A.
        let (_, na) = st.allocate_device(tnet(), &a, 7, "device").await.unwrap();
        let (_, nb) = st.allocate_device(tnet(), &b, 7, "device").await.unwrap();
        let (_, nc) = st.allocate_device(tnet(), &c, 7, "device").await.unwrap();
        assert_eq!(na, "device");
        assert_eq!(nb, "device-2");
        assert_eq!(nc, "device-3");

        // A different owner is a separate namespace — no suffix.
        let (_, other) = st
            .allocate_device(tnet(), &[4u8; 32], 8, "device")
            .await
            .unwrap();
        assert_eq!(other, "device");

        // Re-registering an existing device returns its stored name, never re-suffixing.
        let (_, na2) = st.allocate_device(tnet(), &a, 7, "device").await.unwrap();
        assert_eq!(na2, "device");

        // Renaming onto a taken name suffixes; renaming a device to its own name is a no-op (its
        // current name is excluded from the collision check, so no runaway `-2`).
        assert_eq!(st.rename_device(7, &c, "device").await.unwrap(), "device-3");
        assert_eq!(st.rename_device(7, &b, "laptop").await.unwrap(), "laptop");
        assert_eq!(st.rename_device(7, &c, "laptop").await.unwrap(), "laptop-2");
    }
}
