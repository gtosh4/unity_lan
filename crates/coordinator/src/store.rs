//! SQLite persistence: signing-key seed, network registry, per-device IP allocations.
//!
//! u64 Discord snowflakes are stored as i64 (bit-preserving cast) since SQLite lacks u64.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::Context;
use common::netid::{addr_from_index, device_hint, pick_free_index};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

/// A registered network = a role designated as a UnityLAN network.
#[derive(Clone, Debug)]
pub struct Network {
    pub guild_id: u64,
    pub role_id: u64,
    pub name: String,
}

pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .connect_with(opts)
            .await
            .with_context(|| format!("opening sqlite {}", path.display()))?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS signing_key (
                id   INTEGER PRIMARY KEY CHECK (id = 1),
                seed BLOB NOT NULL
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
                device_name TEXT    NOT NULL
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
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Load the signing seed, or generate + persist one on first run.
    pub async fn load_or_create_seed(&self) -> anyhow::Result<[u8; 32]> {
        if let Some(row) = sqlx::query("SELECT seed FROM signing_key WHERE id = 1")
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
        sqlx::query("INSERT INTO signing_key (id, seed) VALUES (1, ?)")
            .bind(seed.as_slice())
            .execute(&self.pool)
            .await?;
        tracing::info!("generated new signing key");
        Ok(seed)
    }

    // ---- network registry (managed by admin slash commands; seeded in tests) ----

    pub async fn upsert_network(&self, guild_id: u64, role_id: u64, name: &str) -> anyhow::Result<()> {
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

    // Used by the `/unitylan network remove|list` slash-command handler (wired with live bot).
    #[allow(dead_code)]
    pub async fn remove_network(&self, guild_id: u64, role_id: u64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM networks WHERE guild_id = ? AND role_id = ?")
            .bind(guild_id as i64)
            .bind(role_id as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[allow(dead_code)]
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

    /// Return the device's stable `/32`, allocating on first sight. The device_name is upserted
    /// so a rename is reflected on the next register.
    pub async fn allocate_device_ip(
        &self,
        pubkey: &[u8; 32],
        user_id: u64,
        device_name: &str,
    ) -> anyhow::Result<Ipv4Addr> {
        if let Some(row) = sqlx::query("SELECT idx FROM devices WHERE pubkey = ?")
            .bind(pubkey.as_slice())
            .fetch_optional(&self.pool)
            .await?
        {
            sqlx::query("UPDATE devices SET device_name = ? WHERE pubkey = ?")
                .bind(device_name)
                .bind(pubkey.as_slice())
                .execute(&self.pool)
                .await?;
            return Ok(addr_from_index(row.get::<i64, _>("idx") as u32));
        }

        let taken: BTreeSet<u32> = sqlx::query("SELECT idx FROM devices")
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|r| r.get::<i64, _>("idx") as u32)
            .collect();

        let idx = pick_free_index(&taken, device_hint(pubkey))
            .ok_or_else(|| anyhow::anyhow!("address space 100.64.0.0/10 exhausted"))?;

        sqlx::query("INSERT INTO devices (pubkey, idx, user_id, device_name) VALUES (?, ?, ?, ?)")
            .bind(pubkey.as_slice())
            .bind(idx as i64)
            .bind(user_id as i64)
            .bind(device_name)
            .execute(&self.pool)
            .await?;
        Ok(addr_from_index(idx))
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
            let pk: Vec<u8> = r.try_get("pubkey")?;
            let pk: [u8; 32] = pk
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored pubkey is not 32 bytes"))?;
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
            Some(r) => {
                let pk: Vec<u8> = r.try_get("pubkey")?;
                let pk: [u8; 32] = pk
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("stored pubkey is not 32 bytes"))?;
                Ok(Some(pk))
            }
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
        let row = sqlx::query("SELECT user_id, expires_at, used_by FROM enrollment_keys WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("unknown enrollment key"))?;

        let user_id = row.get::<i64, _>("user_id") as u64;
        let used_by: Option<Vec<u8>> = row.try_get("used_by")?;
        if let Some(used) = used_by {
            return if used.as_slice() == pubkey.as_slice() {
                Ok(user_id) // same device re-presenting — idempotent
            } else {
                Err(anyhow::anyhow!("enrollment key already used"))
            };
        }
        if let Some(exp) = row.try_get::<Option<i64>, _>("expires_at")? {
            if now >= exp as u64 {
                return Err(anyhow::anyhow!("enrollment key expired"));
            }
        }

        sqlx::query("UPDATE enrollment_keys SET used_by = ? WHERE key = ? AND used_by IS NULL")
            .bind(pubkey.as_slice())
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mem_store() -> Store {
        // Each :memory: db is private to its single connection.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = Store { pool };
        store.migrate().await.unwrap();
        store
    }

    #[tokio::test]
    async fn enrollment_key_is_one_time_and_binds_device() {
        let st = mem_store().await;
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
        let st = mem_store().await;
        st.create_enrollment_key("k", 7, Some(100)).await.unwrap();
        assert!(st.consume_enrollment_key("k", &[3u8; 32], 100).await.is_err());
        assert_eq!(st.consume_enrollment_key("k", &[3u8; 32], 99).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn primary_auto_assigns_then_reassigns() {
        let st = mem_store().await;
        let a = [1u8; 32];
        let b = [2u8; 32];
        st.allocate_device_ip(&a, 9, "laptop").await.unwrap();
        st.allocate_device_ip(&b, 9, "phone").await.unwrap();

        // First device auto-becomes primary; enrolling a second doesn't steal it.
        st.ensure_primary(9, &a).await.unwrap();
        st.ensure_primary(9, &b).await.unwrap();
        assert_eq!(st.primary_pubkey(9).await.unwrap(), Some(a));

        // Owner reassigns to the second device.
        st.set_primary(9, &b).await.unwrap();
        assert_eq!(st.primary_pubkey(9).await.unwrap(), Some(b));

        let names: Vec<String> = st.user_devices(9).await.unwrap().into_iter().map(|(_, n)| n).collect();
        assert_eq!(names.len(), 2);
    }

    #[tokio::test]
    async fn device_ip_is_stable_per_pubkey() {
        let st = mem_store().await;
        let a = st.allocate_device_ip(&[1u8; 32], 1, "laptop").await.unwrap();
        let a2 = st.allocate_device_ip(&[1u8; 32], 1, "laptop").await.unwrap();
        let b = st.allocate_device_ip(&[2u8; 32], 1, "phone").await.unwrap();
        assert_eq!(a, a2, "same device pubkey → same IP");
        assert_ne!(a, b, "same user's two devices → distinct IPs");
        assert_eq!(st.device_owner(&[1u8; 32]).await.unwrap(), Some(1));
    }
}
