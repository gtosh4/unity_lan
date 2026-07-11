//! SQLite persistence: signing-key seed, network registry, IP allocations.
//!
//! u64 Discord snowflakes are stored as i64 (bit-preserving cast) since SQLite lacks u64.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context;
use common::netid::pick_free_host;
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
            CREATE TABLE IF NOT EXISTS allocations (
                guild_id INTEGER NOT NULL,
                role_id  INTEGER NOT NULL,
                user_id  INTEGER NOT NULL,
                host     INTEGER NOT NULL,
                PRIMARY KEY (guild_id, role_id, user_id)
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

    // ---- allocations ----

    /// Return the member's stable host octet in a network, allocating on first request.
    pub async fn allocate_host(
        &self,
        guild_id: u64,
        role_id: u64,
        user_id: u64,
    ) -> anyhow::Result<u8> {
        if let Some(row) =
            sqlx::query("SELECT host FROM allocations WHERE guild_id=? AND role_id=? AND user_id=?")
                .bind(guild_id as i64)
                .bind(role_id as i64)
                .bind(user_id as i64)
                .fetch_optional(&self.pool)
                .await?
        {
            return Ok(row.get::<i64, _>("host") as u8);
        }

        let taken: BTreeSet<u8> =
            sqlx::query("SELECT host FROM allocations WHERE guild_id=? AND role_id=?")
                .bind(guild_id as i64)
                .bind(role_id as i64)
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|r| r.get::<i64, _>("host") as u8)
                .collect();

        let hint = common::netid::host_hint(user_id);
        let host = pick_free_host(&taken, hint)
            .ok_or_else(|| anyhow::anyhow!("network {guild_id}/{role_id} is full"))?;

        sqlx::query("INSERT INTO allocations (guild_id, role_id, user_id, host) VALUES (?, ?, ?, ?)")
            .bind(guild_id as i64)
            .bind(role_id as i64)
            .bind(user_id as i64)
            .bind(host as i64)
            .execute(&self.pool)
            .await?;
        Ok(host)
    }
}
