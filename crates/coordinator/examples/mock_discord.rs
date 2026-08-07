//! A stand-in for Discord's REST API that rate-limits the way Discord does, so
//! `coordinator-scale-test.sh` can measure what the per-request member fan-out costs at
//! scale. `FakeRoleSource` answers from config with no latency and no limit, which is exactly the
//! part that matters here — this serves the three routes `TwilightRoleSource` calls, with
//! `X-RateLimit-*` headers so twilight's own ratelimiter does its real work against it.
//!
//! Point a coordinator at it with `[discord] api_proxy = "http://127.0.0.1:<port>"` (debug builds
//! only) and read `/stats` afterwards for the observed call rate and 429 count.
//!
//! Membership model: user `u` is a member of guild `(u % guilds) + 1` and of no other, so a
//! deployment of `G` registered guilds costs every device `G` lookups to discover its one guild —
//! the walk in `build_snapshot`.
//!
//! Env: `PORT` `GUILDS` `GLOBAL_RPS` `PER_GUILD_RPS` `LATENCY_MS` `JITTER_MS` `ROLE_ID`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// One fixed-window bucket. Discord publishes a limit per window and a reset instant; twilight
/// reads both off the response and paces itself, so the window is what shapes client behaviour.
struct Window {
    limit: u64,
    used: u64,
    started: Instant,
}

impl Window {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            started: Instant::now(),
        }
    }

    /// Take one slot. `Ok(remaining, reset_after)` when allowed, `Err(retry_after)` when exhausted.
    fn take(&mut self) -> Result<(u64, f64), f64> {
        let elapsed = self.started.elapsed();
        if elapsed >= Duration::from_secs(1) {
            self.started = Instant::now();
            self.used = 0;
        }
        let reset_after =
            (Duration::from_secs(1).saturating_sub(self.started.elapsed())).as_secs_f64();
        if self.used >= self.limit {
            return Err(reset_after);
        }
        self.used += 1;
        Ok((self.limit - self.used, reset_after))
    }
}

/// A call the window let through.
struct Allowed {
    remaining: u64,
    reset_after: f64,
    bucket: String,
    limit: u64,
}

/// A call the window rejected — everything needed to emit a 429 a client can pace off.
struct Denied {
    retry_after: f64,
    global: bool,
    bucket: String,
    limit: u64,
}

#[derive(Default)]
struct Counters {
    /// Calls actually served (200 or 404). Rejected attempts are counted separately, so
    /// `member / devices` stays a measure of the *walk* rather than of retry behaviour.
    member: AtomicU64,
    /// Every member request that arrived, served or 429'd.
    member_attempts: AtomicU64,
    roles: AtomicU64,
    guild: AtomicU64,
    limited: AtomicU64,
    /// Highest number of calls observed inside any one-second window, across all routes.
    peak_rps: AtomicU64,
}

struct Rate {
    /// Calls in the current second, and when that second began — feeds `peak_rps`.
    second: Mutex<(Instant, u64)>,
}

struct App {
    guilds: u64,
    role_id: u64,
    latency: Duration,
    jitter: Duration,
    global: Mutex<Window>,
    /// Per-guild windows for the member route — Discord buckets that route per guild.
    per_guild: Mutex<HashMap<u64, Window>>,
    per_guild_rps: u64,
    counters: Counters,
    rate: Rate,
    started: Instant,
}

impl App {
    /// Charge one call against the global window and (for the member route) the guild's own.
    /// The bucket id and limit come back either way — a 429 that names its bucket is what lets a
    /// client pace instead of retry.
    fn charge(&self, bucket: &str, guild_id: Option<u64>) -> Result<Allowed, Denied> {
        // Take the limit out under the same guard as the charge: re-locking inside the failure arm
        // would deadlock, because the scrutinee's guard is still alive there.
        let global = {
            let mut window = self.global.lock().unwrap();
            window.take().map_err(|retry| (retry, window.limit))
        };
        if let Err((retry, limit)) = global {
            self.counters.limited.fetch_add(1, Ordering::Relaxed);
            return Err(Denied {
                retry_after: retry,
                global: true,
                bucket: bucket.to_string(),
                limit,
            });
        }
        let Some(guild_id) = guild_id else {
            return Ok(Allowed {
                remaining: 0,
                reset_after: 0.0,
                bucket: bucket.to_string(),
                limit: self.per_guild_rps,
            });
        };
        let mut per_guild = self.per_guild.lock().unwrap();
        let window = per_guild
            .entry(guild_id)
            .or_insert_with(|| Window::new(self.per_guild_rps));
        match window.take() {
            Ok((remaining, reset_after)) => Ok(Allowed {
                remaining,
                reset_after,
                bucket: bucket.to_string(),
                limit: self.per_guild_rps,
            }),
            Err(retry) => {
                self.counters.limited.fetch_add(1, Ordering::Relaxed);
                Err(Denied {
                    retry_after: retry,
                    global: false,
                    bucket: bucket.to_string(),
                    limit: self.per_guild_rps,
                })
            }
        }
    }

    /// Record one served call and update the peak observed calls-per-second.
    fn tick(&self) {
        let mut second = self.rate.second.lock().unwrap();
        if second.0.elapsed() >= Duration::from_secs(1) {
            *second = (Instant::now(), 0);
        }
        second.1 += 1;
        let now = second.1;
        drop(second);
        self.counters.peak_rps.fetch_max(now, Ordering::Relaxed);
    }

    /// Discord's round trip isn't free, and the time a lookup holds a snapshot slot is the whole
    /// point of the measurement. Jitter is derived from the counter rather than a RNG so runs stay
    /// reproducible.
    async fn delay(&self) {
        let n = self.counters.member.load(Ordering::Relaxed);
        let jitter = if self.jitter.is_zero() {
            Duration::ZERO
        } else {
            Duration::from_micros(n % (self.jitter.as_micros() as u64).max(1))
        };
        tokio::time::sleep(self.latency + jitter).await;
    }

    fn member_of(&self, user_id: u64) -> u64 {
        (user_id % self.guilds) + 1
    }
}

fn header_map(pairs: &[(&str, String)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        if let (Ok(name), Ok(value)) = (
            HeaderName::try_from(*name),
            HeaderValue::from_str(value.as_str()),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}

/// The 429 Discord sends, with the headers twilight keys its backoff off. The bucket id matters as
/// much as the delay: without it a client cannot attribute the rejection to a route and will retry
/// blind rather than pace itself, which shows up as call amplification that Discord would not
/// actually produce.
fn limited(
    retry_after: f64,
    global: bool,
    bucket: Option<String>,
    limit: u64,
) -> axum::response::Response {
    let mut pairs = vec![
        ("retry-after", format!("{retry_after:.3}")),
        ("x-ratelimit-reset-after", format!("{retry_after:.3}")),
        ("x-ratelimit-remaining", "0".to_string()),
        ("x-ratelimit-limit", limit.to_string()),
        ("x-ratelimit-global", global.to_string()),
        (
            "x-ratelimit-scope",
            if global { "global" } else { "user" }.to_string(),
        ),
    ];
    if let Some(bucket) = bucket {
        pairs.push(("x-ratelimit-bucket", bucket));
    }
    let headers = header_map(&pairs);
    (
        StatusCode::TOO_MANY_REQUESTS,
        headers,
        Json(json!({
            "message": "You are being rate limited.",
            "retry_after": retry_after,
            "global": global,
        })),
    )
        .into_response()
}

fn ok(
    body: Value,
    remaining: u64,
    reset_after: f64,
    bucket: String,
    limit: u64,
) -> axum::response::Response {
    let headers = header_map(&[
        ("x-ratelimit-bucket", bucket),
        // Without a limit twilight cannot size the bucket, so it paces off `remaining` alone and
        // ends up retrying into a closed window instead of waiting for it to open.
        ("x-ratelimit-limit", limit.to_string()),
        ("x-ratelimit-remaining", remaining.to_string()),
        ("x-ratelimit-reset-after", format!("{reset_after:.3}")),
    ]);
    (StatusCode::OK, headers, Json(body)).into_response()
}

/// `GET /guilds/{guild}/members/{user}` — the call this whole harness exists to count.
async fn member(
    State(app): State<Arc<App>>,
    Path((guild_id, user_id)): Path<(u64, u64)>,
) -> axum::response::Response {
    app.counters.member_attempts.fetch_add(1, Ordering::Relaxed);
    app.tick();
    let allowed = match app.charge(&format!("member-{guild_id}"), Some(guild_id)) {
        Ok(v) => v,
        Err(d) => return limited(d.retry_after, d.global, Some(d.bucket), d.limit),
    };
    app.counters.member.fetch_add(1, Ordering::Relaxed);
    app.delay().await;
    if app.member_of(user_id) != guild_id {
        // Discord's "Unknown Member" — the answer for most (user, guild) pairs in this model, and
        // the one the coordinator pays for on every guild the user *isn't* in.
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "message": "Unknown Member", "code": 10007 })),
        )
            .into_response();
    }
    ok(
        member_json(user_id, app.role_id),
        allowed.remaining,
        allowed.reset_after,
        allowed.bucket,
        allowed.limit,
    )
}

async fn roles(State(app): State<Arc<App>>, Path(guild_id): Path<u64>) -> axum::response::Response {
    app.counters.roles.fetch_add(1, Ordering::Relaxed);
    app.tick();
    let allowed = match app.charge(&format!("roles-{guild_id}"), Some(guild_id)) {
        Ok(v) => v,
        Err(d) => return limited(d.retry_after, d.global, Some(d.bucket), d.limit),
    };
    app.delay().await;
    ok(
        json!([
            role_json(app.role_id, "mesh"),
            role_json(guild_id * 1000, "@everyone")
        ]),
        allowed.remaining,
        allowed.reset_after,
        allowed.bucket,
        allowed.limit,
    )
}

async fn guild(State(app): State<Arc<App>>, Path(guild_id): Path<u64>) -> axum::response::Response {
    app.counters.guild.fetch_add(1, Ordering::Relaxed);
    app.tick();
    let allowed = match app.charge(&format!("guild-{guild_id}"), Some(guild_id)) {
        Ok(v) => v,
        Err(d) => return limited(d.retry_after, d.global, Some(d.bucket), d.limit),
    };
    app.delay().await;
    ok(
        guild_json(guild_id),
        allowed.remaining,
        allowed.reset_after,
        allowed.bucket,
        allowed.limit,
    )
}

async fn stats(State(app): State<Arc<App>>) -> Json<Value> {
    let elapsed = app.started.elapsed().as_secs_f64().max(0.001);
    let member = app.counters.member.load(Ordering::Relaxed);
    let roles = app.counters.roles.load(Ordering::Relaxed);
    let guild = app.counters.guild.load(Ordering::Relaxed);
    Json(json!({
        "member_calls": member,
        "member_attempts": app.counters.member_attempts.load(Ordering::Relaxed),
        "role_calls": roles,
        "guild_calls": guild,
        "rate_limited": app.counters.limited.load(Ordering::Relaxed),
        "peak_rps": app.counters.peak_rps.load(Ordering::Relaxed),
        "elapsed_secs": elapsed,
        "mean_rps": (member + roles + guild) as f64 / elapsed,
    }))
}

fn member_json(user_id: u64, role_id: u64) -> Value {
    json!({
        "user": {
            "id": user_id.to_string(),
            "username": format!("user-{user_id}"),
            "discriminator": "0",
            "global_name": Value::Null,
            "avatar": Value::Null,
        },
        "nick": Value::Null,
        "avatar": Value::Null,
        "roles": [role_id.to_string()],
        "joined_at": "2020-01-01T00:00:00.000000+00:00",
        "premium_since": Value::Null,
        "deaf": false,
        "mute": false,
        "flags": 0,
        "pending": false,
    })
}

fn role_json(role_id: u64, name: &str) -> Value {
    json!({
        "id": role_id.to_string(),
        "name": name,
        "color": 0,
        "colors": {
            "primary_color": 0,
            "secondary_color": Value::Null,
            "tertiary_color": Value::Null,
        },
        "hoist": false,
        "position": 1,
        "permissions": "0",
        "managed": false,
        "mentionable": false,
        "flags": 0,
    })
}

fn guild_json(guild_id: u64) -> Value {
    json!({
        "id": guild_id.to_string(),
        "name": format!("guild-{guild_id}"),
        "icon": Value::Null,
        "splash": Value::Null,
        "discovery_splash": Value::Null,
        "owner_id": "1",
        "afk_channel_id": Value::Null,
        "afk_timeout": 300,
        "verification_level": 1,
        "default_message_notifications": 0,
        "explicit_content_filter": 0,
        "roles": [role_json(10, "mesh")],
        "emojis": [],
        "features": [],
        "mfa_level": 0,
        "application_id": Value::Null,
        "system_channel_id": Value::Null,
        "system_channel_flags": 0,
        "rules_channel_id": Value::Null,
        "premium_tier": 0,
        "preferred_locale": "en-US",
        "public_updates_channel_id": Value::Null,
        "nsfw_level": 0,
        "premium_progress_bar_enabled": false,
        "safety_alerts_channel_id": Value::Null,
    })
}

fn env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Fail at startup rather than at measurement time: the coordinator swallows a deserialize error
/// (`.ok()?` in `discord.rs`) and just reports "not a member", which would silently turn a broken
/// mock into a plausible-looking benchmark.
fn self_check() -> anyhow::Result<()> {
    use twilight_model::guild::{Guild, Member, Role};
    serde_json::from_value::<Member>(member_json(1, 10))
        .map_err(|e| anyhow::anyhow!("member JSON does not parse as twilight Member: {e}"))?;
    serde_json::from_value::<Role>(role_json(10, "mesh"))
        .map_err(|e| anyhow::anyhow!("role JSON does not parse as twilight Role: {e}"))?;
    serde_json::from_value::<Guild>(guild_json(1))
        .map_err(|e| anyhow::anyhow!("guild JSON does not parse as twilight Guild: {e}"))?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    self_check()?;

    let port: u16 = env("PORT", 18081);
    let app = Arc::new(App {
        guilds: env("GUILDS", 1u64).max(1),
        role_id: env("ROLE_ID", 10u64),
        latency: Duration::from_millis(env("LATENCY_MS", 40u64)),
        jitter: Duration::from_millis(env("JITTER_MS", 20u64)),
        global: Mutex::new(Window::new(env("GLOBAL_RPS", 50u64))),
        per_guild: Mutex::new(HashMap::new()),
        per_guild_rps: env("PER_GUILD_RPS", 10u64),
        counters: Counters::default(),
        rate: Rate {
            second: Mutex::new((Instant::now(), 0)),
        },
        started: Instant::now(),
    });

    // twilight prefixes every request with `/api/v10`.
    let router = Router::new()
        .route("/api/v10/guilds/{guild_id}/members/{user_id}", get(member))
        .route("/api/v10/guilds/{guild_id}/roles", get(roles))
        .route("/api/v10/guilds/{guild_id}", get(guild))
        .route("/stats", get(stats))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(app.clone());

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!(
        "mock discord on 127.0.0.1:{port} guilds={} global_rps={} per_guild_rps={} latency={}ms",
        app.guilds,
        env("GLOBAL_RPS", 50u64),
        app.per_guild_rps,
        app.latency.as_millis()
    );
    axum::serve(listener, router).await?;
    Ok(())
}
