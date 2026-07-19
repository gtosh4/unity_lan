//! Operator admin surface (`/admin` dashboard + `/metrics`).

use std::collections::BTreeSet;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;

use super::wake::wait_for_change_until;
use super::{internal, ApiError, AppState};

/// One network's live count within a guild.
struct NetStat {
    role_id: u64,
    name: String,
    online: usize,
}

/// One guild's admin view: display name (falls back to the id) and its networks.
struct GuildStat {
    id: u64,
    name: Option<String>,
    networks: Vec<NetStat>,
}

/// A point-in-time operational snapshot for the admin surface. Assembled from the store (enrolled
/// devices, registered networks, guilds contacted), live presence (online counts), and the role
/// source (guild names). Read-only and off the client hot path — served only to the operator, on
/// rare admin requests, from cheap SQLite/in-memory reads plus cached guild-name lookups.
struct AdminStats {
    guilds: Vec<GuildStat>,
    total_networks: usize,
    online_devices: usize,
    online_users: usize,
    enrolled_devices: u64,
    longpoll_waiters: usize,
    version: u64,
}

async fn gather_stats(st: &AppState) -> Result<AdminStats, ApiError> {
    let networks = st.store.all_networks().await.map_err(internal)?;
    let enrolled_devices = st.store.count_devices().await.map_err(internal)?;
    let guild_ids = st.store.guild_ids().await.map_err(internal)?;
    let pres = st.presence.stats();

    // Guild set = guilds with a signing key ∪ guilds owning a network ∪ guilds with anyone online.
    let mut ids: BTreeSet<u64> = guild_ids.into_iter().collect();
    ids.extend(networks.iter().map(|n| n.guild_id));
    ids.extend(pres.online_per_network.keys().map(|(g, _)| *g));

    let mut guilds = Vec::with_capacity(ids.len());
    for id in ids {
        let name = st.roles.guild_name(id).await;
        let mut nets: Vec<NetStat> = networks
            .iter()
            .filter(|n| n.guild_id == id)
            .map(|n| NetStat {
                role_id: n.role_id,
                name: n.name.clone(),
                online: pres
                    .online_per_network
                    .get(&(id, n.role_id))
                    .copied()
                    .unwrap_or(0),
            })
            .collect();
        nets.sort_by(|a, b| a.name.cmp(&b.name));
        guilds.push(GuildStat {
            id,
            name,
            networks: nets,
        });
    }

    Ok(AdminStats {
        guilds,
        total_networks: networks.len(),
        online_devices: pres.online_devices,
        online_users: pres.online_users,
        enrolled_devices,
        longpoll_waiters: st.versions.waiters(),
        version: st.versions.global(),
    })
}

/// Gate an admin request on the `[admin]` token. `Err(404)` when no token is configured (surface
/// disabled — indistinguishable from a missing route); `Err(401)` on a missing or wrong bearer.
/// Constant-time comparison so a wrong token leaks no timing signal about matching prefix length.
fn admin_auth(st: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(token) = st.admin_token.as_deref() else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "not found"));
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(p) if ct_eq(p.as_bytes(), token.as_bytes()) => Ok(()),
        _ => Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized")),
    }
}

/// Constant-time byte-slice equality. Length still differs observably, acceptable for a secret.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `GET /admin`: the operator dashboard **shell** (a self-contained HTML+JS app). Unauthenticated
/// by necessity — a browser sends no bearer header on navigation — but it carries **no data**: the
/// JS prompts for the `[admin]` token (stored in `localStorage`) and fetches the gated
/// `/admin/stats` itself. Served only when admin is enabled; otherwise 404, same as the data route.
pub(super) async fn admin_dashboard(
    State(st): State<AppState>,
) -> Result<Html<&'static str>, ApiError> {
    if st.admin_token.is_none() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "not found"));
    }
    Ok(Html(ADMIN_HTML))
}

/// Heartbeat hold for the `/admin/stats` long-poll — short (unlike the register renewal hold) so a
/// held dashboard request survives reverse-proxy idle timeouts and its "updated" clock stays fresh.
const ADMIN_POLL_HOLD_SECS: u64 = 25;

#[derive(serde::Deserialize)]
pub(super) struct StatsQuery {
    /// The membership `version` the client last rendered. When it equals the current version the
    /// request long-polls (holds until membership changes or the heartbeat elapses); absent/stale
    /// returns immediately. Drives the dashboard's realtime feed off the existing `watch`.
    since: Option<u64>,
}

/// `GET /admin/stats[?since=N]`: token-gated JSON snapshot, the dashboard's data feed. With `since`
/// at the current version it long-polls via the same machinery as `/register` — so the browser
/// re-renders the instant a peer joins/leaves/reaps, with a ~heartbeat tick otherwise. One held
/// request per open tab; wakes only on real version bumps, so idle cost is negligible.
pub(super) async fn admin_stats(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<StatsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    admin_auth(&st, &headers)?;
    let version = st.versions.global();
    if q.since == Some(version) {
        wait_for_change_until(
            &st,
            version,
            std::time::Duration::from_secs(ADMIN_POLL_HOLD_SECS),
        )
        .await;
    }
    Ok(Json(stats_json(&gather_stats(&st).await?)))
}

/// Serialize a snapshot for the dashboard. Guild/role snowflakes go out as **strings** — they
/// exceed 2^53 and a JS `Number` would silently mangle them.
fn stats_json(s: &AdminStats) -> serde_json::Value {
    serde_json::json!({
        "version": s.version,
        "totals": {
            "guilds": s.guilds.len(),
            "networks": s.total_networks,
            "devices_online": s.online_devices,
            "users_online": s.online_users,
            "devices_enrolled": s.enrolled_devices,
            "longpoll_waiters": s.longpoll_waiters,
        },
        "guilds": s.guilds.iter().map(|g| serde_json::json!({
            "id": g.id.to_string(),
            "name": g.name,
            "networks": g.networks.iter().map(|n| serde_json::json!({
                "role_id": n.role_id.to_string(),
                "name": n.name,
                "online": n.online,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

/// `GET /metrics`: Prometheus text exposition of the same counts.
pub(super) async fn admin_metrics(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    admin_auth(&st, &headers)?;
    let body = render_metrics(&gather_stats(&st).await?);
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response())
}

/// The operator dashboard: a self-contained HTML+CSS+JS app (no external assets). It reads the
/// `[admin]` token from `localStorage` (prompting once), then long-polls `/admin/stats` with a
/// `Bearer` header and re-renders on every response — realtime with no server-rendered data here.
const ADMIN_HTML: &str = include_str!("../admin.html");

/// Escape a Prometheus label value (backslash, double-quote, newline).
fn esc_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn gauge(out: &mut String, name: &str, help: &str, val: impl std::fmt::Display) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {val}");
}

fn render_metrics(s: &AdminStats) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    gauge(
        &mut out,
        "unitylan_guilds",
        "Guilds this coordinator has contacted.",
        s.guilds.len(),
    );
    gauge(
        &mut out,
        "unitylan_networks",
        "Registered networks (roles) across all guilds.",
        s.total_networks,
    );
    gauge(
        &mut out,
        "unitylan_devices_enrolled",
        "Enrolled devices (persistent registrations).",
        s.enrolled_devices,
    );
    gauge(
        &mut out,
        "unitylan_devices_online",
        "Distinct devices currently online.",
        s.online_devices,
    );
    gauge(
        &mut out,
        "unitylan_users_online",
        "Distinct users currently online.",
        s.online_users,
    );
    gauge(
        &mut out,
        "unitylan_longpoll_waiters",
        "Parked long-poll requests.",
        s.longpoll_waiters,
    );
    gauge(
        &mut out,
        "unitylan_membership_version",
        "Monotonic membership version.",
        s.version,
    );
    let _ = writeln!(
        out,
        "# HELP unitylan_peers_online Devices online per network."
    );
    let _ = writeln!(out, "# TYPE unitylan_peers_online gauge");
    for g in &s.guilds {
        let gname = esc_label(g.name.as_deref().unwrap_or(""));
        for n in &g.networks {
            let _ = writeln!(
                out,
                "unitylan_peers_online{{guild_id=\"{}\",guild=\"{}\",network=\"{}\",role_id=\"{}\"}} {}",
                g.id,
                gname,
                esc_label(&n.name),
                n.role_id,
                n.online
            );
        }
    }
    out
}
