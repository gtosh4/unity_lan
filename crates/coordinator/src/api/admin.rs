//! Operator admin surface (`/admin` dashboard + `/metrics`).

use std::collections::{BTreeMap, BTreeSet};

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

/// `GET /admin/graph`: token-gated, fully-anonymized bipartite graph of **networks ↔ currently-
/// online users**, for the dashboard's interactive view and its Graphviz export. Built from the
/// same cheap sources as `/admin/stats` — the network registry plus in-memory presence — so it
/// adds **no** Discord/DB fan-out. Every identifier (guild, network/role, user) is replaced by a
/// deployment-keyed opaque label (see [`common::crypto::anon_label`]): the mapping is stable within
/// a deployment (a user is the same node across renders) but leaks no Discord snowflake or name.
/// Returned immediately (no long-poll); the dashboard refetches it when the `/admin/stats` version
/// ticks, so the graph stays live without a second parked request.
pub(super) async fn admin_graph(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    admin_auth(&st, &headers)?;
    Ok(Json(build_graph(&st).await?))
}

/// Gather the graph's cheap inputs (deployment seed, network registry, live membership, version)
/// and hand them to [`graph_json`]. The split keeps the async I/O here and the anonymization +
/// assembly pure and unit-testable.
async fn build_graph(st: &AppState) -> Result<serde_json::Value, ApiError> {
    // The deployment seed is a stable per-deployment secret (not a signing key); it keys the
    // anonymization so labels are consistent across requests yet meaningless off this instance.
    let seed = st
        .store
        .load_or_create_deployment_seed()
        .await
        .map_err(internal)?;
    let networks = st.store.all_networks().await.map_err(internal)?;
    let membership = st.presence.membership();
    let version = st.versions.global();
    Ok(graph_json(&seed, &networks, &membership, version))
}

/// Assemble the anonymized graph. Network nodes come from the registry (so empty networks still
/// appear, as isolated nodes); user nodes and edges come from live presence `membership` (one edge
/// per user per network they're online in). Every identifier is replaced by a seed-keyed opaque
/// label. Ordering is deterministic (BTree-backed) so the graph and its DOT export are stable
/// between renders.
fn graph_json(
    seed: &[u8; 32],
    networks: &[crate::store::Network],
    membership: &[(u64, u64, u64)],
    version: u64,
) -> serde_json::Value {
    let net = |role_id: u64| {
        format!(
            "net-{}",
            common::crypto::anon_label(seed, "network", role_id)
        )
    };
    let guild = |guild_id: u64| {
        format!(
            "guild-{}",
            common::crypto::anon_label(seed, "guild", guild_id)
        )
    };
    let user = |user_id: u64| format!("user-{}", common::crypto::anon_label(seed, "user", user_id));

    // role_id → guild_id, from the registry plus any presence network lingering after its
    // registry row was removed (reaped shortly, but keep the edge's endpoint from dangling).
    let mut net_guild: BTreeMap<u64, u64> =
        networks.iter().map(|n| (n.role_id, n.guild_id)).collect();
    for (g, r, _) in membership {
        net_guild.entry(*r).or_insert(*g);
    }

    let guilds: BTreeSet<String> = net_guild.values().map(|g| guild(*g)).collect();
    let users: BTreeSet<String> = membership.iter().map(|(_, _, u)| user(*u)).collect();

    let mut nodes: Vec<serde_json::Value> = net_guild
        .iter()
        .map(|(r, g)| serde_json::json!({ "id": net(*r), "kind": "network", "guild": guild(*g) }))
        .collect();
    nodes.extend(
        users
            .iter()
            .map(|u| serde_json::json!({ "id": u, "kind": "user" })),
    );
    let edges: Vec<serde_json::Value> = membership
        .iter()
        .map(|(_, r, u)| serde_json::json!({ "from": user(*u), "to": net(*r) }))
        .collect();

    serde_json::json!({
        "version": version,
        "guilds": guilds.into_iter().collect::<Vec<_>>(),
        "nodes": nodes,
        "edges": edges,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Network;

    fn net(guild_id: u64, role_id: u64, name: &str) -> Network {
        Network {
            guild_id,
            role_id,
            name: name.into(),
        }
    }

    #[test]
    fn graph_json_anonymizes_and_keeps_empty_networks() {
        let seed = [3u8; 32];
        // Guild 100 has two networks (roles 11, 12); guild 200 has one (role 21).
        let networks = [
            net(100, 11, "gamers"),
            net(100, 12, "empty-net"),
            net(200, 21, "staff"),
        ];
        // Live membership: user 7 in (100,11); user 8 in (100,11) and (200,21). Role 12 has nobody.
        let membership = [(100, 11, 7), (100, 11, 8), (200, 21, 8)];
        let g = graph_json(&seed, &networks, &membership, 42);

        assert_eq!(g["version"], 42);

        // Raw identifiers must never appear in the anonymized output.
        let blob = g.to_string();
        for raw in [
            "gamers",
            "empty-net",
            "staff",
            "\"11\"",
            "\"7\"",
            "\"8\"",
            "\"100\"",
        ] {
            assert!(!blob.contains(raw), "leaked raw identifier: {raw}");
        }

        // 3 network nodes (empty one included) + 2 distinct user nodes = 5.
        let nodes = g["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 5);
        let networks_n = nodes.iter().filter(|n| n["kind"] == "network").count();
        let users_n = nodes.iter().filter(|n| n["kind"] == "user").count();
        assert_eq!((networks_n, users_n), (3, 2));

        // The empty network (role 12) is present but has no edge.
        let empty_id = format!("net-{}", common::crypto::anon_label(&seed, "network", 12));
        assert!(nodes.iter().any(|n| n["id"] == serde_json::json!(empty_id)));
        let edges = g["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 3);
        assert!(edges.iter().all(|e| e["to"] != serde_json::json!(empty_id)));

        // Two guilds, both anonymized; network nodes carry their anonymized guild.
        assert_eq!(g["guilds"].as_array().unwrap().len(), 2);
        let g100 = format!("guild-{}", common::crypto::anon_label(&seed, "guild", 100));
        let net11 = format!("net-{}", common::crypto::anon_label(&seed, "network", 11));
        let node11 = nodes
            .iter()
            .find(|n| n["id"] == serde_json::json!(net11))
            .unwrap();
        assert_eq!(node11["guild"], serde_json::json!(g100));

        // Deterministic: same inputs → byte-identical JSON.
        assert_eq!(g, graph_json(&seed, &networks, &membership, 42));
    }
}
