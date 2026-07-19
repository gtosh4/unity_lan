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
///
/// The **listing** shows only what is live: networks with nobody online are omitted, and a guild
/// left with no networks after that is omitted too. The **totals** above it stay unfiltered (they
/// are deployment-wide registration counts, not a live view), as does `/metrics` — a Prometheus
/// series that disappears at zero reads as a scrape failure rather than "nobody online".
fn stats_json(s: &AdminStats) -> serde_json::Value {
    let guilds: Vec<serde_json::Value> = s
        .guilds
        .iter()
        .filter_map(|g| {
            let nets: Vec<serde_json::Value> = g
                .networks
                .iter()
                .filter(|n| n.online > 0)
                .map(|n| {
                    serde_json::json!({
                        "role_id": n.role_id.to_string(),
                        "name": n.name,
                        "online": n.online,
                    })
                })
                .collect();
            if nets.is_empty() {
                return None;
            }
            Some(serde_json::json!({
                "id": g.id.to_string(),
                "name": g.name,
                "networks": nets,
            }))
        })
        .collect();

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
        "guilds": guilds,
    })
}

/// `GET /admin/graph`: token-gated bipartite graph of **networks ↔ currently-online users**, for
/// the dashboard's interactive view and its Graphviz export. Built from the same cheap sources as
/// `/admin/stats` — the network registry, in-memory presence, and the TTL-cached guild-name lookup
/// — so it adds no DB fan-out and at most one cached Discord read per guild.
///
/// **Anonymization is asymmetric, by policy.** Guilds and networks appear under their real
/// snowflake and name: they are the operator's own registry (set by `/unitylan network add`) and
/// already ride in every peer snapshot, so hiding them here buys nothing. **Users never do** —
/// each is a deployment-keyed opaque label ([`common::crypto::anon_label`]), stable across renders
/// so the topology stays readable, but carrying no Discord id, username, or device name. The
/// operator can see *which communities and networks exist*, and *the shape* of who joins what,
/// without seeing *who*.
///
/// Returned immediately (no long-poll); the dashboard refetches it when the `/admin/stats` version
/// ticks, so the graph stays live without a second parked request.
pub(super) async fn admin_graph(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    admin_auth(&st, &headers)?;
    Ok(Json(build_graph(&st).await?))
}

/// Gather the graph's cheap inputs (deployment seed, network registry, live membership, guild
/// display names, version) and hand them to [`graph_json`]. The split keeps the async I/O here and
/// the anonymization + assembly pure and unit-testable.
async fn build_graph(st: &AppState) -> Result<serde_json::Value, ApiError> {
    // The deployment seed is a stable per-deployment secret (not a signing key); it keys the
    // *user* anonymization so labels are consistent across requests yet meaningless off this
    // instance. Guilds and networks are not anonymized — see `admin_graph`.
    let seed = st
        .store
        .load_or_create_deployment_seed()
        .await
        .map_err(internal)?;
    let networks = st.store.all_networks().await.map_err(internal)?;
    let membership = st.presence.membership();

    // One TTL-cached lookup per guild, same source the dashboard already uses. Admin-only and
    // rare, so this stays off the client hot path.
    let mut guild_names: BTreeMap<u64, String> = BTreeMap::new();
    for id in networks
        .iter()
        .map(|n| n.guild_id)
        .chain(membership.iter().map(|(g, _, _)| *g))
        .collect::<BTreeSet<u64>>()
    {
        if let Some(name) = st.roles.guild_name(id).await {
            guild_names.insert(id, name);
        }
    }

    let version = st.versions.global();
    Ok(graph_json(
        &seed,
        &networks,
        &membership,
        &guild_names,
        version,
    ))
}

/// Assemble the graph. Everything is driven by live presence `membership` (one edge per user per
/// network they're online in): a network with nobody online is omitted, and so is a guild left
/// with no networks. The registry supplies display names and the authoritative role→guild mapping
/// for the networks that survive.
///
/// Guild and network nodes carry their real snowflake as `id` and their real name as `label` (a
/// network's is qualified `guild: role`, since the same role name can exist in several guilds).
/// User nodes carry only a seed-keyed opaque label and have no `label` field — there is no user
/// name, id, or device name anywhere in the output. Ordering is deterministic (BTree-backed) so
/// the graph and its DOT export are stable between renders.
fn graph_json(
    seed: &[u8; 32],
    networks: &[crate::store::Network],
    membership: &[(u64, u64, u64)],
    guild_names: &BTreeMap<u64, String>,
    version: u64,
) -> serde_json::Value {
    let net = |role_id: u64| format!("net-{role_id}");
    let guild = |guild_id: u64| format!("guild-{guild_id}");
    let user = |user_id: u64| format!("user-{}", common::crypto::anon_label(seed, "user", user_id));

    // role_id → guild_id for the networks that actually have someone online. The registry is
    // authoritative for the mapping; a presence network lingering after its registry row was
    // removed (reaped shortly) falls back to the guild presence recorded it under.
    let registry_guild: BTreeMap<u64, u64> =
        networks.iter().map(|n| (n.role_id, n.guild_id)).collect();
    let net_guild: BTreeMap<u64, u64> = membership
        .iter()
        .map(|(g, r, _)| (*r, registry_guild.get(r).copied().unwrap_or(*g)))
        .collect();
    // role_id → display name; a presence-only network has no registry row, so it falls back to
    // its id below.
    let net_names: BTreeMap<u64, &str> = networks
        .iter()
        .map(|n| (n.role_id, n.name.as_str()))
        .collect();

    // Guild display label, id as fallback. Shared by the guild nodes and the `guild: role` network
    // labels below.
    let guild_label = |g: u64| {
        guild_names
            .get(&g)
            .cloned()
            .unwrap_or_else(|| g.to_string())
    };

    let guilds: Vec<serde_json::Value> = net_guild
        .values()
        .copied()
        .collect::<BTreeSet<u64>>()
        .into_iter()
        .map(|g| serde_json::json!({ "id": guild(g), "label": guild_label(g) }))
        .collect();
    let users: BTreeSet<String> = membership.iter().map(|(_, _, u)| user(*u)).collect();

    let mut nodes: Vec<serde_json::Value> = net_guild
        .iter()
        .map(|(r, g)| {
            // `guild: role` — the same name can be registered in several guilds, so the guild
            // qualifies it (the guild colour alone can't disambiguate two identical labels).
            let name = net_names
                .get(r)
                .map(|s| s.to_string())
                .unwrap_or_else(|| r.to_string());
            serde_json::json!({
                "id": net(*r), "kind": "network", "guild": guild(*g),
                "label": format!("{}: {name}", guild_label(*g)),
            })
        })
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
        "guilds": guilds,
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
    // Ids only, never guild/network *names*. A scrape stream leaves this box for whatever
    // Prometheus/Grafana consumes it — an audience wider than the `[admin]` token — and the ids
    // are enough to correlate a series with a support report. Names stay on the token-gated
    // dashboard.
    for g in &s.guilds {
        for n in &g.networks {
            let _ = writeln!(
                out,
                "unitylan_peers_online{{guild_id=\"{}\",role_id=\"{}\"}} {}",
                g.id, n.role_id, n.online
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

    struct Fixture {
        seed: [u8; 32],
        networks: Vec<Network>,
        membership: Vec<(u64, u64, u64)>,
        guild_names: BTreeMap<u64, String>,
    }

    impl Fixture {
        fn graph(&self) -> serde_json::Value {
            graph_json(
                &self.seed,
                &self.networks,
                &self.membership,
                &self.guild_names,
                42,
            )
        }
    }

    /// Guild 100 has two networks (roles 11, 12); guild 200 has one (role 21); guild 300 has one
    /// (role 31). Live membership: user 7 in (100,11); user 8 in (100,11) and (200,21). Role 12
    /// has nobody, and guild 300 has nobody at all — so both should be filtered out.
    fn fixture() -> Fixture {
        Fixture {
            seed: [3u8; 32],
            networks: vec![
                net(100, 11, "gamers"),
                net(100, 12, "empty-net"),
                net(200, 21, "staff"),
                net(300, 31, "ghost-town"),
            ],
            membership: vec![(100, 11, 7), (100, 11, 8), (200, 21, 8)],
            guild_names: [
                (100u64, "Some Server".to_string()),
                (200, "Staff HQ".into()),
                (300, "Nobody Home".into()),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[test]
    fn graph_json_names_guilds_and_networks_but_never_users() {
        let f = fixture();
        let g = f.graph();
        let blob = g.to_string();

        // Guilds and networks are the operator's own registry — the live ones are shown as-is.
        for shown in ["gamers", "staff", "Some Server", "Staff HQ"] {
            assert!(blob.contains(shown), "expected to expose: {shown}");
        }
        assert!(blob.contains("guild-100") && blob.contains("net-11"));

        // Users are never identifiable: no raw user id, and every user node is an opaque label
        // with no `label` field to leak a name.
        for uid in [7u64, 8] {
            let anon = format!("user-{}", common::crypto::anon_label(&f.seed, "user", uid));
            assert!(blob.contains(&anon), "user {uid} should appear anonymized");
        }
        let nodes = g["nodes"].as_array().unwrap();
        for n in nodes.iter().filter(|n| n["kind"] == "user") {
            let id = n["id"].as_str().unwrap();
            assert!(id.starts_with("user-"));
            assert!(!id.contains('7') || id.len() > 6, "raw id in {id}");
            assert!(n.get("label").is_none(), "user node carries a label: {n}");
        }
        // Edges reference users only by their anonymized node id.
        for e in g["edges"].as_array().unwrap() {
            assert!(e["from"].as_str().unwrap().starts_with("user-"));
        }
    }

    #[test]
    fn graph_json_omits_empty_networks_and_their_guilds() {
        let f = fixture();
        let g = f.graph();

        assert_eq!(g["version"], 42);

        // Only the 2 networks with someone online + 2 distinct user nodes = 4. `empty-net` (role
        // 12, registered but nobody online) and `ghost-town` (role 31) are both gone.
        let nodes = g["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 4);
        let networks_n = nodes.iter().filter(|n| n["kind"] == "network").count();
        let users_n = nodes.iter().filter(|n| n["kind"] == "user").count();
        assert_eq!((networks_n, users_n), (2, 2));
        for gone in ["net-12", "net-31"] {
            assert!(
                !nodes.iter().any(|n| n["id"] == serde_json::json!(gone)),
                "empty network still rendered: {gone}"
            );
        }
        assert_eq!(g["edges"].as_array().unwrap().len(), 3);

        // Guild 300's only network is empty, so the guild drops out entirely.
        assert_eq!(
            g["guilds"],
            serde_json::json!([
                {"id": "guild-100", "label": "Some Server"},
                {"id": "guild-200", "label": "Staff HQ"},
            ])
        );

        let node11 = nodes
            .iter()
            .find(|n| n["id"] == serde_json::json!("net-11"))
            .unwrap();
        assert_eq!(node11["guild"], serde_json::json!("guild-100"));
        assert_eq!(node11["label"], serde_json::json!("Some Server: gamers"));

        // Deterministic: same inputs → byte-identical JSON.
        assert_eq!(g, f.graph());
    }

    /// A guild whose name lookup failed, and a network present only in live presence (its registry
    /// row was removed and not yet reaped), both fall back to their id rather than dangling.
    #[test]
    fn graph_json_falls_back_to_ids_when_names_are_missing() {
        let g = graph_json(&[3u8; 32], &[], &[(100, 11, 7)], &BTreeMap::new(), 1);
        assert_eq!(
            g["guilds"],
            serde_json::json!([{"id": "guild-100", "label": "100"}])
        );
        let node = g["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["kind"] == "network")
            .unwrap()
            .clone();
        assert_eq!(node["label"], serde_json::json!("100: 11"));
    }

    /// Policy guard: user identity never reaches an operator surface. `/admin/stats` and
    /// `/metrics` are built from counts only — if someone later threads a username, device name,
    /// or raw user id into `AdminStats`, this fails.
    #[test]
    fn stats_and_metrics_expose_no_user_identity() {
        let s = AdminStats {
            guilds: vec![GuildStat {
                id: 100,
                name: Some("Some Server".into()),
                networks: vec![NetStat {
                    role_id: 11,
                    name: "gamers".into(),
                    online: 2,
                }],
            }],
            total_networks: 1,
            online_devices: 3,
            online_users: 2,
            enrolled_devices: 9,
            longpoll_waiters: 1,
            version: 42,
        };

        let json = stats_json(&s).to_string();
        let metrics = render_metrics(&s);
        for surface in [&json, &metrics] {
            for key in ["username", "user_id", "device_name", "pubkey"] {
                assert!(
                    !surface.contains(key),
                    "user identity on admin surface: {key}"
                );
            }
        }

        // Metrics carries ids only — names stay on the token-gated dashboard.
        assert!(metrics.contains("unitylan_peers_online{guild_id=\"100\",role_id=\"11\"} 2"));
        assert!(!metrics.contains("Some Server") && !metrics.contains("gamers"));
        // The dashboard, by contrast, does show them.
        assert!(json.contains("Some Server") && json.contains("gamers"));
    }

    /// The listing shows only what's live: zero-online networks drop out, and a guild left with
    /// nothing drops with them. Totals and `/metrics` stay unfiltered.
    #[test]
    fn stats_listing_hides_empty_networks_and_guilds() {
        let s = AdminStats {
            guilds: vec![
                GuildStat {
                    id: 100,
                    name: Some("Some Server".into()),
                    networks: vec![
                        NetStat {
                            role_id: 11,
                            name: "gamers".into(),
                            online: 2,
                        },
                        NetStat {
                            role_id: 12,
                            name: "empty-net".into(),
                            online: 0,
                        },
                    ],
                },
                GuildStat {
                    id: 300,
                    name: Some("Nobody Home".into()),
                    networks: vec![NetStat {
                        role_id: 31,
                        name: "ghost-town".into(),
                        online: 0,
                    }],
                },
            ],
            total_networks: 3,
            online_devices: 3,
            online_users: 2,
            enrolled_devices: 9,
            longpoll_waiters: 1,
            version: 42,
        };

        let v = stats_json(&s);

        // Only the live guild, with only its live network.
        assert_eq!(
            v["guilds"],
            serde_json::json!([{
                "id": "100",
                "name": "Some Server",
                "networks": [{"role_id": "11", "name": "gamers", "online": 2}],
            }])
        );

        // Totals are registration counts, not a live view — they still count all 2 guilds and all
        // 3 networks.
        assert_eq!(v["totals"]["guilds"], 2);
        assert_eq!(v["totals"]["networks"], 3);

        // Metrics is unaffected: a series that vanished at zero would read as a scrape failure.
        let metrics = render_metrics(&s);
        for series in [
            "unitylan_peers_online{guild_id=\"100\",role_id=\"12\"} 0",
            "unitylan_peers_online{guild_id=\"300\",role_id=\"31\"} 0",
        ] {
            assert!(metrics.contains(series), "metrics dropped a zero: {series}");
        }
    }
}
