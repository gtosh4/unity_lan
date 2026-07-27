//! Building one caller's view of the mesh: its identity, its grant, and every peer it may reach.
//!
//! This is the coordinator's hot path. [`build_snapshot`] runs once per client per renewal (≈ every
//! `LONGPOLL_HOLD_SECS`) *plus* once per client on every herd wake, so work added here is multiplied
//! by the deployment's client count — see CLAUDE.md, "Keep the coordinator off the hot path". It is
//! written as a sequence of named phases for that reason: each one states what it costs and what it
//! caches, so the multiplication is visible rather than buried in a single long function.
//!
//! The phases, in order:
//!
//! 1. [`resolve_device`] — who is calling, and the one IP + name their device holds.
//! 2. [`resolve_membership`] — which networks they hold a role in, and their presence in each.
//! 3. [`build_grant`] — their own per-guild attestations.
//! 4. [`build_seeds`] — every co-member, attested and decorated with a NAT path.
//! 5. [`apply_delta`] — narrow that to what this client doesn't already hold.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};

use common::api::{
    Grant, GuildAnchor, GuildAttestation, IceParams, NetworkStatus, RegisterReq, RegisterResp,
    RelayInfo, Seed, SharedNetwork,
};
use common::netid::sanitize_label;

use super::auth::resolve_user;
use super::nat::{punch_target, record_peer_reports, relay_target, validate_peer_reports};
use super::register::negotiate;
use super::{internal, ApiError, AppState, RelayReg};
use crate::presence::MemberPresence;
use crate::roles::{MemberRoles, RoleSource};
use crate::store::Network;
use crate::versions::Scope;

/// What [`build_snapshot`] produced for one caller.
pub(super) struct Built {
    pub(super) resp: RegisterResp,
    /// `true` when the caller's own request changed something (membership or a pair table) — the
    /// signal for [`super::register::register`] to return now rather than park, so the client can
    /// continue its report loop.
    pub(super) caller_changed: bool,
    /// The scopes whose membership this caller cares about: its own user scope (own-device peering)
    /// plus every guild it holds a network role in. Backs both the wire `version` and
    /// [`super::wake::wait_park`].
    pub(super) scopes: BTreeSet<Scope>,
}

/// The caller's device identity: one IP and one name per device (keyed by pubkey), reused across
/// every network it holds. Zeroed when the caller holds no network role at all — see
/// [`resolve_device`] for why that case allocates nothing.
struct Device {
    ip: Ipv4Addr,
    name: String,
    is_primary: bool,
}

/// What the caller's Discord roles resolve to for this snapshot.
struct Membership {
    /// One row per network the caller holds a role in, **enabled or not** — the toggle list the
    /// client renders. Non-empty is what "this caller has an identity" means.
    status: Vec<NetworkStatus>,
    /// `(guild, role)` for each *enabled* network. Parallel to [`Self::network_names`].
    held: Vec<(u64, u64)>,
    /// Display names of the enabled networks. Parallel to [`Self::held`].
    network_names: Vec<String>,
    /// guild → community label, resolved once per guild and reused across every use below.
    community: HashMap<u64, String>,
    /// The caller's handle, taken from any held role (even a disabled network's).
    username: String,
    /// The caller holds no network role anywhere, but asked to peer its own devices — so it is
    /// attested under [`common::attestation::PERSONAL_SCOPE`] instead of a guild. Never set
    /// alongside a non-empty [`Self::status`]: a caller with a role is attested under its guilds,
    /// and re-scoping those callers would churn pins for no gain.
    personal: bool,
}

impl Membership {
    /// Every scope the caller's attestations are signed under: the guilds it holds a role in
    /// (enabled or not), or [`PERSONAL_SCOPE`](common::attestation::PERSONAL_SCOPE) when it holds
    /// none and peers only its own devices. Drives the self-grant attestations and the response
    /// anchors; a peer's shared guilds are always a subset of this.
    fn guilds(&self) -> BTreeSet<u64> {
        if self.personal {
            return [common::attestation::PERSONAL_SCOPE].into_iter().collect();
        }
        self.status.iter().map(|n| n.guild_id).collect()
    }

    /// Whether the caller gets an identity (IP, name, grant) at all — it holds ≥1 network role, or
    /// it qualifies for the personal scope. Without either there is no anchor to attest it (or a
    /// sibling) under.
    fn has_identity(&self) -> bool {
        !self.status.is_empty() || self.personal
    }
}

pub(super) async fn build_snapshot(
    st: &AppState,
    req: &RegisterReq,
    caller_ip: std::net::IpAddr,
) -> Result<Built, ApiError> {
    validate_peer_reports(req)?;
    let (user_id, already_enrolled) = resolve_user(st, req).await?;
    // Record where this device connects from (as the coordinator sees it), so a peer's reflexive
    // report about it can be validated against its real source address (see `accepted_reflexives`).
    st.source_ip
        .lock()
        .unwrap()
        .insert(req.wg_pubkey, caller_ip);
    let now = common::now_unix();
    // Always sign the V2 layout. V2 read support shipped in v0.3.0 and the whole fleet is past it, so
    // the per-client capability gate that once kept V1 alive for older readers is retired.
    let att_schema = common::attestation::ATTESTATION_SCHEMA_V2;
    let all_networks = st.store.all_networks().await.map_err(internal)?;
    // A caller we recently walked and found no role for skips the walk entirely: for a personal-scope
    // user it is one Discord member lookup per registered guild, all returning "not a member", every
    // renewal and every herd wake (see [`crate::roleless`]). Handing the phases an empty network list
    // is exactly what that walk would have concluded, without the calls.
    let walked = !st.roleless.fresh(user_id);
    let networks: &[Network] = if walked { &all_networks } else { &[] };

    // Cache per-guild member lookups so we hit the role source once per guild — shared across both
    // phases below, so a guild is queried from Discord once per snapshot rather than once per pass.
    let mut member_cache: HashMap<u64, Option<MemberRoles>> = HashMap::new();

    // Scopes whose membership this request changed → bumped at the end, waking the clients of those
    // scopes only. A presence change in a guild is scoped to that guild; an own-device (`*_self`)
    // change crosses guilds, so it's scoped to the owning user instead.
    let mut changed: BTreeSet<Scope> = BTreeSet::new();

    let device = resolve_device(st, req, user_id, networks, &mut member_cache).await?;
    retire_superseded(st, req, user_id, &mut changed).await?;
    let membership = resolve_membership(
        st,
        req,
        user_id,
        networks,
        &device,
        &mut member_cache,
        now,
        &mut changed,
    )
    .await?;
    // A walk that turned up nothing is what the memo above is for; remember it so the next renewal
    // costs no lookups. Only ever written after a real walk, and never refreshed on a hit, so an
    // entry ages out on schedule instead of being held alive by an active client.
    if walked && membership.status.is_empty() {
        st.roleless.remember(user_id);
    }
    // Stamp liveness for the reclaim sweep. Only meaningful for a device that actually holds an
    // allocation, and it re-writes the personal flag each time, so a device that gains a role stops
    // being reclaimable from that register on.
    if membership.has_identity() {
        st.store
            .touch_device(&req.wg_pubkey, membership.personal)
            .await
            .map_err(internal)?;
    }
    record_own_device(st, req, user_id, &device, &membership, now, &mut changed);

    let grant_guilds = membership.guilds();
    let grant = build_grant(st, req, user_id, &device, &membership, att_schema).await?;

    // Peers named in this caller's pair-specific reports (reflexive/relay/ICE) — each is woken
    // individually instead of bumping a membership scope, so a NAT-traversal exchange doesn't wake
    // a whole guild for a change only the one target cares about.
    let mut wake_targets: HashSet<[u8; 32]> = HashSet::new();
    let all = build_seeds(
        st,
        req,
        user_id,
        &membership,
        &grant_guilds,
        now,
        att_schema,
        &mut wake_targets,
    )
    .await?;
    let (seeds, removed, partial) = apply_delta(req, all);

    // Hand back the device's bearer token *only* on the register that first enrolls it — i.e. when
    // the pubkey was resolved via a secret (enrollment key / OAuth binding), not by naming an
    // already-enrolled pubkey. A WG public key is not a secret here (it rides in every co-member's
    // seed), so re-issuing the token to anyone who names a known pubkey would let a co-member pull
    // a victim's token and drive `/devices/manage` (rename/remove/set-primary) against them. The
    // client persists the token from this first delivery; refresh never needs it re-sent.
    let device_token = if already_enrolled {
        None
    } else {
        st.store
            .device_token(&req.wg_pubkey)
            .await
            .map_err(internal)?
    };

    // Bump each scope whose membership changed → wake every parked client *of that scope*. A guild's
    // co-members wake; an unrelated guild's clients stay parked and cost nothing.
    st.versions.bump_all(changed.iter().copied());
    // Fire targeted wakes for the peers named in this caller's pair-specific reports — each learns
    // its new reflexive/relay/ICE state on its own parked request, without a global herd wake.
    for t in &wake_targets {
        st.wakers.wake(t);
    }

    // The caller's own scopes: its user scope (own-device peering) plus every guild it holds a role
    // in. Its wire `version` aggregates exactly these, so nothing outside them can wake it. A
    // network registered in a guild the caller has no role in is therefore picked up on its next
    // renewal rather than instantly — that's an admin-rare event, unlike presence churn.
    // The personal scope is not a membership scope — nothing ever bumps it, and a personal caller's
    // wakes all arrive on its user scope — so it's filtered out rather than tracked as a guild.
    let scopes: BTreeSet<Scope> = std::iter::once(Scope::User(user_id))
        .chain(
            grant_guilds
                .iter()
                .filter(|&&g| g != common::attestation::PERSONAL_SCOPE)
                .map(|&g| Scope::Guild(g)),
        )
        .collect();
    let version = st.versions.aggregate(&scopes);

    tracing::debug!(
        user = user_id,
        since = ?req.since,
        version,
        scopes = ?scopes,
        held_networks = membership.status.len(),
        networks = ?membership.status
            .iter()
            .map(|n| format!("{}({}/{})={}", n.name, n.guild_id, n.role_id, n.enabled))
            .collect::<Vec<_>>(),
        grant = if membership.has_identity() { "issued" } else { "none" },
        enabled_networks = membership.held.len(),
        "snapshot built"
    );

    let anchors = build_anchors(st, &grant_guilds).await?;
    let release = sign_release(st, &grant_guilds).await?;

    Ok(Built {
        caller_changed: !changed.is_empty() || !wake_targets.is_empty(),
        scopes,
        resp: RegisterResp {
            anchors,
            grant,
            device_token,
            seeds,
            version,
            networks: membership.status,
            stun_port: st.stun_port,
            dns_domain: st.dns.as_ref().map(|d| d.domain.clone()),
            // The version we *selected* for this client, not our ceiling. `register` already
            // rejected a non-overlapping range, so the fallback here is unreachable.
            proto: negotiate(req).unwrap_or(common::PROTOCOL_VERSION),
            proto_min: common::MIN_PROTOCOL_VERSION,
            proto_max: common::PROTOCOL_VERSION,
            caps: common::CAPABILITIES.iter().map(|c| c.to_string()).collect(),
            server_version: common::VERSION.to_string(),
            release,
            // Served verbatim to every caller — the coordinator holds no release key, just relays the
            // blob the pipeline signed offline. Cloned out of the RwLock (never held across an await).
            release_signed: st.release_signed.read().unwrap().clone(),
            partial,
            removed,
        },
    })
}

/// Phase 1 — allocate (or recover) this device's mesh identity.
///
/// The role check runs **before** the allocation. A caller who holds no network role *and* isn't
/// asking to peer its own devices — e.g. a Discord user who authorized the app and then walked away
/// — must not consume a mesh IP or leave a permanent device row behind, or an account with no access
/// could exhaust the mesh range and bloat the store (TM-2). Such a caller gets a zeroed [`Device`];
/// every reader of these fields is gated on [`Membership::has_identity`], so the placeholder is
/// never observed.
///
/// A roleless caller that *did* ask for own-device peering does allocate — that's the personal mesh
/// (see [`PERSONAL_SCOPE`](common::attestation::PERSONAL_SCOPE)). What holds TM-2 there is
/// enrollment itself: an OAuth-bound Discord account plus the possession proof in
/// [`super::auth::resolve_user`], bounded by the per-account device cap, and reclaimed when the
/// device goes idle.
async fn resolve_device(
    st: &AppState,
    req: &RegisterReq,
    user_id: u64,
    networks: &[Network],
    member_cache: &mut HashMap<u64, Option<MemberRoles>>,
) -> Result<Device, ApiError> {
    if !holds_any_network_role(st.roles.as_ref(), networks, user_id, member_cache).await
        && !wants_personal_scope(req)
    {
        return Ok(Device {
            ip: Ipv4Addr::UNSPECIFIED,
            name: String::new(),
            is_primary: false,
        });
    }
    // One IP + one name per device (keyed by pubkey), reused across every network it holds. The
    // request name only seeds these on first enrollment; thereafter `allocate_device` returns the
    // stored (possibly renamed / auto-suffixed) name, and we build the attestation/hostname from
    // *that* so DNS tracks renames and never advertises a duplicate label.
    let (ip, name) = st
        .store
        .allocate_device(
            st.guild_keys.wg_net(),
            &req.wg_pubkey,
            user_id,
            &sanitize_label(&req.device_name),
        )
        .await
        .map_err(internal)?;
    // Primary device: first-enrolled auto-becomes primary; reassigned via `/unitylan primary`.
    st.store
        .ensure_primary(user_id, &req.wg_pubkey)
        .await
        .map_err(internal)?;
    let is_primary = st
        .store
        .primary_pubkey(user_id)
        .await
        .map_err(internal)?
        .is_some_and(|p| p == req.wg_pubkey);
    Ok(Device {
        ip,
        name,
        is_primary,
    })
}

/// Phase 2 — resolve the caller's networks and record its presence in each.
///
/// Walks every registered network, keeping only those whose guild the caller is a member of *and*
/// whose role it holds. A network the client has locally disabled is still **listed** (so the toggle
/// can be rendered, and so identity resolves) but contributes no presence, no grant network and no
/// seeds — the opt-out is symmetric, in both directions.
///
/// Also self-evicts: a network we were recorded in but no longer hold (role revoked), or every
/// network at once while the client is `paused`. Peers pick that up on their next woken refresh.
#[allow(clippy::too_many_arguments)]
async fn resolve_membership(
    st: &AppState,
    req: &RegisterReq,
    user_id: u64,
    networks: &[Network],
    device: &Device,
    member_cache: &mut HashMap<u64, Option<MemberRoles>>,
    now: u64,
    changed: &mut BTreeSet<Scope>,
) -> Result<Membership, ApiError> {
    // Networks this device has opted out of peering on. The client is the source of truth and
    // sends its current set on every register/refresh, so this works even across coordinator
    // restarts and while the coordinator was unreachable.
    let optouts: HashSet<(u64, u64)> = req
        .disabled_networks
        .iter()
        .map(|n| (n.guild_id, n.role_id))
        .collect();

    let mut m = Membership {
        status: Vec::new(),
        held: Vec::new(),
        network_names: Vec::new(),
        community: HashMap::new(),
        username: format!("user-{user_id}"), // fallback until a role source gives a handle
        personal: false,                     // decided below, once we know whether any role landed
    };
    // Whether the per-user label has been allocated yet on this walk (see the loop below).
    let mut label_resolved = false;

    for net in networks {
        let member = match member_cache.get(&net.guild_id) {
            Some(m) => m.clone(),
            None => {
                let m = st.roles.member(net.guild_id, user_id).await;
                member_cache.insert(net.guild_id, m.clone());
                m
            }
        };
        let Some(member) = member else {
            tracing::debug!(
                user = user_id,
                guild = net.guild_id,
                role = net.role_id,
                net = %net.name,
                "snapshot: skip network — caller not a member of its guild"
            );
            continue;
        };
        if !member.role_ids.contains(&net.role_id) {
            tracing::debug!(
                user = user_id,
                guild = net.guild_id,
                role = net.role_id,
                net = %net.name,
                held = ?member.role_ids,
                "snapshot: skip network — caller does not hold its role"
            );
            continue;
        }

        // The user holds this role. Record it for the toggle UI; a disabled network is listed but
        // contributes no presence / grant / seeds (so it doesn't peer, in either direction).
        let guild_label = match m.community.get(&net.guild_id) {
            Some(l) => l.clone(),
            None => {
                let l = community_of(st, net.guild_id).await.map_err(internal)?;
                m.community.insert(net.guild_id, l.clone());
                l
            }
        };
        // Resolve the name live from the role source so it tracks Discord role renames; fall back
        // to the snapshot captured at registration if the lookup fails.
        let name = st
            .roles
            .role_name(net.guild_id, net.role_id)
            .await
            .unwrap_or_else(|| net.name.clone());
        let enabled = !optouts.contains(&(net.guild_id, net.role_id));
        m.status.push(NetworkStatus {
            guild_id: net.guild_id,
            role_id: net.role_id,
            name: name.clone(),
            guild_name: guild_label,
            enabled,
        });

        // Identity resolves from any held role — even a disabled one — so the device still gets a
        // grant (stable name/IP/hostname) and the client can render the toggle list. Otherwise a
        // network that is auto-disabled on discovery (secure default) would yield no grant, the
        // engine would treat us as holding no networks, and the toggle needed to *enable* it would
        // never appear: a chicken-and-egg lockout.
        //
        // The label is allocated per *user*, not per network, so resolve it on the first role that
        // lands and reuse it for the rest of the walk. The username only seeds it — see
        // `Store::user_label` for why the label is allocated once rather than recomputed.
        if !label_resolved {
            m.username = st.user_label(user_id, &member.username).await?;
            label_resolved = true;
        }

        // A disabled network is listed (above) but contributes no presence / grant-network / seeds
        // (so it doesn't peer, in either direction) until the user enables it.
        if !enabled {
            continue;
        }
        m.network_names.push(name);

        // Record the device as present in this network (for others' seeds) — unless it has locally
        // disconnected (`paused`), in which case we still build its grant + seeds (so it can
        // re-mesh instantly on reconnect) but advertise no presence, so co-members prune it.
        if !req.paused
            && st.presence.record(
                net.guild_id,
                net.role_id,
                presence_of(req, user_id, device, &m.username),
                req.client_version.clone(),
                now,
            )
        {
            changed.insert(Scope::Guild(net.guild_id));
        }
        m.held.push((net.guild_id, net.role_id));
    }

    // Self-eviction: drop our presence from any network we were recorded in but no longer hold
    // (role revoked) — or from *every* network while disconnected (`paused`). Peers pick this up
    // on their next (long-poll-woken) refresh and prune us.
    for (g, r) in st.presence.networks_of(&req.wg_pubkey) {
        if (req.paused || !m.held.contains(&(g, r))) && st.presence.evict(g, r, &req.wg_pubkey) {
            changed.insert(Scope::Guild(g));
        }
    }

    // No role landed anywhere, but the caller wants its own devices meshed: attest it under the
    // personal scope instead of a guild. `status` being empty is exactly the role check
    // `resolve_device` already ran, so this costs no extra role-source lookups and the two agree.
    m.personal = m.status.is_empty() && wants_personal_scope(req);
    if m.personal {
        // No role means no member lookup ever supplies a username, so the handle captured at login is
        // the only name this user has. A local read, and only for personal callers.
        if let Some(h) = st.store.user_handle(user_id).await.map_err(internal)? {
            m.username = st.user_label(user_id, &h).await?;
        }
    }

    Ok(m)
}

/// Whether a caller with no network role still gets an identity — it asked to peer its own devices.
///
/// Deliberately **not** gated on `paused`: pausing withdraws presence (see [`record_own_device`])
/// but must not dissolve the identity, for the same reason a role-holding caller keeps its grant
/// while paused — it re-meshes instantly on reconnect instead of re-deriving its name and IP.
fn wants_personal_scope(req: &RegisterReq) -> bool {
    req.peer_own_devices
}

/// Own-device peering: record this device in the per-user online set (independent of networks) so
/// its siblings can seed it even with no shared enabled network. Gated on the client opting in
/// (`peer_own_devices`, default on), not being paused, and holding an identity (a role's guild or
/// the personal scope → a grant is issued; without one there's no anchor to attest a sibling under).
/// Evict in every other case so an opt-out / pause / role-loss withdraws this device from its
/// siblings' seeds.
fn record_own_device(
    st: &AppState,
    req: &RegisterReq,
    user_id: u64,
    device: &Device,
    m: &Membership,
    now: u64,
    changed: &mut BTreeSet<Scope>,
) {
    let self_changed = if req.peer_own_devices && !req.paused && m.has_identity() {
        st.presence.record_self(
            user_id,
            presence_of(req, user_id, device, &m.username),
            req.client_version.clone(),
            now,
        )
    } else {
        st.presence.evict_self(user_id, &req.wg_pubkey)
    };
    // Own-device peering ignores networks, so this wakes the owner's *other* devices wherever they
    // are — the user scope, not any guild.
    if self_changed {
        changed.insert(Scope::User(user_id));
    }
}

/// The presence row this device advertises — identical whether recorded per-network or in the
/// owner's own-device set, which is what makes one device one identity across both.
fn presence_of(req: &RegisterReq, user_id: u64, device: &Device, username: &str) -> MemberPresence {
    MemberPresence {
        pubkey: req.wg_pubkey,
        ip: device.ip,
        user_id,
        username: username.to_string(),
        device_name: device.name.clone(),
        is_primary: device.is_primary,
        endpoint: req.endpoint,
    }
}

/// Phase 3 — the caller's self-grant: one device attestation **per guild**, each signed by that
/// guild's key (design.md §3.1/§4.1).
///
/// Issued whenever the caller holds ≥1 network role, even if every one is currently disabled — the
/// device still needs its identity/IP and the client needs the grant to surface the toggle list.
/// `None` only when the caller holds no network roles at all.
async fn build_grant(
    st: &AppState,
    req: &RegisterReq,
    user_id: u64,
    device: &Device,
    m: &Membership,
    att_schema: u32,
) -> Result<Option<Grant>, ApiError> {
    if !m.has_identity() {
        return Ok(None);
    }
    let guilds = m.guilds();
    let mut attestations = Vec::with_capacity(guilds.len());
    for &g in &guilds {
        let key = st.guild_keys.get(g).await.map_err(internal)?;
        let signed = key
            .signer
            .sign_attestation(
                &crate::signer::AttIdentity {
                    user_id,
                    username: &m.username,
                    device_name: &device.name,
                    is_primary: device.is_primary,
                    ip: device.ip,
                    pubkey: req.wg_pubkey,
                },
                att_schema,
            )
            .map_err(internal)?;
        attestations.push(GuildAttestation {
            att_schema,
            attestation: signed.to_base64(),
            community_name: m.community.get(&g).cloned().unwrap_or_default(),
        });
    }
    Ok(Some(Grant {
        attestations,
        networks: m.network_names.clone(),
    }))
}

/// Phase 4 — every device the caller may reach, attested and given a NAT path.
///
/// A seed is produced for each device sharing ≥1 *enabled* network with the caller, deduplicated by
/// pubkey but accumulating the shared networks (so the client can scope `expose --net` per network
/// and show which server each came from), plus the caller's own other online devices. Each seed
/// carries one attestation per guild it shares with the caller, and — if a punch won't work — a
/// punch target or a relay both ends will independently agree on.
///
/// Also the point where the caller's own peer-keyed reports are accepted: the seed set *is* the
/// co-membership set, which is the trust boundary those reports are checked against.
#[allow(clippy::too_many_arguments)]
async fn build_seeds(
    st: &AppState,
    req: &RegisterReq,
    user_id: u64,
    m: &Membership,
    grant_guilds: &BTreeSet<u64>,
    now: u64,
    att_schema: u32,
    wake_targets: &mut HashSet<[u8; 32]>,
) -> Result<Vec<([u8; 32], Seed)>, ApiError> {
    // Third slot: the set of guilds this peer shares with the caller (always a subset of the
    // caller's held guilds). Each shared guild yields one attestation, signed by that guild's key.
    let mut by_pubkey: HashMap<[u8; 32], (MemberPresence, Vec<SharedNetwork>, BTreeSet<u64>)> =
        HashMap::new();
    for ((guild_id, role_id), net_name) in m.held.iter().zip(m.network_names.iter()) {
        let net = SharedNetwork {
            name: net_name.clone(),
            community: m.community.get(guild_id).cloned().unwrap_or_default(),
            // The identity clients scope on; the two strings above are display only.
            guild_id: *guild_id,
            role_id: *role_id,
        };
        for mp in st.presence.others_in(*guild_id, *role_id, &req.wg_pubkey) {
            let entry = by_pubkey
                .entry(mp.pubkey)
                .or_insert_with(|| (mp.clone(), Vec::new(), BTreeSet::new()));
            if !entry.1.contains(&net) {
                entry.1.push(net.clone());
            }
            entry.2.insert(*guild_id);
        }
    }
    // Own-device peering: fold in the caller's other online devices (same user) not already seeded
    // via a shared network. They carry no `SharedNetwork` (they share none) and are attested under
    // the caller's own scopes — same user → identical guild membership (or the same personal scope)
    // → the caller already pins each anchor, so every attestation verifies. Guarded on the caller
    // opting in *and* holding an identity (`grant_guilds` non-empty), since each seed needs ≥1
    // signed attestation or the client rejects the whole batch. `or_insert_with` keeps a sibling
    // already present via a shared network
    // (its narrower shared-guild set stands).
    if req.peer_own_devices && m.has_identity() {
        for mp in st.presence.others_of_user(user_id, &req.wg_pubkey) {
            by_pubkey
                .entry(mp.pubkey)
                .or_insert_with(|| (mp, Vec::new(), grant_guilds.clone()));
        }
    }
    // The caller's co-members: every device it shares ≥1 network with. This is the trust boundary
    // for the peer-keyed exchange tables — the caller may publish reflexive/relay/ICE state *only
    // about a peer it actually meshes with* (see `record_peer_reports`).
    let comembers: HashSet<[u8; 32]> = by_pubkey.keys().copied().collect();
    record_peer_reports(st, req, &comembers, wake_targets);

    // Relay candidates for the caller: co-members that advertise a TURN relay, captured with their
    // shared-with-caller network names before the seed loop consumes `by_pubkey`. A relay is used
    // for a peer only if it *also* shares a network with that peer (symmetric authorization) — and
    // both endpoints, building their own snapshots, pick the same min-pubkey relay from the same
    // set, so they meet on it.
    let relay_regs = st.relays.lock().unwrap().clone();
    let relay_candidates: Vec<([u8; 32], Vec<SharedNetwork>, RelayReg)> = by_pubkey
        .iter()
        .filter_map(|(pk, (_mp, nets, _c))| {
            relay_regs
                .get(pk)
                .map(|reg| (*pk, nets.clone(), reg.clone()))
        })
        .collect();
    let need_relay: HashSet<[u8; 32]> = req.need_relay.iter().copied().collect();
    let relay_allocs = st.relay_allocs.lock().unwrap().clone();
    let ice_exchange = st.ice.lock().unwrap().clone();

    // Whether the caller itself is directly dialable (self-reported endpoint: UPnP / manual
    // forward). If so, a NAT'd peer just dials us and no punch is needed on either side.
    let caller_dialable = req.endpoint.is_some();
    let reflexive = st.reflexive.lock().unwrap().clone();
    // (pubkey, seed) pairs — the pubkey (carried inside each attestation, not a top-level Seed field)
    // is tracked here so the delta filter can diff against the client's `held` set.
    let mut all: Vec<([u8; 32], Seed)> = Vec::new();
    for (_pubkey, (mp, networks, shared_guilds)) in by_pubkey {
        let punch = punch_target(
            caller_dialable,
            mp.endpoint,
            reflexive.get(&mp.pubkey).copied(),
        );
        // If we told the coordinator we can't reach this peer directly (punch went Unreachable),
        // hand back a relay we both share a network with, plus the peer's own relayed address on it
        // (once the peer has reported one) so we know where to send.
        let relay = if need_relay.contains(&mp.pubkey) {
            relay_target(&mp.pubkey, &networks, &relay_candidates, now).map(|mut info| {
                info.peer_relayed = relay_allocs.get(&(mp.pubkey, req.wg_pubkey)).copied();
                info
            })
        } else {
            None
        };
        // One attestation per guild this peer shares with the caller, each signed by that guild's
        // key. The client admits the peer once any one verifies against the matching pinned anchor.
        let peer_id = crate::signer::AttIdentity {
            user_id: mp.user_id,
            username: &mp.username,
            device_name: &mp.device_name,
            is_primary: mp.is_primary,
            ip: mp.ip,
            pubkey: mp.pubkey,
        };
        let mut attestations = Vec::with_capacity(shared_guilds.len());
        for &g in &shared_guilds {
            let blob = st
                .sign_cache
                .attestation(&st.guild_keys, g, &peer_id, now, att_schema)
                .await
                .map_err(internal)?;
            attestations.push(GuildAttestation {
                att_schema,
                attestation: blob.to_string(),
                community_name: m.community.get(&g).cloned().unwrap_or_default(),
            });
        }
        // The peer's ICE offer for reaching us (if it has run ICE toward this caller): key is
        // (owner=peer, peer=caller). The client feeds it into its agent to run connectivity checks.
        let ice = ice_exchange.get(&(mp.pubkey, req.wg_pubkey)).cloned();
        let rev = seed_rev(&mp, mp.endpoint, punch, &networks, &relay, &ice);
        all.push((
            mp.pubkey,
            Seed {
                attestations,
                endpoint: mp.endpoint,
                punch,
                networks,
                relay,
                ice,
                rev,
            },
        ));
    }
    Ok(all)
}

/// Phase 5 — delta sync. If the client sent its held set (pubkey → last-seen rev), return only the
/// seeds that are new or whose rev changed, plus the pubkeys it should drop — collapsing a herd wake
/// from O(peers) per client to O(changes). An empty `held` (older client, first contact, or a client
/// forcing an attestation refresh) gets the full set.
fn apply_delta(req: &RegisterReq, all: Vec<([u8; 32], Seed)>) -> (Vec<Seed>, Vec<[u8; 32]>, bool) {
    if req.held.is_empty() {
        return (all.into_iter().map(|(_, s)| s).collect(), Vec::new(), false);
    }
    let held: HashMap<[u8; 32], u64> = req.held.iter().map(|h| (h.pubkey, h.rev)).collect();
    let current: HashSet<[u8; 32]> = all.iter().map(|(pk, _)| *pk).collect();
    let removed: Vec<[u8; 32]> = held
        .keys()
        .filter(|pk| !current.contains(*pk))
        .copied()
        .collect();
    let seeds: Vec<Seed> = all
        .into_iter()
        .filter(|(pk, s)| held.get(pk) != Some(&s.rev))
        .map(|(_, s)| s)
        .collect();
    (seeds, removed, true)
}

/// An opaque revision of a seed's **peering-relevant** content, for delta sync ([`Seed::rev`]).
/// Deliberately excludes the attestation blob: its `issued_at`/`expires_at` roll every epoch, and a
/// rev that churned on refresh would force a full resend each epoch (the renewal herd we're avoiding)
/// — attestation freshness is the client's own Option-A concern instead. The client treats the value
/// as opaque, so the hash need only be stable within one coordinator process.
fn seed_rev(
    mp: &MemberPresence,
    endpoint: Option<SocketAddr>,
    punch: Option<SocketAddr>,
    networks: &[SharedNetwork],
    relay: &Option<RelayInfo>,
    ice: &Option<IceParams>,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    // Serialize the peering-relevant fields to a canonical byte string (struct/vec order is stable)
    // and hash that — avoids requiring `Hash` on every wire type.
    let bytes = serde_json::to_vec(&(
        mp.pubkey,
        mp.ip.octets(),
        mp.is_primary,
        &mp.username,
        &mp.device_name,
        endpoint,
        punch,
        networks,
        relay,
        ice,
    ))
    .unwrap_or_default();
    bytes.hash(&mut h);
    h.finish()
}

/// Re-key supersede (design.md §9): a device regenerating its WG key registers under a *new* pubkey,
/// orphaning the old one — its presence would linger (never self-evicted, since its owner now
/// refreshes under the new key) until the reaper ages it out. If the client still holds the old
/// device token it proves ownership, so retire the old device *now*: drop its store row (freeing its
/// IP and stale DNS name) and evict its presence everywhere, recording the affected scopes in
/// `changed`.
/// Possession of the old token authorizes this; we still require it resolve to the same owner so one
/// member can't retire another's device even with a leaked token.
async fn retire_superseded(
    st: &AppState,
    req: &RegisterReq,
    user_id: u64,
    changed: &mut BTreeSet<Scope>,
) -> Result<(), ApiError> {
    let Some(old_token) = &req.supersede else {
        return Ok(());
    };
    let Some((owner, old_pubkey)) = st
        .store
        .device_by_token(old_token)
        .await
        .map_err(internal)?
    else {
        return Ok(());
    };
    if !should_supersede(owner, old_pubkey, user_id, req.wg_pubkey) {
        return Ok(());
    }
    st.store
        .remove_device(user_id, &old_pubkey)
        .await
        .map_err(internal)?;
    for (g, r) in st.presence.networks_of(&old_pubkey) {
        if st.presence.evict(g, r, &old_pubkey) {
            changed.insert(Scope::Guild(g));
        }
    }
    // …and from the per-user own-device set, so a re-keyed device's siblings prune the retired
    // pubkey immediately rather than waiting for the reaper.
    if st.presence.evict_self(owner, &old_pubkey) {
        changed.insert(Scope::User(owner));
    }
    Ok(())
}

/// Whether a re-key supersede request should retire the old device. The old device token proved
/// possession; we retire the pubkey it names iff it belongs to the *same* owner (a leaked token
/// can't retire another member's device) and it's a *different* key than the one now registering
/// (a steady-state register carrying its own current token is a no-op, not a self-retire).
fn should_supersede(
    token_owner: u64,
    old_pubkey: [u8; 32],
    caller_user: u64,
    caller_pubkey: [u8; 32],
) -> bool {
    token_owner == caller_user && old_pubkey != caller_pubkey
}

/// Whether `user_id` holds a role in any registered network — the gate that decides whether a
/// register may allocate a mesh address at all. Fills `cache` (keyed by guild) as it goes, so the
/// caller's own membership pass reuses it and each guild is queried from the role source only once
/// across both. Short-circuits on the first held role.
async fn holds_any_network_role(
    roles: &dyn RoleSource,
    networks: &[Network],
    user_id: u64,
    cache: &mut HashMap<u64, Option<MemberRoles>>,
) -> bool {
    for net in networks {
        let member = match cache.get(&net.guild_id) {
            Some(m) => m.clone(),
            None => {
                let m = roles.member(net.guild_id, user_id).await;
                cache.insert(net.guild_id, m.clone());
                m
            }
        };
        if member.is_some_and(|m| m.role_ids.contains(&net.role_id)) {
            return true;
        }
    }
    false
}

/// One trust anchor per guild the caller participates in (covers every peer's guild too, since shared
/// guilds are a subset). The client pins each independently and re-pins via its chain.
async fn build_anchors(
    st: &AppState,
    grant_guilds: &BTreeSet<u64>,
) -> Result<Vec<GuildAnchor>, ApiError> {
    let mut anchors = Vec::with_capacity(grant_guilds.len());
    for &g in grant_guilds {
        let key = st.guild_keys.get(g).await.map_err(internal)?;
        anchors.push(GuildAnchor {
            guild_id: g,
            pubkey: key.signer.anchor_bytes(),
            rotation_chain: key.rotation_chain.clone(),
        });
    }
    Ok(anchors)
}

/// Auto-update manifest, signed on demand with a key the caller holds (the smallest `guild_id`,
/// deterministically) so the client verifies it against an anchor it has pinned (design.md §3.1 — no
/// separate deployment-wide key). `None` when no manifest is configured or the caller holds no
/// scope. A personal-scope caller signs under
/// [`PERSONAL_SCOPE`](common::attestation::PERSONAL_SCOPE), which *is* one key per deployment — but
/// it is a key this coordinator already holds alongside every guild key, so it widens no trust
/// boundary that a guild key didn't already sit on.
async fn sign_release(
    st: &AppState,
    grant_guilds: &BTreeSet<u64>,
) -> Result<Option<String>, ApiError> {
    // Clone the manifest out before the await so the RwLock guard isn't held across it.
    let manifest = st.release.read().unwrap().clone();
    match (manifest, grant_guilds.iter().next()) {
        (Some(m), Some(&g)) => {
            let key = st.guild_keys.get(g).await.map_err(internal)?;
            Ok(Some(key.signer.sign_to_base64(&m).map_err(internal)?))
        }
        _ => Ok(None),
    }
}

/// The community label for a guild: the admin-set slug, else the guild name.
async fn community_of(st: &AppState, guild_id: u64) -> anyhow::Result<String> {
    match st.store.community_slug(guild_id).await? {
        Some(s) => Ok(s),
        None => Ok(st.roles.guild_name(guild_id).await.unwrap_or_default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allocation_gate_opens_only_for_a_role_holder() {
        use crate::config::{FakeConfig, FakeGuild, FakeMember};
        use crate::roles::FakeRoleSource;

        // Guild 1 registers role 10 as a network. User 7 holds it; user 8 is a member but with a
        // different role; user 9 is not a member at all.
        let roles = FakeRoleSource::new(FakeConfig {
            guilds: vec![FakeGuild {
                id: 1,
                name: "acme".into(),
                members: vec![
                    FakeMember {
                        user_id: 7,
                        username: "holder".into(),
                        role_ids: vec![10],
                    },
                    FakeMember {
                        user_id: 8,
                        username: "other".into(),
                        role_ids: vec![99],
                    },
                ],
            }],
        });
        let networks = vec![Network {
            guild_id: 1,
            role_id: 10,
            name: "net".into(),
        }];

        // Role holder → gate opens (a mesh address may be allocated).
        let mut c = HashMap::new();
        assert!(holds_any_network_role(&roles, &networks, 7, &mut c).await);
        // Member without the network's role → gate stays closed (no allocation, TM-2).
        let mut c = HashMap::new();
        assert!(!holds_any_network_role(&roles, &networks, 8, &mut c).await);
        // Non-member (e.g. a Discord user who only authorized the app) → gate stays closed.
        let mut c = HashMap::new();
        assert!(!holds_any_network_role(&roles, &networks, 9, &mut c).await);
    }

    #[test]
    fn supersede_retires_only_same_owner_different_key() {
        let old = [7u8; 32];
        let new = [8u8; 32];
        // Re-key: same owner, token names the old key → retire it.
        assert!(should_supersede(42, old, 42, new));
        // Steady state: token names the key now registering → no-op (don't self-retire).
        assert!(!should_supersede(42, new, 42, new));
        // Leaked/foreign token: names another owner's device → refuse (can't retire theirs).
        assert!(!should_supersede(99, old, 42, new));
    }
}
