//! Coordinator client: register/refresh, verify our grant + seeds against the pinned anchor.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{bail, Context};
use common::api::{Grant, GuildAttestation, NetworkRef, RegisterReq, RegisterResp};
use common::attestation::{verify_attestation, Attestation};
use common::crypto::{anchor_from_bytes, WgPublicKey};
use common::now_unix;
use common::wire::Signed;

use crate::keys;

/// The coordinator refused us on wire protocol version (`426 Upgrade Required`) — our range and its
/// range don't overlap, so no amount of retrying helps until one side is updated.
///
/// A distinct type rather than a string, because the daemon must treat it differently from every
/// other failure: retrying it is pointless, and the GUI needs to say "update" instead of showing a
/// connectivity error. The coordinator's message says which side is stale; we pass it through.
#[derive(Debug)]
pub struct UpgradeRequired(pub String);

impl std::fmt::Display for UpgradeRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for UpgradeRequired {}

/// Return the response if it's a success status, else read the body and bail with the
/// coordinator's error. `what` names the route for the error message.
async fn ensure_ok(resp: reqwest::Response, what: &str) -> anyhow::Result<reqwest::Response> {
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::UPGRADE_REQUIRED {
            return Err(anyhow::Error::new(UpgradeRequired(body)));
        }
        bail!("coordinator rejected {what}: {status}: {body}");
    }
    Ok(resp)
}

/// Our own verified device: its `/32`, hostname, and the networks it belongs to.
pub struct SelfDevice {
    pub community_name: String,
    /// The owner's Discord user id (from our verified attestation). Lets the client recognize its
    /// own other devices among the peers — they carry this same `user_id` — for the "My devices"
    /// display grouping.
    pub user_id: u64,
    /// The owner's Discord handle this device is enrolled as (the `<user>` label).
    pub username: String,
    pub networks: Vec<String>,
    pub wg_ip: Ipv4Addr,
    /// The deployment's mesh CIDR (from our signed attestation) — checked against local interfaces
    /// for overlap, and the range future multi-coordinator support would route.
    pub wg_net: ipnet::Ipv4Net,
    pub hostname: String,
    pub is_primary: bool,
    /// Our own grant attestation's expiry (unix secs). The daemon forces a *completing* coordinator
    /// renewal before this, so our served attestation (peer-direct refresh) never goes stale — only a
    /// completed poll refreshes the grant, and the idle re-poll otherwise keeps cancelling the park.
    pub grant_expires_at: u64,
    /// `<user>.unity.internal` if we're the owner's primary device.
    pub primary_alias: Option<String>,
    /// Every network our roles grant (role@guild) with per-device enabled state — for the toggle.
    pub networks_status: Vec<common::api::NetworkStatus>,
}

/// This device's relay-related fields for a register/refresh (§7.2, M5.4): whether we offer
/// ourselves as a TURN relay (+ our address/secret), and which peers we currently can't reach and
/// want a relay for. Bundled so the register/refresh signatures don't sprout four more arguments.
#[derive(Clone, Default)]
pub struct RelayReport {
    pub capable: bool,
    pub addr: Option<SocketAddr>,
    pub secret: Option<String>,
    pub need_relay: Vec<[u8; 32]>,
    pub allocated: Vec<common::api::RelayAllocation>,
}

/// A verified co-member to peer with.
#[derive(Clone)]
pub struct SeedPeer {
    pub pubkey: [u8; 32],
    /// The peer owner's Discord id + handle (from the verified attestation). `user_id` is the
    /// identity a local peer-block acts on — stable across the owner re-keying/renaming a device.
    pub user_id: u64,
    pub username: String,
    pub ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
    /// Hole-punch target (peer's reflexive `ip:port`) when neither side is directly dialable.
    pub punch: Option<SocketAddr>,
    /// `<device>.<user>.unity.internal`.
    pub hostname: String,
    /// `<user>.unity.internal` if this is the owner's primary device, else `None`.
    pub primary_alias: Option<String>,
    /// Networks shared with us (name + community) — used to scope `expose --net` and to show which
    /// server each shared network came from.
    pub networks: Vec<common::api::SharedNetwork>,
    /// Relay reservation for reaching this peer when direct + punch both fail (§7.2, M5.4): the TURN
    /// server + credentials to allocate on, and (once known) the peer's own relayed address.
    pub relay: Option<common::api::RelayInfo>,
    /// The peer's ICE offer (ufrag/pwd + candidates) for reaching us (§7.2, M5.5), relayed by the
    /// coordinator. `None` until the peer offers ICE for this pair.
    pub ice: Option<common::api::IceParams>,
    /// Opaque per-seed revision ([`common::api::Seed::rev`]) — echoed back in the next refresh's
    /// `held` so the coordinator resends this peer only when it changes (delta sync).
    pub rev: u64,
    /// This peer's attestation expiry (unix secs). The daemon forces a **full** refresh (empty
    /// `held`) once its soonest-expiring peer nears this, so delta-held attestations never lapse.
    pub expires_at: u64,
}

/// The engine-side inputs to a coordinator `register`/`refresh` POST. `post` maps these onto the
/// wire [`RegisterReq`], filling the fixed fields (proto/caps/version) and expanding `relay`. Bundled
/// into one struct so the call sites read as named fields instead of a dozen-plus positional args.
pub struct CoordReq {
    pub wg_pubkey: WgPublicKey,
    pub device_name: String,
    pub endpoint: Option<SocketAddr>,
    pub enrollment_key: Option<String>,
    /// Last-seen version echoed as `since`. `Some` on a renewal (the coordinator holds the request
    /// until membership changes or ~TTL/2 elapses); `None` returns immediately (no long-poll hold).
    pub since: Option<u64>,
    pub disabled_networks: Vec<NetworkRef>,
    pub observed: Vec<common::api::ObservedEndpoint>,
    /// Our stored device token, so the coordinator retires a prior pubkey we just re-keyed away from
    /// (no-op unless the token names a different key). Only sent on the initial register.
    pub supersede: Option<String>,
    pub paused: bool,
    pub peer_own_devices: bool,
    pub relay: RelayReport,
    pub ice: Vec<common::api::IceEndpoint>,
    pub held: Vec<common::api::HeldPeer>,
}

/// First contact: returns immediately (no hold) and carries no peer state yet.
pub async fn register(
    base_url: &str,
    state_dir: &Path,
    req: CoordReq,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    post(
        base_url,
        state_dir,
        "register",
        CoordReq {
            since: None, // no long-poll hold on first contact
            observed: Vec::new(),
            ice: Vec::new(),  // no peers yet → nothing to report
            held: Vec::new(), // no held peers yet → full snapshot
            ..req
        },
    )
    .await
}

/// Long-poll `/refresh`: `req.since` is the last-seen `version`; the coordinator holds the request
/// until membership changes or ~TTL/2 elapses (renewal). Returns the new version.
pub async fn refresh(
    base_url: &str,
    state_dir: &Path,
    req: CoordReq,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    // refresh never supersedes: a re-key retires the old key on the initial register.
    post(
        base_url,
        state_dir,
        "refresh",
        CoordReq {
            supersede: None,
            ..req
        },
    )
    .await
}

async fn post(
    base_url: &str,
    state_dir: &Path,
    path: &str,
    req: CoordReq,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    // Total timeout must exceed the coordinator's long-poll hold, else we'd cancel a legit held
    // request. The connect timeout is short, though: an unreachable coordinator should fail fast so
    // the daemon loop keeps ticking (peer-direct refresh, cache) instead of hanging on a dead TCP
    // connect — the OS default is ~130s, long enough to starve the mesh's own freshness path.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            common::LONGPOLL_HOLD_SECS + 60,
        ))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .context("building http client")?;
    let url = format!("{base_url}/{path}");

    let resp = client
        .post(&url)
        .json(&RegisterReq {
            wg_pubkey: req.wg_pubkey,
            device_name: req.device_name,
            enrollment_key: req.enrollment_key,
            endpoint: req.endpoint,
            since: req.since,
            disabled_networks: req.disabled_networks,
            observed: req.observed,
            supersede: req.supersede,
            paused: req.paused,
            peer_own_devices: req.peer_own_devices,
            relay_capable: req.relay.capable,
            relay_addr: req.relay.addr,
            relay_secret: req.relay.secret,
            need_relay: req.relay.need_relay,
            relay_allocated: req.relay.allocated,
            ice: req.ice,
            proto: common::PROTOCOL_VERSION,
            proto_min: common::MIN_PROTOCOL_VERSION,
            caps: common::CAPABILITIES.iter().map(|c| c.to_string()).collect(),
            client_version: common::VERSION.to_string(),
            held: req.held,
        })
        .send()
        .await
        .with_context(|| format!("sending /{path}"))?;
    let resp = ensure_ok(resp, path).await?;
    let resp: RegisterResp = resp.json().await.context("decoding RegisterResp")?;

    // The coordinator echoes the version it selected. It negotiated within the range we offered, so
    // a value outside it means the two sides disagree about what was agreed — worth saying out loud,
    // since everything downstream decodes on the assumption that they don't.
    if resp.proto != 0
        && !(common::MIN_PROTOCOL_VERSION..=common::PROTOCOL_VERSION).contains(&resp.proto)
    {
        tracing::warn!(
            selected = resp.proto,
            ours = %format!("{}..={}", common::MIN_PROTOCOL_VERSION, common::PROTOCOL_VERSION),
            coordinator = %format!("{}..={}", resp.proto_min, resp.proto_max),
            "coordinator selected a wire protocol version outside the range we offered"
        );
    }

    // Trust gate: pin every guild anchor the response carries (TOFU per guild, design.md §3.1). On a
    // change we accept only a valid rotation path for that guild; a MITM that swaps an anchor (and
    // self-signs) is rejected here — before we trust any attestation. Every register *and* refresh
    // goes through this, so the pins hold in steady state, not just at first contact.
    for a in &resp.anchors {
        keys::pin_anchor(state_dir, a.guild_id, &a.pubkey, &a.rotation_chain)?;
    }
    let pinned = pinned_anchors(&resp, state_dir);
    let now = now_unix();

    let device = match &resp.grant {
        Some(grant) => {
            let (att, community) = verify_grant(grant, &pinned, now).context("verifying grant")?;
            let hostname = att.hostname();
            let primary_alias = att.primary_alias();
            Some(SelfDevice {
                community_name: community,
                user_id: att.user_id,
                username: att.username.clone(),
                networks: grant.networks.clone(),
                wg_ip: att.wg_ip,
                wg_net: att.wg_net,
                hostname,
                is_primary: att.is_primary,
                grant_expires_at: att.expires_at,
                primary_alias,
                networks_status: resp.networks.clone(),
            })
        }
        None => None,
    };
    Ok((resp, device))
}

/// The trusted `(guild_id, anchor-bytes)` pairs read **from disk** (the pins) for every guild the
/// response references. The response was already gated through [`keys::pin_anchor`], so these — not
/// the anchors the response carries — are the keys we verify attestations against.
fn pinned_anchors(resp: &RegisterResp, state_dir: &Path) -> Vec<(u64, [u8; 32])> {
    resp.anchors
        .iter()
        .filter_map(|a| {
            keys::load_anchor(state_dir, a.guild_id)
                .ok()
                .map(|pk| (a.guild_id, pk))
        })
        .collect()
}

/// Verify one attestation against whichever pinned guild anchor it is scoped to (the `guild_id`
/// check inside [`verify_attestation`] binds it to that guild). Returns the verified attestation, or
/// `None` if no pinned anchor accepts it — wrong guild, bad signature, or expired.
/// `schema` is the layout the sender declared in [`GuildAttestation::att_schema`] — the blob is
/// postcard, so we must be told rather than guess.
fn verify_against_pinned(
    signed: &Signed,
    pinned: &[(u64, [u8; 32])],
    now: u64,
    schema: u32,
) -> Option<Attestation> {
    for (guild_id, pk) in pinned {
        let Ok(anchor) = anchor_from_bytes(pk) else {
            continue;
        };
        if let Ok(att) = verify_attestation(signed, &anchor, now, *guild_id, schema) {
            return Some(att);
        }
    }
    None
}

/// The first attestation in `blobs` that both verifies against a pinned guild anchor and satisfies
/// `accept`, paired with the source `GuildAttestation`. The shared trust gate behind grant, seed,
/// and pull verification — keeping the three from drifting apart. Undecodable or unverifiable blobs
/// (and ones `accept` rejects) are skipped, so `None` means *none* cleared: fail closed, and one bad
/// blob never rejects the rest of the batch.
fn first_verified<'a>(
    blobs: &'a [GuildAttestation],
    pinned: &[(u64, [u8; 32])],
    now: u64,
    accept: impl Fn(&Attestation) -> bool,
) -> Option<(&'a GuildAttestation, Attestation)> {
    blobs.iter().find_map(|ga| {
        let signed = Signed::from_base64(&ga.attestation).ok()?;
        let att = verify_against_pinned(&signed, pinned, now, ga.att_schema)?;
        accept(&att).then_some((ga, att))
    })
}

/// Verify our grant: return the first per-guild attestation that verifies against its pinned anchor,
/// with its community name (the representative hostname for this device). Fails closed if none do.
fn verify_grant(
    grant: &Grant,
    pinned: &[(u64, [u8; 32])],
    now: u64,
) -> anyhow::Result<(Attestation, String)> {
    first_verified(&grant.attestations, pinned, now, |_| true)
        .map(|(ga, att)| (att, ga.community_name.clone()))
        .ok_or_else(|| {
            anyhow::anyhow!("no grant attestation verified against a pinned guild anchor")
        })
}

/// Verify a peer's self-served attestations (from a p2p pull, `docs/gossip-refresh.md`) against our
/// pinned anchors — the same trust gate as the coordinator path, so a pull establishes no new trust.
/// Returns the attestation for `expected_pubkey` iff one verifies, its `wg_ip` is inside its signed
/// `wg_net`, and it is strictly fresher than `current_expiry`. Binding `expected_pubkey` stops a peer
/// from serving a (validly-signed) attestation for a *different* device.
pub fn verify_pulled(
    blobs: &[GuildAttestation],
    expected_pubkey: [u8; 32],
    current_expiry: u64,
    state_dir: &Path,
    now: u64,
) -> Option<Attestation> {
    let pinned = keys::load_all_pinned(state_dir);
    first_verified(blobs, &pinned, now, |att| {
        att.wg_pubkey == expected_pubkey
            && att.wg_net.contains(&att.wg_ip)
            && att.expires_at > current_expiry
    })
    .map(|(_, att)| att)
}

/// Fold a peer-direct-verified attestation into a held seed: advance its expiry and re-derive the
/// attestation-scoped identity fields. Leaves the coordinator-brokered transport fields (endpoint,
/// punch, networks, relay, ice, rev) untouched — a peer serves only its own identity, not the
/// pair-state the coordinator brokers.
pub fn apply_pulled(seed: &mut SeedPeer, att: &Attestation) {
    seed.user_id = att.user_id;
    seed.username = att.username.clone();
    seed.ip = att.wg_ip;
    seed.hostname = att.hostname();
    seed.primary_alias = att.primary_alias();
    seed.expires_at = att.expires_at;
}

/// Resolve the coordinator's STUN responder address from the port it advertises: its host is the
/// one we already dial for the API. The coordinator publishes only a port because behind NAT (a
/// container bridge, a cloud VM whose public IP is NAT'd to the interface) it can't know its own
/// reachable address — but the URL the admin configured here is reachable by construction.
///
/// `None` if the port is unset, the URL has no host, or resolution finds no address.
pub async fn stun_addr(base_url: &str, port: Option<u16>) -> Option<SocketAddr> {
    let host = reqwest::Url::parse(base_url).ok()?.host_str()?.to_string();
    tokio::net::lookup_host((host, port?)).await.ok()?.next()
}

/// Fetch the public PKCE config (Discord `client_id`, fake-mode flag) so the engine can run the
/// authorization-code + PKCE flow itself.
pub async fn pkce_config(base_url: &str) -> anyhow::Result<common::api::PkceConfigResp> {
    let resp = reqwest::Client::new()
        .get(format!("{base_url}/oauth/pkce-config"))
        .send()
        .await
        .context("sending /oauth/pkce-config")?;
    let resp = ensure_ok(resp, "oauth/pkce-config").await?;
    resp.json().await.context("decoding PkceConfigResp")
}

/// Finish login: hand the coordinator the access token we obtained so it verifies it and binds our
/// pubkey to the authenticated user. Our next register then succeeds (no enrollment key needed).
pub async fn oauth_complete(
    base_url: &str,
    wg_pubkey: WgPublicKey,
    access_token: &str,
) -> anyhow::Result<()> {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/oauth/complete"))
        .json(&common::api::OauthCompleteReq {
            wg_pubkey,
            access_token: access_token.to_string(),
        })
        .send()
        .await
        .context("sending /oauth/complete")?;
    ensure_ok(resp, "oauth/complete").await?;
    Ok(())
}

/// Send an owner-scoped device management op, authenticated by the device token.
pub async fn manage(
    base_url: &str,
    token: String,
    op: common::api::ManageOp,
) -> anyhow::Result<common::api::ManageResp> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base_url}/devices/manage"))
        .json(&common::api::ManageReq { token, op })
        .send()
        .await
        .context("sending /devices/manage")?;
    let resp = ensure_ok(resp, "manage").await?;
    resp.json().await.context("decoding ManageResp")
}

/// Verify the seeds in a response against the **pinned** per-guild anchors → the co-members to peer
/// with. Anchors come from disk, not the response: the response was already gated through
/// [`keys::pin_anchor`] in [`post`], so a pinned key is what we trust (re-pinned already if a valid
/// rotation occurred). Each seed is admitted on the first of its shared-guild attestations that
/// verifies against the matching pinned anchor; a seed none of whose attestations verify is **skipped**
/// (fail closed — a substituted/self-signed seed is never peered — but one bad seed doesn't deny the
/// rest of the mesh, which is what peer version skew would otherwise cause).
pub fn verified_seeds(resp: &RegisterResp, state_dir: &Path) -> anyhow::Result<Vec<SeedPeer>> {
    let pinned = pinned_anchors(resp, state_dir);
    let now = now_unix();
    let mut peers = Vec::new();
    let mut admitted = 0usize;
    for seed in &resp.seeds {
        // Any one of the peer's shared-guild attestations verifying admits it; the hostname no longer
        // depends on which guild (community left the name — see `Attestation::hostname`), so we just
        // need the first that clears a pinned anchor.
        let verified =
            first_verified(&seed.attestations, &pinned, now, |_| true).map(|(_, att)| att);
        // Still fail closed — an unverifiable seed is never peered — but per *peer*, not per batch.
        // A `?` here let one peer deny the whole mesh: a single co-member running a build whose
        // attestation layout we can't read (or mid-rotation, or corrupt) would drop every other peer
        // along with it. That's the failure mode version skew actually produces, so it must degrade
        // to "that peer is unreachable", matching the `wg_net` skip below.
        let Some(att) = verified else {
            tracing::warn!(
                "seed has no attestation signed by a pinned guild anchor — skipping peer"
            );
            continue;
        };
        // Defence in depth: the signed `wg_net` exists to bound `wg_ip` (attestation.rs). Refuse to
        // route a `/32` that falls outside it, so a compromised or buggy guild key can't get a
        // co-member's allowed-IPs pointed at an off-mesh address (a LAN gateway, a public host).
        // Skip just this peer rather than failing the batch — the bogus route is never installed
        // either way, and one bad attestation shouldn't deny peering with everyone else.
        if !att.wg_net.contains(&att.wg_ip) {
            tracing::warn!(
                peer_ip = %att.wg_ip, wg_net = %att.wg_net,
                "seed attestation wg_ip is outside its signed wg_net — skipping peer"
            );
            continue;
        }
        admitted += 1;
        peers.push(SeedPeer {
            pubkey: att.wg_pubkey,
            user_id: att.user_id,
            username: att.username.clone(),
            ip: att.wg_ip,
            endpoint: seed.endpoint,
            punch: seed.punch,
            hostname: att.hostname(),
            primary_alias: att.primary_alias(),
            networks: seed.networks.clone(),
            relay: seed.relay.clone(),
            ice: seed.ice.clone(),
            rev: seed.rev,
            expires_at: att.expires_at,
        });
    }
    // Per-peer skipping means a wholesale substitution (a MITM signing every seed with its own key)
    // now reads as "nobody is reachable" instead of an error. Losing every peer at once is not the
    // same event as losing one, so say so at error level — it is the signature of an attack or a
    // botched anchor rotation, and it would otherwise be a silent, empty mesh.
    if admitted == 0 && !resp.seeds.is_empty() {
        tracing::error!(
            seeds = resp.seeds.len(),
            "every seed failed verification against the pinned anchors — peering with no one"
        );
    }
    Ok(peers)
}

/// Fold a `/refresh` response into the peer set the daemon holds. A **full** response
/// (`partial == false`) replaces it outright (today's behaviour); a **delta** upserts the verified
/// changed peers by pubkey, drops the ones in `removed`, and keeps the rest untouched — so an
/// unchanged peer's attestation and endpoint survive across a delta that didn't mention it.
pub fn merge_seeds(
    prev: &[SeedPeer],
    resp: &RegisterResp,
    state_dir: &Path,
) -> anyhow::Result<Vec<SeedPeer>> {
    let changed = verified_seeds(resp, state_dir)?;
    if !resp.partial {
        return Ok(changed);
    }
    let dropped: std::collections::HashSet<[u8; 32]> = resp.removed.iter().copied().collect();
    let mut by_pubkey: std::collections::HashMap<[u8; 32], SeedPeer> = prev
        .iter()
        .filter(|p| !dropped.contains(&p.pubkey))
        .map(|p| (p.pubkey, p.clone()))
        .collect();
    for p in changed {
        by_pubkey.insert(p.pubkey, p);
    }
    Ok(by_pubkey.into_values().collect())
}

/// The `held` set to send on the next refresh: our current peers' `(pubkey, rev)`, so the coordinator
/// returns only what changed. Returns empty to force a **full** refresh when the soonest-expiring
/// peer attestation is within `refresh_margin` of lapsing (Option A) — delta responses don't resend
/// unchanged attestations, so the client pulls a full one before they expire.
pub fn held_for_refresh(
    seeds: &[SeedPeer],
    now: u64,
    refresh_margin: u64,
) -> Vec<common::api::HeldPeer> {
    let soonest = seeds.iter().map(|p| p.expires_at).min();
    match soonest {
        Some(exp) if exp <= now + refresh_margin => Vec::new(), // force full to refresh attestations
        _ => seeds
            .iter()
            .map(|p| common::api::HeldPeer {
                pubkey: p.pubkey,
                rev: p.rev,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use common::api::{GuildAnchor, GuildAttestation, RegisterResp, Seed};
    use common::attestation::{ATTESTATION_SCHEMA_EMIT, ATTESTATION_SCHEMA_V2};
    use common::crypto::CoordinatorKey;

    const GUILD: u64 = 42;

    /// A self-cleaning state dir with `GUILD`'s anchor already pinned to a fresh honest key —
    /// the starting point every seed-verification test needs.
    fn pinned_state_dir(tag: &str) -> (TempDir, CoordinatorKey) {
        let dir = TempDir::new(&format!("coord-{tag}"));
        let honest = CoordinatorKey::generate();
        keys::pin_anchor(&dir, GUILD, &honest.anchor_bytes(), &[]).unwrap();
        (dir, honest)
    }

    /// The attestation every test here signs, varying only the fields any of them care about; the
    /// owner identity is fixed because nothing verifies against it.
    fn test_attestation(
        guild_id: u64,
        wg_ip: Ipv4Addr,
        wg_net: &str,
        wg_pubkey: [u8; 32],
        expires_at: u64,
    ) -> Attestation {
        Attestation {
            guild_id,
            user_id: 5,
            username: "neo".into(),
            device_name: "box".into(),
            is_primary: false,
            wg_ip,
            wg_net: wg_net.parse().unwrap(),
            wg_pubkey,
            issued_at: 0,
            expires_at,
        }
    }

    /// A seed with one attestation for `guild_id`, signed by `key` (attacker or honest coordinator).
    fn seed_signed_by(key: &CoordinatorKey, guild_id: u64) -> Seed {
        seed_with_ip(key, guild_id, Ipv4Addr::new(100, 64, 0, 9), "100.64.0.0/10")
    }

    /// Like `seed_signed_by`, but with an explicit signed `wg_ip` / `wg_net` (to exercise the
    /// off-mesh-`/32` guard).
    fn seed_with_ip(key: &CoordinatorKey, guild_id: u64, wg_ip: Ipv4Addr, wg_net: &str) -> Seed {
        seed_with_ip_schema(key, guild_id, wg_ip, wg_net, ATTESTATION_SCHEMA_EMIT)
    }

    /// Sign `att` in `schema` and wrap it in the envelope that declares that layout — the pairing the
    /// reader depends on.
    fn signed_ga(key: &CoordinatorKey, att: &Attestation, schema: u32) -> GuildAttestation {
        GuildAttestation {
            attestation: common::attestation::sign_attestation(key, att, schema)
                .unwrap()
                .to_base64(),
            community_name: "c".into(),
            att_schema: schema,
        }
    }

    fn seed_with_ip_schema(
        key: &CoordinatorKey,
        guild_id: u64,
        wg_ip: Ipv4Addr,
        wg_net: &str,
        schema: u32,
    ) -> Seed {
        let expires_at = now_unix() + common::ATTESTATION_TTL_SECS;
        let att = test_attestation(guild_id, wg_ip, wg_net, [9u8; 32], expires_at);
        Seed {
            attestations: vec![signed_ga(key, &att, schema)],
            endpoint: None,
            punch: None,
            networks: Vec::new(),
            relay: None,
            ice: None,
            rev: 0,
        }
    }

    fn resp_with_seeds(
        anchor_guild: u64,
        anchor_key: &CoordinatorKey,
        seeds: Vec<Seed>,
    ) -> RegisterResp {
        RegisterResp {
            anchors: vec![GuildAnchor {
                guild_id: anchor_guild,
                pubkey: anchor_key.anchor_bytes(),
                rotation_chain: Vec::new(),
            }],
            seeds,
            version: 1,
            proto: common::PROTOCOL_VERSION,
            server_version: common::VERSION.to_string(),
            ..Default::default()
        }
    }

    /// Regression for the steady-state MITM: after we pin the honest anchor for a guild, a later
    /// response that self-signs its seeds with an attacker key must be rejected — seeds are verified
    /// against the PINNED anchor, not the anchor the response carries. This equally covers tenant
    /// isolation (design.md §3.1): any key that isn't the one pinned for the guild — including
    /// another guild's honest key — fails the same signature check.
    #[test]
    fn seeds_verified_against_pinned_not_response_anchor() {
        let (dir, honest) = pinned_state_dir("pinned");
        let attacker = CoordinatorKey::generate();

        // Attacker-substituted response: its own anchor for GUILD + seeds self-signed by it. The
        // pin on disk (honest) is what we verify against, so the forged seed is rejected. Rejection
        // is per-peer (it's skipped, not an error), so the property to assert is that it was never
        // *admitted* — a forged seed must never become a peer we route to.
        let forged = resp_with_seeds(GUILD, &attacker, vec![seed_signed_by(&attacker, GUILD)]);
        assert!(
            verified_seeds(&forged, &dir).unwrap().is_empty(),
            "seeds signed by a non-pinned anchor must never be peered"
        );

        // Sanity: seeds legitimately signed by the pinned anchor still verify.
        let honest_resp = resp_with_seeds(GUILD, &attacker, vec![seed_signed_by(&honest, GUILD)]);
        assert_eq!(verified_seeds(&honest_resp, &dir).unwrap().len(), 1);

        // The isolation property itself: one forged seed alongside an honest one drops only the
        // forgery. Before per-peer skipping this returned `Err` and denied peering with everyone —
        // which is exactly how a single skewed or malicious peer could deny the whole mesh.
        let mixed = resp_with_seeds(
            GUILD,
            &honest,
            vec![
                seed_signed_by(&attacker, GUILD),
                seed_with_ip(
                    &honest,
                    GUILD,
                    Ipv4Addr::new(100, 64, 0, 11),
                    "100.64.0.0/10",
                ),
            ],
        );
        let peers = verified_seeds(&mixed, &dir).unwrap();
        assert_eq!(peers.len(), 1, "only the honestly-signed peer is admitted");
        assert_eq!(peers[0].ip, Ipv4Addr::new(100, 64, 0, 11));
    }

    /// A partially-upgraded mesh puts both attestation layouts in one snapshot. Each seed is decoded
    /// per its own envelope hint, so peers on either side of the rollout mesh together — that's the
    /// whole reason the hint rides outside the signed blob.
    #[test]
    fn seeds_of_mixed_layouts_all_verify() {
        let (dir, honest) = pinned_state_dir("mixed-layout");
        let resp = resp_with_seeds(
            GUILD,
            &honest,
            vec![
                seed_with_ip_schema(
                    &honest,
                    GUILD,
                    Ipv4Addr::new(100, 64, 0, 9),
                    "100.64.0.0/10",
                    ATTESTATION_SCHEMA_EMIT,
                ),
                seed_with_ip_schema(
                    &honest,
                    GUILD,
                    Ipv4Addr::new(100, 64, 0, 10),
                    "100.64.0.0/10",
                    ATTESTATION_SCHEMA_V2,
                ),
            ],
        );
        let peers = verified_seeds(&resp, &dir).unwrap();
        assert_eq!(peers.len(), 2, "both layouts must be admitted");
    }

    /// Defence in depth: a seed whose signature verifies but whose signed `wg_ip` falls outside its
    /// signed `wg_net` is dropped (not routed) — a compromised/buggy guild key can't point a
    /// co-member's `/32` at an off-mesh address. The in-net peer in the same batch still admits.
    #[test]
    fn seed_wg_ip_outside_signed_net_is_dropped() {
        let (dir, honest) = pinned_state_dir("wg-ip-oob");

        let resp = resp_with_seeds(
            GUILD,
            &honest,
            vec![
                seed_with_ip(
                    &honest,
                    GUILD,
                    Ipv4Addr::new(100, 64, 0, 9),
                    "100.64.0.0/10",
                ),
                // 10.0.0.1 is not inside the signed 100.64.0.0/10 → must be skipped.
                seed_with_ip(&honest, GUILD, Ipv4Addr::new(10, 0, 0, 1), "100.64.0.0/10"),
            ],
        );
        let peers = verified_seeds(&resp, &dir).unwrap();
        assert_eq!(peers.len(), 1, "only the in-mesh peer is admitted");
        assert_eq!(peers[0].ip, Ipv4Addr::new(100, 64, 0, 9));
    }

    fn sp(pubkey: [u8; 32], rev: u64, expires_at: u64) -> SeedPeer {
        SeedPeer {
            pubkey,
            user_id: 1,
            username: "u".into(),
            ip: Ipv4Addr::new(100, 64, 0, 1),
            endpoint: None,
            punch: None,
            hostname: "h".into(),
            primary_alias: None,
            networks: vec![],
            relay: None,
            ice: None,
            rev,
            expires_at,
        }
    }

    /// Delta sync: a full response replaces the held set; a partial one upserts the changed peers,
    /// drops the `removed` ones, and leaves everything it didn't mention untouched.
    #[test]
    fn merge_seeds_full_replaces_delta_upserts_and_drops() {
        let (dir, honest) = pinned_state_dir("merge");

        let a = [9u8; 32]; // matches the pubkey seed_signed_by mints
        let b = [8u8; 32];
        let prev = vec![sp(a, 100, 9999), sp(b, 200, 9999)];

        // Full response (partial = false) replaces outright — prev and `removed` are ignored.
        let full = resp_with_seeds(GUILD, &honest, vec![seed_signed_by(&honest, GUILD)]);
        let merged = merge_seeds(&prev, &full, &dir).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].pubkey, a);

        // Delta: A changed (resent), B removed, nothing else present → {A'} only.
        let mut delta = resp_with_seeds(GUILD, &honest, vec![seed_signed_by(&honest, GUILD)]);
        delta.partial = true;
        delta.removed = vec![b];
        let merged = merge_seeds(&prev, &delta, &dir).unwrap();
        let pks: std::collections::HashSet<_> = merged.iter().map(|p| p.pubkey).collect();
        assert_eq!(merged.len(), 1);
        assert!(pks.contains(&a) && !pks.contains(&b));

        // Delta that mentions nothing keeps the whole held set (unchanged peers survive).
        let mut noop = resp_with_seeds(GUILD, &honest, vec![]);
        noop.partial = true;
        let merged = merge_seeds(&prev, &noop, &dir).unwrap();
        assert_eq!(merged.len(), 2, "an empty delta must not drop held peers");
    }

    /// Option A: normally echo held `(pubkey, rev)`, but return empty (force a full attestation
    /// refresh) once the soonest-expiring peer is within the margin.
    #[test]
    fn held_for_refresh_echoes_then_forces_full_near_expiry() {
        let now = 1_000;
        let held = held_for_refresh(&[sp([1; 32], 42, now + 10_000)], now, 900);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].rev, 42);
        // Within the margin of expiry → empty → full refresh.
        assert!(held_for_refresh(&[sp([1; 32], 42, now + 100)], now, 900).is_empty());
        // No peers → nothing to diff → empty (a full is fine).
        assert!(held_for_refresh(&[], now, 900).is_empty());
    }

    /// A raw `GuildAttestation` for `pubkey` signed by `key` for `guild`, expiring at `expires_at`.
    fn signed_att(
        key: &CoordinatorKey,
        guild: u64,
        pubkey: [u8; 32],
        expires_at: u64,
    ) -> GuildAttestation {
        let att = test_attestation(
            guild,
            Ipv4Addr::new(100, 64, 0, 9),
            "100.64.0.0/10",
            pubkey,
            expires_at,
        );
        signed_ga(key, &att, ATTESTATION_SCHEMA_EMIT)
    }

    /// Peer-direct pull verification: adopt only a pinned-anchor-valid attestation for the *expected*
    /// pubkey that is strictly fresher than what we hold. Reject wrong pubkey, non-fresher, unpinned.
    #[test]
    fn verify_pulled_adopts_only_fresher_valid_for_expected_pubkey() {
        let (dir, honest) = pinned_state_dir("pulled");
        let attacker = CoordinatorKey::generate();
        let pk = [7u8; 32];
        let now = 1_000;
        let fresh = signed_att(&honest, GUILD, pk, now + 1800);

        // Valid, right pubkey, fresher than what we hold (0) → adopted.
        let att =
            verify_pulled(std::slice::from_ref(&fresh), pk, 0, &dir, now).expect("should adopt");
        assert_eq!(att.wg_pubkey, pk);
        assert_eq!(att.expires_at, now + 1800);

        // Not strictly fresher than what we already hold → nothing to adopt.
        assert!(verify_pulled(std::slice::from_ref(&fresh), pk, now + 1800, &dir, now).is_none());
        // A peer serving a valid attestation for a *different* device → rejected (pubkey binding).
        assert!(verify_pulled(std::slice::from_ref(&fresh), [8u8; 32], 0, &dir, now).is_none());
        // Signed by a non-pinned (attacker) key → rejected.
        assert!(verify_pulled(
            &[signed_att(&attacker, GUILD, pk, now + 1800)],
            pk,
            0,
            &dir,
            now
        )
        .is_none());
    }

    /// `apply_pulled` advances expiry + identity from the verified attestation but leaves the
    /// coordinator-brokered transport fields (endpoint here) untouched.
    #[test]
    fn apply_pulled_advances_expiry_keeps_transport() {
        let mut seed = sp([7; 32], 42, 100);
        seed.endpoint = Some("203.0.113.9:51820".parse().unwrap());
        let att = test_attestation(
            GUILD,
            Ipv4Addr::new(100, 64, 0, 9),
            "100.64.0.0/10",
            [7u8; 32],
            9_999,
        );
        apply_pulled(&mut seed, &att);
        assert_eq!(seed.expires_at, 9_999);
        assert_eq!(seed.username, att.username);
        assert_eq!(seed.ip, Ipv4Addr::new(100, 64, 0, 9));
        assert_eq!(
            seed.rev, 42,
            "rev is coordinator-owned, not touched by a pull"
        );
        assert_eq!(
            seed.endpoint,
            Some("203.0.113.9:51820".parse().unwrap()),
            "transport fields stay — a peer serves only its own identity"
        );
    }
}
