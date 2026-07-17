//! Coordinator client: register/refresh, verify our grant + seeds against the pinned anchor.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{bail, Context};
use common::api::{Grant, NetworkRef, RegisterReq, RegisterResp};
use common::attestation::{verify_attestation, Attestation};
use common::crypto::{anchor_from_bytes, WgPublicKey};
use common::now_unix;
use common::wire::Signed;

use crate::keys;

/// Return the response if it's a success status, else read the body and bail with the
/// coordinator's error. `what` names the route for the error message.
async fn ensure_ok(resp: reqwest::Response, what: &str) -> anyhow::Result<reqwest::Response> {
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("coordinator rejected {what}: {status}: {body}");
    }
    Ok(resp)
}

/// Our own verified device: its `/32`, hostname, and the networks it belongs to.
pub struct SelfDevice {
    pub community_name: String,
    /// The owner's Discord handle this device is enrolled as (the `<user>` label).
    pub username: String,
    pub networks: Vec<String>,
    pub wg_ip: Ipv4Addr,
    /// The deployment's mesh CIDR (from our signed attestation) — checked against local interfaces
    /// for overlap, and the range future multi-coordinator support would route.
    pub wg_net: ipnet::Ipv4Net,
    pub hostname: String,
    pub is_primary: bool,
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
}

#[allow(clippy::too_many_arguments)]
pub async fn register(
    base_url: &str,
    state_dir: &Path,
    wg_pubkey: WgPublicKey,
    device_name: String,
    endpoint: Option<SocketAddr>,
    enrollment_key: Option<String>,
    disabled_networks: Vec<NetworkRef>,
    supersede: Option<String>,
    paused: bool,
    peer_own_devices: bool,
    relay: RelayReport,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    // First contact: `since = None` returns immediately (no long-poll hold). No peers yet → no
    // observed endpoints to report. `supersede` carries our stored device token so the coordinator
    // retires a prior pubkey we just re-keyed away from (no-op unless the token names a different key).
    post(
        base_url,
        state_dir,
        "register",
        wg_pubkey,
        device_name,
        endpoint,
        enrollment_key,
        None,
        disabled_networks,
        Vec::new(),
        supersede,
        paused,
        peer_own_devices,
        relay,
        Vec::new(), // no ICE offers at initial register (no peers yet)
    )
    .await
}

/// Long-poll `/refresh`: pass the last-seen `version` as `since`; the coordinator holds the
/// request until membership changes or ~TTL/2 elapses (renewal). Returns the new version.
#[allow(clippy::too_many_arguments)]
pub async fn refresh(
    base_url: &str,
    state_dir: &Path,
    wg_pubkey: WgPublicKey,
    device_name: String,
    endpoint: Option<SocketAddr>,
    enrollment_key: Option<String>,
    since: Option<u64>,
    disabled_networks: Vec<NetworkRef>,
    observed: Vec<common::api::ObservedEndpoint>,
    paused: bool,
    peer_own_devices: bool,
    relay: RelayReport,
    ice: Vec<common::api::IceEndpoint>,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    post(
        base_url,
        state_dir,
        "refresh",
        wg_pubkey,
        device_name,
        endpoint,
        enrollment_key,
        since,
        disabled_networks,
        observed,
        None, // refresh never supersedes: a re-key retires the old key on the initial register
        paused,
        peer_own_devices,
        relay,
        ice,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn post(
    base_url: &str,
    state_dir: &Path,
    path: &str,
    wg_pubkey: WgPublicKey,
    device_name: String,
    endpoint: Option<SocketAddr>,
    enrollment_key: Option<String>,
    since: Option<u64>,
    disabled_networks: Vec<NetworkRef>,
    observed: Vec<common::api::ObservedEndpoint>,
    supersede: Option<String>,
    paused: bool,
    peer_own_devices: bool,
    relay: RelayReport,
    ice: Vec<common::api::IceEndpoint>,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    // Timeout must exceed the coordinator's long-poll hold, else we'd cancel a legit held request.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            common::LONGPOLL_HOLD_SECS + 60,
        ))
        .build()
        .context("building http client")?;
    let url = format!("{base_url}/{path}");

    let resp = client
        .post(&url)
        .json(&RegisterReq {
            wg_pubkey,
            device_name,
            enrollment_key,
            endpoint,
            since,
            disabled_networks,
            observed,
            supersede,
            paused,
            peer_own_devices,
            relay_capable: relay.capable,
            relay_addr: relay.addr,
            relay_secret: relay.secret,
            need_relay: relay.need_relay,
            relay_allocated: relay.allocated,
            ice,
            proto: common::PROTOCOL_VERSION,
            client_version: common::VERSION.to_string(),
        })
        .send()
        .await
        .with_context(|| format!("sending /{path}"))?;
    let resp = ensure_ok(resp, path).await?;
    let resp: RegisterResp = resp.json().await.context("decoding RegisterResp")?;

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
                username: att.username.clone(),
                networks: grant.networks.clone(),
                wg_ip: att.wg_ip,
                wg_net: att.wg_net,
                hostname,
                is_primary: att.is_primary,
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
fn verify_against_pinned(
    signed: &Signed,
    pinned: &[(u64, [u8; 32])],
    now: u64,
) -> Option<Attestation> {
    for (guild_id, pk) in pinned {
        let Ok(anchor) = anchor_from_bytes(pk) else {
            continue;
        };
        if let Ok(att) = verify_attestation(signed, &anchor, now, *guild_id) {
            return Some(att);
        }
    }
    None
}

/// Verify our grant: return the first per-guild attestation that verifies against its pinned anchor,
/// with its community name (the representative hostname for this device). Fails closed if none do.
fn verify_grant(
    grant: &Grant,
    pinned: &[(u64, [u8; 32])],
    now: u64,
) -> anyhow::Result<(Attestation, String)> {
    for ga in &grant.attestations {
        let signed = Signed::from_base64(&ga.attestation).context("decoding grant attestation")?;
        if let Some(att) = verify_against_pinned(&signed, pinned, now) {
            return Ok((att, ga.community_name.clone()));
        }
    }
    bail!("no grant attestation verified against a pinned guild anchor")
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
/// verifies against the matching pinned anchor; a seed none of whose attestations verify fails the
/// whole batch (fail closed — a substituted/self-signed seed must be rejected, not silently peered).
pub fn verified_seeds(resp: &RegisterResp, state_dir: &Path) -> anyhow::Result<Vec<SeedPeer>> {
    let pinned = pinned_anchors(resp, state_dir);
    let now = now_unix();
    let mut peers = Vec::new();
    for seed in &resp.seeds {
        // Any one of the peer's shared-guild attestations verifying admits it; the hostname no longer
        // depends on which guild (community left the name — see `Attestation::hostname`), so we just
        // need the first that clears a pinned anchor.
        let mut verified: Option<Attestation> = None;
        for ga in &seed.attestations {
            let signed =
                Signed::from_base64(&ga.attestation).context("decoding seed attestation")?;
            if let Some(att) = verify_against_pinned(&signed, &pinned, now) {
                verified = Some(att);
                break;
            }
        }
        let att = verified.context("seed has no attestation signed by a pinned guild anchor")?;
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
        });
    }
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::api::{GuildAnchor, GuildAttestation, RegisterResp, Seed};
    use common::crypto::CoordinatorKey;

    const GUILD: u64 = 42;

    fn temp_state_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("unitylan-coord-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A seed with one attestation for `guild_id`, signed by `key` (attacker or honest coordinator).
    fn seed_signed_by(key: &CoordinatorKey, guild_id: u64) -> Seed {
        let now = now_unix();
        let att = Attestation {
            guild_id,
            user_id: 7,
            username: "eve".into(),
            device_name: "box".into(),
            is_primary: false,
            wg_ip: Ipv4Addr::new(100, 64, 0, 9),
            wg_net: "100.64.0.0/10".parse().unwrap(),
            wg_pubkey: [9u8; 32],
            issued_at: now,
            expires_at: now + common::ATTESTATION_TTL_SECS,
        };
        Seed {
            attestations: vec![GuildAttestation {
                attestation: Signed::sign(key, &att).unwrap().to_base64(),
                community_name: "c".into(),
            }],
            endpoint: None,
            punch: None,
            networks: Vec::new(),
            relay: None,
            ice: None,
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
            grant: None,
            device_token: None,
            seeds,
            version: 1,
            networks: Vec::new(),
            stun_addr: None,
            proto: common::PROTOCOL_VERSION,
            server_version: common::VERSION.to_string(),
            release: None,
        }
    }

    /// Regression for the steady-state MITM: after we pin the honest anchor for a guild, a later
    /// response that self-signs its seeds with an attacker key must be rejected — seeds are verified
    /// against the PINNED anchor, not the anchor the response carries.
    #[test]
    fn seeds_verified_against_pinned_not_response_anchor() {
        let dir = temp_state_dir("pinned");
        let honest = CoordinatorKey::generate();
        let attacker = CoordinatorKey::generate();
        keys::pin_anchor(&dir, GUILD, &honest.anchor_bytes(), &[]).unwrap();

        // Attacker-substituted response: its own anchor for GUILD + seeds self-signed by it. The
        // pin on disk (honest) is what we verify against, so the forged seed is rejected.
        let forged = resp_with_seeds(GUILD, &attacker, vec![seed_signed_by(&attacker, GUILD)]);
        assert!(
            verified_seeds(&forged, &dir).is_err(),
            "seeds signed by a non-pinned anchor must be rejected"
        );

        // Sanity: seeds legitimately signed by the pinned anchor still verify.
        let honest_resp = resp_with_seeds(GUILD, &attacker, vec![seed_signed_by(&honest, GUILD)]);
        assert!(verified_seeds(&honest_resp, &dir).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Tenant isolation: a seed's attestation signed by guild A's honest key but presented for a
    /// guild we pinned with a *different* key must be rejected — a compromised guild-A key cannot
    /// vouch for a peer in guild B (design.md §3.1). Here we pin GUILD with `honest`; a seed carrying
    /// a GUILD-scoped attestation signed by `other` fails because the signature doesn't match the pin.
    #[test]
    fn cross_guild_key_cannot_vouch() {
        let dir = temp_state_dir("cross-guild");
        let honest = CoordinatorKey::generate();
        let other = CoordinatorKey::generate();
        keys::pin_anchor(&dir, GUILD, &honest.anchor_bytes(), &[]).unwrap();

        let forged = resp_with_seeds(GUILD, &honest, vec![seed_signed_by(&other, GUILD)]);
        assert!(
            verified_seeds(&forged, &dir).is_err(),
            "an attestation signed by a different guild's key must be rejected"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
