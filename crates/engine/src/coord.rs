//! Coordinator client: register/refresh, verify our grant + seeds against the pinned anchor.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{bail, Context};
use common::api::{NetworkRef, RegisterReq, RegisterResp};
use common::attestation::verify_attestation;
use common::crypto::{anchor_from_bytes, WgPublicKey};
use common::now_unix;
use common::wire::Signed;

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
    pub hostname: String,
    pub is_primary: bool,
    /// `<user>.<community>.unity.internal` if we're the owner's primary device.
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
    /// `<device>.<user>.<community>.unity.internal`.
    pub hostname: String,
    /// `<user>.<community>.unity.internal` if this is the owner's primary device, else `None`.
    pub primary_alias: Option<String>,
    /// Networks (display names) shared with us — used to scope `expose --net`.
    pub networks: Vec<String>,
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
    wg_pubkey: WgPublicKey,
    device_name: String,
    endpoint: Option<SocketAddr>,
    enrollment_key: Option<String>,
    disabled_networks: Vec<NetworkRef>,
    supersede: Option<String>,
    paused: bool,
    relay: RelayReport,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    // First contact: `since = None` returns immediately (no long-poll hold). No peers yet → no
    // observed endpoints to report. `supersede` carries our stored device token so the coordinator
    // retires a prior pubkey we just re-keyed away from (no-op unless the token names a different key).
    post(
        base_url,
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
    wg_pubkey: WgPublicKey,
    device_name: String,
    endpoint: Option<SocketAddr>,
    enrollment_key: Option<String>,
    since: Option<u64>,
    disabled_networks: Vec<NetworkRef>,
    observed: Vec<common::api::ObservedEndpoint>,
    paused: bool,
    relay: RelayReport,
    ice: Vec<common::api::IceEndpoint>,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    post(
        base_url,
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
        relay,
        ice,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn post(
    base_url: &str,
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
            relay_capable: relay.capable,
            relay_addr: relay.addr,
            relay_secret: relay.secret,
            need_relay: relay.need_relay,
            relay_allocated: relay.allocated,
            ice,
        })
        .send()
        .await
        .with_context(|| format!("sending /{path}"))?;
    let resp = ensure_ok(resp, path).await?;
    let resp: RegisterResp = resp.json().await.context("decoding RegisterResp")?;

    let anchor =
        anchor_from_bytes(&resp.coord_pubkey).map_err(|e| anyhow::anyhow!("bad anchor: {e}"))?;
    let now = now_unix();

    let device = match &resp.grant {
        Some(grant) => {
            let signed = Signed::from_base64(&grant.attestation).context("decoding grant")?;
            let att = verify_attestation(&signed, &anchor, now).context("verifying grant")?;
            let hostname = att.hostname(&grant.community_name);
            let primary_alias = att.primary_alias(&grant.community_name);
            Some(SelfDevice {
                community_name: grant.community_name.clone(),
                username: att.username.clone(),
                networks: grant.networks.clone(),
                wg_ip: att.wg_ip,
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

/// Verify the seeds in a response against its anchor → the co-members to peer with.
pub fn verified_seeds(resp: &RegisterResp) -> anyhow::Result<Vec<SeedPeer>> {
    let anchor =
        anchor_from_bytes(&resp.coord_pubkey).map_err(|e| anyhow::anyhow!("bad anchor: {e}"))?;
    let now = now_unix();
    let mut peers = Vec::new();
    for seed in &resp.seeds {
        let signed = Signed::from_base64(&seed.attestation).context("decoding seed")?;
        let att = verify_attestation(&signed, &anchor, now).context("verifying seed")?;
        peers.push(SeedPeer {
            pubkey: att.wg_pubkey,
            user_id: att.user_id,
            username: att.username.clone(),
            ip: att.wg_ip,
            endpoint: seed.endpoint,
            punch: seed.punch,
            hostname: att.hostname(&seed.community_name),
            primary_alias: att.primary_alias(&seed.community_name),
            networks: seed.networks.clone(),
            relay: seed.relay.clone(),
            ice: seed.ice.clone(),
        });
    }
    Ok(peers)
}
