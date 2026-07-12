//! Coordinator client: register/refresh, verify our grant + seeds against the pinned anchor.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{bail, Context};
use common::api::{NetworkRef, RegisterReq, RegisterResp};
use common::attestation::verify_attestation;
use common::crypto::{anchor_from_bytes, WgPublicKey};
use common::now_unix;
use common::wire::Signed;

/// Our own verified device: its `/32`, hostname, and the networks it belongs to.
pub struct SelfDevice {
    pub community_name: String,
    pub networks: Vec<String>,
    pub wg_ip: Ipv4Addr,
    pub hostname: String,
    pub is_primary: bool,
    /// `<user>.<community>.internal` if we're the owner's primary device.
    pub primary_alias: Option<String>,
    /// Every network our roles grant (role@guild) with per-device enabled state — for the toggle.
    pub networks_status: Vec<common::api::NetworkStatus>,
}

/// A verified co-member to peer with.
#[derive(Clone)]
pub struct SeedPeer {
    pub pubkey: [u8; 32],
    pub ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
    /// `<device>.<user>.<community>.internal`.
    pub hostname: String,
    /// `<user>.<community>.internal` if this is the owner's primary device, else `None`.
    pub primary_alias: Option<String>,
    /// Networks (display names) shared with us — used to scope `expose --net`.
    pub networks: Vec<String>,
}

pub async fn register(
    base_url: &str,
    wg_pubkey: WgPublicKey,
    device_name: String,
    endpoint: Option<SocketAddr>,
    enrollment_key: Option<String>,
    disabled_networks: Vec<NetworkRef>,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    // First contact: `since = None` returns immediately (no long-poll hold).
    post(base_url, "register", wg_pubkey, device_name, endpoint, enrollment_key, None, disabled_networks).await
}

/// Long-poll `/refresh`: pass the last-seen `version` as `since`; the coordinator holds the
/// request until membership changes or ~TTL/2 elapses (renewal). Returns the new version.
pub async fn refresh(
    base_url: &str,
    wg_pubkey: WgPublicKey,
    device_name: String,
    endpoint: Option<SocketAddr>,
    enrollment_key: Option<String>,
    since: Option<u64>,
    disabled_networks: Vec<NetworkRef>,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    post(base_url, "refresh", wg_pubkey, device_name, endpoint, enrollment_key, since, disabled_networks).await
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
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    // Timeout must exceed the coordinator's long-poll hold, else we'd cancel a legit held request.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(common::LONGPOLL_HOLD_SECS + 60))
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
        })
        .send()
        .await
        .with_context(|| format!("sending /{path}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("coordinator rejected {path}: {status}: {body}");
    }
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
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("coordinator rejected manage: {status}: {body}");
    }
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
            ip: att.wg_ip,
            endpoint: seed.endpoint,
            hostname: att.hostname(&seed.community_name),
            primary_alias: att.primary_alias(&seed.community_name),
            networks: seed.networks.clone(),
        });
    }
    Ok(peers)
}
