//! Coordinator client: register/refresh, verify our grant + seeds against the pinned anchor.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{bail, Context};
use common::api::{RegisterReq, RegisterResp};
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
}

/// A verified co-member to peer with.
pub struct SeedPeer {
    pub pubkey: [u8; 32],
    pub ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
}

pub async fn register(
    base_url: &str,
    wg_pubkey: WgPublicKey,
    device_name: String,
    endpoint: Option<SocketAddr>,
    enrollment_key: Option<String>,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    post(base_url, "register", wg_pubkey, device_name, endpoint, enrollment_key).await
}

pub async fn refresh(
    base_url: &str,
    wg_pubkey: WgPublicKey,
    device_name: String,
    endpoint: Option<SocketAddr>,
    enrollment_key: Option<String>,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    post(base_url, "refresh", wg_pubkey, device_name, endpoint, enrollment_key).await
}

async fn post(
    base_url: &str,
    path: &str,
    wg_pubkey: WgPublicKey,
    device_name: String,
    endpoint: Option<SocketAddr>,
    enrollment_key: Option<String>,
) -> anyhow::Result<(RegisterResp, Option<SelfDevice>)> {
    let client = reqwest::Client::new();
    let url = format!("{base_url}/{path}");

    let resp = client
        .post(&url)
        .json(&RegisterReq {
            wg_pubkey,
            device_name,
            enrollment_key,
            endpoint,
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
            Some(SelfDevice {
                community_name: grant.community_name.clone(),
                networks: grant.networks.clone(),
                wg_ip: att.wg_ip,
                hostname,
                is_primary: att.is_primary,
            })
        }
        None => None,
    };
    Ok((resp, device))
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
        });
    }
    Ok(peers)
}
