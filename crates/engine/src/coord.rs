//! Coordinator client: register/refresh, verify grants + seeds against the pinned anchor.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{bail, Context};
use common::api::{RegisterReq, RegisterResp};
use common::attestation::verify_attestation;
use common::crypto::{anchor_from_bytes, WgPublicKey};
use common::now_unix;
use common::wire::Signed;

/// A verified membership of our own (one of our `/32`s + its hostname).
pub struct Membership {
    pub guild_name: String,
    pub network_name: String,
    pub role_id: u64,
    pub wg_ip: Ipv4Addr,
    pub hostname: String,
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
    endpoint: Option<SocketAddr>,
    dev_user: Option<u64>,
) -> anyhow::Result<(RegisterResp, Vec<Membership>)> {
    post(base_url, "register", wg_pubkey, endpoint, dev_user).await
}

pub async fn refresh(
    base_url: &str,
    wg_pubkey: WgPublicKey,
    endpoint: Option<SocketAddr>,
    dev_user: Option<u64>,
) -> anyhow::Result<(RegisterResp, Vec<Membership>)> {
    post(base_url, "refresh", wg_pubkey, endpoint, dev_user).await
}

async fn post(
    base_url: &str,
    path: &str,
    wg_pubkey: WgPublicKey,
    endpoint: Option<SocketAddr>,
    dev_user: Option<u64>,
) -> anyhow::Result<(RegisterResp, Vec<Membership>)> {
    let client = reqwest::Client::new();
    let mut url = format!("{base_url}/{path}");
    if let Some(u) = dev_user {
        url.push_str(&format!("?dev_user={u}"));
    }

    let resp = client
        .post(&url)
        .json(&RegisterReq { wg_pubkey, endpoint })
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

    let mut memberships = Vec::new();
    for grant in &resp.grants {
        let signed = Signed::from_base64(&grant.attestation).context("decoding grant")?;
        let att = verify_attestation(&signed, &anchor, now).context("verifying grant")?;
        let hostname = att.hostname(&grant.network_name, &grant.guild_name);
        memberships.push(Membership {
            guild_name: grant.guild_name.clone(),
            network_name: grant.network_name.clone(),
            role_id: att.role_id,
            wg_ip: att.wg_ip,
            hostname,
        });
    }
    Ok((resp, memberships))
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
