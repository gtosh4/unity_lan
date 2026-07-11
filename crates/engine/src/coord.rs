//! Coordinator client: register, then verify + pin the returned attestations (grants).

use anyhow::{bail, Context};
use common::api::{RegisterReq, RegisterResp};
use common::attestation::verify_attestation;
use common::crypto::{anchor_from_bytes, WgPublicKey};
use common::now_unix;
use common::wire::Signed;

/// A verified membership the engine can act on.
pub struct Membership {
    pub guild_name: String,
    pub network_name: String,
    pub role_id: u64,
    pub wg_ip: std::net::Ipv4Addr,
    pub hostname: String,
}

/// `POST /register`, verify every attestation against the returned anchor, return memberships.
pub async fn register(
    base_url: &str,
    wg_pubkey: WgPublicKey,
    dev_user: Option<u64>,
) -> anyhow::Result<(RegisterResp, Vec<Membership>)> {
    let client = reqwest::Client::new();
    let mut url = format!("{base_url}/register");
    if let Some(u) = dev_user {
        url.push_str(&format!("?dev_user={u}"));
    }

    let resp = client
        .post(&url)
        .json(&RegisterReq { wg_pubkey })
        .send()
        .await
        .context("sending /register")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("coordinator rejected register: {status}: {body}");
    }
    let resp: RegisterResp = resp.json().await.context("decoding RegisterResp")?;

    let anchor =
        anchor_from_bytes(&resp.coord_pubkey).map_err(|e| anyhow::anyhow!("bad anchor: {e}"))?;
    let now = now_unix();

    let mut memberships = Vec::new();
    for grant in &resp.grants {
        let signed = Signed::from_base64(&grant.attestation).context("decoding attestation")?;
        let att = verify_attestation(&signed, &anchor, now).context("verifying attestation")?;
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
