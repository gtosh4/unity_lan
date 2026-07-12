//! UPnP-IGD port mapping (design.md §7.2, "reachable members"). Best-effort: on success we map
//! our WireGuard UDP port through the home router and learn our external `ip:port`, which we then
//! publish as the endpoint peers dial. Any failure (no IGD gateway, router refuses) is non-fatal —
//! we advertise no endpoint and rely on being dialed by a reachable peer (or, later, hole-punched).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use anyhow::{Context, Result};
use igd_next::aio::tokio as igd;
use igd_next::{PortMappingProtocol, SearchOptions};

const DESC: &str = "UnityLAN";
/// Lease we request from the router, renewed at half-life. Finite so a crash/kill self-cleans at
/// the router instead of leaving a stale mapping forever.
const LEASE_SECS: u32 = 3600;

/// Map `port` (UDP) through the local IGD gateway and return the external `ip:port` peers can dial.
/// Spawns a background task that renews the lease at half-life for as long as the daemon runs.
/// Best-effort: any failure returns `Err` and the caller falls back to advertising no endpoint.
pub async fn map_port(port: u16) -> Result<SocketAddr> {
    let gateway = igd::search_gateway(SearchOptions {
        // Bound the SSDP wait so a gateway-less network fails fast rather than hanging startup.
        timeout: Some(Duration::from_secs(3)),
        ..Default::default()
    })
    .await
    .context("no UPnP-IGD gateway found")?;

    // The mapping must point at our LAN address (the private IP the router forwards to), not
    // 0.0.0.0. Discover the local IPv4 the default route uses (no packets are sent on a UDP
    // connect — it just selects the route/source address).
    let local_ip = default_route_ipv4().context("finding LAN IPv4")?;
    let local = SocketAddr::new(IpAddr::V4(local_ip), port);

    gateway
        .add_port(PortMappingProtocol::UDP, port, local, LEASE_SECS, DESC)
        .await
        .context("router refused UPnP port mapping")?;

    let external_ip = gateway
        .get_external_ip()
        .await
        .context("reading external IP")?;
    let endpoint = SocketAddr::new(external_ip, port);

    // Renew at half-life so the mapping never lapses while the daemon is up.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs((LEASE_SECS / 2) as u64));
        tick.tick().await; // the first tick fires immediately; skip it (we just mapped)
        loop {
            tick.tick().await;
            if let Err(e) = gateway
                .add_port(PortMappingProtocol::UDP, port, local, LEASE_SECS, DESC)
                .await
            {
                tracing::warn!("UPnP lease renewal failed: {e:#}");
            }
        }
    });

    Ok(endpoint)
}

/// The LAN IPv4 the default route uses — the address a UPnP mapping must forward to. Uses the
/// connect-then-read-local-addr trick: a connected UDP socket picks the route's source address
/// without sending anything.
fn default_route_ipv4() -> Result<Ipv4Addr> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("bind probe socket")?;
    // 192.0.2.1 (TEST-NET-1, RFC 5737) is never routed anywhere real; we only need it to make the
    // OS pick our outbound interface's source address.
    sock.connect((Ipv4Addr::new(192, 0, 2, 1), 9))
        .context("select route")?;
    match sock.local_addr().context("reading probe local_addr")?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Ok(v4),
        other => anyhow::bail!("no usable LAN IPv4 (got {other})"),
    }
}
