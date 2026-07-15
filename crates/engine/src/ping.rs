//! Per-peer latency probe. WireGuard exposes tx/rx and last-handshake but no round-trip time, so we
//! measure it ourselves with an ICMP echo to each peer's WG IP — the peer's OS answers automatically
//! (the mesh firewall allows ICMP echo by default), so no listener or wire protocol is needed. The
//! probe rides the daemon's existing status-refresh loop.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::Context;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};

/// Timeout for a single echo — a peer that doesn't answer within this reads as "no latency".
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// A shared ICMP client. Opening the raw socket needs privilege (the engine has it); if that fails
/// the daemon runs without latency numbers rather than aborting.
pub fn client() -> anyhow::Result<Client> {
    Client::new(&Config::default()).context("opening ICMP socket for latency probe")
}

/// Ping every IP once, concurrently, and return round-trip times in ms. IPs that don't answer within
/// [`PROBE_TIMEOUT`] are simply absent from the map (caller reads that as `latency_ms: None`).
pub async fn probe(client: &Client, ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, u32> {
    let probes = ips.iter().enumerate().map(|(i, &ip)| async move {
        // A distinct identifier per concurrent pinger so the client can demux the replies.
        let mut pinger = client
            .pinger(IpAddr::V4(ip), PingIdentifier(i as u16))
            .await;
        pinger.timeout(PROBE_TIMEOUT);
        match pinger.ping(PingSequence(0), &[0u8; 16]).await {
            Ok((_, rtt)) => Some((ip, rtt.as_millis() as u32)),
            Err(_) => None,
        }
    });
    futures::future::join_all(probes)
        .await
        .into_iter()
        .flatten()
        .collect()
}
