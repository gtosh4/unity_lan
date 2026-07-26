//! Minimal STUN Binding responder (M5.5 ICE bootstrap fallback).
//!
//! When no relay-capable co-member is online for a stuck peer to STUN, the ICE agent falls back to
//! this coordinator-hosted responder for its server-reflexive candidate — so a lone / all-NAT'd mesh
//! with no observer peer can still obtain a reflexive and bootstrap ICE. It answers a Binding request
//! with the caller's `XOR-MAPPED-ADDRESS` (its NAT mapping as seen here) — the exact reflexive a
//! relay node's embedded `turn::server::Server` already returns (it answers Binding too), so the two
//! STUN sources are interchangeable. Stateless and unauthenticated (a public, reflexive-only lookup
//! that carries no traffic and reveals nothing beyond the caller's own source address); it stays off
//! the data path, consistent with the coordinator's control-plane-only role.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Context;

use crate::limiter::{Caps, WindowCounter};
use stun::fingerprint::FINGERPRINT;
use stun::message::{Message, Setter, BINDING_REQUEST, BINDING_SUCCESS};
use stun::xoraddr::XorMappedAddress;
use tokio::net::UdpSocket;

/// Rate-limit window and caps. The responder answers *unauthenticated, source-spoofable* packets, so
/// without a limit it is a reflector and a cheap resource-DoS on the control plane. A fixed 1s window
/// bounds work: at most `MAX_PER_IP` replies to any one (claimed) source — so a single victim can't be
/// hammered — and at most `MAX_TOTAL` replies overall, capping the reflector's total output regardless
/// of source spoofing. The per-IP table is cleared every window and hard-capped at `MAX_TRACKED_IPS`
/// so a spoofed-source flood can't grow it unbounded.
const WINDOW: Duration = Duration::from_secs(1);
const MAX_PER_IP: u32 = 20;
const MAX_TOTAL: u32 = 2_000;
const MAX_TRACKED_IPS: usize = 4_096;

/// Caps for this responder's shared [`WindowCounter`]. The single-task `serve` loop owns the counter
/// directly, so it needs no locking.
fn rate_limit_caps() -> Caps {
    Caps {
        window: WINDOW,
        max_per_ip: MAX_PER_IP,
        max_total: MAX_TOTAL,
        max_tracked_ips: MAX_TRACKED_IPS,
    }
}

/// Bind a UDP STUN responder at `bind` and serve Binding requests until the task is dropped.
pub async fn serve(bind: SocketAddr) -> anyhow::Result<()> {
    let sock = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("binding STUN socket {bind}"))?;
    tracing::info!(%bind, "STUN: responder up");
    let mut limiter = WindowCounter::new(rate_limit_caps(), Instant::now());
    let mut buf = vec![0u8; 1500]; // a Binding request is tiny; this is generous
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("STUN: recv error: {e}");
                continue;
            }
        };
        // Rate-limit before doing any work, so a flood (of possibly-spoofed sources) can't turn the
        // responder into a reflector or starve the control plane.
        if !limiter.allow(src.ip(), Instant::now()) {
            continue;
        }
        if let Some(reply) = binding_response(&buf[..n], src) {
            let _ = sock.send_to(&reply, src).await; // best-effort; the client retransmits
        }
    }
}

/// Build a Binding **success** response (the caller's reflexive as `XOR-MAPPED-ADDRESS`) for a
/// Binding request packet, or `None` if the packet isn't a well-formed STUN Binding request.
fn binding_response(packet: &[u8], src: SocketAddr) -> Option<Vec<u8>> {
    let mut req = Message::new();
    req.raw = packet.to_vec();
    req.decode().ok()?;
    if req.typ != BINDING_REQUEST {
        return None;
    }
    let attrs: Vec<Box<dyn Setter>> = vec![
        Box::new(Message {
            transaction_id: req.transaction_id, // echo the client's transaction id
            ..Default::default()
        }),
        Box::new(BINDING_SUCCESS),
        Box::new(XorMappedAddress {
            ip: src.ip(),
            port: src.port(),
        }),
        Box::new(FINGERPRINT),
    ];
    let mut resp = Message::new();
    resp.build(&attrs).ok()?;
    Some(resp.raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stun::message::Getter;

    fn binding_request() -> Message {
        let mut req = Message::new();
        req.build(&[Box::new(BINDING_REQUEST)]).unwrap();
        req
    }

    #[test]
    fn answers_binding_request_with_callers_reflexive() {
        let req = binding_request();
        let src: SocketAddr = "203.0.113.5:41000".parse().unwrap();

        let raw = binding_response(&req.raw, src).expect("binding response");
        let mut resp = Message::new();
        resp.raw = raw;
        resp.decode().unwrap();

        assert_eq!(resp.typ, BINDING_SUCCESS);
        assert_eq!(resp.transaction_id, req.transaction_id); // echoed
        let mut xor = XorMappedAddress::default();
        xor.get_from(&resp).unwrap();
        assert_eq!(xor.ip, src.ip());
        assert_eq!(xor.port, src.port());
    }

    #[test]
    fn ignores_non_binding_packets() {
        let src: SocketAddr = "198.51.100.7:9".parse().unwrap();
        assert!(binding_response(b"not a stun packet", src).is_none());
    }

    /// The STUN socket takes unauthenticated UDP from anywhere on the internet, and decoding runs
    /// before anything else can reject the packet. A panic here is a one-datagram denial of service
    /// against the whole coordinator, so feed it junk at every length that matters — around the
    /// 20-byte header boundary especially, where a decoder is most likely to trust a length field
    /// it hasn't checked. Rejecting is a pass; only panicking fails.
    #[test]
    fn decoding_never_panics_on_arbitrary_datagrams() {
        let src: SocketAddr = "198.51.100.7:9".parse().unwrap();
        for seed in 0..200u64 {
            for len in 0..64 {
                binding_response(&common::testutil::seeded_bytes(seed, len), src);
            }
        }
        // Junk carrying a real STUN header prefix, so decoding gets past the magic cookie and into
        // the attribute walk rather than bailing immediately.
        for seed in 0..200u64 {
            for len in 0..64usize {
                let mut pkt = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
                pkt.extend(common::testutil::seeded_bytes(seed, len));
                binding_response(&pkt, src);
            }
        }
    }
}
