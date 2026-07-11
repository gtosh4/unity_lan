//! A tiny authoritative resolver for the `.internal` zone (design.md §6.4). Answers A queries
//! from an in-memory name→IP map built from our verified attestations (self + seeds), so peers
//! are reachable by `<device>.<user>.<community>.internal` and primaries by `<user>.<community>`.
//!
//! Per-OS resolver hookup (systemd-resolved / NRPT / macOS resolver dir) is separate polish;
//! this just serves correct answers on a UDP socket.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::coord::{SeedPeer, SelfDevice};

/// Name (lower-case, no trailing dot) → IPv4. Swapped in on each refresh.
pub type Zone = Arc<RwLock<HashMap<String, Ipv4Addr>>>;

pub fn empty_zone() -> Zone {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Rebuild the zone from our own device plus the current set of seed peers.
pub async fn update(zone: &Zone, me: &SelfDevice, seeds: &[SeedPeer]) {
    let mut map = HashMap::new();
    map.insert(norm(&me.hostname), me.wg_ip);
    if let Some(alias) = &me.primary_alias {
        map.insert(norm(alias), me.wg_ip);
    }
    for s in seeds {
        map.insert(norm(&s.hostname), s.ip);
        if let Some(alias) = &s.primary_alias {
            map.insert(norm(alias), s.ip);
        }
    }
    tracing::debug!(names = map.len(), "dns zone updated");
    *zone.write().await = map;
}

fn norm(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Serve the zone on `bind` (UDP) until the task is dropped.
pub async fn serve(bind: SocketAddr, zone: Zone) -> anyhow::Result<()> {
    let sock = UdpSocket::bind(bind).await?;
    tracing::info!(%bind, "dns resolver listening");
    let mut buf = [0u8; 512];
    loop {
        let (len, from) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("dns recv: {e}");
                continue;
            }
        };
        if let Some(reply) = answer(&buf[..len], &zone).await {
            let _ = sock.send_to(&reply, from).await;
        }
    }
}

async fn answer(bytes: &[u8], zone: &Zone) -> Option<Vec<u8>> {
    let req = Message::from_vec(bytes).ok()?;
    let mut resp = Message::response(req.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.authoritative = true;

    let map = zone.read().await;
    let mut answered = false;
    let mut ours_but_missing = false;
    for q in &req.queries {
        resp.add_query(q.clone());
        if q.query_type() != RecordType::A {
            continue;
        }
        let name = norm(&q.name().to_ascii());
        if let Some(ip) = map.get(&name) {
            resp.add_answer(Record::from_rdata(q.name().clone(), 30, RData::A(A(*ip))));
            answered = true;
        } else if name.ends_with(".internal") {
            ours_but_missing = true;
        }
    }
    if !answered && ours_but_missing {
        resp.metadata.response_code = ResponseCode::NXDomain;
    }
    resp.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;

    fn query_bytes(name: &str) -> Vec<u8> {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        m.to_vec().unwrap()
    }

    #[tokio::test]
    async fn resolves_known_name_and_nxdomains_unknown() {
        let zone = empty_zone();
        {
            let mut w = zone.write().await;
            w.insert("host-b.nodeb.lan.internal".into(), Ipv4Addr::new(100, 69, 1, 2));
        }

        // Known name → A record with the mapped IP.
        let reply = answer(&query_bytes("host-b.nodeb.lan.internal."), &zone)
            .await
            .unwrap();
        let msg = Message::from_vec(&reply).unwrap();
        assert_eq!(msg.answers.len(), 1, "expected one answer");
        match &msg.answers[0].data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(100, 69, 1, 2)),
            other => panic!("expected A, got {other:?}"),
        }

        // Unknown .internal name → NXDomain, no answers.
        let reply = answer(&query_bytes("nope.nodeb.lan.internal."), &zone)
            .await
            .unwrap();
        let msg = Message::from_vec(&reply).unwrap();
        assert!(msg.answers.is_empty());
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn serves_over_udp_socket() {
        let zone = empty_zone();
        zone.write()
            .await
            .insert("host-b.nodeb.lan.internal".into(), Ipv4Addr::new(100, 69, 1, 2));

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            let reply = answer(&buf[..len], &zone).await.unwrap();
            server.send_to(&reply, from).await.unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query_bytes("host-b.nodeb.lan.internal."), addr).await.unwrap();
        let mut buf = [0u8; 512];
        let len = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response from resolver socket")
            .unwrap();
        let msg = Message::from_vec(&buf[..len]).unwrap();
        assert_eq!(msg.answers.len(), 1);
    }
}
