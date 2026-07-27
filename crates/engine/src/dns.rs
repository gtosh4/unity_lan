//! A tiny authoritative resolver for the `.unity.internal` zone (design.md §6.4). Answers A queries
//! from an in-memory name→IP map built from our verified attestations (self + seeds), so peers
//! are reachable by `<device>.<user>.unity.internal` and primaries also by `<user>.unity.internal`.
//!
//! Per-OS resolver hookup (systemd-resolved / NRPT / macOS resolver dir) is separate polish;
//! this just serves correct answers on a UDP socket.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::coord::{SeedPeer, SelfDevice};

/// The names we answer for, and the suffixes we are willing to speak for at all.
#[derive(Default, PartialEq, Eq)]
pub struct ZoneData {
    /// Name (lower-case, no trailing dot) → IPv4.
    names: HashMap<String, Ipv4Addr>,
    /// The deployment's certificate domain, when it has one. Mesh names gain an alias under it, so
    /// it is a second suffix we speak for — see [`certificate_alias`].
    cert_domain: Option<String>,
}

impl ZoneData {
    pub fn insert(&mut self, name: String, ip: Ipv4Addr) -> Option<Ipv4Addr> {
        self.names.insert(name, ip)
    }

    /// Whether this name is one we are entitled to speak for at all.
    ///
    /// Checked *before* the map, so a name that somehow reached the map from outside our zones is
    /// still not answered — the map is built only from verified attestations, and this keeps that a
    /// belt-and-braces property rather than the sole guarantee.
    fn ours(&self, name: &str) -> bool {
        name.ends_with(&format!(".{}", common::DNS_SUFFIX))
            || self
                .cert_domain
                .as_ref()
                .is_some_and(|d| name.ends_with(&format!(".{d}")))
    }
}

/// Swapped in on each refresh.
pub type Zone = Arc<RwLock<ZoneData>>;

pub fn empty_zone() -> Zone {
    Arc::new(RwLock::new(ZoneData::default()))
}

/// Rebuild the zone from our own device plus the current set of seed peers.
/// Rebuild the zone from our device + peers. Returns whether the contents actually changed — a
/// no-delta refresh (the common case: the coordinator re-sends the same membership every hold) skips
/// the write and the log rather than churning an identical map every couple of seconds.
pub async fn update(zone: &Zone, me: &SelfDevice, seeds: &[SeedPeer]) -> bool {
    let mut map = HashMap::new();
    let domain = me.dns_domain.as_deref();
    let mut add = |name: &str, ip: Ipv4Addr| {
        let name = norm(name);
        if let Some(alias) = certificate_alias(&name, domain) {
            map.insert(alias, ip);
        }
        map.insert(name, ip);
    };
    add(&me.hostname, me.wg_ip);
    if let Some(alias) = &me.primary_alias {
        add(alias, me.wg_ip);
    }
    for s in seeds {
        add(&s.hostname, s.ip);
        if let Some(alias) = &s.primary_alias {
            add(alias, s.ip);
        }
    }
    let next = ZoneData {
        names: map,
        cert_domain: me.dns_domain.clone(),
    };
    if *zone.read().await == next {
        return false;
    }
    tracing::debug!(names = next.names.len(), "dns zone updated");
    *zone.write().await = next;
    true
}

fn norm(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The same mesh name under the deployment's certificate domain — `<device>.<user>.<domain>` for a
/// `<device>.<user>.unity.internal` name. `None` when the deployment issues no certificates, or the
/// name is not one of ours.
///
/// The alias is *additional*: `unity.internal` stays the canonical name and keeps working untouched.
/// It exists because a publicly-trusted certificate can never name `.internal` — that suffix is
/// reserved, so no CA will ever issue for it — while the same host under a real domain can be named
/// and reached identically inside the mesh.
fn certificate_alias(name: &str, domain: Option<&str>) -> Option<String> {
    let domain = domain?;
    let stem = name.strip_suffix(&format!(".{}", common::DNS_SUFFIX))?;
    Some(format!("{stem}.{domain}").to_ascii_lowercase())
}

/// Serve the zone on an already-bound UDP socket until the task is dropped. The caller binds so it
/// controls the address/port (the daemon binds this device's own mesh IP, known only after register).
pub async fn serve(sock: UdpSocket, zone: Zone) -> anyhow::Result<()> {
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
        // Only ever speak for our own zones: a query outside them gets no answer here (no record, no
        // authoritative NXDOMAIN) even if a name somehow collided in the map — we are not its
        // authority.
        if !map.ours(&name) {
            continue;
        }
        if let Some(ip) = map.names.get(&name) {
            resp.add_answer(Record::from_rdata(q.name().clone(), 30, RData::A(A(*ip))));
            answered = true;
        } else if name.ends_with(&format!(".{}", common::DNS_SUFFIX)) {
            // An unknown name in `.unity.internal` is our own missing record, so NXDOMAIN. We are
            // *not* the authority for the certificate domain — the coordinator serves that zone — so
            // an unknown name under it draws no denial we have no standing to make.
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

    /// The resolver answers UDP from the mesh, so every peer can reach it — and parsing happens
    /// before any check could turn a peer away. Sweep junk at every length, plus truncations of a
    /// real query (the shape a clipped datagram takes), asserting only that it returns. A panic
    /// here would let one peer stop the privileged daemon.
    #[tokio::test]
    async fn parsing_never_panics_on_arbitrary_datagrams() {
        let zone = empty_zone();
        for seed in 0..200u64 {
            for len in 0..80 {
                answer(&crate::testutil::seeded_bytes(seed, len), &zone).await;
            }
        }
        let real = query_bytes("host-b.nodeb.lan.unity.internal");
        for n in 0..=real.len() {
            answer(&real[..n], &zone).await;
        }
    }

    #[tokio::test]
    async fn resolves_known_name_and_nxdomains_unknown() {
        let zone = empty_zone();
        {
            let mut w = zone.write().await;
            w.insert(
                "host-b.nodeb.lan.unity.internal".into(),
                Ipv4Addr::new(100, 69, 1, 2),
            );
        }

        // Known name → A record with the mapped IP.
        let reply = answer(&query_bytes("host-b.nodeb.lan.unity.internal."), &zone)
            .await
            .unwrap();
        let msg = Message::from_vec(&reply).unwrap();
        assert_eq!(msg.answers.len(), 1, "expected one answer");
        match &msg.answers[0].data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(100, 69, 1, 2)),
            other => panic!("expected A, got {other:?}"),
        }

        // Unknown .unity.internal name → NXDomain, no answers.
        let reply = answer(&query_bytes("nope.nodeb.lan.unity.internal."), &zone)
            .await
            .unwrap();
        let msg = Message::from_vec(&reply).unwrap();
        assert!(msg.answers.is_empty());
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn a_certificate_alias_swaps_the_suffix_and_nothing_else() {
        // `.internal` is reserved, so no CA will ever issue for a `unity.internal` name. The alias is
        // the same host under a real domain, which *can* be certified.
        assert_eq!(
            certificate_alias("laptop.gordon.unity.internal", Some("mesh.example.com")).as_deref(),
            Some("laptop.gordon.mesh.example.com")
        );
        // The bare primary alias too.
        assert_eq!(
            certificate_alias("gordon.unity.internal", Some("mesh.example.com")).as_deref(),
            Some("gordon.mesh.example.com")
        );
        // No configured domain → no alias; the deployment issues no certificates.
        assert_eq!(
            certificate_alias("laptop.gordon.unity.internal", None),
            None
        );
        // Not one of ours → left alone.
        assert_eq!(
            certificate_alias("evil.example.com", Some("mesh.example.com")),
            None
        );
    }

    #[tokio::test]
    async fn the_certificate_alias_resolves_to_the_same_address() {
        let zone = empty_zone();
        {
            let mut z = zone.write().await;
            z.cert_domain = Some("mesh.example.com".into());
            z.insert(
                "laptop.gordon.unity.internal".into(),
                Ipv4Addr::new(100, 73, 61, 4),
            );
            z.insert(
                "laptop.gordon.mesh.example.com".into(),
                Ipv4Addr::new(100, 73, 61, 4),
            );
        }

        for name in [
            "laptop.gordon.unity.internal.",
            "laptop.gordon.mesh.example.com.",
        ] {
            let reply = answer(&query_bytes(name), &zone).await.unwrap();
            let msg = Message::from_vec(&reply).unwrap();
            assert_eq!(msg.answers.len(), 1, "{name} should resolve");
        }
    }

    #[tokio::test]
    async fn an_unknown_name_under_the_certificate_domain_draws_no_denial() {
        // The coordinator is authoritative for that zone, not us — we serve only the specific alias
        // names we hold attestations for, so we have no standing to say a name does not exist.
        let zone = empty_zone();
        zone.write().await.cert_domain = Some("mesh.example.com".into());

        let reply = answer(&query_bytes("nobody.mesh.example.com."), &zone)
            .await
            .unwrap();
        let msg = Message::from_vec(&reply).unwrap();
        assert!(msg.answers.is_empty());
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);

        // ...whereas an unknown name in our own zone is an authoritative NXDOMAIN, as before.
        let reply = answer(&query_bytes("nobody.unity.internal."), &zone)
            .await
            .unwrap();
        let msg = Message::from_vec(&reply).unwrap();
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn does_not_speak_for_names_outside_the_zone() {
        // Even a name planted in the map is not answered if it's outside our suffix: no A record and
        // no authoritative NXDOMAIN, since we aren't its authority.
        let zone = empty_zone();
        zone.write()
            .await
            .insert("evil.example.com".into(), Ipv4Addr::new(10, 0, 0, 1));

        let reply = answer(&query_bytes("evil.example.com."), &zone)
            .await
            .unwrap();
        let msg = Message::from_vec(&reply).unwrap();
        assert!(msg.answers.is_empty());
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn serves_over_udp_socket() {
        let zone = empty_zone();
        zone.write().await.insert(
            "host-b.nodeb.lan.unity.internal".into(),
            Ipv4Addr::new(100, 69, 1, 2),
        );

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            let reply = answer(&buf[..len], &zone).await.unwrap();
            server.send_to(&reply, from).await.unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&query_bytes("host-b.nodeb.lan.unity.internal."), addr)
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let len = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response from resolver socket")
            .unwrap();
        let msg = Message::from_vec(&buf[..len]).unwrap();
        assert_eq!(msg.answers.len(), 1);
    }
}
