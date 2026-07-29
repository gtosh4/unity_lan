//! Authoritative DNS for the deployment's certificate domain (the `[dns]` block).
//!
//! A mesh name resolves to a `100.64.0.0/10` address reachable only inside the mesh, so a CA can
//! never connect to it: HTTP-01 and TLS-ALPN-01 are both impossible, leaving DNS-01 as the only
//! challenge type. DNS-01 validates *control of the name*, not reachability of the host — the CA
//! looks up a `_acme-challenge` TXT record in public DNS. This module is what serves it.
//!
//! The zone carries challenge records and **nothing else**. No `A` records, so mesh addresses are
//! never published; clients keep resolving those locally through the engine's resolver hook. A device
//! posts its challenge value to `/acme-challenge`, runs ACME against the CA itself, and keeps the
//! private key — the coordinator only ever holds a short-lived TXT string, and stays off the data
//! path exactly as it does everywhere else.
//!
//! **This listener is unauthenticated and source-spoofable**, like [`crate::stun`]. It is hardened
//! accordingly: it answers only `TXT` under `_acme-challenge`, plus `SOA`/`NS` at the apex; refuses
//! `ANY` and zone transfers (the classic amplification levers); never recurses; and rate-limits by
//! source. Answers are a few hundred bytes for a query of comparable size, so the amplification
//! factor stays near 1.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{NS, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::config::DnsConfig;
use crate::limiter::{Caps, WindowCounter};

/// How long a published challenge stays live. An ACME order validates within seconds of the client
/// posting it; five minutes is generous cover for a slow CA without leaving stale records around.
const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

/// TTL on the TXT records themselves. Short, because a device may re-post a new value for the same
/// name minutes later on a retry and must not be shadowed by a cached old one.
const CHALLENGE_RECORD_TTL_SECS: u32 = 60;

/// TTL on the apex `SOA`/`NS`, and the SOA `minimum` (the negative-caching TTL). Kept modest so a
/// resolver that caches an NXDOMAIN for a name whose challenge is *about* to be posted re-asks soon.
const ZONE_TTL_SECS: u32 = 300;

/// Hard ceiling on simultaneously-live challenges. Bounds the memory an authenticated-but-hostile
/// fleet could pin. Sized far above any real deployment's in-flight issuances (each lives 5 minutes).
const MAX_LIVE_CHALLENGES: usize = 4_096;

/// Values kept at one challenge name. A retry adds a value rather than replacing (see
/// [`Live::push`]), so this is the bound on how far one name can grow; past it the oldest value —
/// the one least likely to belong to the order still being validated — is evicted.
const MAX_VALUES_PER_NAME: usize = 8;

/// The rolling window `max_certs_per_week` is measured over.
const ISSUANCE_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The slice of the deployment's weekly budget any single device may spend. Without it, one member —
/// malicious, or merely crash-looping through orders — exhausts `max_certs_per_week` and locks
/// certificate issuance out for everybody until the window rolls. The client-side gates that would
/// otherwise pace issuance (opt-in, exposed-port requirement, `cert.rs`'s backoff) all run on the
/// device, so they bound only a device that is behaving.
///
/// Sized for a device that is churning legitimately: a certificate is renewed about every 60 days,
/// and the extra orders come from adding service names, which `cert.rs` already coalesces over a
/// 10-minute settle window.
const MAX_CERTS_PER_DEVICE_PER_WEEK: u32 = 5;

/// Largest response we will put in a UDP datagram absent EDNS (RFC 1035). Past this we set TC and
/// let the resolver retry over TCP.
const MIN_UDP_PAYLOAD: usize = 512;

/// Cap on a TCP query we will read. A DNS message is length-prefixed with 16 bits, but nothing we
/// answer needs anything close to this — refusing early keeps a stalled or hostile connection cheap.
const MAX_TCP_QUERY: usize = 4_096;

/// Read deadline for one TCP query, so a peer that opens a connection and dribbles cannot pin a task.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Rate-limit window and caps, mirroring [`crate::stun`]'s reasoning: the responder answers
/// unauthenticated, spoofable packets, so without a limit it is a reflector and a cheap resource DoS
/// on the control plane. `MAX_PER_IP` bounds what one claimed source can extract, `MAX_TOTAL` bounds
/// total output regardless of spoofing, and the per-IP table is capped so a spoofed flood cannot grow
/// it without bound.
const RATE_WINDOW: Duration = Duration::from_secs(1);
const MAX_PER_IP: u32 = 20;
const MAX_TOTAL: u32 = 2_000;
const MAX_TRACKED_IPS: usize = 4_096;

fn rate_limit_caps() -> Caps {
    Caps {
        window: RATE_WINDOW,
        max_per_ip: MAX_PER_IP,
        max_total: MAX_TOTAL,
        max_tracked_ips: MAX_TRACKED_IPS,
    }
}

/// The certificate domain and its live challenge records — everything the `/acme-challenge` route
/// needs. `None` on [`crate::api::AppState`] when the deployment configured no `[dns]`, which is what
/// makes the whole certificate feature opt-in.
pub struct DnsState {
    /// The configured `[dns] domain`, already normalised (lower-case, no trailing dot).
    pub domain: String,
    pub challenges: Arc<ChallengeStore>,
}

/// Why a challenge could not be published.
#[derive(Debug, PartialEq, Eq)]
pub enum PublishError {
    /// This device has already spent its own slice of the week (see
    /// [`MAX_CERTS_PER_DEVICE_PER_WEEK`]). Distinct from [`Self::BudgetExhausted`] so the message can
    /// tell the operator which one they are looking at.
    DeviceBudgetExhausted,
    /// The deployment has already admitted `max_certs_per_week` issuances this week.
    BudgetExhausted,
    /// Too many challenges are live at once (see [`MAX_LIVE_CHALLENGES`]).
    TooManyLive,
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceBudgetExhausted => write!(
                f,
                "this device has spent its weekly certificate allowance; try again later"
            ),
            Self::BudgetExhausted => write!(
                f,
                "this deployment's weekly certificate budget is exhausted; try again later"
            ),
            Self::TooManyLive => write!(f, "too many certificate validations are in flight"),
        }
    }
}

/// The live `_acme-challenge` records, plus the deployment's weekly issuance budget.
///
/// Deliberately in memory rather than SQLite: a challenge is valid for minutes and is worthless after
/// the order validates, so persisting it would put writes on a path that exists only to be discarded,
/// and a coordinator restart mid-order costs one retry.
pub struct ChallengeStore {
    inner: Mutex<Inner>,
    max_certs_per_week: u32,
}

struct Inner {
    /// `_acme-challenge.<name>` (lower-case, no trailing dot) → the values live for it.
    live: HashMap<String, Live>,
    /// When each admitted issuance happened, pruned to [`ISSUANCE_WINDOW`]. Bounded by
    /// `max_certs_per_week`, so it stays tiny.
    issuances: Vec<Instant>,
    /// The same, per device pubkey. An entry exists only while that device has an issuance inside the
    /// window, and every issuance in here is also in `issuances` — so the map is bounded by
    /// `max_certs_per_week` too.
    per_device: HashMap<[u8; 32], Vec<Instant>>,
}

struct Live {
    values: Vec<String>,
    expires_at: Instant,
}

impl ChallengeStore {
    pub fn new(max_certs_per_week: u32) -> Self {
        Self {
            inner: Mutex::new(Inner {
                live: HashMap::new(),
                issuances: Vec::new(),
                per_device: HashMap::new(),
            }),
            max_certs_per_week,
        }
    }

    /// Publish every `(name, value)` of one certificate order for `device`, spending one unit of that
    /// device's weekly slice and one of the deployment's.
    ///
    /// Budget is charged per *order*, not per name: a certificate covering a device and its primary
    /// alias raises one authorization per name but is still one certificate against the CA's cap.
    /// Re-posting an order whose values are all still live costs nothing at all — a device retrying
    /// inside the challenge TTL is the same certificate, and charging it would let a client burn its
    /// own allowance (and the deployment's) on retries the CA never counted.
    pub fn publish(
        &self,
        device: &[u8; 32],
        records: &[(String, String)],
    ) -> Result<(), PublishError> {
        self.publish_at(device, records, Instant::now())
    }

    fn publish_at(
        &self,
        device: &[u8; 32],
        records: &[(String, String)],
        now: Instant,
    ) -> Result<(), PublishError> {
        let mut inner = self.inner.lock().expect("challenge store poisoned");
        inner.prune(now);

        // Nothing new to say: refresh the expiry so the in-flight validation keeps its records, and
        // charge nothing.
        let novel = records.iter().any(|(name, value)| {
            !inner
                .live
                .get(name)
                .is_some_and(|live| live.values.iter().any(|v| v == value))
        });
        if !novel {
            let expires_at = now + CHALLENGE_TTL;
            for (name, _) in records {
                if let Some(live) = inner.live.get_mut(name) {
                    live.expires_at = expires_at;
                }
            }
            return Ok(());
        }

        // Per device before the shared counter, so a device that is over its own allowance never
        // touches the budget everyone else draws on.
        let per_device_cap = MAX_CERTS_PER_DEVICE_PER_WEEK.min(self.max_certs_per_week) as usize;
        if inner.per_device.get(device).map_or(0, Vec::len) >= per_device_cap {
            return Err(PublishError::DeviceBudgetExhausted);
        }
        if inner.issuances.len() >= self.max_certs_per_week as usize {
            return Err(PublishError::BudgetExhausted);
        }
        // Refuse rather than evict: an eviction would silently break somebody else's in-flight
        // validation, which is worse than telling this caller to come back.
        let fresh = records
            .iter()
            .filter(|(name, _)| !inner.live.contains_key(name))
            .count();
        if inner.live.len() + fresh > MAX_LIVE_CHALLENGES {
            return Err(PublishError::TooManyLive);
        }

        let expires_at = now + CHALLENGE_TTL;
        for (name, value) in records {
            inner
                .live
                .entry(name.clone())
                .or_insert_with(|| Live {
                    values: Vec::new(),
                    expires_at,
                })
                .push(value.clone(), expires_at);
        }
        inner.issuances.push(now);
        inner.per_device.entry(*device).or_default().push(now);
        Ok(())
    }

    /// The values live for `name`, or `None`. `name` is lower-case with no trailing dot.
    fn lookup(&self, name: &str) -> Option<Vec<String>> {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("challenge store poisoned");
        inner.prune(now);
        inner.live.get(name).map(|live| live.values.clone())
    }

    /// Issuances admitted in the current window — for `/metrics` and the admin dashboard.
    pub fn issued_this_week(&self) -> usize {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("challenge store poisoned");
        inner.prune(now);
        inner.issuances.len()
    }
}

impl Inner {
    fn prune(&mut self, now: Instant) {
        self.live.retain(|_, live| live.expires_at > now);
        let in_window = |at: &Instant| now.duration_since(*at) < ISSUANCE_WINDOW;
        self.issuances.retain(in_window);
        // Dropping the emptied entries is what keeps the map bounded by the weekly budget rather than
        // by how many devices have ever ordered a certificate.
        self.per_device.retain(|_, ats| {
            ats.retain(in_window);
            !ats.is_empty()
        });
    }
}

impl Live {
    /// A retry for the same name adds a value rather than replacing: the CA accepts the challenge if
    /// *any* TXT at the name matches, so keeping both makes a re-post safe when the first attempt is
    /// still being validated.
    ///
    /// Capped at [`MAX_VALUES_PER_NAME`], oldest evicted. Every lookup clones this vector, so an
    /// unbounded one turns a name into an amplifier for the spoofable UDP listener; the value an
    /// eviction can cost is the one that has been sitting unvalidated the longest.
    fn push(&mut self, value: String, expires_at: Instant) {
        if !self.values.contains(&value) {
            if self.values.len() >= MAX_VALUES_PER_NAME {
                self.values.remove(0);
            }
            self.values.push(value);
        }
        self.expires_at = expires_at;
    }
}

/// The zone this coordinator is authoritative for.
pub struct Zone {
    origin: Name,
    /// SOA serial, stamped once at startup. Nothing does zone transfers here — the value exists
    /// because the record must have one.
    serial: u32,
    store: Arc<ChallengeStore>,
}

impl Zone {
    pub fn new(domain: &str, store: Arc<ChallengeStore>) -> anyhow::Result<Self> {
        let origin: Name = format!("{domain}.")
            .parse()
            .with_context(|| format!("parsing dns domain {domain:?} as a DNS name"))?;
        let serial = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(1);
        Ok(Self {
            origin: origin.to_lowercase(),
            serial,
            store,
        })
    }

    fn soa(&self) -> Record {
        // `mname` names the primary server for the zone. The parent's `NS` delegation is what
        // resolvers actually follow, and we serve no `A` here, so pointing at the apex keeps the
        // record well-formed without inventing a hostname the operator never configured.
        let soa = SOA::new(
            self.origin.clone(),
            Name::from_ascii(format!("hostmaster.{}", self.origin)).unwrap_or(self.origin.clone()),
            self.serial,
            ZONE_TTL_SECS as i32,
            ZONE_TTL_SECS as i32,
            ISSUANCE_WINDOW.as_secs() as i32,
            ZONE_TTL_SECS,
        );
        Record::from_rdata(self.origin.clone(), ZONE_TTL_SECS, RData::SOA(soa))
    }

    /// Build the response to one decoded query. Returns `None` when the message should be dropped
    /// without a reply.
    fn answer(&self, req: &Message) -> Option<Message> {
        // Never reply to a reply: doing so is how two servers are turned into a packet loop.
        if req.metadata.message_type != MessageType::Query {
            return None;
        }

        let mut resp = Message::response(req.metadata.id, req.metadata.op_code);
        resp.metadata.recursion_desired = req.metadata.recursion_desired;
        resp.metadata.recursion_available = false;
        resp.metadata.authoritative = true;

        if req.metadata.op_code != OpCode::Query {
            resp.metadata.response_code = ResponseCode::NotImp;
            return Some(resp);
        }
        let [query] = req.queries.as_slice() else {
            // Exactly one question or nothing to answer. Multi-question messages are undefined in
            // practice and every real resolver sends one.
            resp.metadata.response_code = ResponseCode::FormErr;
            return Some(resp);
        };
        resp.add_query(query.clone());

        let qtype = query.query_type();
        let qname = query.name().to_lowercase();

        // Outside our zone we are not authoritative, and saying REFUSED (rather than NXDOMAIN)
        // is what stops us being used as an open resolver or a lying one.
        if !self.origin.zone_of(&qname) {
            resp.metadata.authoritative = false;
            resp.metadata.response_code = ResponseCode::Refused;
            return Some(resp);
        }

        // ANY and zone transfers are the amplification levers — one small query, a large answer.
        // Nothing legitimate here needs either.
        if matches!(qtype, RecordType::ANY | RecordType::AXFR | RecordType::IXFR) {
            resp.metadata.response_code = ResponseCode::Refused;
            return Some(resp);
        }

        if qname == self.origin {
            match qtype {
                RecordType::SOA => resp.add_answer(self.soa()),
                RecordType::NS => resp.add_answer(Record::from_rdata(
                    self.origin.clone(),
                    ZONE_TTL_SECS,
                    RData::NS(NS(self.origin.clone())),
                )),
                // NODATA: the name exists, this type does not. NOERROR with the SOA in authority,
                // which is what tells a resolver how long to cache the absence.
                _ => resp.add_authority(self.soa()),
            };
            return Some(resp);
        }

        // Everything below the apex: only a live challenge answers, and only for TXT.
        let key = qname.to_string();
        let key = key.strip_suffix('.').unwrap_or(&key);
        match self.store.lookup(key) {
            Some(values) if qtype == RecordType::TXT => {
                for value in values {
                    resp.add_answer(Record::from_rdata(
                        query.name().clone(),
                        CHALLENGE_RECORD_TTL_SECS,
                        RData::TXT(TXT::new(vec![value])),
                    ));
                }
            }
            // The name exists but holds no record of this type — NODATA, not NXDOMAIN.
            Some(_) => {
                resp.add_authority(self.soa());
            }
            None => {
                resp.metadata.response_code = ResponseCode::NXDomain;
                resp.add_authority(self.soa());
            }
        }
        Some(resp)
    }

    /// Decode one wire-format query and encode its reply. `None` means send nothing.
    fn respond(&self, query: &[u8], over_tcp: bool) -> Option<Vec<u8>> {
        // A message we cannot parse gets no reply: we have no reliable id or question to echo, and
        // answering garbage from a spoofable source is free amplification.
        let req = Message::from_vec(query).ok()?;
        let resp = self.answer(&req)?;

        let bytes = resp.to_vec().ok()?;
        if over_tcp {
            return Some(bytes);
        }
        // EDNS lets the resolver advertise a larger datagram; `max_payload` already floors at 512.
        let limit = req.max_payload() as usize;
        let limit = limit.max(MIN_UDP_PAYLOAD);
        if bytes.len() <= limit {
            return Some(bytes);
        }
        // Too big for a datagram: set TC and let the resolver come back over TCP.
        resp.truncate().to_vec().ok()
    }
}

/// A bound-but-not-yet-serving responder. Split from [`Serving::run`] so a bad bind address aborts
/// startup, rather than logging into the void after boot has already reported success.
pub struct Serving {
    udp: UdpSocket,
    tcp: TcpListener,
    zone: Arc<Zone>,
}

/// Bind the authoritative responder on UDP **and** TCP.
///
/// Both transports are mandatory: a resolver that receives a truncated UDP answer retries over TCP,
/// so a UDP-only server silently fails every query whose answer does not fit a datagram.
pub async fn bind(cfg: &DnsConfig, store: Arc<ChallengeStore>) -> anyhow::Result<Serving> {
    let zone = Arc::new(Zone::new(&cfg.domain, store)?);
    let udp = UdpSocket::bind(cfg.bind)
        .await
        .with_context(|| format!("binding DNS UDP socket {}", cfg.bind))?;
    let tcp = TcpListener::bind(cfg.bind)
        .await
        .with_context(|| format!("binding DNS TCP socket {}", cfg.bind))?;
    tracing::info!(bind = %cfg.bind, domain = %cfg.domain, "DNS: authoritative responder up");
    Ok(Serving { udp, tcp, zone })
}

impl Serving {
    /// Serve both transports until one of them fails.
    pub async fn run(self) -> anyhow::Result<()> {
        let Self { udp, tcp, zone } = self;
        let udp_zone = Arc::clone(&zone);
        let udp_task = tokio::spawn(async move { serve_udp(udp, udp_zone).await });
        let tcp_task = tokio::spawn(async move { serve_tcp(tcp, zone).await });
        tokio::select! {
            r = udp_task => r?,
            r = tcp_task => r?,
        }
    }
}

async fn serve_udp(sock: UdpSocket, zone: Arc<Zone>) -> anyhow::Result<()> {
    let mut limiter = WindowCounter::new(rate_limit_caps(), Instant::now());
    let mut buf = vec![0u8; MIN_UDP_PAYLOAD * 8];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("DNS: udp recv error: {e}");
                continue;
            }
        };
        if !limiter.allow(src.ip(), Instant::now()) {
            continue;
        }
        if let Some(resp) = zone.respond(&buf[..n], false) {
            if let Err(e) = sock.send_to(&resp, src).await {
                tracing::debug!(%src, "DNS: udp send failed: {e}");
            }
        }
    }
}

async fn serve_tcp(listener: TcpListener, zone: Arc<Zone>) -> anyhow::Result<()> {
    let limiter = Arc::new(Mutex::new(WindowCounter::new(
        rate_limit_caps(),
        Instant::now(),
    )));
    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("DNS: tcp accept error: {e}");
                continue;
            }
        };
        {
            let mut limiter = limiter.lock().expect("dns limiter poisoned");
            if !limiter.allow(src.ip(), Instant::now()) {
                continue;
            }
        }
        let zone = Arc::clone(&zone);
        tokio::spawn(async move {
            if let Err(e) = serve_tcp_conn(stream, src, zone).await {
                tracing::debug!(%src, "DNS: tcp connection: {e}");
            }
        });
    }
}

async fn serve_tcp_conn(
    mut stream: tokio::net::TcpStream,
    _src: SocketAddr,
    zone: Arc<Zone>,
) -> anyhow::Result<()> {
    // One query per connection. Resolvers may pipeline, but nothing that queries this zone does, and
    // closing after the answer keeps a hostile connection's lifetime bounded.
    tokio::time::timeout(TCP_READ_TIMEOUT, async {
        let len = stream.read_u16().await? as usize;
        if len > MAX_TCP_QUERY {
            anyhow::bail!("query of {len} bytes exceeds the {MAX_TCP_QUERY}-byte limit");
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        if let Some(resp) = zone.respond(&buf, true) {
            stream.write_u16(resp.len() as u16).await?;
            stream.write_all(&resp).await?;
            stream.flush().await?;
        }
        Ok(())
    })
    .await
    .context("timed out reading a DNS query")?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> Zone {
        Zone::new("mesh.example.com", Arc::new(ChallengeStore::new(40))).unwrap()
    }

    /// A distinct device pubkey per `n`, so a test can say whose budget it is spending.
    fn dev(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn query(name: &str, qtype: RecordType) -> Message {
        let mut m = Message::query();
        m.metadata.id = 1234;
        m.add_query(hickory_proto::op::Query::query(
            name.parse().unwrap(),
            qtype,
        ));
        m
    }

    fn answer_of(zone: &Zone, name: &str, qtype: RecordType) -> Message {
        zone.answer(&query(name, qtype)).expect("a reply")
    }

    fn txt_values(msg: &Message) -> Vec<String> {
        msg.answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .collect::<Vec<_>>()
                        .join(""),
                ),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn serves_a_published_challenge_as_txt() {
        let store = Arc::new(ChallengeStore::new(40));
        let zone = Zone::new("mesh.example.com", Arc::clone(&store)).unwrap();
        store
            .publish(
                &dev(1),
                &[(
                    "_acme-challenge.laptop.gordon.mesh.example.com".into(),
                    "token-value".into(),
                )],
            )
            .unwrap();

        let resp = answer_of(
            &zone,
            "_acme-challenge.laptop.gordon.mesh.example.com.",
            RecordType::TXT,
        );
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.metadata.authoritative);
        assert_eq!(txt_values(&resp), vec!["token-value".to_string()]);
    }

    #[test]
    fn unpublished_name_is_nxdomain_with_soa() {
        let zone = zone();
        let resp = answer_of(
            &zone,
            "_acme-challenge.nobody.mesh.example.com.",
            RecordType::TXT,
        );
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        // The SOA in the authority section is what tells a resolver how long to cache the absence.
        assert_eq!(resp.authorities.len(), 1);
    }

    #[test]
    fn refuses_names_outside_the_zone() {
        // Answering these authoritatively is how a DNS server becomes a lying open resolver.
        let zone = zone();
        for name in ["example.com.", "google.com.", "mesh.example.org."] {
            let resp = answer_of(&zone, name, RecordType::A);
            assert_eq!(
                resp.metadata.response_code,
                ResponseCode::Refused,
                "{name} should be refused"
            );
            assert!(!resp.metadata.authoritative);
        }
    }

    #[test]
    fn refuses_any_and_zone_transfers() {
        // The amplification levers: a tiny query that would otherwise draw a large answer.
        let zone = zone();
        for qtype in [RecordType::ANY, RecordType::AXFR, RecordType::IXFR] {
            let resp = answer_of(&zone, "mesh.example.com.", qtype);
            assert_eq!(
                resp.metadata.response_code,
                ResponseCode::Refused,
                "{qtype} should be refused"
            );
        }
    }

    #[test]
    fn never_offers_recursion() {
        let zone = zone();
        let mut req = query("_acme-challenge.a.b.mesh.example.com.", RecordType::TXT);
        req.metadata.recursion_desired = true;
        let resp = zone.answer(&req).unwrap();
        assert!(!resp.metadata.recursion_available);
        // RD is echoed back, as the protocol requires; RA=0 is what actually declines.
        assert!(resp.metadata.recursion_desired);
    }

    #[test]
    fn serves_soa_and_ns_at_the_apex() {
        let zone = zone();
        let soa = answer_of(&zone, "mesh.example.com.", RecordType::SOA);
        assert_eq!(soa.answers.len(), 1);
        let ns = answer_of(&zone, "mesh.example.com.", RecordType::NS);
        assert_eq!(ns.answers.len(), 1);
        // An apex A query is NODATA — the name exists, the type does not — never NXDOMAIN.
        let a = answer_of(&zone, "mesh.example.com.", RecordType::A);
        assert_eq!(a.metadata.response_code, ResponseCode::NoError);
        assert!(a.answers.is_empty());
        assert_eq!(a.authorities.len(), 1);
    }

    #[test]
    fn a_published_name_answers_nodata_for_other_types() {
        let store = Arc::new(ChallengeStore::new(40));
        let zone = Zone::new("mesh.example.com", Arc::clone(&store)).unwrap();
        let name = "_acme-challenge.laptop.gordon.mesh.example.com";
        store
            .publish(&dev(1), &[(name.into(), "v".into())])
            .unwrap();
        let resp = answer_of(&zone, &format!("{name}."), RecordType::A);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
    }

    #[test]
    fn never_replies_to_a_reply() {
        // Otherwise two of these pointed at each other become a packet loop.
        let zone = zone();
        let mut req = query("mesh.example.com.", RecordType::SOA);
        req.metadata.message_type = MessageType::Response;
        assert!(zone.answer(&req).is_none());
    }

    #[test]
    fn unparseable_input_draws_no_reply() {
        let zone = zone();
        assert!(zone.respond(b"not a dns message at all", false).is_none());
        assert!(zone.respond(&[], false).is_none());
    }

    #[test]
    fn challenges_expire() {
        let store = ChallengeStore::new(40);
        let start = Instant::now();
        store
            .publish_at(
                &dev(1),
                &[("_acme-challenge.a.mesh.example.com".into(), "v".into())],
                start,
            )
            .unwrap();
        assert!(store.lookup("_acme-challenge.a.mesh.example.com").is_some());

        // Re-publishing after the TTL prunes the stale entry rather than accumulating it.
        store
            .publish_at(
                &dev(1),
                &[("_acme-challenge.b.mesh.example.com".into(), "v".into())],
                start + CHALLENGE_TTL + Duration::from_secs(1),
            )
            .unwrap();
        let inner = store.inner.lock().unwrap();
        assert!(!inner
            .live
            .contains_key("_acme-challenge.a.mesh.example.com"));
        assert!(inner
            .live
            .contains_key("_acme-challenge.b.mesh.example.com"));
    }

    #[test]
    fn weekly_budget_is_charged_per_order_not_per_name() {
        // A certificate covering a device and its primary alias raises two authorizations but is
        // still one certificate against the CA's cap.
        let store = ChallengeStore::new(2);
        let order = |n: u32| {
            vec![
                (
                    format!("_acme-challenge.d{n}.gordon.mesh.example.com"),
                    "v".into(),
                ),
                (
                    format!("_acme-challenge.gordon{n}.mesh.example.com"),
                    "v".into(),
                ),
            ]
        };
        // A device apiece, so this exercises the deployment budget rather than the per-device slice.
        store.publish(&dev(1), &order(1)).unwrap();
        store.publish(&dev(2), &order(2)).unwrap();
        assert_eq!(store.issued_this_week(), 2);
        assert_eq!(
            store.publish(&dev(3), &order(3)),
            Err(PublishError::BudgetExhausted)
        );
    }

    #[test]
    fn a_retry_adds_its_value_rather_than_replacing() {
        // The CA accepts the challenge if *any* TXT at the name matches, so keeping both makes a
        // re-post safe while the first attempt is still being validated.
        let store = ChallengeStore::new(40);
        let name = "_acme-challenge.laptop.gordon.mesh.example.com";
        store
            .publish(&dev(1), &[(name.into(), "first".into())])
            .unwrap();
        store
            .publish(&dev(1), &[(name.into(), "second".into())])
            .unwrap();
        let values = store.lookup(name).unwrap();
        assert_eq!(values, vec!["first".to_string(), "second".to_string()]);
        // ...and an identical re-post does not grow the set without bound.
        store
            .publish(&dev(1), &[(name.into(), "second".into())])
            .unwrap();
        assert_eq!(store.lookup(name).unwrap().len(), 2);
    }

    #[test]
    fn one_device_cannot_spend_the_whole_deployment_budget() {
        // The failure this exists to prevent: a single member — hostile, or just crash-looping
        // through orders — locking certificate issuance out for everybody else for a week.
        let store = ChallengeStore::new(40);
        let order = |n: u32| {
            vec![(
                "_acme-challenge.laptop.gordon.mesh.example.com".to_string(),
                format!("value{n}"),
            )]
        };
        for n in 0..MAX_CERTS_PER_DEVICE_PER_WEEK {
            store.publish(&dev(1), &order(n)).unwrap();
        }
        assert_eq!(
            store.publish(&dev(1), &order(99)),
            Err(PublishError::DeviceBudgetExhausted)
        );
        // The deployment budget is untouched by the refusal, so everyone else still issues.
        assert_eq!(
            store.issued_this_week(),
            MAX_CERTS_PER_DEVICE_PER_WEEK as usize
        );
        store.publish(&dev(2), &order(1)).unwrap();
    }

    #[test]
    fn a_device_slice_is_never_larger_than_the_deployment_budget() {
        // A deployment that meters itself to one certificate a week does not hand one device five.
        let store = ChallengeStore::new(1);
        store
            .publish(
                &dev(1),
                &[("_acme-challenge.a.mesh.example.com".into(), "a".into())],
            )
            .unwrap();
        assert_eq!(
            store.publish(
                &dev(1),
                &[("_acme-challenge.a.mesh.example.com".into(), "b".into())]
            ),
            Err(PublishError::DeviceBudgetExhausted)
        );
    }

    #[test]
    fn a_device_budget_frees_as_its_window_rolls() {
        let store = ChallengeStore::new(40);
        let start = Instant::now();
        let order = |n: u32| {
            vec![(
                "_acme-challenge.laptop.gordon.mesh.example.com".to_string(),
                format!("value{n}"),
            )]
        };
        for n in 0..MAX_CERTS_PER_DEVICE_PER_WEEK {
            store.publish_at(&dev(1), &order(n), start).unwrap();
        }
        assert_eq!(
            store.publish_at(&dev(1), &order(99), start),
            Err(PublishError::DeviceBudgetExhausted)
        );
        // Once the oldest issuances age out, so does the refusal — and the per-device row goes with
        // them rather than accumulating one entry per device that has ever ordered.
        let later = start + ISSUANCE_WINDOW + Duration::from_secs(1);
        store.publish_at(&dev(1), &order(99), later).unwrap();
        assert_eq!(store.inner.lock().unwrap().per_device.len(), 1);
    }

    #[test]
    fn re_posting_a_live_order_is_free() {
        // A device retrying inside the challenge TTL is the same certificate to the CA, so charging
        // it would let a client burn its own allowance (and the deployment's) on retries.
        let store = ChallengeStore::new(40);
        let order = vec![
            (
                "_acme-challenge.laptop.gordon.mesh.example.com".to_string(),
                "device-value".to_string(),
            ),
            (
                "_acme-challenge.gordon.mesh.example.com".to_string(),
                "primary-value".to_string(),
            ),
        ];
        store.publish(&dev(1), &order).unwrap();
        for _ in 0..20 {
            store.publish(&dev(1), &order).unwrap();
        }
        assert_eq!(store.issued_this_week(), 1);
        // ...and the records are still there, with their expiry refreshed rather than duplicated.
        assert_eq!(
            store
                .lookup("_acme-challenge.laptop.gordon.mesh.example.com")
                .unwrap(),
            vec!["device-value".to_string()]
        );
    }

    #[test]
    fn a_names_values_are_capped() {
        // Every lookup clones this vector for the spoofable UDP listener, so the name cannot be
        // allowed to grow into an amplifier.
        let store = ChallengeStore::new(40);
        let name = "_acme-challenge.laptop.gordon.mesh.example.com";
        // Two devices' worth of allowance, so more distinct values reach one name than it may hold.
        let mut n = 0;
        for device in [dev(1), dev(2)] {
            for _ in 0..MAX_CERTS_PER_DEVICE_PER_WEEK {
                store
                    .publish(&device, &[(name.to_string(), format!("value{n}"))])
                    .unwrap();
                n += 1;
            }
        }
        let values = store.lookup(name).unwrap();
        assert_eq!(values.len(), MAX_VALUES_PER_NAME);
        // Oldest evicted, newest kept — the newest is the order most likely still validating.
        assert_eq!(values.last().unwrap(), &format!("value{}", n - 1));
        assert!(!values.contains(&"value0".to_string()));
    }
}
