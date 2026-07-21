//! Per-IP + global request rate limiting middleware.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Rate-limit window and caps for the HTTP API. Generous per-IP so a legitimate NAT'd herd of
/// clients (all waking on one version bump) isn't throttled — long-pollers issue well under 1 req/s
/// each — while a real flood (thousands/s) is refused. The global cap bounds total work regardless of
/// source spoofing; the per-IP table is cleared every window and hard-capped so it can't grow
/// unbounded. Tune `RL_MAX_PER_IP` up for deployments behind a large shared NAT.
const RL_WINDOW: Duration = Duration::from_secs(1);
const RL_MAX_PER_IP: u32 = 30;
const RL_MAX_TOTAL: u32 = 500;
const RL_MAX_TRACKED_IPS: usize = 65_536;

/// The IP to rate-limit this request under: the real client when a **trusted** proxy named it in
/// `X-Forwarded-For`, else the peer we're actually talking to.
///
/// Without this, terminating TLS in a same-host proxy collapses every client into one loopback
/// bucket and the per-IP cap throttles the whole deployment at once. With it, the limiter sees real
/// clients again.
///
/// `X-Forwarded-For` is client-writable, so it's read **only** when the peer is a configured proxy —
/// otherwise a caller would forge a fresh bucket per request and walk straight past the limiter.
/// Entries are scanned right-to-left (each hop appends what it saw, so the rightmost is the most
/// trustworthy) skipping addresses that are themselves trusted proxies; the first remaining entry is
/// the client. Falls back to the peer if the header is absent or unparseable.
pub(crate) fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[ipnet::IpNet]) -> IpAddr {
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(&peer) {
        return peer;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.rsplit(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .find(|ip| !is_trusted(ip))
        })
        .unwrap_or(peer)
}

/// Middleware state for [`rate_limit`]: the shared counter plus the proxies allowed to name the
/// real client via `X-Forwarded-For`.
#[derive(Clone)]
pub(super) struct RateLimitState {
    pub(super) limiter: Arc<Mutex<RateLimiter>>,
    pub(super) trusted_proxies: Arc<Vec<ipnet::IpNet>>,
}

/// A per-source + global windowed request counter, shared across handlers behind an `Arc<Mutex>`.
pub(super) struct RateLimiter {
    window_start: Instant,
    total: u32,
    per_ip: HashMap<IpAddr, u32>,
}

impl RateLimiter {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            total: 0,
            per_ip: HashMap::new(),
        }
    }

    /// Whether to admit a request from `ip` at `now`, accounting it against the window if so.
    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= RL_WINDOW {
            self.window_start = now;
            self.total = 0;
            self.per_ip.clear();
        }
        if self.total >= RL_MAX_TOTAL {
            return false;
        }
        match self.per_ip.get_mut(&ip) {
            Some(count) if *count >= RL_MAX_PER_IP => return false,
            Some(count) => *count += 1,
            None => {
                if self.per_ip.len() >= RL_MAX_TRACKED_IPS {
                    return false; // table full this window — refuse unknown sources
                }
                self.per_ip.insert(ip, 1);
            }
        }
        self.total += 1;
        true
    }
}

/// Axum middleware: refuse a request with `429 Too Many Requests` once the caller's source IP (or the
/// deployment as a whole) exceeds the window budget. The source IP comes from `ConnectInfo`; if it's
/// absent the request still counts against the global cap under the unspecified-address bucket.
pub(super) async fn rate_limit(
    State(st): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let ip = client_ip(peer, req.headers(), &st.trusted_proxies);
    let admit = st.limiter.lock().unwrap().allow(ip, Instant::now());
    if admit {
        next.run(req).await
    } else {
        StatusCode::TOO_MANY_REQUESTS.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimiter, RL_MAX_PER_IP, RL_MAX_TOTAL, RL_WINDOW};
    use std::net::IpAddr;
    use std::time::Instant;

    #[test]
    fn rate_limiter_per_ip_and_window_reset() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(t0);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        for _ in 0..RL_MAX_PER_IP {
            assert!(rl.allow(ip, t0));
        }
        assert!(!rl.allow(ip, t0)); // over the per-IP cap
        let other: IpAddr = "198.51.100.9".parse().unwrap();
        assert!(rl.allow(other, t0)); // a different source is unaffected
        assert!(rl.allow(ip, t0 + RL_WINDOW)); // a new window clears the counters
    }

    #[test]
    fn client_ip_trusts_forwarded_for_only_from_a_configured_proxy() {
        use super::{client_ip, HeaderMap};
        let trusted: Vec<ipnet::IpNet> = vec!["127.0.0.1/32".parse().unwrap()];
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let direct: IpAddr = "198.51.100.9".parse().unwrap();
        let client: IpAddr = "203.0.113.5".parse().unwrap();
        let hdr = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", v.parse().unwrap());
            h
        };

        // Behind the proxy: the header names the client, so each one gets its own bucket instead of
        // the whole deployment sharing loopback's.
        assert_eq!(client_ip(proxy, &hdr("203.0.113.5"), &trusted), client);

        // A direct caller's header is ignored — otherwise anyone could mint a fresh bucket per
        // request and bypass the limiter entirely.
        assert_eq!(client_ip(direct, &hdr("203.0.113.5"), &trusted), direct);

        // Client-supplied entries sit to the LEFT of what our proxy observed; scanning right-to-left
        // past trusted hops picks the real client, not the spoofed prefix.
        assert_eq!(
            client_ip(proxy, &hdr("1.2.3.4, 203.0.113.5, 127.0.0.1"), &trusted),
            client
        );

        // No header, or garbage, falls back to the peer rather than failing open.
        assert_eq!(client_ip(proxy, &HeaderMap::new(), &trusted), proxy);
        assert_eq!(client_ip(proxy, &hdr("not-an-ip"), &trusted), proxy);

        // Default config trusts nobody: behavior is exactly as before for a directly exposed server.
        assert_eq!(client_ip(proxy, &hdr("203.0.113.5"), &[]), proxy);
    }

    #[test]
    fn rate_limiter_global_cap() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(t0);
        let mut allowed = 0u32;
        for i in 0..(RL_MAX_TOTAL + 200) {
            let ip = IpAddr::from([10, 0, (i >> 8) as u8, (i & 0xff) as u8]);
            if rl.allow(ip, t0) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, RL_MAX_TOTAL);
    }
}
