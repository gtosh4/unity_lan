//! A per-source + global windowed request counter, shared by the HTTP rate-limit middleware
//! (`api::ratelimit`) and the STUN responder (`stun`). Both need the same mechanism — cap requests
//! per source IP and overall within a fixed window, bound the tracked-IP table so a spoofed-source
//! flood can't grow it unbounded — differing only in their caps and threat-model rationale (which
//! live at each caller). The counter is **not** internally synchronized: a single-task owner (STUN)
//! uses it directly; a shared one (the HTTP middleware) wraps it in a `Mutex`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Window length and caps for a [`WindowCounter`].
pub struct Caps {
    /// Length of the counting window; counters reset on the first request past it.
    pub window: Duration,
    /// Max requests admitted from any one source IP per window.
    pub max_per_ip: u32,
    /// Max requests admitted overall per window, regardless of source (bounds spoofed-source floods).
    pub max_total: u32,
    /// Max distinct source IPs tracked per window; once full, unknown sources are refused.
    pub max_tracked_ips: usize,
}

/// A per-source + global windowed counter.
pub struct WindowCounter {
    caps: Caps,
    window_start: Instant,
    total: u32,
    per_ip: HashMap<IpAddr, u32>,
}

impl WindowCounter {
    pub fn new(caps: Caps, now: Instant) -> Self {
        Self {
            caps,
            window_start: now,
            total: 0,
            per_ip: HashMap::new(),
        }
    }

    /// Whether to admit a request from `ip` at `now`, accounting it against the window if so.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= self.caps.window {
            self.window_start = now;
            self.total = 0;
            self.per_ip.clear();
        }
        if self.total >= self.caps.max_total {
            return false;
        }
        match self.per_ip.get_mut(&ip) {
            Some(count) if *count >= self.caps.max_per_ip => return false,
            Some(count) => *count += 1,
            None => {
                if self.per_ip.len() >= self.caps.max_tracked_ips {
                    return false; // table full this window — refuse unknown sources
                }
                self.per_ip.insert(ip, 1);
            }
        }
        self.total += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{Caps, WindowCounter};
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    fn counter(now: Instant) -> WindowCounter {
        WindowCounter::new(
            Caps {
                window: Duration::from_secs(1),
                max_per_ip: 5,
                max_total: 20,
                max_tracked_ips: 64,
            },
            now,
        )
    }

    #[test]
    fn caps_per_ip_and_resets_each_window() {
        let t0 = Instant::now();
        let mut rl = counter(t0);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        for _ in 0..5 {
            assert!(rl.allow(ip, t0)); // up to max_per_ip
        }
        assert!(!rl.allow(ip, t0)); // over the per-IP cap
        let other: IpAddr = "198.51.100.9".parse().unwrap();
        assert!(rl.allow(other, t0)); // a different source is unaffected
        assert!(rl.allow(ip, t0 + Duration::from_secs(1))); // a new window clears the counters
    }

    #[test]
    fn caps_total_across_sources() {
        let t0 = Instant::now();
        let mut rl = counter(t0);
        // Spread across many sources so the per-IP cap never trips — only the global one does.
        let mut allowed = 0u32;
        for i in 0..100u32 {
            let ip = IpAddr::from([10, 0, (i >> 8) as u8, (i & 0xff) as u8]);
            if rl.allow(ip, t0) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 20); // exactly max_total, despite the per-IP cap never being reached
    }

    #[test]
    fn refuses_unknown_sources_once_the_tracked_table_is_full() {
        let t0 = Instant::now();
        let mut rl = WindowCounter::new(
            Caps {
                window: Duration::from_secs(1),
                max_per_ip: 5,
                max_total: 1_000,
                max_tracked_ips: 4,
            },
            t0,
        );
        for i in 0..4u32 {
            assert!(rl.allow(IpAddr::from([10, 0, 0, i as u8]), t0)); // fills the table
        }
        assert!(!rl.allow(IpAddr::from([10, 0, 0, 99]), t0)); // a new source is refused, not tracked
        assert!(rl.allow(IpAddr::from([10, 0, 0, 0]), t0)); // an already-tracked source still counts
    }
}
