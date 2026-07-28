//! Which service a request is for, and whether the caller may have it.
//!
//! Split from the serving so the access decision is a pure function: this is where a mistake would
//! hand one member another member's service, and a policy you cannot evaluate in a test is one you
//! cannot check.

use std::net::Ipv4Addr;

use common::control::ProxyRoute;

/// What to do with a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Forward to this loopback port.
    Forward(u16),
    /// The name exists but this caller is not in its scope.
    Forbidden,
    /// No service answers to this name here.
    Unknown,
}

/// The routes currently served, as the engine last described them.
#[derive(Default, Clone)]
pub struct Routes(Vec<ProxyRoute>);

impl Routes {
    pub fn new(routes: Vec<ProxyRoute>) -> Self {
        Self(routes)
    }

    /// Decide what a request for `host` from `peer` gets.
    ///
    /// **Fail closed at both ends.** A name nothing serves is [`Decision::Unknown`] rather than
    /// falling through to a default backend — a default is how a proxy quietly serves the wrong
    /// thing. And a caller outside the service's scope is refused even though the packet reached us:
    /// the firewall opens 443 to everyone allowed *any* web service, so once several share a port it
    /// can no longer tell them apart, and this is the check that can.
    pub fn resolve(&self, host: &str, peer: Ipv4Addr) -> Decision {
        let host = normalize_host(host);
        let Some(route) = self.0.iter().find(|r| r.hostnames.contains(&host)) else {
            return Decision::Unknown;
        };
        // `None` restricts nobody; `Some(list)` is exactly those, and an empty list is nobody — a
        // scope whose peers are all offline stays closed rather than falling open.
        match &route.allow {
            None => Decision::Forward(route.port),
            Some(allow) if allow.contains(&peer) => Decision::Forward(route.port),
            Some(_) => Decision::Forbidden,
        }
    }
}

/// The comparable form of a `Host` header: lower-case, no port, no trailing dot.
///
/// All three are the same name to a browser and to DNS, so treating them as different names here
/// would mean a service that works in one address bar and 404s in another.
fn normalize_host(host: &str) -> String {
    let host = host.trim();
    // An IPv6 literal is bracketed, so only split a port off when the colon is unambiguous. Such a
    // request never matches a route (routes are names), but it must not panic or mis-parse either.
    let host = match host.rfind(':') {
        Some(i) if !host.contains(']') || host.rfind(']').is_some_and(|b| b < i) => &host[..i],
        _ => host,
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, port: u16, allow: Option<Vec<Ipv4Addr>>) -> ProxyRoute {
        ProxyRoute {
            hostnames: vec![
                format!("{name}.alice.unity.internal"),
                format!("{name}.alice.mesh.example.com"),
            ],
            port,
            allow,
        }
    }

    const PEER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);
    const STRANGER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);

    #[test]
    fn a_service_answers_to_both_of_its_names() {
        // People type whichever they know. The certificate name is the one a browser needs, but the
        // `unity.internal` one is what the rest of the mesh has always used.
        let r = Routes::new(vec![route("jellyfin", 8096, None)]);
        for host in [
            "jellyfin.alice.unity.internal",
            "jellyfin.alice.mesh.example.com",
            "JELLYFIN.Alice.Mesh.Example.COM", // case is not part of a name
            "jellyfin.alice.mesh.example.com:443", // nor is the port a browser appends
            "jellyfin.alice.mesh.example.com.", // nor a trailing root dot
        ] {
            assert_eq!(r.resolve(host, PEER), Decision::Forward(8096), "{host}");
        }
    }

    #[test]
    fn an_unserved_name_is_refused_rather_than_defaulted() {
        // No default backend: a proxy that falls back to "the first one" serves the wrong service
        // to someone who asked for a different one, and does it silently.
        let r = Routes::new(vec![route("jellyfin", 8096, None)]);
        assert_eq!(
            r.resolve("git.alice.mesh.example.com", PEER),
            Decision::Unknown
        );
        assert_eq!(r.resolve("", PEER), Decision::Unknown);
        assert_eq!(
            Routes::default().resolve("anything", PEER),
            Decision::Unknown
        );
    }

    /// The reason this check exists: once every web service shares port 443, the packet filter can
    /// no longer tell them apart, so the per-service scope has to be enforced here.
    #[test]
    fn a_caller_outside_the_services_scope_is_refused_even_though_the_packet_arrived() {
        let r = Routes::new(vec![route("jellyfin", 8096, Some(vec![PEER]))]);
        assert_eq!(
            r.resolve("jellyfin.alice.mesh.example.com", PEER),
            Decision::Forward(8096)
        );
        assert_eq!(
            r.resolve("jellyfin.alice.mesh.example.com", STRANGER),
            Decision::Forbidden
        );
    }

    /// An empty allow-list is "nobody", not "everybody" — the scope's peers are simply all offline,
    /// and a service must not fall open when its audience goes away.
    #[test]
    fn a_scope_with_no_one_in_it_is_closed_not_open() {
        let r = Routes::new(vec![route("jellyfin", 8096, Some(vec![]))]);
        assert_eq!(
            r.resolve("jellyfin.alice.mesh.example.com", PEER),
            Decision::Forbidden
        );
    }

    #[test]
    fn a_bracketed_address_literal_is_parsed_without_panicking() {
        // Never matches a route — routes are names — but hostile input reaches this before anything
        // else does, so it has to be handled rather than assumed away.
        let r = Routes::new(vec![route("jellyfin", 8096, None)]);
        for host in ["[::1]", "[::1]:443", ":", "::::", "[", "]"] {
            assert_eq!(r.resolve(host, PEER), Decision::Unknown, "{host}");
        }
    }
}
