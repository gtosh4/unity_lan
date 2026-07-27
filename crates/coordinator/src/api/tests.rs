//! End-to-end tests over the real [`router`] — request in, response out.
//!
//! The other modules' tests cover their decision functions in isolation. These cover what only the
//! assembled thing can be wrong about: whether a route is wired at all, whether the extractors
//! accept what a client actually sends, whether the layers (rate limit, connect-info) let a request
//! through, and whether a change to one phase of a snapshot silently breaks another. Every one of
//! those has a status code as its symptom and no unit test as its witness.
//!
//! Everything runs against an in-memory store and a config-seeded role source, so there is no
//! network, no Discord and no disk — the same constraints as the unit tests, one layer up.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use common::api::{RegisterReq, RegisterResp};
use tower::ServiceExt;

use super::{router, AppState};
use crate::config::{FakeConfig, FakeGuild, FakeMember};
use crate::presence::Presence;
use crate::roles::FakeRoleSource;
use crate::signer::{GuildKeys, SignCache};
use crate::store::Store;
use crate::versions::Versions;

const GUILD: u64 = 1;
const ROLE: u64 = 10;
const TTL: u64 = 600;

/// Counts the role-source lookups a snapshot makes, so a test can assert on the *cost* of a code
/// path and not only its answer. Membership lookups are the coordinator's per-client Discord traffic
/// — the thing that multiplies under a herd — and nothing else would notice them growing.
struct CountingRoles {
    inner: FakeRoleSource,
    member_calls: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl crate::roles::RoleSource for CountingRoles {
    async fn guild_name(&self, guild_id: u64) -> Option<String> {
        self.inner.guild_name(guild_id).await
    }
    async fn member(&self, guild_id: u64, user_id: u64) -> Option<crate::roles::MemberRoles> {
        self.member_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.member(guild_id, user_id).await
    }
    async fn role_name(&self, guild_id: u64, role_id: u64) -> Option<String> {
        self.inner.role_name(guild_id, role_id).await
    }
}

/// A coordinator wired exactly as `main` wires it, minus the socket.
struct TestCoordinator {
    state: AppState,
    /// How many member lookups the role source has served.
    member_calls: Arc<AtomicU64>,
    /// Device bearer tokens as a client would persist them: issued once at enrollment, then
    /// presented on every later register. Without this the harness would 401 itself, since a
    /// public WG key is not authentication.
    tokens: Mutex<std::collections::HashMap<[u8; 32], String>>,
    /// Uniquifier for minted enrollment keys (they are one-time).
    keys_minted: AtomicU64,
}

impl TestCoordinator {
    /// One guild, one registered network on `ROLE`, and one member per `(user_id, holds_role)`.
    async fn new(members: &[(u64, bool)]) -> Self {
        let store = Arc::new(Store::memory().await);
        store
            .upsert_network(GUILD, ROLE, "mesh")
            .await
            .expect("register the test network");
        let member_calls = Arc::new(AtomicU64::new(0));
        let roles = Arc::new(CountingRoles {
            member_calls: member_calls.clone(),
            inner: FakeRoleSource::new(FakeConfig {
                guilds: vec![FakeGuild {
                    id: GUILD,
                    name: "acme".into(),
                    members: members
                        .iter()
                        .map(|&(user_id, holds)| FakeMember {
                            user_id,
                            username: format!("user{user_id}"),
                            role_ids: if holds { vec![ROLE] } else { vec![99] },
                        })
                        .collect(),
                }],
            }),
        });
        let guild_keys = Arc::new(GuildKeys::new(
            store.clone(),
            "100.72.0.0/16".parse().unwrap(),
            TTL,
        ));
        Self {
            state: AppState {
                guild_keys,
                sign_cache: Arc::new(SignCache::new(TTL)),
                wakers: Arc::new(super::Wakers::default()),
                longpoll_hold_secs: TTL / 2,
                park_slots: Arc::new(super::ParkSlots::new(64)),
                roles,
                store,
                presence: Arc::new(Presence::default()),
                versions: Arc::new(Versions::default()),
                roleless: Arc::new(crate::roleless::RolelessMemo::default()),
                oauth: None,
                trusted_proxies: Arc::new(Vec::new()),
                source_ip: Arc::new(Mutex::new(std::collections::HashMap::new())),
                user_labels: Arc::new(Mutex::new(std::collections::HashMap::new())),
                dns: None,
                reflexive: Arc::new(Mutex::new(std::collections::HashMap::new())),
                relays: Arc::new(Mutex::new(std::collections::HashMap::new())),
                relay_allocs: Arc::new(Mutex::new(std::collections::HashMap::new())),
                ice: Arc::new(Mutex::new(std::collections::HashMap::new())),
                stun_port: None,
                release: Arc::new(std::sync::RwLock::new(None)),
                release_signed: Arc::new(std::sync::RwLock::new(None)),
                admin_token: None,
                enroll_secret: [7u8; 32],
                require_enroll_proof: false,
                enroll_proven: Arc::new(AtomicU64::new(0)),
                enroll_unproven: Arc::new(AtomicU64::new(0)),
            },
            tokens: Mutex::new(std::collections::HashMap::new()),
            keys_minted: AtomicU64::new(0),
            member_calls,
        }
    }

    /// Mint a one-time enrollment key for `user_id`, as `/unitylan enroll` does.
    async fn enrollment_key(&self, user_id: u64) -> String {
        // Unique per call: a key is one-time, so an owner enrolling a second device needs a second
        // key rather than a 401 on the reused one.
        let nth = self
            .keys_minted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let key = format!("enroll-key-{user_id}-{nth}");
        self.state
            .store
            .create_enrollment_key(&key, user_id, Some(common::now_unix() + 3600))
            .await
            .expect("mint an enrollment key");
        key
    }

    /// Drive one request through the assembled router, including its layers. `ConnectInfo` is
    /// inserted directly because there is no accept loop here to supply it.
    async fn send(&self, path: &str, body: serde_json::Value) -> (StatusCode, String) {
        let mut req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("build the request");
        req.extensions_mut().insert(ConnectInfo(
            "203.0.113.9:40000".parse::<SocketAddr>().unwrap(),
        ));
        let resp = router(self.state.clone())
            .oneshot(req)
            .await
            .expect("router responded");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read the response body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// `POST /register`, behaving like a real client: any bearer token this device was issued is
    /// presented on every later request, and a newly-issued one is remembered. Tests that want to
    /// see the unauthenticated behavior call [`Self::send`] directly.
    async fn register(&self, req: &RegisterReq) -> Result<RegisterResp, (StatusCode, String)> {
        let mut req = req.clone();
        if req.device_token.is_none() {
            req.device_token = self.tokens.lock().unwrap().get(&req.wg_pubkey).cloned();
        }
        let (status, body) = self
            .send("/register", serde_json::to_value(&req).unwrap())
            .await;
        if status != StatusCode::OK {
            return Err((status, body));
        }
        let resp: RegisterResp = serde_json::from_str(&body).expect("decode RegisterResp");
        if let Some(tok) = &resp.device_token {
            self.tokens
                .lock()
                .unwrap()
                .insert(req.wg_pubkey, tok.clone());
        }
        Ok(resp)
    }

    /// Enrol one device: mint its owner a key, register with it, and keep the token that comes back.
    async fn enrol(&self, pubkey: u8, user_id: u64, device_name: &str) -> RegisterResp {
        let mut r = req(pubkey, device_name);
        r.enrollment_key = Some(self.enrollment_key(user_id).await);
        self.register(&r).await.expect("enrol the device")
    }

    /// Turn on certificate issuance, as a `[dns]` block would.
    fn with_dns(mut self, domain: &str, max_certs_per_week: u32) -> Self {
        self.state.dns = Some(Arc::new(crate::zone::DnsState {
            domain: domain.into(),
            challenges: Arc::new(crate::zone::ChallengeStore::new(max_certs_per_week)),
        }));
        self
    }

    /// This device's persisted bearer token.
    fn token(&self, pubkey: u8) -> String {
        self.tokens
            .lock()
            .unwrap()
            .get(&[pubkey; 32])
            .cloned()
            .expect("device was issued a token")
    }

    /// `POST /acme-challenge` for a device.
    async fn acme(&self, pubkey: u8, primary: Option<&str>) -> (StatusCode, String) {
        self.send(
            "/acme-challenge",
            serde_json::json!({
                "token": self.token(pubkey),
                "device": "device-challenge-value",
                "primary": primary,
            }),
        )
        .await
    }
}

/// A register request for a device, built from the JSON a current client would actually send —
/// every other field takes its wire default, which is the point: a `serde(default)` chosen wrongly
/// shows up here as a behavior change, not as a compile error nobody writes.
fn req(pubkey: u8, device_name: &str) -> RegisterReq {
    serde_json::from_value(serde_json::json!({
        "wg_pubkey": vec![pubkey; 32],
        "device_name": device_name,
        "peer_own_devices": true,
        "proto": common::PROTOCOL_VERSION,
        "proto_min": common::MIN_PROTOCOL_VERSION,
    }))
    .expect("a current client's register body")
}

#[tokio::test]
async fn a_challenge_name_is_derived_from_the_caller_never_supplied_by_it() {
    // The security property the whole route rests on. The request carries values only; a device
    // cannot name the hostname it wants validated, so it cannot obtain a certificate for anyone
    // else's name. Two owners register here and each gets only its own name back.
    let c = TestCoordinator::new(&[(7, true), (8, true)])
        .await
        .with_dns("mesh.example.com", 40);
    c.enrol(1, 7, "laptop").await;
    c.enrol(2, 8, "laptop").await;

    let (status, body) = c.acme(1, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let names: Vec<String> = serde_json::from_str::<serde_json::Value>(&body).unwrap()["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        names,
        vec!["_acme-challenge.laptop.user7.mesh.example.com".to_string()]
    );

    // The second owner's identically-named device lands on its own name, not the first's.
    let (status, body) = c.acme(2, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("_acme-challenge.laptop.user8.mesh.example.com"),
        "{body}"
    );
}

#[tokio::test]
async fn the_bare_user_alias_is_only_published_for_the_primary_device() {
    // `<user>.<domain>` names one machine. Honouring it for any of an owner's devices would let a
    // second device hold a publicly-trusted certificate for the name meant to identify the first.
    let c = TestCoordinator::new(&[(7, true)])
        .await
        .with_dns("mesh.example.com", 40);
    c.enrol(1, 7, "laptop").await; // first enrolled → auto-primary
    c.enrol(2, 7, "desktop").await;

    let (_, body) = c.acme(1, Some("alias-challenge-value")).await;
    assert!(
        body.contains("_acme-challenge.user7.mesh.example.com"),
        "{body}"
    );

    // Same request from the non-primary device: its own name only, the alias silently dropped.
    let (_, body) = c.acme(2, Some("alias-challenge-value")).await;
    assert!(
        body.contains("_acme-challenge.desktop.user7.mesh.example.com"),
        "{body}"
    );
    assert!(
        !body.contains("_acme-challenge.user7.mesh.example.com"),
        "{body}"
    );
}

#[tokio::test]
async fn issuance_is_refused_when_the_deployment_configured_no_domain() {
    // No `[dns]` → the feature does not exist here, and the client is told so rather than left to
    // fail against the CA.
    let c = TestCoordinator::new(&[(7, true)]).await;
    c.enrol(1, 7, "laptop").await;
    let (status, _) = c.acme(1, None).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn a_bad_device_token_cannot_publish_a_challenge() {
    let c = TestCoordinator::new(&[(7, true)])
        .await
        .with_dns("mesh.example.com", 40);
    c.enrol(1, 7, "laptop").await;
    let (status, _) = c
        .send(
            "/acme-challenge",
            serde_json::json!({ "token": "not-a-real-token", "device": "v" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_weekly_budget_refuses_rather_than_spending_the_last_of_it() {
    // Exhausting the CA's per-domain cap locks the whole deployment out for the rest of the week,
    // which is worse than declining early — so the coordinator meters and says no.
    let c = TestCoordinator::new(&[(7, true)])
        .await
        .with_dns("mesh.example.com", 1);
    c.enrol(1, 7, "laptop").await;
    c.enrol(2, 7, "desktop").await;

    assert_eq!(c.acme(1, None).await.0, StatusCode::OK);
    let (status, body) = c.acme(2, None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("budget"), "{body}");
}

#[tokio::test]
async fn a_stuck_pair_is_handed_the_relay_and_each_others_relayed_addresses() {
    // A is relay-capable and dialable; B and C are stuck behind NATs and ask for a relay. This is
    // the coordinator half of `scripts/relay-test.sh`: the ~2-round converge where each stuck peer
    // publishes the address it allocated and is handed the other's.
    let c = TestCoordinator::new(&[(7, true), (8, true), (9, true)]).await;
    c.enrol(1, 7, "relay").await;
    c.enrol(2, 8, "b").await;
    c.enrol(3, 9, "c").await;

    // A advertises its embedded TURN server.
    let mut relay = req(1, "relay");
    relay.relay_capable = true;
    relay.relay_addr = Some("10.0.0.1:3478".parse().unwrap());
    relay.relay_secret = Some("sekret".into());
    relay.endpoint = Some("10.0.0.1:51820".parse().unwrap());
    c.register(&relay).await.expect("relay registers");

    // Round 1: B and C each report the punch to the other as stuck. Both get relay credentials for
    // A, but neither has allocated yet, so neither is handed a `peer_relayed`.
    let mut b = req(2, "b");
    b.need_relay = vec![[3; 32]];
    let mut cc = req(3, "c");
    cc.need_relay = vec![[2; 32]];
    let rb = c.register(&b).await.expect("B asks for a relay");
    let seed_c = rb
        .seeds
        .iter()
        .find(|s| s.networks.iter().any(|_| true) && s.relay.is_some())
        .expect("B is offered a relay for C");
    assert_eq!(
        seed_c.relay.as_ref().unwrap().turn_addr,
        "10.0.0.1:3478".parse::<SocketAddr>().unwrap()
    );
    assert!(
        seed_c.relay.as_ref().unwrap().peer_relayed.is_none(),
        "nothing to send to before the peer has allocated"
    );
    c.register(&cc).await.expect("C asks for a relay");

    // Round 2: each reports the relayed address it allocated on A.
    b.relay_allocated = vec![common::api::RelayAllocation {
        peer: [3; 32],
        relayed: "10.0.0.1:40002".parse().unwrap(),
    }];
    cc.relay_allocated = vec![common::api::RelayAllocation {
        peer: [2; 32],
        relayed: "10.0.0.1:40003".parse().unwrap(),
    }];
    c.register(&b).await.expect("B reports its allocation");
    c.register(&cc).await.expect("C reports its allocation");

    // Round 3: each must now be handed the *other's* relayed address — without it the relay shim
    // has no destination and no packet ever crosses.
    let rb = c.register(&b).await.expect("B refreshes");
    let relay_for_c = rb
        .seeds
        .iter()
        .find_map(|s| s.relay.as_ref())
        .expect("B still offered a relay for C");
    assert_eq!(
        relay_for_c.peer_relayed,
        Some("10.0.0.1:40003".parse().unwrap()),
        "B must learn where to send to reach C"
    );

    let rc = c.register(&cc).await.expect("C refreshes");
    let relay_for_b = rc
        .seeds
        .iter()
        .find_map(|s| s.relay.as_ref())
        .expect("C still offered a relay for B");
    assert_eq!(
        relay_for_b.peer_relayed,
        Some("10.0.0.1:40002".parse().unwrap()),
        "C must learn where to send to reach B"
    );
}

#[tokio::test]
async fn enrolling_register_issues_a_grant_and_a_one_time_token() {
    let c = TestCoordinator::new(&[(7, true)]).await;
    let mut r = req(1, "laptop");
    r.enrollment_key = Some(c.enrollment_key(7).await);

    let resp = c.register(&r).await.expect("a role holder registers");
    let grant = resp.grant.expect("a role holder gets a grant");
    assert_eq!(grant.networks, vec!["mesh".to_string()]);
    assert_eq!(resp.anchors.len(), 1, "one anchor per guild held");
    assert_eq!(resp.anchors[0].guild_id, GUILD);

    // The bearer token is delivered exactly once — on the register that enrolls the device.
    let token = resp.device_token.expect("token on first enrollment");
    let mut again = req(1, "laptop");
    again.device_token = Some(token.clone());
    let resp = c
        .register(&again)
        .await
        .expect("re-register with the token");
    assert!(
        resp.device_token.is_none(),
        "the token must not be re-issued to anyone who names a known pubkey"
    );
}

#[tokio::test]
async fn an_enrolled_device_without_its_token_is_refused() {
    let c = TestCoordinator::new(&[(7, true)]).await;
    let mut r = req(1, "laptop");
    r.enrollment_key = Some(c.enrollment_key(7).await);
    c.register(&r).await.expect("enrol");

    // A WG public key rides in every co-member's seed, so knowing one must not be enough to pull
    // that device's snapshot or forge its state. This is the regression `rotation-test.sh` caught
    // end to end when the one-shot CLI path dropped the token it was handed.
    let (status, body) = c
        .send("/register", serde_json::to_value(req(1, "laptop")).unwrap())
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.contains("device token"), "{body}");
}

#[tokio::test]
async fn a_member_without_the_role_gets_a_personal_identity() {
    let c = TestCoordinator::new(&[(8, false)]).await;
    let mut r = req(2, "desktop");
    r.enrollment_key = Some(c.enrollment_key(8).await);

    let resp = c.register(&r).await.expect("register is admitted");
    // No role anywhere, but the client asked to peer its own devices: it is attested under the
    // personal scope so a user with nothing but a Discord account can still mesh their own machines.
    let grant = resp.grant.expect("own-device peering → a personal grant");
    assert_eq!(grant.attestations.len(), 1);
    assert!(
        grant.networks.is_empty(),
        "a personal grant carries no networks — it is not an ACL group"
    );
    assert!(resp.networks.is_empty(), "no role → no toggle rows");
    assert!(resp.seeds.is_empty(), "no networks and no siblings online");
    assert_eq!(
        resp.anchors.len(),
        1,
        "one anchor: the personal scope's own key"
    );
    assert_eq!(
        resp.anchors[0].guild_id,
        common::attestation::PERSONAL_SCOPE
    );
}

#[tokio::test]
async fn a_personal_users_renewals_stop_probing_discord_for_membership() {
    use std::sync::atomic::Ordering::Relaxed;

    let c = TestCoordinator::new(&[(8, false)]).await;
    let mut r = req(2, "laptop");
    r.enrollment_key = Some(c.enrollment_key(8).await);
    c.register(&r).await.expect("enrol");
    let after_first = c.member_calls.load(Relaxed);
    assert!(after_first > 0, "the first snapshot has to actually look");

    // Every later renewal is free. This is the whole reason the memo exists: a user in no guild has
    // no member row to cache, so without it each renewal — and each herd wake — would re-ask Discord
    // once per registered guild, forever, to be told "no" every time.
    for _ in 0..3 {
        c.register(&req(2, "laptop")).await.expect("renew");
    }
    assert_eq!(
        c.member_calls.load(Relaxed),
        after_first,
        "a remembered roleless user costs no further lookups"
    );

    // A role change invalidates it — the gateway's `MemberUpdate` path — so the walk resumes.
    c.state.roleless.forget(8);
    c.register(&req(2, "laptop")).await.expect("renew");
    assert!(
        c.member_calls.load(Relaxed) > after_first,
        "forgetting the memo must make the next snapshot look again"
    );
}

#[tokio::test]
async fn a_personal_hostname_uses_the_handle_captured_at_login() {
    let c = TestCoordinator::new(&[(8, false)]).await;
    // What `/oauth/complete` records. Without it the only name a guild-less user has is their
    // snowflake, and their machines would answer to `laptop.user-8.unity.internal`.
    c.state
        .store
        .set_user_handle(8, "Ada Lovelace")
        .await
        .expect("record the handle");

    let mut r = req(2, "laptop");
    r.enrollment_key = Some(c.enrollment_key(8).await);
    let resp = c.register(&r).await.expect("register");

    let grant = resp.grant.expect("a personal grant");
    let ga = &grant.attestations[0];
    let signed = common::wire::Signed::from_base64(&ga.attestation).expect("decode");
    let anchor = common::crypto::anchor_from_bytes(&resp.anchors[0].pubkey).expect("anchor");
    let att = common::attestation::verify_attestation(
        &signed,
        &anchor,
        common::now_unix(),
        common::attestation::PERSONAL_SCOPE,
        ga.att_schema,
    )
    .expect("the personal attestation verifies against the personal anchor");
    assert_eq!(att.username, "ada-lovelace", "sanitized to a DNS label");
    assert_eq!(att.hostname(), "laptop.ada-lovelace.unity.internal");
}

#[tokio::test]
async fn a_roleless_device_declining_own_device_peering_gets_no_address() {
    let c = TestCoordinator::new(&[(8, false)]).await;
    let mut r = req(2, "desktop");
    r.enrollment_key = Some(c.enrollment_key(8).await);
    r.peer_own_devices = false;

    let resp = c.register(&r).await.expect("register is admitted");
    // Admitted, but allocation-gated: an account with no access and nothing to mesh must not consume
    // a mesh IP or leave a device row behind (TM-2). The personal scope is opt-in, and this is the
    // opt-out.
    assert!(
        resp.grant.is_none(),
        "no role, no own-device peering → nothing"
    );
    assert!(resp.networks.is_empty());
    assert!(resp.seeds.is_empty());
}

#[tokio::test]
async fn two_devices_of_a_roleless_user_mesh_with_each_other() {
    let c = TestCoordinator::new(&[(8, false), (9, false)]).await;
    c.enrol(2, 8, "laptop").await;
    // Second device of the *same* owner — its own enrollment key, since each is one-time.
    let key = "enroll-key-8-second";
    c.state
        .store
        .create_enrollment_key(key, 8, Some(common::now_unix() + 3600))
        .await
        .expect("mint the second key");
    let mut second = req(3, "desktop");
    second.enrollment_key = Some(key.into());
    let resp = c.register(&second).await.expect("enrol the second device");

    assert_eq!(resp.seeds.len(), 1, "the owner's other device, and only it");
    let seed = &resp.seeds[0];
    assert!(
        seed.networks.is_empty(),
        "siblings share no network — that is the whole point"
    );
    assert_eq!(seed.attestations.len(), 1);

    // A different roleless user is not pulled in: the personal scope is per owner, not a lobby of
    // everyone the deployment failed to give a role to.
    let stranger = c.enrol(4, 9, "theirs").await;
    assert!(stranger.seeds.is_empty(), "another user's devices stay out");
    let again = c.register(&req(2, "laptop")).await.expect("re-register");
    assert_eq!(again.seeds.len(), 1, "…and don't appear to ours either");
}

#[tokio::test]
async fn co_members_see_each_other_and_a_stranger_sees_neither() {
    let c = TestCoordinator::new(&[(7, true), (8, true), (9, false)]).await;
    c.enrol(1, 7, "a").await;
    c.enrol(2, 8, "b").await;
    // The role-less user sees nobody: it holds no network, and it is the only device its owner has,
    // so its personal scope seeds nothing either.
    let stranger = c.enrol(3, 9, "c").await;
    assert!(stranger.seeds.is_empty(), "a non-member sees no peers");

    // Two holders of the same role are co-members: each sees exactly the other.
    let a = req(1, "a"); // no `held` → the full set, not a delta
    let resp = c.register(&a).await.expect("re-register A");
    assert_eq!(resp.seeds.len(), 1, "A sees exactly B");
    assert_eq!(resp.seeds[0].networks[0].guild_id, GUILD);
    assert!(!resp.seeds[0].attestations.is_empty());

    // …and the stranger is in neither of their snapshots.
    let resp = c.register(&req(2, "b")).await.expect("re-register B");
    assert_eq!(
        resp.seeds.len(),
        1,
        "B sees exactly A, never the non-member"
    );
}

#[tokio::test]
async fn delta_sync_returns_only_what_changed() {
    let c = TestCoordinator::new(&[(7, true), (8, true)]).await;
    for (pk, user, name) in [(1u8, 7u64, "a"), (2, 8, "b")] {
        c.enrol(pk, user, name).await;
    }

    let full = c.register(&req(1, "a")).await.expect("full snapshot");
    assert_eq!(full.seeds.len(), 1);
    assert!(!full.partial);

    // Echo back what we hold at the rev we were given → nothing to resend.
    let mut held = req(1, "a");
    held.held = vec![common::api::HeldPeer {
        pubkey: [2; 32],
        rev: full.seeds[0].rev,
    }];
    let delta = c.register(&held).await.expect("delta snapshot");
    assert!(delta.partial, "a client that sent `held` gets a delta");
    assert!(delta.seeds.is_empty(), "unchanged peer is not resent");
    assert!(delta.removed.is_empty());

    // A peer we hold that is no longer a co-member comes back as a removal.
    let mut stale = req(1, "a");
    stale.held = vec![common::api::HeldPeer {
        pubkey: [99; 32],
        rev: 1,
    }];
    let delta = c.register(&stale).await.expect("delta snapshot");
    assert_eq!(
        delta.removed,
        vec![[99u8; 32]],
        "drop what we no longer see"
    );
}

#[tokio::test]
async fn an_unspeakable_protocol_is_refused_before_any_work() {
    let c = TestCoordinator::new(&[(7, true)]).await;
    let mut r = req(1, "laptop");
    r.proto = 2;
    r.proto_min = 1;
    let (status, body) = c.send("/register", serde_json::to_value(&r).unwrap()).await;
    assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
    assert!(body.contains("client is too old"), "{body}");
    // Refused on the range alone: no enrollment key was sent, yet this is a 426 and not a 401.
}

#[tokio::test]
async fn login_routes_report_unavailable_when_oauth_is_unconfigured() {
    let c = TestCoordinator::new(&[]).await;
    let body = serde_json::json!({
        "wg_pubkey": vec![0u8; 32],
        "access_token": "t",
    });
    let (status, _) = c.send("/oauth/complete", body).await;
    // A deployment with no `[oauth]` must say so rather than 500 or silently bind a device.
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn the_admin_surface_is_absent_until_an_operator_opts_in() {
    let c = TestCoordinator::new(&[]).await;
    let req = Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = router(c.state.clone()).oneshot(req).await.unwrap();
    // No `[admin] token` → the route exists but reveals nothing, not even that it is gated.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
