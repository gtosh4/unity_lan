# UnityLAN — Peer-direct attestation refresh

**Status: implemented** (stages 1–2, §10; stage 3 optional and not yet built). This is the
**design/reference doc** for the peer-direct attestation-refresh feature — the code points back
here: `common::p2p` (wire envelope), `engine::p2p` (serve + pull), `engine::daemon` (refresh loop),
`engine::coord::verify_pulled`, and `scripts/gossip-test.sh` (end-to-end). It offloads the
coordinator's per-refresh attestation fan-out to the mesh without weakening the trust model, and
realizes the "gossip/lazy-peering/deltas as the >~1k escape hatch" named in `roadmap.md` item 7 and
`design.md` §5.

**Relationship to M3b (deferred gossip).** M3b prototyped *epidemic discovery gossip* and reverted
it, finding: gossip runs over WG tunnels, WG needs **reciprocal** peer knowledge, so a node can only
gossip with peers that already know it → gossip cannot bootstrap discovery, and its residual value
looked marginal. This design is deliberately **not** that:

- It is **refresh, not discovery.** New-peer introduction stays 100% on the coordinator (the only
  ACL authority). We never try to learn an unknown peer from the mesh — the exact thing M3b showed
  gossip can't do.
- It operates **only between already-meshed peers**, which is precisely the reciprocal regime M3b
  said gossip is limited to. We embrace that limit instead of fighting it.
- It is **single-hop authoritative pull, not epidemic** — each device serves *its own*
  coordinator-minted attestation to its co-members. No multi-hop propagation, so none of M3b's
  convergence-bug class (the 3-node bug) can arise.
- M3b judged the payoff "marginal" *before* per-guild signing keys made the coordinator's
  distribution cost explicitly **O(N²) signs + O(N²) bytes per epoch**. That cost is now the
  measured scale wall (see the sign-cache work), so the payoff is no longer marginal at target
  scale.

---

## 1. Problem

For a mesh of `N` co-members in one guild, the coordinator today rebuilds and re-signs a full
snapshot **per client per renewal** (≈ every `LONGPOLL_HOLD_SECS`), and again on every membership
herd. Each snapshot carries every co-member's signed attestation. That is:

- **O(N²) Ed25519 signs / epoch** — mitigated to O(N) by the sign-cache (each attestation signed
  once per epoch, reused across snapshots), but still centralized.
- **O(N²) build + serialize + bytes / epoch** — the coordinator assembles and ships `N` seeds to
  each of `N` clients. This is the residual central cost the cache does *not* remove.

Both scale with the square of a single guild's size and concentrate on one box (a `t3.micro` in the
target deployment). The north-star (`CLAUDE.md` "keep the coordinator off the hot path") says push
this work to the peers.

## 2. Key fact: attestations are self-verifying

An attestation is a `Signed<Attestation>` — a coordinator-minted token any holder of the guild
anchor can verify (`coord::verified_seeds` → verify vs the **pinned** anchor). Two consequences:

- **Minting must stay central** — only the coordinator holds the per-guild signing key. Irreducible,
  but only **O(N)/epoch** (one sign per device), and already cached.
- **Distribution need not be central** — a peer that holds C's attestation can hand it to another
  co-member, who verifies it against the pinned anchor exactly as if the coordinator had served it.
  The coordinator does not need to be in the loop for the *handoff*.

So the O(N²) *distribution* is what moves to the mesh; the O(N) *minting* stays put.

## 3. Invariant: the coordinator is always sufficient

Peer-direct refresh is a **fast path layered over an always-present coordinator fallback**, never a
replacement. There must be no state where a node *needs* the mesh and cannot fall back. Cases that
are **coordinator-only** (no peer to pull from, or ACL knowledge required):

| Case | Why the mesh can't serve it |
|---|---|
| Cold start / first join | Zero tunnels → no peer to pull from. Own attestation + initial peer set from coordinator. |
| First/only member online | Empty mesh — nobody to pull from. |
| New-peer introduction | Learning a co-member you've never met needs Discord-role/ACL knowledge — coordinator only. |
| All paths to peer C down | Can't pull C's attestation from an unreachable C → coordinator serves it. |
| Long-offline re-sync | Attestations expired + peers churned while away → re-bootstrap from coordinator. |

Because the fallback is always there, this feature is **purely additive** and shippable in stages:
any peer not covered by a successful pull silently flows through the coordinator exactly as today.

## 4. Design: pull-own + serve-own

Each device is the **authority for distributing its own attestation**. It:

1. **Pulls its own** freshly-minted attestation(s) from the coordinator on its epoch cadence —
   **O(1)/device/epoch** (this is just the caller's own `grant`, already returned by `/refresh`).
2. **Serves its own** current attestation to any co-member that asks, over the mesh (§5). No signing
   — it returns the cached blob it got from the coordinator.
3. **Refreshes a known peer C** by asking **C directly** when C's held attestation nears expiry,
   instead of waiting for the coordinator to re-serve it. Verify the reply against the pinned anchor
   for C's pubkey; adopt on success; **fall back to the coordinator** on timeout/failure.

This is single-hop and authoritative: the source of truth for C's attestation is C, which always
holds its own current copy (step 1). No epidemic, no convergence problem.

**Load.** The coordinator's O(N²) fan-out becomes O(N) mints (each device pulls its own). The
distribution cost is spread across the mesh: each node answers ~`N` cheap requests per refresh
window (one per co-member) = **O(N) per node**, which is inherent to already holding `N` tunnels.
The square term is decentralized, not eliminated — exactly the goal.

**Refresh trigger (ties to the sign-cache's Option A).** A device refreshes a peer's attestation
when it enters a refresh window before expiry (e.g. `ATTESTATION_TTL_SECS − SIGN_CACHE_TTL_SECS`
remaining). Triggers stagger across peers/nodes by join time → no synchronized herd. The same
window drives the client's coordinator fallback, so the two paths share one clock.

## 5. Transport

Peer-direct refresh rides **inside the WG tunnel**, so the channel is already mutually authenticated
and encrypted, and reachable **only by meshed co-members** (a stranger's packets never make it
through WG crypto-routing — the M3b reciprocity property, here a feature). Precedent: the engine
already binds a small UDP service to its mesh IP for DNS (`engine/src/dns.rs`).

- A tiny **request/response UDP service** bound to the device's mesh `/32`, dedicated port.
- **Pull-only** for the base pattern. No push, no subscriptions, no epidemic fan-out — avoids storms
  and the M3b convergence bug class. (A future notify-style type is possible in the envelope; see
  §5.3.)
- Rate-limit inbound per source mesh IP and per message type — replies are cached blobs, so cost is
  negligible, but bound it anyway.

QUIC/HTTP is overkill; a request/response over the authenticated tunnel is enough.

### 5.1 A typed, versioned envelope (don't hard-wire "get attestation")

The one thing worth getting right up front is **not** the attestation payload — it's making the
channel carry *arbitrary* future message types without a new socket/port/handshake each time. So the
wire is a small self-describing envelope, mirroring how the coordinator API is one endpoint with a
typed request enum:

```
P2PRequest  { proto: u32, body: ReqType }     // ReqType = enum { GetAttestations{guild?}, ... }
P2PResponse { proto: u32, body: RespType }     // RespType includes an `Unsupported` variant
```

Requirements the envelope must satisfy from day one, even though only one type ships first:

- **Extensible message type** — a versioned `enum` (serde-tagged), so a new type is an added variant,
  not a protocol break. Reserve the `proto` field for coarse breaks.
- **Capability graceful-degrade** — a peer that doesn't know a requested type replies `Unsupported`
  (never a hard error), so mixed-version meshes interoperate. The caller then falls back to the
  coordinator (§3), exactly as if the peer were offline.
- **Per-type size + rate bounds** — a datagram fits attestations/hints; a bulk type (a release
  manifest) may not, so the envelope is defined **transport-agnostic** — start UDP-datagram, and if
  a future type needs bulk, add framing/chunking (or a stream sidecar) without touching existing
  types. Bulk types stay coordinator-served until then.

### 5.2 Future payloads this channel should be able to carry

Only attestation-refresh ships now; the rest justify the typed envelope. Each is classified by
**shape** (which determines how it's verified and whether it can live here at all):

| Payload | Shape | Verification | Fits? |
|---|---|---|---|
| **Attestation refresh** (now) | serve-own signed | `Signed` vs pinned anchor | ✅ ships first |
| **Rotation-chain / anchor update** (design §9) | serve-own signed | chain links signed by prior key | ✅ same shape; adds "re-pin even if coordinator down" |
| **Signed release manifest** (auto-update) | serve-own signed | `Signed` vs pinned anchor | ✅ shape fits; may need bulk transport (§5.1) — mesh-propagated updates |
| **Endpoint / reflexive freshness** (roaming) | observed advisory | none — best-effort only | ⚠ allowed but **never security-load-bearing** (wrong value just fails a WG handshake) |
| **Coordinator-reachability proxy** (README bootstrap) | relay-for-others | coordinator's response is self-verifying | ✅ different flow; forwards a joiner's `/register` when its path to the coordinator is down |
| **Signed revocation hint** (faster-than-TTL evict) | signed negative | coordinator-signed, short-lived | ✅ only if signed — an unsigned evict is a DoS; note the risk before building |
| **Peer-relayed ICE candidates** | relay-for-others | pair already coordinator-authorized | ◻ possible; overlaps M5.5 brokering — defer |

### 5.3 Scope boundary (so the channel stays bounded, not a discovery system)

The envelope is extensible in *message types* but **deliberately bounded in scope**: it carries only
what is valid between **already-meshed, mutually-authorized peers**, and payloads are either
**self-verifying** (signed vs the pinned anchor) or **purely advisory** (never load-bearing for
security). Anything that needs ACL authority over an **unmet** peer — discovery, membership certs
(§7) — does **not** belong here; it stays with the coordinator. Keeping that line crisp is what
stops this channel from accreting back into the epidemic discovery-gossip that M3b showed doesn't
work. Future-proof in payloads; fixed in scope.

## 6. Security

- **No new trust.** Every adopted attestation is verified against the **pinned** guild anchor
  ([[pinned-anchor-invariant]]) for the expected pubkey, identical to the coordinator path. A
  malicious peer cannot forge one (self-verifying) or substitute another device's (pubkey is bound
  and checked).
- **Revocation window unchanged.** Gossiped or not, an attestation expires at its signed TTL; a peer
  cannot extend it. A kicked member's credential dies on the same clock as today.
- **DoS.** The serve endpoint is reachable only through WG (authenticated co-members) and returns a
  cached blob; rate-limit per source. A peer flooding requests hurts only itself.

## 7. Privacy

Refresh talks **only to already-meshed peers** — pairs the coordinator already authorized — so it
reveals nothing a co-member didn't already have. This is the crucial contrast with the **deferred**
full-discovery-gossip tier, which would need the coordinator to issue signed **per-network
membership certs** so peers self-check the ACL and learn *unmet* peers — at the cost of leaking a
device's full role membership to every co-member (today only *shared* networks are revealed). That
tier is out of scope here (§9).

## 8. Interaction with the coordinator-side plan

The coordinator's `/refresh` conflates **three** jobs, each with a different cost profile and a
different right tool. Untangling them is what makes each fix simple:

| # | Job | Frequency | Fixed by |
|---|---|---|---|
| 1 | Attestation freshness (renewal) | periodic | **this doc** (gossip-refresh) |
| 2 | Membership discovery (join/leave/role) | event / churn | **simple membership delta** |
| 3 | NAT brokering (ICE / reflexive / relay exchange) | connection-setup bursts | **targeted wakeups** |

- **Sign-cache (done)** — still needed regardless: minting stays central, the cache keeps it O(N),
  and it serves the bootstrap/fallback paths (§3) which remain coordinator-side.

- **Gossip-refresh (this doc)** removes **job 1**. In steady state the coordinator then serves ≈ zero
  peer bytes — the client long-polls only for membership changes and pulls its own O(1) grant.

- **Membership delta — keep, but the *simple* version, not the complex one.** Once job 1 leaves and
  job 3 is handled separately (below), a delta only has to convey **membership** — peer
  added/removed/identity-changed — via `changed_at_version` + removal tombstones. That is ~1/3 the
  code of the rejected *5-source client-assisted digest* (which existed only to also cover the
  frequent per-pair NAT updates — now job 3's problem, not delta's).

  It earns its keep on the **membership herd**, which gossip does *not* touch (learning a *new* peer
  is coordinator-only — §3). Worst case is the **evening login-storm**: N members log on within
  minutes, each join waking the growing herd, each woken client rebuilding a full snapshot → **Σk² ≈
  O(N³)** (~12 GB of seed-builds at N=500). Simple delta sends each woken client only the one joiner
  → **O(N²)** (~37 MB). A real game-night scenario, ~300× cheaper. In a quiescent mesh its value → 0;
  it's a churn-insurance layer.

- **Targeted wakeups** handle **job 3**. An ICE/reflexive/relay update is *pair-specific* — P's ICE
  offer is **for** X — yet today it bumps the global version and wakes the whole herd, each
  rebuilding a full snapshot for a change only X cares about. Waking **only X** kills that herd at
  the source. This is why delta doesn't need to cover the NAT sources: targeted wakeups remove the
  need, and it's simpler than delta-ing pair-specific data. (Job 2's herd, by contrast, legitimately
  fans out to *all* co-members — targeted wakeups can't shrink it, which is exactly why job 2 needs
  delta and job 3 doesn't.)

- **Herd jitter** — still cheap insurance to spread the residual job-2 fan-out (all co-members do
  wake on a real join) over a few seconds, protecting coordinator burst credits.

Net: **cache** (O(N) minting) + **gossip** (job 1 off-coordinator) + **simple delta** (job 2 payload)
+ **targeted wakeups** (job 3 herd) + **jitter** (smooth job 2). The complex 5-source delta is
**rejected** — its responsibilities are split across gossip and targeted wakeups, each simpler.

## 9. Non-goals

- **Discovery gossip** — learning unmet peers from the mesh. Stays on the coordinator (M3b). The
  membership-cert tier that would enable it is deferred (§7).
- **Epidemic / push gossip** — not needed; single-hop authoritative pull suffices and is simpler.
- **Removing the coordinator** — it remains source of truth, ACL authority, and fallback (§3).

## 10. Build plan (incremental — each stage is a safe no-op-if-off addition)

1. ✅ **Serve-own endpoint** — engine binds the mesh-IP UDP service with the typed envelope (§5.1) and
   its first request type `GetAttestations`; answers with its own `Vec<GuildAttestation>`. Behind the
   `gossip` flag (default on). (Build the envelope, not a one-off endpoint — later types are added
   variants.)
2. ✅ **Peer-direct pull + fallback** — daemon, on a held peer entering the refresh window, pulls from
   that peer; verifies vs pinned anchor; adopts or falls back to the coordinator.
3. ◻ **Lengthen coordinator renewal** (optional, not yet built) — once peer-direct refresh carries
   freshness, the client's coordinator `/refresh` can back off (membership-driven wakes + a long
   safety renewal), cutting idle coordinator polling further.

**Verify.** ✅ `scripts/gossip-test.sh`: brings up A+B via coordinator, **blocks A→coordinator**, and
confirms A refreshes B's attestation directly and the mesh stays up past one attestation TTL, then
unblocks and confirms coordinator fallback still works. Plus engine unit tests for the serve/verify
path (malformed/expired/wrong-pubkey replies rejected).

## 11. Open questions

Resolved as the feature shipped:

- ✅ **Port + envelope framing** — UDP `common::p2p::P2P_PORT` (51830) bound to the mesh `/32`; a
  serde internally-tagged `ReqBody`/`RespBody` enum with a `proto` version field and an
  `Unknown`/`Unsupported` degrade path; `P2P_MAX_DATAGRAM` (16 KiB) caps a datagram, above which a
  future bulk type must chunk/stream.
- ✅ **Refresh-window vs. sign-cache epoch** — the client refreshes a peer within a window before
  expiry driven by the same clock as the coordinator fallback (§4), so peer-served blobs and the
  fallback share one trigger instead of double-fetching.

Still open:

- Whether to also serve a peer's *endpoint/ICE* freshness here, or keep those coordinator-brokered
  (they're pair-specific; likely leave them until a concrete need — M3b's "marginal" caveat applies
  to endpoint-only gossip).
- Backoff schedule for coordinator `/refresh` (stage 3, §10).
