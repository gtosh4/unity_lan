# UnityLAN — Prior Art & Data-Plane Direction

How UnityLAN compares to existing WireGuard (and non-WG) mesh VPNs, what to borrow, and the
resulting **data-plane direction** (userspace-primary + side-socket ICE + relay). Read
`design.md` for our own model first; tasks live in `roadmap.md` (M5.4/M5.5, M8 note, Post-GA).

> Status: **notes + one decision** (§6, data-plane direction). Everything else feeds the
> roadmap; nothing here is committed work.

## 1. The family

All the WireGuard products share UnityLAN's shape: a **WG data plane** + a **central control
plane** that authenticates members and distributes keys/config, with traffic flowing **directly
peer-to-peer**. The control plane carries no traffic. Differences are in *identity*, *NAT
strategy*, *relay*, and *trust root*.

| Product | Control plane | Identity / ACL | NAT traversal | Relay | WG backend | Client |
|---|---|---|---|---|---|---|
| **Tailscale** | Cloud (vendor) | SSO + policy ACLs, tags, **tailnet lock** | DisCo, in-socket STUN | **DERP** (:443) | userspace (wg-go) | Own, all OS incl. mobile |
| **Headscale** | Self-host reimpl of TS control | TS ACL format | via TS client | DERP (self / TS) | userspace | **Reuses TS client** |
| **NetBird** | Self-host: Mgmt + **Signal** + Relay | IdP/OIDC + posture | **side-socket ICE** (pion) | Coturn + WS relay | kernel **or** userspace | Own |
| **Defguard** | Self-host: Core + Gateway + **Edge** | OIDC provider, LDAP, **MFA at WG handshake** | none (**public gateway hub**) | Gateway (hub) | `defguard_wireguard_rs` (same lib we use) | Own + native WG |
| **Nebula** | Self-host **lighthouse** | CA-signed certs w/ groups | lighthouse-coordinated punch | via lighthouse | **custom (non-WG)** Noise | Own |
| **ZeroTier** | Roots (planet/moon) | network controller | lazy stateless punch | via roots | **custom (non-WG)** | Own |
| **UnityLAN** | Self-host, **control-plane-only** | **Discord roles → signed attestations** | UPnP + peer-observed reflexive + cone punch | **none (v1)** | userspace (unix) / kernel (win) | Own (engine+gui) |

Our differentiator — **Discord roles as ACL, enforced by short-lived signed attestations** — is
unique here. Everything below is about closing the *connectivity* gap without diluting that model
or pulling work onto the coordinator (`CLAUDE.md`).

## 2. Where UnityLAN's NAT traversal already is

Not naïve pure-P2P. M5 already ships:

- **UPnP-IGD** port mapping (`nat.rs`) — reachable peers advertise a dialable endpoint.
- **Peer-observed reflexive** — a reachable peer reports each co-member's last-seen source
  `ip:port` (`peer_endpoints()`), so we learn reflexives **without a STUN server** (boringtun
  owns the WG socket → no side-socket STUN). Symmetric-correct (per-peer mapping).
- **Coordinator-mediated cone-NAT punch** — the simultaneous long-poll wake *is* the punch sync;
  both sides dial each other's reflexive at once (`nat-test.sh`).
- **Diagnostics** — `classify_reach`: `Direct` / `Punching` / `Unreachable`.

Open hole = the acknowledged tail: **both ends symmetric / CGNAT / UDP-blocked.** `roadmap.md`
§7.2 marks relay a v1 non-goal; those peers render `Unreachable`. Every product here closes this
with a relay.

## 3. The WG-socket problem, and the four ways the field solves it

Plain WireGuard owns its UDP socket and does no NAT discovery — if a peer is behind NAT with no
forwarded port, **WireGuard just doesn't connect**. So every WG mesh has to answer: *how do I
discover reflexive endpoints and punch/relay, given WG owns the socket?* Four answers:

| # | Architecture | Who | Socket approach | Kernel WG? | Cost |
|---|---|---|---|---|---|
| 1 | **In-socket multiplex** (magicsock) | Tailscale | STUN + DISCO multiplexed *onto* the WG socket | ❌ userspace-only | reimplement traversal; no kernel fast-path |
| 2 | **Side-socket ICE + handoff/proxy** | NetBird | separate ICE agent; hand endpoint to WG (direct) or userspace-proxy WG over it (relay) | ✅ **yes** | proxy hop on relay; fragile handoff seam |
| 3 | **Public hub/gateway** (no punch) | Defguard | clients dial a public gateway; no P2P traversal | ✅ yes | gateway on data path; not real mesh |
| 4 | **Own protocol, own socket** | ZeroTier, Nebula | custom (non-WG) transport → full socket control | n/a | rewrite crypto/transport; lose WG ecosystem |

**Tailscale (1).** wireguard-go userspace on *all* platforms → owns the socket everywhere →
multiplexes STUN + DISCO on it (they're distinguishable: STUN magic cookie `0x2112A442`, WG
msg-type byte 1–4). Relay = **DERP** over HTTPS:443 (the port firewalls always allow), ciphertext
only. Cost: userspace everywhere, no kernel fast-path — a deliberate trade.

**NetBird (2).** Full ICE agent (`pion/ice`) on a *separate* socket: STUN for candidates,
WebSocket Signal to swap them, Coturn/WS relay as TURN fallback. On success it *"updates the
WireGuard peer endpoint to the remote connection address"* so **kernel WG** talks direct; relayed
peers get a **userspace proxy** bridging WG↔relay. Traversal lives entirely *outside* the WG
socket → works with kernel **and** userspace WG. Cost is the seam: roaming/sleep drops back to
relay (issue #2507), kernel sent-counter overflow on P2P handshake (#6054), and relayed traffic
eats a userspace hop even under kernel WG.

**Defguard (3).** Sidesteps traversal — hub-and-spoke through a **public Gateway** everyone dials.
No client↔client punch. Uses `defguard_wireguard_rs` (kernel netlink / wg-nt / userspace
boringtun — *the same lib we use*). Simplest, but the Gateway is on the data path = not
decentralized.

**Nebula (4) — architecturally almost identical to UnityLAN.** Custom Noise protocol owns its
socket. A **lighthouse** learns each host's NATed `ip:port`, hands the candidate list to an
initiating peer, nudges the target, both punch; falls back to **relay through a lighthouse** for
CGNAT. We independently rebuilt this pattern (see §5), minus the relay.

**ZeroTier (4).** Custom L2 protocol, own socket, "lazy" stateless punch, relay via planet/moon
roots. Symmetric-both → roots dominate.

**Reframe that matters:** the choice is *not* "magicsock (best traversal, userspace-only) vs weak
traversal." NetBird's option 2 gets full ICE + relay **while keeping kernel WG** — traversal on a
side socket, WG pointed at the negotiated endpoint or a local proxy. That breaks the false binary
and shapes our decision (§6).

## 4. Userspace vs kernel WireGuard

| Axis | Kernel WG (netlink / wg-nt) | Userspace WG (boringtun) |
|---|---|---|
| Throughput | Multi-Gbps, near line-rate | Fraction; single-core ceiling (~hundreds Mbps–~1-2 Gbps) |
| CPU / packet | Low — in-kernel crypto, no copies | High — every packet crosses kernel↔userspace |
| Latency + jitter | Lower, steadier | Extra hop + scheduler jitter |
| **Socket ownership** | kernel hides it → **no magicsock** | you own it → STUN/DISCO multiplex possible |
| Portability | per-OS driver; **macOS/iOS/Android: none** | one portable codebase, any OS with a TUN |
| Deploy | needs module/driver present | just needs TUN access |
| Observability | only uapi/netlink exposes (endpoints, handshakes, counters) | full — every packet |
| Attack surface | ring-0 (bug = kernel), tiny audited code | process-contained, memory-safe Rust, larger TCB |

Both still need a kernel **TUN NIC** (Wintun/utun/tun) — packet plumbing, separate from crypto.

**Platform matrix — the decisive axis:**

| Platform | Kernel WG | Userspace |
|---|---|---|
| Linux | ✅ | ✅ |
| Windows | ✅ (wg-nt) | ✅ (needs Wintun) |
| **macOS** | ❌ none | ✅ |
| **iOS** | ❌ none | ✅ (NetworkExtension) |
| **Android** | ❌ none | ✅ (VpnService) |

macOS and mobile have **no usable kernel WG** — the OS hands packets to userspace. So **userspace
is the only backend spanning the full target matrix**; kernel only ever covers Linux+Windows.
Userspace must therefore be first-class regardless. Kernel's sole advantage — throughput — is
**irrelevant to UnityLAN's workload** (gaming vLANs, gameserver sharing, light file transfer:
latency-sensitive, not throughput-bound; the userspace ceiling is ample). Kernel's only unique
*cost* is that it forecloses magicsock.

## 5. Where UnityLAN sits today — a lighthouse clone

Closer to **Nebula's lighthouse model than to NetBird's ICE model**:

| | Nebula lighthouse | UnityLAN |
|---|---|---|
| Learn reflexive | STUN-self (owns socket) | **peer-observed** (can't own WG socket) |
| Distribute candidate | lighthouse → peers | coordinator `Seed.punch` → peers |
| Punch sync | both nudged | **simultaneous long-poll wake** |
| Relay fallback | ✅ through lighthouse | ❌ **none (v1)** |

We rebuilt the lighthouse pattern independently. The one missing rung — **relay** — is the same
rung everyone else has.

## 6. Decision — data-plane direction

**Chosen: userspace-primary, side-socket ICE via mature crates, relay first, in-socket magicsock
deferred.** Rationale below; tasks in `roadmap.md`.

### 6.1 Userspace-primary
Userspace is the only backend covering Linux/Windows/macOS/iOS/Android (§4), and the workload
doesn't need kernel throughput. So userspace is the target; **kernel becomes an optional per-OS
perf boost, not the goal** — and can be dropped entirely (Tailscale-style, one data plane to
maintain) if the second-backend cost outweighs the throughput it buys. Owning the socket also
keeps the magicsock door open (§6.4). Cost to name honestly: giving up the kernel fast-path caps
single-core throughput — **acceptable for gaming/light-file, not for a future 10GbE use case.**

### 6.2 Side-socket ICE via crates (the near-term traversal upgrade)
Adopt NetBird's option 2, in Rust, **reusing mature libraries** instead of hand-rolling: an ICE
agent (`webrtc-rs` `ice`/`stun`/`turn`, or `str0m`) on a socket beside boringtun. This gets, for
little code:
- **STUN reflexive** — fixes the *bootstrap* case our peer-observed method can't (a lone or
  all-NAT'd mesh has no online observer, so today it can't even start a punch; STUN needs no peer).
- **host/srflx candidates + real ICE** — replaces the ad-hoc punch.
- **TURN relay** — the fallback (see §6.3).

Keep the **long-poll as the ICE signal channel** (swap candidates in the register/refresh
snapshot) — no separate Signal server, stays coordinator-mediated and decentralization-consistent.
Userspace-only (owns the socket); kernel backends, if kept, retain punch + relay.

### 6.3 Relay first (backend-agnostic, required regardless)
Relay is **#1** and lands *before* the ICE rework, because it closes the actual gap (symmetric /
CGNAT / UDP-blocked) and is **backend-agnostic** — a relay is just an endpoint WG dials, so it
works on today's kernel(win)+userspace(unix) split with no data-plane rewrite. Relay forwards WG
**ciphertext** only → e2e intact, trust model untouched. **Userspace does not remove the relay
need** — magicsock still can't cross symmetric-both-ends; *Tailscale still runs DERP*. Decentral
twist (fits our north star): any online peer with a public endpoint is a candidate relay, advertised
in its attestation; the coordinator pairs relay↔client the same way it pairs a punch, staying off
the data path. See `roadmap.md` M5.4.

### 6.4 In-socket magicsock (deferred)
Multiplexing STUN/DISCO onto the WG socket (Tailscale-style). Bespoke, the larger bet. Only worth
it if the side-socket **residual gap** (§6.5) bites. Requires driving boringtun `Tunn` on our own
`Bind` (dropping `defguard_wireguard_rs`'s device layer) and, on Windows, adding **Wintun**
(defguard's userspace path is unix-only). Deferred, not abandoned — §6.1 keeps it reachable.

### 6.5 Residual gap after side-socket ICE (the ~10% magicsock would close)
Side-socket ICE + relay is a clear step up (adds STUN bootstrap + a real relay), but leaves a
residual that only **in-socket** integration removes:

1. **Efficient direct paths through restricted-cone NAT.** ICE discovers the working path on *its*
   socket; boringtun's WG socket has a *different* NAT mapping. Handing off to a truly-direct WG
   path works cleanly only for endpoint-independent (**full-cone**) NAT. Port/address-restricted
   and punchable-symmetric cases must instead take a **userspace proxy hop** (ICE socket forwards
   to WG locally) or fall to **relay** — extra latency / a relay dependency for peers that
   magicsock would make *directly* connected (STUN/disco on the WG socket → discovered mapping *is*
   the WG mapping).
2. **UDP-hostile networks.** If a network blocks outbound UDP (some corporate/guest/hotel Wi-Fi),
   UDP STUN+TURN die. Mitigation is relay over **TCP/TLS:443** (TURN-over-TLS, or a DERP-style
   HTTPS relay). Achievable with the crates + a :443 relay, but always *relayed* there (never
   direct) — same as DERP. Gap = we must operate a :443 relay; magicsock packages this more
   seamlessly (single socket, HTTPS framing).
3. **Handoff-seam fragility.** The two-socket decoupling has operational edge cases — NetBird's
   roaming/sleep re-relay (#2507) and kernel sent-counter overflow (#6054). In-socket integration
   removes the seam.

Net: **side-socket ICE gets ~90%** (all cone NATs directly, symmetric/CGNAT via relay, bootstrap
via STUN). The residual ~10% is *efficiency* (restricted-cone via proxy/relay instead of direct)
and *UDP-blocked-network packaging* — the case for magicsock later, not now.

## 7. Other borrowable ideas (not data-plane)

- **Tailnet-lock co-signature (Tailscale).** Our model pins *one* coordinator Ed25519 anchor = a
  single forge point (compromise it → sign any attestation → inject a rogue peer). Tailnet lock
  requires node keys be **co-signed by trusted nodes**, so a hacked control server alone can't add
  a machine. Borrow: optional admin/peer co-signature on a *new* device's attestation for
  high-trust meshes. Fail-closed on coordinator compromise. Aligns with secure-by-default.
- **Edge front (Defguard).** Their Core/Gateway/**Edge** split keeps the management plane (signing
  key + secrets) off the public listener. Our coordinator *is* the public listener and holds the
  signing key + Discord token. An Edge-style front shrinks attack surface on the one key that
  matters. Ops-hardening option, not a default.
- **MFA framing (Defguard).** They re-auth per WG connection. Our **short-lived attestations
  already give this** (device keeps re-proving; expiry ≈ TTL). We're ahead — borrow the *framing*
  ("continuous re-authorization") + an optional step-up (fresh Discord presence/MFA) for sensitive
  networks.
- **Finer ACLs on roles (Tailscale/NetBird).** Discord-role-as-network is our base and stays. Layer
  **port/service scoping** and **device posture checks** on top (extra signed attestation fields,
  evaluated peer-side → no coordinator hot-path cost).
- **Enrollment UX (Defguard/NetBird).** Both invest in one-command/token/QR join. Ours is
  Discord-OAuth; borrow the polish.

## 8. Strategic note — Headscale (no action)

Headscale's leverage is **reusing the Tailscale client** — instant mature multi-OS + mobile client,
zero client-dev cost. We build our own engine+gui for full control (Discord integration, our trust
model) at the cost of **owning client maintenance forever** across Linux/Windows/macOS/mobile. No
action — the userspace-primary direction (§6.1) is what makes that mobile/macOS burden tractable.

## 9. Action list → roadmap

1. **Relay fallback** — `roadmap.md` **M5.4** (near-term, backend-agnostic, closes the real gap).
2. **Side-socket ICE via crates** — **M5.5** (STUN bootstrap + ICE + TURN, long-poll signal).
3. **Data-plane direction note** — **M8** (kernel demoted to optional; Linux netlink deferred).
4. **In-socket magicsock** — Post-GA (closes §6.5 residual; needs own-socket + Windows Wintun).
5. **Userspace Windows (Wintun) + macOS/mobile clients** — Post-GA (unlocked by §6.1).
6. Non-data-plane borrows (§7) — tracked separately as they surface.

## Sources

- Tailscale / NetBird / Headscale — <https://www.pkgpulse.com/guides/tailscale-vs-netbird-vs-headscale-mesh-vpn-2026>
- NetBird how-it-works / connection mgmt — <https://netbirdio-netbird-9.mintlify.app/architecture/how-it-works>,
  <https://deepwiki.com/netbirdio/netbird/5.3-peer-connection-management>; seam bugs
  <https://github.com/netbirdio/netbird/issues/2507>, <https://github.com/netbirdio/netbird/issues/6054>
- Defguard — <https://defguard.net/>, <https://docs.defguard.net/about/about-defguard>
- Nebula / ZeroTier NAT — <https://www.defined.net/blog/nebula-vs-wireguard/>,
  <https://www.zerotier.com/blog/the-state-of-nat-traversal/>
- Overlay mesh deep-dive 2026 — <https://www.youngju.dev/blog/culture/2026-05-16-overlay-vpn-mesh-networking-2026-tailscale-headscale-zerotier-nebula-wireguard-netbird-deep-dive.en>
