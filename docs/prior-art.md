# UnityLAN — Prior Art & Data-Plane Direction

How UnityLAN compares to existing WireGuard (and non-WG) mesh VPNs **at the level of mechanism** —
NAT traversal, trust root, socket ownership, relay — what to borrow, and the resulting **data-plane
direction** (userspace-primary + side-socket ICE + relay). Read `design.md` for our own model first;
tasks live in `roadmap.md` (M5.4/M5.5, M8 note, Post-GA).

> Scope: engineering prior art. **Who these products are *for*, what users compare us to, and where
> we win or lose a buyer** is `positioning.md` — including the two user segments (p2p gaming vs
> homelab sharing), which have entirely separate competitive sets.

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
| **Netmaker** | Self-host server + `netclient` | server-managed ACLs | STUN-ish + `netclient` punch | server/egress node | **kernel** (netlink) | Own |
| **Firezone** | Self-host portal + gateways | IdP/OIDC + policy engine | via gateways | **gateway hub** | userspace (Rust) | Own |
| **EasyTier** ‡ | **none — fully decentralized** | shared network name + secret | UDP punch, NAT4↔NAT4 | any peer node | own transport, **optional** WG | Own |
| **Pangolin** † | Self-host VPS **or** vendor cloud | IdP/OIDC + built-in users, **per-resource RBAC** | punch to exit node, probes **in-socket** | **the hub *is* the default path** | userspace (wg-go) | `newt` connector + `olm` client + **browser** |
| **UnityLAN** | Self-host, **control-plane-only** | **Discord roles → signed attestations** | UPnP + peer-observed reflexive + cone punch | **none (v1)** | userspace (unix) / kernel (win) | Own (engine+gui) |

† Pangolin is the one row that breaks the family shape: its control plane **carries traffic** by
design (reverse proxy through the VPS), and P2P is a newer client feature rather than the
foundation. Implementation notes in §9.

The Netmaker and Firezone rows are from public documentation, not source, and are thinner than the
rest — added for coverage after both turned up repeatedly in 2026 self-hosted-VPN roundups. Verify
before relying on either.

‡ EasyTier (Rust/Tokio, LGPL-3.0) is the **closest architectural match to UnityLAN** in the field
and goes further on decentralization — no coordinator of any kind; peers bootstrap off each other
or off shared public nodes holding the same network name + secret. It pays for that in identity:
a shared secret, so no roles, no per-device revocation, no attestations. Notable transport choice —
**KCP/QUIC for high-packet-loss links** alongside TCP/UDP/WS, which is a deliberate bet on the
latency-sensitive gaming case. Read at documentation depth only, not source; treat the row as
provisional. Audience overlap is covered in `positioning.md` §6.

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
| 1 | **In-socket multiplex** (magicsock) | Tailscale, **Pangolin** (partial) | STUN + DISCO multiplexed *onto* the WG socket | ❌ userspace-only | reimplement traversal; no kernel fast-path |
| 2 | **Side-socket ICE + handoff/proxy** | NetBird | separate ICE agent; hand endpoint to WG (direct) or userspace-proxy WG over it (relay) | ✅ **yes** | proxy hop on relay; fragile handoff seam |
| 3 | **Public hub/gateway** (no punch) | Defguard, **Pangolin** (default path) | clients dial a public gateway; no P2P traversal | ✅ yes | gateway on data path; not real mesh |
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

**Pangolin (3 → 1).** Ships both. The default path is a hub (3): connectors dial the VPS, traffic
crosses it. But its client stack takes option **1** for the P2P case — `newt/bind/shared_bind.go`
is a wireguard-go `conn.Bind` that carries hole punch, path-liveness probes, and relay injection on
the **WireGuard socket itself**. It multiplexes only its own magic packets (no STUN), so it is a
partial magicsock; the significance for us is §6.4.

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

**Evidence it is smaller than it looks (2026-08).** Pangolin's `newt/bind/shared_bind.go` is a
complete, production custom `Bind` in ~840 lines of Go: magic-packet intercept before the WG
device, packet injection from a netstack, refcounting, and a `Rebind()` that swaps the socket on
network change (Wi-Fi → cellular) while parking the receive goroutines on a condvar instead of
tearing the device down. It does *not* multiplex STUN, so it is not full magicsock — but it shows
the socket-ownership rewrite is a bounded task, not a research project. Two things it buys that
§6.5 lists as residual: the punched NAT mapping **is** the WG mapping (no restricted-cone proxy
hop), and there is exactly **one** UDP port to open in the host firewall.

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

- **Tailnet-lock co-signature (Tailscale).** Our model pins one coordinator Ed25519 anchor per guild;
  each is a forge point within that guild (compromise it → sign any guild attestation → inject a
  rogue peer there). Tailnet lock
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

## 9. Pangolin — implementation notes

`fosrl/pangolin` (control plane) + `fosrl/newt` (connector) + `fosrl/gerbil` (WG interface manager /
relay / SNI proxy), read at source 2026-08-07. Architecturally it is a **zero-trust access
gateway**: a VPS runs the control plane plus Traefik, `newt` connectors dial *outbound* from private
networks, and access is via browser or client. The hub is on the data path by default; P2P is a
newer client feature, not the foundation.

That product shape — who it serves, where a user picks it over us — is `positioning.md` §3. What
follows is only the **mechanism**, which is where it is worth reading: its P2P client stack solves
the same problems ours does, and solves two of them differently enough to matter (§9.2.1, §9.4).

### 9.1 Where we're ahead

- **Traversal.** We run a real ICE agent (`webrtc-ice`) with host/srflx/relay candidates and
  connectivity checks; Pangolin punches to a fixed exit node and probes liveness with magic
  packets. No ICE.
- **Relay auth.** Ours is TURN long-term-credential HMAC with a concurrent-allocation cap
  (`engine/src/relay.rs`). Gerbil arrived at its own cap (8192 sockets, `GERBIL_MAX_UDP_CONNECTIONS`)
  only after two dated production outages from fd/ephemeral-port exhaustion under peer churn — a
  useful confirmation that the cap we already ship is load-bearing, not defensive clutter.
- **Update trust.** We verify a signed release manifest. `newt/updates/selfupdate.go` checks a
  server-supplied SHA-256 and **skips verification entirely when the server omits it**.
- **Punch crypto.** Our beacon probe/ack is nonce + MAC over the peers' WG-derived shared secret,
  so it is replay-rejecting. Their punch payload is ECIES to the exit node's static key with no
  replay guard, and takes the AEAD nonce from `golang.org/x/exp/rand` — a non-cryptographic PRNG,
  saved only by the fresh ephemeral key per message.
- **Control plane.** Their WebSocket fan-out is an in-process `connectedClients` map keyed by
  `NODE_ID`; multi-node broadcast is unsolved. Our watch-version long-poll does the same job with
  fewer moving parts. **Not a borrow.**

### 9.2 Worth borrowing

1. **One socket for WireGuard, punch and probes** (`newt/bind/shared_bind.go`) — see §6.4. Two
   concrete wins for us: the firewall surface collapses to a single UDP port (the Windows rule that
   never opened 51830 could not have existed), and the punched NAT mapping becomes the mapping WG
   uses — today we punch three separate bindings (WG 51820, beacon 51821, ICE on its own socket),
   and on port-restricted/symmetric NAT a mapping validated on the ICE socket says nothing about
   the WG socket. Userspace/Windows backends only; kernel WG never hands over the socket.
2. **Ranked local-endpoint candidates** (`newt/network/localendpoints.go`) — see §9.4, which is
   where the design work is. The liftable part here is the heuristic itself: enumerate interfaces,
   score them physical (0) / unknown (10) / virtual (20) by name pattern (docker, veth, virbr,
   `br-`, utun, tailscale…), drop loopback and link-local, offer the list in preference order.
3. **Engine-side metrics.** Gerbil exports Prometheus/OTel counters for **handshake success and
   failure**, per-peer bandwidth, relay sessions, route-cache hit ratio. Our coordinator has
   `/metrics`; the engine has none. Every flap investigation so far has been reconstructed from
   logs after the fact.
4. **Punch cadence.** Exponential backoff 1 s → 60 s, reset to the floor on a membership change,
   plus a settable interval pair for a low-power mode. Matters once laptops and phones are peers.

Two product-level borrows — **alert rules** (`server/routers/alertRule`: `site_offline` /
`health_check_unhealthy` events, per-rule `cooldownSeconds`, recipients addressed **by role**, plus
webhook actions) and **blueprints** (`server/routers/blueprints`: declarative YAML/JSON applied to
the control plane) — are features, not mechanism. Rationale and priority in `positioning.md` §7.

### 9.3 Don't copy

The checksum-optional self-update path is a straight downgrade from a signed manifest.

The browser gateway, in-browser RDP/VNC and PAM are an enterprise surface that would pull us away
from "a LAN for a community" — **but note the narrower question this does not settle.**
`positioning.md` §5 asks whether a *minimal guest gateway* (one opted-in mesh device terminating
TLS for a non-member) is worth building for the homelab-sharing segment, where devices like a TV or
a Roku cannot run our engine at all. That is a much smaller thing than what is rejected here, and
it is open.

### 9.4 Local-endpoint candidates — the gap, and an open privacy question

> Status: **not decided.** §9.4.3 is a question for a human, not a plan.

#### 9.4.1 What the beacon can't reach

`beacon.rs` learns a peer's LAN address by *receiving a broadcast from it* — the datagram's
`src_ip` plus the advertised port. That is a strong property (only a host on your L2 segment can
deliver a broadcast to you: proof by receipt, not by address guessing) and it is what lets the
module advertise nothing private. It also binds the mechanism to **one broadcast domain**. Cases it
structurally cannot serve:

- **Cloud VPC** — AWS/GCP/Azure subnets don't forward broadcast at all. Two devices in the same
  subnet currently reach each other via their public reflexives, out the NAT gateway and back.
  Broadcast will never fix this; strongest case for the feature.
- **Routed home LAN** — wired `192.168.1.0/24` and Wi-Fi `192.168.2.0/24` behind one router (an AP
  in router mode), or any VLAN-segmented homelab (IoT / trusted / guest).
- **Campus/office networks** where two peers share routed infrastructure but not a segment.
- Partially, APs that drop or rate-limit multicast/broadcast forwarding while still routing unicast
  between stations. Full AP client isolation blocks both and stays out of reach.

#### 9.4.2 Mechanism: peer-direct, not coordinator-mediated

The obvious shape — seal candidates to each peer and ship them in the snapshot — is **wrong**. A
`Seed` is built once per device and handed to everyone sharing a network with it, so per-recipient
sealing means each device emits N blobs per refresh: N² on the long-poll path, the exact cost
`crates/coordinator/CLAUDE.md` exists to prevent.

Peer-direct is simpler and free. `p2p.rs` already runs request/response over the mesh `/32` —
*inside the tunnel* — so WireGuard already supplies the confidentiality and peer authentication the
sealing was for. It also matches when the feature is needed: the hairpin case **has** a tunnel, just
a flaky one. This upgrades a working path; it does not bootstrap from nothing (that stays the
coordinator's punch/ICE job).

Sketch, small because it reuses the existing state machine:

1. New `p2p.rs` request kind: "your local candidates". Response = ranked `Vec<SocketAddr>`, capped
   at ~4. Unknown-kind must degrade to "peer doesn't support this, stop asking" — both sides
   upgrade independently.
2. Build the list with the §9.2.2 interface heuristic, excluding the mesh interface, loopback and
   link-local.
3. Feed results into the existing `candidates` map with a source tag.
4. Adoption path **unchanged**: `Probing` → probe/ack (nonce + MAC over the WG-derived shared
   secret) → `Trying` → `Active`, with `PROBE_BACKOFF` / `VERIFY_GRACE` / `STALE_GRACE` as they are.

Step 4 is the point: the entire security argument in `beacon.rs`'s module header carries over
untouched.

**New exposure to handle.** A broadcast-learned candidate is proof by receipt; a peer-asserted one
is a *claim*. The peer names an address and we send an authenticated 39-byte UDP packet to it — a
weak scan/reflection primitive aimed at our own network. Adoption is still gated on a valid ack, so
a bogus address costs one unanswered probe, but the packet is sent. Accept **private ranges only**
(RFC1918 / ULA — a LAN candidate is private by definition; public addresses are the reflexive
path's job), reject loopback / multicast / broadcast, cap the list, lean on the existing backoff.

#### 9.4.3 Open question: we already leak this to the coordinator

`beacon.rs`'s header justifies advertising no LAN address as "a privacy choice: LAN addresses would
leak internal topology to the coordinator and every peer." **That property does not currently
hold.** `ice.rs` builds its agent with `..Default::default()` (`AgentConfig`, no `candidate_types`
restriction), so `webrtc-ice` gathers **host** candidates — the module header says so itself
("gathers host + server-reflexive + relay"). Those are marshaled into `IceParams.candidates`
(`common/src/api.rs`) and reported to the coordinator, which relays them to the peer. A host
candidate carries the private interface address in the clear.

So for every peer running ICE, private LAN addresses already reach the coordinator today. The
beacon is paying a real capability cost (§9.4.1) for a guarantee the ICE path doesn't keep. The
question is therefore not *may we reveal LAN addresses* but **to whom, and consistently**:

- **Peer-only (fail-closed).** Restrict ICE gathering to srflx + relay via `candidate_types`, and
  carry host candidates peer-direct per §9.4.2. Coordinator stays blind; the beacon's stated
  property becomes true again. Costs ICE the host-candidate pair type — which for same-LAN peers is
  exactly what §9.4.2 replaces, so the loss is small.
- **Accept the exposure.** Let host candidates flow through the coordinator as ICE already does,
  drop the beacon's privacy claim, and reuse `IceParams` for non-ICE peers too. Cheaper, but
  concedes topology to the coordinator permanently.

Either is defensible; they must not both be half-true, which is the state today.

## 10. Action list → roadmap

1. **Relay fallback** — `roadmap.md` **M5.4** (near-term, backend-agnostic, closes the real gap).
2. **Side-socket ICE via crates** — **M5.5** (STUN bootstrap + ICE + TURN, long-poll signal).
3. **Data-plane direction note** — **M8** (kernel demoted to optional; Linux netlink deferred).
4. **In-socket magicsock** — Post-GA (closes §6.5 residual; needs own-socket + Windows Wintun).
   Scope evidence in §6.4; folds in the single-firewall-port and same-mapping wins of §9.2.1.
5. **Userspace Windows (Wintun) + macOS/mobile clients** — Post-GA (unlocked by §6.1).
6. **Peer-direct local-endpoint candidates** (§9.4) — extends the LAN beacon past one L2 segment
   (cloud VPC, routed home LAN, VLANs). Blocked on the §9.4.3 privacy decision first: ICE already
   ships host candidates to the coordinator, so the beacon's stated property is not currently true.
7. **Engine `/metrics` + handshake counters** (§9.2.3) — makes flap diagnosis a dashboard read.
8. Non-data-plane borrows (§7) — tracked separately as they surface.

Product-level items driven by user segment rather than by mechanism — guest gateway, broadcast
relay priority, per-service ACLs, health-check alerts — are listed in `positioning.md` §7.

## Sources

- Tailscale / NetBird / Headscale — <https://www.pkgpulse.com/guides/tailscale-vs-netbird-vs-headscale-mesh-vpn-2026>
- NetBird how-it-works / connection mgmt — <https://netbirdio-netbird-9.mintlify.app/architecture/how-it-works>,
  <https://deepwiki.com/netbirdio/netbird/5.3-peer-connection-management>; seam bugs
  <https://github.com/netbirdio/netbird/issues/2507>, <https://github.com/netbirdio/netbird/issues/6054>
- Defguard — <https://defguard.net/>, <https://docs.defguard.net/about/about-defguard>
- Nebula / ZeroTier NAT — <https://www.defined.net/blog/nebula-vs-wireguard/>,
  <https://www.zerotier.com/blog/the-state-of-nat-traversal/>
- Overlay mesh deep-dive 2026 — <https://www.youngju.dev/blog/culture/2026-05-16-overlay-vpn-mesh-networking-2026-tailscale-headscale-zerotier-nebula-wireguard-netbird-deep-dive.en>
- Pangolin (§9, read at source 2026-08-07) — <https://github.com/fosrl/pangolin>,
  <https://github.com/fosrl/newt>, <https://github.com/fosrl/gerbil>, <https://docs.pangolin.net/>
- EasyTier (§1, documentation depth only) — <https://github.com/EasyTier/EasyTier>
- Netmaker — <https://github.com/gravitl/netmaker>; Firezone — <https://github.com/firezone/firezone>
- Market/adoption comparison and traction numbers — `positioning.md`
