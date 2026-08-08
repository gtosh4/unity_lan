# UnityLAN — Positioning & Competitive Set

Who UnityLAN is for, what people compare it to, and where it wins and loses. **Two user segments
with different competitors, different demands, and a genuine disagreement about the client** (§5).

> Scope: this doc is about *users and alternatives*. Prior art on **how other meshes solve NAT
> traversal, trust and the WG-socket problem** is `prior-art.md`, and the data-plane decision lives
> there (§6). Concepts are in `design.md`; work is in `roadmap.md`.

> Status: **analysis, one open decision** (§5). Nothing here is committed work.

## 1. The two segments

`README.md` already names both. They are worth separating because *nothing in their competitive
sets overlaps*.

| | **Segment 1 — p2p gaming** | **Segment 2 — homelab sharing** |
|---|---|---|
| The ask | "Set up a Minecraft/Valheim server and let my friends join" | "Share Jellyfin / Audiobookshelf / a NAS with my community" |
| Why a mesh at all | the game has **no Steam lobby or invite flow** — joining means an address | the service is private and should stay off the public internet |
| Who installs | the host, and each friend | the host; the friend ideally installs **nothing** |
| Traffic | latency-sensitive, low volume | throughput-ish, bursty, mostly HTTP |
| Lifetime | a session, a weekend | months; set-and-forget |
| Failure feels like | lag, or an empty server browser | a cert warning, or "it won't load on the TV" |

Both reduce to one sentence — *let the people in my Discord reach a box I run* — which is why one
mechanism serves both (§4). But the buyer's checklist differs enough that a feature can be decisive
for one and irrelevant to the other.

## 2. Segment 1 — p2p gaming

### 2.1 Competitive set

Not the mesh-VPN field. This segment's search is "Hamachi alternative", and the listicles that
answer it rank a different cast:

| | What it is | GitHub | Friction for *the friend* |
|---|---|---|---|
| **ZeroTier** | L2 overlay — broadcast/multicast work | 17.0k | install + join a network ID |
| **EasyTier** | decentralized L3 mesh, Rust; large CN gaming following | 13.0k | install + shared network name/secret |
| **Radmin VPN** | free, **Windows-only**, 100 Mbps cap | closed | install |
| **Hamachi** | the legacy default; 5-peer free cap | closed | install + LogMeIn account |
| **playit.gg** | **a tunnel, not a VPN** — host runs an agent, friend gets an address | closed | **nothing** |
| **Tailscale** | general mesh; shows up via brand recognition | 34.9k | install + SSO login |

Pangolin does **not** appear in this segment's results. NetBird barely does.

### 2.2 What the segment demands

1. **Near-zero friction for someone who didn't ask for a VPN.** They want to play; the network is
   overhead. Every extra step loses people.
2. **Low latency** — direct P2P, no relay hop.
3. **Discoverability**: either the in-game server browser populates, or the address is memorable.

### 2.3 Where we win

- **Names, not addresses.** `mc.alice.unity.internal` beats pasting a Hamachi `25.x.x.x` into
  Discord.
- **No second credential.** Every competitor makes the host share a network ID + secret, which then
  lives in a Discord message forever and never rotates. Our credential *is* the role they already
  hold, and it **revokes itself** when they leave the server or lose the role. No competitor in this
  table can do that.
- **Direct P2P.** No 100 Mbps cap (Radmin), no peer cap (Hamachi), no relay by default.
- **Headless host support** — a dedicated game-server box enrolls with a one-time key, no Discord
  client and no desktop on it (`docs/headless.md`).

### 2.4 Where we lose

- **Empty server browsers.** ZeroTier is L2, so LAN auto-discovery works; we are L3 and it does not.
  `roadmap.md` ("Trusted networks + LAN game discovery") costs the fix honestly: firewall relaxation
  is ~1 unit and unlocks direct-connect-by-IP only; the broadcast/multicast relay is 5–10× that plus
  **Npcap or a signed WFP callout driver on Windows**, and puts the engine in the packet path for
  the first time.

  **The segment definition argues against paying it.** "Games without Steam lobbies" — Minecraft
  Java, Terraria, Factorio, Valheim — are overwhelmingly **direct-connect-by-address**. L3 plus a
  good hostname is already the whole feature for them. The broadcast relay buys the Warcraft
  III–era auto-discovery tail specifically, which is narrower than the segment.
- **playit.gg needs nothing on the friend's machine.** For "friends join my MC server" that is a
  genuinely lower-friction answer than ours. It costs the friend nothing and the host a third party
  on the data path — a trade many will take. See §5.
- **Brand recognition.** Hamachi and ZeroTier are the reflex answers; we are unknown.

## 3. Segment 2 — homelab sharing

### 3.1 Competitive set

| | What it is | GitHub | Friend installs |
|---|---|---|---|
| **Pangolin** | identity-aware tunneled reverse proxy; VPS + Traefik | 22.0k | **nothing — a browser** |
| **Cloudflare Tunnel** | vendor tunnel + Access policies | closed | **nothing** |
| **Tailscale Funnel / serve** | publish a tailnet service to the public web | 34.9k | nothing (Funnel) / client (serve) |
| **Twingate** | zero-trust access, freemium | closed | client |
| **Firezone** | self-hosted WireGuard zero-trust w/ policy | 9.0k | client |
| **Caddy/Traefik + Authelia** | roll it yourself, publicly exposed | — | nothing |

### 3.2 What the segment demands

1. **Valid HTTPS.** A cert warning ends the conversation with a non-technical friend.
2. **Works in a browser.**
3. **Works on devices that cannot run a VPN client** — Android TV, Roku, Chromecast, a guest's iPad.
4. **Per-service access control**, not "you're on the network now".

### 3.3 Where we win

- **Real certificates, no config.** `https://jellyfin.alice.mesh.unitylan.com` opens with no warning
  page via ACME DNS-01 (`engine/src/cert.rs`), and **Jellyfin needs no TLS setup of its own** — the
  engine's unprivileged proxy terminates it.
- **Nothing on the public internet.** Cloudflare Tunnel and Pangolin both publish to the open web
  and then gate it; we never publish at all. Different security posture, and the better one for a
  private library.
- **No third party on the data path.** Cloudflare sees the bytes. A Pangolin VPS sees the bytes. We
  don't have one.
- **The ACL maintains itself.** The community *is* a Discord server. Nobody curates a user list, and
  removal from Discord is removal from the mesh.
- **No VPS to rent.** Pangolin's floor is a public-IP VPS. Ours is a coordinator that can be small,
  shared, or someone else's.

### 3.4 Where we lose

Two things, and the second is the harder one:

1. **Clientless access.** Pangolin and Cloudflare Tunnel let a friend *click a link*. We require the
   engine installed and enrolled. For "share my media library with 20 people in Discord", that is a
   materially higher bar.
2. **The TV problem.** Jellyfin's and Audiobookshelf's highest-value clients are Android TV, Roku,
   Chromecast, a handed-over iPad. Most cannot run a privileged mesh daemon at all. This is not
   friction — it is a hard exclusion, and it lands on exactly this segment's flagship apps.

Also: per-service ACLs are currently **network-level** (= role-level). Sharing *one* service with a
narrower group means creating another Discord role and another network.

## 4. What only UnityLAN does

No competitor spans both segments:

- ZeroTier, EasyTier, Radmin, Hamachi — no HTTPS service publishing, no real certs, no service
  discovery beyond an IP.
- Pangolin, Cloudflare Tunnel, Twingate — no low-latency P2P game traffic; the hub is on the path.
- Tailscale spans the most, but identity is SSO/vendor-tied and there is no "my community" primitive.

**The line:** *your Discord server already defines who's in your group — UnityLAN turns that into a
LAN, for game servers and self-hosted services alike, with nothing exposed publicly and no bytes
through anyone else's box.*

That claim is stronger than any single-segment feature comparison, and it is the one to lead with.

## 5. Open decision — the client fork

The segments disagree about the client, and the disagreement is real:

- Segment 1's friend **will install something**. They install mods.
- Segment 2's friend wants a URL, and on a TV **cannot install anything**.

If segment 2 is a first-class goal, the largest product gap is a **clientless path** — which is
precisely Pangolin's core competence.

`prior-art.md` §9.3 currently files that under "don't copy". That judgment was made against browser
RDP/VNC and PAM — enterprise surface we should stay away from. A **minimal guest gateway** (one
opted-in mesh device terminates TLS for non-member guests on a named service) is a much smaller
thing than what was dismissed, and it is what segment 2 actually needs.

It still costs the north star: a gateway is **on the data path**, and "the coordinator carries no
traffic" does not automatically extend to "no member ever proxies for a non-member". Arguments both
ways:

- **For.** Unblocks the TV problem, which no amount of client polish can solve. The gateway is a
  *peer*, not the coordinator — the same shape as the embedded TURN relay, which we already accept.
  Opt-in per device and per service.
- **Against.** It is a second access model to secure, document and support. Guests are unattested by
  definition, so it needs its own authn story (link + token? Discord OAuth without enrolment?). It
  invites scope creep straight toward what §9.3 rejects.

**Not decided.** But it should be decided deliberately, because it competes for effort with the
broadcast relay (§2.4) — and the two serve different segments. Picking both is picking neither.

## 6. Traction snapshot

Stars are a weak proxy for adoption, useful only for calibration. Fetched **2026-08-07**:

| Project | Stars | Created | Note |
|---|---|---|---|
| Headscale | 42,608 | 2020-06 | |
| Tailscale | 34,928 | 2020-01 | |
| NetBird | 28,137 | 2021-04 | |
| **Pangolin** | 22,049 | 2024-09 | **fastest growth in the field** — 12.6k at its YC launch ~5 months in |
| Nebula | 17,591 | 2019-11 | |
| ZeroTier | 16,988 | 2013-04 | 13 years to reach what Pangolin did in under 2 |
| **EasyTier** | 13,018 | 2023-09 | closest architectural + audience match to us |
| Netmaker | 11,739 | 2021-03 | |
| Firezone | 8,992 | 2020-04 | |
| OpenZiti | 4,335 | 2019-11 | |
| Defguard | 2,798 | 2022-10 | |

Two things to read from this. **Pangolin's growth is the story** — the "expose my self-hosted stuff"
problem has more demand right now than the mesh-VPN problem, which is segment 2's pull. And
**EasyTier is the closest thing to us that exists**: decentralized, Rust, L3, gaming-community
adoption. It is further along on decentralization (no coordinator at all) and far behind on
identity — a shared network name and secret, with no roles, no attestations, no revocation. That
gap is our differentiator stated in someone else's terms.

## 7. What this implies for the roadmap

Ordered by how much each moves a segment, not by effort:

1. **Decide the client fork (§5)** before spending on either branch — it is the gate on 2 and 3.
2. **Guest gateway** (segment 2) — unblocks the TV problem, the one hard exclusion we have.
3. **Broadcast/multicast relay** (segment 1) — narrow tail; explicitly *lower* than its roadmap
   position implies, given §2.4.
4. **Per-service ACLs below role granularity** (segment 2) — removes "make another Discord role to
   share one thing".
5. **Service health checks → Discord webhook alerts** (both) — cheap, and identity is already there.
   Detail in `prior-art.md` §9.2.
6. **Onboarding polish for the non-technical friend** (segment 1) — the whole segment is a friction
   contest and we are unknown.

## Sources

- Pangolin — <https://github.com/fosrl/pangolin>, <https://docs.pangolin.net/>,
  YC launch <https://www.ycombinator.com/launches/O0B-pangolin-open-source-secure-gateway-to-private-networks>
- EasyTier — <https://github.com/EasyTier/EasyTier>
- Virtual-LAN-gaming category (the "Hamachi alternative" search) —
  <https://sysprobs.com/hamachi-alternatives>, <https://alternativeto.net/software/zerotier-one/?tag=virtual-lan>
- Self-hosted VPN roundups 2026 — <https://dev.to/moksh/self-hosted-vpn-in-2026-wireguard-headscale-netbird-and-more-compared-5fln>
- Star counts — GitHub API, 2026-08-07
