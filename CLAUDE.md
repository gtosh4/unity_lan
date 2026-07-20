# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

UnityLAN: a WireGuard mesh VPN whose membership is defined by **Discord roles** and enforced by a
self-hosted **coordinator** that issues short-lived Ed25519-signed **attestations**. Peers discover
each other through the coordinator (long-poll) and form **direct P2P WireGuard tunnels**. The
coordinator is a **control plane only** — it carries no traffic and holds no peer private keys.
Hostnames: `<device>.<user>.unity.internal` (a user's primary device is also the bare
`<user>.unity.internal`). The `unity` label is the coordinator's namespace (fixed while
single-coordinator); the community/guild is **not** in the name — a device is one identity/IP
across all a coordinator's guilds (Model B), so the guild rides on each shared network instead
(`api::SharedNetwork`). Multi-coordinator will make `unity` per-coordinator — see `DNS_SUFFIX`.

Deeper design lives in `docs/design.md` (concepts, trust model, NAT), `docs/technical.md`, and
`CONTRIBUTING.md` (full local-mesh setup for Linux + Windows). Read those before large changes.

## Commands

```sh
cargo build                                        # whole workspace (debug)
cargo build -p unitylan-engine                     # one crate

# The three gates CI enforces (a pre-commit hook in .githooks runs these):
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# CI also runs a dependency-vuln gate (cargo audit, ignore-list in .cargo/audit.toml). The hook
# runs it too, but only when a commit changes Cargo.lock (and only if cargo-audit is installed):
cargo audit

cargo test -p unitylan-coordinator                 # one crate's tests
cargo test -p unitylan-coordinator rename_and       # single test by name substring
```

Unit tests need no privilege or network. `cargo test` is platform-aware: on Windows it runs the
`fw/windows.rs` + `resolver/windows.rs` arg-construction tests, on Linux the nftables/resolved ones.

**Enable the hook once per clone:** `git config core.hooksPath .githooks`. Bypass a single commit
with `git commit --no-verify` — but note the hook runs `fmt --all`, so a pre-existing formatting
issue anywhere in the tree blocks every commit until fixed.

**Every user-visible feature or fix also updates `CHANGELOG.md`**, under an `## Unreleased` heading
(create one if the top section is an already-tagged release). Write it for the person running
UnityLAN, not the person who wrote the patch: lead with the symptom or the new ability, then the
why — match the prose style of the existing entries rather than pasting the commit subject. Internal
work with no effect on users (refactors, test harnesses, CI) stays out of it. Release CI lifts the
notes straight from the section whose heading matches the tag (`## v1.2.3`), so at release time the
`Unreleased` heading is renamed to the version — an unrenamed one ships a release with generic
notes.

### Running a local mesh (offline, no real Discord)

```sh
cargo run -p unitylan-coordinator -- coordinator.test.toml   # fake-Discord mode on :8080
scripts/dev-run.sh                                           # engine (via sudo) + GUI, shared socket
```

`scripts/*.sh` are Linux-only end-to-end tests over network namespaces (a fake Discord/OAuth
coordinator + `nft`/`veth`). `mesh-test.sh`, `nat-test.sh`, `expose-net-test.sh`,
`net-toggle-test.sh`, `rotation-test.sh`, `own-device-test.sh` are the ones that exercise the coordinator↔engine path;
prefer running the relevant one to verify a behavior change end-to-end. `update-test.sh` covers the
signed auto-update path (manifest → verify → download → swap → restart onto the new version); it
temporarily patches the workspace version to build a fake-old client, and restores it after.

**Privilege: almost none of them need `sudo`.** Most re-exec themselves under
`unshare -Urnm --map-root-user`, so they get root *inside a user namespace* and run fine as an
unprivileged user. Run them directly — `sudo` is unnecessary and, in a Claude session, impossible
(no password).

| Script | How to run |
| --- | --- |
| `mesh-test.sh`, `nat-test.sh`, `gui-login-test.sh`, `gossip-test.sh`, `ice-test.sh`, `relay-test.sh`, `expose-net-test.sh`, `net-toggle-test.sh`, `own-device-test.sh`, `wg-tunnel-test.sh` | directly, self-unshares — `timeout 150 scripts/<name>.sh` |
| `oauth-test.sh`, `rotation-test.sh` | directly, unprivileged (HTTP + key files only, no netns/WG) |
| `update-test.sh` | directly, self-unshares — `timeout 420 scripts/update-test.sh` (builds twice; needs `openssl` + `python3`) |
| `resolver-hook-test.sh` | **real host root** — needs a live `systemd-resolved`, a userns won't do |
| `dev-run.sh` | **real host root** — engine builds a real `wg` interface on the host |
| `readme-demo.sh` | **interactive desktop** — needs a Wayland screencast portal, not headless-able |

The last three the user must run themselves via the `! <cmd>` prefix; ask rather than attempting.
Wrap the rest in `timeout` — a hung daemon otherwise blocks until the tool timeout.

### Debugging a live engine (subscribe, don't poll)

The engine's control socket (`<state_dir>/control.sock`, e.g. `engine-state-prod/control.sock`)
speaks **newline-delimited JSON** — a `ControlRequest` line in, `ControlResponse` line(s) out (see
`common/src/control.rs`). A unit-variant request serializes to a bare string. So no client build is
needed; `socat` + `jq` reach it directly:

```sh
sock=engine-state-prod/control.sock
# One-shot snapshot, one peer's row:
printf '"Status"\n' | socat -t2 UNIX-CONNECT:$sock - \
  | jq -c '.Status.peers[]? | select(.wg_ip=="100.73.61.1")'
# Live subscription — the daemon holds the conn open and pushes a fresh StatusReport on EVERY change
# (the same push channel the GUI's `ctl::watch_status` uses). Prefer this over polling `Status`:
printf '"Watch"\n' | socat -t 86400 UNIX-CONNECT:$sock - \
  | jq --unbuffered -c '.Status.peers[]? | select(.wg_ip=="100.73.61.1")
        | {up, reach, ep:.endpoint, hs:.last_handshake_secs, lat:.latency_ms, rx:.rx_bytes, tx:.tx_bytes}'
```

Pair `Watch` with a `Monitor` over the dedup'd output to wake on a specific edge (a down, an endpoint
landing) instead of re-polling. **`Watch` and `engine.log` are complementary, and the gap between
them is itself a diagnostic.** A "peer reachability changed" log line is emitted **only** by the main
liveness loop, and only when the WG-stats-derived `up`/`reach` actually flips (`daemon.rs`,
`prev_reach`). The status snapshot the GUI/`Watch` sees is a *separate* surface: `control::update`
(inside `apply_state`) rebuilds it from seeds and `send_replace`s it **before** `set_live` re-overlays
the live WG stats. So a peer can **flash** in the GUI/`Watch` stream — a momentary all-null row
(`up:false, hs:null, rx:0`) at an `apply_state` timestamp — with **no** log line, because the tunnel
never actually dropped. GUI-flaps-but-log-silent ⇒ suspect a snapshot rebuild, not the data plane;
subscribing is what makes that transient visible (polling `Status` will usually miss it).

## Architecture

Four crates (`crates/*`), two planes:

| Crate | Binary | Role |
| --- | --- | --- |
| `common` | — | shared wire types: coordinator API (`api.rs`), engine control protocol (`control.rs`), crypto/attestation |
| `coordinator` | `unitylan-coordinator` | **control plane**: Discord auth (OAuth PKCE), role→network registry, signs attestations |
| `engine` | `unitylan-engine` | **data plane**, privileged daemon: WireGuard, host firewall, DNS resolver, control socket |
| `gui` | `unitylan-gui` | unprivileged iced desktop app, drives the engine over its control socket |

**GUI screenshots are docs.** When a GUI change alters what the app looks like, regenerate the
README images — `assets/demo.gif`, `assets/exposed.png` (plus `peers.png`/`networks.png`,
generated but not currently referenced) — with
`scripts/readme-demo.sh` (fake-engine canned fixtures + scripted tour + screencast). Keep the
fixtures in `crates/gui/examples/fake-engine.rs` representative of the feature being shown, or the
regenerated stills won't demonstrate it.

**Trust model.** A *network* is a Discord role an admin registered (`/unitylan network add`) — an
ACL group, not a subnet. Networks may overlap; a device has **one IP and one tunnel per co-device**
regardless of how many networks they share. The coordinator holds **one Ed25519 signing key per
guild** (the trust anchor; independently generated on first use — design.md §3.1) and signs
short-lived attestations binding device identity + guild — `guild + user + device + ip + wg_pubkey
(+ is_primary)`, **not** role. A device in N guilds gets N attestations (same identity, different
signer/guild). Role/network membership rides separately in the snapshot (each peer lists the
networks it shares with you); the coordinator gates access by only putting peers you share a network
with into your snapshot. Peers **pin one anchor per guild** (TOFU) and verify each peer's
attestation against the matching guild anchor, checking `guild_id` — so a compromised guild key's
blast radius is one guild. The coordinator never sees peer traffic.

**Discovery is coordinator-mediated long-poll, not gossip** (`coordinator/src/api/`,
`engine/src/coord.rs`). Clients long-poll `/register` + `/refresh`; the coordinator holds each
request `LONGPOLL_HOLD_SECS` (≈ attestation TTL / 2) then rebuilds a fresh, re-signed snapshot.
A membership change bumps a shared `watch` **version**, which wakes every parked client at once.

**Changing a wire type? Read `CONTRIBUTING.md` § "Changing a wire type" first.** Coordinator and
clients upgrade on **independent schedules**, so anything crossing the network has to answer "what
happens when the other side hasn't got this change yet?". Work down the ladder and stop at the first
rung that fits: **additive field** (`#[serde(default)]`, default chosen so *absent = old behavior*)
→ **capability flag** (`common::caps`) → **version bump** (last resort: it costs every user in every
mesh a coordinated upgrade). A bump means moving `MIN_PROTOCOL_VERSION` to the retired version,
writing the shim that keeps it working, and adding a golden fixture — the support window is
current + 1 previous, and it's a promise, not a number. Two things that bite: `#[serde(default)]`
does **nothing** inside a `Signed` envelope (postcard encodes by position — hence `Attestation`'s
schema tag, and `RotationCert` being frozen), and peer-supplied data that won't parse or verify must
cost you *that peer*, not the whole batch. Rationale in `docs/technical.md` §3.6.

**Platform split.** Engine OS-specific code is separate modules selected at runtime:
`wg/{userspace,windows}.rs`, `fw/{nftables,windows}.rs`, `resolver/{linux,windows}.rs`. The
userspace WireGuard (boringtun) backend is the portable primary; kernel drivers (Linux netlink,
Windows wireguard-nt via `wireguard.dll`) are per-OS optimizations. Windows is a first-class target
— keep both sides of every platform split in mind.

**NAT traversal.** Direct P2P isn't free behind NAT. The engine runs a userspace **ICE** agent
(`engine/src/ice.rs`, `nat.rs`): STUN candidate gathering (the coordinator answers STUN binding
requests, `coordinator/src/stun.rs`) plus UDP hole-punching, with a ciphertext-only **TURN relay**
fallback (`engine/src/relay.rs`) for pairs a punch can't connect. The coordinator only **brokers** —
it exchanges ICE candidates over the long-poll and pairs a relay peer with a stuck client — and
stays **off the traffic path**: a relay is another *peer*, never the coordinator.

**Discord role source** is behind the `RoleSource` trait (`coordinator/src/roles.rs`):
`TwilightRoleSource` (live bot token, `discord.rs`) and `FakeRoleSource` (config-seeded, offline
dev/tests). Slash commands + gateway events (role revocation, evictions) live in `commands.rs`.

## Keep the coordinator off the hot path (decentralization goal)

UnityLAN's north star is **decentralization**: any online member can bootstrap a new joiner, the
data plane is pure P2P, and the coordinator is a lightweight control plane that a mesh can run
without once tunnels are established. Every design decision should push work *toward* the peers and
*away* from the coordinator — never the reverse. Treat coordinator load as a cost to minimize, not a
resource to spend.

**So before adding or changing work on any coordinator request path, ask what it does to that
goal** — and specifically how it behaves under a burst, because the coordinator is a fan-in/fan-out
chokepoint: one membership change can wake every client at once, and one deployment serves many
clients across possibly-many guilds.

- **Fan-in (thundering herd on version bump).** `wait_park` parks long-pollers on the membership
  versions of their own **scopes** — the guilds they hold a role in, plus their user scope for
  own-device peering (`versions.rs`). A bump releases every client of that scope at once, each
  re-running `build_snapshot`. So: bump a version only when membership actually changed, bump the
  **narrowest scope** that covers who cares (a deployment-wide bump would wake every disjoint guild
  for nothing), and keep the wake path cheap since a herd multiplies it.
- **Fan-out (per-request external calls).** `build_snapshot` runs per client per renewal (≈ every
  `LONGPOLL_HOLD_SECS`, *plus* on every herd wake). Any Discord REST call inside it is multiplied by
  client count, and Discord rate-limits per route/bucket (e.g. `GET guild roles` is a **per-guild**
  bucket) — so N clients in one guild hit the same bucket at once and serialize or 429. Cache/dedup
  shared per-guild data once and reuse across clients (see `TwilightRoleSource`'s per-guild
  role-name TTL cache in `discord.rs`).

Prefer a solution the peers can carry themselves, or that the coordinator answers once and caches,
over one that makes each client's request do more coordinator/Discord work. When a change pulls
work onto the coordinator or amplifies its traffic, flag it and weigh it against the decentralization
goal before proceeding.
