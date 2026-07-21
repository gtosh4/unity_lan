# CLAUDE.md

Guidance for Claude Code (claude.ai/code) in this repo.

## What this is

UnityLAN: WireGuard mesh VPN. Membership defined by **Discord roles**, enforced by self-hosted
**coordinator** that issues short-lived Ed25519-signed **attestations**. Peers discover each other
through coordinator (long-poll), form **direct P2P WireGuard tunnels**. Coordinator is **control
plane only** — carries no traffic, holds no peer private keys.
Hostnames: `<device>.<user>.unity.internal` (user's primary device also bare
`<user>.unity.internal`). `unity` label = coordinator's namespace (fixed while single-coordinator);
community/guild **not** in name — device is one identity/IP across all a coordinator's guilds
(Model B), so guild rides on each shared network instead (`api::SharedNetwork`). Multi-coordinator
will make `unity` per-coordinator — see `DNS_SUFFIX`.

Deeper design: `docs/design.md` (concepts, trust model, NAT), `docs/technical.md`, `CONTRIBUTING.md`
(full local-mesh setup, Linux + Windows). Read before large changes.

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

Unit tests need no privilege or network. `cargo test` platform-aware: Windows runs
`fw/windows.rs` + `resolver/windows.rs` arg-construction tests, Linux runs nftables/resolved ones.

**Enable hook once per clone:** `git config core.hooksPath .githooks`. Bypass single commit with
`git commit --no-verify` — but hook runs `fmt --all`, so a pre-existing formatting issue anywhere
in the tree blocks every commit until fixed.

**Every user-visible feature or fix also updates `CHANGELOG.md`**, under `## Unreleased` heading
(create one if top section is already-tagged release). Write for person running UnityLAN, not
patch author: lead with symptom or new ability, then why — match prose style of existing entries,
don't paste commit subject. Internal work with no user effect (refactors, test harnesses, CI) stays
out. Release CI lifts notes from section whose heading matches tag (`## v1.2.3`), so at release time
`Unreleased` renamed to version — unrenamed one ships generic notes.

### Running a local mesh (offline, no real Discord)

```sh
cargo run -p unitylan-coordinator -- coordinator.test.toml   # fake-Discord mode on :8080
scripts/dev-run.sh                                           # engine (via sudo) + GUI, shared socket
```

`scripts/*.sh` = Linux-only end-to-end tests over network namespaces (fake Discord/OAuth
coordinator + `nft`/`veth`). `mesh-test.sh`, `nat-test.sh`, `expose-net-test.sh`, `net-toggle-test.sh`,
`rotation-test.sh`, `own-device-test.sh` exercise coordinator↔engine path; prefer running the
relevant one to verify behavior change end-to-end. `update-test.sh` covers signed auto-update path
(manifest → verify → download → swap → restart onto new version); temporarily patches workspace
version to build fake-old client, then restores.

**Privilege: almost none need `sudo`.** Most re-exec under `unshare -Urnm --map-root-user` (root
inside user namespace), so run fine unprivileged. Run directly — `sudo` unnecessary and, in a Claude
session, impossible (no password).

| Script | How to run |
| --- | --- |
| `mesh-test.sh`, `nat-test.sh`, `gui-login-test.sh`, `gossip-test.sh`, `ice-test.sh`, `relay-test.sh`, `expose-net-test.sh`, `net-toggle-test.sh`, `own-device-test.sh`, `wg-tunnel-test.sh` | directly, self-unshares — `timeout 150 scripts/<name>.sh` |
| `oauth-test.sh`, `rotation-test.sh` | directly, unprivileged (HTTP + key files only, no netns/WG) |
| `update-test.sh` | directly, self-unshares — `timeout 420 scripts/update-test.sh` (builds twice; needs `openssl` + `python3`) |
| `resolver-hook-test.sh` | **real host root** — needs live `systemd-resolved`, a userns won't do |
| `dev-run.sh` | **real host root** — engine builds a real `wg` interface on host |
| `readme-demo.sh` | **interactive desktop** — needs Wayland screencast portal, not headless-able |

Last three the user must run themselves via `! <cmd>` prefix; ask rather than attempting. Wrap rest
in `timeout` — a hung daemon otherwise blocks until tool timeout.

### Debugging a live engine (subscribe, don't poll)

Engine's control socket (`<state_dir>/control.sock`, e.g. `engine-state-prod/control.sock`) speaks
**newline-delimited JSON** — `ControlRequest` line in, `ControlResponse` line(s) out (see
`common/src/control.rs`). Unit-variant request serializes to bare string, so no client build needed;
`socat` + `jq` reach it directly:

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

Pair `Watch` with a `Monitor` over dedup'd output to wake on a specific edge (a down, an endpoint
landing) instead of re-polling. **`Watch` and `engine.log` are complementary, and the gap between
them is itself a diagnostic.** "peer reachability changed" log line comes **only** from main liveness
loop, and only when WG-stats-derived `up`/`reach` actually flips (`daemon.rs`, `prev_reach`). Status
snapshot GUI/`Watch` sees is a *separate* surface: `control::update` (inside `apply_state`) rebuilds
it from seeds and `send_replace`s it **before** `set_live` re-overlays live WG stats. So a peer can
**flash** in GUI/`Watch` stream — a momentary all-null row (`up:false, hs:null, rx:0`) at an
`apply_state` timestamp — with **no** log line, because tunnel never dropped. GUI-flaps-but-log-silent
⇒ suspect snapshot rebuild, not data plane; subscribing makes that transient visible (polling
`Status` usually misses it).

## Architecture

Four crates (`crates/*`), two planes:

| Crate | Binary | Role |
| --- | --- | --- |
| `common` | — | shared wire types: coordinator API (`api.rs`), engine control protocol (`control.rs`), crypto/attestation |
| `coordinator` | `unitylan-coordinator` | **control plane**: Discord auth (OAuth PKCE), role→network registry, signs attestations |
| `engine` | `unitylan-engine` | **data plane**, privileged daemon: WireGuard, host firewall, DNS resolver, control socket |
| `gui` | `unitylan-gui` | unprivileged iced desktop app, drives engine over its control socket |

**GUI screenshots are docs.** When a GUI change alters what app looks like, regenerate README images
— `assets/demo.gif`, `assets/exposed.png` (plus `peers.png`/`networks.png`, generated but not
currently referenced) — with `scripts/readme-demo.sh` (fake-engine canned fixtures + scripted tour +
screencast). Keep fixtures in `crates/gui/examples/fake-engine.rs` representative of the feature
shown, else regenerated stills won't demonstrate it.

**Trust model.** A *network* = a Discord role an admin registered (`/unitylan network add`) — an ACL
group, not a subnet. Networks may overlap; a device has **one IP and one tunnel per co-device**
regardless of how many networks they share. Coordinator holds **one Ed25519 signing key per guild**
(the trust anchor; independently generated on first use — design.md §3.1) and signs short-lived
attestations binding device identity + guild — `guild + user + device + ip + wg_pubkey (+ is_primary)`,
**not** role. A device in N guilds gets N attestations (same identity, different signer/guild).
Role/network membership rides separately in snapshot (each peer lists networks it shares with you);
coordinator gates access by only putting peers you share a network with into your snapshot. Peers
**pin one anchor per guild** (TOFU), verify each peer's attestation against matching guild anchor,
checking `guild_id` — so a compromised guild key's blast radius is one guild. Coordinator never sees
peer traffic.

**Discovery is coordinator-mediated long-poll, not gossip** (`coordinator/src/api/`,
`engine/src/coord.rs`). Clients long-poll `/register` + `/refresh`; coordinator holds each request
`LONGPOLL_HOLD_SECS` (≈ attestation TTL / 2) then rebuilds a fresh, re-signed snapshot. A membership
change bumps a shared `watch` **version**, waking every parked client at once.

**Changing a wire type? Read `CONTRIBUTING.md` § "Changing a wire type" first.** Coordinator and
clients upgrade on **independent schedules**, so anything crossing the network must answer "what
happens when the other side hasn't got this change yet?". Work down the ladder, stop at first rung
that fits: **additive field** (`#[serde(default)]`, default chosen so *absent = old behavior*) →
**capability flag** (`common::caps`) → **version bump** (last resort: costs every user in every mesh
a coordinated upgrade). A bump means moving `MIN_PROTOCOL_VERSION` to the retired version, writing
the shim that keeps it working, adding a golden fixture — support window is current + 1 previous,
a promise not a number. Two gotchas: `#[serde(default)]` does **nothing** inside a `Signed` envelope
(postcard encodes by position — hence `Attestation`'s schema tag, and `RotationCert` being frozen),
and peer-supplied data that won't parse or verify must cost you *that peer*, not the whole batch.
Rationale in `docs/technical.md` §3.6.

**Platform split.** Engine OS-specific code = separate modules selected at runtime:
`wg/{userspace,windows}.rs`, `fw/{nftables,windows}.rs`, `resolver/{linux,windows}.rs`. Userspace
WireGuard (boringtun) backend is portable primary; kernel drivers (Linux netlink, Windows
wireguard-nt via `wireguard.dll`) are per-OS optimizations. Windows is first-class target — keep
both sides of every platform split in mind.

**NAT traversal.** Direct P2P isn't free behind NAT. Engine runs a userspace **ICE** agent
(`engine/src/ice.rs`, `nat.rs`): STUN candidate gathering (coordinator answers STUN binding requests,
`coordinator/src/stun.rs`) plus UDP hole-punching, with a ciphertext-only **TURN relay** fallback
(`engine/src/relay.rs`) for pairs a punch can't connect. Coordinator only **brokers** — exchanges ICE
candidates over long-poll, pairs a relay peer with a stuck client — and stays **off the traffic
path**: a relay is another *peer*, never the coordinator.

**Discord role source** behind `RoleSource` trait (`coordinator/src/roles.rs`): `TwilightRoleSource`
(live bot token, `discord.rs`) and `FakeRoleSource` (config-seeded, offline dev/tests). Slash commands
+ gateway events (role revocation, evictions) live in `commands.rs`.

## Keep the coordinator off the hot path (decentralization goal)

UnityLAN's north star = **decentralization**: any online member can bootstrap a new joiner, data
plane is pure P2P, coordinator is a lightweight control plane a mesh can run without once tunnels
established. Every decision should push work *toward* peers and *away* from coordinator — never the
reverse. Treat coordinator load as a cost to minimize, not a resource to spend.

**Before adding or changing work on any coordinator request path, ask what it does to that goal** —
specifically under a burst, because coordinator is a fan-in/fan-out chokepoint: one membership change
can wake every client at once, and one deployment serves many clients across possibly-many guilds.

- **Fan-in (thundering herd on version bump).** `wait_park` parks long-pollers on membership versions
  of their own **scopes** — guilds they hold a role in, plus their user scope for own-device peering
  (`versions.rs`). A bump releases every client of that scope at once, each re-running
  `build_snapshot`. So: bump a version only when membership actually changed, bump the **narrowest
  scope** covering who cares (a deployment-wide bump wakes every disjoint guild for nothing), keep the
  wake path cheap since a herd multiplies it.
- **Fan-out (per-request external calls).** `build_snapshot` runs per client per renewal (≈ every
  `LONGPOLL_HOLD_SECS`, *plus* every herd wake). Any Discord REST call inside it is multiplied by
  client count, and Discord rate-limits per route/bucket (e.g. `GET guild roles` is a **per-guild**
  bucket) — so N clients in one guild hit the same bucket at once and serialize or 429. Cache/dedup
  shared per-guild data once, reuse across clients (see `TwilightRoleSource`'s per-guild role-name
  TTL cache in `discord.rs`).

Prefer a solution peers carry themselves, or coordinator answers once and caches, over one that makes
each client's request do more coordinator/Discord work. When a change pulls work onto coordinator or
amplifies its traffic, flag it and weigh against the decentralization goal before proceeding.
