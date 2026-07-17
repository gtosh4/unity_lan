# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

UnityLAN: a WireGuard mesh VPN whose membership is defined by **Discord roles** and enforced by a
self-hosted **coordinator** that issues short-lived Ed25519-signed **attestations**. Peers discover
each other through the coordinator (long-poll) and form **direct P2P WireGuard tunnels**. The
coordinator is a **control plane only** — it carries no traffic and holds no peer private keys.
Hostnames: `<device>.<user>.<community>.unity.internal` (a user's primary device is also the bare
`<user>.<community>.unity.internal`).

Deeper design lives in `docs/design.md` (concepts, trust model, NAT), `docs/technical.md`, and
`CONTRIBUTING.md` (full local-mesh setup for Linux + Windows). Read those before large changes.

## Commands

```sh
cargo build                                        # whole workspace (debug)
cargo build -p unitylan-engine                     # one crate

# The three gates CI enforces (a pre-commit hook in .githooks runs exactly these):
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

cargo test -p unitylan-coordinator                 # one crate's tests
cargo test -p unitylan-coordinator rename_and       # single test by name substring
```

Unit tests need no privilege or network. `cargo test` is platform-aware: on Windows it runs the
`fw/windows.rs` + `resolver/windows.rs` arg-construction tests, on Linux the nftables/resolved ones.

**Enable the hook once per clone:** `git config core.hooksPath .githooks`. Bypass a single commit
with `git commit --no-verify` — but note the hook runs `fmt --all`, so a pre-existing formatting
issue anywhere in the tree blocks every commit until fixed.

### Running a local mesh (offline, no real Discord)

```sh
cargo run -p unitylan-coordinator -- coordinator.test.toml   # fake-Discord mode on :8080
scripts/dev-run.sh                                           # engine (via sudo) + GUI, shared socket
```

`scripts/*.sh` are Linux-only end-to-end tests over network namespaces (a fake Discord/OAuth
coordinator + `nft`/`veth`). `mesh-test.sh`, `nat-test.sh`, `expose-net-test.sh`,
`net-toggle-test.sh`, `rotation-test.sh` are the ones that exercise the coordinator↔engine path;
prefer running the relevant one to verify a behavior change end-to-end.

## Architecture

Four crates (`crates/*`), two planes:

| Crate | Binary | Role |
| --- | --- | --- |
| `common` | — | shared wire types: coordinator API (`api.rs`), engine control protocol (`control.rs`), crypto/attestation |
| `coordinator` | `unitylan-coordinator` | **control plane**: Discord auth (OAuth PKCE), role→network registry, signs attestations |
| `engine` | `unitylan-engine` | **data plane**, privileged daemon: WireGuard, host firewall, DNS resolver, control socket |
| `gui` | `unitylan-gui` | unprivileged iced desktop app, drives the engine over its control socket |

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

**Discovery is coordinator-mediated long-poll, not gossip** (`coordinator/src/api.rs`,
`engine/src/coord.rs`). Clients long-poll `/register` + `/refresh`; the coordinator holds each
request `LONGPOLL_HOLD_SECS` (≈ attestation TTL / 2) then rebuilds a fresh, re-signed snapshot.
A membership change bumps a shared `watch` **version**, which wakes every parked client at once.

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

- **Fan-in (thundering herd on version bump).** `wait_for_change` parks *all* long-pollers on one
  shared version (`api.rs`). Anything that bumps it — roles changing, a presence eviction, an
  enrollment — releases every parked client at once, each re-running `build_snapshot`. Bump the
  version only when membership actually changed; keep the wake path cheap since a herd multiplies it.
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
