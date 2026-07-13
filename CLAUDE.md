# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

UnityLAN: a WireGuard mesh VPN whose membership is defined by **Discord roles** and enforced by a
self-hosted **coordinator** that issues short-lived Ed25519-signed **attestations**. Peers discover
each other through the coordinator (long-poll) and form **direct P2P WireGuard tunnels**. The
coordinator is a **control plane only** — it carries no traffic and holds no peer private keys.
Hostnames: `<nick>.<role>.<guild>.internal`.

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
regardless of how many networks they share. The coordinator holds one Ed25519 signing key per
deployment (the trust anchor) and signs short-lived attestations binding
`user + role + device + ip + wg_pubkey`. Peers verify each other's attestations against the pinned
anchor — the coordinator never sees peer traffic.

**Discovery is coordinator-mediated long-poll, not gossip** (`coordinator/src/api.rs`,
`engine/src/coord.rs`). Clients long-poll `/register` + `/refresh`; the coordinator holds each
request `LONGPOLL_HOLD_SECS` (≈ attestation TTL / 2) then rebuilds a fresh, re-signed snapshot.
A membership change bumps a shared `watch` **version**, which wakes every parked client at once.

**Platform split.** Engine OS-specific code is separate modules selected at runtime:
`wg/{userspace,windows}.rs`, `fw/{nftables,windows}.rs`, `resolver/{linux,windows}.rs`. The
userspace WireGuard (boringtun) backend is the portable primary; kernel drivers (Linux netlink,
Windows wireguard-nt via `wireguard.dll`) are per-OS optimizations. Windows is a first-class target
— keep both sides of every platform split in mind.

**Discord role source** is behind the `RoleSource` trait (`coordinator/src/roles.rs`):
`TwilightRoleSource` (live bot token, `discord.rs`) and `FakeRoleSource` (config-seeded, offline
dev/tests). Slash commands + gateway events (role revocation, evictions) live in `commands.rs`.

## Coordinator: check burst traffic patterns

The coordinator is a fan-in/fan-out chokepoint. **Before adding or changing work on any
coordinator request path, reason explicitly about how it behaves under a burst** — a single
membership change can wake every client at once, and one deployment serves many clients across
possibly-many guilds.

- **Fan-in (thundering herd on version bump).** `wait_for_change` parks *all* long-pollers on one
  shared version (`api.rs`). Anything that bumps that version — a member's roles changing, a
  presence eviction, an enrollment — releases every parked client simultaneously, each of which
  re-runs `build_snapshot`. Bump the version only when membership actually changed, and never do
  per-client work in the wake path that a herd would multiply. When adding a new bump site, ask:
  how many parked clients does this release, and what does each then do?
- **Fan-out (per-request external calls).** `build_snapshot` runs per client per renewal (≈ every
  `LONGPOLL_HOLD_SECS`, *plus* on every herd wake). Any external/Discord REST call added inside it
  is multiplied by client count. Discord rate-limits per route/bucket (e.g. `GET guild roles` is a
  **per-guild** bucket), so N clients in one guild hitting the same route at once serialize or 429.
  Deduplicate and cache: resolve shared per-guild data once and reuse it across clients (see
  `TwilightRoleSource`'s per-guild role-name TTL cache in `discord.rs`), rather than one REST call
  per client per request.

When a change to the coordinator (or a request it serves) could amplify traffic in either
direction, call it out and prefer caching/dedup/coalescing over per-request external work.
