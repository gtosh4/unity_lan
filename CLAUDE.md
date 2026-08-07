# CLAUDE.md

Guidance for Claude Code (claude.ai/code) in this repo.

## What this is

UnityLAN: WireGuard mesh VPN. Membership defined by **Discord roles**, enforced by a self-hosted
**coordinator** that issues short-lived Ed25519-signed **attestations**. Peers discover each other
through the coordinator (long-poll), then form **direct P2P WireGuard tunnels**. The coordinator is
**control plane only** — carries no traffic, holds no peer private keys.

Hostnames: `<device>.<user>.unity.internal` (`DNS_SUFFIX`; a user's primary device is also bare
`<user>.unity.internal`). The `unity` label is the coordinator's namespace (fixed while
single-coordinator). Community/guild is **not** in the name — a device is one identity/IP across all
of a coordinator's guilds (Model B), so guild rides on each shared network instead
(`api::SharedNetwork`). A deployment can mirror those names under a real public domain (hosted:
`mesh.unitylan.com`), where the device itself gets a publicly-trusted certificate over ACME DNS-01
(`engine/src/cert.rs`) covering its name plus one label below it; the coordinator only publishes the
challenge TXT.

Deeper design: `docs/design.md` (concepts, trust model, NAT), `docs/technical.md`, `CONTRIBUTING.md`
(full local-mesh setup, Linux + Windows). Read before large changes.

## Commands

```sh
cargo build                                        # whole workspace (debug); -p unitylan-engine for one crate
cargo test -p unitylan-coordinator                 # one crate's tests (append a name substring to filter)

# The four gates CI enforces, also run by the .githooks pre-commit hook:
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps   # broken intra-doc links rot silently

# Dependency gates, also CI. Vulnerabilities (ignore-list in .cargo/audit.toml) — the hook runs this
# one too, but only when a commit touches Cargo.lock and cargo-audit is installed:
cargo audit
# ...and policy: licences shippable inside an AGPL binary, crates.io as the only source, no unused
# manifest entries. Policy + reasoning in deny.toml; advisories stay above so there's one ignore-list:
cargo deny check licenses bans sources
cargo machete
```

Lint policy lives in `[workspace.lints]` (root `Cargo.toml`), not just the clippy flag, so a local run
and an IDE see the same set. Add a lint there only if the tree already passes it. Unit tests need no
privilege or network.

**Enable hook once per clone:** `git config core.hooksPath .githooks`. It skips the cargo gates when
no Rust build input is staged; bypass with `git commit --no-verify`. It runs `fmt --all`, so a
pre-existing formatting issue anywhere in the tree blocks every Rust-touching commit until fixed.

**Every user-visible feature or fix also updates `CHANGELOG.md`**, under `## Unreleased` (create one
if the top section is an already-tagged release). Write for the person running UnityLAN, not the patch
author: lead with the symptom or new ability, then why — match the prose style of existing entries,
don't paste the commit subject. Internal work with no user effect (refactors, test harnesses, CI)
stays out.

To verify a behavior change end-to-end, run the relevant `scripts/*-test.sh` — which script, what
privilege, what timeout: the **`mesh-e2e` skill**. To inspect a running daemon over its control
socket: the **`debug-engine` skill**. To tag and announce a release: the **`cut-release` skill**.

**Work whose point is performance gets measured before and after — never only after.** Take a
baseline first, on the unmodified code, with the harness that will judge the change
(`coordinator-scale-test.sh` for coordinator load; a purpose-built one otherwise). Then implement,
re-run the *same* harness at the *same* parameters, and report both numbers. Rules that follow from
having done this:

- **Baseline first, because it is what tells you the change was worth making**, and because a
  harness written after the fact tends to measure what the fix improved. A first run also routinely
  finds the harness lying — a warm cache reporting zero cost, a limit that never engaged, a wait that
  hung on the wrong process. Discovering that *after* you have an improvement to show is how a
  measurement bug gets published as a result.
- **Simulate the constraint that actually binds**, not the one that is easy to drive. If the ceiling
  is an external rate limit, the harness has to impose it (`crates/coordinator/examples/mock_discord.rs`);
  a fake that answers instantly measures nothing that matters.
- **Report the table, not an adjective.** Parameters, before, after, at more than one scale — a single
  ratio hides whether the change fixed a term or just moved it. Say which term left the cost, e.g.
  "calls per device is 1.0 at every guild count" beats "much faster".
- **Say what the numbers do not cover.** A synthetic harness on a dev box is not the deployment; name
  the parameters you did not sweep and the paths no test exercises.

A change whose stated purpose is speed and whose evidence is "should be faster" is unfinished.

## Architecture

Five crates (`crates/*`), two planes. Each of the four binary crates has its own `CLAUDE.md` with the
rules specific to it — read it before changing that crate.

| Crate | Binary | Role |
| --- | --- | --- |
| `common` | — | shared wire types: coordinator API (`api.rs`), engine control protocol (`control.rs`), crypto/attestation |
| `coordinator` | `unitylan-coordinator` | **control plane**: Discord auth (OAuth PKCE), role→network registry, signs attestations |
| `engine` | `unitylan-engine` | **data plane**, privileged daemon: WireGuard, host firewall, DNS resolver, control socket |
| `gui` | `unitylan-gui` | unprivileged iced desktop app, drives the engine over its control socket |
| `proxy` | — (linked into the engine) | unprivileged TLS terminator for **web services**: reads its config off the engine's `Watch` push, forwards to loopback backends. The engine re-executes *itself* under a hidden `proxy-serve` subcommand and drops the child to `[proxy] user` — a separate process, not a separate binary |

**Trust model.** A *network* = a Discord role an admin registered (`/unitylan network add`) — an ACL
group, not a subnet. Networks may overlap; a device has **one IP and one tunnel per co-device**
regardless of how many networks they share. The coordinator holds **one Ed25519 signing key per guild**
(the trust anchor, generated independently on first use — design.md §3.1) and signs short-lived
attestations binding `guild + user + device + ip + wg_pubkey (+ is_primary)` — **not** role. A device
in N guilds gets N attestations (same identity, different signer/guild). A user holding **no** role
anywhere is attested under a reserved **personal scope** instead (`guild_id = 0`,
`common::attestation::PERSONAL_SCOPE`; one key per deployment), so a Discord account with no server can
still mesh its own devices — issued only if the device opted into own-device peering, allocation
reclaimed after 30 days idle. Role/network membership rides separately in the snapshot (each peer lists
networks it shares with you); the coordinator gates access by only putting peers you share a network
with into your snapshot. Peers **pin one anchor per guild** (TOFU) and verify each attestation against
the matching guild anchor, checking `guild_id` — so a compromised guild key's blast radius is one
guild. The coordinator never sees peer traffic.

**Discovery is coordinator-mediated long-poll, not gossip** (`coordinator/src/api/`,
`engine/src/coord.rs`). Clients long-poll `/register` + `/refresh`; the coordinator holds each request
`LONGPOLL_HOLD_SECS` (≈ attestation TTL / 2) then rebuilds a fresh, re-signed snapshot. A membership
change bumps a shared `watch` **version**, waking every parked client at once. Mechanics and the load
rules that follow from it: `crates/coordinator/CLAUDE.md`.

**Changing a wire type? Read `CONTRIBUTING.md` § "Changing a wire type" first.** Coordinator and
clients upgrade on **independent schedules**, so anything crossing the network must answer "what
happens when the other side hasn't got this change yet?". Work down the ladder, stopping at the first
rung that fits: **additive field** (`#[serde(default)]`, default chosen so *absent = old behavior*) →
**capability flag** (`common::caps`) → **version bump** (last resort: costs every user in every mesh a
coordinated upgrade). A bump means moving `MIN_PROTOCOL_VERSION` to the retired version, writing the
shim that keeps it working, and adding a golden fixture — the support window is current + 1 previous, a
promise not a number. Two gotchas: `#[serde(default)]` does **nothing** inside a `Signed` envelope
(postcard encodes by position — hence `Attestation`'s schema tag, and `RotationCert` being frozen), and
peer-supplied data that won't parse or verify must cost you *that peer*, not the whole batch. Rationale
in `docs/technical.md` §3.6.

**Decentralization is the north star.** Any online member can bootstrap a new joiner, the data plane is
pure P2P, and the coordinator is a lightweight control plane a mesh can run without once tunnels are
established. Every decision should push work *toward* peers and *away* from the coordinator — never the
reverse. **Adding or changing work on a coordinator request path? Read
`crates/coordinator/CLAUDE.md` first** — it has the fan-in/fan-out costs that decide whether the change
is affordable.
