# Coordinator crate

Control plane: Discord auth (OAuth PKCE), role→network registry, signs attestations. Root `CLAUDE.md`
has the project-wide rules (trust model, wire-type ladder, CI gates) — this file is the
coordinator-specific part.

## Keep the coordinator off the hot path (decentralization goal)

UnityLAN's north star = **decentralization**: any online member can bootstrap a new joiner, the data
plane is pure P2P, and the coordinator is a lightweight control plane a mesh can run without once
tunnels are established. Every decision should push work *toward* peers and *away* from the
coordinator — never the reverse. Treat coordinator load as a cost to minimize, not a resource to spend.

**Before adding or changing work on any request path, ask what it does to that goal** — specifically
under a burst, since the coordinator is a fan-in/fan-out chokepoint.

- **Fan-in (thundering herd on version bump).** `wait_park` parks long-pollers on membership versions
  of their own **scopes** — guilds they hold a role in, plus their user scope for own-device peering
  (`versions.rs`). A bump releases every client of that scope at once, each re-running
  `build_snapshot`. So: bump a version only when membership actually changed, bump the **narrowest
  scope** covering who cares (a deployment-wide bump wakes every disjoint guild for nothing), and keep
  the wake path cheap since a herd multiplies it.
- **Fan-out (per-request external calls).** `build_snapshot` runs per client per renewal (≈ every
  `LONGPOLL_HOLD_SECS`, *plus* every herd wake). Any Discord REST call inside it is multiplied by
  client count, and Discord rate-limits per route/bucket (e.g. `GET guild roles` is a **per-guild**
  bucket) — so N clients in one guild hit the same bucket at once and serialize or 429. Cache/dedup
  shared per-guild data once and reuse it across clients (see `TwilightRoleSource`'s per-guild
  role-name TTL cache in `discord.rs`).
- **The walk is per-guild, so a per-request call costs `guilds`, not 1.** `resolve_membership` asks
  about the caller in *every* registered guild, since Discord offers no "which guilds is this user
  in" for a bot. Left uncached that made the deployment ceiling `devices × guilds` — a shared
  coordinator getting slower for everyone each time an unrelated community registered a network.
  `MEMBER_ABSENT_TTL` (`discord.rs`) caches the "not a member" answer for a renewal period, which is
  what keeps guild count out of the per-request cost. **It is only safe because `Event::MemberAdd`
  drops the entry** (`commands.rs`); anything that weakens that invalidation makes joins take up to
  the absent-TTL to appear.

Prefer a solution peers carry themselves, or one the coordinator answers once and caches. When a change
pulls work onto the coordinator or amplifies its traffic, flag it and weigh it against the
decentralization goal before proceeding.

`coordinator-scale-test.sh` is the probe for this: N synthetic devices against a coordinator whose
Discord REST is pointed at `examples/mock_discord.rs` (`[discord] api_proxy`, debug-only,
loopback-only), which rate-limits and delays the way Discord does. Takes `[devices] [guilds]`, because
**guild count scales the per-request cost as hard as device count does** — `build_snapshot` walks
every registered network for every device. Reports timings rather than pass/fail; run it directly,
unprivileged.

## Discovery mechanics

Clients long-poll `/register` + `/refresh` (`api/`, answered against `engine/src/coord.rs`); the
coordinator holds each request `LONGPOLL_HOLD_SECS` (≈ attestation TTL / 2), then rebuilds a fresh,
re-signed snapshot. A membership change bumps a shared `watch` **version**, waking every parked client
of that scope at once. Access gating is by omission: only peers you share a network with go into your
snapshot.

## Discord role source

Behind the `RoleSource` trait (`roles.rs`): `TwilightRoleSource` (live bot token, `discord.rs`) and
`FakeRoleSource` (config-seeded, offline dev/tests). Slash commands + gateway events (role revocation,
evictions) live in `commands.rs`. The fake source is what every `scripts/*-test.sh` and
`coordinator.test.toml` run against, so a change to role handling should be exercised through both.

**Membership freshness rests on the gateway, in both directions.** `MemberUpdate`/`MemberRemove` drop
the cached membership and evict; `MemberAdd` drops the cached *absence*. All three need the
GUILD_MEMBERS privileged intent (requested in `commands.rs`), and without it a change waits out its
TTL — 30s for a role change, a renewal period for a join. Note the fake source has no gateway and no
cache, so **no `scripts/*-test.sh` covers any of this**; the mock-Discord harness and the unit tests
in `discord.rs` are the only coverage.
