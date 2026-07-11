# UnityLAN — Roadmap (Milestones & Tasks)

Task breakdown of the milestones in [design.md §11](./design.md). Each milestone has a
**goal**, **tasks**, and a **verify** (done-when). Build in order; later milestones assume
earlier ones.

Dependency sketch:
```
M1 spine ─▶ M2 wg+control ─▶ M3 gossip ─▶ M4 gui
                          └─▶ M5 nat
   M3/M5 ─▶ M6 dns/multihome ─▶ M7 revocation/expose ─▶ M8 native backends
```

---

## M1 — Membership spine (no WG, no GUI)
**Goal:** prove authenticated, signed, role-derived membership end to end. Engine prints a
verified `wg_ip` + hostname obtained from the coordinator.

### M1.0 Workspace
- [ ] Cargo workspace `Cargo.toml`; crates `common`, `coordinator`, `engine` (+ `gui` stub later).
- [ ] Shared workspace deps (tokio, serde, tracing) via `[workspace.dependencies]`.
- [ ] `.gitignore` for `/target`, secrets, `*.db`.

### M1.1 `common` (pure, unit-tested — no network)
- [ ] `crypto.rs`: Ed25519 keypair, `sign`/`verify` (ed25519-dalek); WG key types (x25519-dalek).
- [ ] `wire.rs`: `Signed<T>` envelope, postcard encode/decode, base64 transport form.
- [ ] `attestation.rs`: `Attestation` struct (serde) + `verify(anchor, now)`.
- [ ] `netid.rs`: `subnet_of(guild,role)`, `host_hint(user)`, `sanitize_label`, siphash.
- [ ] `api.rs`: coordinator DTOs (`RegisterReq/Resp`, `SeedRecord`, `RefreshReq/Resp`).
- [ ] **Tests**: sign→verify round-trip; tamper → fail; TTL expiry → fail; subnet in `100.64/10`.

### M1.2 `coordinator`
- [ ] `config.rs`: TOML (guild_id, bot_token, oauth client id/secret + redirect, role→network
      allowlist, bind addr, db path, signing-key path).
- [ ] `store.rs`: SQLite via sqlx — `allocations`, `signing_key`, `tombstones`; migrations.
- [ ] `signer.rs`: load/generate Ed25519 key; `sign_attestation(user, role, …, ttl=30m)`.
- [ ] `discord.rs`: twilight-http `GET member` → roles + nick.
- [ ] `oauth.rs`: Discord OAuth2 auth-code + PKCE; exchange code → `user_id` (`identify`).
- [ ] `alloc.rs`: allocate stable `wg_ip` per `(guild,role,user)`; persist; collision-resolve.
- [ ] `api.rs` (axum): `GET /oauth/start`, `GET /oauth/callback`, `POST /register`.
- [ ] `main.rs`: load config, open store, serve.

### M1.3 `engine` (headless)
- [ ] `config.rs` + state dir (0600).
- [ ] `auth.rs`: loopback OAuth (return authorize URL, catch redirect → session token).
- [ ] gen WG keypair (private stays local).
- [ ] `coord.rs`: `POST /register{wg_pubkey}` → attestations + `coord_pubkey`; **verify** sig +
      TTL; **pin** anchor.
- [ ] `main.rs`: run once → print each `wg_ip` + `<nick>.<role>.<guild>.internal`.

**Verify:** against a test Discord guild, engine logs a signature-verified attestation and
prints e.g. `alice.minecraft.myguild.internal → 100.64.42.7`. Tamper the payload → engine
rejects.
> ⚙️ Needs from you: a Discord application (client id/secret), a bot token in the test guild,
> and a role or two. (Setup steps documented when we reach M1.2.)

---

## M2 — WireGuard backend + control socket
**Goal:** engine can bring up an interface and add/remove peers; GUI-less control channel.
- [x] `wg/mod.rs`: `WgBackend` trait (`up`, `set_peer`, `remove_peer`, `down`).
- [x] `wg/userspace.rs`: defguard/boringtun userspace backend (portable primary).
- [x] Bring up an interface with the client's `/32`; add a peer; **ping over the tunnel**
      (`scripts/wg-tunnel-test.sh` — two netns + veth, no host root; PASS).
- [x] engine dev subcommands: `wg-smoke`, `wg-keygen`, `wg-node`.
- [ ] `control.rs`: `interprocess` local-socket server; `common::control` request/event enums.
- [ ] ⚠️ **Spike**: confirm `defguard_wireguard_rs` userspace path on **Windows + macOS**
      (Linux userspace confirmed working).

**Verify:** ✅ real encrypted tunnel carries ICMP across two namespaces, 0% loss
(`scripts/wg-tunnel-test.sh`). Control socket + `status` still pending.

---

## M3 — Mesh formation
**Goal:** members auto-discover and mesh; new joiner bootstraps via any online member.

### M3a — Seed-based meshing (done)
- [x] Coordinator presence + `seeds` in `/register`; `/refresh` endpoint + client endpoint report.
- [x] Engine daemon (`run`): register → bring up iface with its `/32`s → peer seeds →
      refresh loop picking up new co-members.
- [x] `scripts/mesh-test.sh`: coordinator + two engine daemons in separate netns mesh and
      ping across — **PASS**, no host root.
- **Gap:** the daemon does not yet bring the interface admin-up or install routes itself
  (the test script does it); defguard `configure_peer_routing` needs the link up. Fix as
  part of daemon OS-plumbing (link-up after `up()`), then routes apply automatically.

### M3b — P2P gossip (next)
- [ ] `gossip.rs`: endpoint on `wg_ip` serving `{attestations, endpoints, tombstones}`.
- [ ] Anti-entropy loop: pull from N random peers, merge (verify sig+TTL, newest endpoint seq).
- [ ] Bootstrap purely via a seed peer (coordinator out of the steady-state path).
- [ ] STUN reflection at the coordinator; endpoint-record `seq`.

**Verify (M3a):** ✅ two daemons mesh via coordinator seeds and ping across
(`scripts/mesh-test.sh`). M3b verify: 4th node joins via one seed, reaches all; kill the
starter → others stay meshed.

---

## M4 — iced GUI + tray
**Goal:** a real desktop app driving the engine.
- [ ] `gui` crate: iced app (State/Message/update/view), `tray-icon`.
- [ ] `engine.rs`: control-socket client + `Subscription` of engine events.
- [ ] Screens: login (opens browser), networks list + toggle, status/peers.
- [ ] Tray: up/down, open, quit; engine survives window close.

**Verify:** click Login → OAuth → networks appear → toggle a network → status shows peers,
all via the socket; closing the window keeps the mesh up.

---

## M5 — NAT traversal
**Goal:** reach members behind NAT.
- [ ] `nat.rs`: UPnP-IGD port mapping; publish mapped endpoint.
- [ ] Mesh-relayed hole punch: relay peer passes endpoints + synchronized punch signal.
- [ ] Diagnostics for symmetric-NAT-both (best-effort, clear error).

**Verify:** two NAT'd hosts (no port-forward) mesh via a mutually-connected relay peer.

---

## M6 — DNS + multi-homing
**Goal:** `*.internal` names resolve; overlapping networks work on one interface.
- [ ] `dns.rs`: hickory-server `.internal` zone from verified attestations.
- [ ] Per-OS hookup: resolved/resolv.conf · Windows NRPT/netsh · macOS resolver dir; hosts fallback.
- [ ] One interface, per-role `/32`s; verify cross-network isolation.

**Verify:** `ping alice.minecraft.myguild.internal` resolves + reaches; a member in two roles
gets two names/IPs; the networks can't route to each other.

---

## M7 — Revocation, expose, status polish
**Goal:** losing a role cuts you off; expose local ports; solid status.
- [ ] Coordinator gateway (`GUILD_MEMBER_UPDATE/REMOVE`) → tombstone + stop re-signing.
- [ ] Client TTL refresh at half-life; apply tombstones (drop peer immediately).
- [ ] `expose <port> --net <role>` end to end.
- [ ] Status/event polish in GUI.

**Verify:** remove a member's role in Discord → within the TTL (or immediately via tombstone)
they lose the tunnel. Expose a port → a peer reaches it.

---

## M8 — Native kernel backends (optimization)
**Goal:** faster path where the OS offers it.
- [ ] `wg/native.rs`: Linux netlink; Windows WireGuardNT (via defguard).
- [ ] Select native when present, else userspace; parity tests.

**Verify:** same behavior as userspace on Linux + Windows, measurably lower overhead.

---

## Cross-cutting (ongoing)
- [ ] `tracing` logging across binaries.
- [ ] Per-OS service packaging (systemd unit · Windows Service · launchd plist).
- [ ] CI: `cargo fmt`/`clippy`/`test`.
- [ ] Open design items to close before GA: coordinator key rotation, pubkey re-key signal,
      endpoint-record spoof hardening, symmetric-NAT policy (design.md Open Questions).
