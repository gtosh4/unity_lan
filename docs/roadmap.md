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
- [x] `oauth.rs`: Discord OAuth2 auth-code; exchange code → `user_id` (`identify`). Confidential
      server-mediated flow (PKCE deferred). `FakeOauth` for offline tests.
- [ ] `alloc.rs`: allocate stable `wg_ip` per `(guild,role,user)`; persist; collision-resolve.
- [x] `api.rs` (axum): `POST /oauth/start`, `GET /oauth/callback`, `POST /register`.
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
- [x] `control.rs`: local-socket server (newline-JSON) + `ctl status` CLI — shows device
      (ip/hostname/primary/networks) + peers (ip/hostname/endpoint). Done as part of M-device 6.
      **Windows named-pipe transport** landed (M-win): the transport is now `interprocess`'s
      cross-platform local socket (unix-domain socket on unix, named pipe on Windows); the endpoint
      is named by `Config::control_name` (path on unix, `unitylan-<stem>` pipe on Windows). The GUI
      client (`gui/src/ctl.rs`) uses the same transport + name convention.
- [x] ⚠️ **Spike** resolved (M-win): defguard's **userspace** path is unix-only; on **Windows** the
      supported path is `WGApi<Kernel>` (wireguard-nt), wired up as `wg/windows.rs` (see M8). macOS
      userspace still unconfirmed.

**Verify:** ✅ real encrypted tunnel carries ICMP across two namespaces, 0% loss
(`scripts/wg-tunnel-test.sh`). Control socket + `status` still pending.

---

## M3 — Mesh formation
**Goal:** members auto-discover and mesh; new joiner bootstraps via any online member.

### M3a — Seed-based meshing (done)
- [x] Coordinator presence + `seeds` in `/register`; `/refresh` endpoint + client endpoint report.
- [x] Engine daemon (`run`): register → bring up iface with its `/32`s → peer seeds →
      refresh loop picking up new co-members.
- [x] Daemon brings its own link admin-up (Linux `ip link set up`; netlink/ioctl later) so
      defguard installs routes automatically — meshes with **no external plumbing**.
- [x] `scripts/mesh-test.sh`: coordinator + two engine daemons in separate netns mesh and
      ping across — **PASS**, no host root, no manual link-up/routes.

### M3b — P2P gossip (attempted, deferred)
Prototyped a bidirectional gossip exchange over the mesh, then reverted. **Finding:** gossip
runs *over* WG tunnels, and WireGuard needs **reciprocal** peer knowledge to open a tunnel
(a peer drops handshakes from pubkeys it hasn't been told about). So a node can only gossip
with peers that already know it — gossip cannot bootstrap discovery of a peer that doesn't
know you. The coordinator's full-seed `/register` is therefore the real discovery mechanism
(and it already yields a full reciprocal mesh). Gossip's remaining value here is only
endpoint-freshness + less coordinator polling — marginal — and the prototype had a 3-node
convergence bug. **Deferred** until there's a concrete need (e.g. very large meshes, or
frequent roaming) and a reciprocity-aware bootstrap (ring/hub seed selection).

**Verify (M3a):** ✅ two daemons mesh via coordinator seeds and ping across
(`scripts/mesh-test.sh`).

---

## M-device — Device model, addressing & naming (supersedes old per-network addressing)
Reshapes M1/M3 addressing to the settled **Model B** (design §6). Build order:
1. **One IP per device** ✅ — allocation keyed by device pubkey in a flat `100.64/10`
   (`netid`: `device_hint`/`pick_free_index`/`addr_from_index`; `devices` table by pubkey);
   attestation carries `device_name` + `username` + `is_primary`; presence keyed by device
   pubkey (a user's multiple devices no longer collide); networks are pure ACL — seeds = anyone
   sharing ≥1 network. Verified: `mesh-test.sh` meshes with per-device IPs (0% loss).
2. **Enrollment** — one-time enrollment keys (headless) ✅: `enrollment_keys` table (one-time,
   optional expiry, bound to a pubkey on use); `resolve_user` = known device by pubkey, else
   consume a key; minted via `/unitylan enroll` (any member, ephemeral) or config seed for tests.
   Replaced `dev_auth`/`?dev_user=`. Verified: `mesh-test.sh` enrolls + meshes; store tests cover
   one-time/expiry/rejection. OAuth session (interactive) still TODO — reuses the same binding.
3. **Community slug** ✅ — `communities` table (guild → slug); admin config via `[[community]]`
   seed, default = guild name; threaded into `Grant.community_name`. Runtime setter command
   deferred to the management chunk. Verified: `mesh-test.sh` shows `<device>.<user>.lan.internal`.
4. **Primary device** ✅ — `primary_device` table (one per user; simpler than per-community —
   the alias resolves the same everywhere). First enrollment auto-assigns; owner reassigns via
   `/unitylan primary set <device>` (`list` shows them). `is_primary` computed at register and
   propagated through the attestation → `SelfDevice`. CLI/GUI setter lands with the control
   socket (chunk 6). Verified: store test (auto-assign/reassign) + `mesh-test.sh` shows
   `[primary]`. The `<user>.<community>` alias itself is served in chunk 5 (DNS).
5. **DNS** ✅ — engine `dns.rs`: a tiny authoritative UDP resolver (hickory-proto) serving the
   `.internal` zone from verified attestations (self + seeds). Answers `<device>.<user>.<community>`
   and the `<user>.<community>` primary alias; NXDOMAIN for unknown `.internal`; EDNS-compatible.
   Zone rebuilt each refresh; enabled via `dns_bind`. Seeds now carry `community_name` so peer
   hostnames are well-defined. Per-OS resolver hookup (resolved/NRPT/macOS) deferred to polish.
   Verified: `mesh-test.sh` digs node A's resolver → peer B's name + primary alias → B's IP; two
   engine unit tests (answer + socket).
6. **Device management** — ✅
   - [x] Control socket (engine daemon serves it) + `ctl status` CLI (read-only): live device +
     peers snapshot, updated each refresh. Verified: `mesh-test.sh` runs `ctl status` on node A →
     lists peer B's ip/hostname/endpoint.
   - [x] Mutations: rename / set-primary / remove over the socket → coordinator, authenticated
     by a **per-device bearer token** minted at enrollment (`devices.token`, returned in
     `RegisterResp`, persisted 0600 in `state_dir/token`). Coordinator maps token→device→user and
     executes owner-scoped ops; remove auto-promotes a new primary. `ctl rename|set-primary|remove`.
     (Token secrecy relies on TLS in prod + local perms; a signed-request upgrade can come later.)
   - [x] `devices` list (`ctl devices` → `ManageOp::List`).
   - [x] iced GUI frontend — see M4.
7. **Discovery: long-poll + version/ETag** — ✅ (supersedes M3 gossip). `/refresh` carries the
   client's last-seen `version`; the coordinator holds an up-to-date request until presence
   changes (a `tokio::watch` version bump wakes parked peers at once) or ~TTL/2 elapses (renewal
   re-signs attestations). Near-zero idle traffic; joins propagate near-instantly. Rationale +
   scale envelope (eager peering at target scale; gossip/lazy-peering/deltas as the >~1k
   escape hatch) in design.md §5. Verified: `mesh-test.sh` (2/2 — B's join wakes A's long-poll).

## M4 — iced GUI
**Goal:** a real desktop app driving the engine over the control socket.
- [x] `gui` crate: iced app (State/Message/update/view) with a 2s `Subscription` timer refresh.
- [x] Async control-socket client (shared `common::control` DTOs; GUI needs no engine dep).
- [x] Screens: live status (this device + peers) and device management (rename / set-primary /
      remove) — exactly what the control socket backs today. `unitylan-gui [control.sock]`.
- [x] **Mesh connect / disconnect** — the GUI's primary on/off is a mesh **connect/disconnect** over
      the control socket (`ControlRequest::SetConnected`), *not* a Windows-service stop. Disconnect
      keeps the engine resident and still long-polling (so reconnect is instant) but drops the local
      peer-set (interface stays up holding our `/32`) **and** withdraws us from every co-member's seed
      list so peers prune us and see us offline. **Client is the source of truth**: a global paused
      flag persisted separately (`<state_dir>/paused.json`), layered *on top of* the per-network
      opt-out (so a connect/disconnect cycle never clobbers individual per-network prefs), enforced
      locally (empty active seed set) so it works while the coordinator is **unreachable** — the
      toggle wakes the daemon (`tokio::Notify`) to tear down / re-mesh from the last snapshot at once.
      It rides to the coordinator as `RegisterReq.paused`, which skips recording the device's presence
      and evicts any existing (peers wake on the version bump and prune), while still returning the
      device's own grant (its IP) + seeds so reconnect re-meshes instantly. `StatusReport.connected`
      surfaces the state; `ctl connect|disconnect` is the CLI. The engine **Windows service stays
      resident** (auto-start); the GUI keeps only a **start** affordance for the stopped case (no
      socket to talk to until it's running) — routine stop/restart is gone (mesh disconnect replaces
      it). Verified: `netcfg` pause-persistence test + 2 GUI reducer tests (connect busy/clears,
      status carries connection state).
- [x] `expose` / `unexpose` / exposed-ports list — added in M7d (the engine now backs them over
      the control socket).
- [x] **Networks list + per-network peering toggle** — a device can enable/disable peering on
      each of its networks (role@guild) from the GUI (or `ctl net enable|disable <network>`).
      **Client is the source of truth**: the opt-out set is persisted locally
      (`<state_dir>/network_optout.json`) and enforced by filtering seeds, so it works even when
      the coordinator is **unreachable** — a toggle wakes the daemon (`tokio::Notify`) to re-mesh
      from the last snapshot at once. The set rides along in every `RegisterReq.disabled_networks`;
      the coordinator mirrors it (excludes those from presence/grant/seeds both ways) → symmetric
      when reachable, auto-syncs on reconnect. `RegisterResp`/`StatusReport` carry `NetworkStatus`
      (guild/role/name/enabled). Verified: `scripts/net-toggle-test.sh` (3 nodes/2 nets — online:
      A disables mesh2 → drops C both ways, keeps B, re-enable → C returns; **offline**:
      coordinator killed → `ctl net disable` still succeeds and A drops C locally) + GUI unit tests.
- [x] **Interactive login (OAuth)** — `unitylan login <config>` runs Discord OAuth2 (auth-code):
      the coordinator is a confidential client (holds the secret, exchanges server-side), so the
      client only opens the authorize URL and polls register. `/oauth/start` (mint state → pubkey)
      + `/oauth/callback` (exchange code → bind pubkey→user in `oauth_authorized`); `resolve_user`
      accepts an OAuth-bound device. A `FakeOauth` provider (parses `user:<id>`) backs offline
      tests. PKCE deferred (unnecessary for a confidential server-mediated flow). Two frontends:
      the headless/direct `unitylan login`, and the **GUI/daemon-mediated** path — the daemon now
      serves the control socket *before* enrollment (reporting `needs_login` instead of bailing),
      the GUI shows a **Log in with Discord** button (`ControlRequest::Login` → authorize URL), and
      the daemon's register loop binds the device + brings up the mesh once the browser completes.
      Verified: `scripts/oauth-test.sh` (direct: no-key refused → login → fake callback → register
      succeeds) and `scripts/gui-login-test.sh` (daemon-mediated: needs_login → `ctl login` → fake
      callback → daemon meshes).
- [ ] Tray — deferred: the engine doesn't yet back it over the socket (post-M5).

**Verify:** 4 reducer unit tests (status/devices/error/rename paths); launch smoke (window +
wgpu/tiny-skia renderer + timer subscription + async socket task boot clean). The socket
protocol itself is the same one `mesh-test.sh` exercises via the `ctl` CLI.

---

## M5 — NAT traversal
**Goal:** reach members behind NAT. Split by reachability class: *reachable* (UPnP / forward →
dialable), *cone-NAT'd* (hole punch), *symmetric-both* (diagnostics only, §7.2 non-goal).
Punch architecture (settled): **coordinator-mediated + peer-observed reflexive** — reuses the
long-poll/presence/endpoint cache already built; the simultaneous long-poll wake *is* the punch
sync signal; reflexive endpoint is read from a reachable peer's view of us (no STUN server — the
WG socket is owned by boringtun, so a side-socket STUN is impossible). Corrects design §3.1's
"reflect the refresh source" note: refresh is HTTP/TCP, a different NAT mapping than the WG UDP
port — useless for punch.

### M5.1 — UPnP + endpoint autodiscovery ✅
- [x] `nat.rs`: UPnP-IGD (`igd-next`) maps the WG UDP port, learns external `ip:port`, renews the
      lease at half-life. Best-effort: no gateway / refusal → advertise no endpoint (be dialed).
- [x] Endpoint precedence in the daemon: explicit `endpoint` (manual forward) > UPnP-mapped > none;
      the result rides every register/refresh (existing plumbing). `upnp = true` default, skipped
      when `endpoint` is set.
- **Verify:** ✅ `mesh-test.sh` green (explicit-endpoint path unchanged; UPnP skipped when set).
      Live UPnP path needs a real IGD router (or the `mock-igd` crate) — manual/opportunistic.

### M5.2 — Coordinator-mediated hole punch (cone NAT) ✅
- [x] **Spike (gate)** ✅ — defguard `read_interface_data()` exposes each peer's last-seen source
      endpoint (`Host.peers[k].endpoint`, parsed from the boringtun uapi `get` dump) on every
      backend. Peer-observed reflexive is viable.
- [x] `WgBackend::peer_endpoints()` — reads the endpoint WG last saw each peer send from. The
      daemon reports these as `RegisterReq.observed`; a reachable peer (A) thereby tells the
      coordinator every NAT'd co-member's reflexive `ip:port`. The read is retried (boringtun's
      uapi is racy under load) and re-polled every ~2s so a freshly-learned reflexive is reported
      promptly (the long-poll hold would otherwise sit on it for ~TTL/2); a failed read is treated
      as "unchanged" so it never flaps a spurious report.
- [x] API: `RegisterReq.observed: Vec<ObservedEndpoint>` + `Seed.punch: Option<SocketAddr>`.
      Coordinator caches reflexives (`AppState.reflexive`, last-writer-wins) and `punch_target`
      sets `punch` for a peer only when **neither** side is directly dialable (else the dialable
      one is reached via `endpoint`); a new/roamed reflexive bumps the version so parked peers wake.
- [x] Daemon: a seed carrying `punch` → set that peer's WG endpoint (`endpoint.or(punch)`) and
      handshake it; both sides wake on the same version bump → simultaneous open.
- **Verify:** ✅ `scripts/nat-test.sh` (3 netns, A reachable + B & C behind separate full-cone
      NATs): A observes both reflexives → coordinator pairs them → **B dials C's reflexive and C
      dials B's** (gated). Plus `punch_target` unit test. The final UDP data-plane hop (ping over
      the punched tunnel) is reported **best-effort, not gated**: Linux netns MASQUERADE/DNAT can't
      faithfully emulate an endpoint-independent NAT's simultaneous-open (conntrack clash — proven
      with a standalone raw-socket punch); real cone/full-cone routers punch fine. `mesh-test.sh`
      still green (no regression from the reflexive-reporting loop changes).

### M5.3 — NAT / reachability diagnostics ✅
- [x] Per-peer reachability classifier (`common::control::classify_reach`): a peer is `Direct`
      (dialable, or a hole punch whose WG handshake completed), `Punching` (dialing a reflexive,
      within a 30s grace window), or `Unreachable` (punch outstanding past the window with no
      handshake — the symmetric-NAT-both-ends tail; no relay in v1, §7.2).
- [x] `WgBackend::peer_stats()` surfaces each peer's last-seen endpoint **and** last-handshake
      time; the daemon classifies every peer each loop and overlays it onto the control-socket
      status (`control::set_reach`, cheap — no DNS/firewall work) so a stuck punch shows up even
      when nothing else changes. `StatusReport`/`PeerStatus` gain `reach`.
- [x] `ctl status` annotates a peer `[hole-punching…]` / `[unreachable: symmetric NAT?]`; the GUI
      renders the same `PeerReach` from the shared status.
- **Verify:** ✅ `classify_reach` unit test (all transitions). `nat-test.sh` surfaces the state over
      `ctl status` (informational there — netns produces a one-sided handshake so B records a
      handshake for C and reads `Direct`; the `last_handshake` liveness signal is correct on real
      networks, where a lost return path also fails the handshake). `mesh-test.sh` still green.

---

## M6 — DNS + multi-homing
**Goal:** `*.internal` names resolve on the OS; overlapping networks work on one interface.
- [x] `dns.rs`: `.internal` authoritative resolver from verified attestations — built in M-device ch5.
- [x] **Per-OS resolver hookup (Linux)** ✅ — `resolver.rs`: `ResolverHook` trait + systemd-resolved
      backend (`ResolvectlHook`). On iface-up the daemon points resolved at our resolver via a
      **per-link `~internal` routing domain** (`resolvectl dns <iface> <server>` + `domain <iface>
      ~internal`), so only `*.internal` lookups go to us — global DNS untouched. Reverted on clean
      shutdown (`resolvectl revert`); also clears with the link. `resolver_hook = true` default,
      best-effort (needs privilege — the daemon already runs privileged; a failure only means names
      don't auto-resolve). The resolver binds loopback (`dns_bind`) and resolved routes to it because
      the wg iface is operational (carries its `/32`) — resolved ignores per-link DNS on a
      non-operational link. macOS `/etc/resolver` is a future backend behind the trait.
- [x] **Per-OS resolver hookup (Windows)** ✅ (M-win2) — `resolver/windows.rs`: `NrptHook` drives the
      Name Resolution Policy Table via PowerShell (`Add-DnsClientNrptRule -Namespace '.internal'
      -NameServers <ip>` / `Remove-DnsClientNrptRule`). NRPT is namespace-scoped (system-wide), not
      link-scoped — same split-horizon effect as resolved's routing domain. Every rule carries
      `-Comment UnityLAN`, so `install` clears stale rules then re-adds (idempotent) and `revert`
      removes only ours. Two NRPT constraints vs. Linux: nameservers are port-53-only (`install`
      errors if `dns_bind` isn't on :53), and rules persist across an unclean exit (self-healed by the
      clear-on-install). `resolver.rs` split into `resolver/{mod,linux,windows}.rs` mirroring `fw/`;
      `platform_hook()` now selects resolved (Linux) vs NRPT (Windows). Needs elevation.
- [x] **Multi-homing / cross-network isolation** ✅ — obsolete under **Model B** (design §6): one
      device IP in a flat `100.64/10`, networks are pure ACL. Isolation is already enforced by
      seed-scoping (you only peer co-members sharing ≥1 network) + the firewall's `--net` source
      scoping (M7c-2), not per-role `/32`s.

**Verify:** ✅ 2 `resolver/linux.rs` unit tests (resolvectl arg construction) + 2 `resolver/windows.rs`
tests (NRPT script construction); `scripts/resolver-hook-test.sh` (live, root) — on this host's real
systemd-resolved, scoped to a throwaway link: the daemon's actual `ResolvectlHook` routes `.internal`
and `resolvectl query host-a.alice.lan.internal → 100.64.0.9`, then reverts. `mesh-test.sh` still
green (in-netns the hook warns best-effort — no resolved there). Windows NRPT: builds + unit tests
pass on Windows; the `resolver-install`/`resolver-revert` dev subcommands drive the real `NrptHook`,
and the port-53 guard errors cleanly. Live NRPT rule install + `.internal` resolution needs an
elevated box. macOS `/etc/resolver` still deferred.

---

## M7 — Revocation, expose, status polish
**Goal:** losing a role cuts you off; expose local ports; solid status.

### M7a — Revocation core ✅
- [x] **Client prune**: `apply_seeds` removes peers absent from the current seed set (was
      add-only). A revoked/departed co-member drops out of the coordinator's presence → its
      next-absent refresh removes the peer + reinstalls routing. Grant→None mid-loop (own role
      lost) prunes every peer, isolating us.
- [x] **Coordinator stop-signing + self-eviction**: `build_snapshot` skips networks the caller
      no longer holds (no grant/seed) *and* evicts the caller's stale presence from any network
      it dropped, bumping the version so parked long-polls wake and prune. `Presence::evict` /
      `evict_user` / `networks_of` (unit-tested).
- [x] Client TTL refresh at half-life — already via the long-poll hold (~TTL/2); revocation
      propagates on the next woken refresh.
- **Verify:** ✅ `mesh-test.sh` — after the mesh pings, node B's role is stripped and the
  coordinator restarts; node A prunes peer B (log + `ctl status` no longer lists it).

### M7b — Live gateway revocation (immediate, prod trigger) ✅
- [x] Gateway `MEMBER_UPDATE`/`MEMBER_REMOVE` (GUILD_MEMBERS intent) → `presence.evict_user` for
      every network whose role the member no longer holds + version bump → parked long-polls wake
      and prune instantly, even when the revoked node is offline. `presence`/`version` wired into
      the gateway task. Verified-by-construction (compiles against twilight's event model); no
      headless test — needs a live Discord guild.
- [ ] Optional persisted tombstones (survive coordinator restart before the live role re-check) —
      deferred: the live role re-check on re-register already blocks a revoked member.

### M7c — expose (enforcing firewall)
- [x] **Firewall core** ✅ — `FirewallBackend` trait + Linux nftables backend (`inet unitylan`,
      atomic `nft -f -` load). Default-deny new inbound on the wg iface; allow established/related
      + ICMP echo; accept only exposed ports. On by default (`firewall = true`); fail-closed at
      startup if nft errors. Backend-agnostic so Windows WFP / macOS pf drop in later (both kernel
      and userspace WG deliver decrypted packets through the OS stack, so the rules are identical).
- [x] `ctl expose <port> [tcp|udp]` / `unexpose` / `exposes` over the control socket → `Firewall`
      reconciles the whole ruleset; config `[[expose]]` seeds initial ports. Clean shutdown
      (ctrl_c) tears the table down.
- **Verify:** ✅ `mesh-test.sh` firewall phase — 9001 blocked by default-deny, reachable after
      `ctl expose 9001`, never-exposed 9002 stays blocked, blocked again after `unexpose`; ping
      (ICMP) survives throughout. Plus 2 nft ruleset unit tests.
- [x] **`--net <role>` source scoping** ✅ (M7c-2): `expose <port> --net <role>` opens the port
      only to that network's peers. `Seed.networks` (per-peer shared-network names) added to the
      API; the client groups peer IPs per network (`peers_by_net`, refreshed each membership
      change) and nft emits a named `ipv4_addr` source set + `ip saddr @set … dport … accept`.
      `--net` is validated against the device's held networks. **Verify:** ✅
      `scripts/expose-net-test.sh` — 3 nodes / 2 nets (A∈{mesh,mesh2}, B∈mesh, C∈mesh2): B reaches
      A's mesh-scoped 9001 but not mesh2-scoped 9002; C the reverse; expose to a non-held network
      is rejected. Plus 2 nft scoped-ruleset unit tests.
- [x] **Windows firewall backend** (M-win): `WindowsFwBackend` drives Windows Defender Firewall via
      PowerShell `New-NetFirewallRule`/`Remove-NetFirewallRule` (group `UnityLAN`), each rule an
      inbound-allow scoped to the wg iface (`-InterfaceAlias`), `--net` exposes carrying
      `-RemoteAddress` peer sets. Relies on the OS's stateful default-deny-inbound for the base
      policy. `fw::default_backend()` selects nft (unix) vs this (Windows). 3 arg-construction unit
      tests. macOS pf still a future backend.

### M7d — status polish ✅
- [x] GUI surfaces the firewall: an **exposed ports** section (proto/port + `→ net:` scope) with
      per-row **unexpose** buttons and an **expose** row (port `25565` or `udp/34197`, optional
      net). Auto-refreshed on the 2s tick over the same control socket the CLI uses.
- [x] Revocation events show implicitly — a pruned peer drops out of the auto-refreshed peers
      list. **Verify:** 4 new GUI reducer tests (exposes list / valid submit clears inputs / bad
      port surfaces error / `parse_port`); launch smoke clean. 36 unit tests total.

---

## M8 — Native kernel backends (optimization)
**Goal:** faster path where the OS offers it.
- [x] **Windows WireGuardNT** (M-win): `wg/windows.rs` `KernelBackend` drives defguard's
      `WGApi<Kernel>` (wireguard-nt). Since defguard's Windows `configure_peer`/`remove_peer` are
      no-ops, it holds the desired iface + peer state and re-applies the full `configure_interface`
      on every change (endpoint-less peers skipped — wireguard-nt requires an endpoint).
      `wg::new_backend()` selects userspace (unix) vs this (Windows). Needs elevation + `wireguard.dll`.
- [ ] `wg/native.rs`: Linux netlink; select native when present, else userspace; parity tests.

**Verify:** same behavior as userspace on Linux + Windows, measurably lower overhead.

---

## Cross-cutting (ongoing)
- [ ] `tracing` logging across binaries.
- [~] Per-OS service packaging (systemd unit · **Windows Service** ✅ · launchd plist).
      **Windows Service** landed (M-win2): `service.rs` wraps the engine as a `LocalSystem`
      auto-start service via the `windows-service` crate. `service install [config.toml]` registers
      it (config canonicalized to an absolute path + baked into the SCM command line, since a service
      runs with CWD=System32); `service uninstall` stops + deletes; `service run` is the SCM entry
      (dispatcher → control handler translating Stop/Shutdown into the daemon's shutdown signal). The
      daemon's shutdown was refactored off `ctrl_c()` onto a shared `shutdown::Shutdown` (watch-based,
      fire-once) so console mode (Ctrl-C) and the service (SCM Stop) share one path. Service logs to
      `unitylan-engine-service.log` next to the exe (no console). **GUI service control** (M-win2):
      `install` relaxes the service DACL (`sc.exe sdset`, `RELAXED_DACL`) so the interactive user gets
      `SERVICE_START`/`SERVICE_STOP` — the unprivileged GUI (`gui/src/svc.rs`) queries status and can
      **start** the engine with no UAC prompt (blocking SCM calls hopped onto `spawn_blocking`). The GUI
      shows an "engine" section: running/stopped/not-installed; `WINDOWS_SERVICE_NAME` lives in `common`
      so engine + GUI can't drift. **Note (M4 connect/disconnect):** the service is meant to stay
      **resident** (auto-start) — day-to-day on/off is a mesh connect/disconnect over the control socket
      (which needs no SCM access at all), so the GUI now keeps only **start** here (bootstrap when the
      engine is stopped and there's no socket yet); routine stop/restart is gone. Stopping the service
      only drops the mesh (firewall rules are scoped to the vanishing wg iface), so it can't open the
      host. Still TODO: an MSI/WiX installer to bundle engine+gui+`wireguard.dll`, register the service,
      and write a default config; systemd + launchd packaging. Follow-up: with GUI stop gone, the `WP`
      (`SERVICE_STOP`) grant in `RELAXED_DACL` could be dropped to `SERVICE_START` only.
- [ ] CI: `cargo fmt`/`clippy`/`test`.
- [x] Endpoint-record spoof hardening ✅ — the coordinator accepts a peer-observed reflexive
      (`RegisterReq.observed`) only for a pubkey the caller actually meshes with (a co-member seed),
      via `accepted_reflexives`. Was: any authenticated member could write an arbitrary endpoint for
      any device → redirect that device's co-members' WG punch target to an attacker-chosen address
      (DoS + a "point a member's handshakes at arbitrary ip:port" reflector; no confidentiality break
      — WG auths by pubkey). Now bounded to the network trust boundary (a victim's own co-members).
      Verified: `reflexive_reports_accepted_only_for_comembers` unit test; `nat-test.sh` still green.
- [x] Coordinator key rotation ✅ — signed `prev → new` rotation certs (`RotationCert`, signed by
      the outgoing key) served as an ordered chain in every `RegisterResp`; a client whose pin is
      superseded walks the chain (verifying each hop under the key it already trusts) and re-pins to
      the current anchor without manual steps. Multi-hop, so a client offline across several
      rotations still catches up; a gap the chain can't bridge is refused (MITM preserved → manual
      re-pin). Trigger: offline `coordinator rotate-key <config>` admin subcommand + restart.
      Verified: 5 `walk_chain` unit tests (multi-hop, forged-cert, rollback, no-path);
      `scripts/rotation-test.sh` end-to-end (TOFU pin → A→B→C re-pin → unrelated-key refusal);
      `mesh-test.sh` still green.
- All GA-blocker design items (design.md Open Questions) are now closed: symmetric-NAT policy,
  pubkey re-key signal, coordinator key rotation. Remaining pre-GA work is packaging/perf, below.
- [x] Pubkey re-key signal ✅ — a re-keyed device passes its old device token as `supersede`; the
      coordinator authenticates ownership and retires the old pubkey at once (drops the device row,
      evicts presence). A presence reaper (`PRESENCE_TTL_SECS`) backstops it and any unclean drop
      (crashed/dropped client) that would otherwise linger until coordinator restart. Verified:
      `should_supersede` + `reap_evicts_only_stale_entries` +
      `record_refreshes_last_seen_without_reporting_change` unit tests; `mesh-test.sh` still green.
- [x] Symmetric-NAT policy ✅ — v1 settled as best-effort + `[unreachable: symmetric NAT?]`
      diagnostic, no relay (design.md §7.2). System already degrades cleanly; no code change.

## Post-GA
- [ ] Symmetric-NAT-both relay: data-plane forward through a common mesh peer for pairs where both
      ends are symmetric-NAT'd (punch structurally can't work). Relay sees WG ciphertext only
      (e2e intact); design must cover relay-peer selection/authorization + consent/DoS surface.
      Deferred: rare for home peers, mostly corporate/CGNAT.
