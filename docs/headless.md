# UnityLAN — Headless servers

Putting a machine with no desktop on the mesh: a game server, a media box, a NAS. Everything here
is CLI. For the desktop app, see [`user-guide.md`](user-guide.md).

The shape of it: install the engine, enroll once with a key minted from Discord, then open the port
your service listens on. No browser needed on the box, and no Discord client.

## 1. Install

Install the `unitylan` package — engine and CLI, no graphics libraries. Packages are attached to
each [release](../../releases); x86-64 only for now.

## 2. Mint an enrollment key

From Discord, in a channel where the bot is present:

```
/unitylan enroll
```

The bot replies **only to you** with a key like `unl_a1b2…`. It's **single-use** and expires in
about **15 minutes** — mint it right before you need it, and don't paste it into a shared channel.
Expired before you got there? Run it again.

## 3. Configure

Write `/etc/unitylan/engine.toml` — at minimum a coordinator and a state directory. Use
[`engine.example.toml`](../engine.example.toml) as a template:

```toml
coordinator = "https://coordinator.unitylan.com"
state_dir = "/var/lib/unitylan"
device_name = "gameserver"   # optional; defaults to the system hostname
```

The name matters: this box becomes `gameserver.<you>.unity.internal`, which is what people will
type.

## 4. Enroll

Two ways to hand over the key. Prefer the first — it never reaches disk:

```sh
sudo unitylan-engine --token unl_a1b2… run
```

Or put `enrollment_key = "unl_a1b2…"` in `engine.toml` and start the service:

```sh
sudo systemctl enable --now unitylan-engine
```

The first registration binds the box's WireGuard public key to your Discord account and consumes the
key. From then on the box is known by its key, and the enrollment key no longer matters — delete it
from the config.

`UNITYLAN_ENROLLMENT_KEY` in the environment works too, and is safer than the flag: an argv value is
visible to every local user through `ps` and `/proc/<pid>/cmdline`, while the environment is
readable only by the process owner.

## 5. Open the port

Nothing is reachable until you say so — the mesh firewall drops all inbound except what you share.

```sh
sudo unitylan-engine ctl status                        # confirm it's on the mesh
sudo unitylan-engine ctl expose 25565 minecraft        # to one network's members
sudo unitylan-engine ctl expose udp/34197 gaming       # ...and another network
sudo unitylan-engine ctl expose 22 --own-devices       # to your own machines only
sudo unitylan-engine ctl exposes                       # what's open, and to whom
```

Every exposure names who it is for — a network, or `--own-devices`. There is no "everyone": the
widest sharing the mesh can express should never be what you get by typing least, so it is not a
default and there is no flag for it. A port exposed that way before this stays open and keeps
working; nothing is taken away, there is just no way to choose it afresh.

Scopes stack: run `expose` again with a different network to open one port to several, then close
them individually with `unexpose … --net <name>`. `unexpose <port>` with no scope closes every scope
of it. If two of your Discord servers have a role with the same name, disambiguate with
`--guild <name>`.

Two shapes worth knowing:

- **A game server** usually wants one port open to one network — the role that represents "people
  allowed on my server". Kick someone from the role and they're off.
- **A media or file host** often wants `--own-devices` for admin access (SSH, the web UI) plus a
  network scope for the service itself, so your friends can watch but not administer.

## 6. Name it

A port that people have to remember by number is a port they will ask you about. Name it instead:

```sh
sudo unitylan-engine ctl service add mc 25565 --net minecraft   # mc.<you>.unity.internal
sudo unitylan-engine ctl service add jellyfin 8096 --own-devices  # just your own machines
sudo unitylan-engine ctl services                               # names, ports and who can reach them
sudo unitylan-engine ctl service scope mc --net gaming          # also offer it to another network
sudo unitylan-engine ctl service rm mc                          # stop serving it, closing its ports
```

`service add` is `expose` plus a name, so everything above about scopes applies unchanged — including
that a name is only announced to peers who could reach the port anyway. A port opened by `expose`
with no name of its own is called `port-<number>`: every exposure is a service, so there is no second
kind of thing to keep track of. Re-run `service add` with the same port and scope to give one a real
name in place. Run it twice with the same
name to put one service on two ports (a game wanting TCP and UDP), and `service rm` closes both.

`service scope` offers an existing one to another network without restating it: name the service and
the network, and every port it runs on opens there. Nothing to look up, and no way to add a port by
mistyping one — which is what happens if you reach for `service add` instead and get the number
wrong. Saying it twice is a no-op. Like every other kind of sharing it insists on `--net` or
`--own-devices`.

One machine can carry as many names as it runs things: `mc`, `jellyfin`, `git`. They all resolve to
this device, from any meshed machine, with nothing to configure on the other end.

Names travel peer to peer rather than through the coordinator, so allow up to 30 seconds for one to
reach other people, and expect an offline device to advertise nothing. A device name always wins over
a service label — you cannot take a machine's own hostname by naming a service after it.

**A service a browser opens wants `--web`:**

```sh
sudo unitylan-engine ctl cert on                                 # once per device
sudo unitylan-engine ctl service add jellyfin 8096 --web         # jellyfin.<you>.<domain>
```

That puts the service's name in this device's certificate, so a browser reaches
`https://jellyfin.alice.mesh.unitylan.com` with no warning page. It is the one part of services the
coordinator is told about — only it can publish the DNS record the certificate authority checks — and
it stores nothing beyond the label. Everything in the certificate section below applies: it is opt-in,
and the name is published to public Certificate Transparency logs permanently.

`ctl services` then lists it under that name rather than its `.unity.internal` one — that one still
resolves, but no certificate covers it, so a browser rejects it. Its port is shown as what it is, the
local one the proxy forwards to:

```
jellyfin  (jellyfin.alice.mesh.unitylan.com)
    https  ·  tcp/8096 behind it (My devices)
mc  (mc.alice.unity.internal)
    tcp/25565 (minecraft)
```

**Jellyfin itself needs no TLS configuration.** The engine runs a small TLS proxy
(`unitylan-proxy`) that serves your web services on the mesh and forwards to them over plain HTTP on
loopback, so several of them share port 443 under different names and none of them has to learn about
certificates. It reads its whole configuration from the engine as it changes, so a renewal or a newly
named service needs no restart.

It runs as its **own unprivileged user**, because parsing web requests from mesh peers has no
business happening in a daemon that holds your WireGuard keys. The packages create that account and
put it in the certificate key's group; if you built from source, say who it should be:

```toml
[proxy]
user = "unitylan-proxy"    # required when the engine runs as root
# enabled = false          # ...or turn it off and serve TLS yourself with nginx/Caddy
[cert]
group = "unitylan-proxy"   # so the proxy can read the key
```

A root engine with no `[proxy] user` **refuses to start the proxy** and logs what to set, rather than
running it as root — that would look like it worked while giving away the isolation it exists for.

Two behaviours to expect. Naming several web services in a row reissues **once**, about ten minutes
after you stop — CAs cap certificates per domain per week and that cap is shared by every device on
your coordinator, so a burst is batched rather than spent one at a time. And a label another of your
devices already registered is refused rather than moved: the service still runs and still resolves,
it just is not certified, and `ctl services` says so.

These commands find `/etc/unitylan/engine.toml` on their own. An `engine.toml` in the working
directory wins if there is one, and `-c <path>` overrides both — worth remembering when a command
seems to be talking to the wrong daemon.

## Serving HTTPS without a warning page (optional)

Mesh names end in `.unity.internal`, which ICANN reserves — no certificate authority will ever
certify one, so a browser hitting your media server over the mesh gets a warning page and no amount
of configuration fixes it.

If your coordinator is configured with a certificate domain, every device also answers to an alias
under it, and can obtain a **publicly-trusted certificate** for that alias itself. On the canonical
coordinator the domain is `mesh.unitylan.com`, so `mediabox.alice.unity.internal` is also
`mediabox.alice.mesh.unitylan.com`.

```sh
sudo unitylan-engine ctl cert            # show the current state
sudo unitylan-engine ctl cert on         # opt in
sudo unitylan-engine ctl cert off        # stop issuing and renewing
```

With a certificate held, `ctl cert` prints what a TLS server's config needs:

```
certificates: on (domain mesh.unitylan.com)
  certificate  /var/lib/unitylan/certs/cert.pem
  private key  /var/lib/unitylan/certs/key.pem
  covers       mediabox.alice.mesh.unitylan.com, *.mediabox.alice.mesh.unitylan.com
  expires      in 74 days
```

Point nginx, Caddy, Jellyfin, or whatever you're running at those two paths. Renewal is automatic;
the paths don't change.

**The wildcard is what makes this useful behind a reverse proxy.** One certificate covers every name
one label below the device — `jellyfin.mediabox.alice.mesh.unitylan.com`,
`grafana.mediabox.alice.mesh.unitylan.com`, as many as you run — and each of those resolves to this
machine already, so nothing needs adding on the client side or at the coordinator. Give Caddy or
nginx one TLS block reading the two paths above, and route by `Host` from there; a new service is a
new vhost, not a new certificate.

It is deliberately anchored under *this device* rather than under your account. `*.alice.mesh.unitylan.com`
would match your other devices' own names, so any one machine holding it could serve TLS for the
rest of them.

**Read this before turning it on.** Issuing a certificate publishes this device's name to public
**Certificate Transparency logs, permanently** — that's how CT works, and it applies to every
publicly-trusted certificate. Anyone can search those logs. Turning the option back off later stops
renewal but does **not** unpublish what's already there. That's why it's off by default and opt-in
per device.

Three things must all be true for issuance to happen: the coordinator has a certificate domain
configured, this device exposes at least one port (a certificate is only useful if something is
listening), and you've opted in. `ctl cert` names whichever one is missing.

The client is deliberately cautious with the CA's rate limits — it creates its ACME account once per
device lifetime, refuses to reissue while a valid certificate is held, and backs off failures up to
a day. A crash-looping daemon can't burn a week's allowance.

## Day-to-day

```sh
sudo unitylan-engine ctl status                   # peers, addresses, reachability
sudo unitylan-engine ctl devices                  # everything enrolled under your account
sudo unitylan-engine ctl rename mediabox          # change this box's hostname
sudo unitylan-engine ctl net disable gaming       # stop peering with one network
sudo unitylan-engine ctl own-devices off          # stop peering with your own devices
sudo unitylan-engine ctl disconnect               # mesh down, daemon stays up
sudo unitylan-engine ctl connect                  # and back up
sudo unitylan-engine ctl block someone#1234       # locally drop every device of one account
sudo unitylan-engine ctl update                   # apply a staged, verified update
```

`ctl status` is the one to reach for first — it shows whether the coordinator is reachable, which
networks are active, and every peer's address and path type (`direct`, `ice`, `relayed`).

## Watching it live

The daemon pushes a fresh status on every change, so subscribe instead of polling:

```sh
sock=/var/lib/unitylan/control.sock     # your state_dir
printf '"Watch"\n' | socat -t 86400 UNIX-CONNECT:$sock - \
  | jq --unbuffered -c '.Status.peers[]? | {name: .hostname, up, reach, lat: .latency_ms}'
```

For more detail, set `RUST_LOG=debug` (or `RUST_LOG=unitylan_engine=debug`) in the service
environment and restart. `log_file` in `engine.toml` appends to a file as well as the journal; a
relative path lands under `state_dir`.

## Removing a box

Stop the daemon first — it reverts the interface, firewall, and resolver hook on shutdown — then:

```sh
sudo unitylan-engine uninstall            # un-enroll at the coordinator, keep local state
sudo unitylan-engine uninstall --purge     # also wipe keys, token, and pinned anchors
```

Then remove the package. Un-enrolling is what returns the mesh address to the pool.

## Full CLI reference

| Command | What it does |
| --- | --- |
| `run` | Run the daemon in the foreground (Ctrl-C stops it) |
| `login` | Interactive Discord login; prints a URL to open elsewhere |
| `uninstall [--purge]` | Un-enroll, optionally wiping local state |
| `wg-keygen` | Print a fresh WireGuard keypair |
| `ctl status` | This device, its networks, and every peer |
| `ctl devices` | Devices enrolled under your account |
| `ctl rename <name>` | Rename this device |
| `ctl set-primary <device>` | Choose which device the bare `<user>` name resolves to |
| `ctl remove <device>` | Un-enroll one of your devices |
| `ctl expose <port> [net]` | Open a port — `--own-devices` or `--guild` to scope it |
| `ctl unexpose <port>` | Close a port, or one scope with `--net` / `--own-devices` |
| `ctl exposes` | List open ports and who can reach them |
| `ctl service add <name> <port>` | Name a port — same scope flags as `expose` |
| `ctl service rm <name>` | Stop serving a name, closing every port it was on |
| `ctl services` | List this device's named services and the names they answer to |
| `ctl net <enable\|disable> <network>` | Peer with a network, or stop |
| `ctl own-devices <on\|off>` | Peer with your own devices, or stop |
| `ctl cert [on\|off]` | Show the TLS certificate and its paths, or opt in and out of issuance |
| `ctl block <user>` / `ctl unblock <user>` | Locally drop every device of one Discord account |
| `ctl connect` / `ctl disconnect` | Mesh up or down without stopping the daemon |
| `ctl update` | Apply a staged, verified update |
| `ctl login` | Start a Discord login; prints the URL |

Every `ctl` command talks to the running daemon over its control socket, so all of them need root.
