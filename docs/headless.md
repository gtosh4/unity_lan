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
sudo unitylan-engine ctl expose udp/34197              # to every peer you mesh with
sudo unitylan-engine ctl expose 22 --own-devices       # to your own machines only
sudo unitylan-engine ctl exposes                       # what's open, and to whom
```

Scopes stack: run `expose` again with a different network to open one port to several, then close
them individually with `unexpose … --net <name>`. `unexpose <port>` with no scope closes every scope
of it. If two of your Discord servers have a role with the same name, disambiguate with
`--guild <name>`.

Two shapes worth knowing:

- **A game server** usually wants one port open to one network — the role that represents "people
  allowed on my server". Kick someone from the role and they're off.
- **A media or file host** often wants `--own-devices` for admin access (SSH, the web UI) plus a
  network scope for the service itself, so your friends can watch but not administer.

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
| `ctl net <enable\|disable> <network>` | Peer with a network, or stop |
| `ctl own-devices <on\|off>` | Peer with your own devices, or stop |
| `ctl cert [on\|off]` | Show the TLS certificate and its paths, or opt in and out of issuance |
| `ctl block <user>` / `ctl unblock <user>` | Locally drop every device of one Discord account |
| `ctl connect` / `ctl disconnect` | Mesh up or down without stopping the daemon |
| `ctl update` | Apply a staged, verified update |
| `ctl login` | Start a Discord login; prints the URL |

Every `ctl` command talks to the running daemon over its control socket, so all of them need root.
