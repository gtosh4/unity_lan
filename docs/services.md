# UnityLAN — Services and HTTPS

How to put something on your machine in front of the people you mesh with, under a name they can
type — and, if it's a website, under a real HTTPS certificate a browser already trusts.

This page is the map. The desktop app's version of every step is in
[`user-guide.md`](user-guide.md#letting-people-reach-something-on-your-machine); the full CLI is in
[`headless.md`](headless.md#6-name-it).

## What a service is

An **exposed port with a name**. That's the whole model — there is no second kind of thing.

Joining a network opens nothing. Until you say otherwise a peer can ping you and nothing else. When
you do open a port, you say *who for*: a network, or your own devices. There is no "everyone".

Naming it gives it a DNS name on the mesh:

```
mc.alice.unity.internal          # a Minecraft server on alice's machine
jellyfin.alice.unity.internal    # a media library
```

Anyone meshed with you resolves those with nothing to configure. A port you opened without naming it
shows up as `port-25565`; re-adding it with a name renames it in place.

Names travel **peer to peer, not through the coordinator**, so a new one takes up to 30 seconds to
reach other people and survives a coordinator outage. An offline device advertises nothing.

## Naming one

<table>
<tr><th>Desktop app</th><th>Headless</th></tr>
<tr valign="top"><td>

**Services** tab → **expose a service** → name, port, TCP/UDP, and a scope → **expose**.

Chips under each service show who can reach it. **+** adds another scope, **x** removes one,
**remove** takes the service down and closes every port it was on.

</td><td>

```sh
sudo unitylan-engine ctl service add mc 25565 --net minecraft
sudo unitylan-engine ctl service add jellyfin 8096 --own-devices
sudo unitylan-engine ctl services
sudo unitylan-engine ctl service scope mc --net gaming
sudo unitylan-engine ctl service rm mc
```

</td></tr>
</table>

Scope is required — `--net <network>` or `--own-devices`. A service offered to one network is
**invisible** to everyone else: people outside it aren't told the name exists, so nothing leaks
about what you run.

One machine can carry as many names as it runs things. The same name on two ports is one service (a
game wanting TCP and UDP); `service rm` closes both.

## Serving a website over HTTPS

Mesh names end in `.unity.internal`, which ICANN reserves — **no certificate authority will ever
certify one**, so a browser opening your media server over the mesh gets a warning page and no
amount of configuration fixes it.

The fix is a second name. If your coordinator is configured with a certificate domain, every device
also answers to an alias under it and can obtain a **publicly-trusted certificate** for that alias
itself. On the hosted coordinator that domain is `mesh.unitylan.com`, so
`mediabox.alice.unity.internal` is also `mediabox.alice.mesh.unitylan.com`.

Two steps:

```sh
sudo unitylan-engine ctl cert on                          # once per device
sudo unitylan-engine ctl service add jellyfin 8096 --web  # per web service
```

In the app: tick **Get an HTTPS certificate for this device** in **Manage**, then **It's a website**
beside the service in the **Services** tab.

Then `https://jellyfin.alice.mesh.unitylan.com` opens with no warning page — and **the app behind it
needs no TLS setup at all.** The engine runs a small TLS proxy that terminates HTTPS for your web
services and forwards to them over plain HTTP on loopback, so Jellyfin stays exactly as it was and
several services share port 443 under different names. It picks up a renewed certificate or a
newly-named service without a restart.

The proxy is the engine binary re-executed as its **own unprivileged user** — parsing web requests
from mesh peers has no business happening in a daemon holding your WireGuard keys. It gets a
read-only control socket and the certificate key's group, and nothing else. Packages create the
account; from source, set `[proxy] user` and `[cert] group` in `engine.toml`
([details](headless.md#serving-https-without-a-warning-page-optional)).

### Or serve TLS yourself

`ctl cert` prints the certificate and key paths, and the certificate covers **every name one label
below your device** — `jellyfin.mediabox.alice.mesh.unitylan.com`, `grafana.mediabox.alice…`, as
many as you run, all resolving to the machine already. Point nginx or Caddy at the two paths, route
by `Host`, and a new site is a new vhost rather than a new certificate. Set `[proxy] enabled =
false` if you'd rather the built-in proxy stayed out of the way.

It stops one label below the device on purpose: `*.alice.mesh.unitylan.com` would match your *other*
devices' names, and one machine holding a certificate for the rest of yours is a bad trade.

### Before you turn it on

Issuing a certificate publishes that name to public **Certificate Transparency logs, permanently**.
That is how CT works and it applies to every publicly-trusted certificate anywhere. Anyone can search
those logs. Turning the option off later stops renewal but **cannot unpublish** what's already there.
That's why it's off by default, opt-in per device, and why marking a service as a website is a
separate deliberate tick rather than something naming it does for you.

The `--web` label is also the one part of services the coordinator is told about — only it can
publish the DNS record the CA checks — and it stores nothing beyond the label itself.

### Does my coordinator issue certificates?

Three things must all be true, and `ctl cert` names whichever is missing:

| | |
| --- | --- |
| The coordinator has a certificate domain | The **hosted coordinator does** (`mesh.unitylan.com`). Self-hosting? See [coordinator-setup.md](coordinator-setup.md#certificate-domain-optional--publicly-trusted-tls-on-mesh-names) — it needs a domain you own and a delegated subdomain. |
| This device exposes at least one port | A certificate is only useful if something is listening. |
| You opted in | `ctl cert on`, or the checkbox in **Manage**. |

In the app the checkbox is **hidden entirely** until the first two hold, so there's nothing to click
that can't work.

Two behaviours to expect. Naming several web services in a row reissues **once**, about ten minutes
after you stop — CAs cap certificates per domain per week, and that cap is shared by every device on
your coordinator. And a label another of your devices already registered is refused rather than
moved: the service still runs and resolves, it just isn't certified, and the list says so.

## When it doesn't work

- **Nothing arrives** — [troubleshooting.md § No HTTPS certificate arrives](troubleshooting.md#no-https-certificate-arrives)
  decodes each `ctl cert` status line.
- **A valid certificate but the browser can't connect** — on a **packaged Linux install before
  v0.6.1** the proxy could not start at all (wrong install path, missing unit capabilities).
  Upgrade; there is no workaround on the old packages.
- **The name doesn't resolve** — [troubleshooting.md § Names don't resolve](troubleshooting.md#names-dont-resolve).

## For coordinator admins

Serving certificates means delegating a subdomain to the coordinator so it can answer the
`_acme-challenge` TXT record, plus a deployment-wide weekly issuance budget. Full setup, the DNS
delegation, and the reasoning behind the cap:
[coordinator-setup.md § Certificate domain](coordinator-setup.md#certificate-domain-optional--publicly-trusted-tls-on-mesh-names).
Verify the whole path with `scripts/cert-test.sh`.
