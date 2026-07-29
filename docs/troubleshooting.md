# UnityLAN — Troubleshooting

Symptoms first, each with what to check in the app and, where it differs, on a headless box. If
none of these match, ask in [Discord](https://discord.gg/QAmz2j54kS) or open an issue.

## Start here

**In the app:** the **Peers** tab. It shows whether the coordinator is reachable (the dot up top),
which networks are on, and every peer with its address, latency, and how it's being reached.

**Headless:** `sudo unitylan-engine ctl status` prints the same picture.

Either way, the line under each peer's name is the thing to read:

| | Meaning |
| --- | --- |
| **direct** | Straight peer-to-peer. Nothing in the middle. |
| **ice** | A hole punch got through. Also peer-to-peer, just harder-won. |
| **relayed** | Going through another member as ciphertext it can't read. |
| **no handshake yet** | Still setting up. Normal for a few seconds. |
| **unreachable** | No path found, or an established one went silent. |

## A peer shows unreachable

In order of likelihood:

1. **They're offline.** The common case.
2. **You don't share a network.** If the role you had in common was removed, they drop out of your
   list entirely. Check the **Networks** tab — you both need a network in common, or to be each
   other's own devices.
3. **The network is switched off** on one side, in **Networks**. (Headless:
   `ctl net enable <network>`.)
4. **Both ends are behind hard NAT** — CGNAT or symmetric NAT on both sides, or a network blocking
   the UDP transports. This is the known-maturing case: a relay member has to be online and opted in
   for the fallback to work, and if none is, the pair stays unreachable.

Give it a minute either way — punching and the relay fallback take a few attempt cycles.

## Peers look connected, but nothing works

**If you also run Tailscale on Linux:** this is almost certainly the address-range collision, and
the engine should already be handling it. Both products use `100.64.0.0/10`, and Tailscale installs
a firewall rule dropping that range on interfaces that aren't its own — which blackholes every
UnityLAN packet while peers still look fine. The engine detects the rule and narrowly exempts the
mesh interface (`tailscale_compat`, on by default), rechecking after each Tailscale restart.

**If you also run Tailscale on Windows:** not handled yet. Same collision, no workaround — that's
the explanation if mesh traffic vanishes while peers show as connected.

**Otherwise:** check the port is actually shared. Nothing on a machine is reachable until it's
exposed — the **Services** tab in the app, `ctl services` on a server. A peer can always ping you; anything else needs an entry there.

**If you're reaching it by name and it doesn't resolve**, that's the next section — but note a
service's name is only announced to peers its scope admits, so someone outside it sees nothing at
all rather than a refusal. That is deliberate; check the scope before assuming it's broken.

## Names don't resolve

The address works but `laptop.alice.unity.internal` doesn't.

- Names only resolve for peers **currently in your mesh**. A peer you can't reach is a peer whose
  name won't resolve.
- **Linux:** the resolver hook needs a live `systemd-resolved`. On a system using something else for
  DNS, it has nowhere to attach — use addresses, or point your resolver at the engine yourself.
- **Windows:** the rule is an NRPT entry applied by the service, so it needs the service actually
  running.

In the app, **copy hostname** / **copy IP** on a peer's **⋮** menu sidesteps typos while you're
diagnosing.

## The app says the engine isn't reachable

The app is a viewer for a background service; if that service isn't running there's nothing to show.

- **Linux:** `systemctl status unitylan-engine`.
- **Windows:** check the UnityLAN service in Services.

The app retries on its own, so once the service is up the UI fills in without a restart.

**Headless**, the equivalent symptom is `ctl` refusing to connect:

```
connecting to control socket … (is the daemon running?)
```

Check the daemon is up, that you're root (the socket is privileged), and that you're pointing at the
right config — `./engine.toml` wins over `/etc/unitylan/engine.toml`, which is a classic way to end
up talking to no daemon at all. `-c <path>` settles it.

## Login won't finish

The browser flow binds this device to your Discord account, and the background service completes it.

- The service has to be running — the browser can't finish it alone.
- If the browser never opened, use **Open Discord login** or **Copy link** in the app.
- Check the coordinator is reachable from that machine: `curl -sf <coordinator>/healthz`.
- On a headless box, prefer an enrollment key over the browser flow entirely — see
  [`headless.md`](headless.md).

## No HTTPS certificate arrives

Issuance needs three things at once, and whichever is missing is named by
`sudo unitylan-engine ctl cert` (or shown in the app under the checkbox):

- **`certificates: unavailable (this coordinator issues none)`** — the coordinator has no
  certificate domain configured. Nothing to do on this end; ask whoever runs it.
- **`no port is exposed, so this certificate will not be renewed`** — a certificate is only issued
  for a device actually serving something. Expose the port first.
- **`no certificate yet`** with the option on — it's still working. First issuance takes a moment.
- Anything else after `no certificate yet:` is the error from the certificate authority verbatim.

In the app the checkbox is **hidden entirely** until the deployment offers certificates *and* you
have a port exposed — so if you can't find it, that's why.

Renewal is automatic and the file paths never change, so a server pointed at them keeps working
across renewals. If a certificate has lapsed and isn't coming back, check the port is still exposed:
closing your last one stops renewal.

## A peer keeps connecting and dropping

Usually one of:

- **Both peers are on the same LAN behind one router** that doesn't hairpin properly. The LAN beacon
  is meant to find the direct local path; if it can't (isolated segments, filtered broadcast), the
  pair falls back to the router's public address, which flaps.
- **A dual-WAN or load-balancing router** on one side, changing the source address between packets.

Neither has a clean fix from inside UnityLAN today. A peer that flaps but reconnects is usually
still usable.

## Reporting a problem

Include:

- What the Peers tab shows for the peer in question (or `ctl status` output — redact addresses if
  you'd rather).
- The version, from **Manage → account**.
- Both ends' OS, whether either is behind CGNAT, and whether Tailscale is installed.
- On a server, the engine log around the failure — the journal, or your configured `log_file`.

Bugs and feature requests belong in [GitHub issues](https://github.com/gtosh4/unity_lan/issues);
questions are welcome in [Discord](https://discord.gg/QAmz2j54kS). Security problems go privately —
see [SECURITY.md](../SECURITY.md), never a public channel.
