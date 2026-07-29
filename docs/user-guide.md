# UnityLAN — User guide

Using the desktop app. Everything here is done by clicking; nothing needs a terminal.

Running a game server, media box, or anything else without a screen? That's
[`headless.md`](headless.md). Something not working? [`troubleshooting.md`](troubleshooting.md).

## Getting on the mesh

Install the packages ([README](../README.md#try-it--install)) and open UnityLAN. You need a Discord
account; you do **not** need to own or join any particular Discord server.

The app shows **Not logged in** until you sign in. Click **Log in with Discord** — your browser
opens, you approve, and the app takes it from there. If the browser doesn't open on its own, use
**Open Discord login**, or **Copy link** to paste it somewhere yourself.

Behind the app there's a background service (the *engine*) doing the actual networking. The app is a
viewer and remote control for it — closing the app doesn't take you off the mesh.

## Reading the main window

The app opens on whichever tab has something to show — **Services** if anything on the mesh is
serving one, else **Peers** if you have any, else **Networks**. Pick a tab yourself and it stays
picked.

Along the top: a dot for the **coordinator** connection, a dot for the **mesh**, and a
**disconnect** / **connect** button that takes your tunnels down or brings them back without
stopping the service.

Below that, four tabs.

### Networks

Every network you're in, each with a toggle. Turning one off stops peering with that network's
members — you keep the Discord role, you just stop talking to them.

**My devices** is the same kind of toggle for machines you own. It's on by default and works with no
Discord server at all. Turn it off and this device holds no personal address.

If you see **not joined to any network**, nobody has registered a role you hold as a network yet —
ask whoever runs the server, or just use My devices for your own machines.

### Peers

Everything you can reach, grouped into **this device**, **my devices**, **online**, and **offline**.
Each peer shows its name, its mesh address, latency, and how much traffic has moved.

Under each name is how you're reaching it:

| | |
| --- | --- |
| **direct** | A straight peer-to-peer connection. |
| **ice** | A hole punch got through a difficult NAT. Still peer-to-peer. |
| **relayed** | Going through another member, who is forwarding ciphertext it can't read. |
| **unreachable** | No path found, or an established one went quiet. |
| **no handshake yet** | Still setting up. Normal for a few seconds. |

The **⋮** button on a peer offers **copy hostname**, **copy IP**, and **block user**. Blocking is
local to your machine and covers every device that person owns — you'll be asked to confirm, and you
can undo it later with **unblock**.

### Services

Named things, on your machine and everyone else's.

- **My services** — what this machine serves under a name, each showing the full name people type
  and the ports behind it. The form below adds one; **remove** stops serving a name and closes every
  port it was on.
- **Other open ports** — ports opened without a name (from the command line, or carried over from
  an older version). Only shown when you have some.
- **On the mesh** — what other members are running, grouped by owner. This is the easiest way to
  find out what's there: a green dot means the machine is up, amber means the owner has two devices
  claiming that name and this one lost (they can rename it), red means offline.

Only services you're allowed to reach appear here — someone else's service scoped to a network
you're not in is invisible rather than listed-and-refused.

### Manage

Your account and your devices.

- **Account** — who you're signed in as, the version you're running, and **log out**.
- **Devices** — every machine you've enrolled. **set primary** picks which one answers to your bare
  `<you>.unity.internal` name; **remove** un-enrolls one you no longer have; **rename** on this
  device's own row turns it into a text field, seeded with the current name.
When an update is ready, an **update** button appears here; after it installs, **restart now**
finishes the job.

## Letting people reach something on your machine

Joining a network doesn't open anything up. Until you say otherwise, a peer can ping you and nothing
else — no file shares, no game server, nothing.

Go to the **Services** tab, give it a **name**, enter the **port**, pick **TCP** or **UDP**, and
choose a **scope**:

- a **network**, so only that network's members can reach it,
- **one of my devices**, so only machines you own can,
- or leave it open to every peer you mesh with.

Then click **add**. Each service lists chips underneath, one per scope that can reach it. Add the
same name and port again with a different scope to widen it; **remove** takes the whole service down,
closing every port it was on.

A Minecraft server on this machine, shared with just your Gaming network, is one service (`mc`,
`25565`, TCP) with one scope.

The name is the point. `100.83.12.4:25565` is not something anyone remembers, but `mc` becomes
`mc.alice.unity.internal` — which you can type into a game's server browser, a browser, or an SSH
command, and read out loud to a friend.

If you opened a port from the command line without naming it, or carried one over from an older
version, it appears under **other open ports** with a **close** button. Adding a service on the same
port gives it a name.

One machine can serve as many as you like: `mc`, `jellyfin`, `git`, each its own name pointing at the
same device. The Services tab also lists what everyone else on your mesh is running, which is the
easiest way to find out what's there.

A service is an exposed port with a name, so it is scoped the same way. A service you offer to one
network is invisible to everyone else — people outside it aren't told the name exists, so nothing
leaks about what you run.

Two small things worth knowing. Names are announced device to device rather than through the
coordinator, so a name you just added takes up to half a minute to reach other people, and a device
that's offline doesn't advertise anything. And if two of *your own* devices claim the same name, one
of them wins — the app marks the other, so you can rename it.

**If the service is a website, tick the HTTPS box** (it appears once you've turned certificates on
below). Then `jellyfin.alice.mesh.unitylan.com` opens in a browser with no warning page. That name
goes into public certificate logs permanently, same as your device's own — so it's a separate,
deliberate tick rather than something naming a service does for you.

### Getting an HTTPS certificate (advanced)

Once a port is exposed, a checkbox appears: **Get an HTTPS certificate for this device**. It's there
for people serving something a browser opens — a media library, a dashboard, a web UI.

Mesh names end in `.unity.internal`, which no certificate authority will ever certify, so browsers
show a warning page. If your coordinator is set up for it, your device also answers to a name under
a real domain — on the hosted coordinator that's `mesh.unitylan.com`, so `laptop.alice.unity.internal`
is also `laptop.alice.mesh.unitylan.com` — and ticking the box gets a real, publicly-trusted
certificate for it. The app then shows where the certificate and key live so you can point your
server at them. Renewal is automatic.

**The certificate also covers every name one level below your device.** For a device called
`server`, that's `server.alice.mesh.unitylan.com` *and* anything of the form
`<something>.server.alice.mesh.unitylan.com` — `plex.server.alice…`, `git.server.alice…`, as many as
you like. Those names resolve to the same machine with no extra setup, so a reverse proxy on it can
serve a different site per name from the one certificate, and you never have to ask for another.

It stops there on purpose. The certificate never covers `*.alice.mesh.unitylan.com`, because that
pattern would also match your *other* devices' names, and one machine holding a certificate for the
rest of yours is a worse trade than a little convenience.

**The warning next to that checkbox is worth taking seriously.** Getting a certificate publishes
this device's name to public certificate-transparency logs, **permanently**, where anyone can search
them. Unticking the box later stops renewals but cannot unpublish what's already there. That's why
it's off unless you choose it, and why it only appears once you're actually serving something.

## Minimising to the tray

Closing the window doesn't quit — UnityLAN lives in the system tray. Clicking the tray icon hides
and restores the window, and its menu has **Connect mesh**, **Disconnect mesh**, and **Quit**.

Quitting the app leaves the engine running, so your machine stays on the mesh. To actually leave,
see below.

## Names

Your machines get names other members can use:

| Name | Which machine |
| --- | --- |
| `laptop.alice.unity.internal` | Alice's device named `laptop` |
| `alice.unity.internal` | Whichever of Alice's devices is set primary |
| `plex.laptop.alice.unity.internal` | Also Alice's `laptop` — anything one label below a device name reaches it, for serving several sites from one machine |
| `mc.alice.unity.internal` | Whichever of Alice's devices serves the `mc` service (see above) |

If your coordinator is configured with a certificate domain, the same machines answer to matching
names under it — `laptop.alice.mesh.unitylan.com` on the hosted one — which is what makes a real
HTTPS certificate possible (see above).

They work from any meshed device with no setup — type the name into a game's server browser, a
browser address bar, or a file manager. Only the `unity.internal` suffix is affected; the rest of
your DNS is untouched.

## Leaving

Log out from **Manage → account** to sign this machine out, or **remove** a device from the same tab
to un-enroll one you no longer have. Then uninstall the packages if you're done entirely.

Un-enrolling is what frees a device's mesh address for reuse. The one case that happens on its own
is a **personal** device (yours only, no Discord server involved), whose address is released after
30 days without connecting. A device enrolled through a Discord server keeps its address until it's
removed.
