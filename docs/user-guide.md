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

Along the top: a dot for the **coordinator** connection, a dot for the **mesh**, and a
**disconnect** / **connect** button that takes your tunnels down or brings them back without
stopping the service.

Below that, three tabs.

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

### Manage

Your account, your devices, and what this machine shares.

- **Account** — who you're signed in as, the version you're running, and **log out**.
- **Devices** — every machine you've enrolled. **set primary** picks which one answers to your bare
  `<you>.unity.internal` name; **remove** un-enrolls one you no longer have; the text box plus
  **rename** changes this machine's name.
- **Exposed ports** — see below.

When an update is ready, an **update** button appears here; after it installs, **restart now**
finishes the job.

## Letting people reach something on your machine

Joining a network doesn't open anything up. Until you say otherwise, a peer can ping you and nothing
else — no file shares, no game server, nothing.

To share something, go to **Manage → exposed ports**, enter the port, pick **TCP** or **UDP**, and
choose a **scope**:

- a **network**, so only that network's members can reach it,
- **one of my devices**, so only machines you own can,
- or leave it open to every peer you mesh with.

Then click **expose**. Each open port lists chips under **who can reach this port**, one per scope.
Add the same port again with a different scope to widen it; **close** removes it.

A Minecraft server on this machine, shared with just your Gaming network, is one port (`25565`,
TCP) with one scope.

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
