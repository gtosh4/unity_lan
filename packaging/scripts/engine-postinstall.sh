#!/bin/sh
# Runs after install/upgrade on both deb and rpm.
set -e

# The control socket is owned root:unitylan so a desktop user can drive the engine without root (see
# the systemd unit's Group= and engine.toml control_group). Create the group before the service
# starts. Idempotent (-f) across upgrades.
groupadd -f unitylan >/dev/null 2>&1 || true

# The TLS proxy runs as its own unprivileged account, because parsing HTTP from mesh peers has no
# business happening in the root daemon. Its own group `unitylan-proxy` is the whole grant:
#
#   * it owns the certificate **private key** (engine.toml's `[cert] group`), which the engine
#     chmods to 0640 root:unitylan-proxy after each issuance;
#   * it owns the **read-only** control socket (`control-ro.sock`), where the proxy reads its whole
#     configuration — status and nothing else.
#
# Deliberately *not* a member of `unitylan`: that group owns the full control socket, which grants
# authority over the whole device (expose a port, log out, apply an update). The process most likely
# to be compromised is the last one that should hold it.
#
# A system account with no login shell and no home: it never needs either, and both are attack
# surface on a machine that just serves web pages to a handful of mesh peers.
if ! getent passwd unitylan-proxy >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin \
        --comment "UnityLAN TLS proxy" unitylan-proxy >/dev/null 2>&1 \
      || useradd --system --user-group --no-create-home --shell /sbin/nologin \
        --comment "UnityLAN TLS proxy" unitylan-proxy >/dev/null 2>&1 || true
fi
# Undo the membership older packages granted: it is what this account must not have.
gpasswd -d unitylan-proxy unitylan >/dev/null 2>&1 || true

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # Pick up the new binary on an upgrade. `try-restart` restarts the service only if it is already
    # running, so a first install (service not yet enabled) is a no-op — we never start an
    # unconfigured engine — while an upgrade of a running node relaunches onto the new binary. Without
    # this, a package upgrade left the old binary running until a manual restart/reboot, unlike the
    # signed auto-update path (which relaunches itself by re-execing the new binary in place).
    systemctl try-restart unitylan-engine.service >/dev/null 2>&1 || true
fi
echo "unitylan-engine installed."
echo "  1. edit /etc/unitylan/engine.toml (set coordinator + enrollment_key)"
echo "  2. let your user drive the mesh:  sudo usermod -aG unitylan <you>   (then log out and back in)"
echo "  3. systemctl enable --now unitylan-engine"
