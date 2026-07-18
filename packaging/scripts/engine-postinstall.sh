#!/bin/sh
# Runs after install/upgrade on both deb and rpm.
set -e

# The control socket is owned root:unitylan so a desktop user can drive the engine without root (see
# the systemd unit's Group= and engine.toml control_group). Create the group before the service
# starts. Idempotent (-f) across upgrades.
groupadd -f unitylan >/dev/null 2>&1 || true

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
echo "unitylan-engine installed."
echo "  1. edit /etc/unitylan/engine.toml (set coordinator + enrollment_key)"
echo "  2. let your user drive the mesh:  sudo usermod -aG unitylan <you>   (then log out and back in)"
echo "  3. systemctl enable --now unitylan-engine"
