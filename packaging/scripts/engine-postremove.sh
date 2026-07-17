#!/bin/sh
# Runs after removal/upgrade on both deb and rpm.
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# On a deb `purge` (apt passes "purge"), wipe the state dir — WG key, token, pinned anchors, relay
# secret. A plain `remove` keeps it so a reinstall keeps this device's identity/IP. rpm has no purge
# concept (erase == remove), so state always survives an rpm erase, matching that keep-identity model.
# The coordinator's device row is not touched here (no guaranteed token, daemon already stopped); it
# expires on presence timeout. Use `unitylan uninstall --purge` before removal to un-enroll actively.
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/unitylan
fi
