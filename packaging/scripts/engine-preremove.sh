#!/bin/sh
# Runs before removal. Stop + disable only on real uninstall, not on upgrade.
# deb passes "remove"; rpm passes "0" for the final erase.
set -e
if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --no-reload disable --now unitylan-engine.service >/dev/null 2>&1 || true
    fi
fi
