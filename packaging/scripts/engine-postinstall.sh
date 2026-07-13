#!/bin/sh
# Runs after install/upgrade on both deb and rpm.
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
echo "unitylan-engine installed."
echo "  1. edit /etc/unitylan/engine.toml (set coordinator + enrollment_key)"
echo "  2. systemctl enable --now unitylan-engine"
