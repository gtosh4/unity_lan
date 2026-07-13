#!/bin/sh
# Runs after removal/upgrade on both deb and rpm.
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
