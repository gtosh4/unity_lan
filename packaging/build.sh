#!/usr/bin/env bash
# Build release binaries and produce .deb + .rpm for engine and gui via nfpm.
# One spec per package yields both formats — no per-distro build environment.
set -euo pipefail
cd "$(dirname "$0")"          # -> packaging/
ROOT="$(cd .. && pwd)"

VERSION="$(grep '^version' "$ROOT/crates/engine/Cargo.toml" | head -1 | cut -d'"' -f2)"
case "$(uname -m)" in
    x86_64)        ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac
export VERSION ARCH

if ! command -v nfpm >/dev/null 2>&1; then
    echo "nfpm not found. Install: https://nfpm.goreleaser.com/install/" >&2
    exit 1
fi

echo ">> building release binaries (v$VERSION, $ARCH)"
( cd "$ROOT" && cargo build --release -p unitylan-engine -p unitylan-gui )

DIST="$ROOT/packaging/dist"
mkdir -p "$DIST"
cd nfpm  # nfpm resolves contents.src relative to its working dir
for cfg in engine desktop; do
    for fmt in deb rpm; do
        nfpm pkg -f "$cfg.yaml" -p "$fmt" -t "$DIST"
    done
done

echo ">> packages:"
ls -1 "$DIST"
