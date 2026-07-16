#!/usr/bin/env bash
# Build release binaries and produce .deb + .rpm for engine and gui via nfpm.
# One spec per package yields both formats — no per-distro build environment.
set -euo pipefail
cd "$(dirname "$0")"          # -> packaging/
ROOT="$(cd .. && pwd)"

# Release CI presets VERSION from the git tag; otherwise take the shared workspace version (all
# crates use `version.workspace = true`, so the single source of truth is the root Cargo.toml).
VERSION="${VERSION:-$(grep '^version' "$ROOT/Cargo.toml" | head -1 | cut -d'"' -f2)}"
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

# Raw engine binary for the signed auto-update path (the Linux artifact a release manifest points
# at; the engine self-replaces its own binary with it). Named by platform to match Platform::LinuxAmd64.
cp "$ROOT/target/release/unitylan-engine" "$DIST/unitylan-engine-linux-$ARCH"

# SHA256SUMS over every artifact — the admin pastes the relevant hash into the coordinator's
# [release] config so clients can verify the download against the signed manifest.
( cd "$DIST" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\n' | sort | xargs sha256sum > SHA256SUMS )

echo ">> packages:"
ls -1 "$DIST"
