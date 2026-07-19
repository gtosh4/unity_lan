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

# Two Linux artifacts for the signed auto-update path, because the rollout is phased.
#
# The bundle carries **both** binaries: the engine and GUI speak an unversioned control protocol, so
# an update replacing only the engine leaves an older GUI talking to a newer daemon. Engines from
# this release on sniff gzip magic and unpack it.
#
# The raw binary is what a **pre-0.3 engine** must be pointed at. Its `apply` writes the artifact
# bytes straight over its own executable — hand it the tarball and it installs a gzip file as its
# binary and crash-loops on exec format error, needing a manual reinstall.
#
# So: publish `unitylan-engine-linux-$ARCH` in the coordinator's [release] block while any pre-0.3
# clients remain, and switch to the bundle once they're gone. See packaging/README.md.
cp "$ROOT/target/release/unitylan-engine" "$DIST/unitylan-engine-linux-$ARCH"
tar -czf "$DIST/unitylan-linux-$ARCH.tar.gz" \
    -C "$ROOT/target/release" unitylan-engine unitylan-gui

# SHA256SUMS over every artifact — the admin pastes the relevant hash into the coordinator's
# [release] config so clients can verify the download against the signed manifest.
( cd "$DIST" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\n' | sort | xargs sha256sum > SHA256SUMS )

echo ">> packages:"
ls -1 "$DIST"
