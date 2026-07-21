#!/usr/bin/env bash
# Point a coordinator config's [release] block at the latest GitHub release: rewrites the version and
# each artifact's url/sha256/size in place (comments and everything else untouched). Only updates the
# platform blocks already present — it won't add one.
#
#   scripts/update-release-config.sh [path/to/coordinator.toml]   # default: ./coordinator.toml
#
# Needs `gh` authenticated against the repo.
set -euo pipefail

CONFIG="${1:-coordinator.toml}"
REPO="gtosh4/unity_lan"
[ -f "$CONFIG" ] || { echo "no such config: $CONFIG" >&2; exit 1; }

tag=$(gh release view --repo "$REPO" --json tagName -q .tagName)
ver="${tag#v}"
base="https://github.com/${REPO}/releases/download/${tag}"

# Per-platform artifact names in the release (msi name embeds the version; the tarball name doesn't).
lin_name="unitylan-linux-amd64.tar.gz"
win_name="unitylan-${ver}-x64.msi"

# Sizes from the release asset list; SHA-256s from the checksum manifests CI attaches.
sizes=$(gh release view "$tag" --repo "$REPO" --json assets -q '.assets[] | "\(.name) \(.size)"')
# The Windows manifest is CRLF (PowerShell Set-Content), so strip carriage returns before matching.
sums=$(gh release download "$tag" --repo "$REPO" -p 'SHA256SUMS' -O - 2>/dev/null | tr -d '\r')
wsums=$(gh release download "$tag" --repo "$REPO" -p 'SHA256SUMS-windows.txt' -O - 2>/dev/null | tr -d '\r')
size_for() { awk -v n="$1" '$1==n{print $2}' <<<"$sizes"; }
sha_for()  { awk -v n="$2" '$2==n{print $1}' <<<"$1"; }

lin_sha=$(sha_for "$sums" "$lin_name");  lin_size=$(size_for "$lin_name")
win_sha=$(sha_for "$wsums" "$win_name"); win_size=$(size_for "$win_name")

for v in "$ver" "$lin_sha" "$lin_size" "$win_sha" "$win_size"; do
	[ -n "$v" ] || { echo "missing an artifact value in release $tag — nothing written" >&2; exit 1; }
done

tmp=$(mktemp)
awk -v ver="$ver" \
	-v lin_url="${base}/${lin_name}" -v lin_sha="$lin_sha" -v lin_size="$lin_size" \
	-v win_url="${base}/${win_name}" -v win_sha="$win_sha" -v win_size="$win_size" '
	/^\[release\]/ { inrel = 1 }
	inrel && /^version[[:space:]]*=/ { print "version = \"" ver "\""; next }
	/^platform[[:space:]]*=/ {
		if ($0 ~ /linux-amd64/)   plat = "lin"
		else if ($0 ~ /windows-amd64/) plat = "win"
		else plat = ""
		print; next
	}
	plat == "lin" && /^url[[:space:]]*=/    { print "url      = \"" lin_url  "\""; next }
	plat == "lin" && /^sha256[[:space:]]*=/ { print "sha256   = \"" lin_sha  "\""; next }
	plat == "lin" && /^size[[:space:]]*=/   { print "size     = " lin_size;       next }
	plat == "win" && /^url[[:space:]]*=/    { print "url      = \"" win_url  "\""; next }
	plat == "win" && /^sha256[[:space:]]*=/ { print "sha256   = \"" win_sha  "\""; next }
	plat == "win" && /^size[[:space:]]*=/   { print "size     = " win_size;       next }
	{ print }
' "$CONFIG" >"$tmp"
mv "$tmp" "$CONFIG"
echo "updated $CONFIG [release] block to $tag"
