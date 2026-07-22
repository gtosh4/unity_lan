#!/usr/bin/env bash
# Point a coordinator config's [release] block at the latest GitHub release: rewrites the version and
# each artifact's url/sha256/size in place (comments and everything else untouched). Only updates the
# platform blocks already present — it won't add one.
#
#   scripts/update-release-config.sh [path/to/coordinator.toml]              # default: ./coordinator.toml
#   scripts/update-release-config.sh coordinator.toml --seed release.seed    # override the seed path
#
# After rewriting the block it signs the manifest with the offline release key and injects the
# resulting `signed_blob` — so clients with the release pubkey baked in verify updates against that
# key, not any guild key. The seed defaults to `secrets/release.seed` (gitignored); override with
# --seed or RELEASE_SEED=<file>. The seed is the update trust root: keep it offline, never on the
# coordinator. If the *default* seed is absent the script just rewrites the block and skips signing;
# an explicitly-passed seed (--seed / RELEASE_SEED) that's missing is a hard error.
# Signing runs `unitylan-coordinator sign-release` — set COORDINATOR_BIN to a prebuilt binary, else it
# falls back to `cargo run -q -p unitylan-coordinator`.
#
# Needs `gh` authenticated against the repo.
set -euo pipefail

CONFIG=""
SEED="${RELEASE_SEED:-}"
seed_explicit=0
[ -n "$SEED" ] && seed_explicit=1   # RELEASE_SEED set (even to a path) means "sign, and mean it"
while [ $# -gt 0 ]; do
	case "$1" in
		--seed) SEED="${2:?--seed needs a file}"; seed_explicit=1; shift 2 ;;
		*) CONFIG="$1"; shift ;;
	esac
done
CONFIG="${CONFIG:-coordinator.toml}"
SEED="${SEED:-secrets/release.seed}"   # default when neither --seed nor RELEASE_SEED given
REPO="gtosh4/unity_lan"
[ -f "$CONFIG" ] || { echo "no such config: $CONFIG" >&2; exit 1; }
if [ -n "$SEED" ] && [ ! -f "$SEED" ]; then
	[ "$seed_explicit" = 0 ] || { echo "no such seed file: $SEED" >&2; exit 1; }
	echo "note: default seed $SEED absent — rewriting the block only, skipping signing" >&2
	SEED=""
fi

tag=$(gh release view --repo "$REPO" --json tagName -q .tagName)
ver="${tag#v}"
base="https://github.com/${REPO}/releases/download/${tag}"

# Per-platform auto-update bundles in the release (both version-agnostic tarball names). Windows
# serves the tar.gz file-swap bundle now that the whole fleet is >= 0.4.0; a pre-0.4.0 engine's
# updater expects the .msi and would write the gzip over its own exe, so never revert this while any
# such client remains.
lin_name="unitylan-linux-amd64.tar.gz"
win_name="unitylan-windows-x64.tar.gz"

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

# Optional: sign the manifest with the offline release key and inject `signed_blob`.
if [ -n "$SEED" ]; then
	bin=${COORDINATOR_BIN:-"cargo run -q -p unitylan-coordinator --"}
	blob=$($bin sign-release "$CONFIG" --seed "$SEED") || { echo "sign-release failed — signed_blob left unchanged" >&2; exit 1; }
	[ -n "$blob" ] || { echo "sign-release produced no blob" >&2; exit 1; }
	# Replace an existing `signed_blob` under [release], else insert one right after `version`. A
	# [release] key must precede the [[release.artifact]] sub-tables, so `inrel` is still set when we
	# reach it (a following [[…]] table only clears the flag after we've inserted).
	tmp=$(mktemp)
	awk -v blob="$blob" '
		/^\[release\]/ { inrel = 1; print; next }
		inrel && /^signed_blob[[:space:]]*=/ { next }                       # drop any old blob line
		inrel && /^version[[:space:]]*=/ { print; print "signed_blob = \"" blob "\""; done = 1; next }
		/^\[/ { inrel = 0 }
		{ print }
		END { if (!done) exit 3 }
	' "$CONFIG" >"$tmp" || { echo "could not locate [release] version to attach signed_blob" >&2; rm -f "$tmp"; exit 1; }
	mv "$tmp" "$CONFIG"
	echo "signed the manifest and injected signed_blob (release-key path armed)"
fi
