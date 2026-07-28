#!/usr/bin/env bash
# Record the GUI demo GIF (+ stills) for the README.
#
# Runs the `fake-engine` example (canned mesh fixtures + a scripted UI tour — see
# crates/gui/examples/fake-engine.rs), which launches the GUI and drives it over the control
# socket: switch to Peers, open a peer menu, arm/cancel a block, back to Networks. A screencast of
# that window is captured and encoded to a looping GIF for the README, a short looping video for
# the site's hero, and three stills.
#
# Capture uses GPU Screen Recorder (Flatpak) via the desktop screencast portal — the sandbox-
# friendly path on Wayland (KMS/monitor capture is blocked in the flatpak). The FIRST run pops a
# "Share your screen" dialog: pick the **UnityLAN** window. The choice is saved to a restore-token
# file, so later runs are non-interactive.
#
# Deps:  cargo, ffmpeg, and the flatpak com.dec05eba.gpu_screen_recorder
#        (flatpak install flathub com.dec05eba.gpu_screen_recorder)
# Usage: scripts/readme-demo.sh            # writes assets/demo.gif (README), assets/demo-peers.{webm,mp4}
#                                          # (site hero), assets/peers.png, assets/services.png,
#                                          # assets/exposed.png, assets/networks.png
#        SECS=30 FPS=15 WIDTH=400 scripts/readme-demo.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GSR_APP="com.dec05eba.gpu_screen_recorder"
GSR_COMM="gpu-screen-reco" # Linux truncates comm to 15 chars — pkill/pgrep match this, not the full name.
SOCK="$(mktemp -u /tmp/unitylan-demo.XXXXXX.sock)"
TOKEN="${XDG_CACHE_HOME:-$HOME/.cache}/unitylan-readme-demo.token" # persists so only the first run prompts
WORK="$(mktemp -d)"
# Overridable so a capture can be staged and reviewed before it lands in the repo.
OUT="${OUT:-$ROOT/assets}"

SECS="${SECS:-42}"   # recording length; the scripted tour runs ~40s
FPS="${FPS:-15}"     # GIF frame rate
WIDTH="${WIDTH:-400}" # GIF width (height auto)

command -v ffmpeg >/dev/null || { echo "FAIL: ffmpeg not found"; exit 1; }
flatpak info "$GSR_APP" >/dev/null 2>&1 || {
  echo "FAIL: $GSR_APP not installed"
  echo "  flatpak install flathub $GSR_APP"
  exit 1
}

# Kill our procs + salvage the recording on any exit. INT the gsr child so it finalizes the file.
cleanup() {
  pkill -INT -x "$GSR_COMM" 2>/dev/null
  sleep 2
  killall fake-engine unitylan-gui 2>/dev/null
  rm -f "$SOCK"
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> building GUI + fake-engine"
cargo build -q -p unitylan-gui --example fake-engine || exit 1
cargo build -q -p unitylan-gui || exit 1
FAKE="$ROOT/target/debug/examples/fake-engine"

echo "==> launching fake-engine + GUI"
"$FAKE" "$SOCK" >"$WORK/fake.log" 2>&1 &
# Wait for the GUI window to exist (the example spawns it) so the portal has something to capture.
for _ in $(seq 1 20); do
  pgrep -x unitylan-gui >/dev/null && break
  sleep 0.25
done
sleep 2

echo "==> recording ${SECS}s (first run: pick the UnityLAN window in the portal dialog)"
flatpak run --filesystem="$WORK" --filesystem="$(dirname "$TOKEN")" \
  --command=gpu-screen-recorder "$GSR_APP" \
  -w portal -restore-portal-session yes -portal-session-token-filepath "$TOKEN" \
  -cursor no -f 30 -o "$WORK/tour.mkv" >"$WORK/gsr.log" 2>&1 &
sleep "$SECS"

echo "==> stopping recording"
pkill -INT -n -x "$GSR_COMM" 2>/dev/null
for _ in $(seq 1 12); do
  pgrep -x "$GSR_COMM" >/dev/null || break
  sleep 0.5
done
[ -s "$WORK/tour.mkv" ] || { echo "FAIL: no recording (see $WORK/gsr.log)"; cat "$WORK/gsr.log"; exit 1; }

echo "==> encoding GIF + stills -> $OUT"
mkdir -p "$OUT"
VF="fps=$FPS,scale=$WIDTH:-1:flags=lanczos"
ffmpeg -y -v error -i "$WORK/tour.mkv" -vf "$VF,palettegen=max_colors=128" "$WORK/palette.png"
ffmpeg -y -v error -i "$WORK/tour.mkv" -i "$WORK/palette.png" \
  -lavfi "$VF[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3" "$OUT/demo.gif"
# A second, single-purpose cut for the site's hero: just the Peers list with its counters ticking,
# ending before the peer menu opens (tour t=8, i.e. ~6s into the recording). The full tour is the
# right thing in the README, where there's room to explain it, but a landing page wants one idea.
# Keep the end below that menu mark if the tour timings in `fake-engine.rs` ever move.
#
# Video, not GIF: the same clip costs ~4x less as VP9 and skips the 128-colour palette and bayer
# dither a GIF needs. The README above stays a GIF because GitHub's markdown won't play a
# repo-relative <video>; the site has no such limit. WebM is the small one, MP4 the one every
# browser can decode, so the page offers both and takes the first that fits.
CUT=(-ss 1.3 -t 3.5 -i "$WORK/tour.mkv")
CUT_VF="fps=30,scale=$WIDTH:-2:flags=lanczos,format=yuv420p"
ffmpeg -y -v error "${CUT[@]}" -vf "$CUT_VF" \
  -c:v libvpx-vp9 -crf 34 -b:v 0 -row-mt 1 -an "$OUT/demo-peers.webm"
ffmpeg -y -v error "${CUT[@]}" -vf "$CUT_VF" \
  -c:v libx264 -crf 26 -preset slow -movflags +faststart -an "$OUT/demo-peers.mp4"
# Stills from stable tour marks (recording starts a couple seconds into the tour): a clean Peers
# list in the menu-closed window (tour ~18-21s), Services mid-dwell (tour 21-30s), the Manage tab
# mid-dwell for the exposed ports (tour 30-37s), and Networks from the tour's end (it returns to the
# Networks tab at tour t=37 and dwells there — the initial Networks view is gone before the
# recording starts). Each mark sits in the *middle* of its dwell, so a tour timing change in
# `fake-engine.rs` means moving these too.
ffmpeg -y -v error -ss 17 -i "$WORK/tour.mkv" -frames:v 1 "$OUT/peers.png"
ffmpeg -y -v error -ss 25 -i "$WORK/tour.mkv" -frames:v 1 "$OUT/services.png"
ffmpeg -y -v error -ss 34 -i "$WORK/tour.mkv" -frames:v 1 "$OUT/exposed.png"
ffmpeg -y -v error -ss 39 -i "$WORK/tour.mkv" -frames:v 1 "$OUT/networks.png"

echo "==> done:"
ls -la "$OUT/demo.gif" "$OUT/demo-peers.webm" "$OUT/demo-peers.mp4" \
  "$OUT/peers.png" "$OUT/services.png" "$OUT/exposed.png" "$OUT/networks.png"
