---
name: cut-release
description: Cut a UnityLAN release — rename the CHANGELOG section, write the Discord announce summary, tag, and point the deployed coordinator's [release] block at the new artifacts. Use when asked to cut, tag, publish, or announce a release (vX.Y.Z).
---

# Cutting a UnityLAN release

Release CI (`.github/workflows/release.yml`) fires on a pushed `v*` tag. It creates the GitHub Release
with notes lifted from the `CHANGELOG.md` section whose heading matches the tag, builds and attaches
artifacts, and posts a Discord embed.

## 1. CHANGELOG: rename, don't trim

Rename `## Unreleased` → `## vX.Y.Z`, leaving it **fully detailed**. The GitHub Release body wants the
depth and isn't length-constrained. A section left named `Unreleased` ships generic notes instead.

## 2. Write `announce/vX.Y.Z.md`

The `announce` job posts an embed *description*, which Discord caps at 4096 chars — CI cuts at 4000
(`jq -Rs '.[:4000]'`). A real release section routinely runs longer, so the job **prefers
`announce/<tag>.md` when that file exists** and falls back to the truncated GitHub Release body
otherwise. Skip this file and a long section gets clipped mid-sentence.

Write a scannable summary, ≤4000 chars (`wc -c announce/vX.Y.Z.md` to verify): headline security items
first, then fixes, then changed; end with the release URL. This is what members actually read. Match
the shape of `announce/v0.5.0.md` / `v0.5.1.md`.

## 3. Version bump + tag

Bump the workspace version in the root `Cargo.toml` (crates inherit it; `common::VERSION` is
`CARGO_PKG_VERSION`), commit with the CHANGELOG + announce file, then:

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

## 4. Point the deployed coordinator at the new artifacts (after CI publishes)

Auto-update clients verify against the dedicated release key, not any guild key, so the manifest must
be **signed** with the offline seed:

```sh
scripts/update-release-config.sh coordinator.toml          # seed: secrets/release.seed by default
```

This rewrites the `[release]` block (version/url/sha256/size) from the GitHub release and injects a
fresh signed `signed_blob`. Then reload the coordinator (`kill -HUP <pid>` or restart). Without a seed
the script rewrites the block but skips signing — armed clients then have nothing to accept and will
not update. Full detail: `docs/release-signing.md`. Never hand-edit the `[release]` block.
