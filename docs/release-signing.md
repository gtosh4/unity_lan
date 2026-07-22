# Release signing (auto-update trust root)

Auto-updates are verified by clients against a **dedicated release key**, kept separate from the
per-guild attestation keys. A leaked guild signing key can forge attestations but **cannot** sign a
binary update — so it can't push root code to a guild's members. The release key's private half stays
**offline** with the release operator; it never lives on a coordinator or in CI.

How it fits together:

- Clients bake in the release **public** key at build time via `UNITYLAN_RELEASE_PUBKEY`
  (`common::update::release_pubkey`). A build with it unset is *unarmed* and falls back to the legacy
  guild-signed update path — fine for dev, and the migration default.
- The coordinator serves a **pre-signed** manifest blob verbatim from `[release] signed_blob`; it holds
  no release key and never signs. A client with the pubkey baked in verifies the blob against it alone
  and won't fall back to the guild-signed path once a coordinator offers a signed blob.

## One-time setup

1. **Generate the key** (on your own machine, not a coordinator, not CI):

   ```sh
   unitylan-coordinator gen-release-key secrets/release.seed
   ```

   It writes the private seed to `secrets/release.seed` (owner-only; `/secrets` is gitignored) — the
   default the release script looks for — and prints the public key hex. Keep a durable offline backup
   of the seed (password manager / hardware token); it's the update trust root. **If it leaks, rotate**
   (generate a new key, update the repo variable, cut a release from armed builds).

2. **Bake the public key into releases.** Set the repo **variable** (not secret — it's public)
   `UNITYLAN_RELEASE_PUBKEY` to the printed hex, under repo *Settings → Secrets and variables →
   Actions → Variables*. The release workflow reads it and bakes it into every `.deb`/`.rpm`/`.msi`/
   `.tar.gz` build; each build job logs `release signing: ARMED` (or a warning if unset).

   > Forks: generate your own key and set your own fork's variable — clients built from your fork trust
   > your release key, not upstream's.

## Each release

After the release artifacts are published (the tag build attaches `.tar.gz` bundles + `SHA256SUMS`),
point your coordinator config at them **and sign**, in one step, with the offline seed:

```sh
scripts/update-release-config.sh coordinator.toml
```

This rewrites the `[release]` block (version/url/sha256/size) from the GitHub release and — using
`secrets/release.seed` by default (override with `--seed`/`RELEASE_SEED`) — signs the manifest and
injects a fresh `signed_blob`. Then reload the coordinator (`kill -HUP <pid>`, or restart). Clients on
armed builds pick up the release-key-signed manifest on their next refresh.

If the seed isn't present the script rewrites the block and skips signing (legacy guild-signed path
only) — unarmed clients still update, armed clients wait for a signed blob.

## Retiring the legacy path

The coordinator serves both the guild-signed `release` and the release-key-signed `release_signed`
during the transition, so old and new clients both update. Once every client in the mesh is on an
armed build, you can stop populating the guild-signed `[release]` artifacts and serve only
`signed_blob` — at which point a leaked guild key has no update path at all.
