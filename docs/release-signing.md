# Release signing (auto-update trust root)

Auto-updates are verified by clients against a **dedicated release key**, kept separate from the
per-guild attestation keys. A leaked guild signing key can forge attestations but **cannot** sign a
binary update — so it can't push root code to a guild's members. The release key's private half stays
**offline** with the release operator; it never lives on a coordinator or in CI.

How it fits together:

- Clients bake in the release **public** key at build time via `UNITYLAN_RELEASE_PUBKEY`
  (`common::update::release_pubkey`). This is the *sole* update trust root: a build with it unset is
  *unarmed* and **does not self-update at all** (fine for dev/CI). There is no guild-signed fallback —
  see "No fallback" below.
- The coordinator serves a **pre-signed** manifest blob verbatim from `[release] signed_blob`; it holds
  no release key and never signs. An armed client verifies the blob against the baked-in key alone; a
  present-but-invalid blob is refused outright, and a response with no blob offers no update that cycle.

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

If the seed isn't present the script rewrites the block and skips signing — armed clients then have no
signed blob to accept and will not update until you sign one. Always sign for a real deployment.

## No fallback (the legacy path was removed)

Current clients accept updates **only** over the release-key path — there is no fallback to a
guild-signed manifest. Dropping that fallback is what makes a leaked guild key unable to ship a binary
(previously, a stripped `release_signed` field let an armed client accept a guild-signed manifest,
which was an update-channel RCE).

Consequence for a **coordinator** during a fleet upgrade: a client accepts updates using the code it is
*already running*. Clients built before this change (their own old code) still consult the guild-signed
`release` manifest, so keep populating the `[release]` artifacts **until every deployed client has
upgraded to a build that includes this change**. Once they have, you can stop populating the
guild-signed `[release.artifact]` blocks and serve only `signed_blob` — the guild-signed manifest is
then dead weight (no current client reads it). Verify with each host's reported version before pulling
it.
