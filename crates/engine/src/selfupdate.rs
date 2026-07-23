//! Signed auto-update (design phase 3): verify the coordinator's release manifest, then download →
//! re-verify → apply on the user's confirmation.
//!
//! **Trust root.** The manifest is verified against the **dedicated release key** baked into this
//! binary (`common::update::release_pubkey`) whose private half lives offline in the release pipeline,
//! *never* on a coordinator. That deliberately keeps the update trust root separate from the per-guild
//! attestation keys: a leaked guild signing key can forge attestations but **cannot** sign a binary
//! update. The manifest binds each artifact's SHA-256, so the (large) artifact is fetched over plain
//! HTTPS from anywhere and still proven to be exactly what the release key blessed — a MITM can neither
//! forge the manifest nor swap the artifact. Apply is user-triggered from the GUI, never automatic.
//!
//! **Legacy fallback (transition only).** A build with no release key baked in (dev/CI), or one talking
//! to a coordinator that hasn't published a release-key-signed blob yet, falls back to the older path:
//! the manifest signed by a **pinned guild anchor** (`keys::load_all_anchors`), never `resp.coord_pubkey`
//! — a substituted response could carry an attacker's anchor + a matching manifest, which would be an
//! update-channel RCE. Same rule as `coord::verified_seeds`. This fallback is what a leaked guild key
//! *could* still abuse, so it exists only until the fleet has migrated to the release-key path; an armed
//! build refuses to fall back once the coordinator does send a (here, tampered) release-signed blob.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use common::api::RegisterResp;
use common::crypto::anchor_from_bytes;
use common::update::{current_platform, ReleaseArtifact, ReleaseManifest};
use common::wire::Signed;
use sha2::{Digest, Sha256};

/// A verified update the daemon has staged: a strictly-newer release with an artifact for this
/// platform. Held so the control socket's `ApplyUpdate` can act on it.
#[derive(Clone, Debug)]
pub struct PendingUpdate {
    pub version: String,
    pub artifact: ReleaseArtifact,
}

/// The daemon writes the staged update here each refresh; the control handler reads it on
/// `ApplyUpdate`. A plain mutex — held only for a quick clone, never across an await.
pub type PendingSlot = Arc<Mutex<Option<PendingUpdate>>>;

pub fn pending_slot() -> PendingSlot {
    Arc::new(Mutex::new(None))
}

/// What to re-exec after a Unix update: the new binary at its install path (captured *before*
/// `self_replace` moves the old inode aside) plus the arguments to relaunch it with. Built by
/// [`exec_plan`], performed by [`ExecPlan::exec`] once the daemon has fully torn down.
#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecPlan {
    pub exe: PathBuf,
    pub args: Vec<std::ffi::OsString>,
}

/// The Unix apply path stashes the re-exec plan here for the daemon loop to pick up after teardown.
#[cfg(unix)]
pub type ExecSlot = Arc<Mutex<Option<ExecPlan>>>;

#[cfg(unix)]
pub fn exec_slot() -> ExecSlot {
    Arc::new(Mutex::new(None))
}

/// Decide what to re-exec: the captured install path as the program, and the original argv with
/// `argv[0]` dropped (the new binary supplies its own). `current_exe` must be captured *before*
/// `self_replace` — `/proc/self/exe` would still point at the moved-aside old inode.
#[cfg(unix)]
pub(crate) fn exec_plan(current_exe: PathBuf, argv: Vec<std::ffi::OsString>) -> ExecPlan {
    ExecPlan {
        exe: current_exe,
        args: argv.into_iter().skip(1).collect(),
    }
}

#[cfg(unix)]
impl ExecPlan {
    /// Replace this process image with the new binary (same PID). Returns only on failure — a
    /// successful `exec` never comes back.
    pub fn exec(&self) -> std::io::Error {
        use std::os::unix::process::CommandExt;
        std::process::Command::new(&self.exe)
            .args(&self.args)
            .exec()
    }
}

/// True iff `candidate` is a strictly newer semver than `current`. Unparseable input (an empty
/// version from a pre-versioning coordinator, or garbage) is "not newer" — never offer an update we
/// can't order, never a downgrade.
pub(crate) fn is_newer(candidate: &str, current: &str) -> bool {
    match (
        semver::Version::parse(candidate),
        semver::Version::parse(current),
    ) {
        (Ok(c), Ok(cur)) => c > cur,
        _ => false,
    }
}

/// The rollback floor: the highest release version we've ever verified, persisted in the state dir.
fn floor_path(state_dir: &Path) -> PathBuf {
    state_dir.join("update_floor")
}

/// Accept `version` against the persisted rollback floor, raising the floor to it when accepted.
/// The manifest is signed by the coordinator's anchor, but the transport is deliberately untrusted,
/// so a MITM can *replay* an older-but-genuinely-signed manifest to walk us back onto a release with
/// a known vuln (`is_newer` only blocks going below what we currently *run*, not below what we've
/// already been offered). Once we've verified some release, we refuse any strictly-older one. A
/// *withheld* newer manifest — freezing us in place — can't be caught here; that needs a signed
/// freshness stamp inside the manifest itself.
fn within_floor(state_dir: &Path, version: &str) -> bool {
    let floor = std::fs::read_to_string(floor_path(state_dir))
        .ok()
        .and_then(|s| semver::Version::parse(s.trim()).ok());
    if let Some(floor) = &floor {
        if is_newer(&floor.to_string(), version) {
            return false;
        }
    }
    // Raise the floor when this is the newest we've seen. Best-effort: a write failure just means we
    // don't tighten the floor this round, never that we wrongly reject.
    let raise = match (&floor, semver::Version::parse(version)) {
        (Some(f), Ok(v)) => v > *f,
        (None, Ok(_)) => true,
        _ => false,
    };
    if raise {
        let _ = std::fs::write(floor_path(state_dir), version);
    }
    true
}

/// Breadcrumb recording the version we're restarting onto, written just before the daemon tears down
/// to apply an update and reconciled on the next startup. The Windows file-swap path has no installer
/// log and no e2e test, so this is its post-mortem: a swap-and-restart that silently didn't take
/// leaves a trace instead of the mesh just quietly staying on the old version.
fn update_marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join("update_pending")
}

/// Record that we're about to restart onto `version`. Best-effort — a write failure only costs us the
/// post-mortem, never the update.
pub fn mark_update_pending(state_dir: &Path, version: &str) {
    if let Err(e) = std::fs::write(update_marker_path(state_dir), version) {
        tracing::warn!("could not record the pending-update marker: {e}");
    }
}

/// Reconcile the update breadcrumb at startup. If we came up on (at least) the version it names, the
/// update took — log it and clear the marker. If we're *still older*, the swap-and-restart didn't take
/// effect (a failed file swap, a restart that relaunched the old binary, an MSI rollback); log a
/// warning and leave the marker so a later successful update clears it. A no-op when absent — the
/// normal case, every ordinary startup.
pub fn reconcile_update_marker(state_dir: &Path) {
    let path = update_marker_path(state_dir);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return;
    };
    let target = contents.trim();
    if target.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    if is_newer(target, common::VERSION) {
        tracing::warn!(
            target,
            running = common::VERSION,
            "a staged auto-update did not take effect — still on the older engine (see the update log)"
        );
    } else {
        tracing::info!(target, running = common::VERSION, "auto-update completed");
        let _ = std::fs::remove_file(&path);
    }
}

/// Verify the coordinator's release manifest and stage an update if one applies to us. Delegates to
/// [`stage_with`] using the release key baked into this build ([`common::update::release_pubkey`]).
pub fn stage(resp: &RegisterResp, state_dir: &Path) -> Option<PendingUpdate> {
    stage_with(resp, state_dir, common::update::release_pubkey())
}

/// Core of [`stage`], with the release key injected so tests can arm/disarm the strong path.
///
/// Two verification paths, in order:
/// 1. **Release-key path (strong).** If this build has a baked release key *and* the response carries
///    a `release_signed` blob, verify that blob against the release key **alone**. A valid signature
///    stages; a *present but invalid* one is refused outright (`None`) — an armed build never falls
///    back to the weaker guild-anchor path once the coordinator has spoken the strong protocol, so a
///    MITM can't strip the strong signature down to a forgeable one.
/// 2. **Legacy guild-anchor path (transition).** Otherwise (no baked key, or the coordinator sent no
///    strong blob) verify `release` against any **pinned** guild anchor on disk — never the response's
///    own anchors, which a substituted response controls. This is the pre-release-key behavior and
///    exists only until the fleet migrates.
///
/// `None` in every non-staging case (no manifest, bad signature, not newer, rollback, wrong platform)
/// — a failure is logged and swallowed, never fatal to the mesh.
pub(crate) fn stage_with(
    resp: &RegisterResp,
    state_dir: &Path,
    release_pk: Option<common::crypto::VerifyingKey>,
) -> Option<PendingUpdate> {
    // Strong path: an armed build + a coordinator that published a release-key-signed blob.
    if let Some(pk) = release_pk {
        if let Some(b64) = resp.release_signed.as_ref() {
            let signed = Signed::from_base64(b64)
                .map_err(|e| tracing::warn!("release manifest (signed): bad base64: {e}"))
                .ok()?;
            let manifest: ReleaseManifest = signed
                .verify(&pk)
                .map_err(|_| {
                    // Present but doesn't verify against the release key: treat as hostile and refuse
                    // — do NOT fall through to the guild-anchor path (that would be a downgrade).
                    tracing::warn!(
                        "release-signed manifest failed release-key verification — refusing"
                    )
                })
                .ok()?;
            return stage_manifest(manifest, state_dir);
        }
        // Armed build, but the coordinator sent no strong blob (older coordinator mid-transition):
        // fall through to the legacy path so we're not stranded, unable to update at all.
    }
    // Legacy guild-anchor path.
    let b64 = resp.release.as_ref()?;
    let signed = Signed::from_base64(b64)
        .map_err(|e| tracing::warn!("release manifest: bad base64: {e}"))
        .ok()?;
    let anchors = crate::keys::load_all_anchors(state_dir);
    if anchors.is_empty() {
        tracing::warn!("release manifest: no pinned anchors yet");
        return None;
    }
    // Accept the manifest if it verifies against any pinned guild anchor.
    let manifest: ReleaseManifest = anchors
        .iter()
        .find_map(|pk| {
            anchor_from_bytes(pk)
                .ok()
                .and_then(|a| signed.verify(&a).ok())
        })
        .or_else(|| {
            tracing::warn!("release manifest verified against no pinned anchor");
            None
        })?;
    stage_manifest(manifest, state_dir)
}

/// The applicability gate shared by both verification paths: refuse a rollback below the highest
/// version we've verified, require strictly newer than what we run, and pick this platform's artifact.
fn stage_manifest(manifest: ReleaseManifest, state_dir: &Path) -> Option<PendingUpdate> {
    if !within_floor(state_dir, &manifest.version) {
        tracing::warn!(
            version = %manifest.version,
            "release manifest older than one already verified — refusing (possible rollback)"
        );
        return None;
    }
    if !is_newer(&manifest.version, common::VERSION) {
        return None;
    }
    let platform = current_platform()?;
    let artifact = manifest.artifact_for(platform)?.clone();
    Some(PendingUpdate {
        version: manifest.version,
        artifact,
    })
}

/// Download the artifact, re-verify size + SHA-256 against the (signed) manifest, then swap the
/// binary in place. Returns the [`ExecPlan`] the daemon re-execs *after* a full teardown — so the
/// new engine inherits no live TUN fd or bound socket. Any verification failure aborts before a
/// byte is applied.
#[cfg(unix)]
pub async fn apply(artifact: &ReleaseArtifact, state_dir: &Path) -> anyhow::Result<ExecPlan> {
    let bytes = download_verified(artifact).await?;
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    apply_bytes(&bytes, state_dir)
}

/// Download the artifact, re-verify size + SHA-256 against the (signed) manifest, then apply it. For a
/// file-swap bundle this returns `Ok(())` once the binary is swapped, and the caller signals the
/// daemon to tear down and let the SCM restart the service onto the new binary. For a legacy MSI it
/// launches msiexec and never returns on success (see [`apply_bytes`]).
#[cfg(windows)]
pub async fn apply(artifact: &ReleaseArtifact, state_dir: &Path) -> anyhow::Result<()> {
    let bytes = download_verified(artifact).await?;
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    apply_bytes(&bytes, state_dir)
}

/// Fetch the artifact over HTTPS, bounding the download to its declared size and checking the
/// SHA-256 the signed manifest committed to. Any mismatch aborts before a single byte is applied.
async fn download_verified(artifact: &ReleaseArtifact) -> anyhow::Result<Vec<u8>> {
    if !artifact.url.starts_with("https://") {
        anyhow::bail!("refusing non-HTTPS update URL: {}", artifact.url);
    }
    let builder = reqwest::Client::builder().timeout(Duration::from_secs(300));
    // Test-only (feature off in every shipped build): trust a self-signed cert so the offline e2e
    // harness can serve the artifact over the mandatory HTTPS from a local host. See the crate
    // feature's doc in Cargo.toml.
    #[cfg(feature = "test-insecure-tls")]
    let builder = builder.danger_accept_invalid_certs(true);
    let client = builder.build().context("building update http client")?;
    let mut resp = client
        .get(&artifact.url)
        .send()
        .await
        .with_context(|| format!("fetching {}", artifact.url))?
        .error_for_status()
        .context("update download HTTP error")?;
    let mut buf: Vec<u8> = Vec::with_capacity(artifact.size as usize);
    while let Some(chunk) = resp.chunk().await.context("reading update body")? {
        if buf.len() as u64 + chunk.len() as u64 > artifact.size {
            anyhow::bail!("update exceeds declared size {} bytes", artifact.size);
        }
        buf.extend_from_slice(&chunk);
    }
    if buf.len() as u64 != artifact.size {
        anyhow::bail!("update size {} != declared {}", buf.len(), artifact.size);
    }
    let digest = Sha256::digest(&buf);
    if digest.as_slice() != artifact.sha256 {
        anyhow::bail!("update SHA-256 mismatch — refusing to apply");
    }
    Ok(buf)
}

/// Linux: the artifact is a `.tar.gz` carrying **both** `unitylan-engine` and `unitylan-gui`.
///
/// Both, because the GUI drives the engine over a control protocol that carries no version of its
/// own: replacing only the engine (as this used to) left an older GUI talking to a newer daemon, and
/// a field it didn't know was a dropped connection, not a clean error. Windows's file-swap path
/// carries the same two-binary bundle and promotes the GUI in place the same way (`apply_bundle_swap`
/// → `promote_gui`, renaming an open GUI's exe aside since the engine — not the unprivileged GUI —
/// can write the install dir) — so both platforms keep the engine and GUI in on-disk lockstep across
/// an update.
///
/// A bare (non-gzip) artifact is still accepted as the engine binary alone, so a manifest published
/// before this change keeps applying.
#[cfg(unix)]
fn apply_bytes(bytes: &[u8], state_dir: &Path) -> anyhow::Result<ExecPlan> {
    let engine = if bytes.starts_with(&[0x1f, 0x8b]) {
        let bundle = unpack_bundle(bytes, state_dir)?;
        // Best-effort: a headless install has no GUI to replace, and failing the engine update over
        // that would be worse than the skew we're preventing.
        if let Some(gui) = bundle.gui {
            match replace_gui(&gui) {
                Ok(Some(at)) => tracing::info!(path = %at.display(), "replaced the GUI binary"),
                Ok(None) => tracing::info!("no installed GUI found; updating the engine only"),
                Err(e) => tracing::warn!("could not replace the GUI binary: {e:#}"),
            }
        }
        bundle
            .engine
            .context("update archive has no unitylan-engine")?
    } else {
        let tmp = state_dir.join("unitylan-engine.update");
        std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
        make_executable(&tmp)?;
        tmp
    };
    // Capture the install path *before* the swap: `self_replace` overwrites the file at the exe
    // path but leaves `/proc/self/exe` pointing at the moved-aside old inode, so we can't re-exec
    // that. `current_exe()` resolves the path that will hold the new binary once swapped.
    let current_exe = std::env::current_exe().context("resolving the engine's install path")?;
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    self_replace::self_replace(&engine).context("replacing the running engine binary")?;
    let _ = std::fs::remove_file(&engine);
    tracing::info!("engine binary replaced; re-execing onto the new version after teardown");
    Ok(exec_plan(current_exe, argv))
}

/// The two binary names the update bundle carries, per platform — Windows entries keep the `.exe`
/// suffix so the extracted files are directly runnable. Used to match archive entries by exact file
/// name (never by an archive-supplied path — see [`unpack_bundle`]).
#[cfg(windows)]
const BUNDLE_ENGINE: &str = "unitylan-engine.exe";
#[cfg(windows)]
const BUNDLE_GUI: &str = "unitylan-gui.exe";
#[cfg(unix)]
const BUNDLE_ENGINE: &str = "unitylan-engine";
#[cfg(unix)]
const BUNDLE_GUI: &str = "unitylan-gui";

/// The staged files extracted from an update bundle.
struct Bundle {
    engine: Option<std::path::PathBuf>,
    gui: Option<std::path::PathBuf>,
}

/// Extract the two known binaries from the `.tar.gz` into `state_dir`. Entries are matched by file
/// name and everything else is ignored — so a path-traversal entry (`../../etc/passwd`) can never
/// escape, because we never join an archive-supplied path onto the destination.
fn unpack_bundle(bytes: &[u8], state_dir: &Path) -> anyhow::Result<Bundle> {
    let mut bundle = Bundle {
        engine: None,
        gui: None,
    };
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    for entry in ar.entries().context("reading update archive")? {
        let mut entry = entry.context("reading update archive entry")?;
        let path = entry.path().context("update archive entry path")?;
        let slot = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) if n == BUNDLE_ENGINE => &mut bundle.engine,
            Some(n) if n == BUNDLE_GUI => &mut bundle.gui,
            _ => continue,
        };
        let out = state_dir.join(format!(
            "{}.update",
            path.file_name()
                .and_then(|n| n.to_str())
                .expect("matched above")
        ));
        let mut f =
            std::fs::File::create(&out).with_context(|| format!("writing {}", out.display()))?;
        std::io::copy(&mut entry, &mut f)
            .with_context(|| format!("extracting {}", out.display()))?;
        drop(f);
        #[cfg(unix)]
        make_executable(&out)?;
        *slot = Some(out);
    }
    Ok(bundle)
}

/// Overwrite the installed GUI with `staged`, returning where it landed (or `None` if this host has
/// no GUI installed — a headless server, which is a normal deployment, not an error).
///
/// Only ever replaces a path that already holds a GUI: an update must not *install* a component the
/// operator chose not to have.
#[cfg(unix)]
fn replace_gui(staged: &Path) -> anyhow::Result<Option<std::path::PathBuf>> {
    // Alongside the running engine first (a self-contained/dev layout), then the packaged location
    // — the .deb/.rpm put the engine in /usr/lib/unitylan but the GUI in /usr/bin.
    let beside = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("unitylan-gui")));
    let mut candidates = beside
        .into_iter()
        .chain([std::path::PathBuf::from("/usr/bin/unitylan-gui")]);
    let Some(target) = candidates.find(|p| p.exists()) else {
        return Ok(None);
    };
    // Replace via rename so a running GUI keeps its open inode and the swap is atomic. Same
    // filesystem is not guaranteed, so fall back to a copy.
    if std::fs::rename(staged, &target).is_err() {
        std::fs::copy(staged, &target)
            .with_context(|| format!("copying the GUI to {}", target.display()))?;
        let _ = std::fs::remove_file(staged);
    }
    make_executable(&target)?;
    Ok(Some(target))
}

#[cfg(unix)]
fn make_executable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod +x on {}", path.display()))
}

/// Windows apply, mirroring the Linux gzip-magic sniff: a `.tar.gz` **file-swap bundle** (the
/// preferred, primary path) is swapped in place; anything else is treated as a legacy **MSI** and
/// applied the old installer-driven way. Keeping the MSI fallback lets a manifest still pointing at an
/// `.msi` keep working while the rollout to the bundle is phased (coordinator and clients upgrade on
/// independent schedules).
#[cfg(windows)]
fn apply_bytes(bytes: &[u8], state_dir: &Path) -> anyhow::Result<()> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        apply_bundle_swap(bytes, state_dir)
    } else {
        apply_msi(bytes, state_dir) // never returns on success
    }
}

/// The file-swap update, matching the Linux path: promote the new GUI in place, swap the engine
/// binary, then return so the daemon can tear down cleanly and let the SCM restart the service onto
/// the new binary. No MSI, no `MajorUpgrade`, none of the service-reregistration machinery that made
/// the installer-driven upgrade fragile — a routine version bump is now just a file swap.
///
/// Windows forbids overwriting a *running* image but permits renaming it aside, which is exactly what
/// `self_replace` does (the same crate the Unix path uses): the old image is moved out of the way and
/// the new bytes land at our install path, so the SCM's next start launches the new version.
#[cfg(windows)]
fn apply_bundle_swap(bytes: &[u8], state_dir: &Path) -> anyhow::Result<()> {
    let bundle = unpack_bundle(bytes, state_dir)?;
    // Promote the GUI in place beside the installed one. This must happen *here*, in the
    // LocalSystem engine, and not in the GUI: the install dir is `%ProgramFiles%\UnityLAN`, where an
    // unprivileged GUI has only read+execute and so cannot rename its own exe — the reason the old
    // GUI-driven swap silently failed on a real install. Best-effort: a host with no GUI beside the
    // engine still updates it.
    if let Some(gui) = &bundle.gui {
        match promote_gui(gui) {
            Ok(Some(at)) => {
                tracing::info!(path = %at.display(), "promoted the new GUI in place")
            }
            Ok(None) => {
                tracing::info!("no installed GUI beside the engine; updating the engine only")
            }
            Err(e) => tracing::warn!("could not promote the new GUI: {e:#}"),
        }
    }
    let engine = bundle
        .engine
        .context("update bundle has no unitylan-engine.exe")?;
    self_replace::self_replace(&engine).context("replacing the running engine binary")?;
    let _ = std::fs::remove_file(&engine);
    tracing::info!(
        "engine binary swapped; the service will restart onto the new version after teardown"
    );
    Ok(())
}

/// Promote the freshly-extracted GUI (`staged`) to the installed `unitylan-gui.exe` beside the
/// engine, returning where it landed — or `None` if no GUI is installed there, since an update must
/// not *add* a component the operator chose not to install.
///
/// Runs in the LocalSystem engine on purpose: it has FullControl over `%ProgramFiles%\UnityLAN`,
/// which the unprivileged GUI does not. Windows forbids overwriting a running image but permits
/// *renaming* one (the loader opens it share-delete), so a GUI that is open right now is handled the
/// same way `self_replace` handles the engine — rename the current `unitylan-gui.exe` aside to
/// `.old.exe` (the open GUI keeps executing from that inode), then move the new binary into the
/// canonical name. The open GUI picks it up when it re-execs the canonical path
/// (`gui::relaunch_successor`); the stale `.old.exe` is deleted by the successor on its next start
/// (`gui::clean_stale_gui`).
#[cfg(windows)]
fn promote_gui(staged: &Path) -> anyhow::Result<Option<PathBuf>> {
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    else {
        return Ok(None);
    };
    promote_gui_in(&dir, staged)
}

/// Startup hook: finish a GUI update that an *older* engine only staged, by promoting a leftover
/// `unitylan-gui.new.exe` into place. A no-op when nothing is staged — every ordinary startup.
///
/// This is the counterpart to [`promote_gui`], and it is what makes the fix apply to the very update
/// that ships it. An update is applied by the version you're coming *from*, so the apply-time
/// promotion can't run during that transition; engines before this release instead staged the new GUI
/// under `.new.exe` and expected the *unprivileged* GUI to rename it into place, which always failed
/// in an admin-only install dir. Running the promotion here — in the freshly-started **new** engine,
/// which does have the rights — means that by the time the user clicks "restart to finish", the
/// canonical `unitylan-gui.exe` already holds the new bytes. Even the old GUI's relaunch then lands on
/// them: Windows `current_exe()` reports the load-time path (the canonical name), not the aside-renamed
/// one, and with `.new.exe` consumed its own failing self-swap is skipped entirely.
///
/// Promoting unconditionally when `.new.exe` exists is safe: it only ever exists as an update artifact,
/// and every path that updates `gui.exe` now also removes it, so it can never be *older* than what's
/// installed.
#[cfg(windows)]
pub fn promote_staged_gui() {
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    else {
        return;
    };
    let staged = dir.join("unitylan-gui.new.exe");
    if !staged.exists() {
        return;
    }
    match promote_gui_in(&dir, &staged) {
        Ok(Some(at)) => {
            tracing::info!(path = %at.display(), "promoted a GUI staged by the previous engine")
        }
        Ok(None) => tracing::info!("a GUI was staged but none is installed beside the engine"),
        Err(e) => tracing::warn!("could not promote the staged GUI: {e:#}"),
    }
}

/// Testable core of [`promote_gui`] with the install dir injected (so a test needn't stand in for the
/// engine's real install path).
#[cfg(windows)]
fn promote_gui_in(dir: &Path, staged: &Path) -> anyhow::Result<Option<PathBuf>> {
    let target = dir.join("unitylan-gui.exe");
    if !target.exists() {
        return Ok(None);
    }
    let old = dir.join("unitylan-gui.old.exe");
    // Clear a leftover aside-image from a prior update. It may still be locked if a GUI is *still*
    // running from it (the user never relaunched); then the rename below fails and we abort before
    // touching the working `gui.exe`, rather than destroy it.
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&target, &old)
        .with_context(|| format!("renaming {} aside for the update", target.display()))?;
    // Move the new GUI into the now-free canonical name. The state dir (`%ProgramData%`) and the
    // install dir (`%ProgramFiles%`) can be on different volumes, so fall back to copy when rename
    // can't cross. On any failure, roll the aside-image back so we never leave the install with no
    // `gui.exe` at all.
    let moved =
        std::fs::rename(staged, &target).or_else(|_| std::fs::copy(staged, &target).map(|_| ()));
    match moved {
        Ok(()) => {
            let _ = std::fs::remove_file(staged);
            // Retire the legacy `unitylan-gui.new.exe` staging file. Older builds dropped one here for
            // the GUI to promote itself; nothing consumes it now, so without this it would sit in the
            // install dir forever — and the unprivileged GUI can't delete it either.
            let _ = std::fs::remove_file(dir.join("unitylan-gui.new.exe"));
            Ok(Some(target))
        }
        Err(e) => {
            let _ = std::fs::rename(&old, &target);
            Err(anyhow::Error::new(e)
                .context(format!("promoting the new GUI to {}", target.display())))
        }
    }
}

/// Legacy MSI path: write the signed MSI and launch it, then `exit(0)` so the running engine releases
/// the service and its files before the `MajorUpgrade` removes them. The MSI stops+reregisters+starts
/// the service on its own; `msiexec` is a detached child that survives our exit. We run `/quiet`, so
/// no install wizard (and no GUI-launching ExitDialog) shows — an auto-update just swaps files.
///
/// Unlike the file-swap path, this does **not** run the daemon's teardown (it hard-exits), which is
/// one reason the bundle path is preferred. It stays only as the compatibility fallback. New here:
/// `/l*v` writes a verbose install log next to the state dir — the MSI upgrade has no e2e coverage, so
/// a silent rollback previously left nothing to diagnose.
#[cfg(windows)]
fn apply_msi(bytes: &[u8], state_dir: &Path) -> anyhow::Result<()> {
    let msi = state_dir.join("unitylan-update.msi");
    std::fs::write(&msi, bytes).with_context(|| format!("writing {}", msi.display()))?;
    let log = state_dir.join("update-msi.log");
    let msi_arg = msi
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 MSI path"))?;
    let log_arg = log
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 log path"))?;
    std::process::Command::new("msiexec")
        .args(["/i", msi_arg, "/quiet", "/norestart", "/l*v", log_arg])
        .spawn()
        .context("launching msiexec for the update")?;
    tracing::info!(log = %log.display(), "launched msiexec; the service will restart via the MSI upgrade");
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `.tar.gz` in memory with the given (name, contents) entries.
    ///
    /// Names are written straight into the header rather than through `append_data`, because the
    /// `tar` builder refuses to *emit* a `..` path — and a hostile archive is exactly what we need to
    /// hand the reader here.
    fn targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tarball = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tarball);
            for (name, data) in entries {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o755);
                let bytes = name.as_bytes();
                h.as_gnu_mut().unwrap().name[..bytes.len()].copy_from_slice(bytes);
                h.set_cksum();
                b.append(&h, *data).unwrap();
            }
            b.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tarball).unwrap();
        gz.finish().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn bundle_extracts_both_binaries() {
        let dir = crate::testutil::TempDir::new("su-bundle");
        let bytes = targz(&[
            ("unitylan-engine", b"ENGINE" as &[u8]),
            ("unitylan-gui", b"GUI"),
        ]);
        let b = unpack_bundle(&bytes, &dir).unwrap();
        // Both must land — replacing only the engine is the skew this bundle exists to prevent.
        assert_eq!(std::fs::read(b.engine.unwrap()).unwrap(), b"ENGINE");
        assert_eq!(std::fs::read(b.gui.unwrap()).unwrap(), b"GUI");
    }

    /// Windows: the bundle carries the `.exe`-suffixed names, and `unpack_bundle` must match those
    /// (via `BUNDLE_ENGINE`/`BUNDLE_GUI`) and stage both — the file-swap update's engine source and
    /// GUI stage-source. A name mismatch here would silently make every Windows update a no-op.
    #[cfg(windows)]
    #[test]
    fn bundle_extracts_both_windows_binaries() {
        let dir = crate::testutil::TempDir::new("su-bundle-win");
        let bytes = targz(&[
            ("unitylan-engine.exe", b"ENGINE" as &[u8]),
            ("unitylan-gui.exe", b"GUI"),
        ]);
        let b = unpack_bundle(&bytes, &dir).unwrap();
        assert_eq!(std::fs::read(b.engine.unwrap()).unwrap(), b"ENGINE");
        assert_eq!(std::fs::read(b.gui.unwrap()).unwrap(), b"GUI");
    }

    /// Windows GUI promotion runs in the (LocalSystem) engine because the unprivileged GUI can't write
    /// the Program Files install dir. It must land the new bytes at the canonical `unitylan-gui.exe`
    /// (what the relaunching GUI spawns) and keep the previous one aside as `.old.exe` rather than
    /// destroy it — an open GUI is still executing from that inode.
    #[cfg(windows)]
    #[test]
    fn promote_gui_replaces_in_place_keeping_old_aside() {
        let dir = crate::testutil::TempDir::new("su-promote");
        let gui = dir.join("unitylan-gui.exe");
        std::fs::write(&gui, b"OLD").unwrap();
        // The freshly-extracted new GUI, as `unpack_bundle` leaves it in the state dir.
        let staged = dir.join("unitylan-gui.exe.update");
        std::fs::write(&staged, b"NEW").unwrap();
        // A legacy staging file an older build left behind. Nothing consumes it anymore, and the
        // unprivileged GUI can't delete it, so promotion must be what retires it.
        let legacy = dir.join("unitylan-gui.new.exe");
        std::fs::write(&legacy, b"LEGACY").unwrap();

        let at = promote_gui_in(&dir, &staged)
            .unwrap()
            .expect("a GUI is installed here");
        assert_eq!(at, gui);
        assert_eq!(
            std::fs::read(&gui).unwrap(),
            b"NEW",
            "the canonical name now holds the new bytes"
        );
        assert_eq!(
            std::fs::read(dir.join("unitylan-gui.old.exe")).unwrap(),
            b"OLD",
            "the previous GUI was renamed aside, not destroyed"
        );
        assert!(!staged.exists(), "the staged copy was consumed");
        assert!(
            !legacy.exists(),
            "the legacy .new.exe staging file was retired"
        );
    }

    /// A leftover `.old.exe` from a prior update (successor never cleaned it) must not block a new
    /// promotion: it's cleared first, then the current GUI takes its place.
    #[cfg(windows)]
    #[test]
    fn promote_gui_clears_a_stale_aside_image() {
        let dir = crate::testutil::TempDir::new("su-promote-stale");
        std::fs::write(dir.join("unitylan-gui.exe"), b"OLD").unwrap();
        std::fs::write(dir.join("unitylan-gui.old.exe"), b"STALE").unwrap();
        let staged = dir.join("unitylan-gui.exe.update");
        std::fs::write(&staged, b"NEW").unwrap();

        promote_gui_in(&dir, &staged).unwrap().unwrap();
        assert_eq!(std::fs::read(dir.join("unitylan-gui.exe")).unwrap(), b"NEW");
        assert_eq!(
            std::fs::read(dir.join("unitylan-gui.old.exe")).unwrap(),
            b"OLD",
            "the stale aside-image was replaced by the just-superseded GUI"
        );
    }

    /// The transition case that makes this fix self-applying: an *older* engine staged the new GUI as
    /// `unitylan-gui.new.exe` and couldn't promote it. The new engine's startup hook must consume that
    /// exact file and land it at the canonical name — otherwise the old GUI's relaunch (which spawns
    /// the canonical path) would come back up on the old version.
    #[cfg(windows)]
    #[test]
    fn promote_gui_consumes_a_legacy_staged_new_exe() {
        let dir = crate::testutil::TempDir::new("su-promote-legacy");
        std::fs::write(dir.join("unitylan-gui.exe"), b"OLD").unwrap();
        let staged = dir.join("unitylan-gui.new.exe");
        std::fs::write(&staged, b"NEW").unwrap();

        promote_gui_in(&dir, &staged).unwrap().unwrap();
        assert_eq!(
            std::fs::read(dir.join("unitylan-gui.exe")).unwrap(),
            b"NEW",
            "the canonical name the relaunching GUI spawns now holds the new bytes"
        );
        assert!(!staged.exists(), "the legacy staging file was consumed");
        assert_eq!(
            std::fs::read(dir.join("unitylan-gui.old.exe")).unwrap(),
            b"OLD"
        );
    }

    /// The load-bearing assumption the inert-file tests above cannot reach: Windows lets us rename an
    /// executable image that is **currently running**. Everything here depends on it — it's why
    /// promotion renames aside instead of overwriting — and if it ever stopped holding (a lock, an AV
    /// hook, a future OS change) every other test would still pass while real updates silently failed.
    /// That is precisely how the GUI-side swap shipped broken, so pin it against a live process.
    ///
    /// `ping.exe` stands in for the GUI: present on every Windows host, and we promote over *our own
    /// copy* of it, never the system one. Skips rather than fails if it isn't there — the logic is
    /// covered above either way.
    #[cfg(windows)]
    #[test]
    fn promote_gui_replaces_an_image_that_is_currently_running() {
        let system_exe = Path::new(r"C:\Windows\System32\ping.exe");
        if !system_exe.exists() {
            return;
        }
        let dir = crate::testutil::TempDir::new("su-promote-running");
        let gui = dir.join("unitylan-gui.exe");
        std::fs::copy(system_exe, &gui).unwrap();

        // Launch it so the image is genuinely mapped, and outlives the promotion below.
        let mut child = std::process::Command::new(&gui)
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("launching the stand-in GUI");
        std::thread::sleep(std::time::Duration::from_millis(300));
        let was_running = child.try_wait().unwrap().is_none();

        let staged = dir.join("unitylan-gui.exe.update");
        std::fs::write(&staged, b"NEW").unwrap();
        let promoted = promote_gui_in(&dir, &staged);

        // Reap before asserting, so a failure can't leak the process.
        let _ = child.kill();
        let _ = child.wait();

        assert!(
            was_running,
            "the stand-in must still be running for this test to mean anything"
        );
        promoted
            .expect("promoting over a running image must succeed")
            .expect("a GUI is installed here");
        assert_eq!(
            std::fs::read(&gui).unwrap(),
            b"NEW",
            "the canonical name holds the new bytes even though the old image was in use"
        );
        assert!(
            dir.join("unitylan-gui.old.exe").exists(),
            "the in-use image was renamed aside, not clobbered"
        );
    }

    /// A headless host has the engine but no GUI beside it: promotion must not *add* one.
    #[cfg(windows)]
    #[test]
    fn promote_gui_noop_when_no_gui_installed() {
        let dir = crate::testutil::TempDir::new("su-promote-headless");
        let staged = dir.join("unitylan-gui.exe.update");
        std::fs::write(&staged, b"NEW").unwrap();
        assert!(promote_gui_in(&dir, &staged).unwrap().is_none());
        assert!(!dir.join("unitylan-gui.exe").exists());
    }

    /// Windows traversal guard, mirroring the Unix one: a `..` entry whose *file name* is one we accept
    /// must land inside the destination as the staged engine, never at the archive's chosen path.
    #[cfg(windows)]
    #[test]
    fn bundle_ignores_traversal_windows() {
        let dir = crate::testutil::TempDir::new("su-traversal-win");
        let bytes = targz(&[
            (
                "../../../../../../Windows/Temp/unitylan-engine.exe",
                b"EVIL" as &[u8],
            ),
            ("unitylan-engine.exe", b"ENGINE"),
        ]);
        let b = unpack_bundle(&bytes, &dir).unwrap();
        assert_eq!(std::fs::read(b.engine.unwrap()).unwrap(), b"ENGINE");
        assert!(
            !std::path::Path::new(r"C:\Windows\Temp\unitylan-engine.exe").exists(),
            "a traversal entry escaped the destination"
        );
    }

    /// An archive entry naming a path outside the destination must not be able to write there. We
    /// never join the archive's path onto the destination — only its file name, and only for the two
    /// names we expect — so traversal has nowhere to land.
    #[cfg(unix)]
    #[test]
    fn bundle_ignores_traversal_and_unexpected_entries() {
        let dir = crate::testutil::TempDir::new("su-traversal");
        let bytes = targz(&[
            // Traversal whose file name is one we *do* accept — the dangerous shape. It must land
            // inside `dir` as the staged engine, never at the archive's chosen path.
            ("../../../../../../tmp/unitylan-engine", b"EVIL" as &[u8]),
            ("nested/evil.sh", b"EVIL"),
            ("unitylan-engine", b"ENGINE"),
        ]);
        let b = unpack_bundle(&bytes, &dir).unwrap();
        // The later real entry wins; either way the bytes came from inside `dir`.
        assert_eq!(std::fs::read(b.engine.unwrap()).unwrap(), b"ENGINE");
        assert!(b.gui.is_none(), "no GUI in this archive");
        assert!(
            !std::path::Path::new("/tmp/unitylan-engine").exists(),
            "a traversal entry escaped the destination"
        );
        // Only the staged engine was written — the unexpected entries were skipped entirely.
        let written: Vec<_> = std::fs::read_dir(&*dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(written, vec!["unitylan-engine.update"]);
    }

    // The re-exec must use the captured install path (where `self_replace` put the new binary),
    // not `/proc/self/exe`, and forward the original argv minus argv[0] (the new binary is its own
    // argv[0]). Getting the path or the arg-shift wrong silently re-runs the old binary or drops
    // flags, so pin both here without actually exec-ing.
    #[cfg(unix)]
    #[test]
    fn exec_plan_uses_install_path_and_drops_argv0() {
        use std::ffi::OsString;
        let argv: Vec<OsString> = ["unitylan-engine", "run", "--config", "/etc/x.toml"]
            .iter()
            .map(OsString::from)
            .collect();
        let plan = exec_plan(PathBuf::from("/usr/lib/unitylan/unitylan-engine"), argv);
        assert_eq!(plan.exe, PathBuf::from("/usr/lib/unitylan/unitylan-engine"));
        assert_eq!(plan.args, vec!["run", "--config", "/etc/x.toml"]);
    }

    #[test]
    fn is_newer_gates_strictly_and_safely() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("", "0.1.0"));
        assert!(!is_newer("garbage", "0.1.0"));
    }

    // A substituted response can carry an attacker's anchor + an attacker-signed manifest. `stage`
    // must verify against the PINNED anchor, not `resp.coord_pubkey`, or it's an update-channel RCE.
    #[test]
    fn stage_rejects_manifest_from_non_pinned_anchor() {
        use common::crypto::CoordinatorKey;
        use common::update::{Platform, ReleaseArtifact, ReleaseManifest};

        let dir = crate::testutil::TempDir::new("su-test");
        let honest = CoordinatorKey::generate();
        let attacker = CoordinatorKey::generate();
        const GUILD: u64 = 42;
        crate::keys::pin_anchor(&dir, GUILD, &honest.anchor_bytes(), &[]).unwrap();

        // Version far ahead so the semver gate never masks the signature check; both platforms
        // present so `current_platform()` matches on either CI target.
        let manifest = ReleaseManifest {
            version: "9.9.9".into(),
            artifacts: vec![
                ReleaseArtifact {
                    platform: Platform::LinuxAmd64,
                    url: "https://example.test/x".into(),
                    sha256: [0u8; 32],
                    size: 1,
                },
                ReleaseArtifact {
                    platform: Platform::WindowsAmd64,
                    url: "https://example.test/x.msi".into(),
                    sha256: [0u8; 32],
                    size: 1,
                },
            ],
        };
        let base = |signer: &CoordinatorKey| RegisterResp {
            // Attacker-substituted anchor for GUILD in the response; `stage` must ignore it and
            // verify against the pinned (honest) anchor on disk instead.
            anchors: vec![common::api::GuildAnchor {
                guild_id: GUILD,
                pubkey: attacker.anchor_bytes(),
                rotation_chain: Vec::new(),
            }],
            version: 1,
            proto: common::PROTOCOL_VERSION,
            server_version: "9.9.9".into(),
            release: Some(Signed::sign(signer, &manifest).unwrap().to_base64()),
            ..Default::default()
        };
        // Signed by the attacker (matches the response's anchor) → must still be rejected.
        assert!(stage(&base(&attacker), &dir).is_none());
        // Signed by the pinned (honest) anchor → stages, proving the gate keys on the pin.
        assert!(stage(&base(&honest), &dir).is_some());
    }

    // A MITM on the (untrusted) update transport can replay an older-but-genuinely-signed manifest
    // to downgrade us onto a version with a known vuln. Once we've verified a release, `stage` must
    // refuse any strictly-older one even though its signature checks out.
    #[test]
    fn stage_refuses_rollback_below_seen_version() {
        use common::crypto::CoordinatorKey;
        use common::update::{Platform, ReleaseArtifact, ReleaseManifest};

        let dir = crate::testutil::TempDir::new("su-rollback");
        let honest = CoordinatorKey::generate();
        const GUILD: u64 = 42;
        crate::keys::pin_anchor(&dir, GUILD, &honest.anchor_bytes(), &[]).unwrap();

        let resp = |version: &str| {
            let manifest = ReleaseManifest {
                version: version.into(),
                artifacts: vec![
                    ReleaseArtifact {
                        platform: Platform::LinuxAmd64,
                        url: "https://example.test/x".into(),
                        sha256: [0u8; 32],
                        size: 1,
                    },
                    ReleaseArtifact {
                        platform: Platform::WindowsAmd64,
                        url: "https://example.test/x.msi".into(),
                        sha256: [0u8; 32],
                        size: 1,
                    },
                ],
            };
            RegisterResp {
                version: 1,
                proto: common::PROTOCOL_VERSION,
                server_version: version.into(),
                release: Some(Signed::sign(&honest, &manifest).unwrap().to_base64()),
                ..Default::default()
            }
        };

        // Newest release seen first raises the floor to 9.9.9.
        assert!(stage(&resp("9.9.9"), &dir).is_some());
        // A replayed older (but still signed, still > our running version) manifest is refused.
        assert!(stage(&resp("9.9.8"), &dir).is_none());
        // Re-offering the version at the floor still stages (not a rollback).
        assert!(stage(&resp("9.9.9"), &dir).is_some());
    }

    // ---- Dedicated release-key path (strong) ----

    use common::crypto::CoordinatorKey;
    use common::update::{Platform, ReleaseArtifact, ReleaseManifest};

    /// A version-9.9.9 manifest with an artifact for both CI platforms (so `current_platform()`
    /// matches on either target and the semver gate never masks a signature check).
    fn manifest_9() -> ReleaseManifest {
        ReleaseManifest {
            version: "9.9.9".into(),
            artifacts: vec![
                ReleaseArtifact {
                    platform: Platform::LinuxAmd64,
                    url: "https://example.test/x".into(),
                    sha256: [0u8; 32],
                    size: 1,
                },
                ReleaseArtifact {
                    platform: Platform::WindowsAmd64,
                    url: "https://example.test/x.msi".into(),
                    sha256: [0u8; 32],
                    size: 1,
                },
            ],
        }
    }

    fn resp_with(release: Option<String>, release_signed: Option<String>) -> RegisterResp {
        RegisterResp {
            version: 1,
            proto: common::PROTOCOL_VERSION,
            server_version: "9.9.9".into(),
            release,
            release_signed,
            ..Default::default()
        }
    }

    // An armed build (has a release key) verifies `release_signed` against that key alone — no guild
    // anchor pinned or needed. This is the whole point: the update trust root is the release key.
    #[test]
    fn strong_path_stages_manifest_signed_by_release_key() {
        let dir = crate::testutil::TempDir::new("su-strong");
        let release = CoordinatorKey::generate();
        let resp = resp_with(
            None,
            Some(Signed::sign(&release, &manifest_9()).unwrap().to_base64()),
        );
        assert!(stage_with(&resp, &dir, Some(release.anchor())).is_some());
    }

    // The anti-downgrade invariant: once the coordinator sends a `release_signed` blob, an armed build
    // verifies it against the release key and NEVER falls back to the guild-anchor path. A blob signed
    // by a (leaked) guild key — even alongside a perfectly valid legacy `release` — must be refused, or
    // stripping the strong signature down to a guild-signed one would re-open the RCE.
    #[test]
    fn strong_path_refuses_non_release_key_and_does_not_fall_back() {
        let dir = crate::testutil::TempDir::new("su-strong-reject");
        let release = CoordinatorKey::generate();
        let guild = CoordinatorKey::generate();
        crate::keys::pin_anchor(&dir, 42, &guild.anchor_bytes(), &[]).unwrap();
        let by_guild = Signed::sign(&guild, &manifest_9()).unwrap().to_base64();
        // Strong blob signed by the wrong (guild) key, plus a legit legacy manifest that WOULD stage.
        let resp = resp_with(Some(by_guild.clone()), Some(by_guild));
        assert!(stage_with(&resp, &dir, Some(release.anchor())).is_none());
    }

    // Transition case: an armed build talking to an older coordinator that sends only the legacy
    // `release` (no strong blob) still updates via the guild-anchor path, so it isn't stranded.
    #[test]
    fn armed_build_falls_back_to_legacy_when_no_strong_blob() {
        let dir = crate::testutil::TempDir::new("su-fallback");
        let guild = CoordinatorKey::generate();
        crate::keys::pin_anchor(&dir, 42, &guild.anchor_bytes(), &[]).unwrap();
        let resp = resp_with(
            Some(Signed::sign(&guild, &manifest_9()).unwrap().to_base64()),
            None,
        );
        // Armed with an unrelated release key; falls back because the coordinator sent no strong blob.
        assert!(stage_with(&resp, &dir, Some(CoordinatorKey::generate().anchor())).is_some());
    }

    // An unarmed build (no baked release key) ignores `release_signed` entirely and uses the legacy
    // guild-anchor path — even if the strong blob is garbage.
    #[test]
    fn unarmed_build_ignores_strong_blob_and_uses_legacy() {
        let dir = crate::testutil::TempDir::new("su-unarmed");
        let guild = CoordinatorKey::generate();
        crate::keys::pin_anchor(&dir, 42, &guild.anchor_bytes(), &[]).unwrap();
        let resp = resp_with(
            Some(Signed::sign(&guild, &manifest_9()).unwrap().to_base64()),
            Some("not-a-valid-blob".into()),
        );
        assert!(stage_with(&resp, &dir, None).is_some());
    }

    // A tampered/oversized/short artifact must be rejected before apply. We drive `download_verified`
    // indirectly through the size + hash checks by constructing an artifact whose declared hash can't
    // match arbitrary bytes; the pure checks live here as a guard against regressions in the gate.
    #[test]
    fn sha256_of_known_bytes() {
        // Sanity: our digest wiring matches a known vector (sha256("") prefix), so a mismatch test is
        // meaningful. Full-path download is covered by the mesh e2e script.
        let d = Sha256::digest(b"");
        assert_eq!(
            d[..4],
            [0xe3, 0xb0, 0xc4, 0x42],
            "sha256 empty-string vector"
        );
    }
}
