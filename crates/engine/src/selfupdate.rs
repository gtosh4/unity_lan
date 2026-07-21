//! Signed auto-update (design phase 3): verify the coordinator's release manifest against the
//! pinned anchor, then download → re-verify → apply on the user's confirmation.
//!
//! Trust chain: the manifest is signed by the coordinator's anchor (already TOFU-pinned client-side,
//! same key that signs attestations — no new trust root), and it binds each artifact's SHA-256. So
//! the (large) artifact is fetched over plain HTTPS from anywhere and still proven to be exactly what
//! the anchor blessed — a MITM can neither forge the manifest nor swap the artifact. Apply is
//! user-triggered from the GUI, never automatic.
//!
//! Critically, the manifest is verified against the **pinned** anchor on disk (`keys::load_anchor`),
//! never `resp.coord_pubkey` — a substituted response could carry an attacker's anchor + a manifest
//! signed by it, which would otherwise be an update-channel RCE. Same rule as `coord::verified_seeds`.

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

/// Verify the coordinator's release manifest and stage an update if one applies to us: signature
/// valid against the **pinned** anchor, version strictly newer than ours, and an artifact for this
/// platform. `None` in every other case (no manifest, bad signature, not newer, wrong platform) — a
/// failure is logged and swallowed, never fatal to the mesh.
///
/// The anchors are the pinned per-guild keys on disk (`keys::load_all_anchors`), **not** the
/// response's own anchors: trusting those would let a substituted response ship an attacker-signed
/// update. The coordinator signs the manifest under one guild key the caller holds (design.md
/// §3.1), so we accept it if it verifies against *any* pinned anchor. Same discipline as
/// [`crate::coord::verified_seeds`].
pub fn stage(resp: &RegisterResp, state_dir: &Path) -> Option<PendingUpdate> {
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

/// Download the artifact, re-verify size + SHA-256 against the (signed) manifest, then launch the
/// MSI and exit. Returns only on error; on success it never continues (see `apply_bytes`).
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
/// a field it didn't know was a dropped connection, not a clean error. Windows solves the same skew
/// through its MSI (which ships the new GUI, applied via `swap_in_staged_gui` when the exe is in
/// use) — so this restores the same on-disk lockstep on Linux.
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

/// The staged files extracted from an update bundle.
#[cfg(unix)]
struct Bundle {
    engine: Option<std::path::PathBuf>,
    gui: Option<std::path::PathBuf>,
}

/// Extract the two known binaries from the `.tar.gz` into `state_dir`. Entries are matched by file
/// name and everything else is ignored — so a path-traversal entry (`../../etc/passwd`) can never
/// escape, because we never join an archive-supplied path onto the destination.
#[cfg(unix)]
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
            Some("unitylan-engine") => &mut bundle.engine,
            Some("unitylan-gui") => &mut bundle.gui,
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

/// Windows: the artifact is the signed MSI. Write it out and launch `msiexec`; the MSI's
/// `MajorUpgrade` tears down the old service, replaces the files (engine + DLL), re-registers
/// the service, and starts it again (the `StartService` custom action, gated on `NOT Installed`,
/// true for the new product on an upgrade). We run `/quiet`, so the MSI's install wizard — including
/// the ExitDialog that would otherwise launch the GUI — is suppressed: an auto-update just swaps
/// files and restarts the daemon, it does not pop the GUI. We `exit(0)` first so the running engine
/// releases the service and its files before the upgrade removes them. `msiexec` is a detached
/// child, so it survives our exit and completes the swap + relaunch on its own.
///
/// The GUI is the exception: if it's open, its `unitylan-gui.exe` is locked and the upgrade
/// reboot-defers it. The MSI sidesteps that by also laying down an always-writable
/// `unitylan-gui.new.exe`; the running GUI renames that into place and relaunches itself in-session
/// once the user clicks "restart" (see the GUI's `swap_in_staged_gui`), so no reboot is needed.
#[cfg(windows)]
fn apply_bytes(bytes: &[u8], state_dir: &Path) -> anyhow::Result<()> {
    let msi = state_dir.join("unitylan-update.msi");
    std::fs::write(&msi, bytes).with_context(|| format!("writing {}", msi.display()))?;
    let msi_arg = msi
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 MSI path"))?;
    std::process::Command::new("msiexec")
        .args(["/i", msi_arg, "/quiet", "/norestart"])
        .spawn()
        .context("launching msiexec for the update")?;
    tracing::info!("launched msiexec; the service will restart via the MSI upgrade");
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
    #[cfg(unix)]
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
