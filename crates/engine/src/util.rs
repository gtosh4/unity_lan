//! Small cross-module helpers.

/// Short lowercase-hex prefix (first 4 bytes) of a pubkey, for log lines.
pub fn hex8(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

/// Days of rolled log file kept. Long enough to still hold the failure a user is only now getting
/// round to reporting; short enough that a chronically flapping peer can't fill the disk of a box
/// nobody logs into.
const LOG_FILES_KEPT: usize = 7;

/// A daily-rolling appender for `path`, which names a *pattern* rather than one file: `engine.log`
/// is written as `engine.<date>.log` beside it, keeping [`LOG_FILES_KEPT`] days.
///
/// Both file-logging paths go through here — the `--log-file`/`log_file` sink in `main`, and the
/// Windows service, which has no console and so has nowhere else to log at all. Nothing prunes
/// these otherwise: before this they were plain appends that grew for the life of the install.
pub fn rolling_log_appender(
    path: &std::path::Path,
) -> anyhow::Result<tracing_appender::rolling::RollingFileAppender> {
    use anyhow::Context;

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .with_context(|| format!("log file {} has no file name", path.display()))?;
    let builder = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(stem)
        .max_log_files(LOG_FILES_KEPT);
    let builder = match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => builder.filename_suffix(ext),
        None => builder,
    };
    builder
        .build(dir)
        .with_context(|| format!("opening log file {}", path.display()))
}

/// Capability bits this daemon needs for things the kernel refuses without them. Linux only: nothing
/// else in the tree has a capability model where root is not enough.
#[cfg(target_os = "linux")]
pub mod caps {
    /// `CAP_CHOWN` — handing the certificate key to the proxy account's group.
    pub const CHOWN: u8 = 0;
    /// `CAP_SETUID` — dropping the TLS proxy child to its own account. `CAP_SETGID` (bit 6) is
    /// granted with it by every unit that grants either, so checking one answers for both.
    pub const SETUID: u8 = 7;

    /// Whether this process's **bounding** set is missing `bit`, which is what makes an operation
    /// fail with `EPERM` even as uid 0 — the systemd unit's `CapabilityBoundingSet` decides it, so a
    /// unit written before a feature existed silently disables that feature. Worth saying out loud:
    /// the bare `Operation not permitted` that comes back otherwise points at nothing.
    ///
    /// `None` when the answer cannot be known (no procfs, an unparsable line): callers then say
    /// nothing rather than guess at a cause.
    pub fn bounding_set_lacks(bit: u8) -> Option<bool> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        lacks_in(&status, bit)
    }

    /// The parsing half, split out so it is testable without a procfs shape to fake.
    fn lacks_in(status: &str, bit: u8) -> Option<bool> {
        let hex = status
            .lines()
            .find_map(|l| l.strip_prefix("CapBnd:"))?
            .trim();
        let set = u64::from_str_radix(hex, 16).ok()?;
        Some(set & (1u64 << bit) == 0)
    }

    /// A sentence naming the missing capability, or nothing at all when it is present (or unknown).
    /// Appended to the failure it explains rather than logged on its own, so the cause and the fix
    /// arrive together.
    pub fn hint(bit: u8, name: &str) -> String {
        match bounding_set_lacks(bit) {
            Some(true) => format!(
                " — this daemon's capability bounding set has no {name}, so the kernel refuses it \
                 even as root. Add {name} to `CapabilityBoundingSet=` and `AmbientCapabilities=` in \
                 the systemd unit (`systemctl edit unitylan-engine`), then restart"
            ),
            _ => String::new(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The bit arithmetic is the whole function, and getting it wrong would either cry wolf on a
        /// working host or stay quiet on the one host that needed telling.
        #[test]
        fn a_missing_bit_is_reported_and_a_present_one_is_not() {
            // CAP_NET_ADMIN|CAP_NET_BIND_SERVICE|CAP_NET_RAW — the pre-0.6.1 unit's set.
            let old = "Name:\tunitylan-engine\nCapBnd:\t0000000000003400\nSeccomp:\t0\n";
            assert_eq!(lacks_in(old, SETUID), Some(true));
            assert_eq!(lacks_in(old, CHOWN), Some(true));
            // ...plus CAP_CHOWN, CAP_SETGID, CAP_SETUID.
            let fixed = "CapBnd:\t00000000000034c1\n";
            assert_eq!(lacks_in(fixed, SETUID), Some(false));
            assert_eq!(lacks_in(fixed, CHOWN), Some(false));
            // Nothing to read means nothing to say — never a guess.
            assert_eq!(lacks_in("Name:\tx\n", SETUID), None);
            assert_eq!(lacks_in("CapBnd:\tnot-hex\n", SETUID), None);
        }
    }
}

/// Run a PowerShell `-Command` script, bailing on failure with `{context} script failed` + stderr.
/// `context` names the caller's domain (e.g. "firewall", "NRPT") for the error message.
#[cfg(windows)]
pub fn run_powershell(script: &str, context: &str) -> anyhow::Result<()> {
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| anyhow::anyhow!("spawning powershell (is it on PATH?): {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "powershell {context} script failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}
