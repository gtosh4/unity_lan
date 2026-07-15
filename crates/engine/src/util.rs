//! Small cross-module helpers.

/// Short lowercase-hex prefix (first 4 bytes) of a pubkey, for log lines.
pub fn hex8(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
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
