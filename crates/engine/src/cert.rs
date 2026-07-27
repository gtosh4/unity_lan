//! ACME (DNS-01) issuance of a publicly-trusted certificate for this device's mesh names.
//!
//! The device does the whole ACME conversation itself: it generates the keypair, talks to the CA,
//! and keeps the private key. The coordinator's only involvement is publishing a TXT record it
//! derives from our own allocation (`/acme-challenge`, [`crate::coord::acme_challenge`]) — it never
//! sees key material, which keeps it on the control plane like everything else.
//!
//! DNS-01 rather than HTTP-01 because a mesh name resolves to a `100.64.0.0/10` address the CA can
//! never reach; DNS-01 validates *control of the name*, not reachability of the host.
//!
//! **Rate limits shape this module more than anything else.** A CA caps duplicate certificates
//! (Let's Encrypt: ~5 per identical name set per week) and ACME accounts per IP (~10 per 3 hours),
//! and a LAN party enrolling twenty machines behind one NAT hits the second immediately. So: the
//! account key is created once per device *lifetime* and persisted, issuance is refused outright
//! while a valid certificate exists, and every failure is recorded so a retry backs off instead of
//! spinning. Burning a limit locks the device — or the whole deployment — out for the window.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};

/// Let's Encrypt's production directory — the default when a config names none.
pub const DEFAULT_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Renew once the certificate has less than this left. Well inside a 90-day lifetime, so a device
/// that is offline for a few weeks still wakes with time to renew before anything breaks.
pub const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The names one certificate covers: this device and everything one label below it
/// ([`CertNames::wildcard`]), plus the bare `<user>` alias when it is the owner's primary. Pinned at
/// issuance — see [`IssuedState`].
///
/// The wildcard is derived rather than stored: it is always ordered, so a field would only be a
/// second place for the same fact to live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertNames {
    pub device: String,
    #[serde(default)]
    pub primary: Option<String>,
    /// Full names for this device's **web** services — `jellyfin.alice.<domain>`. Only labels the
    /// coordinator confirmed are ours appear here: it will not publish a challenge for anything
    /// else, so ordering one would fail the whole certificate rather than just that name.
    #[serde(default)]
    pub services: Vec<String>,
}

impl CertNames {
    /// Build the names for this device under `domain`, from the mesh names it already answers to.
    /// `hostname` and `primary_alias` are the `unity.internal` names; the certificate covers the same
    /// stems under the deployment's public domain. `services` are bare labels the coordinator has
    /// confirmed this device holds.
    pub fn new(
        hostname: &str,
        primary_alias: Option<&str>,
        domain: &str,
        services: &[String],
    ) -> Option<Self> {
        let device = swap_suffix(hostname, domain)?;
        // A service name sits under the *user*, not the device — `jellyfin.alice`, beside
        // `laptop.alice` — so it is built from the user part of our own hostname.
        let user = device.split_once('.').map(|(_, rest)| rest.to_string())?;
        Some(Self {
            device,
            primary: primary_alias.and_then(|a| swap_suffix(a, domain)),
            services: services
                .iter()
                .map(|label| format!("{label}.{user}").to_ascii_lowercase())
                .collect(),
        })
    }

    /// `*.<device>.<user>.<domain>` — every name one label below this device.
    ///
    /// So a device running a reverse proxy can serve `plex.server.alice.<domain>`,
    /// `git.server.alice.<domain>` and the rest from one certificate. The glob stops at this
    /// device: deliberately *not* `*.<user>.<domain>`, which would match a sibling device's own
    /// name and hand this machine TLS authority over the owner's other devices.
    pub fn wildcard(&self) -> String {
        format!("*.{}", self.device)
    }

    fn identifiers(&self) -> Vec<Identifier> {
        self.all().into_iter().map(Identifier::Dns).collect()
    }

    /// The bare label for one of our service names, or `None` if we did not order it.
    fn service_label(&self, name: &str) -> Option<String> {
        self.services
            .iter()
            .find(|s| *s == name)
            .and_then(|s| s.split_once('.'))
            .map(|(label, _)| label.to_string())
    }

    /// Every name the certificate covers, in the order it names them.
    pub fn all(&self) -> Vec<String> {
        std::iter::once(self.device.clone())
            .chain(std::iter::once(self.wildcard()))
            .chain(self.primary.clone())
            .chain(self.services.iter().cloned())
            .collect()
    }
}

fn swap_suffix(name: &str, domain: &str) -> Option<String> {
    let stem = name
        .trim_end_matches('.')
        .strip_suffix(&format!(".{}", common::DNS_SUFFIX))?;
    Some(format!("{stem}.{domain}").to_ascii_lowercase())
}

/// What we last did, persisted beside the certificate.
///
/// Exists so a restart does not re-enter ACME: without it, a crash-looping daemon would re-order on
/// every start and exhaust the duplicate-certificate limit within an hour, locking the device out for
/// a week — a far worse outcome than the failure it was retrying.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IssuedState {
    /// The names the live certificate was issued for. **Pinned**: a later Discord rename changes the
    /// mesh name but must not invalidate a certificate bound to the old one for its whole life. A
    /// device rename does trigger reissue — that one is deliberate and rare.
    #[serde(default)]
    pub names: Option<CertNames>,
    /// `notAfter` of the live certificate (unix secs).
    #[serde(default)]
    pub expires_at: u64,
    /// When the last attempt failed (unix secs), and how many have failed in a row. Drives backoff.
    #[serde(default)]
    pub last_failure: u64,
    #[serde(default)]
    pub failures: u32,
    /// When the wanted name set first stopped matching the held certificate (unix secs); `0` when
    /// they agree. Drives the [`SETTLE`] wait, and is persisted so a restart mid-setup does not
    /// forget it and start the batching window over.
    #[serde(default)]
    pub pending_since: u64,
}

impl IssuedState {
    /// How long to wait after `failures` consecutive failures: 5 minutes doubling to a 24-hour
    /// ceiling. Jittered by the caller so a fleet that failed together does not retry together.
    pub fn backoff(&self) -> Duration {
        if self.failures == 0 {
            return Duration::ZERO;
        }
        // Clamp the shift well below `u64`'s width so the multiply cannot wrap; the 24-hour ceiling
        // is what actually bounds it.
        let secs = 300u64.saturating_mul(1u64 << self.failures.min(32));
        Duration::from_secs(secs.min(24 * 60 * 60))
    }
}

pub fn certs_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("certs")
}
pub fn cert_path(state_dir: &Path) -> PathBuf {
    certs_dir(state_dir).join("cert.pem")
}
pub fn key_path(state_dir: &Path) -> PathBuf {
    certs_dir(state_dir).join("key.pem")
}
fn account_path(state_dir: &Path) -> PathBuf {
    certs_dir(state_dir).join("acme-account.json")
}
fn state_path(state_dir: &Path) -> PathBuf {
    certs_dir(state_dir).join("issued.json")
}

pub fn load_state(state_dir: &Path) -> IssuedState {
    std::fs::read_to_string(state_path(state_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_state(state_dir: &Path, state: &IssuedState) -> anyhow::Result<()> {
    std::fs::create_dir_all(certs_dir(state_dir))?;
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(state_path(state_dir), json).context("writing certificate issuance state")
}

/// Reuse this device's ACME account, creating one only on first ever issuance.
///
/// Persisted deliberately: a CA caps new accounts per source IP over a short window, so a fleet
/// behind one NAT that created an account per issuance would throttle itself on the first evening it
/// was set up.
async fn account(
    state_dir: &Path,
    directory: &str,
    root: Option<&Path>,
) -> anyhow::Result<Account> {
    // A custom root governs the TLS connection to the ACME directory only — it is how a local test
    // CA is reached, and it grants nothing about which certificates are trusted.
    let builder = || match root {
        Some(pem) => Account::builder_with_root(pem)
            .with_context(|| format!("reading the ACME root {}", pem.display())),
        None => Account::builder().context("building an ACME client"),
    };
    let path = account_path(state_dir);
    if let Ok(text) = std::fs::read_to_string(&path) {
        let creds: AccountCredentials =
            serde_json::from_str(&text).context("decoding the saved ACME account")?;
        return builder()?
            .from_credentials(creds)
            .await
            .context("restoring the saved ACME account");
    }

    let (account, credentials) = builder()?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.to_string(),
            None,
        )
        .await
        .context("creating an ACME account")?;
    // The account key is a credential: it can act for every certificate this device ever holds.
    crate::keys::write_private(&path, serde_json::to_string(&credentials)?.as_bytes())
        .context("saving the ACME account")?;
    Ok(account)
}

/// Run one full issuance and write the results. Returns the certificate's `notAfter`.
///
/// The caller decides *whether* to issue (see [`crate::daemon`]); this only knows how.
pub async fn issue(
    state_dir: &Path,
    coordinator: &str,
    token: String,
    names: &CertNames,
    directory: &str,
    root: Option<&Path>,
) -> anyhow::Result<u64> {
    let account = account(state_dir, directory, root).await?;
    let identifiers = names.identifiers();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("creating the ACME order")?;

    // Pass one: collect every challenge value. They must all be published *before* any is marked
    // ready, and in one request — the coordinator charges its weekly budget per request, so posting
    // per authorization would spend two units on a single certificate.
    let mut device_values = Vec::new();
    let mut primary_value = None;
    let mut service_values = std::collections::BTreeMap::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.context("reading an ACME authorization")?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => anyhow::bail!("ACME authorization is {other:?}, cannot proceed"),
        }
        let challenge = authz
            .challenge(ChallengeType::Dns01)
            .context("the CA offered no dns-01 challenge")?;
        let identifier = challenge.identifier().to_string();
        let value = challenge.key_authorization().dns_value();
        // The device name and its wildcard are two authorizations with two distinct values, both
        // of which the CA looks for at the *one* `_acme-challenge.<device>.<user>.<domain>` name —
        // dns-01 validates a wildcard at its base. So both are collected here and published
        // together, rather than the second silently replacing the first.
        //
        // `identifier()` reports what we ordered, `*.` and all. (The authorization object itself
        // carries the base name plus a `wildcard` flag — RFC 8555 §7.1.4 — but that is not the
        // string this returns, and assuming otherwise cost a debugging round.)
        if identifier == names.device || identifier == names.wildcard() {
            device_values.push(value);
        } else if Some(&identifier) == names.primary.as_ref() {
            primary_value = Some(value);
        } else if let Some(label) = names.service_label(&identifier) {
            // Keyed by label: the coordinator publishes this only if its own rows say we hold the
            // name, so a value can never land on somebody else's.
            service_values.insert(label, value);
        } else {
            anyhow::bail!("the CA asked us to validate {identifier:?}, which we did not order");
        }
    }
    if device_values.is_empty() && service_values.is_empty() {
        // Every authorization was already valid — the CA is reusing a recent one, so nothing to
        // publish and the order is ready to finalize.
        return finalize(state_dir, &mut order).await;
    }
    if device_values.len() > common::api::MAX_DEVICE_CHALLENGES {
        anyhow::bail!(
            "the CA raised {} challenges for this device's name; expected at most {}",
            device_values.len(),
            common::api::MAX_DEVICE_CHALLENGES
        );
    }

    crate::coord::acme_challenge(
        coordinator,
        token,
        device_values,
        primary_value,
        service_values,
    )
    .await
    .context("asking the coordinator to publish the challenge")?;

    // Pass two: tell the CA to check, now that the records are live.
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.context("reading an ACME authorization")?;
        if authz.status != AuthorizationStatus::Pending {
            continue;
        }
        authz
            .challenge(ChallengeType::Dns01)
            .context("the CA offered no dns-01 challenge")?
            .set_ready()
            .await
            .context("telling the CA the challenge is ready")?;
    }

    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .context("waiting for the CA to validate the challenge")?;
    if status != OrderStatus::Ready {
        anyhow::bail!("the CA left the order {status:?} rather than ready");
    }
    finalize(state_dir, &mut order).await
}

/// Mint the keypair, finalize, and write both halves. Returns the certificate's `notAfter`.
async fn finalize(state_dir: &Path, order: &mut instant_acme::Order) -> anyhow::Result<u64> {
    // `finalize` generates the keypair locally and sends only a CSR — the private key never leaves
    // this machine, and the coordinator never sees it either.
    let key_pem = order.finalize().await.context("finalizing the order")?;
    let chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("collecting the issued certificate")?;

    let expires_at = not_after(&chain_pem)?;
    std::fs::create_dir_all(certs_dir(state_dir))?;
    // The certificate is public by definition; the key is not.
    std::fs::write(cert_path(state_dir), &chain_pem).context("writing the certificate")?;
    crate::keys::write_private(&key_path(state_dir), key_pem.as_bytes())
        .context("writing the certificate key")?;
    Ok(expires_at)
}

/// Hand the key to the group that needs to read it: `root:<group>`, mode `0640`.
///
/// Without this the key is owner-only and the engine is root, so the daemon that actually serves TLS
/// cannot open it. Failure is reported, not fatal — the certificate is still valid and an operator
/// can fix the group; silently continuing with an unreadable key would be worse.
#[cfg(not(windows))]
pub fn grant_key_group(state_dir: &Path, group: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = key_path(state_dir);
    let gid = crate::control::server::group_gid(group)
        .with_context(|| format!("no such group {group:?} for the certificate key"))?;
    std::os::unix::fs::chown(&path, None, Some(gid))
        .with_context(|| format!("giving {} to group {group}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
        .context("relaxing the certificate key to group-readable")?;
    Ok(())
}

#[cfg(windows)]
pub fn grant_key_group(_state_dir: &Path, _group: &str) -> anyhow::Result<()> {
    anyhow::bail!("[cert] group is unix-only; grant access with an ACL on the certs directory")
}

/// Run the configured reload command, so whatever serves TLS re-reads the certificate we just wrote.
///
/// `argv` comes from config alone and is executed directly — never through a shell, and never
/// carrying anything a peer or the coordinator supplied. A command that outlives
/// [`crate::config::RELOAD_TIMEOUT`] is killed rather than allowed to stall the reconcile loop.
pub async fn run_reload(argv: &[String]) -> anyhow::Result<()> {
    let Some((program, args)) = argv.split_first() else {
        return Ok(());
    };
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("running the certificate reload command {program:?}"))?;
    let status = match tokio::time::timeout(crate::config::RELOAD_TIMEOUT, child.wait()).await {
        Ok(status) => status.context("waiting for the certificate reload command")?,
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!(
                "the certificate reload command {program:?} outlived its {:?} deadline and was killed",
                crate::config::RELOAD_TIMEOUT
            );
        }
    };
    if !status.success() {
        anyhow::bail!("the certificate reload command {program:?} exited with {status}");
    }
    Ok(())
}

/// `notAfter` of the leaf, in unix seconds.
fn not_after(chain_pem: &str) -> anyhow::Result<u64> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("the CA returned an unparseable certificate: {e}"))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("the CA returned an unparseable certificate: {e}"))?;
    Ok(cert.validity().not_after.timestamp().max(0) as u64)
}

/// Everything the reconcile needs, gathered by the daemon once per refresh.
pub struct Reconcile<'a> {
    pub state_dir: &'a Path,
    pub coordinator: &'a str,
    pub token: String,
    pub cfg: &'a crate::config::CertConfig,
    /// This device's `unity.internal` names, and the deployment's certificate domain.
    pub hostname: &'a str,
    pub primary_alias: Option<&'a str>,
    pub dns_domain: Option<&'a str>,
    /// Whether the owner opted in, and whether anything is actually listening.
    pub enabled: bool,
    pub exposed: bool,
    /// Web service labels the coordinator confirmed are ours, to be named in the certificate.
    pub services: Vec<String>,
}

/// How long a changed name set must hold still before it is worth a certificate.
///
/// Naming three services in a row is one intent, but each change makes the previous certificate
/// wrong — issuing per change would spend three of the CA's weekly allowance on the first two
/// minutes of setup, and that allowance is shared by every device on the deployment. Waiting a few
/// minutes costs nothing a person notices and turns a burst into one order.
pub const SETTLE: Duration = Duration::from_secs(10 * 60);

/// Decide what to do, and say why when the answer is "nothing".
///
/// Separated from the doing so the policy is testable without an ACME server: every gate below is a
/// rate limit or a privacy decision, and getting one wrong is expensive in a way a network round trip
/// would hide.
pub enum Action {
    /// Nothing to do; the string is what to show the user, or `None` when a valid certificate is
    /// simply in place.
    Idle(Option<String>),
    Issue(CertNames),
}

/// Stamp (or clear) when the wanted names stopped matching the held certificate, so [`decide`] can
/// tell a set that just changed from one that has settled. Returns whether the stamp moved, which is
/// the caller's cue to persist.
///
/// Split out rather than folded into `decide` so that stays a pure function of state — every gate in
/// it is a rate limit, and a policy you cannot evaluate twice for the same answer is one you cannot
/// test.
pub fn note_pending(r: &Reconcile<'_>, state: &mut IssuedState, now: u64) -> bool {
    let wanted = r
        .dns_domain
        .and_then(|d| CertNames::new(r.hostname, r.primary_alias, d, &r.services));
    let matches = wanted.is_some() && wanted.as_ref() == state.names.as_ref();
    let before = state.pending_since;
    if matches || state.names.is_none() {
        state.pending_since = 0;
    } else if state.pending_since == 0 {
        state.pending_since = now;
    }
    state.pending_since != before
}

pub fn decide(r: &Reconcile<'_>, state: &IssuedState, now: u64) -> Action {
    let Some(domain) = r.dns_domain else {
        return Action::Idle(None); // the feature does not exist on this deployment
    };
    if !r.enabled {
        return Action::Idle(None); // not opted in; nothing to explain
    }
    let Some(names) = CertNames::new(r.hostname, r.primary_alias, domain, &r.services) else {
        return Action::Idle(Some("this device has no mesh name yet".into()));
    };

    let held = state.names.as_ref() == Some(&names) && state.expires_at > now;
    let renew_due = state.expires_at.saturating_sub(now) < RENEW_BEFORE.as_secs();

    // A certificate is only useful if something is listening. Skipping renewal while nothing is
    // exposed keeps the existing one to its natural expiry rather than yanking it from a service
    // that may still be reading it.
    if !r.exposed {
        return Action::Idle(Some(if held {
            "no port is exposed, so this certificate will not be renewed".into()
        } else {
            "expose a port first — a certificate is only useful if something is listening".into()
        }));
    }
    if held && !renew_due {
        return Action::Idle(None);
    }
    // A name set that changed under a *live* certificate waits for the churn to stop. Renewal and
    // first issuance are exempt: there is nothing to protect in the first case (the certificate is
    // expiring anyway) and nothing to wait for in the second.
    if !held && state.expires_at > now && !renew_due {
        let waited = now.saturating_sub(state.pending_since);
        if waited < SETTLE.as_secs() {
            let mins = (SETTLE.as_secs().saturating_sub(waited) / 60).max(1);
            return Action::Idle(Some(format!(
                "the services this certificate covers changed; reissuing in about {mins} minutes \
                 (batched, so naming a few in a row costs one certificate)"
            )));
        }
    }
    // Back off after a failure. A CA caps duplicate certificates at roughly five a week, so a tight
    // retry loop locks this device out for days — far worse than waiting.
    let wait = state.backoff().as_secs();
    if state.failures > 0 && now < state.last_failure.saturating_add(wait) {
        let mins = state.last_failure.saturating_add(wait).saturating_sub(now) / 60;
        return Action::Idle(Some(format!(
            "the last attempt failed; retrying in about {} minutes",
            mins.max(1)
        )));
    }
    Action::Issue(names)
}

/// Run one reconcile: issue or renew if the policy says so, then hand the result to whatever serves
/// TLS. Returns the status to publish.
pub async fn reconcile(r: Reconcile<'_>) -> common::control::CertStatus {
    let mut state = load_state(r.state_dir);
    let mut status = common::control::CertStatus {
        enabled: r.enabled,
        domain: r.dns_domain.map(str::to_string),
        ..Default::default()
    };
    if let Some(names) = &state.names {
        if state.expires_at > common::now_unix() {
            status.names = names.all();
            status.cert_path = Some(cert_path(r.state_dir).display().to_string());
            status.key_path = Some(key_path(r.state_dir).display().to_string());
            status.expires_at = state.expires_at;
        }
    }

    if note_pending(&r, &mut state, common::now_unix()) {
        // Persisted so the batching window survives a restart mid-setup rather than starting over.
        let _ = save_state(r.state_dir, &state);
    }
    let names = match decide(&r, &state, common::now_unix()) {
        Action::Idle(why) => {
            status.blocked = why;
            return status;
        }
        Action::Issue(names) => names,
    };

    let directory = r.cfg.acme_directory.as_deref().unwrap_or(DEFAULT_DIRECTORY);
    tracing::info!(name = %names.device, "certificate: requesting from {directory}");
    match issue(
        r.state_dir,
        r.coordinator,
        r.token,
        &names,
        directory,
        r.cfg.acme_root.as_deref(),
    )
    .await
    {
        Ok(expires_at) => {
            state = IssuedState {
                names: Some(names.clone()),
                expires_at,
                last_failure: 0,
                failures: 0,
                pending_since: 0,
            };
            if let Err(e) = save_state(r.state_dir, &state) {
                tracing::warn!("certificate: could not record issuance: {e:#}");
            }
            // Permissions before the reload: the service is about to read the key.
            if let Some(group) = &r.cfg.group {
                if let Err(e) = grant_key_group(r.state_dir, group) {
                    tracing::error!("certificate: {e:#}");
                }
            }
            if let Err(e) = run_reload(&r.cfg.reload_command).await {
                // Loud, because the symptom otherwise appears 60 days later as an expired
                // certificate on a service nobody was watching.
                tracing::error!("certificate: {e:#}");
            }
            tracing::info!(name = %names.device, "certificate: issued");
            status.names = names.all();
            status.cert_path = Some(cert_path(r.state_dir).display().to_string());
            status.key_path = Some(key_path(r.state_dir).display().to_string());
            status.expires_at = expires_at;
            status.blocked = None;
        }
        Err(e) => {
            state.failures = state.failures.saturating_add(1);
            state.last_failure = common::now_unix();
            let _ = save_state(r.state_dir, &state);
            tracing::warn!("certificate: issuance failed (will retry): {e:#}");
            status.blocked = Some(format!("{e:#}"));
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_names_swap_the_suffix_for_the_public_domain() {
        let names = CertNames::new(
            "laptop.gordon.unity.internal",
            Some("gordon.unity.internal"),
            "mesh.example.com",
            &[],
        )
        .unwrap();
        assert_eq!(names.device, "laptop.gordon.mesh.example.com");
        assert_eq!(names.primary.as_deref(), Some("gordon.mesh.example.com"));
    }

    #[test]
    fn a_non_primary_device_orders_its_own_name_and_its_wildcard() {
        let names = CertNames::new(
            "desktop.gordon.unity.internal",
            None,
            "mesh.example.com",
            &[],
        )
        .unwrap();
        assert_eq!(names.identifiers().len(), 2);
        assert!(names.primary.is_none());
        assert_eq!(
            names.all(),
            vec![
                "desktop.gordon.mesh.example.com".to_string(),
                "*.desktop.gordon.mesh.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn the_wildcard_stops_at_this_device() {
        // `*.<user>.<domain>` would match a sibling device's own name — `laptop.gordon.…` — and so
        // hand whichever machine held it a publicly-trusted certificate for the owner's others.
        // The glob is anchored one level lower, under this device.
        let names = CertNames::new(
            "laptop.gordon.unity.internal",
            Some("gordon.unity.internal"),
            "mesh.example.com",
            &[],
        )
        .unwrap();
        assert_eq!(names.wildcard(), "*.laptop.gordon.mesh.example.com");
        assert!(!names
            .all()
            .contains(&"*.gordon.mesh.example.com".to_string()));
    }

    const NOW: u64 = 1_800_000_000;

    fn recon(enabled: bool, exposed: bool, domain: Option<&'static str>) -> Reconcile<'static> {
        Reconcile {
            state_dir: Path::new("/nonexistent"),
            coordinator: "http://coordinator.invalid",
            token: "t".into(),
            cfg: Box::leak(Box::new(crate::config::CertConfig::default())),
            hostname: "laptop.gordon.unity.internal",
            primary_alias: None,
            dns_domain: domain,
            enabled,
            exposed,
            services: Vec::new(),
        }
    }

    fn held(names: CertNames, expires_in: u64) -> IssuedState {
        IssuedState {
            names: Some(names),
            expires_at: NOW + expires_in,
            ..Default::default()
        }
    }

    fn names() -> CertNames {
        CertNames::new(
            "laptop.gordon.unity.internal",
            None,
            "mesh.example.com",
            &[],
        )
        .unwrap()
    }

    #[test]
    fn a_web_service_is_named_under_the_user_not_the_device() {
        // `jellyfin.gordon`, beside `laptop.gordon` — not `jellyfin.laptop.gordon`. The service
        // belongs to the owner and may move between their devices; the name should not have to
        // change when it does.
        let names = CertNames::new(
            "laptop.gordon.unity.internal",
            None,
            "mesh.example.com",
            &["jellyfin".to_string(), "git".to_string()],
        )
        .unwrap();
        assert_eq!(
            names.services,
            vec![
                "jellyfin.gordon.mesh.example.com".to_string(),
                "git.gordon.mesh.example.com".to_string(),
            ]
        );
        assert!(names
            .all()
            .contains(&"jellyfin.gordon.mesh.example.com".to_string()));
    }

    /// Naming three services in a row is one intent; issuing per change would spend three of the
    /// CA's weekly allowance — shared by the whole deployment — on the first minutes of setup.
    #[test]
    fn a_changed_service_set_batches_instead_of_reissuing_per_change() {
        let mut r = recon(true, true, Some("mesh.example.com"));
        let mut state = held(names(), 60 * 24 * 3600); // a live certificate, nowhere near renewal
        assert!(
            matches!(decide(&r, &state, NOW), Action::Idle(None)),
            "settled"
        );

        // The owner names a web service: the held certificate no longer covers what we want.
        r.services = vec!["jellyfin".to_string()];
        assert!(note_pending(&r, &mut state, NOW), "stamped when it changed");
        assert_eq!(state.pending_since, NOW);
        assert!(
            matches!(decide(&r, &state, NOW + 60), Action::Idle(Some(_))),
            "still inside the settle window"
        );

        // A second service a minute later does not restart the clock — the window is about the
        // burst, not the latest change.
        r.services = vec!["jellyfin".to_string(), "git".to_string()];
        assert!(!note_pending(&r, &mut state, NOW + 60), "stamp unchanged");
        assert_eq!(state.pending_since, NOW);

        // Once it settles, one order covers both.
        match decide(&r, &state, NOW + SETTLE.as_secs()) {
            Action::Issue(names) => assert_eq!(names.services.len(), 2),
            other => panic!(
                "expected an issue after the settle window, got {:?}",
                matches!(other, Action::Idle(_))
            ),
        }
    }

    /// First issuance has nothing to batch and nothing to protect, so it must not wait.
    #[test]
    fn a_device_with_no_certificate_yet_does_not_wait_out_the_settle_window() {
        let mut r = recon(true, true, Some("mesh.example.com"));
        r.services = vec!["jellyfin".to_string()];
        let mut state = IssuedState::default();
        note_pending(&r, &mut state, NOW);
        assert_eq!(state.pending_since, 0, "nothing held, nothing pending");
        assert!(matches!(decide(&r, &state, NOW), Action::Issue(_)));
    }

    /// ...and neither does a renewal: that certificate is expiring regardless, so waiting only eats
    /// into the margin.
    #[test]
    fn a_renewal_is_not_held_up_by_a_changed_service_set() {
        let mut r = recon(true, true, Some("mesh.example.com"));
        r.services = vec!["jellyfin".to_string()];
        let mut state = held(names(), RENEW_BEFORE.as_secs() - 3600);
        note_pending(&r, &mut state, NOW);
        assert!(matches!(decide(&r, &state, NOW), Action::Issue(_)));
    }

    #[test]
    fn nothing_happens_without_a_domain_or_an_opt_in() {
        // Both are silent rather than "blocked": the feature simply doesn't apply, and nagging about
        // it would be noise on every device that never wanted it.
        let idle = |r: Reconcile<'_>| {
            matches!(decide(&r, &IssuedState::default(), NOW), Action::Idle(None))
        };
        assert!(idle(recon(true, true, None)), "no certificate domain");
        assert!(
            idle(recon(false, true, Some("mesh.example.com"))),
            "not opted in"
        );
    }

    #[test]
    fn an_opted_in_device_with_nothing_listening_is_told_why() {
        // A certificate is only useful if something is serving, and issuing one publishes this
        // device's name to public logs forever — so an unused device does not silently spend that.
        let r = recon(true, false, Some("mesh.example.com"));
        let Action::Idle(Some(why)) = decide(&r, &IssuedState::default(), NOW) else {
            panic!("should be blocked with a reason");
        };
        assert!(why.contains("expose a port"), "{why}");
    }

    #[test]
    fn un_exposing_stops_renewal_but_keeps_the_certificate() {
        // Yanking a live certificate out from under a service that may still be reading it would be
        // worse than letting it run to its natural expiry.
        let r = recon(true, false, Some("mesh.example.com"));
        let Action::Idle(Some(why)) = decide(&r, &held(names(), 10 * 86_400), NOW) else {
            panic!("should be blocked with a reason");
        };
        assert!(why.contains("not be renewed"), "{why}");
    }

    #[test]
    fn a_valid_certificate_is_left_alone_until_renewal_is_due() {
        // The duplicate-certificate limit is the reason this gate exists: re-ordering a certificate
        // we already hold burns it for nothing.
        let r = recon(true, true, Some("mesh.example.com"));
        assert!(matches!(
            decide(&r, &held(names(), 60 * 86_400), NOW),
            Action::Idle(None)
        ));
        assert!(matches!(
            decide(&r, &held(names(), 10 * 86_400), NOW),
            Action::Issue(_)
        ));
    }

    #[test]
    fn a_rename_does_not_invalidate_the_pinned_certificate() {
        // The certificate names what it was issued for. A device answering to a new mesh name still
        // holds a valid certificate for the old one, and reissuing on every rename would spend the
        // weekly budget on cosmetics.
        let r = recon(true, true, Some("mesh.example.com"));
        let stale = held(
            CertNames::new(
                "laptop.oldname.unity.internal",
                None,
                "mesh.example.com",
                &[],
            )
            .unwrap(),
            60 * 86_400,
        );
        // The device's *own* name changed, so this one does reissue — that is the deliberate case.
        assert!(matches!(decide(&r, &stale, NOW), Action::Issue(_)));
        // ...while an unchanged name with plenty of life left is left alone.
        assert!(matches!(
            decide(&r, &held(names(), 60 * 86_400), NOW),
            Action::Idle(None)
        ));
    }

    #[test]
    fn a_failure_backs_off_before_retrying() {
        let r = recon(true, true, Some("mesh.example.com"));
        let failed = IssuedState {
            failures: 2,
            last_failure: NOW - 60,
            ..Default::default()
        };
        let Action::Idle(Some(why)) = decide(&r, &failed, NOW) else {
            panic!("should be waiting out the backoff");
        };
        assert!(why.contains("retrying"), "{why}");
        // Once the window passes it tries again.
        assert!(matches!(
            decide(&r, &failed, NOW + failed.backoff().as_secs()),
            Action::Issue(_)
        ));
    }

    #[test]
    fn backoff_grows_then_caps() {
        // A failing device must not keep hammering: the duplicate-certificate limit is ~5 a week, so
        // a tight retry loop would lock this device out for days.
        let mut s = IssuedState::default();
        assert_eq!(s.backoff(), Duration::ZERO);
        s.failures = 1;
        assert_eq!(s.backoff(), Duration::from_secs(600));
        s.failures = 3;
        assert_eq!(s.backoff(), Duration::from_secs(2400));
        s.failures = 99;
        assert_eq!(s.backoff(), Duration::from_secs(24 * 60 * 60));
    }
}
