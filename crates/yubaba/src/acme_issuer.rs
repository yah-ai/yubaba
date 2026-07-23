//! Single elected ACME issuer for the fleet-shared wildcard cert (R600-F3 / W273).
//!
//! Exactly one node issues + renews `*.<domain>` at a time; every other node is
//! a pure consumer that reads the replicated ciphertext (R600-F2). "Exactly one"
//! is enforced with the raft distributed-lock primitive
//! ([`YubabaRequest::AcquireLock`]) rather than a copy of leader election: each
//! node periodically tries to acquire the `acme-issuer/<domain>` lock; the
//! single grantee issues, everyone else stands by. The lock carries a TTL, so a
//! dead issuer's claim frees automatically and a survivor takes over on the next
//! tick — a leader change (or issuer crash) re-elects cleanly and two nodes never
//! issue concurrently.
//!
//! The cert material is sealed with the node-local cluster KEK
//! ([`crate::secrets::seal_cluster_secret`]) and written into raft as two
//! separate cluster secrets — one for the cert chain, one for the private key —
//! keyed by [`cert_secret_name`] / [`key_secret_name`]. Two records (not one
//! bundled blob) because the `SecretRef::Cluster` resolver (R600-F2) renders one
//! record to one tmpfs `File` mount, and passway consumes the cert and key as
//! two separate files (`PASSWAY_TLS_CERT` / `PASSWAY_TLS_KEY`). F5 declares the
//! matching pair of `SecretMount`s.
//!
//! This module holds the *pure* election + renewal decision so it is unit-
//! testable without a live raft node or a network ACME round-trip; the loop that
//! drives `AcquireLock` → `acme_engine::issue` → seal → `PutSecret` is wired on
//! top of it (R600-F3 runtime).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use acme_engine::{AcmeChallengeKind, AcmeDirectory, IssueConfig};
use openraft::async_runtime::watch::WatchReceiver;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use crate::raft::{
    SecretRecord, YubabaNodeId, YubabaRaft, YubabaRequest, YubabaResponse, YubabaStateMachine,
};
use crate::secrets::{load_cluster_kek, seal_cluster_secret, CLUSTER_KEK_PATH};

/// How often the issuer polls while the fleet still has **no** cert — a cold
/// start should mint the first cert within a minute of the issuer node winning
/// leadership, not wait a full renewal interval.
const FIRST_ISSUE_POLL_SECS: u64 = 60;

/// Logical cluster-secret key for the issued cert **chain** PEM of `domain`.
/// e.g. `cert_secret_name("yah.dev") == "tls/yah.dev/cert"`.
pub fn cert_secret_name(domain: &str) -> String {
    format!("tls/{domain}/cert")
}

/// Logical cluster-secret key for the issued private **key** PEM of `domain`.
/// e.g. `key_secret_name("yah.dev") == "tls/yah.dev/key"`.
pub fn key_secret_name(domain: &str) -> String {
    format!("tls/{domain}/key")
}

/// The raft lock key that elects the single issuer for `domain`. Only the holder
/// issues; the TTL frees it if the holder dies.
pub fn issuer_lock_key(domain: &str) -> String {
    format!("acme-issuer/{domain}")
}

/// What this node should do this tick, given its election + cert state.
///
/// Total function over the decision inputs — the loop maps each variant to an
/// action, and the table below is the spec. Keeping it pure means the
/// "when do we issue" contract is tested directly, not inferred from the I/O
/// loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerAction {
    /// This node did not win the issuer lock — do nothing but keep polling so it
    /// can take over if the current holder's TTL lapses.
    Standby,
    /// This node holds the lock and a (re)issuance is due — run the ACME order,
    /// seal, and `PutSecret` the new cert + key.
    Issue,
    /// This node holds the lock but the cert is present and fresh — nothing to
    /// issue; the tick's `AcquireLock` already renewed the claim.
    HoldOnly,
}

/// Decide the tick's action from the two facts the loop can observe:
///
/// | `lock_won` | `renewal_due` | action     |
/// |------------|---------------|------------|
/// | `false`    | (either)      | `Standby`  |
/// | `true`     | `true`        | `Issue`    |
/// | `true`     | `false`       | `HoldOnly` |
///
/// `renewal_due` folds together "no cert stored yet" and "the stored cert is
/// within its renew-before margin" — both mean a fresh order is due — so the
/// caller computes it once (missing record ⇒ due; else
/// [`acme_engine::is_renewal_due`] over the record's `updated_at`).
pub fn decide_issuer_action(lock_won: bool, renewal_due: bool) -> IssuerAction {
    match (lock_won, renewal_due) {
        (false, _) => IssuerAction::Standby,
        (true, true) => IssuerAction::Issue,
        (true, false) => IssuerAction::HoldOnly,
    }
}

// ── Runtime config ───────────────────────────────────────────────────────────

/// Everything the issuer loop needs. Built by [`parse_issuer_config`] from the
/// daemon environment; the loop is only spawned when a config is present, so an
/// unconfigured node (dev, single-node) runs no issuer at all.
#[derive(Debug, Clone)]
pub struct IssuerConfig {
    /// SAN base, e.g. `"yah.dev"`. Names the issuer lock and the cluster-secret
    /// keys; the issued cert covers `*.<domain>` + `<domain>`.
    pub domain: String,
    /// Provider-agnostic issuance inputs handed to [`acme_engine::issue`].
    pub issue: IssueConfig,
    /// Node-local cluster KEK path — seals cert+key before `PutSecret`.
    pub kek_path: PathBuf,
    /// Steady-state poll cadence (renewal checks) once a cert exists.
    pub check_interval: Duration,
    /// TTL on the issuer lock. Must exceed `check_interval` so the holder renews
    /// before it lapses; a dead issuer's claim frees after this.
    pub lock_ttl: Duration,
    /// Assumed issued-cert validity (renewal math; LE default 90d).
    pub cert_lifetime: Duration,
    /// Renew when within this margin of expiry (default 30d).
    pub renew_before: Duration,
}

/// Parse the issuer config from a `key -> value` lookup (a pure function over
/// the environment, so it is unit-testable without touching `std::env`).
///
/// Returns `Ok(None)` when `YUBABA_ACME_DOMAIN` is unset — the issuer is opt-in,
/// exactly one deployment (the HA fleet) turns it on. The challenge is always
/// DNS-01-via-Cloudflare: a wildcard `*.<domain>` cannot be proven with HTTP-01,
/// and the CF token is a fob secret injected only into the issuer as a file.
pub fn parse_issuer_config(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<IssuerConfig>, String> {
    let domain = match get("YUBABA_ACME_DOMAIN") {
        Some(d) if !d.trim().is_empty() => d.trim().to_string(),
        _ => return Ok(None),
    };
    let contact_email = get("YUBABA_ACME_CONTACT_EMAIL")
        .filter(|s| !s.trim().is_empty())
        .ok_or("YUBABA_ACME_CONTACT_EMAIL is required when YUBABA_ACME_DOMAIN is set")?;
    let token_file = get("YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE")
        .filter(|s| !s.trim().is_empty())
        .ok_or(
            "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE is required (fob-injected CF token file)",
        )?;
    let zone_id = get("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID")
        .filter(|s| !s.trim().is_empty())
        .ok_or("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID is required")?;

    let directory = AcmeDirectory::parse(
        &get("YUBABA_ACME_DIRECTORY").unwrap_or_else(|| "staging".to_string()),
    );
    let account_cache_path = get("YUBABA_ACME_ACCOUNT_CACHE")
        .unwrap_or_else(|| "/var/lib/yah/yubaba/acme-account.json".to_string());
    let kek_path =
        PathBuf::from(get("YUBABA_ACME_KEK_PATH").unwrap_or_else(|| CLUSTER_KEK_PATH.to_string()));

    let propagation_secs = parse_u64(&get, "YUBABA_ACME_DNS01_PROPAGATION_SECS", 10)?;
    let check_interval_secs = parse_u64(&get, "YUBABA_ACME_CHECK_INTERVAL_SECS", 43_200)?;
    let lock_ttl_secs = parse_u64(&get, "YUBABA_ACME_LOCK_TTL_SECS", 86_400)?;
    let renew_before_days = parse_u64(&get, "YUBABA_ACME_RENEW_BEFORE_DAYS", 30)?;
    let cert_lifetime_days = parse_u64(&get, "YUBABA_ACME_CERT_LIFETIME_DAYS", 90)?;

    // The holder renews the lock every `check_interval`; a TTL that doesn't
    // outlast one interval would lapse between renewals and let a second node
    // (or a transient co-leader whose ACME order runs long) steal it and
    // double-issue. Reject the misconfiguration at parse time rather than
    // discovering it as a duplicate-cert incident.
    if lock_ttl_secs <= check_interval_secs {
        return Err(format!(
            "YUBABA_ACME_LOCK_TTL_SECS ({lock_ttl_secs}) must be greater than \
             YUBABA_ACME_CHECK_INTERVAL_SECS ({check_interval_secs}) so the issuer \
             renews its lock before it expires"
        ));
    }

    // Wildcard fleet cert: one order for `*.<domain>` + the apex, issued once and
    // shared by every consumer node.
    let domains = vec![format!("*.{domain}"), domain.clone()];

    Ok(Some(IssuerConfig {
        domain,
        issue: IssueConfig {
            domains,
            contact_email,
            directory,
            account_cache_path,
            challenge: AcmeChallengeKind::Dns01Cloudflare {
                token_file,
                zone_id,
            },
            dns01_propagation_delay: Duration::from_secs(propagation_secs),
        },
        kek_path,
        check_interval: Duration::from_secs(check_interval_secs),
        lock_ttl: Duration::from_secs(lock_ttl_secs),
        cert_lifetime: Duration::from_secs(cert_lifetime_days * 86_400),
        renew_before: Duration::from_secs(renew_before_days * 86_400),
    }))
}

fn parse_u64(
    get: &impl Fn(&str) -> Option<String>,
    key: &str,
    default: u64,
) -> Result<u64, String> {
    match get(key) {
        // Don't echo the raw value: if an operator fat-fingers a secret into a
        // numeric override, it shouldn't land in a startup error line.
        Some(v) => v
            .parse::<u64>()
            .map_err(|_| format!("{key}: expected a non-negative integer")),
        None => Ok(default),
    }
}

// ── Runtime loop ─────────────────────────────────────────────────────────────

/// Spawn the issuer background task. Aborted on daemon shutdown; also exits on
/// its own if the node-local KEK can't be loaded (this node then can't seal, so
/// it can't be the issuer — consumers still resolve via the F2 path).
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    config: IssuerConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { run(node_id, raft, state_machine, config).await })
}

async fn run(node_id: YubabaNodeId, raft: YubabaRaft, sm: YubabaStateMachine, cfg: IssuerConfig) {
    let kek = match load_cluster_kek(&cfg.kek_path) {
        Ok(k) => k,
        Err(e) => {
            error!(
                kek_path = ?cfg.kek_path,
                "acme issuer: cannot load cluster KEK — issuer disabled on this node: {e}"
            );
            return;
        }
    };
    let owner = node_id.to_string();
    let lock_key = issuer_lock_key(&cfg.domain);
    let cert_key = cert_secret_name(&cfg.domain);
    let key_key = key_secret_name(&cfg.domain);
    info!(
        domain = %cfg.domain,
        directory = %cfg.issue.directory.url(),
        "acme issuer: watching (single issuer elected via raft lock {lock_key})"
    );

    loop {
        let cert_present = sm.cluster_secret(&cert_key);

        // Only the raft leader can `client_write`; a follower's AcquireLock would
        // just ForwardToLeader. Gate on leadership to avoid the spam, then let
        // the lock be the linearizable single-issuer guard: during a transient
        // double-leader, raft orders the two AcquireLocks and the second sees a
        // live owner and is denied, so two nodes never issue concurrently.
        let is_leader = { raft.metrics().borrow_watched().current_leader == Some(node_id) };
        // Stays true unless an issuance leaves the store MISMATCHED (new key
        // written, cert write failed); that must retry promptly, not sleep the
        // full renewal interval, or consumers see a new-key/old-cert TLS
        // failure until then.
        let mut store_consistent = true;
        if is_leader {
            let lock_won = match raft
                .client_write(YubabaRequest::AcquireLock {
                    key: lock_key.clone(),
                    owner: owner.clone(),
                    ttl_secs: cfg.lock_ttl.as_secs(),
                    acquired_at: unix_now(),
                })
                .await
            {
                Ok(resp) => matches!(resp.data, YubabaResponse::LockGranted(true)),
                Err(e) => {
                    warn!("acme issuer: AcquireLock write failed (retry next tick): {e}");
                    false
                }
            };

            let renewal_due = match &cert_present {
                None => true,
                Some(rec) => acme_engine::is_renewal_due(
                    UNIX_EPOCH + Duration::from_secs(rec.updated_at),
                    cfg.cert_lifetime,
                    cfg.renew_before,
                    SystemTime::now(),
                ),
            };

            if decide_issuer_action(lock_won, renewal_due) == IssuerAction::Issue {
                store_consistent = issue_and_store(&raft, &kek, &cfg, &cert_key, &key_key).await;
            }
        }

        // Poll fast until a cert exists (cold-start first issuance) OR the last
        // issuance left the store mismatched; otherwise relax to the renewal
        // cadence.
        let nap = if cert_present.is_some() && store_consistent {
            cfg.check_interval
        } else {
            Duration::from_secs(FIRST_ISSUE_POLL_SECS)
        };
        tokio::time::sleep(nap).await;
    }
}

/// Run one ACME order, seal the cert + key under the node KEK, and `PutSecret`
/// both into the cluster store. Every failure is logged and never panics.
///
/// Returns `true` when the store is left **consistent** — either both records
/// were written, or nothing was (issuance failed, or the *first* write failed)
/// so the prior state is intact. Returns `false` only when it is left
/// **mismatched** (the new key landed but the cert write failed), so the caller
/// retries promptly instead of sleeping the renewal interval.
async fn issue_and_store(
    raft: &YubabaRaft,
    kek: &[u8; 32],
    cfg: &IssuerConfig,
    cert_key: &str,
    key_key: &str,
) -> bool {
    info!(domain = %cfg.domain, "acme issuer: issuing/renewing the fleet cert");
    // DNS-01 needs no HTTP-01 token map, but the engine's signature takes one.
    let tokens: acme_engine::ChallengeTokens = Arc::new(RwLock::new(HashMap::new()));
    let issued = match acme_engine::issue(&cfg.issue, &tokens).await {
        Ok(i) => i,
        Err(e) => {
            error!("acme issuer: issuance failed (retry next tick): {e}");
            return true; // nothing written — prior state intact and consistent
        }
    };

    let stamp = unix_now();
    let cert_rec = seal_cluster_secret(kek, issued.cert_chain_pem.as_bytes(), stamp);
    // Copy the private-key PEM into a zeroizing buffer so the plaintext key is
    // scrubbed when it drops at the end of this fn, rather than lingering in a
    // freed `String`'s heap page (the engine hands us a plain `String`; this is
    // the issuer's own copy — the sensitive one on this node).
    let key_bytes = Zeroizing::new(issued.key_pem.into_bytes());
    let key_rec = seal_cluster_secret(kek, &key_bytes, stamp);

    // KEY first, CERT last — deliberately, because `renewal_due` gates off the
    // CERT record's `updated_at` (see `run`). Writing the gate record last means
    // a partial failure leaves the cert stale/absent, so `renewal_due` stays
    // true and the next tick re-issues and heals — the store never gets wedged
    // with a fresh cert paired to a stale key.
    if let Err(e) = put_secret(raft, key_key, key_rec).await {
        // Key write is first, so nothing was overwritten — store still consistent.
        error!("acme issuer: PutSecret(key) failed (prior state intact): {e}");
        return true;
    }
    if let Err(e) = put_secret(raft, cert_key, cert_rec).await {
        error!(
            "acme issuer: PutSecret(cert) failed AFTER the key write — store has a \
             new key against the old cert; retrying promptly to heal: {e}"
        );
        return false;
    }
    info!(
        domain = %cfg.domain,
        "acme issuer: sealed cert+key written to cluster store — replicating to all nodes"
    );
    true
}

async fn put_secret(raft: &YubabaRaft, name: &str, rec: SecretRecord) -> anyhow::Result<()> {
    raft.client_write(YubabaRequest::PutSecret {
        name: name.to_string(),
        ciphertext: rec.ciphertext,
        nonce: rec.nonce,
        updated_at: rec.updated_at,
    })
    .await?;
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_naming() {
        assert_eq!(cert_secret_name("yah.dev"), "tls/yah.dev/cert");
        assert_eq!(key_secret_name("yah.dev"), "tls/yah.dev/key");
        assert_eq!(issuer_lock_key("yah.dev"), "acme-issuer/yah.dev");
    }

    #[test]
    fn standby_when_lock_lost_regardless_of_renewal() {
        assert_eq!(decide_issuer_action(false, false), IssuerAction::Standby);
        assert_eq!(decide_issuer_action(false, true), IssuerAction::Standby);
    }

    #[test]
    fn issue_only_when_holder_and_due() {
        assert_eq!(decide_issuer_action(true, true), IssuerAction::Issue);
    }

    #[test]
    fn hold_when_holder_but_cert_fresh() {
        assert_eq!(decide_issuer_action(true, false), IssuerAction::HoldOnly);
    }

    // ── parse_issuer_config ─────────────────────────────────────────────────

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn issuer_disabled_without_domain() {
        assert!(parse_issuer_config(env(&[])).unwrap().is_none());
        // An empty domain is also "off", not an error.
        assert!(parse_issuer_config(env(&[("YUBABA_ACME_DOMAIN", "  ")]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn domain_without_required_fields_errors() {
        let err = parse_issuer_config(env(&[("YUBABA_ACME_DOMAIN", "yah.dev")])).unwrap_err();
        assert!(err.contains("CONTACT_EMAIL"), "got {err}");

        let err = parse_issuer_config(env(&[
            ("YUBABA_ACME_DOMAIN", "yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
        ]))
        .unwrap_err();
        assert!(err.contains("TOKEN_FILE"), "got {err}");
    }

    #[test]
    fn full_config_builds_wildcard_dns01() {
        let cfg = parse_issuer_config(env(&[
            ("YUBABA_ACME_DOMAIN", "yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
            (
                "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE",
                "/run/secrets/cf.token",
            ),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
        ]))
        .unwrap()
        .expect("config present");

        assert_eq!(cfg.domain, "yah.dev");
        // Wildcard + apex, in that order.
        assert_eq!(cfg.issue.domains, vec!["*.yah.dev", "yah.dev"]);
        assert!(matches!(
            cfg.issue.challenge,
            AcmeChallengeKind::Dns01Cloudflare { .. }
        ));
        // Defaults: staging directory, 90d/30d renewal window, default KEK path.
        assert_eq!(cfg.cert_lifetime, Duration::from_secs(90 * 86_400));
        assert_eq!(cfg.renew_before, Duration::from_secs(30 * 86_400));
        assert_eq!(cfg.kek_path, PathBuf::from(CLUSTER_KEK_PATH));
        assert_eq!(cfg.issue.directory, AcmeDirectory::Staging);
    }

    #[test]
    fn lock_ttl_must_exceed_check_interval() {
        // A TTL shorter than the renew cadence would lapse between renewals and
        // let a second node steal the lock and double-issue.
        let err = parse_issuer_config(env(&[
            ("YUBABA_ACME_DOMAIN", "yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
            (
                "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE",
                "/run/secrets/cf.token",
            ),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
            ("YUBABA_ACME_CHECK_INTERVAL_SECS", "600"),
            ("YUBABA_ACME_LOCK_TTL_SECS", "600"),
        ]))
        .unwrap_err();
        assert!(err.contains("LOCK_TTL_SECS"), "got {err}");
    }

    #[test]
    fn numeric_override_error_does_not_echo_value() {
        // A mis-pasted secret in a numeric override must not appear in the error.
        let err = parse_issuer_config(env(&[
            ("YUBABA_ACME_DOMAIN", "yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
            (
                "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE",
                "/run/secrets/cf.token",
            ),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
            ("YUBABA_ACME_CHECK_INTERVAL_SECS", "s3cr3t-leak"),
        ]))
        .unwrap_err();
        assert!(!err.contains("s3cr3t-leak"), "raw value leaked: {err}");
    }

    #[test]
    fn bad_numeric_override_is_an_error() {
        let err = parse_issuer_config(env(&[
            ("YUBABA_ACME_DOMAIN", "yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
            (
                "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE",
                "/run/secrets/cf.token",
            ),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
            ("YUBABA_ACME_CHECK_INTERVAL_SECS", "soon"),
        ]))
        .unwrap_err();
        assert!(err.contains("CHECK_INTERVAL"), "got {err}");
    }
}
