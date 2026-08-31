//! Per-domain ACME issuer for **custom tenant domains** (R779, W267 §Decision 2).
//!
//! [`crate::acme_issuer`] issues *one* cert — the fleet wildcard `*.<domain>` —
//! elected by a raft lock and written into raft. That is exactly right for one
//! KB-scale record and exactly wrong for ten thousand: R779's DECISION 1 moved
//! per-domain material to the object store ([`crate::cert_store`]) precisely
//! because raft rewrites its whole state on every `PutSecret`. This module is
//! the writer for that store.
//!
//! ## What it sweeps, and why that is the enrollment set
//!
//! The work list is [`ObjectCertStore::enrolled`], **not**
//! [`ObjectCertStore::domains`]. `domains()` is what has already been issued; a
//! loop gated on it would never issue a domain's *first* cert. `enrolled()` is
//! the fact a tenant registered the name, which is knowable before any cert
//! exists — and it is the same set [`crate::demux_routes`] publishes to the
//! demux, so a domain becomes routable and issuable from one write.
//!
//! ## Why DNS-01 by delegation, and not HTTP-01
//!
//! Decided 2026-08-29. HTTP-01 needs
//! `http://<domain>/.well-known/acme-challenge/<token>` to reach the process
//! holding the token, and 10k cold per-tenant passways cannot each bind `:80` —
//! it would need a new public `:80` tier that routes by `Host`, and it would pin
//! every *renewal* to whichever node currently holds the public IP. DNS-01 needs
//! neither: the tenant CNAMEs `_acme-challenge.<domain>` into a zone we do hold,
//! the CA follows the CNAME, and validation never touches this node — so a
//! renewal works from anywhere, including a node that is not fronting anything.
//! The record name is [`acme_engine::dns01_record_name`]; that function is the
//! whole of the contract an onboarding page has to state.
//!
//! ## Single-writer, and the two rate limits
//!
//! - **Per domain**, [`ObjectCertStore::claim_issuance`] is the lock —
//!   certmagic's `Locker` as one CAS object. No raft round-trip per domain,
//!   which is what DECISION 1 was avoiding.
//! - **Per account**, DECISION 3's arithmetic: Let's Encrypt allows 300 new
//!   orders / 3 h, i.e. one every 36 s. [`DomainIssuerConfig::min_order_interval`]
//!   paces orders to that whether they succeed or fail, so a first-fill of a
//!   large enrollment set drains at a rate the CA will accept instead of
//!   tripping the limit on the first sweep and stalling every domain.
//! - **Per failure**, [`ObjectCertStore::cool_down_issuance`] parks a failed
//!   domain behind a long claim. LE counts *authorization failures* per
//!   identifier (5/hour), and the overwhelmingly common failure here is "the
//!   tenant has not added the CNAME yet" — a human-timescale problem. So the
//!   cooldown is flat rather than exponential: one attempt per hour per domain
//!   is comfortably inside the budget, and an exponential curve would only make
//!   the first success *after* the tenant fixes their DNS arrive later.
//!
//! ## Failure posture
//!
//! Every failure in a sweep is logged and skipped; the loop never exits. A
//! listing failure ends that sweep (there is nothing to work from), it does not
//! end the loop. Nothing here can de-route or delete a domain — the only writes
//! are the sealed pair and the claim object.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use acme_engine::{AcmeChallengeKind, AcmeDirectory, IssueConfig};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use crate::acme_issuer::{cert_secret_name, key_secret_name};
use crate::cert_store::{CertStoreError, ObjectCertStore};
use crate::raft::SecretRecord;
use crate::secrets::{load_cluster_kek, seal_cluster_secret, CLUSTER_KEK_PATH};
use workload_spec::secrets::SecretAccess;

/// Env key naming the zone tenants delegate their challenge into. Its presence
/// turns the per-domain issuer on.
pub const DELEGATE_ZONE_ENV: &str = "YUBABA_DOMAIN_ISSUER_DELEGATE_ZONE";
/// Env key overriding the sweep cadence.
pub const SWEEP_SECS_ENV: &str = "YUBABA_DOMAIN_ISSUER_SWEEP_SECS";
/// Env key overriding the minimum spacing between two ACME orders.
pub const MIN_ORDER_SECS_ENV: &str = "YUBABA_DOMAIN_ISSUER_MIN_ORDER_SECS";
/// Env key overriding how long a failed domain is parked.
pub const FAILURE_COOLDOWN_SECS_ENV: &str = "YUBABA_DOMAIN_ISSUER_FAILURE_COOLDOWN_SECS";
/// Env key overriding who may mount the issued per-domain records; falls back to
/// `YUBABA_ACME_CONSUMERS`.
pub const CONSUMERS_ENV: &str = "YUBABA_DOMAIN_ISSUER_CONSUMERS";

/// Default seconds between sweeps of the enrollment set.
///
/// Same reasoning as [`crate::demux_routes::DEFAULT_SWEEP_SECS`] and the same
/// number on purpose: a sweep is one `list_prefix` plus a `get` per domain, and
/// the thing it is watching for (a newly enrolled domain, a cert crossing its
/// renewal margin) does not move on a second-by-second scale.
pub const DEFAULT_SWEEP_SECS: u64 = 300;

/// Default seconds between two ACME orders — 300 new orders / 3 h is one per
/// 36 s. See the module doc's DECISION 3 note.
pub const DEFAULT_MIN_ORDER_SECS: u64 = 36;

/// Default seconds a failed domain is parked before anyone retries it.
pub const DEFAULT_FAILURE_COOLDOWN_SECS: u64 = 3600;

// ── Config ───────────────────────────────────────────────────────────────────

/// Everything the per-domain loop needs. The [`IssueConfig`] carried here is a
/// *template*: [`IssueConfig::domains`] is replaced per domain, everything else
/// (account, directory, challenge) is shared across every order this node makes.
#[derive(Debug, Clone)]
pub struct DomainIssuerConfig {
    /// Shared issuance inputs; `domains` is overwritten per order.
    pub issue: IssueConfig,
    /// Node-local cluster KEK path — seals cert+key before they are stored.
    pub kek_path: PathBuf,
    /// R706 (W294): who may mount an issued per-domain cert+key.
    pub access: SecretAccess,
    /// Seconds between sweeps of the enrollment set.
    pub sweep: Duration,
    /// Minimum spacing between two ACME orders from this node.
    pub min_order_interval: Duration,
    /// How long a failed domain is parked behind its claim.
    pub failure_cooldown: Duration,
    /// Assumed issued-cert validity (renewal math; LE default 90 d).
    pub cert_lifetime: Duration,
    /// Renew when within this margin of expiry.
    pub renew_before: Duration,
}

/// Parse the per-domain issuer config from a `key -> value` lookup — pure over
/// the environment, so it is unit-testable without `std::env`.
///
/// `Ok(None)` when [`DELEGATE_ZONE_ENV`] is unset: this loop is opt-in, and a
/// node that is not the free tier's issuer must not sweep the bucket. The rest
/// of the ACME inputs are deliberately the *same* `YUBABA_ACME_*` keys the fleet
/// issuer reads — one contact, one account cache, one Cloudflare token, one
/// directory. Two sets would be two ACME accounts, and DECISION 3's order budget
/// is per account, so splitting them would silently halve the accounting an
/// operator does.
pub fn parse_domain_issuer_config(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<DomainIssuerConfig>, String> {
    let delegate_zone = match get(DELEGATE_ZONE_ENV) {
        Some(z) if !z.trim().is_empty() => z.trim().to_string(),
        _ => return Ok(None),
    };
    let contact_email = get("YUBABA_ACME_CONTACT_EMAIL")
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            format!("YUBABA_ACME_CONTACT_EMAIL is required when {DELEGATE_ZONE_ENV} is set")
        })?;
    let token_file = get("YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE")
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE is required when {DELEGATE_ZONE_ENV} \
                 is set (the CF token for the delegation zone)"
            )
        })?;
    let zone_id = get("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID")
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID is required when {DELEGATE_ZONE_ENV} is \
                 set: the zone id of {delegate_zone}, which is where every tenant's challenge \
                 TXT is written"
            )
        })?;
    // Same rule as the fleet issuer (R706 / W294): no default either way. A
    // permissive default makes 10k tenant private keys bearer secrets; a
    // deny-all default issues 10k certs nobody can mount.
    let access = crate::acme_issuer::parse_consumers(
        &get(CONSUMERS_ENV)
            .or_else(|| get("YUBABA_ACME_CONSUMERS"))
            .unwrap_or_default(),
    )
    .ok_or_else(|| {
        format!(
            "{CONSUMERS_ENV} (or YUBABA_ACME_CONSUMERS) is required when {DELEGATE_ZONE_ENV} \
             is set: a comma-separated list of workload names allowed to mount an issued \
             per-domain cert+key, or the literal \"any\""
        )
    })?;

    let directory = AcmeDirectory::parse(
        &get("YUBABA_ACME_DIRECTORY").unwrap_or_else(|| "staging".to_string()),
    );
    let account_cache_path = get("YUBABA_ACME_ACCOUNT_CACHE")
        .unwrap_or_else(|| "/var/lib/yah/yubaba/acme-account.json".to_string());
    let kek_path =
        PathBuf::from(get("YUBABA_ACME_KEK_PATH").unwrap_or_else(|| CLUSTER_KEK_PATH.to_string()));

    let propagation_secs = parse_u64(&get, "YUBABA_ACME_DNS01_PROPAGATION_SECS", 10)?;
    let sweep_secs = parse_u64(&get, SWEEP_SECS_ENV, DEFAULT_SWEEP_SECS)?;
    let min_order_secs = parse_u64(&get, MIN_ORDER_SECS_ENV, DEFAULT_MIN_ORDER_SECS)?;
    let failure_cooldown_secs =
        parse_u64(&get, FAILURE_COOLDOWN_SECS_ENV, DEFAULT_FAILURE_COOLDOWN_SECS)?;
    let renew_before_days = parse_u64(&get, "YUBABA_ACME_RENEW_BEFORE_DAYS", 30)?;
    let cert_lifetime_days = parse_u64(&get, "YUBABA_ACME_CERT_LIFETIME_DAYS", 90)?;

    if sweep_secs == 0 {
        return Err(format!("{SWEEP_SECS_ENV} must be greater than zero"));
    }
    // A zero here is not "fast", it is "no rate limit" — and the limit it would
    // remove is the one thing standing between a first fill and a 3-hour
    // account-wide `429` that stalls every domain, not just the excess ones.
    if min_order_secs == 0 {
        return Err(format!(
            "{MIN_ORDER_SECS_ENV} must be greater than zero — it is the per-account new-order \
             pacing (Let's Encrypt: 300 orders / 3 h = one per 36 s)"
        ));
    }

    Ok(Some(DomainIssuerConfig {
        issue: IssueConfig {
            // Replaced per domain; a template value here would be a silent
            // mis-issue if a code path ever forgot to set it, so it starts empty
            // and `issue_domain` is the only thing that fills it.
            domains: Vec::new(),
            contact_email,
            directory,
            account_cache_path,
            challenge: AcmeChallengeKind::Dns01Cloudflare {
                token_file,
                zone_id,
                delegate_zone: Some(delegate_zone),
            },
            dns01_propagation_delay: Duration::from_secs(propagation_secs),
        },
        kek_path,
        access,
        sweep: Duration::from_secs(sweep_secs),
        min_order_interval: Duration::from_secs(min_order_secs),
        failure_cooldown: Duration::from_secs(failure_cooldown_secs),
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
        // Don't echo the raw value — see the fleet issuer's copy of this.
        Some(v) => v
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{key}: expected a non-negative integer")),
        None => Ok(default),
    }
}

// ── The per-domain decision ──────────────────────────────────────────────────

/// Whether `domain` needs an order this sweep, given what the store holds.
///
/// Pure, so the whole decision is testable without a bucket or a CA:
///
/// - **no cert record** → order (the first cert for a newly enrolled domain);
/// - **a cert inside its renewal margin** → order;
/// - **a fresh cert** → skip.
///
/// A *read failure* is deliberately not modelled here — the caller must not turn
/// "the bucket is unreachable" into "no cert yet, order one", which is why
/// [`ObjectCertStore::read_secret`] returns a `Result<Option<_>>` and this takes
/// only the `Option`.
pub fn needs_issuance(
    cert: Option<&SecretRecord>,
    cert_lifetime: Duration,
    renew_before: Duration,
    now: SystemTime,
) -> bool {
    match cert {
        None => true,
        Some(rec) => acme_engine::is_renewal_due(
            UNIX_EPOCH + Duration::from_secs(rec.updated_at),
            cert_lifetime,
            renew_before,
            now,
        ),
    }
}

// ── Runtime loop ─────────────────────────────────────────────────────────────

/// Spawn the per-domain issuer. Aborted on daemon shutdown; also exits on its
/// own if the node-local KEK cannot be loaded, since without it this node cannot
/// seal and therefore cannot be an issuer at all.
pub fn spawn(
    store: Arc<ObjectCertStore>,
    node_id: String,
    cfg: DomainIssuerConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { run(store, node_id, cfg).await })
}

async fn run(store: Arc<ObjectCertStore>, node_id: String, cfg: DomainIssuerConfig) {
    let kek = match load_cluster_kek(&cfg.kek_path) {
        Ok(k) => k,
        Err(e) => {
            error!(
                kek_path = ?cfg.kek_path,
                "domain issuer: cannot load cluster KEK — per-domain issuance disabled on \
                 this node: {e}"
            );
            return;
        }
    };
    info!(
        issuer = %store.issuer(),
        sweep_secs = cfg.sweep.as_secs(),
        "domain issuer: watching the enrollment set for custom domains needing a cert"
    );

    // Paces orders across sweeps, not just within one — otherwise a sweep
    // boundary would be a free order.
    let mut last_order: Option<Instant> = None;

    loop {
        match sweep(&store, &node_id, &cfg, &kek, &mut last_order).await {
            Ok(SweepOutcome { considered, issued }) if issued > 0 => info!(
                considered,
                issued, "domain issuer: sweep complete"
            ),
            Ok(_) => {}
            Err(e) => warn!(
                "domain issuer: sweep aborted (the enrollment set could not be listed; \
                 retrying next tick): {e}"
            ),
        }
        tokio::time::sleep(cfg.sweep).await;
    }
}

/// What one sweep did. Returned rather than logged inline so a test can drive
/// [`sweep`] and assert on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Enrolled domains examined.
    pub considered: usize,
    /// Orders that completed and were stored.
    pub issued: usize,
}

/// One pass over the enrollment set.
///
/// Fails only when the set itself could not be listed — a per-domain failure is
/// logged, parked, and stepped over, because one tenant's broken CNAME must not
/// stop the other 9,999 from being issued.
async fn sweep(
    store: &Arc<ObjectCertStore>,
    node_id: &str,
    cfg: &DomainIssuerConfig,
    kek: &[u8; 32],
    last_order: &mut Option<Instant>,
) -> Result<SweepOutcome, CertStoreError> {
    let store_for_list = Arc::clone(store);
    let enrolled = blocking(move || store_for_list.enrolled()).await?;

    let mut outcome = SweepOutcome {
        considered: enrolled.len(),
        issued: 0,
    };
    for (domain, _enrollment) in enrolled {
        match consider_domain(store, node_id, cfg, kek, &domain, last_order).await {
            Ok(true) => outcome.issued += 1,
            Ok(false) => {}
            Err(e) => warn!(domain = %domain, "domain issuer: skipped: {e}"),
        }
    }
    Ok(outcome)
}

/// One domain: decide, claim, pace, order, store. `Ok(true)` when a cert landed.
async fn consider_domain(
    store: &Arc<ObjectCertStore>,
    node_id: &str,
    cfg: &DomainIssuerConfig,
    kek: &[u8; 32],
    domain: &str,
    last_order: &mut Option<Instant>,
) -> Result<bool, CertStoreError> {
    let cert_name = cert_secret_name(domain);
    let key_name = key_secret_name(domain);

    // Read BEFORE claiming: a claim is a write, and the overwhelming majority of
    // domains on any given sweep need nothing at all.
    let existing = {
        let (store, cert_name) = (Arc::clone(store), cert_name.clone());
        blocking(move || store.read_secret(&cert_name)).await?
    };
    if !needs_issuance(
        existing.as_ref(),
        cfg.cert_lifetime,
        cfg.renew_before,
        SystemTime::now(),
    ) {
        return Ok(false);
    }

    // Claim. A live claim held by anyone — another node mid-order, or this
    // domain's own failure cooldown — means skip, not wait.
    {
        let (store, domain_owned, holder) =
            (Arc::clone(store), domain.to_string(), node_id.to_string());
        match blocking(move || {
            store.claim_issuance(&domain_owned, &holder, SystemTime::now())
        })
        .await
        {
            Ok(_) => {}
            Err(CertStoreError::Claimed {
                holder,
                remaining_secs,
                ..
            }) => {
                info!(
                    domain = %domain,
                    holder = %holder,
                    remaining_secs,
                    "domain issuer: not ours this tick"
                );
                return Ok(false);
            }
            Err(e) => return Err(e),
        }
    }

    // Pace to the per-account order budget. Done AFTER the claim so the wait is
    // spent holding the domain rather than racing another node for it, and
    // inside the claim TTL by construction (the interval is seconds, the TTL
    // minutes).
    if let Some(last) = *last_order {
        let elapsed = last.elapsed();
        if elapsed < cfg.min_order_interval {
            tokio::time::sleep(cfg.min_order_interval - elapsed).await;
        }
    }
    *last_order = Some(Instant::now());

    match issue_domain(cfg, domain).await {
        Ok(issued) => {
            store_issued(store, cfg, kek, domain, &cert_name, &key_name, issued).await?;
            let (store, domain_owned) = (Arc::clone(store), domain.to_string());
            if let Err(e) = blocking(move || store.release_issuance(&domain_owned)).await {
                // Harmless: the claim expires on its own. Worth a line because a
                // pattern of these means the bucket is refusing deletes.
                warn!(domain = %domain, "domain issuer: could not release the claim: {e}");
            }
            info!(domain = %domain, "domain issuer: issued and stored");
            Ok(true)
        }
        Err(e) => {
            error!(domain = %domain, "domain issuer: issuance failed: {e}");
            let (store, domain_owned, holder, ttl) = (
                Arc::clone(store),
                domain.to_string(),
                node_id.to_string(),
                cfg.failure_cooldown,
            );
            if let Err(e) = blocking(move || {
                store.cool_down_issuance(&domain_owned, &holder, SystemTime::now(), ttl)
            })
            .await
            {
                // The claim's ordinary TTL still applies, so this degrades to a
                // shorter backoff rather than to none.
                warn!(domain = %domain, "domain issuer: could not park the failure: {e}");
            }
            Ok(false)
        }
    }
}

/// One ACME order for exactly one identifier.
///
/// No wildcard, no SAN list: a tenant domain gets a cert for itself. A SAN list
/// would put several tenants on one cert, which makes one tenant's unenrollment
/// a re-issue for all of them and puts every name in the set into the others'
/// CT-log footprint.
async fn issue_domain(
    cfg: &DomainIssuerConfig,
    domain: &str,
) -> Result<acme_engine::Issued, acme_engine::AcmeError> {
    let mut issue = cfg.issue.clone();
    issue.domains = vec![domain.to_string()];
    // DNS-01 needs no HTTP-01 token map, but the engine's signature takes one.
    let tokens: acme_engine::ChallengeTokens = Arc::new(RwLock::new(HashMap::new()));
    acme_engine::issue(&issue, &tokens).await
}

/// Seal the freshly issued pair under the node KEK and write it to the store.
async fn store_issued(
    store: &Arc<ObjectCertStore>,
    cfg: &DomainIssuerConfig,
    kek: &[u8; 32],
    domain: &str,
    cert_name: &str,
    key_name: &str,
    issued: acme_engine::Issued,
) -> Result<(), CertStoreError> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cert_rec = seal_cluster_secret(
        kek,
        issued.cert_chain_pem.as_bytes(),
        stamp,
        cfg.access.clone(),
    );
    // Zeroizing for the same reason the fleet issuer does it: this is the
    // node's own plaintext copy of a tenant's private key, and it should not
    // linger in a freed heap page after this frame.
    let key_bytes = Zeroizing::new(issued.key_pem.into_bytes());
    let key_rec = seal_cluster_secret(kek, &key_bytes, stamp, cfg.access.clone());

    // `write_pair` is key-first/cert-last, which is what makes a partial write
    // heal: `needs_issuance` gates off the CERT record, so a half-written pair
    // reads as "still due" and the next sweep re-issues.
    let (store, cert_name, key_name, domain) = (
        Arc::clone(store),
        cert_name.to_string(),
        key_name.to_string(),
        domain.to_string(),
    );
    blocking(move || {
        store
            .write_pair(&cert_name, &key_name, &cert_rec, &key_rec)
            .inspect_err(|_| {
                // Named here rather than at the call site because only this
                // frame knows both the domain and which write failed.
                warn!(domain = %domain, "domain issuer: storing the sealed pair failed");
            })
    })
    .await
}

/// Run a synchronous [`ObjectCertStore`] call off the runtime's worker threads.
///
/// The object-store trait is sync (every R2 consumer in this tree shares one
/// client shape), and each of these is an HTTPS round-trip — blocking a worker
/// on one would stall every other task on that thread.
async fn blocking<T, F>(f: F) -> Result<T, CertStoreError>
where
    F: FnOnce() -> Result<T, CertStoreError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => Err(CertStoreError::Backend(yah_object_store::Error::Backend(
            format!("blocking cert-store call failed: {e}"),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: Map<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    fn base_pairs() -> Vec<(&'static str, &'static str)> {
        vec![
            (DELEGATE_ZONE_ENV, "acme.yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE", "/etc/cf-token"),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
            ("YUBABA_ACME_CONSUMERS", "ingress"),
        ]
    }

    #[test]
    fn the_loop_is_off_without_a_delegate_zone() {
        let mut pairs = base_pairs();
        pairs.retain(|(k, _)| *k != DELEGATE_ZONE_ENV);
        assert!(parse_domain_issuer_config(env(&pairs)).unwrap().is_none());
    }

    #[test]
    fn a_delegate_zone_builds_a_delegated_dns01_challenge() {
        let cfg = parse_domain_issuer_config(env(&base_pairs()))
            .unwrap()
            .expect("configured");
        assert_eq!(
            cfg.issue.challenge,
            AcmeChallengeKind::Dns01Cloudflare {
                token_file: "/etc/cf-token".to_string(),
                zone_id: "zone123".to_string(),
                delegate_zone: Some("acme.yah.dev".to_string()),
            }
        );
        assert!(
            cfg.issue.domains.is_empty(),
            "the template must carry no identifier — issue_domain fills it per order"
        );
        assert_eq!(cfg.sweep, Duration::from_secs(DEFAULT_SWEEP_SECS));
        assert_eq!(
            cfg.min_order_interval,
            Duration::from_secs(DEFAULT_MIN_ORDER_SECS)
        );
        assert_eq!(
            cfg.failure_cooldown,
            Duration::from_secs(DEFAULT_FAILURE_COOLDOWN_SECS)
        );
    }

    #[test]
    fn consumers_is_required_and_falls_back_to_the_fleet_issuers_rule() {
        // The dedicated key wins when both are present.
        let mut pairs = base_pairs();
        pairs.push((CONSUMERS_ENV, "any"));
        let cfg = parse_domain_issuer_config(env(&pairs)).unwrap().unwrap();
        assert_eq!(cfg.access, SecretAccess::AllowAny);

        // Neither present is a config error, never a permissive default.
        let mut pairs = base_pairs();
        pairs.retain(|(k, _)| *k != "YUBABA_ACME_CONSUMERS");
        let err = parse_domain_issuer_config(env(&pairs)).unwrap_err();
        assert!(err.contains(CONSUMERS_ENV), "got: {err}");
    }

    #[test]
    fn a_missing_cloudflare_zone_names_the_delegation_zone_in_the_error() {
        let mut pairs = base_pairs();
        pairs.retain(|(k, _)| *k != "YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID");
        let err = parse_domain_issuer_config(env(&pairs)).unwrap_err();
        assert!(
            err.contains("acme.yah.dev"),
            "the error should say which zone needs the id: {err}"
        );
    }

    #[test]
    fn a_zero_order_interval_is_rejected_rather_than_read_as_unlimited() {
        let mut pairs = base_pairs();
        pairs.push((MIN_ORDER_SECS_ENV, "0"));
        let err = parse_domain_issuer_config(env(&pairs)).unwrap_err();
        assert!(err.contains(MIN_ORDER_SECS_ENV), "got: {err}");
    }

    #[test]
    fn a_zero_sweep_is_rejected() {
        let mut pairs = base_pairs();
        pairs.push((SWEEP_SECS_ENV, "0"));
        assert!(parse_domain_issuer_config(env(&pairs)).is_err());
    }

    #[test]
    fn a_bad_numeric_override_does_not_echo_the_value() {
        let mut pairs = base_pairs();
        pairs.push((SWEEP_SECS_ENV, "hunter2"));
        let err = parse_domain_issuer_config(env(&pairs)).unwrap_err();
        assert!(!err.contains("hunter2"), "leaked the value: {err}");
    }

    // ── needs_issuance ───────────────────────────────────────────────────────

    fn record_aged(days: u64) -> SecretRecord {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        SecretRecord {
            ciphertext: Vec::new(),
            nonce: vec![0u8; 12],
            updated_at: now.saturating_sub(days * 86_400),
            access: SecretAccess::AllowAny,
            digest: None,
        }
    }

    const LIFETIME: Duration = Duration::from_secs(90 * 86_400);
    const MARGIN: Duration = Duration::from_secs(30 * 86_400);

    #[test]
    fn a_newly_enrolled_domain_with_no_cert_is_due() {
        assert!(needs_issuance(None, LIFETIME, MARGIN, SystemTime::now()));
    }

    #[test]
    fn a_fresh_cert_is_not_due() {
        let rec = record_aged(1);
        assert!(!needs_issuance(
            Some(&rec),
            LIFETIME,
            MARGIN,
            SystemTime::now()
        ));
    }

    #[test]
    fn a_cert_inside_the_renewal_margin_is_due() {
        // 70 days old on a 90-day cert with a 30-day margin: 20 days left.
        let rec = record_aged(70);
        assert!(needs_issuance(
            Some(&rec),
            LIFETIME,
            MARGIN,
            SystemTime::now()
        ));
    }
}
