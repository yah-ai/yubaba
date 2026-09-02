//! Registering a custom tenant domain, and telling its owner what to do (R779 / W267).
//!
//! Everything R779 built for custom domains — the enrollment set, the route
//! publisher, the per-domain issuer — is driven by one object per domain under
//! [`crate::cert_store::ENROLLED_PREFIX`], and until this module nothing wrote
//! one outside a test. This is the operator's end of that: enrol a domain,
//! unenrol it, read what state it is in, and — the part that is not bookkeeping
//! — **print the DNS the domain's owner has to create**.
//!
//! ## Why the CNAME line lives in code and not in a runbook
//!
//! DECISION 2 settled custom-domain validation on DNS-01 by `_acme-challenge`
//! CNAME delegation. That makes [`acme_engine::dns01_record_name`] a *contract
//! with a third party*: whatever it returns is exactly the name a tenant must
//! point `_acme-challenge.<their domain>` at, and if the issuer's idea of that
//! name and the onboarding page's idea of it ever differ by one label, every
//! affected order fails validation and the failure surfaces as "the CA says
//! there is no TXT record" — with both sides looking correct in isolation.
//!
//! So this module derives the instruction from the same function the issuer
//! publishes under, rather than restating it. A UI or a docs page should render
//! [`Onboarding`] (or the `--json` form of the CLI command) instead of
//! hard-coding the shape of the name.
//!
//! ## Reads the bucket, not the daemon
//!
//! These commands talk to the object store directly. The enrollment set is not
//! raft state and needs no quorum, no leader, and no running yubaba — which is
//! the whole point of DECISION 1 — so an admin verb that went through the daemon
//! would add a dependency the data does not have. The cost is that the caller
//! needs the store's credentials; the same `YUBABA_CERT_STORE_*` /
//! `cloudflare-r2-*` vault slots the daemon reads.

use std::net::SocketAddr;
use std::time::SystemTime;

use acme_engine::{dns01_record_name, AcmeDirectory};
use serde_json::json;

use crate::acme_issuer::{cert_secret_name, key_secret_name};
use crate::cert_store::{
    CertStoreConfig, CertStoreError, Enrollment, IssuanceClaim, ObjectCertStore, BUCKET_ENV,
};
use crate::domain_issuer::DELEGATE_ZONE_ENV;

/// Env key naming the ACME directory, shared with the issuers.
///
/// Read here for one reason only: the directory URL is what
/// [`crate::cert_store::issuer_key`] turns into the store's issuer path segment,
/// so an admin command reading a *different* default from the daemon would list
/// an empty prefix and report a fleet of enrolled domains as having no
/// certificates.
pub const DIRECTORY_ENV: &str = "YUBABA_ACME_DIRECTORY";

/// The default when [`DIRECTORY_ENV`] is unset — **staging**, matching
/// [`crate::acme_issuer::parse_issuer_config`]. Kept equal deliberately; see
/// [`DIRECTORY_ENV`].
pub const DEFAULT_DIRECTORY: &str = "staging";

/// What an admin command needs from the environment.
///
/// Deliberately much less than [`crate::acme_issuer::IssuerConfig`]: enrolling a
/// domain neither issues nor seals anything, so requiring a contact email, a
/// Cloudflare token file and a KEK path to run `domain list` would make the
/// read verbs unavailable exactly on the machines an operator runs them from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminConfig {
    /// Where the enrollment set and the sealed certs live.
    pub store: CertStoreConfig,
    /// Directory URL, which names the store's issuer segment.
    pub directory_url: String,
    /// [`DELEGATE_ZONE_ENV`], when this deployment delegates challenges. `None`
    /// means the identifier's own zone is expected to be one we hold.
    pub delegate_zone: Option<String>,
}

/// Parse [`AdminConfig`] from a `key -> value` lookup.
///
/// A hard error rather than `Ok(None)` when the bucket is unset: unlike the
/// daemon's opt-in spawn paths, a person typing `domain enrol` has asked for
/// this explicitly, and the useful answer to "no store configured" is which
/// variable to set — not silence and exit 0.
pub fn parse_admin_config(get: impl Fn(&str) -> Option<String>) -> Result<AdminConfig, String> {
    let store = CertStoreConfig::parse(&get)?.ok_or(format!(
        "{BUCKET_ENV} is unset — the domain commands read the enrollment set \
         straight from the object store, so it must name the bucket the daemon uses"
    ))?;
    let directory_url = AcmeDirectory::parse(
        &get(DIRECTORY_ENV).unwrap_or_else(|| DEFAULT_DIRECTORY.to_string()),
    )
    .url();
    let delegate_zone = get(DELEGATE_ZONE_ENV)
        .map(|s| s.trim().trim_matches('.').to_string())
        .filter(|s| !s.is_empty());
    Ok(AdminConfig {
        store,
        directory_url,
        delegate_zone,
    })
}

impl AdminConfig {
    /// Open the store this config names.
    pub fn connect(&self) -> Result<ObjectCertStore, CertStoreError> {
        self.store.connect(&self.directory_url)
    }
}

// ── The onboarding contract ──────────────────────────────────────────────────

/// How one domain's DNS-01 challenge is answered — the fact everything a tenant
/// has to do follows from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Validation {
    /// No delegation configured: the TXT is published at `record` directly,
    /// which only works when this deployment holds the identifier's own zone
    /// (the fleet wildcard's case). The tenant creates no challenge record —
    /// and, if we do *not* hold their zone, issuance simply cannot succeed, so
    /// this variant on a custom domain is a misconfiguration to surface, not a
    /// state to render cheerfully.
    ZoneHeld {
        /// `_acme-challenge.<domain>` — where the CA looks.
        record: String,
    },
    /// Delegated: the tenant points `record` at `target` with a CNAME, and the
    /// CA follows it into a zone we do hold.
    Delegated {
        /// `_acme-challenge.<domain>` — the name the tenant creates.
        record: String,
        /// What it points at, inside the delegate zone.
        target: String,
    },
}

impl Validation {
    /// The name the CA resolves for `domain`, either way.
    pub fn record(&self) -> &str {
        match self {
            Validation::ZoneHeld { record } | Validation::Delegated { record, .. } => record,
        }
    }
}

/// Resolve how `domain` will be validated under `delegate_zone`.
///
/// Both names come from [`dns01_record_name`] rather than being formatted here,
/// so this cannot drift from what the issuer actually publishes.
pub fn validation(domain: &str, delegate_zone: Option<&str>) -> Validation {
    let record = dns01_record_name(domain, None);
    match delegate_zone {
        Some(zone) => Validation::Delegated {
            record,
            target: dns01_record_name(domain, Some(zone)),
        },
        None => Validation::ZoneHeld { record },
    }
}

/// Everything the owner of a domain must do, in the order they must do it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Onboarding {
    /// The domain being onboarded.
    pub domain: String,
    /// Where its traffic must be pointed. Empty when the caller did not supply
    /// one — see [`Onboarding::new`].
    pub ingress: Vec<String>,
    /// How its certificate will be validated.
    pub validation: Validation,
}

impl Onboarding {
    /// `ingress` is the public address record's target(s) — the host running
    /// `passway-demux` on `:443`.
    ///
    /// Passed in rather than derived, and left renderable when empty, because
    /// nothing in the cert store knows it: the enrollment record names the
    /// *internal* backend the demux splices to, which is precisely not the
    /// address a tenant points DNS at. Inventing one from the enrollment would
    /// hand a tenant a loopback address as their A record.
    pub fn new(domain: &str, validation: Validation, ingress: Vec<String>) -> Self {
        Self {
            domain: domain.to_string(),
            ingress,
            validation,
        }
    }

    /// The instruction, as a tenant-facing page or email would carry it.
    pub fn render(&self) -> String {
        let mut out = format!(
            "{} — DNS records the domain's owner must create\n\n",
            self.domain
        );
        out.push_str("  1. Address record, so requests reach this deployment:\n");
        if self.ingress.is_empty() {
            out.push_str(&format!(
                "       {}  A/AAAA/CNAME  ->  <this deployment's public ingress address>\n",
                self.domain
            ));
            out.push_str(
                "\n     Not known to this command: the enrollment record names the internal\n",
            );
            out.push_str(
                "     backend the demux splices to, not the public address. It is the host\n",
            );
            out.push_str(
                "     running passway-demux on :443. Pass --ingress to have it printed here.\n",
            );
        } else {
            for target in &self.ingress {
                out.push_str(&format!(
                    "       {}  A/AAAA/CNAME  ->  {target}\n",
                    self.domain
                ));
            }
        }
        out.push('\n');
        match &self.validation {
            Validation::Delegated { record, target } => {
                out.push_str(
                    "  2. Challenge delegation, so the certificate can be issued and renewed\n",
                );
                out.push_str("     without handing over the zone:\n");
                out.push_str(&format!("       {record}  CNAME  ->  {target}\n"));
                out.push_str(
                    "\n     Permanent, not one-time: every renewal re-validates through it, so\n",
                );
                out.push_str(
                    "     deleting it later stops renewals ~30 days before anything breaks\n",
                );
                out.push_str("     visibly.\n");
            }
            Validation::ZoneHeld { record } => {
                out.push_str(
                    "  2. No delegation record — this deployment is configured to publish the\n",
                );
                out.push_str(&format!(
                    "     challenge TXT at {record} itself, which only works if it holds that\n"
                ));
                out.push_str("     zone. For a domain whose zone belongs to the tenant, set\n");
                out.push_str(&format!(
                    "     {DELEGATE_ZONE_ENV} to a zone this deployment does hold; the tenant\n"
                ));
                out.push_str(&format!("     then CNAMEs {record} into it.\n"));
            }
        }
        out
    }

    /// The same, for a UI or an onboarding API to render itself.
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = json!({
            "domain": self.domain,
            "address_record": {
                "name": self.domain,
                "targets": self.ingress,
            },
        });
        v["challenge_record"] = match &self.validation {
            Validation::Delegated { record, target } => json!({
                "delegated": true,
                "name": record,
                "type": "CNAME",
                "target": target,
            }),
            Validation::ZoneHeld { record } => json!({
                "delegated": false,
                "name": record,
                "type": "TXT",
                "note": format!(
                    "published by this deployment; set {DELEGATE_ZONE_ENV} to delegate instead"
                ),
            }),
        };
        v
    }
}

// ── Reading one domain's state ───────────────────────────────────────────────

/// One domain, as the store sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainReport {
    /// The domain queried.
    pub domain: String,
    /// Its enrollment record, or `None` if it was never registered.
    pub enrollment: Option<Enrollment>,
    /// `updated_at` of the sealed cert record, or `None` if no cert has issued.
    pub cert_updated_at: Option<u64>,
    /// Whether the sealed private key is present. Split from the cert because a
    /// key with no cert is the signature of an interrupted order, and reading
    /// that as "no certificate yet" hides a half-written pair.
    pub key_present: bool,
    /// A live `issuing` object, if one exists.
    pub claim: Option<IssuanceClaim>,
    /// How this domain validates.
    pub validation: Validation,
}

impl DomainReport {
    /// Gather `domain`'s state: enrollment, cert, key, claim.
    ///
    /// Four `get`s. Not folded into one listing on purpose — `status` is a
    /// single-domain verb and a prefix listing at 10k domains to answer a
    /// question about one of them is the wrong cost.
    pub fn collect(
        store: &ObjectCertStore,
        domain: &str,
        delegate_zone: Option<&str>,
    ) -> Result<Self, CertStoreError> {
        Ok(Self {
            domain: domain.to_string(),
            enrollment: store.enrollment(domain)?,
            cert_updated_at: store.read_secret(&cert_secret_name(domain))?.map(|r| r.updated_at),
            key_present: store.read_secret(&key_secret_name(domain))?.is_some(),
            claim: store.issuance_claim(domain)?,
            validation: validation(domain, delegate_zone),
        })
    }

    /// Human-readable, relative to `now` (unix seconds).
    pub fn render(&self, now: u64) -> String {
        let mut out = format!("{}\n", self.domain);
        match &self.enrollment {
            Some(e) => {
                out.push_str(&format!(
                    "  enrolled     yes ({} ago)  tls -> {}\n",
                    age(now, e.enrolled_at),
                    e.tls_backend
                ));
                if let Some(http) = e.http_backend {
                    out.push_str(&format!("               http -> {http}\n"));
                }
            }
            None => out.push_str(
                "  enrolled     NO — not in the allowlist, so the demux has no route for it \
                 and no certificate can be ordered\n",
            ),
        }
        out.push_str(&match (self.cert_updated_at, self.key_present) {
            (Some(at), true) => format!("  certificate  present (issued {} ago)\n", age(now, at)),
            (Some(at), false) => format!(
                "  certificate  present (issued {} ago) but the KEY IS MISSING — \
                 unservable; delete the pair and let it re-issue\n",
                age(now, at)
            ),
            (None, true) => {
                "  certificate  none, key present — an order was interrupted after the key \
                 was written; the next sweep re-issues\n"
                    .to_string()
            }
            (None, false) => "  certificate  none yet\n".to_string(),
        });
        out.push_str(&match &self.claim {
            Some(c) if c.is_expired(now) => format!(
                "  issuance     a lapsed claim from {} ({} ago) — the next sweep steals it\n",
                c.holder,
                age(now, c.acquired_at)
            ),
            Some(c) => format!(
                "  issuance     held by {} for another {}\n",
                c.holder,
                secs(c.remaining_secs(now))
            ),
            None => "  issuance     free\n".to_string(),
        });
        out.push_str(&match &self.validation {
            Validation::Delegated { record, target } => {
                format!("  validation   {record}  CNAME  ->  {target}\n")
            }
            Validation::ZoneHeld { record } => {
                format!("  validation   TXT at {record}, published by this deployment (no delegation configured)\n")
            }
        });
        out
    }

    /// Machine-readable form.
    pub fn to_json(&self, now: u64) -> serde_json::Value {
        json!({
            "domain": self.domain,
            "enrolled": self.enrollment.is_some(),
            "tls_backend": self.enrollment.as_ref().map(|e| e.tls_backend.to_string()),
            "http_backend": self
                .enrollment
                .as_ref()
                .and_then(|e| e.http_backend)
                .map(|a| a.to_string()),
            "enrolled_at": self.enrollment.as_ref().map(|e| e.enrolled_at),
            "cert_updated_at": self.cert_updated_at,
            "key_present": self.key_present,
            "issuance": self.claim.as_ref().map(|c| json!({
                "holder": c.holder,
                "acquired_at": c.acquired_at,
                "expired": c.is_expired(now),
                "remaining_secs": c.remaining_secs(now),
            })),
            "challenge_record": Onboarding::new(&self.domain, self.validation.clone(), Vec::new())
                .to_json()["challenge_record"],
        })
    }
}

// ── Listing ──────────────────────────────────────────────────────────────────

/// One row of `domain list`: an enrolled domain and whether it holds a cert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRow {
    /// The enrolled domain.
    pub domain: String,
    /// Its enrollment record.
    pub enrollment: Enrollment,
    /// Whether [`ObjectCertStore::domains`] reports a cert for it.
    pub has_cert: bool,
}

/// Every enrolled domain, joined against the issued set.
///
/// Two listings, not one `get` per domain: at 10k domains the per-domain form is
/// 10k round trips to answer a question two prefix listings already answer.
///
/// The join direction matters. Rows come from the **enrollment** set, so a
/// domain registered a minute ago and not yet issued still appears (as
/// `has_cert: false`) — listing the issued set instead would hide exactly the
/// domains an operator is most likely to be asking about.
pub fn list(store: &ObjectCertStore) -> Result<Vec<DomainRow>, CertStoreError> {
    let issued = store.domains()?;
    Ok(store
        .enrolled()?
        .into_iter()
        .map(|(domain, enrollment)| DomainRow {
            has_cert: issued.binary_search(&domain).is_ok(),
            domain,
            enrollment,
        })
        .collect())
}

/// Render [`list`] as aligned columns.
pub fn render_list(rows: &[DomainRow]) -> String {
    if rows.is_empty() {
        return "no domains enrolled\n".to_string();
    }
    let width = rows.iter().map(|r| r.domain.len()).max().unwrap_or(0);
    let mut out = String::new();
    for row in rows {
        out.push_str(&format!(
            "{:<width$}  {:<7}  {}\n",
            row.domain,
            if row.has_cert { "cert" } else { "NOCERT" },
            row.enrollment.tls_backend,
            width = width
        ));
    }
    out
}

// ── Enrolling ────────────────────────────────────────────────────────────────

/// Register `domain` and return what its owner must now do.
///
/// Enrollment is deliberately the *whole* of "turn this domain on": it is the
/// allowlist the demux routes from and the work list the per-domain issuer
/// sweeps, so there is no second activation step that could be forgotten. The
/// tenant's DNS is the only remaining input, which is why this returns
/// [`Onboarding`] rather than unit.
pub fn enroll(
    store: &ObjectCertStore,
    domain: &str,
    tls_backend: SocketAddr,
    http_backend: Option<SocketAddr>,
    delegate_zone: Option<&str>,
    ingress: Vec<String>,
    now: SystemTime,
) -> Result<Onboarding, CertStoreError> {
    let mut record = Enrollment::new(tls_backend, now);
    if let Some(http) = http_backend {
        record = record.with_http_backend(http);
    }
    store.enroll(domain, &record)?;
    Ok(Onboarding::new(
        domain,
        validation(domain, delegate_zone),
        ingress,
    ))
}

// ── Small renderers ──────────────────────────────────────────────────────────

/// `now - then` as a coarse duration, saturating at 0 for a future stamp.
fn age(now: u64, then: u64) -> String {
    secs(now.saturating_sub(then))
}

/// Coarse duration: seconds, minutes, hours, then days. One unit, no decimals —
/// this is for a human deciding whether something is stuck, not for arithmetic.
fn secs(d: u64) -> String {
    match d {
        0..=119 => format!("{d}s"),
        120..=7_199 => format!("{}m", d / 60),
        7_200..=172_799 => format!("{}h", d / 3_600),
        _ => format!("{}d", d / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    use yah_object_store::InMemoryObjectStore;

    fn store() -> ObjectCertStore {
        ObjectCertStore::new(
            Arc::new(InMemoryObjectStore::new()),
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        )
    }

    fn at(s: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(s)
    }

    fn backend(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn the_delegated_target_is_exactly_what_the_issuer_publishes() {
        // The whole reason this module exists: an onboarding instruction that
        // disagrees with `dns01_record_name` by one label fails validation with
        // both sides looking right.
        let v = validation("shop.tenant.io", Some("acme.yah.dev"));
        match &v {
            Validation::Delegated { record, target } => {
                assert_eq!(record, "_acme-challenge.shop.tenant.io");
                assert_eq!(target, &dns01_record_name("shop.tenant.io", Some("acme.yah.dev")));
                assert_eq!(target, "shop.tenant.io.acme.yah.dev");
            }
            other => panic!("expected Delegated, got {other:?}"),
        }
        assert_eq!(v.record(), "_acme-challenge.shop.tenant.io");
    }

    #[test]
    fn no_delegate_zone_renders_the_misconfiguration_rather_than_a_record() {
        // A custom domain with no delegate zone cannot issue — say so, rather
        // than printing a TXT the tenant has no way to create.
        let text = Onboarding::new(
            "shop.tenant.io",
            validation("shop.tenant.io", None),
            Vec::new(),
        )
        .render();
        assert!(text.contains(DELEGATE_ZONE_ENV), "{text}");
        // No delegation record is offered — only the address record's
        // `A/AAAA/CNAME` line, which is a different record entirely.
        assert!(
            !text.contains("_acme-challenge.shop.tenant.io  CNAME"),
            "{text}"
        );
    }

    #[test]
    fn onboarding_names_the_ingress_when_given_and_says_it_cannot_when_not() {
        let v = validation("shop.tenant.io", Some("acme.yah.dev"));
        let with = Onboarding::new("shop.tenant.io", v.clone(), vec!["203.0.113.7".into()]).render();
        assert!(with.contains("shop.tenant.io  A/AAAA/CNAME  ->  203.0.113.7"), "{with}");

        // Without one, it must not guess — the enrollment's backend is a
        // loopback/mesh address and handing that to a tenant as their A record
        // is worse than saying nothing.
        let without = Onboarding::new("shop.tenant.io", v, Vec::new()).render();
        assert!(without.contains("public ingress address"), "{without}");
        assert!(!without.contains("127.0.0.1"), "{without}");
    }

    #[test]
    fn onboarding_json_carries_the_same_target_as_the_text() {
        let o = Onboarding::new(
            "shop.tenant.io",
            validation("shop.tenant.io", Some("acme.yah.dev")),
            vec!["203.0.113.7".into()],
        );
        let j = o.to_json();
        assert_eq!(j["challenge_record"]["delegated"], json!(true));
        assert_eq!(j["challenge_record"]["type"], json!("CNAME"));
        assert_eq!(
            j["challenge_record"]["target"],
            json!("shop.tenant.io.acme.yah.dev")
        );
        assert_eq!(j["address_record"]["targets"], json!(["203.0.113.7"]));
        assert!(o.render().contains(j["challenge_record"]["target"].as_str().unwrap()));
    }

    #[test]
    fn enroll_writes_the_allowlist_entry_and_returns_the_instruction() {
        let certs = store();
        let o = enroll(
            &certs,
            "shop.tenant.io",
            backend(8443),
            Some(backend(8080)),
            Some("acme.yah.dev"),
            vec!["203.0.113.7".into()],
            at(1_700_000_000),
        )
        .unwrap();
        assert!(o.render().contains("shop.tenant.io.acme.yah.dev"));

        let rec = certs.enrollment("shop.tenant.io").unwrap().unwrap();
        assert_eq!(rec.tls_backend, backend(8443));
        assert_eq!(rec.http_backend, Some(backend(8080)));
        assert_eq!(rec.enrolled_at, 1_700_000_000);
    }

    #[test]
    fn a_report_on_a_domain_that_was_never_enrolled_says_so_first() {
        let certs = store();
        let r = DomainReport::collect(&certs, "nope.tenant.io", Some("acme.yah.dev")).unwrap();
        assert_eq!(r.enrollment, None);
        assert_eq!(r.cert_updated_at, None);
        assert!(!r.key_present);
        assert_eq!(r.claim, None);
        let text = r.render(1_700_000_000);
        assert!(text.contains("enrolled     NO"), "{text}");
        assert!(text.contains("no route"), "{text}");
    }

    #[test]
    fn a_live_claim_reads_as_held_and_a_lapsed_one_as_stealable() {
        let certs = store();
        certs
            .enroll(
                "shop.tenant.io",
                &Enrollment::new(backend(8443), at(1_700_000_000)),
            )
            .unwrap();
        certs
            .claim_issuance("shop.tenant.io", "100.64.0.3:7443", at(1_700_000_000))
            .unwrap();

        let r = DomainReport::collect(&certs, "shop.tenant.io", Some("acme.yah.dev")).unwrap();
        let held = r.render(1_700_000_060);
        assert!(held.contains("held by 100.64.0.3:7443"), "{held}");

        // Past the TTL the same object is a lapsed claim, not a live one — the
        // distinction an operator staring at a stuck `issuing` needs.
        let lapsed = r.render(1_700_000_000 + 10_000);
        assert!(lapsed.contains("lapsed claim"), "{lapsed}");
    }

    #[test]
    fn peeking_at_a_claim_does_not_take_or_disturb_it() {
        // An admin `status` that peeked by attempting a claim would evict a
        // live issuer mid-order.
        let certs = store();
        let held = certs
            .claim_issuance("shop.tenant.io", "node-1", at(1_000))
            .unwrap();
        let seen = certs.issuance_claim("shop.tenant.io").unwrap().unwrap();
        assert_eq!(seen, held);
        // Still node-1's: a competing claim is still refused.
        assert!(certs
            .claim_issuance("shop.tenant.io", "node-2", at(1_060))
            .is_err());
        assert_eq!(certs.issuance_claim("nope.tenant.io").unwrap(), None);
    }

    #[test]
    fn list_shows_an_enrolled_domain_that_has_no_cert_yet() {
        // The join must run from the enrollment set: a domain enrolled a minute
        // ago and not yet issued is the row an operator is most likely looking
        // for, and listing the issued set would omit it entirely.
        let certs = store();
        certs
            .enroll("new.tenant.io", &Enrollment::new(backend(8443), at(1)))
            .unwrap();
        certs
            .enroll("old.tenant.io", &Enrollment::new(backend(8444), at(1)))
            .unwrap();
        certs
            .write_secret(
                &cert_secret_name("old.tenant.io"),
                &crate::raft::SecretRecord {
                    ciphertext: b"c".to_vec(),
                    nonce: vec![0; 12],
                    updated_at: 1_700_000_000,
                    access: Default::default(),
                    digest: None,
                },
            )
            .unwrap();

        let rows = list(&certs).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].domain, "new.tenant.io");
        assert!(!rows[0].has_cert);
        assert_eq!(rows[1].domain, "old.tenant.io");
        assert!(rows[1].has_cert);

        let text = render_list(&rows);
        assert!(text.contains("new.tenant.io  NOCERT"), "{text}");
        assert!(text.contains("old.tenant.io  cert"), "{text}");
        assert_eq!(render_list(&[]), "no domains enrolled\n");
    }

    #[test]
    fn admin_config_reads_the_same_issuer_segment_the_daemon_writes_under() {
        // Reading a different directory default from the daemon would list an
        // empty prefix and report every enrolled domain as having no cert.
        let cfg = parse_admin_config(|k| match k {
            BUCKET_ENV => Some("yah-certs".to_string()),
            crate::cert_store::ACCOUNT_ID_ENV => Some("acct123".to_string()),
            DELEGATE_ZONE_ENV => Some(" acme.yah.dev. ".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(cfg.store.bucket, "yah-certs");
        assert_eq!(cfg.directory_url, AcmeDirectory::Staging.url());
        // Trailing dot trimmed, so an operator's fully-qualified zone does not
        // become `shop.tenant.io.acme.yah.dev.` with a stray label separator.
        assert_eq!(cfg.delegate_zone.as_deref(), Some("acme.yah.dev"));

        let prod = parse_admin_config(|k| match k {
            BUCKET_ENV => Some("yah-certs".to_string()),
            crate::cert_store::ACCOUNT_ID_ENV => Some("acct123".to_string()),
            DIRECTORY_ENV => Some("production".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(prod.directory_url, AcmeDirectory::Production.url());
        assert_eq!(prod.delegate_zone, None);
    }

    #[test]
    fn a_missing_bucket_names_the_variable_instead_of_exiting_quietly() {
        let err = parse_admin_config(|_| None).unwrap_err();
        assert!(err.contains(BUCKET_ENV), "{err}");
    }

    #[test]
    fn durations_stay_single_unit() {
        assert_eq!(secs(0), "0s");
        assert_eq!(secs(119), "119s");
        assert_eq!(secs(120), "2m");
        assert_eq!(secs(7_199), "119m");
        assert_eq!(secs(7_200), "2h");
        assert_eq!(secs(172_800), "2d");
        // A future stamp (clock skew) reads as 0, never as a huge wrapped age.
        assert_eq!(age(100, 500), "0s");
    }
}
