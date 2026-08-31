//! Per-domain TLS material in an object store instead of raft (R779 / W267).
//!
//! [`crate::acme_issuer`] seals the fleet's wildcard cert under the node KEK and
//! `PutSecret`s it into raft. That is correct for *one* cert: `raft/store.rs:5`
//! sizes the state machine as "tiny (KB-scale) so we can afford to rewrite the
//! full file on every mutation", and `persist()` does exactly that —
//! `serde_json::to_string` of the whole state, on every mutation, on every node.
//! W267's free-tier ingress wants a cert *per domain* at 10k domains, which is
//! ~40 MB of full-state rewrite per `PutSecret` and breaks that assumption
//! outright. R779's DECISION 1: **raft holds nothing per domain**; per-domain
//! cert material lives in an object store (R2), reached through
//! [`yah_object_store::ObjectStore`].
//!
//! ## What does *not* change, deliberately
//!
//! Only the backing store moves. Everything W273 established stays:
//!
//! - The stored value is the same [`SecretRecord`] — AES-256-GCM ciphertext,
//!   12-byte nonce, `updated_at`, the R706 [`SecretAccess`] rule and the R720-F1
//!   keyed digest — serialised as JSON. The object store, like a raft snapshot
//!   on disk, holds **ciphertext only**.
//! - Sealing stays [`crate::secrets::seal_cluster_secret`] under the node-local
//!   cluster KEK, and opening stays [`crate::secrets::ClusterResolver`], which
//!   still checks the record's access rule *before* touching the KEK. This
//!   module implements [`ClusterSecretStore`], the one-method read trait the
//!   resolver is already generic over, so the resolver does not know or care
//!   which store a record came from.
//! - The KEK never leaves the node, and in particular **never reaches passway**.
//!   That is load-bearing, not incidental: passway is the most exposed process
//!   in the fleet, and R777's tenant-isolation verdict (`passway/src/tls.rs`,
//!   "One listener serves one cert") turns on one compromised passway costing
//!   one tenant's key. A passway that fetched its own cert from R2 would need
//!   the cluster KEK, and one RCE would then decrypt *every* tenant's key. So
//!   the fetch stays on this side of the mount boundary: the node resolves and
//!   materialises two files, passway reads two files, exactly as today.
//!
//! ## Layout
//!
//! ```text
//! certs/<issuer>/<domain>/cert.sealed   SecretRecord JSON — the chain PEM
//! certs/<issuer>/<domain>/key.sealed    SecretRecord JSON — the private key PEM
//! certs/<issuer>/<domain>/issuing       IssuanceClaim JSON — the CAS lock, transient
//! enrolled/<domain>                     Enrollment JSON — the tenant registry
//! ```
//!
//! `<issuer>` is the ACME directory's host ([`issuer_key`]), mirroring
//! certmagic's `certificates/<issuer-key>/<domain>/` layout. It is in the path
//! so one domain can hold a Let's Encrypt cert and a second-CA cert side by side
//! — R779's DECISION 3 keeps ZeroSSL/GTS as overflow if LE refuses a rate-limit
//! adjustment, and a flat layout would make that a migration instead of a write.
//!
//! ## The two things this store does that raft did not
//!
//! - [`ObjectCertStore::enrolled`] enumerates the *routable* set with one
//!   `list_prefix`. That is the source of truth for the SNI demux's route table,
//!   which R779's DECISION 2 makes *structural*: an SNI absent from
//!   `PASSWAY_DEMUX_ROUTES` never reaches a passway, so it can never provoke an
//!   ACME order. Caddy spells this an "ask" endpoint; here it is a list.
//!   [`ObjectCertStore::domains`] is the neighbouring but *different* question —
//!   which domains hold a cert — and is what a renewal sweep works from.
//! - [`ObjectCertStore::claim_issuance`] is a TTL lock over
//!   [`yah_object_store::Precondition`] compare-and-swap — certmagic's `Locker`,
//!   and the reason the per-domain path does not need a raft `AcquireLock` per
//!   domain (which would put the pressure straight back where DECISION 1 took it
//!   from). Two nodes racing the same domain: one wins the `IfAbsent` put, the
//!   other backs off; a dead holder's claim expires and is stolen under
//!   `IfMatch`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use yah_object_store::{Error as ObjectError, ObjectStore, Precondition};

use crate::raft::SecretRecord;
use crate::secrets::ClusterSecretStore;

/// Top-level key prefix for every object this module writes.
pub const CERT_PREFIX: &str = "certs";

/// Object suffix holding the sealed certificate chain.
pub const CERT_OBJECT: &str = "cert.sealed";

/// Object suffix holding the sealed private key.
pub const KEY_OBJECT: &str = "key.sealed";

/// Object suffix holding a live issuance claim ([`IssuanceClaim`]).
pub const CLAIM_OBJECT: &str = "issuing";

/// How long an issuance claim stays valid before another node may steal it.
///
/// Long enough to cover a full ACME order including DNS-01 propagation (the
/// issuer's own `dns01_propagation_delay` plus validation), short enough that a
/// node that dies mid-order does not park the domain for an hour.
pub const CLAIM_TTL: Duration = Duration::from_secs(10 * 60);

/// Failures reaching the object-backed cert store.
///
/// Deliberately does **not** wrap [`crate::secrets::SecretError`]: nothing here
/// decrypts, so there is no failure mode that could name key material.
#[derive(Debug, Error)]
pub enum CertStoreError {
    /// The backing object store failed (network, auth, protocol).
    #[error("cert store backend: {0}")]
    Backend(#[from] ObjectError),

    /// An object exists at the key but is not a record this module wrote.
    /// Treated as a hard error rather than a miss — a corrupt cert object must
    /// not silently become "no cert yet, order another one".
    #[error("cert store: malformed record at {key}: {source}")]
    Malformed {
        key: String,
        #[source]
        source: serde_json::Error,
    },

    /// Another node holds a live issuance claim on this domain.
    #[error("cert store: {domain} is already being issued by {holder} ({remaining_secs}s left)")]
    Claimed {
        domain: String,
        holder: String,
        remaining_secs: u64,
    },

    /// A write was attempted under a logical name that is not per-domain TLS
    /// material. Refused rather than given an invented key — see [`object_key`].
    #[error("cert store: {name} is not per-domain TLS material (expected tls/<domain>/cert or tls/<domain>/key)")]
    NotCertMaterial { name: String },

    /// A domain name that cannot be a single key segment — empty, containing
    /// `/`, or containing `..`. Refused at the API rather than sanitised, so a
    /// caller never believes it enrolled a domain that landed under some other
    /// prefix.
    #[error("cert store: {domain:?} is not a usable domain (empty, or contains '/' or '..')")]
    InvalidDomain { domain: String },

    /// [`ObjectCertStore::enroll`] found a *different* enrollment already in
    /// place. Two tenants claiming one hostname is a configuration bug that
    /// must not resolve silently to last-writer-wins — the same rule
    /// `RouteTable::parse` applies to a duplicate host in
    /// `PASSWAY_DEMUX_ROUTES`.
    #[error("cert store: {domain} is already enrolled to {existing} (unenroll it first)")]
    AlreadyEnrolled { domain: String, existing: String },
}

/// Whether `domain` can be used as one object-key segment.
///
/// Rejects the shapes that would address an object outside the domain's own
/// prefix, or collapse two domains into one key.
fn is_safe_domain(domain: &str) -> bool {
    !domain.is_empty() && !domain.contains('/') && !domain.contains("..")
}

/// Derive the path segment for an ACME directory URL — its host, lowercased.
///
/// `https://acme-v02.api.letsencrypt.org/directory` → `acme-v02.api.letsencrypt.org`.
/// Any character outside `[a-z0-9.-]` is replaced with `-` so the result is
/// always a single safe path segment; a URL with no recognisable host falls back
/// to the sanitised whole string rather than an empty segment (which would
/// collapse two issuers' key spaces into one).
pub fn issuer_key(directory_url: &str) -> String {
    let after_scheme = directory_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(directory_url);
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()
        .filter(|h| !h.is_empty())
        .unwrap_or(directory_url);
    let sanitised: String = host
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if sanitised.is_empty() {
        "unknown-issuer".to_string()
    } else {
        sanitised
    }
}

/// `certs/<issuer>/` — the prefix every object for one issuer sits under.
pub fn issuer_prefix(issuer: &str) -> String {
    format!("{CERT_PREFIX}/{issuer}/")
}

/// Map a logical cluster-secret name onto its object key, or `None` if the name
/// is not per-domain TLS material.
///
/// Recognises exactly the two names [`crate::acme_issuer::cert_secret_name`] and
/// [`crate::acme_issuer::key_secret_name`] produce — `tls/<domain>/cert` and
/// `tls/<domain>/key`. **Everything else returns `None` on purpose**: this store
/// is for certs, and a general cluster secret (a registry credential, a mesh
/// pre-shared key) must never be looked for in an object store just because raft
/// happened to miss. That would turn a fail-closed `ClusterNotFound` into a
/// network round-trip whose answer an operator with bucket access controls.
///
/// A domain containing `/` is rejected for the same reason a path traversal is:
/// it would let a crafted secret name address an object outside its own domain's
/// prefix.
pub fn object_key(issuer: &str, name: &str) -> Option<String> {
    let rest = name.strip_prefix("tls/")?;
    let (domain, leaf) = rest.rsplit_once('/')?;
    let object = match leaf {
        "cert" => CERT_OBJECT,
        "key" => KEY_OBJECT,
        _ => return None,
    };
    if !is_safe_domain(domain) {
        return None;
    }
    Some(format!("{}{domain}/{object}", issuer_prefix(issuer)))
}

/// Where the object-backed cert store lives.
///
/// Parsed from the daemon environment by [`CertStoreConfig::parse`] and turned
/// into a live store by [`CertStoreConfig::connect`]. Kept separate from the
/// store itself so config parsing stays a pure function over a `key -> value`
/// lookup — the same shape [`crate::acme_issuer::parse_issuer_config`] uses, and
/// for the same reason: it is unit-testable without a network or `std::env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertStoreConfig {
    /// Cloudflare account id — the subdomain in `<id>.r2.cloudflarestorage.com`.
    pub account_id: String,
    /// Bucket holding the `certs/` prefix.
    pub bucket: String,
    /// S3-compatible endpoint override (the pond tier's MinIO, or a test
    /// server). `None` uses the derived R2 endpoint.
    pub endpoint: Option<String>,
}

/// Env key naming the bucket. Its presence is what turns the cert store on.
pub const BUCKET_ENV: &str = "YUBABA_CERT_STORE_BUCKET";
/// Env key naming the Cloudflare account id.
pub const ACCOUNT_ID_ENV: &str = "YUBABA_CERT_STORE_ACCOUNT_ID";
/// Env key overriding the S3 endpoint.
pub const ENDPOINT_ENV: &str = "YUBABA_CERT_STORE_ENDPOINT";

impl CertStoreConfig {
    /// `Ok(None)` when [`BUCKET_ENV`] is unset — the cert store is opt-in, and a
    /// node without it behaves exactly as it did before R779.
    ///
    /// A bucket *with* no account id is a hard error rather than a silent
    /// skip: half-configured means an operator meant to turn this on, and a
    /// cert store that quietly does not exist is discovered as a missing cert
    /// weeks later.
    pub fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let bucket = match get(BUCKET_ENV) {
            Some(b) if !b.trim().is_empty() => b.trim().to_string(),
            _ => return Ok(None),
        };
        let account_id = get(ACCOUNT_ID_ENV)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or(format!("{ACCOUNT_ID_ENV} is required when {BUCKET_ENV} is set"))?;
        let endpoint = get(ENDPOINT_ENV)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Ok(Some(Self {
            account_id,
            bucket,
            endpoint,
        }))
    }

    /// Build a live [`ObjectCertStore`] against `directory_url`'s issuer segment.
    ///
    /// Credentials come from [`yah_object_store::R2ObjectStore::from_vault`] —
    /// the `cloudflare-r2-*` vault slots with a `CF_R2_*` env fallback — so this
    /// adds no new credential surface beyond the one every other R2 consumer in
    /// the tree already uses.
    pub fn connect(&self, directory_url: &str) -> Result<ObjectCertStore, CertStoreError> {
        let mut store = yah_object_store::R2ObjectStore::from_vault(&self.account_id, &self.bucket)?;
        if let Some(endpoint) = &self.endpoint {
            store = store.with_endpoint(endpoint.clone());
        }
        Ok(ObjectCertStore::new(Arc::new(store), directory_url))
    }
}

/// A live issuance claim — certmagic's `Locker`, expressed as one object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuanceClaim {
    /// Who holds it. A node id, for the operator reading a stuck claim.
    pub holder: String,
    /// Unix seconds the claim was taken.
    pub acquired_at: u64,
    /// Seconds from `acquired_at` after which another node may steal it.
    pub ttl_secs: u64,
}

impl IssuanceClaim {
    /// Whether `now` is past `acquired_at + ttl_secs`.
    ///
    /// A claim from the *future* (clock skew between nodes) is not expired —
    /// `saturating_sub` would otherwise read a skewed-ahead claim as instantly
    /// stealable, which is the one case where two nodes would both order.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.acquired_at.saturating_add(self.ttl_secs)
    }

    /// Seconds still to run, `0` once expired.
    pub fn remaining_secs(&self, now: u64) -> u64 {
        self.acquired_at
            .saturating_add(self.ttl_secs)
            .saturating_sub(now)
    }
}

// ── The enrollment set ───────────────────────────────────────────────────────

/// Top-level key prefix for the enrollment set.
///
/// Deliberately **not** under [`CERT_PREFIX`]: enrolment is a fact about a
/// tenant, not about a CA, so it must not be duplicated per issuer. A domain
/// enrolled once stays routable whichever CA ends up holding its cert (DECISION
/// 3's overflow).
pub const ENROLLED_PREFIX: &str = "enrolled/";

/// One enrolled domain — the tenant registry, as one object per domain.
///
/// This is what DECISION 2 means by "the route table *is* the allowlist". A
/// hostname with no enrollment object has no route, so it never reaches a
/// passway and can never provoke an ACME order; registering a domain *is*
/// writing this object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Enrollment {
    /// Where the demux splices this domain's TLS bytes — the per-tenant
    /// passway's listener (a loopback or mesh address, or the socket kamaji
    /// holds in custody for a cold tenant).
    ///
    /// A [`SocketAddr`], not a string, because the demux's `RouteTable` parses
    /// its backends to one: a hostname here would be a routes file the demux
    /// refuses at load, discovered as an outage instead of as an enrollment
    /// error.
    pub tls_backend: SocketAddr,
    /// Where this domain's port-80 traffic goes, once an HTTP tier exists — the
    /// same passway's HTTP-01 responder (`PASSWAY_ACME_HTTP01_BIND`), which is a
    /// *different* port from `tls_backend` because one process cannot serve
    /// plaintext and TLS on one port.
    ///
    /// `None` today, and `#[serde(default)]` so records written now load once it
    /// is populated. Carried in the record rather than derived (`tls_backend`
    /// port + 1, say) because a derived port is a silent collision waiting for
    /// the first tenant whose neighbour took it.
    #[serde(default)]
    pub http_backend: Option<SocketAddr>,
    /// Unix seconds the enrollment was written. For an operator reading the
    /// bucket; nothing keys off it.
    pub enrolled_at: u64,
}

impl Enrollment {
    /// A TLS-only enrollment stamped at `now`.
    pub fn new(tls_backend: SocketAddr, now: SystemTime) -> Self {
        Self {
            tls_backend,
            http_backend: None,
            enrolled_at: unix_secs(now),
        }
    }

    /// The same, also routing port 80 to `http_backend`.
    pub fn with_http_backend(mut self, http_backend: SocketAddr) -> Self {
        self.http_backend = Some(http_backend);
        self
    }
}

/// Render `PASSWAY_DEMUX_ROUTES` from an enrollment set.
///
/// `domain=addr` pairs, comma-joined, sorted by domain — deterministic so a
/// publisher can compare two renders byte-for-byte and skip a no-op write, and
/// so an operator diffing two routes files sees only what actually changed.
///
/// Only `tls_backend` is rendered: the demux is the `:443` tier and its table
/// has one backend per host. When an HTTP tier lands it gets its own render off
/// [`Enrollment::http_backend`] rather than a second column here — the demux's
/// parser takes `host=addr`, and widening that format would break every existing
/// `PASSWAY_DEMUX_ROUTES` string.
pub fn render_demux_routes<'a>(
    enrolled: impl IntoIterator<Item = (&'a str, &'a Enrollment)>,
) -> String {
    route_entries(enrolled).join(",")
}

/// The `host=addr` entries [`render_demux_routes`] joins, sorted and deduped.
///
/// Exposed because the routes *file* the demux reloads is newline-separated —
/// one entry per line is what makes a 10k-domain table diffable — while the
/// `PASSWAY_DEMUX_ROUTES` env var is comma-separated. Same entries, two
/// separators, one place that decides what an entry is.
pub fn route_entries<'a>(
    enrolled: impl IntoIterator<Item = (&'a str, &'a Enrollment)>,
) -> Vec<String> {
    let mut entries: Vec<String> = enrolled
        .into_iter()
        .map(|(domain, e)| format!("{domain}={}", e.tls_backend))
        .collect();
    entries.sort();
    entries.dedup();
    entries
}

/// Object-store-backed store for per-domain sealed TLS material.
///
/// Cheap to clone in the sense that matters — the backing store is behind an
/// `Arc` — so a node can hand one to both the issuer loop and each per-deploy
/// resolver without re-establishing an HTTP client.
#[derive(Clone)]
pub struct ObjectCertStore {
    objects: Arc<dyn ObjectStore>,
    issuer: String,
}

impl std::fmt::Debug for ObjectCertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The store itself may hold credentials; only the issuer segment is safe
        // (and useful) to print.
        f.debug_struct("ObjectCertStore")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl ObjectCertStore {
    /// Build a store writing under `certs/<issuer_key(directory_url)>/`.
    pub fn new(objects: Arc<dyn ObjectStore>, directory_url: &str) -> Self {
        Self {
            objects,
            issuer: issuer_key(directory_url),
        }
    }

    /// The path segment this store writes under.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Read and deserialise the [`SecretRecord`] at `name`, or `None` if the
    /// name is not TLS material or no object exists.
    ///
    /// Separate from the [`ClusterSecretStore`] impl because that trait's
    /// `Option` return cannot distinguish "absent" from "the bucket is
    /// unreachable" — a caller that needs to tell those apart (the issuer
    /// deciding whether to order) calls this and reads the error.
    pub fn read_secret(&self, name: &str) -> Result<Option<SecretRecord>, CertStoreError> {
        let Some(key) = object_key(&self.issuer, name) else {
            return Ok(None);
        };
        let Some(bytes) = self.objects.get(&key)? else {
            return Ok(None);
        };
        let rec = serde_json::from_slice(&bytes).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        Ok(Some(rec))
    }

    /// Write the sealed `rec` at `name`. Overwrites.
    ///
    /// Rejects a name that is not per-domain TLS material rather than inventing
    /// a key for it — see [`object_key`].
    pub fn write_secret(&self, name: &str, rec: &SecretRecord) -> Result<(), CertStoreError> {
        let Some(key) = object_key(&self.issuer, name) else {
            return Err(CertStoreError::NotCertMaterial {
                name: name.to_string(),
            });
        };
        let body = serde_json::to_vec(rec).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        self.objects.put(&key, body)?;
        Ok(())
    }

    /// Write a freshly-issued sealed pair.
    ///
    /// **Key first, cert last** — the same ordering, for the same reason, as
    /// [`crate::acme_issuer`]'s raft writes: renewal-due is gated off the *cert*
    /// record's `updated_at`, so writing the gate record last means a partial
    /// failure leaves the cert stale and the next tick re-issues and heals. The
    /// reverse order can wedge the store with a fresh cert against a stale key,
    /// which is a TLS failure for every consumer until someone notices.
    pub fn write_pair(
        &self,
        cert_name: &str,
        key_name: &str,
        cert_rec: &SecretRecord,
        key_rec: &SecretRecord,
    ) -> Result<(), CertStoreError> {
        self.write_secret(key_name, key_rec)?;
        self.write_secret(cert_name, cert_rec)?;
        Ok(())
    }

    /// Remove both objects for `domain`. Idempotent.
    pub fn delete_domain(&self, domain: &str) -> Result<(), CertStoreError> {
        let prefix = format!("{}{domain}/", issuer_prefix(&self.issuer));
        for leaf in [CERT_OBJECT, KEY_OBJECT, CLAIM_OBJECT] {
            self.objects.delete(&format!("{prefix}{leaf}"))?;
        }
        Ok(())
    }

    /// Every domain with a stored certificate under this issuer.
    ///
    /// Keyed off the *cert* object specifically — a domain with only a claim or
    /// only a key is mid-issuance and holds nothing servable. This answers "what
    /// have we issued", which is a renewal sweep's work list.
    ///
    /// **Not the demux's route table.** R779's first pass recorded it as such,
    /// and that deadlocks: on-demand TLS issues a domain's first cert when the
    /// first connection reaches its passway, so a route table gated on the cert
    /// already existing means a new domain is never routed, therefore never
    /// reached, therefore never issued. The allowlist is
    /// [`ObjectCertStore::enrolled`] — the fact that a tenant registered the
    /// name, which is knowable before any cert exists.
    ///
    /// Sorted, so a caller diffing successive listings sees a stable order.
    pub fn domains(&self) -> Result<Vec<String>, CertStoreError> {
        let prefix = issuer_prefix(&self.issuer);
        let suffix = format!("/{CERT_OBJECT}");
        let mut out: Vec<String> = self
            .objects
            .list_prefix(&prefix)?
            .into_iter()
            .filter_map(|k| {
                let rest = k.strip_prefix(&prefix)?;
                let domain = rest.strip_suffix(&suffix)?;
                (!domain.is_empty() && !domain.contains('/')).then(|| domain.to_string())
            })
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Try to become the node that issues for `domain`.
    ///
    /// Wins by creating the claim object under [`Precondition::IfAbsent`]. A
    /// losing caller gets [`CertStoreError::Claimed`] naming the holder, unless
    /// the existing claim has expired — in which case it is stolen under
    /// [`Precondition::IfMatch`] against the etag just read, so two nodes both
    /// noticing the same expiry still produce exactly one winner.
    pub fn claim_issuance(
        &self,
        domain: &str,
        holder: &str,
        now: SystemTime,
    ) -> Result<IssuanceClaim, CertStoreError> {
        let key = format!("{}{domain}/{CLAIM_OBJECT}", issuer_prefix(&self.issuer));
        let now = unix_secs(now);
        let claim = IssuanceClaim {
            holder: holder.to_string(),
            acquired_at: now,
            ttl_secs: CLAIM_TTL.as_secs(),
        };
        let body = serde_json::to_vec(&claim).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;

        match self
            .objects
            .put_if(&key, body.clone(), Precondition::IfAbsent)
        {
            Ok(_) => return Ok(claim),
            Err(ObjectError::PreconditionFailed(_)) => {}
            Err(e) => return Err(e.into()),
        }

        // Someone holds it. Read the etag and the record together: the etag is
        // what makes the steal a compare-and-swap rather than a second racer's
        // blind overwrite.
        let etag = self.objects.etag(&key)?;
        let existing = self.objects.get(&key)?;
        let (Some(etag), Some(bytes)) = (etag, existing) else {
            // It vanished between the failed IfAbsent and this read — the holder
            // finished and released. Retry the create; a second racer that got
            // here at the same moment loses that IfAbsent, and losing is
            // `Claimed`, not a backend fault.
            return match self.objects.put_if(&key, body, Precondition::IfAbsent) {
                Ok(_) => Ok(claim),
                Err(ObjectError::PreconditionFailed(_)) => Err(CertStoreError::Claimed {
                    domain: domain.to_string(),
                    holder: "another node".to_string(),
                    remaining_secs: CLAIM_TTL.as_secs(),
                }),
                Err(e) => Err(e.into()),
            };
        };
        let held: IssuanceClaim =
            serde_json::from_slice(&bytes).map_err(|source| CertStoreError::Malformed {
                key: key.clone(),
                source,
            })?;
        if !held.is_expired(now) {
            let remaining_secs = held.remaining_secs(now);
            return Err(CertStoreError::Claimed {
                domain: domain.to_string(),
                holder: held.holder,
                remaining_secs,
            });
        }
        match self.objects.put_if(&key, body, Precondition::IfMatch(etag)) {
            Ok(_) => Ok(claim),
            // Lost the steal to another node that noticed the same expiry.
            Err(ObjectError::PreconditionFailed(_)) => Err(CertStoreError::Claimed {
                domain: domain.to_string(),
                holder: held.holder,
                remaining_secs: 0,
            }),
            Err(e) => Err(e.into()),
        }
    }

    /// Drop this node's claim on `domain`. Idempotent.
    ///
    /// Not required for correctness — a claim expires on its own — but a
    /// released claim lets a retry start immediately instead of waiting out
    /// [`CLAIM_TTL`] after a fast failure.
    pub fn release_issuance(&self, domain: &str) -> Result<(), CertStoreError> {
        let key = format!("{}{domain}/{CLAIM_OBJECT}", issuer_prefix(&self.issuer));
        self.objects.delete(&key)?;
        Ok(())
    }

    /// R779 — the opposite of [`release_issuance`]: **hold** the claim past its
    /// normal TTL so a *failed* order is not retried by anyone until `ttl`
    /// elapses.
    ///
    /// The claim object doubles as the failure backoff marker, which is why
    /// there is no separate one. That matters: Let's Encrypt rate-limits
    /// authorization failures **per identifier**, not per client, so a
    /// node-local marker (passway's `<cert>.acme-failed` file) would let N nodes
    /// each burn the same domain's budget N times over. This one is in the
    /// shared bucket, so every node sees the same cooldown.
    ///
    /// Written unconditionally rather than under `IfMatch`: the caller reached
    /// here holding the claim, and if its own claim had already lapsed and been
    /// stolen mid-order, over-writing the thief's claim costs one delayed
    /// issuance — strictly cheaper than the alternative of leaving a
    /// just-failed domain immediately retryable.
    pub fn cool_down_issuance(
        &self,
        domain: &str,
        holder: &str,
        now: SystemTime,
        ttl: Duration,
    ) -> Result<(), CertStoreError> {
        let key = format!("{}{domain}/{CLAIM_OBJECT}", issuer_prefix(&self.issuer));
        let claim = IssuanceClaim {
            holder: holder.to_string(),
            acquired_at: unix_secs(now),
            ttl_secs: ttl.as_secs(),
        };
        let body = serde_json::to_vec(&claim).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        self.objects.put(&key, body)?;
        Ok(())
    }

    // ── Enrollment ───────────────────────────────────────────────────────────

    /// `enrolled/<domain>` — issuer-independent, see [`ENROLLED_PREFIX`].
    fn enrolled_key(domain: &str) -> Result<String, CertStoreError> {
        if !is_safe_domain(domain) {
            return Err(CertStoreError::InvalidDomain {
                domain: domain.to_string(),
            });
        }
        Ok(format!("{ENROLLED_PREFIX}{domain}"))
    }

    /// Add `domain` to the routable set.
    ///
    /// Idempotent for an identical record and **refused** for a conflicting one
    /// ([`CertStoreError::AlreadyEnrolled`]): re-pointing a live domain at a
    /// different backend is `unenroll` + `enroll`, spelled in two calls so it
    /// cannot happen by a stale config being replayed.
    pub fn enroll(&self, domain: &str, enrollment: &Enrollment) -> Result<(), CertStoreError> {
        let key = Self::enrolled_key(domain)?;
        if let Some(existing) = self.enrollment(domain)? {
            if existing.tls_backend == enrollment.tls_backend
                && existing.http_backend == enrollment.http_backend
            {
                return Ok(()); // same enrollment, different timestamp — a no-op
            }
            return Err(CertStoreError::AlreadyEnrolled {
                domain: domain.to_string(),
                existing: existing.tls_backend.to_string(),
            });
        }
        let body = serde_json::to_vec(enrollment).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        self.objects.put(&key, body)?;
        Ok(())
    }

    /// Read one domain's enrollment, or `None` if it is not enrolled.
    ///
    /// A malformed object here IS a hard error (unlike in [`Self::enrolled`]):
    /// a single-domain lookup has one caller asking about one domain, and
    /// reporting "not enrolled" for a corrupt record would let a caller
    /// re-enroll it to a different backend without ever seeing the conflict.
    pub fn enrollment(&self, domain: &str) -> Result<Option<Enrollment>, CertStoreError> {
        let key = Self::enrolled_key(domain)?;
        let Some(bytes) = self.objects.get(&key)? else {
            return Ok(None);
        };
        let rec = serde_json::from_slice(&bytes).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        Ok(Some(rec))
    }

    /// Remove `domain` from the routable set. Idempotent.
    ///
    /// Leaves the cert material alone: unenrolling is a routing decision, and a
    /// re-enrolled domain should not have to re-order a cert it already holds
    /// (which would spend an ACME order to undo an operator's typo). Deleting
    /// the material is [`Self::delete_domain`], explicitly.
    pub fn unenroll(&self, domain: &str) -> Result<(), CertStoreError> {
        let key = Self::enrolled_key(domain)?;
        self.objects.delete(&key)?;
        Ok(())
    }

    /// The whole enrollment set, sorted by domain.
    ///
    /// One `list_prefix` plus one `get` per domain — the listing carries keys
    /// only, so the backend has to be read. That is the cost of keeping one
    /// object per domain (concurrent enrollments never collide, unlike writers
    /// to a single manifest); a publisher sweeping this should do so on the
    /// order of minutes, not seconds.
    ///
    /// **A malformed object is skipped with a warning, not an error** — the
    /// opposite of [`Self::read_secret`], deliberately. The consumer is the
    /// route table: erroring out on one corrupt object would withhold the whole
    /// render and freeze *every* tenant's routing on one bad key, while skipping
    /// costs exactly the one domain that is broken. A cert read makes the
    /// reverse trade because there a miss means "order another one".
    pub fn enrolled(&self) -> Result<Vec<(String, Enrollment)>, CertStoreError> {
        let mut out: Vec<(String, Enrollment)> = Vec::new();
        for key in self.objects.list_prefix(ENROLLED_PREFIX)? {
            let Some(domain) = key.strip_prefix(ENROLLED_PREFIX) else {
                continue;
            };
            if !is_safe_domain(domain) {
                continue;
            }
            let Some(bytes) = self.objects.get(&key)? else {
                continue; // unenrolled between the list and the get
            };
            match serde_json::from_slice::<Enrollment>(&bytes) {
                Ok(rec) => out.push((domain.to_string(), rec)),
                Err(e) => tracing::warn!(
                    domain = %domain,
                    error = %e,
                    "cert store: malformed enrollment object — this domain will not be routed"
                ),
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}

/// Reading a cert record fails **closed but quiet**: the resolver's trait can
/// only say present-or-absent, so a backend error is logged here and reported as
/// absent, which the resolver turns into a fail-closed `ClusterNotFound`. The
/// log line is what tells an operator "the bucket is down" apart from "no cert
/// for that domain" — do not remove it in favour of the silent `Option`.
impl ClusterSecretStore for ObjectCertStore {
    fn get_secret(&self, name: &str) -> Option<SecretRecord> {
        match self.read_secret(name) {
            Ok(rec) => rec,
            Err(e) => {
                tracing::warn!(
                    secret = %name,
                    issuer = %self.issuer,
                    error = %e,
                    "object cert store read failed; treating as absent (fail-closed)"
                );
                None
            }
        }
    }
}

/// Read cluster secrets from `primary`, falling back to `fallback` on a miss.
///
/// Production shape is `LayeredSecretStore::new(state_machine, object_cert_store)`:
/// raft answers everything it has — including the fleet-wide wildcard cert, which
/// is one KB-scale record and exactly what raft was sized for — and per-domain
/// TLS material, which raft deliberately never holds, comes from the object
/// store. The order matters: raft is local and synchronous, so the common case
/// costs no network at all, and a domain migrated *into* raft (an operator
/// pinning one cert) shadows the object store rather than racing it.
pub struct LayeredSecretStore<P, F> {
    primary: P,
    fallback: F,
}

impl<P, F> LayeredSecretStore<P, F> {
    pub fn new(primary: P, fallback: F) -> Self {
        Self { primary, fallback }
    }
}

impl<P: ClusterSecretStore, F: ClusterSecretStore> ClusterSecretStore for LayeredSecretStore<P, F> {
    fn get_secret(&self, name: &str) -> Option<SecretRecord> {
        self.primary
            .get_secret(name)
            .or_else(|| self.fallback.get_secret(name))
    }
}

impl<S: ClusterSecretStore + ?Sized> ClusterSecretStore for Arc<S> {
    fn get_secret(&self, name: &str) -> Option<SecretRecord> {
        (**self).get_secret(name)
    }
}

/// An absent store is a store that holds nothing.
///
/// This is what lets the production call site layer unconditionally —
/// `LayeredSecretStore::new(state_machine, state.cert_store.clone())` — instead
/// of branching on `Option` and building two differently-typed resolvers. An
/// unconfigured node then takes exactly the pre-R779 path, one `Option::is_none`
/// short of it.
impl<S: ClusterSecretStore> ClusterSecretStore for Option<S> {
    fn get_secret(&self, name: &str) -> Option<SecretRecord> {
        self.as_ref().and_then(|s| s.get_secret(name))
    }
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme_issuer::{cert_secret_name, key_secret_name};
    use std::sync::Mutex;
    use workload_spec::secrets::SecretAccess;
    use yah_object_store::InMemoryObjectStore;

    const LE: &str = "https://acme-v02.api.letsencrypt.org/directory";

    fn store() -> (Arc<InMemoryObjectStore>, ObjectCertStore) {
        let mem = Arc::new(InMemoryObjectStore::new());
        let certs = ObjectCertStore::new(mem.clone(), LE);
        (mem, certs)
    }

    fn rec(body: &[u8]) -> SecretRecord {
        SecretRecord {
            ciphertext: body.to_vec(),
            nonce: vec![0u8; 12],
            updated_at: 1_700_000_000,
            access: SecretAccess::AllowAny,
            digest: None,
        }
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn issuer_key_is_the_directory_host() {
        assert_eq!(issuer_key(LE), "acme-v02.api.letsencrypt.org");
        assert_eq!(
            issuer_key("https://acme-staging-v02.api.letsencrypt.org/directory"),
            "acme-staging-v02.api.letsencrypt.org"
        );
        // Two CAs must not collapse into one key space — DECISION 3 keeps a
        // second CA as overflow, and both may hold a cert for one domain.
        assert_ne!(issuer_key(LE), issuer_key("https://acme.zerossl.com/v2/DV90"));
    }

    #[test]
    fn issuer_key_sanitises_to_one_path_segment() {
        let k = issuer_key("https://ca.example.com:8443/acme/dir");
        assert!(!k.contains('/'), "issuer key must be one segment: {k}");
        assert_eq!(k, "ca.example.com-8443");
        assert_eq!(issuer_key(""), "unknown-issuer");
    }

    #[test]
    fn object_key_maps_only_tls_names() {
        let i = "le";
        assert_eq!(
            object_key(i, &cert_secret_name("a.example.com")),
            Some("certs/le/a.example.com/cert.sealed".to_string())
        );
        assert_eq!(
            object_key(i, &key_secret_name("a.example.com")),
            Some("certs/le/a.example.com/key.sealed".to_string())
        );
        // A general cluster secret is never sought in the object store.
        assert_eq!(object_key(i, "registry/dockerhub"), None);
        assert_eq!(object_key(i, "tls/a.example.com/account"), None);
        assert_eq!(object_key(i, "tls//cert"), None);
    }

    #[test]
    fn object_key_refuses_a_traversing_domain() {
        // `tls/../../etc/cert` must not address an object outside the prefix.
        assert_eq!(object_key("le", "tls/../../etc/cert"), None);
        assert_eq!(object_key("le", "tls/a/../b/cert"), None);
    }

    #[test]
    fn write_then_read_round_trips_the_sealed_record() {
        let (_mem, certs) = store();
        let name = cert_secret_name("a.example.com");
        let original = rec(b"sealed-chain");
        certs.write_secret(&name, &original).unwrap();
        assert_eq!(certs.read_secret(&name).unwrap(), Some(original.clone()));
        // And through the resolver's trait, which is how it is actually read.
        assert_eq!(certs.get_secret(&name), Some(original));
    }

    #[test]
    fn the_object_body_is_ciphertext_only() {
        let (mem, certs) = store();
        certs
            .write_secret(&key_secret_name("a.example.com"), &rec(b"sealed-key-bytes"))
            .unwrap();
        let raw = mem
            .get("certs/acme-v02.api.letsencrypt.org/a.example.com/key.sealed")
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&raw);
        // The record serialises its ciphertext as a byte array; what must never
        // appear is a PEM header, i.e. plaintext key material.
        assert!(!text.contains("BEGIN"), "object body must hold no PEM: {text}");
        assert!(text.contains("ciphertext"));
    }

    #[test]
    fn writing_a_non_tls_name_is_refused() {
        let (mem, certs) = store();
        let err = certs.write_secret("registry/dockerhub", &rec(b"x")).unwrap_err();
        assert!(matches!(err, CertStoreError::NotCertMaterial { .. }), "got {err:?}");
        assert!(mem.keys().is_empty(), "nothing may be written under a bad name");
    }

    #[test]
    fn a_malformed_object_is_an_error_not_a_miss() {
        // The dangerous failure: a corrupt cert object read as "no cert yet",
        // which would order a replacement on every boot.
        let (mem, certs) = store();
        mem.put(
            "certs/acme-v02.api.letsencrypt.org/a.example.com/cert.sealed",
            b"{ not json".to_vec(),
        )
        .unwrap();
        let err = certs
            .read_secret(&cert_secret_name("a.example.com"))
            .unwrap_err();
        assert!(matches!(err, CertStoreError::Malformed { .. }), "got {err:?}");
    }

    #[test]
    fn domains_lists_only_domains_with_a_cert() {
        let (mem, certs) = store();
        certs.write_secret(&cert_secret_name("b.example.com"), &rec(b"c")).unwrap();
        certs.write_secret(&key_secret_name("b.example.com"), &rec(b"k")).unwrap();
        certs.write_secret(&cert_secret_name("a.example.com"), &rec(b"c")).unwrap();
        // Mid-issuance: key + claim but no cert. Not servable, so not routable.
        certs.write_secret(&key_secret_name("z.example.com"), &rec(b"k")).unwrap();
        certs.claim_issuance("z.example.com", "node-1", at(100)).unwrap();
        // Another issuer's objects are not this issuer's route table.
        mem.put("certs/acme.zerossl.com/q.example.com/cert.sealed", b"{}".to_vec())
            .unwrap();

        assert_eq!(
            certs.domains().unwrap(),
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
    }

    #[test]
    fn write_pair_writes_the_key_before_the_cert() {
        // renewal-due is gated off the CERT record, so the cert must land last:
        // a partial failure has to leave the cert stale (re-issue heals) rather
        // than fresh-against-a-stale-key (TLS failure until someone notices).
        struct OrderRecording(Mutex<Vec<String>>);
        impl ObjectStore for OrderRecording {
            fn put(&self, key: &str, _data: Vec<u8>) -> Result<(), yah_object_store::Error> {
                self.0.lock().unwrap().push(key.to_string());
                Ok(())
            }
            fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, yah_object_store::Error> {
                Ok(None)
            }
            fn delete(&self, _key: &str) -> Result<(), yah_object_store::Error> {
                Ok(())
            }
            fn list_prefix(&self, _p: &str) -> Result<Vec<String>, yah_object_store::Error> {
                Ok(vec![])
            }
        }

        let rec_store = Arc::new(OrderRecording(Mutex::new(Vec::new())));
        let certs = ObjectCertStore::new(rec_store.clone(), LE);
        certs
            .write_pair(
                &cert_secret_name("a.example.com"),
                &key_secret_name("a.example.com"),
                &rec(b"c"),
                &rec(b"k"),
            )
            .unwrap();

        let order = rec_store.0.lock().unwrap().clone();
        assert_eq!(
            order,
            vec![
                "certs/acme-v02.api.letsencrypt.org/a.example.com/key.sealed".to_string(),
                "certs/acme-v02.api.letsencrypt.org/a.example.com/cert.sealed".to_string(),
            ]
        );
    }

    #[test]
    fn cert_store_config_is_off_without_a_bucket() {
        let none = |_: &str| None;
        assert_eq!(CertStoreConfig::parse(none).unwrap(), None);
    }

    #[test]
    fn cert_store_config_reads_bucket_account_and_endpoint() {
        let cfg = CertStoreConfig::parse(|k| match k {
            BUCKET_ENV => Some(" yah-certs ".to_string()),
            ACCOUNT_ID_ENV => Some("acct123".to_string()),
            ENDPOINT_ENV => Some("http://127.0.0.1:9000".to_string()),
            _ => None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(cfg.bucket, "yah-certs");
        assert_eq!(cfg.account_id, "acct123");
        assert_eq!(cfg.endpoint.as_deref(), Some("http://127.0.0.1:9000"));
    }

    #[test]
    fn delete_domain_removes_cert_key_and_claim() {
        let (mem, certs) = store();
        certs.write_secret(&cert_secret_name("a.example.com"), &rec(b"c")).unwrap();
        certs.write_secret(&key_secret_name("a.example.com"), &rec(b"k")).unwrap();
        certs.claim_issuance("a.example.com", "node-1", at(100)).unwrap();
        certs.delete_domain("a.example.com").unwrap();
        assert!(mem.keys().is_empty(), "left over: {:?}", mem.keys());
        // Idempotent.
        certs.delete_domain("a.example.com").unwrap();
    }

    #[test]
    fn one_claim_wins_and_the_loser_is_told_who_holds_it() {
        let (_mem, certs) = store();
        let won = certs.claim_issuance("a.example.com", "node-1", at(1_000)).unwrap();
        assert_eq!(won.holder, "node-1");

        let err = certs
            .claim_issuance("a.example.com", "node-2", at(1_060))
            .unwrap_err();
        match err {
            CertStoreError::Claimed { holder, remaining_secs, .. } => {
                assert_eq!(holder, "node-1");
                assert_eq!(remaining_secs, CLAIM_TTL.as_secs() - 60);
            }
            other => panic!("expected Claimed, got {other:?}"),
        }
    }

    #[test]
    fn an_expired_claim_is_stolen() {
        let (_mem, certs) = store();
        certs.claim_issuance("a.example.com", "dead-node", at(1_000)).unwrap();
        let after = 1_000 + CLAIM_TTL.as_secs();
        let stolen = certs
            .claim_issuance("a.example.com", "node-2", at(after))
            .unwrap();
        assert_eq!(stolen.holder, "node-2");
        assert_eq!(stolen.acquired_at, after);
    }

    #[test]
    fn a_released_claim_is_immediately_reclaimable() {
        let (_mem, certs) = store();
        certs.claim_issuance("a.example.com", "node-1", at(1_000)).unwrap();
        certs.release_issuance("a.example.com").unwrap();
        let re = certs.claim_issuance("a.example.com", "node-2", at(1_001)).unwrap();
        assert_eq!(re.holder, "node-2");
    }

    #[test]
    fn a_cooled_down_domain_is_not_retried_when_the_ordinary_ttl_lapses() {
        // R779: the failure backoff IS the claim, written with a longer TTL. The
        // point of the test is the gap — a domain whose order just failed must
        // still be untouchable at the moment an ordinary claim would have
        // expired, or every node re-orders it every CLAIM_TTL and burns Let's
        // Encrypt's 5-failures-per-hour-per-identifier budget in minutes.
        let (_mem, certs) = store();
        certs.claim_issuance("a.example.com", "node-1", at(1_000)).unwrap();
        certs
            .cool_down_issuance("a.example.com", "node-1", at(1_010), Duration::from_secs(3600))
            .unwrap();

        let just_past_the_ordinary_ttl = 1_010 + CLAIM_TTL.as_secs() + 1;
        let err = certs
            .claim_issuance("a.example.com", "node-2", at(just_past_the_ordinary_ttl))
            .unwrap_err();
        assert!(
            matches!(err, CertStoreError::Claimed { ref holder, .. } if holder == "node-1"),
            "still parked, and it says who parked it: {err}"
        );

        // And it does free itself: a permanently broken tenant domain retries on
        // a human timescale rather than never.
        let after_cooldown = 1_010 + 3600;
        let retry = certs
            .claim_issuance("a.example.com", "node-2", at(after_cooldown))
            .unwrap();
        assert_eq!(retry.holder, "node-2");
    }

    #[test]
    fn a_future_dated_claim_is_not_expired() {
        // Clock skew between nodes must not read as "stealable now" — that is
        // the one shape where two nodes would both place an order.
        let c = IssuanceClaim {
            holder: "node-1".into(),
            acquired_at: 2_000,
            ttl_secs: 600,
        };
        assert!(!c.is_expired(1_000));
        assert!(!c.is_expired(2_599));
        assert!(c.is_expired(2_600));
    }

    struct FakeRaft(Vec<(String, SecretRecord)>);
    impl ClusterSecretStore for FakeRaft {
        fn get_secret(&self, name: &str) -> Option<SecretRecord> {
            self.0.iter().find(|(n, _)| n == name).map(|(_, r)| r.clone())
        }
    }

    #[test]
    fn layered_prefers_raft_and_falls_back_to_the_object_store() {
        let (_mem, certs) = store();
        certs
            .write_secret(&cert_secret_name("tenant.example.com"), &rec(b"from-r2"))
            .unwrap();
        let raft = FakeRaft(vec![(
            cert_secret_name("yah.dev"),
            rec(b"from-raft"),
        )]);
        let layered = LayeredSecretStore::new(raft, certs);

        // The fleet wildcard still comes from raft, unchanged.
        assert_eq!(
            layered.get_secret(&cert_secret_name("yah.dev")).unwrap().ciphertext,
            b"from-raft".to_vec()
        );
        // A per-domain cert raft never held comes from the object store.
        assert_eq!(
            layered
                .get_secret(&cert_secret_name("tenant.example.com"))
                .unwrap()
                .ciphertext,
            b"from-r2".to_vec()
        );
        // A miss in both stays a miss — the resolver turns it into a
        // fail-closed ClusterNotFound.
        assert_eq!(layered.get_secret(&cert_secret_name("nope.example.com")), None);
    }

    #[test]
    fn raft_shadows_the_object_store_for_the_same_name() {
        let (_mem, certs) = store();
        let name = cert_secret_name("pinned.example.com");
        certs.write_secret(&name, &rec(b"from-r2")).unwrap();
        let layered = LayeredSecretStore::new(FakeRaft(vec![(name.clone(), rec(b"pinned"))]), certs);
        assert_eq!(layered.get_secret(&name).unwrap().ciphertext, b"pinned".to_vec());
    }

    // ── Enrollment ───────────────────────────────────────────────────────────

    fn backend(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn enrollment(port: u16) -> Enrollment {
        Enrollment::new(backend(port), at(1_700_000_000))
    }

    #[test]
    fn enroll_then_list_round_trips_and_sorts() {
        let (_mem, certs) = store();
        certs.enroll("b.example.com", &enrollment(8444)).unwrap();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        let enrolled = certs.enrolled().unwrap();
        assert_eq!(
            enrolled.iter().map(|(d, _)| d.as_str()).collect::<Vec<_>>(),
            vec!["a.example.com", "b.example.com"]
        );
        assert_eq!(enrolled[0].1.tls_backend, backend(8443));
        assert_eq!(certs.enrollment("b.example.com").unwrap(), Some(enrollment(8444)));
        assert_eq!(certs.enrollment("nope.example.com").unwrap(), None);
    }

    #[test]
    fn enrollment_is_not_scoped_to_an_issuer() {
        // A domain enrolled once stays routable if DECISION 3's overflow moves
        // its cert to a second CA — the key must carry no issuer segment.
        let mem = Arc::new(InMemoryObjectStore::new());
        let le = ObjectCertStore::new(mem.clone(), LE);
        let other = ObjectCertStore::new(mem.clone(), "https://acme.zerossl.com/v2/DV90");
        le.enroll("a.example.com", &enrollment(8443)).unwrap();
        assert_eq!(other.enrolled().unwrap().len(), 1);
        assert_eq!(mem.keys(), vec!["enrolled/a.example.com".to_string()]);
    }

    #[test]
    fn re_enrolling_the_same_backend_is_a_no_op_and_a_different_one_is_refused() {
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        // Same backend, later stamp: a replayed config, not a change.
        certs
            .enroll(
                "a.example.com",
                &Enrollment::new(backend(8443), at(1_700_009_999)),
            )
            .unwrap();
        // A different backend is two tenants claiming one name.
        let err = certs.enroll("a.example.com", &enrollment(8444)).unwrap_err();
        assert!(matches!(err, CertStoreError::AlreadyEnrolled { .. }), "got {err:?}");
        assert_eq!(
            certs.enrollment("a.example.com").unwrap().unwrap().tls_backend,
            backend(8443),
            "a refused enroll must not have overwritten the live backend"
        );
    }

    #[test]
    fn unenroll_drops_the_route_but_keeps_the_cert() {
        let (_mem, certs) = store();
        let cert = cert_secret_name("a.example.com");
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        certs.write_secret(&cert, &rec(b"sealed-chain")).unwrap();

        certs.unenroll("a.example.com").unwrap();
        assert!(certs.enrolled().unwrap().is_empty());
        // Re-enrolling must not have to spend an ACME order to undo a typo.
        assert!(certs.read_secret(&cert).unwrap().is_some());
        certs.unenroll("a.example.com").unwrap(); // idempotent
    }

    #[test]
    fn enrollment_refuses_a_traversing_domain() {
        let (mem, certs) = store();
        for bad in ["", "../../etc", "a/b"] {
            assert!(
                matches!(
                    certs.enroll(bad, &enrollment(8443)),
                    Err(CertStoreError::InvalidDomain { .. })
                ),
                "{bad:?} must be refused"
            );
            assert!(matches!(
                certs.enrollment(bad),
                Err(CertStoreError::InvalidDomain { .. })
            ));
        }
        assert!(mem.keys().is_empty(), "nothing may be written under a bad domain");
    }

    #[test]
    fn a_malformed_enrollment_is_skipped_not_fatal() {
        // One corrupt object must cost exactly one domain's route, not the
        // whole render — a listing error would freeze every tenant's routing.
        let (mem, certs) = store();
        certs.enroll("good.example.com", &enrollment(8443)).unwrap();
        mem.put("enrolled/bad.example.com", b"{not json".to_vec()).unwrap();
        let enrolled = certs.enrolled().unwrap();
        assert_eq!(
            enrolled.iter().map(|(d, _)| d.as_str()).collect::<Vec<_>>(),
            vec!["good.example.com"]
        );
        // Asked about directly, though, it is an error and not "not enrolled".
        assert!(matches!(
            certs.enrollment("bad.example.com"),
            Err(CertStoreError::Malformed { .. })
        ));
    }

    #[test]
    fn an_enrolled_domain_is_routable_before_it_has_a_cert() {
        // The deadlock this set exists to break: on-demand TLS issues on the
        // first connection, so routing gated on a cert existing means the
        // connection never arrives and the cert never exists.
        let (_mem, certs) = store();
        certs.enroll("new.example.com", &enrollment(8443)).unwrap();
        assert!(certs.domains().unwrap().is_empty(), "no cert yet");
        assert_eq!(
            render_demux_routes(certs.enrolled().unwrap().iter().map(|(d, e)| (d.as_str(), e))),
            "new.example.com=127.0.0.1:8443"
        );
    }

    #[test]
    fn rendered_routes_are_sorted_and_parse_as_demux_routes() {
        let set = [
            ("b.example.com".to_string(), enrollment(8444)),
            ("a.example.com".to_string(), enrollment(8443)),
        ];
        let rendered = render_demux_routes(set.iter().map(|(d, e)| (d.as_str(), e)));
        assert_eq!(
            rendered,
            "a.example.com=127.0.0.1:8443,b.example.com=127.0.0.1:8444"
        );
        // The demux's own parser shape: `host=addr` pairs, comma-separated,
        // every addr a SocketAddr. Checked here because the two crates are in
        // different workspaces and nothing else holds them to one format.
        for entry in rendered.split(',') {
            let (host, addr) = entry.split_once('=').expect("host=addr");
            assert!(!host.is_empty());
            addr.parse::<SocketAddr>().expect("backend parses as a SocketAddr");
        }
        assert_eq!(render_demux_routes(std::iter::empty()), "");
    }
}
