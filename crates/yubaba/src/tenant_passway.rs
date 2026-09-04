//! Arming one cold passway per enrolled custom domain (R852-F1 / W267
//! §"Free-tier ingress at 10k domains").
//!
//! [`crate::demux_routes`] publishes the enrollment set as the SNI demux's
//! `host=addr` table — it tells `:443` *where* to splice a tenant's bytes.
//! Nothing was listening at the other end of that splice. This module is the
//! missing half: sweep the same set, and for each domain ask kamaji to hold its
//! [`Enrollment::tls_backend`] socket and fork a
//! [`passway`](workload_spec::TenantPasswayWorkload) on the first connection.
//!
//! ```text
//!   enrolled/<domain>  ──┬─▶ demux_routes  ──▶ routes file ──▶ passway-demux :443
//!    (cert_store)        │                                        │ splice
//!                        └─▶ THIS MODULE   ──▶ kamaji Deploy ──▶ held socket
//!                                 │                                │ fork on 1st conn
//!                                 │ unseal (R852-F3)               ▼
//!                                 ▼                         cold passway (self-reaps)
//!                      <cert_dir>/<domain>/tls.{crt,key} ──────────┘ reads
//! ```
//!
//! ## Materialize, then arm
//!
//! The sealed pair lives in the object store; the forked passway reads two files
//! off the node. [`materialize`] closes that gap once per sweep, *before*
//! [`plan`] decides what to deploy, and a domain whose pair is not on disk is
//! deliberately left unarmed — arming it would fork a process per inbound
//! connection, each dying on a missing `PASSWAY_TLS_CERT`. Pruning runs last,
//! after the stop set, so a tenant's private key leaves the node only once
//! nothing holds a socket for it.
//!
//! [`tls_paths`] is the single renderer of that layout: [`declare`] tells the
//! workload where to read, [`materialize`] writes there, and neither formats a
//! path itself.
//!
//! ## One set, two consumers, zero re-derivation
//!
//! Both sweeps read `enrolled()` and both key off `tls_backend`, so a domain
//! becomes routable and servable from **one** write. That is the property worth
//! protecting: a route table and a workload set derived from different sources
//! drift, and the drift shows up as a domain that resolves, handshakes and
//! hangs — the hardest ingress failure to attribute. `tls_backend` is a
//! [`SocketAddr`](std::net::SocketAddr) in the record and reaches kamaji as the
//! string it renders to, which is also passway's `PASSWAY_LISTEN`; see
//! [`workload_spec::TenantPasswayWorkload`] for why that string may not be
//! restated anywhere.
//!
//! ## Fail-closed means fail-stale here too
//!
//! Same posture as [`crate::demux_routes`], for the same reason and with one
//! addition:
//!
//! - **A listing failure reconciles nothing.** Live passways keep serving.
//! - **An empty listing stops nothing.** A successful listing of an empty
//!   bucket and a bucket pointed at the wrong prefix are indistinguishable, and
//!   one of them is "tear down every tenant's front door". Unenrolling the last
//!   domain therefore leaves its passway armed until an operator stops it —
//!   which is the right way round.
//! - **Only passways this module owns are ever stopped.** The stop set is
//!   filtered to idents carrying [`IDENT_PREFIX`], so a sweep can never reap a
//!   bundle, a container, or anything else sharing the node.
//!
//! ## A sweep re-declares only what changed
//!
//! `Deploy` is not a no-op when nothing moved: kamaji's JIT tier is idempotent
//! by *tearing down*, releasing the held listen socket before binding fresh. So
//! [`plan`] compares each domain's declaration against the digest kamaji
//! reports it armed that domain with ([`kamaji_proto::WorkloadEntry::spec_digest`])
//! and leaves an unchanged one alone — the steady state of a 10k-domain node is
//! a sweep that binds nothing. Unknown ("kamaji has no record") always
//! redeploys, so the failure direction is a redundant rebind, never a change
//! that silently never lands. See [`plan`] for the full argument.
//!
//! @yah:ticket(R852-F3, "Materialize each enrolled domain's sealed cert pair onto the node the cold passway reads it from")
//! @yah:status(review)
//! @yah:at(2026-09-03T18:52:54Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R852)
//! @yah:gotcha("Until this lands a per-tenant passway forks and fails to read PASSWAY_TLS_CERT. R852-F1's declaration points at <cert_dir>/<domain>/tls.crt and tls.key and nothing writes those files, so the chain is complete except for its last link. The socket IS armed and the demux DOES route — the symptom is a TLS handshake failing at the node, not a domain that fails to resolve.")
//! @yah:next("WHY THIS IS SEPARABLE FROM R852-F1 RATHER THAN UNFINISHED INSIDE IT: the pair is sealed (AES-256-GCM, W273 envelope) in cert_store at certs/<issuer>/<domain>/{cert,key}.sealed, so materializing means unsealing with the KEK — which goes through the R706/W294 SecretAccess model in secrets.rs, not through a file copy. SecretRecord.access defaults to the EMPTY allow-list (admits nobody), so the open question is what rule a per-tenant passway's own cert carries and who stamps it. That is an access-model decision in a module R852-F1 does not own.")
//! @yah:next("WHERE TO PUT IT: yubaba::tenant_passway::reconcile_once already lists enrolled() once per sweep, so materializing there gives the ordering you want for free — write the pair, THEN arm the socket, so a passway is never forked at a cert that is not on disk. Prune on unenroll in the same pass the stop set is applied. Paths come from TenantPasswayConfig::cert_dir (YUBABA_TENANT_PASSWAY_CERT_DIR, default workload_spec::DEFAULT_TENANT_PASSWAY_CERT_DIR = /run/yah/passway/tenants); the layout <dir>/<domain>/tls.crt + tls.key is fixed by TenantPasswayTls::for_domain and by tenant_passway::declare, which must stay the single renderer.")
//! @yah:handoff("LANDED — the chain is complete end to end. `tenant_passway::materialize` unseals each enrolled domain's stored pair onto <cert_dir>/<domain>/tls.{crt,key} once per sweep, BEFORE `plan` decides what to arm; `plan` now takes `Materialized::servable` so a domain with no pair on disk is deliberately NOT armed (arming forks a process per inbound connection, each dying on PASSWAY_TLS_CERT); `prune` runs last, after the stop set. THE ACCESS DECISION, which is what the ticket was filed to make: the rule is stamped PER DOMAIN AT SEAL TIME. `tenant_passway::grant` widens the operator's configured rule to also admit `passway.<domain>` and `domain_issuer::store_issued` seals through it — an allow-list written in advance cannot name one entry per tenant at 10k domains, and AllowAny over-answers it by making every tenant private key a bearer secret. Same shape as R555-F5's forge-<uuid>, same answer. `grant` and `consumer` are both `workload_ident(domain)` so the authorized identity and the deployed identity cannot disagree, including the hashed form for a domain past 55 chars. A pair sealed under a narrower pre-existing rule is refused loudly rather than silently widened.")
//! @yah:verify("cargo test -p yubaba --lib tenant_passway — 15 pass (9 new). cargo test -p yubaba --lib — 619 pass / 0 fail, which is the real check on the secrets.rs extraction: every existing ClusterResolver and domain_issuer test is green through the refactored path. cargo check --workspace --all-targets from oss/yubaba — 0 errors (2 pre-existing unused-import warnings in a peer's crates/cloud/src/reconciler/mesofact_static.rs, not mine). cargo check -p cloud-client --all-targets from the repo root — clean, that being the root-workspace consumer of the yubaba crate. NOTE: yubaba is not a root-workspace member — `cargo test -p yubaba` from the repo root errors 'requires dev-dependencies and is not a member of the workspace'; run it from oss/yubaba. NOT RUN: `cargo test -p yubaba --test main`, whose raft tests are a known load-sensitive flake on this box (recorded on R852-F2); nothing under tests/ references tenant_passway, verified by grep, and --all-targets compiles them.")
//! @yah:gotcha("DISCOVERED WHILE HERE, FILED AS R852-B4, NOT FIXED: `reconcile_once` puts every enrolled+servable domain in `Plan::deploy` every sweep, and kamaji's `deploy_on_demand` (oss/kamaji/crates/kamaji/src/jit.rs:172) is idempotent by unconditionally TEARING DOWN first — so a 10k-domain node unbinds and rebinds 10k sockets every 300 s and kills any warm passway mid-idle-TTL. The fix needs a comparable spec digest on `WorkloadEntry` (oss/kamaji/crates/kamaji-proto/src/messages.rs), which carries only id/state/pid/mesh_ident/bound_ports — a kamaji-proto change, outside this ticket's blast radius. Read off source, not measured on a node.")
//! @yah:cleanup("Materialization costs two object-store GETs per enrolled domain per sweep, unconditionally, because noticing a renewal requires reading the record. Writes are already skipped when content is unchanged, so the steady state is reads-only, but a conditional GET (ETag / If-None-Match) on the sealed records would cut the network half too. Not done: it needs a `read_secret` variant that can return 'unmodified', which is a cert_store surface change.")
//! @yah:gotcha("SUPERSEDED 2026-09-03: the \"FILED AS R852-B4, NOT FIXED\" gotcha above is no longer current — R852-B4 shipped and is in review. WorkloadEntry now carries `spec_digest` (kamaji-proto V5) and tenant_passway::plan skips a domain whose live digest equals declare()'s, so a sweep re-declares only what changed. Read B4 before acting on that bullet.")

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kamaji::sibling::{KamajiClient, KamajiSibling};
use kamaji_proto::{spec_digest, SpecDigest, WorkloadId};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use workload_spec::secrets::{SecretAccess, SecretConsumer, WorkloadMatch};
use workload_spec::{Millis, TenantPasswayTls, TenantPasswayWorkload, Workload};
use zeroize::Zeroizing;

use crate::acme_issuer::{cert_secret_name, key_secret_name};
use crate::cert_store::{CertStoreError, Enrollment, ObjectCertStore};
use crate::secrets::{load_cluster_kek, open_cluster_secret, CLUSTER_KEK_PATH};

/// Env key naming the node directory each cold passway's log capture lands in.
/// Its presence turns the reconciler on — a node that is not a front door
/// should not be arming tenant sockets.
pub const STATE_DIR_ENV: &str = "YUBABA_TENANT_PASSWAY_STATE_DIR";
/// Env key overriding the sweep cadence.
pub const SWEEP_SECS_ENV: &str = "YUBABA_TENANT_PASSWAY_SWEEP_SECS";
/// Env key overriding the per-passway idle TTL, in seconds. `0` means **never
/// reap** — a resident per-tenant passway, which is what the free tier exists
/// to avoid; see [`TenantPasswayWorkload::idle_ttl`].
pub const IDLE_TTL_SECS_ENV: &str = "YUBABA_TENANT_PASSWAY_IDLE_TTL_SECS";
/// Env key overriding the node directory holding materialized cert pairs.
pub const CERT_DIR_ENV: &str = "YUBABA_TENANT_PASSWAY_CERT_DIR";
/// Env key overriding the node-local cluster KEK the sealed pairs are opened
/// with. Defaults to [`CLUSTER_KEK_PATH`], the same file every other consumer of
/// cluster secrets on the node reads — a *different* key here would decrypt
/// nothing the issuer sealed.
pub const KEK_PATH_ENV: &str = "YUBABA_TENANT_PASSWAY_KEK_PATH";

/// Permission bits on a materialized private key: owner read/write only.
///
/// The public half is written with the same bits rather than something laxer.
/// The two files live in one directory and are rotated together, and a mode that
/// varies between them is one more thing to get wrong for no gain — nothing on
/// the node needs to read a tenant's cert chain except the passway that also
/// needs its key.
const PAIR_MODE: u32 = 0o600;

/// Permission bits on `<cert_dir>` and each `<cert_dir>/<domain>`.
const DIR_MODE: u32 = 0o700;

/// Default seconds between sweeps — the same 5 minutes, and the same argument,
/// as [`crate::demux_routes::DEFAULT_SWEEP_SECS`]: a sweep is one `list_prefix`
/// plus a `get` per domain, and enrollment changes when a human registers a
/// name.
pub const DEFAULT_SWEEP_SECS: u64 = 300;

/// Default idle TTL before a cold passway self-reaps.
///
/// Long enough that a browser's follow-up requests for a page's assets all hit
/// the warm process, short enough that a domain nobody is visiting costs
/// nothing but the held fd within a minute.
pub const DEFAULT_IDLE_TTL_SECS: u64 = 60;

/// Ident prefix every workload this module owns carries. The stop set is
/// filtered on it, so nothing else on the node can be reaped by a sweep.
pub const IDENT_PREFIX: &str = "passway.";

/// The kamaji workload identity for `domain` — also its mesh ident, its
/// socket-custody key, and its log-capture directory name.
///
/// `passway.<domain>` is the normal form: the prefix plus a dot-separated DNS
/// name is itself a dot-separated DNS name, which is exactly what
/// `workload_spec::validate`'s mesh-ident check accepts, and it is injective —
/// two domains cannot produce one ident.
///
/// A [`MeshIdent`](workload_spec::MeshIdent) is capped at 63 characters, so a
/// domain past 55 falls back to `passway.<16 hex of sha256(domain)>`. The
/// obvious alternative — truncating — is the one shape that must not be used
/// here: two tenants sharing an identity share a *socket custodian entry*, so
/// the second deploy tears the first tenant's front door down. A hash is
/// illegible in a log; a collision is an outage.
pub fn workload_ident(domain: &str) -> String {
    let plain = format!("{IDENT_PREFIX}{domain}");
    if plain.len() <= 63 {
        return plain;
    }
    let digest = Sha256::digest(domain.as_bytes());
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{IDENT_PREFIX}{hex}")
}

/// How this node arms tenant passways.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPasswayConfig {
    /// Node directory holding each domain's materialized cert pair, as
    /// `<dir>/<domain>/{tls.crt,tls.key}`.
    pub cert_dir: String,
    /// Node-local cluster KEK that opens the sealed pairs (R852-F3).
    pub kek_path: PathBuf,
    /// Idle TTL each passway self-reaps on. `None` = never reap.
    pub idle_ttl: Option<Millis>,
    /// Seconds between sweeps.
    pub sweep: Duration,
}

/// Parse the reconciler config from a `key -> value` lookup — a pure function
/// over the environment, same shape as
/// [`crate::demux_routes::parse_publisher_config`].
///
/// `Ok(None)` when [`STATE_DIR_ENV`] is unset: arming tenant sockets is opt-in.
pub fn parse_config(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<TenantPasswayConfig>, String> {
    match get(STATE_DIR_ENV) {
        Some(p) if !p.trim().is_empty() => {}
        _ => return Ok(None),
    }
    let sweep_secs = match get(SWEEP_SECS_ENV) {
        Some(v) => v
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{SWEEP_SECS_ENV}: expected a non-negative integer"))?,
        None => DEFAULT_SWEEP_SECS,
    };
    if sweep_secs == 0 {
        return Err(format!("{SWEEP_SECS_ENV} must be greater than zero"));
    }
    let idle_ttl_secs = match get(IDLE_TTL_SECS_ENV) {
        Some(v) => v
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{IDLE_TTL_SECS_ENV}: expected a non-negative integer"))?,
        None => DEFAULT_IDLE_TTL_SECS,
    };
    let cert_dir = get(CERT_DIR_ENV)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| workload_spec::DEFAULT_TENANT_PASSWAY_CERT_DIR.to_string());

    let kek_path = PathBuf::from(
        get(KEK_PATH_ENV)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| CLUSTER_KEK_PATH.to_string()),
    );

    Ok(Some(TenantPasswayConfig {
        cert_dir,
        kek_path,
        // Zero is the only way to say "never reap", because `Millis(0)` would
        // otherwise round up to a one-second TTL and silently make every
        // tenant's passway churn once a second.
        idle_ttl: (idle_ttl_secs > 0).then(|| Millis::from_secs(idle_ttl_secs)),
        sweep: Duration::from_secs(sweep_secs),
    }))
}

/// The declaration for one enrolled domain.
///
/// `upstreams` is left empty: this module knows *where the tenant's TLS
/// terminates*, not where their app runs. A passway with no backend answers 503
/// rather than refusing to start, so a domain is routable and issuable before
/// placement — which is the order onboarding actually happens in.
pub fn declare(domain: &str, enrollment: &Enrollment, cfg: &TenantPasswayConfig) -> Workload {
    Workload::TenantPassway(TenantPasswayWorkload {
        schema_version: workload_spec::SchemaVersion::V1,
        domain: domain.to_string(),
        // The enrollment's own address, rendered once. See the module doc.
        listen: enrollment.tls_backend.to_string(),
        upstreams: Vec::new(),
        tls: tls_paths(&cfg.cert_dir, domain),
        idle_ttl: cfg.idle_ttl,
        command: None,
        env: BTreeMap::new(),
    })
}

/// The pair of paths for `domain` under `cert_dir` — **the single renderer**.
///
/// [`declare`] states where the forked passway will *read* its cert from, and
/// [`materialize`] writes the files. Those are the two ends of one contract with
/// no shared type between them: the workload carries strings, the filesystem
/// carries paths, and a mismatch is a passway that starts, binds, and fails
/// every handshake looking for a file one directory over. So both ends call
/// this, and neither formats a path itself.
///
/// [`TenantPasswayTls::for_domain`] renders the same layout against the
/// compiled-in [`workload_spec::DEFAULT_TENANT_PASSWAY_CERT_DIR`]; this is its
/// configurable twin, which is why the trailing slash is trimmed here rather
/// than assumed away.
pub fn tls_paths(cert_dir: &str, domain: &str) -> TenantPasswayTls {
    let dir = cert_dir.trim_end_matches('/');
    TenantPasswayTls {
        cert: format!("{dir}/{domain}/tls.crt"),
        key: format!("{dir}/{domain}/tls.key"),
    }
}

/// The [`SecretConsumer`] identity a domain's own passway presents when its
/// sealed pair is opened (R706 / W294).
///
/// This is [`workload_ident`] again, and deliberately so: the thing being
/// authorized *is* the workload this module is about to arm, so the access check
/// and the kamaji deploy must not be able to disagree about who that is.
pub fn consumer(domain: &str) -> SecretConsumer {
    SecretConsumer::workload(workload_ident(domain))
}

/// Widen an issuer's configured [`SecretAccess`] rule to admit `domain`'s own
/// passway — the access-model decision R852-F3 exists to make.
///
/// ## Why the operator's list cannot answer this
///
/// `YUBABA_DOMAIN_ISSUER_CONSUMERS` names workloads *in advance*. A per-tenant
/// passway's name is [`workload_ident`]`(domain)`, one per enrolled domain, and
/// the free tier's target is 10k of them — so the rule that would admit them all
/// is either a 10k-entry list nobody maintains or
/// [`SecretAccess::AllowAny`], which turns 10k tenant private keys into bearer
/// secrets readable by anything that can reach the node. That is the same shape
/// as R555-F5's `forge-<uuid>` problem and it wants the same answer: the
/// identity is known at *seal* time, so stamp it then.
///
/// The issuer knows the domain when it seals, so each pair carries a rule that
/// admits exactly the one passway serving that domain — plus whatever the
/// operator configured, which is preserved rather than replaced. A pair sealed
/// before this existed is unaffected: [`SecretAccess::AllowAny`] already admits
/// the passway, and a narrower pre-existing rule that does not is refused
/// loudly at materialization rather than silently widened here.
///
/// [`SecretAccess::Recipes`] passes through unchanged, which means a passway
/// cannot read a recipe-ruled pair. That combination is unreachable today —
/// `parse_consumers` yields only `AllowAny` or `Workloads` — and forcing it to
/// work would mean inventing a union of two rule kinds the enum cannot express.
/// Failing closed on an impossible configuration is the right cost.
pub fn grant(base: &SecretAccess, domain: &str) -> SecretAccess {
    match base {
        SecretAccess::AllowAny | SecretAccess::Recipes(_) => base.clone(),
        SecretAccess::Workloads(entries) => {
            let mine = WorkloadMatch::workload(workload_ident(domain));
            let mut out = entries.clone();
            if !out.contains(&mine) {
                out.push(mine);
            }
            SecretAccess::Workloads(out)
        }
    }
}

// ── Materializing the pair (R852-F3) ─────────────────────────────────────────

/// What one materialization pass did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Materialized {
    /// Domains whose pair is on disk — the set that is safe to arm. Everything
    /// else is deliberately left unarmed; see [`materialize`].
    pub servable: BTreeSet<String>,
    /// Pairs written or rewritten this pass. Zero is the steady state.
    pub written: usize,
    /// Enrolled domains with no issued certificate yet. Not a failure: on-demand
    /// TLS enrols a domain *before* its first order, so this is the normal state
    /// of a name registered in the last few minutes.
    pub awaiting_cert: usize,
    /// Domains whose pair could not be materialized — unreadable bucket, refused
    /// access rule, bad KEK, failed write. Counted per domain and never fatal:
    /// one tenant's broken pair must not stop the other 9,999 being armed.
    pub failed: usize,
}

/// Unseal each enrolled domain's stored pair onto the node the cold passway
/// reads it from, and report which domains are servable as a result.
///
/// ## A domain with no cert on disk is not armed
///
/// The alternative — arm everything, let the fork fail — is worse than it
/// sounds. Arming means kamaji holds the fd and forks a passway *on every
/// connection*, so a domain whose cert is missing becomes a process spawn per
/// inbound TCP connection, all of them dying on `PASSWAY_TLS_CERT`. Skipping it
/// costs one counter and heals on the next sweep the moment the issuer lands the
/// pair. This is why [`plan`] takes [`Materialized::servable`] rather than
/// deriving the deploy set from the enrollment set alone.
///
/// ## Fail-closed, per domain, and never on a listing
///
/// Every per-domain failure is counted and skipped. The three that are *not*
/// interchangeable, and are therefore kept apart in the counters:
///
/// - **absent** — no cert record. Normal, expected, `awaiting_cert`.
/// - **unreadable** — the bucket errored. `failed`, because reporting an
///   unreachable store as "no cert issued yet" would make an outage look like a
///   slow tenant. This is why the records are read through
///   [`ObjectCertStore::read_secret`], whose `Result<Option<_>>` can tell those
///   apart, rather than through the `ClusterSecretStore` trait, whose `Option`
///   cannot.
/// - **refused** — the record's [`SecretAccess`] rule does not admit this
///   domain's passway. `failed`, with a warning naming the fix, because it means
///   a pair was sealed under a rule that predates [`grant`].
pub fn materialize(
    store: &ObjectCertStore,
    kek: &[u8; 32],
    cfg: &TenantPasswayConfig,
    enrolled: &[(String, Enrollment)],
) -> Materialized {
    let mut out = Materialized::default();

    // Once per sweep, not once per domain. `create_dir_all` would otherwise
    // leave the root at the umask default, and a world-listable root leaks the
    // list of every domain this node fronts even though each pair inside it is
    // unreadable.
    let root = Path::new(cfg.cert_dir.trim_end_matches('/'));
    if let Err(e) = std::fs::create_dir_all(root).and_then(|()| restrict_dir(root)) {
        warn!(dir = %root.display(), error = %e, "tenant passway: cert directory is unusable — nothing can be materialized this sweep");
        out.failed = enrolled.len();
        return out;
    }

    for (domain, _) in enrolled {
        let who = consumer(domain);
        let (cert_name, key_name) = (cert_secret_name(domain), key_secret_name(domain));

        let pair = match (store.read_secret(&cert_name), store.read_secret(&key_name)) {
            (Ok(Some(c)), Ok(Some(k))) => (c, k),
            // Half a pair is mid-issuance, not a failure: `write_pair` is
            // key-first/cert-last, so a torn write reads as "still due" and the
            // issuer's next sweep completes it.
            (Ok(_), Ok(_)) => {
                out.awaiting_cert += 1;
                continue;
            }
            (Err(e), _) | (_, Err(e)) => {
                out.failed += 1;
                warn!(domain = %domain, error = %e, "tenant passway: reading the sealed pair failed");
                continue;
            }
        };

        let cert = match open_cluster_secret(kek, &cert_name, &pair.0, &who) {
            Ok(bytes) => bytes,
            Err(e) => {
                out.failed += 1;
                warn!(
                    domain = %domain,
                    workload = %who.workload,
                    rule = %pair.0.access.summary(),
                    error = %e,
                    "tenant passway: opening the sealed cert failed — if this is a refusal, the \
                     pair was sealed under a rule that predates the per-domain grant and must be \
                     re-issued"
                );
                continue;
            }
        };
        // The node's plaintext copy of a tenant's private key. Zeroized on drop
        // for the same reason the issuer does it on the way in.
        let key = match open_cluster_secret(kek, &key_name, &pair.1, &who) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(e) => {
                out.failed += 1;
                warn!(domain = %domain, error = %e, "tenant passway: opening the sealed key failed");
                continue;
            }
        };

        match materialize_pair(cfg, domain, &cert, &key) {
            Ok(changed) => {
                if changed {
                    out.written += 1;
                    info!(domain = %domain, "tenant passway: materialized cert pair");
                }
                out.servable.insert(domain.clone());
            }
            Err(e) => {
                out.failed += 1;
                warn!(domain = %domain, error = %e, "tenant passway: writing the cert pair failed");
            }
        }
    }
    out
}

/// Write one domain's pair to the paths [`declare`] told the workload to read.
///
/// Returns whether anything changed on disk, so the steady state — 10k domains
/// whose certs are 30 days from renewal — costs two reads and no writes per
/// domain per sweep, and nothing observes a modification that did not happen.
fn materialize_pair(
    cfg: &TenantPasswayConfig,
    domain: &str,
    cert: &[u8],
    key: &[u8],
) -> std::io::Result<bool> {
    let tls = tls_paths(&cfg.cert_dir, domain);
    let (cert_path, key_path) = (PathBuf::from(&tls.cert), PathBuf::from(&tls.key));
    let dir = cert_path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("cert path {} has no parent directory", tls.cert),
        )
    })?;
    std::fs::create_dir_all(dir)?;
    restrict_dir(dir)?;

    // Key first, cert last, matching `ObjectCertStore::write_pair`. Nothing
    // gates off the on-disk pair the way renewal gates off the cert record, but
    // a torn write leaves this domain out of `servable` either way — it returns
    // `Err` and is not armed.
    let wrote_key = write_if_changed(&key_path, key)?;
    let wrote_cert = write_if_changed(&cert_path, cert)?;
    Ok(wrote_key || wrote_cert)
}

/// `chmod 0700`, but only when it is not already that.
///
/// The read-then-maybe-write matters at this call's frequency: it runs once per
/// enrolled domain per sweep, so an unconditional `set_permissions` is 10k
/// pointless metadata writes every five minutes on a directory tree that has not
/// changed since the last sweep.
fn restrict_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::metadata(dir)?.permissions();
    if perms.mode() & 0o777 == DIR_MODE {
        return Ok(());
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_MODE))
}

/// Write `content` at `path` unless it is already exactly that, via a
/// same-directory temp file and a rename.
///
/// Atomic because a passway can fork *while this runs*: a plain truncating write
/// gives the forked process a window in which it reads half a PEM, and the
/// failure it produces ("bad certificate") is indistinguishable from a genuinely
/// malformed cert. The temp file is created with [`PAIR_MODE`] rather than
/// chmod-ed afterwards, so a tenant's private key is never briefly readable by
/// anything else on the node.
fn write_if_changed(path: &Path, content: &[u8]) -> std::io::Result<bool> {
    if let Ok(existing) = std::fs::read(path) {
        if existing == content {
            return Ok(false);
        }
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "unnamed cert path"))?;
    // NOT `with_extension("tmp")` — that maps both `tls.crt` and `tls.key` onto
    // the same `tls.tmp`, so the two writes of one pair would race each other.
    let tmp = path.with_file_name(format!("{name}.tmp"));

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(PAIR_MODE)
        .open(&tmp)?;
    f.write_all(content)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    Ok(true)
}

/// Remove the materialized pair of every domain under `cert_dir` that is no
/// longer enrolled. Returns how many were removed.
///
/// **An empty `enrolled` prunes nothing**, exactly as an empty enrolled set
/// stops nothing in [`plan`] — a successful listing of an empty bucket and a
/// bucket pointed at the wrong prefix are the same observation, and one of them
/// is "delete every tenant's private key off this node".
///
/// Keyed off the directory listing rather than off [`Plan::stop`] because a stop
/// entry is a [`WorkloadId`], and [`workload_ident`] hashes a long domain — the
/// domain is not recoverable from it. Diffing the directory also cleans up a
/// domain whose passway was never armed.
pub fn prune(cfg: &TenantPasswayConfig, enrolled: &[(String, Enrollment)]) -> usize {
    if enrolled.is_empty() {
        return 0;
    }
    let keep: BTreeSet<&str> = enrolled.iter().map(|(d, _)| d.as_str()).collect();
    let root = Path::new(cfg.cert_dir.trim_end_matches('/'));
    let Ok(entries) = std::fs::read_dir(root) else {
        // No directory yet means nothing has been materialized. Not an error,
        // and not worth a warning every sweep on a node with no tenants.
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if keep.contains(name.as_str()) {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => {
                removed += 1;
                info!(domain = %name, "tenant passway: pruned the cert pair of an unenrolled domain");
            }
            Err(e) => warn!(domain = %name, error = %e, "tenant passway: pruning failed"),
        }
    }
    removed
}

/// What one sweep should do to the node.
///
/// `PartialEq` but not `Eq`: [`Workload`] is only `PartialEq` (a `WorkloadSpec`
/// reaches an `f64` through its resource limits), and a `Plan` is compared in
/// tests, never used as a key.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Plan {
    /// Domains to arm (or re-arm — `deploy_on_demand` is idempotent and tears
    /// down a predecessor before binding fresh, so a redeploy is how a changed
    /// backend address or TTL lands).
    pub deploy: Vec<(WorkloadId, Workload)>,
    /// Passways this module owns whose domain is no longer enrolled.
    pub stop: Vec<WorkloadId>,
    /// Domains already armed with **this exact declaration** — counted, not
    /// acted on (R852-B4). In the steady state this is every enrolled domain
    /// and the other two lists are empty.
    pub unchanged: usize,
}

impl Plan {
    /// Nothing to do.
    pub fn is_empty(&self) -> bool {
        self.deploy.is_empty() && self.stop.is_empty()
    }
}

/// One workload kamaji reports it is holding: its ident, and the digest of the
/// spec it was deployed with (`None` when kamaji has no record — see
/// [`kamaji_proto::WorkloadEntry::spec_digest`]).
///
/// A pair rather than the wire type so [`plan`] stays a pure function over the
/// two facts it needs, and so a test can state "armed, spec unknown" without
/// building a five-field wire struct.
pub type Live = (String, Option<SpecDigest>);

/// Diff the enrollment set against what kamaji currently has armed.
///
/// Pure, so the whole reconciliation decision is testable without a node, a
/// bucket, or a supervisor. `live` is every ident kamaji reports — the filter to
/// this module's own is applied here rather than by the caller, so the
/// "never reap a neighbour" rule lives in one place.
///
/// **An empty `enrolled` yields an empty plan, not a full teardown.** See the
/// module doc: an empty listing and a misconfigured prefix are the same
/// observation.
///
/// `servable` is [`Materialized::servable`] — the domains whose cert pair is on
/// disk. Only those are armed, because a passway forked at a cert that is not
/// there dies on every connection; see [`materialize`]. It does **not** narrow
/// the stop set: a domain that is still enrolled but has lost its pair keeps its
/// live passway rather than being torn down, which is the same fail-stale
/// posture as everything else here.
///
/// ## A domain already armed with this exact declaration is skipped (R852-B4)
///
/// A redeploy is not free and not invisible: kamaji's JIT tier is idempotent by
/// *tearing down* — `deploy_on_demand` stops the supervisor and **releases the
/// held listen socket** before binding fresh — so re-declaring everything every
/// sweep unbinds and rebinds one socket per enrolled domain per sweep, and kills
/// any passway that happened to be warm inside its idle TTL. At the 300 s
/// default and 10k domains that is 10k rebinds every five minutes, reported in
/// the log as `armed = 10000`, which is exactly what it did.
///
/// So a domain whose live digest equals the digest of the declaration this
/// sweep would send is counted in [`Plan::unchanged`] and left alone. Equality
/// is only ever asserted in the safe direction: `None` (kamaji restarted, or
/// never recorded one) matches nothing, so an unknown spec is redeployed. The
/// digest is computed over the same [`Workload`] value both sides hold, and a
/// tenant-passway declaration carries only ordered maps — see
/// [`kamaji_proto::digest`] for why that matters and where the guarantee stops.
///
/// **This is the only cheap thing here that a node-local record could not do.**
/// The alternative — yubaba remembering what it last declared — is rejected on
/// the module doc: a second copy of the truth can only disagree with
/// `enrolled()`, whereas a digest read back from kamaji answers the question
/// actually being asked, which is what the *node* is holding right now.
pub fn plan(
    enrolled: &[(String, Enrollment)],
    live: &[Live],
    cfg: &TenantPasswayConfig,
    servable: &BTreeSet<String>,
) -> Plan {
    if enrolled.is_empty() {
        return Plan::default();
    }
    let wanted: BTreeSet<String> = enrolled
        .iter()
        .map(|(domain, _)| workload_ident(domain))
        .collect();
    let armed: BTreeMap<&str, Option<SpecDigest>> = live
        .iter()
        .map(|(ident, digest)| (ident.as_str(), *digest))
        .collect();

    let mut deploy = Vec::new();
    let mut unchanged = 0usize;
    for (domain, enrollment) in enrolled.iter().filter(|(d, _)| servable.contains(d)) {
        let ident = workload_ident(domain);
        let workload = declare(domain, enrollment, cfg);
        // `flatten`: absent from the live set and present-but-undigested are
        // the same answer here — "no digest to compare" — and both mean deploy.
        let live_digest = armed.get(ident.as_str()).copied().flatten();
        match (live_digest, spec_digest(&workload)) {
            (Some(live), Some(wanted)) if live == wanted => unchanged += 1,
            _ => deploy.push((WorkloadId::new(&ident), workload)),
        }
    }

    let stop = live
        .iter()
        .map(|(ident, _)| ident)
        .filter(|ident| ident.starts_with(IDENT_PREFIX))
        .filter(|ident| !wanted.contains(*ident))
        .map(|ident| WorkloadId::new(ident))
        .collect();

    Plan {
        deploy,
        stop,
        unchanged,
    }
}

/// A sweep that could not complete.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("reading the enrollment set: {0}")]
    Store(#[from] CertStoreError),
    #[error("listing kamaji's workloads: {0}")]
    List(String),
    #[error("loading the node KEK from {path}: {source}")]
    Kek {
        path: String,
        #[source]
        source: workload_spec::secrets::SecretError,
    },
}

/// What one sweep did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reconciled {
    pub armed: usize,
    pub stopped: usize,
    /// Domains whose deploy or stop was refused. Counted, never fatal: one
    /// tenant's bad enrollment must not stop the other 9,999 from being armed.
    pub failed: usize,
    /// Cert pairs written to disk this sweep (R852-F3). Zero is the steady
    /// state; a non-zero count is a first fill or a renewal landing.
    pub materialized: usize,
    /// Enrolled domains with no certificate yet, and therefore not armed.
    pub awaiting_cert: usize,
    /// Domains already armed with this exact declaration and therefore left
    /// alone (R852-B4). This is the steady state — a sweep whose whole output
    /// is `unchanged = <every enrolled domain>` is the healthy one, and a
    /// non-zero `armed` alongside it is a real change landing.
    pub unchanged: usize,
    /// Unenrolled domains whose materialized pair was removed from the node.
    pub pruned: usize,
}

/// One sweep: list the enrollment set, ask kamaji what it holds, materialize
/// every issued pair, then apply the diff.
///
/// **Materialize, then arm** — the ordering the whole module hangs on. A pair
/// reaches the disk before the socket that will serve it is held, so a passway
/// is never forked at a cert that is not there. Pruning runs last, after the
/// stop set is applied, so a private key is removed only once nothing is holding
/// a socket that would want it.
///
/// Every per-domain failure is logged and counted; the sweep continues. A
/// *listing* failure ends the sweep, because there is nothing to reconcile
/// against — it does not end the loop. So does a KEK failure: without it nothing
/// can be materialized, and arming against a stale disk would fork passways at
/// certs this node can no longer prove it may serve.
///
/// @yah:ticket(R852-B4, "Every sweep tears down and rebinds every tenant's held socket, because nothing can tell an unchanged declaration from a changed one")
/// @yah:status(review)
/// @yah:at(2026-09-03T21:32:18Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R852)
/// @yah:severity(medium)
/// @yah:next("THE FIX IS A PROTO FIELD, in a crate this relay's children do not own: give WorkloadEntry a comparable digest of the deployed spec (or the listen string + idle_ttl), have `plan` skip a domain whose live digest equals `declare()`'s, and keep redeploy for the difference. The node-local-record alternative is already rejected on the module: W267 says a restart-resume record could only disagree with `enrolled()`, and a digest read back from kamaji is the authoritative answer rather than a second copy.")
/// @yah:gotcha("READ BOTH SIDES BEFORE BELIEVING THIS IS CHEAP. kamaji's `deploy_on_demand` (oss/kamaji/crates/kamaji/src/jit.rs:159) is idempotent by TEARING DOWN: line 172 is an unconditional `self.teardown_workload(&ident).await?` — it stops the supervisor and releases the held socket — before `bind_and_hold` binds fresh. `tenant_passway::plan` puts EVERY enrolled+servable domain in `Plan::deploy` on every sweep, so at the 300 s default a 10k-domain node unbinds and rebinds 10k listening sockets every five minutes, and any passway that happened to be warm inside its 60 s idle TTL is killed mid-life. Nothing is wrong-looking in a log: each sweep reports `armed = 10000` and that is exactly what it did.")
/// @yah:assumes("NOT MEASURED ON A NODE — read off the source on 2026-09-03 while landing R852-F3, not observed on a fleet member. The tenant tier is opt-in (YUBABA_TENANT_PASSWAY_STATE_DIR) and I did not verify it is enabled anywhere live, so the blast radius today may be zero domains. Confirm before treating the severity as urgent.")
/// @yah:handoff("FIXED as the ticket specified — a proto field, not a node-local record. (1) kamaji-proto gains src/digest.rs: `spec_digest(&Workload) -> Option<[u8;32]>`, SHA-256 over the postcard encoding under a domain-separation prefix, plus `WorkloadEntry.spec_digest: Option<SpecDigest>` and ProtocolVersion::V5 (same reasoning V4 carries: a field appended to an existing struct shifts every byte after it and postcard has no field names, so the bump turns a mid-frame decode error into a handshake refusal). (2) kamaji-bin records it centrally rather than per backend: Registry.digests, set on an accepted Deploy (digested BEFORE the dispatch match, since the arms take the Workload apart), moved on an accepted GracefulUpgrade, dropped on Stop, and stamped onto the merged+deduped entries in the List arm. Deliberately NOT computed inside runtime_state_to_entry — a runtime holds a lowered WorkloadSpec, and a digest over a derived value would never match a caller's declaration. (3) yubaba::tenant_passway::plan takes `live: &[(String, Option&lt;SpecDigest&gt;)]`, skips a domain whose live digest equals declare()'s, counts it in the new Plan::unchanged / Reconciled::unchanged, and logs `unchanged` beside `armed` so the two read as the split they now are.")
/// @yah:verify("All run, all green. oss/kamaji `cargo test --workspace --all-features` — 0 failed (kamaji-proto carries 5 new digest tests: determinism, listen-string sensitivity, domain sensitivity, the BTreeMap env escape hatch, and that the domain prefix is actually mixed in). kamaji-bin --features tenant-passway --lib tenant_passway 6/6 (3 new: List reports the digest of the caller's own Workload and a changed declaration moves it; Stop drops the record so an identical redeploy is not skipped; a refused deploy records nothing). kamaji-bin --lib without the feature 218 pass. oss/yubaba `cargo test -p yubaba --lib` 625 pass / 0 fail, tenant_passway 20/20 (5 new: steady state binds nothing; a changed backend address redeploys; a changed idle_ttl redeploys though the socket is identical; a kamaji restart re-arms everything since None is never 'unchanged'; an unchanged domain that unenrolls is still released). cargo check clean: oss/kamaji --workspace --all-targets --all-features, oss/yubaba --workspace --all-targets, root --workspace --all-targets --exclude xtask.")
/// @yah:gotcha("YUBABA AND KAMAJI MUST BE REDEPLOYED AS A PAIR. ProtocolVersion is now V5; a node running one V4 binary and one V5 binary gets an explicit handshake refusal naming the version, not a degraded mode. That is the designed behaviour (blast radius is one node — this is a node-local UDS and the two self-install together), but it means a partial rollout of this commit takes a node's kamaji dispatch down until both halves land.")
/// @yah:assumes("THE SEVERITY QUESTION ON THIS TICKET IS NOW SETTLED, and the answer is zero: the tenant tier is enabled on no fleet machine. `rg -l \"TENANT_PASSWAY|tenant-passway-dir\"` over the tree outside target/ hits only source files plus one line of W267 — no systemd unit, no .yah/infra/machines/*.toml, and no deploy script sets YUBABA_TENANT_PASSWAY_STATE_DIR or passes --tenant-passway-dir. So this landed as prevention before the tier is switched on, not as a fix to live churn. Still unmeasured on a node, because there is no node running it to measure.")
/// @yah:cleanup("The digest is only a sound unchanged-check for specs whose maps are ordered. workload_spec::WorkloadSpec carries `labels`/`annotations` as HashMaps, whose iteration order is randomized per process, so a Workload::Container's digest can differ between two processes holding identical specs. Documented at length in kamaji-proto/src/digest.rs and safe in the direction it fails (a spurious mismatch costs one redeploy, a spurious match cannot happen), and the tenant-passway declaration this ticket exists for carries only BTreeMaps. If a container-shaped reconciler ever wants to lean on the same field, those two HashMaps should become BTreeMaps first.")
pub async fn reconcile_once(
    store: &ObjectCertStore,
    kamaji: &KamajiClient,
    cfg: &TenantPasswayConfig,
) -> Result<Reconciled, ReconcileError> {
    let enrolled = store.enrolled()?;
    // R852-B4: the digest rides the same listing, so "what is armed" and "what
    // is it armed WITH" are one observation and cannot disagree.
    let live: Vec<Live> = kamaji
        .list()
        .await
        .map_err(|e| ReconcileError::List(e.to_string()))?
        .into_iter()
        .map(|entry| (entry.id.0, entry.spec_digest))
        .collect();

    // Loaded per sweep rather than held for the process lifetime: a rotated KEK
    // is picked up within one sweep, and the key material is resident for the
    // materialization pass instead of forever.
    let kek = load_cluster_kek(&cfg.kek_path).map_err(|source| ReconcileError::Kek {
        path: cfg.kek_path.display().to_string(),
        source,
    })?;
    let materialized = materialize(store, &kek, cfg, &enrolled);
    drop(kek);

    let plan = plan(&enrolled, &live, cfg, &materialized.servable);
    let mut out = Reconciled {
        materialized: materialized.written,
        awaiting_cert: materialized.awaiting_cert,
        failed: materialized.failed,
        unchanged: plan.unchanged,
        ..Reconciled::default()
    };

    for (id, workload) in &plan.deploy {
        // No mesh assignment: a tenant passway binds the loopback (or node)
        // address its enrollment names, and the demux splices to it from the
        // same node. Passing a mesh sentinel here would read on the wire as a
        // real instruction to bind one — see `KamajiClient::deploy_envelope`.
        match kamaji.deploy_envelope(id, workload, None).await {
            Ok(()) => out.armed += 1,
            Err(e) => {
                out.failed += 1;
                warn!(id = %id.0, error = %e, "tenant passway: arming failed");
            }
        }
    }
    for id in &plan.stop {
        match kamaji.stop(id).await {
            Ok(()) => out.stopped += 1,
            Err(e) => {
                out.failed += 1;
                warn!(id = %id.0, error = %e, "tenant passway: releasing failed");
            }
        }
    }
    out.pruned = prune(cfg, &enrolled);
    Ok(out)
}

/// Spawn the reconciler loop. Sweeps immediately, then every `cfg.sweep`.
///
/// Every failure is logged and the loop continues, for the reason
/// [`crate::demux_routes::spawn`]'s does: a reconciler that exited on the first
/// R2 error would freeze the fleet's tenant tier at whatever it held when the
/// bucket blipped, and nothing would say so again.
///
/// Takes the reconnecting [`KamajiSibling`] rather than a
/// [`KamajiClient`] and re-resolves it **every sweep**. A held `Arc<KamajiClient>`
/// would strand this loop on `PeerClosed` the first time someone
/// `systemctl restart kamaji` — the live incident of 2026-08-13 that
/// `KamajiSibling` exists to prevent — and it would strand it *silently*, because
/// a sweep that fails every deploy still logs one warning per domain and keeps
/// looping.
pub fn spawn(
    store: Arc<ObjectCertStore>,
    kamaji: KamajiSibling,
    cfg: TenantPasswayConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            sweep_secs = cfg.sweep.as_secs(),
            idle_ttl_secs = cfg.idle_ttl.map(|t| t.as_ms() / 1000),
            cert_dir = %cfg.cert_dir,
            issuer = %store.issuer(),
            "tenant passway: arming one cold passway per enrolled custom domain"
        );
        loop {
            match kamaji.current() {
                Some(client) => match reconcile_once(&store, &client, &cfg).await {
                    Ok(r)
                        if r.armed > 0
                            || r.stopped > 0
                            || r.failed > 0
                            || r.materialized > 0
                            || r.pruned > 0 =>
                    {
                        info!(
                            armed = r.armed,
                            stopped = r.stopped,
                            failed = r.failed,
                            materialized = r.materialized,
                            awaiting_cert = r.awaiting_cert,
                            pruned = r.pruned,
                            // R852-B4: printed BESIDE `armed` so the two read
                            // as the split they are. `armed` used to be every
                            // enrolled domain on every sweep, which said
                            // nothing; now `armed` is what actually changed
                            // and `unchanged` is what was left holding its
                            // socket.
                            unchanged = r.unchanged,
                            "tenant passway: sweep applied"
                        )
                    }
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "tenant passway: sweep failed"),
                },
                None => warn!(
                    socket = %kamaji.socket().display(),
                    "tenant passway: no kamaji attached — skipping this sweep. Enrolled \
                     domains stay routed by the demux but nothing is armed behind them."
                ),
            }
            tokio::time::sleep(cfg.sweep).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::SystemTime;

    fn cfg() -> TenantPasswayConfig {
        TenantPasswayConfig {
            cert_dir: "/run/yah/passway/tenants".into(),
            kek_path: PathBuf::from(CLUSTER_KEK_PATH),
            idle_ttl: Some(Millis::from_secs(60)),
            sweep: Duration::from_secs(300),
        }
    }

    /// Every domain servable — the shape every pre-R852-F3 test assumed.
    fn all(enrolled: &[(String, Enrollment)]) -> BTreeSet<String> {
        enrolled.iter().map(|(d, _)| d.clone()).collect()
    }

    fn enrollment(addr: &str) -> Enrollment {
        Enrollment::new(addr.parse::<SocketAddr>().unwrap(), SystemTime::UNIX_EPOCH)
    }

    /// Armed, but kamaji has no digest on record — a restart, or a peer that
    /// predates R852-B4. The pre-R852-B4 shape of `live`.
    fn undigested(idents: &[&str]) -> Vec<Live> {
        idents.iter().map(|i| (i.to_string(), None)).collect()
    }

    /// Armed with exactly the declaration this config would produce — the
    /// steady state.
    fn as_declared(enrolled: &[(String, Enrollment)], cfg: &TenantPasswayConfig) -> Vec<Live> {
        enrolled
            .iter()
            .map(|(d, e)| (workload_ident(d), spec_digest(&declare(d, e, cfg))))
            .collect()
    }

    #[test]
    fn the_declaration_carries_the_enrollments_own_backend_as_the_bind_string() {
        let w = declare("shop.tenant.io", &enrollment("127.0.0.1:8443"), &cfg());
        let p = w.tenant_passway().expect("declared a tenant passway");
        assert_eq!(p.listen, "127.0.0.1:8443");
        assert_eq!(p.domain, "shop.tenant.io");
        assert_eq!(p.tls.cert, "/run/yah/passway/tenants/shop.tenant.io/tls.crt");

        // And it survives to the forked process's env unchanged — the property
        // the whole workload kind exists to hold.
        let spec = p.jit_spec("passway.shop.tenant.io");
        let listen = spec
            .env
            .iter()
            .find(|e| e.name == "PASSWAY_LISTEN")
            .expect("PASSWAY_LISTEN is set");
        assert!(
            matches!(&listen.value, workload_spec::EnvValue::Literal { value } if value == "127.0.0.1:8443"),
            "{listen:?}"
        );
    }

    #[test]
    fn a_trailing_slash_on_the_cert_dir_does_not_double_up() {
        let mut c = cfg();
        c.cert_dir = "/run/certs/".into();
        let w = declare("a.io", &enrollment("127.0.0.1:1"), &c);
        assert_eq!(w.tenant_passway().unwrap().tls.key, "/run/certs/a.io/tls.key");
    }

    #[test]
    fn the_ident_is_the_domain_until_it_would_exceed_the_mesh_ident_cap() {
        assert_eq!(workload_ident("shop.tenant.io"), "passway.shop.tenant.io");

        // 55 chars is the last that fits: `passway.` is 8, and 8 + 55 == 63.
        let fits = format!("{}.example.com", "a".repeat(43));
        assert_eq!(fits.len(), 55);
        assert_eq!(workload_ident(&fits), format!("passway.{fits}"));

        // 56 chars — `passway.` + this is 64, one past the cap.
        let long = format!("{}.example.com", "a".repeat(44));
        assert_eq!(long.len(), 56);
        let ident = workload_ident(&long);
        assert!(ident.len() <= 63, "{ident}");
        assert!(ident.starts_with(IDENT_PREFIX), "{ident}");
        // Injective where truncation would not be: two domains sharing a 55-char
        // prefix must not share a custodian entry.
        let sibling = format!("{}.example.net", "a".repeat(44));
        assert_ne!(workload_ident(&sibling), ident);
    }

    #[test]
    fn a_sweep_arms_every_enrolled_domain_and_releases_only_its_own_strays() {
        let enrolled = vec![
            ("a.io".to_string(), enrollment("127.0.0.1:8443")),
            ("b.io".to_string(), enrollment("127.0.0.1:8444")),
        ];
        let live = undigested(&[
            "passway.a.io",
            // No longer enrolled — this one is ours to release.
            "passway.gone.io",
            // Not ours. Reaping either of these would take down a neighbour.
            "yah-dashboard",
            "passway-ingress",
        ]);
        let p = plan(&enrolled, &live, &cfg(), &all(&enrolled));

        let armed: Vec<&str> = p.deploy.iter().map(|(id, _)| id.0.as_str()).collect();
        assert_eq!(armed, vec!["passway.a.io", "passway.b.io"]);
        let stopped: Vec<&str> = p.stop.iter().map(|id| id.0.as_str()).collect();
        assert_eq!(
            stopped,
            vec!["passway.gone.io"],
            "a sweep must only ever release passways it owns"
        );
        assert_eq!(
            p.unchanged, 0,
            "kamaji reported no digests, so nothing can be known to be unchanged"
        );
    }

    #[test]
    fn a_domain_armed_with_this_exact_declaration_is_left_alone() {
        // The whole point (R852-B4): `deploy_on_demand` is idempotent by
        // TEARING DOWN — it releases the held listen socket before rebinding —
        // so re-declaring an unchanged domain unbinds a working front door and
        // kills a passway that may be warm inside its idle TTL.
        let enrolled = vec![
            ("a.io".to_string(), enrollment("127.0.0.1:8443")),
            ("b.io".to_string(), enrollment("127.0.0.1:8444")),
        ];
        let live = as_declared(&enrolled, &cfg());
        let p = plan(&enrolled, &live, &cfg(), &all(&enrolled));

        assert!(
            p.deploy.is_empty(),
            "steady state must rebind nothing, got {:?}",
            p.deploy.iter().map(|(id, _)| &id.0).collect::<Vec<_>>()
        );
        assert!(p.stop.is_empty());
        assert_eq!(p.unchanged, 2);
        assert!(p.is_empty(), "a steady-state sweep applies nothing");
    }

    #[test]
    fn a_changed_backend_address_still_redeploys() {
        // The other half of the same property: skipping is only correct if the
        // digest actually moves when the declaration does. The bind string is
        // the field a re-enrollment changes, and the one whose staleness is an
        // outage — kamaji would be holding a socket the demux no longer routes
        // to.
        let before = vec![("a.io".to_string(), enrollment("127.0.0.1:8443"))];
        let after = vec![("a.io".to_string(), enrollment("127.0.0.1:9443"))];
        let live = as_declared(&before, &cfg());
        let p = plan(&after, &live, &cfg(), &all(&after));

        assert_eq!(p.unchanged, 0);
        let armed: Vec<&str> = p.deploy.iter().map(|(id, _)| id.0.as_str()).collect();
        assert_eq!(armed, vec!["passway.a.io"]);
        let declared = p.deploy[0].1.tenant_passway().unwrap();
        assert_eq!(declared.listen, "127.0.0.1:9443");
    }

    #[test]
    fn a_changed_idle_ttl_redeploys_even_though_the_socket_is_the_same() {
        // A config change nothing about the *address* reflects. Without the
        // digest covering the whole declaration this is the shape that would
        // silently never land: same domain, same bind string, different
        // process lifetime.
        let enrolled = vec![("a.io".to_string(), enrollment("127.0.0.1:8443"))];
        let live = as_declared(&enrolled, &cfg());
        let mut longer = cfg();
        longer.idle_ttl = Some(Millis::from_secs(600));
        let p = plan(&enrolled, &live, &longer, &all(&enrolled));
        assert_eq!(p.unchanged, 0);
        assert_eq!(p.deploy.len(), 1);
    }

    #[test]
    fn a_kamaji_restart_rearms_everything() {
        // `None` is "no record", never "unchanged". After a kamaji restart
        // nothing is bound, so a sweep that read `None` as agreement would
        // leave every tenant's domain dark until the next enrollment change.
        let enrolled = vec![("a.io".to_string(), enrollment("127.0.0.1:8443"))];
        let p = plan(&enrolled, &[], &cfg(), &all(&enrolled));
        assert_eq!(p.deploy.len(), 1);
        assert_eq!(p.unchanged, 0);

        // And the same when the ident IS listed but carries no digest — a peer
        // that never recorded one is not evidence of agreement either.
        let p = plan(&enrolled, &undigested(&["passway.a.io"]), &cfg(), &all(&enrolled));
        assert_eq!(p.deploy.len(), 1);
        assert_eq!(p.unchanged, 0);
    }

    #[test]
    fn an_unchanged_domain_that_stops_being_enrolled_is_still_released() {
        // Skipping the deploy must not make a domain invisible to the stop
        // half: `unchanged` is about what to re-declare, not about ownership.
        let was = vec![("gone.io".to_string(), enrollment("127.0.0.1:8443"))];
        let live = as_declared(&was, &cfg());
        let still = vec![("a.io".to_string(), enrollment("127.0.0.1:8444"))];
        let p = plan(&still, &live, &cfg(), &all(&still));
        let stopped: Vec<&str> = p.stop.iter().map(|id| id.0.as_str()).collect();
        assert_eq!(stopped, vec!["passway.gone.io"]);
    }

    #[test]
    fn an_empty_enrollment_set_stops_nothing() {
        let live = undigested(&["passway.a.io", "passway.b.io"]);
        let p = plan(&[], &live, &cfg(), &BTreeSet::new());
        assert!(
            p.is_empty(),
            "an empty listing and a misconfigured prefix are the same observation — \
             tearing down every tenant on one is the outage this guards"
        );
    }

    #[test]
    fn config_is_opt_in_and_zero_ttl_means_never_reap() {
        let none = parse_config(|_| None).expect("parses");
        assert!(none.is_none(), "no state dir means the reconciler stays off");

        let c = parse_config(|k| match k {
            STATE_DIR_ENV => Some("/var/lib/yah/passway".into()),
            _ => None,
        })
        .expect("parses")
        .expect("enabled");
        assert_eq!(c.sweep, Duration::from_secs(DEFAULT_SWEEP_SECS));
        assert_eq!(c.idle_ttl, Some(Millis::from_secs(DEFAULT_IDLE_TTL_SECS)));
        assert_eq!(
            c.cert_dir,
            workload_spec::DEFAULT_TENANT_PASSWAY_CERT_DIR.to_string()
        );
        assert_eq!(
            c.kek_path,
            PathBuf::from(CLUSTER_KEK_PATH),
            "the default must be the node's one cluster KEK — a different key here decrypts \
             nothing the issuer sealed"
        );

        let resident = parse_config(|k| match k {
            STATE_DIR_ENV => Some("/var/lib/yah/passway".into()),
            IDLE_TTL_SECS_ENV => Some("0".into()),
            _ => None,
        })
        .expect("parses")
        .expect("enabled");
        assert_eq!(
            resident.idle_ttl, None,
            "0 must mean never reap, not a one-second churn"
        );
        // And that reaches the rendered env as an ABSENT variable.
        let w = declare("a.io", &enrollment("127.0.0.1:1"), &resident);
        let spec = w.tenant_passway().unwrap().jit_spec("passway.a.io");
        assert!(
            !spec.env.iter().any(|e| e.name == "PASSWAY_IDLE_TTL_SECS"),
            "never-reap must omit the variable"
        );
    }

    // ── R852-F3: materializing the pair ──────────────────────────────────────

    use crate::secrets::seal_cluster_secret;
    use yah_object_store::{InMemoryObjectStore, ObjectStore};

    const LE: &str = "https://acme-v02.api.letsencrypt.org/directory";
    const KEK: [u8; 32] = [7u8; 32];

    fn store() -> (Arc<InMemoryObjectStore>, ObjectCertStore) {
        let mem = Arc::new(InMemoryObjectStore::new());
        let certs = ObjectCertStore::new(mem.clone(), LE);
        (mem, certs)
    }

    /// Seal one domain's pair into `certs` under the rule the issuer would
    /// stamp for `access`.
    fn issue(certs: &ObjectCertStore, domain: &str, access: &SecretAccess) {
        let rule = grant(access, domain);
        certs
            .write_pair(
                &cert_secret_name(domain),
                &key_secret_name(domain),
                &seal_cluster_secret(&KEK, b"CERTPEM", 1, rule.clone()),
                &seal_cluster_secret(&KEK, b"KEYPEM", 1, rule),
            )
            .expect("sealed pair stored");
    }

    fn tmp_cfg(dir: &std::path::Path) -> TenantPasswayConfig {
        let mut c = cfg();
        c.cert_dir = dir.display().to_string();
        c
    }

    #[test]
    fn the_grant_admits_this_domains_own_passway_without_dropping_the_operators_list() {
        let operators = SecretAccess::workloads(["yah-cloud-admin"]);
        let rule = grant(&operators, "shop.tenant.io");

        assert!(
            rule.admits(&consumer("shop.tenant.io")),
            "a domain's cert must admit the passway that serves it: {}",
            rule.summary()
        );
        assert!(
            rule.admits(&SecretConsumer::workload("yah-cloud-admin")),
            "widening must not drop what the operator configured"
        );
        assert!(
            !rule.admits(&consumer("other.tenant.io")),
            "and it must NOT admit a NEIGHBOUR's passway — that is the whole point of \
             stamping per domain rather than reaching for AllowAny"
        );

        // Idempotent: a renewal re-seals through `grant` and must not grow the
        // list by one entry every 60 days.
        assert_eq!(grant(&rule, "shop.tenant.io"), rule);

        // AllowAny is an auditable operator choice and stays exactly what it is.
        assert_eq!(
            grant(&SecretAccess::AllowAny, "shop.tenant.io"),
            SecretAccess::AllowAny
        );
    }

    #[test]
    fn the_authorized_identity_is_the_deployed_identity_including_the_hashed_form() {
        // If these two ever disagree, a cert is sealed for a workload name that
        // is not the one kamaji arms, and every handshake fails a check that
        // looks correct on both sides.
        for domain in ["a.io", &format!("{}.example.com", "a".repeat(60))] {
            assert_eq!(consumer(domain).workload, workload_ident(domain));
            assert!(
                grant(&SecretAccess::default(), domain).admits(&consumer(domain)),
                "even from the deny-all default, the grant admits its own passway"
            );
        }
    }

    #[test]
    fn a_materialized_pair_lands_at_exactly_the_paths_the_workload_reads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = tmp_cfg(dir.path());
        let (_mem, certs) = store();
        issue(&certs, "shop.tenant.io", &SecretAccess::default());

        use std::os::unix::fs::PermissionsExt;
        // Widen the root first, so the mode assertion below proves this code
        // narrowed it rather than inheriting what `tempdir()` happens to make.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        let enrolled = vec![("shop.tenant.io".to_string(), enrollment("127.0.0.1:8443"))];
        let m = materialize(&certs, &KEK, &cfg, &enrolled);
        assert_eq!(m.written, 1);
        assert_eq!(m.failed, 0);
        assert_eq!(m.awaiting_cert, 0);
        assert!(m.servable.contains("shop.tenant.io"));

        // Read the paths off the DECLARATION, not off a second format!() — this
        // assertion is the anti-drift device: it fails if the writer and the
        // workload ever disagree about where the pair goes.
        let w = declare("shop.tenant.io", &enrollment("127.0.0.1:8443"), &cfg);
        let tls = &w.tenant_passway().expect("tenant passway").tls;
        assert_eq!(std::fs::read(&tls.cert).expect("cert on disk"), b"CERTPEM");
        assert_eq!(std::fs::read(&tls.key).expect("key on disk"), b"KEYPEM");

        for p in [&tls.cert, &tls.key] {
            let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, PAIR_MODE, "{p} must be owner-only, got {mode:#o}");
        }
        // The two writes must not have raced through one shared temp name.
        assert!(!dir.path().join("shop.tenant.io/tls.tmp").exists());

        // The root is not world-listable either: each pair inside it is
        // unreadable, but the directory names are the list of every domain this
        // node fronts.
        for d in [dir.path(), &dir.path().join("shop.tenant.io")] {
            let mode = std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, DIR_MODE, "{} is {mode:#o}", d.display());
        }

        // Unchanged input writes nothing — the steady state at 10k domains.
        let again = materialize(&certs, &KEK, &cfg, &enrolled);
        assert_eq!(again.written, 0, "an unchanged pair must not be rewritten");
        assert!(again.servable.contains("shop.tenant.io"));
    }

    #[test]
    fn a_renewal_replaces_both_halves_of_the_pair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = tmp_cfg(dir.path());
        let (_mem, certs) = store();
        issue(&certs, "a.io", &SecretAccess::default());
        let enrolled = vec![("a.io".to_string(), enrollment("127.0.0.1:1"))];
        materialize(&certs, &KEK, &cfg, &enrolled);

        let rule = grant(&SecretAccess::default(), "a.io");
        certs
            .write_pair(
                &cert_secret_name("a.io"),
                &key_secret_name("a.io"),
                &seal_cluster_secret(&KEK, b"CERT2", 2, rule.clone()),
                &seal_cluster_secret(&KEK, b"KEY2", 2, rule),
            )
            .unwrap();

        let m = materialize(&certs, &KEK, &cfg, &enrolled);
        assert_eq!(m.written, 1);
        let tls = tls_paths(&cfg.cert_dir, "a.io");
        assert_eq!(std::fs::read(&tls.cert).unwrap(), b"CERT2");
        assert_eq!(
            std::fs::read(&tls.key).unwrap(),
            b"KEY2",
            "a renewal that replaced only the cert would leave a mismatched pair"
        );
    }

    #[test]
    fn a_pair_whose_rule_refuses_this_passway_is_not_materialized_and_not_servable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = tmp_cfg(dir.path());
        let (_mem, certs) = store();

        // Sealed the pre-R852-F3 way: a static operator list, stamped WITHOUT
        // going through `grant`, so it never names `passway.a.io`.
        let stale = SecretAccess::workloads(["yah-cloud-admin"]);
        certs
            .write_pair(
                &cert_secret_name("a.io"),
                &key_secret_name("a.io"),
                &seal_cluster_secret(&KEK, b"CERTPEM", 1, stale.clone()),
                &seal_cluster_secret(&KEK, b"KEYPEM", 1, stale),
            )
            .unwrap();

        let enrolled = vec![("a.io".to_string(), enrollment("127.0.0.1:1"))];
        let m = materialize(&certs, &KEK, &cfg, &enrolled);
        assert_eq!(m.failed, 1, "a refusal is a failure, not a quiet skip");
        assert!(m.servable.is_empty());
        assert!(
            !dir.path().join("a.io/tls.key").exists(),
            "a refused key must never reach the node's disk"
        );
    }

    #[test]
    fn an_unissued_domain_is_awaiting_a_cert_and_a_broken_bucket_is_a_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = tmp_cfg(dir.path());
        let (mem, certs) = store();
        let enrolled = vec![("a.io".to_string(), enrollment("127.0.0.1:1"))];

        // Nothing issued yet — the normal state of a name registered a minute
        // ago, since on-demand TLS enrols before it orders.
        let m = materialize(&certs, &KEK, &cfg, &enrolled);
        assert_eq!((m.awaiting_cert, m.failed), (1, 0));
        assert!(m.servable.is_empty());

        // Half a pair is the issuer mid-write (key first, cert last), not a
        // failure either.
        certs
            .write_secret(
                &key_secret_name("a.io"),
                &seal_cluster_secret(&KEK, b"KEYPEM", 1, SecretAccess::AllowAny),
            )
            .unwrap();
        let m = materialize(&certs, &KEK, &cfg, &enrolled);
        assert_eq!((m.awaiting_cert, m.failed), (1, 0));

        // A malformed record is the bucket answering wrongly, which must NOT be
        // reported as "no cert issued yet" — that would make an outage look
        // like a slow tenant.
        mem.put(
            &format!("certs/{}/a.io/cert.sealed", certs.issuer()),
            b"not json".to_vec(),
        )
        .unwrap();
        let m = materialize(&certs, &KEK, &cfg, &enrolled);
        assert_eq!((m.awaiting_cert, m.failed), (0, 1));
    }

    #[test]
    fn a_domain_with_no_pair_on_disk_is_not_armed() {
        let enrolled = vec![
            ("a.io".to_string(), enrollment("127.0.0.1:8443")),
            ("b.io".to_string(), enrollment("127.0.0.1:8444")),
        ];
        let servable: BTreeSet<String> = ["a.io".to_string()].into_iter().collect();
        let p = plan(&enrolled, &[], &cfg(), &servable);

        let armed: Vec<&str> = p.deploy.iter().map(|(id, _)| id.0.as_str()).collect();
        assert_eq!(
            armed,
            vec!["passway.a.io"],
            "arming a domain with no cert forks a process per connection, each dying on \
             PASSWAY_TLS_CERT"
        );

        // But it is still WANTED, so a passway already serving it is not reaped
        // when its cert temporarily cannot be read.
        let live = undigested(&["passway.b.io"]);
        let p = plan(&enrolled, &live, &cfg(), &servable);
        assert!(p.stop.is_empty(), "fail-stale: a live passway keeps serving");
    }

    #[test]
    fn pruning_removes_an_unenrolled_domains_key_but_never_on_an_empty_listing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = tmp_cfg(dir.path());
        let (_mem, certs) = store();
        for d in ["a.io", "gone.io"] {
            issue(&certs, d, &SecretAccess::default());
        }
        let both = vec![
            ("a.io".to_string(), enrollment("127.0.0.1:1")),
            ("gone.io".to_string(), enrollment("127.0.0.1:2")),
        ];
        materialize(&certs, &KEK, &cfg, &both);
        assert!(dir.path().join("gone.io/tls.key").exists());

        // An empty listing and a bucket pointed at the wrong prefix are the same
        // observation; one of them is "delete every tenant's key off this node".
        assert_eq!(prune(&cfg, &[]), 0);
        assert!(dir.path().join("gone.io/tls.key").exists());

        let only_a = vec![("a.io".to_string(), enrollment("127.0.0.1:1"))];
        assert_eq!(prune(&cfg, &only_a), 1);
        assert!(!dir.path().join("gone.io").exists());
        assert!(
            dir.path().join("a.io/tls.key").exists(),
            "pruning must not touch a domain that is still enrolled"
        );
    }

    #[test]
    fn a_zero_sweep_is_refused_rather_than_hot_looping_the_bucket() {
        let err = parse_config(|k| match k {
            STATE_DIR_ENV => Some("/var/lib/yah/passway".into()),
            SWEEP_SECS_ENV => Some("0".into()),
            _ => None,
        })
        .expect_err("zero must be refused");
        assert!(err.contains(SWEEP_SECS_ENV), "{err}");
    }
}
