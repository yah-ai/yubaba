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
//!
//! @yah:ticket(R853-B9, "yubaba's fleet issuer decides renewal from the record's updated_at alone, so YUBABA_ACME_EXTRA_DOMAINS is silently ignored until expiry")
//! @yah:at(2026-09-05T18:45:03Z)
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R853)
//! @yah:severity(medium)
//! @yah:next("The engine half already exists and is tested — R853-B8 added acme_engine::cert_dns_names (leaf SAN set, None = unparseable) and acme_engine::domains_not_covered (RFC 6125 matching: exact, or a wildcard SAN covering exactly one label). This ticket is only the yubaba-side wiring; do NOT rewrite the matching.")
//! @yah:gotcha("FOUND WHILE FIXING R853-B8, which is this exact bug one crate over in passway. acme_issuer.rs:424-432 computes renewal_due as is_renewal_due(rec.updated_at, ..) and nothing else — it never compares the stored cert's SAN set against cfg.issue.domains. That list is operator-widenable at :227-231 (the `*.<domain>` + apex pair, plus YUBABA_ACME_EXTRA_DOMAINS), so adding an extra domain and restarting leaves the fleet serving the old narrower cert until the age window opens, with the env var reading as though it took effect. Same silent failure, same up-to-60-day blast radius as B8.")
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @yah:next("THE DESIGN FORK, and why this was filed rather than folded into B8. passway could read its cert straight off disk; here `cert_present = sm.cluster_secret(&cert_key)` (acme_issuer.rs:394) is a SEALED SecretRecord, so coverage costs a KEK unseal. Three options. (A) Unseal on each tick before the renewal_due decision — simplest, correct, but puts a decrypt of the fleet cert into a loop that otherwise never touches the KEK except when actually issuing. (B) Unseal only when is_renewal_due says NOT due, i.e. use coverage purely to override a false negative — same protection, and the decrypt disappears entirely on the tick where an order is happening anyway. (C) Store the SAN set as plaintext metadata beside the sealed record so the check needs no key at all — cheapest per tick, but it adds a field to the record shape and a migration for records already written. RECOMMEND B: it is the smallest change that closes the hole, and the cost lands on the path that is already about to do far more work.")
//! @yah:next("Test it the way B8 was: a regression test that FAILS without the fix (stored cert SAN = [yah.dev, *.yah.dev], cfg.issue.domains widened with an extra domain, fresh updated_at, assert renewal_due), plus the inverse (a cert that covers everything is not re-ordered) — the inverse is the expensive one to get wrong, since a false 'not covered' re-orders the FLEET wildcard on every tick against Let's Encrypt's per-account order budget.")
//! @yah:next("Check whether the per-domain issuer (domain_issuer.rs) needs the same treatment. Believed NO — it orders one identifier per enrolled domain with no operator-widenable list, so there is no way for config to drift ahead of the stored cert — but that was reasoned about, not tested, so confirm before closing this out.")
//! @yah:handoff("FIXED, but built by @Ashguard:griffin (session:327930f2) rather than by me, and the record should say so. I picked up R853 and found griffin already mid-edit in acme_issuer.rs — an unanchored `chat` session taking direction from the operator, who had chosen the record-shape fix. Rather than hand-fight the file I took their proposed split: they finished the implementation, I did the close-out, the epoch re-record and the verification. They did not claim the ticket or check the board before editing, which they flagged themselves.")
//! @yah:handoff("THE DESIGN WENT WITH OPTION (C), NOT THE (B) THIS TICKET RECOMMENDED, and (C) is the better call — worth recording because the ticket argued the other way. `SecretRecord` gained `sans: Option<Vec<String>>` (#[serde(default)], raft/mod.rs:1071) with the matching field on `YubabaRequest::PutSecret` (:443, applied :1344), stored as PLAINTEXT beside the sealed record. A leaf's SAN list is public by construction, so coverage costs no KEK unseal per tick at all — (B)'s whole premise was minimizing an unseal that (C) removes. The migration the ticket feared is handled by the field contract instead: `None` means 'pre-field, or not a cert' and maps to `acme_engine::CertSans::NotChecked`, so a legacy record degrades to exactly the pre-B9 age-only decision and heals at the next issuance.")
//! @yah:handoff("THE SUBTLE PART, and the reason this is more correct than what the ticket asked for: `issue_and_store` writes the CA's ACTUAL leaf SANs via `acme_engine::cert_dns_names(&issued.cert_chain_pem)`, not `cfg.issue.domains`. Writing the configured list would have recorded INTENT as FACT — a partially-honoured order would read as covered forever. `seal_cluster_secret` sets `sans: None`. `run()` now goes through a new pure `renewal_decision_for(cert, cfg, now) -> RenewalDecision`, extracted out of the I/O loop precisely so the decision is testable without a raft node or a CA, and warns on `DueForCoverage` with have/want/missing.")
//! @yah:handoff("DISCOVERED AND FIXED IN PASS, outside the ticket title (mine, not griffin's). (1) The R600-F10 standby-observability gap: an issuer on a non-leader logged its `watching` start line and then NOTHING for 6+ minutes, indistinguishable in a journal from a wedged process. Added `enum IssuerPresence { Active, NotLeader, LockHeldElsewhere }` + `report_presence()` in acme_issuer.rs — edge-triggered, so it logs on transition and on FIRST observation (the restarted-unit case, which is the actual bug) but never per tick. The two standby reasons read differently as the gotcha asked (never tried vs tried-and-lost), each line names the leader, and a leaderless raft renders as its own third state rather than collapsing into 'someone else leads'. `info!` not `warn!`: on three voters two are correctly in standby at all times, and warning on the normal state is how people learn to ignore warnings. Two tests. I did NOT build the endpoint half of that fix shape — separate surface, own auth question. (2) `decide_issuer_action`'s doc comment still pointed at `acme_engine::is_renewal_due`, which griffin's refactor made private; re-pointed at `renewal_decision_for` and it now names coverage as a third reason an order is due.")
//! @yah:handoff("EPOCH SURFACE RE-RECORDED, which was the drift-gate half @Ashguard:libra (R836-B1) flagged red. `cargo run -p xtask -- cluster-epochs --write`: cluster_protocol stays 5, state_epoch stays 4, both surface hashes updated. The tool writes hashes but NOT the reasoning, so I hand-wrote the `surface_rerecords` entry (now 18) — the gate asks a real compatibility question and a bare hash update does not answer it. The judgment call it turns on is the R706 discriminator, since `access` WAS bumped on this same file with this same #[serde(default)] Option-field shape: R706 failed OPEN (an old node dropping the field kept serving the secret under its own absent authorization check, defeating the guarantee). `sans` fails the other way — a dropped field skips the coverage check, renewal falls back to age, and the cost is a missed re-order bounded by the renew-before window, never a cert served to the wrong party.")
//! @yah:verify("`cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib` = 733 passed / 0 failed (731 from griffin's work + my 2 presence tests). The camp skew detector reported 'Input closure unchanged across the whole run: no skew' on this one — an EARLIER 731/0 run was flagged SUSPECT because session:aa5e882d edited three files mid-run, so 733/0 is the number of record and 731 should not be quoted.")
//! @yah:verify("Verified griffin's work BY CONTENT rather than taking the report: all five claimed test fns exist (acme_issuer.rs:828/843/856/881, domain_issuer.rs:715), `renewal_decision_for` at :614, `SecretRecord.sans` at raft/mod.rs:1071, the PutSecret apply arm at :1344.")
//! @yah:verify("Both regression directions this ticket asked for exist, and the failing-direction one is MUTATION-PROVEN rather than merely present: with `renewal_decision_for` forced back to `CertSans::NotChecked` (pre-B9 behaviour), exactly one test fails — `a_widened_config_reorders_a_brand_new_cert` — 25 passed / 1 failed, restored and re-run green. The expensive inverse the ticket warned about (`a_fully_covering_cert_is_never_reordered_for_coverage`) is covered, plus `coverage_matching_is_not_defeated_by_case_or_a_root_dot`, which is what stops a capital letter re-ordering the fleet wildcard every tick against the LE order budget.")
//! @yah:verify("The ticket's last question — does domain_issuer.rs need the same treatment — is answered NO and now PINNED rather than reasoned. `order_identifiers(domain)` was extracted from the inline `vec![domain.to_string()]` and `a_tenant_order_covers_exactly_its_own_domain_and_nothing_else` asserts it, with a doc saying that if it ever returns more than one name, `needs_issuance` must switch to `CertSans::Known`. The next person to add a `www.` alias trips a test instead of re-deriving the analysis.")
//! @yah:verify("`cargo test -p xtask --lib cluster_epochs` = 18 passed / 0 failed after the re-record, i.e. the drift guard libra reported red is green. JSON re-validated with python3 json.load, and `git diff --stat` on cluster-epochs.json is 24 insertions / 5 deletions — the rationale entry plus the four digests, no wholesale reformat.")
//! @yah:verify("`YubabaRequest` really has no `#[serde(deny_unknown_fields)]` — checked rather than inherited from the neighbouring epoch entries, because the whole no-bump verdict rests on it. rg finds the string 4 times in raft/mod.rs (:54, :82, :440, :2705) and every one is PROSE inside a doc comment or @yah: annotation asserting its absence; not one is an actual attribute.")
//! @yah:gotcha("THIS FIX CANNOT RUN IN PRODUCTION TODAY, and it is gated outside R853 entirely — found by @Ashguard:griffin reading .yah/infra/machines/us-west-001.toml rather than the R858 summary. The fleet issuer gates on raft leadership (acme_issuer.rs). us-west-001 holds leadership, has NO issuer drop-in, and cannot take a yubaba restart to get one: headscale is lifecycle-bound to leadership (`ingress_ownership: FollowsRaftLeader`), `cloud.mesh.yah.dev` is a fixed A record to west's IP, `headscale.db` is local disk and not raft-replicated, and a transfer reproduces the 37-hour outage of 2026-09-03. us-east-001 and us-south-001 HAVE the drop-in and can never legitimately become leader. So the issuer is configured on exactly the two nodes where it is guaranteed inert, no tls/yah.dev/* cluster secret exists, and no PutSecret carrying `sans` has ever been replicated on this fleet. The fix is correct and unit-tested but UNOBSERVED LIVE, and stays that way until R858-T3 makes leadership movable. This is not an argument against having fixed it: when leadership does become movable the coverage hole would have been live and silent for up to 60 days, so it was closed before the thing that arms it.")
//! @yah:gotcha("DO NOT ROLL 0.8.33 ACROSS THE WHOLE FLEET on the strength of this ticket. `yah cloud rollout yubaba` drains the leader with an explicit POST /raft/transfer-leader under FollowersFirstLeaderLast, which is the same Sept-3 chain as above. A followers-only roll (east + south to 0.8.33, west left at 0.8.32) is safe for THIS change specifically — `sans` is #[serde(default)] on an existing struct and an existing variant, tolerated in both directions, per the surface_rerecords entry — but that is a statement about this field, not a general clearance for the release.")
//! @yah:gotcha("The every-voter deployment invariant that R600-F10:51 records as the fix for silent standby is currently UNSATISFIABLE for the reason above. It stands as a correct statement and is simply unreachable on this fleet until R858 lands. My IssuerPresence logging is what makes the interim state legible — an edge-triggered NotLeader line naming the leader is the only thing distinguishing 'correctly inert' from 'misconfigured' while that is true.")

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
use crate::cert_store::{CertStoreConfig, ObjectCertStore};
use crate::secrets::{load_cluster_kek, seal_cluster_secret, CLUSTER_KEK_PATH};
use workload_spec::secrets::SecretAccess;

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
/// `renewal_due` folds together "no cert stored yet", "the stored cert is within
/// its renew-before margin", and "the stored cert does not cover every
/// configured domain" — all three mean a fresh order is due — so the caller
/// computes it once via [`renewal_decision_for`], whose
/// [`acme_engine::RenewalDecision`] this collapses with `is_due()`.
pub fn decide_issuer_action(lock_won: bool, renewal_due: bool) -> IssuerAction {
    match (lock_won, renewal_due) {
        (false, _) => IssuerAction::Standby,
        (true, true) => IssuerAction::Issue,
        (true, false) => IssuerAction::HoldOnly,
    }
}

/// Why this node is or is not the acting issuer, for the journal.
///
/// R600-F10 measured the failure this exists to close: with the issuer drop-in
/// installed on us-east-001 and us-south-001 on 2026-09-05, both nodes logged
/// the `acme issuer: watching` start line and then **nothing at all** for six
/// minutes — no issuance, no warning, no error. The behaviour was correct
/// (neither held raft leadership, so neither reached `AcquireLock`) but it is
/// indistinguishable in a journal from a wedged process, and the operator's
/// decision to roll the drop-in onto *every* voter makes silence the normal
/// state on all but one node.
///
/// The two standby reasons are genuinely different conditions and must read
/// differently: `NotLeader` means this node never tried, `LockHeldElsewhere`
/// means it tried and lost. Logged once per transition, never per tick — a line
/// every `check_interval` would be its own kind of unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IssuerPresence {
    /// Holds raft leadership and won the issuer lock: this node is the issuer.
    Active,
    /// Another node holds raft leadership, so the tick short-circuits before
    /// `AcquireLock`.
    NotLeader,
    /// This node is the raft leader, but another owner's lock lease is still
    /// live and has not lapsed.
    LockHeldElsewhere,
}

/// Log `now` iff it differs from `last`, then record it.
///
/// Every line names the *reason* and who to look at instead, because the
/// operator reading it is trying to answer "is this node broken?" and the
/// answer lives on a different node. Standby is `info!`, not `warn!` — on a
/// three-voter fleet two nodes are correctly in standby at all times, and
/// warning about the normal state trains people to ignore the warning.
fn report_presence(
    last: &mut Option<IssuerPresence>,
    now: IssuerPresence,
    current_leader: Option<YubabaNodeId>,
    lock_key: &str,
) {
    if *last == Some(now) {
        return;
    }
    *last = Some(now);

    // `None` is a real and distinct state — a leaderless raft, e.g. mid-election
    // or quorum lost — and reads very differently from "someone else leads".
    let leader = match current_leader {
        Some(id) => id.to_string(),
        None => "none (no raft leader elected)".to_string(),
    };

    match now {
        IssuerPresence::Active => info!(
            leader = %leader,
            "acme issuer: ACTIVE — this node holds raft leadership and the issuer \
             lock {lock_key}; it is the node that places ACME orders"
        ),
        IssuerPresence::NotLeader => info!(
            leader = %leader,
            "acme issuer: standby — another node holds raft leadership, so this \
             node does not attempt the issuer lock. This is the normal state for \
             a non-leader voter and is NOT an error; the issuer runs on the \
             leader. If no node is issuing, check that the leader also has the \
             issuer configured"
        ),
        IssuerPresence::LockHeldElsewhere => info!(
            leader = %leader,
            "acme issuer: standby — this node is the raft leader but another \
             owner still holds the issuer lock {lock_key}; taking over when that \
             lease lapses"
        ),
    }
}

// ── Runtime config ───────────────────────────────────────────────────────────

/// Everything the issuer loop needs. Built by [`parse_issuer_config`] from the
/// daemon environment; the loop is only spawned when a config is present, so an
/// unconfigured node (dev, single-node) runs no issuer at all.
#[derive(Debug, Clone)]
pub struct IssuerConfig {
    /// SAN base, e.g. `"yah.dev"`. Names the issuer lock and the cluster-secret
    /// keys; the issued cert covers `*.<domain>` + `<domain>`, plus any
    /// [`EXTRA_DOMAINS_ENV`] names (R858-T1).
    pub domain: String,
    /// Provider-agnostic issuance inputs handed to [`acme_engine::issue`].
    pub issue: IssueConfig,
    /// Node-local cluster KEK path — seals cert+key before `PutSecret`.
    pub kek_path: PathBuf,
    /// R706 (W294): who may mount the issued cert+key. Stamped onto both
    /// `SecretRecord`s so the fleet cert is not a bearer secret. Required
    /// config — see [`parse_issuer_config`].
    pub access: SecretAccess,
    /// Steady-state poll cadence (renewal checks) once a cert exists.
    pub check_interval: Duration,
    /// TTL on the issuer lock. Must exceed `check_interval` so the holder renews
    /// before it lapses; a dead issuer's claim frees after this.
    pub lock_ttl: Duration,
    /// Assumed issued-cert validity (renewal math; LE default 90d).
    pub cert_lifetime: Duration,
    /// Renew when within this margin of expiry (default 30d).
    pub renew_before: Duration,
    /// R779 (W267): also write the sealed pair to an object store, when the node
    /// is configured with one ([`crate::cert_store::CertStoreConfig::parse`]).
    ///
    /// Additive, not a replacement: the fleet wildcard is *one* KB-scale record
    /// and raft is exactly the right home for it. The mirror exists because a
    /// free-tier edge node fronting 10k domains is not a raft member and so
    /// cannot read a cluster secret at all — the object store is how cert
    /// material reaches it, and R779's DECISION 1 puts the per-domain certs
    /// there for the separate reason that 10k of them would rewrite the whole
    /// raft state on every `PutSecret`. `None` on an unconfigured node, which
    /// then behaves exactly as it did before R779.
    pub cert_store: Option<CertStoreConfig>,
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
    // R706 (W294): the issuer is the one writer of a cluster secret that is not
    // driven by an operator command, so it is the one place where an unruled
    // record could appear by omission. There is deliberately NO default: a
    // permissive default would make the fleet cert's private key a bearer
    // secret again, and a deny-all default would silently produce a cert nobody
    // can mount. Required config, rejected at parse time either way.
    let access = parse_consumers(&get("YUBABA_ACME_CONSUMERS").unwrap_or_default()).ok_or(
        "YUBABA_ACME_CONSUMERS is required when YUBABA_ACME_DOMAIN is set: a \
         comma-separated list of workload names allowed to mount the issued \
         cert+key (e.g. \"ingress\"), or the literal \"any\" to store them \
         unrestricted",
    )?;

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
    //
    // R858-T1: plus any [`EXTRA_DOMAINS_ENV`] names. An RFC 6125 wildcard matches
    // exactly ONE label, so `*.yah.dev` does NOT cover `cloud.mesh.yah.dev` — a
    // third-level name a passway front door must terminate TLS for has to be its
    // own SAN. It cannot be solved at the door instead: passway does no SNI cert
    // selection (one listener, one cert — `passway::tls`, pingora's rustls
    // backend), so widening this order is the only lever.
    //
    // Order is wildcard, apex, then extras in declaration order, deduped
    // case-insensitively: a repeated ACME identifier is a needless order
    // failure, and a nondeterministic list makes the tests flaky.
    let mut domains = vec![format!("*.{domain}"), domain.clone()];
    for extra in parse_extra_domains(&get(EXTRA_DOMAINS_ENV).unwrap_or_default(), &domain)? {
        if !domains.iter().any(|d| d.eq_ignore_ascii_case(&extra)) {
            domains.push(extra);
        }
    }

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
                // The fleet wildcard is issued for a zone we own outright, so
                // the challenge record goes at `_acme-challenge.<domain>` in
                // that zone. Delegation (R779) is only for *custom tenant*
                // domains — see [`crate::domain_issuer`].
                delegate_zone: None,
                // R779-P8 test hook; the SAME key the domain issuer reads,
                // for the same reason every other `YUBABA_ACME_*` input is
                // shared — two config sets would be two ACME accounts.
                api_base: cf_api_base(&get),
            },
            dns01_propagation_delay: Duration::from_secs(propagation_secs),
            directory_root_cert: None,
        },
        kek_path,
        access,
        check_interval: Duration::from_secs(check_interval_secs),
        lock_ttl: Duration::from_secs(lock_ttl_secs),
        cert_lifetime: Duration::from_secs(cert_lifetime_days * 86_400),
        renew_before: Duration::from_secs(renew_before_days * 86_400),
        cert_store: CertStoreConfig::parse(&get)?,
    }))
}

/// R858-T1 — the env key naming EXTRA SANs to fold into the fleet order, as a
/// comma-separated list (same shape as `YUBABA_ACME_CONSUMERS`).
///
/// Exists because an RFC 6125 wildcard matches exactly one label: the default
/// `*.<domain>` + `<domain>` pair does not cover a third-level name such as
/// `cloud.mesh.yah.dev`, and passway terminates TLS with a single cert per
/// listener (no SNI selection), so the name must be in the fleet cert or the
/// handshake fails. Unset (the default) leaves the order at exactly two SANs.
pub const EXTRA_DOMAINS_ENV: &str = "YUBABA_ACME_EXTRA_DOMAINS";

/// Parse [`EXTRA_DOMAINS_ENV`] into normalized SANs, rejecting anything outside
/// the configured `domain`'s zone.
///
/// The issuer holds ONE Cloudflare zone credential, so a name outside that zone
/// cannot have its `_acme-challenge` TXT published and the order dies at DNS-01
/// with an error that reads like a token problem. Catching it at config time
/// names the offending value instead. Entries are lowercased because ACME
/// identifiers are, and because it makes the dedupe in `parse_issuer_config`
/// correct rather than case-sensitive.
fn parse_extra_domains(raw: &str, domain: &str) -> Result<Vec<String>, String> {
    let zone = domain.trim().to_ascii_lowercase();
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let name = entry.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if name != zone && !name.ends_with(&format!(".{zone}")) {
            return Err(format!(
                "{EXTRA_DOMAINS_ENV}: {name:?} is not inside the issuer's zone {zone:?} — \
                 the issuer holds one Cloudflare zone credential, so a name outside that \
                 zone cannot pass the DNS-01 challenge"
            ));
        }
        out.push(name);
    }
    Ok(out)
}

/// R779-P8 — the env key naming a Cloudflare-shaped API base for the DNS-01
/// TXT publisher. Unset (the production case) means the real Cloudflare API;
/// only the DNS-01 integration harness has any reason to set it.
pub const CF_API_BASE_ENV: &str = "YUBABA_ACME_CF_API_BASE";

/// Read [`CF_API_BASE_ENV`]. Deliberately shared by BOTH issuers rather than
/// duplicated per-loop: the fleet issuer and the per-domain issuer read the
/// same `YUBABA_ACME_*` keys throughout (one contact, one account cache, one
/// CF token) because two config sets would silently be two ACME accounts.
pub fn cf_api_base(get: &impl Fn(&str) -> Option<String>) -> Option<String> {
    get(CF_API_BASE_ENV).map(|b| b.trim().to_string()).filter(|b| !b.is_empty())
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
    // R779: build the object-store mirror once, up front. A misconfigured or
    // unreachable bucket disables the mirror and is loud about it — it must not
    // stop the fleet cert from renewing, which is what returning here would do.
    let mirror = match &cfg.cert_store {
        None => None,
        Some(store_cfg) => match store_cfg.connect(&cfg.issue.directory.url()) {
            Ok(store) => {
                info!(
                    bucket = %store_cfg.bucket,
                    issuer = %store.issuer(),
                    "acme issuer: mirroring the sealed pair to the object cert store"
                );
                Some(store)
            }
            Err(e) => {
                error!(
                    bucket = %store_cfg.bucket,
                    "acme issuer: object cert store unavailable — mirroring disabled, \
                     raft writes continue: {e}"
                );
                None
            }
        },
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

    // Last presence logged, so transitions are reported and steady state is
    // silent. `None` until the first tick, which therefore always logs — an
    // operator restarting the unit sees where it landed rather than nothing.
    let mut last_presence: Option<IssuerPresence> = None;

    loop {
        let cert_present = sm.cluster_secret(&cert_key);

        // Only the raft leader can `client_write`; a follower's AcquireLock would
        // just ForwardToLeader. Gate on leadership to avoid the spam, then let
        // the lock be the linearizable single-issuer guard: during a transient
        // double-leader, raft orders the two AcquireLocks and the second sees a
        // live owner and is denied, so two nodes never issue concurrently.
        let current_leader = { raft.metrics().borrow_watched().current_leader };
        let is_leader = current_leader == Some(node_id);
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

            let decision = renewal_decision_for(cert_present.as_ref(), &cfg, SystemTime::now());
            if let acme_engine::RenewalDecision::DueForCoverage(missing) = &decision {
                warn!(
                    domain = %cfg.domain,
                    have = %cert_present.as_ref().and_then(|r| r.sans.as_ref()).map(|s| s.join(", ")).unwrap_or_default(),
                    want = %cfg.issue.domains.join(", "),
                    missing = %missing.join(", "),
                    "acme issuer: the stored fleet cert does not cover every configured \
                     domain — re-ordering regardless of its age"
                );
            }
            let renewal_due = decision.is_due();

            report_presence(
                &mut last_presence,
                if lock_won {
                    IssuerPresence::Active
                } else {
                    IssuerPresence::LockHeldElsewhere
                },
                current_leader,
                &lock_key,
            );

            if decide_issuer_action(lock_won, renewal_due) == IssuerAction::Issue {
                store_consistent =
                    issue_and_store(&raft, &kek, &cfg, mirror.as_ref(), &cert_key, &key_key).await;
            }
        } else {
            report_presence(
                &mut last_presence,
                IssuerPresence::NotLeader,
                current_leader,
                &lock_key,
            );
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
    mirror: Option<&ObjectCertStore>,
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
    let mut cert_rec = seal_cluster_secret(
        kek,
        issued.cert_chain_pem.as_bytes(),
        stamp,
        cfg.access.clone(),
    );
    // R853-B9: stamp the leaf's ACTUAL SANs, read back out of the PEM the CA
    // just returned — not `cfg.issue.domains`, which is what we asked for. A CA
    // that honoured only part of the order must leave this record reading as
    // still-uncovered so the next tick re-orders, rather than recording our
    // intent as if it were fact. `None` (unparseable chain) degrades to the
    // pre-B9 age-only decision; it never reads as covered.
    cert_rec.sans = acme_engine::cert_dns_names(&issued.cert_chain_pem);
    if cert_rec.sans.is_none() {
        warn!(
            domain = %cfg.domain,
            "acme issuer: could not parse the SANs out of the freshly issued chain — \
             storing it without coverage metadata, so renewal falls back to age alone"
        );
    }
    // Copy the private-key PEM into a zeroizing buffer so the plaintext key is
    // scrubbed when it drops at the end of this fn, rather than lingering in a
    // freed `String`'s heap page (the engine hands us a plain `String`; this is
    // the issuer's own copy — the sensitive one on this node).
    let key_bytes = Zeroizing::new(issued.key_pem.into_bytes());
    let key_rec = seal_cluster_secret(kek, &key_bytes, stamp, cfg.access.clone());

    // KEY first, CERT last — deliberately, because `renewal_due` gates off the
    // CERT record's `updated_at` (see `run`). Writing the gate record last means
    // a partial failure leaves the cert stale/absent, so `renewal_due` stays
    // true and the next tick re-issues and heals — the store never gets wedged
    // with a fresh cert paired to a stale key.
    if let Err(e) = put_secret(raft, key_key, key_rec.clone()).await {
        // Key write is first, so nothing was overwritten — store still consistent.
        error!("acme issuer: PutSecret(key) failed (prior state intact): {e}");
        return true;
    }
    if let Err(e) = put_secret(raft, cert_key, cert_rec.clone()).await {
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

    // R779: mirror to the object store, after raft. Ordered this way on purpose
    // — raft is the store the live fleet resolves from today, so it must not
    // wait on an R2 round-trip, and a mirror failure must not be able to make
    // `renewal_due` retry an order that already succeeded. A missed mirror heals
    // on the next renewal; a repeated ACME order does not heal, it burns the
    // account's rate limit.
    mirror_pair(mirror, cfg, cert_key, key_key, cert_rec, key_rec).await;
    true
}

/// Write the sealed pair to the object cert store on a blocking thread.
///
/// [`ObjectCertStore`] is synchronous (the object-store trait is, so the whole
/// tree's R2 consumers share one client shape), and this call site is inside a
/// tokio task — so it goes through `spawn_blocking` rather than stalling a
/// worker on an HTTPS round-trip. Every failure is logged and swallowed: see the
/// caller for why a mirror failure must not fail the issuance.
async fn mirror_pair(
    mirror: Option<&ObjectCertStore>,
    cfg: &IssuerConfig,
    cert_key: &str,
    key_key: &str,
    cert_rec: SecretRecord,
    key_rec: SecretRecord,
) {
    let Some(store) = mirror.cloned() else { return };
    let (domain, cert_key, key_key) = (
        cfg.domain.clone(),
        cert_key.to_string(),
        key_key.to_string(),
    );
    let written = tokio::task::spawn_blocking(move || {
        store.write_pair(&cert_key, &key_key, &cert_rec, &key_rec)
    })
    .await;
    match written {
        Ok(Ok(())) => info!(
            domain = %domain,
            "acme issuer: sealed cert+key mirrored to the object cert store"
        ),
        Ok(Err(e)) => warn!(
            domain = %domain,
            "acme issuer: object cert store mirror failed (raft write succeeded; \
             heals on the next renewal): {e}"
        ),
        Err(e) => warn!(
            domain = %domain,
            "acme issuer: object cert store mirror task failed: {e}"
        ),
    }
}

/// Whether the fleet cert needs a new order this tick, given what the cluster
/// store holds — R853-B9.
///
/// Pure, so the whole decision is testable without a raft node or a CA, and so
/// the two failure directions can be pinned separately. They cost very
/// differently:
///
/// - a missed **coverage** miss is silent and lasts up to
///   `cert_lifetime - renew_before` (60 days by default), which is the bug
///   this exists to close;
/// - a spurious "not covered" re-orders the fleet wildcard **every
///   `check_interval`**, straight into the per-account new-order budget. That
///   is why matching is delegated to `acme_engine::domains_not_covered`
///   (RFC 6125, both sides normalized) rather than a string compare here.
///
/// `rec.sans == None` means "written before the field existed, or not a cert"
/// and degrades to the pre-B9 age-only decision — never to "covered".
pub fn renewal_decision_for(
    cert: Option<&SecretRecord>,
    cfg: &IssuerConfig,
    now: SystemTime,
) -> acme_engine::RenewalDecision {
    let Some(rec) = cert else {
        // No cert at all: due, and not for age. Cold start.
        return acme_engine::RenewalDecision::DueUnreadable;
    };
    acme_engine::renewal_decision(
        rec.sans
            .as_deref()
            .map_or(acme_engine::CertSans::NotChecked, acme_engine::CertSans::Known),
        &cfg.issue.domains,
        UNIX_EPOCH + Duration::from_secs(rec.updated_at),
        cfg.cert_lifetime,
        cfg.renew_before,
        now,
    )
}

async fn put_secret(raft: &YubabaRaft, name: &str, rec: SecretRecord) -> anyhow::Result<()> {
    raft.client_write(YubabaRequest::PutSecret {
        name: name.to_string(),
        ciphertext: rec.ciphertext,
        nonce: rec.nonce,
        updated_at: rec.updated_at,
        access: rec.access,
        digest: rec.digest,
        sans: rec.sans,
    })
    .await?;
    Ok(())
}

/// Parse `YUBABA_ACME_CONSUMERS` into a [`SecretAccess`] rule (R706 / W294).
///
/// - `"any"` (case-insensitive) → [`SecretAccess::AllowAny`], the deliberate
///   unrestricted marker.
/// - a comma-separated list of workload names → an allow-list in the singleton
///   tenant/namespace.
/// - empty / whitespace-only / all-empty-entries → `None`, which the caller
///   turns into a hard config error. An empty allow-list would be a valid
///   deny-all rule, but as a *parse result* it is far more likely a typo than an
///   intent to issue a cert nobody can use.
pub(crate) fn parse_consumers(raw: &str) -> Option<SecretAccess> {
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("any") {
        return Some(SecretAccess::AllowAny);
    }
    let names: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if names.is_empty() {
        return None;
    }
    Some(SecretAccess::workloads(names))
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

    /// R600-F10: the journal must distinguish "correctly standing by" from
    /// "wedged", and must do it without a line per tick. This pins the
    /// edge-trigger itself — the log text is not assertable here, but *whether a
    /// line is emitted at all* is the whole behaviour, so it is what we test.
    #[test]
    fn presence_is_edge_triggered_not_level_triggered() {
        let mut last = None;
        let logged = |last: &mut Option<IssuerPresence>, p: IssuerPresence| {
            let before = *last;
            report_presence(last, p, Some(7), "acme-issuer/yah.dev");
            before != Some(p)
        };

        // First observation always logs: a freshly restarted unit must say where
        // it landed rather than sitting silent, which is the original bug.
        assert!(logged(&mut last, IssuerPresence::NotLeader));
        // Steady state is silent, however many ticks pass.
        assert!(!logged(&mut last, IssuerPresence::NotLeader));
        assert!(!logged(&mut last, IssuerPresence::NotLeader));
        // Every real transition speaks, in both directions.
        assert!(logged(&mut last, IssuerPresence::Active));
        assert!(logged(&mut last, IssuerPresence::LockHeldElsewhere));
        assert!(logged(&mut last, IssuerPresence::NotLeader));
        assert_eq!(last, Some(IssuerPresence::NotLeader));
    }

    /// The two standby reasons are different conditions, so a move between them
    /// is a transition that must log — collapsing them into one "standby" state
    /// would hide a leader change from the operator.
    #[test]
    fn the_two_standby_reasons_are_distinct_states() {
        assert_ne!(IssuerPresence::NotLeader, IssuerPresence::LockHeldElsewhere);

        let mut last = Some(IssuerPresence::NotLeader);
        report_presence(
            &mut last,
            IssuerPresence::LockHeldElsewhere,
            None,
            "acme-issuer/yah.dev",
        );
        assert_eq!(last, Some(IssuerPresence::LockHeldElsewhere));
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

    // ── R779: the object cert-store mirror ──────────────────────────────────

    /// The base env every issuer config needs, so a cert-store test only has to
    /// add the keys it is actually about.
    fn issuer_env_pairs() -> Vec<(&'static str, &'static str)> {
        vec![
            ("YUBABA_ACME_DOMAIN", "yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
            (
                "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE",
                "/run/secrets/cf.token",
            ),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
            ("YUBABA_ACME_CONSUMERS", "ingress"),
        ]
    }

    #[test]
    fn cert_store_mirror_is_off_unless_a_bucket_is_named() {
        let cfg = parse_issuer_config(env(&issuer_env_pairs())).unwrap().unwrap();
        assert_eq!(cfg.cert_store, None);
    }

    #[test]
    fn cert_store_mirror_parses_from_the_issuer_env() {
        let mut pairs = issuer_env_pairs();
        pairs.push((crate::cert_store::BUCKET_ENV, "yah-certs"));
        pairs.push((crate::cert_store::ACCOUNT_ID_ENV, "acct123"));
        let cfg = parse_issuer_config(env(&pairs)).unwrap().unwrap();
        assert_eq!(
            cfg.cert_store,
            Some(crate::cert_store::CertStoreConfig {
                account_id: "acct123".into(),
                bucket: "yah-certs".into(),
                endpoint: None,
            })
        );
    }

    #[test]
    fn a_bucket_without_an_account_id_is_a_config_error() {
        // Half-configured means an operator meant to turn this on; a silent skip
        // surfaces weeks later as a missing cert.
        let mut pairs = issuer_env_pairs();
        pairs.push((crate::cert_store::BUCKET_ENV, "yah-certs"));
        let err = parse_issuer_config(env(&pairs)).unwrap_err();
        assert!(err.contains(crate::cert_store::ACCOUNT_ID_ENV), "got {err}");
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

    // -- R853-B9: renewal_decision_for -----------------------------------

    /// A config with `extra` appended to the usual wildcard + apex pair.
    fn issuer_cfg(extra: &[(&str, &str)]) -> IssuerConfig {
        let mut pairs = vec![
            ("YUBABA_ACME_DOMAIN", "yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
            (
                "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE",
                "/run/secrets/cf.token",
            ),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
            ("YUBABA_ACME_CONSUMERS", "ingress"),
        ];
        pairs.extend_from_slice(extra);
        parse_issuer_config(env(&pairs)).unwrap().expect("config present")
    }

    /// A stored cert record `age_days` old carrying `sans`.
    fn stored(sans: Option<&[&str]>, age_days: u64) -> SecretRecord {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        SecretRecord {
            ciphertext: Vec::new(),
            nonce: vec![0u8; 12],
            updated_at: now.saturating_sub(age_days * 86_400),
            access: Default::default(),
            digest: None,
            sans: sans.map(|s| s.iter().map(|n| n.to_string()).collect()),
        }
    }

    /// THE B9 REGRESSION. Widening `YUBABA_ACME_EXTRA_DOMAINS` and restarting
    /// must re-order immediately, not in 60 days. Fails on the pre-B9 code,
    /// which decided on `updated_at` alone and would return `Fresh` here.
    #[test]
    fn a_widened_config_reorders_a_brand_new_cert() {
        let cfg = issuer_cfg(&[("YUBABA_ACME_EXTRA_DOMAINS", "cloud.mesh.yah.dev")]);
        let rec = stored(Some(&["*.yah.dev", "yah.dev"]), 1);

        assert_eq!(
            renewal_decision_for(Some(&rec), &cfg, SystemTime::now()),
            acme_engine::RenewalDecision::DueForCoverage(vec!["cloud.mesh.yah.dev".to_string()]),
            "a one-label wildcard does not cover a third-level name"
        );
    }

    /// THE EXPENSIVE DIRECTION. A cert that DOES cover the configured list must
    /// not be re-ordered — a false "not covered" fires every `check_interval`
    /// against the per-account new-order budget, forever.
    #[test]
    fn a_fully_covering_cert_is_never_reordered_for_coverage() {
        let cfg = issuer_cfg(&[("YUBABA_ACME_EXTRA_DOMAINS", "cloud.mesh.yah.dev")]);
        let rec = stored(Some(&["*.yah.dev", "yah.dev", "cloud.mesh.yah.dev"]), 1);

        assert_eq!(
            renewal_decision_for(Some(&rec), &cfg, SystemTime::now()),
            acme_engine::RenewalDecision::Fresh
        );
    }

    /// Case and a trailing root dot must not re-order a good cert — the slow
    /// rate-limit burn this normalization exists to prevent.
    #[test]
    fn coverage_matching_is_not_defeated_by_case_or_a_root_dot() {
        let cfg = issuer_cfg(&[]);
        let rec = stored(Some(&["*.YAH.dev.", "Yah.Dev"]), 1);

        assert_eq!(
            renewal_decision_for(Some(&rec), &cfg, SystemTime::now()),
            acme_engine::RenewalDecision::Fresh
        );
    }

    /// Age still decides once coverage is satisfied — B9 adds a reason, it does
    /// not replace the old one.
    #[test]
    fn a_covering_but_aged_cert_is_still_due_for_age() {
        let cfg = issuer_cfg(&[]);
        assert_eq!(
            renewal_decision_for(Some(&stored(Some(&["*.yah.dev", "yah.dev"]), 61)), &cfg, SystemTime::now()),
            acme_engine::RenewalDecision::DueForAge
        );
    }

    /// BACK-COMPAT: a record written before `sans` existed carries `None`, which
    /// must read as "unknown" and fall back to age — never as "covered". Without
    /// this a legacy record would look satisfied against any config at all.
    #[test]
    fn a_pre_sans_record_falls_back_to_age_and_never_reads_as_covered() {
        let cfg = issuer_cfg(&[("YUBABA_ACME_EXTRA_DOMAINS", "cloud.mesh.yah.dev")]);

        assert_eq!(
            renewal_decision_for(Some(&stored(None, 1)), &cfg, SystemTime::now()),
            acme_engine::RenewalDecision::Fresh,
            "unknown SANs must not manufacture a coverage failure either"
        );
        assert_eq!(
            renewal_decision_for(Some(&stored(None, 61)), &cfg, SystemTime::now()),
            acme_engine::RenewalDecision::DueForAge
        );
    }

    #[test]
    fn no_stored_cert_at_all_is_due() {
        assert!(renewal_decision_for(None, &issuer_cfg(&[]), SystemTime::now()).is_due());
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
            ("YUBABA_ACME_CONSUMERS", "ingress"),
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

    // ── R858-T1: extra SANs on the fleet order ──────────────────────────────

    /// The five required keys, so the extras tests below vary one thing only.
    fn base_env() -> Vec<(&'static str, &'static str)> {
        vec![
            ("YUBABA_ACME_DOMAIN", "yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
            (
                "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE",
                "/run/secrets/cf.token",
            ),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
            ("YUBABA_ACME_CONSUMERS", "ingress"),
        ]
    }

    fn domains_with_extras(extras: Option<&str>) -> Vec<String> {
        let mut pairs = base_env();
        if let Some(v) = extras {
            pairs.push((EXTRA_DOMAINS_ENV, v));
        }
        parse_issuer_config(env(&pairs))
            .unwrap()
            .expect("config present")
            .issue
            .domains
    }

    #[test]
    fn extra_domains_unset_leaves_exactly_wildcard_and_apex() {
        // The back-compat guarantee: unset must be bit-identical to pre-R858-T1.
        assert_eq!(domains_with_extras(None), vec!["*.yah.dev", "yah.dev"]);
        // An empty / whitespace-only value is "unset", not an error.
        assert_eq!(domains_with_extras(Some("  ")), vec!["*.yah.dev", "yah.dev"]);
    }

    #[test]
    fn one_extra_domain_lands_in_the_order() {
        // The R858-T1 case itself: `*.yah.dev` does not cover a third-level
        // name, so `cloud.mesh.yah.dev` has to be its own SAN.
        assert_eq!(
            domains_with_extras(Some("cloud.mesh.yah.dev")),
            vec!["*.yah.dev", "yah.dev", "cloud.mesh.yah.dev"]
        );
    }

    #[test]
    fn extra_domains_dedupe_and_keep_a_deterministic_order() {
        // Repeats against each other, against the apex and against the
        // wildcard all collapse; survivors keep declaration order after the
        // wildcard/apex pair. A duplicate identifier fails the ACME order, and
        // a nondeterministic list would make this assertion flaky.
        assert_eq!(
            domains_with_extras(Some(
                " cloud.mesh.yah.dev , a.mesh.yah.dev ,, CLOUD.MESH.yah.dev , yah.dev , \
                 *.yah.dev , cloud.mesh.yah.dev "
            )),
            vec![
                "*.yah.dev",
                "yah.dev",
                "cloud.mesh.yah.dev",
                "a.mesh.yah.dev"
            ]
        );
    }

    #[test]
    fn out_of_zone_extra_domain_is_refused_by_name() {
        // One CF zone credential: a name outside the zone cannot publish its
        // `_acme-challenge` TXT, so it must fail at parse time rather than
        // deep inside DNS-01 where it reads like a bad token.
        let mut pairs = base_env();
        pairs.push((EXTRA_DOMAINS_ENV, "cloud.mesh.example.com"));
        let err = parse_issuer_config(env(&pairs)).unwrap_err();
        assert!(err.contains(EXTRA_DOMAINS_ENV), "got {err}");
        assert!(err.contains("cloud.mesh.example.com"), "got {err}");

        // A suffix that merely *ends with* the zone text is not in the zone:
        // `notyah.dev` must not be accepted by a naive `ends_with`.
        let mut pairs = base_env();
        pairs.push((EXTRA_DOMAINS_ENV, "a.notyah.dev"));
        let err = parse_issuer_config(env(&pairs)).unwrap_err();
        assert!(err.contains("a.notyah.dev"), "got {err}");
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
            ("YUBABA_ACME_CONSUMERS", "ingress"),
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
            ("YUBABA_ACME_CONSUMERS", "ingress"),
            ("YUBABA_ACME_CHECK_INTERVAL_SECS", "s3cr3t-leak"),
        ]))
        .unwrap_err();
        assert!(!err.contains("s3cr3t-leak"), "raw value leaked: {err}");
        // Pin that this is the error we think it is. Without a positive
        // assertion the test passes for *any* unrelated failure — which it
        // silently did when R706 added a required field parsed ahead of this
        // one, and a purely-negative assertion could not notice.
        assert!(
            err.contains("CHECK_INTERVAL_SECS"),
            "must be the numeric-parse error, got {err}"
        );
    }

    // ── R706 (W294): the issued cert's access rule ──────────────────────────

    #[test]
    fn consumers_is_required_when_the_issuer_is_on() {
        // No default is possible here: permissive would make the fleet cert's
        // private key a bearer secret again, deny-all would mint a cert nobody
        // can mount. So it must be stated.
        let err = parse_issuer_config(env(&[
            ("YUBABA_ACME_DOMAIN", "yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
            (
                "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE",
                "/run/secrets/cf.token",
            ),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
        ]))
        .unwrap_err();
        assert!(err.contains("YUBABA_ACME_CONSUMERS"), "got {err}");
    }

    #[test]
    fn consumers_parses_lists_and_the_any_marker() {
        use workload_spec::secrets::SecretConsumer;

        let rule = parse_consumers("ingress").unwrap();
        assert!(rule.admits(&SecretConsumer::workload("ingress")));
        assert!(!rule.admits(&SecretConsumer::workload("something-else")));

        // Whitespace and empty entries are tolerated inside a real list.
        let rule = parse_consumers(" ingress , passway ,, ").unwrap();
        assert!(rule.admits(&SecretConsumer::workload("ingress")));
        assert!(rule.admits(&SecretConsumer::workload("passway")));

        // The deliberate escape hatch, case-insensitively.
        assert_eq!(parse_consumers("any"), Some(SecretAccess::AllowAny));
        assert_eq!(parse_consumers("ANY"), Some(SecretAccess::AllowAny));

        // Nothing usable → None, which the caller turns into a config error
        // rather than an accidental deny-all cert.
        assert_eq!(parse_consumers(""), None);
        assert_eq!(parse_consumers("   "), None);
        assert_eq!(parse_consumers(" , , "), None);
    }

    #[test]
    fn the_issued_cert_carries_its_rule() {
        // Both records the issuer writes must be stamped — a cert with a rule
        // and a key without one would be a half-closed door.
        let cfg = parse_issuer_config(env(&[
            ("YUBABA_ACME_DOMAIN", "yah.dev"),
            ("YUBABA_ACME_CONTACT_EMAIL", "ops@yah.dev"),
            (
                "YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE",
                "/run/secrets/cf.token",
            ),
            ("YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
            ("YUBABA_ACME_CONSUMERS", "passway"),
        ]))
        .unwrap()
        .unwrap();

        let kek = [5u8; 32];
        for record in [
            seal_cluster_secret(&kek, b"CERTPEM", 1, cfg.access.clone()),
            seal_cluster_secret(&kek, b"KEYPEM", 1, cfg.access.clone()),
        ] {
            assert!(record
                .access
                .admits(&workload_spec::secrets::SecretConsumer::workload("passway")));
            assert!(!record
                .access
                .admits(&workload_spec::secrets::SecretConsumer::workload("other")));
        }
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
            ("YUBABA_ACME_CONSUMERS", "ingress"),
            ("YUBABA_ACME_CHECK_INTERVAL_SECS", "soon"),
        ]))
        .unwrap_err();
        assert!(err.contains("CHECK_INTERVAL"), "got {err}");
    }
}
