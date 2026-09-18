//! Append-only JSONL journal of **measured** restore times (R850-T2).
//!
//! Path: `.yah/cloud/recovery.jsonl`, via [`crate::paths::recovery_journal`].
//! One record per restored *subject*; replay yields the last record per
//! `(workload, subject)`, summed into one [`WorkloadRecovery`] per workload.
//!
//! Same shape as [`crate::asset_journal`] — append-only JSONL, one `write` per
//! line so concurrent writers are safe, replayed to a map, a missing file
//! replaying to empty rather than erroring. Two deliberate differences:
//!
//! - **Synchronous.** [`crate::config::CloudConfig::load`] is sync and this
//!   journal is replayed from inside it, so `std::fs` rather than `tokio::fs`.
//!   There is no in-process `subscribe()` either: nothing watches a
//!   measurement the way the desktop panel watches an asset transition.
//! - **Nobody prunes it.** Append-only is the whole answer to retention: a
//!   stale measurement is *reported with its age*, never discarded, because a
//!   real timed restore from six weeks ago still beats an extrapolation from
//!   `MEASURED_HYDRATE_MB_PER_S` — one constant measured once on one host
//!   against one backend. See [`crate::topology::RecoveryEstimate`].
//!
//! ## The input is the helper's own output
//!
//! `turso-backup-hydrate` prints one JSON line describing what it restored
//! (`oss/turso-backup/src/bin/hydrate.rs::outcome_to_json`).
//! [`RecoveryRecord::from_helper_json`] parses *that* line, keyed off its field
//! names verbatim — `restored[].{subject,source,bytes,seconds}` — rather than a
//! re-typed parallel vocabulary that could drift from it silently.
//!
//! `cloud` takes no dependency on `turso-backup` (see the note on
//! [`crate::topology::DEFAULT_STREAM_RPO_SECONDS`] for why), so the coupling is
//! pinned from both sides by a byte-identical fixture: the literal in
//! `a_real_hydrate_line_parses_verbatim` here, and the full-line equality
//! assertion in that helper's own
//! `a_hydrated_outcome_reports_measured_bytes_and_seconds`.
//!
//! @yah:ticket(R850-T4, "Carry the hydrate measurement back over the kamaji wire so the recovery journal fills without an operator")
//! @yah:status(review)
//! @yah:at(2026-09-11T07:31:38Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P3c)
//! @yah:parent(R850)
//! @yah:next("R850-T2 shipped the journal and the reader end: `.yah/cloud/recovery.jsonl`, replayed by `CloudConfig::load` into `CloudConfig.recovery_measurements`, surfacing as `RecoveryEstimate::Measured` in `yah cloud topology`. What it did NOT ship is an automatic writer. Today the only way a measurement reaches the camp tree is a human running `yah cloud topology --record-hydrate <path|-> --workload <w> --node <n>` against a JSON line they copied out of a node's kamaji log. That works and is tested, but a planning surface nobody remembers to feed reports an extrapolation forever.")
//! @yah:next("THE SEAM, and why it was deliberately not taken in R850-T2. `kamaji::hydrate::run` already HAS the measurement in hand — it returns `HydrateResult::Proceed(Some(line))` carrying turso-backup-hydrate's JSON verbatim — and oss/kamaji/crates/kamaji-bin/src/server.rs:2086 does nothing with it but `info!`. Carrying it back to yubaba means widening the deploy response in oss/kamaji/crates/kamaji-proto/src/messages.rs and threading it through server.rs, and BOTH of those files were uncommitted-dirty in the shared working tree on 2026-09-10 and plausibly a live peer's. That is a scheduling reason, not a design objection — re-check `camp.roster` and the working tree before starting.")
//! @yah:next("WATCH THE WIRE SHAPE: kamaji-proto is positional postcard (R590-B3), the same constraint that pushed durability onto annotations rather than WorkloadSpec fields in R850-P4. Add the field in the way that crate already handles additive change; do not assume a struct field is free.")
//! @yah:next("ATTRIBUTION IS THE REAL WORK, not the transport. A journal record needs {workload, node} to be useful, and the helper's own JSON carries neither — the CLI seam takes them as flags for exactly that reason. Whatever lands here must attach the deploying node's name and the workload's name at the point where both are known, which is yubaba's side of the deploy, not the helper's.")
//! @yah:gotcha("DO NOT MAKE `topology::analyze` DO I/O — the same hard constraint R850-T2 held. analyze is a pure function of what `CloudConfig::load` read off the local tree, which is what makes it trustworthy in a test and is the contract `migrate::plan_migration` also holds. This ticket changes only how the journal FILLS; the read path is done and must not grow a network call.")
//! @yah:handoff("THE MEASUREMENT NOW REACHES `.yah/cloud/recovery.jsonl` WITHOUT A HUMAN. Seven hops, all on disk: `kamaji::hydrate::run` -> new `KamajiToYubaba::DeployAck { request_id, id, hydrate: Option<String> }` (kamaji-proto/src/messages.rs) -> `DeployResult.hydrate` -> yubaba's deploy response (yubaba/src/lib.rs:4712) -> `cloud-client`'s `WorkloadDeployResponse.hydrate` over JSON -> `cloud::recovery_journal::record_deploy_measurement` -> the journal R850-T2 built. The manual `yah cloud topology --record-hydrate` seam stays and is untouched.")
//! @yah:handoff("THE WIRE CHANGE IS A REAL BREAK AND IS BUMPED TO `ProtocolVersion::V10`, FOR TWO INDEPENDENT REASONS — the second one is the easy-to-miss one and is written into the version stanza. (1) An old peer cannot decode the new reply mid-deploy. (2) `AckKind::Deploy` was REMOVED rather than kept beside the new variant, and removing a variant RENUMBERS the remaining `AckKind` discriminants — so a V9 `Stop` ack would decode as `Probe`. The removal is deliberate under CLAUDE.md's pre-1.0 rule: two deploy-reply shapes where which one you got depended on which backend arm answered is exactly the shim that compounds, and deleting the variant made the compiler name all 20 call sites. The crate's own additive-change conventions were read first (appended VARIANTS ride `#[non_exhaustive]` unbumped; appended FIELDS are breaking — the V2/V4/V5/V6/V8/V9 stanzas; messages.rs:670 records the R746-B11 failure where an appended reply variant went unclassified, so the new one is classified in `reply_request_id` and added to `every_reply_variant_correlates_to_its_request`). The bump was verified to actually do something: server.rs:1373 refuses any `Hello` whose version != CURRENT with `UnsupportedVersion`, so skew is a named handshake refusal rather than a postcard error.")
//! @yah:handoff("ATTRIBUTION WAS THE REAL WORK, AND IT LANDED SOMEWHERE OTHER THAN THE BRIEF SAID — deliberately, with the reasoning written into the code at both ends. The brief said append in `oss/yubaba/`. Node-side yubaba cannot: it has no name for itself that `.yah/infra/machines/*.toml` would recognise, and it is not running in the camp tree the journal lives in. The first scope holding BOTH facts and sitting inside the camp tree is the CLI, which dialed a machine BY NAME to deploy a workload BY NAME — so the journal write is `record_hydrate_from_deploy` at app/yah/cli/src/cloud.rs:3827. Yubaba still does its half: it puts the line on the deploy response, and the cloud-client JSON leg is genuinely self-describing so `serde(default)` is compatible there, unlike the postcard leg.")
//! @yah:handoff("TWO CLI SITES, NOT ONE, AND THE CALL SITS AFTER THE STATUS MATCH. `handle_workload_deploy` and `handle_workload_rolling` — the rolling path matters MORE, because its destroy leaves the volume empty, so the redeploy IS the restore. The call is deliberately past the match arm: a real kamaji deploy answers \"deployed\" and only stub mode answers \"accepted\", so an arm-local call would have journaled exactly the deploys that ran nothing. The other four `deploy_workload` sites (passway, cloudflared, mesofact bundle, inner door) are unwired on purpose — hydrate-on-place only runs on kamaji's container-deploy path, so they structurally return `None`. A failed journal write WARNS and prints the line rather than erroring: the workload is already deployed by that point, and erroring would make an operator redeploy a live workload to fix bookkeeping.")
//! @yah:handoff("DISCOVERED WORK, FIXED IN THIS PASS RATHER THAN FILED. kamaji-bin/src/server.rs:1766 — `deploy_workload`'s `if let Ack{..}` gate records the R852-B4 spec digest; left unconverted after the variant removal it would have kept COMPILING and silently stopped recording digests on every deploy, which is a reconciler regression no test would have caught. (server.rs:1649 is the graceful-upgrade path and correctly stays `Ack`.) Also `attach_hydrate` decorates only a `DeployAck`, so a restore in front of a deploy that then FAILED measures nothing recoverable. `topology::analyze` is untouched: no I/O, no clock, no `Path` — only the fill path changed, which was this ticket's hard constraint.")
//! @yah:verify("LEADER RE-RAN EVERY GATE INDEPENDENTLY (@Ashguard:eclipse) rather than accepting the courier's counts, and all four agree. `cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib`: 1190 passed / 0 failed / 4 ignored (courier's pre-edit baseline 1187/0/4, so +3). `cargo test --manifest-path oss/kamaji/Cargo.toml --workspace`: every suite ok, 0 failed (kamaji-bin lib 234, kamaji lib 119, proto 33, plus the rest; baseline exit 0). `cargo check --workspace --all-targets` from the repo root: exit 0, warnings all pre-existing and none in the changed files. `scripts/check-schema-drift.sh` and `scripts/check-workload-spec-ts.sh`: both 'ok, in sync'. NOTE the yah-cloud invocation — a repo-root `cargo test -p yah-cloud` does NOT work; it is not a root workspace member and needs dev-deps.")
//! @yah:verify("THE END-TO-END SHAPE IS PINNED FROM BOTH ENDS, which matters because a re-encoded line would fail to parse only on the far side of a real restore. `sibling_wire_e2e` asserts the hydrate line survives the postcard wire BYTE-FOR-BYTE. `recovery_journal`'s new test drives `record_deploy_measurement` with `REAL_HYDRATE_LINE` — the same literal `oss/turso-backup/src/bin/hydrate.rs` asserts full-line equality against, the two-sided pin R850-T2 added — and replays it back to {workload, node, 12.25s, 1024 bytes}; that existing assertion is intact. Plus: a deploy that measured nothing writes no file at all, and a non-JSON reply errors naming both the workload and the node.")
//! @yah:verify("ONE FLAKE, CHECKED RATHER THAN ASSUMED, AND IT IS NOT THIS TICKET'S. `tenant_passway::deploy_arms_the_declared_socket_and_stop_releases_it` failed intermittently mid-run under `--all-features`; it passes 3/3 in isolation, the failing assertion is a post-`Stop` `TcpListener::bind` on a `free_port()`-chosen port, and nothing in this diff touches custody teardown. It is a port-reuse race between parallel passway tests. The leader's own full kamaji workspace re-run was green. Separately, a W298 skew advisory on the leader's re-run named oss/kamaji/crates/kamaji/src/cgroup.rs and oss/yah-base/crates/workload-spec/src/lib.rs as modified mid-run — both peers' files, neither touched by this ticket.")
//! @yah:gotcha("V10 IS ALREADY DEPLOYED TO A PRODUCTION RAFT VOTER, AHEAD OF THIS TICKET REACHING REVIEW. Reported by @Ashguard:coffee (session:91597c1e, R881-B7) on 2026-09-11 07:00 UTC: us-east-001 now runs kamaji AND yubaba 0.8.38-h5 built from this shared tree, so the V10 bump and the untracked recovery_journal.rs are live there. The node is healthy — /health reports version and kamaji_version both 0.8.38-h5, so the handshake agrees, and all five workloads are Running. TWO CONSEQUENCES. (1) V10 is DEPLOYED BUT UNRELEASED: rolling us-east-001 back to a published release (scripts/roll-node.sh) silently reverts it. (2) Shipping ONE HALF of {kamaji, yubaba} reproduces a real incident — it already happened an hour earlier: V10 kamaji met the node's released V9 yubaba, they misframed ('decode failed: frame too large: 542393671 > 1048576'), and yubaba fell back to its in-process containerd runtime WITH NO LOG LINE AT ALL; that runtime wires no netns, so two noisetable-account deploys came up with no address and no resolver while their service records still advertised 10.128.3.2. Filed as R881-B8. The V10 doc stanza predicted the skew precisely; what it could not predict is that the symptom presents as a NETWORKING bug rather than a protocol error. @Ashguard:coffee added a guard to scripts/hotship.sh refusing a one-sided ship when the tree's ProtocolVersion is ahead of the last `release v*` commit (--allow-proto-skew overrides, --no-restart downgrades to a warning).")

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The helper that produces the measurements this journal ingests today.
/// Recorded on every line so a second source of restore timings is
/// distinguishable in the journal without re-reading the code that wrote it.
pub const HELPER_TURSO_BACKUP_HYDRATE: &str = "turso-backup-hydrate";

/// A measurement older than this is *stale*: reported, with its age, and
/// flagged in the headline. Not discarded — see the module docs.
pub const STALE_AFTER_DAYS: i64 = 30;

/// One subject's measured restore, appended to `.yah/cloud/recovery.jsonl`.
///
/// `bytes` and `seconds` are the helper's own measured figures, copied
/// unmodified. `at` is when the measurement was **ingested** — the helper emits
/// no timestamp of its own, so for a line piped straight out of a restore this
/// is within seconds of the event, and for a replayed old log it is not. Use
/// [`RecoveryRecord::from_helper_json_at`] when the real time is known.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryRecord {
    pub at: DateTime<Utc>,
    pub workload: String,
    pub node: String,
    /// The durability tier the restore read from, when the operator said so.
    /// The helper does not print it — it reads `TIER` from its environment and
    /// emits per-subject `source` object keys instead — so this is `None`
    /// unless attributed at ingest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    pub subject: String,
    pub bytes: u64,
    pub seconds: f64,
    pub helper: String,
}

/// The helper's line, named exactly as it prints it. Private: the public shape
/// is [`RecoveryRecord`], and nothing outside this module should have to know
/// the helper's envelope.
/// `outcome`, `epoch`, `subjects` and the envelope `bytes`/`seconds` are
/// deliberately not read: the per-subject `restored` array is the measurement,
/// and a field this module ignores is one the helper is free to change.
/// Absent on every non-`hydrated` outcome (`already_populated`,
/// `nothing_in_the_store`, `refused`) — those are legitimate lines that carry
/// no measurement, and parse to zero records.
#[derive(Debug, Deserialize)]
struct HelperLine {
    #[serde(default)]
    restored: Vec<HelperSubject>,
}

#[derive(Debug, Deserialize)]
struct HelperSubject {
    subject: String,
    bytes: u64,
    seconds: f64,
}

impl RecoveryRecord {
    /// Parse one line of `turso-backup-hydrate` output into one record per
    /// restored subject, stamped with the current time.
    ///
    /// A well-formed line reporting no restore (`already_populated`, a refusal)
    /// yields an empty vec — that is an answer, not an error. Only a line that
    /// is not the helper's JSON at all is an `Err`.
    pub fn from_helper_json(line: &str, workload: &str, node: &str) -> Result<Vec<Self>> {
        Self::from_helper_json_at(line, workload, node, Utc::now())
    }

    /// [`from_helper_json`](Self::from_helper_json) with the ingest timestamp
    /// supplied — for tests, and for ingesting a log whose real time is known.
    pub fn from_helper_json_at(
        line: &str,
        workload: &str,
        node: &str,
        at: DateTime<Utc>,
    ) -> Result<Vec<Self>> {
        let parsed: HelperLine = serde_json::from_str(line.trim()).with_context(|| {
            format!(
                "parsing turso-backup-hydrate output as JSON (expected one object per line, \
                 with a `restored` array): {line:?}"
            )
        })?;
        Ok(parsed
            .restored
            .into_iter()
            .map(|s| Self {
                at,
                workload: workload.to_string(),
                node: node.to_string(),
                tier: None,
                subject: s.subject,
                bytes: s.bytes,
                seconds: s.seconds,
                helper: HELPER_TURSO_BACKUP_HYDRATE.to_string(),
            })
            .collect())
    }

    /// Attribute these records to a durability tier the helper did not print.
    pub fn with_tier(mut self, tier: impl Into<String>) -> Self {
        self.tier = Some(tier.into());
        self
    }
}

/// Every measured subject for one workload, plus the clock reading that dates
/// them.
///
/// `as_of` is captured at replay so that [`age_days`](Self::age_days) is a pure
/// function of already-read data: `topology::analyze` must not read a clock any
/// more than it may read a file.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkloadRecovery {
    pub workload: String,
    /// The node the most recent measurement was taken on. Measurements taken on
    /// different machines are all kept; this names the latest, because a
    /// restore time is a property of a host as much as of a database.
    pub node: String,
    /// Last record per subject, ordered by subject name.
    pub subjects: BTreeMap<String, RecoveryRecord>,
    /// Wall clock at replay time.
    pub as_of: DateTime<Utc>,
}

impl WorkloadRecovery {
    /// Total measured wall-clock seconds: the workload's restore is all of its
    /// subjects, and the helper measures them one at a time.
    pub fn seconds(&self) -> f64 {
        self.subjects.values().map(|r| r.seconds).sum()
    }

    /// Total measured bytes on disk after the restore.
    pub fn bytes(&self) -> u64 {
        self.subjects.values().map(|r| r.bytes).sum()
    }

    /// When the summed figure was measured — the **oldest** component, because
    /// a sum is only as fresh as its stalest part.
    pub fn measured_at(&self) -> DateTime<Utc> {
        self.subjects
            .values()
            .map(|r| r.at)
            .min()
            .unwrap_or(self.as_of)
    }

    /// Whole days between [`measured_at`](Self::measured_at) and `as_of`,
    /// floored at zero (a clock that went backwards is not negative age).
    pub fn age_days(&self) -> i64 {
        (self.as_of - self.measured_at()).num_days().max(0)
    }

    /// Whether the headline must say the figure may no longer describe the
    /// declared state.
    pub fn is_stale(&self) -> bool {
        self.age_days() > STALE_AFTER_DAYS
    }

    /// How many subjects the summed figure covers.
    pub fn subject_count(&self) -> usize {
        self.subjects.len()
    }

    /// The helper that produced the most recent record.
    pub fn helper(&self) -> &str {
        self.subjects
            .values()
            .max_by_key(|r| r.at)
            .map(|r| r.helper.as_str())
            .unwrap_or(HELPER_TURSO_BACKUP_HYDRATE)
    }
}

/// Append-only JSONL journal at `.yah/cloud/recovery.jsonl`.
pub struct RecoveryJournal {
    path: PathBuf,
}

impl RecoveryJournal {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Journal rooted at `<workspace_root>/.yah/cloud/recovery.jsonl`.
    pub fn at_workspace(workspace_root: &Path) -> Self {
        Self::new(crate::paths::recovery_journal(workspace_root))
    }

    /// Path to the journal file on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append records, one JSONL line each.
    ///
    /// Unlike [`crate::asset_journal::AssetStatusJournal::append`] this
    /// propagates its error: that one is a best-effort side note during a
    /// reconcile, whereas this is the entire point of the command the operator
    /// ran, and a measurement silently not written is one nobody takes again.
    pub fn append(&self, records: &[RecoveryRecord]) -> Result<()> {
        use std::io::Write;

        if records.is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut buf = String::new();
        for r in records {
            buf.push_str(&serde_json::to_string(r).context("serializing RecoveryRecord")?);
            buf.push('\n');
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening {}", self.path.display()))?;
        file.write_all(buf.as_bytes())
            .with_context(|| format!("writing to {}", self.path.display()))?;
        Ok(())
    }

    /// Replay the journal into one entry per workload, last record winning per
    /// `(workload, subject)`.
    ///
    /// Never errors: an absent journal — the state of every camp that has never
    /// timed a restore — replays to an empty map, exactly like an unsynced
    /// infra source overlays nothing in `CloudConfig::load`. An unparseable
    /// line is skipped with a warning rather than failing the whole load.
    pub fn replay(&self) -> BTreeMap<String, WorkloadRecovery> {
        self.replay_as_of(Utc::now())
    }

    /// [`replay`](Self::replay) with the clock supplied, so ages are
    /// deterministic in tests.
    pub fn replay_as_of(&self, now: DateTime<Utc>) -> BTreeMap<String, WorkloadRecovery> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return BTreeMap::new(),
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    journal = %self.path.display(),
                    "recovery journal unreadable — returning empty map",
                );
                return BTreeMap::new();
            }
        };

        let mut out: BTreeMap<String, WorkloadRecovery> = BTreeMap::new();
        for (lineno, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let record: RecoveryRecord = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        line = lineno + 1,
                        journal = %self.path.display(),
                        error = %e,
                        "skipping unparseable recovery journal line",
                    );
                    continue;
                }
            };
            let entry = out
                .entry(record.workload.clone())
                .or_insert_with(|| WorkloadRecovery {
                    workload: record.workload.clone(),
                    node: record.node.clone(),
                    subjects: BTreeMap::new(),
                    as_of: now,
                });
            // Last line wins per subject.
            entry.subjects.insert(record.subject.clone(), record);
        }
        // The most recently measured surviving record names the node — done
        // after the replay so a superseded line cannot leave its host behind.
        for entry in out.values_mut() {
            if let Some(latest) = entry.subjects.values().max_by_key(|r| r.at) {
                entry.node = latest.node.clone();
            }
        }
        out
    }
}

/// Journal the measurement a deploy just came back with (R850-T4).
///
/// This is the automatic half of the seam `yah cloud topology --record-hydrate`
/// is the manual half of: same parser, same journal, same record shape — the
/// only difference is that the line arrives on the deploy reply instead of
/// being copied out of a node's log by a human who remembered to look.
///
/// `hydrate` is whatever `WorkloadDeployResponse.hydrate` carried, so `None`
/// (no restore happened) and a line that restored nothing both end as
/// `Ok(0)` — an answer, not an error. The whole point is that a caller can
/// wire this into every deploy without first knowing whether the workload is
/// durable.
///
/// **Attribution happens here and can happen nowhere earlier.** The helper's
/// JSON names neither the workload nor the node; kamaji knows only a
/// `WorkloadId`; the node cannot name itself as the camp's machine files do.
/// The caller that dialed `node` to deploy `workload` is the first place both
/// facts are in one scope, which is why this takes them as arguments rather
/// than digging them out of the line.
///
/// Errors propagate for the same reason [`RecoveryJournal::append`]'s do: a
/// restore is a rare, unrepeatable event, and a measurement dropped silently
/// is one nobody takes again.
pub fn record_deploy_measurement(
    workspace_root: &Path,
    workload: &str,
    node: &str,
    hydrate: Option<&str>,
) -> Result<usize> {
    let Some(line) = hydrate else {
        return Ok(0);
    };
    let records = RecoveryRecord::from_helper_json(line, workload, node)
        .with_context(|| format!("recording the hydrate measurement {node} reported for {workload}"))?;
    RecoveryJournal::at_workspace(workspace_root).append(&records)?;
    Ok(records.len())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    /// Byte-identical to what `outcome_to_json` prints for the outcome built in
    /// `oss/turso-backup/src/bin/hydrate.rs`'s
    /// `a_hydrated_outcome_reports_measured_bytes_and_seconds` — that test
    /// asserts full-line equality against this same literal, so the two cannot
    /// drift without one of them going red.
    const REAL_HYDRATE_LINE: &str = concat!(
        r#"{"outcome":"hydrated","epoch":4,"subjects":1,"bytes":1024,"seconds":12.500,"#,
        r#""restored":[{"subject":"accounts.db","#,
        r#""source":"wl/acct/accounts.db/snapshots/snapshot-000.db","#,
        r#""bytes":1024,"seconds":12.250}]}"#,
    );

    fn at(days_ago: i64) -> DateTime<Utc> {
        now() - chrono::Duration::days(days_ago)
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 10, 12, 0, 0).unwrap()
    }

    fn record(workload: &str, subject: &str, bytes: u64, seconds: f64, days_ago: i64) -> RecoveryRecord {
        RecoveryRecord {
            at: at(days_ago),
            workload: workload.to_string(),
            node: "us-west-001".to_string(),
            tier: None,
            subject: subject.to_string(),
            bytes,
            seconds,
            helper: HELPER_TURSO_BACKUP_HYDRATE.to_string(),
        }
    }

    #[test]
    fn a_real_hydrate_line_parses_verbatim() {
        let records =
            RecoveryRecord::from_helper_json_at(REAL_HYDRATE_LINE, "acct", "us-west-001", now())
                .unwrap();
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.subject, "accounts.db");
        assert_eq!(r.bytes, 1024);
        assert_eq!(r.seconds, 12.25);
        assert_eq!(r.workload, "acct");
        assert_eq!(r.node, "us-west-001");
        assert_eq!(r.helper, HELPER_TURSO_BACKUP_HYDRATE);
        // The helper prints no tier; nothing invents one.
        assert_eq!(r.tier, None);
    }

    /// R850-T4, the end-to-end shape: what a deploy reply carries becomes a
    /// journal entry `yah cloud topology` reads back as a Measured estimate,
    /// with the workload and the node attached.
    ///
    /// The fixture is the helper's REAL emitted line — the same constant
    /// `oss/turso-backup/src/bin/hydrate.rs` asserts full-line equality against
    /// — because the producer and the consumer of this line live in crates that
    /// deliberately do not depend on each other. A hand-written approximation
    /// would let `outcome_to_json` change shape and leave this green while
    /// every real restore silently failed to journal.
    ///
    /// It is deliberately driven through `record_deploy_measurement` rather
    /// than `from_helper_json` + `append`: the thing under test is the whole
    /// automatic path, including that attribution is applied at ingest and that
    /// replay keys on it.
    #[test]
    fn a_measurement_off_the_deploy_wire_lands_as_a_replayable_record() {
        let dir = tempdir().unwrap();

        // What kamaji put on the DeployAck, verbatim, as the CLI would hand it
        // over having dialed us-west-001 by name to deploy `acct`.
        let written =
            record_deploy_measurement(dir.path(), "acct", "us-west-001", Some(REAL_HYDRATE_LINE))
                .unwrap();
        assert_eq!(written, 1, "the line restored one subject");

        let replayed = RecoveryJournal::at_workspace(dir.path()).replay_as_of(now());
        let acct = replayed
            .get("acct")
            .expect("the workload the deploy named must be replayable by that name");
        assert_eq!(acct.node, "us-west-001", "the node must survive the round trip");
        assert_eq!(acct.subject_count(), 1);
        assert_eq!(acct.seconds(), 12.25, "the helper's own measured seconds");
        assert_eq!(acct.bytes(), 1024);
        assert_eq!(acct.helper(), HELPER_TURSO_BACKUP_HYDRATE);
        assert!(!acct.is_stale(), "a measurement taken just now is not stale");
    }

    /// A deploy that restored nothing must not write a line, and must not be an
    /// error either — this runs on EVERY deploy, and the overwhelming majority
    /// of them place a workload that declares no durability tier at all.
    #[test]
    fn a_deploy_that_measured_nothing_writes_no_journal_at_all() {
        let dir = tempdir().unwrap();
        let journal = RecoveryJournal::at_workspace(dir.path());

        assert_eq!(
            record_deploy_measurement(dir.path(), "marketing", "us-west-001", None).unwrap(),
            0
        );
        assert_eq!(
            record_deploy_measurement(
                dir.path(),
                "marketing",
                "us-west-001",
                Some(r#"{"outcome":"already_populated"}"#),
            )
            .unwrap(),
            0
        );
        assert!(
            !journal.path().exists(),
            "nothing was measured, so no journal file should have been created"
        );
        assert!(journal.replay_as_of(now()).is_empty());
    }

    /// A node that answered with something that is not the helper's JSON is an
    /// error the caller sees, not a silently-dropped measurement. The deploy
    /// itself already succeeded by then, so this cannot mean "fail the deploy"
    /// — it means the operator is told the measurement did not land.
    #[test]
    fn a_reply_that_is_not_the_helpers_json_is_an_error_naming_the_workload() {
        let dir = tempdir().unwrap();
        let err = record_deploy_measurement(dir.path(), "acct", "us-west-001", Some("not json"))
            .unwrap_err();
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("acct") && rendered.contains("us-west-001"),
            "the error must name what it failed to record: {rendered}"
        );
    }

    #[test]
    fn an_outcome_that_restored_nothing_is_zero_records_not_an_error() {
        for line in [
            r#"{"outcome":"already_populated"}"#,
            r#"{"outcome":"nothing_in_the_store","epoch":4,"subjects":["a.db"]}"#,
            r#"{"outcome":"refused","reason":"torn_volume","message":"whatever"}"#,
        ] {
            let records = RecoveryRecord::from_helper_json_at(line, "w", "n", now()).unwrap();
            assert!(records.is_empty(), "{line}");
        }
    }

    #[test]
    fn a_line_that_is_not_the_helpers_json_is_an_error() {
        let err = RecoveryRecord::from_helper_json_at("hydrating /var/lib/...", "w", "n", now())
            .unwrap_err();
        assert!(format!("{err:#}").contains("turso-backup-hydrate"), "{err:#}");
    }

    #[test]
    fn an_absent_journal_replays_to_empty() {
        let tmp = tempdir().unwrap();
        let j = RecoveryJournal::at_workspace(tmp.path());
        assert!(!j.path().exists());
        assert!(j.replay().is_empty());
    }

    #[test]
    fn a_workloads_figure_is_the_sum_of_its_subjects() {
        let tmp = tempdir().unwrap();
        let j = RecoveryJournal::at_workspace(tmp.path());
        j.append(&[
            record("acct", "accounts.db", 1024, 12.25, 1),
            record("acct", "ledger.db", 2048, 7.75, 1),
            record("other", "x.db", 16, 1.0, 1),
        ])
        .unwrap();

        let map = j.replay_as_of(now());
        assert_eq!(map.len(), 2);
        let acct = &map["acct"];
        assert_eq!(acct.subject_count(), 2);
        assert_eq!(acct.bytes(), 3072);
        assert!((acct.seconds() - 20.0).abs() < 1e-9, "{}", acct.seconds());
        assert_eq!(acct.age_days(), 1);
        assert!(!acct.is_stale());
        assert_eq!(acct.node, "us-west-001");
    }

    #[test]
    fn the_last_record_for_a_subject_wins_and_nothing_is_pruned() {
        let tmp = tempdir().unwrap();
        let j = RecoveryJournal::at_workspace(tmp.path());
        j.append(&[record("acct", "accounts.db", 1024, 99.0, 40)])
            .unwrap();
        j.append(&[record("acct", "accounts.db", 4096, 3.5, 2)])
            .unwrap();

        // Both lines are still on disk — append-only, nobody prunes.
        let raw = std::fs::read_to_string(j.path()).unwrap();
        assert_eq!(raw.lines().count(), 2);

        let acct = &j.replay_as_of(now())["acct"];
        assert_eq!(acct.subject_count(), 1);
        assert_eq!(acct.bytes(), 4096);
        assert!((acct.seconds() - 3.5).abs() < 1e-9);
        assert_eq!(acct.age_days(), 2);
    }

    #[test]
    fn a_sum_is_only_as_fresh_as_its_stalest_subject() {
        let tmp = tempdir().unwrap();
        let j = RecoveryJournal::at_workspace(tmp.path());
        j.append(&[
            record("acct", "accounts.db", 1024, 12.0, 90),
            record("acct", "ledger.db", 2048, 8.0, 1),
        ])
        .unwrap();

        let acct = &j.replay_as_of(now())["acct"];
        assert_eq!(acct.age_days(), 90);
        assert!(acct.is_stale());
        // Stale, and still reported in full — never discarded.
        assert!((acct.seconds() - 20.0).abs() < 1e-9);
    }

    #[test]
    fn an_unparseable_line_is_skipped_not_fatal() {
        let tmp = tempdir().unwrap();
        let j = RecoveryJournal::at_workspace(tmp.path());
        j.append(&[record("acct", "accounts.db", 1024, 12.0, 1)])
            .unwrap();
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(j.path())
                .unwrap();
            writeln!(f, "{{not json").unwrap();
        }
        let map = j.replay_as_of(now());
        assert_eq!(map["acct"].subject_count(), 1);
    }

    #[test]
    fn a_record_round_trips_through_the_journal_line() {
        let r = record("acct", "accounts.db", 1024, 12.25, 3).with_tier("stream");
        let line = serde_json::to_string(&r).unwrap();
        assert!(line.contains("\"tier\":\"stream\""), "{line}");
        assert_eq!(serde_json::from_str::<RecoveryRecord>(&line).unwrap(), r);
    }
}
