//! File-backed raft storage for yubaba.
//!
//! Both `YubabaLogStore` (log entries + vote) and `YubabaStateMachine`
//! (applied state + snapshot) use JSON files under a configurable
//! directory (`raft_dir`).  State is tiny (KB-scale) so we can afford
//! to rewrite the full file on every mutation — no append-log format
//! needed at this scale.
//!
//! File layout:
//! ```text
//! {raft_dir}/
//!   raft_vote.json      — persisted Vote
//!   raft_log.json       — BTreeMap<u64, Entry>
//!   raft_state.json     — StateMachineData (YubabaState + meta)
//!   raft_meta.json      — LogMeta (last_purged_log_id + committed)
//! ```
//!
//! Every one of those is rewritten whole through [`write_atomic`] — temp file,
//! fsync, rename — because [`YubabaLogStore::open`] refuses to start on a file
//! it cannot parse, and a plain `write` that is interrupted leaves exactly such
//! a file.
//!
//! openraft 0.10 notes: storage methods now fail with plain [`std::io::Error`]
//! (not the old `StorageError`); ids/votes/memberships are the `…Of<C>` type
//! aliases; `RaftStateMachine::apply` consumes a stream of `(entry, responder)`
//! and each entry's response is delivered through its [`ApplyResponder`]; and
//! `SnapshotData` (a `Cursor<Vec<u8>>` here) lives on the state machine /
//! network, not the type config.
//!
//! [`ApplyResponder`]: openraft::storage::ApplyResponder
//!
//! @yah:ticket(R841-B1, "raft store never persists last_purged_log_id — a voter that has purged its log cannot cold-start")
//! @yah:status(review)
//! @yah:at(2026-08-31T16:02:08Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R841)
//! @yah:severity(critical)
//! @yah:next("MECHANISM: `last_purged_log_id` (store.rs:64) is in-memory only. Initialized to None on load (store.rs:120), written solely by `purge()` (store.rs:196), never serialized — the raft dir holds only raft_log.json / raft_state.json / raft_vote.json. So `get_log_state()` (store.rs:147) reports `last_purged_log_id: None` on every cold start, telling openraft the log begins at index 0; openraft reads LogIndex(0), which purge deleted, and the process exits 1.")
//! @yah:next("Tier: Wizard — openraft storage-contract semantics plus a migration for already-purged on-disk logs; getting the reconstruction wrong re-breaks startup on live voters.")
//! @yah:gotcha("LIVE INCIDENT 2026-08-31: all three production raft voters (us-west-001, us-south-001, us-east-001) failed to restart with `Error: when Read LogIndex(0): log entry not found` and crash-looped under systemd. Reproduced identically on yubaba 0.8.28 AND 0.8.29 — not release-specific, and NOT caused by the 0.8.29 upgrade that surfaced it. On-disk raft_log.json held indices 189000-193466; everything below 189000 had been purged. The fleet had been up continuously since ~2026-07-20, so a cold start had never been exercised — it was one reboot from unbootable for weeks.")
//! @yah:handoff("LANDED. last_purged_log_id (and the optional committed watermark) now persist to a new raft_meta.json in the raft dir, written by purge() and save_committed(). A voter that has purged its log cold-starts.")
//! @yah:handoff("THE MIGRATION GUESSES NOTHING, which was the ticket's stated Wizard-tier risk. Two facts pin the marker exactly: purging leaves no hole (so the purge point is first_index-1), and everything at or below it is applied, hence committed, hence its log id is cluster-canonical. Two exact cases, no third: last_applied.index == first_index-1 means last_applied IS the purged log id; last_applied.index >= first_index means the first surviving entry is itself already applied, so its own log id is an exact marker (the entry stays on disk, harmlessly - openraft only ever reads purged+1..). No term is ever invented.")
//! @yah:handoff("A last_applied below first_index-1 is a genuine hole and open() now REFUSES with an actionable message naming all four raft files, rather than fabricating a term openraft would fail every consistency check against.")
//! @yah:handoff("ORDERING IS LOAD-BEARING in purge(): the marker is written BEFORE the entries are removed. Dying between the two leaves entries at or below the marker on disk, which openraft never reads and the next purge sweeps. Dying with the log ahead of the marker is exactly the unbootable state this ticket exists for.")
//! @yah:handoff("DISCOVERED WORK 1, done in this pass: save_committed() was also in-memory-only, so read_committed() returned None on every restart. openraft's trait calls persisting it optional but recommended - without it a restarted node recovers only to its snapshot and can serve a read OLDER than one it already served pre-restart. Now persisted in the same file, skipping the write when the watermark is unchanged.")
//! @yah:handoff("DISCOVERED WORK 2: all four raft files now go through write_atomic() (temp file, fsync, rename, dir fsync) instead of std::fs::write. Same failure class as this ticket - open() refuses to start on a file it cannot parse, so an interrupted plain write turns the daemon into a crash loop with nothing to recover from. Zero on-disk format change; only the path there.")
//! @yah:handoff("DISCOVERED WORK 3, and this one is a footgun this change would otherwise have INTRODUCED. The 2026-08-31 recovery runbook says 'wipe raft_log/raft_state/raft_vote.json' - it predates raft_meta.json, so running it from memory now leaves a purge marker over an empty log. MEASURED: get_initial_state still succeeds, then the founding init panics inside openraft's own validit invariant (expect: purged(Some(index 5)) <= snapshot.flushed()(None), io_state.rs:181). open() now detects that exact shape (marker present, log empty, no raft_state.json) and drops the marker. raft/mod.rs::open_with_state_machine's raft_dir doc now names all four files as one unit.")
//! @yah:verify("cargo test -p yubaba --lib = 561 passed / 0 failed (560 before, +1 net new store test; 9 tests now in raft::store::tests, was 1).")
//! @yah:verify("FALSIFIED, not assumed. Forcing open() to hand back last_purged_log_id: None (the pre-fix behaviour) fails a_purged_log_can_still_produce_an_initial_state with StorageError { subject: LogIndex(0), verb: Read, source: log entry not found } - the production error verbatim - and takes the three marker tests with it, while the hole and committed tests stay green. Probe removed; recorded in that test's doc comment.")
//! @yah:verify("FALSIFIED SEPARATELY: disabling the wiped-dir marker drop makes a_marker_left_behind_by_a_partial_wipe_is_dropped panic in openraft's validit invariant at cluster founding. That is why that test pays for a real raft node instead of stopping at get_initial_state, which passes either way.")
//! @yah:verify("cargo test -p yubaba --test main raft_ -- --test-threads=1 = 41 passed / 0 failed, matching the recorded serial baseline. (Run serially per R734-T1's gotcha: the ten raft suites share one test binary and spin five-node clusters concurrently.)")
//! @yah:verify("cargo test -p xtask --test main cluster_epoch = 8 passed / 0 failed after re-recording.")
//! @yah:verify("cargo clippy -p yubaba --all-targets: no new warnings. The three hits on store.rs (clone_on_copy x2 in read_vote/save_vote, derivable_impls on StateMachineData) are all pre-existing and on lines this change does not touch.")
//! @yah:verify("rustfmt --edition 2021 --check on both edited files: clean on every hunk of this change. The two remaining deviations (store.rs pub fn tenants, mod.rs rpo_bound assert) are both present at HEAD and were left alone - shared tree.")
//! @yah:gotcha("EPOCH VERDICT: state_epoch stays 4, surface re-recorded (5d01cc38... -> 7811ac8f...). raft/store.rs is a state_epoch surface input so the gate went red; the NOT-BREAKING call and its reasoning are in oss/yubaba/crates/yubaba/cluster-epochs.json surface_rerecords[2026-08-31]. Short form: new-reads-old IS the fix (the migration), old-reads-new is a no-op (a pre-R841 binary opens the other three files by exact name and never looks at raft_meta.json, and none of their schemas changed), and no replicated type moved. cluster_protocol was untouched and stayed green - store.rs is not one of its inputs.")
//!
//! @yah:ticket(R836-B2-B1, "open() trusts a present last_purged_log_id without checking it against the log's first index, so a rollback across a purge leaves a stale marker")
//! @yah:at(2026-09-02T23:19:15Z)
//! @yah:status(open)
//! @yah:parent(R836-B2)
//! @yah:severity(medium)
//! @yah:next("In open(), validate a PRESENT meta.last_purged_log_id against entries.first(). Today the recovery arms are asymmetric: is_none() reconstructs from raft_state.json, and the wiped-dir case (entries empty, no raft_state.json) drops the marker, but a marker that is present and WRONG is trusted verbatim. The check is cheap and local: if the marker's index+1 != first surviving index, the same reconstruct_last_purged reasoning already in this file says which value is right.")
//! @yah:next("Reachable sequence, all three legs supported today: roll a node forward to a build that writes raft_meta.json; roll it back to a pre-R841-B1 build, which purges without knowing the file exists; roll forward again. The marker now names a purge point BELOW where the log starts, openraft reads a deleted entry, and the node exits with the same 'log entry not found' R841-B1 was filed to fix.")
//! @yah:verify("A test in this file's suite: write a raft dir with a purge marker at index N, truncate the log so it starts at M > N+1, open() and assert the marker is corrected or the open refuses with a message naming the mismatch. The existing a_purged_log_can_still_produce_an_initial_state and the wiped-dir test are the shape to follow.")
//! @yah:gotcha("NOT AN EPOCH QUESTION and do not re-open one. state_epoch was settled NOT BREAKING on 2026-09-02 (cluster-epochs.json surface_rerecords, closing R836-B2): new-reads-old migrates exactly, old-reads-new never opens the file, nothing replicated moved. Bumping the epoch would not fix this shape — it would only forbid the rollback that produces it, and the code is what should be robust to it.")
//! @yah:gotcha("FAILS LOUDLY, which is why this is medium and not high: the node refuses to start with a storage error. No divergence, no stale read served, no silent corruption.")
//! @yah:tier(Wizard)
//!
//! @yah:relay(R869, "Raft state has no off-fleet copy: total node loss is unrecoverable, and rebuilding resets tenant fencing epochs")
//! @yah:at(2026-09-05T20:18:22Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @yah:next("ESTABLISH THE RECOVERY SEMANTICS FIRST, before any replicator code. The operator's stated constraint (2026-09-05) is that downtime and DATA LOSS are both acceptable, but losing TRACK of state required for cluster health is not, and the acceptance property is 'delete every machine and move to new hardware'. That budget says this ticket is not about durability of the log — it is about being able to reconstitute a correct cluster on new hardware without a silent split-brain. Those are different designs and the cheaper one is probably sufficient: a periodic snapshot of the applied YubabaState plus a monotonic epoch floor, not continuous log streaming.")
//! @yah:next("CHECK WHETHER AN EPOCH FLOOR ALONE CLOSES THE CORRECTNESS HALF. If the fresh cluster starts every tenant epoch above the highest value any survivor could hold, the resurrected-node hazard dies without restoring the log at all. The floor has to come from somewhere off-fleet and monotonic — the R2 sink already stores watermarks per tenant, so the number may already exist in the bucket. If so, the whole ticket collapses to 'read the floor at founding init', which is dramatically smaller than a replicator.")
//! @yah:next("THEN decide what else is worth carrying. members / ingress_owner / service_placement are re-derivable from declared config plus a fresh election; rollouts is in-flight state that a rebuild can legitimately abandon; secrets is re-seedable from the fob vault but doing it by hand for N secrets is exactly the 'losing track' the operator ruled out, so a re-seed-from-declarations command is a candidate deliverable on its own.")
//! @yah:next("ACCEPTANCE IS THE CHAOS TEST, not a unit test — the operator is standing up a chaos-monkey practice on the dev cluster and destroying nodes routinely as of 2026-09-05. Sign-off is: destroy every voter, rebuild from camp + R2, and prove (a) the cluster serves, (b) an intentionally-resurrected old node with a stale-high epoch is REFUSED rather than winning. (b) is the one that matters and is the one a happy-path rebuild test will silently skip.")
//! @yah:gotcha("THE HAZARD IS FENCING EPOCHS, NOT THE DATA — read this before scoping, because it changes what 'recovery' has to mean. raft/mod.rs:98 states the single-writer invariant: 'a stale-high token cannot exist (only committed entries reach the state machine)'. That holds for every failure mode EXCEPT rebuild-from-nothing. Wipe the raft dir and re-form, and tenant epochs restart low; a node that comes back from the dead holding a HIGHER epoch then out-fences the fresh cluster at the R2 sink and legitimately wins. So a recovery design that only restores the DATA reintroduces the split-brain the epochs exist to prevent. Any scheme here must either restore epochs monotonically or bump them past any possible survivor.")
//! @yah:gotcha("THIS HAS ALREADY HAPPENED ONCE, by accident rather than hardware loss — store.rs:40 records it. 2026-08-31: all three production voters (us-west-001, us-south-001, us-east-001) failed to restart with 'when Read LogIndex(0): log entry not found' and crash-looped under systemd. Reproduced on 0.8.28 AND 0.8.29, so not release-specific. The fleet had been up since ~2026-07-20, so a cold start had never been exercised — it was one reboot from unbootable for weeks. Recovery was wiping the raft dir. So the de-facto total-loss procedure today IS 'lose this state', undesigned. Treat that incident as the acceptance scenario, not a footnote.")
//! @yah:gotcha("SCOPE IT BY WHAT ACTUALLY DIES, so nobody rebuilds something that is already safe. SURVIVES total fleet loss and needs nothing: the cluster KEK (fob vault slot cluster-kek, off-fleet), declared secret plaintexts (fob vault, 4 slots, declarations in .yah/infra/secrets/*.toml), machine config (.yah/infra/machines/*.toml + mirror.yml), and — importantly — certs AND the enrollment set, because cert_store.rs is yah_object_store-backed (R2) by R779 Decision 1, which deliberately kept 10k certs out of raft. DIES: YubabaState's members, service_placement, locks, ingress_owner, rollouts, secrets (re-seedable from the vault, so recoverable but not automatic), and tenant ownership + epochs. The genuinely-irrecoverable set is therefore SMALL — which is why this is a bounded ticket and not a redesign.")
//! @yah:gotcha("COST IS LOW, WHICH IS THE ARGUMENT FOR DOING IT PROPERLY RATHER THAN DEFERRING. raft/store.rs's own module docs say state is KB-scale and persist() rewrites the whole file on every mutation, so an off-fleet copy is small and cheap. Do NOT reach for litestream here: that replicates a sqlite DB and this is four JSON files. oss/turso-backup already implements the R2 side of exactly this shape (frame keys, manifests, watermark CAS, epoch comparison) and raft/mod.rs:134 records a test driving a real turso-backup BackupTarget over an in-memory object store — check whether that machinery generalizes before writing a new replicator.")

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::{self, Cursor, Write};
use std::ops::RangeBounds;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use openraft::storage::{
    EntryResponder, IOFlushed, LogState, RaftLogReader, RaftLogStorage, RaftSnapshotBuilder,
    RaftStateMachine,
};
use openraft::type_config::alias::{
    EntryOf, LogIdOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf, VoteOf,
};
use openraft::{EntryPayload, OptionalSend, Snapshot, SnapshotMeta, StoredMembership};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_stream::{Stream, StreamExt};

use super::super::raft::apply;
use super::{YubabaRaftConfig as TC, YubabaRequest, YubabaResponse, YubabaState};

/// Snapshot payload handle. Yubaba state is KB-scale, so the whole snapshot is
/// an in-memory JSON blob behind a cursor — the same on both the state machine
/// and the network transport (`RaftNetworkV2::SnapshotData`).
type SnapshotData = Cursor<Vec<u8>>;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Wrap any displayable error as an `io::Error` — the 0.10 storage traits fail
/// with `io::Error`, so serialization failures funnel through here.
fn io_other<E: Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Replace `path`'s contents with `bytes` atomically: write a sibling temp
/// file, fsync it, rename it over the target, then fsync the directory so the
/// rename itself is durable.
///
/// Every file in the raft dir is rewritten whole on each mutation, and
/// [`YubabaLogStore::open`] / [`YubabaStateMachine::open`] both `?` on a parse
/// failure — so a `std::fs::write` interrupted midway (OOM kill, power cut, a
/// full disk) leaves a truncated JSON document that turns the daemon into a
/// crash loop with nothing left to recover from. A rename is atomic, so a
/// reader sees either the whole previous document or the whole new one.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

// ── Log store ─────────────────────────────────────────────────────────────────

/// Durable log metadata that cannot be re-derived from the entries themselves
/// (`raft_meta.json`).
///
/// R841-B1: `last_purged_log_id` used to live only in memory. Purging *deletes*
/// the entries it covers, so after a restart the store reported
/// `last_purged_log_id: None` over a log that no longer began at index 0.
/// openraft's `StorageHelper::get_key_log_ids` then reads
/// `purged.next_index()` — index 0 — finds nothing, and `Raft::new` fails with
/// `when Read LogIndex(0): log entry not found`. Every production voter was one
/// reboot from unbootable for six weeks before a rolling upgrade found it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct LogMeta {
    /// The greatest log id purged out of `raft_log.json`.
    #[serde(default)]
    last_purged_log_id: Option<LogIdOf<TC>>,
    /// The committed watermark openraft last handed us. Persisting this is
    /// optional per `RaftLogStorage::save_committed`, but skipping it means a
    /// restarted node recovers only as far as its snapshot and can serve a read
    /// *older* than one it already served before the restart.
    #[serde(default)]
    committed: Option<LogIdOf<TC>>,
}

struct LogStoreInner {
    last_purged_log_id: Option<LogIdOf<TC>>,
    /// Log entries kept after the last purge.
    entries: BTreeMap<u64, EntryOf<TC>>,
    committed: Option<LogIdOf<TC>>,
    vote: Option<VoteOf<TC>>,
    base_dir: PathBuf,
}

impl LogStoreInner {
    fn persist_log(&self) -> Result<(), io::Error> {
        let json = serde_json::to_string(&self.entries).map_err(io_other)?;
        write_atomic(&self.base_dir.join("raft_log.json"), json.as_bytes())
    }

    fn persist_vote(&self) -> Result<(), io::Error> {
        let json = serde_json::to_string(&self.vote).map_err(io_other)?;
        write_atomic(&self.base_dir.join("raft_vote.json"), json.as_bytes())
    }

    /// Persist `raft_meta.json` (R841-B1).
    fn persist_meta(&self) -> Result<(), io::Error> {
        let meta = LogMeta {
            last_purged_log_id: self.last_purged_log_id,
            committed: self.committed,
        };
        let json = serde_json::to_string(&meta).map_err(io_other)?;
        write_atomic(&self.base_dir.join("raft_meta.json"), json.as_bytes())
    }
}

/// Rebuild `last_purged_log_id` for a log left behind by a binary that never
/// persisted one (R841-B1).
///
/// **The term is never guessed.** Two facts pin the marker exactly:
///
/// - purging leaves no hole, so whatever was purged ends at `first_index - 1`;
/// - everything at or below the purge point has been applied, and an applied
///   entry is committed, so its log id is the cluster-canonical one for that
///   index — no two replicas disagree about it.
///
/// That gives two exact answers and no third:
///
/// - `last_applied.index == first_index - 1` — `last_applied` *is* the purged
///   log id, term included.
/// - `last_applied.index >= first_index` — the first surviving entry is itself
///   already applied, so adopting **its** log id as the marker is exact. The
///   entry stays on disk, harmlessly: openraft only ever reads `purged + 1 ..`,
///   and the next purge sweeps it.
///
/// A `last_applied` below `first_index - 1` is a hole — the state machine is
/// missing entries the log no longer holds, and no marker makes that replica
/// startable. Refuse loudly rather than invent one; a wrong term here would
/// hand openraft a consistency check that silently never matches.
fn reconstruct_last_purged(
    dir: &Path,
    entries: &BTreeMap<u64, EntryOf<TC>>,
) -> anyhow::Result<Option<LogIdOf<TC>>> {
    // An empty log carries no evidence of a purge, and openraft closes that
    // case itself: `get_initial_state` purges up to `last_applied` when the log
    // is behind it, which routes through `purge()` and writes a marker.
    let Some((&first_index, first)) = entries.iter().next() else {
        return Ok(None);
    };
    if first_index == 0 {
        return Ok(None);
    }

    /// Just the one field we need out of `raft_state.json`. Serde ignores the
    /// rest, so this stays readable across state-machine schema moves.
    #[derive(Deserialize)]
    struct AppliedProbe {
        #[serde(default)]
        last_applied: Option<LogIdOf<TC>>,
    }

    let state_path = dir.join("raft_state.json");
    let last_applied = if state_path.exists() {
        serde_json::from_str::<AppliedProbe>(&std::fs::read_to_string(&state_path)?)?.last_applied
    } else {
        None
    };

    match last_applied {
        Some(applied) if applied.index + 1 == first_index => Ok(Some(applied)),
        Some(applied) if applied.index >= first_index => Ok(Some(first.log_id)),
        other => {
            let missing_from = other.map(|a| a.index + 1).unwrap_or(0);
            anyhow::bail!(
                "raft log in {dir} starts at index {first_index} but the state machine has applied \
                 only up to {other:?}: entries {missing_from}..{first_index} were purged before \
                 they were applied, so this replica cannot be rebuilt from its own files. Restore \
                 the raft dir from a backup, or stop yubaba, delete raft_log.json / \
                 raft_state.json / raft_vote.json / raft_meta.json, and re-join the cluster from \
                 an empty log.",
                dir = dir.display(),
            )
        }
    }
}

/// Log storage: clone-able via the inner `Arc<RwLock<>>` so the same
/// instance serves as both `LogStore` and `LogReader`.
#[derive(Clone)]
pub struct YubabaLogStore {
    inner: Arc<RwLock<LogStoreInner>>,
}

impl YubabaLogStore {
    /// Open or create the log store in `dir`.
    pub async fn open(dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;

        let vote: Option<VoteOf<TC>> = {
            let p = dir.join("raft_vote.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                None
            }
        };

        let entries: BTreeMap<u64, EntryOf<TC>> = {
            let p = dir.join("raft_log.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                BTreeMap::new()
            }
        };

        let mut meta: LogMeta = {
            let p = dir.join("raft_meta.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                LogMeta::default()
            }
        };

        // R841-B1 migration. A log written by a binary that never persisted the
        // purge marker begins above index 0 with nothing on disk to explain
        // why; `reconstruct_last_purged` recovers the marker exactly (or
        // refuses). Runs whenever the marker is absent rather than only when
        // `raft_meta.json` is, so a meta file that predates the node's first
        // purge is covered too.
        if meta.last_purged_log_id.is_none() {
            if let Some(recovered) = reconstruct_last_purged(&dir, &entries)? {
                tracing::warn!(
                    last_purged_log_id = ?recovered,
                    dir = %dir.display(),
                    "raft log starts above index 0 with no purge marker on disk; reconstructed it \
                     from the applied state (R841-B1)"
                );
                meta.last_purged_log_id = Some(recovered);
                let json = serde_json::to_string(&meta)?;
                write_atomic(&dir.join("raft_meta.json"), json.as_bytes())?;
            }
        } else if entries.is_empty() && !dir.join("raft_state.json").exists() {
            // A PARTIAL WIPE, and this file is why it needs handling. The
            // documented recovery from the 2026-08-31 incident is "stop yubaba,
            // delete raft_log/raft_state/raft_vote.json, restart, re-init" —
            // written before `raft_meta.json` existed, so anyone running it from
            // memory now leaves a purge marker standing over an empty log and an
            // empty state machine. openraft would then be told this node had
            // purged past index 0 with nothing applied, which no `raft init` can
            // satisfy: the marker survives the wipe and bricks the fresh node.
            //
            // An empty log with no state machine at all is unambiguously a fresh
            // node — the marker's own invariant is `last_purged <= last_applied`,
            // and there is no applied state for it to be under. Drop it. (The
            // milder shape, an empty log with a state machine BEHIND the marker,
            // needs nothing: openraft's `get_initial_state` purges up to
            // `last_applied` when the log is behind it, which rewrites the marker
            // through `purge()`.)
            tracing::warn!(
                stale_last_purged_log_id = ?meta.last_purged_log_id,
                dir = %dir.display(),
                "raft_meta.json holds a purge marker but the log and state machine are both \
                 absent; treating this as a wiped raft dir and dropping the marker (R841-B1)"
            );
            meta = LogMeta::default();
            let json = serde_json::to_string(&meta)?;
            write_atomic(&dir.join("raft_meta.json"), json.as_bytes())?;
        }

        Ok(Self {
            inner: Arc::new(RwLock::new(LogStoreInner {
                last_purged_log_id: meta.last_purged_log_id,
                entries,
                committed: meta.committed,
                vote,
                base_dir: dir,
            })),
        })
    }
}

impl RaftLogReader<TC> for YubabaLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<EntryOf<TC>>, io::Error> {
        let inner = self.inner.read().unwrap();
        Ok(inner.entries.range(range).map(|(_, e)| e.clone()).collect())
    }

    async fn read_vote(&mut self) -> Result<Option<VoteOf<TC>>, io::Error> {
        Ok(self.inner.read().unwrap().vote.clone())
    }
}

impl RaftLogStorage<TC> for YubabaLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TC>, io::Error> {
        let inner = self.inner.read().unwrap();
        let last_log_id = inner.entries.values().last().map(|e| e.log_id);
        Ok(LogState {
            last_purged_log_id: inner.last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &VoteOf<TC>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        inner.vote = Some(vote.clone());
        inner.persist_vote()
    }

    async fn append<I>(&mut self, entries: I, callback: IOFlushed<TC>) -> Result<(), io::Error>
    where
        I: IntoIterator<Item = EntryOf<TC>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        {
            let mut inner = self.inner.write().unwrap();
            for entry in entries {
                inner.entries.insert(entry.log_id.index, entry);
            }
            inner.persist_log()?;
        }
        callback.io_completed(Ok(()));
        Ok(())
    }

    async fn truncate_after(&mut self, last_log_id: Option<LogIdOf<TC>>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        // Remove everything strictly after `last_log_id` (exclusive). `None`
        // truncates the entire log.
        let keep_upto = last_log_id.map(|l| l.index);
        inner.entries.retain(|&idx, _| match keep_upto {
            Some(upto) => idx <= upto,
            None => false,
        });
        inner.persist_log()
    }

    async fn purge(&mut self, log_id: LogIdOf<TC>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        inner.last_purged_log_id = Some(log_id);
        // R841-B1: the marker goes down BEFORE the entries come out, and the
        // order is load-bearing. Dying between the two writes with the marker
        // ahead of the log leaves entries at or below it still on disk, which
        // openraft never reads (it only ever asks for `purged + 1 ..`) and the
        // next purge sweeps. Dying with the log ahead of the marker is exactly
        // the unbootable state this ticket exists for.
        inner.persist_meta()?;
        inner.entries.retain(|&idx, _| idx > log_id.index);
        inner.persist_log()
    }

    async fn save_committed(&mut self, committed: Option<LogIdOf<TC>>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        // Called on every commit advance; skip the write when it says nothing
        // new (openraft re-saves the same watermark on an idle heartbeat).
        if inner.committed == committed {
            return Ok(());
        }
        inner.committed = committed;
        inner.persist_meta()
    }

    async fn read_committed(&mut self) -> Result<Option<LogIdOf<TC>>, io::Error> {
        Ok(self.inner.read().unwrap().committed)
    }
}

// ── State machine ─────────────────────────────────────────────────────────────

/// Serialised form of the state machine — written to `raft_state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateMachineData {
    last_applied: Option<LogIdOf<TC>>,
    last_membership: StoredMembershipOf<TC>,
    state: YubabaState,
}

impl Default for StateMachineData {
    fn default() -> Self {
        Self {
            last_applied: None,
            last_membership: StoredMembership::default(),
            state: YubabaState::default(),
        }
    }
}

struct StateMachineInner {
    data: StateMachineData,
    /// The last snapshot we installed (if any).
    snapshot_meta: Option<SnapshotMetaOf<TC>>,
    snapshot_bytes: Option<Vec<u8>>,
    base_dir: PathBuf,
    /// R600-F4 (W273): bumped on every applied cluster-secret change
    /// (`PutSecret`/`DeleteSecret`) and on snapshot install, so a consumer task
    /// (rotation → live reload) can re-render the affected tmpfs mounts and
    /// graceful-upgrade the workload. Coarse epoch counter — a subscriber wakes
    /// on any bump and re-reads the current secrets map (re-render is
    /// idempotent), so coalesced bumps never lose a change.
    secrets_epoch: watch::Sender<u64>,
}

impl StateMachineInner {
    fn persist(&self) -> Result<(), io::Error> {
        let json = serde_json::to_string(&self.data).map_err(io_other)?;
        write_atomic(&self.base_dir.join("raft_state.json"), json.as_bytes())
    }
}

/// State machine storage — `Clone`-able via inner `Arc<RwLock<>>` so
/// it doubles as the `SnapshotBuilder`.
#[derive(Clone)]
pub struct YubabaStateMachine {
    inner: Arc<RwLock<StateMachineInner>>,
}

impl YubabaStateMachine {
    pub async fn open(dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;

        let data: StateMachineData = {
            let p = dir.join("raft_state.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                StateMachineData::default()
            }
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(StateMachineInner {
                data,
                snapshot_meta: None,
                snapshot_bytes: None,
                base_dir: dir,
                secrets_epoch: watch::channel(0).0,
            })),
        })
    }

    /// Subscribe to cluster-secret changes (R600-F4 / W273). The receiver's
    /// value is a coarse epoch counter bumped on every applied `PutSecret` /
    /// `DeleteSecret` and on snapshot install. Wake on a change and re-read the
    /// current state via [`Self::cluster_secret`] — the counter says *something*
    /// changed, not what, which is all the (idempotent) re-render needs.
    pub fn subscribe_secrets(&self) -> watch::Receiver<u64> {
        self.inner.read().unwrap().secrets_epoch.subscribe()
    }

    /// Read a cluster secret's ciphertext record from the local applied state
    /// (R600-F2 / W273). Returns a clone so the caller never holds the state
    /// lock while decrypting. `None` if no secret is stored under `name`.
    ///
    /// The record is AES-256-GCM ciphertext only (see [`super::SecretRecord`]);
    /// the state machine cannot itself read a secret's plaintext — decryption
    /// happens in `secrets::ClusterResolver` with the node-local KEK.
    pub fn cluster_secret(&self, name: &str) -> Option<super::SecretRecord> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .secrets
            .get(name)
            .cloned()
    }

    /// Metadata for every cluster secret in the local replica, as
    /// `(name, updated_at, access-rule summary, digest hex)` (R706 / R720-F1 /
    /// W294).
    ///
    /// **Deliberately returns no bytes for ciphertext.** This backs
    /// `GET /secrets` → `yah cloud secret ls`, whose job is to answer "what
    /// exists, who may mount it, when did it last change, does it match what
    /// the camp declares" — none of which needs the ciphertext, and the
    /// ciphertext is the one thing an operator listing must never casually
    /// hand out (it would put a KEK-compromise's whole decrypt corpus one
    /// unauthenticated GET away). The digest is served hex-encoded — it is
    /// already keyed (see `SecretRecord::digest`), so publishing it costs
    /// nothing an attacker without the KEK can use; `None` becomes `None`
    /// (pre-digest), never a stand-in hex value.
    pub fn cluster_secret_index(&self) -> Vec<(String, u64, String, Option<String>)> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .secrets
            .iter()
            .map(|(name, rec)| {
                (
                    name.clone(),
                    rec.updated_at,
                    rec.access.summary(),
                    rec.digest.as_deref().map(hex_encode),
                )
            })
            .collect()
    }

    // ── Locally-applied control-plane reads (R118-T1) ─────────────────────────
    //
    // The rig's non-negotiable rule (W138): nothing on the audio or graph path
    // may synchronously await a raft commit. So every question the realtime
    // side asks of the control plane — "who owns this role right now" — must be
    // answerable from the replica this process already holds: no quorum, no
    // leader round-trip, no `.await`. A node that has lost the cluster entirely
    // still answers, with its last-known-good view, and reports how stale that
    // view is via [`Self::applied_index`].
    //
    // These are the same shape as [`Self::cluster_secret`] above, which was the
    // first consumer of the idea; naming them here makes it the general
    // capability rather than a secrets-only affordance.

    /// Who holds the singleton role `key` in **this node's applied state**.
    ///
    /// `None` means no live claim is recorded locally — which is not the same
    /// as "nobody owns it cluster-wide", because this replica may be behind.
    /// Callers that care about the difference read [`Self::applied_index`]
    /// alongside it.
    ///
    /// Returns a clone so no caller holds the state lock while acting on the
    /// answer. Expiry is deliberately *not* evaluated here: TTL is judged
    /// against the acquiring node's clock inside [`apply`](super::apply), so a
    /// local reader inventing its own "expired" verdict would be a second,
    /// disagreeing authority. Read [`super::LockEntry::acquired_at`] +
    /// `ttl_secs` if you need to render staleness.
    pub fn singleton_owner(&self, key: &str) -> Option<super::LockEntry> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .locks
            .get(key)
            .cloned()
    }

    /// Every singleton role recorded in this node's applied state.
    pub fn singleton_owners(&self) -> BTreeMap<String, super::LockEntry> {
        self.inner.read().unwrap().data.state.locks.clone()
    }

    /// R732-T4 (W245): the fencing token `node` may stream `tenant` under, per
    /// this node's applied state. Delegates to
    /// [`YubabaState::tenant_fencing_token`](super::YubabaState::tenant_fencing_token)
    /// so the owner-and-lease predicate lives in exactly one place.
    ///
    /// This is a *local* read and may be stale — this replica might not yet
    /// have applied the entry that transferred the tenant away. That is safe
    /// by construction rather than by luck: acting on a stale answer means
    /// streaming under an old epoch, which the sink rejects
    /// (`turso_backup::stream::StreamOutcome::Fenced`). Staleness costs a
    /// wasted tail attempt, never a double writer — which is the entire reason
    /// the epoch exists rather than a lock.
    pub fn tenant_fencing_token(
        &self,
        tenant: &workload_spec::TenantId,
        node: super::YubabaNodeId,
        now: u64,
    ) -> Option<u64> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .tenant_fencing_token(tenant, node, now)
    }

    /// R732-T4: the whole ownership record for `tenant` in this node's applied
    /// state, or `None` if there is no record.
    ///
    /// Serves the diagnostic half of `GET /tenants/{id}` — who owns it, at
    /// which epoch, until when. The streamer decides whether it may *write*
    /// from [`Self::tenant_fencing_token`] and never by re-deriving the
    /// owner-and-lease predicate from these fields; it reads `lease_expires`
    /// only to know when to renew. Keeping the two apart is deliberate: one
    /// predicate, one place (see R732-F1's handoff).
    pub fn tenant_ownership(
        &self,
        tenant: &workload_spec::TenantId,
    ) -> Option<super::TenantOwnership> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .tenants
            .get(tenant)
            .cloned()
    }

    /// R737-F3: every tenant's ownership record in this node's applied state —
    /// the scheduler's per-tick read of who currently holds each tenant's
    /// write path, so it can find whose owner just went down. A single-tenant
    /// read is [`Self::tenant_ownership`]; this is the whole map for the loop
    /// that has to walk it.
    pub fn tenants(
        &self,
    ) -> BTreeMap<workload_spec::TenantId, super::TenantOwnership> {
        self.inner.read().unwrap().data.state.tenants.clone()
    }

    /// R737-F3: one tenant's declared placement intent in this node's applied
    /// state, or `None` if it has none — a legal state (see
    /// [`super::TenantPlacement`]'s doc), read by the scheduler as
    /// "unconstrained region, default tier, zero demand" rather than an
    /// error.
    pub fn tenant_placement(
        &self,
        tenant: &workload_spec::TenantId,
    ) -> Option<super::TenantPlacement> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .placement
            .get(tenant)
            .cloned()
    }

    /// R737-F3: whether `node` has headroom for `demand` at `now`, forwarding
    /// to [`super::YubabaState::node_admits`] under this node's single read
    /// lock rather than cloning `members`/`tenants`/`placement` out to
    /// recompute it at the call site.
    pub fn node_admits(
        &self,
        node: super::YubabaNodeId,
        demand: &super::TenantDemand,
        now: u64,
    ) -> bool {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .node_admits(node, demand, now)
    }

    /// R734-F5: every member row in this node's applied state — the yubaba-side
    /// mirror of membership, carrying the `region` tag openraft's `BasicNode`
    /// has no room for.
    ///
    /// This is *not* the authority on who is in the cluster: raft membership is,
    /// and it is reachable from `Raft::metrics`. This map is the replicated
    /// *annotation* on those nodes, written by each node about itself
    /// ([`member_registration`](crate::member_registration)), so a lag between
    /// the two is normal — a node that has just joined is in membership and has
    /// no row here until its registration loop converges.
    pub fn members(&self) -> BTreeMap<super::YubabaNodeId, super::MemberInfo> {
        self.inner.read().unwrap().data.state.members.clone()
    }

    /// One member row from this node's applied state (R734-F5).
    ///
    /// The registration loop's read half: a node compares its own row against
    /// what it would write and stays quiet when they agree, which is what keeps
    /// the loop from putting a raft write through quorum on every tick.
    pub fn member(&self, node_id: super::YubabaNodeId) -> Option<super::MemberInfo> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .members
            .get(&node_id)
            .cloned()
    }

    /// Apply one request directly, bypassing the log. Test-only, and the only
    /// way a router test can seed applied state — `apply` takes an openraft
    /// entry stream, which is a lot of scaffolding to assert that a handler
    /// reads the right field.
    #[cfg(test)]
    pub(crate) fn apply_for_test(&self, req: &super::YubabaRequest) -> super::YubabaResponse {
        let mut guard = self.inner.write().unwrap();
        super::apply(&mut guard.data.state, req)
    }

    /// The cluster's external-ingress owner in this node's applied state.
    ///
    /// Always `None` under [`IngressOwnership::Unmanaged`][io] — the rig preset
    /// — because no node claims it from the raft-leader path there.
    ///
    /// [io]: crate::cluster_policy::IngressOwnership::Unmanaged
    pub fn ingress_owner(&self) -> Option<String> {
        self.inner.read().unwrap().data.state.ingress_owner.clone()
    }

    /// R859-F2: the machine name `node_id` runs on, per its replicated member
    /// row — the half of the identity bridge that turns a consensus/liveness
    /// fact into something the `cloud` config layer can name.
    ///
    /// `None` means *no mapping is recorded*, which covers three cases that
    /// deliberately read the same: the node is not in the member map, it
    /// registered before [`MemberInfo::machine`] existed, or it could not
    /// derive its own machine name. Callers must treat all three as "cannot
    /// resolve", never as a match — an effector that guessed here would
    /// command the wrong box's floating IP.
    pub fn machine_for_node(&self, node_id: super::YubabaNodeId) -> Option<String> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .members
            .get(&node_id)
            .and_then(|m| m.machine.clone())
    }

    /// The inverse of [`Self::machine_for_node`] — which node id runs
    /// `machine`, if any member row claims it.
    ///
    /// This is the direction [`Self::ingress_owner`] needs: `ingress_owner`
    /// holds a machine name, and every liveness/hysteresis judgement is keyed
    /// by [`YubabaNodeId`](super::YubabaNodeId), so answering "is the ingress
    /// owner confirmed down?" means coming back the other way.
    ///
    /// Ties are impossible in practice (each node writes only its own row, from
    /// its own hostname) but are resolved deterministically anyway — the lowest
    /// node id wins, because `members` is a `BTreeMap` and this scans it in
    /// order. A tie would mean two nodes believe they are the same machine,
    /// which is a misconfiguration; picking arbitrarily would make its symptom
    /// depend on map iteration order.
    pub fn node_for_machine(&self, machine: &str) -> Option<super::YubabaNodeId> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .members
            .iter()
            .find(|(_, m)| m.machine.as_deref() == Some(machine))
            .map(|(id, _)| *id)
    }

    /// The raft log index this replica has applied up to, or `None` before the
    /// first entry.
    ///
    /// This is the staleness marker that makes a local read honest: the answer
    /// from [`Self::singleton_owner`] is "true as of this index". A node that
    /// has been out of contact keeps serving reads and this number stops
    /// moving, which is exactly the signal a consumer needs to decide whether
    /// to trust its last-known-good assignment.
    pub fn applied_index(&self) -> Option<u64> {
        self.inner
            .read()
            .unwrap()
            .data
            .last_applied
            .map(|id| id.index)
    }
}

/// Lower-case hex encoding. No `hex` crate dep in this crate; a digest is
/// rendered a handful of times per `GET /secrets`, not a hot path, so a
/// one-line encoder beats pulling in a dependency for it.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl RaftSnapshotBuilder<TC> for YubabaStateMachine {
    type SnapshotData = SnapshotData;

    async fn build_snapshot(&mut self) -> Result<SnapshotOf<TC, SnapshotData>, io::Error> {
        let inner = self.inner.read().unwrap();
        let bytes = serde_json::to_vec(&inner.data).map_err(io_other)?;
        let snapshot_id = inner
            .data
            .last_applied
            .map(|id| format!("{}-{}", id.leader_id, id.index))
            .unwrap_or_else(|| "empty".to_string());
        let meta = SnapshotMeta {
            last_log_id: inner.data.last_applied,
            last_membership: inner.data.last_membership.clone(),
            snapshot_id,
        };
        Ok(Snapshot {
            meta,
            snapshot: Cursor::new(bytes),
        })
    }
}

impl RaftStateMachine<TC> for YubabaStateMachine {
    type SnapshotData = SnapshotData;
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogIdOf<TC>>, StoredMembershipOf<TC>), io::Error> {
        let inner = self.inner.read().unwrap();
        Ok((inner.data.last_applied, inner.data.last_membership.clone()))
    }

    async fn apply<Strm>(&mut self, mut entries: Strm) -> Result<(), io::Error>
    where
        Strm: Stream<Item = Result<EntryResponder<TC>, io::Error>> + Unpin + OptionalSend,
    {
        // Drain the stream first (await here holds NO lock), then apply under the
        // sync lock, then deliver responses after releasing it. This keeps the
        // std `RwLock` guard off every `.await` point.
        let mut items = Vec::new();
        while let Some(item) = entries.next().await {
            items.push(item?);
        }

        let mut pending = Vec::with_capacity(items.len());
        let mut secrets_changed = false;
        {
            let mut inner = self.inner.write().unwrap();
            for (entry, responder) in items {
                let log_id = entry.log_id;
                inner.data.last_applied = Some(log_id);
                let resp = match entry.payload {
                    EntryPayload::Blank => YubabaResponse::Ok,
                    EntryPayload::Normal(req) => {
                        if matches!(
                            req,
                            YubabaRequest::PutSecret { .. } | YubabaRequest::DeleteSecret { .. }
                        ) {
                            secrets_changed = true;
                        }
                        apply(&mut inner.data.state, &req)
                    }
                    EntryPayload::Membership(membership) => {
                        inner.data.last_membership =
                            StoredMembership::new(Some(log_id), membership);
                        YubabaResponse::Ok
                    }
                };
                pending.push((responder, resp));
            }

            inner.persist()?;
            // Notify AFTER persist so a woken consumer that re-reads observes
            // durable state. Coalesced into one bump per batch.
            if secrets_changed {
                inner.secrets_epoch.send_modify(|e| *e = e.wrapping_add(1));
            }
        }

        // Responders are notified after the lock is dropped.
        for (responder, resp) in pending {
            if let Some(responder) = responder {
                responder.send(resp);
            }
        }
        Ok(())
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<SnapshotData, io::Error> {
        Ok(Cursor::new(Vec::new()))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMetaOf<TC>,
        snapshot: SnapshotData,
    ) -> Result<(), io::Error> {
        let bytes = snapshot.into_inner();
        let data: StateMachineData = serde_json::from_slice(&bytes).map_err(io_other)?;
        let mut inner = self.inner.write().unwrap();
        inner.data = data;
        inner.data.last_applied = meta.last_log_id;
        inner.data.last_membership = meta.last_membership.clone();
        inner.snapshot_meta = Some(meta.clone());
        inner.snapshot_bytes = Some(bytes);
        inner.persist()?;
        // A snapshot install can replace the secrets map wholesale (a follower
        // catching up), so notify unconditionally — diffing isn't worth it at
        // KB scale, and the subscriber's re-render is idempotent.
        inner.secrets_epoch.send_modify(|e| *e = e.wrapping_add(1));
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<SnapshotOf<TC, SnapshotData>>, io::Error> {
        let inner = self.inner.read().unwrap();
        match (&inner.snapshot_meta, &inner.snapshot_bytes) {
            (Some(meta), Some(bytes)) => Ok(Some(Snapshot {
                meta: meta.clone(),
                snapshot: Cursor::new(bytes.clone()),
            })),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::testing::log_id;

    fn normal_entry(index: u64, req: YubabaRequest) -> EntryOf<TC> {
        openraft::Entry {
            log_id: log_id::<TC>(1, 1, index),
            payload: EntryPayload::Normal(req),
        }
    }

    // R600-F4: the secrets-change watch fires for cluster-secret writes only.
    #[tokio::test]
    async fn secret_writes_bump_the_epoch_but_other_writes_do_not() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut sm = YubabaStateMachine::open(tmp.path().to_path_buf())
            .await
            .unwrap();
        let mut rx = sm.subscribe_secrets();
        assert_eq!(*rx.borrow_and_update(), 0);

        apply_one(
            &mut sm,
            normal_entry(
                1,
                YubabaRequest::PutSecret {
                    name: "tls/yah.dev/cert".into(),
                    ciphertext: vec![1, 2, 3],
                    nonce: vec![0; 12],
                    updated_at: 1,
                    access: workload_spec::secrets::SecretAccess::AllowAny,
                    digest: None,
                    sans: None,
                },
            ),
        )
        .await;
        assert!(rx.has_changed().unwrap(), "PutSecret should notify");
        assert_eq!(*rx.borrow_and_update(), 1);

        // A non-secret write must not wake secret consumers.
        apply_one(
            &mut sm,
            normal_entry(
                2,
                YubabaRequest::SetIngressOwner {
                    machine: "m1".into(),
                },
            ),
        )
        .await;
        assert!(
            !rx.has_changed().unwrap(),
            "non-secret write must not notify"
        );

        apply_one(
            &mut sm,
            normal_entry(
                3,
                YubabaRequest::DeleteSecret {
                    name: "tls/yah.dev/cert".into(),
                },
            ),
        )
        .await;
        assert!(rx.has_changed().unwrap(), "DeleteSecret should notify");
        assert_eq!(*rx.borrow_and_update(), 2);
    }

    /// Apply a single entry through the 0.10 stream/responder `apply` API with
    /// no client responder attached (as a follower would).
    async fn apply_one(sm: &mut YubabaStateMachine, entry: EntryOf<TC>) {
        let item: Result<EntryResponder<TC>, io::Error> = Ok((entry, None));
        let stream = tokio_stream::iter(vec![item]);
        sm.apply(stream).await.unwrap();
    }

    // ── R841-B1: cold start after a purge ─────────────────────────────────────

    fn blank_entry(index: u64) -> EntryOf<TC> {
        openraft::Entry {
            log_id: log_id::<TC>(1, 1, index),
            payload: EntryPayload::Blank,
        }
    }

    /// Seed `raft_log.json` the way a pre-R841-B1 binary left it: entries from
    /// `first..=last` and nothing on disk saying anything below `first` was ever
    /// purged.
    fn seed_purged_log(dir: &Path, first: u64, last: u64) {
        let entries: BTreeMap<u64, EntryOf<TC>> =
            (first..=last).map(|i| (i, blank_entry(i))).collect();
        std::fs::write(
            dir.join("raft_log.json"),
            serde_json::to_string(&entries).unwrap(),
        )
        .unwrap();
    }

    /// Seed `raft_state.json` with an applied watermark and otherwise-empty
    /// state.
    fn seed_applied(dir: &Path, last_applied: Option<LogIdOf<TC>>) {
        let data = StateMachineData {
            last_applied,
            ..StateMachineData::default()
        };
        std::fs::write(
            dir.join("raft_state.json"),
            serde_json::to_string(&data).unwrap(),
        )
        .unwrap();
    }

    /// The marker `purge()` records must outlive the process. Before R841-B1 it
    /// did not: it was an in-memory field, so a restart reported "nothing was
    /// ever purged" over a log that no longer began at index 0.
    #[tokio::test]
    async fn a_purge_marker_survives_a_cold_start() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        {
            let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
            let entries: Vec<EntryOf<TC>> = (0..=10).map(blank_entry).collect();
            log.append(entries, IOFlushed::noop()).await.unwrap();
            log.purge(log_id::<TC>(1, 1, 5)).await.unwrap();
        }

        let mut reopened = YubabaLogStore::open(dir).await.unwrap();
        let st = reopened.get_log_state().await.unwrap();
        assert_eq!(
            st.last_purged_log_id,
            Some(log_id::<TC>(1, 1, 5)),
            "the purge marker must be read back from disk, not reset to None"
        );
        assert_eq!(st.last_log_id, Some(log_id::<TC>(1, 1, 10)));
    }

    /// The incident itself, through the code path that actually failed:
    /// `Raft::new` calls `StorageHelper::get_initial_state`, which asks the log
    /// reader for `last_purged_log_id.next_index()`. With no marker that is
    /// index 0 — purged, absent — and every production voter died with
    /// `when Read LogIndex(0): log entry not found`.
    ///
    /// FALSIFIED, not assumed: forcing `open` to hand back
    /// `last_purged_log_id: None` (the pre-R841-B1 behaviour) fails this test
    /// with `StorageError { subject: LogIndex(0), verb: Read, source: log entry
    /// not found }` — the production error verbatim — and takes the three
    /// marker tests around it down with it, while the hole and committed tests
    /// stay green. Probe removed.
    #[tokio::test]
    async fn a_purged_log_can_still_produce_an_initial_state() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        {
            let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
            let entries: Vec<EntryOf<TC>> = (0..=10).map(blank_entry).collect();
            log.append(entries, IOFlushed::noop()).await.unwrap();
            log.purge(log_id::<TC>(1, 1, 5)).await.unwrap();
        }

        let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
        let mut sm = YubabaStateMachine::open(dir).await.unwrap();
        openraft::StorageHelper::new(&mut log, &mut sm)
            .with_id(1)
            .get_initial_state()
            .await
            .expect("a voter that has purged its log must be able to cold-start");
    }

    /// Migration, exact case 1: the state machine sits exactly at the purge
    /// point, so `last_applied` *is* the purged log id.
    #[tokio::test]
    async fn a_pre_r841_log_takes_its_marker_from_a_last_applied_at_the_purge_point() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        seed_purged_log(&dir, 6, 10);
        seed_applied(&dir, Some(log_id::<TC>(1, 1, 5)));

        let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
        let st = log.get_log_state().await.unwrap();
        assert_eq!(st.last_purged_log_id, Some(log_id::<TC>(1, 1, 5)));

        // One-shot: the reconstruction is written out, so the next open reads it
        // back rather than re-deriving it.
        assert!(dir.join("raft_meta.json").exists());
        let mut again = YubabaLogStore::open(dir).await.unwrap();
        assert_eq!(
            again.get_log_state().await.unwrap().last_purged_log_id,
            Some(log_id::<TC>(1, 1, 5))
        );
    }

    /// Migration, exact case 2 — the shape the live fleet was in (log
    /// 189000..193466, applied well past the start). The first surviving entry
    /// is itself already applied, so its own log id is an exact marker; no term
    /// is invented.
    #[tokio::test]
    async fn a_pre_r841_log_applied_past_its_start_adopts_the_first_entrys_log_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        seed_purged_log(&dir, 6, 10);
        seed_applied(&dir, Some(log_id::<TC>(1, 1, 10)));

        let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
        let st = log.get_log_state().await.unwrap();
        assert_eq!(st.last_purged_log_id, Some(log_id::<TC>(1, 1, 6)));
        assert_eq!(st.last_log_id, Some(log_id::<TC>(1, 1, 10)));

        // And that is enough for openraft's startup read to resolve.
        let mut sm = YubabaStateMachine::open(dir).await.unwrap();
        openraft::StorageHelper::new(&mut log, &mut sm)
            .with_id(1)
            .get_initial_state()
            .await
            .expect("the migrated marker must satisfy openraft's startup read");
    }

    /// A log purged past what the state machine ever applied is a hole. There is
    /// no marker that makes that replica startable, so `open` refuses instead of
    /// guessing a term openraft would then fail every consistency check against.
    #[tokio::test]
    async fn a_log_purged_past_the_applied_state_refuses_to_open() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        seed_purged_log(&dir, 6, 10);
        seed_applied(&dir, Some(log_id::<TC>(1, 1, 3)));

        let Err(err) = YubabaLogStore::open(dir).await else {
            panic!("a hole between the applied state and the log must not open");
        };
        let msg = err.to_string();
        assert!(msg.contains("starts at index 6"), "{msg}");
        assert!(msg.contains("re-join the cluster"), "{msg}");
    }

    /// The 2026-08-31 recovery runbook says "delete raft_log.json /
    /// raft_state.json / raft_vote.json and re-init" — it predates
    /// `raft_meta.json`, so anyone running it from memory leaves a purge marker
    /// standing over a wiped dir. That must not brick the fresh node.
    #[tokio::test]
    async fn a_marker_left_behind_by_a_partial_wipe_is_dropped() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        {
            let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
            let entries: Vec<EntryOf<TC>> = (0..=10).map(blank_entry).collect();
            log.append(entries, IOFlushed::noop()).await.unwrap();
            log.purge(log_id::<TC>(1, 1, 5)).await.unwrap();
        }
        // The runbook's three deletions, verbatim — raft_meta.json survives.
        for f in ["raft_log.json", "raft_state.json", "raft_vote.json"] {
            let _ = std::fs::remove_file(dir.join(f));
        }
        assert!(dir.join("raft_meta.json").exists());

        let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
        assert_eq!(
            log.get_log_state().await.unwrap().last_purged_log_id,
            None,
            "a stale marker over a wiped dir must not survive"
        );
        drop(log);

        // …and the node it produces must actually be foundable. This half is
        // what makes the guard load-bearing rather than tidy, and it was
        // MEASURED: with the drop disabled, `get_initial_state` still succeeds
        // (a stale marker over an empty log does not trip openraft's startup
        // read), and the founding init then panics inside openraft's own
        // invariant — `expect: &self.purged(Some(LogId { .. index: 5 })) <=
        // &self.snapshot.flushed()(None)`, validit via io_state.rs:181. So only
        // driving init distinguishes the two states, which is why this test
        // pays for a real raft node.
        let raft = crate::raft::open(1, dir, &crate::cluster_policy::ClusterPolicy::default())
            .await
            .unwrap();
        crate::raft::bootstrap_single_node(&raft, 1, "127.0.0.1:1")
            .await
            .expect("a wiped raft dir must be foundable as a fresh cluster");
        raft.shutdown().await.unwrap();
    }

    /// `save_committed` is optional per openraft's trait, but a node that drops
    /// it recovers only as far as its snapshot and can serve a read older than
    /// one it already served before the restart. Persist it.
    #[tokio::test]
    async fn the_committed_watermark_survives_a_cold_start() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        {
            let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
            log.save_committed(Some(log_id::<TC>(1, 1, 7)))
                .await
                .unwrap();
        }

        let mut reopened = YubabaLogStore::open(dir).await.unwrap();
        assert_eq!(
            reopened.read_committed().await.unwrap(),
            Some(log_id::<TC>(1, 1, 7))
        );
    }

    /// An interrupted write must never leave a half-written file behind, since
    /// `open` refuses to start on one. The rename is the guarantee; this pins
    /// that the temp file is a sibling that gets cleaned up rather than left
    /// beside the real one.
    #[tokio::test]
    async fn writes_land_atomically_and_leave_no_temp_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
        log.append(vec![blank_entry(0)], IOFlushed::noop())
            .await
            .unwrap();
        log.save_committed(Some(log_id::<TC>(1, 1, 0)))
            .await
            .unwrap();
        log.purge(log_id::<TC>(1, 1, 0)).await.unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }
}
