//! Rollout subsystem — raft-replicated state + engine + supervisor + gate.
//!
//! # Where a rollout lives (R118-T5)
//!
//! In [`crate::raft::YubabaState::rollouts`], and nowhere else. R278-F1 kept
//! rollouts in an `Arc<Mutex<RolloutStore>>` on `ServerState` — a `HashMap`
//! with no disk path — and R278-F3 added the raft variants beside it as
//! forward-compat, leaving the in-memory copy authoritative. That arrangement
//! fails at exactly the case W138 §"Coordinated N-node rollout" cares about:
//! the node driving a fleet image update loses power, and with it the only
//! record that a rollout was ever in flight. Every other node is left holding
//! a half-updated rig and no way to know it.
//!
//! So the store is gone. [`RolloutRecord`] is a *view* built from the
//! replicated [`RolloutRaftRecord`], and every mutation goes through consensus
//! as a `SetRolloutState` / `ClearRolloutState`. Reads are local applied-state
//! reads (no leader round-trip), the same posture as
//! `GET /cluster/singletons` and `GET /tenants/{id}`.
//!
//! # Who drives one
//!
//! [`supervisor`], on the leader, exclusively. Nothing spawns an engine at
//! create time any more: `POST /v1/rollouts` commits a `Pending` record and
//! returns, and the leader's supervisor picks it up on its next tick. Starting
//! a rollout is therefore the *same code path* as resuming an interrupted one,
//! which is the only way the resume path stays working — a path that runs only
//! after a power cut is a path that is broken and nobody knows.

pub mod engine;
pub mod gate;
pub mod health;
pub mod supervisor;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use workload_spec::rollout::RolloutPolicy;

use crate::raft::{RolloutRaftRecord, YubabaRequest};

// ── ID generation ─────────────────────────────────────────────────────────────

static ROLLOUT_SEQ: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_rollout_id() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let seq = ROLLOUT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("rt-{t:x}-{seq:04x}")
}

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Domain types ──────────────────────────────────────────────────────────────

/// A single rollout, as the API renders it.
///
/// The typed twin of [`RolloutRaftRecord`]: same facts, with `status` decoded
/// so `GET /v1/rollouts/{id}` answers with a status *object* rather than a
/// string of JSON. Build one with [`RolloutRecord::from_raft`] and turn it back
/// into a consensus write with [`RolloutRecord::set_request`].
#[derive(Debug, Clone, Serialize)]
pub struct RolloutRecord {
    pub rollout_id: String,
    /// Artifact URI, e.g. `"release:yah-marketing@v1.2.3"`.
    pub artifact: String,
    /// Resolved rollout policy.
    pub policy: RolloutPolicy,
    /// Trigger metadata from the HTTP request (opaque JSON).
    pub trigger: serde_json::Value,
    pub status: RolloutStatus,
    /// Index of the next step to execute (0-based).
    pub current_step: usize,
    /// Unix seconds at creation time.
    pub created_at: u64,
    /// The committed revision this view was read at, or `0` for a record that
    /// has never been written (see [`RolloutRaftRecord::revision`]).
    ///
    /// Carried on the view, and rendered by the API, because it is what any
    /// writer — including a caller hand-rolling a `POST /raft/write` — must
    /// pass as `expected_revision` for its write to be accepted.
    pub revision: u64,
}

impl RolloutRecord {
    /// Open a brand-new rollout in `Pending`, with a freshly minted id.
    pub fn new(artifact: String, policy: RolloutPolicy, trigger: serde_json::Value) -> Self {
        Self {
            rollout_id: next_rollout_id(),
            artifact,
            policy,
            trigger,
            status: RolloutStatus::Pending,
            current_step: 0,
            created_at: now_unix_secs(),
            // Nothing has been committed for this id yet, and 0 is exactly what
            // the apply arm requires of a create.
            revision: 0,
        }
    }

    /// Decode a replicated record.
    ///
    /// A `status_json` this node cannot parse reads as
    /// [`RolloutStatus::Failed`] rather than propagating an error: the record
    /// is committed either way, and a reader that refused to render it would
    /// hide an in-flight rollout from the operator looking for it. The reason
    /// travels in the status so the corruption is visible rather than silent.
    pub fn from_raft(rec: &RolloutRaftRecord) -> Self {
        let status = serde_json::from_str(&rec.status_json).unwrap_or_else(|e| {
            RolloutStatus::Failed {
                reason: format!(
                    "undecodable replicated status for rollout {}: {e}",
                    rec.rollout_id
                ),
            }
        });
        Self {
            rollout_id: rec.rollout_id.clone(),
            artifact: rec.artifact.clone(),
            policy: rec.policy.clone(),
            trigger: rec.trigger.clone(),
            status,
            current_step: rec.current_step,
            created_at: rec.started_at,
            revision: rec.revision,
        }
    }

    /// The consensus write that makes this record the cluster's view.
    ///
    /// Guarded on [`Self::revision`] — the revision this view was *read* at —
    /// so a write built from a record that has since moved is rejected rather
    /// than applied over the top of whoever moved it.
    pub fn set_request(&self) -> YubabaRequest {
        YubabaRequest::SetRolloutState {
            expected_revision: self.revision,
            rollout_id: self.rollout_id.clone(),
            artifact: self.artifact.clone(),
            // `RolloutStatus` is a plain enum of owned data; serialising it
            // cannot fail for any value that exists, and a panic here would
            // take down a request handler, so a hard-coded fallback that shows
            // up as a failed rollout is the safer unreachable branch.
            status_json: serde_json::to_string(&self.status).unwrap_or_else(|_| {
                r#"{"kind":"failed","reason":"status could not be serialised"}"#.to_string()
            }),
            current_step: self.current_step,
            started_at: self.created_at,
            policy: self.policy.clone(),
            trigger: self.trigger.clone(),
        }
    }
}

// ── Guarded writes ────────────────────────────────────────────────────────────

/// How many times a writer re-reads and retries before giving up.
///
/// Contention here is two writers, not N: the leader's one engine and an
/// operator. Anything past a couple of rounds means something is wrong that
/// retrying will not fix, and a bounded count keeps a request handler from
/// spinning on a partitioned leader.
const MAX_WRITE_ATTEMPTS: usize = 8;

/// Pause between a rejection and the re-read. Covers the gap between a
/// forwarded write committing on a remote leader and this node applying it —
/// without it, a forwarding writer would re-read its own stale state and send
/// the identical doomed request `MAX_WRITE_ATTEMPTS` times.
const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(25);

/// What a guarded write did.
///
/// No `PartialEq`: `RolloutPolicy` has none, and comparing two whole records is
/// not a question any caller asks — they match on the variant and read the
/// record out.
#[derive(Debug, Clone)]
pub enum Written {
    /// Committed; the record as it now stands, at its new revision.
    ///
    /// Boxed because the other variant carries nothing and a `RolloutRecord` is
    /// ~216 bytes (it holds the whole policy), so an unboxed enum would pay
    /// that on every `Abandoned` too.
    Committed(Box<RolloutRecord>),
    /// The writer looked at the current state and chose not to write — an
    /// engine finding its rollout already overridden, an override finding no
    /// record. Not an error: the intent no longer applies.
    Abandoned,
}

/// Commit a change to one rollout under optimistic concurrency, retrying on
/// rejection (R118-T5).
///
/// `intent` is handed the record **as it currently stands in applied state** —
/// `None` when there is no record — and returns the record it wants committed,
/// or `None` to abandon. It is called again on every retry, against freshly
/// read state, which is the whole point: a writer re-derives its intent from
/// the truth rather than replaying a decision made against a record that has
/// since moved.
///
/// `forward_with` decides who may write from here. `Some(client)` forwards to
/// the leader (the HTTP handlers' posture: an operator may POST to any node);
/// `None` requires this node to *be* the leader and fails otherwise, which is
/// the engine's fence — see [`engine`].
pub async fn commit_guarded(
    raft: &crate::raft::YubabaRaft,
    state_machine: &crate::raft::YubabaStateMachine,
    rollout_id: &str,
    forward_with: Option<&reqwest::Client>,
    mut intent: impl FnMut(Option<&RolloutRecord>) -> Option<RolloutRecord>,
) -> anyhow::Result<Written> {
    use crate::raft::{RolloutWriteOutcome, YubabaResponse};

    for attempt in 0..MAX_WRITE_ATTEMPTS {
        let current = state_machine.rollout(rollout_id).map(|r| {
            let mut view = RolloutRecord::from_raft(&r);
            // `from_raft` already carries the revision; naming it here keeps the
            // invariant visible: what we read is what we guard on.
            view.revision = r.revision;
            view
        });
        let Some(next) = intent(current.as_ref()) else {
            return Ok(Written::Abandoned);
        };

        let request = next.set_request();
        let response = match forward_with {
            Some(client) => crate::raft::client_write_forwarded(raft, client, request).await?,
            None => raft
                .client_write(request)
                .await
                .map(|r| r.data)
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        };

        match response {
            YubabaResponse::Rollout(RolloutWriteOutcome::Committed { revision }) => {
                let mut committed = next;
                committed.revision = revision;
                return Ok(Written::Committed(Box::new(committed)));
            }
            YubabaResponse::Rollout(RolloutWriteOutcome::Stale { current_revision }) => {
                tracing::debug!(
                    rollout_id,
                    attempt,
                    expected = next.revision,
                    current_revision,
                    "rollout write lost a race; re-reading and retrying"
                );
                tokio::time::sleep(RETRY_BACKOFF).await;
            }
            // Every other variant is another subsystem's answer. Reaching one
            // here means `apply` stopped answering rollout writes with
            // `Rollout(..)`, which is a bug rather than a race — retrying would
            // hide it.
            other => anyhow::bail!(
                "unexpected raft response to a rollout write for {rollout_id}: {other:?}"
            ),
        }
    }
    anyhow::bail!(
        "rollout {rollout_id}: gave up after {MAX_WRITE_ATTEMPTS} rejected writes — \
         something else is writing this record continuously"
    )
}

/// Retire a rollout from cluster state, guarded on the revision it was read at.
pub async fn clear_guarded(
    raft: &crate::raft::YubabaRaft,
    expected_revision: u64,
    rollout_id: &str,
) -> anyhow::Result<crate::raft::RolloutWriteOutcome> {
    use crate::raft::YubabaResponse;

    let response = raft
        .client_write(YubabaRequest::ClearRolloutState {
            rollout_id: rollout_id.to_string(),
            expected_revision,
        })
        .await
        .map(|r| r.data)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    match response {
        YubabaResponse::Rollout(outcome) => Ok(outcome),
        other => anyhow::bail!("unexpected raft response to ClearRolloutState: {other:?}"),
    }
}

/// Lifecycle state of a rollout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RolloutStatus {
    /// Accepted; engine not yet started.
    Pending,
    /// Engine is running (deploying or waiting gate window).
    Running,
    /// All steps promoted; rollout complete.
    Succeeded,
    /// A gate failed or an unrecoverable error occurred.
    Failed { reason: String },
    /// A gate failed and the on_failure action rolled back mirrors.
    RolledBack { step: usize, reason: String },
    /// Operator forced a state change via `POST /v1/rollouts/{id}/override`.
    ///
    /// Terminal. Only `rollback` lands here — a `promote` override advances
    /// `current_step` and leaves the rollout `Running`, because a promote is a
    /// statement about one step and not about the rollout.
    Overridden { action: String, by: String },
}

impl RolloutStatus {
    /// Whether a rollout in this state is one the supervisor should be driving.
    ///
    /// The single predicate behind three questions that must never disagree:
    /// does the leader's supervisor claim this rollout, does a running engine
    /// keep going, and does a node returning from a power cut re-drive
    /// something the cluster already finished. One rule, one place — a
    /// second opinion is how you get two image generations playing at once.
    pub fn is_in_flight(&self) -> bool {
        match self {
            Self::Pending | Self::Running => true,
            Self::Succeeded
            | Self::Failed { .. }
            | Self::RolledBack { .. }
            | Self::Overridden { .. } => false,
        }
    }
}

// ── Override action ───────────────────────────────────────────────────────────

/// Valid override actions for `POST /v1/rollouts/{id}/override`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverrideAction {
    /// Skip the current gate window and promote the current step.
    Promote,
    /// Abort the rollout and roll back all promoted steps.
    Rollback,
}

impl OverrideAction {
    /// The operator-facing name, as recorded in
    /// [`RolloutStatus::Overridden::action`] and echoed in the HTTP response.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Promote => "promote",
            Self::Rollback => "rollback",
        }
    }

    /// Apply this override to `record`, in place.
    ///
    /// Pure, so the two override semantics are testable without a cluster: a
    /// promote advances the step and leaves the rollout in flight (the engine's
    /// gate-window poll notices and stops waiting), a rollback is terminal.
    pub fn apply(&self, record: &mut RolloutRecord, by: &str) {
        match self {
            Self::Promote => {
                record.current_step += 1;
                record.status = RolloutStatus::Running;
            }
            Self::Rollback => {
                record.status = RolloutStatus::Overridden {
                    action: self.as_str().to_string(),
                    by: by.to_string(),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RolloutPolicy {
        serde_json::from_value(serde_json::json!({
            "strategy": "linear",
            "window_seconds": 60,
            "steps": [
                { "mirrors": ["staging"], "gate_window_seconds": 0 },
                { "mirrors": ["prod"], "gate_window_seconds": 0 }
            ]
        }))
        .expect("a linear two-step policy")
    }

    /// The round trip a resuming leader depends on: everything it needs to
    /// drive the rollout survives a trip through the replicated record.
    #[test]
    fn a_record_survives_the_round_trip_through_raft_state_with_its_policy() {
        let mut record = RolloutRecord::new(
            "release:rig@v2".into(),
            policy(),
            serde_json::json!({ "source": "test" }),
        );
        record.status = RolloutStatus::Running;
        record.current_step = 1;
        // As if read back at revision 4 — the write must guard on it.
        record.revision = 4;

        let YubabaRequest::SetRolloutState {
            rollout_id,
            artifact,
            status_json,
            current_step,
            started_at,
            policy,
            trigger,
            expected_revision,
        } = record.set_request()
        else {
            panic!("set_request must produce SetRolloutState");
        };
        assert_eq!(
            expected_revision, 4,
            "a write must expect the revision its record was read at, or it is \
             a last-write-wins clobber wearing a CAS"
        );
        let back = RolloutRecord::from_raft(&RolloutRaftRecord {
            rollout_id,
            artifact,
            status_json,
            current_step,
            started_at,
            policy,
            trigger,
            // What `apply` would have stored on accepting the write above.
            revision: expected_revision + 1,
        });
        assert_eq!(back.revision, 5, "the view carries the committed revision");

        assert_eq!(back.rollout_id, record.rollout_id);
        assert_eq!(back.status, RolloutStatus::Running);
        assert_eq!(back.current_step, 1);
        assert_eq!(back.created_at, record.created_at);
        assert_eq!(back.trigger, serde_json::json!({ "source": "test" }));
        // The field that made the widening necessary: without the steps a new
        // leader knows a rollout is in flight and not what to do about it.
        assert_eq!(back.policy.steps.len(), 2);
        assert_eq!(back.policy.steps[1].mirrors, vec!["prod".to_string()]);
    }

    /// Exactly the states the supervisor may claim. Written as an exhaustive
    /// list rather than a spot check because a new variant defaulting to
    /// "in flight" would have a returning node re-drive finished work.
    #[test]
    fn only_pending_and_running_are_in_flight() {
        assert!(RolloutStatus::Pending.is_in_flight());
        assert!(RolloutStatus::Running.is_in_flight());
        assert!(!RolloutStatus::Succeeded.is_in_flight());
        assert!(!RolloutStatus::Failed {
            reason: "x".into()
        }
        .is_in_flight());
        assert!(!RolloutStatus::RolledBack {
            step: 0,
            reason: "x".into()
        }
        .is_in_flight());
        assert!(!RolloutStatus::Overridden {
            action: "rollback".into(),
            by: "op".into()
        }
        .is_in_flight());
    }

    /// A promote is about one step; a rollback is about the rollout. The
    /// engine's stop condition reads `is_in_flight`, so this is the difference
    /// between "skip this gate window" and "stop driving".
    #[test]
    fn promote_advances_the_step_and_rollback_is_terminal() {
        let mut record =
            RolloutRecord::new("release:rig@v2".into(), policy(), serde_json::Value::Null);
        record.status = RolloutStatus::Running;

        OverrideAction::Promote.apply(&mut record, "operator");
        assert_eq!(record.current_step, 1);
        assert!(record.status.is_in_flight());

        OverrideAction::Rollback.apply(&mut record, "operator");
        assert!(!record.status.is_in_flight());
        assert_eq!(
            record.status,
            RolloutStatus::Overridden {
                action: "rollback".into(),
                by: "operator".into()
            }
        );
    }
}
