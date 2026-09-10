//! Linear rollout engine (R278-F1; made raft-resident by R118-T5).
//!
//! Drives a `strategy = "linear"` rollout step-by-step, from wherever the
//! replicated record says it is:
//!
//! 1. Mark the rollout `Running`.
//! 2. From `current_step` to the end of `policy.steps`:
//!    a. Log the deploy intent (artifact resolution into WorkloadSpec is a
//!       follow-on — see R278 §"v1 slice").
//!    b. Wait `step.gate_window_seconds`, watching for an operator override and for the per-node boot health the policy requires ([`super::health`]).
//!    c. Evaluate all `policy.gates` via the Prometheus evaluator.
//!    d. All green → commit `current_step + 1`.
//!    e. Any red / error → commit `on_failure`'s outcome and terminate.
//! 3. Commit `Succeeded`.
//!
//! # The step gate is not a timer (R118-T5)
//!
//! Step 2b used to be `sleep(gate_window_seconds)`, which on a rig meant a
//! rollout could promote over a plinth that had already come up broken — the
//! node knew (R101-F1 gave it a real A/B verdict), and nothing above it was
//! listening. With `policy.require_node_health` on, the window is now the
//! *earliest* a step may promote and never the reason it does: a filed failure
//! reverts immediately, and silence holds the step until the rollout's own
//! `window_seconds` runs out. See [`super::health`] for why unknown is a veto.
//!
//! # Every write goes through consensus, and that is the fence
//!
//! The engine holds no store. It commits each status and step change with
//! [`YubabaRaft::client_write`] — deliberately *not*
//! [`crate::raft::client_write_forwarded`]. A demoted leader's `client_write`
//! fails with `ForwardToLeader` and this engine stops on the spot, which is
//! what stops two nodes driving one rollout onto the same rig. Forwarding
//! would let a node that has lost the cluster keep steering it by proxy.
//!
//! Every step therefore re-reads the committed record before acting on it: it
//! is how an operator override reaches an engine already in flight, and it is
//! why an engine resumed by a new leader and a stale one that somehow survived
//! cannot disagree about which step is next.

use std::time::Duration;

use tracing::{info, warn};
use workload_spec::rollout::{RolloutOnFailure, RolloutStep, RolloutStrategy};

use super::health::{step_health, StepHealth};
use super::{gate::PrometheusGateEvaluator, RolloutRecord, RolloutStatus};
use crate::raft::{YubabaRaft, YubabaStateMachine};

/// How often the gate window looks up from its sleep to re-read the record.
///
/// Bounds how long a `promote` override waits before it takes effect. Short
/// enough to feel immediate to an operator, long enough that a 10-minute gate
/// window is 2400 lock-free map reads and not a busy loop.
const WINDOW_POLL: Duration = Duration::from_millis(250);

/// Why a step's gate stopped waiting.
///
/// The three non-`Ready` variants are the whole of R118-T5's second half: a
/// step no longer promotes just because a timer ran out.
#[derive(Debug)]
enum StepGate {
    /// The gate window elapsed **and** whatever evidence the policy requires is
    /// on file and green. The only way past this gate.
    Ready,
    /// The committed record moved under us — an operator promoted this step, or
    /// stopped the rollout, or cleared it. The caller re-reads rather than
    /// gating a step the cluster has already left behind.
    Moved,
    /// A node reported a **failed** boot. Reverts the rollout; does not wait out
    /// the rest of the window, because the window exists to observe exactly this
    /// and it has been observed.
    HealthFailed { node: String, detail: String },
    /// The rollout's whole `window_seconds` budget ran out with nodes still
    /// silent. Fails the rollout — the fail-closed half of the gate, since
    /// "never reported" is the shape a plinth that did not come back takes.
    EvidenceTimeout { missing: Vec<String> },
}

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct RolloutEngine {
    /// This engine's working copy. Refreshed from the state machine at the top
    /// of every step — the committed record is the authority, never this.
    record: RolloutRecord,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    /// `None` → stub mode (gates auto-pass, useful for tests and environments
    /// with no Prometheus configured).
    evaluator: Option<PrometheusGateEvaluator>,
}

impl RolloutEngine {
    /// Drive `record` — whether it was created a moment ago or committed by a
    /// leader that has since lost power. There is no separate "start" and
    /// "resume" constructor because there is no difference: both begin by
    /// reading `current_step` out of the committed record.
    pub fn new(
        record: RolloutRecord,
        raft: YubabaRaft,
        state_machine: YubabaStateMachine,
        prometheus_url: Option<String>,
    ) -> Self {
        Self {
            record,
            raft,
            state_machine,
            evaluator: prometheus_url.map(PrometheusGateEvaluator::new),
        }
    }

    /// Drive the rollout to completion. Never panics; terminal outcomes are
    /// committed to raft as a [`RolloutStatus`].
    pub async fn run(mut self) {
        let id = self.record.rollout_id.clone();
        if let Err(e) = self.run_inner().await {
            warn!(rollout_id = %id, error = %e, "rollout engine terminated with error");
        }
    }

    async fn run_inner(&mut self) -> anyhow::Result<()> {
        if self.record.policy.strategy != RolloutStrategy::Linear {
            let reason = format!(
                "strategy {:?} is not implemented in v1 (only 'linear' is supported)",
                self.record.policy.strategy
            );
            self.commit_status(RolloutStatus::Failed {
                reason: reason.clone(),
            })
            .await?;
            return Err(anyhow::anyhow!(reason));
        }

        if self.record.status != RolloutStatus::Running
            && !self.commit_status(RolloutStatus::Running).await?
        {
            // Abandoned before the first step: the rollout was overridden
            // between the supervisor claiming it and this engine starting.
            info!(
                rollout_id = %self.record.rollout_id,
                "rollout left flight before the engine started; standing down"
            );
            return Ok(());
        }
        info!(
            rollout_id = %self.record.rollout_id,
            artifact = %self.record.artifact,
            from_step = self.record.current_step,
            "rollout driving"
        );

        loop {
            // The committed record leads; this engine's copy follows. A record
            // that has gone terminal under us (an override, or another leader)
            // stops us here rather than after one more step.
            if !self.refresh()? {
                info!(
                    rollout_id = %self.record.rollout_id,
                    status = ?self.record.status,
                    "rollout is no longer in flight; engine standing down"
                );
                return Ok(());
            }

            let idx = self.record.current_step;
            let Some(step) = self.record.policy.steps.get(idx).cloned() else {
                break;
            };

            info!(
                rollout_id = %self.record.rollout_id,
                step = idx,
                mirrors = ?step.mirrors,
                artifact = %self.record.artifact,
                "deploying step — artifact resolution is R278 v2; \
                 gate evaluation and status tracking are live"
            );

            let on_failure = RolloutOnFailure::for_step(step.on_failure.as_ref());

            // ── gate window + per-node boot health ────────────────────────────
            info!(
                rollout_id = %self.record.rollout_id,
                step = idx,
                gate_window_secs = step.gate_window_seconds,
                require_node_health = self.record.policy.require_node_health,
                "waiting gate window"
            );
            match self.await_step_gate(idx, &step).await {
                StepGate::Ready => {}
                StepGate::Moved => continue,
                StepGate::HealthFailed { node, detail } => {
                    let reason = format!(
                        "node '{node}' reported a failed boot during step {idx}{}",
                        if detail.is_empty() {
                            String::new()
                        } else {
                            format!(": {detail}")
                        }
                    );
                    warn!(rollout_id = %self.record.rollout_id, step = idx, %node, %reason, "reverting on a node's boot-health verdict");
                    let status = match on_failure {
                        RolloutOnFailure::RollbackStep | RolloutOnFailure::RollbackAll => {
                            RolloutStatus::RolledBack {
                                step: idx,
                                reason: reason.clone(),
                            }
                        }
                    };
                    self.commit_status(status).await?;
                    return Err(anyhow::anyhow!(reason));
                }
                StepGate::EvidenceTimeout { missing } => {
                    let reason = format!(
                        "step {idx} never heard from {} within the rollout's {}s window; \
                         a node that has not reported is not healthy, so this step does \
                         not promote",
                        missing.join(", "),
                        self.record.policy.window_seconds
                    );
                    warn!(rollout_id = %self.record.rollout_id, step = idx, %reason, "rollout out of time waiting for boot health");
                    self.commit_status(RolloutStatus::Failed {
                        reason: reason.clone(),
                    })
                    .await?;
                    return Err(anyhow::anyhow!(reason));
                }
            }

            // ── gate evaluation ───────────────────────────────────────────────
            for gate in &self.record.policy.gates.clone() {
                match self.eval_gate(gate).await {
                    Ok(true) => {
                        info!(
                            rollout_id = %self.record.rollout_id,
                            step = idx,
                            metric = %gate.metric,
                            condition = %gate.condition,
                            "gate passed"
                        );
                    }
                    Ok(false) => {
                        let reason = format!(
                            "gate '{}' ({}) failed at step {}",
                            gate.metric, gate.condition, idx
                        );
                        warn!(rollout_id = %self.record.rollout_id, step = idx, metric = %gate.metric, %reason, "gate failed");
                        let status = match on_failure {
                            RolloutOnFailure::RollbackStep | RolloutOnFailure::RollbackAll => {
                                RolloutStatus::RolledBack {
                                    step: idx,
                                    reason: reason.clone(),
                                }
                            }
                        };
                        self.commit_status(status).await?;
                        return Err(anyhow::anyhow!(reason));
                    }
                    Err(e) => {
                        let reason = format!(
                            "gate '{}' evaluation error at step {}: {e}",
                            gate.metric, idx
                        );
                        warn!(rollout_id = %self.record.rollout_id, step = idx, error = %e, "gate evaluation error");
                        self.commit_status(RolloutStatus::Failed {
                            reason: reason.clone(),
                        })
                        .await?;
                        return Err(anyhow::anyhow!(reason));
                    }
                }
            }

            // Advance the step counter after all gates pass. Committed before
            // the next step starts, so a power cut here costs at most a repeat
            // of one step, never a skipped one.
            //
            // The intent is re-derived against freshly read state, not against
            // the copy this engine gated: an override that landed while the
            // gates were evaluating has already moved the record, and replaying
            // this engine's `status` over the top of it is exactly the
            // lost-update this CAS exists to prevent.
            let promoted = self
                .commit_intent(|live| {
                    let live = live?;
                    if !live.status.is_in_flight() || live.current_step != idx {
                        // Somebody else decided: an override stopped the
                        // rollout, or promoted this very step. Either way this
                        // advance is stale.
                        return None;
                    }
                    let mut next = live.clone();
                    next.current_step = idx + 1;
                    Some(next)
                })
                .await?;
            if !promoted {
                continue;
            }
            info!(rollout_id = %self.record.rollout_id, step = idx, mirrors = ?step.mirrors, "step promoted");
        }

        // Same rule for the terminal write, where getting it wrong is worst: an
        // engine that overwrote an operator's `Overridden` with `Succeeded`
        // would report a rolled-back fleet update as having shipped.
        if self
            .commit_intent(|live| {
                let live = live?;
                if !live.status.is_in_flight() {
                    return None;
                }
                let mut next = live.clone();
                next.status = RolloutStatus::Succeeded;
                Some(next)
            })
            .await?
        {
            info!(rollout_id = %self.record.rollout_id, "rollout succeeded");
        }
        Ok(())
    }

    /// Re-read the committed record into [`Self::record`]. `Ok(false)` means
    /// the rollout is no longer in flight and this engine should stand down.
    ///
    /// A record that has *vanished* (an operator cleared it) is the same
    /// answer, not an error: the cluster has decided this rollout is over.
    fn refresh(&mut self) -> anyhow::Result<bool> {
        let Some(rec) = self.state_machine.rollout(&self.record.rollout_id) else {
            self.record.status = RolloutStatus::Failed {
                reason: "rollout record was removed from cluster state".to_string(),
            };
            return Ok(false);
        };
        self.record = RolloutRecord::from_raft(&rec);
        Ok(self.record.status.is_in_flight())
    }

    /// Hold a step until it may promote, or until something says it never will.
    ///
    /// Three clocks and one map, polled together on the same `WINDOW_POLL`
    /// cadence:
    ///
    /// - the step's **gate window**, which is the earliest a promotion can
    ///   happen and — when the policy requires no node health — still the only
    ///   thing that gates it, exactly as before R118-T5;
    /// - the **rollout's** `window_seconds`, which bounds how long silence is
    ///   tolerated. Read off the replicated `created_at` rather than a local
    ///   `Instant` on purpose: a rollout resumed by a new leader must inherit
    ///   how much of its budget is left, and a monotonic clock in this process
    ///   started when this process did;
    /// - the committed **record**, so an operator override still cuts a window
    ///   short (R118-T5 part 1);
    /// - and the replicated **health map**, checked first on every pass so a
    ///   failed boot reverts the rollout the moment it is filed rather than
    ///   after a half-hour window it was supposed to be the answer to.
    async fn await_step_gate(&self, idx: usize, step: &RolloutStep) -> StepGate {
        let window_deadline =
            tokio::time::Instant::now() + Duration::from_secs(step.gate_window_seconds);
        let rollout_deadline = self
            .record
            .created_at
            .saturating_add(self.record.policy.window_seconds);

        loop {
            let reports = self.state_machine.rollout_health(&self.record.rollout_id);
            match step_health(&self.record.policy, step, &reports) {
                StepHealth::Failed { node, detail } => {
                    return StepGate::HealthFailed { node, detail }
                }
                // Both of these mean "nothing is blocking on evidence" — the
                // policy asks for none, or all of it is in and green. The window
                // is then the gate, as it always was.
                StepHealth::NotRequired | StepHealth::AllGood => {
                    if tokio::time::Instant::now() >= window_deadline {
                        return StepGate::Ready;
                    }
                }
                // Fail closed. Keep holding — past the gate window if need be —
                // and give up only when the rollout's own budget is spent.
                StepHealth::Unknown { missing } => {
                    if super::now_unix_secs() >= rollout_deadline {
                        return StepGate::EvidenceTimeout { missing };
                    }
                }
            }

            let now = tokio::time::Instant::now();
            let nap = if now >= window_deadline {
                WINDOW_POLL
            } else {
                WINDOW_POLL.min(window_deadline - now)
            };
            tokio::time::sleep(nap).await;

            match self.state_machine.rollout(&self.record.rollout_id) {
                Some(rec) => {
                    if rec.current_step != idx {
                        return StepGate::Moved;
                    }
                    let live = RolloutRecord::from_raft(&rec);
                    if !live.status.is_in_flight() {
                        return StepGate::Moved;
                    }
                }
                // Cleared under us — let the caller's `refresh` render the
                // verdict, in one place.
                None => return StepGate::Moved,
            }
        }
    }

    async fn eval_gate(&self, gate: &workload_spec::rollout::RolloutGate) -> anyhow::Result<bool> {
        match &self.evaluator {
            Some(ev) => ev.evaluate(gate).await,
            None => {
                // Stub mode — no Prometheus configured. Gates auto-pass so the
                // rollout still traverses all steps in test / dev environments.
                info!(
                    rollout_id = %self.record.rollout_id,
                    metric = %gate.metric,
                    "no Prometheus URL configured; gate auto-passes in stub mode"
                );
                Ok(true)
            }
        }
    }

    /// Set a status, abandoning if the record has since left flight.
    ///
    /// Returns whether the write landed.
    async fn commit_status(&mut self, status: RolloutStatus) -> anyhow::Result<bool> {
        self.commit_intent(|live| {
            let live = live?;
            if !live.status.is_in_flight() {
                return None;
            }
            let mut next = live.clone();
            next.status = status.clone();
            Some(next)
        })
        .await
    }

    /// Commit `intent` through consensus under the record's CAS, refreshing
    /// this engine's own copy from whatever was committed.
    ///
    /// `Ok(false)` means the intent was abandoned because the committed record
    /// no longer supports it — the operator, or another writer, got there
    /// first. That is a normal outcome and not an error.
    ///
    /// The error path is load-bearing: a `client_write` that fails because this
    /// node is no longer the leader is how a stale engine finds out, and every
    /// caller propagates it straight out of `run_inner`. `forward_with: None`
    /// is what keeps that true — an engine must never reach the leader by
    /// proxy.
    async fn commit_intent(
        &mut self,
        intent: impl FnMut(Option<&RolloutRecord>) -> Option<RolloutRecord>,
    ) -> anyhow::Result<bool> {
        let written = super::commit_guarded(
            &self.raft,
            &self.state_machine,
            &self.record.rollout_id,
            None,
            intent,
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "committing rollout {} state through raft: {e}",
                self.record.rollout_id
            )
        })?;
        match written {
            super::Written::Committed(record) => {
                self.record = *record;
                Ok(true)
            }
            super::Written::Abandoned => Ok(false),
        }
    }
}
