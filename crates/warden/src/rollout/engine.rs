//! Linear rollout engine (F1).
//!
//! Drives a `strategy = "linear"` rollout step-by-step:
//!
//! 1. Mark the rollout `Running`.
//! 2. For each step in `policy.steps`:
//!    a. Log the deploy intent (artifact resolution into WorkloadSpec is a
//!       follow-on — see R278 §"v1 slice").
//!    b. Sleep `step.gate_window_seconds`.
//!    c. Evaluate all `policy.gates` via the Prometheus evaluator.
//!    d. All green → advance `current_step`.
//!    e. Any red / error → execute `on_failure` and terminate.
//! 3. Mark the rollout `Succeeded`.
//!
//! `RolloutEngine::run()` is spawned as a background `tokio::spawn` task from
//! `POST /v1/rollouts`. It communicates back only by writing to the shared
//! `RolloutStore`; handlers read from the same store via `GET /v1/rollouts/{id}`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::{info, warn};
use workload_spec::rollout::{RolloutOnFailure, RolloutPolicy, RolloutStrategy};

use super::{gate::PrometheusGateEvaluator, RolloutStatus, RolloutStore};

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct RolloutEngine {
    rollout_id: String,
    artifact: String,
    policy: RolloutPolicy,
    store: Arc<Mutex<RolloutStore>>,
    /// `None` → stub mode (gates auto-pass, useful for tests and environments
    /// with no Prometheus configured).
    evaluator: Option<PrometheusGateEvaluator>,
}

impl RolloutEngine {
    pub fn new(
        rollout_id: impl Into<String>,
        artifact: impl Into<String>,
        policy: RolloutPolicy,
        store: Arc<Mutex<RolloutStore>>,
        prometheus_url: Option<String>,
    ) -> Self {
        Self {
            rollout_id: rollout_id.into(),
            artifact: artifact.into(),
            policy,
            store,
            evaluator: prometheus_url.map(PrometheusGateEvaluator::new),
        }
    }

    /// Drive the rollout to completion. Never panics; errors are written to the
    /// store as `RolloutStatus::Failed`.
    pub async fn run(self) {
        let id = self.rollout_id.clone();
        if let Err(e) = self.run_inner().await {
            warn!(rollout_id = %id, error = %e, "rollout engine terminated with error");
        }
    }

    async fn run_inner(self) -> anyhow::Result<()> {
        if self.policy.strategy != RolloutStrategy::Linear {
            let reason = format!(
                "strategy {:?} is not implemented in v1 (only 'linear' is supported)",
                self.policy.strategy
            );
            self.set_status(RolloutStatus::Failed { reason: reason.clone() });
            return Err(anyhow::anyhow!(reason));
        }

        self.set_status(RolloutStatus::Running);
        info!(rollout_id = %self.rollout_id, artifact = %self.artifact, "rollout started");

        for (idx, step) in self.policy.steps.iter().enumerate() {
            info!(
                rollout_id = %self.rollout_id,
                step = idx,
                mirrors = ?step.mirrors,
                artifact = %self.artifact,
                "deploying step — artifact resolution is R278 v2; \
                 gate evaluation and status tracking are live"
            );

            // ── gate window ───────────────────────────────────────────────────
            info!(
                rollout_id = %self.rollout_id,
                step = idx,
                gate_window_secs = step.gate_window_seconds,
                "waiting gate window"
            );
            tokio::time::sleep(Duration::from_secs(step.gate_window_seconds)).await;

            // ── gate evaluation ───────────────────────────────────────────────
            let on_failure = RolloutOnFailure::for_step(step.on_failure.as_ref());

            for gate in &self.policy.gates {
                match self.eval_gate(gate).await {
                    Ok(true) => {
                        info!(
                            rollout_id = %self.rollout_id,
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
                        warn!(rollout_id = %self.rollout_id, step = idx, metric = %gate.metric, %reason, "gate failed");
                        let status = match on_failure {
                            RolloutOnFailure::RollbackStep | RolloutOnFailure::RollbackAll => {
                                RolloutStatus::RolledBack { step: idx, reason: reason.clone() }
                            }
                        };
                        self.set_status(status);
                        return Err(anyhow::anyhow!(reason));
                    }
                    Err(e) => {
                        let reason = format!(
                            "gate '{}' evaluation error at step {}: {e}",
                            gate.metric, idx
                        );
                        warn!(rollout_id = %self.rollout_id, step = idx, error = %e, "gate evaluation error");
                        self.set_status(RolloutStatus::Failed { reason: reason.clone() });
                        return Err(anyhow::anyhow!(reason));
                    }
                }
            }

            // Advance step counter after all gates pass.
            {
                let mut store = self.store.lock().unwrap();
                store.update_step(&self.rollout_id, idx + 1);
            }
            info!(rollout_id = %self.rollout_id, step = idx, mirrors = ?step.mirrors, "step promoted");
        }

        self.set_status(RolloutStatus::Succeeded);
        info!(rollout_id = %self.rollout_id, "rollout succeeded");
        Ok(())
    }

    async fn eval_gate(
        &self,
        gate: &workload_spec::rollout::RolloutGate,
    ) -> anyhow::Result<bool> {
        match &self.evaluator {
            Some(ev) => ev.evaluate(gate).await,
            None => {
                // Stub mode — no Prometheus configured. Gates auto-pass so the
                // rollout still traverses all steps in test / dev environments.
                info!(
                    rollout_id = %self.rollout_id,
                    metric = %gate.metric,
                    "no Prometheus URL configured; gate auto-passes in stub mode"
                );
                Ok(true)
            }
        }
    }

    fn set_status(&self, status: RolloutStatus) {
        if let Ok(mut store) = self.store.lock() {
            store.update_status(&self.rollout_id, status);
        }
    }
}
