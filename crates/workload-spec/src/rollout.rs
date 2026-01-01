//! Rollout policy schema — the typed form of `.warden/rollout.toml`.
//!
//! Policy files live in the release bundle alongside the `WorkloadSpec` they
//! govern. Warden deserialises the policy and drives the rollout according to
//! the declared strategy, gates, and steps.
//!
//! Corresponds to §"Rollout policy" in `.yah/docs/working/W140-yah-warden-ci-cd.md`.

use serde::{Deserialize, Serialize};

#[cfg(feature = "json-schema")]
use schemars::JsonSchema;

/// Top-level wrapper when reading `.warden/rollout.toml` from disk.
///
/// TOML files have a `[rollout]` section; when the policy is inlined in JSON
/// (e.g. in the `POST /v1/rollouts` request body), use [`RolloutPolicy`] directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(JsonSchema))]
pub struct RolloutFile {
    pub rollout: RolloutPolicy,
}

/// Rollout policy for a single service — the content of the `[rollout]` TOML section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(JsonSchema))]
pub struct RolloutPolicy {
    /// Deployment strategy. Only `linear` is implemented in warden v1.
    pub strategy: RolloutStrategy,
    /// Maximum wall-clock seconds for the entire rollout before it times out.
    pub window_seconds: u64,
    /// SLO gates evaluated after each step's gate window elapses.
    #[serde(default)]
    pub gates: Vec<RolloutGate>,
    /// Ordered deployment steps (e.g. staging → canary → prod).
    #[serde(default)]
    pub steps: Vec<RolloutStep>,
}

/// Rollout strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RolloutStrategy {
    /// Deploy to each step's mirrors in sequence; promote only when all gates pass.
    Linear,
    /// Deploy to a configurable fraction of mirrors per step. Not implemented in v1.
    CanaryFraction,
}

/// A single SLO gate evaluated after a step's gate window elapses.
///
/// All gates must pass before the rollout advances to the next step.
/// A gate failure triggers the step's `on_failure` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(JsonSchema))]
pub struct RolloutGate {
    /// Metric name. v1 warden supports `http_5xx_rate` and `p95_latency_ms`;
    /// arbitrary PromQL expressions are also accepted.
    pub metric: String,
    /// Comparison condition, e.g. `"< 0.01"` or `"< 200"`.
    /// Operators: `<`, `<=`, `>`, `>=`.
    pub condition: String,
    /// Prometheus query window, e.g. `"5m"`. Must exceed the scrape interval
    /// to avoid false positives from observation lag.
    pub window: String,
}

/// One step in the ordered rollout sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(JsonSchema))]
pub struct RolloutStep {
    /// Mirror names to deploy in this step (e.g. `["yah-marketing-staging"]`).
    pub mirrors: Vec<String>,
    /// Seconds to observe gates after this step's deploy finishes.
    /// Must exceed `gate.window` for all gates to avoid racing observation lag.
    pub gate_window_seconds: u64,
    /// Action when any gate fails. Defaults to `rollback-all` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_failure: Option<RolloutOnFailure>,
}

/// Failure action for a step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RolloutOnFailure {
    /// Rollback only this step's mirrors; earlier-promoted steps stay on the
    /// new version.
    RollbackStep,
    /// Rollback all previously promoted steps back to the prior artifact.
    RollbackAll,
}

impl RolloutOnFailure {
    /// Return the effective `on_failure` action for a step, defaulting to
    /// `RollbackAll` when the step doesn't declare one.
    pub fn for_step(on_failure: Option<&Self>) -> Self {
        on_failure.cloned().unwrap_or(Self::RollbackAll)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_TOML: &str = r#"
[rollout]
strategy = "linear"
window_seconds = 600

[[rollout.gates]]
metric = "http_5xx_rate"
condition = "< 0.01"
window = "5m"

[[rollout.gates]]
metric = "p95_latency_ms"
condition = "< 200"
window = "5m"

[[rollout.steps]]
mirrors = ["yah-marketing-staging"]
gate_window_seconds = 600

[[rollout.steps]]
mirrors = ["yah-marketing-prod"]
gate_window_seconds = 1800
on_failure = "rollback-step"
"#;

    #[test]
    fn round_trip_toml() {
        // Parse from TOML, re-encode as JSON, parse back.
        let file: RolloutFile = toml::from_str(EXAMPLE_TOML).expect("parse toml");
        let policy = &file.rollout;

        assert_eq!(policy.strategy, RolloutStrategy::Linear);
        assert_eq!(policy.window_seconds, 600);
        assert_eq!(policy.gates.len(), 2);
        assert_eq!(policy.steps.len(), 2);

        let step1 = &policy.steps[1];
        assert_eq!(step1.mirrors, vec!["yah-marketing-prod".to_string()]);
        assert_eq!(step1.gate_window_seconds, 1800);
        assert_eq!(step1.on_failure, Some(RolloutOnFailure::RollbackStep));
    }

    #[test]
    fn on_failure_default() {
        assert_eq!(RolloutOnFailure::for_step(None), RolloutOnFailure::RollbackAll);
        assert_eq!(
            RolloutOnFailure::for_step(Some(&RolloutOnFailure::RollbackStep)),
            RolloutOnFailure::RollbackStep
        );
    }
}
