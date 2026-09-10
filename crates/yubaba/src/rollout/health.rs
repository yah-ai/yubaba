//! Per-node boot health as a rollout step gate (R118-T5, W138).
//!
//! # What this closes
//!
//! Before this module a linear rollout's step gate was a *timer*: sleep
//! `gate_window_seconds`, ask Prometheus, promote. On a cloud fleet that is
//! defensible — the metric is the evidence. On a rig it is not. R101-F1 gives a
//! plinth a real A/B verdict about its own boot (`rauc-health.sh good` /
//! `failed`, against the U-Boot `BOOT_<slot>_LEFT` dead-man's-switch), and
//! nothing above it was listening — so a rig could roll forward over a node
//! that came up broken, which is precisely "two image generations playing".
//!
//! This is the listener. It introduces **no second health authority**: the
//! verdict is still decided exactly where R101-F1 decided it, on the node, by
//! the same supervisor that spends the boot-attempt counter. The cluster is a
//! new *observer* of that seam, and a later kamaji adoption changes who calls
//! `good`/`failed`, not what happens here.
//!
//! # Fail closed
//!
//! [`StepHealth`] has no "probably fine" value. A node that has not reported is
//! not healthy — it is unknown, and unknown does not promote a step. That is
//! the same posture `crates/society/core/src/liveness.rs` takes in the
//! noisetable camp, where an unknown node is a veto rather than an assumed yes,
//! and it is the whole point: the failure this gate exists to catch (a plinth
//! that never came back) looks *exactly* like silence.
//!
//! The bound on waiting is the rollout's own
//! [`RolloutPolicy::window_seconds`](workload_spec::rollout::RolloutPolicy) —
//! already declared, and until now unread by the engine. A step that never
//! gathers its evidence fails the rollout when that budget runs out; it does
//! not promote and it does not hang forever.

use std::collections::BTreeMap;

use workload_spec::rollout::{RolloutPolicy, RolloutStep};

use crate::raft::{NodeHealthRecord, NodeHealthVerdict};

/// What the filed evidence says about promoting one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepHealth {
    /// The policy does not require node health. The gate is the window and the
    /// SLO gates, exactly as before R118-T5.
    NotRequired,
    /// Every node this step names has reported a healthy boot, and no node
    /// anywhere in this rollout has reported a failed one.
    AllGood,
    /// A node reported a failed boot. Terminal for the rollout.
    ///
    /// Scanned across **every** node that has reported for this rollout, not
    /// just the ones in the current step: a plinth promoted two steps ago that
    /// has since fallen over is exactly the case the acceptance line ("the rig
    /// never ends up with two image generations playing") is about, and a
    /// per-step scan would look straight past it.
    Failed { node: String, detail: String },
    /// Not every node this step names has reported yet. Not a failure — but
    /// not a promotion either.
    Unknown { missing: Vec<String> },
}

/// Read the filed evidence for one step.
///
/// Pure over `(policy, step, reports)` so the rule is testable without a
/// cluster — which matters more here than usual, because the two branches that
/// must never be confused ([`StepHealth::AllGood`] and
/// [`StepHealth::Unknown`]) differ only by an absent map key.
pub fn step_health(
    policy: &RolloutPolicy,
    step: &RolloutStep,
    reports: &BTreeMap<String, NodeHealthRecord>,
) -> StepHealth {
    if !policy.require_node_health {
        return StepHealth::NotRequired;
    }

    // Failure first, and rollout-wide. Checked before the current step's own
    // evidence so a step still gathering reports cannot mask a node that has
    // already said no.
    if let Some(rec) = reports
        .values()
        .find(|r| r.verdict == NodeHealthVerdict::Failed)
    {
        return StepHealth::Failed {
            node: rec.node.clone(),
            detail: rec.detail.clone(),
        };
    }

    let missing: Vec<String> = step
        .mirrors
        .iter()
        .filter(|node| !reports.contains_key(*node))
        .cloned()
        .collect();
    if missing.is_empty() {
        StepHealth::AllGood
    } else {
        StepHealth::Unknown { missing }
    }
}

/// Which rollouts one node's boot-health verdict actually speaks to.
///
/// A plinth does not know what a rollout is — it knows it just booted and
/// whether that went well. So the mapping from "this node, this verdict" to
/// "these rollout ids" is resolved here, against replicated state, rather than
/// being something the reporter has to work out and could get wrong.
///
/// Three filters, each of which is load-bearing:
///
/// - **in flight** — a finished rollout is not evidence-gathering, and a report
///   arriving after it retires would resurrect a map that was cleared with it.
/// - **`require_node_health`** — a cloud rollout's `mirrors` are mirror names,
///   and a node whose hostname happens to collide with one must not file health
///   against it. Reports are only stored where they are read.
/// - **named by some step** — any step, not just the current one. A node
///   promoted two steps ago that has since fallen over is exactly the report
///   worth having, and the step gate scans rollout-wide for failures precisely
///   so it can act on it.
pub fn rollouts_awaiting(
    node: &str,
    rollouts: &BTreeMap<String, crate::raft::RolloutRaftRecord>,
) -> Vec<String> {
    rollouts
        .iter()
        .filter(|(_, raw)| {
            raw.policy.require_node_health
                && super::RolloutRecord::from_raft(raw).status.is_in_flight()
                && raw
                    .policy
                    .steps
                    .iter()
                    .any(|s| s.mirrors.iter().any(|m| m == node))
        })
        .map(|(id, _)| id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(require: bool) -> RolloutPolicy {
        let mut p: RolloutPolicy = serde_json::from_value(serde_json::json!({
            "strategy": "linear",
            "window_seconds": 600,
            "steps": [
                { "mirrors": ["plinth-1", "plinth-2"], "gate_window_seconds": 1 },
                { "mirrors": ["plinth-3"], "gate_window_seconds": 1 }
            ]
        }))
        .expect("policy fixture");
        p.require_node_health = require;
        p
    }

    fn report(node: &str, verdict: NodeHealthVerdict) -> (String, NodeHealthRecord) {
        (
            node.to_string(),
            NodeHealthRecord {
                node: node.to_string(),
                verdict,
                detail: format!("{node} says {verdict:?}"),
                reported_at: 1,
            },
        )
    }

    #[test]
    fn a_policy_that_does_not_require_health_is_gated_by_the_window_alone() {
        let p = policy(false);
        // Even with a filed FAILURE on the books: an operator can turn the
        // requirement off, and this function must then say nothing at all
        // rather than half-enforce it.
        let reports = BTreeMap::from([report("plinth-1", NodeHealthVerdict::Failed)]);
        assert_eq!(
            step_health(&p, &p.steps[0], &reports),
            StepHealth::NotRequired
        );
    }

    #[test]
    fn no_reports_at_all_is_unknown_and_names_every_node_it_is_waiting_on() {
        let p = policy(true);
        assert_eq!(
            step_health(&p, &p.steps[0], &BTreeMap::new()),
            StepHealth::Unknown {
                missing: vec!["plinth-1".to_string(), "plinth-2".to_string()],
            }
        );
    }

    #[test]
    fn a_partially_reported_step_is_unknown_not_good() {
        // The bug this rules out: one node of two reports `good`, and a gate
        // written as "no failures on file" promotes over the silent one.
        let p = policy(true);
        let reports = BTreeMap::from([report("plinth-1", NodeHealthVerdict::Good)]);
        assert_eq!(
            step_health(&p, &p.steps[0], &reports),
            StepHealth::Unknown {
                missing: vec!["plinth-2".to_string()],
            }
        );
    }

    #[test]
    fn every_node_reporting_good_is_the_only_way_to_promote() {
        let p = policy(true);
        let reports = BTreeMap::from([
            report("plinth-1", NodeHealthVerdict::Good),
            report("plinth-2", NodeHealthVerdict::Good),
        ]);
        assert_eq!(step_health(&p, &p.steps[0], &reports), StepHealth::AllGood);
    }

    #[test]
    fn one_failure_beats_every_good_beside_it() {
        let p = policy(true);
        let reports = BTreeMap::from([
            report("plinth-1", NodeHealthVerdict::Good),
            report("plinth-2", NodeHealthVerdict::Failed),
        ]);
        assert!(matches!(
            step_health(&p, &p.steps[0], &reports),
            StepHealth::Failed { node, .. } if node == "plinth-2"
        ));
    }

    #[test]
    fn a_failure_from_an_earlier_step_still_stops_a_later_one() {
        // step 1 names only plinth-3, and plinth-3 is fine. The rollout is not:
        // plinth-1, promoted in step 0, has since reported a failed boot. A
        // per-step scan would promote here and leave the rig split.
        let p = policy(true);
        let reports = BTreeMap::from([
            report("plinth-1", NodeHealthVerdict::Failed),
            report("plinth-3", NodeHealthVerdict::Good),
        ]);
        assert!(matches!(
            step_health(&p, &p.steps[1], &reports),
            StepHealth::Failed { node, .. } if node == "plinth-1"
        ));
    }

    fn raft_record(id: &str, status: &str, p: &RolloutPolicy) -> crate::raft::RolloutRaftRecord {
        crate::raft::RolloutRaftRecord {
            rollout_id: id.to_string(),
            artifact: "release:rig-image@v2".to_string(),
            status_json: format!(r#"{{"kind":"{status}"}}"#),
            current_step: 0,
            started_at: 1,
            policy: p.clone(),
            trigger: serde_json::Value::Null,
            revision: 1,
        }
    }

    #[test]
    fn a_report_resolves_to_the_in_flight_rollouts_that_name_the_node() {
        let requiring = policy(true);
        let rollouts = BTreeMap::from([
            ("rt-live".to_string(), raft_record("rt-live", "running", &requiring)),
            // Finished: its health map has been (or is about to be) cleared with
            // it, so a late report must not revive one.
            ("rt-done".to_string(), raft_record("rt-done", "succeeded", &requiring)),
            // In flight, names the node, but does not gate on node health — a
            // cloud rollout whose mirror name collides with a plinth hostname.
            ("rt-cloud".to_string(), raft_record("rt-cloud", "running", &policy(false))),
        ]);
        assert_eq!(
            rollouts_awaiting("plinth-1", &rollouts),
            vec!["rt-live".to_string()]
        );
    }

    #[test]
    fn a_node_no_step_names_resolves_to_nothing() {
        // The ordinary case on a fielded board: an everyday reboot, with a
        // fleet update in flight somewhere else. Reporting must be a no-op.
        let requiring = policy(true);
        let rollouts = BTreeMap::from([(
            "rt-live".to_string(),
            raft_record("rt-live", "running", &requiring),
        )]);
        assert!(rollouts_awaiting("plinth-99", &rollouts).is_empty());
    }

    #[test]
    fn a_node_from_a_later_step_still_resolves_while_an_earlier_step_runs() {
        // plinth-3 is only named by step 1, and the rollout is on step 0. Its
        // verdict is still worth filing — a `failed` from it is rollout-wide.
        let requiring = policy(true);
        let rollouts = BTreeMap::from([(
            "rt-live".to_string(),
            raft_record("rt-live", "running", &requiring),
        )]);
        assert_eq!(
            rollouts_awaiting("plinth-3", &rollouts),
            vec!["rt-live".to_string()]
        );
    }

    #[test]
    fn a_step_that_names_no_nodes_is_good_rather_than_forever_unknown() {
        // Degenerate but reachable: a policy step with an empty mirror list has
        // nothing to wait for. Answering `Unknown` here would stall a rollout
        // on evidence that can never arrive.
        let mut p = policy(true);
        p.steps[0].mirrors.clear();
        assert_eq!(step_health(&p, &p.steps[0], &BTreeMap::new()), StepHealth::AllGood);
    }
}
