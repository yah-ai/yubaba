//! Is this cluster's quorum healthy enough to act on? — R859-F2 (W267).
//!
//! `.yah/docs/guides/yubaba-failover.md` opens its pre-checks with a rule an
//! operator is expected to apply by eye:
//!
//! > Quorum is currently healthy. Do not fail over out of a degraded quorum —
//! > you will lose it entirely.
//!
//! [`judge_quorum`] is that sentence as code. Nothing enforced it before: the
//! nearest thing,
//! [`QuorumGeography::judge_voter_count`](crate::cluster_policy::QuorumGeography::judge_voter_count),
//! judges the *shape* of a proposed voter set (does one region hold a
//! majority?) and never its live *health*. Two different questions — a
//! perfectly-shaped 3-voter set with two voters down is geographically sound
//! and operationally dead.
//!
//! # Why this is a pure function
//!
//! Both inputs are already in the leader loop's hand once per tick — the voter
//! set from `RaftMetrics::membership_config` and the
//! [`LivenessReport`](crate::failure_detector::LivenessReport) from the
//! raft-heartbeat detector ([`crate::scheduler`] reads both). So the judgement
//! needs no I/O, no clock and no cluster, which means it can be tested as
//! arithmetic across the cases that matter rather than by standing up nodes and
//! killing them. Same pure-decision / paced-loop split
//! [`crate::scheduler::decide_transfer`] and `leader_pin` already use.
//!
//! # The counting rule, and its one deliberate asymmetry
//!
//! A raft cluster of `n` voters needs `n / 2 + 1` to commit. This module counts
//! a voter as *unavailable* only on an explicit [`NodeLiveness::Down`]
//! observation. `Suspect`, `Unknown`, and a voter absent from the report
//! entirely all count as **available**.
//!
//! That is the same direction-preserving rule
//! [`crate::failure_detector::FailureDetector`] states for its own trait ("an
//! empty report never means every node is down") and that [`crate::scheduler`]
//! applies to the raft channel's veto — and here it cuts a specific way. This
//! verdict's consumer *refuses withdrawals* when quorum is degraded (R859-F2
//! decision 3), so reading absence as `Down` would manufacture a `Degraded`
//! verdict out of no evidence and freeze the effector permanently. The failure
//! mode of the chosen direction is milder and self-correcting: a genuinely
//! dead-but-unobserved voter reads as available for exactly as long as the
//! detector has nothing to say about it.
//!
//! An **empty membership** is the one case that is neither — see
//! [`QuorumVerdict::Unknown`].
//!
//! # Small is not degraded
//!
//! "Degraded" here means **a voter is actually down**, not "this topology has
//! no redundancy". The two come apart at the bottom of the ladder and getting
//! it wrong is not conservative, it is inert: a 1-voter rig has zero margin by
//! construction, so a margin-only rule would call its healthiest possible state
//! degraded and the verdict would refuse every withdrawal forever. A permanent
//! refusal is not a safety property, it is a disabled feature that looks like
//! one.
//!
//! So the rule takes both halves: [`QuorumVerdict::Degraded`] needs the cluster
//! to be at or under the majority *and* to have lost a voter to get there. A
//! fully-available cluster is [`QuorumVerdict::Healthy`] at any size, with
//! `margin: 0` stating plainly how much slack it has. That is also the honest
//! reading of the guide's sentence — "do not fail over **out of** a degraded
//! quorum" describes a cluster that has already lost something, not a small one
//! that is entirely intact.

use crate::failure_detector::{LivenessReport, NodeLiveness};
use crate::raft::YubabaNodeId;

/// What [`judge_quorum`] concluded about the cluster's live consensus health.
///
/// Every variant carries enough to render a log line or an operator-facing
/// refusal without the caller re-deriving the counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumVerdict {
    /// Enough voters are available to commit, and nothing is degraded — either
    /// every voter is available, or enough are that a further loss is
    /// survivable.
    Healthy {
        /// Voters in the membership config.
        voters: usize,
        /// Voters not explicitly observed `Down`.
        available: usize,
        /// How many voters could still be lost while staying quorate.
        ///
        /// `0` is legitimate and does **not** mean degraded: a fully-available
        /// 1- or 2-voter cluster has no slack by construction. See the module
        /// docs' "small is not degraded".
        margin: usize,
    },
    /// Quorum is at risk or already lost: fewer available voters than the
    /// majority needs, or exactly the majority *because a voter went down*.
    Degraded {
        voters: usize,
        available: usize,
        /// Why, in one operator-readable sentence.
        reason: String,
    },
    /// There is nothing to judge — the membership config names no voters.
    ///
    /// Deliberately its own verdict rather than folded into `Degraded`, because
    /// the two want opposite handling and the distinction is not cosmetic. An
    /// empty membership is what a node reads *before* `raft init`, and on every
    /// tick of a single-node rig that never initialised. Calling that
    /// `Degraded` would be a false alarm; calling it `Healthy` would let an
    /// effector act with no consensus behind it at all. So it is neither, and
    /// [`Self::permits_withdrawal`] answers `false` for it — unknown is not
    /// permission.
    Unknown {
        /// The reason no judgement could be made.
        reason: String,
    },
}

impl QuorumVerdict {
    /// May an effector take a **withdrawal** action on this verdict?
    ///
    /// `true` only for [`Healthy`](Self::Healthy). This is R859-F2 decision 3
    /// and it is the same fail-closed-on-withdrawal / fail-open-on-addition
    /// rule R859-F1 established for its apex prune gate
    /// (`cloud::reconciler::domain::DomainPasswayPlan::origins_complete`):
    /// taking a live record or a live IP *away* on evidence we are not sure of
    /// is how a flap becomes an outage, while an addition can never make the
    /// world worse. Additions are not gated by this and must not be.
    pub fn permits_withdrawal(&self) -> bool {
        matches!(self, Self::Healthy { .. })
    }

    /// The operator-facing explanation, for a refusal message or a log line.
    pub fn reason(&self) -> String {
        match self {
            Self::Healthy {
                voters,
                available,
                margin,
            } => format!(
                "quorum healthy: {available}/{voters} voters available, {margin} to spare"
            ),
            Self::Degraded { reason, .. } | Self::Unknown { reason } => reason.clone(),
        }
    }
}

/// Judge live quorum health from the voter set and one detector's report.
///
/// `voters` is the membership config's voter ids —
/// `RaftMetrics::membership_config.membership().voter_ids()` at the call site.
/// `report` is any [`LivenessReport`]; the caller decides which channel it
/// trusts (the leader loop passes the raft-heartbeat detector's, because
/// whether a voter can *commit* is a raft question, not a lease question).
///
/// See the module docs for why an unobserved voter counts as available and why
/// an empty membership is [`QuorumVerdict::Unknown`] rather than degraded.
pub fn judge_quorum(voters: &[YubabaNodeId], report: &LivenessReport) -> QuorumVerdict {
    let total = voters.len();
    if total == 0 {
        return QuorumVerdict::Unknown {
            reason: "raft membership names no voters — nothing to judge (a node that has not \
                     been `raft init`ed yet reads exactly like this)"
                .to_string(),
        };
    }

    let mut down: Vec<YubabaNodeId> = voters
        .iter()
        .copied()
        .filter(|id| {
            report
                .get(id)
                .is_some_and(|obs| obs.liveness == NodeLiveness::Down)
        })
        .collect();
    down.sort_unstable();
    down.dedup();

    let available = total - down.len();
    // Raft's own majority: n/2 + 1, which is why an even voter count buys no
    // extra fault tolerance over the odd count below it (4 voters need 3, the
    // same as 3 voters need 2, while giving one more thing to lose).
    let majority = total / 2 + 1;

    if available < majority {
        return QuorumVerdict::Degraded {
            voters: total,
            available,
            reason: format!(
                "quorum LOST: {available}/{total} voters available but {majority} are needed to \
                 commit (down: {down:?})"
            ),
        };
    }
    // Quorate, but a voter is down AND there is no margin left. Both halves are
    // required — see the module docs' "small is not degraded".
    if available == majority && available < total {
        return QuorumVerdict::Degraded {
            voters: total,
            available,
            reason: format!(
                "quorum AT RISK: {available}/{total} voters available, exactly the {majority} \
                 needed to commit — losing one more loses quorum entirely, so this is not a \
                 state to take a withdrawal out of (yubaba-failover.md pre-check 1) (down: \
                 {down:?})"
            ),
        };
    }

    QuorumVerdict::Healthy {
        voters: total,
        available,
        margin: available - majority,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure_detector::NodeObservation;

    fn report(rows: &[(YubabaNodeId, NodeLiveness)]) -> LivenessReport {
        rows.iter()
            .map(|(id, liveness)| {
                (
                    *id,
                    NodeObservation {
                        liveness: *liveness,
                        silent_for_ms: None,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn three_of_three_live_is_healthy_with_one_to_spare() {
        let v = judge_quorum(
            &[1, 2, 3],
            &report(&[
                (1, NodeLiveness::Live),
                (2, NodeLiveness::Live),
                (3, NodeLiveness::Live),
            ]),
        );
        assert_eq!(
            v,
            QuorumVerdict::Healthy {
                voters: 3,
                available: 3,
                margin: 1
            }
        );
        assert!(v.permits_withdrawal());
    }

    /// The case the guide's prose is really about: still *quorate*, but with no
    /// margin. A 3-voter cluster with one voter down can still commit — and is
    /// exactly the state "do not fail over out of a degraded quorum, you will
    /// lose it entirely" warns against, because the failover itself is what
    /// costs the second voter.
    #[test]
    fn two_of_three_is_quorate_but_degraded_because_the_margin_is_gone() {
        let v = judge_quorum(
            &[1, 2, 3],
            &report(&[
                (1, NodeLiveness::Live),
                (2, NodeLiveness::Live),
                (3, NodeLiveness::Down),
            ]),
        );
        match &v {
            QuorumVerdict::Degraded {
                voters,
                available,
                reason,
            } => {
                assert_eq!((*voters, *available), (3, 2));
                assert!(reason.contains("AT RISK"), "{reason}");
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
        assert!(
            !v.permits_withdrawal(),
            "a withdrawal must be refused with no quorum margin left"
        );
    }

    #[test]
    fn one_of_three_has_lost_quorum_outright() {
        let v = judge_quorum(
            &[1, 2, 3],
            &report(&[
                (1, NodeLiveness::Live),
                (2, NodeLiveness::Down),
                (3, NodeLiveness::Down),
            ]),
        );
        match &v {
            QuorumVerdict::Degraded {
                available, reason, ..
            } => {
                assert_eq!(*available, 1);
                assert!(reason.contains("LOST"), "{reason}");
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
        assert!(!v.permits_withdrawal());
    }

    /// An even voter count is not a second rule, it is the same `n/2 + 1`
    /// arithmetic — and the point worth pinning is that it buys nothing: 4
    /// voters tolerate one loss just as 3 do, so 3-of-4 is `Degraded` for the
    /// identical no-margin reason 2-of-3 is.
    #[test]
    fn an_even_voter_count_buys_no_extra_tolerance() {
        let all_live = judge_quorum(
            &[1, 2, 3, 4],
            &report(&[
                (1, NodeLiveness::Live),
                (2, NodeLiveness::Live),
                (3, NodeLiveness::Live),
                (4, NodeLiveness::Live),
            ]),
        );
        assert_eq!(
            all_live,
            QuorumVerdict::Healthy {
                voters: 4,
                available: 4,
                margin: 1
            },
            "4 voters need 3 to commit, so 4 available leaves a margin of exactly 1 — the same \
             margin 3 voters have"
        );

        let one_down = judge_quorum(&[1, 2, 3, 4], &report(&[(4, NodeLiveness::Down)]));
        assert!(
            matches!(one_down, QuorumVerdict::Degraded { available: 3, .. }),
            "got {one_down:?}"
        );

        let two_down = judge_quorum(
            &[1, 2, 3, 4],
            &report(&[(3, NodeLiveness::Down), (4, NodeLiveness::Down)]),
        );
        assert!(
            matches!(two_down, QuorumVerdict::Degraded { available: 2, .. }),
            "got {two_down:?}"
        );
    }

    #[test]
    fn a_two_voter_cluster_has_no_fault_tolerance_at_all() {
        let v = judge_quorum(&[1, 2], &report(&[(2, NodeLiveness::Down)]));
        assert!(
            matches!(v, QuorumVerdict::Degraded { available: 1, .. }),
            "got {v:?}"
        );
    }

    /// The case that forced the "small is not degraded" rule (this test failed
    /// on the first, margin-only implementation). A 1-voter rig has zero margin
    /// at its healthiest, so a rule keyed on margin alone would refuse every
    /// withdrawal on it forever — an inert feature wearing the costume of a
    /// safety check.
    #[test]
    fn a_single_voter_rig_is_healthy_while_it_is_up_and_lost_when_it_is_not() {
        let up = judge_quorum(&[1], &report(&[(1, NodeLiveness::Live)]));
        assert_eq!(
            up,
            QuorumVerdict::Healthy {
                voters: 1,
                available: 1,
                margin: 0
            },
            "a fully-available cluster is healthy at any size; margin 0 states the slack honestly"
        );
        assert!(up.permits_withdrawal());
        assert!(!judge_quorum(&[1], &report(&[(1, NodeLiveness::Down)])).permits_withdrawal());
    }

    /// Same rule one size up, and the pair that shows it is about *loss* rather
    /// than about size: an intact 2-voter cluster is healthy with no margin,
    /// while a 3-voter cluster reduced to the same two available voters is
    /// degraded. Identical `available`, opposite verdicts — because one has lost
    /// a voter and the other has not.
    #[test]
    fn an_intact_two_voter_cluster_is_healthy_but_a_three_voter_one_reduced_to_two_is_not() {
        assert_eq!(
            judge_quorum(&[1, 2], &LivenessReport::new()),
            QuorumVerdict::Healthy {
                voters: 2,
                available: 2,
                margin: 0
            }
        );
        assert!(
            !judge_quorum(&[1, 2, 3], &report(&[(3, NodeLiveness::Down)])).permits_withdrawal()
        );
    }

    #[test]
    fn empty_membership_is_unknown_and_does_not_permit_a_withdrawal() {
        let v = judge_quorum(&[], &LivenessReport::new());
        assert!(matches!(v, QuorumVerdict::Unknown { .. }), "got {v:?}");
        assert!(
            !v.permits_withdrawal(),
            "unknown is not permission — an uninitialised node must not act"
        );
    }

    /// The direction rule from the module docs, pinned: only an explicit `Down`
    /// subtracts. An empty report on a healthy 3-voter cluster must read as
    /// healthy, or a follower's (always-empty) raft-heartbeat report would
    /// freeze every effector in the fleet.
    #[test]
    fn suspect_unknown_and_absent_all_count_as_available() {
        for liveness in [NodeLiveness::Suspect, NodeLiveness::Unknown] {
            let v = judge_quorum(&[1, 2, 3], &report(&[(2, liveness), (3, liveness)]));
            assert!(
                v.permits_withdrawal(),
                "{liveness:?} must not be read as Down, got {v:?}"
            );
        }
        let empty = judge_quorum(&[1, 2, 3], &LivenessReport::new());
        assert_eq!(
            empty,
            QuorumVerdict::Healthy {
                voters: 3,
                available: 3,
                margin: 1
            },
            "an empty report is 'no view', never 'everyone is down'"
        );
    }

    /// A report may name nodes that are not voters (learners, or a node just
    /// removed from membership). Those must not subtract from the voter count.
    #[test]
    fn a_down_non_voter_does_not_degrade_quorum() {
        let v = judge_quorum(
            &[1, 2, 3],
            &report(&[(4, NodeLiveness::Down), (5, NodeLiveness::Down)]),
        );
        assert_eq!(
            v,
            QuorumVerdict::Healthy {
                voters: 3,
                available: 3,
                margin: 1
            }
        );
    }
}
