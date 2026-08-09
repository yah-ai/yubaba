//! Cluster policy — the deployment-wide rules a yubaba cluster runs under,
//! named as a value instead of hardcoded at the sites that obey them.
//!
//! Three rules were, until this module existed, invisible decisions living in
//! doc comments and literals:
//!
//! | rule | used to live at | now |
//! |---|---|---|
//! | joining nodes stay learners forever | prose in `raft_add_learner`'s doc comment | [`VoterAdmission`] |
//! | the raft leader is also the external-ingress owner | `leader::on_became_leader` writing `SetIngressOwner` unconditionally | [`IngressOwnership`] |
//! | election/heartbeat timings tuned for cross-region WAN | three literals in `raft::open_with_state_machine` | [`RaftTiming`] |
//!
//! Naming them is worth doing for the fleet on its own: "why is this cluster's
//! election timeout 3 seconds" and "why can't I promote this node" now have
//! answers you can read, test, and print, rather than answers you have to
//! excavate. That the same seam lets a second kind of deployment exist is a
//! consequence, not the motivation.
//!
//! # This is a value, not a mode enum
//!
//! There is deliberately **no** `enum ClusterMode { Fleet, Gallery }` that call
//! sites match on. With ~40 HTTP routes a `if mode == Gallery` branch would
//! metastasise, and it is the type-name-sniffing anti-pattern: behaviour keyed
//! on an identity label rather than on the property actually being decided.
//! Instead every decision point reads *the field that answers its question* —
//! [`ClusterPolicy::voter_admission`], [`ClusterPolicy::ingress_ownership`],
//! [`ClusterPolicy::timing`]. [`ClusterPolicy::fleet`] and
//! [`ClusterPolicy::rig`] are constructors for such a value and nothing more;
//! nothing downstream can ask "which preset am I?", because the answer is not
//! recorded.
//!
//! # Static per deployment
//!
//! The policy is chosen once, at process start (`yubaba serve
//! --cluster-profile`), and never negotiated at runtime. A cluster does not
//! discover its policy from peers at join time, and two clusters running
//! different policies never merge: a rig founds its own cluster and talks to
//! the cloud over ordinary API calls, never by joining the cloud's raft.

use std::time::Duration;

use crate::raft::YubabaNodeId;

/// Whether a learner in this cluster may ever be promoted to a voter.
///
/// Promotion is a quorum-safety decision, which is why it is policy rather than
/// an operator whim: every added voter raises the number of nodes that must
/// stay reachable for the cluster to accept writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoterAdmission {
    /// Nodes that join a running cluster stay learners for good. They receive
    /// full log/snapshot replication (so they hold complete cluster state and
    /// serve local reads) but never vote and never count toward quorum.
    ///
    /// This is the cloud fleet's rule. Voters are the founding set written by
    /// `raft init`; a macOS home-lab box or a residential-network node joins as
    /// a learner so a flaky link can never endanger the datacenter voters'
    /// quorum.
    LearnerOnly,

    /// A caught-up learner may be promoted to voter, as long as doing so keeps
    /// the voter count at or below `max_voters`.
    ///
    /// This is the rule for a self-contained installation whose nodes are all
    /// peers on one LAN: there is no separate "cloud tier" to be the permanent
    /// voter set, so the cluster grows its own. The cap exists because quorum
    /// cost grows with the voter set — past a handful of voters every write
    /// waits on more machines for no additional fault tolerance.
    PromotableUpTo {
        /// Maximum number of voters this cluster will hold. Prefer an odd
        /// number: an even voter set tolerates the same number of failures as
        /// the odd one below it while needing one more ack per write.
        max_voters: usize,
    },
}

/// What [`VoterAdmission`] decided about one promotion request.
///
/// Separating the verdict from the HTTP handler keeps the rule unit-testable
/// without a live cluster, and keeps the *reason* for a refusal in the same
/// place as the rule that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionVerdict {
    /// The node is already a voter — nothing to do (idempotent success).
    AlreadyVoter,
    /// Promotion is permitted; the caller should perform the membership change.
    Promote,
    /// Promotion is forbidden by policy. Carries an operator-readable reason —
    /// this is a permanent "no" under the current policy, not a retryable error.
    Refuse(String),
}

impl VoterAdmission {
    /// Judge a request to promote `node` to voter.
    ///
    /// `current_voters` is the size of the voter set *before* the promotion, and
    /// `is_already_voter` says whether `node` is in it.
    pub fn judge(
        &self,
        node: YubabaNodeId,
        current_voters: usize,
        is_already_voter: bool,
    ) -> PromotionVerdict {
        if is_already_voter {
            return PromotionVerdict::AlreadyVoter;
        }
        match self {
            Self::LearnerOnly => PromotionVerdict::Refuse(format!(
                "cluster policy is learner-only: node {node} cannot be promoted to voter. \
                 The voter set is fixed at cluster founding so that a node on an \
                 unreliable link can never endanger quorum."
            )),
            Self::PromotableUpTo { max_voters } => {
                if current_voters >= *max_voters {
                    PromotionVerdict::Refuse(format!(
                        "cluster policy caps the voter set at {max_voters}; it already holds \
                         {current_voters}. Remove a voter before promoting node {node}, or \
                         leave it a learner — learners hold full replicated state either way."
                    ))
                } else {
                    PromotionVerdict::Promote
                }
            }
        }
    }
}

/// Who owns the cluster's **external** identity — the address clients outside
/// the mesh reach it at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressOwnership {
    /// The raft leader is also the external-ingress owner: on winning
    /// leadership a node restores and starts the ingress services and claims
    /// `SetIngressOwner` in replicated state; on losing it, it stops them.
    ///
    /// The cloud fleet's rule — its Headscale coordinator's clients live
    /// outside the mesh, so exactly one node must hold that external identity
    /// and it must move when leadership moves.
    FollowsRaftLeader,

    /// No node claims external ingress from the raft-leader path.
    ///
    /// For a cluster with no outside-the-mesh clients to serve — every peer is
    /// on the local link and reaches the others directly. Leadership still
    /// elects and still decides who *writes*; it simply carries no external
    /// identity with it.
    ///
    /// Note this is not merely "the fleet behaviour minus the systemd calls":
    /// coupling gateway election to raft leadership is itself a choice, and one
    /// that lets a flaky uplink cause leadership churn. Decoupling the two is
    /// the reason this is a named field rather than an `if` around the
    /// `systemctl` calls.
    Unmanaged,
}

impl IngressOwnership {
    /// Whether a leadership transition should drive the external-ingress
    /// services and the `SetIngressOwner` claim.
    pub fn follows_raft_leader(&self) -> bool {
        matches!(self, Self::FollowsRaftLeader)
    }
}

/// Raft election and heartbeat timings, in milliseconds.
///
/// These are the knobs that decide how fast a cluster notices a dead leader,
/// traded against how often a healthy-but-slow link triggers a spurious
/// election. The right values are a property of the *network the cluster sits
/// on*, which is why they belong to the policy and not to a constant in the
/// node factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaftTiming {
    /// Leader → follower heartbeat period.
    pub heartbeat_interval_ms: u64,
    /// Lower bound of the randomised election timeout.
    pub election_timeout_min_ms: u64,
    /// Upper bound of the randomised election timeout. Also openraft's leader
    /// lease: a follower will not grant a vote within this long of hearing from
    /// a leader it believes in.
    pub election_timeout_max_ms: u64,
}

impl RaftTiming {
    /// Cross-region WAN timings: heartbeat 500 ms, election 1.5–3 s.
    ///
    /// Sized for voters in different datacenters, where a 200 ms round trip and
    /// an occasional multi-second stall are normal. An election timeout tight
    /// enough for a LAN would make transatlantic voters campaign against each
    /// other on ordinary jitter.
    pub const fn wan() -> Self {
        Self {
            heartbeat_interval_ms: 500,
            election_timeout_min_ms: 1500,
            election_timeout_max_ms: 3000,
        }
    }

    /// Single-LAN timings: heartbeat 150 ms, election 450–900 ms.
    ///
    /// Every node is a switch hop away, so sub-millisecond round trips are the
    /// norm and there is no reason to leave a dead leader in place for three
    /// seconds. Failover lands inside a second.
    pub const fn lan() -> Self {
        Self {
            heartbeat_interval_ms: 150,
            election_timeout_min_ms: 450,
            election_timeout_max_ms: 900,
        }
    }

    /// Build the openraft [`Config`](openraft::Config) this timing describes.
    ///
    /// Fails if the timings are inconsistent (openraft requires
    /// `heartbeat_interval < election_timeout_min <= election_timeout_max`),
    /// so an invalid policy is rejected at node open rather than producing a
    /// cluster that campaigns continuously.
    pub fn to_openraft_config(self) -> Result<openraft::Config, openraft::ConfigError> {
        openraft::Config {
            heartbeat_interval: self.heartbeat_interval_ms,
            election_timeout_min: self.election_timeout_min_ms,
            election_timeout_max: self.election_timeout_max_ms,
            ..Default::default()
        }
        .validate()
    }
}

/// A node is judged `Suspect` once it has been silent for this many heartbeat
/// periods, and `Down` after [`DOWN_AFTER_HEARTBEATS`].
///
/// Three periods is the usual "one lost packet is not a failure, three in a row
/// is a pattern" threshold, and it lands just below the election timeout — so a
/// node reads as suspect at about the point raft itself starts to doubt it.
pub const SUSPECT_AFTER_HEARTBEATS: u32 = 3;

/// A node silent for this many heartbeat periods is judged `Down`.
///
/// Deliberately several times the election timeout: by the time a detector says
/// "down" the cluster has already had the chance to elect around the node, so
/// this threshold is about *reporting* a failure, not reacting to one.
pub const DOWN_AFTER_HEARTBEATS: u32 = 10;

/// How long a peer may be silent before a failure detector downgrades its
/// liveness. Derived from [`RaftTiming`] so the thresholds scale with the
/// network the cluster was configured for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessThresholds {
    /// Silence beyond this is `Suspect`.
    pub suspect_after: Duration,
    /// Silence beyond this is `Down`.
    pub down_after: Duration,
}

impl LivenessThresholds {
    /// Scale the thresholds off `timing`'s heartbeat period.
    pub const fn from_timing(timing: RaftTiming) -> Self {
        Self {
            suspect_after: Duration::from_millis(
                timing.heartbeat_interval_ms * SUSPECT_AFTER_HEARTBEATS as u64,
            ),
            down_after: Duration::from_millis(
                timing.heartbeat_interval_ms * DOWN_AFTER_HEARTBEATS as u64,
            ),
        }
    }
}

/// The rules a yubaba cluster runs under, fixed for the life of the process.
///
/// Read [the module docs](self) before adding a field: the constraint that
/// makes this shape work is that every field answers a *question a decision
/// point asks*, and no field records which preset produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterPolicy {
    /// Whether learners can become voters — read by `POST /raft/promote-voter`.
    pub voter_admission: VoterAdmission,
    /// Whether the raft leader carries the cluster's external identity — read
    /// by the [`leader`](crate::leader) watcher on every leadership transition.
    pub ingress_ownership: IngressOwnership,
    /// Raft election/heartbeat timings — read by
    /// [`raft::open`](crate::raft::open) when constructing the node, and by
    /// failure detectors deriving their thresholds.
    pub timing: RaftTiming,
}

impl ClusterPolicy {
    /// The cloud fleet: geographically distributed voters, a fixed voter set,
    /// and an external Headscale/ingress identity that follows leadership.
    ///
    /// This is the behaviour yubaba had before the policy was named, so it is
    /// also [`Default`].
    pub const fn fleet() -> Self {
        Self {
            voter_admission: VoterAdmission::LearnerOnly,
            ingress_ownership: IngressOwnership::FollowsRaftLeader,
            timing: RaftTiming::wan(),
        }
    }

    /// A self-contained installation on one LAN: peers all of a kind, so the
    /// cluster grows its own voter set (capped at five), no external ingress
    /// identity, and sub-second failover.
    pub const fn rig() -> Self {
        Self {
            voter_admission: VoterAdmission::PromotableUpTo { max_voters: 5 },
            ingress_ownership: IngressOwnership::Unmanaged,
            timing: RaftTiming::lan(),
        }
    }

    /// Thresholds a failure detector should use under this policy.
    pub const fn liveness_thresholds(&self) -> LivenessThresholds {
        LivenessThresholds::from_timing(self.timing)
    }
}

impl Default for ClusterPolicy {
    fn default() -> Self {
        Self::fleet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_never_promotes_a_learner() {
        let verdict = ClusterPolicy::fleet().voter_admission.judge(4, 3, false);
        assert!(
            matches!(verdict, PromotionVerdict::Refuse(_)),
            "the fleet's learner-only rule must refuse promotion: {verdict:?}"
        );
    }

    #[test]
    fn promoting_an_existing_voter_is_a_noop_under_every_policy() {
        for policy in [ClusterPolicy::fleet(), ClusterPolicy::rig()] {
            assert_eq!(
                policy.voter_admission.judge(2, 3, true),
                PromotionVerdict::AlreadyVoter,
                "an already-voter request is idempotent, never an error"
            );
        }
    }

    #[test]
    fn rig_promotes_until_the_cap_then_refuses() {
        let admission = ClusterPolicy::rig().voter_admission;
        let VoterAdmission::PromotableUpTo { max_voters } = admission else {
            panic!("the rig preset must allow promotion");
        };
        assert_eq!(
            admission.judge(6, max_voters - 1, false),
            PromotionVerdict::Promote,
            "one below the cap must be promotable"
        );
        let at_cap = admission.judge(6, max_voters, false);
        assert!(
            matches!(at_cap, PromotionVerdict::Refuse(msg) if msg.contains(&max_voters.to_string())),
            "at the cap the refusal must name the cap"
        );
    }

    #[test]
    fn both_presets_produce_a_valid_openraft_config() {
        for (name, policy) in [
            ("fleet", ClusterPolicy::fleet()),
            ("rig", ClusterPolicy::rig()),
        ] {
            let cfg = policy
                .timing
                .to_openraft_config()
                .unwrap_or_else(|e| panic!("{name} timing must validate: {e}"));
            assert_eq!(cfg.heartbeat_interval, policy.timing.heartbeat_interval_ms);
            assert_eq!(
                cfg.election_timeout_max,
                policy.timing.election_timeout_max_ms
            );
        }
    }

    #[test]
    fn inconsistent_timing_is_rejected_rather_than_campaigning_forever() {
        // Heartbeat slower than the election timeout: every follower times out
        // before the leader can reach it, so the cluster elects continuously.
        let broken = RaftTiming {
            heartbeat_interval_ms: 5000,
            election_timeout_min_ms: 1500,
            election_timeout_max_ms: 3000,
        };
        assert!(
            broken.to_openraft_config().is_err(),
            "openraft must reject a heartbeat longer than the election timeout"
        );
    }

    #[test]
    fn liveness_thresholds_scale_with_the_networks_heartbeat() {
        let fleet = ClusterPolicy::fleet().liveness_thresholds();
        let rig = ClusterPolicy::rig().liveness_thresholds();
        assert_eq!(fleet.suspect_after, Duration::from_millis(1500));
        assert_eq!(fleet.down_after, Duration::from_secs(5));
        assert_eq!(rig.suspect_after, Duration::from_millis(450));
        assert_eq!(rig.down_after, Duration::from_millis(1500));
        assert!(
            rig.suspect_after < fleet.suspect_after && rig.down_after < fleet.down_after,
            "a LAN cluster must lose patience sooner than a WAN one at both thresholds"
        );
        assert!(
            rig.down_after <= fleet.suspect_after,
            "the LAN cluster should have written a node off entirely by the time the WAN \
             cluster has merely started to wonder"
        );
    }

    #[test]
    fn only_the_fleet_ties_external_identity_to_leadership() {
        assert!(ClusterPolicy::fleet()
            .ingress_ownership
            .follows_raft_leader());
        assert!(!ClusterPolicy::rig().ingress_ownership.follows_raft_leader());
    }
}
