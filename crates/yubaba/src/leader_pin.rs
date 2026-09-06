//! Stable leader pin — soft-prefer an anchor region for leadership (R734-T4,
//! W247 §3).
//!
//! Raft elects whichever voter's timer fires first. On a LAN that is fine; on a
//! WAN it means leadership lands in a region essentially at random and moves
//! again on every transient. That costs real latency — every client write pays a
//! round trip to wherever the leader happens to be — and it costs it invisibly,
//! because a cluster with its leader in the wrong region looks exactly like one
//! with its leader in the right region.
//!
//! This loop expresses a *preference*: when the sitting leader is outside the
//! anchor region and a healthy, caught-up voter is inside it, the leader hands
//! off using the native `Trigger::transfer_leader` that R608-B11 shipped.
//!
//! # Why leader-side transfer, and not election-timeout skew
//!
//! The other implementation of "prefer this region" is to give anchor-region
//! nodes the low end of the election band and everyone else the high end, so the
//! anchor wins a healthy race. It needs no replicated data — a node only needs
//! its own region — and it was rejected for two reasons.
//!
//! It is statistical. Its test can only assert that the anchor *usually* wins,
//! which is the flaky-test shape every other suite here has avoided. And
//! R118-T9 already records mismatched timings across nodes as a
//! *misconfiguration* (see `cluster-epochs.json`'s residual-risk note), so
//! deliberately skewing them would need a strong argument that the next operator
//! to read `/raft/status` will not mistake the design for the accident.
//!
//! Transfer is deterministic instead: a specific node hands leadership to a
//! specific node at a specific moment, so the test asserts leadership *settles*
//! on the anchor voter rather than asserting a distribution.
//!
//! # Soft by construction
//!
//! The loop only ever acts when an anchor-region voter is present, in the
//! current voter set, and caught up. Every other case is a no-op, which is what
//! makes this safe for the disaster half of W247 §3: if the anchor region is
//! dark, there is no candidate, so nothing moves and the surviving region keeps
//! the leadership it elected. The pin can never prevent a failover — it can only
//! tidy up after one.
//!
//! Note the asymmetry that makes that true: this is *not* a rule that leadership
//! must be in the anchor region. It is a rule that leadership moves *toward* it
//! when doing so is free. Nothing here ever refuses, blocks, or reverts an
//! election.
//!
//! # Churn is the failure mode to design against
//!
//! Two mechanisms disagreeing about who leads is strictly worse than an
//! off-anchor leader: they fight, and the cluster spends its time in elections
//! instead of serving writes. Three guards, all of them in [`run`]:
//!
//! - the candidate must be **caught up** ([`PinConfig::max_lag_entries`]), so a
//!   handoff is not attempted at a node that would immediately lose it back;
//! - a **cooldown** after any attempt ([`PinConfig::cooldown`]), so a transfer
//!   that lands in a contested state cannot be re-driven every tick;
//! - a **per-target backoff** after a failed attempt
//!   ([`PinConfig::failure_backoff`]), so a node that cannot take leadership is
//!   not asked again immediately.
//!
//! And one guard in [`decide`] itself: the pin acts only on **positive evidence
//! about both ends**. A leader whose own region is not in replicated state does
//! nothing, rather than assuming it is off-anchor. Every node is row-less for a
//! moment after boot while R734-F5's registration loop converges, so the
//! opposite rule would make a rolling upgrade hand leadership around for no
//! gain — churn caused by the anti-churn feature.
//!
//! # The anchor is deployment config, not [`ClusterPolicy`]
//!
//! `cluster_policy`'s module docs set the bar: a field earns its place there by
//! answering a question some decision point asks, and no field records which
//! preset produced it. The question this loop asks is "*which region* should
//! lead?", and its answer is a label — `"us-west"` — that varies per deployment.
//! [`ClusterPolicy::fleet`](crate::cluster_policy::ClusterPolicy::fleet) is a
//! `const fn` returning a `Copy` value shared by every fleet on earth; it cannot
//! supply one deployment's anchor, and adding an `Option<String>` to carry it
//! would cost the type both properties for a value the preset does not know.
//!
//! So the anchor travels the way `--region` does: an operator flag, per process.
//! What the *policy* does decide is whether an anchor is meaningful at all, and
//! [`validate`] reads
//! [`quorum_geography`](crate::cluster_policy::ClusterPolicy::quorum_geography)
//! for it — under `SingleFailureDomain` there are no regions to prefer between,
//! so an anchor is a typo rather than a preference, and it is refused rather
//! than accepted into a loop that could never act on it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use openraft::async_runtime::watch::WatchReceiver;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::cluster_policy::{ClusterPolicy, QuorumGeography, RaftTiming};
use crate::raft::{MemberInfo, YubabaNodeId, YubabaRaft, YubabaStateMachine};

/// How the pin loop is paced and how strict it is about a candidate's log.
///
/// Every duration is derived from [`RaftTiming`] by [`PinConfig::new`] rather
/// than being an independent constant, because all four answer the same
/// question — "how long is an election here?" — and a WAN cluster's answer is
/// twenty times a LAN cluster's. Tests construct the struct directly to run the
/// loop on a scale a test can wait out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinConfig {
    /// The region leadership is preferred to sit in — the same label space as
    /// [`MemberInfo::region`], i.e. what the machine declares as `region` in
    /// `.yah/infra/machines/<name>.toml`.
    pub anchor: String,
    /// How often the decision is re-evaluated.
    pub evaluate_every: Duration,
    /// Minimum gap between two handoff *attempts*, whatever their outcome.
    pub cooldown: Duration,
    /// How long a target that failed to take leadership is skipped for.
    pub failure_backoff: Duration,
    /// How many log entries a candidate may be behind the leader and still count
    /// as caught up.
    pub max_lag_entries: u64,
}

impl PinConfig {
    /// Derive the pacing from this cluster's raft timings.
    ///
    /// The multipliers encode "much slower than an election". Evaluating four
    /// election timeouts apart means the loop never races the election it is
    /// reacting to; a cooldown of twenty means a cluster cannot be handed
    /// around more than about once a minute on the WAN preset, which is far
    /// below the rate at which leader churn costs anything.
    pub fn new(anchor: impl Into<String>, timing: RaftTiming) -> Self {
        let election = Duration::from_millis(timing.election_timeout_max_ms);
        Self {
            anchor: anchor.into(),
            evaluate_every: election * 4,
            cooldown: election * 20,
            failure_backoff: election * 40,
            max_lag_entries: DEFAULT_MAX_LAG_ENTRIES,
        }
    }
}

/// How far behind the leader a candidate may be and still be handed leadership.
///
/// Not zero: the leader appends while we are deciding, so demanding an exact
/// match would make the pin fire only on a perfectly idle cluster. Small enough
/// that the target can replay the difference in well under an election timeout,
/// which is what "caught up" has to mean here — openraft's `transfer_leader`
/// sends the target a `TimeoutNow`, and a target that then has to catch up
/// before it can win wastes the handoff.
const DEFAULT_MAX_LAG_ENTRIES: u64 = 10;

/// Whether an anchor region means anything under `policy`.
///
/// The one genuinely policy-shaped question here (see the module docs). Called
/// by the daemon at startup so `--leader-anchor` on a rig fails loudly at boot
/// rather than starting a loop with nothing to do.
pub fn validate(policy: &ClusterPolicy, anchor: &str) -> Result<(), String> {
    if anchor.trim().is_empty() {
        return Err(
            "leader anchor region is empty; pass a region label such as \
                    \"us-west\", or omit the flag to leave leadership wherever raft \
                    elects it"
                .to_string(),
        );
    }
    match policy.quorum_geography {
        QuorumGeography::MustSpanRegions => Ok(()),
        QuorumGeography::SingleFailureDomain => Err(format!(
            "leader anchor {anchor:?} was set, but this cluster's policy is \
             SingleFailureDomain — every voter shares one failure domain, so there \
             are no regions to prefer between and no voter would ever carry a \
             region tag to match. Drop the anchor, or run this cluster under the \
             fleet profile if its voters really are in different regions."
        )),
    }
}

/// What the loop should do on this tick.
///
/// A pure verdict, split out of [`run`] for the same reason `plan_transfer` is
/// split out of the transfer-leader handler and `plan_registration` out of
/// member registration: the decision is the part worth testing, and testing it
/// should not need a live cluster.
#[derive(Debug, PartialEq, Eq)]
pub enum PinDecision {
    /// This node is not the leader. Only the sitting leader can hand off, so
    /// every follower's pin loop is inert — which is also why running this on
    /// every node is safe rather than redundant.
    NotLeader,
    /// The leader is already in the anchor region. The steady state.
    AlreadyAnchored,
    /// This node leads but replicated state does not say where it is — no member
    /// row, or a row that declares no region. Do nothing until it does.
    ///
    /// Absence of evidence is not evidence of being off-anchor, and this is the
    /// asymmetry that made an earlier version of this function wrong: it
    /// required positive evidence about the *target* but accepted silence about
    /// *itself*, so a leader that was in the anchor region and had merely not
    /// registered yet would hand leadership to another anchor voter for no gain.
    /// That is churn produced by the anti-churn feature, on exactly the shape a
    /// rolling upgrade produces (R734-F5's registration loop converges a moment
    /// after boot, so every node passes through row-less).
    LeaderRegionUnknown,
    /// Nothing to hand off to: no other voter is in the anchor region, or the
    /// ones that are are lagging or in failure backoff. Includes the case that
    /// matters most — the anchor region is dark — and the response to it is to
    /// leave leadership exactly where it is.
    NoAnchorCandidate,
    /// Hand leadership to this voter.
    HandOffTo(YubabaNodeId),
}

/// Decide whether to hand leadership off, given a snapshot of this node's view.
///
/// `eligible` is the set of voters that are both caught up and not in failure
/// backoff; the loop computes it because catch-up comes from openraft's
/// replication metrics, which only the leader has. Passing the finished set
/// keeps this function free of openraft types and therefore testable as
/// arithmetic.
///
/// **Both ends need positive evidence.** The pin acts only when replicated state
/// says where the leader is *and* says where the candidate is. A leader with no
/// member row, or a row declaring no region, yields
/// [`PinDecision::LeaderRegionUnknown`] and nothing happens — see that variant
/// for why the opposite rule is a churn bug rather than a mere conservatism
/// preference.
///
/// Ties break to the lowest node id, so every node in the cluster that runs this
/// computation reaches the same answer. Nothing depends on that today — only the
/// leader acts — but a rule that is stable under re-evaluation is what keeps a
/// second actuator from disagreeing with this one later.
pub fn decide(
    my_id: YubabaNodeId,
    current_leader: Option<YubabaNodeId>,
    voters: &BTreeSet<YubabaNodeId>,
    members: &BTreeMap<YubabaNodeId, MemberInfo>,
    eligible: &BTreeSet<YubabaNodeId>,
    anchor: &str,
) -> PinDecision {
    if current_leader != Some(my_id) {
        return PinDecision::NotLeader;
    }
    let region_of = |id: &YubabaNodeId| members.get(id).and_then(|m| m.region.as_deref());
    let in_anchor = |id: &YubabaNodeId| region_of(id).is_some_and(|region| region == anchor);
    match region_of(&my_id) {
        None => return PinDecision::LeaderRegionUnknown,
        Some(region) if region == anchor => return PinDecision::AlreadyAnchored,
        Some(_) => {}
    }
    // BTreeSet iterates in ascending node-id order, so `find` is the lowest
    // eligible id without an explicit sort.
    match voters
        .iter()
        .find(|id| **id != my_id && eligible.contains(id) && in_anchor(id))
    {
        Some(target) => PinDecision::HandOffTo(*target),
        None => PinDecision::NoAnchorCandidate,
    }
}

/// Which voters are close enough to the leader's log to be handed leadership.
///
/// `replication` is `(node id, matched log index)` per peer, flattened from
/// openraft's replication metrics at the call site so this stays free of
/// openraft's type-config aliases and testable with plain integers. Those
/// metrics are `Some` only on a leader, so a follower passes an empty iterator,
/// finds nobody eligible, and [`decide`] finds no candidate — the right answer
/// for a node with no business handing anything off.
///
/// A peer the leader has not replicated to at all has `matched: None`, read as
/// index 0. On a fresh cluster that is genuinely caught up (the log is empty
/// too); on a cluster with history it is maximally behind. Both fall out of the
/// same subtraction.
fn caught_up(
    replication: impl IntoIterator<Item = (YubabaNodeId, Option<u64>)>,
    last_log_index: Option<u64>,
    max_lag_entries: u64,
) -> BTreeSet<YubabaNodeId> {
    let last = last_log_index.unwrap_or(0);
    replication
        .into_iter()
        .filter(|(_, matched)| last.saturating_sub(matched.unwrap_or(0)) <= max_lag_entries)
        .map(|(id, _)| id)
        .collect()
}

/// Spawn the leader-pin loop.
///
/// Safe to run on every node: a follower's loop reaches [`PinDecision::NotLeader`]
/// and does nothing, so there is no "start this only on the leader" edge to get
/// wrong across an election.
///
/// The returned handle can be aborted on shutdown; the loop also exits on its
/// own when the raft metrics channel closes.
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    config: PinConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state_machine, config).await;
    })
}

async fn run(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    config: PinConfig,
) {
    info!(
        node_id,
        anchor = %config.anchor,
        evaluate_every = ?config.evaluate_every,
        "leader pin active — leadership will be preferred in the anchor region"
    );
    let watch = raft.metrics();
    // Attempt gating. `next_attempt_at` is the global cooldown (any target);
    // `backoff` is per-target, for the ones that have already failed to take it.
    let mut next_attempt_at: Option<Instant> = None;
    let mut backoff: HashMap<YubabaNodeId, Instant> = HashMap::new();

    loop {
        // Deliberately a plain interval rather than a wake on the metrics watch,
        // which is what member registration uses. A leader's metrics change on
        // every heartbeat, and this loop has no reason to be prompt: it is an
        // anti-churn mechanism, so evaluating it at election speed would be
        // working against its own purpose.
        tokio::time::sleep(config.evaluate_every).await;

        let now = Instant::now();
        backoff.retain(|_, until| *until > now);

        let (current_leader, voters, eligible) = {
            let metrics = watch.borrow_watched();
            if metrics.running_state.is_err() {
                warn!(node_id, "raft node has stopped — leader pin exiting");
                return;
            }
            let voters: BTreeSet<YubabaNodeId> =
                metrics.membership_config.membership().voter_ids().collect();
            let replication = metrics
                .replication
                .iter()
                .flatten()
                .map(|(id, matched)| (*id, matched.as_ref().map(|log_id| log_id.index)))
                .collect::<Vec<_>>();
            let eligible = caught_up(replication, metrics.last_log_index, config.max_lag_entries)
                .into_iter()
                .filter(|id| !backoff.contains_key(id))
                .collect();
            (metrics.current_leader, voters, eligible)
        };

        let members = state_machine.members();
        let decision = decide(
            node_id,
            current_leader,
            &voters,
            &members,
            &eligible,
            &config.anchor,
        );

        let PinDecision::HandOffTo(target) = decision else {
            debug!(node_id, ?decision, "leader pin: nothing to do");
            continue;
        };
        if next_attempt_at.is_some_and(|at| now < at) {
            debug!(
                node_id,
                target, "leader pin: handoff wanted but still in cooldown"
            );
            continue;
        }

        // Set the cooldown *before* awaiting the transfer, so a slow or hanging
        // handoff cannot be joined by a second one on the next tick.
        next_attempt_at = Some(now + config.cooldown);
        info!(
            node_id,
            target,
            anchor = %config.anchor,
            "leader pin: handing leadership to a voter in the anchor region"
        );
        // No confirmation poll, unlike `POST /raft/transfer-leader`. That route
        // answers an operator who needs to know whether to proceed with a drain;
        // this loop has nobody waiting on it, and the next tick observes the
        // outcome for free by reading `current_leader` again.
        if let Err(e) = raft.trigger().transfer_leader(target).await {
            warn!(
                node_id,
                target,
                "leader pin: transfer to the anchor failed, not retrying it for {:?}: {e}",
                config.failure_backoff
            );
            backoff.insert(target, now + config.failure_backoff);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_policy::ClusterPolicy;

    fn members(rows: &[(YubabaNodeId, Option<&str>)]) -> BTreeMap<YubabaNodeId, MemberInfo> {
        rows.iter()
            .map(|(id, region)| {
                (
                    *id,
                    MemberInfo {
                        addr: format!("100.64.0.{id}:7443"),
                        region: region.map(str::to_string),
                        // The pin judges regions only; capacity is R737-F1's
                        // axis and machine is R859-F2's, and neither is part of
                        // this decision.
                        capacity: None,
                        machine: None,
                    },
                )
            })
            .collect()
    }

    fn ids(ids: &[YubabaNodeId]) -> BTreeSet<YubabaNodeId> {
        ids.iter().copied().collect()
    }

    /// The whole loop is inert on a follower. This is what makes it safe to
    /// start on every node rather than having to start and stop it across
    /// elections.
    #[test]
    fn a_follower_never_decides_to_hand_anything_off() {
        let m = members(&[(1, Some("us-east")), (2, Some("us-west"))]);
        assert_eq!(
            decide(
                1,
                Some(2),
                &ids(&[1, 2, 3]),
                &m,
                &ids(&[1, 2, 3]),
                "us-west"
            ),
            PinDecision::NotLeader
        );
    }

    /// The steady state: once leadership is in the anchor the loop stops acting,
    /// which is what stops it from fighting itself.
    #[test]
    fn a_leader_already_in_the_anchor_region_stays_put() {
        let m = members(&[(1, Some("us-west")), (2, Some("us-west"))]);
        assert_eq!(
            decide(
                1,
                Some(1),
                &ids(&[1, 2, 3]),
                &m,
                &ids(&[1, 2, 3]),
                "us-west"
            ),
            PinDecision::AlreadyAnchored
        );
    }

    #[test]
    fn an_off_anchor_leader_hands_off_to_the_anchor_voter() {
        let m = members(&[
            (1, Some("us-east")),
            (2, Some("us-west")),
            (3, Some("us-south")),
        ]);
        assert_eq!(
            decide(
                1,
                Some(1),
                &ids(&[1, 2, 3]),
                &m,
                &ids(&[1, 2, 3]),
                "us-west"
            ),
            PinDecision::HandOffTo(2)
        );
    }

    /// THE disaster-survivability property, stated as a test rather than as a
    /// comment: with the anchor region gone, an off-anchor leader keeps
    /// leadership. A pin that could strand a cluster leaderless when its
    /// preferred region died would be worse than no pin.
    #[test]
    fn a_dark_anchor_region_leaves_the_surviving_leader_alone() {
        let m = members(&[(1, Some("us-east")), (3, Some("us-south"))]);
        assert_eq!(
            decide(1, Some(1), &ids(&[1, 3]), &m, &ids(&[1, 3]), "us-west"),
            PinDecision::NoAnchorCandidate
        );
    }

    /// A lagging anchor voter is not a candidate. `transfer_leader` sends the
    /// target a TimeoutNow, so handing off to a node that must first catch up
    /// spends an election to end up back where it started.
    #[test]
    fn a_lagging_anchor_voter_is_not_handed_leadership() {
        let m = members(&[(1, Some("us-east")), (2, Some("us-west"))]);
        assert_eq!(
            decide(1, Some(1), &ids(&[1, 2]), &m, &ids(&[1]), "us-west"),
            PinDecision::NoAnchorCandidate
        );
    }

    /// A learner in the anchor region is not a candidate either: leadership can
    /// only go to a voter, and under `VoterAdmission::LearnerOnly` a fleet's
    /// learners are exactly the nodes deliberately kept out of quorum.
    #[test]
    fn an_anchor_region_learner_is_not_a_candidate() {
        let m = members(&[(1, Some("us-east")), (9, Some("us-west"))]);
        assert_eq!(
            decide(1, Some(1), &ids(&[1, 2, 3]), &m, &ids(&[1, 9]), "us-west"),
            PinDecision::NoAnchorCandidate
        );
    }

    /// A leader that has not registered its own row yet does NOTHING, even with
    /// a known anchor voter sitting right there.
    ///
    /// This is the rolling-upgrade shape — every node is row-less for a moment
    /// after boot while R734-F5's registration loop converges — and the earlier
    /// version of `decide` got it wrong in the expensive direction: it handed
    /// leadership away on the strength of the target's row alone, so a leader
    /// already in the anchor region would move leadership to a peer in the *same*
    /// region for no gain. Caught by @Ashguard:libra during R734-F5.
    #[test]
    fn a_leader_with_no_member_row_waits_rather_than_handing_off() {
        let m = members(&[(2, Some("us-west"))]);
        assert_eq!(
            decide(
                1,
                Some(1),
                &ids(&[1, 2, 3]),
                &m,
                &ids(&[1, 2, 3]),
                "us-west"
            ),
            PinDecision::LeaderRegionUnknown
        );
    }

    /// A registered row that declares no region is the same answer. It is
    /// settled information rather than a pending write, but it is still not
    /// evidence about where this node is — so the conservative rule applies to
    /// both, and there is one rule to remember instead of two.
    #[test]
    fn a_leader_whose_row_declares_no_region_also_waits() {
        let m = members(&[(1, None), (2, Some("us-west"))]);
        assert_eq!(
            decide(
                1,
                Some(1),
                &ids(&[1, 2, 3]),
                &m,
                &ids(&[1, 2, 3]),
                "us-west"
            ),
            PinDecision::LeaderRegionUnknown
        );
    }

    /// The candidate-side mirror: a voter that is physically in the anchor
    /// region but has published no row is not a target. Its silence is not
    /// evidence either way, and the leader stays put rather than reaching for
    /// the next-best node.
    ///
    /// Already correct before [`PinDecision::LeaderRegionUnknown`] existed — a
    /// row-less peer has always failed `in_anchor` — but worth pinning, because
    /// the obvious "optimisation" of falling back to the founding payload's
    /// region tags would break it, and those tags sit in membership to tempt
    /// someone.
    #[test]
    fn an_unregistered_anchor_voter_is_not_a_handoff_target() {
        let m = members(&[(1, Some("us-east")), (3, Some("us-south"))]);
        assert_eq!(
            decide(
                1,
                Some(1),
                &ids(&[1, 2, 3]),
                &m,
                &ids(&[1, 2, 3]),
                "us-west"
            ),
            PinDecision::NoAnchorCandidate
        );
    }

    /// With nobody tagged at all — a fleet whose member rows have not converged
    /// yet — the loop does nothing rather than picking arbitrarily.
    #[test]
    fn an_entirely_untagged_cluster_is_left_alone() {
        assert_eq!(
            decide(
                1,
                Some(1),
                &ids(&[1, 2, 3]),
                &BTreeMap::new(),
                &ids(&[1, 2, 3]),
                "us-west"
            ),
            PinDecision::LeaderRegionUnknown
        );
    }

    /// The complement of the row-less case, and the reason it is a *wait* rather
    /// than a permanent refusal: once the leader's row lands and says it is
    /// off-anchor, the same inputs produce the handoff.
    #[test]
    fn the_same_cluster_hands_off_once_the_leader_row_lands() {
        let m = members(&[(1, Some("us-east")), (2, Some("us-west"))]);
        assert_eq!(
            decide(
                1,
                Some(1),
                &ids(&[1, 2, 3]),
                &m,
                &ids(&[1, 2, 3]),
                "us-west"
            ),
            PinDecision::HandOffTo(2)
        );
    }

    /// Determinism, so two evaluations of the same state cannot disagree about
    /// the target and hand the cluster back and forth.
    #[test]
    fn ties_break_to_the_lowest_node_id() {
        let m = members(&[
            (1, Some("us-east")),
            (2, Some("us-west")),
            (3, Some("us-west")),
        ]);
        assert_eq!(
            decide(
                1,
                Some(1),
                &ids(&[1, 2, 3]),
                &m,
                &ids(&[1, 2, 3]),
                "us-west"
            ),
            PinDecision::HandOffTo(2)
        );
    }

    #[test]
    fn a_caught_up_peer_is_eligible_and_a_lagging_one_is_not() {
        let rep = [(2u64, Some(98u64)), (3, Some(50)), (4, None)];
        // Node 2 is 2 entries behind (inside the allowance); 3 is 50 behind and
        // 4 has never been replicated to.
        assert_eq!(caught_up(rep, Some(100), 10), ids(&[2]));
        // A wider allowance admits the laggard too.
        assert_eq!(caught_up(rep, Some(100), 60), ids(&[2, 3]));
        // On an empty log everyone is trivially caught up, `matched: None`
        // included — there is nothing to be behind on.
        assert_eq!(caught_up(rep, None, 10), ids(&[2, 3, 4]));
        // A follower has no replication metrics at all, so it finds nobody.
        assert_eq!(caught_up([], Some(100), 10), BTreeSet::new());
    }

    /// An anchor is meaningless where there is only one failure domain, and a
    /// flag that silently does nothing is worse than one that is refused.
    #[test]
    fn an_anchor_is_refused_under_a_single_failure_domain_policy() {
        assert!(validate(&ClusterPolicy::fleet(), "us-west").is_ok());
        let err = validate(&ClusterPolicy::rig(), "us-west").unwrap_err();
        assert!(err.contains("SingleFailureDomain"), "{err}");
    }

    #[test]
    fn an_empty_anchor_is_refused() {
        assert!(validate(&ClusterPolicy::fleet(), "   ").is_err());
    }

    /// The pacing must stay far slower than an election under both presets, or
    /// the pin races the very churn it exists to damp.
    #[test]
    fn the_pin_is_paced_well_below_election_speed_under_both_presets() {
        for policy in [ClusterPolicy::fleet(), ClusterPolicy::rig()] {
            let cfg = PinConfig::new("us-west", policy.timing);
            let election = Duration::from_millis(policy.timing.election_timeout_max_ms);
            assert!(cfg.evaluate_every >= election * 2, "{cfg:?}");
            assert!(cfg.cooldown > cfg.evaluate_every, "{cfg:?}");
            assert!(cfg.failure_backoff > cfg.cooldown, "{cfg:?}");
        }
    }
}
