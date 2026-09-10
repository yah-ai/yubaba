//! The membership ratchet — shrink the voter set **while quorum still holds**,
//! and rest at a single voter rather than wedging (`R118-F8`, `W138`, `W158`).
//!
//! # The thesis, in one paragraph
//!
//! Raft's quorum rule is a *partition* defence, not a node-failure defence: a
//! minority may not commit because it cannot tell whether the missing majority
//! is dead or on the far side of a split. A gallery rig can tell, because its
//! nodes share a second, physically independent channel — BLE — and `R118-F7`'s
//! detector turns that into a corroborated verdict. So the rig is allowed to do
//! the thing a datacenter cluster may not: take the vote away from a node it can
//! *prove* is off, and keep committing with what is left.
//!
//! The window to do that is short and it is the whole design. Five voters, a
//! power strip takes two: there are still three of five, so a membership change
//! still commits. Wait, lose a third, and there is no quorum left to commit the
//! change that would have rescued the cluster — that wedge is what `W158`
//! exists to argue about, and every ratchet step that fires is a wedge that
//! never happens. Hence `W158` §7.2(1): **time from first loss to single-node is
//! this module's headline metric**, not an implementation detail.
//!
//! # The safety rule is inverted, and it is the only rule that matters
//!
//! **Absence of evidence is the permission; presence of it is a veto.** A peer
//! that BLE can still hear is a *partition*, and reconfiguring during a
//! partition is the split brain the whole design exists to prevent. So only
//! [`PeerLivenessVerdict::Dark`] licenses a shrink, and `Alive`,
//! `UnreachableButRadiating`, `SilentWithinHoldDown` and `Unknown` all veto —
//! including `Unknown`, which is the observer's own blindness and is therefore
//! the one a naive gate is most likely to wave through. [`plan`] fails closed on
//! every one of them.
//!
//! # Where each half lives, and why it is split
//!
//! The **detector** is not in this process. It is noisetable's
//! `society_facility::liveness`, which corroborates an IP path against BLE and
//! deliberately links no yubaba crate (`cargo test -p society_facility
//! --features control-plane --test lan_path_is_yubaba_free` enforces that), so
//! it cannot implement the in-process
//! [`FailureDetector`](crate::failure_detector::FailureDetector) trait. It
//! reports over loopback to the yubaba beside it, that report is replicated as
//! [`YubabaRequest::ReportPeerLiveness`], and this module reads it back out of
//! locally-applied state. The seam is exactly the one `R118-T5` opened for
//! `POST /v1/nodes/{node}/boot-health`, for the same reason: the verdict that
//! matters most is filed by a node the leader may be about to lose.
//!
//! The **decision** is here, because `change_membership` is leader-only and
//! internal to raft.
//!
//! # `retain = true`, always
//!
//! Verified in openraft 0.10 `raft/impl_raft_blocking_write.rs`: with `retain`
//! set, removed voters are **demoted to learners**, not evicted. They keep
//! replicating, so they stay caught up and a returning plinth is a promotion
//! rather than a full rejoin. There is no case in this module for `false` — the
//! symmetric operator verb `POST /raft/remove-member` uses `false` because
//! *decommissioning* is what it means, and that is a different act.
//!
//! ```bash
//! cargo test -p yubaba --lib membership_ratchet
//! cargo test -p yubaba --test main -- raft_membership_ratchet:: --test-threads=2
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use tracing::{info, warn};

use crate::cluster_policy::{ClusterPolicy, PromotionVerdict};
#[allow(unused_imports)] // referenced from doc comments only.
use crate::cluster_policy::MembershipRatchet;
use crate::raft::{
    MembershipRatchetRecord, PeerLivenessVerdict, YubabaNodeId, YubabaRaft, YubabaRequest,
    YubabaState, YubabaStateMachine,
};

/// The singleton role whose current owner wins the tie-break (`R118-F4`).
///
/// It lives in yubaba's own lock store, so the leader can read it out of applied
/// state without asking anyone — which is what makes "decided by the cluster
/// while it still can" implementable at all.
pub const GATEWAY_ROLE: &str = "rig/egress-gateway";

/// The one sentence a [`MembershipRatchet::Frozen`] cluster ever answers with,
/// stated once so the shrink and rehydrate halves cannot drift into two
/// different explanations of the same policy.
const FROZEN_REASON: &str =
    "cluster policy freezes the voter set: membership changes only on an operator's \
     POST /raft/remove-member or /raft/promote-voter, whatever a liveness detector believes";

/// Everything [`plan`] knows about one voter.
///
/// Built from applied state by [`evidence_from_state`]; a separate type so the
/// decision is a pure function of stated facts and can be tested without a
/// cluster, a clock, or a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterEvidence {
    /// What every fresh observer, folded, says about this voter.
    pub verdict: PeerLivenessVerdict,
    /// How many distinct fresh observers currently report this voter `Alive`.
    ///
    /// The tie-break's link-quality proxy, and deliberately a count of
    /// *witnesses* rather than a latency number: the ratchet has no latency
    /// measurement and inventing one would be a guess, whereas "three peers can
    /// still see it and only one can see the other" is a fact already in the
    /// replicated map. Ranks below gateway ownership and above node id.
    pub alive_witnesses: usize,
    /// Whether this voter currently holds [`GATEWAY_ROLE`].
    pub holds_gateway: bool,
}

/// What the ratchet decided this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetPlan {
    /// Do nothing, for the stated reason. Every refusal carries its reason
    /// because the interesting failure of a ratchet is the one that *should*
    /// have fired, and "it held" with no sentence attached is unbisectable.
    Hold { reason: String },
    /// Demote `demote` to learners, leaving `after` as the voter set.
    Shrink {
        demote: BTreeSet<YubabaNodeId>,
        after: BTreeSet<YubabaNodeId>,
        reason: String,
    },
}

impl RatchetPlan {
    fn hold(reason: impl Into<String>) -> Self {
        Self::Hold {
            reason: reason.into(),
        }
    }
}

/// Fold applied state into per-voter evidence at `now` (unix seconds).
///
/// `ttl` is the policy's evidence window — see
/// [`MembershipRatchet::evidence_ttl`]. Every voter appears in the result, so
/// the returned map's key set *is* the voter set [`plan`] judges.
pub fn evidence_from_state(
    state: &YubabaState,
    voters: &BTreeSet<YubabaNodeId>,
    now: u64,
    ttl: u64,
) -> BTreeMap<YubabaNodeId, VoterEvidence> {
    // The lock's `owner` is a caller-chosen string; `node_for_machine` resolves
    // it when it is a machine name, which is what the ingress/appliance paths
    // write. An owner that resolves to no node simply leaves `holds_gateway`
    // false everywhere and the tie-break falls through to link quality — a
    // degradation, never a wrong answer.
    let gateway_owner = state
        .locks
        .get(GATEWAY_ROLE)
        .and_then(|entry| state.node_for_machine(&entry.owner));

    voters
        .iter()
        .map(|voter| {
            let alive_witnesses = state
                .peer_liveness
                .iter()
                .filter(|(observer, _)| *observer != voter)
                .filter_map(|(_, reports)| reports.get(voter))
                .filter(|record| now.saturating_sub(record.observed_at) <= ttl)
                .filter(|record| record.verdict == PeerLivenessVerdict::Alive)
                .count();
            (
                *voter,
                VoterEvidence {
                    verdict: state.corroborated_liveness(*voter, now, ttl),
                    alive_witnesses,
                    holds_gateway: gateway_owner == Some(*voter),
                },
            )
        })
        .collect()
}

/// Decide whether to shrink, and to what. Pure.
///
/// # The order of the gates is the argument
///
/// 1. **Policy.** [`MembershipRatchet::Frozen`] holds unconditionally, so a
///    fleet cluster is byte-for-byte unaffected by everything below.
/// 2. **Veto scan, before anything else is computed.** If *any* voter's folded
///    verdict is not `Alive` or `Dark`, the whole tick holds. Not "skip that
///    node": a `SilentWithinHoldDown` peer may be five seconds from `Dark` and
///    an `UnreachableButRadiating` one means the cluster is *currently
///    partitioned*, which is the state in which no membership change is safe to
///    make about anybody. Holding is free — the next tick is a second away —
///    and the whole cost of being wrong here is a split brain.
/// 3. **Something to do.** No dark voter, nothing to shrink.
/// 4. **The quorum window.** The change has to commit under the *current*
///    configuration, so a majority of the current voter set must be alive. Past
///    that point the ratchet has already lost and `W158`'s operator-gated
///    recovery is the only path; saying so is more useful than proposing a write
///    that cannot commit.
/// 5. **Descend to an odd count, never below the floor.** `QuorumGeography::
///    judge_voter_count` already states the rule this reuses: an even voter set
///    survives exactly the failures the odd set below it does while making every
///    write wait on one more node. Four alive voters therefore rest at three,
///    and — the case the ticket names — two rest at **one**, which is why the
///    tie-break has to be decided here, while both survivors are alive and the
///    cluster can still commit the decision. After the next loss there is no
///    quorum left to decide anything with.
pub fn plan(
    policy: &ClusterPolicy,
    evidence: &BTreeMap<YubabaNodeId, VoterEvidence>,
) -> RatchetPlan {
    let Some(floor) = policy.membership_ratchet.floor().map(|f| f.get()) else {
        return RatchetPlan::hold(FROZEN_REASON);
    };
    if evidence.is_empty() {
        return RatchetPlan::hold("no voters in membership");
    }

    if let Some((id, held)) = evidence
        .iter()
        .find(|(_, e)| !matches!(e.verdict, PeerLivenessVerdict::Alive | PeerLivenessVerdict::Dark))
    {
        return RatchetPlan::hold(format!(
            "voter {id} is `{}` — only `dark` licenses a shrink, and any other evidence vetoes \
             the whole tick: a peer that can still be heard is a partition, and a peer nobody \
             can answer for is the observer's blindness, not the peer's absence",
            held.verdict.as_str()
        ));
    }

    let dark: BTreeSet<YubabaNodeId> = evidence
        .iter()
        .filter(|(_, e)| e.verdict.licenses_shrink())
        .map(|(id, _)| *id)
        .collect();
    let alive: BTreeSet<YubabaNodeId> = evidence
        .keys()
        .copied()
        .filter(|id| !dark.contains(id))
        .collect();

    if dark.is_empty() {
        return RatchetPlan::hold(format!(
            "all {} voters are alive; nothing to ratchet",
            evidence.len()
        ));
    }
    if alive.len() < floor {
        return RatchetPlan::hold(format!(
            "only {} of {} voters are alive, below this policy's floor of {floor}",
            alive.len(),
            evidence.len()
        ));
    }

    // The window. A membership change is an ordinary raft write and needs a
    // majority of the CURRENT voter set; openraft's joint consensus then needs a
    // majority of the new one too, which `alive` satisfies by construction.
    let quorum = evidence.len() / 2 + 1;
    if alive.len() < quorum {
        return RatchetPlan::hold(format!(
            "quorum is already lost — {} of {} voters alive, {quorum} needed to commit a \
             membership change. The ratchet shrinks while it still can and this is past that \
             window; recovery from here is W158's operator-gated path",
            alive.len(),
            evidence.len()
        ));
    }

    let mut after = alive.clone();
    while after.len() > floor && after.len().is_multiple_of(2) {
        let loser = *after
            .iter()
            .min_by_key(|id| survivor_rank(**id, evidence))
            .expect("after is non-empty: its length is above the floor, which is at least 1");
        after.remove(&loser);
    }

    let demote: BTreeSet<YubabaNodeId> = evidence
        .keys()
        .copied()
        .filter(|id| !after.contains(id))
        .collect();
    let conceded: Vec<YubabaNodeId> = demote.difference(&dark).copied().collect();
    let reason = if conceded.is_empty() {
        format!(
            "{} of {} voters corroborated dark ({}); demoting them leaves {} voters",
            dark.len(),
            evidence.len(),
            render(&dark),
            after.len()
        )
    } else {
        format!(
            "{} of {} voters corroborated dark ({}); demoting them alone would leave {} voters, \
             an even set that survives no more failures than {} while needing one more ack per \
             write, so live voter(s) {} give up the vote too while the cluster can still commit \
             the decision",
            dark.len(),
            evidence.len(),
            render(&dark),
            alive.len(),
            after.len(),
            render(&conceded.iter().copied().collect())
        )
    };

    RatchetPlan::Shrink {
        demote,
        after,
        reason,
    }
}

/// The tie-break, as a sort key where **smaller loses the vote** (it is used
/// with `min_by_key`).
///
/// Three clauses, in the order `R118-F8` specifies:
///
/// 1. **Gateway ownership.** The node holding [`GATEWAY_ROLE`] is the one the
///    room is already reaching the outside world through; making it the lone
///    voter keeps the cluster's writable half and its egress path on the same
///    box, so a subsequent loss takes one thing rather than two.
/// 2. **Link quality**, as the number of peers that can currently see it.
/// 3. **Lowest node id**, purely so the answer is deterministic. It is the final
///    fallback and never the reason — a tie-break that led with it would be the
///    coin-flip `W138` was trying to replace.
fn survivor_rank(
    id: YubabaNodeId,
    evidence: &BTreeMap<YubabaNodeId, VoterEvidence>,
) -> (bool, usize, std::cmp::Reverse<YubabaNodeId>) {
    let e = &evidence[&id];
    (
        e.holds_gateway,
        e.alive_witnesses,
        std::cmp::Reverse(id),
    )
}

// ── Rehydration ──────────────────────────────────────────────────────────────
//
// The mirror of the shrink, and the half where getting it wrong is worse than
// not building it: a ratchet that re-promotes a flapping plinth moves quorum on
// every cycle, so the mechanism built to keep the cluster writable becomes the
// thing that stops it committing. **The hold-down is the feature.**

/// Everything [`plan_rehydrate`] knows about one learner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnerEvidence {
    /// The folded verdict, exactly as [`VoterEvidence::verdict`].
    pub verdict: PeerLivenessVerdict,
    /// Unix seconds since which every fresh observer has said `Alive`, from
    /// [`YubabaState::corroborated_alive_since`]. `None` is a refusal: either
    /// the node is not corroborated alive, or nobody can say since when.
    pub alive_since: Option<u64>,
    /// Whether this learner's log has caught up with the leader's, from
    /// openraft's own replication metrics.
    ///
    /// A separate gate from the hold-down and not a substitute for it: catching
    /// up takes seconds on a kilobyte-scale state machine, so a flapping plinth
    /// is *caught up* within moments of every return. Catch-up says the node can
    /// serve; the hold-down says it can be trusted.
    ///
    /// # It is LOG REPLAY here, not a snapshot — checked, because the ticket
    /// assumed otherwise
    ///
    /// `R118-F8`'s brief and `W138` both said rehydration is cheap *"because the
    /// replicated state is kilobytes: snapshot, not log replay"*. Read out of
    /// openraft 0.10 (`progress/entry/mod.rs`, `ProgressEntry::next_send`), the
    /// mechanism is the other one: a snapshot is chosen under exactly two
    /// conditions, and both of them are *"the entries this follower needs have
    /// already been purged"* — otherwise the leader streams log entries from the
    /// follower's matched index. A plinth demoted minutes ago is nowhere near
    /// the purge boundary, so it catches up by ordinary replication.
    ///
    /// The conclusion survives — it *is* cheap — but it is cheap because the
    /// **log** is short, not because a snapshot is sent, and the distinction is
    /// the one that matters to anyone tuning `max_in_snapshot_log_to_keep`: make
    /// the retained log short enough and a returning learner starts taking
    /// snapshots instead, which is a different cost curve.
    pub caught_up: bool,
}

/// What the rehydrate half decided this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RehydratePlan {
    /// Do nothing, for the stated reason.
    Hold { reason: String },
    /// Promote these learners to voters, in **one** membership change.
    Promote {
        promote: BTreeSet<YubabaNodeId>,
        after: BTreeSet<YubabaNodeId>,
        reason: String,
    },
}

impl RehydratePlan {
    fn hold(reason: impl Into<String>) -> Self {
        Self::Hold {
            reason: reason.into(),
        }
    }
}

/// Decide whether to give a learner its vote back, and to whom. Pure, and
/// `now` is injected — there is no clock read anywhere below.
///
/// # The gates, in order, and why each one is where it is
///
/// 1. **Policy.** `Frozen` holds unconditionally, so `ClusterPolicy::fleet()` is
///    unaffected by every line after this one.
/// 2. **The sitting voter set must be entirely `Alive` first.** Promotion
///    *raises* quorum, so doing it while an existing voter is dark or
///    unreachable makes the cluster strictly less writable at the moment it is
///    least able to afford it — and the shrink half is about to act on that
///    voter anyway. Shed before you admit; [`run_once`] runs the halves in that
///    order for the same reason.
/// 3. **Hold-down, per candidate.** A learner qualifies only if every fresh
///    observer has called it `Alive` **continuously** for
///    [`MembershipRatchet::promote_hold_down`]. The clock is
///    [`LearnerEvidence::alive_since`], which the state machine's apply arm
///    re-stamps on every verdict CHANGE — so a plinth that flaps resets it every
///    cycle and can never accumulate a full hold-down, however fast it reports.
/// 4. **Caught up.** Openraft's replication metrics, not a guess.
/// 5. **[`VoterAdmission::judge`], per candidate.** The same rule
///    `POST /raft/promote-voter` applies, called rather than re-derived, so
///    `max_voters` and the fleet's learner-only rule cannot diverge between the
///    operator verb and the automatic one.
/// 6. **Land on an ODD voter count, or do not move.** This is the clause that
///    makes rehydration safe to pair with the shrink, and it is not the same
///    rule R118-T9 stated for the operator verb — that one correctly permits an
///    even *intermediate*, because an operator growing 3 → 5 by hand is present
///    and watching. An automatic promoter is not: taking a 1-voter cluster to 2
///    and then finding no second candidate ready leaves it resting at the one
///    count `R118-F8` exists to forbid, where a single further loss is an
///    unrecoverable wedge and the shrink half cannot even fix it (2 voters need
///    both to commit). So promotion goes 1 → 3 or 3 → 5 in **one**
///    `ChangeMembers::AddVoterIds`, and holds when it cannot.
pub fn plan_rehydrate(
    policy: &ClusterPolicy,
    voters: &BTreeMap<YubabaNodeId, VoterEvidence>,
    learners: &BTreeMap<YubabaNodeId, LearnerEvidence>,
    now: u64,
) -> RehydratePlan {
    let Some(hold_down) = policy.membership_ratchet.promote_hold_down() else {
        return RehydratePlan::hold(FROZEN_REASON);
    };
    let hold_down = hold_down.as_secs();

    if let Some((id, e)) = voters
        .iter()
        .find(|(_, e)| e.verdict != PeerLivenessVerdict::Alive)
    {
        return RehydratePlan::hold(format!(
            "voter {id} is `{}` — promotion raises quorum, so the voter set must be whole before \
             it grows; the shrink half acts on that voter first",
            e.verdict.as_str()
        ));
    }
    if learners.is_empty() {
        return RehydratePlan::hold("no learners to promote");
    }

    let mut ready: Vec<YubabaNodeId> = Vec::new();
    let mut refusals: Vec<String> = Vec::new();
    for (id, e) in learners {
        let Some(alive_since) = e.alive_since else {
            refusals.push(format!("{id}=not-corroborated-alive({})", e.verdict.as_str()));
            continue;
        };
        let steady = now.saturating_sub(alive_since);
        if steady < hold_down {
            refusals.push(format!("{id}=alive-only-{steady}s-of-{hold_down}s"));
            continue;
        }
        if !e.caught_up {
            refusals.push(format!("{id}=not-caught-up"));
            continue;
        }
        ready.push(*id);
    }
    if ready.is_empty() {
        return RehydratePlan::hold(format!(
            "no learner has cleared the {hold_down}s stability hold-down: {}",
            refusals.join(" ")
        ));
    }

    // Gate 5, before gate 6, so a refusal names the policy rather than the
    // arithmetic: at the cap there is no odd count to reach in the first place.
    let mut admissible: Vec<YubabaNodeId> = Vec::new();
    for id in &ready {
        match policy
            .voter_admission
            .judge(*id, voters.len() + admissible.len(), false)
        {
            PromotionVerdict::Promote => admissible.push(*id),
            PromotionVerdict::AlreadyVoter => {}
            PromotionVerdict::Refuse(reason) => {
                refusals.push(format!("{id}={reason}"));
            }
        }
    }
    if admissible.is_empty() {
        return RehydratePlan::hold(format!(
            "every stable learner was refused by cluster policy: {}",
            refusals.join(" ")
        ));
    }

    // Gate 6. `voters.len()` is odd whenever the shrink half has been the only
    // thing moving membership, so `need` is 2 — but it is computed rather than
    // assumed, because an operator's `POST /raft/promote-voter` can legitimately
    // leave an even set behind and rehydration should then restore oddness with
    // ONE promotion rather than refusing forever.
    let need = if voters.len().is_multiple_of(2) { 1 } else { 2 };
    if admissible.len() < need {
        // The refusals are carried into THIS message too, not only into the
        // two above it. "I needed two and had one" is half an answer; the other
        // half is why the others did not qualify, and an operator watching a
        // cluster sit at one voter needs both halves in one line.
        let because = if refusals.is_empty() {
            String::from("no other learner is in membership")
        } else {
            refusals.join(" ")
        };
        return RehydratePlan::hold(format!(
            "{} learner(s) are stable and admissible but {need} are needed to land on an odd \
             voter count from {}; promoting fewer would rest the cluster on {} voters, which \
             tolerates zero further losses and which the shrink half cannot repair (a {}-voter \
             set needs both nodes to commit anything). The others: {because}",
            admissible.len(),
            voters.len(),
            voters.len() + admissible.len(),
            voters.len() + admissible.len(),
        ));
    }

    let promote: BTreeSet<YubabaNodeId> = admissible.into_iter().take(need).collect();
    let after: BTreeSet<YubabaNodeId> = voters.keys().copied().chain(promote.iter().copied()).collect();
    let reason = format!(
        "learner(s) {} have been corroborated alive continuously for at least {hold_down}s and \
         are caught up; promoting them takes the voter set from {} to {}",
        render(&promote),
        voters.len(),
        after.len()
    );
    RehydratePlan::Promote {
        promote,
        after,
        reason,
    }
}

// ── Re-admission after a RECOVERY, which is a different path ─────────────────

/// Where a node joining a cluster has been (`W158` §7.2(2)).
///
/// **Read off the joiner by [`ask_origin`], never sent in a request body.** See
/// that function for why the first cut had this as an optional request field and
/// why moving it was the fix rather than making the field required.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeOrigin {
    /// The joiner's [`cluster_epoch::CLUSTER_PROTOCOL`](crate::cluster_epoch::CLUSTER_PROTOCOL).
    pub cluster_protocol: u32,
    /// The joiner's [`cluster_epoch::STATE_EPOCH`](crate::cluster_epoch::STATE_EPOCH).
    pub state_epoch: u32,
    /// The highest raft **term** the joiner's own log has ever held.
    ///
    /// This is the field that actually discriminates an incarnation — see
    /// [`judge_origin`].
    pub last_seen_term: u64,
}

/// This cluster's side of the comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalLineage {
    pub cluster_protocol: u32,
    pub state_epoch: u32,
    /// The leader's current term.
    pub current_term: u64,
}

/// Whether a declared origin may be handed to `add_learner` at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginVerdict {
    /// Adopt normally.
    Adopt,
    /// Refuse, permanently under this identity. The string is what an operator
    /// reads and it must say what to do next.
    Refuse(String),
}

/// How long the leader waits for a joiner to answer [`ask_origin`]. Sized like
/// [`sovereign_group`](crate::sovereign_group)'s: one loopback-or-mesh round
/// trip, at join time, not on any hot path.
const ASK_TIMEOUT: Duration = Duration::from_secs(3);

/// **Ask the joiner where it has been.** Two GETs at the address the leader is
/// about to start replicating to.
///
/// # The joiner is asked, not believed — and that is a rule this handler already
/// keeps
///
/// The first cut of this made `origin` a field on the add-learner *request
/// body*, optional by default. Review rightly called the optionality a hole a
/// caller walks through by saying nothing; making it required then broke six
/// pre-existing callers, because a request-body field cannot tell **"a node with
/// no history"** (which declares term 0 and is the ordinary way a cluster grows)
/// from **"a caller that will not say"**. Both look like an absent field.
///
/// So the field is gone and the fact is fetched. That is exactly what
/// [`sovereign_group::ask_peer`](crate::sovereign_group::ask_peer) does eleven
/// lines earlier in the same handler, for the reason its own doc gives: *"A
/// request body cannot be the source of a fact whose whole purpose is to catch a
/// mis-aimed request."* The same sentence is true here and more sharply, because
/// the fact this catches is one a misbehaving joiner has every reason to
/// misreport. Three things follow, all of them improvements:
///
/// - **there is nothing to omit**, so the hole closes without a `required` flag;
/// - **no caller changes** — `yah raft join`, the six existing tests, and every
///   operator script keep working untouched, which is how you can tell the
///   requirement is now in the right place;
/// - the residual *"the joiner declares this itself"*, which the first cut
///   documented as inherent, **is no longer inherent and no longer present**.
///
/// `/raft/status` carries `current_term`; `/health` carries the two build
/// epochs. Two small requests rather than one because no single route serves
/// both, and this runs once per join.
pub async fn ask_origin(addr: &str) -> Result<NodeOrigin, String> {
    let client = reqwest::Client::builder()
        .timeout(ASK_TIMEOUT)
        .build()
        .map_err(|e| format!("build http client: {e}"))?;

    let get_json = async |url: String| -> Result<serde_json::Value, String> {
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("GET {url}: HTTP {}", resp.status()));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| format!("GET {url}: decoding body: {e}"))
    };

    let status = get_json(format!("http://{addr}/raft/status")).await?;
    // A node that has never been in a cluster reports term 0, which is the
    // ordinary "brand new plinth" case and passes every clause below.
    let last_seen_term = status
        .get("current_term")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{addr}/raft/status carries no current_term"))?;

    let health = get_json(format!("http://{addr}/health")).await?;
    let epoch = |key: &str| -> Result<u32, String> {
        health
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as u32)
            .ok_or_else(|| format!("{addr}/health carries no {key}"))
    };

    Ok(NodeOrigin {
        cluster_protocol: epoch("cluster_protocol")?,
        state_epoch: epoch("state_epoch")?,
        last_seen_term,
    })
}

/// **Rehydration and re-admission are different paths, and this is the fork.**
///
/// `W158` §7.2(2): a voter demoted by the ratchet's `retain = true` is still in
/// membership, still replicating, and rejoins by ordinary replication plus
/// [`plan_rehydrate`] — it never touches `add_learner` at all. A node returning
/// after a *recovery* is from a cluster that no longer exists, carrying a longer
/// and higher-term log; handing that to `add_learner` directly is how one
/// cluster's history is grafted onto another. It must be wiped and given a new
/// node id first.
///
/// # The build epochs are NOT the incarnation discriminator, and saying so is
/// the point of this function
///
/// It is tempting to read `CLUSTER_PROTOCOL` / `STATE_EPOCH` as the fence,
/// because they are stamped on every [`MembershipRatchetRecord`]. They are not,
/// and `W158` §8 now records the finding: they are *build* compatibility
/// integers, so **two clusters founded independently from the same binary carry
/// identical values** — which is precisely the pair this has to tell apart. What
/// they legitimately answer is a different, still-necessary question ("can these
/// two builds share a cluster at all"), and that clause is checked first because
/// its failure is unconditional.
///
/// The clause that does the incarnation work is the **term**, which is the
/// property `W158` §5 itself names: a recovered cluster is refounded and its
/// terms climb independently, so a returner whose log has held a term this
/// cluster has never reached cannot have got it here. The converse is safe by
/// construction — a node this cluster demoted has replicated only this
/// cluster's entries, so its term is at or below the leader's.
///
/// This is a *sufficient* test, not a complete one: two lineages can be
/// distinguished only when their terms have actually diverged, and a recovered
/// cluster whose term has not yet passed the original's slips through. Closing
/// that needs the real `(cluster_id, epoch)` fence `W158` §5.2 describes and
/// this crate does not yet have. Stated rather than papered over.
pub fn judge_origin(declared: &NodeOrigin, local: &LocalLineage) -> OriginVerdict {
    if declared.cluster_protocol != local.cluster_protocol
        || declared.state_epoch != local.state_epoch
    {
        return OriginVerdict::Refuse(format!(
            "node declares cluster_protocol {} / state_epoch {}, this cluster runs {} / {}. \
             These builds cannot share a raft cluster; roll the joiner to a matching build \
             before adding it.",
            declared.cluster_protocol,
            declared.state_epoch,
            local.cluster_protocol,
            local.state_epoch
        ));
    }
    if declared.last_seen_term > local.current_term {
        return OriginVerdict::Refuse(format!(
            "node returns from a FOREIGN CLUSTER INCARNATION: it has held raft term {}, and this \
             cluster's term is {}. A node this cluster demoted can only carry a term at or below \
             the leader's, so this log is from a cluster that was recovered or refounded \
             elsewhere. Adding it as a learner would graft that history onto this one. Wipe its \
             raft directory and re-adopt it under a NEW node id (W158 §5.4); do not retry this \
             call.",
            declared.last_seen_term, local.current_term
        ));
    }
    OriginVerdict::Adopt
}

fn render(ids: &BTreeSet<YubabaNodeId>) -> String {
    ids.iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// How often the leader-resident loop re-evaluates.
#[derive(Debug, Clone, Copy)]
pub struct RatchetConfig {
    /// Tick period. The evidence it reads is already latched and hysteretic on
    /// the detector's side (`R118-F7`), so this only sets how promptly a
    /// verdict already reached becomes a membership change — it adds no
    /// debounce of its own and must not, or the hold-down would be applied
    /// twice.
    pub evaluate_every: Duration,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            evaluate_every: Duration::from_secs(1),
        }
    }
}

/// What one tick of [`run_once`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetOutcome {
    /// This node is not the leader. Only the leader changes membership.
    NotLeader,
    /// Neither half acted. `reason` carries the shrink's reason and, when the
    /// rehydrate half also had something to say, its reason after a `|`.
    Held { reason: String },
    /// [`plan`] shrank the voter set — dark voters demoted to learners.
    Shrank {
        demoted: BTreeSet<YubabaNodeId>,
        after: BTreeSet<YubabaNodeId>,
    },
    /// [`plan_rehydrate`] gave stable learners their vote back.
    Promoted {
        promoted: BTreeSet<YubabaNodeId>,
        after: BTreeSet<YubabaNodeId>,
    },
    /// A plan said act and the write failed. Transient by construction — every
    /// failure here is the next tick's to retry.
    Failed { error: String },
}

/// Evaluate once and act. Safe to call on any node: a follower returns
/// [`RatchetOutcome::NotLeader`] without reading anything.
///
/// Exposed rather than buried in [`spawn`]'s loop so an integration test can
/// drive the real decision path deterministically instead of sleeping against a
/// background task.
pub async fn run_once(
    node_id: YubabaNodeId,
    raft: &YubabaRaft,
    state_machine: &YubabaStateMachine,
    policy: &ClusterPolicy,
    http: &reqwest::Client,
    now: u64,
) -> RatchetOutcome {
    use openraft::async_runtime::watch::WatchReceiver;

    let Some(ttl) = policy.membership_ratchet.evidence_ttl() else {
        return RatchetOutcome::Held {
            reason: FROZEN_REASON.to_string(),
        };
    };

    let metrics = raft.metrics().borrow_watched().clone();
    if metrics.current_leader != Some(node_id) {
        return RatchetOutcome::NotLeader;
    }
    let membership = metrics.membership_config.membership().clone();
    let voters: BTreeSet<YubabaNodeId> = membership.voter_ids().collect();
    let learner_ids: BTreeSet<YubabaNodeId> = membership
        .nodes()
        .map(|(id, _)| *id)
        .filter(|id| !voters.contains(id))
        .collect();
    // Openraft's own record of how far each follower has replicated. A node the
    // leader has no entry for reads as NOT caught up — the fail-closed
    // direction, and the state a just-restarted learner is in.
    let last_log = metrics.last_log_index;
    let caught_up: BTreeMap<YubabaNodeId, bool> = learner_ids
        .iter()
        .map(|id| {
            let matched = metrics
                .replication
                .as_ref()
                .and_then(|r| r.get(id).cloned().flatten())
                .map(|log_id| log_id.index());
            (*id, matches!((matched, last_log), (Some(m), Some(l)) if m >= l))
        })
        .collect();

    let (evidence, learners) = state_machine.with_state(|state| {
        let evidence = evidence_from_state(state, &voters, now, ttl.as_secs());
        let learners: BTreeMap<YubabaNodeId, LearnerEvidence> = learner_ids
            .iter()
            .map(|id| {
                (
                    *id,
                    LearnerEvidence {
                        verdict: state.corroborated_liveness(*id, now, ttl.as_secs()),
                        alive_since: state.corroborated_alive_since(*id, now, ttl.as_secs()),
                        caught_up: caught_up.get(id).copied().unwrap_or(false),
                    },
                )
            })
            .collect();
        (evidence, learners)
    });

    // Shed before you admit. A shrink makes the cluster MORE writable and a
    // promotion makes it less, so when both have something to say the shrink
    // goes first — and `plan_rehydrate`'s gate 2 refuses anyway while any voter
    // is not alive, so the two can never both fire on one tick.
    let (demote, after, reason) = match plan(policy, &evidence) {
        RatchetPlan::Shrink {
            demote,
            after,
            reason,
        } => (demote, after, reason),
        RatchetPlan::Hold { reason: shrink_held } => {
            return match plan_rehydrate(policy, &evidence, &learners, now) {
                RehydratePlan::Promote {
                    promote,
                    after,
                    reason,
                } => promote_voters(node_id, raft, promote, after, reason).await,
                RehydratePlan::Hold { reason } => RatchetOutcome::Held {
                    reason: format!("{shrink_held} | rehydrate: {reason}"),
                },
            };
        }
    };

    info!(
        node_id,
        ?demote,
        ?after,
        %reason,
        "membership ratchet: demoting dark voters to learners"
    );

    // `retain = true`: demote, never evict. See this module's docs.
    let change = openraft::ChangeMembers::RemoveVoters(demote.clone());
    let resp = match raft.change_membership(change, true).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(node_id, ?demote, error = %e, "membership ratchet: change_membership failed");
            return RatchetOutcome::Failed {
                error: e.to_string(),
            };
        }
    };

    let committed: BTreeSet<YubabaNodeId> = resp
        .membership()
        .as_ref()
        .map(|m| m.voter_ids().collect())
        .unwrap_or_default();

    // Provenance, written after the fact and deliberately not folded into the
    // membership entry — openraft owns that entry's shape. Nothing reads this to
    // make a safety decision, so the two writes need not be atomic; see
    // `MembershipRatchetRecord` for what a returning node asks of it.
    let record = MembershipRatchetRecord {
        at: now,
        membership_term: resp.log_id().committed_leader_id().term,
        membership_index: resp.log_id().index(),
        before: evidence.keys().copied().collect(),
        after: committed.iter().copied().collect(),
        demoted: demote.iter().copied().collect(),
        cluster_protocol: crate::cluster_epoch::CLUSTER_PROTOCOL,
        state_epoch: crate::cluster_epoch::STATE_EPOCH,
        reason,
    };
    if let Err(e) =
        crate::raft::client_write_forwarded(raft, http, YubabaRequest::RecordMembershipRatchet {
            record,
        })
        .await
    {
        // The membership change is committed and that is the part that matters;
        // losing the provenance record costs a returning node its cheap answer,
        // not the cluster its correctness.
        warn!(node_id, error = %e, "membership ratchet: shrank, but could not record provenance");
    }

    RatchetOutcome::Shrank {
        demoted: demote,
        after: committed,
    }
}

/// Commit a rehydration, in **one** membership change.
///
/// `ChangeMembers::AddVoterIds` with the whole set, which is what lets the voter
/// count step 1 -> 3 without ever coming to rest on 2. `POST /raft/promote-voter`
/// takes a single `node_id` and so cannot express this; the *policy* gate is
/// still that route's, called from [`plan_rehydrate`] via
/// [`VoterAdmission::judge`](crate::cluster_policy::VoterAdmission::judge), so
/// there is one rule with two callers rather than two rules.
///
/// `retain` has no meaning for an add; `false` is passed to match
/// `raft_promote_voter`'s own call.
async fn promote_voters(
    node_id: YubabaNodeId,
    raft: &YubabaRaft,
    promote: BTreeSet<YubabaNodeId>,
    after: BTreeSet<YubabaNodeId>,
    reason: String,
) -> RatchetOutcome {
    info!(
        node_id,
        ?promote,
        ?after,
        %reason,
        "membership ratchet: rehydrating - promoting stable learners to voters"
    );
    let change = openraft::ChangeMembers::AddVoterIds(promote.clone());
    match raft.change_membership(change, false).await {
        Ok(resp) => {
            let committed: BTreeSet<YubabaNodeId> = resp
                .membership()
                .as_ref()
                .map(|m| m.voter_ids().collect())
                .unwrap_or_default();
            RatchetOutcome::Promoted {
                promoted: promote,
                after: committed,
            }
        }
        Err(e) => {
            warn!(node_id, ?promote, error = %e, "membership ratchet: promotion failed");
            RatchetOutcome::Failed {
                error: e.to_string(),
            }
        }
    }
}

/// Spawn the ratchet loop.
///
/// Safe to run on every node, like [`crate::scheduler::spawn`]: a follower's
/// tick returns [`RatchetOutcome::NotLeader`] and does nothing. Under
/// [`MembershipRatchet::Frozen`] the loop is not spawned at all — see
/// `main.rs` — so a fleet node does not even carry the task.
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    policy: ClusterPolicy,
    config: RatchetConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let http = match reqwest::Client::builder()
            .timeout(crate::raft::FORWARD_TIMEOUT)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(node_id, error = %e, "membership ratchet: no HTTP client, loop not started");
                return;
            }
        };
        info!(
            node_id,
            evaluate_every = ?config.evaluate_every,
            floor = ?policy.membership_ratchet.floor(),
            "membership ratchet active"
        );
        loop {
            tokio::time::sleep(config.evaluate_every).await;
            let now = crate::rollout::now_unix_secs();
            match run_once(node_id, &raft, &state_machine, &policy, &http, now).await {
                RatchetOutcome::Shrank { demoted, after } => {
                    info!(node_id, ?demoted, ?after, "membership ratchet: voter set shrank");
                }
                RatchetOutcome::Promoted { promoted, after } => {
                    info!(node_id, ?promoted, ?after, "membership ratchet: voter set rehydrated");
                }
                RatchetOutcome::Failed { error } => {
                    warn!(node_id, %error, "membership ratchet: write failed, retrying next tick");
                }
                RatchetOutcome::NotLeader | RatchetOutcome::Held { .. } => {}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_policy::ClusterPolicy;

    fn ev(verdict: PeerLivenessVerdict) -> VoterEvidence {
        VoterEvidence {
            verdict,
            alive_witnesses: 0,
            holds_gateway: false,
        }
    }

    fn evidence(
        entries: impl IntoIterator<Item = (YubabaNodeId, VoterEvidence)>,
    ) -> BTreeMap<YubabaNodeId, VoterEvidence> {
        entries.into_iter().collect()
    }

    fn all(n: YubabaNodeId, verdict: PeerLivenessVerdict) -> BTreeMap<YubabaNodeId, VoterEvidence> {
        evidence((1..=n).map(|id| (id, ev(verdict))))
    }

    fn shrink(plan: RatchetPlan) -> (BTreeSet<YubabaNodeId>, BTreeSet<YubabaNodeId>) {
        match plan {
            RatchetPlan::Shrink { demote, after, .. } => (demote, after),
            RatchetPlan::Hold { reason } => panic!("expected a shrink, held: {reason}"),
        }
    }

    fn held(plan: RatchetPlan) -> String {
        match plan {
            RatchetPlan::Hold { reason } => reason,
            RatchetPlan::Shrink { demote, after, .. } => {
                panic!("expected a hold, shrank: demote={demote:?} after={after:?}")
            }
        }
    }

    #[test]
    fn the_fleet_never_shrinks_under_any_evidence() {
        // Every voter but one corroborated dark — the strongest stimulus the
        // rig acts on — and the fleet must still be inert.
        let mut e = all(5, PeerLivenessVerdict::Dark);
        e.insert(1, ev(PeerLivenessVerdict::Alive));
        let reason = held(plan(&ClusterPolicy::fleet(), &e));
        assert!(
            reason.contains("freezes the voter set"),
            "the fleet must refuse for the policy reason, not incidentally: {reason}"
        );
    }

    #[test]
    fn five_voters_losing_two_shrink_to_three() {
        let mut e = all(5, PeerLivenessVerdict::Alive);
        e.insert(4, ev(PeerLivenessVerdict::Dark));
        e.insert(5, ev(PeerLivenessVerdict::Dark));
        let (demote, after) = shrink(plan(&ClusterPolicy::rig(), &e));
        assert_eq!(demote, BTreeSet::from([4, 5]));
        assert_eq!(after, BTreeSet::from([1, 2, 3]));
    }

    #[test]
    fn three_voters_losing_one_go_straight_to_one_never_resting_at_two() {
        let mut e = all(3, PeerLivenessVerdict::Alive);
        e.insert(3, ev(PeerLivenessVerdict::Dark));
        let (demote, after) = shrink(plan(&ClusterPolicy::rig(), &e));
        assert_eq!(
            after.len(),
            1,
            "two voters tolerate zero losses and are strictly worse than one; the ratchet must \
             spend the window in which both survivors can still commit the decision"
        );
        assert_eq!(demote.len(), 2);
        assert!(demote.contains(&3));
    }

    #[test]
    fn an_even_survivor_count_descends_to_the_odd_one_below() {
        let mut e = all(5, PeerLivenessVerdict::Alive);
        e.insert(5, ev(PeerLivenessVerdict::Dark));
        let (_, after) = shrink(plan(&ClusterPolicy::rig(), &e));
        assert_eq!(
            after.len(),
            3,
            "four voters survive exactly the failures three do while needing one more ack"
        );
    }

    #[test]
    fn every_non_dark_verdict_vetoes_the_whole_tick() {
        // The safety rule, exhaustively: three of five dark is a licensed
        // shrink, and ONE peer in any other state must stop all of it.
        for veto in [
            PeerLivenessVerdict::UnreachableButRadiating,
            PeerLivenessVerdict::SilentWithinHoldDown,
            PeerLivenessVerdict::Unknown,
        ] {
            let mut e = all(5, PeerLivenessVerdict::Alive);
            e.insert(4, ev(PeerLivenessVerdict::Dark));
            e.insert(5, ev(veto));
            let reason = held(plan(&ClusterPolicy::rig(), &e));
            assert!(
                reason.contains(veto.as_str()),
                "the hold must name the vetoing verdict {}: {reason}",
                veto.as_str()
            );
        }
    }

    #[test]
    fn a_partitioned_peer_is_never_demoted_even_alongside_a_dark_one() {
        let mut e = all(3, PeerLivenessVerdict::Alive);
        e.insert(2, ev(PeerLivenessVerdict::UnreachableButRadiating));
        e.insert(3, ev(PeerLivenessVerdict::Dark));
        held(plan(&ClusterPolicy::rig(), &e));
    }

    #[test]
    fn a_shrink_past_the_quorum_window_is_refused_rather_than_attempted() {
        let mut e = all(5, PeerLivenessVerdict::Dark);
        e.insert(1, ev(PeerLivenessVerdict::Alive));
        e.insert(2, ev(PeerLivenessVerdict::Alive));
        let reason = held(plan(&ClusterPolicy::rig(), &e));
        assert!(
            reason.contains("quorum is already lost"),
            "past the window the ratchet must say so rather than propose an uncommittable \
             write: {reason}"
        );
    }

    #[test]
    fn nothing_dark_is_a_hold_not_an_empty_shrink() {
        let reason = held(plan(&ClusterPolicy::rig(), &all(3, PeerLivenessVerdict::Alive)));
        assert!(reason.contains("all 3 voters are alive"), "{reason}");
    }

    #[test]
    fn the_gateway_owner_keeps_the_vote_over_a_better_connected_peer() {
        let mut e = all(3, PeerLivenessVerdict::Alive);
        e.insert(3, ev(PeerLivenessVerdict::Dark));
        // Node 2 is seen by more peers; node 1 owns egress. Gateway ownership
        // ranks above link quality, so node 1 survives.
        e.get_mut(&1).unwrap().holds_gateway = true;
        e.get_mut(&2).unwrap().alive_witnesses = 9;
        let (_, after) = shrink(plan(&ClusterPolicy::rig(), &e));
        assert_eq!(after, BTreeSet::from([1]));
    }

    #[test]
    fn link_quality_breaks_the_tie_when_nobody_owns_the_gateway() {
        let mut e = all(3, PeerLivenessVerdict::Alive);
        e.insert(3, ev(PeerLivenessVerdict::Dark));
        e.get_mut(&2).unwrap().alive_witnesses = 1;
        let (_, after) = shrink(plan(&ClusterPolicy::rig(), &e));
        assert_eq!(
            after,
            BTreeSet::from([2]),
            "the better-connected survivor keeps the vote; node id is the last resort, not the \
             first"
        );
    }

    #[test]
    fn the_lowest_node_id_is_the_final_deterministic_fallback() {
        let mut e = all(3, PeerLivenessVerdict::Alive);
        e.insert(3, ev(PeerLivenessVerdict::Dark));
        let (_, after) = shrink(plan(&ClusterPolicy::rig(), &e));
        assert_eq!(after, BTreeSet::from([1]));
    }

    #[test]
    fn the_reason_names_the_live_voter_that_conceded_its_vote() {
        let mut e = all(3, PeerLivenessVerdict::Alive);
        e.insert(3, ev(PeerLivenessVerdict::Dark));
        let RatchetPlan::Shrink { reason, .. } = plan(&ClusterPolicy::rig(), &e) else {
            panic!("expected a shrink");
        };
        assert!(
            reason.contains("give up the vote too"),
            "demoting a LIVE voter is the surprising half of this decision and must be explained \
             in the record an operator reads: {reason}"
        );
    }

    #[test]
    fn a_single_voter_cluster_holds_rather_than_emptying_itself() {
        let e = evidence([(1, ev(PeerLivenessVerdict::Dark))]);
        let reason = held(plan(&ClusterPolicy::rig(), &e));
        assert!(reason.contains("floor"), "{reason}");
    }

    #[test]
    fn the_rig_preset_rests_at_one_voter_and_the_fleet_never_shrinks() {
        assert_eq!(
            ClusterPolicy::rig().membership_ratchet.floor().map(|f| f.get()),
            Some(1)
        );
        assert_eq!(ClusterPolicy::fleet().membership_ratchet.floor(), None);
        assert_eq!(ClusterPolicy::fleet().membership_ratchet.evidence_ttl(), None);
    }

    // ── Rehydration (part 2) ────────────────────────────────────────────────

    /// The rig's hold-down, so the arithmetic below reads against the real one.
    const HOLD: u64 = 300;

    fn learner(alive_since: Option<u64>) -> LearnerEvidence {
        LearnerEvidence {
            verdict: if alive_since.is_some() {
                PeerLivenessVerdict::Alive
            } else {
                PeerLivenessVerdict::Dark
            },
            alive_since,
            caught_up: true,
        }
    }

    fn learners(
        entries: impl IntoIterator<Item = (YubabaNodeId, LearnerEvidence)>,
    ) -> BTreeMap<YubabaNodeId, LearnerEvidence> {
        entries.into_iter().collect()
    }

    fn promoted(plan: RehydratePlan) -> (BTreeSet<YubabaNodeId>, BTreeSet<YubabaNodeId>) {
        match plan {
            RehydratePlan::Promote { promote, after, .. } => (promote, after),
            RehydratePlan::Hold { reason } => panic!("expected a promotion, held: {reason}"),
        }
    }

    fn rehydrate_held(plan: RehydratePlan) -> String {
        match plan {
            RehydratePlan::Hold { reason } => reason,
            RehydratePlan::Promote { promote, .. } => {
                panic!("expected a hold, promoted {promote:?}")
            }
        }
    }

    #[test]
    fn the_fleet_never_rehydrates() {
        let voters = evidence([(1, ev(PeerLivenessVerdict::Alive))]);
        let l = learners([(2, learner(Some(0))), (3, learner(Some(0)))]);
        let reason = rehydrate_held(plan_rehydrate(&ClusterPolicy::fleet(), &voters, &l, HOLD * 10));
        assert!(reason.contains("freezes the voter set"), "{reason}");
    }

    #[test]
    fn a_returned_learner_is_not_promoted_before_the_hold_down_expires() {
        let voters = evidence([(1, ev(PeerLivenessVerdict::Alive))]);
        // Both came back at t=1000. At t=1000+HOLD-1 neither has cleared it.
        let l = learners([(2, learner(Some(1_000))), (3, learner(Some(1_000)))]);
        let reason = rehydrate_held(plan_rehydrate(
            &ClusterPolicy::rig(),
            &voters,
            &l,
            1_000 + HOLD - 1,
        ));
        assert!(
            reason.contains(&format!("{}s-of-{HOLD}s", HOLD - 1)),
            "the hold must say how far through the hold-down each candidate is: {reason}"
        );
        // One second later, exactly at the boundary, both clear it.
        let (promote, after) = promoted(plan_rehydrate(
            &ClusterPolicy::rig(),
            &voters,
            &l,
            1_000 + HOLD,
        ));
        assert_eq!(promote, BTreeSet::from([2, 3]));
        assert_eq!(after, BTreeSet::from([1, 2, 3]));
    }

    /// **The test the whole feature exists for.**
    ///
    /// A flapping node's `alive_since` is re-stamped by the state machine on
    /// every verdict change, so each return restarts the clock. Simulated here
    /// as the plan sees it: at every point in the flap the node's continuous
    /// presence is short, and the answer must be no every single time.
    #[test]
    fn a_flapping_learner_never_becomes_a_voter() {
        let voters = evidence([(1, ev(PeerLivenessVerdict::Alive))]);
        let first_came_up_at = 1_000u64;
        let mut now = first_came_up_at;
        // up, down, up, down, up — each up lasts most of a hold-down but never
        // all of it, which is exactly what a plinth on a failing PSU does.
        for cycle in 0..5 {
            let came_up_at = now;
            // While up: alive, but only ever for (HOLD - 1) seconds.
            let up = learners([(2, learner(Some(came_up_at)))]);
            let reason = rehydrate_held(plan_rehydrate(
                &ClusterPolicy::rig(),
                &voters,
                &up,
                came_up_at + HOLD - 1,
            ));
            assert!(
                reason.contains("hold-down"),
                "cycle {cycle}: a node up for less than a hold-down must not be promoted: {reason}"
            );
            now = came_up_at + HOLD - 1;

            // It drops. `alive_since` is gone; the fold is not Alive.
            let down = learners([(2, learner(None))]);
            let reason = rehydrate_held(plan_rehydrate(&ClusterPolicy::rig(), &voters, &down, now));
            assert!(
                reason.contains("not-corroborated-alive"),
                "cycle {cycle}: a node that is down is not a candidate at all: {reason}"
            );
            // It comes back — and because the apply arm re-stamps `since` on a
            // verdict CHANGE, the next `alive_since` is NOW, not the original.
            now += 5;
        }
        // **The closing claim, and the one the cycles above build to.**
        //
        // By now far more than a hold-down of wall clock has passed since the
        // node first appeared — five cycles of nearly 300 s each — and the node
        // is up right now. A gate that measured TOTAL presence, or that measured
        // "first seen" instead of "continuously since", would promote it here.
        // It must still refuse, because what the hold-down asks for is an
        // unbroken run and this node has never had one.
        let total_elapsed = now - first_came_up_at;
        assert!(
            total_elapsed > HOLD,
            "the flap must span more than one hold-down of wall clock, or this assertion is not \
             testing anything: {total_elapsed}s elapsed against a {HOLD}s hold-down"
        );
        let up_again = learners([(2, learner(Some(now)))]);
        let reason = rehydrate_held(plan_rehydrate(&ClusterPolicy::rig(), &voters, &up_again, now));
        assert!(
            reason.contains(&format!("2=alive-only-0s-of-{HOLD}s")),
            "after {total_elapsed}s of flapping the node's CONTINUOUS presence is still zero, and \
             the refusal must be measured from its latest return rather than from its first: \
             {reason}"
        );
    }

    /// The clause that makes rehydration safe to pair with the shrink: a
    /// promotion must land on an odd count or not happen.
    #[test]
    fn one_ready_learner_does_not_take_a_lone_voter_to_two() {
        let voters = evidence([(1, ev(PeerLivenessVerdict::Alive))]);
        let l = learners([(2, learner(Some(0))), (3, learner(None))]);
        let reason = rehydrate_held(plan_rehydrate(&ClusterPolicy::rig(), &voters, &l, HOLD * 10));
        assert!(
            reason.contains("tolerates zero further losses"),
            "resting at 2 is the state the shrink half cannot repair, and the refusal must say \
             so: {reason}"
        );
    }

    /// ...but from an EVEN voter set — which only an operator's manual
    /// promote-voter can produce — one promotion is exactly right.
    #[test]
    fn from_an_even_voter_set_a_single_promotion_restores_oddness() {
        let voters = evidence([
            (1, ev(PeerLivenessVerdict::Alive)),
            (2, ev(PeerLivenessVerdict::Alive)),
        ]);
        let l = learners([(3, learner(Some(0)))]);
        let (promote, after) = promoted(plan_rehydrate(
            &ClusterPolicy::rig(),
            &voters,
            &l,
            HOLD * 10,
        ));
        assert_eq!(promote, BTreeSet::from([3]));
        assert_eq!(after.len(), 3);
    }

    #[test]
    fn a_learner_that_is_not_caught_up_is_not_promoted() {
        let voters = evidence([(1, ev(PeerLivenessVerdict::Alive))]);
        let mut l = learners([(2, learner(Some(0))), (3, learner(Some(0)))]);
        l.get_mut(&3).unwrap().caught_up = false;
        let reason = rehydrate_held(plan_rehydrate(&ClusterPolicy::rig(), &voters, &l, HOLD * 10));
        assert!(
            reason.contains("3=not-caught-up"),
            "the refusal must name the node and the gate it failed: {reason}"
        );
        assert!(
            reason.contains("1 learner(s) are stable and admissible but 2 are needed"),
            "…and, since dropping it leaves too few to reach an odd count, must say that too — \
             an operator seeing a cluster stuck at one voter needs both halves in one line: \
             {reason}"
        );
    }

    #[test]
    fn rehydration_stops_at_the_policys_max_voters() {
        // Five voters is the rig cap. A sixth stable learner is refused BY
        // VoterAdmission::judge, not by an arithmetic accident here.
        let mut voters = all(5, PeerLivenessVerdict::Alive);
        voters.insert(5, ev(PeerLivenessVerdict::Alive));
        let l = learners([(6, learner(Some(0))), (7, learner(Some(0)))]);
        let reason = rehydrate_held(plan_rehydrate(&ClusterPolicy::rig(), &voters, &l, HOLD * 10));
        assert!(
            reason.contains("caps the voter set at 5"),
            "the refusal must be the cluster policy's own words, so there is one rule and not \
             two: {reason}"
        );
    }

    #[test]
    fn the_voter_set_must_be_whole_before_it_grows() {
        let mut voters = all(3, PeerLivenessVerdict::Alive);
        voters.insert(3, ev(PeerLivenessVerdict::Dark));
        let l = learners([(4, learner(Some(0))), (5, learner(Some(0)))]);
        let reason = rehydrate_held(plan_rehydrate(&ClusterPolicy::rig(), &voters, &l, HOLD * 10));
        assert!(
            reason.contains("voter 3 is `dark`"),
            "promotion raises quorum, so a degraded voter set must be shed before it is grown: \
             {reason}"
        );
    }

    // ── Re-admission after a recovery ───────────────────────────────────────

    fn local() -> LocalLineage {
        LocalLineage {
            cluster_protocol: crate::cluster_epoch::CLUSTER_PROTOCOL,
            state_epoch: crate::cluster_epoch::STATE_EPOCH,
            current_term: 7,
        }
    }

    fn origin(term: u64) -> NodeOrigin {
        NodeOrigin {
            cluster_protocol: crate::cluster_epoch::CLUSTER_PROTOCOL,
            state_epoch: crate::cluster_epoch::STATE_EPOCH,
            last_seen_term: term,
        }
    }

    #[test]
    fn a_node_this_cluster_demoted_is_adopted() {
        assert_eq!(judge_origin(&origin(7), &local()), OriginVerdict::Adopt);
        assert_eq!(judge_origin(&origin(3), &local()), OriginVerdict::Adopt);
    }

    #[test]
    fn a_higher_term_is_a_foreign_incarnation_and_is_refused_with_the_remedy() {
        let OriginVerdict::Refuse(reason) = judge_origin(&origin(9), &local()) else {
            panic!("a node carrying a term this cluster has never reached cannot have got it here");
        };
        assert!(reason.contains("FOREIGN CLUSTER INCARNATION"), "{reason}");
        assert!(
            reason.contains("NEW node id"),
            "a refusal that does not say what to do next sends an operator to retry it: {reason}"
        );
        assert!(
            reason.contains("do not retry"),
            "this is permanent under the current identity, not a transient failure: {reason}"
        );
    }

    /// Only a cluster that rehydrates pays for the dial — and only it needs to.
    #[test]
    fn only_a_ratcheting_policy_interrogates_a_joiner() {
        assert!(
            ClusterPolicy::rig().membership_ratchet.vets_joiner_lineage(),
            "a cluster that hands votes back by machinery must vet a joiner at the join, because \
             that is the last point at which anything asks where it has been"
        );
        assert!(
            !ClusterPolicy::fleet().membership_ratchet.vets_joiner_lineage(),
            "the fleet promotes nobody without an operator, so an unvetted joiner stays a \
             learner and a human is still the gate on every vote — it skips the dial and \
             behaves exactly as it did before this existed"
        );
    }

    /// A brand-new plinth reports term 0 and is adopted. This is the case a
    /// *required request field* could not express — an absent field and "no
    /// history" look identical — and it is the ordinary way a cluster grows.
    #[test]
    fn a_node_that_has_never_been_in_a_cluster_is_adopted() {
        assert_eq!(judge_origin(&origin(0), &local()), OriginVerdict::Adopt);
    }

    #[test]
    fn a_build_epoch_mismatch_is_refused_before_the_term_is_even_looked_at() {
        let mut o = origin(3);
        o.state_epoch = crate::cluster_epoch::STATE_EPOCH + 1;
        let OriginVerdict::Refuse(reason) = judge_origin(&o, &local()) else {
            panic!("two builds at different state epochs cannot share a cluster");
        };
        assert!(
            reason.contains("cannot share a raft cluster"),
            "the build-epoch clause is unconditional and is a DIFFERENT refusal from the \
             incarnation one — see judge_origin's docs on why the build epochs are not the \
             incarnation discriminator: {reason}"
        );
    }

    #[test]
    fn only_dark_licenses_a_shrink() {
        for v in [
            PeerLivenessVerdict::Alive,
            PeerLivenessVerdict::UnreachableButRadiating,
            PeerLivenessVerdict::SilentWithinHoldDown,
            PeerLivenessVerdict::Unknown,
        ] {
            assert!(!v.licenses_shrink(), "{v:?} must veto");
        }
        assert!(PeerLivenessVerdict::Dark.licenses_shrink());
    }
}
