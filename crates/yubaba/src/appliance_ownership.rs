//! Appliance ownership — who runs the cluster's pinned-singleton appliance,
//! decided **independently of who holds raft leadership** (R858-T3).
//!
//! # The incident this module exists to make impossible
//!
//! On 2026-09-03T06:03:03Z a routine `POST /raft/transfer-leader` moved
//! leadership us-west-001 → us-south-001. Under
//! [`IngressOwnership::FollowsRaftLeader`](crate::cluster_policy::IngressOwnership::FollowsRaftLeader)
//! the appliance follows the leader, so west correctly tore headscale down;
//! south then failed to deploy it (kamaji refused: no native backend) and its
//! systemd fallback failed too (no such unit). **Both failures were `warn!` and
//! the cluster carried on.** The mesh had no coordination server for 37 hours
//! while every external healthcheck stayed green.
//!
//! Three independent defects produced that, and this module answers the first
//! two; [`crate::leader`] applies them:
//!
//! 1. **Ownership aliased leadership**, so a healthy owner was torn down for a
//!    reason that had nothing to do with the appliance. Answered by
//!    [`decide_owner`]'s stickiness rule: a serving owner does not move because
//!    leadership moved. Ownership changes on owner *failure*.
//! 2. **Exactly one node ever tried.** There was no candidate list and no
//!    retry. Answered by [`OwnerElection`] — a failed deploy puts that node in
//!    backoff and the next eligible candidate is elected.
//! 3. **A node that could not serve still recorded itself as the owner.** That
//!    one is [`crate::leader`]'s: claim on success only, and refuse loudly.
//!
//! # Flapping is the failure mode of the fix, not of the bug
//!
//! Re-election on failure is trivially writable as an infinite fast loop that
//! moves the coordinator every few seconds. That would be *worse* than the
//! outage it replaces: an intermittently-up mesh is harder to diagnose than an
//! absent one, and every move costs a full client reconvergence. Three bounds
//! hold it, and each is a named constant so the reasoning is readable at the
//! value rather than inferable from the code:
//!
//! - [`MAX_CANDIDATES_PER_ROUND`] — how many nodes one vacancy may burn before
//!   the cluster stops trying and surfaces [`ApplianceHealth::Unhealthy`].
//! - [`BACKOFF_BASE_SECS`] / [`BACKOFF_MAX_SECS`] — a node that just failed to
//!   deploy is ineligible for at least the base, doubling per consecutive
//!   failure. A node cannot fail and be re-elected on the next tick.
//! - The stickiness rule in [`decide_owner`] — the common case (leadership
//!   moved, appliance is fine) produces no movement at all.
//!
//! # Reuse, not a second eligibility model
//!
//! The readiness gates are [`crate::scheduler`]'s: this module carries
//! [`NodeEligibility`] verbatim and defers to
//! [`judge_readiness`](crate::lease_detector::judge_readiness) for "live,
//! raft-peer-healthy, within headroom". [`ApplianceCandidate`] adds exactly the
//! two facts a *tenant* placement does not have — a native-exec capability
//! (R858-T4's seam) and this node's own deploy-failure backoff — so there is
//! one eligibility vocabulary in the crate, not two.
//!
//! The one place the appliance's projection differs from a tenant's is
//! `hydrated`: a tenant's is tier-derived ([`SlaTier::WarmReplica`] needs a warm
//! replica first), while the appliance has no SLA tier and hydrates *as part of*
//! being started — `litestream restore` runs before `headscale serve` in
//! [`crate::leader`]. So the gate is vacuously satisfied here, the same reading
//! [`SlaTier::ColdHydrate`] gets there.
//!
//! [`SlaTier::WarmReplica`]: workload_spec::SlaTier::WarmReplica
//! [`SlaTier::ColdHydrate`]: workload_spec::SlaTier::ColdHydrate

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use crate::lease_detector::{judge_readiness, NotReady, ReadinessInputs};
use crate::raft::YubabaNodeId;
use crate::scheduler::NodeEligibility;

/// How many distinct nodes one vacancy may try before the cluster stops and
/// surfaces [`ApplianceHealth::Unhealthy`].
///
/// Three, because the prod voter set is three and the sanctioned dev cluster is
/// three: one round is therefore a full sweep of the fleet rather than an
/// arbitrary slice of it. The bound is not there to save work — trying a fourth
/// node costs nothing — it is there so that "nothing can run the appliance"
/// becomes a *reported state* after a bounded time instead of an unbounded
/// retry loop that no operator ever sees the end of. A cluster larger than this
/// still converges: the round resets on any success, and the backoff expiry of
/// the earliest failure re-opens the next round.
pub const MAX_CANDIDATES_PER_ROUND: usize = 3;

/// Minimum time a node that failed to deploy the appliance stays ineligible.
///
/// Thirty seconds is ten times the WAN election-timeout ceiling
/// ([`RaftTiming::wan`](crate::cluster_policy::RaftTiming::wan) tops out at
/// 3 s), which is the property that matters: a node cannot fail a deploy and be
/// re-elected inside the same election cycle, so a broken node cannot ping-pong
/// with a working one. It is also short enough that a genuinely transient
/// failure (a raced port release, a slow kamaji socket) costs one short gap
/// rather than an operator round trip.
pub const BACKOFF_BASE_SECS: u64 = 30;

/// Ceiling on the doubling backoff: 30 → 60 → 120 → 240 → 300, then flat.
///
/// Five minutes, not "forever". A node whose failure was environmental — the
/// kamaji that R858-T4 will teach to run native workloads, a headscale binary
/// that was not on disk — becomes a candidate again within five minutes of
/// being fixed, without an operator having to know that a ledger exists or how
/// to clear it. Unbounded doubling optimises for a case (a permanently broken
/// node) that [`ApplianceHealth::Unhealthy`] already reports.
pub const BACKOFF_MAX_SECS: u64 = 300;

/// Whether a node can fork+exec a native workload — the fact that actually
/// decides whether the headscale appliance can run there.
///
/// **This is R858-T4's seam and it is deliberately unpopulated here.** T4's job
/// is "model per-node native-exec capability in placement, and make the
/// headscale binary present on every candidate"; it fills this in from real
/// probe data. Until then every live call site passes [`Self::Unknown`], which
/// [`judge_appliance_candidate`] treats as *permissive* — the placeholder is
/// named rather than an inline `true` precisely so that T4 changes the producer
/// and not the predicate.
///
/// Permissive is the right placeholder direction: reading "unknown" as "cannot"
/// would make every node ineligible the moment this landed and reproduce the
/// outage from the other side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NativeExecCapability {
    /// Nothing has probed this node. Permissive until R858-T4 lands.
    #[default]
    Unknown,
    /// Probed: this node's kamaji was built with `native-exec` and started with
    /// `--native-exec-dir`, and the appliance binary is present.
    Present,
    /// Probed: this node cannot run the appliance. Hard-refuses.
    Absent,
}

/// One node's candidacy for the appliance — [`NodeEligibility`]'s shared
/// readiness facts plus the two the appliance adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplianceCandidate {
    /// The gates [`crate::scheduler`] already defines. Carried whole rather
    /// than flattened so a caller cannot lose the `None`/`Down` distinction
    /// [`ReadinessInputs::liveness`] is explicit about.
    pub node: NodeEligibility,
    /// R858-T4's seam. See [`NativeExecCapability`].
    pub capability: NativeExecCapability,
    /// Unix seconds until which this node is serving out a deploy-failure
    /// backoff, from [`OwnerElection::backoff_until`]. `None` means no recorded
    /// failure.
    pub backoff_until: Option<u64>,
}

/// Why [`judge_appliance_candidate`] refused, in check order.
///
/// Ordered readiness-first so that a node which is simply *down* reports
/// `NotReady(NotLive)` rather than a capability verdict about a machine nobody
/// can reach — the same "first gate that fails is the one reported" contract
/// [`NotReady`] holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplianceIneligible {
    /// Failed one of [`crate::scheduler`]'s shared readiness gates.
    NotReady(NotReady),
    /// [`NativeExecCapability::Absent`] — cannot fork+exec the appliance.
    MissingNativeExec,
    /// Failed a deploy recently; ineligible until `until_unix`.
    InFailureBackoff { until_unix: u64 },
}

impl ApplianceIneligible {
    /// Stable lowercase token for the operator-facing refusal line, mirroring
    /// [`crate::scheduler`]'s `refusal_str`: a log token, never prose.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotReady(NotReady::NotLive) => "not-live",
            Self::NotReady(NotReady::RaftPeerUnhealthy) => "raft-peer-unhealthy",
            Self::NotReady(NotReady::NotHydrated) => "not-hydrated",
            Self::NotReady(NotReady::StreamerBehindBound) => "streamer-behind-bound",
            Self::NotReady(NotReady::OverHeadroom) => "over-headroom",
            Self::MissingNativeExec => "missing-native-exec",
            Self::InFailureBackoff { .. } => "deploy-backoff",
        }
    }
}

/// The eligibility predicate. **This is the extension point R858-T4 adds to.**
///
/// Three gates, in this order:
///
/// 1. [`crate::scheduler`]'s shared readiness gates, via
///    [`judge_readiness`] — the node is confirmed live, its raft peer link is
///    not known-dead, and it is within its headroom.
/// 2. Native-exec capability — [`NativeExecCapability::Absent`] refuses;
///    [`NativeExecCapability::Unknown`] admits (the R858-T4 placeholder).
/// 3. Deploy-failure backoff — a node that just failed is not immediately
///    re-electable.
///
/// A new gate is one arm added here plus one field on [`ApplianceCandidate`];
/// nothing about [`decide_owner`]'s shape changes.
pub fn judge_appliance_candidate(
    cand: &ApplianceCandidate,
    now_unix: u64,
) -> Result<(), ApplianceIneligible> {
    judge_readiness(&ReadinessInputs {
        liveness: cand.node.liveness,
        raft_peer_healthy: cand.node.raft_peer_healthy,
        // Vacuously satisfied — the appliance hydrates as part of being
        // started. See the module doc.
        hydrated: true,
        within_headroom: cand.node.admits,
        // The appliance has no per-tenant RPO target; its DB continuity is
        // litestream's, gated inside `leader::start_headscale` rather than
        // here.
        streamer_watermark_age: None,
        streamer_rpo_bound: None,
    })
    .map_err(ApplianceIneligible::NotReady)?;

    // R858-T4 fills this in. `Unknown` is the permissive placeholder; see
    // `NativeExecCapability`.
    if cand.capability == NativeExecCapability::Absent {
        return Err(ApplianceIneligible::MissingNativeExec);
    }

    if let Some(until) = cand.backoff_until {
        if now_unix < until {
            return Err(ApplianceIneligible::InFailureBackoff { until_unix: until });
        }
    }

    Ok(())
}

/// The recorded owner and whether it is actually serving.
///
/// `serving` is deliberately a separate fact from "there is a record": the
/// entire R858 outage is the gap between the two. A record with `serving:
/// false` is precisely the state [`decide_owner`] must re-elect out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerStatus {
    pub node: YubabaNodeId,
    pub serving: bool,
}

/// Build the [`OwnerStatus`] [`decide_owner`] takes, from the **replicated**
/// record first and this process's memory only as a fallback.
///
/// # Why the record has to lead
///
/// [`OwnerElection`]'s health lives in the leadership watcher's stack frame, so
/// it is empty on every freshly-started yubaba. Deriving the owner from it alone
/// means a restarted daemon believes the appliance is vacant — and a vacant
/// appliance is one this node elects itself to run. On the coordinator that is a
/// needless restart of a healthy headscale; on any other node it is a second
/// one. Either way "restart yubaba" moves the appliance, which is the property
/// R858-T3 exists to remove and the one the operator's rehearsal tests.
///
/// `ingress_owner` is replicated, survives the restart, and — since R858-T3
/// change (3) — is written *only after a successful start*. So its presence is
/// real evidence that some node stood the appliance up, which is exactly what
/// this needs and exactly what it did not mean before change (3).
///
/// # `serving` is measured where it can be and assumed where it cannot
///
/// - **The record names this node.** The one case with local evidence, so it is
///   read rather than assumed: `local_appliance_running` comes from asking this
///   node's own supervisor whether the appliance is up. A record that says "me"
///   over a supervisor that says "nothing here" is precisely the stale claim
///   that must re-elect, and it is the shape a node left behind after a crash.
/// - **The record names another node.** No local evidence exists and inventing
///   some would be the R734-T4 mistake. Assumed serving; a genuinely dead owner
///   is R858-T7's retraction to expire, not this function's to guess at.
/// - **No record.** Fall back to this process's own [`ApplianceHealth`], which
///   is what a cluster that has never elected an owner has (and what every
///   pre-R859-F2 node, whose member row carries no machine name, degrades to).
pub fn owner_status(
    recorded: Option<YubabaNodeId>,
    this_node: YubabaNodeId,
    local_appliance_running: bool,
    local_health: &ApplianceHealth,
) -> Option<OwnerStatus> {
    match recorded {
        Some(node) if node == this_node => Some(OwnerStatus {
            node,
            serving: local_appliance_running,
        }),
        Some(node) => Some(OwnerStatus {
            node,
            serving: true,
        }),
        None => match local_health {
            ApplianceHealth::Serving(node) => Some(OwnerStatus {
                node: *node,
                serving: true,
            }),
            _ => None,
        },
    }
}

/// What [`decide_owner`] concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipDecision {
    /// The recorded owner is serving and still eligible. **Nothing moves.**
    /// This is the answer on an ordinary raft leadership change, and it is the
    /// single most important arm in this module.
    OwnerServing(YubabaNodeId),
    /// Vacant, or the owner failed: elect this node.
    ElectTo(YubabaNodeId),
    /// Nobody can run the appliance. The cluster is UNHEALTHY and must say so —
    /// see [`ApplianceHealth`]. Not a `warn!`-and-continue.
    NoEligibleCandidate,
}

/// The cluster's appliance-availability verdict, as a value rather than a log
/// line.
///
/// R858 ran 37 hours because the failure existed only as two `warn!`s. A typed
/// state is what lets a healthcheck, `yah mesh status`, or a test assert on it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ApplianceHealth {
    /// A node is recorded as owner and reported a successful deploy.
    Serving(YubabaNodeId),
    /// No owner yet, and no failure recorded — a cluster that has not elected
    /// one. Distinct from `Unhealthy`: nothing has gone wrong, it just has not
    /// happened yet.
    #[default]
    Vacant,
    /// Something tried and could not, or nothing is eligible. `reason` is the
    /// operator-facing detail.
    Unhealthy { reason: String },
}

impl ApplianceHealth {
    /// Whether this verdict should fail a healthcheck.
    pub fn is_unhealthy(&self) -> bool {
        matches!(self, Self::Unhealthy { .. })
    }
}

/// Decide who owns the appliance.
///
/// # Stickiness — the rule the outage turned on
///
/// A serving, still-eligible owner returns [`OwnershipDecision::OwnerServing`]
/// and **nothing moves**, regardless of who holds raft leadership. Ownership is
/// its own elected fact; leadership is an input to nothing here. That is the
/// whole point of R858-T3, and it is why this function does not take a
/// leader id at all — there is no way to express "move it because leadership
/// moved", because that is the bug.
///
/// # Ordering, and why it is deterministic
///
/// Eligible candidates rank by ascending node id, with no region preference:
/// unlike a tenant, the appliance has no declared region — its clients are
/// outside the mesh by definition, so no node is nearer to them. Determinism is
/// load-bearing rather than cosmetic: every node evaluates this independently
/// from replicated state, so an identical ordering is what makes them agree on
/// one winner without another round of consensus. Two nodes disagreeing here
/// means two coordinators, which is the failure worse than the outage.
///
/// Only the first [`MAX_CANDIDATES_PER_ROUND`] eligible nodes are considered,
/// so one vacancy cannot walk an arbitrarily long fleet.
///
/// # An owner missing from `candidates` is *unjudged*, never *ineligible*
///
/// This distinction is the difference between "a yubaba restart leaves the
/// coordinator alone" and "a yubaba restart takes it away", so it is worth
/// stating rather than reading off the `match`.
///
/// [`crate::leader`]'s call site can only put **one** node in `candidates` —
/// itself — because the hysteresis-confirmed liveness a peer's
/// [`NodeEligibility`] needs lives in the scheduler loop's tracker and there is
/// no ask-a-peer-to-deploy channel. So on every node that is *not* the owner,
/// the owner is simply absent from the map. Reading that absence as "the owner
/// failed its gates" makes every such node elect *itself*, which is a second
/// coordinator — the failure this module calls worse than the outage.
///
/// So the rule is: move only on positive evidence that the owner is broken.
/// Silence about the owner leaves it exactly where it is. That is the same
/// correction `leader_pin::decide` took under R734-T4 (`LeaderRegionUnknown`:
/// act only on positive evidence about both ends), for the same reason — a
/// row-less or unjudgeable peer is what a *restart* looks like, so treating it
/// as a verdict manufactures churn out of an anti-churn mechanism.
///
/// The residual is deliberate and named: a recorded owner that is genuinely
/// **dead** is not re-elected away from by this function alone, because nothing
/// here can see that it died. Retracting a dead owner's record is R858-T7's
/// (expire + fence), and once a caller can judge remote nodes it lands in
/// `candidates` and the first arm above fires without a change here.
pub fn decide_owner(
    owner: Option<OwnerStatus>,
    candidates: &BTreeMap<YubabaNodeId, ApplianceCandidate>,
    now_unix: u64,
) -> OwnershipDecision {
    if let Some(o) = owner {
        if o.serving {
            match candidates.get(&o.node) {
                // POSITIVE evidence the owner cannot serve — its lease expired,
                // it lost native-exec, it is in deploy backoff. Fall through and
                // re-elect: this is `killing_the_serving_owner_...`'s path.
                Some(c) if judge_appliance_candidate(c, now_unix).is_err() => {}
                // Judged eligible, or **not judgeable from here at all**.
                // Either way nothing moves. See this function's doc.
                _ => return OwnershipDecision::OwnerServing(o.node),
            }
        }
    }

    let winner = candidates
        .iter()
        .filter(|(_, cand)| judge_appliance_candidate(cand, now_unix).is_ok())
        .map(|(id, _)| *id)
        .take(MAX_CANDIDATES_PER_ROUND)
        .next();

    match winner {
        Some(id) => OwnershipDecision::ElectTo(id),
        None => OwnershipDecision::NoEligibleCandidate,
    }
}

// ─── R858-T7: ungraceful death — expiry and fencing ─────────────────────────
//
// Everything above answers "who should own the appliance", and every one of its
// inputs arrives because some node CHOSE to produce it. A powered-off node
// chooses nothing: it does not retract its service record, it does not release
// the claim, it does not run `stop_headscale`. `decide_owner`'s own doc names
// the residual — "a recorded owner that is genuinely **dead** is not re-elected
// away from by this function alone, because nothing here can see that it died".
//
// This section closes it from both ends, and they are two different problems
// wearing one word:
//
// - **EXPIRE** is the cluster's problem. The survivors must conclude, from
//   evidence the dead node did not have to supply, that the record is stale —
//   and then overwrite or clear it. [`owner_lease_expired`].
// - **FENCE** is the *holder's* problem, and it is the one that outranks the
//   outage. A node that comes back — from a power cut, from a partition, from a
//   `systemctl enable`d unit firing at boot — must not serve. [`judge_self_fence`].
//
// # Why the fence is a lease and NOT a raft-minted epoch
//
// This ticket was handed the fork explicitly: "either the appliance claim itself
// carries the epoch and a stale holder refuses to serve, or ownership is a lease
// the old node observes expiring. Decide which." It is the lease, and the reason
// is that an epoch does not fence the case this relay exists for.
//
// Walk a power-off. West owns and dies. The survivors elect south and bump the
// hypothetical epoch to N+1. West boots. Two sub-cases, and only one of them is
// the interesting one:
//
// 1. **West rejoins raft and applies current state.** It reads an ownership
//    record naming south. It fences. A plain machine-name comparison already
//    decides this; the epoch adds nothing.
// 2. **West boots with stale raft state** — partitioned, or simply lagging
//    behind its own replay. Its applied state says `owner = west`, epoch N. It
//    has no way to know N+1 exists, *because that is what stale means*. An epoch
//    is an ordinal, and a node holding a stale ordinal believes it exactly as
//    confidently as it would believe a stale name.
//
// So the ordinal is not what makes a claim safe — **freshness** is, and
// freshness can only be measured on the holder's own monotonic clock against
// evidence it currently has contact with a quorum. That is a lease. The epoch is
// still the right primitive one layer down, on the *replica stream*, where a
// stale writer's frames must be rejected by a watermark sidecar that IS current
// (turso-backup's `StreamConfig::epoch`, R732-F2/R732-T3) — but the ticket is
// right that it does not follow that it fences serving, and it does not.
//
// # The safety inequality, which is the whole design
//
// Two independent clocks have to be ordered, or expiry races the fence and
// produces the two coordinators this is here to prevent:
//
// ```text
//   holder stops serving   <   cluster may elect a replacement
//   (self_fence_after)          (expire_after)
// ```
//
// [`FenceTiming`] derives both from one [`LivenessThresholds`] so the ordering
// is a property of the constructor rather than of two constants someone might
// tune independently, and
// `expiry_cannot_outrun_the_self_fence_at_any_preset` pins it.

use std::time::Duration;

use crate::cluster_policy::LivenessThresholds;

/// The two deadlines that order [`judge_self_fence`] against
/// [`owner_lease_expired`], derived together from one set of thresholds.
///
/// Scaled off `down_after` rather than fixed, for the same reason
/// [`HysteresisPolicy::from_thresholds`](crate::lease_detector::HysteresisPolicy::from_thresholds)
/// is: a WAN fleet and a LAN rig need channel-appropriate patience, and a
/// constant tuned for one is either twitchy or useless on the other.
///
/// # The multipliers, and why they are this large
///
/// The ticket's inherited `@yah:assumes` guesses that an appliance wants a
/// *shorter* dwell than a tenant, since the coordinator's blast radius is the
/// whole fleet. **Measured against the failure modes, that is backwards**, and
/// it is worth saying so where the numbers are:
///
/// - A tenant that fails over wrongly costs one needless move. An appliance that
///   fails over wrongly costs *two live coordinators*, which this module already
///   calls the failure worse than the outage.
/// - A shorter fence deadline does not shorten the outage on the path that
///   matters. On a genuine power-off the coordinator is gone at t=0 regardless
///   of what any deadline says; the deadline only governs how long a *survivor*
///   keeps serving. Buying failover speed with fence margin therefore spends the
///   one thing that prevents a split and gets nothing back.
///
/// So: 4× `down_after` to self-fence, 6× to expire. At the fleet preset
/// (`down_after` = 5 s) that is 20 s and 30 s; at the rig preset (1.5 s), 6 s and
/// 9 s. Twenty seconds is ~40 consecutive missed lease renewals at the fleet's
/// heartbeat pacing — a partition, not a blip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceTiming {
    /// **Holder side.** A node serving the appliance stops it once it has gone
    /// this long without confirming, from replicated state, that it is still the
    /// recorded owner.
    pub self_fence_after: Duration,
    /// **Cluster side.** The leader may treat the recorded owner as expired once
    /// the node-lease channel has been silent about it for this long.
    ///
    /// Strictly greater than [`Self::self_fence_after`], and that gap is the
    /// only thing standing between a partition and two coordinators.
    pub expire_after: Duration,
}

impl FenceTiming {
    /// Multiplier on `down_after` for the holder's self-fence deadline.
    const SELF_FENCE_HEARTBEATS: u32 = 4;
    /// Multiplier on `down_after` for the cluster's expiry deadline. Must
    /// exceed [`Self::SELF_FENCE_HEARTBEATS`]; the difference is the margin.
    const EXPIRE_HEARTBEATS: u32 = 6;

    pub const fn from_thresholds(thresholds: LivenessThresholds) -> Self {
        Self {
            self_fence_after: Duration::from_millis(
                thresholds.down_after.as_millis() as u64 * Self::SELF_FENCE_HEARTBEATS as u64,
            ),
            expire_after: Duration::from_millis(
                thresholds.down_after.as_millis() as u64 * Self::EXPIRE_HEARTBEATS as u64,
            ),
        }
    }

    /// The window between the holder having stopped and the cluster being
    /// allowed to start a replacement. Exposed so a test can assert it is
    /// positive rather than re-deriving the multipliers.
    pub fn fence_margin(&self) -> Duration {
        self.expire_after.saturating_sub(self.self_fence_after)
    }
}

/// **EXPIRE.** May the leader treat the recorded owner as gone?
///
/// `silence` is how long the node-lease channel
/// ([`LeaseFailureDetector::silence`](crate::lease_detector::LeaseFailureDetector::silence))
/// has gone without a renewal from that node. `None` — never heard from at all —
/// is deliberately **not** expiry: it is the shape of a leader that was elected
/// thirty seconds ago and has not yet received anyone's first renewal, and
/// reading it as death would make every leadership change expire every owner.
/// That is the same "absence of evidence is not evidence" rule
/// [`decide_owner`] holds for an unjudgeable owner, applied to the other channel.
///
/// # Raw silence, not the hysteresis verdict — and this corrects the ticket
///
/// The inherited assumption was that [`crate::lease_detector`] "only needs
/// wiring, not building". It needed one thing built: an accessor for the raw
/// elapsed silence. [`TransitionTracker`](crate::lease_detector::TransitionTracker)
/// debounces the channel down to a *boolean* `Confirmed::Down`, which is exactly
/// right for tenant placement — where the question is "should I act?" — and
/// throws away the one number this decision needs. The safety argument here is
/// an inequality between two elapsed times, so a verdict that has discarded the
/// elapsed time cannot make it. Hysteresis makes a decision **stable**; it does
/// not make it **safe**.
///
/// The debounced verdict is still what the answer is *expressed* as: a caller
/// projects a `true` here onto `liveness: Some(Confirmed::Down)` so
/// [`judge_appliance_candidate`] refuses it through the one readiness
/// vocabulary this crate has, rather than through a second one.
pub fn owner_lease_expired(silence: Option<Duration>, timing: FenceTiming) -> bool {
    silence.is_some_and(|s| s >= timing.expire_after)
}

/// Why a node must stop serving the appliance it is currently running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceReason {
    /// The replicated record names somebody else. The unambiguous case: the
    /// cluster moved on while this node was away, and this node is a second
    /// coordinator until it stops.
    ///
    /// This is what a power-cycled us-west-001 looks like the moment it can read
    /// raft again — and, on today's fleet, what a boot-persistent
    /// `systemctl enable headscale` produces at *every* subsequent boot.
    RecordNamesAnotherNode { owner: YubabaNodeId },
    /// This node cannot confirm it is still the owner and has not been able to
    /// for [`FenceTiming::self_fence_after`].
    ///
    /// The partition case, and the one an ownership *record* alone cannot
    /// answer: a node cut off from quorum reads its own stale applied state and
    /// finds its own name in it. The only sound response to "I cannot check" is
    /// to stop.
    ClaimUnconfirmed { unconfirmed_for: Duration },
}

impl FenceReason {
    /// Stable lowercase token for the operator-facing line, mirroring
    /// [`ApplianceIneligible::as_str`].
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RecordNamesAnotherNode { .. } => "record-names-another-node",
            Self::ClaimUnconfirmed { .. } => "claim-unconfirmed",
        }
    }
}

/// What a node running the appliance should do about it, judged **only** from
/// facts local to that node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfFence {
    /// Keep serving.
    Serve,
    /// Stop serving, now.
    Stop(FenceReason),
}

/// **FENCE.** Decide whether this node may go on serving the appliance.
///
/// Deliberately takes no candidate map, no leadership flag and no peer opinion:
/// a fence that needed the cluster's help would be useless in exactly the
/// situations that call for one. Every input is something the node can establish
/// about itself.
///
/// - `recorded` — who the node's own applied raft state says owns the appliance,
///   already resolved to a node id.
/// - `running_here` — whether the appliance is actually up on this node, from
///   its own supervisor. A node running nothing has nothing to fence, and
///   returning [`SelfFence::Serve`] for it keeps the `Stop` arm meaning "stop
///   something" rather than "stop nothing, loudly, forever".
/// - `unconfirmed_for` — how long since this node last *confirmed* the record
///   named it. `None` means it is confirmed right now.
///
/// # The two arms are ordered, and the order is not cosmetic
///
/// A positive record naming somebody else is checked first because it is
/// evidence, and it is available immediately; the lease is the fallback for when
/// no evidence can be obtained at all. Checking the lease first would let a node
/// that CAN read a record naming south keep serving for the whole fence window
/// just because its clock had recently been refreshed.
///
/// # The cost it charges, stated plainly: quorum loss now stops the coordinator
///
/// [`FenceReason::ClaimUnconfirmed`] cannot tell "I lost quorum and nobody else
/// has it" from "I lost quorum and the others have it". From the holder's side
/// those are the *same observation* — no leader, no confirmable record — and it
/// has to act on the worse one. So a cluster that loses a majority also loses
/// its coordinator [`FenceTiming::self_fence_after`] later, where before T7 it
/// would have kept serving.
///
/// That is a genuine availability cost and it is accepted deliberately. In the
/// case it costs (a real majority outage) no replacement can be elected either,
/// so the mesh is degraded whatever happens; in the case it buys (a partition
/// where the majority is alive elsewhere and elects a new owner) it is the only
/// thing preventing two coordinators. No refinement is available: in a
/// three-voter cluster there is no observation a lone node can make that
/// distinguishes the two.
///
/// # What this cannot fence, stated plainly
///
/// The fence is enforced *by yubaba*. A node whose yubaba does not start comes
/// up serving whatever `systemctl` starts for it, and nothing here runs to stop
/// it. That residual is why [`crate::leader`]'s start and stop paths both
/// `systemctl disable` unconditionally: the boot-persistent bit is removed on
/// every transition, so the only way to hold one is for an operator to set it by
/// hand — which is precisely the live hazard R858-T7's gotcha records on
/// us-west-001 and requires undone before the rehearsal.
pub fn judge_self_fence(
    recorded: Option<YubabaNodeId>,
    this_node: YubabaNodeId,
    running_here: bool,
    unconfirmed_for: Option<Duration>,
    timing: FenceTiming,
) -> SelfFence {
    if !running_here {
        return SelfFence::Serve;
    }
    if let Some(owner) = recorded {
        if owner != this_node {
            return SelfFence::Stop(FenceReason::RecordNamesAnotherNode { owner });
        }
    }
    match unconfirmed_for {
        Some(d) if d >= timing.self_fence_after => {
            SelfFence::Stop(FenceReason::ClaimUnconfirmed { unconfirmed_for: d })
        }
        _ => SelfFence::Serve,
    }
}

/// One node's deploy-failure history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FailureRecord {
    consecutive: u32,
    retry_after_unix: u64,
}

/// The failure ledger and round counter — the mutable half of an election.
///
/// Kept separate from [`decide_owner`] so the decision stays testable as
/// arithmetic, the same split [`crate::scheduler`] uses between
/// `decide_transfer` and its loop.
#[derive(Debug, Default)]
pub struct OwnerElection {
    ledger: BTreeMap<YubabaNodeId, FailureRecord>,
    round_attempts: usize,
    health: ApplianceHealth,
}

impl OwnerElection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Backoff expiry for `node`, if it has a recorded failure.
    pub fn backoff_until(&self, node: YubabaNodeId) -> Option<u64> {
        self.ledger.get(&node).map(|r| r.retry_after_unix)
    }

    /// Record that `node` failed to stand the appliance up.
    ///
    /// Doubles that node's backoff and burns one of this round's
    /// [`MAX_CANDIDATES_PER_ROUND`] attempts. Does **not** clear the ownership
    /// record — that is the caller's, and the caller's rule is that a failure
    /// claims nothing in the first place.
    pub fn record_failure(&mut self, node: YubabaNodeId, now_unix: u64, reason: impl Into<String>) {
        let consecutive = self
            .ledger
            .get(&node)
            .map_or(1, |r| r.consecutive.saturating_add(1));
        // 30 → 60 → 120 → 240 → 300 (capped). `min(4)` keeps the shift inside
        // u64 regardless of how long a node has been broken.
        let delay = BACKOFF_BASE_SECS
            .saturating_mul(1u64 << consecutive.saturating_sub(1).min(4))
            .min(BACKOFF_MAX_SECS);
        self.ledger.insert(
            node,
            FailureRecord {
                consecutive,
                retry_after_unix: now_unix.saturating_add(delay),
            },
        );
        self.round_attempts = self.round_attempts.saturating_add(1);
        self.set_health(ApplianceHealth::Unhealthy {
            reason: reason.into(),
        });
    }

    /// Record that `node` stood the appliance up. Clears its backoff and ends
    /// the round — the cluster has an owner, so the next failure starts from a
    /// fresh budget rather than inheriting an exhausted one.
    pub fn record_success(&mut self, node: YubabaNodeId) {
        self.ledger.remove(&node);
        self.round_attempts = 0;
        self.set_health(ApplianceHealth::Serving(node));
    }

    /// Whether this round has burned its [`MAX_CANDIDATES_PER_ROUND`] budget.
    pub fn round_exhausted(&self) -> bool {
        self.round_attempts >= MAX_CANDIDATES_PER_ROUND
    }

    /// Project `node`'s ledger entry onto an [`ApplianceCandidate`], so callers
    /// build candidates from raft state without reaching into the ledger.
    pub fn candidate(
        &self,
        node: YubabaNodeId,
        eligibility: NodeEligibility,
        capability: NativeExecCapability,
    ) -> ApplianceCandidate {
        ApplianceCandidate {
            node: eligibility,
            capability,
            backoff_until: self.backoff_until(node),
        }
    }

    pub fn health(&self) -> &ApplianceHealth {
        &self.health
    }

    /// Record that this node fenced itself off the appliance (R858-T7).
    ///
    /// Deliberately **not** a [`Self::record_failure`]: nothing was attempted
    /// and nothing failed, so there is nothing to back off and no round budget
    /// to burn. A node that fences itself on every tick of a long partition must
    /// not exhaust the election round it will need the moment the partition
    /// heals.
    ///
    /// The two reasons produce genuinely different verdicts, and collapsing them
    /// to one would make this channel useless in exactly one of the two:
    ///
    /// - [`FenceReason::RecordNamesAnotherNode`] is **not an unhealthy state.**
    ///   The cluster has a coordinator, this node knows which one, and it has
    ///   just correctly stopped pretending to be it. Recording
    ///   [`ApplianceHealth::Serving`] of the *real* owner is the accurate value,
    ///   and it is self-clearing: without it a node that fenced once for the
    ///   most ordinary reason there is would fail its healthcheck forever, since
    ///   `decide_owner`'s remote-`OwnerServing` arm never touches health.
    /// - [`FenceReason::ClaimUnconfirmed`] **is** unhealthy, and it is the one
    ///   an operator most needs to see: this node cannot reach a quorum, so it
    ///   cannot know who owns the appliance and has stopped serving on that
    ///   basis alone.
    pub fn record_fenced(&mut self, reason: &FenceReason) {
        let health = match reason {
            FenceReason::RecordNamesAnotherNode { owner } => ApplianceHealth::Serving(*owner),
            FenceReason::ClaimUnconfirmed { unconfirmed_for } => ApplianceHealth::Unhealthy {
                reason: format!(
                    "fenced: could not confirm this node still owns the appliance for {}s — \
                     stopped serving rather than risk a second coordinator",
                    unconfirmed_for.as_secs()
                ),
            },
        };
        self.set_health(health);
    }

    /// Record that nothing is eligible. Separate from [`Self::record_failure`]
    /// because no node attempted anything — there is nothing to back off.
    pub fn record_no_candidate(&mut self, refusals: impl Into<String>) {
        self.set_health(ApplianceHealth::Unhealthy {
            reason: format!(
                "no eligible candidate for the appliance: {}",
                refusals.into()
            ),
        });
    }

    fn set_health(&mut self, health: ApplianceHealth) {
        self.health = health.clone();
        publish_health(health);
    }
}

/// The last-published [`ApplianceHealth`], readable without holding the
/// watcher's state.
///
/// A process-level cell rather than a field on `ServerState` for the same
/// reason [`crate::litestream`]'s start/stop are free functions: the appliance
/// is a process singleton, and its health has exactly one value per node. This
/// is the read side a healthcheck or `yah mesh status` consumes — wiring that
/// HTTP surface is R858-T7/T8's, but the value has to exist before it can be
/// published, and its absence is what let R858 run for 37 hours.
fn health_cell() -> &'static Mutex<ApplianceHealth> {
    static CELL: OnceLock<Mutex<ApplianceHealth>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(ApplianceHealth::Vacant))
}

fn publish_health(health: ApplianceHealth) {
    if let Ok(mut cell) = health_cell().lock() {
        *cell = health;
    }
}

/// This node's current appliance-availability verdict.
pub fn current_health() -> ApplianceHealth {
    health_cell()
        .lock()
        .map(|c| c.clone())
        .unwrap_or(ApplianceHealth::Vacant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease_detector::Confirmed;

    /// A node the cluster has confirmed up and which admits work — the shape
    /// `scheduler::tests::node` builds, narrowed to what the appliance reads.
    fn live() -> NodeEligibility {
        NodeEligibility {
            liveness: Some(Confirmed::Up),
            raft_peer_healthy: true,
            region: None,
            admits: true,
            warm_for_tenant: false,
            streamer_watermark_age: None,
        }
    }

    fn dead() -> NodeEligibility {
        NodeEligibility {
            liveness: Some(Confirmed::Down),
            ..live()
        }
    }

    fn candidate(node: NodeEligibility) -> ApplianceCandidate {
        ApplianceCandidate {
            node,
            capability: NativeExecCapability::Unknown,
            backoff_until: None,
        }
    }

    /// The whole point of the ticket: a raft leadership change is not an input
    /// to this function, so it cannot move a healthy owner.
    #[test]
    fn a_serving_owner_does_not_move_however_the_candidates_rank() {
        // Node 3 owns and serves; nodes 1 and 2 are live, admitting, and sort
        // ahead of it. Under the old rule (owner == leader) a transfer to 1
        // would have moved the appliance. Here nothing moves.
        let candidates = BTreeMap::from([
            (1, candidate(live())),
            (2, candidate(live())),
            (3, candidate(live())),
        ]);
        let owner = Some(OwnerStatus {
            node: 3,
            serving: true,
        });
        assert_eq!(
            decide_owner(owner, &candidates, 1_000),
            OwnershipDecision::OwnerServing(3)
        );
    }

    #[test]
    fn a_recorded_owner_that_is_not_serving_is_re_elected_away_from() {
        let candidates = BTreeMap::from([(1, candidate(live())), (3, candidate(live()))]);
        let owner = Some(OwnerStatus {
            node: 3,
            serving: false,
        });
        assert_eq!(
            decide_owner(owner, &candidates, 1_000),
            OwnershipDecision::ElectTo(1)
        );
    }

    /// Kill the node — do not mock a refusal. The owner's liveness is what a
    /// power-off actually changes, and that alone must move ownership.
    #[test]
    fn killing_the_serving_owner_moves_ownership_to_the_next_eligible_node() {
        let mut candidates = BTreeMap::from([(1, candidate(live())), (2, candidate(live()))]);
        let owner = Some(OwnerStatus {
            node: 1,
            serving: true,
        });
        assert_eq!(
            decide_owner(owner, &candidates, 1_000),
            OwnershipDecision::OwnerServing(1)
        );

        // Node 1 loses power. Its lease stops renewing and the hysteresis
        // tracker commits Down; nothing else about the cluster changes.
        candidates.insert(1, candidate(dead()));
        assert_eq!(
            decide_owner(owner, &candidates, 1_000),
            OwnershipDecision::ElectTo(2)
        );
    }

    #[test]
    fn a_vacant_record_elects_the_lowest_eligible_node() {
        let candidates = BTreeMap::from([
            (2, candidate(dead())),
            (5, candidate(live())),
            (9, candidate(live())),
        ]);
        assert_eq!(
            decide_owner(None, &candidates, 1_000),
            OwnershipDecision::ElectTo(5)
        );
    }

    #[test]
    fn no_live_node_surfaces_no_eligible_candidate_rather_than_electing_a_dead_one() {
        let candidates = BTreeMap::from([(1, candidate(dead())), (2, candidate(dead()))]);
        assert_eq!(
            decide_owner(None, &candidates, 1_000),
            OwnershipDecision::NoEligibleCandidate
        );
    }

    /// R858-T4's seam, from both directions.
    #[test]
    fn an_absent_native_exec_capability_refuses_and_unknown_admits() {
        let mut absent = candidate(live());
        absent.capability = NativeExecCapability::Absent;
        assert_eq!(
            judge_appliance_candidate(&absent, 0),
            Err(ApplianceIneligible::MissingNativeExec)
        );

        let mut present = candidate(live());
        present.capability = NativeExecCapability::Present;
        assert_eq!(judge_appliance_candidate(&present, 0), Ok(()));

        // The placeholder every live call site passes until T4 lands.
        assert_eq!(judge_appliance_candidate(&candidate(live()), 0), Ok(()));
        assert_eq!(
            NativeExecCapability::default(),
            NativeExecCapability::Unknown
        );
    }

    /// Readiness is judged before capability, so an unreachable node reports
    /// that rather than a capability verdict about a box nobody can talk to.
    #[test]
    fn readiness_is_reported_before_capability() {
        let mut cand = candidate(dead());
        cand.capability = NativeExecCapability::Absent;
        assert_eq!(
            judge_appliance_candidate(&cand, 0),
            Err(ApplianceIneligible::NotReady(NotReady::NotLive))
        );
    }

    /// The ticket's headline sequence, driven end to end through the ledger: a
    /// real deploy failure on the elected owner, not a mocked refusal arm.
    #[test]
    fn a_deploy_failure_on_the_elected_owner_moves_ownership_to_the_next_candidate() {
        let mut election = OwnerElection::new();
        let now = 1_000;
        let fleet = |e: &OwnerElection| -> BTreeMap<YubabaNodeId, ApplianceCandidate> {
            (1..=3)
                .map(|id| (id, e.candidate(id, live(), NativeExecCapability::Unknown)))
                .collect()
        };

        // Vacant record: node 1 is elected.
        assert_eq!(
            decide_owner(None, &fleet(&election), now),
            OwnershipDecision::ElectTo(1)
        );

        // Node 1 tries and cannot — this is us-south-001 on 2026-09-03: kamaji
        // refuses for want of a native backend and the systemd unit is absent.
        // It claims nothing; the record stays vacant.
        election.record_failure(
            1,
            now,
            "no start path succeeded (kamaji: no native backend)",
        );
        assert!(election.health().is_unhealthy());

        // The re-election skips it and lands on node 2. This is the behaviour
        // whose absence produced the outage: exactly one node ever tried.
        assert_eq!(
            decide_owner(None, &fleet(&election), now),
            OwnershipDecision::ElectTo(2)
        );

        // Node 2 succeeds. The cluster is Serving, and now sticky.
        election.record_success(2);
        assert_eq!(election.health(), &ApplianceHealth::Serving(2));
        let owner = Some(OwnerStatus {
            node: 2,
            serving: true,
        });
        assert_eq!(
            decide_owner(owner, &fleet(&election), now),
            OwnershipDecision::OwnerServing(2)
        );
    }

    /// The end of a round: everything that could run it has failed, so the
    /// cluster reports that instead of spinning. This is the arm R858 needed
    /// and did not have.
    #[test]
    fn a_fleet_where_every_candidate_fails_ends_unhealthy_rather_than_looping() {
        let mut election = OwnerElection::new();
        let now = 1_000;
        for node in 1..=3 {
            let candidates: BTreeMap<_, _> = (1..=3)
                .map(|id| {
                    (
                        id as YubabaNodeId,
                        election.candidate(id, live(), NativeExecCapability::Unknown),
                    )
                })
                .collect();
            assert_eq!(
                decide_owner(None, &candidates, now),
                OwnershipDecision::ElectTo(node),
                "round should walk to node {node}"
            );
            election.record_failure(node, now, "no native backend");
        }

        assert!(election.round_exhausted());
        let candidates: BTreeMap<_, _> = (1..=3)
            .map(|id| {
                (
                    id as YubabaNodeId,
                    election.candidate(id, live(), NativeExecCapability::Unknown),
                )
            })
            .collect();
        assert_eq!(
            decide_owner(None, &candidates, now),
            OwnershipDecision::NoEligibleCandidate
        );
        assert!(election.health().is_unhealthy());

        // And it recovers on its own once the backoffs expire — the bound stops
        // the loop, it does not wedge the cluster until an operator intervenes.
        let candidates: BTreeMap<_, _> = (1..=3)
            .map(|id| {
                (
                    id as YubabaNodeId,
                    election.candidate(id, live(), NativeExecCapability::Unknown),
                )
            })
            .collect();
        assert_eq!(
            decide_owner(None, &candidates, now + BACKOFF_MAX_SECS),
            OwnershipDecision::ElectTo(1)
        );
    }

    // ── Flapping bounds ───────────────────────────────────────────────────────

    #[test]
    fn a_node_that_just_failed_is_not_immediately_re_elected() {
        let mut election = OwnerElection::new();
        let now = 1_000;
        election.record_failure(1, now, "kamaji refused the appliance");

        let candidates = BTreeMap::from([
            (
                1,
                election.candidate(1, live(), NativeExecCapability::Unknown),
            ),
            (
                2,
                election.candidate(2, live(), NativeExecCapability::Unknown),
            ),
        ]);
        // Node 1 sorts first and is otherwise perfectly eligible. The backoff
        // is the only thing keeping the appliance from flapping back onto it.
        assert_eq!(
            decide_owner(None, &candidates, now + 1),
            OwnershipDecision::ElectTo(2)
        );
        assert_eq!(
            judge_appliance_candidate(&candidates[&1], now + 1),
            Err(ApplianceIneligible::InFailureBackoff {
                until_unix: now + BACKOFF_BASE_SECS
            })
        );
    }

    #[test]
    fn the_backoff_expires_so_a_fixed_node_becomes_a_candidate_again() {
        let mut election = OwnerElection::new();
        let now = 1_000;
        election.record_failure(1, now, "kamaji refused the appliance");
        let cand = election.candidate(1, live(), NativeExecCapability::Unknown);

        assert!(judge_appliance_candidate(&cand, now + BACKOFF_BASE_SECS - 1).is_err());
        assert_eq!(
            judge_appliance_candidate(&cand, now + BACKOFF_BASE_SECS),
            Ok(())
        );
    }

    #[test]
    fn consecutive_failures_double_the_backoff_up_to_the_cap() {
        let mut election = OwnerElection::new();
        let expected = [
            BACKOFF_BASE_SECS,
            BACKOFF_BASE_SECS * 2,
            BACKOFF_BASE_SECS * 4,
            BACKOFF_BASE_SECS * 8,
            BACKOFF_MAX_SECS,
            BACKOFF_MAX_SECS,
        ];
        for (i, want) in expected.iter().enumerate() {
            let now = 1_000 + i as u64;
            election.record_failure(1, now, "still refusing");
            assert_eq!(
                election.backoff_until(1),
                Some(now + want),
                "failure #{} should back off {want}s",
                i + 1
            );
        }
    }

    #[test]
    fn a_success_clears_that_nodes_backoff_and_ends_the_round() {
        let mut election = OwnerElection::new();
        election.record_failure(1, 1_000, "transient");
        election.record_failure(2, 1_000, "transient");
        assert!(!election.round_exhausted());

        election.record_success(2);
        assert_eq!(election.backoff_until(2), None);
        assert!(!election.round_exhausted());
        assert_eq!(election.health(), &ApplianceHealth::Serving(2));
        // Node 1's ledger entry survives — only the node that succeeded is
        // cleared, so a still-broken node does not get a free pass.
        assert!(election.backoff_until(1).is_some());
    }

    #[test]
    fn a_round_is_bounded_at_three_attempts() {
        let mut election = OwnerElection::new();
        for node in 1..=MAX_CANDIDATES_PER_ROUND as YubabaNodeId {
            assert!(!election.round_exhausted());
            election.record_failure(node, 1_000, "no native backend");
        }
        assert!(election.round_exhausted());
    }

    #[test]
    fn decide_owner_never_considers_more_than_the_round_bound() {
        // Ten live nodes; the bound must not turn into "scan the whole fleet".
        let candidates: BTreeMap<_, _> = (1..=10)
            .map(|id| (id as YubabaNodeId, candidate(live())))
            .collect();
        assert_eq!(
            decide_owner(None, &candidates, 0),
            OwnershipDecision::ElectTo(1)
        );
        assert_eq!(MAX_CANDIDATES_PER_ROUND, 3);
    }

    // ── Health ────────────────────────────────────────────────────────────────

    #[test]
    fn a_deploy_failure_makes_the_cluster_unhealthy_rather_than_leaving_it_vacant() {
        let mut election = OwnerElection::new();
        assert_eq!(election.health(), &ApplianceHealth::Vacant);
        assert!(!election.health().is_unhealthy());

        election.record_failure(1, 1_000, "kamaji refused: no native backend");
        assert!(election.health().is_unhealthy());
        match election.health() {
            ApplianceHealth::Unhealthy { reason } => {
                assert!(reason.contains("no native backend"), "reason: {reason}")
            }
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[test]
    fn no_eligible_candidate_is_unhealthy_not_merely_vacant() {
        let mut election = OwnerElection::new();
        election.record_no_candidate("1=not-live 2=not-live");
        assert!(election.health().is_unhealthy());
    }

    // ── Restart safety: the record leads, and silence moves nothing ───────────

    /// A node that cannot judge the owner must not elect itself.
    ///
    /// This is `leader.rs`'s actual candidate set — one entry, itself — and it
    /// is what every non-owner node in the fleet sees. Under the old
    /// `is_some_and` rule the absent owner read as ineligible and node 2 took
    /// the appliance, which is a second coordinator.
    #[test]
    fn an_owner_absent_from_the_candidate_map_is_unjudged_and_keeps_the_appliance() {
        let candidates = BTreeMap::from([(2, candidate(live()))]);
        let owner = Some(OwnerStatus {
            node: 1,
            serving: true,
        });
        assert_eq!(
            decide_owner(owner, &candidates, 1_000),
            OwnershipDecision::OwnerServing(1)
        );
    }

    /// The distinction that makes the rule above safe rather than merely inert:
    /// silence leaves the owner alone, but *evidence* still moves it. Same
    /// owner, same candidate map shape — the only difference is that node 1 is
    /// present and judged dead.
    #[test]
    fn positive_evidence_still_moves_ownership_off_a_dead_owner() {
        let candidates = BTreeMap::from([(1, candidate(dead())), (2, candidate(live()))]);
        let owner = Some(OwnerStatus {
            node: 1,
            serving: true,
        });
        assert_eq!(
            decide_owner(owner, &candidates, 1_000),
            OwnershipDecision::ElectTo(2)
        );
    }

    /// The restart, as arithmetic: a fresh `OwnerElection` (empty health, which
    /// is all a restarted process has) plus the replicated record must still
    /// conclude "nothing moves".
    #[test]
    fn a_restarted_owner_reading_its_own_record_does_not_restart_the_appliance() {
        let election = OwnerElection::new();
        assert_eq!(election.health(), &ApplianceHealth::Vacant);

        // The record survived the restart and names this node; its supervisor
        // confirms the appliance is still running.
        let owner = owner_status(Some(1), 1, true, election.health());
        assert_eq!(
            owner,
            Some(OwnerStatus {
                node: 1,
                serving: true
            })
        );

        let candidates = BTreeMap::from([(1, candidate(live()))]);
        assert_eq!(
            decide_owner(owner, &candidates, 1_000),
            OwnershipDecision::OwnerServing(1)
        );
    }

    /// The same restart on a node that is *not* the owner: it may become raft
    /// leader at any moment, and that must not be a reason to take the
    /// appliance. This is the 2026-09-03 transfer, replayed against the fix.
    #[test]
    fn a_new_raft_leader_does_not_take_the_appliance_from_the_recorded_owner() {
        let election = OwnerElection::new();
        let owner = owner_status(Some(1), 2, false, election.health());
        assert_eq!(
            owner,
            Some(OwnerStatus {
                node: 1,
                serving: true
            })
        );

        // Node 2's candidate set is itself alone — it cannot judge node 1.
        let candidates = BTreeMap::from([(2, candidate(live()))]);
        assert_eq!(
            decide_owner(owner, &candidates, 1_000),
            OwnershipDecision::OwnerServing(1)
        );
    }

    /// Stickiness must not become a way to strand a stale claim. A record
    /// naming this node over a supervisor that is not running the appliance is
    /// what a crash leaves behind, and it has to re-elect — here, back onto
    /// this same node, which starts it.
    #[test]
    fn a_record_naming_this_node_over_a_stopped_appliance_re_elects() {
        let election = OwnerElection::new();
        let owner = owner_status(Some(1), 1, false, election.health());
        assert_eq!(
            owner,
            Some(OwnerStatus {
                node: 1,
                serving: false
            })
        );

        let candidates = BTreeMap::from([(1, candidate(live()))]);
        assert_eq!(
            decide_owner(owner, &candidates, 1_000),
            OwnershipDecision::ElectTo(1)
        );
    }

    /// No replicated record (a cluster that has never elected, or a pre-R859-F2
    /// peer whose member row carries no machine name) degrades to this
    /// process's own health rather than to a wrong answer.
    #[test]
    fn without_a_record_the_local_health_is_the_fallback() {
        assert_eq!(
            owner_status(None, 1, true, &ApplianceHealth::Vacant),
            None,
            "a vacant cluster has no owner to be sticky about"
        );
        assert_eq!(
            owner_status(None, 1, true, &ApplianceHealth::Serving(1)),
            Some(OwnerStatus {
                node: 1,
                serving: true
            })
        );
        assert_eq!(
            owner_status(
                None,
                1,
                true,
                &ApplianceHealth::Unhealthy {
                    reason: "kamaji refused".into()
                }
            ),
            None
        );
    }

    // ── R858-T7: expiry and fencing ─────────────────────────────────────────

    use crate::cluster_policy::ClusterPolicy;

    fn fleet_timing() -> FenceTiming {
        FenceTiming::from_thresholds(ClusterPolicy::fleet().liveness_thresholds())
    }

    /// **The safety property of this whole ticket, in one assertion.**
    ///
    /// Expiry and fencing are two clocks on two channels. If the cluster is
    /// allowed to elect a replacement before the old holder has stopped, the
    /// mechanism built to prevent two coordinators produces two coordinators —
    /// on a schedule, reliably, every partition.
    ///
    /// Asserted across every preset rather than for one, because the durations
    /// are derived from `LivenessThresholds` and a future preset is exactly the
    /// thing that could silently invert them.
    #[test]
    fn expiry_cannot_outrun_the_self_fence_at_any_preset() {
        for (name, policy) in [("fleet", ClusterPolicy::fleet()), ("rig", ClusterPolicy::rig())] {
            let t = FenceTiming::from_thresholds(policy.liveness_thresholds());
            assert!(
                t.expire_after > t.self_fence_after,
                "{name}: a cluster that expires an owner at {:?} while that owner keeps serving \
                 until {:?} has two coordinators for the difference",
                t.expire_after,
                t.self_fence_after
            );
            assert!(
                !t.fence_margin().is_zero(),
                "{name}: zero margin leaves the ordering to scheduling luck"
            );
        }
    }

    /// The multipliers are also asserted concretely, so a change to them is a
    /// change to a number a reader can check against the doc comment rather
    /// than an invisible re-derivation.
    #[test]
    fn the_fleet_preset_fences_at_twenty_seconds_and_expires_at_thirty() {
        let t = fleet_timing();
        assert_eq!(t.self_fence_after, Duration::from_secs(20));
        assert_eq!(t.expire_after, Duration::from_secs(30));
        assert_eq!(t.fence_margin(), Duration::from_secs(10));
    }

    /// The resurrection case: power comes back, the cluster has moved on, and
    /// this node is serving a coordinator it no longer owns.
    #[test]
    fn a_record_naming_another_node_fences_a_running_appliance() {
        assert_eq!(
            judge_self_fence(Some(2), 1, true, None, fleet_timing()),
            SelfFence::Stop(FenceReason::RecordNamesAnotherNode { owner: 2 })
        );
    }

    /// …and it fences even though this node's ownership clock was refreshed a
    /// moment ago. Positive evidence outranks a fresh lease; checking the lease
    /// first would give a node that can plainly read "south owns it" a full
    /// fence window of serving anyway.
    #[test]
    fn a_record_naming_another_node_fences_regardless_of_the_lease_clock() {
        assert_eq!(
            judge_self_fence(Some(2), 1, true, Some(Duration::ZERO), fleet_timing()),
            SelfFence::Stop(FenceReason::RecordNamesAnotherNode { owner: 2 })
        );
    }

    /// A node running nothing has nothing to fence. Without this the `Stop` arm
    /// would fire on every tick of every idle follower and mean nothing.
    #[test]
    fn a_node_running_nothing_is_never_fenced() {
        let t = fleet_timing();
        assert_eq!(judge_self_fence(Some(2), 1, false, None, t), SelfFence::Serve);
        assert_eq!(
            judge_self_fence(None, 1, false, Some(Duration::from_secs(3600)), t),
            SelfFence::Serve
        );
    }

    /// The confirmed owner keeps serving — the common case, and the one a fence
    /// must not touch. `None` means "confirmed right now".
    #[test]
    fn a_confirmed_owner_is_not_fenced() {
        assert_eq!(
            judge_self_fence(Some(1), 1, true, None, fleet_timing()),
            SelfFence::Serve
        );
    }

    /// The partition case. This node reads its own name out of its own applied
    /// state and is *wrong*, because that state is stale — so the fence cannot
    /// be a record comparison here. It is the elapsed time since the record
    /// could last be believed.
    #[test]
    fn an_unconfirmable_claim_fences_only_after_the_lease_deadline() {
        let t = fleet_timing();
        // Still inside the window: a blip must not take the coordinator down.
        assert_eq!(
            judge_self_fence(
                Some(1),
                1,
                true,
                Some(t.self_fence_after - Duration::from_millis(1)),
                t
            ),
            SelfFence::Serve
        );
        // At the deadline it stops.
        assert_eq!(
            judge_self_fence(Some(1), 1, true, Some(t.self_fence_after), t),
            SelfFence::Stop(FenceReason::ClaimUnconfirmed {
                unconfirmed_for: t.self_fence_after
            })
        );
    }

    /// A node with **no** record at all and no way to get one is fenced by the
    /// same clock. This is the shape a resurrected node hits when the cluster
    /// cleared the record (`ClearIngressOwner`) or when it cannot reach quorum
    /// to read one — and "I do not know who owns this" is never grounds to keep
    /// serving it.
    #[test]
    fn an_absent_record_does_not_license_serving_past_the_deadline() {
        let t = fleet_timing();
        assert_eq!(
            judge_self_fence(None, 1, true, Some(t.self_fence_after), t),
            SelfFence::Stop(FenceReason::ClaimUnconfirmed {
                unconfirmed_for: t.self_fence_after
            })
        );
    }

    /// Never having heard from a node is not evidence it died — it is what a
    /// leader elected ten seconds ago sees about everybody. Reading it as
    /// expiry would expire every owner on every leadership change, which is the
    /// 2026-09-03 outage rebuilt out of its own fix.
    #[test]
    fn never_having_heard_from_a_node_is_not_expiry() {
        assert!(!owner_lease_expired(None, fleet_timing()));
    }

    #[test]
    fn silence_shorter_than_the_deadline_is_not_expiry() {
        let t = fleet_timing();
        assert!(!owner_lease_expired(
            Some(t.expire_after - Duration::from_millis(1)),
            t
        ));
        assert!(owner_lease_expired(Some(t.expire_after), t));
    }

    /// The composed claim, spelled out as an ordering over one timeline rather
    /// than left implicit in two constants: at every instant the cluster is
    /// permitted to expire the owner, that owner has already fenced itself.
    #[test]
    fn at_every_instant_expiry_is_permitted_the_holder_has_already_stopped() {
        let t = fleet_timing();
        for secs in 0..120u64 {
            let elapsed = Duration::from_secs(secs);
            if owner_lease_expired(Some(elapsed), t) {
                assert_eq!(
                    judge_self_fence(Some(1), 1, true, Some(elapsed), t),
                    SelfFence::Stop(FenceReason::ClaimUnconfirmed {
                        unconfirmed_for: elapsed
                    }),
                    "at {secs}s the cluster may replace the owner but the owner is still serving"
                );
            }
        }
    }

    /// Fencing because the cluster moved on is a *correct* outcome, so it must
    /// not leave this node permanently failing its healthcheck. The remote
    /// `OwnerServing` arm never writes health, so if this recorded `Unhealthy`
    /// nothing would ever clear it.
    #[test]
    fn fencing_to_a_known_owner_reports_that_owner_as_serving_not_unhealthy() {
        let mut e = OwnerElection::new();
        e.record_fenced(&FenceReason::RecordNamesAnotherNode { owner: 2 });
        assert_eq!(e.health(), &ApplianceHealth::Serving(2));
        assert!(!e.health().is_unhealthy());
    }

    /// Fencing because this node cannot reach a quorum IS unhealthy, and it is
    /// the case an operator most needs surfaced.
    #[test]
    fn fencing_on_an_unconfirmable_claim_is_unhealthy() {
        let mut e = OwnerElection::new();
        e.record_fenced(&FenceReason::ClaimUnconfirmed {
            unconfirmed_for: Duration::from_secs(20),
        });
        assert!(e.health().is_unhealthy());
    }

    /// A fence is not a deploy attempt: it must not burn the round budget the
    /// cluster needs the moment the partition heals, and it must not put this
    /// node into a backoff it never earned.
    #[test]
    fn fencing_burns_no_election_round_and_no_backoff() {
        let mut e = OwnerElection::new();
        for _ in 0..10 {
            e.record_fenced(&FenceReason::ClaimUnconfirmed {
                unconfirmed_for: Duration::from_secs(30),
            });
        }
        assert!(!e.round_exhausted());
        assert_eq!(e.backoff_until(1), None);
    }

    /// The expiry verdict has to speak `decide_owner`'s language, or it changes
    /// nothing. A confirmed-down owner projected onto the candidate map is
    /// exactly the "positive evidence" arm that re-elects.
    #[test]
    fn an_expired_owner_projected_as_down_re_elects_away_from_itself() {
        let owner = Some(OwnerStatus {
            node: 2,
            serving: true,
        });
        // Without the projection the owner is unjudgeable and nothing moves —
        // this is the pre-T7 behaviour, asserted so the next line is not
        // mistaken for something `decide_owner` did on its own.
        let without = BTreeMap::from([(1, candidate(live()))]);
        assert_eq!(
            decide_owner(owner, &without, 0),
            OwnershipDecision::OwnerServing(2)
        );

        let mut with = without.clone();
        with.insert(2, candidate(dead()));
        assert_eq!(decide_owner(owner, &with, 0), OwnershipDecision::ElectTo(1));
    }
}
