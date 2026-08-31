//! Leader-resident tenant placement scheduler (R737-F3, W246 §"Scheduler").
//!
//! The missing middle W246 names: yubaba has a real raft and a real leadership
//! watcher, but nothing that notices a tenant's owner died and moves it onto
//! live capacity. This is that loop.
//!
//! # Shape: a second `leader_pin`-style loop, not a new pattern
//!
//! Same structure as [`crate::leader_pin`]: a pure `decide`-style function
//! (here, [`decide_transfer`]) tested as arithmetic, run inside a paced loop
//! that is [`spawn`]ed **unconditionally on every node**. A follower's tick
//! finds it is not the leader and does nothing — see [`run`] — so there is no
//! start/stop edge to get wrong across an election, exactly the property
//! `leader_pin`'s module doc argues for.
//!
//! # What "rebuild from the committed log on leader change" means here
//!
//! This loop carries **no placement state of its own** across ticks. Every
//! tick re-reads `YubabaStateMachine::tenants`/`tenant_placement`/`members` —
//! the committed log, replayed — and computes a decision fresh. A new leader
//! that has never run this loop before starts with an empty
//! [`crate::lease_detector::TransitionTracker`] and reaches the exact same
//! conclusions its predecessor would have, one tick later. There is nothing
//! to "resume": the state that matters is already in the state machine.
//!
//! **Idempotency is the state machine's, not this loop's.** A `TransferTenant`
//! is CAS-guarded on `from_epoch` (R732-F1). This loop reads the *current*
//! epoch fresh every tick rather than remembering one, so a mid-decision
//! leader failover cannot double-place: the surviving leader (old or new)
//! either observes its own already-committed transfer (owner is no longer the
//! dead node, so the tenant no longer matches the trigger and nothing is
//! sent) or re-derives the same CAS write from the same live state. No
//! decision-log, no dedup table — the epoch already *is* one.
//!
//! # What is deliberately NOT persisted to raft: liveness itself
//!
//! A tempting alternative reading of "rebuild from the committed log" is that
//! a confirmed node-down fact should itself be a raft entry, so a new leader
//! does not have to re-earn [`crate::lease_detector::HysteresisPolicy`]'s confirm
//! dwell from zero. This was considered and rejected for this ticket:
//!
//! - W253 §7 and [`crate::lease_detector`]'s module doc are explicit that
//!   renewals — and by extension the liveness judgement built on them — stay
//!   off the raft log; only R737-F2's *own* channel separation makes that
//!   evidence trustworthy for placement in the first place. Writing "node X
//!   is down" into raft the moment one leader's tracker confirms it would
//!   re-couple the two channels through the back door.
//! - A brand-new leader independently re-confirming liveness rather than
//!   trusting a predecessor's possibly-stale judgement is the more
//!   conservative failure mode, and the cost is bounded and one-time: at most
//!   one extra [`crate::lease_detector::HysteresisPolicy::confirm_down_after`] dwell,
//!   paid once per leadership change, never compounding.
//!
//! So "rebuild from the committed log" is scoped to *placement* (`tenants` /
//! `placement`, both raft state), not to *liveness* (deliberately raft-free).
//! If that dwell-on-failover cost ever proves too slow in practice, the fix is
//! a dedicated, narrow raft entry for confirmed transitions — not folding
//! liveness into the existing tenant/member state.
//!
//! # Readiness is [`crate::lease_detector::judge_readiness`], not a second opinion
//!
//! W253 §7 lists four gates a node must pass before it may *own* a tenant —
//! streamer caught up within bound, tenant hydrated, within headroom, raft peer
//! healthy — and R737-F2 already expresses them as one pure function. This
//! loop does **not** re-derive them: [`judge_candidate`] projects a
//! [`NodeEligibility`] onto [`crate::lease_detector::ReadinessInputs`] and defers, so
//! the gate set cannot drift between the module that defines it and the module
//! that acts on it.
//!
//! One of the four inputs still has no *default* source, carried explicitly
//! rather than silently dropped:
//!
//! - **`hydrated`** is derived, not measured: for [`SlaTier::ColdHydrate`] the
//!   hydrate *is* part of the transfer, so demanding it beforehand would
//!   deadlock every cold placement; for [`SlaTier::WarmReplica`] the node must
//!   already hold the tenant, which is exactly what
//!   [`NodeEligibility::warm_for_tenant`] means. So `hydrated` is
//!   `tier != WarmReplica || warm_for_tenant` — one rule, not a warm-tier
//!   filter sitting next to a hydration flag saying the same thing twice.
//!
//! `streamer_watermark_age` / `rpo_bound` (R782) are plumbed as of this
//! ticket: `rpo_bound` reads straight off `TenantPlacement`, and
//! `streamer_watermark_age` off `rpo_registry` — but both still read as
//! `None` for the common case today, and that is not a bug to chase. A
//! tenant's `TenantPlacement.rpo_bound` is `None` until an operator declares
//! one (the gate stays vacuous, exactly as before this ticket), and even once
//! declared, `rpo_registry` only ever holds a fresh value for a node whose
//! `tenant-streamer` is *actively streaming that tenant* — today that is only
//! ever the current owner, who is excluded from `candidates` by construction.
//! So a bound tenant's failover candidates read `None` until W248's warm
//! fan-out gives some other node a reason to be streaming it too, and fail
//! `StreamerBehindBound` until then — the fail-closed behavior
//! [`judge_readiness`]'s own doc calls for, not a wiring gap.
//!
//! ## Why the raft-heartbeat channel may only *veto*
//!
//! `raft_peer_healthy` is sourced from
//! [`RaftHeartbeatDetector`](crate::failure_detector::RaftHeartbeatDetector) —
//! the very evidence channel R737-F2 exists to keep *out* of placement. That is
//! not a contradiction: W253 §7 makes "its Raft peer is healthy/connected" its
//! own gate, and that is a raft question. The separation is preserved by
//! direction. This channel can only ever *refuse* a candidate — an explicit
//! `Down` observation — and can never be the reason one is accepted. `Suspect`,
//! `Unknown`, a node absent from the report, and no detector at all all leave
//! the gate open, per the [`FailureDetector`](crate::failure_detector::FailureDetector)
//! trait's own "an empty report never means every node is down" rule. So a
//! placement still rests entirely on the lease channel; the raft channel only
//! catches the gray failure where a node renews its HTTP lease happily while
//! its consensus link is dead, which would hand a tenant to an owner that
//! cannot participate in the log that fences it.
//!
//! # What "already warm" cannot check yet
//!
//! [`NodeEligibility::warm_for_tenant`] exists because [`SlaTier::WarmReplica`]
//! tenants must only fail over onto a node already streaming them (W246 §
//! "Proposed design", W248's territory). Nothing in this codebase yet records
//! *which* nodes hold a warm replica of a tenant — that map is W248's WAL
//! streamer/applier fan-out, explicitly out of this relay's scope. Until it
//! exists, [`run`] passes `warm_for_tenant: false` for every candidate, which
//! means a `WarmReplica` tenant's dead owner currently produces
//! [`PlacementDecision::NoEligibleCandidate`] (with a
//! [`NotReady::NotHydrated`] refusal per candidate) rather than a wrong or a
//! guessed placement — the same pessimistic-default philosophy `SlaTier`'s own
//! doc states for an *undeclared* tier, applied here to an *unmeasurable* one.

use std::collections::BTreeMap;
use std::time::Duration;

use tracing::{info, warn};

use crate::cluster_policy::RaftTiming;
use crate::lease_detector::{
    judge_readiness, Confirmed, HysteresisPolicy, LeaseFailureDetector, NotReady,
    ReadinessInputs, TransitionTracker,
};
use crate::raft::{SlaTier, TenantDemand, YubabaNodeId, YubabaRaft, YubabaRequest, YubabaStateMachine};

/// Lease TTL requested on the tenant this loop just moved.
///
/// Mirrors `tenant_streamer::config::DEFAULT_LEASE_SECS` by convention, not by
/// a shared constant — this crate does not take a data-plane dependency on
/// `tenant_streamer` (see `lease_detector`'s module doc for the same rule
/// stated for the `ReadinessInputs` fields). Long relative to the streamer's
/// own renewal cadence for the same reason the streamer's default is: the
/// lease is a liveness *hint* bounding when a further takeover is permitted,
/// never the safety property (the epoch is), so a short value buys nothing but
/// spurious churn.
const TRANSFER_LEASE_SECS: u64 = 300;

/// How this loop is paced.
///
/// Unlike [`crate::leader_pin::PinConfig`], which is deliberately *slower*
/// than an election to avoid fighting one, this loop's anti-churn property
/// comes from [`HysteresisPolicy`]'s confirm dwell, not from its own pacing —
/// a dead owner's tenants should be re-placed promptly once R737-F2 has
/// actually confirmed the owner down. So `evaluate_every` tracks the raft
/// heartbeat instead of the election timeout.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub evaluate_every: Duration,
    pub hysteresis: HysteresisPolicy,
    pub transfer_lease_secs: u64,
}

impl SchedulerConfig {
    pub fn new(timing: RaftTiming, hysteresis: HysteresisPolicy) -> Self {
        Self {
            evaluate_every: Duration::from_millis(timing.heartbeat_interval_ms.max(1)) * 2,
            hysteresis,
            transfer_lease_secs: TRANSFER_LEASE_SECS,
        }
    }
}

/// One tenant's committed ownership plus declared intent, narrowed to what
/// [`decide_transfer`] needs — free of raft/state-machine types so it is
/// testable as arithmetic, the same discipline
/// [`crate::leader_pin::decide`] uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSnapshot {
    pub owner: YubabaNodeId,
    pub epoch: u64,
    /// From `TenantPlacement::region`, or `None` if this tenant has no
    /// declared intent at all — same reading either way: unconstrained.
    pub region: Option<String>,
    pub tier: SlaTier,
    pub demand: TenantDemand,
    /// The RPO bound a candidate's streamer must be caught up within, from
    /// this tenant's tier. `None` — the only value [`run`] can produce today —
    /// means no target is configured, which
    /// [`judge_readiness`] treats as vacuously satisfied. See the module doc.
    pub rpo_bound: Option<Duration>,
}

/// One candidate node's eligibility to receive a tenant, precomputed by the
/// caller so `decide_transfer` needs no I/O and no lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEligibility {
    /// Straight from [`TransitionTracker::committed`]. `None` (never confirmed
    /// either way) fails the gate exactly like `Some(Confirmed::Down)` — the
    /// fail-closed rule [`ReadinessInputs::liveness`] states, carried here
    /// unflattened so a caller cannot lose the distinction on the way in.
    pub liveness: Option<Confirmed>,
    /// Whether this node's raft peer link is *not* known-dead. A veto only:
    /// see the module doc for why the raft-heartbeat channel may refuse a
    /// candidate but never justify one.
    pub raft_peer_healthy: bool,
    pub region: Option<String>,
    /// `YubabaStateMachine::node_admits` for this tenant's demand — the
    /// headroom floor R737-F1 already built.
    pub admits: bool,
    /// Whether this node already holds a warm replica of the tenant being
    /// placed. Always `false` from the live call site today — see this
    /// module's doc for why, and for why this doubles as the `hydrated`
    /// evidence a [`SlaTier::WarmReplica`] tenant needs.
    pub warm_for_tenant: bool,
    /// Elapsed time since this tenant's WAL watermark last advanced on this
    /// node. Always `None` from the live call site today — see the module doc.
    pub streamer_watermark_age: Option<Duration>,
}

/// What [`decide_transfer`] concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementDecision {
    /// The owner is not confirmed down. Nothing to do — this is the steady
    /// state for almost every tenant on almost every tick.
    OwnerLive,
    /// The owner is confirmed down, but no candidate is both live and
    /// admitting (and, for a warm-tier tenant, already warm). Includes the
    /// case that matters most: a cluster-wide capacity crunch, where the
    /// correct answer is to leave the tenant unplaced rather than overcommit
    /// a node or guess at warmth.
    NoEligibleCandidate,
    /// Commit `TransferTenant` to this node.
    TransferTo(YubabaNodeId),
}

/// Project one candidate onto W253 §7's readiness gates and defer to
/// [`judge_readiness`] — the *only* place this module decides whether a node
/// may own a tenant.
///
/// The projection is where the tenant-relative reading of each gate lives:
/// `hydrated` collapses the warm-tier requirement (see the module doc), the RPO
/// bound comes from the tenant while the watermark comes from the node, and
/// liveness passes through unflattened. Everything else is
/// `judge_readiness`'s call, in `judge_readiness`'s order, so the refusal a
/// caller sees here is the same one R737-F2 defines.
///
/// Note what is *not* here: the region preference. That is a ranking among
/// ready nodes, not a readiness gate — an out-of-region node is perfectly ready
/// to own the tenant, just less preferred, and treating it as a gate is the
/// failure mode [`decide_transfer`]'s doc argues against.
pub fn judge_candidate(
    tenant: &TenantSnapshot,
    elig: &NodeEligibility,
) -> Result<(), NotReady> {
    judge_readiness(&ReadinessInputs {
        liveness: elig.liveness,
        raft_peer_healthy: elig.raft_peer_healthy,
        // Not measured — derived from the tier. A cold tenant hydrates *as
        // part of* the transfer, so requiring it first would deadlock; a warm
        // tenant's hydration evidence is exactly `warm_for_tenant`.
        hydrated: tenant.tier != SlaTier::WarmReplica || elig.warm_for_tenant,
        within_headroom: elig.admits,
        streamer_watermark_age: elig.streamer_watermark_age,
        streamer_rpo_bound: tenant.rpo_bound,
    })
}

/// Decide whether — and where — to re-place one tenant, given a snapshot of
/// its committed state and a precomputed view of every other node's
/// eligibility.
///
/// **Region-preferred, not region-required**: a candidate in the tenant's
/// declared region is preferred over one outside it, but an out-of-region
/// live, admitting (and warm, if required) node is still chosen over leaving
/// the tenant unplaced — W246 says "in-region-preferred", and the failure
/// mode of treating it as a hard filter is a tenant stuck down because its
/// only declared region lost every node, which is exactly the availability
/// case the whole relay exists to prevent.
///
/// Ties (after the region preference) break to the lowest node id, so two
/// evaluations of the same state — this leader on the next tick, or a new
/// leader after failover — reach the same target rather than thrashing.
pub fn decide_transfer(
    owner_confirmed_down: bool,
    tenant: &TenantSnapshot,
    candidates: &BTreeMap<YubabaNodeId, NodeEligibility>,
) -> PlacementDecision {
    if !owner_confirmed_down {
        return PlacementDecision::OwnerLive;
    }
    let mut eligible: Vec<(YubabaNodeId, &NodeEligibility)> = candidates
        .iter()
        .filter(|(id, elig)| **id != tenant.owner && judge_candidate(tenant, elig).is_ok())
        .map(|(id, elig)| (*id, elig))
        .collect();
    eligible.sort_by_key(|(id, elig)| {
        let out_of_region = match &tenant.region {
            Some(r) => elig.region.as_deref() != Some(r.as_str()),
            None => false,
        };
        (out_of_region, *id)
    });
    match eligible.first() {
        Some((id, _)) => PlacementDecision::TransferTo(*id),
        None => PlacementDecision::NoEligibleCandidate,
    }
}

/// Spawn the scheduler loop.
///
/// Safe to run on every node, like [`crate::leader_pin::spawn`]: a follower's
/// tick finds `current_leader != Some(node_id)` and does nothing but advance
/// its own (unused) [`TransitionTracker`].
///
/// `raft_detector` supplies the `raft_peer_healthy` gate only, and only as a
/// veto — passing `None` leaves that gate open rather than freezing placement,
/// so a deployment (or a test harness) without one behaves exactly as it did
/// before the gate existed. See the module doc.
///
/// `rpo_registry` (R782) supplies `streamer_watermark_age` per candidate.
/// `None` here has the same "behaves like before the gate existed" property —
/// but only for tenants with no `rpo_bound` declared; a tenant that *does*
/// declare one and gets `None` here fails every candidate closed, per
/// `judge_readiness`'s absence-of-evidence rule. See the module doc.
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    lease_detector: Option<std::sync::Arc<LeaseFailureDetector>>,
    raft_detector: Option<std::sync::Arc<dyn crate::failure_detector::FailureDetector>>,
    rpo_registry: Option<std::sync::Arc<crate::lease_detector::RpoWatermarkRegistry>>,
    config: SchedulerConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(
            node_id,
            raft,
            state_machine,
            lease_detector,
            raft_detector,
            rpo_registry,
            config,
        )
        .await;
    })
}

async fn run(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    lease_detector: Option<std::sync::Arc<LeaseFailureDetector>>,
    raft_detector: Option<std::sync::Arc<dyn crate::failure_detector::FailureDetector>>,
    rpo_registry: Option<std::sync::Arc<crate::lease_detector::RpoWatermarkRegistry>>,
    config: SchedulerConfig,
) {
    use crate::failure_detector::{FailureDetector, LivenessReport};
    use openraft::async_runtime::watch::WatchReceiver;

    info!(
        node_id,
        evaluate_every = ?config.evaluate_every,
        "tenant placement scheduler active"
    );
    let watch = raft.metrics();
    let mut tracker = TransitionTracker::new();

    loop {
        tokio::time::sleep(config.evaluate_every).await;

        let is_leader = watch.borrow_watched().current_leader == Some(node_id);

        // Feed the tracker every tick, leader or not, so a node's hysteresis
        // state is already warm if it becomes leader mid-dwell rather than
        // starting the confirm window over at the moment it matters most.
        // Harmless on a follower: nobody renews against a non-leader (R737-F2
        // §"nodes renew ... via the leader"), so its report is empty and
        // `observe` is a no-op.
        let report: LivenessReport = match &lease_detector {
            Some(d) => d.observe().await,
            None => LivenessReport::new(),
        };
        tracker.observe(&report, config.hysteresis, std::time::Instant::now());

        if !is_leader {
            continue;
        }

        let now_unix = unix_now_secs();
        let members = state_machine.members();
        let tenants = state_machine.tenants();

        // The veto channel. Empty on a follower, empty when no detector is
        // attached, and empty of any node it has no acknowledgement for — all
        // of which read as "no objection", never as "unhealthy". See module doc.
        let raft_report: LivenessReport = match &raft_detector {
            Some(d) => d.observe().await,
            None => LivenessReport::new(),
        };

        for (tenant, ownership) in &tenants {
            let owner_confirmed_down = tracker.committed(ownership.owner) == Some(Confirmed::Down);
            if !owner_confirmed_down {
                continue;
            }
            let placement = state_machine.tenant_placement(tenant);
            let snapshot = TenantSnapshot {
                owner: ownership.owner,
                epoch: ownership.epoch,
                region: placement.as_ref().and_then(|p| p.region.clone()),
                tier: placement.as_ref().map_or_else(SlaTier::default, |p| p.tier),
                demand: placement.as_ref().map_or_else(TenantDemand::default, |p| p.demand),
                // R782: TenantPlacement now carries the declared RPO target
                // directly; `None` for any tenant that never had one set.
                rpo_bound: placement.as_ref().and_then(|p| p.rpo_bound),
            };
            let candidates: BTreeMap<YubabaNodeId, NodeEligibility> = members
                .iter()
                .filter(|(id, _)| **id != snapshot.owner)
                .map(|(id, info)| {
                    (
                        *id,
                        NodeEligibility {
                            liveness: tracker.committed(*id),
                            raft_peer_healthy: raft_peer_healthy(&raft_report, *id),
                            region: info.region.clone(),
                            admits: state_machine.node_admits(*id, &snapshot.demand, now_unix),
                            // W248 unpopulated — see module doc.
                            warm_for_tenant: false,
                            // R782: whatever this candidate's own streamer
                            // last pushed over `POST /mesh/rpo-report`, or
                            // `None` if it never has (fail-closed — see the
                            // module doc and `spawn`'s doc on `rpo_registry`).
                            streamer_watermark_age: rpo_registry
                                .as_ref()
                                .and_then(|r| r.watermark_age(*id, tenant)),
                        },
                    )
                })
                .collect();

            match decide_transfer(owner_confirmed_down, &snapshot, &candidates) {
                PlacementDecision::OwnerLive => {}
                PlacementDecision::NoEligibleCandidate => {
                    // Report *which* gate each candidate failed. "No eligible
                    // candidate" alone is the least actionable line an operator
                    // can be handed during an outage — a capacity crunch, a
                    // fleet that has not been confirmed live yet, and a
                    // warm-tier tenant that can never place until W248 lands
                    // are three very different problems with one message.
                    let refusals = candidates
                        .iter()
                        .map(|(id, elig)| {
                            format!("{id}={}", refusal_str(judge_candidate(&snapshot, elig)))
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                    warn!(
                        node_id,
                        tenant = %tenant.0,
                        dead_owner = ownership.owner,
                        %refusals,
                        "scheduler: owner confirmed down but no candidate passed the readiness \
                         gates — tenant stays unplaced this tick"
                    );
                }
                PlacementDecision::TransferTo(target) => {
                    let req = YubabaRequest::TransferTenant {
                        tenant: tenant.clone(),
                        to: target,
                        from_epoch: snapshot.epoch,
                        lease_secs: config.transfer_lease_secs,
                        now: now_unix,
                    };
                    info!(
                        node_id,
                        tenant = %tenant.0,
                        dead_owner = ownership.owner,
                        target,
                        from_epoch = snapshot.epoch,
                        "scheduler: re-placing tenant off a confirmed-down owner"
                    );
                    if let Err(e) = raft.client_write(req).await {
                        warn!(
                            node_id,
                            tenant = %tenant.0,
                            target,
                            "scheduler: TransferTenant commit failed, will re-evaluate next tick: {e}"
                        );
                    }
                }
            }
        }
    }
}

/// The raft channel's veto, per the module doc: only an explicit `Down`
/// observation refuses. A node absent from the report has not been *judged* by
/// this channel — on the leader that means it never acked, on a follower it
/// means the channel has no view at all — and the
/// [`FailureDetector`](crate::failure_detector::FailureDetector) trait is
/// explicit that absence is not death.
fn raft_peer_healthy(report: &crate::failure_detector::LivenessReport, node: YubabaNodeId) -> bool {
    !matches!(
        report.get(&node).map(|obs| obs.liveness),
        Some(crate::failure_detector::NodeLiveness::Down)
    )
}

/// Stable lowercase spelling of a readiness verdict, for the operator-facing
/// refusal line. Mirrors [`crate::failure_detector::NodeLiveness::as_str`]'s
/// contract: a wire/log token, never prose.
fn refusal_str(verdict: Result<(), NotReady>) -> &'static str {
    match verdict {
        Ok(()) => "ready",
        Err(NotReady::NotLive) => "not-live",
        Err(NotReady::RaftPeerUnhealthy) => "raft-peer-unhealthy",
        Err(NotReady::NotHydrated) => "not-hydrated",
        Err(NotReady::StreamerBehindBound) => "streamer-behind-bound",
        Err(NotReady::OverHeadroom) => "over-headroom",
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(owner: YubabaNodeId, region: Option<&str>, tier: SlaTier) -> TenantSnapshot {
        TenantSnapshot {
            owner,
            epoch: 3,
            region: region.map(str::to_string),
            tier,
            demand: TenantDemand::default(),
            rpo_bound: None,
        }
    }

    fn node(confirmed_up: bool, region: Option<&str>, admits: bool) -> NodeEligibility {
        NodeEligibility {
            liveness: confirmed_up.then_some(Confirmed::Up),
            raft_peer_healthy: true,
            region: region.map(str::to_string),
            admits,
            warm_for_tenant: false,
            streamer_watermark_age: None,
        }
    }

    #[test]
    fn a_live_owner_is_left_alone_regardless_of_candidates() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([(2, node(true, None, true))]);
        assert_eq!(decide_transfer(false, &s, &candidates), PlacementDecision::OwnerLive);
    }

    #[test]
    fn a_confirmed_dead_owner_re_places_onto_the_only_live_admitting_node() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([
            (2, node(false, None, true)), // not confirmed up
            (3, node(true, None, false)), // no room
            (4, node(true, None, true)),  // the one
        ]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(4));
    }

    #[test]
    fn no_live_admitting_candidate_is_reported_rather_than_guessed() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([
            (2, node(false, None, true)),
            (3, node(true, None, false)),
        ]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::NoEligibleCandidate);
    }

    #[test]
    fn the_dead_owner_itself_is_never_a_candidate() {
        // Even if somehow present in the candidate map with every gate open
        // (a stale read, a test double), the owner must never be offered
        // itself as the re-placement target.
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([(1, node(true, None, true))]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::NoEligibleCandidate);
    }

    #[test]
    fn in_region_candidate_is_preferred_over_an_out_of_region_one() {
        let s = snapshot(1, Some("us-west"), SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([
            (2, node(true, Some("us-east"), true)),
            (3, node(true, Some("us-west"), true)),
        ]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(3));
    }

    /// W246: "in-region-preferred", not in-region-required. Leaving a tenant
    /// down because its home region has no live capacity is the exact
    /// availability failure this relay exists to prevent.
    #[test]
    fn an_out_of_region_candidate_is_used_when_no_in_region_one_exists() {
        let s = snapshot(1, Some("us-west"), SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([(2, node(true, Some("us-east"), true))]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(2));
    }

    #[test]
    fn ties_after_region_preference_break_to_the_lowest_node_id() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([
            (5, node(true, None, true)),
            (2, node(true, None, true)),
            (9, node(true, None, true)),
        ]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(2));
    }

    #[test]
    fn a_warm_replica_tenant_requires_an_already_warm_candidate() {
        let s = snapshot(1, None, SlaTier::WarmReplica);
        let candidates = BTreeMap::from([(2, node(true, None, true))]); // live, admits, but not warm
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::NoEligibleCandidate);

        let mut warm_candidate = node(true, None, true);
        warm_candidate.warm_for_tenant = true;
        let candidates = BTreeMap::from([(2, warm_candidate)]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(2));
    }

    #[test]
    fn a_cold_hydrate_tenant_does_not_require_warmth() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([(2, node(true, None, true))]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(2));
    }

    // ── readiness gates now actually gate (R737-F2) ──────────────────────

    /// The gate that had no call site at all before: a node the lease channel
    /// confirmed live, with room, whose raft peer link is dead must not be
    /// handed a tenant it cannot then be fenced through.
    #[test]
    fn a_confirmed_live_node_with_a_dead_raft_peer_is_refused() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let mut sick = node(true, None, true);
        sick.raft_peer_healthy = false;
        assert_eq!(judge_candidate(&s, &sick), Err(NotReady::RaftPeerUnhealthy));

        let candidates = BTreeMap::from([(2, sick), (3, node(true, None, true))]);
        assert_eq!(
            decide_transfer(true, &s, &candidates),
            PlacementDecision::TransferTo(3),
            "a healthy higher-id node must beat an unhealthy lower-id one"
        );
    }

    /// A never-confirmed node and a confirmed-down one are both `NotLive`, but
    /// they are distinct inputs — the old `confirmed_up: bool` flattened them
    /// on the way in, which is exactly what `ReadinessInputs::liveness`'s doc
    /// asks callers not to do.
    #[test]
    fn never_confirmed_and_confirmed_down_are_both_not_live() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let mut never = node(true, None, true);
        never.liveness = None;
        assert_eq!(judge_candidate(&s, &never), Err(NotReady::NotLive));

        let mut down = node(true, None, true);
        down.liveness = Some(Confirmed::Down);
        assert_eq!(judge_candidate(&s, &down), Err(NotReady::NotLive));

        let candidates = BTreeMap::from([(2, never), (3, down)]);
        assert_eq!(
            decide_transfer(true, &s, &candidates),
            PlacementDecision::NoEligibleCandidate
        );
    }

    /// The warm-tier requirement and the `hydrated` gate are one rule, not
    /// two: a cold tenant hydrates as part of the transfer, a warm one must
    /// already be there.
    #[test]
    fn hydration_is_the_warm_tier_requirement_not_a_second_gate() {
        let cold = snapshot(1, None, SlaTier::ColdHydrate);
        let warm = snapshot(1, None, SlaTier::WarmReplica);
        let bare = node(true, None, true);
        let mut warmed = node(true, None, true);
        warmed.warm_for_tenant = true;

        assert_eq!(judge_candidate(&cold, &bare), Ok(()));
        assert_eq!(judge_candidate(&warm, &bare), Err(NotReady::NotHydrated));
        assert_eq!(judge_candidate(&warm, &warmed), Ok(()));
    }

    /// Once an RPO bound *is* plumbed through, the gate is live with no
    /// further wiring — this pins the projection, not `judge_readiness`'s own
    /// arithmetic (which `lease_detector` already covers).
    #[test]
    fn an_rpo_bound_on_the_tenant_gates_against_the_nodes_watermark() {
        let mut s = snapshot(1, None, SlaTier::ColdHydrate);
        s.rpo_bound = Some(Duration::from_secs(30));

        let mut behind = node(true, None, true);
        behind.streamer_watermark_age = Some(Duration::from_secs(60));
        assert_eq!(
            judge_candidate(&s, &behind),
            Err(NotReady::StreamerBehindBound)
        );

        let mut caught_up = node(true, None, true);
        caught_up.streamer_watermark_age = Some(Duration::from_secs(1));
        assert_eq!(judge_candidate(&s, &caught_up), Ok(()));

        // No watermark at all against a real bound is not evidence of being
        // caught up. At the live `run()` call site (R782) this is exactly
        // what happens to every candidate for a bound tenant until some node
        // other than the (excluded) owner has pushed a fresh
        // `POST /mesh/rpo-report` for it — W248's warm fan-out, not a bug in
        // this plumbing. See the module doc.
        assert_eq!(
            judge_candidate(&s, &node(true, None, true)),
            Err(NotReady::StreamerBehindBound)
        );
    }

    /// The default at the live call site for any tenant that has never had an
    /// RPO target declared: `TenantPlacement.rpo_bound` reads `None`
    /// (R782 plumbed the field; an operator still has to set it), so the gate
    /// stays vacuously satisfied exactly as it did before R782 landed. If
    /// this ever starts refusing for an undeclared tenant, `rpo_bound` is
    /// leaking a stale value from somewhere, not "the plumbing landed
    /// without its bound" (that phase is over — both inputs are wired).
    #[test]
    fn an_undeclared_rpo_target_stays_vacuous_by_default() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        assert_eq!(s.rpo_bound, None);
        let candidate = node(true, None, true);
        assert_eq!(candidate.streamer_watermark_age, None);
        assert_eq!(judge_candidate(&s, &candidate), Ok(()));
    }

    #[test]
    fn the_raft_veto_only_fires_on_an_explicit_down() {
        use crate::failure_detector::{LivenessReport, NodeLiveness, NodeObservation};

        let obs = |liveness| NodeObservation {
            liveness,
            silent_for_ms: None,
        };
        let report: LivenessReport = [
            (1, obs(NodeLiveness::Live)),
            (2, obs(NodeLiveness::Suspect)),
            (3, obs(NodeLiveness::Unknown)),
            (4, obs(NodeLiveness::Down)),
        ]
        .into_iter()
        .collect();

        assert!(raft_peer_healthy(&report, 1));
        assert!(raft_peer_healthy(&report, 2), "slow is not dead");
        assert!(raft_peer_healthy(&report, 3), "unjudged is not dead");
        assert!(!raft_peer_healthy(&report, 4));
        assert!(
            raft_peer_healthy(&report, 99),
            "a node this channel has never seen must not be vetoed by it"
        );
        assert!(
            raft_peer_healthy(&LivenessReport::new(), 1),
            "an empty report (follower, or no detector) must veto nobody — \
             otherwise placement freezes fleet-wide"
        );
    }

    #[test]
    fn refusal_strings_are_stable_log_tokens() {
        assert_eq!(refusal_str(Ok(())), "ready");
        assert_eq!(refusal_str(Err(NotReady::NotLive)), "not-live");
        assert_eq!(
            refusal_str(Err(NotReady::RaftPeerUnhealthy)),
            "raft-peer-unhealthy"
        );
        assert_eq!(refusal_str(Err(NotReady::NotHydrated)), "not-hydrated");
        assert_eq!(
            refusal_str(Err(NotReady::StreamerBehindBound)),
            "streamer-behind-bound"
        );
        assert_eq!(refusal_str(Err(NotReady::OverHeadroom)), "over-headroom");
    }

    #[test]
    fn scheduler_config_paces_off_the_heartbeat_not_the_election() {
        use crate::cluster_policy::ClusterPolicy;
        let policy = ClusterPolicy::fleet();
        let cfg = SchedulerConfig::new(policy.timing, HysteresisPolicy::from_thresholds(policy.liveness_thresholds()));
        assert_eq!(
            cfg.evaluate_every,
            Duration::from_millis(policy.timing.heartbeat_interval_ms * 2)
        );
    }
}
