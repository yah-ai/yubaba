//! N+1 (N+2 across regions) warm-spare headroom accounting — R737-T4, W253 §8.
//!
//! > Headroom: run N+1 (N+2 if a region can vanish) of warm spare so failover
//! > never needs provisioning.
//!
//! [`crate::scheduler`] re-places a dead owner's tenants onto *already live*
//! capacity and never provisions inline (the invariant its own module doc and
//! `leader.rs`'s gotcha both hold the line on). That only stays true as long
//! as live spare capacity actually exists — this module is the accounting
//! that watches for the moment it stops being true, and the background loop
//! that says so loudly rather than silently degrading into the thing the
//! scheduler was built to avoid.
//!
//! # Derived, not replicated — the same call R737-F1 made for load
//!
//! Headroom is computed fresh from `members` + `tenants`, both already
//! raft-replicated, the same way [`crate::raft::YubabaState::node_load`] is
//! derived rather than stored. There is nothing here that needs its own raft
//! entry: two nodes reading the same applied state reach the same headroom
//! report, so there is no "which node's opinion is authoritative" question a
//! replicated field would need to answer.
//!
//! # What "enqueue a background provisioning job" means here, and what it
//! deliberately does not
//!
//! This module does **not** call [`cloud::provision::execute`] — nothing in
//! this process has the `MachineConfig` / provider credentials that call
//! needs. Those live with the operator-invoked `yah cloud machine provision`
//! CLI (`app/yah/cli/src/cloud.rs`), and handing the control-plane daemon
//! direct cloud-provisioning authority is a materially larger change than
//! this ticket's own tier ("an invariant plus an enqueue path") asks for.
//!
//! "Enqueue" is scoped to: compute the deficit on a slow, leader-only,
//! failover-independent cadence, publish it somewhere durable and visible
//! ([`ServerState::headroom`], surfaced on `GET /raft/status`), and log it at
//! `warn` on every tick it persists. That is a real signal an operator (or a
//! future automated consumer polling `/raft/status`) can act on — wiring that
//! consumer is next work, explicitly out of this ticket's scope; see the
//! module's own `@yah:next`.
//!
//! # Why "spare", not merely "has headroom"
//!
//! [`crate::raft::YubabaState::node_headroom`] answers "how much room is left
//! on this node", which is nonzero for almost every node almost all the time.
//! W253 §8 asks a stricter question: is there a node held **in reserve**,
//! carrying nothing, ready to absorb a whole failed node's tenants without
//! first evicting anyone. [`is_spare`] is that stricter predicate — capacity
//! published, confirmed live, and zero currently-owned live tenants.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::cluster_policy::RaftTiming;
use crate::lease_detector::{Confirmed, HysteresisPolicy, LeaseFailureDetector, TransitionTracker};
use crate::raft::{MemberInfo, TenantOwnership, YubabaNodeId, YubabaRaft, YubabaStateMachine};
use crate::ServerState;
use workload_spec::TenantId;

/// How many idle, capacity-published nodes must be held in reserve.
///
/// `2` (N+2) once the fleet declares more than one distinct region — losing a
/// whole region must not exhaust the spare pool, per W253 §8's own
/// parenthetical. `1` (N+1) otherwise, including a rig's single failure
/// domain, where "a region can vanish" has no meaning.
pub fn required_spare(members: &BTreeMap<YubabaNodeId, MemberInfo>) -> usize {
    let regions: BTreeSet<&str> = members.values().filter_map(|m| m.region.as_deref()).collect();
    if regions.len() >= 2 {
        2
    } else {
        1
    }
}

/// Whether `node` is a genuine warm spare at `now`: confirmed live, has
/// published capacity (an unmeasured node is never a spare — same
/// fail-closed reading [`crate::raft::MemberInfo::capacity`]'s own doc states
/// for placement), and currently owns zero *live* tenants. A node quietly
/// carrying one small tenant is not held in reserve, even though it may still
/// have room for another — that node is counted by `node_headroom`, not here.
pub fn is_spare(
    node: YubabaNodeId,
    members: &BTreeMap<YubabaNodeId, MemberInfo>,
    tenants: &BTreeMap<TenantId, TenantOwnership>,
    confirmed_up: bool,
    now: u64,
) -> bool {
    if !confirmed_up {
        return false;
    }
    if members.get(&node).and_then(|m| m.capacity).is_none() {
        return false;
    }
    !tenants.values().any(|t| t.owner == node && t.is_live(now))
}

/// The headroom invariant's current answer — cheap to compute, cheap to
/// clone, and what [`ServerState::headroom`] caches for `GET /raft/status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadroomReport {
    pub spare: usize,
    pub required: usize,
}

impl HeadroomReport {
    pub fn satisfied(&self) -> bool {
        self.spare >= self.required
    }
}

/// Evaluate the invariant against a snapshot of live state.
///
/// `confirmed_up` names every node this evaluator currently trusts as live —
/// [`TransitionTracker::committed`] filtered to `Confirmed::Up`, passed in
/// rather than derived here so this stays pure arithmetic over plain
/// collections, the same discipline [`crate::scheduler::decide_transfer`] and
/// [`crate::leader_pin::decide`] use.
pub fn evaluate(
    members: &BTreeMap<YubabaNodeId, MemberInfo>,
    tenants: &BTreeMap<TenantId, TenantOwnership>,
    confirmed_up: &BTreeSet<YubabaNodeId>,
    now: u64,
) -> HeadroomReport {
    let spare = members
        .keys()
        .filter(|id| is_spare(**id, members, tenants, confirmed_up.contains(id), now))
        .count();
    HeadroomReport {
        spare,
        required: required_spare(members),
    }
}

/// How the background loop is paced.
///
/// Deliberately far slower than [`crate::scheduler::SchedulerConfig`]: a
/// headroom deficit is a *trend*, not an emergency a single tick should react
/// to (that reaction, when it becomes an emergency, is exactly what the
/// scheduler's re-placement is for). Derived off the election timeout the
/// same way [`crate::leader_pin::PinConfig`] is, for the same reason — both
/// are anti-churn-adjacent background accounting, not failover-path code.
#[derive(Debug, Clone)]
pub struct HeadroomConfig {
    pub evaluate_every: Duration,
    pub hysteresis: HysteresisPolicy,
}

impl HeadroomConfig {
    pub fn new(timing: RaftTiming, hysteresis: HysteresisPolicy) -> Self {
        Self {
            evaluate_every: Duration::from_millis(timing.election_timeout_max_ms) * 10,
            hysteresis,
        }
    }
}

/// Spawn the headroom accounting loop.
///
/// Safe to run on every node, like [`crate::scheduler::spawn`] and
/// [`crate::leader_pin::spawn`]: a follower's tick reads and caches nothing,
/// since only the leader has real evidence from R737-F2's lease channel — a
/// follower's [`LeaseFailureDetector`] registry is empty by construction
/// (nodes renew against the leader), so its `TransitionTracker` would never
/// confirm anyone `Up` and every node would spuriously read as zero spare.
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    lease_detector: Option<Arc<LeaseFailureDetector>>,
    state: Arc<ServerState>,
    config: HeadroomConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state_machine, lease_detector, state, config).await;
    })
}

async fn run(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    lease_detector: Option<Arc<LeaseFailureDetector>>,
    state: Arc<ServerState>,
    config: HeadroomConfig,
) {
    use crate::failure_detector::{FailureDetector, LivenessReport};
    use openraft::async_runtime::watch::WatchReceiver;

    info!(
        node_id,
        evaluate_every = ?config.evaluate_every,
        "headroom accounting active"
    );
    let watch = raft.metrics();
    let mut tracker = TransitionTracker::new();

    loop {
        tokio::time::sleep(config.evaluate_every).await;

        let report: LivenessReport = match &lease_detector {
            Some(d) => d.observe().await,
            None => LivenessReport::new(),
        };
        tracker.observe(&report, config.hysteresis, std::time::Instant::now());

        let is_leader = watch.borrow_watched().current_leader == Some(node_id);
        if !is_leader {
            continue;
        }

        let members = state_machine.members();
        let tenants = state_machine.tenants();
        let confirmed_up: BTreeSet<YubabaNodeId> = members
            .keys()
            .copied()
            .filter(|id| tracker.committed(*id) == Some(Confirmed::Up))
            .collect();
        let now_unix = unix_now_secs();

        let headroom = evaluate(&members, &tenants, &confirmed_up, now_unix);
        if headroom.satisfied() {
            info!(
                node_id,
                spare = headroom.spare,
                required = headroom.required,
                "headroom: satisfied"
            );
        } else {
            warn!(
                node_id,
                spare = headroom.spare,
                required = headroom.required,
                "headroom: BELOW N+1 target — no live spare capacity to fail over into; \
                 provision more capacity (yah cloud machine provision) before the next \
                 owner death has nowhere live to land"
            );
        }
        *state.headroom.lock().unwrap() = Some(headroom);
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
    use crate::raft::NodeCapacity;

    fn member(region: Option<&str>, capacity: Option<NodeCapacity>) -> MemberInfo {
        MemberInfo {
            addr: "100.64.0.1:7443".into(),
            region: region.map(str::to_string),
            capacity,
        }
    }

    const BOX: NodeCapacity = NodeCapacity { memory_mb: 1024, cpu_millis: 1000 };

    fn owned(owner: YubabaNodeId, lease_expires: u64) -> TenantOwnership {
        TenantOwnership { owner, epoch: 1, lease_expires }
    }

    #[test]
    fn a_single_region_fleet_requires_only_n_plus_one() {
        let members = BTreeMap::from([
            (1, member(Some("us-west"), Some(BOX))),
            (2, member(Some("us-west"), Some(BOX))),
        ]);
        assert_eq!(required_spare(&members), 1);
    }

    #[test]
    fn a_multi_region_fleet_requires_n_plus_two() {
        let members = BTreeMap::from([
            (1, member(Some("us-west"), Some(BOX))),
            (2, member(Some("us-east"), Some(BOX))),
        ]);
        assert_eq!(required_spare(&members), 2);
    }

    #[test]
    fn an_untagged_fleet_requires_only_n_plus_one() {
        let members = BTreeMap::from([(1, member(None, Some(BOX))), (2, member(None, Some(BOX)))]);
        assert_eq!(required_spare(&members), 1);
    }

    #[test]
    fn a_node_with_no_tenants_and_published_capacity_is_spare() {
        let members = BTreeMap::from([(1, member(None, Some(BOX)))]);
        let tenants = BTreeMap::new();
        assert!(is_spare(1, &members, &tenants, true, 100));
    }

    #[test]
    fn a_node_carrying_a_live_tenant_is_not_spare() {
        let members = BTreeMap::from([(1, member(None, Some(BOX)))]);
        let tenants = BTreeMap::from([(TenantId("acme".into()), owned(1, 200))]);
        assert!(!is_spare(1, &members, &tenants, true, 100));
    }

    /// The point of deriving load rather than storing it (R737-F1's own
    /// argument, restated here): a tenant whose lease already expired
    /// contributes nothing, so the node that lost it is spare again the
    /// moment its own lease lapses — not stuck "occupied" by a dead record.
    #[test]
    fn a_node_whose_only_tenant_leases_expired_is_spare_again() {
        let members = BTreeMap::from([(1, member(None, Some(BOX)))]);
        let tenants = BTreeMap::from([(TenantId("acme".into()), owned(1, 50))]); // expired at now=100
        assert!(is_spare(1, &members, &tenants, true, 100));
    }

    #[test]
    fn an_unmeasured_node_is_never_spare() {
        let members = BTreeMap::from([(1, member(None, None))]);
        let tenants = BTreeMap::new();
        assert!(!is_spare(1, &members, &tenants, true, 100));
    }

    #[test]
    fn an_unconfirmed_node_is_never_spare_even_with_room_and_no_tenants() {
        let members = BTreeMap::from([(1, member(None, Some(BOX)))]);
        let tenants = BTreeMap::new();
        assert!(!is_spare(1, &members, &tenants, false, 100));
    }

    #[test]
    fn evaluate_counts_spare_nodes_against_the_region_derived_requirement() {
        let members = BTreeMap::from([
            (1, member(Some("us-west"), Some(BOX))), // owns a tenant
            (2, member(Some("us-east"), Some(BOX))), // spare
            (3, member(Some("us-east"), None)),      // unmeasured, never spare
        ]);
        let tenants = BTreeMap::from([(TenantId("acme".into()), owned(1, 200))]);
        let confirmed_up = BTreeSet::from([1, 2, 3]);

        let report = evaluate(&members, &tenants, &confirmed_up, 100);
        assert_eq!(report, HeadroomReport { spare: 1, required: 2 });
        assert!(!report.satisfied(), "1 spare against a 2-region fleet's N+2 requirement");
    }

    #[test]
    fn headroom_config_is_paced_far_slower_than_the_scheduler() {
        use crate::cluster_policy::ClusterPolicy;
        let policy = ClusterPolicy::fleet();
        let cfg = HeadroomConfig::new(policy.timing, HysteresisPolicy::from_thresholds(policy.liveness_thresholds()));
        let election = Duration::from_millis(policy.timing.election_timeout_max_ms);
        assert!(cfg.evaluate_every >= election * 8, "{cfg:?}");
    }
}
