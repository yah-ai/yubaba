//! R737-T5 — the live-cluster proof of the placement driver: **a dead owner's
//! tenant moves onto capacity that was already there, and a cluster that has
//! lost quorum stops placing without stopping serving.**
//!
//! W246 §"Implementation order" step 5, W253 §9's canonical test. The unit
//! coverage in `scheduler.rs` tests [`decide_transfer`] as arithmetic; nothing
//! there runs the real `spawn`/`run` loop against a real raft cluster, so
//! nothing there can catch a loop that reads the wrong map, never becomes
//! leader, or writes a `TransferTenant` the state machine rejects.
//!
//! ```bash
//! cargo test -p yubaba --test main -- raft_tenant_placement::
//! ```
//!
//! Credential-free and containerd-free: real openraft over loopback HTTP with
//! `DummyRuntime`, on [`ClusterPolicy::rig`] rather than the fleet preset. The
//! policy choice is not cosmetic — it sets both the election bounds and the
//! liveness thresholds this whole test is timed against (rig: suspect 450 ms,
//! down 1500 ms, so a confirmed down-transition costs ~2× down_after ≈ 3 s;
//! the fleet preset would make the same assertions take ~10 s each).
//!
//! ## Why not `integration_mesh.rs`
//!
//! T5 was filed pointing at `integration_mesh.rs`, which already has the
//! partition and quorum-loss mechanics. It is the wrong home: those tests are
//! `#[test_with_provider(local, smoke)]` behind the `containerd-integration`
//! feature, so the §9 control/data-separation proof would sit in a file the
//! default `cargo test` never runs — the exact "passes vacuously" outcome T5's
//! own tier note warns about. This file uses the same `Cluster` harness and the
//! same `kill_node` primitive, with no feature gate.
//!
//! ## What "zero provisioning calls" means observably
//!
//! There is no counter to assert on, and a mock `MachineProvider` would be
//! vacuous: the local tier never touches the provider, so it would read zero
//! whatever the scheduler did. The static fact is stronger and already true —
//! `rg 'cloud::provision' oss/yubaba/crates/yubaba/src/` finds only prose in
//! `headroom.rs`'s module doc explaining that it deliberately does *not* call
//! it. What this test adds is the live property that fact is supposed to
//! produce: **the raft member map is unchanged across the failover**. Failover
//! that provisioned would have to grow the cluster, and growing it means a new
//! member row. Same nodes in, same nodes out, tenant moved.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cloud::provider::HetznerDriver;
use workload_spec::TenantId;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::failure_detector::RaftHeartbeatDetector;
use yubaba::lease_detector::HysteresisPolicy;
use yubaba::raft::{
    MemberInfo, NodeCapacity, SlaTier, TenantDemand, TenantPlacement, YubabaNodeId, YubabaRequest,
};
use yubaba::runtime::DummyRuntime;
use yubaba::scheduler::{self, SchedulerConfig};
use yubaba_test_harness::{test_cluster_with_policy, Cluster};

/// The tenant every test here places.
const TENANT: &str = "acme-prod";

/// Lease length on the seeded claim. Long enough that nothing expires by
/// accident: this test drives failover through the *lease detector's* node
/// liveness, not through the tenant lease, and those are different clocks. A
/// tenant lease that quietly expired mid-test would let a takeover happen for
/// the wrong reason and the assertion would still pass.
const TENANT_LEASE_SECS: u64 = 3600;

/// What each node publishes as its schedulable budget. Fixed and synthetic for
/// the same reason `HARNESS_CAPACITY` is: an assertion about the scheduler must
/// not become an assertion about the host that ran it.
const CAPACITY: NodeCapacity = NodeCapacity {
    memory_mb: 16384,
    cpu_millis: 8000,
};

/// Comfortably larger than one confirm cycle (~3 s on rig) plus election
/// slack, so a slow CI box reports a real failure rather than a timeout.
const BUDGET: Duration = Duration::from_secs(45);

/// How long a re-placement is allowed to take once the owner goes silent, and
/// — the reason it is one constant rather than two — how long test 2 watches a
/// quorum-less cluster before calling placement frozen.
///
/// On rig timings the real cost is `down_after` (1.5 s) to judge the node
/// silent, plus the tracker's confirm dwell (another 1.5 s), plus a scheduler
/// tick (300 ms) ≈ 3.3 s; the rest is CI headroom. Test 1 *asserts* a placement
/// lands inside this window, which is what makes test 2's freeze assertion an
/// argument rather than an assumption: the same setup, given the same time,
/// demonstrably moves a tenant when it has quorum.
const PLACEMENT_WINDOW: Duration = Duration::from_secs(20);

/// How often the test pushes lease renewals and re-reads state.
const PUMP: Duration = Duration::from_millis(50);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs()
}

fn tenant() -> TenantId {
    TenantId(TENANT.to_string())
}

/// `POST /raft/write`, asserting the cluster committed it.
///
/// Built from the real [`YubabaRequest`] rather than hand-rolled JSON so an
/// upstream field rename breaks this at compile time instead of turning into a
/// silently-mismatched body.
async fn write(base_url: &str, request: YubabaRequest) {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/raft/write"))
        .json(&serde_json::json!({ "request": request }))
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST /raft/write: {e}"));
    assert!(
        resp.status().is_success(),
        "seeding write rejected: HTTP {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// The scheduler loops for one cluster, aborted together when the test ends.
///
/// Held by the test rather than pushed into the harness for the same reason
/// `raft_leader_pin.rs`'s `Pins` is: the harness has no business knowing that
/// some tests also run an actuator.
struct Schedulers(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Schedulers {
    fn drop(&mut self) {
        for s in &self.0 {
            s.abort();
        }
    }
}

/// Start the real `scheduler::spawn` on **every** node, exactly as `main.rs`
/// does — a follower's tick is a no-op, and starting it only on the current
/// leader would quietly test a loop that production does not run.
///
/// Both detectors are the production ones: the node's own lease registry (which
/// this test drives directly instead of standing up `lease_renewal`'s HTTP
/// loop) and a `RaftHeartbeatDetector` for R737-F2's `raft_peer_healthy` veto.
/// Passing `None` for the second would leave that gate open and make this test
/// blind to a veto that wrongly fires.
fn start_schedulers(cluster: &Cluster, policy: ClusterPolicy) -> Schedulers {
    let mut handles = Vec::new();
    for idx in 0..cluster.node_count() {
        let (Some(raft), Some(sm), Some(node_id)) = (
            cluster.raft(idx),
            cluster.cluster_state(idx),
            cluster.node_id(idx),
        ) else {
            continue;
        };
        handles.push(scheduler::spawn(
            node_id,
            raft.clone(),
            sm.clone(),
            cluster.lease_detector(idx).cloned(),
            Some(Arc::new(RaftHeartbeatDetector::new(
                raft.clone(),
                policy.liveness_thresholds(),
            ))),
            cluster.rpo_registry(idx).cloned(),
            SchedulerConfig::new(
                policy.timing,
                HysteresisPolicy::from_thresholds(policy.liveness_thresholds()),
            ),
        ));
    }
    Schedulers(handles)
}

/// Publish a member row with capacity for every node, declare the tenant's
/// intent (with `rpo_bound`, `None` for every test but the R782 one below),
/// and claim it for `owner_idx`.
///
/// `test_cluster` does not run `member_registration`, so without the member
/// rows every candidate would fail `node_admits` and the scheduler would
/// correctly refuse to place anything — a test that then asserted "nothing
/// moved" would be asserting on missing setup, not on the freeze.
async fn seed(cluster: &Cluster, leader: usize, owner_idx: usize) {
    seed_with_rpo_bound(cluster, leader, owner_idx, None).await;
}

async fn seed_with_rpo_bound(
    cluster: &Cluster,
    leader: usize,
    owner_idx: usize,
    rpo_bound: Option<Duration>,
) {
    let leader_url = cluster.yubaba(leader).base_url.clone();

    for idx in 0..cluster.node_count() {
        let Some(node_id) = cluster.node_id(idx) else {
            continue;
        };
        write(
            &leader_url,
            YubabaRequest::SetMember {
                node_id,
                addr: cluster.yubaba(idx).base_url.clone(),
                // Rig policy is SingleFailureDomain, so no region is declared —
                // which also exercises `decide_transfer`'s unconstrained arm.
                region: None,
                capacity: Some(CAPACITY),
                machine: None,
            },
        )
        .await;
    }

    write(
        &leader_url,
        YubabaRequest::SetTenantPlacement {
            tenant: tenant(),
            placement: TenantPlacement {
                region: None,
                // Cold, deliberately: `warm_for_tenant` is hardcoded false
                // until W248 lands, so a WarmReplica tenant cannot place at all
                // today and this test would pass for the wrong reason.
                tier: SlaTier::ColdHydrate,
                demand: TenantDemand {
                    memory_mb: 512,
                    cpu_millis: 250,
                },
                rpo_bound,
            },
        },
    )
    .await;

    write(
        &leader_url,
        YubabaRequest::ClaimTenant {
            tenant: tenant(),
            node: cluster
                .node_id(owner_idx)
                .expect("the seeded owner is a raft node"),
            lease_secs: TENANT_LEASE_SECS,
            now: now_secs(),
        },
    )
    .await;
}

/// Pump lease renewals into `at_idx`'s registry until `done` returns true or
/// `budget` elapses. Returns whether `done` fired.
///
/// Renewals are pushed straight into the registry rather than over
/// `POST /mesh/lease-renew` so the test controls exactly who looks alive:
/// `renew_leases_except` skips nodes `kill_node` stopped, so "the fleet is
/// alive except the one I killed" needs no bookkeeping here and cannot
/// accidentally keep a corpse renewing.
async fn pump_until(
    cluster: &Cluster,
    at_idx: usize,
    budget: Duration,
    mut done: impl FnMut(&Cluster) -> bool,
) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        cluster.renew_leases_except(at_idx, &[]);
        if done(cluster) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(PUMP).await;
    }
}

/// Pump renewals for `dwell` with no exit condition — used to establish
/// confirmed-`Up` liveness before staging a death, and to give a frozen
/// cluster every chance to misbehave.
async fn pump_for(cluster: &Cluster, at_idx: usize, dwell: Duration) {
    pump_until(cluster, at_idx, dwell, |_| false).await;
}

fn owner_of(cluster: &Cluster, idx: usize) -> Option<YubabaNodeId> {
    cluster
        .cluster_state(idx)?
        .tenants()
        .get(&tenant())
        .map(|o| o.owner)
}

fn epoch_of(cluster: &Cluster, idx: usize) -> Option<u64> {
    cluster
        .cluster_state(idx)?
        .tenants()
        .get(&tenant())
        .map(|o| o.epoch)
}

fn members_of(cluster: &Cluster, idx: usize) -> std::collections::BTreeMap<u64, MemberInfo> {
    cluster
        .cluster_state(idx)
        .expect("a raft node has applied state")
        .members()
}

// ── 1. A dead owner's tenant lands on live capacity, and only live capacity ──

/// **Kill a tenant's owner; the tenant re-places onto a node that was already
/// in the cluster, and the cluster does not grow.**
///
/// The sequence the whole relay exists to produce, end to end on a real raft:
/// node-lease renewals stop for the dead node → R737-F2's `LeaseFailureDetector`
/// judges it silent past `down_after` → `TransitionTracker` confirms the
/// down-*transition* after its dwell → R737-F3's leader-resident loop reads the
/// committed tenant map, picks a candidate that passes W253 §7's readiness
/// gates, and commits `TransferTenant` under the current epoch's CAS.
///
/// Non-vacuity, in order of how easily each could be faked:
///
/// - The victim is **not** the leader, so the transfer is a live leader acting
///   on a dead follower rather than a side effect of an election.
/// - The epoch must **advance**. An assertion on `owner` alone would pass if
///   the record were rewritten by any path at all; the epoch bump is what says
///   a fencing transfer happened (R732-F1).
/// - The member map must be **identical** before and after — this is the
///   "no provisioning on the failover path" property (see the module doc).
/// - The new owner must be one of the **surviving** nodes, not merely
///   "different": placing onto the other dead node would satisfy "moved".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_owners_tenant_re_places_onto_a_node_that_was_already_there() {
    let policy = ClusterPolicy::rig();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let mut cluster: Cluster = test_cluster_with_policy(&provider, DummyRuntime, 3, policy)
        .await
        .expect("3-node rig cluster");

    let leader = cluster
        .wait_for_agreed_leader(BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    // The owner is a follower: killing the leader would move leadership too,
    // and then this would be a test about elections.
    let victim = (0..3).find(|i| *i != leader).expect("a non-leader node");
    let victim_id = cluster.node_id(victim).expect("victim is a raft node");

    seed(&cluster, leader, victim).await;
    assert_eq!(
        owner_of(&cluster, leader),
        Some(victim_id),
        "the seeded claim must be committed before anything is killed",
    );
    let epoch_before = epoch_of(&cluster, leader).expect("the seeded tenant has an epoch");
    let members_before = members_of(&cluster, leader);
    assert_eq!(members_before.len(), 3, "all three nodes published a row");

    let _schedulers = start_schedulers(&cluster, policy);

    // Every node must be confirmed *Up* before the kill, or the survivors are
    // not yet eligible candidates and the scheduler would refuse the transfer
    // for a reason that has nothing to do with the dead owner.
    pump_for(&cluster, leader, policy.liveness_thresholds().suspect_after * 3).await;

    cluster.kill_node(victim).await.expect("kill the owner");

    let placed = pump_until(&cluster, leader, PLACEMENT_WINDOW, |c| {
        owner_of(c, leader).is_some_and(|o| o != victim_id)
    })
    .await;
    assert!(
        placed,
        "the tenant's owner was confirmed down but the tenant never moved — \
         still owned by node {victim_id} after {PLACEMENT_WINDOW:?}. This window \
         is also what test 2 waits before calling placement frozen, so widening \
         it here silently weakens that test too.",
    );

    let new_owner = owner_of(&cluster, leader).expect("the tenant still has a record");
    let survivors: Vec<u64> = (0..3)
        .filter(|i| *i != victim)
        .filter_map(|i| cluster.node_id(i))
        .collect();
    assert!(
        survivors.contains(&new_owner),
        "tenant went to node {new_owner}, which is not one of the surviving nodes {survivors:?}",
    );
    assert!(
        epoch_of(&cluster, leader).expect("epoch") > epoch_before,
        "ownership moved without advancing the fencing epoch — the old owner is not fenced",
    );
    assert_eq!(
        members_of(&cluster, leader),
        members_before,
        "the failover path changed the member map — failover must re-place onto \
         capacity that was already there, never provision (W246 §4)",
    );
}

// ── 2. Quorum loss freezes placement without stopping the read path ──────────

/// **Kill 2 of 3 voters: placement freezes, and the surviving node keeps
/// answering who owns what.** W253 §9's control/data-separation test.
///
/// This is the assertion that is easy to write vacuously — "nothing moved" is
/// also what a cluster that never had a working scheduler produces. Three
/// things make it non-vacuous:
///
/// 1. **Identical setup to test 1.** Same policy, same seeding, same
///    schedulers, same renewal pump, same tenant owned by a killed node. The
///    *only* difference is how many nodes die. Test 1 proves that setup places
///    a tenant within `BUDGET`; so the freeze here is the quorum loss, not a
///    scheduler that was never going to act.
/// 2. **The wait is the same window.** The freeze is asserted after a full
///    [`PLACEMENT_WINDOW`] of pumping — the window test 1 asserts a placement
///    lands inside, so this is not "we did not wait long enough".
/// 3. **The read path is asserted live, not just unchanged.** A survivor that
///    had wedged would also report an unchanged owner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn losing_quorum_freezes_placement_while_the_data_path_keeps_serving() {
    let policy = ClusterPolicy::rig();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let mut cluster: Cluster = test_cluster_with_policy(&provider, DummyRuntime, 3, policy)
        .await
        .expect("3-node rig cluster");

    let leader = cluster
        .wait_for_agreed_leader(BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let doomed: Vec<usize> = (0..3).filter(|i| *i != leader).collect();
    let owner_idx = doomed[0];
    let owner_id = cluster.node_id(owner_idx).expect("owner is a raft node");

    seed(&cluster, leader, owner_idx).await;
    assert_eq!(owner_of(&cluster, leader), Some(owner_id));
    let epoch_before = epoch_of(&cluster, leader).expect("epoch");

    let _schedulers = start_schedulers(&cluster, policy);
    pump_for(&cluster, leader, policy.liveness_thresholds().suspect_after * 3).await;

    // Both followers lose power. The survivor is the old leader — 1 of 3 is
    // not a quorum, so it steps down and can commit nothing.
    for idx in &doomed {
        cluster.kill_node(*idx).await.expect("power cut");
    }
    let survivor = leader;

    // Give the freeze every chance to fail: the same window test 1 asserts a
    // placement lands inside, of renewals and scheduler ticks. The dead nodes
    // *are* confirmed down here — the survivor's tracker watched them go
    // silent — so the scheduler has a trigger and is refused only by the
    // missing quorum, which is the property under test.
    pump_for(&cluster, survivor, PLACEMENT_WINDOW).await;

    assert_eq!(
        owner_of(&cluster, survivor),
        Some(owner_id),
        "placement moved with only 1 of 3 voters alive — a quorum-less control \
         plane must not re-place tenants (W253 §9)",
    );
    assert_eq!(
        epoch_of(&cluster, survivor),
        Some(epoch_before),
        "the fencing epoch advanced without a quorum, which means a transfer was \
         applied locally — the one thing that would let a healed cluster see two owners",
    );

    // ── the data path never stopped ──────────────────────────────────────────
    // Reads are answered off the survivor's own applied state; losing quorum
    // costs authority, never the ability to say who owns what. Asserted with a
    // timeout so "the read path stalled" fails rather than hangs.
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let survivor_url = cluster.yubaba(survivor).base_url.clone();
    for _ in 0..20 {
        let resp = http
            .get(format!("{survivor_url}/health"))
            .send()
            .await
            .expect("the survivor's read path must answer without a quorum");
        assert!(
            resp.status().is_success(),
            "a quorum-less node must still serve reads, got HTTP {}",
            resp.status()
        );
        tokio::time::sleep(PUMP).await;
    }
    assert_eq!(
        owner_of(&cluster, survivor),
        Some(owner_id),
        "the survivor must still be able to name the tenant's owner after \
         quorum loss — degraded authority, not a degraded read path",
    );
}

// ── 3. R782: a declared RPO bound gates which live candidate gets the tenant ──

/// **A dead owner's tenant re-places only onto a candidate whose streamer has
/// pushed fresh evidence — a live, admitting, region-eligible node with no
/// evidence at all is refused, not silently trusted.**
///
/// Tests 1/2 seed with `rpo_bound: None`, which is deliberate: they prove the
/// scheduler loop end to end without this gate in the mix. This is the one
/// live-cluster proof that R782's two plumbed inputs — `TenantPlacement.
/// rpo_bound` and `RpoWatermarkRegistry` — actually reach `judge_readiness`
/// together, the same way test 1 proves the lease channel does. `report_watermark`
/// substitutes for `tenant_streamer::rpo_report::RpoReporter`'s HTTP push, the
/// same way `renew_lease` substitutes for the node-lease client loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_declared_rpo_bound_refuses_a_candidate_with_no_streamer_evidence() {
    let policy = ClusterPolicy::rig();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let mut cluster: Cluster = test_cluster_with_policy(&provider, DummyRuntime, 3, policy)
        .await
        .expect("3-node rig cluster");

    let leader = cluster
        .wait_for_agreed_leader(BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let others: Vec<usize> = (0..3).filter(|i| *i != leader).collect();
    let victim = others[0]; // the tenant's soon-to-be-dead owner
    let victim_id = cluster.node_id(victim).expect("victim is a raft node");
    // The only candidate this test gives fresh RPO evidence to. Neither the
    // leader itself nor the victim — so the assertion below cannot pass by
    // accident of "whichever node the scheduler happens to prefer".
    let evidenced = others[1];
    let evidenced_id = cluster.node_id(evidenced).expect("evidenced is a raft node");

    seed_with_rpo_bound(&cluster, leader, victim, Some(Duration::from_secs(30))).await;
    assert_eq!(owner_of(&cluster, leader), Some(victim_id));

    let _schedulers = start_schedulers(&cluster, policy);
    pump_for(&cluster, leader, policy.liveness_thresholds().suspect_after * 3).await;

    // Fresh evidence for `evidenced` only, pushed straight into the leader's
    // registry (the only one `run()` ever reads — see the module doc on
    // `rpo_registry` in scheduler.rs). The leader itself and the victim get
    // none: the leader is a live, admitting, region-eligible candidate for
    // its own tenant (candidates exclude only the *owner*), so if the gate
    // were not actually wired in, `decide_transfer` would happily pick the
    // leader (lower id, or tie-break) instead.
    cluster.report_watermark(leader, evidenced, &tenant(), Some(Duration::from_secs(1)));

    cluster.kill_node(victim).await.expect("kill the owner");

    let placed = pump_until(&cluster, leader, PLACEMENT_WINDOW, |c| {
        owner_of(c, leader).is_some_and(|o| o != victim_id)
    })
    .await;
    assert!(placed, "the tenant never moved off its confirmed-dead owner");

    assert_eq!(
        owner_of(&cluster, leader),
        Some(evidenced_id),
        "the tenant must land specifically on the node with fresh RPO evidence, \
         not on whichever other live/admitting candidate the ranking preferred — \
         proof that streamer_watermark_age is actually reaching judge_readiness",
    );
}
