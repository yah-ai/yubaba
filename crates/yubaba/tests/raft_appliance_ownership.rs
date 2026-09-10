//! R858-T3 — **a yubaba restart on the appliance owner leaves the appliance in
//! place.**
//!
//! Part of R858-T3 — the canonical `@yah:ticket` annotation lives in
//! `src/leader.rs`. Credential-free and containerd-free: a real three-node
//! openraft cluster on loopback, the real
//! [`leader`](yubaba::leader) watcher and the real
//! [`member_registration`](yubaba::member_registration) loop on every node, and
//! a [`FakeRuntime`] standing in for kamaji.
//!
//! ```bash
//! cargo test -p yubaba --features testing --test testing -- raft_appliance_ownership::
//! ```
//!
//! # The property, and why it is the one that matters
//!
//! On 2026-09-03 a `POST /raft/transfer-leader` moved leadership off
//! us-west-001 and the mesh lost its coordination server for 37 hours, because
//! `ingress_ownership: FollowsRaftLeader` made the appliance's lifecycle a
//! function of consensus leadership. The operator's acceptance test for the fix
//! is deliberately smaller than a failover: *restart yubaba on the owner and the
//! appliance must not move.* Every fleet roll drains the leader, so until that
//! holds, rolling yubaba is indistinguishable from re-running the outage.
//!
//! A restart is a harder case than a leadership transfer, which is why it is the
//! one asserted here. It is *both* transitions at once and it erases the
//! process's memory:
//!
//! 1. Leadership leaves the owner while it is down — some peer wins an election
//!    and its watcher sees `false -> true`. Under the pre-fix rule that peer
//!    elects itself and takes the appliance.
//! 2. The owner comes back with an **empty** [`OwnerElection`]. Its own health
//!    ledger is a stack frame, so nothing in the process remembers that this
//!    node is the owner — the appliance reads as vacant, and a vacancy is
//!    something to elect yourself into.
//!
//! Both are answered by reading `ingress_owner` out of replicated state instead
//! of out of process memory, and both are exercised below by one restart.
//!
//! # Non-vacuity: the deploy fault is what gives the assertion teeth
//!
//! `FaultTarget::DeployWorkload` is armed **before** the restart, so from that
//! moment any attempt to (re)start the appliance anywhere fails — and
//! `leader.rs` answers a failed start by tearing down, which removes the
//! workload from the registry. So "the appliance is still `Running` at the end"
//! is not a statement that nothing was observed; it is a statement that *no node
//! attempted a start*, which is the actual claim. Remove the fault and the test
//! passes for the wrong reason; remove the fix and it fails.
//!
//! # One `FakeRuntime` per node, and why it had to become one per node
//!
//! This suite used to share a single runtime across the cluster, on an argument
//! that was true when it was written: a node asking "is the appliance running
//! *here*" only had its answer consulted when the replicated record named it, so
//! on every other node the answer was discarded and the shared registry could
//! not manufacture a pass.
//!
//! **R858-T7 made that false, and it is worth recording why rather than just
//! changing the line.** The fence has to stop a node that is serving an
//! appliance it does not own — a node which, by definition, the record does
//! *not* name. So the local-supervisor answer is now load-bearing on exactly
//! the nodes where it used to be ignored, and under one shared registry every
//! node reads "the appliance is running here", fences, and tears down the one
//! instance the cluster actually has. A shared runtime would turn a correct
//! implementation red.
//!
//! So every test here now takes a supervisor per node
//! (`test_cluster_with_runtimes`), and each assertion names which node's
//! registry it reads. That is also strictly stronger for the pre-existing
//! tests: "the appliance is still running" becomes "it is still running *on the
//! same node*", which is the claim they were always making in prose.

use std::sync::Arc;
use std::time::{Duration, Instant};

use cloud::provider::HetznerDriver;
use kamaji::fake::{FailMode, FakeRuntime, FaultTarget};
use kamaji::WorkloadStatus;
use yubaba::appliance_ownership::{FenceTiming, BACKOFF_BASE_SECS};
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::headscale_appliance;
use yubaba_test_harness::{test_cluster_with_runtimes, Cluster};

/// How long a fleet-preset cluster gets to elect, register and place the
/// appliance. The fleet election window is 1.5–3 s, so this is many elections
/// of headroom on a loaded machine — the same posture as the other raft suites,
/// which is what keeps a slow CI box from reading as a regression.
const SETTLE: Duration = Duration::from_secs(45);

/// How long the cluster is watched *after* the restart before the appliance is
/// declared to have stayed put. Long enough for the restarted node to rejoin,
/// for leadership to settle wherever it settles, and for every node's watcher to
/// have processed that transition.
const OBSERVE: Duration = Duration::from_secs(20);

/// This node's machine name, as both the leadership watcher and the member
/// registration loop see it.
///
/// Distinct per node, which `/etc/hostname` cannot be for three servers inside
/// one test process — and it has to be distinct, because
/// `YubabaStateMachine::node_for_machine` is the bridge from the `ingress_owner`
/// string back to a node id, and it resolves ties by lowest node id. Three nodes
/// claiming one hostname would make every record resolve to node 1.
fn machine_name(node_id: u64) -> String {
    format!("test-node-{node_id}")
}

/// Handles for the per-node daemon loops, aborted on drop.
///
/// The harness deliberately does not spawn these — `raft_leader_pin` and
/// `raft_tenant_placement` start their own loops for the same reason. Held in a
/// guard so a failing assertion cannot leave watchers running against a cluster
/// that is being torn down.
/// Keyed by node index, so one node's loops can be stopped without touching the
/// rest of the cluster's — which is what [`Self::stop`] exists for and what
/// `kill_node` alone cannot do.
struct Loops(Vec<(usize, tokio::task::JoinHandle<()>)>);

impl Drop for Loops {
    fn drop(&mut self) {
        for (_, h) in self.0.drain(..) {
            h.abort();
        }
    }
}

impl Loops {
    /// Start the real leadership watcher and member-registration loop on node
    /// `idx`, exactly as `main.rs` does — including handing **one** derived
    /// machine name to both, which is what makes `ingress_owner` and
    /// `MemberInfo::machine` comparable at all (R859-F2).
    fn start(&mut self, cluster: &Cluster, idx: usize) {
        self.start_inner(cluster, idx, false);
    }

    /// [`Self::start`] plus the real node-lease renewal loop (R858-T7).
    ///
    /// Separate rather than always-on because it is only the *expiry* suite
    /// that needs it, and it is the one thing here that talks HTTP to every
    /// peer on a 500 ms clock. Running the real loop — instead of the harness's
    /// `renew_lease` shortcut — is deliberate: expiry is only sound if the
    /// evidence it consumes is produced the way production produces it, and the
    /// bug this ticket found in `lease_renewal` (a leader renewing only itself
    /// leaves its successors with no sample for it, so a dead owner can never
    /// expire) is invisible to any test that injects the evidence by hand.
    fn start_with_leases(&mut self, cluster: &Cluster, idx: usize) {
        self.start_inner(cluster, idx, true);
    }

    /// Abort every loop belonging to node `idx`.
    ///
    /// **`Cluster::kill_node` is not sufficient on its own, and this is not
    /// bookkeeping tidiness — it is the difference between modelling a power
    /// cut and modelling a firewall rule.** `kill_node` shuts the node's raft
    /// actor down and aborts its HTTP server, so nothing can reach it. The
    /// per-node loops a test spawned are *outbound* clients, and they hold their
    /// own clones of the raft handle whose metrics watch keeps serving its last
    /// value after shutdown. So they keep running: `lease_renewal` goes on
    /// POSTing "node N is alive" to every peer, from a node that has no power.
    ///
    /// That is not a subtle inaccuracy. It makes the corpse's lease renew
    /// forever, so its silence never accrues, so the cluster never expires it —
    /// and a power-off test built on it hangs at exactly the assertion it exists
    /// to make. Measured: without this the survivors' `silence(dead)` sat at
    /// ~300 ms for the full ninety seconds after the kill.
    ///
    /// The same rule as the harness's own `kill_node` doc, one level up: a
    /// half-killed node is not a failure model, it is a different system.
    fn stop(&mut self, idx: usize) {
        self.0.retain(|(i, h)| {
            if *i == idx {
                h.abort();
                false
            } else {
                true
            }
        });
    }

    fn start_inner(&mut self, cluster: &Cluster, idx: usize, leases: bool) {
        // A restart replaces this node's loops; leaving the previous set running
        // would model two daemons on one node.
        self.stop(idx);
        let (Some(raft), Some(sm), Some(node_id), Some(state)) = (
            cluster.raft(idx),
            cluster.cluster_state(idx),
            cluster.node_id(idx),
            cluster.server_state(idx),
        ) else {
            panic!("node {idx} is missing raft wiring — this suite is local-tier only");
        };
        let machine = machine_name(node_id);
        self.0.push((
            idx,
            yubaba::member_registration::spawn(
                node_id,
                raft.clone(),
                sm.clone(),
                yubaba::raft::NodeDeclaration {
                    machine: Some(machine.clone()),
                    ..Default::default()
                },
            ),
        ));
        if leases {
            self.0.push((
                idx,
                yubaba::lease_renewal::spawn(
                    node_id,
                    raft.clone(),
                    cluster.lease_detector(idx).map(Arc::clone),
                    // Paced off the raft heartbeat, exactly as `main.rs` does.
                    Duration::from_millis(POLICY.timing.heartbeat_interval_ms.max(1)),
                ),
            ));
        }
        self.0.push((
            idx,
            yubaba::leader::spawn(node_id, raft.clone(), Arc::clone(&state), Some(machine)),
        ));
    }
}

/// Is the appliance present and `Running` in the supervisor's registry?
fn appliance_running(runtime: &FakeRuntime) -> bool {
    let ident = headscale_appliance::appliance_ident();
    runtime
        .snapshot()
        .into_iter()
        .any(|w| w.ident == ident && matches!(w.status, WorkloadStatus::Running))
}

/// The `ingress_owner` any node has applied, if the record has replicated there.
fn recorded_owner(cluster: &Cluster, idx: usize) -> Option<String> {
    cluster.cluster_state(idx)?.ingress_owner()
}

/// Poll until `cond`, or panic with `what` after `budget`.
async fn wait_for(budget: Duration, what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + budget;
    loop {
        if cond() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {budget:?} waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn a_yubaba_restart_on_the_owner_leaves_the_appliance_in_place() {
    // A runtime per node, and — critically — the *same* handles across the
    // restart. kamaji supervises the appliance; yubaba does not. A restarted
    // daemon coming back to a registry that still holds a running headscale is
    // exactly the fleet's shape, and a fresh registry would model a reboot
    // rather than a service restart.
    let (mut cluster, runtimes) = power_off_cluster().await;

    let mut loops = Loops(Vec::new());
    for idx in 0..cluster.node_count() {
        loops.start(&cluster, idx);
    }

    // ── 1. The cluster elects an appliance owner and stands it up ────────────
    // `settle_owner` asserts the precondition this test used to assert inline —
    // that the record and the running workload are on the same node — so a green
    // run cannot be one where neither was ever real.
    let (owner_idx, owner_machine) = settle_owner(&cluster, &runtimes).await;

    // ── 2. Arm the fault that makes any further start attempt visible ────────
    //
    // From here a deploy cannot succeed on ANY node, and `leader.rs` answers a
    // failed start by tearing the appliance down. So the appliance surviving to
    // the end of this test means no node tried to start it.
    fail_every_deploy(&runtimes);

    // ── 3. Restart yubaba on the owner ───────────────────────────────────────
    //
    // Kill + restart, not a leadership transfer: this is the operator's
    // rehearsal step and the thing every fleet roll does to every node.
    cluster
        .kill_node(owner_idx)
        .await
        .expect("kill the owner's yubaba");
    loops.stop(owner_idx);
    cluster
        .restart_node(owner_idx)
        .await
        .expect("restart the owner's yubaba");
    // A real restart brings the daemon's loops back with it, against the NEW
    // `ServerState` the restart built — hence re-reading it from the cluster
    // rather than reusing the handle from step 1.
    loops.start(&cluster, owner_idx);

    // ── 4. Watch, then assert ────────────────────────────────────────────────
    //
    // Leadership moved while the owner was down and moves again as it rejoins,
    // so every node's watcher sees at least one transition in this window. Under
    // the pre-fix rule each of those transitions is a self-election.
    let watch_until = Instant::now() + OBSERVE;
    while Instant::now() < watch_until {
        assert!(
            appliance_running_on(&runtimes, owner_idx),
            "the appliance was torn down after a yubaba restart on its owner \
             ({owner_machine}) — ownership is still following raft leadership (R858-T3)"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // The record must also still name the same machine. An appliance that is
    // running while the record has been rewritten to someone else is the split
    // this ticket calls worse than the outage.
    let after = (0..cluster.node_count())
        .filter_map(|i| recorded_owner(&cluster, i))
        .collect::<Vec<_>>();
    assert!(
        !after.is_empty() && after.iter().all(|m| m == &owner_machine),
        "ingress_owner moved off {owner_machine} across the restart: {after:?}"
    );

    cluster.destroy_all().await.ok();
}

/// `POST /raft/transfer-leader`, returning the HTTP status.
async fn post_transfer(base_url: &str, to: u64) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("{base_url}/raft/transfer-leader"))
        .json(&serde_json::json!({ "to": to }))
        .send()
        .await
        .expect("POST /raft/transfer-leader")
        .status()
}

/// The 2026-09-03 outage, replayed against the fix — and the sequence
/// `yah cloud rollout yubaba` performs on every wave.
///
/// The restart test above turns out **not** to cover this: a restart is faster
/// than the fleet preset's 1.5–3 s election window, so the owner reclaims
/// leadership without any peer ever winning it, and the arm that protects a
/// *peer* from electing itself is never reached. This drives leadership onto a
/// non-owner deterministically instead of hoping an election does, which is also
/// what the rollout executor does — `FollowersFirstLeaderLast` drains the leader
/// with exactly this call.
///
/// The claim is narrow and it is the whole of R858-T3: the node that receives
/// leadership must not conclude it has received the appliance.
#[tokio::test]
async fn transferring_raft_leadership_does_not_move_the_appliance() {
    let (mut cluster, runtimes) = power_off_cluster().await;

    let mut loops = Loops(Vec::new());
    for idx in 0..cluster.node_count() {
        loops.start(&cluster, idx);
    }

    let (owner_idx, owner_machine) = settle_owner(&cluster, &runtimes).await;
    let leader_idx = cluster
        .current_leader_idx()
        .expect("a leader, since a write just committed");
    // The node leadership is being handed TO — deliberately not the sitting
    // leader, which would make the transfer an idempotent no-op and the test
    // vacuous.
    let target_idx = (0..cluster.node_count())
        .find(|&i| i != leader_idx)
        .expect("a three-node cluster has a non-leader");
    let target_id = cluster.node_id(target_idx).expect("target node id");

    // Same fault as above: from here, any start attempt fails and `leader.rs`
    // answers a failed start by tearing down. The appliance surviving means no
    // node tried.
    fail_every_deploy(&runtimes);

    let status = post_transfer(&cluster.yubaba(leader_idx).base_url, target_id).await;
    assert!(
        status.is_success(),
        "POST /raft/transfer-leader to node {target_id}: HTTP {status}"
    );

    // Precondition for a non-vacuous run: leadership really did move, so the
    // target's watcher really did see a `false -> true` transition.
    wait_for(SETTLE, "leadership to land on the transfer target", || {
        cluster.current_leader_idx() == Some(target_idx)
    })
    .await;

    let watch_until = Instant::now() + OBSERVE;
    while Instant::now() < watch_until {
        assert!(
            appliance_running_on(&runtimes, owner_idx),
            "the appliance was torn down by a raft leadership transfer to node {target_id} \
             — this is the 2026-09-03 outage (R858-T3)"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let after = (0..cluster.node_count())
        .filter_map(|i| recorded_owner(&cluster, i))
        .collect::<Vec<_>>();
    assert!(
        !after.is_empty() && after.iter().all(|m| m == &owner_machine),
        "ingress_owner moved off {owner_machine} on a leadership transfer: {after:?}"
    );

    cluster.destroy_all().await.ok();
}

/// The owner is a **follower** and its appliance dies. Nothing gives it a
/// leadership edge, so only the reconcile clock can notice.
///
/// This is the hole a `yah cloud rollout yubaba` wave leaves, and it is not
/// hypothetical: `FollowersFirstLeaderLast` drains the leader *before*
/// restarting it, so the owner necessarily comes back as a follower. An
/// edge-driven watcher never looks at it again, and the two mechanisms R858-T3
/// is built on — the deploy-failure backoff expiring into a retry, and an
/// owner-of-record noticing its appliance is gone — are both unreachable
/// without a tick.
///
/// Non-vacuity here is structural rather than injected: the appliance is removed
/// from the supervisor directly, so a run in which nothing restarts it ends with
/// an empty registry and the assertion fails. There is no fault armed, because
/// the claim is the opposite of the other two tests' — this one requires a start
/// to happen.
#[tokio::test]
async fn a_follower_that_owns_the_appliance_restarts_it_without_a_leadership_change() {
    use kamaji::Kamaji as _;

    let (mut cluster, runtimes) = power_off_cluster().await;

    let mut loops = Loops(Vec::new());
    for idx in 0..cluster.node_count() {
        loops.start(&cluster, idx);
    }

    let (owner_idx, owner_machine) = settle_owner(&cluster, &runtimes).await;

    // Push leadership OFF the owner, so the rest of this test runs with the
    // owner as a follower — the posture a rolled leader comes back in.
    let leader_idx = cluster.current_leader_idx().expect("a leader");
    let target_idx = (0..cluster.node_count())
        .find(|&i| i != owner_idx && i != leader_idx)
        .or_else(|| (0..cluster.node_count()).find(|&i| i != owner_idx))
        .expect("some node other than the owner");
    let target_id = cluster.node_id(target_idx).expect("target node id");
    let status = post_transfer(&cluster.yubaba(leader_idx).base_url, target_id).await;
    assert!(status.is_success(), "transfer-leader: HTTP {status}");
    wait_for(SETTLE, "leadership to leave the owner", || {
        cluster.current_leader_idx().is_some_and(|l| l != owner_idx)
    })
    .await;

    // The appliance dies out from under yubaba. On the fleet this is the
    // pre-R858-T3 binary's teardown during the drain, a crashed headscale, or a
    // supervisor restart — from yubaba's side they are the same fact.
    let ident = headscale_appliance::appliance_ident();
    runtimes[owner_idx]
        .teardown_workload(&ident)
        .await
        .expect("remove the appliance from the supervisor");
    assert!(
        !appliance_running_on(&runtimes, owner_idx),
        "precondition: the appliance really is gone before the clock is given a chance"
    );

    // No leadership change from here. Only `RECONCILE_INTERVAL` can save it.
    wait_for(
        SETTLE,
        "the follower that owns the appliance to restart it on its own clock",
        || appliance_running_on(&runtimes, owner_idx),
    )
    .await;

    // And it came back where it belonged, not somewhere new.
    let after = (0..cluster.node_count())
        .filter_map(|i| recorded_owner(&cluster, i))
        .collect::<Vec<_>>();
    assert!(
        after.iter().all(|m| m == &owner_machine),
        "the appliance was restarted under a different owner: {after:?}"
    );

    cluster.destroy_all().await.ok();
}

// ─── R858-T7: ungraceful death ──────────────────────────────────────────────
//
// Everything above stages a *graceful* transition — a restart, a
// `transfer-leader`, a teardown yubaba performs on itself. The two tests below
// stage the one thing none of those model: the node stops, and nothing runs on
// it afterwards. No retraction, no `stop_headscale`, no goodbye. That is the
// distinction R858-T8's gotcha is emphatic about — "a rehearsal done with
// `systemctl stop` or a leadership transfer proves the happy path and skips the
// case this relay exists for" — and it is why `kill_node` is the only teardown
// verb either of them calls.
//
// # One supervisor per node, and it is the whole reason these can assert
// anything
//
// The suite above shares one `FakeRuntime` across the cluster and argues,
// correctly, that this cannot manufacture a pass for its claims. It would
// manufacture a *failure* for these. The property here is "**exactly one** node
// serves the appliance", and under a shared registry the two coordinators a
// fence exists to prevent collapse onto one entry under one `MeshIdent` — while
// a *correct* fence on the resurrected node tears down the very instance the new
// owner just deployed. So these use `test_cluster_with_runtimes`, which is
// `test_cluster` with a supervisor per node, and every assertion below names
// *which* node's registry it is reading.

/// The preset these run under. The fleet preset, like the rest of the suite:
/// `FenceTiming` is derived from its `LivenessThresholds`, and a test run at
/// LAN timings would measure the arithmetic rather than the shipped fleet's.
const POLICY: ClusterPolicy = ClusterPolicy::fleet();

/// How long a survivor gets to notice a dead owner and stand the appliance up
/// elsewhere.
///
/// Derived from the same `FenceTiming` the production path reads rather than
/// written as a number, so a change to the multipliers cannot leave this test
/// asserting against a deadline the code no longer has. The terms: the expiry
/// deadline itself, one full `leader::RECONCILE_INTERVAL` for the tick that
/// acts on it, one election, and generous slack for a loaded camp machine.
fn failover_budget() -> Duration {
    FenceTiming::from_thresholds(POLICY.liveness_thresholds()).expire_after
        + Duration::from_secs(60)
}

/// Is the appliance present and `Running` in **this node's** supervisor?
fn appliance_running_on(runtimes: &[FakeRuntime], idx: usize) -> bool {
    appliance_running(&runtimes[idx])
}

/// Arm `FaultTarget::DeployWorkload` on every node's supervisor.
///
/// With one shared runtime a single `fail_inject` covered the cluster. With one
/// per node it has to be armed on each, or "no node attempted a start" degrades
/// to "the node I happened to arm did not attempt one" — which is the weaker
/// claim the fault exists to rule out.
fn fail_every_deploy(runtimes: &[FakeRuntime]) {
    for rt in runtimes {
        rt.fail_inject(FaultTarget::DeployWorkload, FailMode::Always);
    }
}

/// Three nodes, one `FakeRuntime` each, under the fleet preset.
async fn power_off_cluster() -> (Cluster, Vec<FakeRuntime>) {
    let runtimes: Vec<FakeRuntime> = (0..3).map(|_| FakeRuntime::new()).collect();
    let erased: Vec<Arc<dyn kamaji::Kamaji + Send + Sync>> = runtimes
        .iter()
        .map(|r| Arc::new(r.clone()) as Arc<dyn kamaji::Kamaji + Send + Sync>)
        .collect();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let cluster = test_cluster_with_runtimes(&provider, erased, POLICY)
        .await
        .expect("three-node local cluster, one supervisor per node");
    (cluster, runtimes)
}

/// Drive the cluster to a placed appliance and return `(owner_idx,
/// owner_machine)`.
async fn settle_owner(cluster: &Cluster, runtimes: &[FakeRuntime]) -> (usize, String) {
    wait_for(SETTLE, "the appliance to be deployed somewhere", || {
        (0..runtimes.len()).any(|i| appliance_running_on(runtimes, i))
    })
    .await;
    wait_for(SETTLE, "the ingress-owner record to be written", || {
        (0..cluster.node_count()).any(|i| recorded_owner(cluster, i).is_some())
    })
    .await;

    let owner_machine = (0..cluster.node_count())
        .find_map(|i| recorded_owner(cluster, i))
        .expect("an owner record, just waited for");
    let owner_idx = (0..cluster.node_count())
        .find(|&i| cluster.node_id(i).map(machine_name).as_deref() == Some(&owner_machine))
        .unwrap_or_else(|| panic!("ingress_owner {owner_machine:?} names no node in this cluster"));

    // The record and the running workload must be on the SAME node, or every
    // assertion below is reading two unrelated facts.
    assert!(
        appliance_running_on(runtimes, owner_idx),
        "the recorded owner ({owner_machine}) is not the node running the appliance — the \
         preconditions for a power-off test were never met"
    );
    (owner_idx, owner_machine)
}

/// **EXPIRE.** Power off the owner and never bring it back: the survivors must
/// conclude the ownership record is stale and stand the appliance up elsewhere.
///
/// # What makes this different from every test above it
///
/// The dead node runs no code after the kill. It does not retract its service
/// record, it does not call `stop_headscale`, it does not release the claim, and
/// its `ingress_owner` entry goes on naming it in replicated state indefinitely.
/// `decide_owner` alone cannot move off it — its own doc says so: an owner that
/// is merely absent from the candidate map is *unjudged*, never ineligible, and
/// that rule is load-bearing for the restart tests above. So the only thing that
/// can produce a failover here is R858-T7's expiry: a survivor observing, on the
/// node-lease channel, that the owner has been silent past its own self-fence
/// deadline, and projecting that into the candidate map as positive evidence.
///
/// # Non-vacuity
///
/// Structural, not injected. The appliance is running on the killed node's
/// supervisor and *stays* running there (nothing tore it down — that is what a
/// power cut means), so "some node is serving" was already true before the kill
/// and cannot be what this passes on. The assertion is specifically that a
/// **survivor** is serving and that the **record has moved off the dead
/// machine**, neither of which any pre-T7 code path can produce.
#[tokio::test]
async fn a_powered_off_owner_expires_and_the_appliance_comes_up_on_a_survivor() {
    let (mut cluster, runtimes) = power_off_cluster().await;

    let mut loops = Loops(Vec::new());
    for idx in 0..cluster.node_count() {
        loops.start_with_leases(&cluster, idx);
    }

    let (owner_idx, owner_machine) = settle_owner(&cluster, &runtimes).await;

    // ── Pull the power ───────────────────────────────────────────────────────
    //
    // `kill_node` shuts the raft actor down and aborts the HTTP server. It does
    // NOT run any teardown, and it deliberately leaves this node's supervisor
    // registry holding a `Running` appliance — which is exactly the state a
    // power-cycled box comes back in, and the input the fence test below needs.
    loops.stop(owner_idx);
    cluster
        .kill_node(owner_idx)
        .await
        .expect("power off the appliance owner");
    assert!(
        appliance_running_on(&runtimes, owner_idx),
        "precondition: a power cut does not retract anything, so the dead node's supervisor \
         must still hold the appliance — otherwise this test is staging a graceful stop"
    );

    // ── The survivors must work it out from silence alone ────────────────────
    let survivors: Vec<usize> = (0..cluster.node_count())
        .filter(|&i| i != owner_idx)
        .collect();
    wait_for(
        failover_budget(),
        "a survivor to expire the dead owner and stand the appliance up",
        || {
            survivors
                .iter()
                .any(|&i| appliance_running_on(&runtimes, i))
        },
    )
    .await;

    // The record must have moved too. An appliance running on a survivor while
    // `ingress_owner` still names the corpse is a cluster that will fence its
    // own new coordinator on the next tick.
    wait_for(
        failover_budget(),
        "the ingress-owner record to stop naming the powered-off machine",
        || {
            survivors
                .iter()
                .any(|&i| recorded_owner(&cluster, i).is_some_and(|m| m != owner_machine))
        },
    )
    .await;

    cluster.destroy_all().await.ok();
}

/// **FENCE.** Restore power to the old owner: it must not serve.
///
/// R858-T8's verify names this as the assertion that matters most — "assert the
/// OLD node cannot serve after power is restored, which is the failure that is
/// worse than the outage". Two live coordinators on one tailnet hand diverging
/// copies of the node database to whichever clients still resolve to each, and
/// unlike an outage nothing about it is obvious from outside.
///
/// The resurrected node comes back with its supervisor still holding a
/// `Running` headscale — the honest model of both a kamaji that resumes
/// supervision and the boot-persistent `systemctl enable headscale` currently
/// live on us-west-001. Nothing asks it to stop. It has to work that out itself.
///
/// # Non-vacuity
///
/// The appliance is asserted `Running` on the resurrected node's own supervisor
/// at the moment its watcher starts, so "not running there" at the end is a
/// transition this test watched happen, not a state it inherited. And the second
/// assertion — that the *survivor's* appliance is still up — is what stops a
/// fence that simply stops everything from passing.
#[tokio::test]
async fn a_resurrected_owner_is_fenced_and_cannot_serve() {
    let (mut cluster, runtimes) = power_off_cluster().await;

    let mut loops = Loops(Vec::new());
    for idx in 0..cluster.node_count() {
        loops.start_with_leases(&cluster, idx);
    }

    let (owner_idx, owner_machine) = settle_owner(&cluster, &runtimes).await;
    let survivors: Vec<usize> = (0..cluster.node_count())
        .filter(|&i| i != owner_idx)
        .collect();

    loops.stop(owner_idx);
    cluster
        .kill_node(owner_idx)
        .await
        .expect("power off the appliance owner");

    wait_for(
        failover_budget(),
        "a survivor to take the appliance over",
        || {
            survivors
                .iter()
                .any(|&i| appliance_running_on(&runtimes, i))
        },
    )
    .await;
    let new_owner_idx = *survivors
        .iter()
        .find(|&&i| appliance_running_on(&runtimes, i))
        .expect("a survivor is serving, just waited for");
    wait_for(
        failover_budget(),
        "the ingress-owner record to name the survivor",
        || recorded_owner(&cluster, new_owner_idx).is_some_and(|m| m != owner_machine),
    )
    .await;

    // ── Power comes back ─────────────────────────────────────────────────────
    cluster
        .restart_node(owner_idx)
        .await
        .expect("restore power to the old owner");
    loops.start_with_leases(&cluster, owner_idx);
    assert!(
        appliance_running_on(&runtimes, owner_idx),
        "precondition: the resurrected node comes back with its appliance still up — that is \
         what a boot-persistent unit and a resuming supervisor both produce, and it is the \
         thing the fence has to stop. Without it this test asserts nothing."
    );

    // Its first reconcile tick reads a record naming somebody else and stops.
    wait_for(
        failover_budget(),
        "the resurrected owner to fence itself off the appliance",
        || !appliance_running_on(&runtimes, owner_idx),
    )
    .await;

    // And it fenced only itself. A fence that took the live coordinator down
    // with it would satisfy the assertion above and be strictly worse than the
    // split it prevents.
    assert!(
        appliance_running_on(&runtimes, new_owner_idx),
        "the resurrected node's fence tore down the SURVIVOR's appliance — the cluster now has \
         no coordinator at all"
    );

    // Exactly one, checked as a count rather than inferred from the two
    // assertions above, so a third node quietly starting one is not invisible.
    let serving: Vec<usize> = (0..cluster.node_count())
        .filter(|&i| appliance_running_on(&runtimes, i))
        .collect();
    assert_eq!(
        serving,
        vec![new_owner_idx],
        "exactly one node must serve the appliance after power is restored; these are serving: \
         {serving:?}"
    );

    // The record must still name the survivor. A resurrected node that fenced
    // its appliance but re-claimed the record would leave every front door
    // following ownership pointed at a node serving nothing.
    let after: Vec<String> = (0..cluster.node_count())
        .filter_map(|i| recorded_owner(&cluster, i))
        .collect();
    assert!(
        !after.is_empty() && after.iter().all(|m| m != &owner_machine),
        "ingress_owner went back to the powered-off machine {owner_machine} after it returned: \
         {after:?}"
    );

    cluster.destroy_all().await.ok();
}

// ─── R858-B13: the respawn loop ───────────────────────────────────────────────
//
// The live symptom these two cover, measured on us-west-001 on 2026-09-06:
// kamaji's journal showed `native workload forked id=headscale` 132 times in one
// 60-second window, `ss -lntp` showed nothing ever listening, and yubaba's own log
// claimed a successful deploy on every one of those cycles. Two INDEPENDENT
// defects produced it, and they need one test each — established by measurement,
// not by symmetry: with only the crash-loop test present, reintroducing the
// pacing defect left it green, and with only the pacing test present,
// reintroducing `record_success` left that green.
//
//  1. **The reconcile clock could not fire on a leader.** `leader::run` built its
//     `tokio::time::sleep(RECONCILE_INTERVAL)` *inside* the `select!`, so the
//     openraft metrics arm cancelled and rebuilt it on every heartbeat. The
//     ten-second arm was unreachable and reconciliation ran at consensus speed.
//     Covered by `the_appliance_reconciler_runs_on_its_own_clock_...`.
//  2. **A crash loop was recorded as a success.** `on_became_leader` returning
//     `Ok` meant "the supervisor accepted the workload", never "the process is
//     alive". `record_success` on that clears `OwnerElection`'s failure ledger,
//     so the 30 s backoff that exists for a node which cannot run the appliance
//     could never accumulate a single entry. Covered by
//     `a_crash_looping_appliance_is_retried_on_the_backoff_...`.

/// How long to wait for one deploy attempt to follow another.
///
/// Derived from the two clocks that bound a correct retry rather than written as
/// a number: the crash is noticed on the reconcile tick after the start, and the
/// retry is held for `BACKOFF_BASE_SECS` after that. Plus slack for a loaded camp
/// machine.
fn retry_budget() -> Duration {
    leader_reconcile_interval() + Duration::from_secs(BACKOFF_BASE_SECS) + Duration::from_secs(25)
}

/// `leader::RECONCILE_INTERVAL`, which is private. Kept as one named function so
/// the duplication is in one place and says so.
fn leader_reconcile_interval() -> Duration {
    Duration::from_secs(10)
}

/// Block until this runtime has answered one more `deploy_workload` than
/// `baseline`, and return when that happened.
async fn next_deploy_at(runtime: &FakeRuntime, baseline: usize, budget: Duration) -> Instant {
    let deadline = Instant::now() + budget;
    loop {
        if runtime.deploy_calls().len() > baseline {
            return Instant::now();
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {budget:?} waiting for the appliance owner to attempt deploy \
             #{} — a crash-looping appliance must be RETRIED on a backoff, and a fix that \
             simply stops restarting it is the outage this relay exists to end, not a pass \
             (R858-B13)",
            baseline + 1
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// **The respawn loop.** An appliance that dies the instant it starts must be
/// retried on `OwnerElection`'s backoff — not restarted on every pass of the
/// control loop.
///
/// # The fixture
///
/// A reaper task flips the appliance out of `Running` in the owner's supervisor
/// within ~10 ms of every deploy. That is what a `headscale` exiting immediately
/// looks like to `observe_local_appliance`, which is the only evidence this node
/// has: kamaji reports the workload gone, and yubaba has to decide what to do
/// about it. Nothing else is injected — no fault, no fence, no kill. The node
/// stays the leader, stays the recorded owner, and stays eligible.
///
/// # What is asserted, and why it is a GAP rather than a count
///
/// The interval between the deploy that placed the appliance and the retry after
/// it died. A rate bound over a window was tried first and is **vacuous**:
/// measured, with `record_success` restored on the start path, a 45-second window
/// admits four redeploys and a correct backoff admits two, which no honest bound
/// separates. The gap does separate them exactly — a backed-off retry cannot come
/// sooner than `BACKOFF_BASE_SECS`, and a loop that records a crash as a success
/// retries on the next `RECONCILE_INTERVAL`, three times sooner.
///
/// # Non-vacuity
///
/// Structural, in both directions. The retry is *waited for*, so this cannot pass
/// because nothing happened: a fix that stopped restarting the appliance
/// altogether — the other way to make a respawn loop go away, and a worse one —
/// fails inside `next_deploy_at` rather than sliding through a gap assertion that
/// is trivially satisfied by an infinite gap. And the reaper's kill count is
/// asserted, so a run in which the appliance was never actually destroyed cannot
/// report a passing gap between two events that had nothing to do with a crash.
///
/// # Falsification
///
/// Restore `election.record_success(node_id)` (and drop `*start_awaiting_proof =
/// true`) in `ElectTo`'s `Ok` arm in `leader.rs`: the ledger is cleared on every
/// start, the backoff never accumulates, and the gap collapses to one
/// `RECONCILE_INTERVAL`.
#[tokio::test]
async fn a_crash_looping_appliance_is_retried_on_the_backoff_not_on_every_pass() {
    let (mut cluster, runtimes) = power_off_cluster().await;

    let mut loops = Loops(Vec::new());
    for idx in 0..cluster.node_count() {
        loops.start(&cluster, idx);
    }

    let (owner_idx, owner_machine) = settle_owner(&cluster, &runtimes).await;

    // The reaper: `headscale` exiting the moment kamaji forks it.
    let kills = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reaper = {
        let runtime = runtimes[owner_idx].clone();
        let kills = Arc::clone(&kills);
        tokio::spawn(async move {
            let ident = headscale_appliance::appliance_ident();
            loop {
                if appliance_running(&runtime) {
                    let n = kills.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    runtime.mark_restarting(ident.0.clone(), 1, n as u32, 0);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    };

    // `settle_owner` returns within one 200 ms poll of the deploy that placed the
    // appliance, so this is that deploy's timestamp to well inside the tolerance
    // a thirty-second threshold has. Measuring from here rather than from a
    // second observed deploy keeps the test to one backoff step: the ledger
    // doubles (30 → 60 → …), so waiting for a *third* attempt would mean sitting
    // out 60 s more for no extra claim.
    let first = Instant::now();
    let baseline = runtimes[owner_idx].deploy_calls().len();
    let second = next_deploy_at(&runtimes[owner_idx], baseline, retry_budget()).await;
    let gap = second - first;
    reaper.abort();

    let killed = kills.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        killed > 0,
        "the fixture never armed: the reaper never caught the appliance running, so nothing \
         crashed and the gap measured below is the gap between two unrelated events"
    );
    assert!(
        gap >= Duration::from_secs(BACKOFF_BASE_SECS),
        "the owner ({owner_machine}) restarted the crash-looping appliance {gap:?} after the \
         previous attempt — below `BACKOFF_BASE_SECS` ({BACKOFF_BASE_SECS}s), so the failure \
         ledger is not accumulating and the appliance is being respawned faster than it can \
         bind its ports (R858-B13)"
    );

    // The loop must not have leaked onto the other nodes either: a follower that
    // is not the recorded owner has nothing to start, and an owner in backoff
    // must not be replaced by a peer that cannot see it is broken.
    for idx in 0..cluster.node_count() {
        if idx == owner_idx {
            continue;
        }
        assert!(
            !appliance_running_on(&runtimes, idx),
            "node {idx} started a second appliance while the recorded owner was crash-looping — \
             two coordinators is the failure that is worse than the outage"
        );
    }

    cluster.destroy_all().await.ok();
}

/// How long the reconciler's cadence is sampled. A little over one
/// `leader::RECONCILE_INTERVAL`, so a correctly-paced loop is expected to pass
/// through it once or twice and a loop running at raft-heartbeat rate cannot
/// look like one.
const CADENCE_WINDOW: Duration = Duration::from_secs(12);

/// The most reconcile passes that may happen inside [`CADENCE_WINDOW`] on a
/// cluster where nothing is wrong.
///
/// One per ten seconds, plus slack for the boundary and for a leadership edge
/// that legitimately forces one. Four is generous; the pre-fix loop produced
/// upwards of twenty per second.
const MAX_RECONCILES_IN_WINDOW: usize = 4;

/// **The pacing.** With nothing wrong anywhere, the appliance reconciler must run
/// on its own ten-second clock — not once per raft heartbeat.
///
/// # Why this is a separate test from the crash-loop one
///
/// Because the crash-loop test does not cover it, which was established by
/// measurement rather than assumed: with the pacing defect reintroduced and the
/// backoff fix left in place, that test still passes. `OwnerElection`'s backoff
/// bounds the *deploys* whatever the loop's rate is. So the rate needs its own
/// assertion, or a future edit could restore the heartbeat-rate loop and every
/// test in this file would stay green while every node in the fleet went back to
/// asking its supervisor about the appliance twenty times a second.
///
/// # What is being counted
///
/// `get_workload` calls on the owner's supervisor. `reconcile_appliance_ownership`
/// asks exactly once per pass (through `observe_local_appliance`, before any
/// early return), so this counter is the reconciler's cadence with nothing else
/// mixed in — no HTTP handler is touched by this test and no other loop in the
/// harness calls it.
///
/// # Falsification
///
/// Restore the pre-B13 shape of `leader::run` — drop the `reconcile_due` gate and
/// build the timer as `_ = tokio::time::sleep(RECONCILE_INTERVAL)` inside the
/// `select!` — and this fails with a count in the hundreds.
#[tokio::test]
async fn the_appliance_reconciler_runs_on_its_own_clock_not_at_raft_heartbeat_rate() {
    let (mut cluster, runtimes) = power_off_cluster().await;

    let mut loops = Loops(Vec::new());
    for idx in 0..cluster.node_count() {
        loops.start(&cluster, idx);
    }

    let (owner_idx, owner_machine) = settle_owner(&cluster, &runtimes).await;

    // From here, not from the start: settling deliberately drives several passes
    // (an election edge, a deploy, the record landing), and charging those to the
    // steady state would measure the setup instead of the loop.
    let before = runtimes[owner_idx].get_workload_calls();
    tokio::time::sleep(CADENCE_WINDOW).await;
    let passes = runtimes[owner_idx].get_workload_calls() - before;

    assert!(
        passes > 0,
        "the reconciler did not run at all on the owner ({owner_machine}) in {CADENCE_WINDOW:?} — \
         its clock is not merely slow, it has stopped, and every retry rule that depends on it is \
         dead (R858-T3 defect 3)"
    );
    assert!(
        passes <= MAX_RECONCILES_IN_WINDOW,
        "the appliance reconciler ran {passes} times in {CADENCE_WINDOW:?} on the owner \
         ({owner_machine}) — it is paced off the raft metrics watch rather than \
         `leader::RECONCILE_INTERVAL`, which is what forked the live coordinator's headscale \
         ~2.5 times a second on 2026-09-06 (R858-B13)"
    );

    cluster.destroy_all().await.ok();
}

/// **SETTLE (R858-B20).** A rebooted owner must not start a coordinator off its
/// own replayed record.
///
/// The sibling test above,
/// `a_resurrected_owner_is_fenced_and_cannot_serve`, models a resurrection in
/// which the appliance is *still running* on the returning node — a resuming
/// supervisor, or the boot-persistent `systemctl enable headscale`. That is the
/// teardown shape, and the fence handles it.
///
/// This is the other shape, and it is the one that was measured on real
/// hardware. A hard reset does not resume anything: `us-west-011` came back on
/// 2026-09-08 with kamaji holding no workloads at all, so
/// `observe_local_appliance` answered `None` and the node did not need to be
/// *stopped* — it needed to be stopped from **starting**. It read its own
/// pre-failover state machine, found its own name in `ingress_owner` 0.6 s after
/// learning who the leader was, took the elect path, forked a second headscale
/// on a stale database, and pushed frames from that database into the shared
/// litestream prefix for 9.7 s until the fence caught up.
///
/// So the assertion here is deliberately not "it stopped": it is that the
/// resurrected node's supervisor is **never asked to deploy**, at all, for the
/// whole of the window in which the old code deployed.
///
/// # Non-vacuity
///
/// Two guards, because "no deploy happened" is the easiest assertion in the file
/// to pass for the wrong reason.
///
/// * The deploy counter is snapshotted *before* the restart and compared, so a
///   node that never deployed anything in the first place cannot make this pass
///   — the count has to be unchanged across a period in which the node was
///   demonstrably alive and reconciling.
/// * A survivor must be serving throughout. If the failover had not happened,
///   the record would still name the returning node, its claim would be
///   legitimate, and refusing to act would be a bug rather than the fix.
#[tokio::test]
async fn a_rebooted_owner_does_not_start_a_coordinator_off_its_stale_record() {
    use kamaji::Kamaji;

    let (mut cluster, runtimes) = power_off_cluster().await;

    let mut loops = Loops(Vec::new());
    for idx in 0..cluster.node_count() {
        loops.start_with_leases(&cluster, idx);
    }

    let (owner_idx, owner_machine) = settle_owner(&cluster, &runtimes).await;
    let survivors: Vec<usize> = (0..cluster.node_count())
        .filter(|&i| i != owner_idx)
        .collect();

    // ── Pull the power, and lose the process with it ─────────────────────────
    //
    // The teardown is what makes this a REBOOT rather than the suspend the
    // sibling test models. It is done on the runtime directly, not through
    // yubaba, precisely because nothing in the cluster is supposed to have
    // retracted anything — the box simply stopped existing and came back empty.
    loops.stop(owner_idx);
    cluster
        .kill_node(owner_idx)
        .await
        .expect("power off the appliance owner");
    runtimes[owner_idx]
        .teardown_workload(&headscale_appliance::appliance_ident())
        .await
        .expect("a hard reset leaves the supervisor holding nothing");
    assert!(
        !appliance_running_on(&runtimes, owner_idx),
        "precondition: this test is about a node that comes back with NO appliance, so that the \
         path under test is the one that STARTS one rather than the one that stops one"
    );

    wait_for(
        failover_budget(),
        "a survivor to expire the dead owner and take the appliance over",
        || {
            survivors
                .iter()
                .any(|&i| appliance_running_on(&runtimes, i))
        },
    )
    .await;
    let new_owner_idx = *survivors
        .iter()
        .find(|&&i| appliance_running_on(&runtimes, i))
        .expect("a survivor is serving, just waited for");
    wait_for(
        failover_budget(),
        "the ingress-owner record to name the survivor",
        || recorded_owner(&cluster, new_owner_idx).is_some_and(|m| m != owner_machine),
    )
    .await;

    // ── Power comes back, on a state machine replayed from disk ──────────────
    let deploys_before = runtimes[owner_idx].deploy_calls().len();
    cluster
        .restart_node(owner_idx)
        .await
        .expect("restore power to the old owner");
    loops.start_with_leases(&cluster, owner_idx);

    // Long enough to cover the settle window and a reconcile pass past it, so a
    // pass that WOULD have deployed has had every opportunity to.
    let timing = FenceTiming::from_thresholds(POLICY.liveness_thresholds());
    let observation = timing.settle_after + Duration::from_secs(15);
    let deadline = Instant::now() + observation;
    while Instant::now() < deadline {
        assert_eq!(
            runtimes[owner_idx].deploy_calls().len(),
            deploys_before,
            "the rebooted owner ({owner_machine}) asked its supervisor to deploy the appliance. \
             It is not the raft leader and the record names {:?} — it acted on its own replayed \
             pre-failover state machine, which is R858-B20 and is one half of a split brain",
            recorded_owner(&cluster, new_owner_idx)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        !appliance_running_on(&runtimes, owner_idx),
        "the rebooted owner is serving a coordinator it never legitimately claimed"
    );
    assert!(
        appliance_running_on(&runtimes, new_owner_idx),
        "the survivor stopped serving during the observation window — this test would then be \
         asserting that nobody is a coordinator, which is the outage rather than the fix"
    );

    cluster.destroy_all().await.ok();
}
