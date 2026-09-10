//! R118-F8 — the membership ratchet, on five real nodes.
//!
//! Part of R118-F8 — the canonical `@yah:ticket` annotation lives in the
//! noisetable camp at `crates/society/core/src/lib.rs`. The design is
//! `.yah/docs/working/W138-installation-as-a-cluster.md` §"the ratchet" and
//! `.yah/docs/working/W158-wedge-recovery-decision.md` §7.2 in that same camp.
//!
//! Four claims, and the second is the one that matters:
//!
//! 1. **It shrinks while quorum still holds, and does not stop at two.** Five
//!    voters, a strip takes two, then a third goes: the cluster ends at one
//!    voter with four learners, and the elapsed time from the *first* loss is
//!    `W158` §7.2(1)'s headline metric, reported by
//!    [`five_voters_losing_two_then_one_more_ratchet_down_to_a_single_voter`].
//! 2. **It does not shrink a peer it can still hear.** `R118-F7` built the
//!    partition primitive this needs and stated the safety rule it enforces:
//!    absence of evidence is the permission, *presence of it is a veto*. A
//!    partitioned-but-radiating node keeps its vote —
//!    [`a_partitioned_but_radiating_voter_keeps_its_vote`].
//! 3. **`Unknown` vetoes too**, and that is the inversion a naive gate gets
//!    wrong: `Unknown` is the observer's own blindness, and blindness is not
//!    evidence of a dead peer.
//! 4. **The fleet never shrinks** under the identical stimulus.
//!
//! # These are not vacuity-proof by construction, so each one carries a control
//!
//! A test that asserts "the voter set did not change" passes just as happily
//! when the ratchet is not running at all. Tests 2 and 3 therefore end by
//! restating the *same* peer's verdict as `Dark`, against the *same* cluster and
//! the *same* code path, and asserting the set then does change. That negative
//! control is what makes the preceding assertion mean "the verdict vetoed it"
//! rather than "nothing happened".
//!
//! Test 4 is built the same way: one cluster, one set of dark verdicts, and
//! [`run_once`] called twice — once with [`ClusterPolicy::fleet`] and once with
//! [`ClusterPolicy::rig`]. The only difference between the two calls is the
//! policy field, which is the entire claim.
//!
//! # Rig policy, and `wait_for_agreed_leader`
//!
//! `test_cluster_with_policy(.., ClusterPolicy::rig())` because a ratchet
//! measured on WAN election bounds is a measurement of the wrong system. And
//! `wait_for_agreed_leader`, never `wait_for_leader`: straight after a kill the
//! survivors unanimously still believe in the dead leader, and a failover
//! assertion that accepts that belief asserts nothing.
//!
//! ```bash
//! cargo test -p yubaba --test main -- raft_membership_ratchet:: --test-threads=2
//! ```

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use cloud::provider::HetznerDriver;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::membership_ratchet::{run_once, RatchetOutcome};
use yubaba::raft::{PeerLivenessVerdict, YubabaNodeId};
use yubaba::runtime::DummyRuntime;
use yubaba_test_harness::{test_cluster_with_policy, Cluster};

/// Generous: the rig's election window is 450–900 ms, so this is many elections
/// of headroom on a machine also running the rest of the suite.
const FAILOVER_BUDGET: Duration = Duration::from_secs(20);

/// The ceiling this ticket's headline metric is asserted against. Not a target —
/// the measured number is printed and is what gets reported — but a ceiling that
/// would catch the ratchet silently degrading into "eventually, on a retry
/// storm".
const RATCHET_BUDGET: Duration = Duration::from_secs(60);

/// Unix seconds, the same clock `run_once` is normally handed.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs()
}

/// The rig's promotion hold-down, restated so the tests that step over it say
/// which number they are stepping over.
const PROMOTE_HOLD_DOWN_SECS: u64 = 300;

/// `ClusterPolicy::rig()` with a wider **evidence** window, for the tests that
/// step the injected clock past the promotion hold-down.
///
/// # Why this is needed, and why it is not a weakened test
///
/// `run_once` reads one `now` and judges two things against it: how long a
/// learner has been continuously alive (300 s to clear) and how stale each
/// liveness report is (30 s to expire). The rig runs a hold-down **ten times**
/// its evidence TTL on purpose — in production the reporter restates every
/// unchanged verdict every 10 s (`LivenessReporter::restate_after`), so the
/// evidence stays fresh across a hold-down it far outlives.
///
/// A test cannot restate thirty times across 300 *simulated* seconds: the
/// timestamps are stamped server-side by the handler, at the real clock. Step
/// the injected clock to `now + 301` under the rig's own TTL and every report
/// ages out at once, every peer folds to `Unknown`, and the tick holds for a
/// reason that has nothing to do with the thing under test — which is exactly
/// what the first run of these two tests reported.
///
/// So the window is widened rather than the hold-down shortened. The state
/// reached is the one production reaches (fresh evidence, hold-down elapsed);
/// the number that is *not* exercised here is the TTL, which
/// `raft::tests::a_dead_observers_stale_alive_stops_vetoing_once_it_ages_out`
/// covers directly. The production value stays pinned by
/// `cluster_policy::tests::the_rigs_promotion_hold_down_matches_r118_f7s_darkness_hold_down`.
fn rehydration_policy() -> ClusterPolicy {
    ClusterPolicy {
        membership_ratchet: yubaba::cluster_policy::MembershipRatchet::ShrinkToSurvivors {
            floor: yubaba::cluster_policy::VoterFloor::ONE,
            evidence_ttl_secs: 3_600,
            promote_hold_down_secs: PROMOTE_HOLD_DOWN_SECS,
        },
        ..ClusterPolicy::rig()
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client")
}

/// Node ids are 1-indexed: node 0 → id 1.
fn id_of(idx: usize) -> YubabaNodeId {
    idx as YubabaNodeId + 1
}

/// `POST /v1/nodes/{observer}/peer-liveness` — the loopback seam noisetable's
/// `R118-F7` detector reports through, driven here by hand.
///
/// Reports a **whole view** from one observer, which is what a detector holds:
/// every peer it is not, at one evaluation instant.
async fn report_view(
    http: &reqwest::Client,
    base_url: &str,
    observer: YubabaNodeId,
    node_count: usize,
    dark: &BTreeSet<YubabaNodeId>,
    special: &[(YubabaNodeId, PeerLivenessVerdict)],
) {
    let peers: Vec<serde_json::Value> = (0..node_count)
        .map(id_of)
        .filter(|id| *id != observer)
        .map(|id| {
            let verdict = special
                .iter()
                .find(|(sid, _)| *sid == id)
                .map(|(_, v)| *v)
                .unwrap_or(if dark.contains(&id) {
                    PeerLivenessVerdict::Dark
                } else {
                    PeerLivenessVerdict::Alive
                });
            serde_json::json!({
                "node_id": id,
                "verdict": verdict,
                "detail": format!("harness view from node {observer}"),
            })
        })
        .collect();

    let resp = http
        .post(format!("{base_url}/v1/nodes/{observer}/peer-liveness"))
        .json(&serde_json::json!({ "peers": peers }))
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST peer-liveness to {base_url}: {e}"));
    assert!(
        resp.status().is_success(),
        "peer-liveness report from node {observer} rejected: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Report the same view from every node the harness still considers running.
///
/// A killed node reports nothing, which is the point: its last opinions age out
/// under the policy's evidence TTL instead of vetoing forever. A *partitioned*
/// node is still running and still answers `/v1/nodes/...`, but its write is
/// forwarded through a raft it no longer has, so it is skipped here rather than
/// left to fail — the majority side is what the leader reads.
async fn report_from_survivors(
    cluster: &Cluster,
    http: &reqwest::Client,
    dark: &BTreeSet<YubabaNodeId>,
    special: &[(YubabaNodeId, PeerLivenessVerdict)],
) {
    let n = cluster.node_count();
    for idx in 0..n {
        if !cluster.is_running(idx) || cluster.is_partitioned(idx) {
            continue;
        }
        let base = cluster.yubaba(idx).base_url.clone();
        report_view(http, &base, id_of(idx), n, dark, special).await;
    }
}

/// The voter set as raft itself holds it — the oracle independent of every HTTP
/// surface under test.
fn voters(cluster: &Cluster) -> BTreeSet<YubabaNodeId> {
    use openraft::async_runtime::watch::WatchReceiver;
    for idx in 0..cluster.node_count() {
        if let Some(raft) = cluster.raft(idx) {
            return raft
                .metrics()
                .borrow_watched()
                .membership_config
                .membership()
                .voter_ids()
                .collect();
        }
    }
    panic!("no live raft handle in the cluster");
}

/// Tick the ratchet on the current leader until the voter set reaches `want`,
/// or the budget expires.
///
/// Drives [`run_once`] explicitly rather than sleeping against
/// [`yubaba::membership_ratchet::spawn`]'s background loop: the decision path is
/// identical, and a test that owns the tick reports a *measurement* rather than
/// a multiple of somebody's poll interval.
async fn ratchet_until(
    cluster: &Cluster,
    http: &reqwest::Client,
    policy: &ClusterPolicy,
    want: usize,
    budget: Duration,
) -> BTreeSet<YubabaNodeId> {
    ratchet_until_at(cluster, http, policy, want, budget, now_secs).await
}

/// [`ratchet_until`] with the clock the decision reads supplied by `clock`.
///
/// `run_once` takes `now` rather than reading the wall clock, which is what
/// makes the rehydration hold-down testable at all: `R118-F8`'s promotion
/// hold-down is 300 s and no test may sleep for it. Pass `now_secs` for the real
/// one; pass a closure returning `now + 400` to stand where a stable learner has
/// already cleared it.
async fn ratchet_until_at(
    cluster: &Cluster,
    http: &reqwest::Client,
    policy: &ClusterPolicy,
    want: usize,
    budget: Duration,
    clock: fn() -> u64,
) -> BTreeSet<YubabaNodeId> {
    let deadline = Instant::now() + budget;
    let mut last = String::from("(never ticked)");
    loop {
        let current = voters(cluster);
        if current.len() == want {
            return current;
        }
        for idx in 0..cluster.node_count() {
            let (Some(raft), Some(sm), Some(node_id)) = (
                cluster.raft(idx),
                cluster.cluster_state(idx),
                cluster.node_id(idx),
            ) else {
                continue;
            };
            match run_once(node_id, raft, sm, policy, http, clock()).await {
                RatchetOutcome::NotLeader => {}
                other => last = format!("node {node_id}: {other:?}"),
            }
        }
        if Instant::now() > deadline {
            panic!(
                "voter set never reached {want} within {budget:?}; it is {:?} and the last \
                 ratchet outcome was {last}",
                voters(cluster)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Tick the ratchet on every node once, and return the leader's outcome.
async fn tick_once(
    cluster: &Cluster,
    http: &reqwest::Client,
    policy: &ClusterPolicy,
) -> RatchetOutcome {
    tick_once_at(cluster, http, policy, now_secs()).await
}

/// [`tick_once`] at an explicit `now`.
async fn tick_once_at(
    cluster: &Cluster,
    http: &reqwest::Client,
    policy: &ClusterPolicy,
    now: u64,
) -> RatchetOutcome {
    let mut outcome = RatchetOutcome::NotLeader;
    for idx in 0..cluster.node_count() {
        let (Some(raft), Some(sm), Some(node_id)) = (
            cluster.raft(idx),
            cluster.cluster_state(idx),
            cluster.node_id(idx),
        ) else {
            continue;
        };
        match run_once(node_id, raft, sm, policy, http, now).await {
            RatchetOutcome::NotLeader => {}
            other => outcome = other,
        }
    }
    outcome
}

/// **The headline metric.** Five voters, a power strip takes two, then a third
/// board dies — and the cluster ends at a single voter rather than wedged.
///
/// The two shrinks are different arguments. `5 → 3` demotes only nodes that are
/// dark: three of five survive, so a membership change still commits, and that
/// is the whole thesis — *act while the window is open*. `3 → 1` also demotes a
/// node that is perfectly alive, because the alternative resting place is two
/// voters, which tolerates zero further losses and is therefore strictly worse
/// than one. The tie-break has to be spent here, while both survivors can still
/// commit the decision; after the next loss there is no quorum left to decide
/// anything with.
///
/// `retain = true` throughout, so every demoted node is a **learner** still
/// replicating, not an evicted one — which is what makes rehydration a promotion
/// rather than a rejoin. Asserted directly on the membership's node set.
#[tokio::test]
async fn five_voters_losing_two_then_one_more_ratchet_down_to_a_single_voter() {
    let policy = ClusterPolicy::rig();
    let mut cluster =
        test_cluster_with_policy(&HetznerDriver::new("unused-on-local-tier"), DummyRuntime, 5, policy)
            .await
            .expect("5-node rig cluster");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("initial leader");
    assert_eq!(voters(&cluster), BTreeSet::from([1, 2, 3, 4, 5]));

    let http = client();

    // The strip trips. Nodes 4 and 5 (ids 5 and 4) lose power together — a
    // correlated failure, which is the rig's actual failure domain.
    let first_loss = Instant::now();
    cluster.kill_node(4).await.expect("kill node 5");
    cluster.kill_node(3).await.expect("kill node 4");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("leader after losing two of five");

    let dark = BTreeSet::from([4, 5]);
    report_from_survivors(&cluster, &http, &dark, &[]).await;
    let after_first = ratchet_until(&cluster, &http, &policy, 3, RATCHET_BUDGET).await;
    assert_eq!(
        after_first,
        BTreeSet::from([1, 2, 3]),
        "the ratchet must demote exactly the dark voters while quorum still holds"
    );

    // A third board dies. Two of three survive, so a membership change still
    // commits — and this is the last moment at which one ever will.
    cluster.kill_node(2).await.expect("kill node 3");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("leader after losing three of five");

    let dark = BTreeSet::from([3, 4, 5]);
    report_from_survivors(&cluster, &http, &dark, &[]).await;
    let after_second = ratchet_until(&cluster, &http, &policy, 1, RATCHET_BUDGET).await;
    let elapsed = first_loss.elapsed();

    assert_eq!(
        after_second.len(),
        1,
        "the resting place is ONE voter, not two: two tolerates zero losses while requiring \
         both nodes for every write. Got {after_second:?}"
    );
    assert!(
        after_second.iter().all(|id| *id == 1 || *id == 2),
        "the surviving voter must be one of the two live nodes, not a dark one: {after_second:?}"
    );

    // `retain = true`: demoted, not evicted. Every one of the five is still in
    // membership, so a returning plinth is a promotion away from voting again.
    {
        use openraft::async_runtime::watch::WatchReceiver;
        let raft = cluster.raft(0).or_else(|| cluster.raft(1)).expect("a live raft");
        let membership = raft
            .metrics()
            .borrow_watched()
            .membership_config
            .membership()
            .clone();
        let known: BTreeSet<YubabaNodeId> = membership.nodes().map(|(id, _)| *id).collect();
        assert_eq!(
            known,
            BTreeSet::from([1, 2, 3, 4, 5]),
            "retain=true demotes to learner and must never evict — a demoted node that left \
             membership turns rehydration into a full rejoin"
        );
    }

    // W158 §7.2(3): the change is stamped, so a returning learner can tell "I
    // was demoted" from "my cluster was replaced" without asking anyone.
    let sm = cluster
        .cluster_state(0)
        .or_else(|| cluster.cluster_state(1))
        .expect("a live state machine");
    let record = sm
        .last_membership_ratchet()
        .expect("the ratchet must record the membership change it made");
    assert!(
        record.membership_index > 0 && !record.demoted.is_empty(),
        "the record must name a real membership entry and the nodes it demoted: {record:?}"
    );
    assert!(
        record.membership_term > 0,
        "a membership entry committed by a leader has a non-zero term: {record:?}"
    );
    // The epoch stamp itself, by VALUE. Asserting only that a record exists
    // would pass against a record carrying zeros, and a returning node reading
    // `cluster_protocol: 0` would conclude it was from a foreign build.
    assert_eq!(
        (record.cluster_protocol, record.state_epoch),
        (
            yubaba::cluster_epoch::CLUSTER_PROTOCOL,
            yubaba::cluster_epoch::STATE_EPOCH
        ),
        "W158 §7.2(3): the change must be stamped with THIS build's epochs, so a returning node \
         can tell a demotion from a cluster it can no longer join: {record:?}"
    );
    assert_eq!(record.after.len(), 1, "the record must describe what it did: {record:?}");
    assert_eq!(
        record.before.len(),
        3,
        "…and what it did it from — the second shrink went 3 -> 1: {record:?}"
    );

    eprintln!(
        "R118-F8 HEADLINE METRIC — time from first loss to single-node: {:?} \
         (5 voters -> 3 -> {} on a rig-policy cluster)",
        elapsed,
        after_second.len()
    );
    assert!(
        elapsed < RATCHET_BUDGET,
        "time from first loss to single-node was {elapsed:?}, over the {RATCHET_BUDGET:?} ceiling"
    );
}

/// **The safety test.** A node the cluster can still *hear* is a partition, and
/// reconfiguring during a partition is the split brain this whole design exists
/// to avoid.
///
/// `R118-F7` built [`Cluster::partition_node`] precisely so this could be
/// written: the node is cut off from raft in both directions while staying
/// powered on and answering `/health` — which is the harness's stand-in for the
/// BLE advert that makes the verdict `UnreachableButRadiating` instead of
/// `Dark`.
///
/// The assertion is that the voter set does not move. On its own that would pass
/// against a ratchet that is not running at all, so the test ends by restating
/// the identical peer as `Dark` — same cluster, same partition, same code path,
/// one field different — and asserting the set then *does* move. That control is
/// what makes the first half mean anything.
#[tokio::test]
async fn a_partitioned_but_radiating_voter_keeps_its_vote() {
    let policy = ClusterPolicy::rig();
    let mut cluster =
        test_cluster_with_policy(&HetznerDriver::new("unused-on-local-tier"), DummyRuntime, 5, policy)
            .await
            .expect("5-node rig cluster");
    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("initial leader");

    // Partition a follower, so the assertion is about the ratchet and not about
    // a leadership transition happening underneath it.
    let victim = (0..5).find(|idx| *idx != leader).expect("a follower");
    cluster.partition_node(victim).await.expect("partition");
    assert!(
        cluster.is_running(victim) && cluster.is_partitioned(victim),
        "the point of this test is a node that is UP and unreachable, not a dead one"
    );
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("leader with one node partitioned");

    let http = client();
    let subject = id_of(victim);
    let before = voters(&cluster);
    assert_eq!(before.len(), 5);

    report_from_survivors(
        &cluster,
        &http,
        &BTreeSet::new(),
        &[(subject, PeerLivenessVerdict::UnreachableButRadiating)],
    )
    .await;

    for _ in 0..10 {
        let outcome = tick_once(&cluster, &http, &policy).await;
        match &outcome {
            RatchetOutcome::Held { reason } => assert!(
                reason.contains("unreachable_but_radiating"),
                "the hold must be FOR the radiating peer, not incidental: {reason}"
            ),
            other => panic!(
                "the ratchet must never shrink a peer it can still hear; got {other:?}"
            ),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        voters(&cluster),
        before,
        "the voter set must be untouched while a peer is radiating"
    );

    // ── The negative control ────────────────────────────────────────────────
    // Everything above is unchanged; only the reported verdict moves. If the
    // ratchet were inert, this would not fire either, and the assertion above
    // would have proved nothing.
    report_from_survivors(&cluster, &http, &BTreeSet::from([subject]), &[]).await;
    let after = ratchet_until(&cluster, &http, &policy, 3, RATCHET_BUDGET).await;
    assert!(
        !after.contains(&subject),
        "control: with the SAME node reported `dark` the ratchet must demote it, which is what \
         makes the veto above a veto rather than an absence of machinery. Got {after:?}"
    );
}

/// `Unknown` is the observer's own blindness — "the BLE stack faulted", "the
/// observer started less than a hold-down ago" — and `W158` §7.1(3) requires
/// every consumer to treat it exactly as a partition: **fail closed**.
///
/// This is the inversion a plausible implementation gets wrong, because
/// "unknown" reads like "no objection". Here the node is genuinely *dead*
/// (`kill_node`, a power cut) and the ratchet must still refuse, because what
/// licenses the shrink is the detector's corroborated verdict and not the
/// node's actual state. Same negative control as the partition test.
#[tokio::test]
async fn an_unknown_verdict_vetoes_the_shrink_even_for_a_genuinely_dead_node() {
    let policy = ClusterPolicy::rig();
    let mut cluster =
        test_cluster_with_policy(&HetznerDriver::new("unused-on-local-tier"), DummyRuntime, 5, policy)
            .await
            .expect("5-node rig cluster");
    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("initial leader");

    let victim = (0..5).find(|idx| *idx != leader).expect("a follower");
    cluster.kill_node(victim).await.expect("kill a follower");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("leader after one loss");

    let http = client();
    let subject = id_of(victim);
    let before = voters(&cluster);

    report_from_survivors(
        &cluster,
        &http,
        &BTreeSet::new(),
        &[(subject, PeerLivenessVerdict::Unknown)],
    )
    .await;

    for _ in 0..10 {
        match tick_once(&cluster, &http, &policy).await {
            RatchetOutcome::Held { reason } => assert!(
                reason.contains("unknown"),
                "the hold must name the unknown verdict: {reason}"
            ),
            other => panic!("`Unknown` must fail closed; got {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(voters(&cluster), before, "no shrink on an unknown verdict");

    // Control: the same dead node, now corroborated dark.
    report_from_survivors(&cluster, &http, &BTreeSet::from([subject]), &[]).await;
    let after = ratchet_until(&cluster, &http, &policy, 3, RATCHET_BUDGET).await;
    assert!(!after.contains(&subject), "control: {after:?}");
}

/// **The fleet gate.** One cluster, one set of dark verdicts, [`run_once`]
/// called twice — the only difference between the two calls is
/// `policy.membership_ratchet`.
///
/// Built this way deliberately. Founding a second cluster under
/// [`ClusterPolicy::fleet`] would also differ in election bounds, admission rule
/// and geography rule, and a reader could not tell which one produced the hold.
/// Here nothing differs but the field under test, so the fleet's inertness is
/// attributable to the field and to nothing else — and the rig call immediately
/// after proves the stimulus was real.
#[tokio::test]
async fn the_fleet_never_shrinks_under_the_stimulus_that_makes_the_rig_shrink() {
    let rig = ClusterPolicy::rig();
    let mut cluster = test_cluster_with_policy(&HetznerDriver::new("unused-on-local-tier"), DummyRuntime, 5, rig)
        .await
        .expect("5-node cluster");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("initial leader");

    let http = client();
    cluster.kill_node(4).await.expect("kill node 5");
    cluster.kill_node(3).await.expect("kill node 4");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("leader after losing two of five");

    let dark = BTreeSet::from([4, 5]);
    report_from_survivors(&cluster, &http, &dark, &[]).await;
    let before = voters(&cluster);
    assert_eq!(before.len(), 5);

    let fleet = ClusterPolicy::fleet();
    for _ in 0..10 {
        match tick_once(&cluster, &http, &fleet).await {
            RatchetOutcome::Held { reason } => assert!(
                reason.contains("freezes the voter set"),
                "the fleet must hold for the POLICY reason, not because the evidence was \
                 missing: {reason}"
            ),
            other => panic!("a fleet cluster must never shrink itself; got {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        voters(&cluster),
        before,
        "ClusterPolicy::fleet() must be byte-for-byte unaffected by the ratchet"
    );

    // The same evidence, the same tree, the same tick — under the rig policy.
    let after = ratchet_until(&cluster, &http, &rig, 3, RATCHET_BUDGET).await;
    assert_eq!(
        after,
        BTreeSet::from([1, 2, 3]),
        "control: the stimulus the fleet ignored must be one the rig acts on, or the fleet \
         assertion above is vacuous"
    );
}

// ── Part 2: rehydration ──────────────────────────────────────────────────────

/// Shrink a 3-node rig to a single voter by killing `victim_idx`, then bring it
/// back. Returns the surviving voter's index.
///
/// The setup both rehydration tests need, and it is the *real* path: the two
/// demoted nodes are learners because `retain = true` left them in membership,
/// not because anything called `add_learner`.
async fn shrink_to_one_voter(
    cluster: &mut Cluster,
    http: &reqwest::Client,
    policy: &ClusterPolicy,
    victim_idx: usize,
) -> usize {
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("initial leader");
    cluster.kill_node(victim_idx).await.expect("kill");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("leader after one loss");
    report_from_survivors(cluster, http, &BTreeSet::from([id_of(victim_idx)]), &[]).await;
    let after = ratchet_until(cluster, http, policy, 1, RATCHET_BUDGET).await;
    assert_eq!(after.len(), 1, "expected a single voter, got {after:?}");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("leader after shrinking to one voter")
}

/// A returned node comes back as a **learner** and does not get its vote until
/// it has been continuously alive for the whole hold-down.
///
/// The clock is injected — `run_once` takes `now` — because the rig's hold-down
/// is 300 s and no test may sleep for it. The first half ticks at the *real*
/// clock, where the node has been back for seconds: it must not be promoted, and
/// the refusal must say how far through the hold-down it is. The second half
/// ticks at `now + hold-down + 1`, standing where a genuinely stable node would
/// be, and it must promote. That second half is also the negative control:
/// without it, the first would pass against a rehydrate path that does nothing
/// at all.
#[tokio::test]
async fn a_returned_learner_waits_out_the_hold_down_before_it_votes_again() {
    let policy = rehydration_policy();
    let mut cluster = test_cluster_with_policy(
        &HetznerDriver::new("unused-on-local-tier"),
        DummyRuntime,
        3,
        policy,
    )
    .await
    .expect("3-node rig cluster");
    let http = client();

    shrink_to_one_voter(&mut cluster, &http, &policy, 2).await;
    let lone = voters(&cluster);
    assert_eq!(lone.len(), 1);

    // The plinth comes back. `restart_node` is the return, not a new join: it is
    // still in membership as a learner, which is what retain=true bought.
    cluster.restart_node(2).await.expect("restart");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("leader after the return");
    let returned_at = Instant::now();
    report_from_survivors(&cluster, &http, &BTreeSet::new(), &[]).await;

    // Real clock: it has been back for seconds, not for a hold-down.
    for _ in 0..5 {
        match tick_once(&cluster, &http, &policy).await {
            RatchetOutcome::Held { reason } => assert!(
                reason.contains("hold-down"),
                "the refusal must be the hold-down's, not an incidental one: {reason}"
            ),
            other => panic!(
                "a node back for seconds must not be handed a vote; got {other:?}"
            ),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        voters(&cluster),
        lone,
        "the voter set must not move while the hold-down is unspent"
    );

    // Stand past the hold-down. Nothing else changes.
    fn stable_clock() -> u64 {
        now_secs() + PROMOTE_HOLD_DOWN_SECS + 1
    }
    let after = ratchet_until_at(
        &cluster,
        &http,
        &policy,
        3,
        RATCHET_BUDGET,
        stable_clock,
    )
    .await;
    let round_trip = returned_at.elapsed();
    assert_eq!(
        after,
        BTreeSet::from([1, 2, 3]),
        "both demoted learners clear the hold-down together, and the promotion lands on an ODD \
         count in one membership change rather than resting at 2: {after:?}"
    );

    eprintln!(
        "R118-F8 REHYDRATION METRIC — returned learner to voter again: {round_trip:?} of \
         mechanical latency under the injected clock, on top of the \
         {PROMOTE_HOLD_DOWN_SECS}s stability hold-down that dominates it in production"
    );
    assert!(
        round_trip < RATCHET_BUDGET,
        "rehydration took {round_trip:?} of mechanical latency, over the {RATCHET_BUDGET:?} ceiling"
    );
}

/// **The test the whole feature exists for.** A plinth on a failing PSU that
/// comes up, dies, comes up and dies again must never touch quorum.
///
/// Two claims, and the second is the mechanism the first rests on:
///
/// 1. across every cycle, under the real clock, the voter set never moves;
/// 2. the replicated `since` latch **strictly advances on every return**, which
///    is what makes claim 1 hold for a flap of any length rather than only for
///    one that happens to be short. A `since` that were carried forward across a
///    down-up cycle would let a node accumulate credit for time it spent dark,
///    and the hold-down would be satisfied by a node that had never once been up
///    for it.
#[tokio::test]
async fn a_flapping_node_never_gets_its_vote_back() {
    let policy = ClusterPolicy::rig();
    let mut cluster = test_cluster_with_policy(
        &HetznerDriver::new("unused-on-local-tier"),
        DummyRuntime,
        3,
        policy,
    )
    .await
    .expect("3-node rig cluster");
    let http = client();

    let lone_idx = shrink_to_one_voter(&mut cluster, &http, &policy, 2).await;
    let lone = voters(&cluster);
    let flapper = id_of(2);

    /// Read the `since` the cluster currently holds for `subject`, as any
    /// observer sees it. The replicated latch, read from applied state — the
    /// oracle independent of the decision under test.
    fn since_of(cluster: &Cluster, idx: usize, subject: YubabaNodeId) -> Option<u64> {
        cluster
            .cluster_state(idx)?
            .peer_liveness()
            .values()
            .filter_map(|by_subject| by_subject.get(&subject))
            .filter(|r| r.verdict == PeerLivenessVerdict::Alive)
            .map(|r| r.since)
            .max()
    }

    let mut previous_since: Option<u64> = None;
    for cycle in 0..3 {
        // Up.
        cluster.restart_node(2).await.expect("restart");
        cluster
            .wait_for_agreed_leader(FAILOVER_BUDGET)
            .await
            .expect("leader after the return");
        report_from_survivors(&cluster, &http, &BTreeSet::new(), &[]).await;

        let since = since_of(&cluster, lone_idx, flapper)
            .unwrap_or_else(|| panic!("cycle {cycle}: no alive record for the flapper"));
        if let Some(prev) = previous_since {
            assert!(
                since > prev,
                "cycle {cycle}: the `since` latch must be RE-STAMPED on a Dark -> Alive \
                 transition ({since} must exceed {prev}). Carrying it forward across a flap \
                 would credit the node for time it spent dark, and the hold-down would be \
                 satisfied by a node that was never up for it."
            );
        }
        previous_since = Some(since);

        match tick_once(&cluster, &http, &policy).await {
            RatchetOutcome::Held { reason } => assert!(
                reason.contains("hold-down"),
                "cycle {cycle}: {reason}"
            ),
            other => panic!("cycle {cycle}: a flapping node must never be promoted; got {other:?}"),
        }
        assert_eq!(voters(&cluster), lone, "cycle {cycle}: the voter set moved");

        // Down again. The next return must land on a later unix second than this
        // one, or the latch has nothing to advance to.
        cluster.kill_node(2).await.expect("kill");
        report_from_survivors(&cluster, &http, &BTreeSet::from([flapper]), &[]).await;
        tokio::time::sleep(Duration::from_millis(1_100)).await;
    }

    assert_eq!(
        voters(&cluster),
        lone,
        "three up-down cycles and the flapping plinth never held a vote"
    );
}

/// **Rehydration and re-admission are different paths** (`W158` §7.2(2)), and
/// the fork is a question the leader ASKS rather than a field the joiner sends.
///
/// Three live behaviours of that gate, and the third is the one that makes it a
/// gate rather than a suggestion:
///
/// 1. a reachable joiner is interrogated and adopted, and the 200 says so;
/// 2. a `Frozen` cluster does not interrogate at all and reports `false`;
/// 3. **a joiner that cannot be asked is refused**, so there is no way onto a
///    rehydrating cluster without being answerable — which is precisely what a
///    request-body field could never guarantee, because a caller can always omit
///    one.
///
/// The term comparison itself — a foreign incarnation carrying a term this
/// cluster has never reached — is exercised exhaustively against
/// [`yubaba::membership_ratchet::judge_origin`] in that module's unit tests,
/// where a higher term can be stated. Staging a genuinely higher-term node here
/// would mean refounding a second cluster on the same node id, which tests the
/// harness rather than the rule.
#[tokio::test]
async fn a_rehydrating_cluster_interrogates_a_joiner_and_refuses_one_it_cannot_ask() {
    let policy = rehydration_policy();
    let mut cluster = test_cluster_with_policy(
        &HetznerDriver::new("unused-on-local-tier"),
        DummyRuntime,
        3,
        policy,
    )
    .await
    .expect("3-node rig cluster");
    let http = client();

    // A demoted learner is the node a rejoin actually targets.
    let lone_idx = shrink_to_one_voter(&mut cluster, &http, &policy, 2).await;
    cluster.restart_node(2).await.expect("restart");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("leader after the return");

    let leader_url = cluster.yubaba(lone_idx).base_url.clone();
    let joiner_addr = cluster.yubaba(2).base_url.replace("http://", "");
    let add_learner = async |addr: String| -> (u16, String) {
        let resp = http
            .post(format!("{leader_url}/raft/add-learner"))
            .json(&serde_json::json!({ "node_id": id_of(2), "addr": addr }))
            .send()
            .await
            .expect("POST /raft/add-learner");
        let status = resp.status().as_u16();
        (status, resp.text().await.unwrap_or_default())
    };

    // 1. Reachable: asked, judged ours, adopted. Note the body carries no
    //    `origin` — there is nothing for a caller to omit.
    let (status, body) = add_learner(joiner_addr).await;
    assert_eq!(
        status, 200,
        "a node this cluster demoted holds a term at or below the leader's and must be adopted \
         normally: {body}"
    );
    assert!(
        body.contains("\"origin_judged\":true"),
        "the 200 must say the lineage was CHECKED, so an unchecked join is never mistaken for a \
         passed one: {body}"
    );

    // 3. Unreachable: refused, and 502 rather than 409 — "the box did not
    //    answer" and "the box answered, from the wrong cluster" are different
    //    operator actions, the same distinction the sovereign-group gate draws.
    let (status, body) = add_learner("127.0.0.1:1".to_string()).await;
    assert_eq!(
        status, 502,
        "there must be no way onto a rehydrating cluster without being answerable: {body}"
    );
    assert!(
        body.contains("could not ask"),
        "the refusal must name what failed, so an operator retries the right thing: {body}"
    );
    assert_eq!(
        voters(&cluster).len(),
        1,
        "a refused join changes no membership"
    );
}

/// 2. The other half: a `Frozen` cluster does not interrogate at all.
///
/// It promotes nobody without an operator, so an unvetted joiner stays a learner
/// and a human is still the gate on every vote. Requiring an answer there would
/// have cost every pre-existing `raft join` for a check whose consumer does not
/// exist — and `origin_judged: false` is how a reader tells "not checked" from
/// "checked and fine".
#[tokio::test]
async fn a_frozen_cluster_admits_a_joiner_without_interrogating_it() {
    let cluster = test_cluster_with_policy(
        &HetznerDriver::new("unused-on-local-tier"),
        DummyRuntime,
        3,
        ClusterPolicy::fleet(),
    )
    .await
    .expect("3-node fleet cluster");
    let http = client();
    let leader = cluster
        .wait_for_agreed_leader(Duration::from_secs(30))
        .await
        .expect("fleet leader");
    let member = (0..3).find(|i| *i != leader).expect("a follower");

    // `Raft::add_learner` is `ChangeMembers::AddNodes` with `retain: true`
    // (openraft 0.10 raft/api/management.rs), so re-adding a node already in
    // membership touches no voter set — which is what makes an existing member a
    // safe target for this call.
    let before = voters(&cluster);
    let resp = http
        .post(format!(
            "{}/raft/add-learner",
            cluster.yubaba(leader).base_url
        ))
        .json(&serde_json::json!({
            "node_id": id_of(member),
            "addr": cluster.yubaba(member).base_url.replace("http://", ""),
        }))
        .send()
        .await
        .expect("POST /raft/add-learner on the fleet");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, 200,
        "ClusterPolicy::fleet() must be byte-for-byte unaffected by this gate: {body}"
    );
    assert!(
        body.contains("\"origin_judged\":false"),
        "…and must report that the lineage was NOT checked, rather than letting an unchecked \
         join look like one that passed: {body}"
    );
    assert_eq!(
        voters(&cluster),
        before,
        "re-adding an existing member is AddNodes with retain=true and moves no voter"
    );
}

/// The fleet does not rehydrate either, under the stimulus that makes the rig
/// rehydrate — same cluster, same evidence, one policy field different.
#[tokio::test]
async fn the_fleet_never_rehydrates_under_the_stimulus_that_makes_the_rig_rehydrate() {
    let rig = rehydration_policy();
    let mut cluster = test_cluster_with_policy(
        &HetznerDriver::new("unused-on-local-tier"),
        DummyRuntime,
        3,
        rig,
    )
    .await
    .expect("3-node cluster");
    let http = client();

    shrink_to_one_voter(&mut cluster, &http, &rig, 2).await;
    cluster.restart_node(2).await.expect("restart");
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("leader after the return");
    report_from_survivors(&cluster, &http, &BTreeSet::new(), &[]).await;

    let before = voters(&cluster);
    let fleet = ClusterPolicy::fleet();
    let stable = now_secs() + PROMOTE_HOLD_DOWN_SECS + 1;
    for _ in 0..5 {
        match tick_once_at(&cluster, &http, &fleet, stable).await {
            RatchetOutcome::Held { reason } => assert!(
                reason.contains("freezes the voter set"),
                "the fleet must hold for the POLICY reason, not because the hold-down was \
                 unspent: {reason}"
            ),
            other => panic!("a fleet cluster must never rehydrate itself; got {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(voters(&cluster), before, "the fleet's voter set is untouched");

    // Control: the same tree, the same evidence, the same clock — under rig.
    let after = ratchet_until_at(
        &cluster,
        &http,
        &rig,
        3,
        RATCHET_BUDGET,
        || now_secs() + PROMOTE_HOLD_DOWN_SECS + 1,
    )
    .await;
    assert_eq!(
        after.len(),
        3,
        "control: the stimulus the fleet ignored must be one the rig acts on: {after:?}"
    );
}
