//! R118-F7 — the harness's partition primitive, and the thing it exists to
//! prove: **a partitioned node is not a dead node.**
//!
//! Part of R118-F7 — the canonical `@yah:ticket` annotation lives in the
//! noisetable camp at `crates/society/core/src/lib.rs`. The design is
//! `.yah/docs/working/W138-installation-as-a-cluster.md` and
//! `.yah/docs/working/W158-wedge-recovery-decision.md` in that same camp.
//!
//! Raft's quorum rule is a **partition** defense, not a node-failure defense. A
//! minority may not make progress because it cannot tell whether the missing
//! majority is dead or on the far side of a split. W138's membership ratchet
//! (R118-F8) removes that ambiguity for a gallery rig using a physically
//! independent channel — BLE — and is then allowed to shrink the voter set on
//! nodes it can prove are *off*. The safety rule inverts the intuition: absence
//! of evidence is the permission, **presence of it is a veto**.
//!
//! That makes "powered off" and "unreachable" two different events that a test
//! suite must be able to stage separately. Until now it could stage only the
//! first: [`Cluster::kill_node`] is a power cut, and the harness had no way to
//! cut a node's network while leaving the machine running.
//! [`Cluster::partition_node`] is that missing half, and this file is its
//! consumer.
//!
//! ## The trap this is written against
//!
//! Every harness node lives in one process on one loopback namespace, so gating
//! a node's *inbound* `/raft/*` routes is not a partition: its outbound
//! `AppendEntries` still reach peers, the replies ride back on connections it
//! opened, and an "isolated" leader keeps its lease and goes on leading. The
//! primitive therefore cuts **both** directions — `Raft::shutdown()` for
//! outbound, a raft-less rebind of the router for inbound — and
//! [`the_partitioned_leader_stops_leading_and_the_survivors_elect_a_new_one`]
//! is the test that would fail if either half were missing.
//!
//! ## What it is NOT
//!
//! Not `tc`. W138 claimed a `tc qdisc` knob in the local tier and there is
//! none: the harness's `NetworkDegrade` was write-only dead code (deleted in
//! R118-T1), and the real `YAH_LOCAL_NETWORK_DEGRADE` belongs to a different,
//! container-based tier. In-process loopback servers share one network
//! namespace and cannot be impaired with `tc` at all.
//!
//! ## The fidelity gap, stated once so R118-F8 knows what its chaos test proves
//!
//! **A shut-down node stops campaigning, where a really-partitioned one keeps
//! raising terms.** So this models the majority side's view faithfully — the
//! minority node is unreachable and commits nothing — but it does not reproduce
//! a returning node that comes back with a higher term, which is exactly what
//! W158 §5's epoch fence exists for. A ratchet test built on this proves *"does
//! not shrink a peer it can still hear"*; it does not prove the fence.
//!
//! Rig policy, not fleet: the election bounds are what failover timing is
//! measured against, and a rig fails over inside a second where the fleet takes
//! three.
//!
//! ```bash
//! cargo test -p yubaba --test main -- raft_partition::
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cloud::provider::HetznerDriver;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::raft::{YubabaRequest, YubabaResponse};
use yubaba::runtime::DummyRuntime;
use yubaba_test_harness::{test_cluster_with_policy, Cluster};

/// The singleton role these tests write, so a commit is observable as data
/// rather than only as a log index.
const ROLE: &str = "rig/egress-gateway";

/// Long enough that no assertion here is racing a lease expiry.
const ROLE_TTL_SECS: u64 = 300;

/// Failover budget. The rig preset's election window is 450–900 ms, so this is
/// several elections of headroom on a loaded machine.
const FAILOVER_BUDGET: Duration = Duration::from_secs(10);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client")
}

/// `POST /raft/write` an `AcquireLock`. `Err` carries the HTTP status text —
/// on a node whose raft is cut off that is the expected outcome, not a failure.
async fn acquire(
    http: &reqwest::Client,
    base_url: &str,
    owner: &str,
    at: u64,
) -> Result<bool, String> {
    let request = YubabaRequest::AcquireLock {
        key: ROLE.to_string(),
        owner: owner.to_string(),
        ttl_secs: ROLE_TTL_SECS,
        acquired_at: at,
    };
    let resp = http
        .post(format!("{base_url}/raft/write"))
        .json(&serde_json::json!({ "request": request }))
        .send()
        .await
        .map_err(|e| format!("POST /raft/write: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!(
            "HTTP {status}: {}",
            resp.text().await.unwrap_or_default()
        ));
    }
    match resp
        .json::<YubabaResponse>()
        .await
        .map_err(|e| format!("decoding YubabaResponse: {e}"))?
    {
        YubabaResponse::LockGranted(granted) => Ok(granted),
        other => Err(format!("expected LockGranted, got {other:?}")),
    }
}

/// The role owner this node reports out of its own applied state, plus the log
/// index that answer is true as of.
#[derive(Debug)]
struct SingletonView {
    owner: Option<String>,
    applied_index: Option<u64>,
}

async fn read_singletons(http: &reqwest::Client, base_url: &str) -> Result<SingletonView, String> {
    let resp = http
        .get(format!("{base_url}/cluster/singletons"))
        .send()
        .await
        .map_err(|e| format!("GET /cluster/singletons: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("decoding singleton body: {e}"))?;
    Ok(SingletonView {
        owner: body["roles"][ROLE]["owner"].as_str().map(str::to_string),
        applied_index: body["applied_index"].as_u64(),
    })
}

/// `GET /health` — the channel a partitioned node keeps answering, and the
/// harness stand-in for W138's independent radio.
async fn health_ok(http: &reqwest::Client, base_url: &str) -> bool {
    http.get(format!("{base_url}/health"))
        .send()
        .await
        .is_ok_and(|r| r.status().is_success())
}

/// Poll until `node` reports `expected` as the role owner.
async fn await_owner(
    http: &reqwest::Client,
    base_url: &str,
    expected: &str,
    budget: Duration,
) -> SingletonView {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if let Ok(view) = read_singletons(http, base_url).await {
            if view.owner.as_deref() == Some(expected) {
                return view;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("{base_url} never reported owner {expected}; last was {view:?}");
            }
        } else if tokio::time::Instant::now() > deadline {
            panic!("{base_url} never answered /cluster/singletons");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// **The primitive's own test, and the trap in one assertion.**
///
/// Partition the *leader* — the case an inbound-only gate gets wrong. If only
/// inbound were cut, the isolated node's outbound replication would keep
/// flowing, its lease would keep renewing, and it would go on leading a cluster
/// it can no longer reach; the survivors would never elect anyone and
/// `wait_for_agreed_leader` below would time out.
///
/// Four claims, in the order that makes each one non-vacuous:
///
/// 1. The isolated node is still **running and reachable** — `/health` answers.
///    Without this the rest would pass equally well against `kill_node`, and
///    the test would not be about a partition at all.
/// 2. It still answers `GET /cluster/singletons` from its own applied state.
///    That is R118-T3's local read path and, for R118-F7, the corroborating
///    channel: this is the node the ratchet must **not** shrink.
/// 3. It nonetheless **stops leading**, and cannot commit: the survivors elect
///    somebody else and a write against the isolated node fails.
/// 4. Healed, it rejoins and catches up on what it missed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_partitioned_leader_stops_leading_and_the_survivors_elect_a_new_one() {
    let http = client();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let mut cluster: Cluster =
        test_cluster_with_policy(&provider, DummyRuntime, 3, ClusterPolicy::rig())
            .await
            .expect("3-node rig cluster");

    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let survivors: Vec<usize> = (0..3).filter(|i| *i != leader).collect();

    // A committed fact from before the cut, so "caught up" later has something
    // to be measured against.
    let t0 = now_secs();
    let leader_url = cluster.yubaba(leader).base_url.clone();
    assert!(
        acquire(&http, &leader_url, "plinth-1", t0)
            .await
            .expect("AcquireLock against a healthy quorum"),
        "an unheld role must be grantable",
    );
    let before = await_owner(&http, &leader_url, "plinth-1", FAILOVER_BUDGET).await;

    // ── the network under the leader is cut ───────────────────────────────────
    cluster
        .partition_node(leader)
        .await
        .expect("partition the leader");
    assert!(cluster.is_partitioned(leader));
    assert!(
        cluster.is_running(leader),
        "a partitioned node must still be RUNNING — otherwise this is kill_node \
         wearing a different name and proves nothing about a network fault",
    );

    // (1) still reachable, and (2) still answering off local applied state.
    assert!(
        health_ok(&http, &leader_url).await,
        "the partitioned node must keep answering /health — that is the \
         corroborating channel R118-F7's detector reads, and the reason this \
         node must never be shrunk out",
    );
    let isolated = read_singletons(&http, &leader_url)
        .await
        .expect("a partitioned node still serves its own applied state");
    assert_eq!(
        isolated.owner.as_deref(),
        Some("plinth-1"),
        "it still believes what it had already committed",
    );

    // (3) and it stops leading. This is the assertion an inbound-only gate
    // fails: the survivors could not elect anyone while the old leader was
    // still replicating to them.
    let new_leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the survivors elect a new leader while the old one is cut off");
    assert_ne!(
        new_leader, leader,
        "the partitioned node must not still be the leader",
    );
    assert!(survivors.contains(&new_leader));

    // It commits nothing: every /raft/* route on it refuses.
    let err = acquire(&http, &leader_url, "plinth-9", now_secs())
        .await
        .expect_err("a cut-off node must not be able to commit");
    assert!(
        err.contains("503"),
        "expected a raft-not-configured refusal from the isolated node, got: {err}",
    );

    // ── the majority side keeps working ───────────────────────────────────────
    let new_leader_url = cluster.yubaba(new_leader).base_url.clone();
    assert!(
        acquire(&http, &new_leader_url, "plinth-2", t0 + ROLE_TTL_SECS + 1)
            .await
            .expect("the surviving quorum still commits"),
        "an expired lease must be re-grantable on the majority side",
    );
    await_owner(&http, &new_leader_url, "plinth-2", FAILOVER_BUDGET).await;

    // The isolated node did NOT see it — that is what being partitioned means.
    let still_isolated = read_singletons(&http, &leader_url)
        .await
        .expect("still answering");
    assert_eq!(
        still_isolated.owner.as_deref(),
        Some("plinth-1"),
        "a cut-off node must not observe commits it could not receive",
    );
    assert_eq!(
        still_isolated.applied_index, before.applied_index,
        "its applied index must have stopped advancing — the staleness signal \
         R118-T3 exposes for exactly this case",
    );

    // ── (4) heal, and it rejoins ──────────────────────────────────────────────
    cluster.heal_node(leader).await.expect("heal the partition");
    assert!(!cluster.is_partitioned(leader));

    let healed = await_owner(&http, &leader_url, "plinth-2", FAILOVER_BUDGET).await;
    assert!(
        healed.applied_index > before.applied_index,
        "a healed node must catch up past where it was cut off: {:?} -> {:?}",
        before.applied_index,
        healed.applied_index,
    );
    cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the whole cluster agrees on one leader again");
}

/// Partitioning a **follower** must not disturb the cluster at all: quorum
/// survives 1 of 3, so the majority side never even pauses.
///
/// The companion to the leader case, and the shape R118-F8's ratchet actually
/// meets first — the peer it is tempted to shrink is usually a follower, and
/// this is the one it must refuse to shrink because BLE can still hear it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partitioned_follower_stays_reachable_while_the_majority_keeps_committing() {
    let http = client();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let mut cluster: Cluster =
        test_cluster_with_policy(&provider, DummyRuntime, 3, ClusterPolicy::rig())
            .await
            .expect("3-node rig cluster");

    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let follower = (0..3).find(|i| *i != leader).expect("a follower exists");
    let leader_url = cluster.yubaba(leader).base_url.clone();
    let follower_url = cluster.yubaba(follower).base_url.clone();

    cluster
        .partition_node(follower)
        .await
        .expect("partition a follower");

    // The majority commits without pausing.
    let t0 = now_secs();
    assert!(
        acquire(&http, &leader_url, "plinth-1", t0)
            .await
            .expect("2 of 3 is still a quorum"),
        "a partitioned follower must not stop the cluster committing",
    );
    await_owner(&http, &leader_url, "plinth-1", FAILOVER_BUDGET).await;

    // And the follower is *there* the whole time. This is the veto: a node
    // answering a channel is a node that must not be shrunk out, however
    // silent raft has gone.
    assert!(
        health_ok(&http, &follower_url).await,
        "a partitioned follower is powered on and must say so",
    );
    assert!(cluster.is_running(follower) && cluster.is_partitioned(follower));

    // The leader kept its job — a follower's partition is not an election.
    assert_eq!(
        cluster
            .wait_for_agreed_leader(FAILOVER_BUDGET)
            .await
            .expect("the majority still agrees"),
        leader,
        "partitioning a follower must not cause a leadership change",
    );

    cluster.heal_node(follower).await.expect("heal");
    await_owner(&http, &follower_url, "plinth-1", FAILOVER_BUDGET).await;
}
