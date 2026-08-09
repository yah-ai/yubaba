//! R118-T9 — `POST /raft/promote-voter`, and the [`ClusterPolicy`] that decides
//! whether it does anything.
//!
//! Part of R118-T9 — the canonical `@yah:ticket` annotation lives in the
//! noisetable camp at `crates/society/core/src/lib.rs`; the endpoint and the
//! policy it reads are implemented in `src/lib.rs` and `src/cluster_policy.rs`.
//!
//! Credential-free and containerd-free: real openraft clusters over loopback
//! HTTP with `DummyRuntime`. The point of testing it end-to-end rather than
//! only through `VoterAdmission::judge` (which has its own unit tests) is that
//! the interesting claims are about *membership after a real consensus round*:
//!
//! - under the fleet policy the endpoint refuses (403) and the founding voter
//!   set is genuinely untouched — the refusal is not a 403 that already
//!   mutated something;
//! - under a promoting policy the learner really becomes a voter in a single
//!   uniform membership config, which is the invariant R608-B11 cared about;
//! - `/raft/status` reports peer liveness from the attached `FailureDetector`.
//!
//! ```bash
//! cargo test -p yubaba --test raft_promote_voter
//! ```

use std::sync::Arc;
use std::time::Duration;

use cloud::provider::HetznerDriver;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::failure_detector::RaftHeartbeatDetector;
use yubaba::runtime::DummyRuntime;
use yubaba_test_harness::{test_cluster, Cluster};

/// The joining node's id — one past the harness's 1..=3 voters.
const JOINER_ID: u64 = 4;

/// A standalone yubaba node on a loopback port with a live raft instance.
/// Holds the tempdir + server task alive for the duration of the test.
struct Node {
    base_url: String,
    addr: String,
    _tmp: tempfile::TempDir,
    _task: tokio::task::JoinHandle<()>,
}

/// Bring up a solo, **uninitialised** yubaba node running under `policy`.
///
/// Mirrors how a node actually comes up: `--raft-node-id <id>` and a cluster
/// profile, no `initialize` and no single-node bootstrap. The policy is passed
/// to `raft::open` *and* to the server state, exactly as `main.rs` does — the
/// raft timers and the handlers must agree.
async fn spawn_node(id: u64, policy: ClusterPolicy) -> Node {
    let tmp = tempfile::TempDir::new().expect("node tempdir");
    let state_path = tmp.path().join("identity.json");
    let raft_dir = tmp.path().join("raft");
    std::fs::create_dir_all(&raft_dir).expect("node raft dir");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind node listener");
    let port = listener.local_addr().expect("node local_addr").port();
    let addr = format!("127.0.0.1:{port}");
    let base_url = format!("http://{addr}");

    let raft = yubaba::raft::open(id, raft_dir, &policy)
        .await
        .expect("open raft node");

    let state = yubaba::ServerState::load(state_path)
        .expect("load node state")
        .with_runtime(Arc::new(DummyRuntime))
        .with_cluster_policy(policy)
        .with_raft(raft.clone())
        .with_node_id(id)
        .with_failure_detector(Arc::new(RaftHeartbeatDetector::new(
            raft,
            policy.liveness_thresholds(),
        )));
    let router = yubaba::build_router(Arc::new(state));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if reqwest::Client::new()
            .get(format!("{base_url}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "node {id} did not become healthy"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Node {
        base_url,
        addr,
        _tmp: tmp,
        _task: task,
    }
}

async fn raft_status(base_url: &str) -> serde_json::Value {
    reqwest::Client::new()
        .get(format!("{base_url}/raft/status"))
        .send()
        .await
        .expect("GET /raft/status")
        .json()
        .await
        .expect("status json")
}

async fn post_json(url: String, body: serde_json::Value) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("POST");
    let status = resp.status();
    (status, resp.text().await.unwrap_or_default())
}

/// Sorted voter ids from a `/raft/status` body, asserting a single uniform
/// (non-joint) membership config along the way.
fn voter_ids(status: &serde_json::Value) -> Vec<u64> {
    let configs = status["membership_config"]["membership"]["configs"]
        .as_array()
        .expect("membership.configs array");
    assert_eq!(
        configs.len(),
        1,
        "membership must be a single uniform config (not joint): {configs:?}"
    );
    let mut ids: Vec<u64> = configs[0]
        .as_array()
        .expect("voter set array")
        .iter()
        .map(|v| v.as_u64().expect("voter id u64"))
        .collect();
    ids.sort_unstable();
    ids
}

/// Poll `base_url`'s status until `want` are the voters, or fail after `timeout`.
async fn wait_for_voters(base_url: &str, want: &[u64], timeout: Duration) -> Vec<u64> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let seen = voter_ids(&raft_status(base_url).await);
        if seen == want {
            return seen;
        }
        if tokio::time::Instant::now() >= deadline {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The fleet's learner-only rule, end to end: a learner that is fully caught up
/// and perfectly healthy is *still* refused, and the refusal changes nothing.
///
/// This is the behaviour the fleet has always had — it was previously
/// unreachable (there was no endpoint) and documented only in a doc comment.
/// Now that the endpoint exists, the rule has to be enforced rather than
/// implied, and this test is what holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fleet_policy_refuses_to_promote_a_learner() {
    let provider = HetznerDriver::new("unused-on-local-tier");
    let cluster: Cluster = test_cluster(&provider, DummyRuntime, 3)
        .await
        .expect("spin up 3-node local raft cluster");

    let leader = cluster
        .wait_for_leader(Duration::from_secs(30))
        .await
        .expect("leader elected");
    let leader_url = cluster.yubaba(leader).base_url.clone();

    // Join a learner the ordinary way, and let it catch up.
    let joiner = spawn_node(JOINER_ID, ClusterPolicy::fleet()).await;
    let (status, body) = post_json(
        format!("{leader_url}/raft/add-learner"),
        serde_json::json!({ "node_id": JOINER_ID, "addr": joiner.addr }),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "leader must accept add-learner: {body}"
    );

    // The promotion the fleet does not allow.
    let (status, body) = post_json(
        format!("{leader_url}/raft/promote-voter"),
        serde_json::json!({ "node_id": JOINER_ID }),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "the fleet's learner-only policy must refuse promotion with 403, got: {body}"
    );
    assert!(
        body.contains("learner-only"),
        "the refusal must say which rule refused it, got: {body}"
    );

    // And the refusal must be inert — no partial membership change.
    let after = voter_ids(&raft_status(&leader_url).await);
    assert_eq!(
        after,
        vec![1, 2, 3],
        "a refused promotion must leave the founding voter set exactly as it was"
    );

    // A node the cluster has never heard of is a different failure: 400, not a
    // policy refusal. Getting these two confused would let an operator read
    // "typo in the node id" as "policy says no".
    let (status, _) = post_json(
        format!("{leader_url}/raft/promote-voter"),
        serde_json::json!({ "node_id": 99 }),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "an unknown node id is a bad request, not a policy refusal"
    );

    // The R118-T9 failure detector, reported through /raft/status. The leader
    // is actively replicating to every peer, so all of them read as live.
    let status_body = raft_status(&leader_url).await;
    assert_eq!(
        status_body["liveness"]["channel"], "raft-heartbeat",
        "the leader must name the evidence channel its liveness came from: {status_body}"
    );
    let peers = status_body["liveness"]["peers"]
        .as_object()
        .expect("liveness.peers object");
    assert!(
        !peers.is_empty(),
        "a leader replicating to three peers must report on them: {status_body}"
    );
    for (node, obs) in peers {
        assert_eq!(
            obs["state"], "live",
            "peer {node} of a healthy cluster must read live: {obs}"
        );
    }
}

/// A promoting policy, end to end: a learner really becomes a voter, and the
/// result is a single uniform two-voter config rather than a stuck joint one.
///
/// Built without the harness because the harness deliberately pins the fleet
/// policy — this cluster has to be founded under a different one, which is the
/// whole point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_promoting_policy_turns_a_caught_up_learner_into_a_voter() {
    let policy = ClusterPolicy::rig();

    let founder = spawn_node(1, policy).await;
    let joiner = spawn_node(2, policy).await;

    // Found a cluster-of-one, then grow it.
    let (status, body) = post_json(
        format!("{}/raft/initialize", founder.base_url),
        serde_json::json!({ "members": { "1": founder.addr } }),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "founding a cluster-of-one must succeed: {body}"
    );

    // Sub-second election timings, so this is quick — but poll rather than sleep.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if raft_status(&founder.base_url).await["current_leader"].as_u64() == Some(1) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the founder never self-elected"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (status, body) = post_json(
        format!("{}/raft/add-learner", founder.base_url),
        serde_json::json!({ "node_id": 2, "addr": joiner.addr }),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "add-learner must succeed before promotion: {body}"
    );
    assert_eq!(
        voter_ids(&raft_status(&founder.base_url).await),
        vec![1],
        "add-learner alone must not create a voter under any policy"
    );

    // The promotion this policy allows.
    let (status, body) = post_json(
        format!("{}/raft/promote-voter", founder.base_url),
        serde_json::json!({ "node_id": 2 }),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "a promoting policy must accept promotion of a caught-up learner: {body}"
    );

    assert_eq!(
        wait_for_voters(&founder.base_url, &[1, 2], Duration::from_secs(15)).await,
        vec![1, 2],
        "the learner must land in the voter set as a single uniform config"
    );

    // Idempotent: promoting a voter is a success that changes nothing.
    let (status, body) = post_json(
        format!("{}/raft/promote-voter", founder.base_url),
        serde_json::json!({ "node_id": 2 }),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "re-promoting an existing voter must be an idempotent success: {body}"
    );
    assert!(
        body.contains("\"already_voter\":true"),
        "the idempotent case must say so rather than pretending it acted: {body}"
    );
    assert_eq!(
        voter_ids(&raft_status(&founder.base_url).await),
        vec![1, 2],
        "the no-op must not disturb membership"
    );

    // The new voter now holds a vote: it learned the leader and applied state.
    let joiner_status = raft_status(&joiner.base_url).await;
    assert_eq!(
        joiner_status["current_leader"].as_u64(),
        Some(1),
        "the promoted node must know who leads: {joiner_status}"
    );
    assert_eq!(
        voter_ids(&joiner_status),
        vec![1, 2],
        "the promoted node must see itself as a voter: {joiner_status}"
    );
}
