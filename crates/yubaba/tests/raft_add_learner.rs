//! R569-F3 — join a *running* yubaba quorum as a non-voting learner via
//! `POST /raft/add-learner`.
//!
//! Part of R569-F3 — the canonical `@yah:ticket` annotation lives in
//! `.yah/docs/working/W255-headless-macos-yubaba-node.md`; the endpoint it
//! documents is implemented in `src/lib.rs`. This suite is credential-free and
//! containerd-free: it stands up a real 3-voter openraft cluster over loopback
//! HTTP (via the harness), then stands up a **separate, uninitialised** yubaba
//! node (node id 4) — exactly how a fresh macOS fleet box comes up: with
//! `--raft-node-id 4` but no `raft init` and no `--bootstrap-single-node` — and
//! joins it to the live cluster as a learner.
//!
//! It asserts the W255 join contract:
//! - the leader accepts `POST /raft/add-learner` (200),
//! - the joiner receives replicated state (its `/raft/status` learns the leader
//!   and its `last_applied` advances past the membership entry) — i.e. the
//!   learner really holds cluster state, not just a membership stub,
//! - **quorum is unchanged**: membership stays a single uniform 3-*voter* config
//!   and node 4 appears only as a non-voting node (never promoted). This is the
//!   deliberate design — a home-lab Mac node can never endanger the cloud
//!   voters' quorum.
//! - a *follower* rejects the call with 421 Misdirected (only the leader can
//!   change membership).
//!
//! ```bash
//! cargo test -p yubaba --test raft_add_learner
//! ```

use std::sync::Arc;
use std::time::Duration;

use cloud::provider::HetznerDriver;
use yubaba::runtime::DummyRuntime;
use yubaba_test_harness::{test_cluster, Cluster};

/// node index (0-based) → raft node id (1-based, per the harness convention).
fn node_id(idx: usize) -> u64 {
    (idx as u64) + 1
}

/// The joining learner's node id — one past the harness's 1..=3 voters.
const JOINER_ID: u64 = 4;

/// GET `/raft/status` as JSON.
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

/// A standalone, uninitialised yubaba node bound on a loopback port with a live
/// raft instance — the joiner. Holds the tempdir + server task alive.
struct Joiner {
    base_url: String,
    addr: String,
    _tmp: tempfile::TempDir,
    _task: tokio::task::JoinHandle<()>,
}

/// Bring up a solo, **uninitialised** yubaba node (no `initialize`, no
/// single-node bootstrap) that just serves the raft RPC routes so a leader can
/// add it as a learner. Mirrors a fresh macOS node started with
/// `--raft-node-id <id>` and nothing else.
async fn spawn_joiner(id: u64) -> Joiner {
    let tmp = tempfile::TempDir::new().expect("joiner tempdir");
    let state_path = tmp.path().join("identity.json");
    let raft_dir = tmp.path().join("raft");
    std::fs::create_dir_all(&raft_dir).expect("joiner raft dir");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind joiner listener");
    let port = listener.local_addr().expect("joiner local_addr").port();
    let addr = format!("127.0.0.1:{port}");
    let base_url = format!("http://{addr}");

    // Open the raft node but never initialise it — it comes up as a lone,
    // uninitialised member waiting to be established by a leader's AppendEntries.
    let raft = yubaba::raft::open(id, raft_dir)
        .await
        .expect("open joiner raft node");

    let state = yubaba::ServerState::load(state_path)
        .expect("load joiner state")
        .with_runtime(Arc::new(DummyRuntime))
        .with_raft(raft)
        .with_node_id(id);
    let router = yubaba::build_router(Arc::new(state));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // Wait for the joiner's /health to come up before returning.
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
            "joiner did not become healthy"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Joiner {
        base_url,
        addr,
        _tmp: tmp,
        _task: task,
    }
}

/// Voter ids from a `/raft/status` body: the flattened `membership.configs`.
fn voter_ids(status: &serde_json::Value) -> Vec<u64> {
    let configs = status["membership_config"]["membership"]["configs"]
        .as_array()
        .expect("membership.configs array");
    assert_eq!(
        configs.len(),
        1,
        "membership must be a single uniform config (not joint): {configs:?}"
    );
    configs[0]
        .as_array()
        .expect("voter set array")
        .iter()
        .map(|v| v.as_u64().expect("voter id u64"))
        .collect()
}

/// All node ids known to membership (voters *and* learners): `membership.nodes`.
fn node_ids(status: &serde_json::Value) -> Vec<u64> {
    status["membership_config"]["membership"]["nodes"]
        .as_object()
        .expect("membership.nodes object")
        .keys()
        .map(|k| k.parse::<u64>().expect("node id key u64"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn add_learner_joins_running_quorum_without_changing_voters() {
    // Pure, unconnected driver just satisfies the `MachineProvider` bound;
    // DummyRuntime keeps the cluster off containerd so it runs in standard CI.
    let provider = HetznerDriver::new("unused-on-local-tier");
    let cluster: Cluster = test_cluster(&provider, DummyRuntime, 3)
        .await
        .expect("spin up 3-node local raft cluster");

    let leader = cluster
        .wait_for_leader(Duration::from_secs(30))
        .await
        .expect("leader elected");
    let follower = (0..cluster.node_count())
        .find(|&i| i != leader)
        .expect("a follower exists");

    let leader_url = cluster.yubaba(leader).base_url.clone();
    let follower_url = cluster.yubaba(follower).base_url.clone();

    // Bring up the fresh, uninitialised joiner (as a macOS node would come up).
    let joiner = spawn_joiner(JOINER_ID).await;

    // (1) A *follower* must refuse — only the leader can change membership.
    let status = reqwest::Client::new()
        .post(format!("{follower_url}/raft/add-learner"))
        .json(&serde_json::json!({ "node_id": JOINER_ID, "addr": joiner.addr }))
        .send()
        .await
        .expect("POST /raft/add-learner to follower");
    assert_eq!(
        status.status(),
        reqwest::StatusCode::MISDIRECTED_REQUEST,
        "a follower must reject add-learner with 421 Misdirected"
    );

    // (2) Happy path against the leader. add_learner is blocking(true), so a 200
    // means the leader believes the learner is caught up.
    let resp = reqwest::Client::new()
        .post(format!("{leader_url}/raft/add-learner"))
        .json(&serde_json::json!({ "node_id": JOINER_ID, "addr": joiner.addr }))
        .send()
        .await
        .expect("POST /raft/add-learner to leader");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "leader must accept add-learner (body: {:?})",
        resp.text().await
    );

    // (3) Quorum invariant: voters are still exactly {1,2,3}; node 4 is present
    // in membership but NOT a voter (it joined as a non-voting learner).
    let leader_status = raft_status(&leader_url).await;
    let mut voters = voter_ids(&leader_status);
    voters.sort_unstable();
    assert_eq!(
        voters,
        vec![1, 2, 3],
        "the three founding voters must be unchanged — the learner never joins the voter set"
    );
    let nodes = node_ids(&leader_status);
    assert!(
        nodes.contains(&JOINER_ID),
        "the learner must appear in membership.nodes: {nodes:?}"
    );
    assert!(
        !voters.contains(&JOINER_ID),
        "the learner must NOT be a voter: voters={voters:?}"
    );

    // (4) The learner actually holds replicated state: it learned the current
    // leader and applied at least the membership entry that added it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let learner_caught_up = loop {
        let s = raft_status(&joiner.base_url).await;
        let learned_leader = s["current_leader"].as_u64() == Some(node_id(leader));
        let applied = s["last_applied"]["index"].as_u64().unwrap_or(0);
        if learned_leader && applied > 0 {
            break true;
        }
        if tokio::time::Instant::now() >= deadline {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert!(
        learner_caught_up,
        "the learner never received replicated state (no leader learned / nothing applied)"
    );
}
