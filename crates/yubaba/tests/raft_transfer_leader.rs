//! R608-B11 — end-to-end leadership handoff via `POST /raft/transfer-leader`.
//!
//! Part of R608-B11 — the canonical `@yah:ticket` annotation lives in
//! `src/lib.rs`. This suite is credential-free and containerd-free: it stands up
//! a real 3-node openraft cluster over loopback HTTP (`DummyRuntime` + a
//! never-called provider that only satisfies the `MachineProvider` type bound),
//! then exercises the trigger-elect-on-target handoff:
//!
//! - leadership moves to the requested voter,
//! - membership stays a single uniform 3-voter config (no quorum reduction, not
//!   stuck in a joint config),
//! - a follower rejects the call (misdirected — not the leader),
//! - a redundant transfer to the sitting leader is an idempotent no-op.
//!
//! ```bash
//! cargo test -p yubaba --test raft_transfer_leader
//! ```

use std::time::Duration;

use cloud::provider::HetznerDriver;
use yubaba::runtime::DummyRuntime;
use yubaba_test_harness::{test_cluster, Cluster};

/// node index (0-based) → raft node id (1-based, per the harness convention).
fn node_id(idx: usize) -> u64 {
    (idx as u64) + 1
}

/// POST `/raft/transfer-leader` and return the HTTP status.
async fn post_transfer(base_url: &str, to: u64) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("{base_url}/raft/transfer-leader"))
        .json(&serde_json::json!({ "to": to }))
        .send()
        .await
        .expect("POST /raft/transfer-leader")
        .status()
}

/// Poll until `current_leader_idx == Some(want)` or `timeout` elapses.
async fn wait_until_leader_idx(cluster: &Cluster, want: usize, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cluster.current_leader_idx() == Some(want) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// R608-B11 (Option C): with openraft 0.10 this drives the real
// `Trigger::transfer_leader`, which sends the target a TimeoutNow that bypasses
// the follower leader-lease — so leadership actually moves while membership stays
// a uniform 3-voter config. (The earlier openraft-0.9 force-elect workaround
// could NOT unseat a healthy leader: the lease made the other voters reject the
// forced candidate's vote. That falsification is why we bumped to 0.10.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfer_leader_moves_leadership_and_keeps_membership() {
    // The provider is never touched on the local tier — a pure, unconnected
    // driver just satisfies the `MachineProvider` type bound. DummyRuntime keeps
    // the test off containerd so it runs in standard CI.
    let provider = HetznerDriver::new("unused-on-local-tier");
    let cluster = test_cluster(&provider, DummyRuntime, 3)
        .await
        .expect("spin up 3-node local raft cluster");

    let leader = cluster
        .wait_for_leader(Duration::from_secs(30))
        .await
        .expect("leader elected");
    let followers: Vec<usize> = (0..cluster.node_count()).filter(|&i| i != leader).collect();
    assert_eq!(followers.len(), 2, "3-node cluster has two followers");
    let (f0, f1) = (followers[0], followers[1]);

    let leader_url = cluster.yubaba(leader).base_url.clone();
    let f0_url = cluster.yubaba(f0).base_url.clone();

    // (1) A follower rejects a transfer to a *third* node — it is not the leader,
    // so it cannot drive a handoff (targeting the current leader would instead
    // be an idempotent no-op, so we target the other follower here).
    let status = post_transfer(&f0_url, node_id(f1)).await;
    assert_eq!(
        status,
        reqwest::StatusCode::CONFLICT,
        "a follower must reject transfer-leader with 409"
    );

    // (2) Happy path: hand leadership from the leader to follower f0. Retry on
    // 409 — right after election the leader's replication metrics for the target
    // may not yet show it caught up (plan_transfer bails with CONFLICT until it
    // is), which is the documented retry contract.
    let mut moved = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        let status = post_transfer(&leader_url, node_id(f0)).await;
        if status == reqwest::StatusCode::ACCEPTED {
            moved = true;
            break;
        }
        assert_eq!(
            status,
            reqwest::StatusCode::CONFLICT,
            "only a retryable 409 is expected while the target catches up, got {status}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(moved, "transfer-leader never returned 202 Accepted");

    // Leadership actually settled on the requested target.
    assert!(
        wait_until_leader_idx(&cluster, f0, Duration::from_secs(10)).await,
        "leadership did not settle on the target node f0"
    );

    // (3) Membership intact: a single uniform config with all 3 voters. This is
    // the R608-B11 invariant — the handoff never touches membership, so there is
    // no quorum reduction and the cluster is never left in a joint config.
    let status_json: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/raft/status", cluster.yubaba(f0).base_url))
        .send()
        .await
        .expect("GET /raft/status")
        .json()
        .await
        .expect("status json");
    let configs = status_json["membership_config"]["membership"]["configs"]
        .as_array()
        .expect("membership.configs array");
    assert_eq!(
        configs.len(),
        1,
        "membership must be a single uniform config (not joint): {configs:?}"
    );
    let voters = configs[0].as_array().expect("voter set array");
    assert_eq!(
        voters.len(),
        3,
        "all 3 voters must remain after the transfer: {voters:?}"
    );

    // (4) Idempotent no-op: transferring to the node that already leads returns
    // 202 without forcing another election.
    let status = post_transfer(&f0_url, node_id(f0)).await;
    assert_eq!(
        status,
        reqwest::StatusCode::ACCEPTED,
        "transfer to the sitting leader is an idempotent no-op success"
    );
}
