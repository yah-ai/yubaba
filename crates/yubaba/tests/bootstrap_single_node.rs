//! Single-node raft **cluster-of-one** bootstrap (W197 §"Single-node raft",
//! A032 §"cluster-mesh-1").
//!
//! Part of R482-T3 — the canonical @yah:ticket annotation lives in
//! `src/lib.rs`. This suite is the ticket's verify target:
//!
//! ```bash
//! cargo test -p yubaba --test bootstrap_single_node
//! ```
//!
//! It exercises [`yubaba::raft::bootstrap_single_node`] directly (no HTTP, no
//! containerd) — a freshly-opened raft node self-initialises as a one-voter
//! cluster, self-elects as leader, and accepts a consensus write. The
//! cluster-of-one path issues no peer RPC, so it runs green in plain CI with no
//! network and is independent of the raft/mesh transport parked under R593-T7.

use std::time::{Duration, Instant};

use openraft::async_runtime::watch::WatchReceiver;
use yubaba::raft::{self, YubabaRaft, YubabaRequest, YubabaResponse};

/// Poll the raft metrics until `node_id` is the current leader, or panic after
/// `timeout`. A single-node cluster self-elects within one election timeout
/// (election_timeout_max = 3s in [`raft::open_with_state_machine`]), so a 10s
/// budget is comfortable headroom.
async fn wait_for_leader(raft: &YubabaRaft, node_id: raft::YubabaNodeId, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if raft.metrics().borrow_watched().current_leader == Some(node_id) {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "node {node_id} did not become leader within {timeout:?}; \
                 current_leader = {:?}",
                raft.metrics().borrow_watched().current_leader
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Count the voters in the node's committed membership config.
fn voter_count(raft: &YubabaRaft) -> usize {
    raft.metrics()
        .borrow_watched()
        .membership_config
        .membership()
        .voter_ids()
        .count()
}

/// A fresh node bootstraps into a live one-voter cluster: it self-elects as
/// leader, membership holds exactly this node, and a `client_write` commits
/// through consensus. A second bootstrap on the same node is an idempotent
/// no-op.
#[tokio::test]
async fn single_node_bootstrap_forms_a_live_one_voter_cluster() {
    let dir = tempfile::tempdir().unwrap();
    let raft = raft::open(1, dir.path().to_path_buf()).await.unwrap();

    // Fresh node: bootstrap performs the init and reports it did.
    let performed = raft::bootstrap_single_node(&raft, 1, "100.64.0.1:7443")
        .await
        .expect("bootstrap of a fresh node succeeds");
    assert!(performed, "a fresh node should be initialised by bootstrap");

    // Single-node clusters self-elect ~immediately (no peers to campaign to).
    wait_for_leader(&raft, 1, Duration::from_secs(10)).await;
    assert_eq!(
        raft.metrics().borrow_watched().current_leader,
        Some(1),
        "the sole node must be its own leader"
    );
    assert_eq!(
        voter_count(&raft),
        1,
        "cluster-of-one has exactly one voter"
    );

    // The cluster is genuinely live: a consensus write commits and applies.
    let resp = raft
        .client_write(YubabaRequest::SetIngressOwner {
            machine: "solo".into(),
        })
        .await
        .expect("client_write commits on a live single-node cluster");
    assert!(matches!(resp.data, YubabaResponse::Ok));

    // Idempotent: re-running bootstrap on the now-initialised node is a no-op.
    let performed_again = raft::bootstrap_single_node(&raft, 1, "100.64.0.1:7443")
        .await
        .expect("re-bootstrap does not error");
    assert!(
        !performed_again,
        "an already-initialised node reports bootstrap as a no-op"
    );
    assert_eq!(voter_count(&raft), 1, "no-op bootstrap must not add voters");
}

/// Bootstrap is idempotent across a daemon restart: the founding membership is
/// persisted to the raft state dir, so reopening the node and calling bootstrap
/// again is a no-op rather than a second init.
#[tokio::test]
async fn bootstrap_is_idempotent_across_restart() {
    let dir = tempfile::tempdir().unwrap();

    // First boot: initialise, elect, then shut down cleanly.
    {
        let raft = raft::open(7, dir.path().to_path_buf()).await.unwrap();
        assert!(
            raft::bootstrap_single_node(&raft, 7, "100.64.0.7:7443")
                .await
                .unwrap(),
            "first boot performs the init"
        );
        wait_for_leader(&raft, 7, Duration::from_secs(10)).await;
        raft.shutdown().await.ok();
    }

    // Restart from the same state dir: vote/log state persisted, so bootstrap
    // is a no-op and the node picks its leadership back up.
    let raft = raft::open(7, dir.path().to_path_buf()).await.unwrap();
    let performed = raft::bootstrap_single_node(&raft, 7, "100.64.0.7:7443")
        .await
        .expect("re-bootstrap after restart does not error");
    assert!(
        !performed,
        "persisted membership means a restart re-bootstrap is a no-op"
    );
    wait_for_leader(&raft, 7, Duration::from_secs(10)).await;
    assert_eq!(voter_count(&raft), 1);
}
