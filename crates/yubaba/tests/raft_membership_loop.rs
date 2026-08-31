//! R734-T3 — the membership loop closed: grow 3 → 5 voters, then shrink 5 → 3.
//!
//! Part of R734-T3 — the canonical `@yah:ticket` annotation lives in
//! `src/lib.rs`. Credential-free and containerd-free: five real yubaba nodes on
//! loopback under `ClusterPolicy::rig` (the promoting policy — the fleet's
//! `LearnerOnly` rule refuses promotion by design, so a growth test cannot be
//! written against it).
//!
//! This is W253 §10's last open box, "membership-change mechanism exercised and
//! tested", and the reason it needs a live cluster rather than a unit test: the
//! failure mode of joint consensus is not a wrong return value. openraft
//! proposes a joint configuration, waits for it to commit, then proposes the
//! uniform one; if the second never lands the cluster is left *in* the joint
//! config, which keeps working — it just now needs a quorum of both the old and
//! the new voter sets for every write, and nothing says so. So every transition
//! here asserts the settled membership is a **single uniform config**, not
//! merely that the voter list is right.
//!
//! The three claims:
//!
//! - **Growth**: two learners join, catch up, and are promoted — 3 → 4 → 5,
//!   uniform at every settled point.
//! - **Shrink**: 5 → 3 in ONE change removing two voters, and the departed
//!   nodes are gone from membership entirely rather than left as silent
//!   learners still receiving replication.
//! - **The count gate**: removing a single voter from three is refused, and the
//!   refusal is inert — the membership afterwards is exactly what it was.
//!
//! ```bash
//! cargo test -p yubaba --test main -- raft_membership_loop::
//! ```

use std::time::Duration;

use serde_json::json;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba_test_harness::{solo_node, SoloNode};

/// POST `path` on `base_url`; return status + body.
async fn post_json(base_url: &str, path: &str, body: serde_json::Value) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}{path}"))
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {path}: {e}"));
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
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

/// The settled voter set, asserting on the way through that membership is a
/// **single uniform config**.
///
/// A cluster stranded mid-transition still answers `/raft/status` with a
/// plausible-looking voter list — it just carries two configs instead of one,
/// and silently requires a quorum of each. Reading the voters without checking
/// the config count is how that state passes for healthy.
async fn uniform_voters(base_url: &str) -> Vec<u64> {
    let status = raft_status(base_url).await;
    let configs = status["membership_config"]["membership"]["configs"]
        .as_array()
        .expect("membership.configs array");
    assert_eq!(
        configs.len(),
        1,
        "membership must be a single uniform config, not a joint one — a cluster left in \
         joint consensus needs a quorum of BOTH voter sets for every write and never says \
         so: {configs:?}"
    );
    let mut voters: Vec<u64> = configs[0]
        .as_array()
        .expect("voter set array")
        .iter()
        .map(|v| v.as_u64().expect("voter id"))
        .collect();
    voters.sort_unstable();
    voters
}

/// Poll until `base_url` reports exactly `want` as its uniform voter set.
async fn wait_for_voters(base_url: &str, want: &[u64], timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    let seen;
    loop {
        let now = uniform_voters(base_url).await;
        if now == want {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            seen = now;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("voters never settled on {want:?}; last seen {seen:?}");
}

/// Every node id membership knows about, voters and learners alike.
async fn known_nodes(base_url: &str) -> Vec<u64> {
    let status = raft_status(base_url).await;
    let mut ids: Vec<u64> = status["membership_config"]["membership"]["nodes"]
        .as_object()
        .expect("membership.nodes object")
        .keys()
        .map(|k| k.parse().expect("node id key"))
        .collect();
    ids.sort_unstable();
    ids
}

/// Wait until every node in `voters` names the **same** live leader, and return
/// its index into `voters`.
///
/// Deliberately not "wait until node 1 leads". Node 1 issues the `initialize`
/// call, but that only writes the founding membership — it does not hand node 1
/// the election. Any of the three can win, and under a loaded test machine
/// another node's timer routinely fires first. A helper that demanded node 1
/// would be encoding a race as a requirement, and would fail on the transitions
/// this suite is actually about.
async fn wait_for_agreed_leader(voters: &[&SoloNode], timeout: Duration) -> usize {
    let deadline = tokio::time::Instant::now() + timeout;
    let ids: Vec<u64> = voters.iter().map(|n| n.node_id).collect();
    loop {
        let mut beliefs = Vec::with_capacity(voters.len());
        for node in voters {
            beliefs.push(raft_status(&node.base_url).await["current_leader"].as_u64());
        }
        if let Some(Some(leader)) = beliefs.first().copied() {
            if beliefs.iter().all(|b| *b == Some(leader)) {
                if let Some(idx) = ids.iter().position(|id| *id == leader) {
                    return idx;
                }
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "voters never agreed on a leader; last per-node current_leader was {beliefs:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Found a 3-voter rig cluster on nodes 1..=3 and return all five nodes plus the
/// leader's index into that vector.
async fn three_voter_cluster_of_five_nodes() -> (Vec<SoloNode>, usize) {
    let policy = ClusterPolicy::rig();
    let mut nodes = Vec::new();
    for id in 1..=5u64 {
        nodes.push(solo_node(id, policy).await.expect("solo rig node"));
    }

    let members: serde_json::Map<String, serde_json::Value> = (0..3)
        .map(|i| (nodes[i].node_id.to_string(), json!(nodes[i].addr)))
        .collect();
    let (status, body) = post_json(
        &nodes[0].base_url,
        "/raft/initialize",
        json!({ "members": members }),
    )
    .await;
    assert_eq!(status, 200, "founding a 3-voter rig cluster: {body}");

    let voters: Vec<&SoloNode> = nodes.iter().take(3).collect();
    let leader_idx = wait_for_agreed_leader(&voters, Duration::from_secs(30)).await;
    assert_eq!(
        uniform_voters(&nodes[leader_idx].base_url).await,
        vec![1, 2, 3]
    );
    (nodes, leader_idx)
}

/// Join `node` as a learner, then promote it, and wait for the uniform config.
async fn add_and_promote(leader: &SoloNode, node: &SoloNode, expect_voters: &[u64]) {
    let (status, body) = post_json(
        &leader.base_url,
        "/raft/add-learner",
        json!({ "node_id": node.node_id, "addr": node.addr }),
    )
    .await;
    assert_eq!(status, 200, "add-learner {}: {body}", node.node_id);

    let (status, body) = post_json(
        &leader.base_url,
        "/raft/promote-voter",
        json!({ "node_id": node.node_id }),
    )
    .await;
    assert_eq!(status, 200, "promote-voter {}: {body}", node.node_id);
    wait_for_voters(&leader.base_url, expect_voters, Duration::from_secs(15)).await;
}

/// The full loop, in one test because the interesting assertions are about the
/// transitions between these states rather than about any one of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_cluster_grows_three_to_five_and_shrinks_back_without_a_split_brain() {
    let (nodes, leader_idx) = three_voter_cluster_of_five_nodes().await;
    let leader = &nodes[leader_idx];

    // ── Grow 3 → 4 → 5 ────────────────────────────────────────────────────
    // One at a time, which is the path an operator actually takes, and which
    // passes through an even voter set on the way. That is why the odd-count
    // rule lives on founding and removal rather than on promotion: forbidding
    // every even intermediate would forbid this growth entirely.
    add_and_promote(leader, &nodes[3], &[1, 2, 3, 4]).await;
    add_and_promote(leader, &nodes[4], &[1, 2, 3, 4, 5]).await;

    assert_eq!(
        known_nodes(&leader.base_url).await,
        vec![1, 2, 3, 4, 5],
        "all five must be in membership after the growth"
    );

    // ── The count gate: 5 → 4 is refused ──────────────────────────────────
    let before = uniform_voters(&leader.base_url).await;
    let (status, body) = post_json(
        &leader.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [5] }),
    )
    .await;
    assert_eq!(
        status, 400,
        "removing one voter from five leaves an even set and must be refused: {body}"
    );
    assert!(
        body.contains("odd"),
        "the refusal must say which rule refused it: {body}"
    );
    assert_eq!(
        uniform_voters(&leader.base_url).await,
        before,
        "a refused removal must be inert — no partial membership change"
    );

    // ── Shrink 5 → 3 in one change ────────────────────────────────────────
    let (status, body) = post_json(
        &leader.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [4, 5] }),
    )
    .await;
    assert_eq!(status, 200, "removing both voters at once: {body}");
    wait_for_voters(&leader.base_url, &[1, 2, 3], Duration::from_secs(15)).await;

    assert_eq!(
        known_nodes(&leader.base_url).await,
        vec![1, 2, 3],
        "removed members must leave the cluster entirely, not linger as learners still \
         receiving replication that nobody remembers is running"
    );

    // ── No split-brain: every surviving voter agrees on one leader, and it is
    // one of them. The removed nodes' opinions are explicitly not consulted —
    // they are out of the cluster, and what they still believe is not the
    // cluster's state.
    let mut beliefs = Vec::new();
    for node in nodes.iter().take(3) {
        beliefs.push(raft_status(&node.base_url).await["current_leader"].as_u64());
    }
    let first = beliefs[0];
    assert!(
        first.is_some_and(|id| (1..=3).contains(&id)),
        "the surviving cluster must name a leader from among the survivors: {beliefs:?}"
    );
    assert!(
        beliefs.iter().all(|b| *b == first),
        "every surviving voter must name the SAME leader after the transition: {beliefs:?}"
    );

    // ── 3 → 2 is refused too, for the same reason ─────────────────────────
    let (status, body) = post_json(
        &leader.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [3] }),
    )
    .await;
    assert_eq!(
        status, 400,
        "removing one voter from three is the drain-a-machine mistake, and must be \
         refused: {body}"
    );
    assert_eq!(uniform_voters(&leader.base_url).await, vec![1, 2, 3]);
}

/// Removing a learner touches no voter, so the count gate does not apply — and
/// must not, or a cluster could never shed a read replica.
///
/// The distinction the endpoint has to get right: a learner is in `nodes` but
/// not in `configs`, so a gate that judged "membership size" rather than "voter
/// count" would refuse this and be wrong in a way that looks principled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_learner_is_not_judged_against_the_voter_count() {
    let (nodes, leader_idx) = three_voter_cluster_of_five_nodes().await;
    let leader = &nodes[leader_idx];
    let learner = &nodes[3];

    let (status, body) = post_json(
        &leader.base_url,
        "/raft/add-learner",
        json!({ "node_id": learner.node_id, "addr": learner.addr }),
    )
    .await;
    assert_eq!(status, 200, "add-learner: {body}");
    assert_eq!(known_nodes(&leader.base_url).await, vec![1, 2, 3, 4]);

    // Three voters plus one learner. Removing the learner leaves three voters,
    // which is fine; a naive "membership must stay odd" gate would see 4 → 3
    // and let it through for the wrong reason, so the assertion that matters is
    // that the voter set never moved.
    let (status, body) = post_json(
        &leader.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [learner.node_id] }),
    )
    .await;
    assert_eq!(status, 200, "removing a learner must be allowed: {body}");

    assert_eq!(
        known_nodes(&leader.base_url).await,
        vec![1, 2, 3],
        "the learner must be gone from membership"
    );
    assert_eq!(
        uniform_voters(&leader.base_url).await,
        vec![1, 2, 3],
        "and the voter set must be untouched"
    );
}

/// Removal is idempotent. A drain script re-run must not fail for work already
/// done — an error there teaches operators to ignore errors from this endpoint,
/// which is exactly the habit the 400 refusals depend on them not having.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_node_the_cluster_never_knew_is_a_no_op_not_an_error() {
    let (nodes, leader_idx) = three_voter_cluster_of_five_nodes().await;
    let leader = &nodes[leader_idx];

    let (status, body) = post_json(
        &leader.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [99] }),
    )
    .await;
    assert_eq!(
        status, 200,
        "removing an unknown node must not error: {body}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(
        parsed["removed"], false,
        "and it must report that nothing was removed rather than claiming success: {body}"
    );
    assert_eq!(
        parsed["already_absent"],
        json!([99]),
        "the response must name the ids that were already absent, so a typo is still \
         visible to the operator: {body}"
    );
    assert_eq!(uniform_voters(&leader.base_url).await, vec![1, 2, 3]);
}

/// A follower cannot change membership. It returns 421 with the leader hint so
/// the caller can retarget, rather than a bare 500 that reads like a fault.
///
/// Removing two of three voters is a strange thing to want, and it is chosen
/// here precisely because it *passes* the count gate (one survivor is odd) — so
/// the request gets far enough to reach openraft and produce the redirect. See
/// [`a_follower_refuses_an_invalid_change_before_redirecting`] for the other
/// ordering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_follower_redirects_remove_member_to_the_leader() {
    let (nodes, leader_idx) = three_voter_cluster_of_five_nodes().await;
    let follower = nodes
        .iter()
        .take(3)
        .enumerate()
        .find(|(i, _)| *i != leader_idx)
        .map(|(_, n)| n)
        .expect("a follower among the three voters");

    let (status, body) = post_json(
        &follower.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [2, 3] }),
    )
    .await;
    assert_eq!(
        status, 421,
        "a follower must redirect rather than attempt the change: {body}"
    );
    assert!(
        body.contains("leader"),
        "the redirect must name where to retarget: {body}"
    );
}

/// Validation runs **before** the leader check, so a follower answers an
/// invalid change with the 400 rather than the 421.
///
/// That ordering is a choice, and this test exists so it stays one. Membership
/// metrics are replicated, so every node can judge the count identically — and
/// a change that is invalid is invalid at the leader too. Answering "retarget
/// at the leader" first would send an operator to do exactly the same thing
/// again and get the real answer on the second try, having learned nothing on
/// the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_follower_refuses_an_invalid_change_before_redirecting() {
    let (nodes, leader_idx) = three_voter_cluster_of_five_nodes().await;
    let follower = nodes
        .iter()
        .take(3)
        .enumerate()
        .find(|(i, _)| *i != leader_idx)
        .map(|(_, n)| n)
        .expect("a follower among the three voters");

    // 3 → 2: invalid anywhere, asked of a node that also is not the leader.
    let (status, body) = post_json(
        &follower.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [3] }),
    )
    .await;
    assert_eq!(
        status, 400,
        "the operator should learn the change is invalid, not be sent to the leader to \
         find that out: {body}"
    );
    assert!(
        body.contains("odd"),
        "and be told which rule refused: {body}"
    );
}
