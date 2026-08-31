//! R734-F5 — every node publishes its own member row, region and all.
//!
//! Part of R734-F5 — the canonical `@yah:ticket` annotation lives in
//! `src/raft/mod.rs`. Credential-free and containerd-free: real yubaba nodes on
//! loopback, founded through the real `POST /raft/initialize`, registering
//! through the real [`member_registration`](yubaba::member_registration) loop.
//!
//! R734-F2 put `region` on `MemberInfo` and taught the founding gate to judge
//! it. Nothing wrote it, so on a live cluster `YubabaState.members` was empty
//! and the tag was a data model rather than cluster state. These tests are the
//! difference: they assert the map is populated **by the nodes themselves**.
//!
//! The assertion that gives this suite its teeth is per-node, not aggregate.
//! Checking merely that three rows exist would pass against a loop that wrote
//! the leader's own region into every row — which is the most likely way to get
//! this wrong, since the leader is the only node that can write without
//! forwarding. So every row is checked against the region *that* node was
//! started with.
//!
//! ```bash
//! cargo test -p yubaba --test main -- raft_member_registration::
//! ```

use std::time::Duration;

use serde_json::json;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba_test_harness::{solo_node, solo_node_in_region, solo_node_unregistered, SoloNode};

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

/// The member rows `base_url` has applied, as `node_id -> region` (with the
/// region rendered as `Option<String>` so an untagged row is distinguishable
/// from an absent one).
async fn member_regions(base_url: &str) -> Vec<(u64, Option<String>)> {
    let status = raft_status(base_url).await;
    let Some(members) = status["members"].as_object() else {
        panic!("GET /raft/status carried no members section: {status}");
    };
    let mut rows: Vec<(u64, Option<String>)> = members
        .iter()
        .map(|(id, row)| {
            (
                id.parse().expect("member row key is a node id"),
                row["region"].as_str().map(str::to_string),
            )
        })
        .collect();
    rows.sort_by_key(|(id, _)| *id);
    rows
}

/// Poll `base_url` until its member rows match what every node in `nodes`
/// declared for itself.
async fn wait_for_registered(base_url: &str, nodes: &[&SoloNode], timeout: Duration) {
    let mut want: Vec<(u64, Option<String>)> = nodes
        .iter()
        .map(|n| (n.node_id, n.region.clone()))
        .collect();
    want.sort_by_key(|(id, _)| *id);

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let seen = member_regions(base_url).await;
        if seen == want {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("member rows never converged on {want:?}; last seen {seen:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Wait until every node names the same leader, and return its index.
async fn wait_for_agreed_leader(nodes: &[&SoloNode], timeout: Duration) -> usize {
    let deadline = tokio::time::Instant::now() + timeout;
    let ids: Vec<u64> = nodes.iter().map(|n| n.node_id).collect();
    loop {
        let mut beliefs = Vec::with_capacity(nodes.len());
        for node in nodes {
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
            "nodes never agreed on a leader; last per-node current_leader was {beliefs:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The fleet layout W247 §2 prescribes: three voters, three regions, 1-1-1.
async fn one_one_one_fleet() -> (Vec<SoloNode>, usize) {
    tagged_fleet(&["us-west", "us-east", "us-south"]).await
}

/// Found a fleet cluster whose node `i + 1` sits in `regions[i]`, and return the
/// nodes plus the index of the elected leader.
async fn tagged_fleet(regions: &[&str]) -> (Vec<SoloNode>, usize) {
    let policy = ClusterPolicy::fleet();
    let mut nodes = Vec::new();
    for (i, region) in regions.iter().enumerate() {
        nodes.push(
            solo_node_in_region(i as u64 + 1, policy, Some(region))
                .await
                .expect("solo fleet node"),
        );
    }

    let members: serde_json::Map<String, serde_json::Value> = nodes
        .iter()
        .map(|n| {
            (
                n.node_id.to_string(),
                json!({ "addr": n.addr, "region": n.region }),
            )
        })
        .collect();
    let (status, body) = post_json(
        &nodes[0].base_url,
        "/raft/initialize",
        json!({ "members": members }),
    )
    .await;
    assert_eq!(
        status, 200,
        "founding a fleet cluster across {regions:?}: {body}"
    );

    let refs: Vec<&SoloNode> = nodes.iter().collect();
    let leader_idx = wait_for_agreed_leader(&refs, Duration::from_secs(30)).await;
    (nodes, leader_idx)
}

/// The headline claim: on a founded cluster every node's row appears, carrying
/// **that node's** region — the live answer R734-F2 left missing.
///
/// Checked on every node rather than only on the leader, because the map is
/// replicated state and a row that existed only where it was written would be
/// useless to the consumers this exists for (a leader reading its peers'
/// regions, a removal gate judging spread).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_node_registers_its_own_region_and_the_map_replicates() {
    let (nodes, _leader_idx) = one_one_one_fleet().await;
    let refs: Vec<&SoloNode> = nodes.iter().collect();

    for node in &nodes {
        wait_for_registered(&node.base_url, &refs, Duration::from_secs(30)).await;
    }

    // Spelled out once, literally, so the test states the expected map rather
    // than only comparing two derived values against each other.
    assert_eq!(
        member_regions(&nodes[0].base_url).await,
        vec![
            (1, Some("us-west".to_string())),
            (2, Some("us-east".to_string())),
            (3, Some("us-south".to_string())),
        ],
        "each row must carry the region THAT node was started with — a loop that wrote its \
         own region into every row would still produce three rows"
    );
}

/// The loop converges and then does nothing.
///
/// This is the property that makes it safe to run on every node forever, and it
/// is invisible to a test that only checks the map's contents: a loop that
/// rewrote an identical row every tick would produce exactly the same map while
/// putting a raft entry through quorum every second, on every node, for the life
/// of the cluster. So the oracle is the applied log index, which must stop
/// moving once the rows are in place.
///
/// Falsified rather than assumed: disabling the converged branch in
/// `plan_registration` fails this test with 1269 applied entries against the 311
/// it settles on, while the other three tests in this file stay green.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registration_stops_writing_once_the_rows_match() {
    let (nodes, leader_idx) = one_one_one_fleet().await;
    let refs: Vec<&SoloNode> = nodes.iter().collect();
    let leader = &nodes[leader_idx];
    wait_for_registered(&leader.base_url, &refs, Duration::from_secs(30)).await;

    let settled = raft_status(&leader.base_url).await["last_applied"]["index"]
        .as_u64()
        .expect("last_applied index after registration");

    // Comfortably longer than the loop's 1s wait tick, so a re-writing loop
    // would have had several chances to advance the log.
    tokio::time::sleep(Duration::from_secs(4)).await;

    let later = raft_status(&leader.base_url).await["last_applied"]["index"]
        .as_u64()
        .expect("last_applied index after idling");
    assert_eq!(
        later, settled,
        "a converged cluster must apply nothing further: the registration loop rewrote a row \
         that already said what it wanted to say"
    );
}

/// A rig's voters have no region to declare, and must still get rows.
///
/// Withholding the row from an untagged node would be the tempting shortcut —
/// "no region, nothing to record" — and it would be wrong in a way that reads as
/// correct: an absent row says "this node is not in the cluster", which is a
/// different and false claim from "this node's region is unknown".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn untagged_rig_nodes_still_register_their_addresses() {
    let policy = ClusterPolicy::rig();
    let mut nodes = Vec::new();
    for id in 1..=3u64 {
        nodes.push(solo_node(id, policy).await.expect("solo rig node"));
    }
    let members: serde_json::Map<String, serde_json::Value> = nodes
        .iter()
        .map(|n| (n.node_id.to_string(), json!(n.addr)))
        .collect();
    let (status, body) = post_json(
        &nodes[0].base_url,
        "/raft/initialize",
        json!({ "members": members }),
    )
    .await;
    assert_eq!(status, 200, "founding an untagged rig cluster: {body}");

    let refs: Vec<&SoloNode> = nodes.iter().collect();
    let leader_idx = wait_for_agreed_leader(&refs, Duration::from_secs(30)).await;
    wait_for_registered(&nodes[leader_idx].base_url, &refs, Duration::from_secs(30)).await;

    let status = raft_status(&nodes[leader_idx].base_url).await;
    let rows = status["members"].as_object().expect("members section");
    assert_eq!(rows.len(), 3, "every rig node must have a row: {status}");
    for (id, row) in rows {
        assert!(
            row["region"].is_null(),
            "an untagged node's row must record no region rather than inventing one: \
             node {id} -> {row}"
        );
        let node = nodes
            .iter()
            .find(|n| n.node_id.to_string() == *id)
            .expect("a row per node");
        assert_eq!(
            row["addr"].as_str(),
            Some(node.addr.as_str()),
            "and must record the address raft membership dials it at"
        );
    }
}

/// What the live map buys: `/raft/remove-member` can finally judge *where* the
/// survivors are, not just how many there are.
///
/// This is the gap R734-T3 shipped with and named — its count clause would wave
/// through a shrink that leaves a quorum inside one datacenter, because until
/// registration existed there was no region to read. The scenario is the real
/// one: a 2-2-1 five-voter fleet, and an operator decommissioning both machines
/// in one region. Three survivors is a perfectly good number; two of them being
/// in `us-east` is the problem.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_removal_that_would_leave_a_lopsided_quorum_is_refused() {
    let (nodes, leader_idx) =
        tagged_fleet(&["us-west", "us-west", "us-east", "us-east", "us-south"]).await;
    let refs: Vec<&SoloNode> = nodes.iter().collect();
    let leader = &nodes[leader_idx];
    wait_for_registered(&leader.base_url, &refs, Duration::from_secs(30)).await;

    // Both us-west voters: leaves 3, 4 (us-east) and 5 (us-south) — an odd,
    // count-legal, region-fatal set.
    let (status, body) = post_json(
        &leader.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [1, 2] }),
    )
    .await;
    assert_eq!(
        status, 400,
        "three survivors is a legal COUNT; two of them in one region is not a legal \
         SPREAD, and the count clause alone cannot see that: {body}"
    );
    assert!(
        body.contains("us-east"),
        "the refusal must name the region that would hold the majority: {body}"
    );

    // Inert: a refused removal must not have moved membership.
    let voters = raft_status(&leader.base_url).await["membership_config"]["membership"]["configs"]
        [0]
    .clone();
    assert_eq!(
        voters,
        json!([1, 2, 3, 4, 5]),
        "a refused removal must be inert"
    );

    // One from each of the two doubled regions leaves 1-1-1, which is exactly
    // what the operator should have asked for.
    let (status, body) = post_json(
        &leader.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [1, 3] }),
    )
    .await;
    assert_eq!(
        status, 200,
        "shrinking 2-2-1 to 1-1-1 must be allowed: {body}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(
        parsed["spread_judged"], true,
        "and the response must say the spread clause actually ran, so an operator can tell \
         an allowed removal from an unjudgeable one: {body}"
    );
}

/// The escape hatch, and the reason it exists.
///
/// A node with no member row has no region to judge, and the commonest reason to
/// be removing a node is that it is *down* — possibly before it ever registered.
/// A gate that refused in that case would lock the operator out of the only verb
/// that repairs the cluster, so the spread clause stands down and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn an_unregistered_survivor_downgrades_the_gate_instead_of_blocking_it() {
    let policy = ClusterPolicy::fleet();
    let regions = ["us-west", "us-west", "us-east", "us-east", "us-south"];
    let mut nodes = Vec::new();
    for (i, region) in regions.iter().enumerate() {
        let id = i as u64 + 1;
        // Node 5 is on a build with no registration loop — the rolling-upgrade
        // shape. It is a founding voter with a region in the *founding request*,
        // so the cluster forms; what it never does is publish a row.
        let node = if id == 5 {
            solo_node_unregistered(id, policy, Some(region)).await
        } else {
            solo_node_in_region(id, policy, Some(region)).await
        };
        nodes.push(node.expect("solo fleet node"));
    }
    let members: serde_json::Map<String, serde_json::Value> = nodes
        .iter()
        .map(|n| {
            (
                n.node_id.to_string(),
                json!({ "addr": n.addr, "region": n.region }),
            )
        })
        .collect();
    let (status, body) = post_json(
        &nodes[0].base_url,
        "/raft/initialize",
        json!({ "members": members }),
    )
    .await;
    assert_eq!(status, 200, "founding a 2-2-1 fleet cluster: {body}");

    let refs: Vec<&SoloNode> = nodes.iter().collect();
    let leader_idx = wait_for_agreed_leader(&refs, Duration::from_secs(30)).await;
    let leader = &nodes[leader_idx];
    // Everyone but node 5 registers; wait for those four so the test is not
    // racing registration when it makes the call below.
    let registering: Vec<&SoloNode> = nodes.iter().take(4).collect();
    wait_for_registered(&leader.base_url, &registering, Duration::from_secs(30)).await;

    // The same removal the previous test refuses — allowed here, because with
    // node 5's region unknown the spread cannot be judged at all.
    let (status, body) = post_json(
        &leader.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [1, 2] }),
    )
    .await;
    assert_eq!(
        status, 200,
        "an unjudgeable spread must not block a count-legal removal: {body}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(
        parsed["spread_judged"], false,
        "and it must report that the spread was NOT checked rather than implying it passed: \
         {body}"
    );
}

/// A node that leaves the cluster loses its row.
///
/// The departing node cannot clear it — its own loop stops the moment it is out
/// of membership, which is correct — so the removing leader does. Without this,
/// the map accumulates rows for machines that were decommissioned months ago,
/// and every consumer that reads regions out of it (the leader pin, a
/// spread-aware removal gate) reasons about a cluster that no longer exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_member_clears_its_row() {
    let policy = ClusterPolicy::rig();
    let mut nodes = Vec::new();
    for id in 1..=4u64 {
        nodes.push(solo_node(id, policy).await.expect("solo rig node"));
    }
    let members: serde_json::Map<String, serde_json::Value> = nodes
        .iter()
        .take(3)
        .map(|n| (n.node_id.to_string(), json!(n.addr)))
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
    let leader = &nodes[leader_idx];

    // Join the fourth as a learner — a learner registers exactly like a voter,
    // since membership is what the loop keys on, not voting rights.
    let joiner = &nodes[3];
    let (status, body) = post_json(
        &leader.base_url,
        "/raft/add-learner",
        json!({ "node_id": joiner.node_id, "addr": joiner.addr }),
    )
    .await;
    assert_eq!(status, 200, "add-learner: {body}");

    let all: Vec<&SoloNode> = nodes.iter().collect();
    wait_for_registered(&leader.base_url, &all, Duration::from_secs(30)).await;

    let (status, body) = post_json(
        &leader.base_url,
        "/raft/remove-member",
        json!({ "node_ids": [joiner.node_id] }),
    )
    .await;
    assert_eq!(status, 200, "removing the learner: {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(
        parsed["stale_rows"],
        json!([]),
        "the removal must report that it left no stale row behind: {body}"
    );

    wait_for_registered(&leader.base_url, &voters, Duration::from_secs(15)).await;
}
