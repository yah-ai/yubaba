//! R734-F2 — the quorum-geography gate on `POST /raft/initialize`.
//!
//! Part of R734-F2 — the canonical `@yah:ticket` annotation lives in
//! `src/raft/mod.rs`. Credential-free and containerd-free.
//!
//! W247 §2's rule: a founding voter set must be odd, and under the fleet policy
//! no single region may hold a majority of it. Three voters as 1-1-1 keep
//! writing when a region goes dark; the same three as 2-1 do not — and the two
//! clusters are indistinguishable from the outside until the day the two-voter
//! region is the one that fails. That delay is the whole reason this is a
//! refusal at founding rather than a warning or a dashboard.
//!
//! What these tests cover that the unit tests in `cluster_policy.rs` cannot:
//! that the rule is actually *wired* to the route, that it runs **before**
//! openraft is asked to write anything, and that the pre-region request shape
//! still deserializes so an old operator script gets the policy refusal rather
//! than a 422 that reads like a typo.
//!
//! ```bash
//! cargo test -p yubaba --test main -- raft_quorum_geography::
//! ```

use serde_json::json;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba_test_harness::{solo_node, SoloNode};

/// POST `/raft/initialize` with a raw `members` value; return status + body.
async fn post_initialize(
    node: &SoloNode,
    members: serde_json::Value,
) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .post(format!("{}/raft/initialize", node.base_url))
        .json(&json!({ "members": members }))
        .send()
        .await
        .expect("POST /raft/initialize");
    let status = resp.status();
    (status, resp.text().await.unwrap_or_default())
}

/// Whether this node has been initialised, read back from `/raft/status`.
///
/// The point of asserting on this rather than on the response code alone: a
/// gate that refuses *after* calling `raft.initialize` would return the same
/// 400 while having already committed the membership it just rejected.
async fn is_initialized(node: &SoloNode) -> bool {
    let status: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/raft/status", node.base_url))
        .send()
        .await
        .expect("GET /raft/status")
        .json()
        .await
        .expect("status json");
    status["membership_config"]["membership"]["configs"]
        .as_array()
        .is_some_and(|configs| configs.iter().any(|c| !c.as_array().unwrap().is_empty()))
}

/// [`is_initialized`], polled — the assertion to use on the ACCEPT path.
///
/// `Raft::initialize` returning `Ok` and the membership showing up in
/// `Raft::metrics` are not the same instant: metrics are published through a
/// watch channel, so a single read taken the moment the 200 lands can miss it.
/// On a loaded machine that window is wide enough to fail, which it did
/// (`a_rig_founds_three_untagged_voters`, intermittently, R734-F5's pass).
///
/// The refusal path deliberately keeps the *unpolled* read: there, "not
/// initialized" must be true immediately and stay true, and a poll would only
/// give a gate that initialised-then-refused extra chances to look correct.
async fn becomes_initialized(node: &SoloNode) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if is_initialized(node).await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// The canonical layout is accepted, and the lopsided one is refused with a
/// message that names both the offending region and the fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_fleet_refuses_a_founding_set_where_one_region_holds_a_majority() {
    let node = solo_node(1, ClusterPolicy::fleet())
        .await
        .expect("solo fleet node");

    // 2-1 across two regions: losing us-west stops writes.
    let (status, body) = post_initialize(
        &node,
        json!({
            "1": { "addr": "127.0.0.1:1", "region": "us-west" },
            "2": { "addr": "127.0.0.1:2", "region": "us-west" },
            "3": { "addr": "127.0.0.1:3", "region": "us-east" },
        }),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "a majority-holding region must be refused: {body}"
    );
    assert!(
        body.contains("us-west") && body.contains("1-1-1"),
        "the refusal must name the offending region and the layout to use: {body}"
    );
    assert!(
        !is_initialized(&node).await,
        "the gate must run BEFORE openraft writes the membership entry — a refusal that \
         leaves the cluster founded anyway is worse than no gate, because the operator is \
         told no and the bad config ships"
    );

    // 1-1-1 across three regions: accepted.
    let (status, body) = post_initialize(
        &node,
        json!({
            "1": { "addr": "127.0.0.1:1", "region": "us-west" },
            "2": { "addr": "127.0.0.1:2", "region": "us-east" },
            "3": { "addr": "127.0.0.1:3", "region": "us-south" },
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "1-1-1 is the layout the rule exists to produce, and must pass: {status} {body}"
    );
    assert!(
        becomes_initialized(&node).await,
        "an accepted founding set must actually found the cluster"
    );
}

/// The pre-R734-F2 request shape — `members` as `id -> "host:port"` — must still
/// deserialize.
///
/// Every existing runbook and operator script writes it. If it stopped parsing,
/// the operator would get a 422 about JSON shape, conclude they mistyped, and
/// never see the actual message about region tags. So the old form is accepted
/// by the parser and then *refused by policy*, which is the difference between
/// a dead end and an instruction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pre_region_request_shape_reaches_the_policy_refusal_not_a_parse_error() {
    let node = solo_node(1, ClusterPolicy::fleet())
        .await
        .expect("solo fleet node");

    let (status, body) = post_initialize(
        &node,
        json!({
            "1": "127.0.0.1:1",
            "2": "127.0.0.1:2",
            "3": "127.0.0.1:3",
        }),
    )
    .await;

    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "expected the policy refusal (400), not a deserialization failure: {status} {body}"
    );
    assert!(
        body.contains("region"),
        "the refusal must tell the operator that region tags are what is missing: {body}"
    );
    assert!(!is_initialized(&node).await);
}

/// A rig founds three untagged voters on one LAN. The spread rule does not
/// apply to a cluster with one failure domain, and demanding tags there would
/// make the preset unusable rather than safer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rig_founds_three_untagged_voters() {
    let node = solo_node(1, ClusterPolicy::rig())
        .await
        .expect("solo rig node");

    let (status, body) = post_initialize(
        &node,
        json!({
            "1": "127.0.0.1:1",
            "2": "127.0.0.1:2",
            "3": "127.0.0.1:3",
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "a rig's voters share a switch; untagged is correct there: {status} {body}"
    );
    assert!(becomes_initialized(&node).await);
}

/// An even voter set is refused under both policies, on the count alone, even
/// when it is perfectly spread. This is W247's "maybe 2 in each region"
/// footgun: 2-2-2 is six voters, which survives exactly what five does while
/// making every write wait on one more node.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn six_perfectly_spread_voters_are_refused_for_being_even() {
    for (name, policy) in [
        ("fleet", ClusterPolicy::fleet()),
        ("rig", ClusterPolicy::rig()),
    ] {
        let node = solo_node(1, policy).await.expect("solo node");
        let (status, body) = post_initialize(
            &node,
            json!({
                "1": { "addr": "127.0.0.1:1", "region": "us-west" },
                "2": { "addr": "127.0.0.1:2", "region": "us-west" },
                "3": { "addr": "127.0.0.1:3", "region": "us-east" },
                "4": { "addr": "127.0.0.1:4", "region": "us-east" },
                "5": { "addr": "127.0.0.1:5", "region": "us-south" },
                "6": { "addr": "127.0.0.1:6", "region": "us-south" },
            }),
        )
        .await;
        assert_eq!(
            status,
            reqwest::StatusCode::BAD_REQUEST,
            "{name} must refuse six voters however well spread: {body}"
        );
        assert!(!is_initialized(&node).await);
    }
}

/// The documented BYO-VPS bootstrap: a cluster-of-one, under the fleet profile,
/// with no region tag. There is no failure tolerance to protect and nothing to
/// spread, so the gate must not stand in its way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fleet_cluster_of_one_still_founds_untagged() {
    let node = solo_node(1, ClusterPolicy::fleet())
        .await
        .expect("solo fleet node");

    let (status, body) = post_initialize(&node, json!({ "1": "127.0.0.1:1" })).await;
    assert!(
        status.is_success(),
        "a single-voter bootstrap must stay open: {status} {body}"
    );
    assert!(becomes_initialized(&node).await);
}
