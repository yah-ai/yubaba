//! R736-T3 (W250) — cell tagging, and a second cell standing up beside the
//! first.
//!
//! Part of R736-T3 — the canonical `@yah:ticket` annotation lives in
//! `src/cluster_policy.rs`. The rule is implemented in `src/cell.rs` and wired
//! in `src/lib.rs`. Credential-free and containerd-free.
//!
//! A cell is one yubaba raft group bound to one jurisdiction, and it is the unit
//! the global tenant pointer names: `tenants/<tenant>/cell.toml` says which cell
//! owns a tenant, and R736-T2's fence lets a node write only while the pointer
//! agrees with the cell that node is in. All of that rests on a cluster being
//! able to answer *which cell am I*, which is what these tests exercise end to
//! end.
//!
//! What they cover that the unit tests in `src/cell.rs` cannot:
//!
//! - that two cells genuinely **stand up independently** — separate quorums,
//!   separate leaders, disjoint membership — rather than being one cluster with
//!   two labels;
//! - that neither can absorb the other, which is W250's *"never merge"* rule and
//!   is enforced by R742-F1's gate rather than by anything new here;
//! - that a box in the right group but the **wrong jurisdiction** is refused,
//!   because that is the misconfiguration a cell cannot survive quietly: one
//!   voter across a legal boundary breaks residency for every tenant in the cell
//!   at once;
//! - that a sovereign group which declares **no** jurisdiction is untouched by
//!   all of it — which is every cluster in the fleet today, so this is the
//!   assertion that says the change ships inert.
//!
//! Each cell here is founded as a cluster-of-one. A real cell is three voters
//! spanning regions (W247 §2, and `QuorumGeography::MustSpanRegions` refuses
//! anything else) — but the spread rule is R734-F2's and has its own tests, and
//! nothing about cell tagging varies with voter count. One node per cell keeps
//! these tests about the thing they name.
//!
//! ```bash
//! cargo test -p yubaba --test main -- raft_cell_tagging::
//! ```

use std::time::Duration;

use serde_json::json;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba_test_harness::{solo_node_in_cell, solo_node_in_sovereign_group, SoloNode};

/// The fleet policy, because a cell is a fleet cluster: residency is a property
/// of the cloud deployment, and a rig has one failure domain and no jurisdiction
/// to speak of. A cluster-of-one founds cleanly under it — `judge` returns
/// `Sound` at `count == 1` — so this costs the tests nothing.
fn policy() -> ClusterPolicy {
    ClusterPolicy::fleet()
}

async fn status(node: &SoloNode) -> serde_json::Value {
    reqwest::Client::new()
        .get(format!("{}/raft/status", node.base_url))
        .send()
        .await
        .expect("GET /raft/status")
        .json()
        .await
        .expect("status json")
}

/// Found `node` as a cluster-of-one and wait until it has elected itself, so a
/// later `add-learner` reaches a real leader instead of bouncing on 421.
async fn found(node: &SoloNode) {
    let resp = reqwest::Client::new()
        .post(format!("{}/raft/initialize", node.base_url))
        .json(&json!({ "members": { node.node_id.to_string(): node.addr } }))
        .send()
        .await
        .expect("POST /raft/initialize");
    assert!(
        resp.status().is_success(),
        "founding node {} failed: {} {:?}",
        node.node_id,
        resp.status(),
        resp.text().await
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if status(node).await["current_leader"].as_u64() == Some(node.node_id) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "node {} never became leader of its cluster-of-one",
            node.node_id
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn add_learner(leader: &SoloNode, joiner: &SoloNode) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .post(format!("{}/raft/add-learner", leader.base_url))
        .json(&json!({ "node_id": joiner.node_id, "addr": joiner.addr }))
        .send()
        .await
        .expect("POST /raft/add-learner");
    let code = resp.status();
    (code, resp.text().await.unwrap_or_default())
}

/// Node ids this cluster's membership knows about — voters *and* learners.
async fn membership_ids(node: &SoloNode) -> Vec<u64> {
    status(node).await["membership_config"]["membership"]["nodes"]
        .as_object()
        .expect("membership.nodes object")
        .keys()
        .filter_map(|k| k.parse().ok())
        .collect()
}

/// The headline of this ticket: a US cell and an EU cell, up at the same time,
/// each answering with its own tag and knowing nothing about the other.
///
/// The membership assertion is the one that makes this a *second cell* rather
/// than a second label — two clusters that shared a quorum would each list both
/// nodes, and every residency guarantee downstream would be decoration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_cells_stand_up_independently_and_each_reports_its_own_tag() {
    let us = solo_node_in_cell(1, policy(), "prod-us", "us", "us-west")
        .await
        .expect("US cell node");
    let eu = solo_node_in_cell(2, policy(), "prod-eu", "eu", "eu-central")
        .await
        .expect("EU cell node");
    found(&us).await;
    found(&eu).await;

    let us_status = status(&us).await;
    assert_eq!(us_status["cell"]["id"], json!("prod-us"));
    assert_eq!(us_status["cell"]["jurisdiction"], json!("us"));
    let eu_status = status(&eu).await;
    assert_eq!(eu_status["cell"]["id"], json!("prod-eu"));
    assert_eq!(eu_status["cell"]["jurisdiction"], json!("eu"));

    assert_eq!(
        membership_ids(&us).await,
        vec![us.node_id],
        "the US cell's quorum must contain only its own voter"
    );
    assert_eq!(
        membership_ids(&eu).await,
        vec![eu.node_id],
        "the EU cell is a separate raft group, not a member of the US one"
    );
    assert_ne!(
        us_status["cell"]["id"], eu_status["cell"]["id"],
        "two cells must be distinguishable by the id the global tenant pointer records"
    );
}

/// The cell id is the sovereign-group label, so W250's "never merge the cells"
/// rule is R742-F1's cross-group gate — already shipped, and the reason this
/// ticket did not add a second identity to keep in sync with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_cell_cannot_absorb_another_cells_node() {
    let us = solo_node_in_cell(1, policy(), "prod-us", "us", "us-west")
        .await
        .expect("US cell node");
    let eu = solo_node_in_cell(2, policy(), "prod-eu", "eu", "eu-central")
        .await
        .expect("EU cell node");
    found(&us).await;

    let (code, body) = add_learner(&us, &eu).await;
    assert_eq!(
        code,
        reqwest::StatusCode::CONFLICT,
        "a node from another cell must be refused: {body}"
    );
    assert!(
        body.contains("prod-us") && body.contains("prod-eu"),
        "the refusal must name both cells: {body}"
    );
    assert_eq!(
        membership_ids(&us).await,
        vec![us.node_id],
        "a refused join must leave membership untouched"
    );
}

/// The failure cell tagging exists to catch: a box that is genuinely in this
/// cell's blast radius — same sovereign group, so R742-F1 permits it — while
/// sitting in another jurisdiction. A copy-pasted unit file, or a machine moved
/// between datacentres without its TOML following it.
///
/// Silent acceptance here is the expensive outcome, because it does not break
/// the new tenant: it breaks the residency promise for every tenant already in
/// the cell, invisibly, from the moment that voter starts replicating.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voter_in_the_wrong_jurisdiction_is_refused_inside_the_right_cell() {
    let us = solo_node_in_cell(1, policy(), "prod-us", "us", "us-west")
        .await
        .expect("US cell node");
    // Same cell id, wrong jurisdiction — the misconfiguration, not a second cell.
    let misconfigured = solo_node_in_cell(2, policy(), "prod-us", "eu", "eu-central")
        .await
        .expect("misconfigured node");
    found(&us).await;

    let (code, body) = add_learner(&us, &misconfigured).await;
    assert_eq!(
        code,
        reqwest::StatusCode::CONFLICT,
        "a cross-jurisdiction voter must be refused: {body}"
    );
    assert!(
        body.contains("\"us\"") && body.contains("\"eu\""),
        "the refusal must name both jurisdictions, since one of the two is simply wrong: {body}"
    );
    assert!(
        !body.contains("cross-group join refused"),
        "the sovereign group MATCHES here — a blast-radius message would send the operator to \
         fix the wrong label: {body}"
    );
    assert_eq!(
        membership_ids(&us).await,
        vec![us.node_id],
        "the gate must run before add_learner, so a refused join adds nothing"
    );
}

/// The permit path, and the receipt for it: a join inside one cell says which
/// jurisdiction it judged, so a join that was never checked cannot be mistaken
/// for one that passed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_inside_one_cell_is_permitted_and_names_the_jurisdiction_it_judged() {
    let leader = solo_node_in_cell(1, policy(), "prod-us", "us", "us-west")
        .await
        .expect("US cell leader");
    let joiner = solo_node_in_cell(2, policy(), "prod-us", "us", "us-east")
        .await
        .expect("US cell joiner");
    found(&leader).await;

    let (code, body) = add_learner(&leader, &joiner).await;
    assert!(
        code.is_success(),
        "a join within one cell must be permitted: {code} {body}"
    );
    let body: serde_json::Value = serde_json::from_str(&body).expect("add-learner json");
    assert_eq!(body["cell_judged"], json!(true));
    assert_eq!(body["jurisdiction"], json!("us"));
    assert_eq!(
        body["sovereign_group"],
        json!("prod-us"),
        "one label answers both questions — the cell id IS the sovereign group"
    );
}

/// The back-compat assertion, and the one that says this ships inert: a
/// sovereign group that declares no jurisdiction is not a cell, so the residency
/// gate does not run — and says so rather than reporting a check that passed.
///
/// This is every cluster in the fleet today. If this test ever fails, the prod
/// raft has stopped accepting members for a residency rule nobody turned on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_group_that_is_not_a_cell_judges_no_jurisdiction_at_all() {
    let leader = solo_node_in_sovereign_group(1, policy(), Some("prod"))
        .await
        .expect("ungoverned leader");
    // The joiner declares one; the leader does not. The gate is in force exactly
    // when the TARGET is a cell, mirroring how R742-F1's is in force exactly
    // when the target declares a group.
    let joiner = solo_node_in_cell(2, policy(), "prod", "us", "us-west")
        .await
        .expect("cell joiner");
    found(&leader).await;

    assert!(
        status(&leader).await.get("cell").is_none(),
        "a group with no jurisdiction must not report a cell section"
    );
    assert_eq!(
        status(&leader).await["jurisdiction"],
        json!(null),
        "the key is present and null — a build that predates the field omits it entirely, and \
         the two get different operator instructions"
    );

    let (code, body) = add_learner(&leader, &joiner).await;
    assert!(
        code.is_success(),
        "an unbound group must still grow exactly as it did before cell tagging: {code} {body}"
    );
    let body: serde_json::Value = serde_json::from_str(&body).expect("add-learner json");
    assert_eq!(
        body["cell_judged"],
        json!(false),
        "nothing was judged; reporting `true` here would claim a residency check that never ran"
    );
    assert_eq!(body["jurisdiction"], json!(null));
}

/// A cell's regions are **derived** from the member rows its nodes publish
/// (R734-F5), not declared a second time on the cell. This is the end of that
/// path: the node registers its own row, and the cell view reports the region
/// out of replicated state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cell_reports_the_regions_its_members_declare() {
    let us = solo_node_in_cell(1, policy(), "prod-us", "us", "us-west")
        .await
        .expect("US cell node");
    found(&us).await;

    // The registration loop writes the row once this node is in membership and a
    // leader exists; both are true after `found`, but not instantaneously.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let regions = status(&us).await["cell"]["regions"].clone();
        if regions == json!(["us-west"]) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the cell never reported its member's region; last saw {regions}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
