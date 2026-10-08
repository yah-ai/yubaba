//! R742-F1 (W305 §F1) — the sovereign-group gate on `POST /raft/add-learner`.
//!
//! Part of R742-F1 — the canonical `@yah:ticket` annotation lives in
//! `.yah/docs/working/W305-sovereign-groups-environments-edges.md`. The rule is
//! implemented in `src/sovereign_group.rs` and wired in `src/lib.rs`.
//! Credential-free and containerd-free.
//!
//! A sovereign group is a blast radius: its own quorum, its own upgrade
//! cadence, destroyable and rebuildable on its own. Until this ticket the only
//! thing keeping a dev Pi out of the prod quorum was a comment in three machine
//! TOMLs saying "never run a raft join against this box from a shell pointed at
//! prod" — and the shell pointed at prod is exactly where this request arrives
//! from.
//!
//! What these tests cover that the unit tests in `src/sovereign_group.rs`
//! cannot:
//!
//! - that the rule is actually **wired** to the route;
//! - that the joiner's group is read **off the joiner**, not off the request —
//!   the one property that makes the gate worth anything, since a caller that
//!   can state its own group can state the wrong one;
//! - that a refusal happens **before** `raft.add_learner`, so a refused join
//!   leaves membership untouched rather than rejecting a node it already added;
//! - that an **unstamped** cluster still grows, and says out loud that it judged
//!   nothing — the pond/rig/BYO case, which must not have been broken by this.
//!
//! R605-F35 added the second half of the join: every permitted join is a
//! **learner** join, and the leader then promotes the joiner only if its own
//! `--sovereign-voters` list names it. These tests pin that a listed joiner is
//! promoted, an unlisted one stays a learner, the leader's list beats anything
//! the joiner believes about itself, and a group with no list promotes nobody.
//!
//! ```bash
//! cargo test -p yubaba --test main -- raft_sovereign_group::
//! ```

use std::time::Duration;

use serde_json::json;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::Participation;
use yubaba_test_harness::{
    solo_node_in_sovereign_group, solo_node_listing_voters, solo_node_with_sovereign_participation,
    SoloNode,
};

/// Every node here is founded as a cluster-of-one, so `rig` is the honest
/// policy: `fleet`'s quorum-geography gate (R734-F2) refuses an untagged
/// founding set, and regions are not what these tests are about. The gate under
/// test reads only the declared group and never the cluster profile.
fn policy() -> ClusterPolicy {
    ClusterPolicy::rig()
}

async fn status(node: &SoloNode) -> serde_json::Value {
    yubaba_test_harness::http()
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
    let resp = yubaba_test_harness::http()
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

/// `POST /raft/add-learner`, with `extra` merged into the request body so a test
/// can try to *tell* the leader something it must refuse to believe.
async fn add_learner(
    leader: &SoloNode,
    joiner_id: u64,
    joiner_addr: &str,
    extra: serde_json::Value,
) -> (reqwest::StatusCode, String) {
    let mut body = json!({ "node_id": joiner_id, "addr": joiner_addr });
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        body[k] = v;
    }
    let resp = yubaba_test_harness::http()
        .post(format!("{}/raft/add-learner", leader.base_url))
        .json(&body)
        .send()
        .await
        .expect("POST /raft/add-learner");
    let code = resp.status();
    (code, resp.text().await.unwrap_or_default())
}

/// Node ids the leader's membership knows about — voters *and* learners.
async fn membership_ids(node: &SoloNode) -> Vec<u64> {
    status(node).await["membership_config"]["membership"]["nodes"]
        .as_object()
        .expect("membership.nodes object")
        .keys()
        .map(|k| k.parse::<u64>().expect("node id key"))
        .collect()
}

/// The case the whole ticket exists for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cross_group_join_is_refused_without_touching_membership() {
    let leader = solo_node_in_sovereign_group(1, policy(), Some("prod"))
        .await
        .expect("prod leader");
    let joiner = solo_node_in_sovereign_group(2, policy(), Some("dev"))
        .await
        .expect("dev joiner");
    found(&leader).await;

    let (code, body) = add_learner(&leader, joiner.node_id, &joiner.addr, json!({})).await;
    assert_eq!(
        code,
        reqwest::StatusCode::CONFLICT,
        "a dev node joining prod must be refused 409: {body}"
    );
    // A refusal that does not name what it saw is one the operator has to go
    // and reconstruct, so it gets worked around instead of fixed.
    assert!(
        body.contains("dev") && body.contains("prod"),
        "the refusal must name both declared groups: {body}"
    );

    // The gate runs *before* `raft.add_learner`. A gate that refused afterwards
    // would return this same 409 having already grown the cluster it rejected.
    assert_eq!(
        membership_ids(&leader).await,
        vec![leader.node_id],
        "a refused join must leave membership exactly as it was"
    );
}

/// R605-F35 (formerly R605-F12's non-voter refusal), end to end: same group,
/// still refused, and the refusal has to be about *participation* rather than
/// the group.
///
/// This is us-west-003. It is a member of prod — same secrets, same upgrade
/// cadence, same destruction — on a residential uplink that must never hold a
/// prod raft node id, not even as a learner. Under R605-F12 this test refused a
/// `non-voter`; R605-F35 moved who-votes onto the group, so what remains on the
/// node is `out`, and it still keeps the box out of the raft entirely.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_out_member_of_the_same_group_is_refused() {
    let leader = solo_node_in_sovereign_group(1, policy(), Some("prod"))
        .await
        .expect("prod leader");
    let joiner =
        solo_node_with_sovereign_participation(2, policy(), Some("prod"), Participation::Out)
            .await
            .expect("out-of-raft prod member");
    found(&leader).await;

    let (code, body) = add_learner(&leader, joiner.node_id, &joiner.addr, json!({})).await;
    assert_eq!(
        code,
        reqwest::StatusCode::CONFLICT,
        "an `out` prod member joining the prod raft must be refused 409: {body}"
    );
    assert!(
        body.contains("OUT of"),
        "the refusal must name participation, which is the only thing that differs: {body}"
    );
    assert!(
        !body.contains("cross-group"),
        "both sides declare prod — blaming the group would read as a bug in the check: {body}"
    );
    assert_eq!(
        membership_ids(&leader).await,
        vec![leader.node_id],
        "a refused join must leave membership exactly as it was"
    );
}

/// Participation is read off the joiner over the wire, exactly as the group is
/// — so `/raft/status` has to publish it, and the leader has to believe that
/// rather than the request body.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_publishes_its_participation_and_the_leader_reads_it_there() {
    let member = solo_node_in_sovereign_group(1, policy(), Some("prod"))
        .await
        .expect("prod member");
    let outsider =
        solo_node_with_sovereign_participation(2, policy(), Some("prod"), Participation::Out)
            .await
            .expect("out-of-raft prod member");

    assert_eq!(status(&member).await["sovereign_participation"], json!("in"));
    assert_eq!(status(&outsider).await["sovereign_participation"], json!("out"));
    // R605-F12's key is gone from the wire, not kept beside the new one.
    assert!(status(&member).await.get("sovereign_role").is_none());

    found(&member).await;
    // Claiming `in` in the body changes nothing: the leader dials the joiner.
    let (code, body) = add_learner(
        &member,
        outsider.node_id,
        &outsider.addr,
        json!({ "sovereign_participation": "in" }),
    )
    .await;
    assert_eq!(
        code,
        reqwest::StatusCode::CONFLICT,
        "the request body must not be able to bring an `out` node into the raft: {body}"
    );
}

/// The other end of the assertion: a node that declares itself out of its
/// group's raft and nonetheless holds a raft seat refuses to grow the raft from
/// it, because it is already in the state its own declaration says is
/// impossible.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_out_leader_refuses_to_grow_its_raft() {
    let leader =
        solo_node_with_sovereign_participation(1, policy(), Some("prod"), Participation::Out)
            .await
            .expect("out-of-raft leader");
    let joiner = solo_node_in_sovereign_group(2, policy(), Some("prod"))
        .await
        .expect("prod member");
    found(&leader).await;

    let (code, body) = add_learner(&leader, joiner.node_id, &joiner.addr, json!({})).await;
    assert_eq!(
        code,
        reqwest::StatusCode::CONFLICT,
        "an `out` cluster must not add members: {body}"
    );
    assert!(body.contains("--raft-node-id"), "{body}");
    assert_eq!(membership_ids(&leader).await, vec![leader.node_id]);
}

/// Voter ids in the leader's current membership config.
async fn voter_ids(node: &SoloNode) -> Vec<u64> {
    let s = status(node).await;
    let mut ids: Vec<u64> = s["membership_config"]["membership"]["configs"]
        .as_array()
        .expect("membership.configs array")
        .iter()
        .flat_map(|c| c.as_array().expect("voter set array").iter())
        .map(|v| v.as_u64().expect("voter id u64"))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// The JSON body of a 200 `add-learner`, asserting the 200 on the way.
async fn joined(leader: &SoloNode, joiner: &SoloNode) -> serde_json::Value {
    let (code, body) = add_learner(leader, joiner.node_id, &joiner.addr, json!({})).await;
    assert_eq!(code, reqwest::StatusCode::OK, "same-group join: {body}");
    serde_json::from_str(&body).expect("add-learner json")
}

/// R605-F35, the case the ticket names: two participants of one group join the
/// same leader. The one the group lists is promoted; the one it does not stays
/// a learner — and stays one when an operator asks for it by hand.
///
/// This is the dev rig's shape in miniature: three listed Pi voters plus VM
/// members nobody listed. `rig` permits promotion up to five voters, so the
/// only thing keeping the unlisted member a learner here is the list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listed_participant_is_promoted_and_an_unlisted_one_stays_a_learner() {
    let leader = solo_node_listing_voters(1, policy(), "dev", &[1, 2])
        .await
        .expect("dev leader listing 1,2");
    let listed = solo_node_in_sovereign_group(2, policy(), Some("dev"))
        .await
        .expect("listed dev member");
    let unlisted = solo_node_in_sovereign_group(3, policy(), Some("dev"))
        .await
        .expect("unlisted dev member");
    found(&leader).await;

    let body = joined(&leader, &listed).await;
    assert_eq!(body["voter_listed"], json!(true), "{body}");
    assert_eq!(body["promoted"], json!(true), "a listed joiner is promoted: {body}");

    let body = joined(&leader, &unlisted).await;
    assert_eq!(body["voter_listed"], json!(false), "{body}");
    assert_eq!(
        body["promoted"],
        json!(false),
        "an unlisted joiner stays a learner: {body}"
    );

    assert_eq!(voter_ids(&leader).await, vec![1, 2]);
    let mut members = membership_ids(&leader).await;
    members.sort_unstable();
    assert_eq!(members, vec![1, 2, 3], "3 is in membership — as a learner");

    // The operator verb is gated by the same list: asking by hand does not get
    // an unlisted learner a seat.
    let resp = yubaba_test_harness::http()
        .post(format!("{}/raft/promote-voter", leader.base_url))
        .json(&json!({ "node_id": 3 }))
        .send()
        .await
        .expect("POST /raft/promote-voter");
    let code = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert_eq!(code, reqwest::StatusCode::FORBIDDEN, "{text}");
    assert!(
        text.contains("not a listed voter") && text.contains("dev"),
        "the refusal must name the list and the group: {text}"
    );
    assert_eq!(voter_ids(&leader).await, vec![1, 2]);
}

/// The disagreement case, pinned both ways: only the LEADER's list is read.
///
/// The joiner is never asked whether it should vote — "asked, never believed"
/// covers the joiner's group and participation, and a seat is not something the
/// joiner gets to declare at all. So a joiner whose own daemon lists itself is
/// still a learner under a leader that does not list it, and a joiner whose own
/// list omits itself is still promoted under a leader that does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_leaders_voter_list_decides_and_the_joiners_own_list_does_not() {
    let leader = solo_node_listing_voters(1, policy(), "dev", &[1, 2])
        .await
        .expect("dev leader listing 1,2");
    // Believes it is NOT a voter — the leader says it is.
    let modest = solo_node_listing_voters(2, policy(), "dev", &[1])
        .await
        .expect("joiner listing only 1");
    // Believes it IS a voter — the leader says it is not.
    let presumptuous = solo_node_listing_voters(3, policy(), "dev", &[1, 2, 3])
        .await
        .expect("joiner listing itself");
    found(&leader).await;

    assert_eq!(status(&presumptuous).await["sovereign_voters"], json!([1, 2, 3]));

    let body = joined(&leader, &modest).await;
    assert_eq!(body["promoted"], json!(true), "the leader lists 2: {body}");
    let body = joined(&leader, &presumptuous).await;
    assert_eq!(
        body["promoted"],
        json!(false),
        "the leader does not list 3, whatever 3's own flag says: {body}"
    );
    assert_eq!(voter_ids(&leader).await, vec![1, 2]);
}

/// A daemon that declares a group but was given no voter list promotes nobody
/// — the fail-closed direction. A participant still joins (as a learner), but
/// no path hands it a seat until `--sovereign-voters` names it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_group_with_no_voter_list_promotes_nobody() {
    let leader = solo_node_in_sovereign_group(1, policy(), Some("dev"))
        .await
        .expect("dev leader with no list");
    let joiner = solo_node_in_sovereign_group(2, policy(), Some("dev"))
        .await
        .expect("dev member");
    found(&leader).await;

    let body = joined(&leader, &joiner).await;
    assert_eq!(body["promoted"], json!(false), "{body}");

    let resp = yubaba_test_harness::http()
        .post(format!("{}/raft/promote-voter", leader.base_url))
        .json(&json!({ "node_id": 2 }))
        .send()
        .await
        .expect("POST /raft/promote-voter");
    let code = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert_eq!(code, reqwest::StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("--sovereign-voters"), "{text}");
    assert_eq!(voter_ids(&leader).await, vec![1]);
}

/// The teeth. The scenario the gate exists for is a command typed against the
/// wrong cluster, so a request that *asserts* the joiner is in prod must not be
/// able to talk its way in — the leader asks the joiner instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_joiners_group_is_read_off_the_joiner_not_the_request() {
    let leader = solo_node_in_sovereign_group(1, policy(), Some("prod"))
        .await
        .expect("prod leader");
    let joiner = solo_node_in_sovereign_group(2, policy(), Some("dev"))
        .await
        .expect("dev joiner");
    found(&leader).await;

    let (code, body) = add_learner(
        &leader,
        joiner.node_id,
        &joiner.addr,
        json!({ "sovereign_group": "prod" }),
    )
    .await;
    assert_eq!(
        code,
        reqwest::StatusCode::CONFLICT,
        "the request body must not be able to declare the joiner's group: {body}"
    );
    assert!(
        body.contains("\"dev\""),
        "the refusal must quote what the JOINER said, not what the caller claimed: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_within_one_group_is_permitted_and_says_which() {
    let leader = solo_node_in_sovereign_group(1, policy(), Some("prod"))
        .await
        .expect("prod leader");
    let joiner = solo_node_in_sovereign_group(2, policy(), Some("prod"))
        .await
        .expect("prod joiner");
    found(&leader).await;

    let (code, body) = add_learner(&leader, joiner.node_id, &joiner.addr, json!({})).await;
    assert_eq!(code, reqwest::StatusCode::OK, "same-group join: {body}");
    let body: serde_json::Value = serde_json::from_str(&body).expect("add-learner json");
    assert_eq!(body["sovereign_group_judged"], json!(true));
    assert_eq!(body["sovereign_group"], json!("prod"));
}

/// `None` on a daemon is *unknown*, not standalone: nothing here can tell
/// whether that box already belongs to another blast radius, and "I could not
/// establish which" is not a reason to grow this one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_undeclared_joiner_cannot_grow_a_declared_group() {
    let leader = solo_node_in_sovereign_group(1, policy(), Some("prod"))
        .await
        .expect("prod leader");
    let joiner = solo_node_in_sovereign_group(2, policy(), None)
        .await
        .expect("unstamped joiner");
    found(&leader).await;

    let (code, body) = add_learner(&leader, joiner.node_id, &joiner.addr, json!({})).await;
    assert_eq!(code, reqwest::StatusCode::CONFLICT, "{body}");
    assert!(
        body.contains("--sovereign-group"),
        "the refusal must name the flag that fixes it, not just the TOML: {body}"
    );
    // Both refusals name the flag, so asserting only on that would let this
    // pass off the old-build branch — which is what happened before
    // `present_but_maybe_null`: a present `null` collapsed into "no such key".
    assert!(
        body.contains("declares no sovereign group") && !body.contains("Roll that node"),
        "an unflagged current build must not be told its binary is too old: {body}"
    );
}

/// Distinct from the 409s on purpose: "the box did not answer" is retryable and
/// "the box answered with the wrong group" is not, and an operator who cannot
/// tell them apart retries the one that will never succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_that_cannot_be_asked_is_refused_502() {
    let leader = solo_node_in_sovereign_group(1, policy(), Some("prod"))
        .await
        .expect("prod leader");
    found(&leader).await;

    // Port 1 — privileged, unbound, connection refused immediately.
    let (code, body) = add_learner(&leader, 99, "127.0.0.1:1", json!({})).await;
    assert_eq!(code, reqwest::StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(
        membership_ids(&leader).await,
        vec![leader.node_id],
        "a node that could not be asked must not have been added"
    );
}

/// The regression this change most easily causes. A pond cluster, a rig and a
/// BYO single-node bootstrap all declare no group; if the gate refused them,
/// every unstamped deployment would lose the ability to grow. It must permit —
/// and must say `sovereign_group_judged: false`, because a join nothing
/// evaluated reading as one that passed is precisely the class of silence W305
/// finding 3 is about.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unstamped_cluster_still_grows_and_admits_it_judged_nothing() {
    let leader = solo_node_in_sovereign_group(1, policy(), None)
        .await
        .expect("unstamped leader");
    // Deliberately a *stamped* joiner: even a node that declares a group is
    // waved through, because the gate is a property of what the cluster being
    // joined asserts, not of what the joiner offers.
    let joiner = solo_node_in_sovereign_group(2, policy(), Some("dev"))
        .await
        .expect("dev joiner");
    found(&leader).await;

    let (code, body) = add_learner(&leader, joiner.node_id, &joiner.addr, json!({})).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{body}");
    let body: serde_json::Value = serde_json::from_str(&body).expect("add-learner json");
    assert_eq!(body["sovereign_group_judged"], json!(false));
    assert_eq!(body["sovereign_group"], json!(null));
}

/// The rolling-upgrade case, over real HTTP rather than through the pure rule.
///
/// A yubaba that predates R742-F1 answers `/raft/status` with no
/// `sovereign_group` key at all — which is a different fact from a current
/// build that answers `null`, and gets a different instruction (roll it, then
/// set the flag; telling an old binary to take a flag it does not have sends
/// the operator round a loop that cannot close). The distinction rests on a
/// serde subtlety, so it is worth proving off a real socket and not only in a
/// unit test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_whose_build_predates_the_field_is_told_to_roll_first() {
    let leader = solo_node_in_sovereign_group(1, policy(), Some("prod"))
        .await
        .expect("prod leader");
    found(&leader).await;

    // A stand-in for a pre-R742-F1 daemon: serves the `/raft/status` shape that
    // build served, i.e. everything except the key this gate reads.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind old-build stub");
    let stub_addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let stub = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut sock, _)) = listener.accept().await {
            let _ = sock.read(&mut [0u8; 2048]).await;
            let body = r#"{"node_id":9,"state":"Learner","current_leader":null}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });

    let (code, body) = add_learner(&leader, 9, &stub_addr, json!({})).await;
    stub.abort();

    assert_eq!(
        code,
        reqwest::StatusCode::CONFLICT,
        "a joiner that cannot report a group must not grow a declared quorum: {body}"
    );
    assert!(
        body.contains("Roll that node"),
        "an old build must be told to roll, not to set a flag it does not have: {body}"
    );
    assert_eq!(
        membership_ids(&leader).await,
        vec![leader.node_id],
        "membership must be untouched"
    );
}

/// The read surface the gate depends on. A leader distinguishes "started
/// without the flag" (`null`) from "build predates the field" (key absent), and
/// gives those two different instructions — so the key must be emitted even
/// when unset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raft_status_reports_this_nodes_own_group_including_when_unset() {
    let stamped = solo_node_in_sovereign_group(1, policy(), Some("dev"))
        .await
        .expect("stamped node");
    let bare = solo_node_in_sovereign_group(2, policy(), None)
        .await
        .expect("unstamped node");

    assert_eq!(status(&stamped).await["sovereign_group"], json!("dev"));
    let bare_status = status(&bare).await;
    assert!(
        bare_status.get("sovereign_group").is_some(),
        "the key must be present even when unset — its absence is how a leader \
         recognises a pre-R742-F1 build: {bare_status}"
    );
    assert_eq!(bare_status["sovereign_group"], json!(null));
}
