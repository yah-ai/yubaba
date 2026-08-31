//! Live-cluster proof of the stable leader pin — R734-T4, W247 §3.
//!
//! Three voters, one per region, founded as a real fleet cluster through
//! `POST /raft/initialize` (so the R734-F2 quorum-geography gate is satisfied
//! the way an operator satisfies it) and registering their own member rows
//! through R734-F5's `member_registration` loop. The pin then runs on all three,
//! exactly as it will on the fleet.
//!
//! Three properties, and the first two pull in opposite directions — which is
//! the point:
//!
//! 1. **The pin acts.** A leader outside the anchor region hands off to the
//!    anchor voter, and leadership *stays* there rather than oscillating.
//! 2. **The pin is soft.** With no voter in the anchor region at all — the shape
//!    a dark anchor region takes — leadership is left exactly where the election
//!    put it. A pin that could strand a cluster whose preferred region died
//!    would be worse than no pin, so this is the more important of the two.
//! 3. **The pin needs positive evidence about both ends.** A leader that has not
//!    published its own member row does nothing, rather than assuming it is
//!    off-anchor. Every node is row-less for a moment after boot, so the
//!    opposite rule manufactures churn on exactly the shape a rolling upgrade
//!    produces.

use std::time::Duration;

use serde_json::json;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::leader_pin::{self, PinConfig};
use yubaba::raft::YubabaNodeId;
use yubaba_test_harness::{solo_node_in_region, solo_node_unregistered, SoloNode};

/// The region leadership is pinned to in the acting test.
const ANCHOR: &str = "us-west";

/// A pin paced for a test rather than for a WAN. `PinConfig::new` derives
/// seconds-to-minutes from the fleet timings, which is right on the fleet and
/// far too slow here; the *behaviour* under test is identical, only the clock
/// differs.
fn test_pin(anchor: &str) -> PinConfig {
    PinConfig {
        anchor: anchor.to_string(),
        evaluate_every: Duration::from_millis(250),
        cooldown: Duration::from_secs(5),
        failure_backoff: Duration::from_secs(10),
        max_lag_entries: 10,
    }
}

/// The pin loops for one cluster, aborted together when the test ends.
///
/// `SoloNode` owns the node's own tasks; these are the test's, so they are held
/// separately rather than pushed into the harness — the harness has no business
/// knowing that some tests also run an actuator.
struct Pins(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Pins {
    fn drop(&mut self) {
        for pin in &self.0 {
            pin.abort();
        }
    }
}

fn start_pins(nodes: &[SoloNode], anchor: &str) -> Pins {
    Pins(
        nodes
            .iter()
            .map(|node| {
                leader_pin::spawn(
                    node.node_id,
                    node.raft.clone(),
                    node.state_machine.clone(),
                    test_pin(anchor),
                )
            })
            .collect(),
    )
}

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
    reqwest::get(format!("{base_url}/raft/status"))
        .await
        .expect("GET /raft/status")
        .json()
        .await
        .expect("/raft/status body")
}

/// Found a 3-voter fleet cluster, one voter per region, and wait until all three
/// agree on a leader.
///
/// Region tags are supplied on `initialize` because the fleet policy's
/// `MustSpanRegions` rule refuses an untagged multi-voter founding set — this is
/// the R734-F2 gate, satisfied rather than bypassed. Note that the tags on the
/// founding payload are independent of whether a node ever *publishes* a member
/// row, which is what lets `register: [false, …]` produce a legitimate founding
/// voter the member map has never heard of.
async fn three_region_cluster(regions: [&str; 3]) -> Vec<SoloNode> {
    three_region_cluster_registering(regions, [true; 3]).await
}

async fn three_region_cluster_registering(
    regions: [&str; 3],
    register: [bool; 3],
) -> Vec<SoloNode> {
    let policy = ClusterPolicy::fleet();
    let mut nodes = Vec::new();
    for (i, region) in regions.iter().enumerate() {
        let id = i as u64 + 1;
        let node = if register[i] {
            solo_node_in_region(id, policy, Some(region)).await
        } else {
            solo_node_unregistered(id, policy, Some(region)).await
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
    assert_eq!(status, 200, "founding a 1-1-1 fleet cluster: {body}");

    agreed_leader(&nodes, Duration::from_secs(30)).await;
    nodes
}

/// Wait until every node names the same live leader, and return its node id.
///
/// Deliberately not "wait until node 1 leads": issuing `initialize` does not win
/// node 1 the election, and demanding it would encode a race as a requirement.
async fn agreed_leader(nodes: &[SoloNode], timeout: Duration) -> YubabaNodeId {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let mut beliefs = Vec::with_capacity(nodes.len());
        for node in nodes {
            beliefs.push(raft_status(&node.base_url).await["current_leader"].as_u64());
        }
        if let Some(Some(leader)) = beliefs.first().copied() {
            if beliefs.iter().all(|b| *b == Some(leader)) {
                return leader;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "voters never agreed on a leader; per-node current_leader was {beliefs:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Block until every node has a member row for every node in `want`, so the pin
/// is deciding on a converged map rather than on a half-registered one.
///
/// Takes a subset rather than the whole cluster because a deliberately
/// unregistered node never converges, and waiting for it would simply time out.
async fn await_registered(nodes: &[SoloNode], want: &[YubabaNodeId], timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let converged = nodes.iter().all(|node| {
            let members = node.state_machine.members();
            nodes
                .iter()
                .filter(|peer| want.contains(&peer.node_id))
                .all(|peer| {
                    members.get(&peer.node_id).and_then(|m| m.region.clone()) == peer.region
                })
        });
        if converged {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "member rows never converged; node 1 sees {:?}",
            nodes[0].state_machine.members()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn await_all_registered(nodes: &[SoloNode], timeout: Duration) {
    let all: Vec<YubabaNodeId> = nodes.iter().map(|n| n.node_id).collect();
    await_registered(nodes, &all, timeout).await;
}

/// The voter set as one uniform config, or `None` while a joint consensus is in
/// flight. A pin that quietly left the cluster in joint consensus would answer
/// `/raft/status` plausibly and need a quorum of *both* sets for every write.
async fn uniform_voters(base_url: &str) -> Option<Vec<u64>> {
    let status = raft_status(base_url).await;
    let configs = status["membership_config"]["membership"]["configs"]
        .as_array()
        .expect("membership.configs array")
        .clone();
    if configs.len() != 1 {
        return None;
    }
    let mut ids: Vec<u64> = configs[0]
        .as_array()
        .expect("config entry array")
        .iter()
        .map(|v| v.as_u64().expect("voter id"))
        .collect();
    ids.sort_unstable();
    Some(ids)
}

async fn wait_for_leader(nodes: &[SoloNode], want: YubabaNodeId, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut seen;
    loop {
        seen = raft_status(&nodes[0].base_url).await["current_leader"].as_u64();
        if seen == Some(want) && agreed_leader(nodes, Duration::from_secs(10)).await == want {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("leadership never settled on node {want}; last seen {seen:?}");
}

/// Move leadership onto `to` through the operator route, so a test's starting
/// state is chosen rather than won.
async fn force_leader(nodes: &[SoloNode], to: YubabaNodeId) {
    let leader = agreed_leader(nodes, Duration::from_secs(10)).await;
    if leader == to {
        return;
    }
    let from = nodes.iter().find(|n| n.node_id == leader).expect("leader");
    let (status, body) =
        post_json(&from.base_url, "/raft/transfer-leader", json!({ "to": to })).await;
    assert_eq!(status, 202, "moving leadership to node {to}: {body}");
    wait_for_leader(nodes, to, Duration::from_secs(30)).await;
}

/// The acting half: an off-anchor leader hands leadership to the anchor voter,
/// and it stays there.
///
/// Node 2 is the anchor, so leadership is first moved onto node 1 — through the
/// operator route that already exists — and only then are the pins started. That
/// makes the starting state deterministic rather than election-dependent, which
/// is the whole reason leader-side transfer was chosen over election-timeout
/// skew.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn an_off_anchor_leader_hands_leadership_to_the_anchor_region() {
    let nodes = three_region_cluster(["us-east", ANCHOR, "us-south"]).await;
    await_all_registered(&nodes, Duration::from_secs(30)).await;
    let anchor_id = nodes[1].node_id;

    force_leader(&nodes, nodes[0].node_id).await;
    assert_ne!(
        agreed_leader(&nodes, Duration::from_secs(10)).await,
        anchor_id,
        "the test must start with leadership outside the anchor region"
    );

    let _pins = start_pins(&nodes, ANCHOR);
    wait_for_leader(&nodes, anchor_id, Duration::from_secs(60)).await;

    // Membership must be untouched: `transfer_leader` moves leadership without a
    // membership change, so a joint config here would mean the pin reached for
    // the wrong primitive.
    assert_eq!(
        uniform_voters(&nodes[1].base_url).await,
        Some(vec![1, 2, 3]),
        "the pin must not change membership"
    );

    // And it must STOP. A pin that keeps acting once anchored is the churn
    // failure this design exists to avoid, and it would show up as leadership
    // moving again with every pin still running.
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            raft_status(&nodes[1].base_url).await["current_leader"].as_u64(),
            Some(anchor_id),
            "leadership moved back off the anchor — the pin is oscillating"
        );
    }
}

/// The soft half, and the property that makes this safe to run on the fleet:
/// when no voter is in the anchor region, leadership is left alone.
///
/// This is the shape of the disaster case. "The anchor region is dark" and "no
/// voter is tagged with the anchor" are the same input to the pin — there is no
/// eligible candidate — so a cluster that has lost its preferred region keeps
/// serving from whichever survivor won the election, and the pin never fights
/// it. Asserting the *non*-event needs the pin to have had many chances to act:
/// `evaluate_every` is 250 ms and this watches for five seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_cluster_with_no_voter_in_the_anchor_region_is_left_alone() {
    let nodes = three_region_cluster(["us-east", "us-south", "eu-central"]).await;
    await_all_registered(&nodes, Duration::from_secs(30)).await;
    let before = agreed_leader(&nodes, Duration::from_secs(10)).await;

    let _pins = start_pins(&nodes, "ap-southeast");

    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            raft_status(&nodes[0].base_url).await["current_leader"].as_u64(),
            Some(before),
            "the pin moved leadership with no voter in the anchor region"
        );
    }
    assert_eq!(
        uniform_voters(&nodes[0].base_url).await,
        Some(vec![1, 2, 3]),
        "membership must be untouched"
    );
}

/// A leader that has not published its own member row does nothing, even with a
/// caught-up anchor voter available.
///
/// Regression test for a bug this suite did not originally catch: `decide` used
/// to hand leadership away on the strength of the *target's* row alone, so a
/// leader whose own row had not landed yet would move leadership — possibly to a
/// peer in the very same region — for no gain. Every node is row-less for a
/// moment after boot while R734-F5's registration loop converges, which makes it
/// the shape a rolling upgrade produces on every node in turn. Caught by
/// @Ashguard:libra while building R734-F5; the old rule fails this test in under
/// three seconds.
///
/// Node 1 never registers and is then handed leadership, so the interesting
/// state — row-less leader, tagged anchor peer, both caught up — is reached
/// deterministically rather than by winning a race.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_leader_that_has_not_published_its_region_does_not_hand_off() {
    let nodes =
        three_region_cluster_registering(["us-east", ANCHOR, "us-south"], [false, true, true])
            .await;
    let unregistered = nodes[0].node_id;
    let anchor_id = nodes[1].node_id;
    await_registered(
        &nodes,
        &[anchor_id, nodes[2].node_id],
        Duration::from_secs(30),
    )
    .await;

    force_leader(&nodes, unregistered).await;

    // Preconditions, so a green run cannot be a vacuous one: the leader really
    // has no row, and the anchor voter really does.
    let members = nodes[1].state_machine.members();
    assert!(
        !members.contains_key(&unregistered),
        "the leader must have no member row for this test to mean anything: {members:?}"
    );
    assert_eq!(
        members.get(&anchor_id).and_then(|m| m.region.as_deref()),
        Some(ANCHOR),
        "the anchor voter must be registered, or there is nothing to be tempted by"
    );

    let _pins = start_pins(&nodes, ANCHOR);

    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            raft_status(&nodes[1].base_url).await["current_leader"].as_u64(),
            Some(unregistered),
            "the pin handed leadership away on the target's row alone, without \
             knowing where the leader itself was"
        );
    }
}

/// The mirror of the case above, on the *candidate* side: an anchor-region voter
/// that has not published a row is not a handoff target, and its silence does
/// not become a reason to move leadership somewhere else.
///
/// Node 2 is physically in the anchor region but never registers, so the only
/// rows the leader can see are its own (`us-east`) and node 3's (`us-south`).
/// The pin must find no candidate and do nothing. This documents behaviour that
/// was already correct rather than fixing a second bug — a row-less peer has
/// always failed the `in_anchor` test — but it is worth pinning, because the
/// obvious "optimisation" of falling back to the founding payload's region tags
/// would break it, and the tags on `initialize` are still sitting right there in
/// membership to tempt someone.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn an_unregistered_anchor_voter_is_not_a_handoff_target() {
    let nodes =
        three_region_cluster_registering(["us-east", ANCHOR, "us-south"], [true, false, true])
            .await;
    await_registered(
        &nodes,
        &[nodes[0].node_id, nodes[2].node_id],
        Duration::from_secs(30),
    )
    .await;

    force_leader(&nodes, nodes[0].node_id).await;
    let before = agreed_leader(&nodes, Duration::from_secs(10)).await;
    assert!(
        !nodes[0]
            .state_machine
            .members()
            .contains_key(&nodes[1].node_id),
        "the anchor voter must be unregistered for this test to mean anything"
    );

    let _pins = start_pins(&nodes, ANCHOR);

    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            raft_status(&nodes[0].base_url).await["current_leader"].as_u64(),
            Some(before),
            "the pin acted on a region it could not read from replicated state"
        );
    }
}
