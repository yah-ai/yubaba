//! R734-T1 — Pre-Vote, end to end over the real HTTP transport.
//!
//! Part of R734-T1 — the canonical `@yah:ticket` annotation lives in
//! `src/cluster_policy.rs`. Credential-free and containerd-free: it drives real
//! yubaba nodes over loopback HTTP.
//!
//! Pre-Vote is the fix for a specific disruption: a voter that has been
//! partitioned, or has just restarted, or is log-behind, times out, increments
//! the cluster's term, and campaigns — an election it cannot win but which
//! costs the healthy leader its term anyway. With Pre-Vote it must first ask a
//! quorum whether they *would* elect it, and that asking persists nothing.
//!
//! Three properties, each of which fails differently if it is missing:
//!
//! - **`/raft/pre-vote` is a probe, `/raft/vote` is a commitment.** The same
//!   request to the same node changes its term on one route and not the other.
//!   This is the whole feature; without it the route is just a second vote
//!   endpoint.
//! - **A healthy leader's followers refuse a Pre-Vote outright.** This is the
//!   disruption actually being prevented, asserted against a live cluster.
//! - **Elections still work.** Pre-Vote adds a quorum gate *in front of* every
//!   election, so a wrong answer anywhere in the transport — a route that
//!   404s, a peer counted as refusing when it is merely slow — strands the
//!   cluster leaderless rather than failing loudly. Killing the leader and
//!   waiting for a new one is the only assertion that catches that class.
//!
//! The complementary transport-level cases (a pre-R734 peer's 404 counts as a
//! grant; an unreachable peer does not) are unit tests in
//! `src/raft/network.rs`, where a fake HTTP peer can be posed exactly.
//!
//! # Pre-Vote is currently switched OFF (R734-T3), and this suite still passes
//!
//! `RaftTiming::to_openraft_config` sets `enable_pre_vote: Some(false)`,
//! because enabling it against `openraft = 0.10.0-alpha.30` can strand a node
//! as leader-per-peers and not-leader-per-itself, permanently. The full
//! measurement is in that function's doc comment.
//!
//! Every test here still holds and still means something, because they exercise
//! the *server and transport* halves — `POST /raft/pre-vote` answers correctly
//! and persists nothing, `YubabaNetwork::pre_vote` maps its outcomes correctly —
//! and those are the halves the flag does not touch. What they no longer prove
//! is that openraft is *calling* any of it; the `a_dead_leader_is_still_replaced`
//! test now demonstrates that ordinary elections work, which is a weaker claim
//! than the one it made when the flag was on. Read the falsification note on
//! that test for what changed.
//!
//! ```bash
//! cargo test -p yubaba --test main -- raft_pre_vote::
//! ```

use std::time::Duration;

use cloud::provider::HetznerDriver;
use openraft::raft::{VoteRequest, VoteResponse};
use openraft::type_config::alias::VoteOf;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::raft::YubabaRaftConfig as TC;
use yubaba::runtime::DummyRuntime;
use yubaba_test_harness::{solo_node, test_cluster};

/// node index (0-based) → raft node id (1-based, per the harness convention).
fn node_id(idx: usize) -> u64 {
    (idx as u64) + 1
}

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

/// The node's `current_term` from `/raft/status`.
async fn current_term(base_url: &str) -> u64 {
    raft_status(base_url).await["current_term"]
        .as_u64()
        .expect("current_term is a number")
}

/// POST a `VoteRequest` to `path` (`/raft/vote` or `/raft/pre-vote`) and decode
/// the `Result<VoteResponse, RaftError>` body the raft RPC handlers serialize.
async fn post_vote(base_url: &str, path: &str, req: &VoteRequest<TC>) -> VoteResponse<TC> {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}{path}"))
        .json(req)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {path}: {e}"));
    assert!(
        resp.status().is_success(),
        "POST {path} must be served, got {}",
        resp.status()
    );
    resp.json::<Result<VoteResponse<TC>, openraft::error::RaftError<TC>>>()
        .await
        .unwrap_or_else(|e| panic!("decode {path} reply: {e}"))
        .unwrap_or_else(|e| panic!("{path} returned a raft error: {e}"))
}

/// The defining property, isolated: the two routes take the **same request** and
/// give the same verdict, but only one of them writes it down.
///
/// Asserting the grant alone would pass against a `/raft/pre-vote` that was
/// wired straight to `Raft::vote` — the bug most likely to be written here, and
/// the one that would silently reintroduce the term inflation Pre-Vote exists to
/// remove. The term reading before and after is what rules it out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pre_vote_probes_without_persisting_while_a_real_vote_commits() {
    const NODE: u64 = 9;
    const CANDIDATE: u64 = 7;
    const CANDIDATE_TERM: u64 = 5;

    // Uninitialised on purpose: with no committed vote there is no leader
    // lease, so a vote is actually grantable. Against a node inside a live
    // lease both routes refuse and the comparison proves nothing.
    let node = solo_node(NODE, ClusterPolicy::fleet())
        .await
        .expect("solo fleet node");
    let req = VoteRequest::<TC>::new(VoteOf::<TC>::new(CANDIDATE_TERM, CANDIDATE), None);

    let term_before = current_term(&node.base_url).await;
    assert_eq!(
        term_before, 0,
        "an uninitialised node has never voted, so it starts at term 0"
    );

    // (1) Pre-Vote: this node *would* grant — no leader lease, and the
    // candidate's empty log is not behind its own empty log.
    let probe = post_vote(&node.base_url, "/raft/pre-vote", &req).await;
    assert!(
        probe.vote_granted,
        "an unled node with an empty log must say it would grant: {probe:?}"
    );
    assert_eq!(
        current_term(&node.base_url).await,
        term_before,
        "a Pre-Vote must not move the responder's term — probing is the entire point, and a \
         probe that persists is just a vote with extra steps"
    );

    // (2) The real vote, byte-identical request: same verdict, now durable.
    let vote = post_vote(&node.base_url, "/raft/vote", &req).await;
    assert!(
        vote.vote_granted,
        "the real vote must be granted too, or the two routes disagree for some reason other \
         than persistence and this comparison means nothing: {vote:?}"
    );
    assert_eq!(
        current_term(&node.base_url).await,
        CANDIDATE_TERM,
        "a granted vote must advance the responder's term to the candidate's"
    );
}

/// The disruption itself, against a live 3-voter cluster: a voter that has been
/// away comes back and probes at a much higher term. Every follower must refuse,
/// the leader must stay put, and no term may move.
///
/// Note the refusal here is *not* about the term being high — it is the leader
/// lease. A follower that is still hearing heartbeats would not grant a real
/// vote either, so it must not grant the Pre-Vote, and reporting that honestly
/// is what stops the returning node from campaigning.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pre_vote_against_a_healthy_leader_is_refused_and_moves_nothing() {
    let provider = HetznerDriver::new("unused-on-local-tier");
    let cluster = test_cluster(&provider, DummyRuntime, 3)
        .await
        .expect("spin up 3-node local raft cluster");

    let leader = cluster
        .wait_for_agreed_leader(Duration::from_secs(30))
        .await
        .expect("leader elected");
    let followers: Vec<usize> = (0..cluster.node_count()).filter(|&i| i != leader).collect();
    assert_eq!(followers.len(), 2, "3-node cluster has two followers");

    // Impersonate the *other* follower rejoining after a partition: a real
    // voter, at a term well past anything the cluster has reached.
    let disruptor = node_id(followers[1]);
    let target_url = cluster.yubaba(followers[0]).base_url.clone();
    let term_before = current_term(&target_url).await;
    let req = VoteRequest::<TC>::new(VoteOf::<TC>::new(term_before + 5, disruptor), None);

    let probe = post_vote(&target_url, "/raft/pre-vote", &req).await;
    assert!(
        !probe.vote_granted,
        "a follower inside its leader's lease must refuse a Pre-Vote, however high the term: \
         {probe:?}"
    );
    assert_eq!(
        current_term(&target_url).await,
        term_before,
        "the refused Pre-Vote must leave the follower's term where it was"
    );
    assert_eq!(
        cluster.current_leader_idx(),
        Some(leader),
        "the sitting leader must survive a Pre-Vote at a higher term — this is the whole \
         disruption Pre-Vote exists to prevent"
    );
}

/// Liveness: with Pre-Vote gating every election, a real leader failure must
/// still produce a new leader.
///
/// This is the test that catches a broken Pre-Vote transport. A pre-candidate
/// counts only affirmative `Ok(granted)` replies toward its quorum, so a route
/// that is missing, a body that fails to decode, or an error mapped to the wrong
/// variant all read as "no grant" — and the cluster then sits leaderless
/// forever, with nothing in the logs that looks like a failure. Every assertion
/// in this file except this one would still pass in that state.
///
/// Falsified rather than assumed (2026-08-10, R734-T1): with the flag ON,
/// making `YubabaNetwork::pre_vote` return `Err(Unreachable)` unconditionally
/// left this test hung on `[Some(1), Some(1)]` — both survivors still naming
/// the node that was killed — until the 30s deadline, while the other two tests
/// in this file stayed green. That was the proof that `enable_pre_vote` was
/// genuinely live, since an election not running a Pre-Vote round could not
/// have noticed.
///
/// **That falsification no longer applies**, and saying so matters more than
/// keeping the stronger-sounding claim: R734-T3 switched the flag off, so this
/// test now shows only that ordinary elections work. Re-running the probe today
/// would leave it green, because nothing calls `pre_vote` at all. Restore the
/// flag and this paragraph together — see
/// `RaftTiming::to_openraft_config` for why it is off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_leader_is_still_replaced_with_pre_vote_gating_the_election() {
    let provider = HetznerDriver::new("unused-on-local-tier");
    let mut cluster = test_cluster(&provider, DummyRuntime, 3)
        .await
        .expect("spin up 3-node local raft cluster");

    let leader = cluster
        .wait_for_agreed_leader(Duration::from_secs(30))
        .await
        .expect("leader elected");

    cluster.kill_node(leader).await.expect("kill the leader");

    // The surviving two are a quorum of three, so one of them must win — via a
    // Pre-Vote round first, since the fleet policy enables it.
    let new_leader = cluster
        .wait_for_agreed_leader(Duration::from_secs(30))
        .await
        .expect("a Pre-Vote-gated election must still elect a new leader after the leader dies");
    assert_ne!(
        new_leader, leader,
        "the replacement leader must be a survivor, not the node that was killed"
    );
}
