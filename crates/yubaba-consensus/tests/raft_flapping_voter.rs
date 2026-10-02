//! R936-B6: the term under a voter that flaps on and off the network.
//!
//! Prod measured term 43 -> 121 in ~55 s on a three-voter fleet that had
//! quorum and an elected leader the whole time, while one voter rejoined the
//! mesh. The mechanism, and the gate that stops it, are in the
//! `yubaba_consensus::raft::election_gate` module docs. This file pins both
//! halves:
//!
//! - **Control (gate off, Pre-Vote off).** A flapping voter deposes the
//!   healthy leader, and the healthy side's term climbs by several per flap.
//!   If this ever stops happening, the fixture has stopped reproducing the
//!   storm, and the guarded tests below prove nothing. So it is asserted
//!   rather than assumed.
//! - **Gate on (Pre-Vote off).** The same flap costs the healthy side at most
//!   one term, and the flapping voter comes back at or below the cluster's term.
//! - **Pre-Vote on (gate off), R734-T6.** openraft's own Pre-Vote, re-enabled
//!   on alpha.35, holds the same bound with no gate at all. This is the
//!   evidence any decision to retire the gate would start from.
//! - **Both on, as shipped.** Same bound.
//! - **Both on, leader cut.** Neither guard may strand a cluster that really
//!   lost its leader. The two survivors still elect.
//!
//! Each switch is set explicitly per test rather than inherited from
//! `ClusterPolicy::rig()`, so the control keeps meaning "no guard" whatever
//! the shipped Pre-Vote default is.
//!
//! # Why an in-memory transport, not the harness's `partition_node`
//!
//! `yubaba_test_harness::Cluster::partition_node` cuts a node by shutting its
//! raft down, and its own docs name the gap: "a shut-down node stops
//! campaigning, where a really-partitioned one keeps raising terms". Raising
//! terms while cut off is the whole bug. So these nodes run on real
//! `YubabaLogStore` / `YubabaStateMachine` storage, joined by a router that can
//! drop every RPC to and from one node while its raft keeps running and its
//! election timer keeps firing.
//!
//! Timings are the rig preset (heartbeat 150 ms, election 450-900 ms): four
//! 2.5 s cuts give the flapping node about three election timeouts each, which
//! is enough to separate "several terms per flap" from "at most one" by a
//! wide margin on a loaded machine.
//!
//! ```bash
//! cd oss/yubaba && cargo test -p yubaba-consensus --test raft_flapping_voter
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openraft::async_runtime::watch::WatchReceiver;
use openraft::error::{RPCError, ReplicationClosed, StreamingError, Unreachable};
use openraft::network::v2::RaftNetworkV2;
use openraft::network::{RPCOption, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::type_config::alias::{SnapshotOf, VoteOf};
use openraft::{BasicNode, OptionalSend, ServerState};
use yubaba_consensus::cluster_policy::ClusterPolicy;
use yubaba_consensus::raft::election_gate::spawn_election_gate;
use yubaba_consensus::raft::{
    YubabaLogStore, YubabaRaft, YubabaRaftConfig as TC, YubabaStateMachine,
};

// ── In-memory transport with a cut switch ────────────────────────────────────

#[derive(Default)]
struct RouterInner {
    rafts: Mutex<BTreeMap<u64, YubabaRaft>>,
    cut: Mutex<BTreeSet<u64>>,
    /// Pre-Vote RPCs attempted through the router, cut or not.
    pre_votes: AtomicU64,
}

#[derive(Clone, Default)]
struct Router(Arc<RouterInner>);

impl Router {
    fn set_cut(&self, id: u64, cut: bool) {
        let mut set = self.0.cut.lock().unwrap();
        if cut {
            set.insert(id);
        } else {
            set.remove(&id);
        }
    }

    /// The target's raft, or `None` if either end of the link is cut.
    fn route(&self, from: u64, to: u64) -> Option<YubabaRaft> {
        let cut = self.0.cut.lock().unwrap();
        if cut.contains(&from) || cut.contains(&to) {
            return None;
        }
        drop(cut);
        self.0.rafts.lock().unwrap().get(&to).cloned()
    }
}

#[derive(Clone)]
struct RouterFactory {
    from: u64,
    router: Router,
}

impl RaftNetworkFactory<TC> for RouterFactory {
    type Network = RouterNetwork;

    async fn new_client(&mut self, target: u64, _node: &BasicNode) -> Self::Network {
        RouterNetwork {
            from: self.from,
            to: target,
            router: self.router.clone(),
        }
    }
}

struct RouterNetwork {
    from: u64,
    to: u64,
    router: Router,
}

fn unreachable() -> Unreachable<TC> {
    Unreachable::new(&std::io::Error::other("link cut"))
}

impl RouterNetwork {
    fn target(&self) -> Result<YubabaRaft, RPCError<TC>> {
        self.router
            .route(self.from, self.to)
            .ok_or_else(|| RPCError::Unreachable(unreachable()))
    }
}

impl RaftNetworkV2<TC> for RouterNetwork {
    type SnapshotData = Cursor<Vec<u8>>;

    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TC>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<TC>, RPCError<TC>> {
        self.target()?
            .append_entries(rpc)
            .await
            .map_err(|_| RPCError::Unreachable(unreachable()))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<TC>,
        _option: RPCOption,
    ) -> Result<VoteResponse<TC>, RPCError<TC>> {
        self.target()?
            .vote(rpc)
            .await
            .map_err(|_| RPCError::Unreachable(unreachable()))
    }

    async fn pre_vote(
        &mut self,
        rpc: VoteRequest<TC>,
        _option: RPCOption,
    ) -> Result<VoteResponse<TC>, RPCError<TC>> {
        self.router.0.pre_votes.fetch_add(1, Ordering::Relaxed);
        self.target()?
            .pre_vote(rpc)
            .await
            .map_err(|_| RPCError::Unreachable(unreachable()))
    }

    async fn full_snapshot(
        &mut self,
        vote: VoteOf<TC>,
        snapshot: SnapshotOf<TC, Self::SnapshotData>,
        _cancel: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<TC>, StreamingError<TC>> {
        let target = self
            .router
            .route(self.from, self.to)
            .ok_or_else(|| StreamingError::Unreachable(unreachable()))?;
        target
            .install_full_snapshot(vote, snapshot)
            .await
            .map_err(|_| StreamingError::Unreachable(unreachable()))
    }
}

// ── Three-voter fixture ──────────────────────────────────────────────────────

struct Fixture {
    router: Router,
    rafts: BTreeMap<u64, YubabaRaft>,
    _dirs: Vec<tempfile::TempDir>,
}

const IDS: [u64; 3] = [1, 2, 3];

impl Fixture {
    async fn start(gated: bool, pre_vote: bool) -> Self {
        let policy = ClusterPolicy::rig();
        let mut config = policy.timing.to_openraft_config().expect("valid rig timing");
        config.enable_pre_vote = Some(pre_vote);
        let config = Arc::new(config);
        let router = Router::default();
        let mut rafts = BTreeMap::new();
        let mut dirs = Vec::new();

        for id in IDS {
            let dir = tempfile::tempdir().expect("tempdir");
            let log_store = YubabaLogStore::open(dir.path().join("raft"))
                .await
                .expect("log store");
            let state_machine = YubabaStateMachine::open(dir.path().join("raft"))
                .await
                .expect("state machine");
            let network = RouterFactory {
                from: id,
                router: router.clone(),
            };
            let raft = YubabaRaft::new(id, config.clone(), network.clone(), log_store, state_machine)
                .await
                .expect("raft");
            if gated {
                spawn_election_gate(raft.clone(), network, policy.timing);
            }
            router.0.rafts.lock().unwrap().insert(id, raft.clone());
            rafts.insert(id, raft);
            dirs.push(dir);
        }

        let members: BTreeMap<u64, BasicNode> = IDS
            .iter()
            .map(|id| (*id, BasicNode { addr: format!("mem-{id}") }))
            .collect();
        rafts[&1].initialize(members).await.expect("initialize");

        Self {
            router,
            rafts,
            _dirs: dirs,
        }
    }

    fn term(&self, id: u64) -> u64 {
        self.rafts[&id].metrics().borrow_watched().current_term
    }

    fn is_leader(&self, id: u64) -> bool {
        self.rafts[&id].metrics().borrow_watched().state == ServerState::Leader
    }

    /// Wait until one of `among` leads, and return it.
    async fn wait_for_leader(&self, among: &[u64], timeout: Duration) -> u64 {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(id) = among.iter().copied().find(|id| self.is_leader(*id)) {
                return id;
            }
            assert!(
                Instant::now() < deadline,
                "no leader among {among:?} within {timeout:?}; terms {:?}",
                IDS.map(|id| self.term(id))
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn shutdown(self) {
        for raft in self.rafts.values() {
            let _ = raft.shutdown().await;
        }
    }
}

struct FlapOutcome {
    healthy_before: u64,
    healthy_after: u64,
    victim_after: u64,
}

/// Elect a leader, then cut one follower off four times for 2.5 s with 1 s
/// reconnects between, and report the healthy side's term before and after.
async fn flap(gated: bool, pre_vote: bool) -> FlapOutcome {
    let fx = Fixture::start(gated, pre_vote).await;
    let leader = fx.wait_for_leader(&IDS, Duration::from_secs(10)).await;
    let victim = IDS.into_iter().find(|id| *id != leader).unwrap();
    let healthy: Vec<u64> = IDS.into_iter().filter(|id| *id != victim).collect();

    // Let the leader's lease and (when on) the gate settle: a few heartbeats
    // and more than one election_timeout_max, so the first cut does not race
    // the gate's first pass.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let healthy_term = |fx: &Fixture| healthy.iter().map(|id| fx.term(*id)).max().unwrap();
    let healthy_before = healthy_term(&fx);

    for _ in 0..4 {
        fx.router.set_cut(victim, true);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        fx.router.set_cut(victim, false);
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }

    fx.wait_for_leader(&IDS, Duration::from_secs(10)).await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let outcome = FlapOutcome {
        healthy_before,
        healthy_after: healthy_term(&fx),
        victim_after: fx.term(victim),
    };
    eprintln!(
        "flap(gated={gated}, pre_vote={pre_vote}): healthy term {} -> {}, victim term {}",
        outcome.healthy_before, outcome.healthy_after, outcome.victim_after
    );
    fx.shutdown().await;
    outcome
}

/// Four flaps must cost the healthy side at most one term, and the flapping
/// voter must not come back ahead of the cluster.
fn assert_flap_bounded(out: &FlapOutcome, what: &str) {
    assert!(
        out.healthy_after <= out.healthy_before + 1,
        "{what}: four flaps must cost the healthy side at most one term, got {} -> {}",
        out.healthy_before,
        out.healthy_after
    );
    assert!(
        out.victim_after <= out.healthy_after,
        "{what}: the flapping voter must not come back ahead of the cluster (victim {}, cluster {})",
        out.victim_after,
        out.healthy_after
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_no_guard_a_flapping_voter_deposes_the_leader_every_flap() {
    let out = flap(false, false).await;
    assert!(
        out.healthy_after >= out.healthy_before + 3,
        "the control must reproduce the storm (healthy term {} -> {}); if it no longer does, \
         the gated test below proves nothing",
        out.healthy_before,
        out.healthy_after
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_the_gate_a_flapping_voter_costs_at_most_one_term() {
    assert_flap_bounded(&flap(true, false).await, "gate only");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_pre_vote_alone_a_flapping_voter_costs_at_most_one_term() {
    assert_flap_bounded(&flap(false, true).await, "Pre-Vote only");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_gate_and_pre_vote_a_flapping_voter_costs_at_most_one_term() {
    assert_flap_bounded(&flap(true, true).await, "gate + Pre-Vote (shipped)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn as_shipped_the_survivors_still_replace_a_cut_leader() {
    let fx = Fixture::start(true, true).await;
    let leader = fx.wait_for_leader(&IDS, Duration::from_secs(10)).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let before = fx.term(leader);

    fx.router.set_cut(leader, true);
    let survivors: Vec<u64> = IDS.into_iter().filter(|id| *id != leader).collect();
    let new_leader = fx.wait_for_leader(&survivors, Duration::from_secs(10)).await;
    let after = fx.term(new_leader);
    assert!(
        after > before && after <= before + 3,
        "survivors must elect promptly at a nearby term, got {before} -> {after}"
    );

    // The old leader rejoins as a follower of the new term.
    fx.router.set_cut(leader, false);
    let deadline = Instant::now() + Duration::from_secs(10);
    while fx.is_leader(leader) || fx.term(leader) < after {
        assert!(Instant::now() < deadline, "old leader never stepped down");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(fx.is_leader(new_leader), "rejoining old leader must not depose the new one");
    fx.shutdown().await;
}

/// The gate probes once per heartbeat interval per follower per peer, and no
/// faster.
///
/// The first dev-group build (0.8.42-h7) woke the gate on every metrics-watch
/// change. openraft publishes metrics after every core event, including the
/// probe itself and every Pre-Vote a peer answers, so the gate fed itself: the
/// Pis served 340-930 Pre-Votes/s each. Every flap test above still passed
/// against that build, because correctness never depended on the rate. This
/// test is the one that fails on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probes_run_at_the_heartbeat_cadence() {
    let fx = Fixture::start(true, false).await;
    fx.wait_for_leader(&IDS, Duration::from_secs(10)).await;
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let window = Duration::from_secs(3);
    let start = fx.router.0.pre_votes.load(Ordering::Relaxed);
    tokio::time::sleep(window).await;
    let probes = fx.router.0.pre_votes.load(Ordering::Relaxed) - start;

    // Two followers x two peers x (window / heartbeat) rounds.
    let heartbeat = ClusterPolicy::rig().timing.heartbeat_interval_ms;
    let expected = 2 * 2 * (window.as_millis() as u64 / heartbeat);
    eprintln!("pre-votes in {window:?}: {probes} (cadence predicts {expected})");
    assert!(probes > 0, "the gate must actually be probing");
    assert!(
        probes <= expected * 2,
        "gate probed {probes} times in {window:?}; the heartbeat cadence allows about {expected}"
    );
    fx.shutdown().await;
}
