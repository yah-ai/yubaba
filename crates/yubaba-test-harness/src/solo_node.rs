//! One yubaba node on loopback, serving the real HTTP router, with a live but
//! **uninitialised** raft — R734-F2.
//!
//! [`test_cluster`](crate::test_cluster) founds a working quorum, which is the
//! wrong shape for testing the things that happen *before* a cluster exists:
//! the `/raft/initialize` gate, and any RPC whose interesting answer depends on
//! the node holding no committed vote and therefore no leader lease. Those
//! tests need exactly one node, up, reachable, and not yet a cluster.
//!
//! It is also the shape of a real fleet box between provisioning and founding:
//! started with `--raft-node-id <n>` and nothing else, waiting for either an
//! operator's `raft init` or a leader's AppendEntries.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::runtime::DummyRuntime;
use yubaba::SovereignRole;

/// A solo yubaba node bound on a loopback port. Dropping it aborts the server
/// task and removes the state directory.
/// The schedulable budget every registering harness node publishes (R737-F1).
///
/// A **fixed synthetic** figure, deliberately not the measured one the daemon
/// uses. A placement test asserting "this tenant fits, that one does not" has to
/// be a statement about the scheduler, and reading the host's real RAM would
/// make it a statement about whoever's laptop ran it — green on a 64 GB machine
/// and red in CI for a reason no error message would name.
///
/// 16 GiB / 8 cores is a plausible fleet box (`.yah/infra/machines/*.toml`
/// `[allocatable]` values sit in this range) so the arithmetic in a test reads
/// like the arithmetic in production.
pub const HARNESS_CAPACITY: yubaba::raft::NodeCapacity = yubaba::raft::NodeCapacity {
    memory_mb: 16384,
    cpu_millis: 8000,
};

pub struct SoloNode {
    /// `http://127.0.0.1:<port>` — the node's API base.
    pub base_url: String,
    /// `127.0.0.1:<port>` — the form a peer would be given as a mesh address.
    pub addr: String,
    /// The raft node id this node was opened with.
    pub node_id: u64,
    /// The region this node was started with (`yubaba serve --region`), or
    /// `None` for an untagged node.
    pub region: Option<String>,
    /// The sovereign group this node was started with (`yubaba serve
    /// --sovereign-group`), or `None` for a node declaring no group — which is
    /// what leaves the R742-F1 add-learner gate switched off.
    pub sovereign_group: Option<String>,
    /// This node's raft handle — the same one its router serves from.
    ///
    /// Exposed (R734-T4) because a test that drives a background loop needs to
    /// hand it the same handles the daemon does: `leader_pin::spawn` and
    /// `member_registration::spawn` both take `(YubabaRaft, YubabaStateMachine)`,
    /// and a harness that returns neither forces every such test to rebuild the
    /// node inline and drift from what `solo_node` actually does.
    pub raft: yubaba::raft::YubabaRaft,
    /// Read handle on this node's locally-applied state — the same one wired
    /// into its `ServerState`, so a test can assert on applied state without
    /// going through HTTP. See [`SoloNode::raft`] for why both are public.
    pub state_machine: yubaba::raft::YubabaStateMachine,
    _tmp: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
    registration: tokio::task::JoinHandle<()>,
}

impl Drop for SoloNode {
    fn drop(&mut self) {
        self.task.abort();
        self.registration.abort();
    }
}

/// Bring up a solo, uninitialised yubaba node under `policy` and wait for its
/// `/health` to answer.
///
/// No `initialize`, no `--bootstrap-single-node`: the raft instance is open and
/// every `/raft/*` route is live, but the node holds no membership and no
/// committed vote.
pub async fn solo_node(node_id: u64, policy: ClusterPolicy) -> Result<SoloNode> {
    solo_node_in_region(node_id, policy, None).await
}

/// [`solo_node`], with this node declaring `region` — the harness equivalent of
/// `yubaba serve --region <label>` (R734-F5).
///
/// Like the daemon, the node runs its member-registration loop: once it is in
/// membership and a leader exists, it writes its own `(addr, region)` row into
/// replicated state. A test asserting on regions therefore asserts on the same
/// path production walks, rather than on a hand-seeded map.
pub async fn solo_node_in_region(
    node_id: u64,
    policy: ClusterPolicy,
    region: Option<&str>,
) -> Result<SoloNode> {
    build(Spec {
        node_id,
        policy,
        region,
        ..Spec::default()
    })
    .await
}

/// [`solo_node`], with this node declaring `sovereign_group` — the harness
/// equivalent of `yubaba serve --sovereign-group <label>` (R742-F1).
///
/// Declaring one is what arms this node's `POST /raft/add-learner` gate, so a
/// test of the gate needs at least two of these: the cluster being joined, and
/// the joiner whose own declaration the leader goes and reads. A node built by
/// any other constructor here declares nothing, which is deliberately the
/// unstamped-cluster case the gate must leave alone.
pub async fn solo_node_in_sovereign_group(
    node_id: u64,
    policy: ClusterPolicy,
    sovereign_group: Option<&str>,
) -> Result<SoloNode> {
    build(Spec {
        node_id,
        policy,
        sovereign_group,
        ..Spec::default()
    })
    .await
}

/// [`solo_node_in_sovereign_group`], with this node's quorum eligibility said
/// out loud — the harness equivalent of `yubaba serve --sovereign-group <label>
/// --sovereign-role non-voter` (R605-F12).
///
/// Separate from the constructor above rather than a fourth parameter on it
/// because [`SovereignRole::Voter`] is what every existing gate test means and
/// what a bare `--sovereign-group` gives a real node; only a test of the
/// non-voting refusal needs to say otherwise.
pub async fn solo_node_with_sovereign_role(
    node_id: u64,
    policy: ClusterPolicy,
    sovereign_group: Option<&str>,
    sovereign_role: SovereignRole,
) -> Result<SoloNode> {
    build(Spec {
        node_id,
        policy,
        sovereign_group,
        sovereign_role,
        ..Spec::default()
    })
    .await
}

/// [`solo_node`] with the member-registration loop **not** running — a node that
/// will never publish a row about itself (R734-F5).
///
/// This is a real deployment state, not a synthetic one: it is what a node whose
/// build predates R734-F5 looks like from the rest of the cluster during a
/// rolling upgrade, and it is what any consumer of the member map has to keep
/// working against. Tests of the "the region is unknown" branches need a node
/// that stays unregistered — clearing a row out from under a live loop only
/// races it, since the clearing write is itself a metrics change that wakes the
/// loop straight back up.
pub async fn solo_node_unregistered(
    node_id: u64,
    policy: ClusterPolicy,
    region: Option<&str>,
) -> Result<SoloNode> {
    build(Spec {
        node_id,
        policy,
        region,
        register: false,
        ..Spec::default()
    })
    .await
}

/// What [`build`] needs to stand a node up.
///
/// A struct rather than positional arguments because the list had reached
/// `(u64, ClusterPolicy, Option<&str>, bool)` and R742-F1 wanted to add a
/// second `Option<&str>` — at which point a call site says nothing about which
/// label is the region and which is the sovereign group. Every public
/// constructor above sets the one field it is named for and takes the rest
/// from [`Default`], so adding a third label later costs no call-site churn.
struct Spec<'a> {
    node_id: u64,
    policy: ClusterPolicy,
    region: Option<&'a str>,
    sovereign_group: Option<&'a str>,
    /// R605-F12. Not an `Option`: a real node's flag defaults to `voter`, so
    /// there is no unset state for the harness to reproduce.
    sovereign_role: SovereignRole,
    /// Run the R734-F5 member-registration loop, as the daemon does.
    register: bool,
}

impl Default for Spec<'_> {
    fn default() -> Self {
        Self {
            node_id: 1,
            policy: ClusterPolicy::fleet(),
            region: None,
            sovereign_group: None,
            sovereign_role: SovereignRole::Voter,
            register: true,
        }
    }
}

async fn build(
    Spec {
        node_id,
        policy,
        region,
        sovereign_group,
        sovereign_role,
        register,
    }: Spec<'_>,
) -> Result<SoloNode> {
    let region = region.map(str::to_string);
    let sovereign_group = sovereign_group.map(str::to_string);
    let tmp = tempfile::TempDir::new().context("solo node tempdir")?;
    let state_path = tmp.path().join("identity.json");
    let raft_dir = tmp.path().join("raft");
    std::fs::create_dir_all(&raft_dir).context("solo node raft dir")?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind solo node listener")?;
    let addr = listener.local_addr().context("solo node local_addr")?;
    let addr = format!("127.0.0.1:{}", addr.port());
    let base_url = format!("http://{addr}");

    let (raft, state_machine) = yubaba::raft::open_with_state_machine(node_id, raft_dir, &policy)
        .await
        .with_context(|| format!("open raft for solo node {node_id}"))?;

    let mut state = yubaba::ServerState::load(state_path)
        .context("load solo node state")?
        .with_runtime(Arc::new(DummyRuntime))
        .with_cluster_policy(policy)
        .with_raft(raft.clone())
        .with_node_id(node_id)
        // Applied-state reads: `GET /raft/status`'s member rows, and everything
        // else that answers from the local replica.
        .with_cluster_state(state_machine.clone());
    if let Some(region) = &region {
        state = state.with_region(region.clone());
    }
    if let Some(group) = &sovereign_group {
        state = state.with_sovereign_group(group.clone());
    }
    state = state.with_sovereign_role(sovereign_role);
    let registration = if register {
        yubaba::member_registration::spawn(
            node_id,
            raft.clone(),
            state_machine.clone(),
            region.clone(),
            Some(HARNESS_CAPACITY),
        )
    } else {
        tokio::spawn(async {})
    };
    let router = yubaba::build_router(Arc::new(state));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let client = reqwest::Client::new();
    loop {
        if client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("solo node {node_id} did not become healthy within 10s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Ok(SoloNode {
        base_url,
        addr,
        node_id,
        region,
        sovereign_group,
        raft,
        state_machine,
        _tmp: tmp,
        task,
        registration,
    })
}
