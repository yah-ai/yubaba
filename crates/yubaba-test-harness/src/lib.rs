//! `yubaba-test-harness` — `Cluster` harness for yubaba integration tests.
//!
//! Companion crate to `yubaba-test-macros`. Integration tests get here via
//! the fixture builder:
//!
//! ```rust,ignore
//! let cluster = warden_test_harness::test_cluster(&p, rt, 3).await?;
//! cluster.wait_for_leader(Duration::from_secs(15)).await?;
//! let w0 = cluster.yubaba(0);
//! w0.deploy_workload(&spec).await?;
//! let state = wait_for_state(w0, &spec.expose.mesh.identity,
//!     WorkloadStatus::Running, Duration::from_secs(60)).await?;
//! let resp = cluster.yubaba(1).mesh_get(&spec.expose.mesh.identity, 8080, "/health").await?;
//! assert_eq!(resp.status, 200); // raft replication verified
//! ```
//!
//! ## Auto-teardown contract
//!
//! `Cluster` implements `Drop`. When the cluster goes out of scope (or panics),
//! `Drop` aborts every in-process server task (local tier) and fires the smoke
//! tier teardown closure (destroy Hetzner machines). Call `destroy_all().await`
//! explicitly when you need to assert on teardown errors.
//!
//! ## Tier routing
//!
//! `test_cluster` reads `YAH_SMOKE` at runtime:
//!
//! - **`YAH_SMOKE` unset or `!= "1"`** → local tier: starts yubaba in-process
//!   on random loopback ports, bootstraps a real openraft cluster between the
//!   nodes. Fast, no credentials, no billing.
//! - **`YAH_SMOKE=1`** → smoke tier: provisions real Hetzner machines via
//!   `provider`, waits for yubaba to become healthy on each machine. Requires
//!   `HETZNER_API_TOKEN`, `YAH_YUBABA_URL`, `YAH_YUBABA_SHA256`.
//!
//! ## Multi-node raft (local tier)
//!
//! For `nodes > 1`, the harness:
//! 1. Opens a raft node per server (via `yubaba::raft::open`) using a tempdir
//!    for file-backed persistence.
//! 2. Binds a random loopback port per node.
//! 3. Bootstraps the raft cluster by calling `raft.initialize(all_members)` on
//!    node 0 — the membership map contains every node's `node_id → addr`.
//! 4. Waits for a leader to be elected before returning.
//!
//! Raft messages flow over HTTP between the in-process servers using the
//! `/raft/append-entries`, `/raft/vote`, and `/raft/install-snapshot` routes.
//!
//! ## Mesh connectivity (local tier)
//!
//! `WardenHandle::mesh_get` in the local tier verifies that a peer node can
//! resolve a workload by its mesh identity via raft-replicated state. It does
//! NOT exercise WireGuard-routed traffic (KNOWN-LOCAL-GAP — see
//! yah-yubaba-integration-testing.md §KNOWN-LOCAL-GAPS). Actual wire-level
//! mesh routing is tested in the smoke tier only.
//!
//! ## Implementation sequencing
//!
//! - **F4 (types + stubs)**: Cluster shape, WardenHandle API stubs, wait_for_state.
//! - **F5**: `test_cluster` single-node impl (both tiers), deploy + state round-trip.
//! - **F6 (this revision)**: Multi-node raft bootstrap, `kill_node`, `restart_node`,
//!   `wait_for_leader`, `current_leader_idx`, `mesh_get` implementation.
//!
//! @arch:see(.yah/docs/architecture/A053-yah-yubaba-integration-testing.md)

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use cloud::provider::{MachineProvider, ServerId};
use openraft::async_runtime::watch::WatchReceiver;
use openraft::BasicNode;
use workload_spec::{MeshIdent, WorkloadSpec};
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::failure_detector::RaftHeartbeatDetector;

/// The [`ClusterPolicy`] [`test_cluster`] founds its clusters under.
///
/// The fleet preset, deliberately: `test_cluster` exists to exercise the
/// shipped fleet's behaviour, so its clusters must obey the shipped fleet's
/// rules (learner-only admission, WAN election timings). A test that needs
/// different rules calls [`test_cluster_with_policy`] rather than reconfiguring
/// this out from under every other test.
const HARNESS_POLICY: ClusterPolicy = ClusterPolicy::fleet();

// ── WorkloadStatus re-export ──────────────────────────────────────────────────

pub use kamaji::{WorkloadState, WorkloadStatus};

/// R732-T4/T5: drive the tenant streamer's tail loop against an in-process
/// raft state machine, with no HTTP listener and no service to spawn.
pub mod tenant_ownership;
pub use tenant_ownership::LocalOwnership;

/// R734-F2: one uninitialised node on loopback, for the routes and RPCs whose
/// interesting behaviour happens *before* a cluster exists.
pub mod solo_node;
pub use solo_node::{
    solo_node, solo_node_in_cell, solo_node_in_region, solo_node_in_sovereign_group,
    solo_node_unregistered, solo_node_with_sovereign_role, SoloNode, HARNESS_CAPACITY,
};

// ── MeshResponse ─────────────────────────────────────────────────────────────

/// Response from a mesh-routed HTTP call (or state-check in local tier).
#[derive(Debug)]
pub struct MeshResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body as a string.
    pub body: String,
}

// ── WardenHandle ──────────────────────────────────────────────────────────────

/// RPC handle to one yubaba node in the test cluster.
///
/// Operations proxy through the yubaba HTTP API (same surface exposed to the
/// desktop app and agents in production).
pub struct WardenHandle {
    /// HTTP base URL for this node's yubaba API (e.g. `http://127.0.0.1:7443`).
    pub base_url: String,
    client: reqwest::Client,
}

impl WardenHandle {
    pub(crate) fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Deploy a workload via the yubaba `/workloads/deploy` RPC.
    ///
    /// Posts the spec JSON and waits for acceptance (202) or deployment (201).
    /// The workload may still be in `Pending` state — poll `get_workload_state`
    /// until `Running`.
    pub async fn deploy_workload(&self, spec: &WorkloadSpec) -> Result<()> {
        let body = serde_json::json!({ "spec": spec });
        let resp = self
            .client
            .post(&format!("{}/workloads/deploy", self.base_url))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST /workloads/deploy to {}", self.base_url))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let text = resp.text().await.unwrap_or_default();
        bail!("deploy_workload: HTTP {status}: {text}");
    }

    /// Poll the current status of a workload by mesh identity.
    ///
    /// Returns `Ok(None)` when the workload is not yet known to this yubaba
    /// node (may appear with a short lag after deploy).
    pub async fn get_workload_state(&self, ident: &MeshIdent) -> Result<Option<WorkloadStatus>> {
        let url = format!("{}/workloads/{}/state", self.base_url, ident.0);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let s = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("get_workload_state: HTTP {s}: {text}");
        }

        let state: WorkloadState = resp.json().await.context("deserializing WorkloadState")?;
        Ok(Some(state.status))
    }

    /// Make an HTTP GET via the cluster mesh to `<ident>:<port><path>`.
    ///
    /// **Local tier**: verifies that this node can resolve the workload by its
    /// mesh identity (via raft-replicated state). Returns 200 when the workload
    /// is `Running`, 503 when not ready, 404 when not found.
    ///
    /// **KNOWN-LOCAL-GAP**: WireGuard-routed traffic is NOT exercised in the
    /// local tier. Actual packet routing via the cluster mesh is smoke-tier-only
    /// (see yah-yubaba-integration-testing.md §KNOWN-LOCAL-GAPS). The `port`
    /// and `path` parameters are passed through but ignored in the local-tier
    /// implementation; smoke tier will use them for real HTTP routing.
    pub async fn mesh_get(
        &self,
        ident: &MeshIdent,
        _port: u16,
        _path: &str,
    ) -> Result<MeshResponse> {
        // Local tier: state reachability check via raft replication.
        // Smoke tier would route via WireGuard mesh to <mesh_ip>:<port><path>.
        match self.get_workload_state(ident).await? {
            Some(WorkloadStatus::Running) => Ok(MeshResponse {
                status: 200,
                body: format!("workload {} is Running (raft-replicated state)", ident.0),
            }),
            Some(s) => Ok(MeshResponse {
                status: 503,
                body: format!("workload {} not ready: {s:?}", ident.0),
            }),
            None => Ok(MeshResponse {
                status: 404,
                body: format!("workload {} not found on this node", ident.0),
            }),
        }
    }

    /// Check that the yubaba HTTP API is reachable and healthy.
    pub async fn health_check(&self) -> Result<()> {
        let url = format!("{}/health", self.base_url);
        self.client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("yubaba health check failed at {url}"))?
            .error_for_status()
            .with_context(|| format!("yubaba /health returned non-2xx at {url}"))?;
        Ok(())
    }
}

// ── ClusterNode ───────────────────────────────────────────────────────────────

/// Internal metadata for one node in the cluster.
struct ClusterNode {
    /// Yubaba RPC handle.
    yubaba: WardenHandle,
    /// Provider-side server ID — used for `destroy_server` in smoke-tier teardown.
    #[allow(dead_code)]
    server_id: ServerId,
    /// In-process server task (local tier only). `None` for smoke tier.
    task: Option<tokio::task::JoinHandle<()>>,
    /// Raft node handle, stored for `initialize()` during bootstrap and
    /// `metrics()` queries for leader detection. `None` for smoke tier or
    /// single-node local clusters.
    raft: Option<yubaba::raft::YubabaRaft>,
    /// Read handle to the same applied state the raft node writes into, so a
    /// test can check committed cluster state without an HTTP round-trip.
    /// `None` for smoke tier or single-node local clusters.
    state_machine: Option<yubaba::raft::YubabaStateMachine>,
    /// This node's node-lease registry (R737-F2) — the evidence channel a
    /// placement scheduler is allowed to trust, held here as well as inside
    /// `ServerState` so a test can drive it directly with
    /// [`Cluster::renew_lease`] instead of standing up the HTTP renewal loop.
    /// `None` for smoke tier or single-node local clusters, matching `raft`.
    lease_detector: Option<Arc<yubaba::lease_detector::LeaseFailureDetector>>,
    /// This node's streamer-RPO registry (R782), held here as well as inside
    /// `ServerState` for the same reason `lease_detector` above is — a test
    /// drives it directly with [`Cluster::report_watermark`] instead of
    /// standing up `tenant_streamer::rpo_report`'s HTTP client.
    /// `None` for smoke tier or single-node local clusters, matching `raft`.
    rpo_registry: Option<Arc<yubaba::lease_detector::RpoWatermarkRegistry>>,
    /// Raft persistence directory (local tier, multi-node). Used by
    /// `restart_node` to re-open the raft node from persisted state.
    raft_dir: Option<PathBuf>,
    /// TCP port this yubaba server listens on (local tier). Used by
    /// `restart_node` to bind on the same port after a kill.
    port: Option<u16>,
    /// This node's raft node ID (1-indexed: node 0 → id 1). Used by
    /// `restart_node` to re-open the raft node.
    node_id: Option<u64>,
    /// Path to the yubaba identity state file. Used by `restart_node`.
    state_path: Option<PathBuf>,
    /// Shared container runtime (local tier). Used by `restart_node` to wire
    /// the runtime into the restarted `ServerState`.
    runtime: Option<Arc<dyn kamaji::Kamaji + Send + Sync>>,
    /// The policy this node was founded under. Carried per node rather than
    /// read from a constant so `restart_node` re-opens with the *same* raft
    /// timings the rest of the cluster is running — a node that came back with
    /// different election bounds would campaign against peers that had not.
    policy: ClusterPolicy,
    /// The live `ServerState` this node's router was built on (local tier).
    ///
    /// Held so a test can spawn the daemon loops the harness deliberately does
    /// **not** spawn for it — `leader::spawn` is the one R858-T3 needs, the
    /// same way `raft_leader_pin` spawns `leader_pin` and `raft_tenant_placement`
    /// spawns schedulers. Replaced by [`Cluster::restart_node`], because a
    /// restart builds a genuinely new `ServerState` and a test holding the old
    /// one would be asserting against a dead process's memory.
    state: Option<Arc<yubaba::ServerState>>,
    /// This node's headscale state dir (local tier) — a path inside the node's
    /// tempdir rather than the on-host `/var/lib/yah-cloud/headscale` default.
    ///
    /// Carried per node so `restart_node` re-binds the *same* dir: the whole
    /// point of an appliance-restart test is that on-disk state outlives the
    /// process, and a restarted node pointed at a fresh dir would prove the
    /// opposite of what it was written to prove.
    headscale_dir: Option<PathBuf>,
}

// ── Cluster ───────────────────────────────────────────────────────────────────

/// Test cluster of N yubaba nodes.
///
/// Created by [`test_cluster`]. Implements `Drop` for auto-teardown.
///
/// ## Node-loss operations (F6)
///
/// [`Cluster::kill_node`] aborts the server task for one node (local tier) or
/// stops it (smoke tier stub). [`Cluster::restart_node`] re-binds on the same
/// port and re-opens the raft node from persisted state.
/// [`Cluster::wait_for_leader`] and [`Cluster::current_leader_idx`] expose the
/// raft election state.
///
/// **There is no partition primitive here, and there never was one.** The
/// `NetworkDegrade` type this struct used to carry described a `tc qdisc` spec,
/// but nothing read the field: it was set by a builder method and dropped. The
/// real `tc` knob (`YAH_LOCAL_NETWORK_DEGRADE`) belongs to
/// `cloud::provider::local_docker::LocalDockerProvider`, which puts machines in
/// *containers* — a different tier from these in-process loopback servers,
/// which share one network namespace and cannot be impaired with `tc` at all.
/// The dead type is removed (R118-T1) so that gap reads as a gap.
///
/// This matters because `kill_node` and a partition are **not**
/// interchangeable, and the difference is the whole safety argument for the
/// membership ratchet (W138 / R118-F7): a powered-off node emits nothing on any
/// channel, while an IP-partitioned node stays alive and answers a
/// corroborating one. `kill_node` models the first. Modelling the second needs
/// a way to cut a node's raft links while leaving it running, which is
/// R118-F7's to build alongside the detector that consumes it.
pub struct Cluster {
    nodes: Vec<ClusterNode>,
    /// Smoke tier teardown: destroy Hetzner machines + buckets. `None` for
    /// local tier (teardown is handled by `Drop` aborting tasks + dropping dirs).
    teardown: Arc<tokio::sync::Mutex<Option<TeardownFn>>>,
    /// Temp directories for local-tier nodes. Kept alive until `Cluster` drops.
    _tmp_dirs: Vec<tempfile::TempDir>,
}

type TeardownFn =
    Box<dyn FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send>;

impl Cluster {
    /// Access the yubaba handle for node at `idx`.
    ///
    /// Panics if `idx >= self.node_count()`.
    pub fn yubaba(&self, idx: usize) -> &WardenHandle {
        &self.nodes[idx].yubaba
    }

    /// The live `ServerState` behind node `idx`'s router (local tier,
    /// multi-node), for a test that needs to spawn a daemon loop the harness
    /// leaves to its callers.
    ///
    /// **Re-read it after [`Self::restart_node`]** — a restart builds a new
    /// `ServerState`, and the handle you held is the dead process's.
    ///
    /// `None` on the smoke tier, where the state lives in another process.
    pub fn server_state(&self, idx: usize) -> Option<Arc<yubaba::ServerState>> {
        self.nodes[idx].state.clone()
    }

    /// Node `idx`'s headscale state dir — the tempdir path its `ServerState`
    /// was pointed at, stable across [`Self::restart_node`].
    pub fn headscale_dir(&self, idx: usize) -> Option<PathBuf> {
        self.nodes[idx].headscale_dir.clone()
    }

    /// Number of nodes in this cluster.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Read handle to node `idx`'s locally-applied raft state, or `None` for a
    /// smoke-tier or single-node local cluster.
    ///
    /// The same `Arc<RwLock<…>>` the node's raft applies into, so a test can
    /// assert on committed state without an HTTP round-trip — useful as the
    /// independent oracle when the thing under test *is* an HTTP read path.
    pub fn cluster_state(&self, idx: usize) -> Option<&yubaba::raft::YubabaStateMachine> {
        self.nodes[idx].state_machine.as_ref()
    }

    /// Node `idx`'s raft handle — the same one its router serves from — or
    /// `None` for a smoke-tier or single-node local cluster.
    ///
    /// Exposed for the same reason [`crate::SoloNode::raft`] is: a test that
    /// drives one of the daemon's background loops must hand it the handles the
    /// daemon does. `scheduler::spawn` takes `(YubabaRaft, YubabaStateMachine,
    /// lease detector, raft detector, rpo registry)`, and a harness that
    /// returns only the state machine forces every such test to rebuild the
    /// node inline and drift from what `test_cluster` actually does.
    pub fn raft(&self, idx: usize) -> Option<&yubaba::raft::YubabaRaft> {
        self.nodes[idx].raft.as_ref()
    }

    /// Node `idx`'s raft node id (1-indexed: node 0 → id 1), or `None` for a
    /// smoke-tier or single-node local cluster.
    pub fn node_id(&self, idx: usize) -> Option<u64> {
        self.nodes[idx].node_id
    }

    /// Node `idx`'s node-lease registry (R737-F2), or `None` for a smoke-tier
    /// or single-node local cluster.
    ///
    /// Prefer [`Self::renew_lease`] / [`Self::renew_leases_except`] for driving
    /// it; this is the escape hatch for a test that needs the detector itself,
    /// e.g. to hand it to `scheduler::spawn`.
    pub fn lease_detector(
        &self,
        idx: usize,
    ) -> Option<&Arc<yubaba::lease_detector::LeaseFailureDetector>> {
        self.nodes[idx].lease_detector.as_ref()
    }

    /// Node `idx`'s streamer-RPO registry (R782), or `None` for a smoke-tier
    /// or single-node local cluster.
    ///
    /// Prefer [`Self::report_watermark`] for driving it; this is the escape
    /// hatch for a test that needs the registry itself, e.g. to hand it to
    /// `scheduler::spawn`.
    pub fn rpo_registry(
        &self,
        idx: usize,
    ) -> Option<&Arc<yubaba::lease_detector::RpoWatermarkRegistry>> {
        self.nodes[idx].rpo_registry.as_ref()
    }

    /// Explicitly destroy all cluster resources and await completion.
    ///
    /// Prefer this over relying on `Drop` when you want to assert on teardown
    /// errors. The `Drop` impl calls the same teardown but swallows errors.
    pub async fn destroy_all(&mut self) -> Result<()> {
        // Abort in-process tasks (local tier).
        for node in &mut self.nodes {
            if let Some(task) = node.task.take() {
                task.abort();
            }
        }
        // Smoke tier destroy.
        let mut guard = self.teardown.lock().await;
        if let Some(f) = guard.take() {
            f().await;
        }
        Ok(())
    }

    // ── Partition / quorum-loss operations (F6) ───────────────────────────────

    /// Pull the power on node `idx` (local tier): shut its raft node down and
    /// abort its HTTP server task.
    ///
    /// The node's raft persistence files are intact — [`Self::restart_node`]
    /// recovers from them. After this call the node's yubaba HTTP API is
    /// unreachable *and* its raft actor is stopped.
    ///
    /// **Both halves are load-bearing (R118-T1).** Aborting only the server
    /// task — which is all this used to do — models a machine whose HTTP
    /// listener died while its raft kept running: outbound `AppendEntries`
    /// still flow, peers still answer them over connections *it* opened, and so
    /// a "killed" leader keeps its lease and goes on leading a cluster that can
    /// no longer be written to. That is not a power loss, and a failover test
    /// built on it silently asserts nothing. Killing a *follower* happened to
    /// look right (a follower has no outbound replication to give it away),
    /// which is why the gap survived.
    ///
    /// The node's raft handle is dropped here, so [`Self::current_leader_idx`]
    /// stops reading leadership beliefs out of a machine that is meant to be
    /// dark.
    ///
    /// A small sleep is included after abort to let the OS free the TCP port.
    pub async fn kill_node(&mut self, idx: usize) -> Result<()> {
        let node = self
            .nodes
            .get_mut(idx)
            .ok_or_else(|| anyhow::anyhow!("kill_node: no node at index {idx}"))?;

        // Stop raft before the listener: a raft actor that outlives its own
        // server is exactly the half-dead state this models away.
        if let Some(raft) = node.raft.take() {
            raft.shutdown()
                .await
                .map_err(|e| anyhow::anyhow!("kill_node: raft shutdown for node {idx}: {e}"))?;
        }
        node.state_machine = None;

        if let Some(task) = node.task.take() {
            task.abort();
            // Give the OS time to release the port before a potential restart.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok(())
    }

    /// Whether node `idx` is currently running (local tier).
    ///
    /// False between a [`Self::kill_node`] and the matching
    /// [`Self::restart_node`].
    pub fn is_running(&self, idx: usize) -> bool {
        self.nodes[idx].task.is_some()
    }

    /// Restart a previously killed node at `idx`.
    ///
    /// Re-opens the raft node from its persisted state (vote + log files in the
    /// raft dir) and binds a new server on the **same port** as before. The
    /// restarted node re-joins the raft cluster via AppendEntries from the
    /// current leader once the leader detects it's available again.
    ///
    /// Waits for the restarted node's `/health` endpoint to respond.
    pub async fn restart_node(&mut self, idx: usize) -> Result<()> {
        let node = self
            .nodes
            .get_mut(idx)
            .ok_or_else(|| anyhow::anyhow!("restart_node: no node at index {idx}"))?;

        let port = node
            .port
            .ok_or_else(|| anyhow::anyhow!("restart_node: node {idx} has no port (smoke tier?)"))?;
        let raft_dir = node
            .raft_dir
            .clone()
            .ok_or_else(|| anyhow::anyhow!("restart_node: node {idx} has no raft_dir"))?;
        let node_id = node
            .node_id
            .ok_or_else(|| anyhow::anyhow!("restart_node: node {idx} has no node_id"))?;
        let state_path = node
            .state_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("restart_node: node {idx} has no state_path"))?;
        let runtime = node
            .runtime
            .clone()
            .ok_or_else(|| anyhow::anyhow!("restart_node: node {idx} has no runtime"))?;
        let policy = node.policy;

        // Re-open the raft node from persisted state, under the same policy the
        // cluster was founded with — a restarting node that changed its raft
        // timings would campaign against peers that had not.
        let (raft, state_machine) =
            yubaba::raft::open_with_state_machine(node_id, raft_dir, &policy)
                .await
                .with_context(|| format!("restart_node: re-open raft for node {idx}"))?;

        // A restarted node gets a *fresh* lease registry, not the old one: the
        // registry is this node's view of who has renewed to it, and it is
        // deliberately raft-free (R737-F2), so it does not survive a process
        // death any more than it would in production. A test that restarts the
        // leader must therefore re-renew.
        let leases = Arc::new(yubaba::lease_detector::LeaseFailureDetector::new(
            policy.liveness_thresholds(),
        ));
        // Same "fresh, not preserved" posture as `leases` above — R782's
        // registry is also deliberately raft-free.
        let rpo_registry = Arc::new(yubaba::lease_detector::RpoWatermarkRegistry::new());

        // Same dir the node was founded with — see `ClusterNode::headscale_dir`.
        // A restarted node pointed at a fresh dir loses the on-disk state whose
        // survival is the point of restarting it.
        let headscale_dir = node.headscale_dir.clone();

        let mut builder = yubaba::ServerState::load(state_path)
            .with_context(|| format!("restart_node: load state for node {idx}"))?
            .with_runtime(runtime);
        if let Some(dir) = headscale_dir {
            builder = builder.with_headscale_dir(dir);
        }
        let state = Arc::new(
            builder
                .with_cluster_policy(policy)
                .with_raft(raft.clone())
                .with_node_id(node_id)
                .with_cluster_state(state_machine.clone())
                .with_failure_detector(Arc::new(RaftHeartbeatDetector::new(
                    raft.clone(),
                    policy.liveness_thresholds(),
                )))
                .with_lease_detector(Arc::clone(&leases))
                .with_rpo_registry(Arc::clone(&rpo_registry)),
        );

        // Rebind on the same port. The killed task dropped the listener, so
        // this should succeed after the 200ms sleep in kill_node.
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .with_context(|| format!("restart_node: bind 127.0.0.1:{port} for node {idx}"))?;

        let router = yubaba::build_router(Arc::clone(&state));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        // Wait for the restarted server to respond.
        wait_for_yubaba_health(&format!("http://127.0.0.1:{port}"))
            .await
            .with_context(|| format!("restart_node: health check for node {idx}"))?;

        node.task = Some(task);
        node.raft = Some(raft);
        node.state_machine = Some(state_machine);
        node.lease_detector = Some(leases);
        node.rpo_registry = Some(rpo_registry);
        // The old handle belongs to a process that no longer exists; a test
        // that kept asserting against it would be reading a corpse's memory.
        node.state = Some(state);
        Ok(())
    }

    /// Record a node-lease renewal *from* node `from_idx` *into* node
    /// `at_idx`'s registry (R737-F2), without the HTTP hop.
    ///
    /// This is the test-side substitute for
    /// [`yubaba::lease_renewal`]'s production loop: a placement test needs to
    /// choose exactly which nodes look alive to the leader and when, and
    /// spawning the real loop would renew everyone unconditionally. Call it on
    /// every tick of a wait loop for the nodes that should stay live, and
    /// simply stop calling it for the one whose death you are staging.
    ///
    /// A no-op if `at_idx` has no lease detector (smoke tier / single-node).
    pub fn renew_lease(&self, at_idx: usize, from_idx: usize) {
        let Some(detector) = self.nodes[at_idx].lease_detector.as_ref() else {
            return;
        };
        let Some(node_id) = self.nodes[from_idx].node_id else {
            return;
        };
        detector.renew(node_id);
    }

    /// Record a streamer-RPO report (R782) *for* node `from_idx` *into* node
    /// `at_idx`'s registry, without the HTTP hop — the test-side substitute
    /// for `tenant_streamer::rpo_report::RpoReporter`, mirroring
    /// [`Self::renew_lease`] for the same reason: a placement test needs to
    /// choose exactly which candidate has fresh RPO evidence and when.
    ///
    /// A no-op if `at_idx` has no RPO registry (smoke tier / single-node).
    pub fn report_watermark(
        &self,
        at_idx: usize,
        from_idx: usize,
        tenant: &workload_spec::TenantId,
        watermark_age: Option<Duration>,
    ) {
        let Some(registry) = self.nodes[at_idx].rpo_registry.as_ref() else {
            return;
        };
        let Some(node_id) = self.nodes[from_idx].node_id else {
            return;
        };
        registry.report(node_id, tenant.clone(), watermark_age);
    }

    /// Renew every *running* node's lease into node `at_idx`'s registry,
    /// except those named in `except`.
    ///
    /// The shape a placement test actually wants: "the whole fleet is alive
    /// except the one I killed". Nodes stopped by [`Self::kill_node`] are
    /// skipped automatically — a killed node cannot renew, and a test that had
    /// to remember to exclude it by hand would silently keep a corpse alive.
    pub fn renew_leases_except(&self, at_idx: usize, except: &[usize]) {
        for idx in 0..self.nodes.len() {
            if except.contains(&idx) || !self.is_running(idx) {
                continue;
            }
            self.renew_lease(at_idx, idx);
        }
    }

    /// Wait until a raft leader is elected in the cluster.
    ///
    /// Polls `raft.metrics().current_leader` on every node that has a raft
    /// instance. Returns the 0-based index of the leader node once elected.
    ///
    /// Returns an error if `timeout` elapses without a leader.
    pub async fn wait_for_leader(&self, timeout: Duration) -> Result<usize> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if tokio::time::Instant::now() > deadline {
                bail!("wait_for_leader: no leader elected within {timeout:?}");
            }
            if let Some(idx) = self.current_leader_idx() {
                return Ok(idx);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait until every *live* node reports the **same** raft leader **and that
    /// leader is itself still running**, then return its 0-based index.
    ///
    /// Stricter than [`Self::wait_for_leader`] on both counts, and both matter
    /// after a failover:
    ///
    /// - `wait_for_leader` is satisfied by the *first* node that names any
    ///   leader, so one lagging follower's opinion answers for the cluster;
    /// - and neither it nor a bare agreement check notices that the node
    ///   everyone still names is the one the test just killed. Straight after a
    ///   kill the survivors unanimously believe in the dead leader — that
    ///   unanimity is the *pre*-failover state, and a test that accepts it
    ///   asserts nothing about failover at all. (This is not hypothetical: it
    ///   is what the first run of `rig_singleton_ownership` reported.)
    ///
    /// Nodes killed by [`Self::kill_node`] are excluded from both the polling
    /// set (they hold no raft handle) and the set of acceptable answers.
    /// Errors if `timeout` elapses without such an agreement.
    pub async fn wait_for_agreed_leader(&self, timeout: Duration) -> Result<usize> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let beliefs: Vec<Option<u64>> = self
                .nodes
                .iter()
                .filter_map(|n| n.raft.as_ref())
                .map(|raft| raft.metrics().borrow_watched().current_leader)
                .collect();

            if let Some(Some(first)) = beliefs.first().copied() {
                // node_id is 1-indexed: node 0 → id 1.
                let idx = (first as usize).saturating_sub(1);
                let leader_is_running = self.nodes.get(idx).is_some_and(|n| n.raft.is_some());
                if leader_is_running && beliefs.iter().all(|b| *b == Some(first)) {
                    return Ok(idx);
                }
            }
            if tokio::time::Instant::now() > deadline {
                bail!(
                    "wait_for_agreed_leader: live nodes did not agree on a live leader within \
                     {timeout:?}; last per-node current_leader was {beliefs:?} \
                     (node ids are 1-indexed)"
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Return the 0-based index of the current raft leader, or `None`.
    ///
    /// Checks raft metrics on every node with a live raft instance. The first
    /// node that reports a leader (by node ID) is used; the node ID is then
    /// mapped back to a 0-based cluster index.
    pub fn current_leader_idx(&self) -> Option<usize> {
        for node in &self.nodes {
            if let Some(raft) = &node.raft {
                let metrics = raft.metrics().borrow_watched().clone();
                if let Some(leader_node_id) = metrics.current_leader {
                    // node_id is 1-indexed: node 0 → id 1.
                    let leader_idx = (leader_node_id as usize).saturating_sub(1);
                    return Some(leader_idx);
                }
            }
        }
        None
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        // Local tier: abort all server tasks.
        for node in &mut self.nodes {
            if let Some(task) = node.task.take() {
                task.abort();
            }
        }
        // Smoke tier: fire destroy_server teardown.
        let teardown = Arc::clone(&self.teardown);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    let mut guard = teardown.lock().await;
                    if let Some(f) = guard.take() {
                        f().await;
                    }
                });
            }
            Err(_) => {
                eprintln!(
                    "[yubaba-test-harness] Cluster dropped outside a tokio context; \
                     smoke-tier teardown skipped. Ensure tests run via #[tokio::test]."
                );
            }
        }
    }
}

// ── test_cluster ──────────────────────────────────────────────────────────────

/// Provision a test cluster of `nodes` machines.
///
/// ## Tier routing
///
/// When `YAH_SMOKE=1` is set: provisions real Hetzner machines via `provider`,
/// boots yubaba via cloud-init, waits for each node's `/health`. Requires
/// `HETZNER_API_TOKEN`, `YAH_YUBABA_URL`, `YAH_YUBABA_SHA256` in the
/// environment. Prints a cost estimate before provisioning.
///
/// Otherwise (local tier): starts yubaba in-process on random loopback ports.
/// For `nodes > 1`, bootstraps a real openraft cluster between the nodes.
/// Fast and credential-free.
///
/// ## Auto-teardown
///
/// The returned `Cluster` calls teardown (abort in-process servers, or destroy
/// Hetzner machines) in its `Drop` impl. Call `destroy_all().await` explicitly
/// for teardown with error propagation.
pub async fn test_cluster<P, R>(provider: &P, runtime: R, nodes: usize) -> Result<Cluster>
where
    P: MachineProvider + Clone + Send + Sync + 'static,
    R: kamaji::Kamaji + 'static,
{
    test_cluster_with_policy(provider, runtime, nodes, HARNESS_POLICY).await
}

/// [`test_cluster`], but founding the cluster under an explicit
/// [`ClusterPolicy`] instead of the fleet preset (R118-T1).
///
/// Needed because a policy is not decoration: it sets openraft's election and
/// heartbeat bounds (`RaftTiming`), so a rig's behaviour measured on a cluster
/// running WAN timings is a measurement of the wrong system — failover on the
/// rig preset lands inside a second where the fleet preset takes three. It also
/// decides whether a learner can be promoted at all, which is the entire
/// difference the rig deployment exists to exercise.
///
/// The policy is applied to *every* node in the cluster and is remembered
/// per-node, so `restart_node` brings a node back under the same timings its
/// peers are running.
///
/// **Local tier only for the policy argument.** The smoke tier boots yubaba
/// from a release binary via cloud-init, so its cluster profile is whatever
/// that binary's `--cluster-profile` flag says; passing a policy here does not
/// reach it, and the call falls back to the smoke path unchanged.
pub async fn test_cluster_with_policy<P, R>(
    provider: &P,
    runtime: R,
    nodes: usize,
    policy: ClusterPolicy,
) -> Result<Cluster>
where
    P: MachineProvider + Clone + Send + Sync + 'static,
    R: kamaji::Kamaji + 'static,
{
    if std::env::var("YAH_SMOKE").as_deref() == Ok("1") {
        test_cluster_smoke(provider, nodes).await
    } else {
        let runtime: Arc<dyn kamaji::Kamaji + Send + Sync> = Arc::new(runtime);
        let runtimes = (0..nodes).map(|_| Arc::clone(&runtime)).collect();
        test_cluster_local(runtimes, policy).await
    }
}

/// [`test_cluster_with_policy`], but giving **each node its own supervisor**
/// instead of sharing one across the cluster (R858-T7).
///
/// # Why one shared runtime is not always honest
///
/// Sharing is fine — and is what every other suite does — as long as no
/// assertion turns on *which* node a workload is running on. `raft_appliance_
/// ownership`'s own module doc makes exactly that argument for its restart test:
/// the answer is only consulted on the owner, so a shared registry cannot
/// manufacture a pass.
///
/// It stops being fine the moment the property under test is "**exactly one**
/// node is serving this", which is R858-T7's whole subject. Under one registry
/// the two coordinators a fence exists to prevent are indistinguishable from one
/// — they collapse onto a single entry under a single `MeshIdent` — and, worse,
/// a *correct* fence fails the test: the resurrected node's `teardown_workload`
/// deletes the very instance the new owner just deployed. A harness that turns a
/// correct implementation red is not a strict test, it is a broken one.
///
/// `runtimes.len()` must equal the node count; the cluster is that long.
pub async fn test_cluster_with_runtimes<P>(
    provider: &P,
    runtimes: Vec<Arc<dyn kamaji::Kamaji + Send + Sync>>,
    policy: ClusterPolicy,
) -> Result<Cluster>
where
    P: MachineProvider + Clone + Send + Sync + 'static,
{
    if std::env::var("YAH_SMOKE").as_deref() == Ok("1") {
        let nodes = runtimes.len();
        return test_cluster_smoke(provider, nodes).await;
    }
    test_cluster_local(runtimes, policy).await
}

// ── Local tier ────────────────────────────────────────────────────────────────

/// Start N in-process yubaba servers for the local tier.
///
/// For N=1: single server, no raft (identical to pre-F6 behavior).
/// For N>1: opens a file-backed raft node per server, bootstraps the cluster
/// by calling `raft.initialize(all_members)` on node 0, then waits up to 30s
/// for a leader to be elected.
///
/// Raft messages flow over HTTP between the in-process servers. The raft network
/// uses `BasicNode.addr` = `"127.0.0.1:{port}"` which the `YubabaNetworkFactory`
/// wraps as `"http://127.0.0.1:{port}"`.
async fn test_cluster_local(
    runtimes: Vec<Arc<dyn kamaji::Kamaji + Send + Sync>>,
    policy: ClusterPolicy,
) -> Result<Cluster> {
    let nodes = runtimes.len();
    if nodes == 0 {
        bail!("test_cluster_local: nodes must be >= 1");
    }

    let mut tmp_dirs: Vec<tempfile::TempDir> = Vec::with_capacity(nodes);
    let mut ports: Vec<u16> = Vec::with_capacity(nodes);
    let mut raft_nodes: Vec<Option<yubaba::raft::YubabaRaft>> = Vec::with_capacity(nodes);
    let mut state_machines: Vec<Option<yubaba::raft::YubabaStateMachine>> =
        Vec::with_capacity(nodes);
    let mut listeners: Vec<tokio::net::TcpListener> = Vec::with_capacity(nodes);
    let mut state_paths: Vec<PathBuf> = Vec::with_capacity(nodes);
    let mut raft_dirs: Vec<Option<PathBuf>> = Vec::with_capacity(nodes);

    // Phase 1: allocate ports + dirs, open raft nodes (for N>1).
    for i in 0..nodes {
        let tmp =
            tempfile::TempDir::new().with_context(|| format!("tempdir for yubaba node {i}"))?;

        let state_path = tmp.path().join("identity.json");
        state_paths.push(state_path);

        // Bind listener now so we know the port before wiring raft membership.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .with_context(|| format!("binding listener for node {i}"))?;
        let port = listener.local_addr()?.port();
        ports.push(port);
        listeners.push(listener);

        if nodes > 1 {
            let raft_dir = tmp.path().join("raft");
            std::fs::create_dir_all(&raft_dir)
                .with_context(|| format!("creating raft dir for node {i}"))?;
            let node_id = (i as u64) + 1; // 1-indexed
            let (raft, state_machine) =
                yubaba::raft::open_with_state_machine(node_id, raft_dir.clone(), &policy)
                    .await
                    .with_context(|| format!("opening raft node {node_id}"))?;
            raft_nodes.push(Some(raft));
            state_machines.push(Some(state_machine));
            raft_dirs.push(Some(raft_dir));
        } else {
            raft_nodes.push(None);
            state_machines.push(None);
            raft_dirs.push(None);
        }

        tmp_dirs.push(tmp);
    }

    // Phase 2: start all servers.
    let mut cluster_nodes: Vec<ClusterNode> = Vec::with_capacity(nodes);

    for i in 0..nodes {
        let state_path = state_paths[i].clone();
        let port = ports[i];
        let listener = listeners.remove(0); // consume in order

        let node_id_opt = if nodes > 1 {
            Some((i as u64) + 1)
        } else {
            None
        };

        // Redirect headscale's state dir into this node's tempdir. The default
        // is `/var/lib/yah-cloud/headscale`, which a test must never write to
        // and cannot write to on a dev machine anyway.
        let headscale_dir = tmp_dirs[i].path().join("headscale");
        std::fs::create_dir_all(&headscale_dir)
            .with_context(|| format!("creating headscale dir for node {i}"))?;

        let mut srv_state = yubaba::ServerState::load(state_path.clone())
            .with_context(|| format!("loading yubaba state for node {i}"))?
            .with_runtime(Arc::clone(&runtimes[i]))
            .with_headscale_dir(headscale_dir.clone());

        let mut lease_detector = None;
        let mut rpo_registry = None;
        if let (Some(raft), Some(nid)) = (&raft_nodes[i], node_id_opt) {
            // R737-F2/T5: the same handle goes into `ServerState` (so
            // `POST /mesh/lease-renew` and `GET /raft/status` see it) and into
            // `ClusterNode` (so a test can renew or withhold renewals without
            // an HTTP hop). Both are `Arc`s onto one registry — a test that
            // renews via the handle and a node that renews over HTTP are
            // writing the same map.
            let leases = Arc::new(yubaba::lease_detector::LeaseFailureDetector::new(
                policy.liveness_thresholds(),
            ));
            lease_detector = Some(Arc::clone(&leases));
            // R782: same shape as `leases` above, for the streamer-RPO
            // channel.
            let rpo = Arc::new(yubaba::lease_detector::RpoWatermarkRegistry::new());
            rpo_registry = Some(Arc::clone(&rpo));
            srv_state = srv_state
                .with_cluster_policy(policy)
                .with_raft(raft.clone())
                .with_node_id(nid)
                .with_cluster_state(
                    state_machines[i]
                        .clone()
                        .expect("a raft node always comes with its state machine"),
                )
                .with_failure_detector(Arc::new(RaftHeartbeatDetector::new(
                    raft.clone(),
                    policy.liveness_thresholds(),
                )))
                .with_lease_detector(leases)
                .with_rpo_registry(rpo);
        }

        let state = Arc::new(srv_state);
        let router = yubaba::build_router(Arc::clone(&state));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        cluster_nodes.push(ClusterNode {
            yubaba: WardenHandle::new(format!("http://127.0.0.1:{port}")),
            server_id: ServerId(format!("local-node-{i}")),
            task: Some(task),
            raft: raft_nodes[i].clone(),
            state_machine: state_machines[i].clone(),
            lease_detector,
            rpo_registry,
            raft_dir: raft_dirs[i].clone(),
            port: Some(port),
            node_id: node_id_opt,
            state_path: Some(state_path),
            runtime: Some(Arc::clone(&runtimes[i])),
            policy,
            state: Some(state),
            headscale_dir: Some(headscale_dir),
        });
    }

    // Phase 3: wait for every node's yubaba to report healthy.
    let client = reqwest::Client::new();
    for node in &cluster_nodes {
        let url = format!("{}/health", node.yubaba.base_url);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if tokio::time::Instant::now() > deadline {
                bail!("yubaba at {} did not become healthy within 10s", url);
            }
            let ok = client
                .get(&url)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if ok {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // Phase 4: bootstrap raft cluster for N>1.
    if nodes > 1 {
        // Build membership: node_id (1-indexed) → BasicNode { addr: "127.0.0.1:{port}" }
        let members: BTreeMap<u64, BasicNode> = (0..nodes)
            .map(|i| {
                let node_id = (i as u64) + 1;
                let addr = format!("127.0.0.1:{}", ports[i]);
                (node_id, BasicNode { addr })
            })
            .collect();

        // Initialize cluster from node 0's raft. The openraft `initialize()`
        // call creates an initial membership log entry and starts the election.
        // Other nodes receive membership via AppendEntries from the leader.
        let leader_raft = cluster_nodes[0]
            .raft
            .as_ref()
            .expect("node 0 must have a raft for multi-node bootstrap");
        leader_raft
            .initialize(members)
            .await
            .context("raft cluster bootstrap: initialize() on node 0")?;

        // Wait for leader election (up to 15s: election_timeout_max=3s + margin).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        'election: loop {
            if tokio::time::Instant::now() > deadline {
                bail!("raft leader election timed out after 15s during cluster bootstrap");
            }
            for node in &cluster_nodes {
                if let Some(raft) = &node.raft {
                    if raft.metrics().borrow_watched().current_leader.is_some() {
                        break 'election;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    Ok(Cluster {
        nodes: cluster_nodes,
        teardown: Arc::new(tokio::sync::Mutex::new(None)), // local tier: no smoke teardown
        _tmp_dirs: tmp_dirs,
    })
}

// ── Smoke tier ────────────────────────────────────────────────────────────────

/// Provision real Hetzner machines for the smoke tier.
///
/// Required env vars: `HETZNER_API_TOKEN`, `YAH_YUBABA_URL`,
/// `YAH_YUBABA_SHA256`. Missing any of them causes an immediate error.
/// Cost estimate is printed before provisioning.
async fn test_cluster_smoke<P>(provider: &P, nodes: usize) -> Result<Cluster>
where
    P: MachineProvider + Clone + Send + Sync + 'static,
{
    // Gate: all required secrets must be present before we spend money.
    let yubaba_url = std::env::var("YAH_YUBABA_URL")
        .context("YAH_YUBABA_URL required for smoke tier (URL to the yubaba binary)")?;
    let yubaba_sha256 = std::env::var("YAH_YUBABA_SHA256")
        .context("YAH_YUBABA_SHA256 required for smoke tier (SHA256 of yubaba binary)")?;

    // Print cost estimate before spinning anything.
    eprintln!(
        "[test-harness/smoke] COST ESTIMATE: will provision {nodes} Hetzner CPX-11 server(s) \
         for ~5 min (est. ${:.2} total). Ctrl-C within 5s to abort.",
        nodes as f64 * 0.05,
    );
    tokio::time::sleep(Duration::from_secs(5)).await;

    let project = provider
        .ensure_project("yah-smoke-test")
        .await
        .context("ensure_project")?;

    let mut cluster_nodes: Vec<ClusterNode> = Vec::with_capacity(nodes);
    let mut server_ids = Vec::with_capacity(nodes);
    let provider_arc = Arc::new(provider.clone());

    for i in 0..nodes {
        let name = format!("yah-smoke-{}-n{i}", std::process::id());

        let user_data = build_smoke_cloud_init(&yubaba_url, &yubaba_sha256, &name);
        let spec = cloud::provider::ServerSpec {
            name: name.clone(),
            server_type: "cpx11".into(),
            image: "debian-12".into(),
            location: cloud::provider::Location::Fsn,
            ssh_keys: vec![],
        };

        let server_id = provider
            .create_server(&project, &spec, &user_data)
            .await
            .with_context(|| format!("create_server node {i}"))?;
        server_ids.push(server_id.clone());

        // Wait for the machine to have a public IP and yubaba to be reachable.
        let ip = wait_for_server_ip(provider, &name)
            .await
            .with_context(|| format!("waiting for IP on node {i}"))?;
        let base_url = format!("http://{ip}:7443");

        wait_for_yubaba_health(&base_url)
            .await
            .with_context(|| format!("waiting for yubaba health on node {i}"))?;

        cluster_nodes.push(ClusterNode {
            yubaba: WardenHandle::new(base_url),
            server_id,
            task: None,
            raft: None,
            state_machine: None,
            // Smoke-tier nodes hold their lease registry inside their own
            // process; there is no in-process handle to reach it from here.
            lease_detector: None,
            // Same reasoning as `lease_detector` above.
            rpo_registry: None,
            raft_dir: None,
            port: None,
            node_id: None,
            state_path: None,
            runtime: None,
            // Smoke-tier nodes run a release binary whose profile came from its
            // own `--cluster-profile` flag; this field is only read by
            // `restart_node`, which is local-tier-only.
            policy: HARNESS_POLICY,
            // Both live in the smoke node's own process, out of reach from here
            // — same reasoning as `runtime` and `state_path` above.
            state: None,
            headscale_dir: None,
        });
    }

    let teardown_provider = Arc::clone(&provider_arc);
    let teardown_ids = server_ids;
    let teardown: TeardownFn = Box::new(move || {
        Box::pin(async move {
            eprintln!(
                "[test-harness/smoke] AUTO-TEARDOWN: destroying {} server(s)",
                teardown_ids.len()
            );
            for id in teardown_ids {
                if let Err(e) = teardown_provider.destroy_server(&id).await {
                    eprintln!("[test-harness/smoke] destroy_server {}: {e}", id.0);
                } else {
                    eprintln!("[test-harness/smoke] destroyed server {}", id.0);
                }
            }
        })
    });

    Ok(Cluster {
        nodes: cluster_nodes,
        teardown: Arc::new(tokio::sync::Mutex::new(Some(teardown))),
        _tmp_dirs: vec![],
    })
}

/// Build a minimal cloud-init user_data string that downloads and starts yubaba.
fn build_smoke_cloud_init(yubaba_url: &str, yubaba_sha256: &str, name: &str) -> String {
    format!(
        "#cloud-config\n\
         hostname: {name}\n\
         packages:\n\
           - curl\n\
         runcmd:\n\
           - ['sh', '-c', 'curl -fsSL {yubaba_url} -o /usr/local/bin/yah-yubaba && \
              echo \"{yubaba_sha256}  /usr/local/bin/yah-yubaba\" | sha256sum -c && \
              chmod +x /usr/local/bin/yah-yubaba']\n\
           - ['sh', '-c', 'nohup /usr/local/bin/yah-yubaba serve --bind 0.0.0.0:7443 \
              > /var/log/yah-yubaba.log 2>&1 &']\n"
    )
}

/// Poll `find_server_by_name` until the machine has a public IPv4 address.
async fn wait_for_server_ip<P: MachineProvider>(provider: &P, name: &str) -> Result<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if tokio::time::Instant::now() > deadline {
            bail!("timed out waiting for server {name} to have a public IP");
        }
        if let Ok(Some(summary)) = provider.find_server_by_name(name).await {
            if let Some(ip) = summary.public_ipv4 {
                return Ok(ip);
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Poll `GET /health` until it returns 200 or the deadline expires.
async fn wait_for_yubaba_health(base_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{base_url}/health");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    loop {
        if tokio::time::Instant::now() > deadline {
            bail!("yubaba at {url} did not become healthy within 180s");
        }
        let ok = client
            .get(&url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if ok {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// ── wait_for_state ────────────────────────────────────────────────────────────

/// Poll a yubaba node until the named workload reaches `expected`.
///
/// Returns `Ok(status)` when the status matches, or `Err` if `timeout` elapses.
/// Uses 500ms polling intervals.
pub async fn wait_for_state(
    yubaba: &WardenHandle,
    ident: &MeshIdent,
    expected: WorkloadStatus,
    timeout: std::time::Duration,
) -> Result<WorkloadStatus> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            bail!(
                "wait_for_state: timeout waiting for {} to reach {:?}",
                ident.0,
                expected,
            );
        }
        match yubaba.get_workload_state(ident).await? {
            Some(s) if s == expected => return Ok(s),
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
}
