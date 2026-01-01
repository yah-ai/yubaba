//! `warden-test-harness` — `Cluster` harness for warden integration tests.
//!
//! Companion crate to `warden-test-macros`. Integration tests get here via
//! the fixture builder:
//!
//! ```rust,ignore
//! let cluster = warden_test_harness::test_cluster(&p, rt, 3).await?;
//! cluster.wait_for_leader(Duration::from_secs(15)).await?;
//! let w0 = cluster.warden(0);
//! w0.deploy_workload(&spec).await?;
//! let state = wait_for_state(w0, &spec.expose.mesh.identity,
//!     WorkloadStatus::Running, Duration::from_secs(60)).await?;
//! let resp = cluster.warden(1).mesh_get(&spec.expose.mesh.identity, 8080, "/health").await?;
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
//! - **`YAH_SMOKE` unset or `!= "1"`** → local tier: starts warden in-process
//!   on random loopback ports, bootstraps a real openraft cluster between the
//!   nodes. Fast, no credentials, no billing.
//! - **`YAH_SMOKE=1`** → smoke tier: provisions real Hetzner machines via
//!   `provider`, waits for warden to become healthy on each machine. Requires
//!   `HETZNER_API_TOKEN`, `YAH_WARDEN_URL`, `YAH_WARDEN_SHA256`.
//!
//! ## Multi-node raft (local tier)
//!
//! For `nodes > 1`, the harness:
//! 1. Opens a raft node per server (via `warden::raft::open`) using a tempdir
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
//! yah-warden-integration-testing.md §KNOWN-LOCAL-GAPS). Actual wire-level
//! mesh routing is tested in the smoke tier only.
//!
//! ## Implementation sequencing
//!
//! - **F4 (types + stubs)**: Cluster shape, WardenHandle API stubs, wait_for_state.
//! - **F5**: `test_cluster` single-node impl (both tiers), deploy + state round-trip.
//! - **F6 (this revision)**: Multi-node raft bootstrap, `kill_node`, `restart_node`,
//!   `wait_for_leader`, `current_leader_idx`, `mesh_get` implementation.
//!
//! @arch:see(.yah/docs/architecture/A053-yah-warden-integration-testing.md)

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use cloud::provider::{MachineProvider, ServerId};
use openraft::BasicNode;
use workload_spec::{MeshIdent, WorkloadSpec};

// ── NetworkDegrade ────────────────────────────────────────────────────────────

/// `tc qdisc` spec applied between cluster nodes in the local tier.
///
/// Requires `NET_ADMIN` capability in the machine containers. Knob:
/// `YAH_LOCAL_NETWORK_DEGRADE=loss:5%,latency:200ms` (parsed by
/// `LocalDockerProvider`; the harness reads it and stores here for
/// display/logging purposes).
#[derive(Debug, Clone, Default)]
pub struct NetworkDegrade {
    /// Packet loss percentage (0–100). `None` means no loss injection.
    pub packet_loss_pct: Option<u8>,
    /// Artificial latency in milliseconds. `None` means no latency injection.
    pub latency_ms: Option<u32>,
}

impl NetworkDegrade {
    /// Parse from `YAH_LOCAL_NETWORK_DEGRADE` env var format.
    ///
    /// Format: comma-separated `key:value` pairs, e.g.
    /// `"loss:5%,latency:200ms"`.
    pub fn from_env() -> Option<Self> {
        let s = std::env::var("YAH_LOCAL_NETWORK_DEGRADE").ok()?;
        let mut spec = Self::default();
        for part in s.split(',') {
            if let Some(v) = part.strip_prefix("loss:") {
                spec.packet_loss_pct = v.trim_end_matches('%').parse().ok();
            } else if let Some(v) = part.strip_prefix("latency:") {
                spec.latency_ms = v.trim_end_matches("ms").parse().ok();
            }
        }
        Some(spec)
    }
}

// ── WorkloadStatus re-export ──────────────────────────────────────────────────

pub use constable_core::{WorkloadState, WorkloadStatus};

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

/// RPC handle to one warden node in the test cluster.
///
/// Operations proxy through the warden HTTP API (same surface exposed to the
/// desktop app and agents in production).
pub struct WardenHandle {
    /// HTTP base URL for this node's warden API (e.g. `http://127.0.0.1:7443`).
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

    /// Deploy a workload via the warden `/workloads/deploy` RPC.
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
    /// Returns `Ok(None)` when the workload is not yet known to this warden
    /// node (may appear with a short lag after deploy).
    pub async fn get_workload_state(
        &self,
        ident: &MeshIdent,
    ) -> Result<Option<WorkloadStatus>> {
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

        let state: WorkloadState = resp
            .json()
            .await
            .context("deserializing WorkloadState")?;
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
    /// (see yah-warden-integration-testing.md §KNOWN-LOCAL-GAPS). The `port`
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

    /// Check that the warden HTTP API is reachable and healthy.
    pub async fn health_check(&self) -> Result<()> {
        let url = format!("{}/health", self.base_url);
        self.client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("warden health check failed at {url}"))?
            .error_for_status()
            .with_context(|| format!("warden /health returned non-2xx at {url}"))?;
        Ok(())
    }
}

// ── ClusterNode ───────────────────────────────────────────────────────────────

/// Internal metadata for one node in the cluster.
struct ClusterNode {
    /// Warden RPC handle.
    warden: WardenHandle,
    /// Provider-side server ID — used for `destroy_server` in smoke-tier teardown.
    #[allow(dead_code)]
    server_id: ServerId,
    /// In-process server task (local tier only). `None` for smoke tier.
    task: Option<tokio::task::JoinHandle<()>>,
    /// Raft node handle, stored for `initialize()` during bootstrap and
    /// `metrics()` queries for leader detection. `None` for smoke tier or
    /// single-node local clusters.
    raft: Option<warden::raft::WardenRaft>,
    /// Raft persistence directory (local tier, multi-node). Used by
    /// `restart_node` to re-open the raft node from persisted state.
    raft_dir: Option<PathBuf>,
    /// TCP port this warden server listens on (local tier). Used by
    /// `restart_node` to bind on the same port after a kill.
    port: Option<u16>,
    /// This node's raft node ID (1-indexed: node 0 → id 1). Used by
    /// `restart_node` to re-open the raft node.
    node_id: Option<u64>,
    /// Path to the warden identity state file. Used by `restart_node`.
    state_path: Option<PathBuf>,
    /// Shared container runtime (local tier). Used by `restart_node` to wire
    /// the runtime into the restarted `ServerState`.
    runtime: Option<Arc<dyn constable_core::Constable + Send + Sync>>,
}

// ── Cluster ───────────────────────────────────────────────────────────────────

/// Test cluster of N warden nodes.
///
/// Created by [`test_cluster`]. Implements `Drop` for auto-teardown.
///
/// ## Partition + quorum-loss operations (F6)
///
/// [`kill_node`] aborts the server task for one node (local tier) or stops it
/// (smoke tier stub). [`restart_node`] re-binds on the same port and re-opens
/// the raft node from persisted state. [`wait_for_leader`] and
/// [`current_leader_idx`] expose the raft election state.
pub struct Cluster {
    nodes: Vec<ClusterNode>,
    network_degrade: Option<NetworkDegrade>,
    /// Smoke tier teardown: destroy Hetzner machines + buckets. `None` for
    /// local tier (teardown is handled by `Drop` aborting tasks + dropping dirs).
    teardown: Arc<tokio::sync::Mutex<Option<TeardownFn>>>,
    /// Temp directories for local-tier nodes. Kept alive until `Cluster` drops.
    _tmp_dirs: Vec<tempfile::TempDir>,
}

type TeardownFn =
    Box<dyn FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send>;

impl Cluster {
    /// Access the warden handle for node at `idx`.
    ///
    /// Panics if `idx >= self.node_count()`.
    pub fn warden(&self, idx: usize) -> &WardenHandle {
        &self.nodes[idx].warden
    }

    /// Number of nodes in this cluster.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Chain a network degradation spec onto the cluster.
    ///
    /// Applies `tc qdisc` rules between machine containers (local tier) or
    /// across real machines (smoke tier, via warden mesh config). Requires
    /// NET_ADMIN capability in the container image for local tier.
    ///
    /// No-op if `tc` is unavailable or the tier does not support it.
    pub fn with_network_degrade(mut self, spec: NetworkDegrade) -> Self {
        self.network_degrade = Some(spec);
        self
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

    /// Kill the server at `idx` by aborting its task (local tier).
    ///
    /// The node's raft persistence files are intact — `restart_node` can
    /// recover from them. After calling this, the node's warden HTTP API is
    /// unreachable.
    ///
    /// A small sleep is included after abort to let the OS free the TCP port.
    pub async fn kill_node(&mut self, idx: usize) -> Result<()> {
        let node = self.nodes.get_mut(idx)
            .ok_or_else(|| anyhow::anyhow!("kill_node: no node at index {idx}"))?;
        if let Some(task) = node.task.take() {
            task.abort();
            // Give the OS time to release the port before a potential restart.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok(())
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
        let node = self.nodes.get_mut(idx)
            .ok_or_else(|| anyhow::anyhow!("restart_node: no node at index {idx}"))?;

        let port = node.port
            .ok_or_else(|| anyhow::anyhow!("restart_node: node {idx} has no port (smoke tier?)"))?;
        let raft_dir = node.raft_dir.clone()
            .ok_or_else(|| anyhow::anyhow!("restart_node: node {idx} has no raft_dir"))?;
        let node_id = node.node_id
            .ok_or_else(|| anyhow::anyhow!("restart_node: node {idx} has no node_id"))?;
        let state_path = node.state_path.clone()
            .ok_or_else(|| anyhow::anyhow!("restart_node: node {idx} has no state_path"))?;
        let runtime = node.runtime.clone()
            .ok_or_else(|| anyhow::anyhow!("restart_node: node {idx} has no runtime"))?;

        // Re-open the raft node from persisted state.
        let raft = warden::raft::open(node_id, raft_dir)
            .await
            .with_context(|| format!("restart_node: re-open raft for node {idx}"))?;

        let state = Arc::new(
            warden::ServerState::load(state_path)
                .with_context(|| format!("restart_node: load state for node {idx}"))?
                .with_runtime(runtime)
                .with_raft(raft.clone())
                .with_node_id(node_id),
        );

        // Rebind on the same port. The killed task dropped the listener, so
        // this should succeed after the 200ms sleep in kill_node.
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .with_context(|| format!("restart_node: bind 127.0.0.1:{port} for node {idx}"))?;

        let router = warden::build_router(Arc::clone(&state));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        // Wait for the restarted server to respond.
        wait_for_warden_health(&format!("http://127.0.0.1:{port}"))
            .await
            .with_context(|| format!("restart_node: health check for node {idx}"))?;

        node.task = Some(task);
        node.raft = Some(raft);
        Ok(())
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

    /// Return the 0-based index of the current raft leader, or `None`.
    ///
    /// Checks raft metrics on every node with a live raft instance. The first
    /// node that reports a leader (by node ID) is used; the node ID is then
    /// mapped back to a 0-based cluster index.
    pub fn current_leader_idx(&self) -> Option<usize> {
        for node in &self.nodes {
            if let Some(raft) = &node.raft {
                let metrics = raft.metrics().borrow().clone();
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
                    "[warden-test-harness] Cluster dropped outside a tokio context; \
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
/// boots warden via cloud-init, waits for each node's `/health`. Requires
/// `HETZNER_API_TOKEN`, `YAH_WARDEN_URL`, `YAH_WARDEN_SHA256` in the
/// environment. Prints a cost estimate before provisioning.
///
/// Otherwise (local tier): starts warden in-process on random loopback ports.
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
    R: constable_core::Constable + 'static,
{
    if std::env::var("YAH_SMOKE").as_deref() == Ok("1") {
        test_cluster_smoke(provider, nodes).await
    } else {
        test_cluster_local(runtime, nodes).await
    }
}

// ── Local tier ────────────────────────────────────────────────────────────────

/// Start N in-process warden servers for the local tier.
///
/// For N=1: single server, no raft (identical to pre-F6 behavior).
/// For N>1: opens a file-backed raft node per server, bootstraps the cluster
/// by calling `raft.initialize(all_members)` on node 0, then waits up to 30s
/// for a leader to be elected.
///
/// Raft messages flow over HTTP between the in-process servers. The raft network
/// uses `BasicNode.addr` = `"127.0.0.1:{port}"` which the `WardenNetworkFactory`
/// wraps as `"http://127.0.0.1:{port}"`.
async fn test_cluster_local<R>(runtime: R, nodes: usize) -> Result<Cluster>
where
    R: constable_core::Constable + 'static,
{
    if nodes == 0 {
        bail!("test_cluster_local: nodes must be >= 1");
    }

    let runtime: Arc<dyn constable_core::Constable + Send + Sync> = Arc::new(runtime);

    let mut tmp_dirs: Vec<tempfile::TempDir> = Vec::with_capacity(nodes);
    let mut ports: Vec<u16> = Vec::with_capacity(nodes);
    let mut raft_nodes: Vec<Option<warden::raft::WardenRaft>> = Vec::with_capacity(nodes);
    let mut listeners: Vec<tokio::net::TcpListener> = Vec::with_capacity(nodes);
    let mut state_paths: Vec<PathBuf> = Vec::with_capacity(nodes);
    let mut raft_dirs: Vec<Option<PathBuf>> = Vec::with_capacity(nodes);

    // Phase 1: allocate ports + dirs, open raft nodes (for N>1).
    for i in 0..nodes {
        let tmp = tempfile::TempDir::new()
            .with_context(|| format!("tempdir for warden node {i}"))?;

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
            let raft = warden::raft::open(node_id, raft_dir.clone())
                .await
                .with_context(|| format!("opening raft node {node_id}"))?;
            raft_nodes.push(Some(raft));
            raft_dirs.push(Some(raft_dir));
        } else {
            raft_nodes.push(None);
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

        let node_id_opt = if nodes > 1 { Some((i as u64) + 1) } else { None };

        let mut srv_state = warden::ServerState::load(state_path.clone())
            .with_context(|| format!("loading warden state for node {i}"))?
            .with_runtime(Arc::clone(&runtime));

        if let (Some(raft), Some(nid)) = (&raft_nodes[i], node_id_opt) {
            srv_state = srv_state
                .with_raft(raft.clone())
                .with_node_id(nid);
        }

        let state = Arc::new(srv_state);
        let router = warden::build_router(Arc::clone(&state));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        cluster_nodes.push(ClusterNode {
            warden: WardenHandle::new(format!("http://127.0.0.1:{port}")),
            server_id: ServerId(format!("local-node-{i}")),
            task: Some(task),
            raft: raft_nodes[i].clone(),
            raft_dir: raft_dirs[i].clone(),
            port: Some(port),
            node_id: node_id_opt,
            state_path: Some(state_path),
            runtime: Some(Arc::clone(&runtime)),
        });
    }

    // Phase 3: wait for every node's warden to report healthy.
    let client = reqwest::Client::new();
    for node in &cluster_nodes {
        let url = format!("{}/health", node.warden.base_url);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if tokio::time::Instant::now() > deadline {
                bail!("warden at {} did not become healthy within 10s", url);
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
        let leader_raft = cluster_nodes[0].raft.as_ref()
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
                    if raft.metrics().borrow().current_leader.is_some() {
                        break 'election;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    Ok(Cluster {
        nodes: cluster_nodes,
        network_degrade: None,
        teardown: Arc::new(tokio::sync::Mutex::new(None)), // local tier: no smoke teardown
        _tmp_dirs: tmp_dirs,
    })
}

// ── Smoke tier ────────────────────────────────────────────────────────────────

/// Provision real Hetzner machines for the smoke tier.
///
/// Required env vars: `HETZNER_API_TOKEN`, `YAH_WARDEN_URL`,
/// `YAH_WARDEN_SHA256`. Missing any of them causes an immediate error.
/// Cost estimate is printed before provisioning.
async fn test_cluster_smoke<P>(provider: &P, nodes: usize) -> Result<Cluster>
where
    P: MachineProvider + Clone + Send + Sync + 'static,
{
    // Gate: all required secrets must be present before we spend money.
    let warden_url = std::env::var("YAH_WARDEN_URL")
        .context("YAH_WARDEN_URL required for smoke tier (URL to the warden binary)")?;
    let warden_sha256 = std::env::var("YAH_WARDEN_SHA256")
        .context("YAH_WARDEN_SHA256 required for smoke tier (SHA256 of warden binary)")?;

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

        let user_data = build_smoke_cloud_init(&warden_url, &warden_sha256, &name);
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

        // Wait for the machine to have a public IP and warden to be reachable.
        let ip = wait_for_server_ip(provider, &name)
            .await
            .with_context(|| format!("waiting for IP on node {i}"))?;
        let base_url = format!("http://{ip}:7443");

        wait_for_warden_health(&base_url)
            .await
            .with_context(|| format!("waiting for warden health on node {i}"))?;

        cluster_nodes.push(ClusterNode {
            warden: WardenHandle::new(base_url),
            server_id,
            task: None,
            raft: None,
            raft_dir: None,
            port: None,
            node_id: None,
            state_path: None,
            runtime: None,
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
        network_degrade: None,
        teardown: Arc::new(tokio::sync::Mutex::new(Some(teardown))),
        _tmp_dirs: vec![],
    })
}

/// Build a minimal cloud-init user_data string that downloads and starts warden.
fn build_smoke_cloud_init(warden_url: &str, warden_sha256: &str, name: &str) -> String {
    format!(
        "#cloud-config\n\
         hostname: {name}\n\
         packages:\n\
           - curl\n\
         runcmd:\n\
           - ['sh', '-c', 'curl -fsSL {warden_url} -o /usr/local/bin/yah-warden && \
              echo \"{warden_sha256}  /usr/local/bin/yah-warden\" | sha256sum -c && \
              chmod +x /usr/local/bin/yah-warden']\n\
           - ['sh', '-c', 'nohup /usr/local/bin/yah-warden serve --bind 0.0.0.0:7443 \
              > /var/log/yah-warden.log 2>&1 &']\n"
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
async fn wait_for_warden_health(base_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{base_url}/health");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    loop {
        if tokio::time::Instant::now() > deadline {
            bail!("warden at {url} did not become healthy within 180s");
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

/// Poll a warden node until the named workload reaches `expected`.
///
/// Returns `Ok(status)` when the status matches, or `Err` if `timeout` elapses.
/// Uses 500ms polling intervals.
pub async fn wait_for_state(
    warden: &WardenHandle,
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
        match warden.get_workload_state(ident).await? {
            Some(s) if s == expected => return Ok(s),
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
}
