//! `runtime::containerd` — production `ContainerRuntime` impl via the
//! `containerd-client` gRPC crate.
//!
//! ## Gating
//!
//! This file compiles only under `--features containerd-integration` so the
//! release binary does not carry the containerd gRPC client stack when it
//! ships (the binary is curl-fetched from GitHub at boot per the 32KiB
//! user-data cap constraint).
//!
//! ## Log files
//!
//! Container stdout/stderr are redirected to files under
//! `/var/log/yah/<namespace>/<container_id>/`. `stream_logs` tails those
//! files with tokio async I/O. This matches containerd's standard logging
//! path when no external log driver is configured.
//!
//! ## WireGuard (stub in F1)
//!
//! `deploy_workload` accepts a `MeshAssignment` but only uses the `mesh_ip`
//! field in F1. Full WireGuard netns setup (creating a `wg0` interface inside
//! the container netns) lands with the mesh module in R091-F6.
//!
// Original ticket R091-F1 (status:review) lives in yubaba/src/runtime/mod.rs
// — moved with the file but the @yah: annotation stays at the original source
// so the board doesn't see a duplicate (one annotation per ID, R484-T2).

#![cfg(feature = "containerd-integration")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use containerd_client::{
    services::v1::{
        containers_client::ContainersClient,
        content_client::ContentClient,
        images_client::ImagesClient,
        snapshots::{
            snapshots_client::SnapshotsClient, MountsRequest, PrepareSnapshotRequest,
            RemoveSnapshotRequest,
        },
        tasks_client::TasksClient,
        version_client::VersionClient,
        Container, CreateContainerRequest, CreateTaskRequest, DeleteContainerRequest,
        DeleteTaskRequest, GetContainerRequest, GetImageRequest, KillRequest,
        ListContainersRequest, ReadContentRequest, StartRequest,
    },
    tonic,
    with_namespace,
};
// `with_namespace!` expands to `Request::new(...)` — needs a bare `Request` in scope.
use containerd_client::tonic::Request;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_stream::wrappers::LinesStream;
use tokio_stream::StreamExt as TokioStreamExt;
use workload_spec::{MeshIdent, WorkloadSpec};

use crate::{
    Backend, Kamaji, DeployResult, LogEvent, LogOpts, LogStream, LogStreamKind, MeshAssignment,
    RuntimeHealth, WorkloadState, WorkloadStatus,
};

/// Default containerd socket path (Linux production + Colima on macOS).
pub const DEFAULT_SOCKET: &str = "/run/containerd/containerd.sock";

/// Containerd namespace for all yah-managed workloads.
///
/// Containerd's namespace model provides tenant isolation without a separate
/// daemon. All yah containers live in the `"yah"` namespace; other
/// orchestrators (k3s, Rancher, etc.) use their own namespaces and cannot see
/// yah containers.
pub const YAH_NAMESPACE: &str = "yah";

/// Directory prefix for container log files.
///
/// Structure: `<LOG_BASE>/<namespace>/<container_id>/`
///   - `stdout.log` — container stdout
///   - `stderr.log` — container stderr
pub const LOG_BASE: &str = "/var/log/yah";

// ── ContainerdRuntime ─────────────────────────────────────────────────────────

/// Production `ContainerRuntime` that speaks to containerd over its Unix
/// domain socket via gRPC.
///
/// Acquire one via `ContainerdRuntime::connect` or
/// `ContainerdRuntime::connect_at`. Cheaply cloneable — the inner `Channel`
/// is `Arc`-wrapped.
#[derive(Clone)]
pub struct ContainerdRuntime {
    channel: tonic::transport::Channel,
    namespace: String,
    log_base: PathBuf,
    /// Per-container restart bookkeeping (R471-T2). Containerd has no native
    /// restart-count or "currently restarting" signal — its Status enum is
    /// {Unknown, Created, Running, Stopped, Paused, Pausing}. The supervisor
    /// records each exit + relaunch cycle here so `list_workloads` /
    /// `get_workload` can synthesize `WorkloadStatus::Restarting`.
    ledger: RestartLedger,
}

/// One container's restart history.
///
/// Maintained by the yubaba supervisor (workload-spec.rs:1186 `RestartPolicy`
/// applier) which calls [`RestartLedger::record_exit`] when a task exits with
/// a non-zero code AND the policy still has budget, and
/// [`RestartLedger::mark_running`] once the replacement task is up. The
/// runtime read path consults the ledger to populate
/// `WorkloadStatus::Restarting`.
#[derive(Debug, Clone, Copy)]
pub struct RestartRecord {
    pub last_exit_code: i32,
    pub restart_count: u32,
    pub last_finished_at: SystemTime,
    /// `true` between `record_exit` and the next `mark_running` — i.e. while
    /// the supervisor's recreate cycle is in flight.
    pub in_flight: bool,
}

/// Shared, lock-protected map of container ID → `RestartRecord`.
///
/// `Clone` is a cheap pointer-clone (Arc).
#[derive(Clone, Default)]
pub struct RestartLedger {
    inner: Arc<Mutex<HashMap<String, RestartRecord>>>,
}

impl RestartLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bump the restart count and arm the in-flight bit. Called by the
    /// supervisor immediately after observing a non-zero task exit, *before*
    /// recreating the task.
    pub fn record_exit(&self, container_id: &str, exit_code: i32) {
        let mut g = self.inner.lock().unwrap();
        let now = SystemTime::now();
        g.entry(container_id.to_string())
            .and_modify(|r| {
                r.last_exit_code = exit_code;
                r.restart_count = r.restart_count.saturating_add(1);
                r.last_finished_at = now;
                r.in_flight = true;
            })
            .or_insert(RestartRecord {
                last_exit_code: exit_code,
                restart_count: 1,
                last_finished_at: now,
                in_flight: true,
            });
    }

    /// Clear the in-flight bit. Called once the replacement task is started.
    /// Preserves `restart_count` so the next exit increments correctly.
    pub fn mark_running(&self, container_id: &str) {
        let mut g = self.inner.lock().unwrap();
        if let Some(r) = g.get_mut(container_id) {
            r.in_flight = false;
        }
    }

    /// Drop the record entirely — e.g. on successful teardown.
    pub fn forget(&self, container_id: &str) {
        let mut g = self.inner.lock().unwrap();
        g.remove(container_id);
    }

    /// Snapshot lookup. `None` if the container has never crashed.
    pub fn get(&self, container_id: &str) -> Option<RestartRecord> {
        self.inner.lock().unwrap().get(container_id).copied()
    }
}

/// Translate a base `WorkloadStatus` + ledger record into a final status.
///
/// Only Stopped/Failed states upgrade to Restarting (a running container
/// trivially isn't restarting). `in_flight=false` records stay as the base
/// status — the crash-loop is paused/over.
fn apply_ledger(base: WorkloadStatus, rec: Option<RestartRecord>) -> WorkloadStatus {
    let rec = match rec {
        Some(r) if r.in_flight && r.restart_count > 0 => r,
        _ => return base,
    };
    match base {
        WorkloadStatus::Stopped | WorkloadStatus::Failed { .. } => {
            let last_finished_at_unix_ms = rec
                .last_finished_at
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            WorkloadStatus::Restarting {
                last_exit_code: rec.last_exit_code,
                restart_count: rec.restart_count,
                last_finished_at_unix_ms,
            }
        }
        other => other,
    }
}

/// Compute the OCI rootfs chainID from a layer set's `diff_ids`, matching
/// containerd's `identity.ChainID`: fold sha256 over `"{prev} {next}"` of the
/// full `sha256:...` digest strings. The committed snapshot of an unpacked
/// image is keyed by this chainID — it's the `parent` for the active snapshot
/// a task runs on.
#[cfg(feature = "containerd-integration")]
fn chain_id(diff_ids: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut iter = diff_ids.iter();
    let mut chain = match iter.next() {
        Some(first) => first.clone(),
        None => return String::new(),
    };
    for next in iter {
        let mut hasher = Sha256::new();
        hasher.update(format!("{chain} {next}").as_bytes());
        chain = format!("sha256:{:x}", hasher.finalize());
    }
    chain
}

impl ContainerdRuntime {
    /// Connect to the default containerd socket (`/run/containerd/containerd.sock`).
    pub async fn connect() -> Result<Self> {
        Self::connect_at(DEFAULT_SOCKET).await
    }

    /// Connect to a containerd socket at the given path.
    ///
    /// On macOS with Colima, the socket is typically at
    /// `~/.colima/default/containerd.sock`.
    pub async fn connect_at(socket: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = socket.as_ref().to_path_buf();
        let channel = containerd_client::connect(&path)
            .await
            .with_context(|| format!("connecting to containerd socket {}", path.display()))?;
        Ok(ContainerdRuntime {
            channel,
            namespace: YAH_NAMESPACE.to_string(),
            log_base: PathBuf::from(LOG_BASE),
            ledger: RestartLedger::new(),
        })
    }

    /// Borrow the restart ledger so the yubaba supervisor can record exits.
    pub fn ledger(&self) -> &RestartLedger {
        &self.ledger
    }

    /// Override the containerd namespace (useful in tests).
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = ns.into();
        self
    }

    /// Override the log base directory (useful in tests).
    pub fn with_log_base(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_base = path.into();
        self
    }

    fn containers_client(&self) -> ContainersClient<tonic::transport::Channel> {
        ContainersClient::new(self.channel.clone())
    }

    fn tasks_client(&self) -> TasksClient<tonic::transport::Channel> {
        TasksClient::new(self.channel.clone())
    }

    fn images_client(&self) -> ImagesClient<tonic::transport::Channel> {
        ImagesClient::new(self.channel.clone())
    }

    fn version_client(&self) -> VersionClient<tonic::transport::Channel> {
        VersionClient::new(self.channel.clone())
    }

    fn content_client(&self) -> ContentClient<tonic::transport::Channel> {
        ContentClient::new(self.channel.clone())
    }

    fn snapshots_client(&self) -> SnapshotsClient<tonic::transport::Channel> {
        SnapshotsClient::new(self.channel.clone())
    }

    /// Read a content-store blob fully into memory by digest.
    async fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let req = ReadContentRequest {
            digest: digest.to_string(),
            offset: 0,
            size: 0,
        };
        let req = with_namespace!(req, self.namespace);
        let mut stream = self
            .content_client()
            .read(req)
            .await
            .with_context(|| format!("reading content blob {digest}"))?
            .into_inner();
        let mut buf = Vec::new();
        while let Some(chunk) = stream.message().await? {
            buf.extend_from_slice(&chunk.data);
        }
        Ok(buf)
    }

    /// Resolve an image's rootfs `diff_ids` by walking
    /// (optional index →) manifest → config in the content store. Handles
    /// both single-platform manifests and multi-platform indexes (picks the
    /// linux/amd64 entry — the only platform we run on the cloud tier today).
    async fn image_diff_ids(&self, target_digest: &str) -> Result<Vec<String>> {
        let blob = self.read_blob(target_digest).await?;
        let doc: serde_json::Value = serde_json::from_slice(&blob)
            .with_context(|| format!("parsing image target {target_digest} as JSON"))?;

        // Index / manifest-list → pick the linux/amd64 manifest, then recurse.
        if let Some(manifests) = doc.get("manifests").and_then(|m| m.as_array()) {
            let pick = manifests
                .iter()
                .find(|m| {
                    let p = m.get("platform");
                    let arch = p.and_then(|p| p.get("architecture")).and_then(|a| a.as_str());
                    let os = p.and_then(|p| p.get("os")).and_then(|o| o.as_str());
                    arch == Some("amd64") && os == Some("linux")
                })
                .or_else(|| manifests.first())
                .and_then(|m| m.get("digest"))
                .and_then(|d| d.as_str())
                .ok_or_else(|| anyhow!("image index {target_digest} has no usable manifest"))?;
            return Box::pin(self.image_diff_ids(pick)).await;
        }

        // Manifest → config blob → rootfs.diff_ids.
        let config_digest = doc
            .get("config")
            .and_then(|c| c.get("digest"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| anyhow!("image manifest {target_digest} has no config descriptor"))?;
        let config_blob = self.read_blob(config_digest).await?;
        let config: serde_json::Value = serde_json::from_slice(&config_blob)
            .with_context(|| format!("parsing image config {config_digest}"))?;
        let diff_ids = config
            .get("rootfs")
            .and_then(|r| r.get("diff_ids"))
            .and_then(|d| d.as_array())
            .ok_or_else(|| anyhow!("image config {config_digest} has no rootfs.diff_ids"))?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>();
        if diff_ids.is_empty() {
            bail!("image config {config_digest} has empty rootfs.diff_ids");
        }
        Ok(diff_ids)
    }

    /// Prepare an active overlayfs snapshot for `container_id` rooted at the
    /// image's committed layer chain, returning the rootfs mounts to hand to
    /// `CreateTaskRequest`. This is the step the deploy path was missing —
    /// without it the task gets an empty rootfs and runc fails to exec.
    ///
    /// Idempotent: a redeploy whose snapshot already exists falls back to
    /// `Mounts` (read the existing active snapshot's mounts) instead of erroring.
    async fn prepare_rootfs(
        &self,
        container_id: &str,
        image_target_digest: &str,
    ) -> Result<Vec<containerd_client::types::Mount>> {
        let diff_ids = self.image_diff_ids(image_target_digest).await?;
        let parent = chain_id(&diff_ids);

        let prepare = PrepareSnapshotRequest {
            snapshotter: "overlayfs".to_string(),
            key: container_id.to_string(),
            parent,
            labels: std::collections::HashMap::new(),
        };
        let prepare = with_namespace!(prepare, self.namespace);
        match self.snapshots_client().prepare(prepare).await {
            Ok(resp) => Ok(resp.into_inner().mounts),
            Err(status) if status.code() == tonic::Code::AlreadyExists => {
                // Snapshot already active (idempotent redeploy) — read its mounts.
                let req = MountsRequest {
                    snapshotter: "overlayfs".to_string(),
                    key: container_id.to_string(),
                };
                let req = with_namespace!(req, self.namespace);
                let resp = self
                    .snapshots_client()
                    .mounts(req)
                    .await
                    .with_context(|| format!("reading existing snapshot mounts for {container_id}"))?;
                Ok(resp.into_inner().mounts)
            }
            Err(status) => Err(anyhow!(status)
                .context(format!("preparing rootfs snapshot for {container_id}"))),
        }
    }

    /// Derive a deterministic container ID from a `MeshIdent`.
    ///
    /// Containerd container IDs are opaque strings; we use the mesh ident
    /// directly since it is already DNS-safe and unique within a namespace.
    fn container_id(ident: &MeshIdent) -> &str {
        &ident.0
    }

    /// Log directory for the given container ID.
    fn log_dir(&self, container_id: &str) -> PathBuf {
        self.log_base.join(&self.namespace).join(container_id)
    }

    /// Full image reference string, e.g. `"ghcr.io/foo/bar:v1.2.3@sha256:..."`.
    /// Digest is structurally required (R438-T3) and always emitted alongside
    /// the tag.
    fn image_ref(spec: &WorkloadSpec) -> String {
        let img = &spec.image;
        format!("{}/{}:{}@{}", img.registry, img.repository, img.tag, img.digest)
    }

    /// Build the OCI `config.json` for a workload spec.
    ///
    /// In F1 this is a minimal spec sufficient to start the container. The
    /// full resource limits, volume mounts, and secret injection land once the
    /// yubaba deploy pipeline is wired (R091-F5).
    fn build_oci_spec(spec: &WorkloadSpec, mesh: &MeshAssignment) -> serde_json::Value {
        // Collect env vars (literal values only in F1; FromSecret + FromMesh
        // resolution lands with the deploy pipeline in R091-F5).
        let env: Vec<String> = spec
            .env
            .iter()
            .filter_map(|e| {
                if let workload_spec::EnvValue::Literal { value } = &e.value {
                    Some(format!("{}={}", e.name, value))
                } else {
                    None
                }
            })
            .chain(std::iter::once(format!("YAH_MESH_IP={}", mesh.mesh_ip)))
            .collect();

        // Process spec
        let process = serde_json::json!({
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": spec.command.clone().unwrap_or_default(),
            "env": env,
            "cwd": spec.workdir.as_ref()
                .and_then(|p| p.to_str())
                .unwrap_or("/"),
            "capabilities": {
                "bounding":  ["CAP_KILL", "CAP_NET_BIND_SERVICE"],
                "effective": ["CAP_KILL", "CAP_NET_BIND_SERVICE"],
                "permitted": ["CAP_KILL", "CAP_NET_BIND_SERVICE"],
                "ambient":   [],
            },
            "rlimits": [{
                "type": "RLIMIT_NOFILE",
                "hard": 1024_u32,
                "soft": 1024_u32,
            }],
            "noNewPrivileges": true,
        });

        // Namespaces: isolated by default. Host networking is a guarded opt-in
        // (yah.network=host on tier=infra — enforced in deploy_workload below):
        // OMIT the network namespace so runc leaves the container in the host
        // netns, letting it bind host ports directly. This is how a
        // single-tenant runner box lets an on-host Cloudflare tunnel reach
        // 127.0.0.1:<port> without CNI/bridge plumbing. pid/ipc/uts/mount stay
        // isolated regardless.
        let mut namespaces = vec![serde_json::json!({ "type": "pid" })];
        if !spec.wants_host_network() {
            namespaces.push(serde_json::json!({ "type": "network" }));
        }
        namespaces.push(serde_json::json!({ "type": "ipc" }));
        namespaces.push(serde_json::json!({ "type": "uts" }));
        namespaces.push(serde_json::json!({ "type": "mount" }));

        // /sys: a fresh `sysfs` mount requires owning the network namespace,
        // which fails when the container shares the host netns (host
        // networking). Runtimes handle this by bind-mounting the host /sys
        // read-only instead. Match that — isolated netns gets a fresh sysfs,
        // host netns gets a recursive read-only bind of /sys.
        let sys_mount = if spec.wants_host_network() {
            serde_json::json!({
                "destination": "/sys", "type": "bind", "source": "/sys",
                "options": ["rbind","nosuid","noexec","nodev","ro"]
            })
        } else {
            serde_json::json!({
                "destination": "/sys", "type": "sysfs", "source": "sysfs",
                "options": ["nosuid","noexec","nodev","ro"]
            })
        };

        serde_json::json!({
            "ociVersion": "1.0.2",
            "process": process,
            "root": { "path": "rootfs", "readonly": false },
            "hostname": &spec.name,
            "mounts": [
                { "destination": "/proc",  "type": "proc",   "source": "proc",   "options": [] },
                { "destination": "/dev",   "type": "tmpfs",  "source": "tmpfs",  "options": ["nosuid","strictatime","mode=755","size=65536k"] },
                sys_mount,
                { "destination": "/tmp",   "type": "tmpfs",  "source": "tmpfs",  "options": ["nosuid","nodev","mode=1777"] },
            ],
            "linux": {
                "namespaces": namespaces,
                "resources": {
                    "memory": { "limit": (spec.resources.memory_mb as i64) * 1024 * 1024 },
                    "cpu": { "shares": spec.resources.cpu_shares as u64 },
                },
                "cgroupsPath": format!("/yah/{}", spec.name),
            },
        })
    }

    /// Map a containerd task status integer to `WorkloadStatus`.
    ///
    /// Containerd task status codes per the protobuf definition:
    ///   0 = Unknown, 1 = Created, 2 = Running, 3 = Stopped, 4 = Paused, 5 = Pausing
    fn map_task_status(code: i32) -> WorkloadStatus {
        match code {
            2 => WorkloadStatus::Running,
            3 => WorkloadStatus::Stopped,
            4 | 5 => WorkloadStatus::Stopping,
            1 => WorkloadStatus::Pending,
            _ => WorkloadStatus::Failed {
                reason: format!("unknown task status code {code}"),
            },
        }
    }
}

// ── ContainerRuntime impl ─────────────────────────────────────────────────────

#[async_trait]
impl Kamaji for ContainerdRuntime {
    fn backend(&self) -> Backend {
        Backend::Containerd
    }

    async fn deploy_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> Result<DeployResult> {
        // Host networking is a privileged escape hatch — it drops network
        // isolation so the container binds host ports directly. Guard it to the
        // infra tier so an ordinary tenant workload cannot request it (bind
        // mounts are gated the same way in workload_spec::validate::shape).
        if spec.wants_host_network() && spec.tier.0 != "infra" {
            anyhow::bail!(
                "workload requests host networking (annotation {}={}) but tier is {:?}; \
                 host networking is only permitted for tier=\"infra\"",
                workload_spec::HOST_NETWORK_ANNOTATION,
                workload_spec::HOST_NETWORK_VALUE,
                spec.tier.0,
            );
        }

        let container_id = Self::container_id(&spec.expose.mesh.identity).to_string();
        let image_ref = Self::image_ref(spec);

        // Ensure the image is in the containerd image store.
        // If the image is not local, containerd's `pull` mechanism requires a
        // resolver. For now we verify it's listed; callers are expected to
        // pre-pull the image via `ctr images pull` or the MachineProvider
        // bootstrap. A proper pull path lands with the provider in R091-F3.
        let image_target_digest = {
            let mut imgs = self.images_client();
            let req = GetImageRequest {
                name: image_ref.clone(),
            };
            let req = with_namespace!(req, self.namespace);
            let image = imgs
                .get(req)
                .await
                .with_context(|| format!("image not found in containerd: {image_ref} — pre-pull required"))?
                .into_inner()
                .image
                .ok_or_else(|| anyhow!("containerd returned no image record for {image_ref}"))?;
            image
                .target
                .ok_or_else(|| anyhow!("image {image_ref} has no target descriptor"))?
                .digest
        };

        // Build OCI spec and wrap it as protobuf.Any.
        // Import comes from the same prost-types 0.11.x that containerd-client uses.
        let oci_spec = Self::build_oci_spec(spec, mesh);
        let spec_bytes = serde_json::to_vec(&oci_spec)
            .context("serializing OCI spec")?;
        let any_spec = prost_types::Any {
            type_url: "types.containerd.io/opencontainers/runtime-spec/1/Spec".to_string(),
            value: spec_bytes,
        };

        // Create log directory.
        let log_dir = self.log_dir(&container_id);
        tokio::fs::create_dir_all(&log_dir)
            .await
            .with_context(|| format!("creating log dir {}", log_dir.display()))?;
        let stdout_file = log_dir.join("stdout.log");
        let stderr_file = log_dir.join("stderr.log");
        // The containerd shim opens these stdio paths WITHOUT O_CREAT, so they
        // must already exist or task creation fails with "no such file". Touch
        // them (truncate any prior content from a previous run).
        tokio::fs::File::create(&stdout_file)
            .await
            .with_context(|| format!("creating {}", stdout_file.display()))?;
        tokio::fs::File::create(&stderr_file)
            .await
            .with_context(|| format!("creating {}", stderr_file.display()))?;
        let stdout_path = stdout_file.to_string_lossy().into_owned();
        let stderr_path = stderr_file.to_string_lossy().into_owned();

        // Tear down any stale container with the same ID (idempotent redeploy).
        let _ = self.teardown_workload(&spec.expose.mesh.identity).await;

        // Create the container record.
        {
            let mut ctrs = self.containers_client();
            let mut labels = spec.labels.clone();
            labels.insert("yah.ident".to_string(), spec.expose.mesh.identity.0.clone());
            labels.insert("yah.mesh_ip".to_string(), mesh.mesh_ip.to_string());

            let container = Container {
                id: container_id.clone(),
                image: image_ref.clone(),
                runtime: Some(containerd_client::services::v1::container::Runtime {
                    name: "io.containerd.runc.v2".to_string(),
                    options: None,
                }),
                spec: Some(any_spec),
                snapshotter: "overlayfs".to_string(),
                snapshot_key: container_id.clone(),
                labels,
                ..Default::default()
            };

            let req = CreateContainerRequest {
                container: Some(container),
            };
            let req = with_namespace!(req, self.namespace);
            ctrs.create(req)
                .await
                .with_context(|| format!("creating container {container_id}"))?;
        }

        // Prepare the rootfs snapshot from the image's committed layer chain.
        // Without this the task gets an empty rootfs and runc can't exec the
        // entrypoint (the long-standing R091-F5 gap).
        let rootfs_mounts = self
            .prepare_rootfs(&container_id, &image_target_digest)
            .await
            .with_context(|| format!("preparing rootfs for {container_id}"))?;

        // Create the task (execution instance).
        let task_pid = {
            let mut tasks = self.tasks_client();
            let req = CreateTaskRequest {
                container_id: container_id.clone(),
                rootfs: rootfs_mounts,
                stdin: String::new(),
                stdout: stdout_path,
                stderr: stderr_path,
                terminal: false,
                checkpoint: None,
                options: None,
                ..Default::default()
            };
            let req = with_namespace!(req, self.namespace);
            let resp = tasks
                .create(req)
                .await
                .with_context(|| format!("creating task for {container_id}"))?;
            resp.into_inner().pid
        };

        // Start the task.
        {
            let mut tasks = self.tasks_client();
            let req = StartRequest {
                container_id: container_id.clone(),
                exec_id: String::new(),
            };
            let req = with_namespace!(req, self.namespace);
            tasks
                .start(req)
                .await
                .with_context(|| format!("starting task for {container_id}"))?;
        }

        tracing::info!(
            container_id = %container_id,
            mesh_ip = %mesh.mesh_ip,
            task_pid = task_pid,
            "workload deployed"
        );

        Ok(DeployResult {
            container_id,
            mesh_ip: mesh.mesh_ip,
            task_pid,
        })
    }

    async fn list_workloads(&self) -> Result<Vec<WorkloadState>> {
        let mut ctrs = self.containers_client();
        let mut tasks = self.tasks_client();

        let req = ListContainersRequest {
            filters: vec![format!("labels.\"yah.ident\"!=\"\"")],
        };
        let req = with_namespace!(req, self.namespace);
        let containers = ctrs
            .list(req)
            .await
            .context("listing containerd containers")?
            .into_inner()
            .containers;

        let mut states = Vec::with_capacity(containers.len());
        for c in containers {
            let ident_str = c
                .labels
                .get("yah.ident")
                .cloned()
                .unwrap_or_else(|| c.id.clone());
            let mesh_ip = c
                .labels
                .get("yah.mesh_ip")
                .and_then(|s| s.parse().ok());

            // Query task status, then overlay restart-ledger state.
            let base = match get_task_status(&mut tasks, &self.namespace, &c.id).await {
                Ok(code) => Self::map_task_status(code),
                Err(_) => WorkloadStatus::Stopped,
            };
            let status = apply_ledger(base, self.ledger.get(&c.id));

            states.push(WorkloadState {
                ident: MeshIdent(ident_str),
                container_id: c.id,
                status,
                mesh_ip,
            });
        }

        Ok(states)
    }

    async fn get_workload(&self, ident: &MeshIdent) -> Result<Option<WorkloadState>> {
        let container_id = Self::container_id(ident);
        let mut ctrs = self.containers_client();

        let req = GetContainerRequest {
            id: container_id.to_string(),
        };
        let req = with_namespace!(req, self.namespace);
        let container = match ctrs.get(req).await {
            Ok(resp) => resp.into_inner().container,
            Err(status) if status.code() == tonic::Code::NotFound => return Ok(None),
            Err(e) => return Err(anyhow!(e).context(format!("get container {container_id}"))),
        };

        let c = match container {
            Some(c) => c,
            None => return Ok(None),
        };

        let mesh_ip = c.labels.get("yah.mesh_ip").and_then(|s| s.parse().ok());

        let mut tasks = self.tasks_client();
        let base = match get_task_status(&mut tasks, &self.namespace, container_id).await {
            Ok(code) => Self::map_task_status(code),
            Err(_) => WorkloadStatus::Stopped,
        };
        let status = apply_ledger(base, self.ledger.get(container_id));

        Ok(Some(WorkloadState {
            ident: ident.clone(),
            container_id: c.id,
            status,
            mesh_ip,
        }))
    }

    async fn stream_logs(&self, ident: &MeshIdent, opts: LogOpts) -> Result<LogStream> {
        let container_id = Self::container_id(ident).to_string();
        let log_dir = self.log_dir(&container_id);
        let ident_clone = ident.clone();

        let stdout_path = log_dir.join("stdout.log");
        let stderr_path = log_dir.join("stderr.log");

        // Build a stream that tails stdout (and optionally stderr).
        // Using tokio::fs for async file I/O; tokio_stream::wrappers::LinesStream
        // converts an AsyncBufRead into a Stream<Item = io::Result<String>>.

        let include_stdout = opts
            .stream
            .map(|s| s == LogStreamKind::Stdout)
            .unwrap_or(true);
        let include_stderr = opts
            .stream
            .map(|s| s == LogStreamKind::Stderr)
            .unwrap_or(true);

        let follow = opts.follow;

        // Build per-file streams and merge.
        let stdout_stream: Option<LogStream> = if include_stdout && stdout_path.exists() {
            let file = tokio::fs::File::open(&stdout_path)
                .await
                .with_context(|| format!("opening {}", stdout_path.display()))?;
            let reader = BufReader::new(file);
            let ident = ident_clone.clone();
            let lines = LinesStream::new(reader.lines());
            let stream = TokioStreamExt::filter_map(lines, move |line| {
                line.ok().map(|msg| LogEvent::plain(ident.clone(), LogStreamKind::Stdout, msg))
            });
            Some(Box::pin(stream))
        } else {
            None
        };

        let stderr_stream: Option<LogStream> = if include_stderr && stderr_path.exists() {
            let file = tokio::fs::File::open(&stderr_path)
                .await
                .with_context(|| format!("opening {}", stderr_path.display()))?;
            let reader = BufReader::new(file);
            let ident = ident_clone.clone();
            let lines = LinesStream::new(reader.lines());
            let stream = TokioStreamExt::filter_map(lines, move |line| {
                line.ok().map(|msg| LogEvent::plain(ident.clone(), LogStreamKind::Stderr, msg))
            });
            Some(Box::pin(stream))
        } else {
            None
        };

        // Merge the two streams.
        let merged: LogStream = match (stdout_stream, stderr_stream) {
            (Some(a), Some(b)) => Box::pin(tokio_stream::StreamExt::merge(a, b)),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => Box::pin(tokio_stream::empty()),
        };

        // If not following, close the stream once existing lines are consumed.
        // tokio_stream doesn't have a native "read until EOF then close"
        // adapter; instead we rely on the file stream closing at EOF naturally
        // when `follow = false`. For `follow = true` a full inotify/kqueue
        // based tail implementation is needed — that lands with the beholder
        // service in R091 later. For now, the stream drains existing lines.
        let _ = follow; // placeholder until tail-follow impl

        Ok(merged)
    }

    async fn restart_workload(&self, ident: &MeshIdent) -> Result<()> {
        let container_id = Self::container_id(ident);
        let mut tasks = self.tasks_client();

        // Send SIGTERM.
        let req = KillRequest {
            container_id: container_id.to_string(),
            exec_id: String::new(),
            signal: 15, // SIGTERM
            all: false,
        };
        let req = with_namespace!(req, self.namespace);
        tasks
            .kill(req)
            .await
            .with_context(|| format!("SIGTERM {container_id}"))?;

        // Wait briefly for graceful exit, then start a new task.
        tokio::time::sleep(Duration::from_secs(5)).await;

        let req = StartRequest {
            container_id: container_id.to_string(),
            exec_id: String::new(),
        };
        let req = with_namespace!(req, self.namespace);
        tasks
            .start(req)
            .await
            .with_context(|| format!("restarting task for {container_id}"))?;

        tracing::info!(container_id = %container_id, "workload restarted");
        Ok(())
    }

    async fn teardown_workload(&self, ident: &MeshIdent) -> Result<()> {
        let container_id = Self::container_id(ident);
        let mut tasks = self.tasks_client();
        let mut ctrs = self.containers_client();

        // Kill the task (best-effort; container may not be running).
        let kill_req = KillRequest {
            container_id: container_id.to_string(),
            exec_id: String::new(),
            signal: 9, // SIGKILL
            all: true,
        };
        let kill_req = with_namespace!(kill_req, self.namespace);
        let _ = tasks.kill(kill_req).await;

        // Brief delay so the task exits before we try to delete.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Delete the task record.
        let del_task_req = DeleteTaskRequest {
            container_id: container_id.to_string(),
        };
        let del_task_req = with_namespace!(del_task_req, self.namespace);
        let _ = tasks.delete(del_task_req).await;

        // Delete the container record.
        let del_req = DeleteContainerRequest {
            id: container_id.to_string(),
        };
        let del_req = with_namespace!(del_req, self.namespace);
        match ctrs.delete(del_req).await {
            Ok(_) => {}
            Err(status) if status.code() == tonic::Code::NotFound => {}
            Err(e) => {
                return Err(anyhow!(e)
                    .context(format!("deleting container {container_id}")));
            }
        }

        // Remove the active rootfs snapshot so a redeploy can re-prepare it
        // (snapshot key == container id). Best-effort: NotFound is fine.
        let rm_snap = RemoveSnapshotRequest {
            snapshotter: "overlayfs".to_string(),
            key: container_id.to_string(),
        };
        let rm_snap = with_namespace!(rm_snap, self.namespace);
        let _ = self.snapshots_client().remove(rm_snap).await;

        // Drop any restart-loop bookkeeping for this container.
        self.ledger.forget(container_id);

        tracing::info!(container_id = %container_id, "workload torn down");
        Ok(())
    }

    async fn health(&self) -> Result<RuntimeHealth> {
        let mut ver = self.version_client();
        let req = tonic::Request::new(());
        match ver.version(req).await {
            Ok(resp) => {
                let v = resp.into_inner();
                Ok(RuntimeHealth {
                    ok: true,
                    version: Some(v.version),
                    detail: None,
                })
            }
            Err(e) => Ok(RuntimeHealth {
                ok: false,
                version: None,
                detail: Some(e.to_string()),
            }),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Query the status integer of a containerd task (best-effort).
async fn get_task_status(
    tasks: &mut TasksClient<tonic::transport::Channel>,
    namespace: &str,
    container_id: &str,
) -> Result<i32> {
    use containerd_client::services::v1::GetRequest;
    let req = GetRequest {
        container_id: container_id.to_string(),
        exec_id: String::new(),
    };
    let req = with_namespace!(req, namespace);
    let resp = tasks
        .get(req)
        .await
        .context("get task status")?;
    Ok(resp.into_inner().process.map(|p| p.status).unwrap_or(0))
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, ResourceLimits, RestartPolicy, SchemaVersion,
        StopPolicy, TierTag, WorkloadSpec, Millis,
    };

    /// Returns `true` when a containerd socket is reachable. Used to skip
    /// tests on machines without containerd (standard CI, most dev Macs).
    async fn containerd_available() -> bool {
        ContainerdRuntime::connect().await.is_ok()
    }

    fn test_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.to_string(),
            image: ImageRef {
                registry: "docker.io".to_string(),
                repository: "library/alpine".to_string(),
                tag: "latest".to_string(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".to_string()),
            replicas: 1,
            command: Some(vec!["sleep".to_string(), "30".to_string()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 64,
                cpu_shares: 128,
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Never,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name.to_string()),
                    ports: vec![],
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        }
    }

    fn netns_present(oci: &serde_json::Value) -> bool {
        oci["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["type"] == "network")
    }

    #[test]
    fn chain_id_single_layer_is_identity() {
        // A one-layer image's chainID is just that layer's diff_id.
        let d = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(chain_id(&[d.to_string()]), d);
    }

    #[test]
    fn chain_id_folds_multiple_layers() {
        let a = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let b = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let chain = chain_id(&[a.to_string(), b.to_string()]);
        // Folded result is a fresh sha256 digest, not either input.
        assert!(chain.starts_with("sha256:"));
        assert_eq!(chain.len(), "sha256:".len() + 64);
        assert_ne!(chain, a);
        assert_ne!(chain, b);
        // Deterministic.
        assert_eq!(chain, chain_id(&[a.to_string(), b.to_string()]));
    }

    #[test]
    fn chain_id_empty_is_empty() {
        assert_eq!(chain_id(&[]), "");
    }

    #[test]
    fn oci_spec_isolates_network_by_default() {
        let mesh = MeshAssignment::stub("10.64.0.9".parse().unwrap());
        let oci = ContainerdRuntime::build_oci_spec(&test_spec("svc"), &mesh);
        assert!(netns_present(&oci), "default workload must get an isolated netns");
    }

    #[test]
    fn oci_spec_host_network_omits_netns() {
        let mesh = MeshAssignment::stub("10.64.0.9".parse().unwrap());
        let mut spec = test_spec("svc");
        spec.annotations.insert(
            workload_spec::HOST_NETWORK_ANNOTATION.into(),
            workload_spec::HOST_NETWORK_VALUE.into(),
        );
        let oci = ContainerdRuntime::build_oci_spec(&spec, &mesh);
        assert!(!netns_present(&oci), "yah.network=host must share the host netns");
        let types: Vec<&str> = oci["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["type"].as_str().unwrap())
            .collect();
        for ns in ["pid", "ipc", "uts", "mount"] {
            assert!(types.contains(&ns), "namespace {ns} must remain isolated");
        }
    }

    #[test]
    fn ledger_record_exit_increments_count_and_arms_in_flight() {
        let ledger = RestartLedger::new();
        ledger.record_exit("c1", 137);
        let r = ledger.get("c1").unwrap();
        assert_eq!(r.restart_count, 1);
        assert_eq!(r.last_exit_code, 137);
        assert!(r.in_flight);

        ledger.record_exit("c1", 2);
        let r = ledger.get("c1").unwrap();
        assert_eq!(r.restart_count, 2);
        assert_eq!(r.last_exit_code, 2);
        assert!(r.in_flight);
    }

    #[test]
    fn ledger_mark_running_clears_in_flight_preserves_count() {
        let ledger = RestartLedger::new();
        ledger.record_exit("c1", 1);
        ledger.mark_running("c1");
        let r = ledger.get("c1").unwrap();
        assert_eq!(r.restart_count, 1);
        assert!(!r.in_flight);
    }

    #[test]
    fn apply_ledger_upgrades_stopped_to_restarting_when_in_flight() {
        let ledger = RestartLedger::new();
        ledger.record_exit("c1", 137);
        let status = apply_ledger(WorkloadStatus::Stopped, ledger.get("c1"));
        match status {
            WorkloadStatus::Restarting {
                last_exit_code,
                restart_count,
                last_finished_at_unix_ms,
            } => {
                assert_eq!(last_exit_code, 137);
                assert_eq!(restart_count, 1);
                assert!(last_finished_at_unix_ms > 0);
            }
            other => panic!("expected Restarting, got {other:?}"),
        }
    }

    #[test]
    fn apply_ledger_passthrough_when_no_record_or_not_in_flight() {
        // No record → base unchanged.
        assert_eq!(
            apply_ledger(WorkloadStatus::Stopped, None),
            WorkloadStatus::Stopped
        );

        // Record exists but in_flight cleared → base unchanged (crash-loop paused).
        let ledger = RestartLedger::new();
        ledger.record_exit("c1", 1);
        ledger.mark_running("c1");
        assert_eq!(
            apply_ledger(WorkloadStatus::Stopped, ledger.get("c1")),
            WorkloadStatus::Stopped
        );

        // Even with an in-flight record, Running stays Running.
        ledger.record_exit("c1", 1);
        assert_eq!(
            apply_ledger(WorkloadStatus::Running, ledger.get("c1")),
            WorkloadStatus::Running
        );
    }

    #[test]
    fn apply_ledger_upgrades_failed_to_restarting() {
        let ledger = RestartLedger::new();
        ledger.record_exit("c1", 1);
        let status = apply_ledger(
            WorkloadStatus::Failed { reason: "exit 1".into() },
            ledger.get("c1"),
        );
        assert!(matches!(status, WorkloadStatus::Restarting { .. }));
    }

    #[test]
    fn restarting_serde_round_trips_through_json() {
        // Verifies the yubaba HTTP API surface: WorkloadStatus::Restarting
        // must serialize as `{type: "restarting", ...}` and deserialize back.
        let original = WorkloadStatus::Restarting {
            last_exit_code: 2,
            restart_count: 5,
            last_finished_at_unix_ms: 1_700_000_000_000,
        };
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("\"type\":\"restarting\""));
        let parsed: WorkloadStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
        assert!(!original.is_terminal(), "Restarting must not be terminal");
    }

    #[tokio::test]
    async fn runtime_health_returns_ok_or_degraded() {
        if !containerd_available().await {
            eprintln!("SKIP: containerd not reachable (run with --features containerd-integration on a host with containerd)");
            return;
        }
        let rt = ContainerdRuntime::connect().await.unwrap();
        let h = rt.health().await.unwrap();
        assert!(h.ok, "expected healthy containerd: {:?}", h.detail);
        assert!(h.version.is_some(), "expected version string");
    }

    #[tokio::test]
    async fn deploy_get_teardown() {
        if !containerd_available().await {
            eprintln!("SKIP: containerd not reachable");
            return;
        }
        let rt = ContainerdRuntime::connect()
            .await
            .unwrap()
            .with_namespace("yah-test");

        let spec = test_spec("test-deploy-get-teardown");
        let mesh = MeshAssignment::stub("10.64.0.1".parse().unwrap());

        // Deploy
        let result = rt.deploy_workload(&spec, &mesh).await.unwrap();
        assert_eq!(result.container_id, "test-deploy-get-teardown");
        assert!(result.task_pid > 0);

        // Get
        let state = rt
            .get_workload(&spec.expose.mesh.identity)
            .await
            .unwrap()
            .expect("workload should exist after deploy");
        assert_eq!(state.status, WorkloadStatus::Running);

        // Teardown
        rt.teardown_workload(&spec.expose.mesh.identity)
            .await
            .unwrap();

        // Should be gone
        let after = rt
            .get_workload(&spec.expose.mesh.identity)
            .await
            .unwrap();
        assert!(after.is_none(), "workload should be absent after teardown");
    }

    #[tokio::test]
    async fn list_workloads_empty_when_no_containers() {
        if !containerd_available().await {
            eprintln!("SKIP: containerd not reachable");
            return;
        }
        let rt = ContainerdRuntime::connect()
            .await
            .unwrap()
            .with_namespace("yah-test-list-empty");
        let list = rt.list_workloads().await.unwrap();
        assert!(
            list.is_empty(),
            "expected empty namespace, found {} containers",
            list.len()
        );
    }

    #[tokio::test]
    async fn stream_logs_returns_output() {
        if !containerd_available().await {
            eprintln!("SKIP: containerd not reachable");
            return;
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let rt = ContainerdRuntime::connect()
            .await
            .unwrap()
            .with_namespace("yah-test-logs")
            .with_log_base(tmp.path());

        let spec = test_spec("test-log-stream");
        let mesh = MeshAssignment::stub("10.64.0.2".parse().unwrap());

        rt.deploy_workload(&spec, &mesh).await.unwrap();

        // Give the container a moment to write to stdout.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let opts = LogOpts {
            tail: Some(100),
            follow: false,
            stream: Some(LogStreamKind::Stdout),
        };
        let mut log_stream = rt
            .stream_logs(&spec.expose.mesh.identity, opts)
            .await
            .unwrap();

        use tokio_stream::StreamExt as _;
        let mut events = vec![];
        while let Some(ev) = log_stream.next().await {
            events.push(ev);
        }

        rt.teardown_workload(&spec.expose.mesh.identity)
            .await
            .unwrap();

        // Alpine `sleep 30` writes nothing to stdout — just ensure we got the
        // stream without error. A more useful test would use `echo` as the
        // command; update in R091-F5 when the full E2E harness lands.
        println!("log events: {}", events.len());
    }
}
