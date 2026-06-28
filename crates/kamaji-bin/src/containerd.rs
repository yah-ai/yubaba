//! Kamaji's containerd backend (R406-T9).
//!
//! ## Why this lives in Kamaji, not in Yubaba
//!
//! Per [W154](../../../../.yah/docs/working/W154-yubaba-dual-runtime.md)
//! §"Kamaji's native driver" and §"Impact on yubaba codebase":
//!
//! > Existing crates/yah/yubaba/: trimmed to mesh/raft/admission/federation.
//! > Drops direct knowledge of containerd internals; talks to Kamaji over
//! > UDS for all workload lifecycle.
//!
//! Containerd is one of Kamaji's two backends (the other is `native` —
//! see [`crate::native`]). Both consume the same enriched `WorkloadSpec`
//! after Kamaji applies the WorkloadSpec enforcement layer (capabilities,
//! secret mounts, MeshIdent-aware bindings). Yubaba owns admission and
//! mesh-IP allocation; the spec arrives already mesh-resolved.
//!
//! ## Gating
//!
//! This module compiles only under `--features containerd-integration` so
//! the dev binary and pond's inner kamaji (which uses the host docker
//! socket via a separate backend) don't carry tonic + the containerd-client
//! stack.
//!
//! ## Shape
//!
//! - One `ContainerdBackend` per Kamaji instance, holding the tonic
//!   `Channel`. Cheap to clone; the inner channel is `Arc`-wrapped.
//! - All yah-managed containers live in containerd namespace `"yah"`.
//! - Container IDs derive from the [`WorkloadId`] passed in `Deploy` (stable
//!   across Kamaji restarts so reconciliation can match).
//! - Each call returns `Result<_, BackendError>`; the server layer maps
//!   these to `ConstableToWarden::Error { code, message }` for the wire.

#![cfg(feature = "containerd-integration")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use kamaji_proto::{WorkloadEntry, WorkloadId, WorkloadState};
use containerd_client::{
    services::v1::{
        container::Runtime as ContainerRuntime, containers_client::ContainersClient,
        content_client::ContentClient, images_client::ImagesClient,
        snapshots::{
            snapshots_client::SnapshotsClient, MountsRequest, PrepareSnapshotRequest,
            RemoveSnapshotRequest,
        },
        tasks_client::TasksClient, version_client::VersionClient, Container,
        CreateContainerRequest, CreateTaskRequest, DeleteContainerRequest, DeleteTaskRequest,
        GetContainerRequest, GetImageRequest, KillRequest, ListContainersRequest,
        ReadContentRequest, StartRequest,
    },
    tonic::{self, transport::Channel, Request},
    with_namespace,
};
use thiserror::Error;
use tokio::task::AbortHandle;
use tracing::{info, warn};
use workload_spec::{EnvValue, WorkloadSpec};

use crate::journal::{LogSink, Stream};

/// Default containerd UDS — matches the production cloud-tier deploy. The
/// kamaji.service systemd unit binds-mounts this path in the yubaba.slice.
pub const DEFAULT_SOCKET: &str = "/run/containerd/containerd.sock";

/// Single containerd namespace for every yah-managed container.
///
/// Containerd's per-namespace listing means another orchestrator (k3s, etc.)
/// on the same host won't see our containers and vice versa. Stable so
/// reconciliation across Kamaji restarts can re-discover surviving
/// children.
pub const YAH_NAMESPACE: &str = "yah";

/// `/var/log/yah/<namespace>/<container-id>/{stdout,stderr}.fifo`.
///
/// Each workload gets a per-stream FIFO. Containerd's shim opens these for
/// write as the container's stdout/stderr; Kamaji opens them for read
/// (via [`tokio::net::unix::pipe::Receiver`]) and runs a
/// [`crate::journal::forward_reader`] per stream to fan log lines into
/// journald (R406-T10).
pub const LOG_BASE: &str = "/var/log/yah";

/// Errors surfaced by the backend. The server layer maps these to wire
/// `ErrorCode` variants.
#[derive(Debug, Error)]
pub enum BackendError {
    /// The provided workload spec failed validation Kamaji applies
    /// before dispatching to containerd (unresolved `FromSecret`/`FromMesh`
    /// env, etc.). Maps to `ErrorCode::InvalidSpec`.
    #[error("invalid spec: {0}")]
    InvalidSpec(String),

    /// Containerd refused or failed a syscall — connection dropped, image
    /// missing, task creation refused. Maps to `ErrorCode::BackendRefused`.
    #[error("containerd: {0}")]
    Containerd(#[from] anyhow::Error),
}

/// Per-workload state Kamaji tracks for cancellation. R406-T10 stores
/// the abort handles for the stdout/stderr journald forwarder tasks so
/// teardown can stop them deterministically (the workload's writer side
/// of an `O_RDWR` FIFO would otherwise keep the reader's loop alive).
#[derive(Debug, Default)]
struct WorkloadTracking {
    forwarders: Vec<AbortHandle>,
    fifo_paths: Vec<PathBuf>,
}

/// Connection + per-instance config for the containerd backend.
#[derive(Clone, Debug)]
pub struct ContainerdBackend {
    channel: Channel,
    namespace: String,
    log_base: PathBuf,
    /// Sink for forwarded log lines (R406-T10). Defaults to a sink that
    /// silently drops everything; production attaches a [`crate::JournalSender`]
    /// via [`with_log_sink`].
    log_sink: Arc<dyn LogSink>,
    /// Per-workload forwarder handles and FIFO paths. Wrapped in `Arc<Mutex<>>`
    /// so deploy and teardown can mutate from inside async fns without
    /// requiring `&mut self`.
    tracked: Arc<Mutex<HashMap<WorkloadId, WorkloadTracking>>>,
}

impl ContainerdBackend {
    /// Connect to the default containerd socket.
    pub async fn connect() -> Result<Self> {
        Self::connect_at(DEFAULT_SOCKET).await
    }

    /// Connect to an explicit socket path. Use for Colima on dev hosts
    /// (`~/.colima/default/containerd.sock`).
    pub async fn connect_at(socket: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = socket.as_ref().to_path_buf();
        let channel = containerd_client::connect(&path)
            .await
            .with_context(|| format!("connecting to containerd at {}", path.display()))?;
        Ok(Self {
            channel,
            namespace: YAH_NAMESPACE.to_string(),
            log_base: PathBuf::from(LOG_BASE),
            log_sink: Arc::new(NoopSink),
            tracked: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Override the namespace (testing).
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = ns.into();
        self
    }

    /// Override the log base (testing).
    pub fn with_log_base(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_base = path.into();
        self
    }

    /// Attach a log sink. The production binary passes the kamaji-wide
    /// [`crate::JournalSender`] here at startup; tests pass a
    /// [`crate::journal::VecSink`].
    pub fn with_log_sink(mut self, sink: Arc<dyn LogSink>) -> Self {
        self.log_sink = sink;
        self
    }

    fn containers_client(&self) -> ContainersClient<Channel> {
        ContainersClient::new(self.channel.clone())
    }

    fn tasks_client(&self) -> TasksClient<Channel> {
        TasksClient::new(self.channel.clone())
    }

    fn images_client(&self) -> ImagesClient<Channel> {
        ImagesClient::new(self.channel.clone())
    }

    fn version_client(&self) -> VersionClient<Channel> {
        VersionClient::new(self.channel.clone())
    }

    fn content_client(&self) -> ContentClient<Channel> {
        ContentClient::new(self.channel.clone())
    }

    fn snapshots_client(&self) -> SnapshotsClient<Channel> {
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
                .ok_or_else(|| anyhow::anyhow!("image index {target_digest} has no usable manifest"))?;
            return Box::pin(self.image_diff_ids(pick)).await;
        }

        // Manifest → config blob → rootfs.diff_ids.
        let config_digest = doc
            .get("config")
            .and_then(|c| c.get("digest"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| anyhow::anyhow!("image manifest {target_digest} has no config descriptor"))?;
        let config_blob = self.read_blob(config_digest).await?;
        let config: serde_json::Value = serde_json::from_slice(&config_blob)
            .with_context(|| format!("parsing image config {config_digest}"))?;
        let diff_ids = config
            .get("rootfs")
            .and_then(|r| r.get("diff_ids"))
            .and_then(|d| d.as_array())
            .ok_or_else(|| anyhow::anyhow!("image config {config_digest} has no rootfs.diff_ids"))?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>();
        if diff_ids.is_empty() {
            anyhow::bail!("image config {config_digest} has empty rootfs.diff_ids");
        }
        Ok(diff_ids)
    }

    /// Prepare an active overlayfs snapshot for `container_id` rooted at the
    /// image's committed layer chain, returning the rootfs mounts to hand to
    /// `CreateTaskRequest`. Without this the task gets an empty rootfs and runc
    /// fails to exec the entrypoint (R563 REMAINING 2 — parity with
    /// kamaji-core::containerd::prepare_rootfs).
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
            labels: HashMap::new(),
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
                    .with_context(|| {
                        format!("reading existing snapshot mounts for {container_id}")
                    })?;
                Ok(resp.into_inner().mounts)
            }
            Err(status) => Err(anyhow::anyhow!(status)
                .context(format!("preparing rootfs snapshot for {container_id}"))),
        }
    }

    fn log_dir(&self, container_id: &str) -> PathBuf {
        self.log_base.join(&self.namespace).join(container_id)
    }

    /// Full image reference string used as the containerd image key.
    /// Digest is structurally required (R438-T3) and always pinned alongside
    /// the human-readable tag.
    fn image_ref(spec: &WorkloadSpec) -> String {
        let img = &spec.image;
        format!("{}/{}:{}@{}", img.registry, img.repository, img.tag, img.digest)
    }

    /// Deploy a workload. The `id` is what Kamaji's registry keys on and
    /// what surfaces in `ConstableToWarden::WorkloadStarted` / lifecycle
    /// events. Returns the OS pid containerd reports for the new task.
    pub async fn deploy(
        &self,
        id: &WorkloadId,
        spec: &WorkloadSpec,
    ) -> Result<u32, BackendError> {
        validate_spec_for_constable(spec)?;
        let container_id = id.as_str().to_string();
        let image_ref = Self::image_ref(spec);

        // Verify the image is in containerd's image store and grab its target
        // descriptor digest — we walk that (manifest → config → diff_ids) to
        // prepare the rootfs snapshot below. Callers (yubaba admission,
        // R040-F11's bootstrap) are expected to have pre-pulled the image via
        // `ctr images pull` or the MachineProvider bootstrap path.
        let image_target_digest = {
            let mut imgs = self.images_client();
            let req = GetImageRequest {
                name: image_ref.clone(),
            };
            let req = with_namespace!(req, self.namespace);
            let image = imgs
                .get(req)
                .await
                .map_err(|e| {
                    BackendError::Containerd(anyhow::anyhow!(
                        "image not found in containerd: {image_ref} — pre-pull required ({e})"
                    ))
                })?
                .into_inner()
                .image
                .ok_or_else(|| {
                    BackendError::Containerd(anyhow::anyhow!(
                        "containerd returned no image record for {image_ref}"
                    ))
                })?;
            image
                .target
                .ok_or_else(|| {
                    BackendError::Containerd(anyhow::anyhow!(
                        "image {image_ref} has no target descriptor"
                    ))
                })?
                .digest
        };

        // OCI spec — capabilities, mounts, namespaces, cgroup path.
        let oci_spec = build_oci_spec(spec);
        let spec_bytes = serde_json::to_vec(&oci_spec)
            .context("serializing OCI spec")
            .map_err(BackendError::Containerd)?;
        let any_spec = prost_types::Any {
            type_url: "types.containerd.io/opencontainers/runtime-spec/1/Spec".to_string(),
            value: spec_bytes,
        };

        // Log fan-in to journald (R406-T10): mkfifo per stream, point
        // containerd at the FIFO paths, open the read side ourselves, and
        // spawn one forward_reader task per stream. The forwarders' abort
        // handles are tracked so teardown can stop them.
        let log_dir = self.log_dir(&container_id);
        tokio::fs::create_dir_all(&log_dir)
            .await
            .with_context(|| format!("creating log dir {}", log_dir.display()))
            .map_err(BackendError::Containerd)?;
        let stdout_fifo = log_dir.join("stdout.fifo");
        let stderr_fifo = log_dir.join("stderr.fifo");

        // Idempotent redeploy: tear down any prior container with the same id
        // before recreating. teardown is itself idempotent (missing -> Ok)
        // and also unlinks any stale FIFOs / aborts prior forwarders.
        let _ = self.teardown(id).await;

        ensure_fifo(&stdout_fifo)
            .with_context(|| format!("mkfifo {}", stdout_fifo.display()))
            .map_err(BackendError::Containerd)?;
        ensure_fifo(&stderr_fifo)
            .with_context(|| format!("mkfifo {}", stderr_fifo.display()))
            .map_err(BackendError::Containerd)?;

        let stdout_path = stdout_fifo.to_string_lossy().into_owned();
        let stderr_path = stderr_fifo.to_string_lossy().into_owned();

        // Create the container record.
        {
            let mut ctrs = self.containers_client();
            let labels = labels_for(spec, id);
            let container = Container {
                id: container_id.clone(),
                image: image_ref.clone(),
                runtime: Some(ContainerRuntime {
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
                .with_context(|| format!("creating container {container_id}"))
                .map_err(BackendError::Containerd)?;
        }

        // Prepare the rootfs snapshot from the image's committed layer chain.
        // Without this the task gets an empty rootfs and runc can't exec the
        // entrypoint (R563 REMAINING 2 — parity with kamaji-core).
        let rootfs_mounts = self
            .prepare_rootfs(&container_id, &image_target_digest)
            .await
            .with_context(|| format!("preparing rootfs for {container_id}"))?;

        // Create + start the task (the live execution instance).
        let pid = {
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
                .with_context(|| format!("creating task for {container_id}"))
                .map_err(BackendError::Containerd)?;
            resp.into_inner().pid
        };
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
                .with_context(|| format!("starting task for {container_id}"))
                .map_err(BackendError::Containerd)?;
        }

        // Spawn the journald forwarders. Open the read side AFTER StartRequest
        // so containerd's shim has already opened the write end — the
        // O_RDWR flag belt-and-braces this against an EPOLLHUP-on-no-writer
        // glitch even if the open order races.
        let stdout_handle = spawn_forwarder(
            self.log_sink.clone(),
            id.clone(),
            Stream::Stdout,
            &stdout_fifo,
        )?;
        let stderr_handle = spawn_forwarder(
            self.log_sink.clone(),
            id.clone(),
            Stream::Stderr,
            &stderr_fifo,
        )?;
        {
            let mut tracked = self.tracked.lock().expect("tracked mutex poisoned");
            tracked.insert(
                id.clone(),
                WorkloadTracking {
                    forwarders: vec![stdout_handle, stderr_handle],
                    fifo_paths: vec![stdout_fifo.clone(), stderr_fifo.clone()],
                },
            );
        }

        info!(
            container_id = %container_id,
            pid = pid,
            image = %image_ref,
            "kamaji: containerd workload deployed"
        );
        Ok(pid)
    }

    /// Idempotent teardown — kill, delete task, delete container, and stop
    /// any per-workload journald forwarder tasks plus unlink their FIFOs
    /// (R406-T10). Missing containers and missing tasks both surface as
    /// `Ok(())`. Tracking-side cleanup runs even when the container itself
    /// is absent, so a redeploy that mkfifo's into a stale path on disk
    /// doesn't EEXIST-fail.
    pub async fn teardown(&self, id: &WorkloadId) -> Result<(), BackendError> {
        let container_id = id.as_str().to_string();

        // Stop forwarders + unlink FIFOs first — this is idempotent and
        // independent of whether the container itself is in containerd. A
        // crashed Kamaji that left FIFOs behind needs them gone before
        // the next deploy mkfifo's the same path.
        let tracking = {
            let mut tracked = self.tracked.lock().expect("tracked mutex poisoned");
            tracked.remove(id)
        };
        if let Some(tracking) = tracking {
            for handle in tracking.forwarders {
                handle.abort();
            }
            for fifo in tracking.fifo_paths {
                if let Err(e) = tokio::fs::remove_file(&fifo).await {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!(
                            workload = %container_id,
                            fifo = %fifo.display(),
                            error = %e,
                            "kamaji: failed to unlink FIFO during teardown"
                        );
                    }
                }
            }
        }

        // Check container exists.
        let mut ctrs = self.containers_client();
        let probe = ctrs
            .get({
                let req = GetContainerRequest {
                    id: container_id.clone(),
                };
                with_namespace!(req, self.namespace)
            })
            .await;
        if probe.is_err() {
            return Ok(());
        }

        // Kill the task with SIGKILL — Stop's gentle path goes through Drain
        // (T7); this is the hard-tear-down used by `Stop` and idempotent
        // redeploy.
        {
            let mut tasks = self.tasks_client();
            let req = KillRequest {
                container_id: container_id.clone(),
                exec_id: String::new(),
                signal: 9, // SIGKILL
                all: false,
            };
            let req = with_namespace!(req, self.namespace);
            let _ = tasks.kill(req).await; // missing/already-dead → ignore
        }

        // Delete the task record.
        {
            let mut tasks = self.tasks_client();
            let req = DeleteTaskRequest {
                container_id: container_id.clone(),
            };
            let req = with_namespace!(req, self.namespace);
            let _ = tasks.delete(req).await;
        }

        // Delete the container record.
        {
            let mut ctrs = self.containers_client();
            let req = DeleteContainerRequest {
                id: container_id.clone(),
            };
            let req = with_namespace!(req, self.namespace);
            let _ = ctrs.delete(req).await;
        }

        // Remove the active rootfs snapshot so a redeploy can re-prepare it
        // (snapshot key == container id). Best-effort: NotFound is fine.
        {
            let req = RemoveSnapshotRequest {
                snapshotter: "overlayfs".to_string(),
                key: container_id.clone(),
            };
            let req = with_namespace!(req, self.namespace);
            let _ = self.snapshots_client().remove(req).await;
        }

        info!(container_id = %container_id, "kamaji: containerd workload torn down");
        Ok(())
    }

    /// List every yah-managed container in containerd's `"yah"` namespace.
    /// Returns `WorkloadEntry` (the on-wire shape) so the server layer can
    /// fold this list into `ConstableToWarden::WorkloadList` without an
    /// intermediate conversion.
    pub async fn list(&self) -> Result<Vec<WorkloadEntry>, BackendError> {
        let mut ctrs = self.containers_client();
        let req = ListContainersRequest {
            filters: vec!["labels.\"yah.ident\"!=\"\"".to_string()],
        };
        let req = with_namespace!(req, self.namespace);
        let containers = ctrs
            .list(req)
            .await
            .context("listing containerd containers")
            .map_err(BackendError::Containerd)?
            .into_inner()
            .containers;

        let mut tasks = self.tasks_client();
        let mut entries = Vec::with_capacity(containers.len());
        for c in containers {
            // Default to Starting until the task is created; map the task
            // status to a proto WorkloadState once it exists.
            let (state, pid) = match get_task_status(&mut tasks, &self.namespace, &c.id).await {
                Ok(Some((code, pid))) => (map_task_state(code), Some(pid)),
                Ok(None) => (WorkloadState::Pending, None),
                Err(_) => (WorkloadState::Failed, None),
            };
            entries.push(WorkloadEntry {
                id: WorkloadId::new(c.id),
                state,
                pid,
            });
        }
        Ok(entries)
    }

    /// Probe containerd liveness — used by the server's `health` surface
    /// once it is wired (not on the wire yet).
    pub async fn health(&self) -> Result<String, BackendError> {
        let mut v = self.version_client();
        let resp = v
            .version(Request::new(()))
            .await
            .context("containerd version RPC")
            .map_err(BackendError::Containerd)?;
        let inner = resp.into_inner();
        Ok(inner.version)
    }
}

/// Inert sink used when [`ContainerdBackend::with_log_sink`] hasn't been
/// called. Drops every line on the floor — production wires
/// [`crate::JournalSender`] in `main.rs`.
#[derive(Debug)]
struct NoopSink;

impl LogSink for NoopSink {
    fn write_line(&self, _workload: &WorkloadId, _stream: Stream, _line: &[u8]) {}
}

/// Create a FIFO at `path` with mode 0o600 if one doesn't already exist.
/// Returns `Ok(())` if the path already holds a FIFO (idempotent redeploy
/// after a crashed teardown), an error otherwise.
///
/// Linux-only — non-Linux returns a clear unsupported error. macOS hosts
/// running kamaji with the `containerd-integration` feature are an
/// unsupported combination in production (containerd doesn't run on Mac);
/// the gate keeps build hygiene without burning a runtime crash.
#[cfg(target_os = "linux")]
fn ensure_fifo(path: &Path) -> Result<()> {
    use nix::sys::stat::{stat, Mode, SFlag};
    use nix::unistd::mkfifo;
    match stat(path) {
        Ok(st) => {
            // Already exists — accept if it's a FIFO, error otherwise.
            let mode = SFlag::from_bits_truncate(st.st_mode);
            if mode.contains(SFlag::S_IFIFO) {
                return Ok(());
            }
            anyhow::bail!(
                "{}: exists but is not a FIFO ({:#o})",
                path.display(),
                st.st_mode
            );
        }
        Err(nix::errno::Errno::ENOENT) => {}
        Err(e) => anyhow::bail!("stat({}): {e}", path.display()),
    }
    mkfifo(path, Mode::from_bits_truncate(0o600))
        .map_err(|e| anyhow::anyhow!("mkfifo({}): {e}", path.display()))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_fifo(path: &Path) -> Result<()> {
    let _ = path;
    anyhow::bail!("containerd FIFO log fan-in requires Linux")
}

/// Open `fifo_path` for read+write (so EPOLLHUP-on-no-writer doesn't fire),
/// then spawn a tokio task that runs [`crate::journal::forward_reader`]
/// against it. The returned [`AbortHandle`] is tracked in
/// [`ContainerdBackend::tracked`] and aborted by teardown.
#[cfg(target_os = "linux")]
fn spawn_forwarder(
    sink: Arc<dyn LogSink>,
    workload: WorkloadId,
    stream: Stream,
    fifo_path: &Path,
) -> Result<AbortHandle, BackendError> {
    let recv = tokio::net::unix::pipe::OpenOptions::new()
        .read_write(true)
        .open_receiver(fifo_path)
        .with_context(|| format!("open FIFO {} for read", fifo_path.display()))
        .map_err(BackendError::Containerd)?;
    let workload_label = workload.as_str().to_string();
    let join = tokio::spawn(async move {
        if let Err(e) =
            crate::journal::forward_reader(sink, workload, stream, recv).await
        {
            tracing::warn!(
                workload = %workload_label,
                stream = stream.label(),
                error = %e,
                "kamaji: log forwarder ended on read error"
            );
        }
    });
    Ok(join.abort_handle())
}

#[cfg(not(target_os = "linux"))]
fn spawn_forwarder(
    sink: Arc<dyn LogSink>,
    workload: WorkloadId,
    stream: Stream,
    fifo_path: &Path,
) -> Result<AbortHandle, BackendError> {
    let _ = (sink, workload, stream, fifo_path);
    Err(BackendError::Containerd(anyhow::anyhow!(
        "containerd FIFO log fan-in requires Linux"
    )))
}

/// Build labels Kamaji stamps on every container — these are how
/// `list_workloads` filters yah-managed containers out of other orchestrators'
/// containers in the same containerd namespace, and how reconciliation
/// recovers the workload id after a Kamaji restart.
fn labels_for(spec: &WorkloadSpec, id: &WorkloadId) -> HashMap<String, String> {
    let mut labels = spec.labels.clone();
    labels.insert("yah.ident".to_string(), id.as_str().to_string());
    labels.insert("yah.name".to_string(), spec.name.clone());
    labels.insert("yah.tier".to_string(), spec.tier.0.clone());
    labels
}

/// Translate a containerd task status code to a wire `WorkloadState`.
///
/// Containerd codes per the protobuf definition:
///   0 = Unknown, 1 = Created, 2 = Running, 3 = Stopped, 4 = Paused, 5 = Pausing
fn map_task_state(code: i32) -> WorkloadState {
    match code {
        1 => WorkloadState::Pending,
        2 => WorkloadState::Running,
        3 => WorkloadState::Exited,
        4 | 5 => WorkloadState::Draining,
        _ => WorkloadState::Failed,
    }
}

/// One round-trip to fetch a container's task status. Returns `Ok(None)` if
/// the container exists but has no task (e.g. created-but-not-started).
async fn get_task_status(
    tasks: &mut TasksClient<Channel>,
    namespace: &str,
    container_id: &str,
) -> anyhow::Result<Option<(i32, u32)>> {
    use containerd_client::services::v1::GetRequest;
    let req = GetRequest {
        container_id: container_id.to_string(),
        exec_id: String::new(),
    };
    let req = with_namespace!(req, namespace);
    match tasks.get(req).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            let process = inner.process;
            match process {
                Some(p) => Ok(Some((p.status, p.pid))),
                None => Ok(None),
            }
        }
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!("task get failed: {e}")),
    }
}

/// Validate the spec before dispatching to containerd. Mirrors the parity
/// floor in [`crate::native::SandboxPlan::from_spec`] — unresolved
/// `FromSecret` / `FromMesh` env values are yubaba's responsibility; if
/// they reach Kamaji it's a bug in yubaba's admission layer.
fn validate_spec_for_constable(spec: &WorkloadSpec) -> Result<(), BackendError> {
    // Host networking is a privileged escape hatch: it drops the network
    // isolation every other workload gets, letting the container bind host
    // ports directly. Guard it to the infra tier so an ordinary tenant
    // workload cannot request it. (Bind mounts are gated the same way in
    // workload_spec::validate::shape.)
    if spec.wants_host_network() && spec.tier.0 != "infra" {
        return Err(BackendError::InvalidSpec(format!(
            "workload requests host networking (annotation {}={}) but tier is {:?}; \
             host networking is only permitted for tier=\"infra\"",
            workload_spec::HOST_NETWORK_ANNOTATION,
            workload_spec::HOST_NETWORK_VALUE,
            spec.tier.0,
        )));
    }

    for env in &spec.env {
        match &env.value {
            EnvValue::Literal { .. } => {}
            EnvValue::FromSecret { secret, .. } => {
                return Err(BackendError::InvalidSpec(format!(
                    "env {} carries an unresolved FromSecret({secret}) — yubaba must resolve before Deploy",
                    env.name
                )));
            }
            EnvValue::FromMesh { ident, .. } => {
                return Err(BackendError::InvalidSpec(format!(
                    "env {} carries an unresolved FromMesh({}) — yubaba must resolve before Deploy",
                    env.name, ident.0
                )));
            }
        }
    }
    Ok(())
}

/// Build the OCI runtime spec. Centralises the WorkloadSpec → OCI mapping
/// so both backends (this one, and the future docker-socket backend used in
/// pond) apply the same enforcement — capabilities default-drop, no-new-
/// privileges, cgroup path under `/yah/<name>`, tmpfs `/tmp` + `/dev`.
/// Compute the OCI rootfs chainID from a layer set's `diff_ids`, matching
/// containerd's `identity.ChainID`: fold sha256 over `"{prev} {next}"` of the
/// full `sha256:...` digest strings. The committed snapshot of an unpacked
/// image is keyed by this chainID — it's the `parent` for the active snapshot
/// a task runs on (R563 REMAINING 2 — parity with kamaji-core::containerd).
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

fn build_oci_spec(spec: &WorkloadSpec) -> serde_json::Value {
    let env: Vec<String> = spec
        .env
        .iter()
        .filter_map(|e| match &e.value {
            EnvValue::Literal { value } => Some(format!("{}={}", e.name, value)),
            _ => None, // validate_spec_for_constable rejects these
        })
        .collect();

    let process = serde_json::json!({
        "terminal": false,
        "user": { "uid": 0, "gid": 0 },
        "args": spec.command.clone().unwrap_or_default(),
        "env": env,
        "cwd": spec.workdir.as_ref()
            .and_then(|p| p.to_str())
            .unwrap_or("/"),
        // Default-deny capabilities — workloads that need elevated caps
        // declare them in a future spec field. CAP_NET_BIND_SERVICE is kept
        // so low-port HTTP listeners work without an explicit opt-in (the
        // expectation in W154 §"Runtime parity contract").
        "capabilities": {
            "bounding":  ["CAP_NET_BIND_SERVICE"],
            "effective": ["CAP_NET_BIND_SERVICE"],
            "permitted": ["CAP_NET_BIND_SERVICE"],
            "ambient":   [],
        },
        "rlimits": [{
            "type": "RLIMIT_NOFILE",
            "hard": 1024_u32,
            "soft": 1024_u32,
        }],
        "noNewPrivileges": true,
    });

    // Namespaces: every workload is isolated by default. Host networking is a
    // guarded opt-in (yah.network=host on tier=infra — enforced upstream in
    // validate_spec_for_constable): we simply OMIT the network namespace so
    // runc leaves the container in the host's netns. The container then binds
    // host ports directly, which is how a single-tenant runner box lets an
    // on-host Cloudflare tunnel reach 127.0.0.1:<port> without CNI/bridge
    // plumbing. pid/ipc/uts/mount stay isolated regardless.
    let mut namespaces = vec![serde_json::json!({ "type": "pid" })];
    if !spec.wants_host_network() {
        namespaces.push(serde_json::json!({ "type": "network" }));
    }
    namespaces.push(serde_json::json!({ "type": "ipc" }));
    namespaces.push(serde_json::json!({ "type": "uts" }));
    namespaces.push(serde_json::json!({ "type": "mount" }));

    // /sys: a fresh `sysfs` mount requires owning the network namespace, which
    // fails when the container shares the host netns (host networking). Match
    // what runc does in that case — bind-mount the host /sys read-only instead.
    // Isolated netns gets a fresh sysfs; host netns gets a recursive ro bind of
    // /sys (R563 REMAINING 2 — parity with kamaji-core::containerd).
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

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        EnvVar, ExposeSpec, ImageRef, MeshExpose, MeshIdent, MeshLookup, Millis,
        ResourceLimits, RestartPolicy, SchemaVersion, StopPolicy, TierTag,
    };

    fn make_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.into(),
            image: ImageRef {
                registry: "ghcr.io".into(),
                repository: "example/svc".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("public".into()),
            replicas: 1,
            command: Some(vec!["/usr/bin/svc".into()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![EnvVar {
                name: "FOO".into(),
                value: EnvValue::Literal {
                    value: "bar".into(),
                },
            }],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                cpu_shares: 1024,
                memory_mb: 512,
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name.into()),
                    ports: vec![8080],
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        }
    }

    #[test]
    fn image_ref_emits_tag_and_digest() {
        let mut spec = make_spec("svc");
        spec.image.digest = "sha256:deadbeef".into();
        assert_eq!(
            ContainerdBackend::image_ref(&spec),
            "ghcr.io/example/svc:latest@sha256:deadbeef"
        );
    }

    #[test]
    fn validate_rejects_unresolved_from_secret() {
        let mut spec = make_spec("svc");
        spec.env.push(EnvVar {
            name: "DB_PASS".into(),
            value: EnvValue::FromSecret {
                secret: "db-creds".into(),
                key: "password".into(),
            },
        });
        let err = validate_spec_for_constable(&spec).unwrap_err();
        assert!(matches!(err, BackendError::InvalidSpec(_)));
        let msg = err.to_string();
        assert!(msg.contains("FromSecret"), "msg: {msg}");
        assert!(msg.contains("yubaba must resolve"), "msg: {msg}");
    }

    #[test]
    fn validate_rejects_unresolved_from_mesh() {
        let mut spec = make_spec("svc");
        spec.env.push(EnvVar {
            name: "PEER".into(),
            value: EnvValue::FromMesh {
                ident: MeshIdent("peer".into()),
                kind: MeshLookup::Url,
            },
        });
        let err = validate_spec_for_constable(&spec).unwrap_err();
        assert!(matches!(err, BackendError::InvalidSpec(_)));
        assert!(err.to_string().contains("FromMesh"));
    }

    #[test]
    fn validate_passes_pure_literals() {
        let spec = make_spec("svc");
        validate_spec_for_constable(&spec).unwrap();
    }

    #[test]
    fn oci_spec_drops_capabilities_to_net_bind_only() {
        let spec = make_spec("svc");
        let oci = build_oci_spec(&spec);
        let caps = &oci["process"]["capabilities"];
        assert_eq!(caps["bounding"], serde_json::json!(["CAP_NET_BIND_SERVICE"]));
        assert_eq!(caps["ambient"], serde_json::json!([]));
        assert_eq!(oci["process"]["noNewPrivileges"], serde_json::json!(true));
    }

    /// Helper: set the host-network opt-in annotation.
    fn with_host_network(mut spec: WorkloadSpec) -> WorkloadSpec {
        spec.annotations.insert(
            workload_spec::HOST_NETWORK_ANNOTATION.into(),
            workload_spec::HOST_NETWORK_VALUE.into(),
        );
        spec
    }

    fn netns_present(oci: &serde_json::Value) -> bool {
        oci["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["type"] == "network")
    }

    #[test]
    fn oci_spec_isolates_network_by_default() {
        let oci = build_oci_spec(&make_spec("svc"));
        assert!(netns_present(&oci), "default workload must get an isolated netns");
    }

    #[test]
    fn oci_spec_host_network_omits_netns() {
        let oci = build_oci_spec(&with_host_network(make_spec("svc")));
        assert!(
            !netns_present(&oci),
            "yah.network=host must omit the network namespace so the container shares the host netns"
        );
        // The other namespaces stay isolated — only networking is shared.
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

    /// Find the `/sys` entry in the OCI mounts list.
    fn sys_mount(oci: &serde_json::Value) -> serde_json::Value {
        oci["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/sys")
            .expect("/sys mount must be present")
            .clone()
    }

    #[test]
    fn oci_spec_default_sys_is_fresh_sysfs() {
        // Isolated netns owns its own sysfs — a fresh `sysfs` mount works.
        let sys = sys_mount(&build_oci_spec(&make_spec("svc")));
        assert_eq!(sys["type"], "sysfs");
        assert_eq!(sys["source"], "sysfs");
    }

    #[test]
    fn oci_spec_host_network_binds_host_sys_ro() {
        // Sharing the host netns means a fresh sysfs would fail (it needs to
        // own the netns); runc bind-mounts the host /sys read-only instead.
        let sys = sys_mount(&build_oci_spec(&with_host_network(make_spec("svc"))));
        assert_eq!(sys["type"], "bind");
        assert_eq!(sys["source"], "/sys");
        let opts: Vec<&str> = sys["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        assert!(opts.contains(&"rbind"), "host /sys bind must be recursive");
        assert!(opts.contains(&"ro"), "host /sys bind must be read-only");
    }

    #[test]
    fn validate_rejects_host_network_for_non_infra_tier() {
        // make_spec is tier=public; host networking must be refused.
        let err = validate_spec_for_constable(&with_host_network(make_spec("svc"))).unwrap_err();
        assert!(matches!(err, BackendError::InvalidSpec(_)));
        let msg = err.to_string();
        assert!(msg.contains("host networking"), "msg: {msg}");
        assert!(msg.contains("infra"), "msg: {msg}");
    }

    #[test]
    fn validate_allows_host_network_for_infra_tier() {
        let mut spec = with_host_network(make_spec("svc"));
        spec.tier = TierTag("infra".into());
        validate_spec_for_constable(&spec).unwrap();
    }

    #[test]
    fn oci_spec_carries_literal_env_only() {
        let mut spec = make_spec("svc");
        spec.env.push(EnvVar {
            name: "MESH_IP".into(),
            value: EnvValue::FromMesh {
                ident: MeshIdent("self".into()),
                kind: MeshLookup::Url,
            },
        });
        // build_oci_spec is a pure mapper — it does NOT validate. It just
        // filters non-literal env. validate_spec_for_constable runs first.
        let oci = build_oci_spec(&spec);
        let env = oci["process"]["env"].as_array().unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].as_str().unwrap(), "FOO=bar");
    }

    #[test]
    fn labels_stamp_identity_and_tier() {
        let spec = make_spec("svc");
        let labels = labels_for(&spec, &WorkloadId::new("svc"));
        assert_eq!(labels.get("yah.ident").map(|s| s.as_str()), Some("svc"));
        assert_eq!(labels.get("yah.name").map(|s| s.as_str()), Some("svc"));
        assert_eq!(labels.get("yah.tier").map(|s| s.as_str()), Some("public"));
    }

    #[test]
    fn map_task_state_covers_known_codes() {
        assert_eq!(map_task_state(1), WorkloadState::Pending);
        assert_eq!(map_task_state(2), WorkloadState::Running);
        assert_eq!(map_task_state(3), WorkloadState::Exited);
        assert_eq!(map_task_state(4), WorkloadState::Draining);
        assert_eq!(map_task_state(5), WorkloadState::Draining);
        assert_eq!(map_task_state(0), WorkloadState::Failed);
        assert_eq!(map_task_state(99), WorkloadState::Failed);
    }

    // ── R406-T10: FIFO log fan-in ─────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_fifo_creates_a_named_pipe_at_the_path() {
        use nix::sys::stat::{stat, SFlag};
        let tmp = tempfile::TempDir::new().unwrap();
        let fifo = tmp.path().join("stdout.fifo");
        ensure_fifo(&fifo).unwrap();
        let st = stat(&fifo).unwrap();
        assert!(SFlag::from_bits_truncate(st.st_mode).contains(SFlag::S_IFIFO));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_fifo_is_idempotent_when_called_twice() {
        let tmp = tempfile::TempDir::new().unwrap();
        let fifo = tmp.path().join("stdout.fifo");
        ensure_fifo(&fifo).unwrap();
        ensure_fifo(&fifo).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_fifo_refuses_a_path_holding_a_regular_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("not_a_fifo");
        std::fs::write(&path, b"hi").unwrap();
        let err = ensure_fifo(&path).unwrap_err();
        assert!(
            err.to_string().contains("not a FIFO"),
            "err: {err}"
        );
    }

    /// End-to-end forwarder path: open a FIFO, spawn the forwarder, simulate
    /// containerd's shim by opening the write side ourselves and pumping a
    /// few lines. Asserts that each line lands in the sink with the right
    /// workload id and stream tag.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fifo_forwarder_emits_lines_written_by_a_separate_writer() {
        use crate::journal::{LogSink, Stream, VecSink};
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let fifo = tmp.path().join("stdout.fifo");
        ensure_fifo(&fifo).unwrap();

        let sink: Arc<VecSink> = Arc::new(VecSink::new());
        let handle = spawn_forwarder(
            sink.clone() as Arc<dyn LogSink>,
            WorkloadId::new("svc-fifo"),
            Stream::Stdout,
            &fifo,
        )
        .unwrap();

        // Open the writer side after the forwarder has the reader side open
        // (spawn_forwarder opened it before returning). Write a few lines
        // and close to model a workload exiting cleanly.
        let mut writer = tokio::net::unix::pipe::OpenOptions::new()
            .open_sender(&fifo)
            .unwrap();
        writer.write_all(b"hello\nworld\n").await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        // Poll briefly for the lines to land — read_until is async and runs
        // inside the spawned task, so give it a few ticks. Bounded so a
        // bug doesn't wedge the test suite.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if sink.entries().len() >= 2 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "forwarder did not surface both lines within 2s; got {:?}",
                    sink.entries()
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.abort();

        let entries = sink.entries();
        let lines: Vec<&[u8]> =
            entries.iter().map(|(_, _, l)| l.as_slice()).collect();
        assert!(lines.contains(&b"hello".as_slice()), "got: {lines:?}");
        assert!(lines.contains(&b"world".as_slice()), "got: {lines:?}");
        let (wid, stream, _) = &entries[0];
        assert_eq!(wid, &WorkloadId::new("svc-fifo"));
        assert_eq!(*stream, Stream::Stdout);
    }

    /// Aborting the forwarder handle prevents subsequent writes from landing
    /// in the sink — teardown's cancellation contract.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn aborted_forwarder_stops_consuming_further_writes() {
        use crate::journal::{LogSink, Stream, VecSink};
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let fifo = tmp.path().join("stdout.fifo");
        ensure_fifo(&fifo).unwrap();

        let sink: Arc<VecSink> = Arc::new(VecSink::new());
        let handle = spawn_forwarder(
            sink.clone() as Arc<dyn LogSink>,
            WorkloadId::new("svc-abort"),
            Stream::Stdout,
            &fifo,
        )
        .unwrap();

        // Abort before any writes. Give the runtime a moment to actually
        // tear the task down.
        handle.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now write a line. The forwarder task is gone, so nothing should
        // appear in the sink. We can't synchronously prove "task is gone"
        // but the empty sink after a fair wait is the operative signal.
        let mut writer = tokio::net::unix::pipe::OpenOptions::new()
            .open_sender(&fifo)
            .unwrap();
        writer.write_all(b"too-late\n").await.unwrap();
        drop(writer);
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            sink.entries().is_empty(),
            "expected no entries after abort, got {:?}",
            sink.entries()
        );
    }
}

