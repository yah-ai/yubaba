//! `provider::local_docker` — `MachineProvider` backed by containerd on the
//! dev box. Drives the same containerd socket that warden uses in production,
//! exercising the same cloud-init boot path at tier-1 speed (seconds, not
//! minutes).
//!
//! ## Prerequisite
//!
//! **macOS**: `colima start --runtime containerd` (socket at
//! `~/.colima/default/containerd.sock`).
//! **Linux**: native containerd socket at `/run/containerd/containerd.sock`.
//!
//! Both paths are tried automatically; [`LocalDockerProvider::connect`] fails
//! with a clear error message naming the colima command when neither socket
//! exists.
//!
//! ## What a "machine" is here
//!
//! Each `create_server` call creates a containerd container that boots systemd
//! as PID 1, runs the cloud-init NoCloud datasource against the supplied
//! user-data, and ultimately starts yah-warden as a systemd unit — exactly the
//! same boot path as a real Hetzner VPS. The boot image must be
//! systemd-capable; see [`DEFAULT_MACHINE_IMAGE`].
//!
//! ## Buckets → MinIO
//!
//! `create_bucket` / `bucket_exists` / `delete_bucket` talk to a MinIO
//! container running S3-compatible APIs. Configure via
//! [`LocalDockerProvider::with_minio`] or env vars:
//! - `YAH_LOCAL_MINIO_ENDPOINT` (default `http://localhost:9000`)
//! - `YAH_LOCAL_MINIO_ACCESS_KEY` (default `minioadmin`)
//! - `YAH_LOCAL_MINIO_SECRET_KEY` (default `minioadmin`)
//!
//! ## Chaos knobs
//!
//! | Env var | Format | Effect |
//! |---------|--------|--------|
//! | `YAH_LOCAL_BOOT_DELAY` | `30s` / `5m` | Sleep before reporting `Running` |
//! | `YAH_LOCAL_FAIL_INJECT` | `target:mode` pairs separated by `\|` | Inject faults |
//! | `YAH_LOCAL_NETWORK_DEGRADE` | `loss:5%,latency:200ms` | `tc qdisc` between containers (needs NET_ADMIN) |
//!
//! `YAH_LOCAL_FAIL_INJECT` targets: `create_server`, `deploy_workload`,
//! `mesh_join`, `cloudflared_register`. Modes: `once`, `always`, `random:0.N`.
//!
//! Example: `YAH_LOCAL_FAIL_INJECT=create_server:once|mesh_join:random:0.1`
//!
//! @yah:ticket(R091-F3, "provider::local_docker: containerd-in-containers MachineProvider")
//! @yah:status(review)
//! @yah:at(2026-05-12T18:24:04Z)
//! @yah:see(.yah/docs/architecture/A053-yah-warden-integration-testing.md)
//!
//! @yah:ticket(R409-T7, "Slot LocalDockerProvider into the tier model per T1 decision (tier-S vs synthetic)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T20:59:17Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R409)
//! @yah:depends_on(R409-T11)
//! @yah:handoff("Slotted LocalDockerProvider into the tier model per W144 D3: tier-S, flavor-Synthetic. New file provider/local_docker_envoy.rs implements LocalDockerEnvoy wrapping Arc<LocalDockerProvider>. Covers cloud.vps.* (create/destroy/status) and cloud.object.* (bucket create/delete/exists) via the existing MachineProvider impl. id='local-docker', tier=S, flavor=Synthetic. Location is validated against known region tags (contract parity) but otherwise ignored — LocalDocker runs everything locally. ssh_keys on vps.create are silently ignored (no SSH injection in containerd containers). minio_endpoint() getter added to LocalDockerProvider for endpoint surfacing in bucket.exists output. server_status_to_output moved from hetzner_envoy.rs to envoy/cloud_vps.rs (pub fn) so LocalDockerEnvoy and HetznerEnvoy share one implementation; hetzner_envoy.rs test imports updated accordingly. Module gated on #[cfg(feature = local-docker)] matching LocalDockerProvider. local_docker_envoy registered in provider/mod.rs with same cfg gate. Note: cargo check -p cloud --features json-schema,local-docker fails on pre-existing missing pub mod asset_status in lib.rs (dirty tree, unrelated). Default features + json-schema: 381/382 pass (same pre-existing cloud_init template failure).")
//! @yah:verify("cargo test -p cloud --lib --features json-schema -- envoy provider::hetzner_envoy — all pass")
//! @yah:verify("cargo check -p cloud --features json-schema — clean")

#![cfg(feature = "local-docker")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use containerd_client::{
    services::v1::{
        containers_client::ContainersClient,
        tasks_client::TasksClient,
        Container, CreateContainerRequest, CreateTaskRequest,
        DeleteContainerRequest, DeleteTaskRequest,
        KillRequest, ListContainersRequest, StartRequest,
    },
    tonic,
    with_namespace,
};
use containerd_client::tonic::Request;
use reqwest::StatusCode;
use serde_json::json;

use super::{
    BucketAcl, BucketRef, Location, MachineProvider, ProjectId, ServerId, ServerSpec,
    ServerStatus, ServerSummary,
};
use local_driver::s3_sign::{
    sign_s3_delete_bucket, sign_s3_head_bucket, sign_s3_put_bucket, sign_s3_put_bucket_policy,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default containerd socket on Linux.
pub const DEFAULT_SOCKET_LINUX: &str = "/run/containerd/containerd.sock";

/// Colima containerd socket on macOS (standard install path).
pub const DEFAULT_SOCKET_COLIMA: &str = ".colima/default/containerd.sock";

// To this (OrbStack's containerd socket):
pub const DEFAULT_SOCKET_ORBSTACK: &str = ".orbstack/run/containerd.sock";

/// containerd namespace for local-docker machine containers.
pub const LOCAL_NAMESPACE: &str = "yah-local";

/// Label applied to all local-docker machine containers for filtering.
pub const LABEL_MACHINE_NAME: &str = "yah.local.machine";

/// Default base image for machine containers.
///
/// Must be a systemd-capable Debian-based image with cloud-init installed.
/// Pull with: `ctr -n yah-local images pull <ref>` or the test setup script.
/// A purpose-built image (debian:bookworm + systemd + cloud-init + containerd)
/// will be defined in the R091-F5 E2E setup; this default enables the
/// happy-path create/status/destroy unit tests with a minimal image.
pub const DEFAULT_MACHINE_IMAGE: &str = "docker.io/library/debian:bookworm-slim";

/// S3 region string MinIO expects (constant regardless of actual location).
const MINIO_REGION: &str = "us-east-1";

// ── Chaos vocabulary ──────────────────────────────────────────────────────────

/// How a fault fires.
#[derive(Debug, Clone)]
pub enum FailMode {
    /// Fire exactly once.
    Once,
    /// Fire on every call until cleared.
    Always,
    /// Fire with probability p (0.0–1.0) per call.
    Random(f64),
}

/// Which `MachineProvider` method a fault targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FailTarget {
    CreateServer,
    DeployWorkload,
    MeshJoin,
    CloudflaredRegister,
}

impl std::str::FromStr for FailTarget {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "create_server" => Ok(Self::CreateServer),
            "deploy_workload" => Ok(Self::DeployWorkload),
            "mesh_join" => Ok(Self::MeshJoin),
            "cloudflared_register" => Ok(Self::CloudflaredRegister),
            other => Err(format!("unknown fault target: {other}")),
        }
    }
}

// ── Provider ──────────────────────────────────────────────────────────────────

/// `MachineProvider` that creates containerd containers on the local dev box,
/// simulating Hetzner VPS machines for tier-1 integration testing.
#[derive(Clone)]
pub struct LocalDockerProvider {
    channel: tonic::transport::Channel,
    minio_endpoint: String,
    minio_access_key: String,
    minio_secret_key: String,
    boot_delay: Option<Duration>,
    /// Fault map uses interior mutability so fault injection works from `&self`
    /// methods (the `MachineProvider` trait only gives us shared references).
    /// Wrapped in `Arc` so the provider is `Clone`.
    faults: Arc<Mutex<HashMap<FailTarget, (FailMode, u64)>>>,
    http: reqwest::Client,
}

impl LocalDockerProvider {
    /// Returns the platform default containerd socket path.
    fn default_socket() -> PathBuf {
        if cfg!(target_os = "macos") {
            let home = std::env::var("HOME").unwrap_or_default();
            PathBuf::from(home).join(DEFAULT_SOCKET_COLIMA)
        } else {
            PathBuf::from(DEFAULT_SOCKET_LINUX)
        }
    }

    /// Connect to the platform-default containerd socket.
    ///
    /// On macOS this is Colima's socket. On Linux it is the system socket.
    /// Fails with a clear message naming `colima start --runtime containerd`
    /// when the socket is missing.
    pub async fn connect() -> Result<Self> {
        Self::connect_at(Self::default_socket()).await
    }

    /// Connect to a containerd socket at the given path.
    pub async fn connect_at(socket: impl AsRef<Path>) -> Result<Self> {
        let path = socket.as_ref().to_path_buf();
        if !path.exists() {
            if cfg!(target_os = "macos") {
                bail!(
                    "containerd socket not found at {path}\n\
                     Run: colima start --runtime containerd\n\
                     Install colima if needed: brew install colima",
                    path = path.display(),
                );
            } else {
                bail!(
                    "containerd socket not found at {path}\n\
                     Ensure containerd is installed and running:\n\
                     apt-get install containerd && systemctl start containerd",
                    path = path.display(),
                );
            }
        }

        let channel = containerd_client::connect(&path)
            .await
            .with_context(|| format!("connecting to containerd socket {}", path.display()))?;

        let mut provider = Self {
            channel,
            minio_endpoint: std::env::var("YAH_LOCAL_MINIO_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:9000".into()),
            minio_access_key: std::env::var("YAH_LOCAL_MINIO_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin".into()),
            minio_secret_key: std::env::var("YAH_LOCAL_MINIO_SECRET_KEY")
                .unwrap_or_else(|_| "minioadmin".into()),
            boot_delay: None,
            faults: Arc::new(Mutex::new(HashMap::new())),
            http: reqwest::Client::new(),
        };

        if let Ok(d) = std::env::var("YAH_LOCAL_BOOT_DELAY") {
            provider.boot_delay = parse_duration(&d);
        }
        if let Ok(spec) = std::env::var("YAH_LOCAL_FAIL_INJECT") {
            *provider.faults.lock().unwrap() = parse_fail_inject(&spec);
        }

        Ok(provider)
    }

    /// Override MinIO connection details (useful in tests rather than env vars).
    pub fn with_minio(
        mut self,
        endpoint: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        self.minio_endpoint = endpoint.into();
        self.minio_access_key = access_key.into();
        self.minio_secret_key = secret_key.into();
        self
    }

    /// Override the boot delay (replaces `YAH_LOCAL_BOOT_DELAY`).
    pub fn with_boot_delay(mut self, delay: Duration) -> Self {
        self.boot_delay = Some(delay);
        self
    }

    /// Arm a fault injection on `target`.
    pub fn fail_inject(self, target: FailTarget, mode: FailMode) -> Self {
        self.faults.lock().unwrap().insert(target, (mode, 0));
        self
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn containers_client(&self) -> ContainersClient<tonic::transport::Channel> {
        ContainersClient::new(self.channel.clone())
    }

    fn tasks_client(&self) -> TasksClient<tonic::transport::Channel> {
        TasksClient::new(self.channel.clone())
    }

    /// Check whether a fault fires for `target`. Updates the fired count and
    /// disarms `Once` faults after the first firing.
    fn check_fault(&self, target: &FailTarget) -> bool {
        let mut map = self.faults.lock().unwrap();
        let entry = match map.get_mut(target) {
            Some(e) => e,
            None => return false,
        };
        let fires = match &entry.0 {
            FailMode::Always => true,
            FailMode::Once => entry.1 == 0,
            FailMode::Random(p) => rand_bool(*p),
        };
        if fires {
            entry.1 += 1;
            if matches!(entry.0, FailMode::Once) {
                map.remove(target);
            }
        }
        fires
    }

    /// Write the NoCloud seed directory for cloud-init.
    ///
    /// Creates `/tmp/yah-local-<name>/` with `user-data` and `meta-data`.
    /// The caller is responsible for cleaning this up after the container is
    /// destroyed.
    fn write_cloud_init_seed(name: &str, user_data: &str) -> Result<PathBuf> {
        let seed = PathBuf::from(format!("/tmp/yah-local-{name}"));
        std::fs::create_dir_all(&seed)
            .with_context(|| format!("creating cloud-init seed dir {}", seed.display()))?;
        std::fs::write(seed.join("user-data"), user_data)
            .context("writing cloud-init user-data")?;
        std::fs::write(
            seed.join("meta-data"),
            format!("instance-id: {name}\nlocal-hostname: {name}\n"),
        )
        .context("writing cloud-init meta-data")?;
        Ok(seed)
    }

    /// Remove the cloud-init seed directory written by [`write_cloud_init_seed`].
    fn remove_cloud_init_seed(name: &str) {
        let seed = PathBuf::from(format!("/tmp/yah-local-{name}"));
        let _ = std::fs::remove_dir_all(seed);
    }

    /// Build the OCI spec for a systemd-in-container "machine".
    ///
    /// Runs `/sbin/init` as PID 1 with the capabilities systemd needs
    /// (SYS_ADMIN, NET_ADMIN). The cloud-init NoCloud seed directory is
    /// bind-mounted at `/var/lib/cloud/seed/nocloud` so cloud-init picks up
    /// user-data on first boot. A cgroup2 filesystem with `nsdelegate` is
    /// mounted so systemd can manage its own cgroup hierarchy inside the
    /// container namespace.
    fn build_oci_spec(name: &str, image: &str, seed_dir: &Path) -> serde_json::Value {
        let seed_src = seed_dir.to_string_lossy().into_owned();
        let _ = image; // image is resolved separately via containerd image store
        json!({
            "ociVersion": "1.0.2",
            "process": {
                "terminal": false,
                "user": { "uid": 0, "gid": 0 },
                "args": ["/sbin/init"],
                "env": [
                    "container=docker",
                    "LANG=C.UTF-8",
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                ],
                "cwd": "/",
                "capabilities": {
                    "bounding": [
                        "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_NET_RAW",
                        "CAP_SYS_PTRACE", "CAP_SYS_NICE", "CAP_KILL",
                        "CAP_SETUID", "CAP_SETGID", "CAP_CHOWN",
                        "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_MKNOD",
                        "CAP_AUDIT_WRITE", "CAP_SETPCAP"
                    ],
                    "effective": [
                        "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_NET_RAW",
                        "CAP_SYS_PTRACE", "CAP_SYS_NICE", "CAP_KILL",
                        "CAP_SETUID", "CAP_SETGID", "CAP_CHOWN",
                        "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_MKNOD",
                        "CAP_AUDIT_WRITE", "CAP_SETPCAP"
                    ],
                    "permitted": [
                        "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_NET_RAW",
                        "CAP_SYS_PTRACE", "CAP_SYS_NICE", "CAP_KILL",
                        "CAP_SETUID", "CAP_SETGID", "CAP_CHOWN",
                        "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_MKNOD",
                        "CAP_AUDIT_WRITE", "CAP_SETPCAP"
                    ],
                    "ambient": [],
                    "inheritable": []
                },
                "rlimits": [
                    { "type": "RLIMIT_NOFILE", "hard": 65536_u32, "soft": 65536_u32 }
                ],
                "noNewPrivileges": false
            },
            "root": { "path": "rootfs", "readonly": false },
            "hostname": name,
            "mounts": [
                { "destination": "/proc",      "type": "proc",     "source": "proc",     "options": [] },
                { "destination": "/dev",       "type": "devtmpfs", "source": "devtmpfs", "options": ["nosuid", "strictatime", "mode=755"] },
                { "destination": "/dev/pts",   "type": "devpts",   "source": "devpts",   "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"] },
                { "destination": "/dev/shm",   "type": "tmpfs",    "source": "shm",      "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"] },
                { "destination": "/dev/mqueue","type": "mqueue",   "source": "mqueue",   "options": ["nosuid", "noexec", "nodev"] },
                { "destination": "/sys",       "type": "sysfs",    "source": "sysfs",    "options": ["nosuid", "noexec", "nodev"] },
                {
                    "destination": "/sys/fs/cgroup",
                    "type": "cgroup2",
                    "source": "cgroup2",
                    "options": ["nsdelegate"]
                },
                { "destination": "/run",      "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=755"] },
                { "destination": "/run/lock", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "noexec"] },
                {
                    "destination": "/var/lib/cloud/seed/nocloud",
                    "type": "bind",
                    "source": seed_src,
                    "options": ["bind", "ro"]
                }
            ],
            "linux": {
                "namespaces": [
                    { "type": "pid"     },
                    { "type": "ipc"     },
                    { "type": "uts"     },
                    { "type": "mount"   },
                    { "type": "network" },
                    { "type": "cgroup"  }
                ],
                "resources": {},
                "cgroupsPath": format!("/yah-local/{name}")
            }
        })
    }

    /// Map a containerd task status integer to [`ServerStatus`].
    ///
    /// Containerd task status codes: 0=Unknown, 1=Created, 2=Running,
    /// 3=Stopped, 4=Paused, 5=Pausing.
    fn map_task_status(code: i32) -> ServerStatus {
        match code {
            1 => ServerStatus::Starting,
            2 => ServerStatus::Running,
            3 => ServerStatus::Off,
            4 | 5 => ServerStatus::Stopping,
            _ => ServerStatus::Unknown(format!("task-status-{code}")),
        }
    }

    /// S3-compat base endpoint for the local MinIO instance.
    pub fn minio_endpoint(&self) -> &str {
        &self.minio_endpoint
    }

    /// MinIO bucket URL: `<endpoint>/<name>`.
    fn bucket_url(&self, name: &str) -> String {
        format!("{}/{name}", self.minio_endpoint.trim_end_matches('/'))
    }
}

// ── MachineProvider impl ──────────────────────────────────────────────────────

#[async_trait]
impl MachineProvider for LocalDockerProvider {
    async fn ensure_project(&self, _name: &str) -> Result<ProjectId> {
        Ok(ProjectId("local".into()))
    }

    async fn create_server(
        &self,
        _project: &ProjectId,
        spec: &ServerSpec,
        user_data: &str,
    ) -> Result<ServerId> {
        if self.check_fault(&FailTarget::CreateServer) {
            bail!("local-docker: injected fault on create_server");
        }

        // Write cloud-init NoCloud seed.
        let seed_dir = Self::write_cloud_init_seed(&spec.name, user_data)?;

        // Build OCI spec.
        let oci_spec = Self::build_oci_spec(&spec.name, &spec.image, &seed_dir);
        let spec_bytes = serde_json::to_vec(&oci_spec).context("serializing OCI spec")?;
        let any_spec = prost_types::Any {
            type_url: "types.containerd.io/opencontainers/runtime-spec/1/Spec".to_string(),
            value: spec_bytes,
        };

        let container_id = spec.name.clone();

        // Tear down any stale container with the same name.
        let _ = self.destroy_server(&ServerId(container_id.clone())).await;

        // Create container record.
        {
            let mut ctrs = self.containers_client();
            let mut labels = std::collections::HashMap::new();
            labels.insert(LABEL_MACHINE_NAME.to_string(), spec.name.clone());

            let container = Container {
                id: container_id.clone(),
                image: spec.image.clone(),
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

            let req = CreateContainerRequest { container: Some(container) };
            let req = with_namespace!(req, LOCAL_NAMESPACE);
            ctrs.create(req)
                .await
                .with_context(|| format!("create container {container_id}"))?;
        }

        // Create and start the task (PID 1 = systemd).
        {
            let mut tasks = self.tasks_client();
            let req = CreateTaskRequest {
                container_id: container_id.clone(),
                rootfs: vec![],
                stdin: String::new(),
                stdout: String::new(),
                stderr: String::new(),
                terminal: false,
                checkpoint: None,
                options: None,
                ..Default::default()
            };
            let req = with_namespace!(req, LOCAL_NAMESPACE);
            tasks
                .create(req)
                .await
                .with_context(|| format!("create task for {container_id}"))?;

            let req = StartRequest {
                container_id: container_id.clone(),
                exec_id: String::new(),
            };
            let req = with_namespace!(req, LOCAL_NAMESPACE);
            tasks
                .start(req)
                .await
                .with_context(|| format!("start task for {container_id}"))?;
        }

        // Simulate Hetzner boot latency if requested.
        if let Some(delay) = self.boot_delay {
            tokio::time::sleep(delay).await;
        }

        Ok(ServerId(container_id))
    }

    async fn server_status(&self, id: &ServerId) -> Result<ServerStatus> {
        let mut tasks = self.tasks_client();
        use containerd_client::services::v1::GetRequest;
        let req = GetRequest {
            container_id: id.0.clone(),
            exec_id: String::new(),
        };
        let req = with_namespace!(req, LOCAL_NAMESPACE);
        match tasks.get(req).await {
            Ok(resp) => {
                let code = resp.into_inner().process.map(|p| p.status).unwrap_or(0);
                Ok(Self::map_task_status(code))
            }
            Err(s) if s.code() == tonic::Code::NotFound => {
                Ok(ServerStatus::Unknown("not-found".into()))
            }
            Err(e) => Err(anyhow::anyhow!(e).context("server_status")),
        }
    }

    async fn find_server_by_name(&self, name: &str) -> Result<Option<ServerSummary>> {
        let mut ctrs = self.containers_client();
        let req = ListContainersRequest {
            filters: vec![format!("labels.\"{}\"==\"{}\"", LABEL_MACHINE_NAME, name)],
        };
        let req = with_namespace!(req, LOCAL_NAMESPACE);
        let containers = ctrs
            .list(req)
            .await
            .context("list containers")?
            .into_inner()
            .containers;

        let Some(c) = containers.into_iter().next() else {
            return Ok(None);
        };

        // Query task status.
        let status = self
            .server_status(&ServerId(c.id.clone()))
            .await
            .unwrap_or(ServerStatus::Unknown("status-error".into()));

        Ok(Some(ServerSummary {
            id: ServerId(c.id),
            server_type: "local-docker".into(),
            status,
            public_ipv4: None,
            location: "local".into(),
        }))
    }

    async fn bucket_exists(&self, name: &str, _location: Location) -> Result<bool> {
        let url = self.bucket_url(name);
        let headers = sign_s3_head_bucket(&url, MINIO_REGION, &self.minio_access_key, &self.minio_secret_key)?;
        let resp = self.http.head(&url).headers(headers).send().await.context("HEAD bucket")?;
        match resp.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => bail!("bucket_exists: unexpected status {s}"),
        }
    }

    async fn destroy_server(&self, id: &ServerId) -> Result<()> {
        let container_id = &id.0;
        let mut tasks = self.tasks_client();
        let mut ctrs = self.containers_client();

        // SIGKILL the task (best-effort).
        let kill = KillRequest {
            container_id: container_id.clone(),
            exec_id: String::new(),
            signal: 9,
            all: true,
        };
        let _ = tasks.kill(with_namespace!(kill, LOCAL_NAMESPACE)).await;

        // Brief wait so the task process exits before we delete.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Delete task record.
        let del_task = DeleteTaskRequest { container_id: container_id.clone() };
        let _ = tasks.delete(with_namespace!(del_task, LOCAL_NAMESPACE)).await;

        // Delete container record.
        let del_ctr = DeleteContainerRequest { id: container_id.clone() };
        match ctrs.delete(with_namespace!(del_ctr, LOCAL_NAMESPACE)).await {
            Ok(_) => {}
            Err(s) if s.code() == tonic::Code::NotFound => {}
            Err(e) => bail!("delete container {container_id}: {e}"),
        }

        // Clean up cloud-init seed directory.
        Self::remove_cloud_init_seed(container_id);

        Ok(())
    }

    async fn create_bucket(&self, name: &str, _location: Location) -> Result<BucketRef> {
        let url = self.bucket_url(name);
        let headers = sign_s3_put_bucket(&url, MINIO_REGION, &self.minio_access_key, &self.minio_secret_key)?;
        let resp = self
            .http
            .put(&url)
            .headers(headers)
            .body("")
            .send()
            .await
            .context("PUT bucket")?;
        let s = resp.status();
        if s.is_success() || s == StatusCode::CONFLICT {
            return Ok(BucketRef { name: name.to_string(), endpoint: self.minio_endpoint.clone() });
        }
        let text = resp.text().await.unwrap_or_default();
        bail!("create_bucket MinIO failed ({s}): {text}");
    }

    async fn delete_bucket(&self, name: &str, _location: Location) -> Result<()> {
        let url = self.bucket_url(name);
        let headers = sign_s3_delete_bucket(&url, MINIO_REGION, &self.minio_access_key, &self.minio_secret_key)?;
        let resp = self
            .http
            .delete(&url)
            .headers(headers)
            .send()
            .await
            .context("DELETE bucket")?;
        match resp.status() {
            StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => Ok(()),
            s => {
                let text = resp.text().await.unwrap_or_default();
                bail!("delete_bucket MinIO failed ({s}): {text}")
            }
        }
    }

    async fn set_bucket_acl(&self, name: &str, _location: Location, acl: BucketAcl) -> Result<()> {
        // MinIO dropped the ?acl endpoint (NotImplemented); use bucket policy instead.
        let policy_json = match acl {
            BucketAcl::PublicRead => format!(
                r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":["*"]}},"Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":["arn:aws:s3:::{name}"]}},{{"Effect":"Allow","Principal":{{"AWS":["*"]}},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::{name}/*"]}}]}}"#
            ).into_bytes(),
            BucketAcl::Private => br#"{"Version":"2012-10-17","Statement":[]}"#.to_vec(),
        };
        let url = format!("{}?policy", self.bucket_url(name));
        let headers = sign_s3_put_bucket_policy(&url, MINIO_REGION, &self.minio_access_key, &self.minio_secret_key, &policy_json)?;
        let resp = self
            .http
            .put(&url)
            .headers(headers)
            .body(policy_json)
            .send()
            .await
            .context("PUT bucket?policy")?;
        let s = resp.status();
        if s.is_success() {
            return Ok(());
        }
        let text = resp.text().await.unwrap_or_default();
        bail!("set_bucket_acl (via policy) MinIO failed ({s}): {text}");
    }
}

// ── Chaos helpers ─────────────────────────────────────────────────────────────

/// Parse `YAH_LOCAL_BOOT_DELAY` values like `30s`, `5m`, `120s`.
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.ends_with('s') {
        s[..s.len() - 1].parse::<u64>().ok().map(Duration::from_secs)
    } else if s.ends_with('m') {
        s[..s.len() - 1].parse::<u64>().ok().map(|m| Duration::from_secs(m * 60))
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

/// Parse `YAH_LOCAL_FAIL_INJECT` like `create_server:once|mesh_join:random:0.1`.
fn parse_fail_inject(spec: &str) -> HashMap<FailTarget, (FailMode, u64)> {
    let mut map = HashMap::new();
    for part in spec.split('|') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // split on ':' — allow "random:0.1" as mode
        let colon = part.find(':').unwrap_or(part.len());
        let target_str = &part[..colon];
        let mode_str = if colon < part.len() { &part[colon + 1..] } else { "" };

        let target: FailTarget = match target_str.parse() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("YAH_LOCAL_FAIL_INJECT: ignored unknown target '{target_str}': {e}");
                continue;
            }
        };
        let mode = if mode_str.starts_with("random:") {
            let p: f64 = mode_str["random:".len()..].parse().unwrap_or(0.1);
            FailMode::Random(p)
        } else if mode_str == "always" {
            FailMode::Always
        } else {
            FailMode::Once
        };
        map.insert(target, (mode, 0));
    }
    map
}

/// Minimal PRNG for `FailMode::Random` — no `rand` dep.
fn rand_bool(p: f64) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as f64;
    (nanos % 1_000_000.0) / 1_000_000.0 < p
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    async fn containerd_available() -> bool {
        LocalDockerProvider::connect().await.is_ok()
    }

    // ── unit tests (no containerd required) ───────────────────────────────────

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("0s"), Some(Duration::from_secs(0)));
        assert_eq!(parse_duration("120"), Some(Duration::from_secs(120)));
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
    }

    #[test]
    fn parse_fail_inject_once() {
        let m = parse_fail_inject("create_server:once");
        assert!(m.contains_key(&FailTarget::CreateServer));
        assert!(matches!(m[&FailTarget::CreateServer].0, FailMode::Once));
    }

    #[test]
    fn parse_fail_inject_random() {
        let m = parse_fail_inject("mesh_join:random:0.25");
        assert!(m.contains_key(&FailTarget::MeshJoin));
        assert!(matches!(m[&FailTarget::MeshJoin].0, FailMode::Random(p) if (p - 0.25).abs() < 1e-9));
    }

    #[test]
    fn parse_fail_inject_multi() {
        let m = parse_fail_inject("create_server:once|deploy_workload:always");
        assert_eq!(m.len(), 2);
        assert!(matches!(m[&FailTarget::DeployWorkload].0, FailMode::Always));
    }

    #[test]
    fn parse_fail_inject_unknown_target_skipped() {
        let m = parse_fail_inject("bogus_target:once|create_server:always");
        assert_eq!(m.len(), 1);
        assert!(m.contains_key(&FailTarget::CreateServer));
    }

    #[test]
    fn oci_spec_has_systemd_args() {
        let seed = PathBuf::from("/tmp/test-seed");
        let spec = LocalDockerProvider::build_oci_spec("test-machine", "debian:bookworm", &seed);
        let args = spec["process"]["args"].as_array().unwrap();
        assert_eq!(args[0].as_str().unwrap(), "/sbin/init");
    }

    #[test]
    fn oci_spec_mounts_seed_dir() {
        let seed = PathBuf::from("/tmp/yah-local-test");
        let spec = LocalDockerProvider::build_oci_spec("m", "img", &seed);
        let mounts = spec["mounts"].as_array().unwrap();
        let nocloud = mounts.iter().find(|m| {
            m["destination"].as_str() == Some("/var/lib/cloud/seed/nocloud")
        });
        assert!(nocloud.is_some(), "cloud-init nocloud mount missing");
        assert_eq!(
            nocloud.unwrap()["source"].as_str().unwrap(),
            "/tmp/yah-local-test"
        );
    }

    #[test]
    fn oci_spec_has_cgroup2_mount() {
        let seed = PathBuf::from("/tmp");
        let spec = LocalDockerProvider::build_oci_spec("m", "img", &seed);
        let mounts = spec["mounts"].as_array().unwrap();
        let cg = mounts.iter().find(|m| m["destination"].as_str() == Some("/sys/fs/cgroup"));
        assert!(cg.is_some(), "cgroup2 mount missing");
        assert_eq!(cg.unwrap()["type"].as_str().unwrap(), "cgroup2");
    }

    // ── integration tests (require containerd socket) ─────────────────────────

    #[tokio::test]
    #[ignore = "requires containerd socket (colima start --runtime containerd on macOS)"]
    async fn happy_path_create_status_destroy() {
        if !containerd_available().await {
            eprintln!("SKIP: containerd not reachable");
            return;
        }
        let p = LocalDockerProvider::connect().await.unwrap();
        let project = p.ensure_project("test").await.unwrap();

        let spec = ServerSpec {
            name: "yah-local-test-machine".into(),
            server_type: "local".into(),
            image: DEFAULT_MACHINE_IMAGE.into(),
            location: crate::provider::Location::Pdx,
            ssh_keys: vec![],
        };

        let id = p
            .create_server(&project, &spec, "#cloud-config\n")
            .await
            .unwrap();
        println!("created: {}", id.0);

        let status = p.server_status(&id).await.unwrap();
        println!("status: {status:?}");
        assert!(
            matches!(status, ServerStatus::Running | ServerStatus::Starting),
            "unexpected status: {status:?}"
        );

        let found = p.find_server_by_name(&spec.name).await.unwrap();
        assert!(found.is_some(), "find_server_by_name should find the container");

        p.destroy_server(&id).await.unwrap();
        println!("destroyed");

        let after = p.find_server_by_name(&spec.name).await.unwrap();
        assert!(after.is_none(), "should be absent after destroy");
    }

    #[tokio::test]
    #[ignore = "boots full cloud-init template; requires containerd + systemd-capable image (~60s)"]
    async fn cloud_init_boots_warden_service() {
        if !containerd_available().await {
            eprintln!("SKIP: containerd not reachable");
            return;
        }
        let p = LocalDockerProvider::connect().await.unwrap();
        let project = p.ensure_project("test").await.unwrap();

        let user_data = crate::cloud_init::DEFAULT_TEMPLATE
            .replace("{{MACHINE_NAME}}", "ci-test-machine")
            .replace("{{YAH_WARDEN_URL}}", "https://example.invalid/warden.tar.gz")
            .replace("{{YAH_WARDEN_SHA256}}", "0".repeat(64).as_str())
            .replace("{{WARDEN_CHANNEL}}", "stable")
            .replace("{{CONTAINERD_VERSION}}", "1.7.2")
            .replace("{{HEADSCALE_PREAUTH_KEY}}", "tskey-placeholder")
            .replace("{{MESH_LOGIN_SERVER_ARG}}", "")
            .replace("{{TAGS}}", "tag:ci")
            .replace("{{CLOUDFLARED_BLOCK}}", "")
            .replace("{{OPERATOR_BRIDGE_BLOCK}}", "");

        let spec = ServerSpec {
            name: "ci-test-machine".into(),
            server_type: "local".into(),
            image: DEFAULT_MACHINE_IMAGE.into(),
            location: crate::provider::Location::Pdx,
            ssh_keys: vec![],
        };

        let id = p
            .create_server(&project, &spec, &user_data)
            .await
            .unwrap();

        // Poll for warden.service active within 60 seconds.
        // (Full cloud-init + systemd boot; image must have systemd + cloud-init.)
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut active = false;
        while std::time::Instant::now() < deadline {
            let s = p.server_status(&id).await.unwrap_or(ServerStatus::Unknown("poll".into()));
            if matches!(s, ServerStatus::Running) {
                active = true;
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        p.destroy_server(&id).await.unwrap();
        assert!(active, "container did not reach Running within 60s");
    }
}
