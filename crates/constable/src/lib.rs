//! Constable — yah's relocatable workload-supervisor primitive.
//!
//! This crate is the public surface of Constable (per W199): the trait one
//! caller hand-rolls against (`Constable`), the typed inputs/outputs it
//! exchanges with the runtime backend, and the `Backend` enum tagging which
//! concrete backend a given Constable instance is driving.
//!
//! ## Two deployment shapes
//!
//! Per W199 §The move, the same trait is used in both shapes:
//!
//! - **Inlined** — the caller holds `Arc<dyn Constable>` directly. Used by
//!   the desktop app where Constable shares the Tauri process tree.
//! - **Sibling** — the caller holds a `ConstableClient` that speaks the
//!   W154 postcard-over-UDS protocol to a separate `constable.service`
//!   process. Used by warden on cluster hosts.
//!
//! T1 only ships the public surface; the inlined / sibling constructors and
//! the backend impls land in R484-T2 / T4 / T5.
//!
//! ## Package naming
//!
//! Package is `constable-core` (not `constable`) because `app/yah/constable`
//! already claims the `constable` workspace package name. Once R484-T5
//! rewires that binary to depend on this crate, a follow-up may rename one
//! of them. The crate path (`crates/yah/constable/`) matches the W199 plan.
//!
//! @arch:see(.yah/docs/working/W199-constable-universal-supervisor.md)
//! @arch:see(.yah/docs/working/W154-warden-dual-runtime.md)

pub mod inlined;
pub mod probe;

#[cfg(feature = "sibling")]
pub mod sibling;

pub use inlined::Inlined;
pub use probe::{BackendAvailability, BackendProbe};

#[cfg(feature = "containerd-integration")]
pub mod containerd;

#[cfg(feature = "docker-integration")]
pub mod docker;

#[cfg(feature = "testing")]
pub mod fake;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_core::Stream;
use serde::{Deserialize, Serialize};

pub use workload_spec::{MeshIdent, WorkloadSpec};

// ── Backend tag ───────────────────────────────────────────────────────────────

/// Which concrete runtime a given `Constable` instance is driving.
///
/// Per W199 §Backend availability, Constable carries three backends. The
/// `Native` backend is always available (fork+exec for musl-static Rust
/// workloads); `Containerd` and `Docker` are probed at init and may be
/// absent on a given host. Workloads that request an absent backend fail
/// with a structured [`BackendUnavailable`] error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// Direct fork+exec+cgroup+pidfd of a musl-static Rust binary. Always
    /// available on Linux; returns `Unsupported` on other hosts.
    Native,
    /// gRPC to a local containerd socket. Standard on fleet hosts.
    Containerd,
    /// Docker CLI shell-out — dev backend for OrbStack / Docker Desktop /
    /// Colima. The pond outer substrate uses this.
    Docker,
}

/// Reported when a workload requests a backend that this Constable instance
/// has not initialized. Carries a human-readable install hint so the camp /
/// desktop can surface "install Docker Desktop" rather than just a generic
/// error.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("backend {backend:?} is not available on this host: {detail}")]
pub struct BackendUnavailable {
    pub backend: Backend,
    pub detail: String,
    /// Optional install hint (e.g. "Install Docker Desktop or OrbStack").
    pub install_hint: Option<String>,
}

// ── Log stream type alias ─────────────────────────────────────────────────────

/// Boxed, pinned log stream returned by [`Constable::stream_logs`].
pub type LogStream = Pin<Box<dyn Stream<Item = LogEvent> + Send + 'static>>;

// ── Supporting types ──────────────────────────────────────────────────────────

/// Mesh context passed to `deploy_workload` for backends that wire workloads
/// onto a cluster-internal WireGuard mesh.
///
/// For inlined desktop deployments where there is no mesh, callers pass
/// [`MeshAssignment::inlined`] (a sentinel value with `wg_listen_port = 0`
/// and an empty `peers` list). T2 will reconcile this with warden's existing
/// `mesh::MeshAssignment` type during the carve-out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshAssignment {
    /// Mesh-plane IP. For inlined desktop, an unused loopback-ish address;
    /// for cluster nodes, assigned from raft's `100.64.0.0/10` pool.
    pub mesh_ip: Ipv4Addr,
    pub wg_private_key: String,
    pub wg_listen_port: u16,
    pub peers: Vec<WireguardPeer>,
    pub netns_name: Option<String>,
}

impl MeshAssignment {
    /// Sentinel assignment for inlined desktop / single-node use. No
    /// WireGuard configuration is applied — `has_wireguard()` returns false.
    pub fn inlined(mesh_ip: Ipv4Addr) -> Self {
        MeshAssignment {
            mesh_ip,
            wg_private_key: String::new(),
            wg_listen_port: 0,
            peers: Vec::new(),
            netns_name: None,
        }
    }

    /// Pre-W199 name for [`MeshAssignment::inlined`]. Kept as an alias so
    /// warden's existing call sites compile without churn during the carve-
    /// out (R484-T2). New code should prefer `inlined()`.
    pub fn stub(mesh_ip: Ipv4Addr) -> Self {
        Self::inlined(mesh_ip)
    }

    pub fn has_wireguard(&self) -> bool {
        !self.wg_private_key.is_empty()
    }
}

/// One WireGuard peer entry in the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardPeer {
    pub public_key: String,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpAddr>,
}

/// Result of a successful `deploy_workload` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    pub container_id: String,
    pub mesh_ip: Ipv4Addr,
    pub task_pid: u32,
}

/// Point-in-time state snapshot for one deployed workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadState {
    pub ident: MeshIdent,
    pub container_id: String,
    pub status: WorkloadStatus,
    pub mesh_ip: Option<Ipv4Addr>,
}

/// Lifecycle status of a deployed workload.
///
/// `Restarting` subsumes pond-side `Degraded` per R471 — both encoded
/// "workload is in-flight restarting", but `Restarting` carries the richer
/// payload (exit code + count + finished-at). Backends populate differently:
///
/// - `Backend::Containerd` synthesizes from an in-supervisor `RestartLedger`
///   (containerd has no native restart-count signal).
/// - `Backend::Docker` reads `docker inspect .State.Restarting` /
///   `RestartCount` / `ExitCode` / `FinishedAt` directly.
/// - `Backend::Native` is supervisor-driven: the fork+exec loop records
///   each exit and re-execs per `RestartPolicy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkloadStatus {
    Pending,
    Running,
    Stopping,
    Stopped,
    Restarting {
        last_exit_code: i32,
        restart_count: u32,
        last_finished_at_unix_ms: u64,
    },
    Failed {
        reason: String,
    },
}

impl WorkloadStatus {
    /// `true` for states the supervisor will not advance out of on its own.
    /// `Restarting` is **not** terminal — the runtime is actively cycling.
    pub fn is_terminal(&self) -> bool {
        matches!(self, WorkloadStatus::Stopped | WorkloadStatus::Failed { .. })
    }
}

/// Options controlling which log lines `stream_logs` returns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogOpts {
    pub tail: Option<u64>,
    pub follow: bool,
    pub stream: Option<LogStreamKind>,
}

/// Which stdio stream a log line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStreamKind {
    Stdout,
    Stderr,
}

/// One log line emitted by a workload container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp_ms: u64,
    pub ident: MeshIdent,
    pub stream: LogStreamKind,
    pub message: String,
    pub correlation_id: Option<String>,
}

impl LogEvent {
    pub fn plain(ident: MeshIdent, stream: LogStreamKind, message: impl Into<String>) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        LogEvent {
            timestamp_ms,
            ident,
            stream,
            message: message.into(),
            correlation_id: None,
        }
    }
}

/// Aggregate health of one backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeHealth {
    /// `true` when the backend socket / runtime is reachable and healthy.
    pub ok: bool,
    /// Backend version string when available (e.g. containerd `"1.7.14"`).
    pub version: Option<String>,
    /// Human-readable detail for degraded / failed states.
    pub detail: Option<String>,
}

// ── Stateful-service contract (W195 §3) ───────────────────────────────────────

/// Owned declaration of a service's persistent SQL state (W195 §3).
///
/// Every yah service that owns `.turso` files registers one of these with
/// constable so backup, disaster recovery, and regional rebalancing are
/// handled generically. `files` paths are relative to the service's root
/// (camp_root for camp-local services, workload data dir for pond services).
///
/// Build from a compile-time [`BuiltinService`] descriptor via
/// `BuiltinService::contract()`, or construct directly for dynamic services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefulServiceContract {
    /// Human-readable service name, unique within a camp / pond.
    pub name: String,
    /// Relative paths of `.turso` files owned by this service.
    pub files: Vec<String>,
    /// Optional SQL vending endpoint (Mode B per W195 §1).
    pub vend_endpoint: Option<String>,
    /// Opaque schema version used by constable for drift detection. Typically
    /// an ISO-8601 date string matching when the schema was last changed.
    pub schema_version: String,
    /// Optional R2 (or compatible) backup target pattern, e.g.
    /// `"r2://yah-backups/{name}/{file}"`. `{file}` is replaced with the
    /// basename of each entry in `files`.
    pub backup_target: Option<String>,
}

/// Compile-time descriptor for a built-in (always-present) yah service.
///
/// Built-in services ship as Rust constants — their declarations don't live in
/// any user-visible `.yah/` file because they're identical across all yah
/// installs. Call [`BuiltinService::contract`] at runtime to obtain an owned
/// [`StatefulServiceContract`] suitable for registering with constable.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinService {
    pub name: &'static str,
    /// Relative file paths (from camp_root / service root).
    pub files: &'static [&'static str],
    pub vend_endpoint: Option<&'static str>,
    /// ISO-8601 date of last schema change.
    pub schema_version: &'static str,
    pub backup_target: Option<&'static str>,
}

impl BuiltinService {
    pub const fn new(
        name: &'static str,
        files: &'static [&'static str],
        schema_version: &'static str,
    ) -> Self {
        Self {
            name,
            files,
            vend_endpoint: None,
            schema_version,
            backup_target: None,
        }
    }

    /// Convert to an owned [`StatefulServiceContract`] for runtime use.
    pub fn contract(&self) -> StatefulServiceContract {
        StatefulServiceContract {
            name: self.name.to_string(),
            files: self.files.iter().map(|s| s.to_string()).collect(),
            vend_endpoint: self.vend_endpoint.map(|s| s.to_string()),
            schema_version: self.schema_version.to_string(),
            backup_target: self.backup_target.map(|s| s.to_string()),
        }
    }
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// The relocatable workload-supervision contract.
///
/// One trait, two deployment shapes (W199): inlined (caller holds
/// `Arc<dyn Constable>`) or sibling (caller holds a `ConstableClient` that
/// implements this trait by forwarding over UDS).
///
/// The 7 methods map to the workload lifecycle: deploy, list, get, log,
/// restart, teardown, health. The trait is intentionally *not*
/// compose-shipper-shaped — callers hand it typed [`WorkloadSpec`] values,
/// not compose YAML.
///
/// Carved out from warden's pre-W199 `ContainerRuntime` trait. R484-T2 moves
/// the concrete `runtime::{native, containerd, docker}` impls here.
#[async_trait]
pub trait Constable: Send + Sync {
    /// Which backend this Constable instance is driving. Used by callers
    /// that need to branch on capability (e.g. "show 'install Docker' UI
    /// when Backend::Docker is unavailable").
    fn backend(&self) -> Backend;

    /// Deploy a workload described by `spec` onto the cluster mesh as
    /// described by `mesh`.
    async fn deploy_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> anyhow::Result<DeployResult>;

    /// List all workloads currently known to this Constable instance.
    async fn list_workloads(&self) -> anyhow::Result<Vec<WorkloadState>>;

    /// Get the current state of one workload by mesh identity. Returns
    /// `Ok(None)` when no workload with that identity is found.
    async fn get_workload(
        &self,
        ident: &MeshIdent,
    ) -> anyhow::Result<Option<WorkloadState>>;

    /// Open a log stream for the named workload.
    async fn stream_logs(
        &self,
        ident: &MeshIdent,
        opts: LogOpts,
    ) -> anyhow::Result<LogStream>;

    /// Restart a running workload (SIGTERM + grace, then fresh task).
    async fn restart_workload(&self, ident: &MeshIdent) -> anyhow::Result<()>;

    /// Tear down a workload completely. Idempotent — returns `Ok(())` if the
    /// workload is already gone.
    async fn teardown_workload(&self, ident: &MeshIdent) -> anyhow::Result<()>;

    /// Query the health of the underlying backend. Used by the camp / warden
    /// `/health` endpoint to report whether the backend socket is reachable.
    async fn health(&self) -> anyhow::Result<RuntimeHealth>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_status_terminal_matrix() {
        assert!(!WorkloadStatus::Pending.is_terminal());
        assert!(!WorkloadStatus::Running.is_terminal());
        assert!(!WorkloadStatus::Stopping.is_terminal());
        assert!(WorkloadStatus::Stopped.is_terminal());
        assert!(!WorkloadStatus::Restarting {
            last_exit_code: 2,
            restart_count: 3,
            last_finished_at_unix_ms: 1,
        }
        .is_terminal());
        assert!(WorkloadStatus::Failed {
            reason: "boom".into()
        }
        .is_terminal());
    }

    #[test]
    fn mesh_assignment_inlined_has_no_wireguard() {
        let m = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        assert!(!m.has_wireguard());
        assert!(m.peers.is_empty());
        assert_eq!(m.wg_listen_port, 0);
    }

    #[test]
    fn backend_serde_round_trip() {
        let json = serde_json::to_string(&Backend::Containerd).unwrap();
        assert_eq!(json, "\"containerd\"");
        let parsed: Backend = serde_json::from_str("\"docker\"").unwrap();
        assert_eq!(parsed, Backend::Docker);
    }
}
