//! `runtime::fake` — in-memory `ContainerRuntime` for warden unit tests.
//!
//! ## Design
//!
//! `FakeRuntime` is a thread-safe in-memory stand-in for the real containerd
//! backend. Tests construct one, optionally seed it with pending log lines or
//! chaos knobs, then hand it to the orchestration code under test via the
//! `ContainerRuntime` trait.
//!
//! ### State machine
//!
//! Each deployed workload follows: `Pending → Running → Stopping → Stopped`.
//! `deploy_workload` inserts at `Pending` then immediately advances to
//! `Running` (simulating a fast boot). `teardown_workload` transitions to
//! `Stopped` then removes the entry. `restart_workload` transitions through
//! `Stopping → Running`.
//!
//! ### Log injection
//!
//! Tests push log lines via `FakeRuntime::push_log`. `stream_logs` drains the
//! per-workload queue and closes the stream — no async I/O, no files, instant.
//!
//! ### Chaos knobs
//!
//! `FakeRuntime::fail_inject(target, mode)` arms a fault on one of the trait
//! methods. The fault fires according to `FailMode`:
//! - `Once` — fires exactly once, then disarms.
//! - `Always` — fires on every call until explicitly disarmed.
//! - `Random(p)` — fires with probability `p` (0.0–1.0) on each call.
//!
//! Supported targets match `YAH_LOCAL_FAIL_INJECT` from the arch doc
//! (§Knobs for edge cases): `deploy_workload`, `teardown_workload`,
//! `restart_workload`, `list_workloads`, `get_workload`, `stream_logs`,
//! `health`.
//!
//! @yah:ticket(R091-F2, "runtime::fake: in-memory ContainerRuntime for warden orchestration unit tests")
//! @yah:status(review)
//! @yah:at(2026-05-12T18:24:04Z)
//! @yah:see(.yah/docs/architecture/A053-yah-warden-integration-testing.md)

#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio_stream::iter as stream_iter;
use workload_spec::MeshIdent;

use crate::{
    Backend, Constable, DeployResult, LogEvent, LogOpts, LogStream, LogStreamKind, MeshAssignment,
    RuntimeHealth, WorkloadState, WorkloadStatus,
};

// ── Chaos vocabulary ──────────────────────────────────────────────────────────

/// How many times a fault fires before it disarms itself.
#[derive(Debug, Clone)]
pub enum FailMode {
    /// Fire exactly once, then disarm.
    Once,
    /// Fire on every call until explicitly cleared.
    Always,
    /// Fire with this probability (0.0–1.0) on each call.
    Random(f64),
}

/// Identifies which `ContainerRuntime` method a fault targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FaultTarget {
    DeployWorkload,
    TeardownWorkload,
    RestartWorkload,
    ListWorkloads,
    GetWorkload,
    StreamLogs,
    Health,
}

impl std::str::FromStr for FaultTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "deploy_workload" => Ok(FaultTarget::DeployWorkload),
            "teardown_workload" => Ok(FaultTarget::TeardownWorkload),
            "restart_workload" => Ok(FaultTarget::RestartWorkload),
            "list_workloads" => Ok(FaultTarget::ListWorkloads),
            "get_workload" => Ok(FaultTarget::GetWorkload),
            "stream_logs" => Ok(FaultTarget::StreamLogs),
            "health" => Ok(FaultTarget::Health),
            other => Err(format!("unknown fault target: {other}")),
        }
    }
}

// ── Internal state ────────────────────────────────────────────────────────────

#[derive(Debug)]
struct FakeWorkload {
    state: WorkloadState,
    /// Queued log lines emitted by `push_log`. Consumed in insertion order
    /// by `stream_logs` and cleared after each drain.
    logs: Vec<LogEvent>,
}

#[derive(Debug, Default)]
struct Inner {
    workloads: HashMap<String, FakeWorkload>,
    faults: HashMap<FaultTarget, (FailMode, u64 /* fired count */)>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// In-memory `ContainerRuntime` for unit tests.
///
/// Cheaply cloneable — all state is behind an `Arc<Mutex<_>>`. Clones share
/// the same underlying registry, so you can hand one clone to the code under
/// test and retain another to drive assertions or inject faults.
#[derive(Clone, Default)]
pub struct FakeRuntime {
    inner: Arc<Mutex<Inner>>,
}

impl FakeRuntime {
    /// Create an empty `FakeRuntime` with no workloads and no faults armed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a log line into the workload's queue.
    ///
    /// The line will appear in the next `stream_logs` call for `ident`. If no
    /// workload with that identity exists yet, the line is queued anyway and
    /// will be returned once the workload is deployed.
    pub fn push_log(
        &self,
        ident: impl Into<String>,
        stream: LogStreamKind,
        message: impl Into<String>,
    ) {
        let key = ident.into();
        let event = LogEvent::plain(MeshIdent(key.clone()), stream, message.into());
        let mut guard = self.inner.lock().unwrap();
        guard
            .workloads
            .entry(key.clone())
            .or_insert_with(|| FakeWorkload {
                state: WorkloadState {
                    ident: MeshIdent(key),
                    container_id: String::new(),
                    status: WorkloadStatus::Pending,
                    mesh_ip: None,
                },
                logs: vec![],
            })
            .logs
            .push(event);
    }

    /// Arm a fault on `target` that fires according to `mode`.
    ///
    /// Calling this a second time for the same target **replaces** the
    /// existing fault (useful for toggling from `Once` to `Always` or
    /// disarming by not calling it).
    pub fn fail_inject(&self, target: FaultTarget, mode: FailMode) {
        let mut guard = self.inner.lock().unwrap();
        guard.faults.insert(target, (mode, 0));
    }

    /// Disarm a previously-armed fault on `target`.
    pub fn clear_fault(&self, target: FaultTarget) {
        let mut guard = self.inner.lock().unwrap();
        guard.faults.remove(&target);
    }

    /// Drive a workload into `WorkloadStatus::Restarting` for R471 test
    /// scenarios. Inserts the workload if it doesn't already exist (some
    /// crash-loop tests assert the runtime surfaces Restarting even before a
    /// successful deploy round-trip).
    pub fn mark_restarting(
        &self,
        ident: impl Into<String>,
        last_exit_code: i32,
        restart_count: u32,
        last_finished_at_unix_ms: u64,
    ) {
        let key = ident.into();
        let mut guard = self.inner.lock().unwrap();
        let entry = guard.workloads.entry(key.clone()).or_insert_with(|| FakeWorkload {
            state: WorkloadState {
                ident: MeshIdent(key.clone()),
                container_id: format!("fake-{key}"),
                status: WorkloadStatus::Pending,
                mesh_ip: None,
            },
            logs: vec![],
        });
        entry.state.status = WorkloadStatus::Restarting {
            last_exit_code,
            restart_count,
            last_finished_at_unix_ms,
        };
    }

    /// Returns a snapshot of the current workload registry.
    ///
    /// Useful in test assertions without going through the async trait.
    pub fn snapshot(&self) -> Vec<WorkloadState> {
        let guard = self.inner.lock().unwrap();
        guard.workloads.values().map(|w| w.state.clone()).collect()
    }

    // ── internal helpers ──────────────────────────────────────────────────────

    /// Check whether a fault fires for `target`. Updates the fired count and
    /// disarms `Once` faults after the first firing.
    fn check_fault(&self, target: &FaultTarget) -> bool {
        let mut guard = self.inner.lock().unwrap();
        let entry = match guard.faults.get_mut(target) {
            Some(e) => e,
            None => return false,
        };
        let fires = match &entry.0 {
            FailMode::Always => true,
            FailMode::Once => {
                let first = entry.1 == 0;
                first
            }
            FailMode::Random(p) => rand_bool(*p),
        };
        if fires {
            entry.1 += 1;
            if matches!(entry.0, FailMode::Once) {
                guard.faults.remove(target);
            }
        }
        fires
    }
}

/// Minimal PRNG for `FailMode::Random` without pulling in `rand`.
/// Returns `true` with probability `p` based on the current system time nanos.
fn rand_bool(p: f64) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as f64;
    (nanos % 1_000_000.0) / 1_000_000.0 < p
}

// ── ContainerRuntime impl ─────────────────────────────────────────────────────

#[async_trait]
impl Constable for FakeRuntime {
    fn backend(&self) -> Backend {
        // FakeRuntime stands in for the Containerd backend in unit tests
        // — keeps test assertions on `backend()` aligned with what the
        // production impl returns.
        Backend::Containerd
    }

    async fn deploy_workload(
        &self,
        spec: &workload_spec::WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> anyhow::Result<DeployResult> {
        if self.check_fault(&FaultTarget::DeployWorkload) {
            anyhow::bail!("fake: injected fault on deploy_workload");
        }

        let ident = spec.expose.mesh.identity.clone();
        let container_id = format!("fake-{}", ident.0);
        let mesh_ip = mesh.mesh_ip;

        let mut guard = self.inner.lock().unwrap();
        let entry = guard
            .workloads
            .entry(ident.0.clone())
            .or_insert_with(|| FakeWorkload {
                state: WorkloadState {
                    ident: ident.clone(),
                    container_id: container_id.clone(),
                    status: WorkloadStatus::Pending,
                    mesh_ip: None,
                },
                logs: vec![],
            });
        // Advance to Running immediately (no real boot delay in the fake).
        entry.state.status = WorkloadStatus::Running;
        entry.state.container_id = container_id.clone();
        entry.state.mesh_ip = Some(mesh_ip);

        Ok(DeployResult {
            container_id,
            mesh_ip,
            task_pid: 1, // fake PID
        })
    }

    async fn list_workloads(&self) -> anyhow::Result<Vec<WorkloadState>> {
        if self.check_fault(&FaultTarget::ListWorkloads) {
            anyhow::bail!("fake: injected fault on list_workloads");
        }
        let guard = self.inner.lock().unwrap();
        Ok(guard.workloads.values().map(|w| w.state.clone()).collect())
    }

    async fn get_workload(&self, ident: &MeshIdent) -> anyhow::Result<Option<WorkloadState>> {
        if self.check_fault(&FaultTarget::GetWorkload) {
            anyhow::bail!("fake: injected fault on get_workload");
        }
        let guard = self.inner.lock().unwrap();
        Ok(guard.workloads.get(&ident.0).map(|w| w.state.clone()))
    }

    async fn stream_logs(&self, ident: &MeshIdent, opts: LogOpts) -> anyhow::Result<LogStream> {
        if self.check_fault(&FaultTarget::StreamLogs) {
            anyhow::bail!("fake: injected fault on stream_logs");
        }
        let mut guard = self.inner.lock().unwrap();
        let events = guard
            .workloads
            .get_mut(&ident.0)
            .map(|w| {
                let mut drained = std::mem::take(&mut w.logs);
                // Apply tail filter.
                if let Some(n) = opts.tail {
                    let n = n as usize;
                    if drained.len() > n {
                        drained = drained.into_iter().rev().take(n).rev().collect();
                    }
                }
                // Apply stream filter.
                if let Some(stream_kind) = opts.stream {
                    drained.retain(|e| e.stream == stream_kind);
                }
                drained
            })
            .unwrap_or_default();

        Ok(Box::pin(stream_iter(events)))
    }

    async fn restart_workload(&self, ident: &MeshIdent) -> anyhow::Result<()> {
        if self.check_fault(&FaultTarget::RestartWorkload) {
            anyhow::bail!("fake: injected fault on restart_workload");
        }
        let mut guard = self.inner.lock().unwrap();
        match guard.workloads.get_mut(&ident.0) {
            Some(w) => {
                w.state.status = WorkloadStatus::Stopping;
                w.state.status = WorkloadStatus::Running;
                Ok(())
            }
            None => anyhow::bail!("fake: restart_workload: unknown ident {}", ident.0),
        }
    }

    async fn teardown_workload(&self, ident: &MeshIdent) -> anyhow::Result<()> {
        if self.check_fault(&FaultTarget::TeardownWorkload) {
            anyhow::bail!("fake: injected fault on teardown_workload");
        }
        let mut guard = self.inner.lock().unwrap();
        // Idempotent — Ok even if not present.
        if let Some(w) = guard.workloads.get_mut(&ident.0) {
            w.state.status = WorkloadStatus::Stopped;
        }
        guard.workloads.remove(&ident.0);
        Ok(())
    }

    async fn health(&self) -> anyhow::Result<RuntimeHealth> {
        if self.check_fault(&FaultTarget::Health) {
            return Ok(RuntimeHealth {
                ok: false,
                version: None,
                detail: Some("fake: injected fault on health".to_string()),
            });
        }
        Ok(RuntimeHealth {
            ok: true,
            version: Some("fake/1.0".to_string()),
            detail: None,
        })
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, MeshIdent, ResourceLimits, RestartPolicy,
        SchemaVersion, StopPolicy, TierTag, WorkloadSpec, Millis,
    };
    use tokio_stream::StreamExt as _;

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
            command: None,
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

    fn stub_mesh() -> MeshAssignment {
        MeshAssignment::stub("10.64.0.1".parse().unwrap())
    }

    #[tokio::test]
    async fn deploy_get_teardown() {
        let rt = FakeRuntime::new();
        let spec = test_spec("api");
        let mesh = stub_mesh();

        let result = rt.deploy_workload(&spec, &mesh).await.unwrap();
        assert_eq!(result.container_id, "fake-api");
        assert_eq!(result.mesh_ip, mesh.mesh_ip);

        let state = rt.get_workload(&spec.expose.mesh.identity).await.unwrap().unwrap();
        assert_eq!(state.status, WorkloadStatus::Running);

        rt.teardown_workload(&spec.expose.mesh.identity).await.unwrap();
        assert!(rt.get_workload(&spec.expose.mesh.identity).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn teardown_is_idempotent() {
        let rt = FakeRuntime::new();
        let ident = MeshIdent("ghost".to_string());
        // Should not error on a workload that was never deployed.
        rt.teardown_workload(&ident).await.unwrap();
    }

    #[tokio::test]
    async fn list_workloads_returns_all() {
        let rt = FakeRuntime::new();
        let mesh = stub_mesh();
        rt.deploy_workload(&test_spec("svc-a"), &mesh).await.unwrap();
        rt.deploy_workload(&test_spec("svc-b"), &mesh).await.unwrap();

        let list = rt.list_workloads().await.unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|w| w.status == WorkloadStatus::Running));
    }

    #[tokio::test]
    async fn restart_bounces_through_stopping() {
        let rt = FakeRuntime::new();
        let spec = test_spec("bouncy");
        rt.deploy_workload(&spec, &stub_mesh()).await.unwrap();

        rt.restart_workload(&spec.expose.mesh.identity).await.unwrap();

        let state = rt
            .get_workload(&spec.expose.mesh.identity)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.status, WorkloadStatus::Running);
    }

    #[tokio::test]
    async fn stream_logs_drains_queue() {
        let rt = FakeRuntime::new();
        let spec = test_spec("logger");
        rt.deploy_workload(&spec, &stub_mesh()).await.unwrap();

        rt.push_log("logger", LogStreamKind::Stdout, "hello");
        rt.push_log("logger", LogStreamKind::Stdout, "world");

        let opts = LogOpts { tail: None, follow: false, stream: None };
        let mut stream = rt.stream_logs(&spec.expose.mesh.identity, opts).await.unwrap();

        let mut messages = vec![];
        while let Some(ev) = stream.next().await {
            messages.push(ev.message);
        }
        assert_eq!(messages, vec!["hello", "world"]);

        // Second drain is empty — logs are consumed.
        let opts2 = LogOpts { tail: None, follow: false, stream: None };
        let mut stream2 = rt.stream_logs(&spec.expose.mesh.identity, opts2).await.unwrap();
        assert!(stream2.next().await.is_none());
    }

    #[tokio::test]
    async fn stream_logs_tail_filter() {
        let rt = FakeRuntime::new();
        let spec = test_spec("tailer");
        rt.deploy_workload(&spec, &stub_mesh()).await.unwrap();

        for i in 0..10u32 {
            rt.push_log("tailer", LogStreamKind::Stdout, format!("line {i}"));
        }

        let opts = LogOpts { tail: Some(3), follow: false, stream: None };
        let stream = rt.stream_logs(&spec.expose.mesh.identity, opts).await.unwrap();
        let events: Vec<_> = stream.collect().await;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].message, "line 7");
        assert_eq!(events[2].message, "line 9");
    }

    #[tokio::test]
    async fn stream_logs_stream_filter() {
        let rt = FakeRuntime::new();
        let spec = test_spec("filtered");
        rt.deploy_workload(&spec, &stub_mesh()).await.unwrap();

        rt.push_log("filtered", LogStreamKind::Stdout, "out");
        rt.push_log("filtered", LogStreamKind::Stderr, "err");

        let opts = LogOpts { tail: None, follow: false, stream: Some(LogStreamKind::Stderr) };
        let stream = rt.stream_logs(&spec.expose.mesh.identity, opts).await.unwrap();
        let events: Vec<_> = stream.collect().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].stream, LogStreamKind::Stderr);
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let rt = FakeRuntime::new();
        let h = rt.health().await.unwrap();
        assert!(h.ok);
        assert_eq!(h.version.as_deref(), Some("fake/1.0"));
    }

    #[tokio::test]
    async fn fail_inject_once_fires_once() {
        let rt = FakeRuntime::new();
        rt.fail_inject(FaultTarget::DeployWorkload, FailMode::Once);

        let spec = test_spec("flakey");
        let mesh = stub_mesh();

        // First call should fail.
        assert!(rt.deploy_workload(&spec, &mesh).await.is_err());
        // Second call should succeed (fault is disarmed).
        assert!(rt.deploy_workload(&spec, &mesh).await.is_ok());
    }

    #[tokio::test]
    async fn fail_inject_always_fires_repeatedly() {
        let rt = FakeRuntime::new();
        rt.fail_inject(FaultTarget::TeardownWorkload, FailMode::Always);

        let ident = MeshIdent("gone".to_string());
        assert!(rt.teardown_workload(&ident).await.is_err());
        assert!(rt.teardown_workload(&ident).await.is_err());

        rt.clear_fault(FaultTarget::TeardownWorkload);
        assert!(rt.teardown_workload(&ident).await.is_ok());
    }

    #[tokio::test]
    async fn fail_inject_deploy_once_flips_to_failed_path() {
        // Verifies the @yah:verify scenario: fail_inject(deploy_workload:once)
        // means orchestration code should flip the workload to Failed.
        // Here we just assert the error propagates correctly.
        let rt = FakeRuntime::new();
        rt.fail_inject(FaultTarget::DeployWorkload, FailMode::Once);

        let spec = test_spec("once-flakey");
        let err = rt.deploy_workload(&spec, &stub_mesh()).await.unwrap_err();
        assert!(err.to_string().contains("injected fault"));

        // After the fault the workload should be absent.
        assert!(rt.get_workload(&spec.expose.mesh.identity).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mark_restarting_drives_status_for_crash_loop_fixture() {
        // R471-T2: tests must be able to put a workload into Restarting so
        // downstream consumers (Services grid, mirror_observation) can be
        // exercised against the crash-loop case without a real containerd.
        let rt = FakeRuntime::new();
        rt.mark_restarting("yah-warden", 2, 3, 1_700_000_000_000);

        let state = rt
            .get_workload(&MeshIdent("yah-warden".to_string()))
            .await
            .unwrap()
            .expect("workload present after mark_restarting");
        match state.status {
            WorkloadStatus::Restarting {
                last_exit_code,
                restart_count,
                last_finished_at_unix_ms,
            } => {
                assert_eq!(last_exit_code, 2);
                assert_eq!(restart_count, 3);
                assert_eq!(last_finished_at_unix_ms, 1_700_000_000_000);
            }
            other => panic!("expected Restarting, got {other:?}"),
        }
        assert!(!state.status.is_terminal());
    }

    #[tokio::test]
    async fn snapshot_reflects_deployed_workloads() {
        let rt = FakeRuntime::new();
        rt.deploy_workload(&test_spec("snap-a"), &stub_mesh()).await.unwrap();
        rt.deploy_workload(&test_spec("snap-b"), &stub_mesh()).await.unwrap();
        let snap = rt.snapshot();
        let names: std::collections::HashSet<_> = snap.iter().map(|w| w.ident.0.as_str()).collect();
        assert!(names.contains("snap-a"));
        assert!(names.contains("snap-b"));
    }
}
