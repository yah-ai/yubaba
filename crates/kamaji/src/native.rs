//! `Backend::Native` — direct fork+exec of a host binary (W199's "ideal
//! native-backend case"; the backend R490-F2 routes mesofact-dev through).
//!
//! v1 scope, deliberately minimal but real:
//!
//! - **fork+exec + wait** via `tokio::process` (the R406 cgroup subtree +
//!   pidfd hardening layers in when this backend graduates to fleet hosts;
//!   desktop/CI supervision needs lifecycle, not isolation).
//! - **`spec.entrypoint` + `spec.command`** concatenate to the argv, exactly
//!   container semantics (ENTRYPOINT vector + CMD args; CMD alone is the
//!   program). `spec.image` is identity metadata only — nothing is pulled.
//! - **Literal env vars** + `YAH_MESH_IP` injection, mirroring the docker
//!   backend.
//! - **stdout/stderr capture** to `<state_dir>/<ident>/{stdout,stderr}.log`;
//!   `stream_logs` replays the captured files (`follow` is not supported in
//!   v1 — callers get the current contents and the stream ends).
//! - **Idempotent teardown**: SIGTERM → grace (spec.stop_policy ignored in
//!   v1; fixed 5s) → SIGKILL. Same-ident redeploys tear the predecessor
//!   down first.
//! - **Crash semantics** per W199 §"Crash semantics": if the supervising
//!   process dies, native workloads are orphaned; next-boot reconcile
//!   re-adopts or re-deploys. `kill_on_drop` is intentionally off.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncBufReadExt;
use tokio::sync::Mutex;
use workload_spec::{EnvValue, MeshIdent, WorkloadSpec};

use crate::{
    Backend, Kamaji, DeployResult, LogEvent, LogOpts, LogStream, LogStreamKind, MeshAssignment,
    RuntimeHealth, WorkloadState, WorkloadStatus,
};

/// How long teardown waits between SIGTERM and SIGKILL.
const TERM_GRACE: Duration = Duration::from_secs(5);

struct NativeWorkload {
    child: tokio::process::Child,
    pid: u32,
    mesh_ip: Ipv4Addr,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

/// Fork+exec backend. One instance supervises any number of workloads;
/// bookkeeping lives in-process (see crash semantics above).
pub struct NativeRuntime {
    state_dir: PathBuf,
    workloads: Mutex<HashMap<String, NativeWorkload>>,
}

impl NativeRuntime {
    /// `state_dir` holds per-workload log captures; created on demand.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self { state_dir: state_dir.into(), workloads: Mutex::new(HashMap::new()) }
    }

    fn workload_dir(&self, ident: &MeshIdent) -> PathBuf {
        // MeshIdent is DNS-segment-shaped (validated upstream); safe as a
        // path component.
        self.state_dir.join(&ident.0)
    }

    /// Resolve the argv from entrypoint + command (container semantics).
    fn argv(spec: &WorkloadSpec) -> Result<Vec<String>> {
        let mut argv: Vec<String> = Vec::new();
        if let Some(entry) = &spec.entrypoint {
            argv.extend(entry.iter().cloned());
        }
        if let Some(cmd) = &spec.command {
            argv.extend(cmd.iter().cloned());
        }
        if argv.is_empty() {
            return Err(anyhow!(
                "workload {}: Backend::Native needs `entrypoint` and/or `command` to name the host binary (image is identity metadata only for native workloads)",
                spec.name
            ));
        }
        Ok(argv)
    }

    async fn spawn(&self, spec: &WorkloadSpec, mesh: &MeshAssignment) -> Result<NativeWorkload> {
        let ident = &spec.expose.mesh.identity;
        let argv = Self::argv(spec)?;

        let dir = self.workload_dir(ident);
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("creating state dir {}", dir.display()))?;
        let stdout_path = dir.join("stdout.log");
        let stderr_path = dir.join("stderr.log");
        let stdout_file = std::fs::File::create(&stdout_path)
            .with_context(|| format!("creating {}", stdout_path.display()))?;
        let stderr_file = std::fs::File::create(&stderr_path)
            .with_context(|| format!("creating {}", stderr_path.display()))?;

        let mut cmd = tokio::process::Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .env("YAH_MESH_IP", mesh.mesh_ip.to_string())
            .kill_on_drop(false);
        if let Some(workdir) = &spec.workdir {
            cmd.current_dir(workdir);
        }
        for e in &spec.env {
            if let EnvValue::Literal { value } = &e.value {
                cmd.env(&e.name, value);
            }
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("spawning {} for workload {}", argv[0], spec.name))?;
        let pid = child
            .id()
            .ok_or_else(|| anyhow!("workload {}: child exited before pid read", spec.name))?;

        Ok(NativeWorkload { child, pid, mesh_ip: mesh.mesh_ip, stdout_path, stderr_path })
    }

    /// SIGTERM, grace, SIGKILL.
    async fn stop_child(child: &mut tokio::process::Child, pid: u32) {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        #[cfg(unix)]
        // SAFETY: plain kill(2) on a pid we spawned and still hold the
        // Child for; worst case the pid already exited and kill returns
        // ESRCH, which we ignore.
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        #[cfg(not(unix))]
        let _ = pid;
        let graceful = tokio::time::timeout(TERM_GRACE, child.wait()).await;
        if graceful.is_err() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }

    fn status_of(child: &mut tokio::process::Child) -> WorkloadStatus {
        match child.try_wait() {
            Ok(None) => WorkloadStatus::Running,
            Ok(Some(status)) if status.success() => WorkloadStatus::Stopped,
            Ok(Some(status)) => WorkloadStatus::Failed { reason: format!("exited with {status}") },
            Err(e) => WorkloadStatus::Failed { reason: format!("wait failed: {e}") },
        }
    }
}

#[async_trait]
impl Kamaji for NativeRuntime {
    fn backend(&self) -> Backend {
        Backend::Native
    }

    async fn deploy_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> Result<DeployResult> {
        if spec.replicas > 1 {
            return Err(anyhow!(
                "workload {}: Backend::Native supervises a single replica (got replicas={})",
                spec.name,
                spec.replicas
            ));
        }
        let ident = spec.expose.mesh.identity.clone();

        // Idempotent: clear any prior workload with the same identity.
        self.teardown_workload(&ident).await?;

        let workload = self.spawn(spec, mesh).await?;
        let result = DeployResult {
            container_id: format!("native-{}", workload.pid),
            mesh_ip: workload.mesh_ip,
            task_pid: workload.pid,
        };
        self.workloads.lock().await.insert(ident.0, workload);
        Ok(result)
    }

    async fn list_workloads(&self) -> Result<Vec<WorkloadState>> {
        let mut map = self.workloads.lock().await;
        let mut out = Vec::with_capacity(map.len());
        for (ident, w) in map.iter_mut() {
            out.push(WorkloadState {
                ident: MeshIdent(ident.clone()),
                container_id: format!("native-{}", w.pid),
                status: Self::status_of(&mut w.child),
                mesh_ip: Some(w.mesh_ip),
            });
        }
        Ok(out)
    }

    async fn get_workload(&self, ident: &MeshIdent) -> Result<Option<WorkloadState>> {
        let mut map = self.workloads.lock().await;
        Ok(map.get_mut(&ident.0).map(|w| WorkloadState {
            ident: ident.clone(),
            container_id: format!("native-{}", w.pid),
            status: Self::status_of(&mut w.child),
            mesh_ip: Some(w.mesh_ip),
        }))
    }

    async fn stream_logs(&self, ident: &MeshIdent, opts: LogOpts) -> Result<LogStream> {
        let (stdout_path, stderr_path) = {
            let map = self.workloads.lock().await;
            let w = map
                .get(&ident.0)
                .ok_or_else(|| anyhow!("no native workload with identity {}", ident.0))?;
            (w.stdout_path.clone(), w.stderr_path.clone())
        };

        let want = |kind: LogStreamKind| match opts.stream {
            None => true,
            Some(k) => k == kind,
        };

        let mut events: Vec<LogEvent> = Vec::new();
        for (path, kind) in
            [(stdout_path, LogStreamKind::Stdout), (stderr_path, LogStreamKind::Stderr)]
        {
            if !want(kind) {
                continue;
            }
            let Ok(file) = tokio::fs::File::open(&path).await else { continue };
            let mut lines = tokio::io::BufReader::new(file).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                events.push(LogEvent::plain(ident.clone(), kind, line));
            }
        }
        if let Some(tail) = opts.tail {
            let keep = tail as usize;
            if events.len() > keep {
                events.drain(..events.len() - keep);
            }
        }
        // v1: no follow — replay the capture and end the stream.
        Ok(Box::pin(tokio_stream::iter(events)))
    }

    async fn restart_workload(&self, ident: &MeshIdent) -> Result<()> {
        Err(anyhow!(
            "Backend::Native v1 cannot restart {} in place — it does not retain the WorkloadSpec; tear down and redeploy (the spec-retaining restart loop lands with the R406 supervisor hardening)",
            ident.0
        ))
    }

    async fn teardown_workload(&self, ident: &MeshIdent) -> Result<()> {
        let Some(mut w) = self.workloads.lock().await.remove(&ident.0) else {
            return Ok(());
        };
        Self::stop_child(&mut w.child, w.pid).await;
        Ok(())
    }

    async fn health(&self) -> Result<RuntimeHealth> {
        Ok(RuntimeHealth {
            ok: true,
            version: Some(format!("native/{}", env!("CARGO_PKG_VERSION"))),
            detail: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt as _;
    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, Millis, ResourceLimits, RestartPolicy, SchemaVersion,
        StopPolicy, TierTag,
    };

    fn native_spec(name: &str, argv: Vec<String>) -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.to_string(),
            image: ImageRef {
                registry: "localhost".to_string(),
                repository: format!("native/{name}"),
                tag: "dev".to_string(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".to_string()),
            replicas: 1,
            command: Some(argv),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits { memory_mb: 64, cpu_shares: 128, ephemeral_storage_mb: 128 },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Never,
            stop_policy: StopPolicy { signal: 15, grace_period: Millis::from_secs(5) },
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

    #[tokio::test]
    async fn deploy_status_logs_teardown_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let spec = native_spec(
            "native-smoke",
            vec!["/bin/sh".into(), "-c".into(), "echo hello-native; sleep 30".into()],
        );
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

        let deployed = runtime.deploy_workload(&spec, &mesh).await.unwrap();
        assert!(deployed.task_pid > 0);

        let ident = spec.expose.mesh.identity.clone();
        let state = runtime.get_workload(&ident).await.unwrap().unwrap();
        assert_eq!(state.status, WorkloadStatus::Running);

        // stdout capture made it to the log stream.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut logs = runtime
            .stream_logs(&ident, LogOpts { tail: None, follow: false, stream: None })
            .await
            .unwrap();
        let mut saw = false;
        while let Some(ev) = logs.next().await {
            if ev.message.contains("hello-native") {
                saw = true;
            }
        }
        assert!(saw, "expected captured stdout line");

        runtime.teardown_workload(&ident).await.unwrap();
        assert!(runtime.get_workload(&ident).await.unwrap().is_none());
        // Idempotent.
        runtime.teardown_workload(&ident).await.unwrap();
    }

    #[tokio::test]
    async fn failed_exit_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let spec =
            native_spec("native-fail", vec!["/bin/sh".into(), "-c".into(), "exit 3".into()]);
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        runtime.deploy_workload(&spec, &mesh).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let state =
            runtime.get_workload(&spec.expose.mesh.identity).await.unwrap().unwrap();
        assert!(matches!(state.status, WorkloadStatus::Failed { .. }), "{:?}", state.status);
    }

    #[tokio::test]
    async fn empty_argv_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec("native-empty", vec![]);
        spec.command = None;
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let err = runtime.deploy_workload(&spec, &mesh).await.unwrap_err();
        assert!(err.to_string().contains("entrypoint"), "{err}");
    }
}
