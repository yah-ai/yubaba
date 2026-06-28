//! `runtime::docker` — `ContainerRuntime` impl backed by the Docker CLI.
//!
//! Targets pond (OrbStack) and any Linux dev box with a Docker-compatible socket.
//! Enabled by the `docker-integration` cargo feature (no extra deps — the gate
//! exists for consistency with `containerd-integration`, not for binary size).
//!
//! ## Why docker CLI over bollard
//!
//! Shell-out avoids the bollard dependency (a meaningful Tokio + hyper stack).
//! `docker inspect` returns structured JSON whose schema is stable across
//! Docker/OrbStack/Podman. Parsing JSON output is safer than parsing
//! human-readable text; per-call process overhead is invisible inside the
//! container spin-up budget (seconds).
//!
//! ## Status mapping
//!
//! | `.State.Restarting` / `.State.Status` | `WorkloadStatus`              |
//! |----------------------------------------|-------------------------------|
//! | `Restarting=true` (any status)          | `Restarting { … }`            |
//! | `"restarting"` (any `Restarting` flag)  | `Restarting { … }`            |
//! | `"running"`                             | `Running`                     |
//! | `"created"`                             | `Pending`                     |
//! | `"paused"` / `"removing"`              | `Stopping`                    |
//! | `"exited"`, `ExitCode = 0`             | `Stopped`                     |
//! | `"exited"`, `ExitCode ≠ 0`            | `Failed { reason }`           |
//! | `"dead"` / unknown                      | `Failed { reason }`           |
//!
//! `RestartCount` and `ExitCode` are read directly from the docker daemon —
//! no in-yubaba ledger is needed (R471-S1 verdict). This is the key difference
//! from `runtime::containerd`, which must synthesise restart state from its own
//! `RestartLedger` because containerd has no native restart-count signal.

#![cfg(feature = "docker-integration")]

use std::collections::HashMap;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tokio::process::Command;
use workload_spec::{MeshIdent, WorkloadSpec};

use crate::{
    Backend, Kamaji, DeployResult, LogEvent, LogOpts, LogStream, LogStreamKind, MeshAssignment,
    RuntimeHealth, WorkloadState, WorkloadStatus,
};

// ── docker inspect JSON types ─────────────────────────────────────────────────

/// The slice of `docker inspect` output this impl cares about.
#[derive(Debug, Deserialize)]
struct DockerInspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "State")]
    state: DockerState,
    /// Top-level restart counter maintained by dockerd/moby's restart-policy
    /// engine. Not present inside `.State` — it lives at the container root.
    #[serde(rename = "RestartCount")]
    restart_count: u32,
    #[serde(rename = "Config")]
    config: DockerConfig,
}

#[derive(Debug, Deserialize)]
struct DockerState {
    /// Canonical status string: `"created"` | `"running"` | `"paused"` |
    /// `"restarting"` | `"removing"` | `"exited"` | `"dead"`.
    #[serde(rename = "Status")]
    status: String,
    /// `true` while dockerd is sleeping between restart attempts.
    #[serde(rename = "Restarting")]
    restarting: bool,
    /// Exit code of the most recent task instance. Meaningful only when
    /// `Status == "exited"` or during a restart cycle.
    #[serde(rename = "ExitCode")]
    exit_code: i32,
    /// UTC ISO8601 timestamp of the last task exit. Docker uses
    /// `"0001-01-01T00:00:00Z"` as the zero value when the container has
    /// never exited.
    #[serde(rename = "FinishedAt")]
    finished_at: String,
}

#[derive(Debug, Deserialize)]
struct DockerConfig {
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
}

// ── DockerRuntime ─────────────────────────────────────────────────────────────

/// `ContainerRuntime` impl backed by the `docker` CLI.
///
/// Acquire via [`DockerRuntime::new`] (inherit `DOCKER_HOST` from environment)
/// or [`DockerRuntime::with_host`] (explicit socket/host).
///
/// Cheaply cloneable — the struct contains only a `String`.
#[derive(Clone)]
pub struct DockerRuntime {
    /// `DOCKER_HOST` value for every CLI invocation. Empty string means
    /// "inherit from environment", which picks up OrbStack's socket on macOS
    /// and the system socket on Linux.
    docker_host: String,
}

impl DockerRuntime {
    /// Use the system-default docker socket (inherit `DOCKER_HOST`).
    pub fn new() -> Self {
        Self { docker_host: String::new() }
    }

    /// Use a specific docker host (e.g. `"unix:///var/run/docker.sock"`).
    pub fn with_host(docker_host: impl Into<String>) -> Self {
        Self { docker_host: docker_host.into() }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new("docker");
        if !self.docker_host.is_empty() {
            cmd.env("DOCKER_HOST", &self.docker_host);
        }
        cmd.kill_on_drop(true);
        cmd
    }

    /// Build the full image reference. Always includes the digest so pulls are
    /// content-addressed (matches containerd impl — see R438-T3).
    fn image_ref(spec: &WorkloadSpec) -> String {
        let img = &spec.image;
        format!("{}/{}:{}@{}", img.registry, img.repository, img.tag, img.digest)
    }

    /// Container name derived from the mesh identity. Used as the `--name`
    /// flag and as the argument to `docker inspect / stop / rm`.
    fn container_name(ident: &MeshIdent) -> &str {
        &ident.0
    }

    /// Run `docker inspect <name>` and return the parsed result.
    /// Returns `Ok(None)` when the container doesn't exist.
    async fn inspect(&self, name: &str) -> Result<Option<DockerInspect>> {
        let out = self
            .cmd()
            .args(["inspect", name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("spawning docker inspect {name}"))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if is_missing_container(&stderr) {
                return Ok(None);
            }
            return Err(anyhow!("docker inspect {name} failed: {}", stderr.trim()));
        }

        let json = String::from_utf8_lossy(&out.stdout);
        let list: Vec<DockerInspect> = serde_json::from_str(&json)
            .with_context(|| format!("parsing docker inspect JSON for {name}"))?;
        Ok(list.into_iter().next())
    }

    /// Translate a `DockerInspect` record into a `WorkloadState`.
    fn inspect_to_state(di: DockerInspect, ident: MeshIdent) -> WorkloadState {
        let labels = di.config.labels.unwrap_or_default();
        let mesh_ip = labels.get("yah.mesh_ip").and_then(|s| s.parse().ok());
        let status = map_docker_state(&di.state, di.restart_count);
        WorkloadState {
            ident,
            container_id: di.id,
            status,
            mesh_ip,
        }
    }
}

impl Default for DockerRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ── ContainerRuntime impl ─────────────────────────────────────────────────────

#[async_trait]
impl Kamaji for DockerRuntime {
    fn backend(&self) -> Backend {
        Backend::Docker
    }

    async fn deploy_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> Result<DeployResult> {
        let ident = &spec.expose.mesh.identity;
        let name = Self::container_name(ident).to_string();
        let image = Self::image_ref(spec);

        // Idempotent: clear any prior container with the same name.
        let _ = self.teardown_workload(ident).await;

        // Ensure the image is present locally.
        let pull = self
            .cmd()
            .args(["pull", &image])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker pull {image}"))?;
        if !pull.status.success() {
            let stderr = String::from_utf8_lossy(&pull.stderr);
            return Err(anyhow!("docker pull {image} failed: {}", stderr.trim()));
        }

        // Build the `docker run` arg list.
        let mut args: Vec<String> = vec![
            "run".into(), "-d".into(),
            "--name".into(), name.clone(),
            // Labels for identity + mesh bookkeeping.
            "--label".into(), format!("yah.ident={}", ident.0),
            "--label".into(), format!("yah.mesh_ip={}", mesh.mesh_ip),
            // Memory ceiling. CPU shares aren't a docker CLI concept
            // (--cpu-shares sets cgroup weight; matches containerd semantics).
            "--memory".into(), format!("{}m", spec.resources.memory_mb),
            "--cpu-shares".into(), spec.resources.cpu_shares.to_string(),
            // Mesh IP surfaced to the workload as an env var.
            "--env".into(), format!("YAH_MESH_IP={}", mesh.mesh_ip),
        ];

        // Literal env vars from the spec.
        for e in &spec.env {
            if let workload_spec::EnvValue::Literal { value } = &e.value {
                args.push("--env".into());
                args.push(format!("{}={}", e.name, value));
            }
        }

        // Image ref + optional command override.
        args.push(image.clone());
        if let Some(cmd) = &spec.command {
            args.extend(cmd.iter().cloned());
        }

        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = self
            .cmd()
            .args(&argv[..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker run {name}"))?;
        if !run.status.success() {
            let stderr = String::from_utf8_lossy(&run.stderr);
            return Err(anyhow!("docker run {name} failed: {}", stderr.trim()));
        }

        // Read back the container ID from inspect.
        let di = self
            .inspect(&name)
            .await?
            .ok_or_else(|| anyhow!("container {name} not found after docker run"))?;
        let container_id = di.id.clone();

        tracing::info!(
            name = %name,
            container_id = %container_id,
            mesh_ip = %mesh.mesh_ip,
            "docker workload deployed"
        );

        Ok(DeployResult {
            container_id,
            mesh_ip: mesh.mesh_ip,
            // Docker CLI doesn't surface the host PID directly; 0 is the
            // sentinel used when the value is unavailable.
            task_pid: 0,
        })
    }

    async fn list_workloads(&self) -> Result<Vec<WorkloadState>> {
        // Enumerate all containers (running or stopped) that carry the
        // `yah.ident` label — the label is written by `deploy_workload`.
        let out = self
            .cmd()
            .args([
                "ps", "-a",
                "--filter", "label=yah.ident",
                "--format", "{{.Names}}",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("docker ps for yah workloads")?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(anyhow!("docker ps failed: {}", stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        let names: Vec<&str> = stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();

        let mut states = Vec::with_capacity(names.len());
        for name in names {
            if let Some(di) = self.inspect(name).await? {
                let ident_str = di
                    .config
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("yah.ident"))
                    .cloned()
                    .unwrap_or_else(|| name.to_string());
                states.push(Self::inspect_to_state(di, MeshIdent(ident_str)));
            }
        }
        Ok(states)
    }

    async fn get_workload(&self, ident: &MeshIdent) -> Result<Option<WorkloadState>> {
        let name = Self::container_name(ident);
        match self.inspect(name).await? {
            Some(di) => Ok(Some(Self::inspect_to_state(di, ident.clone()))),
            None => Ok(None),
        }
    }

    async fn stream_logs(&self, ident: &MeshIdent, opts: LogOpts) -> Result<LogStream> {
        let name = Self::container_name(ident).to_string();
        let ident_clone = ident.clone();

        // Build `docker logs [--tail N] <name>`.
        // follow mode is deferred — `docker logs -f` would require spawning a
        // long-running process and streaming its stdout; for F3 the key use
        // case (crash-loop log inspection) only needs the historical drain.
        let mut args: Vec<String> = vec!["logs".into()];
        match opts.tail {
            Some(n) => {
                args.push("--tail".into());
                args.push(n.to_string());
            }
            None => {
                args.push("--tail".into());
                args.push("all".into());
            }
        }
        args.push(name.clone());

        let out = self
            .cmd()
            .args(args.iter().map(String::as_str))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker logs {name}"))?;

        // If docker itself failed (e.g. container doesn't exist yet during the
        // first restart cycle) return an empty stream rather than an error —
        // callers expect a stream, not a hard failure.
        if !out.status.success() {
            return Ok(Box::pin(tokio_stream::empty()));
        }

        let include_stdout = opts
            .stream
            .map(|s| s == LogStreamKind::Stdout)
            .unwrap_or(true);
        let include_stderr = opts
            .stream
            .map(|s| s == LogStreamKind::Stderr)
            .unwrap_or(true);

        // Timestamp events at capture time (docker logs stdout/stderr don't
        // carry per-line timestamps by default).
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut events: Vec<LogEvent> = Vec::new();

        // docker logs routes container stdout → CLI stdout, container stderr →
        // CLI stderr, making it easy to tag each line with the right kind.
        if include_stdout {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                events.push(LogEvent {
                    timestamp_ms: now_ms,
                    ident: ident_clone.clone(),
                    stream: LogStreamKind::Stdout,
                    message: line.to_string(),
                    correlation_id: None,
                });
            }
        }
        if include_stderr {
            let stderr = String::from_utf8_lossy(&out.stderr);
            for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
                events.push(LogEvent {
                    timestamp_ms: now_ms,
                    ident: ident_clone.clone(),
                    stream: LogStreamKind::Stderr,
                    message: line.to_string(),
                    correlation_id: None,
                });
            }
        }

        Ok(Box::pin(tokio_stream::iter(events)))
    }

    async fn restart_workload(&self, ident: &MeshIdent) -> Result<()> {
        let name = Self::container_name(ident);
        let out = self
            .cmd()
            .args(["restart", name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker restart {name}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(anyhow!("docker restart {name} failed: {}", stderr.trim()));
        }
        tracing::info!(name = %name, "docker workload restarted");
        Ok(())
    }

    async fn teardown_workload(&self, ident: &MeshIdent) -> Result<()> {
        let name = Self::container_name(ident);

        // Stop gracefully first (5 s grace, matching containerd's default).
        // "No such container" is swallowed — teardown is idempotent.
        let stop = self
            .cmd()
            .args(["stop", "-t", "5", name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker stop {name}"))?;
        if !stop.status.success() {
            let stderr = String::from_utf8_lossy(&stop.stderr);
            if !is_missing_container(&stderr) {
                return Err(anyhow!("docker stop {name} failed: {}", stderr.trim()));
            }
        }

        // Force-remove the container record.
        let rm = self
            .cmd()
            .args(["rm", "-f", name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker rm {name}"))?;
        if !rm.status.success() {
            let stderr = String::from_utf8_lossy(&rm.stderr);
            if !is_missing_container(&stderr) {
                return Err(anyhow!("docker rm {name} failed: {}", stderr.trim()));
            }
        }

        tracing::info!(name = %name, "docker workload torn down");
        Ok(())
    }

    async fn health(&self) -> Result<RuntimeHealth> {
        let out = self
            .cmd()
            .args(["version", "--format", "{{.Server.Version}}"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match out {
            Ok(o) if o.status.success() => {
                let version = String::from_utf8_lossy(&o.stdout).trim().to_string();
                Ok(RuntimeHealth {
                    ok: true,
                    version: if version.is_empty() { None } else { Some(version) },
                    detail: None,
                })
            }
            Ok(o) => {
                let detail = String::from_utf8_lossy(&o.stderr).trim().to_string();
                Ok(RuntimeHealth {
                    ok: false,
                    version: None,
                    detail: if detail.is_empty() { None } else { Some(detail) },
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

/// Translate a docker daemon state snapshot into a `WorkloadStatus`.
///
/// The docker daemon itself maintains `RestartCount` and surfaces the
/// `Restarting` flag — no in-yubaba ledger is needed (R471-S1 verdict).
fn map_docker_state(state: &DockerState, restart_count: u32) -> WorkloadStatus {
    // Check the Restarting flag first — it's set while dockerd is sleeping
    // between restart attempts. The Status string may lag behind in some
    // versions; treat either signal as authoritative.
    if state.restarting || state.status == "restarting" {
        return WorkloadStatus::Restarting {
            last_exit_code: state.exit_code,
            restart_count,
            last_finished_at_unix_ms: parse_docker_timestamp_ms(&state.finished_at),
        };
    }
    match state.status.as_str() {
        "running" => WorkloadStatus::Running,
        "created" => WorkloadStatus::Pending,
        "paused" | "removing" => WorkloadStatus::Stopping,
        "exited" if state.exit_code == 0 => WorkloadStatus::Stopped,
        "exited" => WorkloadStatus::Failed {
            reason: format!("exited with code {}", state.exit_code),
        },
        "dead" => WorkloadStatus::Failed { reason: "container is dead".into() },
        other => WorkloadStatus::Failed {
            reason: format!("unknown docker status: {other}"),
        },
    }
}

/// Parse Docker's UTC ISO8601 timestamp into Unix milliseconds.
///
/// Returns 0 for the sentinel zero value (`"0001-01-01…"`) or on any parse
/// failure. This value is used only for display (`"Restarting (N) · M ago"`
/// chips), so precision vs a proper calendar library is acceptable.
fn parse_docker_timestamp_ms(s: &str) -> u64 {
    if s.is_empty() || s.starts_with("0001") {
        return 0;
    }
    // Format: "YYYY-MM-DDTHH:MM:SS[.nnnnnnnZ]" — always UTC.
    let s = s.trim_end_matches('Z');
    let (date_part, time_part) = match s.split_once('T') {
        Some(p) => p,
        None => return 0,
    };

    let mut dp = date_part.splitn(3, '-');
    let year: u64 = dp.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let month: u64 = dp.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let day: u64 = dp.next().and_then(|p| p.parse().ok()).unwrap_or(0);

    // Strip fractional seconds before splitting on ':'.
    let time_no_frac = time_part.split('.').next().unwrap_or("");
    let mut tp = time_no_frac.splitn(3, ':');
    let hour: u64 = tp.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let min: u64 = tp.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let sec: u64 = tp.next().and_then(|p| p.parse().ok()).unwrap_or(0);

    if year < 1970 || month == 0 || month > 12 || day == 0 {
        return 0;
    }

    // Days from 1 Jan 1970 to 1 Jan `year`.
    let years_since_epoch = year - 1970;
    // One extra day per 4 years (rough Gregorian approximation; sufficient for display).
    let leap_days = years_since_epoch / 4;

    // Days in each month (non-leap). Index 0 is unused (months are 1-based).
    let days_in_month: [u64; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let days_through_month: u64 = days_in_month[..month as usize].iter().sum::<u64>();
    let day_of_year = days_through_month + day - 1;

    let total_days = years_since_epoch * 365 + leap_days + day_of_year;
    let total_secs = total_days * 86_400 + hour * 3_600 + min * 60 + sec;
    total_secs * 1_000
}

/// True when docker CLI stderr indicates the named container doesn't exist.
fn is_missing_container(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("no such container") || lower.contains("no such object")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::MeshIdent;

    /// True when a docker daemon is reachable. Used to skip live tests in CI.
    async fn docker_available() -> bool {
        let out = Command::new("docker")
            .args(["version"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        matches!(out, Ok(s) if s.success())
    }

    fn state(status: &str, restarting: bool, exit_code: i32) -> DockerState {
        DockerState {
            status: status.into(),
            restarting,
            exit_code,
            finished_at: "2024-01-15T10:25:03.123456789Z".into(),
        }
    }

    // ── map_docker_state unit tests ───────────────────────────────────────────

    #[test]
    fn restarting_flag_overrides_status() {
        // Even if Status=="running", Restarting=true means the daemon is
        // sleeping before the next restart attempt.
        let ws = map_docker_state(&state("running", true, 137), 3);
        match ws {
            WorkloadStatus::Restarting { last_exit_code, restart_count, last_finished_at_unix_ms } => {
                assert_eq!(last_exit_code, 137);
                assert_eq!(restart_count, 3);
                assert!(last_finished_at_unix_ms > 0);
            }
            other => panic!("expected Restarting, got {other:?}"),
        }
    }

    #[test]
    fn restarting_status_string_matches() {
        let s = DockerState {
            status: "restarting".into(),
            restarting: false, // flag may lag — status string is authoritative
            exit_code: 2,
            finished_at: "0001-01-01T00:00:00Z".into(),
        };
        let ws = map_docker_state(&s, 1);
        assert!(
            matches!(ws, WorkloadStatus::Restarting { restart_count: 1, last_exit_code: 2, .. }),
            "got {ws:?}"
        );
    }

    #[test]
    fn running_maps_to_running() {
        assert_eq!(map_docker_state(&state("running", false, 0), 0), WorkloadStatus::Running);
    }

    #[test]
    fn created_maps_to_pending() {
        assert_eq!(map_docker_state(&state("created", false, 0), 0), WorkloadStatus::Pending);
    }

    #[test]
    fn paused_maps_to_stopping() {
        assert_eq!(map_docker_state(&state("paused", false, 0), 0), WorkloadStatus::Stopping);
    }

    #[test]
    fn exited_zero_maps_to_stopped() {
        assert_eq!(map_docker_state(&state("exited", false, 0), 0), WorkloadStatus::Stopped);
    }

    #[test]
    fn exited_nonzero_maps_to_failed() {
        assert!(matches!(
            map_docker_state(&state("exited", false, 1), 0),
            WorkloadStatus::Failed { .. }
        ));
    }

    #[test]
    fn dead_maps_to_failed() {
        assert!(matches!(
            map_docker_state(&state("dead", false, 0), 0),
            WorkloadStatus::Failed { .. }
        ));
    }

    // ── parse_docker_timestamp_ms unit tests ──────────────────────────────────

    #[test]
    fn zero_timestamp_returns_zero() {
        assert_eq!(parse_docker_timestamp_ms("0001-01-01T00:00:00Z"), 0);
        assert_eq!(parse_docker_timestamp_ms(""), 0);
    }

    #[test]
    fn known_timestamp_is_positive_and_in_range() {
        // "2024-01-15T10:25:03Z" is well past the epoch and before today.
        let ms = parse_docker_timestamp_ms("2024-01-15T10:25:03Z");
        assert!(ms > 1_000_000_000_000, "expected ms > 1e12, got {ms}");
        // Sanity upper bound: 2030-01-01 in ms ≈ 1.9e12
        assert!(ms < 2_000_000_000_000, "expected ms < 2e12, got {ms}");
    }

    #[test]
    fn fractional_seconds_accepted() {
        let ms = parse_docker_timestamp_ms("2024-01-15T10:25:03.123456789Z");
        assert!(ms > 1_000_000_000_000, "got {ms}");
    }

    // ── is_missing_container ──────────────────────────────────────────────────

    #[test]
    fn missing_container_detection() {
        assert!(is_missing_container("Error: No such container: foo"));
        assert!(is_missing_container("Error response from daemon: No such object: bar"));
        assert!(!is_missing_container("Error: permission denied"));
    }

    // ── live docker tests (skip when daemon unreachable) ──────────────────────

    #[tokio::test]
    async fn health_returns_ok_when_docker_reachable() {
        if !docker_available().await {
            eprintln!("SKIP: docker not reachable");
            return;
        }
        let rt = DockerRuntime::new();
        let h = rt.health().await.unwrap();
        assert!(h.ok, "expected healthy docker daemon: {:?}", h.detail);
        assert!(h.version.is_some(), "expected version string");
    }

    #[tokio::test]
    async fn get_workload_returns_none_for_nonexistent() {
        if !docker_available().await {
            eprintln!("SKIP: docker not reachable");
            return;
        }
        let rt = DockerRuntime::new();
        let ident = MeshIdent("r471-f3-nonexistent-sentinel".to_string());
        let result = rt.get_workload(&ident).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_workloads_does_not_error() {
        if !docker_available().await {
            eprintln!("SKIP: docker not reachable");
            return;
        }
        // May or may not have yah.ident containers — just assert no error.
        let rt = DockerRuntime::new();
        let _ = rt.list_workloads().await.unwrap();
    }

    #[tokio::test]
    async fn teardown_is_idempotent_for_missing_container() {
        if !docker_available().await {
            eprintln!("SKIP: docker not reachable");
            return;
        }
        let rt = DockerRuntime::new();
        let ident = MeshIdent("r471-f3-teardown-idempotent-sentinel".to_string());
        // Should not error even when the container has never existed.
        rt.teardown_workload(&ident).await.unwrap();
    }
}
