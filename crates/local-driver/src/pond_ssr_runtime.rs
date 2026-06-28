//! Pond SSR runtime container bring-up primitives (R434-F4).
//!
//! Mirrors the shape of [`crate::pond_minio`] for a long-lived
//! `mesofact-static.ssr_runtime` companion container — the Fetch-handler
//! origin that miniflare proxies SSR-prefix requests to. The canonical image
//! is now `mesofact-serve` (deno_core, W174 pillar 4 / R449-F3,
//! `oss/mesofact/Dockerfile.ssr-runtime`), which replaces the prior
//! `oven/bun:1` + `bun run src/ssr.ts` runtime; the bring-up below stays
//! image-agnostic, so the workload's `ssr_runtime.image` / `.command` select
//! the runtime.
//!
//! The companion is declared in `workload.toml`'s
//! `MesofactStaticWorkload.ssr_runtime: Option<WorkloadSpec>` (R256-F7).
//! Camp lowers the workload spec into the simpler shape this module accepts —
//! see [`SsrRuntimeSpec`] — and yubaba owns the lifecycle alongside MinIO
//! + miniflare (R374-F3 / R374-F4 pattern).
//!
//! Bring-up: pull image, run container with port mapping + env + optional
//! bind mounts, wait for HTTP readiness on the host-mapped port. Used by:
//!
//! - `yubaba::pond::ssr_runtime::SsrRuntimeReconciler` — supervisor + restart
//!   loop that owns the running container, kept in sync with the rest of the
//!   pond registry.
//! - `cloud::reconciler::pond::up_pond` — eventual cloud-direct path; today
//!   only the yubaba path consumes this (camp builds the spec then POSTs).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;
use workload_spec::WorkloadSpec;

use crate::{ContainerRunSpec, LocalRuntime};

/// Default port the SSR container binds inside its image. Bun/Node frameworks
/// default to `3000`; the workload spec can override via
/// `expose.mesh.ports[0]` and that wins.
pub const DEFAULT_SSR_CONTAINER_PORT: u16 = 3000;

/// Caller-supplied SSR-runtime bring-up parameters. Decoupled from
/// `WorkloadSpec` so yubaba's HTTP body stays narrow — camp lowers the full
/// spec to this struct before POSTing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrRuntimeSpec {
    /// Per-cell docker bridge network to attach to (R455-F1). Sibling
    /// containers (miniflare, MinIO) reach this container via
    /// [`network_alias`] — typically `http://ssr:3000` from inside the
    /// Worker. `None` keeps the legacy host-port-only shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// DNS alias on the bridge (e.g. `"ssr"`). Ignored when [`network`]
    /// is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_alias: Option<String>,
    /// Container image to pull (e.g. `"oven/bun:1"`).
    pub image: String,
    /// Override the image's CMD (e.g. `["bun", "run", "src/ssr-entry.ts"]`).
    /// `None` leaves the image default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    /// Env vars passed to the container.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Host port mapped to [`container_port`] inside the container. Miniflare's
    /// `SSR_ORIGIN` binding points at `http://127.0.0.1:{host_port}`.
    pub host_port: u16,
    /// Port the SSR process binds inside the container. Defaults to
    /// [`DEFAULT_SSR_CONTAINER_PORT`]; override via the workload's
    /// `expose.mesh.ports[0]` at lowering time.
    pub container_port: u16,
    /// Volume mounts as (host_path, container_path) pairs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<(PathBuf, PathBuf)>,
    /// Container name (canonical `yah-pond-<svc>-<env>-ssr` form).
    pub container_name: String,
    /// Docker `--label` value for filtering (`yah.pond=<svc>:<env>:ssr`).
    pub container_label: String,
    /// Timeout for the initial port + HTTP-ready probes.
    #[serde(with = "duration_secs_serde")]
    pub ready_timeout: Duration,
    /// HTTP path used for readiness probing. Defaults to `/`. Some SSR
    /// frameworks reserve `/` for catch-all rendering; override with a
    /// dedicated health route if `/` returns non-2xx during normal operation.
    #[serde(default = "default_ready_path")]
    pub ready_path: String,
}

fn default_ready_path() -> String {
    "/".to_string()
}

mod duration_secs_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        d.as_secs().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Coordinates of a running SSR-runtime container returned by
/// [`ensure_ssr_runtime_running`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrRuntimeRunning {
    /// URL miniflare points its `SSR_ORIGIN` binding at — host-side, never
    /// includes a trailing slash. Format: `http://127.0.0.1:{host_port}`.
    pub origin_url: String,
    pub container_name: String,
}

/// Bring the SSR-runtime container up: pull image, run, probe TCP readiness,
/// probe HTTP readiness on `ready_path`. Idempotent end-to-end — re-running
/// against an already-Running container of the same name replaces it
/// (`LocalRuntime::run` is idempotent).
pub async fn ensure_ssr_runtime_running(
    runtime: &LocalRuntime,
    spec: &SsrRuntimeSpec,
) -> Result<SsrRuntimeRunning> {
    runtime
        .ensure_image(&spec.image)
        .await
        .with_context(|| format!("pulling {}", spec.image))?;

    let volumes_str: Vec<(PathBuf, String)> = spec
        .volumes
        .iter()
        .map(|(host, target)| (host.clone(), target.display().to_string()))
        .collect();
    let network_aliases = match (&spec.network, &spec.network_alias) {
        (Some(_), Some(alias)) => vec![alias.clone()],
        _ => vec![],
    };
    let run_spec = ContainerRunSpec {
        name: spec.container_name.clone(),
        image: spec.image.clone(),
        label: spec.container_label.clone(),
        ports: vec![(spec.host_port, spec.container_port)],
        env: spec.env.clone(),
        volumes: volumes_str,
        cmd: spec.cmd.clone().unwrap_or_default(),
        cap_add: vec![],
        cgroupns: None,
        network: spec.network.clone(),
        network_aliases,
    };
    runtime
        .run(&run_spec)
        .await
        .with_context(|| format!("starting SSR-runtime container {}", spec.container_name))?;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), spec.host_port);
    if !wait_for_port(addr, spec.ready_timeout).await {
        let _ = runtime
            .stop_and_remove(&spec.container_name, Duration::from_secs(2))
            .await;
        bail!(
            "SSR-runtime container did not bind {addr} within {:?}",
            spec.ready_timeout,
        );
    }

    let origin_url = format!("http://127.0.0.1:{}", spec.host_port);
    let probe_url = format!("{origin_url}{path}", path = spec.ready_path);
    if !wait_for_http_ready(&probe_url, spec.ready_timeout).await {
        let _ = runtime
            .stop_and_remove(&spec.container_name, Duration::from_secs(2))
            .await;
        bail!(
            "SSR-runtime container at {origin_url} did not pass {probe_url} within {:?}",
            spec.ready_timeout,
        );
    }

    info!(
        origin_url = %origin_url,
        container = %spec.container_name,
        "pond SSR-runtime container ready",
    );

    Ok(SsrRuntimeRunning {
        origin_url,
        container_name: spec.container_name.clone(),
    })
}

/// Lower a [`WorkloadSpec`] (camp's source-of-truth shape, carried in
/// `MesofactStaticWorkload.ssr_runtime`) into the focused [`SsrRuntimeSpec`]
/// the bring-up primitive consumes.
///
/// The mapping is intentionally narrow: most `WorkloadSpec` fields (mesh
/// identity, raft, depends_on, secrets, resource limits) are yubaba-cloud
/// concerns that don't apply to a single host-side companion. We pull:
///
/// - `image` → composed `"{registry}/{repository}:{tag}"`
/// - `command` → `cmd` (overrides image CMD when set)
/// - `env` → literal env vars only (SecretRef / MeshRef rejected at lowering
///   for pond; operator must inline the value or use a different secret mount
///   path when those land in pond)
/// - `volumes` → host-side bind mounts only (named volumes deferred)
/// - `expose.mesh.ports[0]` → `container_port` (defaults to
///   [`DEFAULT_SSR_CONTAINER_PORT`])
///
/// `host_port`, `container_name`, `container_label`, and `ready_timeout` are
/// supplied by the caller — they're tied to the pond mirror, not the workload
/// spec itself.
pub fn lower_workload_spec(
    ws: &WorkloadSpec,
    host_port: u16,
    container_name: String,
    container_label: String,
    ready_timeout: Duration,
) -> Result<SsrRuntimeSpec> {
    let image_str = compose_image_ref(&ws.image);

    let mut env_map = BTreeMap::new();
    for var in &ws.env {
        let (key, value) = lower_env_var(var).with_context(|| {
            format!("lowering env var for SSR runtime {}", ws.name)
        })?;
        env_map.insert(key, value);
    }

    let volumes = ws
        .volumes
        .iter()
        .filter_map(lower_volume_mount)
        .collect();

    let container_port = ws
        .expose
        .mesh
        .ports
        .first()
        .copied()
        .unwrap_or(DEFAULT_SSR_CONTAINER_PORT);

    Ok(SsrRuntimeSpec {
        network: None,
        network_alias: None,
        image: image_str,
        cmd: ws.command.clone(),
        env: env_map,
        host_port,
        container_port,
        volumes,
        container_name,
        container_label,
        ready_timeout,
        ready_path: default_ready_path(),
    })
}

/// Compose `"{registry}/{repository}:{tag}"`, preferring `@digest` when set.
fn compose_image_ref(image: &workload_spec::ImageRef) -> String {
    let repo = if image.registry.is_empty() {
        image.repository.clone()
    } else {
        format!("{}/{}", image.registry, image.repository)
    };
    // ImageRef.digest is structurally required (R438-T3); always emit the
    // tag@digest pair. Defensive empty-string check guards against a
    // hand-constructed ImageRef that bypassed the type-level requirement.
    if image.digest.is_empty() {
        format!("{repo}:{}", image.tag)
    } else {
        format!("{repo}:{}@{}", image.tag, image.digest)
    }
}

/// Lower a workload-spec `EnvVar` to a literal `(key, value)` pair. Only
/// `Literal` variants are accepted at this seam — `FromSecret` and `FromMesh`
/// rely on yubaba's secret store + mesh registry, neither of which is wired
/// for pond. Reject with a clear error so misconfiguration surfaces at
/// spec-build time rather than as a confusing container-side failure.
fn lower_env_var(var: &workload_spec::EnvVar) -> Result<(String, String)> {
    match &var.value {
        workload_spec::EnvValue::Literal { value } => {
            Ok((var.name.clone(), value.clone()))
        }
        workload_spec::EnvValue::FromSecret { .. } => bail!(
            "env var {:?}: FromSecret not yet supported in pond SSR-runtime lowering",
            var.name
        ),
        workload_spec::EnvValue::FromMesh { .. } => bail!(
            "env var {:?}: FromMesh not yet supported in pond SSR-runtime lowering",
            var.name
        ),
    }
}

/// Lower a workload-spec `VolumeMount` to a (host_path, container_path) pair.
/// Returns `None` for non-`Bind` variants — Named volumes are yubaba-managed
/// and Tmpfs is in-memory; neither maps cleanly to a host-side bind mount.
fn lower_volume_mount(
    mount: &workload_spec::VolumeMount,
) -> Option<(PathBuf, PathBuf)> {
    match &mount.source {
        workload_spec::VolumeSource::Bind { host_path } => {
            Some((host_path.clone(), mount.target.clone()))
        }
        _ => None,
    }
}

/// Wait for a TCP port to start accepting connections.
async fn wait_for_port(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Wait for an HTTP endpoint to return a 2xx (or 404 — the SSR app may have
/// no route at `/` but still be up). We accept any non-5xx as ready.
async fn wait_for_http_ready(url: &str, timeout: Duration) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(resp) = client.get(url).send().await {
            let s = resp.status();
            if s != StatusCode::SERVICE_UNAVAILABLE
                && s != StatusCode::BAD_GATEWAY
                && s != StatusCode::GATEWAY_TIMEOUT
                && !s.is_server_error()
            {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        EnvValue, EnvVar, ExposeSpec, ImageRef, MeshExpose, MeshIdent, ResourceLimits,
        RestartPolicy, SchemaVersion, StopPolicy, TierTag, VolumeMount, VolumeSource,
    };

    fn minimal_workload_spec() -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: "ssr-runtime".into(),
            image: ImageRef {
                registry: "docker.io".into(),
                repository: "oven/bun".into(),
                tag: "1".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("service".into()),
            replicas: 1,
            command: Some(vec!["bun".into(), "run".into(), "src/ssr.ts".into()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![EnvVar {
                name: "NODE_ENV".into(),
                value: EnvValue::Literal {
                    value: "production".into(),
                },
            }],
            secrets: vec![],
            volumes: vec![VolumeMount {
                source: VolumeSource::Bind {
                    host_path: PathBuf::from("/host/src"),
                },
                target: PathBuf::from("/app/src"),
                read_only: false,
            }],
            resources: ResourceLimits {
                memory_mb: 256,
                cpu_shares: 512,
                ephemeral_storage_mb: 256,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: workload_spec::Millis::from_secs(10),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent("ssr-runtime".into()),
                    ports: vec![3000],
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
    fn lower_composes_image_ref_with_tag_and_digest() {
        let ws = minimal_workload_spec();
        let spec = lower_workload_spec(
            &ws,
            14321,
            "yah-pond-svc-pond-ssr".into(),
            "svc:pond:ssr".into(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(
            spec.image,
            format!("docker.io/oven/bun:1@{}", workload_spec::testing::TEST_DIGEST)
        );
    }

    #[test]
    fn lower_emits_explicit_digest() {
        let mut ws = minimal_workload_spec();
        ws.image.digest = "sha256:abc123".into();
        let spec = lower_workload_spec(
            &ws,
            14321,
            "yah-pond-svc-pond-ssr".into(),
            "svc:pond:ssr".into(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(spec.image, "docker.io/oven/bun:1@sha256:abc123");
    }

    #[test]
    fn lower_copies_cmd_and_env_literals() {
        let ws = minimal_workload_spec();
        let spec = lower_workload_spec(
            &ws,
            14321,
            "yah-pond-svc-pond-ssr".into(),
            "svc:pond:ssr".into(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(spec.cmd.as_deref(), Some(&["bun".to_string(), "run".to_string(), "src/ssr.ts".to_string()][..]));
        assert_eq!(spec.env.get("NODE_ENV").map(String::as_str), Some("production"));
    }

    #[test]
    fn lower_rejects_from_secret_env() {
        let mut ws = minimal_workload_spec();
        ws.env.push(EnvVar {
            name: "SECRET".into(),
            value: EnvValue::FromSecret {
                secret: "stripe-key".into(),
                key: "value".into(),
            },
        });
        let err = lower_workload_spec(
            &ws,
            14321,
            "n".into(),
            "l".into(),
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("FromSecret"));
    }

    #[test]
    fn lower_uses_expose_mesh_port_for_container_port() {
        let ws = minimal_workload_spec();
        let spec = lower_workload_spec(
            &ws,
            14321,
            "n".into(),
            "l".into(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(spec.container_port, 3000);
    }

    #[test]
    fn lower_defaults_container_port_when_no_mesh_port() {
        let mut ws = minimal_workload_spec();
        ws.expose.mesh.ports.clear();
        let spec = lower_workload_spec(
            &ws,
            14321,
            "n".into(),
            "l".into(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(spec.container_port, DEFAULT_SSR_CONTAINER_PORT);
    }

    #[test]
    fn lower_host_volume_pairs_through() {
        let ws = minimal_workload_spec();
        let spec = lower_workload_spec(
            &ws,
            14321,
            "n".into(),
            "l".into(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(spec.volumes.len(), 1);
        assert_eq!(spec.volumes[0].0, PathBuf::from("/host/src"));
        assert_eq!(spec.volumes[0].1, PathBuf::from("/app/src"));
    }

    #[test]
    fn ssr_runtime_spec_serde_roundtrip() {
        let mut env = BTreeMap::new();
        env.insert("FOO".into(), "bar".into());
        let spec = SsrRuntimeSpec {
            network: None,
            network_alias: None,
            image: "oven/bun:1".into(),
            cmd: Some(vec!["bun".into(), "run".into()]),
            env,
            host_port: 14321,
            container_port: 3000,
            volumes: vec![(PathBuf::from("/a"), PathBuf::from("/b"))],
            container_name: "yah-pond-svc-pond-ssr".into(),
            container_label: "svc:pond:ssr".into(),
            ready_timeout: Duration::from_secs(30),
            ready_path: "/".into(),
        };
        let s = serde_json::to_string(&spec).unwrap();
        let round: SsrRuntimeSpec = serde_json::from_str(&s).unwrap();
        assert_eq!(round.image, spec.image);
        assert_eq!(round.host_port, spec.host_port);
        assert_eq!(round.container_port, spec.container_port);
        assert_eq!(round.ready_path, "/");
    }
}
