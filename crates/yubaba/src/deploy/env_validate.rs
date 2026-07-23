//! Deploy-time environment validation for yubaba workloads.
//!
//! Runs as part of the deploy sequence and races containerd setup. Four stages
//! execute in order; the first failure returns an [`EnvValidateError`] with a
//! structured [`EnvValidateCause`] and flips the workload to `Failed`.
//!
//! **Stage order:**
//! 1. **Image pull** — pull succeeds and (if cluster sigstore is configured)
//!    the signature verifies. Handled by the [`ImageSource`] impl.
//! 2. **Healthcheck** — container reports `Ready` within
//!    `failure_threshold × interval + initial_delay`. Skipped when
//!    `spec.healthcheck` is `None`.
//! 3. **Mesh peering** — raft assigns an IP, WireGuard interface is up, and
//!    peers can reach this workload's `MeshIdent`. **F6 cross-cut**: caller
//!    resolves `FromMesh` env vars *after* this stage succeeds, before building
//!    the containerd spec.
//! 4. **CF tunnel** — Cloudflare tunnel route registers. Skipped when
//!    `spec.expose.public` is `None`.
//!
//! **No implicit retries.** Yubaba's `RestartPolicy` machinery decides whether
//! and how to retry on failure.
//!
//! Failures surface in `yubaba.workloads_status` RPC and are logged to
//! journald as a JSON one-line event with the same shape, so the migration to
//! scryer events (R093) is mechanical.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use workload_spec::{HealthProbe, MeshIdent, WorkloadSpec};

/// A boxed, object-safe async return type. Used so trait methods are usable as
/// `dyn Trait` without the `async_trait` crate. Private — only the trait
/// definitions and test fakes reference it.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ── Cause types ───────────────────────────────────────────────────────────────

/// Structured cause of a deploy-time environment validation failure.
///
/// Serialises to a JSON object with a `"stage"` discriminant field — matches
/// the journald one-line format yubaba logs today so scryer migration (R093) is
/// a mechanical search-and-replace.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum EnvValidateCause {
    /// Stage 1: image pull or sigstore signature check failed.
    ImagePull {
        registry: String,
        repository: String,
        tag: String,
        reason: String,
    },

    /// Stage 2: container healthcheck did not report `Ready` within the
    /// computed deadline (`failure_threshold × interval + initial_delay`).
    HealthcheckTimeout {
        /// Total deadline: `failure_threshold × interval + initial_delay`, ms.
        deadline_ms: u64,
        reason: String,
    },

    /// Stage 3: mesh peering did not complete within the configured timeout.
    /// Either the raft IP assignment timed out, the WireGuard interface failed
    /// to come up, or peers could not reach this workload's `MeshIdent`.
    MeshPeerUnreachable { ident: String, reason: String },

    /// Stage 4: Cloudflare tunnel route did not register in time.
    /// Only triggered when `spec.expose.public` is set.
    CfTunnelFailed { hostname: String, reason: String },
}

/// Deploy-time environment validation failed.
#[derive(Debug)]
pub struct EnvValidateError {
    /// Structured cause identifying which stage failed and why.
    pub cause: EnvValidateCause,
}

impl fmt::Display for EnvValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            EnvValidateCause::ImagePull {
                registry,
                repository,
                tag,
                reason,
            } => {
                write!(
                    f,
                    "image pull failed ({registry}/{repository}:{tag}): {reason}"
                )
            }
            EnvValidateCause::HealthcheckTimeout {
                deadline_ms,
                reason,
            } => {
                write!(f, "healthcheck timed out after {deadline_ms}ms: {reason}")
            }
            EnvValidateCause::MeshPeerUnreachable { ident, reason } => {
                write!(f, "mesh peer unreachable ({ident}): {reason}")
            }
            EnvValidateCause::CfTunnelFailed { hostname, reason } => {
                write!(f, "CF tunnel failed ({hostname}): {reason}")
            }
        }
    }
}

impl std::error::Error for EnvValidateError {}

// ── Trait abstractions for stage injection ────────────────────────────────────

/// Pulls a container image and optionally verifies its sigstore signature.
///
/// The production implementation uses containerd's pull API and runs sigstore
/// verification when the cluster has sigstore configured. Tests inject a fake.
pub trait ImageSource: Send + Sync {
    /// Pull `registry/repository:tag@digest`. Digest is always present per
    /// R438-T3 — implementations should pin against the digest and treat the
    /// tag as informational. Returns `Ok(())` on success; `Err(reason)` on any
    /// failure (not found, auth error, signature reject, network timeout).
    fn pull<'a>(
        &'a self,
        registry: &'a str,
        repository: &'a str,
        tag: &'a str,
        digest: &'a str,
    ) -> BoxFuture<'a, Result<(), String>>;
}

/// Performs a single health probe against a running container.
///
/// The production implementation executes the `HttpGet`, `Exec`, or
/// `TcpConnect` probe. Tests inject a fake. The retry loop (up to
/// `failure_threshold` attempts) is managed by [`stage_healthcheck`].
pub trait HealthcheckProber: Send + Sync {
    /// Run one probe attempt. Returns `Ok(())` when healthy; `Err(reason)` on
    /// probe failure or per-probe timeout.
    fn probe_once<'a>(&'a self, probe: &'a HealthProbe) -> BoxFuture<'a, Result<(), String>>;
}

/// Confirms that a workload's mesh identity is peered and reachable.
///
/// The production implementation waits for the raft IP assignment and verifies
/// the WireGuard interface is up for the given `MeshIdent`. Tests inject a fake.
pub trait MeshPeering: Send + Sync {
    /// Block until `ident` is reachable on the mesh, or return `Err(reason)`
    /// if peering fails or times out.
    fn await_peer_ready<'a>(&'a self, ident: &'a MeshIdent) -> BoxFuture<'a, Result<(), String>>;
}

/// Registers a Cloudflare tunnel route for a public hostname.
///
/// The production implementation calls the Cloudflare API to create or update
/// the tunnel route entry. Tests inject a fake.
pub trait CfTunnel: Send + Sync {
    /// Register (or confirm) the tunnel route for `hostname:port`. Returns
    /// `Ok(())` when the route is active; `Err(reason)` on failure.
    fn register_route<'a>(
        &'a self,
        hostname: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<(), String>>;
}

// ── Per-stage timeout configuration ──────────────────────────────────────────

/// Timeout configuration for each env-validate stage.
///
/// Healthcheck timeout is derived from the spec (`failure_threshold × interval
/// + initial_delay`) rather than carried here. The three fields here cover the
/// stages that don't have spec-embedded timing.
#[derive(Debug, Clone)]
pub struct EnvValidateConfig {
    /// Maximum time for the image pull to complete (stage 1).
    pub image_pull_timeout: Duration,

    /// Maximum time for mesh peering to complete (stage 3).
    pub mesh_peering_timeout: Duration,

    /// Maximum time for the CF tunnel route to register (stage 4).
    pub cf_tunnel_timeout: Duration,
}

impl Default for EnvValidateConfig {
    fn default() -> Self {
        Self {
            image_pull_timeout: Duration::from_secs(120),
            mesh_peering_timeout: Duration::from_secs(60),
            cf_tunnel_timeout: Duration::from_secs(30),
        }
    }
}

// ── Stage implementations ─────────────────────────────────────────────────────

async fn stage_image_pull(
    spec: &WorkloadSpec,
    source: &dyn ImageSource,
    timeout: Duration,
) -> Result<(), EnvValidateCause> {
    let pull = source.pull(
        &spec.image.registry,
        &spec.image.repository,
        &spec.image.tag,
        &spec.image.digest,
    );
    tokio::time::timeout(timeout, pull)
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "image pull timed out after {}ms",
                timeout.as_millis()
            ))
        })
        .map_err(|reason| EnvValidateCause::ImagePull {
            registry: spec.image.registry.clone(),
            repository: spec.image.repository.clone(),
            tag: spec.image.tag.clone(),
            reason,
        })
}

/// Stage 2: healthcheck.
///
/// Skipped immediately when `spec.healthcheck` is `None`. Otherwise:
/// sleeps `initial_delay`, then calls `probe_once` up to `failure_threshold`
/// times (each wrapped in `hc.timeout`), with `interval` between attempts.
/// Returns `Ok(())` on the first successful probe. Returns
/// `Err(HealthcheckTimeout)` after exhausting all attempts.
async fn stage_healthcheck(
    spec: &WorkloadSpec,
    prober: &dyn HealthcheckProber,
) -> Result<(), EnvValidateCause> {
    let hc = match &spec.healthcheck {
        Some(h) => h,
        None => return Ok(()),
    };

    let deadline_ms = hc.failure_threshold as u64 * hc.interval.as_ms() + hc.initial_delay.as_ms();

    // Wait before the first probe.
    if hc.initial_delay.as_ms() > 0 {
        tokio::time::sleep(Duration::from_millis(hc.initial_delay.as_ms())).await;
    }

    // One millisecond floor so a zero timeout doesn't block forever on a slow probe.
    let per_probe_timeout = Duration::from_millis(hc.timeout.as_ms().max(1));

    for attempt in 0..hc.failure_threshold {
        let result = tokio::time::timeout(per_probe_timeout, prober.probe_once(&hc.probe)).await;
        if matches!(result, Ok(Ok(()))) {
            return Ok(());
        }
        // Sleep between probes, but not after the final attempt.
        if attempt + 1 < hc.failure_threshold && hc.interval.as_ms() > 0 {
            tokio::time::sleep(Duration::from_millis(hc.interval.as_ms())).await;
        }
    }

    Err(EnvValidateCause::HealthcheckTimeout {
        deadline_ms,
        reason: format!(
            "container not ready after {} probe attempt(s) (deadline={}ms, \
             failure_threshold={}, interval={}ms, initial_delay={}ms)",
            hc.failure_threshold,
            deadline_ms,
            hc.failure_threshold,
            hc.interval.as_ms(),
            hc.initial_delay.as_ms(),
        ),
    })
}

async fn stage_mesh_peering(
    spec: &WorkloadSpec,
    peering: &dyn MeshPeering,
    timeout: Duration,
) -> Result<(), EnvValidateCause> {
    let ident = &spec.expose.mesh.identity;
    tokio::time::timeout(timeout, peering.await_peer_ready(ident))
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "mesh peering timed out after {}ms",
                timeout.as_millis()
            ))
        })
        .map_err(|reason| EnvValidateCause::MeshPeerUnreachable {
            ident: ident.0.clone(),
            reason,
        })
}

async fn stage_cf_tunnel(
    spec: &WorkloadSpec,
    cf: &dyn CfTunnel,
    timeout: Duration,
) -> Result<(), EnvValidateCause> {
    let public = match &spec.expose.public {
        Some(p) => p,
        None => return Ok(()), // no public exposure — stage skipped
    };
    tokio::time::timeout(timeout, cf.register_route(&public.hostname, public.port))
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "CF tunnel registration timed out after {}ms",
                timeout.as_millis()
            ))
        })
        .map_err(|reason| EnvValidateCause::CfTunnelFailed {
            hostname: public.hostname.clone(),
            reason,
        })
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run all four environment-validation stages in deployment order.
///
/// Stages execute sequentially:
/// 1. Image pull (+ sigstore, delegated to `source`)
/// 2. Healthcheck: probe until `Ready` within the computed deadline
/// 3. Mesh peering: raft IP assigned, WireGuard up, peer reachable
///    — **F6 cross-cut**: after this returns `Ok`, the caller should resolve
///    any `FromMesh` env vars before handing the assembled env to the
///    containerd-spec builder
/// 4. CF tunnel route registration (only when `expose.public` is set)
///
/// Returns `Ok(())` when all stages pass. Returns `Err` with a structured
/// [`EnvValidateError`] on the first failure; later stages do not run.
///
/// **No implicit retries.** Yubaba's `RestartPolicy` machinery decides whether
/// and how to retry.
pub async fn run(
    spec: &WorkloadSpec,
    source: &dyn ImageSource,
    prober: &dyn HealthcheckProber,
    peering: &dyn MeshPeering,
    cf: &dyn CfTunnel,
    config: &EnvValidateConfig,
) -> Result<(), EnvValidateError> {
    stage_image_pull(spec, source, config.image_pull_timeout)
        .await
        .map_err(|cause| EnvValidateError { cause })?;

    stage_healthcheck(spec, prober)
        .await
        .map_err(|cause| EnvValidateError { cause })?;

    // F6: caller resolves FromMesh env vars after this stage returns Ok.
    stage_mesh_peering(spec, peering, config.mesh_peering_timeout)
        .await
        .map_err(|cause| EnvValidateError { cause })?;

    stage_cf_tunnel(spec, cf, config.cf_tunnel_timeout)
        .await
        .map_err(|cause| EnvValidateError { cause })?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod integration {
    mod env_validate {
        use std::future::Future;
        use std::pin::Pin;
        use std::time::Duration;

        use workload_spec::*;

        use crate::deploy::env_validate::{
            run, CfTunnel, EnvValidateCause, EnvValidateConfig, HealthcheckProber, ImageSource,
            MeshPeering,
        };

        type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

        // ── Minimal spec ─────────────────────────────────────────────────────

        fn minimal_spec() -> WorkloadSpec {
            WorkloadSpec {
                schema_version: SchemaVersion::V1,
                name: "test-workload".into(),
                image: ImageRef {
                    registry: "ghcr.io".into(),
                    repository: "test/app".into(),
                    tag: "v1.0".into(),
                    digest: workload_spec::testing::test_digest(),
                },
                tier: TierTag("public".into()),
                tenant: workload_spec::TenantId::singleton(),
                namespace: workload_spec::NamespaceId::singleton(),
                replicas: 1,
                command: None,
                entrypoint: None,
                workdir: None,
                user: None,
                env: vec![],
                secrets: vec![],
                volumes: vec![],
                resources: ResourceLimits {
                    memory_mb: 128,
                    cpu_millis: 256,
                    ephemeral_storage_mb: 128,
                },
                depends_on: vec![],
                healthcheck: None,
                restart_policy: RestartPolicy::Always,
                archetype: None,
                stop_policy: StopPolicy {
                    signal: 15,
                    grace_period: Millis::from_secs(5),
                },
                expose: ExposeSpec {
                    mesh: MeshExpose {
                        identity: MeshIdent("test-workload".into()),
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

        // ── Fakes ────────────────────────────────────────────────────────────

        struct FakeImageSource(Result<(), String>);
        impl ImageSource for FakeImageSource {
            fn pull<'a>(
                &'a self,
                _reg: &'a str,
                _repo: &'a str,
                _tag: &'a str,
                _digest: &'a str,
            ) -> BoxFuture<'a, Result<(), String>> {
                let r = self.0.clone();
                Box::pin(async move { r })
            }
        }

        struct FakeHealthcheckProber(Result<(), String>);
        impl HealthcheckProber for FakeHealthcheckProber {
            fn probe_once<'a>(
                &'a self,
                _probe: &'a HealthProbe,
            ) -> BoxFuture<'a, Result<(), String>> {
                let r = self.0.clone();
                Box::pin(async move { r })
            }
        }

        struct FakeMeshPeering(Result<(), String>);
        impl MeshPeering for FakeMeshPeering {
            fn await_peer_ready<'a>(
                &'a self,
                _ident: &'a MeshIdent,
            ) -> BoxFuture<'a, Result<(), String>> {
                let r = self.0.clone();
                Box::pin(async move { r })
            }
        }

        struct FakeCfTunnel(Result<(), String>);
        impl CfTunnel for FakeCfTunnel {
            fn register_route<'a>(
                &'a self,
                _hostname: &'a str,
                _port: u16,
            ) -> BoxFuture<'a, Result<(), String>> {
                let r = self.0.clone();
                Box::pin(async move { r })
            }
        }

        fn fast_config() -> EnvValidateConfig {
            EnvValidateConfig {
                image_pull_timeout: Duration::from_secs(5),
                mesh_peering_timeout: Duration::from_secs(5),
                cf_tunnel_timeout: Duration::from_secs(5),
            }
        }

        // ── Happy path ────────────────────────────────────────────────────────

        #[tokio::test]
        async fn happy_path_no_healthcheck_no_public() {
            let spec = minimal_spec();
            let result = run(
                &spec,
                &FakeImageSource(Ok(())),
                &FakeHealthcheckProber(Ok(())),
                &FakeMeshPeering(Ok(())),
                &FakeCfTunnel(Ok(())),
                &fast_config(),
            )
            .await;
            assert!(result.is_ok(), "expected Ok, got {result:?}");
        }

        #[tokio::test]
        async fn happy_path_with_healthcheck_and_public() {
            let mut spec = minimal_spec();
            spec.healthcheck = Some(Healthcheck {
                probe: HealthProbe::TcpConnect { port: 8080 },
                interval: Millis::from_ms(1),
                timeout: Millis::from_ms(10),
                initial_delay: Millis::from_ms(0),
                failure_threshold: 3,
            });
            spec.expose.public = Some(PublicExpose {
                hostname: "api.example.io".into(),
                port: 8080,
                tls: PublicTls::CfManaged,
            });

            let result = run(
                &spec,
                &FakeImageSource(Ok(())),
                &FakeHealthcheckProber(Ok(())),
                &FakeMeshPeering(Ok(())),
                &FakeCfTunnel(Ok(())),
                &fast_config(),
            )
            .await;
            assert!(result.is_ok(), "expected Ok, got {result:?}");
        }

        // ── Stage 1: image pull ───────────────────────────────────────────────

        #[tokio::test]
        async fn pull_404() {
            let spec = minimal_spec();
            let err = run(
                &spec,
                &FakeImageSource(Err("404 not found".into())),
                &FakeHealthcheckProber(Ok(())),
                &FakeMeshPeering(Ok(())),
                &FakeCfTunnel(Ok(())),
                &fast_config(),
            )
            .await
            .unwrap_err();

            assert!(
                matches!(
                    &err.cause,
                    EnvValidateCause::ImagePull { registry, repository, tag, reason }
                    if registry == "ghcr.io"
                        && repository == "test/app"
                        && tag == "v1.0"
                        && reason.contains("404")
                ),
                "expected ImagePull cause with 404 reason, got {:?}",
                err.cause
            );
        }

        // ── Stage 2: healthcheck ──────────────────────────────────────────────

        #[tokio::test]
        async fn healthcheck_times_out() {
            let mut spec = minimal_spec();
            // failure_threshold=1: a single failed probe exhausts the budget.
            spec.healthcheck = Some(Healthcheck {
                probe: HealthProbe::TcpConnect { port: 8080 },
                interval: Millis::from_ms(1),
                timeout: Millis::from_ms(1),
                initial_delay: Millis::from_ms(0),
                failure_threshold: 1,
            });

            let err = run(
                &spec,
                &FakeImageSource(Ok(())),
                &FakeHealthcheckProber(Err("connection refused".into())),
                &FakeMeshPeering(Ok(())),
                &FakeCfTunnel(Ok(())),
                &fast_config(),
            )
            .await
            .unwrap_err();

            assert!(
                matches!(
                    &err.cause,
                    EnvValidateCause::HealthcheckTimeout { deadline_ms, .. }
                    if *deadline_ms == 1 // failure_threshold(1) × interval(1ms) + initial_delay(0)
                ),
                "expected HealthcheckTimeout cause, got {:?}",
                err.cause
            );
        }

        #[tokio::test]
        async fn no_healthcheck_skips_probe_stage() {
            let spec = minimal_spec(); // healthcheck: None
            let result = run(
                &spec,
                &FakeImageSource(Ok(())),
                // This prober always fails — would cause HealthcheckTimeout if
                // the stage ran. Passing here confirms the stage is skipped.
                &FakeHealthcheckProber(Err("should not be called".into())),
                &FakeMeshPeering(Ok(())),
                &FakeCfTunnel(Ok(())),
                &fast_config(),
            )
            .await;
            assert!(
                result.is_ok(),
                "healthcheck stage must be skipped when spec.healthcheck is None"
            );
        }

        // ── Stage 3: mesh peering ─────────────────────────────────────────────

        #[tokio::test]
        async fn peer_unreachable() {
            let spec = minimal_spec();
            let err = run(
                &spec,
                &FakeImageSource(Ok(())),
                &FakeHealthcheckProber(Ok(())),
                &FakeMeshPeering(Err("wireguard handshake failed".into())),
                &FakeCfTunnel(Ok(())),
                &fast_config(),
            )
            .await
            .unwrap_err();

            assert!(
                matches!(
                    &err.cause,
                    EnvValidateCause::MeshPeerUnreachable { ident, reason }
                    if ident == "test-workload" && reason.contains("wireguard")
                ),
                "expected MeshPeerUnreachable with workload ident, got {:?}",
                err.cause
            );
        }

        // ── Stage 4: CF tunnel ────────────────────────────────────────────────

        #[tokio::test]
        async fn cf_tunnel_fails() {
            let mut spec = minimal_spec();
            spec.expose.public = Some(PublicExpose {
                hostname: "api.example.io".into(),
                port: 8080,
                tls: PublicTls::CfManaged,
            });

            let err = run(
                &spec,
                &FakeImageSource(Ok(())),
                &FakeHealthcheckProber(Ok(())),
                &FakeMeshPeering(Ok(())),
                &FakeCfTunnel(Err("cloudflare API error".into())),
                &fast_config(),
            )
            .await
            .unwrap_err();

            assert!(
                matches!(
                    &err.cause,
                    EnvValidateCause::CfTunnelFailed { hostname, reason }
                    if hostname == "api.example.io" && reason.contains("cloudflare")
                ),
                "expected CfTunnelFailed with hostname, got {:?}",
                err.cause
            );
        }

        #[tokio::test]
        async fn no_public_expose_skips_cf_stage() {
            let spec = minimal_spec(); // expose.public: None
            let result = run(
                &spec,
                &FakeImageSource(Ok(())),
                &FakeHealthcheckProber(Ok(())),
                &FakeMeshPeering(Ok(())),
                // This tunnel always fails — would cause CfTunnelFailed if the
                // stage ran. Passing confirms the stage is skipped.
                &FakeCfTunnel(Err("should not be called".into())),
                &fast_config(),
            )
            .await;
            assert!(
                result.is_ok(),
                "CF stage must be skipped when expose.public is None"
            );
        }

        // ── Stage ordering ────────────────────────────────────────────────────

        #[tokio::test]
        async fn image_failure_stops_before_later_stages() {
            let spec = minimal_spec();
            // Mesh and CF fakes fail too — but image fails first, so the error
            // should be ImagePull, not MeshPeerUnreachable.
            let err = run(
                &spec,
                &FakeImageSource(Err("pull failed".into())),
                &FakeHealthcheckProber(Ok(())),
                &FakeMeshPeering(Err("mesh failed".into())),
                &FakeCfTunnel(Err("cf failed".into())),
                &fast_config(),
            )
            .await
            .unwrap_err();

            assert!(
                matches!(&err.cause, EnvValidateCause::ImagePull { .. }),
                "ImagePull should short-circuit before MeshPeerUnreachable, got {:?}",
                err.cause
            );
        }
    }
}
