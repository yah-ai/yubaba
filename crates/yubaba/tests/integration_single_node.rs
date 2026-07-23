//! Single-node local mirror E2E test.
//!
//! Exercises the full yubaba HTTP API → `ContainerRuntime` path for one node:
//! start yubaba in-process, deploy a `WorkloadSpec`, wait for Running,
//! assert the state round-trips via `/workloads/{ident}/state`.
//!
//! ## Running
//!
//! ```bash
//! # Local tier — requires a running containerd socket (Colima on macOS):
//! cargo test -p yubaba --features containerd-integration \
//!     --test integration_single_node
//!
//! # Smoke tier — provisions a real Hetzner CPX-11 (est. $0.05):
//! YAH_SMOKE=1 \
//! HETZNER_API_TOKEN=... \
//! YAH_WARDEN_URL=https://... \
//! YAH_WARDEN_SHA256=<sha256> \
//! cargo test -p yubaba --features containerd-integration \
//!     --test integration_single_node -- --ignored
//! ```
//!
//! The `__local` variant skips gracefully when neither containerd nor Colima
//! is reachable (keeps `cargo test` green in standard CI without a container
//! runtime).
//!
//! @yah:ticket(R091-F10, "single-node E2E: deploy + state round-trip in both tiers")
//! @yah:at(2026-05-13T00:26:04Z)
//! @yah:status(review)
//! @yah:parent(R091)
//! @yah:see(.yah/docs/architecture/A053-yah-yubaba-integration-testing.md)
//! @yah:next("Human verify: cargo test -p yubaba --features containerd-integration --test integration_single_node against a Colima socket. Confirm single_node_e2e__local passes. Then archive F10 and proceed to verify F6+F7+F8+F9 the same way.")
//! @yah:handoff("integration_single_node.rs: #[test_with_provider(local, smoke)] on single_node_e2e<P,R> — spins up a 1-node Cluster via test_cluster(), deploys alpine:latest with WorkloadSpec, polls wait_for_state to Running (60s timeout), asserts GET /workloads/{ident}/state round-trips. Local variant self-skips when containerd is unreachable. Smoke variant has #[ignore], requires YAH_SMOKE=1. cargo check --features containerd-integration,testing clean; all 74 lib + integration tests pass.")
//! @yah:verify("cargo test -p yubaba --features containerd-integration --test integration_single_node — single_node_e2e__local passes deploy+state round-trip against Colima containerd. Smoke variant excluded without YAH_SMOKE=1.")

use std::time::Duration;

use cloud::provider::MachineProvider;
use kamaji::Kamaji as ContainerRuntime;
use workload_spec::{
    ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits, RestartPolicy,
    SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
};
use yubaba_test_harness::{test_cluster, wait_for_state, WorkloadStatus};
use yubaba_test_macros::test_with_provider;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal test WorkloadSpec with the given mesh identity name.
///
/// Uses `docker.io/library/alpine:latest` — a tiny image that starts quickly
/// and exits cleanly. The command overrides the default Alpine entrypoint so
/// the container stays alive for the duration of the test.
fn test_workload_spec(name: &str) -> WorkloadSpec {
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: name.to_string(),
        image: ImageRef {
            registry: "docker.io".into(),
            repository: "library/alpine".into(),
            tag: "latest".into(),
            digest: workload_spec::testing::test_digest(),
        },
        tier: TierTag("infra".into()),
        tenant: workload_spec::TenantId::singleton(),
        namespace: workload_spec::NamespaceId::singleton(),
        replicas: 1,
        // Keep the container alive for the test duration.
        command: Some(vec!["sh".into(), "-c".into(), "sleep 300".into()]),
        entrypoint: None,
        workdir: None,
        user: None,
        env: vec![],
        secrets: vec![],
        volumes: vec![],
        resources: ResourceLimits {
            memory_mb: 64,
            cpu_millis: 128,
            ephemeral_storage_mb: 128,
        },
        depends_on: vec![],
        healthcheck: None,
        restart_policy: RestartPolicy::Never,
        archetype: None,
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

// ── E2E test ──────────────────────────────────────────────────────────────────

/// Single-node E2E: start yubaba, deploy a `WorkloadSpec`, assert it reaches
/// `Running`, then verify state round-trips via the `/workloads/{ident}/state`
/// RPC.
///
/// Local tier: yubaba runs in-process with `ContainerdRuntime` pointing at
/// the Colima socket (or the system containerd socket on Linux). The workload
/// is an `alpine` container deployed into containerd.
///
/// Smoke tier: yubaba runs on a real Hetzner CPX-11 machine provisioned via
/// cloud-init. Same assertions, same test code. Auto-teardown on exit.
#[test_with_provider(local, smoke)]
async fn single_node_e2e<P, R>(p: P, rt: R)
where
    P: MachineProvider + Clone + Send + Sync + 'static,
    R: ContainerRuntime + 'static,
{
    let cluster = test_cluster(&p, rt, 1)
        .await
        .expect("test_cluster should spin up a single-node cluster");

    let yubaba = cluster.yubaba(0);

    // Sanity: yubaba is healthy before we try to deploy.
    yubaba
        .health_check()
        .await
        .expect("yubaba /health should return 200 before deploy");

    // Deploy a test workload.
    let spec = test_workload_spec("test-app");
    yubaba
        .deploy_workload(&spec)
        .await
        .expect("deploy_workload should succeed");

    // Poll until Running or timeout at 60 s (local: typically <5 s; smoke: <30 s).
    let final_status = wait_for_state(
        yubaba,
        &spec.expose.mesh.identity,
        WorkloadStatus::Running,
        Duration::from_secs(60),
    )
    .await
    .expect("workload should reach Running within 60s");

    assert_eq!(
        final_status,
        WorkloadStatus::Running,
        "workload did not reach Running"
    );

    // Assert the spec round-trips: GET /workloads/{ident}/state returns Running.
    let polled = yubaba
        .get_workload_state(&spec.expose.mesh.identity)
        .await
        .expect("get_workload_state RPC should succeed")
        .expect("workload should be present after deploy");

    assert_eq!(
        polled,
        WorkloadStatus::Running,
        "round-trip via /workloads/{{ident}}/state should show Running"
    );

    // Cluster teardown happens in Drop.
}
