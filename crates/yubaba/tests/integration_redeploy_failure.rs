//! A deploy that fails at the container backend must not take the previous
//! generation's secrets with it — R854.
//!
//! The live incident: two `yah cloud workload deploy yah-cloud-admin` calls
//! back to back on us-west-001. The second 500'd out of kamaji (containerd:
//! "task yah-cloud-admin: already exists"), and when the operator went looking,
//! `/run/yah/secrets/yah-cloud-admin/` was *gone* — reaped by the deploy
//! handler's backend-failure arm, on a workload that was still declared and one
//! redeploy away from being healthy again.
//!
//! R848 fixed the same overreach on the materialization-failure arm and
//! deliberately left this one alone, because it sits next to `teardown_workload`
//! where reaping is normally right. It is not right here: several of kamaji's
//! refusals (tier guard, admission, an unpullable image) reject *before* the
//! running container is touched, so the files this arm unlinks are the live
//! generation's.
//!
//! What's covered:
//!
//!   1. A failed redeploy leaves an already-materialized secret dir — file and
//!      contents — intact.
//!   2. A failed *first* deploy still reaps, so decrypted material never
//!      outlives a workload that was never running.
//!   3. Recovery: the redeploy after the failure succeeds and the workload is
//!      Running again.
//!
//! Uses `FakeRuntime`'s fault injection, so no container socket is required.
//!
//! ```bash
//! cargo test -p yubaba --features testing --test testing \
//!     -- integration_redeploy_failure::
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use kamaji::fake::{FailMode, FakeRuntime, FaultTarget};
use workload_spec::{
    ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits, RestartPolicy,
    SchemaVersion, SecretMount, SecretRef, SecretTarget, StopPolicy, TierTag, WorkloadSpec,
};
use yubaba::ServerState;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// The one secret this workload mounts, as it sits in the per-machine store.
const SECRET_KEY: &str = "admin-cert";
const SECRET_BODY: &[u8] = b"-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n";

/// A workload that mounts a `LocalFile` secret as a `File` — the shape whose
/// materialized tmpfs dir this ticket is about.
fn secret_spec(name: &str) -> WorkloadSpec {
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
        command: Some(vec!["sh".into(), "-c".into(), "sleep 300".into()]),
        entrypoint: None,
        workdir: None,
        user: None,
        env: vec![],
        secrets: vec![SecretMount {
            source: SecretRef::LocalFile {
                path: PathBuf::from(SECRET_KEY),
            },
            target: SecretTarget::File {
                path: PathBuf::from("/etc/yah/cert.pem"),
                mode: 0o400,
            },
        }],
        volumes: vec![],
        resources: ResourceLimits {
            memory_mb: 64,
            cpu_millis: 128,
            ephemeral_storage_mb: 128,
        },
        depends_on: vec![],
        healthcheck: None,
        // A long-running service, and deliberately no explicit `archetype`:
        // that combination is what R854's archetype fix is about — the
        // materialized secret bind must not infer `Appliance` and get the
        // redeploy refused 409 before it ever reaches the backend.
        restart_policy: RestartPolicy::Always,
        archetype: None,
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(5),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent(name.to_string()),
                ports: MeshExpose::anonymous_ports([8080]),
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: Default::default(),
        annotations: Default::default(),
    }
}

/// A yubaba whose three secret paths all point inside `tmp`: the per-machine
/// store the `LocalFile` ref resolves against, the materialized-secret root,
/// and the (unused here) cluster KEK.
fn boot(tmp: &Path, rt: Arc<FakeRuntime>) -> Arc<ServerState> {
    let store = tmp.join("secret-store");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join(SECRET_KEY), SECRET_BODY).unwrap();

    let mount_root = tmp.join("run-secrets");
    std::fs::create_dir_all(&mount_root).unwrap();

    Arc::new(
        ServerState::load(tmp.join("identity.json"))
            .unwrap()
            .with_secret_paths(tmp.join("cluster.kek"), mount_root)
            .with_local_secret_store(store)
            .with_runtime(rt),
    )
}

async fn deploy(state: &Arc<ServerState>, spec: &WorkloadSpec) -> StatusCode {
    let body = serde_json::json!({ "spec": spec });
    yubaba::build_router(Arc::clone(state))
        .oneshot(
            Request::post("/workloads/deploy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn workload_states(state: &Arc<ServerState>) -> serde_json::Value {
    let resp = yubaba::build_router(Arc::clone(state))
        .oneshot(Request::get("/workloads").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// The materialized-secret dir for `ident`, and the single file in it.
fn secret_dir(state: &ServerState, ident: &str) -> PathBuf {
    state.secret_mount_root.join(ident)
}

fn materialized_file(dir: &Path) -> Option<PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    entries.sort();
    entries.into_iter().next()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// The headline. A redeploy that dies at the backend must leave the running
/// generation's decrypted material exactly where it was — it is still bound
/// into a container, and the workload is still declared.
#[tokio::test]
async fn a_failed_redeploy_leaves_the_running_generations_secrets_alone() {
    let tmp = tempfile::TempDir::new().unwrap();
    let rt = Arc::new(FakeRuntime::new());
    let state = boot(tmp.path(), Arc::clone(&rt));
    let spec = secret_spec("yah-cloud-admin");

    // Deploy 1: healthy, and it materializes the secret dir.
    assert!(
        deploy(&state, &spec).await.is_success(),
        "first deploy should succeed"
    );
    let dir = secret_dir(&state, "yah-cloud-admin");
    let file = materialized_file(&dir).expect("first deploy materializes one secret file");
    assert_eq!(std::fs::read(&file).unwrap(), SECRET_BODY);

    // Deploy 2: refused by the backend, exactly as containerd's "task already
    // exists" refused it live.
    rt.fail_inject(FaultTarget::DeployWorkload, FailMode::Once);
    assert_eq!(
        deploy(&state, &spec).await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an injected backend failure should surface as a 500"
    );

    // The R854 assertion: the dir is still there, with its content, because
    // this request did not create it.
    assert!(
        dir.is_dir(),
        "a failed redeploy must not reap the secret dir it did not create"
    );
    assert_eq!(
        std::fs::read(&file).unwrap(),
        SECRET_BODY,
        "the running generation's secret file must survive intact"
    );

    // And the workload is still declared — the failure did not retract it.
    let states = workload_states(&state).await;
    let listed = states["workloads"]
        .as_array()
        .expect("GET /workloads returns a workload array");
    assert_eq!(listed.len(), 1, "the workload is still declared: {states}");

    // Recovery: the next deploy succeeds, no operator intervention needed.
    assert!(
        deploy(&state, &spec).await.is_success(),
        "the redeploy after a backend failure should succeed"
    );
    assert_eq!(std::fs::read(&file).unwrap(), SECRET_BODY);
}

/// R854, found while writing the test above: a workload that mounts a `File`
/// secret and declares no archetype was deployable exactly once. Materializing
/// the secret appends a read-only bind volume, `effective_archetype()` infers
/// `Appliance` from any volume, and the single-instance guard then refused
/// every later deploy with 409 — before the request reached the backend at all.
#[tokio::test]
async fn a_secret_mounting_server_stays_redeployable() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));
    let spec = secret_spec("ingress");

    assert!(deploy(&state, &spec).await.is_success());
    let second = deploy(&state, &spec).await;
    assert_ne!(
        second,
        StatusCode::CONFLICT,
        "a secret mount must not reclassify a server as a single-instance appliance"
    );
    assert!(second.is_success(), "back-to-back redeploy should succeed");
}

/// The guard the fix above must not have disarmed: a workload that genuinely
/// declares itself an appliance still gets one instance.
#[tokio::test]
async fn a_declared_appliance_is_still_single_instance() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));
    let mut spec = secret_spec("stateful");
    spec.archetype = Some(workload_spec::LifecycleArchetype::Appliance);

    assert!(deploy(&state, &spec).await.is_success());
    assert_eq!(
        deploy(&state, &spec).await,
        StatusCode::CONFLICT,
        "a declared appliance must still refuse a second live instance"
    );
}

/// The other half of the guard, and the property R848 was protecting: when the
/// failing deploy is the one that *created* the dir, decrypted material must
/// not outlive the workload that never started.
#[tokio::test]
async fn a_failed_first_deploy_still_reaps_what_it_materialized() {
    let tmp = tempfile::TempDir::new().unwrap();
    let rt = Arc::new(FakeRuntime::new());
    let state = boot(tmp.path(), Arc::clone(&rt));
    let spec = secret_spec("never-ran");

    rt.fail_inject(FaultTarget::DeployWorkload, FailMode::Once);
    assert_eq!(
        deploy(&state, &spec).await,
        StatusCode::INTERNAL_SERVER_ERROR
    );

    assert!(
        !secret_dir(&state, "never-ran").exists(),
        "a first deploy that failed at the backend must not leave plaintext behind"
    );
}
