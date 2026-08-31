//! Service-record wiring + restart survival — R594-F6.
//!
//! R594-F3 shipped `service_records` as a tested-but-*unwired* mechanism: the
//! read-model had full unit coverage while `ServerState` constructed no
//! registry and no handler ever called it. These tests exist so that gap
//! cannot silently reopen — they drive the real HTTP handlers through
//! `build_router` and assert on the registry, rather than calling
//! `ServiceRecords` directly (that is what the unit tests in
//! `src/service_records.rs` are for).
//!
//! What's covered:
//!
//!   1. `POST /workloads/deploy` publishes a ready, dialable record.
//!   2. A workload with no mesh ports is not admitted (nothing to dial).
//!   3. `POST /workloads/{ident}/destroy` retracts it.
//!   4. **The ticket's headline**: a restarted yubaba recovers the record —
//!      including the serving port, which `list_workloads()` does not carry —
//!      without any redeploy, and only marks it routable once a refresh
//!      confirms the workload is genuinely still running.
//!
//! Uses `FakeRuntime`, so no container socket is required.
//!
//! ```bash
//! cargo test -p yubaba --features testing --test testing \
//!     -- integration_service_records::
//! ```
//!
//! @arch:see(.yah/docs/architecture/A053-yah-yubaba-integration-testing.md)

use std::net::SocketAddrV4;
use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

use serde_json::Value;

use kamaji::fake::FakeRuntime;
use workload_spec::{
    ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits, RestartPolicy,
    SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
};
use yubaba::service_records::{self, Health};
use yubaba::ServerState;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn serving_spec(name: &str, ports: Vec<u16>) -> WorkloadSpec {
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
                ports,
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: Default::default(),
        annotations: Default::default(),
    }
}

/// A yubaba over `state_dir` with the given runtime attached. Reusing the same
/// `state_dir` across two calls is how these tests simulate a restart: the
/// process-local registry is gone, only the on-disk ledger carries over.
fn boot(state_dir: &Path, rt: Arc<FakeRuntime>) -> Arc<ServerState> {
    Arc::new(
        ServerState::load(state_dir.join("identity.json"))
            .unwrap()
            .with_runtime(rt),
    )
}

async fn deploy(state: &Arc<ServerState>, spec: &WorkloadSpec) -> axum::http::StatusCode {
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

async fn destroy(state: &Arc<ServerState>, ident: &str) -> serde_json::Value {
    let resp = yubaba::build_router(Arc::clone(state))
        .oneshot(
            Request::post(format!("/workloads/{ident}/destroy"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// One turn of the refresh sweep that `service_records::run` performs on a
/// timer in the live daemon. Called directly so the tests don't sleep.
async fn sweep(state: &Arc<ServerState>) {
    let backend = state.active_backend().expect("runtime attached");
    let states = backend.list_workloads().await.unwrap();
    state.service_records.reconcile(&states);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// The producer half of the wiring: a deploy through the real handler must
/// leave behind a record an ingress proxy can actually dial.
#[tokio::test]
async fn deploy_publishes_a_ready_dialable_record() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));

    let status = deploy(&state, &serving_spec("api", vec![8080])).await;
    assert!(status.is_success(), "deploy failed: {status}");

    let ready = state.service_records.ready();
    assert_eq!(ready.len(), 1, "deploy should publish exactly one record");
    let record = &ready[0];
    assert_eq!(record.ident, MeshIdent("api".into()));
    assert_eq!(record.ports, vec![8080]);
    assert_eq!(
        record.endpoints(),
        vec![SocketAddrV4::new(record.mesh_ip, 8080)],
        "endpoint must pair the allocated mesh IP with the declared port"
    );
    assert!(
        record.mesh_ip.octets()[0] == 100,
        "mesh IP should come from the CGNAT pool, got {}",
        record.mesh_ip
    );
}

/// A workload declaring no mesh ports can never be an upstream, so it must not
/// pad the registry (or its ledger) — on a qed forge node that is most
/// deploys.
#[tokio::test]
async fn portless_workload_is_not_admitted_as_an_upstream() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));

    let status = deploy(&state, &serving_spec("batch-job", vec![])).await;
    assert!(status.is_success(), "deploy failed: {status}");

    assert!(
        state.service_records.snapshot().is_empty(),
        "a portless workload has no endpoint to publish"
    );
}

/// A redeploy that drops its mesh ports must not leave the previous
/// generation's record advertising a port this generation no longer serves.
#[tokio::test]
async fn redeploy_without_ports_retracts_the_previous_record() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));

    deploy(&state, &serving_spec("api", vec![8080])).await;
    assert_eq!(state.service_records.ready().len(), 1);

    deploy(&state, &serving_spec("api", vec![])).await;
    assert!(
        state.service_records.ready().is_empty(),
        "the 8080 endpoint is no longer served and must not be advertised"
    );
}

/// The consumer half: destroy must stop advertising the upstream immediately,
/// not wait for a sweep to notice.
#[tokio::test]
async fn destroy_retracts_the_record() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));
    deploy(&state, &serving_spec("api", vec![8080])).await;

    let body = destroy(&state, "api").await;
    assert_eq!(
        body["status"], "destroyed",
        "unexpected destroy body: {body}"
    );

    let record = state
        .service_records
        .get(&MeshIdent("api".into()))
        .expect("record kept for diagnostics");
    assert_eq!(record.health, Health::Retracted);
    assert!(state.service_records.ready().is_empty());
}

/// **The ticket.** Before R594-F6 a yubaba restart lost every service record,
/// and because `list_workloads()` carries no serving port, no amount of
/// reconciling could rebuild one — the only recovery was to redeploy every
/// serving workload even though the containers were running fine.
#[tokio::test]
async fn records_survive_a_restart_without_redeploy() {
    let tmp = tempfile::TempDir::new().unwrap();
    // The same runtime instance across both boots: the *containers* survive
    // the restart, which is exactly the case that used to need a redeploy.
    let rt = Arc::new(FakeRuntime::new());

    let mesh_ip = {
        let state = boot(tmp.path(), Arc::clone(&rt));
        deploy(&state, &serving_spec("api", vec![8080])).await;
        state.service_records.ready()[0].mesh_ip
    };

    // ── restart ──
    let state = boot(tmp.path(), Arc::clone(&rt));

    let record = state
        .service_records
        .get(&MeshIdent("api".into()))
        .expect("record rehydrated from the port ledger");
    assert_eq!(
        record.ports,
        vec![8080],
        "the serving port is the fact nothing else can re-derive"
    );
    assert_eq!(record.mesh_ip, mesh_ip);
    assert!(
        !record.is_ready(),
        "a record read off disk is not evidence the workload is up — it must \
         stay un-routable until a sweep confirms it"
    );

    // First sweep confirms the container really is still running.
    sweep(&state).await;
    let ready = state.service_records.ready();
    assert_eq!(ready.len(), 1, "confirmed-live record becomes routable");
    assert_eq!(ready[0].endpoints(), vec![SocketAddrV4::new(mesh_ip, 8080)]);
}

/// The other half of restart survival: a workload that did *not* survive must
/// be retracted by the first sweep rather than advertised off a stale file.
#[tokio::test]
async fn a_workload_that_died_during_downtime_is_retracted_not_advertised() {
    let tmp = tempfile::TempDir::new().unwrap();
    {
        let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));
        deploy(&state, &serving_spec("api", vec![8080])).await;
    }

    // Fresh runtime = the container is gone (it did not outlive the restart).
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));
    assert!(
        state
            .service_records
            .get(&MeshIdent("api".into()))
            .is_some(),
        "rehydrated, but unconfirmed"
    );
    assert!(state.service_records.ready().is_empty());

    sweep(&state).await;
    assert_eq!(
        state
            .service_records
            .get(&MeshIdent("api".into()))
            .unwrap()
            .health,
        Health::Retracted
    );
}

/// A destroy is durable: the record must not reappear on the next boot.
#[tokio::test]
async fn a_destroyed_workload_does_not_come_back_on_restart() {
    let tmp = tempfile::TempDir::new().unwrap();
    let rt = Arc::new(FakeRuntime::new());
    {
        let state = boot(tmp.path(), Arc::clone(&rt));
        deploy(&state, &serving_spec("api", vec![8080])).await;
        destroy(&state, "api").await;
    }

    let state = boot(tmp.path(), rt);
    assert!(
        state.service_records.snapshot().is_empty(),
        "an explicitly destroyed workload must not be re-advertised"
    );
}

// ── The discovery surface (R594-F8) ───────────────────────────────────────────

/// `GET /service-records[?ready=…]` through the real router.
async fn fetch_records(state: &Arc<ServerState>, query: &str) -> (axum::http::StatusCode, Value) {
    let resp = yubaba::build_router(Arc::clone(state))
        .oneshot(
            Request::get(format!("{}{query}", service_records::DISCOVERY_PATH))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// The headline of R594-F8: a deployed workload becomes a dialable upstream on
/// the network surface an off-node passway polls — not just in-process.
#[tokio::test]
async fn discovery_endpoint_publishes_a_dialable_endpoint_off_node() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));
    deploy(&state, &serving_spec("api", vec![8080])).await;

    let (status, body) = fetch_records(&state, "?ready=true").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["version"], service_records::WIRE_VERSION);

    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["ident"], "api");
    assert_eq!(records[0]["health"], service_records::HEALTH_READY);

    // The dialable form: whatever mesh IP was allocated, paired with the port.
    let mesh_ip = state.service_records.ready()[0].mesh_ip;
    assert_eq!(
        records[0]["endpoints"],
        serde_json::json!([format!("{mesh_ip}:8080")]),
        "endpoints must be pre-paired so a proxy cannot re-derive them wrong"
    );
}

/// Cold start is a 200 with an empty list, never an error — the consumer-side
/// half of the fail-ready posture (an error would be indistinguishable from a
/// transient blip, which passway must NOT treat as "drain every backend").
#[tokio::test]
async fn discovery_endpoint_is_200_with_no_records_at_cold_start() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));

    let (status, body) = fetch_records(&state, "?ready=true").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["records"].as_array().unwrap().len(), 0);
}

/// `?ready=true` is the ingress proxy's query and must hide a not-ready
/// upstream; the unfiltered view keeps it (with the reason) so an operator can
/// see *why* traffic isn't reaching it.
#[tokio::test]
async fn ready_filter_hides_unready_records_but_the_full_view_explains_them() {
    let tmp = tempfile::TempDir::new().unwrap();
    {
        let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));
        deploy(&state, &serving_spec("api", vec![8080])).await;
    }

    // Restart with a runtime that never saw the container: the record
    // rehydrates from the ledger as not-ready.
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));

    let (_, ready_only) = fetch_records(&state, "?ready=true").await;
    assert_eq!(
        ready_only["records"].as_array().unwrap().len(),
        0,
        "a rehydrated-but-unconfirmed record is not routable"
    );

    let (_, all) = fetch_records(&state, "").await;
    let records = all["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["health"], service_records::HEALTH_NOT_READY);
    assert_eq!(records[0]["reason"], "rehydrated");
}

/// Two workloads must come back in a stable order, so a consumer diffing
/// consecutive fetches sees a byte-identical body when nothing changed.
#[tokio::test]
async fn discovery_records_are_sorted_by_ident() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = boot(tmp.path(), Arc::new(FakeRuntime::new()));
    deploy(&state, &serving_spec("zeta", vec![8080])).await;
    deploy(&state, &serving_spec("alpha", vec![9090])).await;

    let (_, body) = fetch_records(&state, "?ready=true").await;
    let idents: Vec<&str> = body["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["ident"].as_str().unwrap())
        .collect();
    assert_eq!(idents, vec!["alpha", "zeta"]);
}
