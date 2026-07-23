//! R626-F5 regression: `POST /workloads/deploy` dispatches through the
//! sibling Kamaji when one is attached, instead of silently stub-accepting.
//!
//! The read side (`GET /workloads`, `/state`, `/drain`) migrated to Kamaji at
//! R406-T8; deploy was left on the legacy in-process runtime because Kamaji's
//! Deploy arm was unimplemented. R406-T9 (containerd) + R626-F1 (docker) landed
//! the backend, and `deploy_workload_spec` now routes through
//! `ServerState::active_backend()` — which prefers the sibling `KamajiClient`.
//!
//! The bug this guards against: on a darwin/pond node built without
//! containerd-integration, the pre-migration deploy path ran in STUB MODE — a
//! qed forge job was accepted (`202 {"runtime":"stub"}`) and then never ran.
//! With a Kamaji attached, deploy must reach it. A bare Kamaji (no docker /
//! containerd backend) *refuses* a container deploy, so the handler surfaces
//! that refusal — which is exactly the proof that deploy was routed to Kamaji
//! and NOT stub-accepted.
//!
//! Part of R626-F5 — canonical annotation lives in
//! `oss/yubaba/crates/yubaba/src/lib.rs`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tower::ServiceExt;

use kamaji::sibling::KamajiClient;
use workload_spec::{
    ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits, RestartPolicy,
    SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
};

/// Spawn a real Kamaji on `socket` and wait for the listener to bind.
/// Mirrors `integration_constable_client::spawn_constable`.
async fn spawn_kamaji(socket: PathBuf) -> (tokio::task::JoinHandle<()>, oneshot::Sender<()>) {
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server_path = socket.clone();
    let handle = tokio::spawn(async move {
        let _ = kamaji_bin::serve_with_shutdown(&server_path, async move {
            let _ = stop_rx.await;
        })
        .await;
    });
    for _ in 0..50 {
        if tokio::net::UnixStream::connect(&socket).await.is_ok() {
            return (handle, stop_tx);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("kamaji never bound the UDS at {}", socket.display());
}

/// A minimal, shape-valid container spec — no ingress, no secrets, so the
/// deploy path runs straight to the backend dispatch.
fn container_spec(name: &str) -> WorkloadSpec {
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: name.to_string(),
        image: ImageRef {
            registry: "docker.io".into(),
            repository: "library/alpine".into(),
            tag: "latest".into(),
            digest: ImageRef::UNPINNED_DIGEST.to_string(),
        },
        tier: TierTag("private".into()),
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
            memory_mb: 64,
            cpu_millis: 128,
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
                identity: MeshIdent(name.to_string()),
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

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// With a Kamaji attached, deploy routes to it — never stub-accepts. This is
/// the exact regression bar for the darwin build-worker bug (R626-F5 gotcha).
#[tokio::test]
async fn deploy_with_kamaji_attached_routes_to_kamaji_not_stub() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("kamaji.sock");
    let (server, stop) = spawn_kamaji(sock.clone()).await;

    let client = KamajiClient::connect(sock).await.expect("kamaji handshake");
    let state = Arc::new(
        yubaba::ServerState::load(dir.path().join("identity.json"))
            .unwrap()
            .with_constable_client(Arc::new(client)),
    );
    let app = yubaba::build_router(state);

    let spec = container_spec("f5-probe");
    let resp = app
        .oneshot(
            Request::post("/workloads/deploy")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "spec": spec })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let body = body_json(resp).await;

    // The bug: a backend-less node used to answer 202 {"runtime":"stub"} and
    // the workload never ran. A Kamaji-attached yubaba must NOT do that.
    assert_ne!(
        status,
        StatusCode::ACCEPTED,
        "deploy stub-accepted with a Kamaji attached (the R626-F5 bug): {body}"
    );
    assert_ne!(
        body.get("runtime").and_then(|v| v.as_str()),
        Some("stub"),
        "deploy ran in stub mode instead of routing to Kamaji: {body}"
    );

    // A bare Kamaji (no docker/containerd backend) refuses a container deploy,
    // and the handler surfaces that refusal as a 5xx — which proves the deploy
    // reached Kamaji rather than being handled in-process.
    assert!(
        status.is_server_error(),
        "expected Kamaji's backend-refused to surface as 5xx, got {status}: {body}"
    );

    let _ = stop.send(());
    server.await.unwrap();
}
