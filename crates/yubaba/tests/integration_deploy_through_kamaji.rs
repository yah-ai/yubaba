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

use kamaji::sibling::{KamajiClient, KamajiSibling};
use workload_spec::{
    ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits, RestartPolicy,
    StopPolicy, TierTag, WorkloadSpec,
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
        // Call-site repair only: `WorkloadSpec::files` was added while this
        // test tree was shared, and empty is what "no inline files" means for
        // a spec whose whole point is to be minimal.
        files: vec![],
        volumes: vec![],
        resources: ResourceLimits {
            memory_mb: 64,
            cpu_millis: 128,
            memory_request_mb: None,
            cpu_limit_millis: None,
            pids_max: None,
            scratch_floor_mb: None,
        },
        depends_on: vec![],
        requires: vec![],
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
                ports: MeshExpose::anonymous_ports([8080]),
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: Default::default(),
        durability: None,
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

    let client = KamajiClient::connect(sock.clone())
        .await
        .expect("kamaji handshake");
    let sibling = KamajiSibling::new(client, sock, Duration::from_secs(5));
    let state = Arc::new(
        yubaba::ServerState::load(dir.path().join("identity.json"))
            .unwrap()
            .with_constable_client(sibling),
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

/// R330-F33: `GET /workloads/{ident}/deploy-status` reaches kamaji's
/// `DeployStatus` verb over the real wire.
///
/// A bare kamaji has admitted nothing, so the honest answer is 404 — and 404 is
/// the load-bearing case, because it is what tells a polling caller to stop
/// rather than wait out its budget against an ident that will never appear.
/// Getting a *routed* 404 here also proves the route dispatches to kamaji
/// instead of falling through to axum's own not-found.
#[tokio::test]
async fn deploy_status_dispatches_to_kamaji_over_the_real_wire() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("kamaji.sock");
    let (server, stop) = spawn_kamaji(sock.clone()).await;

    let client = KamajiClient::connect(sock.clone())
        .await
        .expect("kamaji handshake");
    let sibling = KamajiSibling::new(client, sock, Duration::from_secs(5));
    let state = Arc::new(
        yubaba::ServerState::load(dir.path().join("identity.json"))
            .unwrap()
            .with_constable_client(sibling),
    );
    let app = yubaba::build_router(state);

    let resp = app
        .oneshot(
            Request::get("/workloads/never-deployed/deploy-status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    // `x-workload-source: kamaji` is the proof the answer came from the UDS.
    let source = resp
        .headers()
        .get("x-workload-source")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = body_json(resp).await;

    assert_eq!(status, StatusCode::NOT_FOUND, "got {status}: {body}");
    assert_eq!(source.as_deref(), Some("kamaji"));
    assert!(
        body.get("error")
            .and_then(|v| v.as_str())
            .is_some_and(|e| e.contains("never-deployed")),
        "the 404 must name the ident kamaji has no record of: {body}"
    );

    let _ = stop.send(());
    server.await.unwrap();
}

/// R870-B24: `GET /workloads/{ident}/spec` reaches kamaji's `Describe` verb
/// over the real wire.
///
/// Worth an end-to-end test rather than only the unit ones on either side,
/// because the failure this verb exists to prevent is silent: the guard that
/// consumes it refuses a push it cannot prove safe, so a route that answered
/// wrongly — or a reply variant that was never classified as a reply and got
/// dropped as a push, the R746-B11 trap — would show up as apply refusing
/// everything, or as a parked connection, long after the change that caused it.
///
/// A bare kamaji has admitted nothing, so the honest answer is `spec: null`
/// with a 200: kamaji answered, and it holds no record. That is deliberately
/// not a 404 — the ident is a legitimate question, the answer is "nothing" —
/// and `x-workload-source: kamaji` is the proof it came off the UDS rather
/// than from axum's own not-found.
#[tokio::test]
async fn workload_spec_dispatches_to_kamaji_over_the_real_wire() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("kamaji.sock");
    let (server, stop) = spawn_kamaji(sock.clone()).await;

    let client = KamajiClient::connect(sock.clone())
        .await
        .expect("kamaji handshake");
    let sibling = KamajiSibling::new(client, sock, Duration::from_secs(5));
    let state = Arc::new(
        yubaba::ServerState::load(dir.path().join("identity.json"))
            .unwrap()
            .with_constable_client(sibling),
    );
    let app = yubaba::build_router(state);

    let resp = tokio::time::timeout(
        Duration::from_secs(30),
        app.oneshot(
            Request::get("/workloads/never-deployed/spec")
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("the spec read-back must answer, not park the caller")
    .unwrap();

    let status = resp.status();
    let source = resp
        .headers()
        .get("x-workload-source")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = body_json(resp).await;

    assert_eq!(status, StatusCode::OK, "got {status}: {body}");
    assert_eq!(source.as_deref(), Some("kamaji"));
    assert!(
        body.get("spec").is_some_and(serde_json::Value::is_null),
        "a kamaji holding no record answers `spec: null`: {body}"
    );

    let _ = stop.send(());
    server.await.unwrap();
}

/// R746-B11, second and separable defect: a kamaji that completes the
/// handshake and then never answers must degrade to a status code, not park
/// the caller's connection forever.
///
/// Every other failure mode on this route already answers — 503 reconnecting,
/// 501 no kamaji, 404 UnknownWorkload, 502 anything else — so an unanswered
/// `DeployStatus` was the one shape that produced an unbounded hang. Live on
/// us-east-001 this read as `curl` sitting at zero bytes past 20s while the
/// same route 404'd instantly for an ident with no deploy record.
///
/// Note what the sibling test above *cannot* catch: it exercises exactly the
/// arm that always worked. The routing bug only ever bit an ident kamaji had
/// a record for, which is why a green suite shipped it.
#[tokio::test]
async fn deploy_status_answers_a_status_code_when_kamaji_never_replies() {
    use kamaji_proto::{decode_frame, encode_frame, KamajiToYubaba, YubabaToKamaji};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("kamaji.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();

    // A kamaji that answers the handshake and nothing else. Holding `stream`
    // matters: the client must be parked on a live connection, not woken by a
    // close, or this passes for the wrong reason.
    let deaf = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];
        loop {
            if decode_frame::<YubabaToKamaji>(&buf).is_ok() {
                break;
            }
            let n = stream.read(&mut tmp).await.unwrap();
            assert!(n > 0, "client closed before the handshake");
            buf.extend_from_slice(&tmp[..n]);
        }
        let welcome = encode_frame(&KamajiToYubaba::Welcome {
            version: kamaji_proto::ProtocolVersion::CURRENT,
            kamaji_version: "deaf-test".into(),
        })
        .unwrap();
        stream.write_all(&welcome).await.unwrap();
        // Never reply to anything else; keep the socket open.
        tokio::time::sleep(Duration::from_secs(120)).await;
    });

    let client = KamajiClient::connect(sock.clone())
        .await
        .expect("kamaji handshake");
    let sibling = KamajiSibling::new(client, sock, Duration::from_secs(5));
    let state = Arc::new(
        yubaba::ServerState::load(dir.path().join("identity.json"))
            .unwrap()
            .with_constable_client(sibling),
    );
    let app = yubaba::build_router(state);

    // The outer budget is the assertion: before the fix this future never
    // resolved at all, so a regression fails here instead of hanging CI.
    let resp = tokio::time::timeout(
        Duration::from_secs(30),
        app.oneshot(
            Request::get("/workloads/yah-marketing/deploy-status")
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("deploy-status must answer even when kamaji is silent")
    .unwrap();

    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::GATEWAY_TIMEOUT,
        "a silent kamaji must read as 504, got {status}: {body}"
    );
    assert!(
        body.get("error")
            .and_then(|v| v.as_str())
            .is_some_and(|e| e.contains("yah-marketing")),
        "the 504 must name the ident it gave up on: {body}"
    );

    deaf.abort();
}

/// R844-F1: a bundle deploy kamaji REFUSES must not leave a service record
/// behind.
///
/// The bundle tier's registration call (`ServiceRecords::admit_bundle`) lives
/// inside `deploy_non_container`'s `Ok` arm, and that placement is the whole
/// guarantee: a record advertises a dialable upstream, so publishing one for a
/// workload that never started is strictly worse than the empty set this
/// ticket fixed — passway would route live traffic into a process that does
/// not exist. Hoisting the call above the `match` (or into the `Err` arm) is
/// an easy, plausible-looking edit that no unit test on `admit_bundle` itself
/// can catch, because at that level the refusal has already been discarded.
///
/// The test is deliberately NON-VACUOUS: the node is given a real mesh IP via
/// `with_mesh_addr` and the bundle declares a port, so `admit_bundle` would
/// admit this workload if it were reached. The empty registry therefore proves
/// the refusal suppressed it, not that some other precondition was missing.
///
/// Note this asserts the negative only. The success arm cannot be exercised
/// in-process: a bare kamaji has no bundle backend, and reaching `Ok` needs
/// kamaji-bin built with `--features bundle-serving` plus an R2 object store
/// holding a real published bundle to materialize. That path is proved live,
/// not here — see this ticket's re-measure step.
#[tokio::test]
async fn a_refused_bundle_deploy_publishes_no_service_record() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("kamaji.sock");
    let (server, stop) = spawn_kamaji(sock.clone()).await;

    let client = KamajiClient::connect(sock.clone())
        .await
        .expect("kamaji handshake");
    let sibling = KamajiSibling::new(client, sock, Duration::from_secs(5));
    let state = Arc::new(
        yubaba::ServerState::load(dir.path().join("identity.json"))
            .unwrap()
            // Both halves admit_bundle needs, so a passing assertion below can
            // only be explained by the refusal.
            .with_mesh_addr(None, "100.64.0.3:7443")
            .with_constable_client(sibling),
    );
    assert_eq!(
        state.node_mesh_ip(),
        Some(std::net::Ipv4Addr::new(100, 64, 0, 3)),
        "test precondition: the node must have a mesh IP, or this passes vacuously"
    );
    let records = Arc::clone(&state);
    let app = yubaba::build_router(state);

    let envelope = workload_spec::Workload::MesofactStatic(workload_spec::MesofactStaticWorkload {
        build: workload_spec::BuildConfig {
            command: Some("bun run build".into()),
            out_dir: PathBuf::from("dist"),
            render_command: None,
        },
        routes: PathBuf::from("./mesofact.routes.ts"),
        build_mode: workload_spec::BuildMode::default(),
        ssr_runtime: None,
        serve_bundle: Some(workload_spec::MesofactServeBundle {
            digest: workload_spec::BlakeHash("a".repeat(64)),
            runtime: "self".into(),
            lifecycle: workload_spec::BundleLifecycle::KeepAlive,
            // Declared, so the port is not the reason nothing is published.
            port: Some(8080),
            env: Default::default(),
            origin: None,
        }),
        revalidate_receiver: None,
    });

    let resp = app
        .oneshot(
            Request::post("/workloads/deploy")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "spec": envelope,
                        "id": "yah-marketing",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let body = body_json(resp).await;
    assert!(
        !status.is_success(),
        "a bare kamaji has no bundle backend and must refuse, got {status}: {body}"
    );

    assert!(
        records.service_records.snapshot().is_empty(),
        "a refused bundle deploy published a record — admit_bundle must stay \
         inside deploy_non_container's Ok arm, or yubaba advertises an \
         upstream that never started: {:?}",
        records.service_records.snapshot()
    );

    let _ = stop.send(());
    server.await.unwrap();
}

/// R876-B13: an unauthenticated `GET /workloads/{ident}/spec` must not serve a
/// resolved secret VALUE.
///
/// The assertion is **value-shaped**, not field-shaped: it looks for the
/// sentinel's bytes anywhere in the response body rather than at a named field,
/// so reshaping `WorkloadSpec` — or adding a new value channel to it — cannot
/// make this pass vacuously. The live defect was found on a `mesofact-static`
/// workload whose `revalidate_receiver.env` held a Cloudflare API token and an
/// S3 access-key pair as plain strings; this drives the same shape.
///
/// The kamaji here is a scripted one rather than the real `spawn_kamaji`,
/// because `Describe` only answers with a record for a workload kamaji actually
/// admitted, and a bare kamaji has no container backend to admit one with. The
/// wire is real — a real `KamajiClient` handshake, a real postcard frame, the
/// real router and the real handler — only the far side's registry is scripted.
#[tokio::test]
async fn a_served_spec_carries_env_names_but_never_resolved_secret_values() {
    use kamaji_proto::{decode_frame, encode_frame, KamajiToYubaba, YubabaToKamaji};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SENTINEL: &str = "SENTINEL-live-credential-4f1c9a";

    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("kamaji.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();

    // The envelope kamaji claims to be supervising: env VALUES are the
    // sentinel, env KEYS are what the route exists to report.
    let mut env = std::collections::BTreeMap::new();
    env.insert("CLOUDFLARE_API_TOKEN".to_string(), SENTINEL.to_string());
    env.insert(
        "MESOFACT_S3_SECRET_ACCESS_KEY".to_string(),
        SENTINEL.to_string(),
    );
    let supervised = workload_spec::Workload::MesofactStatic(workload_spec::MesofactStaticWorkload {
        build: workload_spec::BuildConfig {
            command: Some("bun run build".into()),
            out_dir: PathBuf::from("dist"),
            render_command: None,
        },
        routes: PathBuf::from("./mesofact.routes.ts"),
        build_mode: workload_spec::BuildMode::default(),
        ssr_runtime: None,
        serve_bundle: None,
        revalidate_receiver: Some(workload_spec::MesofactRevalidateReceiver {
            routes: vec!["/".into()],
            publish_config: "mesofact.config.toml".into(),
            mirror_key_env: Some("MESOFACT_MIRROR_KEY".into()),
            env,
            feeds: vec![],
            feed_runtime: None,
            feed_interval_secs: 300,
            feed_project_prefix: None,
            secrets: vec![],
        }),
    });

    // Non-vacuity, PINNED rather than assumed. The absence assertion at the
    // bottom passes just as happily against an envelope that never carried the
    // sentinel, so without this line a future refactor of the fixture above can
    // make the whole test vacuous and it still goes green — which is exactly
    // the silent regression the ticket was filed to prevent.
    assert!(
        serde_json::to_string(&supervised)
            .unwrap()
            .contains(SENTINEL),
        "test precondition: the supervised envelope must actually carry the \
         sentinel, or the redaction assertion below proves nothing"
    );

    // A kamaji that answers the handshake, then answers every `Describe` with
    // that envelope.
    let scripted = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::with_capacity(8192);
        let mut tmp = [0u8; 8192];
        loop {
            match decode_frame::<YubabaToKamaji>(&buf) {
                Ok((msg, consumed)) => {
                    buf.drain(..consumed);
                    let reply = match msg {
                        YubabaToKamaji::Hello { .. } => KamajiToYubaba::Welcome {
                            version: kamaji_proto::ProtocolVersion::CURRENT,
                            kamaji_version: "scripted-test".into(),
                        },
                        YubabaToKamaji::Describe { request_id, id } => {
                            KamajiToYubaba::WorkloadDescription {
                                request_id,
                                id,
                                spec: Some(supervised.clone()),
                            }
                        }
                        // Nothing else is part of this test's contract.
                        _ => continue,
                    };
                    stream.write_all(&encode_frame(&reply).unwrap()).await.unwrap();
                }
                Err(_) => {
                    let n = stream.read(&mut tmp).await.unwrap();
                    assert!(n > 0, "client closed mid-exchange");
                    buf.extend_from_slice(&tmp[..n]);
                }
            }
        }
    });

    let client = KamajiClient::connect(sock.clone())
        .await
        .expect("kamaji handshake");
    let sibling = KamajiSibling::new(client, sock, Duration::from_secs(5));
    let state = Arc::new(
        yubaba::ServerState::load(dir.path().join("identity.json"))
            .unwrap()
            .with_constable_client(sibling),
    );
    let app = yubaba::build_router(state);

    let resp = tokio::time::timeout(
        Duration::from_secs(30),
        app.oneshot(
            Request::get("/workloads/yah-marketing/spec")
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("the spec read-back must answer, not park the caller")
    .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let raw = serde_json::to_string(&body).unwrap();

    // Deliberately never printed on the success path — a failure prints the
    // sentinel, which is a test fixture, not a credential.
    assert!(
        !raw.contains(SENTINEL),
        "an unauthenticated GET served a resolved secret value: {raw}"
    );
    // Non-vacuity: the route must still have answered with the workload, and
    // with the env KEYS, or the assertion above passes because the body is
    // empty rather than because it is redacted.
    assert!(
        raw.contains("CLOUDFLARE_API_TOKEN") && raw.contains("MESOFACT_S3_SECRET_ACCESS_KEY"),
        "the env NAMES are this route's whole purpose and must survive: {raw}"
    );

    scripted.abort();
}
