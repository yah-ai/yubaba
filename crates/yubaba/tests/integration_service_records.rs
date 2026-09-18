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
    StopPolicy, TierTag, WorkloadSpec,
};
use yubaba::service_records::{self, Health};
use yubaba::ServerState;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Expected-value side of a named port assertion (R844-F15).
fn named_ports(pairs: &[(&str, u16)]) -> std::collections::BTreeMap<String, u16> {
    pairs.iter().map(|(n, p)| ((*n).to_string(), *p)).collect()
}

/// A serving workload that is also a **reachable** one — host-networked, the
/// shape `.yah/infra/workloads/yah-cloud-admin.toml` declares.
///
/// R881-B1: a record is only `Ready` if the workload binds its ports in the
/// node's netns, so the tests below — which are about wiring, the ledger and
/// restart survival — declare that shape rather than leaning on a bare spec
/// whose meaning changed. [`isolated_spec`] is the unreachable counterpart, and
/// only the R881-B1 test uses it.
fn serving_spec(name: &str, ports: Vec<u16>) -> WorkloadSpec {
    let mut spec = isolated_spec(name, ports);
    spec.annotations.insert(
        workload_spec::HOST_NETWORK_ANNOTATION.to_string(),
        workload_spec::HOST_NETWORK_VALUE.to_string(),
    );
    spec
}

/// The tenant shape: no networking annotation, so runc unshares a fresh netns
/// and the declared ports are bound where nothing on the node — and nothing on
/// the mesh — can reach them.
fn isolated_spec(name: &str, ports: Vec<u16>) -> WorkloadSpec {
    WorkloadSpec {
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
            memory_request_mb: None,
            cpu_limit_millis: None,
            pids_max: None,
            scratch_floor_mb: None,
        },
        depends_on: vec![],
        requires: vec![],
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
                ports: MeshExpose::anonymous_ports(ports),
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: Default::default(),
        durability: None,
        annotations: Default::default(),
        files: Vec::new(),
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

/// [`boot`], but as a node that actually holds a mesh address — what every
/// fleet node is, and what [`boot`] alone is not (R844-B11).
///
/// `bind` is the `--bind` a real `yubaba serve` gets, and `ServerState`
/// derives `node_mesh_ip` from it. That address is now the *only* one a
/// deployed workload's service record can advertise, so a test that wants to
/// assert anything about a record's address has to boot a node that has one.
fn boot_on_mesh(state_dir: &Path, rt: Arc<FakeRuntime>, bind: &str) -> Arc<ServerState> {
    Arc::new(
        ServerState::load(state_dir.join("identity.json"))
            .unwrap()
            .with_runtime(rt)
            .with_mesh_addr(None, bind),
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
    assert!(
        yubaba::service_records::sweep_once(state).await,
        "the sweep must have a backend to list"
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// The producer half of the wiring: a deploy through the real handler must
/// leave behind a record an ingress proxy can actually dial.
#[tokio::test]
async fn deploy_publishes_a_ready_dialable_record() {
    let tmp = tempfile::TempDir::new().unwrap();
    // R844-B11: deliberately NOT `100.64.0.1`, `.2` or `.3`. Those are the
    // first three draws of the counter this replaced, and the first three real
    // node addresses in the fleet — the collision that made a record advertise
    // a neighbour. A node address the counter could never have produced is what
    // makes the assertion below discriminating.
    let state = boot_on_mesh(
        tmp.path(),
        Arc::new(FakeRuntime::new()),
        "100.64.0.7:7443",
    );

    let status = deploy(&state, &serving_spec("api", vec![8080])).await;
    assert!(status.is_success(), "deploy failed: {status}");

    let ready = state.service_records.ready();
    assert_eq!(ready.len(), 1, "deploy should publish exactly one record");
    let record = &ready[0];
    assert_eq!(record.ident, MeshIdent("api".into()));
    assert_eq!(record.ports, named_ports(&[("http", 8080)]));
    assert_eq!(
        record.port("http"),
        Some(8080),
        "a single-listener workload's port resolves by the name every tier gives it"
    );
    assert_eq!(
        record.endpoints(),
        vec![SocketAddrV4::new(record.mesh_ip, 8080)],
        "endpoint must pair the allocated mesh IP with the declared port"
    );
    // R844-B11: the record advertises THIS NODE's own address, not an invented
    // one. This assertion replaces `octets()[0] == 100` — "somewhere in the
    // CGNAT pool" — which is exactly the property the bug satisfied: the
    // counter drew from that pool and its third draw was us-east-001's real
    // address, so a west node published a live-looking endpoint one node over.
    // Being in the right /10 was never the invariant; being the ANSWERING
    // node's address is.
    assert_eq!(
        record.mesh_ip,
        state
            .node_mesh_ip()
            .expect("booted on a mesh address, so the node has one"),
        "a service record's address must equal the address of the node serving \
         it — that is the invariant to check against a live `GET /service-records` \
         too, per R844-B11's verify"
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
        named_ports(&[("http", 8080)]),
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
    assert_eq!(
        records[0]["named_endpoints"],
        serde_json::json!({ "http": format!("{mesh_ip}:8080") }),
        "R844-F15: the same endpoint, selectable by what the port IS"
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

/// **R881-B1's acceptance test**, end to end across the seam the incident
/// crossed: yubaba's deploy handler → `GET /service-records?ready=true` →
/// `yah cloud apply`'s upstream resolution.
///
/// The setup is the measured live shape and nothing else: `noisetable-account`,
/// tenant tier, its own netns, `[expose.mesh] ports = [4332]`, deployed onto
/// the mesh node `100.64.0.3` — and a fronted rule for `api.noisetable.com`.
/// What shipped was `PASSWAY_UPSTREAMS=api.noisetable.com=100.64.0.3:4332`,
/// pointing at a port nothing on that host was listening on, so the front door
/// 503'd while looking perfectly healthy to every consumer.
///
/// The apply must now *fail*, and the assertion is written both ways round —
/// that it errors, and that the address never appears — because "errored" alone
/// would also pass if the plan had rendered the dead upstream and then tripped
/// over something unrelated.
///
/// `ingress.rs`'s guard ("a rule left unresolved is an error here rather than a
/// dead upstream later") needed no change: it was always correct and was being
/// fed a fabricated record. This test is the proof that feeding it an honest
/// one is what switches it on.
#[tokio::test]
async fn an_unroutable_tenant_workload_makes_the_ingress_apply_refuse() {
    use cloud::config::IngressProvider;
    use cloud::reconciler::ingress::{IngressPlan, IngressRule};
    use cloud::reconciler::service_discovery::{DiscoveredRecord, ServiceRecordFanout};

    let tmp = tempfile::TempDir::new().unwrap();
    let state = boot_on_mesh(tmp.path(), Arc::new(FakeRuntime::new()), "100.64.0.3:7443");

    let status = deploy(&state, &isolated_spec("noisetable-account", vec![4332])).await;
    assert!(
        status.is_success(),
        "the deploy itself must still succeed — R881-B1 is about the record \
         being honest, not about refusing to run the workload: {status}"
    );

    // What `yah cloud apply` reads off the node.
    let (_, ready) = fetch_records(&state, "?ready=true").await;
    let discovered: Vec<DiscoveredRecord> = ready["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| DiscoveredRecord {
            ident: r["ident"].as_str().unwrap().to_string(),
            mesh_ip: r["mesh_ip"].as_str().unwrap().to_string(),
            ports: r["ports"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_u64().unwrap() as u16)
                .collect(),
            named_ports: Default::default(),
        })
        .collect();
    assert!(
        discovered.is_empty(),
        "the front door was offered an upstream for a workload in its own \
         netns: {discovered:?}"
    );

    let mut plan = IngressPlan {
        provider: IngressProvider::Passway,
        rules: vec![IngressRule {
            hostname: "api.noisetable.com".into(),
            port: Some(4332),
            slot: "compute".into(),
            provider_id: None,
            machines: vec!["us-east-001".into()],
            upstream_hosts: Vec::new(),
        }],
        front_doors: Vec::new(),
        tunnel_id: None,
        edge_provider_id: None,
        image: None,
        auth: None,
        via: None,
        behind_tunnel: false,
        tunnel_door: None,
    };
    let mut fanout = ServiceRecordFanout::default();
    fanout.push_answer("us-east-001", discovered);

    let err = plan.resolve_upstreams_from(&fanout).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("api.noisetable.com"),
        "the refusal must name the rule an operator has to act on, got: {msg}"
    );

    let rendered = plan.passway_upstreams().unwrap_or_default().join(",");
    assert!(
        !rendered.contains("100.64.0.3:4332"),
        "the dead upstream from the live incident was rendered anyway: {rendered}"
    );
}

// ── R881-B8: the silent fallback to the in-process runtime ───────────────────

/// [`boot_on_mesh`], plus the `--container-net` a fleet node carries (R881-T4).
///
/// With one, `workload_bind_ip` allocates an isolated workload an address of
/// its own out of the node's `/24` — which is a promise that *something* wires
/// a veth behind it. Only the kamaji sibling does. This helper attaches no
/// sibling, which is precisely the state a fleet node falls into when
/// `kamaji.service` is down or misframing.
fn boot_on_mesh_with_container_net(
    state_dir: &Path,
    rt: Arc<FakeRuntime>,
    bind: &str,
) -> Arc<ServerState> {
    Arc::new(
        ServerState::load(state_dir.join("identity.json"))
            .unwrap()
            .with_runtime(rt)
            .with_mesh_addr(None, bind)
            .with_container_net(kamaji::container_net::ContainerNet::defaults()),
    )
}

/// [`deploy`], keeping the body — the refusal has to be legible, not just 5xx.
async fn deploy_response(
    state: &Arc<ServerState>,
    spec: &WorkloadSpec,
) -> (axum::http::StatusCode, Value) {
    let body = serde_json::json!({ "spec": spec });
    let resp = yubaba::build_router(Arc::clone(state))
        .oneshot(
            Request::post("/workloads/deploy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// **R881-B8's acceptance test.** Measured live on us-east-001 2026-09-11: a
/// kamaji-proto version mismatch made the sibling unreachable, `active_backend`
/// fell through to yubaba's in-process containerd runtime without a word in
/// either journal, and two `noisetable-account` deploys came up holding only
/// `lo` — while the record advertised `10.128.3.2`, an address the in-process
/// runtime never wires (`join_netns: None`, no `container_net` call at all).
///
/// The fix is the refusal, not a second netns implementation: this is the same
/// answer kamaji-bin already gives on its own path when it was told to do
/// container networking and could not. `deploy_calls()` is the load-bearing
/// half — a 503 emitted *after* the container was started would leave the same
/// orphan behind, so the assertion is that the backend was never asked.
#[tokio::test]
async fn a_workload_needing_a_wired_netns_is_refused_when_the_sibling_is_gone() {
    let tmp = tempfile::TempDir::new().unwrap();
    let rt = Arc::new(FakeRuntime::new());
    let state = boot_on_mesh_with_container_net(tmp.path(), Arc::clone(&rt), "100.64.0.3:7443");

    let (status, body) =
        deploy_response(&state, &isolated_spec("noisetable-account", vec![4332])).await;

    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "an isolated-netns deploy went through the in-process runtime, which \
         cannot give it the address yubaba just allocated: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("network namespace")),
        "the refusal must say what is missing, not just fail: {body}"
    );
    assert!(
        rt.deploy_calls().is_empty(),
        "the container was started anyway — a refusal after the fact leaves \
         exactly the orphan namespace the incident left: {:?}",
        rt.deploy_calls()
    );

    let (_, all) = fetch_records(&state, "").await;
    assert!(
        all["records"].as_array().unwrap().is_empty(),
        "a refused deploy must publish no record at all: {all}"
    );
}

/// The refusal is narrow, and both halves of "narrow" are load-bearing.
///
/// A workload that binds the node's own ports (`yah.network = "host"`) needs no
/// namespace wired, so it must still deploy through the in-process runtime —
/// that is desktop, CI and pond's only backend. And a node started *without*
/// `--container-net` never promised an address in the first place: R881-B1
/// already publishes that workload as `NotReady { reason: "unroutable" }`,
/// which is honest, so refusing it here would break every dev node to fix a
/// fleet bug.
#[tokio::test]
async fn the_refusal_spares_host_networked_workloads_and_nodes_with_no_range() {
    let tmp = tempfile::TempDir::new().unwrap();
    let rt = Arc::new(FakeRuntime::new());
    let state = boot_on_mesh_with_container_net(tmp.path(), Arc::clone(&rt), "100.64.0.3:7443");

    let (status, body) = deploy_response(&state, &serving_spec("yah-cloud-admin", vec![4325])).await;
    assert!(
        status.is_success(),
        "a host-networked workload binds the node's ports and needs nothing \
         wired: {status} {body}"
    );

    let dev_tmp = tempfile::TempDir::new().unwrap();
    let dev_rt = Arc::new(FakeRuntime::new());
    let dev = boot_on_mesh(dev_tmp.path(), Arc::clone(&dev_rt), "100.64.0.3:7443");
    let (status, body) =
        deploy_response(&dev, &isolated_spec("noisetable-account", vec![4332])).await;
    assert!(
        status.is_success(),
        "a node with no container range makes no promise to break — R881-B1's \
         unroutable record is the honest answer there: {status} {body}"
    );
    assert_eq!(dev_rt.deploy_calls(), vec!["noisetable-account".to_string()]);
}

/// Spawn a real kamaji on `socket` and wait for the listener to bind. Mirrors
/// `integration_deploy_through_kamaji::spawn_kamaji`, which lives in the other
/// test group root (`tests/main.rs`, no `testing` feature) and so cannot be
/// shared with a test that needs `FakeRuntime` as the fallback backend.
async fn spawn_kamaji(
    socket: std::path::PathBuf,
) -> (tokio::task::JoinHandle<()>, tokio::sync::oneshot::Sender<()>) {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server_path = socket.clone();
    let handle = tokio::spawn(async move {
        let _ = kamaji_bin::serve_with_shutdown(&server_path, async move {
            let _ = stop_rx.await;
        })
        .await;
    });
    for _ in 0..100 {
        if tokio::net::UnixStream::connect(&socket).await.is_ok() {
            return (handle, stop_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("kamaji never bound the UDS at {}", socket.display());
}

/// Both arms of the selector, on one fleet-shaped node: a **live** sibling wins
/// over the in-process runtime, and a **configured-but-unreachable** one is the
/// substituted state that R881-B8 exists for.
///
/// The second half is what happened on us-east-001 — a kamaji-proto V9/V10 skew
/// made the two processes misframe each other, `KamajiSibling::current()` went
/// `None`, and every deploy quietly went to a backend that wires no namespace.
/// It is reached here with `KamajiSibling::disconnected` rather than by killing
/// the kamaji from the first half, because that does not work:
/// `kamaji_bin::serve_with_shutdown` spawns each connection handler detached
/// (server.rs, the `tokio::spawn` inside its accept loop), so stopping the
/// accept loop leaves the established client connected and `is_dead()` false
/// forever. The first version of this test did exactly that and sat through its
/// whole 15s window without the watchdog ever clearing.
#[tokio::test]
async fn a_configured_but_unreachable_sibling_refuses_the_deploy_and_skips_the_sweep() {
    let tmp = tempfile::TempDir::new().unwrap();
    let sock = tmp.path().join("kamaji.sock");

    // Arm one: a real kamaji on a real UDS must win over the in-process
    // runtime. Without this the assertions below would also pass on a node
    // whose sibling never worked at all.
    {
        let (server, stop) = spawn_kamaji(sock.clone()).await;
        let client = kamaji::sibling::KamajiClient::connect(sock.clone())
            .await
            .expect("kamaji handshake");
        let live = Arc::new(
            ServerState::load(tmp.path().join("identity.json"))
                .unwrap()
                .with_runtime(Arc::new(FakeRuntime::new()) as Arc<dyn kamaji::Kamaji + Send + Sync>)
                .with_constable_client(kamaji::sibling::KamajiSibling::new(
                    client,
                    sock.clone(),
                    std::time::Duration::from_millis(200),
                )),
        );
        let backend = live.workload_backend().expect("a backend");
        assert!(backend.is_sibling(), "the live sibling must win");
        assert!(!live.sibling_substituted(&backend));
        let _ = stop.send(());
        server.await.unwrap();
    }

    // Arm two: the same node, sibling unreachable.
    let rt = Arc::new(FakeRuntime::new());
    let state = Arc::new(
        ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_runtime(rt.clone())
            .with_mesh_addr(None, "100.64.0.3:7443")
            .with_container_net(kamaji::container_net::ContainerNet::defaults())
            .with_constable_client(kamaji::sibling::KamajiSibling::disconnected(sock)),
    );
    let backend = state.workload_backend().expect("the inlined runtime remains");
    assert!(!backend.is_sibling());
    assert!(
        state.sibling_substituted(&backend),
        "a node that HAS a sibling and is not reaching it must read as \
         substituted — a node that never had one must not"
    );

    // The deploy half: refused before the in-process runtime is asked.
    let (status, body) =
        deploy_response(&state, &isolated_spec("noisetable-account", vec![4332])).await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "the exact us-east-001 sequence deployed a workload into a bare \
         namespace and advertised an address for it: {body}"
    );
    assert!(rt.deploy_calls().is_empty(), "{:?}", rt.deploy_calls());

    // The read half. `sweep_once`'s `Err` arm already refuses to reconcile
    // against a backend blip ("a failed list is NOT an empty list"), but a
    // substituted in-process runtime answers `Ok` with a listing of containers
    // it never deployed — a successful, wrong list that walks straight through
    // that guard and retracts every record for a container kamaji is still
    // running.
    assert!(
        !service_records::sweep_once(&state).await,
        "the sweep reconciled the record set against the wrong process's \
         view of containerd"
    );
}

/// The probe cadence runs against a live kamaji, and **refuses to run** when
/// it cannot reach one.
///
/// Both halves matter and the second is the load-bearing one. Before
/// `workload_health` existed, kamaji's probe runner had no caller at all — the
/// `[healthcheck]` in every `.yah/infra/workloads/*.toml` was declared and
/// never executed. The obvious way to get that wrong a second time is a sweep
/// that silently no-ops, which looks identical from the outside to one that
/// runs and finds nothing. So the assertions are on `sweep_once`'s own return:
/// `true` means kamaji answered and the registry was reconciled against its
/// listing, `false` means this tick knew nothing and changed nothing.
///
/// The unreachable arm uses `KamajiSibling::disconnected` for the reason
/// documented on the test above — killing a spawned kamaji leaves the
/// established client connected and `is_dead()` false forever.
#[tokio::test]
async fn the_health_sweep_runs_against_a_live_kamaji_and_refuses_without_one() {
    let tmp = tempfile::TempDir::new().unwrap();
    let sock = tmp.path().join("kamaji.sock");

    {
        let (server, stop) = spawn_kamaji(sock.clone()).await;
        let client = kamaji::sibling::KamajiClient::connect(sock.clone())
            .await
            .expect("kamaji handshake");
        let live = Arc::new(
            ServerState::load(tmp.path().join("identity.json"))
                .unwrap()
                .with_constable_client(kamaji::sibling::KamajiSibling::new(
                    client,
                    sock.clone(),
                    std::time::Duration::from_millis(200),
                )),
        );
        assert!(
            yubaba::workload_health::sweep_once(&live).await,
            "a live sibling answered List, so the tick reconciled — a sweep \
             that no-ops here is the un-driven probe runner all over again"
        );
        // An empty fleet is an empty registry, not a stale one.
        assert!(live.workload_health.keys().is_empty());
        let _ = stop.send(());
        server.await.unwrap();
    }

    let unreachable = Arc::new(
        ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_constable_client(kamaji::sibling::KamajiSibling::disconnected(sock)),
    );
    assert!(
        !yubaba::workload_health::sweep_once(&unreachable).await,
        "a sibling we cannot reach is not evidence about any workload's \
         health; every verdict must be left exactly as it was"
    );
}

/// A node with no kamaji at all runs no health loop and publishes no verdicts.
///
/// This is every dev box and every stub-runtime test. The failure worth
/// pinning is the opposite of a missing probe: a node that cannot probe
/// anything reporting a confident empty health set, which downstream reads as
/// "nothing is degraded here".
#[tokio::test]
async fn a_node_with_no_sibling_publishes_no_health_at_all() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = Arc::new(
        ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_runtime(Arc::new(FakeRuntime::new()) as Arc<dyn kamaji::Kamaji + Send + Sync>),
    );
    assert!(
        !yubaba::workload_health::sweep_once(&state).await,
        "no sibling means no probe channel — the in-process runtime cannot \
         answer a Probe, and must not be asked to guess"
    );
    assert!(state.workload_health.keys().is_empty());
}
