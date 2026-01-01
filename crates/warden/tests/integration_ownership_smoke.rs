//! Ownership-write end-to-end smoke (R427-T2).
//!
//! Exercises the full warden ↔ cheers contract that R427-F1 wired:
//!
//! 1. POST /workloads/deploy with `requesting_camp_id` + `on_behalf_of_user`
//!    → warden provisions the workload → calls `POST /ownership` on the
//!    cheers issuer URL with a `svc:warden-*` PASETO v4.public Bearer token
//!    and the canonical claim block → stores the returned row id keyed by
//!    workload ident.
//! 2. POST /workloads/{ident}/destroy → warden tears down the workload →
//!    calls `DELETE /ownership/{row_id}` with a freshly-minted token.
//!
//! Uses FakeRuntime so no containerd is required, and an in-process axum
//! cheers mock that records every POST/DELETE plus the Bearer token bytes
//! so we can pin the wire shape without standing up a real cheers instance.
//!
//! ## Scope
//!
//! This file proves the **warden ↔ cheers** half of the W159 §"Ownership
//! writes" flow. The full T2 narrative ("agent → constable → warden →
//! cheers → camp refresh → 2nd deploy") needs two more pieces that aren't
//! in this relay:
//!
//! - the **authed transport** in front of warden (R426-F2's
//!   `hub-cheers-rpc` adapter) for the agent → constable hop; today the
//!   tests POST straight to warden's HTTP surface, which mirrors what the
//!   adapter will do once it lands;
//! - cheers's **token-mint endpoint** + the camp's refresh path; today
//!   tests use stub `camp:` / `user:` ids on the deploy body, which R428
//!   will replace with verified MCP-claim derivation.
//!
//! Both gaps are documented in the relay; T2 covers everything that can be
//! covered with what's wired today without forking the design.
//!
//! @yah:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::{delete, post};
use axum::{Json, Router};
use http_body_util::BodyExt;
use tokio::sync::Mutex;
use tower::ServiceExt;

use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, Generate};
use pasetors::token::{Public, UntrustedToken};
use pasetors::version4::{PublicToken, V4};

use warden::cheers_client::{CheersClient, CheersConfig};
use constable_core::fake::FakeRuntime;
use workload_spec::{
    ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits, RestartPolicy,
    SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
};

// ── Cheers mock ────────────────────────────────────────────────────────────

/// What an `Authorization: Bearer <paseto>` token looked like at the cheers
/// receiver. Tests assert on the verified payload, not raw bytes — that's
/// the only stable contract.
#[derive(Debug, Clone)]
struct ObservedCall {
    bearer: String,
    body: Option<serde_json::Value>,
    path_id: Option<String>,
}

#[derive(Clone, Default)]
struct MockState {
    posts: Arc<Mutex<Vec<ObservedCall>>>,
    deletes: Arc<Mutex<Vec<ObservedCall>>>,
    /// When set, POST returns this status + a JSON `error` body instead of
    /// the happy 201.
    fail_post: Arc<Mutex<Option<(StatusCode, String)>>>,
    next_row_id: Arc<Mutex<u64>>,
}

impl MockState {
    fn new() -> Self {
        Self {
            next_row_id: Arc::new(Mutex::new(1)),
            ..Default::default()
        }
    }

    async fn posts(&self) -> Vec<ObservedCall> {
        self.posts.lock().await.clone()
    }

    async fn deletes(&self) -> Vec<ObservedCall> {
        self.deletes.lock().await.clone()
    }
}

async fn mock_post(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    state.posts.lock().await.push(ObservedCall {
        bearer,
        body: Some(body.clone()),
        path_id: None,
    });
    if let Some((status, msg)) = state.fail_post.lock().await.clone() {
        return (status, Json(serde_json::json!({ "error": msg })));
    }
    let mut n = state.next_row_id.lock().await;
    let row_id = format!("01HROW{:04}", *n);
    *n += 1;
    let row = serde_json::json!({
        "id": row_id,
        "principal_id": body["principal_id"],
        "resource_kind": body["resource_kind"],
        "resource_id": body["resource_id"],
        "relationship": body["relationship"],
        "granted_by": "svc:warden-smoke",
        "on_behalf_of": body["on_behalf_of"],
        "granted_at": 1_700_000_000_i64,
        "revoked_at": serde_json::Value::Null,
    });
    (StatusCode::CREATED, Json(row))
}

async fn mock_delete(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> StatusCode {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    state.deletes.lock().await.push(ObservedCall {
        bearer,
        body: None,
        path_id: Some(id),
    });
    StatusCode::NO_CONTENT
}

/// Spawn the mock, returning `(issuer_url, mock_state, warden_pubkey_handle)`.
/// The pubkey handle lets each test verify Bearer tokens against the same
/// key warden minted them with — the install-flow `--rotate` shape end to
/// end.
async fn spawn_cheers_mock_with_keypair() -> (String, MockState, AsymmetricKeyPair<V4>) {
    let state = MockState::new();
    let app = Router::new()
        .route("/ownership", post(mock_post))
        .route("/ownership/{id}", delete(mock_delete))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    (format!("http://{addr}"), state, kp)
}

// ── Bearer-token verifier (mirrors cheers's PASETO check) ──────────────────

fn verify_bearer(bearer: &str, pubkey: &AsymmetricKeyPair<V4>) -> serde_json::Value {
    let token = bearer
        .strip_prefix("Bearer ")
        .expect("Authorization header should start with 'Bearer '");
    let untrusted = UntrustedToken::<Public, V4>::try_from(token).expect("PASETO parse");
    let pk_bytes: [u8; 32] = pubkey.public.as_bytes().try_into().unwrap();
    let pk = AsymmetricPublicKey::<V4>::from(&pk_bytes).unwrap();
    let trusted = PublicToken::verify(&pk, &untrusted, None, None).expect("PASETO verify");
    serde_json::from_str(trusted.payload()).expect("claims JSON")
}

// ── Warden state factory ───────────────────────────────────────────────────

fn mesh_only_spec(name: &str) -> WorkloadSpec {
    // No public ingress, no operator bridge — keeps the deploy path focused
    // on the ownership-write check. Cloudflared/Headscale aren't configured
    // on this state, so an expose with either would short-circuit before
    // reaching the cheers call.
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: name.to_string(),
        image: ImageRef {
            registry: "docker.io".into(),
            repository: "library/alpine".into(),
            tag: "latest".into(),
            digest: workload_spec::testing::test_digest(),
        },
        tier: TierTag("private".into()),
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
            cpu_shares: 128,
            ephemeral_storage_mb: 128,
        },
        depends_on: vec![],
        healthcheck: None,
        restart_policy: RestartPolicy::Always,
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

fn fresh_warden(
    cheers_url: &str,
    kp: &AsymmetricKeyPair<V4>,
) -> (tempfile::TempDir, Arc<warden::ServerState>) {
    let tmp = tempfile::TempDir::new().unwrap();
    let cheers = CheersClient::new(
        CheersConfig {
            issuer_url: cheers_url.to_string(),
            principal_id: "warden-smoke".to_string(),
            kid: "warden-smoke-1".to_string(),
        },
        kp.secret.as_bytes(),
    )
    .unwrap();
    let state = Arc::new(
        warden::ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_runtime(Arc::new(FakeRuntime::new()))
            .with_cheers_client(Arc::new(cheers)),
    );
    (tmp, state)
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn deploy_with_attribution(
    app: axum::Router,
    spec: &WorkloadSpec,
    camp_id: Option<&str>,
    user_id: Option<&str>,
) -> axum::response::Response {
    let mut body = serde_json::json!({ "spec": spec });
    if let Some(c) = camp_id {
        body["requesting_camp_id"] = serde_json::Value::String(c.to_string());
    }
    if let Some(u) = user_id {
        body["on_behalf_of_user"] = serde_json::Value::String(u.to_string());
    }
    app.oneshot(
        Request::post("/workloads/deploy")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn destroy(app: axum::Router, ident: &str) -> axum::response::Response {
    app.oneshot(
        Request::post(format!("/workloads/{ident}/destroy"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// Happy path: deploy with attribution → cheers sees the POST with a
/// well-formed bearer + canonical body → destroy → cheers sees the DELETE
/// with the registered row id.
#[tokio::test]
async fn deploy_registers_then_destroy_revokes() {
    let (cheers_url, mock, kp) = spawn_cheers_mock_with_keypair().await;
    let (_tmp, state) = fresh_warden(&cheers_url, &kp);
    let app = warden::build_router(state.clone());

    let spec = mesh_only_spec("svc-alpha");
    let resp = deploy_with_attribution(
        app.clone(),
        &spec,
        Some("camp:C-acme"),
        Some("user:U-operator"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "deploy must succeed");
    let body = body_json(resp).await;
    assert_eq!(body["status"], "deployed");
    assert_eq!(body["ident"], "svc-alpha");

    // ── Assert the POST /ownership the mock saw is the canonical shape ──
    let posts = mock.posts().await;
    assert_eq!(posts.len(), 1, "cheers must receive exactly one POST /ownership");
    let post = &posts[0];

    let posted = post.body.as_ref().unwrap();
    assert_eq!(posted["principal_id"], "camp:C-acme");
    assert_eq!(posted["resource_kind"], "service");
    assert_eq!(posted["resource_id"], "svc-alpha");
    assert_eq!(posted["relationship"], "owns");
    assert_eq!(posted["on_behalf_of"], "user:U-operator");

    // ── Verify the Bearer token matches the canonical claim block ──
    let claims = verify_bearer(&post.bearer, &kp);
    assert_eq!(claims["sub"], "svc:warden-smoke");
    assert_eq!(claims["iss"], cheers_url);
    assert_eq!(claims["aud"], cheers_url);
    assert_eq!(claims["scope"][0], "ownership:write");
    // Sanity-check the TTL is in W159's 5–15 min access-token band.
    let exp = claims["exp"].as_i64().unwrap();
    let iat = claims["iat"].as_i64().unwrap();
    let ttl = exp - iat;
    assert!(
        (5 * 60..=15 * 60).contains(&ttl),
        "register token TTL {ttl}s outside W159 5–15 min band"
    );

    // The map should now carry one (ident → row_id) entry.
    let row_id = state
        .ownership_rows
        .lock()
        .unwrap()
        .get("svc-alpha")
        .cloned()
        .expect("deploy should populate the ownership_rows map");
    assert!(row_id.starts_with("01HROW"), "row_id from mock: {row_id}");

    // ── Destroy → cheers sees DELETE with the same row id ──
    let resp = destroy(app, "svc-alpha").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "destroyed");
    assert_eq!(body["revoked"], true);

    let deletes = mock.deletes().await;
    assert_eq!(deletes.len(), 1, "cheers must receive exactly one DELETE");
    assert_eq!(deletes[0].path_id.as_deref(), Some(row_id.as_str()));
    let claims = verify_bearer(&deletes[0].bearer, &kp);
    assert_eq!(claims["sub"], "svc:warden-smoke");
    assert_eq!(claims["scope"][0], "ownership:write");

    // Map entry consumed.
    assert!(
        state
            .ownership_rows
            .lock()
            .unwrap()
            .get("svc-alpha")
            .is_none(),
        "destroy should remove the (ident → row_id) entry"
    );
}

/// Two deploys (the "camp refresh → 2nd deploy" half of the T2 narrative,
/// reduced to what's testable today): the second register call must land
/// against the same cheers endpoint with a freshly-minted token, and the
/// per-workload row ids must not collide.
#[tokio::test]
async fn second_deploy_writes_a_distinct_row() {
    let (cheers_url, mock, kp) = spawn_cheers_mock_with_keypair().await;
    let (_tmp, state) = fresh_warden(&cheers_url, &kp);

    for name in ["svc-first", "svc-second"] {
        let app = warden::build_router(state.clone());
        let spec = mesh_only_spec(name);
        let resp = deploy_with_attribution(
            app,
            &spec,
            Some("camp:C-acme"),
            Some("user:U-operator"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "deploy {name} must succeed");
    }

    let posts = mock.posts().await;
    assert_eq!(posts.len(), 2, "cheers should see one POST per deploy");
    let id_a = posts[0].body.as_ref().unwrap()["resource_id"].as_str().unwrap();
    let id_b = posts[1].body.as_ref().unwrap()["resource_id"].as_str().unwrap();
    assert_eq!(id_a, "svc-first");
    assert_eq!(id_b, "svc-second");

    // Distinct PASETO `jti`s — warden's monotonic counter is the replay
    // backstop even if both mints land in the same wallclock second.
    let claims_a = verify_bearer(&posts[0].bearer, &kp);
    let claims_b = verify_bearer(&posts[1].bearer, &kp);
    assert_ne!(claims_a["jti"], claims_b["jti"]);

    // And the persisted row ids on warden's side are also distinct (they're
    // the mock's monotonic id; in real life this is cheers's ULID).
    let map = state.ownership_rows.lock().unwrap().clone();
    let row_first = map.get("svc-first").cloned().unwrap();
    let row_second = map.get("svc-second").cloned().unwrap();
    assert_ne!(row_first, row_second);
}

/// Deploys without `requesting_camp_id` are valid (dev-tier shape) and
/// must NOT call cheers — register is gated on both `cheers_client` AND
/// the body field being present.
#[tokio::test]
async fn deploy_without_camp_id_skips_register() {
    let (cheers_url, mock, kp) = spawn_cheers_mock_with_keypair().await;
    let (_tmp, state) = fresh_warden(&cheers_url, &kp);
    let app = warden::build_router(state.clone());

    let spec = mesh_only_spec("svc-anon");
    let resp = deploy_with_attribution(app, &spec, None, None).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    assert_eq!(mock.posts().await.len(), 0, "no camp_id ⇒ no cheers write");
    assert!(state.ownership_rows.lock().unwrap().get("svc-anon").is_none());
}

/// When cheers's `/ownership` is down, the workload still deploys (warden
/// log-warns, the row is left for a reconciler). The contract — "register
/// failure is not fatal" — is load-bearing for the W159 §"Ownership writes"
/// "keep the privileged set small" rule.
#[tokio::test]
async fn register_failure_does_not_tear_down_workload() {
    let (cheers_url, mock, kp) = spawn_cheers_mock_with_keypair().await;
    *mock.fail_post.lock().await = Some((
        StatusCode::INTERNAL_SERVER_ERROR,
        "cheers booting".into(),
    ));
    let (_tmp, state) = fresh_warden(&cheers_url, &kp);
    let app = warden::build_router(state.clone());

    let spec = mesh_only_spec("svc-resilient");
    let resp = deploy_with_attribution(
        app,
        &spec,
        Some("camp:C-acme"),
        Some("user:U-operator"),
    )
    .await;
    // Deploy still succeeds — workload is up, ownership row missing.
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "deployed");

    // Mock saw the POST attempt but the row wasn't persisted on warden's
    // side because cheers refused to mint one.
    assert_eq!(mock.posts().await.len(), 1);
    assert!(state
        .ownership_rows
        .lock()
        .unwrap()
        .get("svc-resilient")
        .is_none());
}
