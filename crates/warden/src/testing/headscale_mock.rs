//! In-process mock for the Headscale REST API (operator-bridge tests).
//!
//! Accepts preauth-key creation requests from warden, validates the request
//! shape, does NOT run a real Tailscale control plane. Used by local-tier
//! operator-bridge tests (R091-F8).
//!
//! Surface mocked:
//!
//!   POST /api/v1/preauthkey — create a preauth key with ACL tags.
//!   GET  /api/v1/preauthkey — list created preauth keys (for test assertions).
//!
//! Real Headscale + tailscaled exercise (smoke tier) is wired in R091-F9.
//!
//! @arch:see(.yah/docs/architecture/A053-yah-warden-integration-testing.md)

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A preauth key created via `POST /api/v1/preauthkey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthKeyRecord {
    /// Mock-assigned numeric ID.
    pub id: String,
    /// The mock-generated preauth key token (e.g. `"mock-key-0"`).
    pub key: String,
    /// User/namespace the key belongs to.
    pub user: String,
    /// ACL tags associated with this key (e.g. `["tag:ops"]`).
    pub acl_tags: Vec<String>,
    /// Whether the key can be used more than once.
    pub reusable: bool,
    /// Whether nodes that join with this key are ephemeral.
    pub ephemeral: bool,
}

// ── Internal shared state ─────────────────────────────────────────────────────

#[derive(Default)]
struct MockState {
    preauth_keys: Mutex<Vec<PreAuthKeyRecord>>,
    /// Armed by `fail_next_create`. Cleared after firing once.
    fail_next: AtomicBool,
    next_id: AtomicU64,
}

// ── Request/response shapes ───────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct PreAuthKeyCreateRequest {
    user: String,
    #[serde(default)]
    acl_tags: Vec<String>,
    #[serde(default)]
    reusable: bool,
    #[serde(default)]
    ephemeral: bool,
}

#[derive(Serialize)]
struct PreAuthKeyCreateResponse {
    #[serde(rename = "preAuthKey")]
    pre_auth_key: PreAuthKeyRecord,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Running Headscale mock server.
///
/// Created by [`HeadscaleMock::start`]. Accepts preauth-key creation requests
/// from warden's operator-bridge registration path.
///
/// ```rust,ignore
/// let mock = HeadscaleMock::start().await?;
/// let state = ServerState::load(path)?
///     .with_headscale_url(mock.base_url());
/// ```
pub struct HeadscaleMock {
    inner: Arc<MockState>,
    base_url: String,
    /// Kept alive to prevent the server task from being dropped.
    _task: JoinHandle<()>,
}

impl HeadscaleMock {
    /// Bind a random loopback port and start the mock HTTP server.
    pub async fn start() -> anyhow::Result<Self> {
        let state = Arc::new(MockState::default());

        let router = Router::new()
            .route("/api/v1/preauthkey", post(handle_create_preauthkey))
            .route("/api/v1/preauthkey", get(handle_list_preauthkeys))
            .with_state(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let base_url = format!("http://127.0.0.1:{port}");

        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        Ok(Self {
            inner: state,
            base_url,
            _task: task,
        })
    }

    /// HTTP base URL for this mock, e.g. `"http://127.0.0.1:34567"`.
    ///
    /// Pass this to `ServerState::with_headscale_url` to point warden at the
    /// mock instead of a real Headscale daemon.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Arm the mock so the **next** `POST /api/v1/preauthkey` returns HTTP 500.
    ///
    /// Fires exactly once — subsequent POSTs succeed again.
    pub fn fail_next_create(&self) {
        self.inner.fail_next.store(true, Ordering::SeqCst);
    }

    /// Return a snapshot of all preauth keys created so far.
    pub fn preauth_keys(&self) -> Vec<PreAuthKeyRecord> {
        self.inner.preauth_keys.lock().unwrap().clone()
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_create_preauthkey(
    State(state): State<Arc<MockState>>,
    Json(req): Json<PreAuthKeyCreateRequest>,
) -> impl IntoResponse {
    if state.fail_next.swap(false, Ordering::SeqCst) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "message": "mock: preauth key creation failed (injected fault)"
            })),
        )
            .into_response();
    }

    let id = state.next_id.fetch_add(1, Ordering::Relaxed);
    let key = format!("mock-key-{id}");

    let record = PreAuthKeyRecord {
        id: id.to_string(),
        key: key.clone(),
        user: req.user.clone(),
        acl_tags: req.acl_tags.clone(),
        reusable: req.reusable,
        ephemeral: req.ephemeral,
    };

    state.preauth_keys.lock().unwrap().push(record.clone());

    (
        StatusCode::OK,
        Json(serde_json::json!(PreAuthKeyCreateResponse {
            pre_auth_key: record,
        })),
    )
        .into_response()
}

async fn handle_list_preauthkeys(State(state): State<Arc<MockState>>) -> impl IntoResponse {
    let keys = state.preauth_keys.lock().unwrap().clone();
    Json(serde_json::json!({ "preAuthKeys": keys }))
}
