//! In-process mock for the Cloudflare Tunnel REST API.
//!
//! Accepts tunnel registration POSTs from warden, validates the request shape,
//! does NOT route real public traffic. Used by local-tier public-ingress tests
//! (R091-F7).
//!
//! Surface mocked:
//!
//!   POST /v1/tunnels — register a tunnel route; validates {hostname, service_url}.
//!   GET  /v1/tunnels — list registered tunnels (for test assertions).
//!
//! Real Cloudflare Tunnel registration (smoke tier) is exercised in R091-F9.
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

/// A single tunnel route registered via `POST /v1/tunnels`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRegistration {
    /// Mock-assigned opaque identifier.
    pub id: String,
    /// Public hostname, e.g. `"api.noisetable.io"`.
    pub hostname: String,
    /// Backend service URL warden passed, e.g. `"http://127.0.0.1:8080"`.
    pub service_url: String,
}

// ── Internal shared state ─────────────────────────────────────────────────────

#[derive(Default)]
struct MockState {
    registrations: Mutex<Vec<TunnelRegistration>>,
    /// Armed by `fail_next_registration`. Cleared after firing once.
    fail_next: AtomicBool,
    next_id: AtomicU64,
}

// ── Request/response shapes ───────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct TunnelRegisterRequest {
    hostname: String,
    service_url: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Running cloudflared mock server.
///
/// Created by [`CloudflaredMock::start`]. The server lives on a random loopback
/// port and accepts tunnel registration requests from warden.
///
/// ```rust,ignore
/// let mock = CloudflaredMock::start().await?;
/// let state = ServerState::load(path)?
///     .with_cloudflared_url(mock.base_url());
/// ```
pub struct CloudflaredMock {
    inner: Arc<MockState>,
    base_url: String,
    /// Kept alive to prevent the server task from being dropped.
    _task: JoinHandle<()>,
}

impl CloudflaredMock {
    /// Bind a random loopback port and start the mock HTTP server.
    pub async fn start() -> anyhow::Result<Self> {
        let state = Arc::new(MockState::default());

        let router = Router::new()
            .route("/v1/tunnels", post(handle_register))
            .route("/v1/tunnels", get(handle_list))
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
    /// Pass this to `ServerState::with_cloudflared_url` to point warden at the
    /// mock instead of a real cloudflared daemon.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Arm the mock so the **next** `POST /v1/tunnels` returns HTTP 500.
    ///
    /// Fires exactly once — subsequent POSTs succeed again. Call again to arm
    /// another failure.
    pub fn fail_next_registration(&self) {
        self.inner.fail_next.store(true, Ordering::SeqCst);
    }

    /// Return a snapshot of all tunnel registrations received so far.
    pub fn registrations(&self) -> Vec<TunnelRegistration> {
        self.inner.registrations.lock().unwrap().clone()
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_register(
    State(state): State<Arc<MockState>>,
    Json(req): Json<TunnelRegisterRequest>,
) -> impl IntoResponse {
    if state.fail_next.swap(false, Ordering::SeqCst) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "mock: tunnel registration failed (injected fault)"
            })),
        )
            .into_response();
    }

    let id = format!(
        "mock-tunnel-{}",
        state.next_id.fetch_add(1, Ordering::Relaxed)
    );

    let reg = TunnelRegistration {
        id: id.clone(),
        hostname: req.hostname.clone(),
        service_url: req.service_url.clone(),
    };

    state.registrations.lock().unwrap().push(reg);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "hostname": req.hostname,
            "service_url": req.service_url,
            "active": true,
        })),
    )
        .into_response()
}

async fn list_tunnels_handler(State(state): State<Arc<MockState>>) -> impl IntoResponse {
    let registrations = state.registrations.lock().unwrap().clone();
    Json(serde_json::json!({ "tunnels": registrations }))
}

// Alias to satisfy the routing macro which requires a function named after the route.
async fn handle_list(state: State<Arc<MockState>>) -> impl IntoResponse {
    list_tunnels_handler(state).await
}
