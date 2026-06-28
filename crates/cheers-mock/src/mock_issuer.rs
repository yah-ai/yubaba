//! Spawnable in-process mock — runs the HTTP discovery surface + owns the
//! signing keypair.
//!
//! Usage shape:
//!
//! ```no_run
//! # use cheers_mock::{MockConfig, MockIssuer, ambient_user_dev_claims};
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let issuer = MockIssuer::spawn(MockConfig::default()).await?;
//! let claims = ambient_user_dev_claims(
//!     &issuer.issuer_url(),
//!     "https://kamaji.local",
//!     &["cloud:read"],
//!     &["svc-abc"],
//!     1_700_000_000,
//! );
//! let token = issuer.mint(&claims)?;
//! // Hand `token` to a Hub client; kamaji boots its verifier against
//! // `issuer.issuer_url()` and verifies through the production path.
//! issuer.shutdown().await;
//! # Ok(()) }
//! ```
//!
//! The server binds to `127.0.0.1:0` by default — kernel assigns a free port,
//! [`MockIssuer::issuer_url`] returns the bound URL. Override via
//! [`MockConfig::bind_addr`] for fixed-port tests / dev tooling.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64ct::{Base64UrlUnpadded, Encoding};
use pasetors::keys::{AsymmetricKeyPair, AsymmetricSecretKey, Generate};
use pasetors::version4::{PublicToken, V4};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Tunable knobs for [`MockIssuer::spawn`].
#[derive(Debug, Clone)]
pub struct MockConfig {
    /// Bind address. Default `127.0.0.1:0` → kernel assigns a free port.
    pub bind_addr: SocketAddr,
    /// `kid` published in the JWKS + stamped into every minted footer.
    /// Default `"mock-1"`.
    pub kid: String,
    /// Resource URI to advertise in the protected-resource metadata.
    /// When `None`, the `/.well-known/oauth-protected-resource` endpoint
    /// returns 404 — the discovery hop only makes sense when a single
    /// kamaji instance is being mocked into.
    pub expected_aud: Option<String>,
    /// Scope vocabulary advertised under `scopes_supported`. Matches
    /// W159 §Scope vocabulary when [`crate::SCOPE_VOCABULARY_DEFAULT`] is
    /// passed — but the mock accepts an override so individual tests can
    /// pin the published list.
    pub scopes_supported: Vec<String>,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            kid: "mock-1".into(),
            expected_aud: None,
            scopes_supported: default_scopes_supported(),
        }
    }
}

/// W159 §Scope vocabulary, full list. Same content as kamaji's
/// `SCOPE_VOCABULARY` — duplicated here so the mock doesn't pull kamaji
/// as a dep (and so a stale mock can't silently drift behind a kamaji
/// release; both sides assert the same canonical list).
pub const SCOPE_VOCABULARY_DEFAULT: &[&str] = &[
    "arch:read",
    "arch:write",
    "board:read",
    "board:write",
    "camp:read",
    "camp:admin",
    "cloud:read",
    "cloud:deploy",
    "cloud:destroy",
    "party:read",
    "party:write",
    "agent:spawn",
    "agent:control",
    "audit:read",
    "ownership:write",
    "audit:write",
];

fn default_scopes_supported() -> Vec<String> {
    SCOPE_VOCABULARY_DEFAULT.iter().map(|s| s.to_string()).collect()
}

/// Failures from [`MockIssuer::spawn`] / mint.
#[derive(Debug, Error)]
pub enum MockIssuerError {
    #[error("ed25519 keypair generation failed: {0:?}")]
    Keygen(pasetors::errors::Error),
    #[error("could not bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("PASETO sign failed: {0:?}")]
    Sign(pasetors::errors::Error),
    #[error("claim block must serialize to JSON: {0}")]
    BadClaims(#[from] serde_json::Error),
}

/// Running mock — handle to the spawned HTTP server + the signing keypair.
/// Drop signals shutdown; [`Self::shutdown`] is the explicit variant that
/// awaits the server's exit.
pub struct MockIssuer {
    keypair: AsymmetricKeyPair<V4>,
    config: MockConfig,
    bound_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for MockIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockIssuer")
            .field("config", &self.config)
            .field("bound_addr", &self.bound_addr)
            .finish()
    }
}

impl MockIssuer {
    /// Generate a fresh Ed25519 keypair, bind a TCP listener per
    /// [`MockConfig::bind_addr`], spawn the axum server, return a handle
    /// that knows the bound port.
    pub async fn spawn(config: MockConfig) -> Result<Self, MockIssuerError> {
        let keypair = AsymmetricKeyPair::<V4>::generate().map_err(MockIssuerError::Keygen)?;
        let pubkey_bytes = pubkey_array(&keypair);
        let jwks = build_jwks(&config.kid, &pubkey_bytes);

        let listener = tokio::net::TcpListener::bind(config.bind_addr)
            .await
            .map_err(|source| MockIssuerError::Bind {
                addr: config.bind_addr,
                source,
            })?;
        let bound_addr = listener
            .local_addr()
            .map_err(|source| MockIssuerError::Bind {
                addr: config.bind_addr,
                source,
            })?;

        let issuer_url = format!("http://{bound_addr}");
        let state = Arc::new(AppState {
            jwks,
            protected_resource: config.expected_aud.as_ref().map(|aud| {
                ProtectedResourceMetadata::build(
                    aud,
                    &issuer_url,
                    &config.scopes_supported,
                )
            }),
        });

        let app = Router::new()
            .route("/.well-known/jwks.json", get(serve_jwks))
            .route(
                "/.well-known/oauth-protected-resource",
                get(serve_protected_resource),
            )
            .with_state(state);

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let serve = axum::serve(listener, app);
            let _ = serve
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        Ok(Self {
            keypair,
            config,
            bound_addr,
            shutdown_tx: Some(shutdown_tx),
            server_task: Some(server_task),
        })
    }

    /// `http://127.0.0.1:<port>` — the value to pass to kamaji's
    /// `cheers_issuer` config.
    pub fn issuer_url(&self) -> String {
        format!("http://{}", self.bound_addr)
    }

    /// Bound listening address — useful for tests that need raw socket info.
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// `kid` stamped into every minted footer and published in the JWKS.
    pub fn kid(&self) -> &str {
        &self.config.kid
    }

    /// Read-only borrow of the secret key — only useful for tests that want
    /// to exercise the verifier's reaction to off-band signing.
    pub fn secret_key(&self) -> &AsymmetricSecretKey<V4> {
        &self.keypair.secret
    }

    /// Mint a PASETO v4.public token over `claims`. Uses the low-level
    /// `PublicToken::sign` so the i64 `exp`/`iat` shape pinned in W159
    /// §Canonical claim schema round-trips. The footer carries
    /// `{"kid": "<self.kid()>"}` — kamaji's verifier reads it before the
    /// signature check.
    pub fn mint(&self, claims: &Value) -> Result<String, MockIssuerError> {
        let payload_bytes = serde_json::to_vec(claims)?;
        let footer_bytes = format!(r#"{{"kid":"{kid}"}}"#, kid = self.config.kid).into_bytes();
        PublicToken::sign(
            &self.keypair.secret,
            &payload_bytes,
            Some(&footer_bytes),
            None,
        )
        .map_err(MockIssuerError::Sign)
    }

    /// Stop the HTTP server and await its task. Idempotent — calling twice
    /// is a no-op after the first.
    pub async fn shutdown(mut self) {
        self.shutdown_inner().await;
    }

    async fn shutdown_inner(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.server_task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for MockIssuer {
    fn drop(&mut self) {
        // Best-effort shutdown when the handle drops without an explicit
        // shutdown call. The server task is detached at that point — any
        // cleanup it does (e.g. log flush) happens on its own time.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Build the W159 ambient `user:dev` claim block — `sub: user:dev`,
/// `camp_id: C-dev`, `act: agent:dev`, single-element `owns.service` populated
/// from `owns_services`, 15-minute TTL anchored at `now`.
///
/// `now` is Unix seconds — pass in `i64::try_from(SystemTime::now().elapsed())`
/// or whatever clock source the caller already has. Kept as an argument so
/// the mock stays deterministic for tests.
pub fn ambient_user_dev_claims(
    iss: &str,
    aud: &str,
    scopes: &[&str],
    owns_services: &[&str],
    now: i64,
) -> Value {
    let mut owns = serde_json::Map::new();
    if !owns_services.is_empty() {
        owns.insert(
            "service".into(),
            Value::Array(
                owns_services
                    .iter()
                    .map(|s| Value::String((*s).to_string()))
                    .collect(),
            ),
        );
    }

    let mut claims = serde_json::Map::new();
    claims.insert("iss".into(), Value::String(iss.to_string()));
    claims.insert("aud".into(), Value::String(aud.to_string()));
    // 15-minute access-token TTL per W159 §TTLs (5–15 min band).
    claims.insert("exp".into(), Value::Number((now + 15 * 60).into()));
    claims.insert("iat".into(), Value::Number(now.into()));
    claims.insert("jti".into(), Value::String(format!("dev-{now}")));
    claims.insert("sub".into(), Value::String("user:dev".into()));
    claims.insert(
        "scope".into(),
        Value::Array(scopes.iter().map(|s| Value::String((*s).to_string())).collect()),
    );
    claims.insert(
        "act".into(),
        serde_json::json!({ "sub": "agent:dev" }),
    );
    claims.insert("camp_id".into(), Value::String("C-dev".into()));
    if !owns.is_empty() {
        claims.insert("owns".into(), Value::Object(owns));
    }
    claims.insert("auth_strength".into(), Value::String("bootstrap".into()));

    Value::Object(claims)
}

// --- HTTP handlers + state ---------------------------------------------------

#[derive(Clone)]
struct AppState {
    jwks: JwksDoc,
    protected_resource: Option<ProtectedResourceMetadata>,
}

async fn serve_jwks(State(state): State<Arc<AppState>>) -> Json<JwksDoc> {
    Json(state.jwks.clone())
}

async fn serve_protected_resource(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ProtectedResourceMetadata>, axum::http::StatusCode> {
    state
        .protected_resource
        .clone()
        .map(Json)
        .ok_or(axum::http::StatusCode::NOT_FOUND)
}

// --- JWKS shape (subset of kamaji's; duplicated to avoid back-dep) --------

#[derive(Debug, Clone, Serialize)]
struct JwksDoc {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Serialize)]
struct JwkKey {
    kty: &'static str,
    crv: &'static str,
    x: String,
    kid: String,
    #[serde(rename = "use")]
    use_: &'static str,
    alg: &'static str,
}

fn build_jwks(kid: &str, pubkey: &[u8; 32]) -> JwksDoc {
    JwksDoc {
        keys: vec![JwkKey {
            kty: "OKP",
            crv: "Ed25519",
            x: Base64UrlUnpadded::encode_string(pubkey),
            kid: kid.to_string(),
            use_: "sig",
            alg: "EdDSA",
        }],
    }
}

fn pubkey_array(kp: &AsymmetricKeyPair<V4>) -> [u8; 32] {
    let bytes = kp.public.as_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

// --- Protected-resource metadata (RFC 9728 §2) -------------------------------

#[derive(Debug, Clone, Serialize)]
struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    bearer_methods_supported: Vec<&'static str>,
}

impl ProtectedResourceMetadata {
    fn build(aud: &str, issuer: &str, scopes_supported: &[String]) -> Self {
        Self {
            resource: aud.trim_end_matches('/').to_string(),
            authorization_servers: vec![issuer.trim_end_matches('/').to_string()],
            scopes_supported: scopes_supported.to_vec(),
            bearer_methods_supported: vec!["header"],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasetors::keys::AsymmetricPublicKey;
    use pasetors::token::UntrustedToken;

    #[tokio::test]
    async fn spawn_serves_jwks() {
        let issuer = MockIssuer::spawn(MockConfig::default()).await.unwrap();
        let url = format!("{}/.well-known/jwks.json", issuer.issuer_url());
        let body: serde_json::Value = reqwest::get(&url).await.unwrap().json().await.unwrap();
        let keys = body.get("keys").and_then(|v| v.as_array()).unwrap();
        assert_eq!(keys.len(), 1);
        let entry = &keys[0];
        assert_eq!(entry.get("kty").and_then(|v| v.as_str()), Some("OKP"));
        assert_eq!(entry.get("crv").and_then(|v| v.as_str()), Some("Ed25519"));
        assert_eq!(entry.get("kid").and_then(|v| v.as_str()), Some("mock-1"));
        // x is base64url(32 bytes) — 43 chars without padding.
        let x = entry.get("x").and_then(|v| v.as_str()).unwrap();
        assert_eq!(x.len(), 43);
        issuer.shutdown().await;
    }

    #[tokio::test]
    async fn protected_resource_404_when_aud_unset() {
        let issuer = MockIssuer::spawn(MockConfig::default()).await.unwrap();
        let url = format!(
            "{}/.well-known/oauth-protected-resource",
            issuer.issuer_url()
        );
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
        issuer.shutdown().await;
    }

    #[tokio::test]
    async fn protected_resource_served_when_aud_set() {
        let cfg = MockConfig {
            expected_aud: Some("https://kamaji.test".into()),
            ..MockConfig::default()
        };
        let issuer = MockIssuer::spawn(cfg).await.unwrap();
        let url = format!(
            "{}/.well-known/oauth-protected-resource",
            issuer.issuer_url()
        );
        let body: serde_json::Value = reqwest::get(&url).await.unwrap().json().await.unwrap();
        assert_eq!(
            body.get("resource").and_then(|v| v.as_str()),
            Some("https://kamaji.test")
        );
        let servers = body
            .get("authorization_servers")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(servers.len(), 1);
        // The advertised AS is the mock's own bound URL.
        assert!(servers[0]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:"));
        let bearer = body
            .get("bearer_methods_supported")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(bearer.len(), 1);
        assert_eq!(bearer[0].as_str(), Some("header"));
        let scopes = body
            .get("scopes_supported")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(scopes.len(), SCOPE_VOCABULARY_DEFAULT.len());
        issuer.shutdown().await;
    }

    #[tokio::test]
    async fn mint_round_trips_through_paseto() {
        let issuer = MockIssuer::spawn(MockConfig::default()).await.unwrap();
        let claims = ambient_user_dev_claims(
            &issuer.issuer_url(),
            "https://kamaji.test",
            &["cloud:read"],
            &["svc-a"],
            1_700_000_000,
        );
        let token = issuer.mint(&claims).unwrap();

        // Verify the token using pasetors' low-level path against the
        // mock's own pubkey — same shape kamaji's verifier uses.
        let untrusted =
            UntrustedToken::<pasetors::token::Public, V4>::try_from(token.as_str()).unwrap();
        let pubkey_bytes = pubkey_array(&issuer.keypair);
        let pubkey = AsymmetricPublicKey::<V4>::from(&pubkey_bytes).unwrap();
        let trusted = PublicToken::verify(&pubkey, &untrusted, None, None).unwrap();
        let parsed: Value = serde_json::from_str(trusted.payload()).unwrap();
        assert_eq!(parsed.get("sub").and_then(|v| v.as_str()), Some("user:dev"));
        assert_eq!(
            parsed.get("camp_id").and_then(|v| v.as_str()),
            Some("C-dev")
        );
        let owns = parsed
            .get("owns")
            .and_then(|v| v.get("service"))
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(owns.len(), 1);
        assert_eq!(owns[0].as_str(), Some("svc-a"));

        // Footer carries `{"kid":"mock-1"}` so a kid-aware verifier
        // (kamaji) can look up the right key.
        let footer = untrusted.untrusted_footer();
        let footer_str = std::str::from_utf8(footer).unwrap();
        assert!(footer_str.contains(r#""kid":"mock-1""#));

        issuer.shutdown().await;
    }

    #[tokio::test]
    async fn ambient_claims_skip_owns_when_empty() {
        let claims =
            ambient_user_dev_claims("https://i", "https://a", &["cloud:read"], &[], 1_700_000_000);
        assert!(claims.get("owns").is_none());
        // But the other ambient fields are always present.
        assert_eq!(claims.get("sub").and_then(|v| v.as_str()), Some("user:dev"));
        assert_eq!(
            claims.get("act").and_then(|v| v.get("sub")).and_then(|v| v.as_str()),
            Some("agent:dev")
        );
    }

    #[tokio::test]
    async fn ttl_within_w159_band() {
        let now = 1_700_000_000;
        let claims = ambient_user_dev_claims("i", "a", &["s"], &[], now);
        let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap();
        let iat = claims.get("iat").and_then(|v| v.as_i64()).unwrap();
        let ttl = exp - iat;
        assert_eq!(iat, now);
        // W159 §TTLs: 5–15 min for access tokens. Mock defaults to the
        // upper end so test budgets don't accidentally race expiry.
        assert!(
            (5 * 60..=15 * 60).contains(&ttl),
            "ttl {ttl} outside W159 band"
        );
    }
}
