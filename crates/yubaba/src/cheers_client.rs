//! Privileged cheers client (R427-F1, W159 Phase 2).
//!
//! Yubaba is the **only** writer of cheers's ownership table. On successful
//! workload provision it `register_ownership(camp, kind, id, on_behalf_of=user)`;
//! on destroy it `revoke_ownership(row_id)`. Camps and agents have no path
//! into these writes — kamaji's `audit:write` scope is deliberately split
//! from yubaba's `ownership:write` so colocating kamaji on a yubaba host
//! doesn't leak ownership-write authority (W159 §Scope vocabulary).
//!
//! ## Auth shape
//!
//! Per W159 §Service principals + the cheers producer spec §Service principal
//! bootstrap: yubaba holds an Ed25519 keypair allocated at install time
//! (`yubaba install` → `POST /admin/service-principals` → secret half written
//! once to yubaba's config dir, mode 0600). Cheers publishes the pubkey in its
//! JWKS so any verifier (cheers's own `/ownership` route, kamaji) can verify
//! yubaba-minted tokens through the same JWKS path it uses for cheers-minted
//! tokens — no separate fetch path.
//!
//! Tokens are PASETO v4.public, **minted locally** by yubaba — `sub: svc:<id>`,
//! `scope: ["ownership:write"]`, `aud: <cheers issuer URL>` (cheers verifies its
//! own routes' tokens against itself), 5-minute TTL per W159 §TTLs. Local
//! minting means yubaba keeps writing ownership even during brief cheers API
//! blips — the request still 5xxs at the cheers HTTP layer, but the auth path
//! never round-trips, so an outage on cheers's mint endpoint can't paralyze
//! yubaba's writes.
//!
//! ## Wire shape (cheers producer spec)
//!
//! - `POST /ownership` with `Authorization: Bearer <token>` and JSON body
//!   `{principal_id, resource_kind, resource_id, relationship, on_behalf_of?}`.
//!   `granted_by` is filled from the token's verified `sub` server-side — the
//!   client cannot impersonate a different service principal even with a
//!   valid `ownership:write` token (defense-in-depth at the cheers handler).
//!   Returns `201 Created` + `OwnershipRow{id, ...}`. The `id` is what yubaba
//!   stores to call `DELETE` later.
//! - `DELETE /ownership/{id}` — soft-deletes (sets `revoked_at`). Idempotent.
//!
//! See `external/cheers/.yah/docs/working/mcp-auth-and-ownership.md`
//! §Ownership table + `external/cheers/crates/cheers-axum/src/ownership.rs`
//! for the authoritative producer side.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pasetors::keys::AsymmetricSecretKey;
use pasetors::version4::{PublicToken, V4};
use serde::{Deserialize, Serialize};

/// Token TTL for yubaba's ownership-write calls. Bottom of the W159 §TTLs
/// access-token band (5–15 min) — these calls are short, atomic, and minted
/// per-request, so a long TTL buys nothing and just widens the replay window
/// on a leaked transport-level capture.
const TOKEN_TTL_SECS: i64 = 5 * 60;

/// Errors surfaced by [`CheersClient`] calls.
#[derive(Debug, thiserror::Error)]
pub enum CheersError {
    /// PASETO mint failed. Almost always indicates the secret half on disk
    /// is malformed (wrong length, wrong format) — operator should re-run
    /// `yubaba install --rotate` to provision a fresh keypair.
    #[error("paseto mint failed: {0:?}")]
    Mint(pasetors::errors::Error),

    /// HTTP transport failure — DNS, TCP, TLS, timeout. Distinct from
    /// `Status` so a caller can branch on "cheers is unreachable" vs
    /// "cheers rejected the request".
    #[error("cheers transport: {0}")]
    Http(#[from] reqwest::Error),

    /// Cheers returned a non-2xx status. Body (if any) is preserved verbatim
    /// — RFC 6750 error responses are stable and worth surfacing for audit.
    #[error("cheers returned {status}: {body}")]
    Status {
        status: reqwest::StatusCode,
        body: String,
    },

    /// Response body didn't decode as the expected shape — almost always a
    /// cheers-side wire-contract drift bug.
    #[error("cheers response decode: {0}")]
    Decode(String),
}

/// Configuration for [`CheersClient`]. All fields are sourced from the
/// install-time service-principal bootstrap (W159 §Service principals).
#[derive(Debug, Clone)]
pub struct CheersConfig {
    /// Cheers issuer URL, e.g. `https://cheers.yah.cloud`. Used as both
    /// `iss` and `aud` on minted tokens — cheers verifies its own
    /// ownership-write routes against itself.
    pub issuer_url: String,
    /// Service-principal id, e.g. `yubaba-prod-1`. Becomes the token's
    /// `sub` field (prefixed `svc:` on the wire per the canonical claim
    /// schema).
    pub principal_id: String,
    /// `kid` published in cheers's JWKS for yubaba's pubkey. Kamaji and
    /// cheers's own verifier read it from the PASETO footer to look up
    /// yubaba's pubkey.
    pub kid: String,
}

/// Privileged client for cheers's ownership-write endpoints. Holds the
/// service-principal secret + reusable HTTP client; thread-safe.
///
/// Construct once at yubaba startup via [`Self::new`] (reads the secret
/// from disk), then share via `Arc<CheersClient>` across handlers.
pub struct CheersClient {
    config: CheersConfig,
    secret: AsymmetricSecretKey<V4>,
    http: reqwest::Client,
    /// Monotonic counter for `jti` — `(now_secs, counter)` is unique even
    /// when multiple writes land in the same second.
    jti_counter: AtomicU64,
}

impl std::fmt::Debug for CheersClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheersClient")
            .field("issuer_url", &self.config.issuer_url)
            .field("principal_id", &self.config.principal_id)
            .field("kid", &self.config.kid)
            .finish_non_exhaustive()
    }
}

impl CheersClient {
    /// Build a client. `secret_bytes` is the raw PASETO v4 secret key
    /// (64 bytes: 32-byte seed + 32-byte pubkey) as written by
    /// `yubaba install` / `--rotate`.
    pub fn new(config: CheersConfig, secret_bytes: &[u8]) -> Result<Self, CheersError> {
        let secret = AsymmetricSecretKey::<V4>::from(secret_bytes).map_err(CheersError::Mint)?;
        Ok(Self {
            config,
            secret,
            http: reqwest::Client::new(),
            jti_counter: AtomicU64::new(1),
        })
    }

    /// Configured cheers issuer URL — `iss`/`aud` on minted tokens.
    pub fn issuer_url(&self) -> &str {
        &self.config.issuer_url
    }

    /// Configured service-principal id (without the `svc:` prefix).
    pub fn principal_id(&self) -> &str {
        &self.config.principal_id
    }

    /// Mint a `ownership:write`-scoped token, signed locally with yubaba's
    /// service-principal key. Pure — no I/O — so it can be unit-tested
    /// against a known clock.
    fn mint_ownership_write_token(&self, now_secs: i64) -> Result<String, CheersError> {
        let jti = self.jti_counter.fetch_add(1, Ordering::Relaxed);
        let claims = serde_json::json!({
            "iss": self.config.issuer_url,
            "aud": self.config.issuer_url,
            "exp": now_secs + TOKEN_TTL_SECS,
            "iat": now_secs,
            "jti": format!("yubaba-{now_secs}-{jti}"),
            "sub": format!("svc:{}", self.config.principal_id),
            "scope": ["ownership:write"],
        });
        let payload = serde_json::to_vec(&claims)
            .map_err(|e| CheersError::Decode(format!("serialize claims: {e}")))?;
        let footer = format!(r#"{{"kid":"{}"}}"#, self.config.kid).into_bytes();
        PublicToken::sign(&self.secret, &payload, Some(&footer), None).map_err(CheersError::Mint)
    }

    /// `POST /ownership` — record that `principal_id` now `relationship`s
    /// the resource `(resource_kind, resource_id)`. `on_behalf_of` is the
    /// human who triggered the deploy (`user:<U>`); leave `None` for
    /// self-grants. Returns the `id` of the new row — store it so a later
    /// destroy can `DELETE /ownership/{id}`.
    pub async fn register_ownership(
        &self,
        principal_id: &str,
        resource_kind: &str,
        resource_id: &str,
        relationship: &str,
        on_behalf_of: Option<&str>,
    ) -> Result<OwnershipRow, CheersError> {
        let token = self.mint_ownership_write_token(now_unix())?;
        let body = serde_json::json!({
            "principal_id": principal_id,
            "resource_kind": resource_kind,
            "resource_id": resource_id,
            "relationship": relationship,
            "on_behalf_of": on_behalf_of,
        });
        let url = format!("{}/ownership", self.config.issuer_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(CheersError::Status { status, body: text });
        }
        serde_json::from_str(&text)
            .map_err(|e| CheersError::Decode(format!("OwnershipRow: {e} (body: {text})")))
    }

    /// `DELETE /ownership/{id}` — soft-delete by id. Idempotent on the
    /// cheers side; re-revoking an already-revoked row succeeds with
    /// `204 No Content`. `404 Not Found` surfaces as
    /// [`CheersError::Status`] so a destroy path can decide whether to
    /// treat "row missing" as a fatal mismatch or a benign retry.
    pub async fn revoke_ownership(&self, id: &str) -> Result<(), CheersError> {
        let token = self.mint_ownership_write_token(now_unix())?;
        let url = format!(
            "{}/ownership/{}",
            self.config.issuer_url.trim_end_matches('/'),
            id
        );
        let resp = self.http.delete(&url).bearer_auth(&token).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CheersError::Status { status, body });
        }
        Ok(())
    }
}

/// Subset of cheers's `OwnershipRow` shape — enough for yubaba to round-trip
/// the `id` between register and revoke. Cheers may add fields; serde's
/// default ignore-unknown behavior on structs would reject those, so the
/// fields yubaba doesn't care about land in `extra` as raw JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipRow {
    pub id: String,
    pub principal_id: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub relationship: String,
    pub granted_by: String,
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    pub granted_at: i64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{delete, post};
    use axum::{Json, Router};
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, Generate};
    use pasetors::token::{Public, UntrustedToken};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn fresh_keypair() -> AsymmetricKeyPair<V4> {
        AsymmetricKeyPair::<V4>::generate().expect("generate v4 keypair")
    }

    fn client_with(keypair: &AsymmetricKeyPair<V4>, issuer: &str) -> CheersClient {
        let cfg = CheersConfig {
            issuer_url: issuer.to_string(),
            principal_id: "yubaba-test".to_string(),
            kid: "yubaba-test-1".to_string(),
        };
        CheersClient::new(cfg, keypair.secret.as_bytes()).expect("build client")
    }

    #[test]
    fn mint_token_round_trips_and_carries_expected_claims() {
        let kp = fresh_keypair();
        let client = client_with(&kp, "https://cheers.test");
        let token = client.mint_ownership_write_token(1_700_000_000).unwrap();

        let untrusted = UntrustedToken::<Public, V4>::try_from(token.as_str()).unwrap();
        let pubkey_bytes: [u8; 32] = kp.public.as_bytes().try_into().unwrap();
        let pubkey = AsymmetricPublicKey::<V4>::from(&pubkey_bytes).unwrap();
        let trusted = PublicToken::verify(&pubkey, &untrusted, None, None).unwrap();
        let claims: serde_json::Value = serde_json::from_str(trusted.payload()).unwrap();

        assert_eq!(claims["sub"], "svc:yubaba-test");
        assert_eq!(claims["iss"], "https://cheers.test");
        assert_eq!(claims["aud"], "https://cheers.test");
        assert_eq!(claims["scope"][0], "ownership:write");
        assert_eq!(claims["iat"], 1_700_000_000);
        assert_eq!(claims["exp"], 1_700_000_000 + TOKEN_TTL_SECS);

        let footer = std::str::from_utf8(untrusted.untrusted_footer()).unwrap();
        assert!(footer.contains(r#""kid":"yubaba-test-1""#));
    }

    #[test]
    fn jti_is_unique_across_sequential_mints() {
        let kp = fresh_keypair();
        let client = client_with(&kp, "https://cheers.test");
        // Two mints at the same wallclock second still get distinct jtis
        // — the monotonic counter ensures replay-protection inside one second.
        let t1 = client.mint_ownership_write_token(1_700_000_000).unwrap();
        let t2 = client.mint_ownership_write_token(1_700_000_000).unwrap();

        let parse = |tok: &str| -> serde_json::Value {
            let u = UntrustedToken::<Public, V4>::try_from(tok).unwrap();
            let pk_bytes: [u8; 32] = kp.public.as_bytes().try_into().unwrap();
            let pk = AsymmetricPublicKey::<V4>::from(&pk_bytes).unwrap();
            let t = PublicToken::verify(&pk, &u, None, None).unwrap();
            serde_json::from_str(t.payload()).unwrap()
        };

        let c1 = parse(&t1);
        let c2 = parse(&t2);
        assert_ne!(c1["jti"], c2["jti"]);
    }

    #[test]
    fn new_rejects_malformed_secret() {
        let cfg = CheersConfig {
            issuer_url: "https://cheers.test".into(),
            principal_id: "yubaba-test".into(),
            kid: "k1".into(),
        };
        // 3 bytes is nowhere near v4's required key length.
        let err = CheersClient::new(cfg, &[0u8, 1, 2]).unwrap_err();
        assert!(matches!(err, CheersError::Mint(_)));
    }

    // ── Mock cheers server for end-to-end HTTP tests ─────────────────────────

    #[derive(Clone, Default)]
    struct MockState {
        /// Last seen body on POST /ownership — tests assert against this.
        last_post: Arc<Mutex<Option<serde_json::Value>>>,
        last_auth: Arc<Mutex<Option<String>>>,
        last_delete_id: Arc<Mutex<Option<String>>>,
        /// When set, POST returns this status + body instead of the happy path.
        fail_post: Arc<Mutex<Option<(StatusCode, String)>>>,
    }

    async fn mock_post(
        State(state): State<MockState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        if let Some(auth) = headers.get("authorization") {
            *state.last_auth.lock().await = Some(auth.to_str().unwrap_or("").into());
        }
        *state.last_post.lock().await = Some(body.clone());
        if let Some((status, msg)) = state.fail_post.lock().await.clone() {
            return (status, Json(serde_json::json!({ "error": msg })));
        }
        let row = serde_json::json!({
            "id": "01HOWNROW",
            "principal_id": body["principal_id"],
            "resource_kind": body["resource_kind"],
            "resource_id": body["resource_id"],
            "relationship": body["relationship"],
            "granted_by": "svc:yubaba-test",
            "on_behalf_of": body["on_behalf_of"],
            "granted_at": 1_700_000_000_i64,
            "revoked_at": serde_json::Value::Null,
        });
        (StatusCode::CREATED, Json(row))
    }

    async fn mock_delete(
        State(state): State<MockState>,
        Path(id): Path<String>,
    ) -> StatusCode {
        *state.last_delete_id.lock().await = Some(id);
        StatusCode::NO_CONTENT
    }

    async fn spawn_mock() -> (String, MockState) {
        let state = MockState::default();
        let app = Router::new()
            .route("/ownership", post(mock_post))
            .route("/ownership/{id}", delete(mock_delete))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), state)
    }

    #[tokio::test]
    async fn register_ownership_posts_canonical_body_with_bearer() {
        let (url, mock) = spawn_mock().await;
        let kp = fresh_keypair();
        let client = client_with(&kp, &url);

        let row = client
            .register_ownership("camp:C-abc", "service", "svc-xyz", "owns", Some("user:U-1"))
            .await
            .unwrap();

        assert_eq!(row.id, "01HOWNROW");
        let body = mock.last_post.lock().await.clone().unwrap();
        assert_eq!(body["principal_id"], "camp:C-abc");
        assert_eq!(body["resource_kind"], "service");
        assert_eq!(body["resource_id"], "svc-xyz");
        assert_eq!(body["relationship"], "owns");
        assert_eq!(body["on_behalf_of"], "user:U-1");

        let auth = mock.last_auth.lock().await.clone().unwrap();
        assert!(auth.starts_with("Bearer v4.public."), "bearer auth header should carry a v4.public token, got: {auth}");
    }

    #[tokio::test]
    async fn register_ownership_omits_on_behalf_of_when_none() {
        let (url, mock) = spawn_mock().await;
        let kp = fresh_keypair();
        let client = client_with(&kp, &url);

        client
            .register_ownership("svc:yubaba-test", "machine", "m-1", "owns", None)
            .await
            .unwrap();

        let body = mock.last_post.lock().await.clone().unwrap();
        // serde_json::json! writes None as null — cheers's CreateOwnershipBody
        // deserializes `Option<PrincipalId>` from missing OR null, so either
        // form is wire-compatible. Pin null here so a future shift to a
        // serde(skip_serializing_if = "Option::is_none") change is a
        // deliberate decision and not an accident.
        assert!(body["on_behalf_of"].is_null());
    }

    #[tokio::test]
    async fn register_ownership_surfaces_403_as_status_error() {
        let (url, mock) = spawn_mock().await;
        *mock.fail_post.lock().await = Some((
            StatusCode::FORBIDDEN,
            "insufficient_scope".into(),
        ));
        let kp = fresh_keypair();
        let client = client_with(&kp, &url);

        let err = client
            .register_ownership("camp:C-abc", "service", "svc-xyz", "owns", None)
            .await
            .unwrap_err();
        match err {
            CheersError::Status { status, body } => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert!(body.contains("insufficient_scope"), "body should preserve cheers's error: {body}");
            }
            other => panic!("expected Status error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn revoke_ownership_calls_delete_with_id() {
        let (url, mock) = spawn_mock().await;
        let kp = fresh_keypair();
        let client = client_with(&kp, &url);

        client.revoke_ownership("01HOWNROW").await.unwrap();

        let id = mock.last_delete_id.lock().await.clone().unwrap();
        assert_eq!(id, "01HOWNROW");
    }
}
