//! Canonical 401 / 403 wire shapes for the kamaji auth surface.
//!
//! W159 §Failure responses pins the formats verbatim:
//!
//! **401 Unauthorized** — no token / malformed / expired / bad signature /
//! unknown `iss`:
//!
//! ```text
//! HTTP/1.1 401 Unauthorized
//! WWW-Authenticate: Bearer realm="kamaji",
//!   error="invalid_token",
//!   error_description="signature verification failed",
//!   resource_metadata="https://kamaji.example/.well-known/oauth-protected-resource"
//! Content-Type: application/json
//!
//! {"error":"invalid_token"}
//! ```
//!
//! **403 Forbidden** — valid token but lacks required scope, `aud` mismatch,
//! or target resource not in `owns: [...]`:
//!
//! ```text
//! HTTP/1.1 403 Forbidden
//! WWW-Authenticate: Bearer realm="kamaji",
//!   error="insufficient_scope",
//!   scope="cloud:deploy",
//!   resource_metadata="https://kamaji.example/.well-known/oauth-protected-resource"
//! Content-Type: application/json
//!
//! {"error":"insufficient_scope","scope":"cloud:deploy","resource":"svc-xyz"}
//! ```
//!
//! Body carries `error` + `scope` + `resource` only — finer-grained reasons
//! (which signature check failed, which claim shape misbehaved) stay in the
//! local audit journal. The `error_description` parameter on
//! `WWW-Authenticate` uses operator-curated phrasing only, not raw error
//! strings — see [`Self::invalid_token`] / [`Self::insufficient_scope`].

use super::error::VerifyError;

/// W159 default realm. Operator deployments may override at construction.
pub const DEFAULT_REALM: &str = "kamaji";

/// One denial response, ready to serialize into HTTP status + headers + body.
/// Produced by either [`super::AuthVerifier::verify`] failures (via
/// [`From<VerifyError>`]) or [`super::policy::enforce`] failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deny {
    pub kind: DenyKind,
    /// `realm` parameter on `WWW-Authenticate`. Defaults to
    /// [`DEFAULT_REALM`].
    pub realm: String,
    /// Operator-curated short string for the `error_description` parameter
    /// on `WWW-Authenticate`. NOT included in the JSON body. Kept generic
    /// (e.g. `"signature verification failed"`, `"token expired"`) — never
    /// includes raw error text that could aid forgery probing.
    pub description: Option<String>,
    /// Scope-failure shape — single missing scope name. Surfaced both in
    /// the `WWW-Authenticate` `scope` parameter and the JSON body.
    pub scope: Option<String>,
    /// Resource the request targeted, when ownership check failed. JSON
    /// body only — NOT a `WWW-Authenticate` parameter (RFC 6750 doesn't
    /// reserve one).
    pub resource: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyKind {
    /// 401 — no token, malformed, expired, bad signature, bad iss/aud, etc.
    InvalidToken,
    /// 403 — token verified, but lacks the scope or resource ownership the
    /// request requires.
    InsufficientScope,
}

impl Deny {
    /// 401 — token is unusable. Reason is operator-curated, not a raw
    /// error message.
    pub fn invalid_token(reason: impl Into<String>) -> Self {
        Self {
            kind: DenyKind::InvalidToken,
            realm: DEFAULT_REALM.into(),
            description: Some(reason.into()),
            scope: None,
            resource: None,
        }
    }

    /// 403 — token is valid but lacks the required scope, optionally the
    /// targeted resource. Both fields end up in the JSON body; `scope` also
    /// rides on the `WWW-Authenticate` header.
    pub fn insufficient_scope(
        scope: Option<impl Into<String>>,
        resource: Option<impl Into<String>>,
    ) -> Self {
        Self {
            kind: DenyKind::InsufficientScope,
            realm: DEFAULT_REALM.into(),
            description: None,
            scope: scope.map(Into::into),
            resource: resource.map(Into::into),
        }
    }

    /// Override the realm. Defaults to [`DEFAULT_REALM`] otherwise.
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    /// HTTP status code.
    pub fn status_code(&self) -> u16 {
        match self.kind {
            DenyKind::InvalidToken => 401,
            DenyKind::InsufficientScope => 403,
        }
    }

    /// Short OAuth error code, RFC 6750 §3.1: `invalid_token` /
    /// `insufficient_scope`.
    pub fn error_code(&self) -> &'static str {
        match self.kind {
            DenyKind::InvalidToken => "invalid_token",
            DenyKind::InsufficientScope => "insufficient_scope",
        }
    }

    /// Build the `WWW-Authenticate` header value. RFC 6750 §3 challenge
    /// shape with our parameters in canonical order:
    ///
    /// 1. `realm`
    /// 2. `error`
    /// 3. `error_description` (when set)
    /// 4. `scope` (when set)
    /// 5. `resource_metadata`
    ///
    /// `resource_metadata_url` is the absolute URL of *this* kamaji's
    /// `/.well-known/oauth-protected-resource` (F4 endpoint). One-line
    /// output — line-folded `obs-fold` headers are deprecated by RFC 7230.
    pub fn www_authenticate(&self, resource_metadata_url: &str) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(5);
        parts.push(format!("realm={}", quoted(&self.realm)));
        parts.push(format!("error={}", quoted(self.error_code())));
        if let Some(desc) = &self.description {
            parts.push(format!("error_description={}", quoted(desc)));
        }
        if let Some(scope) = &self.scope {
            parts.push(format!("scope={}", quoted(scope)));
        }
        parts.push(format!(
            "resource_metadata={}",
            quoted(resource_metadata_url)
        ));
        format!("Bearer {}", parts.join(", "))
    }

    /// JSON body. Carries `error` + `scope` + `resource` only — no
    /// `error_description` (see W159 §Failure responses).
    pub fn json_body(&self) -> String {
        let mut payload = serde_json::Map::new();
        payload.insert(
            "error".to_string(),
            serde_json::Value::String(self.error_code().to_string()),
        );
        if let Some(scope) = &self.scope {
            payload.insert(
                "scope".to_string(),
                serde_json::Value::String(scope.clone()),
            );
        }
        if let Some(resource) = &self.resource {
            payload.insert(
                "resource".to_string(),
                serde_json::Value::String(resource.clone()),
            );
        }
        serde_json::Value::Object(payload).to_string()
    }
}

impl From<VerifyError> for Deny {
    /// Map verifier-side rejections to wire shapes. All variants land as
    /// 401 `invalid_token` — F2's rejections all mean "the token itself is
    /// unusable." Scope / owns failures are produced by [`super::policy`]
    /// directly as 403 `insufficient_scope`.
    fn from(err: VerifyError) -> Self {
        let reason = match err {
            VerifyError::Malformed(_) => "malformed token",
            VerifyError::MissingKid => "missing key id",
            VerifyError::UnknownKid(_) => "unknown key id",
            VerifyError::SignatureMismatch => "signature verification failed",
            VerifyError::Expired { .. } => "token expired",
            VerifyError::BadIssuer { .. } => "issuer mismatch",
            VerifyError::BadAudience { .. } => "audience mismatch",
            VerifyError::BadClaims(_) => "claim shape violation",
        };
        Deny::invalid_token(reason)
    }
}

/// RFC 6749 quoted-string serialization — wrap in `"…"`, escape `\\` and `"`.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' | '"' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const METADATA_URL: &str =
        "https://kamaji.example/.well-known/oauth-protected-resource";

    #[test]
    fn invalid_token_matches_w159_example() {
        let deny = Deny::invalid_token("signature verification failed");
        assert_eq!(deny.status_code(), 401);
        assert_eq!(
            deny.www_authenticate(METADATA_URL),
            "Bearer realm=\"kamaji\", \
             error=\"invalid_token\", \
             error_description=\"signature verification failed\", \
             resource_metadata=\"https://kamaji.example/.well-known/oauth-protected-resource\""
        );
        assert_eq!(deny.json_body(), r#"{"error":"invalid_token"}"#);
    }

    #[test]
    fn insufficient_scope_matches_w159_example() {
        let deny = Deny::insufficient_scope(Some("cloud:deploy"), Some("svc-xyz"));
        assert_eq!(deny.status_code(), 403);
        assert_eq!(
            deny.www_authenticate(METADATA_URL),
            "Bearer realm=\"kamaji\", \
             error=\"insufficient_scope\", \
             scope=\"cloud:deploy\", \
             resource_metadata=\"https://kamaji.example/.well-known/oauth-protected-resource\""
        );
        // JSON body order matches W159 example: error, scope, resource.
        assert_eq!(
            deny.json_body(),
            r#"{"error":"insufficient_scope","resource":"svc-xyz","scope":"cloud:deploy"}"#
        );
    }

    #[test]
    fn insufficient_scope_without_resource() {
        let deny: Deny =
            Deny::insufficient_scope(Some("camp:admin"), Option::<&str>::None);
        assert_eq!(
            deny.json_body(),
            r#"{"error":"insufficient_scope","scope":"camp:admin"}"#
        );
        // resource_metadata still present on header; resource is body-only.
        let header = deny.www_authenticate(METADATA_URL);
        assert!(header.contains("scope=\"camp:admin\""));
        assert!(!header.contains("resource="));
    }

    #[test]
    fn from_verify_error_maps_to_invalid_token() {
        for err in [
            VerifyError::Malformed("x".into()),
            VerifyError::MissingKid,
            VerifyError::UnknownKid("k-?".into()),
            VerifyError::SignatureMismatch,
            VerifyError::Expired { exp: 1, now: 2 },
            VerifyError::BadIssuer {
                expected: "a".into(),
                got: "b".into(),
            },
            VerifyError::BadAudience {
                expected: "a".into(),
                got: "b".into(),
            },
            VerifyError::BadClaims("x".into()),
        ] {
            let deny: Deny = err.into();
            assert_eq!(deny.status_code(), 401);
            assert_eq!(deny.error_code(), "invalid_token");
            assert!(deny.description.is_some());
        }
    }

    #[test]
    fn realm_override() {
        let deny = Deny::invalid_token("token expired").with_realm("yubaba");
        let header = deny.www_authenticate(METADATA_URL);
        assert!(header.starts_with("Bearer realm=\"yubaba\","));
    }

    #[test]
    fn quoted_escapes_dquote_and_backslash() {
        let weird = Deny::invalid_token(r#"contains " and \"#);
        let header = weird.www_authenticate(METADATA_URL);
        assert!(
            header.contains(r#"error_description="contains \" and \\""#),
            "header was: {header}"
        );
    }
}
