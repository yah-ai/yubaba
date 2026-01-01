//! MCP-call JWT claim shape, verbatim with W159 §Canonical claim schema.
//!
//! The wire is the same as cheers's session tokens (PASETO v4.public over the
//! same `cheers-verify` codec path), but the *claims* differ — session tokens
//! carry user-identity claims, MCP-call tokens carry the scope/owns/camp_id
//! triple plus optional RFC 8693 `act` and `auth_strength` markers.
//!
//! `sub` is parsed as a prefixed string (`user:<id>` / `svc:<id>` /
//! `camp:<id>`) but stays a plain `String` on the type; the prefix is read by
//! [`McpClaims::principal_kind`] when consumers care.

use serde::{Deserialize, Serialize};

/// The full MCP-call claim set. Required fields are present unconditionally;
/// conditional fields are `Option`. Field order mirrors the W159 spec block
/// so a side-by-side diff reads cleanly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpClaims {
    // ── Required ────────────────────────────────────────────────────────────
    /// Cheers issuer URL — `iss` in JWT/OIDC vocabulary.
    pub iss: String,
    /// Resource URI this token is valid for (the constable / sage / ...).
    pub aud: String,
    /// Expiry, Unix seconds. Constable enforces `now < exp` locally.
    pub exp: i64,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Unique token id — revocation handle.
    pub jti: String,
    /// Principal: `user:<id>` / `svc:<id>` / `camp:<id>`.
    pub sub: String,
    /// Verbatim scope list — no wildcards. W159 §Scope vocabulary.
    pub scope: Vec<String>,

    // ── Conditional ─────────────────────────────────────────────────────────
    /// RFC 8693 actor — the agent variant acting on the user's behalf.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
    /// Call context: which camp the action is scoped to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camp_id: Option<String>,
    /// Embedded ownership — keyed by resource kind. W159 §Layer 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owns: Option<OwnsClaim>,
    /// How the camp identity was last asserted. W159 §Local desktop vs remote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_strength: Option<AuthStrength>,
}

/// The `act` claim — `{ "sub": "agent:<variant>" }`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorClaim {
    pub sub: String,
}

/// Embedded ownership: `{ "service": ["svc-abc", ...], "arch_doc": [...] }`.
/// Direct-list form only in v1; merkle-root form is deferred per W159
/// §Defer until the lack hurts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct OwnsClaim {
    pub by_kind: std::collections::BTreeMap<String, Vec<String>>,
}

impl OwnsClaim {
    /// `resource_id ∈ owns[resource_kind]?` — the local check that makes
    /// embedded ownership cheap (W159 §Layer 2). The miss case is a 403
    /// `insufficient_scope` on the wire (F3).
    pub fn contains(&self, resource_kind: &str, resource_id: &str) -> bool {
        self.by_kind
            .get(resource_kind)
            .is_some_and(|ids| ids.iter().any(|id| id == resource_id))
    }
}

/// W159: `bootstrap` for tokens minted off a long-lived camp credential;
/// `user-fresh` for tokens minted within N minutes of a passkey assertion.
/// Constable / downstream services MAY require `user-fresh` for specific ops.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthStrength {
    Bootstrap,
    UserFresh,
}

/// Principal kind, parsed from the `sub:` prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    User,
    Service,
    Camp,
}

impl McpClaims {
    /// Read the principal kind from the `sub` prefix. Returns `None` when
    /// the prefix is missing or unknown — that's a wire-contract violation
    /// the verifier already catches via [`crate::auth::VerifyError::BadClaims`],
    /// but the parsed view stays available for inspection.
    pub fn principal_kind(&self) -> Option<PrincipalKind> {
        let (prefix, _) = self.sub.split_once(':')?;
        match prefix {
            "user" => Some(PrincipalKind::User),
            "svc" => Some(PrincipalKind::Service),
            "camp" => Some(PrincipalKind::Camp),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_required_only() {
        let c = McpClaims {
            iss: "https://cheers.example".into(),
            aud: "https://constable.example".into(),
            exp: 1_700_000_900,
            iat: 1_700_000_000,
            jti: "01HXYZ".into(),
            sub: "user:abc".into(),
            scope: vec!["cloud:deploy".into(), "cloud:read".into()],
            act: None,
            camp_id: None,
            owns: None,
            auth_strength: None,
        };
        let v = serde_json::to_value(&c).unwrap();
        // Conditional fields should be absent in the wire form when None.
        assert!(v.get("act").is_none());
        assert!(v.get("owns").is_none());
        let back: McpClaims = serde_json::from_value(v).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn round_trip_all_fields() {
        let owns_payload = json!({"service": ["svc-abc", "svc-def"], "arch_doc": ["doc-1"]});
        let wire = json!({
            "iss": "https://cheers.example",
            "aud": "https://constable.example",
            "exp": 1_700_000_900_i64,
            "iat": 1_700_000_000_i64,
            "jti": "01HXYZ",
            "sub": "camp:C1",
            "scope": ["cloud:deploy"],
            "act": {"sub": "agent:claude"},
            "camp_id": "C1",
            "owns": owns_payload,
            "auth_strength": "bootstrap",
        });
        let c: McpClaims = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(c.principal_kind(), Some(PrincipalKind::Camp));
        assert_eq!(c.act.as_ref().unwrap().sub, "agent:claude");
        assert_eq!(c.auth_strength, Some(AuthStrength::Bootstrap));
        let owns = c.owns.as_ref().unwrap();
        assert!(owns.contains("service", "svc-abc"));
        assert!(!owns.contains("service", "svc-zzz"));
        assert!(owns.contains("arch_doc", "doc-1"));
        // Round-trip preserves shape.
        assert_eq!(serde_json::to_value(&c).unwrap(), wire);
    }

    #[test]
    fn principal_kinds() {
        let mut c = McpClaims {
            iss: "i".into(),
            aud: "a".into(),
            exp: 0,
            iat: 0,
            jti: "j".into(),
            sub: "user:u".into(),
            scope: vec![],
            act: None,
            camp_id: None,
            owns: None,
            auth_strength: None,
        };
        assert_eq!(c.principal_kind(), Some(PrincipalKind::User));
        c.sub = "svc:warden".into();
        assert_eq!(c.principal_kind(), Some(PrincipalKind::Service));
        c.sub = "camp:C".into();
        assert_eq!(c.principal_kind(), Some(PrincipalKind::Camp));
        c.sub = "bogus".into();
        assert_eq!(c.principal_kind(), None);
    }
}
