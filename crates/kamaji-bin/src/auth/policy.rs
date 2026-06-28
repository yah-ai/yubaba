//! Scope + ownership-list policy check — W159 §The wire Layer 2.
//!
//! Pure-function check against a verified [`McpClaims`] bag. Input is the
//! parsed token claims plus a per-method [`Requirement`] (scopes required,
//! optionally a `(kind, id)` resource the call targets). Output is `Ok(())`
//! or a [`Deny`] ready for serialization onto the wire.
//!
//! No network calls. No state. Layer 1 (signature + standard claims) ran in
//! [`super::AuthVerifier::verify`] already; this is the second-pass policy
//! gate run by the dispatch loop (a later ticket) once it knows which Hub
//! method is being invoked and which resource id the params name.

use super::claims::McpClaims;
use super::deny::Deny;

/// What a specific request requires of the caller's token.
///
/// Built per-call by the dispatch loop based on the Hub method being invoked.
/// `cloud.deploy(svc-xyz)` → `Requirement::scope("cloud:deploy").owns("service", "svc-xyz")`.
/// `cloud.list_services()` → `Requirement::scope("cloud:read")`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requirement {
    /// All scopes that must be present on the token. Exact-match — W159
    /// §Scope vocabulary composition rules forbid wildcards and forbid
    /// implication trees (`camp:admin` does NOT imply `camp:read`).
    pub scopes: Vec<String>,
    /// Resource the call targets — `(resource_kind, resource_id)`. When
    /// present, the token's `owns[resource_kind]` must contain `resource_id`.
    pub owns: Option<(String, String)>,
}

impl Requirement {
    /// Single-scope shorthand. Chain with [`Self::and_scope`] for multi.
    pub fn scope(scope: impl Into<String>) -> Self {
        Self {
            scopes: vec![scope.into()],
            owns: None,
        }
    }

    /// Add an additional required scope. Idempotent — a duplicate is just
    /// checked twice, which is cheap.
    pub fn and_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Require ownership of `(kind, id)` in addition to the scope set.
    /// Convention: `kind` matches the resource-kind key in `owns:` —
    /// `"service"`, `"arch_doc"`, etc.
    pub fn owns(mut self, kind: impl Into<String>, id: impl Into<String>) -> Self {
        self.owns = Some((kind.into(), id.into()));
        self
    }
}

/// Layer 2: enforce a [`Requirement`] against verified claims. Returns
/// `Err(Deny::insufficient_scope)` on first failure — order is scopes-first,
/// then ownership, so a missing scope is reported even when the token also
/// lacks the resource.
pub fn enforce(claims: &McpClaims, requirement: &Requirement) -> Result<(), Deny> {
    for required in &requirement.scopes {
        if !claims.scope.iter().any(|s| s == required) {
            return Err(Deny::insufficient_scope(
                Some(required.clone()),
                requirement.owns.as_ref().map(|(_, id)| id.clone()),
            ));
        }
    }
    if let Some((kind, id)) = &requirement.owns {
        let owned = claims
            .owns
            .as_ref()
            .map(|o| o.contains(kind, id))
            .unwrap_or(false);
        if !owned {
            // No specific scope to surface — all scopes present — so the
            // `WWW-Authenticate` `scope=` parameter stays None. The body's
            // `resource` field reports which resource the request targeted.
            return Err(Deny::insufficient_scope(
                Option::<&str>::None,
                Some(id.clone()),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::claims::{AuthStrength, McpClaims, OwnsClaim};
    use std::collections::BTreeMap;

    fn claims_with(scopes: &[&str], owns: Option<BTreeMap<String, Vec<String>>>) -> McpClaims {
        McpClaims {
            iss: "https://cheers.test".into(),
            aud: "https://kamaji.test".into(),
            exp: 2_000_000_000,
            iat: 1_700_000_000,
            jti: "01HTEST".into(),
            sub: "user:abc".into(),
            scope: scopes.iter().map(|s| s.to_string()).collect(),
            act: None,
            camp_id: Some("C1".into()),
            owns: owns.map(|by_kind| OwnsClaim { by_kind }),
            auth_strength: Some(AuthStrength::Bootstrap),
        }
    }

    #[test]
    fn passes_when_scope_present_no_owns_required() {
        let claims = claims_with(&["cloud:read"], None);
        let req = Requirement::scope("cloud:read");
        assert!(enforce(&claims, &req).is_ok());
    }

    #[test]
    fn fails_when_scope_missing() {
        let claims = claims_with(&["cloud:read"], None);
        let req = Requirement::scope("cloud:deploy");
        let deny = enforce(&claims, &req).unwrap_err();
        assert_eq!(deny.status_code(), 403);
        assert_eq!(deny.scope.as_deref(), Some("cloud:deploy"));
        assert!(deny.resource.is_none());
    }

    #[test]
    fn requires_all_scopes_present() {
        let claims = claims_with(&["cloud:read"], None);
        let req = Requirement::scope("cloud:read").and_scope("cloud:deploy");
        let deny = enforce(&claims, &req).unwrap_err();
        assert_eq!(deny.scope.as_deref(), Some("cloud:deploy"));
    }

    #[test]
    fn owns_check_passes_when_resource_in_list() {
        let mut owns = BTreeMap::new();
        owns.insert(
            "service".into(),
            vec!["svc-abc".into(), "svc-xyz".into()],
        );
        let claims = claims_with(&["cloud:deploy"], Some(owns));
        let req = Requirement::scope("cloud:deploy").owns("service", "svc-xyz");
        assert!(enforce(&claims, &req).is_ok());
    }

    #[test]
    fn owns_check_fails_when_resource_missing() {
        let mut owns = BTreeMap::new();
        owns.insert("service".into(), vec!["svc-abc".into()]);
        let claims = claims_with(&["cloud:deploy"], Some(owns));
        let req = Requirement::scope("cloud:deploy").owns("service", "svc-xyz");
        let deny = enforce(&claims, &req).unwrap_err();
        assert_eq!(deny.status_code(), 403);
        // No missing scope to report — only the resource id.
        assert!(deny.scope.is_none());
        assert_eq!(deny.resource.as_deref(), Some("svc-xyz"));
    }

    #[test]
    fn owns_check_fails_when_no_owns_claim_at_all() {
        let claims = claims_with(&["cloud:deploy"], None);
        let req = Requirement::scope("cloud:deploy").owns("service", "svc-xyz");
        let deny = enforce(&claims, &req).unwrap_err();
        assert_eq!(deny.resource.as_deref(), Some("svc-xyz"));
    }

    #[test]
    fn owns_check_fails_when_kind_missing_even_if_other_kinds_present() {
        let mut owns = BTreeMap::new();
        owns.insert("arch_doc".into(), vec!["doc-1".into()]);
        let claims = claims_with(&["cloud:deploy"], Some(owns));
        let req = Requirement::scope("cloud:deploy").owns("service", "svc-xyz");
        let deny = enforce(&claims, &req).unwrap_err();
        assert_eq!(deny.resource.as_deref(), Some("svc-xyz"));
    }

    #[test]
    fn scope_check_runs_before_owns_check() {
        // Token lacks BOTH the scope and the resource. The reported failure
        // must be the scope — Layer 2 fails on scopes first so the operator
        // grants scope before worrying about ownership.
        let claims = claims_with(&[], None);
        let req = Requirement::scope("cloud:deploy").owns("service", "svc-xyz");
        let deny = enforce(&claims, &req).unwrap_err();
        assert_eq!(deny.scope.as_deref(), Some("cloud:deploy"));
        // The scope-failure path also reports the targeted resource — F3's
        // contract: when both fail, surface scope first but include resource
        // context so the operator sees the full intent.
        assert_eq!(deny.resource.as_deref(), Some("svc-xyz"));
    }

    #[test]
    fn no_admin_implication_tree() {
        // `camp:admin` does NOT imply `camp:read` — W159 §Scope composition
        // rule 3. Kamaji does exact-match only.
        let claims = claims_with(&["camp:admin"], None);
        let req = Requirement::scope("camp:read");
        let deny = enforce(&claims, &req).unwrap_err();
        assert_eq!(deny.scope.as_deref(), Some("camp:read"));
    }
}
