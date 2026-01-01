//! `/.well-known/oauth-protected-resource` — protected-resource discovery doc.
//!
//! W159 §Failure responses points clients at this endpoint via the
//! `resource_metadata` parameter on `WWW-Authenticate` headers; the
//! desktop Connect-Remote modal also probes for it to distinguish an
//! authed `https://` host (hub-cheers-rpc) from a plain SSH host (rpc-ssh).
//!
//! Shape follows RFC 9728 (OAuth 2.0 Protected Resource Metadata). F4
//! lands the data shape + serializer; the HTTPS route that serves this
//! JSON at the well-known path is wired up by the later dispatch-loop
//! ticket that mounts the authed Hub adapter.

use serde::{Deserialize, Serialize};

use super::config::AuthConfig;

/// W159 §Scope vocabulary, with the service-only scopes included. RFC 9728's
/// `scopes_supported` is "every scope the resource accepts" — service-only
/// scopes ARE accepted at the wire even though cheers refuses to grant them
/// to user principals (warden carries `ownership:write`; constable's own
/// audit forwarder carries `audit:write`).
pub const SCOPE_VOCABULARY: &[&str] = &[
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
    "subagent:spawn",
    "subagent:control",
    "audit:read",
    // Service-only (cheers's grant API rejects principal_kind=user for these).
    "ownership:write",
    "audit:write",
];

/// Protected-resource metadata document, RFC 9728 §2 shape. Constable serves
/// this from `/.well-known/oauth-protected-resource`. Fields kept Option /
/// Vec so we can extend additively without breaking existing clients.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedResourceMetadata {
    /// The protected resource's identifier — this constable's `aud` URI.
    pub resource: String,
    /// AS issuer URLs cheers's OAuth token-endpoint lives at.
    pub authorization_servers: Vec<String>,
    /// Scopes constable accepts on the wire — see [`SCOPE_VOCABULARY`].
    pub scopes_supported: Vec<String>,
    /// How the bearer token is delivered. We only accept the
    /// `Authorization: Bearer` header — never the query or form-body forms.
    /// RFC 9728 §2 values: `header` / `body` / `query`.
    pub bearer_methods_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    /// Build the document from an [`AuthConfig`]. The full W159 scope
    /// vocabulary is published — clients can intersect with their own
    /// supported list rather than learning it.
    pub fn from_config(config: &AuthConfig) -> Self {
        Self {
            resource: config.expected_aud.trim_end_matches('/').to_string(),
            authorization_servers: vec![config
                .cheers_issuer
                .trim_end_matches('/')
                .to_string()],
            scopes_supported: SCOPE_VOCABULARY.iter().map(|s| s.to_string()).collect(),
            bearer_methods_supported: vec!["header".to_string()],
        }
    }

    /// Same as [`Self::from_config`] but lets the caller restrict the
    /// published scope set — useful for a constable instance that has been
    /// configured to refuse specific scopes (e.g. an internal-only deploy
    /// that should not advertise `cloud:destroy`).
    pub fn from_config_with_scopes(
        config: &AuthConfig,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let mut meta = Self::from_config(config);
        meta.scopes_supported = scopes.into_iter().map(Into::into).collect();
        meta
    }

    /// Serialize as compact JSON — what the HTTPS endpoint will return.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("ProtectedResourceMetadata always serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_publishes_full_vocabulary() {
        let cfg = AuthConfig::new("https://cheers.example", "https://constable.example");
        let meta = ProtectedResourceMetadata::from_config(&cfg);
        assert_eq!(meta.resource, "https://constable.example");
        assert_eq!(
            meta.authorization_servers,
            vec!["https://cheers.example".to_string()]
        );
        assert_eq!(meta.bearer_methods_supported, vec!["header".to_string()]);
        assert_eq!(meta.scopes_supported.len(), SCOPE_VOCABULARY.len());
        for expected in SCOPE_VOCABULARY {
            assert!(
                meta.scopes_supported.iter().any(|s| s == expected),
                "missing scope {expected}"
            );
        }
    }

    #[test]
    fn trims_trailing_slashes() {
        let cfg = AuthConfig::new("https://cheers.example/", "https://constable.example/");
        let meta = ProtectedResourceMetadata::from_config(&cfg);
        assert_eq!(meta.resource, "https://constable.example");
        assert_eq!(meta.authorization_servers[0], "https://cheers.example");
    }

    #[test]
    fn from_config_with_scopes_overrides_vocabulary() {
        let cfg = AuthConfig::new("https://cheers.example", "https://constable.example");
        let meta = ProtectedResourceMetadata::from_config_with_scopes(
            &cfg,
            ["cloud:read", "cloud:deploy"],
        );
        assert_eq!(
            meta.scopes_supported,
            vec!["cloud:read".to_string(), "cloud:deploy".to_string()]
        );
    }

    #[test]
    fn json_round_trip_preserves_shape() {
        let cfg = AuthConfig::new("https://cheers.example", "https://constable.example");
        let meta = ProtectedResourceMetadata::from_config(&cfg);
        let json = meta.to_json();
        let parsed: ProtectedResourceMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, meta);
    }

    #[test]
    fn rfc_9728_required_fields_present() {
        let cfg = AuthConfig::new("https://cheers.example", "https://constable.example");
        let json = ProtectedResourceMetadata::from_config(&cfg).to_json();
        // The keys clients depend on for the W159 discovery hop. The exact
        // strings — not just the parsed presence — matter because they show
        // up in operator-facing debug output.
        for required in [
            "\"resource\":",
            "\"authorization_servers\":",
            "\"scopes_supported\":",
            "\"bearer_methods_supported\":",
        ] {
            assert!(json.contains(required), "missing field {required} in {json}");
        }
    }

    #[test]
    fn service_only_scopes_advertised() {
        // W159: `scopes_supported` advertises every scope the resource
        // accepts. Service principals (warden) carry `ownership:write`;
        // constable's own forwarder carries `audit:write`. Both are
        // wire-acceptable even though cheers refuses to grant them to user
        // principals at the AS UI.
        assert!(SCOPE_VOCABULARY.contains(&"ownership:write"));
        assert!(SCOPE_VOCABULARY.contains(&"audit:write"));
    }
}
