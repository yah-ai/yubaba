//! Centralized Cloudflare credential resolution.
//!
//! Before this module, every Cloudflare reconciler hardcoded two things:
//! the provider file path (`.yah/infra/providers/cloudflare.toml`) and the
//! global keystore slots (`cloudflare-api-token`, plus the R2 S3 keys). That
//! forced one account / one key across the whole workspace — two services
//! could not target different Cloudflare accounts (e.g. `yah.dev` vs a
//! `scrabcake` account), and a single over-broad token was shared by all.
//!
//! [`CfProvider`] resolves credentials from the mirror slot's `use = "<id>"`
//! provider instead. Each service's mirror names its provider; the provider
//! file (`.yah/infra/providers/<id>.toml`) declares its own `account_id` and
//! credential references. The credential fields are `keystore://<slot>` URIs:
//!
//! ```toml
//! id            = "cloudflare-yah"
//! kind          = "cloudflare"
//! account_id    = "…"
//! default_zone  = "yah.dev"
//! credentials   = "keystore://cloudflare-api-token"      # management API token
//! r2_access_key = "keystore://cloudflare-r2-access-key-id"  # optional S3 override
//! r2_secret_key = "keystore://cloudflare-r2-secret-key"     # optional S3 override
//! ```
//!
//! A provider that omits a credential field falls back to the historical
//! global slot, so today's single-provider setup keeps working unchanged —
//! the only required migration is pointing `credentials` at a real slot name.
//!
//! NB isolation caveat: separate *tokens* only give hard isolation across
//! separate Cloudflare *accounts*. Account-scoped grants (Workers Scripts,
//! R2) are account-wide, so two providers sharing one `account_id` are not
//! isolated at the worker/bucket layer regardless of which slot they name.

use std::path::Path;

use anyhow::{Context, Result};
use workload_spec::{NamespaceId, TenantId};

use crate::config::ProviderConfig;

/// Global fallback slot/env for the management API token when a provider
/// file omits `credentials`. Preserves pre-multi-provider behavior.
const DEFAULT_API_TOKEN_SLOT: &str = "cloudflare-api-token";
const DEFAULT_API_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";

/// Read `[namespaces.<namespace>].<field>` from a provider file, but only when a
/// non-singleton namespace is active (W206 per-namespace override). Returns
/// `None` for the singleton namespace or when the section/field is absent, so
/// single-namespace deployments never touch the `[namespaces]` table.
fn ns_override_in<'a>(
    cfg: &'a ProviderConfig,
    namespace: &NamespaceId,
    field: &str,
) -> Option<&'a str> {
    if namespace.is_singleton() {
        return None;
    }
    cfg.fields
        .get("namespaces")
        .and_then(|n| n.get(namespace.0.as_str()))
        .and_then(|t| t.get(field))
        .and_then(|v| v.as_str())
}

/// A resolved Cloudflare provider: its parsed config file, the resolved
/// `account_id`, and the `(tenant, namespace)` scope it was resolved for.
/// Accessors prefer a `[namespaces.<ns>]` override over the top-level field and
/// derive `(tenant, namespace, provider)`-scoped keystore slots when the
/// provider file leaves a credential unset (W206).
#[derive(Debug)]
pub(crate) struct CfProvider {
    pub cfg: ProviderConfig,
    pub account_id: String,
    provider_id: String,
    tenant: TenantId,
    namespace: NamespaceId,
}

impl CfProvider {
    /// Load `.yah/infra/providers/<provider_id>.toml` for the singleton
    /// `(tenant, namespace)` scope — the pre-W206 behavior. Callers that know
    /// the workload's namespace should use [`CfProvider::resolve_scoped`].
    pub fn resolve(workspace_root: &Path, provider_id: &str) -> Result<Self> {
        Self::resolve_scoped(
            workspace_root,
            provider_id,
            &TenantId::singleton(),
            &NamespaceId::singleton(),
        )
    }

    /// Load `.yah/infra/providers/<provider_id>.toml` and resolve `account_id`
    /// for a specific `(tenant, namespace)` scope. A `[namespaces.<namespace>]`
    /// section in the provider file overrides the top-level `account_id`, and
    /// [`CfProvider::zone`] / credential accessors resolve against the same
    /// scope. Fails before any network I/O so a misconfigured provider is caught
    /// at the top of a reconcile.
    pub fn resolve_scoped(
        workspace_root: &Path,
        provider_id: &str,
        tenant: &TenantId,
        namespace: &NamespaceId,
    ) -> Result<Self> {
        let path = workspace_root
            .join(".yah/infra/providers")
            .join(format!("{provider_id}.toml"));
        let cfg = ProviderConfig::load(&path).with_context(|| {
            format!(
                "loading Cloudflare provider `{provider_id}` — expected at {}",
                path.display()
            )
        })?;
        let account_id = ns_override_in(&cfg, namespace, "account_id")
            .or_else(|| cfg.fields.get("account_id").and_then(|v| v.as_str()))
            .with_context(|| {
                format!(
                    "provider `{provider_id}` ({}): missing `account_id` field — \
                     add your Cloudflare account ID (top-level or under \
                     [namespaces.{}])",
                    path.display(),
                    namespace.0,
                )
            })?
            .to_string();
        Ok(Self {
            cfg,
            account_id,
            provider_id: provider_id.to_string(),
            tenant: tenant.clone(),
            namespace: namespace.clone(),
        })
    }

    /// The Cloudflare zone this provider serves for the active namespace:
    /// `[namespaces.<ns>].zone` when set, else the top-level `default_zone`.
    /// `None` when neither is declared (e.g. an R2-only provider).
    ///
    // Consumed once the CF reconcilers become namespace-aware (the F5→T6
    // wiring); until then only the tests exercise it.
    #[allow(dead_code)]
    pub fn zone(&self) -> Option<String> {
        self.ns_override("zone")
            .or_else(|| self.cfg.fields.get("default_zone").and_then(|v| v.as_str()))
            .map(str::to_string)
    }

    /// Management API token — required. Reads the provider's
    /// `credentials = "keystore://<slot>"` when set, else the global default
    /// slot (`cloudflare-api-token` / `$CLOUDFLARE_API_TOKEN`).
    pub fn api_token(&self) -> Result<String> {
        let (slot, env) = self.api_token_slot()?;
        fob::get_or_env(&slot, &env)
            .with_context(|| {
                format!("resolving `{slot}` for provider `{}`", self.provider_id)
            })?
            .with_context(|| {
                format!("`{slot}` not found — `yah keys set {slot} <token>` or export {env}")
            })
    }

    /// Management API token if present, `None` otherwise — for paths where the
    /// token is optional (e.g. CDN cache purge is skipped when unset).
    pub fn api_token_opt(&self) -> Option<String> {
        let (slot, env) = self.api_token_slot().ok()?;
        fob::get_or_env(&slot, &env).ok().flatten()
    }

    /// R2 S3 data-plane keys `(access_key, secret_key)`. Provider fields
    /// `r2_access_key` / `r2_secret_key` override the global R2 slots when set.
    pub fn r2_keys(&self) -> Result<(String, String)> {
        use super::r2_publish::{
            R2_ACCESS_KEY_ENV, R2_ACCESS_KEY_SLOT, R2_SECRET_KEY_ENV, R2_SECRET_KEY_SLOT,
        };
        let (a_slot, a_env) =
            self.field_slot("r2_access_key", R2_ACCESS_KEY_SLOT, R2_ACCESS_KEY_ENV)?;
        let (s_slot, s_env) =
            self.field_slot("r2_secret_key", R2_SECRET_KEY_SLOT, R2_SECRET_KEY_ENV)?;
        let access = fob::get_or_env(&a_slot, &a_env)
            .with_context(|| format!("resolving R2 access key `{a_slot}`"))?
            .with_context(|| {
                format!("R2 access key `{a_slot}` not found — `yah keys set {a_slot}` or export {a_env}")
            })?;
        let secret = fob::get_or_env(&s_slot, &s_env)
            .with_context(|| format!("resolving R2 secret key `{s_slot}`"))?
            .with_context(|| {
                format!("R2 secret key `{s_slot}` not found — `yah keys set {s_slot}` or export {s_env}")
            })?;
        Ok((access, secret))
    }

    /// Resolve the management-token slot/env. Precedence: a
    /// `[namespaces.<ns>].credentials` override, then the top-level typed
    /// `credentials` field, then a scope-derived default slot.
    fn api_token_slot(&self) -> Result<(String, String)> {
        match self
            .ns_override("credentials")
            .map(str::to_string)
            .or_else(|| self.cfg.credentials.clone())
        {
            Some(uri) => self.parse_uri("credentials", &uri),
            None => Ok(self.default_slot(DEFAULT_API_TOKEN_SLOT, DEFAULT_API_TOKEN_ENV)),
        }
    }

    /// Resolve a flattened credential field (e.g. `r2_access_key`) to slot/env.
    /// Precedence: a `[namespaces.<ns>].<field>` override, then the top-level
    /// `<field>`, then the scope-derived default slot.
    fn field_slot(
        &self,
        field: &str,
        default_slot: &str,
        default_env: &str,
    ) -> Result<(String, String)> {
        match self
            .ns_override(field)
            .or_else(|| self.cfg.fields.get(field).and_then(|v| v.as_str()))
        {
            Some(uri) => self.parse_uri(field, uri),
            None => Ok(self.default_slot(default_slot, default_env)),
        }
    }

    /// Read `[namespaces.<active-ns>].<field>` for this provider's scope.
    fn ns_override(&self, field: &str) -> Option<&str> {
        ns_override_in(&self.cfg, &self.namespace, field)
    }

    /// Derive the default keystore slot/env for a credential family when the
    /// provider file leaves it unset. The singleton scope keeps the historical
    /// global slot (pre-W206 back-compat); a non-singleton `(tenant, namespace)`
    /// prefixes the scope onto the slot so co-resident namespaces don't share
    /// one over-broad key — the "keystore keyed by (tenant, namespace,
    /// provider)" rule from W206 (the provider is already baked into the global
    /// slot name, e.g. `cloudflare-api-token`).
    fn default_slot(&self, global_slot: &str, global_env: &str) -> (String, String) {
        let mut parts = vec![];
        if !self.tenant.is_singleton() {
            parts.push(self.tenant.0.as_str());
        }
        if !self.namespace.is_singleton() {
            parts.push(self.namespace.0.as_str());
        }
        if parts.is_empty() {
            return (global_slot.to_string(), global_env.to_string());
        }
        let slot = format!("{}-{global_slot}", parts.join("-"));
        let env = slot.to_uppercase().replace('-', "_");
        (slot, env)
    }

    /// Parse a `keystore://<slot>` credential URI into `(slot, ENV_VAR)`,
    /// deriving the SCREAMING_SNAKE env fallback from the slot name.
    fn parse_uri(&self, field: &str, uri: &str) -> Result<(String, String)> {
        let slot = uri.strip_prefix("keystore://").with_context(|| {
            format!(
                "provider `{}` field `{field}` = {uri:?} must be a `keystore://<slot>` URI",
                self.provider_id
            )
        })?;
        anyhow::ensure!(
            !slot.is_empty() && !slot.contains('/'),
            "provider `{}` field `{field}` = {uri:?} — slot must be a flat kebab-case name \
             (e.g. `keystore://cloudflare-api-token`)",
            self.provider_id
        );
        let env = slot.to_uppercase().replace('-', "_");
        Ok((slot.to_string(), env))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn write_provider(root: &Path, id: &str, body: &str) {
        let dir = root.join(".yah/infra/providers");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{id}.toml")), body).unwrap();
    }

    #[test]
    fn resolves_account_id_and_defaults_to_global_slots() {
        let tmp = tempdir().unwrap();
        write_provider(
            tmp.path(),
            "cloudflare",
            "schema_version = 1\nid = \"cloudflare\"\nkind = \"cloudflare\"\naccount_id = \"acct-123\"\ndefault_zone = \"yah.dev\"\n",
        );
        let p = CfProvider::resolve(tmp.path(), "cloudflare").unwrap();
        assert_eq!(p.account_id, "acct-123");
        assert_eq!(p.provider_id, "cloudflare");
        // No `credentials` field → falls back to the global default slot/env.
        assert_eq!(
            p.api_token_slot().unwrap(),
            ("cloudflare-api-token".to_string(), "CLOUDFLARE_API_TOKEN".to_string())
        );
    }

    #[test]
    fn honors_per_provider_credential_slots() {
        let tmp = tempdir().unwrap();
        write_provider(
            tmp.path(),
            "cloudflare-scrabcake",
            "schema_version = 1\nid = \"cloudflare-scrabcake\"\nkind = \"cloudflare\"\naccount_id = \"acct-scrab\"\ncredentials = \"keystore://cf-token-scrabcake\"\nr2_access_key = \"keystore://scrab-r2-access\"\n",
        );
        let p = CfProvider::resolve(tmp.path(), "cloudflare-scrabcake").unwrap();
        assert_eq!(
            p.api_token_slot().unwrap(),
            ("cf-token-scrabcake".to_string(), "CF_TOKEN_SCRABCAKE".to_string())
        );
        // Declared r2_access_key overrides; r2_secret_key falls back to global.
        let (a_slot, a_env) = p
            .field_slot("r2_access_key", "default-access", "DEFAULT_ACCESS")
            .unwrap();
        assert_eq!((a_slot.as_str(), a_env.as_str()), ("scrab-r2-access", "SCRAB_R2_ACCESS"));
        let (s_slot, _) = p
            .field_slot("r2_secret_key", "default-secret", "DEFAULT_SECRET")
            .unwrap();
        assert_eq!(s_slot, "default-secret");
    }

    #[test]
    fn rejects_non_keystore_uri() {
        let tmp = tempdir().unwrap();
        write_provider(
            tmp.path(),
            "bad",
            "schema_version = 1\nid = \"bad\"\nkind = \"cloudflare\"\naccount_id = \"a\"\ncredentials = \"cf-token\"\n",
        );
        let p = CfProvider::resolve(tmp.path(), "bad").unwrap();
        let err = p.api_token_slot().unwrap_err().to_string();
        assert!(err.contains("keystore://"), "got: {err}");
    }

    #[test]
    fn rejects_slot_with_slash() {
        let tmp = tempdir().unwrap();
        write_provider(
            tmp.path(),
            "slashy",
            "schema_version = 1\nid = \"slashy\"\nkind = \"cloudflare\"\naccount_id = \"a\"\ncredentials = \"keystore://cloudflare/yah\"\n",
        );
        let p = CfProvider::resolve(tmp.path(), "slashy").unwrap();
        let err = p.api_token_slot().unwrap_err().to_string();
        assert!(err.contains("flat kebab-case"), "got: {err}");
    }

    #[test]
    fn missing_account_id_errors() {
        let tmp = tempdir().unwrap();
        write_provider(
            tmp.path(),
            "noacct",
            "schema_version = 1\nid = \"noacct\"\nkind = \"cloudflare\"\n",
        );
        let err = CfProvider::resolve(tmp.path(), "noacct").unwrap_err().to_string();
        assert!(err.contains("account_id"), "got: {err}");
        let _ = BTreeMap::<String, String>::new();
    }

    // ─── W206-F5: per-namespace provider config ──────────────────────────────

    /// A provider file with a top-level `yah.dev`/global-slot default plus a
    /// `[namespaces.noisetable]` override for a second zone/account/token.
    const MULTI_NS_PROVIDER: &str = "\
schema_version = 1
id = \"cloudflare\"
kind = \"cloudflare\"
account_id = \"acct-yah\"
default_zone = \"yah.dev\"

[namespaces.noisetable]
account_id = \"acct-nt\"
zone = \"noisetable.com\"
credentials = \"keystore://cf-token-noisetable\"
r2_access_key = \"keystore://nt-r2-access\"
";

    fn ns(s: &str) -> NamespaceId {
        NamespaceId(s.to_string())
    }

    #[test]
    fn singleton_scope_uses_top_level_and_global_slots() {
        let tmp = tempdir().unwrap();
        write_provider(tmp.path(), "cloudflare", MULTI_NS_PROVIDER);
        let p = CfProvider::resolve(tmp.path(), "cloudflare").unwrap();
        assert_eq!(p.account_id, "acct-yah");
        assert_eq!(p.zone().as_deref(), Some("yah.dev"));
        // No scope, no top-level credentials → historical global slot.
        assert_eq!(
            p.api_token_slot().unwrap(),
            ("cloudflare-api-token".to_string(), "CLOUDFLARE_API_TOKEN".to_string())
        );
    }

    #[test]
    fn namespace_section_overrides_account_zone_and_token() {
        let tmp = tempdir().unwrap();
        write_provider(tmp.path(), "cloudflare", MULTI_NS_PROVIDER);
        let p = CfProvider::resolve_scoped(
            tmp.path(),
            "cloudflare",
            &TenantId::singleton(),
            &ns("noisetable"),
        )
        .unwrap();
        assert_eq!(p.account_id, "acct-nt");
        assert_eq!(p.zone().as_deref(), Some("noisetable.com"));
        // Explicit per-namespace credentials win over any derived slot.
        assert_eq!(
            p.api_token_slot().unwrap(),
            ("cf-token-noisetable".to_string(), "CF_TOKEN_NOISETABLE".to_string())
        );
        // r2_access_key overridden in the ns section; r2_secret_key unset → the
        // scope-derived default slot (not the bare global).
        let (a_slot, _) = p
            .field_slot("r2_access_key", "global-r2-access", "GLOBAL_R2_ACCESS")
            .unwrap();
        assert_eq!(a_slot, "nt-r2-access");
        let (s_slot, s_env) = p
            .field_slot("r2_secret_key", "cloudflare-r2-secret-key", "CLOUDFLARE_R2_SECRET_KEY")
            .unwrap();
        assert_eq!(s_slot, "noisetable-cloudflare-r2-secret-key");
        assert_eq!(s_env, "NOISETABLE_CLOUDFLARE_R2_SECRET_KEY");
    }

    #[test]
    fn derived_slot_encodes_tenant_and_namespace() {
        let tmp = tempdir().unwrap();
        // No per-namespace credentials declared → the default must be scoped by
        // (tenant, namespace) so co-residents don't share one over-broad key.
        write_provider(
            tmp.path(),
            "cloudflare",
            "schema_version = 1\nid = \"cloudflare\"\nkind = \"cloudflare\"\naccount_id = \"a\"\n",
        );
        let p = CfProvider::resolve_scoped(
            tmp.path(),
            "cloudflare",
            &TenantId("ss".into()),
            &ns("noisetable"),
        )
        .unwrap();
        assert_eq!(
            p.api_token_slot().unwrap(),
            (
                "ss-noisetable-cloudflare-api-token".to_string(),
                "SS_NOISETABLE_CLOUDFLARE_API_TOKEN".to_string()
            )
        );
    }

    #[test]
    fn namespace_without_a_section_falls_back_to_top_level() {
        // A namespace with no [namespaces.<ns>] section resolves the top-level
        // account/zone but still gets a scope-derived credential slot.
        let tmp = tempdir().unwrap();
        write_provider(tmp.path(), "cloudflare", MULTI_NS_PROVIDER);
        let p = CfProvider::resolve_scoped(
            tmp.path(),
            "cloudflare",
            &TenantId::singleton(),
            &ns("other"),
        )
        .unwrap();
        // namespace "other" has no section → falls back to top-level.
        assert_eq!(p.account_id, "acct-yah");
        assert_eq!(p.zone().as_deref(), Some("yah.dev"));
        // Non-singleton namespace with no explicit creds → scoped default slot.
        assert_eq!(p.api_token_slot().unwrap().0, "other-cloudflare-api-token");
    }
}
