//! Per-tenant config from `.yah/services/<svc>/tenants/<id>.toml` (R330-F12).
//!
//! A *tenant* is a distinct surface hosted by a multi-tenant service (today:
//! `yah-cloud`'s `mesofact-runner`). Each tenant file binds the tenant's almanac
//! feeds to two things the runner needs but the feed definition itself does not
//! carry:
//!
//!   1. **identity** — a per-`(tenant, env)` `mirror_key` the almanac receiver
//!      checks on `/revalidate` (R335-F2 shape). Keystore-ref only; never a
//!      literal secret in git. Swapped for a yubaba node-identity capability
//!      (R335-F5) once xlb-net is buildable — the on-wire `{feed, mirror_key}`
//!      request shape is frozen until then so the swap doesn't break callers.
//!
//!   2. **output destination** — where each feed's artifact lands. The crux of
//!      F12 (and its lead gotcha): output goes to the *tenant's* storage, not the
//!      runner's. The runner writes into the tenant's bucket via the named
//!      provider's scoped creds.
//!
//! The feed *definition* (source/trigger/emit) still lives in a `FeedConfig`
//! under `.yah/almanac/<feed>.toml`, shared with the local single-tenant path
//! ([`crate::almanac_dispatch`] / the `almanac` crate). A [`TenantFeed`] only
//! *references* a feed by name and rebinds its emit target — it never redeclares
//! the feed's source.
//!
//! ## Layering
//!
//! This type lives in `cloud` (not `almanac`) because it sits at the
//! service-deployment layer alongside [`crate::config::MirrorConfig`]: it names
//! providers, is env-scoped, and is emitted into `.yah/schema/` by the same
//! `xtask emit-schemas` pipeline. The almanac serve loop consumes a *resolved*
//! view (feed name → output sink + the active env's key); building that resolved
//! view is the runner-workload's job (R330-F11) and is intentionally not done
//! here — this module is parse + validate + expose only.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

fn default_schema_version() -> u32 {
    1
}

/// Error from loading or validating a single tenant TOML file.
#[derive(Debug, Error)]
pub enum TenantError {
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Toml {
        path: String,
        source: toml::de::Error,
    },
    /// The `id` field disagrees with the filename stem. The filename is a
    /// convention (`<id>.toml`); a mismatch almost always means a copy-paste
    /// slip, so we fail loud rather than silently key the tenant by `id` and
    /// leave the file misnamed.
    #[error("tenant id {id:?} does not match filename stem {stem:?} in {path}")]
    IdMismatch {
        path: String,
        id: String,
        stem: String,
    },
}

/// Top-level shape of `.yah/services/<svc>/tenants/<id>.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct TenantConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Tenant id. Authoritative; the filename (`<id>.toml`) must agree
    /// (enforced by [`load_tenants`]).
    pub id: String,
    /// Identity binding the receiver checks on `/revalidate`.
    #[serde(default)]
    pub binding: TenantBinding,
    /// Feeds this tenant runs on the runner.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub feeds: Vec<TenantFeed>,
}

/// Per-`(tenant, env)` revalidate identity (R335-F2 `mirror_key` shape).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct TenantBinding {
    /// `env` → revalidate bearer reference, e.g.
    /// `cloud = "keystore://yah-cloud/tenants/yah-marketing/cloud"`.
    ///
    /// The value is a keystore reference resolved at load time by the runner,
    /// **never** a literal secret committed to git. The receiver compares the
    /// resolved value against the `mirror_key` field of an incoming
    /// `/revalidate` body. An env absent from this map has no configured key →
    /// the runner must treat `/revalidate` for that env as unauthenticated
    /// (reject) rather than open.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mirror_key: BTreeMap<String, String>,
}

/// One feed this tenant runs, plus where its artifact is written.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct TenantFeed {
    /// Names a `FeedConfig` under `.yah/almanac/<feed>.toml`. The feed's
    /// `source`/`trigger`/`emit` definition is shared with the local
    /// single-tenant path; this reference never redeclares it.
    pub feed: String,
    /// Where the feed's artifact lands — in the *tenant's* storage.
    pub output: TenantOutput,
}

/// Output destination for a tenant feed — the tenant's own bucket, written via
/// the named provider's scoped creds (the lead gotcha of F12: output is the
/// tenant's storage, not the runner's).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct TenantOutput {
    /// Provider id under `.yah/infra/providers/<id>.toml` whose credentials
    /// scope the write. **First-tenant case:** `yah-cloud` reuses the
    /// `cloudflare` provider because we own both the runner and
    /// `yah-marketing`'s bucket; a multi-tenant deployment needs a per-tenant
    /// cred slot scoped to only that tenant's bucket (tracked on F12's gotcha).
    pub provider: String,
    /// Bucket name in the provider (e.g. the tenant's R2 bucket).
    pub bucket: String,
    /// Object key the artifact is written to, e.g. `"data/releases.json"`.
    pub key: String,
}

impl TenantConfig {
    /// Parse a single `tenants/<id>.toml` file. Does **not** check the
    /// id/filename invariant — use [`load_tenants`] for that, or call
    /// [`TenantConfig::validate_stem`] yourself.
    pub fn load(path: &Path) -> Result<Self, TenantError> {
        let src = std::fs::read_to_string(path).map_err(|source| TenantError::Io {
            path: path.display().to_string(),
            source,
        })?;
        toml::from_str(&src).map_err(|source| TenantError::Toml {
            path: path.display().to_string(),
            source,
        })
    }

    /// The revalidate bearer reference for `env`, if one is configured.
    pub fn mirror_key_for(&self, env: &str) -> Option<&str> {
        self.binding.mirror_key.get(env).map(String::as_str)
    }

    /// Assert the `id` field agrees with the file's stem (`<id>.toml`).
    fn validate_stem(&self, path: &Path) -> Result<(), TenantError> {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if stem != self.id {
            return Err(TenantError::IdMismatch {
                path: path.display().to_string(),
                id: self.id.clone(),
                stem: stem.to_string(),
            });
        }
        Ok(())
    }
}

/// Load every `*.toml` under a service's `tenants/` directory, keyed by tenant
/// `id`. A missing directory is "no tenants" — returns an empty map, not an
/// error (a service may legitimately have none yet). Non-`.toml` entries and
/// subdirectories are skipped. Each file's `id` must match its filename stem.
pub fn load_tenants(dir: &Path) -> Result<BTreeMap<String, TenantConfig>, TenantError> {
    let mut out = BTreeMap::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(source) => {
            return Err(TenantError::Io {
                path: dir.display().to_string(),
                source,
            })
        }
    };
    // Collect + sort so the load order is deterministic regardless of the
    // filesystem's directory iteration order.
    let mut paths: Vec<_> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| TenantError::Io {
            path: dir.display().to_string(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            paths.push(path);
        }
    }
    paths.sort();
    for path in paths {
        let cfg = TenantConfig::load(&path)?;
        cfg.validate_stem(&path)?;
        out.insert(cfg.id.clone(), cfg);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const YAH_MARKETING: &str = r#"
schema_version = 1
id = "yah-marketing"

[binding]
mirror_key = { cloud = "keystore://yah-cloud/tenants/yah-marketing/cloud" }

[[feeds]]
feed = "releases"

[feeds.output]
provider = "cloudflare"
bucket = "yah-marketing-cloud"
key = "data/releases.json"
"#;

    fn write(dir: &Path, name: &str, body: &str) {
        fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn parses_first_tenant_shape() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "yah-marketing.toml", YAH_MARKETING);
        let cfg = TenantConfig::load(&tmp.path().join("yah-marketing.toml")).unwrap();

        assert_eq!(cfg.id, "yah-marketing");
        assert_eq!(cfg.schema_version, 1);
        assert_eq!(
            cfg.mirror_key_for("cloud"),
            Some("keystore://yah-cloud/tenants/yah-marketing/cloud")
        );
        assert_eq!(cfg.mirror_key_for("dev"), None);

        assert_eq!(cfg.feeds.len(), 1);
        let feed = &cfg.feeds[0];
        assert_eq!(feed.feed, "releases");
        assert_eq!(feed.output.provider, "cloudflare");
        assert_eq!(feed.output.bucket, "yah-marketing-cloud");
        assert_eq!(feed.output.key, "data/releases.json");
    }

    #[test]
    fn schema_version_defaults_to_one() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "t.toml", "id = \"t\"\n");
        let cfg = TenantConfig::load(&tmp.path().join("t.toml")).unwrap();
        assert_eq!(cfg.schema_version, 1);
        assert!(cfg.feeds.is_empty());
        assert!(cfg.binding.mirror_key.is_empty());
    }

    #[test]
    fn load_tenants_keys_by_id_in_sorted_order() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "yah-marketing.toml", YAH_MARKETING);
        write(tmp.path(), "acme.toml", "id = \"acme\"\n");
        // Non-toml + subdir are ignored.
        write(tmp.path(), "README.md", "not a tenant\n");
        fs::create_dir(tmp.path().join("nested")).unwrap();

        let tenants = load_tenants(tmp.path()).unwrap();
        assert_eq!(
            tenants.keys().cloned().collect::<Vec<_>>(),
            vec!["acme".to_string(), "yah-marketing".to_string()]
        );
    }

    #[test]
    fn missing_dir_is_empty_not_error() {
        let tmp = TempDir::new().unwrap();
        let tenants = load_tenants(&tmp.path().join("does-not-exist")).unwrap();
        assert!(tenants.is_empty());
    }

    #[test]
    fn id_filename_mismatch_fails_loud() {
        let tmp = TempDir::new().unwrap();
        // id says "yah-marketing" but file is named "wrong.toml".
        write(tmp.path(), "wrong.toml", YAH_MARKETING);
        let err = load_tenants(tmp.path()).unwrap_err();
        assert!(
            matches!(err, TenantError::IdMismatch { .. }),
            "expected IdMismatch, got {err:?}"
        );
    }
}
