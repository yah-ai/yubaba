//! The R2 buckets a camp declares, gathered from every place the config tree
//! can name one.
//!
//! The Data tab's bucket picker used to read only `services/*/mirrors/*.toml`
//! slots, and only those whose `use =` equalled the id of the *first*
//! Cloudflare-kind provider found. A camp with two Cloudflare provider files
//! (noisetable: `cloudflare-tunnel-staging` sorts ahead of `cloudflare`) matched
//! nothing and showed an empty tab; a bucket no mirror names (a release bucket
//! written only by publish scripts) could never appear at all.
//!
//! One pure function over a loaded [`CloudConfig`], so the rule has one owner
//! and a unit test, instead of living inside a Tauri command.
//!
//! A bucket is declared by any of:
//! - a mirror slot (`[providers.<slot>] use = "<cf id>" bucket = "…"`, or an
//!   inline `kind = "cloudflare"` slot) — [`BucketSource::Mirror`];
//! - a domain manifest: `cdn_bucket`, or a `bucket = "…"` route —
//!   [`BucketSource::Domain`];
//! - a Cloudflare provider file: a `[[r2_bucket]]` credential row, or the
//!   names-only inventory `buckets = ["…"]` for a bucket nothing else
//!   declares — [`BucketSource::Provider`].

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::config::{CloudConfig, MirrorProviderSlot, Provider, RouteMode};

/// Which kind of declaration named a bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BucketSource {
    Mirror,
    Domain,
    Provider,
}

/// One declaration that names a bucket. `owner` is the service (mirror), the
/// domain name (domain) or the provider id (provider); `detail` is the
/// env/slot, the field that named it, or the provider field respectively.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketRef {
    pub source: BucketSource,
    pub owner: String,
    pub detail: String,
}

/// A bucket, deduped by name, with every declaration that names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeclaredBucket {
    pub name: String,
    /// Id of the Cloudflare provider the bucket is attributed to: the one a
    /// mirror slot references, else the account's primary provider.
    pub provider: String,
    pub refs: Vec<BucketRef>,
}

/// The catalog: the Cloudflare account the buckets live in and the buckets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketCatalog {
    /// First Cloudflare provider's `account_id`, in provider-id order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    pub buckets: Vec<DeclaredBucket>,
}

/// Every bucket `cfg` declares. Never fails: a declaration that is not a
/// string is skipped, and a camp with no Cloudflare provider yields only the
/// inline-kind and domain declarations.
pub fn declared_buckets(cfg: &CloudConfig) -> BucketCatalog {
    let cf: Vec<_> = cfg
        .providers
        .iter()
        .filter(|p| p.kind == Provider::Cloudflare)
        .collect();
    let cf_ids: BTreeSet<&str> = cf.iter().map(|p| p.id.as_str()).collect();
    // Providers load sorted by filename, so which Cloudflare file is "first"
    // is an accident of spelling. Prefer a stable pick: the one that carries an
    // account_id, ties broken by id.
    let primary = cf
        .iter()
        .filter(|p| p.fields.get("account_id").and_then(|v| v.as_str()).is_some())
        .min_by(|a, b| a.id.cmp(&b.id))
        .or_else(|| cf.iter().min_by(|a, b| a.id.cmp(&b.id)));
    let account_id = primary
        .and_then(|p| p.fields.get("account_id"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let primary_id = primary.map(|p| p.id.clone()).unwrap_or_default();

    let mut by_name: BTreeMap<String, DeclaredBucket> = BTreeMap::new();
    let mut add = |name: &str, provider: &str, r: BucketRef| {
        if name.is_empty() {
            return;
        }
        let e = by_name
            .entry(name.to_owned())
            .or_insert_with(|| DeclaredBucket {
                name: name.to_owned(),
                provider: provider.to_owned(),
                refs: Vec::new(),
            });
        if !e.refs.contains(&r) {
            e.refs.push(r);
        }
    };

    for (svc, s) in &cfg.services {
        for (env, mirror) in &s.mirrors {
            for (slot, body) in &mirror.providers {
                let pid = match body {
                    MirrorProviderSlot::Reference { provider_id, .. }
                        if cf_ids.contains(provider_id.as_str()) =>
                    {
                        provider_id.as_str()
                    }
                    MirrorProviderSlot::Inline { kind, .. } if *kind == Provider::Cloudflare => {
                        primary_id.as_str()
                    }
                    _ => continue,
                };
                if let Some(b) = body.fields().get("bucket").and_then(|v| v.as_str()) {
                    add(
                        b,
                        pid,
                        BucketRef {
                            source: BucketSource::Mirror,
                            owner: svc.clone(),
                            detail: format!("{env}/{slot}"),
                        },
                    );
                }
            }
        }
    }

    for (name, d) in &cfg.domains {
        let domain_ref = |detail: &str| BucketRef {
            source: BucketSource::Domain,
            owner: name.clone(),
            detail: detail.to_owned(),
        };
        add(&d.cdn_bucket, &primary_id, domain_ref("cdn_bucket"));
        for route in &d.routes {
            if let RouteMode::StaticBucket { bucket } = &route.mode {
                add(bucket, &primary_id, domain_ref(&format!("route {}", route.path)));
            }
        }
    }

    for p in &cf {
        let provider_ref = |detail: &str| BucketRef {
            source: BucketSource::Provider,
            owner: p.id.clone(),
            detail: detail.to_owned(),
        };
        if let Some(rows) = p.fields.get("r2_bucket").and_then(|v| v.as_array()) {
            for n in rows.iter().filter_map(|r| r.get("name")?.as_str()) {
                add(n, &p.id, provider_ref("r2_bucket"));
            }
        }
        if let Some(names) = p.fields.get("buckets").and_then(|v| v.as_array()) {
            for n in names.iter().filter_map(|v| v.as_str()) {
                add(n, &p.id, provider_ref("buckets"));
            }
        }
    }

    BucketCatalog {
        account_id,
        buckets: by_name.into_values().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(root: &std::path::Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    /// The noisetable shape: two Cloudflare provider files, the one that sorts
    /// first is NOT the one mirrors reference, plus buckets declared only by a
    /// domain, an `[[r2_bucket]]` row and the `buckets` inventory.
    #[test]
    fn collects_every_declaration_site_with_two_cloudflare_providers() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        write(
            r,
            ".yah/infra/providers/cloudflare-tunnel-staging.toml",
            "schema_version = 1\nid = \"cloudflare-tunnel-staging\"\nkind = \"cloudflare\"\n",
        );
        write(
            r,
            ".yah/infra/providers/cloudflare.toml",
            "schema_version = 1\nid = \"cloudflare\"\nkind = \"cloudflare\"\n\
             account_id = \"acct\"\nbuckets = [\"app-releases\"]\n\
             [[r2_bucket]]\nname = \"app-backup\"\naccess_key = \"keystore://a\"\nsecret_key = \"keystore://b\"\n",
        );
        write(
            r,
            ".yah/domains/cdn-app.toml",
            "schema_version = 1\nname = \"cdn-app\"\ndomain = \"cdn.app.test\"\n\
             front_door = \"bucket-direct\"\ncdn_bucket = \"app-marketing\"\n",
        );
        write(
            r,
            ".yah/services/web/service.toml",
            "schema_version = 1\nname = \"web\"\n[address]\nkind = \"front-door\"\ndomain = \"cdn.app.test\"\n",
        );
        write(
            r,
            ".yah/services/web/mirrors/prod.toml",
            "schema_version = 1\nshape = \"single-machine\"\n\
             [providers.bundle]\nuse = \"cloudflare\"\nbucket = \"app-marketing\"\n",
        );

        let cfg = CloudConfig::load(r).unwrap();
        let cat = declared_buckets(&cfg);
        assert_eq!(cat.account_id.as_deref(), Some("acct"));
        let names: Vec<_> = cat.buckets.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["app-backup", "app-marketing", "app-releases"]);
        let marketing = &cat.buckets[1];
        assert_eq!(marketing.refs.len(), 2, "mirror + domain, deduped by name");
        assert_eq!(marketing.provider, "cloudflare");
    }
}
