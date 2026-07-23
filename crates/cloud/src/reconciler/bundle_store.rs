//! R2 publish of a W272 mesofact **bundle** — the append-only, content-addressed
//! release store.
//!
//! Part of R599-F1 — the canonical ticket annotation lives on the
//! `yah-mesofact-bundle` crate (`oss/yah-base/crates/mesofact-bundle/src/lib.rs`),
//! which owns the format + the store surface. This module is the thin cloud-side
//! adapter: construct an [`R2ObjectStore`] from the mirror's S3 credentials and
//! drive [`yah_mesofact_bundle::publish_bundle`] on a blocking worker (the store
//! holds a `reqwest::blocking::Client`, so it must be built, used, and dropped
//! off the async runtime — same discipline as [`super::r2_publish::publish_to_r2`]).
//!
//! The services-tab sync arm that assembles a bundle and calls this on a
//! mesofact-component sync is R599-F8; the kamaji node-side materialize of a
//! published digest is R599-F4. This module only owns the publish leg.

use std::path::Path;

use anyhow::{Context, Result};
use yah_mesofact_bundle::publish_bundle;
use yah_object_store::R2ObjectStore;

pub use yah_mesofact_bundle::PublishReport;

/// Publish the assembled bundle tree at `bundle_dir` to the given R2 account +
/// bucket, returning the [`PublishReport`] (digest + which blobs were uploaded
/// vs deduped).
///
/// Credentials are the R2 S3 access key + secret (distinct from the Cloudflare
/// API token), same slots [`super::r2_publish`] documents. Blobs already present
/// in the bucket are skipped — the bundle store is append-only, so re-publishing
/// an unchanged app is cheap and idempotent.
pub async fn publish_bundle_to_r2(
    bundle_dir: &Path,
    account_id: &str,
    bucket: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<PublishReport> {
    let bundle_dir = bundle_dir.to_path_buf();
    let account_id = account_id.to_string();
    let bucket = bucket.to_string();
    let access_key = access_key.to_string();
    let secret_key = secret_key.to_string();

    // Build + use + drop the blocking-reqwest store entirely on the worker
    // thread — constructing it inside a tokio context panics.
    tokio::task::spawn_blocking(move || -> Result<PublishReport> {
        let store = R2ObjectStore::new(account_id, bucket, access_key, secret_key)
            .context("building R2ObjectStore for bundle publish")?;
        let report = publish_bundle(&store, &bundle_dir)
            .with_context(|| format!("publishing bundle from {}", bundle_dir.display()))?;
        Ok(report)
    })
    .await
    .context("bundle publish task panicked")?
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use tempfile::TempDir;
    use yah_mesofact_bundle::{
        publish_bundle, BundleHash, BundleManifest, BundleRuntime, SCHEMA_VERSION,
    };
    use yah_object_store::InMemoryObjectStore;

    /// Proves cloud can drive the crate's publish surface end-to-end against the
    /// in-memory store — the R2 wrapper above is the same call with a live store.
    #[test]
    fn cloud_can_publish_a_bundle_through_the_crate_surface() {
        let store = InMemoryObjectStore::new();
        let src = TempDir::new().unwrap();
        fs::create_dir_all(src.path().join("app")).unwrap();
        fs::write(src.path().join("app/index.html"), b"<html>").unwrap();

        let mut content = BTreeMap::new();
        content.insert("app/index.html".to_string(), BundleHash::of(b"<html>"));
        let manifest = BundleManifest {
            schema_version: SCHEMA_VERSION,
            name: "yah-marketing".to_string(),
            runtime: BundleRuntime::Mesofact { version: "0.8.18".into() },
            content,
        };
        fs::write(
            src.path().join("manifest.toml"),
            manifest.to_toml_string().unwrap(),
        )
        .unwrap();

        let report = publish_bundle(&store, src.path()).unwrap();
        assert_eq!(report.digest, manifest.digest());
        assert_eq!(report.uploaded.len(), 1);
        assert!(report.manifest_uploaded);
    }
}
