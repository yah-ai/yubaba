//! Prune verb for `kind = "static-asset"` components (R429-T3).
//!
//! Companion to [`StaticAssetReconciler`](super::static_asset::StaticAssetReconciler).
//! The reconciler is append-only: it never DELETEs from the bucket, only
//! reports drift. The prune verb is the explicit operator-driven removal step.
//!
//! ## Resolution graph
//!
//! For a given `(service, env)`:
//!
//! 1. Load the service's `MirrorConfig` for `env`. Confirm it has a
//!    `providers.object_store` slot — otherwise pruning is meaningless.
//! 2. Enumerate every `ServiceComponent` with `kind = "static-asset"` on the
//!    service. For each, parse its `workload.toml` catalog (the
//!    [`[[asset]]`](workload_spec::AssetEntry) rows).
//! 3. **Live set** = the union of `filename` values across all those catalogs.
//!    The `[aliases]` table in the catalog and the `[asset_aliases]` table on
//!    the mirror don't expand the live set — by the closed-catalog invariant
//!    every alias value must already be in `[[asset]]`, so they're already
//!    counted.
//! 4. **Prune candidates** = `(bucket-listing) \ live-set`. The
//!    `_yah-asset-catalog.json` sidecar that the reconciler writes is always
//!    excluded — it's bookkeeping, not user data.
//!
//! ## Safety
//!
//! - `dry_run` enumerates without deleting and is the default through the
//!    MCP read tool.
//! - The CLI prompts for confirmation unless `--yes` is passed.
//! - Auto-GC remains OFF: nothing in the reconciler ever calls into
//!    [`execute_prune`]. Only the explicit `yah cloud service prune` verb does.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::reconciler::pond::{DEFAULT_MINIO_API_PORT, DEFAULT_MINIO_PASSWORD, DEFAULT_MINIO_USER};
use crate::reconciler::static_asset::WORKLOAD_KIND;
use crate::{MirrorProviderSlot, Provider, ServiceConfig};

use local_driver::s3_sign::{sign_s3_empty_body, sign_s3_get_with_query};
use workload_spec::StaticAssetWorkload;

/// Sidecar key the reconciler writes — never a prune candidate.
const CATALOG_MANIFEST_KEY: &str = "_yah-asset-catalog.json";

/// S3 region for Cloudflare R2.
const R2_REGION: &str = "auto";
/// S3 region for MinIO (SigV4 requires non-empty).
const MINIO_REGION: &str = "us-east-1";

/// One file in the bucket the prune verb is offering to delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneCandidate {
    /// Object key in the bucket (e.g. `"whisper/distil-large-v3-q5_1.bin"`).
    pub filename: String,
    /// Size in bytes, as reported by `ListObjectsV2`.
    pub size: u64,
    /// `LastModified` from the bucket listing (ISO-8601 UTC).
    pub last_modified: String,
}

/// Outcome of a prune-candidate enumeration. Pure read; nothing deleted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PruneReport {
    /// Service the report was computed for.
    pub service: String,
    /// Mirror environment (e.g. `"pond"`, `"cloud"`).
    pub env: String,
    /// Bucket the report was computed against.
    pub bucket: String,
    /// Catalog filenames the prune verb refuses to remove (live set).
    /// Surfaced so the operator can sanity-check the resolution graph.
    pub live_set: Vec<String>,
    /// Files the operator could remove. Empty list = bucket is in sync.
    pub candidates: Vec<PruneCandidate>,
}

/// Outcome of an actual prune execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PruneOutcome {
    pub service: String,
    pub env: String,
    pub bucket: String,
    /// Filenames the verb attempted to DELETE.
    pub requested: Vec<String>,
    /// Filenames successfully removed.
    pub deleted: Vec<String>,
    /// Per-file errors keyed by filename. Empty when every DELETE succeeded.
    pub errors: Vec<(String, String)>,
}

// ── Public surface ────────────────────────────────────────────────────────────

/// Compute the live set + bucket listing + candidate diff for one mirror.
///
/// Pure read — no mutation. Returns a [`PruneReport`].
pub async fn compute_prune_candidates(
    workspace_root: &Path,
    service: &ServiceConfig,
    mirror: &crate::MirrorConfig,
    env: &str,
) -> Result<PruneReport> {
    let live_set = compute_live_set(workspace_root, service)?;
    let backend = resolve_backend(workspace_root, mirror, &service.name, env)?;
    let listing = list_bucket_objects(&backend).await?;

    let candidates: Vec<PruneCandidate> = listing
        .into_iter()
        .filter(|obj| obj.filename != CATALOG_MANIFEST_KEY)
        .filter(|obj| !live_set.contains(&obj.filename))
        .collect();

    Ok(PruneReport {
        service: service.name.clone(),
        env: env.to_string(),
        bucket: backend.bucket,
        live_set: live_set.into_iter().collect(),
        candidates,
    })
}

/// DELETE the named filenames from the mirror's bucket. The caller is
/// responsible for having confirmed the operation with the operator.
///
/// Refuses to DELETE the catalog manifest sidecar.
pub async fn execute_prune(
    workspace_root: &Path,
    service: &ServiceConfig,
    mirror: &crate::MirrorConfig,
    env: &str,
    filenames: &[String],
) -> Result<PruneOutcome> {
    let backend = resolve_backend(workspace_root, mirror, &service.name, env)?;
    let client = reqwest::Client::new();

    let mut outcome = PruneOutcome {
        service: service.name.clone(),
        env: env.to_string(),
        bucket: backend.bucket.clone(),
        requested: filenames.to_vec(),
        ..PruneOutcome::default()
    };

    for filename in filenames {
        if filename == CATALOG_MANIFEST_KEY {
            outcome.errors.push((
                filename.clone(),
                format!(
                    "refusing to delete catalog manifest sidecar `{CATALOG_MANIFEST_KEY}` — \
                     it's how the reconciler tracks prune candidates across runs"
                ),
            ));
            continue;
        }
        let url = format!(
            "{}/{}/{}",
            backend.endpoint.trim_end_matches('/'),
            backend.bucket,
            filename
        );
        match delete_object(&client, &url, &backend).await {
            Ok(()) => {
                info!(filename, bucket = %backend.bucket, "deleted");
                outcome.deleted.push(filename.clone());
            }
            Err(e) => {
                warn!(filename, error = %format!("{e:#}"), "delete failed");
                outcome.errors.push((filename.clone(), format!("{e:#}")));
            }
        }
    }

    Ok(outcome)
}

// ── Live-set resolution ───────────────────────────────────────────────────────

/// Walk the service's static-asset components and union their catalog
/// filenames. Pure: no I/O beyond reading `workload.toml` files.
pub fn compute_live_set(
    workspace_root: &Path,
    service: &ServiceConfig,
) -> Result<BTreeSet<String>> {
    let mut live = BTreeSet::new();
    for component in &service.components {
        if component.kind != WORKLOAD_KIND {
            continue;
        }
        let workload_path = workspace_root.join(&component.path).join("workload.toml");
        let workload = load_static_asset_workload(&workload_path).with_context(|| {
            format!(
                "service `{}` component `{}`: loading {}",
                service.name,
                component.id,
                workload_path.display()
            )
        })?;
        for entry in &workload.assets {
            live.insert(entry.filename.clone());
        }
    }
    Ok(live)
}

fn load_static_asset_workload(path: &Path) -> Result<StaticAssetWorkload> {
    let src =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let envelope: workload_spec::Workload =
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
    match envelope {
        workload_spec::Workload::StaticAsset(w) => Ok(w),
        other => anyhow::bail!(
            "{}: expected kind=\"static-asset\", got {:?}",
            path.display(),
            workload_kind_str(&other)
        ),
    }
}

fn workload_kind_str(w: &workload_spec::Workload) -> &'static str {
    match w {
        workload_spec::Workload::MesofactStatic(_) => "mesofact-static",
        workload_spec::Workload::Container(_) => "container",
        workload_spec::Workload::Almanac(_) => "almanac",
        workload_spec::Workload::StaticAsset(_) => "static-asset",
    }
}

// ── Backend resolution ────────────────────────────────────────────────────────

/// Resolved S3-compatible endpoint + credentials for a mirror's object_store.
struct Backend {
    endpoint: String,
    bucket: String,
    region: &'static str,
    access_key: String,
    secret_key: String,
}

fn resolve_backend(
    workspace_root: &Path,
    mirror: &crate::MirrorConfig,
    service_name: &str,
    env: &str,
) -> Result<Backend> {
    let slot = mirror.providers.get("object_store").with_context(|| {
        format!(
            "mirror has no `providers.object_store` slot — required for prune \
             (service={service_name}, env={env})"
        )
    })?;

    match slot {
        MirrorProviderSlot::Reference {
            provider_id,
            fields,
        } => {
            // Dispatch on the resolved provider *kind* so multiple cloudflare
            // providers (per zone/account) can coexist in one workspace.
            let cf = super::cf_creds::CfProvider::resolve(workspace_root, provider_id)?;
            anyhow::ensure!(
                matches!(cf.cfg.kind, Provider::Cloudflare),
                "providers.object_store.use = {provider_id:?} (kind={:?}) not supported for \
                 prune — only cloudflare-kind reference providers are",
                cf.cfg.kind,
            );
            let bucket = fields
                .get("bucket")
                .and_then(|v| v.as_str())
                .context("providers.object_store missing `bucket` for cloudflare")?
                .to_string();
            let account_id = cf.account_id.clone();
            let (access_key, secret_key) = cf.r2_keys()?;
            Ok(Backend {
                endpoint: format!("https://{account_id}.r2.cloudflarestorage.com"),
                bucket,
                region: R2_REGION,
                access_key,
                secret_key,
            })
        }
        MirrorProviderSlot::Inline {
            kind: Provider::MinioContainer,
            fields,
        } => {
            let api_port = fields
                .get("api_port")
                .and_then(|v| v.as_integer())
                .and_then(|n| u16::try_from(n).ok())
                .unwrap_or(DEFAULT_MINIO_API_PORT);
            let bucket = fields
                .get("bucket")
                .and_then(|v| v.as_str())
                .context("providers.object_store missing `bucket` for minio-container")?
                .to_string();
            Ok(Backend {
                endpoint: format!("http://127.0.0.1:{api_port}"),
                bucket,
                region: MINIO_REGION,
                access_key: DEFAULT_MINIO_USER.to_string(),
                secret_key: DEFAULT_MINIO_PASSWORD.to_string(),
            })
        }
        MirrorProviderSlot::Inline { kind, .. } => {
            anyhow::bail!(
                "providers.object_store.kind = {kind:?} not supported for prune \
                 (expected `minio-container` or a `cloudflare` reference)"
            )
        }
    }
}

// ── S3 ListObjectsV2 ──────────────────────────────────────────────────────────

/// One object as returned by `ListObjectsV2`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BucketObject {
    filename: String,
    size: u64,
    last_modified: String,
}

impl From<BucketObject> for PruneCandidate {
    fn from(o: BucketObject) -> Self {
        Self {
            filename: o.filename,
            size: o.size,
            last_modified: o.last_modified,
        }
    }
}

async fn list_bucket_objects(backend: &Backend) -> Result<Vec<PruneCandidate>> {
    let client = reqwest::Client::new();
    let mut out = Vec::new();
    let mut continuation: Option<String> = None;

    loop {
        let canonical_query = match &continuation {
            // Canonical query must be sorted lex by key: continuation-token < list-type.
            Some(token) => format!("continuation-token={}&list-type=2", urlencode(token)),
            None => "list-type=2".to_string(),
        };
        let url = format!(
            "{}/{}?{}",
            backend.endpoint.trim_end_matches('/'),
            backend.bucket,
            canonical_query
        );
        let headers = sign_s3_get_with_query(
            &url,
            &canonical_query,
            backend.region,
            &backend.access_key,
            &backend.secret_key,
        )
        .with_context(|| format!("signing LIST {url}"))?;
        let resp = client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .with_context(|| format!("LIST {url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("LIST {url} → {status}: {}", body.trim());
        }
        let body = resp.text().await.context("reading LIST response body")?;
        let (objects, next_token) = parse_list_response(&body)?;
        debug!(
            count = objects.len(),
            has_more = next_token.is_some(),
            "list-objects page"
        );
        out.extend(objects.into_iter().map(PruneCandidate::from));
        match next_token {
            Some(t) => continuation = Some(t),
            None => break,
        }
    }

    Ok(out)
}

/// Parse an `ListObjectsV2` XML response. Returns `(objects, next_continuation_token)`.
///
/// Hand-rolled: we don't want to pull `quick-xml` for one response shape. The
/// XML is server-emitted, single-namespace, and never contains nested
/// `<Contents>` blocks, so substring scanning is safe.
fn parse_list_response(body: &str) -> Result<(Vec<BucketObject>, Option<String>)> {
    let mut objects = Vec::new();
    for chunk in split_tags(body, "Contents") {
        let filename = inner_text(chunk, "Key").context("missing <Key>")?;
        let size = inner_text(chunk, "Size")
            .context("missing <Size>")?
            .parse::<u64>()
            .context("parsing <Size> as u64")?;
        let last_modified = inner_text(chunk, "LastModified")
            .context("missing <LastModified>")?
            .to_string();
        objects.push(BucketObject {
            filename: filename.to_string(),
            size,
            last_modified,
        });
    }

    let is_truncated = inner_text(body, "IsTruncated")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let next_token = if is_truncated {
        inner_text(body, "NextContinuationToken").map(|s| s.to_string())
    } else {
        None
    };

    Ok((objects, next_token))
}

/// Iterate the substrings between `<tag>` and `</tag>` (non-nested).
fn split_tags<'a>(body: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        match after.find(&close) {
            Some(end) => {
                out.push(&after[..end]);
                rest = &after[end + close.len()..];
            }
            None => break,
        }
    }
    out
}

/// Inner text of the first `<tag>...</tag>` in `body`. Trims whitespace.
fn inner_text<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    split_tags(body, tag).into_iter().next().map(|s| s.trim())
}

// ── S3 DeleteObject ───────────────────────────────────────────────────────────

async fn delete_object(client: &reqwest::Client, url: &str, backend: &Backend) -> Result<()> {
    let headers = sign_s3_empty_body(
        "DELETE",
        url,
        backend.region,
        &backend.access_key,
        &backend.secret_key,
    )
    .with_context(|| format!("signing DELETE {url}"))?;
    let resp = client
        .delete(url)
        .headers(headers)
        .send()
        .await
        .with_context(|| format!("DELETE {url}"))?;
    // S3 returns 204 No Content on success. R2 mirrors this.
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("DELETE {url} → {status}: {}", body.trim());
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Minimal RFC-3986 percent-encoder for ListObjectsV2 continuation tokens.
/// SigV4 canonical-query encoding rule: every byte outside the unreserved set
/// `[A-Za-z0-9-._~]` is `%HH` upper-hex encoded.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let unreserved =
            b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~';
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Convenience: resolve `(service, mirror)` from `workspace_root` by name +
/// env. Lifts the file-loading concern off the CLI handler so MCP tools can
/// call into a single function.
pub fn load_service_and_mirror(
    workspace_root: &Path,
    service_name: &str,
    env: &str,
) -> Result<(ServiceConfig, crate::MirrorConfig)> {
    let service_toml = crate::paths::service_toml(workspace_root, service_name);
    let service = ServiceConfig::load(&service_toml).with_context(|| {
        format!(
            "loading service `{service_name}` from {}",
            service_toml.display()
        )
    })?;
    let mirror_toml = crate::paths::service_mirror_toml(workspace_root, service_name, env);
    let mirror = crate::MirrorConfig::load(&mirror_toml).with_context(|| {
        format!(
            "loading mirror `{env}` for service `{service_name}` from {}",
            mirror_toml.display()
        )
    })?;
    Ok((service, mirror))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServiceComponent;
    use tempfile::tempdir;

    const HASH_64: &str = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    fn write_static_asset_workload(dir: &Path, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("workload.toml"), body).unwrap();
    }

    fn svc_with_components(name: &str, components: Vec<ServiceComponent>) -> ServiceConfig {
        ServiceConfig {
            schema_version: 1,
            name: name.into(),
            domain: "releases.example".into(),
            components,
            db: crate::DbCatalog::default(),
        }
    }

    fn asset_component(id: &str, path: &str) -> ServiceComponent {
        ServiceComponent {
            id: id.into(),
            kind: "static-asset".into(),
            path: path.into(),
            role: "assets".into(),
            publishes: None,
            wave: 0,
            git: None,
        }
    }

    // ── live_set ──────────────────────────────────────────────────────────────

    #[test]
    fn live_set_unions_filenames_across_components() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_static_asset_workload(
            &root.join("comp-a"),
            &format!(
                "[static-asset]\nschema_version = \"V1\"\n\n\
                 [[static-asset.asset]]\nfilename = \"a/one.bin\"\nsource = \"src/one.bin\"\nblake3 = \"{HASH_64}\"\n\n\
                 [[static-asset.asset]]\nfilename = \"a/two.bin\"\nsource = \"src/two.bin\"\nblake3 = \"{HASH_64}\"\n"
            ),
        );
        write_static_asset_workload(
            &root.join("comp-b"),
            &format!(
                "[static-asset]\nschema_version = \"V1\"\n\n\
                 [[static-asset.asset]]\nfilename = \"b/three.bin\"\nsource = \"src/three.bin\"\nblake3 = \"{HASH_64}\"\n"
            ),
        );
        let svc = svc_with_components(
            "demo",
            vec![
                asset_component("a", "comp-a"),
                asset_component("b", "comp-b"),
            ],
        );
        let live = compute_live_set(root, &svc).unwrap();
        let want: BTreeSet<String> = ["a/one.bin", "a/two.bin", "b/three.bin"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(live, want);
    }

    #[test]
    fn live_set_ignores_non_static_asset_components() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_static_asset_workload(
            &root.join("assets"),
            &format!(
                "[static-asset]\nschema_version = \"V1\"\n\n\
                 [[static-asset.asset]]\nfilename = \"x.bin\"\nsource = \"x.bin\"\nblake3 = \"{HASH_64}\"\n"
            ),
        );
        let mut svc = svc_with_components("mixed", vec![asset_component("assets", "assets")]);
        svc.components.push(ServiceComponent {
            id: "site".into(),
            kind: "mesofact-static".into(),
            path: "site-dir-doesnt-exist".into(),
            role: "static".into(),
            publishes: None,
            wave: 1,
            git: None,
        });
        // Loading must not try to parse the mesofact-static path.
        let live = compute_live_set(root, &svc).unwrap();
        assert_eq!(live.len(), 1);
        assert!(live.contains("x.bin"));
    }

    #[test]
    fn live_set_empty_when_no_static_asset_components() {
        let svc = svc_with_components("none", vec![]);
        let tmp = tempdir().unwrap();
        let live = compute_live_set(tmp.path(), &svc).unwrap();
        assert!(live.is_empty());
    }

    #[test]
    fn live_set_errors_on_wrong_kind_workload() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        // Component declares static-asset but workload.toml says container.
        std::fs::create_dir_all(root.join("oops")).unwrap();
        std::fs::write(
            root.join("oops/workload.toml"),
            "[almanac]\nschema_version = \"V1\"\ncommand = \"true\"\ncadence = \"once\"\n",
        )
        .unwrap();
        let svc = svc_with_components("oops", vec![asset_component("oops", "oops")]);
        let err = compute_live_set(root, &svc).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("static-asset"), "got: {msg}");
    }

    // ── parse_list_response ───────────────────────────────────────────────────

    #[test]
    fn parse_list_response_single_page() {
        let xml = r#"<?xml version="1.0"?>
<ListBucketResult>
  <Name>yah-dev</Name>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>whisper/v1.bin</Key>
    <LastModified>2026-01-01T00:00:00.000Z</LastModified>
    <ETag>"abc"</ETag>
    <Size>100</Size>
  </Contents>
  <Contents>
    <Key>whisper/v2.bin</Key>
    <LastModified>2026-02-01T00:00:00.000Z</LastModified>
    <ETag>"def"</ETag>
    <Size>200</Size>
  </Contents>
</ListBucketResult>"#;
        let (objects, next) = parse_list_response(xml).unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].filename, "whisper/v1.bin");
        assert_eq!(objects[0].size, 100);
        assert_eq!(objects[0].last_modified, "2026-01-01T00:00:00.000Z");
        assert_eq!(objects[1].filename, "whisper/v2.bin");
        assert_eq!(objects[1].size, 200);
        assert!(next.is_none());
    }

    #[test]
    fn parse_list_response_truncated_yields_token() {
        let xml = r#"<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>opaque-token-123</NextContinuationToken>
  <Contents>
    <Key>k</Key>
    <LastModified>2026-01-01T00:00:00.000Z</LastModified>
    <Size>1</Size>
  </Contents>
</ListBucketResult>"#;
        let (objects, next) = parse_list_response(xml).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(next.as_deref(), Some("opaque-token-123"));
    }

    #[test]
    fn parse_list_response_empty_bucket() {
        let xml = r#"<ListBucketResult>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>"#;
        let (objects, next) = parse_list_response(xml).unwrap();
        assert!(objects.is_empty());
        assert!(next.is_none());
    }

    #[test]
    fn parse_list_response_truncated_without_token_returns_none() {
        // R2 sometimes omits NextContinuationToken when IsTruncated=true if the
        // request didn't include start-after — defensive: don't loop forever.
        let xml = r#"<ListBucketResult>
  <IsTruncated>true</IsTruncated>
</ListBucketResult>"#;
        let (_, next) = parse_list_response(xml).unwrap();
        assert!(next.is_none());
    }

    // ── urlencode ─────────────────────────────────────────────────────────────

    #[test]
    fn urlencode_preserves_unreserved() {
        assert_eq!(urlencode("abcXYZ_.-~0"), "abcXYZ_.-~0");
    }

    #[test]
    fn urlencode_escapes_reserved() {
        assert_eq!(urlencode("a/b c?d"), "a%2Fb%20c%3Fd");
    }

    // ── candidate filtering ───────────────────────────────────────────────────

    #[test]
    fn candidates_exclude_catalog_manifest_sidecar() {
        // Mock the listing → candidates filter step directly: the bucket has
        // the sidecar + one orphan file; live set is empty. Only the orphan
        // should surface.
        let live: BTreeSet<String> = BTreeSet::new();
        let bucket = vec![
            PruneCandidate {
                filename: CATALOG_MANIFEST_KEY.to_string(),
                size: 64,
                last_modified: "2026-01-01T00:00:00Z".into(),
            },
            PruneCandidate {
                filename: "old.bin".to_string(),
                size: 1024,
                last_modified: "2026-01-01T00:00:00Z".into(),
            },
        ];
        let candidates: Vec<_> = bucket
            .into_iter()
            .filter(|o| o.filename != CATALOG_MANIFEST_KEY)
            .filter(|o| !live.contains(&o.filename))
            .collect();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].filename, "old.bin");
    }

    #[test]
    fn candidates_exclude_live_filenames() {
        let mut live = BTreeSet::new();
        live.insert("keep.bin".to_string());
        let bucket = vec![
            PruneCandidate {
                filename: "keep.bin".to_string(),
                size: 1,
                last_modified: "x".into(),
            },
            PruneCandidate {
                filename: "drop.bin".to_string(),
                size: 1,
                last_modified: "x".into(),
            },
        ];
        let candidates: Vec<_> = bucket
            .into_iter()
            .filter(|o| !live.contains(&o.filename))
            .collect();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].filename, "drop.bin");
    }
}
