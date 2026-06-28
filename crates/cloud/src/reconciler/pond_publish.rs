//! Pond publish step (R256-T4) — upload a built `dist/` tree to a
//! running pond-tier MinIO container, feature-flagging the Cloudflare CDN
//! purge as a logged no-op.
//!
//! ## Key layout
//!
//! Production publish (mesofact-publisher) uses a `/<build_id>/…` prefix and
//! Cloudflare cache-tag purge. Pond uses a simplified flat layout so the
//! Worker can route requests without knowing the current build_id:
//!
//! | `dist/` path        | MinIO key        | Why |
//! |---|---|---|
//! | `html/index.html`   | `index.html`     | Caddyfile rewrites `/` → `/<bucket>/index.html` |
//! | `html/404.html`     | `404.html`       | Same `html/` stripping for all HTML files |
//! | `assets/…`          | `assets/…`       | Passed through as-is |
//! | `manifest.json`     | `manifest.json`  | Tooling reads the root pointer |
//! | `tag-index.json`    | `tag-index.json` | Tooling reads the root pointer |
//!
//! ## CDN purge feature-flag
//!
//! CDN purge is intentionally disabled (R256-T4). Tags that would be purged
//! in production are logged at `debug` level so they remain visible during
//! verbose sessions, but no network call is made to Cloudflare. MinIO has no
//! CDN purge equivalent and the pond bucket is public-read for miniflare
//! pass-through anyway. File a follow-up ticket if a local purge simulation
//! is ever needed — the deferred work is intentional (see arch doc).
//!
//! @yah:ticket(R320-F7, "R2 publish step in cloud crate (port local_sim_publish, S3 SigV4)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T00:42:36Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R320)
//! @yah:depends_on(R320-F6)
//! @yah:handoff("R2 publish step implemented in crates/yah/cloud/src/reconciler/r2_publish.rs. Ports local_sim_publish pattern: walk dist/, strip html/ prefix, sign each PUT with S3 SigV4 (region=auto for R2), upload to https://{account_id}.r2.cloudflarestorage.com/{bucket}/{key}. Re-exported from reconciler/mod.rs.")
//!
//! @yah:ticket(R320-F9, "Real CDN cache-tag purge after publish (replace local-sim no-op)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T00:42:37Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R320)
//! @yah:depends_on(R320-T1)
//! @yah:depends_on(R320-T8)
//! @yah:handoff("Real CDN purge wired in r2_publish.rs::publish_to_r2. After upload, reads dist/tag-index.json for cache tags, calls CloudflareClient::zone_id_for_name then purge_cache_tags. Purge is opt-in: only fires when R2PurgeOpts is present (caller passes it if cloudflare-api-token resolves from keystore/env). No-op when opts are None.")
//!
//! @yah:ticket(R335-F4, "Per-mirror artifact key prefix: prevent same-tier (two-cloud-on-one-R2) collision")
//! @yah:at(2026-05-27T02:39:04Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R335)
//! @yah:next("Add a per-mirror key prefix to derive_minio_key + publish_to_r2.")
//! @yah:next("Cross-tier is already separated by the MinIO(pond)/R2(cloud) backend split; this closes the same-tier case (doc §4.1 open item).")

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tracing::debug;

use local_driver::s3_sign::sign_s3_put_object;

/// S3 region MinIO uses regardless of actual location (AWS SigV4 requirement).
const MINIO_REGION: &str = "us-east-1";

/// Summary of a completed pond publish.
#[derive(Debug, Clone, Default)]
pub struct PondPublishReport {
    /// Object keys successfully uploaded to MinIO.
    pub uploaded: Vec<String>,
    /// CDN tags that would have been purged in a production publish. Derived
    /// from `dist/tag-index.json`; always a no-op locally (R256-T4).
    pub would_purge_tags: Vec<String>,
}

/// Upload every file in `dist_dir` to `<endpoint>/<bucket>/` using the
/// simplified pond key layout, then return a report.
///
/// CDN purge is skipped — tags from `dist/tag-index.json` are logged at
/// `debug` level instead of being sent to Cloudflare.
///
/// `key_prefix`: when `Some`, all keys are prefixed with `<prefix>/`. Use
/// `"<service>/<env>"` to isolate two mirrors sharing the same bucket.
pub async fn publish_to_pond(
    dist_dir: &Path,
    endpoint: &str,
    bucket: &str,
    access_key: &str,
    secret_key: &str,
    key_prefix: Option<&str>,
) -> Result<PondPublishReport> {
    if !tokio::fs::try_exists(dist_dir)
        .await
        .with_context(|| format!("checking {}", dist_dir.display()))?
    {
        anyhow::bail!("dist_dir not found: {}", dist_dir.display());
    }

    let client = reqwest::Client::new();
    let endpoint = endpoint.trim_end_matches('/');
    let mut uploaded = Vec::new();

    for entry in walk_files(dist_dir).await.context("walking dist_dir")? {
        let rel = entry
            .strip_prefix(dist_dir)
            .expect("walker always yields paths under root");
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let key = derive_minio_key(&rel_str, key_prefix);

        let body = tokio::fs::read(&entry)
            .await
            .with_context(|| format!("reading {}", entry.display()))?;
        let body_hash = sha256_hex(&body);
        let content_type = content_type_for(&entry);
        let content_length = body.len();

        let url = format!("{endpoint}/{bucket}/{key}");
        let headers = sign_s3_put_object(
            &url,
            &body_hash,
            content_type,
            content_length,
            MINIO_REGION,
            access_key,
            secret_key,
        )
        .with_context(|| format!("signing PUT {url}"))?;

        let resp = client
            .put(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .with_context(|| format!("PUT {url}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            anyhow::bail!("PUT {url} → {status}: {}", body_text.trim());
        }
        uploaded.push(key);
    }

    let would_purge_tags = read_tag_names(dist_dir).await;
    if !would_purge_tags.is_empty() {
        debug!(
            tags = ?would_purge_tags,
            "pond CDN purge is no-op (R256-T4); would purge {} tag(s)",
            would_purge_tags.len(),
        );
    }

    Ok(PondPublishReport {
        uploaded,
        would_purge_tags,
    })
}

/// Map a `dist/`-relative path to a MinIO key.
///
/// Strips the `html/` prefix so the Caddyfile's direct-path routing works:
/// `html/index.html` → `index.html`, `html/404.html` → `404.html`.
/// When `key_prefix` is `Some("svc/env")`, the result is `svc/env/<key>`.
pub fn derive_minio_key(rel: &str, key_prefix: Option<&str>) -> String {
    let stripped = rel.strip_prefix("html/").unwrap_or(rel);
    match key_prefix {
        Some(prefix) => format!("{}/{}", prefix.trim_end_matches('/'), stripped),
        None => stripped.to_string(),
    }
}

/// Read `dist/tag-index.json` and extract the tag names. Returns an empty
/// vec on any read or parse error — purge is a no-op so this is non-fatal.
async fn read_tag_names(dist_dir: &Path) -> Vec<String> {
    let path = dist_dir.join("tag-index.json");
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    let Some(tags_obj) = value.get("tags").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let mut tags: Vec<String> = tags_obj.keys().cloned().collect();
    tags.sort();
    tags
}

fn sha256_hex(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

fn content_type_for(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

async fn walk_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let ft = entry.file_type().await?;
            let p = entry.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn derive_key_strips_html_prefix() {
        assert_eq!(derive_minio_key("html/index.html", None), "index.html");
        assert_eq!(derive_minio_key("html/404.html", None), "404.html");
        assert_eq!(
            derive_minio_key("html/nested/page.html", None),
            "nested/page.html"
        );
    }

    #[test]
    fn derive_key_passes_through_non_html_dirs() {
        assert_eq!(derive_minio_key("assets/main.js", None), "assets/main.js");
        assert_eq!(derive_minio_key("manifest.json", None), "manifest.json");
        assert_eq!(derive_minio_key("tag-index.json", None), "tag-index.json");
    }

    #[test]
    fn derive_key_does_not_strip_html_prefix_on_non_html_dir() {
        assert_eq!(
            derive_minio_key("html-extras/foo.html", None),
            "html-extras/foo.html"
        );
    }

    #[test]
    fn derive_key_prepends_prefix() {
        assert_eq!(
            derive_minio_key("html/index.html", Some("dev-yah/cloud")),
            "dev-yah/cloud/index.html"
        );
        assert_eq!(
            derive_minio_key("assets/main.js", Some("dev-yah/cloud")),
            "dev-yah/cloud/assets/main.js"
        );
    }

    #[test]
    fn derive_key_prefix_trailing_slash_stripped() {
        assert_eq!(
            derive_minio_key("index.html", Some("svc/env/")),
            "svc/env/index.html"
        );
    }

    #[test]
    fn content_type_html() {
        assert_eq!(
            content_type_for(Path::new("index.html")),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn content_type_js() {
        assert_eq!(
            content_type_for(Path::new("main.js")),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type_for(Path::new("chunk.mjs")),
            "application/javascript; charset=utf-8"
        );
    }

    #[test]
    fn content_type_json() {
        assert_eq!(
            content_type_for(Path::new("manifest.json")),
            "application/json"
        );
    }

    #[test]
    fn content_type_unknown_falls_back_to_octet_stream() {
        assert_eq!(
            content_type_for(Path::new("data.bin")),
            "application/octet-stream"
        );
    }

    #[tokio::test]
    async fn read_tag_names_from_valid_index() {
        let tmp = TempDir::new().unwrap();
        let body = r#"{"build_id":"b1","tags":{"page:home":[],"site:yah-dev":[],"page:404":[]}}"#;
        tokio::fs::write(tmp.path().join("tag-index.json"), body)
            .await
            .unwrap();
        let tags = read_tag_names(tmp.path()).await;
        // sorted
        assert_eq!(tags, vec!["page:404", "page:home", "site:yah-dev"]);
    }

    #[tokio::test]
    async fn read_tag_names_returns_empty_when_absent() {
        let tmp = TempDir::new().unwrap();
        assert!(read_tag_names(tmp.path()).await.is_empty());
    }

    #[tokio::test]
    async fn read_tag_names_returns_empty_on_malformed_json() {
        let tmp = TempDir::new().unwrap();
        tokio::fs::write(tmp.path().join("tag-index.json"), b"not json")
            .await
            .unwrap();
        assert!(read_tag_names(tmp.path()).await.is_empty());
    }

    #[tokio::test]
    async fn publish_fails_when_dist_missing() {
        let err = publish_to_pond(
            Path::new("/no/such/dist"),
            "http://127.0.0.1:9000",
            "bucket",
            "user",
            "pass",
            None,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("dist_dir not found"),
            "got: {err:#}"
        );
    }

    #[tokio::test]
    async fn walk_files_collects_files_recursively() {
        let tmp = TempDir::new().unwrap();
        tokio::fs::create_dir(tmp.path().join("html"))
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("html/index.html"), b"<h1>hi</h1>")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("manifest.json"), b"{}")
            .await
            .unwrap();
        let files = walk_files(tmp.path()).await.unwrap();
        let rels: Vec<String> = files
            .iter()
            .map(|p| {
                p.strip_prefix(tmp.path())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert!(rels.contains(&"html/index.html".to_string()));
        assert!(rels.contains(&"manifest.json".to_string()));
    }
}
