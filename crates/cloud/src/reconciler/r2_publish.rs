//! R2 publish step — upload a built `dist/` tree to Cloudflare R2 via the
//! S3-compatible API, then optionally purge the CDN cache tags.
//!
//! ## Credentials
//!
//! Two distinct credential types:
//! - **R2 S3 keys** (`cloudflare-r2-access-key-id` / `cloudflare-r2-secret-key`)
//!   — sourced from CF Dashboard → R2 → Manage API tokens → S3 keys.
//!   Env fallbacks: `CF_R2_ACCESS_KEY_ID` / `CF_R2_SECRET_KEY`.
//! - **API token** (`cloudflare-api-token`) — only needed for the CDN cache-tag
//!   purge step; publish itself uses the S3 keys only. Omit purge opts to skip.
//!
//! ## Key layout
//!
//! Mirrors the pond flat layout: `html/` prefix is stripped, everything
//! else passes through unchanged. Production atomic-swap (`/<build_id>/…`
//! prefix + manifest pointer swap) is deferred to a follow-up.
//!
//! @yah:ticket(R320-F6, "R2 S3 credential slots in keystore (access-key-id + secret)")
//! @yah:at(2026-05-26T00:42:35Z)
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:phase(P2)
//! @yah:parent(R320)
//! @yah:handoff("R2 S3 credential slots defined in r2_publish.rs: R2_ACCESS_KEY_SLOT=cloudflare-r2-access-key-id, R2_SECRET_KEY_SLOT=cloudflare-r2-secret-key, R2_ACCESS_KEY_ENV=CF_R2_ACCESS_KEY_ID, R2_SECRET_KEY_ENV=CF_R2_SECRET_KEY. Consumed by up_cloudflare_r2 in mesofact_static.rs via keys::get_or_env. No keystore UI registration yet (yah keys set works for CLI; Settings→API Keys in desktop is out of scope for this relay).")
//! F7 (R2 publish) and F9 (CDN purge) are annotated in pond_publish.rs.
//!
//!
//! @yah:ticket(R320-F13, "R2 incremental upload: skip unchanged objects instead of full re-PUT every publish")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T16:33:51Z)
//! @yah:status(review)
//! @yah:parent(R320)
//! @yah:next("publish_to_r2 currently PUTs every file unconditionally (r2_publish.rs:113) — no skip for unchanged objects. Add a per-object guard: HEAD the key (or list the bucket once) and compare against a stored content hash before PUT.")
//! @yah:next("This is the prerequisite for cadence-driven publish (almanac) and CI publish (qed): without it every sync full-re-uploads dist/ and needlessly churns CDN cache tags.")
//! @yah:next("Decide v1 mechanism: incremental per-object PUT-skip vs the deferred build-id atomic-swap (/<build_id>/ prefix + manifest pointer) noted in the r2_publish.rs module header.")
//! @yah:gotcha("R2 ETag for a non-multipart PUT is the MD5 hex of the body, not sha256 — don't compare it against the existing sha256_hex. Either compare MD5, or store a content hash in object metadata at upload time and compare that.")
//! @yah:assumes("The Worker deploy is already hash-gated (worker-script-hashes.json); only the R2 object upload lacks an idempotency guard.")
//! @yah:handoff("Incremental upload implemented via a manifest sidecar file (_yah-manifest.json stored in the R2 bucket). Each publish run loads the manifest, computes sha256 of each local file, skips PUT if hash matches, then writes an updated manifest back. Avoids XML/ETag complexity entirely — manifest stores sha256 (not MD5), so the ETag gotcha is irrelevant.")
//! @yah:verify("cargo test -p cloud --lib reconciler::r2_publish -- 2>&1 | grep -E 'ok|FAILED'")
//! @yah:verify("Run `yah cloud mirror up dev-yah --env prod` twice in succession — second run should log `skipped=N uploaded=0` (after first run populates the manifest)")
//!
//! @yah:ticket(R498-F5, "refactor r2_publish::publish_to_r2 onto R2ObjectStore")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-09T03:29:43Z)
//! @yah:status(review)
//! @yah:parent(R498)
//! @yah:next("Replace inline sign_s3_put_object loop in publish_to_r2 with R2ObjectStore::put calls")
//! @yah:next("Manifest sidecar logic (_yah-manifest.json) preserved — load/save still happens here, just goes through object-store put/get")
//! @yah:next("Delete now-unused direct s3_sign imports from r2_publish.rs once R2ObjectStore wraps them")
//! @yah:next("Parallel-friendly: independent of F3/T4/F6, only depends on F2")
//! @yah:verify("cargo test -p cloud --lib reconciler::r2_publish ok")
//! @yah:verify("Round-trip yah cloud mirror up dev-yah --env prod twice: second run logs skipped=N uploaded=0")
//! @yah:depends_on(R498-F2)
//! @yah:tier(Cleric)
//!
//! @yah:ticket(R703-T10, "mesofact static publish still uploads every site file with no Cache-Control — classify hashed assets vs HTML")
//! @yah:status(review)
//! @yah:at(2026-08-09T20:09:04Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R703)
//! @yah:next("The upload loop in publish_to_r2 (the spawn_blocking s.put near r2_publish.rs:220) still calls plain ObjectStore::put, so every HTML page and asset in a mesofact static publish lands in R2 with no Cache-Control. R703-B8 built the seam (ObjectStore::put_cached plus CACHE_CONTROL_IMMUTABLE / CACHE_CONTROL_NO_CACHE) and used it for the publish beacon only.")
//! @yah:next("Missing piece is the classification rule, which is why B8 stopped short: an .html at a fixed route is no-cache, a content-hashed asset is immutable, everything else needs a defensible default. Get HTML wrong and yah.dev serves a stale page from browser caches with no way to bust it. Decide against what the mesofact builder actually emits (hashed filenames or not), do not assume.")
//! @yah:next("MANIFEST_KEY (_yah-manifest.json) is also a mutable pointer written by plain put, but nothing outside the reconciler fetches it, so it is cosmetic - fold it in while here.")
//! @yah:gotcha("Not urgent: cdn.yah.dev answers cf-cache-status DYNAMIC on this zone today, so Cloudflare's edge is not caching these objects regardless. The exposure is browser caches and any future edge-cache rule.")
//! @yah:handoff("Every object a mesofact static publish uploads now carries a Cache-Control. The rule is one function, cache_control_for(rel) in r2_publish.rs, and it is grounded rather than guessed: dist/hydrate/ is the ONLY output the builder content-hashes, via the <key>.[hash].js / <key>.chunk-[hash].js naming in mesofact-build's bundle.rs and its TS twin. Those get immutable; every other key - the prerendered .html pages, install.sh, illustrations/*.webp, manifest.json, tag-index.json - is a fixed key the next publish rewrites in place, so they get no-cache.")
//! @yah:handoff("The directory alone does not earn immutable: the filename must also carry a hash-shaped trailing segment (8+ base62 before the .js). A hand-dropped hydrate/app.js is not content-addressed and a year-long immutable cache on it would be unrecoverable. Unknown falls to no-cache in every branch - guessing 'cacheable' fails much worse than guessing 'not'.")
//! @yah:handoff("MANIFEST_KEY (_yah-manifest.json) folded in as no-cache too. Cosmetic, since nothing outside the reconciler fetches it, but leaving one directive-less mutable pointer behind invites the next reader to copy the pattern.")
//! @yah:handoff("I overstated this ticket's uncertainty when I filed it an hour ago. 'Needs a rule, not a guess' implied an operator call; it was a fact readable from the four built dist trees and the bundler's naming config.")
//! @yah:verify("cargo test -p yah-cloud --lib r2_publish -> 10 pass, 0 fail (3 new: hydrate bundles immutable, fixed keys no-cache, non-hash-named hydrate files stay no-cache)")
//! @yah:verify("cargo test -p yah-cloud --lib -> 744 pass, 0 fail (was 741)")
//! @yah:verify("cargo check --workspace clean on root and oss/yubaba")
//! @yah:verify("Classifier test inputs are REAL filenames read from the built dist trees on 2026-08-09 - hydrate/issues.ervzmehh.js and hydrate/rigs_id.uxTuqN9d.js from marketing/dashboard, plus index.html, install.sh, illustrations/yah-table-dark.webp, manifest.json, tag-index.json - not invented ones")

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tracing::{debug, info};
use yah_object_store::{ObjectStore as _, R2ObjectStore};

use super::publish_beacon::{PublishBeacon, BEACON_KEY};
use crate::provider::cloudflare::CloudflareClient;

/// Bucket key for the per-bucket publish manifest. Starts with `_` to avoid
/// collisions with typical dist/ output (index.html, assets/*, etc.).
const MANIFEST_KEY: &str = "_yah-manifest.json";

/// Map of `bucket_key → sha256_hex` written to R2 after each successful
/// publish. Loaded at the start of the next run to skip unchanged objects.
type PublishManifest = HashMap<String, String>;

// Re-export credential constants from the object-store crate so callers
// that import them from this module continue to compile unchanged.
pub use yah_object_store::r2::{
    R2_ACCESS_KEY_ENV, R2_ACCESS_KEY_SLOT, R2_SECRET_KEY_ENV, R2_SECRET_KEY_SLOT,
};

/// `Cache-Control` for one published object, keyed off the dist-relative path
/// (R703-T10 — the rest of R703-B8's seam).
///
/// Only ONE class of file in a mesofact dist is safe to cache forever, and it
/// is not guessable from the extension: `dist/hydrate/` is the sole output the
/// builder content-hashes, via the `<key>.[hash].js` / `<key>.chunk-[hash].js`
/// naming in `mesofact-build`'s `bundle.rs` (and its TS twin). Everything else
/// — the prerendered `.html` pages, `install.sh`, the `illustrations/*.webp`,
/// `manifest.json`, `tag-index.json` — sits at a FIXED key that the next
/// publish rewrites in place, so an immutable directive there is a promise the
/// bytes cannot keep: yah.dev would serve a stale page out of browser caches
/// with no way to bust it short of renaming the route.
///
/// The hash-shaped-filename check is belt and braces on top of the directory:
/// a plain `hydrate/app.js` (someone bypassing the bundler, a hand-dropped
/// polyfill) is NOT content-addressed, and a year-long immutable cache on it
/// would be unrecoverable. Unknown ⇒ `no-cache`, always — the failure mode of
/// guessing "cacheable" is much worse than the failure mode of guessing "not".
fn cache_control_for(rel: &str) -> &'static str {
    let hashed = rel
        .strip_prefix("hydrate/")
        .and_then(|f| f.rsplit_once('.'))
        // `<name>.<hash>.js` → after dropping `.js`, the trailing dot-segment
        // is the hash. Bun emits 8+ chars of base62; require that rather than
        // "has two dots", so `app.min.js` is not mistaken for hashed output.
        .and_then(|(stem, ext)| (ext == "js").then_some(stem))
        .and_then(|stem| stem.rsplit_once('.'))
        .is_some_and(|(_, tok)| {
            tok.len() >= 8 && tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    if hashed {
        yah_object_store::CACHE_CONTROL_IMMUTABLE
    } else {
        yah_object_store::CACHE_CONTROL_NO_CACHE
    }
}

/// Options for the CDN cache-tag purge step after upload.
/// Omit to skip purge (publish only, no CDN invalidation).
pub struct R2PurgeOpts {
    /// Cloudflare zone name (e.g. `"yah.dev"`). Resolved to a zone ID
    /// via the management API before calling purge.
    pub zone_name: String,
    /// Cloudflare API token with `Zone: Cache Purge` scope.
    pub api_token: String,
}

/// Summary of a completed R2 publish.
///
/// Not `Default`: a report with an empty [`PublishBeacon`] would describe a
/// publish that never happened, and the beacon's whole job is to be
/// impossible to confuse with one.
#[derive(Debug, Clone)]
pub struct R2PublishReport {
    /// Object keys successfully uploaded to R2.
    pub uploaded: Vec<String>,
    /// Object keys skipped because their sha256 matched the stored manifest.
    pub skipped: Vec<String>,
    /// Cache tags purged from the CDN after upload. Empty when no purge opts
    /// were provided or when `dist/tag-index.json` has no tags.
    pub purged_tags: Vec<String>,
    /// R703-B4 — what this publish claims it put in the bucket, written to
    /// `<prefix>/.well-known/yah-publish.json` as the *last* object of the
    /// run. Fetch it back through a front door to find out whether that front
    /// door is serving this publish or something older; see
    /// [`super::publish_beacon`].
    pub beacon: PublishBeacon,
}

/// Upload every file in `dist_dir` to `<bucket>/` in the given R2 account,
/// then optionally purge CDN cache tags.
///
/// Credentials are the R2 S3 access key + secret (distinct from the
/// Cloudflare API token used for management operations). Obtain them from
/// CF Dashboard → R2 → Manage API tokens → S3 API Tokens.
/// Upload every file in `dist_dir` to `<bucket>/` in the given R2 account.
///
/// `key_prefix`: when `Some`, all keys are prefixed with `<prefix>/`. Use
/// `"<service>/<env>"` to isolate two mirrors that share the same R2 bucket.
pub async fn publish_to_r2(
    dist_dir: &Path,
    account_id: &str,
    bucket: &str,
    access_key: &str,
    secret_key: &str,
    key_prefix: Option<&str>,
    purge: Option<R2PurgeOpts>,
) -> Result<R2PublishReport> {
    if !tokio::fs::try_exists(dist_dir)
        .await
        .with_context(|| format!("checking {}", dist_dir.display()))?
    {
        anyhow::bail!("dist_dir not found: {}", dist_dir.display());
    }

    // R2ObjectStore holds a reqwest::blocking::Client whose internal runtime
    // panics if constructed (or dropped) inside an async context — off-load
    // both endpoints to a blocking worker thread. Every method call below is
    // already spawn_blocking-wrapped; matching Drop is handled in the store's
    // impl.
    let account_id_owned = account_id.to_string();
    let bucket_owned = bucket.to_string();
    let access_key_owned = access_key.to_string();
    let secret_key_owned = secret_key.to_string();
    let store = Arc::new(
        tokio::task::spawn_blocking(move || {
            R2ObjectStore::new(
                account_id_owned,
                bucket_owned,
                access_key_owned,
                secret_key_owned,
            )
        })
        .await
        .context("R2ObjectStore construction task panicked")?
        .context("building R2ObjectStore")?,
    );

    // Load manifest non-fatally: empty map on first run or any transient error.
    let manifest: PublishManifest = {
        let s = Arc::clone(&store);
        tokio::task::spawn_blocking(move || s.get(MANIFEST_KEY))
            .await
            .context("manifest GET task panicked")?
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    };
    let mut new_manifest = PublishManifest::new();

    let files = walk_files(dist_dir).await.context("walking dist_dir")?;
    info!(
        bucket,
        account_id,
        files = files.len(),
        prior_tracked = manifest.len(),
        "publishing dist/ to R2"
    );

    let mut uploaded = Vec::new();
    let mut skipped = Vec::new();

    for path in &files {
        let rel = path
            .strip_prefix(dist_dir)
            .expect("walker yields paths under root");
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        // server/ contains SSR bundles — not part of a static R2 deploy.
        if rel_str.starts_with("server/") {
            continue;
        }
        // Strip `html/` prefix; optionally prepend mirror key_prefix.
        let stripped = rel_str.strip_prefix("html/").unwrap_or(&rel_str);
        let key = match key_prefix {
            Some(p) => format!("{}/{}", p.trim_end_matches('/'), stripped),
            None => stripped.to_string(),
        };

        let body = tokio::fs::read(path)
            .await
            .with_context(|| format!("reading {}", path.display()))?;
        let body_hash = sha256_hex(&body);

        // Skip PUT when the stored manifest records an identical sha256.
        if manifest.get(&key).map(|s| s.as_str()) == Some(body_hash.as_str()) {
            debug!(key, "skipped (unchanged)");
            new_manifest.insert(key.clone(), body_hash);
            skipped.push(key);
            continue;
        }

        let s = Arc::clone(&store);
        let key_clone = key.clone();
        let cc = cache_control_for(stripped);
        tokio::task::spawn_blocking(move || s.put_cached(&key_clone, body, cc))
            .await
            .context("PUT task panicked")?
            .with_context(|| format!("PUT {key}"))?;

        debug!(key, cache_control = cc, "uploaded");
        uploaded.push(key.clone());
        new_manifest.insert(key, body_hash);
    }

    // Save the updated manifest. Non-fatal: files are already in R2; a
    // failed manifest write just means the next run re-uploads everything.
    if let Err(e) = {
        let s = Arc::clone(&store);
        let manifest_bytes =
            serde_json::to_vec(&new_manifest).context("serializing publish manifest")?;
        tokio::task::spawn_blocking(move || {
            // A fixed key rewritten by every publish (R703-T10). Nothing
            // outside this reconciler ever fetches it, so the directive is
            // cosmetic — but a mutable pointer with no directive is exactly
            // the pattern being removed, and leaving one behind invites the
            // next reader to copy it.
            s.put_cached(
                MANIFEST_KEY,
                manifest_bytes,
                yah_object_store::CACHE_CONTROL_NO_CACHE,
            )
        })
        .await
        .context("manifest PUT task panicked")?
    } {
        tracing::warn!(error = %e, "failed to save publish manifest (non-fatal) — next run will re-upload all objects");
    }

    info!(
        uploaded = uploaded.len(),
        skipped = skipped.len(),
        "R2 upload complete"
    );

    // R703-B4 — publish beacon, written LAST and unconditionally.
    //
    // Last, because its presence is then also evidence that the run reached
    // the end rather than dying halfway through the file loop. Unconditionally
    // (no manifest skip), because a run where every object was skipped as
    // unchanged still needs to refresh `published_at` — otherwise "the front
    // door is three weeks behind" and "nothing has changed in three weeks"
    // look identical from the outside.
    //
    // Fatal on failure, unlike the manifest write above: the manifest is an
    // optimisation, but a missing beacon disables the serving check that is
    // this object's entire reason to exist, and a publish whose verification
    // silently switched itself off is the exact failure being fixed here.
    let contents: BTreeMap<String, String> = new_manifest
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let beacon = PublishBeacon::new(key_prefix.unwrap_or_default(), &contents);
    let beacon_key = match key_prefix {
        Some(p) => format!("{}/{}", p.trim_end_matches('/'), BEACON_KEY),
        None => BEACON_KEY.to_string(),
    };
    {
        let s = Arc::clone(&store);
        let bytes = serde_json::to_vec(&beacon).context("serializing publish beacon")?;
        let key = beacon_key.clone();
        // R703-B8 — `no-cache`, and of everything this function uploads it is
        // the object that most needs it. The beacon is the freshness oracle the
        // serving check reads back through the public front door; a cached copy
        // makes a stale site verify green, which is worse than having no check.
        // Every other object now carries one too — see `cache_control_for`.
        tokio::task::spawn_blocking(move || {
            s.put_cached(&key, bytes, yah_object_store::CACHE_CONTROL_NO_CACHE)
        })
        .await
        .context("beacon PUT task panicked")?
        .with_context(|| format!("PUT {beacon_key}"))?;
    }
    info!(
        digest = %beacon.digest,
        files = beacon.files,
        key = %beacon_key,
        "publish beacon written"
    );

    // CDN cache-tag purge.
    let purged_tags = if let Some(opts) = purge {
        let tags = read_tag_names(dist_dir).await;
        if tags.is_empty() {
            debug!("no tags in dist/tag-index.json — skipping purge");
            Vec::new()
        } else {
            let cf = CloudflareClient::new(opts.api_token);
            let zone_id = cf
                .zone_id_for_name(&opts.zone_name)
                .await
                .with_context(|| format!("resolving zone id for {:?}", opts.zone_name))?;
            match cf.purge_cache_tags(&zone_id, &tags).await {
                Ok(()) => {
                    info!(
                        zone = opts.zone_name,
                        tags = tags.len(),
                        "CDN cache-tag purge complete"
                    );
                }
                Err(e) => {
                    // Purge failure is non-fatal: files are already in R2.
                    // Likely cause: api-token missing Zone:Cache Purge scope.
                    // Stale CDN content expires on its own; add the scope to
                    // avoid this warning on subsequent publishes.
                    tracing::warn!(
                        zone = opts.zone_name,
                        error = %e,
                        "CDN cache-tag purge failed (non-fatal) — \
                         ensure cloudflare-api-token has Zone:Cache Purge scope"
                    );
                }
            }
            tags
        }
    } else {
        Vec::new()
    };

    Ok(R2PublishReport {
        uploaded,
        skipped,
        purged_tags,
        beacon,
    })
}

// ---------- helpers ----------

fn sha256_hex(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

/// Read `dist/tag-index.json` and extract the tag names. Non-fatal — returns
/// empty vec on any read or parse error.
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

async fn walk_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
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

    #[tokio::test]
    async fn publish_fails_when_dist_missing() {
        let err = publish_to_r2(
            Path::new("/no/such/dist"),
            "acct123",
            "yah-dev",
            "key",
            "secret",
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("dist_dir not found"),
            "got: {err:#}"
        );
    }

    #[test]
    fn html_prefix_stripped() {
        let rel = "html/index.html";
        let key = rel.strip_prefix("html/").unwrap_or(rel);
        assert_eq!(key, "index.html");
    }

    #[test]
    fn assets_pass_through() {
        let rel = "assets/main.js";
        let key = rel.strip_prefix("html/").unwrap_or(rel);
        assert_eq!(key, "assets/main.js");
    }

    #[tokio::test]
    async fn read_tag_names_returns_sorted() {
        let tmp = TempDir::new().unwrap();
        let body = r#"{"build_id":"b1","tags":{"page:home":[],"site:yah-dev":[],"page:404":[]}}"#;
        tokio::fs::write(tmp.path().join("tag-index.json"), body)
            .await
            .unwrap();
        let tags = read_tag_names(tmp.path()).await;
        assert_eq!(tags, vec!["page:404", "page:home", "site:yah-dev"]);
    }

    #[test]
    fn manifest_roundtrip() {
        let mut m = PublishManifest::new();
        m.insert("index.html".to_string(), sha256_hex(b"hello"));
        m.insert("assets/main.js".to_string(), sha256_hex(b"world"));
        let json = serde_json::to_vec(&m).unwrap();
        let m2: PublishManifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn manifest_skip_logic() {
        let content = b"hello world";
        let hash = sha256_hex(content);
        let mut manifest = PublishManifest::new();
        manifest.insert("index.html".to_string(), hash.clone());

        // Same content → should skip.
        assert_eq!(
            manifest.get("index.html").map(|s| s.as_str()),
            Some(hash.as_str())
        );
        // Different content → should upload.
        let other_hash = sha256_hex(b"different");
        assert_ne!(
            manifest.get("index.html").map(|s| s.as_str()),
            Some(other_hash.as_str())
        );
        // Missing key → should upload.
        assert_eq!(manifest.get("missing.html"), None);
    }

    #[test]
    fn load_manifest_empty_on_bad_json() {
        let bad: PublishManifest = serde_json::from_slice(b"not json").unwrap_or_default();
        assert!(bad.is_empty());
    }

    // ── Cache-Control classification (R703-T10) ─────────────────────────────

    /// Pinned against REAL filenames read out of the built dist trees on
    /// 2026-08-09, not invented ones — the whole rule rests on which files the
    /// builder content-hashes, so a test over made-up names would prove nothing.
    #[test]
    fn only_content_hashed_hydrate_bundles_are_immutable() {
        // app/yah/web/marketing/dist/hydrate/ and dashboard's, verbatim.
        for k in [
            "hydrate/issues.ervzmehh.js",
            "hydrate/issues.BdKFYN8Z.js",
            "hydrate/rigs_id.uxTuqN9d.js",
            "hydrate/index.CStDXFd1.js",
            "hydrate/index.chunk-CStDXFd1.js",
        ] {
            assert_eq!(
                cache_control_for(k),
                "public, max-age=31536000, immutable",
                "{k}"
            );
        }
    }

    /// Every fixed key the same publish uploads. These are rewritten in place
    /// by the next publish, so `immutable` here is a promise the bytes cannot
    /// keep — a stale yah.dev page with no way to bust it.
    #[test]
    fn fixed_keys_are_no_cache() {
        for k in [
            "index.html",
            "releases.html",
            "404.html",
            "install.sh",
            "illustrations/yah-table-dark.webp",
            "manifest.json",
            "tag-index.json",
            ".well-known/yah-publish.json",
        ] {
            assert_eq!(cache_control_for(k), "no-cache, max-age=0", "{k}");
        }
    }

    /// The directory alone is not enough. A hand-dropped or non-bundler file
    /// under `hydrate/` is not content-addressed, and a year-long immutable
    /// cache on it would be unrecoverable — unknown must fall to `no-cache`.
    #[test]
    fn hydrate_files_that_are_not_hash_named_stay_no_cache() {
        for k in [
            "hydrate/app.js",        // no hash segment at all
            "hydrate/app.min.js",    // a second dot, but `min` is not a hash
            "hydrate/app.abc.js",    // too short to be one either
            "hydrate/vendor.LICENSE",// not even a .js
            "hydrate/readme.md",
        ] {
            assert_eq!(cache_control_for(k), "no-cache, max-age=0", "{k}");
        }
    }
}
