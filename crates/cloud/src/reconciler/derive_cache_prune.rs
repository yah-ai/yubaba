//! Prune verb for the local derive cache (`.yah/cache/derive/`) (R438-F12).
//!
//! The static-asset reconciler materializes fetched and transformed blobs into
//! a content-addressed cache; entries accumulate over time as workload hashes
//! change. This module provides the explicit prune path that evicts cache
//! entries no longer referenced by any live workload.
//!
//! ## Live-set resolution
//!
//! For each `static-asset` component across all declared services:
//! - `fetch` cache live set  — every `derive.fetch.blake3` value.
//! - `transform` cache live set — every `entry.blake3` value for assets that
//!   carry a `derive.transform` (i.e. the transform output hash).
//!
//! ## Safety
//!
//! - Prune is always explicit; the reconciler never calls this path.
//! - `--dry-run` enumerates candidates without deleting.
//! - The CLI prompts for confirmation unless `--yes` is supplied.
//! - `.partial` files in the cache are NOT included as prune candidates —
//!   they may belong to an in-progress download in another process.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::{info, warn};

use crate::reconciler::static_asset::WORKLOAD_KIND;
use crate::ServiceConfig;

/// Blake3 hashes of derive-cache entries that are still live, split by
/// cache subdirectory.
#[derive(Debug, Default)]
pub struct DeriveCacheLiveHashes {
    /// Hashes live in `.yah/cache/derive/fetch/` (from `derive.fetch.blake3`).
    pub fetch: BTreeSet<String>,
    /// Hashes live in `.yah/cache/derive/transform/` (from `entry.blake3` when
    /// `derive.transform` is set).
    pub transform: BTreeSet<String>,
}

/// A single derive-cache `.bin` file eligible for deletion.
#[derive(Debug, Clone)]
pub struct DerivePruneCandidate {
    /// Full path to the file.
    pub path: PathBuf,
    /// Cache sub-directory: `"fetch"` or `"transform"`.
    pub cache_kind: &'static str,
    /// Blake3 hex stem of the filename.
    pub hash: String,
    /// File size in bytes.
    pub size: u64,
}

/// Walk `services`, load each `static-asset` workload, and collect the live
/// sets of blake3 hashes for the fetch and transform cache directories.
///
/// Workload files that are missing or unparseable are skipped with a warning
/// rather than failing hard — stale component entries in service.toml should
/// not block a prune of the cache.
pub fn collect_live_derive_hashes<'a>(
    workspace_root: &Path,
    services: impl IntoIterator<Item = &'a ServiceConfig>,
) -> Result<DeriveCacheLiveHashes> {
    let mut live = DeriveCacheLiveHashes::default();

    for svc in services {
        for component in &svc.components {
            if component.kind != WORKLOAD_KIND {
                continue;
            }
            let workload_path = workspace_root.join(&component.path).join("workload.toml");
            let src = match std::fs::read_to_string(&workload_path) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        path = %workload_path.display(),
                        error = %e,
                        "derive-cache prune: skipping unreadable workload",
                    );
                    continue;
                }
            };
            let envelope: workload_spec::Workload = match toml::from_str(&src) {
                Ok(w) => w,
                Err(e) => {
                    warn!(
                        path = %workload_path.display(),
                        error = %e,
                        "derive-cache prune: skipping unparseable workload",
                    );
                    continue;
                }
            };
            let workload_spec::Workload::StaticAsset(workload) = envelope else {
                continue;
            };
            for entry in &workload.assets {
                let Some(derive) = &entry.derive else {
                    continue;
                };
                live.fetch.insert(derive.fetch.blake3.0.clone());
                if derive.transform.is_some() {
                    live.transform.insert(entry.blake3.0.clone());
                }
            }
        }
    }

    Ok(live)
}

/// Enumerate `<derive_cache_root>/{fetch,transform}/*.bin` and return those
/// whose hash stem is NOT in the corresponding live set.
///
/// `.partial` files are never included as candidates — they may belong to an
/// in-progress download.
pub fn compute_derive_cache_candidates(
    derive_cache_root: &Path,
    live: &DeriveCacheLiveHashes,
) -> Result<Vec<DerivePruneCandidate>> {
    let mut candidates = Vec::new();

    for (subdir, live_set) in [("fetch", &live.fetch), ("transform", &live.transform)] {
        let dir = derive_cache_root.join(subdir);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue, // cache dir absent = nothing to prune
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if ext != Some("bin") {
                continue; // skip .partial and other files
            }
            let Some(hash) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
            else {
                continue;
            };
            if live_set.contains(hash.as_str()) {
                continue;
            }
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            candidates.push(DerivePruneCandidate {
                path,
                cache_kind: if subdir == "fetch" {
                    "fetch"
                } else {
                    "transform"
                },
                hash,
                size,
            });
        }
    }

    // Deterministic order for diffable output.
    candidates.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(candidates)
}

/// Delete the candidate files from disk. Returns `(deleted_count, deleted_bytes, error_count)`.
pub fn execute_derive_cache_prune(candidates: &[DerivePruneCandidate]) -> (usize, u64, usize) {
    let mut deleted = 0usize;
    let mut bytes = 0u64;
    let mut errors = 0usize;

    for c in candidates {
        match std::fs::remove_file(&c.path) {
            Ok(()) => {
                info!(path = %c.path.display(), "pruned derive cache entry");
                deleted += 1;
                bytes += c.size;
            }
            Err(e) => {
                warn!(path = %c.path.display(), error = %e, "failed to prune derive cache entry");
                errors += 1;
            }
        }
    }

    (deleted, bytes, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServiceComponent, ServiceConfig};
    use tempfile::TempDir;

    fn svc(name: &str, components: Vec<ServiceComponent>) -> ServiceConfig {
        ServiceConfig {
            schema_version: 1,
            name: name.into(),
            domain: String::new(),
            components,
            db: crate::DbCatalog::default(),
        }
    }

    fn static_asset_component(id: &str, path: &str) -> ServiceComponent {
        ServiceComponent {
            id: id.into(),
            kind: "static-asset".into(),
            path: path.into(),
            role: String::new(),
            publishes: None,
            wave: 0,
            git: None,
        }
    }

    fn write_workload(dir: &Path, toml: &str) {
        if let Some(p) = dir.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("workload.toml"), toml).unwrap();
    }

    const FETCH_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OUTPUT_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn workload_with_fetch_only(fetch_hash: &str, output_hash: &str) -> String {
        format!(
            r#"[static-asset]
schema_version = "V1"

[[static-asset.asset]]
filename = "model.bin"
blake3 = "{output_hash}"

[static-asset.asset.derive.fetch]
url = "https://example.com/model.bin"
blake3 = "{fetch_hash}"
license = "mit"
"#
        )
    }

    fn workload_with_fetch_and_transform(fetch_hash: &str, output_hash: &str) -> String {
        format!(
            r#"[static-asset]
schema_version = "V1"

[[static-asset.asset]]
filename = "model.bin"
blake3 = "{output_hash}"

[static-asset.asset.derive.fetch]
url = "https://example.com/model.bin"
blake3 = "{fetch_hash}"
license = "mit"

[static-asset.asset.derive.transform]
recipe = "quantize"
"#
        )
    }

    #[test]
    fn collect_live_hashes_fetch_only() {
        let tmp = TempDir::new().unwrap();
        let workload_dir = tmp.path().join("app/web");
        write_workload(
            &workload_dir,
            &workload_with_fetch_only(FETCH_HASH, OUTPUT_HASH),
        );

        let svc = svc("my-svc", vec![static_asset_component("site", "app/web")]);
        let live = collect_live_derive_hashes(tmp.path(), [&svc]).unwrap();

        assert!(live.fetch.contains(FETCH_HASH), "fetch hash must be live");
        assert!(
            live.transform.is_empty(),
            "fetch-only asset has no transform cache entry"
        );
    }

    #[test]
    fn collect_live_hashes_fetch_and_transform() {
        let tmp = TempDir::new().unwrap();
        let workload_dir = tmp.path().join("app/web");
        write_workload(
            &workload_dir,
            &workload_with_fetch_and_transform(FETCH_HASH, OUTPUT_HASH),
        );

        let svc = svc("my-svc", vec![static_asset_component("site", "app/web")]);
        let live = collect_live_derive_hashes(tmp.path(), [&svc]).unwrap();

        assert!(live.fetch.contains(FETCH_HASH));
        assert!(
            live.transform.contains(OUTPUT_HASH),
            "transform cache entry keyed by output blake3"
        );
    }

    #[test]
    fn collect_live_hashes_missing_workload_skips_silently() {
        let tmp = TempDir::new().unwrap();
        // No workload.toml written.
        let svc = svc("my-svc", vec![static_asset_component("site", "app/web")]);
        let live = collect_live_derive_hashes(tmp.path(), [&svc]).unwrap();
        assert!(live.fetch.is_empty());
        assert!(live.transform.is_empty());
    }

    #[test]
    fn collect_live_hashes_ignores_non_static_asset_components() {
        let tmp = TempDir::new().unwrap();
        let svc = svc(
            "my-svc",
            vec![ServiceComponent {
                id: "api".into(),
                kind: "container".into(),
                path: "app/api".into(),
                role: String::new(),
                publishes: None,
                wave: 0,
                git: None,
            }],
        );
        let live = collect_live_derive_hashes(tmp.path(), [&svc]).unwrap();
        assert!(live.fetch.is_empty());
    }

    #[test]
    fn candidates_exclude_live_hashes() {
        let tmp = TempDir::new().unwrap();
        let fetch_dir = tmp.path().join("fetch");
        std::fs::create_dir_all(&fetch_dir).unwrap();

        // Live hash — must not be a candidate.
        std::fs::write(fetch_dir.join(format!("{FETCH_HASH}.bin")), b"live").unwrap();
        // Orphaned hash — must be a candidate.
        let orphan = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        std::fs::write(fetch_dir.join(format!("{orphan}.bin")), b"orphan").unwrap();
        // .partial file — must NOT be a candidate.
        std::fs::write(fetch_dir.join(format!("{orphan}.partial")), b"partial").unwrap();

        let mut live = DeriveCacheLiveHashes::default();
        live.fetch.insert(FETCH_HASH.to_string());

        let candidates = compute_derive_cache_candidates(tmp.path(), &live).unwrap();
        assert_eq!(candidates.len(), 1, "exactly one orphan");
        assert_eq!(candidates[0].hash, orphan);
        assert_eq!(candidates[0].cache_kind, "fetch");
    }

    #[test]
    fn execute_prune_deletes_candidates() {
        let tmp = TempDir::new().unwrap();
        let fetch_dir = tmp.path().join("fetch");
        std::fs::create_dir_all(&fetch_dir).unwrap();

        let file = fetch_dir.join("dead.bin");
        std::fs::write(&file, b"orphan bytes").unwrap();
        assert!(file.exists());

        let candidate = DerivePruneCandidate {
            path: file.clone(),
            cache_kind: "fetch",
            hash: "dead".into(),
            size: 12,
        };
        let (deleted, bytes, errors) = execute_derive_cache_prune(&[candidate]);
        assert_eq!(deleted, 1);
        assert_eq!(bytes, 12);
        assert_eq!(errors, 0);
        assert!(!file.exists(), "file must be deleted");
    }
}
