//! Workspace-wide lint checks for the `.yah/services/` tree (R470-T3).
//!
//! Currently implements one check: **alias collision** — alias names declared
//! in any service component's `[aliases]` block must be workspace-globally
//! unique. Two services declaring the same alias is a consumer-site ambiguity
//! (`yah-app.toml` says `alias = "whisper-default-ggml"` — which catalog
//! wins?).
//!
//! Invoked by `yah cloud validate` and as a preflight in `yah cloud apply`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

use crate::config::ServiceConfig;
use crate::paths::services_dir;

/// Where an alias is declared — points the operator at the source row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasSource {
    /// Service name (matches `service.toml`'s `name` field).
    pub service: String,
    /// Component `id` within that service.
    pub component_id: String,
    /// Absolute path to the `workload.toml` containing the `[aliases]` block.
    pub workload_toml: PathBuf,
}

/// A duplicate alias declaration found across two components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasCollision {
    pub alias: String,
    pub first: AliasSource,
    pub second: AliasSource,
}

impl AliasCollision {
    /// Human-readable error message matching the format described in W193.
    pub fn message(&self) -> String {
        format!(
            "alias {:?} declared in both {} (component {}) and {} (component {})\n\
             \u{2192} rename the alias in one of these files:\n  {}\n  {}",
            self.alias,
            self.first.service,
            self.first.component_id,
            self.second.service,
            self.second.component_id,
            self.first.workload_toml.display(),
            self.second.workload_toml.display(),
        )
    }
}

/// Walk every service's static-asset components and collect all `(alias →
/// source)` mappings. Returns a list of collisions (empty when clean).
///
/// Missing `.yah/services/` directory is not an error — returns empty.
pub fn check_alias_collisions(workspace_root: &Path) -> anyhow::Result<Vec<AliasCollision>> {
    let dir = services_dir(workspace_root);
    if !dir.exists() {
        return Ok(vec![]);
    }

    // alias_name → first source seen
    let mut seen: BTreeMap<String, AliasSource> = BTreeMap::new();
    let mut collisions = Vec::new();

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let svc_dir = entry.path();
        let service_toml = svc_dir.join("service.toml");
        if !service_toml.exists() {
            continue;
        }
        let service = match ServiceConfig::load(&service_toml) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    path = %service_toml.display(),
                    error = %e,
                    "skipping service with unparseable service.toml"
                );
                continue;
            }
        };

        for component in &service.components {
            if component.kind != "static-asset" {
                continue;
            }
            let workload_dir = workspace_root.join(&component.path);
            let workload_toml_path = workload_dir.join("workload.toml");
            if !workload_toml_path.exists() {
                continue;
            }

            let aliases = match load_static_asset_aliases(&workload_toml_path) {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(
                        path = %workload_toml_path.display(),
                        error = %e,
                        "skipping workload.toml with parse error"
                    );
                    continue;
                }
            };

            for alias_name in aliases.keys() {
                let source = AliasSource {
                    service: service.name.clone(),
                    component_id: component.id.clone(),
                    workload_toml: workload_toml_path.clone(),
                };
                if let Some(first) = seen.get(alias_name) {
                    collisions.push(AliasCollision {
                        alias: alias_name.clone(),
                        first: first.clone(),
                        second: source,
                    });
                } else {
                    seen.insert(alias_name.clone(), source);
                }
            }
        }
    }

    Ok(collisions)
}

/// Load the `[aliases]` block from a `workload.toml` that must be a
/// `static-asset` kind. Returns an empty map for non-static-asset workloads
/// (so the caller skips them silently).
fn load_static_asset_aliases(
    path: &Path,
) -> anyhow::Result<BTreeMap<String, String>> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let workload: workload_spec::Workload =
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
    match workload {
        workload_spec::Workload::StaticAsset(w) => Ok(w.aliases),
        _ => Ok(BTreeMap::new()),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_service(workspace: &Path, svc_name: &str, component_path: &str) {
        let svc_dir = workspace.join(".yah/services").join(svc_name);
        std::fs::create_dir_all(&svc_dir).unwrap();
        let toml = format!(
            "schema_version = 1\nname = \"{svc_name}\"\ndomain = \"{svc_name}.example.com\"\n\
             [[components]]\nid = \"models\"\nkind = \"static-asset\"\n\
             path = \"{component_path}\"\nrole = \"static\"\n"
        );
        std::fs::write(svc_dir.join("service.toml"), toml).unwrap();
    }

    fn write_workload_with_aliases(dir: &Path, aliases: &[(&str, &str)]) {
        std::fs::create_dir_all(dir).unwrap();
        let alias_lines: String = aliases
            .iter()
            .map(|(k, v)| format!("\"{k}\" = \"{v}\"\n"))
            .collect();
        let content = format!(
            "schema_version = \"V1\"\nname = \"models\"\nkind = \"static-asset\"\n\
             [aliases]\n{alias_lines}"
        );
        std::fs::write(dir.join("workload.toml"), content).unwrap();
    }

    #[test]
    fn cloud_validate_clean_workspace_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        write_service(root, "svc-a", "svc-a/models");
        write_workload_with_aliases(
            &root.join("svc-a/models"),
            &[("whisper-default-ggml", "svc-a/whisper/model.bin")],
        );

        let collisions = check_alias_collisions(root).unwrap();
        assert!(collisions.is_empty(), "expected no collisions: {collisions:?}");
    }

    #[test]
    fn cloud_validate_rejects_alias_collision() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        write_service(root, "svc-a", "svc-a/models");
        write_workload_with_aliases(
            &root.join("svc-a/models"),
            &[("whisper-default-ggml", "svc-a/whisper/model.bin")],
        );

        write_service(root, "svc-b", "svc-b/models");
        write_workload_with_aliases(
            &root.join("svc-b/models"),
            &[("whisper-default-ggml", "svc-b/whisper/model.bin")],
        );

        let collisions = check_alias_collisions(root).unwrap();
        assert_eq!(collisions.len(), 1, "expected one collision: {collisions:?}");
        let c = &collisions[0];
        assert_eq!(c.alias, "whisper-default-ggml");
        assert_eq!(c.first.service, "svc-a");
        assert_eq!(c.second.service, "svc-b");

        let msg = c.message();
        assert!(msg.contains("whisper-default-ggml"), "message: {msg}");
        assert!(msg.contains("svc-a"), "message: {msg}");
        assert!(msg.contains("svc-b"), "message: {msg}");
    }

    #[test]
    fn cloud_validate_distinct_aliases_no_collision() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        write_service(root, "svc-a", "svc-a/models");
        write_workload_with_aliases(
            &root.join("svc-a/models"),
            &[
                ("whisper-default-ggml", "svc-a/model.bin"),
                ("whisper-default", "svc-a/model.bin"),
            ],
        );

        write_service(root, "svc-b", "svc-b/models");
        write_workload_with_aliases(
            &root.join("svc-b/models"),
            &[("whisper-default-coreml", "svc-b/model.tar.gz")],
        );

        let collisions = check_alias_collisions(root).unwrap();
        assert!(collisions.is_empty());
    }

    #[test]
    fn cloud_validate_multiple_collisions_all_reported() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        write_service(root, "svc-a", "svc-a/models");
        write_workload_with_aliases(
            &root.join("svc-a/models"),
            &[
                ("alias-one", "svc-a/one.bin"),
                ("alias-two", "svc-a/two.bin"),
            ],
        );

        write_service(root, "svc-b", "svc-b/models");
        write_workload_with_aliases(
            &root.join("svc-b/models"),
            &[
                ("alias-one", "svc-b/one.bin"),
                ("alias-two", "svc-b/two.bin"),
            ],
        );

        let collisions = check_alias_collisions(root).unwrap();
        assert_eq!(collisions.len(), 2);
        let names: Vec<_> = collisions.iter().map(|c| c.alias.as_str()).collect();
        assert!(names.contains(&"alias-one"));
        assert!(names.contains(&"alias-two"));
    }

    #[test]
    fn cloud_validate_missing_services_dir_is_not_error() {
        let dir = tempdir().unwrap();
        let collisions = check_alias_collisions(dir.path()).unwrap();
        assert!(collisions.is_empty());
    }

    #[test]
    fn cloud_validate_non_static_asset_workloads_ignored() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        write_service(root, "svc-a", "svc-a/api");
        // Write a container workload — no [aliases] block, should be silently skipped.
        let workload_dir = root.join("svc-a/api");
        std::fs::create_dir_all(&workload_dir).unwrap();
        // Just make the kind non-static-asset to ensure we skip it.
        // (Writes a valid mesofact-static workload which has no aliases)
        std::fs::write(
            workload_dir.join("workload.toml"),
            "schema_version = \"V1\"\nname = \"api\"\nkind = \"mesofact-static\"\n\
             bundle_dir = \"dist\"\n",
        )
        .unwrap();

        let collisions = check_alias_collisions(root).unwrap();
        assert!(collisions.is_empty());
    }
}
