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

use crate::config::{MirrorConfig, MirrorProviderSlot, Provider, ServiceConfig};
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
fn load_static_asset_aliases(path: &Path) -> anyhow::Result<BTreeMap<String, String>> {
    let src =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let workload: workload_spec::Workload =
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
    match workload {
        workload_spec::Workload::StaticAsset(w) => Ok(w.aliases),
        _ => Ok(BTreeMap::new()),
    }
}

// ── Port collisions (R602-B4) ────────────────────────────────────────────────

/// Where a host port is declared — points the operator at the (service, env,
/// slot) that binds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSource {
    /// Service name (matches `service.toml`'s `name` field).
    pub service: String,
    /// Environment (file stem of `mirrors/<env>.toml`).
    pub env: String,
    /// Provider slot role the port sits under (`providers.<role>`).
    pub slot_role: String,
    /// The field that carried the port (`port` / `api_port` / `console_port`).
    pub field: String,
}

/// Two local-tier mirror slots that bind the same host port. Because local
/// mirrors share the operator's localhost, both binding the same port collide
/// when brought up together — and the local-static adopt probe (a bare TCP
/// connect) may then silently adopt the *wrong* service (R602-B4: `scrabcake`
/// dev and `yah-marketing` pond both on 4322).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortCollision {
    pub port: u16,
    pub first: PortSource,
    pub second: PortSource,
}

impl PortCollision {
    /// True when the two binders belong to different services — the dangerous
    /// case, because the local-static adopt probe can then silently adopt the
    /// *other* service's server. Same-service reuse (e.g. one service's dev +
    /// cloud mirrors sharing a port) is only a can't-co-run bind conflict.
    pub fn is_cross_service(&self) -> bool {
        self.first.service != self.second.service
    }

    /// Human-readable error naming both binders + the fix.
    pub fn message(&self) -> String {
        format!(
            "host port {} is bound by both {}/{} (providers.{}.{}) and {}/{} (providers.{}.{})\n\
             \u{2192} give one a distinct port — local mirrors share the operator's localhost, so \
             two slots on the same port collide, and the local-static adopt probe may silently \
             adopt the wrong service.",
            self.port,
            self.first.service,
            self.first.env,
            self.first.slot_role,
            self.first.field,
            self.second.service,
            self.second.env,
            self.second.slot_role,
            self.second.field,
        )
    }
}

/// Host-port field names a local-binding mirror slot may declare.
const PORT_FIELDS: &[&str] = &["port", "api_port", "console_port"];

/// True when this slot binds a port on the operator's localhost, so its port
/// contends with every other local slot. Reference slots (`use = "..."`) and
/// cloud/CF slots don't bind localhost and are skipped.
fn slot_binds_localhost(slot: &MirrorProviderSlot) -> bool {
    matches!(
        slot.inline_kind(),
        Some(Provider::LocalStatic | Provider::MiniflareContainer | Provider::MinioContainer)
    )
}

/// Walk every service mirror and flag host-port reuse across local-tier
/// provider slots (R602-B4). Only slots that bind a port on the operator's
/// localhost are considered (`local-static`, `miniflare-container`,
/// `minio-container`) — cloud/CF slots don't contend for localhost.
///
/// Deterministic: services + mirror envs are walked in sorted order, slot
/// roles sorted, `PORT_FIELDS` in declared order — so the "first" binder of a
/// port is stable across runs. Missing `.yah/services/` is not an error.
pub fn check_port_collisions(workspace_root: &Path) -> anyhow::Result<Vec<PortCollision>> {
    let dir = services_dir(workspace_root);
    if !dir.exists() {
        return Ok(vec![]);
    }

    // port → first source seen
    let mut seen: BTreeMap<u16, PortSource> = BTreeMap::new();
    let mut collisions = Vec::new();

    let mut svc_entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    svc_entries.sort_by_key(|e| e.file_name());

    for entry in svc_entries {
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

        let mirrors_dir = svc_dir.join("mirrors");
        if !mirrors_dir.exists() {
            continue;
        }
        let mut mirror_entries: Vec<_> = std::fs::read_dir(&mirrors_dir)
            .with_context(|| format!("reading {}", mirrors_dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "toml"))
            .collect();
        mirror_entries.sort_by_key(|e| e.file_name());

        for m in mirror_entries {
            let path = m.path();
            let env = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let mirror = match MirrorConfig::load(&path) {
                Ok(mc) => mc,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "skipping mirror with parse error"
                    );
                    continue;
                }
            };

            let mut roles: Vec<&String> = mirror.providers.keys().collect();
            roles.sort();
            for role in roles {
                let slot = &mirror.providers[role];
                if !slot_binds_localhost(slot) {
                    continue;
                }
                for field in PORT_FIELDS {
                    let Some(port) = crate::reconciler::slot_field_u16(slot.fields(), field) else {
                        continue;
                    };
                    let source = PortSource {
                        service: service.name.clone(),
                        env: env.clone(),
                        slot_role: role.clone(),
                        field: (*field).to_string(),
                    };
                    match seen.get(&port) {
                        Some(first) => collisions.push(PortCollision {
                            port,
                            first: first.clone(),
                            second: source,
                        }),
                        None => {
                            seen.insert(port, source);
                        }
                    }
                }
            }
        }
    }

    Ok(collisions)
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
            "[static-asset]\nschema_version = \"V1\"\n\
             [static-asset.aliases]\n{alias_lines}"
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
        assert!(
            collisions.is_empty(),
            "expected no collisions: {collisions:?}"
        );
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
        assert_eq!(
            collisions.len(),
            1,
            "expected one collision: {collisions:?}"
        );
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

    // ── Port collisions (R602-B4) ────────────────────────────────────────────

    fn write_mirror(workspace: &Path, svc: &str, env: &str, body: &str) {
        let dir = workspace.join(".yah/services").join(svc).join("mirrors");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{env}.toml")), body).unwrap();
    }

    fn local_static_mirror(port: u16) -> String {
        format!(
            "schema_version = 1\nshape = \"local\"\n\
             [providers.static]\nkind = \"local-static\"\nport = {port}\n"
        )
    }

    #[test]
    fn port_collision_across_services_and_envs_is_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_service(root, "scrabcake", "scrabcake/site");
        write_mirror(root, "scrabcake", "dev", &local_static_mirror(4322));
        write_service(root, "yah-marketing", "yah-marketing/site");
        write_mirror(
            root,
            "yah-marketing",
            "pond",
            "schema_version = 1\nshape = \"local\"\n\
             [providers.static]\nkind = \"miniflare-container\"\nport = 4322\n",
        );

        let cols = check_port_collisions(root).unwrap();
        assert_eq!(cols.len(), 1, "{cols:?}");
        assert_eq!(cols[0].port, 4322);
        // Deterministic: "scrabcake" sorts before "yah-marketing".
        assert_eq!(cols[0].first.service, "scrabcake");
        assert_eq!(cols[0].second.service, "yah-marketing");
        assert!(cols[0].is_cross_service(), "different services collide");
        let msg = cols[0].message();
        assert!(msg.contains("4322"), "{msg}");
        assert!(msg.contains("scrabcake"), "{msg}");
        assert!(msg.contains("yah-marketing"), "{msg}");
    }

    #[test]
    fn distinct_ports_no_collision() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_service(root, "a", "a/site");
        write_mirror(root, "a", "dev", &local_static_mirror(4322));
        write_service(root, "b", "b/site");
        write_mirror(root, "b", "dev", &local_static_mirror(4323));
        assert!(check_port_collisions(root).unwrap().is_empty());
    }

    #[test]
    fn same_service_two_envs_reusing_a_port_is_flagged() {
        // The ticket's "scrabcake cloud+dev reuse <port> twice more" shape.
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_service(root, "scrabcake", "scrabcake/site");
        write_mirror(root, "scrabcake", "dev", &local_static_mirror(4352));
        write_mirror(root, "scrabcake", "cloud", &local_static_mirror(4352));
        let cols = check_port_collisions(root).unwrap();
        assert_eq!(cols.len(), 1, "{cols:?}");
        assert_eq!(cols[0].port, 4352);
        // "cloud" sorts before "dev".
        assert_eq!(cols[0].first.env, "cloud");
        assert_eq!(cols[0].second.env, "dev");
        assert!(
            !cols[0].is_cross_service(),
            "same service across envs is NOT cross-service"
        );
    }

    #[test]
    fn reference_slots_do_not_bind_localhost_and_are_ignored() {
        // A `use = "..."` reference slot points at a cloud provider — reusing a
        // `port` field there is not a localhost collision.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ref_slot = "schema_version = 1\nshape = \"local\"\n\
             [providers.static]\nuse = \"cloudflare\"\nport = 8080\n";
        write_service(root, "a", "a/site");
        write_mirror(root, "a", "cloud", ref_slot);
        write_service(root, "b", "b/site");
        write_mirror(root, "b", "cloud", ref_slot);
        assert!(check_port_collisions(root).unwrap().is_empty());
    }

    #[test]
    fn minio_api_and_console_ports_collide_across_ponds() {
        // Two pond MinIO slots on the same api_port bind the same host port.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let minio = "schema_version = 1\nshape = \"local\"\n\
             [providers.object_store]\nkind = \"minio-container\"\napi_port = 9000\nconsole_port = 9001\n";
        write_service(root, "a", "a/site");
        write_mirror(root, "a", "pond", minio);
        write_service(root, "b", "b/site");
        write_mirror(root, "b", "pond", minio);
        let cols = check_port_collisions(root).unwrap();
        // Both api_port (9000) and console_port (9001) collide.
        assert_eq!(cols.len(), 2, "{cols:?}");
        let ports: Vec<u16> = cols.iter().map(|c| c.port).collect();
        assert!(ports.contains(&9000));
        assert!(ports.contains(&9001));
    }

    #[test]
    fn missing_services_dir_is_not_error_for_ports() {
        let dir = tempdir().unwrap();
        assert!(check_port_collisions(dir.path()).unwrap().is_empty());
    }
}
