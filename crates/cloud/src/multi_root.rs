//! Multi-root cloud config — union sibling `.X/` config trees (W206 layout (b)).
//!
//! Part of R558-F4; the ticket annotation lives in
//! `.yah/docs/working/W206-yubaba-namespace-tenancy-axes.md`.
//!
//! Today a yubaba reconciler reads exactly one config tree (`.yah/`, via
//! [`CloudConfig::load`]). W206 adds a second consumer (noisetable) that keeps
//! its declarations in its own repo, materialized as a sibling `.noisetable/`
//! tree next to `.yah/`. Rather than annotate every TOML with a `namespace`
//! (layout (a)), the recommended layout (b) gives each project its own config
//! root and teaches the reconciler to **union** the roots.
//!
//! This module is that union layer:
//!
//! - [`ConfigRoot`] — one `.X/` directory plus the `(tenant, namespace)` every
//!   workload it declares belongs to. Namespace defaults to the directory name
//!   with the leading dot stripped (`.noisetable` → `noisetable`); a
//!   `<dir>/namespace.toml` marker can set the tenant and override the
//!   namespace. This is the **per-directory** invariant from W206's open
//!   questions: one namespace per root, no per-file override.
//! - [`MultiRootConfig`] — the loaded, validated union. Loading rejects two
//!   roots that claim the same `(tenant, namespace)` and validates that
//!   `(tenant, namespace, name)` is unique across every workload/service in the
//!   union (the safety net that makes friendly co-residence collision-proof).
//! - [`discover`] — auto-find sibling `.X/` roots under a parent directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use workload_spec::{NamespaceId, TenantId, WorkloadSpec};

use crate::config::CloudConfig;

/// Optional per-root marker (`<config_dir>/namespace.toml`) declaring the
/// tenant and (optionally) overriding the directory-derived namespace.
///
/// ```toml
/// tenant = "ss"            # optional; defaults to the singleton tenant
/// namespace = "noisetable" # optional; defaults to the dir name sans leading dot
/// ```
#[derive(Debug, Default, Deserialize)]
struct RootMarker {
    tenant: Option<String>,
    namespace: Option<String>,
}

/// One config root and the `(tenant, namespace)` identity every workload it
/// declares belongs to. See the [module docs](self) for the per-directory
/// invariant this enforces.
#[derive(Debug, Clone)]
pub struct ConfigRoot {
    /// The `.X/` directory itself (e.g. `<parent>/.noisetable`).
    pub config_dir: PathBuf,
    /// The camp dir (the config dir's parent) — component `path` references
    /// resolve against this, matching [`CloudConfig::load`].
    pub workspace_root: PathBuf,
    /// Isolation axis. Every workload loaded from this root is stamped with it.
    pub tenant: TenantId,
    /// Routing/naming axis. Every workload loaded from this root is stamped
    /// with it; it cannot be overridden per-file.
    pub namespace: NamespaceId,
}

impl ConfigRoot {
    /// Build a [`ConfigRoot`] from a `.X/` directory, reading the optional
    /// `namespace.toml` marker. The namespace defaults to the directory name
    /// with its leading dot stripped; the tenant defaults to the singleton.
    /// `workspace_root` is the config dir's parent.
    pub fn from_config_dir(config_dir: &Path, workspace_root: &Path) -> Result<Self> {
        let dir_name = config_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                anyhow::anyhow!("config root {} has no usable name", config_dir.display())
            })?;
        let derived_ns = dir_name.strip_prefix('.').unwrap_or(dir_name).to_string();

        let marker_path = config_dir.join("namespace.toml");
        let marker: RootMarker = if marker_path.exists() {
            let text = std::fs::read_to_string(&marker_path)
                .with_context(|| format!("reading {}", marker_path.display()))?;
            toml::from_str(&text)
                .with_context(|| format!("parsing {}", marker_path.display()))?
        } else {
            RootMarker::default()
        };

        let tenant = marker
            .tenant
            .map(TenantId)
            .unwrap_or_else(TenantId::singleton);
        let namespace = NamespaceId(marker.namespace.unwrap_or(derived_ns));

        Ok(Self {
            config_dir: config_dir.to_path_buf(),
            workspace_root: workspace_root.to_path_buf(),
            tenant,
            namespace,
        })
    }
}

/// A single loaded root: its `(tenant, namespace)` identity plus the
/// [`CloudConfig`] read from its tree.
#[derive(Debug)]
pub struct LoadedRoot {
    pub config_dir: PathBuf,
    pub tenant: TenantId,
    pub namespace: NamespaceId,
    pub config: CloudConfig,
}

impl LoadedRoot {
    /// Stamp this root's `(tenant, namespace)` onto a workload spec, enforcing
    /// the per-directory invariant: whatever the on-disk `workload.toml` said
    /// for these axes is overwritten by the root it was loaded from.
    pub fn stamp(&self, spec: &mut WorkloadSpec) {
        spec.tenant = self.tenant.clone();
        spec.namespace = self.namespace.clone();
    }

    /// Every workload/service name declared by this root (service names from the
    /// R215+ tree plus any legacy `.yah/cloud/workloads/` names).
    fn declared_names(&self) -> impl Iterator<Item = String> + '_ {
        self.config
            .services
            .keys()
            .cloned()
            .chain(self.config.workloads.iter().map(|w| w.spec.name.clone()))
    }
}

/// The loaded, validated union of sibling `.X/` config trees.
#[derive(Debug)]
pub struct MultiRootConfig {
    pub roots: Vec<LoadedRoot>,
}

impl MultiRootConfig {
    /// Load and union every [`ConfigRoot`], then validate the union.
    ///
    /// Fails if two roots declare the same `(tenant, namespace)` pair (each
    /// sibling tree must own a distinct namespace) or if any
    /// `(tenant, namespace, name)` triple is claimed twice across the union.
    pub fn load(roots: &[ConfigRoot]) -> Result<Self> {
        let mut loaded = Vec::with_capacity(roots.len());
        let mut seen_ns: BTreeMap<(TenantId, NamespaceId), PathBuf> = BTreeMap::new();

        for root in roots {
            let key = (root.tenant.clone(), root.namespace.clone());
            if let Some(prev) = seen_ns.insert(key, root.config_dir.clone()) {
                bail!(
                    "two config roots declare the same (tenant={}, namespace={}): \
                     {} and {} — each sibling tree needs a distinct namespace \
                     (W206 per-directory invariant)",
                    root.tenant.0,
                    root.namespace.0,
                    prev.display(),
                    root.config_dir.display(),
                );
            }
            let config = CloudConfig::load_from_config_dir(&root.config_dir, &root.workspace_root)?;
            loaded.push(LoadedRoot {
                config_dir: root.config_dir.clone(),
                tenant: root.tenant.clone(),
                namespace: root.namespace.clone(),
                config,
            });
        }

        let out = Self { roots: loaded };
        out.validate_uniqueness()?;
        Ok(out)
    }

    /// Validate that `(tenant, namespace, name)` is unique across every workload
    /// and service in the union. Two namespaces in the same tenant *may* reuse a
    /// name — that's the namespace's whole job — but a single
    /// `(tenant, namespace)` pair must not, or the reconciler would silently
    /// clobber one workload with another.
    fn validate_uniqueness(&self) -> Result<()> {
        let mut seen: BTreeMap<(TenantId, NamespaceId, String), PathBuf> = BTreeMap::new();
        for root in &self.roots {
            for name in root.declared_names() {
                let key = (root.tenant.clone(), root.namespace.clone(), name.clone());
                if let Some(prev) = seen.insert(key, root.config_dir.clone()) {
                    bail!(
                        "workload name collision: (tenant={}, namespace={}, name={}) \
                         is declared in both {} and {}",
                        root.tenant.0,
                        root.namespace.0,
                        name,
                        prev.display(),
                        root.config_dir.display(),
                    );
                }
            }
        }
        Ok(())
    }
}

/// Auto-discover sibling `.X/` config roots under `parent`.
///
/// A directory qualifies when its name starts with `.` and it contains a
/// `services/` or `infra/` subtree — so `.yah` and `.noisetable` are picked up
/// while `.git`, `.DS_Store`, and stray dotfiles are not. Roots are returned in
/// deterministic (directory-name) order. Each root's `(tenant, namespace)` is
/// resolved via [`ConfigRoot::from_config_dir`].
pub fn discover(parent: &Path) -> Result<Vec<ConfigRoot>> {
    if !parent.is_dir() {
        return Ok(vec![]);
    }
    let mut entries: Vec<_> = std::fs::read_dir(parent)
        .with_context(|| format!("reading {}", parent.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map_or(false, |n| n.starts_with('.'))
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut roots = vec![];
    for entry in entries {
        let dir = entry.path();
        if !dir.join("services").is_dir() && !dir.join("infra").is_dir() {
            continue;
        }
        roots.push(ConfigRoot::from_config_dir(&dir, parent)?);
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a minimal service under `<config_dir>/services/<name>/service.toml`.
    fn write_service(config_dir: &Path, name: &str) {
        let dir = config_dir.join("services").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("service.toml"),
            format!(
                "schema_version = 1\nname = \"{name}\"\ndomain = \"{name}.example\"\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn namespace_defaults_to_dir_name_sans_dot() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".noisetable");
        std::fs::create_dir_all(dir.join("services")).unwrap();
        let root = ConfigRoot::from_config_dir(&dir, tmp.path()).unwrap();
        assert_eq!(root.namespace.0, "noisetable");
        assert!(root.tenant.is_singleton());
    }

    #[test]
    fn marker_sets_tenant_and_overrides_namespace() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".noisetable");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("namespace.toml"),
            "tenant = \"ss\"\nnamespace = \"nt\"\n",
        )
        .unwrap();
        let root = ConfigRoot::from_config_dir(&dir, tmp.path()).unwrap();
        assert_eq!(root.tenant.0, "ss");
        assert_eq!(root.namespace.0, "nt");
    }

    #[test]
    fn discover_finds_config_dirs_skips_non_config_dotdirs() {
        let tmp = tempfile::tempdir().unwrap();
        write_service(&tmp.path().join(".yah"), "web");
        write_service(&tmp.path().join(".noisetable"), "site");
        // A dotdir with neither services/ nor infra/ is ignored.
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        let roots = discover(tmp.path()).unwrap();
        let names: Vec<&str> = roots.iter().map(|r| r.namespace.0.as_str()).collect();
        assert_eq!(names, vec!["noisetable", "yah"]); // sorted by dir name
    }

    #[test]
    fn union_of_distinct_namespaces_loads() {
        let tmp = tempfile::tempdir().unwrap();
        write_service(&tmp.path().join(".yah"), "web");
        write_service(&tmp.path().join(".noisetable"), "site");

        let roots = discover(tmp.path()).unwrap();
        let multi = MultiRootConfig::load(&roots).unwrap();
        assert_eq!(multi.roots.len(), 2);
    }

    #[test]
    fn same_name_across_namespaces_is_allowed() {
        // Two namespaces reusing "web" is fine — that's what namespaces are for.
        let tmp = tempfile::tempdir().unwrap();
        write_service(&tmp.path().join(".yah"), "web");
        write_service(&tmp.path().join(".noisetable"), "web");

        let roots = discover(tmp.path()).unwrap();
        MultiRootConfig::load(&roots).unwrap();
    }

    #[test]
    fn duplicate_namespace_across_roots_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        // Two different dirs both forced to namespace "shared" via markers.
        for d in [".a", ".b"] {
            let dir = tmp.path().join(d);
            std::fs::create_dir_all(dir.join("services")).unwrap();
            std::fs::write(dir.join("namespace.toml"), "namespace = \"shared\"\n").unwrap();
        }
        let roots = discover(tmp.path()).unwrap();
        let err = MultiRootConfig::load(&roots).unwrap_err().to_string();
        assert!(err.contains("same (tenant"), "got: {err}");
    }

    #[test]
    fn stamp_overwrites_spec_axes() {
        let tmp = tempfile::tempdir().unwrap();
        write_service(&tmp.path().join(".noisetable"), "site");
        std::fs::write(
            tmp.path().join(".noisetable").join("namespace.toml"),
            "tenant = \"ss\"\n",
        )
        .unwrap();
        let roots = discover(tmp.path()).unwrap();
        let multi = MultiRootConfig::load(&roots).unwrap();
        let root = &multi.roots[0];

        use workload_spec::{ImageRef, TierTag};
        let mut spec = WorkloadSpec::for_forge(
            "some-workload",
            ImageRef {
                registry: "docker.io".into(),
                repository: "library/busybox".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            TierTag("private".into()),
            vec![],
        );
        // Pretend the file claimed a different identity.
        spec.tenant = TenantId("wrong".into());
        spec.namespace = NamespaceId("wrong".into());
        root.stamp(&mut spec);
        assert_eq!(spec.tenant.0, "ss");
        assert_eq!(spec.namespace.0, "noisetable");
    }
}
