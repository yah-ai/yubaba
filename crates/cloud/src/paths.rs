//! On-disk path resolver for camp deployment manifests.
//!
//! Replaces the pre-R215 single-rooted `.yah/cloud/` layout. The new model
//! splits substrate ("where") from service declarations ("what"):
//!
//! ```text
//! .yah/
//!   infra/                                 # substrate registry — Infra tab
//!     machines/<name>.toml                 # provisioned hosts
//!     providers/<id>.toml                  # account/runtime bindings
//!     cloud-init/mirror.yml                # yubaba bootstrap template
//!     rules/<id>.yaml                      # tower alert rules
//!   services/<svc>/                        # operator-facing deployables — Services tab
//!     service.toml                         # name, domain, components
//!     mirrors/<env>.toml                   # service projection onto infra
//! ```
//!
//! Workload manifests stay colocated with the code they deploy (paths come
//! from `service.toml` components).
//!
//! All helpers take `workspace_root` (the camp dir, the parent of `.yah/`).
//! No helper does I/O — with one deliberate exception: [`machines_dir`] reads
//! `camp.toml` to honor a `[infra].inherit_machines` redirect, so a camp can
//! point its machine inventory at another camp's shared cluster. See its doc.
//!
//! @yah:relay(R222, "Service/infra manifest reshape — phases B2–B4")
//! @yah:at(2026-05-18T02:19:27Z)
//! @yah:status(handoff)
//! @yah:assignee(agent:claude)
//! @arch:see(.yah/docs/architecture/A031-yah-cloud-config-shape.md)
//! @yah:verify("cargo check -p cloud && cargo test -p cloud")
//! @yah:verify("cargo check -p yah && cargo check -p agent-tools")
//! @yah:verify("cargo check -p yah --tests && cargo check -p agent-tools --tests")
//! @yah:verify("CloudConfig::load(workspace_root) populates providers + services (with mirrors) from the seven Phase-A manifests")
//! @yah:cleanup("compose.rs + cli/cloud.rs bucket commands + handle_mirror{,_status} + collect_machine_services + derive_public_hostname likely deleted in B3-T2 — confirm against the yubaba integration story first")
//! @yah:cleanup("agent-tools/cloud_tools.rs's duplicate ServiceConfig/MirrorConfig collapses into a re-import once B3-T3/T4 stabilize the loader API")
//! @yah:cleanup("MachineConfig::save signature: tighten in B5 once .yah/infra/ vs .yah/cloud/ migration settles")
//! @yah:next("B4: schemars-generated JSON schemas → .yah/schema/{service,mirror,provider,workload,machine}.toml.schema.json. Implement as an xtask command (not a build script — keeps cloud's compile path clean). Drift test asserts generated == committed. Each manifest's #:schema directive points there.")
//! @yah:next("R222-T1: Update cloud.mirror_state + cloud.service_ports to read from .yah/services/ layout (currently silently empty in post-B2 workspaces).")
//! @yah:handoff("B2 landed (prev agent): Provider/ServiceConfig/MirrorConfig types in config.rs, cross-ref validation, 100+ tests passing.")
//! @yah:handoff("B3 landed: All cli/cloud.rs callers migrated off pre-B2 field names. cfg.mirrors → cfg.legacy_mirrors in machines_for_workload_name, workload_ident_for_machine, machines_for_service, workload-show block. cfg.mirror() → cfg.legacy_mirror() in collect_machine_services, derive_public_hostname, handle_mirror, handle_mirror_status. cfg.services.iter() → cfg.legacy_services.iter() in collect_machine_services. cargo check -p cloud/yah/agent-tools clean; 104 cloud tests pass. compose.rs + bucket commands left pending yubaba integration confirmation. R222-T1 filed for agent-tools cloud_tools.rs path update (.yah/services/ layout).")
//!
//! @yah:ticket(R615-T5, "Retire the inherit_machines stopgap: migrate noisetable to sources.toml, delete the camp.toml redirect")
//! @yah:at(2026-07-20T18:19:18Z)
//! @yah:status(open)
//! @yah:phase(P3)
//! @yah:parent(R615)
//! @yah:next("Author noisetable .yah/infra/sources.toml with a kind=path, mode=read-only source owner=yah path=../yah, and verify its Infra tab + yah cloud reconcile resolve the same machines they do today through inherit_machines.")
//! @yah:next("THEN delete the stopgap in the same pass — no coexistence. Remove paths.rs machines_dir inherited_machines_dir / inherited_machines_source, the [infra] inherit_machines key from noisetable camp.toml, and the InfraSection field from kg-store CampConfig + camp.toml.schema.json if nothing else uses it.")
//! @yah:verify("rg -n inherit_machines across the tree returns ZERO live hits outside archived docs")
//! @yah:verify("noisetable yah cloud validate stays ok and its Infra tab still lists yah cluster machines")
//! @yah:gotcha("Both mechanisms hook the SAME paths::machines_dir seam. If they coexist, resolution order becomes ambiguous and an operator cannot tell which one is winning. inherit_machines is a strict subset of the sources.toml kind=path case, so this is a pure replacement — do not build a compatibility shim.")
//! @yah:gotcha("Dropping InfraSection from CampConfig has a silent-data-loss hazard in reverse: the section was added so camp.toml round-trips without an old binary stripping [infra] on the next relay_high_water save. Confirm no camp.toml in any camp still carries the key before removing the struct field.")
//! @arch:see(.yah/docs/working/W274-linked-infra-sources.md)
//! @yah:depends_on(R615-F4)
//! @yah:tier(Cleric)

use std::path::{Path, PathBuf};

pub fn yah_dir(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".yah")
}

pub fn infra_dir(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("infra")
}

pub fn services_dir(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("services")
}

/// Directory holding this camp's machine inventory (`<name>.toml` per node).
///
/// Normally `<workspace_root>/.yah/infra/machines/`. But a camp that runs on a
/// cluster owned by another camp can inherit that cluster's node inventory by
/// declaring in its `camp.toml`:
///
/// ```toml
/// [infra]
/// inherit_machines = "../yah"   # path to the source camp, relative to this root
/// ```
///
/// When set, this returns `<inherit_machines>/.yah/infra/machines/` instead, so
/// the Infra tab, `CloudConfig::load`, fleet topology, and the coordinator all
/// resolve the shared nodes. Only the machine inventory is redirected —
/// providers, services, domains, and rules stay camp-local (a camp keeps its
/// own Cloudflare zone / credentials). Reading `camp.toml` here is the one I/O
/// exception among these helpers; any read/parse failure falls back to the
/// local dir, so an absent or malformed `camp.toml` is never fatal.
pub fn machines_dir(workspace_root: &Path) -> PathBuf {
    inherited_machines_dir(workspace_root)
        .unwrap_or_else(|| infra_dir(workspace_root).join("machines"))
}

/// If this camp inherits its machine inventory from another camp — i.e.
/// `camp.toml` declares a non-empty `[infra].inherit_machines` — return that
/// source path *as declared* (the raw relative string, e.g. `"../yah"`). `None`
/// when the camp owns its machines locally, or when `camp.toml` is absent /
/// malformed / has no key.
///
/// This is the guardrail hook: machine files resolved through [`machines_dir`]
/// then live under the *source* camp, so a write issued from this camp would
/// silently mutate the source camp's files. Editors gate on this to render
/// inherited machines read-only and point the operator at the source camp.
pub fn inherited_machines_source(workspace_root: &Path) -> Option<String> {
    let camp_toml = yah_dir(workspace_root).join("camp.toml");
    let src = std::fs::read_to_string(camp_toml).ok()?;
    let doc: toml::Value = toml::from_str(&src).ok()?;
    let rel = doc
        .get("infra")?
        .get("inherit_machines")?
        .as_str()?
        .trim();
    if rel.is_empty() {
        return None;
    }
    Some(rel.to_string())
}

/// Resolve a `[infra].inherit_machines` redirect from `<workspace_root>/.yah/camp.toml`,
/// if present and non-empty. Returns the source camp's `.yah/infra/machines`
/// directory, resolved relative to `workspace_root`. Any missing file, parse
/// error, or absent key yields `None` (caller falls back to the local dir).
fn inherited_machines_dir(workspace_root: &Path) -> Option<PathBuf> {
    let rel = inherited_machines_source(workspace_root)?;
    Some(
        workspace_root
            .join(rel)
            .join(".yah")
            .join("infra")
            .join("machines"),
    )
}

pub fn providers_dir(workspace_root: &Path) -> PathBuf {
    infra_dir(workspace_root).join("providers")
}

pub fn cloud_init_dir(workspace_root: &Path) -> PathBuf {
    infra_dir(workspace_root).join("cloud-init")
}

pub fn cloud_init_template(workspace_root: &Path) -> PathBuf {
    cloud_init_dir(workspace_root).join("mirror.yml")
}

pub fn rules_dir(workspace_root: &Path) -> PathBuf {
    infra_dir(workspace_root).join("rules")
}

pub fn machine_toml(workspace_root: &Path, name: &str) -> PathBuf {
    machines_dir(workspace_root).join(format!("{name}.toml"))
}

pub fn service_dir(workspace_root: &Path, service: &str) -> PathBuf {
    services_dir(workspace_root).join(service)
}

pub fn service_toml(workspace_root: &Path, service: &str) -> PathBuf {
    service_dir(workspace_root, service).join("service.toml")
}

pub fn service_mirrors_dir(workspace_root: &Path, service: &str) -> PathBuf {
    service_dir(workspace_root, service).join("mirrors")
}

pub fn service_mirror_toml(workspace_root: &Path, service: &str, env: &str) -> PathBuf {
    service_mirrors_dir(workspace_root, service).join(format!("{env}.toml"))
}

pub fn provider_toml(workspace_root: &Path, id: &str) -> PathBuf {
    providers_dir(workspace_root).join(format!("{id}.toml"))
}

pub fn domains_dir(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("domains")
}

pub fn domain_toml(workspace_root: &Path, name: &str) -> PathBuf {
    domains_dir(workspace_root).join(format!("{name}.toml"))
}

/// Pre-R215 root, kept for one release so we can read existing on-disk
/// state from a tool that wrote there. New writes go through the `infra_*`
/// / `service_*` helpers above.
pub fn legacy_cloud_dir(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("cloud")
}

/// Append-only journal for static-asset reconciler decisions (R470-T1).
/// One JSONL record per reconciler decision; replayed by `yah cloud status`.
pub fn asset_status_journal(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("cloud/status.jsonl")
}

/// Registry of app roots for fast discovery (R470-T7).
/// Populated by `yah cloud apps add <path>` / `yah cloud apps scan`.
pub fn apps_registry(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("apps.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_camp_toml(root: &Path, body: &str) {
        let yah = root.join(".yah");
        std::fs::create_dir_all(&yah).unwrap();
        std::fs::write(yah.join("camp.toml"), body).unwrap();
    }

    #[test]
    fn machines_dir_is_local_without_inherit() {
        let tmp = tempfile::TempDir::new().unwrap();
        // No camp.toml at all.
        assert_eq!(
            machines_dir(tmp.path()),
            tmp.path().join(".yah/infra/machines")
        );
        // camp.toml present but no [infra] section.
        write_camp_toml(tmp.path(), "name = \"solo\"\n");
        assert_eq!(
            machines_dir(tmp.path()),
            tmp.path().join(".yah/infra/machines")
        );
    }

    #[test]
    fn machines_dir_redirects_on_inherit() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_camp_toml(
            tmp.path(),
            "name = \"noisetable\"\n[infra]\ninherit_machines = \"../yah\"\n",
        );
        assert_eq!(
            machines_dir(tmp.path()),
            tmp.path().join("../yah/.yah/infra/machines")
        );
        // machine_toml builds on machines_dir, so it inherits the redirect.
        assert_eq!(
            machine_toml(tmp.path(), "us-west-001"),
            tmp.path().join("../yah/.yah/infra/machines/us-west-001.toml")
        );
    }

    #[test]
    fn empty_inherit_falls_back_to_local() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_camp_toml(tmp.path(), "[infra]\ninherit_machines = \"\"\n");
        assert_eq!(
            machines_dir(tmp.path()),
            tmp.path().join(".yah/infra/machines")
        );
    }

    #[test]
    fn inherited_source_reports_declared_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        // No camp.toml → owns machines locally.
        assert_eq!(inherited_machines_source(tmp.path()), None);
        // Declared, non-empty → returns the raw relative string.
        write_camp_toml(tmp.path(), "[infra]\ninherit_machines = \"../yah\"\n");
        assert_eq!(
            inherited_machines_source(tmp.path()).as_deref(),
            Some("../yah")
        );
        // Empty string → treated as not-inherited.
        write_camp_toml(tmp.path(), "[infra]\ninherit_machines = \"\"\n");
        assert_eq!(inherited_machines_source(tmp.path()), None);
    }

    #[test]
    fn only_machines_redirect_providers_stay_local() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_camp_toml(tmp.path(), "[infra]\ninherit_machines = \"../yah\"\n");
        // Providers, rules, services, domains are NOT redirected — a camp keeps
        // its own credentials/zones even while sharing another camp's nodes.
        assert_eq!(
            providers_dir(tmp.path()),
            tmp.path().join(".yah/infra/providers")
        );
        assert_eq!(rules_dir(tmp.path()), tmp.path().join(".yah/infra/rules"));
        assert_eq!(
            services_dir(tmp.path()),
            tmp.path().join(".yah/services")
        );
    }
}
