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
//! No helper does I/O; callers decide when to read/write.
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

pub fn machines_dir(workspace_root: &Path) -> PathBuf {
    infra_dir(workspace_root).join("machines")
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
