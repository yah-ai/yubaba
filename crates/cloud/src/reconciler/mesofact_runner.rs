//! [`Reconciler`] skeleton for `kind = "mesofact-runner"` components (R330-F11).
//!
//! Skeleton-only — `up()` validates the mirror has the F16 placement
//! constraint (`[providers.compute] required.mesh_tags`) and that a
//! workspace machine satisfies it, then bails with a "wiring pending"
//! error so a dispatcher arm doesn't silently report success.
//!
//! The dispatcher wiring (`app/yah/cli/src/cloud.rs::reconcile_component`
//! + `app/yah/desktop/src/mirror_run.rs`) and the live warden bring-up
//! land in a follow-up slice — see R330-F11's handoff annotation for the
//! cut-list.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use super::{ReconcileCtx, Reconciler, RunningWorkload};
use crate::config::CloudConfig;

/// Workload kind this reconciler handles.
pub const WORKLOAD_KIND: &str = "mesofact-runner";

/// Reconciles `kind = "mesofact-runner"` components onto a cloud-tier
/// runner machine selected by mesh-tag superset (F16).
pub struct MesofactRunnerReconciler;

impl MesofactRunnerReconciler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MesofactRunnerReconciler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Reconciler for MesofactRunnerReconciler {
    fn kind(&self) -> &'static str {
        WORKLOAD_KIND
    }

    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        // Validate placement constraints up front — same fail-fast
        // discipline as cloudflare-worker / mesofact-static. The F16
        // resolver runs at a higher layer (cloud.rs apply loop) once the
        // dispatcher arm is wired; here we surface a structured error
        // rather than silently no-op so a misconfigured mirror gets a
        // clear message.
        let slot = ctx.slot("compute").with_context(|| {
            format!(
                "mirror has no `providers.compute` slot — required for the mesofact-runner component (service={}, env={})",
                ctx.service.name, ctx.env,
            )
        })?;

        let required = slot.required().ok_or_else(|| {
            anyhow::anyhow!(
                "providers.compute has no `required` block — mesofact-runner is placed by mesh-tag superset (F16); declare `required.mesh_tags = [\"tag:cloud-runner\"]` in services/{}/mirrors/{}.toml",
                ctx.service.name, ctx.env,
            )
        })?;

        if required.mesh_tags.is_empty() {
            bail!(
                "providers.compute.required.mesh_tags is empty — mesofact-runner placement needs at least one tag (e.g. `tag:cloud-runner`) in services/{}/mirrors/{}.toml",
                ctx.service.name, ctx.env,
            );
        }

        bail!(
            "mesofact-runner dispatcher wiring pending (R330-F11 follow-up slice): \
             validated placement against tags {:?} for service={}, env={}, but no warden \
             bring-up is wired yet — see crates/yah/local-driver/src/cloud_mesofact_runner.rs \
             for the runtime spec",
            required.mesh_tags, ctx.service.name, ctx.env,
        )
    }
}

/// F16 helper: resolve which machine the mesofact-runner workload should
/// land on for the given mirror. Returns `None` when the mirror's compute
/// slot has no `required` block, when `required.mesh_tags` is empty, or
/// when no machine carries the superset. Callers route a `None` result
/// to a structured error.
///
/// Lives here (not on `CloudConfig`) because it composes the
/// MirrorProviderSlot parser with the mesh-tag resolver — both surfaces
/// the cloud crate already exposes — and ties them to this reconciler's
/// dispatch convention (compute slot, mesofact-runner kind).
pub fn resolve_runner_machine<'a>(
    cfg: &'a CloudConfig,
    mirror: &crate::MirrorConfig,
) -> Option<&'a crate::MachineConfig> {
    let slot = mirror.providers.get("compute")?;
    let required = slot.required()?;
    if required.mesh_tags.is_empty() {
        return None;
    }
    cfg.resolve_machine_by_mesh_tags(&required.mesh_tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MachineConfig, MirrorProviderSlot, MirrorShape, TopologyConfig};
    use crate::MirrorConfig;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn machine(name: &str, tags: Vec<&str>) -> MachineConfig {
        MachineConfig {
            name: name.into(),
            provider: "hetzner".into(),
            location: "hil".into(),
            server_type: "ccx13".into(),
            hosts_mirrors: vec![],
            mesh_tags: tags.into_iter().map(String::from).collect(),
            bucket: None,
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
        }
    }

    fn cfg_with(machines: Vec<MachineConfig>) -> CloudConfig {
        CloudConfig {
            workspace_root: PathBuf::new(),
            machines,
            providers: vec![],
            services: BTreeMap::new(),
            domains: BTreeMap::new(),
            legacy_mirrors: vec![],
            workloads: vec![],
            topology: TopologyConfig::default(),
            legacy_services: vec![],
        }
    }

    fn mirror_with_required(tags: Vec<&str>) -> MirrorConfig {
        let mut fields: BTreeMap<String, toml::Value> = BTreeMap::new();
        let mut required_table = toml::value::Table::new();
        let tag_array = toml::Value::Array(
            tags.into_iter().map(|t| toml::Value::String(t.into())).collect(),
        );
        required_table.insert("mesh_tags".into(), tag_array);
        fields.insert("required".into(), toml::Value::Table(required_table));
        let slot = MirrorProviderSlot::Reference {
            provider_id: "hetzner".into(),
            fields,
        };
        let mut providers = BTreeMap::new();
        providers.insert("compute".into(), slot);
        MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::SingleMachine,
            providers,
            asset_aliases: BTreeMap::new(),
        }
    }

    #[test]
    fn resolve_runner_machine_picks_mesh_tag_superset() {
        let cfg = cfg_with(vec![
            machine("yah-bnt-1", vec!["tag:primary-yah"]),
            machine("us-west-001", vec!["tag:primary-yah", "tag:cloud-runner"]),
        ]);
        let mirror = mirror_with_required(vec!["tag:cloud-runner"]);
        let picked = resolve_runner_machine(&cfg, &mirror).map(|m| m.name.as_str());
        assert_eq!(picked, Some("us-west-001"));
    }

    #[test]
    fn resolve_runner_machine_none_when_required_missing() {
        let cfg = cfg_with(vec![machine("us-west-001", vec!["tag:cloud-runner"])]);
        let mirror = MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::SingleMachine,
            providers: BTreeMap::new(),
            asset_aliases: BTreeMap::new(),
        };
        assert!(resolve_runner_machine(&cfg, &mirror).is_none());
    }

    #[test]
    fn resolve_runner_machine_none_when_no_machine_matches() {
        let cfg = cfg_with(vec![machine("yah-bnt-1", vec!["tag:primary-yah"])]);
        let mirror = mirror_with_required(vec!["tag:cloud-runner"]);
        assert!(resolve_runner_machine(&cfg, &mirror).is_none());
    }
}
