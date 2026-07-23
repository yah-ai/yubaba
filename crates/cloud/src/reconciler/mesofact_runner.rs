//! [`Reconciler`] skeleton for `kind = "mesofact-runner"` components (R330-F11).
//!
//! Skeleton-only — `up()` validates the mirror has the F16 placement
//! constraint (`[providers.compute] required.mesh_tags`) and that a
//! workspace machine satisfies it, then bails with a "wiring pending"
//! error so a dispatcher arm doesn't silently report success.
//!
//! The dispatcher wiring (`app/yah/cli/src/cloud.rs::reconcile_component`
//! + `app/yah/desktop/src/mirror_run.rs`) and the live yubaba bring-up
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

        // Dispatcher arms ARE wired now (R330-F11 Step 4): cli
        // reconcile_component + desktop mirror_run route `mesofact-runner`
        // here. Placement constraints are validated above. What remains is
        // the live yubaba bring-up on the resolved box — which needs yubaba
        // actually running on the runner (R330-T9) and the apply-layer to
        // resolve the concrete machine via `resolve_runner_machine` (the
        // F16-region-aware resolver) and hand it the MesofactRunnerSpec. That
        // is Step 6 (live deploy), blocked on T9.
        bail!(
            "mesofact-runner placement validated ({}) for service={}, env={}, but live yubaba \
             bring-up is not wired yet — blocked on R330-T9 (yubaba not yet running on the \
             runner box) + R330-F11 Step 6 (live deploy). The apply layer resolves the target \
             machine via cloud::reconciler::mesofact_runner::resolve_runner_machine and hands it \
             the MesofactRunnerSpec from crates/yah/local-driver/src/cloud_mesofact_runner.rs.",
            required.describe(),
            ctx.service.name,
            ctx.env,
        )
    }
}

/// F16 helper: resolve which machine the mesofact-runner workload should
/// land on for the given mirror. Returns `None` when the mirror's compute
/// slot has no `required` block, when that block carries no constraints at
/// all, or when no machine satisfies it. Callers route a `None` result to a
/// structured error.
///
/// Honors the **full** F16 placement spec — region/zone/provider membership
/// plus mesh_tags superset — via [`CloudConfig::resolve_machine`], so a
/// `required.regions = ["us-west"]` constraint excludes a same-tag box in
/// another region. (The older mesh-tags-only path was the F11 stub.)
///
/// Lives here (not on `CloudConfig`) because it ties the MirrorProviderSlot
/// parser to this reconciler's dispatch convention (compute slot,
/// mesofact-runner kind).
pub fn resolve_runner_machine<'a>(
    cfg: &'a CloudConfig,
    mirror: &crate::MirrorConfig,
) -> Option<&'a crate::MachineConfig> {
    let slot = mirror.providers.get("compute")?;
    let required = slot.required()?;
    if required.is_unconstrained() {
        return None;
    }
    cfg.resolve_machine(&required).ok()
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
            location: Some("hil".into()),
            server_type: Some("ccx13".into()),
            hosts_mirrors: vec![],
            mesh_tags: tags.into_iter().map(String::from).collect(),
            region: None,
            zone: None,
            arch: None,
            bucket: None,
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
            allocatable: None,
            taints: vec![],
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
            tags.into_iter()
                .map(|t| toml::Value::String(t.into()))
                .collect(),
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

    /// A machine carrying a `region` label plus tags.
    fn machine_in_region(name: &str, region: &str, tags: Vec<&str>) -> MachineConfig {
        MachineConfig {
            region: Some(region.into()),
            zone: Some(region.into()),
            ..machine(name, tags)
        }
    }

    /// Mirror whose compute slot constrains BOTH region and mesh_tags.
    fn mirror_with_region_and_tags(region: &str, tags: Vec<&str>) -> MirrorConfig {
        let mut required_table = toml::value::Table::new();
        required_table.insert(
            "regions".into(),
            toml::Value::Array(vec![toml::Value::String(region.into())]),
        );
        required_table.insert(
            "mesh_tags".into(),
            toml::Value::Array(
                tags.into_iter()
                    .map(|t| toml::Value::String(t.into()))
                    .collect(),
            ),
        );
        let mut fields: BTreeMap<String, toml::Value> = BTreeMap::new();
        fields.insert("required".into(), toml::Value::Table(required_table));
        let mut providers = BTreeMap::new();
        providers.insert(
            "compute".into(),
            MirrorProviderSlot::Reference {
                provider_id: "hetzner".into(),
                fields,
            },
        );
        MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::SingleMachine,
            providers,
            asset_aliases: BTreeMap::new(),
        }
    }

    #[test]
    fn resolve_runner_machine_honors_region_axis() {
        // Two same-tag boxes in different regions; the region constraint picks.
        let cfg = cfg_with(vec![
            machine_in_region("us-west-001", "us-west", vec!["tag:cloud-runner"]),
            machine_in_region("eu-west-001", "eu-west", vec!["tag:cloud-runner"]),
        ]);
        let picked = resolve_runner_machine(
            &cfg,
            &mirror_with_region_and_tags("us-west", vec!["tag:cloud-runner"]),
        )
        .map(|m| m.name.as_str());
        assert_eq!(picked, Some("us-west-001"));
    }

    #[test]
    fn resolve_runner_machine_region_mismatch_excludes_same_tag_box() {
        // The box has the tag but the WRONG region → no placement (fail loud
        // upstream), proving region isn't silently ignored.
        let cfg = cfg_with(vec![machine_in_region(
            "us-west-001",
            "us-west",
            vec!["tag:cloud-runner"],
        )]);
        let picked = resolve_runner_machine(
            &cfg,
            &mirror_with_region_and_tags("eu-west", vec!["tag:cloud-runner"]),
        );
        assert!(picked.is_none());
    }
}
