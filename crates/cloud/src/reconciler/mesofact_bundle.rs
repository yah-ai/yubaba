//! W272 bundle tier for `mesofact-static` / `mesofact-spa` components — the
//! config half of the services-tab sync arm.
//!
//! Part of R599-F8 — the canonical ticket annotation lives in
//! `app/yah/cli/src/cloud.rs`, which owns the orchestration half. This module
//! only owns *what the mirror declares*: parsing the `[providers.bundle]` slot
//! and resolving which machines the built bundle gets deployed to.
//!
//! **The component kind does not change.** A mesofact site is a mesofact site;
//! the mirror decides how its bytes are distributed. A mirror with a
//! `[providers.static]` slot rides the historical build-and-publish-to-CDN path
//! ([`super::mesofact_static`]); a mirror that declares `[providers.bundle]`
//! rides the W272 chain instead:
//!
//! ```text
//! build → bundle assembly (per-file blake3) → R2 publish → workload deploy
//!   → node materializes → kamaji forks the serve binary
//! ```
//!
//! The deploy leg lives at the apply layer (`app/yah/cli/src/cloud.rs`) rather
//! than in a `Reconciler::up`, for the same reason
//! [`super::mesofact_runner`] does: machine resolution needs [`CloudConfig`],
//! which [`ReconcileCtx`] deliberately does not carry. What runs here is the
//! validation a desktop-side bring-up can still do offline —
//! [`MesofactBundleReconciler`] checks the slot parses and the placement
//! resolves, then bails with a pointer at the CLI.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use workload_spec::{BlakeHash, BundleLifecycle, MesofactServeBundle, Millis};

use super::{ReconcileCtx, Reconciler, RunningWorkload};
use crate::config::CloudConfig;
use crate::MirrorConfig;

/// Mirror provider role that opts a mesofact component into the bundle tier.
pub const SLOT_ROLE: &str = "bundle";

/// Default idle TTL for an `on-demand` (JIT) bundle when the slot doesn't name
/// one: five minutes with zero connections before kamaji reaps the process.
pub const DEFAULT_IDLE_TTL_MS: u64 = 300_000;

/// True when this mirror opts its mesofact components into the W272 bundle
/// tier — i.e. declares a `[providers.bundle]` slot.
///
/// Checked at the dispatch layer before the static reconciler runs, so the
/// two tiers are mutually exclusive per mirror rather than per component.
pub fn slot_declared(mirror: &MirrorConfig) -> bool {
    mirror.providers.contains_key(SLOT_ROLE)
}

/// Parsed `[providers.bundle]` slot — everything the sync arm needs that is
/// *declared* rather than *derived*.
///
/// ```toml
/// [providers.bundle]
/// use = "cloudflare"                  # R2 credentials resolve via this provider
/// bucket = "yah-dev-bundles"          # the append-only bundle store
/// machines = ["us-east-001"]          # explicit placement (or `required = {…}`)
/// name = "yah-marketing"              # stable workload handle; defaults to the service name
/// lifecycle = "keep-alive"            # or "on-demand"
/// idle_ttl_ms = 300000                # on-demand only
/// runtime_version = "0.8.20"          # vanilla bundles only (no serve_bins)
/// serve_bins = { x86_64-unknown-linux-musl = "target/…/mesofact-serve" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSlot {
    /// R2 bucket holding the bundle store. Append-only, blob-deduped.
    pub bucket: String,
    /// Cloudflare account id override. `None` → resolve from the workspace's
    /// cloudflare provider config / `CF_ACCOUNT_ID`.
    pub account: Option<String>,
    /// Stable operator-facing workload name. yubaba requires one for a bundle
    /// deploy: the digest is the *content* and changes on every rebuild, so it
    /// is not a usable handle for `list` / `stop`.
    pub name: Option<String>,
    /// Explicitly named target machines, in deploy order. Empty → fall back to
    /// the slot's `required = {…}` placement spec.
    pub machines: Vec<String>,
    /// Stock runtime version recorded as `runtime = "mesofact/<version>"` for a
    /// vanilla bundle. Ignored when `serve_bins` is non-empty. `None` → the
    /// caller's own version.
    pub runtime_version: Option<String>,
    /// `<triple> → <path to serve binary>`. Any entry makes this a
    /// `runtime = "self"` bundle that carries its own serve binaries.
    pub serve_bins: BTreeMap<String, PathBuf>,
    /// How kamaji supervises the served bundle.
    pub lifecycle: BundleLifecycle,
}

impl BundleSlot {
    /// Parse the mirror's `[providers.bundle]` slot.
    ///
    /// Every failure names the offending field plus the service and env, so the
    /// operator gets a file to open rather than a type error. Validation is
    /// total and offline — nothing here touches the network, so a misconfigured
    /// mirror fails before a build runs (R330-B5 fail-fast discipline).
    pub fn parse(mirror: &MirrorConfig, service: &str, env: &str) -> Result<Self> {
        let slot = mirror.providers.get(SLOT_ROLE).with_context(|| {
            format!(
                "mirror has no `providers.{SLOT_ROLE}` slot — required for the W272 bundle tier \
                 (service={service}, env={env})"
            )
        })?;
        let fields = slot.fields();

        let bucket = fields
            .get("bucket")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .with_context(|| {
                format!(
                    "providers.{SLOT_ROLE} has no `bucket` — name the R2 bundle store in \
                     .yah/services/{service}/mirrors/{env}.toml"
                )
            })?
            .to_string();

        let account = fields
            .get("account")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let name = fields
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let machines = match fields.get("machines") {
            None => Vec::new(),
            Some(v) => {
                let list = v.as_array().with_context(|| {
                    format!(
                        "providers.{SLOT_ROLE}.machines must be an array of machine names \
                         (service={service}, env={env})"
                    )
                })?;
                list.iter()
                    .map(|entry| {
                        entry
                            .as_str()
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .with_context(|| {
                                format!(
                                    "providers.{SLOT_ROLE}.machines holds a non-string (or empty) \
                                     entry (service={service}, env={env})"
                                )
                            })
                    })
                    .collect::<Result<Vec<_>>>()?
            }
        };

        let runtime_version = fields
            .get("runtime_version")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let serve_bins = match fields.get("serve_bins") {
            None => BTreeMap::new(),
            Some(v) => {
                let table = v.as_table().with_context(|| {
                    format!(
                        "providers.{SLOT_ROLE}.serve_bins must be a table of \
                         <target-triple> = <path> (service={service}, env={env})"
                    )
                })?;
                table
                    .iter()
                    .map(|(triple, path)| {
                        let path = path.as_str().filter(|s| !s.is_empty()).with_context(|| {
                            format!(
                                "providers.{SLOT_ROLE}.serve_bins.{triple} must be a non-empty \
                                 path (service={service}, env={env})"
                            )
                        })?;
                        Ok((triple.clone(), PathBuf::from(path)))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?
            }
        };

        let lifecycle = parse_lifecycle(
            fields.get("lifecycle").and_then(|v| v.as_str()),
            fields.get("idle_ttl_ms").and_then(|v| v.as_integer()),
            service,
            env,
        )?;

        Ok(Self {
            bucket,
            account,
            name,
            machines,
            runtime_version,
            serve_bins,
            lifecycle,
        })
    }

    /// Stable workload handle: the slot's `name`, else the service name.
    pub fn workload_name<'a>(&'a self, service: &'a str) -> &'a str {
        self.name.as_deref().unwrap_or(service)
    }

    /// True when the assembled bundle carries its own serve binaries
    /// (`runtime = "self"`) rather than resolving a stock node runtime asset.
    pub fn is_self_contained(&self) -> bool {
        !self.serve_bins.is_empty()
    }

    /// Build the `{digest, runtime, lifecycle}` triple a `mesofact-static`
    /// workload carries once its bundle is published.
    ///
    /// `runtime` wire-mirrors `yah_mesofact_bundle::BundleRuntime`, so it is
    /// taken from the manifest the assembler actually wrote rather than
    /// re-derived here — the manifest is what the node will verify against.
    pub fn serve_bundle(&self, digest: &str, runtime: &str) -> MesofactServeBundle {
        MesofactServeBundle {
            digest: BlakeHash(digest.to_string()),
            runtime: runtime.to_string(),
            lifecycle: self.lifecycle.clone(),
        }
    }
}

/// `lifecycle = "keep-alive" | "on-demand"` (+ `idle_ttl_ms` for the latter).
fn parse_lifecycle(
    raw: Option<&str>,
    idle_ttl_ms: Option<i64>,
    service: &str,
    env: &str,
) -> Result<BundleLifecycle> {
    match raw.unwrap_or("keep-alive") {
        "keep-alive" | "keepalive" => {
            if idle_ttl_ms.is_some() {
                bail!(
                    "providers.{SLOT_ROLE}.idle_ttl_ms only applies to `lifecycle = \"on-demand\"` \
                     — a keep-alive bundle is never reaped (service={service}, env={env})"
                );
            }
            Ok(BundleLifecycle::KeepAlive)
        }
        "on-demand" | "ondemand" | "jit" => {
            let ttl = idle_ttl_ms.unwrap_or(DEFAULT_IDLE_TTL_MS as i64);
            if ttl <= 0 {
                bail!(
                    "providers.{SLOT_ROLE}.idle_ttl_ms must be positive, got {ttl} \
                     (service={service}, env={env})"
                );
            }
            Ok(BundleLifecycle::OnDemand {
                idle_ttl: Millis::from_ms(ttl as u64),
            })
        }
        other => bail!(
            "providers.{SLOT_ROLE}.lifecycle must be \"keep-alive\" or \"on-demand\", got \
             {other:?} (service={service}, env={env})"
        ),
    }
}

/// Resolve the machines a published bundle deploys to, in deploy order.
///
/// Two declaration forms, checked in that order:
/// 1. `machines = ["us-east-001", …]` — explicit, ordered, and the shape to
///    prefer while a bundle binds loopback (F10: one bundle per node, passway
///    co-located), because *which* nodes serve is then an operator decision
///    rather than a scheduler outcome.
/// 2. `required = { regions = […], mesh_tags = […] }` — F16 placement, same
///    grammar [`super::mesofact_runner::resolve_runner_machine`] uses. Resolves
///    to exactly one machine.
///
/// An undeclared / unresolvable placement is an error, not an empty deploy —
/// silently publishing a bundle nobody serves is the failure mode this avoids.
pub fn resolve_bundle_machines<'a>(
    cfg: &'a CloudConfig,
    mirror: &MirrorConfig,
    slot: &BundleSlot,
    service: &str,
    env: &str,
) -> Result<Vec<&'a crate::MachineConfig>> {
    if !slot.machines.is_empty() {
        return slot
            .machines
            .iter()
            .map(|name| {
                cfg.machine(name).with_context(|| {
                    format!(
                        "providers.{SLOT_ROLE}.machines names {name:?}, which is not declared in \
                         .yah/infra/machines/ (service={service}, env={env})"
                    )
                })
            })
            .collect();
    }

    let required = mirror
        .providers
        .get(SLOT_ROLE)
        .and_then(|s| s.required())
        .filter(|r| !r.is_unconstrained())
        .with_context(|| {
            format!(
                "providers.{SLOT_ROLE} declares neither `machines = [...]` nor a constrained \
                 `required = {{ … }}` placement — a bundle must name the nodes that serve it \
                 (service={service}, env={env})"
            )
        })?;

    let machine = cfg.resolve_machine(&required).with_context(|| {
        format!(
            "F16 placement: no machine satisfies providers.{SLOT_ROLE}.required ({}) — check \
             .yah/services/{service}/mirrors/{env}.toml against .yah/infra/machines/*.toml",
            required.describe(),
        )
    })?;
    Ok(vec![machine])
}

/// Desktop-side (offline) half of the bundle tier: validate the mirror's
/// declaration and bail with a pointer at the CLI.
///
/// The real chain — build, assemble, publish, deploy — runs at the apply layer
/// where [`CloudConfig`] is in hand. Mirroring
/// [`super::mesofact_runner::MesofactRunnerReconciler`], this exists so a
/// desktop bring-up of a bundle-tier mirror reports a *configuration* verdict
/// instead of "no reconciler wired".
pub struct MesofactBundleReconciler;

impl MesofactBundleReconciler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MesofactBundleReconciler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Reconciler for MesofactBundleReconciler {
    fn kind(&self) -> &'static str {
        super::mesofact_static::WORKLOAD_KIND
    }

    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        let slot = BundleSlot::parse(ctx.mirror, &ctx.service.name, ctx.env)?;
        bail!(
            "bundle tier validated (bucket={}, workload={}, {} serve binar{}) for service={}, \
             env={}, but the sync arm runs at the apply layer — deploy with \
             `yah cloud mirror up {} --env {}` (machine placement needs the workspace's \
             machine set, which a desktop bring-up does not load)",
            slot.bucket,
            slot.workload_name(&ctx.service.name),
            slot.serve_bins.len(),
            if slot.serve_bins.len() == 1 { "y" } else { "ies" },
            ctx.service.name,
            ctx.env,
            ctx.service.name,
            ctx.env,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MachineConfig, MirrorProviderSlot, MirrorShape, TopologyConfig};
    use std::path::PathBuf;

    fn mirror_from(slots: BTreeMap<String, MirrorProviderSlot>) -> MirrorConfig {
        MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::SingleMachine,
            providers: slots,
            asset_aliases: BTreeMap::new(),
        }
    }

    /// Build a mirror whose `[providers.bundle]` slot is exactly `slot_toml`.
    fn mirror_with(slot_toml: &str) -> MirrorConfig {
        let slot: MirrorProviderSlot = toml::from_str(slot_toml).unwrap();
        let mut providers = BTreeMap::new();
        providers.insert(SLOT_ROLE.to_string(), slot);
        mirror_from(providers)
    }

    fn machine(name: &str, region: &str) -> MachineConfig {
        MachineConfig {
            name: name.into(),
            provider: "static".into(),
            location: None,
            server_type: None,
            hosts_mirrors: vec![],
            mesh_tags: vec![],
            region: Some(region.into()),
            zone: None,
            arch: Some("x86_64".into()),
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

    #[test]
    fn slot_declared_keys_off_the_bundle_role() {
        assert!(slot_declared(&mirror_with(
            r#"use = "cloudflare"
bucket = "b""#
        )));
        assert!(!slot_declared(&mirror_from(BTreeMap::new())));
    }

    #[test]
    fn parses_a_self_contained_keep_alive_slot() {
        let mirror = mirror_with(
            r#"
use = "cloudflare"
bucket = "yah-dev-bundles"
machines = ["us-east-001"]
name = "yah-marketing"

[serve_bins]
x86_64-unknown-linux-musl = "target/x86_64-unknown-linux-musl/release/mesofact-serve"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "yah-marketing", "ha").unwrap();
        assert_eq!(slot.bucket, "yah-dev-bundles");
        assert_eq!(slot.machines, vec!["us-east-001".to_string()]);
        assert_eq!(slot.workload_name("yah-marketing"), "yah-marketing");
        assert!(slot.is_self_contained());
        assert_eq!(slot.lifecycle, BundleLifecycle::KeepAlive);
    }

    #[test]
    fn workload_name_falls_back_to_the_service_name() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b""#,
        );
        let slot = BundleSlot::parse(&mirror, "scrabcake", "ha").unwrap();
        assert_eq!(slot.workload_name("scrabcake"), "scrabcake");
        assert!(!slot.is_self_contained());
    }

    #[test]
    fn on_demand_takes_the_default_idle_ttl() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
lifecycle = "on-demand""#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        assert_eq!(
            slot.lifecycle,
            BundleLifecycle::OnDemand {
                idle_ttl: Millis::from_ms(DEFAULT_IDLE_TTL_MS)
            }
        );
    }

    #[test]
    fn on_demand_honors_an_explicit_idle_ttl() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
lifecycle = "on-demand"
idle_ttl_ms = 15000"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        assert_eq!(
            slot.lifecycle,
            BundleLifecycle::OnDemand {
                idle_ttl: Millis::from_ms(15_000)
            }
        );
    }

    /// An idle TTL on a keep-alive bundle is a config mistake that would
    /// otherwise be silently ignored — the process is never reaped.
    #[test]
    fn idle_ttl_on_a_keep_alive_slot_is_rejected() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
idle_ttl_ms = 15000"#,
        );
        let err = BundleSlot::parse(&mirror, "s", "e").unwrap_err().to_string();
        assert!(err.contains("idle_ttl_ms"), "{err}");
        assert!(err.contains("on-demand"), "{err}");
    }

    #[test]
    fn unknown_lifecycle_names_the_legal_values() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
lifecycle = "serverless""#,
        );
        let err = BundleSlot::parse(&mirror, "s", "e").unwrap_err().to_string();
        assert!(err.contains("keep-alive"), "{err}");
        assert!(err.contains("on-demand"), "{err}");
    }

    #[test]
    fn a_slot_without_a_bucket_names_the_file_to_edit() {
        let mirror = mirror_with(r#"use = "cloudflare""#);
        let err = BundleSlot::parse(&mirror, "yah-marketing", "ha")
            .unwrap_err()
            .to_string();
        assert!(err.contains("bucket"), "{err}");
        assert!(
            err.contains(".yah/services/yah-marketing/mirrors/ha.toml"),
            "{err}"
        );
    }

    #[test]
    fn explicit_machines_resolve_in_declaration_order() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
machines = ["us-south-001", "us-east-001"]"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let cfg = cfg_with(vec![
            machine("us-east-001", "us-east"),
            machine("us-south-001", "us-south"),
        ]);
        let resolved = resolve_bundle_machines(&cfg, &mirror, &slot, "s", "e").unwrap();
        let names: Vec<_> = resolved.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["us-south-001", "us-east-001"]);
    }

    #[test]
    fn an_undeclared_machine_is_an_error_not_a_skip() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
machines = ["us-west-999"]"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let cfg = cfg_with(vec![machine("us-east-001", "us-east")]);
        let err = resolve_bundle_machines(&cfg, &mirror, &slot, "s", "e")
            .unwrap_err()
            .to_string();
        assert!(err.contains("us-west-999"), "{err}");
        assert!(err.contains(".yah/infra/machines/"), "{err}");
    }

    #[test]
    fn falls_back_to_f16_required_placement() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
required = { regions = ["us-east"] }"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let cfg = cfg_with(vec![
            machine("us-east-001", "us-east"),
            machine("us-south-001", "us-south"),
        ]);
        let resolved = resolve_bundle_machines(&cfg, &mirror, &slot, "s", "e").unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "us-east-001");
    }

    /// Publishing a bundle no node serves is the silent failure this guards.
    #[test]
    fn no_placement_at_all_is_rejected() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b""#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let cfg = cfg_with(vec![machine("us-east-001", "us-east")]);
        let err = resolve_bundle_machines(&cfg, &mirror, &slot, "s", "e")
            .unwrap_err()
            .to_string();
        assert!(err.contains("machines"), "{err}");
        assert!(err.contains("required"), "{err}");
    }

    #[test]
    fn serve_bundle_carries_the_manifest_runtime_verbatim() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b""#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let digest = "a".repeat(64);
        let sb = slot.serve_bundle(&digest, "mesofact/0.8.20");
        assert_eq!(sb.digest.0, digest);
        assert_eq!(sb.runtime, "mesofact/0.8.20");
        assert_eq!(sb.lifecycle, BundleLifecycle::KeepAlive);
    }
}
