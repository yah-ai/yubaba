//! [`Reconciler`] implementation for `kind = "cloudflare-worker"` components.
//!
//! Bring-up flow:
//!   1. Validate the registry slot (must reference `cloudflare`, declare
//!      `zone` + `domain`); read `[build]` + `[[bindings]]` from
//!      `<workload_dir>/workload.toml`; match each workload binding against
//!      a sibling mirror provider slot by `binding` name. **All validation
//!      runs before any Cloudflare API call** — see R330-B5's `asset_origin`
//!      guard in `mesofact_static.rs` for the same fail-fast discipline.
//!   2. Run `[build].command` from the workload dir, then read the bundled
//!      entrypoint (`[build].entrypoint`, default `dist/index.js`).
//!   3. Resolve the Cloudflare account id from
//!      `.yah/infra/providers/cloudflare.toml` and the API token from the
//!      `cloudflare-api-token` keystore slot.
//!   4. Idempotently create any R2 buckets the workload binds (list → POST
//!      only if absent).
//!   5. Deploy the bundled script with typed [`WorkerBinding`] entries
//!      (R419-F1 surface).
//!   6. Attach the service domain via the Workers Custom Domains API
//!      (account-scoped — distinct from the zone-scoped Worker Routes API).
//!
//! Returns a [`RunningWorkload::adopted`] handle with `public_url` set to
//! `https://<domain>`; the lifecycle handle owns no subprocess (the Worker
//! lives on Cloudflare).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::process::Command;
use tracing::info;

use super::{ReconcileCtx, Reconciler, RunningWorkload};
use crate::provider::cloudflare::{CloudflareClient, WorkerBinding};
use crate::MirrorProviderSlot;

/// Workload kind this reconciler handles. Matches `ServiceComponent.kind`
/// and the `kind = "..."` line in `workload.toml`.
pub const WORKLOAD_KIND: &str = "cloudflare-worker";

/// Reconciles `kind = "cloudflare-worker"` components.
pub struct CloudflareWorkerReconciler;

impl CloudflareWorkerReconciler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CloudflareWorkerReconciler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Reconciler for CloudflareWorkerReconciler {
    fn kind(&self) -> &'static str {
        WORKLOAD_KIND
    }

    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        // (1) Workload kind on disk must agree with the component's declared kind.
        let kind = ctx.workload_kind().context("loading workload.toml")?;
        if kind != WORKLOAD_KIND {
            anyhow::bail!(
                "component {component_id} kind=\"cloudflare-worker\" but {workload_dir}/workload.toml declares kind=\"{kind}\"",
                component_id = ctx.component.id,
                workload_dir = ctx.workload_dir().display(),
            );
        }

        // (2) Registry slot owns zone + domain. Component's `role` names the slot.
        let registry_role = ctx.component.role.as_str();
        let registry_slot = ctx.slot(registry_role).with_context(|| {
            format!(
                "mirror has no `providers.{registry_role}` slot — required for the cloudflare-worker component (service={}, env={})",
                ctx.service.name, ctx.env,
            )
        })?;
        let (zone, domain) =
            read_registry_slot(registry_slot, registry_role, &ctx.service.name, ctx.env)?;

        // (3) Read [build] + [[bindings]] from workload.toml.
        let workload_dir = ctx.workload_dir();
        let workload = read_workload_manifest(&workload_dir)?;

        // (4) Match workload [[bindings]] against sibling mirror slots by name.
        let resolved_bindings = resolve_bindings(
            &workload.bindings,
            registry_role,
            &ctx.mirror.providers,
            &ctx.service.name,
            ctx.env,
        )?;

        // (5) Cloudflare provider resolved from the registry slot's
        // `use = "<id>"` — supplies account_id + management token (fail before
        // build). Different services can name different providers/accounts.
        let provider_id = registry_slot.provider_id().with_context(|| {
            "cloudflare-worker registry slot must be a `use = \"<id>\"` reference".to_string()
        })?;
        let cf_provider = super::cf_creds::CfProvider::resolve_scoped(
            ctx.workspace_root,
            provider_id,
            &ctx.scope.tenant,
            &ctx.scope.namespace,
        )?;
        let account_id = cf_provider.account_id.clone();

        // (6) Run build (no-op when [build].command is absent).
        if let Some(cmd) = &workload.build_command {
            run_build_command(&workload_dir, cmd).await?;
        }

        // (7) Read bundled entrypoint.
        let entrypoint_rel = workload.entrypoint.as_deref().unwrap_or("dist/index.js");
        let entrypoint_path = workload_dir.join(entrypoint_rel);
        let script_js = std::fs::read_to_string(&entrypoint_path).with_context(|| {
            format!(
                "reading worker entrypoint {} — confirm the build emitted it (workload.toml [build].entrypoint)",
                entrypoint_path.display(),
            )
        })?;

        // (8) API token + client (from the resolved provider).
        let api_token = cf_provider.api_token()?;
        let cf = CloudflareClient::new(api_token);

        // (9) Idempotent R2 bucket creation for r2_bucket bindings.
        for rb in &resolved_bindings {
            match rb {
                ResolvedBinding::R2Bucket { bucket_name, .. } => {
                    ensure_r2_bucket(&cf, &account_id, bucket_name).await?;
                }
            }
        }

        // (10) Deploy script + bindings.
        let worker_name = ctx.service.name.clone();
        let worker_bindings: Vec<WorkerBinding<'_>> = resolved_bindings
            .iter()
            .map(|rb| match rb {
                ResolvedBinding::R2Bucket { name, bucket_name } => WorkerBinding::R2Bucket {
                    name: name.as_str(),
                    bucket_name: bucket_name.as_str(),
                },
            })
            .collect();
        cf.deploy_worker_script(&account_id, &worker_name, &script_js, &worker_bindings)
            .await
            .with_context(|| format!("deploying worker script {worker_name}"))?;
        info!(worker_name, "CF Worker script deployed");

        // (11) Attach the custom domain.
        let zone_id = cf
            .zone_id_for_name(&zone)
            .await
            .with_context(|| format!("resolving zone id for {zone}"))?;
        cf.upsert_worker_custom_domain(&account_id, &zone_id, &domain, &worker_name)
            .await
            .with_context(|| format!("attaching custom domain {domain} to worker {worker_name}"))?;
        info!(domain, worker_name, "CF Worker custom domain attached");

        Ok(
            RunningWorkload::adopted("cloudflare-worker", ctx.component.role.clone(), None)
                .with_public_url(format!("https://{domain}")),
        )
    }
}

// ─── pure config readers ─────────────────────────────────────────────────────

/// Parsed bits of `workload.toml` the reconciler cares about.
struct WorkloadManifest {
    build_command: Option<String>,
    entrypoint: Option<String>,
    bindings: Vec<WorkloadBindingDecl>,
}

/// One `[[bindings]]` entry declared in `workload.toml`.
#[derive(Debug, Clone)]
struct WorkloadBindingDecl {
    name: String,
    kind: String,
}

fn read_workload_manifest(workload_dir: &Path) -> Result<WorkloadManifest> {
    let path = workload_dir.join("workload.toml");
    let src =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let value: toml::Value =
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
    let build_command = value
        .get("build")
        .and_then(|b| b.get("command"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let entrypoint = value
        .get("build")
        .and_then(|b| b.get("entrypoint"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let bindings = value
        .get("bindings")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    let name = entry.get("name").and_then(|v| v.as_str())?.to_string();
                    let kind = entry.get("kind").and_then(|v| v.as_str())?.to_string();
                    Some(WorkloadBindingDecl { name, kind })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(WorkloadManifest {
        build_command,
        entrypoint,
        bindings,
    })
}

/// Validate the registry slot and pull out `(zone, domain)`. The role is the
/// component's declared `role` field; this slot owns the Worker custom-domain
/// attachment, not the storage bindings.
fn read_registry_slot(
    slot: &MirrorProviderSlot,
    role: &str,
    service: &str,
    env: &str,
) -> Result<(String, String)> {
    let (provider_id, fields) = match slot {
        MirrorProviderSlot::Reference {
            provider_id,
            fields,
        } => (provider_id.as_str(), fields),
        MirrorProviderSlot::Inline { .. } => anyhow::bail!(
            "providers.{role} must be a `use = \"cloudflare\"` reference for kind=\"cloudflare-worker\" — inline kinds are not supported (service={service}, env={env})",
        ),
    };
    if provider_id != "cloudflare" {
        anyhow::bail!(
            "providers.{role}.use = \"{provider_id}\" — only \"cloudflare\" is supported by the cloudflare-worker reconciler (service={service}, env={env})",
        );
    }
    let zone = fields
        .get("zone")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .with_context(|| {
            format!(
                "providers.{role}.zone missing or empty — required to resolve the Cloudflare zone id (service={service}, env={env})",
            )
        })?
        .to_string();
    let domain = fields
        .get("domain")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .with_context(|| {
            format!(
                "providers.{role}.domain missing or empty — required for the Worker custom domain (service={service}, env={env})",
            )
        })?
        .to_string();
    Ok((zone, domain))
}

/// One resolved binding ready to hand to [`WorkerBinding`].
enum ResolvedBinding {
    R2Bucket { name: String, bucket_name: String },
}

/// Match every workload-declared binding against a sibling mirror slot whose
/// `binding` field carries the same env-var name. Validates per-kind required
/// fields (e.g. `bucket` for `r2_bucket`). Errors fail-fast before any CF call.
fn resolve_bindings(
    workload_bindings: &[WorkloadBindingDecl],
    registry_role: &str,
    mirror_providers: &BTreeMap<String, MirrorProviderSlot>,
    service: &str,
    env: &str,
) -> Result<Vec<ResolvedBinding>> {
    let mut resolved = Vec::with_capacity(workload_bindings.len());
    for wb in workload_bindings {
        let slot_match = mirror_providers
            .iter()
            .filter(|(role, _)| role.as_str() != registry_role)
            .find_map(|(role, slot)| {
                let fields = slot_fields(slot);
                fields
                    .get("binding")
                    .and_then(|v| v.as_str())
                    .filter(|b| *b == wb.name)
                    .map(|_| (role.as_str(), fields))
            });
        let (role, fields) = slot_match.with_context(|| {
            format!(
                "workload [[bindings]] name = {name:?} does not match any mirror provider slot's `binding` field (service={service}, env={env}). \
                 Declare a sibling slot like `[providers.<role>] binding = {name:?}` in the mirror config.",
                name = wb.name,
            )
        })?;
        match wb.kind.as_str() {
            "r2_bucket" => {
                let bucket_name = fields
                    .get("bucket")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .with_context(|| {
                        format!(
                            "providers.{role}.bucket missing or empty — required for r2_bucket binding {:?} (service={service}, env={env})",
                            wb.name,
                        )
                    })?
                    .to_string();
                resolved.push(ResolvedBinding::R2Bucket {
                    name: wb.name.clone(),
                    bucket_name,
                });
            }
            other => anyhow::bail!(
                "binding kind {:?} on workload.toml [[bindings]] name = {:?} is not supported by the cloudflare-worker reconciler (service={service}, env={env})",
                other, wb.name,
            ),
        }
    }
    Ok(resolved)
}

fn slot_fields(slot: &MirrorProviderSlot) -> &BTreeMap<String, toml::Value> {
    match slot {
        MirrorProviderSlot::Reference { fields, .. } => fields,
        MirrorProviderSlot::Inline { fields, .. } => fields,
    }
}

/// Runs `[build].command` from `workload.toml` via a shell.
///
/// **Shell invariant (R592-T2):** `cmd_str` is operator-authored trusted
/// config read from a file the operator commits to the repo — the same
/// trust tier as a qed-gha workflow's `run:` step, or mesofact-dev's own
/// `[build].command` (`mesofact-dev/src/watcher.rs::build_and_swap`, same
/// `sh -c` shape). It is never derived from a request body or other
/// externally-influenced input, so `sh -c` here is not a shell-injection
/// surface — it exists because build commands routinely rely on real shell
/// semantics (`&&` chains, globs, `$VAR` expansion, `npm run x -- --flag`)
/// that a naive argv split would silently break for some subset of
/// `workload.toml`s. Do not replace this with direct argv construction
/// without also handling those cases (e.g. shell-lexing only when no
/// metacharacters are present, keeping `sh -c` as the fallback).
async fn run_build_command(workload_dir: &Path, cmd_str: &str) -> Result<()> {
    info!(
        workload = %workload_dir.display(),
        cmd = %cmd_str,
        "running worker build command",
    );
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd_str)
        .current_dir(workload_dir)
        .status()
        .await
        .with_context(|| format!("spawning build command: {cmd_str}"))?;
    if !status.success() {
        anyhow::bail!(
            "build command failed (exit {}): {cmd_str}",
            status.code().unwrap_or(-1),
        );
    }
    Ok(())
}

/// List R2 buckets in the account; create `bucket_name` only when absent.
/// The CF Create endpoint returns 4xx on a duplicate, so list-first keeps the
/// reconcile loop idempotent without depending on error-shape parsing.
async fn ensure_r2_bucket(
    cf: &CloudflareClient,
    account_id: &str,
    bucket_name: &str,
) -> Result<()> {
    let existing = cf
        .list_r2_buckets(account_id)
        .await
        .context("listing R2 buckets")?;
    if existing.iter().any(|b| b.name == bucket_name) {
        info!(bucket_name, "R2 bucket already exists — skipping create");
        return Ok(());
    }
    cf.create_r2_bucket(account_id, bucket_name)
        .await
        .with_context(|| format!("creating R2 bucket {bucket_name}"))?;
    info!(bucket_name, "R2 bucket created");
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Fail-fast regression tests (R419-F4). Each test constructs a
    //! deliberately-broken mirror config, calls [`CloudflareWorkerReconciler::up`],
    //! and asserts the error names the offending field — no live Cloudflare API
    //! call is needed because validation runs before any HTTP request.
    use super::*;
    use crate::{MirrorConfig, MirrorShape, ServiceComponent, ServiceConfig};
    use std::path::PathBuf;
    use tempfile::tempdir;

    struct Fixture {
        _workspace: tempfile::TempDir,
        workspace_root: PathBuf,
        service: ServiceConfig,
        component: ServiceComponent,
        mirror: MirrorConfig,
        env: String,
    }

    impl Fixture {
        /// Build a fixture for the canonical `yah-cr`-shaped service:
        /// one component `kind = "cloudflare-worker"`, `role = "registry"`,
        /// path `app/yah/workers/yah-cr`. `mirror_providers` is whatever the
        /// test wants to vary; the test seeds the rest (workload.toml,
        /// cloudflare provider file).
        fn new(mirror_providers: BTreeMap<String, MirrorProviderSlot>) -> Self {
            let workspace = tempdir().unwrap();
            let workspace_root = workspace.path().to_path_buf();
            let workload_dir = workspace_root.join("app/yah/workers/yah-cr");
            std::fs::create_dir_all(&workload_dir).unwrap();
            std::fs::write(
                workload_dir.join("workload.toml"),
                r#"schema_version = 1
kind = "cloudflare-worker"

[build]
command = "bun run build"
out_dir = "dist"
entrypoint = "dist/index.js"

[[bindings]]
name = "CACHE"
kind = "r2_bucket"
"#,
            )
            .unwrap();
            // Minimal provider config so any test that gets past binding
            // validation doesn't trip on the cloudflare.toml read.
            let providers_dir = workspace_root.join(".yah/infra/providers");
            std::fs::create_dir_all(&providers_dir).unwrap();
            std::fs::write(
                providers_dir.join("cloudflare.toml"),
                r#"schema_version = 1
id = "cloudflare"
kind = "cloudflare"
account_id = "test-account"
"#,
            )
            .unwrap();

            let mirror = MirrorConfig {
                schema_version: 1,
                shape: MirrorShape::SingleMachine,
                providers: mirror_providers,
                asset_aliases: Default::default(),
            };
            let service = ServiceConfig {
                schema_version: 1,
                name: "yah-cr".to_string(),
                domain: "cr.yah.dev".to_string(),
                components: vec![],
                db: crate::DbCatalog::default(),
            };
            let component = ServiceComponent {
                id: "cache".to_string(),
                kind: "cloudflare-worker".to_string(),
                path: "app/yah/workers/yah-cr".to_string(),
                role: "registry".to_string(),
                publishes: None,
                wave: 0,
                git: None,
            };
            Self {
                _workspace: workspace,
                workspace_root,
                service,
                component,
                mirror,
                env: "cloud".to_string(),
            }
        }

        fn ctx(&self) -> ReconcileCtx<'_> {
            ReconcileCtx {
                workspace_root: &self.workspace_root,
                service: &self.service,
                component: &self.component,
                mirror: &self.mirror,
                env: &self.env,
                scope: crate::reconciler::ProviderScope::singleton(),
            }
        }
    }

    /// Helper: build a `cloudflare`-reference slot from `(key, value)` pairs.
    fn cf_slot(fields: &[(&str, &str)]) -> MirrorProviderSlot {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert((*k).to_string(), toml::Value::String((*v).to_string()));
        }
        MirrorProviderSlot::Reference {
            provider_id: "cloudflare".to_string(),
            fields: map,
        }
    }

    /// Case 3 of the F4 ticket: providers.registry slot missing the `domain` field.
    /// Must fail at config validation naming the offending field, the service,
    /// and the env — before any Cloudflare API call.
    #[tokio::test]
    async fn up_bails_on_registry_missing_domain() {
        let mut providers = BTreeMap::new();
        // registry slot declares `zone` but omits `domain` — invalid.
        providers.insert("registry".into(), cf_slot(&[("zone", "yah.dev")]));
        providers.insert(
            "cache".into(),
            cf_slot(&[("bucket", "yah-cr-cache"), ("binding", "CACHE")]),
        );
        let fx = Fixture::new(providers);
        let err = CloudflareWorkerReconciler::new()
            .up(fx.ctx())
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("domain"),
            "error must name the missing field: {msg}"
        );
        assert!(
            msg.contains("registry"),
            "error must name the offending slot role: {msg}"
        );
        assert!(msg.contains("yah-cr"), "error must name the service: {msg}");
        assert!(msg.contains("cloud"), "error must name the env: {msg}");
    }

    /// Case 2 of the F4 ticket: workload.toml [[bindings]] name does not match
    /// any mirror provider slot's `binding` field. The workload binds `CACHE`
    /// but the mirror's cache slot declares `binding = "STORAGE"` — a name drift
    /// the operator probably meant to keep in sync.
    #[tokio::test]
    async fn up_bails_on_binding_name_drift() {
        let mut providers = BTreeMap::new();
        providers.insert(
            "registry".into(),
            cf_slot(&[("zone", "yah.dev"), ("domain", "cr.yah.dev")]),
        );
        providers.insert(
            "cache".into(),
            cf_slot(&[("bucket", "yah-cr-cache"), ("binding", "STORAGE")]),
        );
        let fx = Fixture::new(providers);
        let err = CloudflareWorkerReconciler::new()
            .up(fx.ctx())
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("CACHE"),
            "error must name the unmatched workload binding: {msg}"
        );
        assert!(
            msg.contains("binding"),
            "error must mention the `binding` field: {msg}"
        );
        assert!(msg.contains("yah-cr"), "error must name the service: {msg}");
        assert!(msg.contains("cloud"), "error must name the env: {msg}");
    }

    /// Case 1 of the F4 ticket: providers.cache slot missing the `bucket` field.
    /// Binding name matches by `binding = "CACHE"` but the slot has no bucket
    /// for the reconciler to pass to `WorkerBinding::R2Bucket`.
    #[tokio::test]
    async fn up_bails_on_cache_slot_missing_bucket() {
        let mut providers = BTreeMap::new();
        providers.insert(
            "registry".into(),
            cf_slot(&[("zone", "yah.dev"), ("domain", "cr.yah.dev")]),
        );
        // Note: binding name matches workload.toml; only `bucket` is missing.
        providers.insert("cache".into(), cf_slot(&[("binding", "CACHE")]));
        let fx = Fixture::new(providers);
        let err = CloudflareWorkerReconciler::new()
            .up(fx.ctx())
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("bucket"),
            "error must name the missing field: {msg}"
        );
        assert!(
            msg.contains("cache"),
            "error must name the offending slot role: {msg}"
        );
        assert!(
            msg.contains("CACHE"),
            "error must name the binding it relates to: {msg}"
        );
        assert!(msg.contains("yah-cr"), "error must name the service: {msg}");
        assert!(msg.contains("cloud"), "error must name the env: {msg}");
    }
}
