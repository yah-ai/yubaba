//! `kind = "container"` reconciler — the local build+run path (R602-T1).
//!
//! A `container` component is a service packaged as a Docker image built from
//! a Dockerfile that lives next to the component (`<path>/Dockerfile`). This
//! reconciler drives the operator-local tier: detect the workspace's
//! `local-container` runtime (orbstack/colima/docker, same provider the pond
//! primitives use), `docker build` the image, then `docker run` it with the
//! declared ports — adopt-idempotent, so a re-reconcile rebuilds (layer-cached)
//! and replaces the running container in place.
//!
//! Config lives in the component's `workload.toml`, parsed through the shared
//! [`workload_spec::Workload`] envelope as a [`ContainerBuild`] recipe — the
//! `[build]` table is what selects the recipe form over the digest-pinned
//! reference form the cloud tier uses (R783-F1 / W324). Its *keys* all default,
//! but the header itself must be present.
//!
//! ```toml
//! schema_version = 1
//! name = "yah-cloud-admin"
//! kind = "container"
//!
//! [build]
//! # Dockerfile path, relative to the component dir. Default "Dockerfile".
//! dockerfile = "Dockerfile"
//! # Build context, relative to the workspace root. Default: the component
//! # dir. Workspace crates set "." so their path-dependency sources resolve.
//! context = "."
//! # Image tag to build + run. Default: yah-local/<service>-<component>:dev.
//! image = "yah-local/yah-cloud-admin:dev"
//!
//! [run]
//! # Container port the process listens on.
//! port = 4325
//! # Host port to publish it on. Default: same as `port`.
//! host_port = 4325
//! # Environment passed into the container.
//! [run.env]
//! YAH_CLOUD_ADMIN_ADDR = "0.0.0.0:4325"
//!
//! # Bind mounts. `host` is relative to the workspace root (absolute paths are
//! # taken as-is); `read_only` defaults to true.
//! [[run.mounts]]
//! host = ".yah/infra"
//! container = "/workspace/.yah/infra"
//! ```
//!
//! Mounts exist because a runtime image is a *binary*, not a checkout: the
//! multi-stage build that produces it deliberately drops the workspace after
//! the compile, so a service whose job is to read workspace config
//! (yah-cloud-admin reads `.yah/infra/machines/*.toml`) came up rendering an
//! empty fleet — running, healthy, and describing a fleet of zero machines,
//! which is the worst possible failure for a monitor (R568-T7).
//!
//! Scope (R602-T1): the **local** tier only. Non-`local` mirror shapes bail
//! with a pointer to `yah cloud workload deploy` (the yubaba-mediated cloud
//! tier), which is a separate surface.
//!
//! @yah:ticket(R783-F2, "ContainerReconciler consumes the envelope instead of its own private struct")
//! @yah:status(review)
//! @yah:at(2026-08-19T07:12:36Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R783)
//! @arch:see(.yah/docs/working/W324-workload-kind-is-not-a-runtime.md)
//! @yah:verify("The cloud-admin pond tier still comes up: yah cloud mirror up yah-cloud-admin --env pond, container builds and runs, publishes on 4326.")
//! @yah:gotcha("crates/yah/cloud-admin/workload.toml also carries a [process] table read by LocalProcessReconciler on the dev mirror - one file, three tiers. Do not let the envelope reject the [process] table when parsing the container form; that file must stay loadable by both reconcilers.")
//! @yah:handoff("LANDED in the same session as R783-F1. ContainerReconciler's private ContainerComponent / BuildSpec / RunSpec / MountSpec structs are DELETED (oss/yubaba/crates/cloud/src/reconciler/container.rs). load_container_component now calls a new parse_container_recipe() that goes through workload_spec::Workload and requires the recipe form; resolve_mounts takes &[ContainerMount]. One parser, one discriminator - the local and cloud shapes can no longer diverge silently, which was the whole point of the split.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib reconciler::container - 12 pass, 0 fail (4 new: a_container_declaring_neither_form_is_rejected_by_name, a_digest_pinned_reference_is_refused_as_the_wrong_tier, the_real_cloud_admin_manifest_loads_through_the_envelope, build_keys_default_inside_an_empty_build_table).")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib - 881 pass, 0 fail, 4 ignored.")
//! @yah:verify("The acceptance case is now a unit test, not a manual step: the_real_cloud_admin_manifest_loads_through_the_envelope reads the REAL crates/yah/cloud-admin/workload.toml off disk (skipping if absent, since the yubaba workspace exports standalone) and asserts name/port/host_port/mounts survive - [process] table and all.")
//! @yah:gotcha("BEHAVIOUR CHANGE, small but real: the `[build]` HEADER is now load-bearing. Every key inside it still defaults (dockerfile=Dockerfile, context=component dir, image=yah-local/<service>-<component>:dev), but a kind = container manifest with only [run] used to parse with a fully defaulted build section and now fails with an error naming both container forms. Zero on-disk files are affected - crates/yah/cloud-admin/workload.toml is the only container manifest in the camp and it has [build]. The old permissive case was covered by a test named build_defaults_when_section_absent; it is replaced by build_keys_default_inside_an_empty_build_table plus a_container_declaring_neither_form_is_rejected_by_name.")
//! @yah:gotcha("The [process] table is TOLERATED, not modelled: ContainerBuild deliberately has no serde(deny_unknown_fields), which is what keeps crates/yah/cloud-admin/workload.toml loadable by BOTH ContainerReconciler and LocalProcessReconciler. Adding deny_unknown_fields there later would break the dev tier - the reason is on ContainerBuild's doc comment, keep it.")
//! @yah:verify("NOT RUN, stated plainly: the ticket's own acceptance line - `yah cloud mirror up yah-cloud-admin --env pond`, container builds and runs, publishes on 4326 - was NOT executed. It needs a live docker/orbstack daemon and a real docker build of the cloud-admin image on this box. The parse path it exercises is covered by the_real_cloud_admin_manifest_loads_through_the_envelope (reads the actual file), and everything after the parse (build_image, ContainerRunSpec, teardown naming) is byte-for-byte the pre-existing code path - only the struct the fields are read off changed. Still worth one live run before archive.")

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use local_driver::{canonical_name, ContainerRunSpec, ContainerState, LocalRuntime};
use workload_spec::{ContainerBuild, ContainerMount, Workload};

use super::{ReconcileCtx, Reconciler, RunningWorkload};
use crate::config::{CloudConfig, Provider};
use crate::local_container_spec_from_provider;
use crate::MirrorShape;

/// The slot role a container component occupies on its mirror.
const SLOT: &str = "compute";

/// Options controlling the container reconciler's local path.
#[derive(Debug, Clone, Default)]
pub struct ContainerOptions {
    /// When true, skip build+run and only adopt an already-running container
    /// (parity with `PondOptions::adopt_only`). Errors when none is running.
    pub adopt_only: bool,
}

/// Reconciler for `kind = "container"` components.
#[derive(Debug, Default)]
pub struct ContainerReconciler {
    opts: ContainerOptions,
}

impl ContainerReconciler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(mut self, opts: ContainerOptions) -> Self {
        self.opts = opts;
        self
    }
}

#[async_trait]
impl Reconciler for ContainerReconciler {
    fn kind(&self) -> &'static str {
        "container"
    }

    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        // git-sourced components: clone/update the local checkout first
        // (no-op for in-tree components).
        ctx.materialize().await?;

        // Scope guard: T1 is the operator-local tier. The cloud tier is
        // yubaba-mediated (`yah cloud workload deploy`), a separate surface.
        if !matches!(ctx.mirror.shape, MirrorShape::Local) {
            bail!(
                "component {}: kind \"container\" has only a local reconciler — mirror \
                 shape is {:?}, not `local`. Deploy the cloud tier via \
                 `yah cloud workload deploy` against a yubaba machine.",
                ctx.component.id,
                ctx.mirror.shape,
            );
        }

        let spec = load_container_component(&ctx)?;
        let container_port = spec.run.port.with_context(|| {
            format!(
                "component {}: workload.toml is missing [run].port — the container reconciler \
                 needs the port the process listens on",
                ctx.component.id,
            )
        })?;
        let host_port = spec.run.host_port.unwrap_or(container_port);

        let runtime = detect_local_runtime(&ctx)
            .await
            .context("detecting local container runtime (orbstack/colima/docker)")?;

        let name = canonical_name(&ctx.service.name, ctx.env, &ctx.component.id);

        // adopt-only: don't build/run, just report an already-running container.
        if self.opts.adopt_only {
            return match runtime.container_state(&name).await? {
                Some(ContainerState::Running) => {
                    let hp = runtime
                        .container_host_port(&name, container_port)
                        .await
                        .unwrap_or(host_port);
                    Ok(RunningWorkload::adopted(
                        "container",
                        SLOT,
                        Some(format!("http://127.0.0.1:{hp}")),
                    )
                    .with_teardown(teardown_for(&ctx, name.clone())))
                }
                other => bail!(
                    "adopt_only: no running container named {name} for component {} \
                     (state: {other:?}) — nothing to adopt",
                    ctx.component.id,
                ),
            };
        }

        // Build the image from the component's Dockerfile.
        let image = spec
            .build
            .image
            .clone()
            .unwrap_or_else(|| default_image_tag(&ctx.service.name, &ctx.component.id));
        let dockerfile = ctx.workload_dir().join(&spec.build.dockerfile);
        let context = match &spec.build.context {
            Some(rel) => ctx.workspace_root.join(rel),
            None => ctx.workload_dir(),
        };
        runtime
            .build_image(&image, &dockerfile, &context)
            .await
            .with_context(|| {
                format!(
                    "building image {image} for component {} (dockerfile {}, context {})",
                    ctx.component.id,
                    dockerfile.display(),
                    context.display(),
                )
            })?;

        // Run it with the declared ports + env. `run` clears any prior
        // container of the same name first, so re-reconcile is idempotent.
        let mut run_spec =
            ContainerRunSpec::new(&ctx.service.name, ctx.env, &ctx.component.id, image);
        run_spec.ports = vec![(host_port, container_port)];
        run_spec.env = spec.run.env.clone();
        run_spec.volumes = resolve_mounts(&spec.run.mounts, ctx.workspace_root)?;
        runtime
            .run(&run_spec)
            .await
            .with_context(|| format!("running container for component {}", ctx.component.id))?;

        // Read the actual host port (host_port=0 requests an ephemeral one).
        let actual = runtime
            .container_host_port(&name, container_port)
            .await
            .unwrap_or(host_port);

        Ok(RunningWorkload::adopted(
            "container",
            SLOT,
            Some(format!("http://127.0.0.1:{actual}")),
        )
        .with_teardown(teardown_for(&ctx, name.clone())))
    }
}

/// Grace period for the stop half of the teardown before the container is
/// removed. Matches what an operator expects from a ■ button: long enough for
/// a well-behaved server to close listeners, short enough not to look hung.
const TEARDOWN_GRACE: Duration = Duration::from_secs(5);

/// Build the explicit teardown for a container-kind workload (R714-B1).
///
/// Before this, `up()` handed back a bare `RunningWorkload::adopted()`, whose
/// `shutdown()` is a documented no-op. Nothing else covered the gap either:
/// the desktop's pond teardown half gates on a `Provider::MiniflareContainer`
/// static slot, and a plain `kind = container` mirror declares no static slot,
/// so its ident list came back empty and the loop body never ran. The ■ button
/// removed the registry entry, called the no-op, and returned success with the
/// container still up.
///
/// The runtime is re-detected inside the hook rather than captured: the hook
/// outlives the borrowed [`ReconcileCtx`], and re-running the same lookup
/// `up()` did means both halves agree on which daemon they mean even if the
/// operator switched runtimes in between.
/// The `Sync` in the return bound is required by [`RunningWorkload::with_teardown`]
/// — see the note on its `TeardownFn` alias for why a non-`Sync` hook breaks
/// every desktop Tauri command that touches the mirror registry.
fn teardown_for(
    ctx: &ReconcileCtx<'_>,
    name: String,
) -> impl FnOnce() -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync + 'static {
    let workspace_root = ctx.workspace_root.to_path_buf();
    move || {
        Box::pin(async move {
            let runtime = detect_local_runtime_at(&workspace_root)
                .await
                .context("detecting local container runtime for teardown")?;
            runtime
                .stop_and_remove(&name, TEARDOWN_GRACE)
                .await
                .with_context(|| format!("stopping container {name}"))
        })
    }
}

/// Read `<workload_dir>/workload.toml` and parse the container `[build]` +
/// `[run]` sections.
fn load_container_component(ctx: &ReconcileCtx<'_>) -> Result<ContainerBuild> {
    let path = ctx.workload_dir().join("workload.toml");
    let src =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    parse_container_recipe(&src).with_context(|| format!("parsing {}", path.display()))
}

/// Parse a `workload.toml` through the shared envelope and require the recipe
/// form (R783-F2).
///
/// This reconciler used to deserialize its own private `ContainerComponent`
/// straight off the file. That is why R658-B2 could exist for months: with two
/// parsers reading one `kind`, the shapes had no way to disagree *loudly* —
/// `crates/yah/cloud-admin/workload.toml` parsed fine here while failing
/// `workload_spec::Workload` entirely, and only a CI walk over every manifest
/// noticed. One parser, one discriminator: now a manifest that is neither a
/// digest-pinned reference nor a build recipe fails in both places with the
/// same message.
pub(crate) fn parse_container_recipe(src: &str) -> Result<ContainerBuild> {
    let workload: Workload = toml::from_str(src)?;
    let Workload::Container(manifest) = &workload else {
        bail!(
            "expected kind = \"container\", found kind = {:?}",
            workload.kind_str(),
        );
    };
    match manifest.clone().into_spec() {
        Err(recipe) => Ok(recipe),
        Ok(spec) => bail!(
            "workload {:?} is a digest-pinned container REFERENCE, not a local build recipe — \
             that form deploys to a yubaba machine via `yah cloud workload deploy`, not \
             through this reconciler",
            spec.name,
        ),
    }
}

/// Default image tag when `workload.toml` doesn't pin one.
fn default_image_tag(service: &str, component: &str) -> String {
    format!("yah-local/{service}-{component}:dev")
}

/// Turn `[[run.mounts]]` into `docker run -v` pairs, resolved against the
/// workspace root.
///
/// A missing host path is a hard error rather than a skipped mount. Docker
/// would happily create an empty directory in its place, and the container
/// would then start, pass health checks, and serve whatever "no config found"
/// means for that service — a deploy that looks green while the thing it was
/// supposed to read isn't there.
///
/// The `:ro` suffix rides on the container-path string because
/// `ContainerRunSpec::docker_run_args` emits `-v <host>:<container>` verbatim;
/// that is docker's own mount-option syntax, not a hack around the type.
fn resolve_mounts(
    mounts: &[ContainerMount],
    workspace_root: &std::path::Path,
) -> Result<Vec<(std::path::PathBuf, String)>> {
    mounts
        .iter()
        .map(|m| {
            let host = std::path::Path::new(&m.host);
            let host = if host.is_absolute() {
                host.to_path_buf()
            } else {
                workspace_root.join(host)
            };
            if !host.exists() {
                bail!(
                    "mount source {} does not exist (declared as `{}` in workload.toml \
                     [[run.mounts]]) — the container would silently get an empty directory",
                    host.display(),
                    m.host,
                );
            }
            let container = m.container.display().to_string();
            let target = if m.read_only {
                format!("{container}:ro")
            } else {
                container
            };
            Ok((host, target))
        })
        .collect()
}

/// Detect the workspace's `local-container` runtime, the same way the pond
/// primitives do — find the `kind = "local-container"` provider (orbstack.toml
/// et al.) and probe its sockets. `ReconcileCtx` doesn't carry `CloudConfig`,
/// so we reload it from the workspace root.
async fn detect_local_runtime(ctx: &ReconcileCtx<'_>) -> Result<LocalRuntime> {
    detect_local_runtime_at(ctx.workspace_root).await
}

/// Same lookup keyed on the workspace root alone, so the R714-B1 teardown hook
/// — which outlives the borrowed [`ReconcileCtx`] — can re-detect the runtime
/// without capturing it.
async fn detect_local_runtime_at(workspace_root: &std::path::Path) -> Result<LocalRuntime> {
    let cfg = CloudConfig::load(workspace_root)
        .context("loading CloudConfig for local-container provider lookup")?;
    let provider = cfg
        .providers
        .iter()
        .find(|p| matches!(p.kind, Provider::LocalContainer))
        .with_context(|| {
            format!(
                "no `kind = \"local-container\"` provider declared in {}/.yah/infra/providers/ — \
                 the container reconciler needs orbstack.toml or equivalent",
                workspace_root.display(),
            )
        })?;
    let local_spec = local_container_spec_from_provider(provider)?;
    LocalRuntime::detect(&local_spec).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_build_and_run_sections() {
        let src = r#"
schema_version = 1
name = "yah-cloud-admin"
kind = "container"

[build]
dockerfile = "Dockerfile"
context = "."
image = "yah-local/yah-cloud-admin:dev"

[run]
port = 4325
host_port = 4325

[run.env]
YAH_CLOUD_ADMIN_ADDR = "0.0.0.0:4325"
YAH_CLOUD_ADMIN_DEV_ANON = "1"
"#;
        let c = parse_container_recipe(src).unwrap();
        assert_eq!(c.build.dockerfile, std::path::Path::new("Dockerfile"));
        assert_eq!(c.build.context.as_deref(), Some(std::path::Path::new(".")));
        assert_eq!(
            c.build.image.as_deref(),
            Some("yah-local/yah-cloud-admin:dev")
        );
        assert_eq!(c.run.port, Some(4325));
        assert_eq!(c.run.host_port, Some(4325));
        assert_eq!(
            c.run.env.get("YAH_CLOUD_ADMIN_ADDR").map(String::as_str),
            Some("0.0.0.0:4325")
        );
        assert_eq!(
            c.run
                .env
                .get("YAH_CLOUD_ADMIN_DEV_ANON")
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn mounts_resolve_against_the_workspace_root_and_default_read_only() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".yah/infra")).unwrap();
        let src = r#"
schema_version = 1
name = "svc"
kind = "container"
[build]
[run]
port = 4325
[[run.mounts]]
host = ".yah/infra"
container = "/workspace/.yah/infra"
"#;
        let c = parse_container_recipe(src).unwrap();
        let out = resolve_mounts(&c.run.mounts, tmp.path()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, tmp.path().join(".yah/infra"));
        assert_eq!(out[0].1, "/workspace/.yah/infra:ro");
    }

    #[test]
    fn a_writable_mount_must_be_asked_for() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("state")).unwrap();
        let src = r#"
schema_version = 1
name = "svc"
kind = "container"
[build]
[run]
port = 1
[[run.mounts]]
host = "state"
container = "/var/lib/state"
read_only = false
"#;
        let c = parse_container_recipe(src).unwrap();
        let out = resolve_mounts(&c.run.mounts, tmp.path()).unwrap();
        assert_eq!(out[0].1, "/var/lib/state");
    }

    /// Docker would invent an empty directory here; a monitor mounting a
    /// non-existent inventory must fail the deploy, not render zero machines.
    #[test]
    fn a_missing_mount_source_fails_the_reconcile() {
        let tmp = tempfile::tempdir().unwrap();
        let src = r#"
schema_version = 1
name = "svc"
kind = "container"
[build]
[run]
port = 1
[[run.mounts]]
host = "nope"
container = "/nope"
"#;
        let c = parse_container_recipe(src).unwrap();
        let err = resolve_mounts(&c.run.mounts, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn no_mounts_declared_is_no_volumes() {
        let c = parse_container_recipe(
            "schema_version = 1\nname = \"svc\"\nkind = \"container\"\n[build]\n[run]\nport = 1\n",
        )
        .unwrap();
        assert!(c.run.mounts.is_empty());
        assert!(resolve_mounts(&c.run.mounts, std::path::Path::new("/"))
            .unwrap()
            .is_empty());
    }

    /// An empty `[build]` header is enough: every key inside it defaults, so a
    /// component that just wants `Dockerfile` in its own directory writes one
    /// line.
    #[test]
    fn build_keys_default_inside_an_empty_build_table() {
        let src = r#"
schema_version = 1
name = "svc"
kind = "container"
[build]
[run]
port = 8080
"#;
        let c = parse_container_recipe(src).unwrap();
        assert_eq!(c.build.dockerfile, std::path::Path::new("Dockerfile"));
        assert!(c.build.context.is_none());
        assert!(c.build.image.is_none());
        assert_eq!(c.run.port, Some(8080));
        assert!(c.run.host_port.is_none());
        assert!(c.run.env.is_empty());
    }

    /// R783-F2, the point of routing through the envelope: the `[build]`
    /// header is now load-bearing. Without it — and without a digest-pinned
    /// `image` — the file declares neither container form, and the error says
    /// so instead of quietly defaulting a Dockerfile that may not be there.
    #[test]
    fn a_container_declaring_neither_form_is_rejected_by_name() {
        let src = r#"
schema_version = 1
name = "svc"
kind = "container"
[run]
port = 8080
"#;
        let err = parse_container_recipe(src).unwrap_err().to_string();
        assert!(err.contains("image"), "{err}");
        assert!(err.contains("[build]"), "{err}");
    }

    /// The other half of the same seam: the wire form is a valid container
    /// manifest, and this reconciler must say it is the wrong *tier* rather
    /// than fail on a parse error that blames the file.
    #[test]
    fn a_digest_pinned_reference_is_refused_as_the_wrong_tier() {
        // Build the fixture from the type rather than by hand — a
        // hand-written WorkloadSpec TOML would be testing my ability to
        // transcribe 20 required fields, not the dispatch.
        let spec = workload_spec::WorkloadSpec::for_forge(
            "noisetable-api",
            workload_spec::ImageRef {
                registry: "ghcr.io".into(),
                repository: "noisetable/api".into(),
                tag: "v1".into(),
                digest: workload_spec::testing::test_digest(),
            },
            workload_spec::TierTag("private".into()),
            vec![8080],
        );
        let src = toml::to_string(&Workload::container(spec)).expect("serialize the wire form");
        assert!(src.contains("kind = \"container\""), "{src}");

        let err = parse_container_recipe(&src).unwrap_err().to_string();
        assert!(err.contains("REFERENCE"), "{err}");
        assert!(err.contains("yah cloud workload deploy"), "{err}");
    }

    /// The acceptance case for R658-B2 / R783: the real cloud-admin manifest,
    /// `[process]` table and all, loads through the shared envelope.
    #[test]
    fn the_real_cloud_admin_manifest_loads_through_the_envelope() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("oss/yubaba/crates/cloud has at least three ancestors")
            .join("crates/yah/cloud-admin/workload.toml");
        let Ok(src) = std::fs::read_to_string(&path) else {
            // The yubaba workspace is exported standalone; the camp file is not
            // there in the mirror. Skip rather than fail in that build.
            return;
        };
        let c = parse_container_recipe(&src)
            .unwrap_or_else(|e| panic!("{} must parse as a container recipe: {e}", path.display()));
        assert_eq!(c.name, "yah-cloud-admin");
        assert_eq!(c.run.port, Some(4325));
        assert_eq!(c.run.host_port, Some(4326));
        assert_eq!(c.run.mounts.len(), 1, "the [[run.mounts]] entry survived");
    }

    /// R714-B1: the teardown must target the container `run()` actually
    /// created. `LocalRuntime::stop_and_remove` is a documented no-op on a
    /// container that doesn't exist, so if these two names ever drift apart
    /// the ■ button goes back to reporting success while the container runs —
    /// and it does so silently, with no error to surface. `up()` feeds the
    /// same `(service, env, component.id)` triple to both; this pins that.
    #[test]
    fn the_teardown_name_matches_the_name_run_created() {
        let (service, env, component) = ("yah-cloud-admin", "pond", "cloud-admin");
        let run_spec = ContainerRunSpec::new(service, env, component, "img:dev");
        let teardown_target = canonical_name(service, env, component);
        assert_eq!(
            run_spec.name, teardown_target,
            "teardown would docker-stop a name that was never created"
        );
    }

    #[test]
    fn default_image_tag_derives_from_service_and_component() {
        assert_eq!(
            default_image_tag("yah-cloud-admin", "cloud-admin"),
            "yah-local/yah-cloud-admin-cloud-admin:dev"
        );
    }

    #[test]
    fn run_spec_publishes_declared_ports_and_env() {
        // The docker_run_args wiring a live reconcile would emit, exercised
        // without a docker socket.
        let mut run_spec =
            ContainerRunSpec::new("yah-cloud-admin", "dev", "cloud-admin", "img:dev");
        run_spec.ports = vec![(4325, 4325)];
        run_spec.env.insert("K".into(), "V".into());
        let args = run_spec.docker_run_args();
        // -p 4325:4325 present.
        let joined = args.join(" ");
        assert!(joined.contains("-p 4325:4325"), "args: {joined}");
        assert!(joined.contains("-e K=V"), "args: {joined}");
        assert!(
            joined.ends_with("img:dev"),
            "image is the final arg: {joined}"
        );
    }
}
