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
//! Config lives in the component's `workload.toml`:
//!
//! ```toml
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
//! ```
//!
//! Scope (R602-T1): the **local** tier only. Non-`local` mirror shapes bail
//! with a pointer to `yah cloud workload deploy` (the yubaba-mediated cloud
//! tier), which is a separate surface.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use local_driver::{canonical_name, ContainerRunSpec, ContainerState, LocalRuntime};
use serde::Deserialize;

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

/// On-disk `workload.toml` shape for a `kind = "container"` component. Only
/// the `[build]` + `[run]` sections this reconciler drives are parsed; other
/// keys (name, kind, …) are ignored.
#[derive(Debug, Default, Deserialize)]
struct ContainerComponent {
    #[serde(default)]
    build: BuildSpec,
    #[serde(default)]
    run: RunSpec,
}

#[derive(Debug, Deserialize)]
struct BuildSpec {
    /// Dockerfile path, relative to the component dir.
    #[serde(default = "default_dockerfile")]
    dockerfile: String,
    /// Build context, relative to the workspace root. `None` → component dir.
    #[serde(default)]
    context: Option<String>,
    /// Image tag to build + run. `None` → derived from (service, component).
    #[serde(default)]
    image: Option<String>,
}

impl Default for BuildSpec {
    fn default() -> Self {
        Self {
            dockerfile: default_dockerfile(),
            context: None,
            image: None,
        }
    }
}

fn default_dockerfile() -> String {
    "Dockerfile".to_string()
}

#[derive(Debug, Default, Deserialize)]
struct RunSpec {
    /// Container port the process listens on.
    #[serde(default)]
    port: Option<u16>,
    /// Host port to publish. `None` → same as `port`.
    #[serde(default)]
    host_port: Option<u16>,
    /// Environment variables passed into the container.
    #[serde(default)]
    env: BTreeMap<String, String>,
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
                    ))
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
        ))
    }
}

/// Read `<workload_dir>/workload.toml` and parse the container `[build]` +
/// `[run]` sections.
fn load_container_component(ctx: &ReconcileCtx<'_>) -> Result<ContainerComponent> {
    let path = ctx.workload_dir().join("workload.toml");
    let src = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))
}

/// Default image tag when `workload.toml` doesn't pin one.
fn default_image_tag(service: &str, component: &str) -> String {
    format!("yah-local/{service}-{component}:dev")
}

/// Detect the workspace's `local-container` runtime, the same way the pond
/// primitives do — find the `kind = "local-container"` provider (orbstack.toml
/// et al.) and probe its sockets. `ReconcileCtx` doesn't carry `CloudConfig`,
/// so we reload it from the workspace root.
async fn detect_local_runtime(ctx: &ReconcileCtx<'_>) -> Result<LocalRuntime> {
    let cfg = CloudConfig::load(ctx.workspace_root)
        .context("loading CloudConfig for local-container provider lookup")?;
    let provider = cfg
        .providers
        .iter()
        .find(|p| matches!(p.kind, Provider::LocalContainer))
        .with_context(|| {
            format!(
                "no `kind = \"local-container\"` provider declared in {}/.yah/infra/providers/ — \
                 the container reconciler needs orbstack.toml or equivalent",
                ctx.workspace_root.display(),
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
        let c: ContainerComponent = toml::from_str(src).unwrap();
        assert_eq!(c.build.dockerfile, "Dockerfile");
        assert_eq!(c.build.context.as_deref(), Some("."));
        assert_eq!(c.build.image.as_deref(), Some("yah-local/yah-cloud-admin:dev"));
        assert_eq!(c.run.port, Some(4325));
        assert_eq!(c.run.host_port, Some(4325));
        assert_eq!(
            c.run.env.get("YAH_CLOUD_ADMIN_ADDR").map(String::as_str),
            Some("0.0.0.0:4325")
        );
        assert_eq!(
            c.run.env.get("YAH_CLOUD_ADMIN_DEV_ANON").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn build_defaults_when_section_absent() {
        // A workload.toml with only [run] still parses; build takes defaults.
        let src = r#"
kind = "container"
[run]
port = 8080
"#;
        let c: ContainerComponent = toml::from_str(src).unwrap();
        assert_eq!(c.build.dockerfile, "Dockerfile");
        assert!(c.build.context.is_none());
        assert!(c.build.image.is_none());
        assert_eq!(c.run.port, Some(8080));
        assert!(c.run.host_port.is_none());
        assert!(c.run.env.is_empty());
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
        let mut run_spec = ContainerRunSpec::new("yah-cloud-admin", "dev", "cloud-admin", "img:dev");
        run_spec.ports = vec![(4325, 4325)];
        run_spec.env.insert("K".into(), "V".into());
        let args = run_spec.docker_run_args();
        // -p 4325:4325 present.
        let joined = args.join(" ");
        assert!(joined.contains("-p 4325:4325"), "args: {joined}");
        assert!(joined.contains("-e K=V"), "args: {joined}");
        assert!(joined.ends_with("img:dev"), "image is the final arg: {joined}");
    }
}
