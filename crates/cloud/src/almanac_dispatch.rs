//! Dispatch [`almanac::OnChangeConfig`] actions after a feed run (R330-F4).
//!
//! The almanac crate writes the feed artifact and returns the on_change action
//! to its caller; this module is the caller-side implementation that knows how
//! to map each action variant to the right reconciler.
//!
//! Current variants:
//! - [`almanac::OnChangeConfig::MesofactRebuild`] → call
//!   [`MesofactStaticReconciler::revalidate_static`] on the named service's
//!   mirror for `env`. An almanac feed change is *data*, not a source/template
//!   change, so this is the revalidate-only path (W225 §3, R535-T1): it never
//!   runs the workload's `build.command` — see `revalidate_static`'s doc for
//!   what "already-built bundle" means for each provider arm.
//! - [`almanac::OnChangeConfig::Reload`] → nothing, deliberately. See the arm.

use anyhow::{Context, Result};
use std::path::Path;
use yah_almanac::OnChangeConfig;

use crate::config::CloudConfig;
use crate::reconciler::{MesofactStaticReconciler, ReconcileCtx};

/// Dispatch the `on_change` action from an almanac [`RunResult`].
///
/// `workspace_root` must be the project root (parent of `.yah/`).
/// `env` selects which mirror environment to target (e.g. `"prod"`, `"pond"`).
pub async fn dispatch_on_change(
    on_change: &OnChangeConfig,
    workspace_root: &Path,
    env: &str,
) -> Result<()> {
    match on_change {
        OnChangeConfig::MesofactRebuild { service, route } => {
            revalidate_mesofact(service, route, workspace_root, env).await
        }
        // Nothing to do here, and that is the design rather than a stub.
        //
        // A `reload` feed's consumer reads the emitted artifact directly, so the
        // artifact write that already happened upstream of this call IS the
        // update — there is no render to trigger and no bundle to publish. The
        // variant exists because `on_change` carries the feed's mirror binding
        // as well as its action (see the enum's docs and R335-F3): without one,
        // the receiver rejects the feed with 422 before it ever runs.
        //
        // A consumer that needs a genuine in-process nudge must get it from the
        // process embedding `almanac::serve::run`, which owns the artifact and
        // the reader. This function is the *control-plane* reconciler and cannot
        // reach into another process's address space; pretending otherwise here
        // would be a silent no-op instead of an explicit one.
        OnChangeConfig::Reload { service } => {
            tracing::info!(
                service,
                env,
                "almanac on_change: reload — the artifact write is the update, \
                 nothing to rebuild"
            );
            Ok(())
        }
    }
}

async fn revalidate_mesofact(
    service_name: &str,
    route: &str,
    workspace_root: &Path,
    env: &str,
) -> Result<()> {
    let config = CloudConfig::load(workspace_root)
        .with_context(|| format!("loading cloud config from {}", workspace_root.display()))?;

    let svc = config
        .service(service_name)
        .with_context(|| format!("service {service_name:?} not found in .yah/services/"))?;

    let component = svc
        .service
        .components
        .iter()
        .find(|c| c.kind == "mesofact-static")
        .with_context(|| format!("service {service_name:?} has no mesofact-static component"))?;

    let mirror = svc
        .mirrors
        .get(env)
        .with_context(|| format!("service {service_name:?} has no mirror for env {env:?}"))?;

    let ctx = ReconcileCtx {
        workspace_root,
        service: &svc.service,
        component,
        mirror,
        env,
        scope: crate::reconciler::ProviderScope::singleton(),
    };

    let reconciler = MesofactStaticReconciler::new();
    let result = reconciler.revalidate_static(ctx, route).await?;

    tracing::info!(
        service = service_name,
        env,
        public_url = ?result.public_url,
        "almanac on_change: mesofact revalidate complete"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_toml(path: &std::path::Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[tokio::test]
    async fn missing_service_returns_error() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // No services declared — CloudConfig::load returns an empty map.
        let on_change = OnChangeConfig::MesofactRebuild {
            service: "no-such-svc".to_string(),
            route: "/releases".to_string(),
        };
        let err = dispatch_on_change(&on_change, root, "prod")
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no-such-svc"), "got: {msg}");
    }

    #[tokio::test]
    async fn missing_mirror_env_returns_error() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // Write service.toml with a mesofact-static component, but no mirrors.
        write_toml(
            &root.join(".yah/services/dev-yah/service.toml"),
            r#"schema_version = 1
name = "dev-yah"
domain = "yah.dev"

[[components]]
id = "site"
kind = "mesofact-static"
path = "app/yah/web"
role = "static"
wave = 0
"#,
        );
        let on_change = OnChangeConfig::MesofactRebuild {
            service: "dev-yah".to_string(),
            route: "/releases".to_string(),
        };
        let err = dispatch_on_change(&on_change, root, "prod")
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no mirror"), "got: {msg}");
    }

    /// R707-F4: a `reload` needs no service declared in `.yah/services/` and no
    /// mirror for `env` — it dispatches nothing. It must not be routed through
    /// the mesofact path and fail on a missing component that was never
    /// relevant.
    #[tokio::test]
    async fn reload_dispatches_nothing_and_needs_no_service_config() {
        let tmp = TempDir::new().unwrap();
        let on_change = OnChangeConfig::Reload {
            service: "yah-cloud-admin".to_string(),
        };
        dispatch_on_change(&on_change, tmp.path(), "prod")
            .await
            .expect("a reload must succeed against an empty workspace");
    }
}
