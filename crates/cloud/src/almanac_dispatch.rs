//! Dispatch [`almanac::OnChangeConfig`] actions after a feed run (R330-F4).
//!
//! The almanac crate writes the feed artifact and returns the on_change action
//! to its caller; this module is the caller-side implementation that knows how
//! to map each action variant to the right reconciler.
//!
//! Current variant:
//! - [`almanac::OnChangeConfig::MesofactRebuild`] → run the workload's build
//!   command then call [`MesofactStaticReconciler::rebuild_static`] on the
//!   named service's mirror for `env`.

use yah_almanac::OnChangeConfig;
use anyhow::{Context, Result};
use std::path::Path;

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
            rebuild_mesofact(service, route, workspace_root, env).await
        }
    }
}

async fn rebuild_mesofact(
    service_name: &str,
    _route: &str,
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
    };

    let reconciler = MesofactStaticReconciler::new();
    let result = reconciler.rebuild_static(ctx).await?;

    tracing::info!(
        service = service_name,
        env,
        public_url = ?result.public_url,
        "almanac on_change: mesofact rebuild complete"
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
}
