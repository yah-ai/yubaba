//! The dev-tier static surface: the same Worker the fleet serves, in front of
//! the `s3` capability driver the mirror binds (W265, R584-F4).
//!
//! # What this replaces, and why the replacement is the point
//!
//! Until this module landed, a dev-tier `mesofact-static` component was served
//! by `local-static`: the reconciler spawned `mesofact-dev`, which read the
//! workload's built `dist/` **off the filesystem** and handed it to the
//! browser. Every other tier published those same bytes into an object store
//! and served them through a Worker — MinIO + miniflare at pond, R2 + a
//! deployed Worker at cloud and ha.
//!
//! Two interfaces for one contract, which is the fork W265 exists to delete.
//! It is not an abstract complaint: a `Content-Type` the disk server inferred
//! differently, a route the Worker rewrites and the disk server does not, a
//! bucket policy nobody at dev ever had to set — each is a thing the app
//! discovers at the *next* tier up, which is the most expensive place to
//! discover it.
//!
//! So the dev tier now does what pond does:
//!
//! ```text
//!   dist/  ──publish_to_pond──▶  <s3 driver>/<bucket>  ──ASSET_ORIGIN──▶  miniflare (workerd)
//! ```
//!
//! The only thing that varies across dev / pond / cloud is **which
//! implementation of `s3` the mirror binds**, and that is declared rather than
//! branched on. The publish step is literally
//! [`super::pond_publish::publish_to_pond`], the door is literally
//! [`super::pond::spawn_miniflare_child`], and the script both run is the same
//! `worker/router.bundle.js` a fleet node serves.
//!
//! # Why there is no container here and one at pond
//!
//! miniflare was never the containerized half of pond — MinIO is. miniflare
//! runs as a plain child process at both tiers (`bun`/`node` executing the
//! shim, which spawns workerd). What dev drops is the MinIO container, because
//! `yah-s3-fs` already gives the camp an S3 surface with no docker daemon
//! anywhere in the picture. That is the whole difference between
//! `miniflare-container` and `miniflare-native`, and it lives in the store
//! binding rather than in the serving code.
//!
//! # The driver is camp-owned, not mirror-owned
//!
//! `yah-s3-fs` is brought up once per camp by `spawn_appliances`
//! ([`super::s3_driver`]), not by this reconciler, and it is always-on for any
//! camp with a dev mirror. A `mirror up` therefore *reads* its coordinates and
//! fails with a pointer at the camp if they are missing — it does not race the
//! camp to start a second store.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::sync::oneshot;
use tracing::{info, warn};

use local_driver::pond_minio::ensure_bucket_public;

use super::pond::{
    ensure_sim_port_free, run_miniflare_supervisor, spawn_miniflare_child, DoorScripts,
    PondOptions,
};
use super::{into_running, slot_field_u16, ReconcileCtx, RunningWorkload};
use crate::capability::Capability;
use crate::config::Provider;
use crate::reconciler::s3_driver::{running_endpoint, DEV_ACCESS_KEY, DEV_SECRET_KEY};

/// Slot role the door is declared under, shared with the pond arm.
const STATIC_SLOT: &str = "static";

/// Default loopback port for the dev door — the port `local-static` served on
/// before it retired, so an operator's bookmark still resolves.
pub const DEFAULT_DEV_DOOR_PORT: u16 = 4321;

/// `true` when this mirror binds the `s3` capability to the dev-tier driver,
/// i.e. when [`up_dev_door`] is the right arm for its static slot.
pub fn binds_dev_store(ctx: &ReconcileCtx<'_>) -> bool {
    ctx.mirror
        .driver(Capability::S3)
        .and_then(|slot| slot.inline_kind())
        == Some(Provider::LocalS3Fs)
}

/// Where the dev door keeps the two JS files it writes before spawning.
///
/// Under `.yah/infra/state/dev/`, beside the driver's own state, rather than
/// under `.yah/infra/pond/` — the tiers are separate and a shared directory
/// would make "is this camp's dev tier up?" unanswerable from the filesystem.
fn door_dir(ctx: &ReconcileCtx<'_>) -> PathBuf {
    ctx.workspace_root
        .join(".yah/infra/state/dev/door")
        .join(format!("{}-{}", ctx.service.name, ctx.component.id))
}

fn door_scripts(ctx: &ReconcileCtx<'_>) -> Result<DoorScripts> {
    let dir = door_dir(ctx);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(DoorScripts {
        worker_js: dir.join("worker.js"),
        miniflare_shim: dir.join("miniflare-sim.mjs"),
    })
}

/// Bucket this component's assets live in.
///
/// Defaults to the service name because that is what the camp driver creates
/// (`s3_driver::declared_s3_buckets` names one bucket per service with a dev
/// mirror) and what `S3_BUCKET` has meant to a dev app since R274-F5. A slot
/// may still name its own — [`ensure_bucket_public`] creates whatever it is
/// told, so an override is not a broken mirror.
fn resolve_bucket(ctx: &ReconcileCtx<'_>, fields: &BTreeMap<String, toml::Value>) -> String {
    fields
        .get("bucket")
        .and_then(|v| v.as_str())
        .unwrap_or(ctx.service.name.as_str())
        .to_string()
}

/// Resolve the store the mirror bound, or say why it cannot be reached.
///
/// The error is the useful half of this function. "connection refused on some
/// port" is what an operator would otherwise get three steps later, from
/// workerd, about a URL they never typed.
fn store_endpoint(ctx: &ReconcileCtx<'_>) -> Result<String> {
    running_endpoint(ctx.workspace_root).with_context(|| {
        format!(
            "the dev-tier s3 driver is not running — {} has no coordinates, so there is \
             nowhere to publish {}/{}'s assets. The camp brings this driver up: start \
             `yah camp` for this workspace (or attach it in the desktop).",
            super::s3_driver::coords_path(ctx.workspace_root).display(),
            ctx.service.name,
            ctx.component.id,
        )
    })
}

/// Publish `dist/` into the bound bucket. Returns how many objects landed.
///
/// Shared with [`sync_dev_door`]; `up` runs it before the door starts routing,
/// for the same reason the pond arm does — a first bring-up that skipped it
/// would serve an empty bucket and 404 every request.
async fn publish(ctx: &ReconcileCtx<'_>, endpoint: &str, bucket: &str) -> Result<usize> {
    ensure_bucket_public(endpoint, bucket, DEV_ACCESS_KEY, DEV_SECRET_KEY)
        .await
        .with_context(|| format!("ensuring dev bucket {bucket} exists and is public-read"))?;

    let out_dir = super::mesofact_static::read_workload_out_dir(&ctx.workload_dir())
        .unwrap_or_else(|| "dist".to_string());
    let dist_dir = ctx.workload_dir().join(&out_dir);
    if !dist_dir.exists() {
        warn!(
            dist = %dist_dir.display(),
            "no built dist to publish — serving existing bucket contents",
        );
        return Ok(0);
    }

    let report = super::pond_publish::publish_to_pond(
        &dist_dir,
        endpoint,
        bucket,
        DEV_ACCESS_KEY,
        DEV_SECRET_KEY,
        None,
    )
    .await
    .with_context(|| format!("publishing {} to dev bucket {bucket}", dist_dir.display()))?;
    Ok(report.uploaded.len())
}

/// Bring the dev-tier static surface up: publish, then serve.
///
/// `static_fields` are the `providers.static` slot's fields — `port` and an
/// optional `bucket` override. `worker_script` is the compiled Worker bundle,
/// injected by the caller so dev runs the same artifact prod does.
pub async fn up_dev_door(
    ctx: &ReconcileCtx<'_>,
    options: &PondOptions,
    static_fields: &BTreeMap<String, toml::Value>,
    worker_script: &str,
) -> Result<RunningWorkload> {
    let door_port = slot_field_u16(static_fields, "port").unwrap_or(DEFAULT_DEV_DOOR_PORT);
    let endpoint = store_endpoint(ctx)?;
    let bucket = resolve_bucket(ctx, static_fields);
    let scripts = door_scripts(ctx)?;

    let uploaded = publish(ctx, &endpoint, &bucket).await?;
    info!(
        uploaded,
        bucket = %bucket,
        endpoint = %endpoint,
        "dev publish complete",
    );

    let worker_mode =
        super::mesofact_static::parse_worker_mode(&ctx.component.kind, static_fields);

    let asset_origin = format!("{}/{}", endpoint.trim_end_matches('/'), bucket);
    let (child, log_buf) = spawn_miniflare_child(
        ctx,
        options,
        door_port,
        &scripts,
        &asset_origin,
        worker_script,
        &worker_mode,
    )
    .await?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    // Unlike the pond arm there is nothing to tear down behind the door: the
    // store is the camp's, outlives this mirror, and is shared with every other
    // dev service. Stopping the mirror stops the door and nothing else.
    let supervisor = tokio::spawn(async move {
        run_miniflare_supervisor(child, shutdown_rx).await;
        Ok(())
    });

    let dev_url = format!("http://127.0.0.1:{door_port}");
    info!(
        dev_url = %dev_url,
        asset_origin = %asset_origin,
        "dev door ready (miniflare + yah-s3-fs)",
    );

    Ok(into_running(
        super::mesofact_static::WORKLOAD_KIND,
        STATIC_SLOT,
        Some(dev_url),
        None,
        Some(log_buf),
        shutdown_tx,
        supervisor,
    ))
}

/// Re-publish a *running* dev mirror's `dist/` without touching the door —
/// the `⟳` affordance, and the exact counterpart of
/// [`super::pond::sync_pond`].
///
/// Re-running [`up_dev_door`] instead would collide on the already-bound door
/// port, which is the same reason pond has a separate sync entry point.
pub async fn sync_dev_door(
    ctx: &ReconcileCtx<'_>,
    static_fields: &BTreeMap<String, toml::Value>,
) -> Result<usize> {
    let endpoint = store_endpoint(ctx)?;
    let bucket = resolve_bucket(ctx, static_fields);
    let uploaded = publish(ctx, &endpoint, &bucket).await?;
    info!(uploaded, bucket = %bucket, "dev re-publish complete");
    Ok(uploaded)
}

/// Free the door port if this camp is holding it — used by callers that are
/// about to re-bind it. Re-exported so the dev arm's failure modes stay in one
/// module even though the implementation is shared with pond.
pub async fn ensure_door_port_free(port: u16) -> Result<()> {
    ensure_sim_port_free(port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MirrorConfig, ServiceComponent, ServiceConfig};
    use crate::reconciler::ProviderScope;
    use std::path::Path;

    fn mirror(src: &str) -> MirrorConfig {
        toml::from_str(src).expect("parse mirror")
    }

    fn service() -> ServiceConfig {
        toml::from_str("schema_version = 1\nname = \"yah-marketing\"\ndomain = \"yah.dev\"\n")
            .expect("parse service")
    }

    fn component() -> ServiceComponent {
        toml::from_str(
            "id = \"site\"\nkind = \"mesofact-static\"\npath = \"app/yah/web\"\nrole = \"static\"\n",
        )
            .expect("parse component")
    }

    fn ctx<'a>(
        root: &'a Path,
        service: &'a ServiceConfig,
        component: &'a ServiceComponent,
        mirror: &'a MirrorConfig,
    ) -> ReconcileCtx<'a> {
        ReconcileCtx {
            workspace_root: root,
            service,
            component,
            mirror,
            env: "dev",
            scope: ProviderScope::singleton(),
        }
    }

    #[test]
    fn the_dev_arm_is_selected_by_the_s3_driver_binding() {
        let svc = service();
        let comp = component();
        let bound = mirror(
            "schema_version = 1\nshape = \"local\"\n\n\
             [providers.static]\nkind = \"miniflare-native\"\nport = 4321\n\n\
             [drivers.s3]\nkind = \"local-s3-fs\"\n",
        );
        assert!(binds_dev_store(&ctx(
            Path::new("/tmp"),
            &svc,
            &comp,
            &bound
        )));

        // A mirror with a static door but no s3 binding is not a dev mirror —
        // the door has nothing to serve, and saying so here is what keeps the
        // pond/prod arms reachable.
        let unbound = mirror(
            "schema_version = 1\nshape = \"local\"\n\n\
             [providers.static]\nkind = \"miniflare-native\"\nport = 4321\n",
        );
        assert!(!binds_dev_store(&ctx(
            Path::new("/tmp"),
            &svc,
            &comp,
            &unbound
        )));
    }

    #[test]
    fn the_bucket_defaults_to_the_service_name_the_camp_created() {
        let svc = service();
        let comp = component();
        let m = mirror("schema_version = 1\nshape = \"local\"\n");
        let c = ctx(Path::new("/tmp"), &svc, &comp, &m);
        assert_eq!(resolve_bucket(&c, &BTreeMap::new()), "yah-marketing");

        let mut fields = BTreeMap::new();
        fields.insert("bucket".to_string(), toml::Value::String("other".into()));
        assert_eq!(resolve_bucket(&c, &fields), "other");
    }

    #[tokio::test]
    async fn a_missing_driver_names_the_coords_file_and_the_camp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let svc = service();
        let comp = component();
        let m = mirror("schema_version = 1\nshape = \"local\"\n");
        let err = store_endpoint(&ctx(dir.path(), &svc, &comp, &m))
            .expect_err("no coords written")
            .to_string();
        assert!(err.contains("coords.json"), "{err}");
        assert!(err.contains("yah camp"), "{err}");
    }
}
