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
        let coords = super::s3_driver::coords_path(ctx.workspace_root);
        // R967-B1: a camp that is running but whose driver failed to come up
        // must not be told to "start yah camp". Quote what actually failed.
        match super::s3_driver::recorded_bringup_error(ctx.workspace_root) {
            Some(why) => format!(
                "the dev-tier s3 driver is not running — {} has no coordinates, so there is \
                 nowhere to publish {}/{}'s assets. Its last bring-up failed: {why}",
                coords.display(),
                ctx.service.name,
                ctx.component.id,
            ),
            None => format!(
                "the dev-tier s3 driver is not running — {} has no coordinates, so there is \
                 nowhere to publish {}/{}'s assets. The camp brings this driver up: start \
                 `yah camp` for this workspace (or attach it in the desktop).",
                coords.display(),
                ctx.service.name,
                ctx.component.id,
            ),
        }
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

    let prefix = mount_key_prefix(ctx);
    let report = super::pond_publish::publish_to_pond(
        &dist_dir,
        endpoint,
        bucket,
        DEV_ACCESS_KEY,
        DEV_SECRET_KEY,
        prefix.as_deref(),
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
///
/// @yah:ticket(R584-B8, "Dev/pond static doors die with the `yah cloud mirror up` CLI: miniflare is supervised in-process with kill_on_drop")
/// @yah:status(review)
/// @yah:at(2026-10-10T19:14:35Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R584)
/// @yah:severity(high)
/// @yah:handoff("LANDED (Ashguard:polaris, courier for noisetable R823, F1071). Choice: a detached supervised child, not a hand-off to the daemon. It is the same durability contract local-process slots already have (pid record + reap on re-run), so it works with no camp running, and the Run tab keeps its in-process supervision unchanged. pond.rs spawn_miniflare_child: no kill_on_drop. stdout/stderr go to door_dir/miniflare.{stdout,stderr}.log (FileTail feeds the LogBuffer and detects the ready line; FileTail is no longer gated to unix). process_group(0), and the pgid is recorded in door_dir/miniflare.pgid. A re-run calls reap_door_predecessor (killpg TERM, 5s, KILL) before ensure_sim_port_free. New MiniflareChild owns child+pgid. Dropping it kills nothing. run_miniflare_supervisor returns Supervised::{Stopped, Detached}: a dropped-unsent shutdown sender means Detached, and the door is left serving. New RunningWorkload::detach() (reconciler/mod.rs). native_support's local-process supervisor also skips teardown on a dropped sender. CLI handle_mirror_up (app/yah/cli/src/cloud.rs) now holds the workloads. On success it detaches them. On any phase failure it rolls them back via shutdown(). Pond: when detached, supervise_miniflare_and_minio leaves MinIO up too. There is no `mirror down` verb (MirrorCommands is Show/Status/Up), so the re-run is the reaper, as it is for local-process.")
/// @yah:verify("yah-cloud lib: 1363 pass / 0 fail / 6 ignored (baseline 1359; +4: a_detached_door_survives_and_the_next_spawn_reaps_it, kill_group_reaps_a_grandchild_that_ignores_sigterm, a_local_process_workload_port_collides_with_a_door, a_mounted_component_publishes_under_its_mount). cargo check -p yah -p desktop EXIT=0. Opt-in binary (target/opt-in/bin/yah) in noisetable: after `mirror up noisetable-marketing --env dev` exited 0, :4331/ gave 200 and :4332/app/ 200 (with R584-B10). On a re-run the old bun/workerd pids were all gone, exactly one bun+workerd per door, one listener each on 4331/4332. Needs yah-install (live ~/.local/bin/yah) before QED web-dev-smoke sees it, and a yah-desktop-build + relaunch for the Run tab.")
/// @yah:gotcha("Behaviour change: since dropping a door handle no longer kills it, a desktop that quits abruptly without calling shutdown leaves its doors serving until the next up of that door reaps them. Previously kill_on_drop killed bun but stranded workerd anyway. Also: the stop-everything step of my verification sent SIGTERM to pids from the stale noisetable-desktop owner.json records (1743, 97637; files dated Oct 4/5). Neither pid exists now, and I cannot tell whether either was live (possibly recycled) when signalled.")
/// The bucket key prefix a component publishes under: its `mount`, the way
/// the cloud tier's `publish_prefix` appends it after `<svc>/<env>`. Every
/// component of a service shares the one dev bucket, so without this a
/// `mount = "/app"` component landed at the bucket root — clobbering its
/// root-mounted sibling's `index.html` and leaving `/app/` a 404 (noisetable
/// R823, found under R584-B8).
///
/// @yah:ticket(R584-B10, "Dev door publishes every component to the bucket root, ignoring `mount`: /app/ 404s and siblings clobber index.html")
/// @yah:status(review)
/// @yah:at(2026-10-10T19:14:49Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R584)
/// @yah:severity(medium)
/// @yah:handoff("LANDED (Ashguard:polaris), found while working noisetable R823 item 2. This ticket was filed after the fix, not before. Cause: dev_door::publish passed key_prefix None, so every component of a service published to the root of the one shared dev bucket. noisetable-marketing's app (mount=/app, out_dir=publish, so it serves app/browser/publish) overwrote the site's index.html and left nothing at app/. :4332/app/ was a 404 and :4332/ served whichever index won. This was not an artifact of R584-B8. Fix: new mount_key_prefix(ctx) publishes under normalize_mount(mount), matching the cloud tier's publish_prefix `<svc>/<env>/<mount>`. No noisetable declaration change is needed.")
/// @yah:verify("Unit: a_mounted_component_publishes_under_its_mount. Live, opt-in: :4332/app/ 200 serving the app bundle (cdn.noisetable.com/app/ refs, 4 hits) and :4331/ the site (0 hits).")
/// @yah:gotcha("The same None prefix exists in pond.rs up_pond's publish_to_pond call. NOT changed (out of brief scope; docker is inert for agents). Separately, the dev door sends no per-route headers: spawn_miniflare_child passes domain None to worker_route_table_json, so /app/ lacks noisetable-com.toml's COOP/COEP, and web-dev-smoke's app-boot fails crossOriginIsolated. Not filed here.")
/// @yah:cleanup("noisetable's dev bucket still holds the app files the pre-fix runs published at its root (BUILDINFO.json, THIRD-PARTY-NOTICES.*). Harmless, but a clean re-publish of the bucket would drop them.")
fn mount_key_prefix(ctx: &ReconcileCtx<'_>) -> Option<String> {
    ctx.component
        .mount
        .as_deref()
        .map(crate::config::normalize_mount)
        .filter(|m| !m.is_empty())
}

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
        &super::mesofact_static::BackendOrigins::from_slot_fields(static_fields),
    )
    .await?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    // Unlike the pond arm there is nothing to tear down behind the door: the
    // store is the camp's, outlives this mirror, and is shared with every other
    // dev service. Stopping the mirror stops the door and nothing else.
    let supervisor = tokio::spawn(async move {
        // Detached (R584-B8) or stopped: either way nothing more to own.
        let _ = run_miniflare_supervisor(child, shutdown_rx).await;
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
        toml::from_str("schema_version = 1\nname = \"yah-marketing\"\n[address]\nkind = \"front-door\"\ndomain = \"yah.dev\"\n")
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

    #[test]
    fn a_mounted_component_publishes_under_its_mount() {
        let svc = service();
        let m = mirror("schema_version = 1\nshape = \"local\"\n");
        let root = component();
        assert_eq!(mount_key_prefix(&ctx(Path::new("/tmp"), &svc, &root, &m)), None);

        let app: ServiceComponent = toml::from_str(
            "id = \"app\"\nkind = \"mesofact-static\"\npath = \"app/browser\"\n\
             role = \"static\"\nmount = \"/app\"\n",
        )
        .expect("parse component");
        assert_eq!(
            mount_key_prefix(&ctx(Path::new("/tmp"), &svc, &app, &m)).as_deref(),
            Some("app")
        );
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

    #[tokio::test]
    async fn a_recorded_bringup_failure_is_quoted_instead_of_telling_a_running_camp_to_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let failure = super::super::s3_driver::bringup_error_path(dir.path());
        std::fs::create_dir_all(failure.parent().unwrap()).unwrap();
        std::fs::write(&failure, "port 49786 (PORT_S3) is held by pid 80519\n").unwrap();
        let svc = service();
        let comp = component();
        let m = mirror("schema_version = 1\nshape = \"local\"\n");
        let err = format!(
            "{:#}",
            store_endpoint(&ctx(dir.path(), &svc, &comp, &m)).expect_err("no coords written")
        );
        assert!(err.contains("coords.json"), "{err}");
        assert!(err.contains("pid 80519"), "{err}");
        assert!(!err.contains("start `yah camp`"), "{err}");
    }
}
