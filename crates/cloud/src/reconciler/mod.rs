//! Reconciler abstraction — bring a workload up against a mirror's
//! provider slots.
//!
//! A reconciler is the kind-specific code that knows how to deploy one
//! workload kind (`mesofact-static`, `container`, future `almanac`, …) to a
//! mirror. Selection: a [`ServiceComponent`](crate::ServiceComponent)'s
//! `kind` field picks which reconciler runs; the reconciler then dispatches
//! on the mirror's provider slot (e.g. `mesofact-static` →
//! `providers.static` slot → `local-static` inline or `cloudflare` ref).
//!
//! T3 ships [`MesofactStaticReconciler`] with the `local-static` path
//! wired (spawn `mesofact-dev` as a child process). The Cloudflare path is
//! a stub — the production reconciler lands once `mesofact-publisher`
//! integration is on the roadmap.
//!
//!
//! @yah:ticket(R419-F2, "Implement CloudflareWorkerReconciler (kind=cloudflare-worker)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T08:02:49Z)
//! @yah:status(review)
//! @yah:parent(R419)
//! @yah:handoff("Landed CloudflareWorkerReconciler in crates/yah/cloud/src/reconciler/cloudflare_worker.rs and re-exported it through reconciler/mod.rs + cloud/src/lib.rs. up() validates the registry slot (must be `use = \"cloudflare\"` with non-empty `zone` + `domain`), reads workload.toml's `[build]` + `[[bindings]]`, matches each binding against a sibling mirror slot by `binding` field, runs build, reads the bundled entrypoint (default dist/index.js), idempotently lists+creates R2 buckets, deploys via deploy_worker_script with WorkerBinding::R2Bucket entries (R419-F1 surface), then attaches the custom domain via the new upsert_worker_custom_domain method on CloudflareClient. Returns RunningWorkload::adopted with public_url=https://<domain>. All config validation runs BEFORE any CF API call (R330-B5 fail-fast discipline).")
//! @yah:handoff("Added CloudflareClient::upsert_worker_custom_domain (cloudflare.rs) — separate from upsert_worker_route because Worker Routes are zone-scoped pattern matches and Custom Domains are account-scoped hostname attachments. List-first idempotency: skips PUT when the (hostname, service, zone_id) tuple is already bound.")
//! @yah:verify("cargo check -p cloud --lib — clean")
//! @yah:depends_on(R419-F1)
//!
//! @yah:ticket(R419-F3, "Register cloudflare-worker reconciler in CLI + desktop dispatch")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T08:02:58Z)
//! @yah:status(review)
//! @yah:parent(R419)
//! @yah:handoff("Added match arm `\"cloudflare-worker\" => CloudflareWorkerReconciler::new().up(ctx)` in both dispatchers: app/yah/cli/src/cloud.rs:reconcile_component and app/yah/desktop/src/mirror_run.rs's component.kind.as_str() match. Imported CloudflareWorkerReconciler at the top of each file. Updated the desktop file-level docstring to list the new kind. Pre-existing fallback arm still produces a clean error for unknown kinds.")
//! @yah:verify("cargo check -p cloud --lib — clean")
//! @yah:verify("cargo check -p yah --lib --bins — clean (warnings unchanged from baseline)")
//! @yah:verify("cargo check -p desktop --lib — clean (warnings unchanged from baseline)")
//! @yah:depends_on(R419-F2)
//!
//! @yah:ticket(R419-F4, "Regression tests: misconfig fail-fast for cloudflare-worker reconciler")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T08:03:09Z)
//! @yah:status(review)
//! @yah:parent(R419)
//! @yah:handoff("Three fail-fast tests in reconciler::cloudflare_worker::tests — Fixture builds an in-tempdir yah-cr-shaped workspace (writes workload.toml + .yah/infra/providers/cloudflare.toml). up_bails_on_registry_missing_domain (case 3) drops domain off the registry slot. up_bails_on_binding_name_drift (case 2) puts binding=\"STORAGE\" in the cache slot while workload.toml binds CACHE. up_bails_on_cache_slot_missing_bucket (case 1) keeps binding=\"CACHE\" but omits bucket. Each test asserts the error message names the offending field, the slot role, the service, and the env — no CF HTTP call is made because validation runs before any client construction.")
//! @yah:verify("cargo test -p cloud --lib reconciler::cloudflare_worker — 3 passed")
//! @yah:verify("cargo test -p cloud --lib — 246 passed (1 pre-existing failure cloud_init::tests::embedded_template_matches_workspace_canonical is unrelated R092-F2 template drift, not caused by R419)")
//! @yah:depends_on(R419-F2)
//!
//! @yah:relay(R458, "Cloud reconciler for .yah/domains/*.toml — R2 custom-domain shape")
//! @yah:at(2026-06-05T08:40:57Z)
//! @yah:status(open)
//! @yah:next("F1: implement ensure_r2_custom_domain (mirror of ensure_r2_bucket) + wire into yah cloud apply as a post-services pass. Scope: domains with cdn_bucket set and no [[routes]] (today: cdn-yah-dev.toml). Worker-routed shape (yah-dev, app-yah-dev) is a separate surface.")
//! @arch:see(.yah/domains/cdn-yah-dev.toml)
//!
//! @yah:ticket(R458-F1, "ensure_r2_custom_domain (CF API) + apply-time orchestration")
//! @yah:at(2026-06-05T08:41:07Z)
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:parent(R458)
//! @arch:see(.yah/domains/cdn-yah-dev.toml)
//! @yah:next("R458 can be archived once F1 is signed off, unless we want to keep it open for the routed-domain (Worker) reconciler shape — that's a much larger surface (DNS + Worker route management + bundle deploy) than this F1's bucket-binding.")
//! @yah:handoff("Live-verified end-to-end. cdn.yah.dev now resolves to CF anycast IPs (104.21.43.100, 172.67.178.4) and curl HTTP/2 200s against https://cdn.yah.dev/yah-desktop/whisper/distil-large-v3-q5_1.bin (content-length 584567555 = the q5_1 bytes R422-F11 published). Second apply is idempotent — the list-first path skips the POST when the binding is already present. Files touched: (1) crates/yah/cloud/src/provider/cloudflare.rs — new R2CustomDomain output type + CloudflareClient::list_r2_custom_domains and CloudflareClient::add_r2_custom_domain methods (GET / POST /accounts/{id}/r2/buckets/{bucket}/domains/custom). The POST body needs zone_id even though the endpoint is bucket-scoped (CF rejects with 'JSON not well formed' otherwise — caught live and added on the second iteration). Re-exported through provider/mod.rs + cloud/src/lib.rs. (2) crates/yah/cloud/src/reconciler/domain.rs — new module with ensure_r2_custom_domain(account_id, bucket, domain) mirroring static_asset::ensure_r2_bucket's list-first idempotency. Resolves the parent zone id via the existing CloudflareClient::zone_id_for_name and a parent_zone_name(domain) heuristic that takes the last two labels (correct for every yah-owned zone today; the doc comment names the longest-suffix-match upgrade path for future three-label-apex zones). 3 unit tests cover apex / subdomain / deeper-subdomain. (3) crates/yah/cloud/src/reconciler/mod.rs — declared `pub mod domain` + re-exported ensure_r2_custom_domain. (4) app/yah/cli/src/cloud.rs — new DomainOutcome enum + a post-services domain pass in handle_apply that walks cfg.domains, dispatches the R2-custom-domain shape (cdn_bucket set, no [[routes]]), and routes routed-shape domains (yah-dev, app-yah-dev) into a Skipped row labelled 'has [[routes]] — Worker-routed shape'. Gated on a cloudflare provider being declared (pond-only setups print 'skip domain pass: no cloudflare provider declared'). Originally also gated on empty --service filter; that gate dropped on review — domains are workspace-scoped and the operator wants them reconciled even when narrowing services. New print_domain_summary mirrors print_apply_summary's table + JSON output. Required CF token scopes (verified live): Workers R2 Storage: Edit + Zone: Read. The existing cloudflare-api-token slot carries both.\n\nLive verification command + transcript:\n\n  $ ./target/debug/yah cloud apply --env cloud --service yah-desktop\n  ==> yah-desktop/cloud: reconciling 2 component(s)\n      component desktop (kind=binary)\n      component whisper-models (kind=static-asset)\n  ==> domain cdn-yah-dev (cdn.yah.dev): ensuring R2 custom-domain binding on bucket yah-dev\n  apply summary (cloud):\n    yah-desktop  ok       2 component(s) reconciled\n  domain summary (cloud):\n    cdn-yah-dev  ok       R2 custom domain bound\n  $ dig +short cdn.yah.dev\n  104.21.43.100\n  172.67.178.4\n  $ curl -sI https://cdn.yah.dev/yah-desktop/whisper/distil-large-v3-q5_1.bin | head -4\n  HTTP/2 200\n  content-length: 584567555\n\nUnblocks R422-T13's client-side `cdn_fallback = \"https://cdn.yah.dev/yah-desktop/whisper/{blake3}\"` — the URL now actually resolves and serves the bytes.")
//! @yah:verify("cargo test -p cloud --lib reconciler::domain --locked  # 3 pass")
//! @yah:verify("cargo check --workspace --locked  # clean")
//! @yah:verify("./target/debug/yah cloud apply --env cloud --service yah-desktop  # domain summary shows cdn-yah-dev=ok, yah-dev/app-yah-dev=skipped (routed)")
//! @yah:verify("curl -sI https://cdn.yah.dev/yah-desktop/whisper/distil-large-v3-q5_1.bin  # HTTP/2 200, content-length 584567555")

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Mutex as AsyncMutex};

use workload_spec::{NamespaceId, TenantId};

use crate::{GitSource, MirrorConfig, MirrorProviderSlot, ServiceComponent, ServiceConfig};

pub mod bundle_store;
pub(crate) mod cf_creds;
pub mod cloudflare_worker;
pub mod container;
pub mod derive_cache_prune;
pub mod domain;
pub mod headscale;
pub mod ingress;
pub mod ingress_verify;
pub mod local_process;
pub mod mesofact_bundle;
pub mod mesofact_static;
mod native_support;
pub mod pg_driver;
pub mod pond;
pub mod pond_door;
pub mod pond_publish;
pub mod publish_beacon;
pub mod r2_publish;
pub mod service_discovery;
pub mod static_asset;
pub mod static_asset_prune;
pub mod sync_status;

#[cfg(test)]
mod lowering_golden;

pub use bundle_store::{publish_bundle_to_r2, PublishReport as BundlePublishReport};
pub use cloudflare_worker::CloudflareWorkerReconciler;
pub use container::{ContainerOptions, ContainerReconciler};
pub use derive_cache_prune::{
    collect_live_derive_hashes, compute_derive_cache_candidates, execute_derive_cache_prune,
    DeriveCacheLiveHashes, DerivePruneCandidate,
};
pub use domain::{
    deploy_domain_passway, diff_apex_records, ensure_passway_apex, ensure_r2_custom_domain,
    plan_domain_passway, public_origins, ApexRecordDiff, DomainPasswayPlan, LiveApexRecord,
    PasswayApexOutcome, PasswayOrigin,
};
pub use headscale::{
    DeclaredHeadscale, DeclaredPolicy, DeclaredPreauthKey, HeadscaleReconciler,
    WORKLOAD_KIND as HEADSCALE_WORKLOAD_KIND,
};
pub use ingress::{
    collate_front_doors, declared as ingress_declared, ensure_tunnel_ingress, machine_mesh_addrs,
    plan_ingress, publish_tunnel_ingress, resolve_ingress_placements, Collation, IngressPlan,
    IngressRule, NodeFrontDoor, PlannedEdge, TunnelIngressOutcome,
};
pub use ingress_verify::{
    apply_public_path, resolve_upstreams_reporting, verify_collation, BeaconFetch, DialOutcome,
    EndpointCheck, PublicReadings, RuleResolution, RuleResolutions, RuleVerdict, VerifyFinding,
    VerifyReport,
};
pub use local_process::LocalProcessReconciler;
pub use mesofact_bundle::{
    resolve_bundle_machines, BundleSlot, MesofactBundleReconciler, RevalidateSlot,
    SLOT_ROLE as BUNDLE_SLOT_ROLE,
};
pub use mesofact_static::{LocalStaticOptions, MesofactStaticReconciler};
pub use pond::{PondOptions, PondState};
pub use pond_door::{
    door_env, door_state_dir, ensure_pond_cert, ensure_pond_cert_as, is_root, plan_pond_door,
    pond_hostname, resolve_passway_binary, spawn_pond_door, CertPair, PondDoorPlan,
    DEFAULT_DOOR_PORT, POND_TLD,
};
pub use pond_publish::{derive_minio_key, publish_to_pond, PondPublishReport};
pub use r2_publish::{
    publish_to_r2, R2PublishReport, R2PurgeOpts, R2_ACCESS_KEY_ENV, R2_ACCESS_KEY_SLOT,
    R2_SECRET_KEY_ENV, R2_SECRET_KEY_SLOT,
};
pub use service_discovery::{
    DiscoveredRecord, RecordVisibility, ServiceRecordFanout, UnknownReason,
};
pub use static_asset::StaticAssetReconciler;
pub use static_asset_prune::{
    compute_live_set, compute_prune_candidates, execute_prune, load_service_and_mirror,
    PruneCandidate, PruneOutcome, PruneReport,
};
pub use sync_status::{
    compute_cell, compute_service, new_sync_id, summarize, CellStatus, DriftEntry, HealthState,
    MirrorObservation, Runtime, ServiceStatus, StatusSummary, SyncHistoryEntry, SyncOutcome,
    SyncState, WireContainerStatus,
};

// ─── Log buffer ─────────────────────────────────────────────────────────────

const LOG_CAP: usize = 500;

#[derive(Debug, Default)]
struct LogRing {
    lines: VecDeque<String>,
    /// Monotonically increasing total lines ever pushed (never decrements).
    total: usize,
}

/// Bounded ring buffer for child-process stdout/stderr (R263-F3).
/// Shared between the reader tasks and the Tauri `mirror_run_logs` command.
#[derive(Debug, Clone, Default)]
pub struct LogBuffer(Arc<AsyncMutex<LogRing>>);

impl LogBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a line; drops the oldest entry when over capacity.
    pub async fn push(&self, line: String) {
        let mut ring = self.0.lock().await;
        ring.total += 1;
        ring.lines.push_back(line);
        if ring.lines.len() > LOG_CAP {
            ring.lines.pop_front();
        }
    }

    /// Return lines not yet seen by the caller.
    ///
    /// `since` is the `total` cursor from the previous call (0 = nothing
    /// seen yet). Returns `(new_lines, new_cursor)`. Pass `new_cursor` back
    /// on the next call to receive only incremental output.
    pub async fn since(&self, since: usize) -> (Vec<String>, usize) {
        let ring = self.0.lock().await;
        let oldest = ring.total.saturating_sub(ring.lines.len());
        let skip = since.saturating_sub(oldest);
        let new_lines: Vec<String> = ring.lines.iter().skip(skip).cloned().collect();
        (new_lines, ring.total)
    }

    /// Current write cursor — the `total` [`Self::since`] would hand back
    /// right now if nothing more were pushed. Lets a producer mark a boundary
    /// (e.g. "everything before this point was the build phase") for a later
    /// reader to seek past without re-reading lines it doesn't want.
    pub async fn cursor(&self) -> usize {
        self.0.lock().await.total
    }
}

/// Shared cell for one phase-boundary cursor a reconciler can publish
/// mid-`up()`, so a poller sees a multi-phase bring-up's internal transition
/// (e.g. build → run) before the whole call returns — the same problem
/// [`LogBuffer`] solves for output, for a single position instead of a ring.
/// `None` until the reconciler reaches that phase; a caller registers one
/// before calling `up()` to observe it live, same pattern as
/// [`LogBuffer::clone`]-and-hand-in.
#[derive(Debug, Clone, Default)]
pub struct PhaseCursor(Arc<AsyncMutex<Option<usize>>>);

impl PhaseCursor {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set(&self, cursor: usize) {
        *self.0.lock().await = Some(cursor);
    }

    pub async fn get(&self) -> Option<usize> {
        *self.0.lock().await
    }
}

/// The `(tenant, namespace)` a bring-up is scoped to (W206). Reconcilers that
/// touch a credentialed provider resolve it at this scope
/// ([`CfProvider::resolve_scoped`](super::reconciler::cf_creds)) so a namespace's
/// Cloudflare zone/account/keystore slots come from its own scope rather than the
/// workspace-global defaults. Defaults to the singleton `(default, default)`,
/// which collapses every scoped lookup back to the historical global slots — so
/// single-namespace deployments are unaffected.
#[derive(Debug, Clone)]
pub struct ProviderScope {
    pub tenant: TenantId,
    pub namespace: NamespaceId,
}

impl ProviderScope {
    /// The degenerate single-tenant / single-namespace scope. Scoped provider
    /// lookups made against it resolve to the pre-W206 global keystore slots.
    pub fn singleton() -> Self {
        Self {
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
        }
    }
}

impl Default for ProviderScope {
    fn default() -> Self {
        Self::singleton()
    }
}

/// Inputs a reconciler sees for one bring-up.
pub struct ReconcileCtx<'a> {
    /// Workspace root (parent of `.yah/`). Used to resolve relative paths
    /// on the component.
    pub workspace_root: &'a Path,
    /// Service that owns the component.
    pub service: &'a ServiceConfig,
    /// Component being brought up.
    pub component: &'a ServiceComponent,
    /// Mirror manifest the bring-up targets.
    pub mirror: &'a MirrorConfig,
    /// Environment name (file stem of `mirrors/<env>.toml`).
    pub env: &'a str,
    /// `(tenant, namespace)` this bring-up is scoped to (W206). Credentialed
    /// providers resolve at this scope; defaults to [`ProviderScope::singleton`].
    pub scope: ProviderScope,
}

impl<'a> ReconcileCtx<'a> {
    /// Absolute path to the component's workload directory (the parent of
    /// `workload.toml`).
    ///
    /// In-tree components resolve to `<workspace_root>/<path>`. For
    /// `git`-sourced components (R561-F1, "BYO git") this points into the
    /// local clone — `<source_cache>/<subdir>/<path>` — which is empty until
    /// [`materialize`](Self::materialize) runs (approach A: clone-at-reconcile,
    /// so config load + validation stay offline).
    pub fn workload_dir(&self) -> PathBuf {
        match &self.component.git {
            None => self.workspace_root.join(&self.component.path),
            Some(git) => {
                let mut dir = self.source_cache_dir();
                if let Some(subdir) = &git.subdir {
                    dir = dir.join(subdir);
                }
                dir.join(&self.component.path)
            }
        }
    }

    /// Root of the local clone for a `git`-sourced component:
    /// `<workspace_root>/.yah/infra/state/sources/<service>/<component_id>`.
    fn source_cache_dir(&self) -> PathBuf {
        self.workspace_root
            .join(".yah/infra/state/sources")
            .join(&self.service.name)
            .join(&self.component.id)
    }

    /// Ensure a `git`-sourced component's code is present locally before build
    /// (R561-F1, approach A). No-op for in-tree components. Idempotent: clones
    /// on the first call, fetches + re-checks-out the pinned ref thereafter.
    ///
    /// Reconcilers MUST call this at the top of [`up`](Reconciler::up) before
    /// reading [`workload_dir`](Self::workload_dir) for a remote component.
    pub async fn materialize(&self) -> Result<()> {
        let Some(git) = &self.component.git else {
            return Ok(());
        };
        materialize_git_source(git, &self.source_cache_dir())
            .await
            .with_context(|| {
                format!(
                    "materializing git source {}@{} for {}/{}",
                    git.repo, git.r#ref, self.service.name, self.component.id
                )
            })
    }

    /// Read `<workload_dir>/workload.toml` and extract just the `kind`
    /// discriminator.
    ///
    /// Why this and not the strongly-typed [`workload_spec::Workload`]
    /// parse: the on-disk `schema_version = 1` form predates the
    /// `SchemaVersion::V1` enum and won't round-trip through the strong
    /// types until B3 lands (see `crates/yah/cloud/src/config.rs` test
    /// `web_workload_round_trips`). Reconcilers only need the kind to
    /// dispatch; per-kind tooling (e.g. `mesofact-dev`'s
    /// `WatchOptions::from_workload`) does its own parsing for the
    /// build/out_dir fields it cares about.
    pub fn workload_kind(&self) -> Result<String> {
        workload_kind(&self.workload_dir())
    }

    /// Look up a provider slot by role (e.g. `"static"`, `"compute"`).
    ///
    /// Tries the component-qualified key first (`"<role>:<component id>"`)
    /// before falling back to the bare role. A mirror role is normally
    /// service-wide — one `providers.static` slot serves every static-kind
    /// component — but a service can declare more than one component with
    /// the same role (e.g. two `mesofact-static`/`mesofact-spa` components
    /// sharing one mirror), and those need distinct ports to ever both come
    /// up. The qualified key is how a mirror opts a specific component out
    /// of sharing the bare-role slot:
    ///
    /// ```toml
    /// [providers."static:site"]
    /// kind = "local-static"
    /// port = 4331
    ///
    /// [providers."static:app"]
    /// kind = "local-static"
    /// port = 4332
    /// ```
    ///
    /// A mirror with only the bare role (the common, single-component case)
    /// is unaffected — the qualified lookup misses and falls through.
    pub fn slot(&self, role: &str) -> Option<&'a MirrorProviderSlot> {
        let qualified = format!("{role}:{}", self.component.id);
        self.mirror
            .providers
            .get(qualified.as_str())
            .or_else(|| self.mirror.providers.get(role))
    }
}

/// An explicit teardown hook for a workload this process did not spawn as a
/// child — see [`RunningWorkload::with_teardown`] (R714-B1).
///
/// Boxed rather than a generic parameter because [`RunningWorkload`] is stored
/// in heterogeneous collections (the desktop's mirror registry) and cannot
/// carry a type parameter.
/// `Sync` on the boxed closure is load-bearing, not belt-and-braces: without
/// it `RunningWorkload` stops being `Sync`, so `&RunningWorkload` stops being
/// `Send`, and every desktop `#[tauri::command]` that holds one across an
/// `.await` (`mirror_run_logs` iterates the registry's handles) fails to
/// compile with "future cannot be sent between threads safely". The captures a
/// teardown needs — a container name and a workspace root — are `Sync` anyway.
type TeardownFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;
type TeardownFn = Box<dyn FnOnce() -> TeardownFuture + Send + Sync + 'static>;

/// Newtype so [`RunningWorkload`] can keep its `#[derive(Debug)]` — a boxed
/// closure is not `Debug`.
struct Teardown(TeardownFn);

impl std::fmt::Debug for Teardown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Teardown(<fn>)")
    }
}

/// Handle to a workload that's been brought up. Owns the lifecycle: drop
/// or call [`RunningWorkload::shutdown`] to take it back down.
#[derive(Debug)]
pub struct RunningWorkload {
    /// Workload kind that was reconciled (e.g. `"mesofact-static"`).
    pub kind: String,
    /// Slot role this workload occupies on the mirror (e.g. `"static"`).
    pub slot: String,
    /// Local URL the workload exposes, when applicable. `None` for
    /// workloads that publish to a non-local artifact store (e.g. R2).
    pub dev_url: Option<String>,
    /// Notional URL of the deployed artifact in the production case
    /// (e.g. `https://yah.dev`). `None` until Cloudflare/R2 wiring lands.
    pub public_url: Option<String>,
    /// Secondary local UI console, if the workload exposes one (e.g. MinIO
    /// console on a pond tier). Surfaced as a separate chip in the Services
    /// matrix next to `dev_url`.
    pub console_url: Option<String>,
    /// Ring buffer for stdout/stderr from the workload's child process.
    /// `None` for workloads that don't capture stdio (e.g. container-backed).
    pub log_buffer: Option<LogBuffer>,

    /// R546-B12: human-readable lines the reconciler wants the operator to see
    /// on THIS run — what it actually did, not what is configured. A clean
    /// static-asset reconcile used to print nothing at all, so a successful
    /// publish and a successful no-op were indistinguishable at the apply
    /// surface, and the one view that would have disambiguated them (`yah cloud
    /// status`) was itself blind.
    ///
    /// Deliberately NOT on [`RunningWorkloadSummary`]: that type is serialized
    /// across the process boundary to the desktop UI, and this is per-run
    /// console output, not state the UI should cache.
    pub notes: Vec<String>,

    /// Sender that signals the supervisor task to tear down. Closing the
    /// channel (drop) is equivalent to sending — supervisor exits on
    /// channel close.
    shutdown: Option<oneshot::Sender<()>>,
    /// Joinable task that owns any child process and reaps it on signal.
    supervisor: Option<tokio::task::JoinHandle<Result<()>>>,
    /// R714-B1: teardown for a workload that runs OUTSIDE this process, so
    /// there is no child to reap and no supervisor to signal.
    ///
    /// Deliberately run from [`RunningWorkload::shutdown`] only, never from
    /// `Drop`. The two are different intents and conflating them breaks both
    /// directions: a container the desktop started is meant to outlive the
    /// desktop (the next launch re-adopts it with `adopt_only`), so quitting
    /// the app must not `docker rm -f` it; but the ■ button IS an explicit
    /// stop, and must.
    teardown: Option<Teardown>,

    /// R715-F4: where to ask this workload for a live status document, when
    /// it declared a process-control channel (W315). `None` for a workload
    /// with no channel — polling is then simply skipped, not an error.
    ///
    /// The desktop holds `RunningWorkload` in-process (it links this crate
    /// directly, unlike the ad-hoc `run.spawn` path which lives behind the
    /// camp daemon's socket), so a live poll is [`crate::proc_control::fetch_status`]
    /// called straight against this endpoint — no RPC hop, no handle registry.
    control: Option<crate::proc_control::ControlEndpoint>,

    /// [`LogBuffer`] cursor marking the end of the build phase, for a
    /// component that was compiled before being spawned (`local-process`
    /// with `cargo_package` set). Lines before this index in `log_buffer` are
    /// `cargo build` output; lines at or after are the spawned process's own
    /// stdout/stderr. `None` when nothing was built (no `cargo_package`, or a
    /// reconciler that predates this field).
    pub build_log_end: Option<usize>,
}

impl RunningWorkload {
    /// Create a handle for a workload that's already running externally
    /// (e.g. embedded in yah-camp). No subprocess is owned; shutdown is a
    /// no-op so the caller can call `shutdown()` uniformly.
    pub fn adopted(
        kind: impl Into<String>,
        slot: impl Into<String>,
        dev_url: Option<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            slot: slot.into(),
            dev_url,
            public_url: None,
            console_url: None,
            log_buffer: None,
            notes: Vec::new(),
            shutdown: None,
            supervisor: None,
            teardown: None,
            control: None,
            build_log_end: None,
        }
    }

    /// Attach an explicit teardown to a handle for an externally-running
    /// workload (R714-B1).
    ///
    /// `adopted()` alone gives a handle whose `shutdown()` is a documented
    /// no-op. That is right for workloads another process owns and will keep
    /// re-asserting (pond containers under camp's yubaba), and wrong for ones
    /// this process started and nobody else will ever stop — for those the ■
    /// button reported success while the container kept running.
    ///
    /// `teardown` runs on `shutdown()` and NOT on `Drop`; see [`Self::teardown`].
    pub fn with_teardown<F, Fut>(mut self, teardown: F) -> Self
    where
        F: FnOnce() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        self.teardown = Some(Teardown(Box::new(move || Box::pin(teardown()))));
        self
    }

    /// Attach per-run operator-facing lines (R546-B12). See [`Self::notes`].
    pub fn with_notes(mut self, notes: Vec<String>) -> Self {
        self.notes = notes;
        self
    }

    /// Record where to poll this workload's process-control channel, when it
    /// declared one (R715-F4). A no-op (leaves `control: None`) when the
    /// argument is `None` — callers can pass the reconciler's resolved
    /// endpoint straight through without an `if let`.
    pub fn with_control(mut self, control: Option<crate::proc_control::ControlEndpoint>) -> Self {
        self.control = control;
        self
    }

    /// Ask this workload's process-control channel for a live status
    /// document (R715-F4). `None` when no channel was declared, or when the
    /// endpoint didn't answer — both are "nothing new to show", not errors;
    /// see [`crate::proc_control::fetch_status`] for why a poll failure isn't
    /// itself meaningful.
    pub async fn poll_control(&self) -> Option<crate::proc_control::ProcStatus> {
        let endpoint = self.control.as_ref()?;
        crate::proc_control::fetch_status(endpoint).await.ok()
    }

    /// Whether the supervisor task that owns this workload's child process is
    /// still running. `spawn_native_log_supervisor` (native_support.rs) exits
    /// as soon as `NativeRuntime::get_workload` reports a terminal state —
    /// which itself comes from a real `child.wait()` in kamaji's native
    /// backend, so this catches a crash (segfault, panic, `SIGKILL`) the same
    /// way it catches a clean exit, not just an unresponsive process.
    ///
    /// A workload with no supervisor (`RunningWorkload::adopted` — runs
    /// outside this process, e.g. a pond container camp re-asserts) has
    /// nothing to check here and reports alive unconditionally; its liveness
    /// is whatever tracks it, not this handle.
    pub fn is_alive(&self) -> bool {
        self.supervisor.as_ref().is_none_or(|h| !h.is_finished())
    }

    /// Record where the build phase ends in `log_buffer`, for a component
    /// that was compiled before being spawned. See [`Self::build_log_end`].
    pub fn with_build_log_end(mut self, cursor: Option<usize>) -> Self {
        self.build_log_end = cursor;
        self
    }

    /// Set the public URL for a published workload (e.g. `"https://yah.dev"`).
    pub fn with_public_url(mut self, url: impl Into<String>) -> Self {
        self.public_url = Some(url.into());
        self
    }

    /// Set the console URL for a workload that exposes a secondary local UI
    /// (e.g. MinIO console on a pond tier).
    pub fn with_console_url(mut self, url: impl Into<String>) -> Self {
        self.console_url = Some(url.into());
        self
    }

    /// Gracefully tear down: signal the supervisor, await its exit, then run
    /// any explicit teardown hook.
    ///
    /// The hook runs LAST and its error propagates. A stop that could not tear
    /// the workload down must surface as an error, never as a silent success —
    /// that silence is the whole of R714-B1.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.supervisor.take() {
            handle
                .await
                .context("joining workload supervisor")?
                .context("workload supervisor")?;
        }
        if let Some(Teardown(hook)) = self.teardown.take() {
            hook().await.context("workload teardown")?;
        }
        Ok(())
    }
}

impl Drop for RunningWorkload {
    fn drop(&mut self) {
        // Best-effort signal. The supervisor task is detached and will
        // reap its child when it observes the closed channel.
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Bring one workload up. Each impl handles one [`ServiceComponent::kind`].
#[async_trait]
pub trait Reconciler: Send + Sync {
    /// Workload kind this reconciler handles (matches `ServiceComponent.kind`).
    fn kind(&self) -> &'static str;

    /// Bring the workload up. Returns a handle whose lifecycle is tied to
    /// the mirror being up.
    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload>;
}

/// Read `<workload_dir>/workload.toml` and return just the `kind` field.
/// See [`ReconcileCtx::workload_kind`] for why we don't deserialize through
/// the strong types yet.
pub fn workload_kind(workload_dir: &Path) -> Result<String> {
    let path = workload_dir.join("workload.toml");
    let src =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let value: toml::Value =
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
    let kind = value
        .get("kind")
        .and_then(|v| v.as_str())
        .with_context(|| format!("{}: missing `kind` field", path.display()))?;
    Ok(kind.to_string())
}

/// Shallow-clone (or update) a [`GitSource`] into `dir` (R561-F1). Idempotent:
/// clones when `dir/.git` is absent, otherwise fetches the pinned ref and
/// force-checks-it-out. Uses the system `git` so it inherits the operator's
/// credential helpers / SSH agent — no in-process git library.
///
/// `pub` (R615-T3 / W274): `yah infra sync` reuses this verbatim for
/// `InfraSourceKind::Git` sources rather than a second shallow-clone-or-pull
/// implementation — same "one git-source shape, reused" discipline R615-F1
/// already applied to the type.
pub async fn materialize_git_source(git: &GitSource, dir: &Path) -> Result<()> {
    use tokio::process::Command;

    async fn run_git(args: &[&std::ffi::OsStr]) -> Result<()> {
        let out = Command::new("git")
            .args(args)
            .output()
            .await
            .context("spawning git")?;
        if !out.status.success() {
            anyhow::bail!(
                "git {} failed: {}",
                args.iter()
                    .map(|a| a.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    use std::ffi::OsStr;
    let dir_os = dir.as_os_str();
    let r#ref = git.r#ref.as_str();

    if dir.join(".git").is_dir() {
        // Existing checkout — update to the pinned ref.
        run_git(&[
            OsStr::new("-C"),
            dir_os,
            OsStr::new("fetch"),
            OsStr::new("--depth"),
            OsStr::new("1"),
            OsStr::new("origin"),
            OsStr::new(r#ref),
        ])
        .await?;
        run_git(&[
            OsStr::new("-C"),
            dir_os,
            OsStr::new("checkout"),
            OsStr::new("--force"),
            OsStr::new("FETCH_HEAD"),
        ])
        .await?;
    } else {
        if let Some(parent) = dir.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        // `--branch` accepts a branch or tag. Pinning to a bare commit SHA is a
        // follow-up (needs clone-then-fetch); the common case is a branch/tag.
        run_git(&[
            OsStr::new("clone"),
            OsStr::new("--depth"),
            OsStr::new("1"),
            OsStr::new("--branch"),
            OsStr::new(r#ref),
            OsStr::new(git.repo.as_str()),
            dir_os,
        ])
        .await?;
    }
    Ok(())
}

/// Build a `RunningWorkload` from the pieces a reconciler produces.
pub(crate) fn into_running(
    kind: impl Into<String>,
    slot: impl Into<String>,
    dev_url: Option<String>,
    public_url: Option<String>,
    log_buffer: Option<LogBuffer>,
    shutdown: oneshot::Sender<()>,
    supervisor: tokio::task::JoinHandle<Result<()>>,
) -> RunningWorkload {
    RunningWorkload {
        kind: kind.into(),
        slot: slot.into(),
        dev_url,
        public_url,
        console_url: None,
        log_buffer,
        notes: Vec::new(),
        shutdown: Some(shutdown),
        supervisor: Some(supervisor),
        teardown: None,
        control: None,
        build_log_end: None,
    }
}

/// Wait for a TCP port to start accepting connections. Returns `true` if
/// the port came up within `timeout`, `false` otherwise. Useful for
/// reconcilers that spawn a server and need to know when it's reachable
/// before reporting success.
pub(crate) async fn wait_for_port(
    addr: std::net::SocketAddr,
    timeout: std::time::Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

// `wait_for_http_ready` lived here pre-R374-F3 to back the MinIO health
// probe in pond's bring-up path. That logic moved to
// `local_driver::pond_minio::wait_for_http_ready` so yubaba + cloud share
// it. The mesofact-static reconciler arm uses [`wait_for_port`] for
// dev-tier port readiness; nothing else needs an HTTP-level probe today.

/// Pluck a `u16` out of a [`MirrorProviderSlot`]'s inline `fields` map.
/// Returns `None` if the key is absent or out of range.
pub(crate) fn slot_field_u16(fields: &BTreeMap<String, toml::Value>, key: &str) -> Option<u16> {
    fields
        .get(key)
        .and_then(|v| v.as_integer())
        .and_then(|n| u16::try_from(n).ok())
}

/// Serializable summary of a running workload — what the desktop / CLI
/// hands to the UI. Subset of [`RunningWorkload`] that's safe to cross
/// process boundaries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunningWorkloadSummary {
    pub kind: String,
    pub slot: String,
    pub dev_url: Option<String>,
    pub public_url: Option<String>,
    pub console_url: Option<String>,
    /// Operator-facing lines from [`RunningWorkload::notes`] (R546-B12).
    ///
    /// These used to stop here — the summary dropped them, so every note a
    /// reconciler attached was written into a struct nobody read. They matter
    /// most for a workload with no `dev_url` to click (R715-T2): the notes are
    /// then the only structured thing the Run tab has to show about it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// See [`RunningWorkload::build_log_end`]. Lets a log-tail consumer skip
    /// straight to run-phase output, or show everything from 0 when the
    /// operator wants the build log too (e.g. after a compile failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_log_end: Option<usize>,
}

impl From<&RunningWorkload> for RunningWorkloadSummary {
    fn from(r: &RunningWorkload) -> Self {
        Self {
            kind: r.kind.clone(),
            slot: r.slot.clone(),
            dev_url: r.dev_url.clone(),
            public_url: r.public_url.clone(),
            console_url: r.console_url.clone(),
            notes: r.notes.clone(),
            build_log_end: r.build_log_end,
        }
    }
}

#[cfg(test)]
mod source_seam_tests {
    //! R561-F1 — the BYO-git source seam: path resolution + materialization.
    use super::*;
    use std::collections::BTreeMap;

    fn component(git: Option<GitSource>) -> ServiceComponent {
        ServiceComponent {
            mount: None,
            id: "site".into(),
            kind: "mesofact-static".into(),
            path: "site".into(),
            role: "static".into(),
            publishes: None,
            wave: 0,
            git,
        }
    }

    fn service(comp: ServiceComponent) -> ServiceConfig {
        ServiceConfig {
            schema_version: 1,
            name: "scrabcake".into(),
            domain: "scrabcake.example".into(),
            components: vec![comp],
            db: crate::DbCatalog::default(),
        }
    }

    fn mirror() -> MirrorConfig {
        MirrorConfig {
            schema_version: 1,
            shape: crate::MirrorShape::Local,
            providers: BTreeMap::new(),
            ingress: Default::default(),
            ingress_machines: Vec::new(),
            drivers: Default::default(),
            asset_aliases: BTreeMap::new(),
        }
    }

    fn ctx<'a>(ws: &'a Path, svc: &'a ServiceConfig, mir: &'a MirrorConfig) -> ReconcileCtx<'a> {
        ReconcileCtx {
            workspace_root: ws,
            service: svc,
            component: &svc.components[0],
            mirror: mir,
            env: "dev",
            scope: ProviderScope::singleton(),
        }
    }

    #[test]
    fn workload_dir_in_tree_joins_workspace_root() {
        let svc = service(component(None));
        let mir = mirror();
        assert_eq!(
            ctx(Path::new("/ws"), &svc, &mir).workload_dir(),
            Path::new("/ws/site")
        );
    }

    #[test]
    fn workload_dir_git_resolves_into_source_cache_with_subdir() {
        let git = GitSource {
            repo: "https://example.com/r.git".into(),
            r#ref: "main".into(),
            subdir: Some("apps".into()),
        };
        let svc = service(component(Some(git)));
        let mir = mirror();
        assert_eq!(
            ctx(Path::new("/ws"), &svc, &mir).workload_dir(),
            Path::new("/ws/.yah/infra/state/sources/scrabcake/site/apps/site")
        );
    }

    #[tokio::test]
    async fn materialize_is_noop_for_in_tree_component() {
        let svc = service(component(None));
        let mir = mirror();
        // No git source → Ok, and nothing is written under the workspace.
        ctx(Path::new("/nonexistent-ws"), &svc, &mir)
            .materialize()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn materialize_clones_git_source_offline() {
        fn git(args: &[&str], cwd: &Path) {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src-repo");
        std::fs::create_dir_all(&src).unwrap();
        git(&["init", "-b", "main"], &src);
        std::fs::write(src.join("hello.txt"), "hi").unwrap();
        git(&["add", "."], &src);
        git(&["commit", "-m", "init"], &src);

        let source = GitSource {
            repo: format!("file://{}", src.display()),
            r#ref: "main".into(),
            subdir: None,
        };
        let dest = tmp.path().join("cache");

        // First call clones.
        materialize_git_source(&source, &dest).await.unwrap();
        assert!(dest.join("hello.txt").is_file());

        // Second call takes the update path and stays green (idempotent).
        materialize_git_source(&source, &dest).await.unwrap();
        assert!(dest.join("hello.txt").is_file());
    }
}

#[cfg(test)]
mod teardown_tests {
    //! R714-B1 — the explicit-teardown contract on [`RunningWorkload`].
    //!
    //! These are about WHEN the hook runs, not what it does. The bug being
    //! fixed was a `shutdown()` that reported success having done nothing, and
    //! the trap in fixing it is a `Drop` that tears down a container which is
    //! supposed to survive the process.
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counting() -> (RunningWorkload, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = hits.clone();
        let w = RunningWorkload::adopted("container", "compute", None)
            .with_teardown(move || {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            });
        (w, hits)
    }

    /// Attaching a teardown must not cost `RunningWorkload` its auto traits.
    /// The desktop stores these handles in a shared registry and its Tauri
    /// commands iterate them across `.await` points, which needs `Sync` — a
    /// hook that is `Send` but not `Sync` takes it away here and surfaces two
    /// crates over as "future cannot be sent between threads safely", with a
    /// span pointing at `mirror_run_logs` rather than at this file.
    #[test]
    fn a_teardown_does_not_cost_the_handle_send_or_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RunningWorkload>();
    }

    #[tokio::test]
    async fn shutdown_runs_the_teardown() {
        let (w, hits) = counting();
        w.shutdown().await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropping_the_handle_does_NOT_run_the_teardown() {
        // A container this process started is meant to outlive it — the next
        // launch re-adopts it. Quitting the app must not `docker rm -f` it.
        let (w, hits) = counting();
        drop(w);
        // Yield so a stray spawned task would have had a chance to run.
        tokio::task::yield_now().await;
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_failing_teardown_makes_shutdown_fail() {
        // The whole of R714-B1: a stop that could not tear the workload down
        // must not report success.
        let w = RunningWorkload::adopted("container", "compute", None)
            .with_teardown(|| async { anyhow::bail!("docker stop refused") });
        let err = w.shutdown().await.unwrap_err();
        assert!(format!("{err:#}").contains("docker stop refused"), "{err:#}");
    }

    #[tokio::test]
    async fn an_adopted_handle_without_a_teardown_still_shuts_down_cleanly() {
        // Pond containers are owned by camp's yubaba and stop through
        // `workload.stop`; their no-op shutdown is correct and must stay.
        let w = RunningWorkload::adopted("mesofact-static", "static", None);
        w.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_teardown_runs_after_the_supervisor_is_joined() {
        // Ordering matters for a workload that has both: reap the child first,
        // then remove the container it was talking to.
        let order = Arc::new(AsyncMutex::new(Vec::<&'static str>::new()));
        let (tx, rx) = oneshot::channel::<()>();
        let sup_order = order.clone();
        let supervisor = tokio::spawn(async move {
            let _ = rx.await;
            sup_order.lock().await.push("supervisor");
            Ok(())
        });
        let hook_order = order.clone();
        let w = into_running("container", "compute", None, None, None, tx, supervisor)
            .with_teardown(move || {
                let hook_order = hook_order.clone();
                async move {
                    hook_order.lock().await.push("teardown");
                    Ok(())
                }
            });

        w.shutdown().await.unwrap();
        assert_eq!(*order.lock().await, vec!["supervisor", "teardown"]);
    }
}
