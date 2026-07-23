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

pub(crate) mod cf_creds;
pub mod bundle_store;
pub mod cloudflare_worker;
pub mod container;
pub mod derive_cache_prune;
pub mod domain;
pub mod mesofact_bundle;
pub mod mesofact_runner;
pub mod mesofact_static;
pub mod pond;
pub mod pond_publish;
pub mod r2_publish;
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
pub use domain::ensure_r2_custom_domain;
pub use mesofact_bundle::{
    resolve_bundle_machines, BundleSlot, MesofactBundleReconciler,
    SLOT_ROLE as BUNDLE_SLOT_ROLE,
};
pub use mesofact_runner::{resolve_runner_machine, MesofactRunnerReconciler};
pub use mesofact_static::{LocalStaticOptions, MesofactStaticReconciler};
pub use pond::{PondOptions, PondState};
pub use pond_publish::{derive_minio_key, publish_to_pond, PondPublishReport};
pub use r2_publish::{
    publish_to_r2, R2PublishReport, R2PurgeOpts, R2_ACCESS_KEY_ENV, R2_ACCESS_KEY_SLOT,
    R2_SECRET_KEY_ENV, R2_SECRET_KEY_SLOT,
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
    pub fn slot(&self, role: &str) -> Option<&'a MirrorProviderSlot> {
        self.mirror.providers.get(role)
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

    /// Sender that signals the supervisor task to tear down. Closing the
    /// channel (drop) is equivalent to sending — supervisor exits on
    /// channel close.
    shutdown: Option<oneshot::Sender<()>>,
    /// Joinable task that owns any child process and reaps it on signal.
    supervisor: Option<tokio::task::JoinHandle<Result<()>>>,
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
            shutdown: None,
            supervisor: None,
        }
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

    /// Gracefully tear down: signal the supervisor, await its exit.
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
async fn materialize_git_source(git: &GitSource, dir: &Path) -> Result<()> {
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
        shutdown: Some(shutdown),
        supervisor: Some(supervisor),
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
}

impl From<&RunningWorkload> for RunningWorkloadSummary {
    fn from(r: &RunningWorkload) -> Self {
        Self {
            kind: r.kind.clone(),
            slot: r.slot.clone(),
            dev_url: r.dev_url.clone(),
            public_url: r.public_url.clone(),
            console_url: r.console_url.clone(),
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
