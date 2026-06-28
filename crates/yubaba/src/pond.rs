//! Pond workload status surface — R374-F2 + F3 + F4.
//!
//! Camp embeds [`crate::serve_on_listener`] as a tokio task and POSTs
//! `/pond/deploy` for each declared pond mirror at startup. Yubaba owns the
//! full bring-up sequence: MinIO container (via `local_driver::pond_minio`) then
//! miniflare process (via `local_driver::pond_miniflare`). Desktop reads the
//! registry via `GET /pond/state?ident=...` to drive its adopt path.
//!
//! Lifecycle layering after R374-F4:
//!
//! ```text
//!   POST /pond/deploy
//!   └─ yubaba::pond::minio::ensure_minio_running    (image-pull / run / probe / bucket-policy)
//!      └─ local_driver::pond_miniflare::spawn_miniflare   (write scripts, spawn bun/node, wait for ready)
//!         └─ registry.insert_full + spawn MinioReconciler + spawn MiniflareReconciler
//! ```
//!
//! F4 removes the `PondHandler` callback. Camp no longer registers a closure
//! to drive the miniflare half — yubaba spawns it directly from the
//! `MiniflareSpec` carried in `PondDeployReq`.
//!
//! @yah:relay(R455, "Phase D — mesofact-dev backend container + bridge network + Worker bindings")
//! @yah:at(2026-06-05T08:23:34Z)
//! @yah:status(open)
//! @yah:phase(D)
//! @yah:parent(Q453)
//! @yah:next("Add a third supervised slot to pond: almanac + issue-tracker side-by-side under tini, on a per-cell docker bridge so the Worker can DNS-resolve the backend")
//! @arch:see(.yah/docs/working/W180-pond-richer-topology.md)
//! @arch:see(.yah/docs/working/W142-pond.md)
//!
//! @yah:relay(R456, "Phase E — Per-slot probes in PondStateRecord")
//! @yah:at(2026-06-05T08:23:37Z)
//! @yah:status(open)
//! @yah:phase(E)
//! @yah:parent(Q453)
//! @yah:next("Extend PondStateRecord with per-slot liveness/readiness probes; top-level phase becomes a roll-up; surface granularity through the observation seam to the UI")
//! @arch:see(.yah/docs/working/W180-pond-richer-topology.md)
//!
//! @yah:ticket(R455-F3, "pond_mesofact_dev local-driver module + PondDeployReq field + yubaba MesofactDevReconciler with HTTP probes")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-05T08:24:39Z)
//! @yah:status(review)
//! @yah:phase(D)
//! @yah:parent(R455)
//! @yah:next("New crates/yah/local-driver/src/pond_mesofact_dev.rs: MesofactDevSpec + ensure_mesofact_dev_running (mirror pond_minio.rs)")
//! @yah:next("PondDeployReq grows optional mesofact_dev: Option<MesofactDevSpec>; existing mirrors keep working")
//! @yah:next("Yubaba gets MesofactDevReconciler paralleling MinioReconciler/MiniflareReconciler: 5s loop, HTTP GET on liveness_path → restart; HTTP GET on readiness_path → mark not-ready (no restart)")
//! @yah:verify("cargo test -p yubaba --lib pond")
//! @yah:verify("Smoke: external HTTP kill of mesofact-dev → yubaba Degraded within probe interval → restart → Running")
//! @arch:see(.yah/docs/working/W180-pond-richer-topology.md)
//! @yah:depends_on(R455-F1)
//! @yah:depends_on(R455-F2)
//!
//! @yah:ticket(R456-F1, "PondStateRecord.slots: Vec<SlotProbe>; phase becomes a roll-up over slots")
//! @yah:at(2026-06-05T08:24:56Z)
//! @yah:status(review)
//! @yah:phase(E)
//! @yah:parent(R456)
//! @yah:next("Extend PondStateRecord: pub slots: Vec<SlotProbe>; SlotProbe { slot, liveness: ProbeOutcome, readiness: ProbeOutcome, last_checked_at, url }; ProbeOutcome = Pass | Fail{reason} | Pending")
//! @yah:next("Reconcilers (Minio/Miniflare/MesofactDev) write their probe results into the registry's slot entries each loop iteration")
//! @yah:next("Top-level phase: Running iff every slot Pass on both probes; Degraded iff any liveness Fail with restart in flight; Failed iff restart budget exhausted; else Pending")
//! @yah:verify("cargo test -p yubaba --lib pond")
//! @yah:verify("Smoke: kill miniflare → /pond/state shows slot=static liveness=Fail, top-level phase=Degraded; restart → back to Running")
//! @arch:see(.yah/docs/working/W180-pond-richer-topology.md)

pub mod mesofact_dev;
pub mod miniflare;
pub mod minio;
pub mod ssr_runtime;

pub use minio::{ensure_bucket_public, ensure_minio_running, MinioRunning, MinioSpec};
pub use ssr_runtime::{lower_workload_spec as lower_ssr_workload_spec, SsrRuntimeRunning};
pub use local_driver::pond_miniflare::{
    ensure_miniflare_running, MiniflareRunning, MiniflareSpec,
};
pub use local_driver::pond_mesofact_dev::{
    ensure_mesofact_dev_running, MesofactDevRunning, MesofactDevSpec,
};
pub use local_driver::pond_ssr_runtime::SsrRuntimeSpec;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use local_driver::LocalRuntime;
use serde::Deserialize;
use tokio::sync::{Notify, RwLock};

use crate::pond::mesofact_dev::{MesofactDevReconciler, MesofactDevSupervision};
use crate::pond::miniflare::{MiniflareReconciler, MiniflareSupervision};
use crate::pond::minio::MinioReconciler;
use crate::pond::ssr_runtime::{SsrRuntimeReconciler, SsrRuntimeSupervision};

// Pond wire types (PondDeployReq, PondStateRecord, PondPhase, ProbeOutcome,
// SlotProbe, PondDeployResponse) were carved out into the lean `yubaba-client`
// crate (R483-T5, W156 §3) so clients can POST /pond/deploy without linking
// yubaba's server closure (openraft + axum + russh + portable-pty). They're
// re-exported here unchanged — `yubaba::pond::PondDeployReq` keeps resolving
// for the server side below and for any in-process consumer.
pub use yubaba_client::{
    PondDeployReq, PondDeployResponse, PondPhase, PondStateRecord, ProbeOutcome, SlotProbe,
};

/// Yubaba's per-workload supervision over the MinIO container. Lives inside
/// [`RegistryEntry`] while the workload is registered.
pub(crate) struct MinioSupervision {
    pub runtime: Arc<LocalRuntime>,
    pub container_name: String,
    pub cancel: Arc<Notify>,
}

struct RegistryEntry {
    record: PondStateRecord,
    /// Miniflare process supervision — `None` after teardown or failed spawn.
    miniflare: Option<MiniflareSupervision>,
    /// MinIO container supervision — `None` for test fixtures + failed deploys.
    minio: Option<MinioSupervision>,
    /// SSR-runtime container supervision — `None` when the workload declares
    /// no `ssr_runtime`, or for test fixtures + failed deploys.
    ssr_runtime: Option<SsrRuntimeSupervision>,
    /// Mesofact-dev container supervision — `None` when the workload declares
    /// no `mesofact_dev`, or for test fixtures + failed deploys.
    mesofact_dev: Option<MesofactDevSupervision>,
    /// Per-slot probe snapshots written by reconcilers (R456-F1). Keyed by
    /// slot name (`"object_store"`, `"static"`, `"ssr_runtime"`, `"mesofact_dev"`).
    slot_probes: HashMap<String, SlotProbe>,
}

/// In-memory registry of currently-tracked pond workloads. Lives inside
/// [`crate::ServerState`].
#[derive(Default)]
pub struct PondRegistry {
    entries: RwLock<HashMap<String, RegistryEntry>>,
}

impl PondRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get(&self, ident: &str) -> Option<PondStateRecord> {
        self.entries.read().await.get(ident).map(record_with_slots)
    }

    pub async fn list(&self) -> Vec<PondStateRecord> {
        self.entries
            .read()
            .await
            .values()
            .map(record_with_slots)
            .collect()
    }

    /// Write one slot's probe result. Updates `entry.slot_probes[slot]` then
    /// recomputes the top-level phase as a roll-up across all known slots.
    /// No-op when the entry is already `Failed` (terminal — prevents a
    /// concurrent reconciler from resurrecting a dead workload).
    pub(crate) async fn write_slot_probe(&self, ident: &str, probe: SlotProbe) {
        let mut g = self.entries.write().await;
        let Some(entry) = g.get_mut(ident) else { return };
        if entry.record.phase == PondPhase::Failed {
            return;
        }
        entry.slot_probes.insert(probe.slot.clone(), probe);
        entry.record.phase = roll_up_phase(&entry.slot_probes);
        entry.record.error = None;
    }

    /// Insert (or replace) a Running record. Used by tests that don't exercise
    /// the full bring-up sequence.
    pub async fn insert_running(
        &self,
        req: &PondDeployReq,
        dev_url: Option<String>,
    ) {
        self.insert_full(req, dev_url, None, None, None, None, None)
            .await;
    }

    /// Insert a Running record with yubaba-supervised MinIO, miniflare, SSR
    /// runtime, and (optionally) mesofact-dev. Called by [`deploy`] after the
    /// full bring-up sequence succeeds.
    pub(crate) async fn insert_full(
        &self,
        req: &PondDeployReq,
        dev_url: Option<String>,
        minio_running: Option<&MinioRunning>,
        minio_supervision: Option<MinioSupervision>,
        miniflare_supervision: Option<MiniflareSupervision>,
        ssr_runtime_supervision: Option<SsrRuntimeSupervision>,
        mesofact_dev_supervision: Option<MesofactDevSupervision>,
    ) {
        let (endpoint, console_url) = match minio_running {
            Some(m) => (Some(m.endpoint.clone()), Some(m.console_url.clone())),
            None => (None, None),
        };
        let (prior_miniflare, prior_minio, prior_ssr, prior_md) = {
            let mut g = self.entries.write().await;
            let (mf, mn, sr, md) = g
                .remove(&req.ident)
                .map(|e| (e.miniflare, e.minio, e.ssr_runtime, e.mesofact_dev))
                .unwrap_or((None, None, None, None));
            g.insert(
                req.ident.clone(),
                RegistryEntry {
                    record: PondStateRecord {
                        ident: req.ident.clone(),
                        service: req.service.clone(),
                        env: req.env.clone(),
                        component_id: req.component_id.clone(),
                        phase: PondPhase::Running,
                        dev_url,
                        console_url,
                        endpoint,
                        error: None,
                        slots: vec![],
                    },
                    miniflare: miniflare_supervision,
                    minio: minio_supervision,
                    ssr_runtime: ssr_runtime_supervision,
                    mesofact_dev: mesofact_dev_supervision,
                    slot_probes: Default::default(),
                },
            );
            (mf, mn, sr, md)
        };
        // Tear down priors outside the write lock.
        if let Some(mf) = prior_miniflare {
            mf.cancel.notify_waiters();
            let _ = mf
                .runtime
                .stop_and_remove(&mf.container_name, Duration::from_secs(3))
                .await;
        }
        if let Some(mn) = prior_minio {
            mn.cancel.notify_waiters();
            let _ = mn
                .runtime
                .stop_and_remove(&mn.container_name, Duration::from_secs(3))
                .await;
        }
        if let Some(sr) = prior_ssr {
            sr.cancel.notify_waiters();
            let _ = sr
                .runtime
                .stop_and_remove(&sr.container_name, Duration::from_secs(3))
                .await;
        }
        if let Some(md) = prior_md {
            md.cancel.notify_waiters();
            let _ = md
                .runtime
                .stop_and_remove(&md.container_name, Duration::from_secs(3))
                .await;
        }
    }

    /// Mark a workload Pending before invoking the handler.
    pub async fn mark_pending(&self, req: &PondDeployReq) {
        let mut g = self.entries.write().await;
        let entry = g.entry(req.ident.clone()).or_insert_with(|| RegistryEntry {
            record: PondStateRecord {
                ident: req.ident.clone(),
                service: req.service.clone(),
                env: req.env.clone(),
                component_id: req.component_id.clone(),
                phase: PondPhase::Pending,
                dev_url: None,
                console_url: None,
                endpoint: None,
                error: None,
                slots: vec![],
            },
            miniflare: None,
            minio: None,
            ssr_runtime: None,
            mesofact_dev: None,
            slot_probes: Default::default(),
        });
        if !matches!(entry.record.phase, PondPhase::Running | PondPhase::Degraded) {
            entry.record.phase = PondPhase::Pending;
            entry.record.error = None;
        }
    }

    /// Mark a workload Failed with an error string. Tears down any prior supervision.
    pub async fn mark_failed(&self, req: &PondDeployReq, err: String) {
        let (prior_miniflare, prior_minio, prior_ssr, prior_md) = {
            let mut g = self.entries.write().await;
            let entry = g.entry(req.ident.clone()).or_insert_with(|| RegistryEntry {
                record: PondStateRecord {
                    ident: req.ident.clone(),
                    service: req.service.clone(),
                    env: req.env.clone(),
                    component_id: req.component_id.clone(),
                    phase: PondPhase::Failed,
                    dev_url: None,
                    console_url: None,
                    endpoint: None,
                    error: Some(err.clone()),
                    slots: vec![],
                },
                miniflare: None,
                minio: None,
                ssr_runtime: None,
                mesofact_dev: None,
                slot_probes: Default::default(),
            });
            entry.record.phase = PondPhase::Failed;
            entry.record.error = Some(err);
            (
                entry.miniflare.take(),
                entry.minio.take(),
                entry.ssr_runtime.take(),
                entry.mesofact_dev.take(),
            )
        };
        if let Some(mf) = prior_miniflare {
            mf.cancel.notify_waiters();
            let _ = mf
                .runtime
                .stop_and_remove(&mf.container_name, Duration::from_secs(3))
                .await;
        }
        if let Some(mn) = prior_minio {
            mn.cancel.notify_waiters();
            let _ = mn
                .runtime
                .stop_and_remove(&mn.container_name, Duration::from_secs(3))
                .await;
        }
        if let Some(sr) = prior_ssr {
            sr.cancel.notify_waiters();
            let _ = sr
                .runtime
                .stop_and_remove(&sr.container_name, Duration::from_secs(3))
                .await;
        }
        if let Some(md) = prior_md {
            md.cancel.notify_waiters();
            let _ = md
                .runtime
                .stop_and_remove(&md.container_name, Duration::from_secs(3))
                .await;
        }
    }

    /// Update a workload's phase + optional error string in place. Used by
    /// [`MinioReconciler`] and [`MiniflareReconciler`] when probes flip the
    /// slot between Running ↔ Degraded ↔ Failed without dropping the supervision
    /// handles attached to the entry.
    pub(crate) async fn mark_phase(
        &self,
        ident: &str,
        phase: PondPhase,
        error: Option<String>,
    ) {
        let mut g = self.entries.write().await;
        if let Some(entry) = g.get_mut(ident) {
            entry.record.phase = phase;
            entry.record.error = error;
        }
    }

    /// Tear down all registered workloads. Called on camp shutdown so
    /// dropping the camp daemon reaps every pond container + process yubaba
    /// is tracking.
    pub async fn shutdown_all(&self) {
        let drained: Vec<_> = {
            let mut g = self.entries.write().await;
            g.drain().collect()
        };
        for (_, entry) in drained {
            // Signal reconcilers first so they don't race teardown with a restart.
            if let Some(mf) = entry.miniflare.as_ref() {
                mf.cancel.notify_waiters();
            }
            if let Some(mn) = entry.minio.as_ref() {
                mn.cancel.notify_waiters();
            }
            if let Some(sr) = entry.ssr_runtime.as_ref() {
                sr.cancel.notify_waiters();
            }
            if let Some(md) = entry.mesofact_dev.as_ref() {
                md.cancel.notify_waiters();
            }
            if let Some(mf) = entry.miniflare {
                let _ = mf
                    .runtime
                    .stop_and_remove(&mf.container_name, Duration::from_secs(3))
                    .await;
            }
            if let Some(mn) = entry.minio {
                let _ = mn
                    .runtime
                    .stop_and_remove(&mn.container_name, Duration::from_secs(3))
                    .await;
            }
            if let Some(sr) = entry.ssr_runtime {
                let _ = sr
                    .runtime
                    .stop_and_remove(&sr.container_name, Duration::from_secs(3))
                    .await;
            }
            if let Some(md) = entry.mesofact_dev {
                let _ = md
                    .runtime
                    .stop_and_remove(&md.container_name, Duration::from_secs(3))
                    .await;
            }
        }
    }
}

// ── Registry helpers ─────────────────────────────────────────────────────────

fn record_with_slots(entry: &RegistryEntry) -> PondStateRecord {
    let mut record = entry.record.clone();
    let mut slots: Vec<SlotProbe> = entry.slot_probes.values().cloned().collect();
    slots.sort_by(|a, b| a.slot.cmp(&b.slot));
    record.slots = slots;
    record
}

fn roll_up_phase(slots: &HashMap<String, SlotProbe>) -> PondPhase {
    if slots.is_empty() {
        return PondPhase::Pending;
    }
    if slots
        .values()
        .any(|p| matches!(p.liveness, ProbeOutcome::Fail { .. }))
    {
        return PondPhase::Degraded;
    }
    if slots.values().all(|p| p.liveness == ProbeOutcome::Pass) {
        return PondPhase::Running;
    }
    PondPhase::Pending
}

// ── HTTP handlers ────────────────────────────────────────────────────────────

/// `POST /pond/deploy` — bring MinIO up via `local_driver::pond_minio`, spawn
/// miniflare via `local_driver::pond_miniflare`, register both under supervision,
/// and spawn the MinIO and miniflare reconcilers.
///
/// Returns 503 when no `LocalRuntime` is wired (pond is not configured in this
/// yubaba instance). Returns 500 with a stage tag if MinIO or miniflare bring-up
/// fails.
pub(crate) async fn deploy(
    State(state): State<Arc<crate::ServerState>>,
    Json(req): Json<PondDeployReq>,
) -> axum::response::Response {
    let Some(runtime) = state.pond_local_runtime.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "no LocalRuntime wired for pond; call ServerState::with_pond_local_runtime",
            })),
        )
            .into_response();
    };
    state.pond_registry.mark_pending(&req).await;

    // ── Per-cell bridge network (R455-F1) ─────────────────────────────────────
    // Idempotent: created on first deploy in a cell, reused on subsequent
    // deploys. Containers without a `network` field on their spec stay on the
    // default `bridge` for backward compatibility, but every modern camp builds
    // specs that carry `Some("yah-pond-<svc>-<env>")` so this is the common
    // path.
    let network_name = req
        .minio
        .network
        .clone()
        .or_else(|| req.miniflare.network.clone());
    if let Some(net) = network_name.as_deref() {
        if let Err(e) = runtime.ensure_network(net).await {
            let err = format!("{e:#}");
            state.pond_registry.mark_failed(&req, err.clone()).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": err,
                    "ident": req.ident,
                    "stage": "network",
                })),
            )
                .into_response();
        }
    }

    // ── MinIO half ────────────────────────────────────────────────────────────
    let minio_running = match ensure_minio_running(&runtime, &req.minio).await {
        Ok(m) => m,
        Err(e) => {
            let err = format!("{e:#}");
            state.pond_registry.mark_failed(&req, err.clone()).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": err,
                    "ident": req.ident,
                    "stage": "minio",
                })),
            )
                .into_response();
        }
    };

    // ── SSR-runtime half (R434-F4) ────────────────────────────────────────────
    // Brought up BEFORE miniflare so the bound origin URL can override
    // `req.miniflare.ssr_origin` before miniflare starts proxying. Skipped
    // when the workload declares no `ssr_runtime` companion (pure
    // static/SPA pond mirrors keep working unchanged).
    let mut effective_miniflare = req.miniflare.clone();
    let ssr_running = if let Some(ref ssr_spec) = req.ssr_runtime {
        match local_driver::pond_ssr_runtime::ensure_ssr_runtime_running(
            &runtime, ssr_spec,
        )
        .await
        {
            Ok(running) => {
                // Camp may have left ssr_origin empty if it didn't know the
                // host port at spec-build time; yubaba owns the final wiring.
                effective_miniflare.ssr_origin = running.origin_url.clone();
                if effective_miniflare.worker_mode != "ssr" {
                    effective_miniflare.worker_mode = "ssr".into();
                }
                Some(running)
            }
            Err(e) => {
                let err = format!("{e:#}");
                let _ = runtime
                    .stop_and_remove(&minio_running.container_name, Duration::from_secs(3))
                    .await;
                state.pond_registry.mark_failed(&req, err.clone()).await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": err,
                        "ident": req.ident,
                        "stage": "ssr_runtime",
                    })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    // ── Mesofact-dev half (R455-F3, W180 Phase D) ─────────────────────────────
    // Brought up after MinIO and SSR runtime but before miniflare so the
    // Worker's MESOFACT_BACKEND_ORIGIN + ISSUES_ORIGIN bindings can reference
    // the bridge endpoint when miniflare starts (R455-T4).
    let mesofact_running = if let Some(ref md_spec) = req.mesofact_dev {
        match ensure_mesofact_dev_running(&runtime, md_spec).await {
            Ok(running) => Some(running),
            Err(e) => {
                let err = format!("{e:#}");
                let _ = runtime
                    .stop_and_remove(&minio_running.container_name, Duration::from_secs(3))
                    .await;
                if let Some(ref s) = ssr_running {
                    let _ = runtime
                        .stop_and_remove(&s.container_name, Duration::from_secs(3))
                        .await;
                }
                state.pond_registry.mark_failed(&req, err.clone()).await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": err,
                        "ident": req.ident,
                        "stage": "mesofact_dev",
                    })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    // When miniflare joins the per-cell bridge but camp left asset_origin
    // pointing at host loopback (the pre-R455-F1 shape), rewrite it on the
    // yubaba side using the MinIO container's bridge endpoint. Keeps camp
    // forward-compatible without forcing every caller to recompute on its
    // own side.
    if effective_miniflare.network.is_some() {
        if let Some(bridge_endpoint) = &minio_running.bridge_endpoint {
            let bucket = &req.minio.bucket;
            let expected_origin = format!("{bridge_endpoint}/{bucket}");
            if effective_miniflare.asset_origin != expected_origin
                && effective_miniflare
                    .asset_origin
                    .starts_with("http://127.0.0.1:")
            {
                effective_miniflare.asset_origin = expected_origin;
            }
        }
    }

    // ── Miniflare half ────────────────────────────────────────────────────────
    let miniflare_running = match ensure_miniflare_running(&runtime, &effective_miniflare).await {
        Ok(running) => running,
        Err(e) => {
            let err = format!("{e:#}");
            // Tear down both containers so we don't leak a half-up workload.
            let _ = runtime
                .stop_and_remove(&minio_running.container_name, Duration::from_secs(3))
                .await;
            if let Some(ref s) = ssr_running {
                let _ = runtime
                    .stop_and_remove(&s.container_name, Duration::from_secs(3))
                    .await;
            }
            state.pond_registry.mark_failed(&req, err.clone()).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": err,
                    "ident": req.ident,
                    "stage": "miniflare",
                })),
            )
                .into_response();
        }
    };

    // ── Wire supervision + reconcilers ────────────────────────────────────────
    let minio_cancel = Arc::new(Notify::new());
    let miniflare_cancel = Arc::new(Notify::new());
    let ssr_cancel = Arc::new(Notify::new());
    let mesofact_cancel = Arc::new(Notify::new());

    let minio_supervision = MinioSupervision {
        runtime: runtime.clone(),
        container_name: minio_running.container_name.clone(),
        cancel: minio_cancel.clone(),
    };
    let miniflare_supervision = MiniflareSupervision {
        runtime: runtime.clone(),
        container_name: miniflare_running.container_name.clone(),
        cancel: miniflare_cancel.clone(),
    };
    let ssr_supervision = ssr_running.as_ref().map(|s| SsrRuntimeSupervision {
        runtime: runtime.clone(),
        container_name: s.container_name.clone(),
        cancel: ssr_cancel.clone(),
    });
    let mesofact_dev_supervision = mesofact_running.as_ref().map(|md| MesofactDevSupervision {
        runtime: runtime.clone(),
        container_name: md.container_name.clone(),
        cancel: mesofact_cancel.clone(),
    });

    let dev_url = Some(miniflare_running.dev_url.clone());
    state
        .pond_registry
        .insert_full(
            &req,
            dev_url,
            Some(&minio_running),
            Some(minio_supervision),
            Some(miniflare_supervision),
            ssr_supervision,
            mesofact_dev_supervision,
        )
        .await;

    let minio_reconciler = MinioReconciler {
        runtime: runtime.clone(),
        spec: req.minio.clone(),
        ident: req.ident.clone(),
        registry: state.pond_registry.clone(),
        cancel: minio_cancel,
    };
    let miniflare_reconciler = MiniflareReconciler {
        runtime: runtime.clone(),
        spec: effective_miniflare.clone(),
        ident: req.ident.clone(),
        registry: state.pond_registry.clone(),
        cancel: miniflare_cancel,
    };
    tokio::spawn(minio_reconciler.run());
    tokio::spawn(miniflare_reconciler.run());
    if let Some(ref spec) = req.ssr_runtime {
        let ssr_reconciler = SsrRuntimeReconciler {
            runtime: runtime.clone(),
            spec: spec.clone(),
            ident: req.ident.clone(),
            registry: state.pond_registry.clone(),
            cancel: ssr_cancel,
        };
        tokio::spawn(ssr_reconciler.run());
    }
    if let Some(ref spec) = req.mesofact_dev {
        let mesofact_reconciler = MesofactDevReconciler {
            runtime: runtime.clone(),
            spec: spec.clone(),
            ident: req.ident.clone(),
            registry: state.pond_registry.clone(),
            cancel: mesofact_cancel,
        };
        tokio::spawn(mesofact_reconciler.run());
    }

    match state.pond_registry.get(&req.ident).await {
        Some(r) => (StatusCode::CREATED, Json(r)).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "registry lost the record between insert and read",
            })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct PondStateQuery {
    pub ident: String,
}

/// `GET /pond/state?ident=...` — return the registered record for one
/// workload. 404 when no registration exists; desktop's adopt path treats
/// 404 as "pond not running" and surfaces a clear error.
pub(crate) async fn get_state(
    State(state): State<Arc<crate::ServerState>>,
    Query(q): Query<PondStateQuery>,
) -> axum::response::Response {
    match state.pond_registry.get(&q.ident).await {
        Some(record) => (StatusCode::OK, Json(record)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("no pond workload registered with ident {:?}", q.ident),
            })),
        )
            .into_response(),
    }
}

/// `GET /pond` — list every currently-tracked pond workload. Always 200.
pub(crate) async fn list_state(
    State(state): State<Arc<crate::ServerState>>,
) -> impl IntoResponse {
    let records = state.pond_registry.list().await;
    (StatusCode::OK, Json(serde_json::json!({ "workloads": records })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    fn miniflare_spec_fixture() -> MiniflareSpec {
        MiniflareSpec {
            image: "ghcr.io/yah-ai/yah-miniflare:latest".into(),
            container_name: "yah-pond-svc-pond-static".into(),
            container_label: "svc:pond:static".into(),
            network: Some("yah-pond-svc-pond".into()),
            network_alias: Some("miniflare".into()),
            port: 4322,
            worker_script: "// noop".into(),
            state_dir: PathBuf::from("/tmp/pond-test"),
            asset_origin: "http://minio:9000/yah-dev".into(),
            worker_mode: "static".into(),
            ssr_origin: String::new(),
            ssr_prefixes: vec![],
            ready_timeout: Duration::from_secs(30),
            extra_env: std::collections::BTreeMap::new(),
        }
    }

    fn minio_spec_fixture() -> MinioSpec {
        MinioSpec {
            image: "minio/minio:RELEASE.2025-04-22T22-12-26Z".into(),
            user: "yahsim".into(),
            password: "yahsim-local-only".into(),
            api_port: 9000,
            console_port: 9001,
            bucket: "yah-dev".into(),
            data_dir: PathBuf::from("/tmp/yah-pond/minio"),
            container_name: "yah-pond-svc-pond-object_store".into(),
            container_label: "svc:pond:object_store".into(),
            ready_timeout: Duration::from_secs(30),
            network: Some("yah-pond-svc-pond".into()),
            network_alias: Some("minio".into()),
        }
    }

    fn req(ident: &str) -> PondDeployReq {
        PondDeployReq {
            ident: ident.into(),
            service: "svc".into(),
            env: "pond".into(),
            component_id: "site".into(),
            minio: minio_spec_fixture(),
            miniflare: miniflare_spec_fixture(),
            ssr_runtime: None,
            mesofact_dev: None,
        }
    }

    fn minio_running_fixture() -> MinioRunning {
        MinioRunning {
            endpoint: "http://127.0.0.1:9000".into(),
            console_url: "http://localhost:9001".into(),
            bucket: "yah-dev".into(),
            access_key: "yahsim".into(),
            secret_key: "yahsim-local-only".into(),
            container_name: "yah-pond-svc-pond-object_store".into(),
            bridge_endpoint: Some("http://minio:9000".into()),
        }
    }

    #[tokio::test]
    async fn pending_then_running() {
        let reg = PondRegistry::new();
        let r = req("svc-pond-site");
        reg.mark_pending(&r).await;
        let snap = reg.get(&r.ident).await.unwrap();
        assert_eq!(snap.phase, PondPhase::Pending);
        assert!(snap.dev_url.is_none());

        reg.insert_running(&r, Some("http://localhost:4322".into()))
            .await;
        let snap = reg.get(&r.ident).await.unwrap();
        assert_eq!(snap.phase, PondPhase::Running);
        assert_eq!(snap.dev_url.as_deref(), Some("http://localhost:4322"));
    }

    #[tokio::test]
    async fn failed_carries_error() {
        let reg = PondRegistry::new();
        let r = req("svc-pond-site");
        reg.mark_failed(&r, "MinIO did not bind port".into()).await;
        let snap = reg.get(&r.ident).await.unwrap();
        assert_eq!(snap.phase, PondPhase::Failed);
        assert_eq!(snap.error.as_deref(), Some("MinIO did not bind port"));
    }

    #[tokio::test]
    async fn missing_ident_returns_none() {
        let reg = PondRegistry::new();
        assert!(reg.get("nope").await.is_none());
    }

    #[tokio::test]
    async fn shutdown_all_drains_registry() {
        let reg = PondRegistry::new();
        let r1 = req("a");
        let r2 = req("b");
        reg.insert_running(&r1, Some("http://a".into())).await;
        reg.insert_running(&r2, Some("http://b".into())).await;
        assert_eq!(reg.list().await.len(), 2);
        reg.shutdown_all().await;
        assert_eq!(reg.list().await.len(), 0);
    }

    #[tokio::test]
    async fn redeploy_replaces_record() {
        let reg = PondRegistry::new();
        let r = req("svc-pond-site");
        reg.insert_running(&r, Some("http://localhost:4322".into()))
            .await;
        reg.insert_running(&r, Some("http://localhost:4323".into()))
            .await;
        let snap = reg.get(&r.ident).await.unwrap();
        assert_eq!(snap.dev_url.as_deref(), Some("http://localhost:4323"));
    }

    #[tokio::test]
    async fn insert_full_populates_endpoint_and_console_url() {
        let reg = PondRegistry::new();
        let r = req("svc-pond-site");
        let m = minio_running_fixture();
        reg.insert_full(
            &r,
            Some("http://localhost:4322".into()),
            Some(&m),
            None,
            None,
            None,
            None,
        )
        .await;
        let snap = reg.get(&r.ident).await.unwrap();
        assert_eq!(snap.endpoint.as_deref(), Some("http://127.0.0.1:9000"));
        assert_eq!(snap.console_url.as_deref(), Some("http://localhost:9001"));
        assert_eq!(snap.dev_url.as_deref(), Some("http://localhost:4322"));
    }

    #[tokio::test]
    async fn mark_phase_does_not_disturb_endpoints() {
        let reg = PondRegistry::new();
        let r = req("svc-pond-site");
        let m = minio_running_fixture();
        reg.insert_full(
            &r,
            Some("http://localhost:4322".into()),
            Some(&m),
            None,
            None,
            None,
            None,
        )
        .await;
        reg.mark_phase(&r.ident, PondPhase::Degraded, Some("probe failed".into()))
            .await;
        let snap = reg.get(&r.ident).await.unwrap();
        assert_eq!(snap.phase, PondPhase::Degraded);
        assert_eq!(snap.error.as_deref(), Some("probe failed"));
        assert_eq!(snap.endpoint.as_deref(), Some("http://127.0.0.1:9000"));
        assert_eq!(snap.console_url.as_deref(), Some("http://localhost:9001"));
    }

    #[tokio::test]
    async fn mark_phase_on_missing_ident_is_a_noop() {
        let reg = PondRegistry::new();
        reg.mark_phase("nope", PondPhase::Failed, Some("nope".into()))
            .await;
        assert!(reg.get("nope").await.is_none());
    }

    fn pass_probe(slot: &str) -> SlotProbe {
        SlotProbe {
            slot: slot.into(),
            liveness: ProbeOutcome::Pass,
            readiness: ProbeOutcome::Pass,
            last_checked_at: 0,
            url: None,
        }
    }

    fn fail_probe(slot: &str, reason: &str) -> SlotProbe {
        SlotProbe {
            slot: slot.into(),
            liveness: ProbeOutcome::Fail { reason: reason.into() },
            readiness: ProbeOutcome::Pending,
            last_checked_at: 0,
            url: None,
        }
    }

    #[tokio::test]
    async fn write_slot_probe_running_when_all_pass() {
        let reg = PondRegistry::new();
        let r = req("w");
        reg.mark_pending(&r).await;
        reg.write_slot_probe("w", pass_probe("object_store")).await;
        reg.write_slot_probe("w", pass_probe("static")).await;
        let snap = reg.get("w").await.unwrap();
        assert_eq!(snap.phase, PondPhase::Running);
        assert_eq!(snap.slots.len(), 2);
        // slots are sorted alphabetically
        assert_eq!(snap.slots[0].slot, "object_store");
        assert_eq!(snap.slots[1].slot, "static");
    }

    #[tokio::test]
    async fn write_slot_probe_degraded_when_any_fail() {
        let reg = PondRegistry::new();
        let r = req("w");
        reg.mark_pending(&r).await;
        reg.write_slot_probe("w", pass_probe("object_store")).await;
        reg.write_slot_probe("w", fail_probe("static", "probe timed out")).await;
        let snap = reg.get("w").await.unwrap();
        assert_eq!(snap.phase, PondPhase::Degraded);
    }

    #[tokio::test]
    async fn write_slot_probe_recovers_to_running() {
        let reg = PondRegistry::new();
        let r = req("w");
        reg.mark_pending(&r).await;
        reg.write_slot_probe("w", fail_probe("static", "down")).await;
        assert_eq!(reg.get("w").await.unwrap().phase, PondPhase::Degraded);
        reg.write_slot_probe("w", pass_probe("static")).await;
        assert_eq!(reg.get("w").await.unwrap().phase, PondPhase::Running);
    }

    #[tokio::test]
    async fn mark_phase_failed_prevents_probe_resurrect() {
        let reg = PondRegistry::new();
        let r = req("w");
        reg.mark_pending(&r).await;
        reg.write_slot_probe("w", pass_probe("static")).await;
        reg.mark_phase("w", PondPhase::Failed, Some("restarts exhausted".into())).await;
        // A subsequent passing probe must NOT overwrite the terminal Failed state.
        reg.write_slot_probe("w", pass_probe("static")).await;
        let snap = reg.get("w").await.unwrap();
        assert_eq!(snap.phase, PondPhase::Failed);
    }

    #[tokio::test]
    async fn slots_absent_before_first_probe() {
        let reg = PondRegistry::new();
        let r = req("w");
        reg.insert_running(&r, Some("http://localhost:4322".into())).await;
        let snap = reg.get("w").await.unwrap();
        assert!(snap.slots.is_empty());
    }
}
