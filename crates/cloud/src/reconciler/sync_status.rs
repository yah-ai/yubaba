//! Argo-style sync / health / drift computation for service mirrors.
//!
//! This is the **declared-vs-live** status query that backs the Services
//! catalog matrix (R323-F3) and deploy panel (R323-F4). It is the
//! service-mirror sibling of [`crate::status`] — where that module diffs a
//! declared *machine* against live Hetzner, this one diffs a declared
//! *mirror* (`.yah/services/<svc>/mirrors/<env>.toml`) against whatever the
//! caller can observe is running.
//!
//! Borrows Argo CD's vocabulary (see `visiting/yah-cloud-design/screens/
//! services.jsx`):
//! - **Sync** — declared vs live: `synced` / `out-of-sync` / `unknown`.
//!   Out-of-sync is the *actionable* signal (the operator's call to sync).
//! - **Health** — runtime state: `healthy` / `progressing` / `degraded` /
//!   `missing` / `idle`.
//! - **Drift** — the per-field diff (declared "desired" vs observed "live")
//!   that explains *why* a mirror is out-of-sync.
//!
//! ## Transport-free, like [`crate::status`]
//!
//! This module computes status from (a) the declared [`MirrorConfig`] and
//! (b) a caller-supplied [`MirrorObservation`]. It never reaches out to a
//! runtime itself — the desktop fills observations from its in-memory
//! running-mirror registry; a future yubaba probe will fill them for cloud
//! tiers. Tiers with **no observation** (`None`) resolve to `unknown` sync /
//! `missing` health, which is the honest state today for `cloud`/`ha`
//! (read-only, declared status only — see the Area-A arch doc).
//!
//! @yah:ticket(R323-F10, "Service sync-history store (recent-syncs timeline backend)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T15:20:26Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R323)
//! @yah:next("Persist a per-(service,env) sync-event log (when/who/rev/result) so the deploy panel's 'recent syncs' timeline (R323-F4) has real data. No store exists today — runs are in-memory.")
//! @yah:next("Expose a query (e.g. service_sync_history) + RPC the timeline reads; mirror the QED run-history pattern (R-QED) rather than inventing a second shape.")
//! @yah:gotcha("Until this lands, F4's timeline has no backing data — render an empty/placeholder state, don't fabricate events.")

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::ServiceWithMirrors;
use crate::{MirrorConfig, MirrorProviderSlot, MirrorShape, Provider};

/// Declared-vs-live agreement for one mirror. Argo's "sync status".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyncState {
    /// Live state matches the declared manifest.
    Synced,
    /// Live differs from declared — there is something to push. The
    /// actionable signal that drives the matrix cell's border/fill.
    OutOfSync,
    /// No live observation available, so agreement can't be determined
    /// (e.g. cloud/ha today — declared only).
    Unknown,
}

/// Runtime health of a mirror's workloads. Argo's "health status", plus an
/// `idle` state for on-demand local mirrors that are declared + in sync but
/// not currently running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthState {
    /// Running and reporting ready.
    Healthy,
    /// Running but not yet ready (rolling out / waiting on a port/probe).
    Progressing,
    /// Running with errors, or the last bring-up/sync failed.
    Degraded,
    /// Declared but absent where it is expected to be continuously live
    /// (cloud/ha tiers), or unobserved.
    Missing,
    /// Declared + in sync but intentionally not running. The resting state
    /// of an on-demand local mirror (`shape = "local"`) you haven't brought
    /// up. Distinct from `missing`: nothing is wrong.
    Idle,
}

/// Runtime-observed container workload status. Serialized as a tagged union
/// (`kind` field). Richer than [`HealthState`] for the Services tab chip
/// row — carries numeric detail (exit code, restart count, timestamps) that
/// `HealthState` deliberately elides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum WireContainerStatus {
    Running,
    Restarting {
        restart_count: u32,
        last_exit_code: i32,
        last_finished_at_unix_ms: u64,
    },
    Stopped,
    Failed {
        reason: String,
    },
}

/// The substrate a mirror runs on. `dev` is the odd one out (a bare
/// process); `sim`/`cloud`/`ha` share the container substrate. Derived from
/// the mirror's provider slots, not from the env name (env names are
/// arbitrary file stems). See the RuntimeAxis grouping in the Area-A design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    /// A bare process (the built-in static server / a dev `axum` binary).
    Process,
    /// Containers (pond miniflare/minio, or a remote container substrate).
    Containers,
}

impl Runtime {
    /// Derive the runtime from a mirror's provider slots: any container or
    /// remote-substrate slot makes the whole mirror `containers`; a mirror
    /// whose only slots are bare-process inline kinds (`local-static`) is
    /// `process`. Empty/unknown defaults to `process` (the dev case).
    pub fn from_mirror(mirror: &MirrorConfig) -> Self {
        let any_container = mirror.providers.values().any(|slot| match slot {
            // Inline container kinds, or the local container runtime itself.
            MirrorProviderSlot::Inline { kind, .. } => matches!(
                kind,
                Provider::MiniflareContainer | Provider::MinioContainer | Provider::LocalContainer
            ),
            // A referenced provider (cloudflare / hetzner / local-container)
            // is always a container/cloud substrate.
            MirrorProviderSlot::Reference { .. } => true,
        });
        if any_container {
            Runtime::Containers
        } else {
            Runtime::Process
        }
    }
}

/// What the operator can observe about one mirror right now.
///
/// Callers fill this from whatever live source they have: the desktop from
/// its in-memory running-mirror registry, a future CLI from a yubaba probe.
/// `None` (no observation) is a first-class state — it yields `unknown`
/// sync, which is honest for tiers with no live source yet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MirrorObservation {
    /// Is the mirror's workload set currently up?
    pub running: bool,
    /// Did the runtime report the workloads as ready (port/HTTP up)? Only
    /// meaningful when `running`.
    pub ready: bool,
    /// The last bring-up/sync failed or a workload is crashing.
    pub errored: bool,
    /// Live revision actually deployed, when the runtime can report it
    /// (image tag / sha / dev hash). `None` when unknown — a `None` live
    /// revision never *by itself* makes a mirror out-of-sync.
    pub live_revision: Option<String>,
    /// Observed live field values, keyed `slot -> field -> value`, for drift
    /// diffing against the declared manifest. Empty when the runtime can't
    /// report its effective config (the common case today).
    pub live_fields: BTreeMap<String, BTreeMap<String, String>>,
}

/// One declared-vs-live field divergence. Rendered in the deploy panel's
/// drift list as `path: − live · + desired`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftEntry {
    /// Dotted path into the manifest, e.g. `providers.static.image`.
    pub path: String,
    /// Declared ("desired") value.
    pub desired: String,
    /// Observed ("live") value.
    pub live: String,
}

/// Computed status for one matrix cell — a single (service, env) mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellStatus {
    /// Env name (file stem of `mirrors/<env>.toml`).
    pub env: String,
    pub sync: SyncState,
    pub health: HealthState,
    pub runtime: Runtime,
    pub shape: MirrorShape,
    /// Best-effort declared revision (an `image`/`version`/`tag` field on a
    /// provider slot). `None` when the manifest carries no version-bearing
    /// field (e.g. a bare `local-static` slot).
    pub declared_revision: Option<String>,
    /// Live revision, echoed from the observation when known.
    pub live_revision: Option<String>,
    /// Operator-facing provider label, e.g. `cloudflare` or
    /// `miniflare-container + minio-container`.
    pub provider_label: String,
    /// Per-field divergences explaining an out-of-sync cell. Empty when in
    /// sync or unobserved.
    pub drift: Vec<DriftEntry>,
    /// Runtime-observed container status. Set for pond cells in crash-loop
    /// or running state; absent for non-pond and unobserved cells. Enriched
    /// by the desktop after `compute_service` — not set by `compute_cell`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_status: Option<WireContainerStatus>,
}

impl CellStatus {
    /// Convenience: number of drifted fields (the matrix cell's "N drift"
    /// badge).
    pub fn drift_count(&self) -> usize {
        self.drift.len()
    }
}

/// Computed status for one service across all its declared mirrors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub domain: String,
    /// One cell per declared mirror, keyed by env. Tiers with no
    /// `mirrors/<env>.toml` are simply absent — the UI renders those as
    /// "undeclared" against its canonical tier list (dev/sim/cloud/ha).
    pub cells: BTreeMap<String, CellStatus>,
}

/// Roll-up counts across a set of services, for the catalog's summary badges.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusSummary {
    pub synced: usize,
    pub out_of_sync: usize,
    pub unknown: usize,
    pub healthy: usize,
    pub progressing: usize,
    pub degraded: usize,
    pub missing: usize,
    pub idle: usize,
}

/// Compute the status of one mirror cell from its declared manifest and an
/// optional live observation.
///
/// Policy:
/// - **No observation** → `unknown` sync, `missing` health. Honest default
///   for tiers with no live source (cloud/ha today).
/// - **Sync**: drift present, or a known live revision that differs from the
///   declared revision → `out-of-sync`; otherwise `synced`. (A `None` live
///   revision never forces out-of-sync — absence of info is not divergence.)
/// - **Health**: `errored` → `degraded`; `running && ready` → `healthy`;
///   `running && !ready` → `progressing`; `!running` → `idle` for a local
///   (on-demand) mirror, else `missing`.
pub fn compute_cell(
    env: &str,
    mirror: &MirrorConfig,
    obs: Option<&MirrorObservation>,
) -> CellStatus {
    let runtime = Runtime::from_mirror(mirror);
    let declared_revision = declared_revision(mirror);
    let provider_label = provider_label(mirror);

    let (sync, health, live_revision, drift) = match obs {
        None => (SyncState::Unknown, HealthState::Missing, None, Vec::new()),
        Some(o) => {
            let drift = compute_drift(mirror, o);
            let rev_diverges = matches!(
                (&declared_revision, &o.live_revision),
                (Some(d), Some(l)) if d != l
            );
            let sync = if !drift.is_empty() || rev_diverges {
                SyncState::OutOfSync
            } else {
                SyncState::Synced
            };
            let health = if o.errored {
                HealthState::Degraded
            } else if o.running && o.ready {
                HealthState::Healthy
            } else if o.running {
                HealthState::Progressing
            } else if mirror.shape == MirrorShape::Local {
                HealthState::Idle
            } else {
                HealthState::Missing
            };
            (sync, health, o.live_revision.clone(), drift)
        }
    };

    CellStatus {
        env: env.to_string(),
        sync,
        health,
        runtime,
        shape: mirror.shape,
        declared_revision,
        live_revision,
        provider_label,
        drift,
        workload_status: None,
    }
}

/// Compute the status of one service across every mirror it declares.
/// `observations` supplies a live snapshot per env; envs absent from the map
/// are treated as unobserved (`None`).
pub fn compute_service(
    svc: &ServiceWithMirrors,
    observations: &BTreeMap<String, MirrorObservation>,
) -> ServiceStatus {
    let cells = svc
        .mirrors
        .iter()
        .map(|(env, mirror)| {
            let cell = compute_cell(env, mirror, observations.get(env));
            (env.clone(), cell)
        })
        .collect();
    ServiceStatus {
        name: svc.service.name.clone(),
        domain: svc.service.domain.clone(),
        cells,
    }
}

/// Tally sync + health states across every cell of every service.
pub fn summarize(services: &[ServiceStatus]) -> StatusSummary {
    let mut s = StatusSummary::default();
    for svc in services {
        for cell in svc.cells.values() {
            match cell.sync {
                SyncState::Synced => s.synced += 1,
                SyncState::OutOfSync => s.out_of_sync += 1,
                SyncState::Unknown => s.unknown += 1,
            }
            match cell.health {
                HealthState::Healthy => s.healthy += 1,
                HealthState::Progressing => s.progressing += 1,
                HealthState::Degraded => s.degraded += 1,
                HealthState::Missing => s.missing += 1,
                HealthState::Idle => s.idle += 1,
            }
        }
    }
    s
}

// ─── field helpers ──────────────────────────────────────────────────────────

/// The version-bearing fields we recognise on a provider slot, in priority
/// order. `image` carries its own tag (`caddy:2.8.1`) so it wins.
const REVISION_KEYS: [&str; 3] = ["image", "version", "tag"];

/// Best-effort declared revision: scan slots (sorted by role for
/// determinism) for the first `image`/`version`/`tag` field.
fn declared_revision(mirror: &MirrorConfig) -> Option<String> {
    for slot in mirror.providers.values() {
        let fields = slot_fields(slot);
        for key in REVISION_KEYS {
            if let Some(v) = fields.get(key).and_then(toml_value_to_string) {
                return Some(v);
            }
        }
    }
    None
}

/// Operator-facing provider label: the distinct slot providers joined with
/// ` + ` (e.g. `miniflare-container + minio-container`, or `cloudflare`).
fn provider_label(mirror: &MirrorConfig) -> String {
    let mut seen: Vec<String> = Vec::new();
    for slot in mirror.providers.values() {
        let label = match slot {
            MirrorProviderSlot::Reference { provider_id, .. } => provider_id.clone(),
            MirrorProviderSlot::Inline { kind, .. } => provider_kind_label(*kind),
        };
        if !seen.contains(&label) {
            seen.push(label);
        }
    }
    seen.join(" + ")
}

/// Diff each declared slot field against the observed live value. Only emits
/// entries for keys the observation actually reports — an empty `live_fields`
/// (the common case today) yields no drift.
fn compute_drift(mirror: &MirrorConfig, obs: &MirrorObservation) -> Vec<DriftEntry> {
    let mut out = Vec::new();
    for (role, slot) in &mirror.providers {
        let Some(live_slot) = obs.live_fields.get(role) else {
            continue;
        };
        let declared = slot_fields(slot);
        for (key, live_val) in live_slot {
            let desired = declared.get(key).and_then(toml_value_to_string);
            // Drift only when declared has a value AND it differs from live.
            if let Some(desired) = desired {
                if &desired != live_val {
                    out.push(DriftEntry {
                        path: format!("providers.{role}.{key}"),
                        desired,
                        live: live_val.clone(),
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn slot_fields(slot: &MirrorProviderSlot) -> &BTreeMap<String, toml::Value> {
    match slot {
        MirrorProviderSlot::Reference { fields, .. } => fields,
        MirrorProviderSlot::Inline { fields, .. } => fields,
    }
}

/// Render a scalar TOML value as a string for revision/drift display.
/// Non-scalar values (tables/arrays) are not version-bearing → `None`.
fn toml_value_to_string(v: &toml::Value) -> Option<String> {
    match v {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Integer(n) => Some(n.to_string()),
        toml::Value::Float(f) => Some(f.to_string()),
        toml::Value::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Kebab-case label for an inline provider kind (matches the serde wire form).
fn provider_kind_label(kind: Provider) -> String {
    match kind {
        Provider::Cloudflare => "cloudflare",
        Provider::Hetzner => "hetzner",
        Provider::Vultr => "vultr",
        Provider::Static => "static",
        Provider::LocalStatic => "local-static",
        Provider::LocalContainer => "local-container",
        Provider::MiniflareContainer => "miniflare-container",
        Provider::MinioContainer => "minio-container",
    }
    .to_string()
}

// ─── sync-history store ───────────────────────────────────────────────────

/// One recorded sync operation for a (service, env) pair.
///
/// Written to `.yah/jit/services/<service>/<env>/syncs/<id>.json` on
/// completion (R323-F10). Terminal-only — no in-progress state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncHistoryEntry {
    pub id: String,
    pub service: String,
    pub env: String,
    pub status: SyncOutcome,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<String>,
    /// Declared revision that was synced to (e.g. `caddy:2.8.1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    pub workload_count: u32,
}

/// Terminal outcome of a sync operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SyncOutcome {
    Success,
    Failed,
    Cancelled,
}

/// Generate a random 8-byte hex string suitable for sync history entry IDs.
pub fn new_sync_id() -> String {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).unwrap_or(());
    hex::encode(bytes)
}

// ─── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServiceConfig, ServiceWithMirrors};

    /// Parse a mirror from inline TOML (the on-disk form), so tests exercise
    /// the same path the loader uses.
    fn mirror(src: &str) -> MirrorConfig {
        toml::from_str(src).expect("mirror toml")
    }

    fn local_static_mirror() -> MirrorConfig {
        mirror(
            "schema_version = 1\nshape = \"local\"\n\n[providers.static]\nkind = \"local-static\"\nport = 4321\n",
        )
    }

    fn cloudflare_mirror() -> MirrorConfig {
        mirror(
            "schema_version = 1\nshape = \"single-machine\"\n\n[providers.static]\nuse = \"cloudflare\"\nimage = \"caddy:2.8.1\"\n",
        )
    }

    fn sim_miniflare_mirror() -> MirrorConfig {
        mirror(
            "schema_version = 1\nshape = \"local\"\n\n[providers.static]\nkind = \"miniflare-container\"\nimage = \"caddy:2.8.1\"\nport = 8080\n\n[providers.object_store]\nkind = \"minio-container\"\n",
        )
    }

    #[test]
    fn runtime_process_for_local_static_only() {
        assert_eq!(
            Runtime::from_mirror(&local_static_mirror()),
            Runtime::Process
        );
    }

    #[test]
    fn runtime_containers_for_inline_container_kinds() {
        assert_eq!(
            Runtime::from_mirror(&sim_miniflare_mirror()),
            Runtime::Containers
        );
    }

    #[test]
    fn runtime_containers_for_referenced_provider() {
        assert_eq!(
            Runtime::from_mirror(&cloudflare_mirror()),
            Runtime::Containers
        );
    }

    #[test]
    fn no_observation_is_unknown_missing() {
        let cell = compute_cell("ha", &cloudflare_mirror(), None);
        assert_eq!(cell.sync, SyncState::Unknown);
        assert_eq!(cell.health, HealthState::Missing);
        assert!(cell.drift.is_empty());
        assert_eq!(cell.live_revision, None);
    }

    #[test]
    fn running_ready_local_is_synced_healthy() {
        let obs = MirrorObservation {
            running: true,
            ready: true,
            ..Default::default()
        };
        let cell = compute_cell("dev", &local_static_mirror(), Some(&obs));
        assert_eq!(cell.sync, SyncState::Synced);
        assert_eq!(cell.health, HealthState::Healthy);
        assert_eq!(cell.runtime, Runtime::Process);
    }

    #[test]
    fn declared_but_down_local_is_idle_not_missing() {
        // A local (on-demand) mirror that isn't running is idle — nothing
        // is wrong, it just hasn't been brought up. Distinct from missing.
        let obs = MirrorObservation {
            running: false,
            ..Default::default()
        };
        let cell = compute_cell("sim", &sim_miniflare_mirror(), Some(&obs));
        assert_eq!(cell.health, HealthState::Idle);
        assert_eq!(cell.sync, SyncState::Synced);
    }

    #[test]
    fn down_continuous_tier_is_missing() {
        // A single-machine (continuously-live) mirror observed as not running
        // is missing, not idle.
        let obs = MirrorObservation {
            running: false,
            ..Default::default()
        };
        let cell = compute_cell("cloud", &cloudflare_mirror(), Some(&obs));
        assert_eq!(cell.health, HealthState::Missing);
    }

    #[test]
    fn running_not_ready_is_progressing() {
        let obs = MirrorObservation {
            running: true,
            ready: false,
            ..Default::default()
        };
        let cell = compute_cell("cloud", &cloudflare_mirror(), Some(&obs));
        assert_eq!(cell.health, HealthState::Progressing);
    }

    #[test]
    fn errored_is_degraded() {
        let obs = MirrorObservation {
            running: true,
            ready: true,
            errored: true,
            ..Default::default()
        };
        let cell = compute_cell("cloud", &cloudflare_mirror(), Some(&obs));
        assert_eq!(cell.health, HealthState::Degraded);
    }

    #[test]
    fn diverging_live_revision_is_out_of_sync() {
        let obs = MirrorObservation {
            running: true,
            ready: true,
            live_revision: Some("caddy:2.7.6".into()),
            ..Default::default()
        };
        let cell = compute_cell("cloud", &cloudflare_mirror(), Some(&obs));
        assert_eq!(cell.declared_revision.as_deref(), Some("caddy:2.8.1"));
        assert_eq!(cell.live_revision.as_deref(), Some("caddy:2.7.6"));
        assert_eq!(cell.sync, SyncState::OutOfSync);
    }

    #[test]
    fn matching_live_revision_is_synced() {
        let obs = MirrorObservation {
            running: true,
            ready: true,
            live_revision: Some("caddy:2.8.1".into()),
            ..Default::default()
        };
        let cell = compute_cell("cloud", &cloudflare_mirror(), Some(&obs));
        assert_eq!(cell.sync, SyncState::Synced);
    }

    #[test]
    fn unknown_live_revision_does_not_force_out_of_sync() {
        // We know the declared rev but not the live one — that's not enough
        // to call divergence. Stays synced.
        let obs = MirrorObservation {
            running: true,
            ready: true,
            live_revision: None,
            ..Default::default()
        };
        let cell = compute_cell("cloud", &cloudflare_mirror(), Some(&obs));
        assert_eq!(cell.sync, SyncState::Synced);
    }

    #[test]
    fn field_drift_is_detected_and_makes_out_of_sync() {
        let mut live_fields = BTreeMap::new();
        let mut static_slot = BTreeMap::new();
        static_slot.insert("image".to_string(), "caddy:2.7.6".to_string());
        static_slot.insert("port".to_string(), "8080".to_string()); // matches declared
        live_fields.insert("static".to_string(), static_slot);

        let obs = MirrorObservation {
            running: true,
            ready: true,
            live_fields,
            ..Default::default()
        };
        let cell = compute_cell("sim", &sim_miniflare_mirror(), Some(&obs));
        assert_eq!(cell.sync, SyncState::OutOfSync);
        assert_eq!(cell.drift_count(), 1, "only the image field drifts");
        assert_eq!(cell.drift[0].path, "providers.static.image");
        assert_eq!(cell.drift[0].desired, "caddy:2.8.1");
        assert_eq!(cell.drift[0].live, "caddy:2.7.6");
    }

    #[test]
    fn provider_label_joins_inline_kinds() {
        // Order follows the role-key (BTreeMap) order — deterministic:
        // `object_store` (minio) sorts before `static` (miniflare).
        assert_eq!(
            provider_label(&sim_miniflare_mirror()),
            "minio-container + miniflare-container"
        );
        assert_eq!(provider_label(&cloudflare_mirror()), "cloudflare");
    }

    #[test]
    fn declared_revision_none_when_no_version_field() {
        assert_eq!(declared_revision(&local_static_mirror()), None);
    }

    #[test]
    fn compute_service_and_summary_roll_up() {
        let svc = ServiceWithMirrors {
            service: ServiceConfig {
                schema_version: 1,
                name: "yah-dev".into(),
                domain: "yah.dev".into(),
                components: vec![],
            },
            mirrors: BTreeMap::from([
                ("dev".to_string(), local_static_mirror()),
                ("cloud".to_string(), cloudflare_mirror()),
            ]),
            component_transform_recipes: BTreeMap::new(),
        };

        let mut obs = BTreeMap::new();
        obs.insert(
            "dev".to_string(),
            MirrorObservation {
                running: true,
                ready: true,
                ..Default::default()
            },
        );
        // No observation for "cloud" → unknown/missing.

        let status = compute_service(&svc, &obs);
        assert_eq!(status.name, "yah-dev");
        assert_eq!(status.cells.len(), 2);
        assert_eq!(status.cells["dev"].sync, SyncState::Synced);
        assert_eq!(status.cells["dev"].health, HealthState::Healthy);
        assert_eq!(status.cells["cloud"].sync, SyncState::Unknown);
        assert_eq!(status.cells["cloud"].health, HealthState::Missing);

        let summary = summarize(&[status]);
        assert_eq!(summary.synced, 1);
        assert_eq!(summary.unknown, 1);
        assert_eq!(summary.healthy, 1);
        assert_eq!(summary.missing, 1);
    }

    #[test]
    fn states_serialize_in_kebab_case_for_the_wire() {
        assert_eq!(
            serde_json::to_string(&SyncState::OutOfSync).unwrap(),
            "\"out-of-sync\""
        );
        assert_eq!(
            serde_json::to_string(&HealthState::Idle).unwrap(),
            "\"idle\""
        );
        assert_eq!(
            serde_json::to_string(&Runtime::Containers).unwrap(),
            "\"containers\""
        );
    }
}
