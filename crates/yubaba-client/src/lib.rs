//! `yubaba-client` — the thin wire surface for talking to a yubaba's pond
//! HTTP API, carved out of the full `yubaba` lib (R483-T5, W156 §3).
//!
//! Camp (and any other client) only needs to *construct* `PondDeployReq` and
//! POST it to `/pond/deploy`, and *decode* the `PondStateRecord` yubaba returns
//! from `/pond/state`. None of that needs yubaba's server closure
//! (openraft + axum + russh + portable-pty). This crate holds just the serde
//! types crossing the wire; the full `yubaba` lib re-exports them from here so
//! `yubaba::pond::PondDeployReq` keeps resolving for the server side.
//!
//! The slot specs `PondDeployReq` embeds (`MinioSpec`, `MiniflareSpec`,
//! `SsrRuntimeSpec`) live in `local-driver` — the runtime that consumes them —
//! and are re-used here unchanged.

use local_driver::pond_miniflare::MiniflareSpec;
use local_driver::pond_minio::MinioSpec;
use local_driver::pond_ssr_runtime::SsrRuntimeSpec;
use serde::{Deserialize, Serialize};

/// Request body for `POST /pond/deploy`. Camp constructs this from a
/// declared `mesofact-static` component on its `CloudConfig`.
///
/// `ident` is the workload's mesh identity — convention is
/// `"{service}-{env}-{component_id}"`.
///
/// `minio` carries the yubaba-owned MinIO slot spec (image, ports, data dir,
/// container name). Camp builds this from the workspace's
/// `providers.object_store` slot.
///
/// `miniflare` carries everything yubaba needs to spawn (and restart) the
/// miniflare process: resolved binary, port, pre-compiled Worker JS content,
/// shim content, and asset origin. Camp resolves all paths before POSTing so
/// yubaba can restart without re-reading any workspace state (R374-F4).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PondDeployReq {
    pub ident: String,
    pub service: String,
    pub env: String,
    pub component_id: String,
    /// MinIO spec — yubaba brings this up before miniflare.
    pub minio: MinioSpec,
    /// Miniflare spec — yubaba spawns and supervises this after MinIO is ready.
    pub miniflare: MiniflareSpec,
    /// Optional SSR-runtime companion container (R434-F4). Present when the
    /// workload's `mesofact-static.ssr_runtime` field is `Some` and the mirror
    /// has any `mode:"ssr"` route. Yubaba brings this up between MinIO and
    /// miniflare so `MiniflareSpec.ssr_origin` can be overridden to point
    /// at the bound container before miniflare starts proxying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssr_runtime: Option<SsrRuntimeSpec>,
}

/// Per-workload phase reported by `GET /pond/state`.
///
/// - `Pending` covers `POST /pond/deploy` arrival → MinIO Ready + miniflare Ready.
/// - `Running` means yubaba's reconcilers last saw both MinIO and miniflare healthy.
/// - `Degraded` means a reconciler's last probe failed; restart-on-failure
///   is in flight.
/// - `Failed` is terminal — restarts exhausted, operator action required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PondPhase {
    Pending,
    Running,
    Degraded,
    Failed,
}

/// Outcome of a single HTTP probe on one slot surface.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ProbeOutcome {
    Pass,
    Fail { reason: String },
    Pending,
}

/// Per-slot liveness + readiness snapshot inside [`PondStateRecord`].
/// Each reconciler writes one entry after every probe tick.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlotProbe {
    /// Logical slot name: `"object_store"` | `"static"` | `"ssr_runtime"`.
    pub slot: String,
    /// HTTP GET on the slot's liveness path. Failure triggers a restart.
    pub liveness: ProbeOutcome,
    /// HTTP GET on the slot's readiness path. Failure is logged; no restart.
    pub readiness: ProbeOutcome,
    /// Unix seconds when this probe completed.
    pub last_checked_at: u64,
    /// URL that was probed (for operator inspection).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Serializable per-workload record returned by `GET /pond/state`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PondStateRecord {
    pub ident: String,
    pub service: String,
    pub env: String,
    pub component_id: String,
    pub phase: PondPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Unix epoch **milliseconds** when this workload entered the Running
    /// phase. `None` while Pending/Failed (nothing is serving yet). Feeds the
    /// Run-tab Live scoreboard's uptime column. `default` so older serialized
    /// records stay valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    /// Per-slot probe snapshot (R456-F1). Empty while deploy is Pending.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slots: Vec<SlotProbe>,
}

/// Response body for `POST /pond/deploy`.
pub type PondDeployResponse = PondStateRecord;
