use serde::{Deserialize, Serialize};
use workload_spec::Workload;

use crate::version::ProtocolVersion;

/// Stable identifier assigned by Yubaba when a workload is admitted.
///
/// Stable across Kamaji restarts: the supervisor reattaches to surviving
/// children by matching its persisted pidfile registry against this id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadId(pub String);

impl WorkloadId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Correlation token pairing a Yubaba request with the Kamaji response
/// that satisfies it. Opaque; Yubaba picks the value, Kamaji echoes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub u64);

/// Structured drain budget — see W154 §"Runtime parity contract" item 2.
///
/// Two windows, both wall-clock from drain start:
///
/// - `flush_ms` — time for the workload to finish in-flight requests and stop
///   accepting new work.
/// - `checkpoint_ms` — time for the workload to persist any restart-with-state
///   it cares about (snapshots, journal flushes, log rotation).
///
/// Kamaji runs a single combined timer (`flush_ms + checkpoint_ms`). If the
/// workload exits within that window the drain is reported as `Flushed` (if
/// elapsed ≤ `flush_ms`) or `Checkpointed` (between `flush_ms` and the total).
/// If the window elapses without an exit, Kamaji escalates to SIGKILL and
/// reports `ForceKilled`. See [`DrainOutcome`].
///
/// At the SIGTERM-only floor (T7), the workload sees one SIGTERM and has the
/// full window to exit; it distinguishes flush vs checkpoint by elapsed time.
/// Once the structured workload-control channel (R406-T11) ships, Kamaji
/// will deliver the budget envelope explicitly so workload-side code can
/// reason about which phase it is in without consulting the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainBudget {
    /// Time the workload may spend flushing in-flight work after acking drain.
    pub flush_ms: u32,
    /// Time the workload may spend persisting checkpoint state.
    pub checkpoint_ms: u32,
}

impl DrainBudget {
    /// Sum of `flush_ms + checkpoint_ms`, saturated at `u32::MAX`. This is the
    /// wall-clock window Kamaji waits on the workload before SIGKILL.
    pub fn total_ms(self) -> u32 {
        self.flush_ms.saturating_add(self.checkpoint_ms)
    }
}

/// Which budget window the workload exited in. Reported alongside
/// [`DrainOutcome::Flushed`] / [`DrainOutcome::Checkpointed`] so operators can
/// see whether a workload typically completes within its flush window or rides
/// into checkpoint — useful for tuning the budget per workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DrainPhase {
    /// Workload exited within `budget.flush_ms`.
    Flush,
    /// Workload exited between `flush_ms` and `flush_ms + checkpoint_ms`.
    Checkpoint,
}

/// Structured outcome of a Kamaji-driven drain procedure.
///
/// Returned by Kamaji's drain enforcer ([`crate`] consumer in
/// `app/yah/kamaji/src/drain.rs`) and surfaced on the wire either as
/// part of [`ConstableToWarden::DrainAck`]`.reason` (synchronous T7 shape)
/// or as a dedicated [`ConstableToWarden::DrainCompleted`] push (future
/// async shape once Kamaji has a push-channel to Yubaba).
///
/// `#[non_exhaustive]` so future variants (e.g. `WorkloadRefused` when a
/// structured-channel workload explicitly nacks drain) can land without
/// bumping the protocol version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DrainOutcome {
    /// Workload exited within the flush window. `elapsed_ms` is wall-clock
    /// from drain start to child reap; `exit` is the child's status.
    Flushed { exit: ExitStatus, elapsed_ms: u32 },
    /// Workload exited after flush_ms but within `flush_ms + checkpoint_ms`.
    Checkpointed { exit: ExitStatus, elapsed_ms: u32 },
    /// Budget elapsed; Kamaji issued SIGKILL. `elapsed_ms` includes the
    /// short tail between SIGKILL and the kernel marking the pidfd readable.
    ForceKilled { elapsed_ms: u32 },
    /// Workload is not in Kamaji's drainable registry — either it already
    /// exited and was reaped, or it was never registered.
    UnknownWorkload,
    /// This Kamaji build doesn't support drain (non-Linux target, no pidfd
    /// syscall surface). Reported so the operator sees an explicit reason
    /// instead of a silent no-op.
    Unsupported,
}

/// Exit status surfaced by `waitid(P_PIDFD, ...)` (native) or by containerd's
/// task state (container). Backend differences are hidden behind this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ExitStatus {
    /// Exited normally with the given status code.
    Exited(i32),
    /// Killed by signal.
    Signaled(i32),
    /// Killed by Kamaji enforcing the drain deadline.
    DrainTimeout,
}

/// Result of a single probe poll. Surface is uniform across HTTP-endpoint and
/// stdio-sentinel probe shapes — R406-T11 picks the wire detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProbeStatus {
    /// Workload is up and serving.
    Ready,
    /// Workload is alive but not yet ready.
    Starting,
    /// Workload reports itself unhealthy.
    Unhealthy { reason: String },
    /// Probe did not respond within the configured budget.
    Timeout,
}

/// Coarse-grained workload state Kamaji surfaces to Yubaba.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkloadState {
    /// Spec accepted but no process started yet.
    Pending,
    /// Process forked/containerd-task created, not yet probe-Ready.
    Starting,
    /// Probe-Ready and serving.
    Running,
    /// Drain in progress.
    Draining,
    /// Process exited cleanly.
    Exited,
    /// Process exited with failure (non-zero status or signal).
    Failed,
}

/// Compact snapshot of one workload — returned in
/// [`ConstableToWarden::WorkloadList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadEntry {
    pub id: WorkloadId,
    pub state: WorkloadState,
    /// OS pid of the workload's root process (native) or containerd task pid
    /// (container). Absent if not yet started or already reaped.
    pub pid: Option<u32>,
}

/// Discriminant for a generic [`ConstableToWarden::Ack`] — which request the
/// ack belongs to. Lets Yubaba's dispatch table key on request-kind without
/// re-parsing the original payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AckKind {
    Deploy,
    Stop,
    Probe,
}

/// Wire-level error codes. The accompanying `message` carries the concrete
/// reason; the code lets Yubaba's retry logic key on category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Request used a protocol version the receiver no longer supports.
    UnsupportedVersion,
    /// Workload id was not found in Kamaji's registry.
    UnknownWorkload,
    /// Workload spec failed validation at Kamaji.
    InvalidSpec,
    /// Backend (containerd RPC or a native syscall) refused the operation.
    BackendRefused,
    /// Internal error — Kamaji hit an unexpected condition.
    Internal,
}

/// Yubaba → Kamaji message variants.
///
/// `#[non_exhaustive]` lets us add new request kinds without bumping the
/// protocol version, as long as the existing variants keep their shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WardenToConstable {
    /// Connection greeting — exchanged once per UDS connection.
    Hello { version: ProtocolVersion },
    /// Deploy a workload. Backend (native vs container) is selected by `spec`.
    Deploy {
        request_id: RequestId,
        id: WorkloadId,
        spec: Workload,
    },
    /// Stop a workload — SIGTERM-with-grace floor; backend hides specifics.
    Stop {
        request_id: RequestId,
        id: WorkloadId,
    },
    /// Structured drain with a deadline budget.
    Drain {
        request_id: RequestId,
        id: WorkloadId,
        budget: DrainBudget,
    },
    /// Poll the current probe status for one workload.
    Probe {
        request_id: RequestId,
        id: WorkloadId,
    },
    /// List every workload Kamaji is currently supervising.
    List { request_id: RequestId },
}

/// Kamaji → Yubaba message variants.
///
/// A mix of request-responses (correlated by [`RequestId`]) and pushed
/// lifecycle events (no request id — Kamaji surfaces them spontaneously).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConstableToWarden {
    /// Response to [`WardenToConstable::Hello`].
    Welcome {
        version: ProtocolVersion,
        /// Build version of the Kamaji peer (for operator visibility).
        constable_version: String,
    },
    /// Generic ack to a request.
    Ack {
        request_id: RequestId,
        kind: AckKind,
    },
    /// Generic error. `request_id` is `None` for errors not tied to a request
    /// (e.g. malformed frame).
    Error {
        request_id: Option<RequestId>,
        code: ErrorCode,
        message: String,
    },
    /// Push: a workload's root process started.
    WorkloadStarted { id: WorkloadId, pid: u32 },
    /// Push: a workload's root process exited.
    WorkloadExited { id: WorkloadId, exit: ExitStatus },
    /// Response to [`WardenToConstable::Probe`].
    ProbeResult {
        request_id: RequestId,
        id: WorkloadId,
        status: ProbeStatus,
    },
    /// Response to [`WardenToConstable::Drain`].
    ///
    /// Two semantic modes — both are valid V1 wire shapes; Kamaji picks
    /// based on whether it has a push channel back to Yubaba:
    ///
    /// 1. **Synchronous (R406-T7 default).** Kamaji runs the drain
    ///    procedure to completion inside the request handler. `accepted=true`
    ///    means the workload exited cleanly within the [`DrainBudget`]
    ///    window; `accepted=false` means SIGKILL escalation, unknown
    ///    workload, or platform-unsupported. `reason` is the human-readable
    ///    summary of the underlying [`DrainOutcome`].
    /// 2. **Asynchronous (future, T8 push-channel).** Kamaji replies
    ///    immediately with `accepted=true, reason=Some("started, budget=…")`
    ///    and later pushes the structured outcome via [`Self::DrainCompleted`].
    ///
    /// Yubaba disambiguates the modes by feature-detecting `DrainCompleted`
    /// support at handshake time (future protocol-version negotiation).
    DrainAck {
        request_id: RequestId,
        id: WorkloadId,
        accepted: bool,
        reason: Option<String>,
    },
    /// Push: structured drain outcome for a workload Kamaji previously
    /// acknowledged as "drain started" (asynchronous mode). Carries the same
    /// [`DrainOutcome`] that synchronous mode encodes in
    /// [`Self::DrainAck`]`.reason`, but typed. Wired once Kamaji grows a
    /// Yubaba-bound push channel (R406-T8).
    DrainCompleted {
        request_id: RequestId,
        id: WorkloadId,
        outcome: DrainOutcome,
    },
    /// Response to [`WardenToConstable::List`].
    WorkloadList {
        request_id: RequestId,
        entries: Vec<WorkloadEntry>,
    },
}
