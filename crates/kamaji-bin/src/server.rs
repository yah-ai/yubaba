//! @yah:ticket(R426-F3, "Kamaji scope + ownership-list check; canonical 401/403 + WWW-Authenticate bodies")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T22:46:00Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R426)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426-F2)
//! @yah:handoff("Landed W159 Layer 2 (scope + ownership-list) and the canonical 401/403 wire shapes. New modules: `kamaji::auth::policy` (Requirement + enforce) and `kamaji::auth::deny` (Deny + From<VerifyError> + serialization). Both match W159 §Failure responses byte-for-byte — the 401 example and the 403 example in the doc are direct asserts in the test suite. Scope check exact-match per composition rule 3 (no `<category>:admin` implication tree); scopes-first, owns-second so a missing scope is reported even when the token also lacks the resource.")
//! @yah:handoff("Wire shapes: 401 Unauthorized for any token-side rejection (Malformed/MissingKid/UnknownKid/SignatureMismatch/Expired/BadIssuer/BadAudience/BadClaims all map to `Deny::invalid_token` with operator-curated short reasons — NOT raw error strings, to avoid aiding forgery probing). 403 Forbidden for scope/owns failures from policy::enforce. JSON body always carries `error` + optional `scope` + optional `resource` only — no `error_description` in body (W159: finer-grained reasons stay in the local audit journal). WWW-Authenticate is single-line (RFC 7230 deprecates obs-fold) with parameters in canonical order: realm, error, error_description?, scope?, resource_metadata.")
//! @yah:handoff("Helper: `AuthConfig::resource_metadata_url()` derives `{expected_aud}/.well-known/oauth-protected-resource` for use as the WWW-Authenticate `resource_metadata` parameter. F4 ticket lands the matching endpoint.")
//! @yah:handoff("Out of F3 scope (→ follow-on): the HTTPS server / JSON-RPC dispatch loop that actually invokes verify() then enforce() and serializes a Deny onto the wire. F3 lands data shapes + pure-function logic; the request handler that calls them is a later integration ticket.")
//! @yah:next("Sign-off: review `kamaji::auth::{policy,deny}` shape + run `cargo test -p kamaji --lib auth` (expect 39 auth-module passes, 127 total kamaji lib passes). Confirm the 401/403 examples in W159 §Failure responses match what `Deny::www_authenticate` + `Deny::json_body` emit byte-for-byte.")
//! @yah:verify("cargo test -p kamaji --lib auth")
//!
//! @yah:ticket(R426-F4, "Kamaji /.well-known/oauth-protected-resource endpoint")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T22:46:01Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R426)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426-F1)
//! @yah:handoff("Landed the RFC 9728 protected-resource metadata shape as `kamaji::auth::metadata`. `ProtectedResourceMetadata` carries `resource` / `authorization_servers` / `scopes_supported` / `bearer_methods_supported`. `from_config(&AuthConfig)` derives `resource` from `expected_aud`, `authorization_servers` from `cheers_issuer` (both trim trailing slashes), publishes the full `SCOPE_VOCABULARY` const, and pins `bearer_methods_supported = [\"header\"]` (we only accept `Authorization: Bearer`, never query/form).")
//! @yah:handoff("SCOPE_VOCABULARY exported as a const &[&str] — the canonical W159 §Scope vocabulary list, 16 entries including the two service-only scopes (`ownership:write`, `audit:write`). RFC 9728 §`scopes_supported` is \"every scope the resource accepts\", which includes service-only scopes since yubaba + kamaji themselves present them at the wire — cheers's grant API is what gates them from user principals at issuance time, not kamaji's verifier.")
//! @yah:handoff("Out of F4 scope (→ follow-on integration ticket): the actual HTTPS route handler that mounts `to_json()` at `/.well-known/oauth-protected-resource`. F4 ships the data shape + serializer ready to drop into whatever HTTP framework the dispatch loop lands on (axum/hyper). `AuthConfig::resource_metadata_url()` (from F3) and this module compose: the WWW-Authenticate header points at the URL this endpoint serves.")
//! @yah:handoff("6 new unit tests green (full-vocab publish, trailing-slash trim, custom-scope override, JSON round-trip, RFC 9728 field-name presence, service-only scope advertisement). Total kamaji lib: 133 tests.")
//! @yah:next("Sign-off: review `kamaji::auth::metadata` shape + run `cargo test -p kamaji --lib auth::metadata` (expect 6 passes). Confirm `SCOPE_VOCABULARY` matches the W159 §Scope vocabulary list including the service-only scopes.")
//! @yah:verify("cargo test -p kamaji --lib auth::metadata")

use std::collections::HashMap;
use std::future::Future;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;

use anyhow::{Context, Result};
use kamaji_proto::{
    decode_frame, encode_frame, ConstableToWarden, DrainOutcome, Error as CodecError, ErrorCode,
    ProtocolVersion, WardenToConstable, WorkloadEntry, WorkloadId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::drain;
use crate::journal::{JournalSender, LogSink};
use crate::probe::{run_probe, ProbeTarget};

/// Build version reported in [`ConstableToWarden::Welcome`].
pub const CONSTABLE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Per-workload state Kamaji needs to drive a structured drain (R406-T7).
///
/// `pidfd` is the only field that must transfer ownership into the drain
/// enforcer — `pid` is kept for tracing and for the `WorkloadEntry.pid` field
/// surfaced via [`ConstableToWarden::WorkloadList`].
pub struct DrainableHandle {
    pub pid: u32,
    pub pidfd: OwnedFd,
}

/// In-memory workload registry.
///
/// Holds:
///
/// - `workloads`: a snapshot list returned verbatim by `List` RPCs (one entry
///   per workload Kamaji is supervising).
/// - `drainable`: per-workload [`DrainableHandle`] containing the pidfd needed
///   to send signals and observe exit. Populated by the deploy path (lands
///   under R406-T8 when Kamaji starts owning workload lifecycle end-to-end)
///   and consumed by the Drain RPC handler. Tests poke entries in directly.
///
/// Held behind a [`tokio::sync::Mutex`] so the dispatch loop can read it
/// without parking the runtime thread.
#[derive(Default)]
pub struct Registry {
    workloads: Vec<WorkloadEntry>,
    drainable: HashMap<WorkloadId, DrainableHandle>,
    /// Per-workload probe configuration, keyed by workload id. Populated by
    /// the deploy path at admission time; consumed by the Probe RPC handler
    /// (R406-T11). Workloads whose spec carries no `healthcheck` field are
    /// absent here, which the Probe handler maps to [`ProbeStatus::Ready`] —
    /// i.e. "no probe declared ↔ trust the workload's existence".
    probes: HashMap<WorkloadId, ProbeTarget>,
}

/// Per-Kamaji runtime context handed to [`handle_message`] (R406-T9).
///
/// Bundles the in-memory registry (shared via mutex) with the optional
/// containerd backend. The backend lives outside the mutex so a slow
/// containerd RPC doesn't park the dispatch loop — the gRPC client is
/// internally synchronized.
pub struct ServerCtx {
    pub registry: Arc<Mutex<Registry>>,
    /// Shared log sink for both backends (R406-T10). On a Linux host with
    /// journald reachable this is a [`JournalSender`] writing the journald
    /// datagram protocol; otherwise it re-emits via `tracing`. Backends
    /// clone this Arc when they spawn per-workload forwarder tasks.
    pub log_sink: Arc<dyn LogSink>,
    /// Optional containerd backend. `None` outside the
    /// `containerd-integration` feature build, or when kamaji is started
    /// without `--containerd-socket`. When `None`, Deploy { Container }
    /// returns a clear "no containerd backend configured" error instead of
    /// the legacy "not implemented" message.
    #[cfg(feature = "containerd-integration")]
    pub containerd: Option<Arc<crate::containerd::ContainerdBackend>>,
}

impl ServerCtx {
    /// Build a context with no containerd backend. Suitable for tests and
    /// pond-tier kamaji instances. The default log sink is a
    /// [`JournalSender`] that gracefully falls back to `tracing` when no
    /// journald is reachable.
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Mutex::new(Registry::new())),
            log_sink: Arc::new(JournalSender::connect()),
            #[cfg(feature = "containerd-integration")]
            containerd: None,
        }
    }

    /// Build a context with the given registry handle — lets tests pre-seed
    /// the registry before dispatch.
    pub fn with_registry(registry: Arc<Mutex<Registry>>) -> Self {
        Self {
            registry,
            log_sink: Arc::new(JournalSender::connect()),
            #[cfg(feature = "containerd-integration")]
            containerd: None,
        }
    }

    /// Override the log sink. Tests use this to capture forwarded lines
    /// without hitting journald; the production binary uses the
    /// [`JournalSender::connect`] default established in [`new`].
    pub fn with_log_sink(mut self, sink: Arc<dyn LogSink>) -> Self {
        self.log_sink = sink;
        self
    }

    /// Attach a containerd backend. Only available with the
    /// `containerd-integration` feature.
    #[cfg(feature = "containerd-integration")]
    pub fn with_containerd(
        mut self,
        backend: Arc<crate::containerd::ContainerdBackend>,
    ) -> Self {
        self.containerd = Some(backend);
        self
    }
}

impl Default for ServerCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn list(&self) -> Vec<WorkloadEntry> {
        self.workloads.clone()
    }

    /// Add a drainable handle for `id`. Replaces any prior entry — the caller
    /// owns the invariant that ids are unique per Kamaji lifetime.
    pub fn insert_drainable(&mut self, id: WorkloadId, handle: DrainableHandle) {
        self.drainable.insert(id, handle);
    }

    /// Remove and return the [`DrainableHandle`] for `id`, if any. Called from
    /// the Drain RPC dispatch — once removed, no further drain or list RPC
    /// observes this workload as drainable.
    pub fn take_drainable(&mut self, id: &WorkloadId) -> Option<DrainableHandle> {
        self.drainable.remove(id)
    }

    /// Register the probe target for `id`. Called by the deploy path once the
    /// workload's network endpoint is known (native: loopback + spec port;
    /// container: containerd bridge address). Replaces any prior entry —
    /// re-deploying a workload re-binds its probe target atomically.
    pub fn insert_probe(&mut self, id: WorkloadId, target: ProbeTarget) {
        self.probes.insert(id, target);
    }

    /// Look up the probe target for `id`, cloned so the dispatch loop can
    /// release the registry mutex before the (possibly slow) probe runs.
    pub fn probe_target(&self, id: &WorkloadId) -> Option<ProbeTarget> {
        self.probes.get(id).cloned()
    }

    /// Drop the probe target for `id` — called when the workload is torn down.
    pub fn remove_probe(&mut self, id: &WorkloadId) -> Option<ProbeTarget> {
        self.probes.remove(id)
    }
}

/// Bind the UDS, accept connections, dispatch frames until ctrl-c.
pub async fn serve(socket: &Path) -> Result<()> {
    serve_with_shutdown(socket, shutdown_signal()).await
}

/// Variant of [`serve`] that takes an explicit shutdown future — used by
/// integration tests so they don't have to send a real SIGINT. Builds a
/// fresh [`ServerCtx`] with no backend; for a backend-equipped instance use
/// [`serve_with_ctx`].
pub async fn serve_with_shutdown<F>(socket: &Path, shutdown: F) -> Result<()>
where
    F: Future<Output = ()>,
{
    serve_with_ctx(socket, Arc::new(ServerCtx::new()), shutdown).await
}

/// Variant of [`serve_with_shutdown`] that takes a caller-built
/// [`ServerCtx`] — needed by `app/yah/kamaji/src/main.rs` so the
/// production binary can attach the containerd backend (R406-T9) before
/// the listener starts accepting connections.
pub async fn serve_with_ctx<F>(
    socket: &Path,
    ctx: Arc<ServerCtx>,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    let listener = bind_listener(socket)
        .with_context(|| format!("bind UDS at {}", socket.display()))?;
    info!(path = %socket.display(), "kamaji UDS listening");

    let mut shutdown = pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received; stopping accept loop");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let ctx = Arc::clone(&ctx);
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(stream, ctx).await {
                                warn!(error = %e, "connection handler error");
                            }
                        });
                    }
                    Err(e) => warn!(error = %e, "accept failed"),
                }
            }
        }
    }

    let _ = tokio::fs::remove_file(socket).await;
    Ok(())
}

fn bind_listener(socket: &Path) -> Result<UnixListener> {
    if let Some(parent) = socket.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir {}", parent.display()))?;
        }
    }
    // Clear any stale socket file left behind by a previous run. UnixListener::bind
    // refuses to overwrite an existing inode.
    if socket.exists() {
        std::fs::remove_file(socket)
            .with_context(|| format!("remove stale socket {}", socket.display()))?;
    }
    UnixListener::bind(socket).map_err(Into::into)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn handle_conn(stream: UnixStream, ctx: Arc<ServerCtx>) -> Result<()> {
    let (mut rd, mut wr) = stream.into_split();
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    loop {
        // Drain every complete frame currently in `buf` before issuing another read.
        loop {
            match decode_frame::<WardenToConstable>(&buf) {
                Ok((msg, consumed)) => {
                    let reply = handle_message(msg, &ctx).await;
                    let frame = encode_frame(&reply).context("encode reply")?;
                    wr.write_all(&frame).await.context("write reply")?;
                    buf.drain(..consumed);
                }
                Err(CodecError::Truncated { .. }) => break,
                Err(e) => {
                    let err_reply = ConstableToWarden::Error {
                        request_id: None,
                        code: ErrorCode::Internal,
                        message: format!("decode failed: {e}"),
                    };
                    if let Ok(frame) = encode_frame(&err_reply) {
                        let _ = wr.write_all(&frame).await;
                    }
                    return Err(anyhow::anyhow!("decode failed: {e}"));
                }
            }
        }

        let n = rd.read(&mut tmp).await.context("read from peer")?;
        if n == 0 {
            debug!("peer closed");
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Dispatch one decoded message. Visible for unit testing.
///
/// R406-T9: when `ctx.containerd` is `Some`, Deploy { Container } and Stop
/// dispatch through the containerd backend; List merges the backend's
/// containers with the in-memory registry. When no backend is configured,
/// Deploy/Stop return a clear `BackendRefused` rather than silently
/// succeeding — operators see exactly why the dispatch path is missing.
pub async fn handle_message(
    msg: WardenToConstable,
    ctx: &Arc<ServerCtx>,
) -> ConstableToWarden {
    match msg {
        WardenToConstable::Hello { version } => {
            if version != ProtocolVersion::CURRENT {
                return ConstableToWarden::Error {
                    request_id: None,
                    code: ErrorCode::UnsupportedVersion,
                    message: format!("unsupported wire version: {version:?}"),
                };
            }
            ConstableToWarden::Welcome {
                version: ProtocolVersion::CURRENT,
                constable_version: CONSTABLE_VERSION.to_string(),
            }
        }
        WardenToConstable::List { request_id } => {
            // Start with the in-memory registry entries (native workloads).
            #[allow(unused_mut)]
            let mut entries = ctx.registry.lock().await.list();

            // Merge containerd containers when the backend is configured.
            #[cfg(feature = "containerd-integration")]
            if let Some(backend) = &ctx.containerd {
                match backend.list().await {
                    Ok(ctr_entries) => entries.extend(ctr_entries),
                    Err(e) => {
                        return ConstableToWarden::Error {
                            request_id: Some(request_id),
                            code: ErrorCode::BackendRefused,
                            message: format!("containerd list failed: {e}"),
                        };
                    }
                }
            }

            ConstableToWarden::WorkloadList {
                request_id,
                entries,
            }
        }
        WardenToConstable::Drain {
            request_id,
            id,
            budget,
        } => {
            // Pull the workload's pidfd out of the registry. None means either
            // the workload never registered or it was already drained — either
            // way Yubaba gets DrainAck { accepted=false, reason="unknown" }.
            let handle = ctx.registry.lock().await.take_drainable(&id);
            let Some(handle) = handle else {
                return ConstableToWarden::DrainAck {
                    request_id,
                    id,
                    accepted: false,
                    reason: Some("unknown workload".to_string()),
                };
            };

            // Synchronous-mode T7 (see DrainAck rustdoc): run the structured
            // drain to completion here, then reply with DrainAck reflecting
            // the outcome. The async-push form using DrainCompleted lands once
            // R406-T8 gives Kamaji a back-channel to Yubaba.
            let outcome =
                drain::enforce_drain(id.clone(), handle.pidfd, budget).await;
            let (accepted, reason) = drain_outcome_to_ack(outcome);
            ConstableToWarden::DrainAck {
                request_id,
                id,
                accepted,
                reason,
            }
        }
        WardenToConstable::Deploy {
            request_id,
            id,
            spec,
        } => deploy_workload(ctx, request_id, id, spec).await,
        WardenToConstable::Stop { request_id, id } => stop_workload(ctx, request_id, id).await,
        WardenToConstable::Probe { request_id, id } => {
            // Clone the target so we don't hold the registry mutex across the
            // probe's network/exec wait. A workload teardown that races with
            // this probe just means we return ProbeResult for a workload
            // Yubaba's already decided to drop — harmless.
            let target = ctx.registry.lock().await.probe_target(&id);
            let status = run_probe(target.as_ref()).await;
            ConstableToWarden::ProbeResult {
                request_id,
                id,
                status,
            }
        }
        // The Yubaba→Kamaji enum is #[non_exhaustive]; reject any variant
        // we don't yet understand instead of relying on the match being total.
        _ => ConstableToWarden::Error {
            request_id: None,
            code: ErrorCode::Internal,
            message: "unhandled message kind".to_string(),
        },
    }
}

/// Dispatch a `Deploy { id, spec }` to the right backend. R406-T9 wires
/// `Workload::Container` to the containerd backend; non-container variants
/// (MesofactStatic, Almanac) are yubaba's responsibility (mesofact-static
/// reconciler / almanac runner) and surface as `InvalidSpec` if they reach
/// Kamaji.
#[allow(unused_variables)]
async fn deploy_workload(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: WorkloadId,
    spec: workload_spec::Workload,
) -> ConstableToWarden {
    match spec {
        workload_spec::Workload::Container(spec) => {
            #[cfg(feature = "containerd-integration")]
            {
                let Some(backend) = ctx.containerd.clone() else {
                    return ConstableToWarden::Error {
                        request_id: Some(request_id),
                        code: ErrorCode::BackendRefused,
                        message: "no containerd backend configured — \
                                  rebuild kamaji with --features containerd-integration \
                                  and start with --containerd-socket"
                            .to_string(),
                    };
                };
                match backend.deploy(&id, &spec).await {
                    Ok(_pid) => ConstableToWarden::Ack {
                        request_id,
                        kind: kamaji_proto::AckKind::Deploy,
                    },
                    Err(crate::containerd::BackendError::InvalidSpec(msg)) => {
                        ConstableToWarden::Error {
                            request_id: Some(request_id),
                            code: ErrorCode::InvalidSpec,
                            message: msg,
                        }
                    }
                    Err(crate::containerd::BackendError::Containerd(e)) => {
                        ConstableToWarden::Error {
                            request_id: Some(request_id),
                            code: ErrorCode::BackendRefused,
                            message: format!("containerd: {e:#}"),
                        }
                    }
                }
            }
            #[cfg(not(feature = "containerd-integration"))]
            {
                let _ = (ctx, spec);
                ConstableToWarden::Error {
                    request_id: Some(request_id),
                    code: ErrorCode::BackendRefused,
                    message: "kamaji built without containerd-integration feature; \
                              Container workloads cannot be deployed"
                        .to_string(),
                }
            }
        }
        workload_spec::Workload::MesofactStatic(_)
        | workload_spec::Workload::Almanac(_)
        | workload_spec::Workload::StaticAsset(_) => ConstableToWarden::Error {
            request_id: Some(request_id),
            code: ErrorCode::InvalidSpec,
            message: "kamaji only dispatches Workload::Container; \
                      mesofact-static, almanac, and static-asset live in yubaba's reconcilers"
                .to_string(),
        },
    }
}

/// Dispatch a `Stop { id }` to the right backend. With the containerd
/// backend configured the workload is torn down via containerd's
/// kill+delete; without a backend (or for a workload Kamaji doesn't know
/// about) we return `Ack` regardless — Stop is idempotent and the absence
/// of the workload satisfies the requested end-state.
#[allow(unused_variables)]
async fn stop_workload(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: WorkloadId,
) -> ConstableToWarden {
    #[cfg(feature = "containerd-integration")]
    if let Some(backend) = ctx.containerd.clone() {
        if let Err(e) = backend.teardown(&id).await {
            return ConstableToWarden::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("containerd teardown: {e}"),
            };
        }
    }
    ConstableToWarden::Ack {
        request_id,
        kind: kamaji_proto::AckKind::Stop,
    }
}

/// Translate a [`DrainOutcome`] from the enforcer into the
/// `(accepted, reason)` pair we return in [`ConstableToWarden::DrainAck`].
///
/// Semantics (synchronous T7 shape — see [`ConstableToWarden::DrainAck`]
/// rustdoc):
///
/// - `Flushed` / `Checkpointed` → `accepted=true`, reason carries the phase
///   and elapsed time so operators can spot workloads riding into checkpoint.
/// - `ForceKilled` → `accepted=false`, reason notes the SIGKILL escalation.
/// - `UnknownWorkload` → `accepted=false`, reason says "unknown workload".
///   (The Drain handler short-circuits this case before calling the enforcer,
///   but the helper handles it anyway for total-function semantics.)
/// - `Unsupported` → `accepted=false`, reason says drain is not available on
///   this Kamaji build.
/// - `Err(DrainError)` → `accepted=false`, reason carries the syscall error.
fn drain_outcome_to_ack(
    outcome: Result<DrainOutcome, drain::DrainError>,
) -> (bool, Option<String>) {
    match outcome {
        Ok(DrainOutcome::Flushed { exit, elapsed_ms }) => (
            true,
            Some(format!("flushed in {elapsed_ms}ms (exit={exit:?})")),
        ),
        Ok(DrainOutcome::Checkpointed { exit, elapsed_ms }) => (
            true,
            Some(format!("checkpointed in {elapsed_ms}ms (exit={exit:?})")),
        ),
        Ok(DrainOutcome::ForceKilled { elapsed_ms }) => (
            false,
            Some(format!(
                "force-killed after {elapsed_ms}ms — workload missed budget"
            )),
        ),
        Ok(DrainOutcome::UnknownWorkload) => {
            (false, Some("unknown workload".to_string()))
        }
        Ok(DrainOutcome::Unsupported) => (
            false,
            Some("drain not supported on this Kamaji build (non-Linux)".to_string()),
        ),
        // `DrainOutcome` is `#[non_exhaustive]` — future variants land in
        // kamaji-proto without a wire-version bump. Surface unknown
        // outcomes as not-accepted so a forward-version Kamaji replying
        // to an older Yubaba doesn't silently misreport success.
        Ok(other) => (
            false,
            Some(format!("unrecognised DrainOutcome variant: {other:?}")),
        ),
        Err(e) => (false, Some(format!("drain failed: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamaji_proto::{AckKind, DrainBudget, ExitStatus, RequestId, WorkloadId};

    #[tokio::test]
    async fn hello_with_current_version_returns_welcome() {
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            WardenToConstable::Hello {
                version: ProtocolVersion::CURRENT,
            },
            &ctx,
        )
        .await;
        match reply {
            ConstableToWarden::Welcome {
                version,
                constable_version,
            } => {
                assert_eq!(version, ProtocolVersion::CURRENT);
                assert_eq!(constable_version, CONSTABLE_VERSION);
            }
            other => panic!("expected Welcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_on_empty_registry_returns_empty_entries() {
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            WardenToConstable::List {
                request_id: RequestId(7),
            },
            &ctx,
        )
        .await;
        match reply {
            ConstableToWarden::WorkloadList {
                request_id,
                entries,
            } => {
                assert_eq!(request_id, RequestId(7));
                assert!(entries.is_empty());
            }
            other => panic!("expected WorkloadList, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stop_without_backend_acks_for_idempotency() {
        // R406-T9: stop is idempotent — without a backend (no containerd
        // attached), the absence of the workload satisfies the requested
        // end-state, so we reply with Ack rather than a contrived error.
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            WardenToConstable::Stop {
                request_id: RequestId(1),
                id: WorkloadId::new("w-1"),
            },
            &ctx,
        )
        .await;
        match reply {
            ConstableToWarden::Ack { request_id, kind } => {
                assert_eq!(request_id, RequestId(1));
                assert_eq!(kind, AckKind::Stop);
            }
            other => panic!("expected Ack, got {other:?}"),
        }
    }

    // AckKind is re-exported for the eventual ack path; touch it so unused-import
    // lint doesn't trip when handlers don't ack yet.
    #[test]
    fn ack_kind_is_addressable() {
        let _ = AckKind::Deploy;
    }

    // ── R406-T9: deploy dispatch ─────────────────────────────────────────────

    /// MesofactStatic / Almanac workloads are not kamaji's concern — they
    /// belong to yubaba's reconcilers. Kamaji rejects them with InvalidSpec
    /// so yubaba surfaces the misroute clearly instead of silently dropping.
    #[tokio::test]
    async fn deploy_mesofact_static_is_rejected_as_invalid_spec() {
        use workload_spec::{
            BuildConfig, BuildMode, MesofactStaticWorkload, SchemaVersion, Workload,
        };
        let ctx = Arc::new(ServerCtx::new());
        let workload = Workload::MesofactStatic(MesofactStaticWorkload {
            schema_version: SchemaVersion::V1,
            build: BuildConfig {
                command: "bun run build".into(),
                out_dir: std::path::PathBuf::from("dist"),
            },
            routes: std::path::PathBuf::from("routes.ts"),
            build_mode: BuildMode::HostSide,
            ssr_runtime: None,
        });
        let reply = handle_message(
            WardenToConstable::Deploy {
                request_id: RequestId(11),
                id: WorkloadId::new("static-site"),
                spec: workload,
            },
            &ctx,
        )
        .await;
        match reply {
            ConstableToWarden::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(11)));
                assert_eq!(code, ErrorCode::InvalidSpec);
                assert!(
                    message.contains("mesofact-static") || message.contains("yubaba"),
                    "got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Without the containerd-integration feature, Deploy { Container } must
    /// surface a clear "feature not built in" error rather than the old
    /// "not implemented (R406-T4..T6/T11)" stub. R406-T11 tracks probe.
    #[cfg(not(feature = "containerd-integration"))]
    #[tokio::test]
    async fn deploy_container_without_feature_says_so() {
        let ctx = Arc::new(ServerCtx::new());
        let spec = workload_spec::Workload::Container(make_minimal_container_spec("svc"));
        let reply = handle_message(
            WardenToConstable::Deploy {
                request_id: RequestId(12),
                id: WorkloadId::new("svc"),
                spec,
            },
            &ctx,
        )
        .await;
        match reply {
            ConstableToWarden::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(12)));
                assert_eq!(code, ErrorCode::BackendRefused);
                assert!(
                    message.contains("containerd-integration"),
                    "got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// With the containerd-integration feature but no backend attached to
    /// ServerCtx, Deploy { Container } returns BackendRefused with a hint at
    /// the missing config.
    #[cfg(feature = "containerd-integration")]
    #[tokio::test]
    async fn deploy_container_without_attached_backend_says_so() {
        let ctx = Arc::new(ServerCtx::new());
        let spec = workload_spec::Workload::Container(make_minimal_container_spec("svc"));
        let reply = handle_message(
            WardenToConstable::Deploy {
                request_id: RequestId(12),
                id: WorkloadId::new("svc"),
                spec,
            },
            &ctx,
        )
        .await;
        match reply {
            ConstableToWarden::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(12)));
                assert_eq!(code, ErrorCode::BackendRefused);
                assert!(
                    message.contains("--containerd-socket"),
                    "got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    fn make_minimal_container_spec(name: &str) -> workload_spec::WorkloadSpec {
        use workload_spec::{
            EnvValue, ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis,
            ResourceLimits, RestartPolicy, SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
        };
        let _ = EnvValue::Literal { value: "x".into() };
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.into(),
            image: ImageRef {
                registry: "ghcr.io".into(),
                repository: "x/y".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".into()),
            replicas: 1,
            command: Some(vec!["/bin/svc".into()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 64,
                cpu_shares: 128,
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name.into()),
                    ports: vec![],
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        }
    }

    // ── R406-T7: drain handler ───────────────────────────────────────────────

    #[tokio::test]
    async fn drain_unknown_workload_returns_drain_ack_with_accepted_false() {
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            WardenToConstable::Drain {
                request_id: RequestId(42),
                id: WorkloadId::new("never-registered"),
                budget: DrainBudget {
                    flush_ms: 100,
                    checkpoint_ms: 100,
                },
            },
            &ctx,
        )
        .await;
        match reply {
            ConstableToWarden::DrainAck {
                request_id,
                id,
                accepted,
                reason,
            } => {
                assert_eq!(request_id, RequestId(42));
                assert_eq!(id, WorkloadId::new("never-registered"));
                assert!(!accepted, "unknown workload must not be accepted");
                let reason = reason.expect("reason should be populated");
                assert!(
                    reason.contains("unknown"),
                    "reason should mention 'unknown', got: {reason}",
                );
            }
            other => panic!("expected DrainAck, got {other:?}"),
        }
    }

    #[test]
    fn drain_outcome_flushed_becomes_accepted_ack_with_summary() {
        let (accepted, reason) =
            super::drain_outcome_to_ack(Ok(DrainOutcome::Flushed {
                exit: ExitStatus::Exited(0),
                elapsed_ms: 250,
            }));
        assert!(accepted);
        let r = reason.expect("reason populated");
        assert!(r.contains("flushed"), "reason: {r}");
        assert!(r.contains("250"), "reason should carry elapsed_ms: {r}");
    }

    #[test]
    fn drain_outcome_checkpointed_is_accepted_with_checkpointed_label() {
        let (accepted, reason) =
            super::drain_outcome_to_ack(Ok(DrainOutcome::Checkpointed {
                exit: ExitStatus::Signaled(15),
                elapsed_ms: 5_800,
            }));
        assert!(accepted);
        let r = reason.expect("reason populated");
        assert!(r.contains("checkpointed"), "reason: {r}");
    }

    #[test]
    fn drain_outcome_force_killed_is_not_accepted() {
        let (accepted, reason) =
            super::drain_outcome_to_ack(Ok(DrainOutcome::ForceKilled {
                elapsed_ms: 6_100,
            }));
        assert!(!accepted, "force-kill must surface as accepted=false");
        let r = reason.expect("reason populated");
        assert!(r.contains("force-killed"), "reason: {r}");
        assert!(r.contains("6100"), "reason should carry elapsed_ms: {r}");
    }

    #[test]
    fn drain_outcome_unknown_workload_translates_cleanly() {
        let (accepted, reason) =
            super::drain_outcome_to_ack(Ok(DrainOutcome::UnknownWorkload));
        assert!(!accepted);
        assert!(reason.expect("reason populated").contains("unknown"));
    }

    #[test]
    fn drain_outcome_unsupported_is_not_accepted() {
        let (accepted, reason) =
            super::drain_outcome_to_ack(Ok(DrainOutcome::Unsupported));
        assert!(!accepted);
        let r = reason.expect("reason populated");
        assert!(r.contains("non-Linux") || r.contains("not supported"), "{r}");
    }

    #[test]
    fn drain_outcome_error_carries_message() {
        // SIGTERM = 15 (POSIX). Avoids the libc dep on the cross-platform
        // test compile (libc is Linux-only in this crate's Cargo.toml).
        let err = drain::DrainError::Signal {
            signal: 15,
            source: std::io::Error::other("synthetic"),
        };
        let (accepted, reason) = super::drain_outcome_to_ack(Err(err));
        assert!(!accepted);
        let r = reason.expect("reason populated");
        assert!(r.contains("drain failed"), "{r}");
    }

    // ── R406-T11: probe RPC ──────────────────────────────────────────────────

    /// Probe of an unregistered workload returns Ready — the "no probe spec
    /// declared" convention. Probe-target absence ↔ Ready makes Yubaba's
    /// admission logic uniform: every Probe answer is wire-typed, never an
    /// error.
    #[tokio::test]
    async fn probe_unregistered_workload_returns_ready() {
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            WardenToConstable::Probe {
                request_id: RequestId(91),
                id: WorkloadId::new("no-probe-registered"),
            },
            &ctx,
        )
        .await;
        match reply {
            ConstableToWarden::ProbeResult {
                request_id,
                id,
                status,
            } => {
                assert_eq!(request_id, RequestId(91));
                assert_eq!(id, WorkloadId::new("no-probe-registered"));
                assert!(
                    matches!(status, kamaji_proto::ProbeStatus::Ready),
                    "expected Ready for absent probe target, got {status:?}",
                );
            }
            other => panic!("expected ProbeResult, got {other:?}"),
        }
    }

    /// Probe of a workload whose registered TcpConnect target points at an
    /// accepting listener returns Ready. Ties the registry → probe runner →
    /// wire shape together end-to-end inside the dispatcher.
    #[tokio::test]
    async fn probe_registered_tcp_connect_target_returns_ready() {
        use crate::probe::ProbeTarget;
        use std::net::{Ipv4Addr, SocketAddr};
        use tokio::net::TcpListener;
        use workload_spec::{HealthProbe, Healthcheck, Millis};

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        let ctx = Arc::new(ServerCtx::new());
        ctx.registry.lock().await.insert_probe(
            WorkloadId::new("svc-1"),
            ProbeTarget {
                healthcheck: Healthcheck {
                    probe: HealthProbe::TcpConnect { port },
                    interval: Millis::from_ms(1000),
                    timeout: Millis::from_ms(500),
                    initial_delay: Millis::from_ms(0),
                    failure_threshold: 3,
                },
                addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            },
        );

        let reply = handle_message(
            WardenToConstable::Probe {
                request_id: RequestId(92),
                id: WorkloadId::new("svc-1"),
            },
            &ctx,
        )
        .await;
        match reply {
            ConstableToWarden::ProbeResult {
                request_id,
                id,
                status,
            } => {
                assert_eq!(request_id, RequestId(92));
                assert_eq!(id, WorkloadId::new("svc-1"));
                assert!(
                    matches!(status, kamaji_proto::ProbeStatus::Ready),
                    "expected Ready, got {status:?}",
                );
            }
            other => panic!("expected ProbeResult, got {other:?}"),
        }
    }
}
