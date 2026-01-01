//! Sibling-deployment client (W199 shape 2): postcard-over-UDS
//! [`ConstableClient`] for callers that talk to a separate
//! `constable.service` process.
//!
//! ## Why
//!
//! Per [W199](../../../../.yah/docs/working/W199-constable-universal-supervisor.md),
//! Constable has two deployment shapes:
//!
//! - **Inlined** — same process as the caller; caller holds
//!   `Arc<dyn Constable>` directly (see [`crate::inlined`]).
//! - **Sibling** — separate process supervised by the host's PID 1
//!   (systemd / container PID 1 / launchd). Caller holds a
//!   [`ConstableClient`] that speaks the [`constable_proto`] wire format
//!   over a unix domain socket. This module owns the caller side.
//!
//! Carved out of warden as part of R484-T4. Warden previously hosted this at
//! `crates/yah/warden/src/constable_client.rs`; the file is now a re-export
//! shim there.
//!
//! ## Shape
//!
//! - Single persistent `tokio::net::UnixStream`, owned by a
//!   [`ConstableClient`].
//! - Requests serialize as `WardenToConstable` postcard frames; responses
//!   deserialize from `ConstableToWarden`. The codec is shared with
//!   `app/yah/constable`'s server.
//! - Constable processes a connection serially (`handle_message` per frame),
//!   so the client matches: one in-flight request at a time, gated by a
//!   `tokio::sync::Mutex<Inner>`. Concurrent callers queue, which mirrors
//!   how warden's HTTP handlers already serialize on the runtime trait.
//! - On connect, the client exchanges `Hello`/`Welcome` to verify the
//!   protocol version and capture Constable's build version for tracing.
//!
//! ## Why a serial mutex, not a multiplex actor
//!
//! `RequestId` is in the wire format so the protocol *can* multiplex, but
//! Constable's current dispatcher (`handle_message`) replies in receipt order
//! per connection. Until Constable grows out-of-order replies, the simpler
//! mutex+serial shape is correct and easier to reason about. When Constable
//! later sends pushed messages (`WorkloadStarted`, `WorkloadExited`,
//! `DrainCompleted`), this client will need a background reader that demuxes
//! responses from pushes by `RequestId`; the public API stays the same.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use constable_proto::{
    decode_frame, encode_frame, ConstableToWarden, DrainBudget, Error as CodecError, ErrorCode,
    ProbeStatus, ProtocolVersion, RequestId, WardenToConstable, WorkloadEntry, WorkloadId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{unix::OwnedReadHalf, unix::OwnedWriteHalf, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, info};

/// Default warden ↔ Constable socket path used when no override is provided.
///
/// Matches the production layout in W154 §"The supervisor split". `app/yah/
/// constable` defaults to the same path via its `CONSTABLE_SOCK` env var
/// fallback, so a stock systemd-managed deploy needs no extra plumbing.
pub const DEFAULT_SOCKET: &str = "/run/yah/constable.sock";

/// Errors surfaced by [`ConstableClient`] calls.
///
/// Distinct from the underlying codec errors so the warden HTTP layer can
/// branch on connectivity vs. protocol-level rejections.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// I/O failure on the UDS — connection dropped, socket missing, partial
    /// write. Warden treats this as "Constable is unreachable" and may fall
    /// back to the legacy in-process runtime where one is configured.
    #[error("constable UDS I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Codec rejected a frame — almost always a Constable bug.
    #[error("constable wire codec: {0}")]
    Codec(#[from] CodecError),

    /// Connection closed mid-request (EOF on read).
    #[error("constable closed the connection mid-request")]
    PeerClosed,

    /// Constable returned `Error { code, message }` for our request.
    #[error("constable error: {code:?}: {message}")]
    Remote { code: ErrorCode, message: String },

    /// Response payload was the wrong variant for the request kind. Tag is
    /// a debug rendering of the unexpected variant.
    #[error("constable replied with unexpected variant: {0}")]
    Unexpected(String),

    /// Constable replied with a [`RequestId`] that did not match the request.
    #[error("constable response request_id mismatch (expected {expected:?}, got {got:?})")]
    RequestIdMismatch {
        expected: RequestId,
        got: RequestId,
    },

    /// Constable handshake rejected our protocol version.
    #[error("constable rejected handshake (version {wanted:?})")]
    HandshakeRefused { wanted: ProtocolVersion },
}

/// Per-connection state. Held behind a `Mutex` so concurrent callers
/// serialize their requests onto the single socket.
#[derive(Debug)]
struct Inner {
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    /// Read buffer carried between calls so a frame split across two reads
    /// still decodes cleanly.
    buf: Vec<u8>,
}

/// Constable-side metadata learned during the handshake. Used for tracing
/// and operator visibility (`GET /health` could surface the constable build
/// version later).
#[derive(Debug, Clone)]
pub struct ConstableInfo {
    pub version: ProtocolVersion,
    pub constable_version: String,
}

/// UDS client for talking to a sibling Constable process.
///
/// Construct with [`ConstableClient::connect`]; share via `Arc<...>` if
/// multiple handlers need it.
#[derive(Debug)]
pub struct ConstableClient {
    socket: PathBuf,
    next_request_id: AtomicU64,
    info: ConstableInfo,
    inner: Mutex<Inner>,
}

impl ConstableClient {
    /// Open the socket, exchange `Hello`/`Welcome`, and return a ready
    /// client. Errors if the socket isn't there, Constable rejects the
    /// protocol version, or the handshake reply is malformed.
    pub async fn connect(socket: impl Into<PathBuf>) -> Result<Self, ClientError> {
        let socket = socket.into();
        let stream = UnixStream::connect(&socket).await?;
        let (rd, wr) = stream.into_split();
        let mut inner = Inner {
            rd,
            wr,
            buf: Vec::with_capacity(4096),
        };

        // Handshake — write Hello, read Welcome (or Error).
        let hello = WardenToConstable::Hello {
            version: ProtocolVersion::CURRENT,
        };
        let inner_mut: &mut Inner = &mut inner;
        write_frame(&mut inner_mut.wr, &hello).await?;
        let reply = read_frame(&mut inner_mut.rd, &mut inner_mut.buf).await?;
        let info = match reply {
            ConstableToWarden::Welcome {
                version,
                constable_version,
            } => ConstableInfo {
                version,
                constable_version,
            },
            ConstableToWarden::Error { code, message, .. } => {
                return Err(ClientError::Remote { code, message });
            }
            other => return Err(ClientError::Unexpected(format!("{other:?}"))),
        };

        info!(
            socket = %socket.display(),
            constable_version = %info.constable_version,
            "constable handshake complete"
        );

        Ok(Self {
            socket,
            next_request_id: AtomicU64::new(1),
            info,
            inner: Mutex::new(inner),
        })
    }

    /// Path this client connected to. Useful for tracing.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Constable build + protocol version captured during handshake.
    pub fn info(&self) -> &ConstableInfo {
        &self.info
    }

    fn next_request_id(&self) -> RequestId {
        RequestId(self.next_request_id.fetch_add(1, Ordering::Relaxed))
    }

    /// `WardenToConstable::List` — every workload Constable is supervising.
    pub async fn list(&self) -> Result<Vec<WorkloadEntry>, ClientError> {
        let request_id = self.next_request_id();
        let reply = self
            .request(WardenToConstable::List { request_id }, request_id)
            .await?;
        match reply {
            ConstableToWarden::WorkloadList {
                request_id: rid,
                entries,
            } => {
                check_rid(request_id, rid)?;
                Ok(entries)
            }
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `WardenToConstable::Stop` — SIGTERM-with-grace floor. Returns when
    /// Constable acks the stop request; the workload may still be reaping
    /// when this returns.
    pub async fn stop(&self, id: &WorkloadId) -> Result<(), ClientError> {
        let request_id = self.next_request_id();
        let reply = self
            .request(
                WardenToConstable::Stop {
                    request_id,
                    id: id.clone(),
                },
                request_id,
            )
            .await?;
        match reply {
            ConstableToWarden::Ack {
                request_id: rid, ..
            } => {
                check_rid(request_id, rid)?;
                Ok(())
            }
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `WardenToConstable::Drain` — structured drain with a deadline budget.
    /// Returns `(accepted, reason)` from Constable's synchronous `DrainAck`.
    pub async fn drain(
        &self,
        id: &WorkloadId,
        budget: DrainBudget,
    ) -> Result<(bool, Option<String>), ClientError> {
        let request_id = self.next_request_id();
        let reply = self
            .request(
                WardenToConstable::Drain {
                    request_id,
                    id: id.clone(),
                    budget,
                },
                request_id,
            )
            .await?;
        match reply {
            ConstableToWarden::DrainAck {
                request_id: rid,
                accepted,
                reason,
                ..
            } => {
                check_rid(request_id, rid)?;
                Ok((accepted, reason))
            }
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `WardenToConstable::Probe` — fire one probe poll for the workload.
    pub async fn probe(&self, id: &WorkloadId) -> Result<ProbeStatus, ClientError> {
        let request_id = self.next_request_id();
        let reply = self
            .request(
                WardenToConstable::Probe {
                    request_id,
                    id: id.clone(),
                },
                request_id,
            )
            .await?;
        match reply {
            ConstableToWarden::ProbeResult {
                request_id: rid,
                status,
                ..
            } => {
                check_rid(request_id, rid)?;
                Ok(status)
            }
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Send `req`, await one reply, surface `Error{code,message}` payloads as
    /// [`ClientError::Remote`]. Holds the inner mutex across the round-trip
    /// so the next caller's frame can't interleave on the wire.
    async fn request(
        &self,
        req: WardenToConstable,
        expected_rid: RequestId,
    ) -> Result<ConstableToWarden, ClientError> {
        let mut guard = self.inner.lock().await;
        // Deref the MutexGuard so disjoint-field borrows of rd/wr/buf are
        // visible to the borrow checker (Deref-target borrows would block).
        let inner: &mut Inner = &mut guard;
        write_frame(&mut inner.wr, &req).await?;
        let reply = read_frame(&mut inner.rd, &mut inner.buf).await?;
        if let ConstableToWarden::Error {
            request_id,
            code,
            message,
        } = reply
        {
            debug!(
                ?request_id,
                ?code,
                %message,
                "constable returned Error for request"
            );
            // The wire only carries Some(request_id) when Constable correlates
            // it to a specific request; an Error with None is a connection-level
            // failure (e.g. malformed frame) and shouldn't be silently mapped.
            if let Some(rid) = request_id {
                check_rid(expected_rid, rid)?;
            }
            return Err(ClientError::Remote { code, message });
        }
        Ok(reply)
    }
}

fn check_rid(expected: RequestId, got: RequestId) -> Result<(), ClientError> {
    if expected == got {
        Ok(())
    } else {
        Err(ClientError::RequestIdMismatch { expected, got })
    }
}

async fn write_frame(
    wr: &mut OwnedWriteHalf,
    msg: &WardenToConstable,
) -> Result<(), ClientError> {
    let bytes = encode_frame(msg)?;
    wr.write_all(&bytes).await?;
    Ok(())
}

/// Read exactly one `ConstableToWarden` frame, refilling `buf` as needed.
///
/// Drains any leftover bytes from the previous read first — if a prior call
/// pulled two frames in one syscall, the second is already buffered.
async fn read_frame(
    rd: &mut OwnedReadHalf,
    buf: &mut Vec<u8>,
) -> Result<ConstableToWarden, ClientError> {
    let mut tmp = [0u8; 4096];
    loop {
        match decode_frame::<ConstableToWarden>(buf) {
            Ok((msg, consumed)) => {
                buf.drain(..consumed);
                return Ok(msg);
            }
            Err(CodecError::Truncated { .. }) => {
                let n = rd.read(&mut tmp).await?;
                if n == 0 {
                    return Err(ClientError::PeerClosed);
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => return Err(ClientError::Codec(e)),
        }
    }
}

// ── Constable trait impl ──────────────────────────────────────────────────────
//
// Bridges the `Constable` trait (W199 caller contract) to the sibling-shape
// postcard-over-UDS wire protocol. Methods with no proto equivalent (stream_logs,
// restart_workload, health) return explicit "not yet in sibling proto" errors
// rather than panicking so callers can handle them gracefully.
//
// See W199 §The move: callers hold `Arc<dyn Constable>` regardless of shape;
// the inlined impl dispatches in-process while this impl speaks the wire.

use async_trait::async_trait;
use constable_proto::WorkloadState as ProtoWorkloadState;

fn proto_state_to_status(s: ProtoWorkloadState) -> crate::WorkloadStatus {
    match s {
        ProtoWorkloadState::Pending | ProtoWorkloadState::Starting => crate::WorkloadStatus::Pending,
        ProtoWorkloadState::Running => crate::WorkloadStatus::Running,
        ProtoWorkloadState::Draining => crate::WorkloadStatus::Stopping,
        ProtoWorkloadState::Exited => crate::WorkloadStatus::Stopped,
        ProtoWorkloadState::Failed => crate::WorkloadStatus::Failed {
            reason: "workload exited with failure".into(),
        },
        // `#[non_exhaustive]` — map unknown future variants to Failed so
        // callers never silently treat an unknown state as healthy.
        _ => crate::WorkloadStatus::Failed {
            reason: "unknown proto WorkloadState variant".into(),
        },
    }
}

fn entry_to_workload_state(entry: WorkloadEntry) -> crate::WorkloadState {
    crate::WorkloadState {
        ident: crate::MeshIdent(entry.id.0.clone()),
        container_id: entry.id.0,
        status: proto_state_to_status(entry.state),
        mesh_ip: None,
    }
}

#[async_trait]
impl crate::Constable for ConstableClient {
    fn backend(&self) -> crate::Backend {
        // The proto handshake doesn't carry backend type today; default to
        // Native. A future protocol-version extension can surface this.
        crate::Backend::Native
    }

    /// Deploy a workload. Wraps `spec` in a `Workload::Container` envelope
    /// and sends `WardenToConstable::Deploy`. Returns a [`DeployResult`]
    /// with `mesh_ip` taken from `mesh` and `task_pid = 0` (the pid arrives
    /// later via the `WorkloadStarted` push message, not yet plumbed).
    async fn deploy_workload(
        &self,
        spec: &workload_spec::WorkloadSpec,
        mesh: &crate::MeshAssignment,
    ) -> anyhow::Result<crate::DeployResult> {
        let id = WorkloadId::new(&spec.name);
        let workload_envelope = workload_spec::Workload::Container(spec.clone());
        let request_id = self.next_request_id();
        let reply = self
            .request(
                WardenToConstable::Deploy {
                    request_id,
                    id: id.clone(),
                    spec: workload_envelope,
                },
                request_id,
            )
            .await
            .map_err(|e| anyhow::anyhow!("constable deploy_workload: {e}"))?;
        match reply {
            ConstableToWarden::Ack {
                request_id: rid,
                kind: constable_proto::AckKind::Deploy,
            } => {
                check_rid(request_id, rid)
                    .map_err(|e| anyhow::anyhow!("constable deploy ack: {e}"))?;
                Ok(crate::DeployResult {
                    container_id: id.0,
                    mesh_ip: mesh.mesh_ip,
                    task_pid: 0,
                })
            }
            other => Err(anyhow::anyhow!(
                "constable deploy_workload: unexpected reply {other:?}"
            )),
        }
    }

    async fn list_workloads(&self) -> anyhow::Result<Vec<crate::WorkloadState>> {
        let entries = self
            .list()
            .await
            .map_err(|e| anyhow::anyhow!("constable list_workloads: {e}"))?;
        Ok(entries.into_iter().map(entry_to_workload_state).collect())
    }

    async fn get_workload(
        &self,
        ident: &crate::MeshIdent,
    ) -> anyhow::Result<Option<crate::WorkloadState>> {
        let all = self.list_workloads().await?;
        Ok(all.into_iter().find(|s| s.ident == *ident))
    }

    async fn stream_logs(
        &self,
        _ident: &crate::MeshIdent,
        _opts: crate::LogOpts,
    ) -> anyhow::Result<crate::LogStream> {
        Err(anyhow::anyhow!(
            "stream_logs not yet in the sibling-Constable wire protocol"
        ))
    }

    async fn restart_workload(&self, ident: &crate::MeshIdent) -> anyhow::Result<()> {
        // No dedicated Restart message in the current proto — issue Stop and
        // let the supervisor's RestartPolicy handle re-launch. Not equivalent
        // to a true restart (the supervisor must have a non-Never policy), but
        // it is the closest available action.
        let id = WorkloadId::new(&ident.0);
        self.stop(&id)
            .await
            .map_err(|e| anyhow::anyhow!("constable restart_workload (via stop): {e}"))
    }

    async fn teardown_workload(&self, ident: &crate::MeshIdent) -> anyhow::Result<()> {
        let id = WorkloadId::new(&ident.0);
        self.stop(&id)
            .await
            .map_err(|e| anyhow::anyhow!("constable teardown_workload: {e}"))
    }

    async fn health(&self) -> anyhow::Result<crate::RuntimeHealth> {
        // No health-check message in the current proto. Report "ok" using the
        // presence of the established connection as the liveness signal.
        Ok(crate::RuntimeHealth {
            ok: true,
            version: Some(self.info().constable_version.clone()),
            detail: None,
        })
    }
}

/// Connect with a bounded timeout so a missing/broken socket doesn't stall
/// `yah-warden serve` startup forever. Returns a recognisable error so the
/// CLI can decide whether to fail-hard or fall back to the legacy runtime.
pub async fn connect_with_timeout(
    socket: impl Into<PathBuf>,
    timeout: Duration,
) -> Result<ConstableClient> {
    let socket = socket.into();
    let result = tokio::time::timeout(timeout, ConstableClient::connect(socket.clone()))
        .await
        .map_err(|_| {
            anyhow!(
                "timed out after {:?} connecting to constable at {}",
                timeout,
                socket.display()
            )
        })?;
    result.with_context(|| format!("connecting to constable at {}", socket.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use constable_proto::{AckKind, WorkloadState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// Spin up a one-shot in-process "constable" on a tempdir socket that
    /// answers the first incoming request with the closure's reply.
    async fn one_shot_server(
        expect_after_hello: impl FnOnce(WardenToConstable) -> ConstableToWarden + Send + 'static,
    ) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("constable.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let welcome = ConstableToWarden::Welcome {
            version: ProtocolVersion::CURRENT,
            constable_version: "test-0.0.1".into(),
        };
        let answer = std::sync::Arc::new(std::sync::Mutex::new(Some(expect_after_hello)));
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::with_capacity(4096);
            let mut tmpbuf = [0u8; 4096];

            // Read Hello.
            let hello = loop {
                match decode_frame::<WardenToConstable>(&buf) {
                    Ok((m, n)) => {
                        buf.drain(..n);
                        break m;
                    }
                    Err(CodecError::Truncated { .. }) => {
                        let n = stream.read(&mut tmpbuf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmpbuf[..n]);
                    }
                    Err(e) => panic!("decode hello: {e}"),
                }
            };
            assert!(matches!(hello, WardenToConstable::Hello { .. }));
            let bytes = encode_frame(&welcome).unwrap();
            stream.write_all(&bytes).await.unwrap();

            // Read the next request and reply via the closure.
            let req = loop {
                match decode_frame::<WardenToConstable>(&buf) {
                    Ok((m, n)) => {
                        buf.drain(..n);
                        break m;
                    }
                    Err(CodecError::Truncated { .. }) => {
                        let n = stream.read(&mut tmpbuf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmpbuf[..n]);
                    }
                    Err(e) => panic!("decode req: {e}"),
                }
            };
            let answer = answer.lock().unwrap().take().expect("answer used once");
            let reply = answer(req);
            let bytes = encode_frame(&reply).unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        (tmp, sock)
    }

    #[tokio::test]
    async fn connect_handshakes_and_captures_info() {
        let (_tmp, sock) = one_shot_server(|_req| ConstableToWarden::WorkloadList {
            request_id: RequestId(1),
            entries: vec![],
        })
        .await;
        let client = ConstableClient::connect(sock).await.expect("connect");
        assert_eq!(client.info().constable_version, "test-0.0.1");
        let entries = client.list().await.expect("list");
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn list_returns_workload_entries() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                WardenToConstable::List { request_id } => request_id,
                other => panic!("expected List, got {other:?}"),
            };
            ConstableToWarden::WorkloadList {
                request_id: rid,
                entries: vec![WorkloadEntry {
                    id: WorkloadId::new("foo"),
                    state: WorkloadState::Running,
                    pid: Some(42),
                }],
            }
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        let entries = client.list().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, WorkloadId::new("foo"));
        assert_eq!(entries[0].state, WorkloadState::Running);
        assert_eq!(entries[0].pid, Some(42));
    }

    #[tokio::test]
    async fn stop_handles_ack() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                WardenToConstable::Stop { request_id, .. } => request_id,
                other => panic!("expected Stop, got {other:?}"),
            };
            ConstableToWarden::Ack {
                request_id: rid,
                kind: AckKind::Stop,
            }
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        client.stop(&WorkloadId::new("foo")).await.expect("stop");
    }

    #[tokio::test]
    async fn drain_surfaces_ack_payload() {
        let (_tmp, sock) = one_shot_server(|req| {
            let (rid, id) = match req {
                WardenToConstable::Drain {
                    request_id,
                    id,
                    budget,
                } => {
                    assert_eq!(budget.flush_ms, 100);
                    assert_eq!(budget.checkpoint_ms, 200);
                    (request_id, id)
                }
                other => panic!("expected Drain, got {other:?}"),
            };
            ConstableToWarden::DrainAck {
                request_id: rid,
                id,
                accepted: true,
                reason: Some("flushed in 50ms".into()),
            }
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        let (accepted, reason) = client
            .drain(
                &WorkloadId::new("foo"),
                DrainBudget {
                    flush_ms: 100,
                    checkpoint_ms: 200,
                },
            )
            .await
            .unwrap();
        assert!(accepted);
        assert_eq!(reason.as_deref(), Some("flushed in 50ms"));
    }

    #[tokio::test]
    async fn remote_error_is_surfaced_as_client_remote() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                WardenToConstable::Stop { request_id, .. } => request_id,
                other => panic!("expected Stop, got {other:?}"),
            };
            ConstableToWarden::Error {
                request_id: Some(rid),
                code: ErrorCode::UnknownWorkload,
                message: "no such id".into(),
            }
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        let err = client.stop(&WorkloadId::new("foo")).await.unwrap_err();
        match err {
            ClientError::Remote { code, message } => {
                assert_eq!(code, ErrorCode::UnknownWorkload);
                assert_eq!(message, "no such id");
            }
            other => panic!("expected Remote, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_with_timeout_fails_on_missing_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("does-not-exist.sock");
        let err = connect_with_timeout(sock, Duration::from_millis(250))
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("connecting to constable"),
            "error should mention the socket path: {msg}"
        );
    }

    // ── Constable trait impl tests ────────────────────────────────────────────

    use crate::Constable as ConstableTrait;

    #[tokio::test]
    async fn constable_backend_returns_native() {
        // backend() is always Native (proto doesn't carry this info yet).
        let (_tmp, sock) = one_shot_server(|_| ConstableToWarden::WorkloadList {
            request_id: RequestId(1),
            entries: vec![],
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        assert_eq!(client.backend(), crate::Backend::Native);
    }

    #[tokio::test]
    async fn constable_list_workloads_maps_proto_entries() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                WardenToConstable::List { request_id } => request_id,
                other => panic!("expected List, got {other:?}"),
            };
            ConstableToWarden::WorkloadList {
                request_id: rid,
                entries: vec![
                    WorkloadEntry {
                        id: WorkloadId::new("svc-a"),
                        state: WorkloadState::Running,
                        pid: Some(1000),
                    },
                    WorkloadEntry {
                        id: WorkloadId::new("svc-b"),
                        state: WorkloadState::Exited,
                        pid: None,
                    },
                ],
            }
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        let states = client.list_workloads().await.unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].ident, crate::MeshIdent("svc-a".into()));
        assert!(matches!(states[0].status, crate::WorkloadStatus::Running));
        assert_eq!(states[1].ident, crate::MeshIdent("svc-b".into()));
        assert!(matches!(states[1].status, crate::WorkloadStatus::Stopped));
    }

    #[tokio::test]
    async fn constable_get_workload_finds_by_ident() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                WardenToConstable::List { request_id } => request_id,
                other => panic!("expected List, got {other:?}"),
            };
            ConstableToWarden::WorkloadList {
                request_id: rid,
                entries: vec![WorkloadEntry {
                    id: WorkloadId::new("target"),
                    state: WorkloadState::Running,
                    pid: Some(42),
                }],
            }
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        let state = client
            .get_workload(&crate::MeshIdent("target".into()))
            .await
            .unwrap();
        assert!(state.is_some());
        assert_eq!(state.unwrap().ident, crate::MeshIdent("target".into()));
    }

    #[tokio::test]
    async fn constable_get_workload_returns_none_for_unknown_ident() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                WardenToConstable::List { request_id } => request_id,
                other => panic!("expected List, got {other:?}"),
            };
            ConstableToWarden::WorkloadList {
                request_id: rid,
                entries: vec![],
            }
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        let state = client
            .get_workload(&crate::MeshIdent("nobody".into()))
            .await
            .unwrap();
        assert!(state.is_none());
    }

    #[tokio::test]
    async fn constable_teardown_workload_sends_stop() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                WardenToConstable::Stop { request_id, id } => {
                    assert_eq!(id, WorkloadId::new("svc-to-stop"));
                    request_id
                }
                other => panic!("expected Stop, got {other:?}"),
            };
            ConstableToWarden::Ack {
                request_id: rid,
                kind: AckKind::Stop,
            }
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        client
            .teardown_workload(&crate::MeshIdent("svc-to-stop".into()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn constable_health_returns_ok_with_constable_version() {
        let (_tmp, sock) = one_shot_server(|_| ConstableToWarden::WorkloadList {
            request_id: RequestId(1),
            entries: vec![],
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        let health = client.health().await.unwrap();
        assert!(health.ok);
        assert_eq!(health.version.as_deref(), Some("test-0.0.1"));
    }

    #[tokio::test]
    async fn constable_stream_logs_returns_not_supported_err() {
        let (_tmp, sock) = one_shot_server(|_| ConstableToWarden::WorkloadList {
            request_id: RequestId(1),
            entries: vec![],
        })
        .await;
        let client = ConstableClient::connect(sock).await.unwrap();
        let result = client
            .stream_logs(&crate::MeshIdent("any".into()), crate::LogOpts::default())
            .await;
        // LogStream doesn't impl Debug, so match manually.
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected stream_logs to return Err"),
        };
        assert!(err.to_string().contains("not yet in the sibling"));
    }
}
