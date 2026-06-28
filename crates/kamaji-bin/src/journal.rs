//! Log fan-in to journald (R406-T10).
//!
//! Kamaji owns stdout/stderr fan-in for both backends so workload logs
//! land in the host's structured log surface (journald) tagged with the
//! workload's id and stream. The wire format is the native journald
//! datagram protocol — `SOCK_DGRAM` connected to `/run/systemd/journal/socket`
//! with field entries `KEY=value\n` (or length-prefixed for values containing
//! newlines or non-printables — see `man systemd.journal-fields`).
//!
//! ## Backends
//!
//! - **Native** (R406-T5/T6): [`crate::native::spawn`] creates pipes for
//!   stdout and stderr in the parent before fork; the child dup2s the write
//!   ends into fd 1 and 2 and the parent retains the read ends. Once the
//!   native deploy path (R406-T8) lands, it spawns one [`forward_reader`]
//!   per stream against the pipe.
//! - **Container** (R406-T9): [`crate::containerd::ContainerdBackend::deploy`]
//!   creates FIFOs at predictable paths under `<log_base>/<namespace>/<id>/`
//!   and points containerd's `CreateTaskRequest.stdout` / `.stderr` at them.
//!   Kamaji opens the FIFOs with `O_RDWR` (keeps a writer side open so
//!   EPOLLHUP doesn't fire on initial connect) and spawns forwarder tasks.
//!
//! ## Sinks
//!
//! [`LogSink`] is the trait the forwarder writes to. Production uses
//! [`JournalSender`] which sends the datagram protocol directly via
//! `UnixDatagram`. Tests use the [`VecSink`] capture which keeps a vector of
//! `(workload, stream, line)` triples for assertions.
//!
//! ## Off-Linux / no-journald fallback
//!
//! On macOS (pond's dev tier) and on Linux hosts without a journald socket
//! (CI, minimal containers), [`JournalSender::connect`] falls back to a
//! mode that re-emits each line via `tracing::info!` / `tracing::error!` so
//! logs still surface through whatever subscriber the operator has wired
//! up. The line buffering logic itself is platform-neutral.
//!
//! @yah:relay(R428, "Multi-player attribution + audit journal forwarding")
//! @yah:at(2026-06-03T22:42:08Z)
//! @yah:status(open)
//! @yah:phase(P3)
//! @yah:parent(Q425)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426)
//!
//! @yah:ticket(R428-F2, "Audit journal: local JSONL + rotation + denied.jsonl sampling + cheers forwarder + W127 projection contract")
//! @yah:at(2026-06-03T22:46:06Z)
//! @yah:status(open)
//! @yah:phase(P3)
//! @yah:parent(R428)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426-F3)

use std::io;
use std::path::Path;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use kamaji_proto::WorkloadId;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

/// Default path of journald's user-API socket on a Linux host with systemd.
/// The production cloud-tier `kamaji.service` runs as root and writes
/// here directly.
pub const JOURNALD_SOCKET: &str = "/run/systemd/journal/socket";

/// Per-record cap on MESSAGE body bytes.
///
/// journald itself accepts up to ~256 KB per record, but a runaway workload
/// emitting one huge line would balloon the read buffer Kamaji holds.
/// Truncating bounds memory; the trailing bytes are dropped on the floor and
/// the operator sees the prefix.
pub const MAX_MESSAGE_LEN: usize = 16 * 1024;

/// Syslog priority used for a single forwarded line.
///
/// journald's `PRIORITY` field is a numeric syslog level (RFC 5424).
/// Kamaji only ever sends Info (stdout) or Err (stderr) — workloads that
/// need a finer-grained level should emit structured JSON, and a downstream
/// log-processor can re-prioritise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogPriority {
    Info = 6,
    Err = 3,
}

impl LogPriority {
    /// ASCII byte for the priority numeral, used directly in the wire form.
    pub fn as_byte(self) -> u8 {
        match self {
            LogPriority::Info => b'6',
            LogPriority::Err => b'3',
        }
    }
}

/// Stream tag attached to every forwarded line. Lands in journald as the
/// `YAH_STREAM` field — operators filter with
/// `journalctl YAH_STREAM=stderr` to scope a tail to error output only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

impl Stream {
    pub fn label(self) -> &'static str {
        match self {
            Stream::Stdout => "stdout",
            Stream::Stderr => "stderr",
        }
    }

    pub fn priority(self) -> LogPriority {
        match self {
            Stream::Stdout => LogPriority::Info,
            Stream::Stderr => LogPriority::Err,
        }
    }
}

/// Sink for forwarded log lines. Production is [`JournalSender`]; tests use
/// [`VecSink`].
///
/// Implementations are expected to be cheap to call from a hot loop —
/// allocation per line is fine but spawn-per-line is not.
pub trait LogSink: std::fmt::Debug + Send + Sync {
    fn write_line(&self, workload: &WorkloadId, stream: Stream, line: &[u8]);
}

/// Build the journald datagram payload for one log line.
///
/// Pure function — separated from the socket write so the wire format is
/// testable on every platform without depending on a live journald.
///
/// Format per `man systemd.journal-fields`:
///
/// - `KEY=value\n` for values that contain no `\n`.
/// - `KEY\n<8-byte LE u64 length><value bytes>\n` for values that contain
///   newlines or other non-printable bytes (binary form).
///
/// Each field is followed by either a terminating `\n` (text form) or an
/// explicit separator `\n` after the value bytes (binary form). The whole
/// datagram is then sent in one `send(2)` to journald's UDS.
pub fn build_journal_payload(
    workload_id: &WorkloadId,
    stream: Stream,
    line: &[u8],
) -> Vec<u8> {
    let truncated_len = line.len().min(MAX_MESSAGE_LEN);
    let body = &line[..truncated_len];

    let mut payload = Vec::with_capacity(body.len() + 128);

    // PRIORITY=N\n
    payload.extend_from_slice(b"PRIORITY=");
    payload.push(stream.priority().as_byte());
    payload.push(b'\n');

    // SYSLOG_IDENTIFIER=kamaji\n — gives journalctl a clean default filter.
    payload.extend_from_slice(b"SYSLOG_IDENTIFIER=kamaji\n");

    // YAH_WORKLOAD_ID=<id>\n
    payload.extend_from_slice(b"YAH_WORKLOAD_ID=");
    payload.extend_from_slice(workload_id.as_str().as_bytes());
    payload.push(b'\n');

    // YAH_STREAM=stdout|stderr\n
    payload.extend_from_slice(b"YAH_STREAM=");
    payload.extend_from_slice(stream.label().as_bytes());
    payload.push(b'\n');

    // MESSAGE — text form if the body has no embedded newlines, binary form
    // otherwise. Line-split callers (the forwarder) strip the trailing \n,
    // so binary form only fires when a workload writes embedded NLs in one
    // logical record.
    if body.contains(&b'\n') {
        payload.extend_from_slice(b"MESSAGE\n");
        let len = body.len() as u64;
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(body);
        payload.push(b'\n');
    } else {
        payload.extend_from_slice(b"MESSAGE=");
        payload.extend_from_slice(body);
        payload.push(b'\n');
    }

    payload
}

/// Production sink: a connected datagram socket to journald (Linux) or a
/// `tracing` fallback (non-Linux / no journald).
#[derive(Debug)]
pub struct JournalSender {
    #[cfg(target_os = "linux")]
    socket: Option<std::os::unix::net::UnixDatagram>,
}

impl JournalSender {
    /// Connect to the default journald socket at [`JOURNALD_SOCKET`]. Falls
    /// back to the tracing mode if the socket isn't reachable (pond dev
    /// tier, CI without systemd, etc.) — see module docs.
    pub fn connect() -> Self {
        Self::connect_at(Path::new(JOURNALD_SOCKET))
    }

    /// Connect to an explicit socket path. Useful for tests that bind a
    /// throwaway socket in a temp dir.
    #[allow(unused_variables)]
    pub fn connect_at(socket: &Path) -> Self {
        #[cfg(target_os = "linux")]
        {
            let s = std::os::unix::net::UnixDatagram::unbound()
                .and_then(|s| {
                    s.connect(socket)?;
                    Ok(s)
                })
                .ok();
            if s.is_none() {
                tracing::warn!(
                    socket = %socket.display(),
                    "journald socket unavailable; falling back to tracing for log fan-in"
                );
            }
            Self { socket: s }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self {}
        }
    }
}

impl LogSink for JournalSender {
    fn write_line(&self, workload: &WorkloadId, stream: Stream, line: &[u8]) {
        #[cfg(target_os = "linux")]
        {
            if let Some(sock) = &self.socket {
                let payload = build_journal_payload(workload, stream, line);
                if let Err(e) = sock.send(&payload) {
                    tracing::warn!(
                        workload = %workload.as_str(),
                        stream = stream.label(),
                        error = %e,
                        "journald send failed; dropping log line"
                    );
                }
                return;
            }
        }
        emit_via_tracing(workload, stream, line);
    }
}

fn emit_via_tracing(workload: &WorkloadId, stream: Stream, line: &[u8]) {
    let utf8 = String::from_utf8_lossy(line);
    match stream {
        Stream::Stdout => tracing::info!(
            workload = %workload.as_str(),
            stream = stream.label(),
            "{utf8}"
        ),
        Stream::Stderr => tracing::error!(
            workload = %workload.as_str(),
            stream = stream.label(),
            "{utf8}"
        ),
    }
}

/// Read `reader` line-by-line and forward each line to `sink` as `stream`,
/// tagged with `workload`.
///
/// Terminates on the first of:
///
/// - EOF (writer closed; native: child exited and pipe's last writer gone).
/// - A read error (returned to the caller).
///
/// Lines are split on `\n`. Trailing `\r\n` and `\n` are both stripped before
/// forwarding. Empty lines are silently dropped — journald emits a record
/// per call and an all-empty workload would spam noise.
///
/// Errors are surfaced via `Result` so the caller can decide whether to log
/// and discard or escalate — the typical caller is a `tokio::spawn`ed task
/// that just lets the result drop.
pub async fn forward_reader<R: AsyncRead + Unpin>(
    sink: Arc<dyn LogSink>,
    workload: WorkloadId,
    stream: Stream,
    reader: R,
) -> io::Result<()> {
    let mut buf_reader = BufReader::new(reader);
    let mut line: Vec<u8> = Vec::with_capacity(256);
    loop {
        line.clear();
        let n = buf_reader.read_until(b'\n', &mut line).await?;
        if n == 0 {
            return Ok(()); // EOF
        }
        // Strip trailing \n then optional \r.
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
        }
        if line.is_empty() {
            continue;
        }
        sink.write_line(&workload, stream, &line);
    }
}

/// In-memory capture sink for unit tests. Holds every `(workload, stream,
/// line)` triple the forwarder writes; `entries()` snapshots them.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct VecSink {
    entries: Mutex<Vec<(WorkloadId, Stream, Vec<u8>)>>,
}

#[cfg(test)]
impl VecSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> Vec<(WorkloadId, Stream, Vec<u8>)> {
        self.entries.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl LogSink for VecSink {
    fn write_line(&self, workload: &WorkloadId, stream: Stream, line: &[u8]) {
        self.entries
            .lock()
            .unwrap()
            .push((workload.clone(), stream, line.to_vec()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wid(s: &str) -> WorkloadId {
        WorkloadId::new(s)
    }

    #[test]
    fn priority_byte_matches_syslog_numeric() {
        assert_eq!(LogPriority::Info.as_byte(), b'6');
        assert_eq!(LogPriority::Err.as_byte(), b'3');
    }

    #[test]
    fn stream_priority_pairs_stdout_with_info_stderr_with_err() {
        assert_eq!(Stream::Stdout.priority(), LogPriority::Info);
        assert_eq!(Stream::Stderr.priority(), LogPriority::Err);
    }

    #[test]
    fn payload_text_form_for_single_line_stdout_message() {
        let p = build_journal_payload(&wid("svc-1"), Stream::Stdout, b"hello world");
        let expected = b"PRIORITY=6\n\
                         SYSLOG_IDENTIFIER=kamaji\n\
                         YAH_WORKLOAD_ID=svc-1\n\
                         YAH_STREAM=stdout\n\
                         MESSAGE=hello world\n";
        assert_eq!(p, expected, "got:\n{}", String::from_utf8_lossy(&p));
    }

    #[test]
    fn payload_stderr_uses_priority_3_and_stream_stderr() {
        let p = build_journal_payload(&wid("svc-1"), Stream::Stderr, b"boom");
        // Just the first line and the stream tag — full bytes covered above.
        assert!(p.starts_with(b"PRIORITY=3\n"));
        assert!(p.windows(b"YAH_STREAM=stderr\n".len())
            .any(|w| w == b"YAH_STREAM=stderr\n"));
    }

    #[test]
    fn payload_binary_form_for_multiline_message() {
        // A message body containing an embedded newline must use the binary
        // form (KEY\n + 8-byte LE length + bytes + \n separator).
        let body = b"line one\nline two";
        let p = build_journal_payload(&wid("svc"), Stream::Stdout, body);
        // Locate the MESSAGE field.
        let needle = b"MESSAGE\n";
        let idx = p
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("MESSAGE\\n header present");
        let after = &p[idx + needle.len()..];
        // 8-byte LE length follows.
        assert!(after.len() >= 8, "payload too short for length prefix");
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&after[..8]);
        assert_eq!(u64::from_le_bytes(len_bytes), body.len() as u64);
        let after_len = &after[8..];
        assert!(after_len.starts_with(body), "body bytes follow length");
        assert_eq!(after_len[body.len()], b'\n', "trailing separator");
    }

    #[test]
    fn payload_truncates_oversize_message_to_cap() {
        let body = vec![b'A'; MAX_MESSAGE_LEN + 4096];
        let p = build_journal_payload(&wid("svc"), Stream::Stdout, &body);
        // No embedded newline → text form. MESSAGE= + truncated_body + \n.
        let needle = b"MESSAGE=";
        let idx = p.windows(needle.len()).position(|w| w == needle).unwrap();
        let after = &p[idx + needle.len()..];
        // Last byte is the trailing \n; everything before is the body.
        let body_in_payload = &after[..after.len() - 1];
        assert_eq!(body_in_payload.len(), MAX_MESSAGE_LEN);
        assert!(body_in_payload.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn payload_carries_workload_id_field_verbatim() {
        let p = build_journal_payload(&wid("orchard-37b"), Stream::Stdout, b"msg");
        let needle = b"YAH_WORKLOAD_ID=orchard-37b\n";
        assert!(p
            .windows(needle.len())
            .any(|w| w == needle));
    }

    #[tokio::test]
    async fn forward_reader_splits_on_newline_and_emits_each_line() {
        let sink: Arc<VecSink> = Arc::new(VecSink::new());
        let input = b"hello\nworld\ntrailer\n".as_slice();
        forward_reader(
            sink.clone() as Arc<dyn LogSink>,
            wid("svc"),
            Stream::Stdout,
            input,
        )
        .await
        .unwrap();
        let entries = sink.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].2, b"hello".to_vec());
        assert_eq!(entries[1].2, b"world".to_vec());
        assert_eq!(entries[2].2, b"trailer".to_vec());
    }

    #[tokio::test]
    async fn forward_reader_emits_final_unterminated_line() {
        // A workload that exits without a trailing newline still has its
        // final partial line surfaced — read_until returns the partial chunk
        // before EOF.
        let sink: Arc<VecSink> = Arc::new(VecSink::new());
        let input = b"alpha\nbeta-no-newline".as_slice();
        forward_reader(
            sink.clone() as Arc<dyn LogSink>,
            wid("svc"),
            Stream::Stdout,
            input,
        )
        .await
        .unwrap();
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].2, b"beta-no-newline".to_vec());
    }

    #[tokio::test]
    async fn forward_reader_strips_crlf() {
        let sink: Arc<VecSink> = Arc::new(VecSink::new());
        let input = b"crlf-line\r\nnext\n".as_slice();
        forward_reader(
            sink.clone() as Arc<dyn LogSink>,
            wid("svc"),
            Stream::Stdout,
            input,
        )
        .await
        .unwrap();
        let entries = sink.entries();
        assert_eq!(entries[0].2, b"crlf-line".to_vec());
        assert_eq!(entries[1].2, b"next".to_vec());
    }

    #[tokio::test]
    async fn forward_reader_drops_empty_lines() {
        // Bare \n lines would be a noisy record-per-newline; suppress them.
        // Real workloads occasionally emit blank progress lines; bounded
        // suppression avoids journald spam.
        let sink: Arc<VecSink> = Arc::new(VecSink::new());
        let input = b"one\n\ntwo\n\n\nthree\n".as_slice();
        forward_reader(
            sink.clone() as Arc<dyn LogSink>,
            wid("svc"),
            Stream::Stdout,
            input,
        )
        .await
        .unwrap();
        let entries = sink.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].2, b"one".to_vec());
        assert_eq!(entries[1].2, b"two".to_vec());
        assert_eq!(entries[2].2, b"three".to_vec());
    }

    #[tokio::test]
    async fn forward_reader_tags_lines_with_supplied_workload_and_stream() {
        let sink: Arc<VecSink> = Arc::new(VecSink::new());
        let input = b"oops\n".as_slice();
        forward_reader(
            sink.clone() as Arc<dyn LogSink>,
            wid("payments"),
            Stream::Stderr,
            input,
        )
        .await
        .unwrap();
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, wid("payments"));
        assert_eq!(entries[0].1, Stream::Stderr);
    }

    #[tokio::test]
    async fn forward_reader_returns_ok_on_immediate_eof() {
        let sink: Arc<VecSink> = Arc::new(VecSink::new());
        let input: &[u8] = b"";
        forward_reader(
            sink.clone() as Arc<dyn LogSink>,
            wid("svc"),
            Stream::Stdout,
            input,
        )
        .await
        .unwrap();
        assert!(sink.entries().is_empty());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn journal_sender_off_linux_is_inert_no_socket() {
        // Off-Linux JournalSender::connect just constructs without socket
        // state — calling write_line falls through to the tracing path
        // without panicking.
        let s = JournalSender::connect();
        s.write_line(&wid("svc"), Stream::Stdout, b"hello");
    }
}
