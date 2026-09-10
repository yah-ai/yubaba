//! Shared plumbing for reconcilers that run a workload as a **kamaji-native
//! host process** rather than a container.
//!
//! Two reconcilers spawn through `kamaji::native::NativeRuntime` today —
//! [`super::mesofact_static`] (mesofact-dev at the dev tier, R490-F2) and
//! [`super::local_process`] (any declared host binary, R715-T1) — and both need
//! the same four things: an ident that is simultaneously DNS-segment shaped and
//! path-safe, a `WorkloadSpec` whose `ImageRef` is identity-only, a bridge from
//! NativeRuntime's *file* capture to the Run-tab's live [`LogBuffer`], and a
//! supervisor that tears the workload down on shutdown.
//!
//! It lives in one module because the second copy is where these drift. The
//! log bridge in particular encodes a non-obvious contract (NativeRuntime
//! writes `<state_dir>/<ident>/{stdout,stderr}.log` and does **not** support
//! follow, so the tail has to carry a partial trailing line across drains); a
//! forked copy that got that wrong would silently truncate the last line of
//! every log the operator reads.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use kamaji::native::NativeRuntime;
use kamaji::{Kamaji, MeshIdent};
use tokio::sync::oneshot;
use workload_spec::{
    EnvVar, ExposeSpec, ImageRef, MeshExpose, Millis, NamespaceId, ResourceLimits, RestartPolicy,
    SchemaVersion, StopPolicy, TenantId, TierTag, WorkloadSpec,
};

use super::LogBuffer;

/// Native workloads are a fork+exec of an already-present host binary — the
/// kamaji Native backend treats `ImageRef` as identity metadata only and
/// never pulls. The schema still demands a valid-format digest, so native
/// specs stamp a fixed all-zeros marker: impossible for any real image, so a
/// leak into a registry-pull path surfaces obviously. (Mirrors
/// `workload_spec::testing::TEST_DIGEST` without reaching into a test-only
/// helper from production code.)
pub(crate) const NATIVE_IDENTITY_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Sanitize an arbitrary label into an ident that is DNS-segment shaped
/// (kamaji's contract) and safe as a filesystem path component (NativeRuntime
/// joins it under its state dir for log capture). Lowercase; every
/// non-alphanumeric collapses to `-`.
pub(crate) fn sanitize_ident(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// Lower a host-binary invocation to a native [`WorkloadSpec`]. `argv[0]` is
/// the binary; the remaining entries are its arguments (kamaji's Native backend
/// uses container `command` semantics — see `constable_core::native`). `image`
/// is identity metadata only: native never pulls, so it carries the
/// [`NATIVE_IDENTITY_DIGEST`] marker.
///
/// `restart_policy` is [`RestartPolicy::Never`] deliberately. The caller owns
/// the readiness probe and reports a bind failure as a failed reconcile; an
/// `Always` policy here would keep re-execing a binary that cannot start, and
/// the operator would watch a spinner instead of reading the error.
pub(crate) fn native_spec(ident: &str, argv: Vec<String>, env: Vec<EnvVar>) -> WorkloadSpec {
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: ident.to_string(),
        image: ImageRef {
            registry: "localhost".to_string(),
            repository: format!("native/{ident}"),
            tag: "dev".to_string(),
            digest: NATIVE_IDENTITY_DIGEST.to_string(),
        },
        tier: TierTag("dev".to_string()),
        replicas: 1,
        command: Some(argv),
        entrypoint: None,
        workdir: None,
        user: None,
        env,
        secrets: vec![],
        volumes: vec![],
        resources: ResourceLimits {
            memory_mb: 512,
            cpu_millis: 512,
            ephemeral_storage_mb: 512,
        },
        depends_on: vec![],
        requires: vec![],
        healthcheck: None,
        restart_policy: RestartPolicy::Never,
        archetype: None,
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(5),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent(ident.to_string()),
                ports: vec![],
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        tenant: TenantId::singleton(),
        namespace: NamespaceId::singleton(),
        labels: Default::default(),
        annotations: Default::default(),
    }
}

/// Capture-file paths NativeRuntime writes for `ident` under `state_dir`.
/// Mirrors the layout documented in `kamaji::native`.
pub(crate) fn capture_paths(state_dir: &std::path::Path, ident: &str) -> (PathBuf, PathBuf) {
    let dir = state_dir.join(ident);
    (dir.join("stdout.log"), dir.join("stderr.log"))
}

/// Tail-only supervisor for an **adopted** native workload — one this process
/// did not spawn and therefore holds no [`NativeRuntime`] handle for.
///
/// The distinction matters and is the whole reason this exists next to
/// [`spawn_native_log_supervisor`] rather than being folded into it. That one
/// owns the workload: it can ask the runtime whether the child is still alive
/// and tear it down. An adopter has neither — after a desktop restart the
/// original supervisor is gone and the child has reparented to init — so all it
/// can do is keep reading the capture files, which NativeRuntime left behind at
/// a deterministic path and the orphan is still appending to.
///
/// Teardown for an adopted workload is therefore NOT this task's job; it rides
/// on `RunningWorkload::with_teardown` (see
/// [`stop_process_listening_on`]).
pub(crate) fn spawn_capture_tail(
    log_buf: LogBuffer,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        // From the end, not from 0 — see [`FileTail::from_end`].
        let mut out_tail = FileTail::from_end(stdout_path).await;
        let mut err_tail = FileTail::from_end(stderr_path).await;
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    out_tail.drain_into(&log_buf).await;
                    err_tail.drain_into(&log_buf).await;
                    return Ok(());
                }
                _ = tokio::time::sleep(Duration::from_millis(200)) => {
                    out_tail.drain_into(&log_buf).await;
                    err_tail.drain_into(&log_buf).await;
                }
            }
        }
    })
}

/// Stop whatever process is currently listening on `addr`: SIGTERM, wait up to
/// `grace` for the port to go quiet, then SIGKILL. Errors if the port is still
/// bound afterwards.
///
/// **Why the port and not a recorded pid.** The case this exists for is an
/// orphan — a native workload whose supervisor died and which reparented to
/// init (observed on this camp 2026-09-08: three `mesofact-dev` processes,
/// PPID 1, one of them holding 4321 across a desktop *and* camp-daemon
/// restart). A pid written to disk at spawn time is only ever stale in exactly
/// that case, and a stale pid on a machine that has since wrapped its pid space
/// names an innocent process. Asking the OS who holds the socket *right now*
/// has no staleness window at all.
///
/// The caller is expected to have already confirmed the listener's identity
/// (mesofact-dev's `/__mesofact/info`) — this function only knows how to kill
/// what answers on a port, not whether killing it is correct.
///
/// Verification is by effect: the port stops accepting connections. A pid that
/// exits while something else keeps the socket open is a failed stop and is
/// reported as one, which is the property the Stop button was missing.
pub(crate) async fn stop_process_listening_on(
    addr: std::net::SocketAddr,
    grace: Duration,
) -> Result<()> {
    let pid = pid_listening_on(addr.port())
        .await?
        .ok_or_else(|| anyhow::anyhow!("nothing is listening on {addr}"))?;

    #[cfg(unix)]
    {
        // SAFETY: kill(2) with a pid `lsof` just reported as the owner of this
        // listening socket. ESRCH (already exited) is the benign race and is
        // ignored — the port check below is what decides success.
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        if wait_for_port_free(addr, grace).await {
            return Ok(());
        }
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
        if wait_for_port_free(addr, Duration::from_secs(2)).await {
            return Ok(());
        }
        anyhow::bail!(
            "sent SIGTERM then SIGKILL to pid {pid}, but {addr} is still accepting \
             connections — the process did not exit, or another one took the socket"
        );
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, grace);
        anyhow::bail!("stopping an adopted host process is only implemented on unix")
    }
}

/// Ask the OS which process holds the listening socket on `port`.
///
/// `lsof` rather than a platform API because this runs on an operator's own
/// machine at the dev tier, where `lsof` is present on macOS by default and is
/// the one spelling that works the same on both unixes we care about. An
/// ambiguous answer (two distinct pids) is an error, not a coin flip.
async fn pid_listening_on(port: u16) -> Result<Option<u32>> {
    let out = tokio::process::Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
        .output()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "cannot resolve the owner of port {port}: running `lsof` failed ({e}). \
                 Stopping an adopted dev server needs it; install lsof or stop the \
                 process by hand."
            )
        })?;
    // lsof exits 1 with no output when nothing matches — not an error here.
    let mut pids: Vec<u32> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .collect();
    pids.sort_unstable();
    pids.dedup();
    match pids.len() {
        0 => Ok(None),
        1 => Ok(Some(pids[0])),
        _ => anyhow::bail!(
            "port {port} reports {} distinct listening pids ({pids:?}) — refusing to \
             guess which one to stop",
            pids.len()
        ),
    }
}

/// Poll until nothing accepts on `addr`, or `timeout` elapses. The inverse of
/// [`super::wait_for_port`].
async fn wait_for_port_free(addr: std::net::SocketAddr, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Supervisor task for a kamaji-native workload.
///
/// NativeRuntime captures stdout/stderr to files with no follow, but the
/// Run-tab expects a live [`LogBuffer`]. This task incrementally tails both
/// capture files into `log_buf`, watches for a terminal child state, and on
/// shutdown (operator signal or self-exit) tears the workload down. Returned
/// as the `RunningWorkload` supervisor so the existing lifecycle contract is
/// unchanged.
pub(crate) fn spawn_native_log_supervisor(
    runtime: Arc<NativeRuntime>,
    ident: MeshIdent,
    log_buf: LogBuffer,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let mut out_tail = FileTail::new(stdout_path);
        let mut err_tail = FileTail::new(stderr_path);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    out_tail.drain_into(&log_buf).await;
                    err_tail.drain_into(&log_buf).await;
                    runtime.teardown_workload(&ident).await.ok();
                    return Ok(());
                }
                _ = tokio::time::sleep(Duration::from_millis(200)) => {
                    out_tail.drain_into(&log_buf).await;
                    err_tail.drain_into(&log_buf).await;
                    match runtime.get_workload(&ident).await {
                        // Still running — keep tailing.
                        Ok(Some(state)) if !state.status.is_terminal() => {}
                        // Exited on its own — final drain, then stop.
                        Ok(Some(_)) => {
                            out_tail.drain_into(&log_buf).await;
                            err_tail.drain_into(&log_buf).await;
                            return Ok(());
                        }
                        // Torn down elsewhere or runtime gone — stop.
                        Ok(None) | Err(_) => return Ok(()),
                    }
                }
            }
        }
    })
}

/// Incremental line-oriented tail of a capture file. Tracks the byte offset
/// already consumed plus any partial trailing line, so each drain emits only
/// whole new lines into the [`LogBuffer`].
pub(crate) struct FileTail {
    path: PathBuf,
    offset: u64,
    partial: String,
}

impl FileTail {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            partial: String::new(),
        }
    }

    /// A tail that starts at the file's current end, so the first drain emits
    /// only lines written from now on.
    ///
    /// This is the right start for an **adopted** workload and the wrong one
    /// for a spawned one. A spawned workload's capture file was just truncated
    /// for it, so offset 0 is its own first line. An adopted one inherits
    /// whatever the last run left at that path — and the two are not reliably
    /// the same process: the mesofact-dev holding 4321 on this camp on
    /// 2026-09-08 started at 17:43 while the capture file it would have written
    /// had not been touched since 17:39. Replaying that from offset 0 would
    /// present a dead run's output as the live server's, which is a worse
    /// answer than an empty pane.
    ///
    /// A file that does not exist yet starts at 0 — nothing to skip.
    pub(crate) async fn from_end(path: PathBuf) -> Self {
        let offset = tokio::fs::metadata(&path).await.map(|m| m.len()).unwrap_or(0);
        Self {
            path,
            offset,
            partial: String::new(),
        }
    }

    pub(crate) async fn drain_into(&mut self, log_buf: &LogBuffer) {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let Ok(mut file) = tokio::fs::File::open(&self.path).await else {
            return;
        };
        if file
            .seek(std::io::SeekFrom::Start(self.offset))
            .await
            .is_err()
        {
            return;
        }
        let mut buf = Vec::new();
        let Ok(n) = file.read_to_end(&mut buf).await else {
            return;
        };
        if n == 0 {
            return;
        }
        self.offset += n as u64;
        // Carry any incomplete trailing line over to the next drain.
        self.partial.push_str(&String::from_utf8_lossy(&buf));
        while let Some(idx) = self.partial.find('\n') {
            let line: String = self.partial.drain(..=idx).collect();
            log_buf
                .push(line.trim_end_matches(['\n', '\r']).to_string())
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_is_lowercased_and_dns_safe() {
        assert_eq!(
            sanitize_ident("yah-cloud-admin/Cloud_Admin"),
            "yah-cloud-admin-cloud-admin"
        );
    }

    #[test]
    fn native_spec_carries_the_identity_only_digest() {
        let spec = native_spec("svc-comp", vec!["/bin/true".into()], vec![]);
        assert_eq!(spec.image.digest, NATIVE_IDENTITY_DIGEST);
        assert_eq!(
            spec.command.as_deref(),
            Some(&["/bin/true".to_string()][..])
        );
        // Never: the caller owns readiness, so a non-starting binary must
        // surface as a failed reconcile rather than a silent re-exec loop.
        assert!(matches!(spec.restart_policy, RestartPolicy::Never));
    }

    /// R875-B1. An adopted workload inherits whatever the last run left in the
    /// capture file, and the two are not reliably the same process — so the
    /// adopt tail must skip what is already there rather than replay a dead
    /// run's output as the live server's.
    #[tokio::test]
    async fn from_end_skips_what_is_already_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stdout.log");
        tokio::fs::write(&path, b"stale line from a previous run\n")
            .await
            .unwrap();

        let buf = LogBuffer::new();
        let mut tail = FileTail::from_end(path.clone()).await;
        tail.drain_into(&buf).await;
        assert!(
            buf.since(0).await.0.is_empty(),
            "history predating the adopt must not surface as this run's output"
        );

        use tokio::io::AsyncWriteExt;
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .unwrap()
            .write_all(b"live line\n")
            .await
            .unwrap();
        tail.drain_into(&buf).await;
        assert_eq!(buf.since(0).await.0, vec!["live line".to_string()]);
    }

    /// The spawn path keeps offset 0: NativeRuntime truncated the file for this
    /// child, so byte 0 really is its first line.
    #[tokio::test]
    async fn new_starts_at_zero_and_reads_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stdout.log");
        tokio::fs::write(&path, b"first line\n").await.unwrap();

        let buf = LogBuffer::new();
        FileTail::new(path).drain_into(&buf).await;
        assert_eq!(buf.since(0).await.0, vec!["first line".to_string()]);
    }

    #[test]
    fn capture_paths_match_native_runtime_layout() {
        let (out, err) = capture_paths(std::path::Path::new("/s"), "id");
        assert_eq!(out, PathBuf::from("/s/id/stdout.log"));
        assert_eq!(err, PathBuf::from("/s/id/stderr.log"));
    }

    /// R490-F2: FileTail emits only whole lines and carries a partial trailing
    /// line over to the next drain (the Run-tab log bridge over kamaji's
    /// file capture). Lifted here from `mesofact_static` when the bridge became
    /// shared — the partial-line carry is exactly what a second copy would get
    /// wrong, and it would do so silently.
    #[tokio::test]
    async fn file_tail_emits_whole_lines_and_carries_partial() {
        use tokio::io::AsyncWriteExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("stdout.log");
        let log = LogBuffer::new();
        let mut tail = FileTail::new(path.clone());

        // No file yet → no-op, no lines.
        tail.drain_into(&log).await;
        let (l0, c0) = log.since(0).await;
        assert!(l0.is_empty());

        // Two whole lines + a partial third (no trailing newline).
        let mut f = tokio::fs::File::create(&path).await.unwrap();
        f.write_all(b"alpha\nbeta\npar").await.unwrap();
        f.flush().await.unwrap();
        tail.drain_into(&log).await;
        let (l1, c1) = log.since(c0).await;
        assert_eq!(l1, vec!["alpha".to_string(), "beta".to_string()]);

        // Completing the partial line surfaces it whole on the next drain.
        f.write_all(b"tial\ngamma\n").await.unwrap();
        f.flush().await.unwrap();
        tail.drain_into(&log).await;
        let (l2, _) = log.since(c1).await;
        assert_eq!(l2, vec!["partial".to_string(), "gamma".to_string()]);
    }
}
