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
