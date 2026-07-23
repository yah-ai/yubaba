//! Yubaba's MinIO supervision loop for the pond tier (R374-F3).
//!
//! Bring-up primitives ([`MinioSpec`], [`MinioRunning`],
//! [`ensure_minio_running`], [`ensure_bucket_public`]) live in the
//! `local-driver` crate so the cloud reconciler path (`pond_smoke`,
//! `yah cloud mirror up`) shares them with the yubaba HTTP path. This
//! module wraps them with the yubaba-specific reconciler: probe loop +
//! restart-on-failure + per-workload phase tracking in [`PondRegistry`].
//!
//! Why the split: the bring-up primitives are stateless (just docker CLI
//! + SigV4), but the reconciler holds a reference to yubaba's
//! [`super::PondRegistry`] to flip slots between Running ↔ Degraded ↔
//! Failed without dropping the lifecycle handles attached to the record.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use local_driver::ContainerLauncher;
use tokio::sync::Notify;
use tracing::{info, warn};

use super::{ProbeOutcome, SlotProbe};

const SLOT: &str = "object_store";

// Re-export so users of `yubaba::pond::minio::*` see [`MinioSpec`] /
// [`MinioRunning`] / [`ensure_minio_running`] / [`ensure_bucket_public`]
// alongside the reconciler. Cloud's reconciler uses the same types via
// `local_driver::pond_minio` directly.
pub use local_driver::pond_minio::{
    ensure_bucket_public, ensure_minio_running, MinioRunning, MinioSpec, MINIO_REGION,
};

/// How often the reconciler probes the MinIO health endpoint when the
/// slot is Running. Chosen so a stop→start of an external container
/// surfaces as Degraded within ~10 s without burning CPU on a healthy
/// slot.
const PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// After this many consecutive restart failures the slot transitions to
/// Failed and stops attempting restarts. Operator intervention required.
const MAX_RESTART_FAILURES: u32 = 3;

/// Per-workload reconciler: probe MinIO health on a tick and publish the
/// result into the registry.
///
/// Whether it also *restarts* the container depends on
/// [`daemon_supervised`](Self::daemon_supervised) — see [`MinioReconciler::run`].
///
/// Spawned by [`super::deploy`] right after the initial bring-up
/// succeeds, and torn down when the workload is shutdown.
pub(crate) struct MinioReconciler {
    pub launcher: Arc<dyn ContainerLauncher>,
    pub spec: MinioSpec,
    pub ident: String,
    pub registry: Arc<super::PondRegistry>,
    pub cancel: Arc<Notify>,
    /// True when the container daemon owns restart (pond deployed this slot
    /// through kamaji with a restart policy, R626-F2). The reconciler then
    /// probes and reports only — resurrecting here would fight dockerd and,
    /// worse, undo a deliberate operator stop.
    pub daemon_supervised: bool,
}

impl MinioReconciler {
    pub async fn run(self) {
        let mut consecutive_failures: u32 = 0;
        loop {
            tokio::select! {
                _ = self.cancel.notified() => {
                    tracing::debug!(ident = %self.ident, "MinioReconciler cancelled");
                    break;
                }
                _ = tokio::time::sleep(PROBE_INTERVAL) => {}
            }

            // `pond_probe_host()` — host.docker.internal when this yubaba
            // runs containerized (R454-F1); loopback on the host.
            let endpoint = format!(
                "http://{}:{}",
                local_driver::pond_probe_host(),
                self.spec.api_port
            );
            let health_url = format!("{endpoint}/minio/health/ready");
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let liveness = match probe_once(&health_url).await {
                Ok(()) => ProbeOutcome::Pass,
                Err(e) => {
                    let reason = format!("{e:#}");
                    warn!(
                        ident = %self.ident,
                        error = %reason,
                        "pond MinIO health probe failed",
                    );
                    ProbeOutcome::Fail { reason }
                }
            };

            self.registry
                .write_slot_probe(
                    &self.ident,
                    SlotProbe {
                        slot: SLOT.into(),
                        liveness: liveness.clone(),
                        readiness: liveness.clone(),
                        last_checked_at: now,
                        url: Some(health_url.clone()),
                    },
                )
                .await;

            if liveness == ProbeOutcome::Pass {
                consecutive_failures = 0;
                continue;
            }

            // Restart is the daemon's job (R626-F2): the container carries
            // `--restart unless-stopped`, so a crash is already being retried
            // and a stop was deliberate. Report, don't resurrect.
            if self.daemon_supervised {
                continue;
            }

            match ensure_minio_running(&self.launcher, &self.spec).await {
                Ok(_) => {
                    info!(ident = %self.ident, "pond MinIO restarted; back to Running");
                    consecutive_failures = 0;
                }
                Err(e) => {
                    consecutive_failures += 1;
                    let msg = format!("{e:#}");
                    warn!(
                        ident = %self.ident,
                        attempt = consecutive_failures,
                        max = MAX_RESTART_FAILURES,
                        error = %msg,
                        "pond MinIO restart failed",
                    );
                    if consecutive_failures >= MAX_RESTART_FAILURES {
                        self.registry
                            .mark_phase(
                                &self.ident,
                                super::PondPhase::Failed,
                                Some(format!(
                                    "MinIO restart failed {consecutive_failures} times: {msg}"
                                )),
                            )
                            .await;
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use local_driver::ContainerRunSpec;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts the launcher calls a reconciler makes. The only thing under test
    /// is *whether* the reconciler reaches for the launcher at all — that is
    /// exactly the supervision authority R626-F2 moves to the daemon.
    #[derive(Default)]
    struct CountingLauncher {
        runs: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ContainerLauncher for CountingLauncher {
        async fn ensure_image(&self, _image: &str) -> Result<bool> {
            Ok(false)
        }
        async fn run(&self, _spec: &ContainerRunSpec) -> Result<()> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn stop_and_remove(&self, _name: &str, _grace: Duration) -> Result<()> {
            Ok(())
        }
    }

    /// Points at a port nothing listens on, so every liveness probe fails and
    /// the restart branch is the one under test.
    fn dead_spec() -> MinioSpec {
        MinioSpec {
            image: "minio/minio:test".into(),
            user: "u".into(),
            password: "p".into(),
            // Port 1 is privileged and unbound — connection refused, fast.
            api_port: 1,
            console_port: 1,
            bucket: "b".into(),
            data_dir: PathBuf::from("/tmp/yah-pond-test/minio"),
            container_name: "yah-pond-test-object_store".into(),
            container_label: "test:pond:object_store".into(),
            ready_timeout: Duration::from_secs(1),
            network: None,
            network_alias: None,
        }
    }

    async fn run_one_tick(daemon_supervised: bool) -> usize {
        let launcher = Arc::new(CountingLauncher::default());
        let cancel = Arc::new(Notify::new());
        let reconciler = MinioReconciler {
            launcher: launcher.clone(),
            spec: dead_spec(),
            ident: "test".into(),
            registry: Arc::new(super::super::PondRegistry::new()),
            cancel: cancel.clone(),
            daemon_supervised,
        };
        let handle = tokio::spawn(reconciler.run());
        // One probe interval, then stop. The probe itself is a real (refused)
        // connection, so give the loop wall-clock time rather than pausing the
        // clock out from under reqwest.
        tokio::time::sleep(PROBE_INTERVAL + Duration::from_millis(500)).await;
        cancel.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
        launcher.runs.load(Ordering::SeqCst)
    }

    /// The migration's core claim: once the daemon owns restart, a failing
    /// probe must NOT make yubaba re-run the container. If it did, a deliberate
    /// `docker stop` would be undone within one probe interval — the exact bug
    /// R626 exists to fix.
    #[tokio::test]
    async fn daemon_supervised_reconciler_never_resurrects() {
        assert_eq!(run_one_tick(true).await, 0);
    }

    /// The fallback path (no kamaji wired) keeps its resurrect loop, so a
    /// yubaba running without a kamaji sibling is no worse off than before.
    #[tokio::test]
    async fn unsupervised_reconciler_still_restarts() {
        assert!(run_one_tick(false).await >= 1);
    }
}

async fn probe_once(url: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("building reqwest client for MinIO probe")?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        bail!("status {}", resp.status());
    }
    Ok(())
}
