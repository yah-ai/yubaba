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
use local_driver::LocalRuntime;
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

/// Per-workload reconciler: probe MinIO health on a tick, flip
/// `PondPhase` Running ↔ Degraded, restart the container when it falls
/// over. Marks the workload Failed after [`MAX_RESTART_FAILURES`]
/// consecutive restart failures.
///
/// Spawned by [`super::deploy`] right after the initial bring-up
/// succeeds, and torn down when the workload is shutdown.
pub(crate) struct MinioReconciler {
    pub runtime: Arc<LocalRuntime>,
    pub spec: MinioSpec,
    pub ident: String,
    pub registry: Arc<super::PondRegistry>,
    pub cancel: Arc<Notify>,
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

            let endpoint = format!("http://127.0.0.1:{}", self.spec.api_port);
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

            match ensure_minio_running(&self.runtime, &self.spec).await {
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
