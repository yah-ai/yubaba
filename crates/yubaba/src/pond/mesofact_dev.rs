//! Yubaba's mesofact-dev supervision loop for the pond tier (R455-F3, W180 Phase D).
//!
//! Mirrors [`super::minio::MinioReconciler`]: probe HTTP liveness on a tick,
//! flip `PondPhase` Running ↔ Degraded, restart the container on failure.
//! After [`MAX_RESTART_FAILURES`] consecutive restart failures the slot
//! transitions to `Failed`.
//!
//! Additionally runs a readiness probe on both ports each tick when liveness
//! passes. Phase D logs readiness failures only; Phase E (R456-F1) will surface
//! them as per-slot `SlotProbe` entries in `PondStateRecord`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use local_driver::pond_mesofact_dev::{ensure_mesofact_dev_running, MesofactDevSpec};
use local_driver::LocalRuntime;
use tokio::sync::Notify;
use tracing::{info, warn};

use super::{ProbeOutcome, SlotProbe};

const SLOT: &str = "mesofact_dev";

const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RESTART_FAILURES: u32 = 3;

/// Yubaba's in-memory handle for a managed mesofact-dev container.
/// Stored inside `RegistryEntry` while the workload is registered.
pub(crate) struct MesofactDevSupervision {
    pub runtime: Arc<LocalRuntime>,
    pub container_name: String,
    pub cancel: Arc<Notify>,
}

/// Per-workload reconciler: probe mesofact-dev liveness + readiness, restart
/// on liveness failure, tear down cleanly on cancel.
pub(crate) struct MesofactDevReconciler {
    pub runtime: Arc<LocalRuntime>,
    pub spec: MesofactDevSpec,
    pub ident: String,
    pub registry: Arc<super::PondRegistry>,
    pub cancel: Arc<Notify>,
}

impl MesofactDevReconciler {
    pub async fn run(self) {
        let mut consecutive_failures: u32 = 0;
        loop {
            tokio::select! {
                _ = self.cancel.notified() => {
                    tracing::debug!(ident = %self.ident, "MesofactDevReconciler cancelled");
                    break;
                }
                _ = tokio::time::sleep(PROBE_INTERVAL) => {}
            }

            let liveness_url = format!(
                "http://127.0.0.1:{}{}",
                self.spec.almanac_port, self.spec.liveness_path,
            );
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let liveness = match probe_once(&liveness_url).await {
                Ok(()) => ProbeOutcome::Pass,
                Err(e) => {
                    let reason = format!("{e:#}");
                    warn!(
                        ident = %self.ident,
                        error = %reason,
                        "pond mesofact-dev liveness probe failed",
                    );
                    ProbeOutcome::Fail { reason }
                }
            };

            // Readiness: AND of almanac + issues readiness paths.
            let readiness = if liveness == ProbeOutcome::Pass {
                let almanac_readyz = format!(
                    "http://127.0.0.1:{}{}",
                    self.spec.almanac_port, self.spec.readiness_path,
                );
                let issues_readyz = format!(
                    "http://127.0.0.1:{}{}",
                    self.spec.issues_port, self.spec.readiness_path,
                );
                let mut outcome = ProbeOutcome::Pass;
                for (label, url) in [
                    ("almanac-serve", almanac_readyz.as_str()),
                    ("issue-tracker", issues_readyz.as_str()),
                ] {
                    if let Err(e) = probe_once(url).await {
                        let reason = format!("{e:#}");
                        warn!(
                            ident = %self.ident,
                            slot = label,
                            error = %reason,
                            "pond mesofact-dev readiness probe failed (no restart)",
                        );
                        outcome = ProbeOutcome::Fail { reason };
                        break;
                    }
                }
                outcome
            } else {
                ProbeOutcome::Pending
            };

            self.registry
                .write_slot_probe(
                    &self.ident,
                    SlotProbe {
                        slot: SLOT.into(),
                        liveness: liveness.clone(),
                        readiness,
                        last_checked_at: now,
                        url: Some(liveness_url.clone()),
                    },
                )
                .await;

            if liveness == ProbeOutcome::Pass {
                consecutive_failures = 0;
                continue;
            }

            match ensure_mesofact_dev_running(&self.runtime, &self.spec).await {
                Ok(_) => {
                    info!(ident = %self.ident, "pond mesofact-dev restarted; back to Running");
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
                        "pond mesofact-dev restart failed",
                    );
                    if consecutive_failures >= MAX_RESTART_FAILURES {
                        self.registry
                            .mark_phase(
                                &self.ident,
                                super::PondPhase::Failed,
                                Some(format!(
                                    "mesofact-dev restart failed {consecutive_failures} times: {msg}"
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
        .context("building reqwest client for mesofact-dev probe")?;
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
