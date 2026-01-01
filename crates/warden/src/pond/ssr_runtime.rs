//! Warden's SSR-runtime supervision loop for the pond tier (R434-F4).
//!
//! Mirrors [`super::minio::MinioReconciler`]: probe the container's HTTP
//! readiness endpoint on a tick, flip `PondPhase` Running ↔ Degraded, restart
//! the container when it falls over. After [`MAX_RESTART_FAILURES`]
//! consecutive restart failures the slot transitions to `Failed` and stops
//! attempting restarts.
//!
//! Bring-up primitives live in `local_driver::pond_ssr_runtime` so the warden
//! path and any cloud-direct path share them.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use local_driver::pond_ssr_runtime::{ensure_ssr_runtime_running, SsrRuntimeSpec};
use local_driver::LocalRuntime;
use tokio::sync::Notify;
use tracing::{info, warn};

pub use local_driver::pond_ssr_runtime::{
    lower_workload_spec, SsrRuntimeRunning, DEFAULT_SSR_CONTAINER_PORT,
};

use super::{ProbeOutcome, SlotProbe};

const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RESTART_FAILURES: u32 = 3;
const SLOT: &str = "ssr_runtime";

/// Warden's per-workload supervision over the SSR-runtime container. Lives
/// inside [`super::RegistryEntry`] while the workload is registered.
pub(crate) struct SsrRuntimeSupervision {
    pub runtime: Arc<LocalRuntime>,
    pub container_name: String,
    pub cancel: Arc<Notify>,
}

/// Per-workload reconciler: probe the SSR runtime's HTTP readiness path on a
/// tick, flip `PondPhase`, restart the container on failure.
pub(crate) struct SsrRuntimeReconciler {
    pub runtime: Arc<LocalRuntime>,
    pub spec: SsrRuntimeSpec,
    pub ident: String,
    pub registry: Arc<super::PondRegistry>,
    pub cancel: Arc<Notify>,
}

impl SsrRuntimeReconciler {
    pub async fn run(self) {
        let mut consecutive_failures: u32 = 0;
        loop {
            tokio::select! {
                _ = self.cancel.notified() => {
                    tracing::debug!(ident = %self.ident, "SsrRuntimeReconciler cancelled");
                    break;
                }
                _ = tokio::time::sleep(PROBE_INTERVAL) => {}
            }

            let probe_url = format!(
                "http://127.0.0.1:{}{path}",
                self.spec.host_port,
                path = self.spec.ready_path,
            );
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let liveness = match probe_once(&probe_url).await {
                Ok(()) => ProbeOutcome::Pass,
                Err(e) => {
                    let reason = format!("{e:#}");
                    warn!(
                        ident = %self.ident,
                        error = %reason,
                        "pond SSR-runtime health probe failed",
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
                        url: Some(probe_url.clone()),
                    },
                )
                .await;

            if liveness == ProbeOutcome::Pass {
                consecutive_failures = 0;
                continue;
            }

            match ensure_ssr_runtime_running(&self.runtime, &self.spec).await {
                Ok(_) => {
                    info!(ident = %self.ident, "pond SSR-runtime restarted; back to Running");
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
                        "pond SSR-runtime restart failed",
                    );
                    if consecutive_failures >= MAX_RESTART_FAILURES {
                        self.registry
                            .mark_phase(
                                &self.ident,
                                super::PondPhase::Failed,
                                Some(format!(
                                    "SSR-runtime restart failed {consecutive_failures} times: {msg}"
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
        .context("building reqwest client for SSR-runtime probe")?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let s = resp.status();
    // Same generous criterion as the bring-up probe: anything non-5xx counts
    // as alive — many SSR apps return 404 at `/` because they only declare
    // `/api/*` routes.
    if s.is_server_error() {
        bail!("status {s}");
    }
    Ok(())
}
