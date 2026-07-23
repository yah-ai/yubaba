//! Yubaba-side miniflare container slot for the pond tier
//! (R374-F4 → R455-F1).
//!
//! Analogous to [`super::minio::MinioReconciler`]: probe HTTP liveness on a
//! tick, mark the workload Degraded on failure, restart via
//! [`ensure_miniflare_running`], and mark Failed after
//! [`MAX_RESTART_FAILURES`] consecutive restart failures.
//!
//! R455-F1 swapped the host-side `bun miniflare-sim.mjs` process for the
//! `yah-miniflare` container so miniflare joins the per-cell
//! `yah-pond-<svc>-<env>` docker bridge. The reconciler shape became
//! identical to MinIO's — no more `Child` handle, no SIGTERM dance, no
//! `kill_on_drop` orphans to worry about; `docker stop` does both.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use local_driver::pond_miniflare::{ensure_miniflare_running, MiniflareSpec};
use local_driver::ContainerLauncher;
use tokio::sync::Notify;
use tracing::{info, warn};

use super::{ProbeOutcome, SlotProbe};

const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RESTART_FAILURES: u32 = 3;
const SLOT: &str = "static";

/// Yubaba's in-memory handle for a managed miniflare container.
/// Stored inside `RegistryEntry` while the workload is registered.
pub(crate) struct MiniflareSupervision {
    pub launcher: Arc<dyn ContainerLauncher>,
    pub container_name: String,
    pub cancel: Arc<Notify>,
}

/// Per-workload reconciler: probe miniflare HTTP, restart on failure, tear
/// down the container cleanly on cancel.
pub(crate) struct MiniflareReconciler {
    pub launcher: Arc<dyn ContainerLauncher>,
    pub spec: MiniflareSpec,
    pub ident: String,
    pub registry: Arc<super::PondRegistry>,
    pub cancel: Arc<Notify>,
    /// True when the container daemon owns restart (pond deployed this slot
    /// through kamaji with a restart policy, R626-F2). The reconciler then
    /// probes and reports only — resurrecting here would fight dockerd and,
    /// worse, undo a deliberate operator stop.
    pub daemon_supervised: bool,
}

impl MiniflareReconciler {
    pub async fn run(self) {
        let mut consecutive_failures: u32 = 0;
        loop {
            tokio::select! {
                _ = self.cancel.notified() => {
                    tracing::debug!(ident = %self.ident, "MiniflareReconciler cancelled");
                    break;
                }
                _ = tokio::time::sleep(PROBE_INTERVAL) => {}
            }

            let probe_url = format!(
                "http://{}:{}/",
                local_driver::pond_probe_host(),
                self.spec.port
            );
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let liveness = match probe_miniflare(self.spec.port).await {
                Ok(()) => ProbeOutcome::Pass,
                Err(e) => {
                    let reason = format!("{e:#}");
                    warn!(
                        ident = %self.ident,
                        port = self.spec.port,
                        error = %reason,
                        "pond miniflare health probe failed",
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
                        url: Some(probe_url),
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

            match ensure_miniflare_running(&self.launcher, &self.spec).await {
                Ok(_) => {
                    info!(ident = %self.ident, "pond miniflare restarted; back to Running");
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
                        "pond miniflare restart failed",
                    );
                    if consecutive_failures >= MAX_RESTART_FAILURES {
                        self.registry
                            .mark_phase(
                                &self.ident,
                                super::PondPhase::Failed,
                                Some(format!(
                                    "miniflare restart failed {consecutive_failures} times: {msg}"
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

/// Single HTTP probe (2 s timeout). Returns `Ok(())` on any non-server-error
/// response — 2xx and 4xx both mean the Worker is up.
async fn probe_miniflare(port: u16) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("building reqwest client for miniflare probe")?;
    // `pond_probe_host()` — host.docker.internal when this yubaba runs
    // containerized (R454-F1); loopback on the host.
    let url = format!("http://{}:{port}/", local_driver::pond_probe_host());
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if resp.status().is_server_error() {
        bail!("status {}", resp.status());
    }
    Ok(())
}
