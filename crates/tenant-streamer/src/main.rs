//! `yubaba-tenant-streamer` — the thin binary wrapper.
//!
//! Everything interesting is in the library (see the crate doc). This file
//! does three things and stops: load config, refuse to start against a sink
//! that cannot fence, and run the loop until a signal arrives.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use turso_backup::snapshot::BackupTarget;
use turso_backup::stream::{CoreWalSeam, StreamOutcome};
use workload_spec::TenantId;
use yubaba_tenant_streamer::streamer::TenantSink;
use yubaba_tenant_streamer::{
    build_store, verify_sink, HttpOwnership, RpoReporter, StreamerConfig, TenantStreamer,
    TenantTick,
};

#[derive(Parser)]
#[command(
    name = "yubaba-tenant-streamer",
    about = "Streams each owned tenant's WAL to object storage under yubaba's fencing epoch"
)]
struct Args {
    /// Path to the TOML config.
    #[arg(long, default_value = "/etc/yah/tenant-streamer.toml")]
    config: PathBuf,
    /// Validate config and probe the sink, then exit without streaming. This
    /// is the check to run in a deploy pipeline — it is the only way to learn
    /// that a bucket cannot fence before real tenants depend on it.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = StreamerConfig::load(&args.config)?;
    info!(
        node_id = config.node_id,
        tenants = config.tenants.len(),
        tail_interval_s = config.tail_interval().as_secs(),
        rpo_s = config.rpo_secs,
        "starting tenant streamer"
    );

    let store = build_store(&config.sink)?;

    let mut sinks: BTreeMap<TenantId, TenantSink> = BTreeMap::new();
    let mut seams: BTreeMap<TenantId, CoreWalSeam> = BTreeMap::new();
    for t in &config.tenants {
        let target = BackupTarget {
            store: store.clone(),
            prefix: config.key_prefix(&t.tenant)?,
        };
        // Before anything is streamed for this tenant, prove its sink can
        // actually fence. Per-tenant rather than once for the bucket because
        // the prefix is what a conditional put is scoped to, and a bucket
        // policy can differ by prefix.
        verify_sink(&target)
            .await
            .with_context(|| format!("verifying the sink for tenant {}", t.tenant.0))?;

        if !args.check {
            let db_path = config.db_path(t)?;
            let seam = CoreWalSeam::open(db_path.to_str().with_context(|| {
                format!("tenant {} db path {} is not valid UTF-8", t.tenant.0, db_path.display())
            })?)
            .with_context(|| format!("opening tenant {}'s local db", t.tenant.0))?;
            seams.insert(t.tenant.clone(), seam);
        }

        sinks.insert(
            t.tenant.clone(),
            TenantSink {
                target,
                base_snapshot_key: t.base_snapshot_key.clone(),
                page_size: t.page_size,
            },
        );
    }

    if args.check {
        info!(tenants = sinks.len(), "config valid and every sink enforces conditional puts");
        return Ok(());
    }

    let ownership = HttpOwnership::new(config.yubaba_url.clone(), config.node_id);
    // R782: same node-local base URL `ownership` already talks to — this
    // process discovers the leader itself before pushing (see the module doc
    // on `rpo_report::RpoReporter`).
    let rpo_reporter = Arc::new(RpoReporter::new(config.yubaba_url.clone(), config.node_id));
    let streamer = TenantStreamer::new(ownership, sinks, config);

    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        if let Err(e) = shutdown_signal().await {
            error!(error = %e, "signal handler failed; streamer will keep running");
            return;
        }
        info!("shutdown signal received; finishing the current pass");
        let _ = tx.send(true);
    });

    streamer
        .run(
            &seams,
            |tenant, tick| {
                log_tick(tenant, tick);
                report_rpo(&rpo_reporter, tenant, tick);
            },
            rx,
        )
        .await;
    info!("tenant streamer stopped");
    Ok(())
}

/// Push this tick's RPO status toward yubaba's leader (R782), if this tick
/// actually produced one — a tenant this node does not own, or one already
/// dropped/fenced, has nothing fresh to report, and reporting nothing simply
/// leaves the leader's registry aging forward from whatever it last heard
/// (the correct fail-closed reading — see `rpo_report`'s module doc).
///
/// Fire-and-forget: spawned so a slow or unreachable leader never delays the
/// next tail tick, matching `RpoReporter::report`'s own best-effort posture.
fn report_rpo(reporter: &Arc<RpoReporter>, tenant: &TenantId, tick: &TenantTick) {
    let TenantTick::Tailed { outcome, .. } = tick else {
        return;
    };
    let Some(rpo) = outcome.rpo() else {
        return;
    };
    let reporter = Arc::clone(reporter);
    let tenant = tenant.clone();
    let watermark_age = rpo.watermark_age;
    tokio::spawn(async move {
        reporter.report(&tenant, watermark_age).await;
    });
}

/// The metrics/alerting seam. Everything the loop learns comes through here.
fn log_tick(tenant: &TenantId, tick: &TenantTick) {
    let tenant = tenant.0.as_str();
    match tick {
        // The resting state for most tenants on most ticks — trace, or the log
        // is unreadable at any real tenant count.
        TenantTick::NotOwner => tracing::trace!(tenant, "not the owner; nothing attempted"),
        TenantTick::Dropped => tracing::trace!(tenant, "dropped after being fenced"),
        TenantTick::Tailed { epoch, outcome } => match outcome {
            StreamOutcome::Empty { rpo, .. } => {
                if rpo.breached {
                    // Nothing new to stream and the watermark is stale past
                    // the bound: the loop is not keeping its own promise.
                    warn!(tenant, epoch, age_s = rpo.watermark_age.map(|d| d.as_secs()),
                          "RPO breached with no new frames");
                } else {
                    tracing::trace!(tenant, epoch, "already current");
                }
            }
            StreamOutcome::Streamed { first_frame, last_frame, rpo, .. }
            | StreamOutcome::Restarted { first_frame, last_frame, rpo, .. } => {
                if rpo.breached {
                    warn!(tenant, epoch, first_frame, last_frame,
                          age_s = rpo.watermark_age.map(|d| d.as_secs()), "RPO breached");
                } else {
                    info!(tenant, epoch, first_frame, last_frame, "streamed");
                }
            }
            other => warn!(tenant, epoch, ?other, "tail returned a non-streaming outcome"),
        },
        // The one an operator actually wants paged on: this node's raft state
        // was behind reality and it tried to write as a stale owner.
        TenantTick::Fenced { our_epoch, current_epoch } => error!(
            tenant, our_epoch, current_epoch,
            "FENCED — this node is no longer the owner and has stopped streaming this tenant"
        ),
        TenantTick::Failed(e) => error!(tenant, error = %format!("{e:#}"), "tail failed"),
    }
}

/// SIGTERM as well as ctrl-c: kamaji stops a service with SIGTERM, and a
/// streamer that ignored it would be SIGKILLed mid-upload every restart.
async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r.context("installing SIGINT handler")?,
            _ = term.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("installing SIGINT handler")?;
        Ok(())
    }
}
