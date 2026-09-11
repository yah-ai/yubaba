//! `yubaba-tenant-streamer` — the thin binary wrapper.
//!
//! Everything interesting is in the library (see the crate doc). This file
//! does three things and stops: load config, refuse to start against a sink
//! that cannot fence, and run the loop until a signal arrives.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info, warn};
use turso_backup::snapshot::BackupTarget;
use turso_backup::stream::{CoreWalSeam, StreamOutcome};
use workload_spec::TenantId;
use yubaba_tenant_streamer::rebuild::{
    bump_pointer_generation, clear_tenant_fence, FenceClearance, FenceSource, PointerStep,
    RebuildOptions, SinkFence,
};
use yubaba_tenant_streamer::streamer::TenantSink;
use yubaba_tenant_streamer::{
    build_pointer_store, build_store, verify_sink, HttpOwnership, RpoReporter, StreamerConfig,
    TenantStreamer, TenantTick,
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
    /// Absent means "stream", which is what kamaji invokes.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Clear the R2 fence a destroyed cluster left behind (W339 / R869).
    ///
    /// Run this ONCE, on the rebuilt cluster, after `yubaba state restore` and
    /// the founding `raft init`, before starting any streamer. It bumps each
    /// tenant's global pointer generation, reads the epoch floor the dead fleet
    /// stamped into the sink, and lifts this cluster's epoch over it.
    Rebuild {
        /// Restrict to these tenants (repeatable). Default: every tenant in the
        /// config.
        #[arg(long = "tenant")]
        tenants: Vec<String>,
        /// Report what each tenant's fence stands at and stop. Writes nothing —
        /// no pointer bump, no raft entry. Run this first.
        #[arg(long)]
        dry_run: bool,
        /// Skip the pointer generation bump (step 1). Only correct when the
        /// tenant pointers live somewhere this config cannot reach.
        #[arg(long)]
        skip_pointer: bool,
        /// Ceiling on committed `ClaimTenant` entries per tenant.
        #[arg(long, default_value_t = RebuildOptions::default().max_claims)]
        max_claims: u64,
        /// Ceiling on fence reads per tenant before declaring the predecessor
        /// cluster alive.
        #[arg(long, default_value_t = RebuildOptions::default().max_rounds)]
        max_rounds: u32,
    },
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

    if let Some(Command::Rebuild {
        tenants,
        dry_run,
        skip_pointer,
        max_claims,
        max_rounds,
    }) = &args.command
    {
        return run_rebuild(
            &config,
            tenants,
            *dry_run,
            *skip_pointer,
            RebuildOptions {
                lease_secs: config.lease_secs,
                max_rounds: *max_rounds,
                max_claims: *max_claims,
            },
        )
        .await;
    }

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

/// `yubaba-tenant-streamer rebuild` — W339's procedure, once, over every
/// configured tenant.
///
/// Every tenant is attempted even after one fails, and the failures are
/// reported together at the end. A recovery that stopped at the first bad
/// tenant would make an operator discover the damage one restart at a time.
async fn run_rebuild(
    config: &StreamerConfig,
    only: &[String],
    dry_run: bool,
    skip_pointer: bool,
    opts: RebuildOptions,
) -> Result<()> {
    let selected = select_tenants(config, only)?;
    let store = build_store(&config.sink)?;
    // CONSTRUCTED off the runtime, not just used off it. `pointer_step` already
    // spawn_blocking's the pointer *calls*; building the store is the same
    // hazard one step earlier and was missed — `R2ObjectStore::new` builds a
    // `reqwest::blocking::Client`, whose constructor drops a temporary tokio
    // runtime, and `reqwest::blocking` asserts against that inside an async
    // context. Debug-only assert, so it never showed up in a release binary or
    // in a test that used an in-memory store — it showed up the first time
    // anyone ran `rebuild` from a `cargo build` checkout (R869-T2).
    let pointers: Option<Arc<dyn yah_object_store::ObjectStore>> = if skip_pointer {
        None
    } else {
        let sink = config.sink.clone();
        let store = tokio::task::spawn_blocking(move || build_pointer_store(&sink)).await??;
        Some(Arc::from(store))
    };
    let claims = HttpOwnership::new(config.yubaba_url.clone(), config.node_id);

    info!(
        tenants = selected.len(),
        node_id = config.node_id,
        dry_run,
        skip_pointer,
        "rebuild: clearing the sink fence a destroyed cluster left behind"
    );

    let mut failures = Vec::new();
    for tenant in &selected {
        if let Err(e) = rebuild_one(
            config,
            &store,
            pointers.as_ref(),
            &claims,
            tenant,
            dry_run,
            &opts,
        )
        .await
        {
            error!(tenant = tenant.0.as_str(), error = %format!("{e:#}"), "rebuild failed");
            failures.push(tenant.0.clone());
        }
    }

    if !failures.is_empty() {
        anyhow::bail!(
            "{} of {} tenants did not clear: {}. Nothing above them was rolled back — a pointer \
             bump and a granted epoch are both monotonic, so re-running this command after fixing \
             the cause is safe and costs only the entries it still needs.",
            failures.len(),
            selected.len(),
            failures.join(", "),
        );
    }
    if dry_run {
        info!("rebuild --dry-run complete; nothing was written");
    } else {
        info!(
            tenants = selected.len(),
            "rebuild complete — start the streamers"
        );
    }
    Ok(())
}

async fn rebuild_one(
    config: &StreamerConfig,
    store: &Arc<dyn object_store::ObjectStore>,
    pointers: Option<&Arc<dyn yah_object_store::ObjectStore>>,
    claims: &HttpOwnership,
    tenant: &TenantId,
    dry_run: bool,
    opts: &RebuildOptions,
) -> Result<()> {
    let name = tenant.0.as_str();
    let fence = SinkFence::new(BackupTarget {
        store: store.clone(),
        prefix: config.key_prefix(tenant)?,
    });

    // Step 1. Blocking IO on a blocking reqwest client, so it must not run on a
    // runtime worker thread — `R2ObjectStore` owns its own runtime internally
    // and panics if one is already driving the calling thread.
    if let Some(pointers) = pointers {
        let step = pointer_step(pointers, tenant, dry_run).await?;
        match step {
            PointerRead::Absent => info!(
                tenant = name,
                "no cell pointer — nothing to fence a resurrected node with (expected until \
                 R736-F6 mints pointer generations)"
            ),
            PointerRead::Read { cell, generation } => info!(
                tenant = name,
                cell, generation, "cell pointer read (dry run; not bumped)"
            ),
            PointerRead::Bumped {
                cell,
                before,
                after,
            } => info!(
                tenant = name,
                cell, before, after, "pointer generation bumped"
            ),
        }
    }

    // Steps 2 and 3.
    if dry_run {
        match fence.fence(tenant).await? {
            None => info!(tenant = name, "no sidecar — nothing has ever streamed here"),
            Some(state) => info!(
                tenant = name,
                floor = state.epoch,
                pointer_generation = state.pointer_generation,
                "sink fence; a rebuilt cluster needs epoch > floor to write"
            ),
        }
        return Ok(());
    }

    match clear_tenant_fence(&fence, claims, tenant, opts).await? {
        FenceClearance::NeverStreamed => {
            info!(
                tenant = name,
                "no sidecar — no fence to clear, nothing claimed"
            )
        }
        FenceClearance::Cleared {
            floor,
            epoch,
            claims,
            rounds,
        } => info!(
            tenant = name,
            floor, epoch, claims, rounds, "fence cleared; this cluster may write again"
        ),
    }
    Ok(())
}

/// What step 1 saw, flattened across the dry-run and the writing path.
enum PointerRead {
    Absent,
    Read {
        cell: String,
        generation: u64,
    },
    Bumped {
        cell: String,
        before: u64,
        after: u64,
    },
}

/// Run the synchronous pointer call off the runtime's worker threads.
async fn pointer_step(
    pointers: &Arc<dyn yah_object_store::ObjectStore>,
    tenant: &TenantId,
    dry_run: bool,
) -> Result<PointerRead> {
    let store = Arc::clone(pointers);
    let tenant = tenant.clone();
    tokio::task::spawn_blocking(move || {
        if dry_run {
            return Ok(
                match yubaba_tenant_streamer::read_pointer_generation(&*store, &tenant)? {
                    None => PointerRead::Absent,
                    Some((cell, generation)) => PointerRead::Read { cell, generation },
                },
            );
        }
        Ok(match bump_pointer_generation(&*store, &tenant)? {
            PointerStep::Absent => PointerRead::Absent,
            PointerStep::Bumped {
                cell,
                before,
                after,
            } => PointerRead::Bumped {
                cell,
                before,
                after,
            },
        })
    })
    .await
    .context("the pointer step panicked")?
}

/// Resolve `--tenant` against the config, refusing ids the config does not
/// know. A typo'd tenant that silently rebuilt nothing is the failure mode
/// here: the operator would read a green run as "the fence is clear".
fn select_tenants(config: &StreamerConfig, only: &[String]) -> Result<Vec<TenantId>> {
    if only.is_empty() {
        return Ok(config.tenants.iter().map(|t| t.tenant.clone()).collect());
    }
    let mut out = Vec::with_capacity(only.len());
    for id in only {
        let found = config
            .tenants
            .iter()
            .find(|t| t.tenant.0 == *id)
            .with_context(|| {
                format!(
                    "--tenant {id} is not in the config; configured tenants are: {}",
                    config
                        .tenants
                        .iter()
                        .map(|t| t.tenant.0.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        out.push(found.tenant.clone());
    }
    Ok(out)
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
