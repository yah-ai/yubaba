//! Per-node data-plane service: stream each owned tenant's WAL to object
//! storage under the fencing epoch yubaba's control plane grants this node.
//!
//! This is the wire between the two halves of the W245 fencing design.
//! yubaba's raft state machine mints the token
//! (`YubabaState::tenant_fencing_token`, R732-F1); turso-backup's
//! [`StreamConfig::epoch`] enforces it on the R2 write path (R732-F2/T3).
//! Neither half knew about the other before this crate existed.
//!
//! # Why a separate process
//!
//! The streamer runs as its own kamaji-managed service on each node, not as a
//! background task inside yubaba. Two reasons, and they point the same way:
//!
//! - **W253 tenet 1** separates the control plane from the data plane.
//!   Consensus governs metadata at a low write rate; tenant bytes move by
//!   async WAL streaming and never touch the raft log. Hosting the byte mover
//!   inside the consensus process couples their failure domains, their memory
//!   profiles, and their restart cadences for no benefit — a streamer restart
//!   would take a raft voter with it.
//! - **The litestream precedent.** yubaba already manages a WAL-shipping
//!   sidecar rather than shipping WAL in-process (`litestream.rs`). This is
//!   the same shape, for the same reason.
//!
//! Consequently this crate does **not** depend on the `yubaba` crate. It talks
//! to the node-local yubaba over HTTP and links neither axum nor openraft.
//!
//! # Shape
//!
//! A library with a thin binary wrapper. The tail loop is the library, so
//! R732-T5's split-brain chaos test drives it in-process against hand-driven
//! raft state machines without spawning a service or standing up a listener.
//!
//! This binary is also the seed of W253 §5/§7's node agent: the push side
//! (streaming) and readiness reporting ("streamer caught up" — [`rpo_report`],
//! R782, which W246/R737's placement driver consumes) are here now; the
//! puller fan-in (§5, one R2 reader per box rather than per replica) accretes
//! here later.
//!
//! # What is deliberately not here
//!
//! Placement. The tenant set is operator-supplied configuration until R737's
//! placement record exists — a node streams exactly the tenants it is
//! configured for, and ownership decides which of those are live.
//!
//! @arch:see(.yah/docs/working/W245-tenant-fencing-epochs.md)
//! @arch:see(.yah/docs/working/W253-tenant-db-platform-architecture.md)
//!
//! [`StreamConfig::epoch`]: turso_backup::stream::StreamConfig::epoch

pub mod config;
pub mod ownership;
pub mod rpo_report;
pub mod streamer;

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use object_store::aws::{AmazonS3Builder, S3ConditionalPut};
use turso_backup::snapshot::BackupTarget;
use turso_backup::stream::{probe_conditional_puts, PreconditionSupport};

pub use config::{SinkConfig, StreamerConfig, TenantConfig};
pub use ownership::{HttpOwnership, LeaseRenewal, Ownership, OwnershipSource};
pub use rpo_report::RpoReporter;
pub use streamer::{TenantSink, TenantStreamer, TenantTick};

/// Build the object store every tenant's sink hangs off.
///
/// `with_conditional_put(ETagMatch)` is asserted rather than assumed: it is
/// what makes `object_store` emit the `If-Match` / `If-None-Match` headers the
/// watermark CAS rests on. Setting it is necessary and *not sufficient* — the
/// backend still has to honour them, which is what [`verify_sink`] checks.
pub fn build_store(sink: &SinkConfig) -> Result<Arc<dyn object_store::ObjectStore>> {
    let access = env_var(sink.access_key_env.as_deref().unwrap_or("S3_ACCESS_KEY_ID"))?;
    let secret = env_var(sink.secret_key_env.as_deref().unwrap_or("S3_SECRET_ACCESS_KEY"))?;
    let store = AmazonS3Builder::new()
        .with_endpoint(&sink.endpoint)
        .with_bucket_name(&sink.bucket)
        .with_access_key_id(&access)
        .with_secret_access_key(&secret)
        .with_region(&sink.region)
        .with_conditional_put(S3ConditionalPut::ETagMatch)
        // Permissive: HTTPS endpoints stay TLS-signed; this only opts in to
        // plain-HTTP MinIO when the endpoint is http://. R2 and real S3 are
        // https:// and ride TLS regardless.
        .with_allow_http(true)
        .with_virtual_hosted_style_request(false)
        .build()
        .with_context(|| {
            format!("building the S3-shaped store for {} bucket={}", sink.endpoint, sink.bucket)
        })?;
    Ok(Arc::new(store))
}

/// Refuse to run against a sink that does not actually enforce conditional
/// puts.
///
/// R732-T3 made the watermark advance a compare-and-swap, and left one hole no
/// test can close: conditional-put support is a property of the deployed
/// backend, not of the code. Point `AmazonS3Builder` at a store that ignores
/// `If-Match` and every put silently succeeds, the CAS degrades to
/// last-write-wins, and the concurrent split-brain window W245 exists to shut
/// reopens — while the entire test suite stays green, because the in-memory
/// store used in tests does honour preconditions.
///
/// So the only guard that can exist is a runtime probe against the real
/// target, and the only safe response to a failed probe is to not start. A
/// streamer that ran anyway would be writing under a fence that isn't there.
pub async fn verify_sink(target: &BackupTarget) -> Result<()> {
    match probe_conditional_puts(target)
        .await
        .context("probing the sink for conditional-put support")?
    {
        PreconditionSupport::Honoured => Ok(()),
        PreconditionSupport::Degraded { stage } => bail!(
            "sink at prefix {:?} does not enforce {} — the watermark compare-and-swap would \
             silently degrade to last-write-wins and two owners could interleave frames. \
             Refusing to start. Check that the bucket supports conditional writes (R2 and \
             MinIO do; some S3-compatible backends do not).",
            target.prefix,
            stage.as_str(),
        ),
    }
}

fn env_var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} must be set (sink credentials come from \
         the environment, never from the config file)"))
}
