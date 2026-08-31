//! The tail loop: one pass per tick over every configured tenant, streaming
//! the ones this node currently owns under the epoch the control plane grants.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use anyhow::{Context, Result};
use turso_backup::snapshot::BackupTarget;
use turso_backup::stream::{tail_frames, StreamConfig, StreamOutcome, WalSeam};
use workload_spec::TenantId;

use crate::config::StreamerConfig;
use crate::ownership::{LeaseRenewal, Ownership, OwnershipSource};

/// Everything the loop needs to stream one tenant that is not ownership.
pub struct TenantSink {
    /// Object-store sink: the bucket + `tenants/<id>/` prefix this tenant's
    /// frames, manifests, and watermark live under.
    pub target: BackupTarget,
    pub base_snapshot_key: String,
    pub page_size: usize,
}

/// What one tenant's tick did.
#[derive(Debug)]
pub enum TenantTick {
    /// This node is not the live owner, so nothing was attempted. The ordinary
    /// resting state for every tenant a node is configured for but does not
    /// currently hold.
    NotOwner,
    /// A tail ran under `epoch`.
    Tailed { epoch: u64, outcome: StreamOutcome },
    /// The control plane refused a renewal, or the sink rejected a write:
    /// either way this node has been fenced and has dropped the tenant. It
    /// will not be attempted again until the process restarts or the tenant is
    /// re-adopted.
    Fenced { our_epoch: u64, current_epoch: u64 },
    /// Already dropped by an earlier `Fenced`. Reported rather than silently
    /// skipped so a "why is this tenant not streaming" question has an answer
    /// in the logs.
    Dropped,
    /// The tail itself failed (sink unreachable, WAL read error, yubaba down).
    /// Returned rather than propagated so one sick tenant cannot stop the loop
    /// for every other tenant on the box.
    Failed(anyhow::Error),
}

impl TenantTick {
    pub fn was_fenced(&self) -> bool {
        matches!(self, TenantTick::Fenced { .. })
    }
}

/// Streams every tenant this node owns, one pass per [`TenantStreamer::tick`].
pub struct TenantStreamer<O: OwnershipSource> {
    ownership: O,
    sinks: BTreeMap<TenantId, TenantSink>,
    config: StreamerConfig,
    /// Tenants this node has been fenced off. Stopping is not merely an
    /// optimisation: a fenced node that kept renewing would look healthy to
    /// every readiness gate in W253 §7 while being unable to write a byte.
    ///
    /// There is deliberately no "last renewed at" alongside this. Whether a
    /// renewal is due is computed from the lease deadline the control plane
    /// reports, which is the authoritative value; a local timestamp would be a
    /// second, drifting copy of it that could disagree after a clock step.
    dropped: Mutex<BTreeSet<TenantId>>,
}

impl<O: OwnershipSource> TenantStreamer<O> {
    pub fn new(ownership: O, sinks: BTreeMap<TenantId, TenantSink>, config: StreamerConfig) -> Self {
        Self { ownership, sinks, config, dropped: Mutex::new(BTreeSet::new()) }
    }

    pub fn config(&self) -> &StreamerConfig {
        &self.config
    }

    pub fn tenants(&self) -> impl Iterator<Item = &TenantId> {
        self.sinks.keys()
    }

    pub fn is_dropped(&self, tenant: &TenantId) -> bool {
        self.dropped.lock().unwrap().contains(tenant)
    }

    /// Stream one tenant, if this node currently owns it.
    ///
    /// `seam` is the live WAL of the local copy. It is passed in rather than
    /// opened here so the caller owns the engine connection's lifetime, and so
    /// a test can drive a fake WAL without a real database.
    ///
    /// The token is read *now*, immediately before the tail, and never cached
    /// across ticks. The freshness of that read is a performance concern, not
    /// a correctness one — see the [`crate::ownership`] module doc.
    pub async fn tick_tenant<S: WalSeam>(&self, tenant: &TenantId, seam: &S) -> TenantTick {
        match self.try_tick_tenant(tenant, seam).await {
            Ok(tick) => tick,
            Err(e) => TenantTick::Failed(e),
        }
    }

    async fn try_tick_tenant<S: WalSeam>(&self, tenant: &TenantId, seam: &S) -> Result<TenantTick> {
        if self.is_dropped(tenant) {
            return Ok(TenantTick::Dropped);
        }
        let Some(sink) = self.sinks.get(tenant) else {
            return Ok(TenantTick::NotOwner);
        };

        let standing = self
            .ownership
            .ownership(tenant)
            .await
            .with_context(|| format!("reading ownership of tenant {}", tenant.0))?;
        let Some(epoch) = standing.fencing_token else {
            return Ok(TenantTick::NotOwner);
        };

        // Renew before tailing, and only when the lease is actually running
        // down. Renewing first means a refusal stops us before we spend a
        // round trip on a write the sink would reject anyway.
        if let Some(tick) = self.maybe_renew(tenant, epoch, &standing).await? {
            return Ok(tick);
        }

        let owner = self.config.node_id.to_string();
        let cfg = StreamConfig {
            base_snapshot_key: &sink.base_snapshot_key,
            page_size: sink.page_size,
            backpressure: Default::default(),
            rpo_target: Some(self.config.rpo_target()),
            epoch,
            // Diagnostic only, and worth the allocation: when a stream is
            // fenced, the manifests are the only record of which node wrote
            // what, and a bare epoch does not answer that.
            owner: Some(&owner),
            // R736-T2: this streamer only knows the intra-cell raft epoch
            // today — there is no second cell yet (R736-T3) and no move
            // protocol handing it a global pointer generation to track
            // (R736-F4). `0` is the documented unfenced default; wire the
            // real value through once this node has a `PointerRecord` to
            // read.
            pointer_generation: 0,
        };
        let outcome = tail_frames(seam, &sink.target, &cfg)
            .await
            .with_context(|| format!("tailing tenant {} at epoch {epoch}", tenant.0))?;

        // The sink is the enforcement point. If it says we are stale, our
        // local raft read was behind reality — drop the tenant here rather
        // than re-attempting on every tick forever.
        if let StreamOutcome::Fenced { current_epoch, our_epoch, .. } = outcome {
            self.drop_tenant(tenant);
            return Ok(TenantTick::Fenced { our_epoch, current_epoch });
        }
        Ok(TenantTick::Tailed { epoch, outcome })
    }

    /// Renew the lease if it is due. `Ok(Some(..))` means the renewal was
    /// refused and the caller must stop; `Ok(None)` means carry on.
    async fn maybe_renew(
        &self,
        tenant: &TenantId,
        epoch: u64,
        standing: &Ownership,
    ) -> Result<Option<TenantTick>> {
        if standing.lease_remaining() > self.config.renew_when_remaining_below().as_secs() {
            return Ok(None);
        }
        match self
            .ownership
            .renew_lease(tenant, epoch, self.config.lease_secs)
            .await
            .with_context(|| format!("renewing the lease on tenant {}", tenant.0))?
        {
            LeaseRenewal::Renewed { .. } => Ok(None),
            LeaseRenewal::Fenced { current_epoch, .. } => {
                self.drop_tenant(tenant);
                Ok(Some(TenantTick::Fenced { our_epoch: epoch, current_epoch }))
            }
        }
    }

    fn drop_tenant(&self, tenant: &TenantId) {
        self.dropped.lock().unwrap().insert(tenant.clone());
    }

    /// One pass over every configured tenant, using the seam `seams` hands
    /// back for each. A tenant with no seam is skipped as
    /// [`TenantTick::NotOwner`] — "the local copy is not open here" and "this
    /// node does not own it" are the same non-event from here.
    pub async fn tick<S: WalSeam>(
        &self,
        seams: &BTreeMap<TenantId, S>,
    ) -> Vec<(TenantId, TenantTick)> {
        let mut out = Vec::new();
        for tenant in self.sinks.keys() {
            let tick = match seams.get(tenant) {
                Some(seam) => self.tick_tenant(tenant, seam).await,
                None => TenantTick::NotOwner,
            };
            out.push((tenant.clone(), tick));
        }
        out
    }

    /// Tail at the configured cadence until `shutdown` fires.
    ///
    /// Never propagates a per-tenant error: a streamer that exited on the
    /// first R2 hiccup would turn a transient fault into an indefinite RPO
    /// breach for every other tenant on the box. Failures surface through
    /// `on_tick`, which is where metrics and alerting hook in.
    pub async fn run<S, F>(
        &self,
        seams: &BTreeMap<TenantId, S>,
        mut on_tick: F,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) where
        S: WalSeam,
        F: FnMut(&TenantId, &TenantTick),
    {
        let mut shutdown = shutdown;
        loop {
            for (tenant, tick) in self.tick(seams).await {
                on_tick(&tenant, &tick);
            }
            tokio::select! {
                _ = tokio::time::sleep(self.config.tail_interval()) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SinkConfig, StreamerConfig};
    use crate::ownership::Ownership;
    use async_trait::async_trait;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use turso_backup::stream::{FrameInfo, Watermark};

    /// A WAL with a fixed number of frames. Enough for the loop's decisions —
    /// whether frames replay correctly is turso-backup's own test surface, and
    /// R732-T5 drives the real engine end to end.
    struct StubWal {
        frames: u64,
    }

    impl WalSeam for StubWal {
        fn wal_state(&self) -> anyhow::Result<Watermark> {
            Ok(Watermark { checkpoint_seq: 1, last_frame: self.frames })
        }
        fn wal_get_frame(&self, frame_no: u64, buf: &mut [u8]) -> anyhow::Result<FrameInfo> {
            let info = FrameInfo { page_no: frame_no as u32, db_size: frame_no as u32 };
            buf[0..4].copy_from_slice(&info.page_no.to_be_bytes());
            buf[4..8].copy_from_slice(&info.db_size.to_be_bytes());
            buf[8..].fill(0);
            Ok(info)
        }
        fn wal_auto_actions_disable(&self) {}
    }

    /// A scripted control plane. Counts renewals so the pacing assertions can
    /// see them.
    struct StubOwnership {
        token: Option<u64>,
        lease_expires: u64,
        now: u64,
        renewal: LeaseRenewal,
        renewals: AtomicUsize,
    }

    impl StubOwnership {
        fn owning(token: u64, lease_remaining: u64) -> Self {
            Self {
                token: Some(token),
                lease_expires: 1_000_000 + lease_remaining,
                now: 1_000_000,
                renewal: LeaseRenewal::Renewed { epoch: token },
                renewals: AtomicUsize::new(0),
            }
        }
        fn unowned() -> Self {
            Self {
                token: None,
                lease_expires: 0,
                now: 1_000_000,
                renewal: LeaseRenewal::Renewed { epoch: 0 },
                renewals: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl OwnershipSource for StubOwnership {
        async fn ownership(&self, _tenant: &TenantId) -> Result<Ownership> {
            Ok(Ownership {
                fencing_token: self.token,
                lease_expires: self.lease_expires,
                now: self.now,
            })
        }
        async fn renew_lease(
            &self,
            _tenant: &TenantId,
            _epoch: u64,
            _lease_secs: u64,
        ) -> Result<LeaseRenewal> {
            self.renewals.fetch_add(1, Ordering::SeqCst);
            Ok(self.renewal)
        }
    }

    fn config() -> StreamerConfig {
        StreamerConfig {
            node_id: 7,
            yubaba_url: "http://127.0.0.1:1".into(),
            data_root: PathBuf::from("/tmp"),
            sink: SinkConfig {
                bucket: "b".into(),
                endpoint: "http://e".into(),
                region: "auto".into(),
                prefix: String::new(),
                access_key_env: None,
                secret_key_env: None,
            },
            tenants: vec![],
            rpo_secs: 30,
            lease_secs: 300,
        }
    }

    fn tenant() -> TenantId {
        TenantId("acme".into())
    }

    fn sinks() -> BTreeMap<TenantId, TenantSink> {
        let target = BackupTarget {
            store: std::sync::Arc::new(object_store::memory::InMemory::new()),
            prefix: "tenants/acme".into(),
        };
        BTreeMap::from([(
            tenant(),
            TenantSink { target, base_snapshot_key: "base.db".into(), page_size: 4096 },
        )])
    }

    /// A tenant this node does not own is never attempted — no sink call, no
    /// renewal, nothing. The resting state for most tenants on most ticks.
    #[tokio::test]
    async fn a_tenant_this_node_does_not_own_is_never_attempted() {
        let s = TenantStreamer::new(StubOwnership::unowned(), sinks(), config());
        let tick = s.tick_tenant(&tenant(), &StubWal { frames: 5 }).await;
        assert!(matches!(tick, TenantTick::NotOwner), "{tick:?}");
    }

    /// The pacing property W253 §4 demands: a healthy lease is NOT renewed on
    /// every tick. Renewing per tail would put a write rate proportional to
    /// tenants × tail rate through the raft log, which that section forbids.
    #[tokio::test]
    async fn a_healthy_lease_is_not_renewed_on_every_tick() {
        // 300s lease, 250s remaining — well above the 100s threshold.
        let s = TenantStreamer::new(StubOwnership::owning(3, 250), sinks(), config());
        for _ in 0..5 {
            s.tick_tenant(&tenant(), &StubWal { frames: 2 }).await;
        }
        assert_eq!(
            s.ownership.renewals.load(Ordering::SeqCst),
            0,
            "five ticks against a healthy lease must produce zero raft writes"
        );
    }

    /// ...but a lease running down IS renewed, or the node loses tenants it
    /// legitimately owns on a timer.
    #[tokio::test]
    async fn a_lease_below_the_threshold_is_renewed() {
        // 90s remaining, under the 100s (lease/3) threshold.
        let s = TenantStreamer::new(StubOwnership::owning(3, 90), sinks(), config());
        s.tick_tenant(&tenant(), &StubWal { frames: 2 }).await;
        assert_eq!(s.ownership.renewals.load(Ordering::SeqCst), 1);
    }

    /// A refused renewal means this node's local raft read was behind reality.
    /// It must stop renewing AND stop streaming: a fenced node that kept its
    /// lease alive would pass every W253 §7 readiness gate while being unable
    /// to write a byte.
    #[tokio::test]
    async fn a_refused_renewal_drops_the_tenant_and_stops_all_further_attempts() {
        let mut own = StubOwnership::owning(1, 10);
        own.renewal = LeaseRenewal::Fenced { current_epoch: 9, current_owner: Some(2) };
        let s = TenantStreamer::new(own, sinks(), config());

        let tick = s.tick_tenant(&tenant(), &StubWal { frames: 3 }).await;
        assert!(
            matches!(tick, TenantTick::Fenced { our_epoch: 1, current_epoch: 9 }),
            "{tick:?}"
        );
        assert!(s.is_dropped(&tenant()));

        // The drop is sticky. A second tick must not re-attempt the renewal —
        // retrying forever is how a fenced node keeps hammering the leader.
        let again = s.tick_tenant(&tenant(), &StubWal { frames: 3 }).await;
        assert!(matches!(again, TenantTick::Dropped), "{again:?}");
        assert_eq!(
            s.ownership.renewals.load(Ordering::SeqCst),
            1,
            "a dropped tenant must not keep renewing"
        );
    }

    /// The sink is the enforcement point, and its verdict is authoritative
    /// over our local raft read. A `Fenced` outcome from `tail_frames` drops
    /// the tenant even though the control plane still says we own it — which
    /// is exactly the partitioned-node case: locally we look like the owner,
    /// and only the sink knows better.
    #[tokio::test]
    async fn a_fenced_outcome_from_the_sink_drops_the_tenant_despite_a_live_local_token() {
        let sinks = sinks();
        // Stage the sink at a higher epoch than ours, as a real new owner
        // would have left it.
        let target = &sinks.get(&tenant()).unwrap().target;
        turso_backup::stream::tail_frames(
            &StubWal { frames: 2 },
            target,
            &StreamConfig {
                base_snapshot_key: "base.db",
                page_size: 4096,
                backpressure: Default::default(),
                rpo_target: None,
                epoch: 9,
                owner: Some("node-9"),
                pointer_generation: 0,
            },
        )
        .await
        .unwrap();

        // We still hold a live lease at epoch 1 — the control plane has no
        // idea anything is wrong.
        let s = TenantStreamer::new(StubOwnership::owning(1, 250), sinks, config());
        let tick = s.tick_tenant(&tenant(), &StubWal { frames: 5 }).await;
        assert!(
            matches!(tick, TenantTick::Fenced { our_epoch: 1, current_epoch: 9 }),
            "{tick:?}"
        );
        assert!(s.is_dropped(&tenant()), "the sink's verdict must stick");
    }

    /// A tenant with no local copy open is a non-event, not an error. It must
    /// not take down the pass for every other tenant on the box.
    #[tokio::test]
    async fn a_tenant_with_no_open_seam_is_skipped_without_failing_the_pass() {
        let s = TenantStreamer::new(StubOwnership::owning(1, 250), sinks(), config());
        let seams: BTreeMap<TenantId, StubWal> = BTreeMap::new();
        let ticks = s.tick(&seams).await;
        assert_eq!(ticks.len(), 1);
        assert!(matches!(ticks[0].1, TenantTick::NotOwner), "{:?}", ticks[0].1);
    }

    /// The ordinary success path, asserted so the fencing tests above are
    /// known to be failing for the right reason.
    #[tokio::test]
    async fn an_owned_tenant_streams_under_the_granted_epoch() {
        let s = TenantStreamer::new(StubOwnership::owning(4, 250), sinks(), config());
        let tick = s.tick_tenant(&tenant(), &StubWal { frames: 3 }).await;
        match tick {
            TenantTick::Tailed { epoch, outcome: StreamOutcome::Streamed { last_frame, .. } } => {
                assert_eq!(epoch, 4);
                assert_eq!(last_frame, 3);
            }
            other => panic!("expected a stream under epoch 4, got {other:?}"),
        }
        assert!(!s.is_dropped(&tenant()));
    }

    /// The RPO bound reaches turso-backup rather than being a number the
    /// streamer keeps to itself — otherwise `RpoStatus::breached` is always
    /// false and the drift reporting is decorative.
    #[tokio::test]
    async fn the_configured_rpo_target_reaches_the_outcome() {
        let s = TenantStreamer::new(StubOwnership::owning(4, 250), sinks(), config());
        let tick = s.tick_tenant(&tenant(), &StubWal { frames: 1 }).await;
        match tick {
            TenantTick::Tailed { outcome: StreamOutcome::Streamed { rpo, .. }, .. } => {
                assert_eq!(rpo.target, Some(std::time::Duration::from_secs(30)));
            }
            other => panic!("expected a stream, got {other:?}"),
        }
    }
}
