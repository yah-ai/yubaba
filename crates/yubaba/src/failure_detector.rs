//! Failure detection as a port — "is that node still there?" asked of
//! something swappable, rather than answered inline from raft metrics.
//!
//! Raft has an opinion about liveness, but it is a narrow one: a node is alive
//! if it acknowledged the leader's last AppendEntries. That is exactly the
//! right evidence for deciding whether a *write* can commit, and it is the only
//! evidence yubaba has today — so [`RaftHeartbeatDetector`] ships here as the
//! default and the fleet keeps behaving as it did.
//!
//! It is not the only possible evidence. A deployment where nodes share a
//! second channel — a local radio link, a power-rail sense line, an out-of-band
//! management network — can corroborate or contradict the raft view, and can
//! often answer sooner and with fewer false positives than a heartbeat timeout
//! on a congested link. Such a detector is deployment-specific and does not
//! belong in this crate; the [`FailureDetector`] trait is the seam it plugs
//! into, wired via [`ServerState::with_failure_detector`].
//!
//! [`ServerState::with_failure_detector`]: crate::ServerState::with_failure_detector
//!
//! # Reporting, not reacting
//!
//! Nothing here *acts* on a verdict. Raft continues to run its own elections
//! off its own timers; a detector's job is to answer the question for a
//! consumer that has to make a placement or reporting decision — today
//! `GET /raft/status`, which is how an operator sees which peers a leader has
//! actually heard from and when. Keeping the detector out of the consensus loop
//! is deliberate: a detector that could unseat a leader would be a second,
//! unproven consensus mechanism racing the real one.
//!
//! @yah:ticket(R737-F2, "Lease layer + readiness gates on the existing FailureDetector seam (today's only detector reads raft heartbeats)")
//! @yah:status(review)
//! @yah:at(2026-08-19T01:42:00Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P3)
//! @yah:parent(R737)
//! @yah:next("Tier: Warrior — the seam is right but its only evidence source is the one W253 section 7 says not to trust; correcting that is design work, not wiring.")
//! @yah:next("SEAM ALREADY EXISTS: failure_detector.rs ships the FailureDetector trait, NodeLiveness{Live,Suspect,Down,Unknown}, RaftHeartbeatDetector, LivenessThresholds derived from ClusterPolicy (suspect after 3 heartbeats, down after 10), and ServerState::with_failure_detector. Do not rebuild it.")
//! @yah:next("Add: nodes renew a coarse TTL lease on a MONOTONIC clock; only up->down TRANSITIONS commit to raft, never renewals; hysteresis so WAN jitter cannot cause failover storms.")
//! @yah:next("Readiness gates live here too — a node may own a tenant only if its streamer is caught up within bound, the tenant is hydrated, it is within headroom, and its raft peer is healthy. R574-T4's RpoStatus.watermark_age is the caught-up-within-bound signal; it already exists.")
//! @yah:gotcha("The shipped detector is deliberately REPORTING-ONLY ('nothing here acts on a verdict') and its only implementation, RaftHeartbeatDetector, derives liveness from raft AppendEntries acks — precisely the evidence source W246 and W253 section 7 say the scheduler must NOT use. It also reports Unknown for every peer when running on a follower, since only the leader tracks acks. So a leader-resident scheduler is the only viable consumer, and a lease-based detector must be added rather than assumed.")
//! @yah:handoff("New oss/yubaba/crates/yubaba/src/lease_detector.rs: LeaseFailureDetector implements the existing FailureDetector trait on a SECOND, non-raft evidence channel (channel()==\"node-lease\"), reusing failure_detector::judge_silence against the same ClusterPolicy-derived LivenessThresholds. Nodes push renewals via POST /mesh/lease-renew (new route + handler mesh_lease_renew in lib.rs); the registry is Instant-keyed (monotonic clock, never wall time).")
//! @yah:handoff("TransitionTracker: hysteresis/debounce on top of the raw per-tick FailureDetector output. Only a CONFIRMED flip (sustained past a dwell window, asymmetric: down_after to declare Down, suspect_after to trust a recovery) is returned from observe() -- single blips, Suspect samples, and Unknown samples never move or reset an in-progress candidate. This is the 'only up->down TRANSITIONS commit to raft, never renewals' piece from the ticket, expressed as the API a scheduler calls once/tick; it does not itself write to raft (see next).")
//! @yah:handoff("judge_readiness(ReadinessInputs) -> Result<(), NotReady>: pure function for W253 §7's four gates (confirmed-live, raft peer healthy, hydrated, within headroom) plus a streamer-caught-up-within-bound gate taking a bare Option<Duration> watermark_age/rpo_bound rather than turso_backup::stream::RpoStatus itself -- deliberately no data-plane dependency added to this control-plane crate, mirroring the rule tenant_streamer::ownership already states in the other direction. No RPO target configured is vacuously satisfied; a target with no watermark ever persisted is NOT ready (absence of evidence != caught up).")
//! @yah:handoff("Wiring: ServerState gained lease_detector: Option<Arc<LeaseFailureDetector>> + with_lease_detector(), initialized None in load(). main.rs attaches it alongside RaftHeartbeatDetector using the same policy.liveness_thresholds(). GET /raft/status gained a lease_liveness section (same shape as the existing liveness section, kept as a SEPARATE key/section on purpose -- liveness stays raft-heartbeat evidence for the operator view; lease_liveness is what a scheduler is allowed to trust).")
//! @yah:handoff("14 new unit tests in lease_detector.rs (renewal freshness, absent-not-down, hysteresis debounce for both directions incl. Suspect/Unknown not resetting dwell, and the full judge_readiness gate matrix) all using synthetic Instant arithmetic (t0 + Duration), no real sleeps. Full verify below.")
//! @yah:handoff("DISCOVERED WORK: hit the documented orphan-gc symptom (missing libsqlite3-sys OUT_DIR bindgen.rs) mid-session -- cargo orphan-gc log did not name it (recorded as an inconclusive occurrence on R770's gotcha per the CLAUDE.md protocol), cleaned only the two stale libsqlite3-sys build+fingerprint dirs (not a full target clean), rebuild succeeded clean after.")
//! @yah:handoff("Tree anchor at handoff: b2157985a18b0046529cd1e15fd0787caf10ea47 — the shared tree as I left it. Diff against it (`git diff b2157985a18b0046529cd1e15fd0787caf10ea47..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("R737-F3 (scheduler loop) is the actual consumer: own one TransitionTracker on the leader, call .observe(lease_detector.observe(), policy, Instant::now()) once/tick, and decide what a returned (node, Confirmed::Down) flip means for raft writes -- this ticket deliberately stopped short of adding a new YubabaRequest variant to persist a down-transition, since the scheduler is what knows what a confirmed-down node should trigger (re-placement) and what should merely be logged for the next leader to rebuild from.")
//! @yah:next("Not wired yet: nothing calls POST /mesh/lease-renew in production -- no renewal-loop client exists (the streamer's ownership.rs renew_lease is the DIFFERENT per-tenant fencing lease from R732, not this node-liveness one). A node-side loop (likely in main.rs's serve task set, alongside member_registration::spawn) needs to POST its own node_id to the current leader's /mesh/lease-renew periodically, discovering the leader the same way raft/write forwarding does.")
//! @yah:next("readiness_gate's streamer_watermark_age/streamer_rpo_bound inputs are not sourced from anything live yet -- R574-T4's RpoStatus exists on the streamer side but nothing plumbs it from a running tenant-streamer process back to the leader's placement decision. That plumbing (likely another HTTP pull, mirroring GET /tenants/{id}) is unscoped work for whoever builds the scheduler's placement-candidate loop.")
//! @yah:verify("cargo check -p yubaba (clean)")
//! @yah:verify("cargo check -p yubaba --bin yubaba (clean, covers main.rs wiring)")
//! @yah:verify("cargo test -p yubaba --lib = 465 passed, 0 failed, 0 ignored")
//! @yah:verify("cargo clippy -p yubaba --lib | grep lease_detector = no output (the -D warnings run surfaced only pre-existing debt in unrelated files: pond/minio.rs, rollout/engine.rs, rollout/mod.rs, raft/store.rs -- none touched by this ticket)")
//! @yah:handoff("CLOSED THE DEAD-CODE GAP: judge_readiness/ReadinessInputs (this ticket's own W253 s7 deliverable) had ZERO production callers. The live path in scheduler.rs applied 2 of 4 gates via a hand-rolled filter (confirmed_up && admits) and never checked raft peer health at all. New scheduler::judge_candidate projects NodeEligibility onto ReadinessInputs and defers to judge_readiness, so the gate set cannot drift between the module that defines it and the one that acts on it.")
//! @yah:verify("cargo check -p yubaba --lib --bin yubaba: clean")
//! @yah:verify("cargo test -p yubaba --lib = 496 passed / 0 failed (was 479 at F3 handoff; +6 from this pass, rest from peers)")
//! @yah:verify("cargo test -p yubaba --lib scheduler = 18 passed / 0 failed")
//! @yah:verify("cargo clippy -p yubaba --lib --bin yubaba: findings only in cluster_epoch.rs, pond/minio.rs, rollout/mod.rs -- pre-existing, none in scheduler.rs / lease_detector.rs / main.rs")
//! @yah:handoff("NEW GATE, previously absent entirely: raft_peer_healthy, sourced from the already-attached RaftHeartbeatDetector (shared_state.failure_detector, passed into scheduler::spawn as a new Option<Arc<dyn FailureDetector>> param). Direction preserves this ticket's channel separation: the raft channel may only VETO a candidate (explicit NodeLiveness::Down) and can never be the reason one is accepted. Suspect / Unknown / node-absent / no-detector all leave the gate open, per the FailureDetector trait's own empty-report rule. Catches the gray failure where a node renews its HTTP lease happily while its consensus link is dead.")
//! @yah:handoff("NodeEligibility.confirmed_up: bool -> liveness: Option<Confirmed>. The bool flattened never-confirmed and confirmed-Down on the way IN, which is what ReadinessInputs::liveness's own doc asks callers not to do; tracker.committed() already returns the right type. hydrated is derived not fabricated: tier != WarmReplica || warm_for_tenant -- a ColdHydrate tenant hydrates AS PART OF the transfer so demanding it first would deadlock every cold placement, and a WarmReplica tenant's hydration evidence IS warm_for_tenant. That collapses F3's separate warm-tier filter into the readiness gate.")
//! @yah:handoff("streamer_watermark_age / rpo_bound are carried explicitly as None at the live call site rather than dropped (TenantSnapshot gained rpo_bound, NodeEligibility gained streamer_watermark_age). judge_readiness reads no-target-configured as vacuously satisfied, so the gate is inert today and those two Nones are the entire diff when R574-T4's RpoStatus gets plumbed. Test the_unplumbed_streamer_gate_is_vacuous_at_the_live_call_site pins that: if it ever starts refusing, a bound landed without its watermark and fleet placement just froze.")
//! @yah:verify("6 new scheduler tests: dead-raft-peer refusal + preference for a healthy higher-id node, never-confirmed vs confirmed-down both NotLive, hydration-is-the-warm-tier-rule, an RPO bound gating a real watermark both directions, the vacuous-today assertion, and the raft veto matrix (Live/Suspect/Unknown/Down/absent/empty-report)")
//! @yah:handoff("Operator-facing: the NoEligibleCandidate warn now logs a per-candidate refusals field (node=not-live node=over-headroom ...) via refusal_str. Bare 'no eligible candidate' is the least actionable line to hand someone during an outage -- a capacity crunch, a fleet not yet confirmed live, and a warm-tier tenant that cannot place until W248 lands are three different problems with one message.")
//! @yah:cleanup("Fixed 3 pre-existing broken intra-doc links in scheduler.rs module doc (lease_detector::X -> crate::lease_detector::X) -- the bare path never resolved since the use statement imports items, not the module.")

use std::collections::BTreeMap;

use openraft::Instant;

use crate::cluster_policy::LivenessThresholds;
use crate::raft::{YubabaNodeId, YubabaRaft};

/// A detector's judgment about one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeLiveness {
    /// Positive evidence, recent enough to trust.
    Live,
    /// Silent longer than expected, but not long enough to call it.
    Suspect,
    /// Silent long past any plausible hiccup.
    Down,
    /// This detector cannot see the node at all — not the same as "down".
    ///
    /// A raft-heartbeat detector running on a follower reports `Unknown` for
    /// everything, because only the leader tracks acknowledgements. Reporting
    /// `Down` there would turn "I am not the one watching" into "the cluster is
    /// dead", which is the classic failure-detector reporting bug.
    Unknown,
}

impl NodeLiveness {
    /// Stable lowercase wire/CLI spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Suspect => "suspect",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
}

/// One peer's entry in a [`LivenessReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeObservation {
    /// The verdict.
    pub liveness: NodeLiveness,
    /// How long ago this detector last had positive evidence of the node, if it
    /// ever has. `None` means "no evidence yet", which is why it pairs with
    /// [`NodeLiveness::Unknown`] rather than with `Down`.
    pub silent_for_ms: Option<u64>,
}

/// Per-node judgments from a single detector.
pub type LivenessReport = BTreeMap<YubabaNodeId, NodeObservation>;

/// The port. Implementors answer "which peers can I currently see, and how
/// stale is that evidence".
#[async_trait::async_trait]
pub trait FailureDetector: std::fmt::Debug + Send + Sync {
    /// Which evidence channel this detector speaks for, e.g. `"raft-heartbeat"`.
    /// Surfaced alongside the report so a reader can tell *what* saw the node.
    fn channel(&self) -> &'static str;

    /// Judge every peer this detector can currently see.
    ///
    /// An empty report means "this detector has no view right now" (a follower
    /// asking the raft-heartbeat detector, a radio detector with the radio
    /// off) — it never means "every node is down".
    async fn observe(&self) -> LivenessReport;
}

/// Turn "how long has this node been silent" into a verdict.
///
/// Split out from [`RaftHeartbeatDetector`] so the rule is testable without a
/// cluster, and reusable by any detector measuring silence against
/// [`LivenessThresholds`].
pub fn judge_silence(
    silent_for: Option<std::time::Duration>,
    thresholds: LivenessThresholds,
) -> NodeObservation {
    let Some(silent_for) = silent_for else {
        return NodeObservation {
            liveness: NodeLiveness::Unknown,
            silent_for_ms: None,
        };
    };
    let liveness = if silent_for >= thresholds.down_after {
        NodeLiveness::Down
    } else if silent_for >= thresholds.suspect_after {
        NodeLiveness::Suspect
    } else {
        NodeLiveness::Live
    };
    NodeObservation {
        liveness,
        silent_for_ms: Some(silent_for.as_millis() as u64),
    }
}

/// The default detector: reads openraft's own record of when each peer last
/// acknowledged this leader.
///
/// openraft 0.10 exposes `RaftMetrics::heartbeat` — a per-node instant of the
/// last acknowledged heartbeat or replication — precisely so applications can
/// guess at offline followers. This detector is that guess, with the thresholds
/// taken from the cluster's [`RaftTiming`](crate::cluster_policy::RaftTiming) so
/// a LAN cluster is not held to a WAN cluster's patience.
///
/// The field is populated **only on the leader**. On a follower `observe`
/// returns an empty report rather than inventing verdicts.
#[derive(Clone)]
pub struct RaftHeartbeatDetector {
    raft: YubabaRaft,
    thresholds: LivenessThresholds,
}

impl std::fmt::Debug for RaftHeartbeatDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaftHeartbeatDetector")
            .field("thresholds", &self.thresholds)
            .finish_non_exhaustive()
    }
}

impl RaftHeartbeatDetector {
    /// Watch `raft`, judging silence against `thresholds` (build them with
    /// [`ClusterPolicy::liveness_thresholds`](crate::cluster_policy::ClusterPolicy::liveness_thresholds)).
    pub fn new(raft: YubabaRaft, thresholds: LivenessThresholds) -> Self {
        Self { raft, thresholds }
    }
}

#[async_trait::async_trait]
impl FailureDetector for RaftHeartbeatDetector {
    fn channel(&self) -> &'static str {
        "raft-heartbeat"
    }

    async fn observe(&self) -> LivenessReport {
        use openraft::async_runtime::watch::WatchReceiver;

        // Clone the map out of the watch channel: the borrow guard must not be
        // held while we walk it, and the map is a handful of entries.
        let heartbeats = self.raft.metrics().borrow_watched().heartbeat.clone();
        let Some(heartbeats) = heartbeats else {
            // Not the leader — no acknowledgements are tracked here.
            return LivenessReport::new();
        };
        heartbeats
            .into_iter()
            .map(|(node, last_ack)| {
                let silent_for = last_ack.map(|instant| instant.elapsed());
                (node, judge_silence(silent_for, self.thresholds))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::cluster_policy::ClusterPolicy;

    fn fleet() -> LivenessThresholds {
        ClusterPolicy::fleet().liveness_thresholds()
    }

    #[test]
    fn fresh_evidence_is_live() {
        let obs = judge_silence(Some(Duration::from_millis(100)), fleet());
        assert_eq!(obs.liveness, NodeLiveness::Live);
        assert_eq!(obs.silent_for_ms, Some(100));
    }

    #[test]
    fn silence_crosses_suspect_then_down() {
        let th = fleet(); // suspect at 1.5s, down at 5s
        assert_eq!(
            judge_silence(Some(th.suspect_after - Duration::from_millis(1)), th).liveness,
            NodeLiveness::Live
        );
        assert_eq!(
            judge_silence(Some(th.suspect_after), th).liveness,
            NodeLiveness::Suspect,
            "the threshold itself is inclusive — at exactly 3 missed heartbeats the node is suspect"
        );
        assert_eq!(
            judge_silence(Some(th.down_after), th).liveness,
            NodeLiveness::Down
        );
    }

    #[test]
    fn no_evidence_is_unknown_never_down() {
        let obs = judge_silence(None, fleet());
        assert_eq!(
            obs.liveness,
            NodeLiveness::Unknown,
            "a node we have never heard from is unobserved, not dead — reporting Down here \
             is how 'I am a follower' becomes 'the cluster is gone'"
        );
        assert_eq!(obs.silent_for_ms, None);
    }

    #[test]
    fn the_same_silence_means_different_things_on_different_networks() {
        let fleet = ClusterPolicy::fleet().liveness_thresholds();
        let rig = ClusterPolicy::rig().liveness_thresholds();

        // 800ms: nothing at all on a WAN cluster, already worth noticing on a LAN.
        let brief = Duration::from_millis(800);
        assert_eq!(
            judge_silence(Some(brief), fleet).liveness,
            NodeLiveness::Live
        );
        assert_eq!(
            judge_silence(Some(brief), rig).liveness,
            NodeLiveness::Suspect
        );

        // 2s: a WAN cluster is only starting to wonder; a LAN cluster has written
        // the node off. Which is the whole reason the thresholds come from the
        // policy rather than from a constant.
        let long = Duration::from_secs(2);
        assert_eq!(
            judge_silence(Some(long), fleet).liveness,
            NodeLiveness::Suspect
        );
        assert_eq!(judge_silence(Some(long), rig).liveness, NodeLiveness::Down);
    }
}
