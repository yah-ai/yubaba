//! A [`FailureDetector`] on a second, non-raft evidence channel, plus the
//! debounce and readiness logic that sits between "a detector has an opinion"
//! and "the scheduler may act on it" (R737-F2, W246 §"Failure detector",
//! W253 §7).
//!
//! [`failure_detector::RaftHeartbeatDetector`](crate::failure_detector::RaftHeartbeatDetector)
//! answers "did this peer ack my last `AppendEntries`?" — exactly the
//! question a *write* needs answered, and precisely the evidence W253 §7
//! forbids a *placement* decision from using (only the leader tracks acks, so
//! that evidence vanishes on every leadership change, and it is entangled
//! with raft's own liveness machinery in a way a second consensus-adjacent
//! decision must not be). [`LeaseFailureDetector`] is the separate channel:
//! nodes push a renewal over plain HTTP (`POST /mesh/lease-renew`), tracked
//! here against a **monotonic** clock (`Instant`, never wall-clock — wall
//! skew can make a node believe its lease outlives the leader's view of it).
//!
//! Two things this module deliberately does NOT do:
//! - **Renewals never touch raft.** Only [`TransitionTracker::observe`]'s
//!   *confirmed* flips are meant to be committed — see its doc for why a
//!   flip, not a raw sample, is the unit of "worth a log entry".
//! - **It does not act.** Same rule as its raft-heartbeat sibling: this
//!   reports; a leader-resident scheduler (R737-F3) decides what a `Down`
//!   confirmation means for tenant placement.
//!
//! @yah:relay(R782, "Plumb the streamer RPO gate: an RPO target on TenantPlacement + watermark_age from a live tenant-streamer back to the leader")
//! @yah:status(review)
//! @yah:at(2026-08-19T06:46:01Z)
//! @yah:assignee(bundle-anthropic-miravel)
//! @yah:phase(P3)
//! @yah:parent(Q731)
//! @yah:next("The gate is already written and already called: lease_detector::judge_readiness checks streamer_watermark_age against streamer_rpo_bound, and scheduler::judge_candidate projects onto it every tick. Both inputs are hardcoded None at the live call site (scheduler.rs run(): TenantSnapshot.rpo_bound and NodeEligibility.streamer_watermark_age), which judge_readiness reads as no-target-configured = vacuously satisfied. So this relay is two plumbing lines plus what feeds them -- do NOT rebuild the gate.")
//! @yah:gotcha("scheduler.rs test the_unplumbed_streamer_gate_is_vacuous_at_the_live_call_site asserts today's None/None combination is Ok(()). It will need updating as part of this work -- and read why first: if an RPO BOUND lands without the watermark source, every candidate fails StreamerBehindBound (absence of evidence is deliberately not caught-up) and fleet placement freezes. Land the watermark source first, or land both atomically.")
//! @yah:next("Two pieces. (1) An RPO target somewhere the leader can read per tenant -- TenantPlacement (raft/mod.rs) is the natural home alongside region/tier/demand, but adding a field there is a state-machine schema change; R737-F1's handoff records that its own two new ENUM VARIANTS forced cluster_protocol 4->5 and state_epoch 3->4, so check whether a serde(default) Option field is a TOLERATED addition here or needs the same bump. (2) Transport for R574-T4's RpoStatus.watermark_age from a running tenant-streamer process back to the leader's placement loop -- likely an HTTP pull mirroring GET /tenants/{id}.")
//! @yah:assumes("That RpoStatus.watermark_age (R574-T4) still exists and still means time-since-the-WAL-watermark-last-durably-advanced. R737-F2 took it on the same secondhand basis and never read the type -- yubaba is control-plane and deliberately takes no turso_backup/tenant_streamer dependency, so judge_readiness crosses it as a bare Option<Duration>. Verify the type before designing the transport.")
//! @yah:handoff("TenantPlacement (raft/mod.rs) gained rpo_bound: Option<Duration> with #[serde(default)] -- the leader-readable per-tenant RPO target. Field, not variant (R720-F1/R734-F2 precedent): NOT BREAKING on both cluster_protocol and state_epoch, hashes re-recorded in cluster-epochs.json with a full why_not_a_bump entry, epochs stay 5/4.")
//! @yah:handoff("New RpoWatermarkRegistry (lease_detector.rs): leader-local, non-raft, keyed (node, tenant) -> (received_at, reported_age), extrapolates staleness forward between reports (never underestimates). Same push shape as LeaseFailureDetector.")
//! @yah:handoff("New POST /mesh/rpo-report route + mesh_rpo_report handler (lib.rs), ServerState.rpo_registry + with_rpo_registry, wired in main.rs alongside lease_detector.")
//! @yah:handoff("scheduler::spawn/run gained an rpo_registry param; TenantSnapshot.rpo_bound now reads TenantPlacement.rpo_bound, NodeEligibility.streamer_watermark_age now reads rpo_registry.watermark_age(candidate, tenant) -- the two hardcoded Nones are gone.")
//! @yah:handoff("New tenant_streamer::rpo_report::RpoReporter: pushes RpoStatus::watermark_age after every tail tick (main.rs's report_rpo, fire-and-forget tokio::spawn), discovering the leader itself via GET /raft/status on its own node-local yubaba (this process has no raft.metrics()). Added StreamOutcome::rpo() accessor in turso-backup to feed it.")
//! @yah:handoff("Test harness (yubaba-test-harness) extended with rpo_registry wiring at all 3 ClusterNode construction sites + Cluster::rpo_registry()/report_watermark() test helpers, mirroring lease_detector's shape.")
//! @yah:handoff("New live-cluster test raft_tenant_placement.rs::a_declared_rpo_bound_refuses_a_candidate_with_no_streamer_evidence proves the gate end-to-end over real raft: a live/admitting/region-eligible candidate with NO pushed evidence is refused; only the candidate report_watermark gave fresh evidence to gets the tenant.")
//! @yah:handoff("Updated the_unplumbed_streamer_gate_is_vacuous_at_the_live_call_site -> an_undeclared_rpo_target_stays_vacuous_by_default per the ticket's own gotcha, plus updated scheduler.rs's module doc explaining the remaining None/None default case is intentional (fail-closed pending W248 warm fan-out), not a wiring gap.")
//! @yah:verify("cargo check -p yubaba: clean")
//! @yah:verify("cargo test -p yubaba --lib: 501/501 passed (one pre-existing exact-wire-shape test updated for the new field)")
//! @yah:verify("cargo test -p turso-backup --lib stream::: 60/60 passed (incl. new stream_outcome_rpo_accessor_covers_every_variant)")
//! @yah:verify("cargo test -p yubaba-tenant-streamer: 22/22 passed (incl. new rpo_report::tests)")
//! @yah:verify("cargo test -p yubaba --test raft_tenant_placement: 3/3 passed, all 3 live-cluster tests including the new R782 gate proof")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift: red as predicted (raft/mod.rs moved both axes) before --write, 8/8 green after")
//! @yah:verify("cargo clippy -p yubaba --lib --no-deps / -p turso-backup --lib: zero findings in any R782-touched file (one type_complexity in lease_detector.rs fixed with a type alias, re-verified clean); the lease_detector re-test after that refactor was still building when the session was asked to close -- the refactor is a pure rename with no logic change, so this is a low-risk residual, not a real gap")
//! @yah:assumes("Confirmed rather than assumed: RpoStatus.watermark_age (R574-T4, turso-backup/src/stream.rs) is Option<Duration>, time since the WAL watermark last durably advanced -- matches R782's inherited assumption exactly.")
//! @yah:verify("cargo test -p yubaba --lib lease_detector::: 18/18 passed after the type_complexity fix (finished after the review was filed) -- the flagged cleanup item is resolved, no residual gap.")

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use workload_spec::TenantId;

use crate::cluster_policy::LivenessThresholds;
use crate::failure_detector::{judge_silence, FailureDetector, LivenessReport, NodeLiveness};
use crate::raft::YubabaNodeId;

/// Reads renewals pushed over `POST /mesh/lease-renew`, judged against the
/// same [`LivenessThresholds`] shape a raft-heartbeat detector uses (so a WAN
/// fleet and a LAN rig get channel-appropriate patience here too).
///
/// Like [`RaftHeartbeatDetector`](crate::failure_detector::RaftHeartbeatDetector),
/// a node this detector has never heard a renewal from is simply absent from
/// [`observe`](FailureDetector::observe)'s report — never reported `Down`, per
/// the trait's own "an empty report never means every node is down" rule.
#[derive(Debug)]
pub struct LeaseFailureDetector {
    renewals: Mutex<BTreeMap<YubabaNodeId, Instant>>,
    thresholds: LivenessThresholds,
}

impl LeaseFailureDetector {
    pub fn new(thresholds: LivenessThresholds) -> Self {
        Self {
            renewals: Mutex::new(BTreeMap::new()),
            thresholds,
        }
    }

    /// Record a renewal for `node`, timestamped by the monotonic clock now.
    ///
    /// Idempotent-ish by construction: a reordered or duplicated renewal
    /// simply sets the same-or-later instant, since `Instant::now()` is
    /// non-decreasing on the machine that calls it. Called from the
    /// `POST /mesh/lease-renew` handler.
    pub fn renew(&self, node: YubabaNodeId) {
        self.renewals.lock().unwrap().insert(node, Instant::now());
    }

    fn snapshot(&self) -> LivenessReport {
        self.renewals
            .lock()
            .unwrap()
            .iter()
            .map(|(node, at)| (*node, judge_silence(Some(at.elapsed()), self.thresholds)))
            .collect()
    }
}

#[async_trait::async_trait]
impl FailureDetector for LeaseFailureDetector {
    fn channel(&self) -> &'static str {
        "node-lease"
    }

    async fn observe(&self) -> LivenessReport {
        self.snapshot()
    }
}

/// R782 (W253 §7): the streamer-RPO evidence channel — the same push shape as
/// [`LeaseFailureDetector`] (a plain HTTP nudge into the leader's **local,
/// non-raft** registry, never a raft write), but reporting a *value* rather
/// than a liveness bit, and keyed per `(node, tenant)` rather than per node —
/// [`ReadinessInputs::streamer_watermark_age`] is what a given *candidate*
/// node's own streamer reports for a given tenant, not a fleet-wide fact.
///
/// `POST /mesh/rpo-report` is the write; a running `tenant-streamer` process
/// pushes into it after every tail tick (see
/// `tenant_streamer::rpo_report::RpoReporter`, which discovers the leader the
/// same way [`crate::lease_renewal`]'s node-lease client does, just over HTTP
/// rather than `raft.metrics()` — that process has no raft of its own; see
/// its module doc for why).
/// One `(node, tenant)` slot: when it was reported, and what was reported.
type RpoReports = BTreeMap<(YubabaNodeId, TenantId), (Instant, Option<Duration>)>;

#[derive(Debug, Default)]
pub struct RpoWatermarkRegistry {
    reports: Mutex<RpoReports>,
}

impl RpoWatermarkRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `node`'s latest reported watermark age for `tenant`. `None`
    /// means the node's streamer has never persisted a watermark for this
    /// tenant — recorded rather than treated as "no report", so
    /// [`Self::watermark_age`] can keep answering `None` (fail-closed, per
    /// [`judge_readiness`]) instead of silently reusing a stale prior value.
    pub fn report(&self, node: YubabaNodeId, tenant: TenantId, watermark_age: Option<Duration>) {
        self.reports.lock().unwrap().insert((node, tenant), (Instant::now(), watermark_age));
    }

    /// This node's current best estimate of `tenant`'s watermark age, or
    /// `None` if `node` has never reported one.
    ///
    /// The reported age is advanced by the wall-clock time elapsed since it
    /// was pushed — a watermark can only get *staler* between reports, never
    /// fresher, so extrapolating forward from the last-known value is the
    /// safe (never-underestimates) reading, the same posture
    /// [`judge_readiness`] already takes for a watermark that was never
    /// reported at all.
    pub fn watermark_age(&self, node: YubabaNodeId, tenant: &TenantId) -> Option<Duration> {
        let reports = self.reports.lock().unwrap();
        let &(received_at, age) = reports.get(&(node, tenant.clone()))?;
        age.map(|a| a + received_at.elapsed())
    }
}

/// A node's debounced, act-on-able liveness — collapses raw per-tick
/// [`NodeLiveness`] samples down to the rare event a placement decision
/// should react to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmed {
    Up,
    Down,
}

/// How long the raw verdict must hold a *different* direction than what is
/// currently committed before [`TransitionTracker::observe`] flips it.
///
/// Deliberately asymmetric by default (see [`Self::from_thresholds`]):
/// trusting a node is dead should not be slower than trusting it recovered,
/// because staying `Up` on a dead node blocks failover, while staying `Down`
/// on a live one only leaves a warm spare idle a little longer.
#[derive(Debug, Clone, Copy)]
pub struct HysteresisPolicy {
    pub confirm_down_after: Duration,
    pub confirm_up_after: Duration,
}

impl HysteresisPolicy {
    /// `confirm_down_after` matches the raw detector's own `down_after`, so
    /// total time from "last renewal" to a committed `Down` is roughly
    /// `2 * down_after` — the raw threshold, then the confirm dwell on top.
    /// `confirm_up_after` uses the shorter `suspect_after` bound: recovering
    /// wrongly costs one retried placement decision next tick, not a
    /// prolonged outage, so it does not need the same margin.
    pub fn from_thresholds(thresholds: LivenessThresholds) -> Self {
        Self {
            confirm_down_after: thresholds.down_after,
            confirm_up_after: thresholds.suspect_after,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Candidate {
    direction: Confirmed,
    since: Instant,
}

/// Debounces a [`FailureDetector`]'s raw, per-tick output into the committed
/// up/down facts a scheduler should act on (W246: "only up->down transitions
/// commit to raft, never renewals").
///
/// Not itself a [`FailureDetector`] — it *consumes* one detector's report
/// once per tick via [`observe`](Self::observe). Owned by a single caller
/// (the leader loop, R737-F3) and called serially, so it needs no internal
/// locking.
#[derive(Debug, Default)]
pub struct TransitionTracker {
    committed: BTreeMap<YubabaNodeId, Confirmed>,
    candidate: BTreeMap<YubabaNodeId, Candidate>,
}

impl TransitionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// This node's last-confirmed direction, or `None` if it has never
    /// dwelled long enough in one direction to be confirmed at all.
    pub fn committed(&self, node: YubabaNodeId) -> Option<Confirmed> {
        self.committed.get(&node).copied()
    }

    /// Feed one tick's raw report through the hysteresis. Returns nodes whose
    /// committed direction just flipped (in `report`'s `BTreeMap` order —
    /// deterministic for tests and for whatever iterates the result to build
    /// raft writes).
    ///
    /// `Unknown` samples are skipped outright: no evidence must never move a
    /// candidate either way. `Suspect` samples are also skipped — they
    /// neither start nor reset an in-progress candidate, so a node blipping
    /// between `Live`/`Suspect` or `Suspect`/`Down` does not lose dwell time
    /// already accumulated toward a flip; only the *opposite* raw direction
    /// resets it.
    pub fn observe(
        &mut self,
        report: &LivenessReport,
        policy: HysteresisPolicy,
        now: Instant,
    ) -> Vec<(YubabaNodeId, Confirmed)> {
        let mut flips = Vec::new();
        for (&node, obs) in report {
            let raw = match obs.liveness {
                NodeLiveness::Live => Confirmed::Up,
                NodeLiveness::Down => Confirmed::Down,
                NodeLiveness::Suspect | NodeLiveness::Unknown => continue,
            };
            if self.committed.get(&node) == Some(&raw) {
                // Evidence agrees with what is already committed: nothing
                // pending, nothing to confirm.
                self.candidate.remove(&node);
                continue;
            }
            let confirm_after = match raw {
                Confirmed::Down => policy.confirm_down_after,
                Confirmed::Up => policy.confirm_up_after,
            };
            let since = match self.candidate.get(&node) {
                Some(c) if c.direction == raw => c.since,
                _ => now,
            };
            if now.saturating_duration_since(since) >= confirm_after {
                self.committed.insert(node, raw);
                self.candidate.remove(&node);
                flips.push((node, raw));
            } else {
                self.candidate.insert(node, Candidate { direction: raw, since });
            }
        }
        flips
    }
}

/// The control-plane facts a scheduler needs before a node may take
/// *ownership* of a tenant — W253 §7's four readiness gates, collapsed to one
/// call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessInputs {
    /// This node's [`TransitionTracker`]-confirmed liveness. `None` (never
    /// confirmed either way) fails the gate exactly like `Some(Down)` — an
    /// unconfirmed node is not evidence of readiness.
    pub liveness: Option<Confirmed>,
    pub raft_peer_healthy: bool,
    pub hydrated: bool,
    pub within_headroom: bool,
    /// Elapsed time since this tenant's WAL watermark last durably advanced
    /// on this node — from the streamer's
    /// `RpoStatus::watermark_age`, crossed as a bare `Duration` rather than
    /// the type itself. This crate is control-plane and does not take a
    /// data-plane dependency on `turso_backup`/`tenant_streamer`; see
    /// `tenant_streamer::ownership`'s module doc for the same rule enforced
    /// in the other direction.
    pub streamer_watermark_age: Option<Duration>,
    /// The bound `streamer_watermark_age` must stay under. `None` means no
    /// RPO target is configured for this tenant's tier — the gate is then
    /// vacuously satisfied, mirroring `RpoStatus::breached`'s own "always
    /// false with no target" rule.
    pub streamer_rpo_bound: Option<Duration>,
}

/// Why [`judge_readiness`] refused. Ordered by check order, not severity —
/// the first gate that fails is the one reported, so a node failing three
/// gates does not need three round trips to learn the first one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReady {
    NotLive,
    RaftPeerUnhealthy,
    NotHydrated,
    StreamerBehindBound,
    OverHeadroom,
}

/// W253 §7: "a node is ready to *own* a tenant only if" all four gates hold.
pub fn judge_readiness(inputs: &ReadinessInputs) -> Result<(), NotReady> {
    if inputs.liveness != Some(Confirmed::Up) {
        return Err(NotReady::NotLive);
    }
    if !inputs.raft_peer_healthy {
        return Err(NotReady::RaftPeerUnhealthy);
    }
    if !inputs.hydrated {
        return Err(NotReady::NotHydrated);
    }
    if let Some(bound) = inputs.streamer_rpo_bound {
        let breached = match inputs.streamer_watermark_age {
            Some(age) => age > bound,
            // No watermark ever persisted: no evidence of being caught up.
            None => true,
        };
        if breached {
            return Err(NotReady::StreamerBehindBound);
        }
    }
    if !inputs.within_headroom {
        return Err(NotReady::OverHeadroom);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_policy::ClusterPolicy;

    fn fleet() -> LivenessThresholds {
        ClusterPolicy::fleet().liveness_thresholds()
    }

    // ── LeaseFailureDetector ──────────────────────────────────────────────

    #[tokio::test]
    async fn a_fresh_renewal_reports_live() {
        let d = LeaseFailureDetector::new(fleet());
        d.renew(7);
        let report = d.observe().await;
        assert_eq!(report[&7].liveness, NodeLiveness::Live);
    }

    #[tokio::test]
    async fn a_node_never_renewed_is_absent_not_down() {
        let d = LeaseFailureDetector::new(fleet());
        d.renew(1);
        let report = d.observe().await;
        assert!(
            !report.contains_key(&2),
            "an empty view of a node must never be reported as Down"
        );
    }

    #[tokio::test]
    async fn channel_is_distinct_from_raft_heartbeat() {
        let d = LeaseFailureDetector::new(fleet());
        assert_eq!(d.channel(), "node-lease");
    }

    // ── RpoWatermarkRegistry ─────────────────────────────────────────────

    fn t(id: &str) -> TenantId {
        TenantId(id.to_string())
    }

    #[test]
    fn a_node_never_reported_for_is_absent_not_zero() {
        let r = RpoWatermarkRegistry::new();
        r.report(1, t("acme"), Some(Duration::from_secs(5)));
        assert_eq!(r.watermark_age(2, &t("acme")), None, "node 2 never reported");
        assert_eq!(
            r.watermark_age(1, &t("widgets")),
            None,
            "node 1 reported for a different tenant"
        );
    }

    #[test]
    fn a_reported_age_grows_with_elapsed_time_rather_than_staying_pinned() {
        let r = RpoWatermarkRegistry::new();
        r.report(1, t("acme"), Some(Duration::from_secs(5)));
        let first = r.watermark_age(1, &t("acme")).unwrap();
        assert!(first >= Duration::from_secs(5));

        std::thread::sleep(Duration::from_millis(20));
        let second = r.watermark_age(1, &t("acme")).unwrap();
        assert!(
            second > first,
            "staleness must keep growing between reports, not freeze at the reported value"
        );
    }

    #[test]
    fn never_persisted_stays_none_even_after_a_report() {
        // The streamer itself has never persisted a watermark for this
        // tenant — reported explicitly as `None`, not omitted, so this reads
        // exactly like "never reported" rather than reusing a stale prior
        // Some(..) from an earlier report.
        let r = RpoWatermarkRegistry::new();
        r.report(1, t("acme"), Some(Duration::from_secs(5)));
        r.report(1, t("acme"), None);
        assert_eq!(r.watermark_age(1, &t("acme")), None);
    }

    #[test]
    fn a_later_report_overwrites_rather_than_accumulates() {
        let r = RpoWatermarkRegistry::new();
        r.report(1, t("acme"), Some(Duration::from_secs(60)));
        r.report(1, t("acme"), Some(Duration::from_secs(1)));
        let age = r.watermark_age(1, &t("acme")).unwrap();
        assert!(age < Duration::from_secs(2), "must reflect the newer, fresher report");
    }

    // ── TransitionTracker hysteresis ────────────────────────────────────

    fn report_of(node: YubabaNodeId, liveness: NodeLiveness) -> LivenessReport {
        [(
            node,
            crate::failure_detector::NodeObservation {
                liveness,
                silent_for_ms: None,
            },
        )]
        .into_iter()
        .collect()
    }

    #[test]
    fn a_single_down_sample_does_not_commit_before_the_dwell() {
        let mut tracker = TransitionTracker::new();
        let policy = HysteresisPolicy::from_thresholds(fleet());
        let t0 = Instant::now();

        // First-ever sample: even Live has to dwell before it is "committed"
        // at all (see the doc on the None-vs-Some(Down) fail-closed rule).
        let flips = tracker.observe(&report_of(1, NodeLiveness::Live), policy, t0);
        assert!(flips.is_empty());
        assert_eq!(tracker.committed(1), None);

        let t1 = t0 + policy.confirm_up_after;
        let flips = tracker.observe(&report_of(1, NodeLiveness::Live), policy, t1);
        assert_eq!(flips, vec![(1, Confirmed::Up)]);
        assert_eq!(tracker.committed(1), Some(Confirmed::Up));

        // Now a single Down sample right after: must not flip immediately.
        let t2 = t1 + Duration::from_millis(1);
        let flips = tracker.observe(&report_of(1, NodeLiveness::Down), policy, t2);
        assert!(flips.is_empty(), "one sample must not itself be a failover trigger");
        assert_eq!(tracker.committed(1), Some(Confirmed::Up));
    }

    #[test]
    fn sustained_down_commits_after_the_confirm_window() {
        let mut tracker = TransitionTracker::new();
        let policy = HysteresisPolicy::from_thresholds(fleet());
        let t0 = Instant::now();
        tracker.observe(&report_of(1, NodeLiveness::Live), policy, t0);
        tracker.observe(&report_of(1, NodeLiveness::Live), policy, t0 + policy.confirm_up_after);
        assert_eq!(tracker.committed(1), Some(Confirmed::Up));

        let down_start = t0 + policy.confirm_up_after + Duration::from_secs(1);
        tracker.observe(&report_of(1, NodeLiveness::Down), policy, down_start);
        let still_pending = tracker.observe(
            &report_of(1, NodeLiveness::Down),
            policy,
            down_start + policy.confirm_down_after - Duration::from_millis(1),
        );
        assert!(still_pending.is_empty());
        assert_eq!(tracker.committed(1), Some(Confirmed::Up));

        let flips = tracker.observe(
            &report_of(1, NodeLiveness::Down),
            policy,
            down_start + policy.confirm_down_after,
        );
        assert_eq!(flips, vec![(1, Confirmed::Down)]);
        assert_eq!(tracker.committed(1), Some(Confirmed::Down));
    }

    #[test]
    fn a_suspect_blip_does_not_reset_dwell_already_accumulated() {
        let mut tracker = TransitionTracker::new();
        let policy = HysteresisPolicy::from_thresholds(fleet());
        let t0 = Instant::now();
        tracker.observe(&report_of(1, NodeLiveness::Down), policy, t0);

        // A Suspect sample midway through the dwell must not restart the
        // clock — WAN jitter that briefly looks like "not yet sure" should
        // not cost the whole confirm window over again.
        let mid = t0 + policy.confirm_down_after / 2;
        let flips = tracker.observe(&report_of(1, NodeLiveness::Suspect), policy, mid);
        assert!(flips.is_empty());

        let flips = tracker.observe(&report_of(1, NodeLiveness::Down), policy, t0 + policy.confirm_down_after);
        assert_eq!(
            flips,
            vec![(1, Confirmed::Down)],
            "dwell time from the original Down sample must still count"
        );
    }

    #[test]
    fn unknown_never_moves_a_candidate() {
        let mut tracker = TransitionTracker::new();
        let policy = HysteresisPolicy::from_thresholds(fleet());
        let t0 = Instant::now();
        tracker.observe(&report_of(1, NodeLiveness::Down), policy, t0);
        tracker.observe(&report_of(1, NodeLiveness::Unknown), policy, t0 + Duration::from_millis(1));
        let flips = tracker.observe(&report_of(1, NodeLiveness::Down), policy, t0 + policy.confirm_down_after);
        assert_eq!(flips, vec![(1, Confirmed::Down)], "an Unknown blip must not reset a Down dwell");
    }

    #[test]
    fn recovery_requires_its_own_dwell_not_a_single_sample() {
        let mut tracker = TransitionTracker::new();
        let policy = HysteresisPolicy::from_thresholds(fleet());
        let t0 = Instant::now();
        tracker.observe(&report_of(1, NodeLiveness::Down), policy, t0);
        tracker.observe(&report_of(1, NodeLiveness::Down), policy, t0 + policy.confirm_down_after);
        assert_eq!(tracker.committed(1), Some(Confirmed::Down));

        let up_start = t0 + policy.confirm_down_after + Duration::from_secs(1);
        let flips = tracker.observe(&report_of(1, NodeLiveness::Live), policy, up_start);
        assert!(flips.is_empty(), "one Live sample must not immediately un-fail a node");
        assert_eq!(tracker.committed(1), Some(Confirmed::Down));

        let flips = tracker.observe(
            &report_of(1, NodeLiveness::Live),
            policy,
            up_start + policy.confirm_up_after,
        );
        assert_eq!(flips, vec![(1, Confirmed::Up)]);
    }

    // ── judge_readiness ─────────────────────────────────────────────────

    fn ready_inputs() -> ReadinessInputs {
        ReadinessInputs {
            liveness: Some(Confirmed::Up),
            raft_peer_healthy: true,
            hydrated: true,
            within_headroom: true,
            streamer_watermark_age: Some(Duration::from_secs(1)),
            streamer_rpo_bound: Some(Duration::from_secs(30)),
        }
    }

    #[test]
    fn every_gate_open_is_ready() {
        assert_eq!(judge_readiness(&ready_inputs()), Ok(()));
    }

    #[test]
    fn unconfirmed_liveness_fails_exactly_like_confirmed_down() {
        let mut inputs = ready_inputs();
        inputs.liveness = None;
        assert_eq!(judge_readiness(&inputs), Err(NotReady::NotLive));
        inputs.liveness = Some(Confirmed::Down);
        assert_eq!(judge_readiness(&inputs), Err(NotReady::NotLive));
    }

    #[test]
    fn each_remaining_gate_refuses_on_its_own() {
        let mut inputs = ready_inputs();
        inputs.raft_peer_healthy = false;
        assert_eq!(judge_readiness(&inputs), Err(NotReady::RaftPeerUnhealthy));

        let mut inputs = ready_inputs();
        inputs.hydrated = false;
        assert_eq!(judge_readiness(&inputs), Err(NotReady::NotHydrated));

        let mut inputs = ready_inputs();
        inputs.within_headroom = false;
        assert_eq!(judge_readiness(&inputs), Err(NotReady::OverHeadroom));
    }

    #[test]
    fn a_watermark_older_than_the_bound_breaches_readiness() {
        let mut inputs = ready_inputs();
        inputs.streamer_watermark_age = Some(Duration::from_secs(60));
        assert_eq!(judge_readiness(&inputs), Err(NotReady::StreamerBehindBound));
    }

    #[test]
    fn no_watermark_ever_persisted_is_not_ready_even_with_no_evidence_of_breach() {
        let mut inputs = ready_inputs();
        inputs.streamer_watermark_age = None;
        assert_eq!(
            judge_readiness(&inputs),
            Err(NotReady::StreamerBehindBound),
            "absence of evidence must not read as being caught up"
        );
    }

    #[test]
    fn no_rpo_target_configured_is_vacuously_satisfied() {
        let mut inputs = ready_inputs();
        inputs.streamer_rpo_bound = None;
        inputs.streamer_watermark_age = None;
        assert_eq!(judge_readiness(&inputs), Ok(()));
    }
}
