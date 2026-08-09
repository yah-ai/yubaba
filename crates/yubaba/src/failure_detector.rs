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
