//! Every node's push onto R737-F2's node-lease channel (W253 §7).
//!
//! [`lease_detector::LeaseFailureDetector`](crate::lease_detector::LeaseFailureDetector)
//! and `POST /mesh/lease-renew` are the *server* half of the lease channel —
//! something to renew against. Nothing calls it without this: the loop here is
//! the client half, the direct analogue of
//! [`member_registration`](crate::member_registration) but for a value that
//! must stay fresh every tick rather than converge once.
//!
//! # Why this is simpler than member registration
//!
//! A member row is *replicated state* — writing it wrong or late is a
//! consensus write with CAS-free but still through-quorum semantics. A lease
//! renewal is not: it is a plain, best-effort HTTP nudge at whichever node
//! this one currently believes leads, recorded in that leader's **local,
//! non-raft** registry (R737-F2's whole point — renewals never touch the
//! log). So there is no write conflict to resolve, no forward-and-retry
//! ladder to build: a renewal that lands late or not at all this tick simply
//! tries again next tick, and [`lease_detector::judge_silence`]'s thresholds
//! are already sized for a few missed ticks to mean nothing.
//!
//! # The leader renews itself in-process
//!
//! When this node believes *it* is the leader, [`plan_renewal`] says
//! [`RenewalPlan::SelfRenew`] and [`run`] calls
//! [`lease_detector::LeaseFailureDetector::renew`] directly rather than
//! looping an HTTP call back through its own router. Every other node forwards
//! to the leader's mesh address exactly the way `member_registration`
//! forwards a `SetMember` write — read from the same
//! `membership_config.membership().get_node(...)` raft already carries no
//! extra discovery needed.

use std::sync::Arc;
use std::time::Duration;

use openraft::async_runtime::watch::WatchReceiver;
use tracing::{debug, warn};

use crate::lease_detector::LeaseFailureDetector;
use crate::raft::{YubabaNodeId, YubabaRaft};

/// Timeout for the renewal POST to the believed leader.
///
/// Short and deliberately so: a renewal is a heartbeat, not a durable write.
/// A slow leader should be found out by [`lease_detector::judge_silence`]'s
/// thresholds, not papered over by a request that hangs past the next tick.
const RENEW_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn this node's lease-renewal loop.
///
/// Safe and correct to run on every node, including the leader — see the
/// module doc for why the leader's own case is in-process rather than a
/// no-op. `interval` should be a small fraction of
/// [`crate::cluster_policy::LivenessThresholds::down_after`] so a detector has
/// several chances to hear from a live node before calling it down; callers
/// derive it the same way [`crate::scheduler::SchedulerConfig::new`] derives
/// its own pacing, off the raft heartbeat rather than a fixed constant.
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    lease_detector: Option<Arc<LeaseFailureDetector>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, lease_detector, interval).await;
    })
}

/// What this tick should do, given a snapshot of this node's raft view.
///
/// Split out for the same reason [`crate::member_registration::plan_registration`]
/// is: the decision is arithmetic over plain values and should be testable
/// without a live cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RenewalPlan {
    /// Record the renewal in this node's own detector and POST it to every
    /// peer's. Addresses are in ascending node-id order — deterministic for
    /// tests, and irrelevant to correctness since every one is attempted.
    Broadcast { peers: Vec<String> },
    /// Raft has handed back no membership yet — nothing to renew against.
    NoPeersYet,
}

/// Renew against **every member, not just the leader** (R858-T7).
///
/// # The bug this shape fixes
///
/// It used to renew against `current_leader` alone, which is the natural
/// reading of "the leader-resident scheduler is the only consumer" — and it
/// leaves a hole that only opens in the one situation a lease exists for.
///
/// A [`LeaseFailureDetector`] is per-node and starts empty, and
/// [`LeaseFailureDetector::silence`] answers `None` for a node it has never
/// heard from — correctly, since never-heard-from is not evidence of death.
/// Now kill the node that *was* the leader. It had been renewing itself
/// in-process, so no peer ever received a renewal from it. A survivor wins the
/// election, looks for how long the old owner has been silent, and gets `None`
/// — not "silent for a long time", but "no evidence at all", **forever**, since
/// a dead node will never supply the first sample.
///
/// So under the leader-only shape a dead owner could never expire, and
/// R858-T7's whole expiry path would have been unreachable on exactly the
/// failure it was built for. Broadcasting means every node holds a real, dated
/// sample for every peer before anything goes wrong, which is what makes
/// "silent for longer than the deadline" a decidable question after leadership
/// has moved.
///
/// The cost is `N-1` small POSTs per node per tick instead of one. At the three
/// to five voters this cluster shape supports that is noise, and it buys the
/// property that no single node's death can blind the survivors.
fn plan_renewal(node_id: YubabaNodeId, members: &[(YubabaNodeId, String)]) -> RenewalPlan {
    if members.is_empty() {
        return RenewalPlan::NoPeersYet;
    }
    RenewalPlan::Broadcast {
        peers: members
            .iter()
            .filter(|(id, _)| *id != node_id)
            .map(|(_, addr)| addr.clone())
            .collect(),
    }
}

async fn run(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    lease_detector: Option<Arc<LeaseFailureDetector>>,
    interval: Duration,
) {
    let client = match reqwest::Client::builder().timeout(RENEW_TIMEOUT).build() {
        Ok(client) => client,
        Err(e) => {
            // Same posture as member_registration: optional liveness metadata,
            // never worth taking the process down over a TLS backend failure.
            warn!(node_id, "lease renewal: could not build HTTP client, not renewing: {e}");
            return;
        }
    };
    let watch = raft.metrics();

    loop {
        tokio::time::sleep(interval).await;

        let members: Vec<(YubabaNodeId, String)> = {
            let metrics = watch.borrow_watched();
            metrics
                .membership_config
                .membership()
                .nodes()
                .map(|(id, n)| (*id, n.addr.clone()))
                .collect()
        };

        match plan_renewal(node_id, &members) {
            RenewalPlan::Broadcast { peers } => {
                // Local first, and unconditionally: this node's own detector is
                // the one a scheduler reads the instant this node wins an
                // election, and it must not have a hole where its own row goes.
                if let Some(detector) = &lease_detector {
                    detector.renew(node_id);
                }
                for addr in peers {
                    let url = format!("http://{addr}/mesh/lease-renew");
                    match client
                        .post(&url)
                        .json(&serde_json::json!({ "node_id": node_id }))
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            debug!(node_id, %addr, "lease renewal: renewed against peer");
                        }
                        Ok(resp) => {
                            // `debug`, not `warn`: with a broadcast this fires
                            // once per unreachable peer per tick, and a fleet
                            // with one node down would otherwise emit a warning
                            // every heartbeat from every survivor. The signal
                            // that a peer is unreachable is the peer's own
                            // silence, which is what this channel measures.
                            debug!(
                                node_id,
                                %addr,
                                status = %resp.status(),
                                "lease renewal: peer refused the renewal — will retry next tick"
                            );
                        }
                        Err(e) => {
                            debug!(
                                node_id,
                                %addr,
                                "lease renewal: POST failed, will retry next tick: {e}"
                            );
                        }
                    }
                }
            }
            RenewalPlan::NoPeersYet => {
                debug!(node_id, "lease renewal: no membership known yet, waiting");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members() -> Vec<(YubabaNodeId, String)> {
        vec![
            (1, "100.64.0.1:7443".to_string()),
            (2, "100.64.0.2:7443".to_string()),
            (3, "100.64.0.3:7443".to_string()),
        ]
    }

    /// The R858-T7 property: a renewal reaches every peer, so no node's death
    /// can leave the survivors with no dated sample for it. Leadership is not
    /// an input — a leader-only renewal is exactly the shape that made a dead
    /// owner unexpirable.
    #[test]
    fn a_renewal_goes_to_every_peer_regardless_of_who_leads() {
        assert_eq!(
            plan_renewal(2, &members()),
            RenewalPlan::Broadcast {
                peers: vec!["100.64.0.1:7443".to_string(), "100.64.0.3:7443".to_string()],
            }
        );
    }

    /// The leader broadcasts on exactly the same terms — no self-only arm.
    /// Under the old shape this was `SelfRenew`, and it is the precise reason a
    /// leader's death blinded its successors.
    #[test]
    fn the_leader_broadcasts_too_rather_than_only_renewing_itself() {
        assert_eq!(
            plan_renewal(1, &members()),
            RenewalPlan::Broadcast {
                peers: vec!["100.64.0.2:7443".to_string(), "100.64.0.3:7443".to_string()],
            }
        );
    }

    /// A node never sends itself an HTTP renewal; `run` records that locally.
    #[test]
    fn a_node_never_posts_a_renewal_to_itself() {
        let RenewalPlan::Broadcast { peers } = plan_renewal(3, &members()) else {
            panic!("a populated membership always broadcasts");
        };
        assert!(!peers.contains(&"100.64.0.3:7443".to_string()));
        assert_eq!(peers.len(), 2);
    }

    /// A single-node cluster has peers to renew against only as it grows; the
    /// local half still runs, which is what keeps a solo leader's own row
    /// present in its own detector.
    #[test]
    fn a_lone_member_broadcasts_to_nobody_rather_than_refusing_to_renew() {
        assert_eq!(
            plan_renewal(1, &[(1, "100.64.0.1:7443".to_string())]),
            RenewalPlan::Broadcast { peers: vec![] }
        );
    }

    /// Before raft hands back any membership there is nothing to act on — and
    /// this must stay distinct from the lone-member case above, which does
    /// renew locally.
    #[test]
    fn an_empty_membership_waits() {
        assert_eq!(plan_renewal(2, &[]), RenewalPlan::NoPeersYet);
    }
}
