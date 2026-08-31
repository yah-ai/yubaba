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
    /// This node believes it is the leader — renew locally, no HTTP.
    SelfRenew,
    /// Renew against this leader mesh address.
    ForwardTo(String),
    /// No leader known yet, or this node is not the leader and raft has not
    /// handed back an address for whoever is — nothing to renew against.
    NoLeaderYet,
}

fn plan_renewal(
    node_id: YubabaNodeId,
    current_leader: Option<YubabaNodeId>,
    leader_addr: Option<&str>,
) -> RenewalPlan {
    match current_leader {
        Some(id) if id == node_id => RenewalPlan::SelfRenew,
        Some(_) => match leader_addr {
            Some(addr) => RenewalPlan::ForwardTo(addr.to_string()),
            None => RenewalPlan::NoLeaderYet,
        },
        None => RenewalPlan::NoLeaderYet,
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

        let (current_leader, leader_addr) = {
            let metrics = watch.borrow_watched();
            let leader = metrics.current_leader;
            let addr = leader.and_then(|id| {
                metrics
                    .membership_config
                    .membership()
                    .get_node(&id)
                    .map(|n| n.addr.clone())
            });
            (leader, addr)
        };

        match plan_renewal(node_id, current_leader, leader_addr.as_deref()) {
            RenewalPlan::SelfRenew => {
                if let Some(detector) = &lease_detector {
                    detector.renew(node_id);
                    debug!(node_id, "lease renewal: renewed self (leader)");
                }
            }
            RenewalPlan::ForwardTo(addr) => {
                let url = format!("http://{addr}/mesh/lease-renew");
                match client
                    .post(&url)
                    .json(&serde_json::json!({ "node_id": node_id }))
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        debug!(node_id, %addr, "lease renewal: renewed against leader");
                    }
                    Ok(resp) => {
                        warn!(
                            node_id,
                            %addr,
                            status = %resp.status(),
                            "lease renewal: leader refused the renewal — will retry next tick"
                        );
                    }
                    Err(e) => {
                        warn!(
                            node_id,
                            %addr,
                            "lease renewal: POST failed, will retry next tick: {e}"
                        );
                    }
                }
            }
            RenewalPlan::NoLeaderYet => {
                debug!(node_id, "lease renewal: no leader known yet, waiting");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_leader_renews_itself_without_an_address() {
        assert_eq!(plan_renewal(1, Some(1), None), RenewalPlan::SelfRenew);
    }

    #[test]
    fn a_follower_forwards_to_the_known_leader_address() {
        assert_eq!(
            plan_renewal(2, Some(1), Some("100.64.0.1:7443")),
            RenewalPlan::ForwardTo("100.64.0.1:7443".to_string())
        );
    }

    #[test]
    fn a_follower_with_no_leader_address_waits() {
        assert_eq!(plan_renewal(2, Some(1), None), RenewalPlan::NoLeaderYet);
    }

    #[test]
    fn no_elected_leader_at_all_waits_regardless_of_a_stale_address() {
        // A stale address surviving in the watch after an election is not
        // usable — `current_leader: None` must dominate.
        assert_eq!(plan_renewal(2, None, Some("100.64.0.1:7443")), RenewalPlan::NoLeaderYet);
    }
}
