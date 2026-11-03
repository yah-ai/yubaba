//! Rejoin cleanup (R977-F4, W364 §4 item 3 and §6).
//!
//! A node that was away (restarted, or on the wrong side of a partition) while
//! one of its replicas was moved elsewhere comes back still running the old
//! copy. Once this node's applied state has caught up with the cluster's
//! commit index, every local copy carrying an intent stamp is compared with
//! `workload_intent`; a copy the intent no longer places here, at this epoch,
//! is Stopped through kamaji. Stop drops kamaji's deployed spec, so
//! `restart.rs` (which restarts only specs it still holds) cannot resurrect it.
//!
//! HELD COPIES (R977-B14). On restart kamaji does not start a recorded deploy
//! carrying an intent stamp; it holds it (kamaji `Registry::held`, listed as
//! `Pending` with no pid and no `spec_digest`, see [`held_for_owner`]). This
//! sweep is the ONE owner that ends a hold: [`confirm_held`] says Confirm
//! (kamaji Deploy of the held spec — the copy starts through the ordinary
//! deploy path) or Discard (kamaji Stop). Before this, kamaji resumed the stale
//! copy ~60 s ahead of this sweep and it stole the writer claim from the moved
//! copy. R977-B15 is meant to reuse the same seam for durability tails.
//!
//! The decision is [`decide`], pure and unit-tested as arithmetic. The caught-up
//! gate is [`caught_up`], read off raft metrics on every tick, so a restart and
//! a healed partition take the same path: both are "a tick where the node had
//! fallen behind, followed by ticks where it has not".
//!
//! @yah:gotcha("STAMPED COPY, NO INTENT = KEEP. A copy carrying a stamp whose workload has no intent row was destroyed (DropWorkloadIntent) while this node was away. Stopping it is probably right, but `decide` keeps it: a destroy also runs teardown on the node that held the copy, and a Drop/re-Put race (F1: re-Put restarts epochs) is indistinguishable from it here. A leaked copy is visible and operator-recoverable; a wrongly stopped one is an outage. Same reasoning for an intent with no placement for the copy's ordinal (a scale-down while away): KEEP.")
//! @yah:gotcha("CAUGHT-UP SIGNAL is metrics-only: last_applied.index >= cluster_committed.index (the leader-reported quorum frontier, openraft 0.10), with a known current_leader. A partitioned follower whose cluster_committed is stale can read itself caught up, but its state can then only be OLDER than the truth, and an older intent can only name this node at the epoch it deployed at (Keep) — except the case where the copy was deployed from a leader response this node had not yet applied. Bounded by requiring the gate to hold on two consecutive ticks with the leader unchanged. A linearizable read (raft.ensure_linearizable) is leader-only in openraft and was not used.")
//! @yah:assumes("ReplicaPlacement.node is the machine name from leader::derive_machine_name(), per R977-F1's handoff ('node: String machine name'); WorkloadKey is the kamaji entry's mesh ident (falling back to its id). If R977-F2 stamps a different node string, every stamped copy reads as 'another node' and is STOPPED — check F2's placement writer before rolling.")

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kamaji_proto::WorkloadId;
use openraft::async_runtime::watch::WatchReceiver;
use tracing::{debug, info, warn};
use yubaba_consensus::workload_intent::{
    read_intent_stamp, IntentStamp, WorkloadIntent, WorkloadKey,
};

use crate::raft::{YubabaRaft, YubabaStateMachine};

/// What to do with one local copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Keep,
    Stop,
}

/// The stale-copy rule (W364 §4 item 3).
///
/// - no stamp: Keep (deployed before intent existed, or by a path that does not stamp)
/// - no intent / no placement for the stamped ordinal: Keep (see module gotcha)
/// - intent places the ordinal on another node: Stop (names, not epochs, because
///   a Drop + re-Put restarts epochs)
/// - same node, intent epoch above the stamp: Stop (moved away and back)
/// - otherwise: Keep
pub fn decide(
    this_node: &str,
    stamp: Option<IntentStamp>,
    intent: Option<&WorkloadIntent>,
) -> Verdict {
    let (Some(stamp), Some(intent)) = (stamp, intent) else {
        return Verdict::Keep;
    };
    let Some(placement) = intent.placements.get(&stamp.ordinal) else {
        return Verdict::Keep;
    };
    if placement.node != this_node || placement.epoch > stamp.epoch {
        Verdict::Stop
    } else {
        Verdict::Keep
    }
}

/// What to do with a copy kamaji is holding for its owner (R977-B14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldVerdict {
    /// The intent still places this ordinal here at this epoch: start it.
    Confirm,
    /// The intent places it elsewhere, or here at a newer epoch: drop it.
    Discard,
    /// No intent row, or no placement for the ordinal: neither — the same
    /// ambiguity [`decide`] keeps on (module gotcha). Stays held and visible.
    Hold,
}

/// The held-copy rule: [`decide`]'s arithmetic, except that a held copy only
/// starts on a positive placement, never on the absence of one.
pub fn confirm_held(
    this_node: &str,
    stamp: IntentStamp,
    intent: Option<&WorkloadIntent>,
) -> HeldVerdict {
    let Some(intent) = intent else {
        return HeldVerdict::Hold;
    };
    if !intent.placements.contains_key(&stamp.ordinal) {
        return HeldVerdict::Hold;
    }
    match decide(this_node, Some(stamp), Some(intent)) {
        Verdict::Keep => HeldVerdict::Confirm,
        Verdict::Stop => HeldVerdict::Discard,
    }
}

/// Is this kamaji row a copy held until its owner confirms (R977-B14)? Kamaji
/// reports a hold as `Pending` with no pid and no `spec_digest` — an admitted
/// deploy always carries a digest, so only a hold matches all three.
pub fn held_for_owner(entry: &kamaji_proto::WorkloadEntry) -> bool {
    entry.state == kamaji_proto::WorkloadState::Pending
        && entry.pid.is_none()
        && entry.spec_digest.is_none()
}

/// Applied state has reached the leader-reported commit frontier.
pub fn caught_up(
    last_applied: Option<u64>,
    cluster_committed: Option<u64>,
    has_leader: bool,
) -> bool {
    match (last_applied, cluster_committed) {
        (_, None) => false,
        (applied, Some(committed)) => has_leader && applied.is_some_and(|a| a >= committed),
    }
}

pub fn spawn(
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    state: Arc<crate::ServerState>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(raft, state_machine, state, interval))
}

async fn run(
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    state: Arc<crate::ServerState>,
    interval: Duration,
) {
    let Some(kamaji) = state.constable_client.clone() else {
        debug!("rejoin cleanup: no kamaji sibling configured, not running");
        return;
    };
    let Some(this_node) = crate::leader::derive_machine_name() else {
        warn!("rejoin cleanup: no machine name, cannot tell which placements are ours");
        return;
    };
    let watch = raft.metrics();
    // Leader seen caught-up on the previous tick; the gate must hold twice.
    let mut armed: Option<u64> = None;
    loop {
        tokio::time::sleep(interval).await;
        let (ok, leader) = {
            let m = watch.borrow_watched();
            let leader = m.current_leader;
            let ok = caught_up(
                m.last_applied.as_ref().map(|l| l.index),
                m.cluster_committed.as_ref().map(|l| l.index),
                leader.is_some(),
            );
            (ok, leader)
        };
        if !ok {
            armed = None;
            continue;
        }
        if armed != leader {
            armed = leader;
            continue;
        }
        let Some(client) = kamaji.current() else {
            continue;
        };
        sweep(&this_node, &client, &state_machine, &state).await;
    }
}

async fn sweep(
    this_node: &str,
    client: &Arc<kamaji::sibling::KamajiClient>,
    sm: &YubabaStateMachine,
    state: &crate::ServerState,
) {
    let entries = match client.list().await {
        Ok(e) => e,
        Err(e) => {
            debug!("rejoin cleanup: kamaji list failed: {e}");
            return;
        }
    };
    let intents: BTreeMap<WorkloadKey, WorkloadIntent> =
        sm.with_state(|s| s.workload_intent.clone());
    for entry in entries {
        let key = WorkloadKey(
            entry
                .mesh_ident
                .clone()
                .unwrap_or_else(|| entry.id.0.clone()),
        );
        // Unknown (Err / None) is not "unstamped" in a way that licenses
        // anything here, and Keep is the only outcome either way.
        let workload = match client.describe(&entry.id).await {
            Ok(w) => w,
            Err(_) => None,
        };
        let stamp = workload
            .as_ref()
            .and_then(|w| w.container_spec())
            .and_then(|s| read_intent_stamp(&s.annotations));
        if held_for_owner(&entry) {
            let (Some(stamp), Some(workload)) = (stamp, workload) else {
                continue;
            };
            resolve_held(this_node, client, state, &entry, &key, stamp, &workload, intents.get(&key))
                .await;
            continue;
        }
        if decide(this_node, stamp, intents.get(&key)) == Verdict::Stop {
            info!(ident = %key.0, ?stamp, "rejoin cleanup: intent no longer places this copy here, stopping it");
            if let Err(e) = client.stop(&WorkloadId(entry.id.0.clone())).await {
                warn!(ident = %key.0, "rejoin cleanup: kamaji stop failed: {e}");
            }
        }
    }
}

/// End one hold per [`confirm_held`].
#[allow(clippy::too_many_arguments)]
async fn resolve_held(
    this_node: &str,
    client: &Arc<kamaji::sibling::KamajiClient>,
    state: &crate::ServerState,
    entry: &kamaji_proto::WorkloadEntry,
    key: &WorkloadKey,
    stamp: IntentStamp,
    workload: &workload_spec::Workload,
    intent: Option<&WorkloadIntent>,
) {
    match confirm_held(this_node, stamp, intent) {
        HeldVerdict::Hold => {
            debug!(ident = %key.0, ?stamp, "rejoin cleanup: held copy has no placement to confirm; left held");
        }
        HeldVerdict::Discard => {
            info!(ident = %key.0, ?stamp, "rejoin cleanup: held copy is no longer placed here, discarding it (R977-B14)");
            if let Err(e) = client.stop(&entry.id).await {
                warn!(ident = %key.0, "rejoin cleanup: kamaji stop of a held copy failed: {e}");
            }
        }
        HeldVerdict::Confirm => {
            let Some(spec) = workload.container_spec() else {
                return;
            };
            // Same mesh the deploy handler hands kamaji for this spec.
            let mesh = crate::mesh::MeshAssignment::stub(
                state
                    .workload_bind_ip(spec)
                    .unwrap_or(std::net::Ipv4Addr::LOCALHOST),
            );
            info!(ident = %key.0, ?stamp, "rejoin cleanup: intent still places the held copy here, starting it (R977-B14)");
            if let Err(e) = client.deploy_envelope(&entry.id, workload, Some(&mesh)).await {
                warn!(ident = %key.0, "rejoin cleanup: deploy of a confirmed held copy failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yubaba_consensus::workload_intent::ReplicaPlacement;

    fn intent(node: &str, epoch: u64) -> WorkloadIntent {
        WorkloadIntent {
            spec_json: String::new(),
            replicas: 1,
            placements: [(
                0,
                ReplicaPlacement {
                    node: node.into(),
                    epoch,
                },
            )]
            .into(),
            movable: true,
            requesting_camp_id: None,
            on_behalf_of_user: None,
            operator_sig: None,
        }
    }
    fn stamp(epoch: u64) -> Option<IntentStamp> {
        Some(IntentStamp { ordinal: 0, epoch })
    }

    #[test]
    fn intent_naming_another_node_stops() {
        assert_eq!(decide("a", stamp(3), Some(&intent("b", 4))), Verdict::Stop);
    }

    #[test]
    fn another_node_stops_even_at_a_lower_epoch_after_drop_and_reput() {
        assert_eq!(decide("a", stamp(5), Some(&intent("b", 1))), Verdict::Stop);
    }

    #[test]
    fn same_node_higher_epoch_stops() {
        assert_eq!(decide("a", stamp(1), Some(&intent("a", 3))), Verdict::Stop);
    }

    #[test]
    fn same_node_same_epoch_keeps() {
        assert_eq!(decide("a", stamp(2), Some(&intent("a", 2))), Verdict::Keep);
    }

    #[test]
    fn same_node_lower_epoch_keeps() {
        assert_eq!(decide("a", stamp(4), Some(&intent("a", 1))), Verdict::Keep);
    }

    #[test]
    fn no_intent_keeps_even_a_stamped_copy() {
        assert_eq!(decide("a", stamp(2), None), Verdict::Keep);
    }

    #[test]
    fn unstamped_copy_keeps() {
        assert_eq!(decide("a", None, Some(&intent("b", 9))), Verdict::Keep);
    }

    #[test]
    fn ordinal_absent_from_intent_keeps() {
        let s = Some(IntentStamp {
            ordinal: 1,
            epoch: 0,
        });
        assert_eq!(decide("a", s, Some(&intent("b", 9))), Verdict::Keep);
    }

    #[test]
    fn held_copy_confirmed_when_intent_places_it_here() {
        assert_eq!(confirm_held("a", IntentStamp { ordinal: 0, epoch: 2 }, Some(&intent("a", 2))), HeldVerdict::Confirm);
    }

    #[test]
    fn held_copy_discarded_when_moved_or_superseded() {
        let s = IntentStamp { ordinal: 0, epoch: 2 };
        assert_eq!(confirm_held("a", s, Some(&intent("b", 3))), HeldVerdict::Discard);
        assert_eq!(confirm_held("a", s, Some(&intent("a", 3))), HeldVerdict::Discard);
    }

    #[test]
    fn held_copy_without_a_placement_stays_held() {
        let s = IntentStamp { ordinal: 1, epoch: 0 };
        assert_eq!(confirm_held("a", s, None), HeldVerdict::Hold);
        assert_eq!(confirm_held("a", s, Some(&intent("a", 0))), HeldVerdict::Hold);
    }

    fn entry(state: kamaji_proto::WorkloadState, pid: Option<u32>) -> kamaji_proto::WorkloadEntry {
        kamaji_proto::WorkloadEntry {
            id: kamaji_proto::WorkloadId::new("fleet-git"),
            state,
            pid,
            mesh_ident: None,
            ports: Vec::new(),
            named_ports: Default::default(),
            spec_digest: None,
        }
    }

    #[test]
    fn only_a_pending_pidless_undigested_row_reads_as_held() {
        use kamaji_proto::WorkloadState as S;
        assert!(held_for_owner(&entry(S::Pending, None)));
        assert!(!held_for_owner(&entry(S::Running, Some(7))));
        assert!(!held_for_owner(&entry(S::Exited, None)));
    }

    #[test]
    fn caught_up_needs_applied_at_commit_and_a_leader() {
        assert!(caught_up(Some(10), Some(10), true));
        assert!(!caught_up(Some(9), Some(10), true));
        assert!(!caught_up(Some(10), Some(10), false));
        assert!(!caught_up(None, Some(0), true));
        assert!(!caught_up(Some(10), None, true));
    }
}
