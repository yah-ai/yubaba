//! Node self-fence, opt-in per workload (R977-F5, W364 §4 item 2).
//!
//! A node that has lost lease contact with the cluster for longer than the
//! leader's re-placement deadline stops each local copy whose workload is
//! `movable` in its `workload_intent` AND opts in through
//! [`SELF_FENCE_ANNOTATION`]. The stop goes through kamaji, which drops the
//! deployed spec, so `restart.rs` cannot resurrect it. The intent is kept.
//!
//! "Lost contact" is [`crate::lease_renewal::last_quorum_contact`]: the latest
//! instant a majority of voters held a renewal from this node. Those renewals
//! are what the leader's lease detector, and so its reconcile, judges this node
//! by, so the fence and the move are measured in the same currency.
//!
//! # Opt-in, default off (operator call 2026-10-11, form F4401)
//!
//! W364 §4 first fenced every movable workload. That turns a fleet-wide loss of
//! raft contact (a tailnet or headscale outage, R858) into a data-plane outage
//! on every node, against R737-T5's rule that the data path keeps serving
//! through quorum loss. So availability through quorum loss stays the default,
//! and the overlap bound is there for any workload that asks for it. fleet-git
//! does not opt in: its writer claim (W363 §3) already fences a stale copy.
//!
//! # The return path
//!
//! After a fence the copy is stopped and its spec is gone, and nothing else
//! restarts it: R977-F3's reconcile acts only on ConfirmedDown nodes, and
//! R977-F4's rejoin cleanup only stops. So once this node is back in contact and
//! caught up, it redeploys its own fenced copy from the intent's `spec_json`
//! under the stamp the copy carried, but only while the intent still places
//! that ordinal on this node at that epoch ([`decide_return`]). If the leader
//! moved it meanwhile, the copy stays down and the new placement stands.
//!
//! Fenced copies are held in memory. A yubaba restart during a fence loses that
//! set, so the first caught-up tick after boot rebuilds it from the same
//! intent-vs-local comparison ([`seed_held`]): every opted-in movable intent
//! that places an ordinal on this node and has no local kamaji copy is held at
//! the intent's own stamp, and [`decide_return`] redeploys it.
//!
//! @yah:assumes("The redeploy goes through R977-F2's crate::place_workload_replica with DeployOrigin::Api and a body carrying only the intent's spec_json. requesting_camp_id / on_behalf_of_user are not in the intent, so a returned copy's cheers ownership row has no camp or user principal. F3's re-placement has the same gap.")
//! @yah:assumes("The seed at boot also restores an opted-in copy kamaji lost for any other reason while the intent still names this node (e.g. a reboot where kamaji did not persist the spec). That is the intent being right, not a side effect to suppress.")

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use openraft::async_runtime::watch::WatchReceiver;
use tracing::{debug, info, warn};
use workload_spec::{Workload, WorkloadSpec};
use yubaba_consensus::workload_intent::{read_intent_stamp, IntentStamp, WorkloadIntent};

use crate::lease_detector::{replacement_grace, HysteresisPolicy};
use crate::raft::{WorkloadKey, YubabaStateMachine};
use crate::{DeployOrigin, ServerState};

/// Spec annotation a workload sets to `"true"` to self-fence when its node is
/// cut off from the cluster. Any other value, or none, is off.
pub const SELF_FENCE_ANNOTATION: &str = "yah.workload-intent.self-fence";

/// Whether `annotations` (a spec's `annotations`) opt into the self-fence.
pub fn self_fence_opted_in(annotations: &HashMap<String, String>) -> bool {
    annotations
        .get(SELF_FENCE_ANNOTATION)
        .is_some_and(|v| v.trim() == "true")
}

/// The two deadlines the fence runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfFenceTiming {
    /// Contact older than this fences: [`replacement_grace`], the one deadline
    /// the leader's reconcile also waits out before it moves anything.
    pub grace: Duration,
    /// Contact at most this old counts as regained, for the return path. Also
    /// the loop's tick.
    pub fresh: Duration,
}

impl SelfFenceTiming {
    /// At the fleet preset (`down_after` 5 s) that is a 65 s grace and a 5 s tick.
    ///
    /// The leader moves a replica once it has held `Confirmed::Down` for
    /// `grace - confirm_down_after`, which is at least `down_after +
    /// confirm_down_after + 60 s` (70 s) after the last renewal it heard. This
    /// node fences at `grace` (65 s) after a majority last heard it, plus at most
    /// one `fresh` tick, so the stop lands no later than the move.
    pub fn from_policy(policy: HysteresisPolicy) -> Self {
        Self {
            grace: replacement_grace(policy),
            fresh: policy.confirm_down_after,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceVerdict {
    Keep,
    Fence,
}

/// The fence rule. `since_contact` is how long ago [`last_quorum_contact`]
/// was; `None` is no evidence (no membership seen yet), never silence.
///
/// Fence only when movable AND opted in AND contact has been lost for at least
/// `grace`. A non-movable workload is never fenced: nothing will re-place it.
///
/// [`last_quorum_contact`]: crate::lease_renewal::last_quorum_contact
pub fn decide_fence(
    movable: bool,
    opted_in: bool,
    since_contact: Option<Duration>,
    timing: SelfFenceTiming,
) -> FenceVerdict {
    if movable && opted_in && since_contact.is_some_and(|d| d >= timing.grace) {
        FenceVerdict::Fence
    } else {
        FenceVerdict::Keep
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnVerdict {
    /// Not back yet (contact not fresh, or applied state not caught up).
    Wait,
    /// The intent still places this copy here at its epoch: deploy it again.
    Redeploy,
    /// Forget the held copy and leave it down: the intent moved it, dropped it,
    /// or a copy is already running here.
    Release,
}

/// The return rule for one held copy, fenced at `held`.
///
/// Compares node names as well as epochs, like `rejoin_cleanup::decide`: a
/// Drop + re-Put restarts epochs, so an epoch match alone could be a new
/// placement elsewhere. A higher epoch on this node means the leader moved it
/// away and back; F3 deploys that placement itself.
pub fn decide_return(
    this_node: &str,
    held: IntentStamp,
    intent: Option<&WorkloadIntent>,
    present_locally: bool,
    since_contact: Option<Duration>,
    caught_up: bool,
    timing: SelfFenceTiming,
) -> ReturnVerdict {
    if !caught_up || !since_contact.is_some_and(|d| d <= timing.fresh) {
        return ReturnVerdict::Wait;
    }
    if present_locally {
        return ReturnVerdict::Release;
    }
    match intent.and_then(|i| i.placements.get(&held.ordinal)) {
        Some(p) if p.node == this_node && p.epoch == held.epoch => ReturnVerdict::Redeploy,
        _ => ReturnVerdict::Release,
    }
}

/// The boot-time rebuild of the held set (module doc): every movable,
/// opted-in intent placing an ordinal on `this_node` that has no local copy,
/// held at the intent's own stamp.
pub fn seed_held(
    this_node: &str,
    intents: &BTreeMap<WorkloadKey, WorkloadIntent>,
    local: &BTreeSet<String>,
) -> BTreeMap<WorkloadKey, IntentStamp> {
    intents
        .iter()
        .filter(|(key, intent)| {
            intent.movable
                && !local.contains(&key.0)
                && spec_annotations(&intent.spec_json).is_some_and(|a| self_fence_opted_in(&a))
        })
        .filter_map(|(key, intent)| {
            let (ordinal, p) = intent
                .placements
                .iter()
                .find(|(_, p)| p.node == this_node)?;
            Some((
                key.clone(),
                IntentStamp {
                    ordinal: *ordinal,
                    epoch: p.epoch,
                },
            ))
        })
        .collect()
}

/// A deploy body's spec annotations: the envelope form first, the bare spec
/// second, as the deploy path parses it.
fn spec_annotations(spec_json: &str) -> Option<HashMap<String, String>> {
    match serde_json::from_str::<Workload>(spec_json) {
        Ok(w) => w.container_spec().map(|s| s.annotations.clone()),
        Err(_) => serde_json::from_str::<WorkloadSpec>(spec_json)
            .ok()
            .map(|s| s.annotations),
    }
}

/// The intent key a kamaji entry runs under: its mesh ident, else its id
/// (the same rule `rejoin_cleanup` uses).
pub(crate) fn local_key(entry: &kamaji_proto::WorkloadEntry) -> String {
    entry
        .mesh_ident
        .clone()
        .unwrap_or_else(|| entry.id.0.clone())
}

pub fn spawn(state: Arc<ServerState>, timing: SelfFenceTiming) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(state, timing))
}

async fn run(state: Arc<ServerState>, timing: SelfFenceTiming) {
    let (Some(node_id), Some(raft), Some(sm), Some(kamaji)) = (
        state.node_id,
        state.raft.clone(),
        state.cluster_state.clone(),
        state.constable_client.clone(),
    ) else {
        debug!("workload fence: needs raft and a kamaji sibling, not running");
        return;
    };
    let Some(this_node) = crate::leader::derive_machine_name() else {
        warn!("workload fence: no machine name, cannot tell which placements are ours");
        return;
    };
    let watch = raft.metrics();
    let mut held: BTreeMap<WorkloadKey, IntentStamp> = BTreeMap::new();
    let mut seeded = false;
    // rejoin_cleanup's rule: caught up on two consecutive ticks, same leader.
    let mut armed: Option<crate::raft::YubabaNodeId> = None;
    loop {
        tokio::time::sleep(timing.fresh).await;
        let since_contact =
            crate::lease_renewal::last_quorum_contact(node_id).map(|at| at.elapsed());
        let Some(client) = kamaji.current() else {
            continue;
        };
        if since_contact.is_some_and(|d| d >= timing.grace) {
            armed = None;
            fence_sweep(&state, &client, &sm, since_contact, timing, &mut held).await;
            continue;
        }
        let (ok, leader) = {
            let m = watch.borrow_watched();
            let ok = crate::rejoin_cleanup::caught_up(
                m.last_applied.as_ref().map(|l| l.index),
                m.cluster_committed.as_ref().map(|l| l.index),
                m.current_leader.is_some(),
            );
            (ok, m.current_leader)
        };
        let caught_up = ok && armed == leader;
        armed = if ok { leader } else { None };
        if !caught_up || (seeded && held.is_empty()) {
            continue;
        }
        let local: BTreeSet<String> = match client.list().await {
            Ok(entries) => entries.iter().map(local_key).collect(),
            Err(e) => {
                debug!("workload fence: kamaji list failed: {e}");
                continue;
            }
        };
        let intents = sm.with_state(|s| s.workload_intent.clone());
        if !seeded {
            held.extend(seed_held(&this_node, &intents, &local));
            seeded = true;
        }
        let mut done = Vec::new();
        for (key, stamp) in &held {
            let intent = intents.get(key);
            match decide_return(
                &this_node,
                *stamp,
                intent,
                local.contains(&key.0),
                since_contact,
                caught_up,
                timing,
            ) {
                ReturnVerdict::Wait => {}
                ReturnVerdict::Release => {
                    info!(ident = %key.0, ?stamp, "workload fence: intent no longer places the fenced copy here, leaving it down");
                    done.push(key.clone());
                }
                ReturnVerdict::Redeploy => {
                    if let Some(intent) = intent {
                        if redeploy(&state, key, &intent, *stamp).await {
                            done.push(key.clone());
                        }
                    }
                }
            }
        }
        for key in done {
            held.remove(&key);
        }
    }
}

/// Stop every local copy [`decide_fence`] fences, and hold its stamp.
async fn fence_sweep(
    state: &Arc<ServerState>,
    client: &Arc<kamaji::sibling::KamajiClient>,
    sm: &YubabaStateMachine,
    since_contact: Option<Duration>,
    timing: SelfFenceTiming,
    held: &mut BTreeMap<WorkloadKey, IntentStamp>,
) {
    let entries = match client.list().await {
        Ok(e) => e,
        Err(e) => {
            warn!("workload fence: kamaji list failed while cut off, cannot fence: {e}");
            return;
        }
    };
    let intents = sm.with_state(|s| s.workload_intent.clone());
    for entry in entries {
        let key = WorkloadKey(local_key(&entry));
        // No intent: the leader has nothing to re-place it from, so no second
        // copy can appear and there is nothing to fence against.
        let Some(intent) = intents.get(&key) else {
            continue;
        };
        if held.contains_key(&key) {
            continue;
        }
        let spec = match client.describe(&entry.id).await {
            Ok(Some(w)) => w.container_spec().cloned(),
            _ => None,
        };
        // No stamp: the return path could not tell whether the intent still
        // places this copy here, so it is never fenced.
        let Some((spec, stamp)) =
            spec.and_then(|s| read_intent_stamp(&s.annotations).map(|st| (s, st)))
        else {
            continue;
        };
        let verdict = decide_fence(
            intent.movable,
            self_fence_opted_in(&spec.annotations),
            since_contact,
            timing,
        );
        if verdict == FenceVerdict::Keep {
            continue;
        }
        let Some(_lock) = ServerState::try_lock_deploy(state, &key.0) else {
            continue;
        };
        match client.stop(&entry.id).await {
            Ok(()) => {
                warn!(ident = %key.0, ?stamp, ?since_contact, "workload fence: cut off from the cluster past grace, stopped this opted-in copy");
                held.insert(key, stamp);
            }
            Err(e) => warn!(ident = %key.0, "workload fence: kamaji stop failed: {e}"),
        }
    }
}

/// Redeploy a fenced copy from its intent, under its own stamp. `true` when
/// the hold is finished: placed, or a `spec_json` that can never be placed.
async fn redeploy(
    state: &Arc<ServerState>,
    key: &WorkloadKey,
    intent: &WorkloadIntent,
    stamp: IntentStamp,
) -> bool {
    // R997-B11: the same attestation check every intent placement passes.
    let body = match crate::workload_reconcile::deploy_body_from_intent(state, key, intent) {
        Ok(body) => body,
        Err(e) => {
            warn!(ident = %key.0, "workload fence: cannot redeploy from this intent: {e}");
            return true;
        }
    };
    let resp =
        crate::place_workload_replica(state.clone(), body, DeployOrigin::Api, Some(stamp)).await;
    if resp.status().is_success() {
        info!(ident = %key.0, ?stamp, "workload fence: back in contact, redeployed the fenced copy");
        true
    } else {
        let error = crate::response_error(resp).await;
        warn!(ident = %key.0, ?stamp, "workload fence: redeploy failed, retrying next tick: {error}");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use yubaba_consensus::workload_intent::ReplicaPlacement;

    use crate::cluster_policy::{LivenessThresholds, RaftTiming};

    fn fleet() -> SelfFenceTiming {
        SelfFenceTiming::from_policy(HysteresisPolicy::from_thresholds(
            LivenessThresholds::from_timing(RaftTiming::wan()),
        ))
    }

    fn spec_json(opted_in: bool) -> String {
        let mut spec = WorkloadSpec::for_forge(
            "svc",
            workload_spec::ImageRef {
                registry: "localhost".into(),
                repository: "test".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            workload_spec::TierTag("infra".into()),
            vec![],
        );
        if opted_in {
            spec.annotations
                .insert(SELF_FENCE_ANNOTATION.to_owned(), "true".to_owned());
        }
        serde_json::to_string(&spec).unwrap()
    }

    fn intent(node: &str, epoch: u64, movable: bool, spec_json: String) -> WorkloadIntent {
        WorkloadIntent {
            spec_json,
            replicas: 1,
            placements: [(
                0,
                ReplicaPlacement {
                    node: node.into(),
                    epoch,
                },
            )]
            .into(),
            movable,
            requesting_camp_id: None,
            on_behalf_of_user: None,
            operator_sig: None,
        }
    }

    const STAMP: IntentStamp = IntentStamp {
        ordinal: 0,
        epoch: 3,
    };

    #[test]
    fn the_annotation_opts_in_only_on_true() {
        let mut a = HashMap::new();
        assert!(!self_fence_opted_in(&a));
        a.insert(SELF_FENCE_ANNOTATION.to_owned(), "false".to_owned());
        assert!(!self_fence_opted_in(&a));
        a.insert(SELF_FENCE_ANNOTATION.to_owned(), "true".to_owned());
        assert!(self_fence_opted_in(&a));
    }

    /// The grace is the leader's: confirm_down_after (5 s at the fleet preset)
    /// plus the 60 s restart window, floored at 120 s (R977-F3,
    /// `lease_detector::REPLACEMENT_GRACE_FLOOR`).
    #[test]
    fn the_fleet_grace_is_the_floored_replacement_grace() {
        let t = fleet();
        assert_eq!(t.grace, Duration::from_secs(120));
        assert_eq!(t.fresh, Duration::from_secs(5));
    }

    /// Time injected: contact last held at t0. Inside grace keeps, at grace
    /// fences, and contact regained before grace resets the clock.
    #[test]
    fn the_fence_waits_out_grace_from_the_last_quorum_contact() {
        let t = fleet();
        let t0 = Instant::now();
        let since = |contact: Instant, now: Instant| Some(now.saturating_duration_since(contact));

        let just_inside = t0 + t.grace - Duration::from_millis(1);
        assert_eq!(
            decide_fence(true, true, since(t0, just_inside), t),
            FenceVerdict::Keep
        );
        assert_eq!(
            decide_fence(true, true, since(t0, t0 + t.grace), t),
            FenceVerdict::Fence
        );
        assert_eq!(
            decide_fence(true, true, since(t0, t0 + t.grace * 2), t),
            FenceVerdict::Fence
        );

        // A renewal lands at t0 + 40 s: at t0 + grace the node has been back
        // for 25 s and keeps its copy.
        let regained = t0 + Duration::from_secs(40);
        assert_eq!(
            decide_fence(true, true, since(regained, t0 + t.grace), t),
            FenceVerdict::Keep
        );
    }

    #[test]
    fn only_a_movable_opted_in_workload_is_fenced() {
        let t = fleet();
        let lost = Some(t.grace + Duration::from_secs(600));
        assert_eq!(decide_fence(true, true, lost, t), FenceVerdict::Fence);
        assert_eq!(
            decide_fence(false, true, lost, t),
            FenceVerdict::Keep,
            "non-movable: never"
        );
        assert_eq!(
            decide_fence(true, false, lost, t),
            FenceVerdict::Keep,
            "default off"
        );
        assert_eq!(decide_fence(false, false, lost, t), FenceVerdict::Keep);
    }

    #[test]
    fn no_contact_evidence_never_fences() {
        assert_eq!(decide_fence(true, true, None, fleet()), FenceVerdict::Keep);
    }

    #[test]
    fn back_in_contact_and_still_placed_here_at_the_same_epoch_redeploys() {
        let t = fleet();
        let i = intent("a", 3, true, String::new());
        let fresh = Some(Duration::from_secs(1));
        assert_eq!(
            decide_return("a", STAMP, Some(&i), false, fresh, true, t),
            ReturnVerdict::Redeploy
        );
    }

    #[test]
    fn the_return_waits_for_fresh_contact_and_caught_up_state() {
        let t = fleet();
        let i = intent("a", 3, true, String::new());
        let stale = Some(t.fresh + Duration::from_millis(1));
        let fresh = Some(t.fresh);
        assert_eq!(
            decide_return("a", STAMP, Some(&i), false, stale, true, t),
            ReturnVerdict::Wait
        );
        assert_eq!(
            decide_return("a", STAMP, Some(&i), false, None, true, t),
            ReturnVerdict::Wait
        );
        assert_eq!(
            decide_return("a", STAMP, Some(&i), false, fresh, false, t),
            ReturnVerdict::Wait
        );
    }

    #[test]
    fn an_intent_that_moved_dropped_or_came_back_at_a_new_epoch_releases() {
        let t = fleet();
        let fresh = Some(Duration::ZERO);
        let moved = intent("b", 4, true, String::new());
        assert_eq!(
            decide_return("a", STAMP, Some(&moved), false, fresh, true, t),
            ReturnVerdict::Release
        );
        // Away and back: F3 deploys epoch 5 itself.
        let back = intent("a", 5, true, String::new());
        assert_eq!(
            decide_return("a", STAMP, Some(&back), false, fresh, true, t),
            ReturnVerdict::Release
        );
        // Drop + re-Put elsewhere at the same epoch number.
        let reput = intent("b", 3, true, String::new());
        assert_eq!(
            decide_return("a", STAMP, Some(&reput), false, fresh, true, t),
            ReturnVerdict::Release
        );
        assert_eq!(
            decide_return("a", STAMP, None, false, fresh, true, t),
            ReturnVerdict::Release
        );
        // Scale-down while away: no placement for the ordinal.
        let other_ordinal = IntentStamp {
            ordinal: 1,
            epoch: 3,
        };
        let i = intent("a", 3, true, String::new());
        assert_eq!(
            decide_return("a", other_ordinal, Some(&i), false, fresh, true, t),
            ReturnVerdict::Release
        );
    }

    #[test]
    fn a_copy_already_running_here_releases_rather_than_redeploying_over_it() {
        let t = fleet();
        let i = intent("a", 3, true, String::new());
        assert_eq!(
            decide_return("a", STAMP, Some(&i), true, Some(Duration::ZERO), true, t),
            ReturnVerdict::Release
        );
    }

    /// A yubaba restart lost the held set: the comparison rebuilds it from
    /// opted-in movable intents placed here with no local copy, and nothing
    /// else.
    #[test]
    fn the_boot_seed_holds_only_missing_opted_in_movable_copies_placed_here() {
        let opted = spec_json(true);
        let plain = spec_json(false);
        let intents: BTreeMap<WorkloadKey, WorkloadIntent> = [
            ("fenced", intent("a", 3, true, opted.clone())),
            ("running", intent("a", 2, true, opted.clone())),
            ("elsewhere", intent("b", 7, true, opted.clone())),
            ("pinned", intent("a", 1, false, opted.clone())),
            ("not-opted", intent("a", 1, true, plain)),
        ]
        .into_iter()
        .map(|(k, i)| (WorkloadKey(k.into()), i))
        .collect();
        let local: BTreeSet<String> = ["running".to_owned()].into();
        let seeded = seed_held("a", &intents, &local);
        assert_eq!(
            seeded,
            [(WorkloadKey("fenced".into()), STAMP)]
                .into_iter()
                .collect()
        );
    }
}
