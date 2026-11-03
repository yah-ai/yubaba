//! R977-F1 (W364 §1): replicated workload intent — what should be running,
//! how many replicas, and which node holds each ordinal under which epoch.
//!
//! The map itself lives on [`YubabaState::workload_intent`](crate::raft::YubabaState)
//! and is written only through `PutWorkloadIntent` / `DropWorkloadIntent` /
//! `MoveWorkloadReplica`. This module owns the record types and the two seams
//! the rest of R977 shares:
//!
//! - [`workload_intent_writes_open`] — the write gate. Nothing may commit one
//!   of the three variants until every voter runs a build that can apply them.
//! - [`WORKLOAD_INTENT_STAMP_ANNOTATION`] + [`stamp_intent`] / [`read_intent_stamp`]
//!   — the record of which ordinal and epoch a local kamaji copy was deployed
//!   at, so rejoin cleanup (R977-F4) can tell a stale copy from a current one.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::raft::YubabaNodeId;

/// The workload's identity: the same `ident` string the deploy and destroy
/// paths address it by. Serialized flat so it can key a JSON map.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadKey(pub String);

/// Where one ordinal lives, and under which epoch.
///
/// `node` is the machine name (W364 §1), the string the deploy path places by.
/// `epoch` only ever rises for a given key while the record exists: every
/// [`MoveWorkloadReplica`](crate::raft::YubabaRequest::MoveWorkloadReplica)
/// bumps it, and a re-`Put` never lowers it (see [`apply_put`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaPlacement {
    pub node: String,
    pub epoch: u64,
}

/// One workload's declared intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIntent {
    /// The `WorkloadSpec` the deploy accepted, verbatim.
    pub spec_json: String,
    /// `spec.replicas`, copied for the reconcile loop.
    pub replicas: u32,
    /// Ordinal → placement.
    pub placements: BTreeMap<u32, ReplicaPlacement>,
    /// Decided once at deploy time (W364 §5). A non-movable intent is never
    /// re-placed; the loop reports it as stranded.
    pub movable: bool,
    /// The deploy's `requesting_camp_id`, carried so a re-placed or
    /// redeployed copy keeps its cheers camp attribution. `None` on an intent
    /// recorded before this field existed.
    #[serde(default)]
    pub requesting_camp_id: Option<String>,
    /// The deploy's `on_behalf_of_user`, for the same reason.
    #[serde(default)]
    pub on_behalf_of_user: Option<String>,
    /// R997-B11: the operator's signature over `spec_json`
    /// (`yubaba_auth_token::delegation::sign_workload_spec`). A node places
    /// a replica from an intent only under a valid one, so a raft write alone
    /// is never a deploy. Moves change placements and carry it untouched.
    /// `None` on an intent recorded before this field, or by an unsigned
    /// deploy; such an intent is never re-placed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_sig: Option<String>,
}

/// The answer to the three workload-intent requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkloadIntentOutcome {
    /// `PutWorkloadIntent` applied. `placements` is what raft now holds, which
    /// can carry higher epochs than the request did; stamp THESE on the deploy.
    Recorded {
        placements: BTreeMap<u32, ReplicaPlacement>,
    },
    /// `DropWorkloadIntent` applied (also when there was nothing to drop).
    Dropped,
    /// `MoveWorkloadReplica` applied, or was already applied (a replay).
    /// `placement` is the ordinal's new record; its epoch is the stamp.
    Moved { placement: ReplicaPlacement },
    /// `MoveWorkloadReplica` refused: the caller's `(from_node, from_epoch)`
    /// is not what raft holds. `current` is what it does hold (`None`: no such
    /// key or ordinal).
    Fenced { current: Option<ReplicaPlacement> },
    /// `AttestWorkloadIntent` found no intent under the key, or one whose
    /// spec is not the attested one (R997-B11). Nothing changed.
    NotAttested,
}

/// Apply `PutWorkloadIntent`. Last-write-wins on the record, except that an
/// ordinal's epoch never regresses: a redeploy carrying `epoch: 1` over an
/// ordinal raft already moved to epoch 4 keeps 4 (same node) or takes 5 (a
/// different node). Without that, A→B→A could hand a stale copy on A the same
/// stamp as the current one.
pub(crate) fn apply_put(
    map: &mut BTreeMap<WorkloadKey, WorkloadIntent>,
    key: &WorkloadKey,
    intent: &WorkloadIntent,
) -> WorkloadIntentOutcome {
    let mut next = intent.clone();
    if let Some(existing) = map.get(key) {
        for (ordinal, placement) in next.placements.iter_mut() {
            if let Some(prev) = existing.placements.get(ordinal) {
                let floor = if prev.node == placement.node {
                    prev.epoch
                } else {
                    prev.epoch + 1
                };
                placement.epoch = placement.epoch.max(floor);
            }
        }
    }
    let placements = next.placements.clone();
    map.insert(key.clone(), next);
    WorkloadIntentOutcome::Recorded { placements }
}

/// Apply `AttestWorkloadIntent` (R997-B11): set the signature only when the
/// stored spec is byte-for-byte the one the signature was checked against at
/// admission, so a concurrent redeploy is never stamped with the old spec's
/// signature. Signature validity is the admitting node's check; every placing
/// node re-verifies it anyway.
pub(crate) fn apply_attest(
    map: &mut BTreeMap<WorkloadKey, WorkloadIntent>,
    key: &WorkloadKey,
    spec_json: &str,
    operator_sig: &str,
) -> WorkloadIntentOutcome {
    match map.get_mut(key) {
        Some(intent) if intent.spec_json == spec_json => {
            intent.operator_sig = Some(operator_sig.to_string());
            WorkloadIntentOutcome::Recorded {
                placements: intent.placements.clone(),
            }
        }
        _ => WorkloadIntentOutcome::NotAttested,
    }
}

/// Apply `MoveWorkloadReplica`: a CAS on `(from_node, from_epoch)` that bumps
/// the epoch. Same already-applied shortcut as `TransferTenant` (R732-F1): a
/// retry after a leader failover that observes exactly this move's post-state
/// reports the same success and mutates nothing.
pub(crate) fn apply_move(
    map: &mut BTreeMap<WorkloadKey, WorkloadIntent>,
    key: &WorkloadKey,
    ordinal: u32,
    from_node: &str,
    from_epoch: u64,
    to_node: &str,
) -> WorkloadIntentOutcome {
    let Some(current) = map
        .get_mut(key)
        .and_then(|i| i.placements.get_mut(&ordinal))
    else {
        return WorkloadIntentOutcome::Fenced { current: None };
    };
    if current.epoch == from_epoch.saturating_add(1) && current.node == to_node {
        return WorkloadIntentOutcome::Moved {
            placement: current.clone(),
        };
    }
    if current.node != from_node || current.epoch != from_epoch {
        return WorkloadIntentOutcome::Fenced {
            current: Some(current.clone()),
        };
    }
    *current = ReplicaPlacement {
        node: to_node.to_owned(),
        epoch: from_epoch + 1,
    };
    WorkloadIntentOutcome::Moved {
        placement: current.clone(),
    }
}

// ── Seam 1: the write gate ────────────────────────────────────────────────────

/// May this cluster commit `PutWorkloadIntent` / `DropWorkloadIntent` /
/// `MoveWorkloadReplica` yet?
///
/// Derived, not declared (R625): open iff there is at least one log receiver
/// and EVERY log receiver has advertised a `cluster_protocol >= min_protocol`.
/// `log_receivers` is the full raft membership — voters AND learners
/// (R977-B10): a learner applies the same log, so an old one diverges on these
/// variants exactly as an old voter does. A receiver absent from `advertised`,
/// or mapped to `None` (unreachable, unparsable), closes the gate — an old
/// node that receives one of these variants hits a hard `unknown variant` and
/// cannot advance past it.
///
/// Pure. The I/O is the caller's: receivers come from raft membership, and
/// each one's protocol from its `GET /health` body (`cluster_protocol`), which is
/// the only place a node advertises it today (member rows do not carry it).
/// `min_protocol` is `yubaba::cluster_epoch::WORKLOAD_INTENT_MIN_PROTOCOL`.
pub fn workload_intent_writes_open(
    log_receivers: &BTreeSet<YubabaNodeId>,
    advertised: &BTreeMap<YubabaNodeId, Option<u32>>,
    min_protocol: u32,
) -> bool {
    !log_receivers.is_empty()
        && log_receivers.iter().all(|v| {
            advertised
                .get(v)
                .copied()
                .flatten()
                .is_some_and(|p| p >= min_protocol)
        })
}

// ── Seam 2: the intent-epoch stamp ───────────────────────────────────────────

/// Spec annotation recording which intent ordinal and epoch a deployed copy
/// belongs to. Value is `"<ordinal>:<epoch>"`. Every intent-bearing deploy
/// (R977-F2 deploy, R977-F3 re-placement) writes it; R977-F4 reads it.
pub const WORKLOAD_INTENT_STAMP_ANNOTATION: &str = "yah.workload-intent.stamp";

/// A parsed [`WORKLOAD_INTENT_STAMP_ANNOTATION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentStamp {
    pub ordinal: u32,
    pub epoch: u64,
}

/// Write the stamp into a spec's annotations (`&mut spec.annotations`),
/// replacing any previous one.
pub fn stamp_intent(annotations: &mut HashMap<String, String>, stamp: IntentStamp) {
    annotations.insert(
        WORKLOAD_INTENT_STAMP_ANNOTATION.to_owned(),
        format!("{}:{}", stamp.ordinal, stamp.epoch),
    );
}

/// Read the stamp off a spec's annotations (`&spec.annotations`). `None` when absent or malformed: a copy with no
/// stamp predates intent writes, and callers must treat it as unknown, never
/// as epoch 0.
pub fn read_intent_stamp(annotations: &HashMap<String, String>) -> Option<IntentStamp> {
    let (ordinal, epoch) = annotations
        .get(WORKLOAD_INTENT_STAMP_ANNOTATION)?
        .split_once(':')?;
    Some(IntentStamp {
        ordinal: ordinal.parse().ok()?,
        epoch: epoch.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn voters(ids: &[u64]) -> BTreeSet<u64> {
        ids.iter().copied().collect()
    }

    #[test]
    fn gate_opens_only_when_every_voter_advertises_the_new_protocol() {
        let all_new: BTreeMap<_, _> = [(1, Some(9)), (2, Some(9)), (3, Some(10))].into();
        assert!(workload_intent_writes_open(
            &voters(&[1, 2, 3]),
            &all_new,
            9
        ));

        let one_old: BTreeMap<_, _> = [(1, Some(9)), (2, Some(8)), (3, Some(9))].into();
        assert!(!workload_intent_writes_open(
            &voters(&[1, 2, 3]),
            &one_old,
            9
        ));

        let one_unreachable: BTreeMap<_, _> = [(1, Some(9)), (2, None), (3, Some(9))].into();
        assert!(!workload_intent_writes_open(
            &voters(&[1, 2, 3]),
            &one_unreachable,
            9
        ));

        let one_missing: BTreeMap<_, _> = [(1, Some(9)), (3, Some(9))].into();
        assert!(!workload_intent_writes_open(
            &voters(&[1, 2, 3]),
            &one_missing,
            9
        ));

        assert!(!workload_intent_writes_open(&voters(&[]), &all_new, 9));
    }

    #[test]
    fn an_old_learner_keeps_the_gate_closed() {
        // Voters 1-3 at 9, learner 4 still at 8: closed.
        let old_learner: BTreeMap<_, _> =
            [(1, Some(9)), (2, Some(9)), (3, Some(9)), (4, Some(8))].into();
        assert!(!workload_intent_writes_open(
            &voters(&[1, 2, 3, 4]),
            &old_learner,
            9
        ));
        let unknown_learner: BTreeMap<_, _> =
            [(1, Some(9)), (2, Some(9)), (3, Some(9)), (4, None)].into();
        assert!(!workload_intent_writes_open(
            &voters(&[1, 2, 3, 4]),
            &unknown_learner,
            9
        ));
    }

    #[test]
    fn stamp_round_trips_and_garbage_reads_as_unknown() {
        let mut spec = HashMap::new();
        assert_eq!(read_intent_stamp(&spec), None);
        stamp_intent(
            &mut spec,
            IntentStamp {
                ordinal: 0,
                epoch: 3,
            },
        );
        assert_eq!(
            read_intent_stamp(&spec),
            Some(IntentStamp {
                ordinal: 0,
                epoch: 3
            })
        );
        spec.insert(WORKLOAD_INTENT_STAMP_ANNOTATION.into(), "nope".into());
        assert_eq!(read_intent_stamp(&spec), None);
    }
}
