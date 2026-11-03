//! Leader-resident workload replica reconcile (R977-F3, W364 §2, §3, §6).
//!
//! When a node is lost, the ordinals workload intent places on it move to
//! another node. Same shape as [`crate::scheduler`] (R737-F3): a pure
//! [`decide_replacement`] tested as arithmetic, run inside a paced loop that is
//! [`spawn`]ed on every node and does nothing on a follower.
//!
//! # What it acts on: node liveness, never task state
//!
//! The trigger is a placement node that is `ConfirmedDown` (lease channel,
//! [`TransitionTracker`] + [`HysteresisPolicy`]) for at least
//! [`replacement_grace`], or one that has left membership. A task that crashes
//! on a live node is `restart.rs`'s business, and exit 0 under `on_failure` is
//! fleet-git fencing itself (W364 §6): that copy must stay down, so nothing
//! here reads task state at all.
//!
//! # State
//!
//! Every tick re-reads `workload_intent` and `members` from the applied raft
//! state. Two clocks live only in memory, and a new leader starts both empty,
//! so it re-earns each wait from zero (W364 §3):
//! - the dwell clock (when this leader first saw each node `ConfirmedDown`), and
//! - the absent clock (when this leader first saw a LIVE placement node hold
//!   no copy at the intent's stamp).
//!
//! # A missing copy converges without leader memory (R977-B9)
//!
//! A failover between a committed Move and a successful place, or a failed
//! place, leaves an intent naming a live node that runs nothing. Nothing about
//! that is remembered. Instead every [`PRESENCE_EVERY`] the leader asks each
//! live placement node which intent stamps it holds (`GET
//! /internal/workload-replica/held`, Peer-authed like the place route). "Held"
//! means kamaji has the spec, in any task state: a crashed or exited copy is
//! present and is `restart.rs`'s business, and fleet-git's fenced exit 0 must
//! stay down (W364 §6). Only after a copy has been absent for a whole
//! [`replacement_grace`] does the leader call the place route on the node the
//! intent names, never any other node; the wait keeps it from racing an
//! in-flight deploy, R977-F5's fence return, or R977-F4's cleanup. Each attempt
//! restarts the absent clock, so a failing target is retried once per grace.
//! See [`decide_missing_copy`].
//!
//! # Node names
//!
//! A placement's `node` is the machine name R977-F4's `rejoin_cleanup` compares
//! against [`crate::leader::derive_machine_name`]. Every node writes that same
//! string into its member row as `MemberInfo::machine` (`main.rs`, at the
//! member-registration spawn), so candidates are keyed by `MemberInfo::machine`
//! verbatim and a member without one is never a candidate.
//!
//! # The remote place
//!
//! The leader commits `MoveWorkloadReplica` first, then asks the target to
//! place: `POST /internal/workload-replica/place {key, ordinal, epoch,
//! min_index}`, Peer-authed with the cluster key like every node-to-node call.
//! The target waits until it has applied `min_index` (the Move's log index),
//! re-reads the intent from its own raft state, refuses unless the intent names
//! THIS node at that epoch, and places through [`crate::place_workload_replica`]
//! with the stamp. The caller supplies no spec, so the route grants nothing
//! the committed log does not already say. A target that is the leader itself
//! is called in-process.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use workload_spec::sovereign::Participation;
use workload_spec::WorkloadSpec;
use yubaba_consensus::workload_intent::{read_intent_stamp, IntentStamp, WorkloadIntent};

use crate::lease_detector::{replacement_grace, Confirmed, HysteresisPolicy, TransitionTracker};
use crate::raft::{self, TenantDemand, WorkloadIntentOutcome, WorkloadKey, YubabaNodeId};
use crate::ServerState;

/// Annotation carrying the mesh-tag node selector (`arch:x86`, comma-joined).
/// Same key as `velveteen_exec::remote::NODE_SELECTOR_MESH_TAGS_ANNOTATION`,
/// which this crate does not depend on.
const MESH_TAGS_ANNOTATION: &str = "yah.node-selector.mesh-tags";
/// The imperative one-machine selector (`--where=node:<name>`); see
/// `velveteen_exec::remote::NODE_SELECTOR_NODE_ANNOTATION`.
const NODE_ANNOTATION: &str = "yah.node-selector.node";

/// How long a candidate probe (`GET /node`, `GET /capabilities`) may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long the target waits to apply the Move before refusing.
const APPLY_WAIT: Duration = Duration::from_secs(10);
/// How long the leader gives the target's place call.
const PLACE_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the leader re-asks live placement nodes what they hold. Coarse on
/// purpose: each answer costs the target a kamaji list plus a describe per
/// intent-backed entry, and the grace it gates is 120 s.
pub const PRESENCE_EVERY: Duration = Duration::from_secs(10);

// ── Pure decision ─────────────────────────────────────────────────────────────

/// What the leader knows about the node an ordinal is placed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementNode {
    /// In membership and not `ConfirmedDown`.
    Live,
    /// In membership and `ConfirmedDown`. `down_for` is how long it has been
    /// raw-`Down`: the time since this leader saw the confirm, plus
    /// `confirm_down_after`.
    Down { down_for: Duration },
    /// No member row carries this machine name, and every member row has one.
    Left,
    /// No member row carries this name, but some member has no machine name,
    /// so "left" cannot be told apart from "not yet registered".
    Unmapped,
}

/// The constraints a replacement node must meet, read off the spec.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requirements {
    /// Repo-vocabulary arch (`x86_64` / `aarch64`) from an `arch:` mesh tag.
    pub arch: Option<String>,
    pub native_exec: bool,
    /// `yah.node-selector.node`: only this machine may run it.
    pub pinned_node: Option<String>,
    /// The selector's non-`arch:` mesh tags (`role:`, `tag:`, `cap:`, …). A
    /// candidate's published tags must be a superset, the rule fresh admission
    /// applies (R1019-F28 / W388). Before the member row carried tags these
    /// were unevaluable and pinned the replica in place.
    pub mesh_tags: Vec<String>,
    pub demand: TenantDemand,
    /// Repelling taint keys this spec tolerates —
    /// `workload_spec::archetype_tolerations` of its archetype, the same
    /// derivation fresh admission uses (R977-B12).
    pub tolerates: Vec<String>,
    /// `yah.placement.requires-taint`: only a node carrying this taint.
    pub requires_taint: Option<String>,
}

/// kamaji's `NodeCapabilities` as the probe saw it (R858-T4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// No answer, or a pre-R858-T4 kamaji. Passes.
    Unknown,
    /// kamaji reports a native backend.
    Present,
    /// kamaji answered and has no native backend. Refuses a native-exec spec.
    Absent,
}

/// Resource fit, from the candidate's published `NodeCapacity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    /// Published capacity has room, or the spec requests nothing.
    Admits,
    /// The member published no capacity. Passes, like an `Unknown`
    /// capability, but ranks after every node whose load is known.
    Unknown,
    /// Published capacity is too small. Refuses.
    Refuses,
}

/// One candidate node, precomputed so the decision does no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateView {
    pub liveness: Option<Confirmed>,
    /// `yah.arch` from its `GET /node`; `None` if the probe failed.
    pub arch: Option<String>,
    pub capability: Capability,
    /// `cluster_protocol` from its `GET /health`; `None` if the probe failed
    /// or the body carries none. Below `WORKLOAD_INTENT_MIN_PROTOCOL`, or
    /// unknown, refuses (R977-B10): an older node has no
    /// `/internal/workload-replica/place`.
    pub cluster_protocol: Option<u32>,
    pub fit: Fit,
    /// The member row's published taints (R977-B12). `None` is unknown and
    /// refuses: a node that never said it is untainted may be a workstation.
    pub taints: Option<Vec<String>>,
    /// The member row's published participation. `None` or `Out` refuses.
    pub participation: Option<Participation>,
    /// The member row's published mesh tags (R1019-F28). `None` is unknown
    /// and refuses a spec that names any non-`arch:` tag; a spec naming none
    /// never reads it.
    pub mesh_tags: Option<Vec<String>>,
    /// The raft-heartbeat veto: `false` only on an explicit `Down`.
    pub raft_peer_healthy: bool,
    /// Ordinals workload intent already places here, all workloads.
    pub load: u32,
}

/// One ordinal's committed placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaSnapshot {
    pub node: String,
    pub epoch: u64,
    pub movable: bool,
}

/// What [`decide_replacement`] concluded for one ordinal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplacementDecision {
    /// The node is live. Steady state.
    Ok,
    /// The node is down but inside grace.
    WaitingGrace { remaining: Duration },
    /// The node is lost and the intent is not movable (W364 §5).
    Stranded,
    /// Cannot judge the node; nothing moves.
    Hold { reason: String },
    /// The node is lost and no candidate passed.
    NoCandidate { reason: String },
    /// Commit `MoveWorkloadReplica` from `(replica.node, replica.epoch)` to this
    /// machine name.
    MoveTo(String),
}

impl ReplacementDecision {
    /// The wire token `GET /workload-intents` shows.
    pub fn verdict(&self) -> String {
        match self {
            Self::Ok => "ok".into(),
            Self::WaitingGrace { remaining } => {
                format!("waiting-grace: {}s left", remaining.as_secs())
            }
            Self::Stranded => "stranded (non-movable)".into(),
            Self::Hold { reason } => format!("hold: {reason}"),
            Self::NoCandidate { reason } => format!("no-candidate: {reason}"),
            Self::MoveTo(to) => format!("moving: {to}"),
        }
    }
}

/// Map an `arch:` mesh tag to the repo vocabulary `GET /node` reports as
/// `yah.arch`. `None` for a tag that is not an arch tag.
fn arch_of_tag(tag: &str) -> Option<&'static str> {
    match tag {
        "arch:x86" | "arch:x86_64" | "arch:amd64" => Some("x86_64"),
        "arch:arm" | "arch:arm64" | "arch:aarch64" => Some("aarch64"),
        _ => None,
    }
}

/// Parse `--taints` / `YUBABA_TAINTS`: comma-separated keys, blanks dropped,
/// so an empty value declares "no taints" (R977-B12).
pub fn parse_taints(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// Read a spec's placement constraints.
pub fn requirements_of(spec: &WorkloadSpec) -> Requirements {
    let mut req = Requirements {
        native_exec: spec.wants_native_exec(),
        pinned_node: spec
            .annotations
            .get(NODE_ANNOTATION)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
        demand: TenantDemand {
            memory_mb: spec.memory_request_mb(),
            cpu_millis: spec.resources.cpu_millis,
        },
        tolerates: workload_spec::archetype_tolerations(&[spec.effective_archetype()]),
        requires_taint: spec.requires_taint().map(str::to_string),
        ..Requirements::default()
    };
    if let Some(tags) = spec.annotations.get(MESH_TAGS_ANNOTATION) {
        for tag in tags.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            match arch_of_tag(tag) {
                Some(a) => req.arch = Some(a.to_string()),
                None => req.mesh_tags.push(tag.to_string()),
            }
        }
    }
    req
}

/// The taint half of [`refusal`]: a repelling taint the spec does not
/// tolerate, or a required taint the node lacks. Shared with floater admission
/// (R1013-B1), which must not hand a deploy to an owner this would refuse.
pub fn taint_refusal(req: &Requirements, taints: &[String]) -> Option<String> {
    if let Some(t) = workload_spec::repelling_taint(taints, &req.tolerates) {
        return Some(format!("taint({t})"));
    }
    if let Some(want) = &req.requires_taint {
        if !taints.contains(want) {
            return Some(format!("requires-taint({want})"));
        }
    }
    None
}

/// The first filter a candidate fails, in W364 §2's order, or `None`.
fn refusal(req: &Requirements, name: &str, c: &CandidateView) -> Option<String> {
    if c.liveness != Some(Confirmed::Up) {
        return Some("not-live".into());
    }
    match c.cluster_protocol {
        Some(p) if p >= crate::cluster_epoch::WORKLOAD_INTENT_MIN_PROTOCOL => {}
        Some(p) => return Some(format!("protocol({p})")),
        None => return Some("protocol(unknown)".into()),
    }
    match c.participation {
        Some(p) if p.is_in() => {}
        Some(p) => return Some(format!("participation({p})")),
        None => return Some("participation(unknown)".into()),
    }
    let Some(taints) = &c.taints else {
        return Some("taints(unknown)".into());
    };
    if let Some(why) = taint_refusal(req, taints) {
        return Some(why);
    }
    if !req.mesh_tags.is_empty() {
        let Some(have) = &c.mesh_tags else {
            return Some("mesh-tags(unknown)".into());
        };
        if let Some(missing) = req.mesh_tags.iter().find(|t| !have.contains(t)) {
            return Some(format!("mesh-tag({missing})"));
        }
    }
    if let Some(want) = &req.arch {
        if c.arch.as_deref() != Some(want.as_str()) {
            return Some(format!("arch({})", c.arch.as_deref().unwrap_or("unknown")));
        }
    }
    if req.native_exec && c.capability == Capability::Absent {
        return Some("no-native-exec".into());
    }
    if let Some(pin) = &req.pinned_node {
        if pin != name {
            return Some(format!("node-selector({pin})"));
        }
    }
    if c.fit == Fit::Refuses {
        return Some("no-fit".into());
    }
    if !c.raft_peer_healthy {
        return Some("raft-peer-down".into());
    }
    None
}

/// Decide whether, and where, to re-place one ordinal. No raft, no network.
///
/// Passing candidates rank known capacity before [`Fit::Unknown`], then least
/// load, then machine name, so a re-evaluation (next tick, or a new leader)
/// reaches the same target.
pub fn decide_replacement(
    replica: &ReplicaSnapshot,
    node: PlacementNode,
    grace: Duration,
    req: &Requirements,
    candidates: &BTreeMap<String, CandidateView>,
) -> ReplacementDecision {
    match node {
        PlacementNode::Live => return ReplacementDecision::Ok,
        PlacementNode::Unmapped => {
            return ReplacementDecision::Hold {
                reason: format!(
                    "{} is in no member row and some member has no machine name",
                    replica.node
                ),
            }
        }
        PlacementNode::Down { down_for } if down_for < grace => {
            return ReplacementDecision::WaitingGrace {
                remaining: grace - down_for,
            }
        }
        PlacementNode::Down { .. } | PlacementNode::Left => {}
    }
    if !replica.movable {
        return ReplacementDecision::Stranded;
    }
    pick_candidate(replica, req, candidates)
}

/// The candidate pick itself: `MoveTo` or `NoCandidate`, never anything else.
/// Shared by [`decide_replacement`] (a lost node) and [`fallback_for`] (a live
/// one) so the observed fallback is the decision, not a second copy of it.
fn pick_candidate(
    replica: &ReplicaSnapshot,
    req: &Requirements,
    candidates: &BTreeMap<String, CandidateView>,
) -> ReplacementDecision {
    let mut refusals = Vec::new();
    let mut best: Option<(bool, u32, &String)> = None;
    for (name, c) in candidates {
        if *name == replica.node {
            continue;
        }
        match refusal(req, name, c) {
            Some(why) => refusals.push(format!("{name}={why}")),
            None => {
                let rank = (c.fit == Fit::Unknown, c.load, name);
                if best.is_none_or(|b| rank < b) {
                    best = Some(rank);
                }
            }
        }
    }
    match best {
        Some((_, _, name)) => ReplacementDecision::MoveTo(name.clone()),
        None if refusals.is_empty() => ReplacementDecision::NoCandidate {
            reason: "no other member".into(),
        },
        None => ReplacementDecision::NoCandidate {
            reason: refusals.join(" "),
        },
    }
}

/// R977-B13: where this ordinal WOULD move if its node were lost right now —
/// a machine name, or `none (<why>)` carrying the per-node refusals. Shown on
/// `GET /workload-intents` for live ordinals so a drill can check the target
/// before stopping anything. The same pick as [`decide_replacement`].
pub fn fallback_for(
    replica: &ReplicaSnapshot,
    req: &Requirements,
    candidates: &BTreeMap<String, CandidateView>,
) -> String {
    if !replica.movable {
        return "none (non-movable)".into();
    }
    match pick_candidate(replica, req, candidates) {
        ReplacementDecision::MoveTo(to) => to,
        ReplacementDecision::NoCandidate { reason } => format!("none ({reason})"),
        other => format!("none ({})", other.verdict()),
    }
}

/// Whether a live placement node holds the copy at the intent's stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyPresence {
    /// kamaji has the spec at this stamp, in any task state.
    Present,
    Absent,
    /// The node did not answer the held probe. Nothing acts on this.
    Unknown,
}

/// Whether `held` (one node's held-probe answer) carries `key` at `stamp`.
pub fn presence_in(held: Option<&[HeldCopy]>, key: &str, stamp: IntentStamp) -> CopyPresence {
    match held {
        None => CopyPresence::Unknown,
        Some(h)
            if h.iter()
                .any(|c| c.key == key && c.ordinal == stamp.ordinal && c.epoch == stamp.epoch) =>
        {
            CopyPresence::Present
        }
        Some(_) => CopyPresence::Absent,
    }
}

/// The absent clock: when this leader first saw each ordinal's copy missing
/// from the node its intent names, at that (node, epoch). In memory only; a
/// new leader starts it empty and so re-earns the wait.
#[derive(Debug, Default)]
pub struct AbsentClock {
    since: BTreeMap<(String, u32), (String, u64, Instant)>,
}

impl AbsentClock {
    /// Feed one observation and return how long the copy has been absent
    /// (`None` unless `presence` is `Absent`). A different node or epoch
    /// restarts the clock; `Present` clears it; `Unknown` leaves it alone but
    /// reports nothing, so a silent node never earns a re-place.
    pub fn observe(
        &mut self,
        key: &str,
        replica: &ReplicaSnapshot,
        ordinal: u32,
        presence: CopyPresence,
        now: Instant,
    ) -> Option<Duration> {
        let slot = (key.to_string(), ordinal);
        match presence {
            CopyPresence::Present => {
                self.since.remove(&slot);
                None
            }
            CopyPresence::Unknown => None,
            CopyPresence::Absent => {
                let e = self
                    .since
                    .entry(slot)
                    .or_insert_with(|| (replica.node.clone(), replica.epoch, now));
                if e.0 != replica.node || e.1 != replica.epoch {
                    *e = (replica.node.clone(), replica.epoch, now);
                }
                Some(now.saturating_duration_since(e.2))
            }
        }
    }

    /// Restart the wait after a place attempt.
    pub fn reset(&mut self, key: &str, ordinal: u32) {
        self.since.remove(&(key.to_string(), ordinal));
    }

    pub fn clear(&mut self) {
        self.since.clear();
    }

    /// Drop slots whose intent ordinal no longer exists.
    pub fn retain(&mut self, mut keep: impl FnMut(&str, u32) -> bool) {
        self.since.retain(|(k, o), _| keep(k, *o));
    }
}

/// What the leader does about one ordinal on a live node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyDecision {
    /// Present, or presence unknown: nothing to do.
    Ok,
    /// Absent, inside the grace.
    AbsentWaiting { remaining: Duration },
    /// Absent for the whole grace: place on exactly this (node, epoch) — the
    /// one the intent names.
    Replace { node: String, epoch: u64 },
}

impl CopyDecision {
    pub fn verdict(&self) -> String {
        match self {
            Self::Ok => "ok".into(),
            Self::AbsentWaiting { remaining } => {
                format!("absent: waiting ({}s left)", remaining.as_secs())
            }
            Self::Replace { node, epoch } => {
                format!("absent: re-placing on {node} (epoch {epoch})")
            }
        }
    }
}

/// Decide about a live placement node's copy. Pure; `absent_for` comes from
/// [`AbsentClock::observe`].
pub fn decide_missing_copy(
    replica: &ReplicaSnapshot,
    absent_for: Option<Duration>,
    grace: Duration,
) -> CopyDecision {
    match absent_for {
        None => CopyDecision::Ok,
        Some(d) if d < grace => CopyDecision::AbsentWaiting {
            remaining: grace - d,
        },
        Some(_) => CopyDecision::Replace {
            node: replica.node.clone(),
            epoch: replica.epoch,
        },
    }
}

/// What a committed `MoveWorkloadReplica` answered: the stamp to place with,
/// or `None` when the CAS lost (another leader moved it, or the epoch went
/// stale) and nothing should be deployed.
pub fn moved_stamp(ordinal: u32, outcome: &WorkloadIntentOutcome) -> Option<(String, IntentStamp)> {
    match outcome {
        WorkloadIntentOutcome::Moved { placement } => Some((
            placement.node.clone(),
            IntentStamp {
                ordinal,
                epoch: placement.epoch,
            },
        )),
        _ => None,
    }
}

/// The target side's check: the stamp to place with, iff the intent places
/// `ordinal` on `me` at exactly `epoch`.
pub fn stamp_for_this_node(
    intent: Option<&WorkloadIntent>,
    ordinal: u32,
    epoch: u64,
    me: &str,
) -> Result<IntentStamp, String> {
    let Some(intent) = intent else {
        return Err("no workload intent under this key".into());
    };
    let Some(p) = intent.placements.get(&ordinal) else {
        return Err(format!("intent has no ordinal {ordinal}"));
    };
    if p.node != me {
        return Err(format!(
            "intent places ordinal {ordinal} on {}, not {me}",
            p.node
        ));
    }
    if p.epoch != epoch {
        return Err(format!(
            "intent is at epoch {}, the request named {epoch}",
            p.epoch
        ));
    }
    Ok(IntentStamp { ordinal, epoch })
}

// ── Verdicts (read surface) ───────────────────────────────────────────────────

type VerdictMap = BTreeMap<(String, u32), String>;

static VERDICTS: OnceLock<Mutex<VerdictMap>> = OnceLock::new();

fn verdicts() -> &'static Mutex<VerdictMap> {
    VERDICTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

static FALLBACKS: OnceLock<Mutex<VerdictMap>> = OnceLock::new();

fn fallbacks() -> &'static Mutex<VerdictMap> {
    FALLBACKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn record_fallback(key: &WorkloadKey, ordinal: u32, fallback: String) {
    fallbacks()
        .lock()
        .unwrap()
        .insert((key.0.clone(), ordinal), fallback);
}

fn record(key: &WorkloadKey, ordinal: u32, verdict: String) {
    verdicts()
        .lock()
        .unwrap()
        .insert((key.0.clone(), ordinal), verdict);
}

#[derive(Serialize)]
struct OrdinalView {
    ordinal: u32,
    node: String,
    epoch: u64,
    /// This node's reconcile verdict, `null` if it has not judged it (it is
    /// not the leader, or has not ticked since becoming one).
    verdict: Option<String>,
    /// R977-B13: for a live ordinal, the machine it would move to if its node
    /// were lost now, or `none (<refusals>)` — [`fallback_for`]. `null` when
    /// this node has not judged it, or the ordinal's node is not live.
    fallback: Option<String>,
}

#[derive(Serialize)]
struct IntentView {
    key: String,
    replicas: u32,
    movable: bool,
    placements: Vec<OrdinalView>,
}

/// `GET /workload-intents` — every workload intent in this node's applied raft
/// state, with the reconcile loop's last verdict per ordinal. Verdicts are only
/// ever written on the leader, so ask the leader (`leader` says who that is).
pub(crate) async fn list_workload_intents(State(s): State<Arc<ServerState>>) -> Response {
    let Some(sm) = s.cluster_state.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no raft on this node").into_response();
    };
    let intents = sm.with_state(|st| st.workload_intent.clone());
    let leader = s.raft.as_ref().and_then(|r| {
        use openraft::async_runtime::watch::WatchReceiver;
        r.metrics().borrow_watched().current_leader
    });
    let verdicts = verdicts().lock().unwrap().clone();
    let fallbacks = fallbacks().lock().unwrap().clone();
    let list: Vec<IntentView> = intents
        .into_iter()
        .map(|(key, intent)| IntentView {
            placements: intent
                .placements
                .iter()
                .map(|(ordinal, p)| OrdinalView {
                    ordinal: *ordinal,
                    node: p.node.clone(),
                    epoch: p.epoch,
                    verdict: verdicts.get(&(key.0.clone(), *ordinal)).cloned(),
                    fallback: fallbacks.get(&(key.0.clone(), *ordinal)).cloned(),
                })
                .collect(),
            key: key.0,
            replicas: intent.replicas,
            movable: intent.movable,
        })
        .collect();
    Json(serde_json::json!({
        "node_id": s.node_id,
        "leader": leader,
        "applied_index": sm.applied_index(),
        "intents": list,
    }))
    .into_response()
}

// ── R997-B11: attaching the operator's signature to a recorded intent ─────────

/// One intent whose spec no configured operator key has signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnattestedIntent {
    pub key: String,
    /// Verbatim; the operator signs the JSON this parses to.
    pub spec_json: String,
}

/// `GET /workload-intents/unattested` (Operator) — the intents this node would
/// refuse to place for want of an operator signature. Operator class because
/// it returns specs.
pub(crate) async fn list_unattested_intents(State(s): State<Arc<ServerState>>) -> Response {
    let Some(sm) = s.cluster_state.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no raft on this node").into_response();
    };
    let intents = sm.with_state(|st| st.workload_intent.clone());
    let list: Vec<UnattestedIntent> = intents
        .into_iter()
        .filter(|(key, intent)| deploy_body_from_intent(&s, key, intent).is_err())
        .map(|(key, intent)| UnattestedIntent {
            key: key.0,
            spec_json: intent.spec_json,
        })
        .collect();
    Json(serde_json::json!({ "intents": list })).into_response()
}

/// `POST /workload-intents/attest` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestRequest {
    pub key: String,
    pub spec_json: String,
    pub operator_sig: String,
}

/// `POST /workload-intents/attest` (Operator) — record the operator's
/// signature on an intent written before signatures existed. Verified here
/// against this node's operator keys, then CAS'd on the exact `spec_json`.
pub(crate) async fn attest_intent_handler(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<AttestRequest>,
) -> Response {
    let Some(raft) = s.raft.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no raft on this node").into_response();
    };
    let key = WorkloadKey(req.key.clone());
    let probe = WorkloadIntent {
        spec_json: req.spec_json.clone(),
        replicas: 0,
        placements: BTreeMap::new(),
        movable: false,
        requesting_camp_id: None,
        on_behalf_of_user: None,
        operator_sig: Some(req.operator_sig.clone()),
    };
    if let Err(why) = deploy_body_from_intent(&s, &key, &probe) {
        return (StatusCode::FORBIDDEN, why).into_response();
    }
    if !crate::workload_intent_deploy::attest_writes_open_live(&s).await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "a raft member does not yet understand intent attestation; roll every node first",
        )
            .into_response();
    }
    let write = raft::YubabaRequest::AttestWorkloadIntent {
        key,
        spec_json: req.spec_json,
        operator_sig: req.operator_sig,
    };
    match raft::client_write_forwarded(&raft, &s.http, write).await {
        Ok(raft::YubabaResponse::WorkloadIntent(WorkloadIntentOutcome::Recorded { .. })) => {
            Json(serde_json::json!({ "status": "attested", "key": req.key })).into_response()
        }
        Ok(raft::YubabaResponse::WorkloadIntent(WorkloadIntentOutcome::NotAttested)) => (
            StatusCode::CONFLICT,
            "no intent under that key carries exactly that spec (redeployed or dropped since it was read)",
        )
            .into_response(),
        Ok(other) => (StatusCode::BAD_GATEWAY, format!("unexpected answer: {other:?}")).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, format!("raft write failed: {e}")).into_response(),
    }
}

// ── Target side: the remote place ─────────────────────────────────────────────

/// `POST /internal/workload-replica/place` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PlaceRequest {
    pub key: String,
    pub ordinal: u32,
    pub epoch: u64,
    /// The Move's log index; the target applies at least this far first.
    pub min_index: u64,
}

/// `POST /internal/workload-replica/place` (Peer). See the module doc.
pub(crate) async fn place_replica_handler(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<PlaceRequest>,
) -> Response {
    place_from_intent(s, req, crate::workload_intent_deploy::this_machine()).await
}

/// Wait for `min_index`, check the intent names this node at `epoch`, place.
/// `me` is [`crate::workload_intent_deploy::this_machine`] in production;
/// tests inject it.
pub(crate) async fn place_from_intent(
    s: Arc<ServerState>,
    req: PlaceRequest,
    me: Option<String>,
) -> Response {
    let Some(sm) = s.cluster_state.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no raft on this node").into_response();
    };
    let deadline = Instant::now() + APPLY_WAIT;
    while sm.applied_index().unwrap_or(0) < req.min_index {
        if Instant::now() >= deadline {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "this node has applied {:?}, not yet {}; retry",
                    sm.applied_index(),
                    req.min_index
                ),
            )
                .into_response();
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let Some(me) = me else {
        return (
            StatusCode::CONFLICT,
            "this node cannot derive its machine name",
        )
            .into_response();
    };
    let key = WorkloadKey(req.key.clone());
    let intent = sm.with_state(|st| st.workload_intent.get(&key).cloned());
    let stamp = match stamp_for_this_node(intent.as_ref(), req.ordinal, req.epoch, &me) {
        Ok(stamp) => stamp,
        Err(why) => return (StatusCode::CONFLICT, why).into_response(),
    };
    let Some(intent) = intent else {
        return (StatusCode::CONFLICT, "intent vanished").into_response();
    };
    let body = match deploy_body_from_intent(&s, &key, &intent) {
        Ok(b) => b,
        Err(e) => {
            warn!(ident = %req.key, "workload reconcile: refusing to place: {e}");
            return (StatusCode::FORBIDDEN, e).into_response();
        }
    };
    info!(
        ident = %req.key,
        ordinal = req.ordinal,
        epoch = req.epoch,
        "workload reconcile: placing a re-placed replica on this node"
    );
    crate::place_workload_replica(s, body, crate::DeployOrigin::Api, Some(stamp)).await
}

/// One intent-stamped copy kamaji holds on a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldCopy {
    pub key: String,
    pub ordinal: u32,
    pub epoch: u64,
}

/// `GET /internal/workload-replica/held` answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HeldResponse {
    pub held: Vec<HeldCopy>,
}

/// `GET /internal/workload-replica/held` (Peer). Read-only: every copy kamaji
/// holds here, in any task state, whose key has a workload intent and whose
/// spec carries an intent stamp. 503 when kamaji cannot be asked, which the
/// leader reads as [`CopyPresence::Unknown`].
pub(crate) async fn held_replicas_handler(State(s): State<Arc<ServerState>>) -> Response {
    match held_local(&s).await {
        Ok(held) => Json(HeldResponse { held }).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
    }
}

/// Does a kamaji row in this state hold the replica? A terminal copy does not
/// (R977-T8 run 3): a fleet-git that lost its writer claim exits 0, is not
/// restarted under `on_failure`, and sat `Exited` as a "held" copy, so the
/// absent clock never fired and nothing served until someone redeployed.
/// Counted absent, it is re-placed after the grace like any missing copy.
pub(crate) fn holds_a_copy(state: &kamaji_proto::WorkloadState) -> bool {
    use kamaji_proto::WorkloadState as S;
    // A state this build does not know (the enum is non_exhaustive) stays
    // held: re-placing on a state we cannot read is the riskier mistake.
    !matches!(state, S::Exited | S::Failed | S::OomKilled | S::DeadlineExceeded)
}

async fn held_local(s: &ServerState) -> Result<Vec<HeldCopy>, String> {
    let Some(sm) = s.cluster_state.as_ref() else {
        return Err("no raft on this node".into());
    };
    let Some(client) = s.constable_client.as_ref().and_then(|k| k.current()) else {
        return Err("no kamaji sibling".into());
    };
    let entries = client
        .list()
        .await
        .map_err(|e| format!("kamaji list: {e}"))?;
    let intents = sm.with_state(|st| st.workload_intent.clone());
    let mut held = Vec::new();
    for entry in entries {
        let key = crate::workload_fence::local_key(&entry);
        if !intents.contains_key(&WorkloadKey(key.clone())) || !holds_a_copy(&entry.state) {
            continue;
        }
        let spec = client
            .describe(&entry.id)
            .await
            .map_err(|e| format!("kamaji describe {}: {e}", entry.id.0))?;
        if let Some(stamp) = spec
            .as_ref()
            .and_then(|w| w.container_spec())
            .and_then(|c| read_intent_stamp(&c.annotations))
        {
            held.push(HeldCopy {
                key,
                ordinal: stamp.ordinal,
                epoch: stamp.epoch,
            });
        }
    }
    Ok(held)
}

/// The deploy body a re-placed copy is placed with: the intent's spec and the
/// original deploy's camp attribution, so a moved copy keeps its cheers
/// ownership principal.
///
/// R997-B11: the ONLY way an intent becomes a deploy body, and it refuses any
/// intent whose spec an operator key did not sign, or whose spec declares an
/// ident other than the key it is stored under. Raft state is writable by the
/// peer tier; the operator's signature is what authorizes the deploy.
pub(crate) fn deploy_body_from_intent(
    s: &ServerState,
    key: &WorkloadKey,
    intent: &WorkloadIntent,
) -> Result<crate::WorkloadDeployBody, String> {
    let spec: serde_json::Value = serde_json::from_str(&intent.spec_json)
        .map_err(|e| format!("intent spec is not JSON: {e}"))?;
    let declared = crate::workload_intent_deploy::container_spec_of(&spec)
        .map(|parsed| parsed.expose.mesh.identity.0);
    if declared.as_deref() != Some(key.0.as_str()) {
        return Err(format!(
            "intent {} carries a spec declaring ident {declared:?}; refusing to place it",
            key.0
        ));
    }
    crate::operator_attested(s, &spec, intent.operator_sig.as_deref())
        .map_err(|why| format!("intent {}: {why}; re-sign it with `yah cloud workload resign`", key.0))?;
    serde_json::from_value(serde_json::json!({
        "spec": spec,
        "requesting_camp_id": intent.requesting_camp_id,
        "on_behalf_of_user": intent.on_behalf_of_user,
        "operator_sig": intent.operator_sig,
    }))
    .map_err(|e| format!("deploy body: {e}"))
}

// ── Loop ──────────────────────────────────────────────────────────────────────

/// How the loop is paced. Grace comes from [`replacement_grace`], not from here.
#[derive(Debug, Clone, Copy)]
pub struct ReconcileConfig {
    pub evaluate_every: Duration,
    pub hysteresis: HysteresisPolicy,
}

impl ReconcileConfig {
    pub fn new(timing: crate::cluster_policy::RaftTiming, hysteresis: HysteresisPolicy) -> Self {
        Self {
            evaluate_every: Duration::from_millis(timing.heartbeat_interval_ms.max(1)) * 2,
            hysteresis,
        }
    }
}

/// Spawn the reconcile loop. Safe on every node: a follower's tick only feeds
/// its tracker.
pub fn spawn(s: Arc<ServerState>, config: ReconcileConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { run(s, config).await })
}

async fn run(s: Arc<ServerState>, config: ReconcileConfig) {
    use crate::failure_detector::{FailureDetector, LivenessReport};
    use openraft::async_runtime::watch::WatchReceiver;

    let (Some(raft), Some(sm), Some(node_id)) =
        (s.raft.clone(), s.cluster_state.clone(), s.node_id)
    else {
        return;
    };
    let grace = replacement_grace(config.hysteresis);
    info!(node_id, ?grace, "workload replica reconcile active");
    let watch = raft.metrics();
    let mut tracker = TransitionTracker::new();
    let mut confirmed_down_at: BTreeMap<YubabaNodeId, Instant> = BTreeMap::new();
    let mut absent = AbsentClock::default();
    let mut held_cache: BTreeMap<String, Option<Vec<HeldCopy>>> = BTreeMap::new();
    let mut held_at: Option<Instant> = None;
    let mut was_leader = false;
    let mut latch_at: Option<Instant> = None;
    const LATCH_REFRESH: Duration = Duration::from_secs(30);

    loop {
        tokio::time::sleep(config.evaluate_every).await;
        let now = Instant::now();
        let report: LivenessReport = match &s.lease_detector {
            Some(d) => d.observe().await,
            None => LivenessReport::new(),
        };
        tracker.observe(&report, config.hysteresis, now);

        // R977-T8: keep the protocol latch warm on EVERY node, leader
        // included, while every member is still alive. The gate only reads the
        // latch once a member has gone silent, and by then it is too late to
        // learn its protocol. Run 2 proved the leader needs this too: it
        // restarted in a roll, kept leadership, and never probed until a move
        // was due, so the dead voter read as unknown and the gate held.
        if latch_at.is_none_or(|t| now.duration_since(t) >= LATCH_REFRESH) {
            crate::workload_intent_deploy::advertised_protocols(&s).await;
            latch_at = Some(now);
        }

        let is_leader = watch.borrow_watched().current_leader == Some(node_id);
        if !is_leader {
            if was_leader {
                // A new leader re-earns the dwell and the absent wait.
                confirmed_down_at.clear();
                absent.clear();
                held_cache.clear();
                held_at = None;
                verdicts().lock().unwrap().clear();
                fallbacks().lock().unwrap().clear();
            }
            was_leader = false;
            continue;
        }
        was_leader = true;

        let members = sm.members();
        for id in members.keys() {
            if tracker.committed(*id) == Some(Confirmed::Down) {
                confirmed_down_at.entry(*id).or_insert(now);
            } else {
                confirmed_down_at.remove(id);
            }
        }
        confirmed_down_at.retain(|id, _| members.contains_key(id));

        let intents = sm.with_state(|st| st.workload_intent.clone());
        if intents.is_empty() {
            verdicts().lock().unwrap().clear();
            continue;
        }

        let machine_ids: BTreeMap<&str, YubabaNodeId> = members
            .iter()
            .filter_map(|(id, m)| m.machine.as_deref().map(|name| (name, *id)))
            .collect();
        let all_named = machine_ids.len() == members.len();
        let mut load: BTreeMap<&str, u32> = BTreeMap::new();
        for intent in intents.values() {
            for p in intent.placements.values() {
                *load.entry(p.node.as_str()).or_default() += 1;
            }
        }

        // Probed lazily, once per tick, only if some ordinal needs a move.
        let mut probed: Option<BTreeMap<String, (Option<String>, Capability, Option<u32>)>> = None;
        let raft_report: LivenessReport = match &s.failure_detector {
            Some(d) => d.observe().await,
            None => LivenessReport::new(),
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        for (key, intent) in &intents {
            let spec = crate::workload_intent_deploy::container_spec_of(
                &serde_json::from_str(&intent.spec_json).unwrap_or_default(),
            );
            for (ordinal, placement) in &intent.placements {
                let node_state = match machine_ids.get(placement.node.as_str()) {
                    Some(id) => match confirmed_down_at.get(id) {
                        Some(at) => PlacementNode::Down {
                            down_for: now.saturating_duration_since(*at)
                                + config.hysteresis.confirm_down_after,
                        },
                        None => PlacementNode::Live,
                    },
                    None if all_named => PlacementNode::Left,
                    None => PlacementNode::Unmapped,
                };
                let replica = ReplicaSnapshot {
                    node: placement.node.clone(),
                    epoch: placement.epoch,
                    movable: intent.movable,
                };
                let live = matches!(node_state, PlacementNode::Live);
                // R977-B13: a live movable ordinal also gets candidates, so its
                // fallback can be shown. Only a lost node's decision uses them.
                let needs_candidates = intent.movable
                    && matches!(node_state, PlacementNode::Left | PlacementNode::Live)
                    || matches!(node_state, PlacementNode::Down { down_for } if down_for >= grace);
                if !live || !intent.movable {
                    fallbacks().lock().unwrap().remove(&(key.0.clone(), *ordinal));
                }
                if needs_candidates && spec.is_none() {
                    if live {
                        record_fallback(key, *ordinal, "none (intent spec does not parse)".into());
                    } else {
                        record(key, *ordinal, "hold: intent spec does not parse".into());
                        continue;
                    }
                }
                let (req, candidates) = if let Some(spec) = spec.as_ref().filter(|_| needs_candidates) {
                    let req = requirements_of(spec);
                    if probed.is_none() {
                        probed = Some(probe_candidates(&s, &members).await);
                    }
                    let probes = probed.as_ref().unwrap();
                    let candidates = members
                        .iter()
                        .filter_map(|(id, m)| {
                            let name = m.machine.clone()?;
                            let (arch, capability, cluster_protocol) = probes
                                .get(&name)
                                .cloned()
                                .unwrap_or((None, Capability::Unknown, None));
                            let fit = if req.demand.memory_mb == 0 && req.demand.cpu_millis == 0 {
                                Fit::Admits
                            } else if m.capacity.is_none() {
                                Fit::Unknown
                            } else if sm.node_admits(*id, &req.demand, now_unix) {
                                Fit::Admits
                            } else {
                                Fit::Refuses
                            };
                            let view = CandidateView {
                                liveness: tracker.committed(*id),
                                arch,
                                capability,
                                cluster_protocol,
                                fit,
                                taints: m.taints.clone(),
                                participation: m.sovereign_participation,
                                mesh_tags: m.mesh_tags.clone(),
                                raft_peer_healthy: !matches!(
                                    raft_report.get(id).map(|o| o.liveness),
                                    Some(crate::failure_detector::NodeLiveness::Down)
                                ),
                                load: load.get(name.as_str()).copied().unwrap_or(0),
                            };
                            Some((name, view))
                        })
                        .collect();
                    (req, candidates)
                } else {
                    (Requirements::default(), BTreeMap::new())
                };

                if live && intent.movable && spec.is_some() {
                    record_fallback(key, *ordinal, fallback_for(&replica, &req, &candidates));
                }
                let decision = decide_replacement(&replica, node_state, grace, &req, &candidates);
                let to = match &decision {
                    ReplacementDecision::MoveTo(to) => to.clone(),
                    ReplacementDecision::NoCandidate { reason } => {
                        warn!(ident = %key.0, ordinal, node = %placement.node, %reason,
                            "workload reconcile: node lost, no candidate passed");
                        record(key, *ordinal, decision.verdict());
                        continue;
                    }
                    ReplacementDecision::Stranded => {
                        warn!(ident = %key.0, ordinal, node = %placement.node,
                            "workload reconcile: non-movable workload stranded on a lost node");
                        record(key, *ordinal, decision.verdict());
                        continue;
                    }
                    ReplacementDecision::Ok => {
                        // Live node: does it hold the copy at the intent's stamp?
                        if held_at
                            .is_none_or(|t| now.saturating_duration_since(t) >= PRESENCE_EVERY)
                        {
                            held_cache = probe_held(&s, &members, &intents, &machine_ids).await;
                            held_at = Some(now);
                        }
                        let stamp = IntentStamp {
                            ordinal: *ordinal,
                            epoch: placement.epoch,
                        };
                        let presence = presence_in(
                            held_cache.get(&placement.node).and_then(|h| h.as_deref()),
                            &key.0,
                            stamp,
                        );
                        let absent_for = absent.observe(&key.0, &replica, *ordinal, presence, now);
                        let copy = decide_missing_copy(&replica, absent_for, grace);
                        let CopyDecision::Replace { node, epoch } = &copy else {
                            record(key, *ordinal, copy.verdict());
                            continue;
                        };
                        warn!(ident = %key.0, ordinal, %node, epoch,
                            "workload reconcile: live node has held no copy for the whole grace, re-placing it there");
                        record(key, *ordinal, copy.verdict());
                        absent.reset(&key.0, *ordinal);
                        let min_index = sm.applied_index().unwrap_or(0);
                        if let Err(e) =
                            call_place(&s, &members, key, *ordinal, node, *epoch, min_index).await
                        {
                            warn!(ident = %key.0, ordinal, %node,
                                "workload reconcile: re-place failed, retrying after another grace: {e}");
                            record(
                                key,
                                *ordinal,
                                format!("absent: re-place failed on {node} (epoch {epoch}): {e}"),
                            );
                        } else {
                            record(
                                key,
                                *ordinal,
                                format!("absent: re-placed on {node} (epoch {epoch})"),
                            );
                        }
                        continue;
                    }
                    _ => {
                        record(key, *ordinal, decision.verdict());
                        continue;
                    }
                };

                if !crate::workload_intent_deploy::workload_intent_writes_open_live(&s).await {
                    warn!(ident = %key.0, ordinal, target = %to,
                        "workload reconcile: would move, but the workload-intent write gate is \
                         closed (a voter does not advertise the protocol) — no write");
                    record(
                        key,
                        *ordinal,
                        format!("hold: write gate closed (would move to {to})"),
                    );
                    continue;
                }
                let mv = raft::YubabaRequest::MoveWorkloadReplica {
                    key: key.clone(),
                    ordinal: *ordinal,
                    from_node: placement.node.clone(),
                    from_epoch: placement.epoch,
                    to_node: to.clone(),
                };
                info!(ident = %key.0, ordinal, from = %placement.node, from_epoch = placement.epoch,
                    target = %to, "workload reconcile: moving a replica off a lost node");
                let committed = match raft.client_write(mv).await {
                    Ok(resp) => match &resp.data {
                        raft::YubabaResponse::WorkloadIntent(outcome) => {
                            moved_stamp(*ordinal, outcome)
                                .map(|(node, st)| (node, st.epoch, resp.log_id.index))
                        }
                        other => {
                            warn!(ident = %key.0, ?other, "workload reconcile: unexpected Move answer");
                            None
                        }
                    },
                    Err(e) => {
                        warn!(ident = %key.0, ordinal,
                            "workload reconcile: Move commit failed, re-evaluating next tick: {e}");
                        None
                    }
                };
                let Some((node, epoch, min_index)) = committed else {
                    debug!(ident = %key.0, ordinal, "workload reconcile: Move not applied (CAS lost)");
                    continue;
                };
                match call_place(&s, &members, key, *ordinal, &node, epoch, min_index).await {
                    Ok(()) => record(key, *ordinal, format!("moved: {node} (epoch {epoch})")),
                    Err(e) => {
                        // No retry here: the target is now a live placement
                        // node with no copy, which the absent clock converges.
                        warn!(ident = %key.0, ordinal, target = %node,
                            "workload reconcile: Move committed, deploy failed — the absent check re-places after grace: {e}");
                        record(
                            key,
                            *ordinal,
                            format!("moved: {node} (epoch {epoch}); deploy failed: {e}"),
                        );
                    }
                }
            }
        }
        // Forget verdicts and absent clocks for intents that no longer exist.
        absent.retain(|k, o| {
            intents
                .get(&WorkloadKey(k.to_string()))
                .is_some_and(|i| i.placements.contains_key(&o))
        });
        verdicts().lock().unwrap().retain(|(k, o), _| {
            intents
                .get(&WorkloadKey(k.clone()))
                .is_some_and(|i| i.placements.contains_key(o))
        });
    }
}

/// `GET /node` (`yah.arch`), `GET /capabilities` and `GET /health`
/// (`cluster_protocol`) on every named member.
async fn probe_candidates(
    s: &ServerState,
    members: &BTreeMap<YubabaNodeId, raft::MemberInfo>,
) -> BTreeMap<String, (Option<String>, Capability, Option<u32>)> {
    let mut out = BTreeMap::new();
    for m in members.values() {
        let Some(name) = m.machine.clone() else {
            continue;
        };
        let base = format!("http://{}", m.addr);
        let arch = async {
            let v: serde_json::Value = s
                .http
                .get(format!("{base}/node"))
                .timeout(PROBE_TIMEOUT)
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            v.get("yah.arch")?.as_str().map(str::to_string)
        }
        .await;
        let capability = async {
            let v: serde_json::Value = s
                .http
                .get(format!("{base}/capabilities"))
                .timeout(PROBE_TIMEOUT)
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            let caps = v.get("capabilities")?;
            Some(match caps.get("native_exec").and_then(|n| n.as_bool()) {
                Some(true) => Capability::Present,
                Some(false) => Capability::Absent,
                None => Capability::Unknown,
            })
        }
        .await
        .unwrap_or(Capability::Unknown);
        let cluster_protocol = async {
            let v: serde_json::Value = s
                .http
                .get(format!("{base}/health"))
                .timeout(PROBE_TIMEOUT)
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            v.get("cluster_protocol")?
                .as_u64()
                .and_then(|p| u32::try_from(p).ok())
        }
        .await;
        out.insert(name, (arch, capability, cluster_protocol));
    }
    out
}

/// Ask every live-named placement node what it holds. `None` per node whose
/// probe failed. The leader itself is asked in-process.
async fn probe_held(
    s: &ServerState,
    members: &BTreeMap<YubabaNodeId, raft::MemberInfo>,
    intents: &BTreeMap<WorkloadKey, WorkloadIntent>,
    machine_ids: &BTreeMap<&str, YubabaNodeId>,
) -> BTreeMap<String, Option<Vec<HeldCopy>>> {
    let nodes: std::collections::BTreeSet<&str> = intents
        .values()
        .flat_map(|i| i.placements.values().map(|p| p.node.as_str()))
        .collect();
    let me = crate::workload_intent_deploy::this_machine();
    let mut out = BTreeMap::new();
    for node in nodes {
        let Some(member) = machine_ids.get(node).and_then(|id| members.get(id)) else {
            continue;
        };
        let held = if me.as_deref() == Some(node) {
            held_local(s).await.ok()
        } else {
            let url = format!("http://{}/internal/workload-replica/held", member.addr);
            async {
                s.http
                    .get(&url)
                    .timeout(PROBE_TIMEOUT)
                    .send()
                    .await
                    .ok()?
                    .error_for_status()
                    .ok()?
                    .json::<HeldResponse>()
                    .await
                    .ok()
                    .map(|r| r.held)
            }
            .await
        };
        if held.is_none() {
            debug!(%node, "workload reconcile: held probe got no answer, presence unknown");
        }
        out.insert(node.to_string(), held);
    }
    out
}

/// Hand a committed Move to its target: in-process when the target is this
/// node, else the Peer-authed internal route.
async fn call_place(
    s: &Arc<ServerState>,
    members: &BTreeMap<YubabaNodeId, raft::MemberInfo>,
    key: &WorkloadKey,
    ordinal: u32,
    node: &str,
    epoch: u64,
    min_index: u64,
) -> Result<(), String> {
    let req = PlaceRequest {
        key: key.0.clone(),
        ordinal,
        epoch,
        min_index,
    };
    let me = crate::workload_intent_deploy::this_machine();
    if me.as_deref() == Some(node) {
        let resp = place_from_intent(Arc::clone(s), req, me).await;
        return if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("local place answered {}", resp.status()))
        };
    }
    let Some(member) = members
        .values()
        .find(|m| m.machine.as_deref() == Some(node))
    else {
        return Err(format!("{node} has no member row"));
    };
    let url = format!("http://{}/internal/workload-replica/place", member.addr);
    let resp = s
        .http
        .post(&url)
        .timeout(PLACE_TIMEOUT)
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("POST {url}: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(format!("{url} answered {status}: {body}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yubaba_consensus::workload_intent::ReplicaPlacement;

    const ME: &str = "node-test";
    const GRACE: Duration = Duration::from_secs(120);

    fn replica(node: &str, movable: bool) -> ReplicaSnapshot {
        ReplicaSnapshot {
            node: node.into(),
            epoch: 3,
            movable,
        }
    }

    fn cand(arch: &str, load: u32) -> CandidateView {
        CandidateView {
            liveness: Some(Confirmed::Up),
            arch: Some(arch.into()),
            capability: Capability::Unknown,
            cluster_protocol: Some(crate::cluster_epoch::WORKLOAD_INTENT_MIN_PROTOCOL),
            fit: Fit::Admits,
            taints: Some(Vec::new()),
            participation: Some(Participation::In),
            mesh_tags: Some(Vec::new()),
            raft_peer_healthy: true,
            load,
        }
    }

    fn x86() -> Requirements {
        Requirements {
            arch: Some("x86_64".into()),
            ..Requirements::default()
        }
    }

    fn fleet() -> BTreeMap<String, CandidateView> {
        BTreeMap::from([
            ("dead".to_string(), cand("x86_64", 0)),
            ("us-west-002".to_string(), cand("x86_64", 1)),
            ("us-east-001".to_string(), cand("aarch64", 0)),
        ])
    }

    fn down(secs: u64) -> PlacementNode {
        PlacementNode::Down {
            down_for: Duration::from_secs(secs),
        }
    }

    /// R977-B13: the fallback a live ordinal shows is exactly the target a
    /// lost-node decision over the same candidates picks, and a refusal-only
    /// fleet names every node's reason.
    #[test]
    fn fallback_is_the_same_pick_as_the_lost_node_decision() {
        let f = fleet();
        let fb = fallback_for(&replica("dead", true), &x86(), &f);
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &x86(), &f);
        assert_eq!(d, ReplacementDecision::MoveTo(fb.clone()));
        assert_eq!(fb, "us-west-002");

        let mut f = f;
        f.get_mut("us-west-002").unwrap().taints = None;
        assert_eq!(
            fallback_for(&replica("dead", true), &x86(), &f),
            "none (us-east-001=arch(aarch64) us-west-002=taints(unknown))"
        );
        assert_eq!(
            fallback_for(&replica("dead", false), &x86(), &f),
            "none (non-movable)"
        );
    }

    #[test]
    fn the_grace_is_floored_at_120s_at_wan() {
        let policy = HysteresisPolicy::from_thresholds(
            crate::cluster_policy::LivenessThresholds::from_timing(
                crate::cluster_policy::RaftTiming::wan(),
            ),
        );
        // confirm_down_after is 5 s at wan(): 5 + 60 = 65 s, floored to 120 s.
        assert_eq!(policy.confirm_down_after, Duration::from_secs(5));
        assert_eq!(replacement_grace(policy), GRACE);
        // A slow timing whose sum exceeds the floor keeps the sum.
        let slow = HysteresisPolicy {
            confirm_down_after: Duration::from_secs(90),
            confirm_up_after: Duration::from_secs(1),
        };
        assert_eq!(replacement_grace(slow), Duration::from_secs(150));
    }

    #[test]
    fn a_dead_node_past_grace_moves() {
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &x86(), &fleet());
        assert_eq!(d, ReplacementDecision::MoveTo("us-west-002".into()));
        let left = decide_replacement(
            &replica("dead", true),
            PlacementNode::Left,
            GRACE,
            &x86(),
            &fleet(),
        );
        assert_eq!(left, ReplacementDecision::MoveTo("us-west-002".into()));
    }

    #[test]
    fn a_dead_node_inside_grace_does_not_move() {
        let d = decide_replacement(&replica("dead", true), down(119), GRACE, &x86(), &fleet());
        assert_eq!(
            d,
            ReplacementDecision::WaitingGrace {
                remaining: Duration::from_secs(1)
            }
        );
    }

    /// W364 §6: task state is not an input at all. A live node gives `Ok` no
    /// matter what, so a crash loop (or fleet-git's fenced exit 0) never moves.
    #[test]
    fn a_live_node_never_moves_however_often_its_task_crashes() {
        for _ in 0..1000 {
            let d = decide_replacement(
                &replica("dead", true),
                PlacementNode::Live,
                GRACE,
                &x86(),
                &fleet(),
            );
            assert_eq!(d, ReplacementDecision::Ok);
        }
    }

    #[test]
    fn a_non_movable_intent_on_a_lost_node_is_stranded() {
        let d = decide_replacement(&replica("dead", false), down(600), GRACE, &x86(), &fleet());
        assert_eq!(d, ReplacementDecision::Stranded);
        assert_eq!(d.verdict(), "stranded (non-movable)");
    }

    #[test]
    fn an_unmapped_node_holds_rather_than_reading_as_left() {
        let d = decide_replacement(
            &replica("dead", true),
            PlacementNode::Unmapped,
            GRACE,
            &x86(),
            &fleet(),
        );
        assert!(matches!(d, ReplacementDecision::Hold { .. }));
    }

    #[test]
    fn no_x86_candidate_for_an_x86_image_gives_no_move_and_a_reason() {
        let mut f = fleet();
        f.remove("us-west-002");
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &x86(), &f);
        match d {
            ReplacementDecision::NoCandidate { reason } => {
                assert_eq!(reason, "us-east-001=arch(aarch64)");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn filters_refuse_in_order_and_unknown_capability_passes() {
        let mut req = x86();
        req.native_exec = true;
        let mut f = BTreeMap::new();
        let mut absent = cand("x86_64", 0);
        absent.capability = Capability::Absent;
        f.insert("a".to_string(), absent);
        let mut no_fit = cand("x86_64", 0);
        no_fit.fit = Fit::Refuses;
        f.insert("b".to_string(), no_fit);
        let mut veto = cand("x86_64", 0);
        veto.raft_peer_healthy = false;
        f.insert("c".to_string(), veto);
        let mut suspect = cand("x86_64", 0);
        suspect.liveness = None;
        f.insert("d".to_string(), suspect);
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &req, &f);
        assert_eq!(
            d,
            ReplacementDecision::NoCandidate {
                reason: "a=no-native-exec b=no-fit c=raft-peer-down d=not-live".into()
            }
        );
        f.insert("e".to_string(), cand("x86_64", 9));
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &req, &f);
        assert_eq!(
            d,
            ReplacementDecision::MoveTo("e".into()),
            "Unknown capability passes"
        );
    }

    #[test]
    fn a_pinned_node_selector_never_moves_elsewhere_and_untagged_candidates_refuse() {
        let mut req = x86();
        req.pinned_node = Some("dead".into());
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &req, &fleet());
        assert!(
            matches!(d, ReplacementDecision::NoCandidate { .. }),
            "{d:?}"
        );
        let mut req = x86();
        req.mesh_tags = vec!["tag:build-worker".into()];
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &req, &fleet());
        assert!(
            matches!(d, ReplacementDecision::NoCandidate { ref reason } if reason.contains("mesh-tag(tag:build-worker)")),
            "{d:?}"
        );
    }

    /// R1019-F28 (W388): a role selector is evaluated against the member row,
    /// superset like fresh admission, and an unknown row refuses (fail closed).
    #[test]
    fn a_role_selector_moves_only_onto_a_member_declaring_the_role() {
        let mut req = x86();
        req.mesh_tags = vec!["role:public-uptime".into()];
        let mut tagged = cand("x86_64", 5);
        tagged.mesh_tags = Some(vec!["arch:x86".into(), "role:public-uptime".into()]);
        let mut capacity_only = cand("x86_64", 0);
        capacity_only.mesh_tags = Some(vec!["arch:x86".into(), "role:best-effort".into()]);
        let mut unknown = cand("x86_64", 0);
        unknown.mesh_tags = None;
        let f = BTreeMap::from([
            ("best-effort".to_string(), capacity_only),
            ("tagged".to_string(), tagged),
            ("unknown".to_string(), unknown),
        ]);
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &req, &f);
        assert_eq!(d, ReplacementDecision::MoveTo("tagged".into()));

        let f = BTreeMap::from([("unknown".to_string(), {
            let mut c = cand("x86_64", 0);
            c.mesh_tags = None;
            c
        })]);
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &req, &f);
        assert!(
            matches!(d, ReplacementDecision::NoCandidate { ref reason } if reason.contains("unknown=mesh-tags(unknown)")),
            "{d:?}"
        );
    }

    /// An `arch:`-only selector (fleet-git before W388) never reads the row's
    /// tags, so a node that predates the field stays a valid target.
    #[test]
    fn an_arch_only_selector_ignores_unknown_mesh_tags() {
        let mut c = cand("x86_64", 0);
        c.mesh_tags = None;
        let f = BTreeMap::from([("old".to_string(), c)]);
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &x86(), &f);
        assert_eq!(d, ReplacementDecision::MoveTo("old".into()));
    }

    #[test]
    fn an_old_or_unknown_protocol_candidate_refuses_and_the_pick_falls_through() {
        let min = crate::cluster_epoch::WORKLOAD_INTENT_MIN_PROTOCOL;
        let mut gamer = cand("x86_64", 0);
        gamer.cluster_protocol = Some(min - 1);
        let mut unknown = cand("x86_64", 0);
        unknown.cluster_protocol = None;
        let mut f = BTreeMap::from([
            ("gamer".to_string(), gamer),
            ("unknown".to_string(), unknown),
        ]);
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &x86(), &f);
        assert_eq!(
            d,
            ReplacementDecision::NoCandidate {
                reason: format!("gamer=protocol({}) unknown=protocol(unknown)", min - 1)
            }
        );
        // gamer outranks it on load and name, but the next eligible node wins.
        f.insert("us-west-001".to_string(), cand("x86_64", 5));
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &x86(), &f);
        assert_eq!(d, ReplacementDecision::MoveTo("us-west-001".into()));
    }

    /// R977-B12: the taint and participation axes fresh admission applies.
    /// gamer (no-server workstation) and us-west-003 (participation out) are the
    /// live shapes; a row with no published taints refuses rather than passes.
    #[test]
    fn taints_and_participation_refuse_like_a_fresh_deploy_and_the_pick_falls_through() {
        let server = Requirements {
            tolerates: workload_spec::archetype_tolerations(&[
                workload_spec::LifecycleArchetype::Server,
            ]),
            ..x86()
        };
        let mut gamer = cand("x86_64", 0);
        gamer.taints = Some(vec!["no-server".into(), "no-appliance".into()]);
        let mut geekom = cand("x86_64", 0);
        geekom.participation = Some(Participation::Out);
        let mut old_row = cand("x86_64", 0);
        old_row.taints = None;
        let mut no_part = cand("x86_64", 0);
        no_part.participation = None;
        let mut f = BTreeMap::from([
            ("gamer".to_string(), gamer),
            ("geekom".to_string(), geekom),
            ("old-row".to_string(), old_row),
            ("no-part".to_string(), no_part),
        ]);
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &server, &f);
        assert_eq!(
            d,
            ReplacementDecision::NoCandidate {
                reason: "gamer=taint(no-server) geekom=participation(out) \
                         no-part=participation(unknown) old-row=taints(unknown)"
                    .into()
            }
        );
        // A tolerated taint does not repel: no-appliance alone admits a Server.
        let mut builder = cand("x86_64", 3);
        builder.taints = Some(vec!["no-appliance".into(), "public-ip".into()]);
        f.insert("us-west-003".to_string(), builder);
        f.insert("us-west-001".to_string(), cand("x86_64", 5));
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &server, &f);
        assert_eq!(d, ReplacementDecision::MoveTo("us-west-003".into()));
        // Affinity: a spec requiring public-ip skips the untainted node.
        let ingress = Requirements {
            requires_taint: Some("public-ip".into()),
            ..server.clone()
        };
        f.remove("us-west-003");
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &ingress, &f);
        assert!(
            matches!(&d, ReplacementDecision::NoCandidate { reason }
                if reason.contains("us-west-001=requires-taint(public-ip)")),
            "{d:?}"
        );
    }

    #[test]
    fn parse_taints_drops_blanks_so_empty_declares_none() {
        assert_eq!(parse_taints(""), Vec::<String>::new());
        assert_eq!(parse_taints(" no-server, ,no-appliance"), vec!["no-server", "no-appliance"]);
    }

    #[test]
    fn ties_break_by_least_load_then_name_deterministically() {
        let f = BTreeMap::from([
            ("n-c".to_string(), cand("x86_64", 1)),
            ("n-b".to_string(), cand("x86_64", 2)),
            ("n-a".to_string(), cand("x86_64", 1)),
        ]);
        for _ in 0..10 {
            let d = decide_replacement(&replica("dead", true), down(120), GRACE, &x86(), &f);
            assert_eq!(d, ReplacementDecision::MoveTo("n-a".into()));
        }
    }

    #[test]
    fn a_stale_epoch_cas_loss_deploys_nothing() {
        let fenced = WorkloadIntentOutcome::Fenced {
            current: Some(ReplicaPlacement {
                node: "us-west-002".into(),
                epoch: 4,
            }),
        };
        assert_eq!(moved_stamp(0, &fenced), None);
        let moved = WorkloadIntentOutcome::Moved {
            placement: ReplicaPlacement {
                node: "us-west-002".into(),
                epoch: 4,
            },
        };
        assert_eq!(
            moved_stamp(0, &moved),
            Some((
                "us-west-002".into(),
                IntentStamp {
                    ordinal: 0,
                    epoch: 4
                }
            ))
        );
    }

    #[test]
    fn requirements_read_the_fleet_git_selector() {
        let mut spec =
            crate::workload_intent_deploy::tests::spec(workload_spec::RestartPolicy::Always);
        spec.annotations
            .insert(MESH_TAGS_ANNOTATION.into(), "arch:x86".into());
        let req = requirements_of(&spec);
        assert_eq!(req.arch.as_deref(), Some("x86_64"));
        assert!(req.mesh_tags.is_empty());
        assert_eq!(req.pinned_node, None);
    }

    /// The candidate key is `MemberInfo::machine`, which this node registers
    /// from `derive_machine_name()`; the target checks the intent against
    /// `this_machine()`, which is the same function F4 compares with.
    #[test]
    fn the_node_name_form_is_derive_machine_name() {
        let me = crate::leader::derive_machine_name().unwrap_or_else(|| "unnamed".into());
        assert_eq!(
            crate::workload_intent_deploy::this_machine(),
            crate::leader::derive_machine_name()
        );
        let intent = WorkloadIntent {
            spec_json: "{}".into(),
            replicas: 1,
            placements: BTreeMap::from([(
                0,
                ReplicaPlacement {
                    node: me.clone(),
                    epoch: 2,
                },
            )]),
            movable: true,
            requesting_camp_id: None,
            on_behalf_of_user: None,
            operator_sig: None,
        };
        assert_eq!(
            stamp_for_this_node(Some(&intent), 0, 2, &me),
            Ok(IntentStamp {
                ordinal: 0,
                epoch: 2
            })
        );
        assert!(stamp_for_this_node(Some(&intent), 0, 2, "other-host").is_err());
        assert!(
            stamp_for_this_node(Some(&intent), 0, 1, &me).is_err(),
            "stale epoch"
        );
        assert!(stamp_for_this_node(None, 0, 2, &me).is_err());
    }

    #[test]
    fn a_re_placed_copy_keeps_the_original_deploys_attribution() {
        let intent = WorkloadIntent {
            spec_json: "{\"x\":1}".into(),
            replicas: 1,
            placements: BTreeMap::new(),
            movable: true,
            requesting_camp_id: Some("camp:C-abc".into()),
            on_behalf_of_user: Some("user:U-1".into()),
            operator_sig: None,
        };
        let spec = crate::workload_intent_deploy::tests::spec(workload_spec::RestartPolicy::Always);
        let spec_value = crate::workload_intent_deploy::tests::body(&spec);
        let (_tmp, s, operator, _) = keyed_state();
        let key = WorkloadKey(spec.expose.mesh.identity.0.clone());
        let intent = WorkloadIntent {
            spec_json: spec_value.to_string(),
            operator_sig: Some(sign(&operator, &spec_value)),
            ..intent
        };
        let body = deploy_body_from_intent(&s, &key, &intent).unwrap();
        assert_eq!(body.requesting_camp_id.as_deref(), Some("camp:C-abc"));
        assert_eq!(body.on_behalf_of_user.as_deref(), Some("user:U-1"));
        assert_eq!(body.spec, spec_value);
        // An intent recorded before the fields existed deserializes to None.
        let old: WorkloadIntent = serde_json::from_str(
            r#"{"spec_json":"{}","replicas":1,"placements":{},"movable":true}"#,
        )
        .unwrap();
        assert_eq!(old.requesting_camp_id, None);
        assert_eq!(old.on_behalf_of_user, None);
    }

    // ── Endpoint against a real one-voter raft (stub runtime) ────────────────

    /// R997-B11: a node that trusts one operator key and one cluster key.
    fn keyed_policy() -> (
        crate::http_auth::HttpAuthPolicy,
        yubaba_auth_token::delegation::OperatorSecretKey,
        pasetors::keys::SymmetricKey<pasetors::version4::V4>,
    ) {
        use pasetors::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
        use pasetors::version4::V4;
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let sym = SymmetricKey::<V4>::generate().unwrap();
        let policy = crate::http_auth::HttpAuthPolicy::new(
            crate::http_auth::AuthMode::Require,
            &[yubaba_auth_token::encode_hex(kp.public.as_bytes())],
            Some(&yubaba_auth_token::encode_hex(sym.as_bytes())),
        )
        .unwrap();
        (policy, kp.secret, sym)
    }

    fn keyed_state() -> (
        tempfile::TempDir,
        Arc<ServerState>,
        yubaba_auth_token::delegation::OperatorSecretKey,
        pasetors::keys::SymmetricKey<pasetors::version4::V4>,
    ) {
        let (policy, operator, cluster) = keyed_policy();
        let tmp = tempfile::TempDir::new().unwrap();
        let state = ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_http_auth(policy);
        (tmp, Arc::new(state), operator, cluster)
    }

    fn sign(
        operator: &yubaba_auth_token::delegation::OperatorSecretKey,
        spec: &serde_json::Value,
    ) -> String {
        yubaba_auth_token::delegation::sign_workload_spec(operator, spec).unwrap()
    }

    async fn single_node() -> (tempfile::TempDir, Arc<ServerState>) {
        let (tmp, s, _, _) = single_node_keyed().await;
        (tmp, s)
    }

    async fn single_node_keyed() -> (
        tempfile::TempDir,
        Arc<ServerState>,
        yubaba_auth_token::delegation::OperatorSecretKey,
        pasetors::keys::SymmetricKey<pasetors::version4::V4>,
    ) {
        use openraft::async_runtime::watch::WatchReceiver;
        let (auth, operator, cluster) = keyed_policy();
        let tmp = tempfile::TempDir::new().unwrap();
        let policy = crate::cluster_policy::ClusterPolicy::rig();
        let (raft, sm) = raft::open_with_state_machine(
            1,
            tmp.path().join("raft"),
            &policy,
            yubaba_auth_token::PeerSigner::unsigned(),
        )
        .await
        .unwrap();
        raft::bootstrap_single_node(&raft, 1, "127.0.0.1:0")
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while raft.metrics().borrow_watched().current_leader != Some(1) {
            assert!(Instant::now() < deadline, "never elected itself");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let state = ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_node_id(1)
            .with_raft(raft)
            .with_cluster_state(sm)
            .with_http_auth(auth);
        (tmp, Arc::new(state), operator, cluster)
    }

    /// Put an intent placing ordinal 0 on `other`, then Move it to this node;
    /// returns the Move's log index and the new epoch.
    async fn intent_moved_here(
        s: &ServerState,
        ident: &str,
        spec_json: String,
        operator_sig: Option<String>,
    ) -> (u64, u64) {
        let me = ME.to_string();
        let raft = s.raft.as_ref().unwrap();
        let key = WorkloadKey(ident.into());
        raft.client_write(raft::YubabaRequest::PutWorkloadIntent {
            key: key.clone(),
            intent: WorkloadIntent {
                spec_json,
                replicas: 1,
                placements: BTreeMap::from([(
                    0,
                    ReplicaPlacement {
                        node: "gone".into(),
                        epoch: 1,
                    },
                )]),
                movable: true,
                requesting_camp_id: Some("camp:C-r977".into()),
                on_behalf_of_user: Some("user:U-r977".into()),
                operator_sig,
            },
        })
        .await
        .unwrap();
        let resp = raft
            .client_write(raft::YubabaRequest::MoveWorkloadReplica {
                key,
                ordinal: 0,
                from_node: "gone".into(),
                from_epoch: 1,
                to_node: me,
            })
            .await
            .unwrap();
        let (_, stamp) = match &resp.data {
            raft::YubabaResponse::WorkloadIntent(o) => moved_stamp(0, o).expect("moved"),
            other => panic!("{other:?}"),
        };
        (resp.log_id.index, stamp.epoch)
    }

    #[tokio::test]
    async fn the_target_places_with_the_intents_stamp_after_applying_the_move() {
        let (_tmp, s, operator, _) = single_node_keyed().await;
        let spec = crate::workload_intent_deploy::tests::spec(workload_spec::RestartPolicy::Always);
        let ident = spec.expose.mesh.identity.0.clone();
        let body = crate::workload_intent_deploy::tests::body(&spec);
        let (index, epoch) =
            intent_moved_here(&s, &ident, body.to_string(), Some(sign(&operator, &body))).await;
        assert_eq!(epoch, 2);
        let resp = place_from_intent(
            Arc::clone(&s),
            PlaceRequest {
                key: ident.clone(),
                ordinal: 0,
                epoch,
                min_index: index,
            },
            Some(ME.into()),
        )
        .await;
        assert!(resp.status().is_success(), "{}", resp.status());
        // Idempotent: the same stamp places again.
        let again = place_from_intent(
            Arc::clone(&s),
            PlaceRequest {
                key: ident.clone(),
                ordinal: 0,
                epoch,
                min_index: index,
            },
            Some(ME.into()),
        )
        .await;
        assert!(again.status().is_success(), "replay: {}", again.status());
    }

    #[tokio::test]
    async fn the_target_refuses_a_stale_epoch_and_an_unapplied_index() {
        let (_tmp, s, operator, _) = single_node_keyed().await;
        let spec = crate::workload_intent_deploy::tests::spec(workload_spec::RestartPolicy::Always);
        let ident = spec.expose.mesh.identity.0.clone();
        let body = crate::workload_intent_deploy::tests::body(&spec);
        let (index, epoch) =
            intent_moved_here(&s, &ident, body.to_string(), Some(sign(&operator, &body))).await;
        let stale = place_from_intent(
            Arc::clone(&s),
            PlaceRequest {
                key: ident.clone(),
                ordinal: 0,
                epoch: epoch - 1,
                min_index: index,
            },
            Some(ME.into()),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        tokio::time::pause();
        let future = place_from_intent(
            Arc::clone(&s),
            PlaceRequest {
                key: ident,
                ordinal: 0,
                epoch,
                min_index: index + 1000,
            },
            Some(ME.into()),
        );
        let resp = future.await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // ── R997-B11: an intent places only under the operator's signature ──────

    async fn place_here(s: &Arc<ServerState>, ident: &str, index: u64, epoch: u64) -> StatusCode {
        place_from_intent(
            Arc::clone(s),
            PlaceRequest {
                key: ident.into(),
                ordinal: 0,
                epoch,
                min_index: index,
            },
            Some(ME.into()),
        )
        .await
        .status()
    }

    #[tokio::test]
    async fn an_unsigned_or_foreign_signed_intent_is_never_placed() {
        let (_tmp, s, _operator, _) = single_node_keyed().await;
        let spec = crate::workload_intent_deploy::tests::spec(workload_spec::RestartPolicy::Always);
        let ident = spec.expose.mesh.identity.0.clone();
        let body = crate::workload_intent_deploy::tests::body(&spec);
        let (index, epoch) = intent_moved_here(&s, &ident, body.to_string(), None).await;
        assert_eq!(place_here(&s, &ident, index, epoch).await, StatusCode::FORBIDDEN);
        // Signed, but by a key this node does not trust (fresh node: the
        // helper's Move CAS starts from epoch 1).
        let (_tmp, s, _operator, _) = single_node_keyed().await;
        let (_, stranger, _) = keyed_policy();
        let (index, epoch) =
            intent_moved_here(&s, &ident, body.to_string(), Some(sign(&stranger, &body))).await;
        assert_eq!(place_here(&s, &ident, index, epoch).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_tampered_spec_under_a_valid_signature_is_refused() {
        let (_tmp, s, operator, _) = single_node_keyed().await;
        let spec = crate::workload_intent_deploy::tests::spec(workload_spec::RestartPolicy::Always);
        let ident = spec.expose.mesh.identity.0.clone();
        let signed_body = crate::workload_intent_deploy::tests::body(&spec);
        let sig = sign(&operator, &signed_body);
        let mut tampered = spec.clone();
        tampered.replicas += 1;
        let tampered_body = crate::workload_intent_deploy::tests::body(&tampered);
        assert_ne!(tampered_body, signed_body);
        let (index, epoch) =
            intent_moved_here(&s, &ident, tampered_body.to_string(), Some(sig.clone())).await;
        assert_eq!(place_here(&s, &ident, index, epoch).await, StatusCode::FORBIDDEN);
        // A signed spec stored under another workload's key is refused too.
        let (index, epoch) =
            intent_moved_here(&s, "some-other-ident", signed_body.to_string(), Some(sig)).await;
        assert_eq!(
            place_here(&s, "some-other-ident", index, epoch).await,
            StatusCode::FORBIDDEN
        );
    }

    /// The migration: an intent recorded unsigned is listed, attested by the
    /// operator, and then places; a wrong signature or a stale spec is not.
    #[tokio::test]
    async fn an_operator_attestation_makes_an_unsigned_intent_placeable() {
        let (_tmp, s, operator, _) = single_node_keyed().await;
        let spec = crate::workload_intent_deploy::tests::spec(workload_spec::RestartPolicy::Always);
        let ident = spec.expose.mesh.identity.0.clone();
        let body = crate::workload_intent_deploy::tests::body(&spec);
        let (index, epoch) = intent_moved_here(&s, &ident, body.to_string(), None).await;
        assert_eq!(place_here(&s, &ident, index, epoch).await, StatusCode::FORBIDDEN);

        let listed = list_unattested_intents(State(Arc::clone(&s))).await;
        let listed = axum::body::to_bytes(listed.into_body(), 1 << 20).await.unwrap();
        let listed: serde_json::Value = serde_json::from_slice(&listed).unwrap();
        let rows: Vec<UnattestedIntent> = serde_json::from_value(listed["intents"].clone()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key, ident);

        let attest = |spec_json: String, operator_sig: String| {
            attest_intent_handler(
                State(Arc::clone(&s)),
                Json(AttestRequest {
                    key: ident.clone(),
                    spec_json,
                    operator_sig,
                }),
            )
        };
        let (_, stranger, _) = keyed_policy();
        assert_eq!(
            attest(rows[0].spec_json.clone(), sign(&stranger, &body)).await.status(),
            StatusCode::FORBIDDEN
        );
        // Signed by the operator but not the spec raft holds: nothing changes.
        let mut other = spec.clone();
        other.replicas += 1;
        let other_body = crate::workload_intent_deploy::tests::body(&other);
        assert_eq!(
            attest(other_body.to_string(), sign(&operator, &other_body)).await.status(),
            StatusCode::CONFLICT
        );
        let ok = attest(rows[0].spec_json.clone(), sign(&operator, &body)).await;
        assert!(ok.status().is_success(), "{}", ok.status());
        assert!(place_here(&s, &ident, index, epoch).await.is_success());
    }

    /// The peer tier can write raft state, so a raft write must never be
    /// enough to deploy: driven through the real router with a peer token.
    #[tokio::test]
    async fn a_peer_token_cannot_turn_a_raft_write_into_a_deploy() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let Some(me) = crate::workload_intent_deploy::this_machine() else {
            eprintln!("skipping: this host has no derivable machine name");
            return;
        };
        let (_tmp, s, operator, cluster) = single_node_keyed().await;
        let peer = format!(
            "Bearer {}",
            yubaba_auth_token::mint_peer_token(&cluster, "node:intruder", 300, yubaba_auth_token::now_unix())
                .unwrap()
        );
        let spec = crate::workload_intent_deploy::tests::spec(workload_spec::RestartPolicy::Always);
        let ident = spec.expose.mesh.identity.0.clone();
        let body = crate::workload_intent_deploy::tests::body(&spec);
        let post = |path: &str, json: serde_json::Value| {
            Request::post(path)
                .header("content-type", "application/json")
                .header("authorization", &peer)
                .body(Body::from(json.to_string()))
                .unwrap()
        };
        let put = |sig: Option<String>, epoch: u64| {
            serde_json::json!({ "request": { "PutWorkloadIntent": {
                "key": ident,
                "intent": {
                    "spec_json": body.to_string(),
                    "replicas": 1,
                    "placements": { "0": { "node": me, "epoch": epoch } },
                    "movable": true,
                    "operator_sig": sig,
                },
            }}})
        };
        let place = |epoch: u64| {
            serde_json::json!({ "key": ident, "ordinal": 0, "epoch": epoch, "min_index": 0 })
        };
        // The write itself is peer traffic and lands.
        let resp = crate::build_router(Arc::clone(&s))
            .oneshot(post("/raft/write", put(Some("00".repeat(64)), 1)))
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
        let resp = crate::build_router(Arc::clone(&s))
            .oneshot(post("/internal/workload-replica/place", place(1)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let listed = crate::build_router(Arc::clone(&s))
            .oneshot(
                Request::get("/workloads")
                    .header("authorization", &peer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let listed = axum::body::to_bytes(listed.into_body(), 1 << 20).await.unwrap();
        assert!(
            !String::from_utf8_lossy(&listed).contains(&ident),
            "a forged intent was deployed"
        );
        // Non-vacuity: the same peer path places an operator-signed spec.
        let resp = crate::build_router(Arc::clone(&s))
            .oneshot(post("/raft/write", put(Some(sign(&operator, &body)), 1)))
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
        let resp = crate::build_router(Arc::clone(&s))
            .oneshot(post("/internal/workload-replica/place", place(1)))
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
    }

    // ── R977-B9: stateless convergence of a missing copy ──────────────────

    #[test]
    fn a_terminal_copy_is_not_held_so_the_absent_clock_can_fire() {
        use kamaji_proto::WorkloadState as S;
        for live in [S::Pending, S::Starting, S::Running, S::Draining] {
            assert!(holds_a_copy(&live), "{live:?}");
        }
        // R977-T8 run 3: the fenced-out fleet-git sat Exited and blocked it.
        for dead in [S::Exited, S::Failed, S::OomKilled, S::DeadlineExceeded] {
            assert!(!holds_a_copy(&dead), "{dead:?}");
        }
    }

    fn held(key: &str, ordinal: u32, epoch: u64) -> HeldCopy {
        HeldCopy {
            key: key.into(),
            ordinal,
            epoch,
        }
    }

    const STAMP: IntentStamp = IntentStamp {
        ordinal: 0,
        epoch: 3,
    };

    #[test]
    fn absent_for_less_than_the_grace_does_nothing() {
        let r = replica("us-west-002", true);
        let mut clock = AbsentClock::default();
        let t0 = Instant::now();
        let p = presence_in(Some(&[]), "fleet-git", STAMP);
        assert_eq!(p, CopyPresence::Absent);
        assert_eq!(
            clock.observe("fleet-git", &r, 0, p, t0),
            Some(Duration::ZERO)
        );
        let d = clock.observe("fleet-git", &r, 0, p, t0 + Duration::from_secs(119));
        assert_eq!(
            decide_missing_copy(&r, d, GRACE),
            CopyDecision::AbsentWaiting {
                remaining: Duration::from_secs(1)
            }
        );
        assert_eq!(
            decide_missing_copy(&r, d, GRACE).verdict(),
            "absent: waiting (1s left)"
        );
    }

    #[test]
    fn absent_past_the_grace_places_on_the_node_the_intent_names() {
        let r = replica("us-west-002", true);
        let mut clock = AbsentClock::default();
        let t0 = Instant::now();
        clock.observe("fleet-git", &r, 0, CopyPresence::Absent, t0);
        let d = clock.observe("fleet-git", &r, 0, CopyPresence::Absent, t0 + GRACE);
        assert_eq!(
            decide_missing_copy(&r, d, GRACE),
            CopyDecision::Replace {
                node: "us-west-002".into(),
                epoch: 3
            }
        );
    }

    #[test]
    fn a_present_copy_in_any_task_state_does_nothing() {
        // The held probe lists every kamaji spec regardless of task state, so a
        // crashed or exit-0 copy reads Present and is restart.rs's business.
        let r = replica("us-west-002", true);
        let list = [held("fleet-git", 0, 3)];
        let p = presence_in(Some(&list), "fleet-git", STAMP);
        assert_eq!(p, CopyPresence::Present);
        let mut clock = AbsentClock::default();
        let t0 = Instant::now();
        clock.observe("fleet-git", &r, 0, CopyPresence::Absent, t0);
        let d = clock.observe("fleet-git", &r, 0, p, t0 + GRACE * 10);
        assert_eq!(decide_missing_copy(&r, d, GRACE), CopyDecision::Ok);
    }

    #[test]
    fn a_copy_at_another_stamp_or_key_is_absent_and_an_unanswered_probe_never_acts() {
        let list = [
            held("fleet-git", 0, 2),
            held("other", 0, 3),
            held("fleet-git", 1, 3),
        ];
        assert_eq!(
            presence_in(Some(&list), "fleet-git", STAMP),
            CopyPresence::Absent
        );
        assert_eq!(presence_in(None, "fleet-git", STAMP), CopyPresence::Unknown);
        let r = replica("us-west-002", true);
        let mut clock = AbsentClock::default();
        let t0 = Instant::now();
        clock.observe("fleet-git", &r, 0, CopyPresence::Absent, t0);
        let d = clock.observe("fleet-git", &r, 0, CopyPresence::Unknown, t0 + GRACE * 10);
        assert_eq!(decide_missing_copy(&r, d, GRACE), CopyDecision::Ok);
    }

    #[test]
    fn a_copy_held_on_a_node_the_intent_does_not_name_never_redirects_the_place() {
        // The copy runs on us-east-001; the intent names us-west-002. Presence
        // is judged only on the named node, and the place aims there.
        let r = replica("us-west-002", true);
        let probes: BTreeMap<String, Option<Vec<HeldCopy>>> = BTreeMap::from([
            (
                "us-east-001".to_string(),
                Some(vec![held("fleet-git", 0, 3)]),
            ),
            ("us-west-002".to_string(), Some(vec![])),
        ]);
        let p = presence_in(
            probes.get(&r.node).and_then(|h| h.as_deref()),
            "fleet-git",
            STAMP,
        );
        assert_eq!(p, CopyPresence::Absent);
        let mut clock = AbsentClock::default();
        let t0 = Instant::now();
        clock.observe("fleet-git", &r, 0, p, t0);
        let d = clock.observe("fleet-git", &r, 0, p, t0 + GRACE);
        match decide_missing_copy(&r, d, GRACE) {
            CopyDecision::Replace { node, .. } => assert_eq!(node, "us-west-002"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_move_restarts_the_absent_wait() {
        let mut clock = AbsentClock::default();
        let t0 = Instant::now();
        clock.observe(
            "fleet-git",
            &replica("a", true),
            0,
            CopyPresence::Absent,
            t0,
        );
        let moved = ReplicaSnapshot {
            node: "b".into(),
            epoch: 4,
            movable: true,
        };
        let d = clock.observe("fleet-git", &moved, 0, CopyPresence::Absent, t0 + GRACE);
        assert_eq!(d, Some(Duration::ZERO));
    }

    #[test]
    fn a_new_leader_re_earns_the_absent_wait() {
        let r = replica("us-west-002", true);
        let mut clock = AbsentClock::default();
        let t0 = Instant::now();
        clock.observe("fleet-git", &r, 0, CopyPresence::Absent, t0);
        // Leadership lost: the loop clears the clock. Whoever leads next
        // starts from an empty one, as here.
        clock.clear();
        let d = clock.observe("fleet-git", &r, 0, CopyPresence::Absent, t0 + GRACE * 5);
        assert_eq!(d, Some(Duration::ZERO));
        assert!(matches!(
            decide_missing_copy(&r, d, GRACE),
            CopyDecision::AbsentWaiting { .. }
        ));
        // A place attempt restarts it too, so a failing target is retried once per grace.
        let d = clock.observe("fleet-git", &r, 0, CopyPresence::Absent, t0 + GRACE * 6);
        assert_eq!(
            decide_missing_copy(&r, d, GRACE),
            CopyDecision::Replace {
                node: r.node.clone(),
                epoch: 3
            }
        );
        clock.reset("fleet-git", 0);
        let d = clock.observe("fleet-git", &r, 0, CopyPresence::Absent, t0 + GRACE * 6);
        assert_eq!(d, Some(Duration::ZERO));
    }

    #[test]
    fn unknown_capacity_passes_and_ranks_after_known() {
        let mut unknown = cand("x86_64", 0);
        unknown.fit = Fit::Unknown;
        let f = BTreeMap::from([
            ("a-unknown".to_string(), unknown.clone()),
            ("z-known".to_string(), cand("x86_64", 5)),
        ]);
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &x86(), &f);
        assert_eq!(d, ReplacementDecision::MoveTo("z-known".into()));
        // Only unknown-capacity nodes: they pass, by load then name.
        let mut u2 = unknown.clone();
        u2.load = 0;
        let f = BTreeMap::from([("b".to_string(), unknown), ("a".to_string(), u2)]);
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &x86(), &f);
        assert_eq!(d, ReplacementDecision::MoveTo("a".into()));
    }

    #[test]
    fn insufficient_published_capacity_refuses() {
        let mut small = cand("x86_64", 0);
        small.fit = Fit::Refuses;
        let f = BTreeMap::from([("n".to_string(), small)]);
        let d = decide_replacement(&replica("dead", true), down(120), GRACE, &x86(), &f);
        assert_eq!(
            d,
            ReplacementDecision::NoCandidate {
                reason: "n=no-fit".into()
            }
        );
    }
}
