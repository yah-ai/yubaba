//! The deploy path's half of W364 §1 and §5 (R977-F2): an operator deploy of a
//! long-running workload records a `WorkloadIntent` in raft before it places
//! the replica, and an operator destroy drops it.
//!
//! Three seams other tickets reuse:
//! - [`workload_intent_writes_open_live`] — the write gate's I/O. R977-F3's
//!   `MoveWorkloadReplica` writes call it too.
//! - [`crate::place_workload_replica`] (in `lib.rs`) — "deploy this spec on
//!   this node under this stamp, no intent write". F3 re-places through it
//!   after its Move CAS; F5 redeploys a fenced copy through it.
//! - [`intent_candidate`] — which deploys get an intent (the rule below).
//!
//! ## Which deploys get an intent
//!
//! Only a deploy that is all of:
//! 1. `DeployOrigin::Api` — an operator/CLI deploy. A floater's local placement
//!    is already owned by the floater map, and a self-supplied provider is
//!    owned by its requirer (the requirer's deploy stands it up again), so
//!    neither arrives here with `Api` (see `deploy_workload_spec_boxed`).
//! 2. a container spec that does not float (`wants_float()` goes to
//!    `admit_floater` and is placed by the floater map);
//! 3. **long-running**: `effective_archetype() != Job` AND
//!    `restart_policy != Never`. Forge records (`WorkloadSpec::for_forge`) are
//!    `RestartPolicy::Never`, so they — and any other run-once step — never get
//!    an intent and the reconcile can never resurrect a finished job. The
//!    restart half matters on its own: `LifecycleArchetype::infer` ranks a
//!    named volume above `Never`, so a forge spec carrying a volume infers
//!    `Appliance`, not `Job`.
//!
//! ## Failure semantics
//!
//! The gate fails closed: no raft, an unknown member address, a voter or
//! learner (every node that receives the raft log, R977-B10) that has
//! never answered `/health` within [`MEMBER_PROBE_TIMEOUT`] (one that answered
//! before is read as its last answer, R977-T8), or one advertising a
//! protocol below `WORKLOAD_INTENT_MIN_PROTOCOL` all mean "write nothing", and
//! the deploy behaves exactly as it did before R977. A failed Put does the
//! same. A failed placement drops the intent only if this deploy created it; a
//! redeploy that fails leaves the existing intent (the previous generation may
//! still be running under it) and surfaces the error.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::response::Response;
use openraft::async_runtime::watch::WatchReceiver;
use workload_spec::{LifecycleArchetype, RestartPolicy, WorkloadSpec};
use yubaba_consensus::workload_intent::{
    workload_intent_writes_open, IntentStamp, ReplicaPlacement, WorkloadIntent,
};

use crate::{raft, DeployOrigin, ServerState, WorkloadDeployBody};

/// How long one raft member gets to answer `GET /health` before it counts as
/// unreachable — i.e. as a closed gate.
pub(crate) const MEMBER_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// A deploy the intent rule accepted, with everything the Put needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntentCandidate {
    pub key: raft::WorkloadKey,
    pub spec_json: String,
    pub replicas: u32,
    pub movable: bool,
    /// The deploy's operator signature over the spec (R997-B11).
    pub operator_sig: Option<String>,
}

/// W364 §5: re-placeable iff no stateful named volume and not an Appliance.
pub(crate) fn is_movable(spec: &WorkloadSpec) -> bool {
    spec.stateful_named_volumes().is_empty()
        && spec.effective_archetype() != LifecycleArchetype::Appliance
}

/// Whether a parsed spec is a long-running replica (rule 3 in the module doc).
pub(crate) fn is_long_running(spec: &WorkloadSpec) -> bool {
    spec.effective_archetype() != LifecycleArchetype::Job
        && !matches!(spec.restart_policy, RestartPolicy::Never)
}

/// The container spec a deploy body carries, parsed the way
/// `check_deploy_body` parses it (envelope first, bare spec second). `None` for
/// anything that is not a digest-pinned container spec.
pub(crate) fn container_spec_of(body: &serde_json::Value) -> Option<WorkloadSpec> {
    match serde_json::from_value::<workload_spec::Workload>(body.clone()) {
        Ok(workload_spec::Workload::Container(manifest)) => manifest.into_spec().ok(),
        Ok(_) => None,
        Err(_) => serde_json::from_value::<WorkloadSpec>(body.clone()).ok(),
    }
}

/// The which-deploys rule. `None` = this deploy writes no intent.
pub(crate) fn intent_candidate(
    body: &serde_json::Value,
    operator_sig: Option<&str>,
    origin: DeployOrigin,
) -> Option<IntentCandidate> {
    if origin != DeployOrigin::Api {
        return None;
    }
    let spec = container_spec_of(body)?;
    if spec.wants_float() || !is_long_running(&spec) {
        return None;
    }
    Some(IntentCandidate {
        key: raft::WorkloadKey(spec.expose.mesh.identity.0.clone()),
        spec_json: body.to_string(),
        replicas: spec.replicas,
        movable: is_movable(&spec),
        operator_sig: operator_sig.map(str::to_string),
    })
}

/// Ask each raft member's `GET /health` for its `cluster_protocol`,
/// concurrently. `None` for a member with no known address, one that did not answer in
/// [`MEMBER_PROBE_TIMEOUT`], or one whose body carries no protocol.
pub(crate) async fn probe_member_protocols(
    http: &yubaba_auth_token::PeerClient,
    members: Vec<(raft::YubabaNodeId, Option<String>)>,
) -> BTreeMap<raft::YubabaNodeId, Option<u32>> {
    let mut probes = tokio::task::JoinSet::new();
    for (id, base) in members {
        let http = http.clone();
        probes.spawn(async move {
            let Some(base) = base else { return (id, None) };
            let protocol = async {
                let resp = http
                    .get(format!("{base}/health"))
                    .timeout(MEMBER_PROBE_TIMEOUT)
                    .send()
                    .await
                    .ok()?;
                let body: serde_json::Value = resp.json().await.ok()?;
                body.get("cluster_protocol")?.as_u64().and_then(|p| u32::try_from(p).ok())
            };
            let protocol = tokio::time::timeout(MEMBER_PROBE_TIMEOUT, protocol)
                .await
                .ok()
                .flatten();
            (id, protocol)
        });
    }
    let mut advertised = BTreeMap::new();
    while let Some(joined) = probes.join_next().await {
        // A panicked probe proves nothing about its member, and the member is
        // simply absent from the map — which the predicate reads as closed.
        if let Ok((id, protocol)) = joined {
            advertised.insert(id, protocol);
        }
    }
    advertised
}

/// The live write gate (F1's seam 1 with its I/O): every log receiver —
/// voters AND learners (R977-B10) — from raft membership, each one's protocol
/// from its `/health` (this node answers for
/// itself from [`crate::cluster_epoch::CLUSTER_PROTOCOL`]), then the pure
/// predicate. Fails closed on every unknown — but a member that does not
/// answer is read as the protocol it last advertised ([`latch_merge`]), not
/// as unknown (R977-T8).
pub(crate) async fn workload_intent_writes_open_live(s: &ServerState) -> bool {
    let Some((log_receivers, advertised)) = advertised_protocols(s).await else {
        return false;
    };
    workload_intent_writes_open(
        &log_receivers,
        &advertised,
        crate::cluster_epoch::WORKLOAD_INTENT_MIN_PROTOCOL,
    )
}

/// Every log receiver and the protocol it advertises: probed live, then
/// merged with — and written into — [`ServerState::protocol_latch`]. `None`
/// when this node has no raft. Followers call this too, purely to keep their
/// latch warm for the day they are elected.
pub(crate) async fn advertised_protocols(
    s: &ServerState,
) -> Option<(
    BTreeSet<raft::YubabaNodeId>,
    BTreeMap<raft::YubabaNodeId, Option<u32>>,
)> {
    let (Some(raft), Some(sm)) = (s.raft.as_ref(), s.cluster_state.as_ref()) else {
        return None;
    };
    let log_receivers: BTreeSet<raft::YubabaNodeId> = raft
        .metrics()
        .borrow_watched()
        .membership_config
        .membership()
        .nodes()
        .map(|(id, _)| *id)
        .collect();
    let members = sm.members();
    let mut advertised = BTreeMap::new();
    let mut remote = Vec::new();
    for id in &log_receivers {
        if Some(*id) == s.node_id {
            advertised.insert(*id, Some(crate::cluster_epoch::CLUSTER_PROTOCOL));
        } else {
            remote.push((*id, members.get(id).map(|m| format!("http://{}", m.addr))));
        }
    }
    advertised.extend(probe_member_protocols(&s.http, remote).await);
    let advertised = latch_merge(&mut s.protocol_latch.lock().unwrap(), advertised);
    Some((log_receivers, advertised))
}

/// R997-B11: may `AttestWorkloadIntent` be written? Only when every log
/// receiver answers `/health` with `workload_intent_attest: true` right now.
/// No latch: this is an operator-run migration, so failing closed while a
/// member is down costs a retry, never a stalled follower.
pub(crate) async fn attest_writes_open_live(s: &ServerState) -> bool {
    let (Some(raft), Some(sm)) = (s.raft.as_ref(), s.cluster_state.as_ref()) else {
        return false;
    };
    let log_receivers: Vec<raft::YubabaNodeId> = raft
        .metrics()
        .borrow_watched()
        .membership_config
        .membership()
        .nodes()
        .map(|(id, _)| *id)
        .filter(|id| Some(*id) != s.node_id)
        .collect();
    let members = sm.members();
    for id in log_receivers {
        let Some(member) = members.get(&id) else {
            return false;
        };
        let capable = async {
            let resp = s
                .http
                .get(format!("http://{}/health", member.addr))
                .timeout(MEMBER_PROBE_TIMEOUT)
                .send()
                .await
                .ok()?;
            let body: serde_json::Value = resp.json().await.ok()?;
            body.get("workload_intent_attest")?.as_bool()
        };
        if tokio::time::timeout(MEMBER_PROBE_TIMEOUT, capable).await.ok().flatten() != Some(true) {
            return false;
        }
    }
    true
}

/// R977-T8: fold one probe round into the latch and answer with the merged
/// view. A member that answered overwrites its latched value (even downwards:
/// what a node says now is the truth about it). A member that did not answer
/// reads as its latched value, or stays `None` if it never answered.
///
/// Why a silent member may keep its last protocol: the gate exists so no log
/// receiver is handed a variant it cannot apply. A dead node applies nothing;
/// it catches up on restart with whatever binary it restarts with, and a
/// binary older than the cluster epoch refuses to rejoin (R625, W275). So
/// "unreachable" is evidence about liveness, not about protocol — and the
/// reconcile's whole job is to act on the dead node. Reading it as unknown
/// made the gate close on exactly the node the reconcile had to move a
/// replica off (R977-T8 run 1: `hold: write gate closed` until the dead
/// voter came back).
pub(crate) fn latch_merge(
    latch: &mut BTreeMap<raft::YubabaNodeId, u32>,
    probed: BTreeMap<raft::YubabaNodeId, Option<u32>>,
) -> BTreeMap<raft::YubabaNodeId, Option<u32>> {
    probed
        .into_iter()
        .map(|(id, p)| match p {
            Some(p) => {
                latch.insert(id, p);
                (id, Some(p))
            }
            None => (id, latch.get(&id).copied()),
        })
        .collect()
}

/// The node name a placement records for THIS node. It must be the exact
/// string `rejoin_cleanup::decide` compares against (R977-F4), which is
/// [`crate::leader::derive_machine_name`]; any other form (raft id, tailnet
/// hostname, IP) gets every stamped copy stopped on its next caught-up tick.
pub(crate) fn this_machine() -> Option<String> {
    crate::leader::derive_machine_name()
}

/// Gate → Put → place with the stamp raft answered with. Any reason not to
/// record (no candidate, gate closed, no raft, this node has no machine name,
/// the Put failed) places exactly as before R977: no Put, no stamp.
pub(crate) async fn deploy_recording_intent(
    s: Arc<ServerState>,
    req: WorkloadDeployBody,
    origin: DeployOrigin,
    candidate: Option<IntentCandidate>,
    gate_open: bool,
    this_machine: Option<String>,
) -> Response {
    let Some(candidate) = candidate.filter(|_| gate_open) else {
        return crate::place_workload_replica(s, req, origin, None).await;
    };
    let (Some(raft), Some(sm)) = (s.raft.clone(), s.cluster_state.clone()) else {
        return crate::place_workload_replica(s, req, origin, None).await;
    };
    let Some(node) = this_machine else {
        tracing::warn!(
            ident = %candidate.key.0,
            "workload intent: this node cannot derive its machine name; deploying without one"
        );
        return crate::place_workload_replica(s, req, origin, None).await;
    };
    let key = candidate.key.clone();
    let existed = sm.with_state(|st| st.workload_intent.contains_key(&key));
    let put = raft::YubabaRequest::PutWorkloadIntent {
        key: key.clone(),
        intent: WorkloadIntent {
            spec_json: candidate.spec_json,
            replicas: candidate.replicas,
            placements: BTreeMap::from([(0, ReplicaPlacement { node, epoch: 1 })]),
            movable: candidate.movable,
            requesting_camp_id: req.requesting_camp_id.clone(),
            on_behalf_of_user: req.on_behalf_of_user.clone(),
            operator_sig: candidate.operator_sig,
        },
    };
    let epoch = match raft::client_write_forwarded(&raft, &s.http, put).await {
        Ok(raft::YubabaResponse::WorkloadIntent(raft::WorkloadIntentOutcome::Recorded {
            placements,
        })) => placements.get(&0).map(|p| p.epoch),
        Ok(other) => {
            tracing::warn!(ident = %key.0, ?other, "workload intent: unexpected Put answer");
            None
        }
        Err(e) => {
            tracing::warn!(ident = %key.0, "workload intent: Put failed, deploying without one: {e}");
            None
        }
    };
    let Some(epoch) = epoch else {
        return crate::place_workload_replica(s, req, origin, None).await;
    };
    let stamp = IntentStamp { ordinal: 0, epoch };
    let resp = crate::place_workload_replica(Arc::clone(&s), req, origin, Some(stamp)).await;
    if !resp.status().is_success() && !existed {
        let drop = raft::YubabaRequest::DropWorkloadIntent { key: key.clone() };
        if let Err(e) = raft::client_write_forwarded(&raft, &s.http, drop).await {
            tracing::error!(
                ident = %key.0,
                "workload intent: deploy failed and the intent it created could not be dropped: {e}"
            );
        }
    }
    resp
}

/// Operator stop/destroy: forget the intent so the reconcile stops re-placing
/// it. Only written when one exists — which also means the gate was open when
/// it was recorded.
pub(crate) async fn drop_intent_if_recorded(s: &ServerState, ident: &str) {
    let (Some(raft), Some(sm)) = (s.raft.as_ref(), s.cluster_state.as_ref()) else {
        return;
    };
    let key = raft::WorkloadKey(ident.to_string());
    if !sm.with_state(|st| st.workload_intent.contains_key(&key)) {
        return;
    }
    let drop = raft::YubabaRequest::DropWorkloadIntent { key };
    if let Err(e) = raft::client_write_forwarded(raft, &s.http, drop).await {
        tracing::warn!(ident = %ident, "workload intent: Drop failed on destroy: {e}");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn spec(restart: RestartPolicy) -> WorkloadSpec {
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
        // `for_forge` authors `Job`; these fixtures want the archetype the
        // restart policy and volumes infer.
        spec.archetype = None;
        spec.restart_policy = restart;
        spec
    }

    pub(crate) fn body(spec: &WorkloadSpec) -> serde_json::Value {
        serde_json::to_value(spec).unwrap()
    }

    pub(crate) fn named_volume(name: &str) -> workload_spec::VolumeMount {
        workload_spec::VolumeMount {
            source: workload_spec::VolumeSource::Named { name: name.into() },
            target: format!("/{name}").into(),
            read_only: false,
            from_secret_mount: false,
        }
    }

    #[test]
    fn movable_follows_stateful_named_volumes_and_archetype() {
        let none = spec(RestartPolicy::Always);
        assert!(is_movable(&none));

        let mut disposable = spec(RestartPolicy::Always);
        disposable.volumes.push(named_volume("scratch"));
        disposable.annotations.insert(
            workload_spec::DISPOSABLE_VOLUMES_ANNOTATION.into(),
            "scratch".into(),
        );
        // A named volume infers Appliance unless the archetype is authored.
        disposable.archetype = Some(LifecycleArchetype::Server);
        assert!(is_movable(&disposable));

        let mut stateful = spec(RestartPolicy::Always);
        stateful.volumes.push(named_volume("data"));
        stateful.archetype = Some(LifecycleArchetype::Server);
        assert!(!is_movable(&stateful));

        let mut appliance = spec(RestartPolicy::Always);
        appliance.archetype = Some(LifecycleArchetype::Appliance);
        assert!(!is_movable(&appliance));
    }

    #[test]
    fn only_long_running_operator_deploys_get_an_intent() {
        let server = spec(RestartPolicy::Always);
        assert!(intent_candidate(&body(&server), None, DeployOrigin::Api).is_some());
        // A floater's local placement belongs to the floater map.
        assert!(intent_candidate(&body(&server), None, DeployOrigin::Floater).is_none());
        // Forge records (as built: authored `Job`, `Never`) and other run-once steps.
        let forge = WorkloadSpec::for_forge(
            "b1",
            spec(RestartPolicy::Never).image,
            workload_spec::TierTag("infra".into()),
            vec![],
        );
        assert!(intent_candidate(&body(&forge), None, DeployOrigin::Api).is_none());
        let job = spec(RestartPolicy::Never);
        assert!(intent_candidate(&body(&job), None, DeployOrigin::Api).is_none());
        // A run-once spec with a named volume infers Appliance, not Job; the
        // restart half of the rule still excludes it.
        let mut job_with_volume = spec(RestartPolicy::Never);
        job_with_volume.volumes.push(named_volume("cache"));
        assert_eq!(job_with_volume.effective_archetype(), LifecycleArchetype::Appliance);
        assert!(intent_candidate(&body(&job_with_volume), None, DeployOrigin::Api).is_none());
        // Explicit Job archetype with a restarting policy.
        let mut explicit_job = spec(RestartPolicy::Always);
        explicit_job.archetype = Some(LifecycleArchetype::Job);
        assert!(intent_candidate(&body(&explicit_job), None, DeployOrigin::Api).is_none());
    }

    #[test]
    fn the_placement_node_is_the_name_rejoin_cleanup_compares() {
        assert_eq!(this_machine(), crate::leader::derive_machine_name());
    }

    #[tokio::test]
    async fn the_gate_fails_closed_on_an_unreachable_voter() {
        let http = yubaba_auth_token::PeerClient::new(
            reqwest::Client::new(),
            yubaba_auth_token::PeerSigner::unsigned(),
        );
        // Port 1 on loopback: refused immediately. Voter 3 has no address.
        let advertised = probe_member_protocols(
            &http,
            vec![(2, Some("http://127.0.0.1:1".into())), (3, None)],
        )
        .await;
        assert_eq!(advertised.get(&2), Some(&None));
        assert_eq!(advertised.get(&3), Some(&None));
        let mut all = advertised.clone();
        all.insert(1, Some(crate::cluster_epoch::CLUSTER_PROTOCOL));
        let voters = BTreeSet::from([1, 2, 3]);
        assert!(!workload_intent_writes_open(
            &voters,
            &all,
            crate::cluster_epoch::WORKLOAD_INTENT_MIN_PROTOCOL
        ));
    }

    // ── Deploy-path tests against a real one-voter raft ──────────────────────

    async fn single_node() -> (tempfile::TempDir, Arc<ServerState>) {
        let tmp = tempfile::TempDir::new().unwrap();
        let policy = crate::cluster_policy::ClusterPolicy::rig();
        let (raft, sm) = raft::open_with_state_machine(
            1,
            tmp.path().join("raft"),
            &policy,
            yubaba_auth_token::PeerSigner::unsigned(),
        )
        .await
        .expect("open a single-node raft");
        raft::bootstrap_single_node(&raft, 1, "127.0.0.1:0")
            .await
            .expect("found a cluster of one");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while raft.metrics().borrow_watched().current_leader != Some(1) {
            assert!(std::time::Instant::now() < deadline, "never elected itself");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let state = ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_node_id(1)
            .with_raft(raft)
            .with_cluster_state(sm);
        (tmp, Arc::new(state))
    }

    fn deploy_body(spec: &WorkloadSpec) -> WorkloadDeployBody {
        serde_json::from_value(serde_json::json!({ "spec": body(spec) })).unwrap()
    }

    fn intent_of(s: &ServerState, ident: &str) -> Option<WorkloadIntent> {
        let key = raft::WorkloadKey(ident.to_string());
        s.cluster_state
            .as_ref()
            .unwrap()
            .with_state(|st| st.workload_intent.get(&key).cloned())
    }

    async fn deploy(s: &Arc<ServerState>, spec: &WorkloadSpec, gate_open: bool) -> Response {
        let req = deploy_body(spec);
        let candidate = intent_candidate(&req.spec, None, DeployOrigin::Api);
        deploy_recording_intent(
            Arc::clone(s),
            req,
            DeployOrigin::Api,
            candidate,
            gate_open,
            Some("node-a".into()),
        )
        .await
    }

    fn ident(spec: &WorkloadSpec) -> String {
        spec.expose.mesh.identity.0.clone()
    }

    #[test]
    fn a_silent_member_reads_as_its_last_advertised_protocol() {
        let mut latch = BTreeMap::new();
        // Never answered: stays unknown, so the gate stays closed on it.
        let m = latch_merge(&mut latch, BTreeMap::from([(1, Some(9)), (3, None)]));
        assert_eq!(m, BTreeMap::from([(1, Some(9)), (3, None)]));
        // Answers once, then goes dark (R977-T8 run 1): its last answer stands.
        latch_merge(&mut latch, BTreeMap::from([(3, Some(9))]));
        let m = latch_merge(&mut latch, BTreeMap::from([(1, Some(9)), (3, None)]));
        assert_eq!(m, BTreeMap::from([(1, Some(9)), (3, Some(9))]));
        assert!(workload_intent_writes_open(&BTreeSet::from([1, 3]), &m, 9));
        // An answer overwrites, downwards too: what a node says now wins.
        let m = latch_merge(&mut latch, BTreeMap::from([(3, Some(7))]));
        assert_eq!(m[&3], Some(7));
        assert_eq!(latch_merge(&mut latch, BTreeMap::from([(3, None)]))[&3], Some(7));
    }

    #[tokio::test]
    async fn the_live_gate_is_open_on_a_cluster_of_one_at_this_build() {
        let (_tmp, s) = single_node().await;
        assert!(workload_intent_writes_open_live(&s).await);
        let (_tmp2, bare) = {
            let tmp = tempfile::TempDir::new().unwrap();
            let st = ServerState::load(tmp.path().join("identity.json")).unwrap();
            (tmp, st)
        };
        assert!(!workload_intent_writes_open_live(&bare).await, "no raft = closed");
    }

    #[tokio::test]
    async fn gate_open_deploy_records_intent_with_movable_per_volume_rule() {
        let (_tmp, s) = single_node().await;
        let cases: Vec<(&str, WorkloadSpec, bool)> = {
            let mut none = spec(RestartPolicy::Always);
            none.expose.mesh.identity.0 = "no-volumes".into();

            let mut disposable = spec(RestartPolicy::Always);
            disposable.expose.mesh.identity.0 = "disposable-only".into();
            disposable.volumes.push(named_volume("scratch"));
            disposable.annotations.insert(
                workload_spec::DISPOSABLE_VOLUMES_ANNOTATION.into(),
                "scratch".into(),
            );
            disposable.archetype = Some(LifecycleArchetype::Server);

            let mut stateful = spec(RestartPolicy::Always);
            stateful.expose.mesh.identity.0 = "stateful-named".into();
            stateful.volumes.push(named_volume("data"));
            stateful.archetype = Some(LifecycleArchetype::Server);

            let mut appliance = spec(RestartPolicy::Always);
            appliance.expose.mesh.identity.0 = "appliance".into();
            appliance.archetype = Some(LifecycleArchetype::Appliance);

            vec![
                ("no volumes", none, true),
                ("disposable only", disposable, true),
                ("stateful named", stateful, false),
                ("appliance", appliance, false),
            ]
        };
        for (label, spec, movable) in cases {
            let resp = deploy(&s, &spec, true).await;
            assert!(resp.status().is_success(), "{label}: {}", resp.status());
            let intent = intent_of(&s, &ident(&spec)).unwrap_or_else(|| panic!("{label}: no intent"));
            assert_eq!(intent.movable, movable, "{label}");
            assert_eq!(intent.replicas, spec.replicas, "{label}");
            assert_eq!(
                intent.placements.get(&0),
                Some(&ReplicaPlacement { node: "node-a".into(), epoch: 1 }),
                "{label}"
            );
            let recorded: WorkloadSpec = serde_json::from_str(&intent.spec_json).unwrap();
            assert_eq!(ident(&recorded), ident(&spec), "{label}: spec verbatim");
        }
    }

    #[tokio::test]
    async fn gate_closed_deploy_writes_no_intent() {
        let (_tmp, s) = single_node().await;
        let spec = spec(RestartPolicy::Always);
        let resp = deploy(&s, &spec, false).await;
        assert!(resp.status().is_success());
        assert!(intent_of(&s, &ident(&spec)).is_none());
    }

    #[tokio::test]
    async fn a_job_deploy_writes_no_intent_even_with_the_gate_open() {
        let (_tmp, s) = single_node().await;
        let job = spec(RestartPolicy::Never);
        assert!(deploy(&s, &job, true).await.status().is_success());
        assert!(intent_of(&s, &ident(&job)).is_none());
    }

    #[tokio::test]
    async fn operator_destroy_drops_the_intent() {
        let (_tmp, s) = single_node().await;
        let spec = spec(RestartPolicy::Always);
        assert!(deploy(&s, &spec, true).await.status().is_success());
        assert!(intent_of(&s, &ident(&spec)).is_some());
        let _ = crate::destroy_workload_as(Arc::clone(&s), ident(&spec), DeployOrigin::Api)
            .await;
        assert!(intent_of(&s, &ident(&spec)).is_none());
    }

    #[tokio::test]
    async fn a_floater_destroy_leaves_the_intent() {
        let (_tmp, s) = single_node().await;
        let spec = spec(RestartPolicy::Always);
        assert!(deploy(&s, &spec, true).await.status().is_success());
        let _ =
            crate::destroy_workload_as(Arc::clone(&s), ident(&spec), DeployOrigin::Floater)
                .await;
        assert!(intent_of(&s, &ident(&spec)).is_some());
    }

    #[tokio::test]
    async fn a_failed_first_deploy_drops_the_intent_it_created_but_a_failed_redeploy_keeps_it() {
        let (_tmp, s) = single_node().await;
        let spec = spec(RestartPolicy::Always);
        {
            // Hold the per-ident deploy lock: placement answers 409.
            let _held = ServerState::try_lock_deploy(&s, &ident(&spec)).unwrap();
            let resp = deploy(&s, &spec, true).await;
            assert!(!resp.status().is_success());
        }
        assert!(intent_of(&s, &ident(&spec)).is_none(), "no intent naming a node with no copy");

        assert!(deploy(&s, &spec, true).await.status().is_success());
        {
            let _held = ServerState::try_lock_deploy(&s, &ident(&spec)).unwrap();
            assert!(!deploy(&s, &spec, true).await.status().is_success());
        }
        assert!(intent_of(&s, &ident(&spec)).is_some(), "a failed redeploy keeps the intent");
    }

    #[tokio::test]
    async fn the_intent_records_the_deploys_camp_attribution() {
        let (_tmp, s) = single_node().await;
        let spec = spec(RestartPolicy::Always);
        let req: WorkloadDeployBody = serde_json::from_value(serde_json::json!({
            "spec": body(&spec),
            "requesting_camp_id": "camp:C-abc",
            "on_behalf_of_user": "user:U-1",
        }))
        .unwrap();
        let candidate = intent_candidate(&req.spec, None, DeployOrigin::Api);
        let resp = deploy_recording_intent(
            Arc::clone(&s),
            req,
            DeployOrigin::Api,
            candidate,
            true,
            Some("node-a".into()),
        )
        .await;
        assert!(resp.status().is_success(), "{}", resp.status());
        let intent = intent_of(&s, &ident(&spec)).unwrap();
        assert_eq!(intent.requesting_camp_id.as_deref(), Some("camp:C-abc"));
        assert_eq!(intent.on_behalf_of_user.as_deref(), Some("user:U-1"));
    }
}
