//! R997-B27: bind node-to-node writes and raft RPC to the node that sent them.
//!
//! The cluster key admits a caller to the peer routes; its node proof
//! ([`crate::http_auth::NodeProof`]) says which node it is. This module holds
//! the rule each request must then satisfy for that caller. W376 §2.2 carries
//! the table and the reasoning behind each row.
//!
//! The invariant: a peer may write only what its own node could legitimately
//! originate. A write that names a node must name the caller; a write a node
//! relays for an operator needs a voter; a write only the leader's own loops
//! make is never accepted from a peer; and a raft RPC must claim its sender.

use std::collections::{BTreeMap, BTreeSet};

use axum::http::StatusCode;
use openraft::async_runtime::watch::WatchReceiver;
use yubaba_auth_token::node_identity::{IdentityKind, ProvenCaller};

use crate::http_auth::{NodeProof, Tier};
use crate::raft::{self, YubabaNodeId, YubabaRequest};

/// A refusal to send back: status plus a reason.
pub type Refusal = (StatusCode, String);

/// The receiver's view of who each node is.
#[derive(Clone, Debug, Default)]
pub struct ClusterView {
    pub voters: BTreeSet<YubabaNodeId>,
    pub learners: BTreeSet<YubabaNodeId>,
    /// Each member row's machine name.
    pub machines: BTreeMap<YubabaNodeId, String>,
}

impl ClusterView {
    /// Read the effective membership off `raft` and machine names off `sm`.
    pub fn from_raft(raft: &raft::YubabaRaft, sm: Option<&raft::YubabaStateMachine>) -> Self {
        let membership = raft
            .metrics()
            .borrow_watched()
            .membership_config
            .membership()
            .clone();
        let machines = sm
            .map(|sm| {
                sm.members()
                    .into_iter()
                    .filter_map(|(id, m)| m.machine.map(|machine| (id, machine)))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            voters: membership.voter_ids().collect(),
            learners: membership.learner_ids().collect(),
            machines,
        }
    }

    fn is_voter(&self, id: YubabaNodeId) -> bool {
        self.voters.contains(&id)
    }

    fn is_member(&self, id: YubabaNodeId) -> bool {
        self.voters.contains(&id) || self.learners.contains(&id)
    }
}

/// What a peer must be to make one write.
#[derive(Debug, PartialEq, Eq)]
enum PeerRule<'a> {
    /// The write names a node, which must be the caller.
    SelfNode(YubabaNodeId),
    /// The write names a machine, which must be the caller's (or its id).
    SelfMachine(&'a str),
    /// The write names a lock owner, which must be the caller's id.
    SelfOwner(&'a str),
    /// A node relays this for an operator it authenticated: voters only.
    Voter,
    /// Operator-signed content: any member may relay it if the signature
    /// verifies under this node's operator keys.
    MemberSigned { spec_json: &'a str, sig: &'a str },
    /// Only the leader's own loops write this, locally.
    LeaderLocal,
    /// No node writes this.
    OperatorOnly,
}

impl PeerRule<'_> {
    fn refusal(&self) -> &'static str {
        match self {
            Self::SelfNode(_) | Self::SelfMachine(_) | Self::SelfOwner(_) => {
                "this write must name the calling node"
            }
            Self::Voter => "only a voter may relay this write",
            Self::MemberSigned { .. } => "the operator signature does not verify here",
            Self::LeaderLocal => "this write is made only by the leader itself",
            Self::OperatorOnly => "only an operator may make this write",
        }
    }
}

/// The rule for each variant. Exhaustive on purpose: a new variant must pick
/// one before it compiles.
fn peer_rule(request: &YubabaRequest) -> PeerRule<'_> {
    use YubabaRequest as R;
    match request {
        R::SetMember { node_id, .. } => PeerRule::SelfNode(*node_id),
        R::ClaimTenant { node, .. } | R::RenewTenantLease { node, .. } => PeerRule::SelfNode(*node),
        R::ReportPeerLiveness { observer, .. } => PeerRule::SelfNode(*observer),
        R::ReportNodeHealth { node, .. } => PeerRule::SelfMachine(node),
        R::AcquireLock { owner, .. } | R::ReleaseLock { owner, .. } => PeerRule::SelfOwner(owner),
        R::SetRolloutState { .. }
        | R::RecordMembershipRatchet { .. }
        | R::PutWorkloadIntent { .. }
        | R::DropWorkloadIntent { .. }
        | R::RemoveMember { .. }
        | R::SetTenantPlacement { .. } => PeerRule::Voter,
        R::AttestWorkloadIntent {
            spec_json,
            operator_sig,
            ..
        } => PeerRule::MemberSigned {
            spec_json,
            sig: operator_sig,
        },
        R::TransferTenant { .. }
        | R::MoveWorkloadReplica { .. }
        | R::ClaimIngressOwner { .. }
        | R::ClearIngressOwner
        | R::ClearRolloutState { .. } => PeerRule::LeaderLocal,
        R::SetIngressOwner { .. }
        | R::SetServicePlacement { .. }
        | R::ClearServicePlacement { .. }
        | R::ClearTenantPlacement { .. }
        | R::PutSecret { .. }
        | R::DeleteSecret { .. } => PeerRule::OperatorOnly,
    }
}

fn forbidden(why: impl Into<String>) -> Refusal {
    (StatusCode::FORBIDDEN, why.into())
}

/// The proven caller to bind, `Ok(None)` for an unproven caller tolerated in
/// warn mode, or the refusal.
fn proven_caller(
    proof: &NodeProof,
    required: bool,
    route: &str,
) -> Result<Option<ProvenCaller>, Refusal> {
    match proof {
        NodeProof::Proven(caller) => Ok(Some(*caller)),
        NodeProof::Invalid(why) => {
            tracing::warn!(route, reason = %why, "refusing a request with an invalid node proof");
            Err((StatusCode::UNAUTHORIZED, "invalid node proof".to_string()))
        }
        NodeProof::Absent if required => {
            Err((StatusCode::UNAUTHORIZED, "node proof required".to_string()))
        }
        NodeProof::Absent => {
            tracing::warn!(
                route,
                "node-to-node request served without a node proof (node identity mode is warn)"
            );
            Ok(None)
        }
    }
}

/// Authorize a `/raft/write` (R997-B27). An operator may write any variant
/// (the secret variants are refused before this is asked). A peer is bound to
/// the node its proof names, per [`peer_rule`], and must be a member here.
pub fn authorize_raft_write(
    tier: Option<Tier>,
    proof: &NodeProof,
    required: bool,
    request: &YubabaRequest,
    view: &ClusterView,
    operator_keys: &[[u8; 32]],
) -> Result<(), Refusal> {
    if tier == Some(Tier::Operator) {
        return Ok(());
    }
    let Some(caller) = proven_caller(proof, required, "/raft/write")? else {
        return Ok(());
    };
    if caller.kind != IdentityKind::Node {
        return Err(forbidden(format!(
            "a {} identity may not write cluster state",
            caller.kind
        )));
    }
    let me = caller.node_id;
    if !view.is_member(me) {
        return Err(forbidden(format!("node {me} is not a raft member here")));
    }
    let rule = peer_rule(request);
    let allowed = match &rule {
        PeerRule::SelfNode(named) => *named == me,
        PeerRule::SelfMachine(machine) => {
            view.machines.get(&me).is_some_and(|mine| mine == machine) || *machine == me.to_string()
        }
        PeerRule::SelfOwner(owner) => *owner == me.to_string(),
        PeerRule::Voter => view.is_voter(me),
        PeerRule::MemberSigned { spec_json, sig } => {
            serde_json::from_str::<serde_json::Value>(spec_json).is_ok_and(|spec| {
                yubaba_auth_token::delegation::verify_workload_spec(operator_keys, &spec, sig)
                    .is_ok()
            })
        }
        PeerRule::LeaderLocal | PeerRule::OperatorOnly => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(forbidden(format!("node {me}: {}", rule.refusal())))
    }
}

/// Authorize a `/tenant-lease` write (R997-B27): the lease must be held for
/// the node the caller's identity is certified for. A tenant-streamer
/// identity serves exactly this route.
pub fn authorize_tenant_lease(
    tier: Option<Tier>,
    proof: &NodeProof,
    required: bool,
    request: &YubabaRequest,
) -> Result<(), Refusal> {
    if tier == Some(Tier::Operator) {
        return Ok(());
    }
    let Some(caller) = proven_caller(proof, required, crate::TENANT_LEASE_PATH)? else {
        return Ok(());
    };
    let named = match request {
        YubabaRequest::ClaimTenant { node, .. } | YubabaRequest::RenewTenantLease { node, .. } => {
            *node
        }
        _ => return Err(forbidden("only tenant leases are accepted on this route")),
    };
    if named == caller.node_id {
        Ok(())
    } else {
        Err(forbidden(format!(
            "{} {}: a tenant lease must be held for the certified node",
            caller.kind, caller.node_id
        )))
    }
}

/// Authorize a raft RPC whose payload claims `claimed` as its leader or
/// candidate (R997-B27). The proof must name that node; in require mode it
/// must also be a voter in this node's membership, when that is known.
pub fn authorize_raft_rpc(
    proof: &NodeProof,
    required: bool,
    route: &str,
    claimed: YubabaNodeId,
    view: &ClusterView,
) -> Result<(), Refusal> {
    let Some(caller) = proven_caller(proof, required, route)? else {
        return Ok(());
    };
    if caller.kind != IdentityKind::Node {
        return Err(forbidden(format!(
            "a {} identity may not speak raft",
            caller.kind
        )));
    }
    if caller.node_id != claimed {
        return Err(forbidden(format!(
            "node {} may not speak raft as node {claimed}",
            caller.node_id
        )));
    }
    if required && !view.voters.is_empty() && !view.is_voter(claimed) {
        return Err(forbidden(format!(
            "node {claimed} is not a voter here, so it may not lead or campaign"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::{NodeHealthVerdict, PeerLivenessVerdict};

    fn req(v: serde_json::Value) -> YubabaRequest {
        serde_json::from_value(v).unwrap()
    }

    const VOTER: YubabaNodeId = 1;
    const OTHER_VOTER: YubabaNodeId = 2;
    const LEARNER: YubabaNodeId = 4;

    fn view() -> ClusterView {
        ClusterView {
            voters: [VOTER, OTHER_VOTER, 3].into(),
            learners: [LEARNER].into(),
            machines: [
                (VOTER, "us-west-011".to_string()),
                (LEARNER, "us-west-004".to_string()),
            ]
            .into(),
        }
    }

    fn node(id: YubabaNodeId) -> NodeProof {
        NodeProof::Proven(ProvenCaller {
            kind: IdentityKind::Node,
            node_id: id,
        })
    }

    fn streamer(id: YubabaNodeId) -> NodeProof {
        NodeProof::Proven(ProvenCaller {
            kind: IdentityKind::TenantStreamer,
            node_id: id,
        })
    }

    fn write(proof: &NodeProof, request: &YubabaRequest) -> Result<(), Refusal> {
        authorize_raft_write(Some(Tier::Peer), proof, true, request, &view(), &[])
    }

    fn set_member(node_id: YubabaNodeId) -> YubabaRequest {
        serde_json::from_value(serde_json::json!({
            "SetMember": { "node_id": node_id, "addr": "10.0.0.9:7443" }
        }))
        .unwrap()
    }

    fn claim(node: YubabaNodeId) -> YubabaRequest {
        req(
            serde_json::json!({"ClaimTenant": {"tenant": "acme", "node": node, "lease_secs": 30, "now": 1}}),
        )
    }

    fn renew(node: YubabaNodeId) -> YubabaRequest {
        req(
            serde_json::json!({"RenewTenantLease": {"tenant": "acme", "node": node, "epoch": 1, "lease_secs": 30, "now": 1}}),
        )
    }

    fn denied(r: Result<(), Refusal>) -> bool {
        matches!(r, Err((StatusCode::FORBIDDEN, _)))
    }

    #[test]
    fn a_peer_cannot_set_another_nodes_member_row() {
        assert!(denied(write(&node(LEARNER), &set_member(VOTER))));
        assert!(denied(write(&node(VOTER), &set_member(OTHER_VOTER))));
        assert!(write(&node(LEARNER), &set_member(LEARNER)).is_ok());
    }

    #[test]
    fn a_peer_cannot_claim_or_renew_a_tenant_under_another_nodes_id() {
        assert!(denied(write(&node(LEARNER), &claim(VOTER))));
        assert!(denied(write(&node(LEARNER), &renew(VOTER))));
        assert!(write(&node(LEARNER), &claim(LEARNER)).is_ok());
    }

    #[test]
    fn a_non_member_or_a_streamer_identity_writes_nothing() {
        assert!(denied(write(&node(77), &set_member(77))));
        assert!(denied(write(&streamer(LEARNER), &claim(LEARNER))));
    }

    #[test]
    fn traffic_and_leader_writes_are_refused_to_every_peer() {
        let refused: Vec<YubabaRequest> = vec![
            YubabaRequest::SetIngressOwner {
                machine: "us-west-004".into(),
            },
            YubabaRequest::SetServicePlacement {
                service: "web".into(),
                machine: "us-west-004".into(),
            },
            YubabaRequest::ClaimIngressOwner { node_id: VOTER },
            req(
                serde_json::json!({"TransferTenant": {"tenant": "acme", "to": VOTER, "from_epoch": 1, "lease_secs": 30, "now": 1}}),
            ),
            req(serde_json::json!({"ClearTenantPlacement": {"tenant": "acme"}})),
        ];
        for request in &refused {
            assert!(denied(write(&node(VOTER), request)), "{request:?}");
            assert!(denied(write(&node(LEARNER), request)), "{request:?}");
        }
    }

    #[test]
    fn relayed_operator_writes_need_a_voter() {
        let drop = req(serde_json::json!({"DropWorkloadIntent": {"key": "web"}}));
        assert!(denied(write(&node(LEARNER), &drop)));
        assert!(write(&node(VOTER), &drop).is_ok());
        let remove = YubabaRequest::RemoveMember {
            node_id: OTHER_VOTER,
        };
        assert!(denied(write(&node(LEARNER), &remove)));
        assert!(write(&node(VOTER), &remove).is_ok());
    }

    /// Every forwarder in R997-B11's census, as its caller actually sends it.
    #[test]
    fn each_census_forwarder_still_passes() {
        let ok = |caller: YubabaNodeId, request: YubabaRequest| {
            let r = write(&node(caller), &request);
            assert!(r.is_ok(), "{request:?} from {caller}: {r:?}");
        };
        // member_registration: its own row.
        ok(LEARNER, set_member(LEARNER));
        // floater admission + effector: claim and renew for `me`.
        ok(LEARNER, claim(LEARNER));
        ok(VOTER, renew(VOTER));
        // acme_issuer: the lock owner is `node_id.to_string()`.
        ok(
            VOTER,
            YubabaRequest::AcquireLock {
                key: "acme".into(),
                owner: VOTER.to_string(),
                ttl_secs: 60,
                acquired_at: 1,
            },
        );
        // boot-health: the node's own machine; peer-liveness: its own id.
        ok(
            LEARNER,
            YubabaRequest::ReportNodeHealth {
                rollout_id: "r1".into(),
                node: "us-west-004".into(),
                verdict: NodeHealthVerdict::Good,
                detail: String::new(),
                reported_at: 1,
            },
        );
        ok(
            LEARNER,
            YubabaRequest::ReportPeerLiveness {
                observer: LEARNER,
                subject: VOTER,
                verdict: PeerLivenessVerdict::Dark,
                detail: String::new(),
                observed_at: 1,
            },
        );
        // Relayed by a voter: deploy/destroy, remove-member, rollout CAS,
        // floater placement demand, and the ratchet record.
        for request in [
            serde_json::json!({"DropWorkloadIntent": {"key": "web"}}),
            serde_json::json!({"RemoveMember": {"node_id": 3}}),
            serde_json::json!({"SetTenantPlacement": {"tenant": "acme", "placement": {
                "region": null, "tier": "cold_hydrate",
                "demand": {"memory_mb": 1, "cpu_millis": 1}, "rpo_bound": null}}}),
        ] {
            ok(VOTER, req(request));
        }
    }

    #[test]
    fn a_machine_bound_write_must_name_the_callers_machine() {
        let health = |machine: &str| YubabaRequest::ReportNodeHealth {
            rollout_id: "r1".into(),
            node: machine.into(),
            verdict: NodeHealthVerdict::Good,
            detail: String::new(),
            reported_at: 1,
        };
        assert!(denied(write(&node(LEARNER), &health("us-west-011"))));
        assert!(write(&node(VOTER), &health("us-west-011")).is_ok());
    }

    #[test]
    fn an_operator_writes_anything_and_warn_mode_tolerates_an_unproven_peer() {
        let ingress = YubabaRequest::SetIngressOwner {
            machine: "us-west-011".into(),
        };
        assert!(authorize_raft_write(
            Some(Tier::Operator),
            &NodeProof::Absent,
            true,
            &ingress,
            &view(),
            &[]
        )
        .is_ok());
        assert!(authorize_raft_write(
            Some(Tier::Peer),
            &NodeProof::Absent,
            false,
            &ingress,
            &view(),
            &[]
        )
        .is_ok());
        assert_eq!(
            authorize_raft_write(
                Some(Tier::Peer),
                &NodeProof::Absent,
                true,
                &ingress,
                &view(),
                &[]
            )
            .unwrap_err()
            .0,
            StatusCode::UNAUTHORIZED
        );
        // A presented proof is enforced even in warn mode.
        assert!(denied(authorize_raft_write(
            Some(Tier::Peer),
            &node(LEARNER),
            false,
            &ingress,
            &view(),
            &[]
        )));
        assert_eq!(
            authorize_raft_write(
                Some(Tier::Peer),
                &NodeProof::Invalid("x".into()),
                false,
                &ingress,
                &view(),
                &[]
            )
            .unwrap_err()
            .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn a_tenant_lease_binds_to_the_certified_node() {
        let lease = |proof: &NodeProof, request: &YubabaRequest| {
            authorize_tenant_lease(Some(Tier::Service), proof, true, request)
        };
        assert!(lease(&streamer(LEARNER), &renew(LEARNER)).is_ok());
        assert!(lease(&streamer(LEARNER), &claim(LEARNER)).is_ok());
        assert!(denied(lease(&streamer(LEARNER), &claim(VOTER))));
        assert!(denied(lease(&streamer(LEARNER), &renew(VOTER))));
        assert_eq!(
            lease(&NodeProof::Absent, &renew(LEARNER)).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn a_raft_rpc_must_claim_its_sender_and_a_voter() {
        let rpc = |proof: &NodeProof, claimed| {
            authorize_raft_rpc(proof, true, "/raft/append-entries", claimed, &view())
        };
        assert!(rpc(&node(VOTER), VOTER).is_ok());
        assert!(denied(rpc(&node(LEARNER), VOTER)));
        assert!(denied(rpc(&node(LEARNER), LEARNER)));
        assert!(denied(rpc(&streamer(VOTER), VOTER)));
        // A receiver that knows no membership yet binds only the claim.
        assert!(authorize_raft_rpc(
            &node(LEARNER),
            true,
            "/raft/vote",
            LEARNER,
            &ClusterView::default()
        )
        .is_ok());
    }
}

/// R997-B27 through the real router: a node enforcing node proofs, driven by
/// requests built exactly as a node's own `PeerClient` sends them.
#[cfg(test)]
mod router_tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use openraft::async_runtime::watch::WatchReceiver;
    use pasetors::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
    use pasetors::version4::V4;
    use serde_json::json;
    use tower::ServiceExt;
    use yubaba_auth_token::delegation::OperatorSecretKey;
    use yubaba_auth_token::node_identity::{IdentityKind, NodeIdentity};
    use yubaba_auth_token::{PeerClient, PeerSigner};

    use crate::http_auth::{AuthMode, HttpAuthPolicy, NodeIdentityMode};
    use crate::{raft, ServerState};

    struct Node {
        _tmp: tempfile::TempDir,
        state: Arc<ServerState>,
        operator: OperatorSecretKey,
        cluster_hex: String,
    }

    /// A single-voter cluster (node 1) in node identity mode `require`.
    async fn enforcing_node() -> Node {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let cluster_hex =
            yubaba_auth_token::encode_hex(SymmetricKey::<V4>::generate().unwrap().as_bytes());
        let own = NodeIdentity::mint(&kp.secret, IdentityKind::Node, 1).unwrap();
        let policy = HttpAuthPolicy::new(
            AuthMode::Require,
            &[yubaba_auth_token::encode_hex(kp.public.as_bytes())],
            Some(&cluster_hex),
        )
        .unwrap()
        .with_node_identity(Some(own), NodeIdentityMode::Require)
        .unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let (raft, sm) = raft::open_with_state_machine(
            1,
            tmp.path().join("raft"),
            &crate::cluster_policy::ClusterPolicy::rig(),
            PeerSigner::unsigned(),
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
            .with_http_auth(policy);
        Node {
            _tmp: tmp,
            state: Arc::new(state),
            operator: kp.secret,
            cluster_hex,
        }
    }

    impl Node {
        fn bearer(&self, id: u64) -> PeerSigner {
            let key = yubaba_auth_token::cluster_key_from_hex(&self.cluster_hex).unwrap();
            PeerSigner::for_cluster_key(key, format!("node:{id}"))
        }

        /// `body` POSTed to `path` as identity `kind` `id` sends it.
        fn as_node(
            &self,
            id: u64,
            kind: IdentityKind,
            path: &str,
            body: &serde_json::Value,
        ) -> Request<Body> {
            let identity = Arc::new(NodeIdentity::mint(&self.operator, kind, id).unwrap());
            let signer = self.bearer(id).with_node_identity(Some(identity));
            let sent = PeerClient::new(reqwest::Client::new(), signer)
                .post_json_proved(&format!("http://10.0.0.1:7443{path}"), body)
                .unwrap()
                .build()
                .unwrap();
            let mut out = Request::post(path);
            for (name, value) in sent.headers() {
                out = out.header(name.as_str(), value.as_bytes());
            }
            out.body(Body::from(
                sent.body().unwrap().as_bytes().unwrap().to_vec(),
            ))
            .unwrap()
        }

        async fn status(&self, req: Request<Body>) -> StatusCode {
            crate::build_router(Arc::clone(&self.state))
                .oneshot(req)
                .await
                .unwrap()
                .status()
        }
    }

    fn set_member(node_id: u64) -> serde_json::Value {
        json!({"request": {"SetMember": {"node_id": node_id, "addr": "127.0.0.1:0"}}})
    }

    fn claim(node: u64) -> serde_json::Value {
        json!({"request": {"ClaimTenant": {"tenant": "acme", "node": node, "lease_secs": 30, "now": 1}}})
    }

    fn vote(candidate: u64) -> serde_json::Value {
        json!({"vote": {"leader_id": {"term": 9, "node_id": candidate}, "committed": false},
               "last_log_id": null})
    }

    #[test]
    fn a_policy_refuses_an_identity_it_cannot_vouch_for() {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let other = AsymmetricKeyPair::<V4>::generate().unwrap();
        let keyed = || {
            HttpAuthPolicy::new(
                AuthMode::Require,
                &[yubaba_auth_token::encode_hex(kp.public.as_bytes())],
                None,
            )
            .unwrap()
        };
        let foreign = NodeIdentity::mint(&other.secret, IdentityKind::Node, 1).unwrap();
        assert!(keyed()
            .with_node_identity(Some(foreign), NodeIdentityMode::Warn)
            .is_err());
        let streamer = NodeIdentity::mint(&kp.secret, IdentityKind::TenantStreamer, 1).unwrap();
        assert!(keyed()
            .with_node_identity(Some(streamer), NodeIdentityMode::Warn)
            .is_err());
        let unkeyed = HttpAuthPolicy::new(AuthMode::Warn, &[], None).unwrap();
        assert!(unkeyed
            .with_node_identity(None, NodeIdentityMode::Require)
            .is_err());

        let own = NodeIdentity::mint(&kp.secret, IdentityKind::Node, 1).unwrap();
        let policy = keyed()
            .with_node_identity(Some(own), NodeIdentityMode::Warn)
            .unwrap();
        let signer = policy.peer_signer("node:1".into());
        assert_eq!(signer.node_identity().unwrap().cert().node_id, 1);
    }

    #[tokio::test]
    async fn node_1_cannot_set_member_or_claim_a_tenant_for_node_2() {
        let n = enforcing_node().await;
        let node = IdentityKind::Node;
        assert_eq!(
            n.status(n.as_node(1, node, "/raft/write", &set_member(2)))
                .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            n.status(n.as_node(1, node, "/raft/write", &claim(2))).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            n.status(n.as_node(1, node, "/raft/write", &set_member(1)))
                .await,
            StatusCode::OK
        );
        assert_eq!(
            n.status(n.as_node(1, node, "/raft/write", &claim(1))).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn require_mode_refuses_a_missing_or_tampered_proof() {
        let n = enforcing_node().await;
        let bearer = n.bearer(1).bearer().unwrap();
        let bare = Request::post("/raft/write")
            .header("content-type", "application/json")
            .header("authorization", &bearer)
            .body(Body::from(set_member(1).to_string()))
            .unwrap();
        assert_eq!(n.status(bare).await, StatusCode::UNAUTHORIZED);

        // A valid proof for node 1's own row, carried on a different body.
        let signed = n.as_node(1, IdentityKind::Node, "/raft/write", &set_member(1));
        let mut swapped = Request::post("/raft/write");
        for (name, value) in signed.headers() {
            swapped = swapped.header(name, value);
        }
        let swapped = swapped.body(Body::from(set_member(2).to_string())).unwrap();
        assert_eq!(n.status(swapped).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_tenant_lease_route_binds_a_streamer_to_its_certified_node() {
        let n = enforcing_node().await;
        let streamer = IdentityKind::TenantStreamer;
        assert_eq!(
            n.status(n.as_node(1, streamer, crate::TENANT_LEASE_PATH, &claim(2)))
                .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            n.status(n.as_node(1, streamer, crate::TENANT_LEASE_PATH, &claim(1)))
                .await,
            StatusCode::OK
        );
        // ...and it opens nothing else.
        assert_eq!(
            n.status(n.as_node(1, streamer, "/raft/write", &claim(1)))
                .await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn a_raft_rpc_claiming_another_node_is_refused() {
        let n = enforcing_node().await;
        let node = IdentityKind::Node;
        // Signed by node 1, claiming candidate 2.
        assert_eq!(
            n.status(n.as_node(1, node, "/raft/vote", &vote(2))).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            n.status(n.as_node(1, node, "/raft/pre-vote", &vote(2)))
                .await,
            StatusCode::FORBIDDEN
        );
        // Node 2 claiming itself: certified, but not a voter here.
        assert_eq!(
            n.status(n.as_node(2, node, "/raft/pre-vote", &vote(2)))
                .await,
            StatusCode::FORBIDDEN
        );
        // A tenant-streamer identity never speaks raft.
        assert_eq!(
            n.status(n.as_node(1, IdentityKind::TenantStreamer, "/raft/pre-vote", &vote(1)))
                .await,
            StatusCode::FORBIDDEN
        );
        // The voter claiming itself reaches openraft.
        assert_eq!(
            n.status(n.as_node(1, node, "/raft/pre-vote", &vote(1)))
                .await,
            StatusCode::OK
        );
    }
}
