//! Yubaba openraft coordination layer — Phase 2 (R040-F20).
//!
//! Builds on top of [`openraft`] to give the yubaba cluster consensus
//! on:
//! - Cluster membership (who is a yubaba peer, current leader)
//! - Service placement (which machine runs Headscale/Postgres/…)
//! - Distributed locks (in-progress provisions, mesh migrations)
//! - Floating ingress ownership (who currently runs the Headscale tunnel)
//!
//! Transport runs peer-to-peer over Tailscale mesh IPs.  The mesh must
//! already be up (Phase 1a/1b) before raft can form quorum.
//!
//! @yah:relay(R277, "Tier 4 — cluster-mesh-1: single-node raft + WireGuard plane")
//! @yah:at(2026-05-27T02:22:55Z)
//! @yah:status(backlog)
//! @yah:parent(Q273)
//! @yah:next("F1: bring up yubaba raft on a single node (openraft, on-disk storage); storage backend choice (sled vs sqlite) resolved as F1 sub-spike")
//! @yah:next("F2: wireguard0 brought up + a single-node 'mesh' (one node, but the bus is live)")
//! @yah:next("F3: consume xlb-net::Endpoint as yubaba control-plane transport (xlb-net 0.1 published; Open Q2 from xlb-net doc finally gets a consumer)")
//! @yah:next("F4: smoke fixture extending R091-F6 multi-node openraft harness so cluster-mesh-2/3 are file-able as follow-on relays without redesign")
//! @yah:gotcha("Depends on Tier-3 relay landing first (real workload runtime needed to host raft as a workload, or co-located)")
//! @yah:gotcha("R271 'Orbit architecture review for yubaba design' should resolve before F1 so its findings shape the storage-backend pick")
//! @arch:see(.yah/docs/architecture/A032-yah-cluster-mesh.md)
//! @arch:see(.yah/docs/architecture/A026-xlb-net.md)
//! @arch:see(.yah/docs/architecture/A041-yah-mesh-bootstrap.md)
//!
//! @yah:ticket(R278-F3, "Raft mirror metadata for rollout state (degenerate-raft v1)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T02:31:24Z)
//! @yah:status(review)
//! @yah:parent(R278)
//! @yah:next("Add rollout fields to WardenState: rollouts: BTreeMap<String, RolloutRaftRecord>")
//! @yah:next("Add WardenRequest variants: SetRolloutState, ClearRolloutState")
//! @yah:next("In-memory store on ServerState for v1; raft variants defined for forward-compat")
//! @arch:see(.yah/docs/architecture/A032-yah-cluster-mesh.md)
//! @yah:handoff("WardenState.rollouts: BTreeMap<String, RolloutRaftRecord> added. WardenRequest::SetRolloutState + ClearRolloutState variants defined and apply() arms wired. WardenState serialises with #[serde(default)] so old snapshots load cleanly. In-memory RolloutStore on ServerState is the v1 authoritative path; raft variants are forward-compat for when R277 lands.")

pub mod network;
pub mod store;

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;

use openraft::{BasicNode, Config, Raft};
use serde::{Deserialize, Serialize};

pub use network::{WardenNetwork, WardenNetworkFactory};
pub use store::{WardenLogStore, WardenStateMachine};

// ── Type config ──────────────────────────────────────────────────────────────

/// Node IDs are u64, assigned at provisioning time and persisted to the
/// yubaba state file alongside the node's Tailscale mesh IP.
pub type WardenNodeId = u64;

openraft::declare_raft_types!(
    pub WardenRaftConfig:
        D            = WardenRequest,
        R            = WardenResponse,
        NodeId       = WardenNodeId,
        Node         = BasicNode,
        Entry        = openraft::Entry<WardenRaftConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);

/// Concrete Raft type alias for the yubaba cluster.
pub type WardenRaft = Raft<WardenRaftConfig>;

// ── State machine commands ────────────────────────────────────────────────────

/// Mutations that go through raft consensus.
///
/// Callers write to the leader via `POST /raft/write`; the leader fans
/// the entry out via AppendEntries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WardenRequest {
    SetMember {
        node_id: WardenNodeId,
        addr: String,
    },
    RemoveMember {
        node_id: WardenNodeId,
    },
    SetServicePlacement {
        service: String,
        machine: String,
    },
    ClearServicePlacement {
        service: String,
    },
    /// `acquired_at` is unix seconds, filled in by the caller.
    AcquireLock {
        key: String,
        owner: String,
        ttl_secs: u64,
        acquired_at: u64,
    },
    ReleaseLock {
        key: String,
        owner: String,
    },
    SetIngressOwner {
        machine: String,
    },
    ClearIngressOwner,
    // R278-F3: rollout mirror metadata — defined for forward-compat with the
    // raft path; the in-process RolloutStore is the v1 store until R277 lands.
    /// Record that a rollout is in progress so a new leader can resume it.
    SetRolloutState {
        rollout_id: String,
        artifact: String,
        /// JSON-serialised `RolloutStatus`.
        status_json: String,
        current_step: usize,
        started_at: u64,
    },
    /// Remove a completed or aborted rollout from the raft snapshot.
    ClearRolloutState {
        rollout_id: String,
    },
}

/// State machine response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WardenResponse {
    Ok,
    LockGranted(bool),
}

// ── Domain state ──────────────────────────────────────────────────────────────

/// The entire yubaba cluster state.  Serialised as a JSON snapshot;
/// state volume is KB-scale even on large clusters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WardenState {
    pub members: BTreeMap<WardenNodeId, MemberInfo>,
    /// service name → machine name
    pub service_placement: BTreeMap<String, String>,
    pub locks: BTreeMap<String, LockEntry>,
    pub ingress_owner: Option<String>,
    /// R278-F3: in-flight rollout metadata replicated via raft so a new leader
    /// can resume a rollout after leader change. The in-process RolloutStore
    /// (on ServerState) is the authoritative v1 store; this map is updated
    /// alongside it via SetRolloutState / ClearRolloutState WardenRequests.
    #[serde(default)]
    pub rollouts: BTreeMap<String, RolloutRaftRecord>,
}

/// Minimal rollout metadata stored in raft state (R278-F3).
///
/// Contains only what's needed for leader-resume after a raft leader change.
/// The full `RolloutRecord` (including the policy and trigger) lives in the
/// in-process `RolloutStore`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutRaftRecord {
    pub rollout_id: String,
    pub artifact: String,
    /// JSON-serialised `RolloutStatus` (avoids a cross-crate dep on yubaba's
    /// rollout module from the raft module).
    pub status_json: String,
    pub current_step: usize,
    pub started_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    /// Tailscale mesh IP:port (e.g. `100.64.0.1:7443`).
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEntry {
    pub owner: String,
    pub acquired_at: u64,
    pub ttl_secs: u64,
}

/// Apply a [`WardenRequest`] to `state`.  Pure function — all I/O is the
/// caller's responsibility.
pub fn apply(state: &mut WardenState, req: &WardenRequest) -> WardenResponse {
    match req {
        WardenRequest::SetMember { node_id, addr } => {
            state
                .members
                .insert(*node_id, MemberInfo { addr: addr.clone() });
            WardenResponse::Ok
        }
        WardenRequest::RemoveMember { node_id } => {
            state.members.remove(node_id);
            WardenResponse::Ok
        }
        WardenRequest::SetServicePlacement { service, machine } => {
            state
                .service_placement
                .insert(service.clone(), machine.clone());
            WardenResponse::Ok
        }
        WardenRequest::ClearServicePlacement { service } => {
            state.service_placement.remove(service);
            WardenResponse::Ok
        }
        WardenRequest::AcquireLock {
            key,
            owner,
            ttl_secs,
            acquired_at,
        } => {
            let now = *acquired_at;
            let grant = match state.locks.get(key) {
                None => true,
                Some(entry) => {
                    entry.owner == *owner
                        || now.saturating_sub(entry.acquired_at) >= entry.ttl_secs
                }
            };
            if grant {
                state.locks.insert(
                    key.clone(),
                    LockEntry {
                        owner: owner.clone(),
                        acquired_at: *acquired_at,
                        ttl_secs: *ttl_secs,
                    },
                );
            }
            WardenResponse::LockGranted(grant)
        }
        WardenRequest::ReleaseLock { key, owner } => {
            if state.locks.get(key).map(|e| e.owner.as_str()) == Some(owner.as_str()) {
                state.locks.remove(key);
            }
            WardenResponse::Ok
        }
        WardenRequest::SetIngressOwner { machine } => {
            state.ingress_owner = Some(machine.clone());
            WardenResponse::Ok
        }
        WardenRequest::ClearIngressOwner => {
            state.ingress_owner = None;
            WardenResponse::Ok
        }
        WardenRequest::SetRolloutState {
            rollout_id,
            artifact,
            status_json,
            current_step,
            started_at,
        } => {
            state.rollouts.insert(
                rollout_id.clone(),
                RolloutRaftRecord {
                    rollout_id: rollout_id.clone(),
                    artifact: artifact.clone(),
                    status_json: status_json.clone(),
                    current_step: *current_step,
                    started_at: *started_at,
                },
            );
            WardenResponse::Ok
        }
        WardenRequest::ClearRolloutState { rollout_id } => {
            state.rollouts.remove(rollout_id);
            WardenResponse::Ok
        }
    }
}

// ── Node factory ──────────────────────────────────────────────────────────────

/// Open (or create) a yubaba raft node.
///
/// `node_id`  — this machine's unique yubaba node ID (u64, assigned at provision time).
/// `raft_dir` — directory for raft persistence files (`raft_vote.json`, `raft_log.json`, `raft_state.json`).
pub async fn open(node_id: WardenNodeId, raft_dir: PathBuf) -> anyhow::Result<WardenRaft> {
    std::fs::create_dir_all(&raft_dir)?;

    let config = Arc::new(
        Config {
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            ..Default::default()
        }
        .validate()?,
    );

    let log_store = WardenLogStore::open(raft_dir.clone()).await?;
    let state_machine = WardenStateMachine::open(raft_dir).await?;
    let network = WardenNetworkFactory;

    let raft = WardenRaft::new(node_id, config, network, log_store, state_machine).await?;
    Ok(raft)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_set_member() {
        let mut state = WardenState::default();
        apply(
            &mut state,
            &WardenRequest::SetMember {
                node_id: 1,
                addr: "100.64.0.1:7443".into(),
            },
        );
        assert!(state.members.contains_key(&1));
    }

    #[test]
    fn apply_lock_grant_and_release() {
        let mut state = WardenState::default();
        let resp = apply(
            &mut state,
            &WardenRequest::AcquireLock {
                key: "provision:foo".into(),
                owner: "node-1".into(),
                ttl_secs: 60,
                acquired_at: 1000,
            },
        );
        assert!(matches!(resp, WardenResponse::LockGranted(true)));

        // Second acquire by different owner before TTL should fail.
        let resp2 = apply(
            &mut state,
            &WardenRequest::AcquireLock {
                key: "provision:foo".into(),
                owner: "node-2".into(),
                ttl_secs: 60,
                acquired_at: 1010,
            },
        );
        assert!(matches!(resp2, WardenResponse::LockGranted(false)));

        // Expired: now = acquired_at + ttl_secs → grant.
        let resp3 = apply(
            &mut state,
            &WardenRequest::AcquireLock {
                key: "provision:foo".into(),
                owner: "node-2".into(),
                ttl_secs: 60,
                acquired_at: 1060,
            },
        );
        assert!(matches!(resp3, WardenResponse::LockGranted(true)));
    }

    #[test]
    fn apply_ingress_owner() {
        let mut state = WardenState::default();
        assert!(state.ingress_owner.is_none());
        apply(
            &mut state,
            &WardenRequest::SetIngressOwner {
                machine: "htz-pdx-1".into(),
            },
        );
        assert_eq!(state.ingress_owner.as_deref(), Some("htz-pdx-1"));
        apply(&mut state, &WardenRequest::ClearIngressOwner);
        assert!(state.ingress_owner.is_none());
    }
}
