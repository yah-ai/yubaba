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
//! @yah:next("F3: consume mshr::Endpoint as yubaba control-plane transport (Open Q2 from the A026 doc finally gets a consumer). RENAMED 2026-07-22 under R593-T7: the crate this bullet used to call `xlb-net::Endpoint` was promoted to the standalone `mshr` workspace in W268 wave 2 — it now lives at oss/mshr/crates/mshr (`pub use endpoint::Endpoint`), NOT oss/xlb/crates/xlb-net. A026-xlb-net.md still carries the pre-promotion name and describes xlb-net 0.1; renaming/rewriting that doc is separate work, so read it as the mshr design doc.")
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
//! @yah:next("Add rollout fields to YubabaState: rollouts: BTreeMap<String, RolloutRaftRecord>")
//! @yah:next("Add YubabaRequest variants: SetRolloutState, ClearRolloutState")
//! @yah:next("In-memory store on ServerState for v1; raft variants defined for forward-compat")
//! @arch:see(.yah/docs/architecture/A032-yah-cluster-mesh.md)
//! @yah:handoff("YubabaState.rollouts: BTreeMap<String, RolloutRaftRecord> added. YubabaRequest::SetRolloutState + ClearRolloutState variants defined and apply() arms wired. YubabaState serialises with #[serde(default)] so old snapshots load cleanly. In-memory RolloutStore on ServerState is the v1 authoritative path; raft variants are forward-compat for when R277 lands.")
//!
//! @yah:ticket(R597-T2, "Rename yubaba-internal raft symbols YubabaState/YubabaRequest/YubabaNodeId/YubabaRaft -> Yubaba*")
//! @yah:status(review)
//! @yah:at(2026-07-20T03:59:44Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R597)
//! @yah:next("DONE (R597-T2): renamed Warden* raft symbols to Yubaba* across oss/yubaba (YubabaState, YubabaRequest, YubabaNodeId, YubabaRaft, YubabaRaftConfig, YubabaStateMachine, YubabaLogStore, YubabaNetwork, YubabaNetworkFactory, YubabaResponse). No wire change; openraft type params only.")
//! @yah:verify("cd oss/yubaba && cargo check -p yubaba --all-features")
//! @yah:gotcha("Tier: Thief -- single-workspace rote symbol rename, no behavior change, no wire surface.")

pub mod network;
pub mod store;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use openraft::{BasicNode, Config, Raft};
use serde::{Deserialize, Serialize};

pub use network::{YubabaNetwork, YubabaNetworkFactory};
pub use store::{YubabaLogStore, YubabaStateMachine};

// ── Type config ──────────────────────────────────────────────────────────────

/// Node IDs are u64, assigned at provisioning time and persisted to the
/// yubaba state file alongside the node's Tailscale mesh IP.
pub type YubabaNodeId = u64;

// openraft 0.10: `Entry`, `AsyncRuntime`, `Vote`, `LeaderId`, `Responder` all
// take crate defaults (adv LeaderId, TokioRuntime, oneshot responder). Only the
// application-facing types are pinned. `SnapshotData` moved off the type config
// onto `RaftStateMachine`/`RaftNetworkV2` (both use `Cursor<Vec<u8>>` here).
openraft::declare_raft_types!(
    pub YubabaRaftConfig:
        D      = YubabaRequest,
        R      = YubabaResponse,
        NodeId = YubabaNodeId,
        Node   = BasicNode,
);

/// Concrete Raft type alias for the yubaba cluster. openraft 0.10 carries the
/// state-machine type on `Raft<C, SM>` (0.9 erased it), so the SM must be named
/// here or `metrics()`/`client_write()` resolve against the unusable `SM = ()`.
pub type YubabaRaft = Raft<YubabaRaftConfig, YubabaStateMachine>;

// ── State machine commands ────────────────────────────────────────────────────

/// Mutations that go through raft consensus.
///
/// Callers write to the leader via `POST /raft/write`; the leader fans
/// the entry out via AppendEntries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum YubabaRequest {
    SetMember {
        node_id: YubabaNodeId,
        addr: String,
    },
    RemoveMember {
        node_id: YubabaNodeId,
    },
    SetServicePlacement {
        service: String,
        machine: String,
    },
    ClearServicePlacement {
        service: String,
    },
    /// `acquired_at` is unix seconds, filled in by the caller. The TTL-expiry
    /// check in `apply` compares a *new* requester's `acquired_at` against the
    /// holder's, so it assumes NTP-synced clocks across voters: a node whose
    /// clock runs fast by more than the remaining TTL could steal a live lock
    /// early. Acceptable for the HA fleet (NTP-synced); issuer lock TTLs are set
    /// far larger than plausible skew (see `acme_issuer::IssuerConfig::lock_ttl`).
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
    // R600-F1 (W273): cluster secret store. Values are AES-256-GCM CIPHERTEXT
    // ONLY — the raft layer never sees plaintext or the KEK. The issuer
    // (R600-F3) encrypts with the node-local cluster KEK before PutSecret; the
    // `SecretRef::Cluster` resolver (R600-F2) decrypts after reading. Homing
    // cert material here gives every node the same bytes via ordinary raft
    // replication (see `SecretRecord` for why plaintext must never appear).
    /// Insert or overwrite a cluster secret.
    PutSecret {
        /// Logical key, e.g. `"tls/yah.dev"`.
        name: String,
        /// AES-256-GCM output (sealed bytes with the GCM tag appended, per the
        /// `aes-gcm` crate's `encrypt` convention). Never plaintext.
        ciphertext: Vec<u8>,
        /// The 12-byte GCM nonce the ciphertext was sealed under.
        nonce: Vec<u8>,
        /// Caller-stamped unix seconds (the domain owns "when", like
        /// [`YubabaRequest::AcquireLock`]'s `acquired_at`).
        updated_at: u64,
    },
    /// Remove a cluster secret. Hard delete, no tombstone: a secret that should
    /// stop being served is removed and the consuming resolver (R600-F2) fails
    /// closed on the miss — there is no 410-vs-404 distinction to preserve here.
    DeleteSecret {
        name: String,
    },
}

// openraft 0.10 requires `AppData: Debug + Display`. The Debug form is a faithful,
// compact rendering of the request, so forward Display to it.
impl std::fmt::Display for YubabaRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// State machine response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum YubabaResponse {
    Ok,
    LockGranted(bool),
}

// ── Domain state ──────────────────────────────────────────────────────────────

/// The entire yubaba cluster state.  Serialised as a JSON snapshot;
/// state volume is KB-scale even on large clusters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct YubabaState {
    pub members: BTreeMap<YubabaNodeId, MemberInfo>,
    /// service name → machine name
    pub service_placement: BTreeMap<String, String>,
    pub locks: BTreeMap<String, LockEntry>,
    pub ingress_owner: Option<String>,
    /// R278-F3: in-flight rollout metadata replicated via raft so a new leader
    /// can resume a rollout after leader change. The in-process RolloutStore
    /// (on ServerState) is the authoritative v1 store; this map is updated
    /// alongside it via SetRolloutState / ClearRolloutState YubabaRequests.
    #[serde(default)]
    pub rollouts: BTreeMap<String, RolloutRaftRecord>,
    /// R600-F1 (W273): raft-replicated cluster secrets, keyed by logical name
    /// (e.g. `"tls/yah.dev"`). Values are AES-256-GCM ciphertext — see
    /// [`SecretRecord`]. This is the fleet-shared store backing
    /// `SecretRef::Cluster` (R600-F2); `#[serde(default)]` so pre-F1 snapshots
    /// load with an empty map (same forward-compat contract as `rollouts`).
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRecord>,
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

/// A cluster secret as stored in raft state (R600-F1 / W273).
///
/// Holds AES-256-GCM **ciphertext only** — never plaintext. The state machine
/// snapshot is serialised as plain JSON to every node's disk
/// (`YubabaStateMachine`'s `serde_json::to_string(&self.data)`), so plaintext
/// secret material must never reach this struct. Encryption and decryption
/// happen *outside* the raft layer with a node-local cluster KEK (issuer:
/// R600-F3 seals; resolver: R600-F2 opens); the state machine only ever moves
/// opaque bytes and cannot itself read a secret's contents.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecord {
    /// AES-256-GCM output: the sealed bytes with the GCM tag appended.
    pub ciphertext: Vec<u8>,
    /// The 12-byte GCM nonce `ciphertext` was sealed under.
    pub nonce: Vec<u8>,
    /// Caller-stamped unix seconds of the last write. Lets a consumer detect
    /// rotation (R600-F4) and aids debugging; not security-sensitive.
    pub updated_at: u64,
}

// Redact the opaque bytes from Debug (which `YubabaState`/snapshot dumps and any
// TRACE-level raft logging would otherwise print). The ciphertext isn't directly
// sensitive — decrypting still needs the node KEK — but keeping it out of log
// archives avoids leaking rotation size/timing and denying a future
// KEK-compromise a ready-made decrypt corpus. Only the byte lengths + timestamp
// surface. (YubabaRequest::PutSecret carries the same bytes inline and derives
// Debug; redacting that too is a follow-up cleanup — lower value than this,
// since state snapshots are the more likely log surface.)
impl std::fmt::Debug for SecretRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRecord")
            .field(
                "ciphertext",
                &format_args!("<{} bytes>", self.ciphertext.len()),
            )
            .field("nonce", &format_args!("<{} bytes>", self.nonce.len()))
            .field("updated_at", &self.updated_at)
            .finish()
    }
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

/// Apply a [`YubabaRequest`] to `state`.  Pure function — all I/O is the
/// caller's responsibility.
pub fn apply(state: &mut YubabaState, req: &YubabaRequest) -> YubabaResponse {
    match req {
        YubabaRequest::SetMember { node_id, addr } => {
            state
                .members
                .insert(*node_id, MemberInfo { addr: addr.clone() });
            YubabaResponse::Ok
        }
        YubabaRequest::RemoveMember { node_id } => {
            state.members.remove(node_id);
            YubabaResponse::Ok
        }
        YubabaRequest::SetServicePlacement { service, machine } => {
            state
                .service_placement
                .insert(service.clone(), machine.clone());
            YubabaResponse::Ok
        }
        YubabaRequest::ClearServicePlacement { service } => {
            state.service_placement.remove(service);
            YubabaResponse::Ok
        }
        YubabaRequest::AcquireLock {
            key,
            owner,
            ttl_secs,
            acquired_at,
        } => {
            let now = *acquired_at;
            let grant = match state.locks.get(key) {
                None => true,
                Some(entry) => {
                    entry.owner == *owner || now.saturating_sub(entry.acquired_at) >= entry.ttl_secs
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
            YubabaResponse::LockGranted(grant)
        }
        YubabaRequest::ReleaseLock { key, owner } => {
            if state.locks.get(key).map(|e| e.owner.as_str()) == Some(owner.as_str()) {
                state.locks.remove(key);
            }
            YubabaResponse::Ok
        }
        YubabaRequest::SetIngressOwner { machine } => {
            state.ingress_owner = Some(machine.clone());
            YubabaResponse::Ok
        }
        YubabaRequest::ClearIngressOwner => {
            state.ingress_owner = None;
            YubabaResponse::Ok
        }
        YubabaRequest::SetRolloutState {
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
            YubabaResponse::Ok
        }
        YubabaRequest::ClearRolloutState { rollout_id } => {
            state.rollouts.remove(rollout_id);
            YubabaResponse::Ok
        }
        YubabaRequest::PutSecret {
            name,
            ciphertext,
            nonce,
            updated_at,
        } => {
            // Opaque bytes in, opaque bytes stored — this layer never decrypts.
            state.secrets.insert(
                name.clone(),
                SecretRecord {
                    ciphertext: ciphertext.clone(),
                    nonce: nonce.clone(),
                    updated_at: *updated_at,
                },
            );
            YubabaResponse::Ok
        }
        YubabaRequest::DeleteSecret { name } => {
            state.secrets.remove(name);
            YubabaResponse::Ok
        }
    }
}

// ── Node factory ──────────────────────────────────────────────────────────────

/// Open (or create) a yubaba raft node.
///
/// `node_id`  — this machine's unique yubaba node ID (u64, assigned at provision time).
/// `raft_dir` — directory for raft persistence files (`raft_vote.json`, `raft_log.json`, `raft_state.json`).
pub async fn open(node_id: YubabaNodeId, raft_dir: PathBuf) -> anyhow::Result<YubabaRaft> {
    Ok(open_with_state_machine(node_id, raft_dir).await?.0)
}

/// Like [`open`], but also hands back a clone of the [`YubabaStateMachine`] so
/// the caller can read applied cluster state directly (linearizable-free local
/// reads). The daemon uses this for the R600-F3 ACME issuer, which reads the
/// stored cert's age to decide renewal, and for the `SecretRef::Cluster`
/// resolver (R600-F2), which reads replicated ciphertext. The state machine is
/// `Clone` (an inner `Arc<RwLock<…>>`), so this handle and the one inside the
/// `Raft` observe the same state.
pub async fn open_with_state_machine(
    node_id: YubabaNodeId,
    raft_dir: PathBuf,
) -> anyhow::Result<(YubabaRaft, YubabaStateMachine)> {
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

    let log_store = YubabaLogStore::open(raft_dir.clone()).await?;
    let state_machine = YubabaStateMachine::open(raft_dir).await?;
    let network = YubabaNetworkFactory;

    let raft = YubabaRaft::new(node_id, config, network, log_store, state_machine.clone()).await?;
    Ok((raft, state_machine))
}

/// Auto-initialise this node as a **cluster-of-one** — the W197 §"Single-node
/// raft" / A032 §"cluster-mesh-1" bootstrap path (R482-T3).
///
/// A freshly-booted BYO-VPS yubaba forms its own one-voter raft cluster with no
/// operator `raft init` call and no peers. Single-node raft is degenerate but
/// fully functional (A032: "single-node raft is degenerate but works") — the
/// node writes the founding membership log entry and self-elects as leader
/// within one election timeout. No [`YubabaNetwork`] RPC is ever issued (there
/// are no peers to reach), so this is independent of the raft/mesh transport
/// parked under R593-T7.
///
/// **Idempotent.** Re-running on a node that already has vote/log state — a
/// restart, or a node that previously founded or joined a cluster — is a no-op:
/// `initialize` returns [`InitializeError::NotAllowed`] once the node is
/// bootstrapped, which is mapped to `Ok(false)`. Safe to call unconditionally
/// at every startup. Returns `true` when this call performed the init, `false`
/// when the node was already initialised.
///
/// `addr` is recorded as this node's membership address. For a cluster-of-one
/// it is self-referential and never dialed (raft is not in the data path with
/// no peers), so any stable self-address works; a later multi-machine join
/// (yubaba's join-by-NodeId flow) supplies real peer addresses.
///
/// Do **not** combine this with the multi-node founding flow (`raft init
/// --member …`): a node that self-inits is its own cluster and cannot later
/// merge with a separately-founded one — fleet growth is join-by-NodeId onto an
/// existing single-node cluster, per W197 §"Single-node raft".
pub async fn bootstrap_single_node(
    raft: &YubabaRaft,
    node_id: YubabaNodeId,
    addr: impl Into<String>,
) -> anyhow::Result<bool> {
    let mut members = BTreeMap::new();
    members.insert(node_id, BasicNode { addr: addr.into() });
    match raft.initialize(members).await {
        Ok(()) => Ok(true),
        // NotAllowed = this node already has vote/log state, i.e. it is (or was)
        // bootstrapped — idempotent no-op, same mapping as the POST
        // /raft/initialize handler.
        Err(openraft::error::RaftError::APIError(
            openraft::error::InitializeError::NotAllowed(_),
        )) => Ok(false),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_set_member() {
        let mut state = YubabaState::default();
        apply(
            &mut state,
            &YubabaRequest::SetMember {
                node_id: 1,
                addr: "100.64.0.1:7443".into(),
            },
        );
        assert!(state.members.contains_key(&1));
    }

    #[test]
    fn apply_lock_grant_and_release() {
        let mut state = YubabaState::default();
        let resp = apply(
            &mut state,
            &YubabaRequest::AcquireLock {
                key: "provision:foo".into(),
                owner: "node-1".into(),
                ttl_secs: 60,
                acquired_at: 1000,
            },
        );
        assert!(matches!(resp, YubabaResponse::LockGranted(true)));

        // Second acquire by different owner before TTL should fail.
        let resp2 = apply(
            &mut state,
            &YubabaRequest::AcquireLock {
                key: "provision:foo".into(),
                owner: "node-2".into(),
                ttl_secs: 60,
                acquired_at: 1010,
            },
        );
        assert!(matches!(resp2, YubabaResponse::LockGranted(false)));

        // Expired: now = acquired_at + ttl_secs → grant.
        let resp3 = apply(
            &mut state,
            &YubabaRequest::AcquireLock {
                key: "provision:foo".into(),
                owner: "node-2".into(),
                ttl_secs: 60,
                acquired_at: 1060,
            },
        );
        assert!(matches!(resp3, YubabaResponse::LockGranted(true)));
    }

    #[test]
    fn apply_ingress_owner() {
        let mut state = YubabaState::default();
        assert!(state.ingress_owner.is_none());
        apply(
            &mut state,
            &YubabaRequest::SetIngressOwner {
                machine: "htz-pdx-1".into(),
            },
        );
        assert_eq!(state.ingress_owner.as_deref(), Some("htz-pdx-1"));
        apply(&mut state, &YubabaRequest::ClearIngressOwner);
        assert!(state.ingress_owner.is_none());
    }

    #[test]
    fn apply_put_overwrite_and_delete_secret() {
        let mut state = YubabaState::default();
        apply(
            &mut state,
            &YubabaRequest::PutSecret {
                name: "tls/yah.dev".into(),
                ciphertext: vec![1, 2, 3, 4],
                nonce: vec![9; 12],
                updated_at: 1000,
            },
        );
        let rec = state.secrets.get("tls/yah.dev").expect("secret stored");
        assert_eq!(rec.ciphertext, vec![1, 2, 3, 4]);
        assert_eq!(rec.nonce, vec![9; 12]);
        assert_eq!(rec.updated_at, 1000);

        // A second PutSecret for the same name overwrites in place (rotation).
        apply(
            &mut state,
            &YubabaRequest::PutSecret {
                name: "tls/yah.dev".into(),
                ciphertext: vec![5, 6],
                nonce: vec![7; 12],
                updated_at: 2000,
            },
        );
        let rec = state.secrets.get("tls/yah.dev").unwrap();
        assert_eq!(rec.ciphertext, vec![5, 6]);
        assert_eq!(rec.updated_at, 2000);
        assert_eq!(state.secrets.len(), 1, "overwrite, not append");

        // Delete removes it; deleting a missing key is a no-op, never a panic.
        apply(
            &mut state,
            &YubabaRequest::DeleteSecret {
                name: "tls/yah.dev".into(),
            },
        );
        assert!(!state.secrets.contains_key("tls/yah.dev"));
        apply(
            &mut state,
            &YubabaRequest::DeleteSecret {
                name: "tls/yah.dev".into(),
            },
        );
        assert!(state.secrets.is_empty());
    }

    #[test]
    fn secrets_survive_snapshot_round_trip() {
        // The snapshot path is serde_json over YubabaState (see store.rs) — the
        // secrets map must serialise and restore byte-identically.
        let mut state = YubabaState::default();
        apply(
            &mut state,
            &YubabaRequest::PutSecret {
                name: "tls/yah.dev".into(),
                ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
                nonce: vec![1; 12],
                updated_at: 42,
            },
        );
        let json = serde_json::to_string(&state).unwrap();
        let restored: YubabaState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.secrets, state.secrets);
    }

    #[test]
    fn pre_f1_snapshot_without_secrets_field_loads() {
        // A snapshot serialised before R600-F1 has no `secrets` key;
        // #[serde(default)] must let it deserialize to an empty map, not error
        // (same forward-compat contract the `rollouts` field relies on).
        let legacy = r#"{"members":{},"service_placement":{},"locks":{},"ingress_owner":null,"rollouts":{}}"#;
        let state: YubabaState = serde_json::from_str(legacy).unwrap();
        assert!(state.secrets.is_empty());
    }
}
