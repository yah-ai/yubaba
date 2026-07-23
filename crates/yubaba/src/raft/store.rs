//! File-backed raft storage for yubaba.
//!
//! Both `YubabaLogStore` (log entries + vote) and `YubabaStateMachine`
//! (applied state + snapshot) use JSON files under a configurable
//! directory (`raft_dir`).  State is tiny (KB-scale) so we can afford
//! to rewrite the full file on every mutation — no append-log format
//! needed at this scale.
//!
//! File layout:
//! ```text
//! {raft_dir}/
//!   raft_vote.json      — persisted Vote
//!   raft_log.json       — BTreeMap<u64, Entry>
//!   raft_state.json     — StateMachineData (YubabaState + meta)
//! ```
//!
//! openraft 0.10 notes: storage methods now fail with plain [`std::io::Error`]
//! (not the old `StorageError`); ids/votes/memberships are the `…Of<C>` type
//! aliases; `RaftStateMachine::apply` consumes a stream of `(entry, responder)`
//! and each entry's response is delivered through its [`ApplyResponder`]; and
//! `SnapshotData` (a `Cursor<Vec<u8>>` here) lives on the state machine /
//! network, not the type config.
//!
//! [`ApplyResponder`]: openraft::storage::ApplyResponder

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::{self, Cursor};
use std::ops::RangeBounds;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use openraft::storage::{
    EntryResponder, IOFlushed, LogState, RaftLogReader, RaftLogStorage, RaftSnapshotBuilder,
    RaftStateMachine,
};
use openraft::type_config::alias::{
    EntryOf, LogIdOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf, VoteOf,
};
use openraft::{EntryPayload, OptionalSend, Snapshot, SnapshotMeta, StoredMembership};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_stream::{Stream, StreamExt};

use super::super::raft::apply;
use super::{YubabaRaftConfig as TC, YubabaRequest, YubabaResponse, YubabaState};

/// Snapshot payload handle. Yubaba state is KB-scale, so the whole snapshot is
/// an in-memory JSON blob behind a cursor — the same on both the state machine
/// and the network transport (`RaftNetworkV2::SnapshotData`).
type SnapshotData = Cursor<Vec<u8>>;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Wrap any displayable error as an `io::Error` — the 0.10 storage traits fail
/// with `io::Error`, so serialization failures funnel through here.
fn io_other<E: Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

// ── Log store ─────────────────────────────────────────────────────────────────

struct LogStoreInner {
    last_purged_log_id: Option<LogIdOf<TC>>,
    /// Log entries kept after the last purge.
    entries: BTreeMap<u64, EntryOf<TC>>,
    committed: Option<LogIdOf<TC>>,
    vote: Option<VoteOf<TC>>,
    base_dir: PathBuf,
}

impl LogStoreInner {
    fn persist_log(&self) -> Result<(), io::Error> {
        let path = self.base_dir.join("raft_log.json");
        let json = serde_json::to_string(&self.entries).map_err(io_other)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    fn persist_vote(&self) -> Result<(), io::Error> {
        let path = self.base_dir.join("raft_vote.json");
        let json = serde_json::to_string(&self.vote).map_err(io_other)?;
        std::fs::write(&path, json)?;
        Ok(())
    }
}

/// Log storage: clone-able via the inner `Arc<RwLock<>>` so the same
/// instance serves as both `LogStore` and `LogReader`.
#[derive(Clone)]
pub struct YubabaLogStore {
    inner: Arc<RwLock<LogStoreInner>>,
}

impl YubabaLogStore {
    /// Open or create the log store in `dir`.
    pub async fn open(dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;

        let vote: Option<VoteOf<TC>> = {
            let p = dir.join("raft_vote.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                None
            }
        };

        let entries: BTreeMap<u64, EntryOf<TC>> = {
            let p = dir.join("raft_log.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                BTreeMap::new()
            }
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(LogStoreInner {
                last_purged_log_id: None,
                entries,
                committed: None,
                vote,
                base_dir: dir,
            })),
        })
    }
}

impl RaftLogReader<TC> for YubabaLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<EntryOf<TC>>, io::Error> {
        let inner = self.inner.read().unwrap();
        Ok(inner.entries.range(range).map(|(_, e)| e.clone()).collect())
    }

    async fn read_vote(&mut self) -> Result<Option<VoteOf<TC>>, io::Error> {
        Ok(self.inner.read().unwrap().vote.clone())
    }
}

impl RaftLogStorage<TC> for YubabaLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TC>, io::Error> {
        let inner = self.inner.read().unwrap();
        let last_log_id = inner.entries.values().last().map(|e| e.log_id);
        Ok(LogState {
            last_purged_log_id: inner.last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &VoteOf<TC>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        inner.vote = Some(vote.clone());
        inner.persist_vote()
    }

    async fn append<I>(&mut self, entries: I, callback: IOFlushed<TC>) -> Result<(), io::Error>
    where
        I: IntoIterator<Item = EntryOf<TC>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        {
            let mut inner = self.inner.write().unwrap();
            for entry in entries {
                inner.entries.insert(entry.log_id.index, entry);
            }
            inner.persist_log()?;
        }
        callback.io_completed(Ok(()));
        Ok(())
    }

    async fn truncate_after(&mut self, last_log_id: Option<LogIdOf<TC>>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        // Remove everything strictly after `last_log_id` (exclusive). `None`
        // truncates the entire log.
        let keep_upto = last_log_id.map(|l| l.index);
        inner.entries.retain(|&idx, _| match keep_upto {
            Some(upto) => idx <= upto,
            None => false,
        });
        inner.persist_log()
    }

    async fn purge(&mut self, log_id: LogIdOf<TC>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        inner.last_purged_log_id = Some(log_id);
        inner.entries.retain(|&idx, _| idx > log_id.index);
        inner.persist_log()
    }

    async fn save_committed(&mut self, committed: Option<LogIdOf<TC>>) -> Result<(), io::Error> {
        self.inner.write().unwrap().committed = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogIdOf<TC>>, io::Error> {
        Ok(self.inner.read().unwrap().committed)
    }
}

// ── State machine ─────────────────────────────────────────────────────────────

/// Serialised form of the state machine — written to `raft_state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateMachineData {
    last_applied: Option<LogIdOf<TC>>,
    last_membership: StoredMembershipOf<TC>,
    state: YubabaState,
}

impl Default for StateMachineData {
    fn default() -> Self {
        Self {
            last_applied: None,
            last_membership: StoredMembership::default(),
            state: YubabaState::default(),
        }
    }
}

struct StateMachineInner {
    data: StateMachineData,
    /// The last snapshot we installed (if any).
    snapshot_meta: Option<SnapshotMetaOf<TC>>,
    snapshot_bytes: Option<Vec<u8>>,
    base_dir: PathBuf,
    /// R600-F4 (W273): bumped on every applied cluster-secret change
    /// (`PutSecret`/`DeleteSecret`) and on snapshot install, so a consumer task
    /// (rotation → live reload) can re-render the affected tmpfs mounts and
    /// graceful-upgrade the workload. Coarse epoch counter — a subscriber wakes
    /// on any bump and re-reads the current secrets map (re-render is
    /// idempotent), so coalesced bumps never lose a change.
    secrets_epoch: watch::Sender<u64>,
}

impl StateMachineInner {
    fn persist(&self) -> Result<(), io::Error> {
        let path = self.base_dir.join("raft_state.json");
        let json = serde_json::to_string(&self.data).map_err(io_other)?;
        std::fs::write(&path, json)?;
        Ok(())
    }
}

/// State machine storage — `Clone`-able via inner `Arc<RwLock<>>` so
/// it doubles as the `SnapshotBuilder`.
#[derive(Clone)]
pub struct YubabaStateMachine {
    inner: Arc<RwLock<StateMachineInner>>,
}

impl YubabaStateMachine {
    pub async fn open(dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;

        let data: StateMachineData = {
            let p = dir.join("raft_state.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                StateMachineData::default()
            }
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(StateMachineInner {
                data,
                snapshot_meta: None,
                snapshot_bytes: None,
                base_dir: dir,
                secrets_epoch: watch::channel(0).0,
            })),
        })
    }

    /// Subscribe to cluster-secret changes (R600-F4 / W273). The receiver's
    /// value is a coarse epoch counter bumped on every applied `PutSecret` /
    /// `DeleteSecret` and on snapshot install. Wake on a change and re-read the
    /// current state via [`Self::cluster_secret`] — the counter says *something*
    /// changed, not what, which is all the (idempotent) re-render needs.
    pub fn subscribe_secrets(&self) -> watch::Receiver<u64> {
        self.inner.read().unwrap().secrets_epoch.subscribe()
    }

    /// Read a cluster secret's ciphertext record from the local applied state
    /// (R600-F2 / W273). Returns a clone so the caller never holds the state
    /// lock while decrypting. `None` if no secret is stored under `name`.
    ///
    /// The record is AES-256-GCM ciphertext only (see [`super::SecretRecord`]);
    /// the state machine cannot itself read a secret's plaintext — decryption
    /// happens in `secrets::ClusterResolver` with the node-local KEK.
    pub fn cluster_secret(&self, name: &str) -> Option<super::SecretRecord> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .secrets
            .get(name)
            .cloned()
    }
}

impl RaftSnapshotBuilder<TC> for YubabaStateMachine {
    type SnapshotData = SnapshotData;

    async fn build_snapshot(&mut self) -> Result<SnapshotOf<TC, SnapshotData>, io::Error> {
        let inner = self.inner.read().unwrap();
        let bytes = serde_json::to_vec(&inner.data).map_err(io_other)?;
        let snapshot_id = inner
            .data
            .last_applied
            .map(|id| format!("{}-{}", id.leader_id, id.index))
            .unwrap_or_else(|| "empty".to_string());
        let meta = SnapshotMeta {
            last_log_id: inner.data.last_applied,
            last_membership: inner.data.last_membership.clone(),
            snapshot_id,
        };
        Ok(Snapshot {
            meta,
            snapshot: Cursor::new(bytes),
        })
    }
}

impl RaftStateMachine<TC> for YubabaStateMachine {
    type SnapshotData = SnapshotData;
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogIdOf<TC>>, StoredMembershipOf<TC>), io::Error> {
        let inner = self.inner.read().unwrap();
        Ok((inner.data.last_applied, inner.data.last_membership.clone()))
    }

    async fn apply<Strm>(&mut self, mut entries: Strm) -> Result<(), io::Error>
    where
        Strm: Stream<Item = Result<EntryResponder<TC>, io::Error>> + Unpin + OptionalSend,
    {
        // Drain the stream first (await here holds NO lock), then apply under the
        // sync lock, then deliver responses after releasing it. This keeps the
        // std `RwLock` guard off every `.await` point.
        let mut items = Vec::new();
        while let Some(item) = entries.next().await {
            items.push(item?);
        }

        let mut pending = Vec::with_capacity(items.len());
        let mut secrets_changed = false;
        {
            let mut inner = self.inner.write().unwrap();
            for (entry, responder) in items {
                let log_id = entry.log_id;
                inner.data.last_applied = Some(log_id);
                let resp = match entry.payload {
                    EntryPayload::Blank => YubabaResponse::Ok,
                    EntryPayload::Normal(req) => {
                        if matches!(
                            req,
                            YubabaRequest::PutSecret { .. } | YubabaRequest::DeleteSecret { .. }
                        ) {
                            secrets_changed = true;
                        }
                        apply(&mut inner.data.state, &req)
                    }
                    EntryPayload::Membership(membership) => {
                        inner.data.last_membership =
                            StoredMembership::new(Some(log_id), membership);
                        YubabaResponse::Ok
                    }
                };
                pending.push((responder, resp));
            }

            inner.persist()?;
            // Notify AFTER persist so a woken consumer that re-reads observes
            // durable state. Coalesced into one bump per batch.
            if secrets_changed {
                inner.secrets_epoch.send_modify(|e| *e = e.wrapping_add(1));
            }
        }

        // Responders are notified after the lock is dropped.
        for (responder, resp) in pending {
            if let Some(responder) = responder {
                responder.send(resp);
            }
        }
        Ok(())
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<SnapshotData, io::Error> {
        Ok(Cursor::new(Vec::new()))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMetaOf<TC>,
        snapshot: SnapshotData,
    ) -> Result<(), io::Error> {
        let bytes = snapshot.into_inner();
        let data: StateMachineData = serde_json::from_slice(&bytes).map_err(io_other)?;
        let mut inner = self.inner.write().unwrap();
        inner.data = data;
        inner.data.last_applied = meta.last_log_id;
        inner.data.last_membership = meta.last_membership.clone();
        inner.snapshot_meta = Some(meta.clone());
        inner.snapshot_bytes = Some(bytes);
        inner.persist()?;
        // A snapshot install can replace the secrets map wholesale (a follower
        // catching up), so notify unconditionally — diffing isn't worth it at
        // KB scale, and the subscriber's re-render is idempotent.
        inner.secrets_epoch.send_modify(|e| *e = e.wrapping_add(1));
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<SnapshotOf<TC, SnapshotData>>, io::Error> {
        let inner = self.inner.read().unwrap();
        match (&inner.snapshot_meta, &inner.snapshot_bytes) {
            (Some(meta), Some(bytes)) => Ok(Some(Snapshot {
                meta: meta.clone(),
                snapshot: Cursor::new(bytes.clone()),
            })),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::testing::log_id;

    fn normal_entry(index: u64, req: YubabaRequest) -> EntryOf<TC> {
        openraft::Entry {
            log_id: log_id::<TC>(1, 1, index),
            payload: EntryPayload::Normal(req),
        }
    }

    // R600-F4: the secrets-change watch fires for cluster-secret writes only.
    #[tokio::test]
    async fn secret_writes_bump_the_epoch_but_other_writes_do_not() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut sm = YubabaStateMachine::open(tmp.path().to_path_buf())
            .await
            .unwrap();
        let mut rx = sm.subscribe_secrets();
        assert_eq!(*rx.borrow_and_update(), 0);

        apply_one(
            &mut sm,
            normal_entry(
                1,
                YubabaRequest::PutSecret {
                    name: "tls/yah.dev/cert".into(),
                    ciphertext: vec![1, 2, 3],
                    nonce: vec![0; 12],
                    updated_at: 1,
                },
            ),
        )
        .await;
        assert!(rx.has_changed().unwrap(), "PutSecret should notify");
        assert_eq!(*rx.borrow_and_update(), 1);

        // A non-secret write must not wake secret consumers.
        apply_one(
            &mut sm,
            normal_entry(
                2,
                YubabaRequest::SetIngressOwner {
                    machine: "m1".into(),
                },
            ),
        )
        .await;
        assert!(
            !rx.has_changed().unwrap(),
            "non-secret write must not notify"
        );

        apply_one(
            &mut sm,
            normal_entry(
                3,
                YubabaRequest::DeleteSecret {
                    name: "tls/yah.dev/cert".into(),
                },
            ),
        )
        .await;
        assert!(rx.has_changed().unwrap(), "DeleteSecret should notify");
        assert_eq!(*rx.borrow_and_update(), 2);
    }

    /// Apply a single entry through the 0.10 stream/responder `apply` API with
    /// no client responder attached (as a follower would).
    async fn apply_one(sm: &mut YubabaStateMachine, entry: EntryOf<TC>) {
        let item: Result<EntryResponder<TC>, io::Error> = Ok((entry, None));
        let stream = tokio_stream::iter(vec![item]);
        sm.apply(stream).await.unwrap();
    }
}
