//! File-backed raft storage for yubaba.
//!
//! Both `WardenLogStore` (log entries + vote) and `WardenStateMachine`
//! (applied state + snapshot) use JSON files under a configurable
//! directory (`raft_dir`).  State is tiny (KB-scale) so we can afford
//! to rewrite the full file on every mutation — no append-log format
//! needed at this scale.
//!
//! File layout:
//! ```text
//! {raft_dir}/
//!   raft_vote.json      — persisted Vote<u64>
//!   raft_log.json       — BTreeMap<u64, Entry<WardenRaftConfig>>
//!   raft_state.json     — StateMachineData (WardenState + meta)
//! ```

use std::collections::BTreeMap;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use openraft::storage::{LogFlushed, RaftLogStorage, RaftStateMachine, Snapshot};
use openraft::{
    BasicNode, Entry, EntryPayload, ErrorSubject, ErrorVerb, LogId, LogState, RaftLogReader,
    RaftSnapshotBuilder, SnapshotMeta, StorageError, StorageIOError, StoredMembership,
    Vote,
};
use serde::{Deserialize, Serialize};

use super::{WardenRaftConfig, WardenResponse, WardenState};
use super::super::raft::apply;

// ── helpers ───────────────────────────────────────────────────────────────────

fn io_err<E: std::error::Error + 'static>(
    e: E,
    subject: ErrorSubject<u64>,
    verb: ErrorVerb,
) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::new(subject, verb, openraft::AnyError::new(&e)),
    }
}

fn ser_err<E: std::error::Error + 'static>(e: E, subject: ErrorSubject<u64>) -> StorageError<u64> {
    io_err(e, subject, ErrorVerb::Write)
}

fn de_err<E: std::error::Error + 'static>(e: E, subject: ErrorSubject<u64>) -> StorageError<u64> {
    io_err(e, subject, ErrorVerb::Read)
}

// ── Log store ─────────────────────────────────────────────────────────────────

struct LogStoreInner {
    last_purged_log_id: Option<LogId<u64>>,
    /// Log entries kept after the last purge.
    entries: BTreeMap<u64, Entry<WardenRaftConfig>>,
    committed: Option<LogId<u64>>,
    vote: Option<Vote<u64>>,
    base_dir: PathBuf,
}

impl LogStoreInner {
    fn persist_log(&self) -> Result<(), StorageError<u64>> {
        let path = self.base_dir.join("raft_log.json");
        let json = serde_json::to_string(&self.entries)
            .map_err(|e| ser_err(e, ErrorSubject::Logs))?;
        std::fs::write(&path, json).map_err(|e| io_err(e, ErrorSubject::Logs, ErrorVerb::Write))?;
        Ok(())
    }

    fn persist_vote(&self) -> Result<(), StorageError<u64>> {
        let path = self.base_dir.join("raft_vote.json");
        let json = serde_json::to_string(&self.vote)
            .map_err(|e| ser_err(e, ErrorSubject::Vote))?;
        std::fs::write(&path, json).map_err(|e| io_err(e, ErrorSubject::Vote, ErrorVerb::Write))?;
        Ok(())
    }
}

/// Log storage: clone-able via the inner `Arc<RwLock<>>` so the same
/// instance serves as both `LogStore` and `LogReader`.
#[derive(Clone)]
pub struct WardenLogStore {
    inner: Arc<RwLock<LogStoreInner>>,
}

impl WardenLogStore {
    /// Open or create the log store in `dir`.
    pub async fn open(dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;

        let vote: Option<Vote<u64>> = {
            let p = dir.join("raft_vote.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                None
            }
        };

        let entries: BTreeMap<u64, Entry<WardenRaftConfig>> = {
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

impl RaftLogReader<WardenRaftConfig> for WardenLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + openraft::OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<WardenRaftConfig>>, StorageError<u64>> {
        let inner = self.inner.read().unwrap();
        Ok(inner.entries.range(range).map(|(_, e)| e.clone()).collect())
    }
}

impl RaftLogStorage<WardenRaftConfig> for WardenLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<WardenRaftConfig>, StorageError<u64>> {
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

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let mut inner = self.inner.write().unwrap();
        inner.vote = Some(*vote);
        inner.persist_vote()
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        Ok(self.inner.read().unwrap().vote)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<WardenRaftConfig>,
    ) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<WardenRaftConfig>> + openraft::OptionalSend,
    {
        {
            let mut inner = self.inner.write().unwrap();
            for entry in entries {
                inner.entries.insert(entry.log_id.index, entry);
            }
            inner.persist_log()?;
        }
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let mut inner = self.inner.write().unwrap();
        inner.entries.retain(|&idx, _| idx <= log_id.index);
        inner.persist_log()
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let mut inner = self.inner.write().unwrap();
        inner.last_purged_log_id = Some(log_id);
        inner.entries.retain(|&idx, _| idx > log_id.index);
        inner.persist_log()
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<u64>>,
    ) -> Result<(), StorageError<u64>> {
        self.inner.write().unwrap().committed = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        Ok(self.inner.read().unwrap().committed)
    }
}

// ── State machine ─────────────────────────────────────────────────────────────

/// Serialised form of the state machine — written to `raft_state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateMachineData {
    last_applied: Option<LogId<u64>>,
    last_membership: StoredMembership<u64, BasicNode>,
    state: WardenState,
}

impl Default for StateMachineData {
    fn default() -> Self {
        Self {
            last_applied: None,
            last_membership: StoredMembership::default(),
            state: WardenState::default(),
        }
    }
}

struct StateMachineInner {
    data: StateMachineData,
    /// The last snapshot we installed (if any).
    snapshot_meta: Option<SnapshotMeta<u64, BasicNode>>,
    snapshot_bytes: Option<Vec<u8>>,
    base_dir: PathBuf,
}

impl StateMachineInner {
    fn persist(&self) -> Result<(), StorageError<u64>> {
        let path = self.base_dir.join("raft_state.json");
        let json = serde_json::to_string(&self.data)
            .map_err(|e| ser_err(e, ErrorSubject::StateMachine))?;
        std::fs::write(&path, json)
            .map_err(|e| io_err(e, ErrorSubject::StateMachine, ErrorVerb::Write))?;
        Ok(())
    }
}

/// State machine storage — `Clone`-able via inner `Arc<RwLock<>>` so
/// it doubles as the `SnapshotBuilder`.
#[derive(Clone)]
pub struct WardenStateMachine {
    inner: Arc<RwLock<StateMachineInner>>,
}

impl WardenStateMachine {
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
            })),
        })
    }
}

impl RaftSnapshotBuilder<WardenRaftConfig> for WardenStateMachine {
    async fn build_snapshot(
        &mut self,
    ) -> Result<Snapshot<WardenRaftConfig>, StorageError<u64>> {
        let inner = self.inner.read().unwrap();
        let bytes = serde_json::to_vec(&inner.data)
            .map_err(|e| ser_err(e, ErrorSubject::StateMachine))?;
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
            snapshot: Box::new(Cursor::new(bytes)),
        })
    }
}

impl RaftStateMachine<WardenRaftConfig> for WardenStateMachine {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let inner = self.inner.read().unwrap();
        Ok((inner.data.last_applied, inner.data.last_membership.clone()))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<WardenResponse>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<WardenRaftConfig>> + openraft::OptionalSend,
    {
        let mut inner = self.inner.write().unwrap();
        let mut responses = Vec::new();

        for entry in entries {
            inner.data.last_applied = Some(entry.log_id);
            match &entry.payload {
                EntryPayload::Blank => responses.push(WardenResponse::Ok),
                EntryPayload::Normal(req) => {
                    let resp = apply(&mut inner.data.state, req);
                    responses.push(resp);
                }
                EntryPayload::Membership(membership) => {
                    inner.data.last_membership =
                        StoredMembership::new(Some(entry.log_id), membership.clone());
                    responses.push(WardenResponse::Ok);
                }
            }
        }

        inner.persist()?;
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let bytes = snapshot.into_inner();
        let data: StateMachineData = serde_json::from_slice(&bytes)
            .map_err(|e| de_err(e, ErrorSubject::StateMachine))?;
        let mut inner = self.inner.write().unwrap();
        inner.data = data;
        inner.data.last_applied = meta.last_log_id;
        inner.data.last_membership = meta.last_membership.clone();
        inner.snapshot_meta = Some(meta.clone());
        inner.snapshot_bytes = Some(bytes);
        inner.persist()
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<WardenRaftConfig>>, StorageError<u64>> {
        let inner = self.inner.read().unwrap();
        match (&inner.snapshot_meta, &inner.snapshot_bytes) {
            (Some(meta), Some(bytes)) => Ok(Some(Snapshot {
                meta: meta.clone(),
                snapshot: Box::new(Cursor::new(bytes.clone())),
            })),
            _ => Ok(None),
        }
    }
}
