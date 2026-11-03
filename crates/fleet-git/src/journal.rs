//! Journal v1 (W363 §2 "Journal entry schema"): one create-only object per
//! accepted push or internal ref change, `seq` gap-free from 1 per repo.
//!
//! The `PutMode::Create` on `journal/<seq>.json` is the fork fence (§3): only
//! one entry can ever exist per `seq`, so a second writer's append surfaces
//! here as [`AppendError::Moved`]. Correctness rests on that, not on `epoch`.

use crate::layout;
use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::Duration;
use store_claim::BackupTarget;

pub const VERSION: u32 = 1;
/// `pusher` of the supervisor's own updates (the 7-day `refs/qed` GC, §6).
pub const GC_PUSHER: &str = "fleet-git:gc";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalUpdate {
    #[serde(rename = "ref")]
    pub refname: String,
    pub old: String,
    pub new: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalEntry {
    pub v: u32,
    pub repo: String,
    pub seq: u64,
    pub epoch: u64,
    pub owner: String,
    pub at_unix_ms: u64,
    pub pusher: String,
    /// `pack-<hex>.pack`, or `None` when the update introduces no objects.
    pub pack: Option<String>,
    pub pack_bytes: u64,
    pub updates: Vec<JournalUpdate>,
}

#[derive(Debug)]
pub enum AppendError {
    /// `journal/<seq>` already exists: another writer appended. Fence loss.
    Moved { seq: u64 },
    Store(anyhow::Error),
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppendError::Moved { seq } => write!(f, "journal moved: entry {seq} was written by another writer; retry"),
            AppendError::Store(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for AppendError {}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// R2 throttling (429) or unavailability (503). W363 §2: retried inline, at
/// most [`MAX_TRIES`], then the push fails. object_store does not expose the
/// status as a field, so this reads it from the error text.
pub fn is_throttled(e: &object_store::Error) -> bool {
    if matches!(
        e,
        object_store::Error::AlreadyExists { .. }
            | object_store::Error::Precondition { .. }
            | object_store::Error::NotFound { .. }
    ) {
        return false;
    }
    let s = e.to_string();
    ["429", "503", "Too Many Requests", "Service Unavailable", "SlowDown"].iter().any(|m| s.contains(m))
}

pub const MAX_TRIES: u32 = 3;

/// Run `op` up to [`MAX_TRIES`] times while it fails with [`is_throttled`].
pub async fn retrying<T, F, Fut>(mut op: F) -> object_store::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = object_store::Result<T>>,
{
    let mut tries = 0;
    loop {
        tries += 1;
        match op().await {
            Err(e) if tries < MAX_TRIES && is_throttled(&e) => {
                tracing::warn!(error = %e, tries, "object store throttled; retrying");
                tokio::time::sleep(Duration::from_millis(200 * u64::from(tries))).await;
            }
            r => return r,
        }
    }
}

/// `PUT Create`, where `AlreadyExists` counts as success (content-addressed keys).
pub async fn put_create_idempotent(t: &BackupTarget, key: &object_store::path::Path, body: PutPayload) -> Result<()> {
    let opts = || PutOptions { mode: PutMode::Create, ..Default::default() };
    match retrying(|| t.store.put_opts(key, body.clone(), opts())).await {
        Ok(_) | Err(object_store::Error::AlreadyExists { .. }) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("PUT {key}")),
    }
}

/// `PUT Create journal/<entry.seq>.json`.
pub async fn append(t: &BackupTarget, entry: &JournalEntry) -> std::result::Result<(), AppendError> {
    let key = layout::journal_key(t, &entry.repo, entry.seq);
    let body = PutPayload::from(serde_json::to_vec(entry).map_err(|e| AppendError::Store(e.into()))?);
    let opts = || PutOptions { mode: PutMode::Create, ..Default::default() };
    match retrying(|| t.store.put_opts(&key, body.clone(), opts())).await {
        Ok(_) => Ok(()),
        Err(object_store::Error::AlreadyExists { .. }) | Err(object_store::Error::Precondition { .. }) => {
            Err(AppendError::Moved { seq: entry.seq })
        }
        Err(e) => Err(AppendError::Store(anyhow::Error::new(e).context(format!("PUT Create {key}")))),
    }
}

pub async fn read(t: &BackupTarget, repo: &str, seq: u64) -> Result<Option<JournalEntry>> {
    let key = layout::journal_key(t, repo, seq);
    match retrying(|| t.store.get(&key)).await {
        Ok(res) => {
            let bytes = res.bytes().await.with_context(|| format!("reading {key}"))?;
            Ok(Some(serde_json::from_slice(&bytes).with_context(|| format!("parsing {key}"))?))
        }
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("GET {key}")),
    }
}

/// Every `seq` present under `journal/`, ascending.
pub async fn list_seqs(t: &BackupTarget, repo: &str) -> Result<Vec<u64>> {
    let dir = layout::journal_dir(t, repo);
    let metas: Vec<_> = t.store.list(Some(&dir)).try_collect().await.with_context(|| format!("LIST {dir}"))?;
    let mut seqs: Vec<u64> = metas.iter().filter_map(|m| layout::parse_journal_key(&m.location)).collect();
    seqs.sort_unstable();
    Ok(seqs)
}

/// The journal head: the highest `seq`, or 0 for an empty journal.
pub async fn head(t: &BackupTarget, repo: &str) -> Result<u64> {
    Ok(list_seqs(t, repo).await?.last().copied().unwrap_or(0))
}

/// Entries with `seq > after`, ascending.
pub async fn entries_after(t: &BackupTarget, repo: &str, after: u64) -> Result<Vec<JournalEntry>> {
    let mut out = Vec::new();
    for seq in list_seqs(t, repo).await?.into_iter().filter(|s| *s > after) {
        if let Some(e) = read(t, repo, seq).await? {
            out.push(e);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use std::sync::Arc;

    pub(crate) fn entry(repo: &str, seq: u64) -> JournalEntry {
        JournalEntry {
            v: VERSION,
            repo: repo.into(),
            seq,
            epoch: 1,
            owner: "fleet-git@t".into(),
            at_unix_ms: 1,
            pusher: "user:t".into(),
            pack: None,
            pack_bytes: 0,
            updates: vec![JournalUpdate { refname: "refs/qed/r/s".into(), old: "0".repeat(40), new: "1".repeat(40) }],
        }
    }

    #[test]
    fn schema_is_v1() {
        let v = serde_json::to_value(entry("yah", 3)).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["updates"][0]["ref"], "refs/qed/r/s");
        assert!(v["pack"].is_null());
        for k in ["repo", "seq", "epoch", "owner", "at_unix_ms", "pusher", "pack_bytes"] {
            assert!(v.get(k).is_some(), "{k}");
        }
    }

    #[tokio::test]
    async fn create_is_the_fork_fence() {
        let t = BackupTarget { store: Arc::new(InMemory::new()), prefix: String::new() };
        assert_eq!(head(&t, "yah").await.unwrap(), 0);
        append(&t, &entry("yah", 1)).await.unwrap();
        let mut rival = entry("yah", 1);
        rival.pusher = "user:other".into();
        assert!(matches!(append(&t, &rival).await, Err(AppendError::Moved { seq: 1 })));
        assert_eq!(read(&t, "yah", 1).await.unwrap().unwrap().pusher, "user:t");
        append(&t, &entry("yah", 2)).await.unwrap();
        assert_eq!(head(&t, "yah").await.unwrap(), 2);
        assert_eq!(entries_after(&t, "yah", 1).await.unwrap().len(), 1);
        assert_eq!(head(&t, "other").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn throttling_is_retried_then_fails() {
        let mut calls = 0;
        let r: object_store::Result<()> = retrying(|| {
            calls += 1;
            async { Err(object_store::Error::Generic { store: "t", source: "503 Service Unavailable".into() }) }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(calls, MAX_TRIES);
        let mut calls = 0;
        let _ = retrying(|| {
            calls += 1;
            async { Err::<(), _>(object_store::Error::Generic { store: "t", source: "403 Forbidden".into() }) }
        })
        .await;
        assert_eq!(calls, 1);
    }
}
