//! Periodic snapshot (W363 §2 "Snapshot and sweep"), bounding rehydrate cost.
//!
//! 1. Under the push lock, capture `seq_s` (the volume marker) and
//!    `for-each-ref`, then release.
//! 2. `git pack-objects --revs --delta-base-offset` from exactly those tips.
//!    Not `repack -a -d`: refs may move while it runs.
//! 3. `PUT Create snapshots/<seq_s>/<pack>`, then `refs.json`, then CAS
//!    `latest.snapshot` last, so a reader never sees a torn snapshot.
//! 4. `git repack -a -d -l` under the push lock (the lock makes `-d` safe).
//!
//! Trigger: 500 entries or 256 MiB of pack bytes since the last snapshot, at
//! least 10 min apart. Only the claim holder runs this, never in the push path.

use crate::journal::{self, retrying};
use crate::layout;
use crate::serve::PushLocks;
use crate::stream::{for_each_ref, read_marker, R2Log};
use crate::{repo, sweep};
use anyhow::{bail, Context, Result};
use object_store::{ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use store_claim::BackupTarget;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Copy)]
pub struct SnapshotPolicy {
    pub max_entries: u64,
    pub max_pack_bytes: u64,
    pub min_interval: Duration,
}

impl Default for SnapshotPolicy {
    fn default() -> Self {
        Self { max_entries: 500, max_pack_bytes: 256 << 20, min_interval: Duration::from_secs(600) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LatestSnapshot {
    pub seq: u64,
    pub pack: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotRef {
    #[serde(rename = "ref")]
    pub refname: String,
    pub oid: String,
}

/// `latest.snapshot`, its CAS version, and when it was written (ms).
pub async fn read_latest(t: &BackupTarget, repo: &str) -> Result<Option<(LatestSnapshot, UpdateVersion, u64)>> {
    let key = layout::latest_snapshot_key(t, repo);
    match retrying(|| t.store.get(&key)).await {
        Ok(res) => {
            let version = UpdateVersion { e_tag: res.meta.e_tag.clone(), version: res.meta.version.clone() };
            let at = res.meta.last_modified.timestamp_millis().max(0) as u64;
            let bytes = res.bytes().await?;
            Ok(Some((serde_json::from_slice(&bytes).with_context(|| format!("parsing {key}"))?, version, at)))
        }
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("GET {key}")),
    }
}

/// Whether the journal since the last snapshot crossed the trigger.
pub async fn due(t: &BackupTarget, repo: &str, policy: &SnapshotPolicy, now_ms: u64) -> Result<bool> {
    let (since, last_at) = match read_latest(t, repo).await? {
        Some((l, _, at)) => (l.seq, Some(at)),
        None => (0, None),
    };
    if let Some(at) = last_at {
        if now_ms.saturating_sub(at) < policy.min_interval.as_millis() as u64 {
            return Ok(false);
        }
    }
    let entries = journal::entries_after(t, repo, since).await?;
    let bytes: u64 = entries.iter().map(|e| e.pack_bytes).sum();
    Ok(!entries.is_empty() && (entries.len() as u64 >= policy.max_entries || bytes >= policy.max_pack_bytes))
}

pub(crate) async fn git_ok(git: &Path, repo_dir: &Path, args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut cmd = tokio::process::Command::new(git);
    cmd.args(args)
        .env("GIT_DIR", repo_dir)
        .stdin(if stdin.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().with_context(|| format!("spawning git {args:?}"))?;
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!("git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Take one snapshot of `repo` now. Returns the new `latest.snapshot`, or
/// `None` when there is nothing to snapshot (no refs, or no entry since the
/// current one).
pub async fn take(log: &R2Log, locks: &PushLocks, repo: &str, repo_dir: &Path) -> Result<Option<LatestSnapshot>> {
    let t = &log.target;
    let git = &log.git;
    // 1. Capture under the lock.
    let (seq, refs) = {
        let _g = locks.lock(repo).await;
        let seq = read_marker(repo_dir)?.map(|m| m.seq).unwrap_or(0);
        (seq, for_each_ref(git, repo_dir, None).await?)
    };
    let latest = read_latest(t, repo).await?;
    if refs.is_empty() || seq == 0 || latest.as_ref().is_some_and(|(l, _, _)| l.seq >= seq) {
        return Ok(None);
    }

    // 2. Pack exactly the objects reachable from the captured tips.
    let tmp = repo_dir.join("fleet-git-snapshot.tmp");
    let _ = tokio::fs::remove_dir_all(&tmp).await;
    tokio::fs::create_dir_all(&tmp).await?;
    let result = async {
        let mut tips = String::new();
        for (oid, _) in &refs {
            tips.push_str(oid);
            tips.push('\n');
        }
        let base = tmp.join("pack");
        let hex = git_ok(
            git,
            repo_dir,
            &["pack-objects", "--revs", "--delta-base-offset", "-q", base.to_str().context("non-UTF-8 path")?],
            Some(&tips),
        )
        .await?;
        let pack = format!("pack-{hex}.pack");
        if !layout::valid_pack_name(&pack) {
            bail!("git pack-objects printed {hex:?}");
        }
        let bytes = tokio::fs::read(tmp.join(&pack)).await?;

        // 3. Pack, then refs.json, then CAS latest.snapshot.
        journal::put_create_idempotent(t, &layout::snapshot_pack_key(t, repo, seq, &pack), bytes.into()).await?;
        let refs_json: Vec<SnapshotRef> =
            refs.iter().map(|(oid, r)| SnapshotRef { refname: r.clone(), oid: oid.clone() }).collect();
        journal::put_create_idempotent(
            t,
            &layout::snapshot_refs_key(t, repo, seq),
            PutPayload::from(serde_json::to_vec(&refs_json)?),
        )
        .await?;
        let new = LatestSnapshot { seq, pack };
        let mode = match latest {
            Some((_, v, _)) => PutMode::Update(v),
            None => PutMode::Create,
        };
        let key = layout::latest_snapshot_key(t, repo);
        let body = PutPayload::from(serde_json::to_vec(&new)?);
        match retrying(|| t.store.put_opts(&key, body.clone(), PutOptions { mode: mode.clone(), ..Default::default() }))
            .await
        {
            Ok(_) => {}
            Err(object_store::Error::Precondition { .. }) | Err(object_store::Error::AlreadyExists { .. }) => {
                bail!("latest.snapshot moved under this snapshot (another writer?)")
            }
            Err(e) => return Err(e).with_context(|| format!("CAS {key}")),
        }
        Ok(new)
    }
    .await;
    let _ = tokio::fs::remove_dir_all(&tmp).await;
    let new = result?;

    // 4. Local maintenance under the lock.
    {
        let _g = locks.lock(repo).await;
        git_ok(git, repo_dir, &["repack", "-a", "-d", "-l", "-q"], None).await?;
    }
    tracing::info!(repo, seq = new.seq, pack = %new.pack, "fleet-git snapshot written");
    Ok(Some(new))
}

/// The background maintenance loop: per repo, the §6 `refs/qed` GC, then a
/// snapshot when [`due`], then a sweep behind it. Stops on fence loss.
pub async fn maintain(log: Arc<R2Log>, locks: Arc<PushLocks>, root: std::path::PathBuf, policy: SnapshotPolicy, every: Duration) {
    let mut tick = tokio::time::interval(every);
    tick.tick().await;
    loop {
        tick.tick().await;
        if log.fence.is_lost() {
            return;
        }
        let names = match repo::list(&root) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "listing repos for maintenance");
                continue;
            }
        };
        for name in names {
            let dir = repo::repo_dir(&root, &name);
            if let Err(e) = maintain_one(&log, &locks, &name, &dir, &policy).await {
                tracing::warn!(repo = %name, error = %format!("{e:#}"), "fleet-git maintenance failed");
            }
        }
    }
}

async fn maintain_one(log: &R2Log, locks: &PushLocks, repo: &str, dir: &Path, policy: &SnapshotPolicy) -> Result<()> {
    let now = journal::now_ms();
    {
        let _g = locks.lock(repo).await;
        sweep::gc_ephemeral(log, repo, dir, now, sweep::AGE_OUTS).await?;
    }
    if due(&log.target, repo, policy, now).await? && take(log, locks, repo, dir).await?.is_some() {
        sweep::sweep(&log.target, repo, journal::now_ms()).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{append, JournalEntry, VERSION};
    use object_store::memory::InMemory;

    fn e(seq: u64, bytes: u64) -> JournalEntry {
        JournalEntry {
            v: VERSION,
            repo: "r".into(),
            seq,
            epoch: 1,
            owner: "o".into(),
            at_unix_ms: 0,
            pusher: "p".into(),
            pack: None,
            pack_bytes: bytes,
            updates: vec![],
        }
    }

    #[tokio::test]
    async fn trigger_counts_entries_and_bytes() {
        let t = BackupTarget { store: Arc::new(InMemory::new()), prefix: String::new() };
        let p = SnapshotPolicy { max_entries: 3, max_pack_bytes: 100, min_interval: Duration::from_secs(600) };
        assert!(!due(&t, "r", &p, 0).await.unwrap());
        append(&t, &e(1, 10)).await.unwrap();
        append(&t, &e(2, 10)).await.unwrap();
        assert!(!due(&t, "r", &p, 0).await.unwrap());
        append(&t, &e(3, 10)).await.unwrap();
        assert!(due(&t, "r", &p, 0).await.unwrap());

        // A fresh latest.snapshot at 3 resets the count and starts the interval.
        let key = layout::latest_snapshot_key(&t, "r");
        t.store.put(&key, serde_json::to_vec(&LatestSnapshot { seq: 3, pack: "x".into() }).unwrap().into()).await.unwrap();
        append(&t, &e(4, 500)).await.unwrap();
        let now = journal::now_ms();
        assert!(!due(&t, "r", &p, now).await.unwrap(), "inside min_interval");
        assert!(due(&t, "r", &p, now + 601_000).await.unwrap(), "bytes trigger");
    }
}
