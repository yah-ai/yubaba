//! The durable step (W363 §2 "Ack semantics"): every accepted push is in R2,
//! pack then journal entry, before `pre-receive` exits 0.
//!
//! [`R2Log`] is the [`PushLog`] the supervisor runs. Under the push lock:
//! policy and `assert_holds` (in [`crate::hook`]) → `PUT Create
//! packs/<name>.pack` from `$GIT_QUARANTINE_PATH/pack` → `PUT Create
//! journal/<seq+1>.json` (`AlreadyExists` refuses the push and enters fence
//! loss) → exit 0. `post-receive` then writes the volume marker
//! `<repo>.git/fleet-git-state.json { seq, refs_digest }`.
//!
//! `seq` comes from this volume's marker: a writer appends `n` only when its
//! local state is `n-1` (§3). A volume behind the journal (a crash after the
//! entry, before the refs moved) is detectable with [`unapplied`] and is
//! reconciled by R971-F4's startup replay, not here.

use crate::fence::Fence;
use crate::hook::{is_zero, AcceptedPush, PushLog, RefUpdate};
use crate::journal::{self, AppendError, JournalEntry, JournalUpdate, GC_PUSHER, VERSION};
use crate::layout;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use store_claim::BackupTarget;
use tokio::io::AsyncWriteExt;

pub const MARKER_FILE: &str = "fleet-git-state.json";

/// The volume marker: the journal position this repo's refs reflect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeMarker {
    pub seq: u64,
    /// [`refs_digest`] of the refs as of `seq`.
    pub refs_digest: String,
}

pub fn read_marker(repo_dir: &Path) -> Result<Option<VolumeMarker>> {
    let p = repo_dir.join(MARKER_FILE);
    match std::fs::read(&p) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).with_context(|| format!("parsing {}", p.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}

pub fn write_marker(repo_dir: &Path, m: &VolumeMarker) -> Result<()> {
    let tmp = repo_dir.join(format!("{MARKER_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec(m)?)?;
    std::fs::rename(&tmp, repo_dir.join(MARKER_FILE))?;
    Ok(())
}

/// `for-each-ref` as `(oid, refname)`, sorted by refname.
pub async fn for_each_ref(git: &Path, repo_dir: &Path, pattern: Option<&str>) -> Result<Vec<(String, String)>> {
    let mut cmd = tokio::process::Command::new(git);
    cmd.args(["for-each-ref", "--format=%(objectname) %(refname)"]).env("GIT_DIR", repo_dir);
    if let Some(p) = pattern {
        cmd.arg(p);
    }
    let out = cmd.output().await?;
    if !out.status.success() {
        bail!("git for-each-ref: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(o, r)| (o.to_string(), r.to_string())))
        .collect())
}

/// A git blob hash of the `for-each-ref` listing: equal iff the refs are.
pub async fn refs_digest(git: &Path, repo_dir: &Path) -> Result<String> {
    let mut listing = String::new();
    for (oid, r) in for_each_ref(git, repo_dir, None).await? {
        listing.push_str(&format!("{oid} {r}\n"));
    }
    let mut child = tokio::process::Command::new(git)
        .args(["hash-object", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(listing.as_bytes()).await?;
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!("git hash-object failed");
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Journal entries this volume has not applied: `seq > marker.seq`. Non-empty
/// after a crash between the journal Create and the ref update (§2 crash table).
pub async fn unapplied(t: &BackupTarget, repo: &str, repo_dir: &Path) -> Result<Vec<JournalEntry>> {
    let at = read_marker(repo_dir)?.map(|m| m.seq).unwrap_or(0);
    journal::entries_after(t, repo, at).await
}

/// The single pack receive-pack left in quarantine, if any.
fn quarantine_pack(quarantine: Option<&Path>) -> Result<Option<PathBuf>> {
    let Some(q) = quarantine else { return Ok(None) };
    let dir = q.join("pack");
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut packs = Vec::new();
    for e in rd {
        let p = e?.path();
        if p.extension().is_some_and(|x| x == "pack") {
            packs.push(p);
        }
    }
    match packs.len() {
        0 => Ok(None),
        1 => Ok(packs.pop()),
        n => bail!("{n} packs in quarantine {}; expected at most one", dir.display()),
    }
}

/// Test-only crash injection: [`R2Log::append`] fails at this point once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPoint {
    /// After the pack PUT, before the journal Create.
    AfterPackPut,
    /// After the journal Create, before git moves the refs.
    AfterJournalCreate,
}

pub struct R2Log {
    pub target: BackupTarget,
    pub fence: Arc<Fence>,
    pub owner: String,
    pub git: PathBuf,
    /// Last `seq` this process appended, per repo (seeded from the marker).
    heads: Mutex<HashMap<String, u64>>,
    /// The `seq` a pre-receive appended, awaiting its post-receive.
    pending: Mutex<HashMap<String, u64>>,
    fault: Mutex<Option<FailPoint>>,
}

impl R2Log {
    pub fn new(target: BackupTarget, fence: Arc<Fence>, owner: &str, git: PathBuf) -> Self {
        Self {
            target,
            fence,
            owner: owner.to_string(),
            git,
            heads: Mutex::default(),
            pending: Mutex::default(),
            fault: Mutex::default(),
        }
    }

    pub fn inject(&self, f: FailPoint) {
        *self.fault.lock().unwrap() = Some(f);
    }

    fn take_fault(&self, at: FailPoint) -> Result<()> {
        let mut f = self.fault.lock().unwrap();
        if *f == Some(at) {
            *f = None;
            bail!("injected crash at {at:?}");
        }
        Ok(())
    }

    fn head(&self, repo: &str, repo_dir: &Path) -> Result<u64> {
        if let Some(h) = self.heads.lock().unwrap().get(repo) {
            return Ok(*h);
        }
        let h = read_marker(repo_dir)?.map(|m| m.seq).unwrap_or(0);
        self.heads.lock().unwrap().insert(repo.to_string(), h);
        Ok(h)
    }

    /// Steps 3–4 for one update set. Returns the appended `seq`. Caller holds
    /// the repo's push lock and has passed policy and the coarse fence.
    async fn durable(&self, repo: &str, repo_dir: &Path, pusher: &str, epoch: u64, quarantine: Option<&Path>, updates: &[RefUpdate]) -> Result<u64> {
        let seq = self.head(repo, repo_dir)? + 1;
        let (pack, pack_bytes) = match quarantine_pack(quarantine)? {
            Some(path) => {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
                if !layout::valid_pack_name(&name) {
                    bail!("unexpected quarantine pack name {name:?}");
                }
                let bytes = tokio::fs::read(&path).await.with_context(|| format!("reading {}", path.display()))?;
                let len = bytes.len() as u64;
                journal::put_create_idempotent(&self.target, &layout::pack_key(&self.target, repo, &name), bytes.into())
                    .await?;
                (Some(name), len)
            }
            None => (None, 0),
        };
        self.take_fault(FailPoint::AfterPackPut)?;
        let entry = JournalEntry {
            v: VERSION,
            repo: repo.to_string(),
            seq,
            epoch,
            owner: self.owner.clone(),
            at_unix_ms: journal::now_ms(),
            pusher: pusher.to_string(),
            pack,
            pack_bytes,
            updates: updates
                .iter()
                .map(|u| JournalUpdate { refname: u.refname.clone(), old: u.old.clone(), new: u.new.clone() })
                .collect(),
        };
        match journal::append(&self.target, &entry).await {
            Ok(()) => {}
            Err(e @ AppendError::Moved { .. }) => {
                self.fence.lose(format!("{repo}: {e}"));
                bail!("{e}");
            }
            Err(AppendError::Store(e)) => return Err(e),
        }
        self.heads.lock().unwrap().insert(repo.to_string(), seq);
        Ok(seq)
    }

    async fn mark(&self, repo_dir: &Path, seq: u64) -> Result<()> {
        let refs_digest = refs_digest(&self.git, repo_dir).await?;
        write_marker(repo_dir, &VolumeMarker { seq, refs_digest })
    }

    /// An internal journaled ref update (the §6 `refs/qed` GC): journal with
    /// `pusher = fleet-git:gc`, `pack = null`, then `git update-ref --stdin`
    /// (no hooks), then the marker. Caller holds the repo's push lock.
    pub async fn internal_update(&self, repo: &str, repo_dir: &Path, updates: &[RefUpdate]) -> Result<u64> {
        if updates.is_empty() {
            bail!("empty internal update");
        }
        match self.fence.check().await {
            crate::fence::FenceCheck::Holds => {}
            crate::fence::FenceCheck::Lost(l) => bail!("writer claim lost: {l}"),
            crate::fence::FenceCheck::Unknown(e) => bail!("could not confirm the writer claim: {e:#}"),
        }
        let seq = self.durable(repo, repo_dir, GC_PUSHER, self.fence.epoch(), None, updates).await?;
        let mut script = String::new();
        for u in updates {
            if is_zero(&u.new) {
                script.push_str(&format!("delete {} {}\n", u.refname, u.old));
            } else {
                script.push_str(&format!("update {} {} {}\n", u.refname, u.new, u.old));
            }
        }
        let mut child = tokio::process::Command::new(&self.git)
            .args(["update-ref", "--stdin"])
            .env("GIT_DIR", repo_dir)
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        child.stdin.take().unwrap().write_all(script.as_bytes()).await?;
        let out = child.wait_with_output().await?;
        if !out.status.success() {
            // The entry exists and the refs did not move: the §2 "after 4" crash
            // state, which F4's replay reconciles.
            bail!("journal entry {seq} written but git update-ref failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        self.mark(repo_dir, seq).await?;
        Ok(seq)
    }
}

#[async_trait::async_trait]
impl PushLog for R2Log {
    async fn append(&self, push: &AcceptedPush) -> Result<()> {
        let seq = self
            .durable(&push.repo, &push.repo_dir, &push.pusher, push.epoch, push.quarantine.as_deref(), &push.updates)
            .await?;
        self.pending.lock().unwrap().insert(push.repo.clone(), seq);
        self.take_fault(FailPoint::AfterJournalCreate)?;
        Ok(())
    }

    async fn committed(&self, push: &AcceptedPush) -> Result<()> {
        let Some(seq) = self.pending.lock().unwrap().remove(&push.repo) else {
            bail!("post-receive for {} with no pending journal entry", push.repo);
        };
        self.mark(&push.repo_dir, seq).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_roundtrip_and_quarantine_scan() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(read_marker(d.path()).unwrap(), None);
        let m = VolumeMarker { seq: 4, refs_digest: "abc".into() };
        write_marker(d.path(), &m).unwrap();
        assert_eq!(read_marker(d.path()).unwrap(), Some(m));

        assert_eq!(quarantine_pack(None).unwrap(), None);
        assert_eq!(quarantine_pack(Some(d.path())).unwrap(), None);
        std::fs::create_dir_all(d.path().join("pack")).unwrap();
        std::fs::write(d.path().join("pack/pack-1.idx"), b"").unwrap();
        assert_eq!(quarantine_pack(Some(d.path())).unwrap(), None);
        std::fs::write(d.path().join("pack/pack-1.pack"), b"").unwrap();
        assert!(quarantine_pack(Some(d.path())).unwrap().is_some());
        std::fs::write(d.path().join("pack/pack-2.pack"), b"").unwrap();
        assert!(quarantine_pack(Some(d.path())).is_err());
    }
}
