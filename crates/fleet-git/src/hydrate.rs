//! Startup rehydrate (W363 §3, §4, §8): the ONLY path that restores the volume
//! from R2, run on every start after the claim is taken and before serving.
//!
//! Per repo, WARM or COLD:
//!
//! - **WARM**: the volume marker is present, its `refs_digest` matches the
//!   refs on disk, and `journal/<marker.seq+1>` exists or nothing follows.
//!   Replay entries `> marker.seq`.
//! - **COLD**: wipe, `git init --bare` with the §1 config ([`repo::ensure`]),
//!   stream `latest.snapshot`'s pack and `git index-pack` it (the integrity
//!   check, and it builds the idx), set refs from `refs.json`, then replay
//!   entries `> snapshot.seq`.
//!
//! Replay downloads each entry's pack, `index-pack`s it, then applies the
//! updates with `git update-ref --stdin` (no hooks). Every ref must sit at
//! either its `old` or its `new`; anything else is divergence, and a WARM
//! repo that diverges goes COLD.
//!
//! Then [`startup`] asserts the claim (Superseded => the caller exits 0) and
//! runs `git fsck --connectivity-only` per repo, with one COLD retry. No full
//! fsck at startup. Deliberately not kamaji's `[durability]` hook: that is
//! turso-only, empty-volume-only, and takes no claim.

use crate::fence::{Fence, FenceCheck};
use crate::gitbin::GitInstall;
use crate::hook::is_zero;
use crate::journal::{self, retrying, JournalEntry};
use crate::layout;
use crate::repo;
use crate::snapshot::{git_ok, read_latest, SnapshotRef};
use crate::stream::{for_each_ref, read_marker, refs_digest, write_marker, VolumeMarker};
use anyhow::{bail, Context, Result};
use futures_util::TryStreamExt;
use object_store::ObjectStoreExt;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use store_claim::{join_key, BackupTarget};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Warm,
    Cold,
}

/// What one repo's rehydrate did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoReport {
    pub repo: String,
    pub mode: Mode,
    /// The snapshot (COLD) or marker (WARM) seq replay started after.
    pub base: u64,
    /// Seqs replayed, ascending.
    pub replayed: Vec<u64>,
    /// The journal position the volume now reflects.
    pub seq: u64,
    pub elapsed: std::time::Duration,
}

/// [`startup`]'s verdict.
#[derive(Debug)]
pub enum Startup {
    /// Rehydrated and connectivity-checked: serve.
    Ready(Vec<RepoReport>),
    /// The claim moved while rehydrating. Exit 0 (W363 §3), do not serve.
    Superseded(String),
}

/// Every repo with anything in the store (`repos/<name>/…`).
pub async fn store_repos(t: &BackupTarget) -> Result<Vec<String>> {
    let dir = join_key(&t.prefix, "repos");
    let res = retrying(|| t.store.list_with_delimiter(Some(&dir))).await.with_context(|| format!("LIST {dir}"))?;
    let mut out: Vec<String> = res
        .common_prefixes
        .iter()
        .filter_map(|p| p.filename().map(str::to_string))
        .filter(|n| repo::valid_name(n))
        .collect();
    out.sort();
    Ok(out)
}

/// W363 §4 steps 3–6 for every repo on the volume or in the store. `fence`
/// is already established (probe + acquire).
pub async fn startup(t: &BackupTarget, fence: &Fence, git: &GitInstall, root: &Path, hook_exe: &Path) -> Result<Startup> {
    std::fs::create_dir_all(root)?;
    let mut names: BTreeSet<String> = store_repos(t).await?.into_iter().collect();
    names.extend(repo::list(root)?);
    let mut reports = Vec::new();
    for name in &names {
        reports.push(hydrate(t, git, root, name, hook_exe, false).await?);
    }
    match fence.check().await {
        FenceCheck::Holds => {}
        FenceCheck::Lost(l) => return Ok(Startup::Superseded(l.to_string())),
        FenceCheck::Unknown(e) => return Err(e.context("asserting the claim after rehydrate")),
    }
    for r in reports.iter_mut() {
        let dir = repo::repo_dir(root, &r.repo);
        if let Err(e) = fsck(&git.git, &dir).await {
            tracing::warn!(repo = %r.repo, error = %format!("{e:#}"), "connectivity check failed; one cold retry");
            *r = hydrate(t, git, root, &r.repo, hook_exe, true).await?;
            fsck(&git.git, &dir).await.with_context(|| format!("{}: connectivity check failed after a cold retry", r.repo))?;
        }
    }
    Ok(Startup::Ready(reports))
}

pub async fn fsck(git: &Path, repo_dir: &Path) -> Result<()> {
    git_ok(git, repo_dir, &["fsck", "--connectivity-only", "--no-progress"], None).await.map(|_| ())
}

/// Rehydrate one repo: WARM when the marker allows it (and `force_cold` is
/// off), COLD otherwise or when a WARM replay diverges.
pub async fn hydrate(
    t: &BackupTarget,
    git: &GitInstall,
    root: &Path,
    name: &str,
    hook_exe: &Path,
    force_cold: bool,
) -> Result<RepoReport> {
    let started = std::time::Instant::now();
    let dir = repo::repo_dir(root, name);
    let seqs = journal::list_seqs(t, name).await?;
    if !force_cold && dir.join("HEAD").exists() {
        if let Some(m) = read_marker(&dir)? {
            let after: Vec<u64> = seqs.iter().copied().filter(|s| *s > m.seq).collect();
            let digest_ok = refs_digest(&git.git, &dir).await? == m.refs_digest;
            if digest_ok && after.first().is_none_or(|s| *s == m.seq + 1) {
                repo::ensure(git, root, name, hook_exe)?;
                match replay(t, &git.git, &dir, name, m.seq, &after).await {
                    Ok(seq) => {
                        let r = report(name, Mode::Warm, m.seq, after, seq, started);
                        tracing::info!(?r, "warm rehydrate");
                        return Ok(r);
                    }
                    Err(e) => tracing::warn!(repo = name, error = %format!("{e:#}"), "warm replay diverged; going cold"),
                }
            } else {
                tracing::info!(repo = name, marker = m.seq, digest_ok, next = ?after.first(), "volume not warm-replayable; going cold");
            }
        }
    }

    // COLD.
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("wiping {}", dir.display())),
    }
    repo::ensure(git, root, name, hook_exe)?;
    let base = match read_latest(t, name).await? {
        Some((latest, _, _)) => {
            let key = layout::snapshot_pack_key(t, name, latest.seq, &latest.pack);
            install_pack(t, &git.git, &dir, &key, &latest.pack).await?;
            let refs_key = layout::snapshot_refs_key(t, name, latest.seq);
            let bytes = retrying(|| t.store.get(&refs_key)).await.with_context(|| format!("GET {refs_key}"))?.bytes().await?;
            let refs: Vec<SnapshotRef> = serde_json::from_slice(&bytes).with_context(|| format!("parsing {refs_key}"))?;
            let script: String = refs.iter().map(|r| format!("create {} {}\n", r.refname, r.oid)).collect();
            if !script.is_empty() {
                git_ok(&git.git, &dir, &["update-ref", "--stdin"], Some(&script)).await?;
            }
            latest.seq
        }
        None => 0,
    };
    let after: Vec<u64> = seqs.into_iter().filter(|s| *s > base).collect();
    if after.first().is_some_and(|s| *s != base + 1) {
        bail!("{name}: journal starts at {} but the restore base is {base}: entries are missing", after[0]);
    }
    let seq = replay(t, &git.git, &dir, name, base, &after).await.with_context(|| format!("{name}: cold replay"))?;
    let r = report(name, Mode::Cold, base, after, seq, started);
    tracing::info!(?r, "cold rehydrate");
    Ok(r)
}

fn report(name: &str, mode: Mode, base: u64, replayed: Vec<u64>, seq: u64, started: std::time::Instant) -> RepoReport {
    RepoReport { repo: name.to_string(), mode, base, replayed, seq, elapsed: started.elapsed() }
}

/// Replay `seqs` (gap-free from `base + 1`) onto `dir`, writing the marker
/// after each entry. Returns the final seq.
async fn replay(t: &BackupTarget, git: &Path, dir: &Path, name: &str, base: u64, seqs: &[u64]) -> Result<u64> {
    let mut at = base;
    for &seq in seqs {
        if seq != at + 1 {
            bail!("journal gap: expected entry {} next, found {seq}", at + 1);
        }
        let entry = journal::read(t, name, seq).await?.with_context(|| format!("journal entry {seq} vanished"))?;
        apply(t, git, dir, name, &entry).await.with_context(|| format!("replaying entry {seq}"))?;
        at = seq;
        write_marker(dir, &VolumeMarker { seq, refs_digest: refs_digest(git, dir).await? })?;
    }
    if seqs.is_empty() {
        // A COLD base, or a WARM marker that was already current: (re)stamp it.
        write_marker(dir, &VolumeMarker { seq: at, refs_digest: refs_digest(git, dir).await? })?;
    }
    Ok(at)
}

async fn apply(t: &BackupTarget, git: &Path, dir: &Path, name: &str, e: &JournalEntry) -> Result<()> {
    if let Some(pack) = &e.pack {
        install_pack(t, git, dir, &layout::pack_key(t, name, pack), pack).await?;
    }
    let current: HashMap<String, String> = for_each_ref(git, dir, None).await?.into_iter().map(|(o, r)| (r, o)).collect();
    let mut script = String::new();
    for u in &e.updates {
        // R997-B18: git never applied an update to a malformed name, so it is
        // not state to restore; skip it rather than let one entry block startup.
        if !crate::hook::valid_refname(&u.refname) {
            tracing::warn!(repo = name, seq = e.seq, refname = ?u.refname, "skipping journalled update to an invalid refname");
            continue;
        }
        let at = current.get(&u.refname).map(String::as_str);
        let is = |want: &str| if is_zero(want) { at.is_none() } else { at == Some(want) };
        if is(&u.new) {
            continue;
        }
        if !is(&u.old) {
            bail!("{} is at {:?}, neither old {} nor new {}", u.refname, at, u.old, u.new);
        }
        if is_zero(&u.new) {
            script.push_str(&format!("delete {} {}\n", u.refname, u.old));
        } else {
            script.push_str(&format!("update {} {} {}\n", u.refname, u.new, u.old));
        }
    }
    if !script.is_empty() {
        git_ok(git, dir, &["update-ref", "--stdin"], Some(&script)).await?;
    }
    Ok(())
}

/// Stream `key` into `objects/pack/<pack>` and `git index-pack` it. A pack
/// already indexed on the volume is kept.
async fn install_pack(t: &BackupTarget, git: &Path, dir: &Path, key: &object_store::path::Path, pack: &str) -> Result<()> {
    if !layout::valid_pack_name(pack) {
        bail!("invalid pack name {pack:?} at {key}");
    }
    let packs = dir.join("objects/pack");
    let dest = packs.join(pack);
    if packs.join(pack.replace(".pack", ".idx")).exists() && dest.exists() {
        return Ok(());
    }
    tokio::fs::create_dir_all(&packs).await?;
    let tmp: PathBuf = packs.join(format!("{pack}.download"));
    let res = retrying(|| t.store.get(key)).await.with_context(|| format!("GET {key}"))?;
    let mut f = tokio::fs::File::create(&tmp).await?;
    let mut stream = res.into_stream();
    while let Some(chunk) = stream.try_next().await.with_context(|| format!("streaming {key}"))? {
        f.write_all(&chunk).await?;
    }
    f.sync_all().await?;
    drop(f);
    tokio::fs::rename(&tmp, &dest).await?;
    let path = dest.to_str().context("non-UTF-8 path")?;
    if let Err(e) = git_ok(git, dir, &["index-pack", path], None).await {
        let _ = tokio::fs::remove_file(&dest).await;
        return Err(e.context(format!("index-pack {key}")));
    }
    Ok(())
}
