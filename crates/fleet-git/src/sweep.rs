//! Sweep behind the snapshot (W363 §2), and the ephemeral ref GC (§6): 7-day
//! `refs/qed`, 30-day `refs/camp-host`.
//!
//! Sweep runs after each `latest.snapshot` move and keeps the newest **two**
//! complete snapshots. It deletes journal entries, and the packs they name,
//! with `seq` at or below the older kept snapshot; snapshot directories other
//! than the two kept (one older than the latest, or abandoned for over 1 h);
//! and packs no retained entry names that are older than 1 h (a crash between
//! pack PUT and journal Create, §2 crash table). It never runs in the push path.
//!
//! The ephemeral GC deletes `refs/qed/*` whose creating journal entry is more
//! than 7 days old, as an internal journaled update (`pusher = fleet-git:gc`,
//! `pack = null`). R971-F5 chains each QED snapshot commit on the staging
//! repo's newest `refs/qed` tip (restarting parentless once the chain root is
//! older than 6 d), so deleting an old ref usually leaves its objects reachable
//! through newer refs chained on it. That is expected, not a leak: a chain's
//! objects free once every ref in it ages out.
//!
//! `refs/camp-host/**` (a planned host move's park, W368 §7) ages out the same
//! way after 30 days ([`PARK_MAX_AGE`], R975-F23): `unpark` deletes it on the
//! normal path, so only an abandoned move ever reaches the GC.
//!
//! `refs/relays/**` is never aged (R979-T2, W365 §7 item 1): fleet-git does
//! not infer relay liveness, and neither does the node. The camp's single
//! relay-release act, at archive or re-placement, deletes
//! `refs/relays/<R>/{base,tip}` under that relay's `git_ref` claim
//! (`hook::check_ref_claim`) and clears the node's relay mount marker
//! (R979-F3). Chain growth is bounded by restarting the tip chain from the new
//! base at every refresh; the old chain then drops out of the volume at the
//! next snapshot's `repack -a -d` and out of R2 once that snapshot is the older
//! kept one (journal packs at or below it are swept above).

use crate::hook::RefUpdate;
use crate::journal::{self, retrying};
use crate::layout;
use crate::snapshot::read_latest;
use crate::stream::{for_each_ref, R2Log};
use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use object_store::ObjectStoreExt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::Duration;
use store_claim::BackupTarget;

pub const UNREFERENCED_GRACE: Duration = Duration::from_secs(3600);
pub const EPHEMERAL_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
/// A planned host move's park nobody unparked (R975-F23, W368 §7): long
/// enough to cover an operator away for a while, short enough that an
/// abandoned move does not pin its objects forever.
pub const PARK_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    pub journal_deleted: usize,
    pub packs_deleted: usize,
    pub snapshot_objects_deleted: usize,
}

async fn delete(t: &BackupTarget, key: &object_store::path::Path) -> Result<()> {
    match retrying(|| t.store.delete(key)).await {
        Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("DELETE {key}")),
    }
}

/// @yah:ticket(R979-T2, "fleet-git lifecycle for refs/relays/**: never age-GC a live relay, delete at archive, and bound the object growth of per-build chained snapshots")
/// @yah:status(review)
/// @yah:at(2026-10-13T12:41:28Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:phase(P1)
/// @yah:parent(R979)
/// @yah:next("Tier: Cleric. Durability path on the fleet's only git remote.")
/// @yah:next("W365 section 7 item 1, the half R978-F4 does not carry (R978-F4 adds the namespace and the ref-scoped write claim to hook.rs/auth.rs). Read: sweep.rs ages only refs/qed/* (EPHEMERAL_MAX_AGE, 7 days), so refs/relays/** is not age-GC'd by default. Keep it that way, and pin it with a test so a later widening of the ephemeral GC cannot silently start reaping relay tips.")
/// @yah:next("Deletion at archive: the camp, which owns relay liveness, deletes refs/relays/<R>/{base,tip} when the relay archives. Today the push token cannot delete refs (R971-F4's leftover drill refs). The delete rides R978-F4's ref-scoped claim; do not mint a broad delete credential.")
/// @yah:next("Growth: every relocated build pushes a tip chained on the previous one, so a long relay keeps every snapshot reachable. Inference to verify: sweep already drops journal entries at or below the older kept snapshot, so the journal itself may be bounded already; reachable objects are not. Decide the bound (restart the chain from base at refresh, or squash on refresh) and write it into W365 section 7 item 1.")
/// @yah:verify("fleet-git unit tests: a refs/relays ref older than EPHEMERAL_MAX_AGE survives sweep; a delete under the relay's claim succeeds; a delete outside it is refused.")
/// @yah:verify("W365 section 7 item 1 states the chosen growth bound.")
/// @yah:depends_on(R979-S1)
/// @yah:depends_on(R978-F4)
/// @yah:files(oss/yubaba/crates/fleet-git/src/sweep.rs)
/// @yah:files(oss/yubaba/crates/fleet-git/src/journal.rs)
/// @yah:handoff("No-age-GC pinned: tests/roundtrip.rs relay_refs_survive_the_ephemeral_gc (refs/relays/R1/{base,tip} survive gc_ephemeral at 2x EPHEMERAL_MAX_AGE while a refs/qed ref is reaped). Delete at archive needed NO server change: R978-F4's check_policy already allows delete in refs/relays/** under the relays grant, and R969-T12's git_ref claim (check_ref_claim) confines it to refs/relays/<R>/; R971-F4's leftover drill refs predate that grant. Added to push_clone_policy_and_fence: an R2-claimed token and a read token cannot delete R1's base/tip; the R1-claimed token deletes both. No broad delete credential. Liveness note (camp's single relay-release deletes the refs and clears R979-F3's mount marker; fleet-git and node infer nothing) in sweep.rs module doc. Growth: inference verified (sweep deletes journal entries+packs with seq <= older kept snapshot). Collection of the old chain: snapshot uses pack-objects --revs from live refs so R2 drops it once that snapshot is swept; volume drops it at repack -a -d -l (receive.unpackLimit=1 so all pushes are packs; -a -d dropping unreachable packed objects is from git's documented semantics, not tested here). Written into W365 s7 item 1; no child filed since something does collect.")
/// @yah:verify("cargo test -p fleet-git (oss/yubaba): 31 passed, 0 failed, 1 ignored (21 unit, 9 roundtrip, 1 tail_cost); F4's recorded baseline was 29. No other crates touched.")
pub async fn sweep(t: &BackupTarget, repo: &str, now_ms: u64) -> Result<SweepReport> {
    let mut report = SweepReport::default();
    let Some((latest, _, _)) = read_latest(t, repo).await? else { return Ok(report) };
    let grace = UNREFERENCED_GRACE.as_millis() as u64;

    // Snapshot dirs: seq -> (leaves, newest mtime, keys).
    let dir = layout::snapshots_dir(t, repo);
    let metas: Vec<_> = t.store.list(Some(&dir)).try_collect().await.with_context(|| format!("LIST {dir}"))?;
    let mut snaps: BTreeMap<u64, (HashSet<String>, u64, Vec<object_store::path::Path>)> = BTreeMap::new();
    for m in metas {
        if let Some((seq, leaf)) = layout::parse_snapshot_key(&m.location) {
            let s = snaps.entry(seq).or_default();
            s.0.insert(leaf);
            s.1 = s.1.max(m.last_modified.timestamp_millis().max(0) as u64);
            s.2.push(m.location);
        }
    }
    let older = snaps
        .iter()
        .filter(|(seq, s)| **seq < latest.seq && s.0.contains("refs.json"))
        .map(|(seq, _)| *seq)
        .next_back();
    for (seq, (_, mtime, keys)) in &snaps {
        let kept = *seq == latest.seq || Some(*seq) == older;
        if !kept && (*seq < latest.seq || now_ms.saturating_sub(*mtime) > grace) {
            for k in keys {
                delete(t, k).await?;
                report.snapshot_objects_deleted += 1;
            }
        }
    }

    // Journal entries at or below the older kept snapshot, and the packs they name.
    let cutoff = older.unwrap_or(0);
    let mut swept_packs = HashSet::new();
    let mut retained_packs = HashSet::new();
    for seq in journal::list_seqs(t, repo).await? {
        let Some(e) = journal::read(t, repo, seq).await? else { continue };
        if seq <= cutoff {
            if let Some(p) = e.pack {
                swept_packs.insert(p);
            }
            delete(t, &layout::journal_key(t, repo, seq)).await?;
            report.journal_deleted += 1;
        } else if let Some(p) = e.pack {
            retained_packs.insert(p);
        }
    }
    let pdir = layout::packs_dir(t, repo);
    let packs: Vec<_> = t.store.list(Some(&pdir)).try_collect().await.with_context(|| format!("LIST {pdir}"))?;
    for m in packs {
        let Some(name) = m.location.filename().map(str::to_string) else { continue };
        if retained_packs.contains(&name) {
            continue;
        }
        let old = now_ms.saturating_sub(m.last_modified.timestamp_millis().max(0) as u64) > grace;
        if swept_packs.contains(&name) || old {
            delete(t, &m.location).await?;
            report.packs_deleted += 1;
        }
    }
    tracing::info!(repo, latest = latest.seq, older = ?older, ?report, "fleet-git sweep");
    Ok(report)
}

/// One namespace the ephemeral GC ages out: refs under `prefix` whose creating
/// journal entry is older than `max_age`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgeOut {
    pub prefix: &'static str,
    pub max_age: Duration,
}

/// Every namespace fleet-git ages out, in one GC pass. `refs/relays/**` is
/// deliberately absent (module doc).
pub const AGE_OUTS: &[AgeOut] = &[
    AgeOut { prefix: "refs/qed/", max_age: EPHEMERAL_MAX_AGE },
    AgeOut { prefix: crate::auth::CAMP_HOST_PREFIX, max_age: PARK_MAX_AGE },
];

/// The §6 GC. Caller holds `repo`'s push lock. A ref's "creating entry" is the
/// newest retained entry that set it to its current oid. If the sweep already
/// removed it, the ref is at least as old as the oldest retained entry, which
/// is the age used. Every namespace in `age_outs` expires in one journaled
/// update. Returns the GC entry's `seq`, if one was written.
pub async fn gc_ephemeral(log: &R2Log, repo: &str, repo_dir: &Path, now_ms: u64, age_outs: &[AgeOut]) -> Result<Option<u64>> {
    let mut refs: Vec<(String, String, Duration)> = Vec::new();
    for a in age_outs {
        let found = for_each_ref(&log.git, repo_dir, Some(a.prefix)).await?;
        refs.extend(found.into_iter().map(|(oid, r)| (oid, r, a.max_age)));
    }
    if refs.is_empty() {
        return Ok(None);
    }
    let entries = journal::entries_after(&log.target, repo, 0).await?;
    let oldest = entries.first().map(|e| e.at_unix_ms).unwrap_or(now_ms);
    let mut created: HashMap<(&str, &str), u64> = HashMap::new();
    for e in &entries {
        for u in &e.updates {
            created.insert((u.refname.as_str(), u.new.as_str()), e.at_unix_ms);
        }
    }
    let zero = "0".repeat(refs[0].0.len());
    let expired: Vec<RefUpdate> = refs
        .iter()
        .filter(|(oid, r, max_age)| {
            let at = created.get(&(r.as_str(), oid.as_str())).copied().unwrap_or(oldest);
            now_ms.saturating_sub(at) > max_age.as_millis() as u64
        })
        .map(|(oid, r, _)| RefUpdate { old: oid.clone(), new: zero.clone(), refname: r.clone() })
        .collect();
    if expired.is_empty() {
        return Ok(None);
    }
    let seq = log.internal_update(repo, repo_dir, &expired).await?;
    tracing::info!(repo, seq, deleted = expired.len(), "fleet-git ephemeral ref GC");
    Ok(Some(seq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{append, JournalEntry, VERSION};
    use crate::snapshot::LatestSnapshot;
    use object_store::memory::InMemory;
    use std::sync::Arc;

    fn e(seq: u64, pack: Option<&str>) -> JournalEntry {
        JournalEntry {
            v: VERSION,
            repo: "r".into(),
            seq,
            epoch: 1,
            owner: "o".into(),
            at_unix_ms: 0,
            pusher: "p".into(),
            pack: pack.map(str::to_string),
            pack_bytes: 0,
            updates: vec![],
        }
    }

    async fn keys(t: &BackupTarget) -> Vec<String> {
        let mut v: Vec<String> =
            t.store.list(None).map_ok(|m| m.location.to_string()).try_collect().await.unwrap();
        v.sort();
        v
    }

    #[tokio::test]
    async fn keeps_two_snapshots_and_what_follows_the_older() {
        let t = BackupTarget { store: Arc::new(InMemory::new()), prefix: String::new() };
        let put = |k: object_store::path::Path| {
            let s = t.store.clone();
            async move { s.put(&k, b"x".to_vec().into()).await.unwrap() }
        };
        for seq in 1..=6 {
            let p = format!("pack-{seq}.pack");
            append(&t, &e(seq, Some(&p))).await.unwrap();
            put(layout::pack_key(&t, "r", &p)).await;
        }
        put(layout::pack_key(&t, "r", "pack-orphan.pack")).await;
        for s in [2, 4, 5] {
            put(layout::snapshot_pack_key(&t, "r", s, "pack-s.pack")).await;
            put(layout::snapshot_refs_key(&t, "r", s)).await;
        }
        // A torn snapshot (no refs.json) below the latest.
        put(layout::snapshot_pack_key(&t, "r", 3, "pack-s.pack")).await;
        let latest = LatestSnapshot { seq: 5, pack: "pack-s.pack".into() };
        t.store
            .put(&layout::latest_snapshot_key(&t, "r"), serde_json::to_vec(&latest).unwrap().into())
            .await
            .unwrap();

        // Now: the orphan pack is fresh, so it survives this pass.
        let r = sweep(&t, "r", journal::now_ms()).await.unwrap();
        assert_eq!(r, SweepReport { journal_deleted: 4, packs_deleted: 4, snapshot_objects_deleted: 3 });
        let want = |orphan: bool| {
            let mut v = vec![
                "repos/r/journal/0000000000000005.json".to_string(),
                "repos/r/journal/0000000000000006.json".into(),
                "repos/r/latest.snapshot".into(),
                "repos/r/packs/pack-5.pack".into(),
                "repos/r/packs/pack-6.pack".into(),
                "repos/r/snapshots/0000000000000004/pack-s.pack".into(),
                "repos/r/snapshots/0000000000000004/refs.json".into(),
                "repos/r/snapshots/0000000000000005/pack-s.pack".into(),
                "repos/r/snapshots/0000000000000005/refs.json".into(),
            ];
            if orphan {
                v.push("repos/r/packs/pack-orphan.pack".into());
            }
            v.sort();
            v
        };
        assert_eq!(keys(&t).await, want(true));
        // Over an hour later the unreferenced pack goes too.
        sweep(&t, "r", journal::now_ms() + 2 * 3600 * 1000).await.unwrap();
        assert_eq!(keys(&t).await, want(false));
    }
}
