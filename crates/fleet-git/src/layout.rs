//! The bucket's key layout (W363 §2 "Layout"). Every key this crate reads or
//! writes is built here, so F4's rehydrate reads exactly what F3 writes.
//!
//! ```text
//! latest.owner-claim                                  store_claim::claim
//! repos/<repo>/packs/<pack-name>.pack                 Create; AlreadyExists = ok; no .idx
//! repos/<repo>/journal/<seq:016>.json                 Create; gap-free from 1; the head AND the fork fence
//! repos/<repo>/snapshots/<seq:016>/<pack-name>.pack   Create
//! repos/<repo>/snapshots/<seq:016>/refs.json          Create, after the pack
//! repos/<repo>/latest.snapshot                        { seq, pack }, CAS'd last
//! ```
//!
//! There is deliberately no `latest.journal-head`: the highest existing
//! `journal/<seq>` is the head.

use object_store::path::Path as ObjPath;
use store_claim::{join_key, BackupTarget};

/// Width of the zero-padded `seq` in keys, so lexicographic listing is numeric order.
pub const SEQ_WIDTH: usize = 16;

pub fn seq_str(seq: u64) -> String {
    format!("{seq:0width$}", width = SEQ_WIDTH)
}

pub fn repo_prefix(t: &BackupTarget, repo: &str) -> ObjPath {
    join_key(&t.prefix, &format!("repos/{repo}"))
}

pub fn packs_dir(t: &BackupTarget, repo: &str) -> ObjPath {
    join_key(&t.prefix, &format!("repos/{repo}/packs"))
}

/// `pack` is the bare file name, `pack-<hex>.pack`.
pub fn pack_key(t: &BackupTarget, repo: &str, pack: &str) -> ObjPath {
    join_key(&t.prefix, &format!("repos/{repo}/packs/{pack}"))
}

pub fn journal_dir(t: &BackupTarget, repo: &str) -> ObjPath {
    join_key(&t.prefix, &format!("repos/{repo}/journal"))
}

pub fn journal_key(t: &BackupTarget, repo: &str, seq: u64) -> ObjPath {
    join_key(&t.prefix, &format!("repos/{repo}/journal/{}.json", seq_str(seq)))
}

pub fn snapshots_dir(t: &BackupTarget, repo: &str) -> ObjPath {
    join_key(&t.prefix, &format!("repos/{repo}/snapshots"))
}

pub fn snapshot_dir(t: &BackupTarget, repo: &str, seq: u64) -> ObjPath {
    join_key(&t.prefix, &format!("repos/{repo}/snapshots/{}", seq_str(seq)))
}

pub fn snapshot_pack_key(t: &BackupTarget, repo: &str, seq: u64, pack: &str) -> ObjPath {
    join_key(&t.prefix, &format!("repos/{repo}/snapshots/{}/{pack}", seq_str(seq)))
}

pub fn snapshot_refs_key(t: &BackupTarget, repo: &str, seq: u64) -> ObjPath {
    join_key(&t.prefix, &format!("repos/{repo}/snapshots/{}/refs.json", seq_str(seq)))
}

pub fn latest_snapshot_key(t: &BackupTarget, repo: &str) -> ObjPath {
    join_key(&t.prefix, &format!("repos/{repo}/latest.snapshot"))
}

/// `…/journal/<seq:016>.json` → `seq`.
pub fn parse_journal_key(key: &ObjPath) -> Option<u64> {
    let leaf = key.filename()?;
    let digits = leaf.strip_suffix(".json")?;
    (digits.len() == SEQ_WIDTH).then(|| digits.parse().ok()).flatten()
}

/// `…/snapshots/<seq:016>/<leaf>` → `(seq, leaf)`.
pub fn parse_snapshot_key(key: &ObjPath) -> Option<(u64, String)> {
    let parts: Vec<_> = key.parts().map(|p| p.as_ref().to_string()).collect();
    let n = parts.len();
    if n < 3 || parts[n - 3] != "snapshots" || parts[n - 2].len() != SEQ_WIDTH {
        return None;
    }
    Some((parts[n - 2].parse().ok()?, parts[n - 1].clone()))
}

/// A quarantine / pack-objects file name is `pack-<40 or 64 hex>.pack`.
pub fn valid_pack_name(name: &str) -> bool {
    name.strip_prefix("pack-")
        .and_then(|s| s.strip_suffix(".pack"))
        .is_some_and(|h| (h.len() == 40 || h.len() == 64) && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use std::sync::Arc;

    #[test]
    fn keys_match_w363() {
        let t = BackupTarget { store: Arc::new(InMemory::new()), prefix: String::new() };
        assert_eq!(journal_key(&t, "yah", 7).as_ref(), "repos/yah/journal/0000000000000007.json");
        assert_eq!(pack_key(&t, "yah", "pack-ab.pack").as_ref(), "repos/yah/packs/pack-ab.pack");
        assert_eq!(snapshot_refs_key(&t, "yah", 12).as_ref(), "repos/yah/snapshots/0000000000000012/refs.json");
        assert_eq!(latest_snapshot_key(&t, "yah").as_ref(), "repos/yah/latest.snapshot");
        let p = BackupTarget { store: Arc::new(InMemory::new()), prefix: "/x/".into() };
        assert_eq!(journal_key(&p, "r", 1).as_ref(), "x/repos/r/journal/0000000000000001.json");
        assert_eq!(parse_journal_key(&journal_key(&p, "r", 42)), Some(42));
        assert_eq!(parse_journal_key(&ObjPath::from("repos/r/journal/42.json")), None);
        let k = snapshot_pack_key(&t, "yah", 9, "pack-cd.pack");
        assert_eq!(parse_snapshot_key(&k), Some((9, "pack-cd.pack".into())));
        assert!(valid_pack_name(&format!("pack-{}.pack", "a".repeat(40))));
        assert!(!valid_pack_name("pack-zz.pack"));
    }
}
