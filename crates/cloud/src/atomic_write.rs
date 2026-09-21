//! Write-then-rename with a staging path no other writer can collide on.
//!
//! R925. A fixed staging path — `path.with_extension("tmp")`, `format!("{p}.tmp")`
//! — is shared by *every* concurrent writer of that file. Two writers interleave
//! into the one staging file and whichever renames second publishes a truncated
//! or spliced result. This is not theoretical: `~/.yah/slots.json` was found
//! corrupt on disk on 2026-09-17 (3719 bytes ending in `]]`, valid at exactly
//! minus one byte) from precisely that race. Malformed JSON projects as EMPTY
//! downstream rather than erroring, so it presents as silent wrong behaviour.
//!
//! The staging name here is disambiguated by pid **and** a per-process sequence
//! counter, so it is unique across processes sharing a directory (the `.yah/cache`
//! tree under one workspace is written by every `yah` process in it) and across
//! concurrent tasks inside one process.
//!
//! # Why this is not `kg::atomic_write`
//!
//! `oss/yubaba` is an independent Cargo workspace that has to stay buildable when
//! exported standalone, so it cannot depend on the monorepo's `kg` crate. The
//! prior art this copies is `oss/cheers/crates/cheers-store/src/atomic_file.rs`,
//! which is a separate module in a separate OSS workspace for the same reason.
//!
//! # Removing the staging file is load-bearing
//!
//! A successful `rename` consumes the staging file. A *failed* one does not, and
//! because the name is now unique per writer, a leaked staging file is never
//! reused — they accumulate without bound in a long-lived cache directory. Both
//! writers below delete the staging file when the rename fails. Any new caller
//! that builds a staging path with [`staging_path`] and renames by hand owes the
//! same cleanup on every error path it can take after the file exists.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};

/// Monotonic within this process; combined with the pid it makes every staging
/// path distinct from every other writer's, anywhere.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// A staging sibling of `path` that no other writer will pick:
/// `<file-name>.<pid>.<seq>.tmp`.
///
/// Kept ending in `.tmp` so the leak checks that sweep for stray temp files
/// (`yubaba-consensus`'s `writes_land_atomically_and_leave_no_temp_file`, the
/// transform executor's "the output element is the one ending in `.tmp`") still
/// recognise it.
///
/// Deliberately *not* opened `create_new`/O_EXCL by the writers below: pids are
/// recycled, so a staging file leaked by a previous boot could otherwise wedge a
/// path permanently. Truncating over it is the recovering behaviour.
pub(crate) fn staging_path(path: &Path) -> PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.{seq}.tmp", std::process::id()));
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

/// `create_dir_all` the parent of `path`, tolerating a bare filename.
fn create_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => std::fs::create_dir_all(parent),
        _ => Ok(()),
    }
}

/// Replace `path` with `bytes`: create the parent, write a uniquely-named
/// staging sibling, rename it over the target, and remove the staging file if
/// the rename fails.
///
/// Uses default permissions. A caller staging key material or a secret blob at
/// an explicit mode (0600) must keep its own hand-rolled writer rather than
/// route through here — see `yubaba::tenant_passway::write_if_changed`.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    create_parent(path).with_context(|| {
        format!(
            "creating parent directory for {} before an atomic write",
            path.display()
        )
    })?;
    let tmp = staging_path(path);
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("renaming {} → {}", tmp.display(), path.display()));
    }
    Ok(())
}

/// [`write_atomic`] on tokio's filesystem pool, for the async reconciler paths.
pub(crate) async fn write_atomic_async(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
    }
    let tmp = staging_path(path);
    tokio::fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("writing {}", tmp.display()))?;
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e).with_context(|| format!("renaming {} → {}", tmp.display(), path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_paths_never_repeat_within_a_process() {
        let target = Path::new("/tmp/does-not-matter/state.json");
        let a = staging_path(target);
        let b = staging_path(target);
        assert_ne!(a, b, "two writers of one path must not share a staging file");
        assert_eq!(a.parent(), target.parent(), "staging stays a sibling");
        for p in [&a, &b] {
            let name = p.file_name().unwrap().to_str().unwrap();
            assert!(name.starts_with("state.json."), "{name}");
            assert!(name.ends_with(".tmp"), "{name}");
        }
    }

    #[test]
    fn a_bare_filename_stages_beside_itself() {
        let p = staging_path(Path::new("state.json"));
        assert_eq!(p.parent(), Some(Path::new("")));
        assert!(p.to_str().unwrap().starts_with("state.json."));
    }

    #[test]
    fn write_atomic_creates_the_parent_and_leaves_no_staging_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("nested/deeper/state.json");
        write_atomic(&target, b"{}").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"{}");
        let strays: Vec<_> = std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty(), "leaked staging files: {strays:?}");
    }

    #[tokio::test]
    async fn write_atomic_async_round_trips() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("ac/key.out");
        write_atomic_async(&target, b"hash\n").await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hash\n");
    }

    /// The failure the cleanup exists for: renaming onto a *directory* fails,
    /// and without the `remove_file` the staging sibling would survive under a
    /// name no later writer ever reuses.
    #[test]
    fn a_failed_rename_removes_the_staging_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("occupied");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("child"), b"x").unwrap();
        assert!(write_atomic(&target, b"bytes").is_err());
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty(), "leaked staging files: {strays:?}");
    }
}
