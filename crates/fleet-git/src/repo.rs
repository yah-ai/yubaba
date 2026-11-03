//! Bare repos on the volume: naming, creation, config and hook install.

use crate::gitbin::GitInstall;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Config every bare repo carries (W363 §1). Deliberately no `receive.deny*`:
/// `pre-receive` runs before git's deny checks, so the hook is the single owner
/// of ref policy (W363 §2 "Ack semantics").
pub const REPO_CONFIG: &[(&str, &str)] = &[
    // Every push carrying an object lands as a self-contained pack.
    ("receive.unpackLimit", "1"),
    ("receive.fsckObjects", "true"),
    // The supervisor authenticates before CGI runs.
    ("http.receivepack", "true"),
    // Bounds index-pack RSS (W363 §8).
    ("pack.threads", "2"),
];

/// A repo name is one path segment of `[A-Za-z0-9._-]`, not starting with `.`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub fn repo_dir(root: &Path, name: &str) -> PathBuf {
    root.join(format!("{name}.git"))
}

/// Inverse of [`repo_dir`]: which repo a hook's `$GIT_DIR` belongs to.
pub fn name_of(root: &Path, dir: &Path) -> Option<String> {
    let rel = dir.strip_prefix(root).ok()?;
    let mut comps = rel.components();
    let only = comps.next()?.as_os_str().to_str()?;
    if comps.next().is_some() {
        return None;
    }
    let name = only.strip_suffix(".git")?;
    valid_name(name).then(|| name.to_string())
}

/// Every repo under `root`.
pub fn list(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str().and_then(|n| n.strip_suffix(".git")) {
            if valid_name(name) && entry.file_type()?.is_dir() {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Create `name` if absent, then (re)apply config and hooks. Idempotent, so
/// startup runs it over every repo: the hooks name this binary's path, which
/// can move between images or hosts.
pub fn ensure(git: &GitInstall, root: &Path, name: &str, hook_exe: &Path) -> Result<PathBuf> {
    if !valid_name(name) {
        bail!("invalid repo name {name:?}");
    }
    let dir = repo_dir(root, name);
    if !dir.join("HEAD").exists() {
        run_git(git, root, &["init", "--bare", "--quiet", &format!("{name}.git")])?;
        // Not `init -b`: that needs git 2.28, above MIN_GIT.
        run_git(git, &dir, &["symbolic-ref", "HEAD", "refs/heads/main"])?;
    }
    for (k, v) in REPO_CONFIG {
        run_git(git, &dir, &["config", k, v])?;
    }
    install_hooks(&dir, hook_exe)?;
    Ok(dir)
}

fn install_hooks(dir: &Path, hook_exe: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let hooks = dir.join("hooks");
    std::fs::create_dir_all(&hooks)?;
    let exe = shell_quote(&hook_exe.to_string_lossy());
    for stage in ["pre-receive", "post-receive"] {
        let path = hooks.join(stage);
        std::fs::write(&path, format!("#!/bin/sh\nexec {exe} hook {stage}\n"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn run_git(git: &GitInstall, cwd: &Path, args: &[&str]) -> Result<()> {
    let out = Command::new(&git.git)
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .with_context(|| format!("running git {args:?}"))?;
    if !out.status.success() {
        bail!("git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("yah"));
        assert!(valid_name("noise-table_2.x"));
        for bad in ["", ".git", "..", "a/b", "a b", "../x"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        let root = Path::new("/var/lib/fleet-git");
        assert_eq!(name_of(root, &repo_dir(root, "yah")).as_deref(), Some("yah"));
        assert_eq!(name_of(root, Path::new("/var/lib/fleet-git/a/b.git")), None);
        assert_eq!(name_of(root, Path::new("/elsewhere/yah.git")), None);
    }

    #[test]
    fn ensure_creates_configured_repo_with_hooks() {
        let git = crate::gitbin::probe().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dir = ensure(&git, tmp.path(), "yah", Path::new("/opt/fleet git/bin")).unwrap();
        let cfg = std::fs::read_to_string(dir.join("config")).unwrap();
        assert!(cfg.contains("unpackLimit = 1"), "{cfg}");
        assert!(!cfg.contains("deny"), "{cfg}");
        let hook = std::fs::read_to_string(dir.join("hooks/pre-receive")).unwrap();
        assert_eq!(hook, "#!/bin/sh\nexec '/opt/fleet git/bin' hook pre-receive\n");
        assert_eq!(list(tmp.path()).unwrap(), vec!["yah".to_string()]);
        // Idempotent.
        ensure(&git, tmp.path(), "yah", Path::new("/x")).unwrap();
    }
}
