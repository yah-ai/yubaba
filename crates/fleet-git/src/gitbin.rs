//! Finding the host's own git, and refusing to start without a usable one.
//!
//! Operator call (R971-F2, form F4372): the server execs whatever
//! `git http-backend` the host's git ships, located through `git --exec-path`,
//! never a hardcoded `/usr/libexec/git-core`. Alpine puts the backend in the
//! `git-daemon` package under `/usr/libexec/git-core`; Debian/Ubuntu ship it in
//! `git` itself under `/usr/lib/git-core`; macOS (Xcode) under the developer
//! dir. `--exec-path` answers all of them, so the workload runs natively on any
//! host with system git and not only from the container image.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Oldest git this server accepts.
///
/// 2.25 is Ubuntu 20.04's git, the oldest glibc distro git we expect to meet.
/// Everything the server leans on is older than that: receive-pack quarantine
/// and `$GIT_QUARANTINE_PATH` (2.11 / 2.13), protocol v2 over HTTP via
/// `GIT_PROTOCOL` (2.18), `receive.fsckObjects` and `receive.unpackLimit`.
pub const MIN_GIT: (u32, u32) = (2, 25);

/// The git install this process will exec, as probed at startup.
#[derive(Debug, Clone)]
pub struct GitInstall {
    /// `git` as found on `PATH`.
    pub git: PathBuf,
    /// `git --exec-path`.
    pub exec_path: PathBuf,
    /// `<exec-path>/git-http-backend`, checked executable.
    pub http_backend: PathBuf,
    /// Parsed `git --version`.
    pub version: (u32, u32, u32),
}

/// Probe the host's git: present, new enough, and shipping an executable
/// `git-http-backend`. Every failure names what to install.
pub fn probe() -> Result<GitInstall> {
    let git = PathBuf::from("git");
    let out = Command::new(&git).arg("--version").output().map_err(|e| {
        anyhow::anyhow!(
            "fleet-git needs the host's git and could not run `git --version`: {e}. \
             Install git (Alpine: `apk add git git-daemon`; Debian/Ubuntu: `apt-get install git`)."
        )
    })?;
    if !out.status.success() {
        bail!("`git --version` exited {}", out.status);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let version = parse_version(&text)
        .with_context(|| format!("could not parse `git --version` output {:?}", text.trim()))?;
    if (version.0, version.1) < MIN_GIT {
        bail!(
            "git {}.{}.{} is older than the minimum {}.{} fleet-git supports",
            version.0,
            version.1,
            version.2,
            MIN_GIT.0,
            MIN_GIT.1
        );
    }

    let out = Command::new(&git)
        .arg("--exec-path")
        .output()
        .context("running `git --exec-path`")?;
    if !out.status.success() {
        bail!("`git --exec-path` exited {}", out.status);
    }
    let exec_path = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    let http_backend = exec_path.join("git-http-backend");
    if !is_executable(&http_backend) {
        bail!(
            "git {}.{}.{} has no executable git-http-backend at {} (from `git --exec-path`). \
             On Alpine it ships in the `git-daemon` package: `apk add git-daemon`.",
            version.0,
            version.1,
            version.2,
            http_backend.display()
        );
    }
    Ok(GitInstall { git, exec_path, http_backend, version })
}

/// Parse `git version 2.50.1 (Apple Git-155)` / `git version 2.39.5` /
/// `git version 2.49.0.windows.1` into `(major, minor, patch)`.
pub fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let v = s.trim().strip_prefix("git version ")?;
    let v = v.split_whitespace().next()?;
    let mut parts = v.split('.').map(|p| p.parse::<u32>());
    let major = parts.next()?.ok()?;
    let minor = parts.next()?.ok()?;
    let patch = parts.next().and_then(|p| p.ok()).unwrap_or(0);
    Some((major, minor, patch))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_distro_version_strings() {
        assert_eq!(parse_version("git version 2.50.1 (Apple Git-155)\n"), Some((2, 50, 1)));
        assert_eq!(parse_version("git version 2.39.5"), Some((2, 39, 5)));
        assert_eq!(parse_version("git version 2.49.0.windows.1"), Some((2, 49, 0)));
        assert_eq!(parse_version("git version 2.25"), Some((2, 25, 0)));
        assert_eq!(parse_version("hg version 6"), None);
    }

    #[test]
    fn probe_finds_this_hosts_git() {
        let g = probe().expect("this host has a usable git");
        assert!(g.http_backend.starts_with(&g.exec_path));
        assert!((g.version.0, g.version.1) >= MIN_GIT);
    }
}
