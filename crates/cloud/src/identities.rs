//! Stub local identity registry: `.yah/cloud/identities/<machine>.json`.
//!
//! Phase 1 (R092-F8) bootstrap layer. The "broker" is a local JSON file; once
//! R034 ships a real global identity broker, the CLI will POST there as well.
//! Until then, the local file IS the source of truth for machine hostkeys.
//!
//! Self-attested mode: fingerprints written here carry `self_attested: true`.
//! The re-sign step (posting to the real R034 broker and clearing the flag)
//! is gated on broker availability and ships as a follow-on.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A machine's hostkey fingerprint entry in the local stub registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalIdentity {
    /// Machine name, matches `machines/<machine>.toml`.
    pub machine: String,
    /// OpenSSH-style fingerprint, e.g. `SHA256:abc123…` (no padding).
    pub fingerprint: String,
    /// Algorithm, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// UNIX epoch seconds when this entry was last written.
    pub attested_at_secs: u64,
    /// `true` until the entry has been confirmed by a real identity broker
    /// (R034). Self-attested entries are valid for Phase 1; re-sign via
    /// `yah cloud identity re-sign` once the broker is deployed.
    pub self_attested: bool,
}

/// Write (or overwrite) a machine's fingerprint to the stub local registry.
///
/// Path: `<cloud_dir>/identities/<machine>.json`.
/// Uses a write-tmp + rename so the file is never left in a partial state.
pub fn register(
    cloud_dir: &Path,
    machine: &str,
    fingerprint: &str,
    algorithm: &str,
) -> Result<()> {
    let dir = cloud_dir.join("identities");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating identity dir {}", dir.display()))?;

    let id = LocalIdentity {
        machine: machine.to_string(),
        fingerprint: fingerprint.to_string(),
        algorithm: algorithm.to_string(),
        attested_at_secs: unix_now_secs(),
        self_attested: true,
    };

    let path = dir.join(format!("{machine}.json"));
    let tmp = path.with_extension("json.tmp");
    let content = serde_json::to_string_pretty(&id).context("serializing local identity")?;
    std::fs::write(&tmp, &content)
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Look up a machine's entry in the stub local registry. Returns `None` if
/// no entry has been written yet (machine not yet provisioned or attached).
pub fn lookup(cloud_dir: &Path, machine: &str) -> Result<Option<LocalIdentity>> {
    let path = cloud_dir.join("identities").join(format!("{machine}.json"));
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&content)
        .map(Some)
        .with_context(|| format!("parsing {}", path.display()))
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const MACHINE: &str = "noisetable-pdx-1";
    const FP: &str = "SHA256:HAo2DsB7cN+GmrEbJ8SR305rJagwQhgP2dNyUemUBbU";
    const ALGO: &str = "ssh-ed25519";

    #[test]
    fn lookup_returns_none_when_not_registered() {
        let tmp = TempDir::new().unwrap();
        let cloud_dir = tmp.path();
        assert!(lookup(cloud_dir, MACHINE).unwrap().is_none());
    }

    #[test]
    fn register_then_lookup_round_trips() {
        let tmp = TempDir::new().unwrap();
        let cloud_dir = tmp.path();
        register(cloud_dir, MACHINE, FP, ALGO).unwrap();
        let entry = lookup(cloud_dir, MACHINE).unwrap().unwrap();
        assert_eq!(entry.machine, MACHINE);
        assert_eq!(entry.fingerprint, FP);
        assert_eq!(entry.algorithm, ALGO);
        assert!(entry.self_attested);
        assert!(entry.attested_at_secs > 0);
    }

    #[test]
    fn register_is_idempotent_and_overwrites() {
        let tmp = TempDir::new().unwrap();
        let cloud_dir = tmp.path();
        register(cloud_dir, MACHINE, FP, ALGO).unwrap();
        let new_fp = "SHA256:ZZZnewfingerprint";
        register(cloud_dir, MACHINE, new_fp, ALGO).unwrap();
        let entry = lookup(cloud_dir, MACHINE).unwrap().unwrap();
        assert_eq!(entry.fingerprint, new_fp);
    }

    #[test]
    fn register_creates_identities_subdir() {
        let tmp = TempDir::new().unwrap();
        let cloud_dir = tmp.path();
        // identities/ does not exist yet
        assert!(!cloud_dir.join("identities").exists());
        register(cloud_dir, MACHINE, FP, ALGO).unwrap();
        assert!(cloud_dir.join("identities").is_dir());
        assert!(cloud_dir.join("identities").join(format!("{MACHINE}.json")).exists());
    }

    #[test]
    fn separate_machines_have_separate_files() {
        let tmp = TempDir::new().unwrap();
        let cloud_dir = tmp.path();
        register(cloud_dir, "machine-a", FP, ALGO).unwrap();
        register(cloud_dir, "machine-b", "SHA256:other", ALGO).unwrap();
        let a = lookup(cloud_dir, "machine-a").unwrap().unwrap();
        let b = lookup(cloud_dir, "machine-b").unwrap().unwrap();
        assert_eq!(a.fingerprint, FP);
        assert_eq!(b.fingerprint, "SHA256:other");
    }
}
