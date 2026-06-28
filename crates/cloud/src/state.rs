//! Reconciler-written sidecar state for declared machines.
//!
//! R330-F15 split: `.yah/infra/machines/<name>.toml` is the declared identity
//! (operator-edited, version-controlled, names the logical slot + shape).
//! `.yah/infra/state/machines/<name>.json` is the observable state captured
//! when the reconciler adopts a live server into that slot. State carries
//! provider-side derivatives (Hetzner server id, current public IPv4, last
//! adoption timestamp, hostkey fingerprint observed at attach time).
//!
//! Why split: name is the binding identity (Hetzner enforces unique server
//! names per project; names survive provider migration). Provider ids and
//! observables are derived state — pinning them in `machine.toml` couples the
//! declared shape to a particular provider instantiation, blocking the
//! us-west-001-moves-Hetzner→DigitalOcean story by editing one TOML field.
//!
//! Adoption-shape verification compares `machine.toml` against the live API,
//! NOT against the state file. State is for humans/audit/idempotency. The
//! reconciler reads it only to skip redundant API calls on re-run.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// On-disk JSON shape for `.yah/infra/state/machines/<name>.json`.
///
/// Forward-compatible: every field is optional so a partial adopt (server
/// found, hostkey poll timed out) still produces a useful record. The file is
/// re-written wholesale on each adopt + each `attach` — no incremental patching.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineState {
    /// Provider-native server id (Hetzner: `server.id` as decimal string).
    /// Captured once on first adopt; refreshed only if the box is rebuilt and
    /// the name re-bound to a new server id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Primary public IPv4 observed at last adopt/attach. Refreshed every
    /// adopt; for audit, not for binding (mesh IP is what callers use).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ipv4: Option<String>,
    /// SSH hostkey fingerprint observed at attach time. Refreshed on every
    /// `attach` — when it changes between runs, the box was rebuilt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostkey_fingerprint: Option<String>,
    /// RFC3339 timestamp of the most recent successful adopt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_adopted_at: Option<String>,
}

impl MachineState {
    /// `<workspace_root>/.yah/infra/state/machines/<name>.json`.
    pub fn path(workspace_root: &Path, name: &str) -> PathBuf {
        workspace_root
            .join(".yah")
            .join("infra")
            .join("state")
            .join("machines")
            .join(format!("{name}.json"))
    }

    /// Load state for `name`. Missing file returns `Ok(MachineState::default())`
    /// so callers can treat the no-state-yet case identically to the partial-
    /// state case (initialize on adopt).
    pub fn load(workspace_root: &Path, name: &str) -> Result<Self> {
        let p = Self::path(workspace_root, name);
        match std::fs::read(&p) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", p.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    /// Write state for `name`, creating parent dirs as needed.
    pub fn save(&self, workspace_root: &Path, name: &str) -> Result<()> {
        let p = Self::path(workspace_root, name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(self)
            .with_context(|| format!("serializing state for {name}"))?;
        std::fs::write(&p, json).with_context(|| format!("writing {}", p.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn load_missing_returns_default() {
        let tmp = TempDir::new().unwrap();
        let s = MachineState::load(tmp.path(), "nonesuch").unwrap();
        assert_eq!(s, MachineState::default());
    }

    #[test]
    fn round_trip_through_disk() {
        let tmp = TempDir::new().unwrap();
        let s = MachineState {
            provider_id: Some("134855726".into()),
            public_ipv4: Some("5.78.210.121".into()),
            hostkey_fingerprint: Some("SHA256:abc".into()),
            last_adopted_at: Some("2026-06-09T02:30:00Z".into()),
        };
        s.save(tmp.path(), "us-west-001").unwrap();
        let loaded = MachineState::load(tmp.path(), "us-west-001").unwrap();
        assert_eq!(loaded, s);
    }

    #[test]
    fn partial_state_skips_none_fields_in_json() {
        let tmp = TempDir::new().unwrap();
        let s = MachineState {
            provider_id: Some("9".into()),
            ..Default::default()
        };
        s.save(tmp.path(), "m").unwrap();
        let bytes = std::fs::read(MachineState::path(tmp.path(), "m")).unwrap();
        let json = String::from_utf8(bytes).unwrap();
        assert!(json.contains("provider_id"));
        assert!(!json.contains("public_ipv4"));
        assert!(!json.contains("hostkey_fingerprint"));
    }
}
