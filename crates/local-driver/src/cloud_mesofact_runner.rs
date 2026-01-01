//! Cloud-tier mesofact runner bring-up primitives (R330-F11, W059).
//!
//! Sibling to [`crate::pond_mesofact_dev`] but for the cloud tier: a single
//! long-lived bun process supervised by warden on the machine F16 places
//! the `yah-cloud` service onto (today: `us-west-001`, selected by mesh-tag
//! `tag:cloud-runner` — see `crates/yah/cloud/src/config.rs::CloudConfig::resolve_machine_by_mesh_tags`).
//!
//! The cloud runner serves multi-tenant traffic — one bun process exposes
//! the same `/revalidate /healthz /readyz` surface for every tenant
//! registered under `.yah/services/yah-cloud/tenants/<id>.toml` (tenant
//! config shape lands with R330-F12; F11 only sets up the supervised
//! process).
//!
//! Differences from the pond-tier sibling:
//!
//!   * Not a docker container — bun runs on the host under a warden slice
//!     so the Cloudflare tunnel (`yah-cloud-runner`) can route directly to
//!     `127.0.0.1:<port>` without bridge gymnastics.
//!   * Multi-tenant by construction — `tenant_config_dir` holds one TOML
//!     per tenant; F12 settles the file shape.
//!   * No `network` / `network_alias` fields — there is no per-cell docker
//!     bridge at this tier.
//!
//! Used by `cloud::reconciler::mesofact_runner` once R330-F11's dispatcher
//! wiring lands (a separate slice — F11 ships the spec + skeleton only).

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Caller-supplied cloud mesofact-runner bring-up parameters. The
/// `MesofactRunnerReconciler` builds this from the resolved mirror config +
/// the placed machine, then POSTs it to warden as the workload payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MesofactRunnerSpec {
    /// Host port the bun process binds to (the Cloudflare tunnel's ingress
    /// rule routes `runner.yah.dev` → `http://localhost:<port>`).
    pub bind_port: u16,
    /// Directory holding `tenants/<id>.toml` files. Mounted read-only into
    /// the bun process; reloads happen via SIGHUP or a `/revalidate?tenant=<id>`
    /// poke from operator tools.
    pub tenant_config_dir: PathBuf,
    /// Directory the bun process writes per-tenant SQLite + almanac
    /// artifacts into.
    pub data_dir: PathBuf,
    /// `ALMANAC_ENV` env var (default `"cloud"` for this tier).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_label: Option<String>,
    /// `ALMANAC_MIRROR_KEY` — optional static bearer for tenant
    /// `/revalidate` calls. F12 may move this per-tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_key: Option<String>,
    /// Timeout for the initial TCP + HTTP liveness probes during bring-up.
    #[serde(with = "duration_secs_serde")]
    pub ready_timeout: Duration,
    /// HTTP path probed for liveness. Default: `"/healthz"`.
    #[serde(default = "default_liveness_path")]
    pub liveness_path: String,
    /// HTTP path probed for readiness. Default: `"/readyz"`.
    #[serde(default = "default_readiness_path")]
    pub readiness_path: String,
}

fn default_liveness_path() -> String {
    "/healthz".into()
}
fn default_readiness_path() -> String {
    "/readyz".into()
}

mod duration_secs_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        d.as_secs().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}

/// Coordinates of a running cloud-runner returned by the warden-side
/// bring-up. Mirrors [`crate::pond_mesofact_dev::MesofactDevRunning`] in
/// purpose; only the host endpoint exists at this tier (no bridge).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MesofactRunnerRunning {
    /// Host-side endpoint — `http://127.0.0.1:<bind_port>`.
    pub endpoint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_round_trips_through_serde() {
        let spec = MesofactRunnerSpec {
            bind_port: 4323,
            tenant_config_dir: PathBuf::from("/var/lib/yah-cloud/tenants"),
            data_dir: PathBuf::from("/var/lib/yah-cloud/data"),
            env_label: Some("cloud".into()),
            mirror_key: None,
            ready_timeout: Duration::from_secs(30),
            liveness_path: "/healthz".into(),
            readiness_path: "/readyz".into(),
        };
        let s = serde_json::to_string(&spec).unwrap();
        let round: MesofactRunnerSpec = serde_json::from_str(&s).unwrap();
        assert_eq!(round.bind_port, 4323);
        assert_eq!(round.env_label.as_deref(), Some("cloud"));
        assert_eq!(round.liveness_path, "/healthz");
    }

    #[test]
    fn defaults_for_optional_paths() {
        let json_src = r#"{
  "bind_port": 4323,
  "tenant_config_dir": "/etc/yah-cloud/tenants",
  "data_dir": "/var/lib/yah-cloud",
  "ready_timeout": 30
}"#;
        let spec: MesofactRunnerSpec = serde_json::from_str(json_src).unwrap();
        assert_eq!(spec.liveness_path, "/healthz");
        assert_eq!(spec.readiness_path, "/readyz");
        assert!(spec.env_label.is_none());
    }
}
