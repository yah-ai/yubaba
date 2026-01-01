//! Pond mesofact-dev container bring-up primitives (R455-F2/F3, W180 Phase D).
//!
//! Ships `almanac-serve` + `issue-tracker` as siblings under tini in the
//! `yah-mesofact-dev` container. The container provides:
//!
//!  - `POST /revalidate` + `/healthz` + `/readyz` on [`MesofactDevSpec::almanac_port`]
//!  - `POST /issues` + IssuesFeed loop + `/healthz` + `/readyz` on [`MesofactDevSpec::issues_port`]
//!
//! Both ports are published to host so the embedded warden reconciler
//! ([`warden::pond::mesofact_dev::MesofactDevReconciler`]) can probe liveness
//! and readiness from outside the bridge. After Phase C (warden containerised),
//! the ports can be unpublished and the reconciler can probe via bridge DNS.
//!
//! Used by:
//!
//! - `warden::pond::mesofact_dev::MesofactDevReconciler` — supervisor + restart
//!   loop that owns the running container slot.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{ContainerRunSpec, LocalRuntime};

/// Container-internal port almanac-serve binds to (published to [`MesofactDevSpec::almanac_port`]).
const ALMANAC_CONTAINER_PORT: u16 = 4323;
/// Container-internal port issue-tracker binds to (published to [`MesofactDevSpec::issues_port`]).
const ISSUES_CONTAINER_PORT: u16 = 8731;

/// Caller-supplied mesofact-dev bring-up parameters. Camp builds this from the
/// service's pond configuration and POSTs it inside `PondDeployReq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MesofactDevSpec {
    /// Container image ref (`ghcr.io/yah-ai/yah-mesofact-dev:latest`).
    pub image: String,
    /// Canonical container name (`yah-pond-<svc>-<env>-mesofact-dev`).
    pub container_name: String,
    /// Docker `--label` value for `yah.pond=<svc>:<env>:mesofact-dev` filtering.
    pub container_label: String,
    /// Per-cell docker bridge network to attach to. When set, the Worker can
    /// DNS-resolve the container by [`network_alias`] inside the bridge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// DNS alias siblings on the bridge use (typically `"mesofact-dev"`).
    /// Worker bindings reference `http://mesofact-dev:4323` (almanac) and
    /// `http://mesofact-dev:8731` (issues) on the bridge (R455-T4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_alias: Option<String>,
    /// Host port published to the container's almanac-serve (internal 4323).
    pub almanac_port: u16,
    /// Host port published to the container's issue-tracker (internal 8731).
    pub issues_port: u16,
    /// Host directory bind-mounted to `/data` — issues SQLite + almanac artifacts.
    pub data_dir: PathBuf,
    /// Host directory bind-mounted to `/etc/almanac` — feed TOML files for
    /// almanac-serve revalidation requests.
    pub almanac_config_dir: PathBuf,
    /// `ALMANAC_SERVICE_ID` env var for mirror binding on `/revalidate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    /// `ALMANAC_ENV` env var (default `"pond"` inside the container).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_label: Option<String>,
    /// `ALMANAC_MIRROR_KEY` env var — optional static bearer secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_key: Option<String>,
    /// Timeout for the initial TCP + HTTP liveness probes during bring-up.
    #[serde(with = "duration_secs_serde")]
    pub ready_timeout: Duration,
    /// HTTP path probed on the almanac port for liveness. Reconciler restarts
    /// the container when this fails. Default: `"/healthz"`.
    #[serde(default = "default_liveness_path")]
    pub liveness_path: String,
    /// HTTP path probed on both ports for readiness. Phase D logs the result
    /// only; Phase E (R456-F1) will surface it per-slot.
    /// Default: `"/readyz"`.
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

/// Coordinates of a running mesofact-dev container returned by
/// [`ensure_mesofact_dev_running`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MesofactDevRunning {
    /// Host-side almanac endpoint — `http://127.0.0.1:<almanac_port>`.
    pub almanac_endpoint: String,
    /// Host-side issue-tracker endpoint — `http://127.0.0.1:<issues_port>`.
    pub issues_endpoint: String,
    pub container_name: String,
    /// In-bridge almanac endpoint — `http://<alias>:4323`. The Worker's
    /// `MESOFACT_BACKEND_ORIGIN` binding points here (R455-T4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_almanac_endpoint: Option<String>,
    /// In-bridge issue-tracker endpoint — `http://<alias>:8731`. The Worker's
    /// `ISSUES_ORIGIN` binding points here (R455-T4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_issues_endpoint: Option<String>,
}

/// Bring the mesofact-dev container up: pull image, create bind-mount dirs,
/// run container with ports + env + volume wiring, then HTTP-probe almanac-serve's
/// liveness path until it responds.
///
/// Idempotent: re-running against an already-running container of the same
/// name replaces it ([`LocalRuntime::run`] is idempotent).
pub async fn ensure_mesofact_dev_running(
    runtime: &LocalRuntime,
    spec: &MesofactDevSpec,
) -> Result<MesofactDevRunning> {
    std::fs::create_dir_all(&spec.data_dir).with_context(|| {
        format!(
            "creating mesofact-dev data dir {}",
            spec.data_dir.display()
        )
    })?;
    std::fs::create_dir_all(&spec.almanac_config_dir).with_context(|| {
        format!(
            "creating almanac config dir {}",
            spec.almanac_config_dir.display()
        )
    })?;

    runtime
        .ensure_image(&spec.image)
        .await
        .with_context(|| format!("pulling {}", spec.image))?;

    let mut env = BTreeMap::new();
    env.insert("ALMANAC_PORT".into(), ALMANAC_CONTAINER_PORT.to_string());
    env.insert("ALMANAC_DIR".into(), "/etc/almanac".into());
    env.insert("ALMANAC_PROJECT_ROOT".into(), "/data".into());
    env.insert(
        "ALMANAC_ENV".into(),
        spec.env_label.clone().unwrap_or_else(|| "pond".into()),
    );
    if let Some(svc) = &spec.service_id {
        env.insert("ALMANAC_SERVICE_ID".into(), svc.clone());
    }
    if let Some(key) = &spec.mirror_key {
        env.insert("ALMANAC_MIRROR_KEY".into(), key.clone());
    }
    env.insert(
        "ISSUE_TRACKER_PORT".into(),
        ISSUES_CONTAINER_PORT.to_string(),
    );
    env.insert("ISSUE_TRACKER_DB_PATH".into(), "/data/issues.db".into());
    env.insert("ISSUES_JSON_PATH".into(), "/data/issues.json".into());

    let network_aliases = match (&spec.network, &spec.network_alias) {
        (Some(_), Some(alias)) => vec![alias.clone()],
        _ => vec![],
    };

    let run_spec = ContainerRunSpec {
        name: spec.container_name.clone(),
        image: spec.image.clone(),
        label: spec.container_label.clone(),
        ports: vec![
            (spec.almanac_port, ALMANAC_CONTAINER_PORT),
            (spec.issues_port, ISSUES_CONTAINER_PORT),
        ],
        env,
        volumes: vec![
            (spec.data_dir.clone(), "/data".into()),
            (spec.almanac_config_dir.clone(), "/etc/almanac".into()),
        ],
        cmd: vec![],
        cap_add: vec![],
        cgroupns: None,
        network: spec.network.clone(),
        network_aliases,
    };

    runtime
        .run(&run_spec)
        .await
        .with_context(|| format!("starting mesofact-dev container {}", spec.container_name))?;

    let almanac_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), spec.almanac_port);
    if !wait_for_port(almanac_addr, spec.ready_timeout).await {
        let _ = runtime
            .stop_and_remove(&spec.container_name, Duration::from_secs(2))
            .await;
        bail!(
            "mesofact-dev container did not bind {almanac_addr} within {:?}",
            spec.ready_timeout,
        );
    }

    let almanac_endpoint = format!("http://127.0.0.1:{}", spec.almanac_port);
    let liveness_url = format!("{almanac_endpoint}{}", spec.liveness_path);
    if !wait_for_http_ready(&liveness_url, spec.ready_timeout).await {
        let _ = runtime
            .stop_and_remove(&spec.container_name, Duration::from_secs(2))
            .await;
        bail!(
            "mesofact-dev container at {almanac_endpoint} did not pass {liveness_url} within {:?}",
            spec.ready_timeout,
        );
    }

    let bridge_almanac_endpoint = spec
        .network
        .as_ref()
        .and(spec.network_alias.as_ref())
        .map(|alias| format!("http://{alias}:{ALMANAC_CONTAINER_PORT}"));
    let bridge_issues_endpoint = spec
        .network
        .as_ref()
        .and(spec.network_alias.as_ref())
        .map(|alias| format!("http://{alias}:{ISSUES_CONTAINER_PORT}"));

    info!(
        almanac_endpoint = %almanac_endpoint,
        issues_endpoint = %format!("http://127.0.0.1:{}", spec.issues_port),
        container = %spec.container_name,
        "pond mesofact-dev container ready",
    );

    Ok(MesofactDevRunning {
        almanac_endpoint,
        issues_endpoint: format!("http://127.0.0.1:{}", spec.issues_port),
        container_name: spec.container_name.clone(),
        bridge_almanac_endpoint,
        bridge_issues_endpoint,
    })
}

async fn wait_for_port(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_http_ready(url: &str, timeout: Duration) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(resp) = client.get(url).send().await {
            if resp.status().is_success() {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> MesofactDevSpec {
        MesofactDevSpec {
            image: "ghcr.io/yah-ai/yah-mesofact-dev:latest".into(),
            container_name: "yah-pond-svc-pond-mesofact-dev".into(),
            container_label: "svc:pond:mesofact-dev".into(),
            network: Some("yah-pond-svc-pond".into()),
            network_alias: Some("mesofact-dev".into()),
            almanac_port: 4323,
            issues_port: 8731,
            data_dir: PathBuf::from("/tmp/yah-pond/svc-pond/mesofact-dev/data"),
            almanac_config_dir: PathBuf::from("/tmp/yah-pond/svc-pond/mesofact-dev/almanac"),
            service_id: Some("yah-marketing".into()),
            env_label: Some("pond".into()),
            mirror_key: None,
            ready_timeout: Duration::from_secs(30),
            liveness_path: "/healthz".into(),
            readiness_path: "/readyz".into(),
        }
    }

    #[test]
    fn spec_round_trips_through_serde() {
        let spec = fixture();
        let s = serde_json::to_string(&spec).unwrap();
        let round: MesofactDevSpec = serde_json::from_str(&s).unwrap();
        assert_eq!(round.image, spec.image);
        assert_eq!(round.network.as_deref(), Some("yah-pond-svc-pond"));
        assert_eq!(round.network_alias.as_deref(), Some("mesofact-dev"));
        assert_eq!(round.almanac_port, 4323);
        assert_eq!(round.issues_port, 8731);
        assert_eq!(round.liveness_path, "/healthz");
        assert_eq!(round.readiness_path, "/readyz");
        assert_eq!(round.ready_timeout, Duration::from_secs(30));
    }

    #[test]
    fn spec_round_trips_without_optional_fields() {
        let json = r#"{
            "image": "ghcr.io/yah-ai/yah-mesofact-dev:latest",
            "container_name": "yah-pond-svc-pond-mesofact-dev",
            "container_label": "svc:pond:mesofact-dev",
            "almanac_port": 4323,
            "issues_port": 8731,
            "data_dir": "/tmp/data",
            "almanac_config_dir": "/tmp/almanac",
            "ready_timeout": 30
        }"#;
        let spec: MesofactDevSpec = serde_json::from_str(json).unwrap();
        assert!(spec.network.is_none());
        assert!(spec.network_alias.is_none());
        assert!(spec.service_id.is_none());
        assert!(spec.mirror_key.is_none());
        assert_eq!(spec.liveness_path, "/healthz");
        assert_eq!(spec.readiness_path, "/readyz");
    }

    #[test]
    fn bridge_endpoints_use_container_internal_ports() {
        let spec = fixture();
        let alias = spec.network_alias.as_ref().unwrap();
        let bridge_almanac = format!("http://{alias}:{ALMANAC_CONTAINER_PORT}");
        let bridge_issues = format!("http://{alias}:{ISSUES_CONTAINER_PORT}");
        assert_eq!(bridge_almanac, "http://mesofact-dev:4323");
        assert_eq!(bridge_issues, "http://mesofact-dev:8731");
    }
}
