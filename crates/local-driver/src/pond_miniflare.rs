//! Pond miniflare container bring-up primitives (R374-F4 → R455-F1).
//!
//! R374-F4's first cut ran miniflare as a host-side `bun miniflare-sim.mjs`
//! process. R455-F1 swaps the process for a container so miniflare joins the
//! per-cell `yah-pond-<svc>-<env>` docker bridge alongside MinIO + mesofact-dev
//! and the Worker can DNS-resolve siblings (`http://minio:9000`,
//! `http://mesofact-dev:4323`) instead of host loopback.
//!
//! Shape:
//!
//! - The `yah-miniflare` qed image (`crates/yah/qed/images/yah-miniflare/`)
//!   bakes in `bun` + miniflare + the shared `miniflare-sim.mjs` shim.
//! - [`MiniflareSpec`] carries the workload bundle as a string; we write it
//!   to `<state_dir>/worker.js` on the host and bind-mount it into the
//!   container at `/work/worker.js`.
//! - Container CMD: `bun /app/miniflare-sim.mjs`, configured via env
//!   (`MF_PORT`, `MF_HOST`, `ASSET_ORIGIN`, `WORKER_MODE`, `SSR_ORIGIN`,
//!   `SSR_PREFIXES`). `MF_HOST=0.0.0.0` so the published port is reachable.
//! - Readiness: host-side HTTP probe on the published port (the
//!   `[miniflare-sim] ready` stdout signal is still emitted but not consumed
//!   — `docker run -d` detaches before logs would be readable).
//!
//! Used by:
//!
//! - `yubaba::pond::miniflare::MiniflareReconciler` — supervisor + restart
//!   loop for the running container.
//! - `cloud::reconciler::pond::up_pond` — cloud-direct path consumed by
//!   `pond_smoke` and `yah cloud mirror up`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{ContainerRunSpec, LocalRuntime};

/// Path inside the container the Worker bundle is bind-mounted to. Pinned
/// here (and in the Dockerfile's `MF_SCRIPT` default) so callers don't
/// repeat the string.
pub const WORKER_SCRIPT_CONTAINER_PATH: &str = "/work/worker.js";

/// Caller-supplied miniflare bring-up parameters. Decoupled from cloud's
/// config types: camp + cloud's reconciler each build a `MiniflareSpec` from
/// their own source of truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiniflareSpec {
    /// Container image to pull. Defaults to `ghcr.io/yah-ai/yah-miniflare:latest`
    /// once the release-pipeline image-yah-miniflare GHA job lands; operators
    /// can override to a locally-built tag in the interim.
    pub image: String,
    /// Canonical container name (`yah-pond-<svc>-<env>-static`).
    pub container_name: String,
    /// Docker `--label` value for `yah.pond=<svc>:<env>:static` filtering.
    pub container_label: String,
    /// Per-cell docker bridge network the container joins. `None` keeps the
    /// legacy host-network shape (pre-R455-F1) — sibling containers reach
    /// miniflare via the host-published port instead of bridge DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// DNS alias siblings on the bridge use to reach miniflare (typically
    /// `"miniflare"`). Ignored when [`network`] is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_alias: Option<String>,
    /// Host port published to the container's `MF_PORT`. The operator hits
    /// `http://localhost:<port>` exactly as they do today.
    pub port: u16,
    /// Compiled Worker JS content. Written to `state_dir/worker.js` and
    /// bind-mounted into the container at [`WORKER_SCRIPT_CONTAINER_PATH`].
    pub worker_script: String,
    /// Directory where `worker.js` is materialised before bind-mounting.
    pub state_dir: PathBuf,
    /// `ASSET_ORIGIN` for the Worker. On the bridge this is
    /// `http://<minio_alias>:9000/<bucket>`; legacy host-network deploys use
    /// `http://127.0.0.1:<api_port>/<bucket>`.
    pub asset_origin: String,
    /// `WORKER_MODE` binding ("static" | "spa" | "ssr"). Defaults to "static".
    #[serde(default = "default_worker_mode")]
    pub worker_mode: String,
    /// `SSR_ORIGIN` binding — host:port the Worker proxies SSR-prefix
    /// matches to. Empty for non-SSR modes.
    #[serde(default)]
    pub ssr_origin: String,
    /// `SSR_PREFIXES` binding (serialized as JSON array string for the
    /// Worker). Sorted + deduped W173-shape prefixes; empty for non-SSR.
    #[serde(default)]
    pub ssr_prefixes: Vec<String>,
    /// How long to wait for the host-port HTTP probe to succeed before
    /// declaring the bring-up failed.
    #[serde(with = "duration_secs_serde")]
    pub ready_timeout: Duration,
    /// Extra `--env` bindings passed verbatim to miniflare. Used to inject
    /// backend origins into the Worker (e.g. `MESOFACT_BACKEND_ORIGIN`,
    /// `ISSUES_ORIGIN`) without adding typed fields for every new binding.
    /// Values are merged after the standard bindings so callers can override
    /// defaults if needed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra_env: BTreeMap<String, String>,
}

fn default_worker_mode() -> String {
    "static".to_string()
}

mod duration_secs_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        d.as_secs().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Coordinates of a running miniflare container returned by
/// [`ensure_miniflare_running`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiniflareRunning {
    /// Host-side URL the operator visits — `http://127.0.0.1:<port>`.
    pub dev_url: String,
    pub container_name: String,
}

/// Bring miniflare up: pull image, write the Worker bundle to the state dir,
/// run the container with bridge + env wiring, then HTTP-probe the published
/// port until the Worker responds.
///
/// Idempotent end-to-end: re-running against an already-Running container of
/// the same name replaces it ([`LocalRuntime::run`] is idempotent).
pub async fn ensure_miniflare_running(
    runtime: &LocalRuntime,
    spec: &MiniflareSpec,
) -> Result<MiniflareRunning> {
    std::fs::create_dir_all(&spec.state_dir)
        .with_context(|| format!("creating miniflare state dir {}", spec.state_dir.display()))?;
    let worker_path = spec.state_dir.join("worker.js");
    std::fs::write(&worker_path, spec.worker_script.as_bytes())
        .with_context(|| format!("writing {}", worker_path.display()))?;

    runtime
        .ensure_image(&spec.image)
        .await
        .with_context(|| format!("pulling {}", spec.image))?;

    let ssr_prefixes_json =
        serde_json::to_string(&spec.ssr_prefixes).unwrap_or_else(|_| "[]".to_string());
    let mut env = BTreeMap::new();
    // MF_PORT inside the container == published port outside so the worker
    // self-reports the correct URL in its stdout `ready on http://…` line.
    env.insert("MF_PORT".into(), spec.port.to_string());
    // Bind to 0.0.0.0 so the published port is reachable from the host.
    env.insert("MF_HOST".into(), "0.0.0.0".into());
    env.insert("MF_SCRIPT".into(), WORKER_SCRIPT_CONTAINER_PATH.into());
    env.insert("ASSET_ORIGIN".into(), spec.asset_origin.clone());
    env.insert("WORKER_MODE".into(), spec.worker_mode.clone());
    env.insert("SSR_ORIGIN".into(), spec.ssr_origin.clone());
    env.insert("SSR_PREFIXES".into(), ssr_prefixes_json);
    for (k, v) in &spec.extra_env {
        env.insert(k.clone(), v.clone());
    }

    let network_aliases = match (&spec.network, &spec.network_alias) {
        (Some(_), Some(alias)) => vec![alias.clone()],
        _ => vec![],
    };

    let run_spec = ContainerRunSpec {
        name: spec.container_name.clone(),
        image: spec.image.clone(),
        label: spec.container_label.clone(),
        ports: vec![(spec.port, spec.port)],
        env,
        volumes: vec![(worker_path.clone(), WORKER_SCRIPT_CONTAINER_PATH.into())],
        cmd: vec![],
        cap_add: vec![],
        cgroupns: None,
        network: spec.network.clone(),
        network_aliases,
    };
    runtime
        .run(&run_spec)
        .await
        .with_context(|| format!("starting miniflare container {}", spec.container_name))?;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), spec.port);
    if !wait_for_port(addr, spec.ready_timeout).await {
        let _ = runtime
            .stop_and_remove(&spec.container_name, Duration::from_secs(2))
            .await;
        bail!(
            "miniflare container did not bind {addr} within {:?}",
            spec.ready_timeout,
        );
    }

    let dev_url = format!("http://127.0.0.1:{}", spec.port);
    if !wait_for_http_ready(&dev_url, spec.ready_timeout).await {
        let _ = runtime
            .stop_and_remove(&spec.container_name, Duration::from_secs(2))
            .await;
        bail!(
            "miniflare container at {dev_url} did not respond within {:?}",
            spec.ready_timeout,
        );
    }

    info!(
        dev_url = %dev_url,
        container = %spec.container_name,
        "pond miniflare container ready",
    );

    Ok(MiniflareRunning {
        dev_url,
        container_name: spec.container_name.clone(),
    })
}

/// Wait for a TCP port to start accepting connections.
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

/// Probe miniflare's published port until any non-5xx response comes back.
/// Returning 4xx is fine — that's the Worker telling us "no route", which
/// still proves workerd booted.
async fn wait_for_http_ready(url: &str, timeout: Duration) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(resp) = client.get(url).send().await {
            let s = resp.status();
            if s != StatusCode::SERVICE_UNAVAILABLE
                && s != StatusCode::BAD_GATEWAY
                && s != StatusCode::GATEWAY_TIMEOUT
                && !s.is_server_error()
            {
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

    fn fixture() -> MiniflareSpec {
        MiniflareSpec {
            image: "ghcr.io/yah-ai/yah-miniflare:latest".into(),
            container_name: "yah-pond-svc-pond-static".into(),
            container_label: "svc:pond:static".into(),
            network: Some("yah-pond-svc-pond".into()),
            network_alias: Some("miniflare".into()),
            port: 4322,
            worker_script: "export default { fetch() { return new Response('ok'); } }".into(),
            state_dir: PathBuf::from("/tmp/yah-pond/svc-pond/miniflare"),
            asset_origin: "http://minio:9000/yah-dev".into(),
            worker_mode: "static".into(),
            ssr_origin: String::new(),
            ssr_prefixes: vec![],
            ready_timeout: Duration::from_secs(30),
            extra_env: BTreeMap::new(),
        }
    }

    #[test]
    fn spec_round_trips_through_serde() {
        let spec = fixture();
        let s = serde_json::to_string(&spec).unwrap();
        let round: MiniflareSpec = serde_json::from_str(&s).unwrap();
        assert_eq!(round.image, spec.image);
        assert_eq!(round.network.as_deref(), Some("yah-pond-svc-pond"));
        assert_eq!(round.network_alias.as_deref(), Some("miniflare"));
        assert_eq!(round.port, 4322);
        assert_eq!(round.asset_origin, "http://minio:9000/yah-dev");
        assert_eq!(round.ready_timeout, Duration::from_secs(30));
    }

    #[test]
    fn spec_round_trips_without_bridge_fields_for_legacy_peers() {
        let legacy = r#"{
            "image": "ghcr.io/yah-ai/yah-miniflare:latest",
            "container_name": "yah-pond-svc-pond-static",
            "container_label": "svc:pond:static",
            "port": 4322,
            "worker_script": "// noop",
            "state_dir": "/tmp/yah-pond/svc-pond/miniflare",
            "asset_origin": "http://127.0.0.1:9000/yah-dev",
            "ready_timeout": 30
        }"#;
        let spec: MiniflareSpec = serde_json::from_str(legacy).unwrap();
        assert!(spec.network.is_none());
        assert!(spec.network_alias.is_none());
        assert_eq!(spec.worker_mode, "static");
        assert!(spec.ssr_prefixes.is_empty());
    }
}
