//! Pond MinIO bring-up primitives (R374-F3).
//!
//! Container-tier MinIO lifecycle without warden state: pull image, run
//! container with bind-mounted data dir, port + HTTP probe, bucket
//! auto-create with public-read policy. Used by:
//!
//! - `warden::pond::minio::MinioReconciler` — the supervisor + restart loop
//!   that owns running MinIO slots in the camp-embedded warden.
//! - `cloud::reconciler::pond::up_pond` — the cloud-tier reconciler path
//!   exercised by `pond_smoke` and `yah cloud mirror up`.
//!
//! Both code paths share these primitives so MinIO state-on-disk stays
//! interchangeable and reconciler / non-reconciler entries surface the
//! same shape on failure.
//!
//! @yah:ticket(R455-F1, "Per-cell docker bridge network yah-pond-<svc>-<env>; switch MinIO + miniflare onto it")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-05T08:24:24Z)
//! @yah:status(review)
//! @yah:phase(D)
//! @yah:parent(R455)
//! @arch:see(.yah/docs/working/W180-pond-richer-topology.md)
//! @arch:see(.yah/docs/working/W142-pond.md)
//! @yah:next("Live smoke under YAH_LOCAL_SIM_E2E=1: warden::tests::pond_reconciler_smoke (now drives the per-cell bridge end-to-end — verifies workerd reaches MinIO via http://minio:9000 instead of loopback)")
//! @yah:next("image-yah-miniflare GHA job in .github/workflows/release.yml (mirror image-yah-warden once it lands; DEFAULT_MINIFLARE_IMAGE = ghcr.io/yah-ai/yah-miniflare:latest)")
//! @yah:next("Two services' ponds coexist verify: yah-marketing + yah-dashboard up simultaneously with per-cell networks yah-pond-<svc>-<env>")
//! @yah:handoff("Substrate landed across local-driver + warden + cloud + camp + qed. (1) LocalRuntime::ensure_network (idempotent docker network create) + ContainerRunSpec.network/network_aliases + pond_network_name(svc, env). (2) MinioSpec gained network/network_alias; siblings reach via MinioRunning.bridge_endpoint = http://<alias>:9000. (3) New yah-miniflare qed image (Dockerfile + bun base + tini + baked miniflare; Worker bundle bind-mounted at /work/worker.js) + catalog.toml entry + EXPECTED_BUNDLED test. (4) local_driver::pond_miniflare rewritten: spawn_miniflare → ensure_miniflare_running container path; MiniflareSpec carries image/container_name/network/network_alias. (5) warden::pond::miniflare::MiniflareReconciler now container-shaped (runtime + container_name + cancel); deploy() ensures the per-cell network before bring-up and rewrites asset_origin to the bridge endpoint when camp sent a host-loopback string. (6) Camp's build_miniflare_deploy_spec emits the new shape; SSR runtime joins the bridge with alias 'ssr' and miniflare's ssr_origin auto-flips to http://ssr:<port> on bridge. (7) cloud::reconciler::pond::build_minio_spec always sets the bridge + MINIO_NETWORK_ALIAS const; cloud-direct (pond_smoke + yah cloud mirror up) keeps using its in-process bun shim because that path doesn't go through local_driver::pond_miniflare.")
//! @yah:verify("cargo check --workspace # clean (warnings only)")
//! @yah:verify("cargo test -p local-driver --lib # pond_network_name + docker_run_args emit --network/--network-alias + ensure_network logic (1 pre-existing failure: workload_spec_to_crs digest test, owned by R438-T3)")
//! @yah:verify("cargo test -p warden --lib # 91/91 pass incl. pond fixtures upgraded to bridge fields")
//! @yah:verify("cargo test -p cloud --lib reconciler::pond # 27/27 pass incl. adopt-path tests with bridge_endpoint field on MinioRunning")
//! @yah:verify("cargo test -p qed --lib images::catalog::tests # 16/16 — bundled_catalog_loads_with_all_entries now requires yah-miniflare")
//! @yah:gotcha("BREAKING for operators who curl localhost:9000 directly is NOT applied yet — to keep the embedded warden's host-side probe working without joining the bridge, MinIO's API port still publishes (and console too). Unpublishing the API port is gated on warden-in-container (R454-T*); the bridge_endpoint + network are otherwise wired end-to-end.")
//! @yah:gotcha("yah-miniflare image must be available locally or built before pond bring-up succeeds (release-pipeline image-yah-miniflare GHA job is the follow-up). Local override: set providers.static.image in mirror.toml to a hand-built tag.")
//! @yah:gotcha("MiniflareSpec lost js_binary/miniflare_shim/miniflare_import/workerd_binary — the container bakes them in. Any out-of-tree code constructing MiniflareSpec needs to switch to image/container_name/network shape.")
//! @yah:gotcha("MiniflareSupervision now carries runtime+container_name (was cancel-only) — registry teardown paths in pond.rs (insert_full prior-replace, mark_failed, shutdown_all) call stop_and_remove on it now.")
//! @yah:gotcha("miniflare-sim.mjs reads MF_HOST (defaults to 127.0.0.1 for backward compat); container path injects MF_HOST=0.0.0.0 so the published port is reachable.")

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::s3_sign::{sign_s3_head_bucket, sign_s3_put_bucket, sign_s3_put_bucket_policy};
use crate::{ContainerRunSpec, LocalRuntime};

/// MinIO defaults to `us-east-1` for SigV4 region regardless of location.
pub const MINIO_REGION: &str = "us-east-1";

/// Caller-supplied MinIO bring-up parameters. Decoupled from cloud's config
/// types: camp + cloud's reconciler each build a `MinioSpec` from their own
/// source of truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinioSpec {
    /// MinIO image ref (pinned tag).
    pub image: String,
    /// MinIO root user (becomes the S3 access key).
    pub user: String,
    /// MinIO root password (S3 secret key).
    pub password: String,
    /// Host port mapped to MinIO's API port (9000 inside the container).
    pub api_port: u16,
    /// Host port mapped to MinIO's console port (9001 inside the container).
    pub console_port: u16,
    /// Bucket name to auto-create with public-read policy.
    pub bucket: String,
    /// Host directory bind-mounted to `/data` inside the container.
    /// Survives `pond down` / `pond up` cycles.
    pub data_dir: PathBuf,
    /// Container name (canonical `yah-pond-<svc>-<env>-<slot>` form).
    pub container_name: String,
    /// Docker `--label` value for `yah.pond=<svc>:<env>:<slot>` filtering.
    pub container_label: String,
    /// Timeout for the initial port + HTTP-ready probes.
    #[serde(with = "duration_secs_serde")]
    pub ready_timeout: Duration,
    /// Per-cell docker bridge network to attach this container to. `None`
    /// keeps MinIO on the default `bridge` network (legacy behaviour). When
    /// set (R455-F1), siblings on the same bridge reach MinIO via DNS using
    /// [`network_alias`] — typically `http://minio:9000/<bucket>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// DNS alias siblings on the bridge use to reach this container.
    /// Ignored when [`network`] is `None`. Defaults to `"minio"` at build
    /// time (see camp's `build_minio_deploy_spec`); the value is reflected
    /// into [`MinioRunning::bridge_endpoint`] so callers can pass it to
    /// the Worker's `ASSET_ORIGIN` binding without recomputing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_alias: Option<String>,
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

/// Coordinates of a running MinIO slot returned by [`ensure_minio_running`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinioRunning {
    /// Host-side S3 endpoint — `http://127.0.0.1:<api_port>` when the API
    /// port is published, used by host-side probes + the cloud-tier
    /// publisher. Always set today (R455-F1 keeps the API port published
    /// even on the bridge so the embedded warden reconciler can probe
    /// without joining the bridge).
    pub endpoint: String,
    pub console_url: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub container_name: String,
    /// In-bridge S3 endpoint — `http://<network_alias>:9000` when the
    /// container joined a docker bridge. `None` for legacy host-network
    /// deployments. Sibling containers (miniflare, mesofact-dev) use
    /// this to reach MinIO without depending on a host-port publish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_endpoint: Option<String>,
}

/// Bring MinIO up: pull image, run container, probe TCP + HTTP readiness,
/// then auto-create the bucket with a public-read policy.
///
/// Idempotent end-to-end: re-running against an already-Running container
/// of the same name replaces it ([`LocalRuntime::run`] is idempotent), and
/// the bucket-policy step is self-healing on re-runs.
pub async fn ensure_minio_running(
    runtime: &LocalRuntime,
    spec: &MinioSpec,
) -> Result<MinioRunning> {
    std::fs::create_dir_all(&spec.data_dir)
        .with_context(|| format!("creating {}", spec.data_dir.display()))?;

    runtime
        .ensure_image(&spec.image)
        .await
        .with_context(|| format!("pulling {}", spec.image))?;

    let mut env = std::collections::BTreeMap::new();
    env.insert("MINIO_ROOT_USER".into(), spec.user.clone());
    env.insert("MINIO_ROOT_PASSWORD".into(), spec.password.clone());
    // Per W180: even on the per-cell bridge, keep MinIO's API + console
    // ports published. The embedded warden reconciler probes the host-side
    // endpoint; the cloud-tier publisher (`yah cloud mirror up`) likewise
    // talks to the host port. Siblings on the bridge use `bridge_endpoint`
    // (DNS alias → 9000 inside the container) instead of the host port.
    let network_aliases = match (&spec.network, &spec.network_alias) {
        (Some(_), Some(alias)) => vec![alias.clone()],
        _ => vec![],
    };
    let run_spec = ContainerRunSpec {
        name: spec.container_name.clone(),
        image: spec.image.clone(),
        label: spec.container_label.clone(),
        ports: vec![(spec.api_port, 9000), (spec.console_port, 9001)],
        env,
        volumes: vec![(spec.data_dir.clone(), "/data".into())],
        cmd: vec![
            "server".into(),
            "/data".into(),
            "--console-address".into(),
            ":9001".into(),
        ],
        cap_add: vec![],
        cgroupns: None,
        network: spec.network.clone(),
        network_aliases,
    };
    runtime
        .run(&run_spec)
        .await
        .with_context(|| format!("starting MinIO container {}", spec.container_name))?;

    let api_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), spec.api_port);
    if !wait_for_port(api_addr, spec.ready_timeout).await {
        let _ = runtime
            .stop_and_remove(&spec.container_name, Duration::from_secs(2))
            .await;
        bail!(
            "MinIO container did not bind {api_addr} within {:?}",
            spec.ready_timeout,
        );
    }

    let endpoint = format!("http://127.0.0.1:{}", spec.api_port);
    let health_url = format!("{endpoint}/minio/health/ready");
    if !wait_for_http_ready(&health_url, spec.ready_timeout).await {
        let _ = runtime
            .stop_and_remove(&spec.container_name, Duration::from_secs(2))
            .await;
        bail!(
            "MinIO container at {endpoint} did not pass {health_url} within {:?}",
            spec.ready_timeout,
        );
    }

    if let Err(e) = ensure_bucket_public(&endpoint, &spec.bucket, &spec.user, &spec.password).await
    {
        let _ = runtime
            .stop_and_remove(&spec.container_name, Duration::from_secs(2))
            .await;
        return Err(e.context(format!(
            "ensuring bucket {bucket:?} on pond MinIO at {endpoint}",
            bucket = spec.bucket,
        )));
    }

    let bridge_endpoint = spec
        .network
        .as_ref()
        .and(spec.network_alias.as_ref())
        .map(|alias| format!("http://{alias}:9000"));

    Ok(MinioRunning {
        endpoint,
        console_url: format!("http://localhost:{}", spec.console_port),
        bucket: spec.bucket.clone(),
        access_key: spec.user.clone(),
        secret_key: spec.password.clone(),
        container_name: spec.container_name.clone(),
        bridge_endpoint,
    })
}

/// HEAD the bucket; if 404, PUT it; then PUT `?policy` with anonymous-read
/// so an embedder's miniflare can serve unsigned GETs through MinIO.
pub async fn ensure_bucket_public(
    endpoint: &str,
    bucket: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/{}", endpoint.trim_end_matches('/'), bucket);

    let head_headers = sign_s3_head_bucket(&url, MINIO_REGION, access_key, secret_key)?;
    let head = client
        .head(&url)
        .headers(head_headers)
        .send()
        .await
        .context("HEAD bucket")?;
    let exists = match head.status() {
        StatusCode::OK | StatusCode::NO_CONTENT => true,
        StatusCode::NOT_FOUND => false,
        s => bail!("HEAD bucket returned unexpected status {s}"),
    };

    if !exists {
        let put_headers = sign_s3_put_bucket(&url, MINIO_REGION, access_key, secret_key)?;
        let put = client
            .put(&url)
            .headers(put_headers)
            .body("")
            .send()
            .await
            .context("PUT bucket")?;
        let s = put.status();
        if !(s.is_success() || s == StatusCode::CONFLICT) {
            let body = put.text().await.unwrap_or_default();
            bail!("PUT bucket failed ({s}): {}", body.trim());
        }
        info!(bucket, %endpoint, "pond bucket created");
    }

    let policy_json = public_read_bucket_policy(bucket).into_bytes();
    let policy_url = format!("{url}?policy");
    let policy_headers = sign_s3_put_bucket_policy(
        &policy_url,
        MINIO_REGION,
        access_key,
        secret_key,
        &policy_json,
    )?;
    let policy_resp = client
        .put(&policy_url)
        .headers(policy_headers)
        .body(policy_json)
        .send()
        .await
        .context("PUT bucket?policy")?;
    if !policy_resp.status().is_success() {
        let body = policy_resp.text().await.unwrap_or_default();
        bail!("PUT bucket?policy public-read failed: {}", body.trim());
    }
    Ok(())
}

fn public_read_bucket_policy(bucket: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":["*"]}},"Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":["arn:aws:s3:::{bucket}"]}},{{"Effect":"Allow","Principal":{{"AWS":["*"]}},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::{bucket}/*"]}}]}}"#
    )
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

/// Wait for an HTTP endpoint to return a 2xx status. MinIO binds its
/// listener before its HTTP stack is serving — the first signed request
/// can land mid-startup and get a TCP RST. Poll the documented readiness
/// probe before any S3 call.
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

    #[test]
    fn public_read_bucket_policy_contains_bucket_name() {
        let policy = public_read_bucket_policy("yah-test");
        assert!(policy.contains("yah-test/*"), "policy must scope GetObject");
        assert!(policy.contains("arn:aws:s3:::yah-test"));
    }

    #[test]
    fn minio_spec_serde_round_trip() {
        let spec = MinioSpec {
            image: "minio/minio:RELEASE.2025-04-22T22-12-26Z".into(),
            user: "yahsim".into(),
            password: "yahsim-local-only".into(),
            api_port: 9000,
            console_port: 9001,
            bucket: "yah-dev".into(),
            data_dir: PathBuf::from("/tmp/yah-pond/minio"),
            container_name: "yah-pond-svc-pond-object_store".into(),
            container_label: "svc:pond:object_store".into(),
            ready_timeout: Duration::from_secs(30),
            network: Some("yah-pond-svc-pond".into()),
            network_alias: Some("minio".into()),
        };
        let s = serde_json::to_string(&spec).unwrap();
        let round: MinioSpec = serde_json::from_str(&s).unwrap();
        assert_eq!(round.bucket, spec.bucket);
        assert_eq!(round.api_port, spec.api_port);
        assert_eq!(round.ready_timeout, spec.ready_timeout);
        assert_eq!(round.network.as_deref(), Some("yah-pond-svc-pond"));
        assert_eq!(round.network_alias.as_deref(), Some("minio"));
    }

    #[test]
    fn minio_spec_round_trips_without_bridge_fields() {
        // serde(default + skip_if_none) keeps the wire shape backward-compatible
        // with pre-R455-F1 camp + warden peers.
        let legacy = r#"{
            "image": "minio/minio:RELEASE.2025-04-22T22-12-26Z",
            "user": "yahsim",
            "password": "yahsim-local-only",
            "api_port": 9000,
            "console_port": 9001,
            "bucket": "yah-dev",
            "data_dir": "/tmp/yah-pond/minio",
            "container_name": "yah-pond-svc-pond-object_store",
            "container_label": "svc:pond:object_store",
            "ready_timeout": 30
        }"#;
        let spec: MinioSpec = serde_json::from_str(legacy).unwrap();
        assert!(spec.network.is_none());
        assert!(spec.network_alias.is_none());
    }
}
