//! Live smoke for R374-F3 + F4's reconcilers: bring MinIO + miniflare up via
//! warden's pond deploy handler, kill each in turn, assert reconcilers flip
//! `PondPhase` Degraded → Running again within budget.
//!
//! This is the regression bar for the half-alive bug R374 was filed against:
//! before R374, a dead MinIO under a still-Running miniflare surfaced as
//! "Network connection lost" from `entry.worker.js` after silent adoption.
//! After R374-F4, warden owns both slots — MinIO (container) and miniflare
//! (process) — and restarts each independently without operator intervention.
//!
//! ## Running
//!
//! Requires orbstack / colima / docker running AND bun on PATH.
//! Gated on `YAH_LOCAL_SIM_E2E=1` to match `pond_smoke`.
//!
//! ```bash
//! YAH_LOCAL_SIM_E2E=1 cargo test -p warden --test pond_reconciler_smoke -- --nocapture
//! ```
//!
//! The test uses a randomised container name + bucket so concurrent runs +
//! local leftovers don't collide.
//!
//! @yah:ticket(R441-B1, "pond_reconciler_smoke: MiniflareSpec + PondDeployReq missing required fields")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T22:56:05Z)
//! @yah:status(review)
//! @yah:parent(R441)
//! @yah:next("MiniflareSpec at line 87 missing ssr_origin + ssr_prefixes + worker_mode; PondDeployReq at line 232 missing ssr_runtime. Compile error E0063.")
//! @yah:next("Check the struct definitions for what defaults this static-only smoke test wants — worker_mode likely Direct (or whatever predates the SSR variant) and the SSR-flavor fields likely None/empty since this test predates SSR.")
//! @yah:next("After the fixture compiles, run `cargo test -p warden --test pond_reconciler_smoke` to confirm reconciler behavior unchanged.")
//! @yah:verify("cargo test -p warden --test pond_reconciler_smoke passes")
//! @yah:handoff("Added mesofact_dev: None to PondDeployReq fixture in pond_reconciler_smoke.rs:261. cargo test -p warden --test pond_reconciler_smoke passes.")

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cloud::CloudConfig;
use local_driver::pond_minio::MinioSpec;
use local_driver::pond_miniflare::MiniflareSpec;
use local_driver::LocalRuntime;
use warden::pond::{PondDeployReq, PondPhase};

/// How long to wait for `phase == Running` after `POST /pond/deploy`.
const DEPLOY_BUDGET: Duration = Duration::from_secs(90);

/// Reconciler tick is 5 s; allow up to 3 ticks for the recovery cycle.
const RECOVER_BUDGET: Duration = Duration::from_secs(30);

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root three dirs above CARGO_MANIFEST_DIR")
        .to_path_buf()
}

async fn detect_runtime(workspace: &std::path::Path) -> Option<LocalRuntime> {
    let cfg = CloudConfig::load(workspace).ok()?;
    let provider = cfg
        .providers
        .iter()
        .find(|p| matches!(p.kind, cloud::Provider::LocalContainer))?;
    let spec = cloud::local_container_spec_from_provider(provider).ok()?;
    LocalRuntime::detect(&spec).await.ok()
}

fn unique_minio_spec(workspace: &std::path::Path) -> MinioSpec {
    let pid = std::process::id();
    let container_name = format!("yah-pond-reconciler-smoke-{pid}-object_store");
    let data_dir = workspace
        .join(".yah/jit/pond-reconciler-smoke")
        .join(format!("data-{pid}"));
    let api_port = 39000 + ((pid % 800) as u16);
    let console_port = api_port + 1;
    MinioSpec {
        image: "docker.io/minio/minio:RELEASE.2025-04-22T22-12-26Z".into(),
        user: "yahsim".into(),
        password: "yahsim-local-only".into(),
        api_port,
        console_port,
        bucket: format!("recon-smoke-{pid}"),
        data_dir,
        container_name,
        container_label: format!("reconciler-smoke:{pid}:object_store"),
        ready_timeout: Duration::from_secs(30),
        network: Some(format!("yah-pond-reconciler-smoke-{pid}")),
        network_alias: Some("minio".into()),
    }
}

fn unique_miniflare_spec(workspace: &std::path::Path, minio: &MinioSpec) -> MiniflareSpec {
    let pid = std::process::id();
    // Use a high port range to avoid colliding with a running camp's pond.
    let port = 34322 + ((pid % 800) as u16);
    let state_dir = workspace
        .join(".yah/jit/pond-reconciler-smoke")
        .join(format!("miniflare-{pid}"));
    // On the bridge the Worker reaches MinIO via DNS — the alias is set on
    // the spec, not the api_port.
    let asset_origin = match minio.network_alias.as_deref() {
        Some(alias) => format!("http://{alias}:9000/{}", minio.bucket),
        None => format!("http://127.0.0.1:{}/{}", minio.api_port, minio.bucket),
    };
    MiniflareSpec {
        image: "ghcr.io/yah-ai/yah-miniflare:latest".into(),
        container_name: format!("yah-pond-reconciler-smoke-{pid}-static"),
        container_label: format!("reconciler-smoke:{pid}:static"),
        network: minio.network.clone(),
        network_alias: minio.network.as_ref().map(|_| "miniflare".to_string()),
        port,
        worker_script: cloud::WORKER_SCRIPT.to_string(),
        state_dir,
        asset_origin,
        worker_mode: "static".into(),
        ssr_origin: String::new(),
        ssr_prefixes: vec![],
        ready_timeout: Duration::from_secs(60),
        extra_env: std::collections::BTreeMap::new(),
    }
}

async fn docker_kill(container_name: &str) -> bool {
    tokio::process::Command::new("docker")
        .args(["kill", container_name])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn docker_force_rm(container_name: &str) {
    let _ = tokio::process::Command::new("docker")
        .args(["rm", "-f", container_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
}

async fn fetch_phase(port: u16, ident: &str) -> Option<PondPhase> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let resp = client
        .get(format!("http://127.0.0.1:{port}/pond/state"))
        .query(&[("ident", ident)])
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: serde_json::Value = resp.json().await.ok()?;
    let phase = v.get("phase").and_then(|x| x.as_str())?;
    match phase {
        "pending" => Some(PondPhase::Pending),
        "running" => Some(PondPhase::Running),
        "degraded" => Some(PondPhase::Degraded),
        "failed" => Some(PondPhase::Failed),
        _ => None,
    }
}

async fn wait_for_phase<F: Fn(PondPhase) -> bool>(
    port: u16,
    ident: &str,
    predicate: F,
    deadline: Duration,
) -> Result<PondPhase, Option<PondPhase>> {
    let start = Instant::now();
    let mut last = None;
    while start.elapsed() < deadline {
        if let Some(p) = fetch_phase(port, ident).await {
            last = Some(p);
            if predicate(p) {
                return Ok(p);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(last)
}

#[tokio::test]
async fn warden_reconciler_restarts_minio_and_miniflare() {
    if std::env::var("YAH_LOCAL_SIM_E2E").as_deref() != Ok("1") {
        eprintln!(
            "[reconciler-smoke] SKIP: set YAH_LOCAL_SIM_E2E=1 to run the warden \
             reconciler regression bar. Requires orbstack / colima / docker running \
             AND bun (or node) on PATH."
        );
        return;
    }

    let workspace = workspace_root();
    let runtime = match detect_runtime(&workspace).await {
        Some(r) => Arc::new(r),
        None => {
            eprintln!(
                "[reconciler-smoke] SKIP: no reachable local-container runtime; \
                 start orbstack/colima/docker and rerun."
            );
            return;
        }
    };

    let minio_spec = unique_minio_spec(&workspace);
    let miniflare_spec = unique_miniflare_spec(&workspace, &minio_spec);
    let container_name = minio_spec.container_name.clone();
    let miniflare_port = miniflare_spec.port;

    struct Cleanup {
        container_name: String,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let name = self.container_name.clone();
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", &name])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    let _cleanup = Cleanup {
        container_name: container_name.clone(),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();

    let state_path = workspace
        .join(".yah/jit")
        .join(format!("pond-reconciler-smoke-state-{}.json", std::process::id()));
    if let Some(parent) = state_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let server_state = warden::ServerState::load(state_path.clone()).expect("ServerState::load");
    let server_state = Arc::new(server_state.with_pond_local_runtime(runtime.clone()));

    let server_handle = tokio::spawn({
        let s = server_state.clone();
        async move {
            let _ = warden::serve_on_listener(listener, s).await;
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let ident = format!("recon-smoke-{}-pond-site", std::process::id());
    let req = PondDeployReq {
        ident: ident.clone(),
        service: format!("recon-smoke-{}", std::process::id()),
        env: "pond".into(),
        component_id: "site".into(),
        minio: minio_spec.clone(),
        miniflare: miniflare_spec.clone(),
        ssr_runtime: None,
        mesofact_dev: None,
    };

    let client = reqwest::Client::new();
    let deploy_resp = client
        .post(format!("http://127.0.0.1:{port}/pond/deploy"))
        .json(&req)
        .send()
        .await
        .expect("POST /pond/deploy");
    assert!(
        deploy_resp.status().is_success(),
        "deploy returned {}: {}",
        deploy_resp.status(),
        deploy_resp.text().await.unwrap_or_default()
    );

    // ── Wait for Running (both MinIO and miniflare up) ──────────────────────
    wait_for_phase(
        port,
        &ident,
        |p| matches!(p, PondPhase::Running),
        DEPLOY_BUDGET,
    )
    .await
    .unwrap_or_else(|last| {
        panic!(
            "warden did not report Running within {:?}; last seen: {:?}",
            DEPLOY_BUDGET, last
        )
    });
    eprintln!("[reconciler-smoke] initial Running confirmed");

    // ── Kill MinIO, verify reconciler restarts it ───────────────────────────
    let t_kill = Instant::now();
    let killed = docker_kill(&container_name).await;
    assert!(killed, "docker kill {container_name} failed");
    eprintln!("[reconciler-smoke] docker killed MinIO container");

    let _degraded = wait_for_phase(
        port,
        &ident,
        |p| matches!(p, PondPhase::Degraded | PondPhase::Failed),
        RECOVER_BUDGET,
    )
    .await;
    wait_for_phase(
        port,
        &ident,
        |p| matches!(p, PondPhase::Running),
        RECOVER_BUDGET,
    )
    .await
    .unwrap_or_else(|last| {
        panic!(
            "warden did not restart MinIO within {:?} after kill; last seen: {:?}",
            RECOVER_BUDGET, last
        )
    });
    eprintln!(
        "[reconciler-smoke] MinIO recovered after {:.1?}",
        t_kill.elapsed()
    );

    // ── Kill miniflare process, verify reconciler restarts it ───────────────
    // Find the bun/node process listening on the miniflare port and kill it.
    let t_kill2 = Instant::now();
    let killed_mf = kill_miniflare_by_port(miniflare_port).await;
    if !killed_mf {
        eprintln!(
            "[reconciler-smoke] WARNING: could not find/kill miniflare process on port {}; \
             skipping miniflare restart assertion",
            miniflare_port
        );
    } else {
        eprintln!("[reconciler-smoke] killed miniflare process on port {miniflare_port}");
        let _degraded2 = wait_for_phase(
            port,
            &ident,
            |p| matches!(p, PondPhase::Degraded | PondPhase::Failed),
            RECOVER_BUDGET,
        )
        .await;
        wait_for_phase(
            port,
            &ident,
            |p| matches!(p, PondPhase::Running),
            RECOVER_BUDGET,
        )
        .await
        .unwrap_or_else(|last| {
            panic!(
                "warden did not restart miniflare within {:?} after kill; last seen: {:?}",
                RECOVER_BUDGET, last
            )
        });
        eprintln!(
            "[reconciler-smoke] miniflare recovered after {:.1?}",
            t_kill2.elapsed()
        );
    }

    // ── Teardown ────────────────────────────────────────────────────────────
    server_handle.abort();
    docker_force_rm(&container_name).await;
    let _ = std::fs::remove_file(&state_path);
}

/// Kill the process listening on `port` via `lsof` + `kill`. Returns `true`
/// when a process was found and signalled.
async fn kill_miniflare_by_port(port: u16) -> bool {
    let out = tokio::process::Command::new("lsof")
        .args(["-ti", &format!("tcp:{port}")])
        .output()
        .await
        .ok();
    let Some(out) = out else { return false };
    if !out.status.success() {
        return false;
    }
    let pids: Vec<_> = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();
    if pids.is_empty() {
        return false;
    }
    for pid in &pids {
        let _ = tokio::process::Command::new("kill")
            .arg(pid.to_string())
            .status()
            .await;
    }
    true
}
