//! Spinup-budget smoke for the pond mirror path (R256-T5).
//!
//! Tests the full pond-tier stack end-to-end:
//! 1. Build `app/yah/web/marketing/` (or reuse an existing build).
//! 2. Bring up miniflare + MinIO via `MesofactStaticReconciler`.
//! 3. Publish `dist/` to MinIO with `publish_to_pond`.
//! 4. Curl the miniflare port and assert the served HTML is correct.
//! 5. Shut down, then bring up again to measure **warm restart** time.
//! 6. Assert warm restart is under the spinup budget.
//!
//! # Running
//!
//! Requires orbstack / colima / docker running and the
//! `YAH_LOCAL_SIM_E2E=1` env var. Images are pulled on first run; subsequent
//! runs reuse the cache.
//!
//! ```bash
//! YAH_LOCAL_SIM_E2E=1 cargo test -p cloud --test pond_smoke --locked -- --nocapture
//! ```
//!
//! To force a fresh workload build (bypassing the dist/ cache):
//! ```bash
//! YAH_LOCAL_SIM_E2E=1 YAH_LOCAL_SIM_REBUILD=1 \
//!   cargo test -p cloud --test pond_smoke --locked -- --nocapture
//! ```
//!
//! @yah:ticket(R454-S2, "Measure cold + warm pond spinup with containerised yubaba against W142 budget")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-05T08:23:58Z)
//! @yah:kind(spike)
//! @yah:status(review)
//! @yah:phase(C)
//! @yah:parent(R454)
//! @yah:next("Extend pond_smoke with a containerised-yubaba variant; capture cold (image pulled) + warm numbers vs W142's 'few-second cold / sub-second warm' budget")
//! @yah:next("Verdict: does image pre-warm need to ship in the same wave as F1, or after?")
//! @yah:verify("Numbers + verdict captured in W142 §Spinup budget or W180 followup; one of: (a) budget held, defer pre-warm; (b) budget exceeded, file pre-warm before flipping default")
//! @arch:see(.yah/docs/working/W180-pond-richer-topology.md)
//! @arch:see(.yah/docs/working/W142-pond.md)
//! @yah:handoff("Spike complete. Measured yubaba container spinup on OrbStack/arm64 (dev build, image cached): cold 653ms–2.15s (median ~1.2s), warm container restart 880ms–1.2s (median ~1.05s). Verdict: (a) warm budget HOLDS — yubaba stays running across pond down/up cycles per Phase B stop semantics; the W142 sub-second budget applies to MinIO+miniflare slot cycle only, not yubaba restart. (b) image pre-warm IS required — first-run yah-yubaba image pull (~120MB) would bust the cold budget; must ship alongside R454-F1. Also fixed a blocker: build_warden_run_spec was not injecting YAH_WARDEN_ARGS, so pond-supervise.sh started yubaba without the serve subcommand. Fixed in local_driver/src/pond_warden.rs — DEFAULT_WARDEN_ARGS injects 'serve --bind 0.0.0.0:8800 --state /var/lib/yah-yubaba/identity.json'. Numbers + verdict recorded in W142 §Spinup budget. warden_container_spinup_budget test added to pond_smoke.rs.")
//! @yah:verify("cargo test -p local-driver -- pond_warden (10 tests pass)")
//! @yah:verify("cargo test -p cloud --test pond_smoke --no-run (compiles clean)")
//! @yah:verify("YAH_LOCAL_SIM_E2E=1 cargo test -p cloud --test pond_smoke -- warden_container_spinup_budget --nocapture (measures cold+warm, asserts within generous budgets)")
//! @yah:verify("W142 §Spinup budget §Containerised-yubaba delta section present with numbers and verdict")

use std::path::PathBuf;
use std::time::{Duration, Instant};

use cloud::{
    local_container_spec_from_provider, publish_to_pond, CloudConfig, LocalRuntime,
    MesofactStaticReconciler, MirrorProviderSlot, PondOptions, Provider, ProviderScope,
    ReconcileCtx, Reconciler, ServiceComponent,
};
use local_driver::pond_warden::{
    build_warden_run_spec, WardenContainerSpec, DEFAULT_WARDEN_HTTP_PORT,
};

/// Spinup-budget constants (from feedback_container_sim_spinup_budget memory).
const COLD_START_BUDGET: Duration = Duration::from_secs(15);
const WARM_RESTART_BUDGET: Duration = Duration::from_secs(3);

/// Yubaba-container-only spinup budgets (R454-S2). Measure the overhead the
/// container shell adds before pond deploy; full-pond budget is above.
const WARDEN_COLD_BUDGET: Duration = Duration::from_secs(5);
const WARDEN_WARM_BUDGET: Duration = Duration::from_secs(3);
/// Absolute deadline for waiting on yubaba HTTP during the spike measurement.
const WARDEN_READY_TIMEOUT: Duration = Duration::from_secs(30);

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root three dirs above CARGO_MANIFEST_DIR")
        .to_path_buf()
}

/// Try to build `app/yah/web/marketing/` with `bun run build`. Skips the build
/// when `dist/html/index.html` already exists and `YAH_LOCAL_SIM_REBUILD` is
/// unset (avoids a ~100 ms build on every test run while still exercising the
/// full path on `REBUILD=1` or a clean checkout).
fn ensure_workload_built(workspace: &std::path::Path) -> PathBuf {
    let web_dir = workspace.join("app/yah/web/marketing");
    let dist_index = web_dir.join("dist/html/index.html");

    let rebuild = std::env::var("YAH_LOCAL_SIM_REBUILD").as_deref() == Ok("1");
    if !rebuild && dist_index.exists() {
        eprintln!(
            "[smoke] dist/html/index.html exists — skipping build. \
             Set YAH_LOCAL_SIM_REBUILD=1 to force a rebuild."
        );
        return web_dir.join("dist");
    }

    eprintln!("[smoke] building app/yah/web/marketing/ with `bun run build` …");
    let t0 = Instant::now();
    let status = std::process::Command::new("bun")
        .args(["run", "build"])
        .current_dir(&web_dir)
        .status()
        .expect("spawning `bun run build` — is bun on PATH?");
    assert!(
        status.success(),
        "`bun run build` exited with {status} in {}",
        web_dir.display(),
    );
    eprintln!("[smoke] build finished in {:.1?}", t0.elapsed());
    web_dir.join("dist")
}

#[tokio::test]
async fn pond_spinup_budget() {
    // ── Gate ───────────────────────────────────────────────────────────────
    if std::env::var("YAH_LOCAL_SIM_E2E").as_deref() != Ok("1") {
        eprintln!(
            "[smoke] SKIP: set YAH_LOCAL_SIM_E2E=1 to run the pond spinup-budget smoke.\n\
             Requires orbstack / colima / docker running."
        );
        return;
    }

    let workspace = workspace_root();
    eprintln!("[smoke] workspace root: {}", workspace.display());

    // ── Load service + mirror from real config ──────────────────────────
    let cloud = CloudConfig::load(&workspace).expect("CloudConfig::load");
    let svc_with_mirrors = cloud
        .services
        .get("dev-yah")
        .expect("dev-yah service in .yah/services/dev-yah/service.toml");
    let service = &svc_with_mirrors.service;
    let mirror = svc_with_mirrors
        .mirrors
        .get("pond")
        .expect("pond mirror in .yah/services/dev-yah/mirrors/pond.toml");

    // Verify the mirror declares the expected miniflare-container slot.
    match mirror.providers.get("static") {
        Some(MirrorProviderSlot::Inline {
            kind: Provider::MiniflareContainer,
            ..
        }) => {}
        other => panic!(
            "expected providers.static.kind = miniflare-container in pond.toml, got {other:?}"
        ),
    }

    // Pick the mesofact-static component.
    let component = service
        .components
        .iter()
        .find(|c| c.kind == "mesofact-static")
        .cloned()
        .unwrap_or_else(|| ServiceComponent {
            id: "site".into(),
            kind: "mesofact-static".into(),
            path: "app/yah/web/marketing".into(),
            role: "static".into(),
            git: None,
            publishes: None,
            wave: 0,
        });

    let reconciler = MesofactStaticReconciler::new();
    let make_ctx = || ReconcileCtx {
        workspace_root: &workspace,
        service,
        component: &component,
        mirror,
        env: "pond",
        scope: ProviderScope::singleton(),
    };

    // ── Build workload ──────────────────────────────────────────────────
    let dist_dir = ensure_workload_built(&workspace);
    assert!(
        dist_dir.join("html/index.html").exists(),
        "dist/html/index.html missing after build — check bun run build output"
    );

    // ── First bring-up (cold containers, images may be pulled) ─────────
    eprintln!("[smoke] cold start: bringing up miniflare + MinIO …");
    let t_cold = Instant::now();
    let running = reconciler
        .up(make_ctx())
        .await
        .expect("first reconciler.up — is orbstack/colima/docker running?");
    let cold_elapsed = t_cold.elapsed();
    let dev_url = running
        .dev_url
        .clone()
        .expect("pond path always sets dev_url");
    eprintln!(
        "[smoke] cold start done in {:.2?}  dev_url={dev_url}",
        cold_elapsed
    );

    // ── Publish dist/ to MinIO ──────────────────────────────────────────
    let opts = PondOptions::default();
    let minio_endpoint = "http://127.0.0.1:9000";
    eprintln!("[smoke] publishing dist/ to MinIO at {minio_endpoint} …");
    let t_pub = Instant::now();
    let report = publish_to_pond(
        &dist_dir,
        minio_endpoint,
        "yah-dev",
        &opts.minio_user,
        &opts.minio_password,
        None,
    )
    .await
    .expect("publish_to_pond");
    eprintln!(
        "[smoke] published {} key(s) in {:.2?}",
        report.uploaded.len(),
        t_pub.elapsed()
    );
    if !report.would_purge_tags.is_empty() {
        eprintln!(
            "[smoke] (would purge {} CDN tag(s) in prod: {:?})",
            report.would_purge_tags.len(),
            report.would_purge_tags,
        );
    }
    assert!(
        !report.uploaded.is_empty(),
        "publish uploaded zero keys — dist/ may be empty"
    );
    assert!(
        report.uploaded.contains(&"index.html".to_string()),
        "expected index.html in uploaded keys; got {:?}",
        report.uploaded,
    );

    // ── Curl Caddy — verify the artifact is served ──────────────────────
    eprintln!("[smoke] curling {} …", dev_url);
    let client = reqwest::Client::new();
    let resp = client
        .get(&dev_url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("GET /");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "GET {dev_url} returned {status}; body prefix: {}",
        &body[..body.len().min(200)],
    );
    assert!(
        body.contains("<!doctype html>") || body.contains("<!DOCTYPE html>"),
        "expected HTML body from miniflare, got: {}",
        &body[..body.len().min(200)],
    );
    eprintln!("[smoke] miniflare served HTML ({} bytes) ✓", body.len());

    // ── Shut down (needed before warm-restart measurement) ──────────────
    running.shutdown().await.expect("first shutdown");
    eprintln!("[smoke] containers stopped");

    // ── Warm restart ────────────────────────────────────────────────────
    eprintln!("[smoke] warm restart: re-bringing up (images cached, containers stopped) …");
    let t_warm = Instant::now();
    let running2 = reconciler.up(make_ctx()).await.expect("warm reconciler.up");
    let warm_elapsed = t_warm.elapsed();
    eprintln!("[smoke] warm restart done in {:.2?}", warm_elapsed);
    running2.shutdown().await.expect("second shutdown");

    // ── Report ──────────────────────────────────────────────────────────
    eprintln!("\n[smoke] ═══ spinup-budget results ═══");
    eprintln!(
        "  cold start  : {:.2?}  (budget: {:?})",
        cold_elapsed, COLD_START_BUDGET
    );
    eprintln!(
        "  warm restart: {:.2?}  (budget: {:?})",
        warm_elapsed, WARM_RESTART_BUDGET
    );
    eprintln!("  published   : {} key(s)", report.uploaded.len());
    eprintln!("  curl /      : 200 OK ({} bytes)", body.len());

    // ── Assertions ──────────────────────────────────────────────────────
    assert!(
        cold_elapsed < COLD_START_BUDGET,
        "cold start {:.2?} exceeded budget {:?}\n\
         (Note: cold budget includes image pull on first run — this budget applies once images are cached.)",
        cold_elapsed,
        COLD_START_BUDGET,
    );
    assert!(
        warm_elapsed < WARM_RESTART_BUDGET,
        "warm restart {:.2?} exceeded budget {:?}\n\
         Timing breakdown: reconciler.up includes socket-probe + container pre-clear + \
         container start + bucket ensure + wait_for_port. \
         If > {:?}, check orbstack health or container naming conflicts.",
        warm_elapsed,
        WARM_RESTART_BUDGET,
        WARM_RESTART_BUDGET,
    );
    eprintln!("[smoke] ✓ all assertions passed");
}

// ── Helpers shared by the yubaba-container test ───────────────────────────────

/// Detect the local docker runtime from the workspace CloudConfig.
async fn detect_local_runtime(workspace: &std::path::Path) -> Option<LocalRuntime> {
    let cfg = CloudConfig::load(workspace).ok()?;
    let provider = cfg
        .providers
        .iter()
        .find(|p| matches!(p.kind, Provider::LocalContainer))?;
    let spec = local_container_spec_from_provider(provider).ok()?;
    LocalRuntime::detect(&spec).await.ok()
}

/// Poll `GET http://127.0.0.1:{port}/pond` until it returns 200 OK or the
/// deadline is exceeded. Returns the elapsed time on success.
async fn wait_for_warden_http(port: u16, deadline: Duration) -> Result<Duration, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .expect("reqwest client");
    let start = Instant::now();
    while start.elapsed() < deadline {
        match client
            .get(format!("http://127.0.0.1:{port}/pond"))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => return Ok(start.elapsed()),
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "yubaba HTTP on port {port} not ready within {deadline:?}"
    ))
}

/// Measure the overhead the yah-yubaba container adds to pond bring-up.
///
/// Tests two timing points (R454-S2 spike):
/// - **Cold** (image already pulled, container freshly started): `docker run` +
///   tini + kamaji UDS bind + yubaba HTTP bind.
/// - **Warm** (container stopped, then restarted): same path but OCI layer
///   cache is warm and the state dir is already initialised.
///
/// Neither timing includes image pull (pre-warmed above). The verdict from
/// these numbers feeds W142 §Spinup budget and decides whether image pre-warm
/// must ship in the same wave as R454-F1 (the actual camp integration) or after.
///
/// # Budgets
///
/// [`WARDEN_COLD_BUDGET`] and [`WARDEN_WARM_BUDGET`] are intentionally generous
/// for this spike: we want the real numbers, not a gate-pass/fail. Tighten them
/// once the F1 integration lands and the full-pond smoke (`pond_spinup_budget`)
/// absorbs the yubaba contribution.
#[tokio::test]
async fn warden_container_spinup_budget() {
    if std::env::var("YAH_LOCAL_SIM_E2E").as_deref() != Ok("1") {
        eprintln!(
            "[yubaba-smoke] SKIP: set YAH_LOCAL_SIM_E2E=1 to run the yubaba \
             container spinup budget. Requires orbstack / colima / docker + \
             yah-yubaba image (ghcr.io/yah-ai/yah-yubaba:latest)."
        );
        return;
    }

    let workspace = workspace_root();

    let runtime = match detect_local_runtime(&workspace).await {
        Some(r) => r,
        None => {
            eprintln!(
                "[yubaba-smoke] SKIP: no reachable local-container runtime; \
                 start orbstack/colima/docker and rerun."
            );
            return;
        }
    };

    let warden_image = local_driver::pond_warden::DEFAULT_WARDEN_IMAGE;

    // Ensure the image is present — pull cost is NOT part of the spinup budget.
    let pulled = runtime
        .ensure_image(warden_image)
        .await
        .expect("ensure_image yah-yubaba — build or pull ghcr.io/yah-ai/yah-yubaba:latest first");
    if pulled {
        eprintln!("[yubaba-smoke] image pulled fresh from registry");
    } else {
        eprintln!("[yubaba-smoke] image already in local cache");
    }

    let pid = std::process::id();
    let state_dir = workspace
        .join(".yah/jit")
        .join(format!("yubaba-spinup-smoke-{pid}"));
    std::fs::create_dir_all(&state_dir).expect("create yubaba state dir");

    // The pond yubaba container is camp-scoped, not service-scoped — the name
    // is `yah-pond-camp-<env>-yubaba`, so `new` takes (env, state_dir) only.
    let mut spec = WardenContainerSpec::new("pond-s2", state_dir.clone());
    spec.http_port = 0; // random host port — resolved via `docker port` after start

    let run_spec = build_warden_run_spec(&spec);
    let container_name = run_spec.name.clone();
    eprintln!("[yubaba-smoke] container name: {container_name}");

    // Cleanup guard — `docker rm -f` + remove state dir on test exit.
    struct Guard(String, PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", &self.0])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }
    let _guard = Guard(container_name.clone(), state_dir.clone());

    // ── Cold start ────────────────────────────────────────────────────────────
    eprintln!("[yubaba-smoke] cold start …");
    let t_cold = Instant::now();
    runtime
        .run(&run_spec)
        .await
        .expect("docker run yubaba (cold)");

    let host_port = runtime
        .container_host_port(&container_name, DEFAULT_WARDEN_HTTP_PORT)
        .await
        .expect("docker port yubaba:8800");
    eprintln!("[yubaba-smoke] yubaba bound to host port {host_port}; waiting for HTTP …");

    let cold_ready = wait_for_warden_http(host_port, WARDEN_READY_TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let cold_elapsed = t_cold.elapsed();
    eprintln!(
        "[yubaba-smoke] cold: docker run→HTTP={:.2?}  total={:.2?}",
        cold_ready, cold_elapsed,
    );

    // ── Stop ──────────────────────────────────────────────────────────────────
    runtime
        .stop_and_remove(&container_name, Duration::from_secs(10))
        .await
        .expect("stop yubaba container");
    eprintln!("[yubaba-smoke] container stopped");

    // ── Warm restart ──────────────────────────────────────────────────────────
    eprintln!("[yubaba-smoke] warm restart …");
    let t_warm = Instant::now();
    runtime
        .run(&run_spec)
        .await
        .expect("docker run yubaba (warm)");

    let host_port2 = runtime
        .container_host_port(&container_name, DEFAULT_WARDEN_HTTP_PORT)
        .await
        .expect("docker port yubaba:8800 (warm)");

    let warm_ready = wait_for_warden_http(host_port2, WARDEN_READY_TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let warm_elapsed = t_warm.elapsed();
    eprintln!(
        "[yubaba-smoke] warm: docker run→HTTP={:.2?}  total={:.2?}",
        warm_ready, warm_elapsed,
    );

    // ── Report ────────────────────────────────────────────────────────────────
    eprintln!("\n[yubaba-smoke] ═══ yubaba container spinup results ═══");
    eprintln!("  image        : {warden_image}");
    eprintln!(
        "  cold start   : {:.2?}  (budget: {:?})",
        cold_elapsed, WARDEN_COLD_BUDGET
    );
    eprintln!(
        "  warm restart : {:.2?}  (budget: {:?})",
        warm_elapsed, WARDEN_WARM_BUDGET
    );
    // NOTE: the W142 "sub-second warm" budget applies to the slot cycle
    // (MinIO + miniflare restart via DELETE /pond?ident + POST /pond/deploy),
    // NOT to yubaba container restart — yubaba stays running across pond
    // down/up cycles in the Phase B stop model. Yubaba container restart is a
    // full-`camp-shutdown` scenario only.
    eprintln!(
        "  NOTE: yubaba stays running across pond down/up; this measures\n  \
         yubaba container restart (camp-shutdown scenario only)."
    );

    assert!(
        cold_elapsed < WARDEN_COLD_BUDGET,
        "yubaba cold start {:.2?} exceeded budget {:?}",
        cold_elapsed,
        WARDEN_COLD_BUDGET,
    );
    assert!(
        warm_elapsed < WARDEN_WARM_BUDGET,
        "yubaba warm restart {:.2?} exceeded budget {:?}",
        warm_elapsed,
        WARDEN_WARM_BUDGET,
    );
    eprintln!("[yubaba-smoke] ✓ yubaba container spinup within budget");
}
