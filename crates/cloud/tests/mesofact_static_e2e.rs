//! End-to-end smoke for [`MesofactStaticReconciler`] against the real
//! `mesofact-dev` binary and the real `app/yah/web/marketing` workload.
//!
//! Skipped unless `YAH_RECONCILER_E2E_BIN` points at a built `mesofact-dev`
//! binary. Build it first with `cargo build -p mesofact-dev`, then run:
//!
//! ```bash
//! YAH_RECONCILER_E2E_BIN=$(pwd)/target/debug/mesofact-dev \
//!   cargo test -p cloud --test mesofact_static_e2e -- --nocapture
//! ```
//!
//! @yah:ticket(R441-B2, "mesofact_static_e2e: MirrorConfig missing asset_aliases field")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T22:56:09Z)
//! @yah:status(review)
//! @yah:parent(R441)
//! @yah:next("MirrorConfig at line 71 missing asset_aliases field (added for R429 static-asset alias chain). Compile error E0063.")
//! @yah:next("Add `asset_aliases: BTreeMap::new()` (or whatever empty value the type wants) to the fixture; the e2e test predates the alias mechanism and just needs the field to be a no-op for its scenario.")
//! @yah:verify("cargo test -p cloud --test mesofact_static_e2e passes")
//! @yah:handoff("Added asset_aliases: Default::default() to MirrorConfig fixture in mesofact_static_e2e.rs:83. cargo test -p cloud --test mesofact_static_e2e passes.")

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use cloud::{
    LocalStaticOptions, MesofactStaticReconciler, MirrorConfig, MirrorProviderSlot, MirrorShape,
    Provider, ProviderScope, ReconcileCtx, Reconciler, ServiceComponent, ServiceConfig,
};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/yah/cloud → ../../.. = workspace root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root from manifest dir")
        .to_path_buf()
}

fn pick_port() -> u16 {
    // Bind to 127.0.0.1:0, read assigned port, drop. Tiny race window
    // between drop and the spawned mesofact-dev re-binding the port; fine
    // for a smoke test.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

#[tokio::test]
async fn local_static_reconciler_brings_up_app_yah_web() {
    let Ok(bin) = std::env::var("YAH_RECONCILER_E2E_BIN") else {
        eprintln!("skipping: set YAH_RECONCILER_E2E_BIN=<path/to/mesofact-dev> to run");
        return;
    };
    let bin = PathBuf::from(bin);
    assert!(
        bin.exists(),
        "YAH_RECONCILER_E2E_BIN points at missing file: {}",
        bin.display(),
    );

    let workspace = workspace_root();
    let workload_path = workspace.join("app/yah/web/marketing");
    assert!(
        workload_path.join("workload.toml").exists(),
        "expected app/yah/web/marketing/workload.toml under {}",
        workspace.display(),
    );

    let port = pick_port();
    let mut fields = BTreeMap::new();
    fields.insert("port".to_string(), toml::Value::Integer(port as i64));
    let static_slot = MirrorProviderSlot::Inline {
        kind: Provider::LocalStatic,
        fields,
    };

    let mut providers = BTreeMap::new();
    providers.insert("static".to_string(), static_slot);
    let mirror = MirrorConfig {
        schema_version: 1,
        shape: MirrorShape::Local,
        providers,
        asset_aliases: Default::default(),
    };

    let service = ServiceConfig {
        schema_version: 1,
        name: "dev-yah".to_string(),
        domain: "yah.dev".to_string(),
        components: vec![],
        db: cloud::DbCatalog::default(),
    };
    let component = ServiceComponent {
        id: "site".to_string(),
        kind: "mesofact-static".to_string(),
        path: "app/yah/web/marketing".to_string(),
        role: "static".to_string(),
        publishes: None,
        git: None,
        wave: 0,
    };

    let reconciler = MesofactStaticReconciler::new().with_local_static(LocalStaticOptions {
        binary: Some(bin),
        // Default watch mode — mesofact-dev runs the initial build,
        // snapshots into .mesofact-dev/gen-0/, and starts serving. Adds
        // ~100 ms to the e2e but exercises the watcher path the operator
        // will hit.
        extra_args: vec![],
        // The initial bun build can take a few seconds on a cold cache.
        ready_timeout: Some(Duration::from_secs(30)),
        ..LocalStaticOptions::default()
    });

    let ctx = ReconcileCtx {
        workspace_root: &workspace,
        service: &service,
        component: &component,
        mirror: &mirror,
        env: "local",
        scope: ProviderScope::singleton(),
    };

    let running = reconciler
        .up(ctx)
        .await
        .expect("reconciler.up succeeds against real workload");
    let dev_url = running
        .dev_url
        .clone()
        .expect("local-static path sets dev_url");
    eprintln!("reconciler reported dev_url={dev_url}");
    assert!(dev_url.starts_with(&format!("http://127.0.0.1:{port}")));
    assert_eq!(running.kind, "mesofact-static");
    assert_eq!(running.slot, "static");

    // Curl through reqwest. The reconciler returns as soon as the port
    // binds, but with watch mode the initial bun build still has to
    // populate dist/html before / serves the real page. Poll until 200
    // (or timeout).
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let body = loop {
        let response = client
            .get(&dev_url)
            .send()
            .await
            .expect("GET / against reconciled dev_url");
        if response.status() == 200 {
            break response.text().await.expect("read body");
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "GET / never returned 200 (last status {}); initial build may have failed",
                response.status(),
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert!(
        body.contains("<!doctype html>") || body.contains("<!DOCTYPE html>"),
        "expected the served body to be HTML, got: {}",
        &body[..body.len().min(120)],
    );

    running.shutdown().await.expect("shutdown succeeds");

    // After shutdown the port should free up; give it a beat.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let connect = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await;
    assert!(
        connect.is_err(),
        "port {port} still accepting connections after shutdown"
    );
}
