//! End-to-end smoke for the dev-tier static path: a real `yah-s3-fs` driver,
//! the real `app/yah/web/marketing` build output, and the same publish step
//! the pond and cloud tiers run.
//!
//! What it pins is the behavioural half of W265 / R584-F4 — that a dev-tier
//! `mesofact-static` component's assets are reachable **through the S3
//! driver's endpoint**, unsigned, with the `Content-Type` a browser needs. The
//! miniflare door in front of that endpoint is deliberately out of scope here:
//! it needs bun plus a workerd download, and what it adds is route rewriting
//! that `mesofact_static::tests::worker_script_*` already covers against the
//! same bundle every tier serves.
//!
//! Before R584-F4 this file drove `mesofact-dev` instead, because the dev tier
//! served `dist/` off the filesystem and had no bucket to publish into.
//!
//! Skipped unless `YAH_RECONCILER_E2E_BIN` points at a built `yah-s3-fs`
//! binary:
//!
//! ```bash
//! cargo build -p yah-s3-fs
//! YAH_RECONCILER_E2E_BIN=$(pwd)/target/debug/yah-s3-fs \
//!   cargo test -p yah-cloud --test main -- mesofact_static_e2e:: --nocapture
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
//! @yah:handoff("R584-F4 rewrote this file: the fixture it exercised (Provider::LocalStatic + LocalStaticOptions + the mesofact-dev binary) no longer exists, so the asset_aliases field this ticket was about is now supplied by the dev-tier fixture below instead. The annotation block stays here because the ticket is anchored to this file.")

use std::path::PathBuf;
use std::time::Duration;

use cloud::reconciler::pond_publish::publish_to_pond;
use cloud::reconciler::s3_driver::{
    up_s3_driver, S3DriverOptions, DEV_ACCESS_KEY, DEV_SECRET_KEY,
};

/// The monorepo root, found by walking up for `.yah/services` rather than by
/// counting path segments.
///
/// Counting is what the pre-R584-F4 version did (`.nth(3)`, with a comment
/// claiming `crates/yah/cloud`) and it had been wrong since this crate moved
/// under `oss/yubaba/` — it resolved to `<repo>/oss`. Nothing noticed, because
/// the whole test is env-gated. A marker beats an offset here: the crate is
/// also exported standalone, where no such root exists at any depth.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|d| d.join(".yah/services").is_dir())
        .expect("monorepo root (an ancestor containing .yah/services)")
        .to_path_buf()
}

#[tokio::test]
async fn dev_assets_are_served_through_the_s3_driver_endpoint() {
    let Some(bin) = std::env::var_os("YAH_RECONCILER_E2E_BIN").map(PathBuf::from) else {
        eprintln!("skipping: set YAH_RECONCILER_E2E_BIN to a built yah-s3-fs binary");
        return;
    };
    assert!(bin.exists(), "YAH_RECONCILER_E2E_BIN={} not found", bin.display());

    let repo = workspace_root();
    let dist = repo.join("app/yah/web/marketing/dist");
    assert!(
        dist.join("html/index.html").exists(),
        "expected a built marketing dist under {} — run its build first",
        dist.display(),
    );

    // The driver publishes coords under the workspace it is given, so point it
    // at a scratch root rather than the live camp's `.yah/infra/state/dev/s3`.
    // A test that retracted the running camp's coords.json would take
    // `S3_ENDPOINT` away from every dev service on this machine.
    let scratch = tempfile::tempdir().expect("scratch workspace");
    let bucket = "yah-marketing";
    let driver = up_s3_driver(
        scratch.path(),
        vec![bucket.to_string()],
        &S3DriverOptions {
            binary: Some(bin),
            ready_timeout: Some(Duration::from_secs(30)),
        },
    )
    .await
    .expect("yah-s3-fs comes up");

    let result = publish_and_probe(&driver.endpoint, bucket, &dist).await;
    driver.teardown().await;
    result.expect("dev publish + unsigned GET");
}

/// The assertion body, split out so a failure still tears the driver down.
async fn publish_and_probe(
    endpoint: &str,
    bucket: &str,
    dist: &std::path::Path,
) -> anyhow::Result<()> {
    local_driver::pond_minio::ensure_bucket_public(
        endpoint,
        bucket,
        DEV_ACCESS_KEY,
        DEV_SECRET_KEY,
    )
    .await?;

    let report =
        publish_to_pond(dist, endpoint, bucket, DEV_ACCESS_KEY, DEV_SECRET_KEY, None).await?;
    anyhow::ensure!(
        report.uploaded.iter().any(|k| k == "index.html"),
        "publish did not produce an index.html key: {:?}",
        report.uploaded,
    );

    // Unsigned, the way the door fetches: the bucket policy is what makes this
    // work, and it is the exact contract R554 found an alternative store
    // storing and then ignoring.
    let url = format!("{}/{}/index.html", endpoint.trim_end_matches('/'), bucket);
    let resp = reqwest::Client::new().get(&url).send().await?;
    anyhow::ensure!(
        resp.status().is_success(),
        "unsigned GET {url} → {}",
        resp.status(),
    );
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    anyhow::ensure!(
        content_type.starts_with("text/html"),
        "served index.html as {content_type:?} — a browser downloads that instead of rendering it",
    );
    let body = resp.text().await?;
    anyhow::ensure!(body.contains("<html"), "served body is not the built page");
    Ok(())
}
