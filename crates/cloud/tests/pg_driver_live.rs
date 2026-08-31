//! Opt-in end-to-end test for dev-tier pg driver activation (W265, R584-F1).
//!
//! `#[ignore]` by default and needs two things the unit tests deliberately
//! don't: a built `yah-pg-dev` binary (it lives in the *root* workspace, so
//! this crate cannot depend on it) and network on a cold cache, because the
//! driver downloads its PostgreSQL tarball on first run.
//!
//! What it proves that nothing else can: the kamaji lowering actually spawns
//! the binary, the binary actually publishes `coords.json`, and `up_pg_driver`
//! actually reads a usable port back out of it. Every link in that chain is
//! a place a plausible-looking wiring bug hides.
//!
//! ```sh
//! cargo build -p yah-pg-dev --bin yah-pg-dev          # from the yah root
//! YAH_PG_DEV_BIN=$PWD/target/debug/yah-pg-dev \
//!   cargo test -p yah-cloud --test main -- pg_driver_live:: --include-ignored --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use cloud::reconciler::pg_driver::{coords_path, up_pg_driver, PgDriverOptions, PG_DEV_BIN_ENV};

#[tokio::test]
#[ignore = "needs a built yah-pg-dev binary (YAH_PG_DEV_BIN) and network on a cold cache"]
async fn camp_activation_spawns_the_driver_and_reads_back_a_port() {
    let Some(binary) = std::env::var_os(PG_DEV_BIN_ENV).map(PathBuf::from) else {
        panic!("set {PG_DEV_BIN_ENV} to a built yah-pg-dev binary — see this file's doc comment");
    };
    assert!(binary.exists(), "{} does not exist", binary.display());

    let camp = tempfile::tempdir().expect("tempdir");
    let opts = PgDriverOptions {
        binary: Some(binary),
        ready_timeout: Some(Duration::from_secs(180)),
    };

    let driver = up_pg_driver(camp.path(), vec!["svc_scrabcake_dev".to_string()], &opts)
        .await
        .expect("bring the dev-tier pg driver up");

    assert_ne!(driver.port, 0, "a bound port must be reported");
    assert_eq!(driver.databases, vec!["svc_scrabcake_dev".to_string()]);

    // The coordinates the camp hands downstream have to name the same port the
    // reconciler reported — a mismatch here is the bug this test exists for.
    let body = std::fs::read_to_string(coords_path(camp.path())).expect("coords.json");
    let coords: serde_json::Value = serde_json::from_str(&body).expect("parse coords");
    assert_eq!(coords["port"].as_u64(), Some(u64::from(driver.port)));
    assert_eq!(coords["username"].as_str(), Some("postgres"));
    assert!(
        coords["databases"]["svc_scrabcake_dev"]
            .as_str()
            .is_some_and(|u| u.contains(&driver.port.to_string())),
        "coords must carry a connection URL for the requested database: {body}"
    );

    driver.teardown().await;
}
