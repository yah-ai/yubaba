//! Smoke test for the live workspace's `.yah/` config.
//!
//! Loads the actual checked-in `.yah/services/`, `.yah/infra/`, and
//! `.yah/domains/` trees via [`CloudConfig::load`] and asserts the
//! cross-ref invariants hold. Catches regressions where someone edits
//! a manifest by hand and breaks a component ref, a provider use, or
//! the domain-route resolution that R347 introduced.
//!
//! Why an integration test (in `tests/`) rather than a unit test: this
//! is the only place we exercise the real workspace shape. Unit tests
//! build hermetic fixtures inside tempdirs and can't catch
//! "manifests-on-disk drift from the loader."

use std::path::PathBuf;

use cloud::CloudConfig;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/yah/cloud. Workspace root is 3 up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("crates/yah/cloud must be three levels under the workspace root")
        .to_path_buf()
}

#[test]
fn live_yah_workspace_loads_cleanly() {
    let root = workspace_root();
    let cfg = CloudConfig::load(&root).unwrap_or_else(|e| {
        panic!(
            "CloudConfig::load({}) failed — a committed manifest is malformed: {e:#}",
            root.display()
        )
    });

    // yah-marketing was renamed from dev-yah in R347-T1; the test pins
    // the rename so a future revert is loud.
    assert!(
        cfg.service("yah-marketing").is_some(),
        "expected `yah-marketing` service after R347-T1 rename"
    );

    // R347-F3 wrote both domain manifests. Their presence + cross-ref
    // resolution is the load-bearing claim of F3.
    assert!(cfg.domain("yah-dev").is_some(), "yah-dev domain missing");
    assert!(
        cfg.domain("app-yah-dev").is_some(),
        "app-yah-dev domain missing"
    );

    let yah_dev = cfg.domain("yah-dev").unwrap();
    assert_eq!(yah_dev.domain, "yah.dev");
    assert_eq!(yah_dev.cdn_bucket, "yah-dev");
    assert!(
        !yah_dev.routes.is_empty(),
        "yah-dev should have at least the catch-all marketing route"
    );

    let app_yah_dev = cfg.domain("app-yah-dev").unwrap();
    assert_eq!(app_yah_dev.domain, "app.yah.dev");
    assert_eq!(app_yah_dev.cdn_bucket, "yah-app-dev");

    // R343-T1 wired yah-dashboard into app-yah-dev. The cross-ref validator
    // in CloudConfig::load already checked that the component exists, but we
    // pin the service + route entry so a rename or deletion is loud here too.
    assert!(
        cfg.service("yah-dashboard").is_some(),
        "expected `yah-dashboard` service after R343-T1"
    );
    let yah_dashboard = cfg.service("yah-dashboard").unwrap();
    assert!(
        yah_dashboard.service.components.iter().any(|c| c.id == "dashboard"),
        "yah-dashboard service must have a `dashboard` component"
    );
    assert!(
        !app_yah_dev.routes.is_empty(),
        "app-yah-dev should have at least the yah-dashboard catch-all route"
    );
    let dashboard_route = app_yah_dev
        .routes
        .iter()
        .find(|r| r.path == "/*")
        .expect("app-yah-dev must have a /*  catch-all route");
    assert_eq!(
        dashboard_route.mode.component(),
        Some("yah-dashboard/dashboard"),
        "/* route must reference yah-dashboard/dashboard"
    );
}
