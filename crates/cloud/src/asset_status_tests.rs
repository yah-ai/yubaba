//! R546-B12: `build_status_json` must never let a declared-but-unloadable
//! component vanish from the report.
//!
//! The bug this guards: the status walk parsed each `workload.toml` and did
//! `Err(_) => continue`. When R546-B7's envelope regression made every real
//! flat workload.toml unparseable, every component was silently dropped and
//! `yah cloud status` printed "no static-asset components or app manifests
//! found in this workspace" — telling the operator they had declared nothing
//! while `yah cloud apply` was reconciling the very same components fine.
//!
//! The parse bug is fixed, but the swallow is the durable hazard: whatever
//! breaks loading NEXT would produce the same confident false negative. These
//! tests pin that a load failure is REPORTED rather than dropped.
//!
//! Lives in its own file because `asset_status.rs` had no test module and the
//! fixture (a real on-disk `.yah/` tree that `CloudConfig::load` accepts) is
//! bulky enough to be worth isolating.

use std::path::Path;

use tempfile::TempDir;

/// Lay down the minimum `.yah/` tree `CloudConfig::load` accepts: one service
/// declaring one `static-asset` component, whose `workload.toml` content is
/// supplied by the caller.
fn workspace_with_component_workload(workload_toml: &str) -> TempDir {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();

    let comp_dir = root.join(".yah/services/demo/components/assets");
    std::fs::create_dir_all(&comp_dir).unwrap();
    std::fs::write(comp_dir.join("workload.toml"), workload_toml).unwrap();

    std::fs::write(
        root.join(".yah/services/demo/service.toml"),
        r#"schema_version = 1
name = "demo"
domain = "demo.example"

[[components]]
id = "assets"
kind = "static-asset"
path = ".yah/services/demo/components/assets"
role = "assets"
wave = 0
"#,
    )
    .unwrap();

    tmp
}

fn problems(report: &serde_json::Value) -> Vec<String> {
    report["problems"]
        .as_array()
        .expect("`problems` must always be present, even when empty")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect()
}

fn services_len(report: &serde_json::Value) -> usize {
    report["services"].as_array().map(Vec::len).unwrap_or(0)
}

const GOOD_WORKLOAD: &str = r#"kind = "static-asset"
schema_version = "V1"

[[asset]]
filename = "a/one.bin"
source = "src/one.bin"
blake3 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;

#[test]
fn a_healthy_component_reports_no_problems() {
    let tmp = workspace_with_component_workload(GOOD_WORKLOAD);
    let report = crate::asset_status::build_status_json(tmp.path(), &[], None);

    assert_eq!(services_len(&report), 1, "{report:#}");
    assert!(
        problems(&report).is_empty(),
        "a clean workspace must report no problems: {report:#}"
    );
}

#[test]
fn an_unparseable_workload_is_reported_not_silently_dropped() {
    let tmp = workspace_with_component_workload("kind = \"static-asset\"\nthis is not toml [[[\n");
    let report = crate::asset_status::build_status_json(tmp.path(), &[], None);

    // The component can't be rendered — that part is unavoidable.
    assert_eq!(services_len(&report), 0, "{report:#}");

    // But it must NOT look like the operator declared nothing.
    let problems = problems(&report);
    assert_eq!(problems.len(), 1, "{report:#}");
    assert!(
        problems[0].contains("demo/assets"),
        "must name the service/component: {problems:?}"
    );
    assert!(
        problems[0].contains("workload.toml"),
        "must name the file the operator has to fix: {problems:?}"
    );
}

#[test]
fn a_missing_workload_file_is_reported_not_silently_dropped() {
    let tmp = workspace_with_component_workload(GOOD_WORKLOAD);
    std::fs::remove_file(
        tmp.path()
            .join(".yah/services/demo/components/assets/workload.toml"),
    )
    .unwrap();

    let report = crate::asset_status::build_status_json(tmp.path(), &[], None);
    assert_eq!(services_len(&report), 0, "{report:#}");
    let problems = problems(&report);
    assert_eq!(problems.len(), 1, "{report:#}");
    assert!(problems[0].contains("cannot read"), "{problems:?}");
}

/// The regression in its original form: an envelope that rejects the real
/// on-disk shape. Whatever the cause, an empty `services` list next to an empty
/// `problems` list must mean "nothing was declared" and nothing else.
#[test]
fn an_empty_report_with_no_problems_means_nothing_was_declared() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join(".yah/services")).unwrap();

    let report = crate::asset_status::build_status_json(tmp.path(), &[], None);
    assert_eq!(services_len(&report), 0, "{report:#}");
    assert!(problems(&report).is_empty(), "{report:#}");
}

/// Guard the walk itself: a workspace root that isn't one at all.
#[test]
fn an_unloadable_workspace_reports_why() {
    let missing = Path::new("/nonexistent/definitely-not-a-yah-workspace");
    let report = crate::asset_status::build_status_json(missing, &[], None);
    // Either it loads an empty config or it fails — but `problems` must exist
    // either way so a consumer can branch on it without an Option dance.
    assert!(report.get("problems").is_some(), "{report:#}");
}
