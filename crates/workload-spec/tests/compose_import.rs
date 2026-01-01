//! Fixture-driven tests for [`workload_spec::compose_import`].
//!
//! Each sub-dir under `tests/compose/<name>/` contains a `docker-compose.yml`
//! plus either an `expected.json` (success path; matches `ImportResult` shape)
//! or an `expected_error.json` (rejection path; carries the variant tag and
//! offending service name).
//!
//! Successful imports are also fed through `validate::shape` to confirm the
//! generated specs are deployable.

use std::fs;
use std::path::Path;

use serde::Deserialize;
use workload_spec::compose_import::{import_compose, ImportError, ImportResult};
use workload_spec::validate;

const FIXTURES_DIR: &str = "tests/compose";

#[derive(Debug, Deserialize)]
struct ExpectedError {
    error: String,
    #[serde(default)]
    service: Option<String>,
}

fn fixture_dir(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURES_DIR).join(name)
}

fn read_yaml(name: &str) -> String {
    fs::read_to_string(fixture_dir(name).join("docker-compose.yml"))
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

fn read_expected_success(name: &str) -> ImportResult {
    let path = fixture_dir(name).join("expected.json");
    let s = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read expected.json for {name}: {e}"));
    serde_json::from_str(&s)
        .unwrap_or_else(|e| panic!("parse expected.json for {name}: {e}"))
}

fn read_expected_error(name: &str) -> ExpectedError {
    let path = fixture_dir(name).join("expected_error.json");
    let s = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read expected_error.json for {name}: {e}"));
    serde_json::from_str(&s)
        .unwrap_or_else(|e| panic!("parse expected_error.json for {name}: {e}"))
}

/// Compare two ImportResults via JSON to avoid printing screen-fulls of struct
/// debug output and to ignore field-order differences.
fn assert_import_eq(actual: &ImportResult, expected: &ImportResult, fixture: &str) {
    let actual_json =
        serde_json::to_value(actual).expect("serialize actual ImportResult");
    let expected_json =
        serde_json::to_value(expected).expect("serialize expected ImportResult");
    assert_eq!(
        actual_json, expected_json,
        "fixture {fixture}: actual import did not match expected.json\n\
         actual:\n{}\n\nexpected:\n{}\n",
        serde_json::to_string_pretty(&actual_json).unwrap(),
        serde_json::to_string_pretty(&expected_json).unwrap(),
    );
}

#[test]
fn simple_web_round_trip() {
    let yaml = read_yaml("simple-web");
    let result = import_compose(&yaml).expect("simple-web import should succeed");
    let expected = read_expected_success("simple-web");
    assert_import_eq(&result, &expected, "simple-web");

    // Smoke verify (Verify line 2): the imported spec passes shape validation.
    for spec in &result.specs {
        validate::shape(spec)
            .unwrap_or_else(|e| panic!("simple-web spec failed shape validation: {e}"));
    }
}

#[test]
fn multi_service_with_deps_round_trip() {
    let yaml = read_yaml("multi-service-with-deps");
    let result = import_compose(&yaml).expect("multi-service import should succeed");
    let expected = read_expected_success("multi-service-with-deps");
    assert_import_eq(&result, &expected, "multi-service-with-deps");

    for spec in &result.specs {
        validate::shape(spec)
            .unwrap_or_else(|e| panic!("multi-service spec failed shape validation: {e}"));
    }
}

#[test]
fn host_network_rejected() {
    let yaml = read_yaml("host-network-rejected");
    let err = import_compose(&yaml).expect_err("host-network must be rejected");
    let expected = read_expected_error("host-network-rejected");

    match err {
        ImportError::HostNetwork { service } => {
            assert_eq!(expected.error, "HostNetwork");
            assert_eq!(Some(service), expected.service);
        }
        other => panic!("expected HostNetwork rejection, got: {other:?}"),
    }
}

#[test]
fn build_block_warns() {
    let yaml = read_yaml("build-block-warns");
    let result = import_compose(&yaml).expect("build-block import should succeed (with warning)");
    let expected = read_expected_success("build-block-warns");
    assert_import_eq(&result, &expected, "build-block-warns");

    // Spec still passes shape validation — build blocks are warned and dropped,
    // not rejected.
    for spec in &result.specs {
        validate::shape(spec)
            .unwrap_or_else(|e| panic!("build-block spec failed shape validation: {e}"));
    }
}

/// Sanity guard: every sub-dir under `tests/compose/` must have a fixture
/// pair (docker-compose.yml + expected.json or expected_error.json) AND a
/// corresponding `#[test]` above. If you add a fixture dir, you must also
/// add a test — this guard fails closed otherwise.
#[test]
fn every_fixture_has_a_test() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURES_DIR);
    let known = [
        "simple-web",
        "multi-service-with-deps",
        "host-network-rejected",
        "build-block-warns",
    ];
    let mut on_disk: Vec<String> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            entry.file_type().ok()?.is_dir().then_some(())?;
            entry.file_name().into_string().ok()
        })
        .collect();
    on_disk.sort();
    let mut known_sorted: Vec<String> = known.iter().map(|s| s.to_string()).collect();
    known_sorted.sort();
    assert_eq!(
        on_disk, known_sorted,
        "fixture dirs on disk do not match the known list — add a test for any new fixture"
    );
}
