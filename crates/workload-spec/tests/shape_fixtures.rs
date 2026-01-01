use std::collections::HashMap;
use std::path::Path;

use workload_spec::validate::{self, FieldPath};
use workload_spec::WorkloadSpec;

fn load(path: &Path) -> WorkloadSpec {
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
}

/// Map from fixture file stem to the expected failing field path.
fn expected_errors() -> HashMap<&'static str, FieldPath> {
    let mut m = HashMap::new();
    m.insert("name_empty", FieldPath::Name);
    m.insert("name_too_long", FieldPath::Name);
    m.insert("name_invalid_chars", FieldPath::Name);
    m.insert("mesh_identity_starts_dash", FieldPath::MeshIdentity);
    m.insert("tailscale_tag_no_prefix", FieldPath::TailscaleTag);
    m.insert("replicas_too_high", FieldPath::Replicas);
    m.insert("image_tag_empty", FieldPath::ImageTag);
    m.insert("bind_volume_non_infra", FieldPath::Volume(0, "source"));
    m.insert("public_port_not_in_mesh", FieldPath::ExposeMeshPort(9000));
    m.insert("secret_target_relative_path", FieldPath::Secret(0, "target.path"));
    m.insert("secret_env_var_lowercase", FieldPath::Secret(0, "target.name"));
    m
}

#[test]
fn bad_fixtures_produce_expected_shape_error() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bad");
    let expected = expected_errors();
    let mut checked = 0u32;

    for entry in std::fs::read_dir(&fixtures).expect("read fixtures/bad") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("stem")
            .to_owned();

        let spec = load(&path);
        let result = validate::shape(&spec);

        assert!(
            result.is_err(),
            "expected ShapeError for fixture {stem} but got Ok({:?})",
            result.as_ref().unwrap()
        );

        if let Some(expected_path) = expected.get(stem.as_str()) {
            let err = result.unwrap_err();
            let validate::ShapeError::Field { path: actual_path, .. } = &err;
            assert_eq!(
                actual_path, expected_path,
                "fixture {stem}: wrong field path — got {actual_path:?}, expected {expected_path:?}"
            );
        } else {
            panic!("fixture {stem} has no entry in expected_errors(); add one");
        }

        checked += 1;
    }

    assert!(checked > 0, "no .json files found in fixtures/bad — check the path");
    assert_eq!(
        checked as usize,
        expected.len(),
        "expected_errors() has {} entries but found {} .json fixtures",
        expected.len(),
        checked
    );
}

#[test]
fn valid_fixtures_pass_shape() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/valid");
    let mut checked = 0u32;

    for entry in std::fs::read_dir(&fixtures).expect("read fixtures/valid") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("stem")
            .to_owned();

        let spec = load(&path);
        let result = validate::shape(&spec);

        assert!(
            result.is_ok(),
            "expected shape to pass for fixture {stem} but got Err({:?})",
            result.unwrap_err()
        );
        checked += 1;
    }

    assert!(checked > 0, "no .json files found in fixtures/valid — check the path");
}

#[test]
fn restart_never_without_forge_annotation_warns() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/valid/warn_restart_never.json");
    let spec = load(&path);
    let warnings = validate::shape(&spec).expect("should pass shape");
    assert!(
        warnings
            .iter()
            .any(|w| w.path == FieldPath::RestartPolicy),
        "expected RestartPolicy warning for Never without yah.forge=true; got {:?}",
        warnings
    );
}

#[test]
fn restart_never_with_forge_annotation_no_warning() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/valid/warn_restart_never.json");
    let mut spec = load(&path);
    spec.annotations.insert("yah.forge".into(), "true".into());
    let warnings = validate::shape(&spec).expect("should pass shape");
    assert!(
        !warnings.iter().any(|w| w.path == FieldPath::RestartPolicy),
        "expected no RestartPolicy warning when yah.forge=true is set; got {:?}",
        warnings
    );
}

#[test]
fn healthcheck_short_delay_warns() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/valid/warn_healthcheck_delay.json");
    let spec = load(&path);
    let warnings = validate::shape(&spec).expect("should pass shape");
    assert!(
        warnings
            .iter()
            .any(|w| w.path == FieldPath::Healthcheck("initial_delay")),
        "expected Healthcheck(initial_delay) warning; got {:?}",
        warnings
    );
}

#[test]
fn unknown_tier_warns() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/valid/warn_unknown_tier.json");
    let spec = load(&path);
    let warnings = validate::shape(&spec).expect("should pass shape");
    assert!(
        warnings.iter().any(|w| w.path == FieldPath::Tier),
        "expected Tier warning for unknown tier; got {:?}",
        warnings
    );
}
