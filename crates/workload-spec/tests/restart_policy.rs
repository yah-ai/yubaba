use workload_spec::{
    testing::test_digest, validate, ImageRef, RestartPolicy, TierTag, WorkloadSpec,
};

fn forge_image() -> ImageRef {
    ImageRef {
        registry: "docker.io".into(),
        repository: "library/alpine".into(),
        tag: "3.19".into(),
        digest: test_digest(),
    }
}

#[test]
fn never_round_trip() {
    let cases = vec![
        RestartPolicy::Always,
        RestartPolicy::Never,
        RestartPolicy::OnFailure {
            max_attempts: 3,
            backoff: workload_spec::BackoffPolicy {
                initial_ms: 100,
                max_ms: 5000,
                multiplier: 1.5,
            },
        },
    ];
    for policy in cases {
        let json = serde_json::to_string(&policy).expect("serialize");
        let back: RestartPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, back, "round-trip failed for {json}");
    }
}

#[test]
fn semantic_warns_without_forge_annotation() {
    let spec = WorkloadSpec::for_forge("test-run-1", forge_image(), TierTag("infra".into()), vec![]);
    // for_forge sets yah.forge=true, so no warning
    let warnings = validate::shape(&spec).expect("shape");
    assert!(
        !warnings
            .iter()
            .any(|w| w.path == validate::FieldPath::RestartPolicy),
        "for_forge should suppress the Never warning; got {:?}",
        warnings
    );

    // Remove the annotation — warning should appear
    let mut spec_no_ann = spec.clone();
    spec_no_ann.annotations.remove("yah.forge");
    let warnings = validate::shape(&spec_no_ann).expect("shape");
    assert!(
        warnings
            .iter()
            .any(|w| w.path == validate::FieldPath::RestartPolicy),
        "expected RestartPolicy warning when yah.forge annotation absent; got {:?}",
        warnings
    );
}

#[test]
fn for_forge_sets_conventional_fields() {
    let spec = WorkloadSpec::for_forge(
        "build-42",
        forge_image(),
        TierTag("infra".into()),
        vec![8080],
    );

    assert!(
        matches!(spec.restart_policy, RestartPolicy::Never),
        "for_forge must set restart_policy=Never"
    );
    assert!(spec.expose.public.is_none(), "for_forge must leave expose.public=None");
    assert!(spec.expose.operator.is_none(), "for_forge must leave expose.operator=None");
    assert_eq!(
        spec.expose.mesh.identity.0, "forge.build-42",
        "mesh identity must be forge.<forge_id>"
    );
    assert_eq!(
        spec.annotations.get("yah.forge").map(String::as_str),
        Some("true"),
        "for_forge must set annotations[yah.forge]=true"
    );
    assert_eq!(spec.expose.mesh.ports, vec![8080]);
}
