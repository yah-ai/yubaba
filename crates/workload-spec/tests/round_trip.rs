use std::collections::HashMap;
use std::path::PathBuf;

use workload_spec::*;

/// Representative spec with every field family populated.
fn full_spec() -> WorkloadSpec {
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: "noisetable-api".into(),
        image: ImageRef {
            registry: "ghcr.io".into(),
            repository: "noisetable/api".into(),
            tag: "v1.4.2".into(),
            digest: "sha256:abc123def456".into(),
        },
        tier: TierTag("private".into()),
        replicas: 2,
        command: Some(vec!["./server".into()]),
        entrypoint: Some(vec!["/bin/sh".into(), "-c".into()]),
        workdir: Some(PathBuf::from("/app")),
        user: Some("1000:1000".into()),
        env: vec![
            EnvVar {
                name: "APP_ENV".into(),
                value: EnvValue::Literal { value: "production".into() },
            },
            EnvVar {
                name: "DB_PASSWORD".into(),
                value: EnvValue::FromSecret {
                    secret: "db-creds".into(),
                    key: "password".into(),
                },
            },
            EnvVar {
                name: "DATABASE_URL".into(),
                value: EnvValue::FromMesh {
                    ident: MeshIdent("noisetable-db.pdx".into()),
                    kind: MeshLookup::Url,
                },
            },
        ],
        secrets: vec![
            SecretMount {
                source: SecretRef::LocalFile {
                    path: PathBuf::from("/var/lib/yah/yubaba/secrets/tls.crt"),
                },
                target: SecretTarget::File {
                    path: PathBuf::from("/etc/tls/cert.crt"),
                    mode: 0o400,
                },
            },
            SecretMount {
                source: SecretRef::Cluster { name: "stripe-key".into() },
                target: SecretTarget::EnvVar { name: "STRIPE_SECRET_KEY".into() },
            },
        ],
        volumes: vec![
            VolumeMount {
                source: VolumeSource::Named { name: "api-data".into() },
                target: PathBuf::from("/data"),
                read_only: false,
            },
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: PathBuf::from("/opt/yah/config"),
                },
                target: PathBuf::from("/config"),
                read_only: true,
            },
            VolumeMount {
                source: VolumeSource::Tmpfs { size_mb: 128 },
                target: PathBuf::from("/tmp"),
                read_only: false,
            },
        ],
        resources: ResourceLimits {
            memory_mb: 512,
            cpu_shares: 1024,
            ephemeral_storage_mb: 256,
        },
        depends_on: vec![MeshIdent("noisetable-db.pdx".into())],
        healthcheck: Some(Healthcheck {
            probe: HealthProbe::HttpGet {
                path: "/healthz".into(),
                port: 8080,
                expect_status: Some(200),
            },
            interval: Millis::from_secs(10),
            timeout: Millis::from_secs(5),
            initial_delay: Millis::from_secs(30),
            failure_threshold: 3,
        }),
        restart_policy: RestartPolicy::OnFailure {
            max_attempts: 5,
            backoff: BackoffPolicy {
                initial_ms: 500,
                max_ms: 30_000,
                multiplier: 2.0,
            },
        },
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(30),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent("noisetable-api.pdx".into()),
                ports: vec![8080, 9090],
                allow_from: vec![TierTag("private".into()), TierTag("tenant".into())],
            },
            public: Some(PublicExpose {
                hostname: "api.noisetable.io".into(),
                port: 8080,
                tls: PublicTls::CfManaged,
            }),
            operator: Some(OperatorExpose {
                tailscale_tag: "tag:noisetable-ops".into(),
                port: 9090,
            }),
        },
        labels: {
            let mut m = HashMap::new();
            m.insert("org.opencontainers.image.source".into(), "https://github.com/noisetable/api".into());
            m
        },
        annotations: {
            let mut m = HashMap::new();
            m.insert("yah.created-by".into(), "agent:claude".into());
            m
        },
    }
}

#[test]
fn round_trip_full_spec() {
    let original = full_spec();
    let json = serde_json::to_string_pretty(&original).expect("serialize");
    let decoded: WorkloadSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, decoded, "spec did not survive JSON round-trip");
}

#[test]
fn schema_version_serializes_as_v1() {
    let spec = full_spec();
    let json = serde_json::to_value(&spec).expect("to_value");
    assert_eq!(json["schema_version"], "V1");
}

#[test]
fn env_value_variants_round_trip() {
    let cases = vec![
        EnvValue::Literal { value: "hello".into() },
        EnvValue::FromSecret { secret: "my-secret".into(), key: "key".into() },
        EnvValue::FromMesh {
            ident: MeshIdent("svc.cluster".into()),
            kind: MeshLookup::Host,
        },
    ];
    for v in cases {
        let json = serde_json::to_string(&v).expect("serialize");
        let back: EnvValue = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, back);
    }
}

#[test]
fn restart_policy_variants_round_trip() {
    let cases = vec![
        RestartPolicy::Always,
        RestartPolicy::Never,
        RestartPolicy::OnFailure {
            max_attempts: 3,
            backoff: BackoffPolicy { initial_ms: 100, max_ms: 5000, multiplier: 1.5 },
        },
    ];
    for p in cases {
        let json = serde_json::to_string(&p).expect("serialize");
        let back: RestartPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back);
    }
}

#[test]
fn health_probe_variants_round_trip() {
    let cases = vec![
        HealthProbe::HttpGet { path: "/".into(), port: 80, expect_status: None },
        HealthProbe::HttpGet { path: "/ready".into(), port: 8080, expect_status: Some(204) },
        HealthProbe::Exec { argv: vec!["pg_isready".into()] },
        HealthProbe::TcpConnect { port: 5432 },
    ];
    for p in cases {
        let json = serde_json::to_string(&p).expect("serialize");
        let back: HealthProbe = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back);
    }
}

#[test]
fn empty_optional_fields_omitted_in_json() {
    let spec = WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: "minimal".into(),
        image: ImageRef {
            registry: "docker.io".into(),
            repository: "library/alpine".into(),
            tag: "3.19".into(),
            digest: workload_spec::testing::test_digest(),
        },
        tier: TierTag("private".into()),
        replicas: 1,
        command: None,
        entrypoint: None,
        workdir: None,
        user: None,
        env: vec![],
        secrets: vec![],
        volumes: vec![],
        resources: ResourceLimits { memory_mb: 64, cpu_shares: 256, ephemeral_storage_mb: 64 },
        depends_on: vec![],
        healthcheck: None,
        restart_policy: RestartPolicy::Always,
        stop_policy: StopPolicy { signal: 15, grace_period: Millis::from_secs(5) },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent("minimal.local".into()),
                ports: vec![80],
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: HashMap::new(),
        annotations: HashMap::new(),
    };

    let json = serde_json::to_value(&spec).expect("to_value");
    assert!(json.get("command").is_none(), "None command should be omitted");
    assert!(json.get("healthcheck").is_none(), "None healthcheck should be omitted");
    assert!(json.get("public").is_none(), "None public should be omitted");

    // Round-trip the minimal spec too
    let text = serde_json::to_string(&spec).expect("serialize");
    let back: WorkloadSpec = serde_json::from_str(&text).expect("deserialize");
    assert_eq!(spec, back);
}
