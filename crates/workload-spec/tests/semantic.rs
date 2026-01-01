use std::collections::HashSet;
use std::path::PathBuf;

use workload_spec::validate::{
    self, ContextError, FieldPath, ValidationContext, WorkloadValidationError,
};
use workload_spec::{
    ExposeSpec, ImageRef, MachineId, MeshExpose, MeshIdent, Millis,
    OperatorExpose, PublicExpose, PublicTls, ResourceLimits, RestartPolicy, SecretMount, SecretRef,
    SecretTarget, StopPolicy, TierTag, WorkloadSpec,
};
use workload_spec::SchemaVersion;

// ── FakeContext ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct FakeContext {
    known_images: HashSet<String>,
    known_secrets: HashSet<String>,
    known_idents: HashSet<String>,
    /// Set of hostname suffixes considered "owned" CF zones.
    known_zones: HashSet<String>,
    known_tags: HashSet<String>,
    has_capacity: bool,
    /// If set, `image_exists` returns this error instead of checking the set.
    image_error: Option<String>,
}

impl FakeContext {
    fn builder() -> FakeBuilder {
        FakeBuilder::default()
    }
}

#[derive(Default)]
struct FakeBuilder {
    ctx: FakeContext,
}

impl FakeBuilder {
    fn image(mut self, registry: &str, repo: &str, tag: &str) -> Self {
        self.ctx.known_images.insert(format!("{registry}/{repo}:{tag}"));
        self
    }

    fn secret_file(mut self, path: &str) -> Self {
        self.ctx.known_secrets.insert(format!("file:{path}"));
        self
    }

    fn secret_cluster(mut self, name: &str) -> Self {
        self.ctx.known_secrets.insert(format!("cluster:{name}"));
        self
    }

    fn mesh_ident(mut self, ident: &str) -> Self {
        self.ctx.known_idents.insert(ident.into());
        self
    }

    fn cf_zone(mut self, suffix: &str) -> Self {
        self.ctx.known_zones.insert(suffix.into());
        self
    }

    fn tailscale_tag(mut self, tag: &str) -> Self {
        self.ctx.known_tags.insert(tag.into());
        self
    }

    fn with_capacity(mut self) -> Self {
        self.ctx.has_capacity = true;
        self
    }

    fn image_error(mut self, msg: &str) -> Self {
        self.ctx.image_error = Some(msg.into());
        self
    }

    fn build(self) -> FakeContext {
        self.ctx
    }
}

fn secret_key(s: &SecretRef) -> String {
    match s {
        SecretRef::LocalFile { path } => format!("file:{}", path.display()),
        SecretRef::Cluster { name } => format!("cluster:{name}"),
    }
}

impl ValidationContext for FakeContext {
    fn image_exists(&self, image: &ImageRef) -> Result<bool, ContextError> {
        if let Some(msg) = &self.image_error {
            return Err(ContextError(msg.clone()));
        }
        Ok(self.known_images.contains(&format!(
            "{}/{}/{}:{}",
            image.registry, image.registry, image.repository, image.tag
        )) || self.known_images.contains(&format!(
            "{}/{}:{}", image.registry, image.repository, image.tag
        )))
    }

    fn secret_exists(&self, secret: &SecretRef) -> Result<bool, ContextError> {
        Ok(self.known_secrets.contains(&secret_key(secret)))
    }

    fn mesh_ident_known(
        &self,
        ident: &MeshIdent,
        batch: &[MeshIdent],
    ) -> Result<bool, ContextError> {
        Ok(self.known_idents.contains(&ident.0) || batch.iter().any(|b| b == ident))
    }

    fn cf_zone_owned(&self, hostname: &str) -> Result<bool, ContextError> {
        Ok(self
            .known_zones
            .iter()
            .any(|z| hostname == z || hostname.ends_with(&format!(".{z}"))))
    }

    fn tailscale_tag_known(&self, tag: &str) -> Result<bool, ContextError> {
        Ok(self.known_tags.contains(tag))
    }

    fn capacity_for(
        &self,
        _spec: &WorkloadSpec,
        _machine_id: &MachineId,
    ) -> Result<bool, ContextError> {
        Ok(self.has_capacity)
    }
}

// ── Spec helpers ──────────────────────────────────────────────────────────────

fn machine() -> MachineId {
    MachineId("machine-1".into())
}

/// A spec that passes all shape checks. Needs a context with
/// image docker.io/library/alpine:3.19 and capacity=true to pass semantic.
fn minimal_spec() -> WorkloadSpec {
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: "test-svc".into(),
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
        resources: ResourceLimits {
            memory_mb: 64,
            cpu_shares: 256,
            ephemeral_storage_mb: 64,
        },
        depends_on: vec![],
        healthcheck: None,
        restart_policy: RestartPolicy::Always,
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(5),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent("test-svc".into()),
                ports: vec![8080],
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: Default::default(),
        annotations: Default::default(),
    }
}

fn full_ctx() -> FakeContext {
    FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .with_capacity()
        .build()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn minimal_spec_passes_semantic() {
    let spec = minimal_spec();
    let ctx = full_ctx();
    let result = validate::semantic(&spec, &ctx, &machine(), &[]);
    assert!(result.is_ok(), "minimal spec should pass semantic: {result:?}");
}

#[test]
fn unknown_image_returns_semantic_error() {
    let spec = minimal_spec();
    let ctx = FakeContext::builder().with_capacity().build(); // no image known
    let err = validate::semantic(&spec, &ctx, &machine(), &[]).unwrap_err();
    assert!(
        matches!(
            &err,
            WorkloadValidationError::Semantic(workload_spec::validate::SemanticError::Unknown {
                path: FieldPath::Image,
                ..
            })
        ),
        "expected Semantic(Unknown {{ Image }}) but got {err:?}"
    );
}

#[test]
fn unknown_secret_returns_semantic_error() {
    let mut spec = minimal_spec();
    spec.secrets.push(SecretMount {
        source: SecretRef::LocalFile {
            path: PathBuf::from("/var/lib/yah/warden/secrets/api-key"),
        },
        target: SecretTarget::EnvVar { name: "API_KEY".into() },
    });

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .with_capacity()
        .build(); // secret not registered

    let err = validate::semantic(&spec, &ctx, &machine(), &[]).unwrap_err();
    assert!(
        matches!(
            &err,
            WorkloadValidationError::Semantic(workload_spec::validate::SemanticError::Unknown {
                path: FieldPath::Secret(0, "source"),
                ..
            })
        ),
        "expected Semantic(Unknown {{ Secret(0, source) }}) but got {err:?}"
    );
}

#[test]
fn known_secret_passes() {
    let mut spec = minimal_spec();
    spec.secrets.push(SecretMount {
        source: SecretRef::LocalFile {
            path: PathBuf::from("/var/lib/yah/warden/secrets/api-key"),
        },
        target: SecretTarget::EnvVar { name: "API_KEY".into() },
    });

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .secret_file("/var/lib/yah/warden/secrets/api-key")
        .with_capacity()
        .build();

    assert!(validate::semantic(&spec, &ctx, &machine(), &[]).is_ok());
}

#[test]
fn unknown_depends_on_returns_semantic_error() {
    let mut spec = minimal_spec();
    spec.depends_on.push(MeshIdent("noisetable-db.pdx".into()));

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .with_capacity()
        .build(); // ident not registered

    let err = validate::semantic(&spec, &ctx, &machine(), &[]).unwrap_err();
    assert!(
        matches!(
            &err,
            WorkloadValidationError::Semantic(workload_spec::validate::SemanticError::Unknown {
                path: FieldPath::DependsOn(0),
                ..
            })
        ),
        "expected Semantic(Unknown {{ DependsOn(0) }}) but got {err:?}"
    );
}

#[test]
fn depends_on_resolved_via_deployed_ident() {
    let mut spec = minimal_spec();
    spec.depends_on.push(MeshIdent("noisetable-db.pdx".into()));

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .mesh_ident("noisetable-db.pdx")
        .with_capacity()
        .build();

    assert!(validate::semantic(&spec, &ctx, &machine(), &[]).is_ok());
}

#[test]
fn depends_on_resolved_via_batch() {
    let mut spec = minimal_spec();
    spec.depends_on.push(MeshIdent("db.local".into()));

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .with_capacity()
        .build(); // ident NOT in deployed set, but is in batch

    let batch = vec![MeshIdent("db.local".into())];
    assert!(
        validate::semantic(&spec, &ctx, &machine(), &batch).is_ok(),
        "depends_on ident in batch should count as known"
    );
}

#[test]
fn unknown_cf_zone_returns_semantic_error() {
    let mut spec = minimal_spec();
    spec.expose.mesh.ports.push(443);
    spec.expose.public = Some(PublicExpose {
        hostname: "api.example.com".into(),
        port: 443,
        tls: PublicTls::CfManaged,
    });
    // 443 must be in mesh ports for shape to pass
    spec.expose.mesh.ports = vec![8080, 443];

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .with_capacity()
        .build(); // no CF zone registered

    let err = validate::semantic(&spec, &ctx, &machine(), &[]).unwrap_err();
    assert!(
        matches!(
            &err,
            WorkloadValidationError::Semantic(workload_spec::validate::SemanticError::Unknown {
                path: FieldPath::Hostname,
                ..
            })
        ),
        "expected Semantic(Unknown {{ Hostname }}) but got {err:?}"
    );
}

#[test]
fn known_cf_zone_passes() {
    let mut spec = minimal_spec();
    spec.expose.mesh.ports = vec![8080, 443];
    spec.expose.public = Some(PublicExpose {
        hostname: "api.example.com".into(),
        port: 443,
        tls: PublicTls::CfManaged,
    });

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .cf_zone("example.com")
        .with_capacity()
        .build();

    assert!(validate::semantic(&spec, &ctx, &machine(), &[]).is_ok());
}

#[test]
fn unknown_tailscale_tag_returns_semantic_error() {
    let mut spec = minimal_spec();
    spec.expose.operator = Some(OperatorExpose {
        tailscale_tag: "tag:ops-team".into(),
        port: 8080,
    });

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .with_capacity()
        .build(); // tag not registered

    let err = validate::semantic(&spec, &ctx, &machine(), &[]).unwrap_err();
    assert!(
        matches!(
            &err,
            WorkloadValidationError::Semantic(workload_spec::validate::SemanticError::Unknown {
                path: FieldPath::TailscaleTag,
                ..
            })
        ),
        "expected Semantic(Unknown {{ TailscaleTag }}) but got {err:?}"
    );
}

#[test]
fn known_tailscale_tag_passes() {
    let mut spec = minimal_spec();
    spec.expose.operator = Some(OperatorExpose {
        tailscale_tag: "tag:ops-team".into(),
        port: 8080,
    });

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .tailscale_tag("tag:ops-team")
        .with_capacity()
        .build();

    assert!(validate::semantic(&spec, &ctx, &machine(), &[]).is_ok());
}

#[test]
fn insufficient_capacity_returns_semantic_error() {
    let spec = minimal_spec();
    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .build(); // has_capacity = false

    let err = validate::semantic(&spec, &ctx, &machine(), &[]).unwrap_err();
    assert!(
        matches!(
            &err,
            WorkloadValidationError::Semantic(workload_spec::validate::SemanticError::Unknown {
                path: FieldPath::Resources,
                ..
            })
        ),
        "expected Semantic(Unknown {{ Resources }}) but got {err:?}"
    );
}

#[test]
fn transient_image_lookup_failure_returns_context_error() {
    let spec = minimal_spec();
    let ctx = FakeContext::builder()
        .image_error("registry timeout")
        .with_capacity()
        .build();

    let err = validate::semantic(&spec, &ctx, &machine(), &[]).unwrap_err();
    assert!(
        matches!(&err, WorkloadValidationError::Context(_)),
        "transient lookup failure should surface as Context error, got {err:?}"
    );
}

// ── validate::all layering tests ──────────────────────────────────────────────

#[test]
fn all_shape_bad_spec_returns_shape_error_not_semantic() {
    // A spec with an invalid name (shape error) — semantic should never run.
    let mut spec = minimal_spec();
    spec.name = "-invalid-starts-with-dash".into(); // fails DNS label check

    let ctx = full_ctx();
    let err = validate::all(&spec, &ctx, &machine(), &[]).unwrap_err();
    assert!(
        matches!(&err, WorkloadValidationError::Shape(_)),
        "a shape-invalid spec should return Shape error from all(), not Semantic: {err:?}"
    );
}

#[test]
fn all_valid_spec_passes_both_layers() {
    let spec = minimal_spec();
    let ctx = full_ctx();
    assert!(validate::all(&spec, &ctx, &machine(), &[]).is_ok());
}

#[test]
fn all_shape_passes_but_semantic_fails_returns_semantic_error() {
    let spec = minimal_spec();
    // Context with no image — shape will pass, semantic will fail.
    let ctx = FakeContext::builder().with_capacity().build();
    let err = validate::all(&spec, &ctx, &machine(), &[]).unwrap_err();
    assert!(
        matches!(&err, WorkloadValidationError::Semantic(_)),
        "shape-valid but semantically invalid spec should return Semantic error: {err:?}"
    );
}

// ── Cluster secret ref ────────────────────────────────────────────────────────

#[test]
fn cluster_secret_ref_passes_when_known() {
    let mut spec = minimal_spec();
    spec.secrets.push(SecretMount {
        source: SecretRef::Cluster { name: "stripe-key".into() },
        target: SecretTarget::EnvVar { name: "STRIPE_SECRET".into() },
    });

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .secret_cluster("stripe-key")
        .with_capacity()
        .build();

    assert!(validate::semantic(&spec, &ctx, &machine(), &[]).is_ok());
}

#[test]
fn cluster_secret_ref_unknown_returns_error() {
    let mut spec = minimal_spec();
    spec.secrets.push(SecretMount {
        source: SecretRef::Cluster { name: "unknown-secret".into() },
        target: SecretTarget::EnvVar { name: "SOMETHING".into() },
    });

    let ctx = FakeContext::builder()
        .image("docker.io", "library/alpine", "3.19")
        .with_capacity()
        .build();

    let err = validate::semantic(&spec, &ctx, &machine(), &[]).unwrap_err();
    assert!(
        matches!(
            &err,
            WorkloadValidationError::Semantic(workload_spec::validate::SemanticError::Unknown {
                path: FieldPath::Secret(0, "source"),
                ..
            })
        ),
        "expected Secret(0, source) error, got {err:?}"
    );
}
