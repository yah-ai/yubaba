//! Shape validators for [`WorkloadSpec`].
//!
//! Called by clients (desktop, agent, CLI) before sending a spec over RPC.
//! Sync, no I/O. Returns `Ok(warnings)` on pass or `Err(ShapeError)` on the
//! first hard constraint violation.
//!
//! Layers: shape (this file, no I/O) → semantic (yubaba-side, R090-F3) →
//! environment (deploy-time, R090-F4).

use std::fmt;
use std::sync::OnceLock;

use regex::Regex;
use thiserror::Error;

use crate::{
    EnvValue, EnvVar, ImageRef, MachineId, MeshIdent, MeshLookup, RestartPolicy, SecretRef,
    SecretTarget, StaticAssetWorkload, VolumeSource, WorkloadSpec,
};

// ── Field paths ───────────────────────────────────────────────────────────────

/// Identifies the field that caused a shape error or warning.
///
/// Structured as an enum so promoting to all-errors mode (collecting into
/// `Vec<FieldError>` instead of returning on the first hit) is mechanical.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldPath {
    Name,
    MeshIdentity,
    TailscaleTag,
    Replicas,
    ImageTag,
    Tier,
    /// `volumes[index].<sub>` — e.g. `Volume(0, "source")`.
    Volume(usize, &'static str),
    /// Public port not found in `expose.mesh.ports`.
    ExposeMeshPort(u16),
    /// `secrets[index].<sub>` — e.g. `Secret(0, "target.path")`.
    Secret(usize, &'static str),
    /// `healthcheck.<sub>`.
    Healthcheck(&'static str),
    RestartPolicy,
    /// `image` — registry says the image/tag is unknown.
    Image,
    /// `depends_on[index]` — mesh ident is not a known deployed workload.
    DependsOn(usize),
    /// `expose.public.hostname` — hostname is not in an owned CF zone.
    Hostname,
    /// `resources` — machine lacks sufficient capacity.
    Resources,
    /// `aliases[key]` — alias target filename is not in the `[[asset]]` catalog.
    AssetAlias(String),
    /// `asset[index].<sub>` — e.g. `Asset(0, "source")` for the XOR rule.
    Asset(usize, &'static str),
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldPath::Name => write!(f, "name"),
            FieldPath::MeshIdentity => write!(f, "expose.mesh.identity"),
            FieldPath::TailscaleTag => write!(f, "expose.operator.tailscale_tag"),
            FieldPath::Replicas => write!(f, "replicas"),
            FieldPath::ImageTag => write!(f, "image.tag"),
            FieldPath::Tier => write!(f, "tier"),
            FieldPath::Volume(i, sub) => write!(f, "volumes[{i}].{sub}"),
            FieldPath::ExposeMeshPort(port) => write!(f, "expose.public.port ({port})"),
            FieldPath::Secret(i, sub) => write!(f, "secrets[{i}].{sub}"),
            FieldPath::Healthcheck(sub) => write!(f, "healthcheck.{sub}"),
            FieldPath::RestartPolicy => write!(f, "restart_policy"),
            FieldPath::Image => write!(f, "image"),
            FieldPath::DependsOn(i) => write!(f, "depends_on[{i}]"),
            FieldPath::Hostname => write!(f, "expose.public.hostname"),
            FieldPath::Resources => write!(f, "resources"),
            FieldPath::AssetAlias(key) => write!(f, "aliases[{key}]"),
            FieldPath::Asset(i, sub) => write!(f, "asset[{i}].{sub}"),
        }
    }
}

// ── Hard errors ───────────────────────────────────────────────────────────────

/// A hard constraint violation that makes a spec impossible to deploy.
///
/// V1 surfaces the first error found. When the UI needs per-field
/// highlighting, wrap in `Vec<ShapeError>` and collect instead of returning
/// early — the `FieldPath` enum is already the common currency.
#[derive(Debug, Error, PartialEq)]
pub enum ShapeError {
    #[error("field {path}: {reason}")]
    Field { path: FieldPath, reason: String },
}

// ── Soft warnings ─────────────────────────────────────────────────────────────

/// A soft check that passed but may indicate misconfiguration.
#[derive(Debug, Clone, PartialEq)]
pub struct ShapeWarning {
    pub path: FieldPath,
    pub message: String,
}

impl fmt::Display for ShapeWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "warning at {}: {}", self.path, self.message)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// V1 known tier values. Unknown tiers produce a warning, not an error
/// (cluster config may add custom tiers).
const KNOWN_TIERS: &[&str] = &["public", "tenant", "private", "infra"];

fn dns_label_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$").unwrap())
}

fn env_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Z_][A-Z0-9_]*$").unwrap())
}

/// Validates a single DNS label: `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, ≤ 63 chars.
fn check_dns_label(value: &str, path: FieldPath) -> Result<(), ShapeError> {
    if value.len() > 63 {
        return Err(ShapeError::Field {
            path,
            reason: format!("length {} exceeds maximum 63", value.len()),
        });
    }
    if !dns_label_re().is_match(value) {
        return Err(ShapeError::Field {
            path,
            reason: format!(
                "{:?} must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
                value
            ),
        });
    }
    Ok(())
}

/// Validates a dot-separated mesh identity where each segment is a DNS label.
/// Total length ≤ 63. Example valid value: `"noisetable-api.pdx"`.
fn check_mesh_ident(value: &str, path: FieldPath) -> Result<(), ShapeError> {
    if value.len() > 63 {
        return Err(ShapeError::Field {
            path,
            reason: format!("length {} exceeds maximum 63", value.len()),
        });
    }
    for segment in value.split('.') {
        if !dns_label_re().is_match(segment) {
            return Err(ShapeError::Field {
                path,
                reason: format!(
                    "segment {:?} in {:?} must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
                    segment, value
                ),
            });
        }
    }
    Ok(())
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Run shape validation — sync, no I/O.
///
/// Returns `Ok(warnings)` when all hard constraints pass; the `Vec` is empty
/// for a clean spec. Returns `Err` on the first hard constraint violation.
/// Callers that only need hard errors can discard the Ok value with
/// `.map(|_| ())`.
///
/// Hard constraints checked:
/// - `name`, `expose.mesh.identity`: DNS-label format, ≤ 63 chars.
/// - `expose.operator.tailscale_tag`: `"tag:<dns-label>"`, ≤ 63 chars.
/// - `replicas`: 0–100.
/// - `image.tag`: non-empty when `digest` is `None`.
/// - `volumes[*].source = Bind`: only allowed when `tier = "infra"`.
/// - `expose.public.port`: must appear in `expose.mesh.ports`.
/// - `secrets[*].target`: file paths must be absolute; env-var names must
///   match `^[A-Z_][A-Z0-9_]*$`.
///
/// Soft checks (produce warnings, not errors):
/// - Unknown tier value.
/// - `RestartPolicy::Never` without `annotations["yah.forge"] = "true"`.
/// - `healthcheck.initial_delay < stop_policy.grace_period * 2`.
pub fn shape(spec: &WorkloadSpec) -> Result<Vec<ShapeWarning>, ShapeError> {
    let mut warnings: Vec<ShapeWarning> = Vec::new();

    // name: single DNS label, ≤ 63 chars
    check_dns_label(&spec.name, FieldPath::Name)?;

    // expose.mesh.identity: dot-separated DNS name, ≤ 63 total
    check_mesh_ident(&spec.expose.mesh.identity.0, FieldPath::MeshIdentity)?;

    // expose.operator.tailscale_tag: "tag:<dns-label>", ≤ 63 chars (optional)
    if let Some(op) = &spec.expose.operator {
        let tag = &op.tailscale_tag;
        if tag.len() > 63 {
            return Err(ShapeError::Field {
                path: FieldPath::TailscaleTag,
                reason: format!("length {} exceeds maximum 63", tag.len()),
            });
        }
        let rest = tag.strip_prefix("tag:").ok_or_else(|| ShapeError::Field {
            path: FieldPath::TailscaleTag,
            reason: format!("{:?} must start with \"tag:\"", tag),
        })?;
        if !dns_label_re().is_match(rest) {
            return Err(ShapeError::Field {
                path: FieldPath::TailscaleTag,
                reason: format!(
                    "the part after \"tag:\" in {:?} must match \
                     ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
                    tag
                ),
            });
        }
    }

    // replicas: 0..=100
    if spec.replicas > 100 {
        return Err(ShapeError::Field {
            path: FieldPath::Replicas,
            reason: format!("{} exceeds maximum 100", spec.replicas),
        });
    }

    // image.tag: non-empty (informational identifier; digest is the source of
    // truth and is structurally required at the type level).
    if spec.image.tag.is_empty() {
        return Err(ShapeError::Field {
            path: FieldPath::ImageTag,
            reason: "tag is empty; provide a human-readable tag alongside the digest".into(),
        });
    }

    // tier: warn on unknown (cluster config may add custom tiers)
    if !KNOWN_TIERS.contains(&spec.tier.0.as_str()) {
        warnings.push(ShapeWarning {
            path: FieldPath::Tier,
            message: format!(
                "\"{}\" is not in the known tier set (public/tenant/private/infra); \
                 yubaba may reject it if the cluster config does not include this tier",
                spec.tier.0
            ),
        });
    }

    // volumes[*]: Bind rejected unless tier = "infra"
    for (i, vol) in spec.volumes.iter().enumerate() {
        if matches!(&vol.source, VolumeSource::Bind { .. }) && spec.tier.0 != "infra" {
            return Err(ShapeError::Field {
                path: FieldPath::Volume(i, "source"),
                reason: format!(
                    "Bind mounts are only allowed when tier = \"infra\" \
                     (current tier: {:?})",
                    spec.tier.0
                ),
            });
        }
    }

    // expose.public.port must appear in expose.mesh.ports
    if let Some(public) = &spec.expose.public {
        if !spec.expose.mesh.ports.contains(&public.port) {
            return Err(ShapeError::Field {
                path: FieldPath::ExposeMeshPort(public.port),
                reason: format!(
                    "port {} must appear in expose.mesh.ports {:?} \
                     before it can be exposed publicly",
                    public.port, spec.expose.mesh.ports
                ),
            });
        }
    }

    // secrets[*]: target paths absolute; env-var names valid identifiers
    for (i, secret) in spec.secrets.iter().enumerate() {
        match &secret.target {
            SecretTarget::File { path, .. } => {
                if !path.is_absolute() {
                    return Err(ShapeError::Field {
                        path: FieldPath::Secret(i, "target.path"),
                        reason: format!("{:?} is not an absolute path", path),
                    });
                }
            }
            SecretTarget::EnvVar { name } => {
                if !env_name_re().is_match(name) {
                    return Err(ShapeError::Field {
                        path: FieldPath::Secret(i, "target.name"),
                        reason: format!(
                            "{:?} is not a valid env-var identifier (^[A-Z_][A-Z0-9_]*$)",
                            name
                        ),
                    });
                }
            }
        }
    }

    // soft: RestartPolicy::Never without yah.forge=true annotation
    if matches!(spec.restart_policy, RestartPolicy::Never) {
        let is_forge = spec
            .annotations
            .get("yah.forge")
            .map(|v| v == "true")
            .unwrap_or(false);
        if !is_forge {
            warnings.push(ShapeWarning {
                path: FieldPath::RestartPolicy,
                message: "restart_policy=Never is intended for forge runs; \
                          add annotation yah.forge=true to suppress this warning"
                    .into(),
            });
        }
    }

    // soft: healthcheck.initial_delay >= stop_policy.grace_period * 2
    if let Some(hc) = &spec.healthcheck {
        let min_recommended = spec.stop_policy.grace_period.as_ms().saturating_mul(2);
        if hc.initial_delay.as_ms() < min_recommended {
            warnings.push(ShapeWarning {
                path: FieldPath::Healthcheck("initial_delay"),
                message: format!(
                    "initial_delay ({}ms) is less than stop_policy.grace_period * 2 ({}ms); \
                     a SIGTERM during startup may catch a still-initialising container",
                    hc.initial_delay.as_ms(),
                    min_recommended
                ),
            });
        }
    }

    Ok(warnings)
}

// ── StaticAsset validator ─────────────────────────────────────────────────────

/// Shape-validate a `kind = "static-asset"` workload.
///
/// Enforces the closed-catalog invariant: every value in `[aliases]` must be a
/// `filename` present in `[[asset]]`. A mirror's `[asset_aliases]` overrides
/// are bound by the same rule and are validated separately at sync time when
/// both the workload and mirror are loaded together.
pub fn shape_static_asset(workload: &StaticAssetWorkload) -> Result<(), ShapeError> {
    // XOR rule (W164 / R438-T2): every [[asset]] row must set exactly one of
    // `source` (legacy local bytes) or `derive` (fetch + optional transform).
    // Both-set is ambiguous (which one wins?); neither-set leaves the
    // reconciler with no bytes to upload.
    for (i, entry) in workload.assets.iter().enumerate() {
        match (entry.source.is_some(), entry.derive.is_some()) {
            (true, true) => {
                return Err(ShapeError::Field {
                    path: FieldPath::Asset(i, "source"),
                    reason: format!(
                        "asset {:?}: both `source` and `derive` are set; pick exactly one",
                        entry.filename
                    ),
                });
            }
            (false, false) => {
                return Err(ShapeError::Field {
                    path: FieldPath::Asset(i, "source"),
                    reason: format!(
                        "asset {:?}: neither `source` nor `derive` is set; pick exactly one",
                        entry.filename
                    ),
                });
            }
            _ => {}
        }
    }

    let filenames: std::collections::HashSet<&str> =
        workload.assets.iter().map(|a| a.filename.as_str()).collect();

    for (alias_key, alias_target) in &workload.aliases {
        if !filenames.contains(alias_target.as_str()) {
            return Err(ShapeError::Field {
                path: FieldPath::AssetAlias(alias_key.clone()),
                reason: format!(
                    "alias target {:?} is not present in the [[asset]] catalog; \
                     add a matching [[asset]] row or correct the filename",
                    alias_target
                ),
            });
        }
    }

    Ok(())
}

// ── Semantic layer ────────────────────────────────────────────────────────────

/// Transient error from a [`ValidationContext`] lookup.
///
/// Distinct from a semantic "resource not found" failure. `ContextError` means
/// the lookup itself could not complete (network timeout, auth failure, etc.),
/// not that the resource is definitively absent.
#[derive(Debug, Error, Clone, PartialEq)]
#[error("context lookup failed: {0}")]
pub struct ContextError(pub String);

/// A semantic constraint violation: the spec references a resource that is not
/// known to the cluster at validation time.
#[derive(Debug, Error, PartialEq)]
pub enum SemanticError {
    #[error("field {path}: {reason}")]
    Unknown { path: FieldPath, reason: String },
}

/// Top-level validation error spanning both shape and semantic layers.
///
/// `Shape` always wins: if the spec is structurally invalid, semantic checks
/// never run.
#[derive(Debug, Error, PartialEq)]
pub enum WorkloadValidationError {
    /// Hard shape constraint failed — spec is structurally invalid.
    #[error("shape: {0}")]
    Shape(ShapeError),

    /// Semantic check failed — spec references an unknown cluster resource.
    #[error("semantic: {0}")]
    Semantic(SemanticError),

    /// Transient ValidationContext lookup failure — the check itself failed.
    #[error("context: {0}")]
    Context(ContextError),
}

impl From<ShapeError> for WorkloadValidationError {
    fn from(e: ShapeError) -> Self { WorkloadValidationError::Shape(e) }
}

impl From<ContextError> for WorkloadValidationError {
    fn from(e: ContextError) -> Self { WorkloadValidationError::Context(e) }
}

/// Read-only view of yubaba state used for semantic validation.
///
/// Defined here so clients (desktop, CLI, agents) can run semantic checks
/// without depending on the yubaba crate. Yubaba implements this trait.
///
/// Each method returns `Result<bool, ContextError>` so transient failures are
/// distinguishable from definitive "not found" answers.
pub trait ValidationContext {
    /// True when the registry confirms the image exists.
    fn image_exists(&self, image: &ImageRef) -> Result<bool, ContextError>;

    /// True when the named secret exists in the yubaba secret store.
    fn secret_exists(&self, secret: &SecretRef) -> Result<bool, ContextError>;

    /// True when `ident` is a known deployed workload OR appears in `batch`
    /// (the set of specs co-deployed in the same request — allows forward
    /// references within a single deployment batch).
    fn mesh_ident_known(&self, ident: &MeshIdent, batch: &[MeshIdent]) -> Result<bool, ContextError>;

    /// True when `hostname` falls under a Cloudflare zone owned by this cluster.
    fn cf_zone_owned(&self, hostname: &str) -> Result<bool, ContextError>;

    /// True when `tag` (e.g. `"tag:noisetable-ops"`) is in the cluster's
    /// Tailscale ACL tag list.
    fn tailscale_tag_known(&self, tag: &str) -> Result<bool, ContextError>;

    /// True when `machine_id` has sufficient remaining capacity to host the
    /// given spec's resource requirements.
    fn capacity_for(&self, spec: &WorkloadSpec, machine_id: &MachineId) -> Result<bool, ContextError>;
}

/// Run semantic validation — requires yubaba state via [`ValidationContext`].
///
/// Shape validation is NOT run here. Callers MUST run [`shape`] first; use
/// [`all`] to enforce this automatically.
///
/// `machine_id` is the target machine for admission-control capacity checks.
/// `batch` is the set of mesh idents being co-deployed (pass `&[]` for
/// single-spec deployment); these count as "known" for `depends_on` resolution.
pub fn semantic(
    spec: &WorkloadSpec,
    ctx: &dyn ValidationContext,
    machine_id: &MachineId,
    batch: &[MeshIdent],
) -> Result<(), WorkloadValidationError> {
    if !ctx.image_exists(&spec.image)? {
        return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
            path: FieldPath::Image,
            reason: format!(
                "image {}/{}:{} not found in registry",
                spec.image.registry, spec.image.repository, spec.image.tag
            ),
        }));
    }

    for (i, secret) in spec.secrets.iter().enumerate() {
        if !ctx.secret_exists(&secret.source)? {
            return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
                path: FieldPath::Secret(i, "source"),
                reason: format!("secret source at index {i} not found in yubaba secret store"),
            }));
        }
    }

    for (i, dep) in spec.depends_on.iter().enumerate() {
        if !ctx.mesh_ident_known(dep, batch)? {
            return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
                path: FieldPath::DependsOn(i),
                reason: format!("mesh ident {:?} is not a known deployed workload", dep.0),
            }));
        }
    }

    if let Some(public) = &spec.expose.public {
        if !ctx.cf_zone_owned(&public.hostname)? {
            return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
                path: FieldPath::Hostname,
                reason: format!(
                    "hostname {:?} is not under a Cloudflare zone owned by this cluster",
                    public.hostname
                ),
            }));
        }
    }

    if let Some(op) = &spec.expose.operator {
        if !ctx.tailscale_tag_known(&op.tailscale_tag)? {
            return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
                path: FieldPath::TailscaleTag,
                reason: format!(
                    "tailscale tag {:?} is not in the cluster's ACL tag list",
                    op.tailscale_tag
                ),
            }));
        }
    }

    if !ctx.capacity_for(spec, machine_id)? {
        return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
            path: FieldPath::Resources,
            reason: format!(
                "machine {:?} lacks capacity (memory={}MB cpu_shares={} ephemeral={}MB)",
                machine_id.0,
                spec.resources.memory_mb,
                spec.resources.cpu_shares,
                spec.resources.ephemeral_storage_mb
            ),
        }));
    }

    Ok(())
}

// ── Mesh resolution layer ─────────────────────────────────────────────────────

/// Failure surface for [`MeshResolver`] lookups.
///
/// `NotDeployed` means the dependency hasn't been observed in mesh state yet
/// (yubaba's deploy step waits on this — see [`crate::EnvValue::FromMesh`]).
/// `NoPorts` means the dependency is deployed but its `MeshExpose.ports`
/// list is empty, so a port-based lookup can't render a value. `Lookup`
/// covers transient failures from the underlying state read.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum MeshError {
    #[error("mesh ident {ident:?} is not yet deployed")]
    NotDeployed { ident: String },

    #[error(
        "mesh ident {ident:?} exposes no ports; {lookup:?} requires at least one"
    )]
    NoPorts { ident: String, lookup: MeshLookup },

    #[error("mesh state lookup failed: {0}")]
    Lookup(String),
}

/// Resolve [`crate::EnvValue::FromMesh`] references to literal env values.
///
/// Defined in workload-spec so clients (agents, desktop, CLI) can render
/// specs against fake mesh state without depending on the yubaba crate.
/// Yubaba's production implementation (in `yubaba::deploy::mesh_resolve`)
/// reads from raft state.
///
/// **Resolution rules** match the arch doc §"Mesh-derived env":
/// - [`MeshLookup::Url`] — `"http://<ident>:<port>"`, where `port` is the
///   first entry in the referenced workload's `MeshExpose.ports`.
/// - [`MeshLookup::Host`] — the bare DNS-ish identifier as authored (e.g.
///   `"noisetable-db.pdx"`).
/// - [`MeshLookup::Port`] — the first port stringified, e.g. `"5432"`.
///
/// Implementations should perform the port lookup atomically — a `Url` and
/// `Port` resolved in the same deploy must agree on which port was first.
pub trait MeshResolver {
    fn resolve(&self, ident: &MeshIdent, kind: MeshLookup) -> Result<String, MeshError>;
}

/// Render every [`EnvValue::FromMesh`] entry in `env` to a [`EnvValue::Literal`]
/// using `resolver`; pass through `Literal` and `FromSecret` values unchanged.
///
/// Returns the first resolution error encountered. Callers should run this
/// after yubaba's stage-3 mesh peering completes (see
/// `yubaba::deploy::env_validate::run` doc), at containerd-spec assembly.
///
/// `FromSecret` values are deliberately untouched here — secret resolution
/// is the secrets layer's job (R090-F5), not the mesh resolver's.
pub fn resolve_env_from_mesh(
    env: &[EnvVar],
    resolver: &dyn MeshResolver,
) -> Result<Vec<EnvVar>, MeshError> {
    env.iter()
        .map(|var| match &var.value {
            EnvValue::FromMesh { ident, kind } => {
                let value = resolver.resolve(ident, *kind)?;
                Ok(EnvVar {
                    name: var.name.clone(),
                    value: EnvValue::Literal { value },
                })
            }
            _ => Ok(var.clone()),
        })
        .collect()
}

/// Run shape then semantic validation in the correct order.
///
/// Shape always runs first. If shape fails, `WorkloadValidationError::Shape`
/// is returned and semantic checks are skipped — callers never see a
/// `Semantic` error for a structurally invalid spec.
///
/// `machine_id` is forwarded to the capacity admission-control check.
/// `batch` is the set of co-deployed mesh idents for forward-reference
/// resolution; pass `&[]` for single-spec deployment.
pub fn all(
    spec: &WorkloadSpec,
    ctx: &dyn ValidationContext,
    machine_id: &MachineId,
    batch: &[MeshIdent],
) -> Result<(), WorkloadValidationError> {
    shape(spec)?;
    semantic(spec, ctx, machine_id, batch)
}
