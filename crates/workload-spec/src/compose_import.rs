//! One-way, lossy compose YAML → [`WorkloadSpec`] import shim.
//!
//! Best-effort translation of a docker-compose v3 file into a set of
//! `WorkloadSpec` values, one per compose service. The output may need
//! hand-editing — compose's expressiveness exceeds ours by design and we lose
//! the parts we don't want. This shim is for one-time migration, not
//! round-trip authoring.
//!
//! Lossy areas (each emits an [`ImportWarning`] keyed by compose path):
//!
//! - `network_mode: host` → rejected as [`ImportError::HostNetwork`].
//! - `build:` blocks → ignored with warning ("build externally; provide an
//!   `image:` reference").
//! - Custom networks → flattened to the mesh; warns when topology can't be
//!   preserved.
//! - Bind volumes → echoed as warning that yubaba requires `tier = "infra"`
//!   (the importer auto-promotes the spec's tier when bind mounts are
//!   present so the result still passes shape validation).
//! - Healthcheck blocks → noted as warning; not translated in V1 (compose's
//!   syntax is rich enough to deserve its own pass).
//!
//! See `.yah/docs/architecture/A054-yah-workload-spec.md` §"Compose-import shim" for
//! the design contract.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    EnvValue, EnvVar, ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, RestartPolicy,
    ResourceLimits, SchemaVersion, StopPolicy, TierTag, VolumeMount, VolumeSource, WorkloadSpec,
};

// ── Public types ──────────────────────────────────────────────────────────────

/// Output of [`import_compose`].
///
/// Serializable so the CLI can emit it as JSON and tests can compare against
/// fixture snapshots without a bespoke equality codec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportResult {
    /// One spec per compose service. Order matches the `services:` map's
    /// iteration order (sorted by service name for determinism).
    pub specs: Vec<WorkloadSpec>,

    /// Soft warnings for lossy translations. Each carries a compose path so
    /// the operator can find the original block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ImportWarning>,
}

/// A non-fatal lossy translation noted during import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportWarning {
    /// Compose path for the affected block, e.g. `"services.web.build"`.
    pub path: String,
    /// Operator-facing explanation.
    pub message: String,
}

/// A hard rejection during import.
#[derive(Debug, Error, PartialEq)]
pub enum ImportError {
    /// The YAML failed to parse as a compose file.
    #[error("compose YAML parse error: {0}")]
    Parse(String),

    /// The compose file has no `services:` block to translate.
    #[error("compose file has no `services:` block")]
    NoServices,

    /// A service uses `network_mode: host`. Yubaba has no host-networking
    /// escape hatch — every workload runs on the mesh. See arch doc
    /// §"What's deliberately not in the schema".
    #[error(
        "service {service:?}: network_mode=host is not supported on the yubaba mesh \
         (every workload runs through the mesh; see \
         .yah/docs/architecture/A054-yah-workload-spec.md §\"What's deliberately not in the schema\")"
    )]
    HostNetwork { service: String },

    /// A service has neither `image:` nor a usable image fallback. Yubaba
    /// can't deploy without an image reference.
    #[error("service {service:?}: no `image:` field — yubaba requires an image reference")]
    MissingImage { service: String },

    /// A service's `image:` reference lacks an `@sha256:<hex>` digest pin.
    /// R438-T3 made digest-pinning structurally required; bare-tag references
    /// like `node:20` no longer construct an [`ImageRef`]. The operator should
    /// pin the digest in the compose file (`image: node:20@sha256:<hex>`).
    #[error("service {service:?}: image {image:?} is not digest-pinned ({reason})")]
    UnpinnedImage {
        service: String,
        image: String,
        reason: String,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Parse a compose v3 YAML string into a set of [`WorkloadSpec`] values.
///
/// Multi-service composes produce one spec per service. Compose service names
/// become mesh idents (with `_` rewritten to `-` and a warning). `depends_on`
/// translates by compose service name → mesh ident.
///
/// Returns the first hard rejection ([`ImportError`]) on rejection paths;
/// otherwise returns [`ImportResult`] with one entry per service.
pub fn import_compose(yaml: &str) -> Result<ImportResult, ImportError> {
    let compose: ComposeFile =
        serde_yaml::from_str(yaml).map_err(|e| ImportError::Parse(e.to_string()))?;

    if compose.services.is_empty() {
        return Err(ImportError::NoServices);
    }

    let mut warnings = Vec::new();

    // Top-level networks: yubaba flattens to one mesh, so any custom networks
    // are lossy.
    if !compose.networks.is_empty() {
        warnings.push(ImportWarning {
            path: "networks".into(),
            message: format!(
                "compose declared {} custom network(s) ({}); yubaba flattens all workloads \
                 onto one mesh — segmentation must be re-expressed via tier `allow_from`",
                compose.networks.len(),
                compose
                    .networks
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }

    let mut specs = Vec::with_capacity(compose.services.len());

    let mut service_names: Vec<&String> = compose.services.keys().collect();
    service_names.sort();
    for service_name in service_names {
        let svc = &compose.services[service_name];
        let spec = translate_service(service_name, svc, &mut warnings)?;
        specs.push(spec);
    }

    Ok(ImportResult { specs, warnings })
}

// ── Translation ───────────────────────────────────────────────────────────────

fn translate_service(
    name: &str,
    svc: &ComposeService,
    warnings: &mut Vec<ImportWarning>,
) -> Result<WorkloadSpec, ImportError> {
    if svc.network_mode.as_deref() == Some("host") {
        return Err(ImportError::HostNetwork { service: name.into() });
    }

    if let Some(mode) = &svc.network_mode {
        if mode != "host" && mode != "default" && mode != "bridge" {
            warnings.push(ImportWarning {
                path: format!("services.{name}.network_mode"),
                message: format!(
                    "network_mode={mode:?} ignored — yubaba runs every workload on the mesh"
                ),
            });
        }
    }

    if svc.build.is_some() {
        warnings.push(ImportWarning {
            path: format!("services.{name}.build"),
            message: "build: blocks are ignored. Build externally (CI) and provide an \
                      image: reference; see arch doc §\"What's deliberately not in the schema\""
                .into(),
        });
    }

    if svc.healthcheck.is_some() {
        warnings.push(ImportWarning {
            path: format!("services.{name}.healthcheck"),
            message: "compose healthcheck not translated in V1 — re-author against \
                      WorkloadSpec.healthcheck (HttpGet / Exec / TcpConnect)"
                .into(),
        });
    }

    if !svc.networks.is_empty() {
        warnings.push(ImportWarning {
            path: format!("services.{name}.networks"),
            message: format!(
                "service-level network attachments ({}) flattened to the mesh — \
                 segmentation must be re-expressed via tier `allow_from`",
                svc.networks.join(", ")
            ),
        });
    }

    let (mesh_name, mesh_warning) = sanitize_mesh_ident(name);
    if let Some(message) = mesh_warning {
        warnings.push(ImportWarning {
            path: format!("services.{name}"),
            message,
        });
    }

    let image = svc
        .image
        .as_deref()
        .ok_or_else(|| ImportError::MissingImage { service: name.into() })?;
    let image = parse_image_ref(image).map_err(|reason| ImportError::UnpinnedImage {
        service: name.into(),
        image: image.into(),
        reason,
    })?;

    let env = translate_env(name, &svc.environment, warnings);

    let mesh_ports = translate_ports(name, &svc.ports, warnings);

    let depends_on = svc
        .depends_on
        .as_ref()
        .map(|d| d.iter_names().map(|n| MeshIdent(sanitize_mesh_ident(n).0)).collect())
        .unwrap_or_default();

    let (volumes, has_bind) = translate_volumes(name, &svc.volumes, warnings);

    let tier_str = if has_bind { "infra" } else { "private" };
    if has_bind {
        warnings.push(ImportWarning {
            path: format!("services.{name}.volumes"),
            message: "bind volume(s) detected; spec auto-promoted to tier=\"infra\" so it \
                      passes shape validation. Hand-review whether infra is the right tier"
                .into(),
        });
    }

    let restart_policy = translate_restart(name, svc.restart.as_deref(), warnings);

    let command = svc.command.as_ref().map(StringOrList::into_argv);
    let entrypoint = svc.entrypoint.as_ref().map(StringOrList::into_argv);
    let workdir = svc.working_dir.as_ref().map(PathBuf::from);

    let spec = WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: mesh_name.clone(),
        image,
        tier: TierTag(tier_str.into()),
        replicas: 1,
        command,
        entrypoint,
        workdir,
        user: svc.user.clone(),
        env,
        secrets: vec![],
        volumes,
        resources: ResourceLimits {
            memory_mb: 256,
            cpu_shares: 512,
            ephemeral_storage_mb: 512,
        },
        depends_on,
        healthcheck: None,
        restart_policy,
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(10),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent(mesh_name),
                ports: mesh_ports,
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: HashMap::new(),
        annotations: HashMap::new(),
    };

    Ok(spec)
}

/// Sanitize a compose service name into a DNS-friendly mesh ident.
///
/// Returns `(sanitized, warning)`. The warning is `Some` when the input had
/// to be modified — operators see it on stderr and in the JSON output.
fn sanitize_mesh_ident(name: &str) -> (String, Option<String>) {
    let lowered = name.to_ascii_lowercase();
    let sanitized: String = lowered
        .chars()
        .map(|c| if c == '_' { '-' } else { c })
        .collect();
    if sanitized != name {
        let msg = format!(
            "compose service name {name:?} rewritten to {sanitized:?} \
             (mesh idents must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$)"
        );
        (sanitized, Some(msg))
    } else {
        (sanitized, None)
    }
}

/// Parse a compose image reference into an [`ImageRef`]. The reference must
/// be digest-pinned — bare-tag references like `nginx:1.25` are rejected per
/// R438-T3. The accepted shape is `[registry/]repo[:tag]@sha256:<hex>`.
///
/// Examples (accepted):
/// - `nginx:1.25@sha256:<hex>` → `docker.io / library/nginx : 1.25 @ sha256:<hex>`
/// - `ghcr.io/foo/bar:v1@sha256:<hex>` → `ghcr.io / foo/bar : v1 @ sha256:<hex>`
/// - `repo@sha256:<hex>` → defaults `tag = "latest"`
///
/// Examples (rejected):
/// - `nginx`, `nginx:1.25`, `ghcr.io/foo/bar:v1` — no digest pin
pub(crate) fn parse_image_ref(s: &str) -> Result<ImageRef, String> {
    parse_pinned_image_ref(s)
}

/// Parse an image reference and **require** an `@sha256:<hex>` digest pin.
/// Bare-tag references (e.g. `node:20`) are rejected — the digest is the only
/// thing that survives an upstream tag retag and is what W164's reproducibility
/// rule and W165's CI-fidelity rule both depend on.
///
/// Used by the string-form deserializer for [`ImageRef`]; the struct-form
/// deserializer is unchanged (legacy `WorkloadSpec` configs keep working).
pub(crate) fn parse_pinned_image_ref(s: &str) -> Result<ImageRef, String> {
    let (head, dig_str) = s.split_once('@').ok_or_else(|| {
        format!(
            "image reference {s:?} must be digest-pinned (e.g. `repo:tag@sha256:<hex>`); \
             bare-tag images are rejected — pin with @sha256:<digest>"
        )
    })?;

    let hex = dig_str.strip_prefix("sha256:").ok_or_else(|| {
        format!("image digest must start with `sha256:`, got {dig_str:?}")
    })?;
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("sha256 digest must be non-empty hex, got {hex:?}"));
    }

    let (head2, tag_opt) = split_repo_and_tag(head);
    let tag = tag_opt.unwrap_or_else(|| "latest".into());
    let (registry, repository) = split_registry_and_repo(head2);

    Ok(ImageRef {
        registry,
        repository,
        tag,
        digest: format!("sha256:{hex}"),
    })
}

/// Split a `repo:tag` or `repo` reference. Careful with `localhost:5000/foo` —
/// the colon there is part of the registry, not a tag. We identify a tag as
/// the colon AFTER the last slash.
fn split_repo_and_tag(s: &str) -> (&str, Option<String>) {
    let last_slash = s.rfind('/');
    let search_from = last_slash.map(|i| i + 1).unwrap_or(0);
    if let Some(colon) = s[search_from..].find(':') {
        let abs = search_from + colon;
        let head = &s[..abs];
        let tag = &s[abs + 1..];
        (head, Some(tag.to_string()))
    } else {
        (s, None)
    }
}

/// Split a `registry/repo` head into `(registry, repo)`. A first segment is
/// treated as a registry hostname when it contains `.` or `:`, or equals
/// `localhost`. Otherwise we default to docker.io and prepend `library/` for
/// official images (compose `nginx` ⇒ docker.io/library/nginx, mirrors the
/// docker CLI default).
fn split_registry_and_repo(head: &str) -> (String, String) {
    if let Some((first, rest)) = head.split_once('/') {
        if first == "localhost" || first.contains('.') || first.contains(':') {
            return (first.to_string(), rest.to_string());
        }
    }
    let repo = if head.contains('/') {
        head.to_string()
    } else {
        format!("library/{head}")
    };
    ("docker.io".into(), repo)
}

fn translate_env(
    service: &str,
    environment: &Option<EnvList>,
    warnings: &mut Vec<ImportWarning>,
) -> Vec<EnvVar> {
    let Some(env) = environment else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match env {
        EnvList::List(items) => {
            for (i, item) in items.iter().enumerate() {
                if let Some((k, v)) = item.split_once('=') {
                    out.push(EnvVar {
                        name: k.into(),
                        value: EnvValue::Literal { value: v.into() },
                    });
                } else {
                    warnings.push(ImportWarning {
                        path: format!("services.{service}.environment[{i}]"),
                        message: format!(
                            "{item:?} omits a value (compose pulls it from the host shell). \
                             Provide a literal value or use EnvValue::FromSecret"
                        ),
                    });
                }
            }
        }
        EnvList::Map(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                let v = &map[k];
                let value = yaml_scalar_to_string(v);
                out.push(EnvVar {
                    name: k.clone(),
                    value: EnvValue::Literal { value },
                });
            }
        }
    }
    out
}

fn yaml_scalar_to_string(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Null => String::new(),
        other => serde_yaml::to_string(other).unwrap_or_default().trim().to_string(),
    }
}

fn translate_ports(
    service: &str,
    ports: &[PortSpec],
    warnings: &mut Vec<ImportWarning>,
) -> Vec<u16> {
    let mut out = Vec::new();
    for (i, p) in ports.iter().enumerate() {
        match p.parse_container_port() {
            Ok(port) => {
                if !out.contains(&port) {
                    out.push(port);
                }
            }
            Err(msg) => {
                warnings.push(ImportWarning {
                    path: format!("services.{service}.ports[{i}]"),
                    message: msg,
                });
            }
        }
    }
    out
}

fn translate_volumes(
    service: &str,
    items: &[String],
    warnings: &mut Vec<ImportWarning>,
) -> (Vec<VolumeMount>, bool) {
    let mut out = Vec::new();
    let mut has_bind = false;
    for (i, raw) in items.iter().enumerate() {
        let parts: Vec<&str> = raw.split(':').collect();
        let (source, target, read_only) = match parts.as_slice() {
            [target] => (None, *target, false),
            [src, tgt] => (Some(*src), *tgt, false),
            [src, tgt, mode] => (Some(*src), *tgt, mode.contains("ro")),
            _ => {
                warnings.push(ImportWarning {
                    path: format!("services.{service}.volumes[{i}]"),
                    message: format!("volume spec {raw:?} could not be parsed; skipped"),
                });
                continue;
            }
        };

        let target = PathBuf::from(target);
        let source = if let Some(src) = source {
            if src.starts_with('/') || src.starts_with('.') || src.starts_with('~') {
                has_bind = true;
                VolumeSource::Bind {
                    host_path: PathBuf::from(src),
                }
            } else {
                VolumeSource::Named { name: src.into() }
            }
        } else {
            VolumeSource::Named {
                name: format!("anon-{}-{}", service, i),
            }
        };

        out.push(VolumeMount {
            source,
            target,
            read_only,
        });
    }
    (out, has_bind)
}

fn translate_restart(
    service: &str,
    restart: Option<&str>,
    warnings: &mut Vec<ImportWarning>,
) -> RestartPolicy {
    match restart {
        None => RestartPolicy::Always,
        Some("always") => RestartPolicy::Always,
        Some("no") => RestartPolicy::Never,
        Some("unless-stopped") => {
            warnings.push(ImportWarning {
                path: format!("services.{service}.restart"),
                message: "restart=unless-stopped translated to RestartPolicy::Always — \
                          yubaba has no manual-stop concept the policy can opt out of"
                    .into(),
            });
            RestartPolicy::Always
        }
        Some(other) if other.starts_with("on-failure") => RestartPolicy::OnFailure {
            max_attempts: 5,
            backoff: crate::BackoffPolicy {
                initial_ms: 1000,
                max_ms: 30_000,
                multiplier: 2.0,
            },
        },
        Some(other) => {
            warnings.push(ImportWarning {
                path: format!("services.{service}.restart"),
                message: format!(
                    "unknown restart policy {other:?}; defaulted to RestartPolicy::Always"
                ),
            });
            RestartPolicy::Always
        }
    }
}

// ── Compose parse types ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ComposeFile {
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<String>,
    #[serde(default)]
    services: HashMap<String, ComposeService>,
    #[serde(default)]
    networks: HashMap<String, serde_yaml::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    volumes: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize, Default)]
struct ComposeService {
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    build: Option<serde_yaml::Value>,
    #[serde(default)]
    command: Option<StringOrList>,
    #[serde(default)]
    entrypoint: Option<StringOrList>,
    #[serde(default)]
    environment: Option<EnvList>,
    #[serde(default)]
    ports: Vec<PortSpec>,
    #[serde(default)]
    depends_on: Option<DependsOn>,
    #[serde(default)]
    volumes: Vec<String>,
    #[serde(default)]
    network_mode: Option<String>,
    #[serde(default)]
    networks: Vec<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    restart: Option<String>,
    #[serde(default)]
    healthcheck: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrList {
    String(String),
    List(Vec<String>),
}

impl StringOrList {
    fn into_argv(&self) -> Vec<String> {
        match self {
            StringOrList::String(s) => shell_split(s),
            StringOrList::List(v) => v.clone(),
        }
    }
}

/// Minimal whitespace tokeniser for compose's string-form `command:` / `entrypoint:`.
/// Compose uses `/bin/sh -c` style strings; we don't honor quoting, just split on
/// whitespace (the rare quoted-arg case stays a hand-edit).
fn shell_split(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_string).collect()
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EnvList {
    List(Vec<String>),
    Map(HashMap<String, serde_yaml::Value>),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DependsOn {
    List(Vec<String>),
    Map(HashMap<String, serde_yaml::Value>),
}

impl DependsOn {
    fn iter_names(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            DependsOn::List(v) => Box::new(v.iter().map(String::as_str)),
            DependsOn::Map(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                Box::new(keys.into_iter().map(String::as_str))
            }
        }
    }
}

/// Compose's `ports:` list is heterogeneous: short strings ("8080:80"), bare
/// numbers (8080), or long-form maps. We only need the container-side port.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PortSpec {
    Short(String),
    Number(u16),
    Long(LongPort),
}

#[derive(Debug, Deserialize)]
struct LongPort {
    target: u16,
    #[serde(default)]
    #[allow(dead_code)]
    published: Option<serde_yaml::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    protocol: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    mode: Option<String>,
}

impl PortSpec {
    fn parse_container_port(&self) -> Result<u16, String> {
        match self {
            PortSpec::Number(n) => Ok(*n),
            PortSpec::Long(l) => Ok(l.target),
            PortSpec::Short(s) => parse_short_port(s),
        }
    }
}

/// Compose short-form port shapes: `"80"`, `"8080:80"`, `"127.0.0.1:8080:80"`,
/// `"8080:80/udp"`. We extract the container-side port and ignore host-side
/// binding (yubaba's mesh handles that).
fn parse_short_port(s: &str) -> Result<u16, String> {
    let no_proto = s.split('/').next().unwrap_or(s);
    let segments: Vec<&str> = no_proto.split(':').collect();
    let container = segments
        .last()
        .ok_or_else(|| format!("port spec {s:?} is empty"))?;
    container
        .parse::<u16>()
        .map_err(|e| format!("port spec {s:?}: container-side port {container:?} not a u16 ({e})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PINNED_NGINX: &str =
        "nginx:1.25@sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    const PINNED_GHCR: &str =
        "ghcr.io/foo/bar:v1@sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    const PINNED_LOCALHOST: &str =
        "localhost:5000/svc:dev@sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

    #[test]
    fn parse_image_ref_rejects_bare_tag() {
        for bare in ["nginx", "nginx:1.25", "ghcr.io/foo/bar:v1"] {
            let res = parse_image_ref(bare);
            assert!(res.is_err(), "bare tag {bare:?} must reject");
        }
    }

    #[test]
    fn parse_image_ref_with_tag_and_digest() {
        let r = parse_image_ref(PINNED_NGINX).expect("pinned parses");
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/nginx");
        assert_eq!(r.tag, "1.25");
        assert!(r.digest.starts_with("sha256:"));
    }

    #[test]
    fn parse_image_ref_ghcr_pinned() {
        let r = parse_image_ref(PINNED_GHCR).expect("pinned parses");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "foo/bar");
        assert_eq!(r.tag, "v1");
    }

    #[test]
    fn parse_image_ref_localhost_port_pinned() {
        let r = parse_image_ref(PINNED_LOCALHOST).expect("pinned parses");
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "svc");
        assert_eq!(r.tag, "dev");
    }

    #[test]
    fn parse_short_port_ok() {
        assert_eq!(parse_short_port("80").unwrap(), 80);
        assert_eq!(parse_short_port("8080:80").unwrap(), 80);
        assert_eq!(parse_short_port("127.0.0.1:8080:80").unwrap(), 80);
        assert_eq!(parse_short_port("8080:80/udp").unwrap(), 80);
    }

    #[test]
    fn sanitize_mesh_ident_underscore_to_dash() {
        let (n, w) = sanitize_mesh_ident("web_app");
        assert_eq!(n, "web-app");
        assert!(w.is_some());
    }

    #[test]
    fn sanitize_mesh_ident_passthrough() {
        let (n, w) = sanitize_mesh_ident("web-app");
        assert_eq!(n, "web-app");
        assert!(w.is_none());
    }
}
