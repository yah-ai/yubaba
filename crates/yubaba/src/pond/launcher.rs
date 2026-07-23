//! Pond's kamaji-backed [`ContainerLauncher`] (R626-F2).
//!
//! Pond's bring-up sequences (`local_driver::pond_{minio,miniflare,ssr_runtime}`)
//! are choreography: make the state dir, pull, run, wait for the port, wait for
//! HTTP ready, apply post-start config. Only three verbs in that sequence touch
//! a container daemon, and [`ContainerLauncher`] is the seam they go through.
//!
//! Before R626-F2 pond drove `LocalRuntime` (docker CLI, in-process) and each
//! slot ran its own resurrect loop — which is precisely why a manual
//! `docker stop` of a pond container lost a race against yubaba. This module
//! routes the same three verbs through **kamaji** instead, so:
//!
//! - the container is created with `--restart unless-stopped`, i.e. **dockerd**
//!   restarts it after a crash, and an explicit stop stays stopped;
//! - the reconcilers become pure probes (observability), with no supervision
//!   authority of their own;
//! - pond containers show up in `kamaji list` next to every other supervised
//!   workload, rather than being a private tier only yubaba knows about.
//!
//! The [`Kamaji`] handle here is normally the sibling UDS client talking to the
//! `kamaji` process inside the pond container (`KAMAJI_SOCK`), which drives the
//! host docker socket. Nothing in this module is docker-specific — it speaks
//! `WorkloadSpec` — but the pond slots are docker containers today, so the
//! lowering below sets the docker rendering annotations kamaji's docker backend
//! reads.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use local_driver::{ContainerLauncher, ContainerRunSpec};
use workload_spec::{
    EnvValue, EnvVar, ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, NamespaceId,
    ResourceLimits, RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, VolumeMount,
    VolumeSource, WorkloadSpec,
};

use kamaji::Kamaji as ContainerRuntime;

/// Docker rendering annotations. Spelled here rather than imported from
/// `kamaji::docker` because that module is behind the `docker-integration`
/// feature, and pond deploys through the *generic* kamaji surface — the docker
/// backend lives in the kamaji process, not in this one. The keys are part of
/// the wire contract; [`annotation_keys_match_kamaji`] pins them.
///
/// [`annotation_keys_match_kamaji`]: tests::annotation_keys_match_kamaji
const PUBLISH_ANNOTATION: &str = "yah.docker.publish";
const NETWORK_ANNOTATION: &str = "yah.docker.network";
const NETWORK_ALIAS_ANNOTATION: &str = "yah.docker.network_alias";

/// Label key carrying the pond slot label (`svc:env:slot`), matching the
/// `yah.pond` label `LocalRuntime::run` writes so `docker ps --filter
/// label=yah.pond` keeps finding pond containers after the migration.
const POND_LABEL_KEY: &str = local_driver::LABEL_KEY;

/// Deploys pond slots through kamaji instead of the docker CLI.
///
/// Cheap to clone — one `Arc`.
#[derive(Clone)]
pub struct KamajiLauncher {
    backend: Arc<dyn ContainerRuntime + Send + Sync>,
}

impl KamajiLauncher {
    pub fn new(backend: Arc<dyn ContainerRuntime + Send + Sync>) -> Self {
        Self { backend }
    }
}

#[async_trait::async_trait]
impl ContainerLauncher for KamajiLauncher {
    /// No-op: kamaji's deploy pulls the image itself, and doing it twice would
    /// just cost a round-trip. Returns `false` ("no pull happened here"), which
    /// is only ever used for logging.
    async fn ensure_image(&self, _image: &str) -> Result<bool> {
        Ok(false)
    }

    async fn run(&self, spec: &ContainerRunSpec) -> Result<()> {
        let ws = lower_run_spec(spec)?;
        // Pond has no mesh IP plane — the slots talk over the per-cell docker
        // bridge and host-published ports. The inlined sentinel is what every
        // other pond-tier deploy passes (same gap R599-F10 records for
        // bundles); docker uses it only for the `yah.mesh_ip` label and the
        // YAH_MESH_IP env var.
        let mesh = crate::mesh::MeshAssignment::inlined("127.0.0.1".parse().unwrap());
        self.backend
            .deploy_workload(&ws, &mesh)
            .await
            .with_context(|| format!("kamaji deploy of pond container {}", spec.name))?;
        Ok(())
    }

    /// Stop + remove through kamaji. `grace` is ignored: kamaji's teardown
    /// applies the backend's own stop grace (5 s on docker, matching
    /// containerd), and pond only ever passed 2–3 s.
    async fn stop_and_remove(&self, name: &str, _grace: Duration) -> Result<()> {
        self.backend
            .teardown_workload(&MeshIdent(name.to_string()))
            .await
            .with_context(|| format!("kamaji teardown of pond container {name}"))
    }
}

/// Lower a pond [`ContainerRunSpec`] into the [`WorkloadSpec`] kamaji deploys.
///
/// Pure — unit-testable without a daemon. The mesh identity **is** the
/// container name: kamaji's docker backend names containers by identity, so
/// this is what makes a later `stop_and_remove(name)` resolve.
pub fn lower_run_spec(spec: &ContainerRunSpec) -> Result<WorkloadSpec> {
    let mut annotations = std::collections::HashMap::new();
    if !spec.ports.is_empty() {
        annotations.insert(
            PUBLISH_ANNOTATION.to_string(),
            spec.ports
                .iter()
                .map(|(host, container)| format!("{host}:{container}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if let Some(net) = &spec.network {
        annotations.insert(NETWORK_ANNOTATION.to_string(), net.clone());
        if !spec.network_aliases.is_empty() {
            annotations.insert(
                NETWORK_ALIAS_ANNOTATION.to_string(),
                spec.network_aliases.join(","),
            );
        }
    }

    let mut labels = std::collections::HashMap::new();
    labels.insert(POND_LABEL_KEY.to_string(), spec.label.clone());

    Ok(WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: spec.name.clone(),
        image: parse_image(&spec.image)?,
        tier: TierTag("infra".into()),
        tenant: TenantId::singleton(),
        namespace: NamespaceId::singleton(),
        replicas: 1,
        command: if spec.cmd.is_empty() {
            None
        } else {
            Some(spec.cmd.clone())
        },
        entrypoint: None,
        workdir: None,
        user: None,
        env: spec
            .env
            .iter()
            .map(|(name, value)| EnvVar {
                name: name.clone(),
                value: EnvValue::Literal {
                    value: value.clone(),
                },
            })
            .collect(),
        secrets: vec![],
        volumes: spec
            .volumes
            .iter()
            .map(|(host, container)| VolumeMount {
                source: VolumeSource::Bind {
                    host_path: host.clone(),
                },
                target: container.into(),
                read_only: false,
            })
            .collect(),
        // Pond slots run uncapped, as they did under `LocalRuntime::run` —
        // zero means "don't render a cgroup limit" (see kamaji's docker
        // backend). A memory cap invented here would be a silent behaviour
        // change on a developer's laptop.
        resources: ResourceLimits {
            memory_mb: 0,
            cpu_millis: 0,
            ephemeral_storage_mb: 0,
        },
        depends_on: vec![],
        healthcheck: None,
        // The point of the migration: dockerd restarts a crashed pond slot,
        // and an explicit stop is honoured. `Always` renders as
        // `--restart unless-stopped`.
        restart_policy: RestartPolicy::Always,
        archetype: None,
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(5),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                // Identity == container name: kamaji's docker backend derives
                // `--name` from this, and teardown resolves by it.
                identity: MeshIdent(spec.name.clone()),
                ports: spec.ports.iter().map(|(_, container)| *container).collect(),
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels,
        annotations,
    })
}

/// Parse a docker image string (`[registry/]repo[:tag][@digest]`) into an
/// [`ImageRef`] whose [`ImageRef::pull_ref`] round-trips back to an equivalent
/// reference.
///
/// Pond's specs carry plain docker strings (`"minio/minio:RELEASE.2025-…"`,
/// `"ghcr.io/yah-ai/yah-miniflare:latest"`), not the digest-pinned struct form
/// yubaba's cloud tier requires. An unpinned reference keeps the all-zeros
/// sentinel digest, which makes `pull_ref` emit the tag-only form docker
/// resolves against (R590-B5).
fn parse_image(image: &str) -> Result<ImageRef> {
    let (rest, digest) = match image.split_once('@') {
        Some((rest, digest)) => (rest, digest.to_string()),
        None => (image, ImageRef::UNPINNED_DIGEST.to_string()),
    };
    let (repo_path, tag) = match rest.rsplit_once(':') {
        // A colon in the *first* path segment is a registry port
        // (`localhost:5000/foo`), not a tag separator.
        Some((head, tail)) if !tail.contains('/') => (head, tail.to_string()),
        _ => (rest, "latest".to_string()),
    };

    let (registry, repository) = match repo_path.split_once('/') {
        // Docker's own rule: the first segment is a registry only when it
        // looks like a host — it has a dot or a port, or is literally
        // `localhost`. `minio/minio` is Docker Hub's `minio` org, not a host.
        Some((head, tail)) if head.contains('.') || head.contains(':') || head == "localhost" => {
            (head.to_string(), tail.to_string())
        }
        _ => ("docker.io".to_string(), repo_path.to_string()),
    };

    if repository.is_empty() {
        anyhow::bail!("pond image {image:?} has no repository component");
    }

    Ok(ImageRef {
        registry,
        repository,
        tag,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn minio_run_spec() -> ContainerRunSpec {
        let mut env = BTreeMap::new();
        env.insert("MINIO_ROOT_USER".to_string(), "yahsim".to_string());
        ContainerRunSpec {
            name: "yah-pond-svc-pond-object_store".into(),
            image: "minio/minio:RELEASE.2025-04-22T22-12-26Z".into(),
            label: "svc:pond:object_store".into(),
            ports: vec![(9000, 9000), (9001, 9001)],
            env,
            volumes: vec![(PathBuf::from("/tmp/yah-pond/minio"), "/data".into())],
            cmd: vec!["server".into(), "/data".into()],
            cap_add: vec![],
            cgroupns: None,
            network: Some("yah-pond-svc-pond".into()),
            network_aliases: vec!["minio".into()],
            extra_hosts: vec![],
        }
    }

    /// The container name is the addressing key on both legs — deploy names the
    /// container from the identity, teardown resolves by it. If these ever
    /// diverge, a stop silently succeeds while the container keeps running.
    #[test]
    fn identity_is_the_container_name() {
        let ws = lower_run_spec(&minio_run_spec()).unwrap();
        assert_eq!(ws.expose.mesh.identity.0, "yah-pond-svc-pond-object_store");
        assert_eq!(ws.name, "yah-pond-svc-pond-object_store");
    }

    /// Restart is the whole point: pond's resurrect loops go away, so the
    /// deployed spec has to carry a restarting policy or nothing brings a
    /// crashed slot back.
    #[test]
    fn pond_slots_are_deployed_restarting() {
        let ws = lower_run_spec(&minio_run_spec()).unwrap();
        assert_eq!(ws.restart_policy, RestartPolicy::Always);
    }

    #[test]
    fn ports_network_and_aliases_become_docker_annotations() {
        let ws = lower_run_spec(&minio_run_spec()).unwrap();
        assert_eq!(
            ws.annotations.get(PUBLISH_ANNOTATION).map(String::as_str),
            Some("9000:9000,9001:9001")
        );
        assert_eq!(
            ws.annotations.get(NETWORK_ANNOTATION).map(String::as_str),
            Some("yah-pond-svc-pond")
        );
        assert_eq!(
            ws.annotations
                .get(NETWORK_ALIAS_ANNOTATION)
                .map(String::as_str),
            Some("minio")
        );
    }

    /// Aliases without a network would be rendered as `--network-alias` with no
    /// `--network`, which docker rejects. The lowering drops them the same way
    /// `LocalRuntime::run` does.
    #[test]
    fn aliases_without_a_network_are_dropped() {
        let mut rs = minio_run_spec();
        rs.network = None;
        let ws = lower_run_spec(&rs).unwrap();
        assert!(!ws.annotations.contains_key(NETWORK_ANNOTATION));
        assert!(!ws.annotations.contains_key(NETWORK_ALIAS_ANNOTATION));
    }

    #[test]
    fn volumes_lower_to_bind_mounts() {
        let ws = lower_run_spec(&minio_run_spec()).unwrap();
        assert_eq!(ws.volumes.len(), 1);
        assert_eq!(
            ws.volumes[0].source,
            VolumeSource::Bind {
                host_path: PathBuf::from("/tmp/yah-pond/minio")
            }
        );
        assert_eq!(ws.volumes[0].target, PathBuf::from("/data"));
    }

    /// Pond has never capped its slots; a cap invented by the lowering would
    /// OOM-kill MinIO on a developer's laptop.
    #[test]
    fn pond_slots_stay_uncapped() {
        let ws = lower_run_spec(&minio_run_spec()).unwrap();
        assert_eq!(ws.resources.memory_mb, 0);
        assert_eq!(ws.resources.cpu_millis, 0);
    }

    #[test]
    fn pond_label_rides_along() {
        let ws = lower_run_spec(&minio_run_spec()).unwrap();
        assert_eq!(
            ws.labels.get(POND_LABEL_KEY).map(String::as_str),
            Some("svc:pond:object_store")
        );
    }

    #[test]
    fn empty_cmd_leaves_the_image_default() {
        let mut rs = minio_run_spec();
        rs.cmd = vec![];
        assert!(lower_run_spec(&rs).unwrap().command.is_none());
    }

    // ── image parsing ─────────────────────────────────────────────────────────

    #[test]
    fn docker_hub_org_is_not_mistaken_for_a_registry() {
        let img = parse_image("minio/minio:RELEASE.2025-04-22T22-12-26Z").unwrap();
        assert_eq!(img.registry, "docker.io");
        assert_eq!(img.repository, "minio/minio");
        assert_eq!(img.tag, "RELEASE.2025-04-22T22-12-26Z");
        assert_eq!(
            img.pull_ref(),
            "docker.io/minio/minio:RELEASE.2025-04-22T22-12-26Z"
        );
    }

    #[test]
    fn hostname_first_segment_is_a_registry() {
        let img = parse_image("ghcr.io/yah-ai/yah-miniflare:latest").unwrap();
        assert_eq!(img.registry, "ghcr.io");
        assert_eq!(img.repository, "yah-ai/yah-miniflare");
        assert_eq!(img.pull_ref(), "ghcr.io/yah-ai/yah-miniflare:latest");
    }

    #[test]
    fn registry_with_a_port_is_a_registry() {
        let img = parse_image("localhost:5000/app:v1").unwrap();
        assert_eq!(img.registry, "localhost:5000");
        assert_eq!(img.repository, "app");
        assert_eq!(img.tag, "v1");
    }

    #[test]
    fn missing_tag_defaults_to_latest() {
        assert_eq!(parse_image("alpine").unwrap().tag, "latest");
    }

    /// An unpinned reference must pull by tag: no store holds an image under
    /// the all-zeros sentinel digest (R590-B5).
    #[test]
    fn unpinned_image_pulls_by_tag() {
        let img = parse_image("alpine:3.20").unwrap();
        assert!(!img.is_pinned());
        assert_eq!(img.pull_ref(), "docker.io/alpine:3.20");
    }

    #[test]
    fn digest_is_preserved_when_present() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let img = parse_image(&format!("ghcr.io/yah-ai/x:v1@{digest}")).unwrap();
        assert_eq!(img.digest, digest);
        assert!(img.is_pinned());
        assert_eq!(img.pull_ref(), format!("ghcr.io/yah-ai/x:v1@{digest}"));
    }

    /// The docker rendering annotations are a wire contract with kamaji's
    /// docker backend, which spells them in its own module. This pins the
    /// strings so a rename there can't silently stop publishing pond's ports.
    #[cfg(feature = "docker-integration")]
    #[test]
    fn annotation_keys_match_kamaji() {
        assert_eq!(PUBLISH_ANNOTATION, kamaji::docker::PUBLISH_ANNOTATION);
        assert_eq!(NETWORK_ANNOTATION, kamaji::docker::NETWORK_ANNOTATION);
        assert_eq!(
            NETWORK_ALIAS_ANNOTATION,
            kamaji::docker::NETWORK_ALIAS_ANNOTATION
        );
    }
}
