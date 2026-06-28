//! Cloud-tier mesofact runner bring-up primitives (R330-F11, W059).
//!
//! Sibling to [`crate::pond_mesofact_dev`] but for the cloud tier: a single
//! long-lived bun process supervised by yubaba on the machine F16 places
//! the `yah-cloud` service onto (today: `us-west-001`, selected by mesh-tag
//! `tag:cloud-runner` — see `crates/yah/cloud/src/config.rs::CloudConfig::resolve_machine_by_mesh_tags`).
//!
//! The cloud runner serves multi-tenant traffic — one bun process exposes
//! the same `/revalidate /healthz /readyz` surface for every tenant
//! registered under `.yah/services/yah-cloud/tenants/<id>.toml` (tenant
//! config shape lands with R330-F12; F11 only sets up the supervised
//! process).
//!
//! Differences from the pond-tier sibling:
//!
//!   * Not a docker container — bun runs on the host under a yubaba slice
//!     so the Cloudflare tunnel (`yah-cloud-runner`) can route directly to
//!     `127.0.0.1:<port>` without bridge gymnastics.
//!   * Multi-tenant by construction — `tenant_config_dir` holds one TOML
//!     per tenant; F12 settles the file shape.
//!   * No `network` / `network_alias` fields — there is no per-cell docker
//!     bridge at this tier.
//!
//! Used by `cloud::reconciler::mesofact_runner` once R330-F11's dispatcher
//! wiring lands (a separate slice — F11 ships the spec + skeleton only).

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use workload_spec::{
    EnvValue, EnvVar, ExposeSpec, HealthProbe, Healthcheck, ImageRef, MeshExpose, MeshIdent,
    Millis, ResourceLimits, RestartPolicy, SchemaVersion, StopPolicy, TierTag, Workload,
    WorkloadSpec, HOST_NETWORK_ANNOTATION, HOST_NETWORK_VALUE,
};

/// DNS name + mesh identity of the cloud-tier runner workload.
pub const RUNNER_WORKLOAD_NAME: &str = "yah-cloud-runner";

/// Container path the runner reads tenant feed TOMLs from. The image bakes
/// this dir; once the containerd backend grows volume support the host
/// `tenant_config_dir` bind-mounts here.
const CONTAINER_TENANT_DIR: &str = "/etc/almanac";

/// Container path the runner writes per-tenant artifacts to (image-baked;
/// host `data_dir` bind-mounts here once volumes land).
const CONTAINER_DATA_DIR: &str = "/data";

/// Caller-supplied cloud mesofact-runner bring-up parameters. The
/// `MesofactRunnerReconciler` builds this from the resolved mirror config +
/// the placed machine, then POSTs it to yubaba as the workload payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MesofactRunnerSpec {
    /// Host port the bun process binds to (the Cloudflare tunnel's ingress
    /// rule routes `runner.yah.dev` → `http://localhost:<port>`).
    pub bind_port: u16,
    /// Directory holding `tenants/<id>.toml` files. Mounted read-only into
    /// the bun process; reloads happen via SIGHUP or a `/revalidate?tenant=<id>`
    /// poke from operator tools.
    pub tenant_config_dir: PathBuf,
    /// Directory the bun process writes per-tenant SQLite + almanac
    /// artifacts into.
    pub data_dir: PathBuf,
    /// `ALMANAC_ENV` env var (default `"cloud"` for this tier).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_label: Option<String>,
    /// `ALMANAC_MIRROR_KEY` — optional static bearer for tenant
    /// `/revalidate` calls. F12 may move this per-tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_key: Option<String>,
    /// Timeout for the initial TCP + HTTP liveness probes during bring-up.
    #[serde(with = "duration_secs_serde")]
    pub ready_timeout: Duration,
    /// HTTP path probed for liveness. Default: `"/healthz"`.
    #[serde(default = "default_liveness_path")]
    pub liveness_path: String,
    /// HTTP path probed for readiness. Default: `"/readyz"`.
    #[serde(default = "default_readiness_path")]
    pub readiness_path: String,
}

impl MesofactRunnerSpec {
    /// Lower this runner spec into a containerd [`Workload`] yubaba can deploy
    /// over RPC.
    ///
    /// The runner is an **infra-tier, host-networked** container: it binds
    /// `bind_port` directly on the host so the on-host Cloudflare tunnel can
    /// route `runner.yah.dev → 127.0.0.1:<bind_port>` without CNI/bridge
    /// plumbing. Host networking is the guarded escape hatch — `tier="infra"`
    /// is required for kamaji to honour the `yah.network=host` annotation
    /// (see `workload_spec::WorkloadSpec::wants_host_network`). `tini` is PID 1
    /// (signal forwarding + zombie reaping); `almanac-serve` is the sole
    /// process.
    ///
    /// `image` is the content-addressed runner image (built from
    /// `oss/qed/crates/qed/images/yah-cloud-runner`). Tenant feed configs +
    /// data dir are surfaced via env knobs pointing at the image's baked
    /// `/etc/almanac` + `/data`. F11 does NOT bind-mount the host
    /// `tenant_config_dir` / `data_dir` yet — the containerd backend's volume
    /// support is a separate gap; almanac-serve degrades gracefully with an
    /// empty feed dir, still serving `/healthz` + `/readyz` (the F11 verify).
    pub fn into_container_workload(&self, image: ImageRef) -> Workload {
        let port = self.bind_port;

        let mut env = vec![
            literal_env("ALMANAC_PORT", port.to_string()),
            literal_env(
                "ALMANAC_ENV",
                self.env_label.clone().unwrap_or_else(|| "cloud".into()),
            ),
            literal_env("ALMANAC_DIR", CONTAINER_TENANT_DIR.to_string()),
            literal_env("ALMANAC_PROJECT_ROOT", CONTAINER_DATA_DIR.to_string()),
        ];
        if let Some(key) = &self.mirror_key {
            env.push(literal_env("ALMANAC_MIRROR_KEY", key.clone()));
        }

        let mut annotations = HashMap::new();
        annotations.insert(
            HOST_NETWORK_ANNOTATION.to_string(),
            HOST_NETWORK_VALUE.to_string(),
        );

        // grace_period * 2 is the soft floor shape-validation recommends for
        // initial_delay; keep them in step to avoid the warning.
        let grace = Millis::from_secs(5);

        let spec = WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: RUNNER_WORKLOAD_NAME.into(),
            image,
            tier: TierTag("infra".into()),
            replicas: 1,
            // build_oci_spec ignores the image ENTRYPOINT/CMD and runs
            // `command` directly, so spell out tini → almanac-serve here.
            command: Some(vec![
                "/usr/bin/tini".into(),
                "--".into(),
                "/usr/local/bin/almanac-serve".into(),
            ]),
            entrypoint: None,
            workdir: None,
            user: None,
            env,
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 256,
                cpu_shares: 512,
                ephemeral_storage_mb: 512,
            },
            depends_on: vec![],
            healthcheck: Some(Healthcheck {
                probe: HealthProbe::HttpGet {
                    path: self.liveness_path.clone(),
                    port,
                    expect_status: None,
                },
                interval: Millis::from_secs(10),
                timeout: Millis::from_secs(2),
                initial_delay: Millis::from_secs(10),
                failure_threshold: 3,
            }),
            restart_policy: RestartPolicy::Always,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: grace,
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(RUNNER_WORKLOAD_NAME.into()),
                    ports: vec![port],
                    allow_from: vec![],
                },
                // Public ingress is the on-host Cloudflare tunnel, not yubaba's
                // CF-route automation — left None so the deploy stays decoupled
                // from that surface (the tunnel ingress is configured directly).
                public: None,
                operator: None,
            },
            labels: HashMap::new(),
            annotations,
        };

        Workload::Container(spec)
    }
}

fn literal_env(name: &str, value: String) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: EnvValue::Literal { value },
    }
}

fn default_liveness_path() -> String {
    "/healthz".into()
}
fn default_readiness_path() -> String {
    "/readyz".into()
}

mod duration_secs_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        d.as_secs().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}

/// Coordinates of a running cloud-runner returned by the yubaba-side
/// bring-up. Mirrors [`crate::pond_mesofact_dev::MesofactDevRunning`] in
/// purpose; only the host endpoint exists at this tier (no bridge).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MesofactRunnerRunning {
    /// Host-side endpoint — `http://127.0.0.1:<bind_port>`.
    pub endpoint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_round_trips_through_serde() {
        let spec = MesofactRunnerSpec {
            bind_port: 4323,
            tenant_config_dir: PathBuf::from("/var/lib/yah-cloud/tenants"),
            data_dir: PathBuf::from("/var/lib/yah-cloud/data"),
            env_label: Some("cloud".into()),
            mirror_key: None,
            ready_timeout: Duration::from_secs(30),
            liveness_path: "/healthz".into(),
            readiness_path: "/readyz".into(),
        };
        let s = serde_json::to_string(&spec).unwrap();
        let round: MesofactRunnerSpec = serde_json::from_str(&s).unwrap();
        assert_eq!(round.bind_port, 4323);
        assert_eq!(round.env_label.as_deref(), Some("cloud"));
        assert_eq!(round.liveness_path, "/healthz");
    }

    fn sample_spec() -> MesofactRunnerSpec {
        MesofactRunnerSpec {
            bind_port: 4323,
            tenant_config_dir: PathBuf::from("/var/lib/yah-cloud/tenants"),
            data_dir: PathBuf::from("/var/lib/yah-cloud/data"),
            env_label: Some("cloud".into()),
            mirror_key: None,
            ready_timeout: Duration::from_secs(30),
            liveness_path: "/healthz".into(),
            readiness_path: "/readyz".into(),
        }
    }

    fn sample_image() -> ImageRef {
        ImageRef {
            registry: "localhost".into(),
            repository: "yah-cloud-runner".into(),
            tag: "r330f11".into(),
            digest: workload_spec::testing::test_digest(),
        }
    }

    #[test]
    fn lowers_to_infra_host_networked_container() {
        let Workload::Container(spec) = sample_spec().into_container_workload(sample_image()) else {
            panic!("expected a Container workload");
        };

        // Host networking is the whole point — and it must be infra-tier so
        // kamaji honours it (validate_spec_for_constable guard).
        assert!(spec.wants_host_network());
        assert_eq!(spec.tier.0, "infra");

        // Port flows into env + mesh ports + the health probe consistently.
        assert!(spec
            .env
            .iter()
            .any(|e| e.name == "ALMANAC_PORT"
                && matches!(&e.value, EnvValue::Literal { value } if value == "4323")));
        assert_eq!(spec.expose.mesh.ports, vec![4323]);
        match &spec.healthcheck.as_ref().unwrap().probe {
            HealthProbe::HttpGet { path, port, .. } => {
                assert_eq!(path, "/healthz");
                assert_eq!(*port, 4323);
            }
            other => panic!("expected HttpGet probe, got {other:?}"),
        }

        // tini is PID 1, almanac-serve the workload.
        assert_eq!(
            spec.command.as_deref().unwrap(),
            ["/usr/bin/tini", "--", "/usr/local/bin/almanac-serve"]
        );

        // The lowered spec must clear shape validation (no errors).
        workload_spec::validate::shape(&spec).expect("lowered spec passes shape validation");
    }

    #[test]
    fn mirror_key_is_threaded_when_present() {
        let mut s = sample_spec();
        s.mirror_key = Some("keystore:cloud".into());
        let Workload::Container(spec) = s.into_container_workload(sample_image()) else {
            panic!("expected Container");
        };
        assert!(spec.env.iter().any(|e| e.name == "ALMANAC_MIRROR_KEY"));
    }

    #[test]
    fn defaults_for_optional_paths() {
        let json_src = r#"{
  "bind_port": 4323,
  "tenant_config_dir": "/etc/yah-cloud/tenants",
  "data_dir": "/var/lib/yah-cloud",
  "ready_timeout": 30
}"#;
        let spec: MesofactRunnerSpec = serde_json::from_str(json_src).unwrap();
        assert_eq!(spec.liveness_path, "/healthz");
        assert_eq!(spec.readiness_path, "/readyz");
        assert!(spec.env_label.is_none());
    }
}
