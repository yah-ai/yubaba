//! Local-container runtime: detect an orbstack/docker-desktop/colima/podman/docker
//! socket per `.yah/infra/providers/orbstack.toml`, then drive appliance containers
//! (miniflare, MinIO) for the pond mirror shape.
//!
//! Shells out to the `docker` CLI rather than linking a Docker REST client.
//! OrbStack, Docker Desktop, Colima, and Podman all expose a Docker-compatible
//! socket; the call sites here are few enough that per-invocation process
//! overhead is invisible inside the container spin-up budget (few seconds).
//!
//! ## Provider cascade
//!
//! [`RuntimeProvider`] is the probe contract each back-end implements.
//! [`LocalContainerSpec::build_cascade`] returns the ordered provider list;
//! [`LocalRuntime::detect`] walks it and picks the first available one.
//! Default Auto order: OrbStack → Docker Desktop → Colima → Podman → Docker →
//! custom `DOCKER_HOST`.
//!
//! ## Module shape
//!
//! - [`LocalContainerSpec`] carries a runtime preference + socket discovery
//!   map. The cloud crate provides the `kind = "local-container"`
//!   ProviderConfig adapter via `cloud::local_container_spec_from_provider`.
//! - [`LocalRuntime::detect`] probes sockets in preference order, expands `~`
//!   in paths, and returns a handle that downstream callers feed every docker
//!   invocation through.
//! - [`LocalRuntime`] exposes the lifecycle primitives R256-T3 will compose
//!   into a reconciler: `ensure_image`, `run`, `stop_and_remove`,
//!   `container_state`, `list_owned`.
//!
//! ## Container naming + orphan cleanup
//!
//! Every container this module starts gets:
//! - A canonical name: `yah-pond-<service>-<env>-<slot>` via [`canonical_name`].
//!   The `yah-pond-` prefix is grep-friendly in `docker ps` output.
//! - A docker label `yah.pond = <service>:<env>:<slot>` for filtered
//!   queries via `docker ps --filter label=yah.pond`.
//!
//! After a crash that misses graceful shutdown, [`LocalRuntime::list_owned`]
//! enumerates leftovers and the caller can reap them before starting a fresh
//! up cycle.
//!
//! @yah:relay(R275, "Tier 2 — Container substrate: provider trait + non-orbstack fallbacks")
//! @yah:at(2026-05-21T21:56:51Z)
//! @yah:status(review)
//! @yah:parent(Q273)
//! @yah:next("F1: promote local_runtime probe into RuntimeProvider trait with explicit OrbStack / Docker Desktop / Colima / Podman / custom DOCKER_HOST providers (per visiting doc)")
//! @yah:next("F2: settings-panel UX surfacing Detected/Current/Mode in rig-prefs")
//! @yah:next("F3: spike built-in macOS VM via Virtualization.framework — go/no-go + scoping estimate; defer build until a real 'Nothing found' case")
//! @yah:next("F4: route reconciler/local_sim.rs Caddy+MinIO path through the new trait (currently calls orbstack-via-docker-CLI directly)")
//! @yah:gotcha("Today only orbstack-via-docker-CLI is exercised in practice; the cascade exists implicitly. Don't assume other backends work until F1 lands.")
//! @arch:see(visiting/container-runtime-strategy.md)
//! @arch:see(.yah/docs/working/W080-dev-yah-static-demo.md)
//! @arch:see(.yah/docs/architecture/A031-yah-cloud-config-shape.md)
//! @yah:handoff("F1 + F4 landed: RuntimeProvider trait (name/available/docker_host), SocketRuntimeProvider, CustomDockerHostProvider — all in local_runtime.rs. RuntimePref/DetectedRuntime expanded with DockerDesktop, Podman, Custom variants. LocalContainerSpec gains custom_docker_host: Option<String> and build_cascade() (returns ordered Vec<(DetectedRuntime, Box<dyn RuntimeProvider>)> for settings-panel use). LocalRuntime.socket: PathBuf replaced by docker_host: String; cmd() uses it directly. local_sim.rs F4 log line updated. lib.rs re-exports updated. 164 tests pass.")
//! @yah:next("F2: settings-panel UX — build_cascade() returns the provider list; surface Detected/Current/Mode in rig-prefs UI (packages/yah/ui)")
//! @yah:next("F3: spike built-in macOS VM via Virtualization.framework — go/no-go + scoping estimate; defer build until a real 'Nothing found' case arises in dogfood")
//! @yah:handoff("F1 + F4 already landed (prior session). F2 now landed: local_runtime_probe Tauri command in app/yah/desktop/src/local_runtime_cmd.rs probes all kind=local-container providers (build_cascade + detect); wire types WireLocalRuntimeCandidate/WireLocalRuntimeStatus in env/types.ts; LocalRuntimeRpc interface added to Rpc in env/index.ts; tauri.ts + browser.ts stub wired; LocalRuntimePanel component at packages/yah/ui/src/components/shell/LocalRuntimePanel.tsx; Settings → Container Runtime section added to SettingsView (SettingsSection type, SECTIONS array, panel render). RuntimePref::as_str() added to local_runtime.rs. 164 cloud lib tests + bun typecheck both pass clean.")
//! @yah:next("F3 (built-in macOS VM via Virtualization.framework): deferred — arch doc (visiting/container-runtime-strategy.md) covers the go/no-go and scoping; defer build until a real Nothing-found case surfaces in dogfood. File as a child spike if/when dogfood hits that case.")
//! @yah:handoff("All deliverable features shipped: F1 (RuntimeProvider trait + SocketRuntimeProvider/CustomDockerHostProvider + full cascade), F2 (LocalRuntimePanel settings UI + Tauri command + wire types), F4 (local_sim.rs routed through trait). F3 (macOS Virtualization.framework spike) remains deferred until dogfood surfaces a Nothing-found case. This session fixed the only remaining breakage: mesofact_static_e2e.rs was missing the adopt_only field added to LocalStaticOptions — fixed with ..LocalStaticOptions::default(). cargo test -p cloud: all pass. bun typecheck: R275 files clean (pre-existing PartyView/test errors from other in-flight work).")

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::process::Command;
use tracing::{debug, warn};
use workload_spec::{EnvValue, VolumeSource, WorkloadRuntime, WorkloadSpec};

// ── RuntimeProvider trait + implementations ───────────────────────────────────

/// Probe contract for a single Docker-compatible runtime back-end.
/// Each implementation knows its socket path (or raw `DOCKER_HOST`) and can
/// report whether it is currently reachable.
pub trait RuntimeProvider: Send + Sync {
    /// Short, stable identifier used in config keys and log output
    /// (e.g. `"orbstack"`, `"docker-desktop"`, `"colima"`, `"podman"`,
    /// `"docker"`, `"custom"`).
    fn name(&self) -> &str;
    /// True when the runtime can be used right now (socket exists, etc.).
    fn available(&self) -> bool;
    /// The value for the `DOCKER_HOST` env var
    /// (e.g. `"unix:///…"` or `"tcp://localhost:2375"`).
    fn docker_host(&self) -> String;
}

/// [`RuntimeProvider`] backed by a Unix socket path.
/// Available iff the tilde-expanded path exists on disk.
pub struct SocketRuntimeProvider {
    pub label: String,
    pub socket: PathBuf,
}

impl RuntimeProvider for SocketRuntimeProvider {
    fn name(&self) -> &str {
        &self.label
    }
    fn available(&self) -> bool {
        expand_tilde(&self.socket).exists()
    }
    fn docker_host(&self) -> String {
        format!("unix://{}", expand_tilde(&self.socket).display())
    }
}

/// [`RuntimeProvider`] for a raw `DOCKER_HOST` string supplied by the operator
/// (e.g. `"tcp://localhost:2375"` or `"unix:///path/to/custom.sock"`).
/// Always reported as available — the operator opted in explicitly; failures
/// surface as docker CLI errors rather than probe misses.
pub struct CustomDockerHostProvider {
    pub host: String,
}

impl RuntimeProvider for CustomDockerHostProvider {
    fn name(&self) -> &str {
        "custom"
    }
    fn available(&self) -> bool {
        true
    }
    fn docker_host(&self) -> String {
        self.host.clone()
    }
}

/// Canonical name prefix for every container managed by this module.
pub const NAME_PREFIX: &str = "yah-pond-";

/// Legacy name prefix from before the sim→pond rename (R362-F5).
/// Used by orphan reconciliation to detect and reap old-generation containers.
pub const LEGACY_NAME_PREFIX: &str = "yah-sim-";

/// Docker label key applied to every container this module owns. The value
/// is `<service>:<env>:<slot>` so `docker ps --filter label=yah.pond=<v>`
/// scopes orphan cleanup to a specific mirror.
pub const LABEL_KEY: &str = "yah.pond";

/// Legacy label key from before the sim→pond rename. Used by `list_owned`
/// to detect old-generation containers during the transition period.
pub const LEGACY_LABEL_KEY: &str = "yah.local-sim";

/// Build the canonical container name for a (service, env, slot) triple.
pub fn canonical_name(service: &str, env: &str, slot: &str) -> String {
    format!("{NAME_PREFIX}{service}-{env}-{slot}")
}

/// Build the canonical label value for the same triple.
pub fn canonical_label(service: &str, env: &str, slot: &str) -> String {
    format!("{service}:{env}:{slot}")
}

/// Canonical per-cell bridge network name. Every container in a pond cell
/// (MinIO, miniflare, mesofact-dev, …) joins this network so they reach each
/// other by their `--network-alias` (R455-F1). One network per (service, env)
/// pair lets two services' ponds coexist without per-port collision juggling.
pub fn pond_network_name(service: &str, env: &str) -> String {
    format!("{NAME_PREFIX}{service}-{env}")
}

/// Operator-declared runtime preference from the provider TOML's top-level
/// `runtime` field. `auto` walks the full cascade; any pinned value probes
/// only that runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePref {
    Auto,
    Orbstack,
    DockerDesktop,
    Colima,
    Podman,
    Docker,
    /// Use the raw `custom_docker_host` string directly.
    Custom,
}

impl RuntimePref {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Orbstack => "orbstack",
            Self::DockerDesktop => "docker-desktop",
            Self::Colima => "colima",
            Self::Podman => "podman",
            Self::Docker => "docker",
            Self::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "auto" => Ok(Self::Auto),
            "orbstack" => Ok(Self::Orbstack),
            "docker-desktop" | "docker_desktop" => Ok(Self::DockerDesktop),
            "colima" => Ok(Self::Colima),
            "podman" => Ok(Self::Podman),
            "docker" => Ok(Self::Docker),
            "custom" => Ok(Self::Custom),
            other => bail!(
                "unknown runtime preference {other:?} \
                 (expected auto/orbstack/docker-desktop/colima/podman/docker/custom)"
            ),
        }
    }
}

/// Probe spec lifted from a `kind = "local-container"` provider TOML.
#[derive(Debug, Clone)]
pub struct LocalContainerSpec {
    pub runtime: RuntimePref,
    /// Socket paths keyed by runtime name. Recognised keys: `orbstack`,
    /// `docker-desktop`, `colima`, `podman`, `docker`. Values are raw paths
    /// (no `unix://` scheme); tilde expansion happens at probe time.
    pub discovery: BTreeMap<String, PathBuf>,
    /// Raw `DOCKER_HOST` value for `runtime = "custom"` (e.g.
    /// `"tcp://localhost:2375"` or `"unix:///path/to/custom.sock"`).
    /// When `runtime = "auto"` this is tried as a last-resort fallback after
    /// all socket candidates fail. Ignored for other pinned runtimes.
    pub custom_docker_host: Option<String>,
}

impl LocalContainerSpec {
    /// Build the ordered [`RuntimeProvider`] cascade for this spec.
    ///
    /// Returns every candidate that has a discovery entry (or a configured
    /// custom host), in probe order. Unlike [`LocalRuntime::detect`], this does
    /// not stop at the first available provider — callers can iterate the list
    /// themselves to render a "Detected / Not found" settings panel.
    pub fn build_cascade(&self) -> Vec<(DetectedRuntime, Box<dyn RuntimeProvider>)> {
        if matches!(self.runtime, RuntimePref::Custom) {
            return if let Some(host) = &self.custom_docker_host {
                vec![(
                    DetectedRuntime::Custom,
                    Box::new(CustomDockerHostProvider { host: host.clone() }),
                )]
            } else {
                vec![]
            };
        }

        let order: &[DetectedRuntime] = match self.runtime {
            RuntimePref::Auto => &[
                DetectedRuntime::Orbstack,
                DetectedRuntime::DockerDesktop,
                DetectedRuntime::Colima,
                DetectedRuntime::Podman,
                DetectedRuntime::Docker,
            ],
            RuntimePref::Orbstack => &[DetectedRuntime::Orbstack],
            RuntimePref::DockerDesktop => &[DetectedRuntime::DockerDesktop],
            RuntimePref::Colima => &[DetectedRuntime::Colima],
            RuntimePref::Podman => &[DetectedRuntime::Podman],
            RuntimePref::Docker => &[DetectedRuntime::Docker],
            RuntimePref::Custom => unreachable!("handled above"),
        };

        let mut result: Vec<(DetectedRuntime, Box<dyn RuntimeProvider>)> = order
            .iter()
            .filter_map(|&kind| {
                self.discovery.get(kind.as_str()).map(|p| -> (DetectedRuntime, Box<dyn RuntimeProvider>) {
                    (kind, Box::new(SocketRuntimeProvider {
                        label: kind.as_str().to_string(),
                        socket: p.clone(),
                    }))
                })
            })
            .collect();

        // Auto: custom host surfaces as last-resort fallback.
        if matches!(self.runtime, RuntimePref::Auto) {
            if let Some(host) = &self.custom_docker_host {
                result.push((
                    DetectedRuntime::Custom,
                    Box::new(CustomDockerHostProvider { host: host.clone() }),
                ));
            }
        }
        result
    }
}

/// Which runtime answered the probe cascade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedRuntime {
    Orbstack,
    DockerDesktop,
    Colima,
    Podman,
    Docker,
    /// Operator-supplied raw `DOCKER_HOST` string (tcp:// or unix://).
    Custom,
}

impl DetectedRuntime {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Orbstack => "orbstack",
            Self::DockerDesktop => "docker-desktop",
            Self::Colima => "colima",
            Self::Podman => "podman",
            Self::Docker => "docker",
            Self::Custom => "custom",
        }
    }
}

/// Reachable local container daemon — the winning provider from the cascade.
#[derive(Debug, Clone)]
pub struct LocalRuntime {
    pub detected: DetectedRuntime,
    /// `DOCKER_HOST` value used for every `docker` CLI invocation against this
    /// runtime (e.g. `"unix:///…"` or `"tcp://localhost:2375"`).
    pub docker_host: String,
}

impl LocalRuntime {
    /// Probe providers in `spec.runtime` order. `Auto` walks the full cascade
    /// orbstack → docker-desktop → colima → podman → docker → custom; a
    /// pinned preference probes only that runtime. Each socket path is
    /// tilde-expanded and existence-checked.
    pub async fn detect(spec: &LocalContainerSpec) -> Result<Self> {
        // Custom DOCKER_HOST: skip the cascade entirely.
        if matches!(spec.runtime, RuntimePref::Custom) {
            let host = spec.custom_docker_host.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "runtime = custom but no custom_docker_host declared in the provider"
                )
            })?;
            return Ok(Self { detected: DetectedRuntime::Custom, docker_host: host.to_string() });
        }

        let order: &[DetectedRuntime] = match spec.runtime {
            RuntimePref::Auto => &[
                DetectedRuntime::Orbstack,
                DetectedRuntime::DockerDesktop,
                DetectedRuntime::Colima,
                DetectedRuntime::Podman,
                DetectedRuntime::Docker,
            ],
            RuntimePref::Orbstack => &[DetectedRuntime::Orbstack],
            RuntimePref::DockerDesktop => &[DetectedRuntime::DockerDesktop],
            RuntimePref::Colima => &[DetectedRuntime::Colima],
            RuntimePref::Podman => &[DetectedRuntime::Podman],
            RuntimePref::Docker => &[DetectedRuntime::Docker],
            RuntimePref::Custom => unreachable!("handled above"),
        };

        let mut attempted = Vec::new();
        for &kind in order {
            let raw = match spec.discovery.get(kind.as_str()) {
                Some(p) => p.clone(),
                None => {
                    attempted.push(format!("{} (no discovery entry)", kind.as_str()));
                    continue;
                }
            };
            let provider = SocketRuntimeProvider {
                label: kind.as_str().to_string(),
                socket: raw,
            };
            if provider.available() {
                return Ok(Self { detected: kind, docker_host: provider.docker_host() });
            }
            attempted.push(format!(
                "{} ({})",
                kind.as_str(),
                expand_tilde(&provider.socket).display()
            ));
        }

        // Auto: custom host as last-resort fallback.
        if matches!(spec.runtime, RuntimePref::Auto) {
            if let Some(host) = &spec.custom_docker_host {
                return Ok(Self {
                    detected: DetectedRuntime::Custom,
                    docker_host: host.clone(),
                });
            }
        }

        bail!(
            "no local container runtime reachable (tried: {}); \
             install or start orbstack, docker-desktop, colima, or podman",
            attempted.join(", "),
        )
    }

    /// Prepare a `docker` Command pre-configured to talk to this runtime via
    /// `DOCKER_HOST`. The CLI must be on PATH (OrbStack and Colima both
    /// register a `docker` shim; Docker Desktop and system Docker install into
    /// `/usr/local/bin`).
    fn cmd(&self) -> Command {
        let mut cmd = Command::new("docker");
        cmd.env("DOCKER_HOST", &self.docker_host);
        cmd.kill_on_drop(true);
        cmd
    }

    /// Run a docker subcommand, returning stdout on success. Captures stderr
    /// for the error message; PATH-not-found surfaces a clean hint.
    async fn run_capture(&self, args: &[&str]) -> Result<String> {
        debug!(runtime = ?self.detected, ?args, "docker");
        let out = self
            .cmd()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("spawning docker (is the CLI installed?): docker {}", args.join(" ")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!(
                "docker {} failed (exit {:?}): {}",
                args.join(" "),
                out.status.code(),
                stderr.trim(),
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// True if `image` is already present in the local image store.
    /// `docker image inspect` returns non-zero (without 'unable to find' on
    /// stderr) when the image is absent.
    pub async fn has_image(&self, image: &str) -> Result<bool> {
        let out = self
            .cmd()
            .args(["image", "inspect", image])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .with_context(|| format!("spawning docker image inspect {image}"))?;
        Ok(out.success())
    }

    /// Pull `image` only when it isn't already cached. Returns `true` if a
    /// pull happened, `false` if the image was already present. Image refs
    /// should be tag-pinned (`caddy:2.10-alpine`) so this stays deterministic.
    pub async fn ensure_image(&self, image: &str) -> Result<bool> {
        if self.has_image(image).await? {
            return Ok(false);
        }
        self.run_capture(&["pull", image]).await?;
        Ok(true)
    }

    /// Idempotently create a docker bridge network. Returns `true` if a
    /// network was created, `false` if one already existed under `name`.
    /// Used by the pond per-cell bridge bring-up (R455-F1).
    pub async fn ensure_network(&self, name: &str) -> Result<bool> {
        let out = self
            .cmd()
            .args(["network", "inspect", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .with_context(|| format!("spawning docker network inspect {name}"))?;
        if out.success() {
            return Ok(false);
        }
        let create = self
            .cmd()
            .args(["network", "create", name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("spawning docker network create {name}"))?;
        if create.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&create.stderr);
        // Race: another caller created the network between inspect and create.
        let lower = stderr.to_lowercase();
        if lower.contains("already exists") {
            return Ok(false);
        }
        bail!("docker network create {name} failed: {}", stderr.trim());
    }

    /// Best-effort `docker rm -f <name>` — silent when the container is
    /// already gone. Used before `run` to clear orphans from a prior crash.
    pub async fn remove_container(&self, name: &str) -> Result<()> {
        let out = self
            .cmd()
            .args(["rm", "-f", name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("spawning docker rm -f {name}"))?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if is_missing_container_error(&stderr) {
            return Ok(());
        }
        bail!("docker rm -f {name} failed: {}", stderr.trim());
    }

    /// Start a detached container per `spec`. Pre-clears any prior container
    /// with the same name so re-runs after a crash are idempotent.
    pub async fn run(&self, spec: &ContainerRunSpec) -> Result<()> {
        // Idempotent: clear any leftover with the same name before launching.
        self.remove_container(&spec.name).await?;

        let args = spec.docker_run_args();
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run_capture(&argv).await?;
        Ok(())
    }

    /// Read the host-side port that the container mapped `container_port/tcp`
    /// to. Runs `docker port <name> <container_port>` and parses the output
    /// (`0.0.0.0:XXXXX` or `:::XXXXX`). Returns an error when the container is
    /// not running or the port is not published.
    pub async fn container_host_port(&self, name: &str, container_port: u16) -> Result<u16> {
        let port_str = container_port.to_string();
        let out = self
            .run_capture(&["port", name, &port_str])
            .await
            .with_context(|| format!("docker port {name} {container_port}"))?;
        // Output is `0.0.0.0:<host_port>` or `:::<host_port>` — split on `:`,
        // take the last token.
        let host_port_str = out
            .trim()
            .rsplit(':')
            .next()
            .filter(|s| !s.is_empty())
            .with_context(|| format!("unexpected docker port output: {:?}", out.trim()))?;
        host_port_str.parse::<u16>().with_context(|| {
            format!(
                "parsing host port {:?} for {name}:{container_port}",
                host_port_str,
            )
        })
    }

    /// Fetch the container's State.Status field (running / exited / …).
    /// Returns `Ok(None)` when the container doesn't exist.
    pub async fn container_state(&self, name: &str) -> Result<Option<ContainerState>> {
        let out = self
            .cmd()
            .args([
                "inspect",
                "--format",
                "{{.State.Status}}",
                name,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("spawning docker inspect {name}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if is_missing_container_error(&stderr) {
                return Ok(None);
            }
            bail!("docker inspect {name} failed: {}", stderr.trim());
        }
        let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Ok(Some(ContainerState::parse(&raw)))
    }

    /// Graceful `docker stop -t <grace_seconds>` followed by `docker rm`.
    /// No-op if the container doesn't exist.
    pub async fn stop_and_remove(&self, name: &str, grace: Duration) -> Result<()> {
        let grace_str = grace.as_secs().to_string();
        let stop = self
            .cmd()
            .args(["stop", "-t", &grace_str, name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("spawning docker stop {name}"))?;
        if !stop.status.success() {
            let stderr = String::from_utf8_lossy(&stop.stderr);
            if !is_missing_container_error(&stderr) {
                bail!("docker stop {name} failed: {}", stderr.trim());
            }
        }
        self.remove_container(name).await
    }

    /// List every container owned by this module on this runtime.
    /// Queries both `yah.pond` (current) and `yah.local-sim` (legacy, pre-R362)
    /// label keys so old-generation containers are visible during the transition.
    pub async fn list_owned(&self) -> Result<Vec<OwnedContainer>> {
        // `docker ps -a --filter label=<key> --format '<name>\t<label-value>\t<state>'`
        // Two passes: current label key + legacy key; merge, dedup by name.
        let mut owned: Vec<OwnedContainer> = Vec::new();
        let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (label_key, format_key) in [
            (LABEL_KEY, LABEL_KEY),
            (LEGACY_LABEL_KEY, LEGACY_LABEL_KEY),
        ] {
            let fmt = format!("{{{{.Names}}}}\t{{{{.Label \"{format_key}\"}}}}\t{{{{.State}}}}");
            let out = self
                .run_capture(&[
                    "ps",
                    "-a",
                    "--filter",
                    &format!("label={label_key}"),
                    "--format",
                    &fmt,
                ])
                .await?;
            for line in out.lines() {
                let mut parts = line.splitn(3, '\t');
                let name = parts.next().unwrap_or_default().trim();
                let label = parts.next().unwrap_or_default().trim();
                let state = parts.next().unwrap_or_default().trim();
                if name.is_empty() || seen_names.contains(name) {
                    continue;
                }
                seen_names.insert(name.to_string());
                owned.push(OwnedContainer {
                    name: name.to_string(),
                    label: label.to_string(),
                    state: ContainerState::parse(state),
                });
            }
        }
        Ok(owned)
    }
}

/// Run-time spec for a single container managed by [`LocalRuntime::run`].
#[derive(Debug, Clone)]
pub struct ContainerRunSpec {
    /// Canonical name — see [`canonical_name`].
    pub name: String,
    /// Image ref. Tag-pinned for cache determinism (`caddy:2.10-alpine`).
    pub image: String,
    /// Value for the `yah.local-sim` label (see [`canonical_label`]).
    pub label: String,
    /// Host→container port bindings.
    pub ports: Vec<(u16, u16)>,
    /// Container env vars.
    pub env: BTreeMap<String, String>,
    /// Bind-mount pairs (host_path, container_path).
    pub volumes: Vec<(PathBuf, String)>,
    /// Optional CMD override; empty leaves the image default.
    pub cmd: Vec<String>,
    /// Linux capabilities to add via `--cap-add` (e.g. `["SYS_ADMIN"]`).
    /// Empty by default; the pond warden-container path (R408-T2) sets this
    /// so Constable can perform cgroup ops inside the container.
    pub cap_add: Vec<String>,
    /// Cgroup namespace mode forwarded to `docker run --cgroupns=...`. Valid
    /// values are `"private"` and `"host"`; `None` leaves the daemon default.
    /// The pond warden-container path (R408-T2) sets `"private"` so the
    /// container sees a fresh `/sys/fs/cgroup` it can write child cgroups
    /// under.
    pub cgroupns: Option<String>,
    /// Docker network to attach the container to via `--network <name>`.
    /// `None` leaves the daemon default (the `bridge` network). The pond
    /// per-cell bridge (R455-F1) sets this to [`pond_network_name`].
    pub network: Option<String>,
    /// Network aliases registered with `--network-alias <alias>` so siblings
    /// on the same bridge can reach this container by name regardless of its
    /// container name. Ignored when [`network`] is `None`.
    pub network_aliases: Vec<String>,
}

impl ContainerRunSpec {
    /// Convenience: build a spec with the canonical name + label derived from
    /// the (service, env, slot) triple.
    pub fn new(service: &str, env: &str, slot: &str, image: impl Into<String>) -> Self {
        Self {
            name: canonical_name(service, env, slot),
            image: image.into(),
            label: canonical_label(service, env, slot),
            ports: vec![],
            env: BTreeMap::new(),
            volumes: vec![],
            cmd: vec![],
            cap_add: vec![],
            cgroupns: None,
            network: None,
            network_aliases: vec![],
        }
    }

    /// Build the full `docker run …` argv emitted by [`LocalRuntime::run`].
    /// Pure helper so callers (and tests) can inspect the wiring without a
    /// live docker socket.
    pub fn docker_run_args(&self) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            self.name.clone(),
            "--label".into(),
            format!("{LABEL_KEY}={}", self.label),
            "--restart".into(),
            "unless-stopped".into(),
        ];
        if let Some(mode) = &self.cgroupns {
            args.push(format!("--cgroupns={mode}"));
        }
        for cap in &self.cap_add {
            args.push("--cap-add".into());
            args.push(cap.clone());
        }
        if let Some(net) = &self.network {
            args.push("--network".into());
            args.push(net.clone());
            for alias in &self.network_aliases {
                args.push("--network-alias".into());
                args.push(alias.clone());
            }
        }
        for (host, container) in &self.ports {
            args.push("-p".into());
            args.push(format!("{host}:{container}"));
        }
        for (k, v) in &self.env {
            args.push("-e".into());
            args.push(format!("{k}={v}"));
        }
        for (host_path, container_path) in &self.volumes {
            args.push("-v".into());
            args.push(format!("{}:{}", host_path.display(), container_path));
        }
        args.push(self.image.clone());
        args.extend(self.cmd.iter().cloned());
        args
    }
}

/// A container managed by this module, as observed via [`LocalRuntime::list_owned`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedContainer {
    pub name: String,
    pub label: String,
    pub state: ContainerState,
}

/// Container State.Status from `docker inspect`. Anything the docs don't
/// enumerate lands in [`Unknown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerState {
    Created,
    Running,
    Restarting,
    Exited,
    Paused,
    Removing,
    Dead,
    Unknown(String),
}

impl ContainerState {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "created" => Self::Created,
            "running" => Self::Running,
            "restarting" => Self::Restarting,
            "exited" => Self::Exited,
            "paused" => Self::Paused,
            "removing" => Self::Removing,
            "dead" => Self::Dead,
            other => Self::Unknown(other.to_string()),
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }
}

/// True if stderr indicates the named container doesn't exist. Both docker
/// CLI and orbstack's docker shim use this shape — but with varying case
/// (`No such container` from upstream docker, `no such object` from orbstack).
fn is_missing_container_error(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("no such container")
        || lower.contains("no such object")
        || lower.contains("not found")
}

/// Expand a leading `~` to `$HOME`. Anything else is returned as-is.
fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    if s == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    p.to_path_buf()
}

// ── LocalDockerRuntime ────────────────────────────────────────────────────────

/// `WorkloadRuntime` implementation backed by the docker CLI.
///
/// Wraps a detected [`LocalRuntime`] and translates each [`WorkloadSpec`] into
/// a [`ContainerRunSpec`] before delegating to the underlying docker calls.
/// This is the sim-tier half of the F10 keystone: camp embeds it pointing at
/// OrbStack; warden supplies the containerd half for cloud/HA.
///
/// Translation notes:
/// - Only `EnvValue::Literal` env vars are forwarded; `FromSecret` and
///   `FromMesh` values are skipped with a warning (no secrets infrastructure
///   at the local tier).
/// - Only `VolumeSource::Bind` mounts are forwarded; named volumes and tmpfs
///   are skipped with a warning.
/// - `spec.command` overrides the image CMD when set.
/// - Mesh / WireGuard / raft fields are ignored — sim containers communicate
///   over OrbStack's bridge network.
pub struct LocalDockerRuntime {
    inner: LocalRuntime,
}

impl LocalDockerRuntime {
    pub fn new(inner: LocalRuntime) -> Self {
        Self { inner }
    }

    /// Access the underlying [`LocalRuntime`] (e.g. to call `ensure_image`
    /// or `list_owned` directly).
    pub fn runtime(&self) -> &LocalRuntime {
        &self.inner
    }
}

/// Translate a `WorkloadSpec` into a `ContainerRunSpec` for the local docker
/// tier. Only the subset of `WorkloadSpec` fields that map directly to docker
/// run args are carried across; warden-specific fields (mesh, resources, raft
/// ident) are silently dropped.
fn workload_spec_to_crs(spec: &WorkloadSpec) -> ContainerRunSpec {
    let image = spec.image.docker_ref();

    let mut env = BTreeMap::new();
    for e in &spec.env {
        match &e.value {
            EnvValue::Literal { value } => {
                env.insert(e.name.clone(), value.clone());
            }
            EnvValue::FromSecret { .. } => {
                warn!(name = %e.name, "LocalDockerRuntime: skipping FromSecret env var (no secrets layer at sim tier)");
            }
            EnvValue::FromMesh { .. } => {
                warn!(name = %e.name, "LocalDockerRuntime: skipping FromMesh env var (no mesh discovery at sim tier)");
            }
        }
    }

    let ports: Vec<(u16, u16)> = spec.expose.mesh.ports.iter().map(|&p| (p, p)).collect();

    let volumes: Vec<(PathBuf, String)> = spec
        .volumes
        .iter()
        .filter_map(|v| match &v.source {
            VolumeSource::Bind { host_path } => {
                Some((host_path.clone(), v.target.to_string_lossy().into_owned()))
            }
            VolumeSource::Named { name } => {
                warn!(volume = %name, "LocalDockerRuntime: skipping Named volume (not supported at sim tier)");
                None
            }
            VolumeSource::Tmpfs { .. } => {
                warn!("LocalDockerRuntime: skipping Tmpfs volume (use -v /dev/null for ephemeral mounts at sim tier)");
                None
            }
        })
        .collect();

    ContainerRunSpec {
        name: spec.name.clone(),
        image,
        label: spec.name.clone(),
        ports,
        env,
        volumes,
        cmd: spec.command.clone().unwrap_or_default(),
        cap_add: vec![],
        cgroupns: None,
        network: None,
        network_aliases: vec![],
    }
}

#[async_trait::async_trait]
impl WorkloadRuntime for LocalDockerRuntime {
    async fn deploy_workload(&self, spec: &WorkloadSpec) -> anyhow::Result<String> {
        let crs = workload_spec_to_crs(spec);
        self.inner.ensure_image(&crs.image).await?;
        self.inner.run(&crs).await?;
        Ok(spec.name.clone())
    }

    async fn teardown_workload(&self, name: &str) -> anyhow::Result<()> {
        self.inner.stop_and_remove(name, Duration::from_secs(10)).await
    }

    async fn is_running(&self, name: &str) -> anyhow::Result<bool> {
        Ok(self
            .inner
            .container_state(name)
            .await?
            .map(|s| s.is_running())
            .unwrap_or(false))
    }

    async fn runtime_health(&self) -> anyhow::Result<bool> {
        // Docker CLI health check: `docker info` exits 0 when the daemon is up.
        let result = self
            .inner
            .run_capture(&["info", "--format", "{{.ServerVersion}}"])
            .await;
        Ok(result.is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn canonical_name_format() {
        assert_eq!(canonical_name("dev-yah", "pond", "static"), "yah-pond-dev-yah-pond-static");
    }

    #[test]
    fn canonical_label_format() {
        assert_eq!(canonical_label("dev-yah", "pond", "object_store"), "dev-yah:pond:object_store");
    }

    #[test]
    fn runtime_pref_parse() {
        assert_eq!(RuntimePref::parse("auto").unwrap(), RuntimePref::Auto);
        assert_eq!(RuntimePref::parse("orbstack").unwrap(), RuntimePref::Orbstack);
        assert_eq!(RuntimePref::parse("docker-desktop").unwrap(), RuntimePref::DockerDesktop);
        assert_eq!(RuntimePref::parse("docker_desktop").unwrap(), RuntimePref::DockerDesktop);
        assert_eq!(RuntimePref::parse("colima").unwrap(), RuntimePref::Colima);
        assert_eq!(RuntimePref::parse("podman").unwrap(), RuntimePref::Podman);
        assert_eq!(RuntimePref::parse("docker").unwrap(), RuntimePref::Docker);
        assert_eq!(RuntimePref::parse("custom").unwrap(), RuntimePref::Custom);
        let err = RuntimePref::parse("nonsense").unwrap_err().to_string();
        assert!(err.contains("nonsense"), "error should name the bad value, got: {err}");
    }

    #[test]
    fn detected_runtime_as_str_round_trips() {
        assert_eq!(DetectedRuntime::Orbstack.as_str(), "orbstack");
        assert_eq!(DetectedRuntime::DockerDesktop.as_str(), "docker-desktop");
        assert_eq!(DetectedRuntime::Colima.as_str(), "colima");
        assert_eq!(DetectedRuntime::Podman.as_str(), "podman");
        assert_eq!(DetectedRuntime::Docker.as_str(), "docker");
        assert_eq!(DetectedRuntime::Custom.as_str(), "custom");
    }

    #[tokio::test]
    async fn detect_returns_error_when_no_socket_exists() {
        // Build a spec pointing at paths that definitely don't exist.
        let mut discovery = BTreeMap::new();
        discovery.insert("orbstack".into(), PathBuf::from("/nonexistent/orbstack.sock"));
        discovery.insert("colima".into(), PathBuf::from("/nonexistent/colima.sock"));
        discovery.insert("docker".into(), PathBuf::from("/nonexistent/docker.sock"));
        let spec = LocalContainerSpec { runtime: RuntimePref::Auto, discovery, custom_docker_host: None };
        let err = LocalRuntime::detect(&spec).await.unwrap_err().to_string();
        assert!(err.contains("no local container runtime reachable"));
        assert!(err.contains("orbstack"));
        assert!(err.contains("colima"));
        assert!(err.contains("docker"));
    }

    #[tokio::test]
    async fn detect_reports_when_pinned_runtime_has_no_discovery_entry() {
        let spec = LocalContainerSpec {
            runtime: RuntimePref::Colima,
            discovery: BTreeMap::new(),
            custom_docker_host: None,
        };
        let err = LocalRuntime::detect(&spec).await.unwrap_err().to_string();
        assert!(err.contains("colima"));
        assert!(err.contains("no discovery entry"));
    }

    #[tokio::test]
    async fn detect_picks_existing_socket() {
        // Use a tempdir + touch file to stand in for a real socket. detect()
        // only checks existence, not socket-ness.
        let tmp = tempfile::TempDir::new().unwrap();
        let fake = tmp.path().join("docker.sock");
        std::fs::write(&fake, b"").unwrap();
        let mut discovery = BTreeMap::new();
        discovery.insert("orbstack".into(), PathBuf::from("/nonexistent/no.sock"));
        discovery.insert("colima".into(), PathBuf::from("/nonexistent/no.sock"));
        discovery.insert("docker".into(), fake.clone());
        let spec = LocalContainerSpec { runtime: RuntimePref::Auto, discovery, custom_docker_host: None };
        let runtime = LocalRuntime::detect(&spec).await.unwrap();
        assert_eq!(runtime.detected, DetectedRuntime::Docker);
        assert_eq!(runtime.docker_host, format!("unix://{}", fake.display()));
    }

    #[tokio::test]
    async fn detect_honors_runtime_pin_and_skips_others() {
        // Even if a later runtime's socket exists, a pinned earlier runtime
        // without a socket should fail rather than fall through.
        let tmp = tempfile::TempDir::new().unwrap();
        let fake = tmp.path().join("docker.sock");
        std::fs::write(&fake, b"").unwrap();
        let mut discovery = BTreeMap::new();
        discovery.insert("orbstack".into(), PathBuf::from("/nonexistent/no.sock"));
        discovery.insert("docker".into(), fake);
        let spec = LocalContainerSpec { runtime: RuntimePref::Orbstack, discovery, custom_docker_host: None };
        let err = LocalRuntime::detect(&spec).await.unwrap_err().to_string();
        assert!(err.contains("orbstack"));
        // The error body should not list docker as an *attempted* probe entry.
        // (The hint text "install or start ... docker-desktop ..." may mention docker
        // substrings, but the tried-list should only show orbstack.)
        assert!(!err.contains("docker ("), "pinned to orbstack — docker should not be in tried list: {err}");
    }

    #[tokio::test]
    async fn detect_custom_pref_uses_host_directly() {
        let spec = LocalContainerSpec {
            runtime: RuntimePref::Custom,
            discovery: BTreeMap::new(),
            custom_docker_host: Some("tcp://localhost:2375".into()),
        };
        let runtime = LocalRuntime::detect(&spec).await.unwrap();
        assert_eq!(runtime.detected, DetectedRuntime::Custom);
        assert_eq!(runtime.docker_host, "tcp://localhost:2375");
    }

    #[tokio::test]
    async fn detect_custom_pref_without_host_errors() {
        let spec = LocalContainerSpec {
            runtime: RuntimePref::Custom,
            discovery: BTreeMap::new(),
            custom_docker_host: None,
        };
        let err = LocalRuntime::detect(&spec).await.unwrap_err().to_string();
        assert!(err.contains("custom_docker_host"), "error should mention the missing field: {err}");
    }

    #[tokio::test]
    async fn detect_auto_falls_back_to_custom_host() {
        // All socket candidates absent, but a custom_docker_host is configured.
        let spec = LocalContainerSpec {
            runtime: RuntimePref::Auto,
            discovery: BTreeMap::new(),
            custom_docker_host: Some("tcp://localhost:2375".into()),
        };
        let runtime = LocalRuntime::detect(&spec).await.unwrap();
        assert_eq!(runtime.detected, DetectedRuntime::Custom);
        assert_eq!(runtime.docker_host, "tcp://localhost:2375");
    }

    #[test]
    fn build_cascade_returns_providers_with_discovery_entries() {
        let mut discovery = BTreeMap::new();
        discovery.insert("orbstack".into(), PathBuf::from("/fake/orbstack.sock"));
        discovery.insert("docker".into(), PathBuf::from("/fake/docker.sock"));
        let spec = LocalContainerSpec { runtime: RuntimePref::Auto, discovery, custom_docker_host: None };
        let cascade = spec.build_cascade();
        // Only orbstack and docker have entries; docker-desktop/colima/podman are absent.
        assert_eq!(cascade.len(), 2);
        assert!(cascade.iter().any(|(k, _)| *k == DetectedRuntime::Orbstack));
        assert!(cascade.iter().any(|(k, _)| *k == DetectedRuntime::Docker));
    }

    #[test]
    fn build_cascade_custom_pref_returns_single_entry() {
        let spec = LocalContainerSpec {
            runtime: RuntimePref::Custom,
            discovery: BTreeMap::new(),
            custom_docker_host: Some("tcp://localhost:2375".into()),
        };
        let cascade = spec.build_cascade();
        assert_eq!(cascade.len(), 1);
        let (kind, provider) = &cascade[0];
        assert_eq!(*kind, DetectedRuntime::Custom);
        assert_eq!(provider.docker_host(), "tcp://localhost:2375");
        assert!(provider.available());
    }

    #[test]
    fn expand_tilde_replaces_home_prefix() {
        std::env::set_var("HOME", "/tmp/fake-home");
        let p = expand_tilde(Path::new("~/foo/bar"));
        assert_eq!(p, PathBuf::from("/tmp/fake-home/foo/bar"));
    }

    #[test]
    fn expand_tilde_leaves_absolute_paths_alone() {
        let p = expand_tilde(Path::new("/var/run/docker.sock"));
        assert_eq!(p, PathBuf::from("/var/run/docker.sock"));
    }

    #[test]
    fn container_state_parse_known_values() {
        assert_eq!(ContainerState::parse("running"), ContainerState::Running);
        assert_eq!(ContainerState::parse("exited"), ContainerState::Exited);
        assert_eq!(ContainerState::parse("PAUSED"), ContainerState::Paused);
    }

    #[test]
    fn container_state_parse_unknown_preserves_string() {
        match ContainerState::parse("zombie") {
            ContainerState::Unknown(s) => assert_eq!(s, "zombie"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn is_missing_container_error_matches_upstream_and_orbstack() {
        assert!(is_missing_container_error("Error: No such container: foo"));
        assert!(is_missing_container_error("error: no such object: foo"));
        assert!(is_missing_container_error("not found: foo"));
        assert!(!is_missing_container_error("Error response from daemon: Conflict."));
        assert!(!is_missing_container_error(""));
    }

    #[test]
    fn container_run_spec_new_uses_canonical_name() {
        let spec = ContainerRunSpec::new("dev-yah", "pond", "static", "caddy:2-alpine");
        assert_eq!(spec.name, "yah-pond-dev-yah-pond-static");
        assert_eq!(spec.label, "dev-yah:pond:static");
        assert!(spec.ports.is_empty());
        assert!(spec.network.is_none());
        assert!(spec.network_aliases.is_empty());
    }

    #[test]
    fn pond_network_name_is_yah_pond_svc_env() {
        assert_eq!(pond_network_name("yah-marketing", "pond"), "yah-pond-yah-marketing-pond");
        assert_eq!(pond_network_name("yah-dashboard", "pond"), "yah-pond-yah-dashboard-pond");
    }

    #[test]
    fn docker_run_args_emit_network_and_aliases_when_set() {
        let mut spec = ContainerRunSpec::new("dev", "pond", "object_store", "minio:latest");
        spec.network = Some("yah-pond-dev-pond".into());
        spec.network_aliases = vec!["minio".into()];
        let args = spec.docker_run_args();
        let joined = args.join(" ");
        assert!(
            joined.contains("--network yah-pond-dev-pond"),
            "expected --network flag in: {joined}",
        );
        assert!(
            joined.contains("--network-alias minio"),
            "expected --network-alias minio in: {joined}",
        );
    }

    #[test]
    fn docker_run_args_omit_network_flags_when_unset() {
        let spec = ContainerRunSpec::new("dev", "pond", "object_store", "minio:latest");
        let args = spec.docker_run_args();
        let joined = args.join(" ");
        assert!(!joined.contains("--network"), "unexpected --network flag: {joined}");
        assert!(!joined.contains("--network-alias"), "unexpected --network-alias flag: {joined}");
    }

    #[test]
    fn docker_run_args_skip_aliases_when_no_network() {
        // Aliases without a network are meaningless — docker would reject `--network-alias`
        // without `--network`. Defensive: emit neither.
        let mut spec = ContainerRunSpec::new("dev", "pond", "object_store", "minio:latest");
        spec.network_aliases = vec!["minio".into()];
        let args = spec.docker_run_args();
        let joined = args.join(" ");
        assert!(!joined.contains("--network-alias"), "should not emit alias without network: {joined}");
    }

    // ── LocalDockerRuntime / workload_spec_to_crs unit tests ─────────────────

    fn minimal_workload_spec(name: &str) -> workload_spec::WorkloadSpec {
        use workload_spec::*;
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.to_string(),
            image: ImageRef {
                registry: "ghcr.io".into(),
                repository: "test/app".into(),
                tag: "v1.0".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".into()),
            replicas: 1,
            command: None,
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits { memory_mb: 256, cpu_shares: 512, ephemeral_storage_mb: 256 },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            stop_policy: StopPolicy { signal: 15, grace_period: Millis::from_secs(10) },
            expose: ExposeSpec {
                mesh: MeshExpose { identity: MeshIdent(name.into()), ports: vec![], allow_from: vec![] },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        }
    }

    #[test]
    fn workload_spec_to_crs_sets_name_and_image() {
        let spec = minimal_workload_spec("test-app");
        let crs = workload_spec_to_crs(&spec);
        assert_eq!(crs.name, "test-app");
        assert_eq!(crs.image, "ghcr.io/test/app:v1.0");
        assert!(crs.ports.is_empty());
        assert!(crs.env.is_empty());
    }

    #[test]
    fn workload_spec_to_crs_forwards_literal_env_only() {
        use workload_spec::{EnvValue, EnvVar, MeshIdent, MeshLookup};
        let mut spec = minimal_workload_spec("env-test");
        spec.env = vec![
            EnvVar { name: "GOOD".into(), value: EnvValue::Literal { value: "yes".into() } },
            EnvVar { name: "BAD_SECRET".into(), value: EnvValue::FromSecret { secret: "s".into(), key: "k".into() } },
            EnvVar { name: "BAD_MESH".into(), value: EnvValue::FromMesh { ident: MeshIdent("x".into()), kind: MeshLookup::Url } },
        ];
        let crs = workload_spec_to_crs(&spec);
        assert_eq!(crs.env.get("GOOD").map(String::as_str), Some("yes"));
        assert!(!crs.env.contains_key("BAD_SECRET"), "FromSecret must be filtered out");
        assert!(!crs.env.contains_key("BAD_MESH"), "FromMesh must be filtered out");
    }

    #[test]
    fn workload_spec_to_crs_maps_mesh_ports() {
        let mut spec = minimal_workload_spec("port-test");
        spec.expose.mesh.ports = vec![8080, 9000];
        let crs = workload_spec_to_crs(&spec);
        assert_eq!(crs.ports, vec![(8080, 8080), (9000, 9000)]);
    }

    #[test]
    fn workload_spec_to_crs_applies_command_override() {
        let mut spec = minimal_workload_spec("cmd-test");
        spec.command = Some(vec!["server".into(), "--port=8080".into()]);
        let crs = workload_spec_to_crs(&spec);
        assert_eq!(crs.cmd, vec!["server", "--port=8080"]);
    }

    #[test]
    fn image_ref_docker_ref_emits_tag_and_digest() {
        use workload_spec::ImageRef;
        let r = ImageRef {
            registry: "ghcr.io".into(),
            repository: "org/app".into(),
            tag: "v1.0".into(),
            digest: "sha256:abc123".into(),
        };
        assert_eq!(r.docker_ref(), "ghcr.io/org/app:v1.0@sha256:abc123");
    }

    // Live docker-socket integration tests + the `from_provider_config`
    // adapter tests live in `cloud::local_driver_glue::tests` so they can
    // depend on `cloud::config::ProviderConfig` without local-driver pulling
    // a reverse dep on cloud.
}
