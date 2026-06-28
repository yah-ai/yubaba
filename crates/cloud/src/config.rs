//! @yah:ticket(R040-F16, "pg-on-mesh service recipe: bind tailscale0 + pg_hba.conf snippet + ufw rules")
//! @yah:at(2026-05-05T00:32:34Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:parent(R040)
//! @yah:handoff("Companion to R040-F15. Inter-node TCP (Postgres primary↔replica, NATS clusters, anything raw-protocol) lives on the Headscale mesh, not on Hetzner public IPs. Each node has a stable 100.64.x.x mesh IP that survives replacement of the underlying box, so DNS / config / pg_hba never churn when a CPX-11 is rebuilt. WireGuard already encrypts the wire — TLS becomes defense-in-depth, not load-bearing. This ticket carries the concrete pg-shaped recipe so the first stateful service deploy doesn't have to re-derive the pattern; subsequent services (redis, NATS, etc.) cargo-cult from it.")
//! @yah:next("ServiceConfig gains a `bind_interface: Option<String>` field (e.g. `Some(\"tailscale0\")` for mesh-only services). The cloud-init/podman compose renderer translates this into either `--network host` + `pg listen_addresses = '<mesh-ip>'` OR a podman macvlan/host-binding pattern that achieves the same.")
//! @yah:next("Generated pg_hba.conf snippet: allow the mesh subnet (100.64.0.0/10) for replication + app users. Postgres binds to the node's tailscale0 mesh IP only — `listen_addresses` is templated from the node's `tailscale ip --4` at first boot.")
//! @yah:next("Generated ufw rules: `ufw allow in on tailscale0 to any port 5432; ufw deny 5432` — mirrors the existing yah-yubaba 7443 pattern in mirror.yml. Same shape works for any mesh-only port.")
//! @yah:next("Replica connection string uses primary's mesh IP, NOT its public IP. Stable across box replacement.")
//! @yah:next("Out of scope: pg_basebackup orchestration, failover, WAL archiving — those belong in noisetable's domain; this ticket only standardizes the binding/firewall/auth shape so noisetable's pg deployment doesn't reinvent it.")
//!
//!
//! @yah:ticket(R323-F9, "Add sync-wave ordering to ServiceComponent (deploy-panel wave order)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T15:20:25Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R323)
//! @yah:next("ServiceComponent gains a wave/order field (or depends_on between components) so the deploy panel (R323-F4) can group workload rollout rows into sync waves (wave 0 parallel, wait healthy, wave 1, …). Today all components are implicitly wave 0.")
//! @yah:next("compute_service/compute_cell in reconciler/sync_status.rs surface the wave per workload so F4 doesn't re-derive it.")
//! @yah:gotcha("Until this lands, F4 should render every workload as wave 0 (no ordering).")
//! @yah:handoff("Added wave: u32 (serde default=0, skip_serializing_if zero) to ServiceComponent in config.rs. Added is_zero_u32 helper. Fixed the three struct literal call-sites that now need wave: 0 (config.rs test, local_sim.rs x2, mesofact_static.rs). Added wave?: number to the TS ServiceComponent interface with a doc comment. Deploy panel now reads c.wave ?? 0 for each WorkloadRow instead of hardcoded 0. SyncFooter computes maxWave from the components array and renders 'wave 0' (all-zero case) or 'waves 0–N' (multi-wave). All 218 cloud lib tests pass; bun run typecheck clean.")
//! @yah:verify("cargo test -p cloud --lib  # 218 passed")
//! @yah:verify("cd packages/yah/ui && bun run typecheck  # no new errors")
//! @yah:verify("In service.toml: add wave = 1 to a component, rebuild, open the deploy panel — that workload row shows 'w1' badge; SyncFooter shows 'waves 0–1'")
//! @yah:verify("Component with no wave field in TOML deserializes as wave=0 (default). Saving a wave=0 component omits the field from the output TOML (skip_serializing_if).")
//!
//! @arch:see(.yah/docs/working/W142-pond.md)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use thiserror::Error;
use workload_spec::{validate, WorkloadSpec};

/// Per-machine TOML from `.yah/cloud/machines/<name>.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MachineConfig {
    pub name: String,
    pub provider: String,
    /// Provider DC code (e.g. Hetzner `"hil"`). **Provisioning-only**: required
    /// iff the provider has an auto-provision driver ([`provider_has_machine_driver`]);
    /// a BYO `static` node we brought up over SSH has no such code. Optional at
    /// load time so static machine.tomls omit it; [`MachineConfig::validate`]
    /// enforces presence at the right moment for driver-backed providers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Provider SKU/size (e.g. Hetzner `"ccx13"`). Provisioning-only, same
    /// optionality contract as [`location`](Self::location).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
    /// **Deprecated (R330-F16).** A machine should describe *itself* (region,
    /// zone, provider, mesh_tags); *which* mirrors run on it is derived by the
    /// reconciler from each mirror's `required` placement spec, not declared
    /// here. Now optional + omitted-when-empty so new machine.tomls leave it
    /// out. The legacy `resolve_mirror_machine` topology fallback still reads
    /// it until yubaba's reverse-index supersedes the topology.toml path; once
    /// that lands, this field and its readers are removed wholesale.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts_mirrors: Vec<String>,
    pub mesh_tags: Vec<String>,
    /// Canonical geo region label (latency axis), e.g. `"us-west"`. F16's three
    /// topology axes are orthogonal: `region` = geo (latency), `zone` = failure
    /// domain within a region (HA), `provider` = network/cost. `region` is
    /// distinct from `location` (the provider's DC code, e.g. Hetzner `"hil"`):
    /// `location` is provider-scoped, `region` is our provider-neutral label.
    /// Optional for backward-compat; a machine without it never satisfies a
    /// `required.regions` constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Failure-domain label within a region (HA axis), e.g. `"hil"`. For
    /// single-DC Hetzner this typically mirrors `location`. F16 placement
    /// matches `required.zones` against this. Optional for backward-compat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    pub bucket: Option<BucketSpec>,
    pub hostkey_fingerprint: Option<String>,
    /// Provider-side SSH-key IDs (Hetzner: from `GET /v1/ssh_keys`)
    /// authorized for `root` at create time. Defaults to empty for
    /// backwards-compat with existing machine declarations; an empty
    /// list yields a Hetzner-emailed random root password (which the
    /// driver currently discards). Populate this when you want pre-mesh
    /// SSH access for bootstrap deploys or recovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_keys: Vec<u64>,
    /// Cloudflare Tunnel ID this machine joins (e.g. `abc123.cfargotunnel.com`).
    /// `None` → no tunnel (mesh-only node, no public ingress).
    /// When set, `yah cloud machine provision` reads `cloudflare-tunnel-token`
    /// from the keys vault and injects the cloudflared install block into
    /// cloud-init so the new machine connects to CF edge on first boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflared: Option<String>,
    /// When `true`, this machine hosts operator-bridge workloads (Tailscale
    /// operator access to mesh-internal services). `yah cloud machine provision`
    /// will install tailscaled and run `tailscale up` during cloud-init via the
    /// `{{OPERATOR_BRIDGE_BLOCK}}` placeholder. Defaults to `false` for
    /// backward-compat with existing machine declarations.
    #[serde(default)]
    pub hosts_operator_bridge: bool,
    /// BYO `static`-node reach descriptor. Static nodes have no provider API to
    /// probe, so how the camp reaches them (SSH user@host + the yubaba URL,
    /// which is loopback until the WireGuard mesh lands) is *declared* here.
    /// `None` for driver-backed providers (Hetzner/Vultr), whose address is
    /// resolved from the provider API / mesh at provision time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<ConnectSpec>,
}

/// True iff `provider` has an auto-provision driver (create/destroy via API).
/// Driver-backed providers require `location` + `server_type`; BYO `static`
/// nodes (brought up over SSH) do not. The cloud-vs-vps distinction the fleet
/// cares about lives here — at the provider-capability layer — not as a
/// separate machine type (W242 BYO Phase-0 decision).
pub fn provider_has_machine_driver(provider: &str) -> bool {
    matches!(provider, "hetzner" | "vultr" | "digitalocean")
}

impl MachineConfig {
    /// Provider DC code, or `""` when omitted (static nodes). Most readers want
    /// a `&str`; the driver-backed provision/status paths still go through
    /// [`validate`](Self::validate) which guarantees presence for those.
    pub fn location(&self) -> &str {
        self.location.as_deref().unwrap_or("")
    }

    /// Provider SKU, or `""` when omitted (static nodes).
    pub fn server_type(&self) -> &str {
        self.server_type.as_deref().unwrap_or("")
    }

    /// Enforce the provisioning-only-field contract: a machine whose provider
    /// has an auto-provision driver MUST declare `location` + `server_type`
    /// (the driver can't create a server without them). Static nodes may omit
    /// both. Call this before any provision/diff that assumes a driver.
    pub fn validate(&self) -> Result<()> {
        if provider_has_machine_driver(&self.provider) {
            if self.location.is_none() {
                anyhow::bail!(
                    "machine '{}' (provider '{}') has an auto-provision driver but no `location`",
                    self.name,
                    self.provider
                );
            }
            if self.server_type.is_none() {
                anyhow::bail!(
                    "machine '{}' (provider '{}') has an auto-provision driver but no `server_type`",
                    self.name,
                    self.provider
                );
            }
        }
        Ok(())
    }

    /// Persist to `<cloud_dir>/machines/<name>.toml`, creating the dir if needed.
    pub fn save(&self, cloud_dir: &Path) -> Result<()> {
        let dir = cloud_dir.join("machines");
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(format!("{}.toml", self.name));
        let s = toml::to_string_pretty(self)
            .with_context(|| format!("serializing machine {}", self.name))?;
        std::fs::write(&path, s).with_context(|| format!("writing {}", path.display()))
    }
}

/// Reach descriptor for a BYO `static` node (no provider API). Lives under
/// `[connect]` in the machine TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ConnectSpec {
    /// Reachable IPv4/host for the box, e.g. `"45.32.194.254"`.
    pub address: String,
    /// SSH target the camp dials for bootstrap + (pre-mesh) tunneled deploys,
    /// e.g. `"root@45.32.194.254"` or `"debian@15.204.89.240"`. Uses the
    /// operator's `~/.ssh/yah` key.
    pub ssh: String,
    /// Yubaba RPC URL. Loopback (`"http://127.0.0.1:7443"`) until the WireGuard
    /// mesh lands — reached via an SSH tunnel to `ssh`. Rebinds to the mesh IP
    /// in the post-mesh world (W242 P2).
    pub yubaba: String,
    /// Declared CPU arch (`"x86_64"` / `"aarch64"`) — no provider API to probe
    /// it, and the yubaba release triple depends on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct BucketSpec {
    pub name: String,
    pub public_read: bool,
}

/// Per-camp mirror declaration from `.yah/cloud/mirrors/<id>/mirror.toml`
/// (folder form) or the legacy `.yah/cloud/mirrors/<id>.toml` (flat form).
///
/// The folder form is preferred for new mirrors so that per-mirror secrets
/// and override files can sit next to `mirror.toml` without polluting the
/// top-level `mirrors/` directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyMirrorConfig {
    /// Logical camp name this mirror hosts, e.g. `"yah"` or `"noisetable"`.
    ///
    /// Serialised as `camp`; accepts the legacy `rig` spelling for files that
    /// predate the R137 rig→camp rename (one-time migration: `sed -i ''
    /// 's/^rig = /camp = /' ~/.yah/cloud/mirrors/*.toml`).
    #[serde(rename = "camp", alias = "rig")]
    pub camp: String,
    pub regions: Vec<String>,
    /// Workload names deployed as part of this mirror (references `workloads/<name>.toml`).
    /// Renamed from `services` in R092-F1; use `yah cloud config migrate-services-to-workloads`
    /// on repos that still have the old `services/` layout.
    #[serde(alias = "services")]
    pub workloads: Vec<String>,
    /// Base domain for Cloudflare-fronted services on this mirror's machines.
    /// Combined with the machine's `location` to build virtual-host names:
    /// e.g. `cloud_domain = "cloud.noisetable.example"` on machine in location
    /// `pdx` → Caddyfile site address `pdx.cloud.noisetable.example`.
    /// Optional: if unset the Caddyfile falls back to `:port` listeners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_domain: Option<String>,
}

/// Error from loading or validating a single workload TOML file.
#[derive(Debug, Error)]
pub enum WorkloadConfigError {
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Toml {
        path: String,
        source: toml::de::Error,
    },
    #[error("invalid WorkloadSpec in {path}: {source}")]
    Shape {
        path: String,
        source: validate::ShapeError,
    },
}

/// A workload declaration loaded from `.yah/cloud/workloads/<name>.toml`.
///
/// Each file is the human-authored TOML serialization of a [`WorkloadSpec`].
/// On load, the spec is validated against the shape layer; failures surface as
/// a [`CloudConfigError::Workload`] with the file path and field path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadConfig {
    /// The validated spec.
    #[serde(flatten)]
    pub spec: WorkloadSpec,
}

impl WorkloadConfig {
    /// Persist to `<cloud_dir>/workloads/<name>.toml`, creating the dir if needed.
    pub fn save(&self, cloud_dir: &Path) -> Result<()> {
        let dir = cloud_dir.join("workloads");
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(format!("{}.toml", self.spec.name));
        let s = toml::to_string_pretty(self)
            .with_context(|| format!("serializing workload {}", self.spec.name))?;
        std::fs::write(&path, s).with_context(|| format!("writing {}", path.display()))
    }
}

/// Error surfaced by [`CloudConfig::load`] when a workload TOML fails validation.
#[derive(Debug, Error)]
pub enum CloudConfigError {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
    #[error("workload validation failed: {0}")]
    Workload(WorkloadConfigError),
}

/// Mirror-to-machine assignment table from `.yah/cloud/topology.toml`.
///
/// Declares which logical mirror names are assigned to which machines.
/// This is the source-canonical placement until yubaba raft observes it
/// (per the migration tracker in the arch doc).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TopologyConfig {
    /// Mirror→machine assignments.
    #[serde(default)]
    pub assignments: Vec<MirrorAssignment>,
    /// Declared buckets, logged by `yah cloud bucket create`.
    /// Source-canonical until yubaba raft observes actual placement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buckets: Vec<BucketLogEntry>,
}

impl TopologyConfig {
    /// Load from a `topology.toml` file, returning `Default` when absent.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let s =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&s).with_context(|| format!("parsing {}", path.display()))
    }

    /// Persist to `topology.toml`, creating parent dirs if needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let s = toml::to_string_pretty(self).context("serializing topology")?;
        std::fs::write(path, s).with_context(|| format!("writing {}", path.display()))
    }

    /// Find a declared bucket by name.
    pub fn bucket_by_name(&self, name: &str) -> Option<&BucketLogEntry> {
        self.buckets.iter().find(|b| b.name == name)
    }

    /// Find a mutable declared bucket by name.
    pub fn bucket_by_name_mut(&mut self, name: &str) -> Option<&mut BucketLogEntry> {
        self.buckets.iter_mut().find(|b| b.name == name)
    }

    /// Returns true if the bucket is declared as cross-machine (no owning machine).
    pub fn is_cross_machine_bucket(&self, name: &str) -> bool {
        self.buckets
            .iter()
            .any(|b| b.name == name && b.machine.is_none())
    }
}

/// One mirror→machine placement entry in `topology.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorAssignment {
    /// Logical mirror name, e.g. `"noisetable-pdx"`.
    pub mirror: String,
    /// Machine that hosts this mirror, e.g. `"noisetable-pdx-1"`.
    pub machine: String,
}

/// A bucket declaration logged in `topology.toml` by `yah cloud bucket create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketLogEntry {
    pub name: String,
    /// Machine that owns this bucket. `None` marks it as cross-machine
    /// (no single-machine ownership; requires an explicit declaration in
    /// `topology.toml` before `yah cloud bucket create` will proceed without
    /// `--machine`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// Logical location of the bucket, e.g. `"pdx"`.
    pub location: String,
    /// Current declared policy: `"private"` | `"public-read"` | `"signed-only"`.
    #[serde(default = "default_bucket_policy")]
    pub policy: String,
}

fn default_bucket_policy() -> String {
    "private".to_string()
}

/// Per-service config from `.yah/cloud/services/<name>.toml`.
///
/// **Deprecated.** The `services/` layout was replaced by `workloads/` in R092-F1.
/// Kept to allow in-place reads for repos that haven't migrated yet; use
/// `yah cloud config migrate-services-to-workloads` to upgrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyServiceConfig {
    pub name: String,
    pub image: String,
    pub version: String,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub ports: Vec<PortMapping>,
    #[serde(default)]
    pub mesh_only: bool,
    /// Network interface this service binds to exclusively (e.g. `"tailscale0"`).
    ///
    /// When set the compose renderer emits `network_mode: "host"` and the
    /// service is NOT joined to the shared compose bridge network. The service
    /// process must bind its listen socket to the named interface's IP — for
    /// Postgres this means setting `POSTGRES_LISTEN_ADDRESSES` to the node's
    /// `tailscale ip --4` output at first boot. See [`crate::mesh_service`] for
    /// the standard pg_hba.conf snippet and ufw rules to pair with this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host: u16,
    pub container: u16,
}

/// A loaded service plus its per-environment mirrors.
///
/// Wraps the `service.toml` body and the directory of `mirrors/<env>.toml`
/// files that project the service onto concrete infra.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceWithMirrors {
    pub service: ServiceConfig,
    /// Mirrors keyed by environment name (file stem of `mirrors/<env>.toml`).
    pub mirrors: BTreeMap<String, MirrorConfig>,
    /// Transform recipe names keyed by component id. Populated from each
    /// static-asset component's `workload.toml` at load time — not stored
    /// in service.toml. Only present for components that declare
    /// `[asset.derive.transform] recipe = "..."`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub component_transform_recipes: BTreeMap<String, String>,
}

/// All cloud config loaded from a workspace root (the parent of `.yah/`).
///
/// Reads two trees:
/// - `.yah/infra/` — `machines/`, `providers/`
/// - `.yah/services/<svc>/` — `service.toml` + `mirrors/<env>.toml`
///
/// Pre-R215 fields (`legacy_mirrors`, `legacy_services`, `workloads`,
/// `topology`) are still populated from `.yah/cloud/` when present so
/// pre-R215 callers (compose.rs, bucket commands) keep compiling — they
/// just see empty collections in a post-B1 workspace where the legacy
/// data was deleted. These fields are scheduled for removal in B3-T3.
#[derive(Debug)]
pub struct CloudConfig {
    /// Workspace root that was loaded — useful for path-resolving
    /// component references on a [`ServiceComponent`].
    pub workspace_root: std::path::PathBuf,

    // ─── R215+ tree ────────────────────────────────────────────────────────
    /// `.yah/infra/machines/<name>.toml`
    pub machines: Vec<MachineConfig>,
    /// `.yah/infra/providers/<id>.toml`
    pub providers: Vec<ProviderConfig>,
    /// `.yah/services/<svc>/` — service.toml plus mirrors/<env>.toml.
    pub services: BTreeMap<String, ServiceWithMirrors>,
    /// `.yah/domains/<name>.toml` — public-facing routing manifests
    /// (R347). Single file per domain; no nested per-env tree because
    /// domains themselves aren't projected onto infra — they describe
    /// how a Worker bundle ingresses requests onto services.
    pub domains: BTreeMap<String, DomainConfig>,

    // ─── Pre-R215 legacy (slated for removal in B3-T3) ────────────────────
    /// Legacy mirrors from `.yah/cloud/mirrors/`.
    pub legacy_mirrors: Vec<LegacyMirrorConfig>,
    /// Workloads from `.yah/cloud/workloads/*.toml` (R092-F1 schema).
    pub workloads: Vec<WorkloadConfig>,
    /// Topology from `.yah/cloud/topology.toml` (mirror→machine assignments).
    pub topology: TopologyConfig,
    /// Legacy services from `.yah/cloud/services/*.toml` (pre-R092 layout).
    pub legacy_services: Vec<LegacyServiceConfig>,
}

impl CloudConfig {
    /// Load all cloud config rooted at `workspace_root` (the parent of `.yah/`).
    ///
    /// Reads the R215+ tree (`.yah/infra/`, `.yah/services/<svc>/`) eagerly
    /// and the pre-R215 `.yah/cloud/` tree opportunistically. Returns `Err`
    /// immediately if any TOML fails to parse or a workload TOML fails
    /// shape validation; the error includes the file path and field path.
    ///
    /// Cross-ref validation runs after both trees finish loading: every
    /// `mirror.providers.X.use = "<id>"` must resolve to a real provider
    /// declared under `.yah/infra/providers/`.
    pub fn load(workspace_root: &Path) -> Result<Self> {
        let providers = load_providers(&crate::paths::providers_dir(workspace_root))?;
        let services = load_services(&crate::paths::services_dir(workspace_root), workspace_root)?;
        let domains = load_domains(&crate::paths::domains_dir(workspace_root))?;

        // Cross-ref validation: mirror `use = "<id>"` slots must resolve.
        let provider_ids: std::collections::HashSet<&str> =
            providers.iter().map(|p| p.id.as_str()).collect();
        for (svc_name, svc) in &services {
            for (env, mirror) in &svc.mirrors {
                for (slot, body) in &mirror.providers {
                    if let Some(id) = body.provider_id() {
                        if !provider_ids.contains(id) {
                            anyhow::bail!(
                                "services/{svc_name}/mirrors/{env}.toml: \
                                 providers.{slot}.use = \"{id}\" — no such provider; \
                                 declare it at .yah/infra/providers/{id}.toml"
                            );
                        }
                    }
                }
            }
        }

        // Cross-ref validation: every domain route's `component =
        // "<service>/<component-id>"` must resolve to a real component.
        for (dom_name, dom) in &domains {
            for (idx, route) in dom.routes.iter().enumerate() {
                let Some(component_ref) = route.mode.component() else {
                    continue; // redirects don't reference components
                };
                let Some((svc_name, comp_id)) = split_component_ref(component_ref) else {
                    anyhow::bail!(
                        "domains/{dom_name}.toml: routes[{idx}].component = \
                         \"{component_ref}\" — expected \"<service>/<component-id>\""
                    );
                };
                let Some(svc) = services.get(svc_name) else {
                    anyhow::bail!(
                        "domains/{dom_name}.toml: routes[{idx}].component = \
                         \"{component_ref}\" — no such service \"{svc_name}\" \
                         under .yah/services/"
                    );
                };
                if !svc.service.components.iter().any(|c| c.id == comp_id) {
                    anyhow::bail!(
                        "domains/{dom_name}.toml: routes[{idx}].component = \
                         \"{component_ref}\" — service \"{svc_name}\" has no \
                         component with id \"{comp_id}\""
                    );
                }
            }
        }

        // Legacy `.yah/cloud/` reads — empty in post-B1 workspaces. Wrapped in
        // a helper so a missing tree is silent (no error, no warning).
        let cloud_dir = crate::paths::legacy_cloud_dir(workspace_root);
        let (legacy_machines, legacy_mirrors, workloads, topology, legacy_services) =
            if cloud_dir.exists() {
                (
                    load_dir::<MachineConfig>(cloud_dir.join("machines"))?,
                    load_mirrors(cloud_dir.join("mirrors"))?,
                    load_workloads(cloud_dir.join("workloads"))?,
                    load_topology(cloud_dir.join("topology.toml"))?,
                    load_dir::<LegacyServiceConfig>(cloud_dir.join("services"))?,
                )
            } else {
                Default::default()
            };

        // Machines come from `.yah/infra/machines/` (R215+); the pre-R215
        // tree shouldn't have any since B1 moved them, but if it does we
        // dedupe by name (R215 wins).
        let mut machines = load_dir::<MachineConfig>(crate::paths::machines_dir(workspace_root))?;
        let names: std::collections::HashSet<String> =
            machines.iter().map(|m| m.name.clone()).collect();
        for m in legacy_machines {
            if !names.contains(&m.name) {
                machines.push(m);
            }
        }

        Ok(Self {
            workspace_root: workspace_root.to_path_buf(),
            machines,
            providers,
            services,
            domains,
            legacy_mirrors,
            workloads,
            topology,
            legacy_services,
        })
    }

    /// Look up a domain manifest by name (file stem under `.yah/domains/`).
    pub fn domain(&self, name: &str) -> Option<&DomainConfig> {
        self.domains.get(name)
    }

    pub fn machine(&self, name: &str) -> Option<&MachineConfig> {
        self.machines.iter().find(|m| m.name == name)
    }

    /// Look up a provider by id (matches `provider.id`, not the file stem).
    pub fn provider(&self, id: &str) -> Option<&ProviderConfig> {
        self.providers.iter().find(|p| p.id == id)
    }

    /// Look up a service by name (matches `service.toml`'s `name` field).
    pub fn service(&self, name: &str) -> Option<&ServiceWithMirrors> {
        self.services.get(name)
    }

    /// Look up a legacy mirror by camp name (pre-R215 .yah/cloud/mirrors/).
    pub fn legacy_mirror(&self, camp: &str) -> Option<&LegacyMirrorConfig> {
        self.legacy_mirrors.iter().find(|m| m.camp == camp)
    }

    pub fn workload(&self, name: &str) -> Option<&WorkloadConfig> {
        self.workloads.iter().find(|w| w.spec.name == name)
    }

    /// F16 placement v1: the first machine satisfying every hard axis of `req`
    /// (region/zone/provider membership + mesh_tags superset). Declaration order
    /// in `.yah/infra/machines/` decides ties — deterministic-greedy, no
    /// backtracking. A fully-unconstrained `req` matches the first machine.
    ///
    /// Fails loud with the constraint summary and the candidate machine names
    /// when nothing matches, so `yah cloud apply` surfaces *why* placement
    /// failed instead of a silent empty set.
    pub fn resolve_machine(&self, req: &RequiredSpec) -> Result<&MachineConfig> {
        self.machines
            .iter()
            .find(|m| req.matches(m))
            .ok_or_else(|| {
                let candidates = if self.machines.is_empty() {
                    "(no machines declared under .yah/infra/machines/)".to_string()
                } else {
                    self.machines
                        .iter()
                        .map(|m| m.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                anyhow::anyhow!(
                    "no candidates matching {} — declared machines: {candidates}",
                    req.describe()
                )
            })
    }

    /// F16 placement: first machine whose `mesh_tags` is a superset of
    /// `required`. Declaration order in `.yah/infra/machines/` decides ties.
    /// Empty `required` matches the first machine; callers should treat
    /// empty-required as "no constraint" and skip this lookup.
    ///
    /// Back-compat thin wrapper over [`CloudConfig::resolve_machine`] for the
    /// mesh-tags-only call sites that predate the topology axes.
    pub fn resolve_machine_by_mesh_tags(&self, required: &[String]) -> Option<&MachineConfig> {
        let req = RequiredSpec {
            mesh_tags: required.to_vec(),
            ..Default::default()
        };
        self.resolve_machine(&req).ok()
    }
}

/// Load every `.yah/infra/providers/*.toml` into a [`ProviderConfig`] list.
/// Missing directory → empty list.
fn load_providers(dir: &Path) -> Result<Vec<ProviderConfig>> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut items = vec![];
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "toml"))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        items.push(ProviderConfig::load(&entry.path())?);
    }
    Ok(items)
}

/// Map legacy mirror file stems to their canonical tier names.
///
/// Canonical tiers: `dev` / `pond` / `cloud` / `ha`.
/// Legacy stems pre-R362: `local` (dev tier), `local-sim` / `sim` (pond tier), `prod` (cloud tier).
/// Both forms are accepted; canonical names are preferred for new files.
pub fn canonical_tier(stem: &str) -> &str {
    match stem {
        "local" => "dev",
        "local-sim" | "sim" => "pond",
        "prod" => "cloud",
        other => other,
    }
}

/// Walk `.yah/services/<svc>/` for every service and its mirrors.
/// Missing directory → empty map. Mirror file stems are normalized to canonical
/// tier names via [`canonical_tier`] so callers always see `dev/pond/cloud/ha`.
fn load_services(
    dir: &Path,
    workspace_root: &Path,
) -> Result<BTreeMap<String, ServiceWithMirrors>> {
    if !dir.exists() {
        return Ok(BTreeMap::new());
    }
    let mut out = BTreeMap::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let svc_dir = entry.path();
        let service_toml = svc_dir.join("service.toml");
        if !service_toml.exists() {
            // Skip directories without a service.toml — leaves room for
            // future siblings (e.g. `secrets/`, `README.md`) without
            // triggering false-positive parse errors.
            continue;
        }
        let service = ServiceConfig::load(&service_toml)?;
        let mut mirrors = BTreeMap::new();
        let mirrors_dir = svc_dir.join("mirrors");
        if mirrors_dir.exists() {
            let mut menv: Vec<_> = std::fs::read_dir(&mirrors_dir)
                .with_context(|| format!("reading {}", mirrors_dir.display()))?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |x| x == "toml"))
                .collect();
            menv.sort_by_key(|e| e.file_name());
            for m in menv {
                let path = m.path();
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                let tier = canonical_tier(&stem).to_string();
                // Last-write wins if both legacy and canonical forms coexist
                // (e.g. local-sim.toml + pond.toml). Sort order ensures the
                // canonical file (pond.toml) wins because 'p' > 'l'.
                mirrors.insert(tier, MirrorConfig::load(&path)?);
            }
        }
        let mut component_transform_recipes = BTreeMap::new();
        for component in &service.components {
            if component.kind == "static-asset" {
                if let Some(recipe) =
                    read_component_transform_recipe(workspace_root, &component.path)
                {
                    component_transform_recipes.insert(component.id.clone(), recipe);
                }
            }
        }
        out.insert(
            service.name.clone(),
            ServiceWithMirrors {
                service,
                mirrors,
                component_transform_recipes,
            },
        );
    }
    Ok(out)
}

/// Read the first transform recipe name from a component's `workload.toml`.
/// Returns `None` when the file is absent or has no `[asset.derive.transform]`
/// section. Best-effort — parse failures are silently ignored so a malformed
/// workload.toml doesn't abort the entire service catalog load.
fn read_component_transform_recipe(workspace_root: &Path, component_path: &str) -> Option<String> {
    let workload_path = workspace_root.join(component_path).join("workload.toml");
    let text = std::fs::read_to_string(&workload_path).ok()?;
    let value: toml::Value = toml::from_str(&text).ok()?;
    let assets = value.get("asset")?.as_array()?;
    for asset in assets {
        if let Some(recipe) = asset
            .get("derive")
            .and_then(|d| d.get("transform"))
            .and_then(|t| t.get("recipe"))
            .and_then(|r| r.as_str())
        {
            return Some(recipe.to_string());
        }
    }
    None
}

/// Load every `.yah/domains/*.toml` into a [`DomainConfig`] map keyed by
/// file stem. Missing directory → empty map.
fn load_domains(dir: &Path) -> Result<BTreeMap<String, DomainConfig>> {
    if !dir.exists() {
        return Ok(BTreeMap::new());
    }
    let mut out = BTreeMap::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "toml"))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let dom = DomainConfig::load(&path)?;
        if dom.name != stem {
            anyhow::bail!(
                "domains/{}.toml: name = \"{}\" must match the file stem",
                stem,
                dom.name
            );
        }
        out.insert(dom.name.clone(), dom);
    }
    Ok(out)
}

/// Load and shape-validate all `*.toml` files in `dir` as [`WorkloadConfig`].
fn load_workloads(dir: std::path::PathBuf) -> Result<Vec<WorkloadConfig>> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut items = vec![];
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "toml"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let path_str = path.display().to_string();
        let src =
            std::fs::read_to_string(&path).with_context(|| format!("reading {}", path_str))?;
        let spec: WorkloadSpec =
            toml::from_str(&src).with_context(|| format!("parsing {}", path_str))?;

        // Shape-validate before accepting into the loaded config.
        validate::shape(&spec)
            .map_err(|e| anyhow::anyhow!("workload {} failed shape validation: {e}", path_str))?;

        items.push(WorkloadConfig { spec });
    }
    Ok(items)
}

/// Load all mirror configs from the `mirrors/` directory.
///
/// Handles two layouts that may coexist:
/// - **Folder**: `mirrors/<id>/mirror.toml` — preferred; allows secrets and
///   per-mirror overrides to live next to the config file.
/// - **Flat**: `mirrors/<id>.toml` — legacy; still supported.
///
/// Each file is parsed as [`LegacyMirrorConfig`]. A malformed file returns an error
/// that includes the file path and the TOML field path + line/column, so the
/// caller can surface it to the user directly.
fn load_mirrors(dir: std::path::PathBuf) -> Result<Vec<LegacyMirrorConfig>> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut mirrors = vec![];
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            // Folder layout: mirrors/<id>/mirror.toml
            let mirror_toml = path.join("mirror.toml");
            if mirror_toml.exists() {
                let src = std::fs::read_to_string(&mirror_toml)
                    .with_context(|| format!("reading {}", mirror_toml.display()))?;
                let cfg: LegacyMirrorConfig = toml::from_str(&src)
                    .with_context(|| format!("parsing {}", mirror_toml.display()))?;
                mirrors.push(cfg);
            }
        } else if path.extension().map_or(false, |e| e == "toml") {
            // Flat layout: mirrors/<id>.toml
            let src = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let cfg: LegacyMirrorConfig =
                toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
            mirrors.push(cfg);
        }
    }
    Ok(mirrors)
}

/// Load `topology.toml` if it exists; return a default (empty) topology otherwise.
fn load_topology(path: std::path::PathBuf) -> Result<TopologyConfig> {
    if !path.exists() {
        return Ok(TopologyConfig::default());
    }
    let src =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))
}

fn load_dir<T: for<'de> Deserialize<'de>>(dir: std::path::PathBuf) -> Result<Vec<T>> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut items = vec![];
    for entry in std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "toml") {
            let src = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let item: T =
                toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
            items.push(item);
        }
    }
    Ok(items)
}

// ─── New manifest shapes (R222 B2) ───────────────────────────────────────────
//
// The post-R215 layout splits substrate from service declarations:
//
//   .yah/infra/providers/<id>.toml      → ProviderConfig
//   .yah/services/<svc>/service.toml    → ServiceConfig
//   .yah/services/<svc>/mirrors/<env>.toml → MirrorConfig
//
// CloudConfig::load still reads the legacy layout — B3 swaps in these types
// and removes the Legacy* shapes plus TopologyConfig.

/// Tag for the infrastructure provider kind. Drives which fields are valid in
/// a [`ProviderConfig`] body or a [`MirrorProviderSlot::Inline`] block.
///
/// Two flavors:
/// - **Account/runtime providers** (`cloudflare`, `hetzner`, `local-container`)
///   live as files under `.yah/infra/providers/<id>.toml` and are referenced
///   from a mirror via `use = "<id>"`.
/// - **Inline-only providers** (`local-static`, `miniflare-container`,
///   `minio-container`) declare an operator-local stand-in directly inside a
///   mirror via `kind = "..."`. They carry no credentials and have no provider
///   file. The container-backed kinds ride on top of whichever
///   `local-container` runtime is declared in infra (orbstack/colima/docker);
///   the reconciler resolves the runtime at up-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// Cloudflare account: R2 buckets, DNS, Workers, Tunnels.
    Cloudflare,
    /// Hetzner Cloud + Object Storage account.
    Hetzner,
    /// Vultr cloud VPS — auto-provisioned via the `cloud.vps.*` Envoy
    /// (`VultrEnvoy`), the burst/scaling counterpart to Hetzner. Driver-backed.
    Vultr,
    /// BYO bare/static node (OVH, on-prem, anything we did NOT provision via a
    /// cloud API). Brought up over SSH (`stand-up-yubaba.sh` / `yah cloud
    /// machine bootstrap`); reach is declared in the machine's `[connect]`
    /// block. No create/destroy driver — placement-only.
    Static,
    /// Built-in static-file server bound to localhost. Inline-only; never
    /// declared as a standalone provider file because it carries no creds.
    LocalStatic,
    /// Local container runtime (orbstack/colima/docker). Configured by a
    /// provider file under `.yah/infra/providers/` so the discovery hints +
    /// runtime override sit in one place.
    LocalContainer,
    /// Containerized miniflare (workerd subprocess) fronting MinIO — the
    /// pond-tier stand-in for a CF Worker + R2 static surface. Inline-only;
    /// the reconciler spawns miniflare via the JS runtime and starts a MinIO
    /// container on the local-container runtime.
    MiniflareContainer,
    /// Containerized MinIO providing an S3-compatible API — the pond-tier
    /// stand-in for Cloudflare R2. Inline-only; the reconciler spins up the
    /// container on the local-container runtime and auto-creates the declared
    /// bucket on first up.
    MinioContainer,
}

/// A provider account/runtime binding from `.yah/infra/providers/<id>.toml`.
///
/// The `kind` discriminator picks the schema for the remaining fields. Strict
/// on `kind` (unknown values are a parse error); permissive on per-kind fields
/// (carried as a free-form map so this loader stays stable as new fields land).
/// B3/B4 will tighten by introducing typed variants alongside JSON Schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ProviderConfig {
    pub schema_version: u32,
    pub id: String,
    pub kind: Provider,
    /// Reference into the OS keystore for live credentials (e.g.
    /// `"keystore://cloudflare/yah"`). `None` for providers that don't need
    /// creds (local-static, optionally local-container).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
    /// Kind-specific fields. Examples:
    /// - cloudflare: `default_zone`
    /// - hetzner:    `default_location`, `default_server_type`, `ssh_keys`
    /// - local-container: `runtime`, `discovery`
    #[serde(flatten)]
    #[cfg_attr(
        feature = "json-schema",
        schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")
    )]
    pub fields: BTreeMap<String, toml::Value>,
}

impl ProviderConfig {
    /// Parse a single `providers/<id>.toml` file.
    pub fn load(path: &Path) -> Result<Self> {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))
    }
}

/// An operator-facing service declaration from
/// `.yah/services/<svc>/service.toml`.
///
/// A service groups one or more components (a static surface, a containerized
/// API, an almanac…) under a single domain. Mirrors project the service onto
/// concrete infra; see [`MirrorConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ServiceConfig {
    pub schema_version: u32,
    pub name: String,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<ServiceComponent>,
}

impl ServiceConfig {
    /// Parse a single `services/<svc>/service.toml` file.
    pub fn load(path: &Path) -> Result<Self> {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))
    }

    /// Persist to `.yah/services/<name>/service.toml`, creating the service
    /// directory if needed. Create-or-overwrite — the canonical replacement
    /// for the legacy `sites.json` write path. `workspace_root` is the camp
    /// dir (the parent of `.yah/`).
    pub fn save(&self, workspace_root: &Path) -> Result<()> {
        let dir = crate::paths::service_dir(workspace_root, &self.name);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = crate::paths::service_toml(workspace_root, &self.name);
        let s = toml::to_string_pretty(self)
            .with_context(|| format!("serializing service {}", self.name))?;
        std::fs::write(&path, s).with_context(|| format!("writing {}", path.display()))
    }

    /// Remove `.yah/services/<name>/` and everything under it (service.toml
    /// plus its `mirrors/`). Returns `false` when the directory was already
    /// absent, so callers can distinguish "deleted" from "no-op".
    pub fn delete(workspace_root: &Path, name: &str) -> Result<bool> {
        let dir = crate::paths::service_dir(workspace_root, name);
        if !dir.exists() {
            return Ok(false);
        }
        std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
        Ok(true)
    }
}

/// A git source for a component (R561-F1, "BYO git").
///
/// When a [`ServiceComponent`] sets `git`, the component's code is NOT in this
/// workspace — it lives in an external repo that the reconciler shallow-clones
/// into a source cache before build (approach A: clone-at-reconcile, so config
/// load + validation stay offline). The component's `path` is then interpreted
/// relative to `<checkout>/<subdir>` instead of the workspace root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct GitSource {
    /// Clone URL (https or ssh) of the tenant repo.
    pub repo: String,
    /// Branch, tag, or commit SHA to check out. Defaults to `"main"`.
    #[serde(default = "default_git_ref")]
    pub r#ref: String,
    /// Optional sub-directory within the repo that the workspace is rooted at
    /// (e.g. a monorepo's `site/`). `path` is resolved relative to this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdir: Option<String>,
}

fn default_git_ref() -> String {
    "main".to_string()
}

/// One component of a [`ServiceConfig`]. The `kind` (e.g. `"mesofact-static"`,
/// `"almanac"`, `"container"`) selects which reconciler runs against the
/// pointed-at workload manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ServiceComponent {
    pub id: String,
    pub kind: String,
    /// Path of the directory holding this component's `workload.toml`. Relative
    /// to the workspace root for in-tree components, or to the materialized
    /// `<checkout>/<subdir>` when [`git`](Self::git) is set.
    pub path: String,
    /// Optional external git source (R561-F1). When set, the component's code
    /// is materialized by shallow-clone before build; see [`GitSource`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitSource>,
    /// Operator-facing role label, e.g. `"static"`, `"dynamic"`, `"compute"`.
    pub role: String,
    /// Optional artifact kind this component publishes (`"static"`,
    /// `"container-image"`, …). Drives mirror provider-slot routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publishes: Option<String>,
    /// Sync-wave index (0-based). Components in wave 0 roll out in parallel
    /// first; the reconciler waits for all wave-N components to become healthy
    /// before starting wave N+1. Defaults to 0 (all components in one wave).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wave: u32,
}

#[inline]
fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

/// Topological shape of a mirror — how its providers sit relative to each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum MirrorShape {
    /// Single machine hosts compute (and any non-Cloudflare-fronted static).
    SingleMachine,
    /// Operator-local dev mirror — static via built-in file server, compute
    /// via the local container runtime.
    Local,
    /// Multi-machine deployment (machines listed per provider slot).
    MultiMachine,
}

/// A service mirror — the projection of a [`ServiceConfig`] onto concrete
/// infra. Lives at `.yah/services/<svc>/mirrors/<env>.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MirrorConfig {
    pub schema_version: u32,
    pub shape: MirrorShape,
    /// Provider slots, keyed by role (`"static"`, `"compute"`, …). Each value
    /// either references a provider declared under `.yah/infra/providers/` or
    /// inlines a local-only provider (no creds, no infra file).
    #[serde(default)]
    pub providers: BTreeMap<String, MirrorProviderSlot>,
    /// Per-environment alias overrides for `kind = "static-asset"` components.
    ///
    /// Keys are logical names (e.g. `"whisper-default"`); values must be
    /// filenames present in the component's `workload.toml` catalog.
    /// **Resolution only** — this table may never introduce a filename absent
    /// from the catalog. Validated against the workload catalog at sync time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub asset_aliases: BTreeMap<String, String>,
}

impl MirrorConfig {
    /// Parse a single `mirrors/<env>.toml` file.
    pub fn load(path: &Path) -> Result<Self> {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))
    }

    /// Persist to `.yah/services/<service>/mirrors/<env>.toml`, creating the
    /// `mirrors/` directory if needed. Create-or-overwrite. The mirror file is
    /// named by `env` (its stem); `service` selects the owning service dir.
    pub fn save(&self, workspace_root: &Path, service: &str, env: &str) -> Result<()> {
        let dir = crate::paths::service_mirrors_dir(workspace_root, service);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = crate::paths::service_mirror_toml(workspace_root, service, env);
        let s = toml::to_string_pretty(self)
            .with_context(|| format!("serializing mirror {service}/{env}"))?;
        std::fs::write(&path, s).with_context(|| format!("writing {}", path.display()))
    }

    /// Remove `.yah/services/<service>/mirrors/<env>.toml`. Returns `false`
    /// when the file was already absent. Leaves the service and its other
    /// mirrors untouched.
    ///
    /// Also checks legacy stems (e.g. `local-sim` when `env = "pond"`) so
    /// deleting a canonical tier name removes whichever file exists on disk.
    pub fn delete(workspace_root: &Path, service: &str, env: &str) -> Result<bool> {
        let path = crate::paths::service_mirror_toml(workspace_root, service, env);
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            return Ok(true);
        }
        // Try legacy file stems for canonical tier names.
        let legacy: &[&str] = match env {
            "dev" => &["local"],
            "pond" => &["local-sim", "sim"],
            "cloud" => &["prod"],
            _ => &[],
        };
        for stem in legacy {
            let alt = crate::paths::service_mirror_toml(workspace_root, service, stem);
            if alt.exists() {
                std::fs::remove_file(&alt)
                    .with_context(|| format!("removing {}", alt.display()))?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// A provider slot inside a [`MirrorConfig`]. Two shapes:
/// - **Reference** (`use = "<provider-id>"`) — point at an infra-declared
///   provider; extra fields are slot-specific (bucket, zone, dns, …).
/// - **Inline** (`kind = "local-*"`) — for providers that need no infra
///   declaration because they carry no credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum MirrorProviderSlot {
    Reference {
        #[serde(rename = "use")]
        provider_id: String,
        #[serde(flatten)]
        #[cfg_attr(
            feature = "json-schema",
            schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")
        )]
        fields: BTreeMap<String, toml::Value>,
    },
    Inline {
        kind: Provider,
        #[serde(flatten)]
        #[cfg_attr(
            feature = "json-schema",
            schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")
        )]
        fields: BTreeMap<String, toml::Value>,
    },
}

impl MirrorProviderSlot {
    /// Provider id this slot references, or `None` for inline slots.
    pub fn provider_id(&self) -> Option<&str> {
        match self {
            Self::Reference { provider_id, .. } => Some(provider_id),
            Self::Inline { .. } => None,
        }
    }

    /// Provider kind for inline slots, or `None` for reference slots
    /// (resolve via the referenced [`ProviderConfig`]).
    pub fn inline_kind(&self) -> Option<Provider> {
        match self {
            Self::Reference { .. } => None,
            Self::Inline { kind, .. } => Some(*kind),
        }
    }

    pub fn fields(&self) -> &BTreeMap<String, toml::Value> {
        match self {
            Self::Reference { fields, .. } | Self::Inline { fields, .. } => fields,
        }
    }

    /// F16 placement: parse the optional `required = { … }` sub-table on this
    /// slot. Returns `None` when absent or unparseable (callers treat as no
    /// constraint). See [`RequiredSpec`] for the field grammar.
    pub fn required(&self) -> Option<RequiredSpec> {
        let v = self.fields().get("required")?.clone();
        v.try_into().ok()
    }
}

/// F16 placement constraints declared on a [`MirrorProviderSlot`], lives under
/// `[providers.<role>] required = { regions = [...], mesh_tags = [...] }` in
/// `mirrors/<env>.toml`.
///
/// Four hard (must-satisfy) axes in v1, all AND-ed together:
/// - `regions` / `zones` / `providers` — *membership*: the machine's
///   `region` / `zone` / `provider` must be one of the listed values.
/// - `mesh_tags` — *superset*: the machine's `mesh_tags` must contain every
///   listed tag.
///
/// An empty list on any axis means "no constraint on that axis". A fully-empty
/// `RequiredSpec` matches every machine (see [`RequiredSpec::is_unconstrained`]).
///
/// Capacity floors (`cpu`/`memory`/`gpu`) and soft `preferred.*` /
/// `topology_spread` / `anti_affinity` are deliberately out of this v1 slice —
/// they need the yubaba↔kamaji capability-gossip view, not just the
/// workspace machine.toml. See R330-F16's next-steps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct RequiredSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mesh_tags: Vec<String>,
}

impl RequiredSpec {
    /// True when no axis carries a constraint — every machine matches.
    pub fn is_unconstrained(&self) -> bool {
        self.regions.is_empty()
            && self.zones.is_empty()
            && self.providers.is_empty()
            && self.mesh_tags.is_empty()
    }

    /// Whether `machine` satisfies every hard axis. Membership axes
    /// (region/zone/provider) require the machine to carry the field AND have
    /// it appear in the constraint list; the mesh_tags axis is a superset test.
    pub fn matches(&self, machine: &MachineConfig) -> bool {
        let member_ok = |constraint: &[String], value: Option<&str>| -> bool {
            constraint.is_empty() || value.map_or(false, |v| constraint.iter().any(|c| c == v))
        };
        member_ok(&self.regions, machine.region.as_deref())
            && member_ok(&self.zones, machine.zone.as_deref())
            && member_ok(&self.providers, Some(machine.provider.as_str()))
            && self
                .mesh_tags
                .iter()
                .all(|t| machine.mesh_tags.iter().any(|mt| mt == t))
    }

    /// Human-readable summary of the constraints, for fail-loud error messages.
    /// Example: `required.regions=[us-west] + required.mesh_tags=[tag:cloud-runner]`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        let mut push = |label: &str, vals: &[String]| {
            if !vals.is_empty() {
                parts.push(format!("required.{label}=[{}]", vals.join(",")));
            }
        };
        push("regions", &self.regions);
        push("zones", &self.zones);
        push("providers", &self.providers);
        push("mesh_tags", &self.mesh_tags);
        if parts.is_empty() {
            "no constraints".to_string()
        } else {
            parts.join(" + ")
        }
    }
}

/// A routing manifest for one domain, from `.yah/domains/<name>.toml`.
///
/// The domain manifest is the *only* place that knows about path routing:
/// services declare static/backend components by opaque ID, and this
/// manifest binds those components to URL paths on a public-facing
/// domain. Generated Worker bundles consume this. See
/// `.yah/docs/working/W118-yah-domain-tiers.md` (R347).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DomainConfig {
    pub schema_version: u32,
    /// Stable identifier for this domain (file stem of the manifest).
    /// Example: `"yah-dev"` for the `yah.dev` zone.
    pub name: String,
    /// The fully-qualified domain this manifest routes for. Example:
    /// `"yah.dev"`, `"app.yah.dev"`.
    pub domain: String,
    /// Public CDN bucket name. Static-mode route components publish into
    /// this bucket. Owned by the domain, *not* by any single service.
    pub cdn_bucket: String,
    /// Optional path (relative to workspace root) where the generated
    /// Worker bundle lands. `None` while the bundle generator (R347-F4)
    /// is still being wired up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_bundle_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<DomainRoute>,
}

/// One entry in a [`DomainConfig`]'s route table.
///
/// The `mode` discriminator picks the variant's body via serde's
/// internally-tagged enum representation. Path patterns follow the
/// Worker convention: a trailing `*` matches everything underneath.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DomainRoute {
    /// URL pattern this route matches. Examples: `"/"`, `"/dashboard/*"`,
    /// `"/camp/ws"`.
    pub path: String,
    #[serde(flatten)]
    pub mode: RouteMode,
}

/// Body of a [`DomainRoute`]. Three modes:
/// - **Static** — Worker reads from the domain's CDN bucket. Component
///   ref points at a `kind = "mesofact-static"` (or similar) service
///   component.
/// - **Backend** — Worker proxies to an HTTP origin owned by a backend
///   component (yubaba workload, gateway, etc.).
/// - **Redirect** — Worker emits a 30x to the target URL. Used to keep
///   old paths alive during domain refactors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum RouteMode {
    Static {
        /// Component reference `"<service>/<component-id>"`. Validated
        /// at [`CloudConfig::load`] time.
        component: String,
    },
    Backend {
        /// Component reference `"<service>/<component-id>"`. Validated
        /// at [`CloudConfig::load`] time.
        component: String,
        /// Origin URL the Worker `fetch()`es. Schema-permissive — could
        /// be `https://...`, `wss://...`, or a yah-internal mesh URL
        /// resolved by yubaba.
        origin: String,
    },
    Redirect {
        /// Absolute URL or path the Worker emits a 30x to.
        target: String,
        /// HTTP status code. Defaults to 308 (permanent + method-preserving)
        /// so deprecations don't silently turn POSTs into GETs.
        #[serde(default = "default_redirect_status")]
        status: u16,
    },
}

fn default_redirect_status() -> u16 {
    308
}

impl DomainConfig {
    /// Parse a single `.yah/domains/<name>.toml`.
    pub fn load(path: &Path) -> Result<Self> {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))
    }

    /// Persist to `.yah/domains/<name>.toml`, creating the domains
    /// directory if needed. Create-or-overwrite.
    pub fn save(&self, workspace_root: &Path) -> Result<()> {
        let dir = crate::paths::domains_dir(workspace_root);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = crate::paths::domain_toml(workspace_root, &self.name);
        let s = toml::to_string_pretty(self)
            .with_context(|| format!("serializing domain {}", self.name))?;
        std::fs::write(&path, s).with_context(|| format!("writing {}", path.display()))
    }

    /// Remove `.yah/domains/<name>.toml`. Returns `false` when the file
    /// was already absent.
    pub fn delete(workspace_root: &Path, name: &str) -> Result<bool> {
        let path = crate::paths::domain_toml(workspace_root, name);
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        Ok(true)
    }
}

impl RouteMode {
    /// Component reference for static/backend modes; `None` for redirects.
    pub fn component(&self) -> Option<&str> {
        match self {
            Self::Static { component } | Self::Backend { component, .. } => Some(component),
            Self::Redirect { .. } => None,
        }
    }
}

/// Split a `"<service>/<component-id>"` ref. Returns `None` if the ref
/// isn't shaped like `service/component`.
fn split_component_ref(s: &str) -> Option<(&str, &str)> {
    let (svc, comp) = s.split_once('/')?;
    if svc.is_empty() || comp.is_empty() || comp.contains('/') {
        return None;
    }
    Some((svc, comp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_machine(name: &str, mesh_tags: Vec<&str>) -> MachineConfig {
        MachineConfig {
            name: name.into(),
            provider: "hetzner".into(),
            location: Some("hil".into()),
            server_type: Some("ccx13".into()),
            hosts_mirrors: vec![],
            mesh_tags: mesh_tags.into_iter().map(String::from).collect(),
            region: None,
            zone: None,
            bucket: None,
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
        }
    }

    /// Like [`make_machine`] but with explicit topology axes for F16 tests.
    fn make_machine_topo(
        name: &str,
        provider: &str,
        region: &str,
        mesh_tags: Vec<&str>,
    ) -> MachineConfig {
        MachineConfig {
            provider: provider.into(),
            region: Some(region.into()),
            zone: Some(region.into()),
            ..make_machine(name, mesh_tags)
        }
    }

    fn make_empty_cfg(machines: Vec<MachineConfig>) -> CloudConfig {
        CloudConfig {
            workspace_root: PathBuf::new(),
            machines,
            providers: vec![],
            services: BTreeMap::new(),
            domains: BTreeMap::new(),
            legacy_mirrors: vec![],
            workloads: vec![],
            topology: TopologyConfig::default(),
            legacy_services: vec![],
        }
    }

    #[test]
    fn required_spec_parses_from_provider_fields() {
        let toml_src = r#"
use = "hetzner-primary"
[required]
mesh_tags = ["tag:cloud-runner"]
"#;
        let slot: MirrorProviderSlot = toml::from_str(toml_src).unwrap();
        let req = slot.required().expect("required block present");
        assert_eq!(req.mesh_tags, vec!["tag:cloud-runner"]);
    }

    #[test]
    fn required_spec_absent_when_field_missing() {
        let slot: MirrorProviderSlot = toml::from_str(r#"use = "hetzner-primary""#).unwrap();
        assert!(slot.required().is_none());
    }

    #[test]
    fn resolve_machine_by_mesh_tags_superset_match() {
        let cfg = make_empty_cfg(vec![
            make_machine("yah-bnt-1", vec!["tag:primary-yah", "tag:tier-scratch"]),
            make_machine("us-west-001", vec!["tag:primary-yah", "tag:cloud-runner"]),
        ]);
        let picked = cfg
            .resolve_machine_by_mesh_tags(&["tag:cloud-runner".into()])
            .map(|m| m.name.as_str());
        assert_eq!(picked, Some("us-west-001"));
    }

    #[test]
    fn resolve_machine_by_mesh_tags_returns_none_when_no_match() {
        let cfg = make_empty_cfg(vec![make_machine("yah-bnt-1", vec!["tag:primary-yah"])]);
        assert!(cfg
            .resolve_machine_by_mesh_tags(&["tag:cloud-runner".into()])
            .is_none());
    }

    // ─── F16 topology-aware resolver ────────────────────────────────────────

    fn two_region_fleet() -> CloudConfig {
        make_empty_cfg(vec![
            make_machine_topo(
                "us-west-001",
                "hetzner",
                "us-west",
                vec!["tag:cloud-runner"],
            ),
            make_machine_topo(
                "eu-west-001",
                "hetzner",
                "eu-west",
                vec!["tag:cloud-runner"],
            ),
        ])
    }

    #[test]
    fn resolve_machine_matches_on_region_plus_mesh_tags() {
        let cfg = two_region_fleet();
        let req = RequiredSpec {
            regions: vec!["us-west".into()],
            mesh_tags: vec!["tag:cloud-runner".into()],
            ..Default::default()
        };
        let picked = cfg.resolve_machine(&req).unwrap();
        assert_eq!(picked.name, "us-west-001");
    }

    #[test]
    fn resolve_machine_region_disambiguates_same_tag() {
        // Both boxes carry tag:cloud-runner; the region axis selects eu-west.
        let cfg = two_region_fleet();
        let req = RequiredSpec {
            regions: vec!["eu-west".into()],
            mesh_tags: vec!["tag:cloud-runner".into()],
            ..Default::default()
        };
        assert_eq!(cfg.resolve_machine(&req).unwrap().name, "eu-west-001");
    }

    #[test]
    fn resolve_machine_fails_loud_with_constraint_summary() {
        let cfg = two_region_fleet();
        let req = RequiredSpec {
            regions: vec!["us-central".into()],
            mesh_tags: vec!["tag:cloud-runner".into()],
            ..Default::default()
        };
        let err = cfg.resolve_machine(&req).unwrap_err().to_string();
        assert!(err.contains("required.regions=[us-central]"), "got: {err}");
        assert!(
            err.contains("required.mesh_tags=[tag:cloud-runner]"),
            "got: {err}"
        );
        // Names the candidates it rejected.
        assert!(err.contains("us-west-001"), "got: {err}");
    }

    #[test]
    fn resolve_machine_provider_axis_filters() {
        let cfg = make_empty_cfg(vec![
            make_machine_topo("aws-west-1", "aws", "us-west", vec!["tag:cloud-runner"]),
            make_machine_topo("hz-west-1", "hetzner", "us-west", vec!["tag:cloud-runner"]),
        ]);
        let req = RequiredSpec {
            regions: vec!["us-west".into()],
            providers: vec!["hetzner".into()],
            ..Default::default()
        };
        assert_eq!(cfg.resolve_machine(&req).unwrap().name, "hz-west-1");
    }

    #[test]
    fn unconstrained_required_spec_matches_first_machine() {
        let cfg = two_region_fleet();
        assert!(RequiredSpec::default().is_unconstrained());
        assert_eq!(
            cfg.resolve_machine(&RequiredSpec::default()).unwrap().name,
            "us-west-001"
        );
    }

    #[test]
    fn required_spec_parses_topology_axes_from_toml() {
        let toml_src = r#"
use = "hetzner-primary"
[required]
regions = ["us-west"]
mesh_tags = ["tag:cloud-runner"]
"#;
        let slot: MirrorProviderSlot = toml::from_str(toml_src).unwrap();
        let req = slot.required().expect("required block present");
        assert_eq!(req.regions, vec!["us-west"]);
        assert_eq!(req.mesh_tags, vec!["tag:cloud-runner"]);
        assert!(req.zones.is_empty());
    }

    #[test]
    fn round_trip_machine() {
        let cfg = MachineConfig {
            name: "test-pdx-1".into(),
            provider: "hetzner".into(),
            location: Some("pdx".into()),
            server_type: Some("cpx22".into()),
            hosts_mirrors: vec!["noisetable".into()],
            mesh_tags: vec!["region:pdx".into()],
            region: Some("us-west".into()),
            zone: Some("pdx".into()),
            bucket: Some(BucketSpec {
                name: "test-assets-pdx-1".into(),
                public_read: false,
            }),
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
        };
        let s = toml::to_string(&cfg).unwrap();
        let back: MachineConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.name, cfg.name);
        assert_eq!(back.location, cfg.location);
        assert_eq!(back.region.as_deref(), Some("us-west"));
        assert_eq!(back.zone.as_deref(), Some("pdx"));
    }

    #[test]
    fn round_trip_mirror() {
        let cfg = LegacyMirrorConfig {
            camp: "noisetable".into(),
            regions: vec!["pdx".into(), "iad".into()],
            workloads: vec!["asset-registry".into()],
            cloud_domain: None,
        };
        let s = toml::to_string(&cfg).unwrap();
        let back: LegacyMirrorConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.camp, cfg.camp);
        assert_eq!(back.regions, cfg.regions);
        assert_eq!(back.workloads, cfg.workloads);
    }

    #[test]
    fn mirror_serialises_as_camp_key() {
        // Serialised form should use `camp`, not `rig`.
        let cfg = LegacyMirrorConfig {
            camp: "noisetable".into(),
            regions: vec!["pdx".into()],
            workloads: vec![],
            cloud_domain: None,
        };
        let s = toml::to_string(&cfg).unwrap();
        assert!(
            s.contains("camp = "),
            "serialised key should be 'camp': {s}"
        );
        assert!(!s.contains("rig = "), "old key should not appear: {s}");
    }

    #[test]
    fn mirror_rig_alias_still_loads() {
        // Old mirrors/*.toml files use `rig = "..."` before the R137 rename;
        // the alias keeps them loading until the one-time `sed` migration runs.
        let toml_str =
            "rig = \"noisetable\"\nregions = [\"pdx\"]\nworkloads = [\"asset-registry\"]\n";
        let cfg: LegacyMirrorConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.camp, "noisetable");
    }

    #[test]
    fn mirror_services_alias_still_loads() {
        // Old mirrors/*.toml files use `services = [...]`; the alias keeps them
        // loading without a migration step.
        let toml_str =
            "camp = \"noisetable\"\nregions = [\"pdx\"]\nservices = [\"asset-registry\"]\n";
        let cfg: LegacyMirrorConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.workloads, vec!["asset-registry"]);
    }

    #[test]
    fn round_trip_service_legacy() {
        let cfg = LegacyServiceConfig {
            name: "asset-registry".into(),
            image: "ghcr.io/noisetable/asset-registry".into(),
            version: "v1.0.0".into(),
            env: HashMap::new(),
            ports: vec![PortMapping {
                host: 8080,
                container: 8080,
            }],
            mesh_only: false,
            bind_interface: None,
        };
        let s = toml::to_string(&cfg).unwrap();
        let back: LegacyServiceConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.name, cfg.name);
        assert_eq!(back.image, cfg.image);
    }

    #[test]
    fn service_bind_interface_round_trips() {
        let cfg = LegacyServiceConfig {
            name: "postgres".into(),
            image: "postgres".into(),
            version: "16".into(),
            env: HashMap::new(),
            ports: vec![PortMapping {
                host: 5432,
                container: 5432,
            }],
            mesh_only: true,
            bind_interface: Some("tailscale0".into()),
        };
        let s = toml::to_string(&cfg).unwrap();
        let back: LegacyServiceConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.bind_interface.as_deref(), Some("tailscale0"));
    }

    #[test]
    fn service_bind_interface_absent_is_none() {
        let toml_str = "name = \"app\"\nimage = \"app\"\nversion = \"v1\"\n";
        let cfg: LegacyServiceConfig = toml::from_str(toml_str).unwrap();
        assert!(
            cfg.bind_interface.is_none(),
            "bind_interface should default to None"
        );
    }

    #[test]
    fn service_bind_interface_skipped_when_none() {
        let cfg = LegacyServiceConfig {
            name: "app".into(),
            image: "app".into(),
            version: "v1".into(),
            env: HashMap::new(),
            ports: vec![],
            mesh_only: false,
            bind_interface: None,
        };
        let s = toml::to_string(&cfg).unwrap();
        assert!(!s.contains("bind_interface"), "None should be skipped: {s}");
    }

    #[test]
    fn load_dir_missing_is_empty() {
        let dir = std::path::PathBuf::from("/nonexistent/path");
        let result: Vec<MachineConfig> = load_dir(dir).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn topology_round_trip() {
        let topo = TopologyConfig {
            assignments: vec![
                MirrorAssignment {
                    mirror: "noisetable-pdx".into(),
                    machine: "noisetable-pdx-1".into(),
                },
                MirrorAssignment {
                    mirror: "noisetable-iad".into(),
                    machine: "noisetable-iad-1".into(),
                },
            ],
            buckets: vec![],
        };
        let s = toml::to_string(&topo).unwrap();
        let back: TopologyConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.assignments.len(), 2);
        assert_eq!(back.assignments[0].mirror, "noisetable-pdx");
        assert_eq!(back.assignments[1].machine, "noisetable-iad-1");
    }

    #[test]
    fn topology_absent_returns_default() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("topology.toml");
        // file doesn't exist
        let topo = load_topology(path).unwrap();
        assert!(topo.assignments.is_empty());
    }

    /// Helper: lay out a `<workspace_root>/.yah/cloud/` legacy tree for the
    /// pre-R215 cargo tests below; returns the legacy cloud_dir for writes.
    fn make_legacy_cloud_dir(root: &std::path::Path) -> std::path::PathBuf {
        let cloud_dir = root.join(".yah").join("cloud");
        std::fs::create_dir_all(&cloud_dir).unwrap();
        cloud_dir
    }

    #[test]
    fn cloud_config_load_and_lookup() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let cloud_dir = make_legacy_cloud_dir(root);

        let machine = MachineConfig {
            name: "noisetable-pdx-1".into(),
            provider: "hetzner".into(),
            location: Some("pdx".into()),
            server_type: Some("cpx22".into()),
            hosts_mirrors: vec!["noisetable".into(), "yah".into()],
            mesh_tags: vec!["region:pdx".into(), "tier:t2".into()],
            region: None,
            zone: None,
            bucket: Some(BucketSpec {
                name: "noisetable-assets-pdx-1".into(),
                public_read: false,
            }),
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
        };
        // Land in the legacy tree so the legacy machine loader picks it up.
        machine.save(&cloud_dir).unwrap();

        let mirror_toml = "camp = \"noisetable\"\nregions = [\"pdx\", \"iad\", \"fsn\"]\nworkloads = [\"asset-registry\"]\n";
        std::fs::create_dir_all(cloud_dir.join("mirrors")).unwrap();
        std::fs::write(cloud_dir.join("mirrors/noisetable.toml"), mirror_toml).unwrap();

        // Legacy services/ dir (backward compat)
        let svc_toml = "name = \"asset-registry\"\nimage = \"ghcr.io/noisetable/asset-registry\"\nversion = \"v1.0.0\"\nmesh_only = false\n";
        std::fs::create_dir_all(cloud_dir.join("services")).unwrap();
        std::fs::write(cloud_dir.join("services/asset-registry.toml"), svc_toml).unwrap();

        let cfg = CloudConfig::load(root).unwrap();

        assert_eq!(cfg.machines.len(), 1);
        assert_eq!(cfg.legacy_mirrors.len(), 1);
        assert_eq!(cfg.legacy_services.len(), 1);
        assert_eq!(cfg.workloads.len(), 0); // no workloads/ dir yet
        assert!(cfg.services.is_empty(), "no R215+ services/ tree");
        assert!(cfg.providers.is_empty(), "no R215+ providers/ tree");

        let m = cfg.machine("noisetable-pdx-1").unwrap();
        assert_eq!(m.location(), "pdx");
        assert_eq!(m.bucket.as_ref().unwrap().name, "noisetable-assets-pdx-1");

        let mir = cfg.legacy_mirror("noisetable").unwrap();
        assert_eq!(mir.regions, vec!["pdx", "iad", "fsn"]);
        assert_eq!(mir.workloads, vec!["asset-registry"]);
    }

    #[test]
    fn mirror_folder_layout_loads() {
        // Folder layout: mirrors/<id>/mirror.toml — new preferred form.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let cloud_dir = make_legacy_cloud_dir(root);
        let mirror_dir = cloud_dir.join("mirrors").join("yah-com");
        std::fs::create_dir_all(&mirror_dir).unwrap();
        std::fs::write(
            mirror_dir.join("mirror.toml"),
            "camp = \"yah\"\nregions = [\"pdx\"]\nworkloads = [\"yah-web\"]\n",
        )
        .unwrap();

        let cfg = CloudConfig::load(root).unwrap();
        assert_eq!(cfg.legacy_mirrors.len(), 1);
        let mir = cfg.legacy_mirror("yah").unwrap();
        assert_eq!(mir.camp, "yah");
        assert_eq!(mir.workloads, vec!["yah-web"]);
    }

    #[test]
    fn mirror_folder_and_flat_coexist() {
        // Both layouts may coexist in the same mirrors/ directory.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let cloud_dir = make_legacy_cloud_dir(root);
        let mirrors_root = cloud_dir.join("mirrors");
        std::fs::create_dir_all(&mirrors_root).unwrap();

        // Flat legacy mirror
        std::fs::write(
            mirrors_root.join("noisetable.toml"),
            "camp = \"noisetable\"\nregions = [\"pdx\"]\nworkloads = []\n",
        )
        .unwrap();

        // Folder-form mirror
        let yah_com_dir = mirrors_root.join("yah-com");
        std::fs::create_dir_all(&yah_com_dir).unwrap();
        std::fs::write(
            yah_com_dir.join("mirror.toml"),
            "camp = \"yah\"\nregions = [\"pdx\"]\nworkloads = []\n",
        )
        .unwrap();

        let cfg = CloudConfig::load(root).unwrap();
        assert_eq!(cfg.legacy_mirrors.len(), 2);
        assert!(cfg.legacy_mirror("noisetable").is_some());
        assert!(cfg.legacy_mirror("yah").is_some());
    }

    #[test]
    fn mirror_malformed_fails_with_field_path() {
        // A malformed mirror.toml should fail at load with a clear error
        // that includes the file path.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let cloud_dir = make_legacy_cloud_dir(root);
        let mirror_dir = cloud_dir.join("mirrors").join("bad");
        std::fs::create_dir_all(&mirror_dir).unwrap();
        // Missing required `camp` field
        std::fs::write(
            mirror_dir.join("mirror.toml"),
            "regions = [\"pdx\"]\nworkloads = []\n",
        )
        .unwrap();

        let err = CloudConfig::load(root).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mirror.toml"),
            "error should reference the file path, got: {msg}"
        );
    }

    #[test]
    fn workload_config_load_and_validate() {
        use workload_spec::{
            ExposeSpec, ImageRef, MeshExpose, MeshIdent, ResourceLimits, RestartPolicy,
            SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
        };

        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let cloud_dir = make_legacy_cloud_dir(root);
        std::fs::create_dir_all(cloud_dir.join("workloads")).unwrap();

        let spec = WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: "asset-registry".into(),
            image: ImageRef {
                registry: "ghcr.io".into(),
                repository: "noisetable/asset-registry".into(),
                tag: "v1.0.0".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("tenant".into()),
            replicas: 1,
            command: None,
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 256,
                cpu_shares: 512,
                ephemeral_storage_mb: 512,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: workload_spec::Millis::from_secs(10),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent("asset-registry.pdx".into()),
                    ports: vec![8080],
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        };

        let toml_str = toml::to_string_pretty(&spec).unwrap();
        std::fs::write(cloud_dir.join("workloads/asset-registry.toml"), &toml_str).unwrap();

        let cfg = CloudConfig::load(root).unwrap();
        assert_eq!(cfg.workloads.len(), 1);
        assert_eq!(cfg.workloads[0].spec.name, "asset-registry");
        assert_eq!(cfg.workload("asset-registry").unwrap().spec.replicas, 1);
    }

    #[test]
    fn workload_loader_rejects_bad_spec() {
        use workload_spec::{
            ExposeSpec, ImageRef, MeshExpose, MeshIdent, ResourceLimits, RestartPolicy,
            SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
        };

        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let cloud_dir = make_legacy_cloud_dir(root);
        std::fs::create_dir_all(cloud_dir.join("workloads")).unwrap();

        // Construct a spec that round-trips through TOML but fails shape
        // validation: replicas = 200 is above the max of 100.
        let mut spec = WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: "asset-registry".into(),
            image: ImageRef {
                registry: "ghcr.io".into(),
                repository: "test/app".into(),
                tag: "v1".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("tenant".into()),
            replicas: 200, // ← invalid: exceeds max 100
            command: None,
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 256,
                cpu_shares: 512,
                ephemeral_storage_mb: 512,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: workload_spec::Millis::from_secs(10),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent("asset-registry.pdx".into()),
                    ports: vec![8080],
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        };

        let toml_str = toml::to_string_pretty(&spec).unwrap();
        std::fs::write(cloud_dir.join("workloads/bad.toml"), &toml_str).unwrap();

        let result = CloudConfig::load(root);
        assert!(
            result.is_err(),
            "loading a WorkloadSpec with replicas=200 should return Err"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("shape validation")
                || msg.contains("Replicas")
                || msg.contains("replicas"),
            "error should mention shape validation or replicas field, got: {msg}"
        );

        // The `spec` binding is only used for the write — suppress warning.
        let _ = &mut spec;
    }

    #[test]
    fn workload_config_save_round_trip() {
        use workload_spec::{
            ExposeSpec, ImageRef, MeshExpose, MeshIdent, ResourceLimits, RestartPolicy,
            SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
        };

        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        let spec = WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: "signing-service".into(),
            image: ImageRef {
                registry: "ghcr.io".into(),
                repository: "noisetable/signing".into(),
                tag: "v2.0.0".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("private".into()),
            replicas: 2,
            command: None,
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 128,
                cpu_shares: 256,
                ephemeral_storage_mb: 256,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: workload_spec::Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent("signing.pdx".into()),
                    ports: vec![9090],
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        };

        let wc = WorkloadConfig { spec };
        let cloud_dir = make_legacy_cloud_dir(root);
        wc.save(&cloud_dir).unwrap();

        let loaded = CloudConfig::load(root).unwrap();
        assert_eq!(loaded.workloads.len(), 1);
        assert_eq!(loaded.workloads[0].spec.name, "signing-service");
        assert_eq!(loaded.workloads[0].spec.replicas, 2);
    }

    #[test]
    fn machine_save_write_back_fingerprint() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        let mut machine = MachineConfig {
            name: "test-pdx-1".into(),
            provider: "hetzner".into(),
            location: Some("pdx".into()),
            server_type: Some("cpx22".into()),
            hosts_mirrors: vec![],
            mesh_tags: vec![],
            region: None,
            zone: None,
            bucket: None,
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
        };
        machine.save(root).unwrap();

        // Simulate A4: write back the hostkey fingerprint after provision.
        machine.hostkey_fingerprint = Some("SHA256:abc123".into());
        machine.save(root).unwrap();

        let reloaded: Vec<MachineConfig> = load_dir(root.join("machines")).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert_eq!(
            reloaded[0].hostkey_fingerprint.as_deref(),
            Some("SHA256:abc123")
        );
    }

    // ─── New-shape (R222 B2) parse tests ────────────────────────────────────
    //
    // These mirror the Phase-A manifests committed under `.yah/services/` and
    // `.yah/infra/providers/`. Keeping the test strings inline (rather than
    // reading the on-disk files) so the loader stays runnable in any workdir
    // and so accidental edits to the on-disk files don't silently change
    // schema expectations.

    #[test]
    fn provider_cloudflare_round_trips() {
        let src = r#"
schema_version = 1
id = "cloudflare"
kind = "cloudflare"
credentials = "keystore://cloudflare/yah"
default_zone = "yah.dev"
"#;
        let cfg: ProviderConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.id, "cloudflare");
        assert_eq!(cfg.kind, Provider::Cloudflare);
        assert_eq!(
            cfg.credentials.as_deref(),
            Some("keystore://cloudflare/yah")
        );
        assert_eq!(
            cfg.fields.get("default_zone").and_then(|v| v.as_str()),
            Some("yah.dev"),
        );
        let back = toml::to_string(&cfg).unwrap();
        let again: ProviderConfig = toml::from_str(&back).unwrap();
        assert_eq!(again.id, cfg.id);
        assert_eq!(again.kind, cfg.kind);
    }

    #[test]
    fn provider_hetzner_round_trips() {
        let src = r#"
schema_version = 1
id = "hetzner"
kind = "hetzner"
credentials = "keystore://hetzner/yah"
default_location = "pdx"
default_server_type = "cpx11"
ssh_keys = []
"#;
        let cfg: ProviderConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.kind, Provider::Hetzner);
        assert_eq!(
            cfg.fields.get("default_location").and_then(|v| v.as_str()),
            Some("pdx"),
        );
        assert!(
            cfg.fields
                .get("ssh_keys")
                .map(|v| v.as_array().unwrap().is_empty())
                .unwrap_or(false),
            "ssh_keys must round-trip as empty array, got {:?}",
            cfg.fields.get("ssh_keys"),
        );
    }

    #[test]
    fn provider_orbstack_local_container_round_trips() {
        let src = r#"
schema_version = 1
id = "orbstack"
kind = "local-container"
runtime = "auto"

[discovery]
orbstack = "~/.orbstack/run/docker.sock"
colima   = "~/.colima/default/docker.sock"
docker   = "/var/run/docker.sock"
"#;
        let cfg: ProviderConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.kind, Provider::LocalContainer);
        assert_eq!(
            cfg.fields.get("runtime").and_then(|v| v.as_str()),
            Some("auto"),
        );
        let discovery = cfg
            .fields
            .get("discovery")
            .and_then(|v| v.as_table())
            .expect("discovery table");
        assert!(discovery.contains_key("orbstack"));
        assert!(discovery.contains_key("colima"));
        assert!(discovery.contains_key("docker"));
    }

    #[test]
    fn provider_unknown_kind_fails() {
        let src = r#"
schema_version = 1
id = "made-up"
kind = "fly-io"
"#;
        let err = toml::from_str::<ProviderConfig>(src).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("kind") || msg.contains("variant"),
            "unknown provider kind should surface as a serde error, got: {msg}"
        );
    }

    #[test]
    fn service_dev_yah_round_trips() {
        let src = r#"
schema_version = 1
name = "dev-yah"
domain = "yah.dev"

[[components]]
id = "site"
kind = "mesofact-static"
path = "app/yah/web"
role = "static"
"#;
        let cfg: ServiceConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.name, "dev-yah");
        assert_eq!(cfg.domain, "yah.dev");
        assert_eq!(cfg.components.len(), 1);
        let c = &cfg.components[0];
        assert_eq!(c.id, "site");
        assert_eq!(c.kind, "mesofact-static");
        assert_eq!(c.path, "app/yah/web");
        assert_eq!(c.role, "static");
        assert!(c.publishes.is_none());

        let back = toml::to_string(&cfg).unwrap();
        let again: ServiceConfig = toml::from_str(&back).unwrap();
        assert_eq!(again.name, cfg.name);
        assert_eq!(again.components[0].kind, c.kind);
    }

    #[test]
    fn mirror_prod_cloudflare_reference_parses() {
        let src = r#"
schema_version = 1
shape = "single-machine"

[providers.static]
use = "cloudflare"
bucket = "yah-dev"
zone = "yah.dev"
dns = { record = "@", type = "CNAME" }
"#;
        let cfg: MirrorConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.shape, MirrorShape::SingleMachine);
        let slot = cfg.providers.get("static").expect("static slot");
        assert_eq!(slot.provider_id(), Some("cloudflare"));
        assert!(slot.inline_kind().is_none());
        if let MirrorProviderSlot::Reference { fields, .. } = slot {
            assert_eq!(
                fields.get("bucket").and_then(|v| v.as_str()),
                Some("yah-dev")
            );
            assert_eq!(fields.get("zone").and_then(|v| v.as_str()), Some("yah.dev"));
            let dns = fields
                .get("dns")
                .and_then(|v| v.as_table())
                .expect("dns table");
            assert_eq!(dns.get("record").and_then(|v| v.as_str()), Some("@"));
            assert_eq!(dns.get("type").and_then(|v| v.as_str()), Some("CNAME"));
        } else {
            panic!("expected Reference slot");
        }
    }

    #[test]
    fn mirror_local_inline_static_and_orbstack_compute_parse() {
        let src = r#"
schema_version = 1
shape = "local"

[providers.static]
kind = "local-static"
port = 4321
artifact_dir = ".yah/infra/state/local/static"

[providers.compute]
use = "orbstack"
"#;
        let cfg: MirrorConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.shape, MirrorShape::Local);

        let static_slot = cfg.providers.get("static").expect("static slot");
        assert_eq!(static_slot.inline_kind(), Some(Provider::LocalStatic));
        assert!(static_slot.provider_id().is_none());
        if let MirrorProviderSlot::Inline { fields, .. } = static_slot {
            assert_eq!(fields.get("port").and_then(|v| v.as_integer()), Some(4321));
            assert_eq!(
                fields.get("artifact_dir").and_then(|v| v.as_str()),
                Some(".yah/infra/state/local/static"),
            );
        } else {
            panic!("expected Inline slot for static");
        }

        let compute_slot = cfg.providers.get("compute").expect("compute slot");
        assert_eq!(compute_slot.provider_id(), Some("orbstack"));
    }

    #[test]
    fn mirror_pond_miniflare_minio_parse() {
        // pond-tier mirror: miniflare-container + minio, both inline.
        // T1 just needs these inline kinds to parse — the reconciler dispatch
        // arrives in R256-T3.
        let src = r#"
schema_version = 1
shape = "local"

[providers.static]
kind = "miniflare-container"
port = 4322
bucket = "yah-dev"

[providers.object_store]
kind = "minio-container"
api_port = 9000
console_port = 9001
bucket = "yah-dev"
"#;
        let cfg: MirrorConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.shape, MirrorShape::Local);

        let static_slot = cfg.providers.get("static").expect("static slot");
        assert_eq!(
            static_slot.inline_kind(),
            Some(Provider::MiniflareContainer)
        );
        if let MirrorProviderSlot::Inline { fields, .. } = static_slot {
            assert_eq!(fields.get("port").and_then(|v| v.as_integer()), Some(4322));
            assert_eq!(
                fields.get("bucket").and_then(|v| v.as_str()),
                Some("yah-dev")
            );
        } else {
            panic!("expected Inline slot for miniflare-container static");
        }

        let object_store_slot = cfg
            .providers
            .get("object_store")
            .expect("object_store slot");
        assert_eq!(
            object_store_slot.inline_kind(),
            Some(Provider::MinioContainer)
        );
        if let MirrorProviderSlot::Inline { fields, .. } = object_store_slot {
            assert_eq!(
                fields.get("api_port").and_then(|v| v.as_integer()),
                Some(9000)
            );
            assert_eq!(
                fields.get("console_port").and_then(|v| v.as_integer()),
                Some(9001)
            );
            assert_eq!(
                fields.get("bucket").and_then(|v| v.as_str()),
                Some("yah-dev")
            );
        } else {
            panic!("expected Inline slot for minio-container object_store");
        }
    }

    #[test]
    fn provider_miniflare_container_kind_round_trips() {
        // Inline-only kind; never declared as a standalone provider file but
        // the enum round-trip is still exercised through ProviderConfig because
        // schemars/serde share the variant table.
        let cfg = MirrorProviderSlot::Inline {
            kind: Provider::MiniflareContainer,
            fields: BTreeMap::new(),
        };
        let s = toml::to_string(&cfg).unwrap();
        assert!(
            s.contains("kind = \"miniflare-container\""),
            "kebab-case wire form expected, got: {s}"
        );
        let back: MirrorProviderSlot = toml::from_str(&s).unwrap();
        assert_eq!(back.inline_kind(), Some(Provider::MiniflareContainer));
    }

    #[test]
    fn provider_minio_container_kind_round_trips() {
        let cfg = MirrorProviderSlot::Inline {
            kind: Provider::MinioContainer,
            fields: BTreeMap::new(),
        };
        let s = toml::to_string(&cfg).unwrap();
        assert!(
            s.contains("kind = \"minio-container\""),
            "kebab-case wire form expected, got: {s}"
        );
        let back: MirrorProviderSlot = toml::from_str(&s).unwrap();
        assert_eq!(back.inline_kind(), Some(Provider::MinioContainer));
    }

    #[test]
    fn mirror_compute_slot_with_machine_reference_parses() {
        // The on-disk prod.toml has a commented-out compute slot; this test
        // covers the form Phase B will need once yubaba is provisioned.
        let src = r#"
schema_version = 1
shape = "single-machine"

[providers.compute]
use = "hetzner"
machine = "yah-cloud-1"
"#;
        let cfg: MirrorConfig = toml::from_str(src).unwrap();
        let slot = cfg.providers.get("compute").expect("compute slot");
        assert_eq!(slot.provider_id(), Some("hetzner"));
        if let MirrorProviderSlot::Reference { fields, .. } = slot {
            assert_eq!(
                fields.get("machine").and_then(|v| v.as_str()),
                Some("yah-cloud-1"),
            );
        }
    }

    #[test]
    fn machine_yah_cloud_1_round_trips_with_existing_shape() {
        // The current machine TOML predates B2 — MachineConfig hasn't been
        // reshaped yet. This locks the expected shape so we notice if B3
        // accidentally regresses it.
        let src = r#"
name = "yah-cloud-1"
provider = "hetzner"
location = "pdx"
server_type = "cpx11"
hosts_mirrors = []
mesh_tags = ["tag:tier-scratch", "tag:primary-yah"]
ssh_keys = [111513970, 111525493]
"#;
        let cfg: MachineConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.name, "yah-cloud-1");
        assert_eq!(cfg.provider, "hetzner");
        assert_eq!(cfg.ssh_keys.len(), 2);
    }

    #[test]
    fn static_node_omits_location_server_type_and_carries_connect() {
        // BYO Phase-0: a `static` node we brought up over SSH has no provider
        // DC code or SKU; it declares reach in `[connect]` instead. Must load.
        let src = r#"
name = "us-south-001"
provider = "static"
region = "us-south"
mesh_tags = ["tag:cloud-runner", "tag:voter-candidate"]

[connect]
address = "45.32.194.254"
ssh = "root@45.32.194.254"
yubaba = "http://127.0.0.1:7443"
arch = "x86_64"
"#;
        let cfg: MachineConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.provider, "static");
        assert!(cfg.location.is_none());
        assert!(cfg.server_type.is_none());
        assert_eq!(cfg.location(), ""); // accessor defaults empty
        let c = cfg.connect.as_ref().expect("connect block");
        assert_eq!(c.ssh, "root@45.32.194.254");
        assert_eq!(c.yubaba, "http://127.0.0.1:7443");
        // Static providers have no driver, so validate() is a no-op pass.
        assert!(!provider_has_machine_driver(&cfg.provider));
        cfg.validate().unwrap();
    }

    #[test]
    fn driver_provider_without_location_fails_validate() {
        // A driver-backed provider (hetzner/vultr) still MUST carry location +
        // server_type — the driver can't create a server without them. The
        // contract moved from load-time (required field) to provision-time
        // (validate), so the TOML loads but validate() rejects it.
        let src = r#"
name = "us-west-001"
provider = "hetzner"
mesh_tags = []
"#;
        let cfg: MachineConfig = toml::from_str(src).unwrap();
        assert!(provider_has_machine_driver(&cfg.provider));
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("location"),
            "expected location complaint: {err}"
        );
    }

    /// Helper for the new-tree integration tests below: lay out
    /// `<workspace>/.yah/{infra,services}/` with `dev-yah` + its mirrors and
    /// the three Phase-A providers (cloudflare, hetzner, orbstack).
    fn make_new_tree_with_dev_yah(root: &std::path::Path) {
        let infra = root.join(".yah").join("infra");
        let providers = infra.join("providers");
        std::fs::create_dir_all(&providers).unwrap();
        std::fs::write(
            providers.join("cloudflare.toml"),
            r#"schema_version = 1
id = "cloudflare"
kind = "cloudflare"
credentials = "keystore://cloudflare/yah"
default_zone = "yah.dev"
"#,
        )
        .unwrap();
        std::fs::write(
            providers.join("hetzner.toml"),
            r#"schema_version = 1
id = "hetzner"
kind = "hetzner"
credentials = "keystore://hetzner/yah"
default_location = "pdx"
default_server_type = "cpx11"
ssh_keys = []
"#,
        )
        .unwrap();
        std::fs::write(
            providers.join("orbstack.toml"),
            r#"schema_version = 1
id = "orbstack"
kind = "local-container"
runtime = "auto"

[discovery]
orbstack = "~/.orbstack/run/docker.sock"
"#,
        )
        .unwrap();

        let svc = root.join(".yah").join("services").join("dev-yah");
        std::fs::create_dir_all(svc.join("mirrors")).unwrap();
        std::fs::write(
            svc.join("service.toml"),
            r#"schema_version = 1
name = "dev-yah"
domain = "yah.dev"

[[components]]
id = "site"
kind = "mesofact-static"
path = "app/yah/web"
role = "static"
"#,
        )
        .unwrap();
        std::fs::write(
            svc.join("mirrors/prod.toml"),
            r#"schema_version = 1
shape = "single-machine"

[providers.static]
use = "cloudflare"
bucket = "yah-dev"
zone = "yah.dev"
"#,
        )
        .unwrap();
        std::fs::write(
            svc.join("mirrors/local.toml"),
            r#"schema_version = 1
shape = "local"

[providers.static]
kind = "local-static"
port = 4321

[providers.compute]
use = "orbstack"
"#,
        )
        .unwrap();
    }

    #[test]
    fn cloud_config_load_new_tree_populates_providers_and_services() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        make_new_tree_with_dev_yah(root);

        let cfg = CloudConfig::load(root).unwrap();
        assert_eq!(cfg.providers.len(), 3, "three providers loaded");
        assert!(cfg.provider("cloudflare").is_some());
        assert!(cfg.provider("hetzner").is_some());
        assert!(cfg.provider("orbstack").is_some());

        let dev = cfg.service("dev-yah").expect("dev-yah service");
        assert_eq!(dev.service.domain, "yah.dev");
        assert_eq!(dev.service.components.len(), 1);
        assert_eq!(dev.mirrors.len(), 2);
        // Legacy file stems "prod" and "local" are normalised to canonical tier names.
        assert!(dev.mirrors.contains_key("cloud"), "prod.toml → cloud tier");
        assert!(dev.mirrors.contains_key("dev"), "local.toml → dev tier");
        assert_eq!(dev.mirrors["cloud"].shape, MirrorShape::SingleMachine);
        assert_eq!(dev.mirrors["dev"].shape, MirrorShape::Local);

        // Legacy fields stay empty when no .yah/cloud/ exists.
        assert!(cfg.legacy_mirrors.is_empty());
        assert!(cfg.legacy_services.is_empty());
        assert!(cfg.workloads.is_empty());
    }

    #[test]
    fn cloud_config_cross_ref_fails_on_missing_provider() {
        // Mirror references a provider id that doesn't exist.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let svc = root.join(".yah").join("services").join("dev-yah");
        std::fs::create_dir_all(svc.join("mirrors")).unwrap();
        std::fs::write(
            svc.join("service.toml"),
            "schema_version = 1\nname = \"dev-yah\"\ndomain = \"yah.dev\"\n",
        )
        .unwrap();
        std::fs::write(
            svc.join("mirrors/prod.toml"),
            "schema_version = 1\nshape = \"single-machine\"\n\n[providers.static]\nuse = \"fly-io\"\n",
        ).unwrap();

        let err = CloudConfig::load(root).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("fly-io"),
            "error should name the missing provider id, got: {msg}"
        );
        assert!(
            msg.contains("providers/fly-io.toml") || msg.contains("no such provider"),
            "error should hint at remedy, got: {msg}"
        );
    }

    #[test]
    fn cloud_config_cross_ref_passes_on_inline_only_mirror() {
        // Inline `kind = "local-static"` doesn't require an infra provider.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let svc = root.join(".yah").join("services").join("local-only");
        std::fs::create_dir_all(svc.join("mirrors")).unwrap();
        std::fs::write(
            svc.join("service.toml"),
            "schema_version = 1\nname = \"local-only\"\ndomain = \"local.test\"\n",
        )
        .unwrap();
        std::fs::write(
            svc.join("mirrors/local.toml"),
            "schema_version = 1\nshape = \"local\"\n\n[providers.static]\nkind = \"local-static\"\nport = 8080\n",
        ).unwrap();

        // Should load fine: no `use=` references, no providers required.
        let cfg = CloudConfig::load(root).unwrap();
        assert!(cfg.service("local-only").is_some());
    }

    #[test]
    fn cloud_config_load_coexists_legacy_and_new_trees() {
        // Both trees present — both fields populated independently.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        make_new_tree_with_dev_yah(root);

        let cloud_dir = make_legacy_cloud_dir(root);
        std::fs::create_dir_all(cloud_dir.join("mirrors")).unwrap();
        std::fs::write(
            cloud_dir.join("mirrors/noisetable.toml"),
            "camp = \"noisetable\"\nregions = [\"pdx\"]\nworkloads = []\n",
        )
        .unwrap();

        let cfg = CloudConfig::load(root).unwrap();
        assert_eq!(cfg.providers.len(), 3);
        assert!(cfg.service("dev-yah").is_some());
        assert_eq!(cfg.legacy_mirrors.len(), 1);
        assert!(cfg.legacy_mirror("noisetable").is_some());
    }

    #[test]
    fn web_workload_round_trips() {
        // app/yah/web/workload.toml is parsed as a WorkloadSpec via the
        // workload-spec crate. The minimum-viable manifest here exercises
        // schema_version + kind + build fields.
        //
        // The on-disk file uses the abbreviated v1 form (kind + build); the
        // full WorkloadSpec is verbose, so this test asserts the new
        // mesofact-static abbreviated form parses as raw TOML (B3 will plumb
        // it through WorkloadSpec proper).
        let src = r#"
schema_version = 1
kind = "mesofact-static"

[build]
command = "bun run build"
out_dir = "dist"

routes = "./routes.ts"
"#;
        let v: toml::Value = toml::from_str(src).unwrap();
        assert_eq!(
            v.get("schema_version").and_then(|x| x.as_integer()),
            Some(1)
        );
        assert_eq!(
            v.get("kind").and_then(|x| x.as_str()),
            Some("mesofact-static")
        );
        let build = v
            .get("build")
            .and_then(|x| x.as_table())
            .expect("build table");
        assert_eq!(
            build.get("command").and_then(|x| x.as_str()),
            Some("bun run build")
        );
        assert_eq!(build.get("out_dir").and_then(|x| x.as_str()), Some("dist"));
    }

    // ─── Canonical CRUD: ServiceConfig/MirrorConfig save + delete (R323-F1) ──

    #[test]
    fn service_config_save_creates_canonical_toml_and_round_trips() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        let svc = ServiceConfig {
            schema_version: 1,
            name: "dev-yah".into(),
            domain: "yah.dev".into(),
            components: vec![ServiceComponent {
                id: "site".into(),
                kind: "mesofact-static".into(),
                path: "app/yah/web".into(),
                role: "static".into(),
                publishes: Some("static".into()),
                wave: 0,
                git: None,
            }],
        };
        svc.save(root).unwrap();

        // Landed at the canonical path.
        let path = crate::paths::service_toml(root, "dev-yah");
        assert!(
            path.exists(),
            "service.toml should exist at {}",
            path.display()
        );

        // Reloads through the full CloudConfig loader (no mirrors yet).
        let cfg = CloudConfig::load(root).unwrap();
        let loaded = cfg.service("dev-yah").expect("dev-yah service");
        assert_eq!(loaded.service.domain, "yah.dev");
        assert_eq!(loaded.service.components.len(), 1);
        assert_eq!(
            loaded.service.components[0].publishes.as_deref(),
            Some("static")
        );
        assert!(loaded.mirrors.is_empty());
    }

    #[test]
    fn service_config_save_overwrites_in_place() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        let mut svc = ServiceConfig {
            schema_version: 1,
            name: "dev-yah".into(),
            domain: "yah.dev".into(),
            components: vec![],
        };
        svc.save(root).unwrap();
        svc.domain = "yah.example".into();
        svc.save(root).unwrap();

        let cfg = CloudConfig::load(root).unwrap();
        assert_eq!(
            cfg.service("dev-yah").unwrap().service.domain,
            "yah.example"
        );
    }

    #[test]
    fn mirror_config_save_round_trips_reference_and_inline_slots() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        // A service must exist so the loader walks the mirrors/ dir.
        ServiceConfig {
            schema_version: 1,
            name: "dev-yah".into(),
            domain: "yah.dev".into(),
            components: vec![],
        }
        .save(root)
        .unwrap();

        // The cloudflare provider the reference slot points at must resolve,
        // or CloudConfig::load's cross-ref check rejects the tree.
        let providers = crate::paths::providers_dir(root);
        std::fs::create_dir_all(&providers).unwrap();
        std::fs::write(
            providers.join("cloudflare.toml"),
            "schema_version = 1\nid = \"cloudflare\"\nkind = \"cloudflare\"\n",
        )
        .unwrap();

        let mut providers_map = BTreeMap::new();
        providers_map.insert(
            "static".to_string(),
            MirrorProviderSlot::Reference {
                provider_id: "cloudflare".into(),
                fields: {
                    let mut f = BTreeMap::new();
                    f.insert("bucket".to_string(), toml::Value::String("yah-dev".into()));
                    f
                },
            },
        );
        providers_map.insert(
            "compute".to_string(),
            MirrorProviderSlot::Inline {
                kind: Provider::LocalStatic,
                fields: {
                    let mut f = BTreeMap::new();
                    f.insert("port".to_string(), toml::Value::Integer(4321));
                    f
                },
            },
        );
        let mirror = MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::SingleMachine,
            providers: providers_map,
            asset_aliases: Default::default(),
        };
        // Save with canonical name; legacy "prod" is normalised to "cloud" on load.
        mirror.save(root, "dev-yah", "cloud").unwrap();

        let path = crate::paths::service_mirror_toml(root, "dev-yah", "cloud");
        assert!(
            path.exists(),
            "mirror toml should exist at {}",
            path.display()
        );

        let cfg = CloudConfig::load(root).unwrap();
        let loaded = &cfg.service("dev-yah").unwrap().mirrors["cloud"];
        assert_eq!(loaded.shape, MirrorShape::SingleMachine);
        assert_eq!(loaded.providers["static"].provider_id(), Some("cloudflare"));
        assert_eq!(
            loaded.providers["compute"].inline_kind(),
            Some(Provider::LocalStatic)
        );
    }

    #[test]
    fn service_delete_removes_dir_and_mirrors() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        let svc = ServiceConfig {
            schema_version: 1,
            name: "dev-yah".into(),
            domain: "yah.dev".into(),
            components: vec![],
        };
        svc.save(root).unwrap();
        MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::Local,
            providers: BTreeMap::new(),
            asset_aliases: Default::default(),
        }
        .save(root, "dev-yah", "local")
        .unwrap();

        assert!(
            ServiceConfig::delete(root, "dev-yah").unwrap(),
            "first delete reports true"
        );
        assert!(!crate::paths::service_dir(root, "dev-yah").exists());
        // Idempotent: deleting again is a no-op that reports false.
        assert!(!ServiceConfig::delete(root, "dev-yah").unwrap());

        let cfg = CloudConfig::load(root).unwrap();
        assert!(cfg.service("dev-yah").is_none());
    }

    #[test]
    fn mirror_delete_leaves_other_mirrors_and_service_intact() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        ServiceConfig {
            schema_version: 1,
            name: "dev-yah".into(),
            domain: "yah.dev".into(),
            components: vec![],
        }
        .save(root)
        .unwrap();
        for env in ["prod", "local"] {
            MirrorConfig {
                schema_version: 1,
                shape: MirrorShape::Local,
                providers: BTreeMap::new(),
                asset_aliases: Default::default(),
            }
            .save(root, "dev-yah", env)
            .unwrap();
        }

        assert!(MirrorConfig::delete(root, "dev-yah", "prod").unwrap());
        assert!(!MirrorConfig::delete(root, "dev-yah", "prod").unwrap());

        let cfg = CloudConfig::load(root).unwrap();
        let svc = cfg
            .service("dev-yah")
            .expect("service survives mirror delete");
        // Legacy file stems are normalised on load: "prod" → "cloud", "local" → "dev".
        assert!(!svc.mirrors.contains_key("cloud"));
        assert!(svc.mirrors.contains_key("dev"));
    }

    // ─── DomainConfig (R347-F2) ────────────────────────────────────────────

    fn write_marketing_service(root: &Path) {
        let svc = ServiceConfig {
            schema_version: 1,
            name: "yah-marketing".into(),
            domain: "yah.dev".into(),
            components: vec![ServiceComponent {
                id: "site".into(),
                kind: "mesofact-static".into(),
                path: "app/yah/web".into(),
                role: "static".into(),
                publishes: None,
                wave: 0,
                git: None,
            }],
        };
        svc.save(root).unwrap();
    }

    #[test]
    fn round_trip_domain_with_each_route_mode() {
        let dom = DomainConfig {
            schema_version: 1,
            name: "yah-dev".into(),
            domain: "yah.dev".into(),
            cdn_bucket: "yah-dev".into(),
            worker_bundle_path: Some(".yah/workers/yah-dev/".into()),
            routes: vec![
                DomainRoute {
                    path: "/".into(),
                    mode: RouteMode::Static {
                        component: "yah-marketing/site".into(),
                    },
                },
                DomainRoute {
                    path: "/dashboard/api/*".into(),
                    mode: RouteMode::Backend {
                        component: "yah-dashboard/api".into(),
                        origin: "https://api.dashboard.yah.dev".into(),
                    },
                },
                DomainRoute {
                    path: "/old".into(),
                    mode: RouteMode::Redirect {
                        target: "https://yah.dev/blog".into(),
                        status: 308,
                    },
                },
            ],
        };
        let s = toml::to_string(&dom).unwrap();
        let back: DomainConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.name, "yah-dev");
        assert_eq!(back.routes.len(), 3);
        assert!(matches!(back.routes[0].mode, RouteMode::Static { .. }));
        assert!(matches!(back.routes[1].mode, RouteMode::Backend { .. }));
        assert!(matches!(back.routes[2].mode, RouteMode::Redirect { .. }));
    }

    #[test]
    fn redirect_status_defaults_to_308() {
        let src = r#"
schema_version = 1
name = "yah-dev"
domain = "yah.dev"
cdn_bucket = "yah-dev"

[[routes]]
path = "/old"
mode = "redirect"
target = "https://yah.dev/blog"
"#;
        let dom: DomainConfig = toml::from_str(src).unwrap();
        let RouteMode::Redirect { status, .. } = &dom.routes[0].mode else {
            panic!("expected redirect");
        };
        assert_eq!(*status, 308);
    }

    #[test]
    fn missing_domains_dir_is_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = CloudConfig::load(tmp.path()).unwrap();
        assert!(cfg.domains.is_empty());
    }

    #[test]
    fn save_reload_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_marketing_service(root);

        let dom = DomainConfig {
            schema_version: 1,
            name: "yah-dev".into(),
            domain: "yah.dev".into(),
            cdn_bucket: "yah-dev".into(),
            worker_bundle_path: None,
            routes: vec![DomainRoute {
                path: "/".into(),
                mode: RouteMode::Static {
                    component: "yah-marketing/site".into(),
                },
            }],
        };
        dom.save(root).unwrap();

        let cfg = CloudConfig::load(root).unwrap();
        let loaded = cfg.domain("yah-dev").expect("yah-dev domain");
        assert_eq!(loaded.domain, "yah.dev");
        assert_eq!(loaded.routes.len(), 1);
    }

    #[test]
    fn delete_returns_false_when_absent() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(!DomainConfig::delete(tmp.path(), "no-such-domain").unwrap());
    }

    #[test]
    fn delete_returns_true_first_time() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let dom = DomainConfig {
            schema_version: 1,
            name: "yah-dev".into(),
            domain: "yah.dev".into(),
            cdn_bucket: "yah-dev".into(),
            worker_bundle_path: None,
            routes: vec![],
        };
        dom.save(root).unwrap();
        assert!(DomainConfig::delete(root, "yah-dev").unwrap());
        assert!(!DomainConfig::delete(root, "yah-dev").unwrap());
    }

    #[test]
    fn cross_ref_bails_on_missing_service() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        // No services declared at all — component ref must fail to resolve.
        let dom = DomainConfig {
            schema_version: 1,
            name: "yah-dev".into(),
            domain: "yah.dev".into(),
            cdn_bucket: "yah-dev".into(),
            worker_bundle_path: None,
            routes: vec![DomainRoute {
                path: "/".into(),
                mode: RouteMode::Static {
                    component: "yah-marketing/site".into(),
                },
            }],
        };
        dom.save(root).unwrap();

        let err = CloudConfig::load(root).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no such service"), "got: {msg}");
        assert!(msg.contains("yah-marketing"), "got: {msg}");
    }

    #[test]
    fn cross_ref_bails_on_missing_component() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_marketing_service(root); // has component id "site", not "elsewhere"

        let dom = DomainConfig {
            schema_version: 1,
            name: "yah-dev".into(),
            domain: "yah.dev".into(),
            cdn_bucket: "yah-dev".into(),
            worker_bundle_path: None,
            routes: vec![DomainRoute {
                path: "/".into(),
                mode: RouteMode::Static {
                    component: "yah-marketing/elsewhere".into(),
                },
            }],
        };
        dom.save(root).unwrap();

        let err = CloudConfig::load(root).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no component with id"), "got: {msg}");
        assert!(msg.contains("elsewhere"), "got: {msg}");
    }

    #[test]
    fn cross_ref_bails_on_malformed_ref() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_marketing_service(root);

        let dom = DomainConfig {
            schema_version: 1,
            name: "yah-dev".into(),
            domain: "yah.dev".into(),
            cdn_bucket: "yah-dev".into(),
            worker_bundle_path: None,
            routes: vec![DomainRoute {
                path: "/".into(),
                mode: RouteMode::Static {
                    component: "no-slash-here".into(),
                },
            }],
        };
        dom.save(root).unwrap();

        let err = CloudConfig::load(root).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("expected"), "got: {msg}");
    }

    #[test]
    fn redirect_routes_skip_component_validation() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        // No services at all — redirect must still load cleanly because it
        // references nothing.
        let dom = DomainConfig {
            schema_version: 1,
            name: "yah-dev".into(),
            domain: "yah.dev".into(),
            cdn_bucket: "yah-dev".into(),
            worker_bundle_path: None,
            routes: vec![DomainRoute {
                path: "/old".into(),
                mode: RouteMode::Redirect {
                    target: "https://yah.dev/blog".into(),
                    status: 308,
                },
            }],
        };
        dom.save(root).unwrap();

        let cfg = CloudConfig::load(root).unwrap();
        assert!(cfg.domain("yah-dev").is_some());
    }

    #[test]
    fn name_must_match_file_stem() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        // Hand-write a file whose stem disagrees with its `name`.
        let dir = root.join(".yah").join("domains");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("yah-dev.toml"),
            r#"schema_version = 1
name = "different-name"
domain = "yah.dev"
cdn_bucket = "yah-dev"
"#,
        )
        .unwrap();

        let err = CloudConfig::load(root).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("must match the file stem"), "got: {msg}");
    }

    #[test]
    fn net_alias_tier_subdomain_manifest_loads_and_cross_refs() {
        // R561-F2: a per-tenant subdomain manifest on the net.yah.dev wildcard
        // alias tier is just a DomainConfig whose `domain` is `<name>.net.yah.dev`
        // and whose static route cross-refs the tenant's service component.
        // This is exactly the shape .yah/domains/scrabcake-net-yah-dev.toml ships.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_marketing_service(root); // service "yah-marketing", component "site"

        let dom = DomainConfig {
            schema_version: 1,
            name: "tenant-net-yah-dev".into(),
            domain: "tenant.net.yah.dev".into(),
            cdn_bucket: "net-yah-dev".into(), // shared per-tier bucket
            worker_bundle_path: None,
            routes: vec![DomainRoute {
                path: "/*".into(),
                mode: RouteMode::Static {
                    component: "yah-marketing/site".into(),
                },
            }],
        };
        dom.save(root).unwrap();

        let cfg = CloudConfig::load(root).unwrap();
        let dom = cfg
            .domain("tenant-net-yah-dev")
            .expect("net-tier subdomain manifest should load");
        assert_eq!(dom.domain, "tenant.net.yah.dev");
        assert_eq!(dom.cdn_bucket, "net-yah-dev");
    }
}
