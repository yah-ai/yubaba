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
//!
//! @yah:relay(R615, "Linked infra sources: sources.toml overlay so a camp can borrow another camp's substrate")
//! @yah:at(2026-07-20T18:18:05Z)
//! @yah:status(open)
//! @arch:see(.yah/docs/working/W274-linked-infra-sources.md)
//!
//! @yah:ticket(R615-F1, "InfraSource types + SourcesConfig::load(infra_dir) parsing .yah/infra/sources.toml")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:at(2026-08-08T19:55:57Z)
//! @yah:phase(P1)
//! @yah:parent(R615)
//! @yah:next("Add InfraSourceKind { Path { path }, Git(GitSource) } + InfraSource { owner, kind, mode, select } to cloud/src/config.rs. Reuse the existing GitSource (config.rs:1205, { repo, ref, subdir }) verbatim — do not invent a second git-source shape.")
//! @yah:next("SourcesConfig::load(infra_dir) reads .yah/infra/sources.toml (schema_version = 1, ordered [[source]] array). Absent file = empty list, never an error — every existing camp has no sources.toml.")
//! @yah:next("mode is the write-gate: read-only (borrower cannot mutate) vs owner-manages. Model it as an enum, not a bool, so a future read-write-with-approval tier is additive.")
//! @yah:verify("cargo check -p cloud && cargo test -p cloud")
//! @arch:see(.yah/docs/working/W274-linked-infra-sources.md)
//! @yah:tier(Cleric)
//! @yah:handoff("InfraSourceKind{Path{path},Git(GitSource)} + SourceMode{ReadOnly,Manage} + InfraSource{owner,kind,mode,select} + SourcesConfig{schema_version,source} all landed in oss/yubaba/crates/cloud/src/config.rs (after default_git_ref, ~line 1550). GitSource reused verbatim -- Git(GitSource) wraps the existing R561 type unchanged, no second git-source shape. InfraSourceKind is internally tagged (#[serde(tag=\"kind\", rename_all=\"kebab-case\")]) and flattened into InfraSource so a [[source]] table reads exactly like W274's example: owner/kind/path-or-repo+ref+subdir/mode/select all at one table level. mode: SourceMode defaults ReadOnly via #[serde(default)] on the field (enum, not bool, per the ticket's own instruction -- Manage is the explicit escape hatch). SourcesConfig::load(infra_dir) returns Ok(default()) -- schema_version=1, empty source list -- when sources.toml is absent; only parses+errors when the file exists and is malformed.")
//! @yah:handoff("Tree anchor 85801e7f. Pathspec: oss/yubaba/crates/cloud/src/config.rs (only file touched). Tests: cargo test -p yah-cloud --lib (from oss/yubaba) 710 passed / 0 failed / 4 ignored, +6 new over the 704 baseline your R707-T6 verification recorded (sources_load_is_empty_when_the_file_is_absent, sources_parses_a_path_kind_exactly_like_w274s_example, sources_parses_a_git_kind_reusing_gitsource_verbatim, sources_mode_defaults_to_read_only_and_manage_is_explicit, sources_preserves_declaration_order, sources_round_trips_through_serialize). cargo check -p cloud also green (implied by the test build).")
//! @yah:handoff("Tree anchor at handoff: 85801e7f6b76b369c0c8ecd2e5c7874990cd9286 — the shared tree as I left it. Diff against it (`git diff 85801e7f6b76b369c0c8ecd2e5c7874990cd9286..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("R615-F2 picks this straight up: overlay these sources into CloudConfig::load, tagging origin{owner,source} and merging camp-local-wins-on-collision.")
//! @yah:handoff("Verified pre-existing work: InfraSourceKind{Path,Git(GitSource)} + SourceMode + InfraSource + SourcesConfig all present in oss/yubaba/crates/cloud/src/config.rs at tree anchor 871fde1c, matching the inline @yah:handoff notes already on this ticket. GitSource reused verbatim, no second git-source shape. This session added no new code -- only ran verification and closed the board state, which a prior session left stuck in `open` despite the work being done (code + handoff notes landed, but board.review/handoff was never called).")
//! @yah:verify("cargo check -p yah-cloud -- clean (2 pre-existing unrelated warnings)")
//! @yah:verify("cargo test -p yah-cloud --lib -- 723 passed; 0 failed; 4 ignored (from oss/yubaba)")
//!
//! @yah:ticket(R615-F2, "Overlay loader: resolve sources in CloudConfig::load, tag origin, camp-local wins on collision")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:at(2026-08-08T19:56:05Z)
//! @yah:phase(P1)
//! @yah:parent(R615)
//! @yah:next("In CloudConfig::load, after loading camp-local machines/providers/rules, resolve each source to an infra root (git sources read from the .yah/cache/infra/ sync cache — load stays offline), load that root's machines/providers/rules, tag each entry with origin { owner, source }, and overlay UNDER camp-local. Camp-local wins on name collision.")
//! @yah:next("The machine load site is config.rs:533 (load_dir::<MachineConfig>(paths::machines_dir(...))). Note config.rs:575 load_from_config_dir is a SECOND machine load site that deliberately skips the inherit_machines redirect for multi-root/sibling trees (W206) — decide explicitly whether sources overlay applies there too, and document the answer either way.")
//! @yah:verify("cargo check -p cloud && cargo test -p cloud")
//! @yah:verify("A camp with sources.toml [[source]] kind=path to a sibling camp sees that camp's machines in CloudConfig::load, each tagged with the source owner")
//! @yah:gotcha("Cross-camp MachineConfig schema skew is real: noisetable ships an older machine schema (location/server_type/hosts_mirrors) while yah's use region/arch/[connect]. A borrowed source can carry fields the borrower's binary predates. Overlay load MUST tolerate/skip unparseable foreign entries per-file and warn — never fail the whole load.")
//! @arch:see(.yah/docs/working/W274-linked-infra-sources.md)
//! @yah:depends_on(R615-F1)
//! @yah:tier(Warrior)
//! @yah:handoff("Overlay landed in CloudConfig::load (oss/yubaba/crates/cloud/src/config.rs). After camp-local machines/providers/legacy-merge finish, SourcesConfig::load(paths::infra_dir(workspace_root)) resolves + overlay_infra_sources() merges each source's machines/providers UNDER what's already there -- camp-local wins any name collision, and among sources themselves the earlier-declared one wins (both proven by dedicated tests). Provenance is NOT a field on MachineConfig/ProviderConfig: added CloudConfig.machine_origins/provider_origins: BTreeMap<String, InfraOrigin> instead, keyed by name/id. Reason recorded in a doc comment on InfraOrigin -- MachineConfig/ProviderConfig are constructed by struct literal in test helpers across several crates (including crates/yah/agent-tools/src/cloud_tools.rs, which is fenced/live-owned this session), so widening either shape would have forced an edit there for zero semantic gain; origin is a property of the LOAD, not the machine.")
//! @yah:handoff("GOTCHA closed: added load_dir_tolerant<T>() -- a per-file-tolerant sibling of the existing (strict) load_dir -- so one unparseable foreign machine/provider (schema skew) skips-with-a-tracing::warn! and never sinks the rest of that source's directory or this camp's own load. Proven by one_unparseable_foreign_machine_does_not_sink_the_rest_of_the_directory_or_the_load. load_dir itself is untouched -- camp-local files still hard-fail on a bad TOML, which is correct, only borrowed roots get the tolerant path.")
//! @yah:handoff("Git sources: InfraSource::infra_root() resolves kind=path to <workspace_root>/<path>/.yah/infra (live tree, no I/O beyond building the path) and kind=git to paths::infra_source_cache_dir(workspace_root, owner)/infra -- a NEW path helper in paths.rs, also what R615-T3's `yah infra sync` target directory must be so the two line up. An unsynced git source (cache dir absent) overlays nothing and is explicitly NOT an error (test: an_unsynced_git_source_overlays_nothing_and_is_not_an_error) -- load() stays fully offline as W274 §3 requires.")
//! @yah:handoff("select filtering implemented for machines only (name exact-match or literal mesh_tags membership -- not a glob engine, matches W274's own example verbatim) via machine_matches_select(); does NOT apply to providers -- documented as a deliberate choice, nothing in W274 or the ticket describes a provider-scoped filter.")
//! @yah:handoff("EXPLICIT DECISION on the config.rs:575-equivalent gotcha (now load_from_config_dir): sources overlay does NOT apply there. Multi-root sibling config dirs (W206 layout (b)) are a second config root INSIDE the same camp, not a second camp -- .yah/infra/sources.toml is tied to paths::infra_dir(workspace_root) specifically, which has no well-defined meaning for an arbitrary config_dir. Documented in the function's doc comment and proven by load_from_config_dir_never_applies_sources_overlay (a sources.toml at the real workspace root does NOT leak into a load_from_config_dir call against a sibling .noisetable/ dir under that same root).")
//! @yah:handoff("Tree anchor 85801e7f. Pathspec: oss/yubaba/crates/cloud/src/config.rs, oss/yubaba/crates/cloud/src/paths.rs (added infra_source_cache_dir + 1 test), oss/yubaba/crates/cloud/src/reconciler/mesofact_bundle.rs (CloudConfig test-literal fixed for the 2 new fields), app/yah/cli/src/cloud.rs (3 CloudConfig test-literal sites fixed, same reason). Tests: cargo test -p yah-cloud --lib (from oss/yubaba) 720 passed / 0 failed / 4 ignored, +10 over R615-F1's 710 baseline (9 overlay tests in config.rs + 1 in paths.rs). cargo build -p yah --lib (repo root) green -- confirms nothing downstream (agent-tools, cloud.rs, hub) broke from CloudConfig's two new fields.")
//! @yah:handoff("Tree anchor at handoff: 85801e7f6b76b369c0c8ecd2e5c7874990cd9286 — the shared tree as I left it. Diff against it (`git diff 85801e7f6b76b369c0c8ecd2e5c7874990cd9286..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("R615-T3 (yah infra sync) is unblocked and has everything it needs: paths::infra_source_cache_dir(workspace_root, owner) is the exact target directory to clone/pull git sources into, already matching what F2's overlay reads from.")
//! @yah:next("R615-F4 (Infra tab origin badge, not in my assigned lane) can read CloudConfig.machine_origins/provider_origins directly -- no further backend plumbing needed for the badge itself.")
//! @yah:handoff("Verified pre-existing work: overlay landed in CloudConfig::load (oss/yubaba/crates/cloud/src/config.rs) at tree anchor 871fde1c -- SourcesConfig::load resolves sources, overlay_infra_sources() merges under camp-local with camp-local-wins and earlier-source-wins collision rules, machine_origins/provider_origins BTreeMaps added to CloudConfig, load_dir_tolerant() added for per-file-tolerant foreign schema skew, InfraSource::infra_root() resolves path/git kinds, load_from_config_dir explicitly does NOT get the overlay (documented). Matches this ticket's own inline @yah:handoff notes. This session added no new code -- only ran verification and closed board state that a prior session left stuck in `open` despite the work being done.")
//! @yah:verify("cargo check -p yah-cloud -- clean (2 pre-existing unrelated warnings)")
//! @yah:verify("cargo test -p yah-cloud --lib -- 723 passed; 0 failed; 4 ignored (from oss/yubaba), includes overlay tests + load_dir_tolerant test + infra_source_cache_dir test in paths.rs")

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use thiserror::Error;
use workload_spec::secrets::SecretAccess;
use workload_spec::{validate, LifecycleArchetype, TenantId, WorkloadSpec};

/// Static node capacity declaration on `machine.toml` (R572-F3).
///
/// `memory_mb` and `cpu_millis` express the node's *total* hardware budget.
/// F5's bin-packer subtracts the sum of committed workload requests from
/// this floor to determine available headroom; an absent `allocatable`
/// block means no capacity constraint is enforced (any workload fits).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct NodeAllocatable {
    /// Total physical RAM in mebibytes (e.g. 512 for a 512 MB node).
    pub memory_mb: u32,
    /// Total CPU in k8s millicores (1000 = 1 core, 250 = 0.25 CPU).
    pub cpu_millis: u32,
}

/// `[registration]` — facts **observed** about a running box, written by the
/// fleet rather than declared by an operator (R707-T1).
///
/// The rest of `machine.toml` is *declaration*: intent, operator-authored,
/// reviewed and diffed like any other source. This block is the other half —
/// what the box turned out to be once it booted and joined. Keeping the two
/// apart is what lets the published fleet index (R707-F3) say which half it is
/// carrying; publishing them under one schema would bake the confusion into a
/// permanent record.
///
/// The split is a **provenance** boundary, not a trust or reach one:
/// - *Declaration* answers "what did we ask for" — `name`, `region`, `arch`,
///   `mesh_tags`, `[allocatable]`, and the declared reach in [`ConnectSpec`].
/// - *Registration* answers "what did we observe" — the hostkey TOFU'd at
///   attach, the mesh address headscale assigned at join.
///
/// It stays in the git-tracked TOML on purpose. Registration is not local
/// scratch state: every consumer needs the mesh address to dial a node, so it
/// has to travel with the declaration. (`.yah/infra/state/machines/<name>.json`
/// — [`crate::state::MachineState`] — remains the *gitignored* sidecar for
/// provider-side derivatives that nobody but this camp needs.)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MachineRegistration {
    /// Yubaba's ed25519 `/identity` fingerprint, TOFU-recorded by
    /// `yah cloud machine attach` on first contact (`SHA256:…`). An observed
    /// property of a running process — not the operator's intent — which is
    /// why it moved out of the top level here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostkey_fingerprint: Option<String>,
    /// Mesh (headscale/tailnet) IPv4 assigned at join, e.g. `"100.64.0.1"`.
    /// Bare address, not a URL: the *port* is declared reach and lives on
    /// [`ConnectSpec::yubaba_port`]. [`MachineConfig::yubaba_url`] composes the
    /// two. Absent until the node has joined the mesh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_ipv4: Option<String>,
    /// RFC3339 timestamp of the mesh join that produced `mesh_ipv4`. Free-form
    /// audit; nothing keys off it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_at: Option<String>,
}

impl MachineRegistration {
    /// True when nothing has been observed yet — used to omit the whole
    /// `[registration]` table from a serialized machine TOML.
    pub fn is_empty(&self) -> bool {
        self.hostkey_fingerprint.is_none() && self.mesh_ipv4.is_none() && self.joined_at.is_none()
    }
}

/// Per-machine TOML from `.yah/infra/machines/<name>.toml`.
///
/// Two halves, split by provenance (R707-T1): everything here is *declaration*
/// — operator intent under review and blame — except [`registration`], which
/// carries what the fleet observed. See [`MachineRegistration`] for why the
/// boundary is drawn there and what depends on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MachineConfig {
    pub name: String,
    pub provider: String,
    /// Who the hardware actually comes from (`"ovh"`, `"vultr"`, `"on-prem"`).
    ///
    /// Deliberately *not* [`provider`](Self::provider), which selects the
    /// auto-provision driver: a box we rented by hand and brought up over SSH
    /// is `provider = "static"` for its whole life, and writing the vendor
    /// there instead would flip it driver-backed and make
    /// [`validate`](Self::validate) demand `location` + `server_type` it has no
    /// answer for. The two axes genuinely differ — vendor is who bills you,
    /// `provider` is who yah can call an API against.
    ///
    /// Worth recording because vendor-scoped policy is invisible in every other
    /// field and decides real work: outbound port 25, rDNS/PTR control, IP
    /// reputation, egress billing. It survived only in TOML prose until now,
    /// which made it ungreppable at exactly the moment you need it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Human label for the box (`"gamer"`, `"the GEEKOM"`). Free-form and never
    /// matched on — [`name`](Self::name) stays the identity everywhere. This is
    /// only so operators and agents can say which box they mean out loud.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
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
    /// Declared CPU architecture (`"x86_64"` / `"aarch64"`). A machine has
    /// exactly one — it's a first-class property of the box, not a reach
    /// detail and not a mesh tag. Drives the yubaba release triple. Optional
    /// only because there's no provider API to probe it (static nodes declare
    /// it; a driver-backed provider may leave it unset until known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    pub bucket: Option<BucketSpec>,
    /// **Legacy location, superseded by `[registration].hostkey_fingerprint`**
    /// (R707-T1). Still deserialized so machine TOMLs written before the split
    /// keep parsing; never *read* directly — go through
    /// [`MachineConfig::hostkey_fingerprint`], which prefers the registration
    /// block. [`MachineConfig::normalize`] folds this into `registration`, and
    /// [`MachineConfig::save`] normalizes before writing, so a load→save cycle
    /// migrates the file rather than dropping the value.
    #[serde(
        rename = "hostkey_fingerprint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub legacy_hostkey_fingerprint: Option<String>,
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
    /// Static node capacity (R572-F3). Declares the node's total hardware
    /// budget; F5's scheduler subtracts committed workload requests from this
    /// to check whether a new workload fits. Absent means unconstrained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocatable: Option<NodeAllocatable>,
    /// Repel-unless-tolerate taint keys (R572-F3). A workload must tolerate
    /// every taint on a candidate node for the scheduler to place it there.
    /// Examples: `"no-appliance"` prevents Appliance workloads; `"no-voter"`
    /// prevents a node from joining quorum; `"public-ip"` is a positive
    /// requirement marker the ingress appliance (W267) demands.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taints: Vec<String>,
    /// `[registration]` — the observed half (R707-T1). Empty until the box has
    /// been attached / mesh-joined. See [`MachineRegistration`].
    #[serde(default, skip_serializing_if = "MachineRegistration::is_empty")]
    pub registration: MachineRegistration,
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

    /// Yubaba's TOFU'd hostkey fingerprint, from `[registration]` and falling
    /// back to the pre-R707-T1 top-level field. **The only read path** — a
    /// caller that reaches for `legacy_hostkey_fingerprint` directly sees
    /// `None` on every migrated machine.
    pub fn hostkey_fingerprint(&self) -> Option<&str> {
        self.registration
            .hostkey_fingerprint
            .as_deref()
            .or(self.legacy_hostkey_fingerprint.as_deref())
    }

    /// Record (or clear) the observed hostkey fingerprint. Writes
    /// `[registration]` and drops any pre-R707-T1 top-level value, so the two
    /// locations can never disagree after a writeback.
    pub fn set_hostkey_fingerprint(&mut self, fingerprint: Option<String>) {
        self.registration.hostkey_fingerprint = fingerprint;
        self.legacy_hostkey_fingerprint = None;
    }

    /// Mesh (tailnet) IPv4 for this node, or `None` pre-mesh.
    ///
    /// Prefers `[registration].mesh_ipv4`; falls back to the host of a legacy
    /// `[connect].yubaba` URL when that host is in the `100.64.0.0/10` CGNAT
    /// range the mesh uses. A loopback placeholder (`http://127.0.0.1:7443`,
    /// meaning "pre-mesh, reachable only through an SSH tunnel") is *not* a
    /// mesh address and yields `None`.
    pub fn mesh_ipv4(&self) -> Option<&str> {
        if let Some(ip) = self.registration.mesh_ipv4.as_deref() {
            return Some(ip);
        }
        let url = self.connect.as_ref()?.yubaba.as_deref()?;
        mesh_ipv4_from_url(url)
    }

    /// Base URL for this node's yubaba, or `None` when it declares no reach.
    ///
    /// A declared `[connect].yubaba` wins whenever present — full stop, not
    /// only for the pre-mesh loopback placeholder. `[registration].mesh_ipv4`
    /// + `[connect].yubaba_port` is the *derivation* used only when nothing is
    /// declared (R707-T6 / W295).
    ///
    /// This was narrower once: a declared literal won only when there was no
    /// registered mesh address, on the reasoning that the loopback placeholder
    /// (`http://127.0.0.1:7443`, "reach me through the SSH tunnel") is a
    /// genuine declaration and not a stale observation. That reasoning still
    /// holds — it just never considered a *non-loopback* literal coexisting
    /// with a mesh address, which is exactly R608-F18's forcing case:
    /// us-west-014 is mesh-joined (`mesh_ipv4`) but its raft peers are
    /// LAN-only, so `rollout::yubaba::membership_to_nodes` needs the LAN
    /// literal, not the mesh-derived URL, to match the raft membership
    /// address. A declared literal is *always* the more specific statement —
    /// whether it says "SSH tunnel only" or "reach me on the LAN" — and
    /// `mesh_ipv4` is only ever a convenience for the common case where
    /// nothing more specific was declared. There is no third state to add: the
    /// fields already say everything needed, only their precedence was wrong
    /// for a declared-and-mesh-joined node.
    pub fn yubaba_url(&self) -> Option<String> {
        let connect = self.connect.as_ref()?;
        if let Some(literal) = &connect.yubaba {
            return Some(literal.clone());
        }
        let ip = self.registration.mesh_ipv4.as_deref()?;
        Some(format!("http://{ip}:{}", connect.yubaba_port()))
    }

    /// Fold the pre-R707-T1 top-level `hostkey_fingerprint` into
    /// `[registration]`, and lift a mesh IP out of a legacy `[connect].yubaba`
    /// URL. Idempotent; a machine already on the split shape is untouched.
    ///
    /// [`save`](Self::save) calls this, so writing a machine TOML migrates it
    /// rather than round-tripping the old shape back out.
    pub fn normalize(&mut self) {
        if let Some(fp) = self.legacy_hostkey_fingerprint.take() {
            self.registration.hostkey_fingerprint.get_or_insert(fp);
        }
        if self.registration.mesh_ipv4.is_none() {
            if let Some(ip) = self
                .connect
                .as_ref()
                .and_then(|c| c.yubaba.as_deref())
                .and_then(mesh_ipv4_from_url)
                .map(str::to_string)
            {
                self.registration.mesh_ipv4 = Some(ip);
                // The URL was pure derivation from mesh IP + port; keep only
                // the declared half so the two can't drift apart.
                if let Some(c) = self.connect.as_mut() {
                    c.yubaba = None;
                }
            }
        }
    }

    /// Persist to `<cloud_dir>/machines/<name>.toml`, creating the dir if needed.
    ///
    /// ⚠ Serializes the struct, so **operator comments in the target file are
    /// lost**. Pre-existing behaviour, not introduced here, but it is why
    /// registration writeback (`yah cloud machine attach`) goes through
    /// [`crate::state::MachineState`] and the comment-preserving path in the
    /// CLI rather than calling this on a hand-authored inventory file.
    pub fn save(&self, cloud_dir: &Path) -> Result<()> {
        let dir = cloud_dir.join("machines");
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(format!("{}.toml", self.name));
        let mut normalized = self.clone();
        normalized.normalize();
        let s = toml::to_string_pretty(&normalized)
            .with_context(|| format!("serializing machine {}", self.name))?;
        std::fs::write(&path, s).with_context(|| format!("writing {}", path.display()))
    }
}

/// Host of an `http://host:port` URL iff it is a mesh (headscale) IPv4 in the
/// `100.64.0.0/10` CGNAT range. String-level rather than URL-parsed: the
/// inventory format is stable and this crate carries no URL dependency (same
/// reasoning as `fleet_metrics::extract_host` and
/// `hub::coordinator::is_loopback_url`).
fn mesh_ipv4_from_url(url: &str) -> Option<&str> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = after_scheme.split(['/', ':']).next()?;
    let ip: std::net::Ipv4Addr = host.parse().ok()?;
    let [a, b, ..] = ip.octets();
    // 100.64.0.0/10 ⇒ first octet 100, second octet 64..=127.
    (a == 100 && (64..=127).contains(&b)).then_some(host)
}

/// Declared **reach** for a BYO `static` node (no provider API). Lives under
/// `[connect]` in the machine TOML.
///
/// Reach only — how the camp gets to the box. *Permission* is a separate axis
/// that belongs to cheers' scopes (W295 §"Deliberately deferred"); the two
/// collapse in practice today (mesh membership grants everything) and the data
/// model must not fuse them, so do not add an authorization field here.
///
/// `address` and `ssh` stay whole, literal, operator-authored strings even
/// though their values often *look* derived. They are not: us-west-001 dials
/// SSH over its public IP while us-west-002 was deliberately repointed at its
/// tailnet IP (R608-F10) precisely because the LAN address is unreachable
/// off-LAN. Decomposing them into user + host and recomposing would silently
/// undo per-machine decisions like that one. `yubaba` is the field that *was*
/// derived — mesh IP plus a fixed port, rewritten by mesh-join — so that is
/// where R707-T1 cut.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ConnectSpec {
    /// Reachable IPv4/host for the box, e.g. `"45.32.194.254"`. Declared: which
    /// of a machine's several addresses the camp should use is an operator
    /// choice (public IP vs. LAN IP vs. tailnet IP).
    pub address: String,
    /// SSH target the camp dials for bootstrap + (pre-mesh) tunneled deploys,
    /// e.g. `"root@45.32.194.254"` or `"struc@100.64.0.4"`. Uses the operator's
    /// `~/.ssh/yah` key. Declared, whole — see the type doc.
    pub ssh: String,
    /// Port yubaba listens on. Declared reach; defaults to 7443 when omitted,
    /// which is every machine in the fleet today. Composed with the *observed*
    /// [`MachineRegistration::mesh_ipv4`] by [`MachineConfig::yubaba_url`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yubaba_port: Option<u16>,
    /// Explicit yubaba base URL, overriding the composed form.
    ///
    /// Two live uses, both genuine declarations: a pre-mesh node saying
    /// `"http://127.0.0.1:7443"` — "I have no mesh address; reach me through
    /// the SSH tunnel to `ssh`" — and any node whose yubaba is not at
    /// `mesh_ipv4:port`. A URL here whose host *is* a mesh IP is the
    /// pre-R707-T1 shape; [`MachineConfig::normalize`] lifts it into
    /// `[registration].mesh_ipv4` and clears this field so the two cannot
    /// drift apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yubaba: Option<String>,
}

/// Default yubaba listen port, used when `[connect].yubaba_port` is omitted.
pub const DEFAULT_YUBABA_PORT: u16 = 7443;

impl ConnectSpec {
    /// Declared yubaba port, defaulting to [`DEFAULT_YUBABA_PORT`].
    pub fn yubaba_port(&self) -> u16 {
        self.yubaba_port.unwrap_or(DEFAULT_YUBABA_PORT)
    }
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

    /// Tenant this service belongs to (W206 isolation axis). Absent in the
    /// service TOML → [`TenantId::singleton`], keeping single-tenant machines
    /// on one shared compose network. When a machine hosts services from two
    /// or more distinct tenants, the compose renderer (R558-T2) splits them
    /// into per-tenant `<tenant>-<tier>` networks so cross-tenant stacks on the
    /// same host are not bridged together.
    #[serde(default = "TenantId::singleton")]
    pub tenant: TenantId,
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
    /// Provenance for every entry in `machines` that came from a linked
    /// `.yah/infra/sources.toml` source rather than this camp's own
    /// `.yah/infra/machines/` (R615-F2 / W274). Keyed by
    /// [`MachineConfig::name`]; a name absent here is camp-local. Empty from
    /// [`CloudConfig::load_from_config_dir`] — see its doc for why sources
    /// don't apply to multi-root sibling trees.
    pub machine_origins: BTreeMap<String, InfraOrigin>,
    /// Same as [`machine_origins`](Self::machine_origins), keyed by
    /// [`ProviderConfig::id`].
    pub provider_origins: BTreeMap<String, InfraOrigin>,
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
        let mut providers = load_providers(&crate::paths::providers_dir(workspace_root))?;
        let services = load_services(&crate::paths::services_dir(workspace_root), workspace_root)?;
        let domains = load_domains(&crate::paths::domains_dir(workspace_root))?;

        Self::cross_ref_validate(&providers, &services, &domains)?;

        // Legacy `.yah/cloud/` reads — empty in post-B1 workspaces. Wrapped in
        // a helper so a missing tree is silent (no error, no warning).
        let cloud_dir = crate::paths::legacy_cloud_dir(workspace_root);
        let (legacy_machines, legacy_mirrors, legacy_workloads, topology, legacy_services) =
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

        // Workloads come from `.yah/infra/workloads/` (R215+). R568-T7: before
        // that path was read here, this field was populated *only* from the
        // legacy tree above — which R222-B1 emptied — so `cfg.workload(name)`
        // resolved nothing in every post-R215 camp and `yah cloud workload
        // deploy` could not find any declaration at all. The bug survived
        // because the only workloads ever deployed were forge/QED runs, which
        // build their spec in memory and never come through here. Same
        // dedupe-by-name shape as machines below: R215+ wins.
        let mut workloads = load_workloads(crate::paths::workloads_dir(workspace_root))?;
        let workload_names: std::collections::HashSet<String> =
            workloads.iter().map(|w| w.spec.name.clone()).collect();
        for w in legacy_workloads {
            if !workload_names.contains(&w.spec.name) {
                workloads.push(w);
            }
        }

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

        // R615-F2: overlay every linked `.yah/infra/sources.toml` source's
        // machines/providers UNDER what's already loaded above, so camp-local
        // (including the legacy-tree entries just merged in) always wins on a
        // name collision. `SourcesConfig::load` itself never touches the
        // network — git sources are read from `yah infra sync`'s cache
        // (R615-T3), so this call keeps `load()`'s whole offline contract.
        let sources = SourcesConfig::load(&crate::paths::infra_dir(workspace_root))?;
        let mut machine_origins = BTreeMap::new();
        let mut provider_origins = BTreeMap::new();
        overlay_infra_sources(
            workspace_root,
            &sources,
            &mut machines,
            &mut providers,
            &mut machine_origins,
            &mut provider_origins,
        );

        Ok(Self {
            workspace_root: workspace_root.to_path_buf(),
            machines,
            providers,
            machine_origins,
            provider_origins,
            services,
            domains,
            legacy_mirrors,
            workloads,
            topology,
            legacy_services,
        })
    }

    /// Load the R215+ tree (`infra/`, `services/`, `domains/`) rooted at an
    /// arbitrary config directory instead of the hardcoded `.yah/`. This is the
    /// building block for multi-root deployments (W206 config layout (b), sibling
    /// `.noisetable/` trees) — see [`crate::multi_root`]. Part of R558-F4.
    ///
    /// `config_dir` is the `.X/` directory itself (e.g. `<parent>/.noisetable`);
    /// `workspace_root` remains the camp dir (the config dir's parent) so a
    /// component's `path` reference resolves against the same tree the classic
    /// [`CloudConfig::load`] uses. The legacy `.yah/cloud/` reads are skipped —
    /// multi-root deployments are post-R215 by construction — so `legacy_*`,
    /// `workloads`, and `topology` come back empty. Machines are read from
    /// `config_dir/infra/machines` directly (sibling trees declare their own
    /// inventory or none).
    ///
    /// R615-F2 decision, explicit rather than silent: **sources.toml overlay
    /// does NOT apply here.** This function
    /// exists specifically because a multi-root sibling tree (W206 layout
    /// (b), e.g. `.noisetable/`) is a *second config root inside the same
    /// camp*, not a second camp — `config_dir` is already wherever the
    /// caller decided this tree's infra lives, and `.yah/infra/sources.toml`
    /// (singular, tied to `paths::infra_dir(workspace_root)`) has no
    /// well-defined meaning for an arbitrary `config_dir` that isn't that
    /// path. A sibling tree that wants borrowed infra declares its own
    /// `sources.toml` under whichever root actually calls
    /// [`CloudConfig::load`] for it; `machine_origins`/`provider_origins`
    /// come back empty here, not wrong — there is nothing to overlay.
    pub fn load_from_config_dir(config_dir: &Path, workspace_root: &Path) -> Result<Self> {
        let providers = load_providers(&config_dir.join("infra").join("providers"))?;
        let services = load_services(&config_dir.join("services"), workspace_root)?;
        let domains = load_domains(&config_dir.join("domains"))?;

        Self::cross_ref_validate(&providers, &services, &domains)?;

        let machines = load_dir::<MachineConfig>(config_dir.join("infra").join("machines"))?;

        Ok(Self {
            workspace_root: workspace_root.to_path_buf(),
            machines,
            providers,
            machine_origins: BTreeMap::new(),
            provider_origins: BTreeMap::new(),
            services,
            domains,
            legacy_mirrors: vec![],
            workloads: vec![],
            topology: TopologyConfig::default(),
            legacy_services: vec![],
        })
    }

    /// Cross-reference validation shared by [`CloudConfig::load`] and
    /// [`CloudConfig::load_from_config_dir`]: every mirror `providers.X.use =
    /// "<id>"` must resolve to a declared provider, and every domain route's
    /// `component = "<service>/<component-id>"` must resolve to a real component.
    fn cross_ref_validate(
        providers: &[ProviderConfig],
        services: &BTreeMap<String, ServiceWithMirrors>,
        domains: &BTreeMap<String, DomainConfig>,
    ) -> Result<()> {
        // Mirror `use = "<id>"` slots must resolve to a declared provider.
        let provider_ids: std::collections::HashSet<&str> =
            providers.iter().map(|p| p.id.as_str()).collect();
        for (svc_name, svc) in services {
            for (env, mirror) in &svc.mirrors {
                for (slot, body) in &mirror.providers {
                    if let Some(id) = body.provider_id() {
                        if !provider_ids.contains(id) {
                            anyhow::bail!(
                                "services/{svc_name}/mirrors/{env}.toml: \
                                 providers.{slot}.use = \"{id}\" — no such provider; \
                                 declare it at infra/providers/{id}.toml"
                            );
                        }
                    }
                }
            }
        }

        // Every domain route's `component = "<service>/<component-id>"` must
        // resolve to a real component.
        for (dom_name, dom) in domains {
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
                         under services/"
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
        Ok(())
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

    /// Admission: resolve the target machine for a remote [`WorkloadSpec`],
    /// honoring the R594 mesh-tag node-selector annotation
    /// (`velveteen_exec::remote::NODE_SELECTOR_MESH_TAGS_ANNOTATION` =
    /// `yah.node-selector.mesh-tags`, comma-joined).
    ///
    /// The producer side (`velveteen_exec::remote::build_workload_spec`, R594) writes
    /// `TaskLocation::RemoteAny.mesh_tags` — e.g. `[tag:build-worker, tier:x86]`
    /// from [`qed::platform::build_worker_mesh_tags`] — into the workload's
    /// annotations. This is the consumer: candidates are restricted to machines
    /// whose `mesh_tags` are a **superset** of the requested set, so an amd64
    /// build lands on the `tier:x86` build-worker (us-west-002) and an arm64
    /// build on a `tier:arm` Pi5. Declaration order in `.yah/infra/machines/`
    /// breaks ties.
    ///
    /// An absent or empty annotation means "no mesh-tag constraint" — pre-R594
    /// behavior (any node), matching [`RequiredSpec::is_unconstrained`].
    ///
    /// This is the single admission seam: R572-F5 extends it with the capacity
    /// floor (workload request fits node allocatable−committed) and
    /// repel-unless-tolerate taints by enriching [`RequiredSpec::matches`] /
    /// [`Self::resolve_machine`]. Do not fork a second selector.
    pub fn admit_workload(&self, ws: &WorkloadSpec) -> Result<&MachineConfig> {
        let req = RequiredSpec {
            mesh_tags: node_selector_mesh_tags(ws),
            // R572-F5: capacity floor from the workload's resource request.
            memory_mb: ws.resources.memory_mb,
            cpu_millis: ws.resources.cpu_millis,
            // R572-F5: taint repulsion derived from the workload's effective archetype.
            repel_archetype: Some(ws.effective_archetype()),
            // R572-F5: taint affinity from the requires-taint annotation.
            requires_taint: ws.requires_taint().map(str::to_owned),
            ..Default::default()
        };
        self.resolve_machine(&req)
    }
}

/// Parse the R594 mesh-tag node-selector off a workload's annotations into the
/// requested tag set. Absent annotation or empty value ⇒ empty vec ("no
/// constraint"). Whitespace around each comma-separated tag is trimmed and
/// empty segments are dropped, so `"tag:build-worker, tier:x86"` and
/// `"tag:build-worker,tier:x86"` parse identically.
pub fn node_selector_mesh_tags(ws: &WorkloadSpec) -> Vec<String> {
    ws.annotations
        .get(velveteen_exec::remote::NODE_SELECTOR_MESH_TAGS_ANNOTATION)
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
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

/// R555-S1: entries are sorted by file name before parsing, so "declaration
/// order in `.yah/infra/machines/` breaks ties" — the contract
/// [`CloudConfig::admit_workload`] documents — is actually true. `read_dir`
/// yields filesystem order, which is unspecified and differs between APFS and
/// a hashed-dir ext4; without the sort, *which* of two equally-matching nodes a
/// workload admits to could change when an unrelated file is added to the
/// directory. That was latent while each tag set had one match and became
/// observable the day us-west-003 joined us-west-002 on
/// `[tag:build-worker, tier:x86, os:linux]`. Same sort `load_providers` has
/// always done.
fn load_dir<T: for<'de> Deserialize<'de>>(dir: std::path::PathBuf) -> Result<Vec<T>> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("reading {}", dir.display()))?;
    entries.sort_by_key(|e| e.file_name());

    let mut items = vec![];
    for entry in entries {
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
    /// Dev-tier compute: the component runs as a kamaji-supervised host
    /// process against the operator's real workspace, no container and no
    /// build step per edit. Inline-only — it carries no credentials, and
    /// "the machine you are sitting at" is not an account to point at.
    /// See `reconciler::local_process`.
    LocalProcess,
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
    /// Dev-tier PostgreSQL — a real server speaking real pgwire on loopback,
    /// supervised by kamaji as the `yah-pg-dev` workload (W265, R584-F1). No
    /// docker daemon: the driver fetches a per-arch PostgreSQL tarball on first
    /// run and `initdb`s a cluster under `.yah/infra/state/dev/pg/`.
    ///
    /// Inline-only — it carries no credentials worth a provider file (the
    /// cluster is loopback-bound with a fixed dev password). Declared under
    /// [`MirrorConfig::drivers`], not `providers`:
    ///
    /// ```toml
    /// [drivers.pg]
    /// kind = "local-pg-dev"
    /// ```
    LocalPgDev,
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
    /// Databases this service exposes, grouped by environment (W241). Every
    /// entry becomes a data-workbench / `sql_*` catalog id of the shape
    /// `<env>:<service>:<name>` (e.g. `pond:scrabcake:main`). Optional and
    /// default-empty — services without databases omit the `[db]` table
    /// entirely.
    #[serde(default, skip_serializing_if = "DbCatalog::is_empty")]
    pub db: DbCatalog,
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

/// How to reach an external infra root (R615-F1 / W274, "linked infra
/// sources"): a filesystem link to a sibling camp's live tree, or a git
/// checkout of an extracted infra repo.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum InfraSourceKind {
    /// Filesystem link — reads the owner's live tree. The dev-loop shortcut,
    /// and the whole story until W274's "infra as its own repo" end-state.
    /// `path` is relative to *this* camp's root; infra is read from
    /// `<path>/.yah/infra/`.
    Path {
        path: String,
    },
    /// Git link — reused verbatim from [`GitSource`] (R561, "BYO git"),
    /// lifted here from "a component's code" to "a camp's infra registry."
    /// Loading stays offline (W274 §3): `yah infra sync` (R615-T3) is what
    /// clones/pulls this into `.yah/cache/infra/<owner>/`; `CloudConfig::load`
    /// only ever reads that cache, never the network.
    Git(GitSource),
}

/// Write-gate for a linked [`InfraSource`] (R615-F1 / W274).
///
/// An enum, not a bool: the two states today are "borrower renders/plans but
/// cannot reconcile" and "this camp genuinely co-administers the shared
/// root," and a future read-write-with-approval tier is a third variant, not
/// a renamed boolean.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SourceMode {
    /// Borrower can render and plan against the linked entries but cannot
    /// reconcile/mutate them — the owner remains the single manager. Default:
    /// a borrower is opt-in to write access, never opt-out of the safe state.
    #[default]
    ReadOnly,
    /// Escape hatch for a camp that genuinely co-administers a shared root.
    Manage,
}

/// One `[[source]]` entry in `.yah/infra/sources.toml` (R615-F1 / W274) — an
/// external infra root this camp borrows machines/providers from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct InfraSource {
    /// Logical owner name, badged in the Infra tab (e.g. `"yah"`). Distinct
    /// from any camp/repo name the `kind` resolves through — this is what an
    /// operator sees on a borrowed row, not a path.
    pub owner: String,
    #[serde(flatten)]
    pub kind: InfraSourceKind,
    #[serde(default)]
    pub mode: SourceMode,
    /// Optional filter — name globs or mesh-tag selectors — to borrow a
    /// subset of the source root rather than everything it declares. Empty
    /// (the default) borrows everything.
    #[serde(default)]
    pub select: Vec<String>,
}

fn default_sources_schema_version() -> u32 {
    1
}

/// `.yah/infra/sources.toml` — the ordered list of external infra roots this
/// camp borrows from (R615-F1 / W274).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct SourcesConfig {
    #[serde(default = "default_sources_schema_version")]
    pub schema_version: u32,
    /// `[[source]]` entries, in declaration order — overlay order matters
    /// when two linked sources both name the same machine (R615-F2).
    #[serde(default, rename = "source")]
    pub source: Vec<InfraSource>,
}

impl Default for SourcesConfig {
    fn default() -> Self {
        Self {
            schema_version: default_sources_schema_version(),
            source: Vec::new(),
        }
    }
}

impl SourcesConfig {
    /// Load `<infra_dir>/sources.toml`. A missing file is not an error —
    /// every camp without linked infra has none, which today is every camp —
    /// and yields an empty source list rather than `Err`.
    pub fn load(infra_dir: &Path) -> Result<Self> {
        let path = infra_dir.join("sources.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let src =
            std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))
    }
}

impl InfraSource {
    /// Human-readable descriptor of *which* source this is, for
    /// [`InfraOrigin::source`] — distinguishes two linked sources from the
    /// same owner. Never includes credentials: `GitSource.repo` is a clone
    /// URL (https/ssh), the same thing R561 already treats as safe to log,
    /// with any real secret resolved separately via `keystore://` (W274's
    /// own precedent).
    fn describe(&self) -> String {
        match &self.kind {
            InfraSourceKind::Path { path } => format!("path:{path}"),
            InfraSourceKind::Git(g) => format!("git:{}@{}", g.repo, g.r#ref),
        }
    }

    /// Resolve this source to an infra root directory (R615-F2 / W274 §3).
    /// Does no I/O and touches no network: `path` sources read the owner's
    /// live tree directly; `git` sources read wherever `yah infra sync`
    /// (R615-T3) last synced to, which may not exist yet (an unsynced git
    /// source overlays nothing, not an error — see [`load_dir_tolerant`]).
    ///
    /// `git.subdir` (reused verbatim from [`GitSource`]/R561) is honoured
    /// exactly like the component case: the checkout root when unset, or
    /// `<checkout>/<subdir>` when set — e.g. `subdir = "infra"` for a
    /// monorepo whose infra registry lives under `infra/` rather than at the
    /// clone's root. `yah infra sync` (R615-T3) clones into the *checkout*
    /// root ([`crate::paths::infra_source_cache_dir`]), never into a
    /// subdir-suffixed path, so this is the one place that appends `subdir`.
    fn infra_root(&self, workspace_root: &Path) -> std::path::PathBuf {
        match &self.kind {
            InfraSourceKind::Path { path } => workspace_root.join(path).join(".yah").join("infra"),
            InfraSourceKind::Git(g) => {
                let checkout = crate::paths::infra_source_cache_dir(workspace_root, &self.owner);
                match g.subdir.as_deref() {
                    Some(subdir) => checkout.join(subdir),
                    None => checkout,
                }
            }
        }
    }
}

/// Provenance for a [`MachineConfig`] or [`ProviderConfig`] pulled in from a
/// linked `.yah/infra/sources.toml` entry, rather than declared in this
/// camp's own `.yah/infra/` (R615-F2 / W274).
///
/// Lives in [`CloudConfig::machine_origins`] / `provider_origins`, keyed by
/// name/id, rather than as a field on `MachineConfig`/`ProviderConfig`
/// themselves: those two types are constructed by struct literal in test
/// helpers across several crates (including ones this ticket has no reason to
/// touch), so widening either shape would ripple out past this crate for no
/// semantic gain — origin is a property of *this load*, not an inherent
/// property of the machine/provider. A name absent from the map is
/// camp-local; present means borrowed, and the Infra tab (R615-F4) / reconcile
/// gating (`InfraSource::mode`, copied onto `mode` below) read it from here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct InfraOrigin {
    /// The [`InfraSource::owner`] that supplied this entry, e.g. `"yah"`.
    pub owner: String,
    /// Which source, rendered — see [`InfraSource::describe`].
    pub source: String,
    /// The write-gate that applied when this entry was overlaid — copied
    /// from [`InfraSource::mode`] so a caller holding just the machine/
    /// provider doesn't need the source list in hand to know it's borrowed
    /// read-only.
    pub mode: SourceMode,
}

/// Like [`load_dir`], but tolerant **per file**: a foreign infra root (an
/// owner's live tree, or a synced git checkout) can carry entries this
/// binary's `T` predates — noisetable's pre-migration machines used an older
/// schema than yah's, and the reverse will happen too as each side evolves
/// independently. One unparseable file on a source this camp doesn't own must
/// never sink every other entry in the same directory, let alone this camp's
/// own load (R615-F2 gotcha). Contrast [`load_dir`], which stays strict for
/// camp-local files, where a malformed TOML genuinely should be a hard error.
///
/// Returns the entries that parsed, plus `(path, error)` for every file that
/// didn't — the caller logs those, it doesn't drop them silently. A missing
/// or unreadable directory yields `(vec![], vec![])`, same "no entries" as
/// `load_dir`'s `!dir.exists()` case (an unsynced git source, or a source
/// root with no `providers/` at all, are both normal, not warnings).
fn load_dir_tolerant<T: for<'de> Deserialize<'de>>(
    dir: &Path,
) -> (Vec<T>, Vec<(std::path::PathBuf, anyhow::Error)>) {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return (Vec::new(), Vec::new());
    };
    let mut entries: Vec<_> = read_dir.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries {
        let path = entry.path();
        if path.extension().map_or(true, |e| e != "toml") {
            continue;
        }
        let parsed = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))
            .and_then(|src| {
                toml::from_str::<T>(&src).with_context(|| format!("parsing {}", path.display()))
            });
        match parsed {
            Ok(item) => items.push(item),
            Err(e) => skipped.push((path, e)),
        }
    }
    (items, skipped)
}

/// Whether a borrowed machine passes an [`InfraSource::select`] filter
/// (R615-F2 / W274). Empty `select` borrows everything. A non-empty `select`
/// entry matches either the machine's exact `name` or literal membership in
/// its `mesh_tags` — the one shape W274's own example uses
/// (`select = ["tag:cloud-runner"]`). Not a glob engine: mesh tags are
/// already flat strings compared for exact equality everywhere else in this
/// crate (see `resolve_machine_by_mesh_tags`), so a select entry is that same
/// comparison, not a new pattern language.
fn machine_matches_select(machine: &MachineConfig, select: &[String]) -> bool {
    select.is_empty()
        || select
            .iter()
            .any(|s| *s == machine.name || machine.mesh_tags.contains(s))
}

/// Overlay every linked `.yah/infra/sources.toml` source's machines and
/// providers into `machines`/`providers`, recording provenance into
/// `machine_origins`/`provider_origins` (R615-F2 / W274). Must be called
/// AFTER camp-local entries are already in both vectors and both origin maps
/// are seeded with every camp-local name/id already `HashSet`-tracked as
/// "seen": collision resolution is "first writer wins," so seeding with
/// camp-local first is what makes camp-local win over every source, and an
/// earlier source win over a later one.
///
/// `select` filters which machines a source contributes; it does not apply
/// to providers (nothing in W274 or the source ticket describes a
/// provider-scoped filter — every provider a source declares either overlays
/// whole or, on a name collision, doesn't).
fn overlay_infra_sources(
    workspace_root: &Path,
    sources: &SourcesConfig,
    machines: &mut Vec<MachineConfig>,
    providers: &mut Vec<ProviderConfig>,
    machine_origins: &mut BTreeMap<String, InfraOrigin>,
    provider_origins: &mut BTreeMap<String, InfraOrigin>,
) {
    let mut seen_machine_names: std::collections::HashSet<String> =
        machines.iter().map(|m| m.name.clone()).collect();
    let mut seen_provider_ids: std::collections::HashSet<String> =
        providers.iter().map(|p| p.id.clone()).collect();

    for source in &sources.source {
        let root = source.infra_root(workspace_root);
        let origin = InfraOrigin {
            owner: source.owner.clone(),
            source: source.describe(),
            mode: source.mode,
        };

        let (foreign_machines, skipped) = load_dir_tolerant::<MachineConfig>(&root.join("machines"));
        for (path, e) in skipped {
            tracing::warn!(
                "infra source {:?} ({}): skipping unparseable machine {}: {e:#}",
                source.owner,
                root.display(),
                path.display()
            );
        }
        for m in foreign_machines {
            if seen_machine_names.contains(&m.name) {
                continue; // camp-local, or an earlier source, already claimed this name
            }
            if !machine_matches_select(&m, &source.select) {
                continue;
            }
            seen_machine_names.insert(m.name.clone());
            machine_origins.insert(m.name.clone(), origin.clone());
            machines.push(m);
        }

        let (foreign_providers, skipped) = load_dir_tolerant::<ProviderConfig>(&root.join("providers"));
        for (path, e) in skipped {
            tracing::warn!(
                "infra source {:?} ({}): skipping unparseable provider {}: {e:#}",
                source.owner,
                root.display(),
                path.display()
            );
        }
        for p in foreign_providers {
            if seen_provider_ids.contains(&p.id) {
                continue;
            }
            seen_provider_ids.insert(p.id.clone());
            provider_origins.insert(p.id.clone(), origin.clone());
            providers.push(p);
        }
    }
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

/// A service's declared databases, grouped by environment (W241 §Sections).
/// Parsed from the `[db]` table of `service.toml`; each `[[db.<env>]]` array
/// entry names one database. The environment tag drives backend selection at
/// query time (see the data-workbench's `db.query` / the `sql_*` MCP tools):
/// `dev` = local file, `pond` = a DB inside the running pond container stack
/// (reached on a declared localhost port), `cloud` = a remote libSQL/Turso or
/// Postgres endpoint whose auth comes from an env var (never stored in TOML).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DbCatalog {
    /// Local-file SQLite databases used in dev mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dev: Vec<DevDb>,
    /// Databases running inside the pond container stack.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pond: Vec<PondDb>,
    /// Remote cloud databases (Turso, Postgres).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cloud: Vec<CloudDb>,
}

impl DbCatalog {
    /// True when no database is declared in any environment. Lets
    /// [`ServiceConfig`] skip serializing an empty `[db]` table.
    pub fn is_empty(&self) -> bool {
        self.dev.is_empty() && self.pond.is_empty() && self.cloud.is_empty()
    }
}

/// A dev-mode local SQLite database (`[[db.dev]]`). `path` is resolved
/// relative to the workspace root and opened as a local file — read/write, no
/// network, no auth.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DevDb {
    /// Logical name, unique within the service's `dev` list. Forms the `name`
    /// segment of the catalog id `dev:<service>:<name>`.
    pub name: String,
    /// On-disk SQLite path, relative to the workspace root (or absolute).
    pub path: String,
}

/// A database running inside the pond container stack (`[[db.pond]]`). The
/// pond publishes the DB on a localhost TCP port; the hub connects to
/// `127.0.0.1:<port>` when the pond is up and returns a clear error when it is
/// not. Either `port` (defaulting to a libSQL/`sqld` HTTP endpoint) or a full
/// `url` must be given.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct PondDb {
    /// Logical name, unique within the service's `pond` list.
    pub name: String,
    /// Localhost TCP port the pond publishes the DB on. Interpreted per
    /// [`kind`](Self::kind). Mutually complete with `url` (provide one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Full connection URL, overriding `port` when set (e.g. a non-localhost
    /// host or an explicit scheme).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Wire protocol the pond DB speaks. Selects how a bare `port` becomes a
    /// URL: `turso` → `http://127.0.0.1:<port>` (libSQL/`sqld` over Hrana),
    /// `postgres` → `postgres://127.0.0.1:<port>`.
    #[serde(default)]
    pub kind: PondDbKind,
}

/// Wire protocol of a [`PondDb`].
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum PondDbKind {
    /// libSQL / `sqld` over Hrana HTTP — the default.
    #[default]
    Turso,
    /// PostgreSQL wire protocol.
    Postgres,
}

/// A remote cloud database (`[[db.cloud]]`). The connection `url` is stored in
/// TOML but the credential never is — `auth_token_env` names an environment
/// variable the daemon reads at connect time, so the same declaration works
/// whether the token is provisioned service-locally or camp-shared (W241;
/// operator confirmed both scopes are needed). A camp-wide cloud DB not owned
/// by any single service is declared identically in `.yah/db/cloud.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudDb {
    /// Logical name, unique within its `cloud` list.
    pub name: String,
    /// Connection URL: `libsql://…` / `http(s)://…` (Turso, `sqld`) or
    /// `postgres://…`.
    pub url: String,
    /// Name of the environment variable holding the auth token. Resolved in
    /// the daemon at connect time (value never stored on disk). For a libSQL
    /// URL the token is threaded as `?auth_token=…`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token_env: Option<String>,
}

/// A camp-shared cloud database catalog, parsed from `.yah/db/cloud.toml`.
/// These are cloud DBs not owned by any single service — declared once at camp
/// scope and addressed as `cloud:<name>` (two-segment id), distinct from a
/// service-local `cloud:<service>:<name>`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CampCloudDbs {
    #[serde(default, rename = "cloud", skip_serializing_if = "Vec::is_empty")]
    pub cloud: Vec<CloudDb>,
}

impl CampCloudDbs {
    /// Load `<camp_root>/.yah/db/cloud.toml`, or an empty catalog if the file
    /// is absent (the common case — most camps declare no shared cloud DBs).
    pub fn load(camp_root: &Path) -> Result<Self> {
        let path = camp_root.join(".yah/db/cloud.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let src = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))
    }
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

/// Which public-ingress provider fronts this mirror's compute (W267, R594-F11).
///
/// Both arms answer exactly one question — *given these local workload ports,
/// make them publicly reachable at these hostnames* — and they differ only in
/// where the ingress rules live and who supervises the front door:
///
/// | | [`CloudflareTunnel`](Self::CloudflareTunnel) | [`Passway`](Self::Passway) |
/// |---|---|---|
/// | Ingress rules live | Cloudflare's API (token-form tunnels are remotely-managed) | the pingora `Backends` set in the proxy process |
/// | How they get there | an API call per deployed workload | passway polls `GET /service-records?ready=true` |
/// | Front door lifecycle | a kamaji-supervised `cloudflared` appliance | a kamaji-supervised passway appliance |
///
/// Flipping this field is the whole tier ladder: rented edge → sovereign edge
/// is a one-line mirror edit, not a rewrite. The provider owns **addressing**
/// and never **rendering** — the W173 render cube stays in mesofact's manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum IngressProvider {
    /// No public front door for this mirror. The default: a mirror that
    /// publishes to R2 behind a Worker, or a mesh-only compute tier, has no
    /// ingress provider to reconcile.
    #[default]
    None,
    /// Rented edge — `cloudflared` dials *out* from the node to Cloudflare's
    /// edge. Zero inbound ports, no TLS to manage on the box, hostname rules
    /// held in Cloudflare's API.
    CloudflareTunnel,
    /// Sovereign edge — passway terminates TLS on the node and load-balances
    /// an upstream set discovered from yubaba's service records.
    Passway,
}

impl IngressProvider {
    /// `true` when this mirror declares a front door that has to be reconciled.
    pub fn is_declared(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Kebab-case wire name, as it appears in `mirrors/<env>.toml`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CloudflareTunnel => "cloudflare-tunnel",
            Self::Passway => "passway",
        }
    }
}

/// A service mirror — the projection of a [`ServiceConfig`] onto concrete
/// infra. Lives at `.yah/services/<svc>/mirrors/<env>.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MirrorConfig {
    pub schema_version: u32,
    pub shape: MirrorShape,
    /// Public-ingress provider fronting this mirror (W267). Defaults to
    /// [`IngressProvider::None`].
    ///
    /// Declared at mirror scope rather than per provider slot because a front
    /// door does **fan-in**: one `cloudflared` (or one passway) on a node
    /// multiplexes every hostname→port rule the mirror needs, so pinning it to
    /// a single slot would mint one edge connection per slot for no gain.
    #[serde(default, skip_serializing_if = "not_declared")]
    pub ingress: IngressProvider,
    /// Provider slots, keyed by role (`"static"`, `"compute"`, …). Each value
    /// either references a provider declared under `.yah/infra/providers/` or
    /// inlines a local-only provider (no creds, no infra file).
    #[serde(default)]
    pub providers: BTreeMap<String, MirrorProviderSlot>,
    /// Capability→driver bindings, keyed by **capability** (`"pg"`, `"s3"`, …)
    /// rather than by slot role (W265 §Drivers).
    ///
    /// This is the generalization of [`Self::providers`]: `providers.static` /
    /// `providers.object_store` are the special case where the slot name and
    /// the capability happen to coincide, and keying by capability is what stops
    /// the slot enum growing one arm per tier-specific implementation. A service
    /// says "I need pg"; the mirror says which implementation of pg *this tier*
    /// uses; the app talks the same wire protocol either way and never forks.
    ///
    /// ```toml
    /// [drivers.pg]
    /// kind = "local-pg-dev"     # dev  — kamaji-supervised loopback postgres
    /// ```
    ///
    /// Additive in P1: `drivers` lands *alongside* `providers`, and migrating
    /// the existing `providers.static` / `providers.object_store` declarations
    /// over is a separate pass (W265 §"Open follow-ups"). A mirror that declares
    /// neither is unchanged.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub drivers: BTreeMap<String, MirrorProviderSlot>,
    /// Per-environment alias overrides for `kind = "static-asset"` components.
    ///
    /// Keys are logical names (e.g. `"whisper-default"`); values must be
    /// filenames present in the component's `workload.toml` catalog.
    /// **Resolution only** — this table may never introduce a filename absent
    /// from the catalog. Validated against the workload catalog at sync time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub asset_aliases: BTreeMap<String, String>,
}

/// `skip_serializing_if` predicate for [`MirrorConfig::ingress`] — an
/// undeclared front door round-trips as an absent key, not `ingress = "none"`.
fn not_declared(ingress: &IngressProvider) -> bool {
    !ingress.is_declared()
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
/// Hard (must-satisfy) axes, all AND-ed together:
/// - `regions` / `zones` / `providers` — *membership*: the machine's
///   `region` / `zone` / `provider` must be one of the listed values.
/// - `mesh_tags` — *superset*: the machine's `mesh_tags` must contain every
///   listed tag.
/// - `memory_mb` / `cpu_millis` — *capacity floor* (R572-F5): the machine's
///   `allocatable` budget must cover the demand. `0` = no constraint.
/// - `repel_archetype` — *taint repulsion* (R572-F5): the machine must not
///   carry the taint `"no-<archetype.taint_key()>"` for the workload's class.
///   `None` = no repulsion check.
/// - `requires_taint` — *taint affinity* (R572-F5): the machine must carry
///   this taint key (in `taints` or `mesh_tags`). `None` = no affinity.
///
/// An empty / zero / None on every axis means "no constraint on that axis".
/// A fully-unconstrained `RequiredSpec` matches every machine (see
/// [`RequiredSpec::is_unconstrained`]).
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

    /// R572-F5: minimum memory (MiB) the target node must have in its
    /// declared `allocatable` budget. `0` = no constraint. Filled by
    /// [`CloudConfig::admit_workload`] from the workload's `resources.memory_mb`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub memory_mb: u32,
    /// R572-F5: minimum CPU (millicores) the target node must have in its
    /// declared `allocatable` budget. `0` = no constraint. Filled by
    /// [`CloudConfig::admit_workload`] from the workload's `resources.cpu_millis`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cpu_millis: u32,
    /// R572-F5: effective archetype of the workload being placed. The scheduler
    /// rejects any node that carries the taint `"no-<archetype.taint_key()>"`.
    /// `None` = no repulsion check (backwards-compat for callers that don't
    /// thread a spec through).
    #[serde(skip)]
    pub repel_archetype: Option<LifecycleArchetype>,
    /// R572-F5: taint the workload requires the target node to carry
    /// (annotation `yah.placement.requires-taint`). The node must have the
    /// key in its `taints` list or `mesh_tags`. `None` = no affinity constraint.
    #[serde(skip)]
    pub requires_taint: Option<String>,
}

impl RequiredSpec {
    /// True when no axis carries a constraint — every machine matches.
    pub fn is_unconstrained(&self) -> bool {
        self.regions.is_empty()
            && self.zones.is_empty()
            && self.providers.is_empty()
            && self.mesh_tags.is_empty()
            && self.memory_mb == 0
            && self.cpu_millis == 0
            && self.repel_archetype.is_none()
            && self.requires_taint.is_none()
    }

    /// Whether `machine` satisfies every hard axis.
    ///
    /// - Membership axes (region/zone/provider): machine must carry the field
    ///   and it must appear in the constraint list.
    /// - `mesh_tags`: machine tags must be a superset of the required set.
    /// - **R572-F5 capacity floor**: `machine.allocatable.{memory,cpu}` must
    ///   cover `self.{memory,cpu}`. A machine with no `allocatable` block passes
    ///   unconditionally (capacity unknown → no constraint enforced).
    /// - **R572-F5 taint repulsion**: machine must not carry the taint
    ///   `"no-<archetype.taint_key()>"` for the workload's class.
    /// - **R572-F5 taint affinity**: if `requires_taint` is set, the machine
    ///   must carry that key in its `taints` list or `mesh_tags`.
    pub fn matches(&self, machine: &MachineConfig) -> bool {
        let member_ok = |constraint: &[String], value: Option<&str>| -> bool {
            constraint.is_empty() || value.map_or(false, |v| constraint.iter().any(|c| c == v))
        };

        // Membership + mesh-tags (pre-existing axes).
        if !member_ok(&self.regions, machine.region.as_deref())
            || !member_ok(&self.zones, machine.zone.as_deref())
            || !member_ok(&self.providers, Some(machine.provider.as_str()))
            || !self
                .mesh_tags
                .iter()
                .all(|t| machine.mesh_tags.iter().any(|mt| mt == t))
        {
            return false;
        }

        // R572-F5: capacity floor. Skipped when machine has no allocatable
        // declaration (unknown capacity → passes, consistent with pre-F5 behaviour).
        if self.memory_mb > 0 || self.cpu_millis > 0 {
            if let Some(alloc) = &machine.allocatable {
                if self.memory_mb > alloc.memory_mb || self.cpu_millis > alloc.cpu_millis {
                    return false;
                }
            }
        }

        // R572-F5: taint repulsion. A node taint "no-<archetype>" repels the
        // workload class unless it explicitly tolerates it.
        if let Some(arch) = self.repel_archetype {
            let repel_key = format!("no-{}", arch.taint_key());
            if machine.taints.iter().any(|t| *t == repel_key) {
                return false;
            }
        }

        // R572-F5: taint affinity. Machine must carry the required taint key
        // in either its `taints` list or `mesh_tags`.
        if let Some(req) = &self.requires_taint {
            let has_it = machine.taints.iter().any(|t| t == req)
                || machine.mesh_tags.iter().any(|t| t == req);
            if !has_it {
                return false;
            }
        }

        true
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
        if self.memory_mb > 0 {
            parts.push(format!("memory_mb>={}", self.memory_mb));
        }
        if self.cpu_millis > 0 {
            parts.push(format!("cpu_millis>={}", self.cpu_millis));
        }
        if let Some(arch) = self.repel_archetype {
            parts.push(format!("not-tainted(no-{})", arch.taint_key()));
        }
        if let Some(req) = &self.requires_taint {
            parts.push(format!("requires_taint={req}"));
        }
        if parts.is_empty() {
            "no constraints".to_string()
        } else {
            parts.join(" + ")
        }
    }
}

/// Which front door actually serves a domain's requests (R594-F12).
///
/// Every domain manifest must say this out loud. Before it existed the
/// difference between "R2 serves this hostname directly" and "a Worker
/// serves it" was expressed *only* by whether the file happened to carry
/// `[[routes]]` — so binding a route-carrying domain straight to R2 was
/// accepted silently and served 200s on its SSG half while losing clean
/// URLs, SPA shell fallback, deferred-route pointers and branded error
/// pages. All of those live in the Worker
/// (`oss/mesofact/packages/mesofact-edge/src/router.ts`) or in
/// mesofact-serve; an R2 custom domain has none of them.
///
/// The vocabulary mirrors `scripts/cf-apex-mode.sh` (worker | grey | orange)
/// — this moves the choice into the config where it can be checked instead
/// of living in one bash script.
///
/// A front door does **fan-in** only. The render cube (SSG / SPA / SSR /
/// deferred / 404) is mesofact's manifest, not this one — see W173 and
/// `.yah/docs/working/W267-sovereign-public-ingress.md`
/// §"Two front doors, one render contract".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum FrontDoor {
    /// Cloudflare R2 custom domain. Requests hit R2 objects with edge
    /// caching and nothing else — no clean URLs, no SPA fallback, no
    /// branded errors. Correct for a pure asset tier (W175's verdict for
    /// `cdn.yah.dev`) and wrong for anything that renders pages.
    /// Implies zero `[[routes]]` and no `worker_bundle_path`.
    BucketDirect,
    /// Cloudflare Worker generated from this manifest's route table.
    Worker,
    /// Sovereign L7 ingress — the `passway` proxy on yah-owned metal
    /// (`oss/passway`, W267). Same route table as `worker`; different
    /// machine terminates TLS.
    Passway,
}

impl FrontDoor {
    /// Whether this front door consumes the manifest's `[[routes]]` table.
    /// `bucket-direct` does not; the other two are nothing without it.
    pub fn is_route_driven(self) -> bool {
        matches!(self, FrontDoor::Worker | FrontDoor::Passway)
    }

    /// The manifest spelling, for error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            FrontDoor::BucketDirect => "bucket-direct",
            FrontDoor::Worker => "worker",
            FrontDoor::Passway => "passway",
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
    /// Which front door serves this domain (R594-F12). **Required** — a
    /// default here would silently re-create the defect the field exists to
    /// close. Cross-checked against `routes` / `worker_bundle_path` by
    /// [`DomainConfig::validate_front_door`] at load time.
    pub front_door: FrontDoor,
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
    /// Parse a single `.yah/domains/<name>.toml`, rejecting a manifest whose
    /// declared front door contradicts its route table
    /// ([`Self::validate_front_door`]).
    pub fn load(path: &Path) -> Result<Self> {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let dom: Self =
            toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
        dom.validate_front_door()
            .with_context(|| format!("validating {}", path.display()))?;
        Ok(dom)
    }

    /// R594-F12 — the front door must agree with the rest of the manifest.
    ///
    /// - `bucket-direct` is an R2 custom domain: a Worker route table would
    ///   never be consulted, so declaring one means the author expected
    ///   Worker behaviour (clean URLs, SPA fallback, branded errors) from a
    ///   surface that cannot provide it. Rejected rather than silently
    ///   ignored. Same for `worker_bundle_path` — nothing would deploy it.
    /// - `worker` / `passway` with an empty route table is a silent 404
    ///   machine: the front door exists, has nothing to serve, and every
    ///   request falls through to the catch-all.
    ///
    /// Called from [`Self::load`], so both [`CloudConfig::load`] and
    /// [`CloudConfig::load_from_config_dir`] enforce it.
    pub fn validate_front_door(&self) -> Result<()> {
        match self.front_door {
            FrontDoor::BucketDirect => {
                if let Some(route) = self.routes.first() {
                    anyhow::bail!(
                        "front_door = \"bucket-direct\" but routes[0].path = \"{}\" — \
                         an R2 custom domain never consults a route table, so this \
                         route would silently do nothing (no clean URLs, no SPA \
                         fallback, no branded errors). Set front_door = \"worker\" \
                         (or \"passway\") to keep the routes, or drop the [[routes]] \
                         to keep the bucket-direct binding.",
                        route.path
                    );
                }
                if let Some(path) = &self.worker_bundle_path {
                    anyhow::bail!(
                        "front_door = \"bucket-direct\" but worker_bundle_path = \
                         \"{path}\" — nothing deploys a Worker bundle for a domain \
                         bound straight to R2"
                    );
                }
            }
            FrontDoor::Worker | FrontDoor::Passway => {
                if self.routes.is_empty() {
                    anyhow::bail!(
                        "front_door = \"{}\" but [[routes]] is empty — a front door \
                         with no route table is a silent 404 machine. Declare at \
                         least one route, or set front_door = \"bucket-direct\" if \
                         this domain really is served straight from R2.",
                        self.front_door.as_str()
                    );
                }
            }
        }
        Ok(())
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

// ─── Service-group vault (R706 / W294) ───────────────────────────────────────

/// A camp's declaration of one cluster secret, from
/// `.yah/infra/secrets/<slug>.toml`.
///
/// This is the *authoring* side of the fleet's cluster-secret store: it names
/// where the value lives in the camp (a `fob` vault slot), what the fleet should
/// call it, and — the point of R706 — which workloads are allowed to mount it.
///
/// The declaration is not itself the enforcement point. `yah cloud secret put`
/// reads this file, seals the vault value under the cluster KEK, and ships the
/// ciphertext **with its access rule** into raft; yubaba's `ClusterResolver`
/// evaluates the rule on the node at mount time. Deleting this file does not
/// revoke anything — the record in raft is the live authority. That asymmetry is
/// deliberate: a rule that lived only in a git-tracked camp file would be
/// trivially bypassed by anyone who could reach the fleet without the camp.
///
/// ```toml
/// #:schema ../../schema/secret.toml.schema.json
/// schema_version = 1
/// name = "cheers/cloud-admin/verify-key"
/// vault_slot = "cheers-cloud-admin-verify-key"
/// description = "Ed25519 public key yah-cloud-admin verifies operator PASETOs with"
///
/// [access]
/// workloads = [{ workload = "yah-cloud-admin" }]
///
/// [target]
/// kind = "file"
/// path = "/run/secrets/cheers-verify.key"
/// mode = 0o400
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct SecretConfig {
    pub schema_version: u32,

    /// Logical cluster-secret key, as `SecretRef::Cluster { name }` spells it —
    /// e.g. `"tls/yah.dev/cert"`, `"cheers/cloud-admin/verify-key"`. May contain
    /// `/`; the file stem is a filesystem-safe slug and carries no meaning.
    pub name: String,

    /// The `fob` vault slot in this camp holding the plaintext value. Read by
    /// `yah cloud secret put` at ship time and never recorded anywhere else — in
    /// particular the value is not in this file, so the declaration is safe to
    /// commit.
    pub vault_slot: String,

    /// Human note for `yah cloud secret ls`. What this secret is and who minted
    /// it — the thing nobody remembers 6 months later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// How the vault slot's text decodes into the bytes the consumer expects.
    ///
    /// `fob` slots hold strings, but plenty of real secrets are **binary** — an
    /// Ed25519 key is exactly 32 raw bytes, and `yah-cloud-admin` rejects a key
    /// file of any other length. Without this field the only way to ship such a
    /// key would be to hope its bytes happened to be valid UTF-8, which for a
    /// random key they are not.
    ///
    /// Defaults to [`SecretEncoding::Utf8`] — the right answer for tokens,
    /// passwords, and PEM, which is most secrets.
    #[serde(default)]
    pub encoding: SecretEncoding,

    /// Who may mount it. Stamped onto the raft record verbatim.
    ///
    /// Defaults to [`SecretAccess::default`] — the deny-all empty allow-list. A
    /// declaration that forgets this field produces a secret nobody can mount,
    /// which is the correct direction to fail in.
    #[serde(default)]
    pub access: SecretAccess,

    /// Advisory: the mount shape a consuming workload should declare. Not
    /// enforced — yubaba honours whatever the `WorkloadSpec` asks for — but it
    /// lets `yah cloud secret put` print the exact `SecretMount` to paste, so
    /// the consumer and the declaration can't drift on path or mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<SecretTargetDecl>,
}

/// How a [`SecretConfig`]'s vault text becomes the bytes delivered to the
/// container (R706 / W294).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SecretEncoding {
    /// Ship the vault string's UTF-8 bytes verbatim. Tokens, passwords, PEM.
    #[default]
    Utf8,
    /// The vault string is hex; ship the decoded bytes. Use for binary key
    /// material — e.g. a raw Ed25519 key, which must land as exactly 32 bytes.
    Hex,
}

/// Advisory mount shape on a [`SecretConfig`]. Mirrors
/// `workload_spec::SecretTarget` in a TOML-friendly, externally-tagged-free
/// shape (a `kind` discriminator reads better in a hand-written manifest than
/// serde's default enum encoding).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SecretTargetDecl {
    /// Mounted as a tmpfs-backed file inside the container.
    File {
        /// Absolute path inside the container.
        path: String,
        /// Unix permission bits. Defaults to `0o400` (owner-read-only).
        #[serde(default = "default_secret_mode")]
        mode: u32,
    },
    /// Injected as an environment variable. Prefer `file` — env vars leak
    /// through subprocess environments and log dumps.
    EnvVar { name: String },
}

fn default_secret_mode() -> u32 {
    0o400
}

impl SecretTargetDecl {
    /// The `workload_spec` target this declaration describes.
    pub fn to_target(&self) -> workload_spec::SecretTarget {
        match self {
            Self::File { path, mode } => workload_spec::SecretTarget::File {
                path: path.into(),
                mode: *mode,
            },
            Self::EnvVar { name } => workload_spec::SecretTarget::EnvVar { name: name.clone() },
        }
    }
}

impl SecretConfig {
    /// Parse a single `.yah/infra/secrets/<slug>.toml`.
    pub fn load(path: &Path) -> Result<Self> {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Self =
            toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()
            .with_context(|| format!("validating {}", path.display()))?;
        Ok(cfg)
    }

    /// Load every declaration in `dir`, keyed by logical secret name. A missing
    /// directory is an empty map (a camp with no cluster secrets is normal).
    ///
    /// Two files declaring the same `name` is a hard error, not a last-writer-
    /// wins merge: they would race to define the access rule for one record, and
    /// whichever lost would look correct in git while being inert on the fleet.
    pub fn load_dir(dir: &Path) -> Result<BTreeMap<String, Self>> {
        let mut out: BTreeMap<String, Self> = BTreeMap::new();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "toml") {
                continue;
            }
            let cfg = Self::load(&path)?;
            if let Some(prev) = out.insert(cfg.name.clone(), cfg) {
                anyhow::bail!(
                    "two secret declarations both claim name {:?} (one of them is {}); \
                     a cluster secret must have exactly one declaration so its access \
                     rule has one author",
                    prev.name,
                    path.display()
                );
            }
        }
        Ok(out)
    }

    /// Reject declarations that would produce an unusable or dangerous record.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            anyhow::bail!("`name` must not be empty");
        }
        if self.vault_slot.trim().is_empty() {
            anyhow::bail!(
                "`vault_slot` must not be empty — it names the fob slot holding the value"
            );
        }
        // A deny-all rule is a *valid* record (it is the fail-closed default the
        // resolver relies on) but it is never a useful thing to deliberately
        // ship, so catching it here saves an operator the round-trip of
        // deploying a workload that mysteriously can't see its own secret.
        if let SecretAccess::Workloads(entries) = &self.access {
            if entries.is_empty() {
                anyhow::bail!(
                    "`[access]` admits nobody: list the workloads allowed to mount {:?} \
                     (e.g. `workloads = [{{ workload = \"my-service\" }}]`), or set \
                     `access = \"allow_any\"` to store it unrestricted",
                    self.name
                );
            }
            if let Some(bad) = entries.iter().find(|e| e.workload.trim().is_empty()) {
                anyhow::bail!("`[access]` entry has an empty `workload` name: {bad:?}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod secret_config_tests {
    use super::*;

    fn parse(body: &str) -> Result<SecretConfig> {
        let cfg: SecretConfig = toml::from_str(body)?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn minimal_declaration_parses_with_narrow_defaults() {
        let cfg = parse(
            r#"
schema_version = 1
name = "svc/token"
vault_slot = "svc-token"
[access]
workloads = [{ workload = "svc" }]
"#,
        )
        .unwrap();

        assert_eq!(cfg.encoding, SecretEncoding::Utf8, "text is the default");
        assert!(cfg.target.is_none());
        // The omitted tenant/namespace must narrow to the singletons, not widen
        // to a wildcard.
        assert!(cfg
            .access
            .admits(&workload_spec::secrets::SecretConsumer::workload("svc")));
        assert!(!cfg
            .access
            .admits(&workload_spec::secrets::SecretConsumer::workload("other")));
    }

    #[test]
    fn allow_any_is_spelled_as_a_bare_string() {
        // The operator-facing spelling, pinned: `access = "allow_any"`.
        let cfg = parse(
            r#"
schema_version = 1
name = "public/thing"
vault_slot = "slot"
access = "allow_any"
"#,
        )
        .unwrap();
        assert_eq!(cfg.access, SecretAccess::AllowAny);
    }

    #[test]
    fn a_declaration_with_no_access_block_is_rejected() {
        // Omitting `[access]` defaults to deny-all, which is the correct
        // *runtime* default but never a correct authoring intent — so it must
        // not silently produce a secret nobody can mount.
        let err = parse(
            r#"
schema_version = 1
name = "svc/token"
vault_slot = "svc-token"
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("admits nobody"), "got {err}");
    }

    #[test]
    fn empty_name_or_slot_is_rejected() {
        assert!(parse(
            r#"
schema_version = 1
name = ""
vault_slot = "slot"
access = "allow_any"
"#
        )
        .is_err());
        assert!(parse(
            r#"
schema_version = 1
name = "x"
vault_slot = "  "
access = "allow_any"
"#
        )
        .is_err());
    }

    #[test]
    fn target_declaration_maps_onto_the_workload_spec_type() {
        let cfg = parse(
            r#"
schema_version = 1
name = "svc/token"
vault_slot = "slot"
access = "allow_any"
[target]
kind = "file"
path = "/run/secrets/t"
"#,
        )
        .unwrap();
        match cfg.target.unwrap().to_target() {
            workload_spec::SecretTarget::File { path, mode } => {
                assert_eq!(path, std::path::PathBuf::from("/run/secrets/t"));
                assert_eq!(mode, 0o400, "owner-read-only by default");
            }
            other => panic!("expected File, got {other:?}"),
        }
    }

    #[test]
    fn load_dir_is_empty_for_a_camp_with_no_secrets() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(SecretConfig::load_dir(&tmp.path().join("nope"))
            .unwrap()
            .is_empty());
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
            arch: None,
            bucket: None,
            vendor: None,
            nickname: None,
            legacy_hostkey_fingerprint: None,
            registration: Default::default(),
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
            allocatable: None,
            taints: vec![],
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
            machine_origins: BTreeMap::new(),
            provider_origins: BTreeMap::new(),
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
    fn db_catalog_parses_all_env_blocks() {
        // W241 / R571-F8: a service.toml [db] table with dev/pond/cloud.
        let toml_src = r#"
schema_version = 1
name = "scrabcake"
domain = "scrabcake.net.yah.dev"

[[db.dev]]
name = "main"
path = "data/dev.sqlite"

[[db.pond]]
name = "main"
port = 5433

[[db.pond]]
name = "pg"
port = 5432
kind = "postgres"

[[db.cloud]]
name = "main"
url = "libsql://scrabcake.turso.io"
auth_token_env = "SCRABCAKE_TURSO_TOKEN"
"#;
        let svc: ServiceConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(svc.db.dev.len(), 1);
        assert_eq!(svc.db.dev[0].path, "data/dev.sqlite");
        assert_eq!(svc.db.pond.len(), 2);
        assert_eq!(svc.db.pond[0].port, Some(5433));
        assert_eq!(svc.db.pond[0].kind, PondDbKind::Turso); // default
        assert_eq!(svc.db.pond[1].kind, PondDbKind::Postgres);
        assert_eq!(
            svc.db.cloud[0].auth_token_env.as_deref(),
            Some("SCRABCAKE_TURSO_TOKEN")
        );
    }

    #[test]
    fn service_without_db_table_has_empty_catalog() {
        let svc: ServiceConfig =
            toml::from_str("schema_version = 1\nname = \"s\"\ndomain = \"s.dev\"\n").unwrap();
        assert!(svc.db.is_empty());
        // And an empty [db] must not appear when re-serialized.
        let out = toml::to_string(&svc).unwrap();
        assert!(
            !out.contains("[db"),
            "empty db table should be skipped: {out}"
        );
    }

    #[test]
    fn camp_shared_cloud_toml_parses() {
        let src = r#"
[[cloud]]
name = "analytics"
url = "postgres://shared/analytics"
"#;
        let shared: CampCloudDbs = toml::from_str(src).unwrap();
        assert_eq!(shared.cloud.len(), 1);
        assert_eq!(shared.cloud[0].name, "analytics");
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

    // ─── R590-F1 mesh-tag node-selector admission ───────────────────────────

    /// Build a forge WorkloadSpec carrying the R594 node-selector annotation.
    /// `selector` is the comma-joined mesh-tag set; `None` omits the annotation
    /// entirely (pre-R594 "no constraint").
    fn ws_with_selector(selector: Option<&str>) -> WorkloadSpec {
        use workload_spec::{ImageRef, TierTag};
        let mut ws = WorkloadSpec::for_forge(
            "R590-F1-test",
            ImageRef {
                registry: "docker.io".into(),
                repository: "library/busybox".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            TierTag("infra".into()),
            vec![],
        );
        if let Some(sel) = selector {
            ws.annotations.insert(
                velveteen_exec::remote::NODE_SELECTOR_MESH_TAGS_ANNOTATION.into(),
                sel.into(),
            );
        }
        ws
    }

    /// The build-worker fleet shape: one x86 node (us-west-002) and one arm
    /// node (a Pi5), both carrying `tag:build-worker`.
    fn build_worker_fleet() -> CloudConfig {
        make_empty_cfg(vec![
            make_machine("us-west-002", vec!["tag:build-worker", "tier:x86"]),
            make_machine("pi5-001", vec!["tag:build-worker", "tier:arm"]),
        ])
    }

    #[test]
    fn admit_workload_routes_amd64_to_x86_worker() {
        let cfg = build_worker_fleet();
        let ws = ws_with_selector(Some("tag:build-worker,tier:x86"));
        let picked = cfg.admit_workload(&ws).unwrap();
        assert_eq!(picked.name, "us-west-002");
    }

    #[test]
    fn admit_workload_routes_arm64_to_pi5_worker() {
        let cfg = build_worker_fleet();
        let ws = ws_with_selector(Some("tag:build-worker,tier:arm"));
        let picked = cfg.admit_workload(&ws).unwrap();
        assert_eq!(picked.name, "pi5-001");
    }

    #[test]
    fn admit_workload_rejects_node_missing_required_tag() {
        // Only an arm worker exists; an x86 build must NOT land on it.
        let cfg = make_empty_cfg(vec![make_machine(
            "pi5-001",
            vec!["tag:build-worker", "tier:arm"],
        )]);
        let ws = ws_with_selector(Some("tag:build-worker,tier:x86"));
        assert!(cfg.admit_workload(&ws).is_err());
    }

    /// R555-S1 regression: with TWO nodes carrying the same tag set, which one
    /// admits must be decided by *declaration order* (file name), which is the
    /// contract `admit_workload` documents — not by `read_dir` order, which is
    /// filesystem-dependent and can change when an unrelated file appears in
    /// the directory. Written creation-order-reversed so a filesystem that
    /// yields creation order (rather than sorted order) trips it without the
    /// sort in `load_dir`.
    ///
    /// Live consequence this guards: `.yah/infra/machines/` carries both
    /// us-west-002 and us-west-003 on `[tag:build-worker, tier:x86, os:linux]`,
    /// so an x86 QED offload has two equal candidates. Unstable selection means
    /// a retried build cannot be relied on to land back on the node whose
    /// working state it left behind.
    #[test]
    fn equally_matching_machines_admit_in_file_name_order() {
        let tmp = tempfile::TempDir::new().unwrap();
        let machines = tmp.path().join(".yah").join("infra").join("machines");
        std::fs::create_dir_all(&machines).unwrap();
        let toml_for = |name: &str| {
            format!(
                r#"name = "{name}"
provider = "static"
mesh_tags = ["tag:build-worker", "tier:x86"]
"#
            )
        };
        // Reverse-of-sorted creation order on purpose.
        std::fs::write(machines.join("b-second.toml"), toml_for("b-second")).unwrap();
        std::fs::write(machines.join("a-first.toml"), toml_for("a-first")).unwrap();

        let cfg = CloudConfig::load(tmp.path()).unwrap();
        assert_eq!(
            cfg.machines.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            vec!["a-first", "b-second"],
            "machines must load in file-name order, not read_dir order"
        );

        let ws = ws_with_selector(Some("tag:build-worker,tier:x86"));
        assert_eq!(cfg.admit_workload(&ws).unwrap().name, "a-first");
    }

    #[test]
    fn admit_workload_empty_selector_is_unconstrained() {
        // Absent annotation ⇒ no mesh-tag constraint ⇒ first declared machine
        // (pre-R594 behavior preserved).
        let cfg = build_worker_fleet();
        let ws = ws_with_selector(None);
        let picked = cfg.admit_workload(&ws).unwrap();
        assert_eq!(picked.name, "us-west-002");
    }

    #[test]
    fn node_selector_mesh_tags_trims_and_drops_empties() {
        let ws = ws_with_selector(Some(" tag:build-worker , tier:x86 ,"));
        assert_eq!(
            node_selector_mesh_tags(&ws),
            vec!["tag:build-worker".to_string(), "tier:x86".to_string()]
        );
        assert!(node_selector_mesh_tags(&ws_with_selector(None)).is_empty());
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
            arch: None,
            bucket: Some(BucketSpec {
                name: "test-assets-pdx-1".into(),
                public_read: false,
            }),
            vendor: None,
            nickname: None,
            legacy_hostkey_fingerprint: None,
            registration: Default::default(),
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
            allocatable: None,
            taints: vec![],
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
            tenant: TenantId::singleton(),
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
            tenant: TenantId::singleton(),
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
            tenant: TenantId::singleton(),
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
            arch: None,
            bucket: Some(BucketSpec {
                name: "noisetable-assets-pdx-1".into(),
                public_read: false,
            }),
            vendor: None,
            nickname: None,
            legacy_hostkey_fingerprint: None,
            registration: Default::default(),
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
            allocatable: None,
            taints: vec![],
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
            ExposeSpec, ImageRef, MeshExpose, MeshIdent, NamespaceId, ResourceLimits,
            RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, WorkloadSpec,
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
                cpu_millis: 512,
                ephemeral_storage_mb: 512,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            archetype: None,
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
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
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

    /// Minimal valid spec for the R215+ loader tests below. Kept as a helper so
    /// the two tests differ only in *where* the file lands, which is the whole
    /// thing under test.
    #[cfg(test)]
    fn minimal_spec(name: &str, replicas: u32) -> workload_spec::WorkloadSpec {
        use workload_spec::{
            ExposeSpec, ImageRef, MeshExpose, MeshIdent, NamespaceId, ResourceLimits,
            RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, WorkloadSpec,
        };
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.into(),
            image: ImageRef {
                registry: "cr.yah.dev".into(),
                repository: name.into(),
                tag: "v1".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".into()),
            replicas,
            command: None,
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 256,
                cpu_millis: 250,
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            archetype: None,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: workload_spec::Millis::from_secs(10),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name.into()),
                    ports: vec![4325],
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            labels: Default::default(),
            annotations: Default::default(),
        }
    }

    /// R568-T7. Workloads must load from the R215+ tree.
    ///
    /// Before the fix this function tested, `CloudConfig::load` read workloads
    /// ONLY from the pre-R215 `.yah/cloud/workloads/` — which R222-B1 emptied —
    /// so in any modern camp `cfg.workload(name)` returned `None` for every
    /// name and the entire `yah cloud workload …` surface was unreachable. The
    /// CLI's own error text has said `.yah/infra/workloads/` throughout, so the
    /// bug read as "you must have typoed the filename".
    ///
    /// Note the fixture writes NO legacy `.yah/cloud/` dir at all: that is the
    /// shape of a real post-R215 camp, and it is exactly the shape the old code
    /// could not serve.
    #[test]
    fn workloads_load_from_the_infra_tree() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let dir = crate::paths::workloads_dir(root);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("yah-cloud-admin.toml"),
            toml::to_string_pretty(&minimal_spec("yah-cloud-admin", 1)).unwrap(),
        )
        .unwrap();

        let cfg = CloudConfig::load(root).unwrap();
        assert_eq!(cfg.workloads.len(), 1);
        assert_eq!(
            cfg.workload("yah-cloud-admin").unwrap().spec.replicas,
            1,
            "a workload declared under .yah/infra/workloads/ must be resolvable by name"
        );
    }

    /// A camp mid-migration can have both trees. R215+ wins on a name
    /// collision — same precedence the machine loader applies — so moving a
    /// declaration into `.yah/infra/workloads/` takes effect immediately
    /// instead of being silently shadowed by the copy left behind.
    #[test]
    fn infra_workload_shadows_the_legacy_copy_of_the_same_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        let legacy = make_legacy_cloud_dir(root);
        std::fs::create_dir_all(legacy.join("workloads")).unwrap();
        std::fs::write(
            legacy.join("workloads/shared.toml"),
            toml::to_string_pretty(&minimal_spec("shared", 9)).unwrap(),
        )
        .unwrap();
        // Legacy-only name, to prove the old tree is still read rather than
        // replaced wholesale.
        std::fs::write(
            legacy.join("workloads/legacy-only.toml"),
            toml::to_string_pretty(&minimal_spec("legacy-only", 3)).unwrap(),
        )
        .unwrap();

        let infra = crate::paths::workloads_dir(root);
        std::fs::create_dir_all(&infra).unwrap();
        std::fs::write(
            infra.join("shared.toml"),
            toml::to_string_pretty(&minimal_spec("shared", 1)).unwrap(),
        )
        .unwrap();

        let cfg = CloudConfig::load(root).unwrap();
        assert_eq!(cfg.workloads.len(), 2, "one `shared`, plus `legacy-only`");
        assert_eq!(
            cfg.workload("shared").unwrap().spec.replicas,
            1,
            "the .yah/infra/ copy must win over the legacy one"
        );
        assert_eq!(cfg.workload("legacy-only").unwrap().spec.replicas, 3);
    }

    #[test]
    fn workload_loader_rejects_bad_spec() {
        use workload_spec::{
            ExposeSpec, ImageRef, MeshExpose, MeshIdent, NamespaceId, ResourceLimits,
            RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, WorkloadSpec,
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
                cpu_millis: 512,
                ephemeral_storage_mb: 512,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            archetype: None,
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
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
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
            ExposeSpec, ImageRef, MeshExpose, MeshIdent, NamespaceId, ResourceLimits,
            RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, WorkloadSpec,
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
                cpu_millis: 256,
                ephemeral_storage_mb: 256,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            archetype: None,
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
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
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
            arch: None,
            bucket: None,
            vendor: None,
            nickname: None,
            legacy_hostkey_fingerprint: None,
            registration: Default::default(),
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
            allocatable: None,
            taints: vec![],
        };
        machine.save(root).unwrap();

        // Simulate A4: write back the hostkey fingerprint after provision.
        // R707-T1: registration is the write target; the accessor is the read.
        machine.registration.hostkey_fingerprint = Some("SHA256:abc123".into());
        machine.save(root).unwrap();

        let reloaded: Vec<MachineConfig> = load_dir(root.join("machines")).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded[0].hostkey_fingerprint(), Some("SHA256:abc123"));
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
        // Loopback is a *declared* reach placeholder, so it stays in [connect]
        // verbatim and composes straight through (R707-T1).
        assert_eq!(c.yubaba.as_deref(), Some("http://127.0.0.1:7443"));
        assert_eq!(cfg.yubaba_url().as_deref(), Some("http://127.0.0.1:7443"));
        assert_eq!(cfg.mesh_ipv4(), None);
        // Static providers have no driver, so validate() is a no-op pass.
        assert!(!provider_has_machine_driver(&cfg.provider));
        cfg.validate().unwrap();
    }

    // ─── R707-T1: declaration / registration split ──────────────────────────

    /// The pre-split shape — top-level `hostkey_fingerprint`, mesh IP baked
    /// into `[connect].yubaba` — must keep parsing, and must read back through
    /// the accessors identically. Every machine TOML in the fleet was written
    /// this way, and other camps' inventories still are.
    #[test]
    fn legacy_shape_still_parses_and_reads_through_accessors() {
        let src = r#"
name = "us-west-001"
provider = "static"
region = "us-west"
arch = "x86_64"
mesh_tags = ["tag:cloud-runner"]
hostkey_fingerprint = "SHA256:dmpq"

[connect]
address = "15.204.89.240"
ssh = "debian@15.204.89.240"
yubaba = "http://100.64.0.1:7443"
"#;
        let cfg: MachineConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.hostkey_fingerprint(), Some("SHA256:dmpq"));
        assert_eq!(cfg.mesh_ipv4(), Some("100.64.0.1"));
        assert_eq!(cfg.yubaba_url().as_deref(), Some("http://100.64.0.1:7443"));
    }

    /// The post-split shape reads identically to the legacy one above — same
    /// three accessor answers from a file that separates the two halves. This
    /// is the "unchanged in meaning" guarantee the fleet migration rests on.
    #[test]
    fn split_shape_is_equivalent_to_legacy_shape() {
        let legacy = r#"
name = "m"
provider = "static"
mesh_tags = []
hostkey_fingerprint = "SHA256:dmpq"

[connect]
address = "15.204.89.240"
ssh = "debian@15.204.89.240"
yubaba = "http://100.64.0.1:7443"
"#;
        let split = r#"
name = "m"
provider = "static"
mesh_tags = []

[connect]
address = "15.204.89.240"
ssh = "debian@15.204.89.240"

[registration]
hostkey_fingerprint = "SHA256:dmpq"
mesh_ipv4 = "100.64.0.1"
"#;
        let old: MachineConfig = toml::from_str(legacy).unwrap();
        let new: MachineConfig = toml::from_str(split).unwrap();
        assert_eq!(old.hostkey_fingerprint(), new.hostkey_fingerprint());
        assert_eq!(old.mesh_ipv4(), new.mesh_ipv4());
        assert_eq!(old.yubaba_url(), new.yubaba_url());
    }

    /// A non-default `[connect].yubaba_port` is declared reach and composes
    /// with the observed mesh address rather than being pinned into a URL.
    #[test]
    fn declared_port_composes_with_observed_mesh_address() {
        let src = r#"
name = "m"
provider = "static"
mesh_tags = []

[connect]
address = "10.0.0.1"
ssh = "yah@10.0.0.1"
yubaba_port = 9443

[registration]
mesh_ipv4 = "100.64.0.9"
"#;
        let cfg: MachineConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.connect.as_ref().unwrap().yubaba_port(), 9443);
        assert_eq!(cfg.yubaba_url().as_deref(), Some("http://100.64.0.9:9443"));
    }

    /// R707-T6: the case no other test here exercises — a node that declares
    /// BOTH a non-loopback `[connect].yubaba` literal AND a registered
    /// `mesh_ipv4` (us-west-014's shape: mesh-joined, but its raft peers are
    /// LAN-only so the literal is what `rollout::yubaba::membership_to_nodes`
    /// needs). The declared literal must win — that's the whole point of the
    /// flip; before it, `mesh_ipv4` unconditionally won and this node's LAN
    /// URL was unreachable through `yubaba_url()`.
    #[test]
    fn a_declared_literal_wins_over_a_registered_mesh_address() {
        let src = r#"
name = "us-west-014"
provider = "static"
mesh_tags = []

[connect]
address = "192.168.10.14"
ssh = "yah@192.168.10.14"
yubaba = "http://192.168.10.14:7443"

[registration]
mesh_ipv4 = "100.64.0.6"
"#;
        let cfg: MachineConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.mesh_ipv4(), Some("100.64.0.6"), "still mesh-joined");
        assert_eq!(
            cfg.yubaba_url().as_deref(),
            Some("http://192.168.10.14:7443"),
            "the declared LAN literal must win over the registered mesh address"
        );
    }

    /// `normalize` migrates in place: the legacy fingerprint moves into
    /// `[registration]`, the mesh IP is lifted out of the URL, and the derived
    /// `[connect].yubaba` is cleared so the two halves cannot drift.
    #[test]
    fn normalize_migrates_legacy_fields_and_is_idempotent() {
        let src = r#"
name = "m"
provider = "static"
mesh_tags = []
hostkey_fingerprint = "SHA256:dmpq"

[connect]
address = "15.204.89.240"
ssh = "debian@15.204.89.240"
yubaba = "http://100.64.0.1:7443"
"#;
        let mut cfg: MachineConfig = toml::from_str(src).unwrap();
        cfg.normalize();
        assert!(cfg.legacy_hostkey_fingerprint.is_none());
        assert_eq!(
            cfg.registration.hostkey_fingerprint.as_deref(),
            Some("SHA256:dmpq")
        );
        assert_eq!(cfg.registration.mesh_ipv4.as_deref(), Some("100.64.0.1"));
        assert!(cfg.connect.as_ref().unwrap().yubaba.is_none());
        // Accessors still answer the same, and re-running changes nothing.
        assert_eq!(cfg.yubaba_url().as_deref(), Some("http://100.64.0.1:7443"));
        let once = format!("{cfg:?}");
        cfg.normalize();
        assert_eq!(once, format!("{cfg:?}"));
    }

    /// A loopback `[connect].yubaba` is a declaration ("no mesh address yet —
    /// reach me through the SSH tunnel"), not a stale observation, so
    /// `normalize` must leave it alone. us-west-003/011/013 depend on this.
    #[test]
    fn normalize_leaves_pre_mesh_loopback_declaration_intact() {
        let src = r#"
name = "m"
provider = "static"
mesh_tags = []

[connect]
address = "192.168.10.11"
ssh = "yah@192.168.10.11"
yubaba = "http://127.0.0.1:7443"
"#;
        let mut cfg: MachineConfig = toml::from_str(src).unwrap();
        cfg.normalize();
        assert_eq!(
            cfg.connect.as_ref().unwrap().yubaba.as_deref(),
            Some("http://127.0.0.1:7443")
        );
        assert!(cfg.registration.is_empty());
        assert_eq!(cfg.mesh_ipv4(), None);
    }

    /// `save` normalizes, so a legacy file that round-trips through the writer
    /// comes back on the split shape with nothing lost — the property that
    /// keeps `yah cloud machine attach` from re-emitting the old layout.
    #[test]
    fn save_writes_the_split_shape_from_a_legacy_config() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let src = r#"
name = "m"
provider = "static"
mesh_tags = []
hostkey_fingerprint = "SHA256:dmpq"

[connect]
address = "15.204.89.240"
ssh = "debian@15.204.89.240"
yubaba = "http://100.64.0.1:7443"
"#;
        let cfg: MachineConfig = toml::from_str(src).unwrap();
        cfg.save(root).unwrap();

        let written = std::fs::read_to_string(root.join("machines/m.toml")).unwrap();
        let reg_at = written
            .find("[registration]")
            .unwrap_or_else(|| panic!("no [registration] table: {written}"));
        let fp_at = written
            .find("hostkey_fingerprint")
            .unwrap_or_else(|| panic!("fingerprint dropped: {written}"));
        assert!(
            fp_at > reg_at,
            "legacy top-level field must not be re-emitted: {written}"
        );
        assert!(
            !written.contains("yubaba ="),
            "derived URL must not be re-emitted alongside mesh_ipv4: {written}"
        );

        let reloaded: MachineConfig = toml::from_str(&written).unwrap();
        assert_eq!(reloaded.hostkey_fingerprint(), Some("SHA256:dmpq"));
        assert_eq!(
            reloaded.yubaba_url().as_deref(),
            Some("http://100.64.0.1:7443")
        );
    }

    /// `[registration]` is omitted entirely for a machine nothing has been
    /// observed about — a scaffolded declaration stays clean.
    #[test]
    fn empty_registration_is_omitted_on_serialize() {
        let src = r#"
name = "m"
provider = "static"
mesh_tags = []
"#;
        let cfg: MachineConfig = toml::from_str(src).unwrap();
        assert!(cfg.registration.is_empty());
        let out = toml::to_string_pretty(&cfg).unwrap();
        assert!(!out.contains("[registration]"), "{out}");
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
            db: DbCatalog::default(),
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
            db: DbCatalog::default(),
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
            db: DbCatalog::default(),
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
            ingress: Default::default(),
            drivers: Default::default(),
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
            db: DbCatalog::default(),
        };
        svc.save(root).unwrap();
        MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::Local,
            providers: BTreeMap::new(),
            ingress: Default::default(),
            drivers: Default::default(),
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
            db: DbCatalog::default(),
        }
        .save(root)
        .unwrap();
        for env in ["prod", "local"] {
            MirrorConfig {
                schema_version: 1,
                shape: MirrorShape::Local,
                providers: BTreeMap::new(),
                ingress: Default::default(),
                drivers: Default::default(),
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
            db: DbCatalog::default(),
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
            front_door: FrontDoor::Worker,
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
front_door = "worker"
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
            front_door: FrontDoor::Worker,
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
            front_door: FrontDoor::BucketDirect,
            cdn_bucket: "yah-dev".into(),
            worker_bundle_path: None,
            routes: vec![],
        };
        dom.save(root).unwrap();
        assert!(DomainConfig::delete(root, "yah-dev").unwrap());
        assert!(!DomainConfig::delete(root, "yah-dev").unwrap());
    }

    // ---- R594-F12: front-door discriminator ------------------------------

    /// Write a raw domain manifest so the tests exercise the deserialize +
    /// validate path, not a hand-built struct that skipped serde.
    fn write_domain_toml(root: &Path, stem: &str, body: &str) {
        let dir = root.join(".yah").join("domains");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{stem}.toml")), body).unwrap();
    }

    #[test]
    fn front_door_is_required() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_marketing_service(root);
        write_domain_toml(
            root,
            "yah-dev",
            r#"
schema_version = 1
name = "yah-dev"
domain = "yah.dev"
cdn_bucket = "yah-dev"
[[routes]]
path = "/*"
mode = "static"
component = "yah-marketing/site"
"#,
        );
        let err = CloudConfig::load(root).unwrap_err().to_string();
        // serde's own missing-field message; the point is that omitting the
        // discriminator is not a silently-defaulted state.
        assert!(err.contains("yah-dev.toml"), "{err}");
    }

    #[test]
    fn bucket_direct_with_routes_is_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_marketing_service(root);
        write_domain_toml(
            root,
            "cdn-yah-dev",
            r#"
schema_version = 1
name = "cdn-yah-dev"
domain = "cdn.yah.dev"
front_door = "bucket-direct"
cdn_bucket = "yah-dev"
[[routes]]
path = "/docs/*"
mode = "static"
component = "yah-marketing/site"
"#,
        );
        let err = format!("{:#}", CloudConfig::load(root).unwrap_err());
        assert!(err.contains("front_door"), "{err}");
        assert!(err.contains("/docs/*"), "{err}");
    }

    #[test]
    fn bucket_direct_with_worker_bundle_path_is_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_domain_toml(
            root,
            "cdn-yah-dev",
            r#"
schema_version = 1
name = "cdn-yah-dev"
domain = "cdn.yah.dev"
front_door = "bucket-direct"
cdn_bucket = "yah-dev"
worker_bundle_path = ".yah/workers/cdn-yah-dev/"
"#,
        );
        let err = format!("{:#}", CloudConfig::load(root).unwrap_err());
        assert!(err.contains("worker_bundle_path"), "{err}");
    }

    #[test]
    fn worker_with_no_routes_is_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_domain_toml(
            root,
            "yah-dev",
            r#"
schema_version = 1
name = "yah-dev"
domain = "yah.dev"
front_door = "worker"
cdn_bucket = "yah-dev"
"#,
        );
        let err = format!("{:#}", CloudConfig::load(root).unwrap_err());
        assert!(err.contains("front_door = \"worker\""), "{err}");
        assert!(err.contains("404"), "{err}");
    }

    #[test]
    fn passway_with_no_routes_is_rejected_too() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_domain_toml(
            root,
            "yah-dev",
            r#"
schema_version = 1
name = "yah-dev"
domain = "yah.dev"
front_door = "passway"
cdn_bucket = "yah-dev"
"#,
        );
        let err = format!("{:#}", CloudConfig::load(root).unwrap_err());
        assert!(err.contains("front_door = \"passway\""), "{err}");
    }

    #[test]
    fn bucket_direct_without_routes_loads() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        // Exactly the shape .yah/domains/cdn-yah-dev.toml ships (W175: a pure
        // asset tier deliberately has no Worker behaviours).
        write_domain_toml(
            root,
            "cdn-yah-dev",
            r#"
schema_version = 1
name = "cdn-yah-dev"
domain = "cdn.yah.dev"
front_door = "bucket-direct"
cdn_bucket = "yah-dev"
"#,
        );
        let cfg = CloudConfig::load(root).unwrap();
        let dom = cfg.domain("cdn-yah-dev").expect("cdn-yah-dev domain");
        assert_eq!(dom.front_door, FrontDoor::BucketDirect);
        assert!(!dom.front_door.is_route_driven());
    }

    #[test]
    fn front_door_round_trips_through_save() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_marketing_service(root);
        let dom = DomainConfig {
            schema_version: 1,
            name: "yah-dev".into(),
            domain: "yah.dev".into(),
            front_door: FrontDoor::Passway,
            cdn_bucket: "yah-dev".into(),
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
        assert_eq!(
            cfg.domain("yah-dev").unwrap().front_door,
            FrontDoor::Passway
        );
    }

    // The four manifests this repo actually ships are asserted in
    // `tests/live_workspace_smoke.rs` — that's the only place with a
    // depth-agnostic path to the live `.yah/` tree and a skip path for the
    // standalone mirror checkout.

    #[test]
    fn cross_ref_bails_on_missing_service() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        // No services declared at all — component ref must fail to resolve.
        let dom = DomainConfig {
            schema_version: 1,
            name: "yah-dev".into(),
            domain: "yah.dev".into(),
            front_door: FrontDoor::Worker,
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
            front_door: FrontDoor::Worker,
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
            front_door: FrontDoor::Worker,
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
            front_door: FrontDoor::Worker,
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
front_door = "bucket-direct"
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
            front_door: FrontDoor::Worker,
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

    // ─── R572-F3: NodeAllocatable + taints ──────────────────────────────────

    #[test]
    fn machine_allocatable_round_trips() {
        let toml_src = r#"
name = "us-west-001"
provider = "static"
mesh_tags = ["tag:cloud-runner"]
[allocatable]
memory_mb = 3800
cpu_millis = 2000
"#;
        let m: MachineConfig = toml::from_str(toml_src).unwrap();
        let a = m.allocatable.as_ref().expect("allocatable should parse");
        assert_eq!(a.memory_mb, 3800);
        assert_eq!(a.cpu_millis, 2000);

        let s = toml::to_string(&m).unwrap();
        let back: MachineConfig = toml::from_str(&s).unwrap();
        let a2 = back.allocatable.as_ref().unwrap();
        assert_eq!(a2.memory_mb, 3800);
        assert_eq!(a2.cpu_millis, 2000);
    }

    #[test]
    fn machine_taints_round_trips() {
        let toml_src = r#"
name = "us-south-001"
provider = "static"
mesh_tags = ["tag:cloud-runner"]
taints = ["no-appliance"]
"#;
        let m: MachineConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(m.taints, vec!["no-appliance"]);

        let s = toml::to_string(&m).unwrap();
        let back: MachineConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.taints, vec!["no-appliance"]);
    }

    #[test]
    fn machine_allocatable_absent_is_none() {
        let toml_src = "name = \"node\"\nprovider = \"static\"\nmesh_tags = []\n";
        let m: MachineConfig = toml::from_str(toml_src).unwrap();
        assert!(m.allocatable.is_none());
        assert!(m.taints.is_empty());
    }

    #[test]
    fn machine_allocatable_skipped_when_none() {
        let m = make_machine("node", vec![]);
        let s = toml::to_string(&m).unwrap();
        assert!(
            !s.contains("allocatable"),
            "None allocatable must be omitted: {s}"
        );
        assert!(!s.contains("taints"), "empty taints must be omitted: {s}");
    }

    #[test]
    fn machine_multiple_taints_round_trip() {
        let toml_src = r#"
name = "us-west-002"
provider = "static"
mesh_tags = ["tag:build-worker"]
taints = ["no-server", "no-appliance", "no-voter"]
"#;
        let m: MachineConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(m.taints.len(), 3);
        assert!(m.taints.contains(&"no-server".to_string()));
        assert!(m.taints.contains(&"no-appliance".to_string()));
        assert!(m.taints.contains(&"no-voter".to_string()));
    }

    // ─── R572-F5: capacity floor + repel-unless-tolerate taints ─────────────

    fn make_machine_with_capacity(
        name: &str,
        memory_mb: u32,
        cpu_millis: u32,
        taints: Vec<&str>,
    ) -> MachineConfig {
        MachineConfig {
            allocatable: Some(NodeAllocatable {
                memory_mb,
                cpu_millis,
            }),
            taints: taints.into_iter().map(String::from).collect(),
            ..make_machine(name, vec![])
        }
    }

    fn server_spec(memory_mb: u32, cpu_millis: u32) -> WorkloadSpec {
        use workload_spec::{ImageRef, LifecycleArchetype, ResourceLimits, TierTag};
        let mut ws = WorkloadSpec::for_forge(
            "f5-test",
            ImageRef {
                registry: "localhost".into(),
                repository: "test".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            TierTag("infra".into()),
            vec![],
        );
        ws.archetype = Some(LifecycleArchetype::Server);
        ws.resources = ResourceLimits {
            memory_mb,
            cpu_millis,
            ephemeral_storage_mb: 0,
        };
        ws
    }

    fn appliance_spec_ws(memory_mb: u32, cpu_millis: u32) -> WorkloadSpec {
        use workload_spec::LifecycleArchetype;
        let mut ws = server_spec(memory_mb, cpu_millis);
        ws.archetype = Some(LifecycleArchetype::Appliance);
        ws
    }

    #[test]
    fn capacity_floor_rejects_undersized_node() {
        let cfg = make_empty_cfg(vec![make_machine_with_capacity("small", 256, 500, vec![])]);
        let ws = server_spec(512, 1000); // demands more than available
        assert!(cfg.admit_workload(&ws).is_err());
    }

    #[test]
    fn capacity_floor_accepts_exact_fit() {
        let cfg = make_empty_cfg(vec![make_machine_with_capacity("exact", 512, 1000, vec![])]);
        let ws = server_spec(512, 1000);
        assert_eq!(cfg.admit_workload(&ws).unwrap().name, "exact");
    }

    #[test]
    fn capacity_floor_passes_when_allocatable_absent() {
        // A machine with no allocatable block skips the capacity check (no data).
        let cfg = make_empty_cfg(vec![make_machine("no-alloc", vec![])]);
        let ws = server_spec(99999, 99999); // would exceed any real node
        assert_eq!(cfg.admit_workload(&ws).unwrap().name, "no-alloc");
    }

    #[test]
    fn taint_repulsion_blocks_appliance_on_no_appliance_node() {
        let cfg = make_empty_cfg(vec![make_machine_with_capacity(
            "south",
            1024,
            2000,
            vec!["no-appliance"],
        )]);
        let ws = appliance_spec_ws(256, 500);
        assert!(
            cfg.admit_workload(&ws).is_err(),
            "appliance must be repelled by no-appliance taint"
        );
    }

    #[test]
    fn taint_repulsion_allows_server_on_no_appliance_node() {
        // "no-appliance" only repels Appliance workloads; servers are unaffected.
        let cfg = make_empty_cfg(vec![make_machine_with_capacity(
            "south",
            1024,
            2000,
            vec!["no-appliance"],
        )]);
        let ws = server_spec(256, 500);
        assert_eq!(cfg.admit_workload(&ws).unwrap().name, "south");
    }

    #[test]
    fn taint_repulsion_job_not_blocked_by_no_server() {
        use workload_spec::LifecycleArchetype;
        let cfg = make_empty_cfg(vec![make_machine_with_capacity(
            "build-box",
            8192,
            4000,
            vec!["no-server", "no-appliance"],
        )]);
        let mut ws = server_spec(256, 500);
        ws.archetype = Some(LifecycleArchetype::Job);
        // Job only repelled by "no-job"; "no-server" and "no-appliance" don't affect it.
        assert_eq!(cfg.admit_workload(&ws).unwrap().name, "build-box");
    }

    #[test]
    fn requires_taint_affinity_blocks_placement_without_it() {
        use workload_spec::{LifecycleArchetype, PUBLIC_IP_TAINT, REQUIRES_TAINT_ANNOTATION};
        // Simulate the passway ingress appliance: requires "public-ip" taint.
        let mut ws = appliance_spec_ws(256, 512);
        ws.archetype = Some(LifecycleArchetype::Appliance);
        ws.annotations
            .insert(REQUIRES_TAINT_ANNOTATION.into(), PUBLIC_IP_TAINT.into());

        // Node without the taint: rejected.
        let cfg = make_empty_cfg(vec![make_machine_with_capacity(
            "no-pip",
            2048,
            2000,
            vec![],
        )]);
        assert!(cfg.admit_workload(&ws).is_err());

        // Node with the taint: accepted.
        let cfg = make_empty_cfg(vec![make_machine_with_capacity(
            "pub-node",
            2048,
            2000,
            vec!["public-ip"],
        )]);
        assert_eq!(cfg.admit_workload(&ws).unwrap().name, "pub-node");
    }

    #[test]
    fn w244_fleet_scenario_appliance_rejected_from_south_and_west002() {
        // Full W244 fleet table scenario:
        // us-west-001/east-001: no taints, large capacity → appliance lands here
        // us-south-001: no-appliance taint → appliance rejected
        // us-west-002: no-server, no-appliance, no-voter → appliance rejected
        let cfg = make_empty_cfg(vec![
            make_machine_with_capacity("us-south-001", 512, 1000, vec!["no-appliance"]),
            make_machine_with_capacity(
                "us-west-002",
                16384,
                8000,
                vec!["no-server", "no-appliance", "no-voter"],
            ),
            make_machine_with_capacity("us-west-001", 4096, 4000, vec![]),
        ]);
        let ws = appliance_spec_ws(256, 500);
        // Skips south (no-appliance) and west-002 (no-appliance), lands on west-001.
        assert_eq!(cfg.admit_workload(&ws).unwrap().name, "us-west-001");
    }

    #[test]
    fn w244_fleet_scenario_job_lands_on_west002_first() {
        use workload_spec::LifecycleArchetype;
        // Jobs should prefer (or at least land on) the job-only box.
        let cfg = make_empty_cfg(vec![
            make_machine_with_capacity("us-west-001", 4096, 4000, vec![]),
            make_machine_with_capacity(
                "us-west-002",
                16384,
                8000,
                vec!["no-server", "no-appliance", "no-voter"],
            ),
        ]);
        let mut ws = server_spec(256, 500);
        ws.archetype = Some(LifecycleArchetype::Job);
        // Jobs tolerate all fleet taints; west-001 comes first in declaration
        // order (greedy, no preference), which is the expected tie-break.
        let picked = cfg.admit_workload(&ws).unwrap();
        // Both are eligible (Job tolerates no-server/no-appliance/no-voter).
        assert!(
            picked.name == "us-west-001" || picked.name == "us-west-002",
            "job must land on an eligible node, got {}",
            picked.name
        );
    }

    #[test]
    fn r569_f4_macos_node_taints_keep_cloud_critical_off_but_admit_build_jobs() {
        use workload_spec::LifecycleArchetype;
        // R569-F4: the headless M2 (us-west-015) joins the fleet as a
        // build-worker but must never take cloud-critical load. It carries the
        // same repel set as the rpi/x86 build-worker pool
        // (`no-server, no-appliance, no-voter` — see
        // .yah/infra/machines/us-west-015.toml). This pins that intent: with a
        // plain cloud node available beside the Mac, every cloud-critical
        // archetype lands on the cloud node and never the Mac; build Jobs
        // (the Mac's actual purpose) remain eligible on it. `no-voter` is
        // honored separately by R569-F3's learner-only join, not by workload
        // admission — there is no "voter" workload archetype.
        let mac_taints = vec!["no-server", "no-appliance", "no-voter"];
        let fleet = || {
            make_empty_cfg(vec![
                make_machine_with_capacity("us-west-015", 24576, 8000, mac_taints.clone()),
                make_machine_with_capacity("us-west-001", 4096, 4000, vec![]),
            ])
        };

        // A cloud-critical Server workload is repelled from the Mac and lands
        // on the untainted cloud node.
        let cfg = fleet();
        assert_eq!(
            cfg.admit_workload(&server_spec(256, 500)).unwrap().name,
            "us-west-001",
            "a Server workload must never land on the no-server Mac node"
        );

        // Same for an Appliance (pinned/stateful cloud-critical) workload.
        let cfg = fleet();
        assert_eq!(
            cfg.admit_workload(&appliance_spec_ws(256, 500))
                .unwrap()
                .name,
            "us-west-001",
            "an Appliance workload must never land on the no-appliance Mac node"
        );

        // Sharpest repulsion proof: with ONLY the Mac in the fleet, a
        // cloud-critical Server workload is rejected outright — the taint keeps
        // it off even when that means nowhere to run.
        let mac_only = make_empty_cfg(vec![make_machine_with_capacity(
            "us-west-015",
            24576,
            8000,
            mac_taints.clone(),
        )]);
        assert!(
            mac_only.admit_workload(&server_spec(256, 500)).is_err(),
            "a Server workload must be repelled from a Mac-only fleet, not admitted"
        );

        // But the Mac's real job — build/forge workloads — IS admitted on it:
        // it tolerates every fleet taint (there is no `no-job`).
        let mut job = server_spec(256, 500);
        job.archetype = Some(LifecycleArchetype::Job);
        assert_eq!(
            mac_only.admit_workload(&job).unwrap().name,
            "us-west-015",
            "a build Job must still be admitted on the Mac build-worker"
        );
    }

    // ─── R615-F1: linked infra sources (`.yah/infra/sources.toml`) ─────────

    #[test]
    fn sources_load_is_empty_when_the_file_is_absent() {
        // "Every camp without linked infra has none" — which today is every
        // camp — must not be an error.
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = SourcesConfig::load(tmp.path()).unwrap();
        assert_eq!(cfg, SourcesConfig::default());
        assert!(cfg.source.is_empty());
        assert_eq!(cfg.schema_version, 1);
    }

    #[test]
    fn sources_parses_a_path_kind_exactly_like_w274s_example() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("sources.toml"),
            r#"
schema_version = 1

[[source]]
owner = "yah"
kind  = "path"
path  = "../yah"
mode  = "read-only"
"#,
        )
        .unwrap();
        let cfg = SourcesConfig::load(tmp.path()).unwrap();
        assert_eq!(cfg.source.len(), 1);
        let s = &cfg.source[0];
        assert_eq!(s.owner, "yah");
        assert_eq!(s.mode, SourceMode::ReadOnly);
        assert!(s.select.is_empty());
        match &s.kind {
            InfraSourceKind::Path { path } => assert_eq!(path, "../yah"),
            other => panic!("expected Path, got {other:?}"),
        }
    }

    #[test]
    fn sources_parses_a_git_kind_reusing_gitsource_verbatim() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("sources.toml"),
            r#"
schema_version = 1

[[source]]
owner  = "yah"
kind   = "git"
repo   = "git@github.com:yah-ai/infra.git"
ref    = "main"
subdir = "infra"
select = ["tag:cloud-runner"]
mode   = "read-only"
"#,
        )
        .unwrap();
        let cfg = SourcesConfig::load(tmp.path()).unwrap();
        assert_eq!(cfg.source.len(), 1);
        let s = &cfg.source[0];
        assert_eq!(s.select, vec!["tag:cloud-runner".to_string()]);
        match &s.kind {
            InfraSourceKind::Git(git) => {
                assert_eq!(git.repo, "git@github.com:yah-ai/infra.git");
                assert_eq!(git.r#ref, "main");
                assert_eq!(git.subdir.as_deref(), Some("infra"));
            }
            other => panic!("expected Git, got {other:?}"),
        }
    }

    #[test]
    fn sources_mode_defaults_to_read_only_and_manage_is_explicit() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("sources.toml"),
            r#"
schema_version = 1

[[source]]
owner = "a"
kind  = "path"
path  = "../a"

[[source]]
owner = "b"
kind  = "path"
path  = "../b"
mode  = "manage"
"#,
        )
        .unwrap();
        let cfg = SourcesConfig::load(tmp.path()).unwrap();
        assert_eq!(cfg.source[0].mode, SourceMode::ReadOnly, "omitted mode = read-only");
        assert_eq!(cfg.source[1].mode, SourceMode::Manage);
    }

    #[test]
    fn sources_preserves_declaration_order() {
        // Overlay order matters (R615-F2) when two sources name the same
        // machine — the list must round-trip in file order, not be reordered
        // by owner or kind.
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("sources.toml"),
            r#"
schema_version = 1

[[source]]
owner = "second"
kind  = "path"
path  = "../second"

[[source]]
owner = "first"
kind  = "path"
path  = "../first"
"#,
        )
        .unwrap();
        let cfg = SourcesConfig::load(tmp.path()).unwrap();
        let owners: Vec<&str> = cfg.source.iter().map(|s| s.owner.as_str()).collect();
        assert_eq!(owners, vec!["second", "first"]);
    }

    #[test]
    fn sources_round_trips_through_serialize() {
        let cfg = SourcesConfig {
            schema_version: 1,
            source: vec![
                InfraSource {
                    owner: "yah".into(),
                    kind: InfraSourceKind::Path {
                        path: "../yah".into(),
                    },
                    mode: SourceMode::ReadOnly,
                    select: vec![],
                },
                InfraSource {
                    owner: "yah".into(),
                    kind: InfraSourceKind::Git(GitSource {
                        repo: "git@github.com:yah-ai/infra.git".into(),
                        r#ref: "main".into(),
                        subdir: Some("infra".into()),
                    }),
                    mode: SourceMode::Manage,
                    select: vec!["tag:cloud-runner".into()],
                },
            ],
        };
        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let reloaded: SourcesConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(reloaded, cfg, "round-trip through TOML must be lossless:\n{toml_str}");
    }

    // ─── R615-F2: overlay loader in CloudConfig::load ───────────────────────

    fn write_min_machine(dir: &Path, name: &str, extra_toml: &str) {
        std::fs::create_dir_all(dir).unwrap();
        // `extra_toml` supplies `mesh_tags` when the caller cares about it;
        // otherwise default to the empty list. Never hardcode `mesh_tags`
        // here as well as in `extra_toml` -- TOML rejects a duplicate key.
        let mesh_tags = if extra_toml.contains("mesh_tags") {
            String::new()
        } else {
            "mesh_tags = []\n".to_string()
        };
        std::fs::write(
            dir.join(format!("{name}.toml")),
            format!("name = \"{name}\"\nprovider = \"static\"\n{mesh_tags}{extra_toml}"),
        )
        .unwrap();
    }

    fn write_min_provider(dir: &Path, id: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(format!("{id}.toml")),
            format!("schema_version = 1\nid = \"{id}\"\nkind = \"static\"\n"),
        )
        .unwrap();
    }

    fn write_sources_toml(camp_root: &Path, body: &str) {
        let dir = camp_root.join(".yah/infra");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sources.toml"), body).unwrap();
    }

    #[test]
    fn load_with_no_sources_toml_is_unchanged() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_min_machine(&tmp.path().join(".yah/infra/machines"), "local-1", "");
        let cfg = CloudConfig::load(tmp.path()).unwrap();
        assert_eq!(cfg.machines.len(), 1);
        assert!(cfg.machine_origins.is_empty());
        assert!(cfg.provider_origins.is_empty());
    }

    #[test]
    fn path_source_overlays_machines_and_providers_tagged_with_origin() {
        let camp = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        write_min_machine(&other.path().join(".yah/infra/machines"), "borrowed-1", "");
        write_min_provider(&other.path().join(".yah/infra/providers"), "borrowed-provider");
        write_sources_toml(
            camp.path(),
            &format!(
                "schema_version = 1\n\n[[source]]\nowner = \"other\"\nkind = \"path\"\npath = \"{}\"\n",
                other.path().display()
            ),
        );

        let cfg = CloudConfig::load(camp.path()).unwrap();
        assert_eq!(cfg.machines.len(), 1);
        assert_eq!(cfg.machines[0].name, "borrowed-1");
        assert_eq!(cfg.providers.len(), 1);
        assert_eq!(cfg.providers[0].id, "borrowed-provider");

        let origin = cfg.machine_origins.get("borrowed-1").expect("origin recorded");
        assert_eq!(origin.owner, "other");
        assert_eq!(origin.mode, SourceMode::ReadOnly);
        assert!(origin.source.starts_with("path:"));
        assert_eq!(
            cfg.provider_origins.get("borrowed-provider").unwrap().owner,
            "other"
        );
    }

    #[test]
    fn camp_local_wins_on_name_collision_and_carries_no_origin() {
        let camp = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        // Both declare a machine named "shared" -- camp-local's copy must win,
        // and it must never gain an origin tag.
        write_min_machine(&camp.path().join(".yah/infra/machines"), "shared", "");
        write_min_machine(
            &other.path().join(".yah/infra/machines"),
            "shared",
            "nickname = \"the borrowed one\"\n",
        );
        write_sources_toml(
            camp.path(),
            &format!(
                "schema_version = 1\n\n[[source]]\nowner = \"other\"\nkind = \"path\"\npath = \"{}\"\n",
                other.path().display()
            ),
        );

        let cfg = CloudConfig::load(camp.path()).unwrap();
        assert_eq!(cfg.machines.len(), 1, "the name collides, so exactly one entry");
        assert_eq!(cfg.machines[0].nickname, None, "camp-local's copy, not the borrowed one");
        assert!(
            !cfg.machine_origins.contains_key("shared"),
            "camp-local entries never carry an origin tag"
        );
    }

    #[test]
    fn an_earlier_source_wins_over_a_later_one_on_collision() {
        let camp = tempfile::TempDir::new().unwrap();
        let first = tempfile::TempDir::new().unwrap();
        let second = tempfile::TempDir::new().unwrap();
        write_min_machine(&first.path().join(".yah/infra/machines"), "dup", "");
        write_min_machine(&second.path().join(".yah/infra/machines"), "dup", "");
        write_sources_toml(
            camp.path(),
            &format!(
                "schema_version = 1\n\n[[source]]\nowner = \"first\"\nkind = \"path\"\npath = \"{}\"\n\n[[source]]\nowner = \"second\"\nkind = \"path\"\npath = \"{}\"\n",
                first.path().display(),
                second.path().display()
            ),
        );

        let cfg = CloudConfig::load(camp.path()).unwrap();
        assert_eq!(cfg.machines.len(), 1);
        assert_eq!(cfg.machine_origins.get("dup").unwrap().owner, "first");
    }

    #[test]
    fn select_filters_borrowed_machines_by_name_or_mesh_tag() {
        let camp = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        write_min_machine(&other.path().join(".yah/infra/machines"), "runner-1", "mesh_tags = [\"tag:cloud-runner\"]\n");
        write_min_machine(&other.path().join(".yah/infra/machines"), "excluded-1", "");
        write_sources_toml(
            camp.path(),
            &format!(
                "schema_version = 1\n\n[[source]]\nowner = \"other\"\nkind = \"path\"\npath = \"{}\"\nselect = [\"tag:cloud-runner\"]\n",
                other.path().display()
            ),
        );

        let cfg = CloudConfig::load(camp.path()).unwrap();
        assert_eq!(cfg.machines.len(), 1);
        assert_eq!(cfg.machines[0].name, "runner-1");
    }

    #[test]
    fn one_unparseable_foreign_machine_does_not_sink_the_rest_of_the_directory_or_the_load() {
        let camp = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        let dir = other.path().join(".yah/infra/machines");
        write_min_machine(&dir, "good", "");
        // Schema-skew gotcha: a foreign machine this binary's MachineConfig
        // can't parse at all (not just an unknown field -- MachineConfig has
        // no deny_unknown_fields, so this has to fail on a TYPE, not a name).
        std::fs::write(dir.join("bad.toml"), "name = 1\nprovider = 2\n").unwrap();
        write_sources_toml(
            camp.path(),
            &format!(
                "schema_version = 1\n\n[[source]]\nowner = \"other\"\nkind = \"path\"\npath = \"{}\"\n",
                other.path().display()
            ),
        );

        // Must not error at all -- camp-local load must never fail because a
        // source it doesn't own has one bad file.
        let cfg = CloudConfig::load(camp.path()).unwrap();
        assert_eq!(cfg.machines.len(), 1, "the good entry still loads");
        assert_eq!(cfg.machines[0].name, "good");
    }

    #[test]
    fn an_unsynced_git_source_overlays_nothing_and_is_not_an_error() {
        // No `yah infra sync` (R615-T3) has ever run, so the cache dir this
        // resolves to doesn't exist. Must be silent, not fatal.
        let camp = tempfile::TempDir::new().unwrap();
        write_sources_toml(
            camp.path(),
            "schema_version = 1\n\n[[source]]\nowner = \"yah\"\nkind = \"git\"\nrepo = \"git@github.com:yah-ai/infra.git\"\nref = \"main\"\n",
        );
        let cfg = CloudConfig::load(camp.path()).unwrap();
        assert!(cfg.machines.is_empty());
        assert!(cfg.machine_origins.is_empty());
    }

    #[test]
    fn a_synced_git_source_reads_from_the_cache_dir_not_the_repo_path() {
        // No `subdir` declared -- the checkout ROOT is the infra root.
        let camp = tempfile::TempDir::new().unwrap();
        let cache = crate::paths::infra_source_cache_dir(camp.path(), "yah");
        write_min_machine(&cache.join("machines"), "synced-1", "");
        write_sources_toml(
            camp.path(),
            "schema_version = 1\n\n[[source]]\nowner = \"yah\"\nkind = \"git\"\nrepo = \"git@github.com:yah-ai/infra.git\"\nref = \"main\"\n",
        );
        let cfg = CloudConfig::load(camp.path()).unwrap();
        assert_eq!(cfg.machines.len(), 1);
        assert_eq!(cfg.machines[0].name, "synced-1");
        assert!(cfg.machine_origins.get("synced-1").unwrap().source.starts_with("git:"));
    }

    #[test]
    fn a_git_sources_subdir_is_honoured_like_the_component_case() {
        // W274's own example declares `subdir = "infra"` for a monorepo whose
        // registry lives under a subdirectory of the clone rather than at its
        // root -- prove `infra_root` actually reads it, not just `.subdir` on
        // GitSource parsing (R615-F1 already covers that half).
        let camp = tempfile::TempDir::new().unwrap();
        let cache = crate::paths::infra_source_cache_dir(camp.path(), "yah");
        write_min_machine(&cache.join("infra").join("machines"), "subdir-1", "");
        // Also plant a decoy at the checkout root to prove the root itself is
        // NOT read when a subdir is declared.
        write_min_machine(&cache.join("machines"), "root-decoy", "");
        write_sources_toml(
            camp.path(),
            "schema_version = 1\n\n[[source]]\nowner = \"yah\"\nkind = \"git\"\nrepo = \"git@github.com:yah-ai/infra.git\"\nref = \"main\"\nsubdir = \"infra\"\n",
        );
        let cfg = CloudConfig::load(camp.path()).unwrap();
        assert_eq!(cfg.machines.len(), 1);
        assert_eq!(cfg.machines[0].name, "subdir-1");
    }

    #[test]
    fn load_from_config_dir_never_applies_sources_overlay() {
        // R615-F2's explicit decision: multi-root sibling trees don't inherit
        // the classic .yah/infra/sources.toml. Prove it rather than assert it
        // silently -- a sources.toml sitting at workspace_root/.yah/infra/
        // must NOT leak into a load_from_config_dir call even though both
        // share the same workspace_root.
        let camp = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        write_min_machine(&other.path().join(".yah/infra/machines"), "borrowed-1", "");
        write_sources_toml(
            camp.path(),
            &format!(
                "schema_version = 1\n\n[[source]]\nowner = \"other\"\nkind = \"path\"\npath = \"{}\"\n",
                other.path().display()
            ),
        );
        let sibling_config_dir = camp.path().join(".noisetable");
        std::fs::create_dir_all(&sibling_config_dir).unwrap();

        let cfg = CloudConfig::load_from_config_dir(&sibling_config_dir, camp.path()).unwrap();
        assert!(cfg.machines.is_empty(), "sources.toml must not apply here");
        assert!(cfg.machine_origins.is_empty());
    }

    // ─── R615-T5: `inherit_machines` retirement — cutover proof ────────────

    /// The successor to R615-T5's parity proof. That earlier pair of tests
    /// asserted the legacy `[infra].inherit_machines` redirect and an
    /// equivalent `kind = "path"` source resolved the same machine set, and
    /// that the two coexisted without duplicating rows. Both claims were about
    /// a mechanism that no longer exists, so they retired with it — what has
    /// to hold *now* is the other half of the same guarantee: a camp that
    /// declares only `sources.toml` resolves the shared root exactly as the
    /// redirect used to, and a stale `inherit_machines` key left behind in
    /// `camp.toml` changes nothing.
    ///
    /// That stale-key case is not hypothetical: it is precisely the state a
    /// camp is in between the code cutover and someone tidying its
    /// `camp.toml`, and a silent re-resolution there would double-count the
    /// borrowed nodes or hide their origin badge.
    #[test]
    fn a_stale_inherit_machines_key_does_not_change_what_sources_toml_resolves() {
        let shared = tempfile::TempDir::new().unwrap();
        write_min_machine(&shared.path().join(".yah/infra/machines"), "shared-node-1", "");
        write_min_machine(&shared.path().join(".yah/infra/machines"), "shared-node-2", "");

        let sources_toml = format!(
            "schema_version = 1\n\n[[source]]\nowner = \"yah\"\nkind = \"path\"\npath = \"{}\"\nmode = \"read-only\"\n",
            shared.path().display()
        );

        // Camp A: migrated cleanly — sources.toml only.
        let clean = tempfile::TempDir::new().unwrap();
        write_sources_toml(clean.path(), &sources_toml);

        // Camp B: mid-migration — same source, plus the retired key still
        // sitting in camp.toml pointing at the same root.
        let stale = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(stale.path().join(".yah")).unwrap();
        std::fs::write(
            stale.path().join(".yah/camp.toml"),
            format!(
                "[infra]\ninherit_machines = \"{}\"\n",
                shared.path().display()
            ),
        )
        .unwrap();
        write_sources_toml(stale.path(), &sources_toml);

        let via_clean = CloudConfig::load(clean.path()).unwrap();
        let via_stale = CloudConfig::load(stale.path()).unwrap();

        let names = |cfg: &CloudConfig| {
            let mut v: Vec<String> = cfg.machines.iter().map(|m| m.name.clone()).collect();
            v.sort();
            v
        };
        assert_eq!(
            names(&via_clean),
            names(&via_stale),
            "a leftover inherit_machines key must be inert — the retired redirect is gone"
        );
        assert_eq!(names(&via_clean), vec!["shared-node-1", "shared-node-2"]);

        // And both are *borrowed*, not camp-local. This is the operator-facing
        // win the stopgap could never deliver: under the old redirect these
        // resolved with no origin at all, indistinguishable from locally-owned
        // nodes.
        assert_eq!(via_clean.machine_origins.len(), 2);
        assert_eq!(via_stale.machine_origins.len(), 2);
        for origin in via_stale.machine_origins.values() {
            assert_eq!(origin.owner, "yah");
            assert_eq!(origin.mode, SourceMode::ReadOnly);
        }
    }
}
