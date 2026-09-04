//! Workspace-wide lint checks for the `.yah/` declaration tree (R470-T3).
//!
//! Every check shares one shape — walk the declarations, return a list of
//! findings, empty means clean:
//!
//! - **alias collision** ([`check_alias_collisions`]) — alias names declared
//!   in any service component's `[aliases]` block must be workspace-globally
//!   unique. Two services declaring the same alias is a consumer-site
//!   ambiguity (`yah-app.toml` says `alias = "whisper-default-ggml"` — which
//!   catalog wins?).
//! - **port collision** ([`check_port_collisions`]) — two local-tier mirror
//!   slots binding the same localhost port (R602-B4).
//! - **inert taint** ([`check_inert_taints`]) — a `taints` entry in
//!   `.yah/infra/machines/*.toml` that no scheduler path can read
//!   (W305/R742-T4).
//! - **retired arch tag** ([`check_retired_arch_tags`]) — a machine still
//!   carrying the `tier:<arch>` build-worker mesh tag R763 renamed.
//! - **unroled sovereign member**
//!   ([`check_unroled_sovereign_members`]) — a machine naming a
//!   `sovereign_group` without saying whether it votes in it (R605-F12).
//! - **LAN dial target** ([`check_lan_dial_targets`]) — a machine whose
//!   `[connect].yubaba` is an RFC1918 literal, i.e. a break-glass address
//!   sitting in the field every automated path dials (R605-T10).
//! - **ingress collation** ([`collate_workspace_ingress`]) — two services
//!   whose declared edges cannot share the node they both front through
//!   (W305/R742-F2). The only check here that is *inherently* cross-service:
//!   each service's own `yah cloud apply` sees one mirror, so a hostname
//!   claimed twice on one box is invisible from either side of it.
//!
//! What unites them: each catches a declaration that *parses*, so nothing
//! downstream complains, but which means something other than what it reads
//! as. That is the class of bug this module exists for — a hard error is the
//! type system's job, and a wrong-but-valid declaration is nobody's until
//! someone writes the lint.
//!
//! Invoked by `yah cloud validate` and as a preflight in `yah cloud apply`.
//!
//! @yah:relay(R787, "Consolidate the four .yah/infra/machines/*.toml walks in oss/yubaba/crates/cloud/src/validate.rs behind one loader")
//! @yah:status(review)
//! @yah:at(2026-08-20T05:26:41Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:notify_on(R555, "Re-run `cd oss/yubaba && cargo test -p yah-cloud --lib validate::` — it was blocked crate-wide by R555's in-flight AdmissionGrant.secrets field missing from crates/cloud/src/reconciler/lowering_golden.rs's TransformRecipe fixture (E0063), unrelated to R787's validate.rs change. Confirm the two new tests (tolerant_mode_skips_an_unparseable_toml_and_still_pairs_the_path, strict_mode_fails_the_whole_load_on_one_unparseable_toml) and the existing validate:: suite pass once that's fixed.")
//! @yah:handoff("Consolidated the four .yah/infra/machines/*.toml walks (check_inert_taints, check_retired_arch_tags, check_unroled_sovereign_members, load_machines) behind one shared load_machine_tomls(workspace_root, mode) in oss/yubaba/crates/cloud/src/validate.rs. Returns Vec<(PathBuf, MachineConfig)> per the agreed shape (Ashguard/R605-F12) so lint findings still name the file.")
//! @yah:handoff("MachineLoadMode::Tolerant preserves the three lints' existing skip-and-warn behavior; MachineLoadMode::Strict preserves load_machines' hard-fail behavior for collate_workspace_ingress's placement resolution (R772) -- no behavior change at any of the four call sites.")
//! @yah:handoff("Closed the vacuous-pass trap flagged in the ticket: added assert_machine_toml_parses(), called by write_machine, write_machine_tags, and write_sovereign_machine right after writing each fixture, so a future edit that drops a required MachineConfig field fails loudly at the helper instead of being silently skipped by the tolerant loader and producing a vacuous assert-empty pass.")
//! @yah:handoff("Added two new tests locking in the Strict/Tolerant contract directly: tolerant_mode_skips_an_unparseable_toml_and_still_pairs_the_path, strict_mode_fails_the_whole_load_on_one_unparseable_toml.")
//! @yah:handoff("R772's load_machines and R605-F12's check_unroled_sovereign_members were already landed and committed on this file before this pass (verified via git diff being empty and no live session on validate.rs at pickup) -- both were settled, so this was safe to do now rather than wait further.")
//! @yah:verify("cargo check -p yah-cloud --lib (from repo root) -- clean, 0 warnings in validate.rs (2 pre-existing unrelated warnings elsewhere: mesofact_static.rs unused imports, and one more in a different file).")
//! @yah:verify("cargo test -p yah-cloud --lib validate:: (from oss/yubaba, required for dev-deps) -- BLOCKED, not failing: E0063 missing field `secrets` in crates/cloud/src/reconciler/lowering_golden.rs's TransformRecipe fixture, caused by R555's in-flight uncommitted AdmissionGrant.secrets field in oss/qed/crates/velveteen-exec (git status confirms those files are live-modified, lowering_golden.rs is not). This is the same blocker R605-F12's own verify section recorded. Filed @yah:notify_on(R555) on this ticket so whoever reopens it re-runs the suite once R555 lands.")
//! @yah:verify("Manual read-through of the diff: every lint's iteration body (finding construction) is byte-identical to before, only the walk+parse boilerplate was extracted -- no logic changed at any of the four call sites.")
//! @yah:gotcha("Test verification for this crate is blocked camp-wide right now by R555 (live, Ashguard) -- see notify_on. Not this ticket's bug; do not attempt to fix lowering_golden.rs or velveteen-exec from here.")

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

use crate::config::{
    live_taint_keys, private_ipv4_from_url, MachineConfig, MirrorConfig, MirrorProviderSlot,
    Provider, ServiceConfig,
};
use crate::paths::{machines_dir, services_dir};

/// Where an alias is declared — points the operator at the source row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasSource {
    /// Service name (matches `service.toml`'s `name` field).
    pub service: String,
    /// Component `id` within that service.
    pub component_id: String,
    /// Absolute path to the `workload.toml` containing the `[aliases]` block.
    pub workload_toml: PathBuf,
}

/// A duplicate alias declaration found across two components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasCollision {
    pub alias: String,
    pub first: AliasSource,
    pub second: AliasSource,
}

impl AliasCollision {
    /// Human-readable error message matching the format described in W193.
    pub fn message(&self) -> String {
        format!(
            "alias {:?} declared in both {} (component {}) and {} (component {})\n\
             \u{2192} rename the alias in one of these files:\n  {}\n  {}",
            self.alias,
            self.first.service,
            self.first.component_id,
            self.second.service,
            self.second.component_id,
            self.first.workload_toml.display(),
            self.second.workload_toml.display(),
        )
    }
}

/// Walk every service's static-asset components and collect all `(alias →
/// source)` mappings. Returns a list of collisions (empty when clean).
///
/// Missing `.yah/services/` directory is not an error — returns empty.
pub fn check_alias_collisions(workspace_root: &Path) -> anyhow::Result<Vec<AliasCollision>> {
    let dir = services_dir(workspace_root);
    if !dir.exists() {
        return Ok(vec![]);
    }

    // alias_name → first source seen
    let mut seen: BTreeMap<String, AliasSource> = BTreeMap::new();
    let mut collisions = Vec::new();

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let svc_dir = entry.path();
        let service_toml = svc_dir.join("service.toml");
        if !service_toml.exists() {
            continue;
        }
        let service = match ServiceConfig::load(&service_toml) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    path = %service_toml.display(),
                    error = %e,
                    "skipping service with unparseable service.toml"
                );
                continue;
            }
        };

        for component in &service.components {
            if component.kind != "static-asset" {
                continue;
            }
            let workload_dir = workspace_root.join(&component.path);
            let workload_toml_path = workload_dir.join("workload.toml");
            if !workload_toml_path.exists() {
                continue;
            }

            let aliases = match load_static_asset_aliases(&workload_toml_path) {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(
                        path = %workload_toml_path.display(),
                        error = %e,
                        "skipping workload.toml with parse error"
                    );
                    continue;
                }
            };

            for alias_name in aliases.keys() {
                let source = AliasSource {
                    service: service.name.clone(),
                    component_id: component.id.clone(),
                    workload_toml: workload_toml_path.clone(),
                };
                if let Some(first) = seen.get(alias_name) {
                    collisions.push(AliasCollision {
                        alias: alias_name.clone(),
                        first: first.clone(),
                        second: source,
                    });
                } else {
                    seen.insert(alias_name.clone(), source);
                }
            }
        }
    }

    Ok(collisions)
}

/// Load the `[aliases]` block from a `workload.toml` that must be a
/// `static-asset` kind. Returns an empty map for non-static-asset workloads
/// (so the caller skips them silently).
fn load_static_asset_aliases(path: &Path) -> anyhow::Result<BTreeMap<String, String>> {
    let src =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let workload: workload_spec::Workload =
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
    match workload {
        workload_spec::Workload::StaticAsset(w) => Ok(w.aliases),
        _ => Ok(BTreeMap::new()),
    }
}

// ── Port collisions (R602-B4) ────────────────────────────────────────────────

/// Where a host port is declared — points the operator at the (service, env,
/// slot) that binds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSource {
    /// Service name (matches `service.toml`'s `name` field).
    pub service: String,
    /// Environment (file stem of `mirrors/<env>.toml`).
    pub env: String,
    /// Provider slot role the port sits under (`providers.<role>`).
    pub slot_role: String,
    /// The field that carried the port (`port` / `api_port` / `console_port`).
    pub field: String,
}

/// Two local-tier mirror slots that bind the same host port. Because local
/// mirrors share the operator's localhost, both binding the same port collide
/// when brought up together — and the local-static adopt probe (a bare TCP
/// connect) may then silently adopt the *wrong* service (R602-B4: `scrabcake`
/// dev and `yah-marketing` pond both on 4322).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortCollision {
    pub port: u16,
    pub first: PortSource,
    pub second: PortSource,
}

impl PortCollision {
    /// True when the two binders belong to different services — the dangerous
    /// case, because the local-static adopt probe can then silently adopt the
    /// *other* service's server. Same-service reuse (e.g. one service's dev +
    /// cloud mirrors sharing a port) is only a can't-co-run bind conflict.
    pub fn is_cross_service(&self) -> bool {
        self.first.service != self.second.service
    }

    /// Human-readable error naming both binders + the fix.
    pub fn message(&self) -> String {
        format!(
            "host port {} is bound by both {}/{} (providers.{}.{}) and {}/{} (providers.{}.{})\n\
             \u{2192} give one a distinct port — local mirrors share the operator's localhost, so \
             two slots on the same port collide, and the local-static adopt probe may silently \
             adopt the wrong service.",
            self.port,
            self.first.service,
            self.first.env,
            self.first.slot_role,
            self.first.field,
            self.second.service,
            self.second.env,
            self.second.slot_role,
            self.second.field,
        )
    }
}

/// Host-port field names a local-binding mirror slot may declare.
const PORT_FIELDS: &[&str] = &["port", "api_port", "console_port"];

/// True when this slot binds a port on the operator's localhost, so its port
/// contends with every other local slot. Reference slots (`use = "..."`) and
/// cloud/CF slots don't bind localhost and are skipped.
fn slot_binds_localhost(slot: &MirrorProviderSlot) -> bool {
    matches!(
        slot.inline_kind(),
        Some(Provider::LocalStatic | Provider::MiniflareContainer | Provider::MinioContainer)
    )
}

/// Walk every service mirror and flag host-port reuse across local-tier
/// provider slots (R602-B4). Only slots that bind a port on the operator's
/// localhost are considered (`local-static`, `miniflare-container`,
/// `minio-container`) — cloud/CF slots don't contend for localhost.
///
/// Deterministic: services + mirror envs are walked in sorted order, slot
/// roles sorted, `PORT_FIELDS` in declared order — so the "first" binder of a
/// port is stable across runs. Missing `.yah/services/` is not an error.
pub fn check_port_collisions(workspace_root: &Path) -> anyhow::Result<Vec<PortCollision>> {
    // port → first source seen
    let mut seen: BTreeMap<u16, PortSource> = BTreeMap::new();
    let mut collisions = Vec::new();

    for m in load_service_mirrors(workspace_root)? {
        let mut roles: Vec<&String> = m.mirror.providers.keys().collect();
        roles.sort();
        for role in roles {
            let slot = &m.mirror.providers[role];
            if !slot_binds_localhost(slot) {
                continue;
            }
            for field in PORT_FIELDS {
                let Some(port) = crate::reconciler::slot_field_u16(slot.fields(), field) else {
                    continue;
                };
                let source = PortSource {
                    service: m.service.clone(),
                    env: m.env.clone(),
                    slot_role: role.clone(),
                    field: (*field).to_string(),
                };
                match seen.get(&port) {
                    Some(first) => collisions.push(PortCollision {
                        port,
                        first: first.clone(),
                        second: source,
                    }),
                    None => {
                        seen.insert(port, source);
                    }
                }
            }
        }
    }

    Ok(collisions)
}

// ── Shared machine-TOML loader (R787) ───────────────────────────────────────

/// How [`load_machine_tomls`] handles a `.yah/infra/machines/*.toml` that
/// fails to read or parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineLoadMode {
    /// Skip the file with a `tracing::warn!` and continue — the lint sweeps'
    /// existing behavior. A peer's half-written scaffold on a shared tree
    /// must not blind the sweep to every other finding it would report.
    Tolerant,
    /// Fail the whole load on the first read/parse error — for callers where
    /// silently dropping a machine could produce a wrong-but-successful
    /// result, e.g. [`collate_workspace_ingress`] resolving a `required`
    /// placement constraint onto a node that isn't actually a candidate.
    Strict,
}

/// Every `.yah/infra/machines/*.toml`, paired with the path that declared it
/// — every lint finding names the file the operator opens, and
/// [`collate_workspace_ingress`]'s placement resolution has no use for the
/// path but takes it anyway rather than forcing a second loader to exist.
///
/// Missing `.yah/infra/machines/` is not an error — a fresh camp declares no
/// nodes. Files are walked in sorted-filename order so callers that report
/// findings (or resolve a first match) are deterministic across runs.
pub fn load_machine_tomls(
    workspace_root: &Path,
    mode: MachineLoadMode,
) -> anyhow::Result<Vec<(PathBuf, MachineConfig)>> {
    let dir = machines_dir(workspace_root);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "toml"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let path = entry.path();
        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if mode == MachineLoadMode::Tolerant => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unreadable machine toml");
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let machine: MachineConfig = match toml::from_str(&src) {
            Ok(m) => m,
            Err(e) if mode == MachineLoadMode::Tolerant => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unparseable machine toml");
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("parsing {}", path.display())),
        };
        out.push((path, machine));
    }
    Ok(out)
}

// ── R742-T4 (W305): inert node taints ──────────────────────────────────────

/// A declared node taint no placement decision can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InertTaint {
    /// Machine name as declared in the TOML.
    pub machine: String,
    /// Path to the declaring `.yah/infra/machines/<name>.toml`.
    pub machine_toml: PathBuf,
    /// The offending key.
    pub key: String,
}

impl InertTaint {
    pub fn message(&self) -> String {
        format!(
            "machine {:?} declares the taint {:?}, which no placement decision can read\n\
             \u{2192} a taint fires in exactly two ways: as repulsion \
             (`no-server` / `no-appliance` / `no-job`, an absolute block on that archetype), \
             or as affinity (a key a workload names in `yah.placement.requires-taint`).\n\
             \u{2192} legal keys today: {}\n\
             \u{2192} if this is a *fact* about the node rather than a placement input, \
             move it to `mesh_tags` or a comment; if it should really constrain placement, \
             add it to cloud::config::AFFINITY_TAINT_KEYS together with the workload that \
             requires it.\n  {}",
            self.machine,
            self.key,
            live_taint_keys().join(", "),
            self.machine_toml.display(),
        )
    }
}

/// Flag every taint in `.yah/infra/machines/*.toml` that the scheduler cannot
/// act on (W305 finding 1 / R742-T4).
///
/// Why this is a *lint* and not a parse error: an inert taint breaks nothing.
/// It changes no placement decision — that is the entire complaint. Refusing
/// to deserialize would make an unrelated `yah cloud machine status` fail on a
/// cosmetic problem, so the judgement is made where the operator asks for it.
///
/// **Camp-local machines only.** [`machines_dir`] is deliberately not the
/// merged view `CloudConfig::load` builds from `.yah/infra/sources.toml` — a
/// borrowed machine is declared in someone else's tree, where this camp cannot
/// fix it, and a lint that cannot be resolved is noise that trains the
/// operator to ignore the whole check.
///
/// Missing `.yah/infra/machines/` is not an error — a fresh camp declares no
/// nodes. Unparseable files are skipped with a warning rather than aborting
/// the sweep, matching [`check_port_collisions`]; whatever is wrong with them
/// is a bigger problem than a taint key and surfaces on the load path.
pub fn check_inert_taints(workspace_root: &Path) -> anyhow::Result<Vec<InertTaint>> {
    let mut found = Vec::new();
    for (path, machine) in load_machine_tomls(workspace_root, MachineLoadMode::Tolerant)? {
        for key in machine.inert_taints() {
            found.push(InertTaint {
                machine: machine.name.clone(),
                machine_toml: path.clone(),
                key: key.to_string(),
            });
        }
    }
    Ok(found)
}

// ── R763 (W314): the retired `tier:` arch mesh tag ─────────────────────────

/// The mesh-tag prefix that used to carry a build-worker's CPU architecture.
/// Retired 2026-08-14 — the value was an architecture, not a tier, and it was
/// squatting a prefix the environment axis wants.
const RETIRED_ARCH_TAG_PREFIX: &str = "tier:";
/// What it became. [`qed::platform::build_worker_mesh_tags`] emits this.
const ARCH_TAG_PREFIX: &str = "arch:";

/// A machine still declaring the retired `tier:<arch>` build-worker mesh tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetiredArchTag {
    pub machine: String,
    pub machine_toml: PathBuf,
    /// The offending tag, verbatim (e.g. `tier:x86`).
    pub tag: String,
}

impl RetiredArchTag {
    /// The replacement tag — same value, current prefix.
    pub fn replacement(&self) -> String {
        format!(
            "{ARCH_TAG_PREFIX}{}",
            self.tag.trim_start_matches(RETIRED_ARCH_TAG_PREFIX)
        )
    }

    pub fn message(&self) -> String {
        format!(
            "machine {:?} declares the retired mesh tag {:?} — rename it to {:?}\n\
             \u{2192} `tier:x86` / `tier:arm` were renamed to `arch:x86` / `arch:arm` \
             (R763): the value is a CPU architecture, not a tier, and `tier:` is \
             reserved for the environment axis.\n\
             \u{2192} this does not fail loudly on its own, which is why it is checked \
             here: `qed::platform::build_worker_mesh_tags` now requests `arch:<arch>`, \
             and placement is SUPERSET matching, so a node still carrying the old tag \
             simply stops matching and the build reports 'no node' instead of \
             'wrong tag'.\n  {}",
            self.machine,
            self.tag,
            self.replacement(),
            self.machine_toml.display(),
        )
    }
}

/// Flag every machine still carrying a `tier:<arch>` build-worker mesh tag.
///
/// Same lint family, and the same camp-local-only scoping, as
/// [`check_inert_taints`] — but note the failure it catches is *quieter* than
/// an inert taint. An inert taint changes no decision; a stale arch tag changes
/// the decision to "no candidate node", and the operator sees a placement
/// failure with no hint that a tag rename caused it.
pub fn check_retired_arch_tags(workspace_root: &Path) -> anyhow::Result<Vec<RetiredArchTag>> {
    let mut found = Vec::new();
    for (path, machine) in load_machine_tomls(workspace_root, MachineLoadMode::Tolerant)? {
        for tag in machine
            .mesh_tags
            .iter()
            .filter(|t| t.starts_with(RETIRED_ARCH_TAG_PREFIX))
        {
            found.push(RetiredArchTag {
                machine: machine.name.clone(),
                machine_toml: path.clone(),
                tag: tag.clone(),
            });
        }
    }
    Ok(found)
}

// ── R605-F12: a group stamp with no role beside it ─────────────────────────

/// A machine declaring `sovereign_group` without an explicit `sovereign_role`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnroledSovereignMember {
    pub machine: String,
    pub machine_toml: PathBuf,
    /// The group it declares — named in the message because the answer to
    /// "voter or not" depends on which blast radius is being joined.
    pub group: String,
}

impl UnroledSovereignMember {
    pub fn message(&self) -> String {
        format!(
            "machine {:?} declares `sovereign_group = {:?}` but no `sovereign_role`\n\
             \u{2192} membership and quorum eligibility are separate axes (R605-F12): a node can \
             be inside a group's blast radius — its secrets, its upgrade cadence, its \
             destruction — and still never hold a seat in its quorum.\n\
             \u{2192} an absent role reads as `\"voter\"`, so this box is quorum-eligible today. \
             That is the pre-R605-F12 meaning and is often right; the complaint is that nothing \
             records whether anyone decided it.\n\
             \u{2192} add `sovereign_role = \"voter\"` or `sovereign_role = \"non-voter\"` as a \
             TOP-LEVEL key (below a `[table]` header TOML makes it a field of that table, and \
             every consumer reads it as absent).\n  {}",
            self.machine,
            self.group,
            self.machine_toml.display(),
        )
    }
}

/// Flag every machine that names a sovereign group without saying whether it
/// votes in it (R605-F12).
///
/// Same lint family and the same camp-local-only scoping as
/// [`check_inert_taints`], for a failure one step quieter than either of the
/// others: an inert taint changes no decision and a stale arch tag changes it
/// to "no candidate node", but an unwritten role changes nothing *visible* and
/// silently grants a quorum seat. That is exactly the shape this ticket was
/// opened about — a guarantee resting on which fields happen to be absent — so
/// closing it by making the *other* absence load-bearing would have been the
/// same bug with the sign flipped.
///
/// Why a lint rather than a required field: [`MachineConfig`] is deserialized
/// from foreign trees too (`.yah/infra/sources.toml` overlays another camp's
/// machines, which may predate this field entirely), and a hard parse error
/// there is unfixable from here. The judgement is made where the operator asks
/// for it, against machines this camp can actually edit.
pub fn check_unroled_sovereign_members(
    workspace_root: &Path,
) -> anyhow::Result<Vec<UnroledSovereignMember>> {
    let mut found = Vec::new();
    for (path, machine) in load_machine_tomls(workspace_root, MachineLoadMode::Tolerant)? {
        if let (Some(group), None) = (&machine.sovereign_group, &machine.sovereign_role) {
            found.push(UnroledSovereignMember {
                machine: machine.name.clone(),
                machine_toml: path.clone(),
                group: group.clone(),
            });
        }
    }
    Ok(found)
}

// ── R605-T10: a LAN literal in the field automation dials ──────────────────

/// A machine whose `[connect].yubaba` points at an RFC1918 private address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanDialTarget {
    pub machine: String,
    pub machine_toml: PathBuf,
    /// The offending URL, verbatim (e.g. `http://192.168.10.11:7443`).
    pub url: String,
    /// The registered mesh address, when the box has one — the difference
    /// between "delete a line" and "go join the mesh first".
    pub mesh_ipv4: Option<String>,
}

impl LanDialTarget {
    pub fn message(&self) -> String {
        let fix = match &self.mesh_ipv4 {
            Some(ip) => format!(
                "\u{2192} this box IS mesh-joined at {ip}: DELETE the `yubaba` line. \
                 `[registration].mesh_ipv4` composes with `[connect].yubaba_port` on its own, \
                 and `[connect].address` already records the LAN address as metadata."
            ),
            None => "\u{2192} this box has no `[registration].mesh_ipv4`: mesh-join it and record \
                     the tailnet address, or taint it out of placement. Until then it is \
                     unresolvable to automation and `MachineConfig::reach` refuses it by name."
                .to_string(),
        };
        format!(
            "machine {:?} declares `[connect].yubaba = {:?}` — a LAN address in the field every \
             automated path dials\n\
             \u{2192} the LAN address is an emergency break-glass route, never an official one \
             (R605-T10, operator 2026-08-19). Automation ALWAYS assumes the caller is not on that \
             LAN, and this camp genuinely is not — it sits on 192.168.22.0/22 with no route to \
             192.168.10.0/24.\n\
             \u{2192} it does not sit beside the mesh route, it OVERRODE it: before this check, a \
             declared literal beat `[registration].mesh_ipv4` outright (R707-T6), so a healthy \
             mesh-joined build worker was elected and then dialed at an address only its own \
             building can reach.\n\
             {fix}\n\
             \u{2192} keeping the LAN address is fine and wanted — in `[connect].address` and \
             `[connect].ssh`, which no resolver dials. A manual SSH session may use it once a \
             human confirms they are on that LAN.\n  {}",
            self.machine,
            self.url,
            self.machine_toml.display(),
        )
    }
}

/// Flag every machine that has put a LAN literal in `[connect].yubaba`.
///
/// Same lint family and camp-local-only scoping as [`check_inert_taints`]. The
/// failure this one catches is the loudest of the four and still went unnoticed
/// for weeks, which is the argument for checking it: the declaration parses, the
/// node is elected by placement, and the only symptom is a connect timeout at
/// dial time attributed to the box rather than to its file.
///
/// Loopback is deliberately not flagged — `http://127.0.0.1:7443` is the
/// pre-mesh "reach me through the SSH tunnel" declaration, a genuine statement
/// that `hub::coordinator::is_loopback_url` already judges downstream.
///
/// A finding here is now belt-and-braces rather than the only guard:
/// [`MachineConfig::reach`] refuses to dial a private literal regardless. The
/// lint exists so the operator hears about it from the file rather than from a
/// roll that silently picked a different address than the one written down.
pub fn check_lan_dial_targets(workspace_root: &Path) -> anyhow::Result<Vec<LanDialTarget>> {
    let mut found = Vec::new();
    for (path, machine) in load_machine_tomls(workspace_root, MachineLoadMode::Tolerant)? {
        let Some(url) = machine.connect.as_ref().and_then(|c| c.yubaba.as_deref()) else {
            continue;
        };
        if private_ipv4_from_url(url).is_none() {
            continue;
        }
        found.push(LanDialTarget {
            machine: machine.name.clone(),
            machine_toml: path.clone(),
            url: url.to_string(),
            mesh_ipv4: machine.mesh_ipv4().map(str::to_string),
        });
    }
    Ok(found)
}

// ── R742-F2 (W305): ingress edge collation ─────────────────────────────────

/// One mirror, loaded with the identity every finding has to be able to name.
#[derive(Debug, Clone)]
pub struct LoadedMirror {
    /// Service name (matches `service.toml`'s `name` field).
    pub service: String,
    /// Environment (file stem of `mirrors/<env>.toml`).
    pub env: String,
    /// Path to the mirror TOML — what an operator opens to fix a finding.
    pub path: PathBuf,
    pub mirror: MirrorConfig,
}

/// Every `.yah/services/<svc>/mirrors/<env>.toml` in the workspace, in a
/// deterministic order (services sorted, then envs).
///
/// Shared by every cross-mirror check, because "walk the mirrors" is the one
/// part all of them agree on and three hand-rolled copies of it drift. A
/// service with no `service.toml`, or a mirror that will not parse, is skipped
/// with a warning rather than aborting the sweep — whatever is wrong with it is
/// a bigger problem than the lint and surfaces on the load path.
pub fn load_service_mirrors(workspace_root: &Path) -> anyhow::Result<Vec<LoadedMirror>> {
    let dir = services_dir(workspace_root);
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut svc_entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    svc_entries.sort_by_key(|e| e.file_name());

    let mut out = Vec::new();
    for entry in svc_entries {
        let svc_dir = entry.path();
        let service_toml = svc_dir.join("service.toml");
        if !service_toml.exists() {
            continue;
        }
        let service = match ServiceConfig::load(&service_toml) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    path = %service_toml.display(),
                    error = %e,
                    "skipping service with unparseable service.toml"
                );
                continue;
            }
        };

        let mirrors_dir = svc_dir.join("mirrors");
        if !mirrors_dir.exists() {
            continue;
        }
        let mut mirror_entries: Vec<_> = std::fs::read_dir(&mirrors_dir)
            .with_context(|| format!("reading {}", mirrors_dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "toml"))
            .collect();
        mirror_entries.sort_by_key(|e| e.file_name());

        for m in mirror_entries {
            let path = m.path();
            let mirror = match MirrorConfig::load(&path) {
                Ok(mc) => mc,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "skipping mirror with parse error"
                    );
                    continue;
                }
            };
            out.push(LoadedMirror {
                service: service.name.clone(),
                env: path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string(),
                path,
                mirror,
            });
        }
    }
    Ok(out)
}

/// An ingress declaration that cannot become a front door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressProblem {
    /// One mirror's own edges do not plan — a hole in its partition, a slot
    /// claimed twice, a selector matching nothing.
    Declaration {
        service: String,
        env: String,
        mirror_toml: PathBuf,
        detail: String,
    },
    /// Two services' edges cannot share the node they both front through.
    /// Nothing but a cross-service pass can see this.
    Collation { detail: String },
    /// A declared edge that collates onto no node at all. Not fatal — the
    /// passway arm deliberately renders a `<machine>` placeholder for an
    /// operator to fill in — but it publishes nothing until it is placed.
    Unplaced { label: String },
}

impl IngressProblem {
    /// `true` for the problems that make the declaration tree incoherent, as
    /// opposed to merely incomplete.
    pub fn is_fatal(&self) -> bool {
        !matches!(self, Self::Unplaced { .. })
    }

    /// Human-readable finding naming the file to open.
    pub fn message(&self) -> String {
        match self {
            Self::Declaration {
                service,
                env,
                mirror_toml,
                detail,
            } => format!(
                "{service}/{env}: ingress declaration does not plan — {detail}\n\u{2192} {}",
                mirror_toml.display()
            ),
            Self::Collation { detail } => format!(
                "ingress edges from two services collide on a shared node — {detail}\n\
                 \u{2192} the node's front door is COLLATED from every service that fronts \
                 through it (W305 F2), so this is invisible from either mirror alone."
            ),
            Self::Unplaced { label } => format!(
                "{label}: declares a front door with no machine to run it on — neither the \
                 edge's `machines` nor the fronted slot's placement names a node, so it \
                 publishes nothing.\n\u{2192} add `machines = [...]` to the edge."
            ),
        }
    }
}

/// What every node in the camp must front, derived from every service's edges.
#[derive(Debug, Clone, Default)]
pub struct IngressReport {
    /// The per-node front doors, empty when nothing collated.
    pub collation: crate::reconciler::Collation,
    /// Findings, fatal ones first-class via [`IngressProblem::is_fatal`].
    pub problems: Vec<IngressProblem>,
}

/// Collate every service's declared ingress edges into the per-node front doors
/// they imply (W305 F2 — the node-controller half).
///
/// **This is the direction that makes the node's front door derived rather than
/// declared.** A service says which edges front it; this walks every service and
/// answers the node's question — *what am I running, and for whom* — without the
/// node declaring anything. The old shape had the node carry its own
/// `MachineConfig.cloudflared` cohort statement (W267 Gap 3), which nothing
/// checked against the services that actually fronted through it.
///
/// Upstreams are resolved **from configuration, never from the network**
/// (R844-F12). A rule that pins `upstream_host` keeps it; every other rule takes
/// the declared `[registration].mesh_ipv4` of each machine in its placement set,
/// via [`machine_mesh_addrs`](crate::reconciler::machine_mesh_addrs). That is a
/// second lookup over the machine slice this function already loaded — no
/// network, no credentials, so this still answers the same question in CI as on
/// the operator's laptop.
///
/// It is also what lets a mirror drop `upstream_host` at all: before this, the
/// pin was the only thing standing between the apex and a collation that
/// rendered `<unresolved>`. What it is *not* is a source of truth — see
/// [`IngressPlan::resolve_upstreams_from_config`](crate::reconciler::IngressPlan::resolve_upstreams_from_config).
/// A rule placed on a machine that declares no mesh address still collates fine
/// and simply has no address yet.
pub fn collate_workspace_ingress(workspace_root: &Path) -> anyhow::Result<IngressReport> {
    // Needed only to resolve a slot's `required = { … }` into a machine name
    // (R772) — `plan_ingress` itself stays pure. Reads `.yah/infra/machines/`
    // directly rather than going through the full `CloudConfig::load`: this
    // walk collates every mirror in the workspace, and has no business
    // hard-failing over an unrelated mirror's `providers.X.use = "<id>"` typo,
    // which cross-ref validation would do. Strict mode: silently dropping a
    // machine here could resolve a `required` constraint onto the wrong node
    // with no error, unlike the tolerant lint sweeps below.
    let machines: Vec<MachineConfig> =
        load_machine_tomls(workspace_root, MachineLoadMode::Strict)?
            .into_iter()
            .map(|(_, m)| m)
            .collect();

    // R844-F12: name -> declared mesh address, built once for the whole walk.
    // Same slice, second lookup — the offline stand-in for the discovery read
    // this pass deliberately cannot make.
    let mesh_addrs = crate::reconciler::machine_mesh_addrs(&machines);

    let mut planned = Vec::new();
    let mut problems = Vec::new();

    for m in load_service_mirrors(workspace_root)? {
        let placements = match crate::reconciler::resolve_ingress_placements(&machines, &m.mirror) {
            Ok(p) => p,
            Err(e) => {
                problems.push(IngressProblem::Declaration {
                    service: m.service.clone(),
                    env: m.env.clone(),
                    mirror_toml: m.path.clone(),
                    detail: format!("{e:#}"),
                });
                continue;
            }
        };
        match crate::reconciler::plan_ingress(&m.mirror, &placements) {
            Ok(plans) => planned.extend(plans.into_iter().map(|mut plan| {
                plan.resolve_upstreams_from_config(&mesh_addrs);
                crate::reconciler::PlannedEdge {
                    service: m.service.clone(),
                    env: m.env.clone(),
                    plan,
                }
            })),
            Err(e) => problems.push(IngressProblem::Declaration {
                service: m.service.clone(),
                env: m.env.clone(),
                mirror_toml: m.path.clone(),
                detail: format!("{e:#}"),
            }),
        }
    }

    let collation = match crate::reconciler::collate_front_doors(&planned) {
        Ok(c) => c,
        Err(e) => {
            problems.push(IngressProblem::Collation {
                detail: format!("{e:#}"),
            });
            Default::default()
        }
    };
    for label in &collation.unplaced {
        problems.push(IngressProblem::Unplaced {
            label: label.clone(),
        });
    }

    Ok(IngressReport {
        collation,
        problems,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_service(workspace: &Path, svc_name: &str, component_path: &str) {
        let svc_dir = workspace.join(".yah/services").join(svc_name);
        std::fs::create_dir_all(&svc_dir).unwrap();
        let toml = format!(
            "schema_version = 1\nname = \"{svc_name}\"\ndomain = \"{svc_name}.example.com\"\n\
             [[components]]\nid = \"models\"\nkind = \"static-asset\"\n\
             path = \"{component_path}\"\nrole = \"static\"\n"
        );
        std::fs::write(svc_dir.join("service.toml"), toml).unwrap();
    }

    fn write_workload_with_aliases(dir: &Path, aliases: &[(&str, &str)]) {
        std::fs::create_dir_all(dir).unwrap();
        let alias_lines: String = aliases
            .iter()
            .map(|(k, v)| format!("\"{k}\" = \"{v}\"\n"))
            .collect();
        let content = format!(
            "kind = \"static-asset\"\nschema_version = \"V1\"\n\
             [aliases]\n{alias_lines}"
        );
        std::fs::write(dir.join("workload.toml"), content).unwrap();
    }

    #[test]
    fn cloud_validate_clean_workspace_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        write_service(root, "svc-a", "svc-a/models");
        write_workload_with_aliases(
            &root.join("svc-a/models"),
            &[("whisper-default-ggml", "svc-a/whisper/model.bin")],
        );

        let collisions = check_alias_collisions(root).unwrap();
        assert!(
            collisions.is_empty(),
            "expected no collisions: {collisions:?}"
        );
    }

    #[test]
    fn cloud_validate_rejects_alias_collision() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        write_service(root, "svc-a", "svc-a/models");
        write_workload_with_aliases(
            &root.join("svc-a/models"),
            &[("whisper-default-ggml", "svc-a/whisper/model.bin")],
        );

        write_service(root, "svc-b", "svc-b/models");
        write_workload_with_aliases(
            &root.join("svc-b/models"),
            &[("whisper-default-ggml", "svc-b/whisper/model.bin")],
        );

        let collisions = check_alias_collisions(root).unwrap();
        assert_eq!(
            collisions.len(),
            1,
            "expected one collision: {collisions:?}"
        );
        let c = &collisions[0];
        assert_eq!(c.alias, "whisper-default-ggml");
        assert_eq!(c.first.service, "svc-a");
        assert_eq!(c.second.service, "svc-b");

        let msg = c.message();
        assert!(msg.contains("whisper-default-ggml"), "message: {msg}");
        assert!(msg.contains("svc-a"), "message: {msg}");
        assert!(msg.contains("svc-b"), "message: {msg}");
    }

    #[test]
    fn cloud_validate_distinct_aliases_no_collision() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        write_service(root, "svc-a", "svc-a/models");
        write_workload_with_aliases(
            &root.join("svc-a/models"),
            &[
                ("whisper-default-ggml", "svc-a/model.bin"),
                ("whisper-default", "svc-a/model.bin"),
            ],
        );

        write_service(root, "svc-b", "svc-b/models");
        write_workload_with_aliases(
            &root.join("svc-b/models"),
            &[("whisper-default-coreml", "svc-b/model.tar.gz")],
        );

        let collisions = check_alias_collisions(root).unwrap();
        assert!(collisions.is_empty());
    }

    #[test]
    fn cloud_validate_multiple_collisions_all_reported() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        write_service(root, "svc-a", "svc-a/models");
        write_workload_with_aliases(
            &root.join("svc-a/models"),
            &[
                ("alias-one", "svc-a/one.bin"),
                ("alias-two", "svc-a/two.bin"),
            ],
        );

        write_service(root, "svc-b", "svc-b/models");
        write_workload_with_aliases(
            &root.join("svc-b/models"),
            &[
                ("alias-one", "svc-b/one.bin"),
                ("alias-two", "svc-b/two.bin"),
            ],
        );

        let collisions = check_alias_collisions(root).unwrap();
        assert_eq!(collisions.len(), 2);
        let names: Vec<_> = collisions.iter().map(|c| c.alias.as_str()).collect();
        assert!(names.contains(&"alias-one"));
        assert!(names.contains(&"alias-two"));
    }

    #[test]
    fn cloud_validate_missing_services_dir_is_not_error() {
        let dir = tempdir().unwrap();
        let collisions = check_alias_collisions(dir.path()).unwrap();
        assert!(collisions.is_empty());
    }

    #[test]
    fn cloud_validate_non_static_asset_workloads_ignored() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        write_service(root, "svc-a", "svc-a/api");
        // Write a container workload — no [aliases] block, should be silently skipped.
        let workload_dir = root.join("svc-a/api");
        std::fs::create_dir_all(&workload_dir).unwrap();
        // Just make the kind non-static-asset to ensure we skip it.
        // (Writes a valid mesofact-static workload which has no aliases)
        std::fs::write(
            workload_dir.join("workload.toml"),
            "schema_version = \"V1\"\nname = \"api\"\nkind = \"mesofact-static\"\n\
             bundle_dir = \"dist\"\n",
        )
        .unwrap();

        let collisions = check_alias_collisions(root).unwrap();
        assert!(collisions.is_empty());
    }

    // ── Port collisions (R602-B4) ────────────────────────────────────────────

    fn write_mirror(workspace: &Path, svc: &str, env: &str, body: &str) {
        let dir = workspace.join(".yah/services").join(svc).join("mirrors");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{env}.toml")), body).unwrap();
    }

    fn local_static_mirror(port: u16) -> String {
        format!(
            "schema_version = 1\nshape = \"local\"\n\
             [providers.static]\nkind = \"local-static\"\nport = {port}\n"
        )
    }

    #[test]
    fn port_collision_across_services_and_envs_is_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_service(root, "scrabcake", "scrabcake/site");
        write_mirror(root, "scrabcake", "dev", &local_static_mirror(4322));
        write_service(root, "yah-marketing", "yah-marketing/site");
        write_mirror(
            root,
            "yah-marketing",
            "pond",
            "schema_version = 1\nshape = \"local\"\n\
             [providers.static]\nkind = \"miniflare-container\"\nport = 4322\n",
        );

        let cols = check_port_collisions(root).unwrap();
        assert_eq!(cols.len(), 1, "{cols:?}");
        assert_eq!(cols[0].port, 4322);
        // Deterministic: "scrabcake" sorts before "yah-marketing".
        assert_eq!(cols[0].first.service, "scrabcake");
        assert_eq!(cols[0].second.service, "yah-marketing");
        assert!(cols[0].is_cross_service(), "different services collide");
        let msg = cols[0].message();
        assert!(msg.contains("4322"), "{msg}");
        assert!(msg.contains("scrabcake"), "{msg}");
        assert!(msg.contains("yah-marketing"), "{msg}");
    }

    #[test]
    fn distinct_ports_no_collision() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_service(root, "a", "a/site");
        write_mirror(root, "a", "dev", &local_static_mirror(4322));
        write_service(root, "b", "b/site");
        write_mirror(root, "b", "dev", &local_static_mirror(4323));
        assert!(check_port_collisions(root).unwrap().is_empty());
    }

    #[test]
    fn same_service_two_envs_reusing_a_port_is_flagged() {
        // The ticket's "scrabcake cloud+dev reuse <port> twice more" shape.
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_service(root, "scrabcake", "scrabcake/site");
        write_mirror(root, "scrabcake", "dev", &local_static_mirror(4352));
        write_mirror(root, "scrabcake", "cloud", &local_static_mirror(4352));
        let cols = check_port_collisions(root).unwrap();
        assert_eq!(cols.len(), 1, "{cols:?}");
        assert_eq!(cols[0].port, 4352);
        // "cloud" sorts before "dev".
        assert_eq!(cols[0].first.env, "cloud");
        assert_eq!(cols[0].second.env, "dev");
        assert!(
            !cols[0].is_cross_service(),
            "same service across envs is NOT cross-service"
        );
    }

    #[test]
    fn reference_slots_do_not_bind_localhost_and_are_ignored() {
        // A `use = "..."` reference slot points at a cloud provider — reusing a
        // `port` field there is not a localhost collision.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ref_slot = "schema_version = 1\nshape = \"local\"\n\
             [providers.static]\nuse = \"cloudflare\"\nport = 8080\n";
        write_service(root, "a", "a/site");
        write_mirror(root, "a", "cloud", ref_slot);
        write_service(root, "b", "b/site");
        write_mirror(root, "b", "cloud", ref_slot);
        assert!(check_port_collisions(root).unwrap().is_empty());
    }

    #[test]
    fn minio_api_and_console_ports_collide_across_ponds() {
        // Two pond MinIO slots on the same api_port bind the same host port.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let minio = "schema_version = 1\nshape = \"local\"\n\
             [providers.object_store]\nkind = \"minio-container\"\napi_port = 9000\nconsole_port = 9001\n";
        write_service(root, "a", "a/site");
        write_mirror(root, "a", "pond", minio);
        write_service(root, "b", "b/site");
        write_mirror(root, "b", "pond", minio);
        let cols = check_port_collisions(root).unwrap();
        // Both api_port (9000) and console_port (9001) collide.
        assert_eq!(cols.len(), 2, "{cols:?}");
        let ports: Vec<u16> = cols.iter().map(|c| c.port).collect();
        assert!(ports.contains(&9000));
        assert!(ports.contains(&9001));
    }

    #[test]
    fn missing_services_dir_is_not_error_for_ports() {
        let dir = tempdir().unwrap();
        assert!(check_port_collisions(dir.path()).unwrap().is_empty());
    }

    // ── R763: the retired `tier:` arch mesh tag ────────────────────────────

    /// Writes and re-parses the TOML immediately: [`load_machine_tomls`]'s
    /// tolerant mode *skips* a file that fails to deserialize, so a fixture
    /// missing a required `MachineConfig` field would otherwise make every
    /// assert-empty test using it pass vacuously instead of failing loud.
    fn assert_machine_toml_parses(path: &Path) {
        let src = std::fs::read_to_string(path).unwrap();
        toml::from_str::<MachineConfig>(&src)
            .unwrap_or_else(|e| panic!("fixture {} does not parse as MachineConfig: {e}\n{src}", path.display()));
    }

    fn write_machine_tags(workspace: &Path, name: &str, mesh_tags: &[&str]) {
        let dir = workspace.join(".yah/infra/machines");
        std::fs::create_dir_all(&dir).unwrap();
        let list: Vec<String> = mesh_tags.iter().map(|t| format!("\"{t}\"")).collect();
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!(
                "name = \"{name}\"\nprovider = \"static\"\nmesh_tags = [{}]\n",
                list.join(", ")
            ),
        )
        .unwrap();
        assert_machine_toml_parses(&path);
    }

    #[test]
    fn the_current_arch_tag_is_clean() {
        let dir = tempdir().unwrap();
        write_machine_tags(dir.path(), "n1", &["tag:build-worker", "arch:x86", "os:linux"]);
        assert!(check_retired_arch_tags(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn a_stale_tier_arch_tag_is_flagged_with_its_replacement() {
        let dir = tempdir().unwrap();
        write_machine_tags(dir.path(), "n1", &["tag:build-worker", "tier:arm", "os:linux"]);
        let found = check_retired_arch_tags(dir.path()).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].tag, "tier:arm");
        assert_eq!(found[0].replacement(), "arch:arm");
        let msg = found[0].message();
        // The message has to carry the fix, not just the complaint — this lint
        // exists precisely because the symptom ("no node") names nothing.
        assert!(msg.contains("arch:arm"), "{msg}");
        assert!(msg.contains("n1"), "{msg}");
    }

    /// The whole point: a node with the old tag is not *rejected* by placement,
    /// it silently stops being a candidate. Superset matching has no way to say
    /// "you asked for arch:x86 and I have tier:x86".
    #[test]
    fn a_stale_tag_is_not_caught_by_the_inert_taint_lint() {
        let dir = tempdir().unwrap();
        write_machine_tags(dir.path(), "n1", &["tier:x86"]);
        assert!(
            check_inert_taints(dir.path()).unwrap().is_empty(),
            "mesh tags are not taints — this needs its own check"
        );
        assert_eq!(check_retired_arch_tags(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn missing_machines_dir_is_not_error_for_arch_tags() {
        let dir = tempdir().unwrap();
        assert!(check_retired_arch_tags(dir.path()).unwrap().is_empty());
    }

    // ── R605-F12: sovereign members with no stated role ────────────────────

    /// `stamp` is the sovereign declaration under test; everything else is the
    /// minimum a `MachineConfig` deserializes from. `assert_machine_toml_parses`
    /// catches a future edit here that drops a required field before it can
    /// produce a vacuously-passing assert-empty test (see that fn's doc).
    fn write_sovereign_machine(workspace: &Path, name: &str, stamp: &str) {
        let dir = workspace.join(".yah/infra/machines");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!("name = \"{name}\"\nprovider = \"static\"\nmesh_tags = []\n{stamp}\n"),
        )
        .unwrap();
        assert_machine_toml_parses(&path);
    }

    #[test]
    fn a_group_with_no_role_is_reported_with_the_declaring_file() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_sovereign_machine(root, "us-west-001", "sovereign_group = \"prod\"");
        let found = check_unroled_sovereign_members(root).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].machine, "us-west-001");
        assert_eq!(found[0].group, "prod");
        assert!(found[0].machine_toml.ends_with("us-west-001.toml"));
        let msg = found[0].message();
        // The message has to say what the silence currently means, or the
        // operator reads it as pedantry and adds the line without deciding.
        assert!(msg.contains("voter") && msg.contains("non-voter"), "{msg}");
        assert!(msg.contains("TOP-LEVEL"), "{msg}");
    }

    #[test]
    fn either_stated_role_is_clean() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_sovereign_machine(
            root,
            "us-west-001",
            "sovereign_group = \"prod\"\nsovereign_role = \"voter\"",
        );
        write_sovereign_machine(
            root,
            "us-west-003",
            "sovereign_group = \"prod\"\nsovereign_role = \"non-voter\"",
        );
        assert!(check_unroled_sovereign_members(root).unwrap().is_empty());
    }

    /// A standalone box has no quorum to be eligible for, so demanding a role
    /// of it would be noise — and noise is what trains an operator to stop
    /// reading the check that matters.
    #[test]
    fn a_machine_in_no_group_is_not_asked_for_a_role() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_sovereign_machine(root, "us-west-002", "taints = [\"no-appliance\"]");
        assert!(check_unroled_sovereign_members(root).unwrap().is_empty());
    }

    #[test]
    fn unroled_findings_are_ordered_by_file_so_output_is_stable() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_sovereign_machine(root, "b-node", "sovereign_group = \"dev\"");
        write_sovereign_machine(root, "a-node", "sovereign_group = \"prod\"");
        let found = check_unroled_sovereign_members(root).unwrap();
        let names: Vec<&str> = found.iter().map(|f| f.machine.as_str()).collect();
        assert_eq!(names, vec!["a-node", "b-node"]);
    }

    #[test]
    fn missing_machines_dir_is_not_error_for_unroled_members() {
        let dir = tempdir().unwrap();
        assert!(check_unroled_sovereign_members(dir.path())
            .unwrap()
            .is_empty());
    }

    // ── R605-T10: LAN dial targets ─────────────────────────────────────────

    /// `connect` is the raw body of the `[connect]` table; `registration` the
    /// raw body of `[registration]` (empty string omits the table).
    fn write_reach_machine(workspace: &Path, name: &str, connect: &str, registration: &str) {
        let dir = workspace.join(".yah/infra/machines");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.toml"));
        let reg = if registration.is_empty() {
            String::new()
        } else {
            format!("\n[registration]\n{registration}\n")
        };
        std::fs::write(
            &path,
            format!(
                "name = \"{name}\"\nprovider = \"static\"\nmesh_tags = []\n\n\
                 [connect]\n{connect}\n{reg}"
            ),
        )
        .unwrap();
        assert_machine_toml_parses(&path);
    }

    #[test]
    fn a_lan_literal_in_the_dialed_field_is_reported_with_its_file() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        // us-west-011's shape at filing time: LAN literal, no mesh address.
        write_reach_machine(
            root,
            "us-west-011",
            "address = \"192.168.10.11\"\nssh = \"yah@192.168.10.11\"\n\
             yubaba = \"http://192.168.10.11:7443\"",
            "",
        );
        let found = check_lan_dial_targets(root).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].machine, "us-west-011");
        assert_eq!(found[0].url, "http://192.168.10.11:7443");
        assert_eq!(found[0].mesh_ipv4, None);
        let msg = found[0].message();
        assert!(msg.contains("mesh-join it"), "{msg}");
        assert!(msg.contains("us-west-011.toml"), "{msg}");
    }

    /// A mesh-joined box gets the cheaper instruction, because the fix really
    /// is one deleted line — us-west-013/014's shape.
    #[test]
    fn a_mesh_joined_lan_declarer_is_told_to_delete_the_line() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_reach_machine(
            root,
            "us-west-014",
            "address = \"192.168.10.14\"\nssh = \"yah@192.168.10.14\"\n\
             yubaba = \"http://192.168.10.14:7443\"",
            "mesh_ipv4 = \"100.64.0.6\"",
        );
        let found = check_lan_dial_targets(root).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].mesh_ipv4.as_deref(), Some("100.64.0.6"));
        let msg = found[0].message();
        assert!(msg.contains("DELETE the `yubaba` line"), "{msg}");
        assert!(msg.contains("100.64.0.6"), "{msg}");
    }

    /// The three shapes that must NOT be flagged: a mesh address, the pre-mesh
    /// loopback placeholder, and a LAN address confined to the metadata fields
    /// (which is the whole point — the operator keeps it, automation ignores it).
    #[test]
    fn mesh_loopback_and_metadata_only_lan_addresses_are_clean() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_reach_machine(
            root,
            "meshed",
            "address = \"192.168.10.15\"\nssh = \"yah@192.168.10.15\"",
            "mesh_ipv4 = \"100.64.0.7\"",
        );
        write_reach_machine(
            root,
            "tunnelled",
            "address = \"192.168.10.16\"\nssh = \"yah@192.168.10.16\"\n\
             yubaba = \"http://127.0.0.1:7443\"",
            "",
        );
        write_reach_machine(
            root,
            "public",
            "address = \"45.32.194.254\"\nssh = \"debian@45.32.194.254\"\n\
             yubaba = \"http://45.32.194.254:7443\"",
            "",
        );
        assert!(check_lan_dial_targets(root).unwrap().is_empty());
    }

    #[test]
    fn missing_machines_dir_is_not_error_for_lan_dial_targets() {
        let dir = tempdir().unwrap();
        assert!(check_lan_dial_targets(dir.path()).unwrap().is_empty());
    }

    // ── R742-T4: inert taints ──────────────────────────────────────────────

    fn write_machine(workspace: &Path, name: &str, taints: &[&str]) {
        let dir = workspace.join(".yah/infra/machines");
        std::fs::create_dir_all(&dir).unwrap();
        let list: Vec<String> = taints.iter().map(|t| format!("\"{t}\"")).collect();
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!(
                "name = \"{name}\"\nprovider = \"static\"\nmesh_tags = []\ntaints = [{}]\n",
                list.join(", ")
            ),
        )
        .unwrap();
        assert_machine_toml_parses(&path);
    }

    #[test]
    fn archetype_repel_keys_and_affinity_keys_are_clean() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_machine(root, "worker", &["no-server", "no-appliance", "no-job"]);
        write_machine(root, "edge", &["public-ip"]);
        write_machine(root, "plain", &[]);
        assert!(check_inert_taints(root).unwrap().is_empty());
    }

    #[test]
    fn a_free_form_taint_is_reported_with_the_declaring_file() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        // W305's headline example. Environment is not a taint.
        write_machine(root, "us-west-011", &["qa"]);
        let found = check_inert_taints(root).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].machine, "us-west-011");
        assert_eq!(found[0].key, "qa");
        assert!(found[0].machine_toml.ends_with("us-west-011.toml"));
        let msg = found[0].message();
        // The message has to carry the legal vocabulary, otherwise the
        // operator's only recourse is reading the scheduler.
        assert!(msg.contains("no-appliance"), "{msg}");
        assert!(msg.contains("public-ip"), "{msg}");
        assert!(msg.contains("mesh_tags"), "{msg}");
    }

    #[test]
    fn no_voter_is_inert_because_voter_is_not_an_archetype() {
        // The one that cost real fleet state: it reads as an exclusion and
        // excludes nothing, so it sat on three nodes asserting a falsehood.
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_machine(root, "us-west-015", &["no-server", "no-appliance", "no-voter"]);
        let found = check_inert_taints(root).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].key, "no-voter");
    }

    #[test]
    fn findings_are_ordered_by_file_so_output_is_stable() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_machine(root, "b-node", &["qa"]);
        write_machine(root, "a-node", &["staging"]);
        let found = check_inert_taints(root).unwrap();
        let names: Vec<&str> = found.iter().map(|f| f.machine.as_str()).collect();
        assert_eq!(names, vec!["a-node", "b-node"]);
    }

    #[test]
    fn missing_machines_dir_is_not_error() {
        let dir = tempdir().unwrap();
        assert!(check_inert_taints(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn an_unparseable_machine_toml_is_skipped_not_fatal() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let mdir = root.join(".yah/infra/machines");
        std::fs::create_dir_all(&mdir).unwrap();
        std::fs::write(mdir.join("broken.toml"), "name = \n").unwrap();
        write_machine(root, "good", &["qa"]);
        // The broken file must not sink the sweep — a peer's half-written
        // scaffold is a normal state on a shared tree.
        let found = check_inert_taints(root).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].machine, "good");
    }

    // ── R787: the shared loader's Strict/Tolerant contract ──────────────────

    #[test]
    fn tolerant_mode_skips_an_unparseable_toml_and_still_pairs_the_path() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let mdir = root.join(".yah/infra/machines");
        std::fs::create_dir_all(&mdir).unwrap();
        std::fs::write(mdir.join("broken.toml"), "name = \n").unwrap();
        write_machine(root, "good", &["qa"]);

        let loaded = load_machine_tomls(root, MachineLoadMode::Tolerant).unwrap();
        assert_eq!(loaded.len(), 1, "{loaded:?}");
        assert_eq!(loaded[0].1.name, "good");
        assert!(loaded[0].0.ends_with("good.toml"));
    }

    #[test]
    fn strict_mode_fails_the_whole_load_on_one_unparseable_toml() {
        // The behavior collate_workspace_ingress relies on: a bad machine toml
        // must not silently resolve a `required` placement onto the wrong node.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let mdir = root.join(".yah/infra/machines");
        std::fs::create_dir_all(&mdir).unwrap();
        std::fs::write(mdir.join("broken.toml"), "name = \n").unwrap();
        write_machine(root, "good", &["qa"]);

        let err = load_machine_tomls(root, MachineLoadMode::Strict).unwrap_err();
        assert!(format!("{err:#}").contains("broken.toml"), "{err:#}");
    }

    // ── R742-F2 (W305): workspace ingress collation ──

    /// A mirror fronting one hostname through one edge on `machines`.
    fn fronted_mirror(provider: &str, machines: &[&str], hostname: &str, port: u16) -> String {
        let list = machines
            .iter()
            .map(|m| format!("\"{m}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "schema_version = 1\nshape = \"single-machine\"\n\
             ingress = \"{provider}\"\ningress_machines = [{list}]\n\
             [providers.compute]\nuse = \"hetzner\"\nzone = \"{hostname}\"\n\
             port = {port}\nupstream_host = \"100.64.0.5\"\n"
        )
    }

    #[test]
    fn two_services_fronting_one_node_collate_into_one_front_door() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_service(root, "yah-marketing", "yah-marketing/site");
        write_mirror(
            root,
            "yah-marketing",
            "cloud",
            &fronted_mirror("passway", &["us-east-001"], "yah.dev", 8080),
        );
        write_service(root, "yah-issues", "yah-issues/site");
        write_mirror(
            root,
            "yah-issues",
            "cloud",
            &fronted_mirror("passway", &["us-east-001"], "issues.yah.dev", 8731),
        );

        let report = collate_workspace_ingress(root).unwrap();
        assert!(report.problems.is_empty(), "{:?}", report.problems);
        assert_eq!(report.collation.front_doors.len(), 1);
        let door = &report.collation.front_doors[0];
        assert_eq!(door.machine, "us-east-001");
        assert_eq!(
            door.passway_upstreams().unwrap(),
            vec!["issues.yah.dev=100.64.0.5:8731", "yah.dev=100.64.0.5:8080"]
        );
    }

    #[test]
    fn a_cross_service_hostname_clash_is_reported_with_both_declarations() {
        // Neither service's own `yah cloud apply` can see this: each plans its
        // own mirror, both look fine, and the box ends up with whichever
        // applied last.
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_service(root, "svc-a", "svc-a/site");
        write_mirror(
            root,
            "svc-a",
            "cloud",
            &fronted_mirror("passway", &["us-east-001"], "yah.dev", 8080),
        );
        write_service(root, "svc-b", "svc-b/site");
        write_mirror(
            root,
            "svc-b",
            "cloud",
            &fronted_mirror("cloudflare-tunnel", &["us-west-001"], "yah.dev", 8080),
        );

        let report = collate_workspace_ingress(root).unwrap();
        let fatal: Vec<String> = report
            .problems
            .iter()
            .filter(|p| p.is_fatal())
            .map(|p| p.message())
            .collect();
        assert_eq!(fatal.len(), 1, "{fatal:?}");
        assert!(fatal[0].contains("svc-a/cloud"), "{}", fatal[0]);
        assert!(fatal[0].contains("svc-b/cloud"), "{}", fatal[0]);
    }

    #[test]
    fn one_mirrors_broken_declaration_does_not_hide_the_rest() {
        // A malformed edge is reported against the file that declared it, and
        // the sweep continues — one service's typo must not blind the operator
        // to every other service's front doors.
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_service(root, "svc-broken", "svc-broken/site");
        write_mirror(
            root,
            "svc-broken",
            "cloud",
            "schema_version = 1\nshape = \"single-machine\"\n\
             ingress_machines = [\"us-east-001\"]\n\
             [providers.compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        write_service(root, "svc-ok", "svc-ok/site");
        write_mirror(
            root,
            "svc-ok",
            "cloud",
            &fronted_mirror("passway", &["us-east-001"], "b.yah.dev", 8080),
        );

        let report = collate_workspace_ingress(root).unwrap();
        assert_eq!(report.problems.len(), 1);
        assert!(
            report.problems[0].message().contains("svc-broken/cloud"),
            "{}",
            report.problems[0].message()
        );
        assert_eq!(report.collation.front_doors.len(), 1, "svc-ok still collates");
    }

    #[test]
    fn a_mirror_with_no_ingress_contributes_nothing_and_is_not_a_finding() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_service(root, "svc", "svc/site");
        write_mirror(root, "svc", "dev", &local_static_mirror(4322));
        let report = collate_workspace_ingress(root).unwrap();
        assert!(report.problems.is_empty());
        assert!(report.collation.front_doors.is_empty());
    }
}
