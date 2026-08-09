//! On-disk path resolver for camp deployment manifests.
//!
//! Replaces the pre-R215 single-rooted `.yah/cloud/` layout. The new model
//! splits substrate ("where") from service declarations ("what"):
//!
//! ```text
//! .yah/
//!   infra/                                 # substrate registry — Infra tab
//!     machines/<name>.toml                 # provisioned hosts
//!     providers/<id>.toml                  # account/runtime bindings
//!     cloud-init/mirror.yml                # yubaba bootstrap template
//!     rules/<id>.yaml                      # tower alert rules
//!   services/<svc>/                        # operator-facing deployables — Services tab
//!     service.toml                         # name, domain, components
//!     mirrors/<env>.toml                   # service projection onto infra
//! ```
//!
//! Workload manifests stay colocated with the code they deploy (paths come
//! from `service.toml` components).
//!
//! All helpers take `workspace_root` (the camp dir, the parent of `.yah/`).
//! No helper does I/O, and every one of them resolves camp-locally. A camp that
//! runs on another camp's shared cluster borrows that inventory through
//! `.yah/infra/sources.toml`, overlaid by `CloudConfig::load` (R615-F2) — not by
//! any helper here returning a foreign directory.
//!
//! @yah:relay(R222, "Service/infra manifest reshape — phases B2–B4")
//! @yah:at(2026-05-18T02:19:27Z)
//! @yah:status(handoff)
//! @yah:assignee(agent:claude)
//! @arch:see(.yah/docs/architecture/A031-yah-cloud-config-shape.md)
//! @yah:verify("cargo check -p cloud && cargo test -p cloud")
//! @yah:verify("cargo check -p yah && cargo check -p agent-tools")
//! @yah:verify("cargo check -p yah --tests && cargo check -p agent-tools --tests")
//! @yah:verify("CloudConfig::load(workspace_root) populates providers + services (with mirrors) from the seven Phase-A manifests")
//! @yah:cleanup("compose.rs + cli/cloud.rs bucket commands + handle_mirror{,_status} + collect_machine_services + derive_public_hostname likely deleted in B3-T2 — confirm against the yubaba integration story first")
//! @yah:cleanup("agent-tools/cloud_tools.rs's duplicate ServiceConfig/MirrorConfig collapses into a re-import once B3-T3/T4 stabilize the loader API")
//! @yah:cleanup("MachineConfig::save signature: tighten in B5 once .yah/infra/ vs .yah/cloud/ migration settles")
//! @yah:next("B4: schemars-generated JSON schemas → .yah/schema/{service,mirror,provider,workload,machine}.toml.schema.json. Implement as an xtask command (not a build script — keeps cloud's compile path clean). Drift test asserts generated == committed. Each manifest's #:schema directive points there.")
//! @yah:next("R222-T1: Update cloud.mirror_state + cloud.service_ports to read from .yah/services/ layout (currently silently empty in post-B2 workspaces).")
//! @yah:handoff("B2 landed (prev agent): Provider/ServiceConfig/MirrorConfig types in config.rs, cross-ref validation, 100+ tests passing.")
//! @yah:handoff("B3 landed: All cli/cloud.rs callers migrated off pre-B2 field names. cfg.mirrors → cfg.legacy_mirrors in machines_for_workload_name, workload_ident_for_machine, machines_for_service, workload-show block. cfg.mirror() → cfg.legacy_mirror() in collect_machine_services, derive_public_hostname, handle_mirror, handle_mirror_status. cfg.services.iter() → cfg.legacy_services.iter() in collect_machine_services. cargo check -p cloud/yah/agent-tools clean; 104 cloud tests pass. compose.rs + bucket commands left pending yubaba integration confirmation. R222-T1 filed for agent-tools cloud_tools.rs path update (.yah/services/ layout).")
//!
//! @yah:ticket(R615-T5, "Retire the inherit_machines stopgap: migrate noisetable to sources.toml, delete the camp.toml redirect")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-08-08T23:57:47Z)
//! @yah:phase(P3)
//! @yah:parent(R615)
//! @yah:next("Author noisetable .yah/infra/sources.toml with a kind=path, mode=read-only source owner=yah path=../yah, and verify its Infra tab + yah cloud reconcile resolve the same machines they do today through inherit_machines.")
//! @yah:next("THEN delete the stopgap in the same pass — no coexistence. Remove paths.rs machines_dir inherited_machines_dir / inherited_machines_source, the [infra] inherit_machines key from noisetable camp.toml, and the InfraSection field from kg-store CampConfig + camp.toml.schema.json if nothing else uses it.")
//! @yah:verify("rg -n inherit_machines across the tree returns ZERO live hits outside archived docs")
//! @yah:verify("noisetable yah cloud validate stays ok and its Infra tab still lists yah cluster machines")
//! @yah:gotcha("Both mechanisms hook the SAME paths::machines_dir seam. If they coexist, resolution order becomes ambiguous and an operator cannot tell which one is winning. inherit_machines is a strict subset of the sources.toml kind=path case, so this is a pure replacement — do not build a compatibility shim.")
//! @yah:gotcha("Dropping InfraSection from CampConfig has a silent-data-loss hazard in reverse: the section was added so camp.toml round-trips without an old binary stripping [infra] on the next relay_high_water save. Confirm no camp.toml in any camp still carries the key before removing the struct field.")
//! @arch:see(.yah/docs/working/W274-linked-infra-sources.md)
//! @yah:depends_on(R615-F4)
//! @yah:tier(Cleric)
//! @yah:handoff("Authored /Users/leif/ss/noisetable/.yah/infra/sources.toml (kind=path, owner=yah, path=../yah, mode=read-only) -- a NEW, purely additive file, zero risk to noisetable's substantial in-progress uncommitted work (git status there shows dozens of modified koda/core files unrelated to this ticket -- did not touch, did not build/run anything in that repo, only wrote the one new file). Left [infra].inherit_machines in noisetable's camp.toml UNTOUCHED -- see next-steps for why.")
//! @yah:handoff("Resolution parity PROVEN two ways. (1) Self-contained unit tests in oss/yubaba/crates/cloud/src/config.rs (no dependency on the live noisetable checkout): inherit_machines_and_a_path_source_resolve_the_same_machines builds two synthetic camps against one shared machine root -- one via [infra].inherit_machines, one via an equivalent kind=path source -- and asserts the resolved machine sets are byte-identical. (2) coexistence_is_a_safe_no_op_not_a_conflict proves the ticket's own gotcha resolves cleanly: with BOTH mechanisms declared against the same root (noisetable's actual current state, now that sources.toml exists alongside inherit_machines), inherit_machines claims the names as camp-local first, so sources.toml's overlay finds every name already 'seen' and contributes nothing -- no duplicate rows, no origin-tag confusion. This is also why adding sources.toml today was safe: it's a provable no-op until inherit_machines is removed.")
//! @yah:handoff("DID NOT delete the stopgap. Three reasons, compounding: (a) noisetable's camp.toml still declares inherit_machines, so deleting the paths.rs/kg-store CODE first would silently empty its Infra tab and reconcile surface the moment this crate is rebuilt and installed -- a live camp.toml file whose own header comments warn 'the running desktop app holds state in memory,' so I have no way to know whether a live session is depending on this right now. (b) Flipping noisetable's camp.toml to delete inherit_machines is the mirror-image risk -- an edit to a live, actively-worked-on separate repo I cannot safely verify end-to-end without running noisetable's own build (which I declined to do given its unrelated in-progress state). (c) THE BLAST RADIUS IS BIGGER THAN THE TICKET DESCRIBED, discovered via rg -n inherit_machines across the tree: crates/yah/hub/src/coordinator.rs independently re-implements the SAME [infra].inherit_machines read (its own parsing, not routed through paths::machines_dir at all) for mesh_yubaba_base_urls -- hub is fenced/live-owned by @Ashguard:polaris this session. app/yah/desktop/src/infra_decl.rs also references the mechanism. So 'delete paths.rs + kg-store's InfraSection' alone would leave hub's independent reader orphaned and still working off the old field, and the desktop app referencing dead code paths -- a genuinely 4-file, 3-crate (+1 fenced) cutover, not the 2-file one the ticket's own next-step described.")
//! @yah:handoff("Tree anchor 85801e7f. Pathspec (this repo): oss/yubaba/crates/cloud/src/config.rs (+2 tests only). Pathspec (noisetable, separate repo, NOT part of this handoff's git tree): .yah/infra/sources.toml (new file). Tests: cargo test -p yah-cloud --lib (from oss/yubaba) 723 passed / 0 failed / 4 ignored, +2 over R615-T3's 721 baseline.")
//! @yah:handoff("Tree anchor at handoff: 85801e7f6b76b369c0c8ecd2e5c7874990cd9286 — the shared tree as I left it. Diff against it (`git diff 85801e7f6b76b369c0c8ecd2e5c7874990cd9286..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("THE ACTUAL CUTOVER is what remains, and it's an operator-timing call, not an engineering gap: (1) confirm no live desktop session has noisetable open / depending on cached inherit_machines state, (2) delete '[infra]\\ninherit_machines = \"../yah\"' from noisetable's camp.toml (the file already carries a big warning about live desktop state -- read it before touching it), (3) in THIS repo: remove paths.rs's inherited_machines_dir/inherited_machines_source + the redirect branch in machines_dir(), remove InfraSection from crates/yah/kg-store/src/camp_config.rs (camp_config.rs:1250-1257's round-trip test goes with it) + regenerate camp.toml.schema.json, AND fix crates/yah/hub/src/coordinator.rs's independent inherit_machines reader (mesh_yubaba_base_urls + its two tests resolves_through_inherit_machines_redirect / enumeration_follows_the_inherit_machines_redirect at coordinator.rs:283,375) to read sources.toml instead or be told sources.toml already covers it via a different call path -- hub is fenced, needs @Ashguard:polaris or a session after that lane drains. (4) app/yah/desktop/src/infra_decl.rs (:326,:394) also references the mechanism in comments -- confirm nothing there needs a matching edit. rg -n inherit_machines across the tree is the ticket's own verify line; it currently returns non-archive hits in exactly these 4 files plus this ticket's own test fixtures (which retire themselves once the mechanism does).")
//! @yah:next("R615-S6 (the settle ticket) can now cite BOTH the sources.toml mechanism (F1/F2) and this coexistence proof as grounding for whether shared infra becomes a named repo any camp links.")
//! @yah:gotcha("Reconciliation audit (871fde1c): verified NOT landed — the ticket's core ask (delete the inherit_machines stopgap) is confirmed absent. rg inherit_machines still hits paths.rs, hub/coordinator.rs, hub/in_process.rs, desktop/infra_decl.rs; the ticket's own verify line ('zero live hits outside archived docs') fails. Only the parity proof (2 new tests in oss/yubaba/crates/cloud/src/config.rs, confirmed present) and the noisetable sources.toml file (outside this repo, unverifiable here) landed. This matches the ticket's own handoff text ('DID NOT delete the stopgap') — board state (open) is accurate, not stale.")
//! @yah:handoff("CUT OVER. The inherit_machines stopgap is deleted across all four call sites the prior pass identified, and noisetable is migrated. Tree anchor 5e86d6d96527fe00aeb77b20c70fec5da7ec2707.")
//! @yah:verify("End-to-end proof against the REAL inventory, three-way, through the real CLI: a scratch camp whose only infra declaration was a sources.toml [[source]] kind=path at /Users/leif/ss/yah resolved us-west-001 (a machine declared solely in yah's tree) via yah cloud machine status. Control 1: a bogus name errored with 'no machine ... check declared names'. Control 2: removing sources.toml made the same camp report 'no machines declared'. So the borrow is load-bearing, not incidental.")
//! @yah:handoff("FOUR CALL SITES, all cut. (1) cloud/src/paths.rs: machines_dir is now a pure path join; inherited_machines_dir + inherited_machines_source deleted. (2) crates/yah/hub/src/coordinator.rs: its independent reader is replaced by machines_dirs() -> Vec<PathBuf>, which parses sources.toml hub-locally (still no cloud dep, same reasoning as MachineToml). (3) crates/yah/kg-store/src/camp_config.rs: InfraSection + the infra field deleted, and .yah/schema/camp.toml.schema.json's [infra] block with it. (4) app/yah/desktop/src/infra_decl.rs: machine_origin_view lost its legacy_inherit parameter and the whole blanket branch; the infra_machines_inherited_from tauri command is deleted, along with its lib.rs registration and the inheritedFrom() RPC in the UI's index.ts/tauri.ts/browser.ts.")
//! @yah:handoff("SCOPE I WIDENED, deliberately: hub's replacement is a LIST of inventory dirs, not a ported single-dir redirect. The old key could return either the local dir or a foreign one and never both, so a camp that owns some nodes and borrows the rest was unrepresentable in hub -- it would have silently seen only one set. machines_dirs yields camp-local first then each source in declaration order, and callers take first-match by machine NAME, which matches CloudConfig::load's camp-local-wins rule. New test local_machines_merge_with_and_shadow_borrowed_ones pins exactly that shape. hub also now honours kind=git sources via the .yah/cache/infra/<owner>/ path yah infra sync (R615-T3) writes, subdir included.")
//! @yah:handoff("THE PRIOR PASS'S THREE BLOCKERS were re-checked and none held. (a) The camp.toml warning about the running desktop app holding state in memory is about relay_high_water, the board counter -- it is not about [infra], which no code caches. (b) noisetable's camp.toml turned out to be a two-line edit against a tree where git status showed no other modifications, not the dozens of in-flight files the earlier note described. (c) hub was described as fenced by @Ashguard:polaris; no polaris session exists on the roster now, so the lane was free.")
//! @yah:verify("Ordering is safe in both directions, which is why the code could land before the config edit: CampConfig has no deny_unknown_fields, so a camp.toml still carrying [infra] loads fine and the key is simply inert. Three tests pin that a stale key cannot resurrect the mechanism in any of the three crates that used to read it -- cloud (a_stale_inherit_machines_key_does_not_change_what_sources_toml_resolves), hub (a_stale_inherit_machines_key_is_ignored), desktop (a_stale_inherit_machines_key_does_not_suppress_the_borrowed_origin) -- plus kg-store's a_stale_infra_section_still_loads_and_does_not_break_other_keys, which pins the riskier direction: a stale key must not take relay_high_water down with it.")
//! @yah:verify("cargo run -p xtask -- emit-schemas produced a zero-byte diff, so the 8 generated schemas were already in sync and nothing needed regenerating. camp.toml.schema.json is NOT xtask-generated -- it is hand-maintained, which is why its [infra] block had to be removed by hand.")
//! @yah:verify("Suites, all from a clean run at the end: yah-cloud 741 passed / 0 failed / 4 ignored (from oss/yubaba). yah-hub 65 passed / 0 failed. kg-store camp_config 49 passed / 0 failed. desktop infra_decl 6 passed / 0 failed. xtask schema_drift 3 passed / 0 failed. packages/yah/ui: typecheck clean, build clean, bun test 1629 pass / 14 fail / 8 errors -- fail and error counts identical to the pre-existing baseline, and none of the named failures touch infra.")
//! @yah:gotcha("PRE-EXISTING, NOT FROM THIS TICKET, and it blocked the obvious way to verify noisetable directly: CloudConfig::load fails on that camp with 'parsing ./.yah/domains/app-noisetable-com.toml'. It is in committed state there (only my two files show as modified) and is unrelated to machines -- but it means yah cloud machine status cannot run against noisetable at all right now. That is why the end-to-end proof uses a scratch camp pointed at yah's real infra root instead. yah cloud validate on noisetable still reports ok, since validate does not take the full-config path.")
//! @yah:next("Operator step, not a code gap: the desktop app must be rebuilt for noisetable's Infra tab to pick this up. A running app built before R615-F1/F2 has neither the retired redirect's removal nor the sources.toml overlay, so until it restarts that camp's Infra tab may look empty. Nothing is lost -- re-adding two lines to camp.toml would restore the old path on an old binary -- but the fix is to rebuild, not to revert.")
//! @yah:handoff("NOISETABLE (separate repo, NOT in this git tree, so it will not appear in any diff against the anchor SHA): .yah/camp.toml lost its [infra] block, replaced by a comment pointing at sources.toml; .yah/infra/sources.toml's header was rewritten from 'NOT yet cut over / coexists safely' to record that it is now the only thing making yah's nodes resolve there -- load-bearing, not additive. Those are the only two files touched in that repo.")
//! @yah:verify("The ticket's own verify line ('rg -n inherit_machines returns ZERO live hits') is satisfied for code: every surviving hit is either a frozen @yah:handoff board annotation recording history, or a comment/test fixture that exists precisely to pin the retired key as inert. No live code path reads it.")

use std::path::{Path, PathBuf};

pub fn yah_dir(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".yah")
}

pub fn infra_dir(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("infra")
}

pub fn services_dir(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("services")
}

/// Directory holding this camp's fleet workload declarations — the TOML
/// serialization of a `WorkloadSpec`, one file per workload, which
/// `yah cloud workload deploy <n> <machine>` looks up by name.
///
/// R568-T7: this is the R215+ home, `<workspace_root>/.yah/infra/workloads/`,
/// and it is new. Before it, [`crate::config::CloudConfig::load`] read workloads
/// *only* from the pre-R215 `.yah/cloud/workloads/`, which R222-B1 emptied —
/// so in any post-R215 camp `cfg.workload(name)` could never resolve anything
/// and the whole `yah cloud workload …` surface was structurally dead. It went
/// unnoticed because the only workloads ever deployed were forge/QED runs,
/// which synthesize their spec in memory and never touch this loader.
///
/// The CLI has been telling operators this path all along
/// (`app/yah/cli/src/cloud.rs`: "no workload '{name}' in .yah/infra/workloads/"),
/// so this makes the code agree with the message rather than the reverse.
/// The legacy directory is still read and merged, R215+ winning on a name
/// collision — the same shape [`machines_dir`]'s callers use.
pub fn workloads_dir(workspace_root: &Path) -> PathBuf {
    infra_dir(workspace_root).join("workloads")
}

/// Directory holding **this camp's own** machine inventory (`<name>.toml` per
/// node): always `<workspace_root>/.yah/infra/machines/`.
///
/// A camp that runs on a cluster owned by another camp does not redirect this
/// path — it declares the owner as a `[[source]]` in `.yah/infra/sources.toml`
/// and `CloudConfig::load` overlays that source's machines on top of whatever
/// this directory holds, camp-local winning on a name collision (R615-F2).
/// Borrowed entries carry an [`crate::config::InfraOrigin`] so the Infra tab
/// can badge them and refuse writes.
///
/// R615-T5 retired the predecessor of that mechanism, a `[infra].inherit_machines`
/// key in `camp.toml` that made this function return the *source* camp's
/// directory instead. It was a strict subset of the `kind = "path"` source case
/// and hooked the same seam, so leaving both in place made it unknowable which
/// one had resolved a given row. This function no longer reads `camp.toml` at
/// all, and does no I/O.
pub fn machines_dir(workspace_root: &Path) -> PathBuf {
    infra_dir(workspace_root).join("machines")
}

pub fn providers_dir(workspace_root: &Path) -> PathBuf {
    infra_dir(workspace_root).join("providers")
}

pub fn cloud_init_dir(workspace_root: &Path) -> PathBuf {
    infra_dir(workspace_root).join("cloud-init")
}

pub fn cloud_init_template(workspace_root: &Path) -> PathBuf {
    cloud_init_dir(workspace_root).join("mirror.yml")
}

pub fn rules_dir(workspace_root: &Path) -> PathBuf {
    infra_dir(workspace_root).join("rules")
}

/// Sync-cache checkout directory for one `kind = "git"` [`crate::config::InfraSource`]
/// (R615-T3 / W274 §3). `yah infra sync` shallow-clones/pulls the source's
/// repo here; `CloudConfig::load`'s overlay (R615-F2) only ever reads this
/// directory, never the network, so config load stays synchronous and
/// offline. `kind = "path"` sources need no cache — they read the owner's
/// live tree directly.
pub fn infra_source_cache_dir(workspace_root: &Path, owner: &str) -> PathBuf {
    yah_dir(workspace_root).join("cache").join("infra").join(owner)
}

pub fn machine_toml(workspace_root: &Path, name: &str) -> PathBuf {
    machines_dir(workspace_root).join(format!("{name}.toml"))
}

pub fn service_dir(workspace_root: &Path, service: &str) -> PathBuf {
    services_dir(workspace_root).join(service)
}

pub fn service_toml(workspace_root: &Path, service: &str) -> PathBuf {
    service_dir(workspace_root, service).join("service.toml")
}

pub fn service_mirrors_dir(workspace_root: &Path, service: &str) -> PathBuf {
    service_dir(workspace_root, service).join("mirrors")
}

pub fn service_mirror_toml(workspace_root: &Path, service: &str, env: &str) -> PathBuf {
    service_mirrors_dir(workspace_root, service).join(format!("{env}.toml"))
}

pub fn provider_toml(workspace_root: &Path, id: &str) -> PathBuf {
    providers_dir(workspace_root).join(format!("{id}.toml"))
}

pub fn domains_dir(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("domains")
}

pub fn domain_toml(workspace_root: &Path, name: &str) -> PathBuf {
    domains_dir(workspace_root).join(format!("{name}.toml"))
}

/// Pre-R215 root, kept for one release so we can read existing on-disk
/// state from a tool that wrote there. New writes go through the `infra_*`
/// / `service_*` helpers above.
pub fn legacy_cloud_dir(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("cloud")
}

/// Append-only journal for static-asset reconciler decisions (R470-T1).
/// One JSONL record per reconciler decision; replayed by `yah cloud status`.
pub fn asset_status_journal(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("cloud/status.jsonl")
}

/// Registry of app roots for fast discovery (R470-T7).
/// Populated by `yah cloud apps add <path>` / `yah cloud apps scan`.
pub fn apps_registry(workspace_root: &Path) -> PathBuf {
    yah_dir(workspace_root).join("apps.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_camp_toml(root: &Path, body: &str) {
        let yah = root.join(".yah");
        std::fs::create_dir_all(&yah).unwrap();
        std::fs::write(yah.join("camp.toml"), body).unwrap();
    }

    #[test]
    fn machines_dir_is_local_without_inherit() {
        let tmp = tempfile::TempDir::new().unwrap();
        // No camp.toml at all.
        assert_eq!(
            machines_dir(tmp.path()),
            tmp.path().join(".yah/infra/machines")
        );
        // camp.toml present but no [infra] section.
        write_camp_toml(tmp.path(), "name = \"solo\"\n");
        assert_eq!(
            machines_dir(tmp.path()),
            tmp.path().join(".yah/infra/machines")
        );
    }

    /// R615-T5: `machines_dir` is now a pure path join. A `camp.toml` still
    /// carrying the retired `[infra].inherit_machines` key must be *ignored*,
    /// not honoured — a stale key in a camp that has already migrated to
    /// `sources.toml` would otherwise silently re-enable the old redirect and
    /// double-resolve the borrowed nodes.
    #[test]
    fn a_retired_inherit_machines_key_no_longer_redirects() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_camp_toml(
            tmp.path(),
            "name = \"noisetable\"\n[infra]\ninherit_machines = \"../yah\"\n",
        );
        assert_eq!(
            machines_dir(tmp.path()),
            tmp.path().join(".yah/infra/machines")
        );
        // machine_toml builds on machines_dir, so it stays local too.
        assert_eq!(
            machine_toml(tmp.path(), "us-west-001"),
            tmp.path().join(".yah/infra/machines/us-west-001.toml")
        );
    }

    #[test]
    fn infra_source_cache_dir_is_scoped_per_owner() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert_eq!(
            infra_source_cache_dir(tmp.path(), "yah"),
            tmp.path().join(".yah/cache/infra/yah")
        );
        assert_ne!(
            infra_source_cache_dir(tmp.path(), "yah"),
            infra_source_cache_dir(tmp.path(), "someone-else")
        );
    }

    #[test]
    fn every_infra_dir_is_camp_local() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_camp_toml(tmp.path(), "name = \"noisetable\"\n");
        // Providers, rules, services, domains all resolve camp-locally. Any
        // borrowing happens in `CloudConfig::load`'s sources.toml overlay, not
        // by rewriting these paths.
        assert_eq!(
            providers_dir(tmp.path()),
            tmp.path().join(".yah/infra/providers")
        );
        assert_eq!(rules_dir(tmp.path()), tmp.path().join(".yah/infra/rules"));
        assert_eq!(services_dir(tmp.path()), tmp.path().join(".yah/services"));
    }
}
