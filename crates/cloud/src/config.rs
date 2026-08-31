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
//!
//! @yah:ticket(R605-F12, "Sovereign groups have no voting axis, so non-voting membership is inexpressible and the raft guard is enforced by an absent field")
//! @yah:status(review)
//! @yah:at(2026-08-20T05:15:30Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @arch:see(.yah/docs/working/W325-isolated-x86-build-capacity.md)
//! @yah:next("OPERATOR INTENT (2026-08-19) that the model cannot currently record: us-west-003 is a NON-VOTING member of the us-west-001-based (prod) sovereign group, and us-west-011 is a DIFFERENT sovereign (dev) from 001/003. The dev/prod split is already declared correctly. The non-voting membership is not — us-west-003.toml declares no sovereign_group at all.")
//! @yah:next("THE GAP: MachineConfig::sovereign_group is a single Option<String>, so membership is binary, and judge_join (oss/yubaba/crates/cloud/src/config.rs:459) permits a join IFF both sides declare the same non-None group. There is no way to say 'in this blast radius, but not quorum-eligible'.")
//! @yah:next("WHY THAT IS ACTIVELY BAD, not just missing: today the ONLY thing refusing us-west-003 into the prod raft at the join gate is its ABSENT stamp. Its own file is emphatic it must never hold a raft node id ('a home-internet partition should never be able to stall the raft'), and that guarantee currently rests on a field nobody wrote. Stamping it prod to record the operator's real intent would REMOVE the guard. This is precisely the W305 failure mode that produced R742-T4: `no-voter` sat inert on three nodes asserting something nothing enforced.")
//! @yah:next("PROPOSED SHAPE (recommended): a second axis, e.g. sovereign_role = voter | non-voter (default voter for back-compat, or make it required), with judge_join permitting a same-group join only for voters. Then us-west-003 stamps prod + non-voter, the intent is machine-readable, and the raft guard stops depending on omission. us-west-004 (R605-T7) would take the same shape.")
//! @yah:next("TOUCHES TWO COPIES OF THE PREDICATE, do not fix only one: cloud::judge_join renders the camp-side refusal, but the predicate itself lives in workload_spec::sovereign::join_permitted because yubaba's POST /raft/add-learner gate asks the same question and there is deliberately no yubaba -> cloud edge. Also re-read `yubaba serve --sovereign-group`, whose node-side gate is narrower on purpose (an unset flag means 'declared nothing', not 'declared standalone').")
//! @yah:gotcha("THE CODE AND THE OPERATOR CURRENTLY DISAGREE ABOUT 003, and a reader should know which is which before editing. judge_join's own doc comment asserts 'prod and dev are both stamped, and us-west-002/003/015 are deliberately not raft members' — i.e. R742-F1 modelled 003 as STANDALONE. The operator's model is that it is a NON-VOTING MEMBER of prod. Those are different claims, not a wording difference: standalone means no blast-radius relationship to 001 at all. Do not silently 'correct' either side; this ticket is the reconciliation.")
//! @yah:gotcha("FLEET STATE AS DECLARED (2026-08-19): prod = us-west-001, us-south-001, us-east-001. dev = us-west-011, us-west-013, us-west-014. NO sovereign_group declared = us-west-002, us-west-003, us-west-015. Verify against the files rather than trusting this list — xtask/tests/fleet_sovereign_groups.rs pins the roster and will need updating in the same change (it also asserts the stamp parses as a TOP-LEVEL key, which matters because 003 has a long comment block before [allocatable] where a stamp would silently become a member of that table).")
//! @yah:gotcha("SEPARATE AXIS, DO NOT ENTANGLE: mesh membership is not sovereign membership. The standing rule is ONE mesh for the entire fleet regardless of group (operator, 2026-08-19), so us-west-003 and us-west-011 enrolling in headscale is unrelated work with no design question in it — see R605-T10. A voting axis on sovereign_group must not become a reason to keep any node off the mesh.")
//! @yah:gotcha("SHARED-TREE COLLISION, live 2026-08-20: R772 (Miravel:spade, session:ce6d74a9) is refactoring oss/yubaba/crates/cloud/src/validate.rs at the same time and the file is currently RED - error[E0425] cannot find function load_machines at validate.rs:753, a half-landed extraction of the machine-loading walk that check_inert_taints / check_retired_arch_tags / the new check_unroled_sovereign_members all duplicate. That error is NOT from this ticket. Told them by party.chat and asked them to absorb check_unroled_sovereign_members into load_machines rather than leave one holdout. Do not hand-fight the file.")
//! @yah:gotcha("R772 ALSO BROKE THREE PRE-EXISTING INGRESS TESTS, again not this ticket: two_services_fronting_one_node_collate_into_one_front_door, a_cross_service_hostname_clash_is_reported_with_both_declarations, one_mirrors_broken_declaration_does_not_hide_the_rest - all failing with 'providers.compute.use = hetzner - no such provider'. Cause is their new CloudConfig::load(workspace_root) at validate.rs:750 inside collate_workspace_ingress; the fronted_mirror fixture declares the slot but never writes infra/providers/hetzner.toml, and CloudConfig::load runs cross_ref_validate. Left alone deliberately - peer-owned.")
//! @yah:gotcha("TRAP THAT MADE THREE OF MY OWN TESTS PASS FOR THE WRONG REASON: the machine-lint sweeps SKIP unparseable TOMLs by design (a peer's half-written scaffold must not sink the sweep). So a test fixture missing a REQUIRED MachineConfig field - mesh_tags is the one that bites - is silently skipped, the lint finds nothing, and every assert-empty test passes vacuously. Only the one test asserting found.len() == 1 noticed. write_sovereign_machine now always writes mesh_tags = [] and carries a comment saying why. Check this before trusting any new test in cloud::validate.")
//! @yah:verify("cargo test -p yah-workload-spec --lib sovereign (from oss/yah-base) -- 9 passed, 0 failed. Covers both new refusals (a_non_voting_member_does_not_join_its_own_group, a_non_voting_target_has_no_quorum_to_join), the back-compat pin (the_default_role_is_the_pre_r605_f12_meaning), and the one-spelling round-trip across TOML/CLI/JSON.")
//! @yah:verify("cargo test -p yubaba --lib sovereign (from oss/yubaba) -- 13 passed, 0 failed. Includes a_non_voting_joiner_is_refused_by_role_not_by_group, a_non_voting_target_refuses_every_joiner, a_group_without_a_role_key_is_a_voter_not_a_refusal (the deployed-fleet back-compat seam), a_peer_reports_its_role_in_the_toml_spelling.")
//! @yah:verify("cargo test -p yubaba --test raft_sovereign_group (from oss/yubaba) -- 11 passed, 0 failed, up from 8. Three new end-to-end against real single-node rafts: a_non_voting_member_of_the_same_group_is_refused, a_non_voting_leader_refuses_to_grow_its_quorum, a_node_publishes_its_role_and_the_leader_reads_it_there (which also proves the request body cannot vote a non-voter in - the leader dials the joiner).")
//! @yah:verify("cargo test -p xtask --test fleet_sovereign_groups (from repo root) -- 2 passed, 0 failed. THE DECISIVE ONE: parses the real .yah/infra/machines/*.toml through the actual MachineConfig deserializer. Confirms us-west-003 = prod + non-voter on disk, all six pre-existing voters now stamped sovereign_role = voter explicitly, and neither key swallowed by a table header.")
//! @yah:verify("cargo test -p yah-cloud --lib (from oss/yubaba) -- 891 passed, 3 failed, where all 3 failures were R772's ingress-collate tests and none were mine. A clean re-run is BLOCKED, not failing: R555's in-flight AdmissionGrant.secrets field breaks velveteen-exec, and yah-cloud is not a root workspace member so its dev-deps can only resolve from the oss/yubaba workspace. Re-run once R555 lands.")
//! @yah:handoff("LANDED, operator chose the second-axis shape (Call 1 = A, 2026-08-20). sovereign_role = voter | non-voter now sits beside sovereign_group, and ONE predicate judges both: workload_spec::sovereign::join_permitted(Membership, Membership) where Membership { group: Option<&str>, role: SovereignRole }. Permitted iff same non-None group AND both sides Voter. Both copies of the predicate call it - cloud::judge_join (camp-side) and yubaba::sovereign_group::judge (node-side) - so the rule itself cannot drift; only the prose differs, which was already the R742-F1 split.")
//! @yah:handoff("WHY THE ROLE IS CHECKED ON BOTH SIDES, since only the joiner half was asked for: a join grows a quorum and it takes two nodes. Refusing a non-voting JOINER is the us-west-003 case. Refusing a non-voting TARGET is the same assertion read from the other end - a box declared non-voting that is serving add-learner is already holding a raft seat its own declaration forbids, and permitting there would paper over the contradiction. Both refusals name the role rather than the group when the groups match, because a message reading 'cross-group join refused: prod and prod' reads as a bug in the check.")
//! @yah:handoff("THE DEFAULT IS THE LOAD-BEARING DECISION AND IT IS DELIBERATELY PERMISSIVE. An absent sovereign_role resolves to Voter (MachineConfig::sovereign_membership, the ONE place the Option is resolved). Reason: before this field, declaring a group WAS declaring quorum eligibility, so absence has to keep meaning that or the change silently retires six live voters. The permissiveness is bounded at the other end by cloud::validate::check_unroled_sovereign_members, which makes `yah cloud validate` FAIL on a group stamp with no role beside it - so the default can be reached by choice but not by silence. MachineConfig::sovereign_role stays Option<SovereignRole> (not a defaulted plain field) precisely so that lint can tell 'chose voter' from 'never considered it'.")
//! @yah:handoff("NODE-SIDE BACK-COMPAT SEAM, pinned by a test because it is a decision and not an oversight: a peer answering GET /raft/status with a sovereign_group but NO sovereign_role key - every yubaba built between R742-F1 and R605-F12, which today is the entire prod raft - is read as Voter, not refused. Refusing would freeze a stamped cluster's growth until every member was rolled, strictly worse than what the role guards against, and it is the same degrade-toward-prior-behaviour stance the module already took for the group. Residue, named rather than hidden in read_group's doc: a box whose machine.toml says non-voter but whose daemon predates the flag answers 'voter' and the node gate admits it. judge_join refuses it camp-side, which is where operator-driven joins go. Window closes per-group as its nodes carry the flag.")
//! @yah:handoff("FILES: workload-spec/src/sovereign.rs (SovereignRole + Membership + role-aware join_permitted, +227). cloud/src/config.rs (sovereign_role field, sovereign_membership(), judge_join same-group role branch, SovereignRole re-exported from cloud::config). cloud/src/validate.rs (check_unroled_sovereign_members + UnroledSovereignMember). app/yah/cli/src/cloud.rs (lint wired: ERROR in `yah cloud validate`, WARNING in the apply preflight - same split as inert-taint/retired-arch-tag, because an unwritten role changes no placement decision and the machine may be declared in a tree this camp does not own). yubaba/src/{sovereign_group,lib,main}.rs (--sovereign-role flag, ServerState.sovereign_role, /raft/status publishes it always-never-null, gate both directions). yubaba-test-harness/src/solo_node.rs (solo_node_with_sovereign_role). .yah/infra/machines/*.toml (7 files). xtask/tests/fleet_sovereign_groups.rs + fleet_build_placement.rs. W325 section 3d.")
//! @yah:handoff("ONE BEHAVIOUR CHANGE WORTH A SECOND OPINION: a node started with --sovereign-role non-voter AND a --raft-node-id now refuses EVERY add-learner. I judged that correct - it is a contradiction the operator should see loudly - but the symptom is 'joins mysteriously stop working' rather than a startup refusal. main.rs warns loudly at boot when that pair is present; I did NOT make it fatal, because refusing to start could brick a node mid-roll. Reconsider if it bites.")
//! @yah:handoff("NOT DONE, and it is a HARD GATE: .yah/schema/machine.toml.schema.json has NOT been regenerated, so sovereign_role is absent from it and schema-drift-guard (scripts/check-schema-drift.sh, a step in .yah/qed/check.toml, run by CI on every push) WILL FAIL. Fix is `cargo run -p xtask -- emit-schemas` from the repo root - it was queued behind ~7 concurrent peer cargo builds for the whole session. Nothing else is required to make this pushable.")
//! @yah:handoff("ALSO NOT RE-CONFIRMED: `cargo test -p yah-cloud --lib` needs a clean run. Its last real run was 891 passed / 3 failed with all three failures belonging to R772's ingress-collate work and none to this ticket. The re-run is BLOCKED not failing - R555's in-flight AdmissionGrant.secrets field breaks velveteen-exec, and yah-cloud is not a root workspace member so its dev-deps only resolve from the oss/yubaba workspace where that break lives. Re-run from oss/yubaba once R555 lands.")
//! @yah:verify("cargo run -p xtask -- emit-schemas (from repo root) -- wrote 8 files, exit 0 after an 18m24s build queued behind ~7 concurrent peer cargo jobs. .yah/schema/machine.toml.schema.json now carries the sovereign_role property (anyOf SovereignRole | null, with the full doc comment) and the SovereignRole definition as a oneOf over the two string enums voter / non-voter. The schema-drift-guard gate for THIS ticket is closed.")
//! @yah:gotcha("emit-schemas IS ALL-OR-NOTHING AND WILL PICK UP A PEER'S UNCOMMITTED WORK. Running it to close this ticket's machine-schema drift also regenerated .yah/schema/secret.toml.schema.json (+34) from R555-F5's in-flight SecretAccess::Recipes / RecipeMatch source. That output is CORRECT for the tree as it stands and was not hand-edited, but it means the schema diff in the working tree is not purely R605-F12's: machine.toml.schema.json (+32) is this ticket, secret.toml.schema.json (+34) is R555. Told Ashguard:spade by party.chat so they carry it with their commit rather than regenerating on top. Anyone splitting these commits needs to split the schema diff too.")
//! @yah:handoff("ALL GATES CLOSED as of 2026-08-20. Both items listed as outstanding in the earlier handoff notes are done: emit-schemas ran (machine.toml.schema.json carries sovereign_role + the SovereignRole voter/non-voter enum, drift guard satisfied), and cargo test -p yah-cloud --lib is 896 passed / 0 failed once R555 and R772 settled. 45 tests green across workload-spec (9), yubaba lib (13), yubaba raft integration (11), yah-cloud lib (10 of this ticket's, within 896), xtask fleet (2). Ready for review. NOTE for whoever commits: the working tree's schema diff is not purely this ticket - .yah/schema/machine.toml.schema.json (+32) is R605-F12, .yah/schema/secret.toml.schema.json (+34) is R555-F5, both correct generated output from one emit-schemas run. Ashguard:spade has agreed to carry theirs.")
//! @yah:verify("cargo test -p yah-cloud --lib (from oss/yubaba) -- 896 passed, 0 FAILED, 4 ignored. The blocked check from earlier is now clean: R555 landed the velveteen-exec and TransformRecipe.secrets fixes, R772's ingress-collate work settled (they replaced the CloudConfig::load in collate_workspace_ingress with a narrower machines-only loader, so cross_ref_validate can no longer fail the collate over an unrelated provider typo). All 45 R605-F12 tests across the four crates are green simultaneously on one tree.")
//! @yah:verify("Confirmed by NAME rather than by total, since a passing count proves nothing about which tests ran: cargo test -p yah-cloud --lib -- role voter voting lists all ten of this ticket's cloud tests green - a_non_voting_member_is_refused_into_its_own_group, a_non_voting_target_has_no_quorum_to_grow, a_refusal_names_the_group_when_fixing_the_role_would_not_help, an_unwritten_role_still_joins_its_group, a_non_voter_is_still_in_the_group_it_names, sovereign_role_round_trips_and_is_omitted_when_unwritten, a_group_with_no_role_is_reported_with_the_declaring_file, either_stated_role_is_clean, a_machine_in_no_group_is_not_asked_for_a_role, unroled_findings_are_ordered_by_file_so_output_is_stable.")

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use thiserror::Error;
use workload_spec::secrets::SecretAccess;
use workload_spec::sovereign::Membership;
pub use workload_spec::sovereign::SovereignRole;
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
    /// Placement taint keys (R572-F3). **There is no toleration** — a
    /// `no-<archetype>` taint is an absolute block, not a preference
    /// (W305/R742-T4; the pre-2026-08-11 "repel-unless-tolerate" wording here
    /// described an `unless` that was never built).
    ///
    /// A key in this list influences placement in exactly one of two ways, and
    /// [`taint_effect`] is the authority on which:
    ///
    /// - **repulsion** — `"no-server"` / `"no-appliance"` / `"no-job"` reject
    ///   workloads of that [`LifecycleArchetype`] outright;
    /// - **affinity** — a key in [`AFFINITY_TAINT_KEYS`] (today just
    ///   `"public-ip"`) that a workload names in
    ///   `yah.placement.requires-taint`, which then *requires* this node.
    ///
    /// Anything else is **inert**: it parses, it round-trips, and no scheduler
    /// decision can ever read it. `yah cloud validate` rejects such keys
    /// (`validate::check_inert_taints`) rather than letting them sit looking
    /// load-bearing — which is how `no-voter` spent months asserting a
    /// falsehood on three nodes. Facts about a node that are not placement
    /// inputs belong in [`mesh_tags`](Self::mesh_tags) or a comment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taints: Vec<String>,
    /// Which consensus group this node belongs to — W305/R742-F1. `None` means
    /// standalone: in no group at all, which is us-west-002 and us-west-015.
    ///
    /// Membership is not by itself quorum eligibility; that is
    /// [`sovereign_role`](Self::sovereign_role), added by R605-F12 because
    /// us-west-003 is in prod's blast radius *and* must never vote in it.
    ///
    /// **Not a placement input.** It is deliberately absent from
    /// [`RequiredSpec::matches`], and adding it there would be a category
    /// error: a sovereign group is a *blast radius*, not a filter. Nothing
    /// about "which quorum does this box vote in" should decide where a
    /// workload runs — that is what made the fleet express three unrelated
    /// properties through one taint list and get all three wrong (W305).
    ///
    /// What it *is* for is refusal. [`judge_join`] answers "may this node join
    /// that node's cluster", and the answer is no unless both declare the same
    /// group. Before this field the only guard was a comment in three machine
    /// TOMLs saying "never run a raft join against this box from a shell
    /// pointed at prod" — habit, with no mechanism behind it, which is the
    /// same class of guard W257 §8 admitted to.
    ///
    /// # Why `sovereign_group` and not `raft_group`
    ///
    /// Raft is today's mechanism (operator, 2026-08-10). A field named for the
    /// mechanism goes stale the day the mechanism is swapped, and every
    /// consumer that reads it inherits the lie. `sovereign` names what the
    /// group *has* — its own authority, its own upgrade cadence, its own
    /// destruction — which stays true under any consensus protocol.
    ///
    /// Note the word already appears in this tree as prose (W267's title, the
    /// `IngressProvider::Passway` doc comment's "sovereign edge"). That is an
    /// adjective meaning "self-hosted, not SaaS"; this is the first time it
    /// carries structure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sovereign_group: Option<String>,
    /// Whether this node may hold a seat in its group's quorum — R605-F12.
    /// Meaningless without [`sovereign_group`](Self::sovereign_group): a
    /// standalone box has no quorum to be eligible for.
    ///
    /// **`None` is "not written", not a third role.** Read it through
    /// [`sovereign_membership`](Self::sovereign_membership), which resolves the
    /// absence to [`SovereignRole::Voter`] — what declaring a group has always
    /// meant, so the six nodes stamped before this field keep their seats
    /// without an edit. The distinction is kept only so
    /// [`crate::validate::check_unroled_sovereign_members`] can tell an
    /// operator who *chose* voter from one who never considered the question;
    /// no join decision reads the `Option` directly.
    ///
    /// # Why this is not a taint
    ///
    /// It was, once: `no-voter` sat in [`taints`](Self::taints) on three nodes
    /// for months, read by nothing, and R742-T4 removed it because the taint
    /// list is a *placement* vocabulary and this is not a placement input (see
    /// [`taint_effect`]). Nor is it a second group label. It is a modifier on
    /// the membership this node already declares, which is why it lives beside
    /// the group and is judged with it in one predicate,
    /// [`workload_spec::sovereign::join_permitted`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sovereign_role: Option<SovereignRole>,
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

/// Taint keys a workload may name in `yah.placement.requires-taint` to
/// *require* a node (W305/R742-T4 affinity vocabulary).
///
/// This is a closed list on purpose. `WorkloadSpec::requires_taint` returns
/// free text, but every producer in the tree is code — `passway_ingress.rs`
/// and `cloudflared_ingress.rs`, both emitting
/// [`workload_spec::PUBLIC_IP_TAINT`] — and no on-disk `workload.toml` sets the
/// annotation at all. So the set of keys a node can usefully carry for
/// affinity is knowable at compile time, which is what lets
/// [`taint_effect`] call anything outside it inert instead of guessing.
///
/// **Adding an affinity key means adding it here**, in the same change that
/// teaches a workload to require it. That coupling is the point: it makes the
/// node side and the workload side impossible to land apart.
pub const AFFINITY_TAINT_KEYS: &[&str] = &[workload_spec::PUBLIC_IP_TAINT];

/// How a key in [`MachineConfig::taints`] can affect placement.
///
/// W305 finding 1: before R742-T4 nothing asked this question, so a key that
/// no scheduler path could read — `"qa"`, `"no-voter"` — parsed, validated,
/// and quietly did nothing. Both of the findings that cost real fleet state
/// were invisible for exactly that reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintEffect {
    /// `"no-<archetype>"`: rejects workloads of that archetype outright. Read
    /// by [`RequiredSpec::matches`] via `repel_archetype`.
    Repels(LifecycleArchetype),
    /// A key in [`AFFINITY_TAINT_KEYS`]: a workload naming it in
    /// `yah.placement.requires-taint` is restricted to nodes carrying it.
    Attracts,
    /// Neither. No placement decision can read this key.
    Inert,
}

/// Classify one node taint key. See [`TaintEffect`].
///
/// The repulsion half is derived from [`LifecycleArchetype::ALL`] rather than
/// a literal list, so a fourth archetype makes `no-<its key>` live without an
/// edit here.
pub fn taint_effect(key: &str) -> TaintEffect {
    if let Some(arch) = LifecycleArchetype::ALL
        .into_iter()
        .find(|a| key == format!("no-{}", a.taint_key()))
    {
        return TaintEffect::Repels(arch);
    }
    if AFFINITY_TAINT_KEYS.contains(&key) {
        return TaintEffect::Attracts;
    }
    TaintEffect::Inert
}

/// Every key the scheduler *can* act on, sorted — for error messages that
/// tell the operator what the legal vocabulary actually is instead of only
/// what was wrong.
pub fn live_taint_keys() -> Vec<String> {
    let mut keys: Vec<String> = LifecycleArchetype::ALL
        .into_iter()
        .map(|a| format!("no-{}", a.taint_key()))
        .chain(AFFINITY_TAINT_KEYS.iter().map(|k| (*k).to_string()))
        .collect();
    keys.sort();
    keys
}

/// What [`judge_join`] decided about one proposed cluster join.
///
/// Shaped like yubaba's `PromotionVerdict` / `GeographyVerdict` and for the
/// same reason: the rule stays unit-testable without a live cluster, and a
/// refusal carries its reason from the place that knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinVerdict {
    /// Both nodes declare the same sovereign group and both are voters. The
    /// join is within one blast radius and grows a quorum both sides are
    /// eligible for.
    Permit,
    /// The join is refused. Carries an operator-readable reason naming both
    /// declared values and the file to edit — a refusal that only says
    /// "invalid" gets worked around rather than fixed.
    Refuse(String),
}

/// May `joiner` join the cluster `target` belongs to? — W305/R742-F1.
///
/// **A join is permitted iff both nodes declare the same non-`None`
/// [`sovereign_group`](MachineConfig::sovereign_group) and both are
/// [`SovereignRole::Voter`].** One rule, no special cases, and it makes the
/// declaration mandatory before any quorum grows.
///
/// The case this exists for is two *different* declared groups: joining a dev
/// Pi into prod is refused rather than trusted, where today the only guard is
/// a comment saying not to do it. But an undeclared node is refused too, and
/// that is the deliberate half — `None` means "in no group", not "unknown", so
/// growing prod with an unstamped box is exactly as much a cross-group join as
/// the dev case is. Failing open there would leave the operator believing a
/// guarantee that was never evaluated, which is the reasoning
/// `QuorumGeography::judge` already applies to untagged voters.
///
/// No legitimate flow pays for that strictness: prod and dev are both stamped,
/// and us-west-002/015 are deliberately in no group at all. Adding a real
/// member means declaring it first, which is the point.
///
/// # The non-voting refusal (R605-F12)
///
/// Same group and still refused, when either side declares
/// [`SovereignRole::NonVoter`]. This is the case a group label alone could not
/// express. us-west-003 is a residential-uplink build box the operator counts
/// as part of prod — same secrets, same upgrade cadence, same destruction — and
/// which must never hold a prod raft seat, because a home-internet partition
/// should not be able to stall the quorum. Until R605-F12 the only thing
/// refusing it was its *absent* stamp, so recording the operator's real intent
/// (`sovereign_group = "prod"`) would have removed the guard. Now the intent
/// and the guard are the same two lines.
///
/// Note what this is not: the refusal here is about *voting*, and it says
/// nothing about the mesh. One mesh spans the whole fleet regardless of group
/// or role (operator, 2026-08-19); a non-voter is reachable, schedulable and
/// rollable like any other node.
///
/// This is the **camp-side** rendering of the rule. The predicate itself lives
/// in [`workload_spec::sovereign::join_permitted`] because yubaba's
/// `POST /raft/add-learner` gate asks the same question and cannot see this
/// crate (there is deliberately no yubaba → cloud edge). Only the prose is
/// duplicated, and it has to be: a refusal here names
/// `.yah/infra/machines/<name>.toml`, while the node-side one has no machine
/// name in hand and must also name `yubaba serve --sovereign-group`.
///
/// The node-side gate is *narrower* on purpose, and the difference is worth
/// knowing when reading either: a daemon started without `--sovereign-group`
/// has declared nothing rather than declared standalone, so yubaba resolves
/// that unknown before it judges, and its gate is in force only once the
/// cluster being joined declares a group. See `yubaba::sovereign_group`.
pub fn judge_join(joiner: &MachineConfig, target: &MachineConfig) -> JoinVerdict {
    let stamp_hint = |m: &MachineConfig| {
        format!(
            "declare `sovereign_group = \"<group>\"` in .yah/infra/machines/{}.toml",
            m.name
        )
    };
    let role_hint = |m: &MachineConfig| {
        format!(
            "set `sovereign_role = \"voter\"` in .yah/infra/machines/{}.toml",
            m.name
        )
    };
    if workload_spec::sovereign::join_permitted(
        joiner.sovereign_membership(),
        target.sovereign_membership(),
    ) {
        return JoinVerdict::Permit;
    }
    let (j, t) = (
        joiner.sovereign_group.as_deref(),
        target.sovereign_group.as_deref(),
    );
    // Everything below is a refusal; the only permitted shape returned above.
    //
    // R605-F12: when both sides name the SAME group, the role is the only thing
    // left that can have refused, and it gets its own message. Falling through
    // to the arms below would print "cross-group join refused: 'us-west-003' is
    // in "prod" and 'us-west-001' is in "prod"" — a message that reads as a bug
    // in the check rather than a decision about the fleet.
    //
    // Deliberately not hoisted above the group comparison. A non-voting joiner
    // whose target is standalone is refused for *both* reasons, and naming the
    // role there would send the operator to fix a field that would not have
    // made the join legal anyway.
    if let (Some(a), Some(b)) = (j, t) {
        if a == b {
            for (m, side, other) in [
                (joiner, "the joiner", &target.name),
                (target, "the target", &joiner.name),
            ] {
                if m.sovereign_membership().role.is_voter() {
                    continue;
                }
                return JoinVerdict::Refuse(format!(
                    "join refused: {side} '{}' is a NON-VOTING member of sovereign group {a:?}, \
                     the same group as '{other}'. It is inside that blast radius — same secrets, \
                     same upgrade cadence, same destruction — but declares itself ineligible for \
                     the quorum, so this is refused by declaration rather than by omission. If it \
                     should genuinely vote, {}; if it should not, this refusal is the field doing \
                     its job and the join is the thing to reconsider.",
                    m.name,
                    role_hint(m),
                ));
            }
        }
    }
    match (j, t) {
        (Some(a), Some(b)) => JoinVerdict::Refuse(format!(
            "cross-group join refused: '{}' is in sovereign group {a:?} and '{}' is in {b:?}. \
             These are separate blast radii — separate quorums, separate upgrade cadences, \
             separately destroyable — and merging them is not something a join can undo. If \
             the move is genuinely intended, restamp '{}' to {b:?} first and treat it as \
             leaving its old group.",
            joiner.name,
            target.name,
            joiner.name,
        )),
        (None, Some(b)) => JoinVerdict::Refuse(format!(
            "join refused: '{}' declares no sovereign_group, so it is standalone — in no \
             group — while '{}' is in {b:?}. That is a cross-group join, not an unchecked \
             one. To make '{}' a member of {b:?}, {}.",
            joiner.name,
            target.name,
            joiner.name,
            stamp_hint(joiner),
        )),
        (Some(a), None) => JoinVerdict::Refuse(format!(
            "join refused: '{}' is in sovereign group {a:?} but '{}' declares none, so the \
             target is standalone and has no group to join. Either {}, or found the group on \
             '{}' rather than growing it.",
            joiner.name,
            target.name,
            stamp_hint(target),
            joiner.name,
        )),
        (None, None) => JoinVerdict::Refuse(format!(
            "join refused: neither '{}' nor '{}' declares a sovereign_group, so this join \
             would form a group nobody declared and nothing could later reason about. Name \
             the group on both boxes first: {}, and the same for '{}'.",
            joiner.name,
            target.name,
            stamp_hint(joiner),
            target.name,
        )),
    }
}

impl MachineConfig {
    /// This node's declared place in a sovereign group, as the shared join rule
    /// wants it — R605-F12.
    ///
    /// The one place `sovereign_role`'s `None` is resolved. Absence means
    /// [`SovereignRole::Voter`], which is what declaring a group meant before
    /// the role existed; resolving it here rather than at each call site is what
    /// keeps the camp-side and node-side gates from disagreeing about a node
    /// that never wrote the field.
    pub fn sovereign_membership(&self) -> Membership<'_> {
        Membership {
            group: self.sovereign_group.as_deref(),
            role: self.sovereign_role.unwrap_or_default(),
        }
    }

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

    /// Declared taints that no placement decision can read (W305/R742-T4).
    ///
    /// Deliberately **not** folded into [`validate`](Self::validate): that
    /// guard runs on the provision/diff hot path and answers a different
    /// question (can the driver create this server). An inert taint is a lint
    /// — it never breaks an operation in flight, it just means the file is
    /// asserting something the scheduler will not honour. `yah cloud validate`
    /// is where the operator asks for that judgement; see
    /// [`crate::validate::check_inert_taints`].
    pub fn inert_taints(&self) -> Vec<&str> {
        self.taints
            .iter()
            .filter(|t| taint_effect(t) == TaintEffect::Inert)
            .map(String::as_str)
            .collect()
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

    /// Base URL for this node's yubaba, or `None` when no reach resolves.
    ///
    /// Thin wrapper over [`reach`](Self::reach) for the many call sites that
    /// only branch on presence. Prefer `reach` anywhere the operator sees the
    /// outcome — a `None` here throws away a refusal that names exactly which
    /// address is missing.
    pub fn yubaba_url(&self) -> Option<String> {
        self.reach().ok()
    }

    /// The **one** address automation dials for this node — mesh-only.
    ///
    /// `Err` is a *named refusal*, not an absence: a node with no mesh address
    /// is unresolvable to every automated path, and R605-T10's whole complaint
    /// is that this used to surface as a connect timeout against an address the
    /// caller has no route to.
    ///
    /// Resolution order:
    ///
    /// 1. A declared `[connect].yubaba` on a **private** host (10/8,
    ///    172.16/12, 192.168/16) is **not dialed** — see below.
    /// 2. Any other declared `[connect].yubaba` wins verbatim. That includes
    ///    the pre-mesh loopback placeholder (`http://127.0.0.1:7443`, "I have
    ///    no mesh address; reach me through the SSH tunnel to `ssh`"), which is
    ///    a genuine declaration and stays honoured.
    /// 3. Otherwise `[registration].mesh_ipv4` composed with
    ///    `[connect].yubaba_port`.
    ///
    /// **Why a LAN literal loses (R605-T10, operator 2026-08-19).** The LAN
    /// address is an emergency break-glass route, never an official one, and
    /// automation must ALWAYS assume the caller is not on that LAN — this camp
    /// sits on 192.168.22.0/22 with no route to the fleet's 192.168.10.0/24 at
    /// all. Writing one into the field every resolver dials does not sit beside
    /// the mesh route, it *overrides* it: R707-T6 made a declared literal beat
    /// `mesh_ipv4` outright, so us-west-011 (mesh-joined, healthy) was elected
    /// for every aarch64 build and then dialed at an address that answers only
    /// from inside bldg-2506.
    ///
    /// **What R707-T6 wanted is preserved elsewhere.** Its forcing case was
    /// identity, not reach: the dev raft group advertises LAN addrs
    /// (`192.168.10.11:7443`, verified live off `/raft/status` 2026-08-27), and
    /// `rollout::yubaba::membership_to_nodes` has to map those back to declared
    /// machines. That match now runs against [`lan_endpoint`](Self::lan_endpoint),
    /// which is composed from the break-glass `[connect].address` metadata and
    /// is never dialed — so the two concerns the old precedence rule fused are
    /// split, and the literal can stop squatting a dialed field.
    ///
    /// The LAN address itself STAYS in the machine TOML. It is useful metadata
    /// and the manual `ssh` path is entitled to it; it is only disconnected
    /// from every automated process.
    pub fn reach(&self) -> Result<String, String> {
        let Some(connect) = self.connect.as_ref() else {
            return Err(format!(
                "machine {:?} declares no [connect] block, so nothing knows how to reach it \
                 \u{2192} declare one, or leave it unprovisioned and out of placement",
                self.name
            ));
        };
        let mesh = || {
            self.registration
                .mesh_ipv4
                .as_deref()
                .map(|ip| format!("http://{ip}:{}", connect.yubaba_port()))
        };
        if let Some(literal) = &connect.yubaba {
            let Some(lan) = private_ipv4_from_url(literal) else {
                return Ok(literal.clone());
            };
            return mesh().ok_or_else(|| {
                format!(
                    "machine {:?} is unresolvable to automation: its only declared yubaba reach \
                     is the private literal {:?} and it has no [registration].mesh_ipv4\n\
                     \u{2192} a LAN address is an emergency break-glass route, never an official \
                     one (R605-T10) — every automated path assumes the caller is NOT on {}/24\n\
                     \u{2192} mesh-join the box and record `mesh_ipv4` under [registration], then \
                     delete `[connect].yubaba` so the port composes with it",
                    self.name,
                    literal,
                    lan.rsplit_once('.').map(|(net, _)| net).unwrap_or(lan),
                )
            });
        }
        mesh().ok_or_else(|| {
            format!(
                "machine {:?} has no [registration].mesh_ipv4 and declares no \
                 [connect].yubaba, so no automated path can reach it\n\
                 \u{2192} mesh-join the box and record its tailnet address, or taint it out of \
                 placement — do not point `[connect].yubaba` at a LAN address (R605-T10)",
                self.name
            )
        })
    }

    /// The LAN `host:port` this node's yubaba answers on, composed from the
    /// break-glass `[connect].address` metadata plus the declared port.
    ///
    /// **Identity only — never dial this.** It exists so a raft membership
    /// entry that names a node by its LAN address can be mapped back to the
    /// declared machine (`rollout::yubaba::membership_to_nodes`) without that
    /// address having to live in a field a resolver reads. `None` when the
    /// machine is unprovisioned.
    pub fn lan_endpoint(&self) -> Option<String> {
        let connect = self.connect.as_ref()?;
        Some(format!("{}:{}", connect.address, connect.yubaba_port()))
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
    let host = ipv4_host_of(url)?;
    let ip: std::net::Ipv4Addr = host.parse().ok()?;
    let [a, b, ..] = ip.octets();
    // 100.64.0.0/10 ⇒ first octet 100, second octet 64..=127.
    (a == 100 && (64..=127).contains(&b)).then_some(host)
}

/// Host of an `http://host:port` URL iff it is an **RFC1918 private** IPv4 —
/// `10/8`, `172.16/12`, `192.168/16`. `None` for anything else, loopback and
/// the `100.64/10` mesh range included: neither is a LAN literal.
///
/// The judgement R605-T10 turns on. A private literal is only ever reachable
/// from inside one building, so it is metadata about where the box physically
/// sits and never an address automation may dial — see
/// [`MachineConfig::reach`] and [`crate::validate::check_lan_dial_targets`].
pub fn private_ipv4_from_url(url: &str) -> Option<&str> {
    let host = ipv4_host_of(url)?;
    is_private_ipv4(host).then_some(host)
}

/// Whether a bare host string is an RFC1918 private IPv4 literal.
pub fn is_private_ipv4(host: &str) -> bool {
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    ip.is_private()
}

/// Bare host of a `[scheme://]host[:port][/path]` string.
fn ipv4_host_of(url: &str) -> Option<&str> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    after_scheme.split(['/', ':']).next()
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
                let Some(component) = svc.service.components.iter().find(|c| c.id == comp_id)
                else {
                    anyhow::bail!(
                        "domains/{dom_name}.toml: routes[{idx}].component = \
                         \"{component_ref}\" — service \"{svc_name}\" has no \
                         component with id \"{comp_id}\""
                    );
                };

                // R746: a mounted component must be routed where it publishes.
                // The publisher writes its bundle under the mount and the front
                // door looks a request up by its own path, so a route path and
                // a mount that disagree produce a 404 with its cause two files
                // away. Checked in both directions, since either one alone is
                // the same silent miss.
                //
                // Static routes only: `mount` is a *storage* prefix, and a
                // backend route proxies to an origin that owns its own paths.
                if !matches!(route.mode, RouteMode::Static { .. }) {
                    continue;
                }
                let mount = component.mount.as_deref().map(normalize_mount);
                let route_prefix = route_path_prefix(&route.path);
                if let Some(mount) = mount {
                    if mount != route_prefix {
                        anyhow::bail!(
                            "domains/{dom_name}.toml: routes[{idx}].path = \
                             \"{path}\" serves \"{component_ref}\", which \
                             declares mount = \"/{mount}\" — a mounted \
                             component publishes under its mount, so the route \
                             must be \"/{mount}\" or \"/{mount}/*\" (or drop \
                             the mount to serve from the service root)",
                            path = route.path,
                        );
                    }
                } else if !route_prefix.is_empty() {
                    anyhow::bail!(
                        "domains/{dom_name}.toml: routes[{idx}].path = \
                         \"{path}\" serves \"{component_ref}\", which declares \
                         no `mount` — its bundle publishes at the service root, \
                         so nothing is stored under \"/{route_prefix}\". Set \
                         mount = \"/{route_prefix}\" on the component, or route \
                         it at \"/*\"",
                        path = route.path,
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

    /// Every machine declaring `sovereign_group == group`, in declaration order.
    ///
    /// W305/R742-F3. A sovereign group has no file of its own — it exists only
    /// as the set of machines that name the same string — so "which boxes are
    /// the dev cluster" has to be *derived*, and before this it was not derived
    /// anywhere: `yah cloud rollout plan` still takes a hand-listed
    /// `--voter us-west-011 --voter us-west-013 …` for a fact the machine TOMLs
    /// already state (W314 gap 1).
    ///
    /// **This is not placement.** Resolving a group to its members is a
    /// *lookup*, and it stays outside [`RequiredSpec`] on purpose — see
    /// [`MachineConfig::sovereign_group`]. `migrate` calls this to pick the
    /// candidate set it then admits a workload against; nothing here filters
    /// scheduling, and adding `sovereign_group` to `matches` would still be the
    /// category error that doc warns about.
    ///
    /// An empty result means no machine declares `group`, which is
    /// indistinguishable from a typo — callers should say so with
    /// [`Self::declared_sovereign_groups`] rather than reporting "no
    /// candidates".
    pub fn machines_in_group(&self, group: &str) -> Vec<&MachineConfig> {
        self.machines
            .iter()
            .filter(|m| m.sovereign_group.as_deref() == Some(group))
            .collect()
    }

    /// Every distinct `sovereign_group` declared by any machine, sorted.
    ///
    /// Exists so a bad `--to` names the real vocabulary instead of complaining
    /// abstractly — the same fail-loud shape [`taint_effect`]'s legal-key list
    /// gives `check_inert_taints`. Standalone machines (`None`) contribute
    /// nothing: "in no group" is not a group you can migrate *to*.
    pub fn declared_sovereign_groups(&self) -> Vec<&str> {
        let mut groups: Vec<&str> = self
            .machines
            .iter()
            .filter_map(|m| m.sovereign_group.as_deref())
            .collect();
        groups.sort_unstable();
        groups.dedup();
        groups
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
        resolve_machine_among(&self.machines, req)
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
    /// `TaskLocation::RemoteAny.mesh_tags` — e.g. `[tag:build-worker, arch:x86]`
    /// from [`qed::platform::build_worker_mesh_tags`] — into the workload's
    /// annotations. This is the consumer: candidates are restricted to machines
    /// whose `mesh_tags` are a **superset** of the requested set, so an amd64
    /// build lands on the `arch:x86` build-worker (us-west-002) and an arm64
    /// build on a `arch:arm` Pi5. Declaration order in `.yah/infra/machines/`
    /// breaks ties.
    ///
    /// An absent or empty annotation means "no mesh-tag constraint" — pre-R594
    /// behavior (any node), matching [`RequiredSpec::is_unconstrained`].
    ///
    /// This is the single admission seam: R572-F5 extends it with the capacity
    /// floor (workload request fits node allocatable−committed) and taint
    /// repulsion/affinity by enriching [`RequiredSpec::matches`] /
    /// [`Self::resolve_machine`]. Do not fork a second selector.
    pub fn admit_workload(&self, ws: &WorkloadSpec) -> Result<&MachineConfig> {
        self.resolve_machine(&admission_spec(ws))
    }

    /// [`Self::admit_workload`] restricted to the machines of one sovereign
    /// group (W305/R742-F3, `yah cloud migrate --to <group>`).
    ///
    /// Same [`RequiredSpec`], same [`RequiredSpec::matches`], same
    /// declaration-order tie-break — only the candidate *set* differs. That is
    /// the whole reason this is a narrowing of the admission seam rather than a
    /// second selector: a workload that cannot be scheduled onto a group's
    /// boxes must fail here for exactly the reason it would fail anywhere else,
    /// and `no-appliance` on the dev Pis (W305 finding 2) is precisely the case
    /// that must not be silently routed around by a migration verb.
    ///
    /// `Err` when the group has no members *or* when no member admits `ws`; the
    /// two are different mistakes, so callers wanting to tell them apart should
    /// check [`Self::machines_in_group`] first.
    pub fn admit_workload_in_group(
        &self,
        ws: &WorkloadSpec,
        group: &str,
    ) -> Result<&MachineConfig> {
        let members = self.machines_in_group(group);
        let empty_pool = format!(
            "(no machine declares sovereign_group = \"{group}\" — declared groups: {})",
            match self.declared_sovereign_groups().as_slice() {
                [] => "(none)".to_string(),
                gs => gs.join(", "),
            }
        );
        first_match(
            &members,
            &admission_spec(ws),
            &format!("machines in sovereign group '{group}'"),
            &empty_pool,
        )
    }
}

/// **The** placement selector: the first candidate satisfying every axis of
/// `req`, declaration order breaking ties, deterministic-greedy with no
/// backtracking.
///
/// Every path that picks a machine goes through here, and the only thing any
/// of them varies is *which machines are candidates* — never the predicate.
/// [`CloudConfig::resolve_machine`] passes the whole fleet;
/// [`CloudConfig::admit_workload_in_group`] passes one sovereign group's
/// members. That split is the point: a candidate-set narrowing composes with
/// the [`RequiredSpec`] axes for free, whereas expressing the same narrowing
/// *as* an axis would put facts like blast radius into a filter they must
/// never be in (see [`MachineConfig::sovereign_group`]).
///
/// So a new placement scope is a new candidate set plus a `pool` label, and a
/// new placement *constraint* is a field on [`RequiredSpec`] — those are the
/// two extension points, and neither is a second selector. `pool` and
/// `empty_pool` exist only so the failure names the set it actually searched;
/// a refusal that says "no candidates" without saying *among what* is one the
/// operator has to reconstruct by hand.
/// F16 placement v1 resolution over an explicit machine list — the
/// `.machines`-only half of [`CloudConfig::resolve_machine`], for callers that
/// have loaded just the machines tree rather than the whole cross-ref-validated
/// config.
///
/// R772: `resolve_ingress_placements` (`reconciler::ingress`) is the reason
/// this is `pub(crate)` rather than staying folded into
/// `CloudConfig::resolve_machine` — ingress collation walks every mirror in
/// the workspace and has no business hard-failing over an unrelated mirror's
/// `providers.X.use = "<id>"` typo, which is what going through
/// `CloudConfig::load`'s cross-ref validation would do. "Do not fork a second
/// selector" (see the module doc above) still holds: this is the *same*
/// [`first_match`], just handed a narrower candidate set than `self.machines`.
pub(crate) fn resolve_machine_among<'a>(
    machines: &'a [MachineConfig],
    req: &RequiredSpec,
) -> Result<&'a MachineConfig> {
    let all: Vec<&MachineConfig> = machines.iter().collect();
    first_match(
        &all,
        req,
        "declared machines",
        "(no machines declared under .yah/infra/machines/)",
    )
}

fn first_match<'a>(
    candidates: &[&'a MachineConfig],
    req: &RequiredSpec,
    pool: &str,
    empty_pool: &str,
) -> Result<&'a MachineConfig> {
    candidates
        .iter()
        .copied()
        .find(|m| req.matches(m))
        .ok_or_else(|| {
            let names = if candidates.is_empty() {
                empty_pool.to_string()
            } else {
                candidates
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            anyhow::anyhow!(
                "no candidates matching {} — {pool}: {names}",
                req.describe()
            )
        })
}

/// The [`RequiredSpec`] a workload is admitted against — the single place the
/// axes are derived from a [`WorkloadSpec`].
///
/// Extracted from [`CloudConfig::admit_workload`] so that
/// [`CloudConfig::admit_workload_in_group`] narrows the candidate set without
/// restating the axes. Forking that derivation is how the two paths would
/// silently disagree about whether a workload fits a node.
fn admission_spec(ws: &WorkloadSpec) -> RequiredSpec {
    RequiredSpec {
        mesh_tags: node_selector_mesh_tags(ws),
        // R833-F8: imperative node pin. Derived here alongside the inferred
        // mesh tags rather than short-circuiting the resolver, so a pinned
        // workload is still checked against capacity and taints.
        nodes: node_selector_node(ws).into_iter().collect(),
        // R572-F5: capacity floor from the workload's resource request.
        //
        // `memory_request_mb()` and NOT `resources.memory_mb`: the latter
        // is a cgroup ceiling, and reading a ceiling as a floor made
        // `for_forge`'s deliberately-roomy 32 GiB limit mean "only place
        // me on a 32 GiB node". That excluded every build-worker in the
        // fleet but one. The accessor falls back to `resources.memory_mb`
        // when no request is declared, so specs that never set one are
        // admitted exactly as before.
        memory_mb: ws.memory_request_mb(),
        cpu_millis: ws.resources.cpu_millis,
        // R572-F5: taint repulsion derived from the workload's effective archetype.
        repel_archetype: Some(ws.effective_archetype()),
        // R572-F5: taint affinity from the requires-taint annotation.
        requires_taint: ws.requires_taint().map(str::to_owned),
        ..Default::default()
    }
}

/// Parse the R594 mesh-tag node-selector off a workload's annotations into the
/// requested tag set. Absent annotation or empty value ⇒ empty vec ("no
/// constraint"). Whitespace around each comma-separated tag is trimmed and
/// empty segments are dropped, so `"tag:build-worker, arch:x86"` and
/// `"tag:build-worker,arch:x86"` parse identically.
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

/// Parse the R833-F8 imperative node-selector off a workload's annotations —
/// the single machine `name` the operator pinned the run to
/// (`--where=node:us-west-003`). Absent or blank ⇒ `None` ("no constraint"),
/// which is every workload built before this axis existed.
///
/// One node, not a list: the annotation exists to express "run it *there*", and
/// a comma-joined set would be a worse spelling of the mesh-tag selector that
/// already handles "any of these".
pub fn node_selector_node(ws: &WorkloadSpec) -> Option<String> {
    ws.annotations
        .get(velveteen_exec::remote::NODE_SELECTOR_NODE_ANNOTATION)
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(String::from)
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
/// `[tag:build-worker, arch:x86, os:linux]`. Same sort `load_providers` has
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
    /// URL sub-path a static component's build output is published under,
    /// relative to the service's publish prefix (R746). `None` = the service
    /// root, which is what every pre-R746 component means.
    ///
    /// Static publishers lay a component's `out_dir` down at
    /// `<bucket>/<service>/<env>/…` and the front door fetches
    /// `${ASSET_ORIGIN}/<request path>` — the request path *is* the key. So a
    /// service with two static components had them overwrite each other at
    /// one prefix, and there was no way to say "this bundle serves under
    /// /app". `mount` is that: it appends to the publish prefix, which makes
    /// the URL sub-path and the storage sub-path the same string by
    /// construction rather than by two manifests agreeing.
    ///
    /// Cross-checked against the domain route that names the component
    /// ([`CloudConfig::cross_ref_validate`]): a component mounted at `/app`
    /// must be routed at `/app` or `/app/*`, because a disagreement means
    /// requests land on a prefix nothing published to — a 404 whose cause is
    /// two files apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount: Option<String>,
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

/// One declared **edge**: a front door, the slots it fronts, and the nodes it
/// is placed on (W305 F2).
///
/// A mirror declares a *list* of these, which is what lets one service mix
/// front doors — cloudflare for the public web tier, passway for an internal or
/// high-throughput one. Before this, [`MirrorConfig::ingress`] was a single
/// [`IngressProvider`], so a mirror could **swap** front doors but never mix
/// them.
///
/// ```toml
/// [[ingress]]
/// provider = "passway"
/// machines = ["us-east-001", "us-south-001"]
/// slots    = ["bundle"]
///
/// [[ingress]]
/// provider  = "cloudflare-tunnel"
/// hostnames = ["issues.yah.dev"]
/// ```
///
/// **The per-node appliance is derived from this, never declared beside it.**
/// An edge does invoke a cloudflared or passway process on a box, but that is a
/// *consequence* of the service's declaration:
/// [`collate_front_doors`](crate::reconciler::collate_front_doors) walks every
/// service and derives what each node must run. Declaring it node-side too is
/// what produces two sources of truth for one fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct IngressEdge {
    /// Which front door this edge is. [`IngressProvider::None`] is rejected at
    /// plan time — an edge that fronts with nothing is always a typo, never an
    /// intent (write no edge instead).
    pub provider: IngressProvider,
    /// Nodes this front door is placed on — **independent of where the fronted
    /// workload runs** (R330-F37).
    ///
    /// Empty falls back to the fronted slot's own `machine` / `machines`, which
    /// is the co-located shape every mirror had before front-door placement was
    /// expressible. Listing several is what lets the ingress tier and the
    /// service tier scale independently: **N front doors over ONE deployment**,
    /// one rendered copy, so no cache coherence to settle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub machines: Vec<String>,
    /// Provider slot roles this edge fronts (`"bundle"`, `"compute"`, …).
    ///
    /// One of the two selectors. With a single edge both may be empty, meaning
    /// "every fronted slot" — the legacy shape. With **several** edges a
    /// selector is mandatory on each, and the partition must be total and
    /// disjoint: a slot claimed by no edge, or by two, is an error naming it.
    /// An implicit catch-all across mixed front doors would silently publish a
    /// service through the wrong one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slots: Vec<String>,
    /// Public hostnames this edge fronts — the other selector, for partitioning
    /// by what the world dials rather than by which slot serves it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    /// Cloudflare Tunnel id this edge publishes through, overriding the
    /// fronting machine's [`MachineConfig::cloudflared`].
    ///
    /// This is W267 Gap 3's real fix, and it is the *service* side of it: a node
    /// can join two cohorts' orange networks, and since §Granularity argues the
    /// tunnel credential **is** the isolation boundary, which cohort a given
    /// service fronts through is a property of the service, not of the box.
    /// `MachineConfig.cloudflared` stays as the per-node default (one tunnel is
    /// the common case, and the credential does live on the node), but it is no
    /// longer the only way to say it — so the node never has to enumerate
    /// cohorts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_id: Option<String>,
}

impl IngressEdge {
    /// An edge with no selector — fronts every fronted slot, legal only when it
    /// is the mirror's only edge.
    pub fn all_slots(provider: IngressProvider, machines: Vec<String>) -> Self {
        Self {
            provider,
            machines,
            slots: Vec::new(),
            hostnames: Vec::new(),
            tunnel_id: None,
        }
    }

    /// `true` when this edge names which slots/hostnames it fronts.
    pub fn has_selector(&self) -> bool {
        !self.slots.is_empty() || !self.hostnames.is_empty()
    }

    /// Does this edge claim the rule derived from `slot` publishing `hostname`?
    ///
    /// A selectorless edge claims everything; that is checked to be
    /// unambiguous (one edge only) before this is consulted.
    pub fn claims(&self, slot: &str, hostname: &str) -> bool {
        if !self.has_selector() {
            return true;
        }
        self.slots.iter().any(|s| s == slot) || self.hostnames.iter().any(|h| h == hostname)
    }

    /// Human-readable identity for an error message — the provider plus
    /// whichever selector was written.
    pub fn label(&self) -> String {
        let sel = match (self.slots.is_empty(), self.hostnames.is_empty()) {
            (true, true) => "no selector".to_string(),
            (false, true) => format!("slots = {:?}", self.slots),
            (true, false) => format!("hostnames = {:?}", self.hostnames),
            (false, false) => format!("slots = {:?} + hostnames = {:?}", self.slots, self.hostnames),
        };
        format!("[[ingress]] provider = {:?} ({sel})", self.provider.as_str())
    }
}

/// A mirror's `ingress` declaration, in either spelling.
///
/// The list is the general form; the bare provider is shorthand for the single
/// edge fronting everything, and is kept rather than migrated because it is the
/// honest spelling for the common case — one service, one front door. Both
/// normalize to the same `Vec<IngressEdge>` through
/// [`MirrorConfig::ingress_edges`], so nothing downstream branches on which was
/// written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum IngressDecl {
    /// `ingress = "passway"` — one edge fronting every fronted slot, placed by
    /// the sibling [`MirrorConfig::ingress_machines`].
    Provider(IngressProvider),
    /// `[[ingress]]` — one entry per declared edge.
    Edges(Vec<IngressEdge>),
}

/// Hand-written because `#[serde(untagged)]` throws the real error away.
///
/// A derived untagged `Deserialize` tries each variant and, on failure, reports
/// only `data did not match any variant of untagged enum IngressDecl` — so a
/// misspelled `provider = "passwya"` says nothing about providers, nothing about
/// the legal values, and points at the `[[ingress]]` header rather than the
/// field. Dispatching on the input shape first means each arm's own error
/// survives: a bad string names the legal provider vocabulary, a bad edge table
/// names the offending field.
impl<'de> Deserialize<'de> for IngressDecl {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct DeclVisitor;

        impl<'de> serde::de::Visitor<'de> for DeclVisitor {
            type Value = IngressDecl;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(
                    "a provider name (`ingress = \"passway\"`) or a list of edge tables \
                     (`[[ingress]]`)",
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                IngressProvider::deserialize(serde::de::value::StrDeserializer::new(v))
                    .map(IngressDecl::Provider)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                Vec::<IngressEdge>::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
                    .map(IngressDecl::Edges)
            }
        }

        d.deserialize_any(DeclVisitor)
    }
}

/// No front door — the shape of every mirror that publishes to R2 behind a
/// Worker, or runs a mesh-only compute tier.
impl Default for IngressDecl {
    fn default() -> Self {
        Self::Provider(IngressProvider::None)
    }
}

impl IngressDecl {
    /// `true` when this mirror declares no front door at all.
    pub fn is_absent(&self) -> bool {
        match self {
            Self::Provider(p) => !p.is_declared(),
            Self::Edges(e) => e.is_empty(),
        }
    }
}

impl From<IngressProvider> for IngressDecl {
    fn from(p: IngressProvider) -> Self {
        Self::Provider(p)
    }
}

/// A service mirror — the projection of a [`ServiceConfig`] onto concrete
/// infra. Lives at `.yah/services/<svc>/mirrors/<env>.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MirrorConfig {
    pub schema_version: u32,
    pub shape: MirrorShape,
    /// Public-ingress edges fronting this mirror (W267, W305 F2). Defaults to
    /// none.
    ///
    /// Two spellings, one meaning — see [`IngressDecl`]. `ingress = "passway"`
    /// is one edge fronting everything; `[[ingress]]` entries declare several,
    /// each naming its provider plus the slots or hostnames it fronts. Read it
    /// through [`ingress_edges`](Self::ingress_edges), never by matching on the
    /// enum, so the two spellings cannot drift apart.
    ///
    /// Declared at mirror scope rather than per provider slot because a front
    /// door does **fan-in**: one `cloudflared` (or one passway) on a node
    /// multiplexes every hostname→port rule it fronts, so pinning one to a
    /// single slot would mint one edge connection per slot for no gain. An
    /// edge's `slots` selector is the general form of that — it groups slots
    /// behind one front door, it does not split a front door per slot.
    #[serde(default, skip_serializing_if = "IngressDecl::is_absent")]
    pub ingress: IngressDecl,
    /// Machines the front door is placed on — **independent of where the
    /// fronted workload runs** (R330-F37).
    ///
    /// The single-edge spelling of [`IngressEdge::machines`]: it applies to the
    /// one edge `ingress = "<provider>"` declares, and combining it with
    /// `[[ingress]]` entries is an error rather than a silent precedence rule.
    ///
    /// Empty (the default) keeps the pre-existing behaviour: the front door is
    /// co-located with the fronted slot's own `machine` / `machines`. That was
    /// never a design choice, it was an artifact of bundles binding
    /// `127.0.0.1` — nothing off-node could reach a workload, so a proxy had to
    /// sit on top of it. R599-F12 landed mesh binding, which removes the
    /// constraint: passway is a reverse proxy, and a valid front door needs a
    /// cert and an upstream it can *reach*, not a local copy of the service.
    ///
    /// Listing several machines is what lets the ingress tier and the service
    /// tier scale independently — **N front doors over ONE deployment**. There
    /// is still exactly one rendered copy of the site, so fanning the front door
    /// out introduces no cache-coherence problem; that only appears if you
    /// deploy the *workload* to every node instead.
    ///
    /// ```toml
    /// ingress = "passway"
    /// ingress_machines = ["us-east-001", "us-west-001"]
    /// ```
    ///
    /// Declaring this without [`ingress`](Self::ingress) is an error, not a
    /// no-op — it always means the operator expected a front door somewhere.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress_machines: Vec<String>,
    /// Provider slots, keyed by role (`"static"`, `"compute"`, …). Each value
    /// either references a provider declared under `.yah/infra/providers/` or
    /// inlines a local-only provider (no creds, no infra file).
    ///
    /// A role is normally service-wide — one slot serves every component that
    /// shares it — but [`ReconcileCtx::slot`](crate::reconciler::ReconcileCtx::slot)
    /// looks up the component-qualified key `"<role>:<component id>"` first.
    /// A service with two components of the same role (e.g. two
    /// `mesofact-static` components under one mirror) declares
    /// `providers."static:<id>"` per component to give each its own port;
    /// omitting the qualifier keeps the pre-existing single-slot behavior.
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

impl MirrorConfig {
    /// This mirror's declared edges, with both spellings normalized (W305 F2).
    ///
    /// The single place `ingress` + `ingress_machines` are reconciled, so no
    /// consumer has to know which spelling was written. Returns an empty vec
    /// when the mirror declares no front door.
    ///
    /// Errors are the declarations that cannot mean anything:
    ///
    /// - `ingress_machines` with no `ingress` — front-door placement with no
    ///   front door to place, always a typo (R330-F37);
    /// - `ingress_machines` alongside `[[ingress]]` — placement declared twice,
    ///   in a form where one silently wins;
    /// - `provider = "none"` on an edge — an edge that fronts with nothing.
    pub fn ingress_edges(&self) -> Result<Vec<IngressEdge>> {
        match &self.ingress {
            IngressDecl::Provider(p) if !p.is_declared() => {
                if !self.ingress_machines.is_empty() {
                    bail!(
                        "mirror declares `ingress_machines = {:?}` but no `ingress` provider — \
                         front-door placement with no front door to place. Add \
                         `ingress = \"passway\"` (or \"cloudflare-tunnel\"), or drop \
                         `ingress_machines`.",
                        self.ingress_machines
                    );
                }
                Ok(Vec::new())
            }
            IngressDecl::Provider(p) => Ok(vec![IngressEdge::all_slots(
                *p,
                self.ingress_machines.clone(),
            )]),
            IngressDecl::Edges(edges) => {
                if !self.ingress_machines.is_empty() {
                    bail!(
                        "mirror declares both `[[ingress]]` edges and the single-edge \
                         `ingress_machines = {:?}` — front-door placement stated twice. Move \
                         those names onto the edge they place: `machines = [...]` inside the \
                         `[[ingress]]` entry.",
                        self.ingress_machines
                    );
                }
                for edge in edges {
                    if !edge.provider.is_declared() {
                        bail!(
                            "{}: `provider = \"none\"` fronts nothing. An edge exists to name a \
                             front door — delete the entry instead.",
                            edge.label()
                        );
                    }
                }
                Ok(edges.clone())
            }
        }
    }

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
///   `None` = no repulsion check. Absolute — see [`Self::repel_archetype`].
/// - `requires_taint` — *taint affinity* (R572-F5): the machine must carry
///   this taint key (in `taints` or `mesh_tags`). `None` = no affinity.
///
/// These two are the **only** readers of [`MachineConfig::taints`], which is
/// what makes [`taint_effect`]'s closed vocabulary well-founded.
///
/// [`MachineConfig::sovereign_group`] is deliberately **not** an axis here and
/// must not become one (W305/R742-F1). A sovereign group is a blast radius,
/// not a filter: which quorum a box votes in says nothing about whether a
/// workload may run on it, and a dev-group node exists precisely so dev-mode
/// services — stateful ones included — can be scheduled onto it. Filtering on
/// it would re-make the mistake W305 exists to undo, where one mechanism
/// silently carried three unrelated properties.
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

    /// R833-F8: **imperative** placement — the machine must be one of these by
    /// `name`. Empty (the default) = no constraint, which is every pre-R833-F8
    /// caller.
    ///
    /// This is the one axis that is not a *capability* the scheduler infers.
    /// The operator typed `--where=node:us-west-003`, so it composes with the
    /// other axes exactly like the rest — a named node that fails the capacity
    /// floor or carries a repelling taint still does not match, and the refusal
    /// names why rather than silently placing the work somewhere else.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,

    /// R572-F5: minimum memory (MiB) the target node must have in its
    /// declared `allocatable` budget. `0` = no constraint. Filled by
    /// [`CloudConfig::admit_workload`] from the workload's
    /// `memory_request_mb()` — its placement **request**, which is not the
    /// same number as the `resources.memory_mb` cgroup **ceiling**.
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
    ///
    /// **This is an absolute block, not a preference.**
    /// [`CloudConfig::admit_workload`] sets it unconditionally from the
    /// workload's effective archetype, and nothing in the tree tolerates a
    /// taint — so a workload cannot opt out of a `no-<archetype>` node
    /// (W305 finding 2 / R742-T4). Adding toleration means giving
    /// `WorkloadSpec` a tolerations list and consulting it here; until then,
    /// do not describe this as "repel-unless-tolerate".
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
            && self.nodes.is_empty()
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
    ///   `"no-<archetype.taint_key()>"` for the workload's class. Absolute —
    ///   the workload has no way to tolerate it (W305 finding 2).
    /// - **R572-F5 taint affinity**: if `requires_taint` is set, the machine
    ///   must carry that key in its `taints` list or `mesh_tags`.
    ///
    /// Any *other* taint on the machine is ignored here, which is precisely
    /// why [`crate::validate::check_inert_taints`] refuses to let one be
    /// declared: it would read as a constraint and be none.
    pub fn matches(&self, machine: &MachineConfig) -> bool {
        let member_ok = |constraint: &[String], value: Option<&str>| -> bool {
            constraint.is_empty() || value.map_or(false, |v| constraint.iter().any(|c| c == v))
        };

        // R833-F8: imperative node pin, checked first because it is the axis a
        // human asserted rather than one the scheduler derived — a refusal
        // should read "us-west-003 does not match" and not lead with a tag set
        // the operator never typed.
        if !member_ok(&self.nodes, Some(machine.name.as_str())) {
            return false;
        }

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

        // R572-F5: taint repulsion. A node taint "no-<archetype>" rejects the
        // workload class outright — there is no toleration list to consult.
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
        push("nodes", &self.nodes);
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
    /// Response headers the front door sets on every response served under
    /// this route (R746). Empty by default.
    ///
    /// This is the manifest's answer to "who decides a path's response
    /// headers". Before it existed the answer was *nobody*: a `_headers` file
    /// is a Cloudflare Pages / Netlify convention, and neither of this
    /// repo's front doors reads one — a Worker returns what it fetched from
    /// R2, and R2 serves only the object's own httpMetadata. So a site could
    /// carry a `_headers` file declaring COOP/COEP and ship without them,
    /// which is exactly how it was found: `SharedArrayBuffer` is simply
    /// absent in a document served cross-origin-isolation-free, with no
    /// error anywhere to say why.
    ///
    /// Deliberately a free-form `name -> value` map rather than named fields
    /// for the isolation headers: the domain manifest has no business
    /// knowing which headers a route's payload happens to need. Ordering
    /// follows the route table's own rule — first matching route wins, no
    /// merging across routes (see the Worker's `applyRouteHeaders`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
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

/// Normalize a component `mount` to a storage/URL key prefix: strip the
/// surrounding slashes. `"/app"`, `"app/"`, `"/app/"` → `"app"`; `"/"`, `""`
/// → `""` (the service root).
///
/// One producer on purpose — the publisher's key prefix, the route-path
/// cross-check and the front door's key lookup must all agree on what `/app`
/// means down to the byte, and three copies of `trim_matches('/')` is how they
/// stop agreeing.
pub fn normalize_mount(raw: &str) -> String {
    raw.trim_matches('/').to_string()
}

/// The key prefix a domain route pattern serves under: `"/*"` → `""`,
/// `"/app/*"` and `"/app"` → `"app"`. The twin of [`normalize_mount`] on the
/// routing side.
pub fn route_path_prefix(path: &str) -> String {
    normalize_mount(path.strip_suffix('*').unwrap_or(path))
}

/// The route-driven domain whose route table binds a component of `service`,
/// if any. Used by static publishers to pick up the per-route response
/// headers a service's paths were declared with.
///
/// Deterministic by `BTreeMap` key order when more than one domain routes the
/// same service (a legitimate shape: an apex and a staging host serving one
/// bundle). Returning the first is a real limitation, not a considered
/// choice — the day two such domains want *different* headers for one
/// component, this needs the domain identity threaded in rather than inferred.
pub fn domain_serving_service<'a>(
    domains: &'a BTreeMap<String, DomainConfig>,
    service: &str,
) -> Option<&'a DomainConfig> {
    domains
        .values()
        .find(|d| d.front_door.is_route_driven() && d.serves_service(service))
}

/// The `ROUTE_HEADERS` Worker-binding value for `service`, read from the
/// workspace's domain manifests. `"[]"` when no route-driven domain routes the
/// service, or when the one that does declares no headers.
///
/// Reads `.yah/domains/` directly rather than taking a loaded [`CloudConfig`]:
/// the static reconcilers are handed a per-component [`ReconcileCtx`], not the
/// whole workspace config, and threading a config reference through all 22 of
/// its construction sites to reach one string would be a wide change for a
/// narrow read. Manifest parse errors propagate — a domain file that no longer
/// loads is a deploy-stopping fact, not a reason to ship a Worker with the
/// headers quietly missing.
pub fn route_headers_for_service(workspace_root: &Path, service: &str) -> Result<String> {
    let domains = load_domains(&crate::paths::domains_dir(workspace_root))?;
    Ok(domain_serving_service(&domains, service)
        .map(DomainConfig::route_headers_json)
        .unwrap_or_else(|| "[]".to_string()))
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

    /// The `ROUTE_HEADERS` Worker binding for this domain (R746) — the route
    /// table's `path` + `headers` pairs, in manifest order, with routes that
    /// declare no headers dropped. `"[]"` when nothing declares any.
    ///
    /// Order is load-bearing and must survive serialization: the front door
    /// applies the FIRST matching rule, so `/app/*` above `/*` is what gives
    /// the app its isolation headers and leaves the marketing site alone.
    /// That is why this is a `Vec` of pairs and not a map keyed by path.
    pub fn route_headers_json(&self) -> String {
        #[derive(Serialize)]
        struct Rule<'a> {
            path: &'a str,
            headers: &'a BTreeMap<String, String>,
        }
        let rules: Vec<Rule<'_>> = self
            .routes
            .iter()
            .filter(|r| !r.headers.is_empty())
            .map(|r| Rule {
                path: &r.path,
                headers: &r.headers,
            })
            .collect();
        serde_json::to_string(&rules).unwrap_or_else(|_| "[]".to_string())
    }

    /// Whether this domain's route table binds any component of `service`.
    pub fn serves_service(&self, service: &str) -> bool {
        self.routes.iter().any(|r| {
            r.mode
                .component()
                .and_then(split_component_ref)
                .is_some_and(|(svc, _)| svc == service)
        })
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
    ///
    /// Three forms:
    ///
    /// ```toml
    /// access = "allow_any"                              # explicit escape hatch
    ///
    /// [access]                                          # named workloads
    /// workloads = [{ workload = "yah-cloud-admin" }]
    ///
    /// [access]                                          # signed recipes (R555-F5)
    /// recipes = [{ recipe = "rusty-v8-musl", key = "3d40…" }]
    /// ```
    ///
    /// Use the `recipes` form for a credential a **dispatched build** needs (the
    /// R2 write key, the cosign signing key). A remote QED run's workload name
    /// is a fresh `forge-<uuid>` every time, so `workloads` cannot name it and
    /// `allow_any` over-answers — see W235 §Seam (c) secret scoping. `key` is
    /// the hex Ed25519 public key from the recipe's `[admission]` block.
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
            sovereign_group: None,
            sovereign_role: None,
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
            make_machine("us-west-002", vec!["tag:build-worker", "arch:x86"]),
            make_machine("pi5-001", vec!["tag:build-worker", "arch:arm"]),
        ])
    }

    #[test]
    fn admit_workload_routes_amd64_to_x86_worker() {
        let cfg = build_worker_fleet();
        let ws = ws_with_selector(Some("tag:build-worker,arch:x86"));
        let picked = cfg.admit_workload(&ws).unwrap();
        assert_eq!(picked.name, "us-west-002");
    }

    #[test]
    fn admit_workload_routes_arm64_to_pi5_worker() {
        let cfg = build_worker_fleet();
        let ws = ws_with_selector(Some("tag:build-worker,arch:arm"));
        let picked = cfg.admit_workload(&ws).unwrap();
        assert_eq!(picked.name, "pi5-001");
    }

    /// A forge run must be admissible on a build-worker smaller than its own
    /// cgroup ceiling.
    ///
    /// The fleet's arm build-workers are 8 GiB Pi-5s and `for_forge` sets a
    /// 32 GiB ceiling, so while admission read `resources.memory_mb` as the
    /// capacity floor this returned "no candidates" and *every* offloaded qed
    /// step to those nodes failed at dispatch — measured on desktop-release run
    /// b04cef47, where the aarch64-linux row died in 1.6s. The other
    /// build-workers (16 GiB us-west-003, and the arm Pi-5s) were excluded the
    /// same way, leaving one 47 GiB node as the fleet's only legal target for
    /// remote CI.
    #[test]
    fn admit_workload_places_a_forge_run_on_a_worker_smaller_than_its_ceiling() {
        let mut pi = make_machine("pi5-001", vec!["tag:build-worker", "arch:arm"]);
        pi.allocatable = Some(NodeAllocatable {
            memory_mb: 8192,
            cpu_millis: 4000,
        });
        let cfg = make_empty_cfg(vec![pi]);

        let ws = ws_with_selector(Some("tag:build-worker,arch:arm"));
        assert!(
            ws.resources.memory_mb > 8192,
            "precondition: the ceiling must exceed the node, or this proves nothing"
        );

        let picked = cfg
            .admit_workload(&ws)
            .expect("an 8 GiB build-worker must admit a forge run");
        assert_eq!(picked.name, "pi5-001");
    }

    /// The floor is still enforced — the fix separates two numbers, it does not
    /// disable the R572-F5 capacity check.
    #[test]
    fn admit_workload_still_rejects_a_node_below_the_declared_request() {
        let mut tiny = make_machine("tiny-001", vec!["tag:build-worker", "arch:arm"]);
        tiny.allocatable = Some(NodeAllocatable {
            memory_mb: 512,
            cpu_millis: 4000,
        });
        let cfg = make_empty_cfg(vec![tiny]);

        let ws = ws_with_selector(Some("tag:build-worker,arch:arm"));
        assert!(
            cfg.admit_workload(&ws).is_err(),
            "a 512 MiB node cannot satisfy a 2 GiB forge request"
        );
    }

    // ─── R833-F8 imperative node-selector admission ─────────────────────────

    /// Build a forge WorkloadSpec carrying the R833-F8 imperative node
    /// selector — the operator's `--where=node:<machine>`.
    fn ws_pinned_to(node: &str) -> WorkloadSpec {
        let mut ws = ws_with_selector(None);
        ws.annotations.insert(
            velveteen_exec::remote::NODE_SELECTOR_NODE_ANNOTATION.into(),
            node.into(),
        );
        ws
    }

    /// The ticket's acceptance shape: a named node wins over the
    /// declaration-order tie-break that would otherwise decide placement.
    /// `us-west-002` is declared first and carries every tag, so an inferred
    /// placement lands there; the pin must reach `pi5-001` regardless.
    #[test]
    fn admit_workload_honours_an_explicitly_named_node() {
        let cfg = build_worker_fleet();
        assert_eq!(
            cfg.admit_workload(&ws_with_selector(Some("tag:build-worker")))
                .unwrap()
                .name,
            "us-west-002",
            "precondition: inference elects the first-declared node",
        );
        assert_eq!(
            cfg.admit_workload(&ws_pinned_to("pi5-001")).unwrap().name,
            "pi5-001",
        );
    }

    /// A pin at a machine that is not declared fails loud, naming the
    /// constraint and the pool — the operator mistyped a node, and silently
    /// running the build somewhere else is the one outcome that must not
    /// happen.
    #[test]
    fn admit_workload_refuses_a_node_that_is_not_declared() {
        let cfg = build_worker_fleet();
        let err = cfg
            .admit_workload(&ws_pinned_to("us-west-404"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("required.nodes=[us-west-404]"), "{err}");
        assert!(err.contains("us-west-002"), "the pool must be named: {err}");
    }

    /// The pin narrows the candidate set; it does not suspend the other axes.
    /// A named node that cannot fit the workload still refuses, rather than
    /// being handed work it has no room for.
    #[test]
    fn a_pinned_node_is_still_checked_against_capacity() {
        let mut tiny = make_machine("tiny-001", vec!["tag:build-worker", "arch:arm"]);
        tiny.allocatable = Some(NodeAllocatable {
            memory_mb: 512,
            cpu_millis: 4000,
        });
        let cfg = make_empty_cfg(vec![tiny]);
        assert!(cfg.admit_workload(&ws_pinned_to("tiny-001")).is_err());
    }

    /// Inference is untouched: with no node annotation the `nodes` axis is
    /// empty, which is "no constraint" — every pre-R833-F8 workload is admitted
    /// exactly as before.
    #[test]
    fn an_unpinned_workload_carries_no_node_constraint() {
        assert!(node_selector_node(&ws_with_selector(Some("arch:x86"))).is_none());
        assert_eq!(
            node_selector_node(&ws_pinned_to("us-west-003")).as_deref(),
            Some("us-west-003")
        );
        assert!(RequiredSpec::default().is_unconstrained());
        assert!(!RequiredSpec {
            nodes: vec!["us-west-003".into()],
            ..Default::default()
        }
        .is_unconstrained());
    }

    #[test]
    fn admit_workload_rejects_node_missing_required_tag() {
        // Only an arm worker exists; an x86 build must NOT land on it.
        let cfg = make_empty_cfg(vec![make_machine(
            "pi5-001",
            vec!["tag:build-worker", "arch:arm"],
        )]);
        let ws = ws_with_selector(Some("tag:build-worker,arch:x86"));
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
    /// us-west-002 and us-west-003 on `[tag:build-worker, arch:x86, os:linux]`,
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
mesh_tags = ["tag:build-worker", "arch:x86"]
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

        let ws = ws_with_selector(Some("tag:build-worker,arch:x86"));
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
        let ws = ws_with_selector(Some(" tag:build-worker , arch:x86 ,"));
        assert_eq!(
            node_selector_mesh_tags(&ws),
            vec!["tag:build-worker".to_string(), "arch:x86".to_string()]
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
            sovereign_group: None,
            sovereign_role: None,
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
            sovereign_group: None,
            sovereign_role: None,
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
            sovereign_group: None,
            sovereign_role: None,
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

    /// R605-T10 inverts R707-T6 for the private-literal case, and this is the
    /// node it was inverted for: us-west-014's shape, mesh-joined AND declaring
    /// a LAN `[connect].yubaba`. R707-T6 made the literal win outright so
    /// `rollout::yubaba::membership_to_nodes` could match the dev group's
    /// LAN-addressed raft membership — which fused identity into reach and made
    /// every automated dial go to an address only bldg-2506 can route.
    /// `lan_endpoint()` now serves that match, so the mesh address wins the
    /// dial and the literal is inert.
    #[test]
    fn a_private_literal_loses_to_the_registered_mesh_address() {
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
            Some("http://100.64.0.6:7443"),
            "automation dials the mesh, never the LAN literal"
        );
        assert_eq!(
            cfg.lan_endpoint().as_deref(),
            Some("192.168.10.14:7443"),
            "the LAN address is still recorded — as identity, not as reach"
        );
    }

    /// The refusal R605-T10 asks for: a node whose ONLY declared reach is a LAN
    /// literal is unresolvable, and says so by name rather than returning a URL
    /// that will time out. us-west-011's shape before this ticket.
    #[test]
    fn a_lan_only_node_refuses_with_a_named_reason() {
        let src = r#"
name = "us-west-011"
provider = "static"
mesh_tags = []

[connect]
address = "192.168.10.11"
ssh = "yah@192.168.10.11"
yubaba = "http://192.168.10.11:7443"
"#;
        let cfg: MachineConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.yubaba_url(), None);
        let err = cfg.reach().unwrap_err();
        assert!(err.contains("us-west-011"), "{err}");
        assert!(err.contains("192.168.10.11"), "{err}");
        assert!(err.contains("mesh_ipv4"), "{err}");
    }

    /// The loopback placeholder is a genuine declaration ("reach me through the
    /// SSH tunnel"), not a LAN literal — 127/8 is not RFC1918. It must keep
    /// resolving verbatim; `hub::coordinator::is_loopback_url` is what judges it
    /// downstream.
    #[test]
    fn a_loopback_placeholder_still_resolves_verbatim() {
        let src = r#"
name = "m"
provider = "static"
mesh_tags = []

[connect]
address = "192.168.10.99"
ssh = "yah@192.168.10.99"
yubaba = "http://127.0.0.1:7443"
"#;
        let cfg: MachineConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.yubaba_url().as_deref(), Some("http://127.0.0.1:7443"));
    }

    #[test]
    fn private_ranges_are_exactly_rfc1918() {
        for lan in [
            "http://192.168.10.11:7443",
            "http://10.0.0.5:7443",
            "http://172.16.4.1:7443",
        ] {
            assert!(private_ipv4_from_url(lan).is_some(), "{lan}");
        }
        for not_lan in [
            "http://100.64.0.6:7443",  // mesh
            "http://127.0.0.1:7443",   // loopback
            "http://172.32.0.1:7443",  // just past 172.16/12
            "http://45.32.194.254:80", // public
            "http://us-west-001:7443", // name, not a literal
        ] {
            assert!(private_ipv4_from_url(not_lan).is_none(), "{not_lan}");
        }
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
        // `routes` above [build] — it is a top-level field, and TOML would
        // scope it into that table if written below the header (R658-B1).
        let src = r#"
schema_version = 1
kind = "mesofact-static"

routes = "./routes.ts"

[build]
command = "bun run build"
out_dir = "dist"
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
                mount: None,
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
            ingress_machines: Vec::new(),
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
            ingress_machines: Vec::new(),
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
                ingress_machines: Vec::new(),
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
                mount: None,
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
                    headers: Default::default(),
                    path: "/".into(),
                    mode: RouteMode::Static {
                        component: "yah-marketing/site".into(),
                    },
                },
                DomainRoute {
                    headers: Default::default(),
                    path: "/dashboard/api/*".into(),
                    mode: RouteMode::Backend {
                        component: "yah-dashboard/api".into(),
                        origin: "https://api.dashboard.yah.dev".into(),
                    },
                },
                DomainRoute {
                    headers: Default::default(),
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
                headers: Default::default(),
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

    // ── R746: per-route response headers + component mounts ──────────────────

    /// A two-component service: `site` at the root, `app` mounted at `/app`
    /// with isolation headers on its route. This is the noisetable.com shape
    /// the primitive was built for.
    fn write_two_component_service(root: &Path) {
        let svc = ServiceConfig {
            schema_version: 1,
            name: "yah-marketing".into(),
            domain: "yah.dev".into(),
            db: DbCatalog::default(),
            components: vec![
                ServiceComponent {
                    mount: None,
                    id: "site".into(),
                    kind: "mesofact-static".into(),
                    path: "app/yah/web".into(),
                    role: "static".into(),
                    publishes: None,
                    wave: 0,
                    git: None,
                },
                ServiceComponent {
                    mount: Some("/app".into()),
                    id: "app".into(),
                    kind: "mesofact-static".into(),
                    path: "app/browser".into(),
                    role: "static".into(),
                    publishes: None,
                    wave: 0,
                    git: None,
                },
            ],
        };
        svc.save(root).unwrap();
    }

    const MOUNTED_DOMAIN: &str = r#"
schema_version = 1
name = "yah-dev"
domain = "yah.dev"
front_door = "worker"
cdn_bucket = "yah-dev"

[[routes]]
path = "/app/*"
mode = "static"
component = "yah-marketing/app"
headers = { "Cross-Origin-Opener-Policy" = "same-origin", "Cross-Origin-Embedder-Policy" = "require-corp" }

[[routes]]
path = "/*"
mode = "static"
component = "yah-marketing/site"
"#;

    #[test]
    fn a_mounted_component_routed_at_its_mount_loads() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_two_component_service(root);
        write_domain_toml(root, "yah-dev", MOUNTED_DOMAIN);
        let cfg = CloudConfig::load(root).unwrap();
        let dom = cfg.domain("yah-dev").unwrap();
        assert_eq!(dom.routes.len(), 2);
        assert_eq!(
            dom.routes[0].headers.get("Cross-Origin-Opener-Policy").map(String::as_str),
            Some("same-origin")
        );
        assert!(dom.routes[1].headers.is_empty());
    }

    /// The header table reaches the Worker in MANIFEST order with headerless
    /// routes dropped. Order is the whole contract — the front door applies the
    /// first match, so `/app/*` before `/*` is what isolates the app without
    /// isolating the marketing site.
    #[test]
    fn route_headers_json_preserves_order_and_drops_headerless_routes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_two_component_service(root);
        write_domain_toml(root, "yah-dev", MOUNTED_DOMAIN);
        let cfg = CloudConfig::load(root).unwrap();
        let json = cfg.domain("yah-dev").unwrap().route_headers_json();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let rules = parsed.as_array().unwrap();
        assert_eq!(rules.len(), 1, "the headerless catch-all is dropped: {json}");
        assert_eq!(rules[0]["path"], "/app/*");
        assert_eq!(rules[0]["headers"]["Cross-Origin-Embedder-Policy"], "require-corp");
    }

    #[test]
    fn route_headers_json_is_an_empty_array_when_nothing_declares_headers() {
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
front_door = "worker"
cdn_bucket = "yah-dev"

[[routes]]
path = "/*"
mode = "static"
component = "yah-marketing/site"
"#,
        );
        let cfg = CloudConfig::load(root).unwrap();
        assert_eq!(cfg.domain("yah-dev").unwrap().route_headers_json(), "[]");
    }

    /// The reconciler's own entry point: given a workspace root and a service
    /// name, produce the binding value. `"[]"` when nothing routes the service.
    #[test]
    fn route_headers_for_service_reads_the_workspace_domains() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_two_component_service(root);
        write_domain_toml(root, "yah-dev", MOUNTED_DOMAIN);
        assert!(route_headers_for_service(root, "yah-marketing")
            .unwrap()
            .contains("require-corp"));
        assert_eq!(route_headers_for_service(root, "some-other-svc").unwrap(), "[]");
    }

    /// A `bucket-direct` domain has no front door to set headers on, so it must
    /// not be picked up as a service's header source.
    #[test]
    fn route_headers_ignores_domains_that_are_not_route_driven() {
        let doms: BTreeMap<String, DomainConfig> = [(
            "cdn".to_string(),
            DomainConfig {
                schema_version: 1,
                name: "cdn".into(),
                domain: "cdn.yah.dev".into(),
                front_door: FrontDoor::BucketDirect,
                cdn_bucket: "yah-dev".into(),
                worker_bundle_path: None,
                routes: vec![],
            },
        )]
        .into_iter()
        .collect();
        assert!(domain_serving_service(&doms, "yah-marketing").is_none());
    }

    #[test]
    fn a_mount_that_disagrees_with_its_route_path_is_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_two_component_service(root);
        write_domain_toml(
            root,
            "yah-dev",
            r#"
schema_version = 1
name = "yah-dev"
domain = "yah.dev"
front_door = "worker"
cdn_bucket = "yah-dev"

[[routes]]
path = "/studio/*"
mode = "static"
component = "yah-marketing/app"
"#,
        );
        let err = format!("{:#}", CloudConfig::load(root).unwrap_err());
        assert!(err.contains("mount = \"/app\""), "{err}");
        assert!(err.contains("/studio/*"), "{err}");
    }

    /// The other direction: routing an unmounted component under a sub-path
    /// points requests at a prefix nothing published to.
    #[test]
    fn routing_an_unmounted_component_under_a_subpath_is_rejected() {
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
front_door = "worker"
cdn_bucket = "yah-dev"

[[routes]]
path = "/docs/*"
mode = "static"
component = "yah-marketing/site"
"#,
        );
        let err = format!("{:#}", CloudConfig::load(root).unwrap_err());
        assert!(err.contains("no `mount`"), "{err}");
        assert!(err.contains("/docs"), "{err}");
    }

    #[test]
    fn mount_and_route_prefix_normalization_agree() {
        for m in ["/app", "app", "app/", "/app/"] {
            assert_eq!(normalize_mount(m), "app", "mount {m:?}");
        }
        assert_eq!(normalize_mount("/"), "");
        assert_eq!(route_path_prefix("/*"), "");
        assert_eq!(route_path_prefix("/app/*"), "app");
        assert_eq!(route_path_prefix("/app"), "app");
        assert_eq!(route_path_prefix("/"), "");
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
                headers: Default::default(),
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
                headers: Default::default(),
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
                headers: Default::default(),
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
                headers: Default::default(),
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
                headers: Default::default(),
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
                headers: Default::default(),
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
name = "quarantined"
provider = "static"
mesh_tags = ["tag:build-worker"]
taints = ["no-server", "no-appliance", "no-job"]
"#;
        let m: MachineConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(m.taints.len(), 3);
        assert!(m.taints.contains(&"no-server".to_string()));
        assert!(m.taints.contains(&"no-appliance".to_string()));
        assert!(m.taints.contains(&"no-job".to_string()));
        // R742-T4: every key here is one the scheduler reads. This fixture
        // used to carry `no-voter`, which none of them is.
        assert!(m.inert_taints().is_empty());
    }

    // ─── R742-T4 (W305): inert-taint classification ─────────────────────────

    #[test]
    fn every_archetype_repel_key_is_live() {
        for arch in LifecycleArchetype::ALL {
            let key = format!("no-{}", arch.taint_key());
            assert_eq!(
                taint_effect(&key),
                TaintEffect::Repels(arch),
                "{key} must repel {arch:?}"
            );
        }
    }

    #[test]
    fn public_ip_is_an_affinity_key_not_an_inert_one() {
        assert_eq!(
            taint_effect(workload_spec::PUBLIC_IP_TAINT),
            TaintEffect::Attracts
        );
    }

    #[test]
    fn a_free_form_taint_is_inert_and_says_so() {
        // W305's headline example: `taints = ["qa"]` parsed clean and did
        // nothing. Environment is not expressible as a taint.
        assert_eq!(taint_effect("qa"), TaintEffect::Inert);
        // And the one that actually cost fleet state: `no-voter` reads as an
        // exclusion and excludes nothing — "voter" is not an archetype.
        assert_eq!(taint_effect("no-voter"), TaintEffect::Inert);
        // A near-miss on a real key is inert too, not silently forgiven.
        assert_eq!(taint_effect("no-servers"), TaintEffect::Inert);

        let m = make_machine_with_capacity(
            "dev-pi",
            8192,
            4000,
            vec!["no-appliance", "no-voter", "qa"],
        );
        assert_eq!(m.inert_taints(), vec!["no-voter", "qa"]);
    }

    #[test]
    fn an_inert_taint_changes_no_placement_decision() {
        // The reason this is a lint and not a behaviour change: the guard's
        // whole premise is that these keys are invisible to `matches`.
        let clean = make_machine_with_capacity("n", 8192, 4000, vec![]);
        let noisy = make_machine_with_capacity("n", 8192, 4000, vec!["no-voter", "qa"]);
        for arch in LifecycleArchetype::ALL {
            let req = RequiredSpec {
                repel_archetype: Some(arch),
                ..Default::default()
            };
            assert_eq!(req.matches(&clean), req.matches(&noisy));
        }
    }

    #[test]
    fn live_taint_keys_lists_the_whole_legal_vocabulary() {
        assert_eq!(
            live_taint_keys(),
            vec!["no-appliance", "no-job", "no-server", "public-ip"]
        );
    }

    // ─── R742-F1 (W305): sovereign groups ───────────────────────────────────

    /// A machine in `group`, with the role left unwritten — which is the state
    /// of every machine TOML that predates R605-F12 and resolves to `voter`.
    fn in_group(name: &str, group: Option<&str>) -> MachineConfig {
        MachineConfig {
            sovereign_group: group.map(String::from),
            ..make_machine(name, vec![])
        }
    }

    /// A machine in `group` with its quorum eligibility stated (R605-F12).
    fn in_group_as(name: &str, group: &str, role: SovereignRole) -> MachineConfig {
        MachineConfig {
            sovereign_group: Some(group.to_string()),
            sovereign_role: Some(role),
            ..make_machine(name, vec![])
        }
    }

    #[test]
    fn a_join_within_one_sovereign_group_is_permitted() {
        assert_eq!(
            judge_join(
                &in_group("us-west-013", Some("dev")),
                &in_group("us-west-011", Some("dev")),
            ),
            JoinVerdict::Permit
        );
    }

    /// The case the field exists for: before it, the only thing standing
    /// between a dev Pi and the prod quorum was a comment in a TOML.
    #[test]
    fn a_cross_group_join_is_refused_naming_both_groups() {
        let verdict = judge_join(
            &in_group("us-west-011", Some("dev")),
            &in_group("us-west-001", Some("prod")),
        );
        let JoinVerdict::Refuse(msg) = verdict else {
            panic!("a dev node joining prod must be refused: {verdict:?}");
        };
        // A refusal that does not name what it saw is one the operator has to
        // go and reconstruct, so it gets worked around instead of fixed.
        assert!(msg.contains("us-west-011") && msg.contains("us-west-001"), "{msg}");
        assert!(msg.contains("dev") && msg.contains("prod"), "{msg}");
    }

    /// `None` is a declaration ("standalone, in no group"), not a gap — so
    /// growing prod with an unstamped box is a cross-group join too, and the
    /// refusal has to say which file makes it legal.
    #[test]
    fn an_undeclared_node_cannot_join_a_declared_group() {
        let verdict = judge_join(
            &in_group("us-west-002", None),
            &in_group("us-west-001", Some("prod")),
        );
        let JoinVerdict::Refuse(msg) = verdict else {
            panic!("an unstamped node joining prod must be refused: {verdict:?}");
        };
        assert!(
            msg.contains(".yah/infra/machines/us-west-002.toml"),
            "the refusal must name the file to stamp: {msg}"
        );
    }

    #[test]
    fn a_declared_node_cannot_join_a_standalone_target() {
        // us-west-003 is `mode: standalone` on purpose; it is not a group of
        // one waiting to be grown.
        let verdict = judge_join(
            &in_group("us-west-001", Some("prod")),
            &in_group("us-west-003", None),
        );
        assert!(matches!(verdict, JoinVerdict::Refuse(msg) if msg.contains("us-west-003")));
    }

    #[test]
    fn two_undeclared_nodes_cannot_form_an_undeclared_group() {
        let verdict = judge_join(
            &in_group("us-west-002", None),
            &in_group("us-west-015", None),
        );
        assert!(
            matches!(&verdict, JoinVerdict::Refuse(msg) if msg.contains("us-west-002")
                && msg.contains("us-west-015")),
            "forming a group nobody declared must be refused, naming both: {verdict:?}"
        );
    }

    // ─── R605-F12: the voting axis ──────────────────────────────────────────

    /// The whole ticket in one assertion. us-west-003 is a member of prod —
    /// same secrets, same upgrade cadence, same destruction — and must never
    /// hold a prod raft seat. Before the role axis, the only thing refusing it
    /// was its *absent* group stamp, so writing down the truth above would have
    /// removed the guard.
    #[test]
    fn a_non_voting_member_is_refused_into_its_own_group() {
        let verdict = judge_join(
            &in_group_as("us-west-003", "prod", SovereignRole::NonVoter),
            &in_group_as("us-west-001", "prod", SovereignRole::Voter),
        );
        let JoinVerdict::Refuse(msg) = verdict else {
            panic!("a non-voting prod member must not join the prod quorum: {verdict:?}");
        };
        assert!(msg.contains("us-west-003") && msg.contains("NON-VOTING"), "{msg}");
        // The refusal must not blame the group: both sides say "prod", and a
        // cross-group message here would read as a bug in the check itself.
        assert!(!msg.contains("cross-group"), "{msg}");
        assert!(
            msg.contains(".yah/infra/machines/us-west-003.toml"),
            "the refusal must name the file that decides it: {msg}"
        );
    }

    /// Read from the other end: a box declared non-voting has no quorum seat to
    /// be grown, so it cannot be a join target either.
    #[test]
    fn a_non_voting_target_has_no_quorum_to_grow() {
        let verdict = judge_join(
            &in_group_as("us-west-001", "prod", SovereignRole::Voter),
            &in_group_as("us-west-003", "prod", SovereignRole::NonVoter),
        );
        assert!(
            matches!(&verdict, JoinVerdict::Refuse(msg) if msg.contains("the target")
                && msg.contains("us-west-003")),
            "{verdict:?}"
        );
    }

    /// A non-voter joining a *standalone* target is refused for two reasons at
    /// once, and the message must pick the one whose fix would actually work.
    /// Naming the role here would send the operator to flip `sovereign_role`
    /// and come back to the same refusal.
    #[test]
    fn a_refusal_names_the_group_when_fixing_the_role_would_not_help() {
        let verdict = judge_join(
            &in_group_as("us-west-003", "prod", SovereignRole::NonVoter),
            &in_group("us-west-002", None),
        );
        let JoinVerdict::Refuse(msg) = verdict else {
            panic!("a standalone target has no group to join: {verdict:?}");
        };
        assert!(
            msg.contains(".yah/infra/machines/us-west-002.toml"),
            "the refusal must point at the target's missing group stamp: {msg}"
        );
        assert!(!msg.contains("NON-VOTING"), "{msg}");
    }

    /// The back-compat seam, pinned: the six nodes stamped before R605-F12
    /// write no role, and an absent role means what declaring a group has
    /// always meant. If this flips, the live prod and dev quorums stop being
    /// growable on a config the operator never edited.
    #[test]
    fn an_unwritten_role_still_joins_its_group() {
        let joiner = in_group("us-west-013", Some("dev"));
        assert_eq!(joiner.sovereign_role, None);
        assert_eq!(
            judge_join(&joiner, &in_group("us-west-011", Some("dev"))),
            JoinVerdict::Permit
        );
        assert_eq!(
            judge_join(
                &joiner,
                &in_group_as("us-west-011", "dev", SovereignRole::Voter)
            ),
            JoinVerdict::Permit
        );
    }

    /// A non-voting member is still a *member*, and the two claims must not be
    /// conflated: `sovereign_membership()` reports the group either way, so a
    /// consumer asking "is this box in prod's blast radius" gets yes.
    #[test]
    fn a_non_voter_is_still_in_the_group_it_names() {
        let m = in_group_as("us-west-003", "prod", SovereignRole::NonVoter);
        assert_eq!(m.sovereign_membership().group, Some("prod"));
        assert!(!m.sovereign_membership().role.is_voter());

        // …and the group-membership query the fleet reads is unaffected by it.
        let cfg = make_empty_cfg(vec![
            m,
            in_group_as("us-west-001", "prod", SovereignRole::Voter),
        ]);
        assert_eq!(
            cfg.machines_in_group("prod")
                .iter()
                .map(|m| m.name.as_str())
                .collect::<Vec<_>>(),
            vec!["us-west-003", "us-west-001"]
        );
    }

    /// The role travels through TOML in one spelling, and an absent one stays
    /// absent on the way back out — otherwise every machine file would grow a
    /// `sovereign_role = "voter"` line the operator never wrote, and the
    /// unroled-member lint would have nothing left to find.
    #[test]
    fn sovereign_role_round_trips_and_is_omitted_when_unwritten() {
        let m: MachineConfig = toml::from_str(
            r#"
name = "us-west-003"
provider = "static"
region = "us-west"
arch = "x86_64"
mesh_tags = []
sovereign_group = "prod"
sovereign_role = "non-voter"
"#,
        )
        .unwrap();
        assert_eq!(m.sovereign_role, Some(SovereignRole::NonVoter));
        assert!(toml::to_string(&m)
            .unwrap()
            .contains(r#"sovereign_role = "non-voter""#));

        let unwritten = MachineConfig {
            sovereign_role: None,
            ..m
        };
        assert!(!toml::to_string(&unwritten)
            .unwrap()
            .contains("sovereign_role"));
    }

    /// The invariant the ticket is most explicit about: a sovereign group is a
    /// blast radius, not a filter. If this ever fails, `matches` has grown an
    /// axis it must not have and dev-mode workloads have silently become
    /// unschedulable on the dev group.
    #[test]
    fn sovereign_group_is_not_a_placement_input() {
        let standalone = in_group("n", None);
        let grouped = in_group("n", Some("dev"));
        let other = in_group("n", Some("prod"));

        for spec in [
            RequiredSpec::default(),
            RequiredSpec {
                regions: vec!["us-west".into()],
                ..Default::default()
            },
            RequiredSpec {
                repel_archetype: Some(LifecycleArchetype::Appliance),
                ..Default::default()
            },
        ] {
            let baseline = spec.matches(&standalone);
            assert_eq!(spec.matches(&grouped), baseline);
            assert_eq!(spec.matches(&other), baseline);
        }
    }

    // ─── R742-F3 (W305): group → machine set, and group-scoped admission ────

    /// The primitive `migrate --to` needs and `rollout plan` still lacks
    /// (W314 gap 1): a group exists only as the set of machines naming it, so
    /// membership has to be derived rather than declared anywhere.
    #[test]
    fn machines_in_group_derives_membership_from_the_declarations() {
        let cfg = make_empty_cfg(vec![
            in_group("us-west-001", Some("prod")),
            in_group("us-west-011", Some("dev")),
            in_group("us-west-013", Some("dev")),
            in_group("us-west-002", None),
        ]);

        let dev: Vec<&str> = cfg
            .machines_in_group("dev")
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert_eq!(dev, vec!["us-west-011", "us-west-013"]);
        assert_eq!(cfg.machines_in_group("prod").len(), 1);

        // Standalone is "in no group", not "in a group called none" — so an
        // unstamped box is never swept into a migration target.
        assert!(cfg.machines_in_group("").is_empty());
        assert!(cfg.machines_in_group("staging").is_empty());
    }

    #[test]
    fn declared_sovereign_groups_is_the_vocabulary_a_bad_target_is_named_against() {
        let cfg = make_empty_cfg(vec![
            in_group("a", Some("prod")),
            in_group("b", Some("dev")),
            in_group("c", Some("prod")),
            in_group("d", None),
        ]);
        // Sorted + deduped, and standalone contributes nothing.
        assert_eq!(cfg.declared_sovereign_groups(), vec!["dev", "prod"]);
        assert!(make_empty_cfg(vec![in_group("a", None)])
            .declared_sovereign_groups()
            .is_empty());
    }

    /// Group-scoped admission must be the SAME predicate as unscoped
    /// admission, only over fewer candidates. If it ever diverges, `migrate`
    /// becomes a way to place a workload somewhere `yah cloud apply` would
    /// refuse — which is exactly the silent routing-around W305 exists to stop.
    #[test]
    fn admit_workload_in_group_narrows_candidates_without_changing_the_predicate() {
        let mut prod = in_group("us-west-001", Some("prod"));
        prod.mesh_tags = vec!["tag:cloud-runner".into()];
        let mut dev_repels = in_group("us-west-011", Some("dev"));
        dev_repels.taints = vec!["no-appliance".into()];
        let mut dev_ok = in_group("us-west-013", Some("dev"));
        dev_ok.mesh_tags = vec!["tag:cloud-runner".into()];

        let cfg = make_empty_cfg(vec![prod, dev_repels, dev_ok]);

        let mut ws = ws_with_selector(None);
        ws.archetype = Some(LifecycleArchetype::Appliance);

        // Unscoped picks the first match in declaration order.
        assert_eq!(cfg.admit_workload(&ws).unwrap().name, "us-west-001");
        // Scoped skips the repelling dev node and lands on the other one —
        // the taint is honoured, not bypassed.
        assert_eq!(
            cfg.admit_workload_in_group(&ws, "dev").unwrap().name,
            "us-west-013"
        );
    }

    #[test]
    fn admit_workload_in_group_distinguishes_an_empty_group_from_a_repelling_one() {
        let mut dev = in_group("us-west-011", Some("dev"));
        dev.taints = vec!["no-appliance".into()];
        let cfg = make_empty_cfg(vec![in_group("us-west-001", Some("prod")), dev]);

        let mut ws = ws_with_selector(None);
        ws.archetype = Some(LifecycleArchetype::Appliance);

        // A group nobody declares names the legal vocabulary, because a typo
        // is the realistic cause and "no candidates" would send the operator
        // hunting for a placement problem that does not exist.
        let missing = cfg.admit_workload_in_group(&ws, "stagng").unwrap_err().to_string();
        assert!(missing.contains("no machine declares"), "{missing}");
        assert!(missing.contains("dev") && missing.contains("prod"), "{missing}");

        // A group that exists but refuses names the machines it tried.
        let repelled = cfg.admit_workload_in_group(&ws, "dev").unwrap_err().to_string();
        assert!(repelled.contains("us-west-011"), "{repelled}");
    }

    #[test]
    fn sovereign_group_round_trips_and_is_omitted_when_standalone() {
        let src = r#"
name = "us-west-011"
provider = "static"
mesh_tags = []
sovereign_group = "dev"
"#;
        let m: MachineConfig = toml::from_str(src).unwrap();
        assert_eq!(m.sovereign_group.as_deref(), Some("dev"));
        assert!(toml::to_string(&m).unwrap().contains("sovereign_group"));

        // A machine that predates the field parses as standalone and does not
        // grow the key back on write.
        let legacy: MachineConfig =
            toml::from_str("name = \"us-west-002\"\nprovider = \"static\"\nmesh_tags = []\n")
                .unwrap();
        assert_eq!(legacy.sovereign_group, None);
        assert!(!toml::to_string(&legacy).unwrap().contains("sovereign_group"));
    }

    // ─── R572-F5: capacity floor + absolute (untolerable) taints ────────────

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
        // These are SERVER specs that borrow `for_forge` as a constructor
        // shortcut, so drop the forge memory request it stamps on — otherwise
        // every spec here silently requests the forge default instead of the
        // `memory_mb` the caller passed, and the capacity-floor tests below
        // stop testing their own argument. A server workload declares no
        // request, which is the documented fall-back-to-`resources.memory_mb`
        // path (`WorkloadSpec::memory_request_mb`).
        ws.annotations
            .remove(workload_spec::MEMORY_REQUEST_ANNOTATION);
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
        // us-west-002: no-server, no-appliance → appliance rejected
        let cfg = make_empty_cfg(vec![
            make_machine_with_capacity("us-south-001", 512, 1000, vec!["no-appliance"]),
            make_machine_with_capacity(
                "us-west-002",
                16384,
                8000,
                vec!["no-server", "no-appliance"],
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
                vec!["no-server", "no-appliance"],
            ),
        ]);
        let mut ws = server_spec(256, 500);
        ws.archetype = Some(LifecycleArchetype::Job);
        // No fleet node declares `no-job`, so a Job is repelled by nothing;
        // west-001 comes first in declaration order (greedy, no preference),
        // which is the expected tie-break. Note this is *absence of a repel
        // key*, not toleration — no workload can tolerate a taint (W305).
        let picked = cfg.admit_workload(&ws).unwrap();
        // Both are eligible.
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
        // same repel set as the x86 build-worker (`no-server, no-appliance` —
        // see .yah/infra/machines/us-west-015.toml). This pins that intent:
        // with a plain cloud node available beside the Mac, every
        // cloud-critical archetype lands on the cloud node and never the Mac;
        // build Jobs (the Mac's actual purpose) remain eligible on it.
        //
        // R742-T4: `no-voter` used to sit in this set and in the TOML. It was
        // never read here — there is no "voter" workload archetype — and
        // R569-F3's learner-only join is what actually keeps the box out of
        // quorum. It is now rejected by `yah cloud validate` as inert.
        let mac_taints = vec!["no-server", "no-appliance"];
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
