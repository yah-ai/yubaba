//! [`Reconciler`] implementation for `kind = "headscale"` components (R861-T1).
//!
//! Owns the API objects that live *inside* a running headscale coordinator —
//! users, pre-auth keys and the ACL policy — the way
//! [`cloudflare_worker`](super::cloudflare_worker) owns what lives inside a
//! Cloudflare account. It does not deploy headscale; that is the appliance
//! [`WorkloadSpec`] in `yubaba::headscale_appliance`, and it stays there.
//!
//! ## Why this exists
//!
//! Two pieces of headscale's state were previously nobody's declared config:
//!
//! 1. **`acls.yaml`** — 77 bytes on us-west-001's local disk, mtime Jun 22,
//!    replicated by nothing (litestream carries only `headscale.db`). A
//!    failover to another node would come up with different ACLs, look
//!    healthy, and partially work. Declaring the policy here means the new
//!    node is *reconciled* to the declared value rather than needing the file
//!    carried to it.
//! 2. **Pre-auth keys** — `headscale-preauth-key` is classified
//!    `Band::Automatable` in the credential spec and its purpose text already
//!    says `headscale-api-key` mints these per machine. That automation
//!    existed only ad hoc, at provision time, for one machine, with no
//!    declared desired state behind it.
//!
//! ## Policy mode is load-bearing, and the reconciler adapts to it
//!
//! headscale 0.23 sources its ACL policy from either a file or the database,
//! per `policy.mode` in `config.yaml`. That bounds what this reconciler can do
//! about ACLs:
//!
//! - `GET /api/v1/policy` works in **both** modes (verified: 200 with the
//!   file's contents against the live file-mode coordinator), so declared-vs-
//!   live drift is always *detectable*.
//! - `PUT /api/v1/policy` is refused in file mode — the pinned v0.23.0's
//!   `SetPolicy` returns `ErrPolicyUpdateIsDisabled` before it even reads the
//!   payload, because the file is the source of truth and a write would be
//!   overwritten at the next reload.
//!
//! So the ACL step compares first and only writes on drift. The write lands on
//! a database-mode coordinator and the policy ends up in `headscale.db`, which
//! litestream already replicates — the point at which `acls.yaml` stops being
//! unreplicated failover state. On a coordinator still in file mode the drift
//! surfaces as a loud, actionable error naming the exact file and the migration
//! that makes it pushable, instead of a silent no-op that *reads* like success.
//!
//! **R861-T2 flipped that default.** Every in-tree renderer now emits
//! `policy.mode: database` ([`crate::mesh::POLICY_MODE`] and yubaba's
//! `HEADSCALE_POLICY_MODE`), so newly-provisioned coordinators come up with
//! policy in the database and no `acls.yaml` at all. **Boxes provisioned
//! earlier are still on file mode until they are migrated** — us-west-001 was
//! measured on 2026-09-04 running
//!
//! ```yaml
//! policy:
//!   mode: file
//!   path: /var/lib/yah-cloud/headscale/acls.yaml
//! ```
//!
//! and that migration is [`policy_migration`], which is a planner plus a
//! rehearsal, not something this reconciler performs as a side effect: the flip
//! reaches a live node only through a yubaba release + roll and it wants the
//! operator's hand on it.
//!
//! ## Declared config
//!
//! Lives in the component's `workload.toml`, in the kind-specific tables each
//! reconciler parses for itself (`cloudflare-worker` reads `[build]` +
//! `[[bindings]]` the same way — the strong `workload_spec::Workload` types
//! do not model per-kind tables, and the generated JSON schema sets no
//! `additionalProperties: false`, so this needs no schema change and no
//! regen).
//!
//! ```toml
//! schema_version = 1
//! kind = "headscale"
//!
//! [headscale]
//! # Optional. Falls back to the `mesh-url` vault slot / HEADSCALE_URL.
//! server_url = "https://cloud.mesh.yah.dev"
//! # Users that must exist. Created if absent; NEVER deleted — a user carries
//! # the nodes registered under it.
//! users = ["yah"]
//! # HuJSON ACL policy, path relative to the workload dir.
//! acl_policy = "acls.hujson"
//!
//! [[headscale.preauth_keys]]
//! user = "yah"
//! tags = ["tag:cloud-runner"]
//! reusable = true
//! ephemeral = false
//! ttl_hours = 168
//! # Optional vault slot the minted key is written to.
//! store_as = "headscale-preauth-key"
//! ```
//!
//! Every one of those fields is validated **before the first API call** — the
//! R330-B5 fail-fast discipline the reconciler docs already name. A typo in a
//! preauth key's `user` must not be discovered after two users have already
//! been created.
//!
//! @yah:ticket(R861-T2, "Decide headscale policy source: keep mode=file with a reconciled acls.yaml, or flip the fleet to mode=database")
//! @yah:status(review)
//! @yah:at(2026-09-04T23:24:31Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R861)
//! @yah:gotcha("MEASURED, NOT ASSUMED: us-west-001's /var/lib/yah-cloud/headscale/config.yaml carries `policy:` / `mode: file` / `path: /var/lib/yah-cloud/headscale/acls.yaml` (read over SSH 2026-09-04 during R861-T1), and all three in-tree renderers emit the same. So acls.yaml is LIVE. It was NOT deleted, and any plan that assumes it is vestigial is wrong.")
//! @yah:assumes("That headscale 0.23's `policy.mode: database` accepts the same HuJSON policy document via the admin API that `mode: file` reads from disk, so R861-T1's get_policy/set_policy pair works unchanged under either mode. Not verified against a running instance in database mode — verify before flipping anything.")
//! @yah:next("THE CALL (operator): R861-T1 landed a HeadscaleReconciler that owns ACLs as declared config, but left the fleet on `policy.mode: file`. Under mode=file the reconciler WRITES acls.yaml, so the file still exists on disk and litestream still does not replicate it (litestream carries only headscale.db) — the failover-state gap R861 was filed against is only PARTLY closed: acls.yaml is now reconstructible from declared config rather than being unique unreplicated state, but it is still state on a box. Flipping to mode=database puts policy inside headscale.db, which litestream already replicates, and the file stops mattering entirely — which is what R861's framing actually wanted.")
//! @yah:next("WHY THIS IS AN OPERATOR CALL AND NOT A DEFAULT: flipping policy.mode on the live fleet is an outward-facing change to running mesh infrastructure, and a wrong ACL state mid-flip is a connectivity outage, not a failed build. It also needs a migration step (read the current acls.yaml, push it through set_policy BEFORE the mode flip, verify, then remove the file) — a sequencing decision with no defensible default. Option A: keep mode=file, accept that acls.yaml stays on disk but is now reconciled/reconstructible. Option B: migrate to mode=database so litestream covers policy and the file is deleted for good.")
//! @yah:next("OPERATOR DECIDED 2026-09-04: Option B — migrate to `policy.mode: database`. Policy moves into headscale.db (which litestream already replicates) and acls.yaml is deleted for good. This is the answer to the call; the ticket is released. Option A (keep mode=file) is off the table — do not re-litigate it.")
//! @yah:next("SEQUENCE, and it is not optional — a wrong ACL state mid-flip is a mesh connectivity outage, not a failed build. (1) VERIFY THE ASSUMPTION FIRST: confirm the pinned headscale version's `mode: database` accepts the same HuJSON document through the admin API that `mode: file` reads from disk, so R861-T1's get_policy/set_policy pair works unchanged. If it does not, stop and report — everything downstream rests on it. (2) Read the live acls.yaml and push it through set_policy. (3) Verify the policy read back from the API matches byte-for-byte semantically. (4) Only then flip the rendered config to mode=database. (5) Only after a confirmed-good flip, delete acls.yaml. Each step must be idempotent and re-runnable.")
//! @yah:next("SCOPE SPLIT: build and rehearse the migration in code first — the renderer change plus a re-runnable migration path, tested. EXECUTING it against the live fleet (us-west-001, us-west-003, and any other headscale-bearing box) is a separate, gated step: the operator authorized the migration, not an unattended production run. Land the code, prove it dry, then surface the execution moment.")
//! @yah:gotcha("THE POLICY BLOCK IS EMITTED AT FOUR SITES ACROSS TWO FILES, and R861-T1's \"three in-tree renderers\" undercounts. Grepped by @Glimmerstone:polaris 2026-09-04 (line numbers are grep hits, not reads): cloud/src/mesh.rs:554 (acl_path :521); yubaba/src/lib.rs:4760 (acl_path :4729); yubaba/src/lib.rs:5170 (acl_path :5134). THE THIRD SITE IS SPELLED WITH ESCAPED SPACES — `\\x20\\x20mode: file` — so a naive `rg \"  mode: file\"` MISSES IT. That is almost certainly the source of the undercount. Missing it leaves newly-provisioned boxes silently on mode=file while every other signal says the migration completed. Search on `mode:` broadly and on `acls.yaml`, never on a literal two-space prefix. NOTE: headscale_appliance.rs does NOT render a policy block at all — do not go looking there.")
//! @yah:next("IN SCOPE FOR THIS TICKET, not followups — the flip breaks these. Two assertions that will fail: yubaba/src/lib.rs:7865 (`cfg.contains(\"mode: file\")`) and cloud/src/mesh.rs:755 (`config.contains(\"acls.yaml\")`). Two prose/doc sites that go stale, both asserting the live coordinator \"runs policy.mode: file\": cloud/src/reconciler/headscale.rs:281 and cloud/src/mesh.rs:367. All four found by grep, not opened — verify each before editing.")
//! @yah:gotcha("THE SEQUENCE ORIGINALLY FILED ON THIS TICKET IS IMPOSSIBLE — DO NOT FOLLOW IT. It said push the policy via set_policy FIRST and flip the config to mode=database afterward. headscale v0.23.0's SetPolicy returns ErrPolicyUpdateIsDisabled *before it reads the payload* unless mode==database is already in effect, so the push cannot precede the flip. CORRECTED ORDER: flip the rendered config to mode=database and restart headscale FIRST, then push the policy through set_policy, then verify the read-back, then delete acls.yaml. Established from headscale v0.23.0 source during R861-T2, not inferred.")
//! @yah:gotcha("THE CORRECTED ORDER OPENS A REAL WINDOW: between the mode flip and the policy push, headscale has NO policy row. That window is safe FOR THIS FLEET AS IT STANDS TODAY, and only for that reason — the live acls.yaml is the permissive default, and headscale compiles a missing policy row to FilterAllowAll, so the gap state and the current effective state are both allow-all and no connectivity is lost. THIS SAFETY ARGUMENT EXPIRES THE MOMENT acls.yaml STOPS BEING PERMISSIVE. Anyone re-running this migration after real ACL rules are declared must re-derive it: with a restrictive policy live, the same window is a fail-OPEN (allow-all) interval, which is a security exposure rather than an outage. Re-read the live acls.yaml and confirm it is still the permissive default before executing.")
//! @yah:verify("ASSUMPTION DISCHARGED: R861-T2's @yah:assumes — that mode=database accepts the same HuJSON document the file mode reads — is VERIFIED from headscale v0.23.0 source, where both modes funnel through the same LoadACLPolicyFromBytes. R861-T1's get_policy/set_policy therefore work unchanged under either mode. Verified by reading the pinned version's source, not from documentation or recollection.")
//! @yah:handoff("ASSUMPTION VERIFIED — IT HOLDS, and it was settled from the pinned version's own source, not from recollection or from a live probe. Downloaded juanfont/headscale v0.23.0 (the pin: cloud::mesh::HEADSCALE_VERSION and yubaba::DEFAULT_HEADSCALE_VERSION, both \"0.23.0\") and read four call sites. (1) hscontrol/app.go loadACLPolicy: file mode calls policy.LoadACLPolicyFromPath, which is os.Open + io.ReadAll + LoadACLPolicyFromBytes; database mode calls LoadACLPolicyFromBytes on the stored row. Same function, same document. (2) hscontrol/policy/acls.go LoadACLPolicyFromBytes: hujson.Parse -> Standardize -> json.Unmarshal into the same ACLPolicy struct. There is no second format. (3) hscontrol/grpcv1.go SetPolicy: parses the request body with that same LoadACLPolicyFromBytes before storing. (4) hscontrol/grpcv1.go GetPolicy: database mode returns the stored row's Data verbatim, file mode returns the file's bytes as-is. (5) hscontrol/types/config.go: policy.mode is exactly \"file\" or \"database\" (PolicyModeFile/PolicyModeDB), viper defaults it to \"file\" when absent, and policy.path is read only in file mode — config-example.yaml says the same. So R861-T1's get_policy/set_policy pair works unchanged under either mode. Nothing downstream is blocked on this.")
//! @yah:handoff("FINDING 1 — THE TICKET'S SEQUENCE IS IMPOSSIBLE AS WRITTEN, AND THE CODE INVERTS IT. R861-T2 step (2) said \"read the live acls.yaml and push it through set_policy\", step (4) \"only then flip the rendered config to mode=database\". That cannot run: hscontrol/grpcv1.go SetPolicy opens with `if api.h.cfg.Policy.Mode != types.PolicyModeDB { return nil, types.ErrPolicyUpdateIsDisabled }` — it refuses BEFORE reading the payload. A file-mode coordinator cannot be pushed to at all, so the config flip has to come FIRST. Implemented order (policy_migration::next_step): (1) rewrite config.yaml to mode: database and restart headscale; (2) push the carried acls.yaml through set_policy; (3) verify the read-back semantically; (4) only then delete acls.yaml. The ticket's step (5) — delete last — is preserved and is load-bearing, see FINDING 3.")
//! @yah:handoff("FINDING 2 — THE WINDOW THAT INVERSION OPENS IS FAIL-OPEN, AND IT IS SAFE FOR THIS FLEET FOR A SPECIFIC REASON THAT WILL EXPIRE. Between the flip and the push, a database-mode coordinator has no policy row. That is NOT an error: app.go loadACLPolicy maps types.ErrPolicyNotFound to a nil *ACLPolicy and returns nil, and acls.go (*ACLPolicy).CompileFilterRules on a nil receiver returns tailcfg.FilterAllowAll (CompileSSHPolicy returns nil, nil). So the coordinator serves ALLOW-ALL during that window. For us-west-001 today this is a semantic no-op: its live acls.yaml is measured (R861-T1, 2026-09-04) as exactly the permissive default {\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}]}, i.e. allow-all already. THE SAFETY ARGUMENT IS ENTIRELY CONTINGENT ON THAT — the day acls.yaml stops being permissive, the same window becomes a real (brief) widening of the tailnet. MigrationPlan::widens_before_push() reports it rather than hiding it, and a test asserts it is reported. Also relevant: GET /api/v1/policy against a database-mode coordinator with no row is an ERROR (grpcv1.go wraps ErrPolicyNotFound as \"loading ACL from database\"), not an empty string; Observation::live_policy models that as None.")
//! @yah:handoff("FINDING 3 — acls.yaml IS THE JOURNAL, WHICH IS WHY IT IS DELETED LAST AND WHY NO STATE FILE WAS NEEDED. Re-runnability was a hard requirement and it is met without writing any migration state anywhere: until the coordinator serves an equivalent policy from its database, acls.yaml is still on disk and the entire migration is re-derivable from it. next_step() is a pure function of an Observation {config_yaml, acls_file, live_policy, headscale_dir}, so a half-completed run is recovered by re-observing and re-running. Delete the file any earlier and an interruption loses the policy. MigrationPlan::deletes_the_file_early() is the invariant check; a test walks all three interruption midpoints (after flip / after push / after delete) and asserts each converges to Done with the invariant intact. One more property worth knowing, from hscontrol/db/policy.go: db.SetPolicy INSERTS a new `policies` row on every call and GetPolicy reads ORDER BY id DESC LIMIT 1 — so a push is idempotent in EFFECT but not in STORAGE. Both the reconciler and the migration compare before writing, so the table does not grow on repeat runs.")
//! @yah:handoff("WHAT LANDED, FILE BY FILE. NEW oss/yubaba/crates/cloud/src/reconciler/headscale/policy_migration.rs (a submodule of headscale.rs, not a sibling of reconciler/mod.rs — the module path is cloud::reconciler::headscale::policy_migration): PolicyMode {File{path}|Database|Unrecognised}, read_policy_mode() and rewrite_to_database_mode() (hand-written line surgery over the policy: block, NOT a serde_yaml round trip — serde_yaml is dev-only in this crate and a reserialize would reformat a config a human may have edited on the box; every other byte is preserved, unknown keys inside the block are kept, policy.path is dropped because headscale reads it only in file mode, an absent policy: block is appended because viper defaults it to file); Observation/Step/next_step() as the state machine; Execution{DryRun|Live} as a type rather than a bool so a dry run cannot arm a write by argument order; apply_push() which after a live PUT reads back and re-compares, and BAILS rather than reporting success if the coordinator serves back something different; rehearse() which drives the machine to a terminal state over a simulated coordinator; Step::on_box_commands() which returns the on-box steps as DATA (systemctl restart — not reload, since policy.mode is read once at startup in loadACLPolicy) instead of executing them. RENDERERS, all three flipped to mode: database with the path line removed: cloud/src/mesh.rs generate_headscale_config (new pub const POLICY_MODE), yubaba/src/lib.rs generate_remote_headscale_config and generate_bootstrap_headscale_config (new pub const HEADSCALE_POLICY_MODE, kept in lockstep by convention like DEFAULT_HEADSCALE_VERSION — there is no dependency edge from yubaba to yah-cloud). The escaped-space site (\\x20\\x20mode: file) was caught: my grep was on `mode: file` broadly, not on a two-space prefix.")
//! @yah:handoff("DISCOVERED WORK DONE, NOT FILED AS FOLLOWUPS — the four sites the leader named plus five more the flip broke or made wrong. FIXED ASSERTIONS: cloud/src/mesh.rs config_contains_server_url (now asserts `mode: database` AND that neither `acls.yaml` nor `policy.path` survives); yubaba/src/lib.rs bootstrap config test (same, and the comment now names the \\x20\\x20 spelling so the next reader does not re-lose the site). FIXED PROSE: reconciler/headscale.rs module header (rewritten — it claimed the fleet runs file mode and that flipping is \"deliberately NOT done here\"; both were the pre-flip world) and its set_policy error text (now names the migration instead of telling the reader file mode is the norm); mesh.rs get_policy/set_policy doc comments (now record what the v0.23.0 handlers actually do, including SetPolicy's pre-store validation and the append-only storage). STOPPED WRITING acls.yaml AT THREE PROVISIONING SITES, because leaving code that recreates the very file the migration deletes is the same bug pointing the other way: yubaba headscale_bootstrap (wrote DEFAULT_ACL_POLICY_HUJSON — behaviourally identical to dropping it, since an absent policy row is FilterAllowAll), yubaba headscale_deploy, and `yah mesh start` in app/yah/cli/src/mesh.rs. THE ONE PLACE THAT COULD HAVE LOST DATA IS NOW LOUD: headscale_deploy used to write the carried acl_policy to acls.yaml. Under database mode nothing reads that file, so a carried policy would have silently vanished and the destination would come up allow-all. It now REFUSES the deploy with 400 when the carried policy is not the permissive default (new pub fn carried_policy_is_permissive_default, whitespace-insensitive, deliberately coarse — a false negative only ever means \"refuse\", the safe direction). Callers updated: app/yah/cli/src/mesh.rs build_deploy_request forwards a leftover acls.yaml verbatim (so the refusal fires) and carries \"\" when there is none, instead of substituting DEFAULT_ACL_POLICY; crates/yah/cloud-client test fixture likewise. Three test fixtures sent `---\\nacls: []`, which headscale's HuJSON loader would have rejected outright — it was never a policy headscale could have booted on; they now send \"\".")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib = 1078 passed / 0 failed / 4 ignored, against the R861-T1 baseline of 1060 / 0 / 4 — +18, all new, all in reconciler::headscale::policy_migration. cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib = 639 passed / 0 failed, baseline 637, +2 (headscale_deploy_refuses_a_carried_non_default_policy, permissive_default_is_recognised_through_reformatting), both confirmed to run by name with --exact. NOTE FOR THE NEXT RUNNER: `cargo test -p yah-cloud --lib` from the repo root FAILS with \"cannot be tested because it requires dev-dependencies and is not a member of the workspace\" — yah-cloud lives in the oss/yubaba workspace, so only the --manifest-path form produces these numbers. cargo check -p yah --lib = no errors from any file I touched; the crate's only errors are the pre-existing E0425 in app/yah/cli/src/keys_doctor.rs (@Ashguard:polaris, R856), so `cargo test -p yah` could NOT be run and the two app/yah/cli/src/mesh.rs tests (build_deploy_request_round_trips_files and the new build_deploy_request_carries_no_policy_when_there_is_no_acls_file) are UNVERIFIED — they are pure-fs unit tests with no new API surface, but say so rather than assume. rustfmt --check (read mode only, never write mode on this tree) is clean on policy_migration.rs, cloud/src/mesh.rs, app/yah/cli/src/mesh.rs and cloud-client/src/lib.rs; it still reports four pre-existing hunks in reconciler/headscale.rs (lines ~261/380/790/887, all R861-T1's code, none in anything I wrote) which I deliberately did NOT reformat, since the leader was actively writing annotations into that file and formatting churn on a shared tree is how peers' hunks get lost.")
//! @yah:gotcha("THE LIVE FLEET WAS NOT TOUCHED, AND THE MIGRATION HAS NOT BEEN EXECUTED — stated plainly because everything above reads like it was. No write of any kind reached us-west-001, us-west-003 or any other box: no config.yaml was rewritten, no headscale was restarted, no policy was pushed, no acls.yaml was deleted. apply_push was never called with Execution::Live against anything. The renderer changes are LOCAL — they reach nodes only through a yubaba release plus a roll, so every live coordinator is still on `policy.mode: file` right now and the reconciler's ACL push is still refused there. The only network I used was an HTTPS GET of the headscale v0.23.0 source tarball from codeload.github.com into /tmp. Every claim about headscale's behaviour in this ticket comes from reading that source; NOTHING was verified against a running database-mode instance, because standing one up is itself a write. The remaining risk the code cannot retire: the rewriter and the state machine are tested against the exact config shape measured on us-west-001, but no real config.yaml has been round-tripped through them on a box. First live run should be a read-only observe (cat config.yaml, cat acls.yaml, GET /api/v1/policy) fed into next_step, and the printed step compared against expectation, BEFORE anything writes.")
//! @yah:next("EXECUTION IS THE GATED STEP AND IT IS NOT DONE. Order for whoever runs it: (1) cut and roll a yubaba release, because the renderer change reaches nodes no other way and an un-rolled node re-renders `mode: file` on its next provision; (2) per box, read-only observe (config.yaml, acls.yaml, GET /api/v1/policy) and feed policy_migration::next_step, checking the step it names matches expectation before any write; (3) execute in the printed order — flip+restart, push, verify read-back, delete — re-observing between each, since next_step is designed to be re-derived rather than batched; (4) us-west-001 first and alone, since it is the only node that currently holds the mesh (R858 gotchas), then us-west-003. Confirm before starting that the box's acls.yaml is still the permissive default: if it is not, the fail-open window between flip and push is a real widening of the tailnet and needs a maintenance slot rather than an in-place flip.")
//! @yah:cleanup("HeadscaleDeployRequest.acl_policy (yubaba/src/lib.rs and crates/yah/cloud-client/src/lib.rs) is now a field whose only remaining job is to be refused when non-default. Once every headscale-bearing box is migrated it can be deleted outright, along with carried_policy_is_permissive_default and the 400 branch. Left in place deliberately rather than removed now: while un-migrated boxes exist it is the only thing standing between a file-mode source coordinator and a silently allow-all destination. Also: DEFAULT_ACL_POLICY (cloud/src/mesh.rs) and DEFAULT_ACL_POLICY_HUJSON (yubaba/src/lib.rs) now have no non-test callers — both are pub so neither warns, and both stay useful as the documented \"what allow-all looks like\" reference, but they are dead weight the day the field goes.")
//! @yah:gotcha("SEQUENCING SLIP WORTH RECORDING SO IT IS NOT REPEATED: I added `pub mod policy_migration;` to reconciler/headscale.rs in one edit and wrote reconciler/headscale/policy_migration.rs in the next, leaving a ~2-minute window (16:02:34 to 16:04:28, 2026-09-04) where yah-cloud would not compile with E0583 and every crate downstream of it stopped there. @Ashguard:polaris hit it on an unrelated ticket. On a shared working tree a `mod` line ahead of its file is a camp-wide outage, not a harmless intermediate state: create the file first, then declare the module, and sequence edits so the tree builds at every point you pause. I also initially dismissed the peer's report because the path they quoted (reconciler/policy_migration.rs) was the Rust-2015 sibling location rather than the real submodule path — the path was wrong but the outage was real, and re-running my own build and finding it green *now* was not evidence about a window two minutes earlier. Check mtimes against the reporting build's timestamp before disputing a build report.")
//! @yah:assumes("That `policy.mode: database` needs no additional headscale config key to work — i.e. the `policies` table exists on an already-provisioned coordinator's headscale.db without a migration step. Grounded but not proven live: hscontrol/db/db.go runs `tx.AutoMigrate(&types.Policy{})` unconditionally as part of the normal migration set, so the table should be created on any headscale that has started at least once at v0.23.0, regardless of policy mode. Not confirmed against us-west-001's actual headscale.db, and it is one `sqlite3 headscale.db '.tables'` (read-only) away — worth doing during step (2) of the execution runbook before the first flip.")
//! @yah:handoff("ASSUMPTION DISCHARGED FIRST, AS THE TICKET REQUIRED. headscale v0.23.0's file and database policy modes both funnel through the same LoadACLPolicyFromBytes, established by reading the pinned version's source rather than probing a live box or trusting documentation. R861-T1's get_policy/set_policy therefore work unchanged under either mode, and everything downstream rests on solid ground.")
//! @yah:handoff("WHAT LANDED: new module cloud::reconciler::headscale::policy_migration (740 lines) — an idempotent state machine, config rewriter, dry-run-typed push, and a `rehearse` driver over a simulated coordinator. All three policy emit sites flipped to `database` and their `path:` lines removed: cloud/src/mesh.rs:598 (const POLICY_MODE at mesh.rs:552), yubaba/src/lib.rs:4811 and yubaba/src/lib.rs:5222 (const HEADSCALE_POLICY_MODE at lib.rs:568). THE ESCAPED-SPACE SITE WAS CAUGHT — that was the one an earlier pass undercounted, and independent verification confirms a repo-wide sweep for `\\x20\\x20mode` now finds only those two plus one comment.")
//! @yah:handoff("THE TWO BROKEN ASSERTIONS AND BOTH STALE PROSE SITES ARE FIXED, in-ticket rather than deferred. cloud/src/mesh.rs:801-802 and yubaba/src/lib.rs:7990-7991 now assert `mode: {POLICY_MODE}` AND `!contains(\"acls.yaml\")`, with lib.rs:7987-7989 naming the `\\x20\\x20` spelling explicitly for the next reader — the trap is now documented at the site instead of only on the board. The headscale.rs module header (:39-62) and mesh.rs:363-379 were rewritten so the old \"runs policy.mode: file\" claims read as past-tense 2026-09-04 measurements, and note that pre-existing boxes stay on file mode until migrated. Also made yubaba's deploy path REFUSE a carried non-permissive policy rather than silently dropping it.")
//! @yah:verify("INDEPENDENTLY RE-VERIFIED by a second agent reading the source and re-running the builds, not by re-reading the courier's claim. cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib = 1078 passed / 0 failed / 4 ignored (baseline 1060, +18). Same manifest -p yubaba --lib = 639 passed / 0 failed (baseline 637, +2). cargo check -p yah --lib = exit 0, zero errors, 19 warnings — the E0425 in keys_doctor.rs that was red earlier in this relay has since been fixed by @Ashguard:polaris. INVOCATION TRAP for anyone re-running: `cargo test -p yah-cloud --lib` FROM THE REPO ROOT fails with \"requires dev-dependencies and is not a member of the workspace\" — yah-cloud lives in the oss/yubaba workspace, so the --manifest-path form is the only one that yields these numbers.")
//! @yah:verify("NO LIVE-BOX WRITE EXISTS, verified three independent ways rather than asserted. (1) apply_push has NO production caller — rg over oss/ app/ crates/ finds Execution::Live only at its own definition (policy_migration.rs:222), its match arm (:243) and one test (:735). (2) Execution::{DryRun,Live} is a TYPE not a bool, so a dry run cannot arm a write by argument order. (3) Step::RemoveAclsFile never calls fs::remove_file — on_box_commands (:144-156) returns `sudo rm ...` as a Vec<String> for an operator rail. The live migration has not been run; nothing reached us-west-001, us-west-003 or any other box.")
//! @yah:handoff("EXECUTION IS FILED AS R861-T3 (blocked_on operator), NOT PARKED HERE. This ticket delivered the migration in code, rehearsed; running it against the live fleet is the remaining work and carries the order and fail-open caveats as gotchas there. Peer-file safety confirmed clean: oss/yah-base/crates/keys/src/spec.rs and oss/yubaba/crates/cloud/src/lib.rs are both UNTOUCHED by this ticket (git status empty for both) — lib.rs needed no export edit because policy_migration is declared as a submodule at headscale.rs:699. Nothing was committed by this work; the `sync` commits in history (be2680f4 etc.) are the camp's automatic wip-sweep, not this ticket's.")

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::info;

use super::{ReconcileCtx, Reconciler, RunningWorkload};
use crate::mesh::{HeadscaleClient, PreauthKeyRequest};

/// Workload kind this reconciler handles. Matches `ServiceComponent.kind`
/// and the `kind = "..."` line in `workload.toml`.
pub const WORKLOAD_KIND: &str = "headscale";

/// Keystore slot (and env fallback) holding the coordinator's admin API key.
/// Already the canonical slot — `crate::mesh`, `app/yah/cli/src/mesh.rs` and
/// `crates/yah/cloud-client` all read it.
pub const API_KEY_SLOT: &str = "headscale-api-key";
/// Env fallback paired with [`API_KEY_SLOT`].
pub const API_KEY_ENV: &str = "HEADSCALE_API_KEY";
/// Keystore slot (and env fallback) holding the coordinator base URL.
pub const MESH_URL_SLOT: &str = "mesh-url";
/// Env fallback paired with [`MESH_URL_SLOT`].
pub const MESH_URL_ENV: &str = "HEADSCALE_URL";

/// Reconciles `kind = "headscale"` components.
pub struct HeadscaleReconciler;

impl HeadscaleReconciler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HeadscaleReconciler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Reconciler for HeadscaleReconciler {
    fn kind(&self) -> &'static str {
        WORKLOAD_KIND
    }

    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        // (1) Materialize a git-sourced component before reading its dir.
        ctx.materialize().await?;

        // (2) Workload kind on disk must agree with the component's kind.
        let kind = ctx.workload_kind().context("loading workload.toml")?;
        if kind != WORKLOAD_KIND {
            anyhow::bail!(
                "component {component_id} kind=\"{WORKLOAD_KIND}\" but {workload_dir}/workload.toml declares kind=\"{kind}\"",
                component_id = ctx.component.id,
                workload_dir = ctx.workload_dir().display(),
            );
        }

        // (3) Parse + FULLY validate the declared config. Nothing below this
        // line may run before every field has been checked (R330-B5).
        let workload_dir = ctx.workload_dir();
        let declared = DeclaredHeadscale::load(&workload_dir)?;

        // (4) Resolve the coordinator URL + admin key. Still no API call.
        let base_url = match &declared.server_url {
            Some(u) => u.clone(),
            None => fob::get_or_env(MESH_URL_SLOT, MESH_URL_ENV)
                .context("reading the mesh-url keystore slot")?
                .with_context(|| {
                    format!(
                        "no coordinator URL: {workload}/workload.toml sets no `[headscale].server_url` \
                         and neither the `{MESH_URL_SLOT}` keystore slot nor ${MESH_URL_ENV} is set",
                        workload = workload_dir.display(),
                    )
                })?,
        };
        let api_key = fob::get_or_env(API_KEY_SLOT, API_KEY_ENV)
            .context("reading the headscale-api-key keystore slot")?
            .with_context(|| {
                format!(
                    "no headscale admin credential: set the `{API_KEY_SLOT}` keystore slot \
                     (`yah keys set {API_KEY_SLOT} <key>`) or ${API_KEY_ENV}. Mint one on the \
                     coordinator with `headscale apikeys create`."
                )
            })?;
        let client = HeadscaleClient::new(&base_url, api_key)?;

        let mut notes = Vec::new();

        // (5) Users — list first, create only what is missing. Never delete:
        // a headscale user owns the nodes registered under it, so a removal
        // here would evict machines nobody asked to evict.
        let live_users = client
            .list_users()
            .await
            .with_context(|| format!("listing headscale users on {base_url}"))?;
        for user in &declared.users {
            if live_users.iter().any(|u| u == user) {
                continue;
            }
            client
                .create_user(user)
                .await
                .with_context(|| format!("creating headscale user {user}"))?;
            info!(user, coordinator = %base_url, "headscale user created");
            notes.push(format!("created user {user}"));
        }

        // (6) Pre-auth keys — list per user, mint only when no live key already
        // satisfies the declared spec.
        let now = chrono::Utc::now();
        for spec in &declared.preauth_keys {
            let existing = client
                .list_preauth_keys(&spec.user)
                .await
                .with_context(|| format!("listing preauth keys for user {}", spec.user))?;
            let satisfied = existing
                .iter()
                .any(|k| k.is_usable_at(now) && spec.matches_record(k));
            if satisfied {
                continue;
            }
            let minted = client
                .create_preauth_key_with(&PreauthKeyRequest {
                    user: spec.user.clone(),
                    tags: spec.tags.clone(),
                    reusable: spec.reusable,
                    ephemeral: spec.ephemeral,
                    ttl_hours: spec.ttl_hours,
                })
                .await
                .with_context(|| format!("minting preauth key for user {}", spec.user))?;
            // The key value never reaches a log line or a note — only the fact
            // that one was minted and where it went.
            info!(
                user = %spec.user,
                tags = %spec.tags.join(","),
                "headscale preauth key minted"
            );
            match &spec.store_as {
                Some(slot) => {
                    fob::KeysStore::open()
                        .context("opening the keystore to store the minted preauth key")?
                        .set(slot, &minted.key)
                        .with_context(|| format!("writing the minted preauth key to slot {slot}"))?;
                    notes.push(format!("minted preauth key for {} -> {slot}", spec.user));
                }
                None => notes.push(format!(
                    "minted preauth key for {} (no `store_as`, value discarded)",
                    spec.user
                )),
            }
        }

        // (7) ACL policy — compare before writing. See the module docs for why
        // a file-mode coordinator can be read but not written.
        if let Some(policy) = &declared.acl_policy {
            let live = client
                .get_policy()
                .await
                .with_context(|| format!("reading the ACL policy from {base_url}"))?;
            if policies_equivalent(&live, &policy.hujson)? {
                notes.push("ACL policy in sync".to_string());
            } else {
                client.set_policy(&policy.hujson).await.with_context(|| {
                    format!(
                        "the declared ACL policy ({declared_path}) differs from the one \
                         {base_url} has loaded, and pushing it was refused. headscale accepts a \
                         policy write only under `policy.mode: database`, which every in-tree \
                         renderer now emits (R861-T2) — so a refusal here means this coordinator \
                         has not been migrated yet and is still reading `policy.path` off disk. \
                         Run the file-to-database migration on it \
                         ({migration}) and retry; until then the declared policy has to reach \
                         the node as the file `policy.path` names",
                        declared_path = policy.path.display(),
                        migration = policy_migration::MODULE_PATH,
                    )
                })?;
                info!(coordinator = %base_url, "headscale ACL policy updated");
                notes.push("ACL policy updated".to_string());
            }
        }

        Ok(
            RunningWorkload::adopted(WORKLOAD_KIND, ctx.component.role.clone(), None)
                .with_notes(notes),
        )
    }
}

// ─── declared config ─────────────────────────────────────────────────────────

/// The `[headscale]` table of a `kind = "headscale"` workload, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredHeadscale {
    pub server_url: Option<String>,
    pub users: Vec<String>,
    pub preauth_keys: Vec<DeclaredPreauthKey>,
    pub acl_policy: Option<DeclaredPolicy>,
}

/// One `[[headscale.preauth_keys]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredPreauthKey {
    pub user: String,
    pub tags: Vec<String>,
    pub reusable: bool,
    pub ephemeral: bool,
    pub ttl_hours: i64,
    pub store_as: Option<String>,
}

impl DeclaredPreauthKey {
    /// Whether a live key already satisfies this declaration.
    ///
    /// TTL is deliberately NOT compared: a key minted a week ago against a
    /// 168-hour declaration has a shorter remaining life than a fresh one and
    /// is still exactly the key that was asked for. Comparing it would mint a
    /// new key on every single run.
    fn matches_record(&self, record: &crate::mesh::PreauthKeyRecord) -> bool {
        record.user == self.user
            && record.reusable == self.reusable
            && record.ephemeral == self.ephemeral
            && record.acl_tags.iter().collect::<BTreeSet<_>>()
                == self.tags.iter().collect::<BTreeSet<_>>()
    }
}

/// The declared ACL policy: where it was read from, and its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredPolicy {
    pub path: std::path::PathBuf,
    pub hujson: String,
}

impl DeclaredHeadscale {
    /// Read and validate `<workload_dir>/workload.toml`'s `[headscale]` table.
    ///
    /// Every check that can be made without the network is made here, so a
    /// misdeclared component fails before it has half-created anything.
    pub fn load(workload_dir: &Path) -> Result<Self> {
        let path = workload_dir.join("workload.toml");
        let src = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let value: toml::Value =
            toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
        Self::from_toml(&value, workload_dir)
            .with_context(|| format!("validating {}", path.display()))
    }

    fn from_toml(value: &toml::Value, workload_dir: &Path) -> Result<Self> {
        let table = value
            .get("headscale")
            .context("missing `[headscale]` table — a kind=\"headscale\" workload declares the users, preauth keys and ACL policy the coordinator must have")?;

        let server_url = match table.get("server_url") {
            None => None,
            Some(v) => {
                let s = v
                    .as_str()
                    .context("[headscale].server_url must be a string")?
                    .trim();
                if !(s.starts_with("http://") || s.starts_with("https://")) {
                    anyhow::bail!(
                        "[headscale].server_url must be an http(s) URL, got {s:?}"
                    );
                }
                Some(s.trim_end_matches('/').to_string())
            }
        };

        let mut users: Vec<String> = Vec::new();
        for entry in table
            .get("users")
            .map(|v| {
                v.as_array()
                    .context("[headscale].users must be an array of strings")
            })
            .transpose()?
            .cloned()
            .unwrap_or_default()
        {
            let name = entry
                .as_str()
                .context("[headscale].users entries must be strings")?
                .trim()
                .to_string();
            if name.is_empty() {
                anyhow::bail!("[headscale].users contains an empty name");
            }
            if name.chars().any(char::is_whitespace) {
                anyhow::bail!("[headscale].users entry {name:?} contains whitespace");
            }
            if users.contains(&name) {
                anyhow::bail!("[headscale].users lists {name:?} twice");
            }
            users.push(name);
        }

        let mut preauth_keys = Vec::new();
        for entry in table
            .get("preauth_keys")
            .map(|v| {
                v.as_array()
                    .context("[[headscale.preauth_keys]] must be an array of tables")
            })
            .transpose()?
            .cloned()
            .unwrap_or_default()
        {
            preauth_keys.push(parse_preauth_key(&entry, &users)?);
        }

        let acl_policy = match table.get("acl_policy") {
            None => None,
            Some(v) => {
                let rel = v
                    .as_str()
                    .context("[headscale].acl_policy must be a path string")?;
                let abs = workload_dir.join(rel);
                let hujson = std::fs::read_to_string(&abs).with_context(|| {
                    format!(
                        "reading the declared ACL policy {} — [headscale].acl_policy is relative to the workload dir",
                        abs.display()
                    )
                })?;
                // Parse it here, not at push time: an unparseable policy must
                // fail before any user or key is created.
                let parsed = parse_hujson(&hujson).with_context(|| {
                    format!("parsing the declared ACL policy {}", abs.display())
                })?;
                if !parsed.get("acls").map(|a| a.is_array()).unwrap_or(false) {
                    anyhow::bail!(
                        "{}: a headscale policy needs a top-level `acls` array",
                        abs.display()
                    );
                }
                Some(DeclaredPolicy { path: abs, hujson })
            }
        };

        if users.is_empty() && preauth_keys.is_empty() && acl_policy.is_none() {
            anyhow::bail!(
                "[headscale] declares nothing — set at least one of `users`, \
                 `[[headscale.preauth_keys]]` or `acl_policy`"
            );
        }

        Ok(Self {
            server_url,
            users,
            preauth_keys,
            acl_policy,
        })
    }
}

fn parse_preauth_key(entry: &toml::Value, declared_users: &[String]) -> Result<DeclaredPreauthKey> {
    let user = entry
        .get("user")
        .and_then(|v| v.as_str())
        .context("[[headscale.preauth_keys]] entry needs a `user` string")?
        .trim()
        .to_string();
    // The typo guard: a key minted against a user headscale does not have
    // answers 500 (R608-B19), and by then users may already have been created.
    if !declared_users.contains(&user) {
        anyhow::bail!(
            "[[headscale.preauth_keys]] names user {user:?}, which [headscale].users does not \
             declare (declared: {declared}). Add it there — the reconciler only creates users it \
             was told about.",
            declared = if declared_users.is_empty() {
                "none".to_string()
            } else {
                declared_users.join(", ")
            }
        );
    }

    let mut tags = Vec::new();
    for tag in entry
        .get("tags")
        .map(|v| {
            v.as_array()
                .context("[[headscale.preauth_keys]].tags must be an array of strings")
        })
        .transpose()?
        .cloned()
        .unwrap_or_default()
    {
        let tag = tag
            .as_str()
            .context("[[headscale.preauth_keys]].tags entries must be strings")?
            .trim()
            .to_string();
        if !tag.starts_with("tag:") {
            anyhow::bail!("ACL tag {tag:?} must start with `tag:` — headscale rejects the rest");
        }
        // headscale answers "tag should be lowercase" for a mixed-case tag.
        if tag != tag.to_lowercase() {
            anyhow::bail!("ACL tag {tag:?} must be lowercase — headscale rejects mixed case");
        }
        if tags.contains(&tag) {
            anyhow::bail!("[[headscale.preauth_keys]] for {user} lists tag {tag:?} twice");
        }
        tags.push(tag);
    }

    let ttl_hours = match entry.get("ttl_hours") {
        None => 1,
        Some(v) => v
            .as_integer()
            .context("[[headscale.preauth_keys]].ttl_hours must be an integer")?,
    };
    if ttl_hours <= 0 {
        anyhow::bail!(
            "[[headscale.preauth_keys]] for {user} has ttl_hours={ttl_hours}; it must be positive"
        );
    }

    let store_as = match entry.get("store_as") {
        None => None,
        Some(v) => {
            let slot = v
                .as_str()
                .context("[[headscale.preauth_keys]].store_as must be a keystore slot name")?
                .trim()
                .to_string();
            if slot.is_empty() {
                anyhow::bail!("[[headscale.preauth_keys]].store_as is empty");
            }
            Some(slot)
        }
    };

    Ok(DeclaredPreauthKey {
        user,
        tags,
        reusable: entry
            .get("reusable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        ephemeral: entry
            .get("ephemeral")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        ttl_hours,
        store_as,
    })
}

// ─── HuJSON ──────────────────────────────────────────────────────────────────

/// Compare two headscale policies for semantic equality.
///
/// A byte compare is the wrong test: headscale round-trips the policy through
/// its own storage, and the declared file carries comments and formatting that
/// say nothing about the tailnet. Both sides are normalized from HuJSON to
/// JSON and compared as values, so reformatting the declared file does not
/// trigger a spurious push and a genuinely different rule always does.
fn policies_equivalent(live: &str, declared: &str) -> Result<bool> {
    let live = parse_hujson(live).context("parsing the coordinator's current ACL policy")?;
    let declared = parse_hujson(declared).context("parsing the declared ACL policy")?;
    Ok(live == declared)
}

/// Parse HuJSON (`policy.path` is documented as "a policy file in HuJSON
/// format") into a JSON value.
///
/// HuJSON is JSON plus `//` and `/* */` comments and trailing commas. There is
/// no HuJSON crate in this workspace, so the two extensions are stripped here
/// and the remainder handed to `serde_json`. String literals are tracked so a
/// `//` or a comma inside a value is left alone.
fn parse_hujson(src: &str) -> Result<serde_json::Value> {
    let stripped = strip_hujson_extensions(src);
    serde_json::from_str(&stripped).context("not valid HuJSON (JSON with comments/trailing commas)")
}

fn strip_hujson_extensions(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;

    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev_star = false;
                for c in chars.by_ref() {
                    if prev_star && c == '/' {
                        break;
                    }
                    prev_star = c == '*';
                }
                // Keep a separator so `1/* */2` cannot fuse into `12`.
                out.push(' ');
            }
            _ => out.push(c),
        }
    }

    strip_trailing_commas(&out)
}

/// Drop commas that are followed only by whitespace/comments and a `}` or `]`.
/// Comments are already gone by the time this runs.
fn strip_trailing_commas(src: &str) -> String {
    let bytes: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut in_string = false;
    let mut escaped = false;

    for (i, &c) in bytes.iter().enumerate() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push(c);
            continue;
        }
        if c == ',' {
            let next = bytes[i + 1..].iter().find(|c| !c.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        out.push(c);
    }

    out
}

// ─── file → database policy migration (R861-T2) ──────────────────────────────

pub mod policy_migration;

#[cfg(test)]
mod tests {
    use super::*;

    fn workload_toml(body: &str) -> toml::Value {
        toml::from_str(body).expect("test fixture parses as TOML")
    }

    #[test]
    fn declared_config_round_trips() {
        let v = workload_toml(
            r#"
schema_version = 1
kind = "headscale"

[headscale]
server_url = "https://cloud.mesh.yah.dev/"
users = ["yah"]

[[headscale.preauth_keys]]
user = "yah"
tags = ["tag:cloud-runner"]
reusable = true
ttl_hours = 168
store_as = "headscale-preauth-key"
"#,
        );
        let declared = DeclaredHeadscale::from_toml(&v, Path::new("/nonexistent")).unwrap();
        assert_eq!(
            declared.server_url.as_deref(),
            Some("https://cloud.mesh.yah.dev")
        );
        assert_eq!(declared.users, vec!["yah".to_string()]);
        assert_eq!(declared.preauth_keys.len(), 1);
        let key = &declared.preauth_keys[0];
        assert!(key.reusable);
        assert!(!key.ephemeral);
        assert_eq!(key.ttl_hours, 168);
        assert_eq!(key.store_as.as_deref(), Some("headscale-preauth-key"));
    }

    #[test]
    fn preauth_key_against_undeclared_user_is_rejected() {
        let v = workload_toml(
            r#"
[headscale]
users = ["yah"]

[[headscale.preauth_keys]]
user = "defualt"
"#,
        );
        let err = DeclaredHeadscale::from_toml(&v, Path::new("/nonexistent")).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("defualt"), "{msg}");
        assert!(msg.contains("yah"), "{msg}");
    }

    #[test]
    fn tags_must_be_prefixed_and_lowercase() {
        for (tags, needle) in [
            (r#"["cloud-runner"]"#, "tag:"),
            (r#"["tag:Cloud-Runner"]"#, "lowercase"),
        ] {
            let v = workload_toml(&format!(
                "[headscale]\nusers = [\"yah\"]\n\n[[headscale.preauth_keys]]\nuser = \"yah\"\ntags = {tags}\n"
            ));
            let err = DeclaredHeadscale::from_toml(&v, Path::new("/nonexistent")).unwrap_err();
            assert!(format!("{err:#}").contains(needle), "{err:#} for {tags}");
        }
    }

    #[test]
    fn non_positive_ttl_is_rejected() {
        let v = workload_toml(
            r#"
[headscale]
users = ["yah"]

[[headscale.preauth_keys]]
user = "yah"
ttl_hours = 0
"#,
        );
        let err = DeclaredHeadscale::from_toml(&v, Path::new("/nonexistent")).unwrap_err();
        assert!(format!("{err:#}").contains("positive"), "{err:#}");
    }

    #[test]
    fn empty_declaration_is_rejected() {
        let v = workload_toml("[headscale]\n");
        let err = DeclaredHeadscale::from_toml(&v, Path::new("/nonexistent")).unwrap_err();
        assert!(format!("{err:#}").contains("declares nothing"), "{err:#}");
    }

    #[test]
    fn duplicate_user_is_rejected() {
        let v = workload_toml("[headscale]\nusers = [\"yah\", \"yah\"]\n");
        let err = DeclaredHeadscale::from_toml(&v, Path::new("/nonexistent")).unwrap_err();
        assert!(format!("{err:#}").contains("twice"), "{err:#}");
    }

    #[test]
    fn server_url_must_be_http() {
        let v = workload_toml("[headscale]\nusers = [\"yah\"]\nserver_url = \"cloud.mesh.yah.dev\"\n");
        let err = DeclaredHeadscale::from_toml(&v, Path::new("/nonexistent")).unwrap_err();
        assert!(format!("{err:#}").contains("http(s) URL"), "{err:#}");
    }

    /// The whole on-disk path: a workload dir with a `workload.toml` and the
    /// HuJSON policy file it points at, read through [`DeclaredHeadscale::load`].
    #[test]
    fn loads_a_workload_dir_off_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("workload.toml"),
            r#"schema_version = 1
kind = "headscale"

[headscale]
users = ["yah"]
acl_policy = "acls.hujson"

[[headscale.preauth_keys]]
user = "yah"
tags = ["tag:cloud-runner", "tag:voter-candidate"]
reusable = true
ttl_hours = 168
store_as = "headscale-preauth-key"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("acls.hujson"),
            "// permissive default\n{ \"acls\": [ { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"] } ] }\n",
        )
        .unwrap();

        let declared = DeclaredHeadscale::load(dir.path()).unwrap();
        assert_eq!(declared.users, vec!["yah".to_string()]);
        assert_eq!(declared.preauth_keys[0].tags.len(), 2);
        let policy = declared.acl_policy.as_ref().unwrap();
        assert_eq!(policy.path, dir.path().join("acls.hujson"));
        // What the live coordinator already serves — so this fixture is in
        // sync and a reconcile against it would push nothing.
        assert!(policies_equivalent(LIVE_POLICY, &policy.hujson).unwrap());
    }

    #[test]
    fn a_missing_policy_file_names_the_path_it_looked_for() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("workload.toml"),
            "[headscale]\nusers = [\"yah\"]\nacl_policy = \"acls.hujson\"\n",
        )
        .unwrap();
        let err = DeclaredHeadscale::load(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("acls.hujson"), "{err:#}");
    }

    #[test]
    fn a_policy_without_an_acls_array_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("workload.toml"),
            "[headscale]\nusers = [\"yah\"]\nacl_policy = \"acls.hujson\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("acls.hujson"), "{ \"tagOwners\": {} }").unwrap();
        let err = DeclaredHeadscale::load(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("`acls` array"), "{err:#}");
    }

    /// The exact bytes on us-west-001, read 2026-09-04.
    const LIVE_POLICY: &str = "{\n  \"acls\": [\n    { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"] }\n  ]\n}\n";

    #[test]
    fn reformatting_the_policy_is_not_drift() {
        let declared = r#"
// The permissive default: every node may reach every node.
{
  "acls": [
    {
      "action": "accept",
      "src": ["*"],
      "dst": ["*:*"],
    },
  ],
}
"#;
        assert!(policies_equivalent(LIVE_POLICY, declared).unwrap());
    }

    #[test]
    fn a_different_rule_is_drift() {
        let declared = r#"{ "acls": [ { "action": "accept", "src": ["tag:cloud-runner"], "dst": ["*:*"] } ] }"#;
        assert!(!policies_equivalent(LIVE_POLICY, declared).unwrap());
    }

    #[test]
    fn comment_markers_inside_strings_survive() {
        let src = r#"{ "acls": [ { "action": "accept", "src": ["*"], "dst": ["https://x/*:443"] } ] }"#;
        let parsed = parse_hujson(src).unwrap();
        assert_eq!(parsed["acls"][0]["dst"][0], "https://x/*:443");
    }

    #[test]
    fn block_comments_are_stripped() {
        let parsed = parse_hujson("{ /* header */ \"acls\": [] }").unwrap();
        assert!(parsed["acls"].as_array().unwrap().is_empty());
    }

    #[test]
    fn unparseable_policy_is_an_error() {
        assert!(parse_hujson("{ \"acls\": [ ").is_err());
    }

    #[test]
    fn preauth_spec_matches_ignore_ttl_but_not_tags() {
        let spec = DeclaredPreauthKey {
            user: "yah".into(),
            tags: vec!["tag:cloud-runner".into()],
            reusable: true,
            ephemeral: false,
            ttl_hours: 168,
            store_as: None,
        };
        let mut record = crate::mesh::PreauthKeyRecord {
            id: "1".into(),
            user: "yah".into(),
            key: "secret".into(),
            reusable: true,
            ephemeral: false,
            used: false,
            expiration: Some(chrono::Utc::now() + chrono::TimeDelta::try_hours(1).unwrap()),
            acl_tags: vec!["tag:cloud-runner".into()],
        };
        assert!(spec.matches_record(&record));
        assert!(record.is_usable_at(chrono::Utc::now()));

        record.acl_tags = vec!["tag:voter".into()];
        assert!(!spec.matches_record(&record));
    }

    #[test]
    fn an_expired_or_spent_key_does_not_satisfy_a_spec() {
        let now = chrono::Utc::now();
        let expired = crate::mesh::PreauthKeyRecord {
            id: "1".into(),
            user: "yah".into(),
            key: "secret".into(),
            reusable: false,
            ephemeral: false,
            used: false,
            expiration: Some(now - chrono::TimeDelta::try_hours(1).unwrap()),
            acl_tags: vec![],
        };
        assert!(!expired.is_usable_at(now));

        let spent = crate::mesh::PreauthKeyRecord {
            used: true,
            expiration: Some(now + chrono::TimeDelta::try_hours(1).unwrap()),
            ..expired.clone()
        };
        assert!(!spent.is_usable_at(now));

        // A reusable key stays usable after being used.
        let reusable = crate::mesh::PreauthKeyRecord {
            reusable: true,
            ..spent.clone()
        };
        assert!(reusable.is_usable_at(now));

        // A key with no expiry never ages out.
        let forever = crate::mesh::PreauthKeyRecord {
            expiration: None,
            used: false,
            reusable: false,
            ..expired
        };
        assert!(forever.is_usable_at(now));
    }
}
