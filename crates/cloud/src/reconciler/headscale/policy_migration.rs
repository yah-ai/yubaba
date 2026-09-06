//! Migrate a headscale coordinator from `policy.mode: file` to
//! `policy.mode: database` (R861-T2).
//!
//! ## Why
//!
//! Under `file` mode the ACL policy is `acls.yaml` on the coordinator's local
//! disk, and litestream replicates only `headscale.db` — so policy is failover
//! state nobody carries. Under `database` mode the policy is a row in
//! `headscale.db`, which litestream already replicates, and the file stops
//! mattering at all. That is the whole point of the flip.
//!
//! ## What was verified before any of this was written
//!
//! R861-T2's load-bearing assumption was that the pinned headscale **v0.23.0**
//! (`crate::mesh::HEADSCALE_VERSION`) accepts, in `database` mode, the same
//! HuJSON document `file` mode reads off disk. **It holds**, read from that
//! version's own source rather than recalled:
//!
//! - `hscontrol/app.go` `loadACLPolicy` — file mode does
//!   `policy.LoadACLPolicyFromPath`, which is `io.ReadAll` followed by
//!   `LoadACLPolicyFromBytes`; database mode does `LoadACLPolicyFromBytes` on
//!   the stored row. Same function, same document, no second format.
//! - `hscontrol/grpcv1.go` `SetPolicy` — parses the request body with that
//!   same `LoadACLPolicyFromBytes` before storing it.
//! - `hscontrol/grpcv1.go` `GetPolicy` — database mode returns the stored
//!   row's `Data` verbatim; file mode returns the file's bytes as-is.
//! - `hscontrol/types/config.go` — `policy.mode` is exactly `"file"` or
//!   `"database"`, defaulting to `"file"` when the key is absent, and
//!   `policy.path` is read only in file mode.
//!
//! So [`crate::mesh::HeadscaleClient::get_policy`] / `set_policy` work
//! unchanged under either mode.
//!
//! ## Three findings that reshape the migration
//!
//! **1. The ticket's stated order is impossible, and this module inverts it.**
//! R861-T2 specified "push the policy through `set_policy`, verify, *then*
//! flip the mode". `SetPolicy` returns `ErrPolicyUpdateIsDisabled` *before
//! looking at the payload* unless `cfg.Policy.Mode == database`
//! (`hscontrol/grpcv1.go`). A file-mode coordinator cannot be pushed to at all,
//! so the config flip has to come FIRST. See [`next_step`].
//!
//! **2. The window the inverted order opens is safe here, and the reason is
//! specific rather than general.** Between the flip and the push, a
//! database-mode coordinator with no policy row is not an error: `loadACLPolicy`
//! maps `ErrPolicyNotFound` to a nil `*ACLPolicy`, and
//! `(*ACLPolicy).CompileFilterRules` on nil returns `tailcfg.FilterAllowAll`
//! (`hscontrol/policy/acls.go`). us-west-001's live `acls.yaml` is the
//! permissive default `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
//! (measured 2026-09-04), so for THIS fleet the window is semantically a no-op.
//! On a coordinator with a restrictive policy the same window is a silent
//! widening to allow-all, which is why [`next_step`] still drives the push
//! immediately and why [`MigrationPlan::widens_before_push`] reports it.
//!
//! **3. `acls.yaml` is the journal, which is why it is deleted last.** Nothing
//! here writes a state file: until the coordinator serves an equivalent policy
//! from its database, `acls.yaml` is still on disk and the whole migration is
//! re-derivable from it. Re-running after any interruption re-observes and
//! resumes. Delete it earlier and a half-completed run loses the policy.
//!
//! ## What this module does NOT do
//!
//! It does not touch a live coordinator. [`next_step`] is a pure function of an
//! [`Observation`], and the steps that must run on the box come back as data
//! ([`Step::on_box_commands`]) for whatever rail the operator uses. The one
//! step that can be driven from here is the policy push, and
//! [`apply_push`] takes an explicit [`Execution`] so a dry run cannot write by
//! omission.
//!
//! ## The rail that does (R861-T3)
//!
//! `yah mesh migrate-policy <machine> [--execute]`
//! (`app/yah/cli/src/mesh.rs::handle_migrate_policy`) is the one production
//! caller. It observes over SSH + the headscale API, prints the next step and
//! the rehearsed remainder, and performs exactly one step per invocation — but
//! only under `--execute`, which is the sole place [`Execution::Live`] is
//! constructed outside tests. It also refuses, before doing anything, when the
//! carried policy is not [`is_permissive`]: the flip-then-push window is a
//! widening to allow-all, and that is a no-op only while the policy being
//! carried across it is itself allow-all.
//!
//! @yah:ticket(R861-T3, "Execute the headscale file-to-database policy migration against the live fleet")
//! @yah:status(review)
//! @yah:at(2026-09-05T01:54:53Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R861)
//! @yah:gotcha("ORDER IS LOAD-BEARING AND COUNTERINTUITIVE: config-flip to mode=database and restart FIRST, then push the policy. headscale v0.23.0's SetPolicy returns ErrPolicyUpdateIsDisabled BEFORE it reads the payload unless mode is already database, so the intuitive push-then-flip is silently impossible. The state machine in policy_migration.rs already encodes the correct order (next_step matches PolicyMode::File first and returns Step::FlipConfigToDatabaseMode; PushCarriedPolicy is only reachable after the Database arm). Do not \"fix\" it to push first.")
//! @yah:gotcha("RE-CHECK THE FAIL-OPEN WINDOW BEFORE EXECUTING — the safety argument is fleet-state-dependent and may have expired. Between the mode flip and the policy push, headscale has no policy row, and a missing row compiles to FilterAllowAll. That is harmless ONLY because the live acls.yaml is currently the permissive default, making the gap state and the current effective state both allow-all. If real ACL rules have been declared since, the same window becomes a fail-OPEN interval — a security exposure, not an outage. Read the live acls.yaml and confirm it is still permissive as the first action of this ticket.")
//! @yah:handoff("PHASE A — THE OPERATOR'S \"do I need to ship new builds first?\" QUESTION, ANSWERED FROM CODE. (1) NO BUILD/SHIP IS REQUIRED TO RUN THE MIGRATION. Both rails originate on this machine. The API half is HTTPS from a LOCAL yah: HeadscaleClient holds only base_url + api_key and PUT/GETs {base_url}/api/v1/policy with bearer auth (oss/yubaba/crates/cloud/src/mesh.rs:131-160, :380, :421), resolved from the vault's headscale-api-key + mesh-url via from_vault_or_env (:151). The on-box half is SSH (`ssh <target> bash -s`, the same transport app/yah/cli/src/rollout/apply.rs:155 uses for installs), target read from [connect].ssh in .yah/infra/machines/us-west-001.toml:71 = debian@15.204.89.240. Nothing on the appliance needs new bytes. (2) THE RENDERER FLIP DOES NEED A SHIPPED ARTIFACT, AND ONLY FOR NEW-COORDINATOR STAND-UP. Two of the three emit sites run ON THE BOX, inside the yubaba daemon: generate_remote_headscale_config is called at oss/yubaba/crates/yubaba/src/lib.rs:4705 inside the `headscale_deploy` handler (route registered lib.rs:1933) and generate_bootstrap_headscale_config at :4916 inside `headscale_bootstrap` (route :1934) — both `std::fs::write(dir.join(\"config.yaml\"))`. Appliance yubaba binaries come only from cdn.yah.dev's signed release manifest via scripts/roll-node.sh (its header: \"THE INPUT IS THE PUBLISHED MANIFEST, NEVER A LOCAL BUILD\"), so for `yah mesh promote` / `yah mesh bootstrap` to stand a coordinator up in database mode the sequence is scripts/publish-yubaba-release.sh then a roll. The third site, cloud::mesh::generate_headscale_config (mesh.rs:561), is called only from the LOCAL CLI (app/yah/cli/src/mesh.rs:389 in handle_start, :934 in handle_promote_abort), so `cargo xtask install` is all that one needs. (3) NO CLOBBER RISK ON THE EXISTING BOX, verified rather than assumed: leader.rs::start_headscale (oss/yubaba/crates/yubaba/src/leader.rs:358-400) materializes the noise key and deploys the appliance spec — it does NOT write config.yaml — so a raft leadership change or a kamaji redeploy will not revert a flipped config. Only an operator-driven POST /headscale/deploy or /headscale/bootstrap rewrites it. (4) VERSION/COMPAT IS CLEAN: `/var/lib/yah-cloud/headscale/headscale version` on us-west-001 returns v0.23.0, exactly the pinned version constant in cloud/src/mesh.rs:628 and yubaba/src/lib.rs:555.")
//! @yah:handoff("PHASE C — TARGETS AND THE FAIL-OPEN GATE, RE-MEASURED. THE TARGET LIST IS ONE BOX, NOT TWO: us-west-003 CARRIES NO HEADSCALE. Enumerated from .yah/infra/machines/ (9 declared) and cross-checked against the mesh itself (`yah mesh status` reports coordinator = us-west-001, 10 nodes, 9 online), then probed read-only over SSH on every reachable one: us-west-001 has /var/lib/yah-cloud/headscale/{config.yaml,acls.yaml,headscale.db,headscale binary}; us-south-001, us-east-001, us-west-003, us-west-011, us-west-013, us-west-014 all answer \"No such file or directory\" for that directory and `systemctl is-active headscale` = inactive; us-west-015 is the fleet's Mac (no systemctl, no directory); us-west-002 is unreachable (SSH to 100.64.0.4 timed out — it is the known-offline WSL box, [connect].ssh points at its mesh address). There is no camp-local coordinator either (~/.local/share/yah/mesh does not exist). So exactly one box migrates. THE FAIL-OPEN PRECONDITION STILL HOLDS: us-west-001's /var/lib/yah-cloud/headscale/acls.yaml is 77 bytes, mtime Jun 22, and is byte-for-byte the permissive default {\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}]} — semantically equal to cloud::mesh::DEFAULT_ACL_POLICY. No real ACL rules anywhere; the flip-then-push window is a no-op for this fleet and the migration's safety argument is intact. Its config.yaml lines 32-34 still read `policy:` / `  mode: file` / `  path: /var/lib/yah-cloud/headscale/acls.yaml`.")
//! @yah:gotcha("DISCOVERED AND FIXED IN-TICKET — `sudo systemctl restart headscale` IS THE WRONG RESTART FOR THE ONLY LIVE COORDINATOR, AND IT FAILS SILENTLY. Measured on us-west-001 2026-09-04: `systemctl is-active headscale` = inactive and `is-enabled` = disabled, while `headscale serve --config /var/lib/yah-cloud/headscale/config.yaml` IS running as pid 515991 whose PPID is /usr/local/bin/kamaji (started 23:11, listening on *:443 and *:80, https://cloud.mesh.yah.dev/key?v=138 returns 200). That is leader.rs::start_headscale's kamaji path (oss/yubaba/crates/yubaba/src/leader.rs:381 does `systemctl disable --now headscale` before deploying the appliance under kamaji). So the systemctl restart R861-T2's Step::on_box_commands emitted would have forked a SECOND headscale against the same :443 — it fails to bind while the kamaji-supervised process keeps serving the PRE-FLIP config, i.e. a config on disk saying `mode: database` and a coordinator still in file mode, reported to the operator as a successful step. `policy.mode` is read once at startup, so that state is invisible until the next real restart. FIX (this ticket, policy_migration.rs): new `Supervisor {Systemd | Kamaji{pid} | Unknown}` on Observation, `on_box_commands(dir, &supervisor)`, and `restart_commands()` which emits `sudo kill <pid>` for the kamaji case (kamaji's native supervisor re-execs the child per RestartPolicy::Always — see oss/kamaji/crates/kamaji/src/native.rs, ALWAYS_RESTART_DELAY = 1s — so ending the process IS the restart) plus a sleep and a pgrep confirmation, and for Unknown emits ONLY comments so no rail can execute a guess. Two new tests pin both.")
//! @yah:handoff("PHASE B — THE EXECUTOR IS WIRED AND ARMED, AND NOTHING HAS BEEN FIRED. New subcommand `yah mesh migrate-policy [machine] [--path .] [--execute]` (app/yah/cli/src/mesh.rs: enum arm in MeshCommands, dispatch arm in handle_mesh_command, handler `handle_migrate_policy` + helpers `ssh_bash`, `sudo_prefix`, `observe_coordinator`). READ-ONLY BY DEFAULT, which is deliberately INVERTED relative to its `--dry-run` siblings (promote/bootstrap): this command's live half rewrites the coordinator's config, restarts it and deletes the only on-disk copy of the policy, so the safe mode has to be the one you get by forgetting a flag. `Execution::Live` is now constructed in exactly ONE production place, app/yah/cli/src/mesh.rs inside the `execute` branch of the PushCarriedPolicy arm — `rg \"Execution::Live\"` over oss/ app/ crates/ finds that one call plus the enum's own arm, the module doc, and one test. One step per invocation, re-observed from scratch each time, so it resumes correctly after an interruption. Machine resolution: [connect].ssh via crate::rollout::fleet::FleetTopology::load, defaulting to the vault's mesh-coordinator-machine. THE FAIL-OPEN GATE IS ENFORCED IN CODE, not just documented: new `policy_migration::is_permissive()` compares the carried policy semantically against cloud::mesh::DEFAULT_ACL_POLICY, and the handler BAILS before doing anything if a flip is pending against a non-permissive acls.yaml. Also refuses to flip when the supervisor is Unknown. ALSO ADDED, both used by the rail and by tests so the operator's rehearsal cannot drift from the tested model: `Step::label()` (one line instead of a Debug that embeds a whole config.yaml) and `pub fn simulate_step()` — the step-effect model promoted out of the test module, so `rehearse()` can run against a REAL observation.")
//! @yah:verify("REHEARSED AGAINST THE REAL COORDINATOR, READ-ONLY — `./target/debug/yah mesh migrate-policy us-west-001` (no --execute) run twice. It resolved debian@15.204.89.240, read the live config.yaml and acls.yaml over SSH and the served policy over the API, and reported: policy.mode = File{path: /var/lib/yah-cloud/headscale/acls.yaml}; supervisor = Kamaji{pid: 515991}; acls.yaml = 77 bytes, the permissive allow-all default; served policy = 77 bytes; and the rehearsed plan from that observed state = 1. FlipConfigToDatabaseMode 2. PushCarriedPolicy (77 bytes) 3. RemoveAclsFile 4. Done, with widens_before_push = true and deletes_the_file_early = FALSE. Flip-then-push, never push-then-flip; the file is never removed before the push. The rewritten config it would write was inspected: `policy:` / `  mode: database` with the `path:` line dropped, every other byte of the 1060-byte config preserved (server_url, tls_letsencrypt_*, noise.private_key_path, database.sqlite.path, unix_socket, dns, prefixes, derp all unchanged). The on-box command list it emits is `sudo kill 515991` + sleep + pgrep, NOT systemctl. Run ended with \"DRY RUN — nothing was changed.\"")
//! @yah:verify("BASELINES, ALL MET. `cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib` = 1081 passed / 0 failed / 4 ignored (baseline 1078/0/4; +3 are this ticket's new tests: a_kamaji_supervised_coordinator_is_never_told_to_systemctl_restart, an_unidentified_supervisor_yields_no_runnable_restart, the_live_acls_file_reads_as_permissive_and_a_real_rule_does_not). `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib` = 649 passed / 0 failed (baseline 639/0 — the +10 are a peer's, untouched by this ticket, all green). `cargo check -p yah --lib` = exit 0, 19 warnings all pre-existing and on files this ticket did not touch; `cargo build -p yah --bin yah` also clean. rustfmt --check on exactly the two edited files (app/yah/cli/src/mesh.rs, policy_migration.rs) = clean, hand-applied 4 hunks; write-mode `cargo fmt` was NOT run, per the standing rule about cloud/src/lib.rs following mod decls into peer files. ONE TRANSIENT PEER BREAKAGE seen and not touched: an unterminated block comment at oss/yah-base/crates/keys/src/spec.rs:1225 failed the `fob` crate mid-session (E0758); it was gone on the retry and is not this ticket's.")
//! @yah:next("MIGRATION DONE — nothing left to execute on the existing fleet. The `acls.yaml` replication gap that motivated R858-T2 is now moot on us-west-001: the policy lives in headscale.db, which litestream already replicates. Tell R858 it can drop acls.yaml from its failover-state enumeration.")
//! @yah:next("ROLLBACK PATH, if a policy problem surfaces later: /var/lib/yah-cloud/headscale/config.yaml.pre-R861-T3 is the pre-flip config on the box (mode=file + path). Restoring it and killing the kamaji-supervised pid reverts — but acls.yaml is gone, so re-create it from the DB policy (GET /api/v1/policy) first.")
//! @yah:handoff("EXECUTED AGAINST THE LIVE FLEET 2026-09-04 18:53-18:58 PDT by @Ashguard:rune (picked up after session:0c65aeae errored on session limits mid-verification). ONE TARGET, us-west-001, driven with the rehearsed ./target/debug/yah (built 16:55, the same binary T3's dry-run rehearsal used; NOT installed to ~/.local/bin, tree still carries peers' in-flight work). PRE-FLIGHT re-observe matched the rehearsal byte for byte: mode=File{/var/lib/yah-cloud/headscale/acls.yaml}, supervisor=Kamaji{pid 515991}, acls.yaml 77 bytes permissive, served 77 bytes — fail-open gate satisfied. STEP 1 FlipConfigToDatabaseMode: config rewritten (old kept at config.yaml.pre-R861-T3), `sudo kill 515991`, kamaji respawned as pid 517125 serving the same argv. STEP 2 PushCarriedPolicy: re-observe showed mode=Database and `served policy: none (no policy row)` — independent proof the restart really re-read the config, and the fail-open window opened and was closed within one invocation; PUT succeeded with read-back verified. STEP 3 RemoveAclsFile: `sudo rm acls.yaml`, taken only after a read-only run confirmed served policy = 77 bytes and https://cloud.mesh.yah.dev/key?v=138 = 200. FINAL: `next step: Done`, acls.yaml absent, served policy 77 bytes from the DB. `yah mesh status` = api reachable HTTP 200, 10 nodes / 9 online — identical to the pre-migration count (us-west-002 is the known-offline WSL box). No node dropped, no re-auth, zero downtime observed.")
//! @yah:verify("LIVE VERIFICATION, POST-MIGRATION (2026-09-04 18:58 PDT): `yah mesh migrate-policy us-west-001` (read-only) reports policy.mode = Database, supervisor = Kamaji{pid 517125}, acls.yaml = absent, served policy = 77 bytes, next step = Done. `curl https://cloud.mesh.yah.dev/key?v=138` = 200. `yah mesh status` = api reachable (HTTP 200), 10 nodes / 9 online, unchanged from pre-migration. The one target was us-west-001; T3's Phase C enumeration (no other box carries /var/lib/yah-cloud/headscale) was re-confirmed by the migrator's own machine resolution.")

use anyhow::{Context, Result};

use super::policies_equivalent;
use crate::mesh::{HeadscaleClient, POLICY_MODE};

/// Where this module lives, for error messages that want to point a reader at
/// the migration without hardcoding a path in three places.
pub const MODULE_PATH: &str = "cloud::reconciler::headscale::policy_migration";

/// Default on-box location of a coordinator's headscale state.
/// Matches us-west-001 (measured 2026-09-04) and `yubaba::DEFAULT_HEADSCALE_DIR`.
pub const DEFAULT_HEADSCALE_DIR: &str = "/var/lib/yah-cloud/headscale";

/// The `policy` block of a coordinator's `config.yaml`, as headscale reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyMode {
    /// `mode: file` — or no `policy:` block at all, since headscale's viper
    /// default for `policy.mode` is `"file"`.
    File { path: Option<String> },
    /// `mode: database`. The migrated state.
    Database,
    /// Something headscale would `log.Fatal` on at startup. Surfaced rather
    /// than coerced: a coordinator in this state is already broken and the
    /// migration must not paper over it.
    Unrecognised(String),
}

/// What is keeping `headscale serve` alive on the box.
///
/// This is not decoration: `policy.mode` is read once at startup, so the flip
/// is only real after a restart, and the two supervisors restart by completely
/// different means. Guessing produces the worst outcome available — a
/// coordinator still serving the old mode while the config on disk says
/// otherwise and the operator has been told the step succeeded.
///
/// Measured on us-west-001 2026-09-04: `headscale.service` is `inactive` and
/// `disabled`, and the live `headscale serve` is a child of
/// `/usr/local/bin/kamaji`. So [`Supervisor::Kamaji`] is the shape the one live
/// coordinator actually has, and the systemd arm is the fallback path
/// `leader.rs::start_headscale` takes when no kamaji backend is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Supervisor {
    /// `headscale.service` is the active unit. `systemctl restart` is correct.
    Systemd,
    /// kamaji supervises the process as a native workload. Its spec carries
    /// `RestartPolicy::Always` (`yubaba::headscale_appliance::appliance_spec`),
    /// so kamaji's own restart loop respawns the child on exit with the same
    /// argv — which is what re-reads `config.yaml`.
    ///
    /// **`systemctl restart` is actively wrong here.** The unit is disabled, so
    /// it would fork a *second* headscale against the same `0.0.0.0:443`; that
    /// one fails to bind while the kamaji-supervised process keeps serving the
    /// pre-flip config.
    Kamaji { pid: u32 },
    /// The probe could not tell. Emitted as a refusal to act rather than a
    /// guess, because both wrong answers above are silent.
    Unknown,
}

/// Everything the migration needs to know about one coordinator, gathered
/// read-only.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Verbatim contents of the coordinator's `config.yaml`.
    pub config_yaml: String,
    /// Verbatim contents of `acls.yaml`, or `None` if the file is gone.
    pub acls_file: Option<String>,
    /// What `GET /api/v1/policy` returned, or `None` when the coordinator has
    /// no policy to serve. In database mode with no row that GET is an error
    /// (`loading ACL from database: policy not found`), not an empty string —
    /// callers map that error to `None`, which is what it means.
    pub live_policy: Option<String>,
    /// Directory holding `config.yaml` / `acls.yaml` on the box.
    pub headscale_dir: String,
    /// What restarts `headscale serve` here — see [`Supervisor`].
    pub supervisor: Supervisor,
}

impl Observation {
    /// Read the observed `policy.mode`.
    pub fn policy_mode(&self) -> PolicyMode {
        read_policy_mode(&self.config_yaml)
    }
}

/// The one action to take next. Re-derive it after every step; never queue a
/// batch, because each step changes what the correct next one is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Write `config_yaml` back and restart headscale. Carries the rewritten
    /// config so the caller never has to re-derive it.
    FlipConfigToDatabaseMode { config_yaml: String },
    /// `PUT /api/v1/policy` with this document. Only reachable once the
    /// coordinator is in database mode.
    PushCarriedPolicy { hujson: String },
    /// The coordinator serves the carried policy from its database. The file
    /// is now genuinely redundant and can go.
    RemoveAclsFile,
    /// Migrated. Re-running from here changes nothing.
    Done,
    /// The coordinator is in a state this migration refuses to guess at.
    Blocked { reason: String },
}

impl Step {
    /// A one-line name for the step, for plans and progress output.
    ///
    /// [`Step`]'s `Debug` embeds a whole `config.yaml` or policy document, which
    /// is right for a failure message and unreadable in a list of steps.
    pub fn label(&self) -> String {
        match self {
            Step::FlipConfigToDatabaseMode { .. } => {
                "FlipConfigToDatabaseMode (rewrite config.yaml + restart)".to_string()
            }
            Step::PushCarriedPolicy { hujson } => {
                format!(
                    "PushCarriedPolicy (PUT /api/v1/policy, {} bytes)",
                    hujson.len()
                )
            }
            Step::RemoveAclsFile => "RemoveAclsFile (rm acls.yaml)".to_string(),
            Step::Done => "Done".to_string(),
            Step::Blocked { reason } => format!("Blocked: {reason}"),
        }
    }

    /// Shell the operator (or a gated rail) runs on the box for the steps that
    /// are not API calls. Empty for [`Step::PushCarriedPolicy`], which is
    /// driven through [`apply_push`], and for the terminal states.
    ///
    /// The restart line depends on `supervisor` and there is no safe default —
    /// see [`Supervisor`] for why emitting `systemctl restart` against a
    /// kamaji-supervised coordinator is worse than emitting nothing.
    pub fn on_box_commands(&self, headscale_dir: &str, supervisor: &Supervisor) -> Vec<String> {
        match self {
            Step::FlipConfigToDatabaseMode { .. } => {
                let mut cmds = vec![format!(
                    "# write the rewritten config to {headscale_dir}/config.yaml"
                )];
                // Restart, not reload: `policy.mode` is read once, in
                // loadACLPolicy, during startup.
                cmds.extend(restart_commands(supervisor));
                cmds.push(format!("grep -A2 '^policy:' {headscale_dir}/config.yaml"));
                cmds
            }
            Step::RemoveAclsFile => vec![format!("sudo rm {headscale_dir}/acls.yaml")],
            _ => Vec::new(),
        }
    }
}

/// How to make `headscale serve` re-read `config.yaml` under each supervisor.
///
/// [`Supervisor::Unknown`] returns a refusal line rather than a command: a
/// restart aimed at the wrong supervisor either does nothing visible or stands
/// up a second coordinator, and both failure modes look like success.
pub fn restart_commands(supervisor: &Supervisor) -> Vec<String> {
    match supervisor {
        Supervisor::Systemd => vec!["sudo systemctl restart headscale".to_string()],
        // kamaji's native supervisor owns the child and re-execs it per
        // `RestartPolicy::Always`, so ending the process IS the restart. SIGTERM
        // rather than SIGKILL so headscale closes its SQLite handles.
        Supervisor::Kamaji { pid } => vec![
            format!(
                "sudo kill {pid}  # kamaji (RestartPolicy::Always) respawns it with the same argv"
            ),
            // kamaji's ALWAYS_RESTART_DELAY is 1s (kamaji::native), so the new
            // child does not exist for at least that long; 5s leaves headscale
            // time to bind :443 too.
            "sleep 5".to_string(),
            "pgrep -af 'headscale serve' || true  # confirm a NEW pid is serving".to_string(),
        ],
        Supervisor::Unknown => vec![
            "# REFUSING to emit a restart: the supervisor could not be identified.".to_string(),
            "# Determine it first — `systemctl is-active headscale` and the ppid of".to_string(),
            "# `pgrep -af 'headscale serve'` — then re-run. A restart aimed at the".to_string(),
            "# wrong supervisor fails silently or binds a second coordinator to :443.".to_string(),
        ],
    }
}

/// Whether a policy document is the permissive allow-all default
/// ([`crate::mesh::DEFAULT_ACL_POLICY`]), compared semantically rather than
/// byte-wise.
///
/// This is the fail-open gate. The migration necessarily opens a window in
/// which the coordinator has no policy row and therefore compiles
/// `FilterAllowAll`; that is a no-op only when the policy being carried across
/// the window is itself allow-all. On any other document the same window is a
/// silent widening, which a caller must refuse rather than narrate.
pub fn is_permissive(hujson: &str) -> Result<bool> {
    policies_equivalent(hujson, crate::mesh::DEFAULT_ACL_POLICY)
        .context("comparing a policy against the permissive allow-all default")
}

/// Decide the single next action from a read-only observation.
///
/// The ordering is forced by headscale's own behaviour, not chosen:
///
/// 1. **Flip the config first** — `SetPolicy` is refused outright in file mode.
/// 2. **Push immediately after** — the interval in between is allow-all.
/// 3. **Delete `acls.yaml` last** — it is the only copy of the policy until the
///    coordinator serves an equivalent one from its database, so it is what
///    makes an interrupted run resumable.
pub fn next_step(obs: &Observation) -> Result<Step> {
    match obs.policy_mode() {
        PolicyMode::Unrecognised(mode) => {
            return Ok(Step::Blocked {
                reason: format!(
                    "{}/config.yaml declares `policy.mode: {mode}`, which headscale v0.23.0 \
                     rejects at startup (it accepts only \"file\" or \"database\"). Fix that \
                     before migrating anything.",
                    obs.headscale_dir,
                ),
            });
        }
        PolicyMode::File { .. } => {
            let config_yaml = rewrite_to_database_mode(&obs.config_yaml)?;
            return Ok(Step::FlipConfigToDatabaseMode { config_yaml });
        }
        PolicyMode::Database => {}
    }

    // Database mode from here on.
    let Some(carried) = obs.acls_file.as_deref() else {
        // No file left. Whatever the database holds is the whole truth, and
        // there is nothing left to carry or delete.
        return Ok(Step::Done);
    };

    let in_sync = match obs.live_policy.as_deref() {
        // No policy row yet: the coordinator is serving allow-all and the file
        // is the only copy. Always a push, never a delete.
        None => false,
        Some(live) => policies_equivalent(live, carried).with_context(|| {
            format!(
                "comparing the policy {} serves against the carried {}/acls.yaml",
                "the coordinator", obs.headscale_dir,
            )
        })?,
    };

    if in_sync {
        Ok(Step::RemoveAclsFile)
    } else {
        Ok(Step::PushCarriedPolicy {
            hujson: carried.to_string(),
        })
    }
}

/// Whether writes are permitted. An explicit type rather than a `bool`, so a
/// caller cannot arm a live push by getting an argument order wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Execution {
    /// Describe the write; perform nothing.
    DryRun,
    /// Actually `PUT /api/v1/policy`.
    Live,
}

/// Perform the one migration step that is an API call.
///
/// Returns the human-readable account of what happened (or, under
/// [`Execution::DryRun`], what would have). Any other [`Step`] is a no-op here
/// — the on-box steps come back from [`Step::on_box_commands`] instead.
pub async fn apply_push(
    client: &HeadscaleClient,
    step: &Step,
    execution: Execution,
) -> Result<String> {
    let Step::PushCarriedPolicy { hujson } = step else {
        return Ok(format!("no API step to run for {step:?}"));
    };
    match execution {
        Execution::DryRun => Ok(format!(
            "DRY RUN: would PUT /api/v1/policy with {} bytes of HuJSON",
            hujson.len()
        )),
        Execution::Live => {
            client
                .set_policy(hujson)
                .await
                .context("pushing the carried acls.yaml into the coordinator's database")?;
            // Read back through the same comparison the reconciler uses, so a
            // coordinator that accepted the write but stored something else
            // cannot read as success.
            let live = client
                .get_policy()
                .await
                .context("reading the policy back after pushing it")?;
            if !policies_equivalent(&live, hujson)? {
                anyhow::bail!(
                    "the coordinator accepted the policy push but serves a different document \
                     back — refusing to treat this as migrated, and acls.yaml must NOT be deleted"
                );
            }
            Ok("pushed the carried policy and verified the read-back".to_string())
        }
    }
}

/// A rehearsal: drive [`next_step`] to a terminal state over a simulated
/// coordinator, so the whole sequence can be inspected without a live box.
///
/// `advance` applies one step to the observation exactly as the real world
/// would, and returns the next observation.
pub fn rehearse<F>(mut obs: Observation, mut advance: F) -> Result<MigrationPlan>
where
    F: FnMut(&Step, &Observation) -> Observation,
{
    let mut steps = Vec::new();
    // Five is generous: the longest real path is flip -> push -> remove ->
    // done. Anything longer means the state machine is cycling, which is a bug
    // worth failing on rather than looping forever.
    for _ in 0..5 {
        let step = next_step(&obs)?;
        steps.push(step.clone());
        if matches!(step, Step::Done | Step::Blocked { .. }) {
            return Ok(MigrationPlan { steps });
        }
        obs = advance(&step, &obs);
    }
    anyhow::bail!("migration did not converge in 5 steps: {steps:?}")
}

/// Apply one step to an observation the way the real world would, for
/// [`rehearse`].
///
/// This is the honest model of each step's effect, and it is public so an
/// operator rail can rehearse a plan against a *real* observation rather than
/// only against a hand-built one: read the coordinator, then
/// `rehearse(obs, simulate_step)` shows the whole sequence before anything is
/// armed.
pub fn simulate_step(step: &Step, obs: &Observation) -> Observation {
    let mut next = obs.clone();
    match step {
        Step::FlipConfigToDatabaseMode { config_yaml } => {
            next.config_yaml = config_yaml.clone();
            // Restarting in database mode with no row: headscale serves a nil
            // policy, and GET /api/v1/policy errors -> None.
            next.live_policy = None;
        }
        Step::PushCarriedPolicy { hujson } => next.live_policy = Some(hujson.clone()),
        Step::RemoveAclsFile => next.acls_file = None,
        Step::Done | Step::Blocked { .. } => {}
    }
    next
}

/// The ordered steps a [`rehearse`] produced.
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    pub steps: Vec<Step>,
}

impl MigrationPlan {
    /// Whether this migration passes through a window where the coordinator
    /// serves allow-all because the config was flipped before the policy was
    /// pushed.
    ///
    /// True whenever a flip is followed by a push. Harmless when the carried
    /// policy is itself permissive (us-west-001's is); a real, if brief,
    /// widening otherwise — and the operator should know which one they have
    /// before running it, not after.
    pub fn widens_before_push(&self) -> bool {
        self.steps.windows(2).any(|w| {
            matches!(w[0], Step::FlipConfigToDatabaseMode { .. })
                && matches!(w[1], Step::PushCarriedPolicy { .. })
        })
    }

    /// Whether the plan ever removes `acls.yaml` before the coordinator is
    /// serving the policy from its database. Must always be false — this is
    /// the invariant that makes an interrupted run recoverable.
    pub fn deletes_the_file_early(&self) -> bool {
        let remove_at = self.steps.iter().position(|s| *s == Step::RemoveAclsFile);
        let push_at = self
            .steps
            .iter()
            .position(|s| matches!(s, Step::PushCarriedPolicy { .. }));
        match (remove_at, push_at) {
            (Some(r), Some(p)) => r < p,
            _ => false,
        }
    }
}

// ─── config.yaml surgery ─────────────────────────────────────────────────────

/// Read `policy.mode` (and `policy.path`) out of a headscale `config.yaml`.
///
/// Hand-parsed rather than round-tripped through a YAML crate, for two reasons:
/// `serde_yaml` is a dev-dependency of this crate, and a reserialize would
/// reorder and reformat a config a human may have edited on the box. The
/// subset handled is exactly what headscale's own config is: a top-level
/// `policy:` key whose block-mapping children are plain `key: value` scalars.
/// Anything else reads as [`PolicyMode::Unrecognised`] rather than being
/// guessed at.
///
/// A missing `policy:` block is [`PolicyMode::File`] with no path, because
/// that is what headscale does — `viper.SetDefault("policy.mode", "file")`.
pub fn read_policy_mode(config_yaml: &str) -> PolicyMode {
    let Some(block) = policy_block(config_yaml) else {
        return PolicyMode::File { path: None };
    };
    let mut mode = None;
    let mut path = None;
    for line in &config_yaml.lines().collect::<Vec<_>>()[block.first_child..block.end] {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "mode" => mode = Some(value),
            "path" => path = Some(value),
            _ => {}
        }
    }
    match mode.as_deref() {
        None | Some("") | Some("file") => PolicyMode::File { path },
        Some("database") => PolicyMode::Database,
        Some(other) => PolicyMode::Unrecognised(other.to_string()),
    }
}

/// Rewrite a coordinator's `config.yaml` so its policy block reads
/// `mode: database` and carries no `path:`.
///
/// Every other byte is preserved: only the `policy:` block's own lines are
/// replaced, at whatever indentation that block already uses. Idempotent —
/// running it on an already-migrated config returns the same bytes.
///
/// `policy.path` is dropped rather than left in place because headscale reads
/// it only in file mode; a leftover path documents a file that is no longer
/// the source of truth, which is exactly the confusion this ticket exists to
/// remove.
pub fn rewrite_to_database_mode(config_yaml: &str) -> Result<String> {
    let lines: Vec<&str> = config_yaml.lines().collect();
    let trailing_newline = config_yaml.ends_with('\n');

    let Some(block) = policy_block(config_yaml) else {
        // No `policy:` block at all — headscale defaults to file mode, so this
        // config still needs migrating. Append one.
        let mut out = config_yaml.to_string();
        if !out.is_empty() && !trailing_newline {
            out.push('\n');
        }
        out.push_str(&format!("policy:\n  mode: {POLICY_MODE}\n"));
        return Ok(out);
    };

    let indent = block.child_indent.clone();
    let mut out: Vec<String> = lines[..block.first_child]
        .iter()
        .map(|l| l.to_string())
        .collect();
    out.push(format!("{indent}mode: {POLICY_MODE}"));
    // Anything in the block that is neither `mode:` nor `path:` is somebody
    // else's key and is kept — dropping a key this module does not understand
    // would be exactly the silent damage it is supposed to avoid.
    for line in &lines[block.first_child..block.end] {
        let key = line.split_once(':').map(|(k, _)| k.trim()).unwrap_or("");
        if key == "mode" || key == "path" || line.trim().is_empty() {
            continue;
        }
        out.push((*line).to_string());
    }
    out.extend(lines[block.end..].iter().map(|l| l.to_string()));

    let mut rendered = out.join("\n");
    if trailing_newline {
        rendered.push('\n');
    }
    Ok(rendered)
}

/// The `policy:` mapping's extent within a config, in line indices.
struct PolicyBlock {
    /// First line of the block's children (one past the `policy:` line).
    first_child: usize,
    /// One past the block's last child.
    end: usize,
    /// The indentation the children use, reused verbatim on rewrite.
    child_indent: String,
}

fn policy_block(config_yaml: &str) -> Option<PolicyBlock> {
    let lines: Vec<&str> = config_yaml.lines().collect();
    // A top-level key: no leading whitespace, and nothing after the colon.
    let header = lines
        .iter()
        .position(|l| l.trim_end() == "policy:" && !l.starts_with(char::is_whitespace))?;

    let first_child = header + 1;
    let child_indent = lines
        .get(first_child)
        .map(|l| l[..l.len() - l.trim_start().len()].to_string())
        .filter(|i| !i.is_empty())
        // An empty `policy:` block (next line is another top-level key) still
        // needs children written; two spaces is what every renderer emits.
        .unwrap_or_else(|| "  ".to_string());

    let end = lines[first_child..]
        .iter()
        .position(|l| !l.trim().is_empty() && !l.starts_with(char::is_whitespace))
        .map(|offset| first_child + offset)
        .unwrap_or(lines.len());

    Some(PolicyBlock {
        first_child,
        end,
        child_indent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact policy block us-west-001 was measured to carry on 2026-09-04,
    /// embedded in a config shaped like the one `generate_remote_headscale_config`
    /// produced when that box was provisioned.
    fn live_file_mode_config() -> String {
        "---\n\
         server_url: https://cloud.mesh.yah.dev\n\
         listen_addr: 0.0.0.0:443\n\
         database:\n\
         \x20\x20type: sqlite\n\
         \x20\x20sqlite:\n\
         \x20\x20\x20\x20path: /var/lib/yah-cloud/headscale/headscale.db\n\
         policy:\n\
         \x20\x20mode: file\n\
         \x20\x20path: /var/lib/yah-cloud/headscale/acls.yaml\n\
         derp:\n\
         \x20\x20server:\n\
         \x20\x20\x20\x20enabled: false\n"
            .to_string()
    }

    /// us-west-001's live acls.yaml, 77 bytes, measured 2026-09-04.
    const LIVE_ACLS: &str = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#;

    fn observation(config: &str, acls: Option<&str>, live: Option<&str>) -> Observation {
        Observation {
            config_yaml: config.to_string(),
            acls_file: acls.map(str::to_string),
            live_policy: live.map(str::to_string),
            headscale_dir: DEFAULT_HEADSCALE_DIR.to_string(),
            // The shape us-west-001 was measured to have on 2026-09-04.
            supervisor: Supervisor::Kamaji { pid: 515991 },
        }
    }

    #[test]
    fn the_live_config_reads_as_file_mode() {
        assert_eq!(
            read_policy_mode(&live_file_mode_config()),
            PolicyMode::File {
                path: Some("/var/lib/yah-cloud/headscale/acls.yaml".to_string()),
            }
        );
    }

    #[test]
    fn a_config_with_no_policy_block_is_file_mode() {
        // headscale's own default: viper.SetDefault("policy.mode", "file").
        assert_eq!(
            read_policy_mode("---\nserver_url: https://x\n"),
            PolicyMode::File { path: None }
        );
    }

    #[test]
    fn an_unknown_mode_is_surfaced_not_coerced() {
        let cfg = "policy:\n  mode: postgres\n";
        assert_eq!(
            read_policy_mode(cfg),
            PolicyMode::Unrecognised("postgres".to_string())
        );
    }

    #[test]
    fn all_three_renderers_now_emit_database_mode() {
        let dir = std::path::PathBuf::from("/var/lib/yah-cloud/headscale");
        let cloud = crate::mesh::generate_headscale_config("https://mesh.example.com", &dir);
        assert_eq!(read_policy_mode(&cloud), PolicyMode::Database, "{cloud}");
        // yubaba's two renderers live in a crate this one does not depend on,
        // so their outputs are pinned by tests over there. What is asserted
        // here is that the mode string both crates hardcode agrees.
        assert_eq!(POLICY_MODE, "database");
    }

    #[test]
    fn rewriting_the_live_config_flips_the_mode_and_drops_the_path() {
        let out = rewrite_to_database_mode(&live_file_mode_config()).unwrap();
        assert_eq!(read_policy_mode(&out), PolicyMode::Database, "{out}");
        assert!(!out.contains("acls.yaml"), "{out}");
        // Everything else survives, including the sibling `path:` under
        // `database.sqlite` that a careless line-based edit would eat.
        assert!(
            out.contains("server_url: https://cloud.mesh.yah.dev"),
            "{out}"
        );
        assert!(
            out.contains("/var/lib/yah-cloud/headscale/headscale.db"),
            "{out}"
        );
        assert!(out.contains("listen_addr: 0.0.0.0:443"), "{out}");
        assert!(out.contains("enabled: false"), "{out}");
        assert!(out.ends_with('\n'), "{out}");
    }

    #[test]
    fn rewriting_is_idempotent() {
        let once = rewrite_to_database_mode(&live_file_mode_config()).unwrap();
        let twice = rewrite_to_database_mode(&once).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn rewriting_a_config_without_a_policy_block_appends_one() {
        let out = rewrite_to_database_mode("---\nserver_url: https://x\n").unwrap();
        assert_eq!(read_policy_mode(&out), PolicyMode::Database, "{out}");
        assert!(out.contains("server_url: https://x"), "{out}");
    }

    #[test]
    fn rewriting_keeps_a_policy_key_this_module_does_not_understand() {
        let cfg = "policy:\n  mode: file\n  path: /x/acls.yaml\n  something_new: 7\n";
        let out = rewrite_to_database_mode(cfg).unwrap();
        assert!(out.contains("something_new: 7"), "{out}");
        assert!(!out.contains("acls.yaml"), "{out}");
    }

    #[test]
    fn a_file_mode_coordinator_is_told_to_flip_the_config_first() {
        // Not to push: SetPolicy is refused outright in file mode.
        let obs = observation(&live_file_mode_config(), Some(LIVE_ACLS), Some(LIVE_ACLS));
        match next_step(&obs).unwrap() {
            Step::FlipConfigToDatabaseMode { config_yaml } => {
                assert_eq!(read_policy_mode(&config_yaml), PolicyMode::Database);
            }
            other => panic!("expected a config flip, got {other:?}"),
        }
    }

    #[test]
    fn a_database_mode_coordinator_with_no_policy_row_is_pushed_to() {
        let flipped = rewrite_to_database_mode(&live_file_mode_config()).unwrap();
        let obs = observation(&flipped, Some(LIVE_ACLS), None);
        assert_eq!(
            next_step(&obs).unwrap(),
            Step::PushCarriedPolicy {
                hujson: LIVE_ACLS.to_string()
            }
        );
    }

    #[test]
    fn the_file_is_removed_only_once_the_database_serves_it() {
        let flipped = rewrite_to_database_mode(&live_file_mode_config()).unwrap();
        // Same policy, reformatted by headscale's own round trip — semantic
        // comparison, not bytes, so this is in sync.
        let served = "{\n  \"acls\": [\n    { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"] }\n  ]\n}";
        let obs = observation(&flipped, Some(LIVE_ACLS), Some(served));
        assert_eq!(next_step(&obs).unwrap(), Step::RemoveAclsFile);
    }

    #[test]
    fn drift_between_the_file_and_the_database_is_a_push_not_a_delete() {
        let flipped = rewrite_to_database_mode(&live_file_mode_config()).unwrap();
        let served = r#"{"acls":[{"action":"accept","src":["tag:ci"],"dst":["*:22"]}]}"#;
        let obs = observation(&flipped, Some(LIVE_ACLS), Some(served));
        assert!(matches!(
            next_step(&obs).unwrap(),
            Step::PushCarriedPolicy { .. }
        ));
    }

    #[test]
    fn a_migrated_coordinator_is_done_and_stays_done() {
        let flipped = rewrite_to_database_mode(&live_file_mode_config()).unwrap();
        let obs = observation(&flipped, None, Some(LIVE_ACLS));
        assert_eq!(next_step(&obs).unwrap(), Step::Done);
        // A freshly-bootstrapped box: database mode, no file, no policy row.
        let fresh = observation(&flipped, None, None);
        assert_eq!(next_step(&fresh).unwrap(), Step::Done);
    }

    #[test]
    fn an_unrecognised_mode_blocks_instead_of_guessing() {
        let obs = observation("policy:\n  mode: postgres\n", Some(LIVE_ACLS), None);
        match next_step(&obs).unwrap() {
            Step::Blocked { reason } => assert!(reason.contains("postgres"), "{reason}"),
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    /// Apply a step the way the real world would, so [`rehearse`] walks the
    /// same path a live run would.
    /// The production model, exercised here rather than a test-local twin — a
    /// second copy would let the rehearsal an operator sees drift from the one
    /// these tests prove.
    fn simulate(step: &Step, obs: &Observation) -> Observation {
        simulate_step(step, obs)
    }

    #[test]
    fn the_whole_migration_converges_from_the_live_starting_state() {
        let start = observation(&live_file_mode_config(), Some(LIVE_ACLS), Some(LIVE_ACLS));
        let plan = rehearse(start, simulate).unwrap();
        assert!(
            matches!(
                plan.steps.as_slice(),
                [
                    Step::FlipConfigToDatabaseMode { .. },
                    Step::PushCarriedPolicy { .. },
                    Step::RemoveAclsFile,
                    Step::Done,
                ]
            ),
            "{:?}",
            plan.steps
        );
        // The recoverability invariant: never delete the only copy first.
        assert!(!plan.deletes_the_file_early());
        // And the window this ordering opens is reported, not hidden.
        assert!(plan.widens_before_push());
    }

    #[test]
    fn resuming_from_any_midpoint_reaches_the_same_end_state() {
        // Every interruption point is re-derivable from what is on the box,
        // which is the property that makes a half-completed run safe to rerun.
        let flipped = rewrite_to_database_mode(&live_file_mode_config()).unwrap();
        let midpoints = [
            // Interrupted right after the flip, before the push.
            observation(&flipped, Some(LIVE_ACLS), None),
            // Interrupted after the push, before the delete.
            observation(&flipped, Some(LIVE_ACLS), Some(LIVE_ACLS)),
            // Interrupted after the delete: already done.
            observation(&flipped, None, Some(LIVE_ACLS)),
        ];
        for obs in midpoints {
            let plan = rehearse(obs, simulate).unwrap();
            assert_eq!(*plan.steps.last().unwrap(), Step::Done, "{:?}", plan.steps);
            assert!(!plan.deletes_the_file_early(), "{:?}", plan.steps);
        }
    }

    #[test]
    fn the_on_box_steps_restart_rather_than_reload() {
        // policy.mode is read once, in loadACLPolicy, at startup — a SIGHUP
        // would leave the coordinator on the old mode with a config that says
        // otherwise, which is the worst of both.
        let step = Step::FlipConfigToDatabaseMode {
            config_yaml: String::new(),
        };
        let cmds = step.on_box_commands(DEFAULT_HEADSCALE_DIR, &Supervisor::Systemd);
        assert!(cmds
            .iter()
            .any(|c| c.contains("systemctl restart headscale")));
        assert!(!cmds.iter().any(|c| c.contains("reload")));
        assert_eq!(
            Step::RemoveAclsFile.on_box_commands(DEFAULT_HEADSCALE_DIR, &Supervisor::Systemd),
            vec!["sudo rm /var/lib/yah-cloud/headscale/acls.yaml".to_string()]
        );
        // The push is not an on-box command; it goes through apply_push.
        assert!(Step::PushCarriedPolicy {
            hujson: LIVE_ACLS.to_string()
        }
        .on_box_commands(DEFAULT_HEADSCALE_DIR, &Supervisor::Systemd)
        .is_empty());
    }

    #[test]
    fn a_kamaji_supervised_coordinator_is_never_told_to_systemctl_restart() {
        // us-west-001's live shape (measured 2026-09-04): headscale.service is
        // inactive+disabled and the running `headscale serve` is a child of
        // /usr/local/bin/kamaji. `systemctl restart` there forks a SECOND
        // headscale onto the same :443 — it fails to bind while the real one
        // keeps serving the pre-flip config, i.e. a silent no-op dressed as a
        // successful step.
        let cmds = Step::FlipConfigToDatabaseMode {
            config_yaml: String::new(),
        }
        .on_box_commands(DEFAULT_HEADSCALE_DIR, &Supervisor::Kamaji { pid: 515991 });
        assert!(!cmds.iter().any(|c| c.contains("systemctl")), "{cmds:?}");
        assert!(
            cmds.iter().any(|c| c.starts_with("sudo kill 515991")),
            "{cmds:?}"
        );
    }

    #[test]
    fn an_unidentified_supervisor_yields_no_runnable_restart() {
        // Every emitted line is a comment: there is nothing here a rail could
        // execute, which is the intended refusal.
        let cmds = restart_commands(&Supervisor::Unknown);
        assert!(!cmds.is_empty());
        assert!(cmds.iter().all(|c| c.starts_with('#')), "{cmds:?}");
    }

    #[test]
    fn the_live_acls_file_reads_as_permissive_and_a_real_rule_does_not() {
        // The whole fail-open safety argument rests on this comparison.
        assert!(is_permissive(LIVE_ACLS).unwrap());
        assert!(is_permissive(crate::mesh::DEFAULT_ACL_POLICY).unwrap());
        let restrictive = r#"{"acls":[{"action":"accept","src":["tag:dev"],"dst":["tag:dev:*"]}]}"#;
        assert!(!is_permissive(restrictive).unwrap());
    }

    #[tokio::test]
    async fn a_dry_run_push_touches_no_coordinator() {
        // The URL is unroutable on purpose: if DryRun ever performed the PUT,
        // this test would fail with a connection error instead of passing.
        let client = HeadscaleClient::new("http://127.0.0.1:1", "unused".to_string()).unwrap();
        let step = Step::PushCarriedPolicy {
            hujson: LIVE_ACLS.to_string(),
        };
        let out = apply_push(&client, &step, Execution::DryRun).await.unwrap();
        assert!(out.starts_with("DRY RUN"), "{out}");
        assert!(out.contains(&LIVE_ACLS.len().to_string()), "{out}");
        // And a non-push step is a no-op even when execution is Live.
        let out = apply_push(&client, &Step::RemoveAclsFile, Execution::Live)
            .await
            .unwrap();
        assert!(out.contains("no API step"), "{out}");
    }
}
