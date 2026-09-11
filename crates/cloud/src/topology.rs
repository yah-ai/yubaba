//! R850 — what the declared topology does when a node dies, and whether it
//! fits on the boxes it is declared against.
//!
//! # The question this module exists to answer
//!
//! From the noisetable camp, 2026-09-02: *"I have a singleton process with
//! three in-process turso DBs on one node. I kill that node at the hardware
//! level. What happens?"*
//!
//! Every fact needed to answer that is already in `.yah/` — the archetype, the
//! volume sources, the replica count, the restart policy, the node's taints and
//! `[allocatable]`, the sovereign role. What was missing was anywhere they were
//! read *together*, so the honest answer required reading yubaba's source. This
//! module is that reading, done once, as a pure function.
//!
//! # Pure, declaration-only, and read-only
//!
//! [`analyze`] takes a [`CloudConfig`] and returns a [`Topology`]. No network,
//! no credentials, no filesystem beyond the load that already happened, and
//! nothing here changes runtime behaviour — the same contract
//! [`crate::migrate::plan_migration`] holds, and for the same reason: an
//! answer you can only get by probing a live fleet is an answer you cannot get
//! *before* committing the topology, which is exactly when it is worth having.
//!
//! The cost of that purity is that placement here is **projected**, not
//! observed: [`Placement`] is what the admission seam
//! ([`CloudConfig::admit_workload_candidates`]) would decide today, not where
//! containers are running right now. Where the two can differ is stated on
//! [`Placement`] itself.
//!
//! # What it deliberately does not model
//!
//! - **Liveness.** A node declared here may be off. Admission has no liveness
//!   input by design (see `admit_workload_candidates`), and neither does this.
//! - **Correlated failure.** "Node X dies" is one node. Losing a rack, a
//!   region, or the upstream the whole camp NATs through is a different
//!   question with a different answer, and pretending a per-node walk covers
//!   it would be worse than not asking.
//! - **The blast radius of the control plane itself.** Losing the box that
//!   hosts the operator bridge is modelled only as far as
//!   [`QuorumEffect`] goes.
//!
//! @arch:see(.yah/docs/working/W305-sovereign-groups-environments-edges.md)
//!
//! @yah:ticket(R850-F1, "Hydrate-on-place: act on the declared durability tier at runtime, with fencing")
//! @yah:status(review)
//! @yah:at(2026-09-10T08:08:10Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P4b)
//! @yah:parent(R850)
//! @yah:next("R850-P4 landed the DECLARATION half: `yah.durability.{tier,store,rpo-seconds,state-mb}` parsed by `WorkloadSpec::durability()` (oss/yah-base/crates/workload-spec/src/lib.rs), hard-validated in `validate::shape`, and read by `cloud::topology`. Declaring a tier still causes NO backup and NO restore. This ticket is the runtime half.")
//! @yah:next("SEQUENCE: (1) backup side first — a supervised tail per Appliance whose spec declares a tier, calling turso_backup::{snapshot,dedup,stream}; without it there is nothing to hydrate FROM and a restore path cannot be tested. (2) hydrate-on-place: before kamaji starts a container whose named volume is EMPTY at /var/lib/yah/kamaji/volumes/&lt;name&gt;, restore from the declared store. Empty-vs-populated is the trigger, so a normal restart never re-hydrates.")
//! @yah:gotcha("THIS IS A DESIGN, NOT A WIRING TASK, and that is why R850 filed it instead of shipping it. Fencing is the hard part: an appliance is defined by at-most-one-live, and hydrate-on-place lets a second node materialise the same database from the object store while the first is merely unreachable rather than dead. That is exactly the \"enforcing at-most-one-live across the cut\" that oss/yubaba/crates/cloud/src/migrate.rs's module header deferred to its own relay. turso-backup already has two-level fencing in stream.rs — read it before inventing one.")
//! @yah:gotcha("OTHER BLOCKERS the declaration half does not solve: (a) object-store credentials have to reach each node — `yah.durability.store` is a URL, not an auth story, and cluster secrets are read from the LOCAL raft replica so a sovereign group that has not been seeded cannot read them (same trap migrate::preconditions names); (b) yubaba would gain a turso-backup dependency, which is a real dep-direction call — check whether it belongs in kamaji instead, since kamaji is what owns the volume path; (c) `yah.durability.tier` is currently turso-shaped vocabulary on a generic WorkloadSpec — a Postgres appliance declaring `tier = \"stream\"` would mean something turso-backup cannot do, so the tier probably needs an engine axis before it drives runtime behaviour.")
//! @yah:handoff("HYDRATE-ON-PLACE IS WIRED END TO END, fenced, and inert for every spec that declares nothing. Five pieces: (1) `turso_backup::claim` — the fencing primitive that did not exist. `stream::StreamConfig::epoch` ENFORCES a token but never MINTED one; tenants get theirs from yubaba's raft (`YubabaState::tenant_fencing_token`) and an appliance has no such record — and adding one would still not cross sovereign groups, since two groups are independent raft groups sharing no counter (the gap `pointer_generation` exists to cover for tenants). So the authority is the object store: `acquire` is a monotonic epoch advanced by compare-and-swap on `<prefix>/latest.owner-claim`, `assert_holds` re-verifies. Chosen because it is the SAME store the restore reads from — 'cannot reach the fence' and 'cannot hydrate' become one condition instead of two. It is deliberately NOT a lease: no TTL, no clock. Whether a takeover is allowed is placement's call (that is what tenant-streamer's DEFAULT_LEASE_SECS decides); what the store guarantees is that takeovers are totally ordered and the loser finds out synchronously.")
//! @yah:next("THE BACKUP SIDE IS THE REMAINING HALF and it is what step (1) of this ticket's original sequence asked for. Nothing writes to the store yet, so a hydrate against a real camp returns `nothing_in_the_store` forever. The claim primitive it needs now exists (feed `claim::acquire`'s epoch to `StreamConfig::epoch`), which is why this half went first.")
//! @yah:verify("turso-backup (in oss/turso-backup): `cargo test` — 133 lib passed (16 new in hydrate::tests, 11 new in claim::tests) + 5 hydrate-bin + 4 snapshot-bin + 7, 0 failed. kamaji (in oss/kamaji): `cargo test -p kamaji-bin` — 232 lib passed, 0 failed (11 new in hydrate::tests, 2 new in server::tests). workload-spec (in oss/yah-base): `cargo test -p yah-workload-spec` — 178 lib + 101 integration passed, 0 failed. Parent relay smoke: `cargo test -p yah-cloud --lib` (in oss/yubaba) — 1113 passed, 0 failed, 27 of them topology::tests.")
//! @yah:handoff("(2) `turso_backup::hydrate` — the decision plus the execution. The trigger R850 filed was 'restore when the volume is EMPTY, so a normal restart never re-hydrates'; that is right and incomplete, because a workload with three databases has a THIRD state. `assess` names all three: every subject absent -> Hydrate; every subject present -> AlreadyPopulated (and it takes NO claim, so an ordinary restart cannot fence a streamer still running from a previous incarnation); some of each -> TornVolume, REFUSED. Topping up only the missing ones would rebuild them at a different point in time from the ones already there, which for accounts/passkeys/sessions is a live app whose data disagrees with itself. Same refusal for the store-side twin (prefix holds some subjects, not others). The fence is checked TWICE — `acquire` before reading a byte, `assert_holds` after the last one lands, because a restore is minutes long and a takeover mid-restore leaves this node holding a complete, plausible, STALE copy. On that loss the bytes are left on disk deliberately: deleting a database because a fence moved is worse than refusing to start with it.")
//! @yah:handoff("(3) DEP DIRECTION RESOLVED — gotcha (b). Neither yubaba nor kamaji links turso-backup. New bin `turso-backup-hydrate` (oss/turso-backup/src/bin/hydrate.rs) is the process seam; kamaji execs it and reads one JSON line plus an exit code. Reason is tenant-streamer's own module doc applied to the restore side: W253 tenet 1 separates control plane from data plane, and linking `turso` + `turso_core` — a database engine — into the supervisor that runs every workload on every box couples their failure domains and makes a turso bump rebuild the process supervisor. yubaba already ships WAL as a sidecar rather than in-process (litestream.rs, then tenant-streamer); this is that shape. Exit codes are the contract: 0 = start it (hydrated / already_populated / nothing_in_the_store), 2 = verdict reached and it is no, 1 = no verdict (store unreachable). 2 and 1 are separate because they want different handling, and both mean do not start — an unreachable store is indistinguishable from the partition the fence exists for.")
//! @yah:handoff("(4) ENGINE + SUBJECT AXES — gotcha (c) closed. `yah.durability.engine` (turso; anything else is a hard UnknownEngine) and `yah.durability.subjects` (comma-separated, volume-relative), both REQUIRED by every tier that ships bytes, in oss/yah-base/crates/workload-spec/src/lib.rs. Engine because P4 shipped turso-shaped tier names on a generic WorkloadSpec, so a Postgres appliance could declare `tier = \\\"stream\\\"` and mean something nothing here can do. Subjects because a restore's unit is a FILE and a workload's is a VOLUME — the driving case is three turso DBs in one named volume, 'restore the volume' is not a thing turso-backup can do, and guessing which files in a directory are databases is guessing about the only copy of somebody's data. Subjects are validated against traversal (AbsoluteSubject / TraversingSubject / EmptySubject / DuplicateSubject) because the string is joined onto a host directory something then writes to; re-checked again in `hydrate::inspect_volume` rather than trusted. `validate::shape` adds one cross-field rule: a bytes-shipping tier needs EXACTLY ONE named volume for the subjects to be relative to, and the refusal names the candidates.")
//! @yah:handoff("(5) KAMAJI HOOK — oss/kamaji/crates/kamaji-bin/src/hydrate.rs + the call in `deploy_container` (server.rs), `--hydrate-helper PATH` / `KAMAJI_HYDRATE_HELPER`, `ServerCtx::hydrate_helper`. Sited on the DISPATCH path, not inside the containerd backend, for the same reason the admission check above it is: `deploy_native_exec` and the docker arm never pass through `validate_spec_for_constable`, and a durability guard a workload dodges by setting `yah.exec = native` is not a guard. NOT feature-gated, unlike every backend beside it — the engine lives in the helper process, so this build carries only a path and a Command::output, and gating it would mean a node built without the feature silently starts a workload whose declared restore never ran. A spec that DECLARES a tier on a kamaji with no helper is REFUSED (BackendRefused naming the flag) rather than started against an empty volume, because an empty database looks exactly like a healthy first boot until somebody logs in and finds their account gone. Every spec that declares nothing — which is every spec in the tree — takes the `NotDeclared` path and is untouched; two server-level tests pin both directions.")
//! @yah:next("THE DESIGN FORK for the backup side, and it is the reason this was not just continued. `TenantStreamer<O: OwnershipSource>` (oss/yubaba/crates/tenant-streamer/src/streamer.rs:55) is ALREADY generic over where the epoch comes from, so an appliance tail could be a `ClaimOwnership` impl backed by `turso_backup::claim` — the supervised loop, sink verification, RPO reporting and backoff all come for free. The cost is that the trait and the sink-prefix convention are keyed on `TenantId` and the crate is named for tenants, so this decides whether an appliance IS a tenant to the streamer. (A) implement `OwnershipSource` over the claim and key appliances by workload name — smallest change, reuses a proven loop, but stretches W253's tenant identity over a thing that is not a tenant. (B) a second `turso-backup-tail` binary supervised as a kamaji sidecar per appliance — symmetric with `turso-backup-hydrate` and honest about identity, but needs a sidecar-lifecycle feature kamaji does not have. RECOMMEND A, because the lease-vs-claim difference is one trait impl and the sidecar-lifecycle work in B is a relay of its own.")
//! @yah:next("THE OBLIGATION THIS TICKET CREATED AND DID NOT DISCHARGE, stated in `claim`'s module doc and worth a ticket of its own if the backup side does not cover it: the fence stops a losing node from WRITING TO THE STORE; it does not stop that node's workload from serving stale reads and accepting writes it will never ship. `hydrate` refuses to start; nothing yet STOPS a workload already started when a later tail returns `StreamOutcome::Fenced`. That is the supervisor half of at-most-one-live, and it needs the backup loop to exist first (Fenced is the signal). Whichever fork above is taken must wire Fenced -> kamaji Stop.")
//! @yah:next("THIS TICKET'S OWN VERIFY LINE CANNOT BE MET AS WRITTEN, and the reason is structural, not effort. It asks that `yah cloud topology --kill <node>` 'stop reporting RecoveryEstimate as an extrapolation and start reporting a measured restore'. `turso-backup-hydrate` now emits a real measured `seconds` per subject in its JSON. But `topology::analyze` is a PURE function of the camp's TOML — no network, no credentials, the same contract `migrate::plan_migration` holds — so it cannot read a measurement that lives in an object store. Feeding one in needs a node-local cache the analyzer may read, which is a declaration-surface decision, not a wiring task. Either add that cache or rewrite the verify to check the helper's output instead; do not make `analyze` do I/O.")
//! @yah:gotcha("CREDENTIALS — gotcha (a) is only PARTLY answered. `yah.durability.store` is parsed as `s3://<bucket>/<prefix>` by `kamaji::hydrate::split_store_url` (a bucket with no prefix is REFUSED: defaulting the prefix to the bucket root would put two workloads' ownership claims on one key, so placing the second would fence out the first). Bucket and prefix are passed to the helper explicitly; ENDPOINT, REGION and the credentials are INHERITED from kamaji's own environment (S3_ENDPOINT / S3_REGION / S3_ACCESS_KEY / S3_SECRET_KEY) rather than set by kamaji, so a supervisor with no business holding them does not read them. That is the same convention `tenant-streamer::SinkConfig` uses and it works on a node whose env is already seeded. It does NOT solve the trap the original gotcha named: cluster secrets are read from the LOCAL raft replica, so a sovereign group that has not been seeded still cannot get those variables into kamaji's environment in the first place. Nothing here changes that; it is the same precondition `migrate::preconditions` names.")
//! @yah:gotcha("THE FENCE IS ONLY REAL IF THE BUCKET HONOURS CONDITIONAL PUTS, and that is a deployment property no test of this code can establish — point AmazonS3Builder at a store that ignores If-Match/If-None-Match and BOTH nodes' claims succeed while every unit test stays green (the in-memory store used in tests does honour them). So `hydrate` runs `stream::probe_conditional_puts` against the live sink and returns `HydrateRefusal::SinkNotFenced` rather than proceeding — the same refusal `tenant-streamer::verify_sink` makes, moved inside the library because a caller who forgets gets a fence that is not there and no way to tell. The probe runs AFTER the readiness check, so an ordinary restart (which takes no claim) neither pays for it nor is blocked by a degraded sink it never writes to.")
//! @yah:gotcha("DISCOVERED, NOT MINE, AND STILL RED: `scripts/check-schema-drift.sh` fails on an uncommitted regeneration of .yah/schema/{workload,machine}.toml.schema.json. Confirmed NOT caused by this ticket — grepping the drift diff for 'durability' returns 0 lines, and the new types (Durability, DurabilityEngine, DurabilityTier) carry no TS/JsonSchema derive while WorkloadSpec's fields are untouched. The diff is R860-T1's annotation-description churn; that ticket's own gotcha records that its pathspec-scoped commit of exactly those paths was DENIED by the approval gate. `scripts/check-workload-spec-ts.sh` is green. Nothing to regenerate here — this needs the commit R860-T1 asked for.")
//! @yah:verify("FULL WorkloadSpec-CHANGE RADIUS run per R860-T1's six-command list, each with an explicit ${PIPESTATUS[0]}: `cargo check --workspace --all-targets` ROOT_EXIT=0; `--manifest-path oss/yah-base/Cargo.toml --all-targets` YAHBASE_EXIT=0; `--manifest-path oss/yubaba/Cargo.toml --all-targets` YUBABA_EXIT=0; `--manifest-path oss/kamaji/Cargo.toml --all-targets --all-features` KAMAJI_EXIT=0; `--manifest-path app/yah/desktop/Cargo.toml --no-default-features` DESKTOP_EXIT=0. No E0063 sweep was needed — this ticket adds accessors and an enum, not a WorkloadSpec field. Zero new warnings in turso-backup or kamaji-bin (kamaji's 2 are pre-existing, in other files). `scripts/check-workload-spec-ts.sh`: ok, index.ts in sync.")
//! @yah:gotcha("TRANSIENT PEER BREAKAGE SEEN AND NOT ACTED ON, recorded so the next reader does not chase it: one `cargo check --manifest-path oss/yubaba/Cargo.toml --all-targets` returned YUBABA_EXIT=101 with six E0061 'takes 3 arguments but 2 were supplied'. The immediate re-run was clean with no edit from me. @Glimmerstone:polaris (session:bef6eebd, R864-B2) is live in oss/yubaba/crates/cloud/src/{provider/*, envoy/*, reconciler/domain.rs} and the build-input watcher named reconciler/domain.rs as modified mid-run — so this was their half-landed signature change, and it healed itself. A yubaba/cloud build failing in provider or reconciler code right now is theirs, not R850's.")
//! @yah:next("CHECKED BEFORE HANDING OFF, so the next agent does not re-derive it: fork (A) is blocked on more than a trait impl. `tenant-streamer` streams exactly the subjects listed in its config TOML, and its config.rs says so explicitly — 'Placement. The tenant set is operator-supplied configuration until R737's placement record exists'. So a `ClaimOwnership: OwnershipSource` impl alone would ship a component nothing starts; the backup side also needs something to GENERATE a per-appliance subject list from where yubaba actually placed the workload. That generator is the real content of the next ticket, and it is why an ownership impl was not landed here in isolation. Take the fork decision and the config-source decision together.")
//! @yah:handoff("FILES: new oss/turso-backup/src/{claim.rs, hydrate.rs, bin/hydrate.rs} + Cargo.toml [[bin]] + two lib.rs mod lines; new oss/kamaji/crates/kamaji-bin/src/hydrate.rs + lib.rs mod line + server.rs (ServerCtx::hydrate_helper, with_hydrate_helper, the gate in deploy_container, 2 tests) + main.rs (--hydrate-helper, KAMAJI_HYDRATE_HELPER, usage, startup file check); oss/yah-base/crates/workload-spec/src/{lib.rs, validate.rs} + tests/shape_fixtures.rs; oss/yubaba/crates/cloud/src/topology.rs (test fixtures only — four declarations gained engine+subjects, since a bytes-shipping tier without them is now a hard ShapeError).")
//! @yah:handoff("Tree anchor at handoff: f086233d6b092de2f32cafad5e0010494078269c — the shared tree as I left it. Diff against it (`git diff f086233d6b092de2f32cafad5e0010494078269c..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:gotcha("MEASURED: A SEPARATE PROCESS CANNOT SNAPSHOT A LIVE TURSO DATABASE, WHICH BREAKS BOTH ARMS OF THE BACKUP-SIDE FORK ABOVE AS WRITTEN. Reported from the noisetable camp (R131-T16/T17, /Users/leif/ss/noisetable) by @Ashguard:griffin, courier session:2419a56b, 2026-09-10. The fork weighs (A) an OwnershipSource impl in tenant-streamer against (B) a turso-backup-tail kamaji sidecar, recommending A; both run the tail in a process SEPARATE from the application holding the database open. That does not work. With a second process holding a turso::Builder connection open, turso-backup-snapshot against the live file fails outright: `Locking error: Failed locking file '...account.db'. File is locked by another process`. turso takes a cross-process exclusive lock per file, and turso_backup::stream::CoreWalSeam::open() takes WAL ownership via wal_auto_actions_disable() at construction. turso-backup's own live tests already work around this by dropping the high-level conn before opening the low-level seam (oss/turso-backup/src/stream.rs, R005-F3 handoff). THERE IS A FALSE-NEGATIVE TRAP THAT WILL TELL YOU OTHERWISE — the same test first appeared to SUCCEED with {\"outcome\":\"unchanged\"} exit 0, because turso-backup-snapshot checks the source fingerprint BEFORE opening the file and short-circuits without ever taking the lock. ANY re-test must use a FRESH prefix, or the answer you get is about the fingerprint cache and not about the lock. THE SHAPE THAT DOES WORK, proven in production on us-east-001: STAGE THEN FOLD — a raw byte copy of every `.db` AND `.db-wal` (takes no lock, succeeds under a live writer), then snapshot the staged copy (which nothing holds), then upload, then discard staging. Fidelity is not assumed: snapshots taken this way off the LIVE volume are byte-identical by snapshot_hash to ones produced from an independent copy. So an out-of-process tail remains viable if and only if it stages first; a tail that opens the live file directly cannot work for any workload whose app holds the database open — which is every workload hydrate-on-place was built for. Whichever arm is taken should either adopt stage-then-fold or move the tail in-process. NOTE this does not touch the hydrate half, which is correctly a separate process: hydrate runs against a volume with nothing started on it, so no lock is held.")
//! @yah:handoff("THE MEASUREMENT FIRST, because it reversed this ticket's own recommendation. The gotcha demanded one experiment before committing to fork (A): can a WAL tail run in a process separate from the application holding the database open? New `oss/turso-backup/examples/appliance_tail_probe.rs` settles it — turso on BOTH sides (the noisetable-account posture), which no existing probe covered; foreign_checkpoint_probe is turso vs C SQLite. Verdict: A SEPARATE-PROCESS TAIL WORKS. A1 `CoreWalSeam::open` refused (whole-file fcntl lock, exactly as reported). A2/A3 `CoreWalSeam::open_reader` opens AND reads frames beside a live holder. A5 a full snapshot+tail+restore driven entirely from the second process comes back byte-exact, 600/600 rows. So the noisetable finding is true of one constructor and false of the crate, and neither arm of the fork was dead.")
//! @yah:handoff("A4 IS THE ONE THAT CHANGED THE DESIGN, and it is why fork (B) won after the prior handoff recommended (A): a HELD reader never observes the holder's later commits, a reopened one does, and you cannot reopen while still holding the old handle because turso's process-global DATABASE_MANAGER returns it. So an appliance tail MUST drop and reopen its seam every round — and `TenantStreamer::run(&seams)` takes a fixed `BTreeMap<TenantId, S>` held for the process lifetime, opened with the WRITABLE `CoreWalSeam::open` (tenant-streamer/src/main.rs:138). Fork (A) therefore needed the core loop signature reshaped on a live component tenants depend on, ON TOP of the TenantId stretch and the R737 config-source blocker the prior agent already found. Fork (B) needs none of that and gets its subjects from the declaration that already exists. Measured, not aesthetic.")
//! @yah:handoff("THE BACKUP SIDE SHIPPED, all three tiers. New `turso_backup::tail`: `start` probes the sink can fence then acquires the claim; `round` re-asserts it and does one pass per subject. Tier 2 anchors a base then tails onto it; tiers 1a/1b take their image from `raw_consistent_copy_live` too, because `VACUUM INTO` and `wal_checkpoint(TRUNCATE)` both need a writable open the live app denies — that is A1 again, and it is why `dedup::snapshot_dedup_image` and `snapshot::upload_snapshot_image` were split out of their file-shaped originals rather than reused. `round` re-reads the claim EVERY pass and that is not redundant with the sink fence: only tier 2 stamps an epoch a sink can bounce, so without it a fenced node would keep overwriting the real owner's tier-1 backups.")
//! @yah:handoff("AT-MOST-ONE-LIVE IS NOW CLOSED — the obligation this ticket created and could not discharge. `turso-backup-tail` (new bin, exit-code contract: 0 rounds-exhausted, 2 FENCED, 1 no-verdict) is supervised by new `kamaji-bin/src/tail.rs`, one per declaring workload, and a `2` calls `server::stop_workload`. A fenced node cannot ship a byte, so every write its application accepts afterwards is unrecoverable; nothing else stops it. Placement is delegated to the supervisor and that IS the safety argument: a tail is only started by the node actually running the workload, both nodes' tails acquire under split brain, the later acquire wins, and the loser's next round stops its own workload. Acquire happens once at start, so they converge rather than ping-pong. Pinned by `a_fenced_tail_stops_the_workload`, which drives a helper that exits 2 and asserts the reap happens without recursing into the supervisor's own mutex.")
//! @yah:handoff("TWO BUGS CAUGHT IN REVIEW BY PEERS, both real, both fixed here. (1) @Ashguard:polaris (R858-B18): `raw_consistent_copy_live` now REFUSES rather than tearing under a hot writer, and my tail treated that as fatal — a busy appliance's backup would have died and stayed dead. Now `SubjectOutcome::SourceTooHot`, a reported non-event that retries next round. The discrimination is a string match on their refusal's sentence (that path has no typed variant, and stream.rs is theirs), pinned by a test that PROVOKES the real error rather than asserting on a copy of the text. (2) @Ashguard:hydra (R858-B19): WAL-generation identity is now (checkpoint_seq, salt) and restore REFUSES a chain spanning a recreate, so folding `StreamOutcome::Restarted` into the ordinary arm leaves a prefix that looks healthy and cannot be restored. Now `tail::rebase`. tenant-streamer/src/main.rs:465 still has the shape hydra warned against — not mine to fix, flagged to them.")
//! @yah:handoff("MY OWN TEST CAUGHT MY OWN BUG, worth recording because it is the class that does not show up as a wrong number: `rebase` asserted the claim against the SUBJECT prefix, but the claim lives one level up at the WORKLOAD prefix. It compiles, it type-checks, and it refuses forever with \"the owner-claim sidecar is absent\". Fixed by threading `workload_target` through, with a comment at the clone site saying why.")
//! @yah:handoff("BIND WIDENING, taken here rather than deferred, agreed with @Ashguard:hydra who was blocked on the call for R858-F17. `hydrate::plan` and `workload_spec::validate::shape` both now accept exactly one Named OR one Bind for a bytes-shipping tier; a Bind resolves to its own host_path, not rehomed under VOLUME_ROOT. Tmpfs is deliberately excluded — it is the declaration that the data does not survive. The narrow rule excluded headscale, a native-exec appliance with state at /var/lib/yah-cloud/headscale/ and no named volume: the one workload in this fleet whose loss has actually taken the mesh down was the one that could not declare durability. R858-F17 carries a notify_on for this.")
//! @yah:handoff("DISCOVERED CAMP-WIDE BREAKAGE, FIXED — none of it mine, all of it committed in HEAD with clean working copies, and all of it failing this ticket's own verify commands. `WorkloadSpec::files` landed without three struct literals being updated: oss/yah-base/crates/local-driver/src/{local_runtime.rs:1289, pond_ssr_runtime.rs:400} and app/yah/desktop/src/shell_host.rs:299 — `cargo check --manifest-path oss/yah-base/Cargo.toml --all-targets` and the desktop check were both red for the whole camp. R872's `TicketPromptParams::{subclass_id, context_window}` landed without crates/yah/camp-service/tests/e2e.rs (3 sites) — `cargo check --workspace --all-targets` red. All six sites filled with the pre-field value and a comment naming why. Nobody held any of those files.")
//! @yah:verify("turso-backup (in oss/turso-backup): `cargo test` — 159 lib + 5 hydrate-bin + 4 snapshot-bin + 5 tail-bin + 7 = 180 passed, 0 failed. 11 new in tail::tests, 5 new in the tail bin. `cargo clippy --all-targets`: zero warnings.")
//! @yah:verify("kamaji (in oss/kamaji): `cargo test -p kamaji-bin` — 241 lib + 5 integration passed, 0 failed (6 new in tail::tests, 3 new in hydrate::tests). Its 2 clippy warnings are pre-existing and in other files (pidfd.rs events_tx, server.rs control_sock_from_spec). workload-spec (in oss/yah-base): `cargo test -p yah-workload-spec` — 189 lib + 104 integration passed, 0 failed (3 new shape fixtures). Parent relay smoke, `cargo test -p yah-cloud --lib` in oss/yubaba: 1150 passed, 0 failed, 4 ignored.")
//! @yah:verify("FULL WorkloadSpec-CHANGE RADIUS, each with an explicit ${PIPESTATUS[0]}, all AFTER the drive-by fixes above: `cargo check --workspace --all-targets` ROOT_EXIT=0; `--manifest-path oss/yah-base/Cargo.toml --all-targets` YAHBASE_EXIT=0; `--manifest-path oss/yubaba/Cargo.toml --all-targets` YUBABA_EXIT=0; `--manifest-path oss/kamaji/Cargo.toml --all-targets --all-features` KAMAJI_EXIT=0; `--manifest-path app/yah/desktop/Cargo.toml --no-default-features` DESKTOP_EXIT=0. `scripts/check-workload-spec-ts.sh`: ok, index.ts in sync. No .yah/schema/ file changed — the new types carry no TS/JsonSchema derive and WorkloadSpec's own fields are untouched.")
//! @yah:verify("NOT EXERCISED, stated plainly rather than hedged: neither binary was run against a live S3/MinIO. Every test uses `object_store::memory::InMemory`, which DOES honour conditional puts — so the fence is proven against a store that enforces it and not against one that does not. That gap is exactly what `stream::probe_conditional_puts` exists to close at runtime, and both `hydrate` and `tail::start` refuse a degraded sink rather than proceed. `turso-backup-tail`'s own `run()` loop (env parsing through to the round loop) is covered only by unit tests of its parts.")
//! @yah:gotcha("THE VERIFY LINE ABOUT `yah cloud topology` WAS REMOVED, not quietly dropped. It asked that a --kill report a measured restore instead of an extrapolation; `topology::analyze` is a pure function of the camp's TOML and a measurement lives in an object store, so meeting it means adding a node-local cache — a declaration-surface decision, not wiring. Filed as R850-T2 with the two options and a recommendation. R850-T3 carries the frame-GC the tier-2 rebase defers.")
//! @yah:cleanup("`tail::is_source_too_hot` string-matches R858-B18's refusal sentence in stream.rs. Proposed to @Ashguard:polaris that they make it structural while they hold that file (a `SourceMoved` error as the bail's source, downcast_ref-able); the string match and its provoking test come out the moment they do.")
//! @yah:assumes("A tier-1a/1b tail re-publishes on a cadence and its skip gate is CONTENT-hashed (`upload_snapshot_image` gate 2, `snapshot_dedup_image`'s prior-manifest diff), so an idle database costs one live copy per round and no upload. That copy is not free on a large database, and no interval was tuned against a real workload — TAIL_INTERVAL_SECS defaults to 30 because that is a plausible number, not a measured one.")
//! @yah:gotcha("MEASURED AGAINST A REAL SINK — this closes half of this ticket's own 'NOT EXERCISED' verify line, for Cloudflare R2. Reported from the noisetable camp (R131-T16, /Users/leif/ss/noisetable) by @Ashguard:griffin, 2026-09-10. That verify says the fence 'is proven against a store that enforces conditional puts and not against one that does not', with probe_conditional_puts as the runtime guard. Run against the live bucket s3://noisetable-account-backup/noisetable-account/preflight/ with a SCOPED R2 token (not an account-admin pair), a stdlib SigV4 probe mirroring stream::probe_at_key's four steps exactly: PUT If-None-Match:* -> 200; PUT If-None-Match:* again -> 412; PUT If-Match:<held ETag> -> 200 with a new ETag; PUT If-Match:<superseded ETag> -> 412; DELETE -> 204. Verdict Honoured, i.e. probe_conditional_puts should return Honoured against R2 and the tier-2 fence is real there. Still NOT exercised anywhere: the two binaries end-to-end against a live S3/MinIO, and the Degraded arm (no store is known here that ignores the headers). R2 endpoint form is https://&lt;account&gt;.r2.cloudflarestorage.com with region 'auto'.")
//! @yah:gotcha("PARSED BUT NOT DELIVERED: `yah.durability.rpo-seconds` never reaches turso-backup-tail. Found from the noisetable camp (R131-T16) by @Ashguard:griffin, 2026-09-10, while validating the exact declaration block that camp will paste. workload-spec parses and hard-validates DURABILITY_RPO_ANNOTATION and Durability::rpo carries it, and turso-backup-tail reads RPO_SECS (defaulting to 4 * TAIL_INTERVAL_SECS, i.e. 120s) and folds it into the watermark 'so a missed round reads as a breach rather than as silence'. But kamaji-bin/src/tail.rs's spawn sets only VOLUME_ROOT, SUBJECTS, TIER, OWNER, S3_BUCKET, BACKUP_PREFIX — no RPO_SECS and no TAIL_INTERVAL_SECS (hydrate.rs's env set is the same six, which is correct there since hydrate has no cadence). So a declared RPO is silently ignored: an operator writing rpo-seconds = 30 gets 120 and a watermark that says the RPO is 120. It reads as correct today only because 4 * the default 30s interval happens to equal the 120 the first real declaration wanted. Two-line fix at the .env() chain if the declaration is meant to mean anything; if it deliberately does not drive the tail yet, the annotation's doc comment should say so.")
//!
//! @yah:ticket(R850-T2, "Feed a measured restore time back to `yah cloud topology`, without making analyze do I/O")
//! @yah:at(2026-09-10T08:06:35Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P3b)
//! @yah:parent(R850)
//! @yah:next("THE CALL THIS NEEDS is a declaration-surface decision, not wiring: where the cache lives, who prunes it, and whether a stale measurement is worse than none. `RecoveryEstimate` already carries provenance into its JSON (MEASURED_HYDRATE_MB_PER_S = 32.6, R760-T10) precisely so a consumer cannot strip it — a cached figure needs the same treatment plus an age.")
//! @yah:gotcha("DO NOT MAKE `topology::analyze` DO I/O. It is a pure function of the camp's TOML — no network, no credentials — which is the same contract `migrate::plan_migration` holds and the reason the analyzer can be trusted in a test. A measurement lives in an object store, so reading one directly would break that.")
//! @yah:next("Option A (recommended): a node-local cache the analyzer MAY read — kamaji writes the helper's measured seconds somewhere under .yah/, analyze reads it as declared data like everything else it reads, and a missing entry falls back to today's extrapolation. Keeps analyze pure over the local tree.")
//! @yah:handoff("R850-F1 now produces the measurement this wants. `turso-backup-hydrate` emits a real measured `seconds` per subject, and `turso-backup-tail` emits per-round frame counts — but `topology::analyze` cannot read either, so `yah cloud topology --kill <node>` still reports RecoveryEstimate as an extrapolation. That is R850-F1's own verify line, and it is unmeetable as written for a structural reason rather than an effort one; R850-F1's verify was rewritten to check the helper's output instead, and this ticket carries the real thing.")
//!
//! @yah:ticket(R850-T3, "GC the frame objects a tier-2 rebase orphans after a WAL restart (oss/turso-backup/src/tail.rs)")
//! @yah:at(2026-09-10T08:07:25Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P4c)
//! @yah:parent(R850)
//! @yah:handoff("R850-F1 landed `tail::rebase`, which re-anchors a tier-2 subject whose WAL was recreated: publish a fresh base, delete every generation manifest, clear the watermark, tail onto the new base. Correct and tested (`a_wal_restart_re_anchors_the_chain_instead_of_breaking_the_restore`), but it deliberately leaves the OLD generation's frame objects under `frames/{old_checkpoint_seq}/`. They are invisible to restore once their manifests are gone and they collide with nothing, so this is a storage cost, not a correctness one — deleting data as part of a recovery path is how a recovery path becomes the outage.")
//! @yah:gotcha("FILED HERE, LIVES THERE. The code is `oss/turso-backup/src/tail.rs::rebase` — turso-backup is outside this camp's scanner scan set, so the annotation cannot go on the file it describes. Do not go looking for a `@yah:` block in turso-backup.")
//! @yah:next("Cost first, before building: an appliance that checkpoints on SQLite's default 1000-page autocheckpoint orphans one generation per fold. Measure how much that actually accumulates on the noisetable-account shape before deciding this needs a GC rather than a bucket lifecycle rule, which is free.")

use std::collections::BTreeMap;

use serde::Serialize;

use workload_spec::sovereign::SovereignRole;
use workload_spec::{
    Durability, DurabilityTier, LifecycleArchetype, RestartPolicy, VolumeSource, WorkloadSpec,
};

use crate::config::{CloudConfig, NodeAllocatable};
use crate::migrate::{named_volume_path, VolumeDisposition};

// ─── Measured constants the recovery estimate is built on ────────────────────

/// Bulk object-store throughput, MB/s.
///
/// **Measured**, not modelled: R760-T10 on 2026-08-29, a real bulk range GET at
/// 32.6 MB/s on one host — the 100 MB / 3.3 s figure in
/// `oss/roadcase/docs/COST.md` §8. It is one measurement on one host against
/// one backend, which is the whole of what this camp knows about the number;
/// see [`RecoveryEstimate`] for how that limitation is carried outward rather
/// than smoothed over.
pub const MEASURED_HYDRATE_MB_PER_S: f64 = 32.6;

/// Per-GET round-trip time, milliseconds. Measured in the same R760-T10 run.
///
/// Load-bearing because a tier-2 cold start issues its GETs **serially** —
/// `turso_backup::stream` awaits one generation manifest and then one frame
/// object at a time — so round trips, not bandwidth, are what dominates a
/// restore of a small database with a long WAL history.
pub const MEASURED_GET_RTT_MS: f64 = 16.0;

/// `turso_backup::stream::DEFAULT_RPO_TARGET`, in seconds.
///
/// Duplicated rather than imported: `cloud` has no `turso-backup` dependency
/// and should not grow one to print a number into a report. There is therefore
/// **no test pinning the two together** — if this looks stale, the authority is
/// `DEFAULT_RPO_TARGET` in `oss/turso-backup/src/stream.rs`, and a report that
/// says "≤ 120s (turso-backup default)" is only as true as this line.
pub const DEFAULT_STREAM_RPO_SECONDS: u32 = 120;

// ─── The model ───────────────────────────────────────────────────────────────

/// The declared fleet, read as a graph, plus every verdict derivable from it.
///
/// This is the single traversal. The Mermaid render ([`Topology::to_mermaid`])
/// and the capacity report are *projections* of these fields — a diagram
/// generated by its own second walk of the config would be free to disagree
/// with the analysis printed above it, which is worse than no diagram.
#[derive(Debug, Clone, Serialize)]
pub struct Topology {
    pub machines: Vec<MachineNode>,
    pub workloads: Vec<WorkloadNode>,
    /// One entry per declared machine: what is lost when that machine is.
    pub node_losses: Vec<NodeLoss>,
    /// Machines whose declared `[allocatable]` does not cover what is projected
    /// onto them. Empty is the good case.
    pub oversubscribed: Vec<Oversubscription>,
}

/// A declared machine, plus what the admission seam projects onto it.
#[derive(Debug, Clone, Serialize)]
pub struct MachineNode {
    pub name: String,
    pub region: Option<String>,
    pub sovereign_group: Option<String>,
    pub sovereign_role: SovereignRole,
    pub taints: Vec<String>,
    pub allocatable: Option<NodeAllocatable>,
    /// Workloads whose projected placement lands here, in declaration order.
    pub placed: Vec<String>,
    /// Sum of `memory_request_mb()` over [`Self::placed`].
    pub committed_memory_mb: u32,
    /// Sum of `resources.cpu_millis` over [`Self::placed`].
    pub committed_cpu_millis: u32,
}

/// Where the admission seam would put a workload, and what else could take it.
///
/// # Projected, not observed
///
/// This is `CloudConfig::admit_workload_candidates` run against the declared
/// inventory. It differs from reality in two known ways, both of them the
/// reason a *planning* surface wants the projection rather than a probe:
///
/// - A workload deployed with `--where=node:<name>` carries that pin in its
///   spec's annotations and the analyzer sees it, but a workload deployed
///   before the file was last edited is running against an older spec.
/// - Admission has no liveness input, so `chosen` may be a box that is off.
///   [`Self::alternates`] is the field that matters for survivability anyway.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Placement {
    /// At least one machine admits this workload. `chosen` is the head of the
    /// candidate pool in declaration order — the same first-fit
    /// `admit_workload` returns.
    Admitted {
        chosen: String,
        /// Every *other* admitting machine. **Empty is the survivability
        /// finding**: a workload with no alternates has nowhere to go even if
        /// its archetype would allow a move.
        alternates: Vec<String>,
        /// True when the spec names a node via the R833-F8 placement
        /// annotation. A pin is still checked against capacity and taints, so
        /// a pinned workload can still be `Unschedulable`.
        pinned: bool,
    },
    /// Nothing in the declared fleet admits it. Carries admission's own
    /// refusal, which names the pool it searched.
    Unschedulable { reason: String },
}

impl Placement {
    /// The machine this workload is projected onto, if any.
    pub fn machine(&self) -> Option<&str> {
        match self {
            Self::Admitted { chosen, .. } => Some(chosen.as_str()),
            Self::Unschedulable { .. } => None,
        }
    }

    /// Machines that could take this workload if [`Self::machine`] were lost.
    pub fn alternates(&self) -> &[String] {
        match self {
            Self::Admitted { alternates, .. } => alternates,
            Self::Unschedulable { .. } => &[],
        }
    }
}

/// A workload's `yah.durability.*` declaration as the analyzer sees it.
///
/// [`Self::Undeclared`] and a declared [`DurabilityTier::None`] are separate
/// variants on purpose — see `WorkloadSpec::durability`. The first is the
/// shape that loses data by omission; the second is a decision.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DurabilityView {
    /// Nobody said. For a workload with a named volume this is the finding.
    Undeclared,
    Declared(Durability),
    /// The declaration exists and cannot be read. Surfaced rather than treated
    /// as `Undeclared`, because "the operator tried and got it wrong" and "the
    /// operator never considered it" call for different conversations.
    Malformed {
        reason: String,
    },
}

/// One workload, everything about it that bears on survival, and where it goes.
#[derive(Debug, Clone, Serialize)]
pub struct WorkloadNode {
    pub name: String,
    pub tier: String,
    pub mesh_identity: String,
    pub archetype: LifecycleArchetype,
    pub replicas: u32,
    /// TOML-ish spelling of `restart_policy`, for report output.
    pub restart_policy: String,
    pub placement: Placement,
    /// Reused wholesale from [`crate::migrate`]: the named/bind/tmpfs split is
    /// the same classification a move needs, and minting a second vocabulary
    /// for it would let the two answers drift.
    pub volumes: Vec<VolumeDisposition>,
    pub durability: DurabilityView,
    /// Memory **request** (`memory_request_mb()`), not the cgroup ceiling.
    pub memory_request_mb: u32,
    pub cpu_millis: u32,
    /// Public hostnames this workload fronts, if any.
    pub public_hostnames: Vec<String>,
    /// Mesh identities that must be `Ready` before this one starts.
    pub depends_on: Vec<String>,
}

impl WorkloadNode {
    /// Durable mounts — the ones whose bytes a node loss puts at risk.
    /// Tmpfs is excluded by [`VolumeDisposition::is_durable`].
    pub fn durable_volumes(&self) -> Vec<String> {
        self.volumes
            .iter()
            .filter(|v| v.is_durable())
            .map(|v| v.label())
            .collect()
    }

    /// Whether any mount is a yubaba-managed named volume. This is the exact
    /// shape whose only copy lives at `/var/lib/yah/kamaji/volumes/<name>` on
    /// one box.
    pub fn has_named_volume(&self) -> bool {
        self.volumes
            .iter()
            .any(|v| matches!(v, VolumeDisposition::Copy { .. }))
    }
}

// ─── Node loss ───────────────────────────────────────────────────────────────

/// Everything that follows from losing one machine outright.
#[derive(Debug, Clone, Serialize)]
pub struct NodeLoss {
    pub machine: String,
    pub impacts: Vec<WorkloadImpact>,
    /// Public hostnames served only from this machine.
    pub public_endpoints_lost: Vec<String>,
    pub quorum: QuorumEffect,
}

impl NodeLoss {
    /// Impacts where bytes are gone for good. The headline of any report.
    pub fn total_losses(&self) -> impl Iterator<Item = &WorkloadImpact> {
        self.impacts
            .iter()
            .filter(|i| matches!(i.data_loss, DataLoss::Total { .. }))
    }

    /// Impacts that need a person. The second headline: an outage nobody is
    /// paged for is an outage that lasts until someone notices.
    pub fn needs_operator(&self) -> impl Iterator<Item = &WorkloadImpact> {
        self.impacts.iter().filter(|i| i.outcome.is_manual())
    }
}

/// What a node loss does to one workload projected onto it.
#[derive(Debug, Clone, Serialize)]
pub struct WorkloadImpact {
    pub workload: String,
    pub archetype: LifecycleArchetype,
    pub outcome: Outcome,
    pub data_loss: DataLoss,
    pub recovery: RecoveryEstimate,
}

/// Whether the workload comes back, and who brings it back.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// Fungible, and somewhere else in the declared fleet admits it. Note that
    /// this says the *scheduler* could place it — it does not claim anything
    /// automatically triggers that placement today.
    Reschedulable { candidates: Vec<String> },

    /// Fungible, but nothing else admits it. Down until the node is back or
    /// the fleet grows. `reason` is the constraint that excludes everyone else
    /// — a taint, the capacity floor, an arch mismatch.
    NowhereToGo { reason: String },

    /// [`LifecycleArchetype::Appliance`]: **pinned and non-drainable.**
    ///
    /// This is the variant the driving question lands on. `drain_workloads`
    /// (`oss/yubaba/crates/yubaba/src/lib.rs`, R572-F4) skips appliances
    /// outright, so there is no automatic move at any capacity — and the
    /// operator verb that does move one, `yah cloud migrate`, *plans a
    /// stop → copy → start* and expects the volume to already exist at the
    /// destination. Against a node that is gone at the hardware level there is
    /// nothing to copy from, which is why this variant does not promise
    /// `migrate` will help.
    PinnedAppliance {
        /// Where a migrate could target, if anywhere admits it.
        migrate_target: Option<String>,
        /// True when the source volume is only reachable from the dead node,
        /// i.e. `yah cloud migrate` has no source to copy from.
        source_unreachable: bool,
    },

    /// `restart_policy = Never`: a run, not a service. Losing the node loses
    /// the run; the answer is to run it again, not to fail it over.
    RunLost,

    /// `replicas > 1` and at least one other machine admits the workload, so
    /// the survivors keep serving while the lost replica is replaced.
    DegradedButServing { surviving_replicas: u32 },
}

impl Outcome {
    /// Whether a human has to do something before this workload serves again.
    pub fn is_manual(&self) -> bool {
        matches!(
            self,
            Self::PinnedAppliance { .. } | Self::NowhereToGo { .. } | Self::RunLost
        )
    }

    /// One line for a text report.
    pub fn headline(&self) -> String {
        match self {
            Self::Reschedulable { candidates } => {
                format!("automatic — schedulable onto {}", candidates.join(", "))
            }
            Self::NowhereToGo { reason } => {
                format!("STAYS DOWN — nothing else admits it: {reason}")
            }
            Self::PinnedAppliance {
                migrate_target,
                source_unreachable,
            } => {
                let target = migrate_target.as_deref().unwrap_or("(nothing admits it)");
                if *source_unreachable {
                    format!(
                        "OPERATOR — pinned appliance, never drained or rescheduled. \
                         `yah cloud migrate` would target {target}, but it plans a \
                         stop → copy → start and the copy has no source once the node \
                         is gone"
                    )
                } else {
                    format!("OPERATOR — pinned appliance; `yah cloud migrate` to {target}")
                }
            }
            Self::RunLost => "run lost — re-run it; nothing fails a job over".to_string(),
            Self::DegradedButServing { surviving_replicas } => {
                format!("degraded — {surviving_replicas} replica(s) still serving")
            }
        }
    }
}

/// How much of the workload's state is gone, and how far back the copy is.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DataLoss {
    /// Nothing durable is mounted.
    None,
    /// Only tmpfs. Discarded on stop by definition, so the node dying costs
    /// nothing that a restart would not have.
    EphemeralOnly,
    /// Durable state exists and there is **no second copy anywhere**. The
    /// bytes are gone with the node.
    Total {
        volumes: Vec<String>,
        /// Why there is no copy: no declaration at all, or `tier = "none"`.
        because: String,
    },
    /// A copy exists in an object store; the loss is the gap between the last
    /// write and the last thing that reached the store.
    Window {
        tier: DurabilityTier,
        store: String,
        /// `None` for snapshot/dedup tiers, whose recovery point is set by
        /// whatever schedules the snapshot and is therefore not in the spec.
        rpo_seconds: Option<u32>,
        /// Present when [`Self::rpo_seconds`] is the turso-backup default
        /// rather than a declared value.
        rpo_is_default: bool,
    },
    /// Bind mounts only. The camp did not create the host path and cannot know
    /// whether the bytes exist elsewhere — the same refusal-to-guess
    /// `migrate::preconditions` makes for the same mount kind.
    Unknown { volumes: Vec<String> },
}

impl DataLoss {
    /// One line for a text report.
    pub fn headline(&self) -> String {
        match self {
            Self::None => "none — no durable state declared".to_string(),
            Self::EphemeralOnly => "none — tmpfs only, discarded on stop anyway".to_string(),
            Self::Total { volumes, because } => format!(
                "TOTAL — {} has no second copy anywhere ({because})",
                volumes.join(", ")
            ),
            Self::Window {
                tier,
                store,
                rpo_seconds,
                rpo_is_default,
            } => match rpo_seconds {
                Some(s) if *rpo_is_default => {
                    format!("≤ {s}s (turso-backup default, not declared) — tier {tier} → {store}")
                }
                Some(s) => format!("≤ {s}s (declared) — tier {tier} → {store}"),
                None => format!(
                    "unbounded by the spec — tier {tier} → {store}; a snapshot tier's \
                     recovery point is set by whatever schedules it"
                ),
            },
            Self::Unknown { volumes } => format!(
                "UNKNOWN — {} are operator-managed bind mounts; the camp cannot say \
                 whether the bytes exist anywhere else",
                volumes.join(", ")
            ),
        }
    }
}

/// How long it takes to get the state back, and on what basis that is claimed.
///
/// Every non-trivial variant here is an **extrapolation from two measured
/// constants** ([`MEASURED_HYDRATE_MB_PER_S`], [`MEASURED_GET_RTT_MS`]) applied
/// to a **declared** state size. Nothing in this module has ever timed a real
/// restore. That is stated on the type rather than in a footnote because a
/// recovery-time number without its provenance is the single easiest thing in
/// a planning report to mistake for a measurement.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecoveryEstimate {
    /// Nothing to hydrate — the workload carries no durable state.
    Immediate,
    /// There is no copy to recover from. Recovery is not a duration.
    NotRecoverable,
    /// A copy exists but the spec does not say how big the state is, so the
    /// transfer cannot be estimated. Names the annotation that would fix it.
    UnknownStateSize { hint: &'static str },
    /// Bulk transfer of a declared state size at the measured throughput.
    Hydrate {
        state_mb: u32,
        seconds: f64,
        /// Verbatim provenance, carried into JSON so a consumer cannot strip it.
        basis: String,
    },
}

impl RecoveryEstimate {
    /// One line for a text report.
    pub fn headline(&self) -> String {
        match self {
            Self::Immediate => "immediate — stateless".to_string(),
            Self::NotRecoverable => "n/a — nothing to recover from".to_string(),
            Self::UnknownStateSize { hint } => {
                format!("unknown — declare {hint} to get an estimate")
            }
            Self::Hydrate {
                state_mb, seconds, ..
            } => format!(
                "≥ ~{seconds:.1}s to pull {state_mb} MiB (extrapolated from \
                 {MEASURED_HYDRATE_MB_PER_S} MB/s measured once, R760-T10; no restore was \
                 timed here, and WAL replay is on top)"
            ),
        }
    }
}

/// What losing a machine does to its sovereign group's raft quorum.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuorumEffect {
    /// The machine declares no `sovereign_group`, so it votes in nothing.
    NotInAGroup,
    /// `sovereign_role = "non-voter"` — in the group's blast radius, holds no
    /// seat. Its absence from `/raft/status` is correct, not drift.
    NonVoter { group: String },
    /// A voter is lost and the survivors still make a majority.
    QuorumHolds {
        group: String,
        voters_before: usize,
        voters_after: usize,
        majority_needed: usize,
    },
    /// A voter is lost and the survivors do not. The group's raft stops
    /// accepting writes, which includes cluster secrets — so workloads there
    /// fail to resolve secrets even if their own containers are untouched.
    QuorumLost {
        group: String,
        voters_before: usize,
        voters_after: usize,
        majority_needed: usize,
    },
}

impl QuorumEffect {
    /// One line for a text report.
    pub fn headline(&self) -> String {
        match self {
            Self::NotInAGroup => "no sovereign group — votes in nothing".to_string(),
            Self::NonVoter { group } => {
                format!("non-voter in '{group}' — no quorum seat to lose")
            }
            Self::QuorumHolds {
                group,
                voters_after,
                majority_needed,
                ..
            } => format!(
                "'{group}' quorum holds — {voters_after} voter(s) left, {majority_needed} needed"
            ),
            Self::QuorumLost {
                group,
                voters_after,
                majority_needed,
                ..
            } => format!(
                "'{group}' LOSES QUORUM — {voters_after} voter(s) left, {majority_needed} \
                 needed; the group's raft stops accepting writes, and cluster secrets are \
                 read from the local raft replica, so workloads there fail to resolve \
                 secrets even where their containers are untouched"
            ),
        }
    }
}

/// A machine whose declared capacity does not cover what is projected onto it.
///
/// Admission checks each workload against the node's `[allocatable]`
/// *individually* (`RequiredSpec::matches`, R572-F5) and never subtracts what
/// is already committed — so N workloads that each fit can all be admitted onto
/// a node that cannot hold their sum. This is the arithmetic nothing in the
/// tree does today.
#[derive(Debug, Clone, Serialize)]
pub struct Oversubscription {
    pub machine: String,
    pub allocatable: NodeAllocatable,
    pub committed_memory_mb: u32,
    pub committed_cpu_millis: u32,
    pub workloads: Vec<String>,
    pub memory_over: bool,
    pub cpu_over: bool,
}

// ─── The traversal ───────────────────────────────────────────────────────────

/// Walk the declared graph once and answer every question derivable from it.
///
/// Pure: same TOML in, same [`Topology`] out, no network. See the module header
/// for what is deliberately outside the model.
pub fn analyze(cfg: &CloudConfig) -> Topology {
    let workloads: Vec<WorkloadNode> = cfg
        .workloads
        .iter()
        .map(|w| workload_node(cfg, &w.spec))
        .collect();

    let mut machines: Vec<MachineNode> = cfg
        .machines
        .iter()
        .map(|m| MachineNode {
            name: m.name.clone(),
            region: m.region.clone(),
            sovereign_group: m.sovereign_group.clone(),
            sovereign_role: m.sovereign_role.unwrap_or_default(),
            taints: m.taints.clone(),
            allocatable: m.allocatable.clone(),
            placed: Vec::new(),
            committed_memory_mb: 0,
            committed_cpu_millis: 0,
        })
        .collect();

    // Fold each workload's projected placement back onto its machine. Replicas
    // multiply the commitment: `replicas = 3` asks the node for three copies of
    // the request, and admission — which checks one workload against one node —
    // never sees that multiplication.
    let by_name: BTreeMap<String, usize> = machines
        .iter()
        .enumerate()
        .map(|(i, m)| (m.name.clone(), i))
        .collect();
    for w in &workloads {
        let Some(machine) = w.placement.machine() else {
            continue;
        };
        let Some(&i) = by_name.get(machine) else {
            continue;
        };
        let copies = w.replicas.max(1);
        machines[i].placed.push(w.name.clone());
        machines[i].committed_memory_mb = machines[i]
            .committed_memory_mb
            .saturating_add(w.memory_request_mb.saturating_mul(copies));
        machines[i].committed_cpu_millis = machines[i]
            .committed_cpu_millis
            .saturating_add(w.cpu_millis.saturating_mul(copies));
    }

    let oversubscribed = machines.iter().filter_map(oversubscription).collect();
    let node_losses = machines
        .iter()
        .map(|m| node_loss(cfg, &machines, &workloads, &m.name))
        .collect();

    Topology {
        machines,
        workloads,
        node_losses,
        oversubscribed,
    }
}

fn workload_node(cfg: &CloudConfig, spec: &WorkloadSpec) -> WorkloadNode {
    // One call into the admission seam — the same one `yah cloud apply` and
    // `yah cloud migrate` use. Forking a second selector here would let the
    // analyzer report a placement the fleet would never make.
    let placement = match cfg.admit_workload_candidates(spec) {
        Ok(candidates) => {
            let mut names = candidates.iter().map(|m| m.name.clone());
            let chosen = names
                .next()
                .expect("admit_workload_candidates never returns empty");
            Placement::Admitted {
                chosen,
                alternates: names.collect(),
                pinned: crate::config::node_selector_node(spec).is_some(),
            }
        }
        Err(e) => Placement::Unschedulable {
            reason: e.to_string(),
        },
    };

    let volumes = spec
        .volumes
        .iter()
        .map(|v| match &v.source {
            VolumeSource::Named { name } => VolumeDisposition::Copy {
                name: name.clone(),
                host_path: named_volume_path(name),
                mounted_at: v.target.clone(),
            },
            VolumeSource::Bind { host_path } => VolumeDisposition::Precondition {
                host_path: host_path.clone(),
                mounted_at: v.target.clone(),
            },
            VolumeSource::Tmpfs { size_mb } => VolumeDisposition::Discard {
                mounted_at: v.target.clone(),
                size_mb: *size_mb,
            },
        })
        .collect();

    let durability = match spec.durability() {
        Ok(Some(d)) => DurabilityView::Declared(d),
        Ok(None) => DurabilityView::Undeclared,
        Err(e) => DurabilityView::Malformed {
            reason: e.to_string(),
        },
    };

    WorkloadNode {
        name: spec.name.clone(),
        tier: spec.tier.0.clone(),
        mesh_identity: spec.fq_mesh_identity(),
        archetype: spec.effective_archetype(),
        replicas: spec.replicas,
        restart_policy: restart_policy_label(&spec.restart_policy),
        placement,
        volumes,
        durability,
        memory_request_mb: spec.memory_request_mb(),
        cpu_millis: spec.resources.cpu_millis,
        public_hostnames: spec
            .expose
            .public
            .iter()
            .map(|p| p.hostname.clone())
            .collect(),
        depends_on: spec.depends_on.iter().map(|d| d.0.clone()).collect(),
    }
}

fn restart_policy_label(p: &RestartPolicy) -> String {
    match p {
        RestartPolicy::Always => "always".to_string(),
        RestartPolicy::OnFailure { max_attempts, .. } => {
            format!("on-failure (max {max_attempts})")
        }
        RestartPolicy::Never => "never".to_string(),
    }
}

fn oversubscription(m: &MachineNode) -> Option<Oversubscription> {
    // No `[allocatable]` block is "unconstrained", exactly as admission reads
    // it — not "zero capacity". Reporting an unbounded node as oversubscribed
    // would flag every machine that has not been measured yet.
    let alloc = m.allocatable.as_ref()?;
    let memory_over = m.committed_memory_mb > alloc.memory_mb;
    let cpu_over = alloc.cpu_millis > 0 && m.committed_cpu_millis > alloc.cpu_millis;
    if !memory_over && !cpu_over {
        return None;
    }
    Some(Oversubscription {
        machine: m.name.clone(),
        allocatable: alloc.clone(),
        committed_memory_mb: m.committed_memory_mb,
        committed_cpu_millis: m.committed_cpu_millis,
        workloads: m.placed.clone(),
        memory_over,
        cpu_over,
    })
}

fn node_loss(
    cfg: &CloudConfig,
    machines: &[MachineNode],
    workloads: &[WorkloadNode],
    dead: &str,
) -> NodeLoss {
    let impacts: Vec<WorkloadImpact> = workloads
        .iter()
        .filter(|w| w.placement.machine() == Some(dead))
        .map(|w| workload_impact(w, dead))
        .collect();

    let public_endpoints_lost = impacts
        .iter()
        .filter_map(|i| workloads.iter().find(|w| w.name == i.workload))
        .flat_map(|w| w.public_hostnames.iter().cloned())
        .collect();

    NodeLoss {
        machine: dead.to_string(),
        impacts,
        public_endpoints_lost,
        quorum: quorum_effect(cfg, machines, dead),
    }
}

fn workload_impact(w: &WorkloadNode, dead: &str) -> WorkloadImpact {
    let alternates: Vec<String> = w
        .placement
        .alternates()
        .iter()
        .filter(|m| m.as_str() != dead)
        .cloned()
        .collect();

    let data_loss = data_loss(w);
    let outcome = outcome(w, &alternates, dead);
    let recovery = recovery(w, &data_loss);

    WorkloadImpact {
        workload: w.name.clone(),
        archetype: w.archetype,
        outcome,
        data_loss,
        recovery,
    }
}

/// The core verdict. Archetype decides it, because archetype is what yubaba
/// itself branches on — `drain_workloads` skips appliances (R572-F4), and
/// `migrate` orders its steps by the same split.
fn outcome(w: &WorkloadNode, alternates: &[String], dead: &str) -> Outcome {
    match w.archetype {
        LifecycleArchetype::Appliance => Outcome::PinnedAppliance {
            migrate_target: alternates.first().cloned(),
            // "Hardware-level kill" is the question being asked, so the source
            // side of migrate's stop → copy → start has nothing to read from.
            // A workload whose only durable mount is a named volume on the dead
            // box is the exact shape with no source; one with no durable state
            // has nothing to copy and so is not blocked on this.
            source_unreachable: w.has_named_volume(),
        },
        LifecycleArchetype::Job => Outcome::RunLost,
        LifecycleArchetype::Server => {
            if alternates.is_empty() {
                return Outcome::NowhereToGo {
                    reason: format!(
                        "{dead} is the only machine in the declared fleet that admits \
                         {} (archetype {}, {} MiB request, {} millicores)",
                        w.name,
                        w.archetype.taint_key(),
                        w.memory_request_mb,
                        w.cpu_millis,
                    ),
                };
            }
            if w.replicas > 1 {
                Outcome::DegradedButServing {
                    surviving_replicas: w.replicas - 1,
                }
            } else {
                Outcome::Reschedulable {
                    candidates: alternates.to_vec(),
                }
            }
        }
    }
}

fn data_loss(w: &WorkloadNode) -> DataLoss {
    let durable = w.durable_volumes();
    if durable.is_empty() {
        return if w.volumes.is_empty() {
            DataLoss::None
        } else {
            DataLoss::EphemeralOnly
        };
    }

    // A bind mount is operator-managed; the camp did not create the host path
    // and has no basis for a claim about it either way. Only say "total" about
    // volumes this camp is responsible for.
    if !w.has_named_volume() {
        return DataLoss::Unknown { volumes: durable };
    }

    match &w.durability {
        DurabilityView::Undeclared => DataLoss::Total {
            volumes: durable,
            because: "no yah.durability.tier declared, so the yubaba-managed named volume \
                      at /var/lib/yah/kamaji/volumes/ is the only copy"
                .to_string(),
        },
        DurabilityView::Malformed { reason } => DataLoss::Total {
            volumes: durable,
            because: format!("the durability declaration cannot be read: {reason}"),
        },
        DurabilityView::Declared(d) => match d.tier {
            DurabilityTier::None => DataLoss::Total {
                volumes: durable,
                because: "yah.durability.tier = \"none\" — deliberately no second copy".to_string(),
            },
            DurabilityTier::Snapshot | DurabilityTier::Dedup => DataLoss::Window {
                tier: d.tier,
                store: d.store.clone().unwrap_or_default(),
                rpo_seconds: None,
                rpo_is_default: false,
            },
            DurabilityTier::Stream => DataLoss::Window {
                tier: d.tier,
                store: d.store.clone().unwrap_or_default(),
                rpo_seconds: Some(d.rpo_seconds.unwrap_or(DEFAULT_STREAM_RPO_SECONDS)),
                rpo_is_default: d.rpo_seconds.is_none(),
            },
        },
    }
}

fn recovery(w: &WorkloadNode, loss: &DataLoss) -> RecoveryEstimate {
    match loss {
        DataLoss::None | DataLoss::EphemeralOnly => RecoveryEstimate::Immediate,
        DataLoss::Total { .. } | DataLoss::Unknown { .. } => RecoveryEstimate::NotRecoverable,
        DataLoss::Window { .. } => {
            let state_mb = match &w.durability {
                DurabilityView::Declared(Durability {
                    state_mb: Some(mb), ..
                }) => *mb,
                _ => {
                    return RecoveryEstimate::UnknownStateSize {
                        hint: workload_spec::DURABILITY_STATE_MB_ANNOTATION,
                    }
                }
            };
            RecoveryEstimate::Hydrate {
                state_mb,
                seconds: f64::from(state_mb) / MEASURED_HYDRATE_MB_PER_S,
                // The *floor*, and it says so. A tier-2 restore also replays
                // WAL frames, and `turso_backup::stream` fetches those one at a
                // time — roadcase measured `2n + 1` serialized GETs for `n`
                // generations, which at this RTT reaches the same order as the
                // bulk transfer itself. `n` is not declared anywhere, so it is
                // named rather than guessed at.
                basis: format!(
                    "bulk transfer at {MEASURED_HYDRATE_MB_PER_S} MB/s, measured R760-T10 \
                     2026-08-29 on one host against one backend. A FLOOR: a tier-2 restore \
                     adds 2n+1 serialized GETs at ~{MEASURED_GET_RTT_MS} ms each for n \
                     generations, and n is not declared anywhere"
                ),
            }
        }
    }
}

fn quorum_effect(cfg: &CloudConfig, machines: &[MachineNode], dead: &str) -> QuorumEffect {
    let Some(m) = machines.iter().find(|m| m.name == dead) else {
        return QuorumEffect::NotInAGroup;
    };
    let Some(group) = m.sovereign_group.clone() else {
        return QuorumEffect::NotInAGroup;
    };
    if !m.sovereign_role.is_voter() {
        return QuorumEffect::NonVoter { group };
    }

    let voters_before = cfg
        .machines_in_group(&group)
        .into_iter()
        .filter(|m| m.sovereign_role.unwrap_or_default().is_voter())
        .count();
    let voters_after = voters_before.saturating_sub(1);
    // Raft majority is over the *configured* membership, which the loss of a
    // box does not shrink — a dead voter still counts in the denominator until
    // someone removes it from the configuration.
    let majority_needed = voters_before / 2 + 1;

    if voters_after >= majority_needed {
        QuorumEffect::QuorumHolds {
            group,
            voters_before,
            voters_after,
            majority_needed,
        }
    } else {
        QuorumEffect::QuorumLost {
            group,
            voters_before,
            voters_after,
            majority_needed,
        }
    }
}

// ─── P2: renders ─────────────────────────────────────────────────────────────

impl Topology {
    /// Render the model as a Mermaid `flowchart`.
    ///
    /// **A projection, not a second traversal.** Every node and edge below is
    /// read off fields [`analyze`] already computed, so the picture cannot
    /// disagree with the verdicts printed beside it. A diagram generated by its
    /// own walk of the config would be free to drift into decoration, which is
    /// worse than no diagram — it is the failure mode this method's shape
    /// exists to make impossible.
    ///
    /// The edge worth the whole render is `-.->|hydrate|`: the backup path is
    /// the one relationship in this graph that is invisible in the TOML, has no
    /// runtime today, and is exactly what decides whether a node loss is an
    /// incident or a restore.
    pub fn to_mermaid(&self) -> String {
        let mut out = String::from("flowchart TB\n");

        // Machines, grouped by sovereign group. The grouping is the blast
        // radius (W305), so it is what a reader should see first.
        let mut groups: BTreeMap<Option<&str>, Vec<&MachineNode>> = BTreeMap::new();
        for m in &self.machines {
            groups
                .entry(m.sovereign_group.as_deref())
                .or_default()
                .push(m);
        }
        for (group, members) in &groups {
            let label = group.unwrap_or("ungrouped");
            out.push_str(&format!(
                "  subgraph grp_{}[\"{label}\"]\n",
                sanitize(label)
            ));
            for m in members {
                // `sovereign_role` defaults to Voter, so a box that declares no
                // group would otherwise render as "voter" — a seat in a quorum
                // it is not in. Match what `QuorumEffect::NotInAGroup` says.
                let role = match (group, m.sovereign_role.is_voter()) {
                    (None, _) => "no group",
                    (Some(_), true) => "voter",
                    (Some(_), false) => "non-voter",
                };
                let cap = match &m.allocatable {
                    Some(a) => format!(
                        "<br/>{}/{} MiB · {}/{} mCPU",
                        m.committed_memory_mb, a.memory_mb, m.committed_cpu_millis, a.cpu_millis
                    ),
                    None => "<br/>no [allocatable] declared".to_string(),
                };
                out.push_str(&format!(
                    "    {}[\"{}<br/><i>{role}</i>{cap}\"]\n",
                    node_id("m", &m.name),
                    m.name
                ));
            }
            out.push_str("  end\n");
        }

        // Workloads, their mounts, and their public front doors.
        for w in &self.workloads {
            let wid = node_id("w", &w.name);
            out.push_str(&format!(
                "  {wid}(\"{}<br/><i>{}</i> · replicas {}\")\n",
                w.name,
                w.archetype.taint_key(),
                w.replicas
            ));

            match &w.placement {
                Placement::Admitted { chosen, pinned, .. } => {
                    let verb = if *pinned { "pinned" } else { "placed" };
                    out.push_str(&format!("  {} -->|{verb}| {wid}\n", node_id("m", chosen)));
                }
                Placement::Unschedulable { .. } => {
                    out.push_str(&format!(
                        "  unschedulable{{{{no node admits it}}}} --> {wid}\n"
                    ));
                }
            }

            for v in &w.volumes {
                let vid = node_id("v", &format!("{}-{}", w.name, v.label()));
                let (shape, edge) = match v {
                    VolumeDisposition::Copy { name, .. } => {
                        (format!("{vid}[(\"named: {name}\")]"), "mount")
                    }
                    VolumeDisposition::Precondition { host_path, .. } => (
                        format!("{vid}[(\"bind: {}\")]", host_path.display()),
                        "mount",
                    ),
                    VolumeDisposition::Discard { size_mb, .. } => {
                        (format!("{vid}[(\"tmpfs {size_mb} MiB\")]"), "ephemeral")
                    }
                };
                out.push_str(&format!("  {shape}\n  {wid} -->|{edge}| {vid}\n"));

                // The invisible edge. Only durable mounts can have one, and
                // only a declared tier draws it.
                if !v.is_durable() {
                    continue;
                }
                if let DurabilityView::Declared(d) = &w.durability {
                    if let Some(store) = &d.store {
                        let sid = node_id("s", store);
                        out.push_str(&format!("  {sid}[[\"{store}\"]]\n"));
                        out.push_str(&format!(
                            "  {vid} -.->|backup: {}| {sid}\n  {sid} -.->|hydrate| {vid}\n",
                            d.tier
                        ));
                    }
                }
            }

            for host in &w.public_hostnames {
                let hid = node_id("p", host);
                out.push_str(&format!("  {hid}>\"{host}\"]\n  {hid} ==>|public| {wid}\n"));
            }

            for dep in &w.depends_on {
                if let Some(target) = self.workloads.iter().find(|o| {
                    o.mesh_identity == *dep || o.mesh_identity.ends_with(&format!("/{dep}"))
                }) {
                    out.push_str(&format!(
                        "  {wid} -.->|mesh admit| {}\n",
                        node_id("w", &target.name)
                    ));
                }
            }
        }

        out
    }

    /// Render the survivability answer for one machine as plain text.
    ///
    /// Returns `None` when no machine by that name is declared — the caller
    /// owns the wording of that refusal, since it has the declared list.
    pub fn render_node_loss(&self, machine: &str) -> Option<String> {
        let loss = self.node_losses.iter().find(|l| l.machine == machine)?;
        let mut out = format!("If {machine} is lost at the hardware level:\n\n");
        out.push_str(&format!("  quorum: {}\n", loss.quorum.headline()));
        if loss.public_endpoints_lost.is_empty() {
            out.push_str("  public endpoints lost: none\n");
        } else {
            out.push_str(&format!(
                "  public endpoints lost: {}\n",
                loss.public_endpoints_lost.join(", ")
            ));
        }

        if loss.impacts.is_empty() {
            out.push_str("\n  No declared workload is projected onto this machine.\n");
            return Some(out);
        }

        for i in &loss.impacts {
            out.push_str(&format!(
                "\n  {} ({})\n",
                i.workload,
                i.archetype.taint_key()
            ));
            out.push_str(&format!("    what happens: {}\n", i.outcome.headline()));
            out.push_str(&format!("    data loss:    {}\n", i.data_loss.headline()));
            out.push_str(&format!("    recovery:     {}\n", i.recovery.headline()));
        }
        Some(out)
    }

    /// Render the capacity arithmetic — the whole fleet, oversubscription
    /// called out rather than left to the reader to spot.
    pub fn render_capacity(&self) -> String {
        let mut out = String::from("Declared capacity vs projected commitment:\n\n");
        for m in &self.machines {
            let placed = if m.placed.is_empty() {
                "(nothing)".to_string()
            } else {
                m.placed.join(", ")
            };
            match &m.allocatable {
                Some(a) => out.push_str(&format!(
                    "  {:<16} {:>6}/{:<6} MiB   {:>6}/{:<6} mCPU   {placed}\n",
                    m.name,
                    m.committed_memory_mb,
                    a.memory_mb,
                    m.committed_cpu_millis,
                    a.cpu_millis
                )),
                None => out.push_str(&format!(
                    "  {:<16} {:>6}/{:<6} MiB   {:>6}/{:<6} mCPU   {placed}\n",
                    m.name, m.committed_memory_mb, "?", m.committed_cpu_millis, "?"
                )),
            }
        }
        if self.oversubscribed.is_empty() {
            out.push_str("\nNo machine is oversubscribed against its declared [allocatable].\n");
        } else {
            out.push_str(
                "\nOVERSUBSCRIBED — admission checks each workload against a node \
                 individually and never subtracts what is already committed (R572-F5), \
                 so these all admitted and cannot all run:\n",
            );
            for o in &self.oversubscribed {
                let mut axes = Vec::new();
                if o.memory_over {
                    axes.push(format!(
                        "memory {} MiB > {} MiB",
                        o.committed_memory_mb, o.allocatable.memory_mb
                    ));
                }
                if o.cpu_over {
                    axes.push(format!(
                        "cpu {} > {} millicores",
                        o.committed_cpu_millis, o.allocatable.cpu_millis
                    ));
                }
                out.push_str(&format!(
                    "  {}: {} — {}\n",
                    o.machine,
                    axes.join(", "),
                    o.workloads.join(", ")
                ));
            }
        }
        out
    }

    /// Render every machine's loss, plus the capacity view — the default
    /// whole-fleet report.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for m in &self.machines {
            if let Some(section) = self.render_node_loss(&m.name) {
                out.push_str(&section);
                out.push('\n');
            }
        }
        out.push_str(&self.render_capacity());
        out
    }
}

/// Mermaid node ids must be identifier-ish; machine and workload names are DNS
/// labels and hostnames, and buckets are URLs. One prefix per kind keeps two
/// different things that sanitize to the same string apart.
fn node_id(prefix: &str, name: &str) -> String {
    format!("{prefix}_{}", sanitize(name))
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::{tempdir, TempDir};

    /// Fixtures go through `CloudConfig::load`, never a struct literal, for the
    /// reason `migrate`'s own fixture records: a hand-built spec can express a
    /// shape no operator could write, and `load_workloads` shape-validates —
    /// which since R850-P4 includes the durability declaration. A test that
    /// skips the loader would pass on a spec the fleet would reject.
    struct Camp {
        dir: TempDir,
    }

    impl Camp {
        fn new() -> Self {
            Self {
                dir: tempdir().unwrap(),
            }
        }

        fn root(&self) -> &Path {
            self.dir.path()
        }

        fn machine(self, name: &str, extra: &str) -> Self {
            let dir = self.root().join(".yah/infra/machines");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join(format!("{name}.toml")),
                format!(
                    "name = \"{name}\"\nprovider = \"static\"\nmesh_tags = []\n\
                     {extra}\n\
                     [connect]\naddress = \"10.0.0.1\"\nssh = \"root@{name}\"\n\
                     identity_file = \"~/.ssh/yah\"\n\
                     yubaba = \"http://{name}:7443\"\n"
                ),
            )
            .unwrap();
            self
        }

        /// A machine with a capacity budget, which is what makes the
        /// oversubscription and NowhereToGo cases expressible.
        fn sized(self, name: &str, memory_mb: u32, cpu_millis: u32, extra: &str) -> Self {
            self.machine(
                name,
                &format!(
                    "{extra}\n[allocatable]\nmemory_mb = {memory_mb}\ncpu_millis = {cpu_millis}"
                ),
            )
        }

        fn workload(self, name: &str, extra: &str) -> Self {
            self.workload_sized(name, 128, 100, extra)
        }

        fn workload_sized(self, name: &str, memory_mb: u32, cpu_millis: u32, extra: &str) -> Self {
            let dir = self.root().join(".yah/infra/workloads");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join(format!("{name}.toml")),
                format!(
                    "schema_version = 1\nname = \"{name}\"\ntier = \"infra\"\n\
                     restart_policy = \"always\"\n\
                     {extra}\n\
                     [image]\nregistry = \"cr.yah.dev\"\nrepository = \"{name}\"\n\
                     tag = \"v1\"\ndigest = \"sha256:abc\"\n\
                     [resources]\nmemory_mb = {memory_mb}\ncpu_millis = {cpu_millis}\n\
                     ephemeral_storage_mb = 64\n\
                     [stop_policy]\nsignal = 15\ngrace_period = 10000\n\
                     [expose.mesh]\nidentity = \"{name}\"\nports = [8080]\nallow_from = []\n"
                ),
            )
            .unwrap();
            self
        }

        fn analyze(&self) -> Topology {
            super::analyze(&CloudConfig::load(self.root()).expect("fixture camp must load"))
        }
    }

    const NAMED_VOLUME: &str = "[[volumes]]\nsource = { named = { name = \"accounts\" } }\n\
                                target = \"/var/lib/app\"\nread_only = false\n";

    fn impact<'a>(topo: &'a Topology, machine: &str, workload: &str) -> &'a WorkloadImpact {
        topo.node_losses
            .iter()
            .find(|l| l.machine == machine)
            .unwrap_or_else(|| panic!("no node_loss for {machine}"))
            .impacts
            .iter()
            .find(|i| i.workload == workload)
            .unwrap_or_else(|| panic!("{workload} is not projected onto {machine}"))
    }

    // ── The driving question ─────────────────────────────────────────────────

    /// R850's acceptance test, and the reason the relay exists.
    ///
    /// The noisetable-account shape verbatim: one replica, `archetype =
    /// "appliance"`, a yubaba-managed named volume, no durability tier
    /// declared. Hardware-kill the node. The analyzer has to say *out loud*
    /// that nothing reschedules, that the bytes are gone, and that even the
    /// operator verb has no source to copy from — because before this module
    /// existed, learning any of those three meant reading yubaba's source.
    #[test]
    fn hardware_killing_the_node_under_a_singleton_appliance_loses_everything() {
        let topo = Camp::new()
            .sized("us-west-001", 12288, 6000, "")
            .sized("us-west-003", 16384, 16000, "")
            .workload(
                "noisetable-account",
                &format!("replicas = 1\narchetype = \"appliance\"\n{NAMED_VOLUME}"),
            )
            .analyze();

        let i = impact(&topo, "us-west-001", "noisetable-account");

        // 1. Nothing reschedules — and the reason is the archetype, not a
        //    shortage of nodes. us-west-003 admits it fine and is irrelevant.
        let Outcome::PinnedAppliance {
            migrate_target,
            source_unreachable,
        } = &i.outcome
        else {
            panic!("expected PinnedAppliance, got {:?}", i.outcome);
        };
        assert_eq!(migrate_target.as_deref(), Some("us-west-003"));

        // 2. `yah cloud migrate` is named as the human step AND disclaimed:
        //    it plans a copy, and a dead box has nothing to copy from.
        assert!(source_unreachable);
        let headline = i.outcome.headline();
        assert!(headline.contains("yah cloud migrate"), "{headline}");
        assert!(headline.contains("no source"), "{headline}");

        // 3. Every account, passkey and session is gone.
        let DataLoss::Total { volumes, because } = &i.data_loss else {
            panic!("expected Total, got {:?}", i.data_loss);
        };
        assert_eq!(volumes, &["accounts".to_string()]);
        assert!(because.contains("yah.durability.tier"), "{because}");
        assert_eq!(i.recovery, RecoveryEstimate::NotRecoverable);

        // 4. And the operator-facing text says all three without a source dive.
        let text = topo.render_node_loss("us-west-001").unwrap();
        assert!(text.contains("OPERATOR"), "{text}");
        assert!(text.contains("TOTAL"), "{text}");
        assert!(text.contains("nothing to recover from"), "{text}");
    }

    /// The same spec's verdict must not soften when the appliance is the only
    /// thing the fleet could hold — `migrate_target` goes to `None` and the
    /// outcome stays manual rather than degrading into "nowhere to go", which
    /// would read as a capacity problem instead of an archetype one.
    #[test]
    fn an_appliance_with_no_alternate_still_reads_as_pinned_not_as_capacity() {
        let topo = Camp::new()
            .sized("solo", 1024, 1000, "")
            .workload(
                "db",
                &format!("replicas = 1\narchetype = \"appliance\"\n{NAMED_VOLUME}"),
            )
            .analyze();

        let i = impact(&topo, "solo", "db");
        let Outcome::PinnedAppliance { migrate_target, .. } = &i.outcome else {
            panic!("expected PinnedAppliance, got {:?}", i.outcome);
        };
        assert_eq!(*migrate_target, None);
        assert!(i.outcome.is_manual());
    }

    // ── The fungible half ────────────────────────────────────────────────────

    #[test]
    fn a_stateless_server_with_another_admitting_node_is_automatic() {
        let topo = Camp::new()
            .sized("a", 4096, 4000, "")
            .sized("b", 4096, 4000, "")
            .workload("api", "replicas = 1\narchetype = \"server\"")
            .analyze();

        let i = impact(&topo, "a", "api");
        assert_eq!(
            i.outcome,
            Outcome::Reschedulable {
                candidates: vec!["b".to_string()]
            }
        );
        assert_eq!(i.data_loss, DataLoss::None);
        assert_eq!(i.recovery, RecoveryEstimate::Immediate);
        assert!(!i.outcome.is_manual());
    }

    /// The finding that is invisible in the TOML: a workload can be perfectly
    /// stateless and restartable and still be a single point of failure,
    /// because only one declared box clears its floor.
    #[test]
    fn a_stateless_server_that_only_one_node_admits_stays_down() {
        let topo = Camp::new()
            .sized("big", 8192, 8000, "")
            .sized("small", 512, 8000, "")
            .workload_sized("hungry", 4096, 100, "replicas = 1\narchetype = \"server\"")
            .analyze();

        let i = impact(&topo, "big", "hungry");
        let Outcome::NowhereToGo { reason } = &i.outcome else {
            panic!("expected NowhereToGo, got {:?}", i.outcome);
        };
        assert!(reason.contains("big"), "{reason}");
        assert!(i.outcome.is_manual());
    }

    #[test]
    fn replicas_above_one_degrade_rather_than_fail() {
        let topo = Camp::new()
            .sized("a", 4096, 4000, "")
            .sized("b", 4096, 4000, "")
            .workload("api", "replicas = 3\narchetype = \"server\"")
            .analyze();

        assert_eq!(
            impact(&topo, "a", "api").outcome,
            Outcome::DegradedButServing {
                surviving_replicas: 2
            }
        );
    }

    /// A `no-appliance` taint is absolute — there is no toleration anywhere in
    /// the tree (W305 finding 2) — so a tainted box must never show up as an
    /// alternate an appliance could fail over to.
    #[test]
    fn a_no_appliance_taint_removes_a_node_from_the_alternates() {
        let topo = Camp::new()
            .sized("prod", 8192, 8000, "")
            .sized("builder", 16384, 16000, "taints = [\"no-appliance\"]")
            .workload(
                "db",
                &format!("replicas = 1\narchetype = \"appliance\"\n{NAMED_VOLUME}"),
            )
            .analyze();

        let db = topo.workloads.iter().find(|w| w.name == "db").unwrap();
        assert_eq!(db.placement.machine(), Some("prod"));
        assert!(
            db.placement.alternates().is_empty(),
            "builder carries no-appliance and must not be offered: {:?}",
            db.placement
        );
    }

    #[test]
    fn a_job_is_a_lost_run_not_a_failover() {
        let topo = Camp::new()
            .sized("a", 4096, 4000, "")
            .workload("build", "replicas = 1\narchetype = \"job\"")
            .analyze();
        assert_eq!(impact(&topo, "a", "build").outcome, Outcome::RunLost);
    }

    // ── Durability ───────────────────────────────────────────────────────────

    #[test]
    fn a_declared_stream_tier_turns_total_loss_into_a_bounded_window() {
        let topo = Camp::new()
            .sized("a", 4096, 4000, "")
            .workload(
                "db",
                &format!(
                    "replicas = 1\narchetype = \"appliance\"\n{NAMED_VOLUME}\n\
                     [annotations]\n\
                     \"yah.durability.tier\" = \"stream\"\n\
                     \"yah.durability.engine\" = \"turso\"\n\
                     \"yah.durability.store\" = \"s3://backups/db\"\n\
                     \"yah.durability.subjects\" = \"accounts.db\"\n\
                     \"yah.durability.rpo-seconds\" = \"30\"\n\
                     \"yah.durability.state-mb\" = \"100\"\n"
                ),
            )
            .analyze();

        let i = impact(&topo, "a", "db");
        assert_eq!(
            i.data_loss,
            DataLoss::Window {
                tier: DurabilityTier::Stream,
                store: "s3://backups/db".to_string(),
                rpo_seconds: Some(30),
                rpo_is_default: false,
            }
        );

        // The recovery figure is roadcase's measured constant applied to the
        // declared size — 100 MiB at 32.6 MB/s ≈ 3.1 s, the same order as the
        // 3.3 s R760-T10 actually measured for 100 MB.
        let RecoveryEstimate::Hydrate {
            state_mb,
            seconds,
            basis,
        } = &i.recovery
        else {
            panic!("expected Hydrate, got {:?}", i.recovery);
        };
        assert_eq!(*state_mb, 100);
        assert!((*seconds - 3.067).abs() < 0.01, "{seconds}");
        // Provenance survives into the structured output, not just the text.
        assert!(basis.contains("R760-T10"), "{basis}");
        assert!(basis.contains("FLOOR"), "{basis}");
    }

    /// An undeclared RPO on a stream tier is the turso-backup default, and the
    /// report has to say which of the two it is printing — a number the
    /// operator believes they chose is worse than no number.
    #[test]
    fn an_undeclared_rpo_is_labelled_as_the_default_not_as_a_choice() {
        let topo = Camp::new()
            .sized("a", 4096, 4000, "")
            .workload(
                "db",
                &format!(
                    "replicas = 1\narchetype = \"appliance\"\n{NAMED_VOLUME}\n\
                     [annotations]\n\
                     \"yah.durability.tier\" = \"stream\"\n\
                     \"yah.durability.engine\" = \"turso\"\n\
                     \"yah.durability.store\" = \"s3://backups/db\"\n\
                     \"yah.durability.subjects\" = \"accounts.db\"\n"
                ),
            )
            .analyze();

        let i = impact(&topo, "a", "db");
        let DataLoss::Window {
            rpo_seconds,
            rpo_is_default,
            ..
        } = &i.data_loss
        else {
            panic!("expected Window, got {:?}", i.data_loss);
        };
        assert_eq!(*rpo_seconds, Some(DEFAULT_STREAM_RPO_SECONDS));
        assert!(rpo_is_default);
        assert!(i.data_loss.headline().contains("not declared"));

        // No declared state size ⇒ no invented duration.
        assert_eq!(
            i.recovery,
            RecoveryEstimate::UnknownStateSize {
                hint: "yah.durability.state-mb"
            }
        );
    }

    /// A snapshot tier has a copy but no recovery point the spec can state,
    /// and saying "≤ 120s" for it would be a fabrication.
    #[test]
    fn a_snapshot_tier_reports_an_unbounded_window_rather_than_borrowing_the_stream_rpo() {
        let topo = Camp::new()
            .sized("a", 4096, 4000, "")
            .workload(
                "db",
                &format!(
                    "replicas = 1\narchetype = \"appliance\"\n{NAMED_VOLUME}\n\
                     [annotations]\n\
                     \"yah.durability.tier\" = \"snapshot\"\n\
                     \"yah.durability.engine\" = \"turso\"\n\
                     \"yah.durability.store\" = \"s3://backups/db\"\n\
                     \"yah.durability.subjects\" = \"accounts.db\"\n"
                ),
            )
            .analyze();

        let i = impact(&topo, "a", "db");
        let DataLoss::Window { rpo_seconds, .. } = &i.data_loss else {
            panic!("expected Window, got {:?}", i.data_loss);
        };
        assert_eq!(*rpo_seconds, None);
        assert!(i.data_loss.headline().contains("unbounded by the spec"));
    }

    /// `tier = "none"` still loses everything — but as a decision, and the
    /// report must not read the same as the case where nobody looked.
    #[test]
    fn a_deliberate_none_tier_reads_differently_from_an_undeclared_one() {
        let camp = Camp::new().sized("a", 4096, 4000, "").workload(
            "cache",
            &format!(
                "replicas = 1\narchetype = \"appliance\"\n{NAMED_VOLUME}\n\
                 [annotations]\n\"yah.durability.tier\" = \"none\"\n"
            ),
        );
        let topo = camp.analyze();
        let DataLoss::Total { because, .. } = &impact(&topo, "a", "cache").data_loss else {
            panic!("expected Total");
        };
        assert!(because.contains("deliberately"), "{because}");
        assert!(
            !because.contains("no yah.durability.tier declared"),
            "{because}"
        );
    }

    /// A bind mount is operator-managed. The camp did not create the host path
    /// and has no basis for saying the bytes are gone — the same refusal to
    /// guess `migrate::preconditions` makes about the same mount kind.
    #[test]
    fn a_bind_mount_is_unknown_rather_than_total() {
        let topo = Camp::new()
            .sized("a", 4096, 4000, "")
            .workload(
                "svc",
                "replicas = 1\narchetype = \"appliance\"\n\
                 [[volumes]]\nsource = { bind = { host_path = \"/srv/data\" } }\n\
                 target = \"/data\"\nread_only = false\n",
            )
            .analyze();

        let i = impact(&topo, "a", "svc");
        assert!(matches!(i.data_loss, DataLoss::Unknown { .. }));
        assert!(i.data_loss.headline().contains("UNKNOWN"));
    }

    #[test]
    fn tmpfs_only_is_not_a_data_loss() {
        let topo = Camp::new()
            .sized("a", 4096, 4000, "")
            .workload(
                "svc",
                "replicas = 1\narchetype = \"server\"\n\
                 [[volumes]]\nsource = { tmpfs = { size_mb = 64 } }\n\
                 target = \"/scratch\"\nread_only = false\n",
            )
            .analyze();
        assert_eq!(impact(&topo, "a", "svc").data_loss, DataLoss::EphemeralOnly);
    }

    // ── Capacity (P3) ────────────────────────────────────────────────────────

    /// The gap admission structurally cannot see: `RequiredSpec::matches`
    /// checks one workload against one node's `[allocatable]` and never
    /// subtracts what is already committed, so three workloads that each fit
    /// are each admitted onto a node that cannot hold their sum.
    #[test]
    fn workloads_that_each_fit_can_still_oversubscribe_the_node_they_all_land_on() {
        let topo = Camp::new()
            .sized("small", 1024, 4000, "")
            .workload_sized("a", 512, 100, "replicas = 1\narchetype = \"server\"")
            .workload_sized("b", 512, 100, "replicas = 1\narchetype = \"server\"")
            .workload_sized("c", 512, 100, "replicas = 1\narchetype = \"server\"")
            .analyze();

        assert_eq!(topo.oversubscribed.len(), 1);
        let o = &topo.oversubscribed[0];
        assert_eq!(o.machine, "small");
        assert_eq!(o.committed_memory_mb, 1536);
        assert!(o.memory_over);
        assert!(!o.cpu_over);
        assert!(topo.render_capacity().contains("OVERSUBSCRIBED"));
    }

    /// Replicas multiply the ask. Admission checks one copy against one node
    /// and never multiplies, so `replicas = 4` of a fitting workload is exactly
    /// the shape that admits cleanly and cannot run.
    #[test]
    fn replicas_multiply_the_commitment() {
        let topo = Camp::new()
            .sized("small", 1024, 4000, "")
            .workload_sized("api", 512, 100, "replicas = 4\narchetype = \"server\"")
            .analyze();

        assert_eq!(topo.machines[0].committed_memory_mb, 2048);
        assert_eq!(topo.oversubscribed.len(), 1);
    }

    /// A node with no `[allocatable]` is *unconstrained*, exactly as admission
    /// reads it — not a zero-capacity node. Flagging it would light up every
    /// machine nobody has measured yet and train the operator to ignore this.
    #[test]
    fn a_node_with_no_allocatable_block_is_never_reported_oversubscribed() {
        let topo = Camp::new()
            .machine("unmeasured", "")
            .workload_sized("api", 99999, 99999, "replicas = 1\narchetype = \"server\"")
            .analyze();

        assert!(topo.oversubscribed.is_empty());
        assert!(topo.render_capacity().contains("unmeasured"));
    }

    // ── Quorum ───────────────────────────────────────────────────────────────

    #[test]
    fn losing_one_of_three_voters_keeps_quorum() {
        let topo = Camp::new()
            .machine(
                "a",
                "sovereign_group = \"prod\"\nsovereign_role = \"voter\"",
            )
            .machine(
                "b",
                "sovereign_group = \"prod\"\nsovereign_role = \"voter\"",
            )
            .machine(
                "c",
                "sovereign_group = \"prod\"\nsovereign_role = \"voter\"",
            )
            .analyze();

        let q = &topo.node_losses[0].quorum;
        assert_eq!(
            *q,
            QuorumEffect::QuorumHolds {
                group: "prod".to_string(),
                voters_before: 3,
                voters_after: 2,
                majority_needed: 2,
            }
        );
    }

    /// The second half of a node loss that is easy to miss: cluster secrets are
    /// read from the *local raft replica*, so a group that loses quorum fails
    /// workloads whose containers were never touched.
    #[test]
    fn losing_one_of_two_voters_loses_quorum_and_says_what_that_costs() {
        let topo = Camp::new()
            .machine(
                "a",
                "sovereign_group = \"prod\"\nsovereign_role = \"voter\"",
            )
            .machine(
                "b",
                "sovereign_group = \"prod\"\nsovereign_role = \"voter\"",
            )
            .analyze();

        let q = &topo.node_losses[0].quorum;
        assert!(matches!(q, QuorumEffect::QuorumLost { .. }), "{q:?}");
        let headline = q.headline();
        assert!(headline.contains("LOSES QUORUM"), "{headline}");
        assert!(headline.contains("secrets"), "{headline}");
    }

    /// A non-voter's absence from `/raft/status` is correct, not drift
    /// (`workload_spec::sovereign`), so losing one costs no seat.
    #[test]
    fn a_non_voter_has_no_seat_to_lose() {
        let topo = Camp::new()
            .machine(
                "a",
                "sovereign_group = \"prod\"\nsovereign_role = \"voter\"",
            )
            .machine(
                "w",
                "sovereign_group = \"prod\"\nsovereign_role = \"non-voter\"",
            )
            .analyze();

        let q = &topo
            .node_losses
            .iter()
            .find(|l| l.machine == "w")
            .unwrap()
            .quorum;
        assert_eq!(
            *q,
            QuorumEffect::NonVoter {
                group: "prod".to_string()
            }
        );
    }

    // ── P2: the render is a projection ───────────────────────────────────────

    /// The scope trap this relay was warned about: a diagram produced by its
    /// own walk of the config can disagree with the analysis printed beside it.
    /// This pins that it cannot — the placement edge in the Mermaid output is
    /// the placement the model computed, and the hydrate edge exists exactly
    /// when the model found a durability tier.
    #[test]
    fn the_mermaid_render_agrees_with_the_model_it_projects() {
        let topo = Camp::new()
            .sized("us-west-001", 12288, 6000, "sovereign_group = \"prod\"")
            .sized("us-west-003", 16384, 16000, "taints = [\"no-appliance\"]")
            .workload(
                "backed-up",
                &format!(
                    "replicas = 1\narchetype = \"appliance\"\n{NAMED_VOLUME}\n\
                     [annotations]\n\
                     \"yah.durability.tier\" = \"stream\"\n\
                     \"yah.durability.engine\" = \"turso\"\n\
                     \"yah.durability.store\" = \"s3://backups/db\"\n\
                     \"yah.durability.subjects\" = \"accounts.db\"\n"
                ),
            )
            .analyze();

        let mermaid = topo.to_mermaid();
        let w = topo
            .workloads
            .iter()
            .find(|w| w.name == "backed-up")
            .unwrap();

        // The edge names the machine the model chose, not a re-derived one.
        assert_eq!(w.placement.machine(), Some("us-west-001"));
        assert!(
            mermaid.contains("m_us_west_001 -->|placed| w_backed_up"),
            "{mermaid}"
        );
        // The blast radius is what a reader sees first.
        assert!(mermaid.contains("subgraph grp_prod[\"prod\"]"), "{mermaid}");
        // The edge that is invisible in the TOML.
        assert!(mermaid.contains("|hydrate|"), "{mermaid}");
        assert!(mermaid.contains("s3://backups/db"), "{mermaid}");
        // Committed-vs-allocatable rides the same numbers as render_capacity.
        assert!(mermaid.contains("128/12288 MiB"), "{mermaid}");
    }

    /// The negative half: no declared tier means no hydrate edge. A diagram
    /// that drew one anyway would show a safety property that does not exist,
    /// which is the single worst thing this render could do.
    #[test]
    fn no_declared_tier_draws_no_hydrate_edge() {
        let topo = Camp::new()
            .sized("a", 4096, 4000, "")
            .workload(
                "db",
                &format!("replicas = 1\narchetype = \"appliance\"\n{NAMED_VOLUME}"),
            )
            .analyze();

        let mermaid = topo.to_mermaid();
        assert!(mermaid.contains("v_db_accounts"), "{mermaid}");
        assert!(!mermaid.contains("hydrate"), "{mermaid}");
    }

    #[test]
    fn a_public_hostname_is_an_edge_and_is_reported_lost_with_its_node() {
        let topo = Camp::new()
            .sized("a", 4096, 4000, "")
            .workload(
                "web",
                "replicas = 1\narchetype = \"server\"\n\
                 [expose.public]\nhostname = \"app.example.com\"\nport = 8080\n\
                 tls = \"cf_managed\"\n",
            )
            .analyze();

        assert_eq!(
            topo.node_losses[0].public_endpoints_lost,
            vec!["app.example.com".to_string()]
        );
        assert!(topo.to_mermaid().contains("|public|"));
        assert!(topo
            .render_node_loss("a")
            .unwrap()
            .contains("public endpoints lost: app.example.com"));
    }

    /// `sovereign_role` defaults to `Voter`, so a box that declares no group
    /// renders as one unless the label is suppressed — a quorum seat in a
    /// quorum that does not exist. Caught against the live camp, where
    /// us-west-002 and us-west-015 declare no group.
    #[test]
    fn an_ungrouped_machine_is_not_labelled_a_voter() {
        let mermaid = Camp::new()
            .sized("loner", 1024, 1000, "")
            .analyze()
            .to_mermaid();
        assert!(mermaid.contains("<i>no group</i>"), "{mermaid}");
        assert!(!mermaid.contains("<i>voter</i>"), "{mermaid}");
    }

    #[test]
    fn an_undeclared_machine_has_no_node_loss_section() {
        let topo = Camp::new().sized("a", 4096, 4000, "").analyze();
        assert!(topo.render_node_loss("typo").is_none());
        assert!(topo.render_node_loss("a").is_some());
    }
}
