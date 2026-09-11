//! File-backed raft storage for yubaba.
//!
//! Both `YubabaLogStore` (log entries + vote) and `YubabaStateMachine`
//! (applied state + snapshot) use JSON files under a configurable
//! directory (`raft_dir`).  State is tiny (KB-scale) so we can afford
//! to rewrite the full file on every mutation — no append-log format
//! needed at this scale.
//!
//! File layout:
//! ```text
//! {raft_dir}/
//!   raft_vote.json      — persisted Vote
//!   raft_log.json       — BTreeMap<u64, Entry>
//!   raft_state.json     — StateMachineData (YubabaState + meta)
//!   raft_meta.json      — LogMeta (last_purged_log_id + committed)
//! ```
//!
//! Every one of those is rewritten whole through [`write_atomic`] — temp file,
//! fsync, rename — because [`YubabaLogStore::open`] refuses to start on a file
//! it cannot parse, and a plain `write` that is interrupted leaves exactly such
//! a file.
//!
//! openraft 0.10 notes: storage methods now fail with plain [`std::io::Error`]
//! (not the old `StorageError`); ids/votes/memberships are the `…Of<C>` type
//! aliases; `RaftStateMachine::apply` consumes a stream of `(entry, responder)`
//! and each entry's response is delivered through its [`ApplyResponder`]; and
//! `SnapshotData` (a `Cursor<Vec<u8>>` here) lives on the state machine /
//! network, not the type config.
//!
//! [`ApplyResponder`]: openraft::storage::ApplyResponder
//!
//! @yah:ticket(R841-B1, "raft store never persists last_purged_log_id — a voter that has purged its log cannot cold-start")
//! @yah:status(review)
//! @yah:at(2026-08-31T16:02:08Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R841)
//! @yah:severity(critical)
//! @yah:next("MECHANISM: `last_purged_log_id` (store.rs:64) is in-memory only. Initialized to None on load (store.rs:120), written solely by `purge()` (store.rs:196), never serialized — the raft dir holds only raft_log.json / raft_state.json / raft_vote.json. So `get_log_state()` (store.rs:147) reports `last_purged_log_id: None` on every cold start, telling openraft the log begins at index 0; openraft reads LogIndex(0), which purge deleted, and the process exits 1.")
//! @yah:next("Tier: Wizard — openraft storage-contract semantics plus a migration for already-purged on-disk logs; getting the reconstruction wrong re-breaks startup on live voters.")
//! @yah:gotcha("LIVE INCIDENT 2026-08-31: all three production raft voters (us-west-001, us-south-001, us-east-001) failed to restart with `Error: when Read LogIndex(0): log entry not found` and crash-looped under systemd. Reproduced identically on yubaba 0.8.28 AND 0.8.29 — not release-specific, and NOT caused by the 0.8.29 upgrade that surfaced it. On-disk raft_log.json held indices 189000-193466; everything below 189000 had been purged. The fleet had been up continuously since ~2026-07-20, so a cold start had never been exercised — it was one reboot from unbootable for weeks.")
//! @yah:handoff("LANDED. last_purged_log_id (and the optional committed watermark) now persist to a new raft_meta.json in the raft dir, written by purge() and save_committed(). A voter that has purged its log cold-starts.")
//! @yah:handoff("THE MIGRATION GUESSES NOTHING, which was the ticket's stated Wizard-tier risk. Two facts pin the marker exactly: purging leaves no hole (so the purge point is first_index-1), and everything at or below it is applied, hence committed, hence its log id is cluster-canonical. Two exact cases, no third: last_applied.index == first_index-1 means last_applied IS the purged log id; last_applied.index >= first_index means the first surviving entry is itself already applied, so its own log id is an exact marker (the entry stays on disk, harmlessly - openraft only ever reads purged+1..). No term is ever invented.")
//! @yah:handoff("A last_applied below first_index-1 is a genuine hole and open() now REFUSES with an actionable message naming all four raft files, rather than fabricating a term openraft would fail every consistency check against.")
//! @yah:handoff("ORDERING IS LOAD-BEARING in purge(): the marker is written BEFORE the entries are removed. Dying between the two leaves entries at or below the marker on disk, which openraft never reads and the next purge sweeps. Dying with the log ahead of the marker is exactly the unbootable state this ticket exists for.")
//! @yah:handoff("DISCOVERED WORK 1, done in this pass: save_committed() was also in-memory-only, so read_committed() returned None on every restart. openraft's trait calls persisting it optional but recommended - without it a restarted node recovers only to its snapshot and can serve a read OLDER than one it already served pre-restart. Now persisted in the same file, skipping the write when the watermark is unchanged.")
//! @yah:handoff("DISCOVERED WORK 2: all four raft files now go through write_atomic() (temp file, fsync, rename, dir fsync) instead of std::fs::write. Same failure class as this ticket - open() refuses to start on a file it cannot parse, so an interrupted plain write turns the daemon into a crash loop with nothing to recover from. Zero on-disk format change; only the path there.")
//! @yah:handoff("DISCOVERED WORK 3, and this one is a footgun this change would otherwise have INTRODUCED. The 2026-08-31 recovery runbook says 'wipe raft_log/raft_state/raft_vote.json' - it predates raft_meta.json, so running it from memory now leaves a purge marker over an empty log. MEASURED: get_initial_state still succeeds, then the founding init panics inside openraft's own validit invariant (expect: purged(Some(index 5)) <= snapshot.flushed()(None), io_state.rs:181). open() now detects that exact shape (marker present, log empty, no raft_state.json) and drops the marker. raft/mod.rs::open_with_state_machine's raft_dir doc now names all four files as one unit.")
//! @yah:verify("cargo test -p yubaba --lib = 561 passed / 0 failed (560 before, +1 net new store test; 9 tests now in raft::store::tests, was 1).")
//! @yah:verify("FALSIFIED, not assumed. Forcing open() to hand back last_purged_log_id: None (the pre-fix behaviour) fails a_purged_log_can_still_produce_an_initial_state with StorageError { subject: LogIndex(0), verb: Read, source: log entry not found } - the production error verbatim - and takes the three marker tests with it, while the hole and committed tests stay green. Probe removed; recorded in that test's doc comment.")
//! @yah:verify("FALSIFIED SEPARATELY: disabling the wiped-dir marker drop makes a_marker_left_behind_by_a_partial_wipe_is_dropped panic in openraft's validit invariant at cluster founding. That is why that test pays for a real raft node instead of stopping at get_initial_state, which passes either way.")
//! @yah:verify("cargo test -p yubaba --test main raft_ -- --test-threads=1 = 41 passed / 0 failed, matching the recorded serial baseline. (Run serially per R734-T1's gotcha: the ten raft suites share one test binary and spin five-node clusters concurrently.)")
//! @yah:verify("cargo test -p xtask --test main cluster_epoch = 8 passed / 0 failed after re-recording.")
//! @yah:verify("cargo clippy -p yubaba --all-targets: no new warnings. The three hits on store.rs (clone_on_copy x2 in read_vote/save_vote, derivable_impls on StateMachineData) are all pre-existing and on lines this change does not touch.")
//! @yah:verify("rustfmt --edition 2021 --check on both edited files: clean on every hunk of this change. The two remaining deviations (store.rs pub fn tenants, mod.rs rpo_bound assert) are both present at HEAD and were left alone - shared tree.")
//! @yah:gotcha("EPOCH VERDICT: state_epoch stays 4, surface re-recorded (5d01cc38... -> 7811ac8f...). raft/store.rs is a state_epoch surface input so the gate went red; the NOT-BREAKING call and its reasoning are in oss/yubaba/crates/yubaba/cluster-epochs.json surface_rerecords[2026-08-31]. Short form: new-reads-old IS the fix (the migration), old-reads-new is a no-op (a pre-R841 binary opens the other three files by exact name and never looks at raft_meta.json, and none of their schemas changed), and no replicated type moved. cluster_protocol was untouched and stayed green - store.rs is not one of its inputs.")
//!
//! @yah:ticket(R836-B2-B1, "open() trusts a present last_purged_log_id without checking it against the log's first index, so a rollback across a purge leaves a stale marker")
//! @yah:at(2026-09-02T23:19:15Z)
//! @yah:status(open)
//! @yah:parent(R836-B2)
//! @yah:severity(medium)
//! @yah:next("In open(), validate a PRESENT meta.last_purged_log_id against entries.first(). Today the recovery arms are asymmetric: is_none() reconstructs from raft_state.json, and the wiped-dir case (entries empty, no raft_state.json) drops the marker, but a marker that is present and WRONG is trusted verbatim. The check is cheap and local: if the marker's index+1 != first surviving index, the same reconstruct_last_purged reasoning already in this file says which value is right.")
//! @yah:next("Reachable sequence, all three legs supported today: roll a node forward to a build that writes raft_meta.json; roll it back to a pre-R841-B1 build, which purges without knowing the file exists; roll forward again. The marker now names a purge point BELOW where the log starts, openraft reads a deleted entry, and the node exits with the same 'log entry not found' R841-B1 was filed to fix.")
//! @yah:verify("A test in this file's suite: write a raft dir with a purge marker at index N, truncate the log so it starts at M > N+1, open() and assert the marker is corrected or the open refuses with a message naming the mismatch. The existing a_purged_log_can_still_produce_an_initial_state and the wiped-dir test are the shape to follow.")
//! @yah:gotcha("NOT AN EPOCH QUESTION and do not re-open one. state_epoch was settled NOT BREAKING on 2026-09-02 (cluster-epochs.json surface_rerecords, closing R836-B2): new-reads-old migrates exactly, old-reads-new never opens the file, nothing replicated moved. Bumping the epoch would not fix this shape — it would only forbid the rollback that produces it, and the code is what should be robust to it.")
//! @yah:gotcha("FAILS LOUDLY, which is why this is medium and not high: the node refuses to start with a storage error. No divergence, no stale read served, no silent corruption.")
//! @yah:tier(Wizard)
//!
//! @yah:relay(R869, "Raft state has no off-fleet copy: total node loss is unrecoverable, and rebuilding resets tenant fencing epochs")
//! @yah:status(review)
//! @yah:phase(P5)
//! @yah:at(2026-09-10T04:13:23Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @arch:see(.yah/docs/working/W339-rebuilding-a-cluster-from-nothing.md)
//! @yah:gotcha("THE HAZARD IS FENCING EPOCHS, NOT THE DATA — read this before scoping, because it changes what 'recovery' has to mean. raft/mod.rs:98 states the single-writer invariant: 'a stale-high token cannot exist (only committed entries reach the state machine)'. That holds for every failure mode EXCEPT rebuild-from-nothing. Wipe the raft dir and re-form, and tenant epochs restart low; a node that comes back from the dead holding a HIGHER epoch then out-fences the fresh cluster at the R2 sink and legitimately wins. So a recovery design that only restores the DATA reintroduces the split-brain the epochs exist to prevent. Any scheme here must either restore epochs monotonically or bump them past any possible survivor.")
//! @yah:gotcha("THIS HAS ALREADY HAPPENED ONCE, by accident rather than hardware loss — store.rs:40 records it. 2026-08-31: all three production voters (us-west-001, us-south-001, us-east-001) failed to restart with 'when Read LogIndex(0): log entry not found' and crash-looped under systemd. Reproduced on 0.8.28 AND 0.8.29, so not release-specific. The fleet had been up since ~2026-07-20, so a cold start had never been exercised — it was one reboot from unbootable for weeks. Recovery was wiping the raft dir. So the de-facto total-loss procedure today IS 'lose this state', undesigned. Treat that incident as the acceptance scenario, not a footnote.")
//! @yah:gotcha("SCOPE IT BY WHAT ACTUALLY DIES, so nobody rebuilds something that is already safe. SURVIVES total fleet loss and needs nothing: the cluster KEK (fob vault slot cluster-kek, off-fleet), declared secret plaintexts (fob vault, 4 slots, declarations in .yah/infra/secrets/*.toml), machine config (.yah/infra/machines/*.toml + mirror.yml), and — importantly — certs AND the enrollment set, because cert_store.rs is yah_object_store-backed (R2) by R779 Decision 1, which deliberately kept 10k certs out of raft. DIES: YubabaState's members, service_placement, locks, ingress_owner, rollouts, secrets (re-seedable from the vault, so recoverable but not automatic), and tenant ownership + epochs. The genuinely-irrecoverable set is therefore SMALL — which is why this is a bounded ticket and not a redesign.")
//! @yah:gotcha("COST IS LOW, WHICH IS THE ARGUMENT FOR DOING IT PROPERLY RATHER THAN DEFERRING. raft/store.rs's own module docs say state is KB-scale and persist() rewrites the whole file on every mutation, so an off-fleet copy is small and cheap. Do NOT reach for litestream here: that replicates a sqlite DB and this is four JSON files. oss/turso-backup already implements the R2 side of exactly this shape (frame keys, manifests, watermark CAS, epoch comparison) and raft/mod.rs:134 records a test driving a real turso-backup BackupTarget over an in-memory object store — check whether that machinery generalizes before writing a new replicator.")
//! @yah:notify_on(R736-F6, "R736-F6 has landed the pointer generation into raft + GET /tenants/{id} + streamer.rs (no more pointer_generation: 0). That unblocks R869's correctness half: step 1 of W339's rebuild procedure (bump the pointer generation off-fleet) stops being inert, so a resurrected node can finally be REFUSED rather than merely out-raced. Re-read W339 §\"What is not closed\", then build the rebuild command and run the chaos drill — destroy every voter, rebuild, and prove BOTH (a) the cluster serves and (b) a deliberately-resurrected node holding a stale-high epoch is fenced. raft_rebuild_fencing::a_generation_bump_fences_a_survivor_the_epoch_floor_cannot already proves the mechanism against real tail_frames; what F6 adds is the wiring that makes it reachable in production.")
//! @yah:gotcha("DESIGN SETTLED AND EVIDENCED — READ .yah/docs/working/W339-rebuilding-a-cluster-from-nothing.md BEFORE ANY MORE SCOPING. The ticket's next(2) hypothesis (\"an epoch floor alone may close the correctness half, in which case this collapses to 'read the floor at founding init'\") is FALSIFIED, not merely unconfirmed. tail_frames fences on `sidecar.epoch > cfg.epoch || sidecar.pointer_generation > cfg.pointer_generation` — an OR, so writing needs BOTH comparands at least the sink's. The epoch floor closes availability only. It cannot fence a survivor, because the sidecar records the highest epoch anyone WROTE under, not the highest the dead raft group GRANTED: a tenant claimed twice while idle leaves a node holding an epoch strictly above anything in the bucket, and no number readable from R2 bounds it. Proven by raft_rebuild_fencing::an_epoch_floor_alone_loses_to_a_survivor_that_outranks_it against the real tail_frames.")
//! @yah:gotcha("THE CORRECTNESS HALF IS GATED ON R736-F6 AND MUST NOT BE ROUTED AROUND. Only the off-fleet yah_tenant_pointer generation can fence a resurrected node, because it is minted by CAS on an object the dead cluster cannot reach — exactly the case W250 built it for (\"two cells are independent raft groups that share no epoch counter\"; a rebuilt cluster is that case against its own predecessor). It is INERT today: tenant-streamer passes pointer_generation: 0 at streamer.rs:144 and :441. Carrying the real value is R736-F6's RATIFIED design call — the generation enters the target cell's raft at commit_target_ownership and is served beside the epoch from GET /tenants/{id}, and F6 explicitly rejects the alternative (\"the streamer reads the pointer itself\") as worse. Do not implement that wiring under R869. A @yah:notify_on(R736-F6) is already on this ticket.")
//! @yah:gotcha("DO NOT RE-PROPOSE `ClaimTenant { min_epoch }`. It was built, measured against the epoch gate, and REVERTED in this pass — the reasoning is in cluster-epochs.json surface_rerecords[2026-09-06] and W339. It would be #[serde(default)] and therefore TOLERATED in both directions, which is the R706 hazard and not the R720-F1/R737-F1 `capacity` precedent: a node on an older binary drops the field and applies current+1 while an upgraded node applies max(current,min_epoch)+1 — one log entry, two applied epochs, state machines diverged. That costs cluster_protocol 5->6 AND state_epoch 4->5, and a disaster-recovery mechanism gated on a fleet-wide upgrade cannot be used in the disaster it exists for. The shipped recovery lifts the epoch with repeated PLAIN ClaimTenant writes over the POST /raft/write that R732-T4 already deployed (raft/mod.rs:98) — one committed entry per epoch of gap, usable against the binaries on the fleet today.")
//! @yah:gotcha("ORDERING IS LOAD-BEARING IN THE REBUILD, AND STEP 3 MAY NEED ONE RETRY. Bump the pointer generation FIRST, then read the epoch floor, then write. A generation bump does not stop a survivor immediately — the sidecar carries the old generation until somebody stamps a new one, so a survivor writing in that window is accepted and raises the sink's epoch above the floor just read, bouncing the rebuild. It TERMINATES because a dead raft group cannot mint an epoch: the survivor's number is frozen at its last applied ClaimTenant, so re-reading the fence after a bounce yields a floor already above it and attempt two wins for good. No backoff policy and no bound beyond re-read-and-retry. Pinned by raft_rebuild_fencing::the_rebuild_wins_in_one_retry.")
//! @yah:handoff("DELIVERED, P1-P5. The title names two defects — raft state had no off-fleet copy, and rebuilding reset tenant fencing epochs — and both are closed in code. P1 established the recovery semantics and found the acceptance property SPLITS IN TWO, because tail_frames fences on an OR (`sidecar.epoch > cfg.epoch || sidecar.pointer_generation > cfg.pointer_generation`): an epoch floor read from the sink closes availability only, and the raft epoch fundamentally cannot fence across a raft-group rebuild because raft is the authority that just died. P2 shipped the copy — src/state_backup.rs, a leader-side loop PUTting the applied YubabaState to cluster-state/<cluster>/latest.json, reusing the cert store's R2 bucket and credentials so that recovery needs no config the fleet does not already carry. P3 shipped `yubaba-tenant-streamer rebuild` (tenant-streamer/src/rebuild.rs), the command that clears the sink fence. P4 shipped the operator runbook. P5 shipped tests/rebuild_drill.rs, which proves the four pieces COMPOSE rather than each working alone.")
//! @yah:handoff("WHERE THE DETAIL LIVES — read this before assuming something was lost. This annotation was condensed from 47 entries (~23 KB, Rule03) and is deliberately a POINTER, not the record; everything cut is durable somewhere better, and the phase-by-phase narrative was the least useful copy of each fact. DESIGN, EVIDENCE AND THE FULL ARGUMENT: .yah/docs/working/W339-rebuilding-a-cluster-from-nothing.md — §'The hazard' and §(a)/(b) for the split, §'The off-fleet copy (shipped, R869 P2)' incl. the guard/restore/adopt semantics, §'The command (shipped, R869 P3)', §'The drill (shipped, R869 P5)' incl. §'The matched pair is the argument', and §'Open work' for what is left. OPERATOR STEPS: .yah/docs/guides/yubaba-total-loss-recovery.md (six steps, preconditions, and a table mapping rebuild's three refusals to what each means). THE REJECTED-DESIGN VERDICT: oss/yubaba/crates/yubaba/cluster-epochs.json surface_rerecords. INVARIANTS A FUTURE EDIT COULD RE-BREAK: at the code sites, in doc comments on the tests that pin them.")
//! @yah:handoff("WHAT R869 DELIBERATELY DID NOT DO, both of which a future session will otherwise re-invent. (1) `ClaimTenant { min_epoch }` was BUILT, measured against the epoch gate, and REVERTED — it would be #[serde(default)] and therefore tolerated in both directions, so an old node drops the field and applies current+1 while an upgraded node applies max(current,min_epoch)+1: one log entry, two applied epochs, state machines diverged. It costs cluster_protocol 5->6 AND state_epoch 4->5, and a disaster-recovery mechanism gated on a fleet-wide upgrade cannot be used in the disaster it exists for. The shipped recovery instead lifts the epoch with repeated PLAIN ClaimTenant writes over the POST /raft/write already deployed by R732-T4 — no new wire surface, usable against the binaries on the fleet today. Reasoning in W339 §'Why step 3 is a loop and not a request field' and cluster-epochs.json. (2) R736-F6's pointer-generation wiring was NOT routed around: only the off-fleet yah_tenant_pointer generation can fence a resurrected node absolutely, and carrying the real value is F6's ratified design call. A @yah:notify_on(R736-F6) watches this ticket.")
//! @yah:handoff("TWO STANDING NEXT-STEPS RETIRED ON EVIDENCE, not on opinion. (1) 'Re-seed cluster secrets from declarations' is SUPERSEDED: `secrets` survives a full restore. state_backup::restorable is field-explicit and drops ONLY `locks` and `rollouts`, letting secrets ride through `..snapshot.state`; the PUT side carries them because StateSnapshot serialises `pub state: YubabaState` whole, and SecretRecord is AES-256-GCM ciphertext by construction — so the copy holds no plaintext AND a restore needs no re-sealing. Pinned by rebuild_drill::end_to_end_rebuild_restores_everything_but_locks_and_rollouts. It survives only as a fallback for a cluster that never enabled the backup. (2) 'Turn it on' was ambiguous between a wiring gap and a deploy gap, and it is purely a DEPLOY: StateBackupConfig::parse is called at src/main.rs:1481 and state_backup::spawn at :1484, on the production serve path. The module is wired, not dead — nothing on the fleet sets the variable, and that is the entire gap.")
//! @yah:handoff("WHAT IS LEFT, all of it owned rather than parked here as unclaimable `next`. R869-T1 — turn the backup on: cut a release, roll the three voters, set YUBABA_STATE_BACKUP_CLUSTER beside the existing YUBABA_CERT_STORE_*; blocked_on operator, since the release cut is theirs. R869-T2 — the chaos drill, depends_on T1: destroy every voter, rebuild from camp + R2, and prove BOTH halves separately; it also carries the last untested span, that nothing has run `rebuild` against a real bucket (the unproven part is the credential read and the R2/S3 transport, not the logic). R736-F6 — external, and the only thing that closes the ABSOLUTE form of half (b). THE RESIDUAL IS BOUNDED, NOT UNBOUNDED, and is pinned as a currently-PASSING test: a survivor whose epoch was granted after the last copy shipped still out-ranks the restored cluster and takes the tenant back. rebuild_drill::a_survivor_granted_an_epoch_after_the_last_copy_still_outranks_the_restored_cluster asserts exactly that, so it reads as a known limit rather than as silence. Until F6, `yubaba state show`'s applied-index age is what bounds the window.")
//! @yah:handoff("DISCOVERED WORK, done across these phases and NOT swept into this ticket's scope. `fleet.md` §'Raft — what's safe and what is a flag-day' documented an openraft minor-version upgrade as 'delete raft_{log,state,vote}.json on every node, then raft init once' — a bare wipe, with no mention of the copy or the sink fence. That is a ROUTINE PLANNED EVENT documented as a procedure that destroys precisely what this ticket protects, and the tenant half of the damage is silent; rewritten to point at the runbook. cert_store::CertStoreConfig::connect was split so connect_objects() yields the bare Arc<dyn ObjectStore>, so a non-cert consumer takes the bucket without being handed a cert store it would only unwrap. R732-T6's gotcha said '4 tests' — corrected to 8, with all six split_brain names and the note that two are plain #[test] wire-contract checks needing no containerd, hence cheapest to re-home first; R869 did NOT re-home them, since that is T6's call, and put its own proofs in tests/main.rs-registered files so they cannot themselves pass vacuously. A broken intra-doc link at rebuild_drill.rs:40 named a test that does not exist; fixed.")
//! @yah:next("R736-F6 IS THE ONE REMAINING EXTERNAL GATE — it closes the ABSOLUTE form of acceptance half (b), and R869 deliberately did not route around it. Read W339 §'What restoring the epochs does to half (b)' before re-planning, because the shape of what F6 buys has CHANGED since this ticket was filed: with the state copy in place a rebuild already out-fences any survivor whose epoch predates the last copy, so what is left is a BOUNDED-staleness window (epochs granted after the last copy) rather than the unbounded one this ticket opened with. A @yah:notify_on(R736-F6) already watches this ticket.")
//! @yah:next("A NEW LINEAGE IS NEVER PRUNED — a design statement, not work. lineage/<n>.json accumulates one object per `yubaba state adopt`, forever, by design: they are KB-scale and they are precisely the pre-accident record, which is the one copy you want after a bad rebuild. If it ever needs bounding that is a policy decision, not an oversight; `StateBackup::lineages()` already lists them.")
//! @yah:verify("FALSIFIED, NOT ASSUMED — every load-bearing assertion in this relay was probed by breaking the production code, watching the test fail, recording the exact failure text in that test's doc comment, and reverting. P1: handing the survivor the bumped generation instead of the stale one flips a_generation_bump_fences_a_survivor_the_epoch_floor_cannot from Fenced to `Streamed { first_frame: 6, last_frame: 7 }` — the survivor takes the sink back — while the file's other three stay green, so the generation comparand fences on its own. P3: deleting the post-claim re-read makes the_rebuild_overtakes_a_survivor_that_wrote_into_the_window return `Cleared { floor: 5, epoch: 6, claims: 6, rounds: 1 }` against a sink standing at 9. P5: dropping `tenants` from restorable gives `left: 1 / right: 6` (the un-backed-up rebuild), and deleting the monotonicity arm gives `left: Wrote { lineage: 1, applied_index: 1 } / right: Regressed { stored: 193466, local: 1 }` — the 2026-08-31 incident, reproduced. All probes reverted; confirmed by CONTENT, not by `git status`, since these files are tracked-and-clean and a diff proves nothing about a probe applied and undone in one session.")
//! @yah:verify("WHAT IS NOT EXERCISED, named rather than silently skipped — this is the honest boundary of the relay's verification and it is what R869-T2 exists to close. (1) The R2/S3 transport itself: `connect_from_env` needs live credentials, so `yubaba state show|restore|adopt` and `tenant-streamer rebuild` against a real bucket are unrun. Everything BENEATH them is unit-tested against InMemoryObjectStore including put_if/ETag CAS semantics, so the untested span is the credential read and the transport, not the logic. (2) The runbook end to end: it is a procedure against live hardware and no fleet node runs a tenant streamer today, so every command, flag and error string in it was read from source rather than executed. (3) The quorum half of the drill: `raft init`'s founding-membership commit and the ordinary openraft write path cannot be observed from a single process, which W339 §'What it deliberately does not cover' states outright.")
//! @yah:verify("CLI SURFACES EXERCISED (not just compiled): `yubaba state --help` / `state restore --help` render; `yubaba state show` with no env fails with its intended message. `yubaba-tenant-streamer --help` shows the rebuild subcommand and the streaming default is unchanged (no subcommand still streams, --check still checks); `rebuild --help` renders every flag; `rebuild --dry-run` with no credentials fails with 'S3_ACCESS_KEY_ID must be set…'; `rebuild --tenant nope` fails with '--tenant nope is not in the config; configured tenants are: acme, globex'. Also `cargo test -p yah-party --lib` = 507 / 0 including resident_prompt_stays_under_its_ceiling, which FAILED first at 'yubaba: 21010 B of 20900 B — OVER by 110 B' and passes at 20867 B after the cloud-ops entry was trimmed. That failure is recorded because it IS the measurement: the yubaba resident prompt has 33 B of headroom, so the next addition to that always-on trait will trip it — growth belongs in the on-demand `fleet` skill or in the guides.")
//! @yah:verify("CLIPPY AND FMT, with one discipline applied throughout: no shared file was ever blanket-reformatted. Files authored solely by this relay (state_backup.rs, rebuild.rs, raft_rebuild_fencing.rs, rebuild_drill.rs) were formatted outright and are clean. On every SHARED file only this relay's own hunks were checked and hand-corrected, leaving the pre-existing drift in place — stream.rs carried ~86 such sites, lib.rs ~150 crate-wide, cert_store.rs 25. That is deliberate: a blanket fmt on a shared tree is how this camp lost 827 uncommitted lines of a peer's work on 2026-08-28. Clippy is clean across turso-backup and yubaba-tenant-streamer; on yubaba the only hits are pre-existing and untouched (raft/store.rs clone_on_copy at :397/:419, derivable_impls at :491) plus dead code in yah-object-store (parse_list_v2, r2.rs:606), none of them in files this relay authored.")
//! @yah:verify("CURRENT STATE, re-run by the leader independently rather than taken from a courier's self-report — the per-phase counts this list used to carry were superseded and are gone. `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --test main -- --test-threads=1` (serial, per R734-T1's gotcha) = 92 passed / 0 failed, exit 0, with all four `rebuild_drill::` tests named in the output. `-p yubaba --lib` = 828+ / 0; `-p yubaba-tenant-streamer` = 35 / 0; turso-backup whole workspace = 151 / 0. Counts EXCEED the baselines quoted in earlier phases because the shared tree also carries peers' in-flight tests; 0 failed is the comparand that holds either way. `cargo build -p yubaba --bin yubaba` from the settled tree = Finished, exit 0. CLUSTER-EPOCHS: the tree records cluster_protocol 7 / state_epoch 6 and the LIVE fleet reports the same on all three prod voters, so they agree and nothing R869 did moved either axis. (An earlier version of this entry said 5 and 4 — those were the values during P1 on 2026-09-06; peers bumped both since. The claim that R869 adds no wire surface is unchanged and is why it needed no bump of its own.)")
//! @yah:handoff("THE TITLE DEFECT IS NOW FACTUALLY FALSE — the fleet has an off-fleet copy. R869-T1 shipped 2026-09-09 and is in review: `yubaba state show` on the prod leader reads cluster prod, lineage 1, applied index 2806091, written by node 2, holding members 3 / cluster secrets 7 / ingress_owner us-south-001. It needed NO release and NO hotship: the code was already on all three voters, carried out by peers' earlier hotships (which build the working tree, not a release), so the activation was one systemd drop-in per voter setting YUBABA_STATE_BACKUP_CLUSTER=prod. Zero availability cost, measured — 123/123 `200/37298` at the public apex across all three restarts including the leader, raft never leaving term 21. This also closes the READ half of the 'nothing has run against a real bucket' span: a pre-arm `state show` returned a definitive 404 for the not-yet-existing object, proving credentials, R2 transport and key layout against the live bucket while writing nothing. TENANTS IS 0 on the live cluster, so the fencing-epoch hazard has nothing to protect yet — today the copy insures members/placement/ingress_owner/secrets, and starts insuring epochs the moment a tenant is claimed.")
//! @yah:handoff("DISCOVERED WHILE OPERATING THE FLEET, all three fixed in this pass — each is a doc that would have misled the next operator, and each was measured rather than inferred. (1) `.yah/infra/machines/us-west-001.toml` claimed in TWO separate comments that that box carries headscale. It does not: the unit reads disabled/inactive with no process there, while us-south-001 runs `headscale serve`. That is operationally load-bearing, because the fleet skill says to avoid a live leader step-down on the headscale host — a wrong name protects the wrong machine. Corrected, dated, and told the reader to re-derive with `pgrep -af headscale`. It also contradicts R858's own gotcha, which is annotation text on another ticket and was left alone; a note was filed on R858 instead. (2) `.yah/docs/guides/yubaba-total-loss-recovery.md` gained the preconditions that only exist now that prod is armed — above all that `prod` is the value a recovering operator MUST pass, because every `yubaba state` subcommand needs it and the machine being rebuilt is not in a cluster yet, so nothing on it can supply the name. A recovery blocked on not knowing the cluster name would be the worst possible failure of that document. (3) fleet.md — see the next entry, it is the significant one.")
//! @yah:handoff("THE FLEET SKILL FORBADE THE MECHANISM THIS CAMP NOW USES, and that is the second time R869 has found this exact defect class in fleet.md (P4 found its raft flag-day section documenting a bare wipe). Its closing paragraph said \"Never hand-build a fleet binary… the answer is to cut a release, not to `scp` a binary — a hand-cut pair is invisible to every version check the fleet has (R746-T3)\". That predates scripts/hotship.sh, and the paragraph's stated objection is precisely what hotship SOLVES: hotship stamps a version via scripts/hotship-version.sh (`0.8.36-h16`, a prerelease of the next patch, ordering strictly after the last release and before the next), so a hot-shipped node is exactly NOT invisible to version checks — confirmed against the live fleet, which reports those stamps on all three voters. I nearly concluded hotship was forbidden BECAUSE of that paragraph, which is the evidence that it misled. Rewritten to keep its real teeth (never hand-install an UNSTAMPED binary; a RELEASE is what anything anyone else depends on must ride) while sanctioning hotship for putting an ITERATION on hardware, never writing the CDN, one node at a time with voters last. MEASURED, not assumed: fleet.md grew ~800 B and every resident-prompt row is byte-identical, so it is on-demand and does not count against the ceiling — no ceiling raised, no prose cut.")
//! @yah:verify("RESIDENT-PROMPT CEILING RE-MEASURED BY THE LEADER, and the number in an earlier P4 handoff entry is now stale in the tightening direction — worth knowing before anyone adds to an always-on trait. `cargo test -p yah-party --lib resident_prompt -- --nocapture` = 1 passed / 0 failed, and prints `yubaba: 20888 B of 20900 B ceiling` — TWELVE bytes of headroom, not the 33 B P4 recorded, because peers have added to those surfaces since. Every other row also passes (leader 67214/67400, courier 38857/39200, relay 23794/24100 are the next tightest). The practical rule stands and is now sharper: growth belongs in an on-demand skill or in .yah/docs/guides/, never in the always-on cloud-ops trait — R869's fleet.md rewrite added ~800 B and moved no row precisely because fleet.md is on-demand.")

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::{self, Cursor, Write};
use std::ops::RangeBounds;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use openraft::storage::{
    EntryResponder, IOFlushed, LogState, RaftLogReader, RaftLogStorage, RaftSnapshotBuilder,
    RaftStateMachine,
};
use openraft::type_config::alias::{
    EntryOf, LogIdOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf, VoteOf,
};
use openraft::{EntryPayload, OptionalSend, Snapshot, SnapshotMeta, StoredMembership};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_stream::{Stream, StreamExt};

use super::super::raft::apply;
use super::{YubabaRaftConfig as TC, YubabaRequest, YubabaResponse, YubabaState};

/// Snapshot payload handle. Yubaba state is KB-scale, so the whole snapshot is
/// an in-memory JSON blob behind a cursor — the same on both the state machine
/// and the network transport (`RaftNetworkV2::SnapshotData`).
type SnapshotData = Cursor<Vec<u8>>;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Wrap any displayable error as an `io::Error` — the 0.10 storage traits fail
/// with `io::Error`, so serialization failures funnel through here.
fn io_other<E: Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Replace `path`'s contents with `bytes` atomically: write a sibling temp
/// file, fsync it, rename it over the target, then fsync the directory so the
/// rename itself is durable.
///
/// Every file in the raft dir is rewritten whole on each mutation, and
/// [`YubabaLogStore::open`] / [`YubabaStateMachine::open`] both `?` on a parse
/// failure — so a `std::fs::write` interrupted midway (OOM kill, power cut, a
/// full disk) leaves a truncated JSON document that turns the daemon into a
/// crash loop with nothing left to recover from. A rename is atomic, so a
/// reader sees either the whole previous document or the whole new one.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

// ── Log store ─────────────────────────────────────────────────────────────────

/// Durable log metadata that cannot be re-derived from the entries themselves
/// (`raft_meta.json`).
///
/// R841-B1: `last_purged_log_id` used to live only in memory. Purging *deletes*
/// the entries it covers, so after a restart the store reported
/// `last_purged_log_id: None` over a log that no longer began at index 0.
/// openraft's `StorageHelper::get_key_log_ids` then reads
/// `purged.next_index()` — index 0 — finds nothing, and `Raft::new` fails with
/// `when Read LogIndex(0): log entry not found`. Every production voter was one
/// reboot from unbootable for six weeks before a rolling upgrade found it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct LogMeta {
    /// The greatest log id purged out of `raft_log.json`.
    #[serde(default)]
    last_purged_log_id: Option<LogIdOf<TC>>,
    /// The committed watermark openraft last handed us. Persisting this is
    /// optional per `RaftLogStorage::save_committed`, but skipping it means a
    /// restarted node recovers only as far as its snapshot and can serve a read
    /// *older* than one it already served before the restart.
    #[serde(default)]
    committed: Option<LogIdOf<TC>>,
}

struct LogStoreInner {
    last_purged_log_id: Option<LogIdOf<TC>>,
    /// Log entries kept after the last purge.
    entries: BTreeMap<u64, EntryOf<TC>>,
    committed: Option<LogIdOf<TC>>,
    vote: Option<VoteOf<TC>>,
    base_dir: PathBuf,
}

impl LogStoreInner {
    fn persist_log(&self) -> Result<(), io::Error> {
        let json = serde_json::to_string(&self.entries).map_err(io_other)?;
        write_atomic(&self.base_dir.join("raft_log.json"), json.as_bytes())
    }

    fn persist_vote(&self) -> Result<(), io::Error> {
        let json = serde_json::to_string(&self.vote).map_err(io_other)?;
        write_atomic(&self.base_dir.join("raft_vote.json"), json.as_bytes())
    }

    /// Persist `raft_meta.json` (R841-B1).
    fn persist_meta(&self) -> Result<(), io::Error> {
        let meta = LogMeta {
            last_purged_log_id: self.last_purged_log_id,
            committed: self.committed,
        };
        let json = serde_json::to_string(&meta).map_err(io_other)?;
        write_atomic(&self.base_dir.join("raft_meta.json"), json.as_bytes())
    }
}

/// Rebuild `last_purged_log_id` for a log left behind by a binary that never
/// persisted one (R841-B1).
///
/// **The term is never guessed.** Two facts pin the marker exactly:
///
/// - purging leaves no hole, so whatever was purged ends at `first_index - 1`;
/// - everything at or below the purge point has been applied, and an applied
///   entry is committed, so its log id is the cluster-canonical one for that
///   index — no two replicas disagree about it.
///
/// That gives two exact answers and no third:
///
/// - `last_applied.index == first_index - 1` — `last_applied` *is* the purged
///   log id, term included.
/// - `last_applied.index >= first_index` — the first surviving entry is itself
///   already applied, so adopting **its** log id as the marker is exact. The
///   entry stays on disk, harmlessly: openraft only ever reads `purged + 1 ..`,
///   and the next purge sweeps it.
///
/// A `last_applied` below `first_index - 1` is a hole — the state machine is
/// missing entries the log no longer holds, and no marker makes that replica
/// startable. Refuse loudly rather than invent one; a wrong term here would
/// hand openraft a consistency check that silently never matches.
fn reconstruct_last_purged(
    dir: &Path,
    entries: &BTreeMap<u64, EntryOf<TC>>,
) -> anyhow::Result<Option<LogIdOf<TC>>> {
    // An empty log carries no evidence of a purge, and openraft closes that
    // case itself: `get_initial_state` purges up to `last_applied` when the log
    // is behind it, which routes through `purge()` and writes a marker.
    let Some((&first_index, first)) = entries.iter().next() else {
        return Ok(None);
    };
    if first_index == 0 {
        return Ok(None);
    }

    /// Just the one field we need out of `raft_state.json`. Serde ignores the
    /// rest, so this stays readable across state-machine schema moves.
    #[derive(Deserialize)]
    struct AppliedProbe {
        #[serde(default)]
        last_applied: Option<LogIdOf<TC>>,
    }

    let state_path = dir.join("raft_state.json");
    let last_applied = if state_path.exists() {
        serde_json::from_str::<AppliedProbe>(&std::fs::read_to_string(&state_path)?)?.last_applied
    } else {
        None
    };

    match last_applied {
        Some(applied) if applied.index + 1 == first_index => Ok(Some(applied)),
        Some(applied) if applied.index >= first_index => Ok(Some(first.log_id)),
        other => {
            let missing_from = other.map(|a| a.index + 1).unwrap_or(0);
            anyhow::bail!(
                "raft log in {dir} starts at index {first_index} but the state machine has applied \
                 only up to {other:?}: entries {missing_from}..{first_index} were purged before \
                 they were applied, so this replica cannot be rebuilt from its own files. Restore \
                 the raft dir from a backup, or stop yubaba, delete raft_log.json / \
                 raft_state.json / raft_vote.json / raft_meta.json, and re-join the cluster from \
                 an empty log.",
                dir = dir.display(),
            )
        }
    }
}

/// Log storage: clone-able via the inner `Arc<RwLock<>>` so the same
/// instance serves as both `LogStore` and `LogReader`.
#[derive(Clone)]
pub struct YubabaLogStore {
    inner: Arc<RwLock<LogStoreInner>>,
}

impl YubabaLogStore {
    /// Open or create the log store in `dir`.
    pub async fn open(dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;

        let vote: Option<VoteOf<TC>> = {
            let p = dir.join("raft_vote.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                None
            }
        };

        let entries: BTreeMap<u64, EntryOf<TC>> = {
            let p = dir.join("raft_log.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                BTreeMap::new()
            }
        };

        let mut meta: LogMeta = {
            let p = dir.join("raft_meta.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                LogMeta::default()
            }
        };

        // R841-B1 migration. A log written by a binary that never persisted the
        // purge marker begins above index 0 with nothing on disk to explain
        // why; `reconstruct_last_purged` recovers the marker exactly (or
        // refuses). Runs whenever the marker is absent rather than only when
        // `raft_meta.json` is, so a meta file that predates the node's first
        // purge is covered too.
        if meta.last_purged_log_id.is_none() {
            if let Some(recovered) = reconstruct_last_purged(&dir, &entries)? {
                tracing::warn!(
                    last_purged_log_id = ?recovered,
                    dir = %dir.display(),
                    "raft log starts above index 0 with no purge marker on disk; reconstructed it \
                     from the applied state (R841-B1)"
                );
                meta.last_purged_log_id = Some(recovered);
                let json = serde_json::to_string(&meta)?;
                write_atomic(&dir.join("raft_meta.json"), json.as_bytes())?;
            }
        } else if entries.is_empty() && !dir.join("raft_state.json").exists() {
            // A PARTIAL WIPE, and this file is why it needs handling. The
            // documented recovery from the 2026-08-31 incident is "stop yubaba,
            // delete raft_log/raft_state/raft_vote.json, restart, re-init" —
            // written before `raft_meta.json` existed, so anyone running it from
            // memory now leaves a purge marker standing over an empty log and an
            // empty state machine. openraft would then be told this node had
            // purged past index 0 with nothing applied, which no `raft init` can
            // satisfy: the marker survives the wipe and bricks the fresh node.
            //
            // An empty log with no state machine at all is unambiguously a fresh
            // node — the marker's own invariant is `last_purged <= last_applied`,
            // and there is no applied state for it to be under. Drop it. (The
            // milder shape, an empty log with a state machine BEHIND the marker,
            // needs nothing: openraft's `get_initial_state` purges up to
            // `last_applied` when the log is behind it, which rewrites the marker
            // through `purge()`.)
            tracing::warn!(
                stale_last_purged_log_id = ?meta.last_purged_log_id,
                dir = %dir.display(),
                "raft_meta.json holds a purge marker but the log and state machine are both \
                 absent; treating this as a wiped raft dir and dropping the marker (R841-B1)"
            );
            meta = LogMeta::default();
            let json = serde_json::to_string(&meta)?;
            write_atomic(&dir.join("raft_meta.json"), json.as_bytes())?;
        }

        Ok(Self {
            inner: Arc::new(RwLock::new(LogStoreInner {
                last_purged_log_id: meta.last_purged_log_id,
                entries,
                committed: meta.committed,
                vote,
                base_dir: dir,
            })),
        })
    }
}

impl RaftLogReader<TC> for YubabaLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<EntryOf<TC>>, io::Error> {
        let inner = self.inner.read().unwrap();
        Ok(inner.entries.range(range).map(|(_, e)| e.clone()).collect())
    }

    async fn read_vote(&mut self) -> Result<Option<VoteOf<TC>>, io::Error> {
        Ok(self.inner.read().unwrap().vote.clone())
    }
}

impl RaftLogStorage<TC> for YubabaLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TC>, io::Error> {
        let inner = self.inner.read().unwrap();
        let last_log_id = inner.entries.values().last().map(|e| e.log_id);
        Ok(LogState {
            last_purged_log_id: inner.last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &VoteOf<TC>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        inner.vote = Some(vote.clone());
        inner.persist_vote()
    }

    async fn append<I>(&mut self, entries: I, callback: IOFlushed<TC>) -> Result<(), io::Error>
    where
        I: IntoIterator<Item = EntryOf<TC>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        {
            let mut inner = self.inner.write().unwrap();
            for entry in entries {
                inner.entries.insert(entry.log_id.index, entry);
            }
            inner.persist_log()?;
        }
        callback.io_completed(Ok(()));
        Ok(())
    }

    async fn truncate_after(&mut self, last_log_id: Option<LogIdOf<TC>>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        // Remove everything strictly after `last_log_id` (exclusive). `None`
        // truncates the entire log.
        let keep_upto = last_log_id.map(|l| l.index);
        inner.entries.retain(|&idx, _| match keep_upto {
            Some(upto) => idx <= upto,
            None => false,
        });
        inner.persist_log()
    }

    async fn purge(&mut self, log_id: LogIdOf<TC>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        inner.last_purged_log_id = Some(log_id);
        // R841-B1: the marker goes down BEFORE the entries come out, and the
        // order is load-bearing. Dying between the two writes with the marker
        // ahead of the log leaves entries at or below it still on disk, which
        // openraft never reads (it only ever asks for `purged + 1 ..`) and the
        // next purge sweeps. Dying with the log ahead of the marker is exactly
        // the unbootable state this ticket exists for.
        inner.persist_meta()?;
        inner.entries.retain(|&idx, _| idx > log_id.index);
        inner.persist_log()
    }

    async fn save_committed(&mut self, committed: Option<LogIdOf<TC>>) -> Result<(), io::Error> {
        let mut inner = self.inner.write().unwrap();
        // Called on every commit advance; skip the write when it says nothing
        // new (openraft re-saves the same watermark on an idle heartbeat).
        if inner.committed == committed {
            return Ok(());
        }
        inner.committed = committed;
        inner.persist_meta()
    }

    async fn read_committed(&mut self) -> Result<Option<LogIdOf<TC>>, io::Error> {
        Ok(self.inner.read().unwrap().committed)
    }
}

// ── State machine ─────────────────────────────────────────────────────────────

/// Serialised form of the state machine — written to `raft_state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateMachineData {
    last_applied: Option<LogIdOf<TC>>,
    last_membership: StoredMembershipOf<TC>,
    state: YubabaState,
}

impl Default for StateMachineData {
    fn default() -> Self {
        Self {
            last_applied: None,
            last_membership: StoredMembership::default(),
            state: YubabaState::default(),
        }
    }
}

struct StateMachineInner {
    data: StateMachineData,
    /// The last snapshot we installed (if any).
    snapshot_meta: Option<SnapshotMetaOf<TC>>,
    snapshot_bytes: Option<Vec<u8>>,
    base_dir: PathBuf,
    /// R600-F4 (W273): bumped on every applied cluster-secret change
    /// (`PutSecret`/`DeleteSecret`) and on snapshot install, so a consumer task
    /// (rotation → live reload) can re-render the affected tmpfs mounts and
    /// graceful-upgrade the workload. Coarse epoch counter — a subscriber wakes
    /// on any bump and re-reads the current secrets map (re-render is
    /// idempotent), so coalesced bumps never lose a change.
    secrets_epoch: watch::Sender<u64>,
}

impl StateMachineInner {
    fn persist(&self) -> Result<(), io::Error> {
        let json = serde_json::to_string(&self.data).map_err(io_other)?;
        write_atomic(&self.base_dir.join("raft_state.json"), json.as_bytes())
    }
}

/// State machine storage — `Clone`-able via inner `Arc<RwLock<>>` so
/// it doubles as the `SnapshotBuilder`.
#[derive(Clone)]
pub struct YubabaStateMachine {
    inner: Arc<RwLock<StateMachineInner>>,
}

impl YubabaStateMachine {
    pub async fn open(dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;

        let data: StateMachineData = {
            let p = dir.join("raft_state.json");
            if p.exists() {
                serde_json::from_str(&std::fs::read_to_string(&p)?)?
            } else {
                StateMachineData::default()
            }
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(StateMachineInner {
                data,
                snapshot_meta: None,
                snapshot_bytes: None,
                base_dir: dir,
                secrets_epoch: watch::channel(0).0,
            })),
        })
    }

    /// Subscribe to cluster-secret changes (R600-F4 / W273). The receiver's
    /// value is a coarse epoch counter bumped on every applied `PutSecret` /
    /// `DeleteSecret` and on snapshot install. Wake on a change and re-read the
    /// current state via [`Self::cluster_secret`] — the counter says *something*
    /// changed, not what, which is all the (idempotent) re-render needs.
    pub fn subscribe_secrets(&self) -> watch::Receiver<u64> {
        self.inner.read().unwrap().secrets_epoch.subscribe()
    }

    /// Read a cluster secret's ciphertext record from the local applied state
    /// (R600-F2 / W273). Returns a clone so the caller never holds the state
    /// lock while decrypting. `None` if no secret is stored under `name`.
    ///
    /// The record is AES-256-GCM ciphertext only (see [`super::SecretRecord`]);
    /// the state machine cannot itself read a secret's plaintext — decryption
    /// happens in `secrets::ClusterResolver` with the node-local KEK.
    pub fn cluster_secret(&self, name: &str) -> Option<super::SecretRecord> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .secrets
            .get(name)
            .cloned()
    }

    /// Metadata for every cluster secret in the local replica, as
    /// `(name, updated_at, access-rule summary, digest hex)` (R706 / R720-F1 /
    /// W294).
    ///
    /// **Deliberately returns no bytes for ciphertext.** This backs
    /// `GET /secrets` → `yah cloud secret ls`, whose job is to answer "what
    /// exists, who may mount it, when did it last change, does it match what
    /// the camp declares" — none of which needs the ciphertext, and the
    /// ciphertext is the one thing an operator listing must never casually
    /// hand out (it would put a KEK-compromise's whole decrypt corpus one
    /// unauthenticated GET away). The digest is served hex-encoded — it is
    /// already keyed (see `SecretRecord::digest`), so publishing it costs
    /// nothing an attacker without the KEK can use; `None` becomes `None`
    /// (pre-digest), never a stand-in hex value.
    pub fn cluster_secret_index(&self) -> Vec<(String, u64, String, Option<String>)> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .secrets
            .iter()
            .map(|(name, rec)| {
                (
                    name.clone(),
                    rec.updated_at,
                    rec.access.summary(),
                    rec.digest.as_deref().map(hex_encode),
                )
            })
            .collect()
    }

    // ── Locally-applied control-plane reads (R118-T1) ─────────────────────────
    //
    // The rig's non-negotiable rule (W138): nothing on the audio or graph path
    // may synchronously await a raft commit. So every question the realtime
    // side asks of the control plane — "who owns this role right now" — must be
    // answerable from the replica this process already holds: no quorum, no
    // leader round-trip, no `.await`. A node that has lost the cluster entirely
    // still answers, with its last-known-good view, and reports how stale that
    // view is via [`Self::applied_index`].
    //
    // These are the same shape as [`Self::cluster_secret`] above, which was the
    // first consumer of the idea; naming them here makes it the general
    // capability rather than a secrets-only affordance.

    /// Who holds the singleton role `key` in **this node's applied state**.
    ///
    /// `None` means no live claim is recorded locally — which is not the same
    /// as "nobody owns it cluster-wide", because this replica may be behind.
    /// Callers that care about the difference read [`Self::applied_index`]
    /// alongside it.
    ///
    /// Returns a clone so no caller holds the state lock while acting on the
    /// answer. Expiry is deliberately *not* evaluated here: TTL is judged
    /// against the acquiring node's clock inside [`apply`](super::apply), so a
    /// local reader inventing its own "expired" verdict would be a second,
    /// disagreeing authority. Read [`super::LockEntry::acquired_at`] +
    /// `ttl_secs` if you need to render staleness.
    pub fn singleton_owner(&self, key: &str) -> Option<super::LockEntry> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .locks
            .get(key)
            .cloned()
    }

    /// Every singleton role recorded in this node's applied state.
    pub fn singleton_owners(&self) -> BTreeMap<String, super::LockEntry> {
        self.inner.read().unwrap().data.state.locks.clone()
    }

    /// R118-T5 (W138): every rollout in this node's applied state.
    ///
    /// The rollout supervisor's per-tick read. It carries no rollout state of
    /// its own across ticks — this map *is* its memory, which is precisely why
    /// a node that has never seen a rollout before can pick one up the moment
    /// it becomes leader.
    pub fn rollouts(&self) -> BTreeMap<String, super::RolloutRaftRecord> {
        self.inner.read().unwrap().data.state.rollouts.clone()
    }

    /// R118-F8: what this node's applied state believes about `subject`, folded
    /// across every observer whose report is fresher than `ttl` seconds at
    /// `now`.
    ///
    /// The ratchet's per-tick read, and locally applied like every accessor in
    /// this block — a leader that has lost quorum still answers, with the
    /// evidence it had. That is not a hazard here: without quorum it cannot
    /// commit a membership change either, so a stale read cannot produce a
    /// stale *action*.
    pub fn corroborated_liveness(
        &self,
        subject: super::YubabaNodeId,
        now: u64,
        ttl: u64,
    ) -> super::PeerLivenessVerdict {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .corroborated_liveness(subject, now, ttl)
    }

    /// R118-F8: every peer-liveness report in this node's applied state, keyed
    /// `observer -> subject`. The operator/diagnostic view; the ratchet itself
    /// asks [`Self::corroborated_liveness`].
    pub fn peer_liveness(
        &self,
    ) -> BTreeMap<super::YubabaNodeId, BTreeMap<super::YubabaNodeId, super::PeerLivenessRecord>>
    {
        self.inner.read().unwrap().data.state.peer_liveness.clone()
    }

    /// R118-F8: the last membership change the ratchet made, or `None` if it has
    /// never fired on this cluster.
    pub fn last_membership_ratchet(&self) -> Option<super::MembershipRatchetRecord> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .last_membership_ratchet
            .clone()
    }

    /// R118-T5: one rollout's record in this node's applied state, or `None` if
    /// there is none. Serves `GET /v1/rollouts/{id}` and the running engine's
    /// per-step re-read (which is how an operator override reaches an engine
    /// that is already mid-flight).
    pub fn rollout(&self, rollout_id: &str) -> Option<super::RolloutRaftRecord> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .rollouts
            .get(rollout_id)
            .cloned()
    }

    /// R118-T5 (W138): every boot-health report filed against one rollout,
    /// keyed by node.
    ///
    /// An **empty map is the honest answer for a rollout nobody has reported
    /// on**, and it is indistinguishable from one for a rollout that does not
    /// exist — deliberately. The only consumer is the engine's step gate, which
    /// is fail-closed: no evidence and some evidence-but-not-enough take the
    /// same branch, so there is nothing for a caller to get wrong by conflating
    /// them, and no way to spell "assume healthy".
    pub fn rollout_health(&self, rollout_id: &str) -> BTreeMap<String, super::NodeHealthRecord> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .rollout_health
            .get(rollout_id)
            .cloned()
            .unwrap_or_default()
    }

    /// R732-T4 (W245): the fencing token `node` may stream `tenant` under, per
    /// this node's applied state. Delegates to
    /// [`YubabaState::tenant_fencing_token`](super::YubabaState::tenant_fencing_token)
    /// so the owner-and-lease predicate lives in exactly one place.
    ///
    /// This is a *local* read and may be stale — this replica might not yet
    /// have applied the entry that transferred the tenant away. That is safe
    /// by construction rather than by luck: acting on a stale answer means
    /// streaming under an old epoch, which the sink rejects
    /// (`turso_backup::stream::StreamOutcome::Fenced`). Staleness costs a
    /// wasted tail attempt, never a double writer — which is the entire reason
    /// the epoch exists rather than a lock.
    pub fn tenant_fencing_token(
        &self,
        tenant: &workload_spec::TenantId,
        node: super::YubabaNodeId,
        now: u64,
    ) -> Option<u64> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .tenant_fencing_token(tenant, node, now)
    }

    /// R732-T4: the whole ownership record for `tenant` in this node's applied
    /// state, or `None` if there is no record.
    ///
    /// Serves the diagnostic half of `GET /tenants/{id}` — who owns it, at
    /// which epoch, until when. The streamer decides whether it may *write*
    /// from [`Self::tenant_fencing_token`] and never by re-deriving the
    /// owner-and-lease predicate from these fields; it reads `lease_expires`
    /// only to know when to renew. Keeping the two apart is deliberate: one
    /// predicate, one place (see R732-F1's handoff).
    pub fn tenant_ownership(
        &self,
        tenant: &workload_spec::TenantId,
    ) -> Option<super::TenantOwnership> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .tenants
            .get(tenant)
            .cloned()
    }

    /// R737-F3: every tenant's ownership record in this node's applied state —
    /// the scheduler's per-tick read of who currently holds each tenant's
    /// write path, so it can find whose owner just went down. A single-tenant
    /// read is [`Self::tenant_ownership`]; this is the whole map for the loop
    /// that has to walk it.
    pub fn tenants(
        &self,
    ) -> BTreeMap<workload_spec::TenantId, super::TenantOwnership> {
        self.inner.read().unwrap().data.state.tenants.clone()
    }

    /// R737-F3: one tenant's declared placement intent in this node's applied
    /// state, or `None` if it has none — a legal state (see
    /// [`super::TenantPlacement`]'s doc), read by the scheduler as
    /// "unconstrained region, default tier, zero demand" rather than an
    /// error.
    pub fn tenant_placement(
        &self,
        tenant: &workload_spec::TenantId,
    ) -> Option<super::TenantPlacement> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .placement
            .get(tenant)
            .cloned()
    }

    /// R737-F3: whether `node` has headroom for `demand` at `now`, forwarding
    /// to [`super::YubabaState::node_admits`] under this node's single read
    /// lock rather than cloning `members`/`tenants`/`placement` out to
    /// recompute it at the call site.
    pub fn node_admits(
        &self,
        node: super::YubabaNodeId,
        demand: &super::TenantDemand,
        now: u64,
    ) -> bool {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .node_admits(node, demand, now)
    }

    /// R734-F5: every member row in this node's applied state — the yubaba-side
    /// mirror of membership, carrying the `region` tag openraft's `BasicNode`
    /// has no room for.
    ///
    /// This is *not* the authority on who is in the cluster: raft membership is,
    /// and it is reachable from `Raft::metrics`. This map is the replicated
    /// *annotation* on those nodes, written by each node about itself
    /// ([`member_registration`](crate::member_registration)), so a lag between
    /// the two is normal — a node that has just joined is in membership and has
    /// no row here until its registration loop converges.
    pub fn members(&self) -> BTreeMap<super::YubabaNodeId, super::MemberInfo> {
        self.inner.read().unwrap().data.state.members.clone()
    }

    /// One member row from this node's applied state (R734-F5).
    ///
    /// The registration loop's read half: a node compares its own row against
    /// what it would write and stays quiet when they agree, which is what keeps
    /// the loop from putting a raft write through quorum on every tick.
    pub fn member(&self, node_id: super::YubabaNodeId) -> Option<super::MemberInfo> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .members
            .get(&node_id)
            .cloned()
    }

    /// Apply one request directly, bypassing the log. Test-only, and the only
    /// way a router test can seed applied state — `apply` takes an openraft
    /// entry stream, which is a lot of scaffolding to assert that a handler
    /// reads the right field.
    #[cfg(test)]
    pub(crate) fn apply_for_test(&self, req: &super::YubabaRequest) -> super::YubabaResponse {
        let mut guard = self.inner.write().unwrap();
        super::apply(&mut guard.data.state, req)
    }

    /// The cluster's external-ingress owner in this node's applied state.
    ///
    /// Always `None` under [`IngressOwnership::Unmanaged`][io] — the rig preset
    /// — because no node claims it from the raft-leader path there.
    ///
    /// [io]: crate::cluster_policy::IngressOwnership::Unmanaged
    pub fn ingress_owner(&self) -> Option<String> {
        self.inner.read().unwrap().data.state.ingress_owner.clone()
    }

    /// R859-F2: the machine name `node_id` runs on, per its replicated member
    /// row — the half of the identity bridge that turns a consensus/liveness
    /// fact into something the `cloud` config layer can name.
    ///
    /// `None` means *no mapping is recorded*, which covers three cases that
    /// deliberately read the same: the node is not in the member map, it
    /// registered before [`MemberInfo::machine`] existed, or it could not
    /// derive its own machine name. Callers must treat all three as "cannot
    /// resolve", never as a match — an effector that guessed here would
    /// command the wrong box's floating IP.
    pub fn machine_for_node(&self, node_id: super::YubabaNodeId) -> Option<String> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .members
            .get(&node_id)
            .and_then(|m| m.machine.clone())
    }

    /// The inverse of [`Self::machine_for_node`] — which node id runs
    /// `machine`, if any member row claims it.
    ///
    /// This is the direction [`Self::ingress_owner`] needs: `ingress_owner`
    /// holds a machine name, and every liveness/hysteresis judgement is keyed
    /// by [`YubabaNodeId`](super::YubabaNodeId), so answering "is the ingress
    /// owner confirmed down?" means coming back the other way.
    ///
    /// Ties are impossible in practice (each node writes only its own row, from
    /// its own hostname) but are resolved deterministically anyway — the lowest
    /// node id wins, because `members` is a `BTreeMap` and this scans it in
    /// order. A tie would mean two nodes believe they are the same machine,
    /// which is a misconfiguration; picking arbitrarily would make its symptom
    /// depend on map iteration order.
    pub fn node_for_machine(&self, machine: &str) -> Option<super::YubabaNodeId> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .node_for_machine(machine)
    }

    /// Read several parts of applied state **at one applied index**.
    ///
    /// The accessors above each take and release the lock, which is right for a
    /// reader asking one question. It is wrong for a reader whose answer is a
    /// *join* across maps: the membership ratchet (R118-F8) folds peer-liveness
    /// verdicts against the singleton-owner lock and the member rows, and three
    /// separate reads could straddle an apply and produce a decision that was
    /// never true of any single state. Nothing is cloned — `f` borrows.
    ///
    /// Hold it briefly. The lock is the one raft applies into.
    pub fn with_state<T>(&self, f: impl FnOnce(&super::YubabaState) -> T) -> T {
        f(&self.inner.read().unwrap().data.state)
    }

    /// R859-F2 phase A: the whole cluster's declared machines, in the shape the
    /// ingress-failover planner takes.
    ///
    /// This is the fleet-side answer to a question the leader previously could
    /// not ask. `floating_ip::plan_ingress_owner_effect` needs a *fleet* of
    /// declarations to resolve an `ingress_owner` string against, and its other
    /// consumer (`yah cloud apply`) gets that by reading
    /// `.yah/infra/machines/*.toml` — a tree no fleet node has. Each node
    /// publishing its own five declared facts into its member row
    /// ([`member_registration`](crate::member_registration)) reassembles the
    /// same list from the inside.
    ///
    /// # Rows with no machine name are skipped, deliberately
    ///
    /// [`MemberInfo::machine`](super::MemberInfo::machine) is `None` for a node
    /// that pre-dates the field or could not read `/etc/hostname`. A
    /// [`FloatingIpMachine`](floating_ip::FloatingIpMachine) with an empty
    /// `name` would not merely be useless — `resolve_ingress_owner` matches on
    /// `name`, so an empty one is a row that matches nothing, and *several*
    /// empty ones look like a duplicate declaration. Omitting them means an
    /// unresolvable owner refuses loudly (the whole point of that function)
    /// instead of resolving onto a nameless placeholder.
    ///
    /// # This list is comparable to `ingress_owner` by construction
    ///
    /// The gotcha that shadows the `cloud` side of this path — `ingress_owner`
    /// carries `/etc/hostname`, which is not reliably the
    /// `.yah/infra/machines/<name>.toml` name — **does not apply here**, and
    /// that is phase A's quiet win. Both strings come from one function
    /// ([`derive_machine_name`](crate::leader::derive_machine_name)) on one
    /// box, so on the fleet path `resolve_ingress_owner` matches by
    /// construction rather than by luck.
    pub fn floating_ip_machines(&self) -> Vec<floating_ip::FloatingIpMachine> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .members
            .values()
            .filter_map(|m| {
                Some(floating_ip::FloatingIpMachine {
                    name: m.machine.clone()?,
                    provider: m.provider.clone().unwrap_or_default(),
                    location: m.location.clone(),
                    region: m.region.clone(),
                    ingress_floating_ip: m.ingress_floating_ip.clone(),
                })
            })
            .collect()
    }

    /// R859-F2 phase A: the public address `machine` answers on, per its
    /// replicated member row.
    ///
    /// The one fact a withdrawal cannot be performed without.
    /// `IngressOwnerEffect::Withdraw` names a machine, and a Cloudflare record
    /// delete is content-matched (a round-robin apex holds several A records
    /// under one name, so deleting *by name* would take the live origins with
    /// it) — so the effector has to turn the name back into an address before
    /// it can subtract exactly one.
    ///
    /// `None` covers "no such machine", "that node never declared an address",
    /// and "no member row", all of which mean *cannot withdraw*, never *nothing
    /// to withdraw*.
    pub fn public_address_for_machine(&self, machine: &str) -> Option<String> {
        self.inner
            .read()
            .unwrap()
            .data
            .state
            .members
            .values()
            .find(|m| m.machine.as_deref() == Some(machine))
            .and_then(|m| m.public_address.clone())
    }

    /// The raft log index this replica has applied up to, or `None` before the
    /// first entry.
    ///
    /// This is the staleness marker that makes a local read honest: the answer
    /// from [`Self::singleton_owner`] is "true as of this index". A node that
    /// has been out of contact keeps serving reads and this number stops
    /// moving, which is exactly the signal a consumer needs to decide whether
    /// to trust its last-known-good assignment.
    pub fn applied_index(&self) -> Option<u64> {
        self.inner
            .read()
            .unwrap()
            .data
            .last_applied
            .map(|id| id.index)
    }

    /// The whole applied state, and the index it is true as of — the pair
    /// [`crate::state_backup`] ships off-fleet (R869 / W339).
    ///
    /// One read under one lock, deliberately: the accessors above each take the
    /// lock separately, so assembling a copy from them could interleave an
    /// apply and produce a snapshot that was never a state this cluster was in.
    /// The index is `None` when nothing has been applied, which is a cluster
    /// with nothing to back up rather than an empty backup.
    pub fn applied_state(&self) -> (super::YubabaState, Option<u64>) {
        let inner = self.inner.read().unwrap();
        (
            inner.data.state.clone(),
            inner.data.last_applied.map(|id| id.index),
        )
    }
}

/// Seed a **fresh** raft dir with `state` — the restore half of R869 / W339.
///
/// Writes `raft_state.json` with `last_applied: None` and a default membership,
/// so the state machine carries the restored maps while openraft still believes
/// nothing has been applied. That is the truth on a rebuild: the log genuinely
/// is empty, and the founding `init` applies its membership entry at index 1 on
/// top of the seeded state rather than replaying anything.
///
/// Refuses when **any** of the four raft files already exists. A restore is
/// only ever correct against a dir that has no history of its own, and the
/// alternative — merging into a live replica — is the split-brain this whole
/// relay exists to prevent. `raft_state.json` alone would be the tempting
/// check; `open()` reads all four as one unit (R841-B1), so all four are the
/// guard.
pub fn seed_state_machine(dir: &Path, state: &super::YubabaState) -> Result<(), io::Error> {
    std::fs::create_dir_all(dir)?;
    for name in [
        "raft_state.json",
        "raft_log.json",
        "raft_vote.json",
        "raft_meta.json",
    ] {
        if dir.join(name).exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} already holds {name}: a state restore only applies to an empty raft dir. \
                     Stop yubaba and remove raft_state.json / raft_log.json / raft_vote.json / \
                     raft_meta.json together, or point --dir at a fresh one.",
                    dir.display()
                ),
            ));
        }
    }
    let data = StateMachineData {
        last_applied: None,
        last_membership: StoredMembership::default(),
        state: state.clone(),
    };
    let json = serde_json::to_string(&data).map_err(io_other)?;
    write_atomic(&dir.join("raft_state.json"), json.as_bytes())
}

/// Lower-case hex encoding. No `hex` crate dep in this crate; a digest is
/// rendered a handful of times per `GET /secrets`, not a hot path, so a
/// one-line encoder beats pulling in a dependency for it.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl RaftSnapshotBuilder<TC> for YubabaStateMachine {
    type SnapshotData = SnapshotData;

    async fn build_snapshot(&mut self) -> Result<SnapshotOf<TC, SnapshotData>, io::Error> {
        let inner = self.inner.read().unwrap();
        let bytes = serde_json::to_vec(&inner.data).map_err(io_other)?;
        let snapshot_id = inner
            .data
            .last_applied
            .map(|id| format!("{}-{}", id.leader_id, id.index))
            .unwrap_or_else(|| "empty".to_string());
        let meta = SnapshotMeta {
            last_log_id: inner.data.last_applied,
            last_membership: inner.data.last_membership.clone(),
            snapshot_id,
        };
        Ok(Snapshot {
            meta,
            snapshot: Cursor::new(bytes),
        })
    }
}

impl RaftStateMachine<TC> for YubabaStateMachine {
    type SnapshotData = SnapshotData;
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogIdOf<TC>>, StoredMembershipOf<TC>), io::Error> {
        let inner = self.inner.read().unwrap();
        Ok((inner.data.last_applied, inner.data.last_membership.clone()))
    }

    async fn apply<Strm>(&mut self, mut entries: Strm) -> Result<(), io::Error>
    where
        Strm: Stream<Item = Result<EntryResponder<TC>, io::Error>> + Unpin + OptionalSend,
    {
        // Drain the stream first (await here holds NO lock), then apply under the
        // sync lock, then deliver responses after releasing it. This keeps the
        // std `RwLock` guard off every `.await` point.
        let mut items = Vec::new();
        while let Some(item) = entries.next().await {
            items.push(item?);
        }

        let mut pending = Vec::with_capacity(items.len());
        let mut secrets_changed = false;
        {
            let mut inner = self.inner.write().unwrap();
            for (entry, responder) in items {
                let log_id = entry.log_id;
                inner.data.last_applied = Some(log_id);
                let resp = match entry.payload {
                    EntryPayload::Blank => YubabaResponse::Ok,
                    EntryPayload::Normal(req) => {
                        if matches!(
                            req,
                            YubabaRequest::PutSecret { .. } | YubabaRequest::DeleteSecret { .. }
                        ) {
                            secrets_changed = true;
                        }
                        apply(&mut inner.data.state, &req)
                    }
                    EntryPayload::Membership(membership) => {
                        inner.data.last_membership =
                            StoredMembership::new(Some(log_id), membership);
                        YubabaResponse::Ok
                    }
                };
                pending.push((responder, resp));
            }

            inner.persist()?;
            // Notify AFTER persist so a woken consumer that re-reads observes
            // durable state. Coalesced into one bump per batch.
            if secrets_changed {
                inner.secrets_epoch.send_modify(|e| *e = e.wrapping_add(1));
            }
        }

        // Responders are notified after the lock is dropped.
        for (responder, resp) in pending {
            if let Some(responder) = responder {
                responder.send(resp);
            }
        }
        Ok(())
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<SnapshotData, io::Error> {
        Ok(Cursor::new(Vec::new()))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMetaOf<TC>,
        snapshot: SnapshotData,
    ) -> Result<(), io::Error> {
        let bytes = snapshot.into_inner();
        let data: StateMachineData = serde_json::from_slice(&bytes).map_err(io_other)?;
        let mut inner = self.inner.write().unwrap();
        inner.data = data;
        inner.data.last_applied = meta.last_log_id;
        inner.data.last_membership = meta.last_membership.clone();
        inner.snapshot_meta = Some(meta.clone());
        inner.snapshot_bytes = Some(bytes);
        inner.persist()?;
        // A snapshot install can replace the secrets map wholesale (a follower
        // catching up), so notify unconditionally — diffing isn't worth it at
        // KB scale, and the subscriber's re-render is idempotent.
        inner.secrets_epoch.send_modify(|e| *e = e.wrapping_add(1));
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<SnapshotOf<TC, SnapshotData>>, io::Error> {
        let inner = self.inner.read().unwrap();
        match (&inner.snapshot_meta, &inner.snapshot_bytes) {
            (Some(meta), Some(bytes)) => Ok(Some(Snapshot {
                meta: meta.clone(),
                snapshot: Cursor::new(bytes.clone()),
            })),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::testing::log_id;

    fn normal_entry(index: u64, req: YubabaRequest) -> EntryOf<TC> {
        openraft::Entry {
            log_id: log_id::<TC>(1, 1, index),
            payload: EntryPayload::Normal(req),
        }
    }

    // R600-F4: the secrets-change watch fires for cluster-secret writes only.
    #[tokio::test]
    async fn secret_writes_bump_the_epoch_but_other_writes_do_not() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut sm = YubabaStateMachine::open(tmp.path().to_path_buf())
            .await
            .unwrap();
        let mut rx = sm.subscribe_secrets();
        assert_eq!(*rx.borrow_and_update(), 0);

        apply_one(
            &mut sm,
            normal_entry(
                1,
                YubabaRequest::PutSecret {
                    name: "tls/yah.dev/cert".into(),
                    ciphertext: vec![1, 2, 3],
                    nonce: vec![0; 12],
                    updated_at: 1,
                    access: workload_spec::secrets::SecretAccess::AllowAny,
                    digest: None,
                    sans: None,
                    ari: None,
                },
            ),
        )
        .await;
        assert!(rx.has_changed().unwrap(), "PutSecret should notify");
        assert_eq!(*rx.borrow_and_update(), 1);

        // A non-secret write must not wake secret consumers.
        apply_one(
            &mut sm,
            normal_entry(
                2,
                YubabaRequest::SetIngressOwner {
                    machine: "m1".into(),
                },
            ),
        )
        .await;
        assert!(
            !rx.has_changed().unwrap(),
            "non-secret write must not notify"
        );

        apply_one(
            &mut sm,
            normal_entry(
                3,
                YubabaRequest::DeleteSecret {
                    name: "tls/yah.dev/cert".into(),
                },
            ),
        )
        .await;
        assert!(rx.has_changed().unwrap(), "DeleteSecret should notify");
        assert_eq!(*rx.borrow_and_update(), 2);
    }

    /// Apply a single entry through the 0.10 stream/responder `apply` API with
    /// no client responder attached (as a follower would).
    async fn apply_one(sm: &mut YubabaStateMachine, entry: EntryOf<TC>) {
        let item: Result<EntryResponder<TC>, io::Error> = Ok((entry, None));
        let stream = tokio_stream::iter(vec![item]);
        sm.apply(stream).await.unwrap();
    }

    // ── R841-B1: cold start after a purge ─────────────────────────────────────

    fn blank_entry(index: u64) -> EntryOf<TC> {
        openraft::Entry {
            log_id: log_id::<TC>(1, 1, index),
            payload: EntryPayload::Blank,
        }
    }

    /// Seed `raft_log.json` the way a pre-R841-B1 binary left it: entries from
    /// `first..=last` and nothing on disk saying anything below `first` was ever
    /// purged.
    fn seed_purged_log(dir: &Path, first: u64, last: u64) {
        let entries: BTreeMap<u64, EntryOf<TC>> =
            (first..=last).map(|i| (i, blank_entry(i))).collect();
        std::fs::write(
            dir.join("raft_log.json"),
            serde_json::to_string(&entries).unwrap(),
        )
        .unwrap();
    }

    /// Seed `raft_state.json` with an applied watermark and otherwise-empty
    /// state.
    fn seed_applied(dir: &Path, last_applied: Option<LogIdOf<TC>>) {
        let data = StateMachineData {
            last_applied,
            ..StateMachineData::default()
        };
        std::fs::write(
            dir.join("raft_state.json"),
            serde_json::to_string(&data).unwrap(),
        )
        .unwrap();
    }

    /// The marker `purge()` records must outlive the process. Before R841-B1 it
    /// did not: it was an in-memory field, so a restart reported "nothing was
    /// ever purged" over a log that no longer began at index 0.
    #[tokio::test]
    async fn a_purge_marker_survives_a_cold_start() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        {
            let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
            let entries: Vec<EntryOf<TC>> = (0..=10).map(blank_entry).collect();
            log.append(entries, IOFlushed::noop()).await.unwrap();
            log.purge(log_id::<TC>(1, 1, 5)).await.unwrap();
        }

        let mut reopened = YubabaLogStore::open(dir).await.unwrap();
        let st = reopened.get_log_state().await.unwrap();
        assert_eq!(
            st.last_purged_log_id,
            Some(log_id::<TC>(1, 1, 5)),
            "the purge marker must be read back from disk, not reset to None"
        );
        assert_eq!(st.last_log_id, Some(log_id::<TC>(1, 1, 10)));
    }

    /// The incident itself, through the code path that actually failed:
    /// `Raft::new` calls `StorageHelper::get_initial_state`, which asks the log
    /// reader for `last_purged_log_id.next_index()`. With no marker that is
    /// index 0 — purged, absent — and every production voter died with
    /// `when Read LogIndex(0): log entry not found`.
    ///
    /// FALSIFIED, not assumed: forcing `open` to hand back
    /// `last_purged_log_id: None` (the pre-R841-B1 behaviour) fails this test
    /// with `StorageError { subject: LogIndex(0), verb: Read, source: log entry
    /// not found }` — the production error verbatim — and takes the three
    /// marker tests around it down with it, while the hole and committed tests
    /// stay green. Probe removed.
    #[tokio::test]
    async fn a_purged_log_can_still_produce_an_initial_state() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        {
            let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
            let entries: Vec<EntryOf<TC>> = (0..=10).map(blank_entry).collect();
            log.append(entries, IOFlushed::noop()).await.unwrap();
            log.purge(log_id::<TC>(1, 1, 5)).await.unwrap();
        }

        let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
        let mut sm = YubabaStateMachine::open(dir).await.unwrap();
        openraft::StorageHelper::new(&mut log, &mut sm)
            .with_id(1)
            .get_initial_state()
            .await
            .expect("a voter that has purged its log must be able to cold-start");
    }

    /// Migration, exact case 1: the state machine sits exactly at the purge
    /// point, so `last_applied` *is* the purged log id.
    #[tokio::test]
    async fn a_pre_r841_log_takes_its_marker_from_a_last_applied_at_the_purge_point() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        seed_purged_log(&dir, 6, 10);
        seed_applied(&dir, Some(log_id::<TC>(1, 1, 5)));

        let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
        let st = log.get_log_state().await.unwrap();
        assert_eq!(st.last_purged_log_id, Some(log_id::<TC>(1, 1, 5)));

        // One-shot: the reconstruction is written out, so the next open reads it
        // back rather than re-deriving it.
        assert!(dir.join("raft_meta.json").exists());
        let mut again = YubabaLogStore::open(dir).await.unwrap();
        assert_eq!(
            again.get_log_state().await.unwrap().last_purged_log_id,
            Some(log_id::<TC>(1, 1, 5))
        );
    }

    /// Migration, exact case 2 — the shape the live fleet was in (log
    /// 189000..193466, applied well past the start). The first surviving entry
    /// is itself already applied, so its own log id is an exact marker; no term
    /// is invented.
    #[tokio::test]
    async fn a_pre_r841_log_applied_past_its_start_adopts_the_first_entrys_log_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        seed_purged_log(&dir, 6, 10);
        seed_applied(&dir, Some(log_id::<TC>(1, 1, 10)));

        let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
        let st = log.get_log_state().await.unwrap();
        assert_eq!(st.last_purged_log_id, Some(log_id::<TC>(1, 1, 6)));
        assert_eq!(st.last_log_id, Some(log_id::<TC>(1, 1, 10)));

        // And that is enough for openraft's startup read to resolve.
        let mut sm = YubabaStateMachine::open(dir).await.unwrap();
        openraft::StorageHelper::new(&mut log, &mut sm)
            .with_id(1)
            .get_initial_state()
            .await
            .expect("the migrated marker must satisfy openraft's startup read");
    }

    /// A log purged past what the state machine ever applied is a hole. There is
    /// no marker that makes that replica startable, so `open` refuses instead of
    /// guessing a term openraft would then fail every consistency check against.
    #[tokio::test]
    async fn a_log_purged_past_the_applied_state_refuses_to_open() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        seed_purged_log(&dir, 6, 10);
        seed_applied(&dir, Some(log_id::<TC>(1, 1, 3)));

        let Err(err) = YubabaLogStore::open(dir).await else {
            panic!("a hole between the applied state and the log must not open");
        };
        let msg = err.to_string();
        assert!(msg.contains("starts at index 6"), "{msg}");
        assert!(msg.contains("re-join the cluster"), "{msg}");
    }

    /// The 2026-08-31 recovery runbook says "delete raft_log.json /
    /// raft_state.json / raft_vote.json and re-init" — it predates
    /// `raft_meta.json`, so anyone running it from memory leaves a purge marker
    /// standing over a wiped dir. That must not brick the fresh node.
    #[tokio::test]
    async fn a_marker_left_behind_by_a_partial_wipe_is_dropped() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        {
            let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
            let entries: Vec<EntryOf<TC>> = (0..=10).map(blank_entry).collect();
            log.append(entries, IOFlushed::noop()).await.unwrap();
            log.purge(log_id::<TC>(1, 1, 5)).await.unwrap();
        }
        // The runbook's three deletions, verbatim — raft_meta.json survives.
        for f in ["raft_log.json", "raft_state.json", "raft_vote.json"] {
            let _ = std::fs::remove_file(dir.join(f));
        }
        assert!(dir.join("raft_meta.json").exists());

        let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
        assert_eq!(
            log.get_log_state().await.unwrap().last_purged_log_id,
            None,
            "a stale marker over a wiped dir must not survive"
        );
        drop(log);

        // …and the node it produces must actually be foundable. This half is
        // what makes the guard load-bearing rather than tidy, and it was
        // MEASURED: with the drop disabled, `get_initial_state` still succeeds
        // (a stale marker over an empty log does not trip openraft's startup
        // read), and the founding init then panics inside openraft's own
        // invariant — `expect: &self.purged(Some(LogId { .. index: 5 })) <=
        // &self.snapshot.flushed()(None)`, validit via io_state.rs:181. So only
        // driving init distinguishes the two states, which is why this test
        // pays for a real raft node.
        let raft = crate::raft::open(1, dir, &crate::cluster_policy::ClusterPolicy::default())
            .await
            .unwrap();
        crate::raft::bootstrap_single_node(&raft, 1, "127.0.0.1:1")
            .await
            .expect("a wiped raft dir must be foundable as a fresh cluster");
        raft.shutdown().await.unwrap();
    }

    /// `save_committed` is optional per openraft's trait, but a node that drops
    /// it recovers only as far as its snapshot and can serve a read older than
    /// one it already served before the restart. Persist it.
    #[tokio::test]
    async fn the_committed_watermark_survives_a_cold_start() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        {
            let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
            log.save_committed(Some(log_id::<TC>(1, 1, 7)))
                .await
                .unwrap();
        }

        let mut reopened = YubabaLogStore::open(dir).await.unwrap();
        assert_eq!(
            reopened.read_committed().await.unwrap(),
            Some(log_id::<TC>(1, 1, 7))
        );
    }

    /// An interrupted write must never leave a half-written file behind, since
    /// `open` refuses to start on one. The rename is the guarantee; this pins
    /// that the temp file is a sibling that gets cleaned up rather than left
    /// beside the real one.
    #[tokio::test]
    async fn writes_land_atomically_and_leave_no_temp_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        let mut log = YubabaLogStore::open(dir.clone()).await.unwrap();
        log.append(vec![blank_entry(0)], IOFlushed::noop())
            .await
            .unwrap();
        log.save_committed(Some(log_id::<TC>(1, 1, 0)))
            .await
            .unwrap();
        log.purge(log_id::<TC>(1, 1, 0)).await.unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    // ── R869 / W339: the off-fleet copy's two ends ───────────────────────────

    fn placed(service: &str, machine: &str) -> super::super::YubabaState {
        super::super::YubabaState {
            service_placement: BTreeMap::from([(service.to_string(), machine.to_string())]),
            ..Default::default()
        }
    }

    /// A seeded dir opens as a state machine holding the restored maps while
    /// still reporting nothing applied — which is the truth on a rebuild, and
    /// what lets the founding `init` land its membership at index 1 on top.
    #[tokio::test]
    async fn a_seeded_dir_opens_with_the_state_and_no_applied_index() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        seed_state_machine(&dir, &placed("web", "us-west-001")).unwrap();

        let sm = YubabaStateMachine::open(dir.clone()).await.unwrap();
        let (state, applied) = sm.applied_state();
        assert_eq!(state.service_placement["web"], "us-west-001");
        assert_eq!(applied, None);

        // And the log half of the same dir is startable: an empty log with a
        // seeded state machine reconstructs no purge marker (the case
        // `reconstruct_last_purged` closes with `Ok(None)`), so a founding
        // voter boots instead of refusing.
        let log = YubabaLogStore::open(dir).await.unwrap();
        assert!(log.inner.read().unwrap().last_purged_log_id.is_none());
    }

    /// A restore is only ever correct against a dir with no history of its own.
    /// All four files guard it, not just `raft_state.json` — `open()` reads them
    /// as one unit (R841-B1), so a dir holding any one of them has a history.
    #[tokio::test]
    async fn seeding_refuses_every_raft_file_that_already_exists() {
        for name in [
            "raft_state.json",
            "raft_log.json",
            "raft_vote.json",
            "raft_meta.json",
        ] {
            let tmp = tempfile::TempDir::new().unwrap();
            let dir = tmp.path().to_path_buf();
            std::fs::write(dir.join(name), b"{}").unwrap();

            let err = seed_state_machine(&dir, &placed("web", "us-west-001")).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{name}");
            assert!(err.to_string().contains(name), "{name}: {err}");
            // Refusing means refusing: nothing was written alongside it.
            assert!(
                !dir.join("raft_state.json").exists() || name == "raft_state.json",
                "{name}: seeded anyway"
            );
        }
    }

    /// `applied_state` reads the state and its index under one lock, so the
    /// pair the backup ships is a state this cluster was actually in.
    #[tokio::test]
    async fn applied_state_reports_the_index_the_state_is_true_as_of() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut sm = YubabaStateMachine::open(tmp.path().to_path_buf())
            .await
            .unwrap();
        apply_one(
            &mut sm,
            normal_entry(
                4,
                YubabaRequest::SetServicePlacement {
                    service: "web".into(),
                    machine: "us-west-001".into(),
                },
            ),
        )
        .await;

        let (state, applied) = sm.applied_state();
        assert_eq!(applied, Some(4));
        assert_eq!(state.service_placement["web"], "us-west-001");
    }

    /// R859-F2 phase A: the member map reassembles the fleet's declarations
    /// into the shape `floating_ip::plan_ingress_owner_effect` takes — the list
    /// `yah cloud apply` reads out of `.yah/infra/machines/*.toml` and a fleet
    /// node cannot.
    ///
    /// Two properties, and the second is the load-bearing one: a row with no
    /// machine name is **omitted**, not included with an empty `name`. An empty
    /// name matches no `ingress_owner`, so including it would turn a clean
    /// "cannot resolve — refusing" into a list whose entries silently cannot be
    /// looked up, and two such rows would look like a duplicate declaration.
    #[tokio::test]
    async fn the_member_map_reassembles_the_fleets_declarations() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut sm = YubabaStateMachine::open(tmp.path().to_path_buf())
            .await
            .unwrap();
        let rows = [
            (
                1u64,
                Some("us-west-001"),
                Some("hetzner"),
                Some("hil"),
                Some("fip-42"),
                Some("15.204.89.240"),
            ),
            (
                2,
                Some("us-east-001"),
                Some("static"),
                None,
                None,
                Some("51.81.85.145"),
            ),
            // A node that pre-dates `MemberInfo::machine`, or could not read
            // its own hostname. Unresolvable by name, so it must not appear.
            (3, None, Some("static"), None, None, Some("45.32.194.254")),
        ];
        for (index, (node_id, machine, provider, location, ip, public)) in
            rows.into_iter().enumerate()
        {
            apply_one(
                &mut sm,
                normal_entry(
                    index as u64 + 1,
                    YubabaRequest::SetMember {
                        node_id,
                        addr: format!("100.64.0.{node_id}:7443"),
                        region: Some("us-west".into()),
                        capacity: None,
                        machine: machine.map(str::to_string),
                        provider: provider.map(str::to_string),
                        location: location.map(str::to_string),
                        ingress_floating_ip: ip.map(str::to_string),
                        public_address: public.map(str::to_string),
                    },
                ),
            )
            .await;
        }

        let machines = sm.floating_ip_machines();
        assert_eq!(
            machines.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            vec!["us-west-001", "us-east-001"],
            "a member row with no machine name has no name to resolve against and must be \
             omitted, not carried as an empty-named entry"
        );
        // The five-field contract, end to end: what a node declared on its
        // flags is what the planner reads.
        let west = &machines[0];
        assert_eq!(west.provider, "hetzner");
        assert_eq!(west.location.as_deref(), Some("hil"));
        assert_eq!(west.region.as_deref(), Some("us-west"));
        assert_eq!(west.ingress_floating_ip.as_deref(), Some("fip-42"));
        // `resolve_ingress_owner` matches on exactly this, so the round trip
        // through the member map has to preserve it byte for byte.
        assert!(floating_ip::resolve_ingress_owner("us-west-001", &machines).is_ok());
        assert!(
            floating_ip::resolve_ingress_owner("vps-4c1efa56", &machines).is_err(),
            "an owner naming no declared machine must refuse, not resolve onto the nameless row"
        );

        assert_eq!(
            sm.public_address_for_machine("us-west-001").as_deref(),
            Some("15.204.89.240")
        );
        assert_eq!(
            sm.public_address_for_machine("us-east-001").as_deref(),
            Some("51.81.85.145")
        );
        assert_eq!(
            sm.public_address_for_machine("us-south-001"),
            None,
            "an unknown machine has no address to withdraw — never a fallback one"
        );
    }
}
