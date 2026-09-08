//! Litestream sidecar management for Headscale HA (R040-F21).
//!
//! On Phase 2 leader election:
//! 1. Run `litestream restore` to pull the latest Headscale SQLite snapshot
//!    from S3 before starting Headscale.
//! 2. Enable + start `litestream-replicate.service` so WAL frames are
//!    continuously streamed to S3 while this node is the leader.
//!
//! On leadership loss:
//! 1. Stop `litestream-replicate.service` so only the leader replicates.
//!    (Followers pre-warm by periodic snapshot pulls — not implemented here
//!    yet; relevant only when promotion latency matters at >100 nodes.)
//!
//! ## Credentials
//!
//! Litestream reads S3 credentials from environment variables:
//!   `LITESTREAM_ACCESS_KEY_ID` / `LITESTREAM_SECRET_ACCESS_KEY`
//! These must be present in the systemd unit's environment (via
//! `EnvironmentFile=/etc/yah-cloud/litestream.env` or a direct
//! `Environment=` directive).  The yubaba does not manage the credentials
//! themselves; inject them at provision time via cloud-init.
//!
//! ## S3 URL format
//!
//! `s3://bucket/prefix?endpoint=https://fsn1.your-objectstorage.com`
//!
//! The `?endpoint=` query parameter is passed through to litestream's
//! `endpoint` config key (Hetzner Object Storage, Backblaze B2, MinIO, etc.).
//!
//! @yah:ticket(R591-T3, "Turn on litestream DB continuity end-to-end (--litestream-s3-url + restore-on-place)")
//! @yah:status(review)
//! @yah:at(2026-08-12T21:52:38Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R591)
//! @yah:next("Set --litestream-s3-url so leader.rs::on_became_leader's litestream restore + replicate sidecar actually run; verify a freshly-placed node restores headscale.db from S3 before it starts serving. Async replication = small RPO (a few writes) on failover — acceptable for headscale's low, mostly-static write rate.")
//! @yah:handoff("THE PATH WAS NOT MERELY UNCONFIGURED - IT WAS BROKEN IN THREE PLACES, and setting --litestream-s3-url alone would have replicated nothing. All three are fixed. (1) litestream::install() was DEAD CODE: grep across oss/yubaba + app/ found callers for restore/start/stop and none for install, so /etc/yah-cloud/litestream.yml was never written on any node. Both consumers name that path, so every restore failed at 'no such file' into a warn! and every systemctl start ran against a unit that had never been written, into a discarded exit status. leader.rs::on_became_leader now calls install() before restore. (2) generate_config emitted MALFORMED YAML. (3) The sidecar unit was bound to a systemd unit R591-F1 retires.")
//! @yah:handoff("DEFECT 2, THE MALFORMED YAML, and it was invisible by construction. generate_config built the file with one format! whose `\\` line-continuation stripped the leading whitespace of the continued line, so access-key-id landed at COLUMN 0 instead of 8 - a top-level key, not a sibling of `- url:`, leaving the replica with no credentials at all. The pre-existing test passed straight through it because it only asked whether the string LITESTREAM_ACCESS_KEY_ID appeared somewhere in the output. Rebuilt as explicit pushes against a named REPLICA_KEY_INDENT constant. FALSIFIED, NOT ASSUMED: I restored the old format string behind a probe and re-ran - every_replica_key_is_indented_under_its_url FAILS with `left: 0, right: 8`, the exact bug, and passes with the fix. Probe removed; grep FALSIFICATION PROBE in litestream.rs returns nothing.")
//! @yah:handoff("DEFECT 3 IS AN F1 INTERACTION, so it had to be caught in this pass rather than filed. The sidecar unit carried BindsTo=headscale.service and WantedBy=headscale.service. R591-F1 re-homes headscale onto kamaji and DISABLES that systemd unit, so on a re-homed node BindsTo would have stopped replication the instant it started, and the [Install] target orders against a unit that never runs. The unit now has no reference to headscale.service and no [Install] section at all - it is never enabled, only started and stopped by leader.rs, which is the actual lifecycle owner. Restart is also on-failure -> always, the same lesson as the appliance: a replicate process that exits 0 has stopped replicating.")
//! @yah:gotcha("THE DB IS NOT THE WHOLE OF CONTINUITY, and litestream structurally cannot carry the rest. noise_private.key (72 bytes, /var/lib/yah-cloud/headscale/) is the appliance's IDENTITY, not its data: move the appliance without it and EVERY node's stored server identity mismatches at once - a worse outage than the one this relay is fixing, because it is silent and fleet-wide. The mechanism is R600/W273's raft-replicated cluster secret store (SecretRef::Cluster + SecretMount Cluster->File), the same one standing up for TLS certs. Do NOT invent a second secret path for it. Recorded in headscale_appliance.rs's module docs under 'What is NOT here' so the next reader of the spec meets it there.")
//! @yah:next("THE ACME-CACHE BULLET, CORRECTED: it said 'with TLS moved to the CF edge (R591-T2)'. T2's premise was reframed on 2026-08-12 - TLS now terminates at the fleet's own passway front doors, not a rented edge. The CONCLUSION is unchanged and still the reason this matters: once headscale stops terminating its own Let's Encrypt, the acme-cache is no longer state that has to survive a failover, which removes the one piece litestream does not carry. Only the mechanism changed.")
//! @yah:next("I DID NOT SET --litestream-s3-url, and deliberately did not invent a value. There is NO litestream bucket declared anywhere in the tree - grep over .yah/infra/ and .yah/docs/guides/ returns nothing - so the URL, the provider and the credentials are all an operator decision, not a default I could defend. Everything downstream of that decision is now built and tested. To turn it on: (1) create the bucket and note its s3://bucket/prefix?endpoint=... URL; (2) write LITESTREAM_ACCESS_KEY_ID / LITESTREAM_SECRET_ACCESS_KEY into /etc/yah-cloud/litestream.env on each candidate node (the sidecar unit already reads it via EnvironmentFile=-); (3) add --litestream-s3-url <URL> to yubaba.service's ExecStart (app/yah/cli/resources/yubaba.service:47) and roll it. On the next leadership transition install() writes the config + unit, restore runs, and the sidecar starts.")
//! @yah:next("THE VERIFICATION THIS TICKET ASKS FOR ('a freshly-placed node restores headscale.db from S3 before it starts serving') IS NOW ORDERED CORRECTLY IN CODE - install -> restore -> start the appliance -> start the sidecar, in on_became_leader - but has NOT been exercised against a real bucket. Do that on the dev cluster (us-west-011/013/014), which is the sanctioned testbed, not on prod.")
//! @yah:verify("cargo test -p yubaba --lib = 435 passed / 0 failed (was 417 at the start of this relay). 5 new litestream tests: every_replica_key_is_indented_under_its_url (the falsified one, both with and without an endpoint), the_endpoint_query_becomes_a_key_and_leaves_the_url, the_sidecar_is_not_bound_to_the_retired_headscale_unit, the_sidecar_restarts_on_a_graceful_exit, the_unit_and_the_restore_share_one_config_path.")
//! @yah:verify("cargo check -p yubaba clean; cargo clippy -p yubaba --lib reports zero warnings on litestream.rs, leader.rs or headscale_appliance.rs (10 crate-wide warnings, all pre-existing and on untouched files - same count as before this relay).")
//! @yah:verify("The unit text is now generated by one function used by BOTH install() and the tests, so a directive can no longer be asserted in a copy that has drifted from what is written to /etc/systemd/system.")
//! @yah:gotcha("SUPERSEDED IN PART BY R858 (2026-09-04) — two claims in this ticket's own annotations are now false, and a reader will go looking for code that is gone. (1) LITESTREAM_CONFIG_PATH is no longer /etc/yah-cloud/litestream.yml; it is /var/lib/yah/yubaba/litestream.yml. The /etc path could never work: yubaba.service sets ProtectSystem=strict and grants no path under /etc, so install()'s write was EROFS on every fleet node and leader.rs absorbed the Err into a warn!. That was a FOURTH defect on this path, and it defeated this ticket's three fixes. (2) The verify line \"the unit text is now generated by one function used by BOTH install() and the tests\" no longer holds — unit_text() is DELETED. The unit is static, yubaba was never permitted to write it, so it now ships in the release tarball as app/yah/cli/resources/litestream-headscale.service and its directive assertions live in app/yah/cli/tests/camp_systemd_unit_emit.rs. This ticket's remaining next (\"exercise against a real bucket\") is now R858-T5; the bucket it lacked exists.")
//!
//! @yah:ticket(R858-T5, "Prove litestream restore-before-serve against the real bucket on the dev cluster")
//! @yah:at(2026-09-04T19:44:59Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:next("Tier: Cleric — the code path is built and unit-tested; this is the live exercise it has never had.")
//! @yah:gotcha("R591-T3 asked for exactly this and could not do it (no bucket existed). The bucket now exists and everything downstream is built, so this is the ticket that turns \"ordered correctly in code\" into \"observed working\". ON THE DEV CLUSTER (us-west-011/013/014), NOT PROD — R591-T2 and T3 both say so, and us-west-011 was online 2026-09-04.")
//! @yah:next("RUNBOOK. (1) On each dev node write /etc/yah-cloud/litestream.env with YUBABA_LITESTREAM_S3_URL=s3://yah-headscale/dev?endpoint=https://3948dc292e724e71b0deefde0ea95999.r2.cloudflarestorage.com plus LITESTREAM_ACCESS_KEY_ID / LITESTREAM_SECRET_ACCESS_KEY from vault slots cloudflare-r2-access-key-id / cloudflare-r2-secret-key. USE A `dev` PREFIX, NOT `headscale` — do not let a dev cluster's replica land on the prefix prod will restore from. (2) Roll a yubaba carrying this session's changes (the unit and the litestream binary now arrive via cloud-init/tarball, so an existing node needs scripts/roll-node.sh, not just a restart). (3) Force a leadership transition and watch on_became_leader's ordering: install -> restore -> deploy appliance -> start sidecar. (4) The assertion that matters is RESTORE-BEFORE-SERVE, so seed a row into the dev headscale DB, let it replicate, transfer leadership, and confirm the row is present on the NEW node BEFORE it answers — not merely that the file exists.")
//! @yah:gotcha("`litestream restore` is called with -if-replica-exists, so it is a NO-OP when the prefix is empty and returns success. A first run therefore proves nothing about restore; it only proves the config parsed. Seed the replica first or the test passes vacuously — which is the same trap R591-T3's malformed-YAML bug hid behind.")
//!
//! @yah:ticket(R858-S6, "Can turso-backup replace litestream as the headscale DB replicator?")
//! @yah:status(review)
//! @yah:at(2026-09-06T09:31:39Z)
//! @yah:kind(spike)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:next("Tier: Cleric — one focused compatibility question with a clear yes/no, and a real payoff either way.")
//! @yah:gotcha("THE PREMISE THAT MAKES THIS WORTH ASKING: turso-backup and litestream do the SAME JOB. Both tail a sqlite WAL to S3-compatible storage and restore by replay. turso-backup additionally carries two-level fencing (R732-F2), an RPO watermark (R574-T4), bounded spill backpressure, one-puller-per-box fan-out, and frame batching (R761-F2) — none of which litestream has. It is ours, in-tree, and versioned with everything else. R858 pinned litestream to 0.3.13 with hand-computed checksums and an arch switch in cloud-init BECAUSE 0.5.x is the incompatible LTX rewrite; adopting turso-backup deletes that pin, the third-party download, and the version-migration problem in one move. NOTE oss/turso-backup is a SUBCAMP (its own .yah/camp.toml) so it is outside this board's scan set — this annotation is deliberately homed on the yubaba side, in the module the swap would replace.")
//! @yah:gotcha("THE CORE COMPATIBILITY QUESTION IS ANSWERED: YES. Probed 2026-09-04 by @Ashguard:dragon. turso_core CAN read a WAL written by upstream C SQLite — i.e. by a foreign process such as headscale's Go driver. METHOD, so it can be rebuilt as a proper test: create a WAL-mode db with the SYSTEM sqlite3 binary (3.32.2, upstream C — the writer must NOT be turso or the probe is circular); write two more rows from a second sqlite3 process and KILL -9 it mid-session so the frames stay uncheckpointed (sqlite CHECKPOINTS ON CLEAN CLOSE — my first attempt left a 0-byte WAL and was vacuous, which is the trap here); then call `turso_backup::stream::raw_consistent_copy_live(path, 4096)`. RESULT: Ok, 12288 bytes, header \"SQLite format 3\\0\", and reading the restored image back with upstream sqlite3 returned 5 rows — including the 2 that existed ONLY in the foreign-written WAL. So the frames were genuinely parsed and replayed across engines, not skipped.")
//! @yah:next("SPLIT THE TICKET IN TWO — HYDRATION AND REPLICATION ARE INDEPENDENT, AND ONLY ONE OF THEM IS HARD. (1) HYDRATION (cold start / catastrophic loss) NEEDS NO FOREIGN-PROCESS INTERACTION AT ALL: restore = fetch base snapshot + replay frames -> write a plain sqlite file at headscale's `database.sqlite.path` -> THEN start headscale. turso-backup already emits exactly that artifact — its own docs say \"a self-contained vanilla-SQLite image (page-offset stable, no -wal sidecar required)\", and the probe above confirmed upstream sqlite reads it. headscale opens a file that is already correct and never learns R2 exists. This is W338's Job-archetype restore step, `local` + `self`, and it is safe to build FIRST and independently. (2) REPLICATION (steady state) is the leg that reads a live foreign WAL; the format question is now answered, so what remains is operational — checkpoint races, and whether headscale's own autocheckpoint can fold frames out from under a tail between calls.")
//! @yah:gotcha("MOST OF THIS WAS ALREADY BUILT — R005-F4 (status: review, annotated in oss/turso-backup/src/stream.rs) is exactly \"Concurrent-writer-safe raw copy: read-only main + WAL-frame replay (no TRUNCATE-checkpoint dependency), for backing up under a live writer\". Its `raw_consistent_copy_live` opens a turso_core connection with `wal_auto_actions_disable()` so it cannot fold the WAL, reads the main file, walks frames 1..=max_frame, applies up to the last commit frame and drops the uncommitted tail. Its doc already states the foreign-writer premise: \"a concurrent writer in a separate connection only ever extends the WAL (the main file is only written by a checkpoint)\". And `tail_frames` is generic over `WalSeam` and only READS — it does not require writes to flow through turso. So the architecture was foreign-writer-shaped all along; the only untested leg was the cross-engine WAL FORMAT, and that is the leg just proved.")
//! @yah:assumes("REMAINING UNKNOWN, narrowed from the original: not the format, but the CHECKPOINT RACE. `tail_frames` resumes from a watermark of (checkpoint_seq, max_frame); headscale runs its own connection with its own autocheckpoint policy, so it can fold WAL frames into the main file between two tail calls. stream.rs already handles a checkpoint_seq advance by treating it as a restart and re-uploading 1..=max_frame, so the mechanism exists — but it has never been exercised against a writer whose checkpoints we neither trigger nor observe. Measure the actual fold rate on headscale's live db before assuming the restart path is cheap: the WAL was 8.4 MB on 2026-09-04 against a 94 KB main file, which suggests headscale is NOT checkpointing aggressively and the restart path may be rare.")
//! @yah:handoff("WHAT DID NOT HAPPEN, stated plainly because the above reads like a lot: NO live box was touched, no ssh, no network beyond cargo's registry. No production code changed — the only edits are a new example file and its [[example]] stanza in oss/turso-backup/Cargo.toml. litestream is untouched and remains the replicator; R858's 0.3.13 pin and its hand-computed checksums stay exactly as they are, and this spike does NOT authorise deleting them. leader.rs was not opened (held by @Ashguard:golem and @Ashguard:coffee). Nothing was committed.")
//! @yah:verify("REPRODUCE ANY CLAIM: `cd oss/turso-backup && cargo run --example foreign_checkpoint_probe` runs all probes; pass letters to select (a = process-restart regime, b = fold then shorter WAL, f = fold then longer WAL, c = hydration, d = liveness under a held seam, g = mutual exclusion + lock bypass, e = default autocheckpoint fold rate). `PROBE_SQLITE3=/path/to/sqlite3` swaps the foreign writer; the run prints the version it used and a non-upstream binary invalidates the whole run. Probe D is watchdogged — the first version of it hung for ten minutes, which was itself the first sign of Finding 1.")
//! @yah:handoff("VERDICT — can turso-backup replace litestream as the headscale DB replicator? **YES FOR HYDRATION, NO FOR REPLICATION, TODAY.** The ticket's instruction to split was right, and the measurement is emphatic about which half is hard. HYDRATION (cold start / failover restore) is a clean yes: it needs no foreign-process interaction, and turso-backup already emits the exact artifact headscale wants. REPLICATION (steady-state WAL tailing of a live headscale) is a no as the code stands — not because of the WAL format, which is fine, but because of two independently disqualifying defects measured below. Filed as R858-F17 (hydration, go), R858-B18 (the coexistence lock), R858-B19 (the restart-detection bug).")
//! @yah:handoff("HOW IT WAS MEASURED, so the next agent can distrust me cheaply. New harness: oss/turso-backup/examples/foreign_checkpoint_probe.rs (+ its [[example]] stanza in that crate's Cargo.toml). Seven probes, A/B/C/D/E/F/G. Every writer is the SYSTEM sqlite3 binary (3.51.0 at /usr/bin/sqlite3, upstream C) — never turso, or the probe is circular. Two traps are handled explicitly and both bit me first: (1) sqlite CHECKPOINTS ON CLEAN CLOSE, so every writer that must leave frames behind is SIGKILLed after a sentinel SELECT proves its statements ran; (2) READING a live source with sqlite3 also folds its WAL on close — my first pass did exactly that and silently destroyed the condition under test midway through probe B, so live sources are now read via rows_via_copy(), which snapshots the db/-wal/-shm trio first. The harness also parses the 32-byte WAL header off disk (wal_hdr) so that engine-independent ground truth sits next to whatever turso reports.")
//! @yah:handoff("FINDING 1 (MEASURED, probes G and D) — turso-backup CANNOT OPEN A DATABASE headscale IS HOLDING. This is prior to the checkpoint race the ticket asked about and it subsumes it. turso_core 0.7.2 takes a WHOLE-FILE EXCLUSIVE fcntl lock at open (io/unix.rs:70, lock_file(true)), so with a foreign sqlite3 connection merely OPEN AND IDLE on the file, CoreWalSeam::open and raw_consistent_copy_live both fail outright: 'Locking error: Failed locking file ... File is locked by another process'. It is symmetric: with the seam held first, the foreign writer is refused with 'database is locked (5)' — the identical write took 4.3ms in the no-seam control — and a foreign PRAGMA wal_checkpoint(TRUNCATE) gives up with the same error after honouring its 2s busy_timeout. A seam held across foreign activity also never sees it (probe D4). headscale holds one connection for its entire process lifetime, so tail_frames cannot run against a live headscale at all. IT IS A GUARD, NOT A FORMAT PROBLEM: with LIMBO_DISABLE_FILE_LOCK=1 (turso_core io/common.rs) the same copy succeeds, integrity_check ok, and includes a row the foreign holder wrote after we had already been refused once. But that flag is process-wide and buys no shared locking protocol — turso locks the whole file, C SQLite uses byte-range locks plus the -shm WAL index, neither observes the other — so it converts 'refuses to open' into 'may read torn state'. Tracked as R858-B18.")
//! @yah:handoff("FINDING 2 (MEASURED, probes A/B/F, cross-checked by E) — THE CHECKPOINT RACE IS REAL AND IT FAILS SILENTLY, and the ticket's premise that the restart path merely 'has never been exercised' was too generous: it does not fire at all in the case that matters. There are TWO foreign-checkpoint regimes and tail_frames is only correct in one. (a) IN-PROCESS AUTOCHECKPOINT — a long-lived writer folding its own WAL at the default 1000-page threshold reuses the WAL file and DOES increment checkpoint_seq monotonically (measured 0 -> 8, salt1 d492ed8a -> d492ed92 in lockstep). Restart detection would work here. (b) WRITER PROCESS RESTART — when the LAST connection closes, SQLite checkpoints and DELETES the WAL, and the next writer creates a fresh WAL back at checkpoint_seq 0 with brand-new random salt (measured b83c03f5 -> 9ca89e39, unrelated). checkpoint_seq goes 0 -> 0 across a completely different WAL, the Restarted branch never fires, and the sink splices two WAL generations into one chain. CONSEQUENCES, both with restore_latest_stream REPORTING SUCCESS and no error raised anywhere: probe B (new WAL shorter than the watermark) -> tail returns Empty forever, restore yields a 9-row image against a 12-row source that passes PRAGMA integrity_check — a plausible, silently stale database. Probe F (new WAL longer, with an early post-fold write whose pages nothing later rewrites) -> restore reports frames_replayed 57 / generations 2 and produces a file that upstream sqlite3 rejects with 'database disk image is malformed (11)'. Regime (b) is NOT exotic for this fleet — R858 exists because headscale gets torn down and redeployed on leadership change. Tracked as R858-B19, with the fix the data points at: carry the WAL salt in the watermark, since it moves in BOTH regimes while checkpoint_seq moves in only one.")
//! @yah:handoff("FINDING 3 (MEASURED, probe C) — HYDRATION WORKS, and it is the half worth taking now. A WAL written by upstream C sqlite 3.51.0 and left uncheckpointed (writer SIGKILLed mid-session) copies through raw_consistent_copy_live to an 8192-byte image that upstream sqlite3 reads with PRAGMA integrity_check = ok and the exact live row count, with no -wal sidecar required. The source was verified UNPERTURBED by the copy — identical WAL salt and max_frame before and after — which matters because the copy is the thing that would run against a real headscale database. This independently reconfirms @Ashguard:dragon's 2026-09-04 cross-engine format result on a different sqlite (3.51.0 vs their 3.32.2). And hydration dodges Finding 1 by construction: it runs BEFORE headscale starts, when nothing else holds the file, so the exclusive lock is a non-issue.")
//! @yah:handoff("COST — WHICH HALF IS MEASURED AND WHICH IS INFERRED, since the ticket asked for exactly this. MEASURED, locally (probe E): with sqlite's DEFAULT wal_autocheckpoint (confirmed 1000 pages) and a long-lived writer doing 200-byte single-row transactions into an indexed table, the WAL folded 8 times in 3000 transactions — ONE RESTART PER ~375 WRITES. That is frequent, not rare. INFERRED, not measured: how often the LIVE headscale folds. I could not reach the box and did not try. The ticket's prior — an 8.4 MB WAL against a 94 KB main file on 2026-09-04 — is consistent with headscale folding much LESS often than my local writer (8.4 MB is ~2050 pages, twice the 1000-page default threshold), which would point at either a non-default autocheckpoint or a long-lived reader blocking backfill; I could not distinguish those from here. ALSO INFERRED: yubaba's emitted headscale config (oss/yubaba/crates/cloud/src/mesh.rs:589-592) sets only `database.type/sqlite.path` and no WAL or autocheckpoint key, so headscale is on ITS OWN defaults, whatever v0.23.0 chooses — I did not read headscale's source to establish that value. NONE OF THIS CHANGES THE VERDICT: the restart path's frequency only matters if the restart path is correct and reachable, and Findings 1 and 2 say it is neither. The cost number is filed so R858-B19 can size its own fix, not because it gates the decision.")
//! @yah:handoff("WHAT THIS MEANS FOR R858'S PAYOFF, stated so nobody over-reads the verdict. Adopting turso-backup for HYDRATION ALONE does NOT delete the litestream pin: litestream stays as the replicate daemon, so the 0.3.13 pin, the third-party download and the hand-computed checksums all remain. The pin only goes away if R858-B18 and R858-B19 are both fixed. So the payoff this spike was asked to size is REAL BUT DEFERRED — R858-F17 is worth taking now because failover restore is the leg that actually hurt on 2026-09-03, not because it retires the pin.")
//! @yah:verify("BASELINES, measured before and after in oss/turso-backup (its own Cargo workspace and its own target dir, so no camp target-lock contention). `cargo test --all-targets`: 149 passed / 0 failed both before and after the change — 133 lib + 5 hydrate bin + 4 snapshot bin + 7 rss_harness + 0 tail_sweep_harness, plus the new example target contributing 0 tests. `cargo clippy --all-targets -- --deny=warnings`: clean, exit 0, both before and after. No production source file was modified, so no behaviour was at risk; the baselines are here to prove the new example target did not break the crate's own gates.")
//! @yah:verify("ASSUMPTION DISCHARGED — and it was wrong in the optimistic direction, which is why this is called out rather than left to be inferred from the handoff. The filed @yah:assumes said the restart mechanism \"exists\" and had merely \"never been exercised\", and guessed from the 8.4 MB WAL that the restart path \"may be rare\". Measured: the mechanism does not fire at all in the regime that matters (a writer process restart resets checkpoint_seq to 0, so the Restarted branch is never taken — Finding 2), and locally the fold rate is one per ~375 writes, i.e. frequent rather than rare. The live-headscale fold rate remains genuinely unmeasured; only the local one is established.")

use anyhow::Result;
use std::path::Path;

/// Name of the litestream replicate systemd unit.
pub const LITESTREAM_UNIT: &str = "litestream-headscale.service";
/// Default litestream config path on the machine.
///
/// Under yubaba's own state directory, NOT `/etc` — and that is a correctness
/// requirement, not tidiness. `yubaba.service` runs with
/// `ProtectSystem=strict`, which mounts the whole hierarchy read-only except
/// the paths it names; `/var/lib/yah/yubaba` is granted (`StateDirectory` +
/// `ReadWritePaths`) and `/etc` is not. This file was at
/// `/etc/yah-cloud/litestream.yml` until R858, where every write of it failed
/// EROFS on a fleet node and [`install`]'s `Err` was absorbed by
/// `leader::on_became_leader` into a `warn!` — the fourth way this path
/// contrived to replicate nothing while looking wired.
///
/// `templates/mirror.yml` already states the constraint for the other half of
/// this pair: "yubaba runs under ProtectSystem=strict and CANNOT write
/// /etc/systemd/system or /etc/ufw", which is why the *unit* is pre-staged at
/// provision time and only the config is written here.
pub const LITESTREAM_CONFIG_PATH: &str = "/var/lib/yah/yubaba/litestream.yml";

/// Every key under a replica entry sits at this indent — `- url:` is at 6, so
/// its sibling keys are at 8. Named because the bug this constant replaced was
/// invisible: a `\` line-continuation in the old format string stripped the
/// leading whitespace of the following line, so `access-key-id` came out at
/// column 0 and the replica had no credentials at all (R591-T3).
const REPLICA_KEY_INDENT: &str = "        ";

/// Generate a litestream config YAML for replicating `headscale_db` to `s3_url`.
///
/// The `?endpoint=` query parameter in `s3_url` is extracted and written as a
/// separate `endpoint:` key in the replica config.
///
/// @yah:ticket(R858-B19, "tail_frames restart detection is blind to a WAL recreate: checkpoint_seq resets to 0 and two WAL generations get spliced into one chain")
/// @yah:at(2026-09-06T09:30:47Z)
/// @yah:status(open)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R858)
/// @yah:severity(high)
/// @yah:next("THE FIX THE MEASUREMENT POINTS AT: carry the WAL header SALT in the watermark and treat a salt change as a restart. The salt moved in EVERY observed fold, in both regimes — on a WAL recreate it is fresh randomness (measured b83c03f5 -> 9ca89e39, unrelated), and on an in-process autocheckpoint salt1 increments in lockstep with checkpoint_seq (measured d492ed8a -> d492ed8b -> ... -> d492ed92 alongside seq 0 -> 8). checkpoint_seq alone is sound only in the second regime; (salt1, salt2) is sound in both. The example's `wal_hdr` already parses the 32-byte WAL header if you need a reference.")
/// @yah:verify("`cd oss/turso-backup && cargo run --example foreign_checkpoint_probe -- b f`. TODAY (bug present) probe B prints 'SILENT WRONG IMAGE' (restored 9 rows against a 12-row source, integrity_check ok, no error raised anywhere) and probe F prints 'restored image UNREADABLE by upstream sqlite3: database disk image is malformed (11)' while restore_latest_stream itself reported success with frames_replayed 57 / generations 2. FIXED means both print a loud refusal or a correct image — never a silent wrong one.")
/// @yah:gotcha("REAL EDIT TARGET IS oss/turso-backup/src/stream.rs — a SUBCAMP, pruned from this board's scan set, which is the only reason this annotation is homed on the yubaba side. Touch `Watermark` (stream.rs:204), `tail_frames`'s start_frame decision (stream.rs:842-846) and `validate_generation_chain` (stream.rs:~1239). THE DEFECT: `Watermark` is `(checkpoint_seq, last_frame)` and `tail_frames` treats an UNCHANGED checkpoint_seq as 'same WAL, resume at last_frame+1'. That inference is false. MEASURED 2026-09-06 by @Ashguard:griffin (session:d27ac15b) with oss/turso-backup/examples/foreign_checkpoint_probe.rs, writer = system sqlite3 3.51.0: when the LAST connection to a DB closes, SQLite checkpoints and DELETES the WAL file, and the next writer creates a fresh WAL whose checkpoint-sequence is back to 0 with a brand-new random salt. So across a writer process restart checkpoint_seq goes 0 -> 0 while the WAL is a completely different one. The `Restarted` branch never fires and the sink silently splices frames from two WAL generations into one generation chain.")
/// @yah:assumes("That the same reset shape occurs when the WRITER IS TURSO rather than upstream C SQLite — i.e. that this bug is general and not foreign-writer-only. NOT MEASURED. The probe drove every writer with the system sqlite3 binary on purpose (a turso-driven probe would have been circular for R858-S6's question). Before sizing the blast radius for in-tree consumers like roadcase, measure the turso-writer-across-process-restart case directly; if turso never recreates its WAL, this is foreign-writer-only and the priority drops.")
pub fn generate_config(headscale_db: &Path, s3_url: &str) -> String {
    let (url_without_query, endpoint) = split_s3_url(s3_url);
    let mut out = String::from("---\ndbs:\n");
    out.push_str(&format!("  - path: {}\n", headscale_db.display()));
    out.push_str("    replicas:\n");
    out.push_str(&format!("      - url: {url_without_query}\n"));
    if let Some(ep) = endpoint {
        out.push_str(&format!("{REPLICA_KEY_INDENT}endpoint: {ep}\n"));
    }
    // Credentials are env-expanded by litestream itself, so the config file is
    // safe to write world-readable and safe to put in a bug report.
    out.push_str(&format!(
        "{REPLICA_KEY_INDENT}access-key-id: ${{LITESTREAM_ACCESS_KEY_ID}}\n"
    ));
    out.push_str(&format!(
        "{REPLICA_KEY_INDENT}secret-access-key: ${{LITESTREAM_SECRET_ACCESS_KEY}}\n"
    ));
    out
}

/// Write the litestream config to [`LITESTREAM_CONFIG_PATH`] (idempotent).
///
/// Credentials are read from `LITESTREAM_ACCESS_KEY_ID` /
/// `LITESTREAM_SECRET_ACCESS_KEY` in the environment — inject via
/// `/etc/yah-cloud/litestream.env`, which `litestream-headscale.service` reads
/// with `EnvironmentFile=-` and `yubaba.service` reads for
/// `YUBABA_LITESTREAM_S3_URL`. One file, both readers, because a URL without
/// the credentials that authenticate to it replicates nothing.
///
/// # The config only. The unit ships at provision time
///
/// This function used to write `/etc/systemd/system/litestream-headscale.service`
/// too, and could not: `yubaba.service` sets `ProtectSystem=strict` and grants
/// no path under `/etc`, so both that write and the config write (then also
/// under `/etc`) failed EROFS on every fleet node, and
/// `leader::on_became_leader` absorbed the `Err` into a `warn!`. R591-T3 found
/// three ways this path replicated nothing while looking wired; this was the
/// fourth, and it defeated the other three's fixes.
///
/// The unit is static text, so it needs no writer at all — it is shipped in
/// the release tarball beside `yubaba.service` and laid down by cloud-init,
/// the same treatment `templates/mirror.yml` already gives `headscale.service`
/// for exactly this reason. What genuinely varies per node is the S3 URL, and
/// that is all this function now writes.
///
/// # Call this before `restore` (R591-T3)
///
/// [`restore`] and the replicate unit both run `litestream -config
/// <LITESTREAM_CONFIG_PATH>`. Until R591-T3 nothing called this function at
/// all, so that file never existed on any node: every restore failed at
/// "no such file", every `systemctl start litestream-headscale.service` failed
/// against a unit that had never been written, and both failures were absorbed
/// — the restore into a `warn!`, the start into a discarded exit status.
///
/// @yah:ticket(R858-F17, "Hydrate headscale's sqlite DB from turso-backup before headscale starts (replaces litestream's restore leg)")
/// @yah:at(2026-09-06T09:29:48Z)
/// @yah:status(open)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R858)
/// @yah:next("DO NOT ALSO MOVE THE IDENTITY FILE IN THIS TICKET. R858's acceptance-test gotcha leg (2) — noise_private.key, 72 bytes, local disk only — is a separate unreplicated-state problem that turso-backup does not solve either. It is R600/W273's cluster secret store. Conflating them is how this ticket grows past its safe scope.")
/// @yah:verify("Reproduce probe C first so the premise is yours and not inherited: `cd oss/turso-backup && cargo run --example foreign_checkpoint_probe -- c`. Expect 'C VERDICT: CORRECT' and an unperturbed source line at C3.")
/// @yah:gotcha("GREEN LIGHT, AND IT IS THE ONLY GREEN HALF OF R858-S6. Hydration needs NO foreign-process interaction whatsoever, which is exactly why it is safe while the replication leg (R858-S6's other follow-ons) is not: the sequence is fetch base snapshot + replay frames -> write a plain sqlite file at headscale's `database.sqlite.path` -> THEN start headscale. Nothing else has the file open at that moment, so the whole-file exclusive lock that blocks the streaming leg is a non-issue here. MEASURED 2026-09-06 by @Ashguard:griffin (session:d27ac15b), probe C in oss/turso-backup/examples/foreign_checkpoint_probe.rs: a WAL written by upstream C sqlite 3.51.0 and left uncheckpointed (writer SIGKILLed) copies through `raw_consistent_copy_live` to an 8192-byte image that upstream sqlite3 reads with `PRAGMA integrity_check` = ok and the exact live row count, with NO -wal sidecar needed. The source was verified unperturbed by the copy (identical WAL salt and max_frame before and after).")
/// @yah:assumes("That headscale reads a hydrated plain-sqlite image with no -wal sidecar present at startup. Grounded — the image is vanilla SQLite and probe C read it with upstream sqlite3 — but not verified against a running headscale, and no live box was touched by R858-S6.")
pub fn install(headscale_db: &Path, s3_url: &str) -> Result<()> {
    let config = generate_config(headscale_db, s3_url);
    if let Some(parent) = Path::new(LITESTREAM_CONFIG_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(LITESTREAM_CONFIG_PATH, &config)?;
    Ok(())
}

/// Start `litestream-headscale.service` (idempotent — no-op if already running).
///
/// @yah:ticket(R858-B18, "turso-backup cannot tail a live foreign-written sqlite DB: turso_core takes a whole-file exclusive lock at open")
/// @yah:at(2026-09-06T09:30:17Z)
/// @yah:status(open)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R858)
/// @yah:severity(high)
/// @yah:next("UNTIL THIS IS ANSWERED, litestream stays as the replicate daemon and only the restore leg moves (R858-F17). That split is deliberate: hydration is safe and independent, replication is not.")
/// @yah:verify("`cd oss/turso-backup && cargo run --example foreign_checkpoint_probe -- d g`. Expect G2/G3 REFUSED, G3b SUCCEEDED, D2 refused with 'database is locked (5)' against a D0 control that ran in ~4ms.")
/// @yah:gotcha("THE ESCAPE HATCH WORKS BUT IS NOT THE FIX — do not close this ticket by setting the env var. MEASURED (probe G3b): with LIMBO_DISABLE_FILE_LOCK=1 the same copy SUCCEEDS against a live foreign holder, integrity_check ok, and it includes a row the holder wrote after we had already been refused once — so the cross-engine WAL read genuinely works and the lock is a guard, not an incompatibility. But that env var removes the guard PROCESS-WIDE and buys no shared locking protocol: turso locks the whole file with fcntl, C SQLite uses byte-range locks plus the -shm WAL index, and neither engine observes the other's. What was measured is one point-in-time copy, NOT correctness under sustained concurrent write pressure. Turning the guard off converts 'refuses to open' into 'may read torn state', which is the strictly worse failure.")
pub fn start() {
    let _ = std::process::Command::new("systemctl")
        .args(["start", LITESTREAM_UNIT])
        .status();
}

/// Stop `litestream-headscale.service`.
pub fn stop() {
    let _ = std::process::Command::new("systemctl")
        .args(["stop", LITESTREAM_UNIT])
        .status();
}

/// Run `litestream restore` to pull the latest Headscale DB snapshot from S3
/// before starting Headscale on a newly-elected leader.
///
/// Uses `-if-replica-exists` so the call is a no-op on first bootstrap (no
/// snapshot in S3 yet).  Runs the blocking child process in a `spawn_blocking`
/// task so it doesn't stall the async runtime.
pub async fn restore(headscale_db: &Path, s3_url: &str) -> Result<()> {
    let (url_without_query, _) = split_s3_url(s3_url);
    let db_path = headscale_db.to_string_lossy().into_owned();
    let url_clone = url_without_query.clone();

    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("litestream")
            .args([
                "restore",
                "-if-replica-exists",
                "-config",
                LITESTREAM_CONFIG_PATH,
                "-o",
                &db_path,
                &url_clone,
            ])
            .status()
    })
    .await??;

    if !status.success() {
        anyhow::bail!(
            "litestream restore from {url_without_query} failed (exit {})",
            status.code().unwrap_or(-1)
        );
    }
    tracing::info!("litestream restore complete from {}", url_without_query);
    Ok(())
}

/// Split `s3://bucket/path?endpoint=https://...` into
/// `(s3://bucket/path, Some("https://..."))`.
fn split_s3_url(url: &str) -> (String, Option<String>) {
    match url.split_once('?') {
        None => (url.to_owned(), None),
        Some((base, query)) => {
            let endpoint = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("endpoint="))
                .map(|v| v.to_owned());
            (base.to_owned(), endpoint)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn split_url_no_query() {
        let (base, ep) = split_s3_url("s3://my-bucket/headscale");
        assert_eq!(base, "s3://my-bucket/headscale");
        assert!(ep.is_none());
    }

    #[test]
    fn split_url_with_endpoint() {
        let (base, ep) =
            split_s3_url("s3://my-bucket/headscale?endpoint=https://fsn1.your-objectstorage.com");
        assert_eq!(base, "s3://my-bucket/headscale");
        assert_eq!(ep.as_deref(), Some("https://fsn1.your-objectstorage.com"));
    }

    #[test]
    fn generate_config_contains_db_path() {
        let cfg = generate_config(
            &PathBuf::from("/etc/yah-cloud/headscale/headscale.db"),
            "s3://bucket/headscale",
        );
        assert!(
            cfg.contains("/etc/yah-cloud/headscale/headscale.db"),
            "db path missing"
        );
        assert!(cfg.contains("s3://bucket/headscale"), "s3 url missing");
        assert!(
            cfg.contains("LITESTREAM_ACCESS_KEY_ID"),
            "cred placeholder missing"
        );
    }

    /// R591-T3. `generate_config` used a `\` line-continuation, which strips
    /// the leading whitespace of the continued line — so `access-key-id` came
    /// out at column 0 instead of 8. The old test above passed anyway (it only
    /// asked whether the string appeared *somewhere*), and the config it
    /// described gave the replica no credentials at all.
    ///
    /// Every key under `- url:` is a sibling of it and must sit at the same
    /// indent as `endpoint`, with or without an endpoint present.
    #[test]
    fn every_replica_key_is_indented_under_its_url() {
        for url in [
            "s3://bucket/headscale",
            "s3://bucket/headscale?endpoint=https://fsn1.your-objectstorage.com",
        ] {
            let cfg = generate_config(&PathBuf::from("/var/lib/hs/headscale.db"), url);
            for key in ["access-key-id", "secret-access-key"] {
                let line = cfg
                    .lines()
                    .find(|l| l.trim_start().starts_with(key))
                    .unwrap_or_else(|| panic!("{key} missing from:\n{cfg}"));
                assert_eq!(
                    line.len() - line.trim_start().len(),
                    REPLICA_KEY_INDENT.len(),
                    "{key} must be a sibling of `- url:`, got {line:?} in:\n{cfg}"
                );
            }
        }
    }

    /// The `?endpoint=` query is litestream's `endpoint:` key, not part of the
    /// replica URL — a bucket URL carrying the query would be dialled verbatim.
    #[test]
    fn the_endpoint_query_becomes_a_key_and_leaves_the_url() {
        let cfg = generate_config(
            &PathBuf::from("/var/lib/hs/headscale.db"),
            "s3://bucket/headscale?endpoint=https://fsn1.your-objectstorage.com",
        );
        assert!(cfg.contains("- url: s3://bucket/headscale\n"), "{cfg}");
        assert!(
            cfg.contains("endpoint: https://fsn1.your-objectstorage.com"),
            "{cfg}"
        );
        assert!(
            !cfg.contains("?endpoint="),
            "query leaked into the url:\n{cfg}"
        );
    }

    /// The unit's own directives — `Restart=always`, no `[Install]`, no
    /// `headscale.service` binding, and the config path it shares with
    /// [`restore`] — moved to
    /// `app/yah/cli/tests/camp_systemd_unit_emit.rs::the_litestream_sidecar_unit_*`
    /// when the unit stopped being generated here (R858). It is shipped text
    /// now, so it is asserted where it is shipped from; generating a second
    /// copy in this crate purely to assert against would be asserting a copy
    /// that can drift from the file nodes actually run.
    ///
    /// What stays here is the half that is still generated: the config.
    /// [`install`] must write it somewhere `ProtectSystem=strict` permits, and
    /// that is the property this test holds.
    #[test]
    fn the_config_lives_where_a_hardened_yubaba_can_write_it() {
        // `yubaba.service` grants ReadWritePaths=/var/lib/yah/yubaba (plus
        // StateDirectory=yah/yubaba) and nothing under /etc. A config path
        // outside that grant is EROFS on every fleet node, and the caller
        // absorbs the error into a warn! — so the bug is silent.
        assert!(
            LITESTREAM_CONFIG_PATH.starts_with("/var/lib/yah/yubaba/"),
            "config must sit inside yubaba's writable state dir, got \
             {LITESTREAM_CONFIG_PATH}"
        );
    }

    /// `install` writes the config and nothing else. It used to also write a
    /// systemd unit, which it had no permission to do; a regression that
    /// reintroduces any `/etc` write reintroduces the silent EROFS.
    #[test]
    fn install_writes_the_config_and_only_the_config() {
        let tmp = std::env::temp_dir().join("yah-litestream-install-probe");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let db = tmp.join("headscale.db");

        // Not calling `install` directly — it targets absolute host paths no
        // test may write. This asserts the payload it would write, which is
        // the part that carries meaning.
        let cfg = generate_config(&db, "s3://yah-headscale/headscale");
        assert!(cfg.contains("s3://yah-headscale/headscale"));
        assert!(
            !cfg.contains("[Service]") && !cfg.contains("ExecStart="),
            "the config is YAML, not a smuggled unit file:\n{cfg}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
