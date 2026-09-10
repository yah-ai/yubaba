//! Leader-resident tenant placement scheduler (R737-F3, W246 §"Scheduler").
//!
//! The missing middle W246 names: yubaba has a real raft and a real leadership
//! watcher, but nothing that notices a tenant's owner died and moves it onto
//! live capacity. This is that loop.
//!
//! # Shape: a second `leader_pin`-style loop, not a new pattern
//!
//! Same structure as [`crate::leader_pin`]: a pure `decide`-style function
//! (here, [`decide_transfer`]) tested as arithmetic, run inside a paced loop
//! that is [`spawn`]ed **unconditionally on every node**. A follower's tick
//! finds it is not the leader and does nothing — see [`run`] — so there is no
//! start/stop edge to get wrong across an election, exactly the property
//! `leader_pin`'s module doc argues for.
//!
//! # What "rebuild from the committed log on leader change" means here
//!
//! This loop carries **no placement state of its own** across ticks. Every
//! tick re-reads `YubabaStateMachine::tenants`/`tenant_placement`/`members` —
//! the committed log, replayed — and computes a decision fresh. A new leader
//! that has never run this loop before starts with an empty
//! [`crate::lease_detector::TransitionTracker`] and reaches the exact same
//! conclusions its predecessor would have, one tick later. There is nothing
//! to "resume": the state that matters is already in the state machine.
//!
//! **Idempotency is the state machine's, not this loop's.** A `TransferTenant`
//! is CAS-guarded on `from_epoch` (R732-F1). This loop reads the *current*
//! epoch fresh every tick rather than remembering one, so a mid-decision
//! leader failover cannot double-place: the surviving leader (old or new)
//! either observes its own already-committed transfer (owner is no longer the
//! dead node, so the tenant no longer matches the trigger and nothing is
//! sent) or re-derives the same CAS write from the same live state. No
//! decision-log, no dedup table — the epoch already *is* one.
//!
//! # What is deliberately NOT persisted to raft: liveness itself
//!
//! A tempting alternative reading of "rebuild from the committed log" is that
//! a confirmed node-down fact should itself be a raft entry, so a new leader
//! does not have to re-earn [`crate::lease_detector::HysteresisPolicy`]'s confirm
//! dwell from zero. This was considered and rejected for this ticket:
//!
//! - W253 §7 and [`crate::lease_detector`]'s module doc are explicit that
//!   renewals — and by extension the liveness judgement built on them — stay
//!   off the raft log; only R737-F2's *own* channel separation makes that
//!   evidence trustworthy for placement in the first place. Writing "node X
//!   is down" into raft the moment one leader's tracker confirms it would
//!   re-couple the two channels through the back door.
//! - A brand-new leader independently re-confirming liveness rather than
//!   trusting a predecessor's possibly-stale judgement is the more
//!   conservative failure mode, and the cost is bounded and one-time: at most
//!   one extra [`crate::lease_detector::HysteresisPolicy::confirm_down_after`] dwell,
//!   paid once per leadership change, never compounding.
//!
//! So "rebuild from the committed log" is scoped to *placement* (`tenants` /
//! `placement`, both raft state), not to *liveness* (deliberately raft-free).
//! If that dwell-on-failover cost ever proves too slow in practice, the fix is
//! a dedicated, narrow raft entry for confirmed transitions — not folding
//! liveness into the existing tenant/member state.
//!
//! # Readiness is [`crate::lease_detector::judge_readiness`], not a second opinion
//!
//! W253 §7 lists four gates a node must pass before it may *own* a tenant —
//! streamer caught up within bound, tenant hydrated, within headroom, raft peer
//! healthy — and R737-F2 already expresses them as one pure function. This
//! loop does **not** re-derive them: [`judge_candidate`] projects a
//! [`NodeEligibility`] onto [`crate::lease_detector::ReadinessInputs`] and defers, so
//! the gate set cannot drift between the module that defines it and the module
//! that acts on it.
//!
//! One of the four inputs still has no *default* source, carried explicitly
//! rather than silently dropped:
//!
//! - **`hydrated`** is derived, not measured: for [`SlaTier::ColdHydrate`] the
//!   hydrate *is* part of the transfer, so demanding it beforehand would
//!   deadlock every cold placement; for [`SlaTier::WarmReplica`] the node must
//!   already hold the tenant, which is exactly what
//!   [`NodeEligibility::warm_for_tenant`] means. So `hydrated` is
//!   `tier != WarmReplica || warm_for_tenant` — one rule, not a warm-tier
//!   filter sitting next to a hydration flag saying the same thing twice.
//!
//! `streamer_watermark_age` / `rpo_bound` (R782) are plumbed as of this
//! ticket: `rpo_bound` reads straight off `TenantPlacement`, and
//! `streamer_watermark_age` off `rpo_registry` — but both still read as
//! `None` for the common case today, and that is not a bug to chase. A
//! tenant's `TenantPlacement.rpo_bound` is `None` until an operator declares
//! one (the gate stays vacuous, exactly as before this ticket), and even once
//! declared, `rpo_registry` only ever holds a fresh value for a node whose
//! `tenant-streamer` is *actively streaming that tenant* — today that is only
//! ever the current owner, who is excluded from `candidates` by construction.
//! So a bound tenant's failover candidates read `None` until W248's warm
//! fan-out gives some other node a reason to be streaming it too, and fail
//! `StreamerBehindBound` until then — the fail-closed behavior
//! [`judge_readiness`]'s own doc calls for, not a wiring gap.
//!
//! ## Why the raft-heartbeat channel may only *veto*
//!
//! `raft_peer_healthy` is sourced from
//! [`RaftHeartbeatDetector`](crate::failure_detector::RaftHeartbeatDetector) —
//! the very evidence channel R737-F2 exists to keep *out* of placement. That is
//! not a contradiction: W253 §7 makes "its Raft peer is healthy/connected" its
//! own gate, and that is a raft question. The separation is preserved by
//! direction. This channel can only ever *refuse* a candidate — an explicit
//! `Down` observation — and can never be the reason one is accepted. `Suspect`,
//! `Unknown`, a node absent from the report, and no detector at all all leave
//! the gate open, per the [`FailureDetector`](crate::failure_detector::FailureDetector)
//! trait's own "an empty report never means every node is down" rule. So a
//! placement still rests entirely on the lease channel; the raft channel only
//! catches the gray failure where a node renews its HTTP lease happily while
//! its consensus link is dead, which would hand a tenant to an owner that
//! cannot participate in the log that fences it.
//!
//! # What "already warm" cannot check yet
//!
//! [`NodeEligibility::warm_for_tenant`] exists because [`SlaTier::WarmReplica`]
//! tenants must only fail over onto a node already streaming them (W246 §
//! "Proposed design", W248's territory). Nothing in this codebase yet records
//! *which* nodes hold a warm replica of a tenant — that map is W248's WAL
//! streamer/applier fan-out, explicitly out of this relay's scope. Until it
//! exists, [`run`] passes `warm_for_tenant: false` for every candidate, which
//! means a `WarmReplica` tenant's dead owner currently produces
//! [`PlacementDecision::NoEligibleCandidate`] (with a
//! [`NotReady::NotHydrated`] refusal per candidate) rather than a wrong or a
//! guessed placement — the same pessimistic-default philosophy `SlaTier`'s own
//! doc states for an *undeclared* tier, applied here to an *unmeasurable* one.
//!
//! @yah:ticket(R858-T4, "Model per-node native-exec capability in placement, and make the headscale binary present on every candidate")
//! @yah:status(review)
//! @yah:at(2026-09-06T08:51:13Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:next("Tier: Cleric — two concrete gaps with a clear shape; the judgement is whether the appliance stays native or becomes a container (see the gotcha).")
//! @yah:gotcha("TWO SEPARATE READINESS GAPS, BOTH MEASURED. (1) CAPABILITY DRIFT PLACEMENT CANNOT SEE: us-south-001's kamaji was started without --native-exec-dir, so it refuses EVERY native workload (\"BackendRefused: ... native backend not configured\"). The tracked unit app/yah/cli/resources/kamaji.service:49 DOES carry the flag — this is per-node drift between the shipped unit and what is actually running, and nothing in the scheduler models it. kamaji should report native-exec availability into node eligibility so placement refuses the node UP FRONT instead of discovering it at deploy time. (2) NO BINARY: appliance_spec is a NATIVE workload, so kamaji forks <headscale_dir>/headscale and pulls nothing. us-west-001 has that 51MB binary (mtime Jun 22); us-south-001 has no binary, no config.yaml, no DB. A \"moveable\" native appliance requires its executable to be a provisioned prerequisite on every candidate.")
//! @yah:next("THE STANDING QUESTION UNDER THIS TICKET: containerise headscale, and do it AFTER R858-T1. headscale_appliance.rs gives three reasons for native exec, and T1 dissolves two. (a) \"the state is already on the host\" — weakened once the DB comes from litestream and the noise key from the cluster secret store (R858-T2); those are replicated sources, not host facts. (b) \"it owns privileged host ports 443 + 80 for HTTP-01\" — this is the load-bearing one TODAY and is exactly what T1 deletes: behind the doors, headscale serves one plain-HTTP non-privileged port. (c) \"cutover risk\" — that cutover already happened. A container image carries the binary and config template, so gap (2) above disappears rather than being solved with a provisioning step. Do NOT containerise before T1: reason (b) is still true until TLS moves off the appliance.")
//! @yah:gotcha("THE \"CONTAINERISE?\" QUESTION ON THIS TICKET IS ANSWERED BY W338 / R860, AND THE ANSWER IS NO. W338 (filed 2026-09-04) reframes it: the real question is not which substrate headscale runs on, it is what an appliance is MADE OF. Its answer is stay native and give the spec a way to declare what else runs alongside — locality-aware requirements (`anywhere | prefer-local | local` x `wait | self`) over kamaji's existing native backend, which already supervises N processes by identity. So the containerise-after-T1 line in this ticket's own next is SUPERSEDED; do not act on it without reading W338 first. What remains genuinely this ticket's is the other half: per-node native-exec capability must be modelled in placement, and a native provider's binary must be present on every candidate node — W338 §\"Placement consequences\" item 3 makes that a placement precondition rather than a deploy-time surprise.")
//! @yah:verify("cargo test -p kamaji-proto -p kamaji (oss/kamaji workspace) = 33 + 58 passed, 0 failed, EXIT=0 — including `messages::reply_correlation_tests::every_reply_variant_correlates_to_its_request`, which now exercises `CapabilitiesReport`, and `codec::tests::welcome_round_trip`, which is the check that the handshake frame is untouched. cargo test -p yubaba --lib = 685 passed / 0 failed, EXIT=0 (was 673 before this pass; the delta is other sessions' tests landing alongside, not mine — the probe itself has no unit test, see the gotcha). NOTE ON READING THESE: the camp build rail reported BOTH of these runs as \"failed with exit code 1\" in its task notifications. That was my own trailing `grep` for error lines exiting 1 on finding none, not the build — the `EXIT=` line I appended inside the command is the build's real status and both say 0. Worth knowing before anyone re-runs on the strength of a red notification.")
//! @yah:handoff("GAP 2 (NO BINARY) IS FILLED IN THE PROVISIONING TEMPLATE — oss/yubaba/crates/cloud/templates/mirror.yml now installs the headscale binary on EVERY node, not only the one that was once promoted. Until now it arrived solely via `POST /headscale/deploy` (the `yah mesh promote` path, which curl-downloads it), which is precisely why us-west-001 has it and us-south-001 has no binary, no config.yaml and no DB. `appliance_spec` is a NATIVE workload, so kamaji forks `/var/lib/yah-cloud/headscale/headscale` and pulls nothing — a moveable native appliance needs its executable to be a provisioned prerequisite on every candidate rather than a side effect of history. Staged and never started; leader.rs decides who runs it. Modelled on the litestream block directly above it: arch-switched on `dpkg --print-architecture`, sha256-verified, and written as a YAML BLOCK SCALAR because the `echo \"headscale: unsupported arch\"` line contains a colon-space that a plain multi-line scalar reads as a mapping indicator (the mistake that block already records having made once). CHECKSUMS WERE COMPUTED BY DOWNLOADING THE EXACT ASSETS, not copied off the release page — the standard the litestream block states: v0.23.0 linux amd64 = d9193dad4b070b9b3f6d54c8f14366952944b6e917672c0bc1dfd8f5491287a7 (51,593,368 bytes), arm64 = 99fa9b2944c50759882b578e78aa11968d6fdec9bbfeced88237a1138b89e9fe (49,610,904 bytes). The amd64 SIZE MATCHES the binary already on us-west-001 exactly, which is the corroboration that this is the asset the fleet is already running rather than a different build of the same version. Version pinned to 0.23.0, the same pin `cloud::mesh::HEADSCALE_VERSION` and `yubaba::DEFAULT_HEADSCALE_VERSION` carry — there is no dependency edge from the template to either constant, so a bump has to touch all three by hand.")
//! @yah:verify("cargo test -p yah-cloud --lib cloud_init = 27 passed / 0 failed, EXIT=0 — the gate that matters for the mirror.yml half, because it includes `rendered_runcmd_entries_are_all_strings` (a real serde_yaml parse of the fully-rendered template with every conditional block present) and both user-data size caps. The headscale install is a YAML BLOCK SCALAR containing a colon-space, which is exactly the shape that broke this template's parse once before, and a 51MB binary's install block is the kind of addition that could push user-data past a provider cap — so this run is evidence for both risks, not a formality.")
//! @yah:verify("cargo test -p yah --test main camp_systemd_unit_emit = 8 passed / 0 failed, EXIT=0 (the T1 artifacts this pass did not author but did assert; re-run because @Ashguard:griffin edited passway-mesh.env underneath it). FULL SET FOR THIS PASS, every one EXIT=0: kamaji-proto 33, kamaji 58, yubaba --lib 685, yah-cloud --lib cloud_init 27, yah --test main camp_systemd_unit_emit 8. SKEW, STATED RATHER THAN GLOSSED: the camp rail flagged the last two runs as suspect because peers modified oss/yubaba/crates/cloud/src/config.rs, deploy/mod.rs and scheduler.rs mid-run. None of those is read by the tests that were flagged — camp_systemd_unit_emit is pure `include_str!` over app/yah/cli/resources/* plus string assertions, and cloud_init renders a template — so I am letting both results stand rather than re-running into the same shared-tree race. The yubaba and kamaji runs had clean input closures.")
//! @yah:handoff("CODE COMPLETE AND GREEN, NOTHING ROLLED — and the gap between those two is the whole remaining ticket, so do not read the column as \"south can take the appliance now\". Both measured gaps are closed in source: the capability probe (kamaji wire + leader.rs producer) and the headscale binary in the provisioning template. Neither has reached a node. The capability half needs a yubaba release + scripts/roll-node.sh; the binary half only affects nodes PROVISIONED after it, because an existing box never re-runs cloud-init. So us-south-001 today still has no `--native-exec-dir` and no /usr/local/bin/headscale, and a leadership move off us-west-001 still ends with the appliance running nowhere. WHAT THIS PASS ACTUALLY BOUGHT: the failure is now LOUD and EARLY instead of silent and late — an incapable node is refused as a candidate with the stable token `missing-native-exec` before ownership moves, rather than answering `BackendRefused` after it already has. That is worth having on its own (it is the half of the 37-hour chain that made the outage invisible), but it is not the failover. Tree anchor at handoff: 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — quote that SHA rather than HEAD in any revert instruction; the camp shares one tree and several peers committed during this pass.")
//! @yah:handoff("Tree anchor at handoff: 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — the shared tree as I left it. Diff against it (`git diff 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:handoff("BOTH MEASURED GAPS ARE NOW CLOSED IN CODE *AND* ON THE LIVE FLEET — this pass was the half the previous one could not do. As of 2026-09-06, all three voters carry kamaji with `--native-exec-dir` (native backend attached, confirmed in each journal) AND headscale v0.23.0 at /var/lib/yah-cloud/headscale/headscale, sha256 d9193dad4b070b9b3f6d54c8f14366952944b6e917672c0bc1dfd8f5491287a7 on east, south and west — byte-identical, and identical to what west has been running since Jun 22, which is the corroboration that this is the fleet's own asset and not a different build of the same version. Operator authorized both nodes explicitly before any node was touched. Mesh and site unaffected throughout: cloud.mesh.yah.dev/key?v=138 = 200 in 0.16s and yah.dev = 200 after.")
//! @yah:gotcha("THIS TICKET'S OWN STATED REMEDY WAS WRONG AND WOULD HAVE BURNED AN OPERATOR ROLL FOR NOTHING — the previous handoff said \"roll us-south-001 so its kamaji.service carries --native-exec-dir ... south is drift from the shipped unit\". MEASURED 2026-09-06: south was ALREADY running published 0.8.33 with the correct shipped unit installed (base unit ExecStart line 49 carries the flag) and still reported no native backend. The actual cause is /etc/systemd/system/kamaji.service.d/20-bundle.conf (R599-T5, dated 2026-07-21), which resets `ExecStart=` and RE-DECLARES kamaji's whole command line — it predates the flag, so it froze the flag set and silently dropped the native backend. Rolling reinstalls the base unit and the drop-in still wins, so a roll changes NOTHING. east had the same drop-in; west has NO kamaji drop-in directory at all, and that — not anything about west — is the entire reason west was the only node that could run the appliance. Half of the 37-hour 2026-09-03 outage traces to one hand-written systemd file.")
//! @yah:handoff("THE LIVE FIX, and it is reversible on both nodes. On east and south the drop-in was backed up in place as `20-bundle.conf.rollback-20260906-coffee` and rewritten to carry its two options as `Environment=KAMAJI_BUNDLE_CACHE_DIR=/var/lib/yah/kamaji/bundles` + `Environment=KAMAJI_BUNDLE_ORIGIN=https://cdn.yah.dev` with NO ExecStart line — kamaji reads both as defaults and argv overrides them (kamaji-bin/src/main.rs parse_args), so a drop-in can add options without owning the flag set. `systemctl cat kamaji.service | grep -c '^ExecStart=$'` is now 0 on both. Post-restart journals show all three backends attached on each node (containerd + native-exec + bundle), so nothing was traded away for the native backend. east's kamaji supervises yah.dev's three mesofact serve processes; R755-B5 replayed them (serve, serve, almanac-feed all back) and yah.dev / yah.dev/releases both returned 200 after. south's kamaji supervised ZERO children, so its restart was a true no-op — which is why south went first.")
//! @yah:handoff("THE PROBE GREW A THIRD FACT, BECAUSE PLACING THE BINARY EXPOSED THE NEXT ONE. The appliance's argv is `<dir>/headscale serve --config <dir>/config.yaml`, and nothing in the leader path writes config.yaml — per R858-B9 only POST /headscale/deploy and /headscale/bootstrap do. So east and south now have the binary and no config, and forking there would exit immediately and crash-loop under RestartPolicy::Always: a failure that LOOKS like a successful deploy, which is precisely the shape this relay exists to kill. `probe_native_exec` therefore checks EVERY path the spec's argv names, not just the binary, and refuses the node naming the missing one. Both paths are threaded from two new exported helpers, `headscale_appliance::binary_path` and `::config_path`, now the single source for probe and spec alike — two independent `join()` calls agree today and become a silent placement lie the day the layout moves. Consequence to state plainly: east and south are capable and still NOT candidates, on purpose. Carrying config.yaml is filed as R858-T16, which is gated on B9's step (4).")
//! @yah:handoff("THE GAP THE LAST HANDOFF NAMED IS CLOSED: `probe_native_exec` now has unit tests, six of them. The seam it said \"does not exist\" is `probe_native_exec_with(ask: Option<F>, argv_paths: &[PathBuf])`, where F is the capability future — `None` models \"no sibling to ask\". The `Option<F>` is deliberately NOT flattened to `Option<NodeCapabilities>` by the caller: \"there was nobody to ask\" and \"the one we asked did not answer\" reach the same permissive verdict for different reasons, and collapsing them upstream would leave a test unable to tell the branches apart. Both Unknown arms are asserted separately for that reason — the permissive reading is the safety property here, since an `Absent` on either would make every un-asked node ineligible, which mid-roll is most of the fleet and is the 2026-09-03 outage reproduced from the other side. Tests: no sibling -> Unknown; Err -> Unknown; native_exec=false -> Absent; binary missing -> Absent; config missing -> Absent; all true -> Present. A seventh, `the_probed_paths_are_the_ones_the_spec_names`, asserts every probed path appears in `appliance_spec`'s own argv, so a future layout change breaks a test rather than blessing a node the spec would crash on.")
//! @yah:handoff("THREE DISCOVERED FIXES OUTSIDE THE TICKET TITLE, all found while working and all landed rather than filed. (1) leader.rs: `self_eligibility`'s doc comment had come adrift and was sitting on top of `probe_native_exec` as one merged block — rustdoc was attributing 14 lines about NodeEligibility to the capability probe. Moved back to its function at leader.rs:~1210. (2) app/yah/cli/resources/kamaji.service: added the warning the drop-in trap needed, beside ExecStart — a drop-in that resets ExecStart= silently drops every flag added afterwards and a roll will not fix it; extra options belong in `Environment=` (KAMAJI_BUNDLE_CACHE_DIR / KAMAJI_BUNDLE_ORIGIN / KAMAJI_NATIVE_EXEC_DIR, all verified present in kamaji-bin/src/main.rs). It also records why moving the bundle flags INTO the shipped unit is not the fix: kamaji bails at startup when handed a flag whose cargo feature is absent, so such a unit would refuse to start on any kamaji built without `bundle-serving`. The camp already had this exact lesson encoded next door as `camp_systemd_unit_emit::the_litestream_target_arrives_by_environment_not_by_execstart`. (3) kamaji-bin/src/server.rs `dedupe_workload_entries`: the duplicate-id warn fired BEFORE the swap, so it labelled the row it was about to discard `kept_` — reading \"kept_state=Pending kept_pid=None\" beside a live pid makes a correct dedupe look inverted. It cost me a full investigation on east before the code proved itself right. Now reports the outcome (`kept_*` / `dropped_*`). Behaviour unchanged; the four existing dedupe tests still pass.")
//! @yah:verify("cargo test -p yubaba --lib = 784 passed / 0 failed, EXIT=0 (was 685 at the previous handoff; the delta is mostly peers' tests landing alongside, plus this pass's 7 in leader::tests). cargo clippy -p yubaba --lib --all-targets = EXIT=0, no findings on leader.rs or headscale_appliance.rs (the warnings it does print are in crates/cloud/src/reconciler/mesofact_static.rs, a peer's in-flight file). cargo test -p kamaji-proto -p kamaji -p kamaji-bin --features kamaji-bin/bundle-serving,kamaji-bin/native-exec = all suites ok, 0 failed, EXIT=0 — the gate for the server.rs log fix, including the four R599-B11 dedupe tests. cargo test -p yah --test main camp_systemd_unit_emit = 13 passed / 0 failed, EXIT=0, run after the kamaji.service comment edit.")
//! @yah:verify("LIVE VERIFICATION, measured on each box rather than inferred. Per voter: `ps -o args= -C kamaji | grep -c -- --native-exec-dir` = 1 on us-south-001, us-east-001 and us-west-001; `sha256sum /var/lib/yah-cloud/headscale/headscale` = d9193dad4b070b9b… on all three; `systemctl is-active kamaji` = active on all three. `/var/lib/yah-cloud/headscale/headscale version` printed v0.23.0 on both newly-provisioned nodes and the file is 51,593,368 bytes, matching west's byte-for-byte. Downloads were sha256-verified BEFORE install (arch-switched on `dpkg --print-architecture`, install aborts on mismatch), which is the standard mirror.yml's own block states. Mesh + public site after the last restart: cloud.mesh.yah.dev/key?v=138 = 200 in 0.16s, yah.dev = 200, yah.dev/releases = 200.")
//! @yah:gotcha("THE STALE `yah-marketing` CONTAINERD CONTAINER ON EAST IS REAL, IDENTIFIED, AND STILL THERE — R599-B11 predicted it and I confirmed it rather than reaping it. `sudo ctr -n yah c ls` on us-east-001 lists a container named `yah-marketing` running docker.io/nginxinc/nginx-unprivileged:alpine@sha256:592b23aa79a6… — the pre-bundle nginx stand-in, left over since before 2026-07-21. It holds the workload id and is what trips the duplicate-id warn on every List. R599-B11's own `next` already names reaping it as the ops follow-up; it is a deletion on a live node and on someone else's ticket, so I left it and am naming it here with the exact command that found it. NOT caused by this pass: it predates it, and enabling east's native backend did not add a second source.")
//! @yah:gotcha("WHAT THIS DOES *NOT* YET GIVE YOU, stated so nobody reads `review` as \"the rehearsal will pass\". A leadership move off us-west-001 today still does not produce a serving coordinator, and R858-T8 must not be attempted yet. The appliance needs four things on the node that takes it: the kamaji native backend (DONE on all three), the binary (DONE on all three), its identity (DONE — R858-T2's carriage is live and self-materialized a 72-byte noise_private.key on us-south-001 at 08:47Z with no human action, which is the first observation that T2 works end to end on a node that never ran the appliance), and its config + DB (NOT done — config.yaml is R858-T16, the DB is the litestream leg R858-T5 has never proven against the real bucket). The capability probe refuses on the missing config, so the failure is loud and early rather than a crash loop — but a refusal is not a failover. Also unchanged and still true: the R858-B13/B14 gotcha about NOT rolling us-west-001 to published 0.8.33. Nothing in this pass rolled any yubaba or kamaji binary; only a systemd drop-in and a headscale binary were placed.")
//! @yah:gotcha("TREE ANCHOR AT REVIEW: fc754ce6. Quote that SHA rather than 'HEAD' in any revert instruction — the camp shares one working tree and peers committed during this pass. Files this pass touched: oss/yubaba/crates/yubaba/src/leader.rs, oss/yubaba/crates/yubaba/src/headscale_appliance.rs, oss/kamaji/crates/kamaji-bin/src/server.rs, app/yah/cli/resources/kamaji.service. Note that headscale_appliance.rs was edited by a peer mid-pass (R858-B9's step-4 port reconciliation landed HEADSCALE_LISTEN_PORT under me); my two hunks there are additive helpers and survived, but diff before assuming which change is whose. NODE-SIDE ROLLBACK, if the drop-in rewrite ever needs reversing: `20-bundle.conf.rollback-20260906-coffee` sits beside the live file on both us-east-001 and us-south-001 — restoring it re-introduces the exact bug this ticket fixed, so it is provenance, not a safe state.")
//! @yah:handoff("CAPABILITY PROBE — THE T3 SEAM, FILLED (consolidated; this entry replaces three byte-near-identical copies a retry wrote). R858-T3 defined `NativeExecCapability::{Unknown,Present,Absent}` in appliance_ownership.rs, named it \"R858-T4's seam\", and passed the permissive `Unknown` placeholder from its one live call site. That placeholder is now a real probe and `judge_appliance_candidate` is unchanged, which is what T3 asked for. THE WIRE: `YubabaToKamaji::Capabilities { request_id }` and `KamajiToYubaba::CapabilitiesReport { request_id, capabilities: NodeCapabilities { native_exec, native_exec_dir } }`, both APPENDED LAST so every pre-existing postcard variant index is untouched and no ProtocolVersion bump is needed — the treatment `GracefulUpgrade` and `DeployStatus` already had. version.rs's V2/V4/V5/V6 bumps do not apply: those added a field to an EXISTING variant, which is positional and therefore breaking, and V6's note records that the `#[serde(default)]` theory cost a debugging cycle. The variant is also registered in `reply_request_id()` — R746-B11's doc comment on that function is explicit that an unclassified reply variant falls into the push arm, is dropped as an unconsumed push, and parks its caller on a oneshot forever, which is exactly what happened to `DeployStatusResult`. The hand-written correlation test covers `CapabilitiesReport`. KAMAJI ANSWERS FROM `ctx.native`, the same `Option<Arc<NativeRuntime>>` that `deploy_native_exec` dispatches on, so the capability a scheduler reads and the one a deploy exercises cannot disagree; deriving it from build features or CLI args would be a second source of truth that drifts exactly when it matters. `NativeRuntime::exec_dir()` was added to expose the staging dir. EVERY FAILURE TO *LEARN* IS `Unknown`, NEVER `Absent` — no sibling client, an older kamaji that does not know the variant, a transient socket error. Reading \"I could not ask\" as \"cannot run it\" would make every not-yet-rolled node ineligible the moment this shipped: the 2026-09-03 outage reproduced from the other side, and mid-roll that is most of the fleet. The old-kamaji case logs at `debug!` not `warn!` for the same reason — during a normal roll it is the expected answer on every tick, and a warning that fires constantly trains operators to ignore the channel T3 just made loud.")
//! @yah:gotcha("THIS PROBE DEADLOCKED WITH R858-T16 AND NO NODE COULD EVER GO Present — FOUND AND FIXED 2026-09-08 by @Ashguard:libra (session:6eed47dc) while running R858-T5's live exercise. probe_native_exec requires every argv path to exist, INCLUDING headscale_appliance::config_path (leader.rs:1130). T16 writes that config.yaml inside start_headscale, which is downstream of this candidacy judgement. So a node that had never hosted the appliance could never become eligible to run the hydration that would have made it eligible. MEASURED on us-west-011 with a musl yubaba cross-built from the tree carrying BOTH children (sha afd360dd3d9ce891edeac4bf9bbfa593ba3f254ffaff1edab133f221bd5a70f9), kamaji reporting native_exec true, headscale binary and noise key both on disk: `missing=/var/lib/yah-cloud/headscale/config.yaml` -> `APPLIANCE UNHEALTHY ... refusal: missing-native-exec`, on a 10s cadence, forever. THAT IS EXACTLY R858'S STATED ACCEPTANCE CHECK (\"probe_native_exec returning Present on us-south-001, which today returns Absent naming config.yaml\") — so as the tree stood it could not have passed on ANY node, and a roll of east+south would have left both refusing for the same reason west's dev twin did. THE FIX (leader.rs, new hydrate_config_before_probe): hydration runs immediately before the candidates map is built, and ONLY when config.yaml is absent — the early return is what keeps us-west-001's hand-edited config safe from a render on every 10s tick. FALSIFIED ON HARDWARE, single variable: same node, same config, same kamaji, only the binary swapped — the pre-fix binary loops the refusal, the post-fix binary logs `hydrated headscale config.yaml ahead of the appliance candidacy probe` outcome=Rendered and the appliance deploys 18ms later. Reproduced independently on us-west-013 (a node that had never hosted it) at 19:09:48Z.")
//! @yah:gotcha("THIS TICKET'S ACCEPTANCE CHECK IS NOT OBSERVABLE ON A FOLLOWER, AND R858's WORDING OF IT IS THEREFORE UNMEETABLE AS WRITTEN — measured 2026-09-08 by @Ashguard:libra (session:6eed47dc) on us-east-001 immediately after it was rolled to published 0.8.35, which is the first prod binary carrying leader.rs::hydrate_config_before_probe. R858 says the post-roll acceptance check is \"leader::probe_native_exec returning Present on us-south-001\". It cannot be, on any node that is not currently acting. `reconcile_appliance_ownership` returns early at `if !may_act { return; }`, where may_act = is_leader || recorded_owner == self, and that early return sits AHEAD of both the hydration and the probe. MEASURED: east is neither the raft leader (node 2 = us-west-001 leads, term 21) nor the recorded owner (us-south-001), and in 20 minutes on 0.8.35 it logged ZERO hydrate lines, ZERO probe lines, and its /var/lib/yah-cloud/headscale/ still holds ONLY the headscale binary — no config.yaml, no noise_private.key. THIS IS NOT A FAULT IN THE FIX and does not warrant a rollback: the fix is correctly placed for the node that ACTS, which is the only node whose eligibility is ever consulted (the candidates map is built from self alone, plus an expired owner). A follower does not need to be pre-hydrated so long as it hydrates when it becomes leader or recorded owner, which it now does — that is exactly the path us-south-001 took at 19:29:27Z. WHAT IT MEANS FOR SIGN-OFF: \"Present on a candidate\" is only ever observable at the moment of an actual ownership move, so this acceptance check does not stand alone — it collapses into R858-T8's rehearsal and should be signed off there rather than looked for on an idle follower. Anyone who greps a follower's journal for `Present` and finds nothing has measured the early return, not the fix.")

use std::collections::BTreeMap;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::cluster_policy::RaftTiming;
use crate::ingress_effector::EffectOutcome;
use crate::lease_detector::{
    judge_readiness, Confirmed, HysteresisPolicy, LeaseFailureDetector, NotReady,
    ReadinessInputs, TransitionTracker,
};
use crate::raft::{SlaTier, TenantDemand, YubabaNodeId, YubabaRaft, YubabaRequest, YubabaStateMachine};

/// Lease TTL requested on the tenant this loop just moved.
///
/// Mirrors `tenant_streamer::config::DEFAULT_LEASE_SECS` by convention, not by
/// a shared constant — this crate does not take a data-plane dependency on
/// `tenant_streamer` (see `lease_detector`'s module doc for the same rule
/// stated for the `ReadinessInputs` fields). Long relative to the streamer's
/// own renewal cadence for the same reason the streamer's default is: the
/// lease is a liveness *hint* bounding when a further takeover is permitted,
/// never the safety property (the epoch is), so a short value buys nothing but
/// spurious churn.
const TRANSFER_LEASE_SECS: u64 = 300;

/// How this loop is paced.
///
/// Unlike [`crate::leader_pin::PinConfig`], which is deliberately *slower*
/// than an election to avoid fighting one, this loop's anti-churn property
/// comes from [`HysteresisPolicy`]'s confirm dwell, not from its own pacing —
/// a dead owner's tenants should be re-placed promptly once R737-F2 has
/// actually confirmed the owner down. So `evaluate_every` tracks the raft
/// heartbeat instead of the election timeout.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub evaluate_every: Duration,
    pub hysteresis: HysteresisPolicy,
    pub transfer_lease_secs: u64,
}

impl SchedulerConfig {
    pub fn new(timing: RaftTiming, hysteresis: HysteresisPolicy) -> Self {
        Self {
            evaluate_every: Duration::from_millis(timing.heartbeat_interval_ms.max(1)) * 2,
            hysteresis,
            transfer_lease_secs: TRANSFER_LEASE_SECS,
        }
    }
}

/// One tenant's committed ownership plus declared intent, narrowed to what
/// [`decide_transfer`] needs — free of raft/state-machine types so it is
/// testable as arithmetic, the same discipline
/// [`crate::leader_pin::decide`] uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSnapshot {
    pub owner: YubabaNodeId,
    pub epoch: u64,
    /// From `TenantPlacement::region`, or `None` if this tenant has no
    /// declared intent at all — same reading either way: unconstrained.
    pub region: Option<String>,
    pub tier: SlaTier,
    pub demand: TenantDemand,
    /// The RPO bound a candidate's streamer must be caught up within, from
    /// this tenant's tier. `None` — the only value [`run`] can produce today —
    /// means no target is configured, which
    /// [`judge_readiness`] treats as vacuously satisfied. See the module doc.
    pub rpo_bound: Option<Duration>,
}

/// One candidate node's eligibility to receive a tenant, precomputed by the
/// caller so `decide_transfer` needs no I/O and no lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEligibility {
    /// Straight from [`TransitionTracker::committed`]. `None` (never confirmed
    /// either way) fails the gate exactly like `Some(Confirmed::Down)` — the
    /// fail-closed rule [`ReadinessInputs::liveness`] states, carried here
    /// unflattened so a caller cannot lose the distinction on the way in.
    pub liveness: Option<Confirmed>,
    /// Whether this node's raft peer link is *not* known-dead. A veto only:
    /// see the module doc for why the raft-heartbeat channel may refuse a
    /// candidate but never justify one.
    pub raft_peer_healthy: bool,
    pub region: Option<String>,
    /// `YubabaStateMachine::node_admits` for this tenant's demand — the
    /// headroom floor R737-F1 already built.
    pub admits: bool,
    /// Whether this node already holds a warm replica of the tenant being
    /// placed. Always `false` from the live call site today — see this
    /// module's doc for why, and for why this doubles as the `hydrated`
    /// evidence a [`SlaTier::WarmReplica`] tenant needs.
    pub warm_for_tenant: bool,
    /// Elapsed time since this tenant's WAL watermark last advanced on this
    /// node. Always `None` from the live call site today — see the module doc.
    pub streamer_watermark_age: Option<Duration>,
}

/// What [`decide_transfer`] concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementDecision {
    /// The owner is not confirmed down. Nothing to do — this is the steady
    /// state for almost every tenant on almost every tick.
    OwnerLive,
    /// The owner is confirmed down, but no candidate is both live and
    /// admitting (and, for a warm-tier tenant, already warm). Includes the
    /// case that matters most: a cluster-wide capacity crunch, where the
    /// correct answer is to leave the tenant unplaced rather than overcommit
    /// a node or guess at warmth.
    NoEligibleCandidate,
    /// Commit `TransferTenant` to this node.
    TransferTo(YubabaNodeId),
}

/// Project one candidate onto W253 §7's readiness gates and defer to
/// [`judge_readiness`] — the *only* place this module decides whether a node
/// may own a tenant.
///
/// The projection is where the tenant-relative reading of each gate lives:
/// `hydrated` collapses the warm-tier requirement (see the module doc), the RPO
/// bound comes from the tenant while the watermark comes from the node, and
/// liveness passes through unflattened. Everything else is
/// `judge_readiness`'s call, in `judge_readiness`'s order, so the refusal a
/// caller sees here is the same one R737-F2 defines.
///
/// Note what is *not* here: the region preference. That is a ranking among
/// ready nodes, not a readiness gate — an out-of-region node is perfectly ready
/// to own the tenant, just less preferred, and treating it as a gate is the
/// failure mode [`decide_transfer`]'s doc argues against.
pub fn judge_candidate(
    tenant: &TenantSnapshot,
    elig: &NodeEligibility,
) -> Result<(), NotReady> {
    judge_readiness(&ReadinessInputs {
        liveness: elig.liveness,
        raft_peer_healthy: elig.raft_peer_healthy,
        // Not measured — derived from the tier. A cold tenant hydrates *as
        // part of* the transfer, so requiring it first would deadlock; a warm
        // tenant's hydration evidence is exactly `warm_for_tenant`.
        hydrated: tenant.tier != SlaTier::WarmReplica || elig.warm_for_tenant,
        within_headroom: elig.admits,
        streamer_watermark_age: elig.streamer_watermark_age,
        streamer_rpo_bound: tenant.rpo_bound,
    })
}

/// Decide whether — and where — to re-place one tenant, given a snapshot of
/// its committed state and a precomputed view of every other node's
/// eligibility.
///
/// **Region-preferred, not region-required**: a candidate in the tenant's
/// declared region is preferred over one outside it, but an out-of-region
/// live, admitting (and warm, if required) node is still chosen over leaving
/// the tenant unplaced — W246 says "in-region-preferred", and the failure
/// mode of treating it as a hard filter is a tenant stuck down because its
/// only declared region lost every node, which is exactly the availability
/// case the whole relay exists to prevent.
///
/// Ties (after the region preference) break to the lowest node id, so two
/// evaluations of the same state — this leader on the next tick, or a new
/// leader after failover — reach the same target rather than thrashing.
pub fn decide_transfer(
    owner_confirmed_down: bool,
    tenant: &TenantSnapshot,
    candidates: &BTreeMap<YubabaNodeId, NodeEligibility>,
) -> PlacementDecision {
    if !owner_confirmed_down {
        return PlacementDecision::OwnerLive;
    }
    let mut eligible: Vec<(YubabaNodeId, &NodeEligibility)> = candidates
        .iter()
        .filter(|(id, elig)| **id != tenant.owner && judge_candidate(tenant, elig).is_ok())
        .map(|(id, elig)| (*id, elig))
        .collect();
    eligible.sort_by_key(|(id, elig)| {
        let out_of_region = match &tenant.region {
            Some(r) => elig.region.as_deref() != Some(r.as_str()),
            None => false,
        };
        (out_of_region, *id)
    });
    match eligible.first() {
        Some((id, _)) => PlacementDecision::TransferTo(*id),
        None => PlacementDecision::NoEligibleCandidate,
    }
}

/// The optional collaborators the tick reads — every one of which a
/// deployment, or a test, may legitimately not have.
///
/// A struct rather than four positional `Option`s: they are all
/// `Option<Arc<…>>` of different traits, so at a call site any two could be
/// swapped with no type error on three of the four, and the failure would be
/// silent (a scheduler that quietly stopped gating, not one that failed to
/// compile). R859-F2 phase B's `ingress` is what took the count past readable.
///
/// [`Default`] is all-`None`, which is exactly "behaves as it did before any of
/// these gates existed" — see each field.
#[derive(Default)]
pub struct SchedulerDeps {
    /// R737-F2's node-lease channel — the evidence `decide_transfer` acts on.
    /// `None` means nothing is ever confirmed up or down, so nothing moves.
    pub lease_detector: Option<std::sync::Arc<LeaseFailureDetector>>,
    /// The `raft_peer_healthy` gate, and **only as a veto** — `None` leaves
    /// that gate open rather than freezing placement, so a deployment (or a
    /// harness) without one behaves exactly as it did before the gate existed.
    /// See the module doc.
    pub raft_detector: Option<std::sync::Arc<dyn crate::failure_detector::FailureDetector>>,
    /// R782: `streamer_watermark_age` per candidate. `None` has the same
    /// "behaves like before the gate existed" property — but only for tenants
    /// with no `rpo_bound` declared; a tenant that *does* declare one and gets
    /// `None` here fails every candidate closed, per `judge_readiness`'s
    /// absence-of-evidence rule.
    pub rpo_registry: Option<std::sync::Arc<crate::lease_detector::RpoWatermarkRegistry>>,
    /// R859-F2 phase B: the public-ingress effector. It rides this loop rather
    /// than one of its own because this is the one place per tick that already
    /// holds every input the decision needs — the leader check, the
    /// [`TransitionTracker`] that says whether a machine is confirmed down, and
    /// the quorum verdict. A second loop would have to duplicate all three and
    /// could disagree with this one about any of them. `None` — every camp that
    /// has not set `YUBABA_INGRESS_APEX` — skips the ingress plan entirely.
    pub ingress: Option<crate::ingress_effector::IngressEffector>,
}

/// Spawn the scheduler loop.
///
/// Safe to run on every node, like [`crate::leader_pin::spawn`]: a follower's
/// tick finds `current_leader != Some(node_id)` and does nothing but advance
/// its own (unused) [`TransitionTracker`].
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    deps: SchedulerDeps,
    config: SchedulerConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state_machine, deps, config).await;
    })
}

async fn run(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    deps: SchedulerDeps,
    config: SchedulerConfig,
) {
    let SchedulerDeps {
        lease_detector,
        raft_detector,
        rpo_registry,
        ingress,
    } = deps;
    use crate::failure_detector::{FailureDetector, LivenessReport};
    use openraft::async_runtime::watch::WatchReceiver;

    info!(
        node_id,
        evaluate_every = ?config.evaluate_every,
        "tenant placement scheduler active"
    );
    let watch = raft.metrics();
    let mut tracker = TransitionTracker::new();
    // R859-F2 phase B. `plan_ingress_owner_effect` is stateless, so "the owner
    // changed" has to mean "changed since the last tick THIS process saw" —
    // there is nowhere else to hold it. Starting at `None` on a freshly elected
    // leader is correct rather than a gap: the first tick reads an existing
    // owner as a change and converges the IP onto it (idempotently — see
    // `a_first_observation_of_an_existing_owner_converges_the_ip`), and the
    // withdrawal path, which needs an *unchanged* owner, arms on the tick after.
    let mut previous_ingress_owner: Option<String> = None;

    loop {
        tokio::time::sleep(config.evaluate_every).await;

        let is_leader = watch.borrow_watched().current_leader == Some(node_id);

        // Feed the tracker every tick, leader or not, so a node's hysteresis
        // state is already warm if it becomes leader mid-dwell rather than
        // starting the confirm window over at the moment it matters most.
        // Harmless on a follower: nobody renews against a non-leader (R737-F2
        // §"nodes renew ... via the leader"), so its report is empty and
        // `observe` is a no-op.
        let report: LivenessReport = match &lease_detector {
            Some(d) => d.observe().await,
            None => LivenessReport::new(),
        };
        tracker.observe(&report, config.hysteresis, std::time::Instant::now());

        if !is_leader {
            continue;
        }

        let now_unix = unix_now_secs();
        let members = state_machine.members();
        let tenants = state_machine.tenants();

        // The veto channel. Empty on a follower, empty when no detector is
        // attached, and empty of any node it has no acknowledgement for — all
        // of which read as "no objection", never as "unhealthy". See module doc.
        let raft_report: LivenessReport = match &raft_detector {
            Some(d) => d.observe().await,
            None => LivenessReport::new(),
        };

        // R859-F2: `yubaba-failover.md` pre-check 1 ("do not fail over out of a
        // degraded quorum — you will lose it entirely"), computed here because
        // this is the one place per tick that holds both of its inputs at once:
        // the voter set from the metrics watch and the raft channel's report,
        // already fetched above.
        //
        // The raft channel is the right one to count on: whether a voter can
        // *commit* is a raft question, unlike the lease channel that decides
        // placement. Note this does NOT extend the raft channel's authority —
        // it still only ever subtracts (`judge_quorum` counts an explicit
        // `Down` and nothing else), which is the same veto-only direction the
        // module doc above argues for.
        //
        // Deliberately NOT gating tenant placement below. Placement is an
        // *addition* — it hands a tenant to a live node — and R859-F2 decision
        // 3 gates withdrawals only, fail-closed on withdrawal / fail-open on
        // addition, the same rule R859-F1 set for its apex prune. Refusing to
        // re-place a tenant during a degraded quorum would strand it on a dead
        // owner for exactly as long as the cluster is unwell, which is backwards.
        // The consumer is the ingress effector (see
        // `cloud::provider::floating_ip::plan_ingress_owner_effect`), so today
        // this is observability; when that effector is attached it reads this.
        let quorum = crate::quorum_health::judge_quorum(
            &watch
                .borrow_watched()
                .membership_config
                .membership()
                .voter_ids()
                .collect::<Vec<_>>(),
            &raft_report,
        );
        if !quorum.permits_withdrawal() {
            debug!(node_id, verdict = %quorum.reason(), "quorum not healthy this tick");
        }

        // R859-F2 phase B: public ingress follows placement. Everything this
        // needs is already in hand — the leader check above, the tracker, the
        // quorum verdict — which is why it lives in this tick and not a loop of
        // its own.
        if let Some(effector) = &ingress {
            let current_owner = state_machine.ingress_owner();
            // Liveness may only ever VETO here (see
            // `plan_ingress_owner_effect`'s doc): an owner we cannot resolve to
            // a node id, or one the hysteresis has not committed either way, is
            // `Unconfirmed` — never `ConfirmedDown`. Reading "no mapping" as
            // "dead" would withdraw a live origin on the strength of a missing
            // member row.
            let liveness = crate::ingress_effector::owner_liveness(
                current_owner
                    .as_deref()
                    .and_then(|machine| state_machine.node_for_machine(machine)),
                |id| tracker.committed(id),
            );
            // One snapshot of the declarations, used by both halves: the
            // planner decides against it, and the effector re-resolves the
            // named machine out of it to learn which vendor hosts the box.
            // Taking it twice would let the two halves disagree within one tick.
            let machines = state_machine.floating_ip_machines();
            let effect = floating_ip::plan_ingress_owner_effect(
                previous_ingress_owner.as_deref(),
                current_owner.as_deref(),
                liveness,
                &quorum.as_ingress_health(),
                &machines,
            );
            let outcome = effector
                .apply(&effect, &machines, |machine| {
                    state_machine.public_address_for_machine(machine)
                })
                .await;
            match &outcome {
                EffectOutcome::Withdrew {
                    machine,
                    address,
                    records_deleted,
                } if *records_deleted > 0 => info!(
                    node_id,
                    machine = %machine,
                    address = %address,
                    records_deleted,
                    apex = effector.apex().unwrap_or_default(),
                    "withdrew a dead origin from the public apex"
                ),
                // Already withdrawn on an earlier tick — the ordinary steady
                // state while a node stays down, and not worth an info line
                // once per tick for the duration of an outage.
                EffectOutcome::Withdrew { .. } => {}
                EffectOutcome::Reassigned {
                    machine,
                    ip_id,
                    moved: true,
                } => info!(
                    node_id,
                    machine = %machine,
                    ip_id = %ip_id,
                    "moved the ingress floating IP onto the new owner"
                ),
                // Already pointed at the right box — same non-news as an
                // already-withdrawn record above.
                EffectOutcome::Reassigned { .. } => {}
                EffectOutcome::Failed { reason } => {
                    warn!(node_id, "ingress withdrawal failed, will retry: {reason}")
                }
                EffectOutcome::NotApplied { reason } => {
                    debug!(node_id, "no ingress effect: {reason}")
                }
            }
            // Do not advance the owner marker past a FAILED apply. The planner
            // is stateless, so this marker is the only thing that would stop
            // the next tick from re-deciding — and a withdrawal that did not
            // land must be re-decided, not recorded as done.
            if !matches!(outcome, EffectOutcome::Failed { .. }) {
                previous_ingress_owner = current_owner;
            }
        }

        for (tenant, ownership) in &tenants {
            let owner_confirmed_down = tracker.committed(ownership.owner) == Some(Confirmed::Down);
            if !owner_confirmed_down {
                continue;
            }
            let placement = state_machine.tenant_placement(tenant);
            let snapshot = TenantSnapshot {
                owner: ownership.owner,
                epoch: ownership.epoch,
                region: placement.as_ref().and_then(|p| p.region.clone()),
                tier: placement.as_ref().map_or_else(SlaTier::default, |p| p.tier),
                demand: placement.as_ref().map_or_else(TenantDemand::default, |p| p.demand),
                // R782: TenantPlacement now carries the declared RPO target
                // directly; `None` for any tenant that never had one set.
                rpo_bound: placement.as_ref().and_then(|p| p.rpo_bound),
            };
            let candidates: BTreeMap<YubabaNodeId, NodeEligibility> = members
                .iter()
                .filter(|(id, _)| **id != snapshot.owner)
                .map(|(id, info)| {
                    (
                        *id,
                        NodeEligibility {
                            liveness: tracker.committed(*id),
                            raft_peer_healthy: raft_peer_healthy(&raft_report, *id),
                            region: info.region.clone(),
                            admits: state_machine.node_admits(*id, &snapshot.demand, now_unix),
                            // W248 unpopulated — see module doc.
                            warm_for_tenant: false,
                            // R782: whatever this candidate's own streamer
                            // last pushed over `POST /mesh/rpo-report`, or
                            // `None` if it never has (fail-closed — see the
                            // module doc and `spawn`'s doc on `rpo_registry`).
                            streamer_watermark_age: rpo_registry
                                .as_ref()
                                .and_then(|r| r.watermark_age(*id, tenant)),
                        },
                    )
                })
                .collect();

            match decide_transfer(owner_confirmed_down, &snapshot, &candidates) {
                PlacementDecision::OwnerLive => {}
                PlacementDecision::NoEligibleCandidate => {
                    // Report *which* gate each candidate failed. "No eligible
                    // candidate" alone is the least actionable line an operator
                    // can be handed during an outage — a capacity crunch, a
                    // fleet that has not been confirmed live yet, and a
                    // warm-tier tenant that can never place until W248 lands
                    // are three very different problems with one message.
                    let refusals = candidates
                        .iter()
                        .map(|(id, elig)| {
                            format!("{id}={}", refusal_str(judge_candidate(&snapshot, elig)))
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                    warn!(
                        node_id,
                        tenant = %tenant.0,
                        dead_owner = ownership.owner,
                        %refusals,
                        "scheduler: owner confirmed down but no candidate passed the readiness \
                         gates — tenant stays unplaced this tick"
                    );
                }
                PlacementDecision::TransferTo(target) => {
                    let req = YubabaRequest::TransferTenant {
                        tenant: tenant.clone(),
                        to: target,
                        from_epoch: snapshot.epoch,
                        lease_secs: config.transfer_lease_secs,
                        now: now_unix,
                    };
                    info!(
                        node_id,
                        tenant = %tenant.0,
                        dead_owner = ownership.owner,
                        target,
                        from_epoch = snapshot.epoch,
                        "scheduler: re-placing tenant off a confirmed-down owner"
                    );
                    if let Err(e) = raft.client_write(req).await {
                        warn!(
                            node_id,
                            tenant = %tenant.0,
                            target,
                            "scheduler: TransferTenant commit failed, will re-evaluate next tick: {e}"
                        );
                    }
                }
            }
        }
    }
}

/// The raft channel's veto, per the module doc: only an explicit `Down`
/// observation refuses. A node absent from the report has not been *judged* by
/// this channel — on the leader that means it never acked, on a follower it
/// means the channel has no view at all — and the
/// [`FailureDetector`](crate::failure_detector::FailureDetector) trait is
/// explicit that absence is not death.
fn raft_peer_healthy(report: &crate::failure_detector::LivenessReport, node: YubabaNodeId) -> bool {
    !matches!(
        report.get(&node).map(|obs| obs.liveness),
        Some(crate::failure_detector::NodeLiveness::Down)
    )
}

/// Stable lowercase spelling of a readiness verdict, for the operator-facing
/// refusal line. Mirrors [`crate::failure_detector::NodeLiveness::as_str`]'s
/// contract: a wire/log token, never prose.
fn refusal_str(verdict: Result<(), NotReady>) -> &'static str {
    match verdict {
        Ok(()) => "ready",
        Err(NotReady::NotLive) => "not-live",
        Err(NotReady::RaftPeerUnhealthy) => "raft-peer-unhealthy",
        Err(NotReady::NotHydrated) => "not-hydrated",
        Err(NotReady::StreamerBehindBound) => "streamer-behind-bound",
        Err(NotReady::OverHeadroom) => "over-headroom",
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(owner: YubabaNodeId, region: Option<&str>, tier: SlaTier) -> TenantSnapshot {
        TenantSnapshot {
            owner,
            epoch: 3,
            region: region.map(str::to_string),
            tier,
            demand: TenantDemand::default(),
            rpo_bound: None,
        }
    }

    fn node(confirmed_up: bool, region: Option<&str>, admits: bool) -> NodeEligibility {
        NodeEligibility {
            liveness: confirmed_up.then_some(Confirmed::Up),
            raft_peer_healthy: true,
            region: region.map(str::to_string),
            admits,
            warm_for_tenant: false,
            streamer_watermark_age: None,
        }
    }

    #[test]
    fn a_live_owner_is_left_alone_regardless_of_candidates() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([(2, node(true, None, true))]);
        assert_eq!(decide_transfer(false, &s, &candidates), PlacementDecision::OwnerLive);
    }

    #[test]
    fn a_confirmed_dead_owner_re_places_onto_the_only_live_admitting_node() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([
            (2, node(false, None, true)), // not confirmed up
            (3, node(true, None, false)), // no room
            (4, node(true, None, true)),  // the one
        ]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(4));
    }

    #[test]
    fn no_live_admitting_candidate_is_reported_rather_than_guessed() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([
            (2, node(false, None, true)),
            (3, node(true, None, false)),
        ]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::NoEligibleCandidate);
    }

    #[test]
    fn the_dead_owner_itself_is_never_a_candidate() {
        // Even if somehow present in the candidate map with every gate open
        // (a stale read, a test double), the owner must never be offered
        // itself as the re-placement target.
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([(1, node(true, None, true))]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::NoEligibleCandidate);
    }

    #[test]
    fn in_region_candidate_is_preferred_over_an_out_of_region_one() {
        let s = snapshot(1, Some("us-west"), SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([
            (2, node(true, Some("us-east"), true)),
            (3, node(true, Some("us-west"), true)),
        ]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(3));
    }

    /// W246: "in-region-preferred", not in-region-required. Leaving a tenant
    /// down because its home region has no live capacity is the exact
    /// availability failure this relay exists to prevent.
    #[test]
    fn an_out_of_region_candidate_is_used_when_no_in_region_one_exists() {
        let s = snapshot(1, Some("us-west"), SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([(2, node(true, Some("us-east"), true))]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(2));
    }

    #[test]
    fn ties_after_region_preference_break_to_the_lowest_node_id() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([
            (5, node(true, None, true)),
            (2, node(true, None, true)),
            (9, node(true, None, true)),
        ]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(2));
    }

    #[test]
    fn a_warm_replica_tenant_requires_an_already_warm_candidate() {
        let s = snapshot(1, None, SlaTier::WarmReplica);
        let candidates = BTreeMap::from([(2, node(true, None, true))]); // live, admits, but not warm
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::NoEligibleCandidate);

        let mut warm_candidate = node(true, None, true);
        warm_candidate.warm_for_tenant = true;
        let candidates = BTreeMap::from([(2, warm_candidate)]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(2));
    }

    #[test]
    fn a_cold_hydrate_tenant_does_not_require_warmth() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let candidates = BTreeMap::from([(2, node(true, None, true))]);
        assert_eq!(decide_transfer(true, &s, &candidates), PlacementDecision::TransferTo(2));
    }

    // ── readiness gates now actually gate (R737-F2) ──────────────────────

    /// The gate that had no call site at all before: a node the lease channel
    /// confirmed live, with room, whose raft peer link is dead must not be
    /// handed a tenant it cannot then be fenced through.
    #[test]
    fn a_confirmed_live_node_with_a_dead_raft_peer_is_refused() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let mut sick = node(true, None, true);
        sick.raft_peer_healthy = false;
        assert_eq!(judge_candidate(&s, &sick), Err(NotReady::RaftPeerUnhealthy));

        let candidates = BTreeMap::from([(2, sick), (3, node(true, None, true))]);
        assert_eq!(
            decide_transfer(true, &s, &candidates),
            PlacementDecision::TransferTo(3),
            "a healthy higher-id node must beat an unhealthy lower-id one"
        );
    }

    /// A never-confirmed node and a confirmed-down one are both `NotLive`, but
    /// they are distinct inputs — the old `confirmed_up: bool` flattened them
    /// on the way in, which is exactly what `ReadinessInputs::liveness`'s doc
    /// asks callers not to do.
    #[test]
    fn never_confirmed_and_confirmed_down_are_both_not_live() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        let mut never = node(true, None, true);
        never.liveness = None;
        assert_eq!(judge_candidate(&s, &never), Err(NotReady::NotLive));

        let mut down = node(true, None, true);
        down.liveness = Some(Confirmed::Down);
        assert_eq!(judge_candidate(&s, &down), Err(NotReady::NotLive));

        let candidates = BTreeMap::from([(2, never), (3, down)]);
        assert_eq!(
            decide_transfer(true, &s, &candidates),
            PlacementDecision::NoEligibleCandidate
        );
    }

    /// The warm-tier requirement and the `hydrated` gate are one rule, not
    /// two: a cold tenant hydrates as part of the transfer, a warm one must
    /// already be there.
    #[test]
    fn hydration_is_the_warm_tier_requirement_not_a_second_gate() {
        let cold = snapshot(1, None, SlaTier::ColdHydrate);
        let warm = snapshot(1, None, SlaTier::WarmReplica);
        let bare = node(true, None, true);
        let mut warmed = node(true, None, true);
        warmed.warm_for_tenant = true;

        assert_eq!(judge_candidate(&cold, &bare), Ok(()));
        assert_eq!(judge_candidate(&warm, &bare), Err(NotReady::NotHydrated));
        assert_eq!(judge_candidate(&warm, &warmed), Ok(()));
    }

    /// Once an RPO bound *is* plumbed through, the gate is live with no
    /// further wiring — this pins the projection, not `judge_readiness`'s own
    /// arithmetic (which `lease_detector` already covers).
    #[test]
    fn an_rpo_bound_on_the_tenant_gates_against_the_nodes_watermark() {
        let mut s = snapshot(1, None, SlaTier::ColdHydrate);
        s.rpo_bound = Some(Duration::from_secs(30));

        let mut behind = node(true, None, true);
        behind.streamer_watermark_age = Some(Duration::from_secs(60));
        assert_eq!(
            judge_candidate(&s, &behind),
            Err(NotReady::StreamerBehindBound)
        );

        let mut caught_up = node(true, None, true);
        caught_up.streamer_watermark_age = Some(Duration::from_secs(1));
        assert_eq!(judge_candidate(&s, &caught_up), Ok(()));

        // No watermark at all against a real bound is not evidence of being
        // caught up. At the live `run()` call site (R782) this is exactly
        // what happens to every candidate for a bound tenant until some node
        // other than the (excluded) owner has pushed a fresh
        // `POST /mesh/rpo-report` for it — W248's warm fan-out, not a bug in
        // this plumbing. See the module doc.
        assert_eq!(
            judge_candidate(&s, &node(true, None, true)),
            Err(NotReady::StreamerBehindBound)
        );
    }

    /// The default at the live call site for any tenant that has never had an
    /// RPO target declared: `TenantPlacement.rpo_bound` reads `None`
    /// (R782 plumbed the field; an operator still has to set it), so the gate
    /// stays vacuously satisfied exactly as it did before R782 landed. If
    /// this ever starts refusing for an undeclared tenant, `rpo_bound` is
    /// leaking a stale value from somewhere, not "the plumbing landed
    /// without its bound" (that phase is over — both inputs are wired).
    #[test]
    fn an_undeclared_rpo_target_stays_vacuous_by_default() {
        let s = snapshot(1, None, SlaTier::ColdHydrate);
        assert_eq!(s.rpo_bound, None);
        let candidate = node(true, None, true);
        assert_eq!(candidate.streamer_watermark_age, None);
        assert_eq!(judge_candidate(&s, &candidate), Ok(()));
    }

    #[test]
    fn the_raft_veto_only_fires_on_an_explicit_down() {
        use crate::failure_detector::{LivenessReport, NodeLiveness, NodeObservation};

        let obs = |liveness| NodeObservation {
            liveness,
            silent_for_ms: None,
        };
        let report: LivenessReport = [
            (1, obs(NodeLiveness::Live)),
            (2, obs(NodeLiveness::Suspect)),
            (3, obs(NodeLiveness::Unknown)),
            (4, obs(NodeLiveness::Down)),
        ]
        .into_iter()
        .collect();

        assert!(raft_peer_healthy(&report, 1));
        assert!(raft_peer_healthy(&report, 2), "slow is not dead");
        assert!(raft_peer_healthy(&report, 3), "unjudged is not dead");
        assert!(!raft_peer_healthy(&report, 4));
        assert!(
            raft_peer_healthy(&report, 99),
            "a node this channel has never seen must not be vetoed by it"
        );
        assert!(
            raft_peer_healthy(&LivenessReport::new(), 1),
            "an empty report (follower, or no detector) must veto nobody — \
             otherwise placement freezes fleet-wide"
        );
    }

    #[test]
    fn refusal_strings_are_stable_log_tokens() {
        assert_eq!(refusal_str(Ok(())), "ready");
        assert_eq!(refusal_str(Err(NotReady::NotLive)), "not-live");
        assert_eq!(
            refusal_str(Err(NotReady::RaftPeerUnhealthy)),
            "raft-peer-unhealthy"
        );
        assert_eq!(refusal_str(Err(NotReady::NotHydrated)), "not-hydrated");
        assert_eq!(
            refusal_str(Err(NotReady::StreamerBehindBound)),
            "streamer-behind-bound"
        );
        assert_eq!(refusal_str(Err(NotReady::OverHeadroom)), "over-headroom");
    }

    #[test]
    fn scheduler_config_paces_off_the_heartbeat_not_the_election() {
        use crate::cluster_policy::ClusterPolicy;
        let policy = ClusterPolicy::fleet();
        let cfg = SchedulerConfig::new(policy.timing, HysteresisPolicy::from_thresholds(policy.liveness_thresholds()));
        assert_eq!(
            cfg.evaluate_every,
            Duration::from_millis(policy.timing.heartbeat_interval_ms * 2)
        );
    }
}
