//! Cluster policy — the deployment-wide rules a yubaba cluster runs under,
//! named as a value instead of hardcoded at the sites that obey them.
//!
//! Three rules were, until this module existed, invisible decisions living in
//! doc comments and literals:
//!
//! | rule | used to live at | now |
//! |---|---|---|
//! | joining nodes stay learners forever | prose in `raft_add_learner`'s doc comment | [`VoterAdmission`] |
//! | the raft leader is also the external-ingress owner | `leader::on_became_leader` writing `SetIngressOwner` unconditionally | [`IngressOwnership`] |
//! | election/heartbeat timings tuned for cross-region WAN | three literals in `raft::open_with_state_machine` | [`RaftTiming`] |
//! | voters span regions, no region holds a majority | W247 prose and nowhere else — nothing enforced it | [`QuorumGeography`] |
//!
//! Naming them is worth doing for the fleet on its own: "why is this cluster's
//! election timeout 3 seconds" and "why can't I promote this node" now have
//! answers you can read, test, and print, rather than answers you have to
//! excavate. That the same seam lets a second kind of deployment exist is a
//! consequence, not the motivation.
//!
//! # This is a value, not a mode enum
//!
//! There is deliberately **no** `enum ClusterMode { Fleet, Gallery }` that call
//! sites match on. With ~40 HTTP routes a `if mode == Gallery` branch would
//! metastasise, and it is the type-name-sniffing anti-pattern: behaviour keyed
//! on an identity label rather than on the property actually being decided.
//! Instead every decision point reads *the field that answers its question* —
//! [`ClusterPolicy::voter_admission`], [`ClusterPolicy::ingress_ownership`],
//! [`ClusterPolicy::timing`]. [`ClusterPolicy::fleet`] and
//! [`ClusterPolicy::rig`] are constructors for such a value and nothing more;
//! nothing downstream can ask "which preset am I?", because the answer is not
//! recorded.
//!
//! # Static per deployment
//!
//! The policy is chosen once, at process start (`yubaba serve
//! --cluster-profile`), and never negotiated at runtime. A cluster does not
//! discover its policy from peers at join time, and two clusters running
//! different policies never merge: a rig founds its own cluster and talks to
//! the cloud over ordinary API calls, never by joining the cloud's raft.
//!
//! @yah:ticket(R734-T1, "Enable pre-vote: set enable_pre_vote in RaftTiming::to_openraft_config AND implement RaftNetworkV2::pre_vote + its route")
//! @yah:status(review)
//! @yah:at(2026-08-10T19:36:43Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P1)
//! @yah:parent(R734)
//! @yah:next("Tier: Warrior — a consensus-behaviour change on a live 3-voter fleet; the transport half makes it more than a config flip.")
//! @yah:next("VERIFIED 2026-08-09: openraft 0.10.0-alpha.30 HAS `enable_pre_vote: Option<bool>`, and `get_enable_pre_vote()` treats None as FALSE — so pre-vote is OFF today. to_openraft_config (cluster_policy.rs:217) sets only heartbeat/election bounds and takes ..Default::default().")
//! @yah:next("It is NOT a one-line config change: openraft 0.10 routes pre-vote through RaftNetworkV2::pre_vote, and yubaba's impl (raft/network.rs:164) provides only append_entries, vote, full_snapshot, transfer_leader. The default no-op impl makes pre-vote inert. Add the transport method plus the HTTP route alongside /raft/vote.")
//! @yah:next("Set it on RaftTiming::wan() (the fleet preset) at minimum; decide whether rig()/LAN wants it too.")
//! @yah:verify("cargo test -p yubaba --lib cluster_policy")
//! @yah:verify("cargo test -p yubaba --test integration_mesh")
//! @yah:handoff("LANDED. Pre-Vote is on for every yubaba cluster, with the transport half it needs. Three coupled edits: (1) cluster_policy.rs to_openraft_config sets enable_pre_vote: Some(true); (2) raft/network.rs implements RaftNetworkV2::pre_vote (POSTs /raft/pre-vote); (3) lib.rs adds the POST /raft/pre-vote route + fn raft_pre_vote handler calling Raft::pre_vote. The ticket was right that this is not a one-line config flip: openraft 0.10's default pre_vote impl GRANTS unconditionally, so the flag without the transport is inert - a pre-candidate collects a fabricated quorum and campaigns exactly as it did before.")
//! @yah:handoff("DECISION 1 - both presets, and NOT a policy field. cluster_policy.rs's module docs say a field earns its place by answering a question some decision point asks; no decision point asks this one. The WAN wants Pre-Vote because transatlantic jitter is what produces a doomed candidate; the LAN wants it because a rebooting peer is the same shape at a shorter timescale. Cost either way is one extra round trip, paid only on an election, which by definition only happens when the leader is already gone. A knob here would exist solely to be turned the wrong way. Set unconditionally in to_openraft_config with that reasoning in the doc comment.")
//! @yah:handoff("DECISION 2 - a peer's HTTP 404 counts as a GRANT; a dead socket does not. This is the load-bearing call. openraft counts only an affirmative Ok(granted) toward the Pre-Vote quorum - an Err is never a grant, deliberately, so an isolated node cannot synthesize a quorum from its own unreachable peers. The naive implementation maps an old peer's 404 to Err, and then a mixed cluster cannot elect after a leader death, silently, with nothing log-shaped to find. YubabaNetwork::pre_vote instead treats 404 specifically as a grant (the peer ANSWERED - it is reachable, its build just has no route), which is exactly the degrade openraft's own default impl provides. Connect failures still return Err, so the isolated-node protection is untouched. Required splitting request() into post() + decode() so pre_vote can see the bare status instead of an opaque NetworkError string.")
//! @yah:handoff("EPOCH VERDICT: cluster_protocol stays at 4, hash re-recorded (dfdaf17f...). state_epoch stayed GREEN untouched and correctly so - a Pre-Vote produces no log entry, so it has no on-disk existence. Full reasoning in oss/yubaba/crates/yubaba/cluster-epochs.json surface_rerecords[2026-08-10]: old-dials-new is a no-op (openraft's enable_pre_vote default None reads as false, so an old node never sends one), new-dials-old degrades via the 404 rule, and no new wire type is introduced - /raft/pre-vote carries the same VoteRequest/VoteResponse /raft/vote always has. Explicitly NOT the R732-F1 shape (new replicated enum variants an old node cannot apply); nothing here is replicated at all.")
//! @yah:handoff("DISCOVERED WORK, done in this pass: three doc claims this work disproved. W247-multiregion-raft-quorum.md said pre-vote was 'relying on openraft defaults' - openraft's default is DISABLED, so that phrasing hid that it was simply off; corrected inline with the shipped state and the divergence from its own sketched design. W247's OVH checklist step 2 told an operator to go turn pre-vote on, now the default. W253-tenant-db-platform-architecture.md:243 said 'Pre-vote is still off and openraft 0.10 routes it through a RaftNetworkV2::pre_vote method yubaba does not implement' - now false in both halves; rewritten, and its Sec-10 checklist box ticked.")
//! @yah:next("R734-F2 (region tag + quorum-geography invariant) is the next ticket in number order and is unblocked by this. Nothing in T1 constrains it; MemberInfo was not touched.")
//! @yah:verify("cargo test -p yubaba --lib = 376 passed / 0 failed (372 baseline from R732 + 3 transport tests in raft::network::tests + 1 cluster_policy test every_preset_enables_pre_vote).")
//! @yah:verify("cargo test -p yubaba --test raft_pre_vote = 3 passed / 0 failed. NEW SUITE. a_pre_vote_probes_without_persisting_while_a_real_vote_commits sends the SAME VoteRequest to both routes on one uninitialised node and reads current_term back after each: pre-vote grants and leaves term 0, vote grants and moves term to 5. That is the assertion that rules out the likeliest bug here - wiring /raft/pre-vote straight to Raft::vote, which grants identically and would pass any grant-only test.")
//! @yah:verify("FALSIFIED, not assumed: forcing YubabaNetwork::pre_vote to return Err(Unreachable) leaves a_dead_leader_is_still_replaced_with_pre_vote_gating_the_election hung on [Some(1), Some(1)] - both survivors still naming the killed node - until its 30s deadline, while the other two tests stay green. That is simultaneously the proof that enable_pre_vote is genuinely live (an election not running a Pre-Vote round could not notice) and that the suite catches a broken Pre-Vote transport. Probe removed; the result is recorded in the test's doc comment.")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift = 8 passed / 0 failed after re-recording.")
//! @yah:verify("No regressions in the neighbouring raft suites, all run with Pre-Vote on: bootstrap_single_node 2/0, raft_add_learner 1/0, raft_promote_voter 2/0, raft_transfer_leader 1/0, rig_singleton_ownership 2/0 (the LAN sub-second failover path), integration_mesh --features containerd-integration 7/0/1. R732 baselines held: turso-backup 94+7+4/0.")
//! @yah:verify("cargo clippy -p yubaba --all-targets: no new warnings on any changed file. The one remaining hit, cluster_policy.rs:267 large-Err-variant on to_openraft_config, is pre-existing - that signature is unchanged.")
//! @yah:cleanup("Pre-Vote's protection is only partial during a mixed roll: an un-rolled peer's 404 is a free grant, so a rolled node can still reach a pre-vote quorum on grants that mean nothing. It degrades toward the pre-R734-T1 behaviour and never below it, so there is no window where the fleet is worse off - but the protection is only fully realised once every voter is rolled. Recorded as residual_risk in cluster-epochs.json; no action needed beyond finishing the roll.")
//! @yah:handoff("REOPENED FROM REVIEW 2026-08-10 BY ITS OWN AUTHOR. My earlier handoff on this ticket claimed Pre-Vote was safely enabled. That claim is WRONG and is now retracted. Enabling enable_pre_vote against the pinned openraft 0.10.0-alpha.30 can leave a node that its peers consider leader and that does not consider itself leader, permanently. The flag is now Some(false). Everything else T1 built stays and is still green: the RaftNetworkV2::pre_vote transport, POST /raft/pre-vote, the 404-counts-as-a-grant rule, and all six tests.")
//! @yah:handoff("HOW IT SURFACED: while building R734-T3's grow-3-to-5 membership test (five concurrent five-node clusters, enough load for timers to slip), debug runs began panicking inside openraft with `elect() requires leadership to be relinquished: leader.vote(<T1-N1:Q>)`. That is openraft's own debug_assert in do_elect, not a yubaba assertion.")
//! @yah:handoff("MEASURED, NOT INFERRED. tests/raft_membership_loop.rs, repeated runs: DEBUG with pre-vote on = 5 of 8 runs hit the assert; DEBUG with it off = 0 of 8. RELEASE with it on (where debug_assert compiles out) = roughly 40% of runs strand current_leader on [None, Some(1), Some(1)] and it is STILL stuck after 75s, so it is not a transient; RELEASE with it off = 0 of 8. One further release run failed 0/5 with the flag off, a whole-suite wipeout I could not reproduce in 14 subsequent runs and could not capture; recorded here because it is unexplained, not because it looks related.")
//! @yah:handoff("THE RELEASE BEHAVIOUR IS THE SAME BUG WITH THE ALARM REMOVED, not a milder one. openraft's own assert message says why: a leader that campaigns keeps leader.committed_vote at the old term while state.vote moves to the new one, breaking the invariant LeaderHandler relies on. The split view is that inconsistency observed from outside. A cluster in it cannot accept writes, because peers forward clients to a node that refuses to act as leader. That makes this outage-class rather than cosmetic.")
//! @yah:handoff("UPSTREAM CAUSE, located: openraft's handle_pre_vote_resp (engine_impl.rs:543) calls self.elect() when a pre-vote quorum lands, guarded ONLY on pre_candidate.is_none(). It never checks leader.is_none(). The real-vote path, handle_vote_resp, DOES guard, via candidate_mut(). That asymmetry is the whole bug, and it is why the failure needs pre-vote to reproduce.")
//! @yah:handoff("WHY SWITCHING IT OFF IS THE CHEAP SIDE: openraft's own docs call Pre-Vote 'an optional refinement rather than a correctness requirement' — the leader lease already rejects a disruptive candidate's vote requests. So running without it costs the term inflation the feature removes, not a safety property. Keeping it on costs write availability.")
//! @yah:handoff("GUARDED AGAINST SILENT RE-ENABLEMENT. The flag is Some(false) explicitly, never None, because openraft reads both as disabled and only one of them says a human decided. cluster_policy::tests::every_preset_leaves_pre_vote_off_until_openraft_is_fixed fails the moment anyone flips it, which is deliberate: it makes the flip read the note in RaftTiming::to_openraft_config, where the measurement table lives.")
//! @yah:handoff("DOCS CORRECTED IN THE SAME PASS rather than left to drift: W247 gained a 'The pre-vote result: built, measured, switched off' section with the table and the upstream diagnosis, and its OVH checklist step 2 now says pre-vote stays off and names the expected consequence. W253's openraft note and its §10 checklist box were rewritten. cluster-epochs.json's R734-T3 entry carries a 'correction' field pointing at the T1 entry below it. tests/raft_pre_vote.rs's module doc and its falsification note now say plainly that the falsification NO LONGER APPLIES — with the flag off, that probe would pass, so the test now proves only that ordinary elections work.")
//! @yah:handoff("Tree anchor at handoff: 6b07ab6774e014deb7ab8bf2d2220a29ecd781af — the shared tree as I left it. Diff against it (`git diff 6b07ab6774e014deb7ab8bf2d2220a29ecd781af..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("THE DECISION IS THE OPERATOR'S, and it is a real fork. Option A: bump openraft (alpha.33 exists locally as a transitive dep of openraft-macros/rt, so the release line has moved past alpha.30) and re-run the measurement table in BOTH profiles under load; if clean, flip enable_pre_vote and the tripwire test together. That bump is cluster_protocol-bumping in its own right — 0.9 -> 0.10 was history entry 2 — so it wants its own ticket rather than being folded in here. Option B: leave pre-vote off indefinitely and accept term inflation from reconnecting voters, which is the pre-R734 status quo and costs nothing new.")
//! @yah:next("IF SOMEONE TAKES OPTION A: the reproduction is cheap and already written. Set enable_pre_vote back to Some(true) in RaftTiming::to_openraft_config, then run `cargo test -p yubaba --test raft_membership_loop` about eight times in debug and eight in release. Debug shows the openraft assert; release shows the stuck [None, Some(1), Some(1)]. Do NOT judge it from a single run or from a serial run — `--test-threads=1` passes 5/5 with the flag on, because the bug needs the timer slippage that concurrency produces.")
//! @yah:next("WORTH REPORTING UPSTREAM: the guard asymmetry in handle_pre_vote_resp is a small, specific, and independently checkable claim, and openraft 0.10 is still in alpha. Not done here — filing an issue against a third-party repo is outward-facing and the operator's call.")
//! @yah:verify("cargo test -p yubaba --lib = 384 passed / 0 failed with the flag off.")
//! @yah:verify("cargo test -p yubaba --test raft_pre_vote = 3 passed / 0 failed. All three still hold with the flag off, because they exercise the server and transport halves that the flag does not touch.")
//! @yah:verify("cargo test -p yubaba --test raft_membership_loop = 5 passed / 0 failed, 6 consecutive debug runs and 12 of 13 release runs, against 5-of-8 and ~40% failure rates with the flag on.")
//! @yah:gotcha("RETRACTED CLAIM: the @yah:handoff entries beginning 'LANDED. Pre-Vote is on for every yubaba cluster' and 'DECISION 1' are from this ticket's first pass and are NO LONGER TRUE. Pre-Vote is built but SWITCHED OFF (enable_pre_vote: Some(false)) — enabling it against openraft 0.10.0-alpha.30 strands a node as leader-per-peers and not-leader-per-itself, permanently. Read the 'REOPENED FROM REVIEW' handoff entries, which supersede them, before acting on anything above.")
//! @yah:gotcha("MEASURED 2026-08-28 (incidental, from R746-B11): with enable_pre_vote already OFF, `cd oss/yubaba && cargo test -p yubaba --test main` is RED. Two consecutive runs failed 10 then 8 tests across raft_member_registration / raft_membership_loop / raft_quorum_geography on 'nodes never agreed on a leader', with a DIFFERENT failing set each run. The same filter run serially -- `cargo test -p yubaba --test main raft_ -- --test-threads=1` -- passes 41/41 in 128s. That is this ticket's own timer-slippage signature, but under a condition its measurement table never covered: all ten raft suites are now mods of ONE test binary (oss/yubaba/crates/yubaba/tests/main.rs:32-41), so they spin their five-node clusters concurrently WITH EACH OTHER, not just within one suite. The machine was under heavy camp build load, so load-vs-structure is not separated by this measurement.")
//! @yah:gotcha("STALE REPRO COMMAND in this ticket's @yah:next: `cargo test -p yubaba --test raft_membership_loop` no longer resolves -- there is no such [[test]] target in crates/yubaba/Cargo.toml (only main / testing / containerd / integration_smoke_filter). The suite is `mod raft_membership_loop` inside tests/main.rs, so the repro is now `cargo test -p yubaba --test main raft_membership_loop`.")
//!
//! @yah:ticket(R736-T3, "Cell tagging: a yubaba raft group carries region + jurisdiction, and a second cell is stood up")
//! @yah:status(review)
//! @yah:at(2026-09-02T04:49:52Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P2)
//! @yah:parent(R736)
//! @yah:next("Tier: Cleric — a tag plus a second deployment; the invariants it must satisfy are R734-F2's.")
//! @yah:next("VERIFIED ABSENT 2026-08-09: yubaba runs a single openraft cluster with no cell concept — grep for cell in oss/yubaba hits only generic pond usage.")
//! @yah:next("A cell is one yubaba raft group tagged with region + jurisdiction. Stand up the residency-bound cells first: a US cell and an EU cell, each with its own quorum and its own R2 jurisdiction bucket (R733-T3).")
//! @yah:next("Reuses R734-F2's region tag rather than adding a parallel one.")
//! @yah:depends_on(R734-F2)
//! @yah:handoff("LANDED. A yubaba raft group can now say which CELL it is. New oss/yubaba/crates/yubaba/src/cell.rs (CellIdentity, identify, check_label, PeerJurisdiction, Gate, judge, describe) + `yubaba serve --jurisdiction <label>`; ServerState.jurisdiction + with_jurisdiction + the derived ServerState::cell(); GET /raft/status gains `jurisdiction` (always emitted, null when undeclared) and an optional `cell` {id, jurisdiction, regions}; POST /raft/add-learner runs cell::judge after the sovereign gate and reports cell_judged / jurisdiction in its 200 body.")
//! @yah:verify("RUSTC_WRAPPER='' cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib  # 573 passed / 0 failed (562 baseline + 11 cell::tests)")
//! @yah:verify("RUSTC_WRAPPER='' cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --test main -- raft_cell_tagging::  # 6 passed / 0 failed")
//! @yah:verify("RUSTC_WRAPPER='' cargo check --manifest-path oss/yubaba/Cargo.toml --workspace --tests  # exit 0")
//! @yah:verify("RUSTC_WRAPPER='' cargo run -p xtask -- cluster-epochs  # cluster_protocol GREEN after re-record; state_epoch still RED on raft/store.rs, which is R836-B2's and was deliberately left")
//! @yah:handoff("THE DESIGN CALL TO REVIEW: there is NO --cell flag. The cell id IS the sovereign-group label (R742-F1). A sovereign group already means one yubaba raft group with its own quorum, own upgrade cadence, separately destroyable, and its add-learner gate already refuses cross-group joins — the same object W250 describes from the residency side. A second id would be two names for one thing with nothing making them agree, and the first disagreement is a tenant pointer naming a cell no cluster answers to. Consequence: W250's 'never merge the cells' rule needed no new code, it is R742-F1's shipped gate, asserted in one_cell_cannot_absorb_another_cells_node.")
//! @yah:handoff("SECOND CALL: a group becomes a cell by declaring a jurisdiction, and jurisdiction is declared PER NODE like --region (R734-F5), never per cluster — a box knows where it is and nothing about anyone else. So not every group is a cell (dev = three Pis, a blast radius with no residency meaning; calling it a cell would let a Locked tenant be placed on it), and the whole change ships INERT: no fleet cluster declares a jurisdiction, so the gate is NotInForce and add-learner behaves exactly as before. Pinned by a_group_that_is_not_a_cell_judges_no_jurisdiction_at_all.")
//! @yah:handoff("THIRD CALL: the cell's regions are DERIVED from the member rows R734-F5 already publishes, not declared a second time. A cell spans regions on purpose (a US cell as us-west/us-east/us-south 1-1-1, so losing one does not stop writes), so a single cell-level region label could not have been correct — the ticket's 'reuse R734-F2's region tag' is satisfied by reading it, not by copying it.")
//! @yah:handoff("EPOCH VERDICT: cluster_protocol stays 5, surface re-recorded (584af848...). One input moved and only one — `rust-items lib.rs fn raft_*`, because raft_status and raft_add_learner grew JSON keys; the `/raft/` route-table slice is byte-identical (no new route) and raft/mod.rs, raft/network.rs and the openraft pin are untouched. Full argument in oss/yubaba/crates/yubaba/cluster-epochs.json surface_rerecords[2026-09-01]: new-dials-old refuses only when the TARGET declares a jurisdiction, which needs a flag no deployed build has; old-dials-new drops the unknown keys (PeerStatus has no deny_unknown_fields); nothing is replicated or persisted, which is why state_epoch did not move by this change and rollback is free.")
//! @yah:handoff("state_epoch WAS LEFT RED ON PURPOSE, and this is the thing to know before running the guard. `cargo run -p xtask -- cluster-epochs --write` re-records EVERY drifted axis, so it also wrote state_epoch; I restored state_epoch_surface and its raft/store.rs input digest by hand to 7811ac8f... / 35915ec3.... That drift is a committed peer change (raft/store.rs) whose verdict has never been made and which R836-B2 is open for. Writing the hash IS the verdict, and asserting NOT BREAKING about an unanalysed on-disk change on the axis where being wrong means a fleet that does not start is not mine to do. Recorded in the same rerecord entry's residual_risk.")
//! @yah:handoff("DISCOVERED WORK, done in this pass: sovereign_group::ask_peer now returns a PeerDeclaration {group, jurisdiction} instead of a bare PeerGroup, so both gates are answered from ONE /raft/status read of the joiner — asking twice would let a node answer differently to the two questions in the window between them, and would double the operator-path round trips the 3s ASK_TIMEOUT is sized for. PeerStatus gained the jurisdiction field on the same present_but_maybe_null idiom, and its existing tests were repointed through a group_of() helper.")
//! @yah:next("FOR R736-F4 (move protocol): a node can now answer which cell it is in — ServerState::cell() in-process, or GET /raft/status .cell.id over HTTP — and that id is exactly what yah_tenant_pointer::PointerRecord::cell holds, by construction rather than by convention. So step 5's commit_cell(store, tenant, target_cell) has a real target_cell to pass, and step 7's fence has a real cell to compare against. NOT done here, correctly out of scope: nothing resolves a PointerRecord yet and yubaba-tenant-streamer still passes pointer_generation: 0 (R736-T2's own next says the same). Wiring that read is F4's, and it needs an ObjectStore handle in the streamer, which cell tagging does not provide.")
//! @yah:handoff("DOCS CORRECTED, since this work disproved them: W250's 'Where we are today' bullet 'One raft group, no cell concept' is now false and is struck with the shipped shape; the Cells design section carries the three calls above; implementation-order item 4 is DONE. Item 3 (two-level fence) was also still unstruck though R736-T2 landed it — struck, with the verification that its code survived the 2026-08-28 working-tree incident (52 pointer_generation references live in oss/turso-backup/src/stream.rs on 2026-09-01).")
//! @yah:gotcha("THE SECOND CELL STANDS UP IN THE TEST HARNESS, NOT ON HARDWARE, and that is a hardware fact rather than a code one. tests/raft_cell_tagging.rs founds a prod-us and a prod-eu cell side by side and asserts separate quorums, disjoint membership and mutual non-absorption. A real EU cell needs EU machines: every box in .yah/infra/machines/ is us-west / us-east / us-south as of 2026-09-01 (9 files, checked). Provisioning one is an operator call; nothing in the code blocks it now.")
//! @yah:gotcha("PRE-EXISTING, NOT MINE: `cargo test -p yubaba --test main` fails 11 tests on a loaded machine (raft_member_registration, raft_membership_loop, raft_leader_pin, raft_tenant_placement, rig_singleton_ownership, raft_pre_vote, raft_quorum_geography, raft_transfer_leader, raft_promote_voter). Established by running the same target with `-- --skip raft_cell_tagging`: 11 failures with my tests excluded, the same 11. They are timeouts in multi-node cluster fixtures (`becomes_initialized` at 10s, leader-election polls) under five concurrent camp builds queued on the cargo lock, and every one of them passes when its own module is run alone.")
//! @yah:assumes("yubaba is NOT clippy-clean at baseline, so the clippy gate was not run as a pass/fail here. `cargo clippy -p yubaba -p yubaba-test-harness --all-targets --no-deps -- -D warnings` reports 9 errors, all in files this ticket never touched (rollout/mod.rs, rollout/engine.rs, pond/minio.rs, cluster_epoch.rs, raft/store.rs, cluster_policy.rs:495). Zero diagnostics land in cell.rs, sovereign_group.rs, lib.rs, main.rs, solo_node.rs or raft_cell_tagging.rs — established from the diagnostic location list, not assumed.")

use std::collections::BTreeMap;
use std::time::Duration;

use crate::raft::YubabaNodeId;

/// Whether the voter set must be spread across failure domains, and therefore
/// which founding configurations this cluster will refuse — R734-F2, W247 §2.
///
/// The rule being encoded is that quorum survives losing a whole region only if
/// no region *holds* a quorum. Three voters as 1-1-1 keep writing when any one
/// region goes dark; the same three voters as 2-1 do not, and nothing about the
/// running cluster looks different until the day the two-voter region is the one
/// that fails. That is why this is a bootstrap refusal and not a warning: the
/// window between the mistake and the consequence is measured in months.
///
/// This one *is* a policy field, unlike Pre-Vote (see
/// [`RaftTiming::to_openraft_config`]) — the two presets genuinely differ, and
/// the difference is a fact about the deployment rather than a preference. A
/// single-LAN rig has exactly one failure domain no matter how its voters are
/// labelled, so demanding they span regions would be demanding the impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumGeography {
    /// Voters must span regions: every voter carries a region tag, and no single
    /// region holds a majority (1-1-1 for three, 2-2-1 for five).
    ///
    /// The cloud fleet's rule. Losing any one region leaves a quorum of the
    /// survivors, which is the entire reason the voters are in different
    /// datacenters.
    MustSpanRegions,

    /// Every voter shares one failure domain by construction, so there is no
    /// geography to spread and region tags are not required.
    ///
    /// A self-contained installation on one LAN: the switch, the room, and the
    /// power feed are common-mode for all of it. Recording that as a named
    /// value rather than as "the fleet rule, skipped" keeps the refusal
    /// messages honest — a rig is not a misconfigured fleet.
    SingleFailureDomain,
}

/// What [`QuorumGeography`] decided about one proposed voter set.
///
/// Shaped like [`PromotionVerdict`] and for the same reason: the rule stays
/// unit-testable without a live cluster, and a refusal carries its reason from
/// the place that knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeographyVerdict {
    /// The voter set satisfies this cluster's quorum-geography rule.
    Sound,
    /// The voter set is refused. Carries an operator-readable reason that names
    /// the concrete layout to use instead — a refusal that only says "invalid"
    /// gets worked around rather than fixed.
    Refuse(String),
}

impl QuorumGeography {
    /// The clauses that hold under **every** policy, judged on the voter count
    /// alone — R734-T3 calls this directly when judging the survivors of a
    /// membership change.
    ///
    /// - A cluster needs at least one voter.
    /// - The count must be odd. An even voter set survives exactly the failures
    ///   the odd set below it does while requiring one more acknowledgement per
    ///   write, so it is never the right answer. This is W247's named footgun,
    ///   "maybe two in each of three regions" — six voters, strictly worse than
    ///   five.
    ///
    /// Separated from [`Self::judge`] rather than inlined because removal and
    /// founding can answer different amounts of this question. At founding the
    /// operator supplies the region tags in the same call, so the spread clause
    /// is always answerable; when *removing* a member the regions live in
    /// replicated state that the operator did not write, so the count is the
    /// part that can always be judged. Splitting it keeps the removal path from
    /// having to either fabricate region data or skip the check it can do.
    ///
    /// A **single** voter passes. A cluster-of-one is an explicit operator
    /// choice (`--bootstrap-single-node`, the BYO-VPS path) with no failure
    /// tolerance to protect; refusing it would break a documented bootstrap for
    /// no gain.
    pub fn judge_voter_count(count: usize) -> GeographyVerdict {
        if count == 0 {
            return GeographyVerdict::Refuse(
                "a voter set cannot be empty: a cluster with no voters can never elect a \
                 leader or accept another write, and no membership change can rescue it"
                    .to_string(),
            );
        }
        if count.is_multiple_of(2) {
            return GeographyVerdict::Refuse(format!(
                "voter count must be odd; got {count}. An even voter set survives exactly the \
                 failures a {}-voter set does while making every write wait on one more node, \
                 so it is strictly worse. Use {} voters, or {count_plus} if you want the extra \
                 fault tolerance.",
                count - 1,
                count - 1,
                count_plus = count + 1,
            ));
        }
        GeographyVerdict::Sound
    }

    /// Judge a proposed **founding** voter set: `voters` maps each founding
    /// voter's node id to its region label (`None` = untagged).
    ///
    /// [`Self::judge_voter_count`] first, then — under
    /// [`Self::MustSpanRegions`] and for more than one voter — the spread
    /// clause: every voter carries a region, and no region holds more than
    /// half.
    pub fn judge(&self, voters: &BTreeMap<YubabaNodeId, Option<String>>) -> GeographyVerdict {
        let count = voters.len();
        if let verdict @ GeographyVerdict::Refuse(_) = Self::judge_voter_count(count) {
            return verdict;
        }
        if matches!(self, Self::SingleFailureDomain) || count == 1 {
            return GeographyVerdict::Sound;
        }

        let untagged: Vec<YubabaNodeId> = voters
            .iter()
            .filter(|(_, region)| region.is_none())
            .map(|(id, _)| *id)
            .collect();
        if !untagged.is_empty() {
            return GeographyVerdict::Refuse(format!(
                "this cluster's voters must span regions, but {} carr{} no region tag. Tag \
                 every founding voter with the `region` its machine declares in \
                 .yah/infra/machines/<name>.toml (e.g. \"us-west\"). Without the tags the \
                 no-single-region-majority rule cannot be checked, and an untagged bootstrap \
                 is exactly how a cluster ends up with a quorum that dies with one datacenter.",
                untagged
                    .iter()
                    .map(|id| format!("node {id}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                if untagged.len() == 1 { "ies" } else { "y" },
            ));
        }

        // No region may hold a majority. For an odd count `n` a majority is
        // `n / 2 + 1`, so the bound is `n / 2`: at most 1 of 3, at most 2 of 5.
        let mut per_region: BTreeMap<&str, Vec<YubabaNodeId>> = BTreeMap::new();
        for (id, region) in voters {
            if let Some(region) = region {
                per_region.entry(region.as_str()).or_default().push(*id);
            }
        }
        let allowed = count / 2;
        let biggest = per_region.iter().max_by_key(|(_, ids)| ids.len());
        if let Some((region, holders)) = biggest.filter(|(_, ids)| ids.len() > allowed) {
            return GeographyVerdict::Refuse(format!(
                "region {region:?} holds {} of {count} voters, which is a majority — losing \
                 that one region would leave the cluster unable to accept writes, which is \
                 the failure spanning regions exists to prevent. No region may hold more than \
                 {allowed}. Use {}.",
                holders.len(),
                match count {
                    3 => "1-1-1 across three regions".to_string(),
                    5 => "2-2-1 across three regions".to_string(),
                    n => format!("a spread where no region exceeds {} of the {n}", n / 2),
                }
            ));
        }

        GeographyVerdict::Sound
    }
}

/// Whether a learner in this cluster may ever be promoted to a voter.
///
/// Promotion is a quorum-safety decision, which is why it is policy rather than
/// an operator whim: every added voter raises the number of nodes that must
/// stay reachable for the cluster to accept writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoterAdmission {
    /// Nodes that join a running cluster stay learners for good. They receive
    /// full log/snapshot replication (so they hold complete cluster state and
    /// serve local reads) but never vote and never count toward quorum.
    ///
    /// This is the cloud fleet's rule. Voters are the founding set written by
    /// `raft init`; a macOS home-lab box or a residential-network node joins as
    /// a learner so a flaky link can never endanger the datacenter voters'
    /// quorum.
    LearnerOnly,

    /// A caught-up learner may be promoted to voter, as long as doing so keeps
    /// the voter count at or below `max_voters`.
    ///
    /// This is the rule for a self-contained installation whose nodes are all
    /// peers on one LAN: there is no separate "cloud tier" to be the permanent
    /// voter set, so the cluster grows its own. The cap exists because quorum
    /// cost grows with the voter set — past a handful of voters every write
    /// waits on more machines for no additional fault tolerance.
    PromotableUpTo {
        /// Maximum number of voters this cluster will hold. Prefer an odd
        /// number: an even voter set tolerates the same number of failures as
        /// the odd one below it while needing one more ack per write.
        max_voters: usize,
    },
}

/// What [`VoterAdmission`] decided about one promotion request.
///
/// Separating the verdict from the HTTP handler keeps the rule unit-testable
/// without a live cluster, and keeps the *reason* for a refusal in the same
/// place as the rule that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionVerdict {
    /// The node is already a voter — nothing to do (idempotent success).
    AlreadyVoter,
    /// Promotion is permitted; the caller should perform the membership change.
    Promote,
    /// Promotion is forbidden by policy. Carries an operator-readable reason —
    /// this is a permanent "no" under the current policy, not a retryable error.
    Refuse(String),
}

impl VoterAdmission {
    /// Judge a request to promote `node` to voter.
    ///
    /// `current_voters` is the size of the voter set *before* the promotion, and
    /// `is_already_voter` says whether `node` is in it.
    pub fn judge(
        &self,
        node: YubabaNodeId,
        current_voters: usize,
        is_already_voter: bool,
    ) -> PromotionVerdict {
        if is_already_voter {
            return PromotionVerdict::AlreadyVoter;
        }
        match self {
            Self::LearnerOnly => PromotionVerdict::Refuse(format!(
                "cluster policy is learner-only: node {node} cannot be promoted to voter. \
                 The voter set is fixed at cluster founding so that a node on an \
                 unreliable link can never endanger quorum."
            )),
            Self::PromotableUpTo { max_voters } => {
                if current_voters >= *max_voters {
                    PromotionVerdict::Refuse(format!(
                        "cluster policy caps the voter set at {max_voters}; it already holds \
                         {current_voters}. Remove a voter before promoting node {node}, or \
                         leave it a learner — learners hold full replicated state either way."
                    ))
                } else {
                    PromotionVerdict::Promote
                }
            }
        }
    }
}

/// Who owns the cluster's **external** identity — the address clients outside
/// the mesh reach it at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressOwnership {
    /// The raft leader is also the external-ingress owner: on winning
    /// leadership a node restores and starts the ingress services and claims
    /// `SetIngressOwner` in replicated state; on losing it, it stops them.
    ///
    /// The cloud fleet's rule — its Headscale coordinator's clients live
    /// outside the mesh, so exactly one node must hold that external identity
    /// and it must move when leadership moves.
    FollowsRaftLeader,

    /// The appliance owner is **its own elected fact**, chosen from an
    /// eligibility set — and a raft leadership change is not an input to it
    /// (R858-T3).
    ///
    /// [`FollowsRaftLeader`](Self::FollowsRaftLeader) reads "exactly one node
    /// holds the external identity" as "the leader holds it", which is a
    /// non-sequitur that cost the fleet 37 hours of mesh downtime on
    /// 2026-09-03: a routine `POST /raft/transfer-leader` tore the coordinator
    /// off a healthy node and handed it to one that could not run it. Consensus
    /// leadership answers "who may write"; nothing about it answers "which box
    /// can serve tailnet clients".
    ///
    /// Under this variant ownership moves on owner **failure** only, the
    /// candidate set is judged by
    /// [`judge_appliance_candidate`](crate::appliance_ownership::judge_appliance_candidate),
    /// a failed deploy backs that node off rather than being retried instantly,
    /// and a node that cannot stand the appliance up claims nothing and reports
    /// [`ApplianceHealth::Unhealthy`](crate::appliance_ownership::ApplianceHealth::Unhealthy).
    /// See [`crate::appliance_ownership`] for the bounds that keep re-election
    /// from flapping.
    ElectedFromEligible,

    /// No node claims external ingress from the raft-leader path.
    ///
    /// For a cluster with no outside-the-mesh clients to serve — every peer is
    /// on the local link and reaches the others directly. Leadership still
    /// elects and still decides who *writes*; it simply carries no external
    /// identity with it.
    ///
    /// Note this is not merely "the fleet behaviour minus the systemd calls":
    /// coupling gateway election to raft leadership is itself a choice, and one
    /// that lets a flaky uplink cause leadership churn. Decoupling the two is
    /// the reason this is a named field rather than an `if` around the
    /// `systemctl` calls.
    Unmanaged,
}

impl IngressOwnership {
    /// Whether a leadership transition should drive the external-ingress
    /// services and the `SetIngressOwner` claim.
    ///
    /// False under [`ElectedFromEligible`](Self::ElectedFromEligible) — that is
    /// the entire difference between the two managed variants, and reading it
    /// through this predicate is what keeps the R858 coupling from creeping
    /// back in at a new call site.
    pub fn follows_raft_leader(&self) -> bool {
        matches!(self, Self::FollowsRaftLeader)
    }

    /// Whether the appliance owner is elected from an eligibility set
    /// (R858-T3), independently of raft leadership.
    pub fn elects_from_eligibility_set(&self) -> bool {
        matches!(self, Self::ElectedFromEligible)
    }

    /// Whether this cluster has an external identity for *some* node to hold at
    /// all — true for both managed variants, false only for
    /// [`Unmanaged`](Self::Unmanaged).
    ///
    /// The question every ingress call site actually asks, so that adding a
    /// third managed variant is one arm here rather than an audit of every
    /// `follows_raft_leader()` in the crate.
    pub fn manages_ingress(&self) -> bool {
        !matches!(self, Self::Unmanaged)
    }
}

/// Raft election and heartbeat timings, in milliseconds.
///
/// These are the knobs that decide how fast a cluster notices a dead leader,
/// traded against how often a healthy-but-slow link triggers a spurious
/// election. The right values are a property of the *network the cluster sits
/// on*, which is why they belong to the policy and not to a constant in the
/// node factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaftTiming {
    /// Leader → follower heartbeat period.
    pub heartbeat_interval_ms: u64,
    /// Lower bound of the randomised election timeout.
    pub election_timeout_min_ms: u64,
    /// Upper bound of the randomised election timeout. Also openraft's leader
    /// lease: a follower will not grant a vote within this long of hearing from
    /// a leader it believes in.
    pub election_timeout_max_ms: u64,
}

impl RaftTiming {
    /// Cross-region WAN timings: heartbeat 500 ms, election 1.5–3 s.
    ///
    /// Sized for voters in different datacenters, where a 200 ms round trip and
    /// an occasional multi-second stall are normal. An election timeout tight
    /// enough for a LAN would make transatlantic voters campaign against each
    /// other on ordinary jitter.
    pub const fn wan() -> Self {
        Self {
            heartbeat_interval_ms: 500,
            election_timeout_min_ms: 1500,
            election_timeout_max_ms: 3000,
        }
    }

    /// Single-LAN timings: heartbeat 150 ms, election 450–900 ms.
    ///
    /// Every node is a switch hop away, so sub-millisecond round trips are the
    /// norm and there is no reason to leave a dead leader in place for three
    /// seconds. Failover lands inside a second.
    pub const fn lan() -> Self {
        Self {
            heartbeat_interval_ms: 150,
            election_timeout_min_ms: 450,
            election_timeout_max_ms: 900,
        }
    }

    /// Build the openraft [`Config`](openraft::Config) this timing describes.
    ///
    /// Fails if the timings are inconsistent (openraft requires
    /// `heartbeat_interval < election_timeout_min <= election_timeout_max`),
    /// so an invalid policy is rejected at node open rather than producing a
    /// cluster that campaigns continuously.
    ///
    /// # Pre-Vote is OFF, deliberately and against our own preference (R734-T1/T3)
    ///
    /// `Some(false)` is written explicitly rather than left as openraft's
    /// `None` — which it also reads as disabled — because the difference
    /// between "nobody considered this" and "this was measured and turned off"
    /// is the whole content of the next few paragraphs.
    ///
    /// Pre-Vote is the right feature. A follower whose election timer fires
    /// asks peers whether they *would* grant it a vote at `term + 1` before it
    /// increments the cluster's term and campaigns for real, so a node that
    /// cannot currently win — partitioned, freshly restarted, log-behind —
    /// stops disrupting a healthy leader every time it reconnects. R734-T1
    /// built the whole thing: the flag, the [`RaftNetworkV2::pre_vote`
    /// transport](crate::raft::YubabaNetwork), `POST /raft/pre-vote`, and the
    /// tests. All of that stays, and all of it is green.
    ///
    /// What it cannot stay is **on**, against the pinned
    /// `openraft = 0.10.0-alpha.30`. Enabling it makes a node reachable that
    /// is leader according to its peers and *not* leader according to itself
    /// — `current_leader: [None, Some(1), Some(1)]` — and that state does not
    /// heal. It was measured, not inferred, by running
    /// `tests/raft_membership_loop.rs` (five concurrent five-node clusters, so
    /// the machine is loaded enough for timers to slip):
    ///
    /// | build | Pre-Vote on | Pre-Vote off |
    /// |---|---|---|
    /// | debug | 5 of 8 runs hit openraft's own `debug_assert!` — `elect() requires leadership to be relinquished` | 0 of 8 |
    /// | release | ~40% of runs strand a node in the split view above, still stuck after 75 s | 0 of 8 |
    ///
    /// The assert names the corruption: openraft's `handle_pre_vote_resp`
    /// calls `elect()` when a Pre-Vote quorum lands, guarded only on
    /// `pre_candidate.is_none()` and **not** on `leader.is_none()` — where the
    /// real-vote path (`handle_vote_resp`) does guard, via `candidate_mut()`.
    /// A leader that campaigns keeps `leader.committed_vote` at the old term
    /// while `state.vote` moves to the new one, which is exactly the
    /// inconsistency the release-mode split view shows once the assert is
    /// compiled out. So the release behaviour is not a milder version of the
    /// debug failure; it is the same failure with the alarm removed.
    ///
    /// A cluster in that state cannot accept writes — peers forward clients to
    /// a node that will not act as leader — so this is outage-class, not
    /// cosmetic. openraft's own docs call Pre-Vote "an optional refinement
    /// rather than a correctness requirement" (the leader lease already
    /// rejects a disruptive candidate's vote requests), which is what makes
    /// switching it off the cheap side of this trade.
    ///
    /// **To turn it back on**, bump openraft first and re-run the table above;
    /// alpha.33 exists. `every_preset_leaves_pre_vote_off_until_openraft_is_fixed`
    /// fails the moment this flips, which is intentional — it is the tripwire
    /// that makes a future flip read this note.
    ///
    /// Deliberately **not** a [`ClusterPolicy`] field. Per [the module
    /// docs](self) a field earns its place by answering a question some
    /// decision point asks, and no decision point asks this one: both networks
    /// want Pre-Vote for the same reason (the WAN because transatlantic jitter
    /// produces doomed candidates, the LAN because a rebooting peer is the same
    /// shape at a shorter timescale), and neither wants the bug. A knob here
    /// would let one deployment run the broken configuration.
    pub fn to_openraft_config(self) -> Result<openraft::Config, openraft::ConfigError> {
        openraft::Config {
            heartbeat_interval: self.heartbeat_interval_ms,
            election_timeout_min: self.election_timeout_min_ms,
            election_timeout_max: self.election_timeout_max_ms,
            enable_pre_vote: Some(false),
            ..Default::default()
        }
        .validate()
    }
}

/// A node is judged `Suspect` once it has been silent for this many heartbeat
/// periods, and `Down` after [`DOWN_AFTER_HEARTBEATS`].
///
/// Three periods is the usual "one lost packet is not a failure, three in a row
/// is a pattern" threshold, and it lands just below the election timeout — so a
/// node reads as suspect at about the point raft itself starts to doubt it.
pub const SUSPECT_AFTER_HEARTBEATS: u32 = 3;

/// A node silent for this many heartbeat periods is judged `Down`.
///
/// Deliberately several times the election timeout: by the time a detector says
/// "down" the cluster has already had the chance to elect around the node, so
/// this threshold is about *reporting* a failure, not reacting to one.
pub const DOWN_AFTER_HEARTBEATS: u32 = 10;

/// How long a peer may be silent before a failure detector downgrades its
/// liveness. Derived from [`RaftTiming`] so the thresholds scale with the
/// network the cluster was configured for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessThresholds {
    /// Silence beyond this is `Suspect`.
    pub suspect_after: Duration,
    /// Silence beyond this is `Down`.
    pub down_after: Duration,
}

impl LivenessThresholds {
    /// Scale the thresholds off `timing`'s heartbeat period.
    pub const fn from_timing(timing: RaftTiming) -> Self {
        Self {
            suspect_after: Duration::from_millis(
                timing.heartbeat_interval_ms * SUSPECT_AFTER_HEARTBEATS as u64,
            ),
            down_after: Duration::from_millis(
                timing.heartbeat_interval_ms * DOWN_AFTER_HEARTBEATS as u64,
            ),
        }
    }
}

/// The rules a yubaba cluster runs under, fixed for the life of the process.
///
/// Read [the module docs](self) before adding a field: the constraint that
/// makes this shape work is that every field answers a *question a decision
/// point asks*, and no field records which preset produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterPolicy {
    /// Whether learners can become voters — read by `POST /raft/promote-voter`.
    pub voter_admission: VoterAdmission,
    /// Whether the voter set must span failure domains — read by
    /// `POST /raft/initialize` when judging a founding membership.
    pub quorum_geography: QuorumGeography,
    /// Whether the raft leader carries the cluster's external identity — read
    /// by the [`leader`](crate::leader) watcher on every leadership transition.
    pub ingress_ownership: IngressOwnership,
    /// Raft election/heartbeat timings — read by
    /// [`raft::open`](crate::raft::open) when constructing the node, and by
    /// failure detectors deriving their thresholds.
    pub timing: RaftTiming,
}

impl ClusterPolicy {
    /// The cloud fleet: geographically distributed voters, a fixed voter set,
    /// and an external Headscale/ingress identity **elected from the eligible
    /// nodes**, not carried by whoever holds raft leadership.
    ///
    /// This was [`IngressOwnership::FollowsRaftLeader`] until R858-T3. The fleet
    /// is the deployment the 2026-09-03 outage happened to, so it is the
    /// deployment the fix has to apply to; `FollowsRaftLeader` remains
    /// constructible for an appliance that genuinely wants the coupling.
    pub const fn fleet() -> Self {
        Self {
            voter_admission: VoterAdmission::LearnerOnly,
            quorum_geography: QuorumGeography::MustSpanRegions,
            ingress_ownership: IngressOwnership::ElectedFromEligible,
            timing: RaftTiming::wan(),
        }
    }

    /// A self-contained installation on one LAN: peers all of a kind, so the
    /// cluster grows its own voter set (capped at five), no external ingress
    /// identity, and sub-second failover.
    pub const fn rig() -> Self {
        Self {
            voter_admission: VoterAdmission::PromotableUpTo { max_voters: 5 },
            quorum_geography: QuorumGeography::SingleFailureDomain,
            ingress_ownership: IngressOwnership::Unmanaged,
            timing: RaftTiming::lan(),
        }
    }

    /// Thresholds a failure detector should use under this policy.
    pub const fn liveness_thresholds(&self) -> LivenessThresholds {
        LivenessThresholds::from_timing(self.timing)
    }
}

impl Default for ClusterPolicy {
    fn default() -> Self {
        Self::fleet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_never_promotes_a_learner() {
        let verdict = ClusterPolicy::fleet().voter_admission.judge(4, 3, false);
        assert!(
            matches!(verdict, PromotionVerdict::Refuse(_)),
            "the fleet's learner-only rule must refuse promotion: {verdict:?}"
        );
    }

    #[test]
    fn promoting_an_existing_voter_is_a_noop_under_every_policy() {
        for policy in [ClusterPolicy::fleet(), ClusterPolicy::rig()] {
            assert_eq!(
                policy.voter_admission.judge(2, 3, true),
                PromotionVerdict::AlreadyVoter,
                "an already-voter request is idempotent, never an error"
            );
        }
    }

    #[test]
    fn rig_promotes_until_the_cap_then_refuses() {
        let admission = ClusterPolicy::rig().voter_admission;
        let VoterAdmission::PromotableUpTo { max_voters } = admission else {
            panic!("the rig preset must allow promotion");
        };
        assert_eq!(
            admission.judge(6, max_voters - 1, false),
            PromotionVerdict::Promote,
            "one below the cap must be promotable"
        );
        let at_cap = admission.judge(6, max_voters, false);
        assert!(
            matches!(at_cap, PromotionVerdict::Refuse(msg) if msg.contains(&max_voters.to_string())),
            "at the cap the refusal must name the cap"
        );
    }

    #[test]
    fn both_presets_produce_a_valid_openraft_config() {
        for (name, policy) in [
            ("fleet", ClusterPolicy::fleet()),
            ("rig", ClusterPolicy::rig()),
        ] {
            let cfg = policy
                .timing
                .to_openraft_config()
                .unwrap_or_else(|e| panic!("{name} timing must validate: {e}"));
            assert_eq!(cfg.heartbeat_interval, policy.timing.heartbeat_interval_ms);
            assert_eq!(
                cfg.election_timeout_max,
                policy.timing.election_timeout_max_ms
            );
        }
    }

    /// Build a voter set from `(node_id, region)` pairs.
    fn voters(pairs: &[(YubabaNodeId, Option<&str>)]) -> BTreeMap<YubabaNodeId, Option<String>> {
        pairs
            .iter()
            .map(|(id, r)| (*id, r.map(str::to_string)))
            .collect()
    }

    /// The layout W247 §2 prescribes, and the two it names as mistakes.
    #[test]
    fn the_fleet_accepts_1_1_1_and_2_2_1_and_nothing_lopsided() {
        let geo = ClusterPolicy::fleet().quorum_geography;

        assert_eq!(
            geo.judge(&voters(&[
                (1, Some("us-west")),
                (2, Some("us-east")),
                (3, Some("us-south")),
            ])),
            GeographyVerdict::Sound,
            "1-1-1 is the canonical three-voter layout"
        );
        assert_eq!(
            geo.judge(&voters(&[
                (1, Some("us-west")),
                (2, Some("us-west")),
                (3, Some("us-east")),
                (4, Some("us-east")),
                (5, Some("us-south")),
            ])),
            GeographyVerdict::Sound,
            "2-2-1 is the canonical five-voter layout"
        );

        // 2-1: one region holds 2 of 3, so losing it stops writes.
        let lopsided = geo.judge(&voters(&[
            (1, Some("us-west")),
            (2, Some("us-west")),
            (3, Some("us-east")),
        ]));
        assert!(
            matches!(&lopsided, GeographyVerdict::Refuse(m)
                if m.contains("us-west") && m.contains("1-1-1")),
            "the refusal must name the offending region AND the layout to use: {lopsided:?}"
        );

        // Three voters, one region — the shape a single-datacenter bring-up
        // drifts into, and the one that looks perfectly healthy until the day
        // that datacenter goes dark.
        assert!(
            matches!(
                geo.judge(&voters(&[
                    (1, Some("us-west")),
                    (2, Some("us-west")),
                    (3, Some("us-west")),
                ])),
                GeographyVerdict::Refuse(_)
            ),
            "three voters in one region must be refused"
        );
    }

    /// W247's named footgun: "maybe 2 in each region" across three regions is
    /// six voters — an even set, which tolerates exactly what five does while
    /// making every write wait on one more node.
    #[test]
    fn six_voters_across_three_regions_is_refused_for_being_even() {
        let six = voters(&[
            (1, Some("us-west")),
            (2, Some("us-west")),
            (3, Some("us-east")),
            (4, Some("us-east")),
            (5, Some("us-south")),
            (6, Some("us-south")),
        ]);
        // Note this set is perfectly spread — 2-2-2, no region holds a
        // majority. It is refused on the count alone, which is why the count
        // rule cannot be folded into the geography rule.
        for (name, policy) in [
            ("fleet", ClusterPolicy::fleet()),
            ("rig", ClusterPolicy::rig()),
        ] {
            let verdict = policy.quorum_geography.judge(&six);
            assert!(
                matches!(&verdict, GeographyVerdict::Refuse(m) if m.contains("odd")),
                "{name} must refuse an even voter set on the count alone: {verdict:?}"
            );
        }
    }

    /// Under the fleet rule an untagged voter is refused rather than waved
    /// through: the check it defeats is silent, so failing open would leave the
    /// operator believing a guarantee that was never evaluated.
    #[test]
    fn the_fleet_refuses_untagged_voters_instead_of_skipping_the_check() {
        let verdict = ClusterPolicy::fleet().quorum_geography.judge(&voters(&[
            (1, Some("us-west")),
            (2, None),
            (3, Some("us-east")),
        ]));
        assert!(
            matches!(&verdict, GeographyVerdict::Refuse(m) if m.contains("node 2")),
            "the refusal must name which voter is untagged: {verdict:?}"
        );
    }

    /// A rig is one failure domain however its voters are labelled, so the
    /// spread rule does not apply — but the odd-count rule still does. Without
    /// this the rig preset could not found a cluster at all.
    #[test]
    fn a_rig_founds_three_untagged_voters_on_one_lan() {
        let geo = ClusterPolicy::rig().quorum_geography;
        assert_eq!(
            geo.judge(&voters(&[(1, None), (2, None), (3, None)])),
            GeographyVerdict::Sound,
            "a rig's voters share a switch; demanding they span regions demands the impossible"
        );
        assert_eq!(
            geo.judge(&voters(&[
                (1, Some("rack-a")),
                (2, Some("rack-a")),
                (3, Some("rack-a"))
            ])),
            GeographyVerdict::Sound,
            "and a rig that does label its nodes is still one failure domain"
        );
    }

    /// A cluster-of-one is sound under both policies. It is an explicit
    /// operator choice (`--bootstrap-single-node`, the BYO-VPS path) with no
    /// failure tolerance to protect, so there is no geography to check —
    /// refusing it would break a documented bootstrap for no gain.
    #[test]
    fn a_cluster_of_one_is_sound_under_every_policy() {
        for (name, policy) in [
            ("fleet", ClusterPolicy::fleet()),
            ("rig", ClusterPolicy::rig()),
        ] {
            assert_eq!(
                policy.quorum_geography.judge(&voters(&[(1, None)])),
                GeographyVerdict::Sound,
                "{name} must allow a single-voter bootstrap"
            );
        }
    }

    #[test]
    fn an_empty_voter_set_is_refused() {
        assert!(matches!(
            ClusterPolicy::fleet().quorum_geography.judge(&voters(&[])),
            GeographyVerdict::Refuse(_)
        ));
    }

    /// The tripwire for the R734-T1/T3 finding.
    ///
    /// This test exists to FAIL when someone re-enables Pre-Vote, so that the
    /// flip is a deliberate act with `to_openraft_config`'s note read first
    /// rather than a one-character change that looks obviously correct. Pre-Vote
    /// against `openraft = 0.10.0-alpha.30` strands a node as leader-per-peers
    /// and not-leader-per-itself, permanently; the measurements are in that
    /// note. Bump openraft, re-run `tests/raft_membership_loop.rs` under load in
    /// both profiles, then change this test and the flag together.
    #[test]
    fn every_preset_leaves_pre_vote_off_until_openraft_is_fixed() {
        for (name, policy) in [
            ("fleet", ClusterPolicy::fleet()),
            ("rig", ClusterPolicy::rig()),
        ] {
            let cfg = policy.timing.to_openraft_config().expect("valid timing");
            assert_eq!(
                cfg.enable_pre_vote,
                Some(false),
                "{name} must keep Pre-Vote OFF: openraft 0.10.0-alpha.30's Pre-Vote path can \
                 call elect() on a node that is still leader, leaving it permanently unable \
                 to act as one. Read RaftTiming::to_openraft_config before changing this."
            );
            // Explicitly Some(false), never None: openraft treats both as
            // disabled, but only one of them says a human decided.
            assert!(
                cfg.enable_pre_vote.is_some(),
                "{name} must state the decision rather than inherit openraft's default"
            );
        }
    }

    #[test]
    fn inconsistent_timing_is_rejected_rather_than_campaigning_forever() {
        // Heartbeat slower than the election timeout: every follower times out
        // before the leader can reach it, so the cluster elects continuously.
        let broken = RaftTiming {
            heartbeat_interval_ms: 5000,
            election_timeout_min_ms: 1500,
            election_timeout_max_ms: 3000,
        };
        assert!(
            broken.to_openraft_config().is_err(),
            "openraft must reject a heartbeat longer than the election timeout"
        );
    }

    #[test]
    fn liveness_thresholds_scale_with_the_networks_heartbeat() {
        let fleet = ClusterPolicy::fleet().liveness_thresholds();
        let rig = ClusterPolicy::rig().liveness_thresholds();
        assert_eq!(fleet.suspect_after, Duration::from_millis(1500));
        assert_eq!(fleet.down_after, Duration::from_secs(5));
        assert_eq!(rig.suspect_after, Duration::from_millis(450));
        assert_eq!(rig.down_after, Duration::from_millis(1500));
        assert!(
            rig.suspect_after < fleet.suspect_after && rig.down_after < fleet.down_after,
            "a LAN cluster must lose patience sooner than a WAN one at both thresholds"
        );
        assert!(
            rig.down_after <= fleet.suspect_after,
            "the LAN cluster should have written a node off entirely by the time the WAN \
             cluster has merely started to wonder"
        );
    }

    /// R858-T3 inverted this assertion, and the inversion is the point: no
    /// preset ties external identity to leadership any more. The fleet still
    /// *manages* an external identity — it simply elects who holds it.
    #[test]
    fn no_preset_ties_external_identity_to_leadership() {
        let fleet = ClusterPolicy::fleet().ingress_ownership;
        assert!(!fleet.follows_raft_leader());
        assert!(fleet.elects_from_eligibility_set());
        assert!(fleet.manages_ingress());

        let rig = ClusterPolicy::rig().ingress_ownership;
        assert!(!rig.follows_raft_leader());
        assert!(!rig.elects_from_eligibility_set());
        assert!(!rig.manages_ingress());
    }

    /// The coupling stays constructible for an appliance that wants it — this
    /// is a new variant, not a replacement.
    #[test]
    fn follows_raft_leader_remains_available_as_a_choice() {
        assert!(IngressOwnership::FollowsRaftLeader.follows_raft_leader());
        assert!(IngressOwnership::FollowsRaftLeader.manages_ingress());
        assert!(!IngressOwnership::FollowsRaftLeader.elects_from_eligibility_set());
    }
}
