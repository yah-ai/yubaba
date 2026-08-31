//! Leadership watcher — Phase 2 (R040-F21).
//!
//! Spawns a background tokio task that subscribes to the openraft metrics
//! watch channel and orchestrates Headscale + litestream on leader transitions:
//!
//! **On becoming leader:**
//! 1. Run `litestream restore` (no-op if S3 has no snapshot yet).
//! 2. Enable + start `headscale.service`.
//! 3. Start `litestream-headscale.service` sidecar.
//! 4. Write `SetIngressOwner` to raft so `/raft/status` reflects the
//!    current Headscale host.
//!
//! **On losing leadership:**
//! 1. Stop `litestream-headscale.service`.
//! 2. Stop `headscale.service`.
//!    (`/mesh/leader-health` automatically returns 503 once headscale stops,
//!    so Cloudflare stops routing to this node without an extra step.)
//!
//! Both halves are gated on
//! [`IngressOwnership::FollowsRaftLeader`](crate::cluster_policy::IngressOwnership)
//! (R118-T9). "The raft leader is also the external-ingress owner" is a rule
//! about a deployment that has clients outside the mesh, not a fact about
//! consensus — a cluster with no external identity to move still elects a
//! leader, it just has nothing for the leader to carry.
//!
//! The watcher exits cleanly when the raft metrics channel closes (daemon
//! shutdown).  It is tolerant of systemctl/litestream errors — it logs them
//! but does not panic, since a follower that fails to stop headscale will
//! surface as two nodes returning 200 on the Cloudflare healthcheck, which
//! the operator can detect and fix.
//!
//! @yah:relay(R591, "Headscale HA: exactly-one appliance whose external identity follows placement (W242 P4)")
//! @yah:at(2026-07-02T17:34:43Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:depends_on(R570)
//! @yah:next("Reframe from 'leader election' to an EXACTLY-ONE appliance workload (R572 archetype): the reconciler places headscale on some node per the cluster's agreed state; leader.rs already implements the follow-the-placement half (on-become: litestream restore → start headscale → replicate; on-lose: stop).")
//! @yah:next("The only property that makes headscale special vs a normal internal workload: its placement must COMMAND AN EXTERNAL INGRESS to follow it, because its clients (tailnet nodes + operator) live OUTSIDE the mesh. That external-identity-follows-placement is the whole point of this relay.")
//! @yah:next("Gated on R570: leader.rs's follow-placement code is inert until there is a real multi-voter raft to re-place the singleton on.")
//! @yah:gotcha("TODAY is the fragile path (verified 2026-07-01): cloud.mesh.yah.dev is a DIRECT A-record → us-west-001 (15.204.89.240), cloudflared inactive, headscale self-terminates Let's Encrypt (HTTP-01 on :80, serving :443). So a failover requires the new head to BOTH (a) take the A-record AND (b) re-mint the LE cert via HTTP-01 — a chicken-and-egg with a hard connectivity gap (DNS must already point at the new node to pass HTTP-01), and litestream restores the DB but NOT the acme-cache. The Cloudflare Tunnel (T2) dissolves both: stable CNAME (DNS never moves) + TLS at the CF edge (no per-node cert). The `cloudflare-tunnel-token-mesh` vault key is already provisioned but unused — the tunnel path was staged and never wired.")
//! @yah:gotcha("OPERATOR FRAMING 2026-08-12, and it generalizes past this relay: the bootstrap cycle here is NOT a headscale quirk. Once the coordinator sits behind front doors that reach it over the mesh, a total-fleet cold start deadlocks - nobody has a mesh, so no front door can reach the thing that grants one. Steady state is fine (a rebooting node borrows a healthy peer's mesh); it is the cold start that has no path. The operator's answer is that a CAMP bootstraps a mesh OUT OF BAND - over ssh, from a list of IPs - rather than over the mesh it is creating, and that this is the general shape for ANY new mesh, not a workaround for this one. Minimum in-design mitigation regardless: the front door co-located with the elected headscale routes cloud.mesh.yah.dev to LOOPBACK, so one path never depends on the mesh. Write that down as a constraint instead of letting the next reader rediscover it. (The deadlock itself is INFERENCE from config + topology as of 2026-08-12, not a tested failure - proving it is the first experiment.)")
//! @yah:gotcha("AUTHORIZED TESTBED: the dev cluster, and the operator explicitly sanctions BLOWING THE MESH AWAY AND RE-BOOTSTRAPPING IT there. That is us-west-011 (192.168.10.11), us-west-013 (192.168.10.13), us-west-014 (192.168.10.14) - the three aarch64 Raspberry Pis, sovereign_group = 'dev', taints = [], vendor = 'on-prem'. DO NOT rehearse on sovereign_group = 'prod' (us-east-001, us-south-001, us-west-001): every node in the fleet dials us-west-001's headscale as its server_url, so a mistake partitions the mesh from the box that coordinates it and recovery is ssh-only. As of 2026-08-12 two live apex origins also depend on that mesh staying up - us-south-001's passway proxies *=100.64.0.3:8080 across it (R330-F37).")
//! @yah:handoff("ALL THREE CHILDREN WORKED AND IN REVIEW (F1, T2, T3), one courier pass, nothing rolled to prod. Net: headscale is now described as an ordinary pinned singleton (new yubaba::headscale_appliance) that kamaji supervises with RestartPolicy::Always, leader.rs drives it through active_backend() on placement, T2's premise was reframed to the sovereign follow-placement design and written into W267, and litestream continuity turned out to be broken in three places rather than merely unconfigured. yubaba lib tests 417 -> 435, all green; clippy clean on every file touched.")
//! @yah:handoff("TREE ANCHOR 497a8a6bac12249c655996759787916ae0e6bd45 - quote that SHA, never HEAD, in any revert instruction. Note for whoever verifies: a peer's `sync` wip-commit swept this relay's edits in mid-pass, so `git status` does NOT list headscale_appliance.rs, release.yml or kamaji.service as modified. Verify by CONTENT - git show 497a8a6b:<path> | grep for front_door_upstream_rule, containerd-integration,native-exec, and native-exec-dir respectively. Files: NEW oss/yubaba/crates/yubaba/src/headscale_appliance.rs; oss/yubaba/crates/yubaba/src/{leader.rs,litestream.rs,lib.rs}; app/yah/cli/resources/kamaji.service; .github/workflows/release.yml; .yah/docs/working/W267-sovereign-public-ingress.md (append-only).")
//!
//! @yah:ticket(R591-F1, "Re-home headscale as a kamaji-supervised pinned-singleton appliance (retire raw systemctl)")
//! @yah:phase(P1)
//! @yah:status(review)
//! @yah:at(2026-08-12T21:40:39Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R591)
//! @yah:next("leader.rs::on_became_leader drives headscale via `systemctl enable --now headscale` (raw systemd). Re-home it as a kamaji-supervised workload with the R572 'appliance' archetype (pinned, single-instance, non-drainable). Placement start/stop flows through kamaji, not systemctl — same supervisor as every other workload.")
//! @yah:next("INTERIM (applied 2026-07-16): the raw headscale.service was hardened `Restart=on-failure` -> `Restart=always` as a reboot-safety bridge for the SPOF coordinator. Cutover to kamaji MUST preserve an equivalent always-restart-including-graceful-exit guarantee — do NOT retire the systemd unit until kamaji actively supervises the appliance (see gotchas + R406).")
//! @yah:gotcha("MOTIVATING INCIDENT (2026-07-16): the SPOF mesh coordinator's raw headscale.service was DEAD for 7 days. Root cause — `headscale serve` exits 0 on SIGTERM (graceful shutdown), and the unit's `Restart=on-failure` does NOT restart a clean exit-0; a boot-race SIGTERM at boot (2026-07-09 09:00:47 UTC, us-west-001) killed it and it never came back. Whole tailnet degraded: operator laptop + us-east-001/us-south-001 (2 of 3 raft voters) fell off-mesh. A kamaji pinned-singleton appliance MUST treat graceful-exit as restart-worthy, not just crash.")
//! @yah:gotcha("TWO native backends — the FLEET gate is kamaji-bin, NOT kamaji-core. The coordinator (us-west-001) runs kamaji.service = the kamaji-bin binary (pid observed: /usr/local/bin/kamaji --socket /run/kamaji/kamaji.sock); yubaba deploys to it over UDS via the sibling KamajiClient. oss/kamaji/crates/kamaji-bin/src/native.rs fork+execs + reaps zombies (R406-T6 pidfd loop) but has ZERO RestartPolicy handling — no respawn. oss/kamaji/crates/kamaji/src/native.rs (kamaji-core) is a SEPARATE inlined backend (desktop/CI + yubaba's in-process `runtime` fallback). So re-homing headscale via leader.rs active_backend() routes to kamaji-bin on the fleet, which won't restart it — the same regression one layer over. The fleet restart loop must hook restart-per-policy into kamaji-bin's pidfd-reaper ExitEvent path (R406-T6 territory, in review).")
//! @yah:gotcha("STATUS 2026-07-16: kamaji-core native restart loop DONE + tested — spec-retaining supervisor task (Always w/ fixed delay, OnFailure w/ max_attempts+exp backoff, Never), publishes WorkloadStatus::Restarting, restart_workload now works in-place, graceful_upgrade preserved; 24 kamaji lib tests green (3 new) + example + `cargo check --workspace --all-features` clean. This covers the INLINED backend ONLY. Remaining gate before leader.rs can retire systemctl: the same loop in kamaji-bin's native supervisor. leader.rs re-home intentionally NOT written yet to avoid routing the coordinator's headscale to an unsupervised backend.")
//! @yah:handoff("LANDED. New oss/yubaba/crates/yubaba/src/headscale_appliance.rs describes headscale as an ordinary pinned singleton: a Container-shaped WorkloadSpec with archetype=Appliance, replicas=1, restart_policy=Always, tier=infra, and the yah.exec=native annotation so kamaji forks the host binary at <headscale_dir>/headscale rather than pulling an image. leader.rs::on_became_leader / on_lost_leader now drive it through state.active_backend() (the same sibling KamajiClient every other deploy uses) instead of systemctl enable --now headscale.")
//! @yah:gotcha("THE 2026-07-16 'TWO NATIVE BACKENDS' GOTCHA ABOVE IS STALE ON ITS LOAD-BEARING CLAIM, and I read the code rather than taking it. It says re-homing via active_backend() routes to kamaji-bin's native.rs, which has no RestartPolicy handling. It does not. kamaji-bin/src/native.rs (SandboxPlan + landlock/cgroup fork+exec) is exported from lib.rs but NO deploy path calls it - server.rs::deploy_native_exec routes to ctx.native, which is kamaji_CORE's kamaji::native::NativeRuntime (server.rs:280, :1162). That is the runtime whose spec-retaining restart loop shipped 2026-07-16, so the fleet gate the gotcha describes was already open. Verified by grep: 'restart' appears ZERO times in kamaji-bin/src/native.rs, and RestartPolicy::Always => true is in kamaji-core's supervise() at oss/kamaji/crates/kamaji/src/native.rs:463.")
//! @yah:gotcha("THE REAL GATE WAS THE BUILD, NOT THE CODE, and it was invisible from the Rust side. kamaji-bin gates its native backend behind the native-exec cargo feature, and .github/workflows/release.yml built the fleet binary with --features containerd-integration ONLY. So every native-marked deploy on the fleet would have come back BackendRefused 'kamaji built without the native-exec feature' and yubaba would have fallen back to systemd forever, silently. Fixed in this pass: the kamaji cross-build now passes containerd-integration,native-exec. Verified the combination compiles (cargo check -p kamaji-bin --features containerd-integration,native-exec: clean, only the pre-existing pidfd events_tx dead-code warning).")
//! @yah:handoff("FOUND AND FIXED A LIVE REGRESSION SOURCE while in here, in scope and not filed away. yubaba::write_and_start_headscale_unit - the function that WRITES headscale.service on every POST /headscale/deploy - still emitted Restart=on-failure, the exact directive that produced the 7-day outage. The 2026-07-16 hardening was applied by hand to the box, never to the generator, so the next deploy would have reinstalled the incident. Now Restart=always, with the unit text split into a pure headscale_unit_text() so it is assertable without a systemd host, plus the regression test the_headscale_unit_restarts_on_a_graceful_exit.")
//! @yah:handoff("TWO EXACTLY-ONE HAZARDS IN THE TRANSITION, both closed. (1) systemd and kamaji both want 0.0.0.0:443, so start_headscale now runs systemctl disable --now headscale BEFORE the kamaji deploy and re-enables it if the deploy is refused - the node lands back exactly where it started rather than somewhere new, and a crash-loop on 'address in use' under RestartPolicy::Always is impossible. (2) The old on_lost_leader only stopped the unit; enable is persistent, so any node that ever ran the fallback path started a SECOND headscale at every later boot regardless of placement. Both paths now disable rather than stop.")
//! @yah:handoff("THE SYSTEMD FALLBACK IS KEPT ON PURPOSE, per this ticket's own next-bullet (do NOT retire the unit until kamaji actively supervises). The kamaji path exists only on a node whose kamaji is BUILT with native-exec and STARTED with --native-exec-dir; a rolling upgrade has both shapes live at once, and a yubaba that dropped the coordinator because its sibling was one release behind would take the tailnet down - the exact failure this relay removes. Retire the fallback once every node is confirmed on a native-exec kamaji.")
//! @yah:handoff("kamaji.service (app/yah/cli/resources/kamaji.service) needed three edits or the appliance starts and immediately fails, none of which are visible from the Rust. (a) --native-exec-dir /var/lib/yah/kamaji/native, else the backend is compiled in but unattached. (b) ReadWritePaths gains /var/lib/yah-cloud: a natively fork+exec'd child SHARES kamaji's mount namespace, so ProtectSystem=strict made headscale's own sqlite DB dir read-only to it - it would have started, then died on its first write. (c) CAP_NET_BIND_SERVICE added to CapabilityBoundingSet AND AmbientCapabilities: headscale binds :443 and :80, kamaji runs as root but the bounding set is a ceiling even for root, and a native child inherits the ambient set (no cap drop on that path, unlike the container path). That grant retires with R591-T2 - once passway fronts headscale over plain HTTP on a high port, nothing kamaji supervises needs a privileged port.")
//! @yah:verify("cargo test -p yubaba --lib = 426 passed / 0 failed (was 417). 9 new: 8 in headscale_appliance over the spec shape (Always restart, Appliance archetype agreeing with effective_archetype, wants_native_exec, the tier=infra admission floor kamaji enforces, argv naming the host binary, deploy/teardown agreeing on the mesh identity, the state dir travelling with it and not being hardcoded) + the headscale.service Restart=always regression test.")
//! @yah:verify("cargo check -p yubaba: clean. cargo clippy -p yubaba --lib: zero warnings on leader.rs or headscale_appliance.rs (the 10 crate-wide warnings are pre-existing and on files this ticket did not touch).")
//! @yah:verify("cargo check -p kamaji-bin --features containerd-integration,native-exec (from oss/kamaji): clean. This feature COMBINATION had never been built before - the fleet built containerd-only and the native-exec tests build it alone.")
//! @yah:next("NOT ROLLED TO THE FLEET, and deliberately - this is an operator step on sovereign_group=prod, where a mistake partitions the mesh from the box that coordinates it and recovery is ssh-only. Sequence when you do: cut a release so the fleet kamaji carries native-exec, ship the new kamaji.service, systemctl daemon-reload + restart kamaji on ONE node, confirm its journal says 'native-exec backend attached', then restart yubaba there and watch for 'headscale appliance deployed under kamaji supervision'. Do us-west-001 LAST - it is the live coordinator and the only node where getting it wrong is felt fleet-wide.")
//! @yah:assumes("That a native child inherits kamaji's AmbientCapabilities and can therefore bind :443. This is INFERENCE from reading the code, not a live test: kamaji-core's spawn_child is a plain tokio::process::Command with no capability drop (unlike kamaji-bin's landlock path, which explicitly clears all five cap sets pre-exec), and systemd's AmbientCapabilities are inherited across a plain fork+exec. If it turns out wrong on the box, the fix is AmbientCapabilities on a headscale-specific mechanism rather than widening kamaji further - and the whole question disappears under R591-T2, which takes headscale off privileged ports entirely.")
//!
//! @yah:ticket(R734-T4, "Stable leader pin: soft-prefer the anchor region for elections while keeping disaster survivability")
//! @yah:status(review)
//! @yah:at(2026-08-12T01:33:23Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P2)
//! @yah:parent(R734)
//! @yah:next("Tier: Cleric — optional/recommended in W247, and the native transfer_leader primitive it rides on already works.")
//! @yah:next("Reduces leader churn over the WAN. openraft 0.10's Trigger::transfer_leader shipped under R608-B11 (verified green in tests/raft_transfer_leader.rs), so the mechanism exists — this is the soft preference on top.")
//! @yah:next("Needs F2's region tag to know which voter is the anchor.")
//! @yah:depends_on(R734-F2)
//! @yah:handoff("NOT BUILT THIS PASS, and deliberately so rather than for lack of time alone. T4's own @yah:next already said 'Needs F2's region tag to know which voter is the anchor'. F2 shipped the tag; what it did not ship is anything that WRITES it, so YubabaState.members is empty on a live cluster and a leader-pin actuator has no way to ask which voter sits in the anchor region. Filed the unblocker as R734-F5 (--region on serve + each node registering its own member row) with the full design worked out, so it is at the start line rather than merely named.")
//! @yah:handoff("Tree anchor at handoff: 6b07ab6774e014deb7ab8bf2d2220a29ecd781af — the shared tree as I left it. Diff against it (`git diff 6b07ab6774e014deb7ab8bf2d2220a29ecd781af..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("DO R734-F5 FIRST. It is the whole gate, and it is small.")
//! @yah:next("DESIGN ANALYSIS, so the next agent does not re-derive it. There are two real implementations and they are not equally good. (A) ELECTION-TIMEOUT SKEW: anchor-region nodes use the lower part of the election band, others the higher, so the anchor wins a healthy race and the rest still elect when it is gone. Needs no replicated region data - a node only needs its own --region - so it could be built before F5. Two reasons I did not: it is statistical, so its test is 'the anchor usually wins', which is exactly the flaky-test shape this suite has avoided everywhere else; and R118-T9's own residual_risk note in cluster-epochs.json already flags mismatched timings across nodes as a misconfiguration, so deliberately skewing them needs a strong argument that it will not be mistaken for the accident.")
//! @yah:next("(B) LEADER-SIDE TRANSFER, and this is the one I would build: when the sitting leader is NOT in the anchor region and a caught-up voter IS, the leader hands off using the native Trigger::transfer_leader that R608-B11 already shipped (green in tests/raft_transfer_leader.rs, driven by POST /raft/transfer-leader). Deterministic, so the test is deterministic - stand up a cluster whose leader is outside the anchor, wait, assert leadership settles on the anchor voter and membership stays a single uniform config. Soft by construction: it only ever acts when an anchor voter is healthy and caught up, so losing the anchor region cannot block failover to a survivor, which is the disaster-survivability half W247 §3 asks for. It needs F5 because the leader must know its peers' regions.")
//! @yah:next("SHAPE OF THE POLICY FIELD, if (B): a `leader_anchor: Option<region>` reads like a natural ClusterPolicy field, but check it against that module's own rule first - a field earns its place by answering a question a decision point asks. Here one does (the transfer loop asks 'should I hand off?'), and the presets genuinely differ (a rig has no anchor; the fleet does), so it fits - unlike pre-vote, which did not. The anchor is per-DEPLOYMENT rather than per-preset though, so it likely wants to come from config/CLI and be carried on the policy value, not hardcoded into fleet().")
//! @yah:next("GUARD AGAINST CHURN whichever way it goes: a transfer loop that fires whenever the leader is off-anchor will fight any other force moving leadership, and two mechanisms disagreeing about who leads is worse than an off-anchor leader. Require the anchor candidate to be caught up, rate-limit the handoff, and do not retry a transfer that just failed.")
//! @yah:notify_on(R734-F5, "R734-F5 populated MemberInfo.region, so a leader can now read its peers' regions. T4's leader-side transfer design (option B in its @yah:next) is unblocked — build that, not the election-timeout skew.")
//! @yah:handoff("LANDED as leader-side transfer (option B from this ticket's own design analysis), not election-timeout skew. New oss/yubaba/crates/yubaba/src/leader_pin.rs: a pure decide() returning PinDecision{NotLeader, AlreadyAnchored, NoAnchorCandidate, HandOffTo(id)} plus a paced loop. On the LEADER only, when its own member row is outside the anchor region and another current voter's row is inside it and that voter is caught up, it hands off with openraft's native Trigger::transfer_leader. Every other node's loop reaches NotLeader and does nothing, so the task is started unconditionally on every node and there is no start/stop edge across an election.")
//! @yah:handoff("SOFT BY CONSTRUCTION, and that is the load-bearing property. The loop only acts when an anchor voter is present, voting, and caught up; a dark anchor region and an untagged cluster are the same input (no eligible candidate) and the response to both is to leave leadership exactly where the election put it. The pin can tidy up after a failover, never block or reverse one. Asserted as a test, not a comment: a_cluster_with_no_voter_in_the_anchor_region_is_left_alone watches for 5s across 20 evaluation ticks.")
//! @yah:handoff("THE ANCHOR IS DEPLOYMENT CONFIG, NOT A CLUSTERPOLICY FIELD, and this ticket's own next-bullet guessed the other way, so here is the reasoning. cluster_policy's bar is that a field answers a question a decision point asks and that no field records which preset produced it. The pin's question is WHICH region should lead, whose answer is a per-deployment label; ClusterPolicy::fleet() is a const fn returning a Copy value shared by every fleet and cannot supply one, and an Option<String> would cost the type both Copy and const for a value the preset does not know. So the anchor travels the way --region does. What the POLICY does decide is whether an anchor means anything at all: leader_pin::validate refuses one under QuorumGeography::SingleFailureDomain, fatally at boot, because a rig has one failure domain and no regions to prefer between. Verified live: serve --cluster-profile rig --leader-anchor us-west exits with that message.")
//! @yah:handoff("CHURN GUARDS, since two mechanisms disagreeing about who leads is worse than an off-anchor leader. (1) The candidate must be caught up, within PinConfig::max_lag_entries=10 of the leader's last_log_index, read from openraft's replication metrics. (2) Any attempt starts a cooldown, set BEFORE the await so a slow handoff cannot be joined by a second. (3) A target that fails is skipped for a longer per-target backoff. All three derive from RaftTiming via PinConfig::new (fleet: evaluate 12s, cooldown 60s, backoff 120s; rig: 3.6/18/36), so a LAN cluster is not paced like a WAN one. The loop is a plain interval rather than a wake on the metrics watch, unlike member_registration: a leader's metrics change every heartbeat and an anti-churn mechanism has no business evaluating at election speed.")
//! @yah:handoff("WIRED, not just built: yubaba serve --leader-anchor <region>, validated fatally at boot, spawned inside the raft branch, and warned about (not fatal) when passed without --raft-node-id. Renders correctly in serve --help.")
//! @yah:next("OPTIONAL FLEET ROLLOUT, and it is genuinely optional - the pin is a latency optimisation, not a correctness requirement. Turning it on is one flag plus a restart per node (--leader-anchor <region>), and turning it off later is the same. W247's OVH checklist step 5 now carries the procedure and the two confirmations: check current_leader lands in the anchor after a minute, then kill the anchor's voter and confirm leadership STAYS with a survivor. Do not roll it before R734-F5 is on every node - the pin reads member rows, so on a fleet without F5 the map is empty and the pin correctly does nothing.")
//! @yah:verify("cargo test -p yubaba --lib = 405 passed / 0 failed. 13 of those are new leader_pin unit tests over decide()/caught_up()/validate(), including the disaster case, a lagging anchor voter, an anchor-region LEARNER (not a voter, so not a candidate), an untagged leader deferring to a known anchor voter, and lowest-id tie-breaking for determinism.")
//! @yah:verify("cargo test -p yubaba --test raft_leader_pin = 2 passed / 0 failed. NEW SUITE, live 3-voter fleet cluster founded 1-1-1 through POST /raft/initialize with region tags (so the R734-F2 gate is satisfied, not bypassed) and registering rows through R734-F5's real member_registration loop rather than a hand-seeded map. Test 1 moves leadership off the anchor deterministically first (via the existing operator route) so the starting state is not election-dependent, then asserts it settles on the anchor, that membership stays a single UNIFORM config, and that it STOPS - 10 further samples over 5s catch an oscillating pin.")
//! @yah:verify("No regressions across the other 8 raft suites: raft_pre_vote 3/0, raft_quorum_geography 5/0, raft_membership_loop 5/0, raft_transfer_leader 1/0, raft_add_learner 1/0, raft_promote_voter 2/0, bootstrap_single_node 2/0, rig_singleton_ownership 2/0.")
//! @yah:verify("cargo clippy -p yubaba --all-targets: zero warnings on leader_pin.rs, tests/raft_leader_pin.rs, or main.rs. The 69 crate-wide warnings are pre-existing or peer-owned and none are on a file this ticket touched.")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift = 8 passed / 0 failed. NO re-record was needed for T4 and none was made by me - it is hash-neutral on both axes by construction. The only lib.rs edit is `pub mod leader_pin;` plus two doc lines; the extractor strips comments first and keeps only lines containing /raft/ and top-level `fn raft_*` items, and leader_pin.rs / main.rs / tests are not surface inputs at all. No new replicated type, no new route, no new wire message - Trigger::transfer_leader rides /raft/transfer-leader-msg, which was already in the surface.")
//! @yah:gotcha("COLLISION, HANDLED, WORTH KNOWING FOR THE RELAY. Two sessions were spawned onto R734 at the same time with the same first action: me (Ashguard/blade, session:b4f7871f) and Ashguard/libra (session:99475bc6). I claimed R734-F5 first, found libra's edits already on disk in it within two minutes, and RELEASED it with zero source edits of mine - see the collision gotcha on R734-F5 for the evidence. T4 was then built alongside their live F5 work rather than against it. This is a dispatch-level issue, not a code one: nothing is corrupted, but the relay should not be double-dispatched again.")
//! @yah:assumes("That a voter within 10 log entries of the leader can win an election promptly after Trigger::transfer_leader's TimeoutNow. The threshold is a judgement, not a measurement: too strict and the pin only fires on a perfectly idle cluster, too loose and the handoff is wasted on a node that must catch up first. 10 entries on a low-write control plane is well under one election timeout, but it has not been measured against a busy cluster. PinConfig::max_lag_entries is the knob if it ever needs revisiting.")
//! @yah:handoff("CORRECTION AFTER REVIEW FEEDBACK from @Ashguard:libra (session:99475bc6, R734-F5), and it was a real bug rather than a nit. decide() originally required positive evidence about the TARGET (a peer row saying anchor) but accepted SILENCE about ITSELF: a leader with no member row fell through to the candidate search and handed leadership away. So a leader already in the anchor region whose own row had not landed yet would move leadership to a peer in the SAME region for no gain. Every node is row-less for a moment after boot while F5's registration loop converges, making this the shape a rolling upgrade produces on every node in turn - churn manufactured by the anti-churn feature.")
//! @yah:handoff("THE FIX: new PinDecision::LeaderRegionUnknown. The pin now acts only on positive evidence about BOTH ends - if replicated state does not say where the leader is, nothing happens. A row that exists but declares region: None gets the same answer as no row at all: it is settled information rather than a pending write, but it is still not evidence about where this node is, so one rule covers both. The old test a_leader_with_no_region_row_defers_to_a_known_anchor_voter asserted the WRONG behaviour and is replaced.")
//! @yah:handoff("FALSIFIED, NOT ASSUMED. I restored the old two-line rule behind a probe and re-ran: a_leader_that_has_not_published_its_region_does_not_hand_off FAILS in 2.84s against a live 3-node cluster with the exact message it was written to catch, and passes with the fix. The probe is removed - grep FALSIFICATION PROBE in leader_pin.rs returns nothing. That is the difference between a test that covers the branch and a test that would have caught the bug.")
//! @yah:verify("cargo test -p yubaba --lib = 407 passed / 0 failed (up from 405: two new leader_pin unit tests for the row-less and no-region-declared cases).")
//! @yah:verify("cargo test -p yubaba --test raft_leader_pin = 3 passed / 0 failed (up from 2). The new live test leaves node 1 out of the registration loop, hands it leadership deterministically through the operator route, and asserts across 20 ticks that the pin does NOT move leadership to the registered anchor voter sitting right there. It carries two precondition assertions so a green run cannot be vacuous: the leader really has no row, and the anchor voter really does.")
//! @yah:verify("No regressions after the change: raft_member_registration 6/0 (@Ashguard:libra's F5 suite), raft_membership_loop 5/0, raft_quorum_geography 5/0, raft_pre_vote 3/0, raft_transfer_leader 1/0. cluster_epoch_drift still 8/0. clippy still clean on leader_pin.rs, tests/raft_leader_pin.rs and main.rs.")
//! @yah:verify("Verified against the live F5 surfaces rather than taking them on description: solo_node_unregistered exists in the harness, GET /raft/status carries a members section (lib.rs:4778), solo_node now wires with_cluster_state (solo_node.rs:119). SoloNode still exposes neither `raft` nor `state_machine`, so the local node builder and its @yah:cleanup both stand.")
//! @yah:handoff("CLEANUP CLOSED, not deferred. @Ashguard:libra added pub raft + pub state_machine to SoloNode while still in solo_node.rs, so the local node builder in tests/raft_leader_pin.rs is GONE - the suite now uses solo_node_in_region / solo_node_unregistered like every other raft suite. Net effect on the file: the builder, its Drop impl and its health-poll are deleted, a Pins guard replaces the per-node pin handle (the harness has no business knowing some tests run an actuator), and a fourth test was added. The @yah:cleanup this ticket carried is removed rather than left standing.")
//! @yah:handoff("FOURTH TEST, the candidate-side mirror of the LeaderRegionUnknown fix: an_unregistered_anchor_voter_is_not_a_handoff_target. A voter physically in the anchor region that has published no row is not a target, and its silence does not become a reason to move leadership elsewhere. This documents behaviour that was ALREADY correct rather than fixing a second bug - a row-less peer has always failed the in_anchor test, so the pin returns NoAnchorCandidate. Worth pinning anyway because the obvious optimisation of falling back to the founding payload's region tags would break it, and those tags sit in membership to tempt someone. Both a unit test and a live one.")
//! @yah:verify("cargo test -p yubaba --lib = 408 passed / 0 failed (16 leader_pin unit tests).")
//! @yah:verify("cargo test -p yubaba --test raft_leader_pin = 4 passed / 0 failed, now built on the harness rather than a private builder.")
//! @yah:verify("Full raft sweep after the fold-back, all green: raft_member_registration 6/0, raft_quorum_geography 5/0, raft_membership_loop 5/0, raft_pre_vote 3/0, raft_transfer_leader 1/0, raft_add_learner 1/0, raft_promote_voter 2/0, bootstrap_single_node 2/0, rig_singleton_ownership 2/0. cluster_epoch_drift 8/0. clippy clean across yubaba + yubaba-test-harness on every file this ticket touched.")
//!
//! @yah:ticket(R737-F3, "Leader-resident scheduler loop: rebuild from the committed log on leader change, idempotent transfer decisions")
//! @yah:status(review)
//! @yah:at(2026-08-16T03:50:39Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:phase(P3)
//! @yah:parent(R737)
//! @yah:next("Tier: Warrior — the missing middle itself; idempotency across a mid-decision leader failover is the whole correctness argument.")
//! @yah:next("The SHAPE already exists: raft/leader.rs's leader watcher starts/stops Headscale + litestream on leadership transitions. This is a second control loop of the same kind, not a new pattern.")
//! @yah:next("Per tick: read lease state from R737-F2's detector; for each tenant whose owner's lease expired, pick a target that is already live, in-region-preferred, within headroom, and (SLA tier) already warm; commit TransferTenant{tenant,to,from_epoch} via R732-F1.")
//! @yah:next("Decisions keyed on (tenant, from_epoch) so a log replay after mid-decision leader failover cannot double-place.")
//! @yah:gotcha("Provisioning is ALREADY correctly off the critical path — cloud::provision::execute is a background, minutes-scale op. Do not regress it by calling provision inline from failover. Failover targets live nodes only; provisioning restores headroom on a relaxed clock.")
//! @yah:depends_on(R737-F1)
//! @yah:depends_on(R737-F2)
//! @yah:handoff("New oss/yubaba/crates/yubaba/src/scheduler.rs: leader-resident placement loop, same shape as leader_pin.rs (unconditionally spawned on every node; a follower's tick is a no-op; a pure decide-style function is the tested unit). decide_transfer(owner_confirmed_down, TenantSnapshot, candidates) -> PlacementDecision{OwnerLive, NoEligibleCandidate, TransferTo(node)} is free of raft/openraft types. Region is PREFERRED not required (an out-of-region live node still gets picked over leaving a tenant down); WarmReplica-tier tenants require a warm candidate, which nothing populates yet (W248's gap, documented -- candidates always report warm_for_tenant=false today, so a warm-tier tenant's dead owner currently yields NoEligibleCandidate rather than a wrong placement, matching SlaTier's existing pessimistic-default philosophy). 10 unit tests cover: live owner no-op, dead-owner re-placement, no-eligible-candidate, owner-excluded-from-its-own-candidacy, region preference both directions, warm-tier gating both ways, cold-tier no warmth requirement, node-id tie-break determinism, config pacing.")
//! @yah:handoff("Idempotency is NOT a scheduler-side dedup table -- it rides R732-F1's existing TransferTenant CAS on (tenant, from_epoch), which the loop satisfies for free by reading the CURRENT epoch fresh every tick rather than caching one. After a successful transfer the owner is no longer the dead node, so the tenant drops out of the trigger set on the very next tick -- no double-placement risk across a mid-decision leader failover, and no persisted decision-log needed.")
//! @yah:handoff("Trigger is R737-F2's TransitionTracker, owned per-loop-instance (fresh on every node, including a newly-elected leader) -- read the module doc's 'What is deliberately NOT persisted to raft: liveness itself' section for the explicit call I made on F2's own open question: liveness stays off the raft log by design (W253 §7), so a brand-new leader re-earns the confirm-down dwell from zero rather than trusting a predecessor's judgement. Bounded, one-time cost (one HysteresisPolicy::confirm_down_after) per leadership change, not compounding.")
//! @yah:handoff("Added 3 read accessors to YubabaStateMachine (raft/store.rs): tenants() (whole map, the scheduler's per-tick walk), tenant_placement(id) (single record), node_admits(node, demand, now) (forwards to the R737-F1 headroom predicate under one lock instead of cloning 3 maps to recompute it). Wired in main.rs: scheduler::spawn(...) alongside leader_pin, using shared_state.lease_detector.clone() and SchedulerConfig::new(policy.timing, HysteresisPolicy::from_thresholds(policy.liveness_thresholds())) -- paced off the raft heartbeat (2x), not the election timeout, since (unlike leader_pin) this loop's anti-churn property is F2's hysteresis dwell, not its own pacing.")
//! @yah:handoff("Verify: cargo check -p yubaba clean; cargo check -p yubaba --bin yubaba clean; cargo test -p yubaba --lib = 475 passed / 0 failed (was 465 before this ticket); cargo clippy -p yubaba --lib and --bin yubaba: zero findings on scheduler.rs, the 3 new store.rs accessors, or main.rs (all clippy output was the same pre-existing debt in unrelated files already noted on F2's handoff).")
//! @yah:handoff("Tree anchor at handoff: 850868d6f33f40b8e62376555f94a9e928254b45 — the shared tree as I left it. Diff against it (`git diff 850868d6f33f40b8e62376555f94a9e928254b45..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("T5 (Placement tests, depends_on this ticket) is the live-cluster proof -- decide_transfer's unit coverage does NOT exercise the real spawn/run loop against a live raft cluster. Template it on tests/raft_leader_pin.rs's SoloNode/three_region_cluster/agreed_leader/force_leader harness: a start_scheduler(nodes) helper mirroring start_pins, POST /raft/write to seed ClaimTenant + SetTenantPlacement + SetMember{capacity} (node_admits needs published capacity or every candidate is refused), then kill/never-renew a node's lease and assert TransferTenant lands on a live node via GET /tenants/{id} -- with cloud::provision never called (T5's own zero-provisioning-calls assertion), and the kill-2-of-3-voters freeze case per W253 §9.")
//! @yah:next("Nothing calls POST /mesh/lease-renew yet (same gap F2's handoff already flagged) -- without a real renewal loop, TransitionTracker never confirms anyone Up OR Down on a live cluster, so today's scheduler is wired but inert end-to-end. T5's test harness will need to fake renewals directly against LeaseFailureDetector::renew() (test-only access, no HTTP) or add the still-missing node-side renewal loop first.")
//! @yah:next("warm_for_tenant is hardcoded false (see module doc) until W248 populates a per-tenant warm-replica-holder map; a WarmReplica-tier tenant cannot fail over at all until that lands. Flag this to whoever picks up W248 -- it is a hard dependency the design doc's own tier split created, not an oversight.")
//! @yah:verify("cargo check -p yubaba (clean)")
//! @yah:verify("cargo check -p yubaba --bin yubaba (clean)")
//! @yah:verify("cargo test -p yubaba --lib = 475 passed, 0 failed, 0 ignored")
//! @yah:verify("cargo clippy -p yubaba --lib and --bin yubaba: no findings on scheduler.rs, store.rs's new accessors, or main.rs")
//! @yah:handoff("DISCOVERED WORK, done rather than filed: added oss/yubaba/crates/yubaba/src/lease_renewal.rs, the client half of R737-F2's lease channel that neither F2 nor this ticket's first pass had built -- without it nothing ever calls POST /mesh/lease-renew, so TransitionTracker never confirms any node Up or Down and the scheduler built above was wired but inert end-to-end. Mirrors member_registration.rs's shape (paced loop, spawned unconditionally on every node) but is simpler: a renewal is a best-effort HTTP nudge into the leader's LOCAL non-raft registry, not a consensus write, so there is no CAS/forward-and-retry ladder -- a missed tick just tries again next tick. The leader renews itself in-process (no self-HTTP-call); every other node forwards to the leader's mesh address read from the same membership_config.get_node() member_registration already uses. plan_renewal() is the pure decide fn (SelfRenew / ForwardTo(addr) / NoLeaderYet), 4 unit tests.")
//! @yah:handoff("Wired in main.rs: yubaba::lease_renewal::spawn(node_id, raft_node.clone(), shared_state.lease_detector.clone(), Duration::from_millis(policy.timing.heartbeat_interval_ms)) -- paced at the raft heartbeat cadence so a detector gets ~10 renewal chances within LivenessThresholds::down_after before calling a node down.")
//! @yah:handoff("With this, the full R737-F2+F3 chain is live end-to-end on a raft-configured node: every node renews -> leader's LeaseFailureDetector observes -> scheduler's TransitionTracker debounces -> a confirmed-Down owner's tenants get TransferTenant'd onto live, admitting capacity. Nothing in this chain has been exercised against a REAL multi-node cluster yet -- that live proof is T5's job (see next), and the test-harness plumbing it needs (SoloNode exposing lease_detector, which does not exist yet) is called out there so T5 does not have to rediscover the gap.")
//! @yah:handoff("Full re-verify after the addition: cargo check -p yubaba clean; cargo check -p yubaba --bin yubaba clean; cargo test -p yubaba --lib = 479 passed / 0 failed (was 475 after the scheduler alone, 465 before this ticket; +4 from lease_renewal); cargo clippy -p yubaba --lib --bin yubaba: zero findings on lease_renewal.rs or the main.rs wiring.")
//! @yah:verify("cargo check -p yubaba (clean)")
//! @yah:verify("cargo check -p yubaba --bin yubaba (clean)")
//! @yah:verify("cargo test -p yubaba --lib = 479 passed, 0 failed, 0 ignored")
//! @yah:verify("cargo clippy -p yubaba --lib --bin yubaba: no findings on scheduler.rs, lease_renewal.rs, the 3 new store.rs accessors, or main.rs")
//!
//! @yah:ticket(R737-T5, "Placement tests: owner death re-places with zero provisioning calls; quorum loss freezes placement while the data path keeps serving")
//! @yah:status(review)
//! @yah:at(2026-08-19T02:08:21Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P3)
//! @yah:parent(R737)
//! @yah:next("Tier: Warrior — the kill-2-of-3 case is the single test that proves control/data separation, and it is easy to write in a way that passes vacuously.")
//! @yah:next("Test 1: kill a tenant's owner, assert re-placement onto a live node and assert cloud::provision was NOT called.")
//! @yah:next("Test 2: kill 2 of 3 raft voters, assert placement FREEZES while existing placements keep serving — the W253 section 9 control/data-separation test.")
//! @yah:next("integration_mesh.rs already covers raft partition and quorum-loss mechanics; extend it rather than starting a new harness.")
//! @yah:verify("cargo test -p yubaba --test integration_mesh")
//! @yah:depends_on(R737-F3)
//! @yah:handoff("New oss/yubaba/crates/yubaba/tests/raft_tenant_placement.rs: 2 live-cluster tests on a real 3-voter openraft cluster (ClusterPolicy::rig, loopback HTTP, DummyRuntime, credential-free, no containerd feature gate). Both drive the REAL scheduler::spawn on every node with both production detectors attached. 24.7s wall.")
//! @yah:verify("cargo test -p yubaba --test raft_tenant_placement = 2 passed / 0 failed in 24.74s")
//! @yah:verify("MUTATION-CHECKED for vacuity: passing None instead of the lease detector into scheduler::spawn makes test 1 fail as designed (tenant never moves, owner still node 2 after 20s). The test can fail.")
//! @yah:verify("cargo test -p yubaba --lib = 496 passed / 0 failed (no regression)")
//! @yah:verify("cargo test -p yubaba --test rig_singleton_ownership --test raft_leader_pin = 4 + 2 passed (harness change breaks no existing consumer)")
//! @yah:verify("cargo test -p yubaba --tests --no-run: every test target still builds")
//! @yah:verify("cargo clippy -p yubaba --lib --bin yubaba -p yubaba-test-harness: no findings in any file this ticket touched")
//! @yah:handoff("Test 1 (owner death re-places, zero provisioning): kills a NON-leader owner so the transfer is a live leader acting on a dead follower rather than an election side effect. Asserts the new owner is one of the SURVIVING node ids (not merely different -- placing onto the other dead node would satisfy 'moved'), that the fencing EPOCH advanced (an owner-only assertion passes if any path rewrote the record), and that the raft member map is byte-identical across the failover.")
//! @yah:handoff("ZERO-PROVISIONING-CALLS, honestly: there is no counter to assert on and a mock MachineProvider would be vacuous (the local tier never touches the provider, so it reads zero whatever the scheduler did). The static fact is stronger and already true -- rg cloud::provision over oss/yubaba/crates/yubaba/src finds only prose in headroom.rs saying it deliberately does not call it. The test asserts the LIVE property that fact should produce: the member map is unchanged across the failover, because provisioning would have to grow the cluster and growing it means a new member row.")
//! @yah:handoff("Test 2 (quorum loss freezes placement, data path keeps serving, W253 s9): kills 2 of 3 voters. Non-vacuity is structural -- identical policy, seeding, schedulers and renewal pump as test 1, the ONLY difference being how many nodes die, and both wait the same PLACEMENT_WINDOW constant that test 1 ASSERTS a placement lands inside. So the freeze is the quorum loss, not a scheduler that was never going to act. The dead nodes ARE confirmed down on the survivor's tracker, so the scheduler has a live trigger and is refused only by the missing quorum. Also asserts the epoch did not advance (a locally-applied transfer is exactly what would let a healed cluster see two owners) and that the survivor keeps answering reads under a 5s client timeout, so a stall fails rather than hangs.")
//! @yah:handoff("DISCOVERED WORK, done not filed -- harness plumbing (oss/yubaba/crates/yubaba-test-harness/src/lib.rs): ClusterNode gained lease_detector, wired via with_lease_detector in BOTH test_cluster and restart_node (restart gets a FRESH registry on purpose -- the registry is deliberately raft-free, so it must not survive a process death any more than it would in production). New Cluster accessors raft(idx) / node_id(idx) / lease_detector(idx), and renew_lease(at,from) / renew_leases_except(at,except). The latter skips nodes kill_node stopped, so 'the fleet is alive except the one I killed' needs no test-side bookkeeping and cannot accidentally keep a corpse renewing. Smoke tier gets None (its lease registry lives in another process).")
//! @yah:handoff("FILED IN A NEW FILE, NOT integration_mesh.rs -- deviation from this ticket's own next-step, with reason. integration_mesh's tests are #[test_with_provider(local, smoke)] behind the containerd-integration feature, so putting the W253 s9 control/data-separation proof there would park it in a file the default cargo test never runs: exactly the 'passes vacuously' outcome this ticket's own tier note warns about. raft_tenant_placement.rs uses the same Cluster harness and the same kill_node primitive with no feature gate. Rationale is in the file's module doc so a reader does not re-litigate it.")
//! @yah:cleanup("Removed a now-false @yah:gotcha from R737-F3 claiming the harness has no with_lease_detector and that T5 must plumb it -- T5 plumbed it, so the note would send the next reader looking for work that is done.")

use std::sync::Arc;

use openraft::async_runtime::watch::WatchReceiver;
use tracing::{error, info, warn};

use crate::raft::{YubabaNodeId, YubabaRaft, YubabaRequest};
use crate::ServerState;
use crate::{headscale_appliance, litestream};

/// Spawn the leadership watcher.  The returned `JoinHandle` can be aborted on
/// daemon shutdown, but the watcher will also exit on its own when the raft
/// metrics channel closes.
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state: Arc<ServerState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state).await;
    })
}

async fn run(node_id: YubabaNodeId, raft: YubabaRaft, state: Arc<ServerState>) {
    let mut watch = raft.metrics();
    let mut prev_is_leader = false;

    loop {
        let is_leader = {
            let metrics = watch.borrow_watched();
            metrics.current_leader == Some(node_id)
        };

        if is_leader != prev_is_leader {
            info!(node_id, is_leader, "raft leader state changed");
            // R118-T9: whether the cluster's *external* identity rides along
            // with raft leadership is a policy decision, not a property of
            // leadership. A cluster whose clients are all inside the mesh has
            // no external identity to move, and coupling gateway election to
            // consensus election lets a flaky uplink churn leadership.
            if state.cluster_policy.ingress_ownership.follows_raft_leader() {
                if is_leader {
                    on_became_leader(node_id, &raft, &state).await;
                } else {
                    on_lost_leader(&state).await;
                }
            } else {
                info!(
                    node_id,
                    is_leader,
                    "cluster policy does not tie external ingress to raft leadership — \
                     no ingress transition"
                );
            }
            prev_is_leader = is_leader;
        }

        if watch.changed().await.is_err() {
            warn!("raft metrics watch closed — leader watcher exiting");
            break;
        }
    }
}

async fn on_became_leader(_node_id: YubabaNodeId, raft: &YubabaRaft, state: &Arc<ServerState>) {
    let headscale_db = state.headscale_dir.join("headscale.db");

    // 1. Restore from S3 (no-op if no snapshot exists yet).
    //
    // R591-T3: `install` MUST come first, and until that ticket nothing called
    // it at all. Both the restore below and the replicate unit started in
    // step 3 run `litestream -config /etc/yah-cloud/litestream.yml`, and
    // nothing else on the node writes that file — so on every node the restore
    // failed at "no such file" into a `warn!` and the sidecar start failed
    // against a unit that had never been written, into a discarded exit status.
    // Installing here rather than at provision time also means a node that
    // becomes the ingress owner years after it was provisioned still gets a
    // config matching the S3 URL this yubaba was actually started with.
    if let Some(s3_url) = &state.litestream_s3_url {
        if let Err(e) = litestream::install(&headscale_db, s3_url) {
            warn!(
                "litestream install failed ({e:#}) — restore and replication will not run on \
                 this node; the headscale DB is unbacked until this is fixed"
            );
        }
        match litestream::restore(&headscale_db, s3_url).await {
            Ok(()) => info!("litestream restore complete"),
            Err(e) => warn!(
                "litestream restore failed (continuing — headscale may start from local DB): {e}"
            ),
        }
    }

    // 2. Start headscale as a kamaji-supervised appliance.
    start_headscale(state).await;

    // 3. Start litestream sidecar.
    if state.litestream_s3_url.is_some() {
        litestream::start();
        info!("litestream-headscale sidecar started");
    }

    // 4. Claim ingress owner in raft state machine so `yah mesh status` can
    //    show which machine is serving Headscale.
    if let Some(machine) = derive_machine_name() {
        let req = YubabaRequest::SetIngressOwner { machine };
        match raft.client_write(req).await {
            Ok(_) => info!("ingress owner set in raft state"),
            Err(e) => error!("failed to set ingress owner in raft: {e}"),
        }
    }
}

async fn on_lost_leader(state: &Arc<ServerState>) {
    // 1. Stop litestream replicate (followers don't replicate).
    if state.litestream_s3_url.is_some() {
        litestream::stop();
        info!("litestream-headscale sidecar stopped");
    }

    // 2. Stop headscale.  `/mesh/leader-health` will return 503 automatically.
    stop_headscale(state).await;
}

/// Start the headscale appliance on this node (R591-F1).
///
/// Prefers the node's kamaji — the same supervisor every other workload runs
/// under — and falls back to the raw `headscale.service` systemd unit when
/// there is no backend attached or when the backend refuses the spec.
///
/// # Why the fallback is not belt-and-braces timidity
///
/// The kamaji path only exists on a node whose kamaji was **built** with the
/// `native-exec` feature and **started** with `--native-exec-dir`. Neither was
/// true of the fleet before this ticket, and a rolling upgrade means both
/// shapes are live at once. A yubaba that lost the appliance because its
/// sibling was a release behind would take the whole tailnet down with it —
/// which is the exact failure mode this relay is here to remove, not a price
/// worth paying for a cleaner call site. The fallback retires when every node
/// is confirmed on a native-exec kamaji; see this ticket's `@yah:next`.
///
/// A refusal is logged at `warn` rather than swallowed, because "kamaji built
/// without the native-exec feature" is an operator-actionable message and the
/// difference between a supervised and an unsupervised coordinator is the
/// entire point of the change.
///
/// # The handover is ordered, and the order is the whole safety argument
///
/// The systemd unit and the kamaji appliance both want `0.0.0.0:443`. Deploying
/// under kamaji while systemd still holds the port produces a coordinator that
/// crash-loops on `bind: address in use`, and `RestartPolicy::Always` would
/// make it loop forever. So the unit is stopped **and disabled** first, then the
/// appliance is deployed, and a refusal re-enables the unit — landing back
/// exactly where the node started rather than somewhere new.
///
/// `disable`, not merely `stop`: `enable` is persistent, so a node that ever ran
/// the fallback path starts headscale at every subsequent boot regardless of
/// where raft has since placed it. That is a second live coordinator waiting on
/// the next reboot, which is precisely the exactly-one invariant this relay
/// exists to hold.
async fn start_headscale(state: &Arc<ServerState>) {
    let spec = headscale_appliance::appliance_spec(&state.headscale_dir);

    if let Some(backend) = state.active_backend() {
        // Release :443/:80 and the boot-persistence bit before kamaji forks its
        // own copy. A no-op on a node that never ran the systemd path.
        systemctl(&["disable", "--now", "headscale"]);

        // R599-F12's rule for a NATIVE workload: hand kamaji this node's own
        // mesh address, never an `alloc_mesh_ip()` one. A fork+exec'd process
        // has no namespace of its own, so a per-workload address would simply
        // fail to bind — and the node address is what makes the appliance
        // reachable from another node, which is the whole premise of R591-T2's
        // follow-placement ingress. `None` (a dev host, `0.0.0.0`) keeps the
        // loopback bind.
        let mesh_ip = state
            .node_mesh_ip()
            .unwrap_or(std::net::Ipv4Addr::LOCALHOST);
        let mesh = crate::mesh::MeshAssignment::inlined(mesh_ip);
        match backend.deploy_workload(&spec, &mesh).await {
            Ok(result) => {
                info!(
                    pid = result.task_pid,
                    mesh_ip = %mesh_ip,
                    "headscale appliance deployed under kamaji supervision"
                );
                // R591-T2: publish the placement so every front door can find
                // it. `leader.rs` deploys straight through the backend rather
                // than through `POST /workloads/deploy`, so it must upsert the
                // record the HTTP handler would have — without this the
                // appliance runs but `GET /service-records` never mentions it,
                // and an ingress proxy has nothing to follow.
                state
                    .service_records
                    .upsert_deployed(&spec, result.mesh_ip, &result.container_id);
                return;
            }
            Err(e) => warn!(
                "kamaji refused the headscale appliance ({e:#}) — reverting to the \
                 headscale.service systemd unit"
            ),
        }
    } else {
        warn!(
            "no kamaji backend attached — starting headscale via systemd (unsupervised by \
             kamaji; see R591-F1)"
        );
    }

    if systemctl(&["enable", "--now", "headscale"]) {
        info!("headscale started via systemd");
    } else {
        warn!("systemctl start headscale failed — may already be running or systemd unavailable");
    }
}

/// Stop the headscale appliance on this node (R591-F1).
///
/// Tears down through kamaji when a backend is attached, **and** disables the
/// systemd unit. Both, not either: on a node mid-rollout the appliance may have
/// been started by the other path, and the invariant this relay defends is
/// *exactly one live headscale in the cluster*. A second one left running on a
/// node that has lost leadership serves a diverging copy of the DB to whichever
/// nodes still resolve to it. Stopping something that was never started is a
/// no-op in both paths, so over-stopping costs nothing and under-stopping costs
/// correctness.
async fn stop_headscale(state: &Arc<ServerState>) {
    let ident = headscale_appliance::appliance_ident();

    // R591-T2: retract FIRST, and unconditionally. A front door that keeps
    // discovering this node after it has lost the appliance sends every mesh
    // client to a coordinator that is about to stop — the retraction is the
    // half of follow-placement that makes the *old* address stop answering,
    // and it must not be conditional on a backend that may not be attached.
    state.service_records.retract(&ident);

    if let Some(backend) = state.active_backend() {
        match backend.teardown_workload(&ident).await {
            Ok(()) => info!("headscale appliance torn down on leadership loss"),
            Err(e) => warn!("kamaji teardown of the headscale appliance failed: {e:#}"),
        }
    }

    // `disable` as well as stop — see `start_headscale`: a still-enabled unit on
    // a node that no longer owns the appliance resurrects it at the next boot.
    systemctl(&["disable", "--now", "headscale"]);
    info!("headscale stopped on leadership loss");
}

/// Run `systemctl <args>`, reporting whether it succeeded. Never panics and
/// never propagates: a non-systemd host (a test, a Mac, a container) is an
/// expected environment for this daemon, and a failed transition must not take
/// the leadership watcher down with it.
fn systemctl(args: &[&str]) -> bool {
    std::process::Command::new("systemctl")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Best-effort: derive a human-readable machine name for the ingress-owner
/// claim.  Reads `/etc/hostname` (Linux cloud VMs), then falls back to the
/// `HOSTNAME` env var.
fn derive_machine_name() -> Option<String> {
    if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
        let name = s.trim().to_string();
        if !name.is_empty() {
            return Some(name);
        }
    }
    std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty())
}
