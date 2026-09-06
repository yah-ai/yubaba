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
//!
//! @yah:ticket(R858-T3, "Appliance ownership must not be raft leadership: pick from eligible candidates, retry on refusal, fail loudly")
//! @yah:status(review)
//! @yah:at(2026-09-05T20:06:24Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:next("Tier: Warrior — the retry/re-election logic is easy to write in a way that flaps, and the test that proves it must kill a node rather than mock a refusal.")
//! @yah:gotcha("headscale IS NOT SCHEDULED — the affinity/taint framing does not apply to it. leader.rs::start_headscale builds the spec in Rust and deploys straight through the backend, bypassing POST /workloads/deploy, placement, and the manifest. So there is no candidate list, no retry, and no other node ever tries: ONE attempt on whoever won leadership, and every failure path is warn! + continue (kamaji refuses -> warn -> fall back to systemd -> unit does not exist -> warn -> done). That silence is why R858 ran 37 hours with the public site green.")
//! @yah:next("FOUR CHANGES, MOST VALUABLE FIRST. (1) OWNERSHIP != LEADERSHIP: IngressOwnership (cluster_policy.rs:367) gains a variant that elects the appliance owner from an ELIGIBILITY SET rather than aliasing raft leadership. Coupling them is what let a routine POST /raft/transfer-leader decapitate the mesh. (2) TRY THE CANDIDATES: a deploy failure marks that node ineligible and re-elects the owner. Reuse scheduler.rs's decide_transfer / NodeEligibility shape rather than inventing a second one — it already encodes \"live, admits, warm, not the current owner\". (3) REFUSE LOUDLY: today on_became_leader writes SetIngressOwner and THEN deploys, so a node that cannot deploy still claims ownership and `yah mesh status` reports an owner that is not serving. Claim only on a successful deploy; a leader that cannot stand up the appliance it just claimed must surface unhealthy, not warn!. (4) NO PRIORITY CLASS NEEDED: there is no priority or preemption concept in workload-spec (TierTag(\"infra\") is the native-exec admission gate, SlaTier in scheduler.rs is tenant SLA), and this does not need one — LifecycleArchetype::Appliance is already pinned and non-drainable, so Appliance + a requires-taint capability + the eligibility set gives \"always placed somewhere eligible, never drained\" without a new concept.")
//! @yah:handoff("CHANGES 1-4 WERE ALREADY LANDED (commit 4bed91fe, @Glimmerstone): IngressOwnership::ElectedFromEligible + ClusterPolicy::fleet() switched to it (cluster_policy.rs:397, :642), appliance_ownership.rs (decide_owner / OwnerElection / judge_appliance_candidate / ApplianceHealth, reusing scheduler.rs's NodeEligibility verbatim), claim-on-success-only via ApplianceStartError (leader.rs:753), and change 4 answered in prose at self_eligibility(). What was NOT done, and what this pass did, is make that machinery actually reachable and restart-safe.")
//! @yah:handoff("DEFECT 1, THE OPERATOR'S CRITERION: ownership was read from PROCESS MEMORY (OwnerElection::health, a stack frame), never from the replicated `ingress_owner`. So every restarted yubaba saw a vacancy and elected itself — on the coordinator that is `systemctl disable --now headscale` + a kamaji re-place + a litestream restore over a live DB; on any other node it is a second coordinator. FIX: new appliance_ownership::owner_status(recorded, this_node, local_running, local_health) reads the record first and process memory only as fallback, plus leader.rs::recorded_owner() bridging ingress_owner -> node id via R859-F2's node_for_machine. `serving` is MEASURED where it can be (new leader.rs::observe_local_appliance asks this node's own kamaji via get_workload) and assumed only for a remote owner.")
//! @yah:handoff("DEFECT 2: decide_owner treated an owner ABSENT from the candidate map as INELIGIBLE (`candidates.get(&o.node).is_some_and(...)`). leader.rs's candidate set is `{self}` by construction, so on every non-owner node the owner is absent — meaning absence of evidence was read as a verdict and each node elected itself. FIX: move only on POSITIVE evidence the owner is broken; silence leaves it where it is. This is literally the correction leader_pin::decide took under R734-T4 (PinDecision::LeaderRegionUnknown — act only on positive evidence about both ends), for the same reason: an unjudgeable peer is what a RESTART looks like, so reading it as a verdict manufactures churn out of an anti-churn mechanism.")
//! @yah:handoff("DEFECT 3, DISCOVERED WHILE VERIFYING AND IT MADE CHANGE (2) DEAD CODE: the watcher only evaluated ownership on an `is_leader` EDGE — which is the ownership==leadership coupling wearing a different hat. Two consequences, both provable. (a) THE RETRY COULD NEVER FIRE: OwnerElection backs a failed node off for BACKOFF_BASE_SECS=30 so a fixed node is re-electable, but nothing re-evaluated when that expired, so 'the next eligible candidate is elected' only happened if raft HAPPENED to hold another election. (b) AN OWNER-OF-RECORD WITH A DEAD APPLIANCE STAYED DEAD — a non-leader owner gets no edge at all. That is precisely the shape a fleet roll produces, since FollowersFirstLeaderLast drains the leader BEFORE restarting it, so the owner necessarily comes back as a follower. FIX: leader.rs::reconcile_appliance_ownership on a RECONCILE_INTERVAL=10s clock (10s vs the 30s backoff floor; deliberately NOT derived from RaftTiming — nothing here is an election). A follower may restart what it is already recorded as owning; only a leader may claim a vacancy (SetIngressOwner needs the leader). The edge keeps only the teardown, which is the one genuinely edge-shaped action.")
//! @yah:handoff("TWO SMALLER FIXES IN THE SAME PASS. (a) ADOPT, DON'T REDEPLOY: on OwnerServing(self) the node re-asserts its SERVICE RECORD from the observed WorkloadState instead of restarting the appliance. ServiceRecords is in-memory and genuinely does die with the process, so without this the appliance runs while GET /service-records denies it exists and every front door following the record sends mesh clients nowhere (R591-T2). (b) ONE MACHINE-NAME DERIVATION: leader::spawn and on_became_leader now TAKE the machine name instead of each calling derive_machine_name(); main.rs derives once and hands the same value to leader::spawn and member_registration::spawn. R859-F2's whole guarantee is that ingress_owner and MemberInfo::machine are comparable — two calls to one function is a convention, one value is a fact. recorded_owner also compares the record against this node's own name DIRECTLY rather than through the member map, because a just-restarted daemon may re-win leadership before member_registration republishes its row, and the map hop would yield None -> 'vacant' -> redeploy a healthy coordinator. Every roll restarts the owner, so that race is the last step of every roll, not a corner case.")
//! @yah:handoff("FILES: oss/yubaba/crates/yubaba/src/{appliance_ownership.rs,leader.rs,main.rs}; NEW oss/yubaba/crates/yubaba/tests/raft_appliance_ownership.rs (+ registered in tests/testing.rs — autotests=false, an unregistered file runs nowhere); oss/yubaba/crates/yubaba-test-harness/src/lib.rs (ClusterNode gains `state` + `headscale_dir`, new Cluster::server_state(idx) / headscale_dir(idx), both rebuilt by restart_node; headscale_dir redirected into each node's tempdir instead of the on-host /var/lib/yah-cloud/headscale default). NOT COMMITTED and NOTHING ROLLED — no live node was touched. oss/yubaba/crates/yubaba/src/lib.rs was NOT edited: the machine name travels as a spawn parameter specifically to keep this ticket out of R861/@Glimmerstone's file.")
//! @yah:gotcha("THE 0.8.33 ROLL IS SAFE FOR THE APPLIANCE **ONLY IF THE WAVE DOES NOT `POST /raft/transfer-leader` AT us-west-001**, and that is an operator step this ticket cannot enforce. Reasoning, each leg read from code: (1) T3 runs the NEW binary's rules, but a drain executes on the binary ALREADY INSTALLED — west is on 0.8.32 with ingress_ownership: FollowsRaftLeader, so a transfer-leader off west still tears headscale down exactly as on 2026-09-03. Nothing in 0.8.33 can prevent that; it is the old code running. (2) A PLAIN RESTART IS SAFE, and this is the load-bearing fact: NO shutdown path in main.rs or leader.rs calls on_lost_leader or stop_headscale — all three call sites are inside the leadership/reconcile paths — so stopping yubaba leaves kamaji supervising headscale, and the restarted 0.8.33 adopts it on its first tick. (3) So: roll us-west-001 by restarting yubaba WITHOUT the drain. The FollowersFirstLeaderLast drain exists to avoid a leaderless window, not to protect the appliance; skipping it on west costs one election and saves an outage. (4) If a drain does happen anyway, recovery is now AUTOMATIC rather than manual — west comes back as a follower, sees the record still names it, and restarts the appliance on the reconcile tick (this is the a_follower_that_owns... test). Outage bounded by west's restart + one 10s tick, not 37 hours.")
//! @yah:assumes("ONE UNVERIFIED PRECONDITION, WITH THE READ-ONLY CHECK THAT SETTLES IT. recorded_owner resolves ANOTHER node's ownership through MemberInfo::machine (R859-F2). I could not verify that the DEPLOYED 0.8.32 populates that field — checking means reading a live node, which this ticket is scoped out of. If it is absent, a new leader cannot resolve `ingress_owner` to a node id and falls back to its own (empty) health, which under change (3) means it tries to start the appliance, fails loudly on us-south-001 (no --native-exec-dir, R858-T4), claims nothing, and backs off — so the failure mode is a loud refusal rather than a silent theft, but it is not the intended path. THE CHECK IS ONE READ-ONLY CURL: `GET /raft/status` on any voter, look for members.<west's node id>.machine being non-null. Note this does NOT affect west protecting its own appliance — recorded_owner compares the record to this node's own machine name directly, no member row needed.")
//! @yah:verify("THREE INTEGRATION TESTS, EACH FALSIFIED AGAINST THE EXACT CHANGE IT COVERS — oss/yubaba/crates/yubaba/tests/raft_appliance_ownership.rs, real 3-node openraft on loopback, real leader::spawn + member_registration::spawn on every node, kamaji FakeRuntime. (1) a_yubaba_restart_on_the_owner_leaves_the_appliance_in_place — THE OPERATOR'S CRITERION. Probe: make recorded_owner return None (pre-fix local-memory-only). FAILS in 2.35s with 'the appliance was torn down after a yubaba restart on its owner (test-node-1)'. (2) transferring_raft_leadership_does_not_move_the_appliance — the literal 2026-09-03 POST /raft/transfer-leader, and the call `yah cloud rollout yubaba` makes. Probe: restore decide_owner's `None => {}` arm. FAILS in 2.53s with 'the appliance was torn down by a raft leadership transfer to node 2'. (3) a_follower_that_owns_the_appliance_restarts_it_without_a_leadership_change — the roll hole. Probe: gate reconcile on is_leader. FAILS in 47.79s with 'timed out after 45s waiting for the follower that owns the appliance to restart it on its own clock'. NON-VACUITY IS BUILT IN for (1) and (2): FaultTarget::DeployWorkload is armed BEFORE the disruption, and leader.rs answers a failed start by tearing down, so 'still Running at the end' asserts that NO NODE ATTEMPTED A START rather than that nothing was observed.")
//! @yah:verify("cargo test -p yubaba --lib = 739 passed / 0 failed (23 in appliance_ownership, 5 new: an_owner_absent_from_the_candidate_map_is_unjudged_and_keeps_the_appliance, positive_evidence_still_moves_ownership_off_a_dead_owner, a_restarted_owner_reading_its_own_record_does_not_restart_the_appliance, a_new_raft_leader_does_not_take_the_appliance_from_the_recorded_owner, a_record_naming_this_node_over_a_stopped_appliance_re_elects, without_a_record_the_local_health_is_the_fallback). cargo test -p yubaba --test main = 64 passed / 0 failed. cargo test -p yubaba --features testing --test testing = 24 passed / 0 failed / 1 pre-existing ignored. cargo clippy -p yubaba --features testing --lib --bins --tests: ZERO findings on leader.rs, appliance_ownership.rs or the new test (crate-wide warnings are pre-existing and on files this ticket did not touch). rustfmt applied to the 5 changed files ONLY — `cargo fmt -p yubaba` would have reformatted a peer's dirty acme_issuer.rs, so it was not run.")
//! @yah:gotcha("A FULL-PARALLELISM `cargo test -p yubaba --test main` FAILS 10 TESTS ON THIS MACHINE AND IT IS LOAD, NOT A REGRESSION — do not chase it. All 10 fail with 'nodes never agreed on a leader; last per-node current_leader was [None, None, None]' in raft_member_registration / raft_membership_loop / raft_quorum_geography. Attributed two ways: they all pass at --test-threads 2 (16/0) and the whole binary passes at --test-threads 4 (64/0); and structurally they use solo_node*, which this ticket did not touch — the harness edits are confined to test_cluster_local / restart_node / ClusterNode, and solo_node builds no ClusterNode. 64 default-parallel tests each standing up 3-5 raft nodes on one contended camp machine is the cause. Use --test-threads 4.")
//!
//! @yah:ticket(R858-T8, "The rehearsal: power off the owner, prove the HA-singleton takes over on the sovereign group")
//! @yah:at(2026-09-04T20:47:59Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:next("Tier: Warrior — this is the acceptance test the whole relay exists to pass, and it is easy to run in a way that proves less than it appears to.")
//! @yah:gotcha("THE OPERATOR'S SEQUENCE IS (a) stand up headscale, (b) POWER OFF that node, (c) watch it take over elsewhere in the sovereign group. Power-off, not a graceful drain — that distinction is the whole value of the test, because every retraction and teardown path in the codebase assumes a graceful exit (R858-T7). A rehearsal done with `systemctl stop` or a leadership transfer proves the happy path and skips the one this relay exists for. Do not substitute it.")
//! @yah:assumes("That the bottleneck is data transfer. It is NOT, and the expectation is worth correcting before anyone tunes the wrong thing: headscale.db measured 94 KB on 2026-09-04 (plus an 8.4 MB WAL), and roadcase's measured cold-start rate is 3.3 s per 100 MB — so hydration from R2 is sub-second. The dominant term is FAILURE DETECTION (the lease hysteresis dwell), followed by client reconvergence, which is tailscaled's backoff and not ours to tune. Budget the rehearsal accordingly.")
//! @yah:next("DO THE PRACTICE RUN ON THE DEV CLUSTER FIRST (us-west-011/013/014) — R591-T2 and T3 both name it as the sanctioned testbed and the operator sanctions blowing that mesh away. The prod rehearsal on us-west-001 is worth doing afterwards because it is the only place the real DNS, the real cert path and the real client population exist, but going there first means debugging a 10-step sequence with the fleet's mesh as collateral.")
//! @yah:verify("The rehearsal passes only if an ALREADY-REGISTERED node reaches the tailnet through the new coordinator without re-registering — that is what proves step 7 carried the identity. A freshly joined node proves nothing, because a brand-new headscale with a fresh noise key accepts new registrations happily while every existing node's stored server identity mismatches. Also assert the OLD node cannot serve after power is restored (step 3), which is the failure that is worse than the outage.")
//! @yah:gotcha("THE FULL SEQUENCE, WITH OWNERS — the operator named three steps (fetch app data, pull the R2 backup, reroute ingress) and those are real, but they are steps 5/6/9 of ten. (1) DETECT the node is gone — crate::lease_detector hysteresis + the raft channel; exists for tenant placement, not wired to appliance ownership [R858-T3]. (2) EXPIRE the dead owner's records — nothing retracts on a power-off [R858-T7]. (3) FENCE the old owner so a resurrected node cannot serve [R858-T7]. (4) ELECT a new owner from eligible candidates [R858-T3]. (5) CONFIRM target readiness — headscale binary present, kamaji native-exec [R858-T4]. (6) HYDRATE the DB from R2 [R858-S6, hydration half]. (7) MATERIALIZE noise_private.key or every existing node rejects the new server [R858-T2]. (8) START and gate on procctl Ready, not a bound port [R860/W338]. (9) REPOINT the front doors — and note R858-T1's blocker, a remote door currently cannot discover which node holds the appliance at all. (10) CLIENTS RECONVERGE — tailscaled backoff, not ours, but a real term in time-to-usable.")
//! @yah:verify("CONFIRM FIRST WHETHER /health TOUCHES THE DATABASE — not established, and it changes how much the probe is worth. If it only reports that the HTTP server is up, it returns `pass` on a coordinator serving an empty or half-restored DB, which is the other post-failover false green. Cheap test on the dev cluster: move the db file aside (or point config at a nonexistent path), restart, and see whether /health still says pass. If it does, the readiness gate for step 8 needs to be a real query — an Exec probe running a `headscale nodes list` against the unix socket at /var/lib/yah-cloud/headscale/headscale.sock would do it — rather than an HttpGet.")
//! @yah:gotcha("DO NOT TRUST /health AS THE FAILOVER GATE — it cannot see the failure that matters most. headscale's `GET /health` returns 200 {\"status\":\"pass\"} (measured on v0.23.0, 2026-09-04), and it would return exactly that on a headscale that came up with a FRESH noise_private.key: the HTTP server is serving fine, it simply rejects every already-registered node. That is the R858-T2 failure, it is the single most likely way this rehearsal produces a false green, and no readiness probe can catch it. It is the reason this ticket's sign-off criterion is \"an ALREADY-REGISTERED node reaches the tailnet without re-registering\" rather than anything the coordinator says about itself.")
//! @yah:notify_on(R858-T7, "R858-T7 landed EXPIRE + FENCE, which are your steps (2) and (3). Read T7's handoff before planning the run — it answers \"is the rehearsal runnable on dev\" explicitly and the answer is NOT YET, with the blockers named in order. Two things to take from it. (1) SPLIT THE REHEARSAL: the OWNERSHIP half (power off the owner, a survivor expires the record and claims it, power restored, the old node cannot serve) is decidable WITHOUT R858-T2 or R858-T5, because it does not care whether the new coordinator's DB is any good — only who may serve. Run that first; it is the half never demonstrated on hardware. The full criterion (\"an ALREADY-REGISTERED node reaches the tailnet without re-registering\") needs T2's noise key and T5's proven restore and must not be attempted before them. (2) STEP ZERO IS A ROLL: T3+T7 are local source only; us-west-011/013/014 run a binary with neither, so nothing in T7 is live until they are rolled. Also: T7's own \"LIVE HAZARD — systemctl disable headscale before the rehearsal\" gotcha is already satisfied on us-west-001 (measured disabled 2026-09-05 by @Ashguard:libra; yubaba disables the unit itself whenever it takes the appliance under kamaji) — re-check, but do not plan a manual step around a bit that is already clear.")

use std::collections::BTreeMap;
use std::sync::Arc;

use openraft::async_runtime::watch::WatchReceiver;
use tracing::{debug, error, info, warn};

use kamaji::sibling::KamajiSibling;

use crate::appliance_ownership::{
    decide_owner, judge_appliance_candidate, judge_self_fence, owner_lease_expired, owner_status,
    ApplianceCandidate, ApplianceHealth, FenceTiming, NativeExecCapability, OwnerElection,
    OwnershipDecision, SelfFence,
};
use crate::lease_detector::Confirmed;
use crate::raft::{YubabaNodeId, YubabaRaft, YubabaRequest};
use crate::scheduler::NodeEligibility;
use crate::secrets::ClusterResolver;
use crate::ServerState;
use crate::{headscale_appliance, headscale_state, litestream};

/// Spawn the leadership watcher.  The returned `JoinHandle` can be aborted on
/// daemon shutdown, but the watcher will also exit on its own when the raft
/// metrics channel closes.
///
/// `machine` is this node's machine name — the string written into
/// `ingress_owner`. It is a **parameter** rather than a
/// [`derive_machine_name`] call inside, for the reason R859-F2 gives for the
/// member row carrying the same value: `ingress_owner` and
/// [`MemberInfo::machine`](crate::raft::MemberInfo::machine) are only comparable
/// if they are one derivation, and two independent calls to the same function
/// is a convention, not a guarantee. The caller derives once and hands the same
/// value to both spawns. It also lets a test give each in-process node a
/// distinct identity, which `/etc/hostname` cannot.
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state: Arc<ServerState>,
    machine: Option<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state, machine).await;
    })
}

async fn run(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state: Arc<ServerState>,
    machine: Option<String>,
) {
    let mut watch = raft.metrics();
    let mut prev_is_leader = false;
    let mut watcher = ApplianceWatcher::new();

    loop {
        let view = {
            let metrics = watch.borrow_watched();
            RaftView {
                is_leader: metrics.current_leader == Some(node_id),
                has_leader: metrics.current_leader.is_some(),
            }
        };
        let is_leader = view.is_leader;

        if is_leader != prev_is_leader {
            info!(node_id, is_leader, "raft leader state changed");
            // R118-T9: whether the cluster's *external* identity rides along
            // with raft leadership is a policy decision, not a property of
            // leadership. A cluster whose clients are all inside the mesh has
            // no external identity to move, and coupling gateway election to
            // consensus election lets a flaky uplink churn leadership.
            let ownership = state.cluster_policy.ingress_ownership;
            if ownership.follows_raft_leader() {
                if is_leader {
                    // The legacy coupling, kept working for an appliance that
                    // genuinely wants it. Even here the claim is now
                    // conditional — a failure is a failure under every policy.
                    if let Err(e) = on_became_leader(node_id, &raft, &state, machine.clone()).await
                    {
                        error!(node_id, "appliance did not start on the new leader: {e}");
                        watcher
                            .election
                            .record_failure(node_id, unix_now_secs(), e.to_string());
                    } else {
                        watcher.election.record_success(node_id);
                    }
                } else {
                    on_lost_leader(&state).await;
                }
            } else if ownership.elects_from_eligibility_set() {
                // The only edge-shaped half; everything else is the tick below.
                if !is_leader {
                    on_leadership_loss_under_election(
                        node_id,
                        &state,
                        &watcher.election,
                        machine.as_deref(),
                    )
                    .await;
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

        // R858-T3: under an elected owner, ownership is evaluated on a CLOCK as
        // well as on leadership edges — see `reconcile_appliance_ownership` for
        // why an edge-only watcher cannot deliver this ticket's own retry rule.
        if state
            .cluster_policy
            .ingress_ownership
            .elects_from_eligibility_set()
        {
            reconcile_appliance_ownership(node_id, view, &raft, &state, &mut watcher, machine.clone())
                .await;
        }

        tokio::select! {
            changed = watch.changed() => {
                if changed.is_err() {
                    warn!("raft metrics watch closed — leader watcher exiting");
                    break;
                }
            }
            _ = tokio::time::sleep(RECONCILE_INTERVAL) => {}
        }
    }
}

/// How often appliance ownership is re-evaluated independently of raft events.
///
/// Ten seconds, chosen against [`BACKOFF_BASE_SECS`]: the minimum deploy-failure
/// backoff is 30 s, so a recovered node is picked up within a third of the
/// window it was excluded for — prompt without turning the ledger's pacing into
/// a suggestion. It is deliberately *not* derived from `RaftTiming`: nothing
/// here is an election, and pacing an appliance's reconciliation at consensus
/// speed is the coupling this ticket removes.
const RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// One tick's snapshot of this node's raft leadership view.
///
/// Two booleans rather than one, because R858-T3 and R858-T7 ask different
/// questions of the same metric and conflating them is a real bug: `is_leader`
/// is *authority* (only a leader may write `SetIngressOwner`), `has_leader` is
/// *freshness* (a node in contact with a leader is receiving `AppendEntries`, so
/// its applied `ingress_owner` is at most one replication round behind, while a
/// node with none can conclude nothing from its own applied state however
/// recently it read it). A follower has the second without the first, and the
/// fence turns on exactly that distinction.
#[derive(Debug, Clone, Copy)]
struct RaftView {
    is_leader: bool,
    has_leader: bool,
}

/// The leadership watcher's own state, held for the life of the process.
///
/// Both fields exist because a *stack frame* is the wrong place for them and a
/// fresh one on every tick would silently disable the mechanism it belongs to —
/// grouped so that stays one idea rather than two parameters.
struct ApplianceWatcher {
    /// R858-T3: the failure ledger and health verdict. Kept across leadership
    /// changes so a node that failed a deploy is still in backoff on the next
    /// one rather than starting fresh.
    election: OwnerElection,
    /// R858-T7: when this node last CONFIRMED, from replicated state it had
    /// reason to believe was current, that it is the recorded appliance owner.
    ///
    /// Seeded at `now` rather than at "never", which grants a starting daemon
    /// one full [`FenceTiming::self_fence_after`] to establish its claim before
    /// the fence fires. A node that boots with a `systemctl enable`d headscale
    /// already serving therefore gets a grace window to discover it is the
    /// legitimate owner — and, if it is not, stops within one window instead of
    /// serving forever.
    ownership_confirmed_at: std::time::Instant,
}

impl ApplianceWatcher {
    fn new() -> Self {
        Self {
            election: OwnerElection::new(),
            ownership_confirmed_at: std::time::Instant::now(),
        }
    }
}

/// What a raft leadership *change* means under
/// [`IngressOwnership::ElectedFromEligible`](crate::cluster_policy::IngressOwnership::ElectedFromEligible)
/// — which is, in the common case, **nothing** (R858-T3).
///
/// This is the half that would have prevented the 2026-09-03 outage on its own.
/// us-west-001 was serving the coordinator perfectly when a routine
/// `POST /raft/transfer-leader` ran, and it tore headscale down because the old
/// rule said the leader owns the ingress. Nothing about the appliance had
/// changed. Under this variant a serving node keeps serving: ownership moves on
/// owner *failure*, and a leadership transfer is not a failure.
///
/// A node that is **not** serving still tears down on leadership loss — that is
/// not stickiness, it is cleanup of anything a `FollowsRaftLeader`-era start (or
/// a failed attempt) left behind, and over-stopping is free while
/// under-stopping costs the exactly-one invariant.
///
/// Everything *else* an ownership decision involves happens in
/// [`reconcile_appliance_ownership`], on a clock. Only the teardown lives here,
/// because only the teardown is genuinely edge-shaped: it is a response to a
/// transition, not to a state.
async fn on_leadership_loss_under_election(
    node_id: YubabaNodeId,
    state: &Arc<ServerState>,
    election: &OwnerElection,
    machine: Option<&str>,
) {
    let recorded = recorded_owner(state, node_id, machine);
    let running_here = observe_local_appliance(state).await.is_some();
    let owner = owner_status(recorded, node_id, running_here, election.health());

    // Serving per the record OR per this process's memory — either is a reason
    // not to tear the coordinator down for a leadership change.
    if owner.is_some_and(|o| o.node == node_id && o.serving)
        || matches!(election.health(), ApplianceHealth::Serving(_))
    {
        info!(
            node_id,
            "lost raft leadership while serving the appliance — ownership is elected, not \
             inherited from leadership (R858-T3); the appliance stays up"
        );
        return;
    }
    on_lost_leader(state).await;
}

/// Bring this node's appliance state in line with who the cluster says owns it.
///
/// # Why this runs on a clock and not only on leadership edges
///
/// The pre-existing watcher evaluated ownership only when `is_leader` flipped,
/// which is the coupling this ticket removes wearing a different hat — and it
/// made two of R858-T3's own mechanisms unreachable:
///
/// - **The retry never fires.** [`OwnerElection`] backs a failed node off for
///   [`BACKOFF_BASE_SECS`](crate::appliance_ownership::BACKOFF_BASE_SECS) = 30 s
///   so that a fixed node becomes a candidate again. On an edge-only watcher
///   nothing re-evaluates when that backoff expires, so "the next eligible
///   candidate is elected" only ever happened if raft *happened* to hold another
///   election. A retry rule whose trigger is a coincidence is not a retry rule.
/// - **An owner-of-record with a dead appliance stays dead.** A node that is
///   named in `ingress_owner` but is not the leader gets no edge at all, so
///   nothing notices the appliance is gone. That is exactly the shape a fleet
///   roll produces: the leader is drained *before* it is restarted, so the owner
///   comes back as a follower — and a follower that only wakes on leadership
///   changes never looks.
///
/// # A follower may restart what it already owns; it may not claim what it does
/// not
///
/// Writing `SetIngressOwner` needs the leader, so *taking* ownership is still
/// leader-only. Re-starting an appliance this node is **already recorded as
/// owning** is not taking anything — the record already says so — and refusing
/// to do it on a follower would leave the coordinator down for exactly as long
/// as it took some unrelated election to happen.
///
/// # The candidate set is `{self}` plus, on a leader, a *dead* owner
///
/// [`decide_owner`] takes the whole fleet and is tested on it. This call site
/// still offers only one node it could actually deploy to — itself — because
/// `leader.rs` deploys straight through *its own* backend and there is no
/// "ask a peer to deploy" channel (see this module's R858-T3 `@yah:gotcha`).
///
/// R858-T7 added the one other entry that is decidable from here: the recorded
/// owner, when this node is the leader **and** the node-lease channel says that
/// owner has been silent past [`FenceTiming::expire_after`]. It is never a
/// candidate to *win* — it is inserted as `Confirmed::Down` precisely so it
/// loses — it is there to be the positive evidence [`decide_owner`] requires
/// before moving off an owner at all.
///
/// That distinction is the whole reason a *dead* owner can now be replaced while
/// a merely *unjudgeable* one still cannot: absence from this map continues to
/// mean "nothing is known", and a yubaba restart continues to leave a healthy
/// coordinator alone. See [`decide_owner`]'s doc; that rule and this call site's
/// narrowness are one design, not two.
///
/// # And it fences before it does any of that (R858-T7)
///
/// The first thing this function does is ask whether **this** node may go on
/// serving an appliance it is currently running, and it asks before the
/// `may_act` early return — because the node that most needs stopping is
/// precisely one with no standing to act. See [`judge_self_fence`].
///
/// # The owner comes from replicated state, not from this process's memory
///
/// [`OwnerElection`]'s health is a stack frame. It is empty on a freshly
/// started yubaba, so deriving the owner from it alone makes every restart look
/// like a vacancy — and a vacancy is something this node elects itself into.
/// That is the operator's rehearsal failing on the *first* step: restart yubaba
/// on the coordinator and the appliance is torn down and redeployed.
///
/// So the owner is read through [`owner_status`] from `ingress_owner`, which is
/// replicated, survives the restart, and (since change 3) is written only after
/// a successful start. Local memory is the fallback, not the source.
async fn reconcile_appliance_ownership(
    node_id: YubabaNodeId,
    view: RaftView,
    raft: &YubabaRaft,
    state: &Arc<ServerState>,
    watcher: &mut ApplianceWatcher,
    machine: Option<String>,
) {
    let RaftView {
        is_leader,
        has_leader,
    } = view;
    // The record survives this process; `election.health()` does not. Ask the
    // supervisor as well, since a record naming *this* node is the one case
    // with local evidence available.
    let recorded = recorded_owner(state, node_id, machine.as_deref());
    let running_here = observe_local_appliance(state).await;
    let timing = FenceTiming::from_thresholds(state.cluster_policy.liveness_thresholds());

    // ── R858-T7, FENCE ───────────────────────────────────────────────────────
    //
    // Runs FIRST, and before `may_act`, and both of those are the point.
    //
    // Before `may_act`, because the node this has to stop is precisely a node
    // with no standing to act: not the leader, not the recorded owner, and
    // therefore returned early by every version of this function before T7. A
    // resurrected us-west-001 whose ownership has already moved to south is
    // exactly that node — it fell straight through the early return while its
    // headscale went on answering `cloud.mesh.yah.dev`.
    //
    // First, because a node that must not be serving must also not be electing.
    let confirmed_now = has_leader && recorded == Some(node_id);
    if confirmed_now {
        watcher.ownership_confirmed_at = std::time::Instant::now();
    }
    let unconfirmed_for = (!confirmed_now).then(|| watcher.ownership_confirmed_at.elapsed());

    if let SelfFence::Stop(reason) = judge_self_fence(
        recorded,
        node_id,
        running_here.is_some(),
        unconfirmed_for,
        timing,
    ) {
        error!(
            node_id,
            fence = reason.as_str(),
            ?reason,
            "FENCED: stopping the appliance on this node. Two live coordinators on one tailnet \
             serve diverging copies of the node database to whichever clients still resolve to \
             each — the failure that is worse than the outage (R858-T7)"
        );
        // `on_lost_leader`, not a bare stop: a fenced node must also stop
        // replicating, or it goes on pushing frames from a losing database into
        // the shared litestream replica the new owner restores from.
        on_lost_leader(state).await;
        watcher.election.record_fenced(&reason);
        return;
    }

    let election = &mut watcher.election;
    let owner = owner_status(recorded, node_id, running_here.is_some(), election.health());

    // Only the leader may claim a vacancy; any node may restart what it is
    // already recorded as owning. A follower with neither has nothing to do —
    // and, importantly, nothing to *say*: reaching the refusal arms below on
    // every tick of every follower would turn this ticket's loud channel into
    // the noise operators learn to skip.
    let may_act = is_leader || recorded == Some(node_id);
    if !may_act {
        return;
    }

    let now = unix_now_secs();
    let mut candidates = BTreeMap::from([(
        node_id,
        election.candidate(
            node_id,
            self_eligibility(),
            // R858-T4: a real probe of this node's kamaji and the appliance
            // binary, replacing the permissive `Unknown` placeholder T3 left.
            probe_native_exec(state).await,
        ),
    )]);

    // ── R858-T7, EXPIRE ──────────────────────────────────────────────────────
    //
    // This is the widening `reconcile_appliance_ownership`'s own doc predicted:
    // "R858-T7 has to plumb both to expire a dead owner's records; when it does,
    // widening this is building a larger `BTreeMap` here and nothing else."
    //
    // The owner enters the map on **positive evidence that it is gone, and on
    // nothing else** — not merely because it is remote, and not because it is
    // unjudgeable. `decide_owner` reads an absent owner as unmoved on purpose,
    // and an entry added on any weaker basis converts that anti-churn rule into
    // a churn generator on every node that cannot see its peers.
    //
    // It is also leader-only, and deliberately narrower than `may_act`: a
    // follower has no `SetIngressOwner` to write, so all it could do with an
    // expiry verdict is disagree loudly with the leader about a node neither can
    // reach.
    let expired_owner = owner
        .map(|o| o.node)
        .filter(|&n| n != node_id)
        .filter(|&n| {
            is_leader
                && owner_lease_expired(
                    state.lease_detector.as_ref().and_then(|d| d.silence(n)),
                    timing,
                )
        });
    if let Some(dead) = expired_owner {
        error!(
            node_id,
            owner = dead,
            expire_after_secs = timing.expire_after.as_secs(),
            "the recorded appliance owner has stopped renewing its node lease past the expiry \
             deadline — treating the ownership record as stale and re-electing (R858-T7). It has \
             been silent for longer than its own self-fence deadline, so it has stopped serving \
             or it is not running."
        );
        // Projected onto the one readiness vocabulary this crate has, so
        // `judge_appliance_candidate` refuses it as `not-live` rather than
        // through a second predicate. `Down` rather than `None`: this is a
        // measured verdict, and `None` would read as "never confirmed", which
        // `judge_readiness` refuses for a different reason and which would make
        // the log line lie about what was established.
        candidates.insert(
            dead,
            ApplianceCandidate {
                node: NodeEligibility {
                    liveness: Some(Confirmed::Down),
                    raft_peer_healthy: false,
                    region: None,
                    admits: false,
                    warm_for_tenant: false,
                    streamer_watermark_age: None,
                },
                capability: NativeExecCapability::Unknown,
                backoff_until: None,
            },
        );
    }

    match decide_owner(owner, &candidates, now) {
        OwnershipDecision::OwnerServing(n) if n == node_id => {
            // Steady state, reached on every tick once this node owns and serves
            // the appliance. Nothing to do and nothing to say — the adoption
            // below is a one-time event, and logging it at `info!` every ten
            // seconds would bury the lines that mean something.
            if matches!(election.health(), ApplianceHealth::Serving(owner) if *owner == node_id) {
                debug!(node_id, "appliance owned and serving here — no change");
                return;
            }
            // ADOPT rather than redeploy. The appliance outlived this process
            // — kamaji supervises it, not yubaba — so the correct action after
            // a restart is to take the running instance back over, not to stop
            // and re-place it.
            //
            // The service record is the one piece of state that genuinely did
            // die with the process: `ServiceRecords` is in-memory, so without
            // this re-assertion the appliance runs while `GET /service-records`
            // denies it exists, and every front door following the record sends
            // mesh clients nowhere (R591-T2).
            if let Some(observed) = running_here {
                let spec = headscale_appliance::appliance_spec(&state.headscale_dir);
                // A native workload has no namespace of its own, so the
                // supervisor may report no per-workload address; the node's own
                // mesh address is the right answer then, exactly as on the
                // deploy path in `start_headscale`.
                let mesh_ip = observed
                    .mesh_ip
                    .or_else(|| state.node_mesh_ip())
                    .unwrap_or(std::net::Ipv4Addr::LOCALHOST);
                state
                    .service_records
                    .upsert_deployed(&spec, mesh_ip, &observed.container_id);
            }
            election.record_success(node_id);
            info!(
                node_id,
                "adopted the appliance already running on this node — a restart is not a \
                 reason to move it (R858-T3)"
            );
        }
        OwnershipDecision::OwnerServing(n) => {
            // `debug`, for the reason the arm above already gives for its own
            // steady state: this is reached on every tick of every leader that
            // is not the owner, which under R858-T3's decoupling is the ordinary
            // posture rather than an event — us-west-001 owns the appliance
            // while raft leadership sits elsewhere, measured on the live fleet
            // 2026-09-05. At `info` it emits a line every ten seconds saying
            // nothing happened, which is how the loud channel R858-T3 built gets
            // trained out of an operator.
            debug!(
                node_id,
                owner = n,
                "appliance already serving — nothing moves"
            );
        }
        OwnershipDecision::ElectTo(n) if n == node_id => {
            match on_became_leader(node_id, raft, state, machine).await {
                Ok(()) => {
                    info!(
                        node_id,
                        "elected appliance owner and the appliance is serving"
                    );
                    election.record_success(node_id);
                }
                Err(e) => {
                    // LOUD, and it claims nothing. The 37-hour version of this
                    // was two `warn!`s and a cluster that carried on.
                    error!(
                        node_id,
                        round_exhausted = election.round_exhausted(),
                        "APPLIANCE UNHEALTHY: elected owner could not start the appliance and \
                         has NOT claimed ownership: {e}"
                    );
                    election.record_failure(node_id, now, e.to_string());
                    // Belt and braces: leave nothing half-started behind for
                    // the next candidate to collide with on :443.
                    on_lost_leader(state).await;
                }
            }
        }
        OwnershipDecision::ElectTo(n) => {
            info!(
                node_id,
                owner = n,
                "appliance belongs to another node — not starting it here"
            );
        }
        OwnershipDecision::NoEligibleCandidate => {
            let refusal = judge_appliance_candidate(&candidates[&node_id], now)
                .err()
                .map_or("ready", |r| r.as_str());
            error!(
                node_id,
                refusal,
                "APPLIANCE UNHEALTHY: no eligible candidate can run the appliance — the cluster \
                 has no coordinator and is not silently carrying on"
            );
            election.record_no_candidate(format!("{node_id}={refusal}"));

            // R858-T7: the record still names a node this leader has just
            // established is gone, and no node can take over. Retract it.
            //
            // The successful path needs no separate retraction — `ElectTo`'s
            // `SetIngressOwner` overwrites the dead node's name with the live
            // one, which is the same fact. Only the nobody-can-take-it path
            // leaves a record that would otherwise go on naming a corpse, and
            // R858's own root-cause note is that "the record says west owns it"
            // is what an operator reads during an outage and it has to be true.
            //
            // The retraction is also load-bearing for the fence: a resurrected
            // node reads this record to decide whether it may serve, and an
            // absent record puts it on the lease path (`ClaimUnconfirmed`)
            // rather than letting it read its own name and resume.
            if let Some(dead) = expired_owner {
                match raft.client_write(YubabaRequest::ClearIngressOwner).await {
                    Ok(_) => error!(
                        node_id,
                        expired_owner = dead,
                        "APPLIANCE VACANT: cleared the ingress-owner record of a node that has \
                         stopped renewing its lease, because nothing here can take the appliance \
                         over. The cluster has NO coordinator and the record now says so."
                    ),
                    Err(e) => warn!(
                        node_id,
                        expired_owner = dead,
                        "could not clear the expired ingress-owner record ({e}) — it still names \
                         a node that is gone; retrying on the next tick"
                    ),
                }
            }
        }
    }
}

/// This node's own [`NodeEligibility`], for the single-node candidate set above.
///
/// A node executing this line is live by construction — it is the raft leader,
/// it is running, and its own raft peer link is trivially healthy — so those two
/// gates are asserted rather than measured. `admits` is `true` because the
/// appliance is a [`LifecycleArchetype::Appliance`]: pinned and non-drainable,
/// so it is not subject to the tenant headroom bin-packing `admits` exists for
/// (R858-T3 change 4 — no priority class is needed to express that).
///
/// The gates that *are* measured for this node are the appliance-specific ones
/// [`judge_appliance_candidate`] adds: native-exec capability and deploy-failure
/// backoff.
///
/// [`LifecycleArchetype::Appliance`]: workload_spec::LifecycleArchetype::Appliance
/// Ask this node whether it can actually run the appliance (R858-T4).
///
/// Two facts, both of which were false on us-south-001 on 2026-09-03 and
/// neither of which anything checked before moving ownership there:
///
/// 1. **Can kamaji fork+exec at all?** `--native-exec-dir` is what turns the
///    native backend on, and the node that inherited the appliance had been
///    started without it. Asked over the wire rather than inferred, because the
///    answer comes from the same `ServerCtx.native` that `deploy_native_exec`
///    dispatches on — a capability derived from build features or CLI parsing
///    would be a second source of truth that drifts exactly when it matters.
/// 2. **Is the binary there?** `appliance_spec` is a native workload, so kamaji
///    forks `<headscale_dir>/headscale` and pulls nothing. A node with the flag
///    and no binary refuses just as hard as one without the flag, and the
///    refusal reads the same from a distance.
///
/// # Every failure to *learn* is `Unknown`, never `Absent`
///
/// A node with no sibling client (the in-process-runtime fallback), an older
/// kamaji that does not know the `Capabilities` variant, or a transient socket
/// error all yield [`NativeExecCapability::Unknown`], which
/// `judge_appliance_candidate` treats permissively. Reading "I could not ask"
/// as "cannot run it" would make every not-yet-rolled node ineligible the
/// moment this shipped — the 37-hour outage reproduced from the other side, and
/// during a rolling upgrade that is *most* of the fleet. Only a kamaji that
/// answers, and answers no, produces `Absent`.
async fn probe_native_exec(state: &Arc<ServerState>) -> NativeExecCapability {
    let Some(client) = state
        .constable_client
        .as_ref()
        .and_then(KamajiSibling::current)
    else {
        debug!("no kamaji sibling to ask about native-exec — capability stays Unknown");
        return NativeExecCapability::Unknown;
    };

    let caps = match client.capabilities().await {
        Ok(caps) => caps,
        Err(e) => {
            // Deliberately not `warn!`: against a pre-R858-T4 kamaji this is the
            // expected answer on every tick of a rolling upgrade, and a warning
            // that fires constantly during a normal roll trains operators to
            // ignore the channel R858-T3 just made loud.
            debug!("kamaji did not report capabilities ({e}) — capability stays Unknown");
            return NativeExecCapability::Unknown;
        }
    };

    if !caps.native_exec {
        error!(
            "this node's kamaji has no native backend (start it with --native-exec-dir): it \
             cannot run the appliance and is refusing candidacy UP FRONT rather than failing \
             the deploy after ownership has moved"
        );
        return NativeExecCapability::Absent;
    }

    let binary = state.headscale_dir.join("headscale");
    if !binary.exists() {
        error!(
            binary = %binary.display(),
            native_exec_dir = caps.native_exec_dir.as_deref().unwrap_or("<unreported>"),
            "this node's kamaji can fork native workloads but the appliance binary is not on \
             disk: a native workload pulls nothing, so this node would refuse the deploy"
        );
        return NativeExecCapability::Absent;
    }

    NativeExecCapability::Present
}

/// Which node the **replicated** record says owns the appliance, if any.
///
/// `ingress_owner` holds a machine name and every decision here is keyed by
/// [`YubabaNodeId`], so this is R859-F2's identity bridge
/// ([`node_for_machine`](crate::raft::YubabaStateMachine::node_for_machine))
/// used in the direction it was built for.
///
/// # "Is it me?" is answered without the member map, on purpose
///
/// The map is the *only* way to turn the record into some **other** node's id,
/// but it is a needless dependency for this node's own name — which the caller
/// already holds, since it is the same string this node writes into the record.
/// Comparing directly matters because of exactly when it is asked: a
/// just-restarted daemon may re-win leadership before `member_registration` has
/// republished its row, and going through the map there yields `None`, which
/// degrades to "vacant", which redeploys a coordinator that is running fine.
/// Every fleet roll restarts the owner, so that race is not a corner case — it
/// is the last step of every roll.
///
/// `None` still covers the cases where nothing can be concluded: no raft state,
/// no owner claimed, or an owner whose row is absent, unreplicated, or predates
/// [`MemberInfo::machine`](crate::raft::MemberInfo::machine). Those degrade to
/// this process's own [`ApplianceHealth`] via [`owner_status`] — the
/// pre-R858-T3 behaviour, so a fleet mid-roll is never worse off than it was,
/// only better once both halves are present.
fn recorded_owner(
    state: &Arc<ServerState>,
    node_id: YubabaNodeId,
    machine: Option<&str>,
) -> Option<YubabaNodeId> {
    let sm = state.cluster_state.as_ref()?;
    let owner = sm.ingress_owner()?;
    if machine.is_some_and(|m| m == owner) {
        return Some(node_id);
    }
    sm.node_for_machine(&owner)
}

/// Ask this node's own supervisor whether the appliance is running **here**.
///
/// The one fact about ownership that is locally measurable, and the reason a
/// yubaba restart can adopt rather than redeploy: kamaji supervises the
/// appliance, yubaba does not, so `headscale` outlives the daemon that placed
/// it. Without this probe a restarted process has no way to tell "I own it and
/// it is up" from "I own it and it is gone", and it has to assume the second.
///
/// Only a supervisor that answers, and answers *running*, counts. A missing
/// backend or an errored query yields `None` — read as "not running here",
/// which is the conservative direction: it costs a redeploy attempt on a node
/// that may already be serving, never a silent claim over a coordinator that is
/// not.
///
/// R858-B11 made this `pub(crate)`: the `/headscale/health` and
/// `/mesh/leader-health` handlers were answering the same question by asking
/// systemd and a hardcoded port instead, and both went stale the moment the
/// appliance moved under kamaji. There is one probe for "is it up here", and
/// this is it.
pub(crate) async fn observe_local_appliance(
    state: &Arc<ServerState>,
) -> Option<kamaji::WorkloadState> {
    let backend = state.active_backend()?;
    let ident = headscale_appliance::appliance_ident();
    match backend.get_workload(&ident).await {
        Ok(Some(w)) if matches!(w.status, kamaji::WorkloadStatus::Running) => Some(w),
        Ok(_) => None,
        Err(e) => {
            debug!("could not ask the supervisor about the appliance ({e:#}) — treating it as not running here");
            None
        }
    }
}

fn self_eligibility() -> NodeEligibility {
    NodeEligibility {
        liveness: Some(Confirmed::Up),
        raft_peer_healthy: true,
        region: None,
        admits: true,
        warm_for_tenant: false,
        streamer_watermark_age: None,
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Take the appliance on this node: hydrate, start, and **claim only if the
/// start succeeded**.
///
/// # The ordering, stated because the ticket and the code disagreed
///
/// Before R858-T3 the sequence here was already restore → `start_headscale` →
/// sidecar → `SetIngressOwner` — the claim came *last*, not first. The defect
/// was never the order: `start_headscale` returned `()` and every failure path
/// inside it was `warn!`-and-continue, so the claim could not depend on the
/// outcome no matter where it sat. Reordering would have fixed nothing; making
/// the outcome *visible* is the fix.
///
/// `Ok(())` here means the appliance is up and this node is recorded as its
/// owner. `Err` means it is up nowhere on this node, nothing was claimed, and
/// the caller must re-elect.
async fn on_became_leader(
    node_id: YubabaNodeId,
    raft: &YubabaRaft,
    state: &Arc<ServerState>,
    machine: Option<String>,
) -> Result<(), ApplianceStartError> {
    let _ = node_id;
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

    // 2. Start headscale as a kamaji-supervised appliance. Everything below is
    //    conditional on this, which is the R858-T3 change.
    start_headscale(state).await?;

    // 3. Start litestream sidecar. After the start, not before: replicating a
    //    DB from a node that is not serving it publishes a losing copy to S3.
    if state.litestream_s3_url.is_some() {
        litestream::start();
        info!("litestream-headscale sidecar started");
    }

    // 4. Claim ingress owner in raft state machine so `yah mesh status` can
    //    show which machine is serving Headscale. Reached only on a successful
    //    start — a node that could not serve must never appear as the owner,
    //    because "the record says west owns it" is what an operator reads
    //    during an outage and it has to be true.
    if let Some(machine) = machine {
        let req = YubabaRequest::SetIngressOwner { machine };
        match raft.client_write(req).await {
            Ok(_) => info!("ingress owner set in raft state"),
            // The appliance IS up; only the record is missing. Not an
            // `ApplianceStartError` — re-electing away from a node that is
            // serving would be the flap this ticket exists to prevent. The next
            // tick re-writes it.
            Err(e) => error!("failed to set ingress owner in raft: {e}"),
        }
    }

    Ok(())
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
///
/// # Why this returns a `Result` (R858-T3)
///
/// It used to return `()`. Every failure path here — the noise-key refusal, a
/// kamaji that will not take the spec, a systemd unit that does not exist — was
/// an `error!`/`warn!` that the caller could not see, so
/// [`on_became_leader`] wrote `SetIngressOwner` regardless and `yah mesh status`
/// reported an owner that was not serving. That gap is the reason R858 ran for
/// 37 hours with every external healthcheck green. The claim now depends on
/// this value.
async fn start_headscale(state: &Arc<ServerState>) -> Result<(), ApplianceStartError> {
    let spec = headscale_appliance::appliance_spec(&state.headscale_dir);

    // R858-T2: place the coordinator's noise identity BEFORE either start path
    // below. `headscale serve` mints a fresh key when the file is absent, and
    // from then on the file exists and looks right while every
    // already-registered node rejects the new server — on a coordinator whose
    // `/health` still returns 200. So "after" here is indistinguishable from
    // "never", and a refusal to start is the only safe answer when the cluster
    // holds an identity this node cannot put on disk.
    let resolver = noise_key_resolver(state, &spec);
    if let Err(e) = headscale_state::materialize_noise_key(
        resolver
            .as_ref()
            .map(|r| r as &dyn workload_spec::secrets::SecretResolver),
        &state.headscale_dir,
    ) {
        error!("{e}");
        // R858-T3 preserves R858-T2's refusal exactly — including that it comes
        // FIRST, before either start path. The only change is that the refusal
        // now propagates instead of vanishing, so no claim is written on top of
        // a coordinator that would come up with the wrong identity.
        return Err(ApplianceStartError::NoiseIdentity(e.to_string()));
    }

    // Carried to the error so the operator gets *both* refusals in one line.
    // "kamaji refused" and "the systemd unit does not exist" are two different
    // problems, and R858 logged them as two unrelated `warn!`s an hour apart.
    let kamaji_refusal: String;

    if let Some(backend) = state.active_backend() {
        // Release :443/:80 and the boot-persistence bit before kamaji forks its
        // own copy. A no-op on a node that never ran the systemd path.
        systemctl(&["disable", "--now", "headscale"]);

        // R599-F12's rule for a NATIVE workload: hand kamaji this node's own
        // mesh address, never a per-workload one. A fork+exec'd process has no
        // namespace of its own, so a per-workload address would simply fail to
        // bind — and the node address is what makes the appliance
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
                return Ok(());
            }
            Err(e) => {
                warn!(
                    "kamaji refused the headscale appliance ({e:#}) — reverting to the \
                     headscale.service systemd unit"
                );
                kamaji_refusal = format!("{e:#}");
            }
        }
    } else {
        warn!(
            "no kamaji backend attached — starting headscale via systemd (unsupervised by \
             kamaji; see R591-F1)"
        );
        kamaji_refusal = "no kamaji backend attached".to_string();
    }

    if systemctl(&["enable", "--now", "headscale"]) {
        info!("headscale started via systemd");
        Ok(())
    } else {
        // Both paths are now spent. This exact pair of failures — kamaji
        // refusing for want of a native backend, then a systemd unit that was
        // never installed — is what us-south-001 hit on 2026-09-03, and it must
        // not read as "started".
        Err(ApplianceStartError::BothPathsFailed {
            kamaji: kamaji_refusal,
        })
    }
}

/// Why this node could not stand the appliance up.
///
/// A value rather than a log line, because [`on_became_leader`] has to *branch*
/// on it: the whole R858-T3 correction is that a failure withholds the
/// ownership claim, and a `warn!` cannot be branched on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplianceStartError {
    /// R858-T2's refusal: the cluster holds a noise identity this node cannot
    /// put on disk. Starting anyway produces a coordinator that looks healthy
    /// and rejects every already-registered node.
    NoiseIdentity(String),
    /// Neither the kamaji path nor the systemd fallback started it.
    BothPathsFailed { kamaji: String },
}

impl std::fmt::Display for ApplianceStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoiseIdentity(e) => {
                write!(
                    f,
                    "refused to start without the cluster's noise identity: {e}"
                )
            }
            Self::BothPathsFailed { kamaji } => write!(
                f,
                "no start path succeeded (kamaji: {kamaji}; systemd: `systemctl enable --now \
                 headscale` failed — unit missing or systemd unavailable)"
            ),
        }
    }
}

/// Build the cluster-secret resolver [`start_headscale`] reads the noise
/// identity through, bound to the appliance spec's own identity so the record's
/// [`SecretAccess`](workload_spec::secrets::SecretAccess) rule is *enforced*
/// (R706 / W294) rather than bypassed — the consumer is a required constructor
/// argument precisely so no call site can opt out.
///
/// `None` means this node has no cluster-secret rail at all: no raft state, or
/// no node-local KEK. That is not treated as a failure here — see
/// [`headscale_state::materialize_noise_key`] for why an *unavailable* store is
/// read as an absent record rather than as a reason to refuse to start.
fn noise_key_resolver(
    state: &Arc<ServerState>,
    spec: &workload_spec::WorkloadSpec,
) -> Option<ClusterResolver<crate::raft::YubabaStateMachine>> {
    let sm = state.cluster_state.as_ref()?;
    match ClusterResolver::from_kek_file(
        sm.clone(),
        &state.cluster_kek_path,
        &state.local_secret_store_root,
        workload_spec::secrets::SecretConsumer::of(spec),
    ) {
        Ok(r) => Some(r),
        Err(e) => {
            warn!(
                "cluster secret resolver unavailable ({e}) — cannot check the store for \
                 headscale's noise identity; the next log line says what that means for this \
                 coordinator's portability"
            );
            None
        }
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
/// This node's self-derived host identity — `/etc/hostname`, falling back to
/// `$HOSTNAME`.
///
/// `pub` as of R859-F2 so the `serve` task set can publish the *same* string
/// into [`MemberInfo::machine`](crate::raft::MemberInfo::machine) that this
/// module writes into `ingress_owner`. One derivation, so the two are
/// comparable by construction rather than by convention — which is the entire
/// basis on which [`YubabaStateMachine::node_for_machine`][nfm] can answer
/// "which node is the ingress owner". See that field's doc for why the value is
/// a hostname and not a `.yah/infra/machines/` name.
///
/// [nfm]: crate::raft::YubabaStateMachine::node_for_machine
pub fn derive_machine_name() -> Option<String> {
    if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
        let name = s.trim().to_string();
        if !name.is_empty() {
            return Some(name);
        }
    }
    std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty())
}
