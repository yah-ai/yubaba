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
//! @yah:gotcha("YOUR UNVERIFIED PRECONDITION IS NOW MEASURED, AND THE ANSWER IS THE BAD ONE — but it is narrower than you feared. T3's @yah:assumes asks whether the DEPLOYED binary populates MemberInfo::machine, and names the check: one read-only GET /raft/status. Run 2026-09-06 by @Ashguard:hydra against the live fleet (both node 3 and node 1 answered identically): every member row carries ONLY `addr` and `region` — `{\\\"1\\\":{\\\"addr\\\":\\\"100.64.0.2:7443\\\",\\\"region\\\":null}, \\\"2\\\":{...}, \\\"3\\\":{...}}`. NO `machine` key on any of the three. The field is not missing from the CODE — raft/mod.rs defines it (R859-F2) and `git diff 4cf740bf..HEAD -- src/raft/` is EMPTY, so 0.8.33 shipped the struct — it is simply never populated by the running nodes, and it is `#[serde(default)]` so it serialises away. CONSEQUENCE EXACTLY AS T3 PREDICTED: once T3 rolls, a node resolving ANOTHER node's ingress ownership gets None from node_for_machine, falls back to its own health, tries to start the appliance, and fails loudly (us-east-001 and us-south-001 were both re-measured today and have no --native-exec-dir, no headscale binary and no /var/lib/yah-cloud/headscale at all). Loud refusal, not silent theft — but not the intended path, and R858-T4 is what closes it. WHAT IS NOT AFFECTED, and it is the case that matters right now: a node resolving its OWN ownership does not use the member map at all — recorded_owner compares the record against this node's own name directly. Verified concretely: raft `ingress_owner` = \\\"vps-4c1efa56\\\" and us-west-001's /etc/hostname = \\\"vps-4c1efa56\\\", so a T3-carrying yubaba restarted on west reads the record, sees itself, observes the appliance already Running under kamaji, and ADOPTS it. That is the a_yubaba_restart_on_the_owner_leaves_the_appliance_in_place path.")
//! @yah:gotcha("FALSIFIED ON HARDWARE 2026-09-06 — DO NOT SIGN THIS OFF AS-IS. @Ashguard:hydra hand-built a musl yubaba from this tree (with R858-B13's fix), shipped it to us-west-001, ran it for ~90s and rolled it back. `cargo test -p yubaba --lib` was 766/0 and the policy line confirms T3 was live: `ingress_ownership: ElectedFromEligible`. The appliance was TORN DOWN anyway. Verbatim from west's journal, the whole sequence inside 400ms of startup: `headscale appliance deployed under kamaji supervision` -> `ERROR failed to set ingress owner in raft: has to forward request to: Some(1), BasicNode { addr: \\\"100.64.0.2:7443\\\" }` -> `elected appliance owner and started the appliance` -> `headscale appliance torn down on leadership loss` -> `headscale stopped on leadership loss` -> `APPLIANCE CRASH-LOOPING ... backing off`. Then a ~40s backoff cycle repeating that forever. TWO DEFECTS, BOTH THIS TICKET'S. D1: A FOLLOWER ELECTS ITSELF, DEPLOYS, AND ONLY THEN DISCOVERS IT CANNOT RECORD OWNERSHIP — west was a follower (south = node 1, term 20), SetIngressOwner must go to the leader and is NOT forwarded, so the node deploys an appliance it can never own on paper, once per backoff round, indefinitely. This ticket's own design says 'only a leader may claim a vacancy'; the code claims and DEPLOYS first and checks second. D2: THE LEADERSHIP-LOSS TEARDOWN FIRES ON A FOLLOWER THAT IS THE RECORDED OWNER — 4ms after starting the appliance the is_leader edge ran on_lost_leader -> stop_headscale. That directly contradicts this ticket's own stated fixes ('a follower may restart what it is already recorded as owning', 'the edge keeps only the teardown'). On a COLD START AS FOLLOWER that teardown is exactly wrong, and it is reachable on the adopt-eligible path, not only on a failed start. NOTE the integration test a_follower_that_owns_the_appliance_restarts_it_without_a_leadership_change passes in the harness while this fails on hardware — the harness evidently does not reproduce a cold yubaba start on a follower whose member row lacks `machine`.")
//! @yah:gotcha("CORRECTION TO MY OWN FALSIFICATION GOTCHA ABOVE, from @Ashguard:golem who owns the code — read this WITH it, because two of its three claims are wrong and they point a reviewer at the wrong file. (1) D2 IS NOT PURELY T3's — IT IS A REGRESSION R858-B13 WIDENED, AND IT IS ALREADY FIXED. `on_leadership_loss_under_election` kept the appliance if `owner.serving` OR this process's ApplianceHealth was `Serving`. Pre-B13, `record_success` fired immediately after a successful deploy, so health was `Serving(self)` within microseconds and that second term covered exactly this case; B13 deliberately WITHHOLDS record_success until the appliance is observed running (that is what makes the backoff accumulate), so for one reconcile interval after a start neither term holds. The 6ms window I measured at 07:56:49.690->.696 IS that gap. golem has landed a third term, `start_awaiting_proof` — this node started the appliance and has not yet been able to judge it — extracted as the testable `appliance_survives_leadership_loss(owner, node_id, health, start_awaiting_proof)` with four unit tests. (2) D1 AS I WROTE IT IS OVERSTATED — FILE IT NARROWLY. `recorded_owner` does NOT need node_for_machine for the SELF case: it compares the record against this node's own machine name first and returns Some(node_id) on a hit. west's /etc/hostname = ingress_owner = \\\"vps-4c1efa56\\\", so west DID resolve itself as recorded owner, and the ElectTo(self) path I saw is T3 BEHAVING AS DESIGNED (a follower that is the recorded owner and is not serving is supposed to restart what it owns). The genuinely wrong part is much narrower: `on_became_leader` writes SetIngressOwner UNCONDITIONALLY and a follower cannot, producing the `has to forward request to: Some(1)` ERROR — a REDUNDANT write, since the record already named west. So the defect is 'a redundant SetIngressOwner from a follower logs a spurious ERROR', NOT 'a follower deploys an appliance it can never own'. (3) CONSEQUENTLY MY 'deploys every backoff round forever' CLAIM IS WRONG: once the appliance is running and adopted, decide_owner returns OwnerServing(self) and nothing redeploys. The repeating cycle I observed was D2 killing the appliance 6ms after each start, not an ownership loop. WHAT STANDS UNCHANGED: the missing `machine` key on every live member row is real, separate, and unexplained by any of the above — self-resolution bypasses the member map, but no node can resolve any OTHER node's ownership, so the entire remote half of recorded_owner is dead on the live fleet.")
//!
//! @yah:ticket(R858-T8, "The rehearsal: power off the owner, prove the HA-singleton takes over on the sovereign group")
//! @yah:status(review)
//! @yah:at(2026-09-08T21:21:22Z)
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
//! @yah:handoff("THE REHEARSAL RAN, ON THE DEV GROUP, AS A REAL POWER-OFF — 2026-09-08 by @Ashguard:libra (session:18023eec). Method, stated because the ticket forbids substituting a graceful drain: `sudo systemctl reboot -ff` on us-west-011, the recorded ingress_owner — no clean shutdown, no SIGTERM to yubaba/kamaji, no retraction, nothing given a chance to hand anything over. Chosen over a sustained power-off because these are Raspberry Pis on the operator's LAN with no remote power control, and because the automatic resurrection ~2min later is what makes step (3), the fence, testable in the same run. THE ONE THING IT DOES NOT COVER is a LONG absence; every other property of a power-off holds. TEN-STEP TIMELINE, every line from a journal or a 1s-cadence HTTP observer, one UTC clock: 21:00:44 owner vanishes. 21:01:18 us-west-013 (raft leader) EXPIRES it — `expire_after_secs: 30`, so 34s from death, and the dwell IS the failover time. 21:01:19.191-21:01:20.043 litestream restore from s3://yah-headscale/dev, 852 ms. 21:01:20.043 noise identity: no KEK on the dev group, so the loud ERROR fires and headscale MINTS A FRESH ONE. 21:01:20.043 config.yaml already in sync. 21:01:20.054 kamaji forks headscale. 21:01:20.129 SetIngressOwner written. 21:01:22 the door answers /key. 21:01:28.172 B13 discharge, appliance observed running. DEATH TO SERVING COORDINATOR: 38 SECONDS, of which 30 is the expire dwell — the assumption on this ticket that data transfer is not the bottleneck is CONFIRMED, and hydration measured 852 ms against a 77 KB DB.")
//! @yah:handoff("THE ACCEPTANCE CRITERION IS MET — an ALREADY-REGISTERED node reached the tailnet through the NEW coordinator without re-registering. Measured, and the client is a real one built for this: a SECOND tailscaled (userspace-networking, own state/socket/port, no TUN) on us-west-003, registered against the dev headscale BEFORE the power-off as node id 1 `r858t8-client`, machine_key mkey:ec79aa2e8b3873c, node_key nodekey:d0b558bd6150, 100.64.0.1. After failover it came back on us-west-013 with BackendState Running, Online true, AuthURL empty, and the SAME node key and SAME IP. us-west-013's `headscale nodes list` shows that identical row, restored out of R2 — so step (6) hydration and step (10) reconvergence both hold. BUT READ THE NEXT ENTRY BEFORE BANKING THIS: it passed for a reason the ticket did not predict, and step (7) was RED the whole time.")
//! @yah:handoff("THE PREMISE UNDER R858-T2 IS FALSIFIED, AND IT IS THIS RELAY'S MOST LOAD-BEARING BELIEF. The claim, written verbatim in .yah/infra/secrets/headscale-noise-private-key.toml and repeated in this ticket's own gotchas, is that a coordinator which mints a fresh noise key \\\"comes up, answers GET /health with 200, and rejects every already-registered node — silent and fleet-wide, strictly worse than the 37-hour outage\\\". IT DOES NOT. Measured THREE times against headscale v0.23.0 + tailscale 1.102.3, each with a different coordinator identity (019f9888 -> cf07e1f7 -> 97e596e8 -> 020b9a81, read off /key?v=138 each time): the already-registered client reconnected with its ORIGINAL node key, Online true, AuthURL empty, no re-registration. THE THIRD RUN CLOSES THE LOOPHOLE — I EXPIRED THE PREAUTH KEY FIRST (`headscale preauthkeys expire`), so re-registration was not available as an explanation, then rotated the identity again; the client still came back as node id 1 on 100.64.0.1. MECHANISM: the client fetches the server's noise public key from /key on every connection and does not pin it. What authenticates an existing node is its MACHINE KEY against the row in headscale.db. So the thing that must survive a failover is THE DATABASE, not the server identity.")
//! @yah:handoff("WHAT AN IDENTITY CHANGE DOES COST, measured, so T2 is re-priced rather than dismissed: an ALREADY-CONNECTED client is knocked offline and did NOT self-heal in 2.5 minutes. Its log names the mechanism — a failed noise dial makes tailscale escalate to `controlhttp: forcing port 443 dial due to recent noise dial`, and on this rig that dial is refused because the dev door is plain HTTP on 8080. Only restarting tailscaled recovered it. NOT MEASURED, AND IT MATTERS FOR PROD: prod's door DOES terminate TLS on 443, so that escalation would land on something real and the wedge may be shorter or absent there. So the honest re-pricing is: identity carriage buys a clean reconnect instead of a client-side stall of unknown length — worth having, cheap, and NOT the fleet-wide silent rejection the relay has been treating as the gating risk. RECOMMEND CORRECTING the secret declaration's prose and this relay's gotchas rather than deleting R858-T2; the seeding is still the right thing, it is just no longer the thing that decides whether a failover is survivable.")
//! @yah:handoff("THE TICKET'S OPEN /health QUESTION IS ANSWERED, both halves, by an isolated probe on idle us-west-014 (scratch dir, port 18080, removed afterwards; the node's own state dir was never touched). (a) On an EMPTY database headscale returns `200 {\\\"status\\\":\\\"pass\\\"}` — confirmed with zero users and zero nodes. So /health is a FALSE GREEN on an empty or half-restored DB, exactly as suspected. (b) On an UNOPENABLE database path headscale FAILS TO START at all (`creating directory for sqlite: ... permission error`) and never binds, so /health is a true red there. CONCLUSION for step (8)'s readiness gate: /health distinguishes \\\"cannot open the DB\\\" from \\\"up\\\", and nothing else. It cannot see an empty DB and it cannot see a wrong identity. TWO CHEAP PROBES COVER WHAT IT MISSES, and the second is better than the exec probe this ticket proposed: a `headscale nodes list` over the unix socket catches the empty DB, and a plain `GET /key?v=138` catches the identity — it returns the coordinator's noise publicKey as an `mkey:`, which is how all three rotations above were detected, and it is an HttpGet rather than an Exec.")
//! @yah:handoff("DISCOVERED WORK. (1) FILED R858-B20, high, and it is the real prize from this run: the resurrected old owner read its OWN stale raft record, elected itself, ran a SECOND coordinator on a stale DB for 9.7 s, and — the part that actually damages state — started litestream and pushed WAL frames from that losing database into the shared s3://yah-headscale/dev prefix at 21:02:43, extending the pre-failover generation e01101da3a30f8da to 82 s AFTER the winning generation 17578973eecfbf58 began. The R858-T7 fence did fire, with the right reason (`record-names-another-node`), but one reconcile tick too late to prevent any of it. Full timeline, root cause, three candidate fixes with a recommendation, and a reproduction are on B20. (2) FIXED IN PASSING, in this relay's own file: oss/yubaba/crates/yubaba/src/leader.rs printed `pid=0` on `headscale appliance deployed under kamaji supervision` for every live deployment, because `KamajiClient::deploy_workload` acks on admission before the fork and its `DeployResult::task_pid` is structurally 0 — while kamaji's own `native workload forked id=headscale pid=8651` sat one line above in the same journal. The field is removed with a comment saying why; a field that is always zero reads as \\\"the appliance has no pid\\\", which is the shape of a failed start.")
//! @yah:gotcha("RIG STATE LEFT BEHIND, AND THREE TEMPORARY UNITS THAT ARE NOT IN THE 2026-09-08 R858-T5 ROLLBACK NOTE. The dev group is UP and coherent: leader 13, term 74, all three voters, ingress_owner us-west-013 (the appliance MOVED and stayed moved), dev client online at 100.64.0.1. us-west-013's noise key was hand-restored to the ORIGINAL dev identity 019f9888 (sha256 43016544236da8d4a64c9f1d04c766b799432ace8004b66f587e71d27c12466d) so it matches what us-west-011 still holds and a future failover between those two does not churn clients — HAND-PLACED, not carried, and us-west-014 deliberately left bare so the T2 gap stays visible. ADDED BY THIS SESSION, each with its rollback in its own file header: /etc/systemd/system/r858t8-door.{socket,service} on us-west-011/013/014 (systemd-socket-proxyd, LAN-IP:8080 -> 127.0.0.1:8080, the stand-in for prod's passway-mesh door); /etc/systemd/system/r858t8-devclient.service on us-west-003 (192.168.10.32) plus a `192.168.10.13 dev-mesh.yah.internal` line in its /etc/hosts and /var/lib/tailscale-dev. THE DEV CLIENT IS A SECOND tailscaled AND DOES NOT TOUCH THAT BOX'S PROD TAILNET MEMBERSHIP — userspace-networking, no TUN, no routes, no DNS, separate state/socket/port; us-west-003 was still on the prod tailnet at 100.64.0.9 throughout. NOTHING ON PROD WAS TOUCHED AT ANY POINT.")
//! @yah:gotcha("STEP (9) WAS MANUAL AND THAT IS THE HONEST REPRESENTATION OF PROD TODAY, not a shortcut in the rehearsal. The dev client's control URL is a name in /etc/hosts and I repointed it by hand from us-west-011 to us-west-013 after the takeover; prod's equivalent is the three static /etc/passway-mesh.env upstreams that this relay's own 2026-09-08 recovery note records as \\\"OWNER-AWARE ONLY BY HAND\\\". So the rehearsal reproduces the gap rather than papering over it. WHAT IT COSTS, MEASURED: the coordinator was serving at 21:01:22 and the client did not return until I intervened at 21:05:03 — i.e. the automated legs took 38 s and the un-automated one took as long as it took a human to notice. That is the whole remaining outage, and it is the thing left to automate. Note the constraint the env file itself states and that this rehearsal does NOT lift: the door must work with a totally dead mesh, so \\\"point the door at the service record\\\" is already-rejected. The dev rig cannot help decide that design — it has no passway at all — but it can now measure any answer, because the door is a two-file systemd unit that can be pointed anywhere.")
//! @yah:gotcha("THE PRIOR SESSION'S \\\"DEAD-OWNER FENCING DOES NOT FIRE\\\" GOTCHA (oss/yubaba/crates/yubaba/src/service_records.rs:300) IS REAL BUT DID NOT BITE HERE, AND THE DIFFERENCE IS ONE PRECONDITION WORTH WRITING DOWN. That measurement had us-west-013 win an election AFTER us-west-011 was already stopped, so its lease detector carried no entry for node 11, `silence(11)` was None, and expiry could never start its clock. In this run us-west-013 had ALREADY been leader for some time with node 11 live in its lease channel — I verified that before the power-off, `lease_liveness.peers` listing 11/13/14 all `live` — so the clock was running when 11 died and expiry fired on schedule at 30 s. BOTH FACTS ARE TRUE AND THEY COVER DIFFERENT CASES: expiry works when the survivor watched the owner die, and is structurally unreachable when it did not. Nothing here discharges that gotcha; this run simply exercised the other branch. Anyone testing the fix for it should reproduce the ORIGINAL shape — stop the owner, then restart or re-elect the survivor — not this one.")
//! @yah:verify("FAILOVER, measured on one UTC clock from journals plus a 1s HTTP observer: death 21:00:44 -> expire 21:01:18 (expire_after_secs=30) -> litestream restore 852 ms -> kamaji fork 21:01:20.054 -> SetIngressOwner 21:01:20.129 -> door serving 21:01:22 -> B13 discharge 21:01:28. 38 s death-to-serving, 30 s of it the expire dwell.")
//! @yah:verify("ACCEPTANCE: already-registered node id 1 `r858t8-client` (machine_key mkey:ec79aa2e8b3873c, node_key nodekey:d0b558bd6150, 100.64.0.1) reached the tailnet through us-west-013 with BackendState Running, Online true, AuthURL empty, identical node key and IP; us-west-013's `headscale nodes list` shows the same row restored out of R2.")
//! @yah:verify("FALSIFICATION OF THE NOISE-KEY PREMISE, three runs, coordinator identity read off /key?v=138 each time (019f9888 -> cf07e1f7 -> 97e596e8 -> 020b9a81). The third was run with the preauth key EXPIRED first, so re-registration was unavailable as an explanation, and the client still returned as node id 1 on 100.64.0.1 with AuthURL empty.")
//! @yah:verify("FENCE: the resurrected us-west-011 is not serving — no headscale process, litestream inactive, and it reads ingress_owner=us-west-013. Its journal carries the fence line at 21:02:50.264 with reason RecordNamesAnotherNode { owner: 13 } — but 9.7 s after it had started a second coordinator and replicated a stale DB. That gap is R858-B20, and it is why this ticket does NOT claim step (3) clean.")
//! @yah:verify("/health: `200 {\"status\":\"pass\"}` on a database with zero users and zero nodes (isolated probe, us-west-014, scratch dir + port 18080, removed); fail-to-start with no bind on an unopenable DB path. CODE: `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib` = 828 passed / 0 failed, after the one-line leader.rs `pid=0` removal. Nothing committed, nothing rolled, no prod node touched.")
//!
//! @yah:ticket(R858-B14, "The appliance is never observable as Running, so ownership never converges — every backoff round redeploys and kills a healthy headscale")
//! @yah:status(review)
//! @yah:at(2026-09-06T08:29:24Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:severity(high)
//! @yah:next("RAISE THE Err ARM AT leader.rs:1149 ABOVE debug! FIRST — it is one line and it decides the whole investigation. If get_workload is erroring over the UDS, the appliance was never unobservable at all and this is a plumbing bug; if it returns Ok with a non-Running status, the defect is in kamaji-bin's native supervisor's status reporting. Do not design a fix before that line tells you which.")
//! @yah:gotcha("MEASURED ON us-west-001 2026-09-06 by @Ashguard:hydra, with R858-B13's fix AND its follow-up D2 fix both live in the binary (hand-built musl yubaba sha 7f6d24d07d4f7f030c7030c17227efd3df78eccf35184245a9897f3d433f4d36, `cargo test -p yubaba --lib` = 770/0). THIS IS A THIRD DEFECT, distinct from B13's pacing and from R858-T3's ownership resolution, and it is what actually keeps us-west-001 out of raft. THE EVIDENCE: over 90s with the D2 fix in, `torn down on leadership loss` occurred ZERO times (so D2 is genuinely fixed), yet the headscale pid still changed 720568 -> 720930 -> 721017 and kamaji logged `native workload forked id=headscale` at 08:05:45, 08:06:25, 08:07:35 — i.e. the backoff IS growing (40s then 70s, so golem's exponential backoff works) but the cycle never stops, and EVERY redeploy kills a healthy headscale that kamaji was already supervising correctly. THE MECHANISM: leader.rs::observe_local_appliance (leader.rs:1140) returns Some only for `Ok(Some(w)) if matches!(w.status, kamaji::WorkloadStatus::Running)`; anything else — including Err — is silently treated as \"not running here\" at :1149. Because the appliance is never observed Running, B13's deliberately-withheld `record_success` is never reached, `decide_owner` never returns OwnerServing(self), and so each backoff round re-elects and REDEPLOYS instead of adopting. Backoff bounds the RATE of this but cannot make it converge — no amount of backoff turns an unobservable appliance into an observed one.")
//! @yah:assumes("I did NOT establish which side is wrong, and the ticket should not assume. The strongest hint is that yubaba logs `headscale appliance deployed under kamaji supervision` with `\"pid\":0` on EVERY deploy while kamaji simultaneously logs real forked pids (720878/720930/721017) — so the DeployResult crossing the UDS carries no pid even though the child is real. Two candidate sites, both unread by me: (a) kamaji-bin's server-side native supervisor, which is what the fleet actually runs (the journal line is `kamaji_bin::server: native workload forked`) and which may be a different implementation from the INLINED oss/kamaji/crates/kamaji/src/native.rs I did read — that one's get_workload at native.rs:822 does return `status: h.status.borrow().clone()` and would report Running, and its `pid` field is documented as \"0 when no child is running\"; (b) yubaba's side, if get_workload errors over the socket and is swallowed by the Err arm at leader.rs:1149, which logs at debug! and so is INVISIBLE at the fleet's default log level. THE FIRST STEP IS TO MAKE THAT ERR ARM LOUD, or query kamaji directly — there is no client CLI on the box (`kamaji --help` shows a server only), so this needs either a small probe or a log-level bump.")
//! @yah:verify("FIXED AND VERIFIED ON PROD HARDWARE 2026-09-06T08:23-08:28Z by @Ashguard:hydra (session:8d1176d7). us-west-001 IS BACK IN RAFT QUORUM: /raft/status now reports all THREE peers live (1: silent_for_ms 236, 2: 391, 3: 569), term 20 unchanged, leader still node 1 — node 2 (west) went from state \"down\"/silent_for_ms 895028 to \"live\". ROOT CAUSE WAS NEITHER CANDIDATE IN THE ASSUMES BLOCK: get_workload did not error and kamaji did not misreport a status. kamaji-bin's List handler (oss/kamaji/crates/kamaji-bin/src/server.rs:1155) merges containerd, bundle (ctx.bundle.native), tenant-passway, microvm and docker, and NEVER merges ctx.native — the --native-exec-dir fork+exec backend that deploy_native_exec (:1809) actually forks headscale through. It opens with `ctx.registry.lock().await.list()` under the comment \"native workloads\", but Registry::workloads has NO writer anywhere in the crate (list() at :808 is the only reference to the field), so on a live daemon that vec is always empty. Chain: headscale forks and runs under ctx.native -> absent from every List reply -> KamajiClient::get_workload (oss/kamaji/crates/kamaji/src/sibling.rs:757) is list_workloads().find(ident) -> Ok(None) -> leader.rs treats it as not running here -> record_success never reached -> re-elect + redeploy every backoff round. THE FIX: a #[cfg(feature = \"native-exec\")] merge arm for ctx.native.list_workloads() mirroring the bundle arm, plus native-exec added to runtime_state_to_entry's cfg gate. `cargo test -p kamaji-bin --features containerd-integration,native-exec,bundle-serving --lib` = 285 passed / 0 failed. FALSIFIED, not just green: the new regression test a_native_exec_workload_is_visible_in_list FAILS with the merge arm cfg'd out, panicking \"a supervised native workload must appear in List, got []\" — an empty list, exactly the live symptom. HARDWARE METHOD: cross-built musl kamaji (scripts/cross-build-guarded.sh kamaji-bin x86_64-unknown-linux-musl '' containerd-integration,native-exec,bundle-serving oss/kamaji, sha256 daededfb201e174e6220209829be1ba13cf3601bf3aba6adff6d5aeb596b9691, static musl ELF), anchored the previous binary at /usr/local/bin/kamaji.rollback-20260906-hydra-b14 (sha 4f5a620b74d6dd394199457c8c95246c7481f446dd0730dfbcc4d0663b658040), installed, `systemctl restart kamaji`, `systemctl enable --now yubaba`. SINGLE VARIABLE: yubaba was NOT rebuilt — west still runs the same hand-built B13+D2 binary (sha 7f6d24d0...) whose behaviour B14 measured, so the only thing that changed is kamaji's List. RESULT, over 3m50s: exactly ONE fork (08:23:38, the deploy that replaced the child the kamaji restart killed), then `kamaji | grep -c \"native workload forked\"` = 0 over the following 3 minutes; headscale pid 721574 unchanged with etime marching 00:24 -> 03:50; `elected appliance owner and started` = 0 over the same window. The line that had never once appeared before arrived exactly one RECONCILE_INTERVAL after the deploy: 08:23:48.192 \"the appliance this node started is now observed running — recording the start as successful (R858-B13)\". That is B13's deliberately-withheld record_success finally being reachable. Mesh green throughout and after: https://cloud.mesh.yah.dev/key?v=138 = 200, http://100.64.0.3:7443/service-records?ready=true = 200. LAST STEP DONE: yubaba is `enabled` AND `active` (symlink /etc/systemd/system/multi-user.target.wants/yubaba.service created), kamaji likewise. headscale config.yaml UNTOUCHED — mtime still 07:36:55Z (pre-run), listen_addr still 127.0.0.1:8080, no tls_letsencrypt_* keys; no /headscale/deploy or /headscale/bootstrap was ever posted.")
//! @yah:gotcha("RESTARTING kamaji ON WEST KILLS headscale WITH NO AUTOMATIC RESTORE — plan for it before you ship a kamaji binary there. kamaji.service is `KillMode=mixed` + `Delegate=yes` over yubaba.slice, so a restart SIGKILLs everything in the delegated cgroup including the appliance, and nothing resumes native-exec workloads on startup (resume_bundle_workloads covers bundles only). With yubaba disabled, that leaves the mesh coordinator dead and nothing to redeploy it. The escape hatch, if a future run needs to restore headscale without yubaba: `sudo systemd-run --unit=headscale-fallback --collect --working-directory=/var/lib/yah-cloud/headscale /var/lib/yah-cloud/headscale/headscale serve --config /var/lib/yah-cloud/headscale/config.yaml` — the exact argv, cwd and user (root) the kamaji-supervised child runs with. This run did not need it: kamaji restart and `enable --now yubaba` were issued back-to-back and the coordinator was down for roughly 20 seconds.")
//! @yah:handoff("LANDED AND VERIFIED ON HARDWARE — us-west-001 is back in raft quorum (3/3 voters live). The full method and measurements are in the @yah:verify entry. CODE CHANGE, all in oss/kamaji/crates/kamaji-bin/src/server.rs, uncommitted in the working tree: (1) a `#[cfg(feature = \"native-exec\")]` merge arm in the `List` handler for `ctx.native.list_workloads()`, mirroring the bundle arm; (2) `native-exec` added to `runtime_state_to_entry`'s cfg gate (it already handled the `native-<pid>` container_id spelling — the native runtime IS the same NativeRuntime the bundle backend uses, only keyed on a different identity space); (3) the regression test `a_native_exec_workload_is_visible_in_list`, which asserts presence, `WorkloadState::Running`, a non-zero pid and the mesh_ident yubaba's get_workload matches on. NOT CHANGED: leader.rs. @Ashguard:golem had already split observe_local_appliance's negative arms into three (Ok(Some) non-Running at warn!, Ok(None) at debug!, Err at warn!) while I was reading; that split is correct and I left it alone — B14's first-action log line was answered by reading the code instead, so no diagnostic ship was needed. yubaba on west is UNCHANGED (still the hand-built B13+D2 binary, sha 7f6d24d0...), which is what made this a single-variable experiment.")
//! @yah:verify("REVIEWER: the two claims worth re-deriving rather than taking from me are (a) that `Registry::workloads` has no writer — `rg -n \"workloads\\.push|self\\.workloads\" oss/kamaji/crates/kamaji-bin/src/server.rs` returns only the `list()` read at :808, which is what makes the handler's \"native workloads\" comment false; and (b) that the fleet build actually compiles the new arm — scripts/publish-yubaba-release.sh:173 builds kamaji-bin with `containerd-integration,native-exec,bundle-serving`. Also note the fix does NOT close R858 itself: this restored quorum, it did not give the fleet failover (R858-T4) and it did not touch the redundant SetIngressOwner ERROR a follower still logs on every start (\"failed to set ingress owner in raft: has to forward request to: Some(1)\"), which golem documented as the narrow, real form of D1 and which is still visible in west's journal at 08:23:38.527576Z.")
//! @yah:gotcha("EAST AND SOUTH ARE UNAFFECTED BY THIS BUG, WHICH IS WHY IT ONLY EVER BIT WEST. The merge arm reads `ctx.native`, which is `None` on any node started without `--native-exec-dir` — and per R858-T4 that is exactly east and south. So the defect could only manifest on the one node that can actually run the appliance, and rolling the fix to the other two is a no-op that changes no behaviour there. It should still roll fleet-wide with the next release rather than being hand-installed on west alone.")

use std::collections::BTreeMap;
use std::sync::Arc;

use openraft::async_runtime::watch::WatchReceiver;
use tracing::{debug, error, info, warn};

use kamaji::sibling::{ClientError, KamajiSibling};
use kamaji_proto::NodeCapabilities;

use crate::appliance_ownership::{
    decide_owner, judge_appliance_candidate, judge_self_fence, may_act_on_ownership,
    owner_lease_expired, owner_status, record_is_settled, ApplianceCandidate, ApplianceHealth,
    FenceTiming, NativeExecCapability, OwnerElection, OwnerStatus, OwnershipDecision, SelfFence,
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

    // R858-B13: an `Interval`, NOT a `sleep` future built inside the `select!`.
    //
    // A `tokio::time::sleep(RECONCILE_INTERVAL)` written as a `select!` arm is
    // constructed fresh on every iteration and **dropped** whenever another arm
    // wins, so its deadline restarts from zero each time. The other arm here is
    // the openraft metrics watch, and a raft leader republishes its metrics on
    // every heartbeat and every replication-progress update — several times a
    // second. So the ten-second arm was not merely late, it was unreachable, and
    // `reconcile_appliance_ownership` ran at heartbeat rate: measured on
    // us-west-001 on 2026-09-06 as 132 appliance deploys in one 60-second window
    // (~2.5/s), each one killing the headscale the previous one had forked
    // before it could finish binding its port.
    //
    // An `Interval` holds its next deadline in a value that outlives the
    // `select!`, so cancelling `tick()` does not reset it. That is the whole
    // difference, and it is the kind that does not show up in a code read.
    let mut reconcile_tick = tokio::time::interval(RECONCILE_INTERVAL);
    reconcile_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // `interval` yields its first tick immediately. Consume it here so the loop's
    // own first pass is the reconcile, rather than reconciling and then falling
    // straight through a zero-delay tick into a second one.
    reconcile_tick.tick().await;

    // The first pass reconciles: a starting daemon must discover an appliance it
    // already owns without waiting out a full interval (R858-T3's restart case).
    let mut reconcile_due = true;

    loop {
        let view = {
            let metrics = watch.borrow_watched();
            RaftView {
                is_leader: metrics.current_leader == Some(node_id),
                has_leader: metrics.current_leader.is_some(),
            }
        };
        // R858-B20: folded here, on the metrics watch, not inside the
        // reconciler — the reconciler runs on a 10 s clock of its own and the
        // quantity being measured is contact with the raft channel.
        watcher.observe_leader_contact(view.has_leader);
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
                    // `claim_required: true` — under `FollowsRaftLeader` this
                    // arm runs on the leadership edge, so the node is claiming
                    // ownership it did not previously hold and the record write
                    // is load-bearing (R858-B20).
                    if let Err(e) =
                        on_became_leader(node_id, &raft, &state, machine.clone(), true).await
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
                        &watcher,
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
            // A leadership change is a genuine reason to re-evaluate now instead
            // of at the next tick — it is the one raft event that changes what
            // this node is *allowed* to do (only a leader may claim a vacancy).
            reconcile_due = true;
        }

        // R858-T3: under an elected owner, ownership is evaluated on a CLOCK as
        // well as on leadership edges — see `reconcile_appliance_ownership` for
        // why an edge-only watcher cannot deliver this ticket's own retry rule.
        //
        // R858-B13: and on a clock *only*, plus that edge. Every other metrics
        // wake is skipped, because none of them carries news this function acts
        // on: `ingress_owner` moves through the state machine rather than the
        // metrics channel, so a metrics update tells this node nothing about
        // ownership it did not already know. Reconciling on all of them cost
        // ~2.5 appliance deploys a second on the live coordinator.
        if reconcile_due
            && state
                .cluster_policy
                .ingress_ownership
                .elects_from_eligibility_set()
        {
            reconcile_appliance_ownership(
                node_id,
                view,
                &raft,
                &state,
                &mut watcher,
                machine.clone(),
            )
            .await;
        }
        reconcile_due = false;

        tokio::select! {
            changed = watch.changed() => {
                if changed.is_err() {
                    warn!("raft metrics watch closed — leader watcher exiting");
                    break;
                }
            }
            _ = reconcile_tick.tick() => {
                reconcile_due = true;
            }
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
///
/// R858-B13: this constant was correct and inert for three days. Consuming it as
/// a `sleep` arm of the `select!` in [`run`] meant the metrics watch reset it on
/// every heartbeat, so the reconciler ran at consensus speed anyway — the exact
/// coupling the paragraph above says it removes, reintroduced by the shape of
/// the timer rather than by the number. It is now driven by a
/// [`tokio::time::Interval`] held outside the `select!`; see [`run`] for why that
/// distinction is load-bearing.
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
    /// R858-B20: when this process most recently *established* contact with a
    /// raft leader, or `None` while it has none.
    ///
    /// Not the same question as `has_leader`, which is why it is a separate
    /// field rather than a boolean read off the metrics each tick: `has_leader`
    /// answers "is there a leader right now", and this answers "have I been
    /// hearing from them long enough for my own applied state to mean
    /// anything". Reset to `None` on every loss of contact rather than kept as a
    /// high-water mark, because a node that was partitioned and has just
    /// rejoined is in exactly the position a node that has just booted is in.
    ///
    /// Seeded `None` rather than `Some(now)`: a starting daemon has *not* been
    /// in contact, and seeding it at `now` would make the first reconcile pass —
    /// the one that runs immediately, before any interval has elapsed — read as
    /// settled, which is precisely the pass that started a second coordinator on
    /// the dev group.
    leader_contact_since: Option<std::time::Instant>,
    /// R858-B13: this node started the appliance and has not since **observed**
    /// it running.
    ///
    /// The brake on a crash loop, and the reason it needs one: a successful
    /// `deploy_workload` proves only that the supervisor accepted the workload
    /// and forked it, never that the process is still alive a moment later. On
    /// the live coordinator `headscale` was exiting immediately, so every
    /// reconcile found the appliance gone, re-elected this node, started it
    /// again, and recorded *success* — which clears
    /// [`OwnerElection`]'s failure ledger, so the 30 s backoff that exists for
    /// exactly this could never accumulate.
    ///
    /// A boolean rather than a counter because one unproven start is all the
    /// evidence needed: being asked to start an appliance this node started and
    /// has never seen running is a crash, and the second attempt is where the
    /// ledger has to begin. A restart requested after the appliance *was*
    /// observed running (a teardown, a roll) clears this and is not penalised —
    /// that is R858-T3's follower-restarts-what-it-owns path and it must stay
    /// prompt.
    start_awaiting_proof: bool,
}

impl ApplianceWatcher {
    fn new() -> Self {
        Self {
            election: OwnerElection::new(),
            ownership_confirmed_at: std::time::Instant::now(),
            leader_contact_since: None,
            start_awaiting_proof: false,
        }
    }

    /// Fold one tick's leadership view into [`Self::leader_contact_since`]
    /// (R858-B20).
    ///
    /// Driven from [`run`]'s loop, which turns on the openraft metrics watch, so
    /// contact is measured against the raft channel rather than against the
    /// reconciler's own 10 s cadence. Those are different clocks and using the
    /// slower one would make the settle window an accident of where in the
    /// interval a node happened to boot.
    fn observe_leader_contact(&mut self, has_leader: bool) {
        match (has_leader, self.leader_contact_since) {
            (true, None) => self.leader_contact_since = Some(std::time::Instant::now()),
            (false, _) => self.leader_contact_since = None,
            (true, Some(_)) => {}
        }
    }

    /// How long this process has been continuously in contact with a leader.
    fn leader_contact_for(&self) -> Option<std::time::Duration> {
        self.leader_contact_since.map(|t| t.elapsed())
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
    watcher: &ApplianceWatcher,
    machine: Option<&str>,
) {
    let election = &watcher.election;
    let recorded = recorded_owner(state, node_id, machine);
    let running_here = observe_local_appliance(state).await.is_some();
    let owner = owner_status(recorded, node_id, running_here, election.health());

    // Serving per the record OR per this process's memory OR just started here
    // and not yet judged — any of the three is a reason not to tear the
    // coordinator down for a leadership change.
    //
    // R858-B13 added the third, and it closes a window B13 itself widened.
    // Withholding `record_success` until the appliance is observed running is
    // what makes the crash-loop backoff accumulate — but it also means that for
    // one reconcile interval after a start this process's memory does NOT say
    // `Serving`. Measured on us-west-001 on 2026-09-06 by @Ashguard:hydra: a
    // cold-started follower deployed the appliance at 07:56:49.690 and this
    // function tore it down again at 07:56:49.696, six milliseconds later,
    // because the supervisor had not yet flipped the workload to `Running` and
    // the health verdict was deliberately still withheld. A start that has not
    // been judged is not evidence of *absence*, and stopping on it converts an
    // unproven appliance into a certainly-dead one.
    if appliance_survives_leadership_loss(
        owner,
        node_id,
        election.health(),
        watcher.start_awaiting_proof,
    ) {
        info!(
            node_id,
            unproven_start = watcher.start_awaiting_proof,
            "lost raft leadership while the appliance is up (or is starting) here — ownership is \
             elected, not inherited from leadership (R858-T3); the appliance stays up"
        );
        return;
    }
    on_lost_leader(state).await;
}

/// Does the appliance on this node survive a raft leadership change?
///
/// Split out of [`on_leadership_loss_under_election`] as arithmetic so it can be
/// asserted without a cluster: every input is a value, and the one regression
/// this predicate has already had (R858-B13's unproven-start window, measured on
/// hardware as a six-millisecond gap between a deploy and a teardown) is a
/// property of the *combination* of inputs rather than of any I/O around it.
fn appliance_survives_leadership_loss(
    owner: Option<OwnerStatus>,
    node_id: YubabaNodeId,
    health: &ApplianceHealth,
    start_awaiting_proof: bool,
) -> bool {
    owner.is_some_and(|o| o.node == node_id && o.serving)
        || matches!(health, ApplianceHealth::Serving(_))
        || start_awaiting_proof
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
///
/// @yah:ticket(R858-B13, "Headscale respawn loop: kamaji fork-kills it every ~450ms, port never binds, no backoff")
/// @yah:status(review)
/// @yah:at(2026-09-06T08:14:33Z)
/// @yah:assignee(agent:claude)
/// @yah:parent(R858)
/// @yah:gotcha("MEASURED LIVE on us-west-001, 2026-09-06, after rolling yubaba/kamaji to 0.8.33 (all 3 voters, followers-first-leader-last, via `yah cloud rollout`) and separately seeding `headscale/noise-private-key` into the cluster secret store (R858-T2's declared fix, `.yah/infra/secrets/headscale-noise-private-key.toml` — confirmed 72 bytes, `yah cloud secret put` succeeded, and yubaba's own log confirmed the read: \"headscale noise identity materialized from the cluster secret store — this appliance is portable\"). Neither the roll nor the secret fix stopped this: kamaji's journal shows `native workload forked id=headscale pid=<N>` repeating every ~350-450ms, continuously, for at least 10+ minutes straight (132 occurrences counted in one 60s window). Each cycle yubaba's own log pairs it with \"headscale appliance deployed under kamaji supervision\" `pid:0` (never a real pid) then \"elected appliance owner and the appliance is serving\" then \"ingress owner set in raft state\" — i.e. yubaba believes every cycle succeeded. `ss -lntp` on the box shows NOTHING listening on :443 or :80 at any point sampled. `RECONCILE_INTERVAL` in this file is `Duration::from_secs(10)` — the observed cadence is ~20x faster than that clock, so whatever is firing this is not the intended timer path. `cloud.mesh.yah.dev:443` is refused throughout (direct curl, not just a `tailscale status` read — that command's peer table is separately known-unreliable per `.yah/services/yah-analytics/mirrors/cloud.toml`'s gotcha, not relied on here). Raft leadership is stable throughout (node_id 2 / us-west-001, term unchanged across repeated `/raft/status` reads) — this is NOT a leadership-thrash symptom.")
/// @yah:assumes("UNVERIFIED HYPOTHESIS, not confirmed: `reconcile_appliance_ownership`'s own writes (the \"ingress owner set in raft state\" line = a `SetIngressOwner` raft write) may be re-observed by the same watcher as a state change and re-trigger reconcile immediately, rather than the loop waiting out the full `RECONCILE_INTERVAL` — which would produce exactly this self-sustaining tight cycle regardless of the 10s `tokio::time::sleep` arm, if the `tokio::select!` in `spawn` (line ~333) also wakes on the raft metrics `watch.changed()` arm and that watch fires on the node's own writes. Have NOT read closely enough to confirm the metrics watch actually fires on a self-authored write vs. only on log/membership changes from OTHER nodes — that's the first thing to check. Also unverified: whether R858-T3's in-review, uncommitted changes (defect 1/2/3 fixes in that ticket's handoff) touch this exact path and would incidentally fix or worsen it — they were NOT rolled to this node (0.8.33 predates that ticket's changes per its own handoff), so this bug is independent of and predates T3's fix, but T3's reviewer should check for interaction before landing.")
/// @yah:next("See R858-T1 (griffin) — the headscale-behind-passway migration is already decided (2026-09-05: dedicated passway-mesh per door, loopback :8444, demux-pinned route) and mostly built/proven on east+south; only blocked on R858-B9 giving west its own co-located door before the DNS cutover. This bug's fork-loop is on the SAME file (leader.rs) as R858-T3 (spade, ownership-election redesign, in review) — read both before touching reconcile_appliance_ownership or the deploy path, since T3's uncommitted changes may already touch this exact function.")
/// @yah:gotcha("ROOT CAUSE CONFIRMED ON HARDWARE 2026-09-06 by @Ashguard:hydra (R858-T1), with a controlled single-variable experiment — @Ashguard:golem's read-only diagnosis is correct and needs no live re-derivation. METHOD: `sudo systemctl stop yubaba` on us-west-001, changing nothing else. RESULT: kamaji forks went from 68-per-30s to ZERO, and the headscale child — which had never been observed past etime 00:00 — stayed up immediately and bound *:443 and *:80. So the redeploy loop in yubaba is the killer and kamaji's own RestartPolicy::Always supervises the appliance correctly once yubaba stops redeploying it; \"the port never binds\" is a CONSEQUENCE of the loop, not a second failure. THE MESH WAS RESTORED BY THIS ALONE (cloud.mesh.yah.dev went from connection-refused to HTTP 200, and both doors from 503 to 200).")
/// @yah:gotcha("THIS TICKET IS NOW THE CRITICAL PATH FOR RAFT QUORUM, AND ITS LANDING HAS A MANDATORY LAST STEP. To stop the loop I left us-west-001's yubaba `is-active`=inactive AND `is-enabled`=DISABLED (disabled deliberately: enabled-but-stopped means a reboot silently restarts the thrash and re-breaks the mesh, which is exactly how the \"restored with enable --now\" gotcha on R858 went stale). CONSEQUENCE: the cluster runs at 2/3 quorum — east (node 3) and south (node 1) only, west (node 2) is out — so ANY single voter failure now loses quorum. THE LAST STEP OF LANDING THIS FIX IS `sudo systemctl enable --now yubaba` ON us-west-001; without it the fix buys nothing, because the node it fixes is not running yubaba. ALSO RE-READ YOUR ASSUMPTIONS FIRST: the appliance moved under them. headscale no longer binds 0.0.0.0:443 — it is `listen_addr: 127.0.0.1:8080`, plain HTTP, `tls_letsencrypt_*` deleted, with west's public :443 now owned by passway-demux (-> passway-mesh 127.0.0.1:8444 -> headscale). So no port contention when your fix redeploys. But do NOT POST /headscale/deploy or /headscale/bootstrap at west: those two handlers (lib.rs:5097, :5379) are the only writers of config.yaml and would overwrite the hand-edited file with the 0.0.0.0:443 + Let's Encrypt bootstrap shape, re-creating the outage. A plain yubaba restart is safe — start_headscale does not rewrite config.")
/// @yah:verify("VERIFIED ON PROD HARDWARE 2026-09-06 by @Ashguard:hydra — this fix works and is NOT what blocks west's return to raft. Method: cross-built a musl yubaba from the tree carrying @Ashguard:golem's fix (`scripts/cross-build-guarded.sh yubaba x86_64-unknown-linux-musl '' containerd-integration oss/yubaba`, sha256 d4b3d16da2b684b36e5eae381cd1a9f8884c10476caa4f6fa6ea9082b0505636, static musl ELF; `cargo test -p yubaba --lib` = 766 passed / 0 failed at that tree), installed it on us-west-001 with the previous 0.8.33 anchored at /usr/local/bin/yubaba.rollback-20260906-hydra (sha 8f9f6dab4ad9536080e64f25c5905b46ffa03e5fa499082a3c9a96470127a9ac), ran `systemctl enable --now yubaba`, observed 45s, then rolled back with `systemctl disable --now yubaba`. Total exposure ~90s; mesh verified healthy after rollback (/key?v=138 = 200, /service-records = 200, 0 forks, appliance stable). RESULT: kamaji forks went from 68-per-30s (pre-fix, measured earlier the same day) to 2 per 45s — roughly a 70x reduction — and the new arms announced themselves exactly as designed: `APPLIANCE CRASH-LOOPING: this node started the appliance and it was gone again before it was ever observed running. NOT starting it a second time on this tick — backing off` followed by `APPLIANCE UNHEALTHY: no eligible candidate can run the appliance` with `refusal: deploy-backoff` on a clean 10s cadence and a ~40s retry. So both halves — the Interval-outside-the-select pacing fix and the withheld-record_success/backoff fix — are confirmed on real hardware against a real 3-node raft cluster, not only in the loopback harness. WHAT STILL TEARS THE APPLIANCE DOWN IS R858-T3's ownership code riding the same binary (a follower elects itself, cannot write SetIngressOwner because it is not the leader, and the is_leader edge then fires on_lost_leader -> stop_headscale 4ms after the deploy) — recorded in full on R858-T3, which is in review and should not be signed off as-is.")
/// @yah:handoff("TWO INDEPENDENT DEFECTS IN leader.rs::run, both fixed, and the filed hypothesis was a special case of the first rather than the whole of it. (1) THE 10s CLOCK COULD NOT FIRE ON A LEADER. `tokio::time::sleep(RECONCILE_INTERVAL)` was constructed FRESH INSIDE the `select!`, so every openraft-metrics wake cancelled and rebuilt it from zero — and a raft leader republishes metrics on every heartbeat and every replication-progress update. RECONCILE_INTERVAL was not merely late, it was unreachable; reconcile ran at consensus speed. The filed guess (the node's own SetIngressOwner re-triggering the watch) is true but incidental: ANY metrics update did it. FIX: a `tokio::time::Interval` held OUTSIDE the select (its deadline survives cancellation) plus a `reconcile_due` gate, so reconcile runs on the clock plus genuine leadership edges and on nothing else. (2) A CRASH LOOP WAS RECORDED AS A SUCCESS. `on_became_leader` returning Ok means the supervisor ACCEPTED the workload, never that the process is alive; `record_success` on that CLEARS OwnerElection's ledger, so the 30s backoff could never accumulate a single entry. FIX: the ElectTo(self) Ok arm sets `start_awaiting_proof` instead of recording success; success is recorded only where `observe_local_appliance` has actually SEEN the appliance running; and being asked to start an appliance this node started and has never seen running is now a `record_failure` + `APPLIANCE CRASH-LOOPING` error, putting the node on the 30/60/120/240/300s ladder.")
/// @yah:verify("VERIFIED ON PRODUCTION HARDWARE by @Ashguard:hydra (R858-T1), who cross-built musl from this tree and ran it on us-west-001 for ~90s inside a rollback window: kamaji forks went from 68-per-30s to 2-per-45s, and the backoff announced itself with this ticket's exact log lines (`APPLIANCE CRASH-LOOPING: ... NOT starting it a second time on this tick`, then `APPLIANCE UNHEALTHY: ... refusal: deploy-backoff` on a clean 10s cadence, retrying at ~40s). They had already isolated the cause independently: `systemctl stop yubaba` alone took forks 68-per-30s to 0 and headscale immediately stayed up and bound *:443 and *:80 — so \"the port never binds\" is a CONSEQUENCE of the loop, not a separate failure.")
/// @yah:verify("TWO HARNESS TESTS, ONE PER DEFECT, EACH FALSIFIED AGAINST ITS OWN — and two tests rather than one because a negative result forced it. `oss/yubaba/crates/yubaba/tests/raft_appliance_ownership.rs`, real 3-node openraft on loopback, one FakeRuntime per node. (a) `the_appliance_reconciler_runs_on_its_own_clock_not_at_raft_heartbeat_rate` — counts `get_workload` calls (one per reconcile pass) on the owner over 12s. PASSES at 1-2. Probe: restore the pre-B13 select (drop the `reconcile_due` gate, rebuild the timer as `sleep` inside the select) -> FAILS at 50 in 12s. (b) `a_crash_looping_appliance_is_retried_on_the_backoff_not_on_every_pass` — a reaper kills the appliance ~10ms after every deploy; asserts the gap to the retry is >= BACKOFF_BASE_SECS. PASSES at ~40s. Probe: restore `election.record_success(node_id)` on the start path -> FAILS at 9.886s, exactly one RECONCILE_INTERVAL. THE NEGATIVE RESULT, recorded because it is the reason for the split: with only (b) present, reintroducing the PACING defect left it GREEN — the backoff bounds deploys whatever the loop rate is — and with only (a) present, reintroducing `record_success` left THAT green. A single test covering both would have been a false green. An earlier rate-bound version of (b) was also discarded as vacuous by measurement: over a 45s window a correct backoff admits 2 redeploys and the broken path admits 4, which no honest bound separates; the GAP separates them exactly.")
/// @yah:verify("LOCAL SUITES, all after the D2 follow-up landed: `cargo test -p yubaba --lib` = 770 passed / 0 failed (766 before, +4 new `leader::tests`). `cargo test -p yubaba --features testing --test testing -- --test-threads 1` = 28 passed / 0 failed / 1 pre-existing ignored, in 206s. `cargo test -p yubaba --test main -- --test-threads 4` = 64 passed / 0 failed. `cargo test -p kamaji --features testing --lib` = 71 passed / 0 failed. `cargo clippy -p yubaba --features testing --lib --tests` = ZERO findings on leader.rs or raft_appliance_ownership.rs; `cargo clippy -p kamaji --features testing --lib` has one finding on fake.rs:280 (`let first = ...; first` inside `check_fault`) which is PRE-EXISTING and in code this ticket did not touch. rustfmt applied to the three changed files ONLY — `cargo fmt` would have reformatted peers' dirty files. ONE FLAKE, ATTRIBUTED, NOT A REGRESSION: at `--test-threads 2` the `testing` suite failed `a_resurrected_owner_is_fenced_and_cannot_serve` (R858-T7's). It passes alone in 52.6s and passed in the serial full run; it is a 52s wall-clock-sensitive fence test now sharing a loaded machine with this ticket's 41s one. Use `--test-threads 1` for this suite.")
/// @yah:handoff("A THIRD FIX, DISCOVERED FROM HARDWARE AND MINE TO MAKE — the leadership-edge teardown. @Ashguard:hydra's prod run caught west deploying the appliance at 07:56:49.690 and `on_leadership_loss_under_election` killing it at 07:56:49.696, six milliseconds later. That is a regression THIS TICKET widened, not a pre-existing T3 bug: the predicate kept the appliance if `owner.serving` OR this process's `ApplianceHealth` was `Serving`, and pre-B13 `record_success` fired microseconds after the deploy so the second term always caught it. Withholding that success is exactly what makes the backoff accumulate, so B13 opened a one-reconcile-interval window in which neither term holds. FIX: a third term, `start_awaiting_proof` — an unproven start is not evidence of absence, and stopping on it converts an unproven appliance into a certainly-dead one. The predicate is extracted as `leader::appliance_survives_leadership_loss(owner, node_id, health, start_awaiting_proof)` so it is assertable as arithmetic, with 4 unit tests including a precondition assert that the OLD input shape still returns false — so the test fails if anyone later widens it into \"never stop anything\".")
/// @yah:handoff("FILES, and the tree anchor is fc754ce6ac4671d4705727df8764ba4e4381aa0d — quote that SHA, never HEAD, in any revert instruction. UNCOMMITTED; verify by CONTENT, not by `git status`. (1) `oss/yubaba/crates/yubaba/src/leader.rs` — grep `reconcile_tick`, `start_awaiting_proof`, `appliance_survives_leadership_loss`. (2) `oss/yubaba/crates/yubaba/tests/raft_appliance_ownership.rs` — appended, grep `a_crash_looping_appliance_is_retried_on_the_backoff`. Already registered via `tests/testing.rs`; no Cargo.toml change needed. (3) `oss/kamaji/crates/kamaji/src/fake.rs` — a DIFFERENT WORKSPACE, easy to miss when reverting: two additive read-only counters on `FakeRuntime`, `deploy_calls()` (attempts, recorded before the fault check) and `get_workload_calls()`, mirroring the existing `graceful_upgrade_calls()`. Both exist because no registry snapshot can show a control loop's RATE — a redeploy of an already-Running workload leaves the snapshot byte-identical, so a hundred deploys a second and a healthy steady state look identical from outside. ALSO IN leader.rs, ON REQUEST AND NOT MINE: `observe_local_appliance`'s arms were split three ways and the two informative ones raised to `warn!` for @Ashguard:hydra's R858-B14. No behaviour change — every arm still returns `None`.")
/// @yah:gotcha("B13 BOUNDS THE DAMAGE; IT DOES NOT MAKE THE APPLIANCE CONVERGE — do not read \"verified on hardware\" as \"west is fixed\". Two things measured by @Ashguard:hydra on 2026-09-06 remain open and both are outside this ticket. (a) R858-B14: `observe_local_appliance` appears never to return `Some` on the live node, so `start_awaiting_proof` is never discharged and the owner cycles start -> \"gone\" -> record_failure -> backoff -> retry, forever. B13 turns that from ~2.5 forks/second into a 30/60/120/240/300s ladder with a loud `APPLIANCE CRASH-LOOPING` line, which is strictly better and is all this ticket claims. THE HARNESS CANNOT REPRODUCE B14 — its `FakeRuntime` answers `get_workload` correctly — so the green tests here say nothing about it. (b) `/raft/status` members carry NO `machine` key on any of the three voters (measured), so `node_for_machine` returns None and the REMOTE half of `recorded_owner` is dead on the live fleet. That is R858-T3's own `@yah:assumes`, now confirmed rather than suspected; it does not affect a node resolving ITSELF (that path compares the record to this node's own machine name directly), which is why west still took the elect path.")
/// @yah:gotcha("us-west-001's yubaba is STOPPED AND DISABLED as of 2026-09-06 (@Ashguard:hydra, deliberate — so a reboot cannot restart the thrash), so the raft cluster is at 2/3 with NO margin and any single voter failure now loses quorum. `sudo systemctl enable --now yubaba` on west is the last step of landing this fix and it must not be forgotten. NOTE what changed under this ticket's feet while it was being worked: headscale no longer binds 0.0.0.0:443. It is `listen_addr: 127.0.0.1:8080`, plain HTTP, `tls_letsencrypt_*` removed, with west's public :443 served by passway-demux -> passway-mesh(127.0.0.1:8444) -> headscale, and all three doors now answering /key?v=138 at 200. That config.yaml is HAND-EDITED and live: `start_headscale` does not rewrite it (only the `POST /headscale/deploy` and `/headscale/bootstrap` handlers do, lib.rs:5097 and :5379), so a plain yubaba restart preserves it — but do NOT POST /headscale/deploy at west, that would overwrite it with the 0.0.0.0:443 + Let's Encrypt bootstrap shape and re-break the mesh.")
/// @yah:assumes("SCOPE, STATED SO NOBODY READS THIS TICKET AS HAVING SETTLED IT: B13 did NOT touch `listen_addr`, `headscale_appliance::appliance_spec`, `demux_routes.rs`, or anything on the ownership/deploy path beyond the two pacing/backoff defects and the teardown regression they created. The 2026-09-06 operator decision that headscale must sit behind passway-demux rather than binding :443 is R858-T1's and R858-T3's, and T1 executed the live half of it while this was in flight. ONE UNVERIFIED THING I DID NOT CHASE, flagged because a redeploy would surface it: if a node ever DOES take the elect path on west now, `backend.deploy_workload(&appliance_spec(...))` declares the workload's ports to kamaji from the SPEC, not from the hand-edited config.yaml — and `headscale_appliance.rs` had an unattributed 2-line uncommitted change in the tree during this pass that I did not author and did not read. Whoever rolls should read those two lines first: a spec still declaring :443 would collide with the demux even though config.yaml says 127.0.0.1:8080.")
/// @yah:gotcha("THE THING THAT KILLED HEADSCALE EVERY ~450ms IS THE REDEPLOY ITSELF, NOT THE TEARDOWN — verified from code 2026-09-06 across two crates, and it CORRECTS a reading of R858-T1's own hardware trace. (1) `NativeRuntime::deploy_workload` (oss/kamaji/crates/kamaji/src/native.rs, ~:763) opens by calling `self.teardown_workload(&ident)` — SIGTERM, 5s grace, SIGKILL — and only then forks. So every redeploy of an already-running native workload kills the previous child by construction. That is the `native workload forked id=headscale pid=<N>` cadence and the `ps` child stuck at etime 00:00. (2) Meanwhile yubaba's own teardown CANNOT kill it: `leader::stop_headscale` calls `backend.teardown_workload(&ident)`, `KamajiClient::teardown_workload` (oss/kamaji/crates/kamaji/src/sibling.rs:833) is `self.stop(&id)`, and `stop_workload` (oss/kamaji/crates/kamaji-bin/src/server.rs:3488) routes to containerd, tenant-passway, bundle, microvm and docker with NO `ctx.native` arm. It Acks and does nothing. CONSEQUENCE FOR THE 07:56:49.696 LINE in T1's D2 trace: `headscale appliance torn down on leadership loss` is logged on `Ok(())` from that Ack, so the teardown did not kill the appliance — the next redeploy did. The D2 window is real and the fix is right, but on today's fleet a spurious teardown is INERT.")
/// @yah:gotcha("SEQUENCING CONSTRAINT FOR WHOEVER GIVES kamaji's `stop_workload` ITS MISSING `ctx.native` ARM — that fix is safe WITH B13 and dangerous WITHOUT it, and the order is not obvious from either ticket alone. Today `leader::stop_headscale` Acks and kills nothing on a native-exec appliance, so every spurious teardown path in yubaba is harmless by accident. Give `stop_workload` a native arm and each of those paths starts actually killing the mesh coordinator. B13's D2 fix (`start_awaiting_proof` as a third term in `appliance_survives_leadership_loss`) is the thing that removes the spurious teardown this would arm — it is currently latent-correct rather than load-bearing, and it becomes load-bearing the moment that arm lands. SO: ship the kamaji `Stop` fix only in a binary that also carries B13, and never to a node still running the fleet's 0.8.33 yubaba, which has neither the pacing fix nor D2. This is an argument for landing B13, not against the kamaji fix.")
///
/// @yah:ticket(R858-B20, "A resurrected dead owner elects itself off its own stale raft record and runs a second coordinator for ~10s, replicating a losing DB into the shared replica")
/// @yah:status(review)
/// @yah:at(2026-09-08T22:16:28Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R858)
/// @yah:severity(high)
/// @yah:gotcha("MEASURED ON THE DEV RAFT GROUP 2026-09-08 by @Ashguard:libra (session:18023eec) during R858-T8's rehearsal, from us-west-011's own journal after a hard reset (`systemctl reboot -ff`, no clean shutdown). THE SEQUENCE, every line read from a journal. 21:00:44 us-west-011 (the recorded ingress_owner) vanishes. 21:01:18 us-west-013, the raft leader, expires it (expire_after_secs=30) and takes over; 21:01:20 it restores the DB from litestream, starts headscale, and writes SetIngressOwner{us-west-013} at raft index 129. 21:02:39 us-west-011 finishes booting. 21:02:40.369 it logs `litestream restore skipped: headscale.db already exists — serving the local DB`. 21:02:40.546 kamaji forks a SECOND headscale on that stale local DB. 21:02:40.574 the claim write FAILS — `failed to set ingress owner in raft: has to forward request to: Some(13)` — proving it was never the leader and had no standing to elect; yet on_became_leader returns Ok and leaves the appliance running. 21:02:40.574 it logs `elected appliance owner and started the appliance`. 21:02:50.264 — NINE POINT SEVEN SECONDS LATER — the R858-T7 fence finally fires with `record-names-another-node`, reason RecordNamesAnotherNode { owner: 13 }, and tears it down.")
/// @yah:gotcha("THE HARM IS NOT HYPOTHETICAL AND IT IS NOT THE SECOND HTTP SERVER — IT IS THE REPLICA. on_became_leader step 3 starts the litestream sidecar after the start, so the fenced node replicated its STALE DB into the shared prefix: at 21:02:43 us-west-011's litestream wrote WAL segments to s3://yah-headscale/dev on generation e01101da3a30f8da, the pre-failover generation, 82 SECONDS AFTER the winning node's generation 17578973eecfbf58 began at 21:01:21. `litestream generations` then showed e01101da3a30f8da with end=2026-09-08T21:02:43Z beside 17578973eecfbf58 with start=21:01:21Z — two live branches of one database in one prefix. A restore issued inside that 82s window selects by latest end and would have picked the LOSING branch. Measured afterwards (`litestream restore -o /tmp/probe`): it now picks 17578973eecfbf58, because the winner kept writing — so the pollution is latent, not active, and only because nothing failed twice in 82 seconds. leader.rs's fence path already states this exact risk in a comment (\\\"a fenced node must also stop replicating, or it goes on pushing frames from a losing database into the shared litestream replica the new owner restores from\\\") — the fence does call on_lost_leader, it just calls it ~7s after the frames have already landed.")
/// @yah:gotcha("ROOT CAUSE, INFERRED FROM THE CODE PLUS THE MEASURED TIMELINE (the inference is the middle step; the endpoints are measured). `reconcile_appliance_ownership` gates everything on `may_act = is_leader || recorded == Some(node_id)` and the R858-T7 fence on `confirmed_now = has_leader && recorded == Some(node_id)`. Both read `recorded_owner`, which reads THIS NODE'S OWN raft state machine. A node that has just booted replays its persisted log and, for a window, its SM holds the PRE-FAILOVER record naming itself — us-west-011 at 21:02:40 had not yet applied index 129. So the node reads its own name, `may_act` passes, `confirmed_now` is true so the fence stays silent, and it starts a coordinator. The fence is designed to run first precisely so \\\"a node that must not be serving must also not be electing\\\" — it is defeated because the node's own stale replica AGREES with it. The observer polled us-west-011's /cluster/singletons at 21:02:38 (\\\"none\\\") and 21:02:41 (\\\"us-west-013\\\"), bracketing the 21:02:40.52 reconcile that read Some(11): the window is roughly one raft catch-up, and it is a function of log length and boot speed, so PROD's window is not bounded by dev's 9.7s.")
/// @yah:next("THREE CANDIDATE FIXES AND THE CHOICE IS AN ARCHITECT CALL — do not pick one without deciding, because a wrong pick re-arms split brain rather than merely failing to fix it. (a) LINEARIZE THE READ: require the node's SM to be caught up to the leader's committed index before `recorded_owner` is trusted on the elect path — openraft's read-index/ensure_linearizable. Correct, and costs a round trip per reconcile tick (10s cadence, so cheap); the objection is that it makes a reconcile pass depend on quorum reachability, which is exactly when you least want it to. (b) BOOT BARRIER: refuse to act on the ownership record until this process has applied at least one entry from the CURRENT term. Cheapest, no extra RPC, and it directly matches the failure (a stale replay can only produce old-term entries) — but it does nothing for a node that was partitioned rather than rebooted. (c) DISTRUST SELF-RECORDS ENTIRELY: drop `recorded == Some(node_id)` from `may_act` so only the raft leader may start an appliance. Simplest, but it deletes the deliberate R858-T3 property that a non-leader owner may restart what it already owns, which is what decouples ownership from leadership. RECOMMEND (b) FIRST as the narrow, testable fix, with (a) layered on if a partition case is ever demonstrated.")
/// @yah:next("A SECOND, INDEPENDENT HALF THAT NEEDS FIXING WHICHEVER OF (a)/(b)/(c) WINS, and it is a two-line discrimination rather than a design call. `on_became_leader` step 4 treats a failed `SetIngressOwner` as cosmetic — it logs `error!` and returns Ok(()), with a comment arguing \\\"the appliance IS up; only the record is missing... the next tick re-writes it\\\". That reasoning holds for a transient write error and is FALSE for the error actually measured, `has to forward request to: Some(13)`, which means this node is not the leader: the next tick will never write it, and the node has just started a coordinator it can never legitimately claim. Distinguish ForwardToLeader from a transient failure and, on ForwardToLeader, stop the appliance you just started rather than returning Ok. That alone would have cut the measured 9.7s window to roughly the deploy round trip.")
/// @yah:verify("REPRODUCTION IS CHEAP AND THE RIG IS UP: on the dev group (us-west-011/013/014, `yah@192.168.10.{11,13,14}`, key ~/.ssh/yah with `-o IdentitiesOnly=yes`), `sudo systemctl reboot -ff` on whichever node /cluster/singletons names as ingress_owner, then read that node's yubaba journal from the moment it boots. The tell is the pair `elected appliance owner and started the appliance` followed by `FENCED: ... record-names-another-node` — if both appear for the same boot, the window is still open. A harness version belongs in oss/yubaba/crates/yubaba/tests/raft_appliance_ownership.rs beside `a_resurrected_owner_is_fenced_and_cannot_serve`, which passes today precisely because it does not model a stale local SM: the fix is only proven when a test starts the resurrected node with an SM replayed to the PRE-failover index and asserts it never deploys.")
/// @yah:gotcha("HEAD CARRIES A BROKEN INTERMEDIATE OF THIS FIX — DO NOT CUT A RELEASE FROM c0976aa0 WITHOUT THE UNCOMMITTED REMAINDER. A peer's wip-commit c0976aa0 (\\\"sync, retag v0.8.35\\\") swept this ticket's work into HEAD MID-SESSION, at a point where the `ForwardToLeader` backstop was still spelled `)) if claim_required => {` — the unqualified form. That form is MEASURED BROKEN: it fails `a_powered_off_owner_expires_and_the_appliance_comes_up_on_a_survivor` with a 90 s timeout, reproducibly and in isolation, because a freshly elected leader's `client_write` transiently returns `ForwardToLeader`, the unqualified guard reads that as fatal, and `OwnerElection` charges the new owner a 30 s backoff on the very tick it won the election. The working tree has the correction (`names_another_leader(&fwd, node_id)`, plus its helper) and the full suite is green with it. THE COMMIT MESSAGE SAYS \\\"retag v0.8.35\\\", so if 0.8.35 was re-cut at that SHA it ships a yubaba whose appliance failover is SLOWER AND FLAKIER THAN BEFORE THIS TICKET — a regression wearing a fix's name. Verify before releasing: `git show HEAD:oss/yubaba/crates/yubaba/src/leader.rs | grep -n 'if claim_required'` must show the `&& names_another_leader` form, not the bare one.")
/// @yah:handoff("FIXED, TWO PARTS, AND THE SECOND ONE TOOK THREE ATTEMPTS BECAUSE THE FIRST TWO BROKE OTHER TESTS — recorded because the wrong versions are plausible and someone will re-derive them. (1) THE SETTLE GATE, the primary fix. `FenceTiming` gains `settle_after` = 1x down_after (5 s fleet, 1.5 s rig), derived by the same constructor as the other two so the ordering is a property of the code rather than of two constants; `appliance_ownership::record_is_settled(leader_contact_for, timing)` is the predicate; `ApplianceWatcher` gains `leader_contact_since: Option<Instant>`, seeded NONE (not `now`) and reset to None on every loss of contact, folded in `run()`'s loop off the openraft metrics watch rather than the reconciler's own 10 s clock. Both `confirmed_now` and the act gate now require it. The act gate is EXTRACTED as `may_act_on_ownership(is_leader, recorded, node_id, settled)` for the reason `appliance_survives_leadership_loss` was — a three-term boolean whose failure mode is one term being too weak cannot be asserted inline. The two clauses are deliberately asymmetric: a LEADER needs no settle term, because it has applied everything it committed; only a reader of somebody else's committed record can be behind. (2) THE BACKSTOP: a `SetIngressOwner` that fails is now fatal — tearing down what was just started — but ONLY when the claim was load-bearing AND raft names a different leader.")
/// @yah:handoff("WHY THE BACKSTOP NEEDS BOTH QUALIFIERS, each learned from a test that went red — this is the part worth reading before touching it. FIRST ATTEMPT: any `ForwardToLeader` is fatal. That broke `a_follower_that_owns_the_appliance_restarts_it_without_a_leadership_change` (45 s timeout), because R858-T3's SUPPORTED path is a non-leader owner restarting the appliance it already owns; its `SetIngressOwner` is a redundant re-assertion of a record that already names it, the write fails purely because it is not the leader, and raising there tore down the appliance it had just legitimately restarted. Qualified with `claim_required = recorded != Some(node_id)`, threaded in from the caller rather than re-read inside `on_became_leader` so it cannot disagree with the read `may_act` was decided on. SECOND ATTEMPT: still broke `a_powered_off_owner_expires_and_the_appliance_comes_up_on_a_survivor` (90 s timeout), because a FRESHLY ELECTED leader also gets `ForwardToLeader` in the window before it establishes itself — so the node that just won the election was charged a 30 s `OwnerElection` backoff and never stood the appliance up inside the budget. Qualified further with `names_another_leader(&fwd, node_id)`: fatal only when `fwd.leader_id` is `Some(other)` and other != me, which is exactly the shape measured on hardware (`has to forward request to: Some(13)` at node 11). `None` or `Some(me)` is transient and the next tick retries.")
/// @yah:handoff("DELIBERATELY NOT DONE, with the reason, so it is not re-litigated. The exactly-correct primitive here is a linearizable read against the leader, and openraft 0.10.0-alpha.30 HAS one — but `Raft::ensure_linearizable` asserts LEADERSHIP and errors on a follower (read at its source: \\\"Err if fails to assert leadership\\\"), and the follower-read form, `get_read_linearizer`, needs the read log id fetched from the leader over a channel this crate does not have. The two cheap local alternatives were both checked against the measured case and both fail it: the raft TERM does not change during an appliance failover (leadership never moved — only ownership did, so node 11 rebooted into term 74 having last applied a term-74 entry), and `last_applied` does not advance on a cluster where nothing else is being written. So elapsed leader contact is the honest available evidence, denominated in the same currency as every other `FenceTiming` deadline. IT IS A BOUND, NOT A PROOF, and the doc comment on `record_is_settled` says so — which is precisely why the backstop exists alongside it. A follow-up worth its own ticket, NOT filed because it needs a design call rather than a fix: plumb a follower read-index so `settled` becomes provable instead of timed.")
/// @yah:verify("FALSIFIED, single variable, against the real 3-node openraft harness. New test `a_rebooted_owner_does_not_start_a_coordinator_off_its_stale_record` (oss/yubaba/crates/yubaba/tests/raft_appliance_ownership.rs) PASSES with the fix; restore `may_act_on_ownership` to the pre-B20 body and it FAILS with `left: 2, right: 1` — the rebooted node deployed while the record named test-node-3, which is the hardware bug reproduced in the harness.")
/// @yah:verify("The new test models a REBOOT, not the suspend its sibling models: it tears the appliance out of the dead node's runtime so `observe_local_appliance` answers None and the path under test is the one that STARTS a coordinator rather than the one that stops one. Non-vacuity is two-sided — the deploy counter is snapshotted before the restart and compared across a window in which the node was demonstrably alive, and a survivor must be serving throughout, or the returning node's claim would be legitimate and refusing it would be the bug.")
/// @yah:verify("SUITES, all re-run after the final `names_another_leader` correction and after rustfmt: `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib` = 830 passed / 0 failed (828 before, +2 new unit tests). `cargo test -p yubaba --features testing --test testing -- --test-threads 1` = 29 passed / 0 failed / 1 pre-existing ignored, 269 s — INCLUDING the two tests the intermediate versions broke. `cargo clippy -p yubaba --features testing --lib --tests` = zero findings on leader.rs, appliance_ownership.rs or raft_appliance_ownership.rs. rustfmt applied to those three files ONLY, never `cargo fmt` (it would reformat peers' dirty files).")
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
    //
    // R858-B20 adds `settled` to what was `has_leader` alone. `has_leader` was
    // carrying the whole freshness argument and could not: it turns `true` the
    // instant this node learns who the leader is, which on a just-booted daemon
    // is before it has received anything from them, so `recorded` is still the
    // node's own replayed pre-failover state. A record naming *this* node, read
    // in that window, is not a confirmation of anything — it is the last thing
    // this node believed before it died.
    // Read before the `ApplianceWatcher` destructure below borrows the whole
    // struct; both values are plain `Copy` snapshots of this tick.
    let leader_contact = watcher.leader_contact_for();
    let settled = record_is_settled(leader_contact, timing);
    let confirmed_now = has_leader && settled && recorded == Some(node_id);
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

    // ── R858-B13, THE DISCHARGE ──────────────────────────────────────────────
    //
    // Observing the appliance running on this node is the ONLY thing that turns
    // a start into a success, and this is where that happens — not in a
    // `decide_owner` arm. Two reasons it has to be here:
    //
    //   * `record_success` clears the backoff ledger, so it must be reachable
    //     from every arm a healthy just-started appliance can land in, or a
    //     recovered node stays in backoff it has already earned its way out of.
    //   * On a node with no machine name nothing writes `ingress_owner`, so the
    //     *only* thing that can make `owner_status` see an owner at all is this
    //     process's own `ApplianceHealth`. Withholding the success until some
    //     later arm records it would leave that node re-electing and
    //     re-deploying itself on every tick — the bug this ticket is about,
    //     moved rather than fixed.
    if running_here.is_some() && watcher.start_awaiting_proof {
        watcher.start_awaiting_proof = false;
        watcher.election.record_success(node_id);
        info!(
            node_id,
            "the appliance this node started is now observed running — recording the start as \
             successful (R858-B13)"
        );
    }

    // Destructured rather than `&mut watcher.election`, because the arms below
    // need both fields at once and one whole-struct borrow would not allow it.
    let ApplianceWatcher {
        election,
        start_awaiting_proof,
        ..
    } = watcher;
    let owner = owner_status(recorded, node_id, running_here.is_some(), election.health());

    // Only the leader may claim a vacancy; any node may restart what it is
    // already recorded as owning. A follower with neither has nothing to do —
    // and, importantly, nothing to *say*: reaching the refusal arms below on
    // every tick of every follower would turn this ticket's loud channel into
    // the noise operators learn to skip.
    //
    // R858-B20: the non-leader half is `settled`-gated. The leader half is not,
    // and does not need to be — a leader has applied every entry it committed,
    // so its own view is authoritative by construction. It is only the *reader*
    // of somebody else's committed record who can be behind.
    let may_act = may_act_on_ownership(is_leader, recorded, node_id, settled);
    if !may_act {
        // Said once per unsettled tick, and only by a node that would otherwise
        // have acted — a follower with no claim at all still returns silently.
        // The distinction matters because this line means "I am withholding an
        // action I believe I am entitled to take", which is worth reading.
        if recorded == Some(node_id) {
            info!(
                node_id,
                settle_after_secs = timing.settle_after.as_secs(),
                leader_contact_ms = leader_contact.map(|d| d.as_millis() as u64),
                "this node's own applied record names it as appliance owner, but it has not been \
                 in contact with a raft leader long enough for that to mean anything yet — \
                 withholding until the record settles (R858-B20)"
            );
        }
        return;
    }

    let now = unix_now_secs();
    // R858-T5: BEFORE the probe, not after. See `hydrate_config_before_probe`.
    hydrate_config_before_probe(&state.headscale_dir, state.headscale_url.as_deref());
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
                // R881-T4: `Some` because a native fork+exec IS bound on this
                // address — `workload_bind_ip` agrees for exactly this spec
                // (`binds_node_ports` covers `yah.exec = native`), and passing
                // it here would only re-derive an address this branch already
                // resolved with more information than that function has.
                state
                    .service_records
                    .upsert_deployed(&spec, Some(mesh_ip), &observed.container_id);
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
            // ── R858-B13, THE BRAKE ──────────────────────────────────────────
            //
            // Reached when this node started the appliance and the appliance is
            // gone again without ever having been seen running. That is a crash
            // loop, and the pre-B13 answer to it was to start it once more —
            // forever, at whatever rate the loop ticked, with `record_success`
            // wiping the backoff ledger on each pass so nothing ever slowed
            // down. Recording it as the failure it is puts this node into
            // `OwnerElection`'s 30→60→120→240→300 s backoff, which
            // `judge_appliance_candidate` reads, so the next tick reports
            // `APPLIANCE UNHEALTHY: no eligible candidate` instead of forking a
            // process that cannot live.
            if *start_awaiting_proof {
                error!(
                    node_id,
                    round_exhausted = election.round_exhausted(),
                    "APPLIANCE CRASH-LOOPING: this node started the appliance and it was gone \
                     again before it was ever observed running. NOT starting it a second time \
                     on this tick — backing off instead, so the process is not respawned faster \
                     than it can bind its ports (R858-B13)"
                );
                election.record_failure(
                    node_id,
                    now,
                    "the appliance exited before it was observed running after a successful start",
                );
                // Cleared, so the brake is a BACKOFF and not a permanent stop:
                // the ledger now paces the retries (30 → 60 → 120 → 240 → 300 s)
                // and the next attempt to survive that backoff must be allowed
                // to happen. Leaving it armed would convert the first crash into
                // a coordinator this node never tries to start again.
                *start_awaiting_proof = false;
                // Nothing half-started is left behind: the supervisor already
                // reports it gone, which is how this arm was reached.
                return;
            }
            match on_became_leader(node_id, raft, state, machine, recorded != Some(node_id)).await {
                Ok(()) => {
                    // NOT `record_success` — deliberately, and this is the whole
                    // of R858-B13's second half. `on_became_leader` returning
                    // `Ok` means the supervisor accepted the workload, not that
                    // the process is alive; a success recorded here clears the
                    // backoff ledger and makes a crash loop indistinguishable
                    // from a healthy appliance. The success is recorded on the
                    // `OwnerServing` arm above, once the appliance has actually
                    // been observed running.
                    *start_awaiting_proof = true;
                    info!(
                        node_id,
                        "elected appliance owner and started the appliance — success is recorded \
                         once it is observed running (R858-B13)"
                    );
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
/// Render `config.yaml` if this node has none, *before* [`probe_native_exec`]
/// judges whether this node could host the appliance.
///
/// # Why this is not inside `start_headscale` (R858-T5)
///
/// It was, and the two halves deadlocked. R858-T16 hydrates `config.yaml` as a
/// pre-start step of [`start_headscale`]; R858-T4's probe refuses candidacy
/// when any argv path — including that same `config.yaml` — is missing. So a
/// node that has never hosted the appliance could never become eligible to run
/// the hydration that would have made it eligible. MEASURED on us-west-011
/// 2026-09-08 with a binary carrying both children: `missing=…/config.yaml` →
/// `APPLIANCE UNHEALTHY … refusal: missing-native-exec`, on a ten-second
/// cadence, forever, on a node with the binary, the noise key and a kamaji that
/// reports `native_exec: true`.
///
/// That is precisely R858's own acceptance check — "`probe_native_exec`
/// returning `Present` on us-south-001, which today returns `Absent` naming
/// config.yaml" — and until this ran first it could not pass anywhere.
///
/// # Only when absent
///
/// The early return is load-bearing, not an optimisation. [`hydrate_config`]
/// deliberately never overwrites (us-west-001's live `config.yaml` is
/// hand-edited, and clobbering it re-decapitates the mesh), and calling it on
/// every ten-second tick of every acting node would log a line per tick for the
/// life of the process. Checking first keeps this silent on the node that is
/// already provisioned and loud exactly once on the node that is not.
///
/// [`hydrate_config`]: headscale_state::hydrate_config
fn hydrate_config_before_probe(headscale_dir: &std::path::Path, server_url: Option<&str>) {
    if headscale_appliance::config_path(headscale_dir).exists() {
        return;
    }
    match headscale_state::hydrate_config(headscale_dir, server_url) {
        Ok(outcome) => info!(
            ?outcome,
            "hydrated headscale config.yaml ahead of the appliance candidacy probe"
        ),
        Err(e) => warn!(
            "could not hydrate headscale config.yaml ({e}) — this node will refuse candidacy \
             until it exists"
        ),
    }
}

async fn probe_native_exec(state: &Arc<ServerState>) -> NativeExecCapability {
    probe_native_exec_with(
        state
            .constable_client
            .as_ref()
            .and_then(KamajiSibling::current)
            .map(|client| async move { client.capabilities().await }),
        &[
            headscale_appliance::binary_path(&state.headscale_dir),
            headscale_appliance::config_path(&state.headscale_dir),
        ],
    )
    .await
}

/// [`probe_native_exec`] with its two host dependencies passed in.
///
/// `ask` is `None` when there is no sibling to ask — the in-process-runtime
/// fallback — and `Some(future)` otherwise. It is deliberately *not* flattened
/// to an `Option<NodeCapabilities>` by the caller: "there was nobody to ask" and
/// "the one we asked did not answer" reach the same verdict for different
/// reasons, and collapsing them upstream would leave this function unable to say
/// which happened and a test unable to tell the two branches apart.
///
/// `argv_paths` are the host paths the deploy's own argv names — the binary and
/// the config file — threaded from [`headscale_appliance::binary_path`] and
/// [`headscale_appliance::config_path`] rather than re-derived, so a probe can
/// never bless a node for a layout the spec would not run. Every one of them
/// must exist: `headscale serve --config <missing>` exits immediately into
/// [`RestartPolicy::Always`], which turns "this node cannot serve" from a
/// refusal placement can act on into a crash loop that looks like a deploy.
///
/// [`RestartPolicy::Always`]: workload_spec::RestartPolicy::Always
async fn probe_native_exec_with<F>(
    ask: Option<F>,
    argv_paths: &[std::path::PathBuf],
) -> NativeExecCapability
where
    F: std::future::Future<Output = Result<NodeCapabilities, ClientError>>,
{
    let Some(ask) = ask else {
        debug!("no kamaji sibling to ask about native-exec — capability stays Unknown");
        return NativeExecCapability::Unknown;
    };

    let caps = match ask.await {
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
        // The remedy names a DROP-IN, not a roll, because that is what was
        // measured. On 2026-09-06 us-south-001 was already running published
        // 0.8.33 — the shipped `kamaji.service` has carried `--native-exec-dir`
        // all along — and still reported `native_exec: false`, because
        // `/etc/systemd/system/kamaji.service.d/20-bundle.conf` (R599-T5, dated
        // 2026-07-21) resets `ExecStart=` and re-declares the whole command
        // line, freezing the flag set as it stood before the flag existed.
        // Rolling the node reinstalls the base unit and changes nothing.
        error!(
            "this node's kamaji has no native backend: it cannot run the appliance and is \
             refusing candidacy UP FRONT rather than failing the deploy after ownership has \
             moved. `systemctl cat kamaji.service` and look for a drop-in that resets \
             `ExecStart=` — one that predates `--native-exec-dir` silently drops it, and \
             rolling the node will NOT fix that. Set the drop-in's extra options through \
             `Environment=KAMAJI_BUNDLE_CACHE_DIR=`/`KAMAJI_BUNDLE_ORIGIN=` instead of \
             re-declaring ExecStart, so the shipped unit stays the one source of the flag set"
        );
        return NativeExecCapability::Absent;
    }

    if let Some(missing) = argv_paths.iter().find(|p| !p.exists()) {
        error!(
            missing = %missing.display(),
            native_exec_dir = caps.native_exec_dir.as_deref().unwrap_or("<unreported>"),
            "this node's kamaji can fork native workloads but a path the appliance's own argv \
             names is not on disk: a native workload pulls nothing, so forking it here would \
             exit immediately and crash-loop rather than serve"
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
    // R858-B14: both negative arms speak at `warn!`, and they say WHICH negative
    // they are. This probe answering `None` forever is indistinguishable, from
    // every caller, from an appliance that is genuinely down — so the node goes
    // on re-electing and re-starting a coordinator that is already serving, and
    // at `debug!` the fleet's log level hides the one line that would say why.
    // R858-B13's backoff bounds how fast that happens; only this line says what
    // it is.
    match backend.get_workload(&ident).await {
        Ok(Some(w)) if matches!(w.status, kamaji::WorkloadStatus::Running) => Some(w),
        Ok(Some(w)) => {
            warn!(
                ident = %ident.0,
                status = ?w.status,
                "the supervisor knows the appliance but does not report it Running — treating it \
                 as not running here"
            );
            None
        }
        Ok(None) => {
            debug!(
                ident = %ident.0,
                "the supervisor has no workload under this identity — the appliance is not \
                 placed here"
            );
            None
        }
        Err(e) => {
            warn!(
                ident = %ident.0,
                "could not ask the supervisor about the appliance ({e:#}) — treating it as not \
                 running here, which will make this node re-elect and re-start an appliance that \
                 may already be serving (R858-B14)"
            );
            None
        }
    }
}

/// This node's own [`NodeEligibility`], for the single-node candidate set in
/// [`reconcile_appliance_ownership`].
///
/// A node executing this line is live by construction — it is the raft leader,
/// it is running, and its own raft peer link is trivially healthy — so those two
/// gates are asserted rather than measured. `admits` is `true` because the
/// appliance is a [`LifecycleArchetype::Appliance`]: pinned and non-drainable,
/// so it is not subject to the tenant headroom bin-packing `admits` exists for
/// (R858-T3 change 4 — no priority class is needed to express that).
///
/// The gates that *are* measured for this node are the appliance-specific ones
/// [`judge_appliance_candidate`] adds: native-exec capability
/// ([`probe_native_exec`]) and deploy-failure backoff.
///
/// [`LifecycleArchetype::Appliance`]: workload_spec::LifecycleArchetype::Appliance
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
    // R858-B20: is the `SetIngressOwner` write below load-bearing, or a
    // redundant re-assertion of a record that already names this node? Only the
    // first makes a `ForwardToLeader` refusal fatal. Passed in rather than
    // re-derived here, because the caller has already read `recorded` for this
    // tick and a second read could disagree with the one `may_act` was decided
    // on.
    claim_required: bool,
) -> Result<(), ApplianceStartError> {
    let headscale_db = state.headscale_dir.join("headscale.db");

    // 1. Write the litestream config the replicate unit started in step 3
    //    reads (`litestream -config /etc/yah-cloud/litestream.yml`). R591-T3:
    //    `install` MUST come first — until that ticket nothing called it at
    //    all, so on every node the sidecar start failed against a unit that
    //    had never been written, into a discarded exit status. Installing
    //    here rather than at provision time also means a node that becomes
    //    the ingress owner years after it was provisioned still gets a config
    //    matching the S3 URL this yubaba was actually started with.
    //
    //    R858-F17: the restore leg that used to run here is gone. Hydrating
    //    `headscale.db` before start is now kamaji's job, driven by the
    //    `yah.durability.*` declaration on the appliance's `WorkloadSpec`
    //    (`headscale_appliance::appliance_spec`) — see `start_headscale`
    //    below, which is where kamaji's hydrate-on-place actually runs.
    if let Some(s3_url) = &state.litestream_s3_url {
        if let Err(e) = litestream::install(&headscale_db, s3_url) {
            warn!(
                "litestream install failed ({e:#}) — replication will not run on this node"
            );
        }
    }

    // 2. Start headscale as a kamaji-supervised appliance. Everything below is
    //    conditional on this, which is the R858-T3 change. Kamaji hydrates
    //    `headscale.db` from turso-backup before forking the appliance
    //    (R858-F17) — see the `yah.durability.*` declaration this spec
    //    carries.
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
            // ── R858-B20, THE BACKSTOP ───────────────────────────────────────
            //
            // `ForwardToLeader` is not a transient write failure and must not be
            // treated as one. It means this node is NOT the raft leader, so the
            // reasoning below — "the next tick re-writes it" — is false: no tick
            // of this node will ever write it. What has actually happened is
            // that a node reached the elect path on a record naming itself,
            // started a coordinator, and cannot claim it. That is one half of a
            // split brain, and it is exactly what a resurrected owner produced
            // on the dev group on 2026-09-08 while its stale database
            // replicated into the shared litestream prefix.
            //
            // Raising it is what makes the caller's `Err` arm run
            // `on_lost_leader`, which stops both the appliance and the
            // replication. NOT forwarded through `raft::client_write_forwarded`,
            // deliberately, even though that helper exists and every other
            // off-leader write in this crate uses it: forwarding would make the
            // leader *accept* a stale node's claim and overwrite the correct
            // record with it, converting a caught error into silent data loss.
            // The refusal is the point.
            Err(openraft::error::RaftError::APIError(
                openraft::error::ClientWriteError::ForwardToLeader(fwd),
            )) if claim_required && names_another_leader(&fwd, node_id) => {
                return Err(ApplianceStartError::ClaimRefused {
                    leader: fwd
                        .leader_id
                        .map_or_else(|| "unknown".to_string(), |id| id.to_string()),
                });
            }
            // The two survivors of that guard, both benign, both measured:
            //
            //  * `claim_required == false` — the record ALREADY names this node,
            //    so the write was a redundant re-assertion and refusing it costs
            //    nothing. This is R858-T3's non-leader owner restarting the
            //    appliance it owns, and raising here tore that appliance back
            //    down; `a_follower_that_owns_the_appliance_restarts_it_without_a_leadership_change`
            //    caught it.
            //  * `names_another_leader == false` — openraft returned
            //    `ForwardToLeader` without naming somebody else, which is what a
            //    *freshly elected* leader emits in the window before it has
            //    established itself. Treating that as fatal put the new owner
            //    into `OwnerElection`'s 30 s backoff on the very tick it won the
            //    election, and
            //    `a_powered_off_owner_expires_and_the_appliance_comes_up_on_a_survivor`
            //    then timed out at 90 s. The next tick retries, which is the
            //    correct answer to "not ready yet".
            Err(openraft::error::RaftError::APIError(
                openraft::error::ClientWriteError::ForwardToLeader(_),
            )) => debug!(
                claim_required,
                "the ingress-owner record was not written on this pass — either it already names \
                 this node, or raft has not settled on a leader yet. Retrying on the next tick \
                 (R858-B20)"
            ),
            // Everything else keeps the original reading, and it is still the
            // right one: the appliance IS up, only the record is missing, and
            // re-electing away from a node that is serving would be the flap
            // R858-T3 exists to prevent. The next tick re-writes it.
            Err(e) => error!("failed to set ingress owner in raft: {e}"),
        }
    }

    Ok(())
}

/// Does this `ForwardToLeader` name a leader that is definitively **not** this
/// node (R858-B20)?
///
/// The distinction the backstop turns on, and it is not decoration. Two very
/// different situations share the one error type:
///
///  * `leader_id: Some(other)`, `other != me` — measured on us-west-011 on
///    2026-09-08 as `has to forward request to: Some(13)`. Raft has a leader and
///    it is somebody else, so this node had no standing to elect itself and
///    never will on any later tick. Fatal.
///  * `leader_id: None`, or `Some(me)` — raft has not settled, or this node *is*
///    the leader but is not yet able to serve the write. Transient: the next
///    reconcile tick retries. Reading it as fatal charges a 30 s backoff to a
///    node that just legitimately won the election.
fn names_another_leader(
    fwd: &openraft::error::ForwardToLeader<crate::raft::YubabaRaftConfig>,
    node_id: YubabaNodeId,
) -> bool {
    fwd.leader_id.is_some_and(|id| id != node_id)
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

    // R858-T16: the THIRD hydration step, beside the litestream DB restore in
    // `on_became_leader` and the noise key above. The appliance's argv names two
    // paths and only the binary was ever placed outside the promote handlers, so
    // a node that was never hand-promoted forked `headscale serve --config
    // <missing>` and crash-looped under `RestartPolicy::Always`.
    //
    // WRITE ONLY IF ABSENT, and see `hydrate_config`'s doc for why that is not
    // timidity: us-west-001's live config.yaml is hand-edited, this function
    // runs on every leadership acquisition, and an unconditional render would
    // re-decapitate the mesh on the next restart.
    //
    // A write failure is logged, not raised. The node simply stays without a
    // config, and `probe_native_exec` already refuses to place the appliance
    // there — the refusal exists and does not need a second spelling.
    match headscale_state::hydrate_config(&state.headscale_dir, state.headscale_url.as_deref()) {
        Ok(outcome) => debug!(?outcome, "headscale config.yaml hydration"),
        Err(e) => error!(
            dir = %state.headscale_dir.display(),
            "could not hydrate headscale config.yaml ({e}) — this node cannot host the appliance \
             until one is placed"
        ),
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
                // No `pid` field, deliberately (R858-T8). On the sibling path
                // `DeployResult::task_pid` is structurally 0 — `KamajiClient`
                // acks on *admission*, before the fork — so this line printed
                // `pid=0` on every live deployment while kamaji's own
                // `native workload forked id=headscale pid=<N>` sat one line
                // above it in the same journal. A field that is always zero is
                // worse than an absent one: it reads as "the appliance has no
                // pid", which is the shape of a failed start.
                info!(
                    mesh_ip = %mesh_ip,
                    "headscale appliance deployed under kamaji supervision"
                );
                // R591-T2: publish the placement so every front door can find
                // it. `leader.rs` deploys straight through the backend rather
                // than through `POST /workloads/deploy`, so it must upsert the
                // record the HTTP handler would have — without this the
                // appliance runs but `GET /service-records` never mentions it,
                // and an ingress proxy has nothing to follow.
                // R881-T4: `Some` — the appliance is `yah.exec = native`, a
                // forked host process bound on the address it just reported.
                state
                    .service_records
                    .upsert_deployed(&spec, Some(result.mesh_ip), &result.container_id);
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
    /// R858-B20: the appliance started, but this node could not record itself as
    /// the owner because it is not the raft leader.
    ///
    /// A start that cannot be claimed is not a start — it is the second half of
    /// a split brain. The variant exists so the caller tears down what it just
    /// stood up rather than leaving an unclaimable coordinator running.
    ClaimRefused { leader: String },
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
            Self::ClaimRefused { leader } => write!(
                f,
                "started the appliance but could not claim ownership: raft says the leader is \
                 {leader}, not this node, so nothing here will ever write the record. This node \
                 acted on an ownership record it had no standing to act on — stopping what it \
                 started rather than leaving a coordinator the cluster does not know about \
                 (R858-B20)"
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

#[cfg(test)]
mod tests {
    use super::*;

    const SELF: YubabaNodeId = 2;
    const OTHER: YubabaNodeId = 1;

    /// The regression R858-B13 introduced into R858-T3's teardown and then
    /// closed, measured on us-west-001 before it was closed.
    ///
    /// The node has just started the appliance. The supervisor has not yet
    /// flipped the workload to `Running` (six milliseconds had passed on the
    /// live box), so `owner.serving` is false. `ApplianceHealth` is deliberately
    /// **not** `Serving` either — withholding that until the appliance is
    /// observed running is what makes the crash-loop backoff accumulate at all.
    /// Both of the pre-B13 reasons to keep the appliance are therefore absent,
    /// and without the third the leadership edge stops a coordinator this node
    /// started six milliseconds ago.
    #[test]
    fn a_just_started_appliance_is_not_torn_down_by_a_leadership_change() {
        let owner = Some(OwnerStatus {
            node: SELF,
            serving: false,
        });
        assert!(
            !appliance_survives_leadership_loss(owner, SELF, &ApplianceHealth::Vacant, false),
            "precondition: without the unproven-start term this is exactly the input that tore \
             the appliance down on us-west-001 — if this now returns true the test is asserting \
             nothing"
        );
        assert!(
            appliance_survives_leadership_loss(owner, SELF, &ApplianceHealth::Vacant, true),
            "a node that started the appliance and has not yet been able to judge it must not \
             stop it for a leadership change — an unproven start is not evidence of absence \
             (R858-B13)"
        );
    }

    /// The unproven-start term must not become a blanket "never stop anything".
    /// A node with nothing started and nothing recorded still cleans up on the
    /// edge, which is the whole reason the teardown is edge-shaped.
    #[test]
    fn a_node_with_no_appliance_still_tears_down_on_leadership_loss() {
        assert!(!appliance_survives_leadership_loss(
            None,
            SELF,
            &ApplianceHealth::Vacant,
            false
        ));
    }

    /// R858-T3's own rule, re-asserted here because B13 rewrote the expression
    /// that carries it: a serving owner keeps serving through a leadership
    /// transfer. This is the 2026-09-03 outage in one line.
    #[test]
    fn a_serving_owner_keeps_the_appliance_through_a_leadership_transfer() {
        let owner = Some(OwnerStatus {
            node: SELF,
            serving: true,
        });
        assert!(appliance_survives_leadership_loss(
            owner,
            SELF,
            &ApplianceHealth::Vacant,
            false
        ));
    }

    /// And it is scoped to THIS node. A record naming someone else, over a local
    /// process with no appliance of its own, is not a reason for this node to
    /// keep anything — that direction is the fence's, not the teardown's.
    #[test]
    fn a_record_naming_another_node_does_not_keep_an_appliance_here() {
        let owner = Some(OwnerStatus {
            node: OTHER,
            serving: true,
        });
        assert!(!appliance_survives_leadership_loss(
            owner,
            SELF,
            &ApplianceHealth::Vacant,
            false
        ));
    }

    // ── R858-T4: probe_native_exec ───────────────────────────────────────────
    //
    // Both `Unknown` branches are asserted SEPARATELY and on purpose. They are
    // one verdict reached two ways, and the permissive reading is the whole
    // safety property here: an `Absent` returned for either would make every
    // node that cannot be asked ineligible, which mid-roll is most of the fleet
    // and is the 2026-09-03 outage reproduced from the other side.

    /// The type annotation the `None` arm needs — never awaited.
    type NeverAsked = std::future::Ready<Result<NodeCapabilities, ClientError>>;

    fn caps(native_exec: bool) -> NodeCapabilities {
        NodeCapabilities {
            native_exec,
            native_exec_dir: Some("/var/lib/yah/kamaji/native".into()),
            microvm: kamaji_proto::MicroVmHealth {
                attached: false,
                kvm_ok: None,
                detail: None,
            },
        }
    }

    /// The argv paths as the probe threads them, over a scratch `headscale_dir`.
    fn argv_paths(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        vec![
            headscale_appliance::binary_path(dir),
            headscale_appliance::config_path(dir),
        ]
    }

    /// A node with every argv path on disk — the fully-provisioned case.
    fn provisioned() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for p in argv_paths(dir.path()) {
            std::fs::write(&p, b"#!/bin/true\n").unwrap();
        }
        dir
    }

    /// R858-T5, the deadlock between T4's probe and T16's hydration. A node
    /// carrying the binary but no `config.yaml` — every failover target the
    /// fleet has — is `Absent` until something renders it, and the thing that
    /// renders it used to sit downstream of this verdict. Measured on
    /// us-west-011 before the fix; pinned here so it cannot come back by moving
    /// the hydration call.
    #[tokio::test]
    async fn hydrating_the_config_first_is_what_turns_a_fresh_candidate_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            headscale_appliance::binary_path(dir.path()),
            b"#!/bin/true\n",
        )
        .unwrap();

        // Before: the binary is there, kamaji says yes, and the node still
        // refuses — naming the file the hydration step would have written.
        assert_eq!(
            probe_native_exec_with(
                Some(std::future::ready(Ok(caps(true)))),
                &argv_paths(dir.path())
            )
            .await,
            NativeExecCapability::Absent,
            "a node with no config.yaml must refuse candidacy",
        );

        hydrate_config_before_probe(dir.path(), Some(COORDINATOR_URL));

        assert_eq!(
            probe_native_exec_with(
                Some(std::future::ready(Ok(caps(true)))),
                &argv_paths(dir.path())
            )
            .await,
            NativeExecCapability::Present,
            "hydration is what makes a fresh node an eligible failover target",
        );
    }

    /// The early return is the guard on us-west-001's hand-edited `config.yaml`:
    /// this runs on every acting node's ten-second tick, so an unconditional
    /// render would rewrite that file forever — R858-T16's re-decapitation
    /// hazard, reintroduced through a new door.
    #[test]
    fn hydration_before_the_probe_never_touches_a_config_that_is_already_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = headscale_appliance::config_path(dir.path());
        std::fs::write(&path, b"hand-edited: do not clobber\n").unwrap();

        hydrate_config_before_probe(dir.path(), Some(COORDINATOR_URL));

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "hand-edited: do not clobber\n",
        );
    }

    /// No coordinator URL means nothing can be rendered. The node must stay
    /// refusing rather than write a config the appliance cannot serve from.
    #[test]
    fn hydration_before_the_probe_writes_nothing_without_a_coordinator_url() {
        let dir = tempfile::tempdir().unwrap();
        hydrate_config_before_probe(dir.path(), None);
        assert!(!headscale_appliance::config_path(dir.path()).exists());
    }

    /// The in-process-runtime fallback: nobody to ask. Not knowing is not a
    /// refusal.
    #[tokio::test]
    async fn no_kamaji_sibling_leaves_the_capability_unknown() {
        let dir = provisioned();
        assert_eq!(
            probe_native_exec_with(None::<NeverAsked>, &argv_paths(dir.path())).await,
            NativeExecCapability::Unknown,
        );
    }

    /// A kamaji that predates the `Capabilities` variant fails the frame, and a
    /// transient socket error looks the same from here. Neither is evidence
    /// about the backend.
    #[tokio::test]
    async fn a_kamaji_that_does_not_answer_leaves_the_capability_unknown() {
        let dir = provisioned();
        let ask = std::future::ready(Err(ClientError::Unexpected("Ack { .. }".into())));
        assert_eq!(
            probe_native_exec_with(Some(ask), &argv_paths(dir.path())).await,
            NativeExecCapability::Unknown,
        );
    }

    /// us-south-001 on 2026-09-03: kamaji started without `--native-exec-dir`.
    /// Only a kamaji that answers, and answers no, produces `Absent` — and this
    /// is the one refusal that has to happen BEFORE ownership moves. Every argv
    /// path is present, so the verdict can only come from the backend answer.
    #[tokio::test]
    async fn a_kamaji_with_no_native_backend_is_absent() {
        let dir = provisioned();
        let ask = std::future::ready(Ok(caps(false)));
        assert_eq!(
            probe_native_exec_with(Some(ask), &argv_paths(dir.path())).await,
            NativeExecCapability::Absent,
        );
    }

    /// The other half of the same measured gap: south had no binary either. A
    /// native workload pulls nothing, so the flag without the executable refuses
    /// the deploy just as hard.
    #[tokio::test]
    async fn a_capable_kamaji_with_no_appliance_binary_is_absent() {
        let dir = provisioned();
        std::fs::remove_file(headscale_appliance::binary_path(dir.path())).unwrap();
        let ask = std::future::ready(Ok(caps(true)));
        assert_eq!(
            probe_native_exec_with(Some(ask), &argv_paths(dir.path())).await,
            NativeExecCapability::Absent,
        );
    }

    /// us-south-001 and us-east-001 as of 2026-09-06, after this pass placed the
    /// binary on both: kamaji capable, binary present, and STILL not a candidate
    /// — nothing in the leader path writes `config.yaml` (R858-B9: only
    /// `POST /headscale/deploy`/`/bootstrap` do), so a node that was never
    /// promoted has one argv path and not the other. Forking there exits
    /// immediately and crash-loops under `RestartPolicy::Always`, which is why
    /// this must be a refusal and not a `Present`.
    #[tokio::test]
    async fn a_node_with_the_binary_but_no_config_is_absent() {
        let dir = provisioned();
        std::fs::remove_file(headscale_appliance::config_path(dir.path())).unwrap();
        let ask = std::future::ready(Ok(caps(true)));
        assert_eq!(
            probe_native_exec_with(Some(ask), &argv_paths(dir.path())).await,
            NativeExecCapability::Absent,
        );
    }

    // ── R858-T16: config.yaml hydration ─────────────────────────────────────

    /// The coordinator URL a fleet node carries in `YUBABA_HEADSCALE_URL`.
    const COORDINATOR_URL: &str = "https://cloud.mesh.yah.dev";

    /// The positive twin of `a_node_with_the_binary_but_no_config_is_absent`:
    /// us-south-001 as of 2026-09-06 — kamaji capable, binary present, noise key
    /// materialized, config absent — becomes a candidate once
    /// `start_headscale`'s third hydration step has run. This is the whole
    /// ticket: the refusal was correct and the missing argv path is now placed
    /// by the leader path instead of only by the promote handlers.
    #[tokio::test]
    async fn a_node_whose_config_was_hydrated_becomes_a_candidate() {
        let dir = provisioned();
        std::fs::remove_file(headscale_appliance::config_path(dir.path())).unwrap();
        let ask = std::future::ready(Ok(caps(true)));
        assert_eq!(
            probe_native_exec_with(Some(ask), &argv_paths(dir.path())).await,
            NativeExecCapability::Absent,
            "precondition: without the config this node is refused"
        );

        assert_eq!(
            headscale_state::hydrate_config(dir.path(), Some(COORDINATOR_URL)).unwrap(),
            headscale_state::ApplianceConfig::Rendered,
        );

        let ask = std::future::ready(Ok(caps(true)));
        assert_eq!(
            probe_native_exec_with(Some(ask), &argv_paths(dir.path())).await,
            NativeExecCapability::Present,
        );
    }

    /// And hydration NEVER clobbers a config that is already there. us-west-001's
    /// live `config.yaml` is hand-edited (R858-B9's loopback cutover), and
    /// `start_headscale` runs on every leadership acquisition — so an
    /// unconditional render would overwrite it on the next yubaba restart and
    /// reproduce the 2026-09-03 decapitation through a different door. Drift is
    /// reported, not corrected.
    #[test]
    fn hydration_leaves_an_existing_config_exactly_as_it_found_it() {
        let dir = provisioned();
        let path = headscale_appliance::config_path(dir.path());
        let hand_edited = "# hand-edited on the live coordinator\nlisten_addr: 127.0.0.1:8080\n";
        std::fs::write(&path, hand_edited).unwrap();

        assert_eq!(
            headscale_state::hydrate_config(dir.path(), Some(COORDINATOR_URL)).unwrap(),
            headscale_state::ApplianceConfig::KeptWithDrift,
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), hand_edited);
    }

    /// Every fact true is the only way to `Present`, which is what makes
    /// `Present` worth acting on.
    #[tokio::test]
    async fn a_capable_fully_provisioned_node_is_present() {
        let dir = provisioned();
        let ask = std::future::ready(Ok(caps(true)));
        assert_eq!(
            probe_native_exec_with(Some(ask), &argv_paths(dir.path())).await,
            NativeExecCapability::Present,
        );
    }

    /// The probe must ask about the paths the deploy would actually use. Both
    /// sides come from [`headscale_appliance`]'s two exported helpers; this pins
    /// that the spec's argv still names exactly those, so a future layout change
    /// breaks a test rather than blessing a node the spec would crash on.
    #[test]
    fn the_probed_paths_are_the_ones_the_spec_names() {
        let dir = std::path::PathBuf::from("/var/lib/yah-cloud/headscale");
        let spec = headscale_appliance::appliance_spec(&dir);
        let argv = spec.command.clone().unwrap_or_default();
        for probed in argv_paths(&dir) {
            let probed = probed.to_string_lossy().into_owned();
            assert!(
                argv.contains(&probed),
                "placement checks {probed} for existence, but the deploy's argv is {argv:?} — a \
                 probe that gates on a path the spec does not use is a placement lie in either \
                 direction"
            );
        }
    }
}
