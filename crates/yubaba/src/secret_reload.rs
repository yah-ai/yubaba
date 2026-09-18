//! Rotation → live reload of cluster-secret file mounts (R600-F4 / W273).
//!
//! The single elected ACME issuer (R600-F3) re-issues the fleet cert and writes
//! the fresh ciphertext into raft via `PutSecret`. That replicated write bumps
//! the node's fleet secret epoch ([`crate::secret_watch`]) on every
//! node. This module is the consumer of that watch: on each bump it re-renders
//! the affected workloads' tmpfs `File` mounts in place (via F2's
//! [`ClusterResolver`]) and then asks kamaji to **graceful-upgrade** the
//! consuming workload so the new cert goes live without dropping connections.
//!
//! ## Why a debounce
//!
//! F3 writes the cert as two records — key first, cert last (see the F4 handoff
//! note). Each `PutSecret` bumps the epoch, so a naive "upgrade on every bump"
//! would fire once on the new-key/old-cert intermediate state, serving a
//! mismatched pair for a sub-second window. Instead, on the first bump we wait a
//! short [`DEBOUNCE`] window (longer than F3's inter-write gap) and coalesce any
//! further bumps, so by the time we resolve, both records are the new pair. A
//! per-workload content digest then gates the actual upgrade: an epoch bump that
//! doesn't change a given workload's resolved bytes (a different secret rotated,
//! or a snapshot install that replayed identical state) is a no-op for it — no
//! spurious connection-dropping reload.
//!
//! ## Rolling reload (interim)
//!
//! Every node observes the same replicated `PutSecret` at ~the same instant, so
//! a naive "reload now" would blip every ingress at once. Until the container
//! backends do a truly zero-downtime handoff (R600-F7), each node waits a
//! per-node [`rolling_stagger`] offset before its reload pass, so a fronting
//! load balancer routes around the one draining node and the *fleet* stays up.
//! This is a mitigation, not a fix: per-node in-flight connections still drop on
//! the container backends until F7. `Backend::Native` is already zero-downtime,
//! so the stagger there is merely a harmless delay.
//!
//! ## Trust boundary
//!
//! Decryption stays in yubaba (the KEK never leaves the node); the re-rendered
//! plaintext lives only in the host tmpfs file and the container's read-only
//! bind, exactly as at initial materialization (R600-F6). This task never logs
//! secret bytes.
//!
//! @yah:ticket(R600-F10, "Deliver the R600 fleet cert to the systemd-managed passway doors: nothing on a non-kamaji node consumes a cluster secret")
//! @yah:at(2026-09-08T20:41:52Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R600)
//! @yah:next("CUTOVER ORDER MATTERS. While per-node ACME and the fleet issuer both exist, the issuer must not request east's exact SAN set or it shares east's Let's Encrypt duplicate-certificate bucket (see R853-B7). Sequence: materialize -> point one door at the shared files with PASSWAY_TLS_MODE=manual -> verify -> repeat on the second -> only then remove the per-node ACME config. Once no node self-issues, the bucket question dies and south.origin.yah.dev can be dropped from south's SAN set.")
//! @yah:verify("The issuer half is already proven live as of 2026-09-05: a 40-acme-issuer.conf drop-in on east + south elects a single issuer over the raft lock acme-issuer/yah.dev against LE STAGING. Sign-off for this ticket is a door serving a cert it never issued: stop the per-node ACME on one origin, confirm openssl s_client against that IP returns the fleet cert, and confirm a re-issue propagates to it with no manual step.")
//! @yah:gotcha("THE GAP THAT KEPT R600 UNDEPLOYED, found 2026-09-05 while fixing R853-B7. All nine R600 children are in review, but the chain terminates at a consumer that does not exist on the live fleet. secret_reload::run walks DEPLOYED WorkloadSpecs holding a SecretMount and calls deploy::secret_mount::rerender_file_secrets — it is a documented no-op until a workload with a cluster File secret is deployed on the node. The two live yah.dev origins are hand-rolled systemd units (passway-test.service on us-east-001, passway.service on us-south-001) reading /var/lib/passway/{cert,key}.pem, NOT kamaji workloads. So R600-F5 (SecretMount Cluster -> File + PASSWAY_TLS_MODE=manual) has nothing to attach to, and enabling the issuer alone produces a replicated cert nobody serves.")
//! @yah:next("STATE AS LEFT 2026-09-05: /etc/systemd/system/yubaba.service.d/40-acme-issuer.conf is installed on us-east-001 and us-south-001 (LE STAGING, YUBABA_ACME_CONSUMERS=ingress, CF token copied to /var/lib/yah/yubaba/cf-token), both yubabas restarted clean and both are in standby. It is NOT on us-west-001, the current raft leader, so no order has been placed and no cluster secret exists yet. Completing that step means restarting yubaba on the leader, which is deliberately left as an operator call while R858 is open — us-west-001 is the node that hosts headscale, and R858 records that leadership movement decapitates the mesh by construction.")
//! @yah:gotcha("A CONFIGURED ISSUER ON A NON-LEADER IS INDISTINGUISHABLE FROM A BROKEN ONE. Measured live 2026-09-05: with the drop-in on us-east-001 and us-south-001, both logged 'acme issuer: watching (single issuer elected via raft lock acme-issuer/yah.dev)' at startup and then NOTHING for 6+ minutes — no issuance, no warning, no error. Cause is correct behaviour badly reported: run() gates the whole tick on `raft.metrics().current_leader == Some(node_id)` (acme_issuer.rs:401) to avoid ForwardToLeader spam, and IssuerAction::Standby logs nothing. us-west-001 (100.64.0.1) held leadership, and it had no issuer config, so no node ever attempted AcquireLock. An operator watching the journal sees a healthy-looking start line and a silent process. Fix shape: log the standby reason once on transition (leader vs lock-loser are different states and should read differently), and/or surface issuer state on an endpoint. Practical consequence for deployment: the drop-in must go on EVERY voter, not just the ingress nodes, because any voter can hold leadership.")
//! @yah:next("LEADER RESTART HELD 2026-09-05 despite being operator-authorised, because the premise the authorisation rested on turned out to be false (see the leader-health gotcha). us-west-001 holds raft leadership AND is running the freshly-recovered headscale appliance; a yubaba restart there drops leadership, R858's chain says the appliance is torn down on leadership loss, and neither other voter can stand it up. Coordinating with the live R858 session instead. The issuer stays in standby on east + south, which costs nothing while no consumer exists.")
//! @yah:gotcha("/mesh/leader-health LIES ABOUT HEADSCALE, and it nearly cost an outage. On 2026-09-05 all three voters reported {\"leader\":...,\"headscale\":\"stopped\"} while headscale was demonstrably RUNNING on us-west-001 — pid 517125, bound *:443 and *:80, started 01:54Z, and cloud.mesh.yah.dev/health returned 200 from the public internet. The field appears to read the systemd unit state (`systemctl is-active headscale` = inactive) while kamaji supervises the process as a native workload, so a healthy appliance reads as dead. I used that field to argue a leader restart was low-risk, and it was not. Told the live R858 session (session:83093d9d) directly; R858 owns the fix.")
//! @yah:next("DELIBERATE LIMITATION worth reading before extending: the reload command is a shell string the operator writes, and for today's doors the honest value is `systemctl restart passway` — which DROPS in-flight connections on that origin. passway cannot hot-swap a cert (tls.rs \"The reload gap\": TlsSettings is static), and its zero-downtime path needs a REPLACEMENT process started with PASSWAY_UPGRADE=true before the old one gets SIGQUIT — orchestration no systemd unit on either node has wired. The rolling stagger means only one origin cycles at a time and the other keeps serving, so the fleet stays up; a single origin blips. Wiring the graceful-upgrade dance for a systemd door is the follow-on, and it is the same machinery R600-F7/F9 are settling for the kamaji case.")
//! @yah:handoff("MATERIALIZER BUILT 2026-09-05 (operator chose the thin-yubaba-module option over moving the doors onto kamaji). NEW oss/yubaba/crates/yubaba/src/cert_materialize.rs: resolves tls/<domain>/{cert,key} through the SAME ClusterResolver + resolve_secrets path every other consumer uses (so the R706 access check cannot be skipped — there is no constructor that omits the consumer), writes the pair atomically to two configured paths, and runs one configured reload command only when the bytes actually changed. Opt-in on YUBABA_CERT_FILES_DOMAIN and completely inert without it; also required: _CERT_PATH, _KEY_PATH, _CONSUMER (must match the issuer's YUBABA_ACME_CONSUMERS), optional _RELOAD_CMD. Reuses secret_reload's DEBOUNCE and rolling_stagger (both widened to pub(crate), no behaviour change) so the issuer's key-first/cert-last pair is never observed half-rotated and a fleet-wide rotation does not cycle every origin at once. Spawned next to secret_reload in main.rs. cargo test -p yubaba --lib = 681 passed / 0 failed, 8 of them new; cargo check -p yubaba --bins clean.")
//! @yah:gotcha("NOT PROVEN AGAINST A REAL CLUSTER SECRET, and cannot be until the issuer runs. The 8 unit tests cover config parsing (including the chain-overwrites-the-key footgun and each required key), the mount shapes the issuer's own naming produces, 0600 on the key, digest order-independence, and atomic write + mode + no leftover temp files. What they do NOT cover is the end-to-end path, because no tls/yah.dev/* record exists anywhere yet — the issuer is in standby on east + south and the leader restart that would start it is held (see the R858 coordination note). Treat the live behaviour as unverified until a cert actually lands.")
//! @yah:next("THE 'DELIBERATE LIMITATION' BULLET IS OBSOLETE AS OF R870-T3 (2026-09-06) — do not set YUBABA_CERT_FILES_RELOAD_CMD to `systemctl restart passway`. Set it to `systemctl reload <unit>`. A door carrying /etc/systemd/system/<unit>.service.d/passway-graceful-upgrade.conf (app/yah/cli/resources/) now has an ExecReload= that spawns a replacement with PASSWAY_UPGRADE=true, waits for it to bind PASSWAY_UPGRADE_SOCK, SIGQUITs the old pid, and blocks until systemd's MainPID is the replacement. passway sends the MAINPID=/READY=1 datagram that makes that handover legal (oss/passway/crates/passway/src/sd_notify.rs); Type=simple could not, because the draining process's exit deactivates the unit and kills the replacement with it. NOT YET INSTALLED ON ANY DOOR — the drop-in is node state and the first activation costs one deliberate `systemctl restart` in a chosen window. Two install preconditions the drop-in states: the door's env must pin PASSWAY_UPGRADE_SOCK to a per-instance path (unset it is pingora's shared /tmp/pingora_upgrade.sock and a node runs two passways), and TimeoutStartSec must be raised because Type=notify makes a slow first ACME order fatal.")
//! @yah:gotcha("THE 'DROP-IN MUST GO ON EVERY VOTER BECAUSE ANY VOTER CAN HOLD LEADERSHIP' GOTCHA ON THIS TICKET IS NOW OBSOLETE IN THE TREE (not yet on the fleet). The leadership gate it described is GONE as of this pass: acme_issuer::run no longer tests `current_leader == Some(node_id)`; every configured node asks for the acme-issuer/<domain> lock each tick via the new raft::client_write_forwarded, so the lock IS the election exactly as W273 specifies. Consequence: the drop-in belongs on whichever nodes you want ELIGIBLE to issue, and issuer identity no longer moves on every raft election. THE OBSOLESCENCE IS TREE-ONLY UNTIL A ROLL — us-east-001 and us-south-001 still run a yubaba built with the gate, so until they are rolled the old gotcha still describes their live behaviour.")
//! @yah:notify_on(R858, "R858's coordinator recovery is done, so the fleet is safe to roll again. Drive R600-F10's live half now: build one yubaba artifact from current tree (it carries BOTH R858's leader.rs hydrate-before-probe fix AND this ticket's acme_issuer leadership-gate removal), roll us-east-001 + us-south-001, then watch either node's journal for 'acme issuer: ACTIVE — this node holds the issuer lock acme-issuer/yah.dev'. That line on a NON-leader is the whole point of this ticket and has never once been observed. The operator already authorized this roll (2026-09-08, including 'short term hiccups are fine'), so it needs no fresh call unless the fleet state has moved again.")
//! @yah:handoff("THE LEADERSHIP GATE IS GONE — this is the change that makes R600 deployable without ever restarting us-west-001, and it removes the last CODE blocker on this ticket. acme_issuer::run no longer tests `current_leader == Some(node_id)`. Every configured node now asks for the acme-issuer/<domain> raft lock on every tick, so the lock IS the election exactly as W273 specifies ('elect the single issuer via the existing raft lock primitive'); the old gate silently intersected the issuer set with {leader}, which is why a fleet with the drop-in on east+south and leadership on west ordered nothing and said nothing for 6+ minutes. Single-issuer safety never came from the gate and is unchanged: raft orders the concurrent AcquireLocks and every one after the first sees a live owner and is denied. Issuer identity is now MORE stable, not less — it no longer moves on every raft election.")
//! @yah:handoff("Tree anchor at handoff: af805057ba632298d3e7e53c0197a164ed413824 — the shared tree as I left it. Diff against it (`git diff af805057ba632298d3e7e53c0197a164ed413824..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:handoff("FILES CHANGED (all local, nothing committed, nothing rolled): NEW `raft::client_write_forwarded` + `raft::FORWARD_TIMEOUT` in oss/yubaba/crates/yubaba/src/raft/mod.rs — writes a YubabaRequest from ANY node, forwarding a follower's write to the leader via POST /raft/write and returning the applied YubabaResponse. Returning the response is the load-bearing part: AcquireLock's LockGranted(bool) has to survive the forward or the election cannot be decided off-leader. DISCOVERED WORK, outside the ticket title: member_registration::write_row held the ONLY prior copy of that forwarding arm, so it was collapsed onto the shared helper rather than left as a second implementation to drift (member_registration.rs, and its local FORWARD_TIMEOUT deleted in favour of the shared const). acme_issuer.rs: run() builds a reqwest client with the same 'then this node cannot be the issuer' exit the KEK load already had; put_secret is forwarded too, because the elected issuer is now very often NOT the leader and a bare client_write would fail on exactly the nodes the election is newly free to pick.")
//! @yah:handoff("OBSERVABILITY, second half of the standby gotcha. IssuerPresence lost NotLeader (no longer a reachable state) and gained LockUnavailable, split out as a new pure `presence_for(Option<bool>)`. The Option is the point: Some(false) = asked and lost the lock (benign, the normal state of every voter but one, logged info!), None = the AcquireLock write never landed (no leader, or the forward failed — NOBODY is issuing, logged warn!). Folding those together with unwrap_or(false) would recreate the R600-F10 bug in a new costume, so the mapping is pure and pinned by test. The per-tick AcquireLock error dropped to debug! since the edge-triggered warn now carries the operator-facing half.")
//! @yah:verify("cargo test -p yubaba --lib = 798 passed / 0 failed, re-run AFTER R858's leader.rs hydrate-before-probe fix landed in the tree, so this number is the composed result rather than my change in isolation (that run was clean — the camp skew rail flagged no mid-run input change). 2 new tests: a_failed_lock_write_is_not_reported_as_standby pins all three presence mappings plus the explicit assert_ne! that None and Some(false) must not collapse; an_unlanded_lock_write_never_issues pins that the same None still takes the Standby ACTION. cargo check -p yubaba --lib and --bins both clean; cargo clippy -p yubaba --lib reports nothing on acme_issuer.rs, member_registration.rs or raft/mod.rs. Grep-verified no `is_leader`/`current_leader ==` gate survives in acme_issuer.rs — current_leader now feeds only the log line.")
//! @yah:verify("NOT VERIFIED, AND IT IS THE HALF THAT MATTERS — say this plainly rather than reading the green suite as proof. No test drives a live raft, so 'a follower actually wins the lock and issues' is UNPROVEN. The tests pin the reporting and the decision table; the forwarding itself and the off-leader issuance are exercised by nothing. The single observation that would prove this ticket is the line `acme issuer: ACTIVE — this node holds the issuer lock acme-issuer/yah.dev` appearing in the journal of a node that is NOT the raft leader. It has never been seen. Nothing was committed, nothing was rolled, no fleet node was mutated by this session (the one live action taken was a read-only `ls` of the KEK path on us-east-001).")
//! @yah:gotcha("FLEET PREMISES ON THIS TICKET WENT STALE UNDER ME IN ONE SESSION — re-measure before acting on any of them, and do not trust the ones below either. Corrected 2026-09-08 by @Ashguard:libra (session:6eed47dc) measuring prod read-only while I was mid-plan: (1) prod is NOT mixed-version — all three voters run ONE yubaba, sha256 0d3d720b909e43dcf07e3cc33c4c7eb529d008e181fc5b17a94ad09022ad6372, /health 0.8.34. R858's 'west runs the hand-built 7f6d24d0, do not roll it' gotcha is stale; west has been re-rolled. I had built a mixed-ownership-policy fencing worry on that premise and it does not arise. (2) cloud.mesh.yah.dev is no longer a single A record to west — dig returns all three voter IPs, so R858-T1's address leg has landed. (3) THE MESH WAS IN AN ACTIVE OUTAGE at the time of this handoff: /key?v=138 = HTTP 503, no headscale process on any voter, ingress_owner recorded as us-south-001 which has the binary and a byte-correct noise key but no config.yaml and no headscale.db. That is why this session stopped short of the fleet.")
//! @yah:next("THE ROLL IS AUTHORIZED AND SEQUENCED, NOT BLOCKED — do not re-ask the operator for it. They authorized it 2026-09-08, choosing the most invasive option offered ('More invasive is fine if it leaves us in a better place afterward. short term hiccups are fine!'), which covers rolling us-east-001 + us-south-001 AND installing the passway graceful-upgrade drop-in. I did neither, deliberately: @Ashguard:libra measured a LIVE MESH OUTAGE on the same fleet minutes later and put a coordinator-recovery call to the same operator, and adding a second fleet mutation mid-incident is how a recovery gets misattributed. Sequence when R858's recovery lands (a @yah:notify_on(R858) edge on this ticket will wake whoever picks it up): build ONE artifact from current tree — it already carries both R858's leader.rs hydrate-before-probe fix and this ticket's gate removal — roll east + south, leave west alone. West needs no restart for R600 any more; that is the entire point of this pass.")
//! @yah:next("THEN THE CUTOVER, unchanged in shape but now reachable. Once a node logs 'acme issuer: ACTIVE' and tls/yah.dev/{cert,key} exists in the cluster store: install app/yah/cli/resources/passway-graceful-upgrade.conf on ONE door (its two stated preconditions first — pin PASSWAY_UPGRADE_SOCK to a per-instance path, since unset it is pingora's shared /tmp/pingora_upgrade.sock and a node runs two passways; and raise TimeoutStartSec, since Type=notify makes a slow first ACME order fatal), costing one deliberate systemctl restart in a chosen window. Then set YUBABA_CERT_FILES_* on that door with _RELOAD_CMD=`systemctl reload <unit>` (NOT `systemctl restart passway` — see the R870-T3 bullet) and PASSWAY_TLS_MODE=manual. Verify with openssl s_client against that IP returning the fleet cert, then a re-issue propagating with no manual step. Only after BOTH doors are cut over should the per-node ACME config be removed — the R853-B7 duplicate-certificate bucket argument still holds while any node self-issues.")
//! @yah:gotcha("THE LOCK IS SQUATTED BY A NODE THAT WILL NOT USE IT — measured live 2026-09-08T19:33Z, and it is a STRICTLY WORSE failure than the standby gotcha above describes, because it cannot self-heal for 24h at a time. `GET /cluster/singletons` on both west and east returns roles={\"acme-issuer/yah.dev\":{\"acquired_at\":1788850794,\"owner\":\"1\",\"ttl_secs\":86400}} — i.e. us-south-001 (node 1) ACQUIRED the issuer lock at 2026-09-08T06:59:54Z and holds it until 2026-09-09T06:59:54Z. But south is NOT issuing: its last presence line (17:02:47Z, after libra's recovery restart) is `standby — another node holds raft leadership`, leader=2. Meanwhile node 2 (us-west-001) IS the leader and has NO issuer drop-in at all — `test -f .../40-acme-issuer.conf` = ABSENT and `journalctl -u yubaba | grep -c \"acme issuer\"` = 0, it has never logged one line. Node 3 (east) has the config and is a non-leader, so it also stands by. NOBODY ISSUES, and the one node that could is fenced out by its own stale lock. THE ORIGINAL GOTCHA SAID 'no node ever attempted AcquireLock'; the live state is now worse — a node attempted, WON, then lost leadership and went silent still holding the prize. Rolling east alone does NOT fix this: east would ask, be denied by south's live lease, and log LockHeldElsewhere. The node that must get the new binary is SOUTH, because only the lock's own owner can renew it and then issue.")
//! @yah:gotcha("LOCK SEMANTICS, READ FROM raft/mod.rs:1269 RATHER THAN ASSUMED — this is what makes the squat breakable without touching the coordinator. The AcquireLock arm grants when `entry.owner == *owner || now.saturating_sub(entry.acquired_at) >= entry.ttl_secs`, i.e. a SAME-OWNER re-acquire is always granted and refreshes acquired_at. Three consequences. (1) Rolling SOUTH works because south owns the lease: it renews its own lock, sees renewal_due (no cert), and issues. (2) Rolling EAST alone appears useless — east's owner \"3\" does not match \"1\" and the lease is live — BUT the second disjunct means it self-heals at 2026-09-09T06:59:54Z, after which east takes the lock and issues with no further action. So \"roll east\" is correct-but-slow, not wrong. (3) There is a `ReleaseLock { key, owner }` request (raft/mod.rs:1284) that removes the entry when the owner matches, which turns that 11h wait into an immediate handover. RELEASING ALONE FIXES NOTHING under the current binaries — the freed lock would only be taken by the raft leader, and the leader (west) has no issuer drop-in at all. It is only useful PAIRED with a rolled node, which is the whole thesis of this ticket: with the gate gone, the node that takes the lock no longer has to be the leader.")
//! @yah:gotcha("THE ROLL IS NOT A LOCAL BUILD AND IT IS NOT FREE — both read out of scripts/roll-node.sh, and both were missing from this ticket's plan. (1) THE INPUT IS THE PUBLISHED MANIFEST, NEVER A LOCAL BUILD: \"Everything this script installs is resolved from cdn.yah.dev's signed release manifest and checked against the sha256 that manifest declares. There is no flag that uploads a binary from the operator's laptop, and there should never be one.\" So delivering this ticket's acme change to any node requires CUTTING AND PUBLISHING A YUBABA RELEASE first — an outward-facing write to R2/CDN, materially bigger than the \"roll two nodes\" the operator authorized, and the same artifact R858 wants. Hand-scp'ing a musl build is what that script exists to end (it is why west carried 7f6d24d0 for weeks). (2) A ROLL RESTARTS KAMAJI, AND \"restarting kamaji KILLS every workload on the box — and kamaji does NOT resume them.\" Measured on us-east-001 2026-08-28 (R755-T4): three yah-marketing workloads stayed gone and passway-test.yah.dev served 503 until they were redeployed by hand. So \"roll east, it holds nothing critical\" is WRONG as I first framed it — east holds kamaji workloads that a roll silently drops. Budget the redeploy as part of the roll, not as a surprise. Documented voter order is east before south, one at a time, leaving one node serving.")
//! @yah:handoff("RELEASE CUT AUTHORIZED AND IN PROGRESS 2026-09-08. Operator chose publish over a hand-install (\"Yes — bump to 0.8.35, publish, roll east\"), after @Ashguard:libra correctly argued publishing is the mature path and that this camp was told no quick fixes. `cargo xtask release patch` applied 224 edits tree-wide; root, oss/yubaba and oss/kamaji all read 0.8.35 and both Cargo.locks refreshed. Re-verified after the bump: yubaba --lib 798 passed / 0 failed, kamaji --bin builds. Publishing is required rather than cosmetic — cdn.yah.dev/yubaba/release-manifest.json is 0.8.34 and the script REFUSES a republish because versioned keys are immutable. PROVENANCE AUDIT BEFORE CUTTING, because a release is cut from the shared working tree and this one is not only mine: every dirty file under the shipped binaries' source is accounted for and authorized. Mine — acme_issuer.rs, member_registration.rs, raft/mod.rs, secret_reload.rs. @Ashguard:libra's (R858, authorized in-session) — leader.rs, litestream.rs, plus one-line inert @yah:gotcha annotations in headscale_appliance.rs, scheduler.rs, service_records.rs. @Ashguard:spade's (R859, authorized in-session) — the new untracked workspace member oss/yubaba/crates/floating-ip plus cloud/provider/*; spade confirmed it is a landed extraction rather than scaffold (18 tests, clippy clean) AND that yah-cloud is a DEV-dependency of yubaba (Cargo.toml:137/:152), so floating-ip is not linked into the yubaba daemon binary at all. oss/kamaji and oss/yah-base are CLEAN.")
//! @yah:verify("CLUSTER-EPOCH DRIFT GUARD: FAILED, JUDGED, RE-RECORDED, RE-RUN GREEN — recording the judgement because the guard's own text says re-recording without making the call is the exact failure it exists to prevent. The 0.8.35 stage run failed at step 2 with 2 problems, both naming `rust-file oss/yubaba/crates/yubaba/src/raft/mod.rs` as MOVED (raft/store.rs and the openraft dep both `same`) — i.e. driven by THIS ticket's change, so the call was mine to make. Verdict (b) NOT BREAKING on BOTH axes, on evidence rather than convenience: `git diff` of that file is 69 insertions, purely additive, appended after bootstrap_single_node — one `pub const FORWARD_TIMEOUT` and one `pub async fn client_write_forwarded`. It changes NO enum variant, NO struct field, NO serde attribute, and does not touch `apply()`. So (i) state_epoch stays 4 — nothing serialized into the raft log or snapshot moved, and a 0.8.34 binary can still read a 0.8.35 log and roll back; (ii) cluster_protocol stays 5 — the helper introduces no new wire message, it POSTs an EXISTING YubabaRequest to the EXISTING POST /raft/write in the exact `{\"request\": ...}` body shape member_registration was already sending, so an old node receives nothing it was not already receiving. Re-recorded with `cargo run -p xtask -- cluster-epochs --write` (cluster_protocol 6361fef0->a77f2501, state_epoch 2b7fa7cc->10215557); `cargo test -p xtask --test main cluster_epoch` now 8 passed / 0 failed.")
//! @yah:next("EAST INSTALL PROCEDURE, deliberately NOT scripts/roll-node.sh — written down so it survives this session. roll-node.sh restarts kamaji, which kills east's workloads without resuming them (R755-T4); @Ashguard:libra pointed out that cost is not intrinsic, since both this ticket's change and R858's are yubaba-only. So: take the PUBLISHED, sha-verified bytes (keeping roll-node.sh's provenance — never a laptop build) but install and restart yubaba ALONE. Steps on us-east-001 (debian@51.81.85.145, x86_64 → x86_64-unknown-linux-musl): (1) fetch https://cdn.yah.dev/yubaba/0.8.35/x86_64-unknown-linux-musl/yubaba-x86_64-unknown-linux-musl.tar.gz and check its sha256 against the published per-version manifest — verify, do not trust; (2) anchor the current binary as /usr/local/bin/yubaba.rollback-20260908-r600f10 (the box already carries seven such anchors — that is the local convention, follow it); (3) `install -m 0755 <extracted>/yubaba /usr/local/bin/yubaba`, that file ONLY — leave kamaji, yah-scryer and the passway tier alone; (4) `systemctl restart yubaba` ONLY. DO NOT restart kamaji. (5) Prove by HASH, never by --version: roll-node.sh's header records us-east-001 reporting kamaji 0.8.22 while carrying none of that tree (R746-T3). ROLLBACK IS ONE COMMAND: install the anchor back and restart yubaba.")
//! @yah:verify("THE ACCEPTANCE OBSERVATION, stated in advance so it cannot be rationalised after the fact. Within one tick of the east restart, east's journal must show `acme issuer: standby — another owner holds the issuer lock acme-issuer/yah.dev`. That exact string is the proof: the OLD binary on a non-leader prints `another node holds raft leadership, so this node does not attempt the issuer lock`, and only a node that ACTUALLY REACHED AcquireLock while not being the raft leader can print the new one. If east instead prints the old leadership line, the install did not take. THEN, at 2026-09-09T06:59:54Z when us-south-001's squatted 86400s lease lapses (acquired_at 1788850794, never renewed because a standby tick never reaches AcquireLock), east's next tick should flip to `acme issuer: ACTIVE` and place the LE STAGING order — after which tls/yah.dev/cert and /key appear in the cluster store and R600 has its first cluster secret. Grant on expiry is guaranteed by raft/mod.rs:1269's second disjunct, `now.saturating_sub(entry.acquired_at) >= entry.ttl_secs`, so no explicit ReleaseLock is needed.")
//! @yah:verify("THE STAGED ARTIFACT WAS PROVEN TO CARRY THE CHANGE BEFORE IT WAS UPLOADED, by string-extraction rather than by --version (which R746-T3 records lying on this very node — us-east-001 reported kamaji 0.8.22 while carrying none of that tree). Extracted yubaba-0.8.35-x86_64-unknown-linux-musl.tar.gz and ran `strings -a` over the yubaba binary: the three NEW strings are each present exactly once — \"another owner holds the issuer lock\", \"lock write is not landing\", \"forwarding raft write to leader at\" — and the OLD string \"another node holds raft leadership\" is ABSENT (count 0). That absence is the decisive half: it proves the gated code path is gone from the shipped bytes rather than merely that new code was added alongside it. Stage run exit 0, both musl triples packaged, cosign-signed and verify-blob'd against cdn.yah.dev/keys/yah-release.pub BEFORE upload. x86_64 sha256 c66661668ab1269b5a94d2d3bfe2940fee9b369b0de4b253365d2c0fd15340bc, aarch64 sha256 3e00ac524415afcbaf4352b848f3bc32b4c4752118d5085805488c71b097661a. Manifest stamps cluster_protocol 5 / state_epoch 4, matching the judgement recorded above.")
//! @yah:verify("PROVEN LIVE 2026-09-08T20:23:24Z — A NON-LEADER ATTEMPTED THE ISSUER LOCK, WHICH HAS NEVER HAPPENED BEFORE ON THIS RELAY. yubaba 0.8.35 installed on us-east-001 (node 3); its journal now reads: `acme issuer: standby — another owner holds the issuer lock acme-issuer/yah.dev; taking over when that lease lapses. This is the normal state for every voter but one and is NOT an error` with leader=\"2\". Read that pair carefully, because it is the whole ticket: east is node 3, the leader is node 2, and east nonetheless reached AcquireLock and came back with LockGranted(false) — denied by us-south-001's live lease, not short-circuited by the leadership gate. The old binary on a non-leader printed `another node holds raft leadership, so this node does not attempt the issuer lock` and never called AcquireLock at all. CORROBORATED INDEPENDENTLY OF THE LOG TEXT: /cluster/singletons applied_index moved 2806059 -> 2806060 across the restart, i.e. east's forwarded AcquireLock was actually applied as a raft log entry — the client_write_forwarded hop to leader node 2 and back is working end to end, not merely compiling. INSTALL WAS BY HASH, both ends: fetched tarball sha256 c66661668ab1269b5a94d2d3bfe2940fee9b369b0de4b253365d2c0fd15340bc matched the published manifest, inner binary 40285095b41acfb6f6e4237ea6dd5fa92beca1596bd43b9f48d27ecdd90da711 matched what /usr/local/bin/yubaba hashes to after install. Rollback anchor /usr/local/bin/yubaba.rollback-20260908-r600f10 = 0d3d720b909e43dcf07e3cc33c4c7eb529d008e181fc5b17a94ad09022ad6372.")
//! @yah:verify("THE YUBABA-ONLY RESTART DID WHAT IT WAS CHOSEN TO DO — no workload was harmed. Measured immediately after: `systemctl is-active kamaji` = active (never restarted), and all three public endpoints green — yah.dev 200 in 0.37s, cloud.mesh.yah.dev/key?v=138 200 in 0.11s, passway-test.yah.dev 200 in 0.92s. That last one is the specific thing roll-node.sh would have broken: R755-T4 measured it serving 503 until three yah-marketing workloads were redeployed by hand after a kamaji restart. Declining roll-node.sh on @Ashguard:libra's observation (both changes in this artifact are yubaba-only, so kamaji never needs to stop) cost nothing and saved that outage. NOT YET VERIFIED AND STILL THE SIGN-OFF BAR: no cert exists, so no door serves one. This ticket is NOT done — the issuer half is proven, the consumption half is untouched.")
//! @yah:next("WATCH FOR THE ISSUANCE AT 2026-09-09T06:59:54Z — this is the next concrete event and it needs no human action, only checking. us-south-001's squatted lease (acquired_at 1788850794, ttl 86400, never renewed) lapses then; east is now running 0.8.35 and asks every tick, so its next tick after that instant should grant on raft/mod.rs:1269's expiry disjunct and flip the journal from `standby — another owner holds the issuer lock` to `acme issuer: ACTIVE — this node holds the issuer lock acme-issuer/yah.dev`, then place the LE STAGING order. CHECK WITH: `ssh -i ~/.ssh/yah debian@51.81.85.145 'sudo journalctl -u yubaba --since \"-2h\" | grep -i \"acme issuer\"'` and `curl -s http://100.64.0.3:7443/cluster/singletons` (the roles entry should show owner \"3\", a fresh acquired_at). IF IT DOES NOT FIRE, the first thing to check is NOT the lock — it is DNS-01: the drop-in pins YUBABA_ACME_DNS01_CLOUDFLARE_TOKEN_FILE=/var/lib/yah/yubaba/cf-token and a 75s propagation delay, and R853-B7 already burned a cycle on LE validating before Cloudflare had published the TXT. ONCE THE CERT LANDS the ticket's remaining half begins: cert_materialize is built and inert, so set YUBABA_CERT_FILES_* on a door and cut it over per the cutover bullet above.")
//! @yah:verify("PROVENANCE GAP FOUND BY @Ashguard:libra AND NOW CLOSED — worth reading as a process lesson, not just a status line. 0.8.35 was cut, signed, published and installed on a prod node while HEAD was still af805057 and the tree carried 128 uncommitted paths across three sessions. Publishing bought signing and sha-verification but NOT traceability, and on this shared tree that is a live risk rather than a theoretical one: one `git checkout <sha> -- <path>` on any of those files would have made the published artifact unreproducible, which this camp has already done once at a cost of 827 lines. The operator committed and tagged in response (e336e727 \"sync\", tag v0.8.35, tree now 0 dirty paths). VERIFIED THAT THE TAG MATCHES THE PUBLISHED BYTES rather than assuming: `git show v0.8.35:oss/yubaba/Cargo.toml` = 0.8.35, and in `git show e336e727:.../acme_issuer.rs` the new \"another owner holds the issuer lock\" appears once while the old \"another node holds raft leadership\" appears ZERO times, with client_write_forwarded present in raft/mod.rs. ALSO CLOSED AN AUDIT GAP OF MY OWN: my pre-publish provenance check covered oss/yubaba, oss/kamaji and oss/yah-base but NOT oss/passway or oss/qed, both of which ship binaries in that tarball. Re-checked after the fact — passway's only source change was my own inert @yah:gotcha annotation in tls.rs (written there by the R870-T3 board update), and oss/qed had no non-manifest source changes at all. So the artifact is clean, but I published before establishing that, which is the wrong order.")
//! @yah:handoff("SHIPPED AND PROVEN LIVE, BUT THE TICKET IS NOT DONE — the issuer half is demonstrated, the consumption half is untouched. yubaba 0.8.35 is published to cdn.yah.dev (both musl triples, cosign-signed, per-version manifest proven from the CDN before the pointer was written) and installed on us-east-001 by hash, yubaba binary only, kamaji never restarted. Committed and tagged v0.8.35 (e336e727) with the tag verified to match the published bytes. THE OBSERVATION THIS TICKET EXISTED TO GET: east (node 3), while node 2 held raft leadership, logged `acme issuer: standby — another owner holds the issuer lock acme-issuer/yah.dev` at 2026-09-08T20:23:24Z — a NON-LEADER that actually reached AcquireLock and was denied by the lock rather than short-circuited by the leadership gate. Corroborated off the log text by applied_index moving 2806059 -> 2806060, so the forwarded write really was applied as a raft entry. @Ashguard:libra independently measured the mixed 0.8.35/0.8.34 cluster converging — all three voters term 21, leader 2, last_applied 2806060 identical — which is the observable form of my (b) not-breaking epoch judgement. Fleet green throughout: yah.dev 200, cloud.mesh 200, passway-test 200.")
//! @yah:handoff("Tree anchor at handoff: e336e7278f7f40780323d40a8ceb6e438bead0b1 — the shared tree as I left it. Diff against it (`git diff e336e7278f7f40780323d40a8ceb6e438bead0b1..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("FIRST THING TO DO, NO ACTION NEEDED, ONLY CHECKING: at 2026-09-09T06:59:54Z us-south-001's squatted lease lapses and east should flip to `acme issuer: ACTIVE` and place the LE STAGING order. `ssh -i ~/.ssh/yah debian@51.81.85.145 'sudo journalctl -u yubaba --since \"-3h\" | grep -i \"acme issuer\"'`. If it did NOT fire, suspect DNS-01 before the lock — R853-B7 already burned a cycle on LE validating before Cloudflare published the TXT, which is why the drop-in sets a 75s propagation delay.")
//!
//! @yah:ticket(R911-F5, "Node-side migration: copy the raft secret map and legacy cert objects into FleetSecretStore, re-sealed with AAD; raft map loses every reader")
//! @yah:status(review)
//! @yah:at(2026-09-15T05:20:57Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R911)
//! @yah:next("Tier: Warrior — one-shot data migration on live state; must be idempotent and safe with mixed versions mid-roll.")
//! @yah:next("Add a startup migration (a new module, e.g. secret_migrate.rs) that runs before the node serves deploys when it has cluster state, a KEK, and cert-store config. For each record in the raft secret map (YubabaStateMachine cluster_secret_index + cluster_secret): open with the LEGACY no-AAD path under the node KEK, re-seal with the R911-F4 AAD format, and write it to FleetSecretStore, preserving updated_at, access and digest. Skip when the store already holds a record with updated_at >= the raft one. Also re-seal legacy per-domain objects under certs/<issuer>/ that fail the new open but pass the legacy one. Plaintext stays in memory only and is zeroized.")
//! @yah:next("Log one summary line (migrated N, skipped M, failed K, with names but never bytes). A failure on one record does not stop the others and does not stop node start.")
//! @yah:next("MIXED ROLL: the first upgraded node in a group migrates, and later ones skip. Leave the raft map and PutSecret/DeleteSecret apply intact (only the migration reads them) so an un-upgraded node keeps resolving mid-roll. Remove every OTHER reader of cluster_secret / cluster_secret_index / subscribe_secrets that F1-F3 left.")
//! @yah:next("Keep the legacy open path private to the migration module. R911-F7 deletes it together with the raft map after both groups roll.")
//! @yah:verify("cargo test -p yubaba --lib green vs baseline; tests: raft records land in an InMemoryObjectStore re-sealed and open through ClusterResolver; a second run is a no-op; a newer store record is not overwritten; one bad record does not block the rest.")
//! @yah:depends_on(R911-F4)
//! @yah:files(oss/yubaba/crates/yubaba/src/lib.rs)
//! @yah:files(oss/yubaba/crates/yubaba/src/main.rs)
//! @yah:files(oss/yubaba/crates/yubaba-consensus/src/raft/store.rs)
//! @yah:handoff("NEW MODULE oss/yubaba/crates/yubaba/src/secret_migrate.rs (declared in lib.rs). `pub async fn run(state: &ServerState) -> Option<MigrationReport>` checks its preconditions in order: raft cluster_state, then the fleet store's rails (FleetSecretStore::for_node), then the node KEK. A missing one logs ONE error, `secret migration: skipped — <reason naming it, e.g. --sovereign-group>`, returns None, and the node still starts. Otherwise all store and crypto work runs in one `off_runtime` call to `migrate(sm, kek, store)`, followed by one summary line.")
//! @yah:handoff("PASS 1, RAFT MAP: for each name in `cluster_secret_index`, read `cluster_secret`, open with `open_legacy_unbound` under the node KEK into a Zeroizing buffer, then re-seal with `seal(kek, pt, secret_aad(name, &access))`, preserving access, updated_at, digest, sans and ari exactly. The record is written with `FleetSecretStore::write_secret`, so tls/* lands in certs/<issuer>/ through the store mapping. SKIP when the store already holds the name, it opens bound, and store.updated_at >= raft.updated_at. OVERWRITE when the store copy is absent, older, or does not open bound. A raft record that fails the legacy open is FAILED, named, and never written. A store read error is also FAILED; it never falls through to a blind overwrite. PASS 2, CERTS/<ISSUER>/: every tls/* row of `store.index()` not already handled in pass 1 that does not open bound but does open unbound is re-sealed in place under its own name and rule. One that opens neither way is FAILED and left untouched. The index lists only cert/key records, so claim (`issuing`), enrollment and holding objects are never touched.")
//! @yah:handoff("WIRING (main.rs): `yubaba::secret_migrate::run(&shared_state).await;` sits immediately after `let shared_state = Arc::new(server_state);`, BEFORE `leader::spawn` (start_headscale reads the noise key) and before `serve` and the secret_watch/secret_reload/cert_materialize/tenant-passway spawns. The one-line comment says why. The earlier startup spawns (demux route publisher, per-domain issuer) read only record metadata, never plaintext.")
//! @yah:handoff("NOT TOUCHED (decision 7): raft apply, PutSecret/DeleteSecret, the secret map, `open_legacy_unbound`. There were no other readers left to remove: a code-only grep shows `cluster_secret`, `cluster_secret_index` and `subscribe_secrets` read only by their definitions in yubaba-consensus raft/store.rs (plus subscribe_secrets' own test), and now by this module. CONCURRENCY: no lock, per decision 5, explained in one module-doc paragraph (two voters write identical plaintext/name/rule/metadata; the secret-watch bump lands on consumers whose digest is unchanged).")
//! @yah:handoff("T6 JOURNAL LINE — grep on the FIRST upgraded node of each group, right after its restart: `journalctl -u yubaba --since '<restart time>' | grep 'secret migration: '`. Success is exactly one line of the form `secret migration: migrated N / skipped M / failed K; migrated=[name, ...] failed=[...]`. Expected on the first PROD node: migrated=[...] includes all 7 raft names (cheers/cloud-admin/verify-key, headscale/noise-private-key, noisetable/account/{magic-link-key,session-key,smtp-password}, tls/yah.dev/{cert,key}) plus any legacy tenant certs under certs/<issuer>/, with `failed 0`. On the first DEV node migrated=[...] includes cloudflare-tunnel-token and noisetable/account-staging/{magic-link-key,session-key}. Every later node in a group should log `migrated 0 / skipped M / failed 0`. A line starting `secret migration: skipped —` means a rail is missing (the reason names it) and nothing migrated. Per-record failures log separately as `secret migration: <name> failed: <reason>`.")
//! @yah:verify("BASELINE: yubaba lib 983/0 (operator-verified after F4).")
//! @yah:verify("AFTER (from oss/yubaba): `cargo check -p yubaba --all-targets` EXIT=0 (log shows Checking yubaba; no yubaba warnings). `cargo test -p yubaba --lib` = 991 passed / 0 failed (+8). `cargo test -p yubaba --features testing --lib secret_reload` = 2 passed / 0 failed. Root `cargo run -p xtask -- cluster-epochs` EXIT=0 (no protocol surface moved).")
//! @yah:verify("New tests (secret_migrate::tests, InMemoryObjectStore + a raft state machine seeded through `apply_for_test(PutSecret)` with legacy unbound seals): raft_records_land_resealed_with_every_field_and_resolve (access/updated_at/digest/sans/ari preserved, ciphertext re-sealed, tls lands at certs/<issuer>/yah.dev/cert.sealed, both resolve through ClusterResolver, raft map untouched, summary prefix); a_second_run_skips_everything_and_writes_nothing (every object byte-identical before and after, each name counted once); a_newer_bound_store_record_is_not_overwritten; an_older_or_unbound_store_record_is_overwritten (older-bound, and newer-but-unbound); an_unopenable_raft_record_is_named_failed_and_the_rest_migrate (failed=[bad/one] in the summary, never written, no bytes in the summary); an_unbound_certs_object_is_resealed_in_place_and_nothing_else_is_touched (legacy re-sealed, bound skipped, wrong-KEK object failed and byte-identical, claim object byte-identical); a_node_missing_a_rail_skips_with_the_named_error (NoStore(NoSovereignGroup) naming --sovereign-group; NoClusterState); run_migrates_through_the_blocking_pool (the production entry on a multi-thread runtime with a real KEK file).")
//! @yah:gotcha("SHARED BUCKET, SHARED certs/<issuer>/: prod and dev use one bucket, and both derive the same issuer segment (ACME staging directory), so pass 2 on whichever group's first node runs first re-seals the shared certs/<issuer>/ objects. The other group's first node then skips them, IF both groups share a cluster KEK. I did not verify whether the prod and dev KEKs are the same. If they differ, the second group's node will list those cert names under failed=[...] (it cannot open another group's records) and leave them untouched. That is expected and harmless for those names, but it means T6's 'failed 0' check must allow for them on the second group.")
//! @yah:gotcha("STARTUP RACE, bounded to the migration window: pass 2 reads then writes each legacy cert object without a precondition. If the per-domain issuer (spawned earlier in main.rs) writes a fresh bound cert for the same domain between those two steps, the migration overwrites it with the re-sealed older, still-valid cert. That cert renews on its normal schedule; nothing is lost that the issuer will not re-issue. The sweep over every tenant cert also costs one GET plus one AEAD open per object on every start until R911-T7 deletes this module.")
//! @yah:gotcha("ROLL: this build must still be preceded by --sovereign-group on every voter (without it migration logs `skipped — ... --sovereign-group` and every cluster-secret read fails closed), and by the matching CLI install (F4 lockstep).")

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use workload_spec::{SecretMount, WorkloadSpec};

use crate::deploy::secret_mount::rerender_file_secrets;
use crate::mesh::MeshAssignment;
use crate::secrets::{resolve_secrets, ClusterResolver, ContainerSecrets, SECRET_STORE_ROOT};
use crate::ServerState;

/// How long to coalesce cluster-secret epoch bumps before re-rendering, so F3's
/// key-first/cert-last two-write rotation is observed as one consistent pair
/// rather than firing on the new-key/old-cert intermediate. Comfortably longer
/// than the sub-second gap between F3's two `PutSecret`s.
pub(crate) const DEBOUNCE: Duration = Duration::from_secs(2);

/// Width of one node's slot in the rolling-reload window (see
/// [`rolling_stagger`]). Wide enough that a fronting load balancer / health
/// check notices a draining node and routes around it before the next node
/// starts its reload.
const ROLL_SLOT: Duration = Duration::from_secs(4);

/// Number of distinct rolling slots. A cluster larger than this wraps (two
/// nodes share a slot) — acceptable, since the goal is "not every node at once",
/// not a strict one-at-a-time barrier (that needs a raft-lock, which is R600-F7
/// territory alongside the real zero-downtime handoff).
const ROLL_SLOTS: u64 = 8;

/// Per-node delay before a node performs its reload pass, so a fleet-wide
/// rotation (every node sees the same replicated `PutSecret` at ~the same
/// instant) rolls node-by-node instead of blipping every ingress at once.
///
/// This is the **interim** mitigation while the container backends still do a
/// connection-dropping reload (R600-F7): staggering keeps the *fleet* available
/// (an LB routes around the one draining node) even though per-node in-flight
/// connections still drop. Once F7 lands the per-node reload is itself
/// zero-downtime and the stagger is merely cosmetic. Harmless for
/// `Backend::Native` (already zero-downtime) — it just delays that node's swap.
pub(crate) fn rolling_stagger(node_id: u64) -> Duration {
    ROLL_SLOT * (node_id % ROLL_SLOTS) as u32
}

/// One workload that mounts a cluster secret as a `File`, tracked so a rotation
/// can re-render its mount and graceful-upgrade it.
#[derive(Clone)]
pub struct SecretWorkloadEntry {
    /// The **materialized** spec (F6 already rewrote its `File` cluster secrets
    /// to read-only `Bind`s of the host tmpfs files). Handed to
    /// `graceful_upgrade_workload` so kamaji re-spawns the ingress with the
    /// re-rendered cert bind.
    pub spec: WorkloadSpec,
    /// The mesh assignment used at deploy time — reused on upgrade so the
    /// replacement keeps the workload's identity / mesh IP (re-allocating would
    /// hand it a different address).
    pub mesh: MeshAssignment,
    /// The workload's original `File`-target `SecretMount`s (pre-materialization,
    /// still `SecretRef::Cluster`) — re-resolved on rotation to produce fresh
    /// cert/key bytes.
    pub file_mounts: Vec<SecretMount>,
    /// Digest of the last-rendered concatenated secret content. A rotation is
    /// detected when a fresh resolve yields a different digest; an epoch bump
    /// that leaves this workload's bytes unchanged is skipped.
    pub content_digest: u64,
}

/// In-memory registry of secret-consuming workloads, keyed on mesh ident.
/// Populated by the deploy handler when a workload with a cluster `File` secret
/// deploys successfully; cleared on destroy.
pub type SecretWorkloadRegistry = Mutex<HashMap<String, SecretWorkloadEntry>>;

/// Order-independent digest of resolved `File` secret content. Only the
/// `(container path, bytes)` pairs feed the hash, so re-resolving the same
/// material yields the same digest regardless of mount order. In-process only
/// (compared across bumps within one daemon lifetime), so a non-portable hasher
/// is fine.
pub fn content_digest(secrets: &ContainerSecrets) -> u64 {
    let mut pairs: Vec<(&std::path::Path, &[u8])> = secrets
        .file_mounts
        .iter()
        .map(|fm| (fm.path.as_path(), fm.content.as_slice()))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for (path, bytes) in pairs {
        path.hash(&mut hasher);
        bytes.hash(&mut hasher);
    }
    hasher.finish()
}

/// Subscribe to cluster-secret rotations and drive the re-render → graceful
/// upgrade loop. Returns immediately (a no-op that logs) on a node with no raft
/// cluster state or no workload backend — nothing can rotate there.
///
/// @yah:ticket(R911-F2, "Secret change watch polls the fleet object store (ETags), replacing raft subscribe_secrets")
/// @yah:status(review)
/// @yah:at(2026-09-15T04:33:19Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R911)
/// @yah:next("Tier: Warrior — async watch plumbing across two consumers, with debounce/stagger semantics to preserve.")
/// @yah:next("secret_reload::run (:192) and cert_materialize (:417) wake on sm.subscribe_secrets(), a raft epoch. Once secrets live in R2 that epoch never moves on rotation. Add a node-level SecretWatch that polls the FleetSecretStore (R911-F1) on an interval (default 30s, env-overridable), fingerprints the ETags (ObjectStore::etag) or updated_at of the keys under secrets/<group>/ and certs/<issuer>/, and bumps a tokio watch::Sender<u64> on change. Both consumers subscribe to it instead of raft. Keep DEBOUNCE and rolling_stagger unchanged.")
/// @yah:next("A poll error must not bump the epoch or read as a change; log it once per outage transition, not on every tick.")
/// @yah:next("Do not delete YubabaStateMachine::subscribe_secrets here. R911-F5 removes the raft secret map.")
/// @yah:verify("cargo test -p yubaba --lib green vs baseline; tests show a changed object bumps once, an unchanged poll does not, and a poll error does not.")
/// @yah:depends_on(R911-F1)
/// @yah:files(oss/yubaba/crates/yubaba/src/secret_reload.rs)
/// @yah:files(oss/yubaba/crates/yubaba/src/cert_materialize.rs)
/// @yah:files(oss/yubaba/crates/yubaba/src/lib.rs)
/// @yah:next("\"BLOCKING I/O (found verifying R911-F1): FleetSecretStore reads R2 through reqwest::blocking::Client (oss/yah-base/crates/object-store/src/r2.rs:33). F1 routed every cluster-secret read through it from async contexts: build_secret_resolver in the lib.rs deploy handler, secret_reload::run/reload_once, cert_materialize::run, and leader.rs start_headscale via noise_key_resolver. That blocks tokio workers, and in debug builds reqwest's blocking wait can panic inside a runtime. Every async caller that resolves or polls must go through tokio::task::spawn_blocking, including the new ETag poll. demux_routes.rs:804 is the in-tree precedent. Add a test that resolves through an async caller on a multi-thread runtime, using a store impl that asserts it is not running on a tokio worker (tokio::runtime::Handle::try_current is Err inside spawn_blocking? no, use a flag set by the wrapper) so the wrapping cannot silently regress.\"")
/// @yah:handoff("BLOCKING I/O FIXED. `fleet_secrets::off_runtime(f)` runs `f` via `tokio::task::spawn_blocking`, the same shape as the demux_routes sweep. It also sets a thread-local marker for the call's duration, resets it on drop, and resumes panics on the caller. Every FleetSecretStore verb (read/write/delete/index/fingerprint) calls `assert_off_runtime()`. In debug builds that panics when `Handle::try_current()` is Ok and the marker is unset, i.e. a bare call from a runtime thread. Plain sync callers with no runtime are never flagged. Wrapped call sites: lib.rs container deploy (new `materialize_spec_secrets` helper, which moves spec+resolver onto the pool, materializes, computes the registration digest in the same pass, and returns the spec), lib.rs `deploy_non_container` (native secrets), `secret_reload::reload_once` (per-workload resolve), cert_materialize `run`, which calls a new `materialize_pass` wrapper around `materialize_once`, and leader.rs `start_headscale`, which calls the new `headscale_state::materialize_noise_key_off_runtime`. `build_secret_resolver` now returns `Box<dyn SecretResolver + Send>`.")
/// @yah:handoff("CHANGE WATCH. New module oss/yubaba/crates/yubaba/src/secret_watch.rs: `run(state)` polls `FleetSecretStore::fingerprint()` inside `off_runtime` every `YUBABA_SECRET_WATCH_INTERVAL_SECS` (default 30s; blank/0/unparsable fall back to the default with a warn). It bumps `ServerState::secret_epoch` (new field, a `tokio::sync::watch::Sender<u64>` created in `ServerState::new`, so consumers can subscribe before the watch starts) via `send_modify`, and only when the fingerprint changes. `fingerprint()` hashes the sorted (object key, `etag:<ETag>` or `updated_at:<n>` when the backend's etag is None) pairs over the same key set `index()` lists (certs/<issuer>/ TLS pairs + valid names under secrets/<group>/). An object that vanishes between the listing and its etag probe is skipped; any backend error fails the poll. A pure Tracker holds the bump rules: the first good read is the baseline and does not bump. An error never bumps and never moves the baseline. Recovery to the same fingerprint wakes nobody; to a different one it bumps once. Errors before any baseline make the first good read bump, so consumers whose startup pass hit the same outage retry. The outage is logged once on the transition into it and once on recovery. main.rs spawns `secret_watch::run` beside `secret_reload`/`cert_materialize`. Both consumers now subscribe to `state.secret_epoch` and no longer require raft `cluster_state`. DEBOUNCE and rolling_stagger are unchanged. `YubabaStateMachine::subscribe_secrets` was NOT deleted; its only remaining caller is its own test in yubaba-consensus store.rs.")
/// @yah:handoff("LEADER DECISION (@Ashguard:griffin, mid-turn 2026-09-14): NO DEFAULT GROUP. Deleted `DEFAULT_GROUP`. `FleetSecretStore::new` takes a required group. New `fleet_secrets::MissingRail { NoObjectStore, NoSovereignGroup }` and `pub type NodeSecretStore = Result<FleetSecretStore, MissingRail>` (implements ClusterSecretStore). New `FleetSecretStore::for_rails(certs, group)` is the pure core that `for_node` delegates to (object store checked first). New `SecretStoreError::NoSovereignGroup`. The F1 `Option<S>` blanket impl was deleted, and every resolver site/signature is now `NodeSecretStore`. A missing rail resolves to `ClusterUnavailable`, so headscale refuses to start and deploys are rejected by secret name. The single startup line is `secret_watch::run`'s error naming `--sovereign-group` on a node that has the bucket but no group; cert_materialize's startup error now names whichever rail is missing.")
/// @yah:verify("BASELINE (operator-verified after F1): cargo test -p yubaba --lib = 961 passed / 0 failed.")
/// @yah:verify("AFTER: cargo check -p yubaba --all-targets EXIT=0; cargo check -p yubaba --features testing --lib --tests EXIT=0 (both logs show `Checking yubaba`, i.e. really compiled); no errors or warnings in the touched yubaba files. cargo test -p yubaba --lib = 975 passed / 0 failed, EXIT=0 (+14: secret_watch 7, fleet_secrets +4 net, cert_materialize 1, headscale_state 1, lib.rs materialize_spec_secrets_tests 1). cargo test -p yubaba --features testing --lib secret_reload = 2 passed, EXIT=0.")
/// @yah:verify("Change-watch tests: secret_watch::tests::{the_baseline_does_not_bump_and_an_unchanged_poll_does_not_either, a_change_bumps_exactly_once, an_error_is_not_a_change_and_does_not_move_the_baseline, an_outage_before_any_baseline_wakes_the_consumers_on_the_first_good_read, the_interval_defaults_and_is_overridable, the_loop_bumps_once_per_change (multi-thread, real poll loop over InMemoryObjectStore), an_unreachable_store_never_bumps}, plus fleet_secrets::tests::{the_fingerprint_moves_only_when_a_resolvable_record_does, the_fingerprint_of_an_unreachable_store_is_an_error}.")
/// @yah:verify("Regression guard for blocking I/O: fleet_secrets::tests::a_store_verb_on_a_runtime_thread_trips_the_guard (should_panic, debug builds) proves the tripwire fires. off_runtime_runs_the_store_and_does_not_leak_its_marker proves the marker resets on a reused pool thread. Each wrapped call site is exercised on a multi-thread runtime against a real FleetSecretStore, so reverting any of them to an inline call panics its test: cert_materialize::tests::a_pass_resolves_off_the_runtime_and_writes_the_pair, headscale_state::tests::the_async_entry_point_reads_the_fleet_store_off_the_runtime, lib.rs materialize_spec_secrets_tests::a_deploy_resolves_cluster_secrets_off_the_runtime, secret_watch::tests::the_loop_bumps_once_per_change, and the feature-gated secret_reload tests, which now seed and digest through off_runtime.")
/// @yah:verify("No-default-group tests: fleet_secrets::tests::{a_node_needs_both_rails_and_names_the_missing_one, a_node_missing_a_rail_fails_closed_by_name}; headscale_state::tests::the_real_resolver_over_a_down_or_missing_store_refuses_to_start now covers an outage, NoObjectStore and NoSovereignGroup.")
/// @yah:gotcha("ROLL GATE (leader decision, fleet recon 2026-09-14): all 6 live raft voters, prod and dev, run with --sovereign-group UNSET even though MachineConfig declares prod/dev. With this build a node lacking the flag has NO fleet secret store: every cluster-secret deploy is rejected ClusterUnavailable, cert_materialize never delivers the fleet cert, secret_watch stays idle, and start_headscale REFUSES to start (NoiseKeyError::StoreUnavailable). R911-T6 must set --sovereign-group on every voter BEFORE this ships. Keep that ordering along with the F1 gate (migrate raft secrets to R2 before rolling the resolver).")
/// @yah:gotcha("The blocking-I/O tripwire is debug-build only (#[cfg(debug_assertions)]), so release binaries never panic on it. Any future async caller of FleetSecretStore (the node-mediated PUT /secrets endpoint, the startup migration) must go through fleet_secrets::off_runtime or its debug-build tests will panic, naming the fix.")
/// @yah:gotcha("yah build run still cannot open the camp daemon's TaskRun store (turso short read, page 24050), so every build here ran locally outside the camp queue.")
pub async fn run(state: Arc<ServerState>) {
    let Some(backend) = state.active_backend() else {
        tracing::debug!("secret_reload: no workload backend; rotation watcher idle");
        return;
    };

    let stagger = state.node_id.map(rolling_stagger).unwrap_or_default();
    // R911-F1/F2: secrets are read from the fleet object store, and the wake
    // signal is the node's fleet secret watch (`crate::secret_watch`), which
    // polls that same store.
    let store = crate::fleet_secrets::FleetSecretStore::for_node(&state);

    let mut rx = state.secret_epoch.subscribe();
    // Absorb the initial value so we only react to changes after startup.
    let _ = rx.borrow_and_update();
    tracing::info!(
        stagger_ms = stagger.as_millis() as u64,
        "secret_reload: watching cluster secrets for rotation → live reload"
    );

    loop {
        if rx.changed().await.is_err() {
            // Sender dropped (state machine gone) — the daemon is shutting down.
            break;
        }
        let _ = rx.borrow_and_update();
        // Coalesce F3's key-first/cert-last two-write rotation (and any burst)
        // into one re-render pass over a consistent pair.
        tokio::time::sleep(DEBOUNCE).await;
        // Roll node-by-node: every node saw the same replicated rotation at
        // ~the same instant, so a per-node offset keeps the fleet available
        // while a (still connection-dropping, pre-F7) reload cycles the ingress.
        if !stagger.is_zero() {
            tokio::time::sleep(stagger).await;
        }
        let _ = rx.borrow_and_update();

        reload_once(
            &store,
            &state.cluster_kek_path,
            &state.secret_mount_root,
            backend.as_ref(),
            &state.secret_workloads,
        )
        .await;
    }
}

/// One re-render pass over every registered secret-consuming workload. Rebuilds
/// the [`ClusterResolver`] fresh (it reloads the node-local KEK), re-resolves
/// each workload's cluster `File` mounts, and — only when the resolved content
/// changed — rewrites the host tmpfs files in place and graceful-upgrades the
/// workload. Failures are per-workload and non-fatal: a workload whose secret is
/// momentarily unresolvable (a partial replicated write) is skipped and retried
/// on the next bump; its stored digest is left untouched so the retry still sees
/// a change.
async fn reload_once(
    store: &crate::fleet_secrets::NodeSecretStore,
    kek_path: &std::path::Path,
    mount_root: &std::path::Path,
    backend: &(dyn crate::ContainerRuntime + Send + Sync),
    registry: &SecretWorkloadRegistry,
) {
    let entries: Vec<(String, SecretWorkloadEntry)> = {
        let guard = registry.lock().unwrap();
        if guard.is_empty() {
            return;
        }
        guard
            .iter()
            .map(|(ident, entry)| (ident.clone(), entry.clone()))
            .collect()
    };

    // Load the KEK once for the pass, but build a resolver *per workload*: the
    // R706 access check is bound to the consumer identity, so a single shared
    // resolver would be asking on the wrong workload's behalf.
    let kek = match crate::secrets::load_cluster_kek(kek_path) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "secret_reload: cannot load the node KEK; skipping this rotation pass"
            );
            return;
        }
    };

    for (ident, entry) in entries {
        let resolver = ClusterResolver::new(
            store.clone(),
            kek.clone(),
            crate::secrets::LocalFileResolver::new(SECRET_STORE_ROOT),
            workload_spec::secrets::SecretConsumer::of(&entry.spec),
        );
        // R911-F2: resolving reads the fleet object store over blocking HTTPS.
        let mounts = entry.file_mounts.clone();
        let resolved = match crate::fleet_secrets::off_runtime(move || {
            resolve_secrets(&mounts, &resolver)
        })
        .await
        {
            Ok(r) => r,
            // R706 / W294 decision 5: a rule edit that revokes a *running*
            // workload takes effect on its next deploy, not by tearing it down
            // mid-flight. The plaintext is already in the container's tmpfs
            // bind, so "revoke now" means "kill the workload" — which would make
            // a typo in an access rule a production-outage weapon. Instead the
            // rotation stops for this workload (it will never see a newer
            // value) and says so loudly, once per bump, distinctly from the
            // transient arm below.
            Err(workload_spec::secrets::SecretError::Forbidden { name }) => {
                tracing::warn!(
                    ident = %ident,
                    secret = %name,
                    workload = %entry.spec.name,
                    "secret_reload: this workload is NO LONGER ADMITTED to a cluster secret it \
                     currently has mounted. Its existing plaintext stays live and stops being \
                     rotated; access actually ends on its next deploy. Redeploy or destroy it to \
                     complete the revocation."
                );
                continue;
            }
            Err(e) => {
                // A partial replicated write (key present, cert not yet) or a
                // decrypt failure — skip and retry on the next bump. Digest is
                // left as-is so the retry still registers a change.
                tracing::warn!(
                    ident = %ident,
                    error = %e,
                    "secret_reload: cluster secret not resolvable yet; deferring reload"
                );
                continue;
            }
        };

        let digest = content_digest(&resolved);
        if digest == entry.content_digest {
            // This workload's material didn't change on this bump.
            continue;
        }

        // Rewrite the host tmpfs files the container's read-only bind points at.
        if let Err(e) = rerender_file_secrets(mount_root, &ident, &resolved) {
            tracing::warn!(
                ident = %ident,
                error = %e,
                "secret_reload: re-render failed; leaving the previous cert live"
            );
            continue;
        }

        // Make the running workload pick up the fresh cert without dropping
        // connections (kamaji sequences the pingora fd-handoff).
        match backend
            .graceful_upgrade_workload(&entry.spec, &entry.mesh)
            .await
        {
            Ok(_) => {
                tracing::info!(
                    ident = %ident,
                    "secret_reload: rotated cluster secret → graceful-upgraded workload"
                );
                // Commit the new digest so we don't re-upgrade on the next
                // unrelated bump.
                if let Some(slot) = registry.lock().unwrap().get_mut(&ident) {
                    slot.content_digest = digest;
                }
            }
            Err(e) => {
                // The host files already carry the new cert; the upgrade failed
                // (backend hiccup). Leave the digest stale so the next bump
                // retries the upgrade.
                tracing::warn!(
                    ident = %ident,
                    error = %format!("{e:#}"),
                    "secret_reload: graceful upgrade failed; will retry on next rotation"
                );
            }
        }
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;

    use kamaji::fake::FakeRuntime;
    use workload_spec::{ImageRef, MeshIdent, SecretRef, SecretTarget, TierTag, WorkloadSpec};
    use yah_object_store::InMemoryObjectStore;

    use crate::fleet_secrets::{FleetSecretStore, NodeSecretStore};
    use crate::secrets::{seal_cluster_secret, ClusterResolver};

    const KEK: [u8; 32] = [5u8; 32];
    const CERT_KEY: &str = "tls/yah.dev/cert";
    const KEY_KEY: &str = "tls/yah.dev/key";

    fn cert_mount() -> SecretMount {
        SecretMount {
            source: SecretRef::Cluster {
                name: CERT_KEY.into(),
            },
            target: SecretTarget::File {
                path: "/run/secrets/tls.crt".into(),
                mode: 0o400,
            },
        }
    }

    fn key_mount() -> SecretMount {
        SecretMount {
            source: SecretRef::Cluster {
                name: KEY_KEY.into(),
            },
            target: SecretTarget::File {
                path: "/run/secrets/tls.key".into(),
                mode: 0o400,
            },
        }
    }

    fn ingress_spec(ident: &str) -> WorkloadSpec {
        let mut spec = WorkloadSpec::for_forge(
            "ingress",
            ImageRef {
                registry: "localhost".into(),
                repository: "passway".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            TierTag("infra".into()),
            vec![],
        );
        spec.expose.mesh.identity = MeshIdent(ident.into());
        spec
    }

    /// The consumer identity every fixture in this module deploys as.
    ///
    /// **Derived from the spec, not spelled out.** `WorkloadSpec::for_forge`
    /// names the workload `forge-<id>`, not `<id>`, so a hardcoded `"ingress"`
    /// here silently produces a rule that admits nobody and every rotation
    /// assertion fails for the wrong reason.
    fn ingress_consumer() -> workload_spec::secrets::SecretConsumer {
        workload_spec::secrets::SecretConsumer::of(&ingress_spec("ingress"))
    }

    fn ingress_access() -> workload_spec::secrets::SecretAccess {
        workload_spec::secrets::SecretAccess::Workloads(vec![
            workload_spec::secrets::WorkloadMatch::workload(ingress_spec("ingress").name),
        ])
    }

    /// An empty fleet secret store over an in-memory bucket (R911-F1).
    fn fleet() -> NodeSecretStore {
        Ok(FleetSecretStore::new(
            Arc::new(InMemoryObjectStore::new()),
            "le",
            "prod",
        ))
    }

    /// Seal `plaintext` for the ingress workload and write it to `store`.
    /// Through `off_runtime`, like every async caller: the store's debug
    /// tripwire panics on a bare call from a runtime thread.
    async fn put_secret(
        store: &NodeSecretStore,
        index: u64,
        name: &str,
        plaintext: &[u8],
    ) {
        let rec = seal_cluster_secret(&KEK, name, plaintext, index, ingress_access());
        let (store, name) = (store.clone().unwrap(), name.to_string());
        crate::fleet_secrets::off_runtime(move || store.write_secret(&name, &rec))
            .await
            .unwrap();
    }

    /// Compute the digest a workload's cluster File mounts resolve to against
    /// the current state — mirrors what the deploy handler seeds at registration.
    async fn digest_now(store: &NodeSecretStore, mounts: &[SecretMount]) -> u64 {
        let resolver = ClusterResolver::from_kek_file(
            store.clone(),
            kek_path(),
            SECRET_STORE_ROOT,
            ingress_consumer(),
        )
        .unwrap();
        let mounts = mounts.to_vec();
        crate::fleet_secrets::off_runtime(move || {
            content_digest(&resolve_secrets(&mounts, &resolver).unwrap())
        })
        .await
    }

    // A KEK file the resolver loads. Written once per test into its tempdir; the
    // path is stashed in a thread-local so the helpers above stay terse.
    thread_local! {
        static KEK_PATH: std::cell::RefCell<Option<std::path::PathBuf>> =
            const { std::cell::RefCell::new(None) };
    }
    fn kek_path() -> std::path::PathBuf {
        KEK_PATH.with(|p| p.borrow().clone().expect("kek path set by test"))
    }
    fn set_kek_path(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("cluster.kek");
        std::fs::write(&path, KEK).unwrap();
        KEK_PATH.with(|p| *p.borrow_mut() = Some(path.clone()));
        path
    }

    #[tokio::test]
    async fn rotation_rerenders_and_graceful_upgrades_only_changed_workloads() {
        let tmp = tempfile::TempDir::new().unwrap();
        let kek = set_kek_path(tmp.path());
        let mount_root = tmp.path().join("mounts");

        // Seed the fleet store with the initial cert + key.
        let store = fleet();
        put_secret(&store, 1, CERT_KEY, b"CERT-V1").await;
        put_secret(&store, 2, KEY_KEY, b"KEY-V1").await;

        // Pretend the workload was already materialized: its host tmpfs files
        // exist with the v1 material (so the test asserts a *rewrite*).
        let ident = "ingress";
        let wl_dir = mount_root.join(ident);
        std::fs::create_dir_all(&wl_dir).unwrap();
        std::fs::write(wl_dir.join("run_secrets_tls.crt"), b"CERT-V1").unwrap();
        std::fs::write(wl_dir.join("run_secrets_tls.key"), b"KEY-V1").unwrap();

        let mounts = vec![cert_mount(), key_mount()];
        let registry: SecretWorkloadRegistry = Default::default();
        registry.lock().unwrap().insert(
            ident.into(),
            SecretWorkloadEntry {
                spec: ingress_spec(ident),
                mesh: crate::mesh::MeshAssignment::stub(std::net::Ipv4Addr::new(100, 64, 0, 1)),
                file_mounts: mounts.clone(),
                content_digest: digest_now(&store, &mounts).await,
            },
        );

        let fake = FakeRuntime::new();

        // A bump that does NOT change this workload's material → no upgrade.
        reload_once(&store, &kek, &mount_root, &fake, &registry).await;
        assert!(
            fake.graceful_upgrade_calls().is_empty(),
            "no rotation yet → no upgrade"
        );

        // Rotate the cert (key unchanged) → the workload's combined digest moves.
        put_secret(&store, 3, CERT_KEY, b"CERT-V2-rotated").await;
        reload_once(&store, &kek, &mount_root, &fake, &registry).await;

        assert_eq!(
            fake.graceful_upgrade_calls(),
            vec![ident.to_string()],
            "rotation graceful-upgrades exactly the consuming workload"
        );
        // Host tmpfs cert file was rewritten in place with the new bytes; the
        // (unrotated) key file keeps its value.
        assert_eq!(
            std::fs::read(wl_dir.join("run_secrets_tls.crt")).unwrap(),
            b"CERT-V2-rotated"
        );
        assert_eq!(
            std::fs::read(wl_dir.join("run_secrets_tls.key")).unwrap(),
            b"KEY-V1"
        );
        // The stored digest advanced, so a redundant pass does not re-upgrade.
        reload_once(&store, &kek, &mount_root, &fake, &registry).await;
        assert_eq!(
            fake.graceful_upgrade_calls().len(),
            1,
            "digest committed → no duplicate upgrade on an unchanged pass"
        );
    }

    #[tokio::test]
    async fn missing_secret_defers_without_upgrading() {
        let tmp = tempfile::TempDir::new().unwrap();
        let kek = set_kek_path(tmp.path());
        let mount_root = tmp.path().join("mounts");

        let store = fleet();
        // Only the key is present — the cert record was never written.
        put_secret(&store, 1, KEY_KEY, b"KEY-V1").await;

        let mounts = vec![cert_mount(), key_mount()];
        let registry: SecretWorkloadRegistry = Default::default();
        registry.lock().unwrap().insert(
            "ingress".into(),
            SecretWorkloadEntry {
                spec: ingress_spec("ingress"),
                mesh: crate::mesh::MeshAssignment::stub(std::net::Ipv4Addr::new(100, 64, 0, 1)),
                file_mounts: mounts,
                // Unknown initial digest — but the cert can't resolve, so the
                // pass must defer rather than upgrade against a partial pair.
                content_digest: 0,
            },
        );

        let fake = FakeRuntime::new();
        reload_once(&store, &kek, &mount_root, &fake, &registry).await;
        assert!(
            fake.graceful_upgrade_calls().is_empty(),
            "an unresolvable (partial) secret must defer, not upgrade"
        );
    }
}
