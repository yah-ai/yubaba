//! @arch:layer(core)
//! @arch:role(net)
//!
//! **Who may call this node's HTTP control plane** (R876-B15).
//!
//! yubaba has two control-plane transports and, until this module, only one
//! of them asked who was calling. The mshr/QUIC lane answers "which machine
//! is this connection?" from the peer's verified TLS certificate and then
//! asks [`control_plane::admission`](crate::control_plane::admission)
//! whether that `NodeId` is entitled. The axum lane on `:7443` asked
//! nothing at all: `build_router` applied exactly one layer
//! (`correlation_id_layer`), so a single unauthenticated reach to a node's
//! mesh address could read every workload's spec, deploy a workload, and
//! drive a self-update of the node's own binary. "It is on the mesh" was
//! the whole access-control story.
//!
//! ## The model
//!
//! Every route is in exactly one [`AuthClass`], and the class is
//! *structural* — [`crate::build_router`] builds one sub-router per class
//! and layers each with its own middleware. There is no path table to fall
//! out of sync with the routes, and adding a route means picking a
//! sub-router to add it to.
//!
//! | Class | Credential | Examples |
//! |---|---|---|
//! | [`AuthClass::Public`] | none | `GET /health`, `GET /mesh/leader-health` |
//! | [`AuthClass::Peer`] | peer **or** operator token | raft RPC, `/raft/write`, lease renew, service discovery, workload reads |
//! | [`AuthClass::Operator`] | operator token only | `/workloads/deploy`, `/workloads/{id}/spec`, `/self-update`, `/secrets`, raft membership |
//!
//! Two credential tiers, one verification path, and the split is
//! deliberate rather than incidental:
//!
//! - **Peer** tokens are PASETO **v4.local** — symmetric, under a
//!   cluster-wide key every node in the cluster holds. The holders are
//!   mutually-trusting members of one trust domain and they must verify
//!   each other with *no network round-trip*, because raft cannot depend on
//!   cheers (or anything else) being reachable to hold an election. One
//!   secret, N holders, no distribution graph.
//! - **Operator** tokens are PASETO **v4.public** — asymmetric, verified
//!   against operator public keys configured on the node. A node can
//!   *verify* an operator token and cannot *forge* one, which is the
//!   property that matters for `/self-update`: compromising a node must not
//!   yield the ability to order its peers to swap their own binaries.
//!
//! An operator token satisfies [`AuthClass::Peer`] as well; a peer token
//! never satisfies [`AuthClass::Operator`].
//!
//! ## Why there is a mode, and when it goes away
//!
//! Enforcing this is a flag day: every caller on the fleet today
//! (the `yah` CLI through `cloud-client`, the passway doors' discovery
//! poll, node-to-node raft) sends no credential at all, and this camp runs
//! a shared tree that ships to a live fleet serving tenant traffic. Landing
//! `Require` in one step would push a yubaba that refuses the fleet's own
//! traffic.
//!
//! So [`AuthMode`] is a *roll* sequencer, not a feature flag: the code is
//! written as if only `Require` exists, and `Warn` exists only so the roll
//! can see two versions at once. It defaults to [`AuthMode::Warn`] —
//! anonymous requests are logged and served, so a node upgraded ahead of
//! its callers keeps working. Flipping the default to `Require` and
//! deleting `Warn` is R876-T18.
//!
//! `Warn` is deliberately *not* "auth off". A credential that is present
//! and bad — bad signature, expired, wrong audience, wrong tier — is
//! refused in **both** modes. Only *absence* is tolerated under `Warn`.
//! That is what makes the soak meaningful: a caller wired up during the
//! roll gets real verification the moment it starts signing, so the flip
//! to `Require` is a no-op for everything already talking.
//!
//! @yah:ticket(R876-T18, "Finish the R876-B15 roll: sign the remaining yubaba callers, distribute the keys, then flip auth-mode to require and delete Warn")
//! @yah:at(2026-10-10T06:39:06Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R876)
//! @yah:gotcha("THE ORDER IS NOT NEGOTIABLE AND STEP 3 IS THE ONLY DANGEROUS ONE. `--auth-mode require` on a node whose PEERS do not yet send a peer token 401s every /raft/append-entries and /raft/vote that node receives, which takes it out of the quorum while systemd still reports it active — the same shape as the R876 protocol-skew gotcha, reached by a different mechanism. Steps 1 and 2 are individually safe to land and roll in any order: a signed caller against a warn-mode node is served (the token is verified, and a VALID token is accepted in both modes), and a keyed node with no signed callers behaves exactly like an unkeyed one.")
//! @yah:gotcha("WARN MODE IS NOT AUTH-OFF, AND THAT IS LOAD-BEARING FOR STEP 1. A credential that is PRESENT AND BAD — bad signature, expired, wrong audience, missing scope, peer token on an operator route — is refused with 401/403 in BOTH modes; only ABSENCE is tolerated under warn. So each caller wired in step 1 gets real verification the moment it starts signing, against nodes still in warn. That is what makes step 3 a no-op for everything already talking, and it is also the trap: a step-1 caller that mints with the wrong audience or the wrong tier breaks IMMEDIATELY rather than at the flip. Test each caller against a require-mode node locally first — `http_auth::router_tests` and cloud-client's `an_enforcing_yubaba_refuses_a_tokenless_client_and_serves_a_tokened_one` are both worked examples of that setup.")
//! @yah:gotcha("MAX_TOKEN_TTL_SECS IS 24h AND IT IS CHECKED AGAINST *NOW*, NOT AGAINST `iat`. A long-lived token pasted into a systemd unit will start 401ing a day later with `token exp is Ns out, beyond the ceiling` or `token is expired`. Peer-side callers must MINT PER PROCESS-START AT MINIMUM, and really should re-mint on a timer — `mint_peer_token` is pure and cheap (no I/O, no round-trip), so a fresh token per request is affordable and is the shape to prefer over caching one.")
//! @yah:handoff("STEP 1, IN-PROCESS HALF — LANDED (uncommitted; git-policy defer). New yubaba-consensus/src/peer_auth.rs: PeerSigner (mints one token per request via an injected closure, so consensus stays crypto-free) + PeerClient (reqwest::Client + signer; get/post/delete sign, raw() for an unsigned builder). Re-exported as yubaba::peer_auth. HttpAuthPolicy::peer_signer(subject) in http_auth.rs mints peer tokens under the node's own cluster key, DEFAULT_TOKEN_TTL_SECS each; unkeyed means unsigned, which is byte-identical to the old behaviour.")
//! @yah:handoff("THREADED THROUGH: YubabaNetworkFactory::new(signer), so all raft RPC is signed; raft::open/open_with_state_machine(.., signer); client_write_forwarded takes &PeerClient; membership_ratchet::spawn/run_once; lease_renewal / member_registration / mesh_directory / acme_issuer spawn(.., signer); leader.rs hand_off_to_eligible_voter now uses state.http; rollout::commit_guarded forward_with is now Option<&PeerClient>. ServerState.http is a PeerClient. with_http_auth and with_node_id both re-key it through rekey_peer_http, so boot order does not matter. main.rs passes server_state.http_auth.peer_signer(node:<id>) to raft and shared_state.http.signer() to every loop. headroom.rs and state_backup.rs dial no peer over HTTP (checked by grep), so they needed no change.")
//! @yah:handoff("DISCOVERED AND FIXED, the trap named in this ticket's own gotcha: floater replication (R936-B12) dialled OPERATOR-class routes node to node, so a peer token would have been a 403 in BOTH modes, failing immediately rather than at the flip. (1) GET/POST /workloads/floaters and POST /workloads/floaters/{ident}/forget moved to the PEER sub-router in build_router. Reason: they are node-to-node, including the owner's once-a-minute re-publish with no operator in the loop, and a cluster-key holder can already make the same writes through /raft/write. (2) The forwarded floater deploy (admit_floater) and the owner destroy (forget_floater) now pass through the operator's OWN Authorization header via the new authorization_of / forward_as_operator in lib.rs. WorkloadDeployBody gained #[serde(skip)] forward_auth, and destroy_workload_as gained a forward_auth param. deploy_workload_spec_boxed now calls deploy_workload_spec_as directly.")
//! @yah:handoff("HARNESS: yubaba-test-harness gains test_cluster_enforcing(runtime, nodes, policy, cluster_key_hex). Every node runs require mode under one key and signs raft; ClusterNode keeps the key so restart_node rebinds under the same policy.")
//! @yah:handoff("CLUSTER EPOCHS: network.rs, raft/mod.rs and store.rs moved. All three diffs are this change only (verified against HEAD). Re-recorded as NOT BREAKING on both axes (cluster_protocol stays 8, state_epoch stays 7), with a dated surface_rerecords entry giving the reasoning: header-only change, and a mixed cluster interoperates in every combination except require-receiver + unsigned-sender, which is chosen by config and owned by step 3's roll order. The file was edited textually from HEAD so its mixed escaping is preserved; the diff is 16+/6-.")
//! @yah:handoff("Tree anchor at handoff: 2cbdc7963bfc28a81446a243fcc0f8d2ff19ab04 — the shared tree as I left it. Diff against it (`git diff 2cbdc7963bfc28a81446a243fcc0f8d2ff19ab04..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:gotcha("\"SIGNATURE CHURN FOR PEERS: raft::open / open_with_state_machine gained a 4th PeerSigner arg, client_write_forwarded takes &PeerClient, and five spawn fns gained a trailing signer. Any in-flight branch calling them needs PeerSigner::unsigned() or state.http.signer().clone().\"")
//! @yah:next("STEP 3 — FLIP AND DELETE. Set `--auth-mode require` on one node, verify the fleet still elects and serves AND that its passway doors and tenant-streamer keep working (both now sign), then roll. Once every node is on require: delete AuthMode::Warn, delete the --auth-mode flag, make HttpAuthPolicy::new require a trust root unconditionally, delete the anonymous branch of http_auth::decide, and consider making the out-of-process key file REQUIRED (delete the unsigned path in tenant-streamer/passway).")
//! @yah:handoff("CLUSTER EPOCHS re-recorded NOT BREAKING on both axes (cluster_protocol 8, state_epoch 7) with a second dated 2026-10-03 surface_rerecords entry: raft/mod.rs, network.rs, store.rs changed only by the import-path rename; diffed all three against 2cbdc7963bfc28a81446a243fcc0f8d2ff19ab04 and every hunk is R876-T18 work.")
//! @yah:verify("cargo test -p yubaba-auth-token -p yubaba-consensus -p yubaba-tenant-streamer --lib = 6 + 134 + 36 passed (consensus was 137; its 3 peer_auth tests moved into yubaba-auth-token)")
//! @yah:verify("cargo test -p passway = 236 + 45 + 41 passed, then +2 new: discovery::tests::a_keyed_poll_carries_a_peer_token_under_the_cluster_key (captures the request head off a real socket, decrypts the token under the cluster key, validate_claims(PEER_SCOPE) = svc:passway) and a_named_but_unreadable_key_file_is_a_boot_failure. cargo test -p cloud-client an_enforcing_yubaba = 1 passed. cargo run -p xtask -- cluster-epochs = surfaces match; cargo test -p xtask cluster_epoch = 18 + 8 passed")
//! @yah:gotcha("PASSWAY `cargo deny check` (run 2026-10-03 from oss/passway) FAILS advisories on RUSTSEC-2026-0285 — rustls 0.23.41, fix >=0.23.45 (`cargo update -p rustls`). PRE-EXISTING: rustls was already in the graph via pingora/reqwest; yubaba-auth-token adds no TLS crate. bans/licenses/sources all pass with the new dep. Not fixed here (outside this ticket; passway's Cargo.lock is untracked).")
//! @yah:next("STEP 2 — KEYS ONTO THE FLEET (live-fleet; operator must authorize). `yubaba auth cluster-keygen --out <path>` once; SAME hex file on every node at /etc/yah-cloud/cluster.key (0600). Three consumers per node now read it: yubaba (YUBABA_CLUSTER_KEY_FILE in a systemd drop-in, R881 --container-net shape), tenant-streamer (`cluster_key_file = \"/etc/yah-cloud/cluster.key\"` in its TOML), each passway door (PASSWAY_YUBABA_CLUSTER_KEY_FILE in its env). The passway line belongs in app/yah/cli/src/cloud.rs passway_discovery_env (~5427) AND for ingress-owner doors — but render it ONLY once the file is on the node: a named-but-missing key file is a deliberate boot failure, so rendering it early crash-loops the door. Operator keys: `yubaba auth keygen --secret-out <path>` per operator, public hex as YUBABA_OPERATOR_KEYS. Keys with mode=warn change nothing observable, so soak before step 3.")
//! @yah:handoff("TENANT-STREAMER: StreamerConfig gained optional `cluster_key_file` (path); HttpOwnership::new and RpoReporter::new take a PeerSigner; main.rs builds one via PeerSigner::from_key_file (subject svc:tenant-streamer@node:<id>) — an unreadable NAMED file fails startup, absent warns and runs unsigned. PASSWAY: new env PASSWAY_YUBABA_CLUSTER_KEY_FILE (discovery::CLUSTER_KEY_FILE_ENV, yubaba_peer_signer()); YubabaDiscoveryConfig and OwnerRouteConfig gained `signer`; path_routes_file::into_mount_sources takes &PeerSigner. DISCOVERED: passway::owner (GET /cluster/ingress-owner, Peer-class) was a THIRD unsigned passway caller the previous next-list missed — now signed too. Every call-site route was confirmed Peer-class in build_router.")
//! @yah:handoff("STEP 1 IS CODE-COMPLETE: every yubaba caller in the tree signs Peer-class calls when keyed (in-process half last session; tenant-streamer + passway discovery/ingress-owner/inner-door this session via the new oss/yubaba/crates/yubaba-auth-token). What remains (steps 2 and 3) is live-fleet and needs operator authorization; nothing further is codeable before keys exist on nodes.")
//! @yah:handoff("Tree anchor at handoff: 2cbdc7963bfc28a81446a243fcc0f8d2ff19ab04 — the shared tree as I left it. Diff against it (`git diff 2cbdc7963bfc28a81446a243fcc0f8d2ff19ab04..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:handoff("OPERATOR DECISION 2026-10-03: step 2 AUTHORIZED NOW (option A), not deferred to the R876-B11/B12 paired hotship. Scope of the authorization: generate ONE cluster key, install it at /etc/yah-cloud/cluster.key (0600) on every node, wire YUBABA_CLUSTER_KEY_FILE via a systemd drop-in, auth-mode stays WARN. NOT authorized by this answer: step 3 (any --auth-mode require), and any yubaba/kamaji binary ship (the V10-node protocol-skew gotcha on R876 still applies — do not hotship a tree build to us-east-001 to get the new key-file code there).")
//! @yah:gotcha("BEFORE STEP 2 ON A NODE, CHECK THE RUNNING yubaba ACTUALLY READS YUBABA_CLUSTER_KEY_FILE. HttpAuthPolicy (R876-B15) may not be in the deployed binary — us-east-001 was measured at 0.8.38-h5. On a binary that predates it the drop-in is inert (harmless, but not 'keyed'); record per node which case it is rather than assuming. Restarting yubaba to pick up the drop-in is a live restart on the node serving noisetable.com: check apex per-origin with --resolve afterwards (see R876 next).")
//! @yah:handoff("STEP 2 DONE ON THE FLEET 2026-10-03 (auth-mode stays WARN everywhere). OPERATOR CALL (ask_user, this session): ONE KEY PER SOVEREIGN GROUP, not one fleet-wide — the binary's own help defines the cluster key per cluster, and a shared key would let a dev box mint prod peer tokens. PROD key (sha256 prefix 6d2f1fbb7250, generated on us-west-001) on us-west-001, us-east-001, us-south-001 and standalone us-west-003. DEV key (prefix 45b35a5550b7, generated on us-west-011) on us-west-011/013/014 and standalone us-west-002. Each: /etc/yah-cloud/cluster.key 0600 root, piped node-to-node (never on the laptop), plus drop-in /etc/systemd/system/yubaba.service.d/85-cluster-key.conf setting YUBABA_CLUSTER_KEY_FILE, then a restart — standalones, then dev followers 11, 13, leader 14, then prod followers 001 (node 2), east-001 (node 3), leader south-001 (node 1). Every node logged `http control-plane auth policy mode=warn cluster_key=true`; both quorums stayed whole (prod leader 1 term 135, dev leader 14 term 542); noisetable.com and yah.dev 200 via all three prod origins with --resolve before and after. Every deployed yubaba (0.8.42 / 0.8.42-h8 / 0.8.41-h1) READS the key file but does NOT sign (grep -c -a: `peer token presented but this node has no cluster key`=1, `node:unregistered`=0), so this is verify-only until the tree's step-1 code ships. NOT KEYED: us-west-015 — its mesh IP 100.64.0.7 and LAN 192.168.10.15 both answer as `leifs-MacBook-Air.local` (yubaba 0.8.20, no systemd), so the declared box is not reachable at its declared addresses; inventory drift, not touched.")
//! @yah:verify("LIVE 2026-10-03: a peer token minted under the prod key against http://100.64.0.3:7443/cluster/ingress-owner = 200; a dev-key token against the same = 401 `invalid credential` (per-group separation holds); no token = 200 (warn); dev token against 100.64.0.10 = 200.")
//! @yah:handoff("FYI FROM R605-F16, 2026-10-07: the whole DEV group now runs a tree build with step-1 signing, hot-shipped as 0.8.43-h4. That covers voters us-west-011/013/014 and the four new learners us-west-111/112/141/142, which are microVMs. This is a dev-only binary ship, still in auth-mode WARN. Each learner got the dev cluster key (sha256 prefix 45b35a5550b7), piped voter-to-guest into /etc/yah-cloud/cluster.key, plus 85-cluster-key.conf. dev-raft-node.sh's JOIN mode now requires and installs that key, because an unkeyed node refuses a signed append-entries. Measured on us-west-013's journal (UTC): before the roll it logged about 14.5k `unauthenticated request served` warnings per 10 min. After the roll it logged 11 in 15 min, and none of them were raft RPCs. So the signing path works node to node on real hardware in the dev group. Prod is untouched.")
//! @yah:gotcha("STEP 1 WAS ONLY HALF DONE: the 'STEP 1 IS CODE-COMPLETE' handoff covers PEER-class callers only. Every production OPERATOR-class caller is still tokenless. CloudClient::with_token (crates/yah/cloud-client/src/lib.rs:1464) is used only by a test, and the operator callers in app/yah/cli (cloud.rs, camp.rs, qed.rs, rollout/*, yubaba_client.rs, mesh.rs, ...), app/yah/desktop panels, agent-tools cloud_tools, tower triggers and fleet-metrics all construct unsigned clients. Under --auth-mode require those calls 401. A PRESENT operator token is refused in BOTH modes on a node whose YUBABA_OPERATOR_KEYS is empty (http_auth.rs verify_operator: 'operator token presented but this node has no operator key'). So the order is: (2b) operator PUBLIC key onto every node, then client signing activated, then soak to zero 'unauthenticated request served', then step 3. Code half filed as R876-T21; T18 depends on it.")
//! @yah:depends_on(R876-B15)
//! @yah:depends_on(R876-T21)
//! @yah:handoff("OPERATOR DECISION 2026-10-09 (ask_user F4361). STEP 2b AUTHORIZED: one operator keypair, secret only on the camp machine (0600). Its public key goes in as YUBABA_OPERATOR_KEYS via a systemd drop-in on every keyed node, prod and dev. Rolling restart in the 10-03 order, auth-mode stays warn, apex checked per origin with --resolve. Runs once R876-T21 (operator callers sign) lands and verifies. STEP 3 AUTHORIZED AS A FULL ROLL: dev group first, then prod. Each node flips to require only after a soak window shows ZERO 'unauthenticated request served', with quorum + apex checks after each flip. Then delete AuthMode::Warn and the --auth-mode flag. Fleet at decision time (/health, measured 2026-10-09): prod voters us-west-001 0.8.44-h5, us-east-001 and us-south-001 0.8.44-h4; us-west-003 0.8.43; dev 011 yubaba 0.8.43-h6 / kamaji 0.8.45-h2, 013/014 0.8.43-h5; us-west-002 0.8.41-h1.")
//! @yah:handoff("STEP 2b DONE ON THE FLEET 2026-10-10 ~04:32-04:46Z. auth-mode is still WARN on every node. Two operator public keys are installed via /etc/systemd/system/yubaba.service.d/86-operator-keys.conf (Environment=YUBABA_OPERATOR_KEYS=<human>,<cloudadmin>). HUMAN key: pubkey sha256 prefix a07fc0f69a47, generated by `yubaba auth keygen` (tree build, oss/yubaba/target/debug). Its secret is 0600 at ~/.yah/operator.key.pending and is NOT ACTIVATED: moving it to ~/.yah/operator.key switches every tree-built yah CLI to signing, and that is the next step. svc:yah-cloud-admin key: pubkey sha256 prefix 34ae220c91fc. Its secret is in vault slot yubaba-operator-yah-cloud-admin, declared at .yah/infra/secrets/yubaba-operator-yah-cloud-admin.toml (prod; access yah-cloud-admin; target /run/secrets/yubaba-operator.key 0400). It was shipped with `yah cloud secret put --machine us-west-001`, status reads in-sync, and the local temp file was overwritten and deleted. NOT YET WIRED: the cloud-admin workload does not read that file yet. New declaration file is uncommitted (git defer).")
//! @yah:handoff("NODES DONE, in order, each logging `http control-plane auth policy mode=warn operator_keys=2 cluster_key=true`: standalones us-west-003 and us-west-002; dev learners us-west-111/112/113 (100.64.0.13/14/15; 141/142/143 timed out on the mesh and were skipped as not live); dev followers 013 and 014; dev leader 011; prod followers us-west-001 (node 2) and us-east-001 (node 3); prod leader us-south-001 (node 1). Nobody set YUBABA_OPERATOR_KEYS before, so nothing was merged. SKIPPED: us-west-015 (inventory drift, per the 10-03 entry). LEADERS: dev 11 term 1192 before and after, 011 came back as leader on the same term; prod 1 term 135 before and after. Logs stayed equal across voters after every restart (dev 1522, prod 2826050). noisetable.com and yah.dev returned 200 via east, south and west with --resolve, before the roll and after every prod restart.")
//! @yah:handoff("INCIDENT ON us-west-013, REPAIRED with operator go (ask_user F4362, resume F4363). Its 85-cluster-key.conf was 147 NUL bytes (mtime 2026-10-04 00:00, most likely an SD-card write never flushed) and /etc/yah-cloud/cluster.key was missing. The process running since 10-03 still held the key, so the damage stayed hidden until my restart. After the restart 013 logged cluster_key=false and 401'd every signed /raft/append-entries (5734 rejections in about 2 min), leaving the dev quorum at 2/3. Fix: piped the dev key from 011 into 013 (prefix 45b35a5550b7, 0600 root), rewrote the 10-03 drop-in, synced, and restarted. 013 then logged cluster_key=true, zero 'no cluster key' rejections, and caught up to log 1522. A read-only scan of all 11 keyed nodes afterwards found every drop-in intact and every key file correct for its group.")
//! @yah:verify("\"LIVE 2b ACCEPTANCE on all 11 nodes (/tmp/t18b-tools/accept.sh, GET /diagnostics, Operator class): token minted from ~/.yah/operator.key.pending = 200; token from a throwaway keypair = 401 {\\\"error\\\":\\\"invalid credential\\\"}; no token = 200 (warn). Pre-roll baseline on us-west-003: the good token got 401, as expected with no key installed.\"")
//! @yah:handoff("CENSUS FOR STEP 3, read-only, journal window 03:49-04:50Z on 2026-10-10 (yubaba -u journal, JSON lines; script + raw output in /tmp/t18c/{remote.sh,agg.py,*.out}). Nothing on any node was changed. The warn line carries uri+class but NO source address or user agent, so attribution comes from the route, from timing (fan-out at the same second on every node = the camp laptop), and from per-process env/binary reads. That part is INFERENCE.\n1) RAFT IS CLEAN. No unsigned /raft/append-entries or /raft/vote on any node. On the dev nodes, about 20k/hr each of /mesh/lease-renew and /raft/pre-vote, plus 013's 102k+21k+20k 'peer token presented but this node has no cluster key' rejections, ALL stop at 04:42:12. That is the us-west-013 incident (013 ran unkeyed, so it sent unsigned and refused signed), not a standing caller. The count since 04:46:30 is 0.\n2) PROD us-west-001 / us-east-001 / us-south-001 (yubaba 0.8.44-h5 / -h4 / -h4, all able to sign): Peer /service-records about 32.4k-32.9k/hr per node and Peer /cluster/ingress-owner 1799/hr per node (every 2s) are the PASSWAY DOORS. Every door process (passway, passway-noisetable, passway-scrabcake, passway-test on east) runs a binary that CAN sign (grep -c -a PASSWAY_YUBABA_CLUSTER_KEY_FILE = 3), but its environ has NO PASSWAY_YUBABA_CLUSTER_KEY_FILE. FIX: config only, i.e. render the env line (cloud.rs passway_discovery_env plus the ingress-owner door env) and restart each door. Legacy passway-mesh / passway-demux / passway-http-router run deleted pre-signing binaries (count = 0) with no PASSWAY_YUBABA_URL, so they do not appear to poll yubaba; verify after the doors are fixed. NO tenant-streamer process or TOML on any keyed node. yah-cloud-admin: a container record exists on us-west-001 (yah ns, cr.yah.dev/yah-cloud-admin:20260914-amd64@sha256:75d5fc3a…), but there is NO process and :4325 is not listening (curl 000), so it contributes 0 traffic today. When it is revived it needs the image/wiring that reads /run/secrets/yubaba-operator.key (binary ship).\n3) CAMP-SIDE (laptop, 0.8.43 daemon + CLI, unsigned): /workloads (Peer, 2-5/hr per node, fanned out at the same second 04:26:50 on every node), /raft/status (Peer, 1-9/hr), /diagnostics (Operator, 1-2 = the 2b acceptance no-token probe), /workloads/{ident} Operator 1-2, /workloads/{ident}/deploy-status + /workloads/deploy (Peer; 52 on east, 29 south, 1 west, all at 03:58, the passway-inner-noisetable-marketing deploy), and /secrets + /secrets/yubaba/operator/yah-cloud-admin (Operator, w001 04:29, the 2b `yah cloud secret put`). FIX: laptop rebuild plus activating ~/.yah/operator.key (R876-T21). NOTE: /workloads, /raft/status and deploy-status are PEER class, so an operator token will NOT satisfy them. A peer token is required, or those routes need to move to Operator. Check build_router before flipping, because otherwise the CLI breaks at require even when signed.\n4) DEV us-west-011 (0.8.43-h6): Peer /service-records about 366 per 4 min after the fix, from its passway door (pid 609102, binary can sign, env has no key file). FIX: config only. us-west-013/014 (0.8.43-h5) and learners 111/112 (0.8.43-h5) and 113 (0.8.43-h6): only camp-side residue after the fix. us-west-002: yubaba 0.8.40, grep node:unregistered = 0, so it CANNOT sign. It has no peers, so only camp traffic reaches it. It is standalone and can flip once the laptop signs, but it needs a binary ship before the Warn deletion lands in a release.\n5) BAD-CREDENTIAL lines: only the 2b acceptance's throwaway-key /diagnostics probe (1 per node), plus 2 'no operator key' on us-west-003 before its 2b restart. Expected, none live.\nPER-NODE TABLE (route | count/hr | caller | configured? | binary can sign? | fix): w001/e001/s001: /service-records ~32.5k + /cluster/ingress-owner 1799 | passway doors | NO | YES | config. Camp routes (above) | <60 | laptop | n/a | NO (0.8.43) | laptop rebuild + T21. w003 (0.8.43, standalone): only camp (3 /workloads, 1 /raft/status, 2 /diagnostics) | laptop | laptop rebuild. w011: /service-records ~5.5k | passway door | NO | YES | config, plus camp. w013/w014/w111/w112/w113: camp only | laptop rebuild. w002: camp only, yubaba cannot sign | laptop rebuild (binary ship before Warn deletion).\nMINIMAL ORDERED ACTIONS TO ZERO: (a) render PASSWAY_YUBABA_CLUSTER_KEY_FILE=/etc/yah-cloud/cluster.key into every door env on w001/e001/s001/w011 and restart the doors one at a time, checking apex with --resolve. This removes more than 99.9% of the count. (b) Decide the class of the Peer routes the CLI hits (/workloads list, /raft/status, deploy-status): either move them to Operator or have the CLI mint a peer token. (c) Land R876-T21, rebuild the camp yah + yah.app, and move operator.key.pending to operator.key. (d) Soak 1h and re-run /tmp/t18c census, expecting 0. (e) Then flip, dev first per the 10-09 call. yah-cloud-admin is dormant and does not block.")
//! @yah:gotcha("CORRECTION TO THE CENSUS, from the leader, 2026-10-10. The census says the laptop's calls to PEER-class routes (/workloads, /raft/status, deploy-status) cannot be satisfied by an operator token. That is wrong: http_auth.rs:184-189 Tier::satisfies returns true for AuthClass::Peer at ANY tier, and validate_claims checks the token's OWN tier scope. So once the T21/T22/T23 build runs on the laptop with ~/.yah/operator.key active, those calls are covered with no extra work. R876-T21's cloud-client test exercises exactly this: a signed POST /workloads/drain is served.")
//! @yah:handoff("LEADER SESSION 2026-10-09/10 (@Glimmerstone:dove, session:e85751b8). Handing off at the context budget.\n- Code prerequisites for step 3, all in REVIEW and leader-verified, all uncommitted (git defer):\n  - R876-T21: laptop/camp operator callers sign via OperatorSigner, keyed by ~/.yah/operator.key.\n  - R876-T22: yah-cloud-admin gets its own principal svc:yah-cloud-admin; on-node scripts mint peer tokens; the `yubaba raft` CLI signs.\n  - R876-T23: the camp pond trusts the operator key.\n- STEP 2b DONE on all 11 keyed nodes (see the 2b entries above).\n- STEP-3 CENSUS DONE (see 'CENSUS FOR STEP 3' above, and the correction gotcha: an operator token DOES satisfy Peer routes).\n- The operator authorized step 3 as a FULL ROLL (F4361). Nothing has flipped yet; every node is still warn.")
//! @yah:handoff("Tree anchor at handoff: abb379b51e9a964efc4d939fcd01dfaa83a12329 — the shared tree as I left it. Diff against it (`git diff abb379b51e9a964efc4d939fcd01dfaa83a12329..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("5) CODE, only after every node is on require. Delete AuthMode::Warn and the --auth-mode flag, make HttpAuthPolicy::new require a trust root, and delete decide's anonymous branch. DECIDE THE POND: with no operator key file, a post-Warn pond has no trust root. Recommended: the camp mints a per-camp operator keypair under ~/.yah when none exists. Then ship that yubaba to the fleet. Landing it earlier is dangerous: peers hotship tree yubaba to dev routinely, and a Warn-less build forces require on a node whose callers are not yet signed.")
//! @yah:next("1) PASSWAY DOORS, the config-only fix covering >99.9% of the unsigned count. Doors on us-west-001, us-east-001, us-south-001 and us-west-011 run signing-capable passway but lack PASSWAY_YUBABA_CLUSTER_KEY_FILE. /etc/yah-cloud/cluster.key now exists on every keyed node, so render `PASSWAY_YUBABA_CLUSTER_KEY_FILE=/etc/yah-cloud/cluster.key` in app/yah/cli/src/cloud.rs passway_discovery_env (~5427) AND for the ingress-owner doors. Then re-apply, and reload the doors gracefully (hotship's door path RELOADS units; it never restarts them). A named-but-missing key file is a deliberate passway boot failure, so check that the file exists on each node first.")
//! @yah:next("2) LAPTOP. Build and install a yah CLI and yah.app containing T21/T22/T23. The operator must restart yah.app, because the camp daemon is still 0.8.43 and its calls are unsigned. THEN run `mv ~/.yah/operator.key.pending ~/.yah/operator.key`. Order matters: every node already trusts the public key (prefix a07fc0f69a47), and the pond respawns on its own (T23).")
//! @yah:next("3) us-west-002 (dev standalone, yubaba 0.8.40/0.8.41-h1) cannot sign. Hotship a tree yubaba there, paired with kamaji per the proto-skew rule and with passway per R876-B20's --allow-routes-skew guard. yah-cloud-admin is not running, so it contributes no unsigned traffic; when R959 deploys it, its service.toml already mounts the svc:yah-cloud-admin secret.")
//! @yah:next("4) SOAK AND FLIP. Re-run the census (read-only). Once a node shows ZERO `unauthenticated request served` over a soak window of at least 30 min, flip it with a drop-in YUBABA_AUTH_MODE=require and restart. Order: dev standalone, dev followers, dev leader, then prod standalone, prod followers, prod leader. After each flip, check quorum, check apex per origin with --resolve (east 51.81.85.145, south 45.32.194.254, west 15.204.89.240), and confirm the journal shows zero `credential required` rejections. us-west-015 is inventory drift, so skip it and record why.")
//! @yah:handoff("PROD OUTER DOORS + MESH DOORS SIGNING (2026-10-10 ~05:36-05:40Z node time, session:ead75f7f). Appended `PASSWAY_YUBABA_CLUSTER_KEY_FILE=/etc/yah-cloud/cluster.key` (backup `<env>.pre-r876t18`) to /etc/passway-{noisetable,scrabcake}.env + /etc/passway.env (w001, s001) / /etc/passway-test.env (e001), then `systemctl reload` (graceful upgrade): each new MainPID has the key in its environ. passway-mesh (no graceful ExecReload, was running a DELETED pre-signing binary) got the same line in /etc/passway-mesh.env and a `systemctl restart` one node at a time, w001 (ingress owner) first; new pid runs /usr/local/bin/passway with the key. mesh door (cloud.mesh.yah.dev/health) and noisetable.com + yah.dev 200 via east/south/west --resolve before and after every step. Scripts: /tmp/t18d/{door.sh,meshfix.sh,mesh.sh}. us-west-011 has NO systemd door: its only passway is the noisetable-marketing INNER door (kamaji-supervised). Dev nodes 013/014/111/112/113/003/002 already read ~0 unsigned (013: 5 in 60 min, laptop residue).")
//! @yah:gotcha("NOISETABLE.COM APEX OUTAGE 2026-10-10 05:47:02-06:28Z (~41 min, all three origins 503), root-caused and recovered. An UNSIGNED POST /workloads/deploy of passway-inner-noisetable-marketing hit all three prod nodes at 05:47:02. The caller is unidentified: not @Ashguard:eclipse's release run (their account: it was in cargo-test), and not this session. It carried a v2 path-routes table (R876-B20 renumbering: discover mounts became schema 2). The prod /usr/local/bin/passway predated B20 and reads v1 only, so the replacement inner door panicked at boot in a crash loop ('unsupported schema_version 2: this passway reads version 1 only', /var/lib/yah/kamaji/native/passway-inner-noisetable-marketing/stderr.log). The deployed 0.8.44 yubaba lacks B20's node-side inner_door_schema gate, so it admitted the table. RECOVERY (operator F4367: downtime acceptable if the fix is the better path): `scripts/hotship.sh --nodes us-west-001,us-east-001,us-south-001 --binaries passway` (0.8.47-h1, sha256 d4674aa4…). The outer doors reloaded gracefully, passway-mesh was STAGED (not restarted), and the crash-looping inner doors booted the new bytes on kamaji's next fork. noisetable.com + yah.dev are 200 via east/south/west --resolve. LESSON for B20: any inner-door redeploy from a tree CLI onto a node whose passway predates B20 reproduces this. us-west-011 (dev) is still on a v1-only passway.")
//! @yah:handoff("SESSION @Ashguard:polaris (session:ead75f7f), 2026-10-10 ~05:30-06:40Z. Every node is still auth-mode WARN; nothing has flipped. DONE: (1) Prod outer doors + passway-mesh sign (see the earlier handoff entry). (2) CODE: oss/yubaba/crates/cloud/src/inner_door.rs has new pub const DOOR_CLUSTER_KEY_FILE, and the inner-door WorkloadSpec now carries PASSWAY_YUBABA_CLUSTER_KEY_FILE. app/yah/cli/src/cloud.rs door_cluster_key_line() uses that const (the CLI's private copy is deleted). Tests: `cd oss/yubaba && cargo test -p yah-cloud --lib inner_door` = 22 passed; `cargo test -p yah --lib passway` = 37 passed. (3) LAPTOP SIGNS: the installed yah.app + ~/.local/bin/yah (0.8.45+abb379b5-dirty, 22:33) already contained T21. Moved ~/.yah/operator.key.pending -> ~/.yah/operator.key. A signed `yah cloud secret ls` was served, with 0 unsigned / 0 bad-credential on prod. (4) PASSWAY 0.8.47-h1 (reads routes schemas 1+2) hotshipped to w001/e001/s001, 0.8.47-h2 to us-west-011. This was the recovery for the 05:47-06:28Z noisetable.com outage (see gotcha). (5) STAGING inner door redeployed with the key: run from ~/ss/noisetable, `/Users/leif/ss/yah/target/opt-in/bin/yah cloud mirror up noisetable-marketing --env staging --door-only`. The new pid has the key in environ, staging.noisetable.com = 200, and w011 shows 0 unsigned since 06:37:55Z. (6) DEV SOAK BASELINE at 06:38Z: 0 unsigned and 0 bad-credential on 013/014/111/112/113/002/003, and on 011 after 06:37:55Z. The soak clock started 06:37:55Z.")
//! @yah:handoff("Tree anchor at handoff: 8a4eabc6787221f5e16ffa55f88bcf8e491bd01c — the shared tree as I left it. Diff against it (`git diff 8a4eabc6787221f5e16ffa55f88bcf8e491bd01c..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("A) PROD INNER DOORS, still UNSIGNED: ~810 unsigned /service-records per minute per prod node, which is the only remaining prod source. `--door-only --env prod` was REFUSED with 409, because prod yubaba 0.8.44 predates R966 `replace`; nothing was torn down. @Ashguard:eclipse's release run 6f575ea9 (yah-release-wizard 0.8.46, sovereign=prod) will roll tree yubaba to prod after release-check. Once that roll finishes on w001/e001/s001, run from ~/ss/noisetable: `/Users/leif/ss/yah/target/opt-in/bin/yah cloud mirror up noisetable-marketing --env prod --door-only --replace`, then check apex per origin with /tmp/t18b-tools/apex.sh. Rebuild the opt-in CLI first if the tree moved (`cargo xtask install`).")
//! @yah:next("B) DEV FLIP once the soak reaches >=30 min of zero (i.e. after ~07:08Z). Re-census each dev node (journalctl -u yubaba --since -30min: 0 'unauthenticated request served'), then add drop-in YUBABA_AUTH_MODE=require and restart, in this order: us-west-002 (standalone; it runs yubaba 0.8.40, which CANNOT sign, but it has no peers, so require is fine as long as only signed callers reach it), us-west-111/112/113 learners, followers 013 and 014, then leader 011. After each flip check quorum (signed /raft/status), 0 'credential required' in the journal, and staging.noisetable.com 200. Check what drop-in/env name the deployed yubaba reads for auth mode before writing it (`--auth-mode` / env in its --help).")
//! @yah:next("C) PROD FLIP after A plus a 30-min zero soak: us-west-003 (standalone), then followers w001 and e001, leader s001 last. Apex per origin after each (east 51.81.85.145, south 45.32.194.254, west 15.204.89.240). Also restart passway-mesh deliberately sometime: 0.8.47-h1 bytes are STAGED on prod; the running mesh doors are the 10-08 binary, which already signs.")
//! @yah:next("D) CODE after every node is on require: delete AuthMode::Warn + --auth-mode, make HttpAuthPolicy::new require a trust root, delete decide's anonymous branch; decide the pond trust root (see the earlier next). us-west-002 needs a signing yubaba before that release lands.")
//! @yah:gotcha("LAPTOP SCRIPTS NEED A MINTER NOW. With ~/.yah/operator.key present, scripts/lib/yubaba-auth.sh hard-fails ('no minter (yubaba) on PATH') instead of falling back to unsigned, and scripts/hotship.sh then reports 'REFUSED: raft is not healthy' — that refusal is wrong, the minter is the cause. Workaround: `YUBABA_BIN=/Users/leif/ss/yah/oss/yubaba/target/debug/yubaba scripts/hotship.sh ...`. Permanent fix (operator): put a yubaba on PATH. The Rust CLI signs in-process and is unaffected.")
//! @yah:gotcha("GRACEFUL DOOR RELOAD LEAVES THE OLD PROCESS POLLING FOR ~5 MIN. After `systemctl reload passway-*`, the old pid stays alive in pingora's grace period and keeps polling yubaba UNSIGNED until 'All runtimes exited'. So measure the unsigned count >5 min after a reload, never immediately.")
//! @yah:gotcha("Backups left on the prod door nodes: /etc/passway-*.env.pre-r876t18 (w001/e001/s001). Delete them once the flip has soaked.")

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use pasetors::keys::{AsymmetricPublicKey, SymmetricKey};
use pasetors::token::{Local, Public, UntrustedToken};
use pasetors::version4::{LocalToken, PublicToken, V4};

use crate::ServerState;

// R876-T18: the token FORMAT — audience, scopes, TTLs, claims, key hex — lives
// in `yubaba-auth-token`, shared with every out-of-process caller that mints.
// This module owns verification and the route policy only.
use yubaba_auth_token::{
    cluster_key_from_hex, now_unix, operator_public_from_hex, validate_claims, PeerSigner,
    OPERATOR_SCOPE, PEER_SCOPE,
};

/// Which credential a route demands.
///
/// Carried as middleware state rather than looked up by path: see the
/// module header on why the classification is structural.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthClass {
    /// No credential. Reachable by anything that can open a socket, so this
    /// is reserved for liveness probes whose *purpose* is to answer before
    /// the node is configured — and which disclose nothing a port scan
    /// does not already.
    Public,
    /// A peer-tier **or** operator-tier token.
    Peer,
    /// An operator-tier token only.
    Operator,
}

/// Whether a missing credential is refused or merely logged.
///
/// See the module header — this is a roll sequencer with a removal ticket
/// (R876-T18), not a permanent knob.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthMode {
    /// Anonymous requests are served and logged at WARN. An *invalid*
    /// credential is still refused.
    #[default]
    Warn,
    /// Anonymous requests are refused with 401.
    Require,
}

impl AuthMode {
    /// Parse the `YUBABA_AUTH_MODE` / `--auth-mode` spelling.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "warn" => Ok(Self::Warn),
            "require" => Ok(Self::Require),
            other => Err(format!(
                "unknown auth mode {other:?} (expected \"warn\" or \"require\")"
            )),
        }
    }
}

/// Which trust root verified a credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// v4.local under the cluster key.
    Peer,
    /// v4.public under a configured operator key.
    Operator,
}

impl Tier {
    fn satisfies(self, class: AuthClass) -> bool {
        match class {
            AuthClass::Public => true,
            AuthClass::Peer => true,
            AuthClass::Operator => self == Tier::Operator,
        }
    }

    fn required_scope(self) -> &'static str {
        match self {
            Tier::Peer => PEER_SCOPE,
            Tier::Operator => OPERATOR_SCOPE,
        }
    }
}

/// The verified caller, stashed in the request extensions for handlers that
/// want to attribute an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// The token's `sub`.
    pub subject: String,
    /// Which trust root vouched for it.
    pub tier: Tier,
}

/// What [`authenticate`] found on the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// No `Authorization` header at all.
    Anonymous,
    /// A credential that verified.
    Allowed(Principal),
    /// A credential was presented and is not acceptable. The string is safe
    /// to log; it is deliberately *not* returned to the caller beyond a
    /// coarse reason, so the route is not an oracle for which key is
    /// configured.
    Invalid(String),
}

/// The node's configured trust roots plus the enforcement mode.
#[derive(Default)]
pub struct HttpAuthPolicy {
    mode: AuthMode,
    operator_keys: Vec<AsymmetricPublicKey<V4>>,
    cluster_key: Option<SymmetricKey<V4>>,
}

impl std::fmt::Debug for HttpAuthPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAuthPolicy")
            .field("mode", &self.mode)
            .field("operator_keys", &self.operator_keys.len())
            .field("cluster_key", &self.cluster_key.is_some())
            .finish()
    }
}

impl HttpAuthPolicy {
    /// Build a policy from raw config values.
    ///
    /// `operator_keys` are 64-char hex ed25519 *public* keys — the same
    /// spelling `--control-plane-allow` already uses for `NodeId`s, so an
    /// operator has one hex convention to learn rather than two.
    /// `cluster_key` is a 64-char hex 32-byte symmetric key.
    pub fn new(
        mode: AuthMode,
        operator_keys: &[String],
        cluster_key: Option<&str>,
    ) -> Result<Self, String> {
        let mut parsed_operator = Vec::with_capacity(operator_keys.len());
        for raw in operator_keys {
            parsed_operator.push(
                operator_public_from_hex(raw).map_err(|e| format!("operator key {raw:?}: {e}"))?,
            );
        }
        let parsed_cluster = match cluster_key {
            Some(raw) => {
                Some(cluster_key_from_hex(raw).map_err(|e| format!("cluster key: {e}"))?)
            }
            None => None,
        };

        // A node that enforces with no trust root at all refuses every
        // authenticated route forever, which looks exactly like a network
        // partition and is far harder to diagnose than a refused boot.
        if mode == AuthMode::Require && parsed_operator.is_empty() && parsed_cluster.is_none() {
            return Err(
                "--auth-mode require with no trust root: pass at least one --operator-key \
                 or --cluster-key-file, or every authenticated route will 401"
                    .to_string(),
            );
        }

        Ok(Self {
            mode,
            operator_keys: parsed_operator,
            cluster_key: parsed_cluster,
        })
    }

    /// Read the policy off the environment.
    ///
    /// - `YUBABA_AUTH_MODE` — `warn` (default) or `require`.
    /// - `YUBABA_OPERATOR_KEYS` — comma-separated hex public keys.
    /// - `YUBABA_CLUSTER_KEY_FILE` — path to a file holding the hex cluster
    ///   key. A *file*, not an env var: the cluster key is a bearer secret,
    ///   and an env var is readable from `/proc/<pid>/environ`, inherited by
    ///   every child yubaba spawns, and printed by half the diagnostics in
    ///   this repo.
    pub fn from_env() -> Result<Self, String> {
        let mode = match std::env::var("YUBABA_AUTH_MODE") {
            Ok(raw) if !raw.trim().is_empty() => AuthMode::parse(&raw)?,
            _ => AuthMode::default(),
        };
        let operator_keys: Vec<String> = std::env::var("YUBABA_OPERATOR_KEYS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let cluster_key = match std::env::var(yubaba_auth_token::CLUSTER_KEY_FILE_ENV) {
            Ok(path) if !path.trim().is_empty() => Some(
                std::fs::read_to_string(path.trim())
                    .map_err(|e| format!("reading YUBABA_CLUSTER_KEY_FILE {path:?}: {e}"))?
                    .trim()
                    .to_string(),
            ),
            _ => None,
        };
        Self::new(mode, &operator_keys, cluster_key.as_deref())
    }

    /// Is a missing credential refused?
    pub fn is_enforcing(&self) -> bool {
        self.mode == AuthMode::Require
    }

    /// Does this node hold any trust root at all?
    pub fn has_trust_root(&self) -> bool {
        !self.operator_keys.is_empty() || self.cluster_key.is_some()
    }

    /// The signer this node's own peer-dialing callers attach (R876-T18) —
    /// raft RPC, forward-to-leader, lease renewal, floater replication.
    ///
    /// The cluster key that verifies inbound peer tokens is the same key that
    /// mints outbound ones, so a node needs no second piece of config to start
    /// signing. Unkeyed, the signer attaches nothing, which is exactly what
    /// these callers sent before. Each token is minted per request with
    /// [`yubaba_auth_token::DEFAULT_TOKEN_TTL_SECS`]: see
    /// [`yubaba_auth_token::MAX_TOKEN_TTL_SECS`] for why a token
    /// minted once at boot would stop working a day later.
    pub fn peer_signer(&self, subject: String) -> PeerSigner {
        match self.cluster_key.clone() {
            Some(key) => PeerSigner::for_cluster_key(key, subject),
            None => PeerSigner::unsigned(),
        }
    }
}

/// Verify the `Authorization` header against the policy. Pure — `now` is
/// passed in so expiry is testable without a clock.
pub fn authenticate(policy: &HttpAuthPolicy, header: Option<&str>, now: i64) -> AuthOutcome {
    let Some(raw) = header else {
        return AuthOutcome::Anonymous;
    };
    let Some(token) = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
    else {
        return AuthOutcome::Invalid("Authorization header is not a Bearer credential".into());
    };
    let token = token.trim();
    if token.is_empty() {
        return AuthOutcome::Anonymous;
    }

    let (tier, payload) = if token.starts_with(PublicToken::HEADER) {
        match verify_operator(policy, token) {
            Ok(p) => (Tier::Operator, p),
            Err(e) => return AuthOutcome::Invalid(e),
        }
    } else if token.starts_with(LocalToken::HEADER) {
        match verify_peer(policy, token) {
            Ok(p) => (Tier::Peer, p),
            Err(e) => return AuthOutcome::Invalid(e),
        }
    } else {
        return AuthOutcome::Invalid("token is neither v4.public nor v4.local".into());
    };

    match validate_claims(&payload, tier.required_scope(), now) {
        Ok(subject) => AuthOutcome::Allowed(Principal { subject, tier }),
        Err(e) => AuthOutcome::Invalid(e),
    }
}

fn verify_operator(policy: &HttpAuthPolicy, token: &str) -> Result<String, String> {
    if policy.operator_keys.is_empty() {
        return Err("operator token presented but this node has no operator key".into());
    }
    let untrusted = UntrustedToken::<Public, V4>::try_from(token)
        .map_err(|_| "malformed v4.public token".to_string())?;
    for key in &policy.operator_keys {
        if let Ok(trusted) = PublicToken::verify(key, &untrusted, None, None) {
            return Ok(trusted.payload().to_string());
        }
    }
    Err("v4.public token matched no configured operator key".into())
}

fn verify_peer(policy: &HttpAuthPolicy, token: &str) -> Result<String, String> {
    let Some(key) = policy.cluster_key.as_ref() else {
        return Err("peer token presented but this node has no cluster key".into());
    };
    let untrusted = UntrustedToken::<Local, V4>::try_from(token)
        .map_err(|_| "malformed v4.local token".to_string())?;
    let trusted = LocalToken::decrypt(key, &untrusted, None, None)
        .map_err(|_| "v4.local token did not decrypt under the cluster key".to_string())?;
    Ok(trusted.payload().to_string())
}

/// The verdict the middleware acts on. `Ok` carries the principal (`None`
/// for a tolerated anonymous request); `Err` is the refusal to send.
pub fn decide(
    policy: &HttpAuthPolicy,
    class: AuthClass,
    outcome: AuthOutcome,
) -> Result<Option<Principal>, (StatusCode, &'static str)> {
    if class == AuthClass::Public {
        return Ok(None);
    }
    match outcome {
        // An invalid credential is refused in BOTH modes — see the module
        // header on why `Warn` is not "auth off".
        AuthOutcome::Invalid(_) => Err((StatusCode::UNAUTHORIZED, "invalid credential")),
        AuthOutcome::Anonymous => {
            if policy.is_enforcing() {
                Err((StatusCode::UNAUTHORIZED, "credential required"))
            } else {
                Ok(None)
            }
        }
        AuthOutcome::Allowed(p) => {
            if p.tier.satisfies(class) {
                Ok(Some(p))
            } else {
                // Valid credential, insufficient tier — refused in both
                // modes, because this is a caller bug rather than a
                // not-yet-upgraded caller.
                Err((StatusCode::FORBIDDEN, "credential tier insufficient"))
            }
        }
    }
}

/// The axum middleware. Layered per sub-router by [`crate::build_router`],
/// with the class baked into the state so there is no path matching here.
pub async fn auth_layer(
    State((state, class)): State<(Arc<ServerState>, AuthClass)>,
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let outcome = authenticate(&state.http_auth, header.as_deref(), now_unix());

    if let AuthOutcome::Invalid(ref why) = outcome {
        tracing::warn!(reason = %why, uri = %req.uri(), "rejecting request with a bad credential");
    }

    match decide(&state.http_auth, class, outcome) {
        Ok(principal) => {
            if principal.is_none() && class != AuthClass::Public {
                tracing::warn!(
                    uri = %req.uri(),
                    class = ?class,
                    "unauthenticated request served (auth mode is warn — R876-T18 flips this to \
                     require; wire this caller to send a token before then)"
                );
            }
            if let Some(p) = principal {
                req.extensions_mut().insert(p);
            }
            next.run(req).await
        }
        Err((status, reason)) => {
            (status, axum::Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasetors::keys::AsymmetricSecretKey;
    use yubaba_auth_token::{
        encode_hex, mint_operator_token, mint_peer_token, AUDIENCE, MAX_TOKEN_TTL_SECS,
    };
    use pasetors::keys::{AsymmetricKeyPair, Generate};

    /// A policy holding one operator key and one cluster key, plus the
    /// secret halves a caller would mint with.
    fn fixture(
        mode: AuthMode,
    ) -> (
        HttpAuthPolicy,
        AsymmetricSecretKey<V4>,
        SymmetricKey<V4>,
        String,
    ) {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let pub_hex = encode_hex(kp.public.as_bytes());
        let sym = SymmetricKey::<V4>::generate().unwrap();
        let sym_hex = encode_hex(sym.as_bytes());
        let policy = HttpAuthPolicy::new(mode, &[pub_hex.clone()], Some(&sym_hex)).unwrap();
        (policy, kp.secret, sym, pub_hex)
    }

    #[test]
    fn an_operator_token_verifies_and_carries_the_operator_tier() {
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let tok = mint_operator_token(&secret, "user:leif", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert_eq!(
            out,
            AuthOutcome::Allowed(Principal {
                subject: "user:leif".into(),
                tier: Tier::Operator
            })
        );
    }

    #[test]
    fn a_peer_token_verifies_and_carries_the_peer_tier() {
        let (policy, _secret, sym, _) = fixture(AuthMode::Require);
        let tok = mint_peer_token(&sym, "node:abc", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert_eq!(
            out,
            AuthOutcome::Allowed(Principal {
                subject: "node:abc".into(),
                tier: Tier::Peer
            })
        );
    }

    #[test]
    fn a_peer_token_never_satisfies_the_operator_class() {
        let (policy, _secret, sym, _) = fixture(AuthMode::Require);
        let tok = mint_peer_token(&sym, "node:abc", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Allowed(_)), "precondition");
        let verdict = decide(&policy, AuthClass::Operator, out);
        assert_eq!(verdict.unwrap_err().0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn an_operator_token_also_satisfies_the_peer_class() {
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let tok = mint_operator_token(&secret, "user:leif", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(decide(&policy, AuthClass::Peer, out).unwrap().is_some());
    }

    #[test]
    fn a_token_from_an_untrusted_operator_key_is_refused() {
        let (policy, _secret, _sym, _) = fixture(AuthMode::Require);
        let stranger = AsymmetricKeyPair::<V4>::generate().unwrap();
        let tok = mint_operator_token(&stranger.secret, "user:mallory", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Invalid(_)), "got {out:?}");
    }

    #[test]
    fn a_peer_token_under_a_foreign_cluster_key_is_refused() {
        let (policy, _secret, _sym, _) = fixture(AuthMode::Require);
        let foreign = SymmetricKey::<V4>::generate().unwrap();
        let tok = mint_peer_token(&foreign, "node:mallory", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Invalid(_)), "got {out:?}");
    }

    #[test]
    fn an_expired_token_is_refused() {
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let tok = mint_operator_token(&secret, "user:leif", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_301);
        assert!(matches!(out, AuthOutcome::Invalid(ref e) if e.contains("expired")), "got {out:?}");
    }

    #[test]
    fn a_token_with_an_absurd_exp_is_refused_even_though_it_signs() {
        // Mint by hand — `mint_operator_token` refuses the TTL itself, so a
        // hostile minter is the only way to produce this shape.
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let payload = serde_json::json!({
            "aud": AUDIENCE, "sub": "user:leif", "iat": 1_000,
            "exp": 1_000 + MAX_TOKEN_TTL_SECS * 365,
            "scope": [OPERATOR_SCOPE],
        })
        .to_string();
        let tok = PublicToken::sign(&secret, payload.as_bytes(), None, None).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Invalid(ref e) if e.contains("ceiling")), "got {out:?}");
    }

    #[test]
    fn a_cheers_audience_token_signed_by_a_trusted_key_is_still_refused_here() {
        // The replay this audience check exists to stop: yubaba mints
        // cheers-audience tokens with an Ed25519 service-principal key. If
        // that key were ever also in the operator trust set, the token must
        // still not open this surface.
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let payload = serde_json::json!({
            "aud": "https://cheers.yah.dev", "sub": "svc:yubaba", "iat": 1_000, "exp": 1_300,
            "scope": ["ownership:write", OPERATOR_SCOPE],
        })
        .to_string();
        let tok = PublicToken::sign(&secret, payload.as_bytes(), None, None).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Invalid(ref e) if e.contains("audience")), "got {out:?}");
    }

    #[test]
    fn a_token_missing_the_tier_scope_is_refused() {
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let payload = serde_json::json!({
            "aud": AUDIENCE, "sub": "user:leif", "iat": 1_000, "exp": 1_300,
            "scope": [PEER_SCOPE],
        })
        .to_string();
        let tok = PublicToken::sign(&secret, payload.as_bytes(), None, None).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Invalid(ref e) if e.contains("scope")), "got {out:?}");
    }

    #[test]
    fn warn_mode_serves_anonymous_but_still_refuses_a_bad_credential() {
        let (policy, _secret, _sym, _) = fixture(AuthMode::Warn);
        assert!(
            decide(&policy, AuthClass::Operator, AuthOutcome::Anonymous)
                .unwrap()
                .is_none(),
            "warn mode must serve an anonymous caller"
        );
        let stranger = AsymmetricKeyPair::<V4>::generate().unwrap();
        let tok = mint_operator_token(&stranger.secret, "user:mallory", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert_eq!(
            decide(&policy, AuthClass::Operator, out).unwrap_err().0,
            StatusCode::UNAUTHORIZED,
            "warn mode is not auth-off: a presented-and-bad credential is refused"
        );
    }

    #[test]
    fn require_mode_refuses_anonymous_on_peer_and_operator_but_not_public() {
        let (policy, _secret, _sym, _) = fixture(AuthMode::Require);
        for class in [AuthClass::Peer, AuthClass::Operator] {
            assert_eq!(
                decide(&policy, class, AuthOutcome::Anonymous).unwrap_err().0,
                StatusCode::UNAUTHORIZED,
                "{class:?} must refuse anonymous under require"
            );
        }
        assert!(decide(&policy, AuthClass::Public, AuthOutcome::Anonymous)
            .unwrap()
            .is_none());
    }

    #[test]
    fn require_with_no_trust_root_refuses_to_build() {
        let err = HttpAuthPolicy::new(AuthMode::Require, &[], None).unwrap_err();
        assert!(err.contains("no trust root"), "got {err}");
    }

    #[test]
    fn the_default_policy_is_warn_with_no_keys() {
        let policy = HttpAuthPolicy::default();
        assert!(!policy.is_enforcing());
        assert!(!policy.has_trust_root());
        assert_eq!(
            authenticate(&policy, None, 1_000),
            AuthOutcome::Anonymous,
            "no header is anonymous, not invalid"
        );
    }

    #[test]
    fn a_non_bearer_authorization_header_is_invalid_not_anonymous() {
        let (policy, _secret, _sym, _) = fixture(AuthMode::Warn);
        let out = authenticate(&policy, Some("Basic aGk6dGhlcmU="), 1_000);
        assert!(matches!(out, AuthOutcome::Invalid(_)), "got {out:?}");
    }

    #[test]
    fn auth_mode_parses_both_spellings_and_rejects_the_rest() {
        assert_eq!(AuthMode::parse("warn").unwrap(), AuthMode::Warn);
        assert_eq!(AuthMode::parse(" REQUIRE ").unwrap(), AuthMode::Require);
        assert!(AuthMode::parse("off").is_err());
    }

    #[test]
    fn a_hand_built_state_defaults_to_the_permissive_policy() {
        // Pins the invariant the ~900 credential-free router tests in this
        // crate depend on: a `ServerState` nobody configured serves them.
        let tmp = tempfile::TempDir::new().unwrap();
        let state = crate::ServerState::load(tmp.path().join("identity.json")).unwrap();
        assert!(!state.http_auth.is_enforcing());
        assert!(!state.http_auth.has_trust_root());
    }

}

/// R876-B15's verify bar: the refusal asserted through the **real**
/// [`crate::build_router`], the way R876-B13's regression test drives the
/// real router rather than a hand-built one. A policy that only works in
/// [`authenticate`] is a policy that is not wired.
#[cfg(test)]
mod router_tests {
    use super::*;
    use pasetors::keys::AsymmetricSecretKey;
    use yubaba_auth_token::{encode_hex, mint_operator_token, mint_peer_token};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use std::sync::Arc;
    use tower::ServiceExt;

    /// An enforcing node plus the two secret halves its callers mint with.
    fn enforcing_node() -> (
        tempfile::TempDir,
        Arc<crate::ServerState>,
        AsymmetricSecretKey<V4>,
        SymmetricKey<V4>,
    ) {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let sym = SymmetricKey::<V4>::generate().unwrap();
        let policy = HttpAuthPolicy::new(
            AuthMode::Require,
            &[encode_hex(kp.public.as_bytes())],
            Some(&encode_hex(sym.as_bytes())),
        )
        .unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let state = crate::ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_http_auth(policy);
        (tmp, Arc::new(state), kp.secret, sym)
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    /// The three routes the ticket names by hand: reads a spec, deploys a
    /// workload, self-updates the binary. Plus `/secrets`, which is the one
    /// with a clean 200 to prove non-vacuity against.
    fn operator_probes() -> Vec<Request<Body>> {
        vec![
            Request::get("/workloads/yah-marketing/spec")
                .body(Body::empty())
                .unwrap(),
            Request::post("/workloads/deploy")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"spec":{}}"#))
                .unwrap(),
            // R892-B1. Same class as /workloads/deploy: it judges a deploy
            // body, and its answer states this node's admission policy.
            Request::post("/workloads/validate")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"spec":{}}"#))
                .unwrap(),
            Request::post("/self-update")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"version":"0.0.0","url":"http://x/y","sha256":"00"}"#,
                ))
                .unwrap(),
            Request::get("/secrets").body(Body::empty()).unwrap(),
        ]
    }

    #[tokio::test]
    async fn an_unauthenticated_request_is_refused_on_every_operator_route() {
        let (_tmp, state, _sk, _sym) = enforcing_node();
        for req in operator_probes() {
            let uri = req.uri().clone();
            let resp = crate::build_router(Arc::clone(&state))
                .oneshot(req)
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{uri} served an unauthenticated caller"
            );
        }
    }

    /// Non-vacuity. Without this, breaking the surface outright would pass
    /// the test above.
    #[tokio::test]
    async fn an_operator_token_still_gets_through_to_the_handler() {
        let (_tmp, state, sk, _sym) = enforcing_node();
        let token = mint_operator_token(&sk, "user:leif", 300, now_unix()).unwrap();
        for mut req in operator_probes() {
            req.headers_mut().insert(
                axum::http::header::AUTHORIZATION,
                bearer(&token).parse().unwrap(),
            );
            let uri = req.uri().clone();
            let resp = crate::build_router(Arc::clone(&state))
                .oneshot(req)
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{uri} refused a valid operator token"
            );
            assert_ne!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{uri} refused a valid operator token"
            );
        }
        // `POST /workloads/drain` is the one operator route that reaches a
        // clean 200 on a state with no runtime wired (see
        // `drain_workloads_returns_empty_until_runtime`), so this pins "the
        // handler RAN" rather than merely "the handler changed which error
        // it returns".
        let resp = crate::build_router(Arc::clone(&state))
            .oneshot(
                Request::post("/workloads/drain")
                    .header(axum::http::header::AUTHORIZATION, bearer(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Holding the cluster key makes you a member, not an administrator.
    #[tokio::test]
    async fn a_peer_token_cannot_deploy_or_self_update() {
        let (_tmp, state, _sk, sym) = enforcing_node();
        let token = mint_peer_token(&sym, "node:us-east-001", 300, now_unix()).unwrap();
        for mut req in operator_probes() {
            req.headers_mut().insert(
                axum::http::header::AUTHORIZATION,
                bearer(&token).parse().unwrap(),
            );
            let uri = req.uri().clone();
            let resp = crate::build_router(Arc::clone(&state))
                .oneshot(req)
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{uri} accepted a peer token"
            );
        }
    }

    /// The rolling-fleet half of the bar: node-to-node traffic keeps working
    /// with the cluster key alone, so a partially-upgraded fleet still holds
    /// elections and forwards writes.
    #[tokio::test]
    async fn a_peer_token_opens_the_node_to_node_routes() {
        let (_tmp, state, _sk, sym) = enforcing_node();
        let token = mint_peer_token(&sym, "node:us-east-001", 300, now_unix()).unwrap();
        for path in ["/capabilities", "/workloads", "/raft/status"] {
            let anon = crate::build_router(Arc::clone(&state))
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                anon.status(),
                StatusCode::UNAUTHORIZED,
                "{path} served an unauthenticated caller"
            );

            let authed = crate::build_router(Arc::clone(&state))
                .oneshot(
                    Request::get(path)
                        .header(axum::http::header::AUTHORIZATION, bearer(&token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                authed.status(),
                StatusCode::UNAUTHORIZED,
                "{path} refused a valid peer token"
            );
            assert_ne!(
                authed.status(),
                StatusCode::FORBIDDEN,
                "{path} refused a valid peer token"
            );
        }
    }

    /// `/health` has to answer before a node is configured — that is what it
    /// is for, and hotship polls it to decide whether a restart landed.
    #[tokio::test]
    async fn the_public_probes_stay_open_under_require() {
        let (_tmp, state, _sk, _sym) = enforcing_node();
        for path in ["/health", "/mesh/leader-health"] {
            let resp = crate::build_router(Arc::clone(&state))
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
    }

    /// `route_layer`, not `layer`: an unknown path must still 404. Otherwise
    /// the surface answers "401" for routes that exist and "401" for routes
    /// that do not, which is a probe oracle wearing a security control's hat.
    #[tokio::test]
    async fn an_unknown_path_is_a_404_not_a_401() {
        let (_tmp, state, _sk, _sym) = enforcing_node();
        let resp = crate::build_router(state)
            .oneshot(
                Request::get("/no/such/route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// The default (and therefore the fleet's behaviour the moment this
    /// ships) serves an unauthenticated deploy and logs it — and still
    /// refuses a credential that is present and bad.
    #[tokio::test]
    async fn warn_mode_serves_the_fleet_but_not_a_forged_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        let stranger = AsymmetricKeyPair::<V4>::generate().unwrap();
        let trusted = AsymmetricKeyPair::<V4>::generate().unwrap();
        let policy = HttpAuthPolicy::new(
            AuthMode::Warn,
            &[encode_hex(trusted.public.as_bytes())],
            None,
        )
        .unwrap();
        let state = Arc::new(
            crate::ServerState::load(tmp.path().join("identity.json"))
                .unwrap()
                .with_http_auth(policy),
        );

        let anon = crate::build_router(Arc::clone(&state))
            .oneshot(
                Request::post("/workloads/drain")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            anon.status(),
            StatusCode::OK,
            "warn mode must not break a caller that sends nothing"
        );

        let forged = mint_operator_token(&stranger.secret, "user:mallory", 300, now_unix()).unwrap();
        let resp = crate::build_router(state)
            .oneshot(
                Request::post("/workloads/drain")
                    .header(axum::http::header::AUTHORIZATION, bearer(&forged))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "warn mode is a roll sequencer, not auth-off"
        );
    }
}
