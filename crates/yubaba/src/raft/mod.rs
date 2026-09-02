//! Yubaba openraft coordination layer — Phase 2 (R040-F20).
//!
//! Builds on top of [`openraft`] to give the yubaba cluster consensus
//! on:
//! - Cluster membership (who is a yubaba peer, current leader)
//! - Service placement (which machine runs Headscale/Postgres/…)
//! - Distributed locks (in-progress provisions, mesh migrations)
//! - Floating ingress ownership (who currently runs the Headscale tunnel)
//!
//! Transport runs peer-to-peer over Tailscale mesh IPs.  The mesh must
//! already be up (Phase 1a/1b) before raft can form quorum.
//!
//! @yah:relay(R277, "Tier 4 — cluster-mesh-1: single-node raft + WireGuard plane")
//! @yah:at(2026-05-27T02:22:55Z)
//! @yah:status(backlog)
//! @yah:parent(Q273)
//! @yah:next("F1: bring up yubaba raft on a single node (openraft, on-disk storage); storage backend choice (sled vs sqlite) resolved as F1 sub-spike")
//! @yah:next("F2: wireguard0 brought up + a single-node 'mesh' (one node, but the bus is live)")
//! @yah:next("F3: consume mshr::Endpoint as yubaba control-plane transport (Open Q2 from the A026 doc finally gets a consumer). RENAMED 2026-07-22 under R593-T7: the crate this bullet used to call `xlb-net::Endpoint` was promoted to the standalone `mshr` workspace in W268 wave 2 — it now lives at oss/mshr/crates/mshr (`pub use endpoint::Endpoint`), NOT oss/xlb/crates/xlb-net. A026-xlb-net.md still carries the pre-promotion name and describes xlb-net 0.1; renaming/rewriting that doc is separate work, so read it as the mshr design doc.")
//! @yah:next("F4: smoke fixture extending R091-F6 multi-node openraft harness so cluster-mesh-2/3 are file-able as follow-on relays without redesign")
//! @yah:gotcha("Depends on Tier-3 relay landing first (real workload runtime needed to host raft as a workload, or co-located)")
//! @yah:gotcha("R271 'Orbit architecture review for yubaba design' should resolve before F1 so its findings shape the storage-backend pick")
//! @arch:see(.yah/docs/architecture/A032-yah-cluster-mesh.md)
//! @arch:see(.yah/docs/architecture/A026-xlb-net.md)
//! @arch:see(.yah/docs/architecture/A041-yah-mesh-bootstrap.md)
//!
//! @yah:ticket(R278-F3, "Raft mirror metadata for rollout state (degenerate-raft v1)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T02:31:24Z)
//! @yah:status(review)
//! @yah:parent(R278)
//! @yah:next("Add rollout fields to YubabaState: rollouts: BTreeMap<String, RolloutRaftRecord>")
//! @yah:next("Add YubabaRequest variants: SetRolloutState, ClearRolloutState")
//! @yah:next("In-memory store on ServerState for v1; raft variants defined for forward-compat")
//! @arch:see(.yah/docs/architecture/A032-yah-cluster-mesh.md)
//! @yah:handoff("YubabaState.rollouts: BTreeMap<String, RolloutRaftRecord> added. YubabaRequest::SetRolloutState + ClearRolloutState variants defined and apply() arms wired. YubabaState serialises with #[serde(default)] so old snapshots load cleanly. In-memory RolloutStore on ServerState is the v1 authoritative path; raft variants are forward-compat for when R277 lands.")
//!
//! @yah:ticket(R597-T2, "Rename yubaba-internal raft symbols YubabaState/YubabaRequest/YubabaNodeId/YubabaRaft -> Yubaba*")
//! @yah:status(review)
//! @yah:at(2026-07-20T03:59:44Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R597)
//! @yah:next("DONE (R597-T2): renamed Warden* raft symbols to Yubaba* across oss/yubaba (YubabaState, YubabaRequest, YubabaNodeId, YubabaRaft, YubabaRaftConfig, YubabaStateMachine, YubabaLogStore, YubabaNetwork, YubabaNetworkFactory, YubabaResponse). No wire change; openraft type params only.")
//! @yah:verify("cd oss/yubaba && cargo check -p yubaba --all-features")
//! @yah:gotcha("Tier: Thief -- single-workspace rote symbol rename, no behavior change, no wire surface.")
//!
//! @yah:ticket(R625-B6, "cluster_protocol drift gate is red — raft wire surface moved, epoch not bumped, needs a breaking/non-breaking call")
//! @yah:status(review)
//! @yah:at(2026-08-12T21:44:23Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R625)
//! @yah:severity(medium)
//! @yah:handoff("VERDICT: NOT BREAKING on both axes. The moving surface was R720-F1's digest: Option<Vec<u8>> on SecretRecord (raft/mod.rs) and on YubabaRequest::PutSecret, both #[serde(default)], plus a fourth hex-encoded column in raft/store.rs cluster_secret_index(). cluster_protocol left at 3 and state_epoch left at 2; both surface hashes re-recorded with `cargo run -p xtask -- cluster-epochs --write`. The full reasoning is durable in oss/yubaba/crates/yubaba/cluster-epochs.json under surface_rerecords, not only in this annotation.")
//! @yah:handoff("Grounded in the encoding rather than the field shape: raft/network.rs sends every raft RPC as reqwest .json() / axum Json<T>, and raft/store.rs persists raft_log.json and raft_state.json via serde_json::to_string, so wire and disk are the same self-describing JSON. No #[serde(deny_unknown_fields)] anywhere in the SecretRecord/PutSecret/YubabaRequest chain, so old-reads-new silently drops the unknown key and new-reads-old defaults it to None; openraft applies identical log bytes on every node, so there is no state-machine divergence path either.")
//! @yah:handoff("The judgment call was distinguishing this from the R706 `access` precedent, which WAS bumped despite the same file and the same #[serde(default)] Option-field shape. The discriminator is enforcement, not shape: access is a security gate, so an old node dropping the unknown field kept serving the secret under its own absent authorization check, silently defeating the guarantee the field exists to create. digest has no enforcement path anywhere - it is a read-only diagnostic that only feeds `yah cloud secret status` (R720-T2), whose design already renders a missing digest as unknown(pre-digest) rather than a false match.")
//! @yah:handoff("Corroborated since by a later ticket rather than left as a self-assessment: the cluster_protocol history entry \"4\" (R732-F1) cites this call by name - 'R720-F1 was correctly NOT bumped' - and draws the line that makes the three verdicts consistent: added struct FIELDS are tolerated in both directions, added enum VARIANTS on the externally-tagged YubabaRequest are not.")
//! @yah:next("None. Verdict is final, recorded in cluster-epochs.json surface_rerecords, and corroborated by the cluster_protocol history entry 4. R625-B6 was the last open child of R625; F2/F3/F4/F5/S1 are all in review, so the relay is ready for operator sign-off and archive.")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift = 8 passed / 0 failed, up from 7 passed / 1 failed (raft_protocol_surface_matches_the_declared_epochs) when the ticket was filed. JSON validity of cluster-epochs.json checked with python3 json.load before running --write.")
//! @yah:verify("Re-verified at review time on tree cf7a7291bd6c6b29528131c852002fcb6fee0d00: the same suite is still 8 passed / 0 failed, with the declared epochs since advanced to cluster_protocol 4 / state_epoch 3 by R732-F1 and re-recorded ten times by later tickets. The gate this ticket was filed against is green and has stayed green.")
//! @yah:gotcha("This gate is NOT covered by the shared-tree 'just regenerate the derived artifact' rule, and that distinction outlives this ticket. .yah/schema/*.json and the TS bindings are pure functions of the tree, so regenerating them takes no decision from anyone. cluster-epochs.json is different: re-recording the hash asserts a VERDICT - that two builds can still share a raft cluster. Silently re-recording someone else's raft change as non-breaking is how you ship a cluster split, so `cargo run -p xtask -- cluster-epochs --write` must always be preceded by the breaking/non-breaking argument and a surface_rerecords entry carrying it. (The filer's original note here, that --write had deliberately not been run, was correct at filing and is now superseded - see the handoff for the verdict that resolved it.)")
//!
//! @yah:ticket(R732-F1, "TenantOwnership{owner,epoch,lease_expires} in YubabaState + ClaimTenant/TransferTenant requests")
//! @yah:status(review)
//! @yah:at(2026-08-09T23:41:06Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P1)
//! @yah:parent(R732)
//! @yah:next("Tier: Warrior — raft state-machine surface change with CAS/idempotency semantics; the correctness argument is the work, not the LOC.")
//! @yah:next("VERIFIED ABSENT 2026-08-09: YubabaState (raft/mod.rs:220) holds members/service_placement/locks/ingress_owner/rollouts/secrets. No tenant map, no epoch, no ownership record of any kind.")
//! @yah:next("Key the map on the EXISTING workload_spec::TenantId (oss/yah-base/crates/workload-spec) — already used by secrets.rs and service_records.rs. Do not mint a second tenant identifier.")
//! @yah:next("TransferTenant CAS on from_epoch so a log replay after mid-decision leader failover cannot double-advance; ClaimTenant is epoch += 1.")
//! @yah:verify("cargo test -p yubaba --lib raft")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift")
//! @yah:gotcha("Adding a field to YubabaState is a state_epoch surface input for the cluster-epochs drift gate (xtask/src/cluster_epochs.rs; test: cargo test -p xtask --test cluster_epoch_drift). Expect it to go red and make a deliberate breaking / non-breaking call, then `cargo run -p xtask -- cluster-epochs --write` with a history entry. See the R625-B6 precedent block at the top of raft/mod.rs for the reasoning style expected.")
//! @yah:handoff("LANDED: TenantOwnership{owner,epoch,lease_expires} + `tenants: BTreeMap<TenantId, TenantOwnership>` on YubabaState (oss/yubaba/crates/yubaba/src/raft/mod.rs), keyed on the existing workload_spec::TenantId as directed. No second tenant identifier minted.")
//! @yah:verify("cargo test -p yubaba --lib raft = 27 passed / 0 failed (14 new tenant tests + the wire-break test).")
//! @yah:verify("cargo test -p yubaba --lib = 368 passed / 0 failed. cargo test -p yubaba --tests --no-run = all integration bins compile.")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift = 8 passed / 0 failed (was 7/1 red on both axes before the bump + re-record).")
//! @yah:handoff("THREE request variants, not two. ClaimTenant + TransferTenant per the ticket, PLUS RenewTenantLease. Reason: lease_expires is inert without it. Claim always bumps the epoch, so heartbeating via Claim would fence your own streamer on every beat. Renew CAS-es on (owner, epoch), never touches the epoch, and moves the deadline monotonically (max, so a reordered renewal cannot retract a lease a later one extended).")
//! @yah:handoff("Correctness calls to review. (1) Claim ALWAYS advances on grant, including self-reclaim: a restarted owner must outrank its own zombie process. Cost is a burnt epoch number on a lost-response retry, benign since only ordering is load-bearing. (2) TransferTenant CAS on from_epoch plus an already-applied shortcut: when current == (from_epoch+1, to) the retry reports the same Granted and mutates nothing, so a mid-decision-failover replay is a true no-op rather than a second advance. No other request can reach that post-state. (3) Transfer deliberately ignores the outgoing owner live lease: draining a healthy node is ordinary and the epoch is what makes it safe. (4) The record is NEVER deleted: expiry leaves owner+epoch in place so a re-claim resumes from the retained epoch. Dropping it would restart at 1 and let a zombie at epoch 5 outrank a legitimate new owner.")
//! @yah:handoff("Lease-vs-epoch split documented on TenantOwnership: the lease is a liveness hint whose clock skew costs availability only (an early takeover advances the epoch, so skew cannot produce two accepted writers); the epoch is the safety property F2 enforces on the R2 write path. YubabaState::tenant_fencing_token(tenant, node, now) -> Option<u64> is the single owner-AND-lease predicate, added for T4 to call rather than re-deriving it per call site.")
//! @yah:handoff("DRIFT GATE: BREAKING on BOTH axes. cluster_protocol 3->4, state_epoch 2->3, both with history entries in oss/yubaba/crates/yubaba/cluster-epochs.json, then `cargo run -p xtask -- cluster-epochs --write`. The discriminator against the R720-F1 precedent that was correctly NOT bumped: that added a struct FIELD (serde tolerates both directions, no deny_unknown_fields). This adds enum VARIANTS to the replicated command type. YubabaRequest is externally tagged with no #[serde(other)], so an epoch-3 node receiving a replicated ClaimTenant gets a hard `unknown variant` error, cannot apply, cannot advance past that log index. Grounded by a test, not asserted from serde docs: raft::tests::an_unknown_request_variant_fails_to_parse_which_is_why_r732_bumped_both_epochs, which also fires if anyone later adds a catch-all and makes the history entry untrue. state_epoch breaks on ROLLBACK specifically: raft_log.json is serde_json over the same enum and is loaded whole, so one retained un-purged tenant entry makes a downgraded binary fail to start. CLUSTER_PROTOCOL/STATE_EPOCH consts are include_str-parsed from the JSON, so no hand-edit needed.")
//! @yah:next("No ReleaseTenant variant (graceful vacate without a named successor). TransferTenant covers coordinated drain; add Release only if an idle-tenant path needs it, and if so it must clear the lease WITHOUT deleting the record.")
//!
//! @yah:ticket(R732-T4, "Wire the epoch: yubaba hands the owning node its fencing token, the node's streamer config carries it")
//! @yah:status(review)
//! @yah:at(2026-08-10T08:05:55Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P1)
//! @yah:parent(R732)
//! @yah:next("The committed ClaimTenant/TransferTenant epoch (F1) must reach the owning node's StreamConfig (F2). Until R737's placement record exists, a manual/operator path is acceptable — do not block on the scheduler.")
//! @yah:depends_on(R732-F1)
//! @yah:depends_on(R732-F2)
//! @yah:gotcha("PREMISE CORRECTION 2026-08-09 (from the session that landed F1/F2/T3). This ticket says 'plumbing between two seams that F1 and F2 have already shaped; no new design call.' That is wrong: there is no third component holding both seams. VERIFIED ABSENT: nothing outside oss/turso-backup depends on the crate (no Cargo.toml dep anywhere in-tree) and nothing calls tail_frames, restore_latest_stream, or the turso-backup-snapshot binary. yubaba has never run a WAL streamer. So T4 is not wiring an epoch through an existing path -- it is building the tenant WAL streamer integration from zero, and that needs design answers this relay never took: where the streamer runs (yubaba background task vs a workload vs a new crate), how a TenantId maps to a local DB path, how the per-tenant R2 target is configured, and the tail cadence. Re-tier it and get an operator call on the hosting shape before an agent starts editing.")
//! @yah:next("Both halves are ready and waiting. Producer: YubabaState::tenant_fencing_token(&TenantId, YubabaNodeId, now) -> Option<u64> (oss/yubaba/crates/yubaba/src/raft/mod.rs) returns the epoch iff that node is the live owner. Consumer: StreamConfig{epoch, owner} (oss/turso-backup/src/stream.rs). The seam is a single u64; everything unresolved is about WHERE the code that carries it lives.")
//! @yah:next("DESIGN DECIDED 2026-08-10, operator-ratified via ask_user (session griffin). Hosting shape: a NEW PER-NODE DATA-PLANE SERVICE, kamaji-managed (the W264 scryer shape: yubaba locates, kamaji runs), NOT a yubaba background task — W253 tenet 1 (control/data separation) and the litestream precedent (yubaba manages a sidecar, never streams in-process) both cut that way. This binary is the seed of W253 §5/§7's node agent: push-side streamer now; puller fan-in and readiness reporting ('streamer caught up' — what W246/R737 consumes) accrete here later.")
//! @yah:next("Crate home: new crate in the oss/yubaba workspace, consuming turso-backup by PUBLISHED version with a root [patch.crates-io] bridge for atomic in-tree dev — the exact pattern yubaba already uses for kamaji 0.8.22. Structure the tail loop as a LIBRARY with a thin binary wrapper so T5's chaos test can drive the loop in-process through yubaba-test-harness without spawning the service.")
//! @yah:next("Epoch transport is PULL, and freshness deliberately does not matter: add a read endpoint (GET /tenants/{id} -> ownership record incl. epoch, backed by YubabaState::tenant_fencing_token) to yubaba's router, served from the LOCAL state machine. Staleness is safe because enforcement is at the R2 sink — a stale-low token gets StreamOutcome::Fenced, a stale-high token cannot exist (only committed entries reach the state machine). NO new write routes: ClaimTenant/TransferTenant/RenewTenantLease are already reachable via the generic POST /raft/write. The tail loop renews the lease each cycle and stops renewing + drops the tenant on Fenced. The T4-permitted manual path falls out for free: curl the token, start the streamer with an explicit epoch.")
//! @yah:next("Defaults adopted (no further operator call needed): tenant set is operator-provided config until R737's placement record replaces it; TenantId -> local DB path by convention <data_root>/tenants/<id>/db with the id sanitized for path safety (TenantId is a raw pub String); ONE configured R2 bucket with tenants/<id>/ key prefixes, not per-tenant buckets or creds; tail cadence derived from an explicit rpo_target (tail at rpo/2, default rpo 30s), reusing turso-backup's RpoStatus for drift reporting.")
//! @yah:gotcha("Startup must probe the real R2 target with a canary conditional put and REFUSE to run if Precondition support is absent — this closes T3's deployment caveat (a backend silently degraded to unconditional writes reopens the concurrent race while every test stays green). Config-not-code, so the runtime probe is the only guard possible.")
//! @yah:handoff("SUPERSEDES an earlier in-process implementation. A prior session (Ashguard:polaris, session:e95b95da, now ended) landed T4 as a background task inside the yubaba process and moved this ticket to review at 08:05Z; the operator-ratified hosting shape recorded in @yah:next arrived after it had started. Its src/tenant_streamer.rs is deleted and the work is rebuilt to the ratified design. Its handoff/verify entries were CLEARED rather than stacked because they had become false -- they name a deleted file, the superseded hosting shape, and a dependency consequence that no longer applies. The history is preserved in the event shards.")
//! @yah:handoff("LANDED, per the ratified shape. NEW CRATE oss/yubaba/crates/tenant-streamer (yubaba-tenant-streamer), a library plus a thin binary, added to the oss/yubaba workspace. It does NOT depend on the yubaba crate -- that dependency is the control/data coupling W253 tenet 1 forbids -- so it links neither axum nor openraft. config.rs holds the conventions; ownership.rs the pull transport; streamer.rs the tail loop; main.rs loads config, probes, and runs until SIGTERM.")
//! @yah:handoff("THE SEAM IS CLOSED, pull-side. NEW ENDPOINT GET /tenants/{id}?node=N on yubaba's router (lib.rs get_tenant_ownership), served from the LOCAL applied state -- no leader round-trip. fencing_token is computed by YubabaStateMachine::tenant_fencing_token rather than re-derived from the record, so the owner-and-lease predicate stays in exactly one place; the record itself (owner/epoch/lease_expires/live/now/applied_index) rides along for diagnostics and to tell the caller when to renew. NO new write routes: RenewTenantLease goes through the existing generic POST /raft/write. Added YubabaStateMachine::tenant_ownership (raft/store.rs) for the diagnostic half.")
//! @yah:handoff("THE STARTUP PROBE, which closes T3's deployment caveat and was the ticket's second gotcha. NEW in turso-backup: probe_conditional_puts(target) -> PreconditionSupport{Honoured|Degraded{stage}} (oss/turso-backup/src/stream.rs). It writes a uniquely-keyed canary under <prefix>/preflight/, exercises BOTH conditional modes with puts that must be rejected, and deletes it. Naming which mode degraded matters: a store can honour If-None-Match (bootstrap looks healthy) while ignoring If-Match (every steady-state advance is unguarded) -- that half-degraded shape is the one that actually ships, and PreflightStage::Update names it. verify_sink() turns a Degraded verdict into a refusal to start, per tenant prefix, since a bucket policy can differ by prefix. `--check` runs config validation plus the probe and exits, for a deploy pipeline.")
//! @yah:handoff("ONE DELIBERATE DEPARTURE from the ratified text, and it is the judgement call in this ticket. @yah:next says the tail loop renews the lease EACH CYCLE. It does not: it renews once a lease drops below a third of its TTL. Renewing per tick would put a raft write rate proportional to (tenants x tail rate) through a cross-region quorum -- with the adopted defaults, 2 writes/minute/tenant -- and W253 section 4 is explicit that heartbeats must not go through the log and that only state transitions should be committed, not every renewal. Pacing off the lease makes the write rate a function of the lease TTL alone. The safety property is untouched either way: the epoch, not the lease, is what fences a stale writer. The remaining third of the lease is a retry budget (~6 attempts at the defaults), and StreamerConfig::validate REFUSES a config whose budget is under two ticks, so the arithmetic cannot silently produce an outage. Documented at the code site on renew_when_remaining_below().")
//! @yah:handoff("ADOPTED DEFAULTS, all as ratified. Tenant set is operator config until R737. TenantId -> <data_root>/tenants/<id>/db, and TenantId -> tenants/<id>/ key prefix in ONE bucket. Cadence is rpo/2 with rpo defaulting to 30s, and the rpo_target reaches turso-backup so RpoStatus::breached is real rather than decorative. NOTE ON SANITISING: TenantId is a raw pub String and reaches both a filesystem path and an object key, so it is validated to [A-Za-z0-9._-]+ and REJECTED when it fails -- not mangled. Mangling is worse than refusing: two distinct tenants can mangle to the same segment and then share a DB path and an R2 prefix, i.e. a cross-tenant leak produced by the code meant to prevent one.")
//! @yah:handoff("DISCOVERED WORK done in this pass rather than filed. (1) yubaba's runtime dep on turso-backup is REVERTED to a dev-dependency (oss/yubaba/crates/yubaba/Cargo.toml), which retires the unpublishable-mirror-dep release concern the previous session recorded in cluster-epochs.json -- dev-deps are stripped from a published manifest. (2) T5's tests were repointed at the new crate and now cover MORE than before: the_streamer_only_tails_tenants_this_node_owns additionally asserts an unowned tenant writes ZERO objects and that the very next tick streams once raft grants the token. (3) TWO NEW CONTRACT TESTS for the untyped wire between yubaba and the streamer, which had none in either direction -- the streamer hand-builds the renewal body and hand-parses the reply, so renaming a field on YubabaRequest::RenewTenantLease would keep both sides compiling while every node silently lost every tenant one lease-TTL later. (4) yubaba-test-harness gained LocalOwnership, the in-process adapter the ratified design asked for.")
//! @yah:handoff("DRIFT GATE: state_epoch went red again (raft/store.rs is an input), verdict NOT BREAKING -- re-recorded at 3 with a why_not_a_bump entry in cluster-epochs.json surface_rerecords dated 2026-08-10. tenant_ownership() clones an existing field and apply_for_test() is #[cfg(test)]; neither ships a serialisation change, and state_epoch 3 already prices in the tenants map R732-F1 bumped for. cluster_protocol stayed GREEN, predicted before running: this adds GET /tenants/{id} and fn get_tenant_ownership, and that axis's lib.rs slice is only /raft/ route lines and fn raft_* handlers. That is correct rather than lucky -- cluster_protocol governs node-to-node raft RPC compatibility, and this endpoint is a node-local service contract (yubaba to that node's own streamer), a different axis, covered by the two contract tests instead.")
//! @yah:verify("cargo test -p yubaba-tenant-streamer = 20 passed / 0 failed (new crate). cargo clippy -p yubaba-tenant-streamer --all-targets = zero warnings.")
//! @yah:verify("cargo test -p yubaba --lib = 372 passed / 0 failed (368 baseline + 4 new GET /tenants/{id} handler tests: no-cluster 503, unknown-tenant 404, owner-gets-token/non-owner-and-anonymous-get-null, expired-lease-yields-no-token-but-keeps-the-record).")
//! @yah:verify("cargo test -p yubaba --features containerd-integration --test integration_mesh = 7 passed / 0 failed / 1 ignored. Was 5 passed before this pass; the four split_brain tests still pass against the relocated loop, plus the two new wire-contract tests. multi_node_mesh__local still passes.")
//! @yah:verify("cargo test -p turso-backup = 94 + 7 + 4 passed / 0 failed (90 baseline + 4 new preflight-probe tests: honoured-and-leaves-no-trace, catches-an-unconditional-store, names-Update-when-only-If-Match-is-ignored, concurrent-probes-do-not-collide). clippy --all-targets clean.")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift = 8 passed / 0 failed after re-recording. ./scripts/check-workspace-members.sh = all 58 members resolve. cargo check --workspace --all-targets clean in oss/yubaba. cargo check -p cloud-client clean (the root-workspace consumer of yubaba is unbroken). Binary smoked: --help renders and --config /nonexistent --check fails with a clean cause chain.")
//! @yah:next("NOT DONE, stated plainly: there is no kamaji deployment manifest for this service. The ratified shape says kamaji-managed, and the binary is built to be managed (SIGTERM shutdown, --check preflight, config file, no daemonising) -- but kamaji has NO service-manifest file format. W264's `service: scryer` block is illustrative pseudo-config, not a real artifact; kamaji runs WORKLOADS via workload-spec, and scryer's own manifest has not landed either. Deploying this means authoring a WorkloadSpec on the native (non-container) archetype path, which is yah-cloud reconciler territory and separable from wiring the epoch. Shipped instead: tenant-streamer.example.toml, parse-tested by config::tests::the_example_config_parses_and_says_what_it_documents so it cannot rot.")
//! @yah:next("The puller half of W253 section 5 and the readiness reporting of section 7 are the accretion points, and the crate doc names them: one R2 puller per box fanning WAL out to hosted replicas (so R2 ops are O(boxes) not O(replicas)), and a `streamer caught up` readiness signal for W246/R737's placement driver to gate ownership on. Neither is in scope here; both belong in this crate when they land.")
//!
//! @yah:ticket(R732-T5, "The canonical chaos test: partition a tenant master, transfer, heal, assert the old owner is fenced")
//! @yah:status(review)
//! @yah:at(2026-08-10T08:06:45Z)
//! @yah:assignee(agent:claude)
//! @yah:phase(P1)
//! @yah:parent(R732)
//! @yah:next("Tier: Wizard — this test IS the design's proof (W253 section 9: 'if only one experiment ever runs, it is this one'). Getting the oracle right matters more than getting it green.")
//! @yah:next("Partition a tenant master -> yubaba commits TransferTenant (epoch++) -> heal -> assert the old master's tail_frames returns Fenced and writes zero frames.")
//! @yah:next("VERIFIED 2026-08-09: integration_mesh.rs covers raft partition and quorum-loss, but nothing asserts 'old owner fenced after heal'. This is a new test, not an extension.")
//! @yah:next("Carry the W253 section 9 oracle: client-side ledger of acked writes, post-recovery reconciliation, and two reported numbers per run (RTO, RPO).")
//! @yah:verify("cargo test -p yubaba --test integration_mesh")
//! @yah:depends_on(R732-T4)
//! @yah:handoff("LANDED: the canonical split-brain test, oss/yubaba/crates/yubaba/tests/integration_mesh.rs, module `split_brain`. Four tests. The headline one partitions a tenant master, transfers ownership (epoch++), heals, and asserts the old master's tail_frames returns Fenced{current_epoch:2, our_epoch:1} and writes ZERO objects.")
//! @yah:verify("cargo test -p yubaba --features containerd-integration --test integration_mesh = 5 passed / 0 failed / 1 ignored (smoke tier). Baseline was 1 passed / 1 ignored, so 4 new tests, and multi_node_mesh__local still passes.")
//! @yah:verify("cargo test -p turso-backup = 90 + 7 + 4 passed / 0 failed, unchanged from T3's baseline; clippy --all-targets --deny=warnings clean.")
//! @yah:verify("cargo test -p yubaba --lib = 368 passed / 0 failed, unchanged.")
//! @yah:verify("Oracle output on a real run: RTO=68.8us RPO=0 acked writes lost (of 8 acked; 4 writes bounced un-acked at the fence).")
//! @yah:handoff("WHAT THE TEST MODELS, stated so nobody over-reads it. A partition is, at the layer this property lives on, exactly one thing: the isolated node's applied raft state stops advancing while the quorum's continues. So it drives two independent YubabaStates through the real raft::apply (real TransferTenant CAS) and feeds the isolated copy nothing during the partition window. openraft's own partition/election/quorum-loss behaviour is NOT re-tested here -- multi_node_mesh in the same file already covers that over real loopback HTTP, and the thing it cannot do is keep a partitioned master ALIVE AND WRITING, which is the only interesting case for fencing (a killed node writes nothing and proves nothing). The R2 side is not simulated at all: a real turso-backup BackupTarget over an in-memory object store, driven through the real tail_frames, so epoch comparison, watermark CAS, frame keys and manifests are all the production code.")
//! @yah:handoff("A FIRST DRAFT OF THIS TEST PASSED FOR THE WRONG REASON and the fix is the most important detail here. With a 30s lease, by the time the partition healed the old master's lease had EXPIRED, so tenant_fencing_token returned None and it never even attempted a write -- the timeout was doing the work and the epoch was untested. The lease is now 300s, so at the moment of the split-brain attempt the old master holds a lease that is still perfectly valid and has every local reason to believe it owns the tenant. Only the epoch stops it. If the fence held only once a lease lapsed, the epoch would be redundant with the timeout, and W253's canonical experiment would be proving nothing.")
//! @yah:handoff("The scenario is deliberately more honest than a simple two-phase one, because there is a legitimate window people get wrong. During the partition but BEFORE the transfer commits, the old master is still the recorded owner and can still reach R2 -- so it keeps streaming and those writes are correctly acked. The test asserts that (a design that broke it would trade availability for a safety property the epoch already provides). Only writes attempted AFTER the transfer bounce. Sequence: 3 frames steady-state, 2 more while partitioned-but-still-owning (both acked), transfer to B at epoch 2, B streams 3 more, heal, A attempts 4 more and is fenced.")
//! @yah:handoff("W253 section 9 oracle carried in full. Client-side ledger of every write and whether it was acked (ack = a tail_frames call covering that frame reported success). Post-recovery reconciliation: every acked frame must be within the replayable range derived from the sink's own generation manifests. Two numbers reported per run: RTO (partition -> new owner serving) and RPO (acked writes lost). Steady-state hypothesis confirmed -- split-brain is never observable, RPO for acked writes is 0. `wrote zero frames` is asserted as a full object COUNT over the whole sink prefix, not a check of keys the test thought to name, so a stray frame, manifest, or watermark rewrite anywhere would fail it. The manifest chain is also asserted to end up [epoch 1, epoch 1, epoch 2] with owners [node-a, node-a, node-b].")
//! @yah:handoff("Three supporting tests alongside the canonical one. (1) a_graceful_transfer_loses_no_acked_writes -- the other half of W253's steady-state hypothesis: drain then hand over, and the new owner's first tail is Empty, RPO 0. (2) a_fenced_node_cannot_renew_its_lease -- a fenced node must not be able to keep a lease alive under a stale token, or it would look healthy to every readiness gate while being unable to write a byte. (3) the_streamer_only_tails_tenants_this_node_owns -- an unowned tenant is never attempted, exercising the T4 module end to end. One API change in turso-backup to support the oracle: list_and_parse_generation_manifests is now pub (a reconciliation oracle needs to ask what a sink would replay without running a full restore).")
//! @yah:handoff("RELOCATION NOTE from R732-T4 (2026-08-10, session:391a5c6b), not a change of verdict. T4 was rebuilt to the operator-ratified hosting shape, so the tail loop moved out of the yubaba crate into the new yubaba-tenant-streamer crate. All four split_brain tests still live in oss/yubaba/crates/yubaba/tests/integration_mesh.rs and still pass. Only the_streamer_only_tails_tenants_this_node_owns changed: it now drives the real loop through yubaba_test_harness::LocalOwnership (an OwnershipSource over this test's own YubabaState) instead of the deleted in-process module, and asserts strictly more -- an unowned tenant writes ZERO objects, and the very next tick streams under epoch 1 once raft grants the token. The other three are untouched, including the 300s-lease detail that keeps the canonical test honest. turso-backup is now a DEV-dependency of yubaba, which is what keeps these tests compiling while the server links neither it nor the streamer at runtime.")
//!
//! @yah:ticket(R733-F1, "ResidencyPolicy on the tenant record: MobilityTier(Locked|ReadFollow|Relocatable) + home_jurisdiction + bucket_class")
//! @yah:at(2026-08-09T22:21:40Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:phase(P1)
//! @yah:parent(R733)
//! @yah:next("Tier: Warrior — an immutable, correctness-bearing field whose shape every downstream gate inherits; cheap to write, expensive to get wrong.")
//! @yah:next("VERIFIED ABSENT 2026-08-09: `rg -i 'residency|jurisdiction|MobilityTier|home_region' --glob '*.rs' oss/` returns nothing. The concept exists only in noisetable's design notes.")
//! @yah:next("Co-lands with R732-F1's TenantOwnership in the same raft state map — same cluster-epochs drift-gate consequence applies.")
//! @yah:next("Set at tenant creation, immutable except by a deliberate audited operation. Tier 0 must be enforceable, not merely documented.")
//! @yah:verify("cargo test -p yubaba --lib raft")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift")
//!
//! @yah:ticket(R733-T2, "policy.permits(action, destination) gate, wired as the FIRST step of placement, replica spin-up, and cross-cell move")
//! @yah:at(2026-08-09T22:21:47Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:phase(P1)
//! @yah:parent(R733)
//! @yah:next("Tier: Cleric — one predicate plus three call sites; the value is that it exists before the callers do.")
//! @yah:next("One function, three consumers: R737 placement/failover (Tier 0/1 must stay in home_jurisdiction), R735 replica spin-up (Tier 0 = deny any off-jurisdiction replica), R736 move protocol step 1.")
//! @yah:next("Land the gate BEFORE those consumers exist. W249's whole argument is that retrofitting a residency check into a dozen paths later is the failure mode.")
//! @yah:depends_on(R733-F1)
//!
//! @yah:ticket(R733-T3, "Jurisdiction-classed R2 bucket selection at tenant creation (JurisdictionLocked(j) vs Global)")
//! @yah:at(2026-08-09T22:21:54Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:phase(P1)
//! @yah:parent(R733)
//! @yah:next("Tier: Thief — bucket_class already decided by F1; this maps it onto an object-store target.")
//! @yah:next("bucket_class picks the object-store target when a tenant is created: residency-bound data to a jurisdiction-locked bucket, roaming/global tenants to non-jurisdictional R2 that may be copied region to region freely.")
//! @yah:depends_on(R733-F1)
//!
//! @yah:ticket(R733-T4, "Tier 0 enforcement test: a Locked tenant never gets an off-jurisdiction replica or relocation, regardless of presence signals")
//! @yah:at(2026-08-09T22:22:03Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:phase(P1)
//! @yah:parent(R733)
//! @yah:next("Tier: Cleric — the test that converts 'documented' into 'enforced'; it is the point of the whole relay.")
//! @yah:next("Assert the deny holds against every entry path the gate guards, not just the one the code happens to call today.")
//! @yah:depends_on(R733-T2)
//!
//! @yah:ticket(R734-F2, "Region tag on MemberInfo + a bootstrap invariant rejecting any voter set where one region holds a majority")
//! @yah:status(review)
//! @yah:at(2026-08-10T18:49:21Z)
//! @yah:assignee(agent:claude)
//! @yah:phase(P1)
//! @yah:parent(R734)
//! @yah:next("Tier: Warrior — the invariant is the deliverable; encoding 'no single region holds a majority' as a rejectable config is the design work.")
//! @yah:next("VERIFIED 2026-08-09: MemberInfo (raft/mod.rs:346) has exactly one field, `addr`. Raft has no region awareness at all.")
//! @yah:next("The region data already exists one layer down — .yah/infra/machines/*.toml carry `region = \"us-west\" | \"us-east\" | \"us-south\"`. Source the tag from there rather than inventing a second taxonomy.")
//! @yah:next("Invariant to enforce at bootstrap/membership-change: odd voter count AND no single region holding a majority (1-1-1 for 3, 2-2-1 for 5). Reject violating configs rather than warning.")
//! @yah:next("Guards W247's named footgun: 2 voters per region across 3 regions = 6 voters = even count, strictly worse than 5.")
//! @yah:verify("cargo test -p yubaba --lib raft")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift")
//! @yah:handoff("LANDED. QuorumGeography is a named, tested, enforced rule. New in cluster_policy.rs: enum QuorumGeography {MustSpanRegions, SingleFailureDomain} + GeographyVerdict {Sound, Refuse(String)} + judge(), and a new ClusterPolicy.quorum_geography field (fleet -> MustSpanRegions, rig -> SingleFailureDomain). MemberInfo gained region: Option<String> and YubabaRequest::SetMember the matching field, both #[serde(default)]. POST /raft/initialize now judges the founding voter set and refuses a violation with 400 BEFORE openraft writes anything. yubaba CLI: raft init --member id=host:port@region.")
//! @yah:handoff("THE RULE, and why it splits the way it does. Two clauses apply under EVERY policy because they are facts about raft, not about a network: a voter set cannot be empty, and it cannot be even (an even set survives exactly what the odd set below it does while making every write wait on one more node - W247's named footgun, 'maybe 2 in each region' = 6 voters, strictly worse than 5). The spread clause - every voter tagged, no region holding more than n/2 - applies only under MustSpanRegions. A single-LAN rig has one failure domain however its nodes are labelled, so demanding they span regions would be demanding the impossible; that is why this IS a policy field where pre-vote was not.")
//! @yah:handoff("A cluster-of-one is Sound under both policies, deliberately. It is an explicit operator choice (--bootstrap-single-node, the BYO-VPS path) with no failure tolerance to protect and no geography to spread; refusing it would have broken a documented bootstrap for no gain. Pinned by a_fleet_cluster_of_one_still_founds_untagged.")
//! @yah:handoff("BACKWARD COMPATIBILITY WAS A DESIGN CHOICE, not an accident. RaftInitializeRequest's members map accepts BOTH the pre-region form (id -> \"host:port\") and the tagged object form, via serde untagged. Reason: every existing runbook writes the bare form, and if it stopped parsing the operator would get a 422 about JSON shape, conclude they mistyped, and never see the actual message about region tags. The old form parses and is then refused BY POLICY, which is the difference between a dead end and an instruction.")
//! @yah:handoff("SCOPE FINDING - I did NOT add the geography check to /raft/promote-voter, and that is deliberate rather than an omission. It would be dead code under both shipped presets: fleet is VoterAdmission::LearnerOnly so promotion is already refused outright, and rig is SingleFailureDomain so the spread rule does not apply. Also, the odd-count clause must NOT be applied to promotion - growing 3 -> 5 one node at a time passes through 4, so a blanket odd rule on promotion would forbid the very membership growth R734-T3 exists to exercise. Oddness is a property of a founding/settled voter set, not of every intermediate.")
//! @yah:handoff("ENFORCEMENT BOUNDARY, stated plainly in raft_initialize's doc comment rather than left to be discovered: the gate is on the HTTP route, not inside raft::open. openraft::Raft::initialize is reachable by anything holding the raft handle (the test harness founds its clusters exactly that way), so this refuses OPERATOR mistakes; it does not make the invariant structurally unbreakable. Making it so would mean wrapping openraft's own API.")
//! @yah:handoff("EPOCH VERDICT: both axes moved (raft/mod.rs is an input to both) and BOTH are re-records - cluster_protocol stays 4, state_epoch stays 3. The discriminator is field-not-variant: R732-F1 had to bump because it added enum VARIANTS to the externally-tagged YubabaRequest, which an old node cannot parse and so cannot apply, diverging. A field on an existing struct variant is dropped silently in both directions. Checked the R706 hazard explicitly rather than assuming - R706's `access` was also a tolerated field and WAS bumped, because an enforcement path read it. Nothing reads MemberInfo.region: judge() runs on the /raft/initialize REQUEST PAYLOAD at a moment when no cluster exists. Full argument in cluster-epochs.json.")
//! @yah:handoff("REUSE: extracted yubaba_test_harness::solo_node(id, policy) -> SoloNode - one uninitialised node on loopback serving the real router. raft_pre_vote.rs had grown a private copy in my T1 pass and raft_add_learner.rs has a third variant (spawn_joiner); rather than add a fourth I moved mine into the harness and switched raft_pre_vote.rs to it. Left raft_add_learner.rs alone - its joiner plays a different role and it is not this ticket's file.")
//! @yah:next("MemberInfo.region is not yet WRITTEN in production - nothing calls SetMember at all today (grep: only tests). The founding-time check reads the request payload, so the invariant works without it, but the replicated tag stays empty until someone writes member rows. The natural protocol is each node writing its OWN row, since a node knows only its own region: that needs a --region flag on `yubaba serve` plus a write on leadership/join. Deliberately not built here - it is a background-task change, not a bootstrap-invariant one. R736-T3 (cell tagging) depends_on this ticket and is the natural place, since it needs region+jurisdiction on a live cluster rather than only at founding.")
//! @yah:verify("cargo test -p yubaba --lib = 384 passed / 0 failed (376 after T1 + 6 geography rules in cluster_policy::tests + 2 serde-compat tests in raft::tests).")
//! @yah:verify("cargo test -p yubaba --test raft_quorum_geography = 5 passed / 0 failed. NEW SUITE. Beyond asserting the 400, each refusal test also reads /raft/status back and asserts the cluster was NOT founded - a gate that refused AFTER calling raft.initialize would return the same 400 while having already committed the membership it just rejected, and that failure is invisible to a status-code-only test.")
//! @yah:verify("Teeth on the accept path too: the 1-1-1 case in the same test asserts is_initialized flips false -> true, so the helper discriminates rather than always returning false.")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift = 8 passed / 0 failed after re-recording both hashes.")
//! @yah:verify("Full yubaba suite green, no regressions: bootstrap_single_node 2/0, raft_add_learner 1/0, raft_pre_vote 3/0, raft_promote_voter 2/0, raft_transfer_leader 1/0, rig_singleton_ownership 2/0, integration_mesh --features containerd-integration 7/0/1, plus the constable/deploy/single-node/pond suites.")
//! @yah:verify("cargo clippy -p yubaba -p yubaba-test-harness --all-targets: no new warnings on any changed file (the one hit, cluster_policy.rs large-Err-variant on to_openraft_config, is pre-existing - that signature is untouched).")
//! @yah:cleanup("BEHAVIOUR CHANGE for operators: under the fleet profile, `raft init` on a multi-voter cluster now refuses an untagged founding set where it previously succeeded. That is the deliverable, not a side effect, but any runbook founding a fleet cluster needs `@region` suffixes added from .yah/infra/machines/<name>.toml. Cluster-of-one and every rig cluster are unaffected.")
//!
//! @yah:ticket(R737-F1, "TenantPlacement intent map in raft + node capacity/load on MemberInfo (derive from existing allocatable, do not re-declare)")
//! @yah:status(review)
//! @yah:at(2026-08-15T21:13:37Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P3)
//! @yah:parent(R737)
//! @yah:next("Tier: Warrior — declaring intent separately from live ownership is the structural call the rest of the relay rests on.")
//! @yah:next("VERIFIED 2026-08-09: YubabaState.service_placement maps SERVICE -> machine. There is no tenant -> home-node map and no scheduler that re-places on failure.")
//! @yah:next("Split intent from liveness: YubabaState.placement (TenantPlacement{region, sla_tier} = declared intent) alongside R732-F1's tenants map (live owner + epoch).")
//! @yah:next("Capacity already exists one layer down — .yah/infra/machines/*.toml [allocatable] memory_mb/cpu_millis, their measured counterparts (yah.allocatable.* in node.rs), and 'available = allocatable - committed'. R572-F5's CloudConfig::admit_workload (oss/yubaba/crates/cloud/src/config.rs) is the existing capacity-floor matcher. Derive from these; do not declare a third capacity model.")
//! @yah:verify("cargo test -p yubaba --lib raft")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift")
//! @yah:depends_on(R732-F1)
//! @yah:depends_on(R734-F2)
//! @yah:handoff("LANDED. YubabaState.placement (BTreeMap TenantId -> TenantPlacement) is the declared-intent map, held separately from R732-F1's tenants map (live owner + epoch). TenantPlacement carries region (same label space as MemberInfo.region), tier (SlaTier), and demand (TenantDemand). Two new request variants: SetTenantPlacement / ClearTenantPlacement. MemberInfo and YubabaRequest::SetMember each gained capacity (Option NodeCapacity), published live by R734-F5's registration loop. All in oss/yubaba/crates/yubaba/src/raft/mod.rs.")
//! @yah:verify("cargo test -p yubaba --lib = 451 passed / 0 failed. cargo test -p xtask --test cluster_epoch_drift = 8 passed / 0 failed after bumping both axes and re-recording.")
//! @yah:handoff("THE DESIGN CALL TO REVIEW, and it is a deliberate deviation from the ticket's own bullet. The ticket said 'node capacity/load on MemberInfo'. Capacity IS on MemberInfo; LOAD IS NOT — it is derived by YubabaState::node_load(node, now) from the tenants + placement maps. Reason: the scheduler that reads load is also the thing that mutates it. Within one tick the leader places tenant A on node N; N cannot notice, publish a row and have it commit before the leader evaluates tenant B, so B would be placed against N's pre-A load and overcommit the box by exactly the amount the accounting existed to prevent. Deriving closes that by construction. Pinned by a_placement_is_visible_to_the_very_next_fit_check, whose assertion message names the failure a reported field would produce. Secondary reason: R734-F5's DISCOVERED WORK #3 measured what a fast-changing value costs in this exact loop.")
//! @yah:handoff("CAPACITY IS MEASURED, NOT DECLARED. main.rs reads node_probe.specs() (the same collection GET /node/specs serves, cached) rather than re-reading the [allocatable] TOML — the declaration is intent about a box, this is what the box turned out to be, and the scheduler must not place onto RAM that exists only in a config file. Both axes or neither: a half-measured node published as cpu_millis 0 would read as 'unconstrained on CPU' (this system's spelling of zero) and take every tenant on the fleet, so a missing axis yields None.")
//! @yah:handoff("None MEANS UNKNOWN, NEVER UNLIMITED. A node with no published capacity is refused by node_headroom / node_admits. During a roll an un-upgraded node sits in membership with no capacity row, and reading that as unconstrained would funnel every tenant onto the one box that cannot say no. Same degradation shape as R734-F5's region residual — it degrades toward the pre-F1 behaviour (nothing schedules there) and never below it.")
//! @yah:handoff("THREE PREDICATES, STATED ONCE so F3 and T4 ask the same question rather than each re-deriving it: node_load(node, now), node_headroom(node, now) -> Option NodeCapacity, node_admits(node, demand, now) -> bool. node_admits applies the same capacity floor CloudConfig::admit_workload applies one layer down, on the same units (MiB + k8s millicores) with the same reading of 0 as unconstrained-on-that-axis.")
//! @yah:handoff("WHY TenantDemand IS A NEW TYPE despite being shape-identical to three existing ones, argued in its doc comment rather than left to look like carelessness: workload_spec::ResourceLimits::memory_mb is a CEILING whose own doc tells schedulers to read memory_request_mb instead; node::WorkloadResources has the right semantics but versions on NODE_SCHEMA_VERSION while this versions on the raft state_epoch, and one type under two independent compat regimes is a trap that springs the day they must move apart; NodeAllocatable is the budget side, not the demand side. What it is NOT is a fourth set of UNITS.")
//! @yah:handoff("SlaTier defaults to ColdHydrate, the pessimistic arm. A tenant whose tier was never declared must not be read as having a warm replica somewhere, or F3 would pick a target on a promise nothing kept. MY OWN TEST CAUGHT THIS: an_undeclared_tier_defaults_to_cold_hydrate failed with 'missing field tier' because the field was not #[serde(default)] despite the doc claiming the default. Fixed; a hard parse error would have stalled the state machine at that log index for a field whose safe value is known.")
//! @yah:handoff("EPOCH VERDICT: BREAKING ON BOTH AXES. cluster_protocol 4 -> 5, state_epoch 3 -> 4, both history entries written, both hashes re-recorded. The forcing fact is the two new ENUM VARIANTS — the same discriminator R732-F1 recorded. YubabaRequest is externally tagged with no #[serde(other)], so an epoch-4 node receiving a replicated SetTenantPlacement over AppendEntries cannot apply it, cannot advance past that log index, and diverges. state_epoch moves for the LOG, not the snapshot: raft_log.json is serde_json over BTreeMap<u64, Entry> whose payload is EntryPayload::Normal(YubabaRequest), so a log that has carried the variant cannot be read by an epoch-3 binary at all. The R706 hazard (a TOLERATED field making a mixed cluster silently wrong) was checked rather than assumed and does NOT apply: an old node dropping `capacity` records None, and None is defined as unschedulable, so the mixed window is fail-closed — it costs placement ONTO un-upgraded nodes, never an overcommit.")
//! @yah:handoff("HARNESS: yubaba_test_harness::HARNESS_CAPACITY (16 GiB / 8 cores) is published by every registering solo_node. Deliberately a FIXED SYNTHETIC figure, not the measured one — a T5 placement test asserting 'this tenant fits, that one does not' has to be a statement about the scheduler, and reading the host's real RAM would make it a statement about whoever's laptop ran it: green on a 64 GB machine, red in CI for a reason no error message would name.")
//! @yah:gotcha("TREE HYGIENE, caused by me and worth knowing before you read `git diff`: I ran `cargo fmt -p yubaba -p yubaba-test-harness`, and HEAD was not rustfmt-clean, so the diff includes pure-reformat churn in files this ticket did not touch — leader.rs, raft/store.rs, acme_issuer.rs, camp_rpc.rs, secrets.rs, litestream.rs, yubaba-test-harness/src/lib.rs, and several tests/. Every one of those hunks is whitespace-only rustfmt output over code that was already committed unformatted; none of it is a semantic change and none of it is a peer's uncommitted work (verified by diffing each file with and without -w). Scope any commit to explicit paths rather than `git add -A`.")
//! @yah:gotcha("SEPARATELY, a live peer IS mid-flight in this workspace: @Ashguard:rune (session:fa39d638) is at phase=working on relay R742 and is adding machines_in_group / declared_sovereign_groups / admit_workload_in_group to oss/yubaba/crates/cloud/src/config.rs (R742-F3, W305). Untouched by me. It matters to R737 because that is the same admission/placement matcher F3's scheduler will want to reuse — re-read that file before building the scheduler rather than the version this ticket read.")
//!
//! @yah:ticket(R734-F5, "Populate MemberInfo.region: --region on yubaba serve + each node registering its own member row")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-08-12T01:37:17Z)
//! @yah:phase(P2)
//! @yah:parent(R734)
//! @yah:next("THE GAP, verified 2026-08-10: R734-F2 added MemberInfo.region and YubabaRequest::SetMember{region}, and the founding gate on POST /raft/initialize judges regions from the REQUEST PAYLOAD. But nothing writes member rows in production at all - `rg SetMember` over oss/yubaba finds only the state machine, the apply() arm, and tests. So YubabaState.members is empty on the live fleet and the region tag is a data model plus a founding-time check, not live cluster state.")
//! @yah:next("WHY IT MATTERS BEYOND TIDINESS: three separate pieces of work wait on this same fact. R734-T4 (leader pin) cannot tell which voter is in the anchor region. R734-T3's remove-member gate can judge only voter COUNT, not region spread, so a removal can take a 2-2-1 cluster to a lopsided 2-1 without being refused. R736-T3 (cell tagging) needs region+jurisdiction on a LIVE cluster, not only at founding.")
//! @yah:next("THE SHAPE, and the constraint that decides it: a node knows only its OWN region, so the protocol is each node writing its own row rather than any node writing everyone's. (1) --region <label> on `yubaba serve`, default None, matching the `region` a machine declares in .yah/infra/machines/<name>.toml - the same label space MemberInfo.region documents, not a second taxonomy. (2) Carry it on ServerState (with_region, alongside with_node_id). (3) A task started with the raft node: once membership contains this node id and metrics name a leader, compare YubabaState.members[self] against this node's own (addr, region) and write SetMember when they differ. Idempotent by construction - it converges and then does nothing, so it is safe to run on every node forever.")
//! @yah:next("THE WRITE PATH IS THE FIDDLY PART. A follower cannot client_write. Use raft.client_write when this node is leader; on ForwardToLeader, POST /raft/write to the leader address the error hands back (membership carries BasicNode.addr, so the address is already in hand). Back off and retry rather than failing - there is no deadline on this, and a node that cannot register yet simply has no row yet, which is the same state it was already in.")
//! @yah:next("DO NOT block node startup on it, and do not make a failed registration fatal. The cluster is fully functional without member rows today; this is additive metadata. A registration loop that can wedge a node boot would be a strictly worse trade than the empty map it replaces.")
//! @yah:next("TEST: found a cluster via the harness solo_node helper with distinct --region values, then assert every node's row appears in GET /raft/status (or a small read endpoint) carrying the right region. The teeth are in asserting each row's region matches THAT node's flag rather than merely that rows exist - a loop that wrote its own region into everyone's row would pass the weaker check.")
//! @yah:verify("cargo test -p yubaba --lib")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift")
//! @yah:gotcha("cluster-epochs.json discipline applies: SetMember already carries `region` as of R734-F2 (a #[serde(default)] struct field, re-recorded not bumped), so ACTUALLY WRITING it moves no wire type. But this change makes yubaba emit a replicated request it never emitted before, which is worth a deliberate look at the wire axis rather than an assumption - re-read the R734-F2 entry's field-not-variant reasoning before deciding.")
//! @arch:see(.yah/docs/working/W247-multiregion-raft-quorum.md)
//! @yah:handoff("NOTHING BUILT BY ME. Claim-and-release, not a work handoff - do not read it as progress. The design in the @yah:next bullets is untouched and still the plan of record.")
//! @yah:handoff("Tree anchor at handoff: 66dc2cf4cc338b0a94c68e189b22feedc330005f — the shared tree as I left it. Diff against it (`git diff 66dc2cf4cc338b0a94c68e189b22feedc330005f..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("The live builder is Ashguard/libra (session:99475bc6), spawned onto relay R734 at the same time I was and holding ticketId R734 on camp.roster. Coordinate before claiming - do not assume it is free because the column says handoff.")
//! @yah:gotcha("COLLISION 2026-08-11 18:10 PDT. I (Ashguard/blade, session:b4f7871f) claimed this and found a live peer already writing it. Released within two minutes with ZERO source edits by me. Evidence: oss/yubaba/crates/yubaba/src/raft/mod.rs and store.rs mtimes moved 60-90s AFTER I first read them, and the new content is F5-shaped - a MemberInfo doc comment citing crate::member_registration plus PartialEq/Eq on MemberInfo, and two new read accessors YubabaStateMachine::members() and member() carrying R734-F5 doc text. None of that is mine.")
//! @yah:handoff("LANDED. MemberInfo.region is live cluster state, not just a data model. NEW src/member_registration.rs: a per-node loop that publishes its OWN row. plan_registration() is a pure verdict (Wait / Converged / Write) with 7 unit tests; the loop writes via raft.client_write when it leads and forwards to POST /raft/write on ForwardToLeader when it does not, using the leader address openraft hands back. --region <label> on `yubaba serve` + ServerState::with_region / ServerState.region. Never fatal, never blocks a boot: every failure backs off and retries, and a node that cannot register simply has no row, which is the state it was already in.")
//! @yah:next("Nothing queued behind this ticket. R734-T4 consumed it live (see below); R736-T3 (cell tagging) is the remaining downstream and now has the live region+addr map it wanted.")
//! @yah:handoff("READ SURFACE, which is what the consumers actually needed: YubabaStateMachine::members() -> BTreeMap<YubabaNodeId, MemberInfo> and ::member(node_id) (raft/store.rs), plus a `members` section on GET /raft/status. Three sections on that response now answer three different questions and can legitimately disagree - membership_config is who raft COUNTS, liveness is who anything has HEARD FROM, members is what those nodes SAY ABOUT THEMSELVES. Stated in the handler doc so nobody reads a lag between them as a bug. MemberInfo gained PartialEq/Eq (the loop's converged check is an equality).")
//! @yah:handoff("DISCOVERED WORK #1, and the most valuable thing in this pass: POST /raft/remove-member now applies the region-SPREAD clause, not just the odd-count one. That gap was R734-T3's, named in its own doc comment as unfixable at the time because there was no region to read - so closing it is this ticket finishing its own consequence rather than scope creep. Concretely: removing both us-west voters from a 2-2-1 five-voter fleet leaves three voters, two of them in us-east. Count-legal, region-fatal, indistinguishable from healthy until that datacenter goes dark. Now a 400 naming the region.")
//! @yah:handoff("THE JUDGEMENT CALL INSIDE THAT, and it is the one to review: the spread clause is judged ONLY when every surviving voter has published a region. A missing row makes the set unjudgeable, and the alternative - refusing - would have been strictly worse: the commonest reason to remove a node is that it is DOWN, possibly before it ever registered, and a node on a build predating this ticket never registers at all. A gate that can lock an operator out of the repair verb is worse than one that occasionally cannot check. It is not silent either way: the response carries spread_judged true/false. Both branches are tested.")
//! @yah:handoff("DISCOVERED WORK #2: /raft/remove-member now also CLEARS the departed nodes rows. The departing node cannot - its own loop goes quiet the moment it leaves membership, which is correct - so the removing leader must, or the map accumulates rows for machines decommissioned months ago and every region consumer reasons about a cluster that no longer exists. Best-effort by design: the membership change has already committed and is the part that matters, so a failure leaves a stale row rather than reporting a real removal as a failure. The one case that reliably hits it is a leader removing itself. Named in the response as stale_rows rather than hidden.")
//! @yah:handoff("DISCOVERED WORK #3, a real defect caught by a flake rather than by review: the loop originally woke on the raft metrics watch, like leader.rs does. That is wrong here. Metrics republish on every heartbeat and every replication step, and a node with no quorum republishes them continuously while it campaigns - so the loop woke tens of times a second to re-evaluate a comparison whose answer changes at most once per process. It measurably slowed the machine (raft_quorum_geography went 3.02s -> 1.38s after the fix). Now it polls: 1s while waiting, 30s once converged. Leadership transitions must be REACTED to; a converged metadata row does not.")
//! @yah:handoff("DISCOVERED WORK #4: fixed a PRE-EXISTING race in R734-F2s tests/raft_quorum_geography.rs. Raft::initialize returning Ok and the membership appearing in Raft::metrics are not the same instant (metrics go through a watch channel), so the accept-path assertion read once and could miss it - a_rig_founds_three_untagged_voters failed intermittently under load. The three ACCEPT-path assertions now poll via a new becomes_initialized(); the three REFUSAL-path ones deliberately keep the unpolled read, because there not-initialized must be true immediately and a poll would only give a gate that initialised-then-refused extra chances to look correct. 5 consecutive clean runs after.")
//! @yah:handoff("EPOCH VERDICT: NOT BREAKING on BOTH axes, both hashes re-recorded, cluster_protocol stays 4 and state_epoch stays 3. Full argument in cluster-epochs.json (2026-08-11 entry). The short version: this adds no type, no variant, no field, no route - it starts EMITTING an existing variant (SetMember, and RemoveMember on the removal path) and populating a field R734-F2 already priced into both axes. The R706 hazard was checked rather than assumed, and this is where it differs from F2: F2 could say nothing reads MemberInfo.region, and that is no longer true. Three reasons it is not the R706 shape are in the entry; the load-bearing one is that an old nodes behaviour is IDENTICAL to the new codes own documented downgrade (count clause only), so a mixed cluster produces an outcome the new code already produces on purpose.")
//! @yah:handoff("HARNESS: yubaba_test_harness gained solo_node_in_region(id, policy, Some(region)) and solo_node_unregistered(id, policy, region); SoloNode gained a `region` field. solo_node now wires with_cluster_state (it did not before) and runs the registration loop, so a harness node models a real one. solo_node_unregistered exists for a specific reason worth keeping: clearing a row out from under a LIVE loop only races it - the clearing write is itself a metrics change - so the only honest way to test the row-is-unknown branches is a node that never registers, which is also exactly what an un-rolled node looks like mid-upgrade.")
//! @yah:handoff("DOCS CORRECTED, since this work disproved them: W247 section 2 is rewritten from a to-do list into a SHIPPED section covering F2 + F5 and the removal-gate consequence, and its Where-we-are-today `No region awareness` bullet gained a SHIPPED-since sub-bullet. W253 section 10s `Voter set is odd and spans regions` box is ticked with the enforcement named (both membership paths, plus the stand-down rule), and its line claiming raft MemberInfo still holds only addr is corrected. W247s OVH checklist step 3 already named --region when I got there - @Ashguard:blade wrote it while building T4.")
//! @yah:handoff("CONCURRENCY, and the reason I did NOT also build T4 as the relay prompt suggested: @Ashguard:blade (session:b4f7871f) is LIVE on R734-T4 and was mid-flight in the same files. Their --leader-anchor flag landed in main.rs under me while I was compiling, two lines from my --region. I stayed out - leader.rs, src/leader_pin.rs and tests/raft_leader_pin.rs are untouched by me - and sent them a party.chat naming every surface F5 gives them (members()/member(), the /raft/status section, the harness constructors, and the one design constraint: a missing row means UNKNOWN, never `no anchor voter exists`). Their tests/raft_leader_pin.rs is green against my harness changes (3/0, run read-only to confirm I had not broken them).")
//! @yah:verify("cargo test -p yubaba --test raft_member_registration = 6 passed / 0 failed. NEW SUITE, 3 consecutive clean runs. Every row is checked against the region THAT node was started with, not merely that three rows exist - the likeliest way to get this wrong is the leader writing its own region into every row, since it is the only node that can write without forwarding, and an aggregate count would pass that.")
//! @yah:verify("FALSIFIED, not assumed: registration_stops_writing_once_the_rows_match asserts the applied log index stops moving after convergence. Disabling the converged branch in plan_registration fails it with 1269 applied entries against the 311 it settles on, while the other five tests stay green. That is the property that makes it safe to run this loop forever on every node, and it is invisible to any test that only checks the maps contents.")
//! @yah:verify("cargo test -p yubaba --lib = 405 passed / 0 failed (384 was the R734-F2 baseline; +7 member_registration unit tests and the rest from concurrent R734-T4 work in the same tree). cargo test -p xtask --test cluster_epoch_drift = 8 passed / 0 failed after re-recording both hashes (was 7/1, both axes red).")
//! @yah:verify("No regressions across the neighbouring suites, all re-run after the change: raft_membership_loop 5/0, raft_quorum_geography 5/0 (5 consecutive runs after the race fix), raft_pre_vote 3/0, raft_add_learner 1/0, raft_promote_voter 2/0, raft_transfer_leader 1/0, bootstrap_single_node 2/0, rig_singleton_ownership 2/0, integration_mesh --features containerd-integration 7/0/1. Also raft_leader_pin 3/0 (the concurrent T4 suite, run only to confirm my harness change did not break it). cargo check -p cloud-client clean; ./scripts/check-workspace-members.sh = all 58 resolve; `yubaba serve --help` renders --region.")
//! @yah:verify("cargo clippy -p yubaba -p yubaba-test-harness --all-targets: zero warnings on any file this ticket touched. The four hits inside these two crates are pre-existing and on untouched lines (raft/store.rs:140/162 Copy-clone on openraft Vote types, store.rs:221 derivable Default on StateMachineData, yubaba-test-harness/src/lib.rs:141 needless borrow).")
//! @yah:gotcha("RESIDUAL, and it is the one thing an operator must know: during a roll the member map is INCOMPLETE rather than wrong. An un-rolled node is in raft membership with no row, so every consumer must read a missing row as `region unknown`, never as `no such node`. The removal gate does (stands down, reports spread_judged:false) and yubaba_test_harness::solo_node_unregistered exists so that branch stays tested. Same shape as R734-T1s pre-vote residual: it degrades toward the pre-F5 behaviour and never below it, so the spread rule is only fully in force once every voter is rolled.")
//! @yah:cleanup("NO yah-CLI SURFACE was added for --region or for reading the members map, matching the standing note on R734-T3. `yubaba serve --region` is the only way to set it and GET /raft/status the only way to read it. If a `yah cloud raft members` view is wanted, /raft/status already carries everything it needs.")
//! @yah:handoff("FOLLOW-UP LANDED after @Ashguard:blade's T4 report: SoloNode now exposes `pub raft: YubabaRaft` and `pub state_machine: YubabaStateMachine`, clones of exactly what the router and the registration loop are given. T4 had carried a private 40-line node builder in tests/raft_leader_pin.rs precisely because the harness returned neither handle, and had filed that as an @yah:cleanup rather than edit solo_node.rs while I was in it. Closing it here was five lines and keeps the third copy of that builder from setting. Re-verified after: raft_leader_pin 3/0, raft_member_registration 6/0, raft_quorum_geography 5/0, raft_membership_loop 5/0, raft_pre_vote 3/0, clippy clean on solo_node.rs.")
//! @yah:handoff("CONSUMED, which is the real proof the harness change was the right shape: R734-T4's tests/raft_leader_pin.rs now runs on solo_node_in_region / solo_node_unregistered and reads peers' regions via node.state_machine.members(). Its private 40-line node builder, its Drop impl and its health-poll are deleted and its @yah:cleanup is dropped. Verified after the fold-back: raft_leader_pin 4/0, raft_member_registration 6/0, yubaba --lib 408/0.")

pub mod network;
pub mod store;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use openraft::{BasicNode, Raft};
use serde::{Deserialize, Serialize};
use workload_spec::secrets::SecretAccess;
use workload_spec::TenantId;

pub use network::{YubabaNetwork, YubabaNetworkFactory};
pub use store::{YubabaLogStore, YubabaStateMachine};

use crate::cluster_policy::ClusterPolicy;

// ── Type config ──────────────────────────────────────────────────────────────

/// Node IDs are u64, assigned at provisioning time and persisted to the
/// yubaba state file alongside the node's Tailscale mesh IP.
pub type YubabaNodeId = u64;

// openraft 0.10: `Entry`, `AsyncRuntime`, `Vote`, `LeaderId`, `Responder` all
// take crate defaults (adv LeaderId, TokioRuntime, oneshot responder). Only the
// application-facing types are pinned. `SnapshotData` moved off the type config
// onto `RaftStateMachine`/`RaftNetworkV2` (both use `Cursor<Vec<u8>>` here).
openraft::declare_raft_types!(
    pub YubabaRaftConfig:
        D      = YubabaRequest,
        R      = YubabaResponse,
        NodeId = YubabaNodeId,
        Node   = BasicNode,
);

/// Concrete Raft type alias for the yubaba cluster. openraft 0.10 carries the
/// state-machine type on `Raft<C, SM>` (0.9 erased it), so the SM must be named
/// here or `metrics()`/`client_write()` resolve against the unusable `SM = ()`.
pub type YubabaRaft = Raft<YubabaRaftConfig, YubabaStateMachine>;

// ── State machine commands ────────────────────────────────────────────────────

/// Mutations that go through raft consensus.
///
/// Callers write to the leader via `POST /raft/write`; the leader fans
/// the entry out via AppendEntries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum YubabaRequest {
    SetMember {
        node_id: YubabaNodeId,
        addr: String,
        /// R734-F2: the node's geo region, e.g. `"us-west"` — see
        /// [`MemberInfo::region`]. `#[serde(default)]` so a pre-R734-F2 node's
        /// replicated `SetMember` still applies, landing as `None`.
        #[serde(default)]
        region: Option<String>,
        /// R737-F1: the node's schedulable budget — see [`NodeCapacity`].
        /// `#[serde(default)]` on the same contract as `region`: a pre-R737 node
        /// replicating `SetMember` lands as `None`, which reads as *unknown* and
        /// therefore unschedulable, not as unlimited.
        #[serde(default)]
        capacity: Option<NodeCapacity>,
    },
    RemoveMember {
        node_id: YubabaNodeId,
    },
    SetServicePlacement {
        service: String,
        machine: String,
    },
    ClearServicePlacement {
        service: String,
    },
    /// `acquired_at` is unix seconds, filled in by the caller. The TTL-expiry
    /// check in `apply` compares a *new* requester's `acquired_at` against the
    /// holder's, so it assumes NTP-synced clocks across voters: a node whose
    /// clock runs fast by more than the remaining TTL could steal a live lock
    /// early. Acceptable for the HA fleet (NTP-synced); issuer lock TTLs are set
    /// far larger than plausible skew (see `acme_issuer::IssuerConfig::lock_ttl`).
    AcquireLock {
        key: String,
        owner: String,
        ttl_secs: u64,
        acquired_at: u64,
    },
    ReleaseLock {
        key: String,
        owner: String,
    },
    SetIngressOwner {
        machine: String,
    },
    ClearIngressOwner,
    // R278-F3: rollout mirror metadata — defined for forward-compat with the
    // raft path; the in-process RolloutStore is the v1 store until R277 lands.
    /// Record that a rollout is in progress so a new leader can resume it.
    SetRolloutState {
        rollout_id: String,
        artifact: String,
        /// JSON-serialised `RolloutStatus`.
        status_json: String,
        current_step: usize,
        started_at: u64,
    },
    /// Remove a completed or aborted rollout from the raft snapshot.
    ClearRolloutState {
        rollout_id: String,
    },
    // R600-F1 (W273): cluster secret store. Values are AES-256-GCM CIPHERTEXT
    // ONLY — the raft layer never sees plaintext or the KEK. The issuer
    // (R600-F3) encrypts with the node-local cluster KEK before PutSecret; the
    // `SecretRef::Cluster` resolver (R600-F2) decrypts after reading. Homing
    // cert material here gives every node the same bytes via ordinary raft
    // replication (see `SecretRecord` for why plaintext must never appear).
    /// Insert or overwrite a cluster secret.
    PutSecret {
        /// Logical key, e.g. `"tls/yah.dev"`.
        name: String,
        /// AES-256-GCM output (sealed bytes with the GCM tag appended, per the
        /// `aes-gcm` crate's `encrypt` convention). Never plaintext.
        ciphertext: Vec<u8>,
        /// The 12-byte GCM nonce the ciphertext was sealed under.
        nonce: Vec<u8>,
        /// Caller-stamped unix seconds (the domain owns "when", like
        /// [`YubabaRequest::AcquireLock`]'s `acquired_at`).
        updated_at: u64,
        /// R706 (W294): who may be served this secret. `#[serde(default)]` so a
        /// log entry written before the field existed replays as
        /// [`SecretAccess::default`] — deny-all — rather than failing the
        /// replay or silently granting access.
        #[serde(default)]
        access: SecretAccess,
        /// R720-F1 (W294): keyed digest of the plaintext — HMAC-SHA256 under a
        /// subkey HKDF-derived from the cluster KEK, domain-separated from the
        /// sealing key. Lets a camp/fleet drift check ("does the record on the
        /// fleet match what's declared locally?") compare without ever
        /// decrypting. `#[serde(default)]` so a log entry written before this
        /// field existed replays as `None` rather than failing.
        #[serde(default)]
        digest: Option<Vec<u8>>,
    },
    /// Remove a cluster secret. Hard delete, no tombstone: a secret that should
    /// stop being served is removed and the consuming resolver (R600-F2) fails
    /// closed on the miss — there is no 410-vs-404 distinction to preserve here.
    DeleteSecret {
        name: String,
    },

    // R732-F1 (W245): per-tenant ownership + fencing epoch. Read
    // [`TenantOwnership`] first — it carries the argument for why the *epoch*,
    // not the lease, is the safety property, and these three variants only make
    // sense against it.
    //
    // All three are caller-stamped with `now` (unix seconds), the same
    // convention as [`YubabaRequest::AcquireLock`], and all three answer with
    // [`YubabaResponse::Tenant`] so the caller learns its fencing token (or
    // learns that it has none).
    /// Take ownership of a tenant.
    ///
    /// Granted when the tenant has no record, its lease has expired, or `node`
    /// is re-claiming a tenant it already owns. Refused — with the current
    /// epoch and owner — when another node holds a live lease.
    ///
    /// **A grant always advances the epoch**, including the self-reclaim case.
    /// That is deliberate: the reason a live owner re-claims is that it
    /// restarted, and the process it replaced may still be mid-write. Handing
    /// the restarted owner the *same* token would leave the zombie
    /// indistinguishable from it. Advancing fences the zombie by construction.
    ///
    /// The cost is that a retry after a lost response burns an epoch number
    /// (the claimant re-claims and gets N+2 rather than N+1). That is benign —
    /// only the ordering of epochs is load-bearing, nobody else ever held N+1,
    /// and u64 does not run out. Contrast [`YubabaRequest::TransferTenant`],
    /// where a double-advance is *not* benign and is CAS-guarded.
    ///
    /// Use [`YubabaRequest::RenewTenantLease`] to keep a lease alive; claiming
    /// as a heartbeat would fence your own streamer on every beat.
    ClaimTenant {
        tenant: TenantId,
        node: YubabaNodeId,
        /// Lease length in seconds; the record's deadline becomes `now + lease_secs`.
        lease_secs: u64,
        /// Caller-stamped unix seconds.
        now: u64,
    },
    /// Hand a tenant from its current owner to `to`, compare-and-swapping on
    /// `from_epoch`.
    ///
    /// This is the *authorized* takeover path and deliberately ignores whether
    /// the outgoing owner's lease is still live — moving a tenant off a healthy
    /// node is an ordinary operation (drain, rebalance), and the epoch is
    /// exactly what makes it safe to do while the old owner is still running
    /// and unaware.
    ///
    /// The CAS is what stops a double-advance. A client whose leader committed
    /// the transfer and then died before answering cannot tell success from
    /// failure, so it retries; without the CAS the retry would advance the
    /// epoch a second time and could reshuffle ownership underneath a decision
    /// that had already been made. With it, the retry either observes its own
    /// post-state (reported as the same `Granted`) or is fenced.
    ///
    /// `from_epoch: 0` transfers a tenant that has no record yet.
    TransferTenant {
        tenant: TenantId,
        to: YubabaNodeId,
        /// The epoch the caller believes is current. `0` means "no record".
        from_epoch: u64,
        lease_secs: u64,
        now: u64,
    },
    /// Extend the current owner's lease **without touching the epoch** — the
    /// heartbeat path.
    ///
    /// Granted only when `node` is the recorded owner *and* `epoch` matches, so
    /// a node running on a stale token cannot keep a lease it no longer holds
    /// alive. Idempotent by construction: the deadline is absolute and only
    /// ever moves forward, so a duplicated or out-of-order entry can neither
    /// double-extend nor retract a lease.
    RenewTenantLease {
        tenant: TenantId,
        node: YubabaNodeId,
        /// The fencing token the caller is renewing under.
        epoch: u64,
        lease_secs: u64,
        now: u64,
    },

    // R737-F1 (W246): declared placement intent. Deliberately NOT stamped with
    // `now` and deliberately carrying no epoch — unlike the three variants
    // above, these do not participate in fencing. Intent is a declaration an
    // operator makes, not a claim a node races another node for, so there is
    // nothing here to compare-and-swap and no clock to trust.
    /// Declare (or re-declare) where a tenant should live.
    ///
    /// Last-write-wins, and that is the correct semantics rather than a
    /// simplification: two writers disagreeing about a tenant's home region is
    /// an operator conflict, and raft has already serialized it. A CAS here
    /// would only convert that conflict into a retry loop over the same
    /// disagreement.
    ///
    /// **Writing intent never moves a tenant.** It is an input to the scheduler,
    /// which reconciles toward it by committing a
    /// [`TransferTenant`](YubabaRequest::TransferTenant) — the only path that
    /// touches the epoch. Redeclaring a tenant's region does not fence its
    /// current owner and must not be expected to.
    SetTenantPlacement {
        tenant: TenantId,
        placement: TenantPlacement,
    },
    /// Withdraw a tenant's placement intent.
    ///
    /// A genuine delete, unlike [`TenantOwnership`] which is never removed. The
    /// asymmetry is not an oversight: the ownership record is retained because
    /// its *epoch* must never regress, and an intent record carries no epoch and
    /// no monotonic property to protect. A decommissioned tenant that kept a
    /// declaration forever would give the scheduler permanent work toward a
    /// tenant nobody wants placed.
    ///
    /// Clearing intent leaves any live owner exactly where it is, for the same
    /// reason `SetTenantPlacement` does not move one: this map is not the write
    /// path. The result is a tenant that is owned but undeclared, which is a
    /// legal state the scheduler reads as "not mine to reconcile".
    ClearTenantPlacement {
        tenant: TenantId,
    },
}

// openraft 0.10 requires `AppData: Debug + Display`. The Debug form is a faithful,
// compact rendering of the request, so forward Display to it.
impl std::fmt::Display for YubabaRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// State machine response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum YubabaResponse {
    Ok,
    LockGranted(bool),
    /// R732-F1: outcome of a tenant ownership transition.
    Tenant(TenantOutcome),
}

/// The answer to a tenant ownership request (R732-F1 / W245).
///
/// Deliberately not a `bool`: the caller needs the *number* on success (that
/// integer is its fencing token — nothing it writes to R2 is safe without it),
/// and needs the current epoch on failure so it can tell "I am behind, stop
/// writing and re-sync" from "the request was malformed".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantOutcome {
    /// The caller owns the tenant at `epoch`. This is its fencing token.
    Granted { epoch: u64 },
    /// Refused. The caller's view of the tenant is stale; `current_epoch` is
    /// what raft actually holds (`0` / `None` when there is no record at all).
    Fenced {
        current_epoch: u64,
        current_owner: Option<YubabaNodeId>,
    },
}

// ── Domain state ──────────────────────────────────────────────────────────────

/// The entire yubaba cluster state.  Serialised as a JSON snapshot;
/// state volume is KB-scale even on large clusters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct YubabaState {
    pub members: BTreeMap<YubabaNodeId, MemberInfo>,
    /// service name → machine name
    pub service_placement: BTreeMap<String, String>,
    pub locks: BTreeMap<String, LockEntry>,
    pub ingress_owner: Option<String>,
    /// R278-F3: in-flight rollout metadata replicated via raft so a new leader
    /// can resume a rollout after leader change. The in-process RolloutStore
    /// (on ServerState) is the authoritative v1 store; this map is updated
    /// alongside it via SetRolloutState / ClearRolloutState YubabaRequests.
    #[serde(default)]
    pub rollouts: BTreeMap<String, RolloutRaftRecord>,
    /// R600-F1 (W273): raft-replicated cluster secrets, keyed by logical name
    /// (e.g. `"tls/yah.dev"`). Values are AES-256-GCM ciphertext — see
    /// [`SecretRecord`]. This is the fleet-shared store backing
    /// `SecretRef::Cluster` (R600-F2); `#[serde(default)]` so pre-F1 snapshots
    /// load with an empty map (same forward-compat contract as `rollouts`).
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRecord>,
    /// R732-F1 (W245): who owns each tenant's write path, and under which
    /// fencing epoch. Keyed on the existing [`workload_spec::TenantId`] — the
    /// same identity `secrets`' [`SecretAccess`] rules and the service records
    /// use — so there is exactly one tenant identifier in the system.
    ///
    /// `#[serde(default)]` so pre-R732 snapshots load with an empty map (same
    /// forward-compat contract as `rollouts` and `secrets`). An empty map means
    /// *nobody* owns anything, which is the safe default: a node with no record
    /// gets no fencing token and therefore may not write.
    #[serde(default)]
    pub tenants: BTreeMap<TenantId, TenantOwnership>,
    /// R737-F1 (W246): where each tenant *should* live — declared intent, as
    /// opposed to `tenants`' record of who holds it right now. See
    /// [`TenantPlacement`] for why the two are separate maps and not one record.
    ///
    /// `#[serde(default)]` so pre-R737 snapshots load empty, same forward-compat
    /// contract as `tenants`. An empty map means nothing is declared, which is
    /// the safe default: the scheduler has no work rather than an implied
    /// placement for everything.
    #[serde(default)]
    pub placement: BTreeMap<TenantId, TenantPlacement>,
}

impl YubabaState {
    /// The fencing token `node` may write `tenant` under at `now`, if any.
    ///
    /// `Some(epoch)` iff `node` is the recorded owner **and** its lease is
    /// still live. Every other case — a different owner, an expired lease, no
    /// record at all — is `None`, meaning "do not write". This is the one place
    /// that predicate is spelled out; R732-T4's streamer wiring asks this rather
    /// than re-deriving owner-and-lease at each call site.
    pub fn tenant_fencing_token(
        &self,
        tenant: &TenantId,
        node: YubabaNodeId,
        now: u64,
    ) -> Option<u64> {
        self.tenants
            .get(tenant)
            .filter(|rec| rec.owner == node && rec.is_live(now))
            .map(|rec| rec.epoch)
    }

    /// What `node` is currently carrying at `now` — R737-F1.
    ///
    /// Derived from `tenants` ∩ `placement`: a tenant contributes iff `node`
    /// holds it with a **live** lease. Read [`NodeLoad`] for why this is a
    /// derivation and not a replicated field; the short version is that the
    /// scheduler reading it is also the thing mutating it, so a reported number
    /// would always be one decision stale at the moment it is used.
    ///
    /// An expired lease contributes nothing. That is the point: the node whose
    /// owner died is exactly the node the scheduler is about to place *away*
    /// from, and counting a dead tenant against the live capacity of the node
    /// that lost it would make a failing node look full while it emptied.
    ///
    /// A tenant owned but not declared contributes to `tenants` and nothing to
    /// the resource axes — there is no demand recorded for it, and inventing one
    /// would be a guess the operator never made. `0` is already this system's
    /// spelling for "unconstrained on that axis".
    pub fn node_load(&self, node: YubabaNodeId, now: u64) -> NodeLoad {
        let mut load = NodeLoad::default();
        for (tenant, owned) in &self.tenants {
            if owned.owner != node || !owned.is_live(now) {
                continue;
            }
            load.tenants += 1;
            if let Some(intent) = self.placement.get(tenant) {
                load.memory_mb = load.memory_mb.saturating_add(intent.demand.memory_mb);
                load.cpu_millis = load.cpu_millis.saturating_add(intent.demand.cpu_millis);
            }
        }
        load
    }

    /// `capacity - load` for `node`, or `None` when the node has published no
    /// capacity (R737-F1).
    ///
    /// `None` is **unknown**, not unlimited — see [`MemberInfo::capacity`]. A
    /// caller choosing a placement target must treat it as ineligible, which is
    /// what [`Self::node_admits`] does.
    ///
    /// Saturating, so an overcommitted node reports `0` headroom rather than
    /// wrapping to an enormous one. Overcommit is reachable without a bug:
    /// capacity can *shrink* under a live placement when a box is resized.
    pub fn node_headroom(&self, node: YubabaNodeId, now: u64) -> Option<NodeCapacity> {
        let capacity = self.members.get(&node)?.capacity?;
        let load = self.node_load(node, now);
        Some(NodeCapacity {
            memory_mb: capacity.memory_mb.saturating_sub(load.memory_mb),
            cpu_millis: capacity.cpu_millis.saturating_sub(load.cpu_millis),
        })
    }

    /// Whether `node` has room for `demand` at `now` — the capacity-floor
    /// predicate, stated once so F3's scheduler and T4's headroom accounting ask
    /// the same question rather than each re-deriving it.
    ///
    /// The same floor `CloudConfig::admit_workload` applies one layer down, on
    /// the same units, with the same reading of `0` as "unconstrained on that
    /// axis". A node with no published capacity is refused (`false`), not
    /// admitted.
    pub fn node_admits(&self, node: YubabaNodeId, demand: &TenantDemand, now: u64) -> bool {
        let Some(headroom) = self.node_headroom(node, now) else {
            return false;
        };
        demand.memory_mb <= headroom.memory_mb && demand.cpu_millis <= headroom.cpu_millis
    }
}

/// Which node owns a tenant's write path, and the monotonic epoch that makes
/// that ownership *enforceable* (R732-F1 / W245).
///
/// **The lease is a liveness hint; the epoch is the safety property.** These do
/// different jobs and conflating them is the classic way to build a
/// split-brain:
///
/// - `lease_expires` bounds when a takeover is *permitted*. It is a
///   caller-stamped unix-seconds deadline, so it inherits the NTP assumption
///   [`YubabaRequest::AcquireLock`] documents — but with a much weaker
///   consequence. A node whose clock runs fast declares the lease dead early
///   and takes over sooner than it should; that costs *availability* for the
///   displaced owner, never correctness, because the takeover advances the
///   epoch and the displaced owner's writes stop being accepted. Skew cannot
///   produce two accepted writers.
/// - `epoch` is what the R2 write path actually checks (R732-F2). It only ever
///   moves forward, only via a committed raft entry, and a writer holding a
///   lower epoch than the one recorded on the object store is *rejected* — not
///   merely unlikely to collide. That is the whole point of W245: "stale
///   routing must be safe, not impossible."
///
/// **The epoch must never regress, including across a vacancy.** There is
/// deliberately no way to delete a tenant's record: a lease that expires leaves
/// the record in place with `owner` naming the last owner and the epoch
/// retained, and the next claim resumes from there. Dropping the record on
/// expiry and letting a fresh claim restart at 1 would let a zombie still
/// holding epoch 5 outrank a legitimate new owner — the exact corruption the
/// epoch exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantOwnership {
    /// The node that most recently held this tenant. Meaningful only together
    /// with `lease_expires` — see [`TenantOwnership::is_live`].
    pub owner: YubabaNodeId,
    /// Monotonic fencing token. Advanced by exactly one on every committed
    /// claim or transfer, never by a renewal, and never decreased.
    pub epoch: u64,
    /// Unix-seconds deadline after which another node may claim the tenant.
    /// Expiry alone fences nobody — it only *permits* a takeover, and the
    /// takeover's epoch bump is what does the fencing.
    pub lease_expires: u64,
}

impl TenantOwnership {
    /// Whether the lease is still valid at `now` (caller-stamped unix seconds).
    pub fn is_live(&self, now: u64) -> bool {
        now < self.lease_expires
    }
}

/// Where a tenant *should* live — declared intent, R737-F1 (W246 §"State").
///
/// **This is not ownership.** [`TenantOwnership`] says who holds the write path
/// right now and under which epoch; this says what the scheduler is trying to
/// make true. Keeping them apart is the structural call the rest of R737 rests
/// on, and the reason is that they answer questions with different lifetimes:
/// ownership changes on every failover, intent changes only when an operator (or
/// a tenant-lifecycle path) changes it. Folding them into one record would mean
/// a failover rewrites the declaration it is supposed to be reconciling toward,
/// and "did the scheduler place this correctly?" would have no fixed thing to
/// compare against.
///
/// A tenant may have intent with no ownership (declared, never placed — the
/// scheduler's work queue), ownership with no intent (placed by hand, or intent
/// cleared under a live owner), or both. All three are legal states and the
/// scheduler must read them as such.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantPlacement {
    /// Home region, in the **same label space** as [`MemberInfo::region`] —
    /// `.yah/infra/machines/<name>.toml`'s `region`, not a second taxonomy.
    ///
    /// `None` means unconstrained: the scheduler may place this tenant on any
    /// node with room. That is deliberately *not* the same as "no preference
    /// recorded yet" — there is no third state, because a tri-state would make
    /// every consumer decide what an absent preference means and they would not
    /// all decide the same thing.
    #[serde(default)]
    pub region: Option<String>,
    /// How the tenant expects to come back up elsewhere, which is what decides
    /// whether a candidate node is *eligible* rather than merely roomy.
    ///
    /// `#[serde(default)]` lands an absent tier on [`SlaTier::ColdHydrate`]
    /// rather than failing the entry. The alternative — a hard parse error —
    /// would stall the state machine at that log index for a field whose safe
    /// value is known, and the safe value is exactly what the default is chosen
    /// to be.
    #[serde(default)]
    pub tier: SlaTier,
    /// The resource request this tenant is placed against — the number the
    /// scheduler subtracts from a node's [`MemberInfo::capacity`].
    #[serde(default)]
    pub demand: TenantDemand,
    /// R782 (W253 §7): the bound a candidate's streamer must stay caught up
    /// within to be considered ready to own this tenant — the tenant-relative
    /// half of [`crate::lease_detector::ReadinessInputs::streamer_rpo_bound`].
    ///
    /// `#[serde(default)]` lands an absent bound on `None`, which
    /// [`crate::lease_detector::judge_readiness`] already documents as
    /// "no target configured, gate vacuously satisfied" — so an old log entry
    /// (or an old node that never wrote this field) means exactly what it
    /// meant before this field existed. A plain new `Option` field, not a new
    /// enum variant: see the R720-F1 / R734-F2 precedent this ticket's
    /// cluster-epochs.json history entry cites for why that discriminator
    /// makes this a tolerated (non-breaking) addition on both axes.
    #[serde(default)]
    pub rpo_bound: Option<Duration>,
}

/// What a tenant needs to be considered *back up* after a move — R737-F1,
/// W248's warm-vs-cold axis expressed as placement input.
///
/// The scheduler reads this to decide eligibility, not just fit: a
/// [`SlaTier::WarmReplica`] tenant may only be re-placed onto a node that is
/// already streaming it, because the whole point of the tier is that failover
/// costs no hydrate. A [`SlaTier::ColdHydrate`] tenant may go anywhere with
/// room and pays a restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaTier {
    /// Restore from R2 on takeover. Cheap to keep, slow to fail over.
    ///
    /// The default, and deliberately the *pessimistic* one: a tenant whose tier
    /// was never declared must not be treated as having a warm replica
    /// somewhere, because that would let the scheduler pick a node on a promise
    /// nothing kept.
    #[default]
    ColdHydrate,
    /// A replica is kept streaming on at least one other node, so takeover is a
    /// promotion rather than a restore.
    WarmReplica,
}

/// A tenant's resource **request**, in the units every other capacity surface in
/// this system already uses: MiB and k8s millicores.
///
/// `0` on either axis means *unconstrained on that axis*, matching
/// [`ResourceSelector`](cloud::config::ResourceSelector)'s convention rather
/// than inventing a second reading of zero.
///
/// # Why this is a new type and not one of the three that look identical
///
/// It is the same shape as `node::WorkloadResources`,
/// `cloud::config::NodeAllocatable` and `workload_spec::ResourceLimits`, and
/// picking any of them would have been wrong for a different reason:
///
/// - `workload_spec::ResourceLimits::memory_mb` is a **ceiling**, not a
///   request — its own doc tells schedulers to read `memory_request_mb`
///   instead. Reusing it here would import exactly the confusion R572-F5 wrote
///   that warning to prevent.
/// - `node::WorkloadResources` is the right *semantics* (an admitted request)
///   but lives on the `/node/usage` HTTP surface, which versions on
///   `NODE_SCHEMA_VERSION`. This type versions on the raft `state_epoch`. One
///   type under two independent compatibility regimes is a trap that only
///   springs the day the two need to move apart.
/// - `NodeAllocatable` is the *budget* side, not the demand side.
///
/// What it must not become is a fourth set of *units*. MiB and millicores are
/// the whole contract, and they are the same ones `CloudConfig::admit_workload`
/// bin-packs against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantDemand {
    /// Requested RAM in MiB.
    pub memory_mb: u32,
    /// Requested CPU in k8s millicores (`1000` = one core).
    pub cpu_millis: u32,
}

/// A node's schedulable budget, replicated so the leader can bin-pack against it
/// (R737-F1).
///
/// The replicated mirror of `[allocatable]` in `.yah/infra/machines/<name>.toml`
/// — same field names, same units, deliberately the same label space as
/// [`MemberInfo::region`] mirrors `MachineConfig::region`. It is *derived*, not
/// re-declared: each node publishes what it measures (`yah.allocatable.memory_mb`
/// / `.cpu_millis` on `GET /node/specs`) through its own member row, exactly as
/// it publishes its region.
///
/// Measured rather than read back from the TOML on purpose. The declaration is
/// an operator's intent about a box; this is what the box turned out to be, and
/// the scheduler must not place a tenant onto RAM that only exists in a config
/// file. Where they disagree, `node.rs` already documents which direction is
/// legitimate: a declaration *below* the measurement is a real constraint (a VM
/// ceiling), a declaration *above* it is over-promising.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapacity {
    /// Schedulable RAM in MiB.
    pub memory_mb: u32,
    /// Schedulable CPU in k8s millicores.
    pub cpu_millis: u32,
}

/// What a node is currently carrying, **derived** from replicated state rather
/// than reported by the node (R737-F1).
///
/// # Why load is derived and `capacity` is not
///
/// This is the one asymmetry in the model worth understanding before changing
/// it. Capacity is a fact about hardware: it changes when someone resizes a box,
/// so a convergent self-published row is exactly right for it. Load changes
/// every time the scheduler commits a decision — and the scheduler is the thing
/// reading it.
///
/// A replicated, node-reported load field would therefore be wrong in the one
/// moment it matters. Within a single scheduling tick the leader places tenant A
/// on node N; node N cannot have noticed, published a new row, and had it commit
/// before the leader evaluates tenant B. So B is placed against N's pre-A load
/// and the node is overcommitted by exactly the amount the scheduler was trying
/// to account for. Deriving the number from the same `tenants` + `placement`
/// maps the scheduler is mutating closes that race by construction: the load
/// reflects decision *k* before decision *k+1* is taken, with no propagation
/// delay to lose.
///
/// The secondary reason is log hygiene. R734-F5 measured what a
/// frequently-changing value costs in this exact loop — a member-registration
/// pass that woke on every metrics republish measurably slowed the machine, and
/// the fix was to make it converge and go quiet. A load field would re-introduce
/// that, permanently and by design, and W246 §"Failure detector" is explicit
/// that renewals must stay off the log.
///
/// **What this deliberately does not count:** non-tenant workloads. A node also
/// runs containers and static bundles whose requests live in
/// `node::committed_totals`, and those are invisible here. That is honest rather
/// than complete — the scheduler this feeds places tenants, and a tenant-only
/// number is the one it can reason about transactionally. Closing the gap needs
/// the node's committed total to be replicated too, which reintroduces the race
/// above for a quantity that changes at deploy rate; T4's headroom accounting is
/// where that trade should be decided, with the N+1 invariant to judge it
/// against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLoad {
    /// How many tenants this node currently owns with a live lease.
    pub tenants: u32,
    /// Summed [`TenantDemand::memory_mb`] of those tenants.
    pub memory_mb: u32,
    /// Summed [`TenantDemand::cpu_millis`] of those tenants.
    pub cpu_millis: u32,
}

/// Minimal rollout metadata stored in raft state (R278-F3).
///
/// Contains only what's needed for leader-resume after a raft leader change.
/// The full `RolloutRecord` (including the policy and trigger) lives in the
/// in-process `RolloutStore`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutRaftRecord {
    pub rollout_id: String,
    pub artifact: String,
    /// JSON-serialised `RolloutStatus` (avoids a cross-crate dep on yubaba's
    /// rollout module from the raft module).
    pub status_json: String,
    pub current_step: usize,
    pub started_at: u64,
}

/// A cluster secret as stored in raft state (R600-F1 / W273).
///
/// Holds AES-256-GCM **ciphertext only** — never plaintext. The state machine
/// snapshot is serialised as plain JSON to every node's disk
/// (`YubabaStateMachine`'s `serde_json::to_string(&self.data)`), so plaintext
/// secret material must never reach this struct. Encryption and decryption
/// happen *outside* the raft layer with a node-local cluster KEK (issuer:
/// R600-F3 seals; resolver: R600-F2 opens); the state machine only ever moves
/// opaque bytes and cannot itself read a secret's contents.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecord {
    /// AES-256-GCM output: the sealed bytes with the GCM tag appended.
    pub ciphertext: Vec<u8>,
    /// The 12-byte GCM nonce `ciphertext` was sealed under.
    pub nonce: Vec<u8>,
    /// Caller-stamped unix seconds of the last write. Lets a consumer detect
    /// rotation (R600-F4) and aids debugging; not security-sensitive.
    pub updated_at: u64,

    /// R706 (W294): which workloads may be served this secret.
    ///
    /// The rule lives **on the record** rather than in the camp's config so the
    /// check happens where the plaintext is produced — `secrets::ClusterResolver`
    /// on the node at mount time. A rule the deploying CLI checks is a lint that
    /// a hand-rolled `POST /workloads/deploy` walks straight past; a rule the
    /// resolver checks cannot be walked past without the KEK.
    ///
    /// `#[serde(default)]` lands pre-R706 snapshots on
    /// [`SecretAccess::default`] — the empty allow-list, which admits nobody. An
    /// unruled legacy secret is therefore **refused**, not granted; the operator
    /// re-stamps it with `yah cloud secret rule`.
    #[serde(default)]
    pub access: SecretAccess,

    /// R720-F1 (W294): keyed digest of the plaintext this record's ciphertext
    /// was sealed from — HMAC-SHA256 under a subkey HKDF-derived from the
    /// cluster KEK (domain-separated from the AES-GCM sealing key), computed
    /// camp-side before sealing since the state machine never sees plaintext.
    ///
    /// **Not "in sync" when `None`** — that means "written before this field
    /// existed", not "matches". `#[serde(default)]` lands pre-digest snapshots
    /// there so they deserialize instead of failing, same forward-compat
    /// contract as `access`. Treating `None` as a match would readmit the
    /// confident-lie failure this field exists to remove.
    ///
    /// Keyed rather than a bare `SHA-256(plaintext)`: `GET /secrets` serves
    /// this, and a bare hash of a low-entropy secret would be a brute-force
    /// oracle for anyone without the KEK. The camp already holds the KEK, so a
    /// keyed digest costs nothing extra.
    #[serde(default)]
    pub digest: Option<Vec<u8>>,
}

// Redact the opaque bytes from Debug (which `YubabaState`/snapshot dumps and any
// TRACE-level raft logging would otherwise print). The ciphertext isn't directly
// sensitive — decrypting still needs the node KEK — but keeping it out of log
// archives avoids leaking rotation size/timing and denying a future
// KEK-compromise a ready-made decrypt corpus. Only the byte lengths + timestamp
// surface. (YubabaRequest::PutSecret carries the same bytes inline and derives
// Debug; redacting that too is a follow-up cleanup — lower value than this,
// since state snapshots are the more likely log surface.)
impl std::fmt::Debug for SecretRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRecord")
            .field(
                "ciphertext",
                &format_args!("<{} bytes>", self.ciphertext.len()),
            )
            .field("nonce", &format_args!("<{} bytes>", self.nonce.len()))
            .field("updated_at", &self.updated_at)
            // The rule is not sensitive — it names workloads, not key material —
            // and seeing it in a state dump is exactly what you want when
            // debugging a refused mount.
            .field("access", &format_args!("{}", self.access.summary()))
            .field(
                "digest",
                &format_args!(
                    "{}",
                    match &self.digest {
                        Some(d) => format!("<{} bytes>", d.len()),
                        None => "None (pre-digest)".to_string(),
                    }
                ),
            )
            .finish()
    }
}

/// The yubaba-side annotation on a raft member — what openraft's
/// `BasicNode { addr }` has no room to carry.
///
/// Raft membership remains the authority on *who is in the cluster*; this map
/// says what the cluster knows *about* those nodes. Each node writes its own row
/// ([`member_registration`](crate::member_registration), R734-F5), because a
/// node knows only its own region — nobody is in a position to write anyone
/// else's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    /// Tailscale mesh IP:port (e.g. `100.64.0.1:7443`).
    pub addr: String,
    /// R734-F2 (W247 §2): the node's geo region — the latency/failure axis the
    /// quorum-geography rule is judged on, e.g. `"us-west"`.
    ///
    /// Deliberately the *same* label space as
    /// [`MachineConfig::region`](cloud::config::MachineConfig::region), read
    /// from `.yah/infra/machines/<name>.toml`, rather than a second taxonomy:
    /// a node whose machine file says `region = "us-east"` and whose raft row
    /// says something else is a bug that no test would catch, so there is only
    /// one spelling to get right. Note `region` is the geo axis specifically —
    /// `zone` is the failure domain *within* a region and `location` is the
    /// provider's own DC code; quorum geography is about surviving the loss of
    /// a whole region, so this is the axis it reads.
    ///
    /// `Option` because it is `#[serde(default)]` for snapshot compatibility
    /// and because a rig's voters legitimately have no region to declare
    /// ([`QuorumGeography::SingleFailureDomain`](crate::cluster_policy::QuorumGeography::SingleFailureDomain)).
    /// Under the fleet policy an untagged founding voter is refused outright.
    #[serde(default)]
    pub region: Option<String>,

    /// R737-F1 (W246): what this node can be scheduled onto — see
    /// [`NodeCapacity`], and [`NodeLoad`] for why the *other* half of the
    /// bin-packing input is derived rather than declared here.
    ///
    /// `None` means **unknown**, never "unlimited" and never "zero". A node that
    /// has not published capacity is one the scheduler must not place onto:
    /// during a roll an un-upgraded node is in membership with no capacity, and
    /// reading that as unconstrained would send every tenant to the one box that
    /// cannot say no. Same degradation shape as R734-F5's region residual — it
    /// degrades toward the pre-F1 behaviour (nothing schedules) and never below
    /// it.
    #[serde(default)]
    pub capacity: Option<NodeCapacity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEntry {
    pub owner: String,
    pub acquired_at: u64,
    pub ttl_secs: u64,
}

/// Apply a [`YubabaRequest`] to `state`.  Pure function — all I/O is the
/// caller's responsibility.
pub fn apply(state: &mut YubabaState, req: &YubabaRequest) -> YubabaResponse {
    match req {
        YubabaRequest::SetMember {
            node_id,
            addr,
            region,
            capacity,
        } => {
            state.members.insert(
                *node_id,
                MemberInfo {
                    addr: addr.clone(),
                    region: region.clone(),
                    capacity: *capacity,
                },
            );
            YubabaResponse::Ok
        }
        YubabaRequest::RemoveMember { node_id } => {
            state.members.remove(node_id);
            YubabaResponse::Ok
        }
        YubabaRequest::SetServicePlacement { service, machine } => {
            state
                .service_placement
                .insert(service.clone(), machine.clone());
            YubabaResponse::Ok
        }
        YubabaRequest::ClearServicePlacement { service } => {
            state.service_placement.remove(service);
            YubabaResponse::Ok
        }
        YubabaRequest::AcquireLock {
            key,
            owner,
            ttl_secs,
            acquired_at,
        } => {
            let now = *acquired_at;
            let grant = match state.locks.get(key) {
                None => true,
                Some(entry) => {
                    entry.owner == *owner || now.saturating_sub(entry.acquired_at) >= entry.ttl_secs
                }
            };
            if grant {
                state.locks.insert(
                    key.clone(),
                    LockEntry {
                        owner: owner.clone(),
                        acquired_at: *acquired_at,
                        ttl_secs: *ttl_secs,
                    },
                );
            }
            YubabaResponse::LockGranted(grant)
        }
        YubabaRequest::ReleaseLock { key, owner } => {
            if state.locks.get(key).map(|e| e.owner.as_str()) == Some(owner.as_str()) {
                state.locks.remove(key);
            }
            YubabaResponse::Ok
        }
        YubabaRequest::SetIngressOwner { machine } => {
            state.ingress_owner = Some(machine.clone());
            YubabaResponse::Ok
        }
        YubabaRequest::ClearIngressOwner => {
            state.ingress_owner = None;
            YubabaResponse::Ok
        }
        YubabaRequest::SetRolloutState {
            rollout_id,
            artifact,
            status_json,
            current_step,
            started_at,
        } => {
            state.rollouts.insert(
                rollout_id.clone(),
                RolloutRaftRecord {
                    rollout_id: rollout_id.clone(),
                    artifact: artifact.clone(),
                    status_json: status_json.clone(),
                    current_step: *current_step,
                    started_at: *started_at,
                },
            );
            YubabaResponse::Ok
        }
        YubabaRequest::ClearRolloutState { rollout_id } => {
            state.rollouts.remove(rollout_id);
            YubabaResponse::Ok
        }
        YubabaRequest::PutSecret {
            name,
            ciphertext,
            nonce,
            updated_at,
            access,
            digest,
        } => {
            // Opaque bytes in, opaque bytes stored — this layer never decrypts.
            // The access rule and digest are stored verbatim alongside them;
            // the raft layer does not evaluate the rule (that's
            // `secrets::ClusterResolver`'s job, at mount time) and cannot
            // itself compute the digest (that needs the KEK, which never
            // reaches this layer).
            state.secrets.insert(
                name.clone(),
                SecretRecord {
                    ciphertext: ciphertext.clone(),
                    nonce: nonce.clone(),
                    updated_at: *updated_at,
                    access: access.clone(),
                    digest: digest.clone(),
                },
            );
            YubabaResponse::Ok
        }
        YubabaRequest::DeleteSecret { name } => {
            state.secrets.remove(name);
            YubabaResponse::Ok
        }

        // ── R732-F1 (W245): tenant ownership + fencing epochs ──────────────
        YubabaRequest::ClaimTenant {
            tenant,
            node,
            lease_secs,
            now,
        } => {
            let current = state.tenants.get(tenant).cloned();
            match &current {
                // Another node holds a live lease: the claimant is not the
                // owner and must not write. Hand it the truth so it can stop.
                Some(rec) if rec.owner != *node && rec.is_live(*now) => {
                    YubabaResponse::Tenant(TenantOutcome::Fenced {
                        current_epoch: rec.epoch,
                        current_owner: Some(rec.owner),
                    })
                }
                // Vacant, expired, or a self-reclaim after restart. All three
                // advance the epoch — see `ClaimTenant`'s docs for why the
                // self-reclaim case must too. `map_or(0, ..)` makes "no record"
                // epoch 0, so a first claim lands on 1 and 0 is never a valid
                // token.
                _ => {
                    let epoch = current.as_ref().map_or(0, |rec| rec.epoch) + 1;
                    state.tenants.insert(
                        tenant.clone(),
                        TenantOwnership {
                            owner: *node,
                            epoch,
                            lease_expires: now.saturating_add(*lease_secs),
                        },
                    );
                    YubabaResponse::Tenant(TenantOutcome::Granted { epoch })
                }
            }
        }
        YubabaRequest::TransferTenant {
            tenant,
            to,
            from_epoch,
            lease_secs,
            now,
        } => {
            let current = state.tenants.get(tenant);
            let current_epoch = current.map_or(0, |rec| rec.epoch);
            let current_owner = current.map(|rec| rec.owner);

            if current_epoch == from_epoch.saturating_add(1) && current_owner == Some(*to) {
                // Exactly this transfer's post-state. A client that lost its
                // response to a mid-decision leader failover is retrying and
                // observing its own effect: report the same success and mutate
                // nothing, so the retry is a true no-op rather than a second
                // advance. No *other* request can produce this state — reaching
                // it requires `TransferTenant { to, from_epoch }` itself.
                return YubabaResponse::Tenant(TenantOutcome::Granted {
                    epoch: current_epoch,
                });
            }
            if current_epoch != *from_epoch {
                return YubabaResponse::Tenant(TenantOutcome::Fenced {
                    current_epoch,
                    current_owner,
                });
            }
            // CAS held. Note there is no liveness check on the outgoing owner:
            // transferring a healthy tenant is ordinary, and the epoch is what
            // makes it safe while the old owner is still running.
            let epoch = current_epoch + 1;
            state.tenants.insert(
                tenant.clone(),
                TenantOwnership {
                    owner: *to,
                    epoch,
                    lease_expires: now.saturating_add(*lease_secs),
                },
            );
            YubabaResponse::Tenant(TenantOutcome::Granted { epoch })
        }
        YubabaRequest::RenewTenantLease {
            tenant,
            node,
            epoch,
            lease_secs,
            now,
        } => match state.tenants.get_mut(tenant) {
            Some(rec) if rec.owner == *node && rec.epoch == *epoch => {
                // `max` keeps the deadline monotonic: a delayed or reordered
                // renewal carrying an older `now` must not retract a lease that
                // a later one already extended.
                rec.lease_expires = rec.lease_expires.max(now.saturating_add(*lease_secs));
                YubabaResponse::Tenant(TenantOutcome::Granted { epoch: rec.epoch })
            }
            // Wrong owner, stale token, or no record: renewing is refused
            // rather than upgraded into a claim. A node that has been fenced
            // must find out here, not keep a lease alive under a token the
            // write path will reject.
            current => YubabaResponse::Tenant(TenantOutcome::Fenced {
                current_epoch: current.as_ref().map_or(0, |rec| rec.epoch),
                current_owner: current.map(|rec| rec.owner),
            }),
        },

        // ── R737-F1 (W246): declared placement intent ──────────────────────
        // Both answer `Ok`, not `Tenant(..)`. There is no fencing token to hand
        // back because nothing here can be refused: the ownership variants above
        // answer with an outcome precisely because a caller may have lost a race
        // it needs to be told about, and a declaration races nobody.
        YubabaRequest::SetTenantPlacement { tenant, placement } => {
            state.placement.insert(tenant.clone(), placement.clone());
            YubabaResponse::Ok
        }
        YubabaRequest::ClearTenantPlacement { tenant } => {
            state.placement.remove(tenant);
            YubabaResponse::Ok
        }
    }
}

// ── Node factory ──────────────────────────────────────────────────────────────

/// Open (or create) a yubaba raft node.
///
/// `node_id`  — this machine's unique yubaba node ID (u64, assigned at provision time).
/// `raft_dir` — directory for raft persistence files (`raft_vote.json`, `raft_log.json`,
///              `raft_state.json`, `raft_meta.json`). **All four are one unit**: wiping a
///              node's raft state means removing every one of them. `raft_meta.json` carries
///              the purge marker (R841-B1), so leaving it behind while deleting the other
///              three hands the fresh node a marker over an empty log —
///              [`YubabaLogStore::open`](store) detects and drops that case, but the
///              instruction to give an operator is still "delete all four".
/// `policy`   — the cluster policy this node runs under; its
///              [`RaftTiming`](crate::cluster_policy::RaftTiming) sets the
///              election and heartbeat timers.
pub async fn open(
    node_id: YubabaNodeId,
    raft_dir: PathBuf,
    policy: &ClusterPolicy,
) -> anyhow::Result<YubabaRaft> {
    Ok(open_with_state_machine(node_id, raft_dir, policy).await?.0)
}

/// Like [`open`], but also hands back a clone of the [`YubabaStateMachine`] so
/// the caller can read applied cluster state directly (linearizable-free local
/// reads). The daemon uses this for the R600-F3 ACME issuer, which reads the
/// stored cert's age to decide renewal, and for the `SecretRef::Cluster`
/// resolver (R600-F2), which reads replicated ciphertext. The state machine is
/// `Clone` (an inner `Arc<RwLock<…>>`), so this handle and the one inside the
/// `Raft` observe the same state.
pub async fn open_with_state_machine(
    node_id: YubabaNodeId,
    raft_dir: PathBuf,
    policy: &ClusterPolicy,
) -> anyhow::Result<(YubabaRaft, YubabaStateMachine)> {
    std::fs::create_dir_all(&raft_dir)?;

    // Timings come from the cluster policy (R118-T9): a cross-region fleet and a
    // single-LAN installation want very different election timeouts, and which
    // one this node is running under is a deployment fact, not a constant.
    let config = Arc::new(policy.timing.to_openraft_config()?);

    let log_store = YubabaLogStore::open(raft_dir.clone()).await?;
    let state_machine = YubabaStateMachine::open(raft_dir).await?;
    let network = YubabaNetworkFactory;

    let raft = YubabaRaft::new(node_id, config, network, log_store, state_machine.clone()).await?;
    Ok((raft, state_machine))
}

/// Auto-initialise this node as a **cluster-of-one** — the W197 §"Single-node
/// raft" / A032 §"cluster-mesh-1" bootstrap path (R482-T3).
///
/// A freshly-booted BYO-VPS yubaba forms its own one-voter raft cluster with no
/// operator `raft init` call and no peers. Single-node raft is degenerate but
/// fully functional (A032: "single-node raft is degenerate but works") — the
/// node writes the founding membership log entry and self-elects as leader
/// within one election timeout. No [`YubabaNetwork`] RPC is ever issued (there
/// are no peers to reach), so this is independent of the raft/mesh transport
/// parked under R593-T7.
///
/// **Idempotent.** Re-running on a node that already has vote/log state — a
/// restart, or a node that previously founded or joined a cluster — is a no-op:
/// `initialize` returns [`InitializeError::NotAllowed`] once the node is
/// bootstrapped, which is mapped to `Ok(false)`. Safe to call unconditionally
/// at every startup. Returns `true` when this call performed the init, `false`
/// when the node was already initialised.
///
/// `addr` is recorded as this node's membership address. For a cluster-of-one
/// it is self-referential and never dialed (raft is not in the data path with
/// no peers), so any stable self-address works; a later multi-machine join
/// (yubaba's join-by-NodeId flow) supplies real peer addresses.
///
/// Do **not** combine this with the multi-node founding flow (`raft init
/// --member …`): a node that self-inits is its own cluster and cannot later
/// merge with a separately-founded one — fleet growth is join-by-NodeId onto an
/// existing single-node cluster, per W197 §"Single-node raft".
pub async fn bootstrap_single_node(
    raft: &YubabaRaft,
    node_id: YubabaNodeId,
    addr: impl Into<String>,
) -> anyhow::Result<bool> {
    let mut members = BTreeMap::new();
    members.insert(node_id, BasicNode { addr: addr.into() });
    match raft.initialize(members).await {
        Ok(()) => Ok(true),
        // NotAllowed = this node already has vote/log state, i.e. it is (or was)
        // bootstrapped — idempotent no-op, same mapping as the POST
        // /raft/initialize handler.
        Err(openraft::error::RaftError::APIError(
            openraft::error::InitializeError::NotAllowed(_),
        )) => Ok(false),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_set_member() {
        let mut state = YubabaState::default();
        apply(
            &mut state,
            &YubabaRequest::SetMember {
                node_id: 1,
                addr: "100.64.0.1:7443".into(),
                region: Some("us-west".into()),
                capacity: Some(NodeCapacity {
                    memory_mb: 16384,
                    cpu_millis: 8000,
                }),
            },
        );
        assert_eq!(
            state.members.get(&1).and_then(|m| m.region.as_deref()),
            Some("us-west"),
            "R734-F2: the region tag must survive apply, or the quorum-geography rule has \
             nothing to judge later membership changes against"
        );
        assert_eq!(
            state.members.get(&1).and_then(|m| m.capacity),
            Some(NodeCapacity {
                memory_mb: 16384,
                cpu_millis: 8000
            }),
            "R737-F1: capacity must survive apply, or the scheduler has nothing to bin-pack \
             against"
        );
    }

    /// R734-F2 wire compatibility: a pre-R734-F2 node's replicated `SetMember`
    /// has no `region` key at all. It must still apply — landing as `None` —
    /// rather than failing to parse, which would stall the state machine at
    /// that log index. This is the property that makes the change a
    /// `cluster_protocol` re-record rather than a bump, so it is pinned rather
    /// than argued from serde's documented behaviour.
    #[test]
    fn a_pre_r734_f2_set_member_still_applies_with_no_region() {
        let legacy = serde_json::json!({
            "SetMember": { "node_id": 2, "addr": "100.64.0.2:7443" }
        });
        let req: YubabaRequest =
            serde_json::from_value(legacy).expect("a region-less SetMember must still parse");

        let mut state = YubabaState::default();
        apply(&mut state, &req);

        let member = state.members.get(&2).expect("member applied");
        assert_eq!(member.addr, "100.64.0.2:7443");
        assert_eq!(
            member.region, None,
            "an untagged legacy member must read as untagged, not as some invented default"
        );
        assert_eq!(
            member.capacity, None,
            "R737-F1: same contract for capacity — a legacy member reads as capacity-UNKNOWN, \
             which node_headroom refuses to schedule onto, rather than as an unlimited box"
        );
    }

    #[test]
    fn apply_lock_grant_and_release() {
        let mut state = YubabaState::default();
        let resp = apply(
            &mut state,
            &YubabaRequest::AcquireLock {
                key: "provision:foo".into(),
                owner: "node-1".into(),
                ttl_secs: 60,
                acquired_at: 1000,
            },
        );
        assert!(matches!(resp, YubabaResponse::LockGranted(true)));

        // Second acquire by different owner before TTL should fail.
        let resp2 = apply(
            &mut state,
            &YubabaRequest::AcquireLock {
                key: "provision:foo".into(),
                owner: "node-2".into(),
                ttl_secs: 60,
                acquired_at: 1010,
            },
        );
        assert!(matches!(resp2, YubabaResponse::LockGranted(false)));

        // Expired: now = acquired_at + ttl_secs → grant.
        let resp3 = apply(
            &mut state,
            &YubabaRequest::AcquireLock {
                key: "provision:foo".into(),
                owner: "node-2".into(),
                ttl_secs: 60,
                acquired_at: 1060,
            },
        );
        assert!(matches!(resp3, YubabaResponse::LockGranted(true)));
    }

    #[test]
    fn apply_ingress_owner() {
        let mut state = YubabaState::default();
        assert!(state.ingress_owner.is_none());
        apply(
            &mut state,
            &YubabaRequest::SetIngressOwner {
                machine: "htz-pdx-1".into(),
            },
        );
        assert_eq!(state.ingress_owner.as_deref(), Some("htz-pdx-1"));
        apply(&mut state, &YubabaRequest::ClearIngressOwner);
        assert!(state.ingress_owner.is_none());
    }

    #[test]
    fn apply_put_overwrite_and_delete_secret() {
        let mut state = YubabaState::default();
        apply(
            &mut state,
            &YubabaRequest::PutSecret {
                name: "tls/yah.dev".into(),
                ciphertext: vec![1, 2, 3, 4],
                nonce: vec![9; 12],
                updated_at: 1000,
                access: SecretAccess::workloads(["ingress"]),
                digest: Some(vec![0xaa; 32]),
            },
        );
        let rec = state.secrets.get("tls/yah.dev").expect("secret stored");
        assert_eq!(rec.ciphertext, vec![1, 2, 3, 4]);
        assert_eq!(rec.nonce, vec![9; 12]);
        assert_eq!(rec.updated_at, 1000);
        assert_eq!(rec.digest, Some(vec![0xaa; 32]));

        // A second PutSecret for the same name overwrites in place (rotation).
        apply(
            &mut state,
            &YubabaRequest::PutSecret {
                name: "tls/yah.dev".into(),
                ciphertext: vec![5, 6],
                nonce: vec![7; 12],
                updated_at: 2000,
                access: SecretAccess::workloads(["ingress"]),
                digest: Some(vec![0xbb; 32]),
            },
        );
        let rec = state.secrets.get("tls/yah.dev").unwrap();
        assert_eq!(rec.ciphertext, vec![5, 6]);
        assert_eq!(rec.updated_at, 2000);
        assert_eq!(
            rec.digest,
            Some(vec![0xbb; 32]),
            "overwrite replaces digest too"
        );
        assert_eq!(state.secrets.len(), 1, "overwrite, not append");

        // Delete removes it; deleting a missing key is a no-op, never a panic.
        apply(
            &mut state,
            &YubabaRequest::DeleteSecret {
                name: "tls/yah.dev".into(),
            },
        );
        assert!(!state.secrets.contains_key("tls/yah.dev"));
        apply(
            &mut state,
            &YubabaRequest::DeleteSecret {
                name: "tls/yah.dev".into(),
            },
        );
        assert!(state.secrets.is_empty());
    }

    #[test]
    fn secrets_survive_snapshot_round_trip() {
        // The snapshot path is serde_json over YubabaState (see store.rs) — the
        // secrets map must serialise and restore byte-identically.
        let mut state = YubabaState::default();
        apply(
            &mut state,
            &YubabaRequest::PutSecret {
                name: "tls/yah.dev".into(),
                ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
                nonce: vec![1; 12],
                updated_at: 42,
                access: SecretAccess::workloads(["ingress"]),
                digest: Some(vec![0xcc; 32]),
            },
        );
        let json = serde_json::to_string(&state).unwrap();
        let restored: YubabaState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.secrets, state.secrets);
    }

    #[test]
    fn digest_round_trips_through_the_state_machine() {
        // R720-F1: a record with a digest survives apply + snapshot round-trip
        // byte-identically — the drift check downstream depends on this.
        let mut state = YubabaState::default();
        apply(
            &mut state,
            &YubabaRequest::PutSecret {
                name: "tls/yah.dev".into(),
                ciphertext: vec![1, 2, 3],
                nonce: vec![4; 12],
                updated_at: 500,
                access: SecretAccess::workloads(["ingress"]),
                digest: Some(vec![0x42; 32]),
            },
        );
        let rec = state.secrets.get("tls/yah.dev").unwrap();
        assert_eq!(rec.digest, Some(vec![0x42; 32]));

        let json = serde_json::to_string(&state).unwrap();
        let restored: YubabaState = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.secrets.get("tls/yah.dev").unwrap().digest,
            Some(vec![0x42; 32])
        );
    }

    #[test]
    fn pre_digest_secret_record_deserializes_to_none() {
        // A SecretRecord serialised before R720-F1 has no `digest` key.
        // `#[serde(default)]` must land it on `None` — meaning "predates
        // digests", never to be read as "matches" by a downstream comparison.
        let legacy = r#"{
            "ciphertext": [1, 2, 3],
            "nonce": [4, 4, 4],
            "updated_at": 7,
            "access": "allow_any"
        }"#;
        let rec: SecretRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(rec.digest, None);
    }

    // ── R732-F1: tenant ownership + fencing epochs ────────────────────────
    //
    // These are the correctness core of W245. Each one names the split-brain
    // scenario it rules out, because the assertion alone doesn't say why the
    // number matters.

    fn tenant(name: &str) -> TenantId {
        TenantId(name.to_string())
    }

    /// Unwrap a tenant outcome, failing loudly on any other response shape.
    fn outcome(resp: YubabaResponse) -> TenantOutcome {
        match resp {
            YubabaResponse::Tenant(o) => o,
            other => panic!("expected a tenant outcome, got {other:?}"),
        }
    }

    fn claim(state: &mut YubabaState, t: &str, node: YubabaNodeId, now: u64) -> TenantOutcome {
        outcome(apply(
            state,
            &YubabaRequest::ClaimTenant {
                tenant: tenant(t),
                node,
                lease_secs: 30,
                now,
            },
        ))
    }

    #[test]
    fn first_claim_lands_on_epoch_one_so_zero_is_never_a_valid_token() {
        let mut state = YubabaState::default();
        assert_eq!(
            claim(&mut state, "acme", 1, 1000),
            TenantOutcome::Granted { epoch: 1 }
        );
        let rec = state.tenants.get(&tenant("acme")).expect("record written");
        assert_eq!(rec.owner, 1);
        assert_eq!(rec.lease_expires, 1030);
    }

    #[test]
    fn a_second_node_claiming_under_a_live_lease_is_fenced() {
        // The split-brain attempt: node 2 believes it should own the tenant
        // while node 1's lease is still good. It must leave empty-handed AND
        // learn the real epoch, not merely fail.
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        assert_eq!(
            claim(&mut state, "acme", 2, 1010),
            TenantOutcome::Fenced {
                current_epoch: 1,
                current_owner: Some(1),
            }
        );
        assert_eq!(state.tenants[&tenant("acme")].owner, 1, "no takeover");
        assert_eq!(state.tenants[&tenant("acme")].epoch, 1, "no epoch churn");
    }

    #[test]
    fn takeover_after_lease_expiry_advances_the_epoch() {
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000); // lease to 1030
                                            // Exactly at the deadline the lease is dead (`is_live` is a strict <).
        assert_eq!(
            claim(&mut state, "acme", 2, 1030),
            TenantOutcome::Granted { epoch: 2 }
        );
        assert_eq!(state.tenants[&tenant("acme")].owner, 2);
    }

    #[test]
    fn self_reclaim_advances_the_epoch_to_fence_the_zombie() {
        // Node 1 restarts while its own previous process may still be
        // mid-write. Handing it back epoch 1 would leave the zombie
        // indistinguishable from the restarted owner on the R2 write path.
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        assert_eq!(
            claim(&mut state, "acme", 1, 1005),
            TenantOutcome::Granted { epoch: 2 },
            "a live self-reclaim must still bump"
        );
    }

    #[test]
    fn epoch_never_regresses_across_a_vacancy() {
        // The record is deliberately never deleted. If expiry dropped it, a new
        // owner would restart at 1 and a zombie holding 3 would outrank it.
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        claim(&mut state, "acme", 1, 1005);
        claim(&mut state, "acme", 1, 1010); // epoch 3
                                            // Long past expiry — nobody has touched it in an hour.
        assert_eq!(
            claim(&mut state, "acme", 7, 99_000),
            TenantOutcome::Granted { epoch: 4 },
            "resumes from the retained epoch, not from scratch"
        );
    }

    #[test]
    fn transfer_cas_advances_once_and_a_replay_does_not_double_advance() {
        // The mid-decision-failover retry: the leader committed the transfer,
        // died before answering, and the client re-sends the identical request.
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000); // epoch 1, owner 1
        let req = YubabaRequest::TransferTenant {
            tenant: tenant("acme"),
            to: 2,
            from_epoch: 1,
            lease_secs: 30,
            now: 1010,
        };
        assert_eq!(
            outcome(apply(&mut state, &req)),
            TenantOutcome::Granted { epoch: 2 }
        );
        assert_eq!(
            outcome(apply(&mut state, &req)),
            TenantOutcome::Granted { epoch: 2 },
            "the retry reports the same token, not a fresh one"
        );
        assert_eq!(state.tenants[&tenant("acme")].epoch, 2, "no double advance");
        assert_eq!(state.tenants[&tenant("acme")].owner, 2);
    }

    #[test]
    fn transfer_ignores_the_outgoing_owners_live_lease() {
        // Draining a healthy node is ordinary. The epoch — not the lease — is
        // what makes it safe while the old owner is still running and unaware.
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        assert_eq!(
            outcome(apply(
                &mut state,
                &YubabaRequest::TransferTenant {
                    tenant: tenant("acme"),
                    to: 2,
                    from_epoch: 1,
                    lease_secs: 30,
                    now: 1001, // lease runs to 1030; still very much alive
                },
            )),
            TenantOutcome::Granted { epoch: 2 }
        );
    }

    #[test]
    fn transfer_from_a_stale_epoch_is_fenced() {
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        claim(&mut state, "acme", 1, 1005); // epoch 2
        assert_eq!(
            outcome(apply(
                &mut state,
                &YubabaRequest::TransferTenant {
                    tenant: tenant("acme"),
                    to: 3,
                    from_epoch: 1, // caller is a whole epoch behind
                    lease_secs: 30,
                    now: 1010,
                },
            )),
            TenantOutcome::Fenced {
                current_epoch: 2,
                current_owner: Some(1),
            }
        );
        assert_eq!(state.tenants[&tenant("acme")].owner, 1, "no takeover");
    }

    #[test]
    fn a_stale_transfer_replay_after_later_transfers_is_fenced_not_deduped() {
        // The replay shortcut keys on "current == this request's exact
        // post-state". Once the world has moved on, the same replay must be
        // refused rather than mistaken for an already-applied success.
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000); // epoch 1
        let a_to_b = YubabaRequest::TransferTenant {
            tenant: tenant("acme"),
            to: 2,
            from_epoch: 1,
            lease_secs: 30,
            now: 1010,
        };
        apply(&mut state, &a_to_b); // epoch 2, owner 2
        apply(
            &mut state,
            &YubabaRequest::TransferTenant {
                tenant: tenant("acme"),
                to: 3,
                from_epoch: 2,
                lease_secs: 30,
                now: 1020,
            },
        ); // epoch 3, owner 3
        assert_eq!(
            outcome(apply(&mut state, &a_to_b)),
            TenantOutcome::Fenced {
                current_epoch: 3,
                current_owner: Some(3),
            }
        );
        assert_eq!(state.tenants[&tenant("acme")].owner, 3, "3 keeps it");
    }

    #[test]
    fn transfer_of_a_tenant_with_no_record_uses_from_epoch_zero() {
        let mut state = YubabaState::default();
        assert_eq!(
            outcome(apply(
                &mut state,
                &YubabaRequest::TransferTenant {
                    tenant: tenant("acme"),
                    to: 5,
                    from_epoch: 0,
                    lease_secs: 30,
                    now: 1000,
                },
            )),
            TenantOutcome::Granted { epoch: 1 }
        );
        // …and a non-zero from_epoch against no record is fenced with 0/None.
        assert_eq!(
            outcome(apply(
                &mut state,
                &YubabaRequest::TransferTenant {
                    tenant: tenant("other"),
                    to: 5,
                    from_epoch: 4,
                    lease_secs: 30,
                    now: 1000,
                },
            )),
            TenantOutcome::Fenced {
                current_epoch: 0,
                current_owner: None,
            }
        );
    }

    #[test]
    fn renew_extends_the_lease_without_touching_the_epoch() {
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000); // epoch 1, expires 1030
        assert_eq!(
            outcome(apply(
                &mut state,
                &YubabaRequest::RenewTenantLease {
                    tenant: tenant("acme"),
                    node: 1,
                    epoch: 1,
                    lease_secs: 30,
                    now: 1020,
                },
            )),
            TenantOutcome::Granted { epoch: 1 },
            "renewal must not hand back a new token"
        );
        let rec = &state.tenants[&tenant("acme")];
        assert_eq!(rec.epoch, 1);
        assert_eq!(rec.lease_expires, 1050);
    }

    #[test]
    fn renew_never_retracts_a_lease_a_later_renewal_already_extended() {
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        let renew = |now| YubabaRequest::RenewTenantLease {
            tenant: tenant("acme"),
            node: 1,
            epoch: 1,
            lease_secs: 30,
            now,
        };
        apply(&mut state, &renew(1100)); // expires 1130
        apply(&mut state, &renew(1020)); // reordered/delayed; would give 1050
        assert_eq!(
            state.tenants[&tenant("acme")].lease_expires,
            1130,
            "the deadline is monotonic"
        );
    }

    #[test]
    fn renew_under_a_stale_token_or_the_wrong_owner_is_fenced() {
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        claim(&mut state, "acme", 1, 1005); // restarted: now epoch 2
                                            // The zombie process still believes it holds epoch 1.
        assert_eq!(
            outcome(apply(
                &mut state,
                &YubabaRequest::RenewTenantLease {
                    tenant: tenant("acme"),
                    node: 1,
                    epoch: 1,
                    lease_secs: 30,
                    now: 1010,
                },
            )),
            TenantOutcome::Fenced {
                current_epoch: 2,
                current_owner: Some(1),
            }
        );
        // A node that never owned it fares no better.
        assert_eq!(
            outcome(apply(
                &mut state,
                &YubabaRequest::RenewTenantLease {
                    tenant: tenant("acme"),
                    node: 9,
                    epoch: 2,
                    lease_secs: 30,
                    now: 1010,
                },
            )),
            TenantOutcome::Fenced {
                current_epoch: 2,
                current_owner: Some(1),
            }
        );
        // And renewing a tenant with no record at all reports 0/None.
        assert_eq!(
            outcome(apply(
                &mut state,
                &YubabaRequest::RenewTenantLease {
                    tenant: tenant("ghost"),
                    node: 1,
                    epoch: 1,
                    lease_secs: 30,
                    now: 1010,
                },
            )),
            TenantOutcome::Fenced {
                current_epoch: 0,
                current_owner: None,
            }
        );
    }

    #[test]
    fn tenant_fencing_token_gates_on_both_owner_and_lease() {
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000); // epoch 1, expires 1030
        let t = tenant("acme");
        assert_eq!(state.tenant_fencing_token(&t, 1, 1020), Some(1));
        assert_eq!(
            state.tenant_fencing_token(&t, 1, 1030),
            None,
            "expired lease yields no token even for the recorded owner"
        );
        assert_eq!(
            state.tenant_fencing_token(&t, 2, 1020),
            None,
            "a non-owner never gets a token"
        );
        assert_eq!(
            state.tenant_fencing_token(&tenant("ghost"), 1, 1020),
            None,
            "no record means no write"
        );
    }

    // ── R737-F1 (W246): placement intent + derived node load ────────────────
    //
    // The property under test throughout is the *split*: intent and ownership
    // are separate facts, and a change to one must not silently move the other.

    fn placement(
        region: Option<&str>,
        tier: SlaTier,
        memory_mb: u32,
        cpu_millis: u32,
    ) -> TenantPlacement {
        TenantPlacement {
            region: region.map(str::to_string),
            tier,
            demand: TenantDemand {
                memory_mb,
                cpu_millis,
            },
            rpo_bound: None,
        }
    }

    fn declare(state: &mut YubabaState, t: &str, p: TenantPlacement) {
        apply(
            state,
            &YubabaRequest::SetTenantPlacement {
                tenant: tenant(t),
                placement: p,
            },
        );
    }

    fn member(state: &mut YubabaState, node: YubabaNodeId, capacity: Option<NodeCapacity>) {
        apply(
            state,
            &YubabaRequest::SetMember {
                node_id: node,
                addr: format!("100.64.0.{node}:7443"),
                region: Some("us-west".into()),
                capacity,
            },
        );
    }

    const BOX_16G: NodeCapacity = NodeCapacity {
        memory_mb: 16384,
        cpu_millis: 8000,
    };

    /// The headline property of the whole ticket. Declaring where a tenant
    /// *should* live must not touch who owns it or what epoch they hold —
    /// otherwise an operator re-homing a tenant would fence its live writer as a
    /// side effect of editing a config, which is a data-loss path dressed up as
    /// a declaration.
    #[test]
    fn declaring_intent_does_not_touch_ownership_or_the_epoch() {
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        let before = state.tenants.get(&tenant("acme")).cloned().unwrap();

        declare(
            &mut state,
            "acme",
            placement(Some("us-east"), SlaTier::WarmReplica, 2048, 1000),
        );

        assert_eq!(
            state.tenants.get(&tenant("acme")),
            Some(&before),
            "intent is an input to the scheduler, not a write path — the owner and epoch are \
             untouched"
        );
        assert_eq!(
            state.placement.get(&tenant("acme")).map(|p| p.tier),
            Some(SlaTier::WarmReplica)
        );
    }

    /// R782: the RPO target rides the same declared-intent write as region/
    /// tier/demand, and defaults to `None` (no target configured) for a
    /// tenant that never had one declared — the reading
    /// `lease_detector::judge_readiness` already documents as vacuously
    /// satisfied.
    #[test]
    fn rpo_bound_round_trips_through_declared_intent_and_defaults_to_none() {
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        assert_eq!(state.placement.get(&tenant("acme")), None);

        let mut p = placement(None, SlaTier::ColdHydrate, 512, 250);
        p.rpo_bound = Some(std::time::Duration::from_secs(30));
        declare(&mut state, "acme", p);

        assert_eq!(
            state.placement.get(&tenant("acme")).and_then(|p| p.rpo_bound),
            Some(std::time::Duration::from_secs(30))
        );
    }

    /// And the converse: withdrawing intent leaves a live owner exactly where it
    /// is. Clearing a declaration is how a tenant *stops being scheduled*, not
    /// how it is evicted — conflating the two would make decommissioning a
    /// tenant an unannounced outage for whoever is still serving it.
    #[test]
    fn clearing_intent_leaves_a_live_owner_serving() {
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        declare(
            &mut state,
            "acme",
            placement(None, SlaTier::ColdHydrate, 512, 250),
        );

        apply(
            &mut state,
            &YubabaRequest::ClearTenantPlacement {
                tenant: tenant("acme"),
            },
        );

        assert!(state.placement.is_empty(), "the declaration is gone");
        assert_eq!(
            state.tenant_fencing_token(&tenant("acme"), 1, 1020),
            Some(1),
            "the owner still holds a live token — clearing intent is not an eviction"
        );
    }

    /// The asymmetry with [`TenantOwnership`], pinned so nobody "fixes" it into
    /// symmetry: intent is genuinely deletable because it carries no monotonic
    /// property, while an ownership record is retained on expiry so its epoch
    /// cannot regress.
    #[test]
    fn intent_is_deletable_where_the_ownership_record_never_is() {
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        declare(
            &mut state,
            "acme",
            placement(None, SlaTier::ColdHydrate, 0, 0),
        );
        apply(
            &mut state,
            &YubabaRequest::ClearTenantPlacement {
                tenant: tenant("acme"),
            },
        );

        assert!(!state.placement.contains_key(&tenant("acme")));
        assert!(
            state.tenants.contains_key(&tenant("acme")),
            "no request removes an ownership record — a re-claim must resume from the retained \
             epoch, or a zombie at epoch 5 would outrank a fresh owner starting at 1"
        );
    }

    /// Re-declaring is last-write-wins with no CAS, and that is deliberate: two
    /// operators disagreeing about a home region is a conflict raft has already
    /// serialized, and a CAS would only turn it into a retry loop over the same
    /// disagreement.
    #[test]
    fn redeclaring_overwrites_rather_than_conflicting() {
        let mut state = YubabaState::default();
        declare(
            &mut state,
            "acme",
            placement(Some("us-west"), SlaTier::ColdHydrate, 512, 250),
        );
        declare(
            &mut state,
            "acme",
            placement(Some("us-east"), SlaTier::WarmReplica, 4096, 2000),
        );
        assert_eq!(
            state.placement.get(&tenant("acme")),
            Some(&placement(
                Some("us-east"),
                SlaTier::WarmReplica,
                4096,
                2000
            ))
        );
    }

    /// Load counts only tenants this node owns **with a live lease**, and that
    /// is the load-bearing half. The node whose owner just died is the node the
    /// scheduler is about to place away from; counting its dead tenants against
    /// it would make a failing node look full exactly while it emptied, and the
    /// re-placement would skip the box with the most room.
    #[test]
    fn an_expired_lease_stops_counting_against_its_node() {
        let mut state = YubabaState::default();
        member(&mut state, 1, Some(BOX_16G));
        claim(&mut state, "acme", 1, 1000); // expires 1030
        declare(
            &mut state,
            "acme",
            placement(None, SlaTier::ColdHydrate, 4096, 2000),
        );

        assert_eq!(
            state.node_load(1, 1020),
            NodeLoad {
                tenants: 1,
                memory_mb: 4096,
                cpu_millis: 2000
            }
        );
        assert_eq!(
            state.node_load(1, 1030),
            NodeLoad::default(),
            "an expired lease contributes nothing — the tenant is the scheduler's to move, not \
             this node's to be charged for"
        );
        assert_eq!(
            state.node_headroom(1, 1030),
            Some(BOX_16G),
            "so the emptied node reports its whole budget as available"
        );
    }

    /// Load is derived from the same maps the scheduler mutates, which is the
    /// entire reason it is not a reported field: two placements committed in one
    /// tick are both visible to the second fit-check.
    #[test]
    fn a_placement_is_visible_to_the_very_next_fit_check() {
        let mut state = YubabaState::default();
        member(&mut state, 1, Some(BOX_16G));
        let big = TenantDemand {
            memory_mb: 12288,
            cpu_millis: 4000,
        };

        assert!(state.node_admits(1, &big, 1000));

        // Decision k: place one 12 GiB tenant.
        claim(&mut state, "acme", 1, 1000);
        declare(
            &mut state,
            "acme",
            placement(None, SlaTier::ColdHydrate, big.memory_mb, big.cpu_millis),
        );

        // Decision k+1, same tick, same `now`.
        assert!(
            !state.node_admits(1, &big, 1000),
            "a node-reported load would still say 16 GiB free here and overcommit the box by \
             8 GiB — this is the race deriving the number exists to close"
        );
    }

    /// A node that has published no capacity is UNKNOWN, never unlimited. During
    /// a roll an un-upgraded node is in membership with no capacity row, and
    /// reading that as unconstrained would funnel every tenant onto the one box
    /// that cannot say no.
    #[test]
    fn a_node_with_no_published_capacity_is_never_scheduled_onto() {
        let mut state = YubabaState::default();
        member(&mut state, 1, None);
        assert_eq!(state.node_headroom(1, 1000), None);
        assert!(!state.node_admits(1, &TenantDemand::default(), 1000));
        assert!(
            !state.node_admits(7, &TenantDemand::default(), 1000),
            "and a node with no member row at all is equally ineligible"
        );
    }

    /// Capacity can shrink under a live placement (a box resized down), so
    /// overcommit is reachable without a bug. Headroom saturates at zero rather
    /// than wrapping to ~4 billion MiB and admitting everything.
    #[test]
    fn overcommit_reports_zero_headroom_rather_than_wrapping() {
        let mut state = YubabaState::default();
        member(&mut state, 1, Some(BOX_16G));
        claim(&mut state, "acme", 1, 1000);
        declare(
            &mut state,
            "acme",
            placement(None, SlaTier::ColdHydrate, 12288, 4000),
        );
        // The box is resized down under the live tenant.
        member(
            &mut state,
            1,
            Some(NodeCapacity {
                memory_mb: 4096,
                cpu_millis: 2000,
            }),
        );

        assert_eq!(
            state.node_headroom(1, 1000),
            Some(NodeCapacity {
                memory_mb: 0,
                cpu_millis: 0
            })
        );
        assert!(!state.node_admits(
            1,
            &TenantDemand {
                memory_mb: 1,
                cpu_millis: 0
            },
            1000
        ));
    }

    /// A tenant owned but never declared counts toward the node's tenant count
    /// and toward neither resource axis. Inventing a demand for it would be a
    /// guess the operator never made, and `0` is already this system's spelling
    /// for "unconstrained on that axis".
    #[test]
    fn an_undeclared_tenant_counts_as_a_tenant_and_no_resources() {
        let mut state = YubabaState::default();
        member(&mut state, 1, Some(BOX_16G));
        claim(&mut state, "orphan", 1, 1000);
        assert_eq!(
            state.node_load(1, 1000),
            NodeLoad {
                tenants: 1,
                memory_mb: 0,
                cpu_millis: 0
            }
        );
    }

    /// The tier default is the pessimistic one. A tenant whose tier was never
    /// declared must not be read as having a warm replica somewhere, because the
    /// scheduler would then pick a target on a promise nothing kept.
    #[test]
    fn an_undeclared_tier_defaults_to_cold_hydrate() {
        let legacy = serde_json::json!({ "tier": "cold_hydrate" });
        let parsed: TenantPlacement = serde_json::from_value(serde_json::json!({}))
            .expect("region, tier and demand are all defaultable");
        assert_eq!(parsed.tier, SlaTier::ColdHydrate);
        assert_eq!(parsed.region, None);
        assert_eq!(parsed.demand, TenantDemand::default());
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            serde_json::json!({
                "region": null,
                "tier": "cold_hydrate",
                "demand": { "memory_mb": 0, "cpu_millis": 0 },
                "rpo_bound": null,
            }),
            "and the wire spelling is snake_case: {legacy}"
        );
    }

    /// Placement rides the same snapshot as everything else, and a pre-R737
    /// snapshot must load with an empty map rather than failing — the same
    /// forward-compat contract `tenants` and `secrets` carry.
    #[test]
    fn pre_r737_snapshot_without_placement_field_loads_declaring_nothing() {
        let legacy = serde_json::json!({
            "members": {},
            "service_placement": {},
            "locks": {},
            "ingress_owner": null
        });
        let state: YubabaState =
            serde_json::from_value(legacy).expect("a pre-R737 snapshot must still load");
        assert!(state.placement.is_empty());
    }

    #[test]
    fn placement_survives_snapshot_round_trip() {
        let mut state = YubabaState::default();
        member(&mut state, 1, Some(BOX_16G));
        declare(
            &mut state,
            "acme",
            placement(Some("us-east"), SlaTier::WarmReplica, 2048, 1000),
        );
        let json = serde_json::to_string(&state).unwrap();
        let restored: YubabaState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.placement, state.placement);
        assert_eq!(restored.members, state.members);
    }

    #[test]
    fn tenants_survive_snapshot_round_trip() {
        // The snapshot path is serde_json over YubabaState (see store.rs), and
        // JSON object keys must be strings — this pins that `TenantId`, a
        // newtype over String, is usable as a BTreeMap key on both legs.
        let mut state = YubabaState::default();
        claim(&mut state, "acme", 1, 1000);
        claim(&mut state, "globex", 2, 1000);
        let json = serde_json::to_string(&state).unwrap();
        assert!(
            json.contains(r#""acme""#),
            "tenant key serialised flat: {json}"
        );
        let restored: YubabaState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tenants, state.tenants);
    }

    #[test]
    fn an_unknown_request_variant_fails_to_parse_which_is_why_r732_bumped_both_epochs() {
        // This is the executable form of R732-F1's breaking/non-breaking call,
        // and the discriminator against the R625-B6 `digest` precedent that was
        // judged NON-breaking. An added struct *field* is tolerated in both
        // directions (no `deny_unknown_fields` anywhere in this chain), so that
        // one only needed a re-record. An added enum *variant* is not: there is
        // no `#[serde(other)]` catch-all on `YubabaRequest`, so a node running
        // the older binary hits a hard deserialize error the moment a
        // ClaimTenant entry reaches it over AppendEntries or turns up in a log
        // it is replaying — it cannot apply, cannot advance, and cannot roll
        // back past that entry. Hence cluster_protocol 3 -> 4 and
        // state_epoch 2 -> 3.
        //
        // If someone ever adds a catch-all variant to make this tolerant, this
        // test fails and the compatibility story in cluster-epochs.json has to
        // be rewritten rather than quietly becoming untrue.
        let err = serde_json::from_str::<YubabaRequest>(r#"{"SomeFutureVariant":{}}"#)
            .expect_err("an unknown variant must not silently parse");
        assert!(
            err.to_string().contains("unknown variant"),
            "expected an unknown-variant error, got: {err}"
        );
    }

    #[test]
    fn pre_r732_snapshot_without_tenants_field_loads_owning_nothing() {
        // Same forward-compat contract as `rollouts` / `secrets`. The absent
        // map must mean "nobody owns anything" — which denies every write —
        // rather than failing the replay.
        let legacy = r#"{"members":{},"service_placement":{},"locks":{},"ingress_owner":null,"rollouts":{},"secrets":{}}"#;
        let state: YubabaState = serde_json::from_str(legacy).unwrap();
        assert!(state.tenants.is_empty());
        assert_eq!(
            state.tenant_fencing_token(&tenant("acme"), 1, 1000),
            None,
            "an upgraded node must not assume ownership it has no record of"
        );
    }

    /// R734-F2, the `state_epoch` half. This axis claims both that a new binary
    /// reads an old snapshot **and** that a rollback works, so both directions
    /// are asserted here rather than argued from serde's documented behaviour.
    ///
    /// The contrast worth keeping in view: R732-F1 had to bump this axis
    /// because it added enum *variants* to the replicated command type, and a
    /// downgraded binary cannot parse its own log past one of those. `region`
    /// is a *field* on an existing struct, which serde drops silently — so the
    /// downgrade stays clean and this is a re-record.
    #[test]
    fn a_pre_r734_f2_snapshot_loads_untagged_and_a_downgrade_reads_a_tagged_one() {
        // New reads old: a member row written before regions existed.
        let legacy = r#"{"members":{"1":{"addr":"100.64.0.1:7443"}},"service_placement":{},"locks":{},"ingress_owner":null,"rollouts":{},"secrets":{}}"#;
        let state: YubabaState = serde_json::from_str(legacy).unwrap();
        assert_eq!(
            state.members.get(&1).and_then(|m| m.region.as_deref()),
            None,
            "an untagged member must read as untagged, never as an invented default"
        );

        // Old reads new: the downgrade direction. A pre-R734-F2 `MemberInfo`
        // is exactly `{ addr }`, so stand in for that binary's decoder and
        // confirm the extra key is ignored rather than fatal.
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct PreF2MemberInfo {
            addr: String,
        }
        let tagged = r#"{"addr":"100.64.0.1:7443","region":"us-west"}"#;
        let old: PreF2MemberInfo = serde_json::from_str(tagged)
            .expect("a downgraded binary must still parse a region-tagged member row");
        assert_eq!(old.addr, "100.64.0.1:7443");
    }

    #[test]
    fn pre_f1_snapshot_without_secrets_field_loads() {
        // A snapshot serialised before R600-F1 has no `secrets` key;
        // #[serde(default)] must let it deserialize to an empty map, not error
        // (same forward-compat contract the `rollouts` field relies on).
        let legacy = r#"{"members":{},"service_placement":{},"locks":{},"ingress_owner":null,"rollouts":{}}"#;
        let state: YubabaState = serde_json::from_str(legacy).unwrap();
        assert!(state.secrets.is_empty());
    }
}
