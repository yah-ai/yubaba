//! Upstream-discovery read-model (R594-F3): serving-workload → mesh-IP:port
//! + health, queryable by a future ingress proxy (R594-F4).
//!
//! ## Why this lives here, not in `cloud::mesh_service`
//!
//! `cloud/src/mesh_service.rs` is compose-recipe helpers — constants and
//! string-builders (`pg_hba_snippet`, `ufw_rules_for_mesh_port`,
//! `mesh_ip_env_runcmd`) that render config *before* a workload exists.
//! It has no notion of a live workload registry and holds no state. This
//! module is the opposite shape: a stateful, queryable record of workloads
//! yubaba has *already placed and knows the mesh address of* — that's
//! workload-placement bookkeeping, which is yubaba-proper's job (yubaba
//! already owns `ServerState`, `workload_bind_ip`, and the `ContainerRuntime` /
//! `kamaji::Kamaji` dispatch that this module reads from). Homing a
//! queryable service-record surface in the cloud crate would duplicate (or
//! reach back into) state yubaba already holds.
//!
//! ## Placement source of truth
//!
//! Yubaba never invents a parallel store of "what's running where" — it
//! already has two facts, at two different moments, and this module
//! combines them instead of re-deriving either:
//!
//! 1. **At deploy time**, once per workload *tier*, because `POST
//!    /workloads/deploy` in `lib.rs` admits two differently-shaped workloads
//!    and only one of them has a [`WorkloadSpec`]:
//!    - *Container* ([`ServiceRecords::upsert_deployed`]): the handler has
//!      both the [`WorkloadSpec`] (which carries `expose.mesh.ports` — where
//!      a container's serving port(s) are declared) and the
//!      [`kamaji::DeployResult`] (which echoes back the mesh IP yubaba handed
//!      the backend at deploy — `ServerState::workload_bind_ip`).
//!    - *W272 bundle* ([`ServiceRecords::admit_bundle`], R844-F1): a
//!      `Workload::MesofactStatic` envelope has no `WorkloadSpec` at all. Its
//!      serving port rides on `MesofactServeBundle::port` and its address is
//!      the node's own mesh IP (`ServerState::node_mesh_ip`) — a native
//!      bundle is a forked host process with no namespace, so there is no
//!      per-workload address to allocate. Same pairing, different two facts.
//!
//!    **Both tiers now advertise the node's own address** (R844-B11). They did
//!    not always: the container tier drew a per-workload address from a
//!    `100.64.0.1`-seeded counter that nothing configured, so it published a
//!    neighbouring node's real address as a dialable endpoint. A record's
//!    `mesh_ip` must equal the answering node's own mesh address — that is the
//!    invariant to check when reading `GET /service-records` off a live node.
//!
//!    Since R876-B3 it is also **enforced at the write boundary** rather than
//!    only declared here: `authoritative_mesh_ip` makes `node_mesh_ip` beat a
//!    backend's disagreeing self-report on every sweep, warning loudly. It had
//!    to be, because a wrong address survives the deploy path being fixed — it
//!    is persisted in the workload's `yah.mesh_ip` container label and replayed
//!    on every `list_workloads`, so west was still publishing east's address
//!    for `yah-cloud-admin` long after `alloc_mesh_ip` was deleted.
//!
//!    Either way that pairing is admission-time knowledge that exists nowhere
//!    else, which is why it cannot be recovered by step 2.
//! 2. **On every subsequent read** ([`ServiceRecords::reconcile`]): the
//!    exact same call `GET /workloads` already makes —
//!    `ContainerRuntime::list_workloads()` → `Vec<`[`WorkloadState`]`>` — is
//!    the authoritative "what does the runtime think is running right now"
//!    source. It carries `status`, (usually) `mesh_ip`, and — since R844-F2 —
//!    the **resolved ports** the supervisor actually bound.
//!
//! ## Declared ports and resolved ports are different facts
//!
//! That third field is why step 2 is no longer only a refresh, and the
//! distinction it introduced is the thing to hold onto:
//!
//! - **Declared** ([`ServiceRecord::ports`]) — what the workload *asked for*.
//!   `expose.mesh.ports` on a container's spec; `serve_bundle.port` on a
//!   bundle, which the mirror's `[providers.bundle] port` key writes. Known at
//!   admission, before anything has bound.
//! - **Resolved** ([`ServiceRecord::resolved_ports`]) — what the supervisor
//!   *bound*, reported on every sweep. For a bundle with no declaration this is
//!   a port kamaji allocated (`kamaji::ports`), which exists nowhere in
//!   yubaba's inputs and can only arrive this way.
//!
//! [`ServiceRecord::dialable_ports`] resolves the precedence once: resolved
//! wins, declared is the fallback. The fallback is not a courtesy — a
//! namespaced container's declared port *is* its bound port, so its backend
//! reports no resolved set and never will.
//!
//! Keeping them apart rather than overwriting one with the other is deliberate:
//! they can disagree, and the disagreement is the diagnosis. A declared port
//! that never appears as resolved is a workload that failed to bind what it
//! asked for; a resolved port with no declaration is the normal steady state
//! once a mirror stops naming one.
//!
//! ## Ports are NAMED (R844-F15)
//!
//! Both sets are `BTreeMap<String, u16>`, not `Vec<u16>`. A consumer handed
//! three bare numbers cannot tell which one is the websocket listener: it
//! guesses by index or by a convention nothing enforces, and is wrong the first
//! time a port moves or a declaration is reordered. That — not allocation — is
//! what actually blocks cross-mesh service discovery, so [`ServiceRecord::port`]
//! and [`ServiceRecord::endpoint`] take a name and either resolve it or don't.
//!
//! Where the names come from, in order of how much they are worth:
//!
//! 1. **The supervisor.** kamaji's allocator resolves a named set (R844-F14) and
//!    reports it on `kamaji::WorkloadState::ports`, which rides the same 15s
//!    sweep that already re-asserts every resolved port. Names cost no new
//!    machinery — they ride an existing correction path.
//! 2. **Synthesis, for declarations that still carry no names.**
//!    `expose.mesh.ports` and `serve_bundle.port` are anonymous number lists, so
//!    [`kamaji::name_anonymous_ports`] names them — and it is the *only* place
//!    that decides, so a workload's ports are spelled the same in a record, in a
//!    kamaji entry, and in the `PORT_<NAME>` environment (R844-T13).
//!
//! The synthesis rule has one clause worth reading before touching it: a **sole**
//! anonymous port is named `http`, and **several** anonymous ports are each named
//! by their own number with *none* of them called `http`. Naming the first one
//! `http` is the obvious rule, reads as harmless, and reintroduces exactly the
//! positional guess this ticket removes — `port_for` would then resolve an
//! ingress rule off declaration order and publish a hostname at whatever
//! listener happened to be written first. Pinned by
//! `kamaji::tests::several_anonymous_ports_name_none_of_themselves_http`.
//!
//! **The two wires this data crosses do NOT have the same compatibility rules,
//! and conflating them cost a debugging cycle.** [`ServiceRecordsWire`] below is
//! JSON over HTTP between independently-versioned binaries on a mixed fleet, so
//! `ports`/`endpoints` keep their array shape forever and the named views are
//! *additional* fields — an un-rolled consumer ignores them. `kamaji-proto`'s
//! `WorkloadEntry` is **postcard**, which is positional: there, an "optional"
//! field is a contradiction, `skip_serializing_if` produces frames a
//! same-version peer cannot decode, and the only compatibility mechanism is a
//! `ProtocolVersion` bump (V6 carries `named_ports`).
//!
//! ## How a record enters, and the one invariant
//!
//! Three routes, and every one of them satisfies the same two-clause
//! invariant — **a record exists iff yubaba declared the workload serving AND
//! a dialable port is known**. The second clause is the one F1 established;
//! the first was implicit while admission was the only route in, and R844-F2
//! made it explicit because cold admission reads from a supervisor that also
//! runs workloads yubaba never placed (see [`ServiceRecords::reconcile`]):
//!
//! - [`ServiceRecords::upsert_deployed`] at deploy time, for a container.
//! - [`ServiceRecords::admit_bundle`] at deploy time, for a bundle that
//!   declares a port.
//! - [`ServiceRecords::reconcile`]'s **cold-admission** arm (R844-F2), for a
//!   workload yubaba declared serving but could name no port for, whose
//!   supervisor has now reported the port it bound. This is what makes a
//!   mirror able to name no port at all: `admit_bundle` declines at admission
//!   because no port exists yet, and the first sweep after the fork publishes
//!   the real one.
//!
//! Plus, on boot, the port ledger written by prior admissions (§The port ledger
//! below).
//!
//! `reconcile` still never *fabricates* a record: an ident yubaba never
//! declared, or one whose state reports no resolved port, is skipped. What
//! changed is only that "no port to publish" is now a question the supervisor
//! can answer, where before R844-F2 it could not: `WorkloadState` had no ports
//! field, which is the gap R594-F6 weighed and deferred (see also `lib.rs`'s
//! R406-T8 note about enriching `WorkloadEntry`).
//!
//! ## Push-on-change over polling
//!
//! Per the platform's mesh-cost rule (cost-of-deciding << cost-of-acting;
//! keep idle CPU near zero), this module publishes via
//! [`tokio::sync::watch`] rather than exposing only a poll-and-diff
//! snapshot API. `watch` is a single-slot "latest value" cell with waker
//! fanout: a subscriber's `changed().await` resolves only when
//! [`ServiceRecords::upsert_deployed`], [`ServiceRecords::reconcile`], or
//! [`ServiceRecords::retract`] actually publishes a new snapshot — no
//! background loop, no timer, nothing to poll. A synchronous
//! [`ServiceRecords::snapshot`] is also exposed for callers (or tests) that
//! just want the current state without subscribing.
//!
//! ## Health signal
//!
//! [`Health`] mirrors the `GET /mesh/leader-health` pattern already used
//! for the Cloudflare healthcheck: a boolean gate ([`Health::is_ready`])
//! plus enough detail to explain *why* not, so an ingress proxy can skip a
//! not-ready upstream instead of routing traffic into a black hole.
//! `Running` is the only ready state; every other [`WorkloadStatus`] value,
//! and a workload's absence from the runtime's own list, are not-ready.
//!
//! ## Wiring (R594-F6)
//!
//! R594-F3 shipped this as a tested-but-unwired mechanism. F6 makes it live:
//!
//! - **Producer**: `deploy_workload_spec` calls [`ServiceRecords::upsert_deployed`]
//!   on a successful deploy (beside the `archetype_registry` /
//!   `workload_resources` inserts it already does), and `destroy_workload`
//!   calls [`ServiceRecords::retract`] beside the matching removals. R844-F1
//!   added the second producer: `deploy_non_container` calls
//!   [`ServiceRecords::admit_bundle`] on a successful kamaji bundle deploy.
//!   Until then the bundle tier had **no** producer at all — every node in
//!   the fleet served bundles and answered `GET /service-records?ready=true`
//!   with an empty set, and because `reconcile` never backfills an
//!   un-admitted ident (below), nothing could recover it.
//! - **Refresh**: [`run`] is a background sweep — `active_backend()`
//!   `.list_workloads()` → [`ServiceRecords::reconcile`] every
//!   [`SWEEP_INTERVAL`] — because health can change without a yubaba-initiated
//!   action (a container crash is nobody's HTTP request). This is the one
//!   poll in the design and it is deliberately slow; every *state-changing*
//!   event still pushes immediately through the `watch`.
//! - **Restart survival**: see §The port ledger below.
//!
//! ## The port ledger — why records survive a yubaba restart
//!
//! Ports are admission-time knowledge — *declared* ports still are, which is
//! the whole reason this file exists. (Read the next sentence in the past
//! tense: when R594-F6 wrote this ledger, `WorkloadState` carried `ident` /
//! `container_id` / `status` / `mesh_ip` and no ports at all. R844-F2 added
//! resolved ports to it and R844-F15 named them, so a *resolved* port is now
//! recoverable from the sweep — but a declaration the supervisor never bound
//! is not, and neither is one on a namespaced container backend that resolves
//! nothing. The ledger is still the only recovery for those.)
//!
//! With no ledger and no resolved ports, the sweep alone can
//! never rebuild a dialable record: it would know a workload is `Running` and
//! know its mesh IP, and still have nothing to dial. Before this ticket the
//! only recovery was to redeploy every serving workload — the containers were
//! fine, yubaba had merely forgotten the one number it never re-derives.
//!
//! Two ways to close that, both named in the ticket: (a) grow a serving-port
//! field on `WorkloadState` / the kamaji list wire, or (b) persist the
//! deploy-time `ident → ports` map locally. This module takes **(b)** — it is
//! strictly node-local, touches no shared wire (`kamaji-proto` is a
//! cross-repo contract with its own sequencing), and the knowledge being
//! persisted is knowledge yubaba *originated*, so no other component has a
//! better claim to store it.
//!
//! The ledger is a small JSON file ([`LEDGER_FILE_NAME`]) written beside
//! `identity.json`, rewritten atomically (via `identity::atomic_write_json`)
//! on every publish. It holds exactly the currently-non-retracted records, so
//! a workload torn down before shutdown does not come back on boot.
//!
//! **Rehydrated records are deliberately NOT `Ready`.** They come back as
//! `NotReady { reason: "rehydrated" }`: the ports and mesh IP are recovered
//! facts, but "is it running *right now*" is not — the process may have died
//! while yubaba was down. The first successful sweep promotes a genuinely-
//! running workload to `Ready` and retracts one that is gone. An ingress proxy
//! gating on [`Health::is_ready`] therefore never routes traffic into a
//! black hole on the strength of a stale file (fail-ready, matching the
//! cold-start posture R594-F4's proxy already takes).
//!
//! ## The discovery surface (R594-F8) — how passway learns its upstreams
//!
//! Everything above is in-process. An ingress proxy is a *separate binary*,
//! typically on a separate rented-doorknob node, so the registry needs a
//! network surface before it can back a front door: [`DISCOVERY_PATH`]
//! (`GET /service-records`), served by [`get_service_records`] and wired into
//! `build_router`. `?ready=true` filters server-side to
//! [`Health::is_ready`] records, which is the only query an ingress proxy
//! actually makes.
//!
//! This is the sovereign twin of the rented arm. Both ingress providers
//! answer one question — *given the workloads this fleet has placed, make
//! them publicly reachable* — and both derive their config from the same
//! placement facts rather than from a hand-written upstream list:
//!
//! | | rented (`cloudflare-tunnel`) | sovereign (`passway`) |
//! |---|---|---|
//! | Where ingress rules live | Cloudflare's API (remotely-managed tunnel) | the proxy process's own `Backends` set |
//! | How they get there | an API call per deployed workload | passway polls [`DISCOVERY_PATH`] |
//! | Source of truth | this registry | this registry |
//!
//! Wire shape is [`ServiceRecordsWire`], deliberately a *separate* type from
//! [`ServiceRecord`]: passway lives in its own Cargo workspace and cannot
//! depend on this crate, so it re-declares the same JSON on its side
//! (`oss/passway/crates/passway/src/discovery.rs`). Keeping the wire type
//! distinct from the in-memory one means an internal refactor can't silently
//! reshape a cross-binary contract — [`WIRE_VERSION`] is the explicit knob
//! for when it must.
//!
//! **A failed fetch is not an empty record set**, on the consumer side too.
//! Serving zero ready records is authoritative ("nothing is up right now");
//! a connection error is not, and passway holds its last-known-good set
//! rather than draining every backend on a transient yubaba blip. That is the
//! same distinction [`run`]'s sweep makes when `list_workloads()` fails.
//!
//! @yah:ticket(R858-T7, "Ungraceful death: expire a dead owner's records and fence it, so a power-off cannot produce two coordinators")
//! @yah:status(review)
//! @yah:at(2026-09-05T21:12:28Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:next("Tier: Warrior — fencing is the one failover step whose failure mode is corruption rather than delay, and a test that does not actually kill a node proves nothing.")
//! @yah:gotcha("EVERY RETRACTION PATH TODAY ASSUMES A GRACEFUL EXIT. `stop_headscale` calls `state.service_records.retract(&ident)` on leadership loss, and `leader.rs` comments correctly that retraction is \"the half of follow-placement that makes the OLD address stop answering\". A POWERED-OFF NODE RUNS NONE OF IT — no teardown, no retract, no `systemctl disable`. The dead node's yubaba is also gone, so its records simply stop being served rather than being marked gone, which is survivable for discovery but means nothing in the cluster ever OBSERVES the transition. Detection has to come from liveness, not from a retraction that will never arrive.")
//! @yah:assumes("That the existing lease layer is the right detector and only needs wiring, not building. `crate::lease_detector` already has LeaseFailureDetector (renewals pushed over POST /mesh/lease-renew), HysteresisPolicy with confirm_up_after / confirm_down_after dwells, judge_readiness, and a SECOND raft channel specifically to catch the gray failure where a node renews its HTTP lease happily while being useless. It was built for W253/R737 TENANT placement. Verify it generalizes to appliance ownership before assuming so — in particular whether an appliance needs a different (probably shorter) confirm-down dwell than a tenant, since the coordinator's blast radius is the whole fleet.")
//! @yah:gotcha("LIVE HAZARD FOR THE PLANNED REHEARSAL, created deliberately on 2026-09-04 and it must be undone before the node is powered back on. The R858 restore ran `systemctl enable --now headscale` on us-west-001 — `enable`, so it is BOOT-PERSISTENT. That was right for an outage with no other coordinator possible, and it is exactly wrong for a rehearsal: power us-west-001 off, let the appliance come up elsewhere, then power us-west-001 back ON, and its headscale starts automatically against its own local DB. That is the two-coordinator split brain above, arrived at by the most likely route. leader.rs's own comments already name this shape — \"a still-enabled unit on a node that no longer owns the appliance resurrects it at the next boot\". BEFORE THE REHEARSAL: `systemctl disable headscale` on us-west-001 (leaving it running), or accept that the node must not be rebooted until ownership is fenced.")
//! @yah:next("FENCING: THE TOKEN ALREADY EXISTS, CHECK WHETHER IT COVERS THE RIGHT THING. turso-backup's `StreamConfig::epoch` is \"a per-tenant fencing token minted by yubaba's raft state machine\", checked against the watermark sidecar before any frame upload and advanced by a compare-and-swap on the version that check read — so a stale owner is rejected both when it arrives late AND when it races (R732-F2/R732-T3, oss/turso-backup/src/stream.rs). That is the correct primitive and it is raft-minted, which is exactly what a power-off needs, because you cannot confirm a dead owner is dead by asking it. WHAT IS NOT ESTABLISHED: that epoch fences the REPLICA STREAM. It does not, on its own, stop a resurrected node from SERVING headscale to clients off a stale local DB — it only stops it corrupting the replica. Serving-side fencing is the open half: either the appliance claim itself carries the epoch and a stale holder refuses to serve, or ownership is a lease the old node observes expiring. Decide which; do not assume the stream epoch covers both.")
//! @yah:handoff("EXPIRE — what retracts a dead owner's record. leader.rs::reconcile_appliance_ownership now widens decide_owner's candidate map with the RECORDED OWNER, on the leader only, when the node-lease channel says it has been silent past FenceTiming::expire_after — projected as liveness: Some(Confirmed::Down) so judge_appliance_candidate refuses it as `not-live` through the one readiness vocabulary this crate has rather than a second predicate. decide_owner's own doc predicted exactly this ('R858-T7 has to plumb both to expire a dead owner's records; when it does, widening this is building a larger BTreeMap here and nothing else'), and its unjudged-owner rule is UNTOUCHED — the owner enters the map on positive evidence of death and on nothing else, so a yubaba restart still leaves a healthy coordinator alone. The record is then OVERWRITTEN by ElectTo's SetIngressOwner on a successful start; on NoEligibleCandidate the leader issues ClearIngressOwner instead, because R858's own root-cause note is that 'the record says west owns it' is what an operator reads during an outage and it has to be true. The clear is also load-bearing for the fence: a resurrected node reads that record to decide whether it may serve, and an absent record puts it on the lease path instead of letting it read its own name and resume.")
//! @yah:handoff("FENCE — the ticket's fork decided WITH EVIDENCE, and not the way its own @yah:next leans. It is a LEASE the old node observes expiring, NOT a raft-minted epoch on the claim. The reason is that an epoch does not fence the case this relay exists for. Walk a power-off: (a) the node rejoins raft and applies current state — it reads a record naming south and fences, which a plain machine-name comparison already decides and the epoch adds nothing to; (b) the node boots with STALE raft state, partitioned or lagging — its applied state says 'owner = west, epoch N' and it has no way to know N+1 exists, BECAUSE THAT IS WHAT STALE MEANS. An ordinal is believed exactly as confidently as a name. What makes a claim safe is not its ordinal but its FRESHNESS, and freshness is only measurable on the holder's own monotonic clock against evidence it currently has quorum contact. That is a lease. turso-backup's StreamConfig::epoch (R732-F2/T3) remains the right primitive one layer down on the REPLICA STREAM, where a stale writer's frames are rejected by a watermark sidecar that IS current — the ticket was right that it does not follow that it fences serving, and it does not. Deciding this way also avoided a YubabaState schema change and its mixed-operation compatibility verdict on a live 3-voter prod raft, which would have been real cost for no safety gain.")
//! @yah:handoff("appliance_ownership::judge_self_fence(recorded, this_node, running_here, unconfirmed_for, timing) -> SelfFence::{Serve, Stop(FenceReason)}. Takes no candidate map, no leadership flag and no peer opinion — a fence that needed the cluster's help would be useless in exactly the situations that call for one. Two arms, ORDERED: (1) RecordNamesAnotherNode, positive evidence, checked first so a node that can plainly read 'south owns it' does not get a full fence window anyway just because its clock was recently refreshed; (2) ClaimUnconfirmed, the partition case, where the node reads its own name out of its own stale applied state and is wrong. Called in leader.rs BEFORE the may_act early return, and that placement is the whole fix: the node that most needs stopping is precisely one with no standing to act — not the leader, not the recorded owner — and every pre-T7 version of reconcile_appliance_ownership returned early on it while its headscale went on answering cloud.mesh.yah.dev. That early return IS the two-coordinator bug and it is readable in the diff. The stop is on_lost_leader, not a bare stop, so a fenced node also stops replicating rather than pushing frames from a losing database into the shared litestream replica the new owner restores from.")
//! @yah:handoff("THE SAFETY INEQUALITY, which is the actual design. Two clocks on two channels have to be ordered or expiry races the fence and the mechanism built to prevent two coordinators produces them on a schedule. FenceTiming::from_thresholds derives BOTH deadlines from one LivenessThresholds so the ordering is a property of the constructor rather than of two constants someone tunes independently: self_fence_after = 4x down_after, expire_after = 6x. At the fleet preset that is 20s / 30s with a 10s margin; at rig, 6s / 9s. Pinned by expiry_cannot_outrun_the_self_fence_at_any_preset (asserted across every preset, since a future preset is exactly what could silently invert them) and at_every_instant_expiry_is_permitted_the_holder_has_already_stopped (swept over a 120s timeline). CORRECTION TO THE TICKET'S INHERITED @yah:assumes: it guesses an appliance wants a SHORTER confirm-down dwell than a tenant because the coordinator's blast radius is the fleet. Measured against the failure modes that is backwards, and the doc says so at the constants. A wrong tenant failover costs one needless move; a wrong appliance failover costs two coordinators, which this module already calls worse than the outage. And a shorter fence deadline does not shorten the outage on the path that matters — on a real power-off the coordinator is gone at t=0 whatever any deadline says, so buying failover speed with fence margin spends the only thing preventing a split and gets nothing back.")
//! @yah:handoff("DISCOVERED AND FIXED (1) — EXPIRY WAS STRUCTURALLY UNREACHABLE AND THIS TICKET COULD NOT HAVE SHIPPED WITHOUT IT. lease_renewal::plan_renewal renewed against current_leader ALONE. LeaseFailureDetector is per-node and starts empty, and its new silence() accessor answers None for a node it has never heard from — correctly, since never-heard-from is not evidence of death. Now kill the node that WAS the leader: it had been self-renewing in-process, so no peer ever received a renewal from it. A survivor wins the election, asks how long the recorded owner has been silent, and gets None — not 'silent for a long time' but 'no evidence at all', FOREVER, because a dead node never supplies the first sample. So a dead owner could never expire, on precisely the failure the lease exists for. Fixed by broadcasting the renewal to every member; POST /mesh/lease-renew was ALREADY unconditional and its doc already says a renewal landing on a follower is recorded, so only the client changed and no server or protocol change was needed. Cost is N-1 small POSTs per node per tick, noise at 3-5 voters, and it buys the property that no single node's death can blind the survivors. Peer-unreachable logging dropped from warn! to debug! in the same change — with a broadcast that fires once per down peer per tick from every survivor, and the signal that a peer is unreachable is its own silence, which is what this channel measures.")
//! @yah:handoff("DISCOVERED AND FIXED (2) — THE SHARED FakeRuntime MADE A CORRECT FENCE FAIL THE TESTS. test_cluster Arc-shares one runtime across all nodes, and raft_appliance_ownership's module doc argued that was honest because the local-supervisor answer was only consulted when the record named THIS node. T7 makes it load-bearing on exactly the nodes where it used to be ignored — the fence has to stop a node serving an appliance it does NOT own — so under one registry every node reads 'running here', fences, and tears down the cluster's only instance. Measured: all three pre-existing R858-T3 tests went red against a correct implementation. New yubaba_test_harness::test_cluster_with_runtimes, additive (test_cluster_local now takes a Vec; every existing public signature unchanged). All three T3 tests migrated to per-node runtimes and their module doc corrected rather than silently edited. That is strictly STRONGER for them: 'the appliance is still running' became 'still running ON THE SAME NODE', which is the claim their prose was already making.")
//! @yah:handoff("DISCOVERED AND FIXED (3) — Cluster::kill_node ALONE DOES NOT MODEL A POWER CUT. It shuts the raft actor down and aborts the HTTP server, so nothing can REACH the node. The per-node loops a test spawned are OUTBOUND clients holding their own clones of the raft handle, whose metrics watch keeps serving its last value after shutdown — so lease_renewal went on POSTing 'node N is alive' to every peer from a node with no power. Measured: the survivors' silence(dead) sat at ~300ms for the full 90 seconds after the kill, and the test hung at exactly the assertion it exists to make. Loops is now keyed by node index with a stop(idx), called before every kill and before every restart (a restart otherwise leaves two daemons' loops on one node). Same rule as the harness's own kill_node doc, one level up: a half-killed node is not a failure model, it is a different system.")
//! @yah:handoff("THE POWER-OFF TEST. Extended onto @Ashguard:libra's harness as instructed rather than built as a second one. Two new tests in oss/yubaba/crates/yubaba/tests/raft_appliance_ownership.rs, both on a real 3-node openraft with the real leader::spawn, the real member_registration::spawn AND the real lease_renewal::spawn. Running the production evidence producer instead of the harness's renew_lease shortcut is deliberate and it is what caught DISCOVERED (1): the leader-only-renewal bug is invisible to any test that injects the evidence by hand. The model is kill_node and NEVER bring it back — no systemctl stop, no transfer-leader, no teardown, no retraction, which is R858-T8's gotcha applied literally. (1) a_powered_off_owner_expires_and_the_appliance_comes_up_on_a_survivor: asserts a SURVIVOR is serving and the record has MOVED OFF the dead machine, neither of which any pre-T7 path can produce. Non-vacuity is structural — the appliance stays Running on the dead node's own supervisor (that is what a power cut means), so 'some node is serving' was already true before the kill and cannot be what it passes on. (2) a_resurrected_owner_is_fenced_and_cannot_serve: restart_node with its supervisor still holding a Running headscale — the honest model of both a resuming kamaji and the boot-persistent systemd unit — then asserts it stops, that the SURVIVOR's stays up, and that exactly ONE node serves, checked as a count so a third node quietly starting one is not invisible.")
//! @yah:handoff("FALSIFIED, each against the specific change it covers, each timing out at the right assertion rather than anywhere. (a) FENCE DISABLED (judge_self_fence's verdict replaced with Serve) -> a_resurrected_owner_is_fenced_and_cannot_serve fails after 90s 'waiting for the resurrected owner to fence itself off the appliance'. Its earlier failover legs still passed, so that final assertion demonstrably depends on the fence and on nothing else. (b) EXPIRE ARM DISABLED (expired_owner forced to None) -> a_powered_off_owner_expires... fails 'waiting for a survivor to expire the dead owner and stand the appliance up'. (c) LEASE BROADCAST REVERTED to the leader-only shape -> the same test, the same failure — which is the direct proof that DISCOVERED (1) was a real blocker and not a defensive rewrite. Each falsification was reverted immediately; `git diff` carries no falsification markers.")
//! @yah:handoff("TWO SMALLER FIXES IN THE SAME PASS, both inside the files this ticket already owned. (a) leader.rs's OwnershipDecision::OwnerServing(remote) arm logged at info! on EVERY tick. It is reached on every 10s tick of every leader that is not the owner, which under R858-T3's decoupling is the ORDINARY steady state, not an event — @Ashguard:libra measured us-west-001 reporting leader:false today while it is the node actually running the appliance. Dropped to debug!, which is verbatim the reasoning the arm immediately above already gives for its own steady state ('logging it at info! every ten seconds would bury the lines that mean something'); T3 clearly did not intend the inconsistency. (b) reconcile_appliance_ownership hit clippy's too_many_arguments at 8/7 from my two new parameters. Bundled rather than #[allow]ed, into RaftView{is_leader, has_leader} and ApplianceWatcher{election, ownership_confirmed_at}. RaftView's two booleans are deliberately NOT one: is_leader is AUTHORITY (only a leader may write SetIngressOwner) and has_leader is FRESHNESS (a node in contact with a leader is receiving AppendEntries, so its applied ingress_owner is at most one replication round behind). A follower has the second without the first, and the fence turns on exactly that distinction.")
//! @yah:gotcha("THE FENCE CHARGES A REAL AVAILABILITY COST AND IT IS ACCEPTED DELIBERATELY: TOTAL QUORUM LOSS NOW STOPS THE COORDINATOR TOO. FenceReason::ClaimUnconfirmed cannot distinguish 'I lost quorum and nobody else has it' from 'I lost quorum and the others have it and have elected a new owner'. From the holder's side those are the SAME observation — no leader, no confirmable record — so it must act on the worse one. Consequence: a cluster that loses a majority also loses its coordinator self_fence_after later (20s at the fleet preset), where before T7 it would have kept serving. This is the right trade and here is why: in the case it costs, no replacement can be elected either, so the mesh is degraded whatever happens; in the case it buys, it is the only thing preventing two coordinators. No refinement is available — in a three-voter cluster there is no observation a lone node can make that tells the two apart. Documented at judge_self_fence. If an operator decides differently, the lever is FenceTiming::SELF_FENCE_HEARTBEATS, and raising it requires raising EXPIRE_HEARTBEATS with it or the inequality inverts (the test will catch that).")
//! @yah:gotcha("MID-ROLL BEHAVIOUR DEGRADES TO PRE-T7, WHICH IS THE FAIL-SAFE DIRECTION — read this before the 0.8.33 wave. An un-rolled 0.8.32 node still renews leader-only, so a rolled node's detector may hold NO sample for it; silence() then answers None, which owner_lease_expired deliberately reads as NOT expiry. So mid-roll, expiry may simply not fire. The fence likewise only runs on rolled nodes. Neither direction can produce a false stop or a false failover — coverage is just incomplete until the wave finishes. Nothing about a partially-rolled fleet is worse than a wholly un-rolled one.")
//! @yah:gotcha("NOTHING IS ROLLED, AND NO LIVE NODE WAS TOUCHED. All of this is local source under oss/yubaba; it reaches a node only via a yubaba release + scripts/roll-node.sh. Every live node including us-west-001 still runs 0.8.32, which has neither the fence nor the expiry. Also worth recording against this ticket's own 'LIVE HAZARD' gotcha, which says `systemctl disable headscale` must be run on us-west-001 before the rehearsal: that action is ALREADY SATISFIED, and not by an operator. @Ashguard:libra measured on the box 2026-09-05 that `systemctl is-active headscale.service` = inactive and `is-enabled` = disabled, because yubaba's own start_headscale disables the unit whenever it takes the appliance under kamaji. The boot-persistence hazard dragon created on 2026-09-04 was removed by yubaba ~6.5h later. Re-check before the rehearsal rather than trusting this line — but do not plan a manual disable step around a bit that is already clear.")
//! @yah:verify("cargo test -p yubaba --lib = 759 passed / 0 failed (was 720 before this ticket; +39, of which 21 are R858-T7's own in appliance_ownership::tests and 5 are the rewritten lease_renewal::tests).")
//! @yah:verify("cargo test -p yubaba --features testing --test testing -- --test-threads 4 = 26 passed / 0 failed / 1 ignored. Includes the two new power-off tests AND the three pre-existing R858-T3 tests after their migration to per-node runtimes.")
//! @yah:verify("cargo test -p yubaba --test main -- --test-threads 4 = 64 passed / 0 failed. Run because the lease_renewal and yubaba-test-harness changes are shared surface — raft_tenant_placement and raft_leader_pin consume both.")
//! @yah:verify("cargo clippy -p yubaba --lib --tests --all-features --no-deps: ZERO findings in any file this ticket touched (leader.rs, appliance_ownership.rs, lease_detector.rs, lease_renewal.rs, tests/raft_appliance_ownership.rs). The one finding in yubaba-test-harness (lib.rs:144, needless borrow in WardenHandle::deploy_workload) is pre-existing and outside this change.")
//! @yah:verify("FALSIFICATION, three runs, each reverted: fence disabled -> a_resurrected_owner_is_fenced_and_cannot_serve times out at 'waiting for the resurrected owner to fence itself off the appliance'; expire arm disabled -> a_powered_off_owner_expires... times out at 'waiting for a survivor to expire the dead owner'; lease broadcast reverted to leader-only -> the same test, the same timeout. No test here passes before its fix.")
//! @yah:verify("NOT VERIFIED, STATED PLAINLY: nothing ran against a live node, a real headscale, a real kamaji or the R2 bucket. This is code + in-process integration tests only, per the ticket's 'change no live node'. The FakeRuntime stands in for kamaji, so 'the fence stopped the appliance' means the workload left that node's supervisor registry — it does not prove `systemctl disable --now headscale` behaves on a real box, and on a non-systemd host that call is a no-op by design.")
//! @yah:handoff("IS R858-T8'S REHEARSAL RUNNABLE ON THE DEV CLUSTER NOW? NO — and T7 is no longer what blocks it. Stated precisely so T8 does not re-derive it. T7 delivers T8's steps (2) EXPIRE and (3) FENCE; R858-T3 delivered (1) DETECT-wiring and (4) ELECT. What remains, in the order it bites: (i) NOTHING IS ROLLED. This is local source. Step one is building a yubaba carrying T3+T7 and rolling us-west-011/013/014; the dev cluster today runs a binary with neither. That is mechanical, not a design gap. (ii) R858-T4 is `handoff`, not done — target-node readiness. T3/T7 call probe_native_exec, so a node that cannot fork a native workload now refuses candidacy UP FRONT and loudly instead of failing after ownership moved, which is a real improvement; but if no dev node has a headscale binary + kamaji --native-exec-dir, the rehearsal ends at NoEligibleCandidate and proves nothing about failover. I did NOT verify what those three boxes have — this ticket changed no live node. (iii) R858-T5 is `open` and R858's own verify says it outright: 'no litestream restore or replicate has ever run against the new bucket. The bucket is empty.' So a new owner comes up with an empty DB. (iv) R858-T2 is `handoff` — without noise_private.key travelling, the new coordinator runs, looks healthy, and rejects every already-registered node, which is exactly the false green T8's own gotcha names as most likely.")
//! @yah:handoff("WHAT *IS* RUNNABLE ON DEV ONCE T3+T7 ARE ROLLED, and it is worth running before the rest lands, because it is the half that has never been demonstrated on real hardware: the OWNERSHIP half of T8. Power off the dev owner and watch (a) a survivor expire the record and claim it, (b) the record stop naming the dead machine, (c) power restored, and the old node NOT serve. That is decidable without T2/T5 — it does not care whether the new coordinator's database is any good, only who is permitted to serve. T8's full acceptance criterion ('an ALREADY-REGISTERED node reaches the tailnet through the new coordinator without re-registering') is the one that needs T2 and T5, and it should not be attempted before them. Splitting the rehearsal that way turns one blocked ten-step run into one runnable four-step run plus a gated remainder.")
//! @yah:handoff("R858-T7 COMPLETE. EXPIRE: a leader now widens decide_owner's candidate map with the recorded owner, as Confirmed::Down, once the node-lease channel says it has been silent past FenceTiming::expire_after — the record is then overwritten by SetIngressOwner, or ClearIngressOwner'd if nothing can take over. FENCE: appliance_ownership::judge_self_fence runs in leader.rs BEFORE the may_act early return, because the node that must be stopped is precisely one with no standing to act; it stops on a record naming another node, or on failing to confirm its own claim for self_fence_after. The fork was decided as a LEASE, not a raft epoch, with the reasoning in the handoff — an epoch cannot fence a node holding stale state, which is the power-off shape. Three defects were found and fixed along the way, one of which (leader-only lease renewal) made expiry structurally unreachable. Files: oss/yubaba/crates/yubaba/src/{appliance_ownership,leader,lease_detector,lease_renewal}.rs, crates/yubaba-test-harness/src/lib.rs, crates/yubaba/tests/raft_appliance_ownership.rs. Nothing rolled; no live node touched.")
//! @yah:assumes("The fence's freshness proxy is `raft metrics.current_leader.is_some()` — reasoned, not measured against a real partition. The argument: a node in contact with a leader is receiving AppendEntries, so its applied `ingress_owner` is at most one replication round behind, and the 10s fleet margin covers that by orders of magnitude. What I did NOT establish is openraft's exact behaviour for a leader that has lost quorum contact but has not yet stepped down — if `current_leader` stayed Some(self) through such a window, that node would keep refreshing its own ownership clock and would not self-fence. openraft has pre-vote and leader step-down (see tests/raft_pre_vote.rs) so this should be bounded by the election timeout, but I did not read the step-down path. Worth one read of openraft's leader-lease handling before the prod rehearsal; it does not affect the follower case, which is the common one.")
//! @yah:gotcha("DEAD-OWNER FENCING DOES NOT FIRE WHEN THE SURVIVING LEADER HAS NO LEASE HISTORY FOR THE DEAD OWNER — MEASURED 2026-09-08 by @Ashguard:libra (session:6eed47dc) on the dev raft group, found while completing R858-T5. DO NOT SIGN THIS OFF AS-IS. The sequence, every step measured: us-west-011 was the recorded ingress_owner and was stopped outright (yubaba+kamaji+litestream-headscale, no headscale process left). us-west-013 won the election (term 74) and then sat there. It hydrated config.yaml, its probe went Present, and it NEVER expired the dead owner or took the appliance — no further appliance line after startup, on a 10s reconcile cadence, indefinitely. THE CAUSE, read straight off 013's own /raft/status: the node-lease channel carries entries ONLY for 13 and 14 — node 11 is absent from it entirely — while the raft-heartbeat channel does list 11 as {\"silent_for_ms\": null, \"state\": \"unknown\"}. leader.rs's expired_owner filter calls owner_lease_expired(state.lease_detector.silence(11), timing), silence(11) is None, and owner_lease_expired is `silence.is_some_and(|s| s >= expire_after)` (appliance_ownership.rs:578) — so None is read as \"no evidence\" and the owner is never expired. CONSEQUENCE, which is this relay's own outage shape reproduced by construction: a leader that restarted after the owner died, or that was elected after the owner died, has no lease history for it and therefore can NEVER fail the appliance over. 30s of expire_after never elapses because the clock never starts. NOTE the anti-churn rule this collides with is deliberate and documented in leader.rs (\"the owner enters the map on positive evidence that it is gone, and on nothing else\"), so the fix is a design call, not a one-liner: absence of an entry after the detector's own uptime exceeds expire_after IS positive evidence, but seeding that naively would expire a live owner 30s after every cold boot. R858-T5 did NOT fix this — it completed its own assertion by wiping the owner's local DB and restarting the SAME node instead, so nothing here is exercised by that result.")

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kamaji::{name_anonymous_ports, WorkloadState, WorkloadStatus};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use workload_spec::{MeshIdent, WorkloadSpec};

/// Readiness signal for one [`ServiceRecord`], modeled after the
/// `/mesh/leader-health` 503 pattern: a proxy checks [`Health::is_ready`]
/// before selecting an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// The workload's last-known [`WorkloadStatus`] is `Running`. Safe to
    /// route traffic to.
    Ready,
    /// The workload exists in the runtime's own listing but is not
    /// currently able to serve (`Pending`, `Stopping`, `Stopped`,
    /// `Restarting`, `Failed`). `reason` is a short machine-stable tag, not
    /// prose, so callers can match on it.
    NotReady { reason: &'static str },
    /// The workload no longer appears in the runtime's authoritative list
    /// (torn down / undeployed). Kept distinct from `NotReady` so a
    /// consumer can tell "temporarily unhealthy" from "gone" if it cares;
    /// [`Health::is_ready`] treats both as `false`.
    Retracted,
}

impl Health {
    /// `true` only for [`Health::Ready`] — the single condition under which
    /// an ingress proxy should select this record's endpoint(s).
    pub fn is_ready(&self) -> bool {
        matches!(self, Health::Ready)
    }

    fn from_status(status: &WorkloadStatus) -> Self {
        match status {
            WorkloadStatus::Running => Health::Ready,
            WorkloadStatus::Pending => Health::NotReady { reason: "pending" },
            WorkloadStatus::Stopping => Health::NotReady { reason: "stopping" },
            WorkloadStatus::Stopped => Health::NotReady { reason: "stopped" },
            WorkloadStatus::Restarting { .. } => Health::NotReady {
                reason: "restarting",
            },
            WorkloadStatus::Failed { .. } => Health::NotReady { reason: "failed" },
        }
    }
}

/// [`Health::NotReady`] reason for a workload whose declared ports are bound
/// somewhere this node cannot name an address for (R881-B1).
///
/// Machine-stable like every other reason tag, and distinct from the
/// `WorkloadStatus`-derived ones on purpose: the workload is not sick. It is
/// *running perfectly* and unreachable, which is precisely the combination
/// that cost an operator a front-door hunt when it shipped as `ready`.
pub const REASON_UNROUTABLE: &str = "unroutable";

/// Does this workload bind its declared ports in the **node's** network
/// namespace — the only shape whose service record may advertise the node's
/// own address (R881-B1)?
///
/// Every [`ServiceRecord`] this node publishes carries *this node's* address
/// (R844-B11, and [`authoritative_mesh_ip`] re-asserts it every sweep). That is
/// honest exactly when the workload answers on that address, and the spec says
/// when it does:
///
/// - **`yah.network = "host"`** ([`WorkloadSpec::wants_host_network`]) — the
///   container shares the host netns and binds host ports directly. kamaji
///   permits it only for `tier = "infra"`.
/// - **`yah.docker.publish`** — the docker backend maps host ports onto the
///   container's (`docker run -p`). Only that backend publishes host ports at
///   all; the annotation is the operator's explicit request for it.
///
/// Anything else gets a fresh, empty netns with nothing but `lo`
/// (`kamaji-containerd-core`'s OCI builder emits a bare `{"type":"network"}`
/// with no path, so runc unshares one and stops). There is no veth, no bridge,
/// no CNI and no NAT rule anywhere in the deploy path, and the mesh IP reaches
/// such a container only as a label and an environment variable — never as an
/// interface address. So the node's address is not where it answers, and there
/// is no other address to name either.
///
/// `join_netns` is deliberately not consulted: both containerd deploy paths
/// hard-code it to `None` (its only intended use is passway's graceful-upgrade
/// fd handoff), so treating it as a reachable shape would be describing code
/// that does not run. If it ever becomes live, a container joining a
/// *host-networked* sibling's netns belongs on the `true` side of this
/// predicate and one joining an isolated sibling does not.
pub fn binds_node_ports(spec: &WorkloadSpec) -> bool {
    spec.wants_host_network()
        || spec
            .annotations
            .contains_key(crate::pond::launcher::PUBLISH_ANNOTATION)
}

/// One serving-workload's mesh endpoint(s) + health, as known to yubaba.
///
/// This is the record shape a future ingress proxy consumes: enough to
/// dial (`mesh_ip` + `ports`) and enough to gate routing (`health`).
///
/// @yah:ticket(R844-F15, "Service records carry NAMED ports — a peer resolving a service can ask for 'wss', not guess an index")
/// @yah:status(review)
/// @yah:at(2026-09-03T22:36:45Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R844)
/// @yah:next("`ServiceRecord.ports: Vec<u16>` (service_records.rs:295) is already plural but anonymous — a consumer gets three numbers and no way to tell which is the websocket listener. This, not allocation, is the actual blocker for cross-mesh service discovery.")
/// @yah:next("Move to `ports: BTreeMap<String, u16>` and keep a derived ordered accessor so `endpoints()` (service_records.rs:341) and the ingress renderer keep working unchanged.")
/// @yah:next("Mirror the same change into `ServiceRecordWire.ports` (service_records.rs:995) and the pre-joined `endpoints` field (service_records.rs:1008) — a wire consumer should be able to select an endpoint by port name.")
/// @yah:next("The 15s service-record sweep already re-asserts every resolved port on each pass; names ride the same path with no new machinery.")
/// @yah:verify("A workload declaring http+wss produces one record whose named map resolves both, and `endpoints()` still yields one endpoint per port in a stable order.")
/// @yah:verify("The existing multi-port test (`deployed_workload_with_multiple_ports_yields_multiple_endpoints`, service_records.rs:1265) passes unmodified or with a name-keyed equivalent.")
/// @yah:verify("A wire round-trip (ServiceRecords -> ServiceRecordsWire -> back) preserves port names.")
/// @yah:handoff("LANDED. Ports are named end to end. `ServiceRecord.{ports,resolved_ports}` and `kamaji::{WorkloadState,DeployResult}.ports` are now `BTreeMap<String,u16>`; `ServiceRecord` gained `port(name)`, `endpoint(name)`, `named_endpoints()` and `dialable_port_numbers()`; `endpoints()` keeps its old contract (one endpoint per distinct port, ascending by NUMBER not by name, so a `[8080,9090]` workload renders exactly as before). `kamaji_proto::WorkloadEntry` gained `named_ports` (protocol V6) so names survive the sibling wire; `ServiceRecordWire` gained `named_ports` + `named_endpoints`.")
/// @yah:handoff("THE NAMING RULE IS THE DESIGN, and the obvious version of it is wrong. `kamaji::name_anonymous_ports` (kamaji/src/lib.rs) is the single place that names a portless declaration: a SOLE anonymous port becomes `http`; SEVERAL anonymous ports each become their own number and NONE becomes `http`. I first wrote first-is-http, and `yah-cloud`'s existing `two_ports_on_one_ident_is_ambiguous_rather_than_a_guess` caught it — that rule would let `port_for` resolve an ingress rule off declaration order and publish a hostname at whichever listener was written first, which is the positional guess this ticket exists to abolish. Pinned by kamaji::tests::several_anonymous_ports_name_none_of_themselves_http and naming_is_independent_of_declaration_order.")
/// @yah:handoff("TWO WIRES, TWO DIFFERENT COMPATIBILITY RULES — the bug I shipped and fixed mid-relay, worth reading before anyone adds a field to either. yubaba's `GET /service-records` is JSON over HTTP between independently-versioned binaries on a mixed fleet (0.8.28-0.8.31), so `ports`/`endpoints` keep their array shape forever and the named views are ADDITIVE; `WIRE_VERSION` does not move. kamaji-proto is POSTCARD — positional, no field names — where `skip_serializing_if` is not 'optional', it omits bytes the decoder still reads, producing frames a peer of its OWN version cannot parse. I carried the JSON reasoning onto the postcard wire and broke `List` with `PeerClosed` on both sibling_wire_e2e and docker_backend_e2e. Fix: drop `skip_serializing_if`, bump `ProtocolVersion::CURRENT` to V6. The rule is now written into the V6 stanza in kamaji-proto/src/version.rs so a fourth person does not pay for it.")
/// @yah:handoff("DOWNSTREAM PAYOFF, in scope and delivered: `ServiceRecordFanout::port_for` (cloud/src/reconciler/service_discovery.rs) used to return None for ANY multi-port workload, which forced such a slot to pin `port` forever — the exact pin R844 exists to remove. It now selects the port named `kamaji::DEFAULT_PORT_NAME` when the read is otherwise ambiguous. Single-port and unnamed records resolve identically to before, and two nodes disagreeing about which port is `http` is still None. `DiscoveredRecord` gained `named_ports`, plumbed from the CLI's `RecordWire` (app/yah/cli/src/cloud.rs).")
/// @yah:handoff("PASSWAY WAS DELIBERATELY NOT CHANGED, and this is a live gap rather than a finished handover. `addrs_from_body` (oss/passway/crates/passway/src/discovery.rs) still flattens every endpoint of every ready record into one backend set, which is silently wrong for a workload with `http` + `metrics`. Nothing has hit it because no fronted workload declares two ports yet. `named_endpoints` on the wire is what will let passway fix it; changing a separate binary's backend selection with no ticket was out of my blast radius. Recorded in the `ServiceRecordWire::named_endpoints` doc at the code site.")
/// @yah:handoff("DISCOVERED WORK DONE IN THIS PASS, beyond the ticket title: (1) fixed the stale `DeployResult.ports` doc citing the removed `ports::PortAllocator::resolve` — flagged by @Ashguard:libra, now says a declared NAME is the request and a declared NUMBER is refused unless it is in `ports::WORLD_FIXED_PORTS`; (2) corrected a module-doc claim in service_records.rs asserting `WorkloadState` carries no ports, false since R844-F2 and disproved by this very change; (3) updated `.yah/docs/guides/write-a-service-toml.md` with the port-naming contract beside F14's `port` guidance; (4) swept every `WorkloadState`/`DeployResult` construction outside oss/yubaba — crates/yah/hub/src/workload.rs (3 sites) and xtask/tests/mirror_ingress.rs (2 fixtures), neither visible from a `cargo check` inside oss/yubaba, both found only because @Ashguard:griffin grepped wider.")
/// @yah:handoff("COORDINATION, all resolved, no unresolved seams. @Ashguard:libra (R844-F14) and I split at `kamaji::WorkloadState`/`DeployResult`: they kept kamaji/src/ports.rs entirely, I took the field types plus every producer and the kamaji-proto wire; agreed by party.chat before either of us touched it. @Ashguard:griffin (R844-B11) fixed a red test my run surfaced — integration_service_records::deploy_publishes_a_ready_dialable_record was asserting the CGNAT pool against B11's `workload_bind_ip()` loopback fallback, their ticket's semantics, so I reported it rather than authoring on it. @Ashguard:libra (R844-F16) is building `yah cloud ingress verify` against `ServiceRecordFanout`, whose public API this change does not touch.")
/// @yah:verify("yubaba: `cargo test -p yubaba --lib service_records` = 45 passed / 0 failed. `cargo test -p yubaba --features testing --test testing -- integration_service_records::` = 11 passed / 0 failed (includes @Ashguard:griffin's B11 fix landing in the same file).")
/// @yah:verify("yubaba workspace: `cargo test --workspace` in oss/yubaba = 1008 + 634 + smaller suites all ok, yah-cloud lib 1000 passed / 0 failed, service_discovery 27 passed / 0 failed. ONE CAVEAT, measured not assumed: 11 raft membership/quorum tests FAILED in that fully-parallel run and then passed 47/0 on re-run with `--test-threads=2`. They spawn real raft clusters and bind real ports; nothing in this change touches raft or service records from those paths.")
/// @yah:verify("kamaji: `cargo test --workspace --all-features` in oss/kamaji = zero failures across every target (kamaji-bin lib 272/0, kamaji lib 39/0). The two wire e2e suites that the postcard bug broke and this fix restored: `--test sibling_wire_e2e` = 2 passed / 0 failed, and @Ashguard:libra re-ran `--test docker_backend_e2e --all-features` = 2 passed / 0 failed on this tree.")
/// @yah:verify("The R844 purity canary, run from the repo root because it lives outside the oss/yubaba workspace: `cargo test -p xtask --test main mirror_ingress` = 11 passed / 0 failed.")
/// @yah:verify("Whole tree: `cargo check --workspace --tests` from the repo root = 0 errors. This is the run that caught the three `crates/yah/hub/src/workload.rs` sites a workspace-local check could not see.")
/// @yah:verify("The ticket's three stated criteria, each with the test that pins it: (1) http+wss resolves both by name and endpoints() still yields one endpoint per port in stable order -> service_records::tests::a_workload_serving_http_and_wss_resolves_both_ports_by_name; (2) the multi-port test still passes -> deployed_workload_with_multiple_ports_yields_multiple_endpoints, UNMODIFIED; (3) a wire round-trip preserves port names -> wire_round_trip_preserves_port_names, plus the_wire_stays_readable_to_a_consumer_that_has_never_heard_of_port_names asserting the JSON keys an un-rolled reader depends on are unchanged in name, type and value.")
/// @yah:verify("Restart survival was re-verified rather than assumed, because it is what the ledger exists for: `LEDGER_VERSION` deliberately did NOT move, and `LedgerEntry` reads both the old `[8080]` and the new `{\"http\":8080}` via a custom deserializer. A version bump would have discarded the ledger on precisely the boot that installs this binary, leaving every serving workload undialable until its next deploy. Pinned by a_ledger_written_before_port_names_still_rehydrates and port_names_survive_the_ledger_round_trip.")
/// @yah:verify("NOT VERIFIED, stated plainly: nothing was run against a live fleet node, and the V6 protocol bump means a node's yubaba and kamaji must be rolled together — which is the documented one-node blast radius of this UDS protocol (version.rs), not a fleet flag-day. The JSON discovery wire is unaffected by that bump and stays readable to every un-rolled consumer.")
#[derive(Debug, Clone)]
pub struct ServiceRecord {
    /// Mesh identity (`expose.mesh.identity` on the [`WorkloadSpec`]) —
    /// the DNS-segment name other workloads (and now the ingress proxy)
    /// address this workload by.
    pub ident: MeshIdent,
    /// Mesh-plane IPv4 address another node dials this workload at.
    ///
    /// Always the **answering node's own** mesh address (R844-B11) — both the
    /// container tier (`ServerState::workload_bind_ip`, echoed through
    /// `DeployResult.mesh_ip`) and the bundle tier
    /// (`ServerState::node_mesh_ip`, via [`ServiceRecords::admit_bundle`]) put
    /// the same value here, because that is the only address anything actually
    /// configured. A record whose `mesh_ip` is some *other* node's address is
    /// the R844-B11 bug, not a workload with its own mesh identity.
    pub mesh_ip: Ipv4Addr,
    /// Port(s) the workload **declared**, keyed by port name —
    /// `expose.mesh.ports` for a container, `serve_bundle.port` for a W272
    /// bundle. A request, made at admission time, before anything bound.
    ///
    /// Both of those declaration surfaces are still anonymous number lists, so
    /// the names here are synthesized by [`kamaji::name_anonymous_ports`] —
    /// `http` for the first, its own number for each of the rest. That is the
    /// same function every other tier uses, so one workload's ports are spelled
    /// identically in a record, in a kamaji entry and in the `PORT_<NAME>`
    /// environment (R844-T13). Once a manifest spells `ports = ["http", "wss"]`
    /// the real names arrive and no synthesis happens.
    pub ports: BTreeMap<String, u16>,
    /// Port(s) the supervisor **actually bound**, keyed by port name, as
    /// reported by `kamaji::WorkloadState::ports` on the refresh sweep
    /// (R844-F2; named by R844-F15).
    ///
    /// Deliberately a separate field rather than overloading [`Self::ports`],
    /// because they are different facts that can disagree and the disagreement
    /// is the interesting part: a declared port that never got bound is a
    /// misconfiguration, and a resolved port with no declaration is the normal
    /// state once a mirror stops naming one. Collapsing them would erase the
    /// only evidence of either.
    ///
    /// Empty means the supervisor reported no resolved port — either a
    /// namespaced container backend, where the declaration *is* the bound port
    /// and there is nothing to resolve, or a workload that has not bound yet.
    /// Dial [`Self::dialable_ports`], not this.
    pub resolved_ports: BTreeMap<String, u16>,
    /// Backend-assigned container/task id, useful for correlating a record
    /// with logs or `docker`/`containerd` inspection.
    pub container_id: String,
    /// Current readiness.
    pub health: Health,
    /// Whether [`Self::mesh_ip`] is an address this workload actually answers
    /// on — [`binds_node_ports`] evaluated against its [`WorkloadSpec`] at
    /// admission (R881-B1).
    ///
    /// **A record, not a side table, because the fact has to survive a
    /// restart.** The spec is available exactly once, at deploy; every later
    /// sweep sees only a `kamaji::WorkloadState`, which carries no netns shape.
    /// Held anywhere non-persistent, the first `reconcile` after a yubaba
    /// restart would rehydrate the record from the ledger and promote it
    /// straight back to `Ready` off `WorkloadStatus::Running` — re-publishing
    /// the dead upstream this field exists to withhold.
    ///
    /// `false` pins [`Self::health`] to
    /// `NotReady { reason: `[`REASON_UNROUTABLE`]` }` on every path, so the
    /// record still appears in `GET /service-records` (with the reason, for the
    /// operator) and never in `?ready=true` (for the front door).
    pub routable: bool,
    /// Wall-clock time (Unix ms) this record was last written. Lets a
    /// consumer notice a record that hasn't been refreshed in a long time
    /// even if `health` still says `Ready` (staleness, not correctness).
    pub observed_at_unix_ms: u64,
}

impl ServiceRecord {
    /// The port(s) a proxy should actually dial: what the supervisor bound
    /// when it reported that, and what the workload declared otherwise
    /// (R844-F2).
    ///
    /// Resolved wins because it is a measurement and the declaration is a
    /// request. The fallback is not a courtesy — it is what the container tier
    /// runs on: a namespaced container's declared port *is* its bound port, so
    /// its backend reports no resolved set and never will.
    ///
    /// The whole map is returned rather than a slice of numbers so a caller can
    /// select the port it actually means — see [`Self::port`].
    pub fn dialable_ports(&self) -> &BTreeMap<String, u16> {
        if self.resolved_ports.is_empty() {
            &self.ports
        } else {
            &self.resolved_ports
        }
    }

    /// The dialable port called `name`, if this workload has one (R844-F15).
    ///
    /// This is the reason the map exists. A consumer holding three bare numbers
    /// has to guess which one is the websocket listener — by index, or by a
    /// convention nothing enforces — and is wrong the first time a port moves
    /// or the declaration order changes. Asking for `wss` cannot be wrong in
    /// that way: it either resolves or it doesn't.
    pub fn port(&self, name: &str) -> Option<u16> {
        self.dialable_ports().get(name).copied()
    }

    /// `mesh_ip:port` for the dialable port called `name` — [`Self::port`]
    /// paired with the address, so a caller never re-derives the join.
    pub fn endpoint(&self, name: &str) -> Option<SocketAddrV4> {
        self.port(name).map(|p| SocketAddrV4::new(self.mesh_ip, p))
    }

    /// `mesh_ip:port` for every dialable port, keyed by port name. Empty if the
    /// workload has no known ports at all (a valid but proxy-uninteresting
    /// shape).
    pub fn named_endpoints(&self) -> BTreeMap<String, SocketAddrV4> {
        self.dialable_ports()
            .iter()
            .map(|(name, &port)| (name.clone(), SocketAddrV4::new(self.mesh_ip, port)))
            .collect()
    }

    /// `mesh_ip:port` for every dialable port, **one entry per distinct port,
    /// ascending by port number**. Empty if the workload has no known ports at
    /// all.
    ///
    /// Ordered by number rather than by name on purpose. Name order would sort
    /// `9090` before `http` (ASCII digits precede letters), which is stable but
    /// silently reverses what every existing consumer saw for a workload
    /// declaring `[8080, 9090]`; numeric order reproduces the old behaviour
    /// exactly while still being independent of declaration order. Two names
    /// pointing at one port (an alias) collapse to one endpoint — this answers
    /// "where can I connect", and that is one place.
    ///
    /// Use [`Self::named_endpoints`] or [`Self::endpoint`] when it matters
    /// *which* listener you reach.
    pub fn endpoints(&self) -> Vec<SocketAddrV4> {
        self.dialable_port_numbers()
            .into_iter()
            .map(|port| SocketAddrV4::new(self.mesh_ip, port))
            .collect()
    }

    /// Every distinct dialable port number, ascending — the anonymous view of
    /// [`Self::dialable_ports`] that the wire's back-compatible `ports` array
    /// and [`Self::endpoints`] are both built from.
    pub fn dialable_port_numbers(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.dialable_ports().values().copied().collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Convenience passthrough — see [`Health::is_ready`].
    pub fn is_ready(&self) -> bool {
        self.health.is_ready()
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// In-process, push-on-change registry of [`ServiceRecord`]s.
///
/// Cheap to hold behind an `Arc` on `ServerState` (mirrors how
/// `pond_registry` is already wired): interior state is a
/// `tokio::sync::watch` channel keyed by mesh identity, so both a
/// synchronous snapshot read and a push subscription come from the same
/// single-slot cell.
pub struct ServiceRecords {
    tx: watch::Sender<Arc<HashMap<String, ServiceRecord>>>,
    /// Where the port ledger lives. `None` disables persistence entirely
    /// (tests, and the embedded/camp path that has no durable state dir) —
    /// every other operation behaves identically either way.
    ledger_path: Option<PathBuf>,
    /// Idents yubaba has **declared to be serving** — the eligibility set for
    /// [`Self::reconcile`]'s cold-admission arm (R844-F2).
    ///
    /// Deliberately NOT the record map. A record needs a declaration *and* a
    /// dialable port; this set is the first half on its own, which is exactly
    /// the state a bundle sits in between "admitted with no declared port" and
    /// "the supervisor reported the port it bound". Without somewhere to hold
    /// that, cold admission has no way to tell a workload yubaba placed from
    /// one kamaji forked for itself.
    ///
    /// Not persisted, and it does not need to be: once cold admission fires,
    /// the resulting record goes in the ledger, and a restart rehydrates it
    /// onto the *refresh* path rather than the cold-admit path. Rehydration
    /// re-declares each recovered ident so the two stay consistent.
    serving: Mutex<HashSet<String>>,
}

/// File name of the port ledger, written beside `identity.json` in the
/// yubaba state directory. See module docs §The port ledger.
pub const LEDGER_FILE_NAME: &str = "service-records.json";

/// Schema version of [`LedgerFile`]. Bump when the on-disk shape changes
/// incompatibly; an unrecognized version is treated as "no ledger" (warn +
/// start empty) rather than an error, since a yubaba that refuses to boot
/// over a stale bookkeeping file is worse than one that re-learns on the
/// next deploy.
const LEDGER_VERSION: u32 = 1;

/// One persisted record. Deliberately only the *recovered facts* — health is
/// not persisted, because health is exactly the thing a restart invalidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerEntry {
    ident: String,
    mesh_ip: Ipv4Addr,
    /// Named since R844-F15, and read through [`de_ports`] so a ledger written
    /// by an older yubaba — where this was a bare `[8080]` — still loads.
    ///
    /// That tolerance is the point of the ledger, not a nicety: this file
    /// exists so records survive a restart, and the restart that matters most
    /// is the one that installs the new binary. A version bump would have
    /// discarded the whole file on exactly that boot (see [`LEDGER_VERSION`]),
    /// leaving every serving workload undialable until its next deploy.
    #[serde(deserialize_with = "de_ports")]
    ports: BTreeMap<String, u16>,
    /// R844-F2. `#[serde(default)]` so a ledger written before this field
    /// existed still loads — the first sweep after boot re-learns the resolved
    /// ports from the supervisor anyway, so an old ledger costs nothing. Same
    /// both-shapes tolerance as [`Self::ports`].
    #[serde(default, deserialize_with = "de_ports")]
    resolved_ports: BTreeMap<String, u16>,
    container_id: String,
    /// R881-B1 — [`ServiceRecord::routable`], the one recovered fact that
    /// cannot be re-derived after a restart (the `WorkloadSpec` it comes from
    /// is gone; sweeps see only a `kamaji::WorkloadState`).
    ///
    /// Defaults to `true` for a ledger written before this field existed, and
    /// that direction is deliberate. Every workload in such a ledger was
    /// admitted `Ready` by the yubaba that wrote it, so `true` reproduces the
    /// old binary's behaviour exactly; `false` would silently withdraw every
    /// live upstream on the boot that installs the new binary — an outage
    /// produced by a default. The next deploy of an unroutable workload writes
    /// the honest value.
    #[serde(default = "ledger_routable_default")]
    routable: bool,
}

/// See [`LedgerEntry::routable`] — pre-R881-B1 ledgers predate the field and
/// held only workloads their writer considered routable.
fn ledger_routable_default() -> bool {
    true
}

/// Deserialize a port set written either as a named map (`{"http": 8080}`, the
/// shape R844-F15 writes) or as the anonymous array (`[8080]`) every yubaba
/// before it wrote.
///
/// An anonymous array is named by [`kamaji::name_anonymous_ports`], the same
/// function the live paths use, so a rehydrated record is indistinguishable
/// from a freshly-admitted one rather than being a second, subtly different
/// naming of the same ports.
fn de_ports<'de, D>(d: D) -> Result<BTreeMap<String, u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Named(BTreeMap<String, u16>),
        Anonymous(Vec<u16>),
    }
    Ok(match Either::deserialize(d)? {
        Either::Named(m) => m,
        Either::Anonymous(v) => name_anonymous_ports(&v),
    })
}

/// On-disk shape of the port ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerFile {
    version: u32,
    services: Vec<LedgerEntry>,
}

impl Default for ServiceRecords {
    fn default() -> Self {
        Self::new()
    }
}

/// @yah:ticket(R876-B3, "yubaba publishes a service record for another node's mesh_ip and marks it ready, violating the R844-B11 per-node invariant")
/// @yah:at(2026-09-09T08:24:05Z)
/// @yah:status(review)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R876)
/// @yah:severity(medium)
/// @yah:gotcha("MEASURED LIVE 2026-09-09, three independent probes. `curl http://100.64.0.1:7443/service-records` on us-west-001 returns one record: ident `yah-cloud-admin`, `\"mesh_ip\":\"100.64.0.3\"`, `\"endpoints\":[\"100.64.0.3:4325\"]`, `\"health\":\"ready\"`. But (a) the workload actually runs ON us-west-001 — `ss -lntp` there shows `100.64.0.1:4325` bound by pid 502611 /usr/local/bin/yah-cloud-admin under containerd shim 502590; (b) us-west-001's own yubaba binds 100.64.0.1:7443 and its tailscale0 is 100.64.0.1/32; (c) on us-east-001 (100.64.0.3) NOTHING is listening on 4325, there is no cloud-admin process, and its own /service-records lists only `noisetable` and `yah-marketing`. So west publishes a ready-marked, dialable-looking endpoint at an address where the service does not exist.")
/// @yah:next("WHY IT MATTERS RATHER THAN BEING COSMETIC: this is the same discovery rail the yah.dev apex rides. Both yah.dev doors run `PASSWAY_UPSTREAM_SOURCE=yubaba` and take address AND port from these records, so a record that names the wrong node with `health: ready` is indistinguishable to a door from a correct one — it routes to a dead endpoint and reports success. service_records.rs states the invariant explicitly (\"A record's `mesh_ip` must equal the answering node's own mesh address\", R844-B11) and nothing enforces it at write time.")
/// @yah:next("WHERE TO START, traced but not fixed. `ServiceRecords::reconcile` (oss/yubaba/crates/yubaba/src/service_records.rs:1008) takes `node_mesh_ip` as the COLD-ADMIT fallback only: at :1021 it does `if let Some(ip) = state.mesh_ip { record.mesh_ip = ip }`, preferring the backend's report unconditionally, and at :1037 `state.mesh_ip.or(node_mesh_ip)`. `WorkloadState::mesh_ip` (oss/kamaji/crates/kamaji/src/lib.rs:295) carries the deploy-time `MeshAssignment::mesh_ip` (lib.rs:217), assigned from raft's 100.64.0.0/10 pool — so a stale or cross-node assignment propagates straight into a published record. The candidate fix is that reconcile should REFUSE (or override + warn) a state whose mesh_ip disagrees with node_mesh_ip, since the module doc already declares that case impossible. Confirm the assignment's provenance before choosing between refuse and override — a host-networked containerd workload arguably should not be carrying a pool-assigned mesh_ip at all.")
/// @yah:next("Tier: Cleric — the measurement is done and the seam is named, but choosing between refusing the record and overriding it needs reading how MeshAssignment is populated for a host-networked containerd workload, and the fix lands in the rail the production apex discovers through.")
/// @yah:handoff("FIXED AT THE WRITE BOUNDARY, override + warn, and the upstream half is ANSWERED rather than open. (a) New private `authoritative_mesh_ip(state, node_mesh_ip)` in oss/yubaba/crates/yubaba/src/service_records.rs, called from BOTH arms of `ServiceRecords::reconcile`: the refresh arm (was `if let Some(ip) = state.mesh_ip { record.mesh_ip = ip }`, took the backend's report unconditionally) and the cold-admit arm (was `state.mesh_ip.or(node_mesh_ip)`). `node_mesh_ip` now WINS whenever it exists; a disagreeing `state.mesh_ip` is overridden and `tracing::warn!`-ed with ident, container_id, reported_mesh_ip and node_mesh_ip. `node_mesh_ip: None` (dev host, no mesh plane) is unchanged — the backend's report passes through and cold admission still declines on a state reporting none. Override not refuse, per the ticket's decision: refusing converts a wrong-address bug into a service-vanishes bug, and passway's `addrs_from_body` would simply lose the apex upstream. warn! not debug! because a wrong address carrying `health: ready` is indistinguishable from a right one to every consumer, so this log is the only place the defect is visible.")
/// @yah:handoff("(b) THE UPSTREAM IS ALREADY FIXED — R844-B11 DID IT — AND THE WRONG VALUE SURVIVES THAT FIX AS PERSISTED CONTAINER STATE. That is the finding, read end to end, and it is why (a) is not merely a correction on the way out but the ONLY thing that repairs the live fleet. (1) No live code path assigns a foreign address any more: `alloc_mesh_ip` and its `next_mesh_ip: AtomicU32` are DELETED; the container deploy path is `MeshAssignment::stub(s.workload_bind_ip())` at oss/yubaba/crates/yubaba/src/lib.rs:3772, the pond/leader paths use `MeshAssignment::inlined(<own or loopback>)`, and `workload_bind_ip()` (lib.rs:1744) is `self.node_mesh_ip.unwrap_or(LOCALHOST)`. Every `MeshAssignment::{stub,inlined}` construction site in oss/ and crates/ was enumerated; none draws from a pool. (2) But the address is DURABLE STATE on the container, not a value recomputed per sweep: containerd writes it as the `yah.mesh_ip` label at deploy (oss/kamaji/crates/kamaji/src/containerd.rs:411) and reads it straight back into `WorkloadState::mesh_ip` on every `list_workloads` (:872) and `get_workload` (:917); docker.rs:414/:283 is the same mechanism. So `yah-cloud-admin` on us-west-001 — placed by a pre-B11 yubaba as that process's 3rd container deploy, hence 100.64.0.3 — keeps reporting east's address forever, and the refresh arm kept re-asserting it into the published record. NOTHING was left to fix upstream, so (a) is the whole code fix. (3) Clearing it AT SOURCE on the live fleet is a redeploy of yah-cloud-admin on us-west-001 — a production action, operator's call, deliberately not taken here. After (a) the published record is correct without it; the redeploy only silences the recurring warn.")
/// @yah:handoff("DISCOVERED WORK, fixed in this pass: a doc-comment claim on `ServerState::workload_bind_ip` (oss/yubaba/crates/yubaba/src/lib.rs, R844-B11's own text) said loopback \"is the honest answer for the isolated-netns shape too\". The one line under it cannot do that — it keys on whether THIS NODE has a mesh plane, not on the workload's shape — so an isolated-netns container on a mesh node gets the node's own address and would advertise a port nothing on the host is listening on. Nothing live hits it (the fleet's one container workload is host-networked, `.yah/infra/workloads/yah-cloud-admin.toml` sets `\"yah.network\" = \"host\"`), and correcting the BEHAVIOUR needs the `WorkloadSpec` that function is deliberately not given — so the claim is replaced by a paragraph naming the real gap instead. Doc-only; no behaviour change. TEST DEBT PAID, and it is the falsification proof for the new override test: `reconcile_refreshes_mesh_ip_when_it_changes` asserted the exact opposite of the fix (deploy at 100.64.0.9, backend reports 100.64.0.10, node is 100.64.0.3, assert the record moved to .10) and passed on the baseline. A per-node store has no \"the workload moved to another node\" case, so what it pinned was the bug; it is rewritten as `reconcile_reasserts_the_node_address_and_leaves_ports_alone`. `first_sweep_promotes_a_rehydrated_record_to_ready` had the same incoherent data (deploy at .22, sweep node .3) and now uses the node's own address — it is about ready-promotion, not addresses.")
/// @yah:verify("BASELINE MEASURED BEFORE ANY EDIT, then re-measured after. `cargo test -p yubaba --lib`: baseline 861 passed / 0 failed -> after 864 passed / 0 failed (+3 = the three new tests; the 4th change is a rename, not an addition). `cargo build -p yubaba`: clean, twice, the second run after the lib.rs doc correction. `cargo test -p yubaba --features testing --test testing` (the group that holds integration_service_records): 29 passed / 0 failed / 1 ignored. `cargo test -p yubaba --test main`: baseline 54 passed / 14 failed -> after 49 passed / 19 failed. NOT MINE, and the evidence is that the failing SET differs between the two runs rather than growing: every failure in both is a raft_*/rig_singleton_ownership test that stands up a real 3-node openraft cluster on loopback and dies on \"leader election timed out after 15s during cluster bootstrap\"; baseline failed raft_add_learner + raft_promote_voter, the after-run passed those and failed raft_leader_pin + raft_tenant_placement instead. That is load flap on a camp running many concurrent builds. The one main-group test that touches this rail, integration_deploy_through_kamaji::a_refused_bundle_deploy_publishes_no_service_record, PASSED in the after-run. Three runs also carried a W298 rung-0 skew advisory naming peers' in-flight edits (cloud/src/reconciler/mesofact_bundle.rs, yah-base/crates/mesofact-bundle/src/{assemble,lib}.rs, yubaba/src/demux_routes.rs) - none in the -p yubaba lib closure that the service_records tests exercise.")
/// @yah:verify("THREE UNIT TESTS ON `reconcile`, in oss/yubaba/crates/yubaba/src/service_records.rs, each named for the case the ticket asked for. (1) `reconcile_leaves_an_agreeing_mesh_ip_alone_and_says_nothing` - agreeing report: record unchanged, endpoint still dialable, and NOTHING warned (this is the non-vacuity anchor for (2); without it a helper that warned unconditionally would pass). (2) `reconcile_overrides_a_backend_reporting_another_nodes_mesh_ip` - the measured shape verbatim: node 100.64.0.1, backend reports 100.64.0.3, asserts the record carries .1, is STILL ready (not withdrawn), resolves to 100.64.0.1:4325, and that the warning text names the ident AND both addresses. (3) `cold_admission_still_falls_back_to_the_node_address` - backend reports no address at all: still cold-admitted at the node's, dialable, and silent. Warnings are captured with a thread-local `tracing::subscriber::with_default` + a small MakeWriter (`capture_warnings` helper), so the assertion is on what was really emitted and stays correct under cargo's parallel test threads. FALSIFICATION for (2) comes free from the baseline rather than from a probe edit: the pre-existing `reconcile_refreshes_mesh_ip_when_it_changes` asserted the EXACT OPPOSITE on the same code path (assert the record moved to the backend's foreign address) and was green in the 861-pass baseline, so the old code demonstrably fails the new assertion.")
/// @yah:verify("STEP-0 FAVOUR FOR THE SIBLING COURIER (apex_failover), both checks pass, nothing touched. `cargo test -p xtask --test main -- apex_failover`: 4 passed / 0 failed / 61 filtered out - the harness is the single `xtask/tests/main.rs` binary and `mod apex_failover;` is registered at main.rs:5, so the filter runs them as `apex_failover::*`. `git status --porcelain .yah/infra/machines/us-east-001.toml`: EMPTY - the temporary edit was restored byte-exactly as claimed.")
/// @yah:handoff("LEADER DECISION, so the ticket's open \"refuse vs override+warn\" question is settled and should not be reopened: OVERRIDE + WARN, because the record store is node-local by construction and the answering node's own address is therefore authoritative — a backend's self-report about a DIFFERENT node's address is never the more trustworthy of the two. Refusing was rejected as the worse trade: it converts a wrong-address bug into a service-vanishes bug on the exact rail the yah.dev apex discovers through.")
/// @yah:verify("LEADER RE-VERIFICATION by an independent second session (@Miravel:libra, session:d24aac7e), and it came back BETTER than the implementing courier reported. The courier attributed a 54p/14f -> 49p/19f move on yubaba's `main` integration binary to pre-existing raft/rig election flap; two clean re-runs of that binary returned 68 passed / 0 failed BOTH times, with no service_records or mesh_ip failure in either. The service_records unit tests are 49/0. So the reported regression did not reproduce at all and the failures the courier saw were camp load, not this change.")
impl ServiceRecords {
    /// In-memory only — nothing is persisted and nothing is rehydrated.
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(Arc::new(HashMap::new()));
        Self {
            tx,
            ledger_path: None,
            serving: Mutex::new(HashSet::new()),
        }
    }

    /// Rehydrate from the port ledger at `path` (missing/corrupt → empty) and
    /// keep writing it on every subsequent publish.
    ///
    /// Recovered records come back `NotReady { reason: "rehydrated" }`, never
    /// `Ready` — see module docs §The port ledger for why.
    pub fn with_ledger(path: PathBuf) -> Self {
        let mut records = HashMap::new();
        for entry in load_ledger(&path) {
            records.insert(
                entry.ident.clone(),
                ServiceRecord {
                    ident: MeshIdent(entry.ident),
                    mesh_ip: entry.mesh_ip,
                    ports: entry.ports,
                    resolved_ports: entry.resolved_ports,
                    container_id: entry.container_id,
                    routable: entry.routable,
                    health: Health::NotReady {
                        reason: "rehydrated",
                    },
                    observed_at_unix_ms: now_unix_ms(),
                },
            );
        }
        if !records.is_empty() {
            tracing::info!(
                count = records.len(),
                ledger = %path.display(),
                "service_records: rehydrated port ledger; records stay not-ready \
                 until the first reconcile sweep confirms the workloads are live"
            );
        }
        // R844-F2: a rehydrated ident was declared serving in a prior life —
        // the ledger entry IS that declaration, persisted. Re-declaring keeps
        // the eligibility set consistent with the records across a restart, so
        // a workload whose record was later retracted (backend blip, say) can
        // still be re-admitted from its resolved port rather than being stuck
        // out until the next deploy.
        let serving = records.keys().cloned().collect::<HashSet<_>>();
        let (tx, _rx) = watch::channel(Arc::new(records));
        Self {
            tx,
            ledger_path: Some(path),
            serving: Mutex::new(serving),
        }
    }

    /// Record that yubaba has placed `ident` as a **serving** workload
    /// (R844-F2) — the eligibility gate for cold admission.
    ///
    /// Called from the two admission paths, and only when the workload's own
    /// declaration says it serves: a container with a non-empty
    /// `expose.mesh.ports` (the caller in `lib.rs` gates on exactly that), or a
    /// bundle envelope carrying a `serve_bundle`. Note the bundle case does
    /// **not** require the declaration to name a port — that is the whole
    /// point. "This workload serves" and "we know where" are separate facts,
    /// and only the first one is knowable at admission.
    fn declare_serving(&self, ident: &MeshIdent) {
        if let Ok(mut serving) = self.serving.lock() {
            serving.insert(ident.0.clone());
        }
    }

    /// Forget that `ident` serves. Paired with [`Self::retract`] so a redeploy
    /// that drops its ports, or an explicit destroy, also drops the workload's
    /// cold-admission eligibility — otherwise the next sweep would re-admit
    /// from a resolved port the record was just retracted for.
    fn undeclare_serving(&self, ident: &MeshIdent) {
        if let Ok(mut serving) = self.serving.lock() {
            serving.remove(ident.0.as_str());
        }
    }

    /// Whether yubaba declared `ident` as serving. `true` is a precondition for
    /// cold admission, never a substitute for knowing a port.
    pub fn is_declared_serving(&self, ident: &MeshIdent) -> bool {
        self.serving
            .lock()
            .map(|s| s.contains(ident.0.as_str()))
            .unwrap_or(false)
    }

    /// The ledger file this registry persists to, if any.
    pub fn ledger_path(&self) -> Option<&Path> {
        self.ledger_path.as_deref()
    }

    /// Subscribe for push-on-change snapshots. `receiver.changed().await`
    /// resolves only when a record is upserted, reconciled to a new health
    /// value, or retracted — no polling loop on either side.
    pub fn subscribe(&self) -> watch::Receiver<Arc<HashMap<String, ServiceRecord>>> {
        self.tx.subscribe()
    }

    /// Current snapshot, no subscription required.
    pub fn snapshot(&self) -> Arc<HashMap<String, ServiceRecord>> {
        self.tx.borrow().clone()
    }

    /// Look up one record by mesh identity.
    pub fn get(&self, ident: &MeshIdent) -> Option<ServiceRecord> {
        self.tx.borrow().get(ident.0.as_str()).cloned()
    }

    /// All currently-ready records — the shape an ingress proxy's
    /// upstream-selection loop actually wants.
    pub fn ready(&self) -> Vec<ServiceRecord> {
        self.tx
            .borrow()
            .values()
            .filter(|r| r.is_ready())
            .cloned()
            .collect()
    }

    fn publish(&self, next: HashMap<String, ServiceRecord>) {
        // Persist BEFORE publishing: a subscriber woken by the publish may
        // act on the new state immediately, and it should never be able to
        // observe a world the ledger hasn't caught up to. (Costs nothing —
        // both are sub-millisecond on a handful of records.)
        self.save_ledger(&next);
        // `Sender::send` is a no-op (returns `Err` without storing the
        // value!) when there are zero live receivers — and this registry
        // is designed to be correct even with no subscriber ever attached
        // (`snapshot`/`get`/`ready` must still reflect reality). Use
        // `send_replace`, which unconditionally stores the value and
        // notifies whatever receivers do exist, regardless of count.
        self.tx.send_replace(Arc::new(next));
    }

    /// Rewrite the port ledger to match `records`. Best-effort: a failed
    /// write is logged and swallowed, never propagated into the caller — the
    /// in-memory registry is still correct, and failing a live deploy over a
    /// bookkeeping-file write would trade a real outage for a recoverable
    /// one (the next publish rewrites the whole file, so a single failure
    /// self-heals rather than compounding).
    fn save_ledger(&self, records: &HashMap<String, ServiceRecord>) {
        let Some(path) = &self.ledger_path else {
            return;
        };
        // Retracted records are dropped: the workload is gone, and bringing
        // it back on the next boot would publish an undialable upstream.
        let mut services: Vec<LedgerEntry> = records
            .values()
            .filter(|r| r.health != Health::Retracted)
            .map(|r| LedgerEntry {
                ident: r.ident.0.clone(),
                mesh_ip: r.mesh_ip,
                ports: r.ports.clone(),
                resolved_ports: r.resolved_ports.clone(),
                container_id: r.container_id.clone(),
                routable: r.routable,
            })
            .collect();
        // Stable order so an unchanged registry produces a byte-identical
        // file (HashMap iteration order is not).
        services.sort_by(|a, b| a.ident.cmp(&b.ident));

        let file = LedgerFile {
            version: LEDGER_VERSION,
            services,
        };
        if let Err(e) = crate::identity::atomic_write_json(path, &file) {
            tracing::warn!(
                ledger = %path.display(),
                error = format!("{e:#}"),
                "service_records: failed to persist port ledger; records survive \
                 in memory but a restart before the next successful write will \
                 lose them"
            );
        }
    }

    /// Record (or refresh) a workload at the moment yubaba deploys it.
    /// `mesh_ip` / `container_id` come from the backend's
    /// [`kamaji::DeployResult`]; `ports` are read from
    /// `spec.expose.mesh.ports` — this is the one seam where yubaba knows
    /// both halves at once (see module docs §Placement source of truth).
    pub fn upsert_deployed(
        &self,
        spec: &WorkloadSpec,
        mesh_ip: Ipv4Addr,
        container_id: impl Into<String>,
    ) {
        let ident = spec.expose.mesh.identity.clone();
        // R844-F2: the caller only reaches here for a spec with non-empty
        // `expose.mesh.ports`, so arriving at all IS the serving declaration.
        self.declare_serving(&ident);
        // R881-B1: this is the one moment the spec is in hand, so it is the
        // one moment the netns shape can be read. See `binds_node_ports`.
        let routable = binds_node_ports(spec);
        if !routable {
            tracing::warn!(
                ident = %ident.0,
                mesh_ip = %mesh_ip,
                ports = ?spec.expose.mesh.ports,
                tier = ?spec.tier,
                "service_records: workload declares mesh ports but binds none of \
                 them in this node's network namespace — it is in its own netns \
                 with no veth, bridge or published host port, so no address here \
                 reaches it. Publishing the record NOT-READY (reason \
                 '{REASON_UNROUTABLE}'): it stays visible on GET \
                 /service-records for diagnosis and is withheld from \
                 ?ready=true, so an ingress apply fails to resolve an upstream \
                 instead of rendering one nothing answers on (R881-B1). Giving \
                 a tenant-tier workload a reachable address is R881-S2."
            );
        }
        let record = ServiceRecord {
            ident: ident.clone(),
            mesh_ip,
            ports: kamaji::declared_port_names(&spec.expose.mesh),
            // A container is namespaced: its declared port is its bound port,
            // so there is nothing to resolve and `dialable_ports` falls back to
            // the declaration. See [`ServiceRecord::resolved_ports`].
            resolved_ports: BTreeMap::new(),
            container_id: container_id.into(),
            routable,
            health: health_for(routable, Health::Ready),
            observed_at_unix_ms: now_unix_ms(),
        };
        let mut next = (*self.tx.borrow()).as_ref().clone();
        next.insert(ident.0, record);
        self.publish(next);
    }

    /// Record a **bundle-tier** workload at the moment yubaba hands it to
    /// kamaji (R844-F1).
    ///
    /// The container tier reaches [`Self::upsert_deployed`] with a whole
    /// [`WorkloadSpec`]; the W272 bundle tier has none. A bundle deploy is a
    /// `Workload::MesofactStatic` envelope whose serving port rides on
    /// `MesofactServeBundle::port` — the field workload-spec's own docs call
    /// "the bundle-tier analogue of a container's `expose.mesh.ports`" — so
    /// the two facts arrive separately and this is the seam that pairs them.
    ///
    /// `ident` **must** be the operator-facing workload id from the deploy
    /// body, not the bundle digest. That id is what kamaji's `list()` reports
    /// as `mesh_ident`, and [`Self::reconcile`] keys on exactly that: keyed on
    /// the digest instead, the record would be retracted by the very first
    /// sweep.
    ///
    /// `ports` empty is a caller bug, not a shape this admits — see
    /// [`Self::admit_bundle`], which is the entry point callers should use.
    fn upsert_bundle_deployed(
        &self,
        ident: &MeshIdent,
        mesh_ip: Ipv4Addr,
        ports: BTreeMap<String, u16>,
        resolved_ports: BTreeMap<String, u16>,
    ) {
        let record = ServiceRecord {
            ident: ident.clone(),
            mesh_ip,
            ports,
            resolved_ports,
            // A native bundle is a forked host process, not a container. The
            // ident is the only handle kamaji correlates it by, so repeating
            // it here is the honest answer rather than an invented id.
            container_id: ident.0.clone(),
            // R881-B1: a forked host process has no namespace of its own — it
            // binds the node's address by construction, which is the same fact
            // `admit_bundle` already relies on to publish `node_mesh_ip` here.
            routable: true,
            health: Health::Ready,
            observed_at_unix_ms: now_unix_ms(),
        };
        let mut next = (*self.tx.borrow()).as_ref().clone();
        next.insert(ident.0.clone(), record);
        self.publish(next);
    }

    /// Admit a bundle-tier workload as an upstream at **deploy time**, or
    /// decline with a reason.
    ///
    /// Returns `true` when a record was published. `declared_port` is
    /// `MesofactServeBundle::port`. Two cases decline:
    ///
    /// - **No declared port.** The port kamaji will bind is not knowable from
    ///   here at admission: a bundle `Deploy` acks on admission, before kamaji
    ///   has materialized the tree or forked anything, so there is no resolved
    ///   port in existence yet. Publishing a guess (kamaji's old node-wide
    ///   8080) would re-create the well-known-port assumption discovery exists
    ///   to remove, and publishing a *portless* record would invent a third
    ///   state (present, `Ready`, undialable) that no consumer handles.
    ///   Non-admission is the same answer the container tier gives a portless
    ///   spec.
    /// - **No node mesh IP.** A dev host binds loopback; there is no
    ///   mesh-plane address another node could dial.
    ///
    /// **R844-F2: declining here is no longer the end of the story.** Since
    /// `kamaji::WorkloadState` carries the resolved port, [`Self::reconcile`]
    /// admits an undeclared bundle on the first sweep after it binds — see
    /// that method's cold-admission arm. So the two paths are: a bundle that
    /// declares a port is discoverable immediately, and one that does not is
    /// discoverable within one sweep, once there is a real port to publish
    /// rather than a guess. Both end at the same invariant — a record exists
    /// iff a dialable port is known.
    ///
    /// Declining is not an error: the workload still deploys and serves.
    pub fn admit_bundle(
        &self,
        ident: &MeshIdent,
        node_mesh_ip: Option<Ipv4Addr>,
        declared_port: Option<u16>,
    ) -> bool {
        // R844-F2: declare FIRST, before the port check decides whether
        // anything can be published. A bundle envelope reaching this function
        // is yubaba saying "this workload serves"; whether it also named a
        // port is a separate question, and the declining path below is exactly
        // the state cold admission later resolves. Declaring only on the
        // success path would make the gate useless for the case it exists for.
        self.declare_serving(ident);
        let (Some(mesh_ip), Some(port)) = (node_mesh_ip, declared_port) else {
            tracing::debug!(
                ident = %ident.0,
                has_mesh_ip = node_mesh_ip.is_some(),
                has_declared_port = declared_port.is_some(),
                "service_records: bundle workload not admitted at deploy time — \
                 no declared port yet. If the node has a mesh IP, the refresh \
                 sweep will admit it once kamaji reports the port it actually \
                 bound (R844-F2); yubaba does not guess a port at admission."
            );
            return false;
        };
        // Declared, not resolved: nothing has bound yet at admission time. The
        // sweep fills `resolved_ports` in, and corrects this if they differ.
        self.upsert_bundle_deployed(
            ident,
            mesh_ip,
            name_anonymous_ports(&[port]),
            BTreeMap::new(),
        );
        true
    }

    /// Refresh health, mesh IP and **resolved ports** against the runtime's own
    /// authoritative listing — the same data `GET /workloads` reads via
    /// `ContainerRuntime::list_workloads()`.
    ///
    /// Three things happen per sweep:
    ///
    /// 1. **Refresh.** Every already-tracked ident found in `states` gets its
    ///    `health`, its `mesh_ip` (when the state reports one) and its
    ///    `resolved_ports` (when the supervisor reports any) updated. The last
    ///    of those is R844-F2's correction path: a keep-alive workload that
    ///    came back on a different port updates its record here instead of
    ///    leaving it advertising a port nothing is listening on. That failure
    ///    is strictly worse than an empty registry, because the record still
    ///    reads as `Ready` and nothing detects it.
    /// 2. **Cold-admit** (R844-F2). An ident with *no* prior record is
    ///    admitted now if — and only if — **both** hold: its state carries a
    ///    resolved port, and yubaba
    ///    [declared it serving](Self::is_declared_serving). This is what lets a
    ///    mirror stop naming a port at all: `admit_bundle` declines at deploy
    ///    time because no port exists yet, and this arm publishes the record
    ///    one sweep later using the port kamaji actually bound.
    ///
    ///    **Both halves are load-bearing, and the declaration half is a
    ///    routing-safety gate, not bookkeeping.** kamaji forks workloads
    ///    yubaba never placed — a bundle's revalidate receiver and its feed
    ///    tier are forked from the bundle deploy, so they appear in
    ///    `list_workloads` with real resolved ports and yubaba holds no
    ///    declaration for either. Admitting on the port alone would publish
    ///    them as `Ready` records, and passway's `addrs_from_body`
    ///    (`oss/passway/crates/passway/src/discovery.rs`) pushes *every*
    ///    endpoint of *every* Ready record into its upstream set with no ident
    ///    filter — so the revalidation receiver would start taking apex
    ///    traffic it cannot serve. A wrong-answer outage out of a change whose
    ///    diff reads like an accuracy improvement.
    ///
    ///    So the invariant grows one clause and keeps its shape: **a record
    ///    exists iff yubaba declared the workload serving AND a dialable port
    ///    is known.** What R844-F2 changed is only where the port may come
    ///    from — the supervisor, not just a human writing it into a file.
    ///
    ///    An ident missing either half is skipped. That also keeps
    ///    container-backend entries out on a second, independent ground: they
    ///    resolve no ports by construction.
    /// 3. **Retract.** Every already-tracked ident **absent** from `states` —
    ///    i.e. the runtime no longer knows about it, which is exactly what
    ///    happens after a teardown — is retracted.
    ///
    /// `node_mesh_ip` is this node's own mesh address, and since R876-B3 it is
    /// the *authoritative* one on both arms rather than only the cold-admit
    /// fallback — see `authoritative_mesh_ip` for why the backend's own
    /// report loses to it and what a disagreement means. A bundle is a forked
    /// host process with no namespace of its own, so it binds the node's
    /// address by construction — the same reasoning `admit_bundle` already
    /// relies on. `None` (a dev host on loopback) disables cold admission:
    /// there is no mesh-plane address another node could dial.
    pub fn reconcile(&self, states: &[WorkloadState], node_mesh_ip: Option<Ipv4Addr>) {
        let mut next = (*self.tx.borrow()).as_ref().clone();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for state in states {
            let key = state.ident.0.as_str();
            // Split on `contains_key` rather than matching on `get_mut`: the
            // cold-admit arm inserts into the same map, which a live `get_mut`
            // borrow would forbid.
            if next.contains_key(key) {
                {
                    let record = next.get_mut(key).expect("checked above");
                    seen.insert(key.to_string());
                    if let Some(ip) = authoritative_mesh_ip(state, node_mesh_ip) {
                        record.mesh_ip = ip;
                    }
                    // Only overwrite from a supervisor that actually reported
                    // ports. An empty report means "this backend resolves
                    // nothing", not "the ports went away" — clearing on it
                    // would blank a bundle's record on any sweep the backend
                    // answered thinly.
                    if !state.ports.is_empty() {
                        record.resolved_ports = state.ports.clone();
                    }
                    record.container_id = state.container_id.clone();
                    // R881-B1: `Running` is a statement about the process, not
                    // about whether anything can reach it. An unroutable record
                    // stays unroutable however healthy the supervisor says the
                    // workload is — that combination *is* the bug.
                    record.health =
                        health_for(record.routable, Health::from_status(&state.status));
                    record.observed_at_unix_ms = now_unix_ms();
                }
            } else if !state.ports.is_empty() && self.is_declared_serving(&state.ident) {
                let Some(mesh_ip) = authoritative_mesh_ip(state, node_mesh_ip) else {
                    tracing::debug!(
                        ident = %state.ident.0,
                        "service_records: reconcile saw an unadmitted workload \
                         with resolved ports but no mesh address to publish it \
                         at; skipping"
                    );
                    continue;
                };
                tracing::info!(
                    ident = %state.ident.0,
                    mesh_ip = %mesh_ip,
                    ports = ?state.ports,
                    "service_records: admitting a workload from its resolved \
                     ports — the supervisor bound a port yubaba was never told \
                     about at deploy time (R844-F2)"
                );
                seen.insert(key.to_string());
                next.insert(
                    state.ident.0.clone(),
                    ServiceRecord {
                        ident: state.ident.clone(),
                        mesh_ip,
                        // Nothing was declared — that is why this is a cold
                        // admission rather than a refresh.
                        ports: BTreeMap::new(),
                        resolved_ports: state.ports.clone(),
                        container_id: state.container_id.clone(),
                        // R881-B1: cold admission is reached only via a
                        // supervisor-*resolved* port, and a resolved port is a
                        // host port — the container backends resolve none by
                        // construction (their declared port is their bound
                        // port, inside the namespace). So the workload holds a
                        // port in this node's netns, which is what routable
                        // asserts. An unroutable workload cannot arrive here
                        // anyway: it is admitted with a record at deploy, so it
                        // takes the refresh arm above.
                        routable: true,
                        health: Health::from_status(&state.status),
                        observed_at_unix_ms: now_unix_ms(),
                    },
                );
            } else {
                tracing::debug!(
                    ident = %state.ident.0,
                    has_resolved_ports = !state.ports.is_empty(),
                    declared_serving = self.is_declared_serving(&state.ident),
                    "service_records: reconcile saw a workload it will not \
                     admit — cold admission needs BOTH a resolved port and a \
                     serving declaration from yubaba. A workload kamaji forked \
                     for itself (a bundle's revalidate receiver or feed tier) \
                     has the former and never the latter, and must not become \
                     a routable upstream."
                );
            }
        }

        for (ident, record) in next.iter_mut() {
            if !seen.contains(ident.as_str()) && record.health != Health::Retracted {
                record.health = Health::Retracted;
                record.observed_at_unix_ms = now_unix_ms();
            }
        }

        self.publish(next);
    }

    /// Explicitly retract one record (e.g. an explicit `POST
    /// /workloads/{ident}/destroy` call site, once wired). Idempotent — a
    /// retract of an unknown or already-retracted ident is a no-op publish.
    pub fn retract(&self, ident: &MeshIdent) {
        // R844-F2: drop cold-admission eligibility too, or the next sweep
        // would re-admit from a resolved port the record was just retracted
        // for — which is precisely the redeploy-drops-its-ports case
        // `redeploy_without_ports_retracts_the_previous_record` pins.
        self.undeclare_serving(ident);
        let mut next = (*self.tx.borrow()).as_ref().clone();
        if let Some(record) = next.get_mut(ident.0.as_str()) {
            record.health = Health::Retracted;
            record.observed_at_unix_ms = now_unix_ms();
            self.publish(next);
        }
    }
}

/// Gate a health verdict on routability (R881-B1) — the single place
/// [`ServiceRecord::routable`] turns into a [`Health`].
///
/// `observed` is what the workload's own state says; the answer is that verdict
/// unless the record is unroutable, in which case it is
/// `NotReady { reason: `[`REASON_UNROUTABLE`]` }` no matter how healthy the
/// process is. Every write path funnels through here so no future one can
/// promote an unroutable record to `Ready` by writing `Health::from_status`
/// directly — which is exactly how the fabricated address survived three
/// sweeps' worth of correct-looking code before.
fn health_for(routable: bool, observed: Health) -> Health {
    if routable {
        observed
    } else {
        Health::NotReady {
            reason: REASON_UNROUTABLE,
        }
    }
}

/// Resolve the address a record may advertise for `state`, enforcing the
/// per-node invariant this module's header declares: **a record's `mesh_ip`
/// must equal the answering node's own mesh address** (R844-B11).
///
/// This store is node-local by construction — one yubaba answers `GET
/// /service-records` about workloads it placed on its own host — so
/// `node_mesh_ip` is authoritative and a backend's self-report about some
/// *other* node's address is never the more trustworthy of the two. It
/// therefore wins on the refresh arm as well as the cold-admit arm. Before
/// R876-B3 the refresh arm took `state.mesh_ip` unconditionally, which is how
/// us-west-001 came to publish `yah-cloud-admin` at `100.64.0.3:4325`
/// (us-east-001) with `health: ready`, while the process was in fact bound to
/// west's own `100.64.0.1:4325` and east had nothing on that port at all.
///
/// **Overridden, not refused.** Dropping the record would convert a
/// wrong-address bug into a service-vanishes bug, which is strictly worse for
/// the apex that discovers through this rail: passway's `addrs_from_body`
/// (`oss/passway/crates/passway/src/discovery.rs`) would simply lose the
/// upstream. So the record stays published, at the address that actually
/// answers, and the defect is made loud instead — `warn!`, not `debug!`,
/// because a wrong address carrying `health: ready` is indistinguishable from
/// a right one to every consumer, so this log is the only place it can be
/// seen at all.
///
/// `None` for `node_mesh_ip` is a dev host with no mesh plane (`--bind
/// 0.0.0.0`): there is no node address to enforce against, so the backend's
/// report passes through unchanged and cold admission still declines on a
/// state that reports none.
///
/// Where a disagreement can still come from, now that no deploy path produces
/// one: containerd writes the deploy-time address as the `yah.mesh_ip`
/// container **label** and reads it straight back out on every
/// `list_workloads` sweep (`oss/kamaji/crates/kamaji/src/containerd.rs`). That
/// label is durable container state, so a container placed by a pre-R844-B11
/// yubaba keeps reporting that process's deleted `alloc_mesh_ip()` counter
/// draw until it is redeployed — which is exactly the live record above. This
/// check is what repairs those in place, with no redeploy.
fn authoritative_mesh_ip(
    state: &WorkloadState,
    node_mesh_ip: Option<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    let Some(node) = node_mesh_ip else {
        return state.mesh_ip;
    };
    if let Some(reported) = state.mesh_ip {
        if reported != node {
            tracing::warn!(
                ident = %state.ident.0,
                container_id = %state.container_id,
                reported_mesh_ip = %reported,
                node_mesh_ip = %node,
                "service_records: the backend reports this workload at a mesh \
                 address that is not this node's own; publishing the node's \
                 address instead (R876-B3). A record may only ever advertise \
                 the node answering for it (R844-B11) — the known source is a \
                 stale `yah.mesh_ip` container label from a pre-R844-B11 \
                 deploy, which a redeploy of this workload clears at source."
            );
        }
    }
    Some(node)
}

/// Read the port ledger. Every failure mode — missing file, unreadable file,
/// malformed JSON, unknown schema version — degrades to "no ledger" rather
/// than an error, because none of them should stop a yubaba from booting:
/// the records are re-learned on the next deploy either way.
fn load_ledger(path: &Path) -> Vec<LedgerEntry> {
    if !path.exists() {
        return Vec::new();
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                ledger = %path.display(),
                error = %e,
                "service_records: port ledger unreadable; starting with no records"
            );
            return Vec::new();
        }
    };
    let file: LedgerFile = match serde_json::from_str(&content) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(
                ledger = %path.display(),
                error = %e,
                "service_records: port ledger is malformed; starting with no records"
            );
            return Vec::new();
        }
    };
    if file.version != LEDGER_VERSION {
        tracing::warn!(
            ledger = %path.display(),
            found = file.version,
            expected = LEDGER_VERSION,
            "service_records: port ledger schema version not recognized; \
             starting with no records"
        );
        return Vec::new();
    }
    file.services
}

// ── Discovery surface (R594-F8) ─────────────────────────────────────────────

/// Path of the discovery endpoint on yubaba's (mesh-bound) HTTP listener.
///
/// Named as a constant so the route registration in `build_router`, this
/// module's docs, and the ticket's verify step all reference one string.
/// passway's own client mirrors it in
/// `oss/passway/crates/passway/src/discovery.rs`.
pub const DISCOVERY_PATH: &str = "/service-records";

/// Schema version of [`ServiceRecordsWire`].
///
/// Bump on any incompatible change to the JSON shape. A consumer that reads a
/// version it doesn't recognize should treat the response as unusable — i.e.
/// as a *fetch failure*, keeping its last-known-good upstream set — rather
/// than as an empty record set, since "I can't read this" and "nothing is
/// running" are the distinction this whole module exists to preserve.
pub const WIRE_VERSION: u32 = 1;

/// Wire tag for [`Health::Ready`]. The one value an ingress proxy routes to.
pub const HEALTH_READY: &str = "ready";
/// Wire tag for [`Health::NotReady`]; the `reason` field carries the detail.
pub const HEALTH_NOT_READY: &str = "not-ready";
/// Wire tag for [`Health::Retracted`].
pub const HEALTH_RETRACTED: &str = "retracted";

/// JSON body of `GET` [`DISCOVERY_PATH`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecordsWire {
    /// Always [`WIRE_VERSION`]. See that constant for consumer behaviour on
    /// an unrecognized value.
    pub version: u32,
    /// Sorted by `ident`, so a consumer diffing two fetches sees a stable
    /// order and a byte-identical body when nothing changed.
    pub records: Vec<ServiceRecordWire>,
}

/// One [`ServiceRecord`] projected onto the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecordWire {
    pub ident: String,
    pub mesh_ip: Ipv4Addr,
    /// The port(s) to dial — [`ServiceRecord::dialable_ports`].
    ///
    /// R844-F2 changed where this comes from, not what it means: it is the
    /// supervisor-resolved port when there is one and the declared port
    /// otherwise, where it used to be only the declaration. A consumer that
    /// dials these keeps working and starts being right about a workload
    /// nobody declared a port for; the split between the two facts is below,
    /// for operators rather than proxies.
    ///
    /// Anonymous, ascending by number, **and staying that way** — the named
    /// view is [`Self::named_ports`] beside it. See that field for why this one
    /// was not simply reshaped.
    pub ports: Vec<u16>,
    /// The same dialable ports, keyed by **port name** (R844-F15) — the field a
    /// consumer should read when it cares *which* listener it reaches.
    ///
    /// **Additive rather than a reshape of [`Self::ports`], deliberately.**
    /// This body is a cross-binary contract: passway reads it in its own Cargo
    /// workspace (`oss/passway/crates/passway/src/discovery.rs`), `yah cloud
    /// apply` reads it to resolve ingress ports, and the fleet runs mixed
    /// yubaba versions — 0.8.28 through 0.8.31 as of 2026-09-03. Turning
    /// `ports` into an object would make a rolled node's answer undecodable to
    /// every consumer that had not been rebuilt, which is a front-door outage
    /// produced by a field rename. An extra object beside the array is ignored
    /// by an old consumer and available to a new one, so names ship ahead of
    /// the roll instead of behind it. [`WIRE_VERSION`] therefore does *not*
    /// move: nothing that could read v1 has stopped being able to.
    ///
    /// Omitted from the JSON when empty, which for the same reason as
    /// `kamaji_proto::WorkloadEntry::named_ports` means either "no ports" or
    /// "written by a yubaba that predates this field" — a consumer that must
    /// tell them apart falls back to naming [`Self::ports`] with
    /// `kamaji::name_anonymous_ports`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub named_ports: BTreeMap<String, u16>,
    /// The port(s) the supervisor reported actually binding, when it reported
    /// any (R844-F2). Omitted from the JSON when empty.
    ///
    /// Diagnostic, not dial-able-by-preference: `ports` above already resolves
    /// the precedence. This is here so an operator can tell "kamaji allocated
    /// 43117" from "someone wrote 8080 in a mirror" without reading two
    /// systems.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_ports: Vec<u16>,
    /// `mesh_ip:port` for every dialable port — exactly what
    /// [`ServiceRecord::endpoints`] computes, pre-joined so a consumer dials
    /// without re-deriving the pairing (and cannot get it wrong).
    ///
    /// One entry per distinct port, ascending by port number. Anonymous, for
    /// the same compatibility reason as [`Self::ports`]; the named view is
    /// [`Self::named_endpoints`].
    pub endpoints: Vec<String>,
    /// The same endpoints keyed by **port name** (R844-F15) — what lets a wire
    /// consumer select an endpoint by what the port *is* rather than by where
    /// it happened to sort.
    ///
    /// The consumer that reads it today is `yah cloud apply`'s ingress port
    /// resolution (`ServiceRecordFanout::port_for` selects the port named
    /// `http`), via `named_ports` above.
    ///
    /// **passway does NOT read this yet, and that is a live gap, not a
    /// completed handover.** `addrs_from_body`
    /// (`oss/passway/crates/passway/src/discovery.rs`) pushes every endpoint of
    /// every ready record into one flat backend set — right for a
    /// single-listener workload, and silently wrong for a workload with an
    /// `http` and a `metrics` port, where half the apex traffic lands on the
    /// metrics listener. Nothing has hit that yet because no fronted workload
    /// declares two ports, and this field is what will let passway fix it when
    /// one does. Changing passway's backend selection is a behaviour change to
    /// a separate binary in its own workspace, so R844-F15 stopped at making
    /// the fact available rather than acting on it there.
    ///
    /// Omitted when empty; same two readings as [`Self::named_ports`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub named_endpoints: BTreeMap<String, String>,
    pub container_id: String,
    /// [`HEALTH_READY`] / [`HEALTH_NOT_READY`] / [`HEALTH_RETRACTED`].
    pub health: String,
    /// Present only alongside [`HEALTH_NOT_READY`] — the machine-stable tag
    /// from [`Health::NotReady`], never prose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub observed_at_unix_ms: u64,
}

impl From<&ServiceRecord> for ServiceRecordWire {
    fn from(r: &ServiceRecord) -> Self {
        let (health, reason) = match &r.health {
            Health::Ready => (HEALTH_READY, None),
            Health::NotReady { reason } => (HEALTH_NOT_READY, Some((*reason).to_string())),
            Health::Retracted => (HEALTH_RETRACTED, None),
        };
        Self {
            ident: r.ident.0.clone(),
            mesh_ip: r.mesh_ip,
            ports: r.dialable_port_numbers(),
            named_ports: r.dialable_ports().clone(),
            // Still the anonymous diagnostic it has always been: `named_ports`
            // above already resolves declared-vs-resolved precedence, so naming
            // this too would put a fourth port field on the wire to answer a
            // question ("did a human write 8080 or did kamaji pick 43117")
            // that the numbers alone answer.
            resolved_ports: {
                let mut v: Vec<u16> = r.resolved_ports.values().copied().collect();
                v.sort_unstable();
                v.dedup();
                v
            },
            endpoints: r.endpoints().iter().map(|e| e.to_string()).collect(),
            named_endpoints: r
                .named_endpoints()
                .into_iter()
                .map(|(name, addr)| (name, addr.to_string()))
                .collect(),
            container_id: r.container_id.clone(),
            health: health.to_string(),
            reason,
            observed_at_unix_ms: r.observed_at_unix_ms,
        }
    }
}

/// Query string of `GET` [`DISCOVERY_PATH`].
#[derive(Debug, Default, Deserialize)]
pub struct DiscoveryQuery {
    /// `?ready=true` — return only [`Health::is_ready`] records. Default
    /// `false` (every tracked record, health tag included) so an operator
    /// debugging a not-ready upstream can see *why* it was skipped.
    #[serde(default)]
    pub ready: bool,
}

/// Build the wire body from a registry snapshot.
///
/// Split out from the handler so the projection is unit-testable without an
/// axum `State` or a live `ServerState`.
pub fn discovery_body(
    records: &HashMap<String, ServiceRecord>,
    ready_only: bool,
) -> ServiceRecordsWire {
    let mut rows: Vec<ServiceRecordWire> = records
        .values()
        .filter(|r| !ready_only || r.is_ready())
        .map(ServiceRecordWire::from)
        .collect();
    rows.sort_by(|a, b| a.ident.cmp(&b.ident));
    ServiceRecordsWire {
        version: WIRE_VERSION,
        records: rows,
    }
}

/// `GET /service-records[?ready=true]` — the upstream-discovery surface an
/// ingress proxy (passway, R594-F8) polls.
///
/// Always 200: an empty `records` array is a normal cold-start state, not an
/// error (see the module docs' fail-ready note). Read-only, and served on the
/// same mesh-bound listener as `GET /workloads`, whose posture it matches.
pub async fn get_service_records(
    axum::extract::State(state): axum::extract::State<Arc<crate::ServerState>>,
    axum::extract::Query(q): axum::extract::Query<DiscoveryQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let snapshot = state.service_records.snapshot();
    (
        axum::http::StatusCode::OK,
        axum::Json(discovery_body(&snapshot, q.ready)),
    )
        .into_response()
}

// ── Background refresh sweep ────────────────────────────────────────────────

/// How often [`run`] re-reads the runtime's workload list.
///
/// Deliberately slow. Every yubaba-initiated change (deploy, destroy) already
/// pushes synchronously through the `watch`; this sweep exists only to catch
/// changes nobody told yubaba about — a container that crashed, or a
/// rehydrated record whose workload is (or isn't) still running after a
/// restart. 15s bounds how long a rehydrated record stays not-ready on boot
/// while keeping idle cost to one cheap list call per interval.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Background task: refresh service-record health against the runtime's own
/// authoritative listing. Spawned from [`crate::serve`] /
/// [`crate::serve_on_listener`]; returns immediately (task ends) when the node
/// has no workload backend, which is the stub/dev case.
pub async fn run(state: Arc<crate::ServerState>) {
    // The backend is re-resolved per tick inside `sweep_once`; this is only the
    // "don't spawn a loop at all" guard for the stub/dev case.
    if state.active_backend().is_none() {
        tracing::debug!("service_records: no workload backend; refresh sweep idle");
        return;
    }
    tracing::info!(
        interval_secs = SWEEP_INTERVAL.as_secs(),
        ledger = ?state.service_records.ledger_path(),
        "service_records: refresh sweep started"
    );
    loop {
        sweep_once(&state).await;
        tokio::time::sleep(SWEEP_INTERVAL).await;
    }
}

/// One turn of [`run`]'s refresh loop, factored out so a test can drive the
/// real thing instead of re-implementing the tick.
///
/// Returns `true` when the backend answered and a reconcile ran. It lives here
/// rather than in the test because the tick reads `ServerState::node_mesh_ip`,
/// which `reconcile` needs as the cold-admission address and which is private
/// to this crate — and because a hand-rolled copy in a test is exactly how a
/// test stops testing the code that ships.
pub async fn sweep_once(state: &Arc<crate::ServerState>) -> bool {
    let Some(backend) = state.active_backend() else {
        return false;
    };
    match backend.list_workloads().await {
        Ok(states) => {
            state
                .service_records
                .reconcile(&states, state.node_mesh_ip);
            true
        }
        // A failed list is NOT an empty list. Reconciling against `&[]` here
        // would retract every record on a transient backend blip (kamaji socket
        // restarting, containerd busy) and yank live upstreams out from under
        // the ingress proxy. Skip the tick.
        Err(e) => {
            tracing::debug!(
                error = format!("{e:#}"),
                "service_records: workload list failed; skipping this refresh tick"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, Millis, ResourceLimits, RestartPolicy, SchemaVersion,
        StopPolicy, TierTag,
    };

    /// A minimal-but-real serving `WorkloadSpec` — configurable mesh identity
    /// and ports, **host-networked**.
    ///
    /// The host-network annotation is R881-B1's doing and it is not decoration:
    /// since that ticket a workload's record is only `Ready` if the workload
    /// binds its ports in the node's netns ([`binds_node_ports`]), and every
    /// test below this line is about something else — port naming, health
    /// transitions, the ledger, retraction. Spelling the reachable shape here
    /// keeps each of those asking its own question. `.yah/infra/workloads/
    /// yah-cloud-admin.toml` is the live spec this mirrors.
    ///
    /// The *unreachable* shape is [`isolated_spec`], and only the R881-B1 tests
    /// use it.
    fn test_spec(name: &str, ports: Vec<u16>) -> WorkloadSpec {
        let mut spec = isolated_spec(name, ports);
        spec.annotations.insert(
            workload_spec::HOST_NETWORK_ANNOTATION.to_string(),
            workload_spec::HOST_NETWORK_VALUE.to_string(),
        );
        spec
    }

    /// The same spec with **no** networking annotation — a container alone in
    /// a fresh netns with nothing but `lo`, which is what a tenant-tier
    /// workload gets (R881-B1). Nothing on the node listens on its ports.
    ///
    /// Mirrors the `test_workload_spec` helper in `tests/integration_mesh.rs` /
    /// `integration_single_node.rs`.
    fn isolated_spec(name: &str, ports: Vec<u16>) -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.to_string(),
            image: ImageRef {
                registry: "docker.io".into(),
                repository: "library/alpine".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".into()),
            tenant: workload_spec::TenantId::singleton(),
            namespace: workload_spec::NamespaceId::singleton(),
            replicas: 1,
            command: Some(vec!["sh".into(), "-c".into(), "sleep 300".into()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 64,
                cpu_millis: 128,
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
            requires: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Never,
            archetype: None,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name.to_string()),
                    ports: MeshExpose::anonymous_ports(ports),
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        }
    }

    /// A backend report with no resolved ports — the container-tier shape, and
    /// the shape every pre-R844-F2 test implicitly assumed.
    fn running_state(name: &str, mesh_ip: Option<Ipv4Addr>) -> WorkloadState {
        WorkloadState {
            ident: MeshIdent(name.to_string()),
            container_id: format!("container-{name}"),
            status: WorkloadStatus::Running,
            mesh_ip,
            ports: BTreeMap::new(),
        }
    }

    /// A backend report that DOES carry resolved ports — the native/bundle
    /// shape kamaji answers with since R844-F2.
    ///
    /// Takes bare numbers and names them the way every real producer does, so
    /// these tests exercise the same synthesis the live path runs rather than a
    /// hand-written map that could disagree with it.
    fn running_state_on_ports(
        name: &str,
        mesh_ip: Option<Ipv4Addr>,
        ports: Vec<u16>,
    ) -> WorkloadState {
        WorkloadState {
            ports: name_anonymous_ports(&ports),
            ..running_state(name, mesh_ip)
        }
    }

    /// A backend report carrying ports the supervisor **named** — the shape
    /// R844-F14's allocator answers with, where the names are real rather than
    /// synthesized.
    fn running_state_on_named_ports(
        name: &str,
        mesh_ip: Option<Ipv4Addr>,
        ports: &[(&str, u16)],
    ) -> WorkloadState {
        WorkloadState {
            ports: named(ports),
            ..running_state(name, mesh_ip)
        }
    }

    /// Build a named port map from pairs — the expected-value side of every
    /// assertion below.
    fn named(pairs: &[(&str, u16)]) -> BTreeMap<String, u16> {
        pairs
            .iter()
            .map(|(n, p)| ((*n).to_string(), *p))
            .collect()
    }

    /// This node's mesh address, as `reconcile` is given it by the sweep.
    ///
    /// Since R876-B3 this is also the address every record a sweep touches
    /// ends up carrying, so a test that deploys at some *other* address and
    /// then sweeps is asserting the bug rather than the behaviour.
    fn sweep_node_ip() -> Option<Ipv4Addr> {
        Some(Ipv4Addr::new(100, 64, 0, 3))
    }

    /// Collect the WARN-and-above lines emitted while `f` runs.
    ///
    /// `with_default` installs the subscriber on this thread only, so this
    /// stays correct under cargo's parallel test threads — a global default
    /// would leak one test's capture into another's.
    fn capture_warnings(f: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
            type Writer = Self;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(captured.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = captured.0.lock().unwrap().clone();
        String::from_utf8(bytes).expect("tracing writes utf-8")
    }

    #[test]
    fn deployed_workload_yields_ready_record_with_mesh_ip_port() {
        let records = ServiceRecords::new();
        let spec = test_spec("api", vec![8080]);
        let ip = Ipv4Addr::new(100, 64, 0, 5);

        records.upsert_deployed(&spec, ip, "container-abc");

        let record = records
            .get(&MeshIdent("api".into()))
            .expect("record present");
        assert!(record.is_ready(), "freshly deployed workload must be ready");
        assert_eq!(record.mesh_ip, ip);
        assert_eq!(record.ports, named(&[("http", 8080)]));
        assert_eq!(
            record.port("http"),
            Some(8080),
            "a single-listener workload's port must be reachable by the name every tier gives it"
        );
        assert_eq!(record.endpoints(), vec![SocketAddrV4::new(ip, 8080)]);
        assert_eq!(record.container_id, "container-abc");
    }

    #[test]
    fn deployed_workload_with_multiple_ports_yields_multiple_endpoints() {
        let records = ServiceRecords::new();
        let spec = test_spec("multi", vec![8080, 9090]);
        let ip = Ipv4Addr::new(100, 64, 0, 6);

        records.upsert_deployed(&spec, ip, "container-multi");

        let record = records.get(&MeshIdent("multi".into())).unwrap();
        assert_eq!(
            record.endpoints(),
            vec![SocketAddrV4::new(ip, 8080), SocketAddrV4::new(ip, 9090),]
        );
    }

    // ── Bundle tier (R844-F1) ──────────────────────────────────────────────
    //
    // These pin the producer the W272 bundle tier had never had. Before this,
    // `deploy_non_container` returned 202 without touching the registry, so
    // every node in the fleet served bundles and answered
    // `GET /service-records?ready=true` with `[]`. Each test below asserts a
    // NON-EMPTY set (or a deliberate refusal) — asserting "the call returned"
    // passed fine against zero records, which is how this stayed invisible.

    /// The defect this ticket exists for: a bundle deploy must leave behind a
    /// record an ingress proxy can dial, carrying BOTH the resolved host and
    /// the resolved port.
    #[test]
    fn admitted_bundle_yields_a_ready_dialable_record() {
        let records = ServiceRecords::new();
        let node_ip = Ipv4Addr::new(100, 64, 0, 3);

        let admitted = records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node_ip), Some(8080));

        assert!(admitted, "a bundle declaring a port must be admitted");
        assert_eq!(
            records.ready().len(),
            1,
            "a bundle deploy must publish exactly one ready record"
        );
        let record = records.get(&MeshIdent("yah-marketing".into())).unwrap();
        assert!(record.is_ready());
        assert_eq!(record.mesh_ip, node_ip, "host must be the node's mesh IP");
        assert_eq!(
            record.ports,
            named(&[("http", 8080)]),
            "port must be the declared one"
        );
        assert_eq!(
            record.endpoints(),
            vec![SocketAddrV4::new(node_ip, 8080)],
            "the record must resolve to a dialable address, not just a host"
        );
    }

    /// The subtlest way this fix could rot. `deploy_non_container` holds two
    /// different strings — the bundle DIGEST and the operator-facing workload
    /// id — and only the latter is what kamaji's `list()` reports back as
    /// `mesh_ident`. `reconcile` keys on that, so a digest-keyed record is
    /// retracted by the very first 15s sweep and the bug returns in disguise.
    #[test]
    fn bundle_record_keyed_on_the_workload_id_survives_the_sweep() {
        let records = ServiceRecords::new();
        let node_ip = Ipv4Addr::new(100, 64, 0, 3);
        records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node_ip), Some(8080));

        // What the sweep actually sees: kamaji lists the bundle under its
        // stable id, never under the digest.
        records.reconcile(&[running_state("yah-marketing", None)], sweep_node_ip());

        assert_eq!(
            records.ready().len(),
            1,
            "the sweep must keep the bundle record, not retract it"
        );
        let record = records.get(&MeshIdent("yah-marketing".into())).unwrap();
        assert_eq!(
            record.ports,
            named(&[("http", 8080)]),
            "the sweep must not lose the admission-time port"
        );
        assert_eq!(
            record.mesh_ip, node_ip,
            "a listing that reports no mesh IP must not blank the record's host"
        );
    }

    // ── R844-F2: the resolved-port return path ────────────────────────────

    /// THE ticket's assertion. Two bundles co-tenant one node, NEITHER mirror
    /// naming a port, and each ends up with a record carrying the port its own
    /// workload actually bound.
    ///
    /// This is the shape that raised R844: yah-marketing holds 8080 on
    /// us-east-001, and a second site landing on the same node had nowhere to
    /// go. A design correct for one workload per node does not address it,
    /// which is why the test is written with two.
    #[test]
    fn two_undeclared_bundles_on_one_node_get_distinct_dialable_records() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);

        // Neither declares a port, so neither is admitted at deploy time —
        // there is no port to publish yet, only a guess, and the registry does
        // not guess.
        assert!(!records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node), None));
        assert!(!records.admit_bundle(&MeshIdent("noisetable-com".into()), Some(node), None));
        assert!(records.snapshot().is_empty());

        // kamaji allocated one each and reports them on the first sweep.
        records.reconcile(
            &[
                running_state_on_ports("yah-marketing", None, vec![43117]),
                running_state_on_ports("noisetable-com", None, vec![43119]),
            ],
            Some(node),
        );

        let marketing = records.get(&MeshIdent("yah-marketing".into())).unwrap();
        let noisetable = records.get(&MeshIdent("noisetable-com".into())).unwrap();
        assert_eq!(marketing.dialable_ports(), &named(&[("http", 43117)]));
        assert_eq!(noisetable.dialable_ports(), &named(&[("http", 43119)]));
        assert_eq!(
            marketing.endpoints(),
            vec![SocketAddrV4::new(node, 43117)],
            "the rendered upstream must carry this workload's own port"
        );
        assert_eq!(noisetable.endpoints(), vec![SocketAddrV4::new(node, 43119)]);
        assert_eq!(records.ready().len(), 2);
    }

    /// The step-(3) regression guard, stated as the thing that must be true
    /// BEFORE the mirror's `port` key is deleted: with no declaration anywhere,
    /// `GET /service-records?ready=true` still answers with a dialable record.
    ///
    /// Without the cold-admission arm this test fails by returning an EMPTY
    /// set — not by erroring — which is precisely how deleting the pin would
    /// have silently undone R844-F1.
    #[test]
    fn a_bundle_with_no_declared_port_anywhere_is_still_discoverable() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        assert!(!records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node), None));

        records.reconcile(
            &[running_state_on_ports("yah-marketing", None, vec![43117])],
            Some(node),
        );

        let body = discovery_body(&records.snapshot(), true);
        assert_eq!(
            body.records.len(),
            1,
            "ready=true must not be empty once kamaji has reported a real port"
        );
        assert_eq!(body.records[0].ident, "yah-marketing");
        assert_eq!(body.records[0].ports, vec![43117]);
        assert_eq!(body.records[0].endpoints, vec!["100.64.0.3:43117"]);
    }

    /// A port that MOVED must be corrected, not left standing. This is the
    /// failure the sweep half of the return path exists for, and it is worse
    /// than an empty registry because the stale record still reads `Ready`.
    #[test]
    fn a_moved_port_is_corrected_by_the_next_sweep() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        // Declared serving but with no port, so the first sweep cold-admits.
        assert!(!records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node), None));
        records.reconcile(
            &[running_state_on_ports("yah-marketing", None, vec![43117])],
            Some(node),
        );
        assert_eq!(
            records
                .get(&MeshIdent("yah-marketing".into()))
                .unwrap()
                .dialable_ports(),
            &named(&[("http", 43117)])
        );

        // Restarted onto a different port (ledger lost, or the old port was
        // taken by something else while kamaji was down).
        records.reconcile(
            &[running_state_on_ports("yah-marketing", None, vec![51001])],
            Some(node),
        );

        let record = records.get(&MeshIdent("yah-marketing".into())).unwrap();
        assert_eq!(
            record.dialable_ports(),
            &named(&[("http", 51001)]),
            "the record must follow the workload, not keep advertising a dead port"
        );
        assert_eq!(record.endpoints(), vec![SocketAddrV4::new(node, 51001)]);
    }

    /// A resolved port beats a declared one when they disagree — the
    /// supervisor is the measurement and the mirror is the request — but BOTH
    /// are kept, because the disagreement is the diagnosis.
    #[test]
    fn a_resolved_port_overrides_a_declared_one_without_erasing_it() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        assert!(records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node), Some(8080)));

        records.reconcile(
            &[running_state_on_ports("yah-marketing", None, vec![43117])],
            Some(node),
        );

        let record = records.get(&MeshIdent("yah-marketing".into())).unwrap();
        assert_eq!(
            record.ports,
            named(&[("http", 8080)]),
            "the declaration is still recorded"
        );
        assert_eq!(record.resolved_ports, named(&[("http", 43117)]));
        assert_eq!(record.dialable_ports(), &named(&[("http", 43117)]));
        let row = &discovery_body(&records.snapshot(), false).records[0];
        assert_eq!(row.ports, vec![43117], "consumers dial the resolved port");
        assert_eq!(
            row.resolved_ports,
            vec![43117],
            "and an operator can still see which of the two it came from"
        );
    }

    /// A thin report must not blank a record. A backend that resolves no ports
    /// (every container backend, by construction) answering the same sweep as
    /// a bundle must leave the bundle's ports alone.
    #[test]
    fn a_backend_reporting_no_ports_does_not_clear_a_known_one() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node), Some(8080));
        records.reconcile(
            &[running_state_on_ports("yah-marketing", None, vec![43117])],
            Some(node),
        );
        // Next tick the backend answers without ports.
        records.reconcile(&[running_state("yah-marketing", None)], Some(node));

        assert_eq!(
            records
                .get(&MeshIdent("yah-marketing".into()))
                .unwrap()
                .dialable_ports(),
            &named(&[("http", 43117)]),
            "an empty report means 'this backend resolves nothing', not 'the ports went away'"
        );
    }

    /// Cold admission needs a mesh address. On a dev host (no node mesh IP,
    /// loopback binds) there is nothing another node could dial, so nothing is
    /// published — the same answer `admit_bundle` gives.
    #[test]
    fn cold_admission_is_declined_without_a_mesh_address() {
        let records = ServiceRecords::new();
        // Declared serving, so the ONLY thing missing is the address — without
        // this the test would pass on the declaration gate instead and stop
        // testing what it names.
        records.admit_bundle(&MeshIdent("yah-marketing".into()), None, None);
        records.reconcile(
            &[running_state_on_ports("yah-marketing", None, vec![43117])],
            None,
        );
        assert!(records.snapshot().is_empty());
    }

    /// Same registry, one field different: proof the cold-admission tests above
    /// are not vacuous. Without resolved ports there is nothing to publish, so
    /// the pre-R844-F2 skip still applies.
    #[test]
    fn cold_admission_is_declined_without_resolved_ports() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        // Declared serving, so the only thing missing is the port.
        records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node), None);
        records.reconcile(&[running_state("yah-marketing", None)], Some(node));
        assert!(records.snapshot().is_empty());
    }

    /// THE ROUTING-SAFETY GATE. kamaji forks a bundle's revalidate receiver and
    /// feed tier from the bundle deploy, so yubaba never places them and holds
    /// no declaration for either — but they DO appear in `list_workloads` with
    /// real resolved ports. They must not become service records.
    ///
    /// This is not tidiness. passway's `addrs_from_body`
    /// (oss/passway/crates/passway/src/discovery.rs) pushes every endpoint of
    /// every Ready record into its upstream set with NO ident filter, so a
    /// record here would put the revalidation receiver into the rotation for
    /// the apex and answer real traffic from something that is not a web
    /// server for that site.
    #[test]
    fn a_kamaji_forked_sibling_is_not_cold_admitted() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        // Only the bundle itself is declared. The two siblings are exactly what
        // kamaji forks beside it, named as they are on us-east-001.
        assert!(!records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node), None));

        records.reconcile(
            &[
                running_state_on_ports("yah-marketing", None, vec![43117]),
                running_state_on_ports("yah-marketing-revalidate", None, vec![43118]),
                running_state_on_ports("yah-marketing-feed", None, vec![43120]),
            ],
            Some(node),
        );

        assert!(
            records
                .get(&MeshIdent("yah-marketing-revalidate".into()))
                .is_none(),
            "a kamaji-forked revalidate receiver must never become a routable upstream"
        );
        assert!(records
            .get(&MeshIdent("yah-marketing-feed".into()))
            .is_none());
        // Non-vacuous: the declared workload on the very same sweep IS admitted,
        // so the gate is discriminating rather than just refusing everything.
        assert_eq!(
            records
                .get(&MeshIdent("yah-marketing".into()))
                .unwrap()
                .dialable_ports(),
            &named(&[("http", 43117)])
        );
        assert_eq!(records.ready().len(), 1);
    }

    /// A redeploy that drops its ports retracts the record AND the eligibility.
    /// Without the second half the next sweep would immediately re-admit the
    /// workload from its resolved port, silently undoing the retraction that
    /// `redeploy_without_ports_retracts_the_previous_record` exists to enforce.
    #[test]
    fn retraction_also_drops_cold_admission_eligibility() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node), Some(8080));
        assert!(records.is_declared_serving(&MeshIdent("yah-marketing".into())));

        records.retract(&MeshIdent("yah-marketing".into()));
        assert!(!records.is_declared_serving(&MeshIdent("yah-marketing".into())));

        // The record still exists but is Retracted; a sweep reporting a live
        // resolved port must not resurrect it as Ready.
        records.reconcile(&[], Some(node));
        assert!(records.ready().is_empty());
    }

    /// Same registry, keyed the wrong way: proof the assertion above is not
    /// vacuous. A record under the digest is invisible to the sweep, gets
    /// retracted, and `ready()` goes back to empty — the exact fleet symptom.
    #[test]
    fn bundle_record_keyed_on_the_digest_is_retracted_by_the_sweep() {
        let records = ServiceRecords::new();
        let digest = "a".repeat(64);
        records.admit_bundle(
            &MeshIdent(digest.clone()),
            Some(Ipv4Addr::new(100, 64, 0, 3)),
            Some(8080),
        );
        assert_eq!(records.ready().len(), 1);

        records.reconcile(&[running_state("yah-marketing", None)], sweep_node_ip());

        assert!(
            records.ready().is_empty(),
            "a digest-keyed record cannot survive a sweep — this is why \
             admit_bundle must be called with the workload id"
        );
    }

    /// kamaji falls back to its own node-wide bind port (`KAMAJI_BUNDLE_PORT`,
    /// else 8080) when a bundle declares none, and that value is not visible
    /// from yubaba. Guessing it would re-create the well-known-port assumption
    /// discovery exists to remove, so this declines — the same non-admission
    /// the container tier gives a spec with empty `expose.mesh.ports`.
    #[test]
    fn bundle_without_a_declared_port_is_not_admitted() {
        let records = ServiceRecords::new();

        let admitted =
            records.admit_bundle(&MeshIdent("portless".into()), Some(Ipv4Addr::new(100, 64, 0, 3)), None);

        assert!(!admitted);
        assert!(
            records.snapshot().is_empty(),
            "a bundle with no known port has no endpoint to publish — a \
             present-but-undialable record reads as healthy and is worse than \
             absence"
        );
    }

    /// A dev host with no mesh-plane address binds loopback; there is no
    /// address another node could dial, so there is nothing to advertise.
    #[test]
    fn bundle_on_a_node_without_a_mesh_ip_is_not_admitted() {
        let records = ServiceRecords::new();

        let admitted = records.admit_bundle(&MeshIdent("dev-host".into()), None, Some(8080));

        assert!(!admitted);
        assert!(records.snapshot().is_empty());
    }

    /// Bundle and container records share one registry and one wire view, so a
    /// node hosting both must advertise both.
    #[test]
    fn bundle_and_container_records_coexist_in_one_ready_set() {
        let records = ServiceRecords::new();
        let node_ip = Ipv4Addr::new(100, 64, 0, 3);

        records.upsert_deployed(&test_spec("api", vec![9090]), Ipv4Addr::new(100, 64, 0, 7), "c1");
        records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node_ip), Some(8080));

        let mut idents: Vec<String> = records.ready().into_iter().map(|r| r.ident.0).collect();
        idents.sort();
        assert_eq!(idents, vec!["api".to_string(), "yah-marketing".to_string()]);
    }

    #[test]
    fn undeployed_workload_is_retracted_on_reconcile() {
        let records = ServiceRecords::new();
        let spec = test_spec("gone", vec![8080]);
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        records.upsert_deployed(&spec, ip, "container-gone");
        assert!(records.get(&MeshIdent("gone".into())).unwrap().is_ready());

        // Torn down: the runtime's own list_workloads() no longer includes
        // it (matches kamaji's FakeRuntime/real backends, which remove the
        // entry entirely on teardown).
        records.reconcile(&[], sweep_node_ip());

        let record = records.get(&MeshIdent("gone".into())).unwrap();
        assert!(!record.is_ready(), "retracted workload must not be ready");
        assert_eq!(record.health, Health::Retracted);
        // Endpoint/port bookkeeping survives retraction — useful for
        // diagnostics — but is_ready() is what a proxy must respect.
        assert_eq!(record.ports, named(&[("http", 8080)]));
    }

    #[test]
    fn stopped_workload_is_not_ready_but_not_retracted_while_still_listed() {
        let records = ServiceRecords::new();
        let spec = test_spec("stopping", vec![8080]);
        let ip = Ipv4Addr::new(100, 64, 0, 8);
        records.upsert_deployed(&spec, ip, "container-stopping");

        let stopped = WorkloadState {
            ident: MeshIdent("stopping".into()),
            container_id: "container-stopping".into(),
            status: WorkloadStatus::Stopping,
            mesh_ip: Some(ip),
            ports: BTreeMap::new(),
        };
        records.reconcile(std::slice::from_ref(&stopped), sweep_node_ip());

        let record = records.get(&MeshIdent("stopping".into())).unwrap();
        assert!(!record.is_ready());
        assert_eq!(record.health, Health::NotReady { reason: "stopping" });
    }

    /// A sweep re-asserts the record's host from the node's own address, and
    /// leaves the admission-time ports alone.
    ///
    /// This test used to read `reconcile_refreshes_mesh_ip_when_it_changes` and
    /// pinned the opposite: a record deployed at `100.64.0.9` was *moved* to
    /// the `100.64.0.10` the backend reported, on a node whose own address is
    /// `100.64.0.3`. R876-B3 removed that behaviour rather than narrowing it —
    /// a per-node store has no "the workload moved to another node" case to
    /// serve, so what the old assertion actually pinned was the bug.
    #[test]
    fn reconcile_reasserts_the_node_address_and_leaves_ports_alone() {
        let records = ServiceRecords::new();
        let spec = test_spec("moved", vec![443]);
        let node = sweep_node_ip().expect("the sweep supplies a node address");
        records.upsert_deployed(&spec, node, "container-moved");

        let state = running_state("moved", Some(node));
        records.reconcile(std::slice::from_ref(&state), sweep_node_ip());

        let record = records.get(&MeshIdent("moved".into())).unwrap();
        assert!(record.is_ready());
        assert_eq!(record.mesh_ip, node);
        assert_eq!(
            record.ports,
            named(&[("http", 443)]),
            "ports are untouched by reconcile"
        );
    }

    // ── R876-B3: the per-node mesh_ip invariant, enforced on write ─────────

    /// The steady state, and the non-vacuity anchor for the override test
    /// below: when the backend agrees with the node, the record is unchanged
    /// and nothing is warned about.
    #[test]
    fn reconcile_leaves_an_agreeing_mesh_ip_alone_and_says_nothing() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 1);
        records.upsert_deployed(&test_spec("yah-cloud-admin", vec![4325]), node, "c-admin");

        let logs = capture_warnings(|| {
            records.reconcile(&[running_state("yah-cloud-admin", Some(node))], Some(node));
        });

        let record = records.get(&MeshIdent("yah-cloud-admin".into())).unwrap();
        assert_eq!(record.mesh_ip, node);
        assert_eq!(
            record.endpoints(),
            vec![SocketAddrV4::new(node, 4325)],
            "the record still dials the node it is served from"
        );
        assert!(
            logs.is_empty(),
            "an agreeing report is the normal case and must be silent, else \
             the warning below is noise nobody reads: {logs}"
        );
    }

    /// THE DEFECT R876-B3 EXISTS FOR, in the shape measured on us-west-001 on
    /// 2026-09-09: `yah-cloud-admin` runs on west (`100.64.0.1:4325`) under a
    /// containerd shim, but west published it at `100.64.0.3:4325` —
    /// us-east-001, where nothing listens on that port — with `health: ready`.
    ///
    /// The backend's report is the stale `yah.mesh_ip` label of a container
    /// placed before R844-B11 deleted `alloc_mesh_ip`. The node's own address
    /// wins, the record stays published (refusing it would take the apex's
    /// upstream away, a strictly worse failure), and the disagreement is
    /// warned about — the only place it is visible at all, since `health:
    /// ready` at a dead address reads exactly like a healthy record to
    /// passway.
    #[test]
    fn reconcile_overrides_a_backend_reporting_another_nodes_mesh_ip() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 1);
        let neighbour = Ipv4Addr::new(100, 64, 0, 3);
        records.upsert_deployed(&test_spec("yah-cloud-admin", vec![4325]), node, "c-admin");

        let logs = capture_warnings(|| {
            records.reconcile(
                &[running_state("yah-cloud-admin", Some(neighbour))],
                Some(node),
            );
        });

        let record = records.get(&MeshIdent("yah-cloud-admin".into())).unwrap();
        assert_eq!(
            record.mesh_ip, node,
            "a node-local store may only advertise the node answering for it"
        );
        assert!(
            record.is_ready(),
            "the record is corrected, not withdrawn — a vanished upstream is \
             a worse failure than a corrected one"
        );
        assert_eq!(
            record.endpoints(),
            vec![SocketAddrV4::new(node, 4325)],
            "and the endpoint a door dials points at the live process"
        );
        assert!(
            logs.contains("yah-cloud-admin")
                && logs.contains("100.64.0.3")
                && logs.contains("100.64.0.1"),
            "the warning must name the workload and BOTH addresses, or it \
             cannot be acted on: {logs}"
        );
    }

    /// The cold-admit fallback is unchanged by the override: a backend that
    /// reports no address at all (every bundle — a forked host process has no
    /// address of its own to report) is still admitted at the node's.
    #[test]
    fn cold_admission_still_falls_back_to_the_node_address() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 1);
        assert!(!records.admit_bundle(&MeshIdent("yah-marketing".into()), Some(node), None));

        let logs = capture_warnings(|| {
            records.reconcile(
                &[running_state_on_ports("yah-marketing", None, vec![43117])],
                Some(node),
            );
        });

        let record = records.get(&MeshIdent("yah-marketing".into())).unwrap();
        assert!(record.is_ready());
        assert_eq!(record.mesh_ip, node);
        assert_eq!(
            record.endpoints(),
            vec![SocketAddrV4::new(node, 43117)],
            "cold admission still publishes a dialable endpoint"
        );
        assert!(
            logs.is_empty(),
            "reporting no address is normal for a bundle, not a disagreement: \
             {logs}"
        );
    }

    #[test]
    fn reconcile_skips_unknown_idents_it_has_no_ports_for() {
        let records = ServiceRecords::new();
        let state = running_state("never-deployed-here", Some(Ipv4Addr::new(100, 64, 0, 11)));
        records.reconcile(std::slice::from_ref(&state), sweep_node_ip());

        assert!(records
            .get(&MeshIdent("never-deployed-here".into()))
            .is_none());
        assert!(records.snapshot().is_empty());
    }

    #[test]
    fn explicit_retract_marks_not_ready_idempotently() {
        let records = ServiceRecords::new();
        let spec = test_spec("explicit", vec![8080]);
        records.upsert_deployed(&spec, Ipv4Addr::new(100, 64, 0, 12), "c1");

        let ident = MeshIdent("explicit".into());
        records.retract(&ident);
        assert!(!records.get(&ident).unwrap().is_ready());

        // Retracting again (or retracting an unknown ident) must not panic
        // or resurrect the record.
        records.retract(&ident);
        records.retract(&MeshIdent("unknown".into()));
        assert_eq!(records.get(&ident).unwrap().health, Health::Retracted);
    }

    #[tokio::test]
    async fn subscriber_is_notified_on_upsert_without_polling() {
        let records = ServiceRecords::new();
        let mut rx = records.subscribe();

        let spec = test_spec("pushed", vec![8080]);
        records.upsert_deployed(&spec, Ipv4Addr::new(100, 64, 0, 13), "c-pushed");

        rx.changed().await.expect("sender still alive");
        let snap = rx.borrow_and_update();
        let record = snap
            .get("pushed")
            .expect("record present in pushed snapshot");
        assert!(record.is_ready());
    }

    #[tokio::test]
    async fn subscriber_is_notified_on_retraction() {
        let records = ServiceRecords::new();
        let spec = test_spec("watched", vec![8080]);
        records.upsert_deployed(&spec, Ipv4Addr::new(100, 64, 0, 14), "c-watched");

        let mut rx = records.subscribe();
        // Baseline: mark the current value seen so the next `changed()`
        // only fires for the retraction below.
        rx.borrow_and_update();

        records.reconcile(&[], sweep_node_ip());

        rx.changed().await.expect("sender still alive");
        let snap = rx.borrow_and_update();
        assert_eq!(snap.get("watched").unwrap().health, Health::Retracted);
    }

    #[test]
    fn ready_filters_to_only_ready_records() {
        let records = ServiceRecords::new();
        records.upsert_deployed(
            &test_spec("healthy", vec![80]),
            Ipv4Addr::new(100, 64, 0, 15),
            "c-healthy",
        );
        records.upsert_deployed(
            &test_spec("sick", vec![80]),
            Ipv4Addr::new(100, 64, 0, 16),
            "c-sick",
        );
        records.retract(&MeshIdent("sick".into()));

        let ready = records.ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].ident, MeshIdent("healthy".into()));
    }

    // ── R594-F8: the discovery wire projection ──────────────────────────────

    #[test]
    fn wire_projection_carries_everything_needed_to_dial() {
        let records = ServiceRecords::new();
        let ip = Ipv4Addr::new(100, 64, 0, 20);
        records.upsert_deployed(&test_spec("api", vec![8080, 9090]), ip, "c-api");

        let body = discovery_body(&records.snapshot(), false);
        assert_eq!(body.version, WIRE_VERSION);
        assert_eq!(body.records.len(), 1);

        let row = &body.records[0];
        assert_eq!(row.ident, "api");
        assert_eq!(row.mesh_ip, ip);
        assert_eq!(row.ports, vec![8080, 9090]);
        assert_eq!(
            row.endpoints,
            vec![format!("{ip}:8080"), format!("{ip}:9090")],
            "one pre-paired endpoint per declared port, in port order"
        );
        assert_eq!(row.container_id, "c-api");
        assert_eq!(row.health, HEALTH_READY);
        assert_eq!(row.reason, None, "a ready record has nothing to explain");
        assert!(row.observed_at_unix_ms > 0);

        // R844-F15 rides beside the anonymous fields, it does not replace them:
        // the two assertions above are byte-for-byte what a pre-F15 consumer
        // saw, and these two are what a new one gets.
        assert_eq!(row.named_ports, named(&[("8080", 8080), ("9090", 9090)]));
        assert_eq!(
            row.named_endpoints,
            [
                ("8080".to_string(), format!("{ip}:8080")),
                ("9090".to_string(), format!("{ip}:9090")),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>()
        );
    }

    // ── R844-F15: named ports, end to end ───────────────────────────────────

    /// The ticket's headline case. A workload serving HTTP **and** a websocket
    /// listener is exactly the shape three bare numbers cannot describe: a
    /// consumer holding `[8080, 8443]` has to guess which is which, and guesses
    /// wrong the moment either moves. Here the supervisor reports real names —
    /// what R844-F14's allocator answers with — and both resolve by name.
    #[test]
    fn a_workload_serving_http_and_wss_resolves_both_ports_by_name() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);

        // Admitted with no declared port at all (the portless mirror shape),
        // then cold-admitted from what the supervisor actually bound.
        records.admit_bundle(&MeshIdent("chatty".into()), Some(node), None);
        records.reconcile(
            &[running_state_on_named_ports(
                "chatty",
                None,
                &[("http", 8080), ("wss", 8443)],
            )],
            Some(node),
        );

        let record = records.get(&MeshIdent("chatty".into())).unwrap();
        assert_eq!(record.port("http"), Some(8080));
        assert_eq!(record.port("wss"), Some(8443));
        assert_eq!(
            record.port("metrics"),
            None,
            "a name the workload does not serve must resolve to nothing, not to \
             whichever port sorted first"
        );
        assert_eq!(
            record.endpoint("wss"),
            Some(SocketAddrV4::new(node, 8443)),
            "the whole point: ask for the websocket listener and get the \
             websocket listener"
        );

        // The anonymous accessor keeps its old contract — one endpoint per
        // port, stable order — so nothing that was reading it has to change.
        assert_eq!(
            record.endpoints(),
            vec![
                SocketAddrV4::new(node, 8080),
                SocketAddrV4::new(node, 8443)
            ]
        );
    }

    /// Names survive the projection onto the wire, which is where they have to
    /// arrive for a *separate binary* (passway, `yah cloud apply`) to use them.
    /// A record that knows its ports are named and a wire that flattens them
    /// back to numbers would be a mechanism with no consumer.
    #[test]
    fn wire_round_trip_preserves_port_names() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        records.admit_bundle(&MeshIdent("chatty".into()), Some(node), None);
        records.reconcile(
            &[running_state_on_named_ports(
                "chatty",
                None,
                &[("http", 8080), ("wss", 8443)],
            )],
            Some(node),
        );

        let body = discovery_body(&records.snapshot(), true);
        let json = serde_json::to_string(&body).unwrap();
        let back: ServiceRecordsWire = serde_json::from_str(&json).unwrap();

        let row = &back.records[0];
        assert_eq!(row.named_ports, named(&[("http", 8080), ("wss", 8443)]));
        assert_eq!(
            row.named_endpoints.get("wss").map(String::as_str),
            Some(format!("{node}:8443").as_str())
        );
        // …and the anonymous halves still say exactly what they used to.
        assert_eq!(row.ports, vec![8080, 8443]);
        assert_eq!(
            row.endpoints,
            vec![format!("{node}:8080"), format!("{node}:8443")]
        );
    }

    /// A consumer built before R844-F15 must still be able to read a rolled
    /// node's answer. It cannot be linked against here, so the check is the one
    /// that actually matters: the JSON keys it reads are unchanged in name,
    /// type and value, and the new ones are additions it will ignore.
    #[test]
    fn the_wire_stays_readable_to_a_consumer_that_has_never_heard_of_port_names() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        records.admit_bundle(&MeshIdent("chatty".into()), Some(node), None);
        records.reconcile(
            &[running_state_on_named_ports(
                "chatty",
                None,
                &[("http", 8080), ("wss", 8443)],
            )],
            Some(node),
        );

        let json = serde_json::to_value(discovery_body(&records.snapshot(), true)).unwrap();
        let row = &json["records"][0];
        assert_eq!(
            row["ports"],
            serde_json::json!([8080, 8443]),
            "`ports` is still an array of numbers — reshaping it into an object \
             is what would break every un-rolled reader"
        );
        assert_eq!(
            row["endpoints"],
            serde_json::json!([format!("{node}:8080"), format!("{node}:8443")])
        );
        assert_eq!(
            json["version"], WIRE_VERSION,
            "an additive field is not a version bump: a v1 reader can still read this"
        );
    }

    /// A record whose ports were never named anywhere gets the same names at
    /// every tier, because one function decides them. If this drifts, a
    /// workload's port is called `http` in kamaji and something else in a
    /// service record, and the `PORT_<NAME>` contract (R844-T13) inherits the
    /// disagreement.
    #[test]
    fn an_anonymous_declaration_is_named_the_same_way_every_tier_names_it() {
        let records = ServiceRecords::new();
        let ip = Ipv4Addr::new(100, 64, 0, 5);
        records.upsert_deployed(&test_spec("api", vec![8080, 9090]), ip, "c-api");

        let record = records.get(&MeshIdent("api".into())).unwrap();
        assert_eq!(record.ports, name_anonymous_ports(&[8080, 9090]));
        assert_eq!(record.port("8080"), Some(8080));
        assert_eq!(record.port("9090"), Some(9090));
        assert_eq!(
            record.port("http"),
            None,
            "AN ANONYMOUS MULTI-PORT DECLARATION NAMES NOTHING `http`. Calling \
             the first one `http` would let ingress port resolution publish a \
             hostname at whichever listener happened to be written first — the \
             positional guess named ports exist to abolish. `None` sends the \
             operator to pin the port or name it in the manifest, which is \
             somebody stating the fact instead of the code inventing it."
        );

        // The single-port case has nothing to be ambiguous about, so it does
        // get the name — that is the whole asymmetry.
        let solo = ServiceRecords::new();
        solo.upsert_deployed(&test_spec("solo", vec![8080]), ip, "c-solo");
        assert_eq!(
            solo.get(&MeshIdent("solo".into())).unwrap().port("http"),
            Some(8080)
        );
    }

    /// Two names for one port collapse to one endpoint. `endpoints()` answers
    /// "where can I connect", and that is one place however many aliases point
    /// at it — a proxy that dialled the same socket twice would double-count it
    /// in its backend set.
    #[test]
    fn aliased_names_on_one_port_yield_one_endpoint() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        records.admit_bundle(&MeshIdent("aliased".into()), Some(node), None);
        records.reconcile(
            &[running_state_on_named_ports(
                "aliased",
                None,
                &[("http", 8080), ("web", 8080)],
            )],
            Some(node),
        );

        let record = records.get(&MeshIdent("aliased".into())).unwrap();
        assert_eq!(record.port("http"), Some(8080));
        assert_eq!(record.port("web"), Some(8080));
        assert_eq!(record.endpoints(), vec![SocketAddrV4::new(node, 8080)]);
        assert_eq!(
            record.named_endpoints().len(),
            2,
            "the named view keeps both names — only the anonymous one dedupes"
        );
    }

    #[test]
    fn wire_ready_filter_matches_the_registrys_own_ready_view() {
        let records = ServiceRecords::new();
        records.upsert_deployed(
            &test_spec("healthy", vec![80]),
            Ipv4Addr::new(100, 64, 0, 21),
            "c-healthy",
        );
        records.upsert_deployed(
            &test_spec("sick", vec![80]),
            Ipv4Addr::new(100, 64, 0, 22),
            "c-sick",
        );
        records.reconcile(&[running_state("healthy", None)], sweep_node_ip());

        let snapshot = records.snapshot();
        let filtered = discovery_body(&snapshot, true);
        assert_eq!(filtered.records.len(), 1);
        assert_eq!(filtered.records[0].ident, "healthy");

        // Unfiltered keeps the un-routable one, tagged with why.
        let all = discovery_body(&snapshot, false);
        assert_eq!(all.records.len(), 2);
        let sick = all.records.iter().find(|r| r.ident == "sick").unwrap();
        assert_eq!(sick.health, HEALTH_RETRACTED);
    }

    #[test]
    fn wire_not_ready_carries_the_machine_stable_reason() {
        let records = ServiceRecords::new();
        records.upsert_deployed(
            &test_spec("api", vec![80]),
            Ipv4Addr::new(100, 64, 0, 23),
            "c-api",
        );
        records.reconcile(
            &[WorkloadState {
                ident: MeshIdent("api".into()),
                container_id: "c-api".into(),
                status: WorkloadStatus::Stopping,
                mesh_ip: None,
                ports: BTreeMap::new(),
            }],
            sweep_node_ip(),
        );

        let row = &discovery_body(&records.snapshot(), false).records[0];
        assert_eq!(row.health, HEALTH_NOT_READY);
        assert_eq!(row.reason.as_deref(), Some("stopping"));
    }

    #[test]
    fn wire_body_round_trips_through_json() {
        let records = ServiceRecords::new();
        records.upsert_deployed(
            &test_spec("api", vec![8080]),
            Ipv4Addr::new(100, 64, 0, 24),
            "c-api",
        );
        let body = discovery_body(&records.snapshot(), true);

        // The contract passway re-declares on its side lives or dies here.
        let json = serde_json::to_string(&body).unwrap();
        let back: ServiceRecordsWire = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, WIRE_VERSION);
        assert_eq!(back.records[0].endpoints, body.records[0].endpoints);
        assert!(
            !json.contains("\"reason\""),
            "reason is omitted, not null, when there is none"
        );
    }

    #[test]
    fn wire_body_is_sorted_by_ident() {
        let records = ServiceRecords::new();
        for (i, name) in ["zeta", "alpha", "mid"].iter().enumerate() {
            records.upsert_deployed(
                &test_spec(name, vec![80]),
                Ipv4Addr::new(100, 64, 0, 30 + i as u8),
                "c",
            );
        }
        let body = discovery_body(&records.snapshot(), true);
        let idents: Vec<&str> = body.records.iter().map(|r| r.ident.as_str()).collect();
        assert_eq!(idents, vec!["alpha", "mid", "zeta"]);
    }

    // ── R594-F6: the port ledger / restart survival ─────────────────────────

    /// Simulate a yubaba restart: drop the registry, build a fresh one over
    /// the same ledger path. Nothing carries over except the file.
    fn restart(path: &std::path::Path) -> ServiceRecords {
        ServiceRecords::with_ledger(path.to_path_buf())
    }

    #[test]
    fn deployed_record_survives_restart_with_ports_and_mesh_ip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        let ip = Ipv4Addr::new(100, 64, 0, 20);

        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.upsert_deployed(&test_spec("api", vec![8080, 9090]), ip, "container-api");
        }

        // This is the whole point of the ticket: the port — which
        // `list_workloads()` does not carry, so nothing could re-derive it —
        // comes back without a redeploy.
        let record = restart(&ledger)
            .get(&MeshIdent("api".into()))
            .expect("record rehydrated from ledger");
        assert_eq!(record.ports, named(&[("8080", 8080), ("9090", 9090)]));
        assert_eq!(record.mesh_ip, ip);
        assert_eq!(record.container_id, "container-api");
        assert_eq!(
            record.endpoints(),
            vec![SocketAddrV4::new(ip, 8080), SocketAddrV4::new(ip, 9090)]
        );
    }

    #[test]
    fn rehydrated_record_is_not_ready_until_a_sweep_confirms_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.upsert_deployed(
                &test_spec("api", vec![8080]),
                Ipv4Addr::new(100, 64, 0, 21),
                "c-api",
            );
        }

        let records = restart(&ledger);
        let record = records.get(&MeshIdent("api".into())).unwrap();
        assert!(
            !record.is_ready(),
            "a record read off disk says nothing about whether the workload \
             is running right now — routing to it would be a black hole"
        );
        assert_eq!(
            record.health,
            Health::NotReady {
                reason: "rehydrated"
            }
        );
        assert!(records.ready().is_empty(), "not a routable upstream yet");
    }

    #[test]
    fn first_sweep_promotes_a_rehydrated_record_to_ready() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        // R876-B3: this node's own address, because the sweep below now
        // re-asserts it — a workload deployed here cannot have been placed at
        // some other node's address, and using one would make this test about
        // the override instead of about ready-promotion.
        let ip = sweep_node_ip().expect("the sweep supplies a node address");
        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.upsert_deployed(&test_spec("api", vec![8080]), ip, "c-api");
        }

        // The workload rode out the restart — the runtime still lists it.
        let records = restart(&ledger);
        let state = running_state("api", Some(ip));
        records.reconcile(std::slice::from_ref(&state), sweep_node_ip());

        let ready = records.ready();
        assert_eq!(ready.len(), 1, "confirmed-live record becomes routable");
        assert_eq!(ready[0].endpoints(), vec![SocketAddrV4::new(ip, 8080)]);
    }

    #[test]
    fn first_sweep_retracts_a_rehydrated_record_whose_workload_died() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.upsert_deployed(
                &test_spec("ghost", vec![8080]),
                Ipv4Addr::new(100, 64, 0, 23),
                "c-ghost",
            );
        }

        // The container did not survive the restart.
        let records = restart(&ledger);
        records.reconcile(&[], sweep_node_ip());
        assert_eq!(
            records.get(&MeshIdent("ghost".into())).unwrap().health,
            Health::Retracted
        );

        // …and it is gone from the ledger, so a second restart doesn't
        // resurrect it.
        assert!(restart(&ledger).snapshot().is_empty());
    }

    #[test]
    fn retracted_record_does_not_come_back_after_restart() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.upsert_deployed(
                &test_spec("keep", vec![80]),
                Ipv4Addr::new(100, 64, 0, 24),
                "c-keep",
            );
            records.upsert_deployed(
                &test_spec("destroyed", vec![80]),
                Ipv4Addr::new(100, 64, 0, 25),
                "c-destroyed",
            );
            // The `destroy_workload` path.
            records.retract(&MeshIdent("destroyed".into()));
        }

        let records = restart(&ledger);
        assert!(records.get(&MeshIdent("keep".into())).is_some());
        assert!(
            records.get(&MeshIdent("destroyed".into())).is_none(),
            "an explicitly destroyed workload must not be advertised again"
        );
    }

    #[test]
    fn missing_ledger_starts_empty_and_is_created_on_first_publish() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join("nested/deeper").join(LEDGER_FILE_NAME);

        let records = ServiceRecords::with_ledger(ledger.clone());
        assert!(records.snapshot().is_empty());
        assert!(!ledger.exists(), "nothing to write yet");

        records.upsert_deployed(
            &test_spec("api", vec![8080]),
            Ipv4Addr::new(100, 64, 0, 26),
            "c-api",
        );
        assert!(ledger.exists(), "parent dirs created, ledger written");
    }

    #[test]
    fn corrupt_or_unversioned_ledger_degrades_to_empty_instead_of_failing() {
        let tmp = tempfile::TempDir::new().unwrap();

        // A yubaba that refuses to boot over a mangled bookkeeping file is
        // worse than one that re-learns its records on the next deploy.
        let garbage = tmp.path().join("garbage.json");
        std::fs::write(&garbage, "{not json at all").unwrap();
        assert!(ServiceRecords::with_ledger(garbage).snapshot().is_empty());

        let future = tmp.path().join("future.json");
        std::fs::write(
            &future,
            serde_json::json!({ "version": LEDGER_VERSION + 1, "services": [] }).to_string(),
        )
        .unwrap();
        assert!(ServiceRecords::with_ledger(future).snapshot().is_empty());
    }

    /// The upgrade boot. A ledger written by a pre-R844-F15 yubaba spells its
    /// ports as bare arrays; the binary that reads it first is, by definition,
    /// the new one. Bumping [`LEDGER_VERSION`] would have discarded the whole
    /// file on exactly that boot — every serving workload undialable until its
    /// next deploy, which is the outage the ledger exists to prevent — so the
    /// old shape is read, not rejected.
    #[test]
    fn a_ledger_written_before_port_names_still_rehydrates() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        std::fs::write(
            &ledger,
            serde_json::json!({
                "version": LEDGER_VERSION,
                "services": [{
                    "ident": "api",
                    "mesh_ip": "100.64.0.5",
                    "ports": [8080, 9090],
                    "resolved_ports": [43117],
                    "container_id": "container-api",
                }],
            })
            .to_string(),
        )
        .unwrap();

        let record = ServiceRecords::with_ledger(ledger)
            .get(&MeshIdent("api".into()))
            .expect("an old-shaped ledger must still rehydrate its records");
        assert_eq!(record.ports, named(&[("8080", 8080), ("9090", 9090)]));
        assert_eq!(record.resolved_ports, named(&[("http", 43117)]));
        assert_eq!(
            record.port("http"),
            Some(43117),
            "resolved still beats declared after rehydration"
        );
    }

    /// And the names a live record carries survive the round trip to disk —
    /// otherwise a restart would silently re-synthesize `http`/`<number>` over
    /// whatever the supervisor actually called them.
    #[test]
    fn port_names_survive_the_ledger_round_trip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        let node = Ipv4Addr::new(100, 64, 0, 3);

        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.admit_bundle(&MeshIdent("chatty".into()), Some(node), None);
            records.reconcile(
                &[running_state_on_named_ports(
                    "chatty",
                    None,
                    &[("http", 8080), ("wss", 8443)],
                )],
                Some(node),
            );
        }

        let record = restart(&ledger)
            .get(&MeshIdent("chatty".into()))
            .expect("record rehydrated");
        assert_eq!(record.port("wss"), Some(8443));
        assert_eq!(record.resolved_ports, named(&[("http", 8080), ("wss", 8443)]));
    }

    #[test]
    fn ledgerless_registry_writes_nothing() {
        let records = ServiceRecords::new();
        assert!(records.ledger_path().is_none());
        // Must not panic or try to write anywhere.
        records.upsert_deployed(
            &test_spec("ephemeral", vec![80]),
            Ipv4Addr::new(100, 64, 0, 27),
            "c-eph",
        );
        assert!(records.get(&MeshIdent("ephemeral".into())).is_some());
    }

    // ── R881-B1: a workload nothing can reach is never Ready ──────────────────

    /// The measured live shape, verbatim: `noisetable-account`, tenant tier,
    /// its own netns, `[expose.mesh] ports = [4332]`, on the mesh node
    /// `100.64.0.3`. Inside the namespace the service answered HTTP 200; on the
    /// host `ss -lntp` showed nothing on 4332 and `curl
    /// http://100.64.0.3:4332/` returned 000 — yet the record said `ready` and
    /// `yah cloud apply` rendered `PASSWAY_UPSTREAMS=api.noisetable.com=
    /// 100.64.0.3:4332`.
    ///
    /// Three assertions, and the third is the one the old code could not
    /// satisfy however strict the deploy path got: the sweep must not promote
    /// the record back. `Health::from_status(Running)` is `Ready`, and the
    /// workload genuinely *is* running.
    #[test]
    fn an_isolated_netns_workload_is_published_unroutable_and_no_sweep_promotes_it() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        let ident = MeshIdent("noisetable-account".into());

        let warnings = capture_warnings(|| {
            records.upsert_deployed(&isolated_spec("noisetable-account", vec![4332]), node, "c-nt")
        });

        let record = records.get(&ident).expect(
            "the record must still EXIST — withholding it entirely would hide \
             the workload from `GET /service-records`, which is where an \
             operator looks",
        );
        assert!(!record.routable);
        assert_eq!(
            record.health,
            Health::NotReady {
                reason: REASON_UNROUTABLE
            }
        );
        assert!(
            records.ready().is_empty(),
            "an unreachable workload was offered to the front door as a ready \
             upstream at {:?}",
            record.endpoints()
        );
        assert!(
            warnings.contains("noisetable-account") && warnings.contains(REASON_UNROUTABLE),
            "the one place this defect is visible is this log line; got: {warnings}"
        );

        // The sweep: kamaji reports the container Running, because it is.
        records.reconcile(&[running_state("noisetable-account", Some(node))], Some(node));
        let after = records.get(&ident).expect("still tracked");
        assert_eq!(
            after.health,
            Health::NotReady {
                reason: REASON_UNROUTABLE
            },
            "a healthy supervisor report promoted an unreachable workload to \
             Ready — `Running` describes the process, not whether anything can \
             reach it"
        );
        assert!(records.ready().is_empty());
    }

    /// Non-vacuity anchor for the test above: change one annotation and the
    /// same workload is `Ready` and dialable. Without this, a `binds_node_ports`
    /// that answered `false` unconditionally would pass everything above.
    #[test]
    fn the_same_workload_host_networked_is_ready_and_dialable() {
        let records = ServiceRecords::new();
        let node = Ipv4Addr::new(100, 64, 0, 3);
        let ident = MeshIdent("noisetable-account".into());

        let warnings = capture_warnings(|| {
            records.upsert_deployed(&test_spec("noisetable-account", vec![4332]), node, "c-nt")
        });

        let record = records.get(&ident).expect("published");
        assert!(record.routable);
        assert_eq!(record.health, Health::Ready);
        assert_eq!(
            record.endpoints(),
            vec![SocketAddrV4::new(node, 4332)],
            "the reachable shape must still advertise the node's address — \
             that is R844-B11's invariant and R881-B1 does not narrow it"
        );
        assert_eq!(records.ready().len(), 1);
        assert!(warnings.is_empty(), "nothing to warn about; got: {warnings}");

        records.reconcile(&[running_state("noisetable-account", Some(node))], Some(node));
        assert_eq!(records.get(&ident).unwrap().health, Health::Ready);
    }

    /// A docker-published workload is namespaced too, but its host ports are
    /// mapped onto the node — so the node's address *is* where it answers.
    /// This is the pond shape, and it is why the predicate is not simply
    /// `wants_host_network()`.
    #[test]
    fn a_docker_published_workload_is_routable_despite_its_own_namespace() {
        let mut spec = isolated_spec("minio", vec![9000]);
        spec.annotations.insert(
            crate::pond::launcher::PUBLISH_ANNOTATION.to_string(),
            "9000:9000".to_string(),
        );
        assert!(binds_node_ports(&spec));

        let records = ServiceRecords::new();
        records.upsert_deployed(&spec, Ipv4Addr::new(100, 64, 0, 3), "c-minio");
        assert_eq!(
            records.get(&MeshIdent("minio".into())).unwrap().health,
            Health::Ready
        );
    }

    /// The restart hole, and the reason `routable` is a persisted record field
    /// rather than an in-memory set: after a reboot the `WorkloadSpec` is gone,
    /// so a sweep sees only `WorkloadStatus::Running` and would re-publish the
    /// dead upstream. The ledger has to carry the fact across.
    #[test]
    fn an_unroutable_record_survives_a_restart_still_unroutable() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join(LEDGER_FILE_NAME);
        let node = Ipv4Addr::new(100, 64, 0, 3);
        let ident = MeshIdent("noisetable-account".into());

        let before = ServiceRecords::with_ledger(path.clone());
        before.upsert_deployed(&isolated_spec("noisetable-account", vec![4332]), node, "c-nt");

        // A new process reading the ledger the old one wrote.
        let after = ServiceRecords::with_ledger(path);
        assert!(!after.get(&ident).expect("rehydrated").routable);
        after.reconcile(&[running_state("noisetable-account", Some(node))], Some(node));
        assert_eq!(
            after.get(&ident).unwrap().health,
            Health::NotReady {
                reason: REASON_UNROUTABLE
            },
            "a restart laundered an unroutable record into a ready one"
        );
        assert!(after.ready().is_empty());
    }

    /// A ledger written before R881-B1 has no `routable` key at all, and every
    /// record in it was one its writer served as `Ready`. Defaulting to `false`
    /// would withdraw every live upstream on the boot that installs this
    /// binary — an outage caused by a serde default.
    #[test]
    fn a_pre_r881_ledger_rehydrates_as_routable() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join(LEDGER_FILE_NAME);
        std::fs::write(
            &path,
            r#"{"version":1,"services":[
                 {"ident":"yah-cloud-admin","mesh_ip":"100.64.0.1",
                  "ports":{"http":4325},"container_id":"c-admin"}]}"#,
        )
        .expect("write ledger");

        let records = ServiceRecords::with_ledger(path);
        let ident = MeshIdent("yah-cloud-admin".into());
        assert!(records.get(&ident).expect("rehydrated").routable);

        let node = Ipv4Addr::new(100, 64, 0, 1);
        records.reconcile(&[running_state("yah-cloud-admin", Some(node))], Some(node));
        assert_eq!(records.get(&ident).unwrap().health, Health::Ready);
    }
}
