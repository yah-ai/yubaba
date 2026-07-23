//! yah-yubaba: per-machine infrastructure daemon for yah-managed mirrors.
//!
//! Phase 1 (R040-F8) ships the minimum HTTP surface needed to unblock live
//! provisioning (R040-T6):
//!
//! - `GET /health` — daemon liveness, version
//! - `GET /identity` — machine's hostkey fingerprint (404 until registered)
//! - `POST /register-hostkey` — accept a pubkey (gated on a single-use
//!   operator-issued bootstrap token, R593-F8), persist + return fingerprint
//!
//! Service-management endpoints (`/services`, `/compose`, `/logs`) belong to
//! R040-F7 and a follow-on yubaba ticket; this build wires the routes only as
//! a stub returning 501 so the route table is documented in code.
//!
//! ## Auth model (Phase 1)
//!
//! Plaintext HTTP. Headscale ACLs gate access on tcp/7443 over `tailscale0`.
//! Public-IP exposure must be blocked at the host firewall (cloud-init's
//! ufw rules). mTLS is a follow-on ticket.
//!
//! @yah:ticket(R040-F20, "Phase 2 — yubaba openraft coordination layer")
//! @yah:at(2026-05-05T00:29:06Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R040)
//! @yah:next("Implements the openraft state machine described in .yah/docs/architecture/A041-yah-mesh-bootstrap.md Phase 2. Pre-req for R040-F21 (Headscale floating coordinator).")
//! @yah:next("Library choice: openraft (databendlabs/openraft). NOT TiKV — TiKV is a distributed KV server with PD + multi-raft sharding designed for TBs / 100+ nodes; yubaba's coordination state is KB-scale across <10 nodes. openraft is a Rust library that compiles into the yubaba binary; yubaba owns the state machine + storage + transport.")
//! @yah:next("State machine scope: cluster membership (yubaba peers, current leader), service placement (which machine runs Headscale/Postgres/etc), distributed locks (in-progress provisions, mesh migrations), floating ingress claim (who currently owns the public Headscale tunnel). Headscale's own DB does NOT live here — that stays in Headscale-managed SQLite (R040-F21 handles via litestream).")
//! @yah:next("Transport: yubaba raft uses Tailscale-mesh IPs for peer-to-peer raft RPC. Means raft itself doesn't need Cloudflare ingress; mesh must be up before raft works (chicken-and-egg solved because mesh exists by Phase 2 — Phase 1a/1b already up).")
//! @yah:next("Storage backend open question: sled vs RocksDB vs minimal append-log+snapshot file. Lean toward minimal append-log unless RocksDB earns its weight in compaction. State volume is tiny so simpler wins.")
//! @yah:next("Surface: yubaba raft {status,peers,transfer-leader} subcommand. yah mesh status (R040-F18) gains a raft-state line once this lands.")
//! @yah:next("LAN local-first benefit: openraft works inside a partition with quorum, so a WAN-isolated LAN cluster can keep coordinating among itself. Free side-effect of building this layer for the cloud HA case.")
//! @yah:verify("yubaba raft status on a 3-node cluster shows leader + 2 followers; transfer-leader moves leadership; killing the leader elects a new one within seconds")
//! @yah:verify("Service-placement claim survives leader change (lock acquired by node A, A dies, new leader B inherits A's claim or marks it expired per TTL)")
//! @arch:see(.yah/docs/architecture/A041-yah-mesh-bootstrap.md)
//!
//! @yah:ticket(R040-F21, "Phase 2 — Headscale floating coordinator: yubaba-orchestrated + litestream-replicated")
//! @yah:at(2026-05-05T00:29:06Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R040)
//! @yah:next("Implements the floating-coordinator part of Phase 2 from .yah/docs/architecture/A041-yah-mesh-bootstrap.md. Hard-depends on R040-F20 (yubaba openraft layer) for leader election + service placement.")
//! @yah:next("Headscale state replication: litestream sidecar streams the SQLite WAL to Hetzner Object Storage (and optionally to peer yubaba nodes). On leader change, the new leader runs litestream restore (seconds for small DB) before starting Headscale. Worst-case staleness on failover bounded by litestream flush cadence (~1s default).")
//! @yah:next("Service-orchestration: yubaba runs Headscale + litestream as managed systemd units ONLY on the raft leader. Followers pre-warm their litestream restore by pulling periodic snapshots so promotion latency is bounded.")
//! @yah:next("Floating ingress (HTTPS only): each yubaba node runs a cloudflared replica connected to the mesh.<your-domain> named tunnel. All replicas serve a healthcheck endpoint that returns 200 only if 'I am the raft leader AND my Headscale is healthy', else 503. Cloudflare load-balances among 200-replicas, so leader change = ~10s ingress flip with no DNS or IP changes.")
//! @yah:next("Honors R040-T17: no Hetzner Floating IP plumbing. Cloudflare Tunnels handle HTTPS Headscale ingress. Reopen FIP discussion only if cloudflared healthcheck cadence proves too slow on failover or a non-HTTPS service requires it.")
//! @yah:next("yah mesh failover <name> subcommand: forces raft leadership transfer for ops + tests. Verifies the full 'old leader → 503, new leader → restore + start + 200, Cloudflare promotes' sequence.")
//! @yah:next("Open: litestream destination — S3 alone vs S3 + peer yubaba nodes. Start with S3-only; add peer replication if S3 outage scenarios warrant the extra complexity.")
//! @yah:verify("3-node cluster with yubaba raft + Headscale running on leader; killing the leader's machine triggers election + Headscale restore on new leader within ~30s; new node provision succeeds against the new leader using the unchanged mesh.<your-domain> URL")
//! @yah:verify("Existing tailnet tunnels stay up across leader change (continuous node-to-node ping uninterrupted)")
//! @yah:verify("yah mesh failover <other-machine> cleanly transfers leadership without data-plane impact")
//! @arch:see(.yah/docs/architecture/A041-yah-mesh-bootstrap.md)
//!
//! @yah:ticket(R278-F1, "POST /v1/rollouts — linear strategy + two-step policy (v1 slice)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T02:31:10Z)
//! @yah:status(review)
//! @yah:parent(R278)
//! @yah:next("Add rollout module to yubaba (src/rollout/) with RolloutStore + RolloutRecord types")
//! @yah:next("Wire POST /v1/rollouts, GET /v1/rollouts/{id}, POST /v1/rollouts/{id}/override routes")
//! @yah:next("Spawn RolloutEngine as background tokio task on rollout creation")
//! @arch:see(.yah/docs/working/W140-yah-yubaba-ci-cd.md)
//! @yah:handoff("POST /v1/rollouts (202), GET /v1/rollouts, GET /v1/rollouts/{id}, POST /v1/rollouts/{id}/override all wired in lib.rs. RolloutEngine background task spawned on create. RolloutStore + RolloutRecord + RolloutStatus types in yubaba/src/rollout/mod.rs. 6 new handler tests green (create, reject-non-linear, get, get-404, override-promote, list). YAH_PROMETHEUS_URL env + with_prometheus_url() builder wired.")
//!
//! @yah:relay(R406, "Core: Yubaba/Kamaji split + native driver + runtime parity")
//! @yah:at(2026-06-02T03:25:07Z)
//! @yah:status(open)
//! @yah:phase(P1)
//! @yah:parent(Q405)
//! @arch:see(.yah/docs/working/W154-yubaba-dual-runtime.md)
//!
//! @yah:ticket(R406-T8, "Yubaba-proper extraction: remove in-process supervision, dispatch to Kamaji over UDS")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T03:26:55Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R406)
//! @arch:see(.yah/docs/working/W154-yubaba-dual-runtime.md)
//! @yah:depends_on(R406-T2,R406-T6)
//! @yah:handoff("WARDEN-SIDE CONSTABLE DISPATCH LANDED. New crate dep + module crates/yah/yubaba/src/constable_client.rs KamajiClient owns a persistent UnixStream (tokio::net), serial-mutex'd via Inner { rd, wr, buf }. Surface: connect()/connect_with_timeout() runs Hello→Welcome handshake (captures ConstableInfo{version, kamaji_version}); list()/stop()/drain(budget)/probe() each allocate a fresh RequestId, write a postcard frame, await one KamajiToYubaba reply, and check the rid matches. Remote Error{code,message} surfaces as ClientError::Remote so yubaba HTTP handlers can branch on category. ServerState gained constable_client: Option<Arc<KamajiClient>> + with_constable_client() builder; yah-yubaba serve grew --kamaji-socket <path> with attach_constable_client() that warns + falls back to in-process runtime on connect failure (5s timeout — short enough not to stall systemd, long enough to ride the kamaji.service unit settling).")
//! @yah:handoff("HANDLERS WIRED TO PREFER CONSTABLE. GET /workloads, GET /workloads/{id}/state, POST /workloads/drain all check s.constable_client first and dispatch through the UDS when set; legacy s.runtime is the fallback. New response header x-workload-source: kamaji|runtime|stub lets callers branch on row shape (kamaji returns WorkloadEntry {id,state,pid}; runtime returns the existing rich WorkloadState). drain_workloads sends a structured Drain{flush_ms=5000, checkpoint_ms=1000} per workload — matches the parity floor in W154 §Runtime parity contract. POST /workloads/deploy is INTENTIONALLY still on the legacy path: Kamaji's Deploy arm returns Error{Internal, 'backend driver not implemented (R406-T4..T6/T11)'}; routing deploy through it before R406-T9 would break every single-node and clustered deploy. The handler doc-comment documents this explicitly.")
//! @yah:handoff("TESTS GREEN. 6 unit tests in constable_client::tests (handshake, list, stop, drain ack, remote-error, connect-timeout) using one-shot in-process UDS servers. 3 new integration tests in crates/yah/yubaba/tests/integration_constable_client.rs that spawn kamaji::serve_with_shutdown against a tempdir socket and round-trip handshake+list, drain-unknown, stop-unknown via the real yubaba client (no mocks on either side — proves wire compatibility). Full suite: 92 yubaba lib + 3 new yubaba integration + 47 kamaji + 19 kamaji-proto pass. cargo check -p yubaba --features containerd-integration also clean — no feature-flag regression.")
//! @yah:next("R406-T9 follow-on: once Kamaji's Deploy arm is wired (containerd backend), migrate POST /workloads/deploy in crates/yah/yubaba/src/lib.rs to dispatch via client.deploy(id, Workload::Container(spec)) — the validation + signature check + mesh-IP allocation + cloudflare ingress + headscale operator-bridge stays in yubaba (they are admission decisions, not supervision). The natural ordering inside the handler is: validate → allocate ident+mesh_ip → kamaji.deploy → on Ok, run cloudflare/headscale registration → on registration failure, kamaji.stop(id) for cleanup → respond. Tests-side: integration_smoke_filter / integration_single_node / integration_public_ingress currently use the legacy runtime; either give them a kamaji fixture or keep them on the runtime path and add a parallel kamaji-fixture suite. Pick whichever is less churn at T9 time.")
//! @yah:next("KamajiClient currently uses a request/response Mutex + serial. Kamaji will eventually push WorkloadStarted/WorkloadExited/DrainCompleted events (see KamajiToYubaba::DrainCompleted rustdoc) — at that point the client needs a background reader that demuxes responses from pushes by RequestId. The public API stays the same; the change is internal to constable_client.rs. Track as a separate sub-ticket once Kamaji grows the push channel; not in scope for T8.")
//! @yah:next("Deploy/get-state JSON shape currently changes when --kamaji-socket is set (WorkloadEntry vs WorkloadState). The x-workload-source response header is the explicit branch signal. If desktop/CLI consumers need a unified shape, the migration path is to enrich Kamaji's WorkloadEntry with mesh_ip+container_id once they live on Kamaji (T9). Not a T8 blocker.")
//! @yah:next("Try the binary end-to-end manually: in one shell, `cargo run -p kamaji -- --socket /tmp/kamaji.sock`. In another, `cargo run -p yubaba --features containerd-integration -- serve --kamaji-socket /tmp/kamaji.sock --bind 127.0.0.1:7443`. `curl http://127.0.0.1:7443/workloads` should return `{ workloads: [] }` with header x-workload-source: kamaji.")
//! @yah:verify("cargo test -p yubaba --lib  # 92 passed")
//! @yah:verify("cargo test -p yubaba --test integration_constable_client  # 3 passed")
//! @yah:verify("cargo test -p kamaji -p kamaji-proto  # 47+19 passed")
//! @yah:verify("cargo check -p yubaba && cargo check -p yubaba --features containerd-integration  # both clean")
//! @yah:gotcha("x-workload-source response header is the branch signal — kamaji, runtime, or stub. Don't assume row shape from URL alone; kamaji mode returns WorkloadEntry {id,state,pid} while runtime mode returns the rich WorkloadState {ident, container_id, status, mesh_ip}.")
//! @yah:gotcha("POST /workloads/deploy is still on the legacy in-process ContainerRuntime path on purpose. Kamaji's Deploy arm returns Error{Internal, 'backend driver not implemented (R406-T4..T6/T11)'} — switching deploy to the UDS now would break every deploy until R406-T9 lands the containerd backend.")
//!
//! @yah:ticket(R406-T9, "Containerd backend via Kamaji: route containerd RPC through Kamaji's WorkloadSpec enforcement")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T03:26:56Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R406)
//! @arch:see(.yah/docs/working/W154-yubaba-dual-runtime.md)
//! @yah:depends_on(R406-T8)
//! @yah:handoff("CONSTABLE'S CONTAINERD BACKEND LANDED. New module app/yah/kamaji/src/containerd.rs (Linux-feature-gated under containerd-integration) owns a tonic Channel to a containerd socket and exposes deploy(id, &WorkloadSpec) -> u32 pid, teardown(id) (idempotent kill+delete), list() -> Vec<WorkloadEntry>, and health() -> version. WorkloadSpec enforcement at dispatch is centralized in two pure functions: validate_spec_for_constable() rejects unresolved EnvValue::FromSecret / FromMesh (yubaba's admission must pre-resolve), and build_oci_spec() applies default-drop capabilities (CAP_NET_BIND_SERVICE only), noNewPrivileges=true, rlimit NOFILE=1024, /yah/<name> cgroupsPath, and PID/network/IPC/UTS/mount namespace isolation. Labels stamped on every container — yah.ident / yah.name / yah.tier — let reconciliation rediscover yah workloads vs other orchestrators sharing the containerd socket. Container ID is the WorkloadId.as_str() so yubaba's id round-trips through containerd for free.")
//! @yah:handoff("DISPATCH WIRED IN handle_message. Added ServerCtx { registry: Arc<Mutex<Registry>>, containerd: Option<Arc<ContainerdBackend>> } as the new dispatch context. handle_message takes &Arc<ServerCtx>; Deploy { Workload::Container(spec) } routes through the backend with feature-gated arms — without containerd-integration it returns BackendRefused with a clear 'rebuild with --features containerd-integration'. With the feature on but no --containerd-socket, ServerCtx.containerd is None and we return BackendRefused naming the flag. Deploy { Workload::MesofactStatic | Almanac } returns InvalidSpec — those live in yubaba's reconcilers, not kamaji. Stop dispatches teardown when the backend is attached; with no backend it acks regardless (Stop is idempotent — absence of the workload satisfies the requested end-state). List merges the in-memory registry (native workloads via R406-T5/T6) with containerd's container list when the backend is attached. Probe still returns Internal with a clear pointer at R406-T11 (probe protocol decision is its own ticket).")
//! @yah:handoff("BINARY WIRED. app/yah/kamaji/src/main.rs gained --containerd-socket / $CONTAINERD_SOCK; serve_with_ctx now drives the dispatch loop with a ServerCtx assembled at startup. Connect failure at startup is fatal (an operator asking for containerd should know immediately, not on the first deploy). Without the flag, warns that Deploy { Container } will refuse — sets clear expectations for the no-backend case. The non-containerd-integration build refuses --containerd-socket with a clean error and shifts dispatch into the no-backend branch.")
//! @yah:handoff("TESTS GREEN. kamaji lib: 49 without the feature, 58 with — new tests cover Container dispatch (with/without feature, without attached backend), MesofactStatic rejection, Stop idempotency, and 9 new pure-function backend tests (image_ref tag/digest, validate FromSecret/FromMesh, OCI cap allowlist, env-literal-only filter, label stamping, task-status mapping). Updated R406-T2/T6's uds_skeleton.rs integration test to expect Ack from Stop (was asserting the now-removed 'R406-T4' placeholder error). 1 uds_skeleton integration test passes both with and without the feature. Yubaba's tests/integration_constable_client.rs: 3 tests pass, including the updated stop_unknown_workload_returns_ack_for_idempotency. Full sweep: 92 yubaba lib + 3 yubaba integration + 49/58 kamaji lib + 19 kamaji-proto pass; cargo check clean in both feature modes for both crates.")
//! @yah:next("MIGRATE yubaba's POST /workloads/deploy through KamajiClient.deploy(). The wire payload is kamaji_proto::YubabaToKamaji::Deploy { request_id, id, spec: Workload::Container(spec) }. The migration order inside the handler: validate (already done) → allocate ident+mesh_ip (already done) → resolve EnvValue::FromMesh / FromSecret on yubaba's side (admission) → kamaji.deploy(id, Workload::Container(enriched_spec)) → on Ack, run cloudflared + headscale registration → on registration failure, kamaji.stop(id) for cleanup → respond. Add a deploy() method on yubaba's KamajiClient that sends YubabaToKamaji::Deploy and awaits KamajiToYubaba::Ack { kind: Deploy } | Error. This was deferred from R406-T8; T9 now unblocks it.")
//! @yah:next("Once yubaba's deploy path migrates, run end-to-end against a real containerd (Colima on macOS or a Hetzner CPX-11). The cloud-tier flow is: `yah cloud machine provision yah-cloud-1`; ensure release.yml ships kamaji alongside yubaba; `yah cloud workload deploy yubaba-probe --machine yah-cloud-1`. Verify kamaji logs show 'containerd backend attached' and `curl http://<yubaba>:7443/workloads` returns the container with x-workload-source: kamaji (R406-T8's header).")
//! @yah:next("R406-T10 (log fan-in to journald) is now ready — the current backend writes stdout/stderr to /var/log/yah/<ns>/<id>/{stdout,stderr}.log; T10 swaps that for sd_journal_send so logs land in journald uniformly across native + container.")
//! @yah:next("R406-T11 (probe protocol) is independently ready and will replace the current 'Internal: probe protocol not implemented yet' arm with whatever shape T11 picks (HTTP endpoint vs stdio sentinel).")
//! @yah:next("R406-T13 (systemd unit ship path) — once yubaba.service + kamaji.service ship together via release.yml, both daemons start on a fresh provision; the kamaji.service unit needs ExecStart=kamaji --containerd-socket /run/containerd/containerd.sock (or set CONTAINERD_SOCK in EnvironmentFile).")
//! @yah:verify("cargo test -p kamaji                                  # 49 passed (+ 1 uds)")
//! @yah:verify("cargo test -p kamaji --features containerd-integration # 58 passed (+ 1 uds)")
//! @yah:verify("cargo test -p yubaba                                     # 92 lib + 3 integration_constable_client")
//! @yah:verify("cargo check -p kamaji --features containerd-integration && cargo check -p yubaba --features containerd-integration  # both clean")
//! @yah:verify("cargo run -q -p kamaji -- --help                       # mentions --containerd-socket")
//! @yah:gotcha("Container ID == WorkloadId.as_str(). If yubaba ever sends two Deploys with the same id, the second tears down the first (idempotent redeploy by design). Stable across restarts so reconciliation can rediscover workloads via the yah.ident label.")
//! @yah:gotcha("ContainerdBackend::deploy fails before container creation if the image isn't already in containerd's image store — pulling is yubaba admission's job (or pre-pulled at machine provision per R040-F11). The error surfaces as BackendError::Containerd ('image not found in containerd: <ref> — pre-pull required').")
//! @yah:gotcha("Kamaji's default capability allowlist is intentionally tighter than yubaba's old runtime::containerd impl: CAP_NET_BIND_SERVICE only (drops CAP_KILL). Workloads that send signals to non-self pids will need an explicit cap field in WorkloadSpec — not currently in the type. Track as a follow-up if a real workload trips this.")
//! @yah:gotcha("Stop without a containerd backend acks anything — this differs from R406-T8's yubaba-side expectations which expected a 'backend not implemented' error. The integration test in tests/uds_skeleton.rs and yubaba's tests/integration_constable_client.rs were updated to expect Ack.")
//!
//! @yah:ticket(R482-T3, "Single-node raft bootstrap + WireGuard interface + xlb-net registration")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:at(2026-07-17T16:59:49Z)
//! @yah:phase(P2)
//! @yah:parent(R482)
//! @yah:next("Cluster-of-one raft init per W197 §'Single-node raft'. No peers, no leader election complexity. Future multi-machine join uses yubaba's existing join-by-NodeId flow.")
//! @yah:next("Bring up wireguard0 + register with xlb-net so desktop can dial via iroh per A043 2026-05-22 update. Default seed list shipped in camp binary; --xlb-seed <node-id> override per W197 §Open questions 2.")
//! @yah:next("Out-of-scope: certificate/identity provisioning (W197 §Open questions 3 — TOFU lives in T5).")
//! @yah:verify("cargo test -p yubaba --test bootstrap_single_node")
//! @arch:see(.yah/docs/working/W197-camp-bootstraps-yubaba.md)
//! @arch:see(.yah/docs/architecture/A032-yah-cluster-mesh.md)
//! @yah:handoff("Single-node raft cluster-of-one auto-bootstrap SHIPPED + verified. New `raft::bootstrap_single_node(raft, node_id, addr)` in oss/yubaba/crates/yubaba/src/raft/mod.rs: idempotent init of a one-voter cluster (maps InitializeError::NotAllowed -> Ok(false), same as POST /raft/initialize). Wired into serve via new flags `--bootstrap-single-node` + `--raft-advertise-addr` (main.rs), called after with_secret_state and before the leader watcher spawns so the watcher sees the self-election. Cluster-of-one issues NO peer RPC, so it is independent of the parked raft/mesh transport (R593-T7). verify GREEN: cargo test -p yubaba --test bootstrap_single_node (2 passed: live one-voter cluster w/ client_write commit; idempotent across restart). cargo check -p yubaba --bins clean; flags render in serve --help.")
//! @yah:handoff("SCOPE SPLIT: the WireGuard `wireguard0` bringup + xlb-net/iroh registration half of this ticket's title is DEFERRED as park-blocked, NOT abandoned. Per raft/network.rs R593-T7 ('Raft/mesh RPC transport adoption on mshr::Endpoint ... blocked-linked, do not implement around', depends_on R277+R570) and identity/bootstrap.rs (mshr QUIC transport 'parked by design; do not implement around it'), the cluster-mesh + control-plane transport must not be scaffolded now. xlb-net is not even a yubaba dep. That work already has homes: R277-F2 (wireguard0 up) + R277-F3 (consume xlb-net::Endpoint) in the backlog R277 relay, gated behind the R593-T7 mshr-transport decision. The W197 §'Single-node raft' deliverable + this ticket's stated verify are fully covered by the raft bootstrap above.")
//!
//! @yah:ticket(R484-T5, "Rewire yubaba + app/yah/kamaji binary to depend on crates/yah/kamaji; delete yubaba/src/runtime/")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-08T02:31:15Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R484)
//! @arch:see(.yah/docs/working/W199-kamaji-universal-supervisor.md)
//! @yah:depends_on(R484-T2)
//! @yah:depends_on(R484-T4)
//! @yah:handoff("Yubaba has been fully rewired off the kamaji-core shims. Deleted: crates/yah/yubaba/src/runtime/{containerd,docker,fake}.rs (~2.4k LoC of dead-since-T2 duplicates the shim layer was hiding) and crates/yah/yubaba/src/constable_client.rs (the T4 re-export shim). Migrated all yubaba call sites and integration tests: lib.rs `use constable_client::KamajiClient` → `use constable_core::sibling::KamajiClient`; `use runtime::ContainerRuntime` → `use constable_core::Kamaji as ContainerRuntime`; main.rs `yubaba::runtime::containerd::ContainerdRuntime` → `constable_core::containerd::ContainerdRuntime`; `yubaba::constable_client::connect_with_timeout` → `constable_core::sibling::connect_with_timeout`; six yubaba integration tests rewritten to import constable_core directly.")
//! @yah:handoff("yubaba-test-harness (which the integration tests pull in) followed the same path — `yubaba::runtime::{WorkloadState,WorkloadStatus,ContainerRuntime}` → `constable_core::*`; added `kamaji-core = { path = \"../kamaji\" }` to its Cargo.toml. yubaba-test-macros's proc-macro now emits `::constable_core::containerd::ContainerdRuntime` instead of `yubaba::runtime::containerd::ContainerdRuntime` in the generated `__local` variant; the smoke variant still references `yubaba::runtime::DummyRuntime` because DummyRuntime correctly stays in yubaba (it's yubaba-smoke-tier specific).")
//! @yah:handoff("crates/yah/yubaba/src/runtime/mod.rs was kept (not deleted) for two reasons: (1) DummyRuntime lives there and is referenced by the smoke-test macro path; (2) the file is the source-of-truth line anchor for several review-status tickets (R091-F1, R256-F10, R471-T2, R471-F3, R484, R484-T2, R484-T3) plus R484-T4 which was relocated from the deleted constable_client.rs into this file. The `pub use constable_core::*` shim re-exports were removed; only the DummyRuntime impl and the historical annotations remain. The file's module doc was rewritten to reflect its new minimal role.")
//! @yah:handoff("app/yah/kamaji binary intentionally NOT rewired to import kamaji-core. The binary is the SERVER side of the W154 UDS protocol — it accepts kamaji-proto frames and dispatches to its own containerd/native/cgroup/pidfd impls. The Kamaji trait in kamaji-core is the CLIENT-facing contract; KamajiClient (in kamaji-core::sibling) talks to this binary over UDS. Both crates already depend on kamaji-proto for the wire format; that IS the wiring. Reshaping the binary to internally use kamaji-core::Kamaji trait dispatch would be a substantial refactor (it'd need to convert kamaji-proto's WorkloadState wire enum to kamaji-core's WorkloadState struct on every call) and is out of scope here.")
//! @yah:handoff("Verified: cargo check -p kamaji-core --all-features -p yubaba -p yubaba-test-harness -p yubaba-test-macros -p kamaji -p kamaji-proto --all-targets → clean. cargo test -p kamaji-core --all-features --lib → 61 passed. cargo test -p yubaba --lib --features containerd-integration,testing,docker-integration → 102 passed. cargo test -p yubaba --test integration_constable_client → 3 passed. cargo test -p kamaji --all-features → lib+integration green. Pre-existing build errors in scryer/task/qed-gha (missing .await on opaque Future types) are unchanged — they exist on the parent commit and are unrelated to T5.")
//! @yah:next("Sign-off check: skim crates/yah/yubaba/src/runtime/mod.rs (annotations + DummyRuntime only — no shim re-exports left), grep for `constable_core::` across yubaba's src + tests to confirm the migration is complete, then archive R484-T5.")
//! @yah:next("T6 (desktop adopts inlined kamaji): app/yah/desktop adds kamaji-core dep, calls BackendAvailability::probe() at startup, uses Inlined::pick(&availability, &[Backend::Docker], factory) to construct an Arc<dyn Kamaji> backed by DockerRuntime, holds it on state. Drops any direct docker/containerd references from desktop's existing code paths.")
//! @yah:next("T7 (inlined-crash next-boot reconcile): on Tauri restart, list yah.slice cgroups + yah-labeled containers and re-adopt them rather than killing-and-restarting. Independent of T6.")
//! @yah:verify("cargo check -p kamaji-core -p yubaba -p yubaba-test-harness -p yubaba-test-macros -p kamaji -p kamaji-proto --all-features --all-targets  # clean (modulo pre-existing scryer/task/qed-gha errors)")
//! @yah:verify("cargo test -p kamaji-core --all-features --lib  # 61 passed")
//! @yah:verify("cargo test -p yubaba --lib --features containerd-integration,testing,docker-integration  # 102 passed")
//! @yah:verify("cargo test -p yubaba --test integration_constable_client --features containerd-integration,testing,docker-integration  # 3 passed")
//! @yah:verify("cargo test -p kamaji --all-features  # green")
//! @yah:verify("test ! -f crates/yah/yubaba/src/constable_client.rs  # shim deleted")
//! @yah:verify("test ! -f crates/yah/yubaba/src/runtime/containerd.rs  # orphaned dup deleted")
//! @yah:verify("test ! -f crates/yah/yubaba/src/runtime/docker.rs  # orphaned dup deleted")
//! @yah:verify("test ! -f crates/yah/yubaba/src/runtime/fake.rs  # orphaned dup deleted")
//! @yah:verify("! grep -r 'yubaba::runtime::ContainerRuntime\\|yubaba::runtime::containerd::\\|yubaba::runtime::fake::\\|yubaba::runtime::docker::\\|yubaba::constable_client::' crates/yah/yubaba/src/ crates/yah/yubaba/tests/ crates/yah/yubaba-test-harness/src/ app/yah/  # no remaining shim refs in source")
//!
//! @yah:ticket(R556-F7-T3, "yubaba: advertise local scryer in /services discovery (one entry, no proxy)")
//! @yah:status(review)
//! @yah:at(2026-06-30T06:24:56Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P1)
//! @yah:parent(R556-F7)
//! @yah:next("When kamaji is running a scryer on this node, add a /services entry: {name:'scryer', endpoint:'http://<tailnet-ip>:6543', capabilities:['events.query','events.aggregate'], managed_by:'kamaji'} per W264 §Discovery. Existing get_services route at oss/yubaba/crates/yubaba/src/lib.rs:579.")
//! @yah:next("Endpoint discovery entry is tag-gated (it leaks endpoint location); the data-path ACL stays at scryer's HTTP listener (W264 §Trust boundary).")
//! @yah:next("No proxy route — yubaba is not in the query data path. Consumers connect to scryer directly using the advertised endpoint.")
//! @yah:next("Sequencing gotcha: ship scryer's HTTP listener (R556-F7-T2) before this entry resolves to a live endpoint.")
//! @yah:next("Tier: Thief — single discovery entry added to an existing surface; rote integration, no novel logic.")
//! @arch:see(.yah/docs/working/W264-kamaji-managed-scryer.md)
//!
//! @yah:ticket(R608-T3, "Enabler: expose kamaji version on GET /health so verify asserts the yubaba+kamaji pair")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-07-16T15:09:52Z)
//! @yah:phase(P1)
//! @yah:parent(R608)
//! @yah:next("Today HealthBody (oss/yubaba/crates/yubaba/src/lib.rs:1078) = {status,name,version,mode} — version is yubaba's CARGO_PKG_VERSION only; kamaji's version is captured at the Hello handshake (ConstableInfo{version,kamaji_version}) but NOT on /health, which is how the live 0.8.17/0.8.18 kamaji skew went unnoticed (W275 OQ5). Add kamaji_version (from the attached KamajiClient's ConstableInfo, Option since it may be in-process-fallback) to HealthBody so the executor's verify asserts BOTH halves of the atomic pair over one HTTP read. Alternative if awkward: executor SSHs 'kamaji --version' — but /health is cleaner.")
//! @yah:verify("GET /health returns kamaji_version when the kamaji UDS is attached; null/absent under in-process fallback; existing health_returns_ok test still green")
//! @yah:tier(Thief)
//!
//! @yah:ticket(R608-B11, "yubaba /raft/transfer-leader is a 501 stub — no leadership transfer; blocks quorum-safe leader roll (dogfood finding)")
//! @yah:status(review)
//! @yah:at(2026-07-18T00:54:27Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R608)
//! @yah:severity(high)
//! @yah:next("OPERATOR: supervised live verify on the 3-voter fleet — POST /raft/transfer-leader on the leader targeting a follower voter; confirm current_leader relocates + mesh/leader-health 200 flips + membership stays 3 voters.")
//! @yah:next("Then fix W275 operational-grounding table: cloud.mesh_failover / POST /raft/transfer-leader is NOW a verified primitive (server implemented; was a 501 stub — only the client path had ever been checked).")
//! @yah:handoff("IMPLEMENTED — Option B (trigger-elect-on-target), operator-approved. NO openraft bump; membership never touched -> no quorum dip, R608 executor undrain stays a correct no-op. oss/yubaba/crates/yubaba/src/lib.rs: new POST /raft/trigger-elect (local raft.trigger().elect() — openraft 0.9 elect is local-only); rewrote raft_transfer_leader to: (a) plan_transfer() precheck [must be leader / `to` is a voter / `to` caught up within MAX_TRANSFER_LAG_ENTRIES=8], (b) POST /raft/trigger-elect to `to` over mesh HTTP, (c) poll current_leader until ==`to`, bounded by TRANSFER_CONFIRM_TIMEOUT=10s, (d) 202 on success, GATEWAY_TIMEOUT (never a silent success) if leadership doesn't move. Idempotent: `to` already leads -> 202 no-op. `to` target is now honored. Also updated the stale 501-era doc on cloud-client raft_transfer_leader (crates/yah/cloud-client/src/lib.rs).")
//! @yah:verify("cd oss/yubaba && cargo test -p yubaba --lib plan_transfer  # 9 pure-fn precondition tests pass (already-leader noop, not-leader 409, non-voter 400, lagging 409, caught-up proceed)")
//! @yah:verify("cd oss/yubaba && cargo test -p yubaba --test raft_transfer_leader  # e2e 3-node loopback cluster (DummyRuntime, credential-free): leadership moves to target, membership stays 1 uniform 3-voter config, follower 409s, idempotent noop; ran 5x stable")
//! @yah:gotcha("LIVE fleet verify still GATED to operator supervision — do NOT force elections on south/west/east 0.8.18.")
//! @yah:gotcha("pond_reconciler_smoke.rs has a PRE-EXISTING, UNRELATED compile error (PondDeployReq.mesofact_dev — a peer's in-flight edit on the shared tree), not caused by this ticket; my lib+test targets compile clean.")
//! @yah:handoff("IMPLEMENTED Option B (trigger-elect-on-target) end-to-end then FALSIFIED it with an e2e test. Code in oss/yubaba/crates/yubaba/src/lib.rs: new POST /raft/trigger-elect (local raft.trigger().elect()), rewritten raft_transfer_leader with a pure plan_transfer() decision fn (leader-only, voter-only, caught-up guard) + trigger-elect-to-target-over-HTTP + poll current_leader until it moves. 9 plan_transfer unit tests PASS (cargo test -p yubaba --lib plan_transfer).")
//! @yah:handoff("BLOCKER FINDING: the mechanism does NOT work against a healthy leader in openraft 0.9. e2e test (tests/raft_transfer_leader.rs, 3-node loopback cluster) returns 504 -- leadership never moves. Root cause (source-audited, engine_impl.rs::handle_vote_req:296-308): a voter rejects a vote-request while its leader lease is valid (vote.is_committed() && now <= vote_utime + lease; lease = election_timeout_max = 3s). The sitting leader keeps heartbeating, so followers' leases never expire and the force-elected target NEVER wins. openraft 0.9 has NO TimeoutNow/transfer primitive to bypass the lease (only elect/heartbeat/snapshot/purge + enable_heartbeat). My spike's Option B recommendation missed the leader-lease -- I was wrong; the e2e caught it. e2e test marked #[ignore] (suite stays green, repro on demand).")
//! @yah:handoff("NET: Option B is dead in 0.9. This reverses the basis for the B-over-A/C pick, so escalating rather than pivoting unilaterally. Only Option A (change_membership -- leader VOLUNTARILY steps down, no lease fight, so it actually works, but has the 3->2 voter dip + restore-on-new-leader + no-op-undrain permanent-voter-loss issues from the original spike) and Option C (openraft 0.10 real transfer_leader = TimeoutNow + lease bypass) remain viable. Nothing committed.")
//! @yah:next("OPERATOR DECISION (Ashguard/leif) A vs C -- B is falsified: (A) change_membership step-down: reliably moves leadership but needs a /raft/promote-voter endpoint + a re-promote step wired into the R608 executor undrain (app/yah/cli/src/rollout/yubaba.rs:245, currently a no-op) or it permanently drops 3->2 voters; also dips fault tolerance mid-roll and can't honor `to` precisely. (C) bump openraft 0.9->0.10+: real trigger().transfer_leader(to), cleanest semantics, keeps membership intact, honors `to` -- but a consensus-lib major bump on the live 3-voter fleet (south/west/east @ 0.8.18).")
//! @yah:next("Whichever is chosen: the existing scaffolding (trigger-elect endpoint, plan_transfer guard, poll-confirm loop, e2e harness) is reusable. For A: keep trigger-elect? no -- swap the handler body to change_membership(exclude self) and un-ignore/rewrite the e2e to assert the demote+repromote. For C: replace the handler body with raft.trigger().transfer_leader(to) and un-ignore the e2e as-is (it already asserts membership stays a uniform 3-voter config).")
//! @yah:next("A 3rd option B'' exists but is NOT recommended: leader enable_heartbeat(false) + wait > leader_lease (~3s) for follower leases to expire + trigger-elect -- introduces a multi-second leaderless window and a non-deterministic winner (can't guarantee `to`); it reinvents transfer_leader badly. Mentioned for completeness only.")
//! @yah:handoff("LANDED Option C (operator-approved): bumped openraft 0.9.24 -> 0.10.0-alpha.30 and rewired raft_transfer_leader to the native Trigger::transfer_leader (TimeoutNow to the target that bypasses the follower leader-lease -> actually unseats a healthy leader, which the falsified 0.9 force-elect could not). Membership is never touched, so quorum tolerance is retained (no voter dip). Full openraft-0.10 migration of oss/yubaba: raft/mod.rs (declare_raft_types trimmed, YubabaRaft=Raft<Cfg,SM>, Display for YubabaRequest), raft/store.rs (storage-v2: io::Error, IOFlushed, apply-stream/EntryResponder, LogIdOf/VoteOf aliases, SnapshotData on SM), raft/network.rs (RaftNetworkV2 + streaming full_snapshot + transfer_leader over HTTP; v1 chunked path removed in 0.10), lib.rs (append/vote/snapshot/transfer-leader-msg handlers return Result<_,RaftError>; new /raft/snapshot + /raft/transfer-leader-msg routes replace /raft/install-snapshot + /raft/trigger-elect; metrics receiver .borrow()->.borrow_watched() via WatchReceiver). Dropped the Option-B trigger-elect scaffolding + lag guard; plan_transfer now leader-only/voter-only/idempotent.")
//! @yah:handoff("VERIFIED GREEN (oss/yubaba workspace): cargo test -p yubaba --lib = 186 passed (incl. migrated store secrets test + 5 plan_transfer guards); bootstrap_single_node = 2 passed; tests/raft_transfer_leader.rs e2e (real 3-node loopback cluster) = PASS -> leadership moves to the requested voter AND membership stays a single uniform 3-voter config (the R608-B11 invariant). The e2e is un-ignored (was #[ignore]d as the Option-B falsification repro). Live-fleet verification remains gated to operator supervision -- NOT run against south/west/east.")
//! @yah:handoff("CROSS-WORKSPACE: openraft 0.10 requires thiserror >=2.0.18; applied `cargo update -p thiserror@2.0.17 --precise 2.0.18` to the ROOT Cargo.lock (clean single-dep resolution, dry-run verified; root `cargo metadata` resolves). oss/yubaba + oss/yubaba-test-harness Cargo.toml pins are =0.10.0-alpha.30 (alpha, operator-accepted). NOTE (pre-existing, NOT mine): oss/yubaba/crates/yubaba/tests/pond_reconciler_smoke.rs fails to compile (PondDeployReq has no field mesofact_dev) -- committed break unrelated to raft; I ran raft tests via explicit --test targets to avoid it. Nothing committed (operator handles git).")
//!
//! @yah:ticket(R603-B6, "R603-T5 durable produced dir unreachable on-box: yubaba.service ProtectSystem=strict blocks ensure_durable_produced_dirs (ReadWritePaths missing /var/lib/yah/qed/produced)")
//! @yah:status(review)
//! @yah:at(2026-07-20T22:34:35Z)
//! @yah:assignee(agent:claude)
//! @yah:parent(R603)
//! @yah:gotcha("Surfaced by R608-F10's on-box proof 2026-07-19 (the exact on-box verify R603-T5 said couldn't run from the Mac). us-west-002 deployed 0.8.20 (carries ensure_durable_produced_dirs), but `yah qed run rusty-v8-musl` STILL failed the containerd bind-mount: `open /var/lib/yah/qed/produced/<id>: no such file or directory`. yubaba journal: WARN 'failed to create durable produced dir ... error: Read-only file system (os error 30)'. ROOT CAUSE: ensure_durable_produced_dirs runs IN yubaba, but yubaba.service has ProtectSystem=strict + ReadWritePaths=/var/lib/yah/yubaba /run/yubaba -- which excludes /var/lib/yah/qed/produced, so create_dir_all is denied. R603-T5 shipped the code but NOT the required unit-file grant + host-dir creation.")
//! @yah:gotcha("TEMP box hand-patch applied 2026-07-19 to unblock the build: sudo mkdir -p /var/lib/yah/qed/produced on us-west-002 + appended /var/lib/yah/qed/produced to yubaba.service ReadWritePaths + daemon-reload + restart. After that rusty-v8-musl cleared the mount and the V8 build ran. This hand-patch is NOT in the repo -- the next real deploy reverts it.")
//! @yah:next("PRIMARY FIX (this is the real blocker, worse than the ReadWritePaths gap): oss/qed runner execute_step_remote's remote-forge wait loop falsely times out an offloaded step after ~10s while step.timeout=9000. On that timeout it DESTROYS the workload -> yubaba reap_produced_dir (logs only at debug, hence invisible) deletes /var/lib/yah/qed/produced/<forge_id> -- but kamaji does NOT actually kill the container, which keeps building for ~57min. The container's bind mount is left pointing at a DELETED inode, so the build's final write dies with ENOENT and the finished artifact is lost. Proven 2026-07-20: nsenter into the live build showed `touch /yah/produced/.writetest -> No such file or directory`.")
//! @yah:next("SECONDARY FIX (still needed): add /var/lib/yah/qed/produced to ReadWritePaths in app/yah/cli/resources/yubaba.service + ensure the dir exists pre-start under ProtectSystem=strict (ExecStartPre/tmpfiles). Hand-patched on us-west-002 2026-07-19; reverts on next deploy.")
//! @yah:next("DESTROY SEMANTICS BUG: a destroy that reaps the produced dir but leaves the container running is incoherent -- either actually stop the workload or don't reap its output dir. reap_produced_dir success logs at debug; raise to info so this is visible in the journal.")
//! @yah:handoff("PRIMARY FIX LANDED 2026-07-20 (oss/qed). Root cause was NOT a wait-loop design flaw but a UNIT MISMATCH: QedStep::timeout is written in SECONDS by every pipeline TOML (P018 `timeout = 9000` = '2.5h cap'; P001 `1800` for cargo check; P015 `3600`), but all three lowering sites in runner.rs did `step.timeout.map(Millis::from_ms)` -- reading 9000 as 9000 MILLIseconds = 9s. That is exactly the ~10s failure observed (05:51:18 -> 05:51:28). Fix: from_ms -> Millis::from_secs at all 3 sites (build_subprocess_spec, build-image, execute_step_remote); documented QedStep::timeout as seconds with the regression history; added test runner::tests::step_timeout_is_seconds_not_millis asserting 9000 -> 9_000_000ms and that None stays unbounded.")
//! @yah:handoff("WHY IT STAYED INVISIBLE: the LOCAL forge driver never enforces spec.timeout (oss/qed/crates/task/src/local.rs), so every local step silently ignored its (wrong) budget and nobody noticed 1800s->1.8s. Only the REMOTE path enforces it (task/src/remote.rs run_log_task wraps ingest_logs in tokio::time::timeout), so the bug only ever bit offloaded build-worker steps -- i.e. rusty-v8-musl.")
//! @yah:handoff("VERIFY-RESULTS: yah-qed lib 608 passed / 5 failed. The 5 are the KNOWN pre-existing rename churn (PackageNotFound 'qed' now yah-qed; on_success warden-deploy vs yubaba-deploy) in config/transform/preflight -- files this fix never touched. Zero regressions.")
//! @yah:handoff("NOT YET IN EFFECT: `yah qed run` proxies to the camp daemon, which is still running the OLD binary. The fix needs a daemon rebuild+restart (or an in-process run) before a clean rusty-v8-musl goes end-to-end.")
//! @yah:handoff("ALL 3 FIXES LANDED + E2E CONFIRMED GREEN 2026-07-20. (1) oss/qed runner: QedStep::timeout lowered with Millis::from_secs (was from_ms -> P018's 9000s '2.5h cap' became 9s); field documented; regression test step_timeout_is_seconds_not_millis. (2) app/yah/cli/resources/yubaba.service: added `yah/qed/produced` to StateDirectory (systemd CREATES the dir AND makes it writable -- strictly better than the box hand-patch, which needed a separate mkdir) + listed /var/lib/yah/qed/produced in ReadWritePaths for consistency. (3) yubaba destroy_workload: reap_produced_dir now fires ONLY on a CONFIRMED teardown (teardown_status == 'destroyed'); a 'not_found' teardown no longer deletes the output dir of a possibly-still-running container -- that was the actual destructive defect. reap success log raised debug -> info.")
//! @yah:handoff("PROOF: `yah qed run rusty-v8-musl` ran GREEN for the first time ever -- qed.status = success, 58m21s (21:33:59 -> 22:32:20 UTC), run 9243ca2e. Durable dir /var/lib/yah/qed/produced/b96b0784-... persisted the whole run (previously reaped within ~10s), the tar landed in it (30714560 bytes), and retrieve_remote_artifacts auto-landed it content-addressed at .yah/cache/artifacts/ebb53464...9971b2 -- that retrieval leg had NEVER executed before.")
//! @yah:handoff("DETERMINISM VERIFIED (not assumed): two independent builds an hour apart produced byte-identical tars, sha256 e856a18d14146fd199040c2557881c38e7275a911e3f6c2076587e5acbb42d01. That validated pasting the recorded hashes into build/rusty-v8/workload.toml, closing R546-T3's code side.")
//! @yah:handoff("TEST GAP (deliberate, not done): the reap guard is NOT unit-tested -- workload_spec::forge_produced::HOST_ROOT is a hardcoded absolute /var/lib path, so a test would touch the real host fs. Making HOST_ROOT injectable is the prerequisite; I did not refactor that unprompted.")
//! @yah:handoff("FLEET NOT YET PROTECTED: us-west-002 still runs the hand-patched unit + a yubaba binary WITHOUT the reap guard. The repo fixes only reach it on the next cross-build+redeploy. Fine for now (the timeout fix removes the trigger; the guard is defense-in-depth), but a fresh node provisioned before that redeploy would still hit the EROFS mkdir failure.")
//!
//! @yah:ticket(R624-T2, "yubaba serve(): retry the mesh-IP bind with backoff instead of hard-exiting into the systemd restart budget")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-07-21T22:27:37Z)
//! @yah:parent(R624)
//! @yah:tier(Cleric)
//! @yah:gotcha("DIAGNOSIS (measured on a real reboot 2026-07-21 22:10Z, not theorised). yubaba::serve() at oss/yubaba/crates/yubaba/src/lib.rs:1159 does a single TcpListener::bind(addr) and propagates the error, so the process exits 1. On a fleet node the unit binds a tailscale mesh IP (ExecStart --bind 100.64.0.2:7443 via the 20-mesh-bind.conf drop-in), which does not exist until tailscaled has connected. Boot order therefore decides whether a raft voter lives: bind before the IP exists -> 'Address not available (os error 99)' -> exit 1.")
//! @yah:gotcha("WHY IT MATTERS: the only thing catching that today is systemd's Restart=on-failure with StartLimitBurst=5 x RestartSec=2 — about TEN SECONDS of total tolerance. Past that, systemd logs 'Start request repeated too quickly' and gives up PERMANENTLY; the voter stays down until a human runs systemctl reset-failed. That is exactly how us-south-001 sat dead for 30+ hours (R624-B1). B1's DNS fix means tailscaled now reconnects in ~2s so restart #1 wins, but the observed margin is still only ~10s — a slow link, DERP negotiation, or a cold control server re-arms the same permanent failure.")
//! @yah:gotcha("SHARED TREE: peers wip-commit constantly and lib.rs is large and actively edited. Commit with an explicit pathspec, do not sweep. Do not 'fix' unrelated breakage you find in that file.")
//! @yah:next("Make serve() retry the bind with bounded backoff before giving up, so a late mesh IP is survivable rather than fatal. Suggested shape: retry only the retryable errno (AddrNotAvailable — a genuine AddrInUse or permission error should still fail FAST and loudly, since those will never resolve by waiting), log each attempt at WARN with the addr and attempt number so the race is visible in the journal, and cap total wait somewhere in the 60-120s range rather than forever. A hung-forever bind is its own failure mode: it looks 'active' to systemd while serving nothing.")
//! @yah:next("Keep serve_with_listener() (the caller-provided-listener path used by camp) unchanged — it is handed an already-bound listener and has no bind to retry.")
//! @yah:next("Add unit tests. The valuable ones do not need a real mesh: assert the retry classifier treats AddrNotAvailable as retryable and AddrInUse as fatal, and that the backoff gives up at the cap rather than looping forever. A test that binds 127.0.0.1:0 proves nothing about this path.")
//! @yah:next("CODE ONLY — do NOT touch the live fleet. No ssh, no deploys, no service restarts on any node. us-east-001 and us-south-001 are raft voters currently healthy on 0.8.20 and a botched roll drops quorum. Rolling this is a separate operator decision.")
//! @yah:next("Related: R589-T2 carries a sibling item — kamaji Type=notify + sd_notify after bind (or yubaba retrying the UDS connect with backoff) for the yubaba-to-kamaji socket race. Same shape as this fix. Read it before starting; if the two want a shared retry helper, say so in the handoff rather than building it speculatively.")
//! @yah:verify("cargo test -p yubaba --lib passes (198 tests green as of 2026-07-21; your new tests are additive).")
//! @yah:verify("cargo check -p yubaba clean.")
//! @yah:verify("Reasoning check to state explicitly in the handoff: with the retry in place, how long can tailscaled take to establish before a voter is still permanently lost? That number is the whole point of the ticket — today it is ~10s.")
//! @yah:handoff("DONE (R624-T2). serve() now binds via a new bind_with_backoff() helper (oss/yubaba/crates/yubaba/src/lib.rs, immediately above serve()): retries ONLY std::io::ErrorKind::AddrNotAvailable, exponential backoff 250ms doubling to a 5s per-step cap, 90s total budget (BIND_RETRY_BUDGET). Each retry logs WARN with addr/attempt/elapsed/retry_in/error; a late success logs INFO with attempts+waited_ms; give-up logs ERROR naming the budget. AddrInUse, PermissionDenied and every other kind propagate on attempt #1. serve_on_listener() untouched.")
//! @yah:handoff("ANSWER TO THE REASONING CHECK: tailscaled can now take up to ~90s to bring the mesh IP up and the voter still comes up on its FIRST start, consuming zero systemd restarts. Past 90s the process exits 1 and the unit's budget (StartLimitBurst=5 x RestartSec=2) applies as before, so the permanent-loss threshold is ~90s + ~10s of restarts = ~100s of tailscaled downtime, versus ~10s today. ~10x margin, and it is spent BEFORE any restart is burned - which is the part that matters, since the old failure mode burned the restart budget while waiting.")
//! @yah:handoff("TESTS: 4 new in mod bind_retry_tests at the end of lib.rs, driven through a fake attempt closure (no real socket, per the ticket). only_addr_not_available_is_worth_waiting_on pins the classifier (AddrNotAvailable retryable; AddrInUse/PermissionDenied/InvalidInput/Other fatal); fatal_error_fails_on_the_first_attempt asserts AddrInUse yields exactly 1 attempt; gives_up_at_the_budget_rather_than_looping_forever uses a 600ms budget and asserts it stops at the cap without overshooting or spinning; succeeds_once_the_address_appears asserts a late address is survivable.")
//! @yah:handoff("R589-T2 SIBLING VERDICT: do NOT build a shared retry helper yet. The shapes differ - this one retries a SERVER bind on one specific errno and is FATAL on give-up (exit 1 so systemd restarts); the kamaji item retries a CLIENT UDS connect on a different error set (NotFound/ConnectionRefused) and is NON-FATAL on give-up (yubaba already falls back to the in-process ContainerRuntime). The only shared part is the ~10 lines of doubling-with-cap loop. Revisit if a third site appears; R589-T2 is also better solved at its root by kamaji Type=notify + sd_notify after bind, which removes the race instead of tolerating it.")
//! @yah:verify("cargo test -p yubaba --lib: 202 passed, 0 failed (198 baseline + 4 new).")
//! @yah:verify("cargo check -p yubaba: clean. cargo fmt clean for the new hunks (the rest of lib.rs has pre-existing fmt drift, deliberately not touched).")
//! @yah:verify("NOT ROLLED. Code only - no ssh, no deploy, no restart. us-east-001 / us-south-001 untouched, still on 0.8.20. Rolling this is an operator decision.")
//! @yah:gotcha("UNCOMMITTED: the git commit was denied at the permission prompt, so the change is in the WORKING TREE ONLY (oss/yubaba/crates/yubaba/src/lib.rs) and not in any commit. That file also carries @Ashguard:dragon's in-flight R599-T5 hunks (deploy_non_container, Workload-envelope parse, WorkloadDeployBody.id, mod bundle_deploy_tests), so any commit of this path necessarily includes theirs too. Do not checkout/restore/stash the file.")
//!
//! @yah:ticket(R626-F5, "Migrate yubaba POST /workloads/deploy to dispatch through kamaji (the read side already is)")
//! @yah:at(2026-07-23T02:53:26Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R626)
//! @yah:next("Deferred from R406-T8, then from R406-T9, and never picked up — the existing next/gotcha notes at oss/yubaba/crates/yubaba/src/lib.rs:83-108 already spell out the intended migration; start by reading those rather than re-deriving.")
//! @yah:next("Handler ordering the old notes prescribe: validate (already done) -> allocate ident+mesh_ip (already done) -> resolve EnvValue::FromMesh / FromSecret on yubaba's side (admission) -> kamaji.deploy(id, Workload::Container(enriched_spec)) -> on Ack run cloudflared + headscale registration -> on registration failure kamaji.stop(id) to clean up -> respond. Admission decisions stay in yubaba; supervision moves to kamaji.")
//! @yah:next("The original blocker for this ('kamaji's Deploy arm returns Internal, backend driver not implemented') is GONE: R406-T9 landed containerd and R626-F1 landed docker, so Deploy is served on both tiers now. The stated reason for the deferral no longer holds.")
//! @yah:next("Test churn is the real cost and the old note flagged it as a judgement call: integration_smoke_filter / integration_single_node / integration_public_ingress all drive the legacy runtime. Either give them a kamaji fixture or keep them on the runtime path and add a parallel kamaji-fixture suite.")
//! @yah:verify("cd oss/yubaba && cargo test -p yubaba")
//! @yah:verify("On us-west-015: POST a container workload to http://100.64.0.7:7443/workloads/deploy and confirm it actually starts (docker ps on the node shows it) rather than being silently stubbed")
//! @yah:verify("Boot log no longer needs the '/workloads/deploy runs in stub mode' warning to be harmless on a darwin node")
//! @yah:gotcha("This is what actually blocks tag:build-worker on us-west-015 (and any future darwin/pond node). Found 2026-07-22 while clearing that node's other three blockers: kamaji there now has a working docker backend on a yah-owned Colima, and GET /workloads already reports x-workload-source: kamaji — but a qed forge job arrives via POST /workloads/deploy (app/yah/cli/src/yubaba_client.rs:348), which is still the legacy in-process ContainerRuntime path. On a build WITHOUT containerd-integration (every macOS node) that path is STUB MODE, so the job is accepted and then does not run.")
//! @yah:gotcha("The READ side is already migrated and must not be re-done: GET /workloads, GET /workloads/{id}/state and POST /workloads/drain all prefer the kamaji client already (R406-T8). Only deploy is stranded. Verified live on us-west-015 2026-07-22 — a labelled container surfaced correctly through yubaba with the right pid.")
//! @yah:gotcha("yubaba on macOS is built WITHOUT containerd-integration and always will be (containerd is Linux-only), so 'just enable the feature' is not an out for darwin nodes. Dispatching to kamaji is the only path that gives a Mac a working deploy.")
//!
//! @yah:relay(R635, "Rename acme-engine (squatted on crates.io at 0.4.0) to a yah- name; unblocks yubaba publish")
//! @yah:at(2026-07-23T03:25:03Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(Q538)
//! @yah:next("Verified against the crates.io sparse index 2026-07-22: `acme-engine` exists but holds only 0.4.0, published by an unrelated project. Our oss/passway crate declares 0.8.20, so the version can never resolve from the registry — root Cargo.toml already calls this bridge 'load-bearing until (if ever) we publish under our own name'.")
//! @yah:next("This is the SOLE remaining blocker on publishing the `yubaba` crate (R542). Everything else yubaba depends on is already on crates.io at 0.8.20: yah-workload-spec, yah-local-driver, kamaji, kamaji-proto, mshr, and yubaba-client (publishable as of R542).")
//! @yah:next("Work: rename the package in oss/passway/crates/acme-engine to a free yah- name (check the target on the sparse index first — https://index.crates.io/ya/h-/<name>), update the root [patch.crates-io] key, oss/yubaba/Cargo.toml's sibling patch key, and yubaba's dependency line. Consumers can keep the short `acme_engine` extern name via `acme-engine = { package = \"yah-acme-engine\", version = \"0.8.20\" }` — that alias trick is what R542 used for cloud -> yah-cloud with zero source churn.")
//! @yah:next("Then fill description/keywords/categories on the renamed crate, cargo publish --dry-run --allow-dirty -p <name>, and hand back to R542 to flip yubaba's publish flag.")
//! @yah:verify("cargo publish --dry-run --allow-dirty -p <renamed acme crate> exits 0")
//! @yah:verify("cargo check -p yubaba (from oss/yubaba) is clean after the rename")

pub mod acme_issuer;
pub mod cheers_client;
pub mod deploy;
pub mod identity;
pub mod leader;
pub mod litestream;
pub mod mesh;
pub mod node;
pub mod pond;
pub mod raft;
pub mod rollout;
pub mod runtime;
pub mod secret_reload;
pub mod secrets;
pub mod service_records;

#[cfg(feature = "testing")]
pub mod testing;

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use openraft::async_runtime::watch::WatchReceiver;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cheers_client::CheersClient;
use kamaji::sibling::KamajiClient;
use kamaji::Kamaji as ContainerRuntime;
use workload_spec::LifecycleArchetype;

/// How yubaba exposes workloads with `expose.operator` set.
///
/// Controlled at startup via `YAH_OPERATOR_BRIDGE_MODE` (or overridden in tests
/// via `ServerState::with_operator_bridge_mode`). Stored once on `ServerState`
/// so handlers don't read a global env var on every request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OperatorBridgeMode {
    /// Create a Headscale preauth key with the requested ACL tag. Default.
    #[default]
    Tailscale,
    /// Skip Tailscale; expose the workload as a direct mesh peer. Faster for
    /// local-tier tests; loses real ACL evaluation.
    MeshPeer,
}

impl OperatorBridgeMode {
    /// Parse from the `YAH_OPERATOR_BRIDGE_MODE` env var.  Unrecognised values
    /// fall back to `Tailscale` (the default).
    fn from_env() -> Self {
        match std::env::var("YAH_OPERATOR_BRIDGE_MODE")
            .unwrap_or_default()
            .as_str()
        {
            "mesh-peer" => Self::MeshPeer,
            _ => Self::Tailscale,
        }
    }
}

pub const DEFAULT_BIND: &str = "0.0.0.0:7443";
// Writable runtime state lives under /var/lib/yah-cloud (the systemd
// StateDirectory), NOT /etc/yah-cloud: yubaba.service runs ProtectSystem=strict,
// so /etc is read-only and `mkdir /etc/yah-cloud/...` fails at runtime
// (R330-F28 #14 / R330-T9 #10). /etc/yah-cloud stays config-only (compose,
// litestream config placed by cloud-init).
pub const DEFAULT_STATE_PATH: &str = "/var/lib/yah-cloud/identity.json";
/// Default directory for headscale binary + state. Must be writable at runtime
/// (the self-bootstrap path creates it + writes config/db), so it lives under
/// the StateDirectory, not read-only /etc (R330-F28 #14).
pub const DEFAULT_HEADSCALE_DIR: &str = "/var/lib/yah-cloud/headscale";
/// Pinned Headscale release used by the self-bootstrap path when the request
/// omits an explicit version. Kept in lockstep with `cloud::mesh::HEADSCALE_VERSION`.
pub const DEFAULT_HEADSCALE_VERSION: &str = "0.23.0";
/// Permissive default ACL — all nodes may reach all nodes. Headscale's
/// file-policy loader parses HuJSON (JSON-with-comments), NOT YAML, so this
/// must stay JSON (a leading `---` fails with "invalid literal: ---").
pub const DEFAULT_ACL_POLICY_HUJSON: &str = "{\n  \"acls\": [\n    { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"] }\n  ]\n}\n";
/// Default directory for compose.yml + Caddyfile (R040-F7).
pub const DEFAULT_COMPOSE_DIR: &str = "/etc/yah-cloud";
/// Systemd unit name for the Podman Compose service stack.
pub const COMPOSE_UNIT: &str = "yah-cloud-services";

/// This machine's node enrollment as known to this process (R593-F4):
/// which mshr NodeId was enrolled and the cheers ownership-row id backing
/// it. Both halves travel together — the row id alone can't detect a
/// hostkey rotation, and the NodeId alone can't be revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEnrollment {
    /// Hex-encoded mshr NodeId (same encoding as `/identity`'s `node_id`).
    pub node_id: String,
    /// Cheers ownership-row id — the handle for `DELETE /ownership/{id}`.
    pub row_id: String,
}

/// Shared in-memory state. Wraps a `Mutex<StateOnDisk>` so concurrent handlers
/// see consistent snapshots.
pub struct ServerState {
    pub state_path: PathBuf,
    pub state: Mutex<identity::StateOnDisk>,
    /// Directory that `POST /headscale/deploy` writes into.
    /// Defaults to [`DEFAULT_HEADSCALE_DIR`]; override in tests via a tempdir.
    pub headscale_dir: PathBuf,
    /// Directory for `compose.yml` + `Caddyfile` (R040-F7).
    /// Defaults to [`DEFAULT_COMPOSE_DIR`]; override in tests via a tempdir.
    pub compose_dir: PathBuf,
    /// R556-F7-T3: local scryer endpoint advertised via `/services`.
    ///
    /// Set to the kamaji-managed scryer's tailnet-bound HTTP base URL (e.g.
    /// `http://100.64.0.7:6543`) once the scryer service is running on this
    /// node. When `None`, `/services` simply omits the scryer entry — yubaba
    /// is service-discovery, not a probe, so absence here means absence in the
    /// advertisement, nothing else.
    pub scryer_endpoint: Option<String>,
    /// Phase 2 (R040-F20): raft coordination node.  `None` until the server
    /// is started with `--raft-node-id` / `--raft-dir`.
    pub raft: Option<raft::YubabaRaft>,
    /// Phase 2 (R040-F21): this node's raft node ID.  Used by
    /// `GET /mesh/leader-health` to check "am I the current leader?"
    /// without re-passing the ID through every handler.
    pub node_id: Option<raft::YubabaNodeId>,

    /// R600-F6 (W273): read handle to the raft-replicated cluster-secret map
    /// (R600-F1/F2), used at admission to resolve `SecretRef::Cluster` File
    /// mounts. Clones the same `Arc<RwLock<…>>` the raft node applies into, so
    /// it observes committed cluster secrets without a round-trip. `None`
    /// outside the raft cluster (single-node) — a spec that references a
    /// cluster secret then fails the deploy closed. Wired in main.rs from
    /// [`raft::open_with_state_machine`].
    pub secret_state: Option<raft::YubabaStateMachine>,

    /// R600-F6 (W273): node-local cluster KEK path (default
    /// [`secrets::CLUSTER_KEK_PATH`]; override in tests). Loaded per-deploy
    /// only when a spec carries a `SecretRef::Cluster` mount.
    pub cluster_kek_path: PathBuf,

    /// R600-F6 (W273): root for materialized secret tmpfs files (default
    /// [`deploy::secret_mount::DEFAULT_SECRET_MOUNT_ROOT`]; override in tests).
    /// Each workload gets a `<root>/<ident>/` subdir, reaped on destroy.
    pub secret_mount_root: PathBuf,

    /// R600-F4 (W273): registry of deployed workloads that mount a cluster
    /// secret as a `File`, keyed on mesh ident. Populated by the deploy handler
    /// on a successful cluster-secret deploy and cleared on destroy; consumed by
    /// the [`secret_reload`] rotation task, which re-renders each entry's tmpfs
    /// mount and graceful-upgrades the workload when its cluster secret rotates.
    pub secret_workloads: secret_reload::SecretWorkloadRegistry,
    /// Phase 2 (R040-F21): S3 URL for litestream Headscale replication.
    /// Format: `s3://bucket/path?endpoint=...`
    /// When set, the leader watcher manages `litestream replicate` as a
    /// sidecar and runs `litestream restore` before starting Headscale on
    /// leader election.
    pub litestream_s3_url: Option<String>,
    /// Unique ID for this daemon session. Generated once at startup;
    /// stamped on every tracing span by the correlation-ID middleware so log
    /// lines from the same yubaba process can be correlated across restarts.
    pub session_id: String,
    /// `ContainerRuntime` wired in by the caller (R091-F5).
    /// `None` until the server is configured with `with_runtime`.
    /// When present, `/workloads/deploy`, `/workloads/{ident}/state`, and
    /// `/workloads` delegate to this impl instead of returning stubs.
    ///
    /// **R406-T8 transition:** the in-process `ContainerRuntime` is the
    /// legacy path; new deploys flow through [`Self::constable_client`]
    /// once T9 ships Kamaji's containerd backend. Read handlers
    /// (`list`/`get_state`/`drain`) already prefer Kamaji when it is
    /// configured and fall back to this field when it isn't.
    pub runtime: Option<Arc<dyn ContainerRuntime + Send + Sync>>,

    /// UDS client for talking to Kamaji — `app/yah/kamaji`'s sibling
    /// process supervisor (R406-T8). Wired by the caller via
    /// [`Self::with_constable_client`]; `None` outside cloud-tier deploys
    /// that run the kamaji.service systemd unit. Workload-lifecycle
    /// handlers consult this client before the legacy `runtime` field.
    pub constable_client: Option<Arc<KamajiClient>>,

    /// Privileged cheers client for ownership-table writes (R427-F1).
    /// `None` outside cloud-tier deploys that have completed the
    /// `yubaba install` service-principal bootstrap. When set, the workload
    /// deploy handler calls `register_ownership` after a successful provision
    /// and the destroy path calls `revoke_ownership` with the row id it
    /// stored alongside the workload identity. See W159 §"Ownership writes
    /// — keep the privileged set small".
    pub cheers_client: Option<Arc<CheersClient>>,

    /// `(workload_ident → cheers ownership_row_id)` for revoke on destroy.
    /// Populated by the deploy handler when a `cheers_client` is configured
    /// and `register_ownership` succeeds; consumed (and removed) by
    /// `/workloads/{ident}/destroy`. Entries for workloads that predate the
    /// cheers client never exist, so a destroy with no entry skips the
    /// revoke call entirely — same idempotent shape as cheers's own
    /// `DELETE /ownership/{id}` for already-revoked rows.
    pub ownership_rows: Mutex<HashMap<String, String>>,

    /// R572-F4: effective [`LifecycleArchetype`] of each live workload, keyed
    /// on mesh ident (= `spec.expose.mesh.identity.0`). Populated on a
    /// successful deploy and cleared on destroy. Drives two behaviours:
    ///
    /// - `drain_workloads` skips `Appliance` entries (pinned, non-drainable).
    /// - `deploy_workload_spec` rejects a second deploy of the same ident when
    ///   the existing entry is `Appliance` (single live instance invariant).
    pub archetype_registry: Mutex<HashMap<String, LifecycleArchetype>>,

    /// Requested `resources` of each live workload, keyed on mesh ident.
    ///
    /// Exactly the lifecycle of [`Self::archetype_registry`] — written by the
    /// deploy handler on success, removed by destroy — because it answers the
    /// same kind of question: something the accepted spec said that the
    /// runtime doesn't remember.
    ///
    /// This is the *committed* half of `available = allocatable − committed`.
    /// The scheduler's capacity floor (`cloud::config::RequiredSpec::matches`)
    /// has always compared a request against a node's static `allocatable`
    /// without subtracting what is already running, because no node reported
    /// its commitments. `GET /node/usage` now does, from this map.
    ///
    /// Deliberately NOT folded into the two `WorkloadEntry` shapes: kamaji's
    /// is `{id, state, pid}` and the HTTP one is `cloud_client::WorkloadEntry`,
    /// and the `x-workload-source` header is a documented back-compat contract
    /// between them. `GET /workloads` enriches whichever shape it produced by
    /// merging these fields into the serialized JSON, which keeps both wire
    /// shapes additive rather than unifying them.
    pub workload_resources: node::ResourceRegistry,

    /// Node spec + usage collector backing `GET /node` and `GET /node/usage`.
    ///
    /// Holds the cached hardware specs and the previous CPU tick sample, so a
    /// client's poll interval doubles as its CPU measurement window — see
    /// [`node::NodeProbe`].
    pub node_probe: node::NodeProbe,

    /// THIS machine's own node enrollment — the mshr NodeId it enrolled
    /// and the cheers ownership-row id backing it (R593-F4, W268 §"The
    /// binding: enrollment is an ownership row"). `None` until
    /// [`Self::admit_node`] runs successfully. Distinct from
    /// `ownership_rows` (workload idents) — a machine has at most one
    /// node-enrollment row for its current identity, so a single slot
    /// (not a map) is enough. Tracking the NodeId *alongside* the row id
    /// makes the admission guard identity-aware: a hostkey rotation (new
    /// NodeId) re-enrolls and revokes the stale row instead of being
    /// skipped. Consumed by [`Self::evict_node`].
    pub node_enrollment: Mutex<Option<NodeEnrollment>>,

    /// R593-F8 (W268 §"Fleet machine" binding ceremony — INTERIM):
    /// operator-issued provisioning bootstrap tokens gating
    /// `POST /register-hostkey`. That handler enrolls the presenting hostkey
    /// via [`Self::admit_node`] — an `ownership:write` into cheers's ledger
    /// under yubaba's trusted service principal — so it must never run for an
    /// unauthenticated caller (otherwise any network-reachable peer
    /// self-enrolls as a fleet node, the R593-F4 adversarial finding). The
    /// handler requires a valid, single-use token before any identity work.
    ///
    /// Minting is in-process: the provisioning path calls
    /// [`bootstrap::BootstrapTokenRegistry::mint`] and templates the token
    /// into the node's cloud-init user-data. Process-local + fail-closed by
    /// design (a daemon restart drops outstanding tokens → the operator
    /// re-provisions). The sanctioned endgame moves admission onto the mshr
    /// QUIC transport where mutual machine auth is intrinsic (R593-T7 /
    /// R277 / R570), retiring this interim. See [`identity::bootstrap`].
    ///
    /// **Interim caveat (operational reality at time of writing):** no
    /// production path POSTs `/register-hostkey` yet — provisioned nodes
    /// self-generate their hostkey at boot ([`Self::load`]) and the operator
    /// attaches via `yah mesh bootstrap`, never invoking this endpoint. The
    /// registry therefore stays empty and the endpoint fails closed until a
    /// provisioning ceremony wires minting; whether the mint host is the
    /// leader (leader-directed POST) or the node-local daemon (self-directed
    /// POST) is decided with the R592-T4-final mesh topology — the core has
    /// no opinion on who hosts it.
    pub bootstrap_tokens: identity::bootstrap::BootstrapTokenRegistry,
    /// URL of the cloudflared API (production daemon) or mock (local-tier tests).
    ///
    /// When `Some`, yubaba POSTs to `<cloudflared_url>/v1/tunnels` for workloads
    /// with `expose.public` set. When `None`, yubaba logs a warning and falls
    /// back to docker-style port mapping — the workload is accessible on
    /// `localhost:<port>` without a public tunnel.
    pub cloudflared_url: Option<String>,

    /// URL of the Headscale API (production daemon) or mock (local-tier tests).
    ///
    /// When `Some`, yubaba POSTs to `<headscale_url>/api/v1/preauthkey` for
    /// workloads with `expose.operator` set (unless `operator_bridge_mode` is
    /// `MeshPeer`). When `None`, operator exposure is skipped with a warning.
    pub headscale_url: Option<String>,

    /// How yubaba exposes workloads with `expose.operator` set.
    ///
    /// Set at startup from `YAH_OPERATOR_BRIDGE_MODE`; override in tests via
    /// `with_operator_bridge_mode`. Stored here so handlers don't re-read a
    /// global env var on every request.
    pub operator_bridge_mode: OperatorBridgeMode,

    /// R278-F1/F3: in-process rollout registry (degenerate-raft v1).
    ///
    /// Migrates to raft-replicated state once R277 cluster-mesh-1 is live.
    pub rollout_store: Arc<std::sync::Mutex<rollout::RolloutStore>>,

    /// R278-F2: Prometheus-compatible base URL for gate evaluation.
    ///
    /// When `None`, gate evaluation runs in stub mode (all gates auto-pass).
    /// Set via `YAH_PROMETHEUS_URL` env var or `with_prometheus_url()`.
    pub prometheus_url: Option<String>,

    /// R374-F3: docker-CLI runtime yubaba uses to drive the MinIO half of
    /// pond workloads. Wired by the embedder via
    /// [`Self::with_pond_local_runtime`] after detecting an orbstack/
    /// docker-desktop/colima/podman/docker socket. `None` outside camp;
    /// `POST /pond/deploy` returns 503 in that case.
    pub pond_local_runtime: Option<Arc<local_driver::LocalRuntime>>,

    /// R374-F2: in-memory pond workload registry. Always present; empty when
    /// no pond workloads have been registered. Desktop reads this via
    /// `GET /pond/state?ident=...` to drive its adopt path.
    pub pond_registry: Arc<pond::PondRegistry>,

    /// Monotonically increasing counter for stub mesh-IP allocation.
    /// Allocates from `100.64.0.1` upward (CGNAT range per RFC 6598).
    /// Replaced by raft-consensus assignment in R091-F6.
    next_mesh_ip: AtomicU32,
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("state_path", &self.state_path)
            .field("headscale_dir", &self.headscale_dir)
            .field("compose_dir", &self.compose_dir)
            .field("raft_configured", &self.raft.is_some())
            .field("node_id", &self.node_id)
            .field("litestream_configured", &self.litestream_s3_url.is_some())
            .field("session_id", &self.session_id)
            .field("runtime_configured", &self.runtime.is_some())
            .field(
                "constable_socket",
                &self
                    .constable_client
                    .as_ref()
                    .map(|c| c.socket().to_path_buf()),
            )
            .field("cheers_client_configured", &self.cheers_client.is_some())
            .field(
                "node_enrolled",
                &self.node_enrollment.lock().unwrap().is_some(),
            )
            .field("cloudflared_url", &self.cloudflared_url)
            .field("headscale_url", &self.headscale_url)
            .field("operator_bridge_mode", &self.operator_bridge_mode)
            .field("prometheus_url", &self.prometheus_url)
            .field(
                "pond_local_runtime_configured",
                &self.pond_local_runtime.is_some(),
            )
            .finish()
    }
}

/// Directory the hostkey lives beside, derived from the `--state` path.
///
/// R569-B2: `Path::parent` returns `Some("")` — not `None` — for a bare
/// filename, so the old `.unwrap_or(".")` fallback was unreachable and a
/// relative `--state identity.json` handed `generate_or_load_hostkey` an empty
/// path, which fails `create_dir_all` with ENOENT and reads as "hostkey
/// generation failed" for no visible reason. [`identity::save_state`] already
/// carries the same empty-parent guard for the state file itself.
fn hostkey_dir_for(state_path: &std::path::Path) -> PathBuf {
    match state_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

impl ServerState {
    pub fn load(state_path: PathBuf) -> Result<Self> {
        let mut state = identity::load_state(&state_path)?;
        if state.identity.is_none() {
            let hostkey_dir = hostkey_dir_for(&state_path);
            match identity::generate_or_load_hostkey(&hostkey_dir) {
                Ok(id) => {
                    state.identity = Some(id);
                    identity::save_state(&state_path, &state)
                        .context("persisting auto-generated hostkey to state file")?;
                }
                Err(e) => {
                    // `{e:#}`, not `%e` (R569-B2): anyhow's plain Display prints
                    // only the outermost context, so the observed rootless-macOS
                    // report was `hostkey generation failed … writing private key
                    // to …` with the errno — the one fact that says whether it's
                    // a permissions problem or a missing mount — discarded. The
                    // alternate form prints the whole cause chain.
                    tracing::error!(
                        error = format!("{e:#}"),
                        hostkey_dir = %hostkey_dir.display(),
                        "hostkey generation failed; this node has NO identity — \
                         /identity returns 404, and it cannot join a mesh or be \
                         admitted until one exists. Fix write access to the \
                         hostkey dir and restart, or register a key with \
                         `yah-yubaba register-hostkey <pubkey> --state <state>`."
                    );
                }
            }
        }
        Ok(Self {
            state_path,
            state: Mutex::new(state),
            headscale_dir: PathBuf::from(DEFAULT_HEADSCALE_DIR),
            compose_dir: PathBuf::from(DEFAULT_COMPOSE_DIR),
            scryer_endpoint: None,
            raft: None,
            node_id: None,
            secret_state: None,
            cluster_kek_path: PathBuf::from(secrets::CLUSTER_KEK_PATH),
            secret_mount_root: PathBuf::from(deploy::secret_mount::DEFAULT_SECRET_MOUNT_ROOT),
            secret_workloads: Default::default(),
            litestream_s3_url: None,
            session_id: new_session_id(),
            runtime: None,
            constable_client: None,
            cheers_client: None,
            ownership_rows: Mutex::new(HashMap::new()),
            archetype_registry: Mutex::new(HashMap::new()),
            workload_resources: Default::default(),
            node_probe: node::NodeProbe::new(),
            node_enrollment: Mutex::new(None),
            bootstrap_tokens: identity::bootstrap::BootstrapTokenRegistry::new(),
            cloudflared_url: None,
            headscale_url: None,
            operator_bridge_mode: OperatorBridgeMode::from_env(),
            rollout_store: Arc::new(std::sync::Mutex::new(rollout::RolloutStore::new())),
            prometheus_url: std::env::var("YAH_PROMETHEUS_URL").ok(),
            pond_local_runtime: None,
            pond_registry: Arc::new(pond::PondRegistry::new()),
            // Start at 100.64.0.1 (first usable in the CGNAT /10 pool).
            next_mesh_ip: AtomicU32::new(u32::from_be_bytes([100, 64, 0, 1])),
        })
    }

    /// R374-F4: register the docker-CLI runtime yubaba uses to drive the
    /// MinIO half of pond workloads. Camp detects this from the workspace's
    /// `kind = "local-container"` provider via cloud's
    /// `local_container_spec_from_provider` adapter and hands the resulting
    /// [`local_driver::LocalRuntime`] to yubaba once at startup.
    pub fn with_pond_local_runtime(mut self, runtime: Arc<local_driver::LocalRuntime>) -> Self {
        self.pond_local_runtime = Some(runtime);
        self
    }

    /// Attach a `ContainerRuntime` impl. Enables the `/workloads/*` endpoints.
    pub fn with_runtime(mut self, runtime: Arc<dyn ContainerRuntime + Send + Sync>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Attach a Kamaji UDS client (R406-T8). When set, workload-lifecycle
    /// handlers prefer this client over the legacy in-process
    /// [`Self::runtime`] field. Build the client with
    /// [`constable_client::KamajiClient::connect`] or
    /// [`constable_client::connect_with_timeout`] before passing it in.
    pub fn with_constable_client(mut self, client: Arc<KamajiClient>) -> Self {
        self.constable_client = Some(client);
        self
    }

    /// Attach a privileged cheers client (R427-F1). When set, the workload
    /// deploy handler registers ownership for newly-provisioned resources
    /// (`(camp_id, service, workload_ident)`) attributed to the deploying
    /// user via `on_behalf_of`; destroy revokes the row by id.
    ///
    /// Built from the service-principal secret written by
    /// `yubaba install` (W159 §Service principals). Without this client,
    /// yubaba still provisions workloads, but ownership writes are skipped
    /// with a warning — useful for development tiers that have no cheers
    /// instance yet.
    pub fn with_cheers_client(mut self, client: Arc<CheersClient>) -> Self {
        self.cheers_client = Some(client);
        self
    }

    /// Node-admission enrollment write (R593-F4, W268 §"The binding:
    /// enrollment is an ownership row" — "fleet machines are devices owned
    /// by the operator's service principal"). Records
    /// `svc:<yubaba's own principal> owns node:<this machine's mshr
    /// NodeId>` in cheers via [`CheersClient::enroll_node`], and stashes
    /// the `(node_id, row_id)` pair in [`Self::node_enrollment`] so a
    /// future eviction can revoke it ([`Self::evict_node`]).
    ///
    /// **Call site (why here):** wired into the `POST /register-hostkey`
    /// handler, right after a node's identity is durably persisted via
    /// [`Self::replace_identity`] — the moment W268 calls "yubaba admission
    /// enrolls it". The other candidate seam, `ServerState::load`'s
    /// R092-F8 self-generate-at-boot branch, was rejected: `load` is a
    /// sync constructor that runs *before* a `cheers_client` exists (it
    /// predates the `with_cheers_client` builder step in the call chain),
    /// so there is no client to enroll with at that point without
    /// restructuring the builder into two phases. A future raft
    /// join-by-NodeId flow (referenced in R482-T3's next-notes, not yet
    /// implemented) is the other natural call site once it lands.
    ///
    /// **Idempotency (identity-aware guard):** re-admission with the SAME
    /// NodeId already enrolled this process lifetime is a no-op with no
    /// network round-trip — `/register-hostkey` is re-POSTed by design
    /// (cloud-init re-runs). The guard compares the *current* identity's
    /// NodeId against the enrolled one, not mere presence of an
    /// enrollment: a hostkey **rotation** (different NodeId) enrolls the
    /// new NodeId and then revokes the stale row, so the ledger converges
    /// on exactly the current identity instead of pointing at a key that
    /// no longer exists. Across daemon restarts the in-memory pair is
    /// lost and the enrollment call goes out again — cheers's
    /// `POST /ownership` is idempotent for identical live rows (returns
    /// the existing row, 200 instead of 201), so restart re-admission
    /// converges on the same row instead of stacking duplicates.
    ///
    /// No-op (returns `None`) when there is no persisted identity yet or
    /// no `cheers_client` configured (dev tiers with no cheers instance)
    /// — same "provision but skip the write" shape
    /// [`deploy_workload_spec`] uses for workload ownership. A
    /// cheers-side failure is a WARN, not fatal: a machine should still
    /// come up even if the enrollment write blips; the row can be
    /// backfilled by a reconciler.
    pub async fn admit_node(
        &self,
    ) -> Option<Result<cheers_client::OwnershipRow, cheers_client::CheersError>> {
        let id = self.snapshot().identity?;
        let cheers = self.cheers_client.clone()?;
        let node_id = match identity::node_id_hex(&id) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "admit_node: failed to derive mshr NodeId from this machine's hostkey"
                );
                return None;
            }
        };
        // Identity-aware idempotency guard. Snapshot under the lock, then
        // drop it before awaiting (std Mutex guards can't be held across
        // await points; see the race note on evict_node).
        let prior = self.node_enrollment.lock().unwrap().clone();
        if let Some(prev) = &prior {
            if prev.node_id == node_id {
                tracing::debug!(
                    node_id = %node_id,
                    "admit_node: this NodeId already enrolled this process lifetime; skipping"
                );
                return None;
            }
            tracing::info!(
                old_node_id = %prev.node_id,
                new_node_id = %node_id,
                "admit_node: hostkey rotation detected — re-enrolling under the new NodeId"
            );
        }
        let result = cheers.enroll_node(&node_id).await;
        match &result {
            Ok(row) => {
                *self.node_enrollment.lock().unwrap() = Some(NodeEnrollment {
                    node_id: node_id.clone(),
                    row_id: row.id.clone(),
                });
                tracing::info!(
                    node_id = %node_id,
                    row_id = %row.id,
                    "node enrolled (cheers ownership row registered)"
                );
                // Rotation: the old NodeId's row is now stale — revoke it
                // so the ledger holds exactly the current identity (W268:
                // eviction removes rows, never keys; the old KEY is simply
                // gone from disk, the ROW must follow it out).
                if let Some(prev) = prior {
                    match cheers.evict_node(&prev.row_id).await {
                        Ok(()) => tracing::info!(
                            old_node_id = %prev.node_id,
                            old_row_id = %prev.row_id,
                            "stale enrollment for rotated-out NodeId revoked"
                        ),
                        Err(e) => tracing::warn!(
                            old_node_id = %prev.node_id,
                            old_row_id = %prev.row_id,
                            error = %e,
                            "failed to revoke stale enrollment after rotation; \
                             ghost row drifts until a reconciler sweeps it"
                        ),
                    }
                }
            }
            Err(e) => {
                // Enrollment of the new NodeId failed — keep the prior
                // enrollment state (if any) untouched: its row is still
                // the live one in cheers.
                tracing::warn!(
                    node_id = %node_id,
                    error = %e,
                    "node enrollment failed; identity stays valid, row may be \
                     backfilled by a reconciler"
                );
            }
        }
        Some(result)
    }

    /// Node-eviction revocation — the counterpart to [`Self::admit_node`].
    /// Per W268 §"The two axes": eviction removes **enrollment rows,
    /// never the key** — this revokes the cheers ownership row(s) via
    /// [`CheersClient::evict_node`]; the on-disk hostkey / NodeId is
    /// completely untouched by this call.
    ///
    /// Two paths:
    /// - **Fast path**: this process enrolled ([`Self::node_enrollment`]
    ///   is `Some`) — revoke by the remembered row id. On failure the
    ///   pair is restored so a retry can find it.
    /// - **Lookup fallback** (post-restart): the in-memory pair is gone,
    ///   but the ledger row survives the restart. List this principal's
    ///   live rows via [`CheersClient::list_ownership`] and revoke EVERY
    ///   live `kind=node` row whose `resource_id` matches the current
    ///   identity's NodeId — all of them, not just one, so any historical
    ///   duplicates are cleared in the same sweep. Without this fallback
    ///   a decommission after restart would silently revoke nothing.
    ///
    /// **Not wired to any removal/decommission flow yet — yubaba has
    /// none.** There is no fleet-machine removal, decommission, or raft
    /// membership-eviction HTTP route in this crate as of R593-F4 (the
    /// raft layer is currently cluster-of-one; multi-machine join/leave is
    /// tracked as future work per R482-T3's next-notes and R593-T7's
    /// parked raft-transport ticket). This method is exposed as a
    /// standalone callable — mirroring [`Self::admit_node`]'s shape — so
    /// whatever removal surface lands later (most likely a raft
    /// remove-learner/remove-voter admin path, or a `POST /decommission`
    /// mirroring `/workloads/{ident}/destroy`) only has to call
    /// `evict_node`, not re-derive the row id or relearn the cheers wire
    /// contract.
    ///
    /// **Known-latent race for whoever wires the decommission route:**
    /// `node_enrollment` is a std `Mutex`, so both this method and
    /// `admit_node` snapshot/take under the lock and drop it BEFORE the
    /// cheers await. Concurrent admit+evict on the same `ServerState` can
    /// therefore interleave between the lock release and the HTTP call
    /// (e.g. evict takes the pair, admit re-enrolls, evict's revoke then
    /// lands on the fresh row). Harmless while evict_node has no caller;
    /// the decommission wiring should serialize admission/eviction (an
    /// async-aware mutex around the whole operation, or route-level
    /// ordering) rather than trying to fix it inside these helpers.
    pub async fn evict_node(&self) -> Option<Result<(), cheers_client::CheersError>> {
        let cheers = self.cheers_client.clone()?;

        // Fast path: this process remembers what it enrolled.
        let taken = self.node_enrollment.lock().unwrap().take();
        if let Some(enrollment) = taken {
            let result = cheers.evict_node(&enrollment.row_id).await;
            match &result {
                Ok(()) => {
                    tracing::info!(
                        node_id = %enrollment.node_id,
                        row_id = %enrollment.row_id,
                        "node enrollment revoked"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        node_id = %enrollment.node_id,
                        row_id = %enrollment.row_id,
                        error = %e,
                        "node eviction revoke failed; row may need manual cleanup"
                    );
                    // Put the pair back so a retry can find it — this call
                    // failed to revoke, so the row is still live in cheers.
                    *self.node_enrollment.lock().unwrap() = Some(enrollment);
                }
            }
            return Some(result);
        }

        // Lookup fallback: no in-memory enrollment (typically a restart
        // happened since admission). Rediscover the row(s) from the ledger.
        let id = self.snapshot().identity?;
        let node_id = match identity::node_id_hex(&id) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "evict_node: failed to derive mshr NodeId from this machine's hostkey"
                );
                return None;
            }
        };
        let principal = format!("svc:{}", cheers.principal_id());
        let rows = match cheers.list_ownership(&principal).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "evict_node: ownership lookup failed; nothing revoked"
                );
                return Some(Err(e));
            }
        };
        let targets: Vec<_> = rows
            .into_iter()
            .filter(|r| {
                r.resource_kind == cheers_client::NODE_RESOURCE_KIND
                    && r.resource_id == node_id
                    && r.revoked_at.is_none()
            })
            .collect();
        if targets.is_empty() {
            tracing::debug!(
                node_id = %node_id,
                "evict_node: no live enrollment rows found for this NodeId; nothing to revoke"
            );
            return None;
        }
        let mut result: Result<(), cheers_client::CheersError> = Ok(());
        for row in targets {
            match cheers.evict_node(&row.id).await {
                Ok(()) => tracing::info!(
                    node_id = %node_id,
                    row_id = %row.id,
                    "node enrollment revoked (rediscovered via ledger lookup)"
                ),
                Err(e) => {
                    tracing::warn!(
                        node_id = %node_id,
                        row_id = %row.id,
                        error = %e,
                        "evict_node: revoke failed for rediscovered row"
                    );
                    result = Err(e);
                }
            }
        }
        Some(result)
    }

    /// Configure the cloudflared API URL for public-ingress tunnel registration.
    ///
    /// In production, point at the local cloudflared daemon
    /// (e.g. `"http://127.0.0.1:2999"`). In local-tier tests, point at a
    /// `CloudflaredMock` instance. When not set, yubaba falls back to
    /// docker-style port mapping for `expose.public` workloads.
    pub fn with_cloudflared_url(mut self, url: impl Into<String>) -> Self {
        self.cloudflared_url = Some(url.into());
        self
    }

    /// Allocate the next mesh IP from the 100.64.0.0/10 stub pool.
    ///
    /// Thread-safe; wraps around at 100.127.255.255 (pool exhaustion silently
    /// rolls over — acceptable for tests). Replaced by raft in R091-F6.
    pub fn alloc_mesh_ip(&self) -> std::net::Ipv4Addr {
        let n = self.next_mesh_ip.fetch_add(1, Ordering::Relaxed);
        std::net::Ipv4Addr::from(n)
    }

    /// Attach an already-opened raft node to the server state.
    pub fn with_raft(mut self, raft: raft::YubabaRaft) -> Self {
        self.raft = Some(raft);
        self
    }

    /// Set this node's raft node ID — needed by [`GET /mesh/leader-health`].
    pub fn with_node_id(mut self, id: raft::YubabaNodeId) -> Self {
        self.node_id = Some(id);
        self
    }

    /// R600-F6 (W273): attach the read handle to the raft-replicated
    /// cluster-secret map so admission can resolve `SecretRef::Cluster` File
    /// mounts. Wired in `main.rs` from [`raft::open_with_state_machine`]; a
    /// `None` `secret_state` makes any cluster-secret deploy fail closed.
    pub fn with_secret_state(mut self, sm: raft::YubabaStateMachine) -> Self {
        self.secret_state = Some(sm);
        self
    }

    /// The active workload backend, preferring the sibling `KamajiClient`
    /// (cloud-tier deploys via `kamaji.service`) over the legacy in-process
    /// `runtime`. `None` in stub mode (no backend configured). The deploy
    /// handler and the R600-F4 [`secret_reload`] rotation task both route
    /// through this so they drive the same supervisor.
    pub fn active_backend(&self) -> Option<Arc<dyn ContainerRuntime + Send + Sync>> {
        self.constable_client
            .clone()
            .map(|c| {
                let backend: Arc<dyn ContainerRuntime + Send + Sync> = c;
                backend
            })
            .or_else(|| self.runtime.clone())
    }

    /// Override the cluster KEK path and materialized-secret tmpfs root — used
    /// by tests to point both at a tempdir instead of the on-host defaults.
    pub fn with_secret_paths(
        mut self,
        kek_path: impl Into<PathBuf>,
        mount_root: impl Into<PathBuf>,
    ) -> Self {
        self.cluster_kek_path = kek_path.into();
        self.secret_mount_root = mount_root.into();
        self
    }

    /// Set the S3 URL for litestream Headscale replication (Phase 2 only).
    pub fn with_litestream_s3_url(mut self, url: impl Into<String>) -> Self {
        self.litestream_s3_url = Some(url.into());
        self
    }

    /// Configure the Headscale API URL for operator-bridge preauth-key registration.
    ///
    /// In production, point at the local Headscale daemon
    /// (e.g. `"http://127.0.0.1:8080"`). In local-tier tests, point at a
    /// `HeadscaleMock` instance. When not set, yubaba checks
    /// `YAH_OPERATOR_BRIDGE_MODE`: if `"mesh-peer"`, operator workloads are
    /// exposed as direct mesh peers without Tailscale; otherwise skipped with
    /// a warning.
    pub fn with_headscale_url(mut self, url: impl Into<String>) -> Self {
        self.headscale_url = Some(url.into());
        self
    }

    /// Set the Prometheus base URL for rollout gate evaluation (R278-F2).
    ///
    /// In production, point at the local VictoriaMetrics or Prometheus daemon
    /// (e.g. `"http://victoriametrics:8428"`). When `None` (the default), gate
    /// evaluation runs in stub mode and all gates auto-pass.
    pub fn with_prometheus_url(mut self, url: impl Into<String>) -> Self {
        self.prometheus_url = Some(url.into());
        self
    }

    /// Override the operator-bridge mode — useful in tests that want to select
    /// `MeshPeer` without setting a global env var.
    pub fn with_operator_bridge_mode(mut self, mode: OperatorBridgeMode) -> Self {
        self.operator_bridge_mode = mode;
        self
    }

    /// Override the headscale directory — useful for integration tests that
    /// don't want to write to `/etc`.
    pub fn with_headscale_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.headscale_dir = dir.into();
        self
    }

    /// Override the compose directory — useful for integration tests.
    pub fn with_compose_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.compose_dir = dir.into();
        self
    }

    /// R556-F7-T3: advertise a local scryer at `url` via `/services`.
    /// Called by kamaji once it's brought the scryer service up on this node;
    /// `url` is scryer's tailnet-bound base URL (e.g. `http://100.64.0.7:6543`).
    pub fn with_scryer_endpoint(mut self, url: impl Into<String>) -> Self {
        self.scryer_endpoint = Some(url.into());
        self
    }

    fn snapshot(&self) -> identity::StateOnDisk {
        self.state.lock().unwrap().clone()
    }

    fn replace_identity(&self, id: identity::Identity) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.identity = Some(id);
        identity::save_state(&self.state_path, &guard).context("persisting state file")?;
        Ok(())
    }
}

pub fn build_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/identity", get(get_identity))
        .route("/node", get(get_node))
        .route("/node/usage", get(get_node_usage))
        .route("/register-hostkey", post(register_hostkey))
        .route("/headscale/deploy", post(headscale_deploy))
        .route("/headscale/bootstrap", post(headscale_bootstrap))
        .route("/headscale/health", get(headscale_health_check))
        // R040-F21: Cloudflare healthcheck — 200 iff raft leader + headscale running
        .route("/mesh/leader-health", get(mesh_leader_health))
        // R040-F7: service management (R040-era compose path, superseded by /workloads)
        .route("/services", get(get_services))
        .route("/compose", post(deploy_compose))
        // R091-F1: WorkloadSpec-based orchestration (replaces compose path)
        .route("/workloads", get(list_workloads))
        .route("/workloads/{ident}/state", get(get_workload_state))
        // R092-F3: drain workloads before machine destroy. Pre-runtime stub:
        // returns 200 with an empty list. R091-F5 fills in the real drain.
        .route("/workloads/drain", post(drain_workloads))
        // R092-F5: WorkloadSpec deploy via yubaba RPC (operator-signed)
        .route("/workloads/deploy", post(deploy_workload_spec))
        // R427-F1: explicit destroy endpoint — tears down via runtime +
        // revokes cheers ownership row (if one was registered at deploy).
        .route("/workloads/{ident}/destroy", post(destroy_workload))
        // R092-F5: workload log streaming (R091-F1 SSE stub; R093 delivers scryer.tail)
        .route("/workloads/{ident}/logs", get(get_workload_logs))
        // R603-T5: read a forge step's durable produced artifact off the host's
        // persistent produced dir. Survives kamaji reaping the exited container
        // (the bytes live on the host bind-mount, not the container rootfs), so
        // boot-reconcile can retrieve + publish after a daemon outage.
        .route("/workloads/{ident}/produced", get(get_produced_file))
        // R092-F3: cloud-init log tail for `yah cloud machine provision`
        // failure surfacing. Reads /var/log/cloud-init{,-output}.log.
        .route("/diagnostics", get(get_diagnostics))
        // R608-F10: mesh-native, SSH-free control-plane roll. The orchestrator
        // POSTs a signed release ref; the node self-installs the yubaba+kamaji
        // pair via a detached systemd-run unit (yubaba's own process is
        // sandboxed and cannot write /usr/local/bin). Bootstraps the SSH-free
        // path — every roll after the first is over the mesh, no SSH.
        .route("/self-update", post(self_update))
        // R278-F1: rollout API — linear strategy + Prometheus gate evaluation
        .route("/v1/rollouts", post(create_rollout))
        .route("/v1/rollouts", get(list_rollouts))
        .route("/v1/rollouts/{id}", get(get_rollout))
        .route("/v1/rollouts/{id}/override", post(override_rollout))
        // R040-F20: raft RPC (peer-to-peer, Tailscale mesh only)
        .route("/raft/append-entries", post(raft_append_entries))
        .route("/raft/vote", post(raft_vote))
        // openraft 0.10 streaming snapshot (replaces chunked /raft/install-snapshot)
        .route("/raft/snapshot", post(raft_snapshot))
        // R040-F20: raft operator API
        .route("/raft/status", get(raft_status))
        .route("/raft/initialize", post(raft_initialize))
        .route("/raft/write", post(raft_write))
        .route("/raft/transfer-leader", post(raft_transfer_leader))
        // R608-B11: openraft-native TransferLeader message — the leader's
        // RaftNetworkV2 posts here so the target campaigns at once.
        .route("/raft/transfer-leader-msg", post(raft_transfer_leader_msg))
        // R374-F2: pond (sim-tier mesofact-static) status surface
        .route("/pond/deploy", post(pond::deploy))
        .route("/pond/state", get(pond::get_state))
        .route("/pond", get(pond::list_state))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, correlation_id_layer))
}

// ── Session ID + correlation-ID middleware ────────────────────────────────────

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a per-session string ID from the current time and a random-ish
/// suffix. Zero external deps; good enough for log correlation.
fn new_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("sess-{t:x}")
}

/// Axum middleware that stamps a `request_id` and the daemon `session_id`
/// on every inbound request span. JSON tracing records these fields alongside
/// every log line emitted during the request, letting agents stitch together
/// cross-service flows.
async fn correlation_id_layer(
    State(state): State<Arc<ServerState>>,
    req: axum::extract::Request,
    next: Next,
) -> impl IntoResponse {
    let request_id = format!("req-{:x}", REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed));
    let session_id = state.session_id.clone();
    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        session_id = %session_id,
        method = %req.method(),
        uri = %req.uri(),
    );
    let _enter = span.enter();
    next.run(req).await
}

/// Total wall-clock budget for retrying a bind whose address does not exist
/// yet. Fleet nodes bind a tailscale mesh IP (`--bind 100.64.0.x:7443` via the
/// `20-mesh-bind.conf` drop-in) that only appears once tailscaled has
/// connected; `After=tailscaled.service` orders the *start* but not the mesh
/// handshake, so on a cold boot the address can be missing for seconds.
///
/// The budget is deliberately finite. A bind that waits forever looks `active`
/// to systemd while serving nothing, which is a worse failure than crashing —
/// so past this point we give up and let the unit's `Restart=on-failure`
/// handle it.
const BIND_RETRY_BUDGET: std::time::Duration = std::time::Duration::from_secs(90);
/// First backoff step; doubles up to [`BIND_RETRY_MAX_DELAY`].
const BIND_RETRY_INITIAL_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
/// Ceiling on a single backoff step, so a late mesh IP is picked up promptly
/// rather than sitting out a long sleep.
const BIND_RETRY_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// Is this bind failure worth waiting on?
///
/// Only [`ErrorKind::AddrNotAvailable`] — the "the IP isn't configured on this
/// host *yet*" case — can resolve on its own. `AddrInUse`, `PermissionDenied`
/// and friends are permanent misconfigurations: retrying them just delays a
/// loud failure into a quiet hang, so they must propagate on the first attempt.
fn bind_error_is_retryable(kind: std::io::ErrorKind) -> bool {
    matches!(kind, std::io::ErrorKind::AddrNotAvailable)
}

/// Run `attempt` until it succeeds, fails with a non-retryable error, or
/// `budget` is exhausted. Returns the last error on give-up.
///
/// Generic over the attempt so tests can drive the backoff without a real
/// socket (binding a loopback port proves nothing about the mesh-IP race).
async fn bind_with_backoff<T, F, Fut>(
    addr: &str,
    budget: std::time::Duration,
    mut attempt: F,
) -> std::io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let started = std::time::Instant::now();
    let mut delay = BIND_RETRY_INITIAL_DELAY;
    let mut attempts: u32 = 0;
    loop {
        attempts += 1;
        let err = match attempt().await {
            Ok(v) => {
                if attempts > 1 {
                    tracing::info!(
                        addr,
                        attempts,
                        waited_ms = started.elapsed().as_millis() as u64,
                        "bind succeeded after waiting for the address to appear"
                    );
                }
                return Ok(v);
            }
            Err(e) => e,
        };
        if !bind_error_is_retryable(err.kind()) {
            return Err(err);
        }
        let elapsed = started.elapsed();
        if elapsed >= budget {
            tracing::error!(
                addr,
                attempts,
                waited_ms = elapsed.as_millis() as u64,
                budget_ms = budget.as_millis() as u64,
                error = %err,
                "address never became available within the bind retry budget; giving up"
            );
            return Err(err);
        }
        // Never sleep past the budget — the last attempt should land on it.
        let sleep_for = delay.min(budget - elapsed);
        tracing::warn!(
            addr,
            attempts,
            waited_ms = elapsed.as_millis() as u64,
            retry_in_ms = sleep_for.as_millis() as u64,
            error = %err,
            "address not available yet (mesh IP not up?); retrying bind"
        );
        tokio::time::sleep(sleep_for).await;
        delay = (delay * 2).min(BIND_RETRY_MAX_DELAY);
    }
}

/// Bind to `addr`, accept connections forever. Cancellation is up to the caller.
///
/// The bind is retried with bounded backoff while the address is merely
/// *not there yet* (see [`bind_with_backoff`]); every other bind error still
/// fails immediately.
pub async fn serve(addr: &str, state: Arc<ServerState>) -> Result<()> {
    let listener = bind_with_backoff(addr, BIND_RETRY_BUDGET, || {
        tokio::net::TcpListener::bind(addr)
    })
    .await
    .with_context(|| format!("binding {addr}"))?;
    let local = listener.local_addr().ok();
    tracing::info!(addr = ?local, "yah-yubaba listening");
    axum::serve(listener, build_router(state))
        .await
        .context("axum::serve")
}

/// Serve over a caller-provided listener. Used by camp when it wants to
/// pre-bind on port 0 to learn the assigned port before announcing it
/// (R374-F2: camp writes the port to `.yah/jit/yubaba-pond-port.json`).
pub async fn serve_on_listener(
    listener: tokio::net::TcpListener,
    state: Arc<ServerState>,
) -> Result<()> {
    let local = listener.local_addr().ok();
    tracing::info!(addr = ?local, "yah-yubaba listening (embedded)");
    axum::serve(listener, build_router(state))
        .await
        .context("axum::serve")
}

// ── Handlers ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
    name: &'static str,
    version: &'static str,
    /// `"single-node"` when started without `--raft-node-id` (real containerd,
    /// no raft mesh — the fully-exercised surface before adding HA). `"clustered"`
    /// when the raft coordination layer is active.
    mode: &'static str,
    /// Version of the sibling kamaji captured at the Hello/Welcome handshake
    /// ([`kamaji::sibling::ConstableInfo::kamaji_version`]). `None` when no
    /// kamaji UDS is attached (in-process runtime fallback / single-node). yubaba
    /// and kamaji ship + install as one atomic pair, but only yubaba's version
    /// was on this surface before — which is how the live 0.8.17/0.8.18 kamaji
    /// skew went unnoticed (W275 OQ5 / R608-T3). Surfacing it here lets the
    /// rolling-upgrade executor's `verify` assert **both** halves over one HTTP
    /// read instead of SSH-ing `kamaji --version`.
    #[serde(skip_serializing_if = "Option::is_none")]
    kamaji_version: Option<String>,
    /// `"present"` once this node has a hostkey, `"absent"` while it doesn't
    /// (R569-B2). An identity-less node is not a silent-degradation-free state:
    /// post-R593-T2 the hostkey *is* the mshr `NodeId`, so `absent` means
    /// `/identity` 404s, the node can't join a mesh, and admission can't enroll
    /// it — but it still binds, serves, and answers `status: "ok"`. A fleet
    /// probe that only reads `status` cannot tell those apart; this field is
    /// how it can.
    hostkey: &'static str,
}

async fn health(State(s): State<Arc<ServerState>>) -> Json<HealthBody> {
    Json(HealthBody {
        status: "ok",
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        mode: if s.raft.is_some() {
            "clustered"
        } else {
            "single-node"
        },
        hostkey: if s.snapshot().identity.is_some() {
            "present"
        } else {
            "absent"
        },
        kamaji_version: s
            .constable_client
            .as_ref()
            .map(|c| c.info().kamaji_version.clone()),
    })
}

/// `GET /node` — this node's hardware specs, measured.
///
/// The counterpart to the hand-written `[allocatable]` block in
/// `.yah/infra/machines/<name>.toml`. Nothing has ever verified those numbers
/// against the actual box; `yah.allocatable.memory_mb` / `.cpu_millis` here
/// are the measured values a consumer can diff the declaration against.
///
/// Field names follow OpenTelemetry semantic conventions where one exists
/// (`host.arch`, `os.type`, `system.memory.limit`, …) with yah-specific
/// fields under `yah.`; see [`node`] for why we took the convention without
/// the SDK.
///
/// Always 200. A platform with no collector returns `yah.collector =
/// "unsupported"` and omits the measurements rather than erroring — for a
/// fleet dashboard, "this node cannot measure itself" and "this node is
/// unreachable" must be distinguishable.
async fn get_node(State(s): State<Arc<ServerState>>) -> Json<node::NodeSpecs> {
    Json(s.node_probe.specs().clone())
}

/// `?window_ms=` on `GET /node/usage`.
#[derive(Deserialize)]
struct NodeUsageQuery {
    /// Explicit CPU sampling window in milliseconds, clamped server-side.
    ///
    /// Omit it — the normal case — and the window is the gap since *this*
    /// caller's previous poll, so the measurement interval automatically
    /// equals the reporting interval. Pass it when you want a reading
    /// independent of your own cadence, or when several clients poll the same
    /// node and would otherwise shorten each other's windows.
    #[serde(default)]
    window_ms: Option<u64>,
}

/// `GET /node/usage` — current resource usage, sampled per request.
///
/// This is the "report usage at whatever interval another yubaba or client
/// wants" surface, implemented as a pull: the caller's poll rate *is* the
/// interval. No subscription state to leak, nothing to re-establish after a
/// yubaba restart, and one code path for the desktop Infra tab and a peer
/// yubaba alike.
///
/// Alongside the machine-wide numbers it reports `yah.committed.memory_mb` /
/// `.cpu_millis` — the sum of resource requests across workloads this node
/// admitted. That is the term the scheduler's capacity floor has always been
/// missing: it compares against static `allocatable` and never subtracts what
/// is already running.
async fn get_node_usage(
    State(s): State<Arc<ServerState>>,
    axum::extract::Query(q): axum::extract::Query<NodeUsageQuery>,
) -> Json<node::NodeUsage> {
    let committed = node::committed_totals(&s.workload_resources);
    Json(s.node_probe.usage(q.window_ms, committed).await)
}

#[derive(Serialize)]
struct IdentityBody {
    hostkey_fingerprint: String,
    algorithm: String,
    /// Hex-encoded mshr NodeId — same key as `hostkey_fingerprint`, added by
    /// R593-T2 so `/identity` reports the mshr machine identity directly.
    node_id: String,
}

async fn get_identity(State(s): State<Arc<ServerState>>) -> Result<Json<IdentityBody>, StatusCode> {
    match s.snapshot().identity {
        Some(id) => {
            // R593-T2: node_id is the hex-encoded mshr NodeId derived from
            // this same Ed25519 public key (W268 §Verification — `curl
            // /identity | jq .node_id` must equal what mshr's identity
            // loader reports for this machine).
            let node_id =
                identity::node_id_hex(&id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Json(IdentityBody {
                hostkey_fingerprint: id.hostkey_fingerprint,
                algorithm: id.algorithm,
                node_id,
            }))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
struct RegisterRequest {
    /// Full OpenSSH public-key line, e.g. `"ssh-ed25519 AAAA… [comment]"`.
    pubkey: String,
    /// Operator-issued provisioning bootstrap token (R593-F8, W268 INTERIM).
    /// `Option` is the WIRE shape only — enforcement is **not** optional: a
    /// request missing a valid, unconsumed token is rejected `401` before any
    /// identity work (see [`register_hostkey`]). Minted into the node's
    /// cloud-init user-data by the provisioning path; single-use, short-TTL.
    /// See [`identity::bootstrap`].
    #[serde(default)]
    bootstrap_token: Option<String>,
}

/// Current Unix time in whole seconds (`i64`), for bootstrap-token TTLs.
/// A pre-epoch / unreadable clock clamps to `0`; the token is still
/// single-use and short-TTL, so a broken clock cannot mint validity out of
/// nothing — it only ever makes a live token read as not-yet-expired.
fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Serialize)]
struct RegisterResponse {
    hostkey_fingerprint: String,
}

async fn register_hostkey(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    // R593-F8 (W268 §"Fleet machine" binding ceremony — INTERIM): admission
    // is an AUTHENTICATED ceremony. This handler enrolls the presenting
    // hostkey via `admit_node` — an ownership:write under yubaba's trusted
    // service principal — so an unauthenticated caller must never reach it,
    // or anyone network-reachable self-enrolls as a fleet node (the F4
    // finding). Require + atomically consume an operator-issued bootstrap
    // token BEFORE any identity work; proof-of-possession of the hostkey is
    // insufficient (an attacker trivially holds their own key). Every failure
    // mode collapses to ONE undifferentiated 401 (the typed
    // `BootstrapTokenError` variants are internal-audit only — see the
    // `identity::bootstrap` module doc) so a probe cannot distinguish
    // unknown / expired / already-used.
    let now_unix = unix_now_secs();
    let Some(token) = req.bootstrap_token.as_deref() else {
        tracing::warn!("register-hostkey rejected: no bootstrap token presented");
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    };
    match s.bootstrap_tokens.validate_and_consume(token, now_unix) {
        Ok(ctx) => {
            tracing::info!(
                node_hint = ?ctx.node_hint,
                "register-hostkey: bootstrap token accepted"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "register-hostkey rejected: bootstrap token invalid");
            return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
        }
    }

    let id = identity::parse_pubkey(&req.pubkey)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid pubkey: {e}")))?;
    let fp = id.hostkey_fingerprint.clone();
    s.replace_identity(id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("persist: {e}")))?;
    // R593-F4: this is the moment a node's identity first becomes durable —
    // the admission seam W268 calls "yubaba admission enrolls it". Write the
    // enrollment row (svc:<operator principal> owns node:<NodeId>) when a
    // cheers_client is configured; no-op + warn-logged otherwise (see
    // ServerState::admit_node's doc for why this handler, not
    // ServerState::load, owns the call site). Response shape is unchanged
    // either way — enrollment failure never blocks hostkey registration.
    s.admit_node().await;
    Ok(Json(RegisterResponse {
        hostkey_fingerprint: fp,
    }))
}

// ── Phase 2 Cloudflare healthcheck (R040-F21) ────────────────────────────────

/// `GET /mesh/leader-health` — Cloudflare load-balancer healthcheck.
///
/// Returns **200** only when both conditions hold:
///   - This yubaba node is the current raft leader.
///   - The Headscale API is reachable on localhost:8080.
///
/// Returns **503** in all other cases (follower, raft not configured, headscale
/// stopped).  Cloudflare will route Headscale HTTPS traffic only to nodes that
/// return 200, so leader changes flip ingress automatically within the CF LB
/// health-check cadence (~10 s).
///
/// When raft is not configured (`--raft-node-id` not passed to `serve`), this
/// endpoint returns 503 so that single-node Phase 1b deployments don't
/// accidentally appear as "healthy" to a load balancer pointing at Phase 2
/// topology.
#[derive(Serialize)]
struct LeaderHealthBody {
    leader: bool,
    headscale: String,
}

async fn mesh_leader_health(State(s): State<Arc<ServerState>>) -> impl IntoResponse {
    let is_leader = match (&s.raft, s.node_id) {
        (Some(raft), Some(my_id)) => {
            let metrics = raft.metrics().borrow_watched().clone();
            metrics.current_leader == Some(my_id)
        }
        _ => false,
    };

    let headscale_running = probe_headscale_local().await;

    let body = LeaderHealthBody {
        leader: is_leader,
        headscale: if headscale_running {
            "running"
        } else {
            "stopped"
        }
        .into(),
    };

    let status = if is_leader && headscale_running {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(body))
}

// ── Workload management (R091-F1) ─────────────────────────────────────────────

// ── Raft quorum helpers ───────────────────────────────────────────────────────

/// Returns `"fresh"` when raft quorum is available (a leader is elected), or
/// `"stale"` when quorum is lost. Single-node servers without raft always
/// return `"fresh"`.
///
/// Used by read handlers to set the `X-State-Freshness` response header so
/// clients (agents, desktop, tests) can distinguish authoritative reads from
/// reads on a node that has lost quorum.
fn raft_freshness(state: &ServerState) -> &'static str {
    match &state.raft {
        Some(raft) if raft.metrics().borrow_watched().current_leader.is_none() => "stale",
        _ => "fresh",
    }
}

/// Check whether write operations are allowed. Returns `Some(error_response)`
/// when raft quorum is unavailable (no leader elected), which callers should
/// return early. Returns `None` when writes are permitted.
fn quorum_write_guard(state: &ServerState) -> Option<axum::response::Response> {
    if let Some(raft) = &state.raft {
        if raft.metrics().borrow_watched().current_leader.is_none() {
            use axum::response::IntoResponse;
            return Some((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "raft quorum unavailable — no leader elected; writes rejected until quorum is restored"
                })),
            ).into_response());
        }
    }
    None
}

/// `GET /workloads` — list all workloads known to the runtime.
///
/// Includes an `X-State-Freshness` header (`fresh` | `stale`) indicating
/// whether this node has raft quorum. Stale means the list reflects the last
/// known state before quorum was lost.
///
/// R406-T8: when a Kamaji client is configured, dispatch through the UDS
/// instead of the legacy in-process `ContainerRuntime`. Each row is the
/// `WorkloadEntry` shape from `kamaji-proto` — `{ id, state, pid }`.
/// A response header `x-workload-source` is set to `kamaji`, `runtime`,
/// or `stub` so callers can branch on the row shape deterministically.
async fn list_workloads(State(s): State<Arc<ServerState>>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let freshness = raft_freshness(&s);

    if let Some(client) = &s.constable_client {
        let headers = [
            ("x-state-freshness", freshness),
            ("x-workload-source", "kamaji"),
        ];
        return match client.list().await {
            Ok(entries) => {
                let mut rows = serde_json::json!(entries);
                node::enrich_workloads(&s.workload_resources, &mut rows);
                (
                    StatusCode::OK,
                    headers,
                    Json(serde_json::json!({ "workloads": rows })),
                )
                    .into_response()
            }
            Err(e) => (
                StatusCode::BAD_GATEWAY,
                headers,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        };
    }

    let Some(rt) = &s.runtime else {
        let headers = [
            ("x-state-freshness", freshness),
            ("x-workload-source", "stub"),
        ];
        return (
            StatusCode::OK,
            headers,
            Json(serde_json::json!({ "workloads": [] })),
        )
            .into_response();
    };
    let headers = [
        ("x-state-freshness", freshness),
        ("x-workload-source", "runtime"),
    ];
    match rt.list_workloads().await {
        Ok(workloads) => {
            // Attach each workload's declared resource request (see
            // `node::enrich_workloads` for why this is a JSON-level merge and
            // not a change to either `WorkloadEntry` type).
            let mut rows = serde_json::json!(workloads);
            node::enrich_workloads(&s.workload_resources, &mut rows);
            (
                StatusCode::OK,
                headers,
                Json(serde_json::json!({ "workloads": rows })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            headers,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// `GET /workloads/{ident}/state` — get state for one workload.
///
/// Includes an `X-State-Freshness` header. In a cluster, read paths stay up
/// even when quorum is lost — callers should check the header when ordering
/// guarantees matter.
///
/// R406-T8: when a Kamaji client is configured, this is implemented as
/// `client.list()` filtered by id. The protocol's `Probe` is reserved for
/// readiness, not lifecycle introspection; until Kamaji gains a per-id
/// query (T9), filtering the list is the right primitive — Kamaji's
/// registry is in-memory.
async fn get_workload_state(
    State(s): State<Arc<ServerState>>,
    axum::extract::Path(ident): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let freshness = raft_freshness(&s);

    if let Some(client) = &s.constable_client {
        let headers = [
            ("x-state-freshness", freshness),
            ("x-workload-source", "kamaji"),
        ];
        let id = kamaji_proto::WorkloadId::new(ident.clone());
        return match client.list().await {
            Ok(entries) => {
                // Match on the container id OR the mesh identity (R590-B9): the
                // poll handle is the workload's mesh identity (e.g.
                // `forge.<uuid>`), which differs from the DNS-safe container id
                // (`forge-<uuid>`) kamaji lists as `WorkloadEntry.id`. kamaji
                // now surfaces the mesh identity on `WorkloadEntry.mesh_ident`;
                // without this a forge run's state 404s and the run is
                // misreported Failed regardless of the container's real outcome.
                if let Some(entry) = entries
                    .into_iter()
                    .find(|e| e.id == id || e.mesh_ident.as_deref() == Some(ident.as_str()))
                {
                    let body = serde_json::to_value(&entry).unwrap_or_else(
                        |e| serde_json::json!({ "error": format!("serialize: {e}") }),
                    );
                    (StatusCode::OK, headers, Json(body)).into_response()
                } else {
                    (
                        StatusCode::NOT_FOUND,
                        headers,
                        Json(serde_json::json!({ "error": "workload not found" })),
                    )
                        .into_response()
                }
            }
            Err(e) => (
                StatusCode::BAD_GATEWAY,
                headers,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        };
    }

    let headers = [
        ("x-state-freshness", freshness),
        ("x-workload-source", "runtime"),
    ];
    let Some(rt) = &s.runtime else {
        let headers = [
            ("x-state-freshness", freshness),
            ("x-workload-source", "stub"),
        ];
        return (
            StatusCode::NOT_IMPLEMENTED,
            headers,
            Json(serde_json::json!({ "error": "workload runtime not yet configured" })),
        )
            .into_response();
    };
    let mesh_ident = workload_spec::MeshIdent(ident);
    match rt.get_workload(&mesh_ident).await {
        Ok(Some(state)) => {
            let body = serde_json::to_value(&state)
                .unwrap_or_else(|e| serde_json::json!({ "error": format!("serialize: {e}") }));
            (StatusCode::OK, headers, Json(body)).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            headers,
            Json(serde_json::json!({ "error": "workload not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            headers,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// `POST /workloads/drain` — gracefully stop all workloads on this machine
/// before a tear-down. Always returns 200 so the destroy CLI can call it
/// unconditionally — empty `drained` list means "nothing to drain right now."
///
/// R406-T8: when a Kamaji client is configured, list workloads via UDS
/// and send each a structured [`kamaji_proto::YubabaToKamaji::Drain`]
/// with the default budget (flush 5s, checkpoint 1s — matches the
/// floor documented in W154 §"Runtime parity contract"). When Kamaji
/// isn't wired, the legacy path tears workloads down via the in-process
/// `ContainerRuntime`.
async fn drain_workloads(State(s): State<Arc<ServerState>>) -> impl IntoResponse {
    if let Some(client) = &s.constable_client {
        let budget = kamaji_proto::DrainBudget {
            flush_ms: 5_000,
            checkpoint_ms: 1_000,
        };
        let entries = client.list().await.unwrap_or_default();
        let mut drained: Vec<String> = Vec::new();
        let mut failed: Vec<serde_json::Value> = Vec::new();
        for entry in entries {
            // R572-F4: appliances are pinned / non-drainable (W244 §Workload
            // classes). The registry key is the mesh ident; fall back to the
            // container id for workloads deployed before F4 landed.
            let ident_key = entry.mesh_ident.as_deref().unwrap_or(entry.id.as_str());
            if s.archetype_registry.lock().unwrap().get(ident_key).copied()
                == Some(LifecycleArchetype::Appliance)
            {
                tracing::info!(
                    id = entry.id.as_str(),
                    ident = ident_key,
                    "drain: skipping appliance (pinned, non-drainable per R572-F4)"
                );
                continue;
            }
            match client.drain(&entry.id, budget).await {
                Ok((true, _)) => drained.push(entry.id.as_str().to_string()),
                Ok((false, reason)) => failed.push(serde_json::json!({
                    "id": entry.id.as_str(),
                    "reason": reason,
                })),
                Err(e) => failed.push(serde_json::json!({
                    "id": entry.id.as_str(),
                    "reason": e.to_string(),
                })),
            }
        }
        let body = serde_json::json!({
            "drained": drained,
            "failed": failed,
            "runtime": "kamaji",
        });
        return (StatusCode::OK, Json(body));
    }

    let Some(rt) = &s.runtime else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "drained": [], "runtime": "stub" })),
        );
    };
    let workloads = rt.list_workloads().await.unwrap_or_default();
    let mut drained = Vec::new();
    for w in &workloads {
        if rt.teardown_workload(&w.ident).await.is_ok() {
            drained.push(w.ident.0.clone());
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "drained": drained })),
    )
}

// ── Workload deploy + logs (R092-F5) ─────────────────────────────────────────

/// `POST /workloads/deploy` request body.
///
/// `spec` is the JSON-encoded `WorkloadSpec`; `operator_signature` is a
/// base64-encoded Ed25519 signature over the spec JSON (operator key from the
/// cluster's known-keys list, per R044). Until R044 ships the key vault,
/// unsigned deploys are accepted with a warning.
#[derive(Deserialize, Debug)]
struct WorkloadDeployBody {
    spec: serde_json::Value,
    #[serde(default)]
    operator_signature: Option<String>,
    /// R427-F1: the cheers camp principal this deploy is scoped to
    /// (`camp:<id>`). Becomes the `principal_id` on the ownership row.
    /// Optional in stub/dev tiers that have no cheers client wired; the
    /// register call is skipped when either this field or `cheers_client`
    /// is absent. R428 replaces this body field with derivation from the
    /// verified MCP claims on the request once the authed transport lands.
    #[serde(default)]
    requesting_camp_id: Option<String>,
    /// R427-F1: the human who triggered this deploy (`user:<id>`). Becomes
    /// the ownership row's `on_behalf_of` — drives cascading revocation
    /// (revoke user → all rows with that `on_behalf_of` revoked) per
    /// W159 §Ownership writes.
    #[serde(default)]
    on_behalf_of_user: Option<String>,
    /// R599-T5: workload id for non-`Container` workloads. A `Container` takes
    /// its id from `spec.name`, but `MesofactStaticWorkload` carries no name —
    /// the bundle it serves is identified by digest, and a digest is a poor
    /// operator-facing handle (it changes on every rebuild, so `stop`/`list`
    /// would chase a moving target). The caller names the workload instead.
    #[serde(default)]
    id: Option<String>,
}

/// `POST /workloads/deploy` — accept a `WorkloadSpec` for deployment.
///
/// Validates the spec (shape layer) and queues it with the ContainerRuntime.
/// ContainerRuntime is wired in R091-F5; this stub returns 202 Accepted and
/// records the intent so desktop + agent clients can integrate before the
/// runtime is live. Returns 422 when the spec fails shape validation.
///
/// **R406-T8 deploy path is intentionally still on the legacy
/// `ContainerRuntime`.** Kamaji's `Deploy` arm in `app/yah/kamaji/
/// src/server.rs::handle_message` returns `Error { Internal, "backend driver
/// not implemented (R406-T4..T6/T11)" }` — wiring the yubaba deploy handler
/// through `client.deploy()` before Kamaji's containerd backend exists
/// would break every single-node and clustered deploy. R406-T9 ships that
/// backend; the deploy migration happens there. The ingress/operator-bridge
/// registration and mesh-IP allocation stay in yubaba after the migration —
/// they are admission, not supervision.
/// Dispatch a non-`Container` [`Workload`] to kamaji (R599-T5).
///
/// Today that means `MesofactStatic` carrying a `serve_bundle` — the W272
/// content-addressed bundle path. Kamaji materializes the bundle from the
/// public origin (verifying every blake3) and forks its serve binary; there is
/// no image, no mesh-IP allocation, and no secret materialization, so this
/// deliberately skips the container admission chain rather than threading a
/// second workload shape through it.
///
/// A `MesofactStatic` *without* `serve_bundle` is the legacy build-and-publish
/// form, which belongs to yubaba's own `mesofact-static` reconciler, not to
/// kamaji — it is rejected here with that pointer rather than being forwarded
/// to a backend that would only answer `InvalidSpec`.
async fn deploy_non_container(
    s: &Arc<ServerState>,
    workload: workload_spec::Workload,
    id: Option<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let (ident, reject) = match &workload {
        workload_spec::Workload::MesofactStatic(w) => match &w.serve_bundle {
            Some(b) => (b.digest.0.clone(), None),
            None => (
                String::new(),
                Some(
                    "mesofact-static without serve_bundle is a build-and-publish workload — \
                     it is reconciled by yubaba's mesofact-static reconciler, not deployed \
                     to a node. Attach serve_bundle {digest, runtime, lifecycle} to serve it \
                     as a W272 bundle."
                        .to_string(),
                ),
            ),
        },
        workload_spec::Workload::Almanac(_) => (
            String::new(),
            Some("almanac workloads are reconciled by yubaba, not deployed to kamaji".into()),
        ),
        workload_spec::Workload::StaticAsset(_) => (
            String::new(),
            Some("static-asset workloads publish to the object store, not to a node".into()),
        ),
        workload_spec::Workload::Container(_) => unreachable!("container handled by the caller"),
    };

    if let Some(error) = reject {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "status": "rejected", "ident": ident, "error": error })),
        )
            .into_response();
    }

    // Request validation comes BEFORE backend availability: a malformed request
    // is the caller's bug whether or not a backend happens to be attached, and
    // reporting 503 for it would send them chasing node config instead of
    // fixing their body.
    //
    // The operator names the workload; the digest is the *content*, not the
    // handle. Without a stable name, `list`/`stop` would chase a new id on
    // every rebuild.
    let Some(name) = id.filter(|n| !n.trim().is_empty()) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "status": "rejected",
                "ident": ident,
                "error": "bundle deploys require an \"id\" in the request body — the stable \
                          operator-facing workload name (e.g. \"yah-marketing\"). The bundle \
                          digest identifies the content and changes on every rebuild, so it \
                          is not a usable handle for list/stop.",
            })),
        )
            .into_response();
    };
    let id = kamaji_proto::WorkloadId::new(&name);

    // Only the sibling kamaji can serve a bundle — the legacy in-process
    // ContainerRuntime has no native fork backend. Say so plainly rather than
    // failing somewhere deeper.
    let Some(kamaji) = s.constable_client.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "rejected",
                "ident": ident,
                "error": "no kamaji sibling attached — bundle workloads need kamaji \
                          (start yubaba with --kamaji-socket and kamaji with \
                          --bundle-cache-dir + --bundle-origin)",
            })),
        )
            .into_response();
    };

    match kamaji.deploy_envelope(&id, &workload).await {
        Ok(()) => {
            tracing::info!(ident = %ident, "bundle workload deployed via kamaji");
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "accepted",
                    "ident": ident,
                    "runtime": "kamaji",
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "status": "rejected",
                "ident": ident,
                "runtime": "kamaji",
                "error": format!("kamaji refused the bundle deploy: {e}"),
            })),
        )
            .into_response(),
    }
}

async fn deploy_workload_spec(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<WorkloadDeployBody>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Reject writes when raft quorum is unavailable.
    if let Some(err_resp) = quorum_write_guard(&s) {
        return err_resp;
    }

    // R599-T5: the body carries either a full `Workload` envelope (externally
    // tagged, e.g. `{"mesofact-static": {...}}`) or — the pre-migration shape
    // every deployed client still sends — a bare `WorkloadSpec`, which means
    // `Container`. The two are unambiguous: `Workload` is externally tagged, so
    // a bare spec (many top-level keys) can never parse as one. Once the CLI
    // and desktop are rolled onto the envelope form, drop the fallback.
    let envelope: workload_spec::Workload =
        match serde_json::from_value::<workload_spec::Workload>(req.spec.clone()) {
            Ok(w) => w,
            Err(envelope_err) => {
                match serde_json::from_value::<workload_spec::WorkloadSpec>(req.spec) {
                    Ok(spec) => workload_spec::Workload::Container(spec),
                    Err(spec_err) => {
                        return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({
                        "status": "rejected",
                        "ident": "",
                        "runtime": "stub",
                        "error": format!(
                            "spec JSON parse error: not a Workload envelope ({envelope_err}) \
                             nor a bare WorkloadSpec ({spec_err})"
                        ),
                    })),
                )
                    .into_response();
                    }
                }
            }
        };

    // Bundle-serving workloads take a short, dedicated path: kamaji materializes
    // the content-addressed bundle and forks its serve binary, so none of the
    // container admission below (mesh-IP allocation, secret materialization,
    // produced dirs, archetype registry) applies to them.
    let mut spec = match envelope {
        workload_spec::Workload::Container(spec) => spec,
        other => return deploy_non_container(&s, other, req.id).await,
    };

    if let Err(e) = workload_spec::validate::shape(&spec) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "status": "rejected",
                "ident": spec.expose.mesh.identity.0,
                "runtime": "stub",
                "error": format!("shape validation failed: {e}"),
            })),
        )
            .into_response();
    }

    if req.operator_signature.is_none() {
        // Strict rejection lands with R044 (key vault). Log a warning now so
        // the operator knows unsigned deploys will break once R044 ships.
        tracing::warn!(
            ident = %spec.expose.mesh.identity.0,
            "workload deploy received without operator signature \
             (unsigned accepted in stub mode — R044 will enforce rejection)"
        );
    }

    let ident = spec.expose.mesh.identity.0.clone();

    // R572-F4: reject a second deploy of the same appliance ident while the
    // first is still live.  Servers are freely re-deployable (rolling update);
    // appliances carry per-ident state (pinned volume, single-instance
    // invariant from W244 §Schema gaps #1) — the caller must destroy first.
    if s.archetype_registry.lock().unwrap().get(&ident).copied()
        == Some(LifecycleArchetype::Appliance)
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "status": "rejected",
                "ident": ident,
                "error": "appliance already live: destroy the existing instance before redeploying",
            })),
        )
            .into_response();
    }

    // R406-T9: route deploy through Kamaji (the W154 supervision backend)
    // when it is wired, falling back to the legacy in-process ContainerRuntime
    // otherwise. `ContainerRuntime` is an alias of `constable_core::Kamaji`
    // (see the `use` at the top of this file) and `KamajiClient` implements
    // it, so `s.constable_client` coerces straight into the same trait object
    // the rest of this handler already drives — deploy_workload + the failure
    // teardowns below stay backend-agnostic, untouched.
    //
    // This closes the deploy/state split-brain: `list`, `get_state`, and
    // `drain` already prefer Kamaji, so a Kamaji-attached yubaba that
    // deployed via the legacy runtime would never find its own workloads when
    // reading them back. Deploy must use the same backend the read handlers do.
    let backend: Option<Arc<dyn ContainerRuntime + Send + Sync>> = s.active_backend();

    if let Some(rt) = backend {
        let mesh = crate::mesh::MeshAssignment::stub(s.alloc_mesh_ip());
        let mesh_ident = workload_spec::MeshIdent(ident.clone());

        // R600-F4 (W273): capture the workload's original cluster `File` secret
        // mounts (pre-materialization, still `SecretRef::Cluster`) before F6
        // rewrites them to `Bind`s. If the deploy succeeds these seed the
        // rotation registry so a later cert renewal can re-render + graceful-
        // upgrade this workload. A pending entry is built inside the
        // materialization block (where the resolver lives) and committed only
        // after the backend accepts the workload.
        let cluster_file_mounts: Vec<workload_spec::SecretMount> = spec
            .secrets
            .iter()
            .filter(|m| {
                matches!(m.source, workload_spec::SecretRef::Cluster { .. })
                    && matches!(m.target, workload_spec::SecretTarget::File { .. })
            })
            .cloned()
            .collect();
        let mut pending_secret_registration: Option<crate::secret_reload::SecretWorkloadEntry> =
            None;

        // R603-T5: create the host-persistent produced dir before the backend
        // binds it. kamaji's OCI mapper is a pure mapper — it does not mkdir a
        // Bind source, and runc refuses a bind whose source is missing. The dir
        // lives outside the container rootfs so the produced tar survives the
        // container being reaped after a daemon outage; yubaba serves reads from
        // it (GET /workloads/{ident}/produced) and reaps it on destroy. Also
        // opportunistically sweep stale produced dirs so orphans (a run whose
        // consumer never came back) don't accumulate unbounded.
        ensure_durable_produced_dirs(&spec).await;
        sweep_stale_produced_dirs().await;

        // R600-F6 (W273): materialize File-target secret mounts into per-workload
        // tmpfs files and rewrite them as read-only Bind volumes BEFORE the spec
        // reaches the backend. Runs after `validate::shape` (so the tier gate
        // still applied to the operator-authored spec) and only in the
        // has-backend branch (stub mode never writes plaintext to disk).
        // Decryption stays in yubaba; kamaji only ever sees the injected bind.
        if spec
            .secrets
            .iter()
            .any(|m| matches!(m.target, workload_spec::SecretTarget::File { .. }))
        {
            let needs_cluster = spec.secrets.iter().any(|m| {
                matches!(m.source, workload_spec::SecretRef::Cluster { .. })
                    && matches!(m.target, workload_spec::SecretTarget::File { .. })
            });
            let resolver: Box<dyn workload_spec::secrets::SecretResolver> = if needs_cluster {
                let Some(sm) = &s.secret_state else {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(serde_json::json!({
                            "status": "rejected",
                            "ident": ident,
                            "error": "spec references a cluster secret but this node \
                                      is not part of a raft cluster (no cluster state)",
                        })),
                    )
                        .into_response();
                };
                match crate::secrets::ClusterResolver::from_kek_file(
                    sm.clone(),
                    &s.cluster_kek_path,
                    crate::secrets::SECRET_STORE_ROOT,
                ) {
                    Ok(r) => Box::new(r),
                    Err(e) => {
                        return (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Json(serde_json::json!({
                                "status": "rejected",
                                "ident": ident,
                                "error": format!("cluster secret resolver init failed: {e}"),
                            })),
                        )
                            .into_response();
                    }
                }
            } else {
                Box::new(crate::secrets::LocalFileResolver::new(
                    crate::secrets::SECRET_STORE_ROOT,
                ))
            };

            if let Err(e) = crate::deploy::secret_mount::materialize_file_secrets(
                &mut spec,
                &ident,
                resolver.as_ref(),
                &s.secret_mount_root,
            ) {
                // Fail closed: a missing / undecryptable cluster secret rejects
                // the deploy rather than starting a workload without its cert.
                crate::deploy::secret_mount::teardown_secret_dir(&s.secret_mount_root, &ident);
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({
                        "status": "rejected",
                        "ident": ident,
                        "error": format!("secret materialization failed: {e}"),
                    })),
                )
                    .into_response();
            }

            // R600-F4: seed the rotation registry for a workload that mounts a
            // cluster secret. `spec` is now materialized (cluster File secrets
            // are Bind volumes of the host tmpfs files); the digest is taken
            // from the *original* cluster File mounts so a later re-resolve can
            // detect an actual rotation. Held pending; committed only if the
            // backend accepts the workload below.
            if !cluster_file_mounts.is_empty() {
                let digest = match crate::secrets::resolve_secrets(
                    &cluster_file_mounts,
                    resolver.as_ref(),
                ) {
                    Ok(resolved) => crate::secret_reload::content_digest(&resolved),
                    // Resolvable a line ago (materialize succeeded); treat a
                    // transient failure here as "unknown" so the first rotation
                    // bump re-resolves and upgrades.
                    Err(_) => 0,
                };
                pending_secret_registration = Some(crate::secret_reload::SecretWorkloadEntry {
                    spec: spec.clone(),
                    mesh: mesh.clone(),
                    file_mounts: cluster_file_mounts.clone(),
                    content_digest: digest,
                });
            }
        }

        match rt.deploy_workload(&spec, &mesh).await {
            Ok(result) => {
                // Public ingress registration (R091-F7): when the spec carries
                // expose.public, register a Cloudflare Tunnel route so external
                // traffic reaches this workload. On registration failure, tear
                // the workload back down and surface the error.
                if let Some(pub_expose) = &spec.expose.public {
                    let service_url = format!("http://127.0.0.1:{}", pub_expose.port);
                    match &s.cloudflared_url {
                        Some(cf_url) => {
                            if let Err(e) = register_cloudflare_tunnel(
                                cf_url,
                                &pub_expose.hostname,
                                &service_url,
                            )
                            .await
                            {
                                // Tear down the container we just started — the
                                // workload is unusable without its public tunnel.
                                let _ = rt.teardown_workload(&mesh_ident).await;
                                crate::deploy::secret_mount::teardown_secret_dir(
                                    &s.secret_mount_root,
                                    &ident,
                                );
                                return (
                                    StatusCode::BAD_GATEWAY,
                                    Json(serde_json::json!({
                                        "status": "failed",
                                        "ident": ident,
                                        "error": format!("cloudflare tunnel registration failed: {e}"),
                                    })),
                                )
                                    .into_response();
                            }
                            tracing::info!(
                                ident = %ident,
                                hostname = %pub_expose.hostname,
                                "cloudflare tunnel registered"
                            );
                        }
                        None => {
                            // No cloudflared configured — fall back to
                            // docker-style port mapping. The workload is
                            // accessible on localhost:<port> without a tunnel.
                            tracing::info!(
                                ident = %ident,
                                port = pub_expose.port,
                                "no cloudflared URL configured; using port-mapping fallback for expose.public"
                            );
                        }
                    }
                }

                // Operator-bridge registration (R091-F8): when the spec carries
                // expose.operator, create a Headscale preauth key with the
                // requested ACL tag so an operator machine can join the tailnet
                // and reach this workload. On failure, tear the workload down.
                // When YAH_OPERATOR_BRIDGE_MODE=mesh-peer, skip Tailscale and
                // expose the workload as a direct mesh peer.
                let mut preauthkey: Option<String> = None;
                let mut operator_mode = "none";
                if let Some(op_expose) = &spec.expose.operator {
                    if s.operator_bridge_mode == OperatorBridgeMode::MeshPeer {
                        operator_mode = "mesh-peer";
                        tracing::info!(
                            ident = %ident,
                            "YAH_OPERATOR_BRIDGE_MODE=mesh-peer: skipping Tailscale, \
                             workload exposed as direct mesh peer"
                        );
                    } else {
                        match &s.headscale_url {
                            Some(hs_url) => {
                                match register_headscale_preauthkey(
                                    hs_url,
                                    &op_expose.tailscale_tag,
                                )
                                .await
                                {
                                    Ok(key) => {
                                        operator_mode = "tailscale";
                                        preauthkey = Some(key);
                                        tracing::info!(
                                            ident = %ident,
                                            tag = %op_expose.tailscale_tag,
                                            "headscale preauth key created for operator bridge"
                                        );
                                    }
                                    Err(e) => {
                                        let _ = rt.teardown_workload(&mesh_ident).await;
                                        crate::deploy::secret_mount::teardown_secret_dir(
                                            &s.secret_mount_root,
                                            &ident,
                                        );
                                        return (
                                            StatusCode::BAD_GATEWAY,
                                            Json(serde_json::json!({
                                                "status": "failed",
                                                "ident": ident,
                                                "error": format!("headscale preauth key creation failed: {e}"),
                                            })),
                                        )
                                            .into_response();
                                    }
                                }
                            }
                            None => {
                                tracing::warn!(
                                    ident = %ident,
                                    tag = %op_expose.tailscale_tag,
                                    "no headscale URL configured and YAH_OPERATOR_BRIDGE_MODE \
                                     is not 'mesh-peer'; expose.operator will have no effect"
                                );
                            }
                        }
                    }
                }

                // R427-F1: register ownership in cheers. The workload is
                // already live by this point — ingress + operator bridge
                // succeeded — so a cheers failure here is a WARN and not a
                // tear-down. Rationale: tearing down a running service over
                // an auth-table write blip is worse than serving an audit
                // gap. The gap is recoverable (the row can be backfilled
                // by a reconciler once cheers is reachable) but a torn-down
                // workload requires re-deploy. 5-min token TTL bounds the
                // staleness window if writes succeed eventually.
                if let (Some(cheers), Some(camp_id)) = (&s.cheers_client, &req.requesting_camp_id) {
                    match cheers
                        .register_ownership(
                            camp_id,
                            "service",
                            &ident,
                            "owns",
                            req.on_behalf_of_user.as_deref(),
                        )
                        .await
                    {
                        Ok(row) => {
                            s.ownership_rows
                                .lock()
                                .unwrap()
                                .insert(ident.clone(), row.id.clone());
                            tracing::info!(
                                ident = %ident,
                                camp_id = %camp_id,
                                row_id = %row.id,
                                "cheers ownership row registered"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                ident = %ident,
                                camp_id = %camp_id,
                                error = %e,
                                "cheers ownership register failed; workload \
                                 stays up, row may be backfilled by reconciler"
                            );
                        }
                    }
                }

                let mut resp_json = serde_json::json!({
                    "status": "deployed",
                    "ident": ident,
                    "container_id": result.container_id,
                    "mesh_ip": result.mesh_ip.to_string(),
                });
                if let Some(key) = preauthkey {
                    resp_json["preauthkey"] = serde_json::Value::String(key);
                    resp_json["operator_mode"] = serde_json::Value::String(operator_mode.into());
                } else if operator_mode == "mesh-peer" {
                    resp_json["operator_mode"] = serde_json::Value::String(operator_mode.into());
                }

                // R600-F4: the workload is live — register it for cert-rotation
                // reload so a later cluster-secret renewal re-renders its mount
                // and graceful-upgrades it.
                if let Some(entry) = pending_secret_registration.take() {
                    s.secret_workloads
                        .lock()
                        .unwrap()
                        .insert(ident.clone(), entry);
                }
                // R572-F4: record the archetype so drain + single-instance
                // guard can branch without re-parsing the spec.
                s.archetype_registry
                    .lock()
                    .unwrap()
                    .insert(ident.clone(), spec.effective_archetype());
                // Record what this workload asked for, so `GET /node/usage`
                // can report committed capacity and `GET /workloads` can
                // attach a per-workload request. Recorded here (post-success,
                // beside the archetype) rather than at admission so a failed
                // deploy never counts against the node's committed total.
                s.workload_resources.lock().unwrap().insert(
                    ident.clone(),
                    node::WorkloadResources {
                        memory_mb: spec.resources.memory_mb,
                        cpu_millis: spec.resources.cpu_millis,
                    },
                );
                return (StatusCode::CREATED, Json(resp_json)).into_response();
            }
            Err(e) => {
                // `{:#}` renders the full anyhow chain (e.g. the containerd /
                // runc message under "creating task for ..."), not just the
                // top context — essential for diagnosing deploy failures.
                tracing::error!(ident = %ident, error = format!("{e:#}"), "workload deploy failed");
                // Reap any secret files materialized before the failed deploy so
                // decrypted PEM doesn't linger for a workload that never started.
                crate::deploy::secret_mount::teardown_secret_dir(&s.secret_mount_root, &ident);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "status": "error",
                        "ident": ident,
                        "error": format!("{e:#}"),
                    })),
                )
                    .into_response();
            }
        }
    }

    // No runtime configured — accept and queue (stub mode).
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "accepted",
            "ident": ident,
            "runtime": "stub",
        })),
    )
        .into_response()
}

/// `POST /workloads/{ident}/destroy` — tear down a workload and revoke its
/// cheers ownership row (R427-F1).
///
/// Order matters: runtime teardown first, then revoke. If teardown fails the
/// row stays in cheers — operator can retry destroy and the second attempt
/// hits revoke. If teardown succeeds but revoke fails, the row drifts as a
/// "ghost" until a reconciler sweeps it; that's the same staleness budget
/// W159 §Ownership writes accepts elsewhere. 404 from revoke is treated as
/// already-gone (logged INFO, response succeeds) — destroy is idempotent
/// on both sides.
///
/// Returns 200 with `{ status: "destroyed" | "not_found", ident, revoked: bool }`.
/// `revoked: true` when a cheers row was actually revoked on this call;
/// `false` when no row was registered (predates cheers client) or revoke
/// returned 404.
async fn destroy_workload(
    State(s): State<Arc<ServerState>>,
    axum::extract::Path(ident): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    if let Some(err_resp) = quorum_write_guard(&s) {
        return err_resp;
    }

    let mesh_ident = workload_spec::MeshIdent(ident.clone());
    let mut teardown_status = "destroyed";
    let mut teardown_error: Option<String> = None;

    if let Some(rt) = &s.runtime {
        match rt.teardown_workload(&mesh_ident).await {
            Ok(()) => {}
            Err(e) => {
                let msg = e.to_string();
                // "not found" surfaces from runtimes as a benign condition;
                // anything else is a real failure that should NOT proceed
                // to revoke (the workload may still be running).
                if msg.to_lowercase().contains("not found") {
                    teardown_status = "not_found";
                } else {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "status": "teardown_failed",
                            "ident": ident,
                            "error": msg,
                        })),
                    )
                        .into_response();
                }
                teardown_error = Some(msg);
            }
        }
    }

    // R600-F6 (W273): reap the workload's materialized-secret tmpfs dir so
    // decrypted PEM does not outlive the container. Idempotent — a no-op when
    // the workload had no File secrets.
    crate::deploy::secret_mount::teardown_secret_dir(&s.secret_mount_root, &ident);
    // R600-F4: stop tracking it for cert-rotation reload (no-op if unregistered).
    s.secret_workloads.lock().unwrap().remove(&ident);
    // R572-F4: clear the archetype so a fresh deploy of the same ident is accepted.
    s.archetype_registry.lock().unwrap().remove(&ident);
    // Release its committed capacity — a destroyed workload must stop
    // counting against `yah.committed.*` or the node slowly reports itself
    // full while sitting idle.
    s.workload_resources.lock().unwrap().remove(&ident);

    // Revoke the cheers ownership row (if registered).
    let row_id = s.ownership_rows.lock().unwrap().remove(&ident);
    let mut revoked = false;
    if let (Some(cheers), Some(row_id)) = (&s.cheers_client, row_id.as_ref()) {
        match cheers.revoke_ownership(row_id).await {
            Ok(()) => {
                revoked = true;
                tracing::info!(
                    ident = %ident,
                    row_id = %row_id,
                    "cheers ownership row revoked"
                );
            }
            Err(cheers_client::CheersError::Status { status, .. })
                if status == StatusCode::NOT_FOUND =>
            {
                tracing::info!(
                    ident = %ident,
                    row_id = %row_id,
                    "cheers ownership row already gone (idempotent destroy)"
                );
            }
            Err(e) => {
                // Workload is already torn down; surface revoke failure to
                // the caller so the row can be reconciled out-of-band, but
                // don't error the whole destroy — the on-host state is
                // already consistent.
                tracing::warn!(
                    ident = %ident,
                    row_id = %row_id,
                    error = %e,
                    "cheers ownership revoke failed after teardown; row may need reconciler"
                );
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "status": teardown_status,
                        "ident": ident,
                        "revoked": false,
                        "revoke_error": e.to_string(),
                    })),
                )
                    .into_response();
            }
        }
    }

    // R603-T5: reap the run's durable produced dir now that it's torn down. The
    // consumer retrieves the artifact (GET /produced) before destroy, so by here
    // the bytes have been collected + landed content-addressed in camp; keeping
    // the host copy would only accumulate. Idempotent + best-effort.
    //
    // R603-B6: ONLY reap on a CONFIRMED teardown. `not_found` means the runtime
    // never acknowledged stopping anything, so the workload may still be alive —
    // and reaping its output dir out from under a running container is
    // destructive: the container keeps the now-deleted inode bind-mounted at
    // /yah/produced, so its final write dies with ENOENT. That is precisely how
    // the rusty-v8-musl build lost a finished 145MB librusty_v8.a after ~57min
    // (QED falsely timed out at 9s -> teardown -> not_found -> reap, while the
    // build ran happily on). Leaking a dir is bounded by the 3-day TTL sweep;
    // deleting a live build's output is not recoverable. Fail safe: keep it.
    if teardown_status == "destroyed" {
        reap_produced_dir(&ident).await;
    } else {
        tracing::info!(
            ident = %ident,
            teardown_status,
            "skipping produced-dir reap: teardown was not confirmed, workload may still be running"
        );
    }

    let mut body = serde_json::json!({
        "status": teardown_status,
        "ident": ident,
        "revoked": revoked,
    });
    if let Some(err) = teardown_error {
        body["teardown_note"] = serde_json::Value::String(err);
    }
    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /workloads/{ident}/logs` — stream logs for a workload.
///
/// Real SSE streaming is wired in R091-F1 (yubaba SSE endpoint) with the
/// final path being scryer.tail over the operator-bridge tailnet (R093-P1).
/// Returns 501 until one of those lands so the CLI can detect the stub and
/// fall back gracefully.
async fn get_workload_logs(
    axum::extract::Path(ident): axum::extract::Path<String>,
) -> impl IntoResponse {
    let _ = ident;
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "workload log streaming not yet available",
            "hint": "R091-F1 ships yubaba SSE; R093-P1 ships scryer.tail over operator-bridge",
        })),
    )
}

// ── Durable forge produced artifacts (R603-T5) ────────────────────────────────

/// Query for [`get_produced_file`]: the container-side path the forge step
/// declared in `produces` (must be under the durable dir `/yah/produced`).
#[derive(Deserialize)]
struct ProducedQuery {
    path: String,
}

/// `GET /workloads/{ident}/produced?path=<container_path>` — read a forge
/// step's durable produced artifact (R603-T5).
///
/// The build wrote its output under the conventional `/yah/produced` dir, which
/// is a host-persistent bind mount (`/var/lib/yah/qed/produced/<forge_id>/`).
/// We read the bytes straight off that **host** path — no containerd / task
/// involvement — so retrieval works even after kamaji reaped the exited
/// container. This is the real transport R590-F6 deferred; T5 reshapes it as a
/// host read (survives reaping) rather than a container-rootfs read (does not).
async fn get_produced_file(
    axum::extract::Path(ident): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<ProducedQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let Some(forge_id) = workload_spec::forge_produced::forge_id_from_ident(&ident) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("ident {ident:?} is not a forge ident (expected forge.<id>)"),
            })),
        )
            .into_response();
    };
    let container_path = std::path::Path::new(&q.path);
    let Some(host_path) = workload_spec::forge_produced::host_path(forge_id, container_path) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "produced path {:?} is not a valid durable path under {}",
                    q.path,
                    workload_spec::forge_produced::CONTAINER_DIR,
                ),
            })),
        )
            .into_response();
    };
    match tokio::fs::read(&host_path).await {
        Ok(bytes) => (StatusCode::OK, bytes).into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("produced artifact not found at {}", host_path.display()),
                "hint": "the build did not write to /yah/produced, or the dir was already reaped",
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("reading produced artifact {}: {e}", host_path.display()),
            })),
        )
            .into_response(),
    }
}

/// R603-T5 retention window: durable produced dirs older than this whose
/// consumer never returned to retrieve + reap them are swept at the next
/// deploy. Bounds unbounded accumulation of orphaned build tars on the worker.
const PRODUCED_RETENTION: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 3);

/// Create the host-persistent produced dir(s) a forge spec declares, so runc
/// can bind them — the OCI mapper never mkdirs a Bind source and runc refuses a
/// bind with a missing source. Best-effort: a failure is logged, not fatal (the
/// deploy proceeds and surfaces the bind failure with its own error).
async fn ensure_durable_produced_dirs(spec: &workload_spec::WorkloadSpec) {
    let dir = std::path::Path::new(workload_spec::forge_produced::CONTAINER_DIR);
    for vol in &spec.volumes {
        if vol.target == dir {
            if let workload_spec::VolumeSource::Bind { host_path } = &vol.source {
                if let Err(e) = tokio::fs::create_dir_all(host_path).await {
                    tracing::warn!(
                        dir = %host_path.display(),
                        error = %e,
                        "failed to create durable produced dir; forge bind mount may fail"
                    );
                }
            }
        }
    }
}

/// Remove one forge run's durable produced dir (called on destroy, after the
/// consumer has retrieved the artifact). Best-effort + idempotent — a missing
/// dir is a no-op.
async fn reap_produced_dir(ident: &str) {
    let Some(forge_id) = workload_spec::forge_produced::forge_id_from_ident(ident) else {
        return;
    };
    let dir = workload_spec::forge_produced::host_dir(forge_id);
    match tokio::fs::remove_dir_all(&dir).await {
        // R603-B6: info, not debug. This deletes a forge's build output; when it
        // fired spuriously the only trace was an absent directory and a build
        // failing with ENOENT an hour later. A destructive act must be legible
        // in the journal at default verbosity.
        Ok(()) => tracing::info!(dir = %dir.display(), "reaped durable produced dir on destroy"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(dir = %dir.display(), error = %e, "failed to reap produced dir"),
    }
}

/// Opportunistically remove durable produced dirs whose retention window has
/// elapsed. Best-effort; called at deploy so accumulation stays bounded without
/// a dedicated background task.
async fn sweep_stale_produced_dirs() {
    let root = std::path::Path::new(workload_spec::forge_produced::HOST_ROOT);
    let mut entries = match tokio::fs::read_dir(root).await {
        Ok(e) => e,
        Err(_) => return, // root not created yet → nothing to sweep
    };
    let now = std::time::SystemTime::now();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let aged_out = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .map(|age| age > PRODUCED_RETENTION)
            .unwrap_or(false);
        if aged_out {
            let path = entry.path();
            match tokio::fs::remove_dir_all(&path).await {
                Ok(()) => tracing::info!(
                    dir = %path.display(),
                    "reaped stale produced dir (retention window elapsed)"
                ),
                Err(e) => tracing::warn!(
                    dir = %path.display(),
                    error = %e,
                    "failed to reap stale produced dir"
                ),
            }
        }
    }
}

// ── Diagnostics (R092-F3) ─────────────────────────────────────────────────────

/// `GET /diagnostics` response body — last N lines of each cloud-init log.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DiagnosticsBody {
    /// Last `lines` lines of `/var/log/cloud-init.log`.
    pub cloud_init_log: String,
    /// Last `lines` lines of `/var/log/cloud-init-output.log`.
    pub cloud_init_output_log: String,
    /// How many lines were requested per file (matches the `lines` query
    /// param; default 200).
    pub lines: usize,
    /// Per-file read errors, when a file existed but couldn't be read
    /// (typically permission-denied). Empty when both reads succeeded
    /// (or the files simply don't exist on this host, which is normal
    /// on dev machines).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Deserialize)]
struct DiagnosticsQuery {
    /// Last N lines per log file (default 200; clamped to 1..=2000).
    #[serde(default)]
    lines: Option<usize>,
}

/// `GET /diagnostics?lines=N` — return the last N lines of each cloud-init
/// log so a failed `yah cloud machine provision --wait` can surface what
/// went wrong without needing SSH. Always 200 — missing files yield empty
/// strings rather than 404 (dev machines won't have them).
async fn get_diagnostics(
    axum::extract::Query(q): axum::extract::Query<DiagnosticsQuery>,
) -> impl IntoResponse {
    let lines = q.lines.unwrap_or(200).clamp(1, 2_000);
    let body = read_diagnostics(
        std::path::Path::new("/var/log/cloud-init.log"),
        std::path::Path::new("/var/log/cloud-init-output.log"),
        lines,
    );
    (StatusCode::OK, Json(body))
}

/// Read the last `lines` lines of each path; pure-function helper so tests
/// can pass tempfiles instead of `/var/log/...`.
fn read_diagnostics(
    cloud_init: &std::path::Path,
    output: &std::path::Path,
    lines: usize,
) -> DiagnosticsBody {
    let mut errors = Vec::new();
    let cloud_init_log = read_tail(cloud_init, lines, &mut errors);
    let cloud_init_output_log = read_tail(output, lines, &mut errors);
    DiagnosticsBody {
        cloud_init_log,
        cloud_init_output_log,
        lines,
        errors,
    }
}

/// Read up to the last `n` lines of `path`. Missing files yield empty string
/// silently (normal on dev hosts); permission-denied or other I/O errors
/// append to `errors` and yield empty content for that file.
fn read_tail(path: &std::path::Path, n: usize, errors: &mut Vec<String>) -> String {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let collected: Vec<&str> = s.lines().collect();
            let start = collected.len().saturating_sub(n);
            collected[start..].join("\n")
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            errors.push(format!("{}: {e}", path.display()));
            String::new()
        }
    }
}

// ── Service management (R040-F7) ────────────────────────────────────────────

/// `POST /compose` request — push a new compose bundle to the machine.
#[derive(Deserialize)]
pub struct ComposeDeployRequest {
    /// Podman Compose YAML to write as `compose.yml`.
    pub compose_yaml: String,
    /// Optional Caddyfile for public services; omitted when all are mesh-only.
    pub caddyfile: Option<String>,
    /// Shell commands to run after writing files (R040-F16: ufw rules for
    /// services with `bind_interface` set). Each is executed via `sh -c`.
    /// Failures are logged but don't abort the deploy.
    #[serde(default)]
    pub firewall_cmds: Vec<String>,
}

/// `POST /compose` response.
#[derive(Serialize)]
pub struct ComposeDeployResponse {
    /// `"started"` | `"restarted"` | `"files-written-systemd-unavailable"`
    pub status: String,
}

async fn deploy_compose(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<ComposeDeployRequest>,
) -> Result<Json<ComposeDeployResponse>, (StatusCode, String)> {
    let dir = &s.compose_dir;
    std::fs::create_dir_all(dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("mkdir {}: {e}", dir.display()),
        )
    })?;

    std::fs::write(dir.join("compose.yml"), &req.compose_yaml).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write compose.yml: {e}"),
        )
    })?;

    if let Some(cf) = &req.caddyfile {
        std::fs::write(dir.join("Caddyfile"), cf).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("write Caddyfile: {e}"),
            )
        })?;
    }

    // Write the systemd unit on first deploy (idempotent — only writes if absent).
    let unit_path = format!("/etc/systemd/system/{COMPOSE_UNIT}.service");
    if !std::path::Path::new(&unit_path).exists() {
        let unit = format!(
            "[Unit]\n\
             Description=yah-cloud managed services (Podman Compose)\n\
             After=network-online.target\n\
             \n\
             [Service]\n\
             WorkingDirectory={dir}\n\
             ExecStart=/usr/bin/podman compose up\n\
             ExecStop=/usr/bin/podman compose down\n\
             Restart=on-failure\n\
             RestartSec=10\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            dir = dir.display(),
        );
        let _ = std::fs::write(&unit_path, unit);
        let _ = std::process::Command::new("systemctl")
            .args(["daemon-reload"])
            .status();
    }

    // Apply firewall rules for mesh-bound services (R040-F16). Run before
    // starting the compose stack so ports are protected on first activation.
    // Failures are logged but do NOT abort the deploy — ufw may not be
    // installed on dev machines or in CI.
    for cmd in &req.firewall_cmds {
        let result = std::process::Command::new("sh").args(["-c", cmd]).status();
        match result {
            Ok(s) if s.success() => {}
            Ok(s) => tracing::warn!(cmd, exit = ?s.code(), "firewall_cmd exited non-zero"),
            Err(e) => tracing::warn!(cmd, err = %e, "firewall_cmd spawn failed"),
        }
    }

    // Enable + (re)start. On non-systemd hosts (dev machines, CI) this will
    // fail — files are written regardless, so the compose stack can be started
    // manually with `podman compose up -d`.
    let svc_ok = std::process::Command::new("systemctl")
        .args(["enable", "--now", COMPOSE_UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !svc_ok {
        // Maybe it was already enabled; try a restart.
        let _ = std::process::Command::new("systemctl")
            .args(["restart", COMPOSE_UNIT])
            .status();
    }

    let status = if svc_ok {
        "started"
    } else {
        "files-written-systemd-unavailable"
    };
    Ok(Json(ComposeDeployResponse {
        status: status.into(),
    }))
}

/// W264 §Discovery service-entry — what yubaba advertises at `GET /services`.
///
/// One row per kamaji-managed (or yubaba-internal) service running on this
/// node. Consumers walk `/raft/status` + `/services` per peer to find every
/// scryer in the mesh and connect to those scryers **directly** — yubaba is
/// not in the data path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceEntry {
    pub name: String,
    pub endpoint: String,
    pub capabilities: Vec<String>,
    pub managed_by: String,
}

/// `GET /services` — typed service discovery (W264 §Discovery).
///
/// Returns the list of services this node advertises to the mesh. R556-F7-T3
/// adds the local kamaji-managed scryer entry when `ServerState::scryer_endpoint`
/// is set; otherwise the list is empty.
///
/// Workload-container enumeration moved to `GET /workloads` (R091-F1); the
/// legacy podman-compose passthrough that used to live on this route was a
/// stub for a path now driven through kamaji.
async fn get_services(State(s): State<Arc<ServerState>>) -> Json<Vec<ServiceEntry>> {
    let mut services: Vec<ServiceEntry> = Vec::new();
    if let Some(endpoint) = &s.scryer_endpoint {
        services.push(ServiceEntry {
            name: "scryer".to_string(),
            endpoint: endpoint.clone(),
            capabilities: vec!["events.query".to_string(), "events.aggregate".to_string()],
            managed_by: "kamaji".to_string(),
        });
    }
    Json(services)
}

// ── Headscale deployment (Phase 1b — R040-F19) ──────────────────────────────

/// `POST /headscale/deploy` request — transfer headscale state from the camp
/// and start it as a managed service on this machine.
///
/// Files are base64-encoded so the whole payload is a single JSON object.
/// The headscale binary is downloaded from GitHub (not inlined here) so the
/// transfer stays small even for multi-MB binaries.
#[derive(Deserialize)]
pub struct HeadscaleDeployRequest {
    /// Headscale release version to download, e.g. `"0.23.0"`.
    pub headscale_version: String,
    /// Headscale SQLite DB (base64-encoded).
    pub db_base64: String,
    /// WireGuard private key for Headscale (base64-encoded).
    pub private_key_base64: String,
    /// Noise private key for Headscale (base64-encoded).
    pub noise_key_base64: String,
    /// ACL policy YAML (plain text).
    pub acl_policy: String,
    /// Stable public URL for this coordinator (`https://mesh.<domain>`).
    pub server_url: String,
}

/// `POST /headscale/deploy` response.
#[derive(Serialize)]
pub struct HeadscaleDeployResponse {
    pub status: String,
    pub headscale_dir: String,
}

/// `GET /headscale/health` response.
#[derive(Serialize, Deserialize, Clone)]
pub struct HeadscaleHealthResponse {
    /// `"running"` | `"stopped"` | `"unknown"`.
    pub headscale: String,
    /// Whether the headscale HTTP API on localhost:8080 responded.
    pub api_reachable: bool,
}

async fn headscale_deploy(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<HeadscaleDeployRequest>,
) -> Result<Json<HeadscaleDeployResponse>, (StatusCode, String)> {
    let dir = &s.headscale_dir;

    std::fs::create_dir_all(dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("mkdir {}: {e}", dir.display()),
        )
    })?;

    // Decode and write state files.
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;

    macro_rules! write_b64 {
        ($field:expr, $filename:expr) => {{
            let bytes = engine.decode(&$field).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("decode {}: {e}", $filename),
                )
            })?;
            std::fs::write(dir.join($filename), &bytes).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("write {}: {e}", $filename),
                )
            })?;
        }};
    }

    write_b64!(req.db_base64, "headscale.db");
    write_b64!(req.private_key_base64, "private.key");
    write_b64!(req.noise_key_base64, "noise_private.key");

    std::fs::write(dir.join("acls.yaml"), &req.acl_policy).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write acls.yaml: {e}"),
        )
    })?;

    // Generate a config.yaml appropriate for remote paths.
    let config_yaml = generate_remote_headscale_config(&req.server_url, dir);
    std::fs::write(dir.join("config.yaml"), &config_yaml).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write config.yaml: {e}"),
        )
    })?;

    // Download headscale binary (Linux-only; this binary runs on Hetzner machines).
    let bin_path = download_headscale_binary(dir, &req.headscale_version)?;

    // Write + start the systemd unit — best-effort on non-systemd hosts (tests, Mac).
    let svc_ok = write_and_start_headscale_unit(&bin_path, dir);

    let status = if svc_ok {
        "started"
    } else {
        "files-written-systemd-unavailable"
    };
    Ok(Json(HeadscaleDeployResponse {
        status: status.into(),
        headscale_dir: dir.to_string_lossy().into_owned(),
    }))
}

async fn headscale_health_check() -> Json<HeadscaleHealthResponse> {
    let systemd_active = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "headscale"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    // Also try a direct HTTP probe of the headscale API on localhost.
    let api_reachable = probe_headscale_local().await;

    let headscale = if systemd_active || api_reachable {
        "running"
    } else {
        "stopped"
    };

    Json(HeadscaleHealthResponse {
        headscale: headscale.into(),
        api_reachable,
    })
}

async fn probe_headscale_local() -> bool {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    client
        .get("http://127.0.0.1:8080/health")
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Generate the headscale config for a remote machine (files under `headscale_dir`).
fn generate_remote_headscale_config(server_url: &str, headscale_dir: &std::path::Path) -> String {
    let private_key = headscale_dir.join("private.key").display().to_string();
    let noise_key = headscale_dir
        .join("noise_private.key")
        .display()
        .to_string();
    let db_path = headscale_dir.join("headscale.db").display().to_string();
    let socket_path = headscale_dir.join("headscale.sock").display().to_string();
    let acl_path = headscale_dir.join("acls.yaml").display().to_string();

    format!(
        "---\n\
         server_url: {server_url}\n\
         listen_addr: 127.0.0.1:8080\n\
         grpc_listen_addr: 127.0.0.1:50443\n\
         metrics_listen_addr: 127.0.0.1:9090\n\
         private_key_path: {private_key}\n\
         noise:\n\
           private_key_path: {noise_key}\n\
         database:\n\
           type: sqlite\n\
           sqlite:\n\
             path: {db_path}\n\
         unix_socket: {socket_path}\n\
         unix_socket_permission: \"0770\"\n\
         dns:\n\
           magic_dns: true\n\
           base_domain: mesh.internal\n\
           nameservers:\n\
             global:\n\
               - 1.1.1.1\n\
               - 8.8.8.8\n\
         log:\n\
           level: info\n\
         prefixes:\n\
           v4: 100.64.0.0/10\n\
           v6: fd7a:115c:a1e0::/48\n\
           allocation: sequential\n\
         policy:\n\
           mode: file\n\
           path: {acl_path}\n\
         derp:\n\
           server:\n\
             enabled: false\n\
           urls:\n\
             - https://controlplane.tailscale.com/derpmap/default\n\
           auto_update_enabled: false\n\
           update_frequency: 24h\n"
    )
}

/// `POST /headscale/bootstrap` request — stand up a BRAND-NEW headscale mesh on
/// this node from scratch (no transplanted state). This is the self-bootstrap
/// path for the FIRST node of a fresh mesh: it has a public IP and becomes the
/// coordinator itself — no camp/laptop coordinator, and crucially no Cloudflare
/// proxy in the noise path (CF strips tailscale's TS2021 `Upgrade` header, which
/// 500s `/machine/register`). Headscale terminates its own TLS via Let's Encrypt
/// so joining nodes reach the noise endpoint directly over HTTPS.
#[derive(Deserialize)]
pub struct HeadscaleBootstrapRequest {
    /// Stable public URL this coordinator advertises to joining nodes, e.g.
    /// `https://cloud.mesh.yah.dev`. The host must resolve (DNS-only / NOT
    /// CF-proxied) to this node so headscale's HTTP-01 ACME challenge succeeds.
    pub server_url: String,
    /// Headscale release to download. Defaults to [`DEFAULT_HEADSCALE_VERSION`].
    #[serde(default)]
    pub headscale_version: Option<String>,
}

/// `POST /headscale/bootstrap` response.
#[derive(Serialize, Deserialize)]
pub struct HeadscaleBootstrapResponse {
    pub status: String,
    pub headscale_dir: String,
    pub server_url: String,
    /// Reusable preauth key minted on the fresh coordinator. Subsequent nodes
    /// join with `tailscale up --login-server <server_url> --auth-key <this>`.
    /// Empty when bootstrap reached the file-writing stage but headscale never
    /// came up (non-systemd host) — `status` reflects that.
    pub preauth_key: String,
    /// Headscale API key minted on the fresh coordinator (R330-F30). The
    /// operator persists this to the vault as `headscale-api-key`; the provision
    /// JOIN path then PREFERS it to mint a fresh single-use-per-node preauth key
    /// per node, falling back to the reusable [`Self::preauth_key`] only when no
    /// api-key is present. Empty when minting failed (headscale not up, or the
    /// CLI errored) — the operator silently keeps using the reusable fallback.
    #[serde(default)]
    pub api_key: String,
}

/// Extract the bare host from a `server_url` for the Let's Encrypt hostname.
/// `https://cloud.mesh.yah.dev:443/foo` -> `cloud.mesh.yah.dev`. Returns `None`
/// when no host component is present.
fn letsencrypt_hostname(server_url: &str) -> Option<String> {
    let after_scheme = server_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(server_url);
    let host = after_scheme
        .split(['/', ':', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

async fn headscale_bootstrap(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<HeadscaleBootstrapRequest>,
) -> Result<Json<HeadscaleBootstrapResponse>, (StatusCode, String)> {
    let dir = &s.headscale_dir;
    let version = req
        .headscale_version
        .clone()
        .unwrap_or_else(|| DEFAULT_HEADSCALE_VERSION.to_string());

    let le_hostname = letsencrypt_hostname(&req.server_url).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("server_url has no host: {}", req.server_url),
        )
    })?;

    std::fs::create_dir_all(dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("mkdir {}: {e}", dir.display()),
        )
    })?;

    // Write config + permissive ACL FIRST so they exist regardless of whether
    // the download/start/mint steps succeed (mirrors headscale_deploy ordering).
    std::fs::write(dir.join("acls.yaml"), DEFAULT_ACL_POLICY_HUJSON).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write acls.yaml: {e}"),
        )
    })?;
    let config_yaml = generate_bootstrap_headscale_config(&req.server_url, &le_hostname, dir);
    std::fs::write(dir.join("config.yaml"), &config_yaml).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write config.yaml: {e}"),
        )
    })?;

    // Open the ports headscale needs as a public coordinator: 80 for the
    // Let's Encrypt HTTP-01 challenge, 443 for the noise endpoint. Best-effort
    // and scoped to the node that actually becomes a coordinator — the shared
    // cloud-init template keeps yubaba RPC (7443) mesh-only for every node.
    allow_headscale_ports();

    // Headscale auto-generates its private/noise keys + an empty SQLite DB on
    // first `serve`; there is no state to transplant.
    let bin_path = download_headscale_binary(dir, &version)?;
    let svc_ok = write_and_start_headscale_unit(&bin_path, dir);

    // Create the default user + mint a reusable preauth key via the local
    // headscale CLI (no API key needed on a fresh box). Best-effort: a
    // non-systemd host can't run headscale, so the key comes back empty and
    // `status` flags it — the file-writing work above still stands.
    let preauth_key = if svc_ok {
        mint_bootstrap_preauth_key(&bin_path, dir)
            .await
            .unwrap_or_default()
    } else {
        String::new()
    };

    // Also mint an API key (R330-F30) so the operator's provision JOIN path can
    // create single-use-per-node preauth keys instead of sharing the reusable
    // one. Only attempt once preauth minting confirmed the CLI socket is live;
    // best-effort, so an empty key just means the reusable-preauth fallback
    // stays in play (no status downgrade — the mesh still works).
    let api_key = if svc_ok && !preauth_key.is_empty() {
        mint_bootstrap_api_key(&bin_path, dir)
            .await
            .unwrap_or_default()
    } else {
        String::new()
    };

    let status = match (svc_ok, preauth_key.is_empty()) {
        (true, false) => "started",
        (true, true) => "started-preauth-mint-failed",
        (false, _) => "files-written-systemd-unavailable",
    };

    Ok(Json(HeadscaleBootstrapResponse {
        status: status.into(),
        headscale_dir: dir.to_string_lossy().into_owned(),
        server_url: req.server_url,
        preauth_key,
        api_key,
    }))
}

/// Create the `yah` user (idempotent) and mint a long-lived reusable preauth key
/// against the locally-running headscale via its CLI + unix socket. Returns the
/// raw key string. Retries briefly to let headscale finish initialising its DB.
async fn mint_bootstrap_preauth_key(
    bin_path: &std::path::Path,
    dir: &std::path::Path,
) -> anyhow::Result<String> {
    let config = dir.join("config.yaml");
    let run = |args: &[&str]| {
        std::process::Command::new(bin_path)
            .arg("--config")
            .arg(&config)
            .args(args)
            .output()
    };

    // Wait for headscale to accept CLI calls (DB created, socket up).
    for attempt in 0..10u32 {
        // `users create` is idempotent enough — a duplicate just errors, which
        // we tolerate; what we need is for the socket to answer at all.
        let _ = run(&["users", "create", "yah"]);
        let out = run(&[
            "preauthkeys",
            "create",
            "--user",
            "yah",
            "--reusable",
            "--expiration",
            "87600h", // ~10 years; rotation is R330-T9 follow-up.
            "--output",
            "json",
        ])?;
        if out.status.success() {
            let v: serde_json::Value = serde_json::from_slice(&out.stdout)
                .context("parsing `headscale preauthkeys create --output json`")?;
            if let Some(key) = v["key"].as_str().filter(|k| !k.is_empty()) {
                return Ok(key.to_string());
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(
            500 + 250 * u64::from(attempt),
        ))
        .await;
    }
    anyhow::bail!("headscale CLI never produced a preauth key after 10 attempts")
}

/// Mint a Headscale API key via the local CLI (`headscale apikeys create`),
/// which prints the bare key token to stdout. Returned to the operator in
/// [`HeadscaleBootstrapResponse::api_key`] and persisted to the vault so the
/// provision JOIN path can mint single-use-per-node preauth keys (R330-F30).
/// Called only after [`mint_bootstrap_preauth_key`] succeeded, so the socket is
/// already live — a short retry just rides out any residual flakiness.
async fn mint_bootstrap_api_key(
    bin_path: &std::path::Path,
    dir: &std::path::Path,
) -> anyhow::Result<String> {
    let config = dir.join("config.yaml");
    for attempt in 0..5u32 {
        let out = std::process::Command::new(bin_path)
            .arg("--config")
            .arg(&config)
            .args(["apikeys", "create"])
            .output()?;
        if out.status.success() {
            let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !key.is_empty() {
                return Ok(key);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(
            500 + 250 * u64::from(attempt),
        ))
        .await;
    }
    anyhow::bail!("headscale CLI never produced an api key after 5 attempts")
}

/// Open ports 80 (ACME HTTP-01) + 443 (headscale noise endpoint) via ufw.
/// Best-effort: a host without ufw (tests, Mac) is a no-op. Only called from
/// the self-bootstrap path so non-coordinator nodes stay locked down.
fn allow_headscale_ports() {
    for port in ["80/tcp", "443/tcp"] {
        let _ = std::process::Command::new("ufw")
            .args(["allow", port])
            .status();
    }
}

/// Download the headscale binary into `dir` and mark it executable.
/// Shared by `headscale_deploy` (state transfer) and `headscale_bootstrap`.
fn download_headscale_binary(
    dir: &std::path::Path,
    version: &str,
) -> Result<PathBuf, (StatusCode, String)> {
    let bin_path = dir.join("headscale");
    let dl_url = headscale_linux_download_url(version);
    let curl_ok = std::process::Command::new("curl")
        .args(["-fsSL", "-o", &bin_path.to_string_lossy(), &dl_url])
        .status()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("curl spawn: {e}"),
            )
        })?
        .success();
    if !curl_ok {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("headscale download failed from {dl_url}"),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&bin_path)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("stat headscale: {e}"),
                )
            })?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&bin_path, perms).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("chmod headscale: {e}"),
            )
        })?;
    }
    Ok(bin_path)
}

/// Write the headscale systemd unit and `enable --now` it. Best-effort: returns
/// `false` on non-systemd hosts (tests, Mac) so callers can report
/// files-written-without-start instead of failing. Shared by deploy + bootstrap.
fn write_and_start_headscale_unit(bin_path: &std::path::Path, dir: &std::path::Path) -> bool {
    let unit = format!(
        "[Unit]\n\
         Description=Headscale coordinator (yah-managed)\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={bin} serve --config {dir}/config.yaml\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        bin = bin_path.display(),
        dir = dir.display()
    );
    let _ = std::fs::write("/etc/systemd/system/headscale.service", &unit);
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();
    std::process::Command::new("systemctl")
        .args(["enable", "--now", "headscale"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Generate the headscale config for a SELF-BOOTSTRAPPED first node. Unlike
/// [`generate_remote_headscale_config`] (which configures a localhost-only
/// coordinator fronted by a proxy), this listens publicly on :443 and
/// terminates its own TLS via Let's Encrypt (HTTP-01 on :80) so the noise
/// protocol reaches it directly — no CF proxy. Headscale creates the keys + DB.
fn generate_bootstrap_headscale_config(
    server_url: &str,
    le_hostname: &str,
    headscale_dir: &std::path::Path,
) -> String {
    let private_key = headscale_dir.join("private.key").display().to_string();
    let noise_key = headscale_dir
        .join("noise_private.key")
        .display()
        .to_string();
    let db_path = headscale_dir.join("headscale.db").display().to_string();
    let socket_path = headscale_dir.join("headscale.sock").display().to_string();
    let acl_path = headscale_dir.join("acls.yaml").display().to_string();
    let tls_cache = headscale_dir.join("acme-cache").display().to_string();

    format!(
        "---\n\
         server_url: {server_url}\n\
         listen_addr: 0.0.0.0:443\n\
         grpc_listen_addr: 127.0.0.1:50443\n\
         metrics_listen_addr: 127.0.0.1:9090\n\
         tls_letsencrypt_hostname: {le_hostname}\n\
         tls_letsencrypt_cache_dir: {tls_cache}\n\
         tls_letsencrypt_challenge_type: HTTP-01\n\
         tls_letsencrypt_listen: \":80\"\n\
         private_key_path: {private_key}\n\
         noise:\n\
         \x20\x20private_key_path: {noise_key}\n\
         database:\n\
         \x20\x20type: sqlite\n\
         \x20\x20sqlite:\n\
         \x20\x20\x20\x20path: {db_path}\n\
         unix_socket: {socket_path}\n\
         unix_socket_permission: \"0770\"\n\
         dns:\n\
         \x20\x20magic_dns: true\n\
         \x20\x20base_domain: mesh.internal\n\
         \x20\x20nameservers:\n\
         \x20\x20\x20\x20global:\n\
         \x20\x20\x20\x20\x20\x20- 1.1.1.1\n\
         \x20\x20\x20\x20\x20\x20- 8.8.8.8\n\
         log:\n\
         \x20\x20level: info\n\
         prefixes:\n\
         \x20\x20v4: 100.64.0.0/10\n\
         \x20\x20v6: fd7a:115c:a1e0::/48\n\
         \x20\x20allocation: sequential\n\
         policy:\n\
         \x20\x20mode: file\n\
         \x20\x20path: {acl_path}\n\
         derp:\n\
         \x20\x20server:\n\
         \x20\x20\x20\x20enabled: false\n\
         \x20\x20urls:\n\
         \x20\x20\x20\x20- https://controlplane.tailscale.com/derpmap/default\n\
         \x20\x20auto_update_enabled: false\n\
         \x20\x20update_frequency: 24h\n"
    )
}

/// Return the GitHub download URL for headscale on Linux amd64.
/// Yubaba runs on Hetzner Linux x86_64 servers in Phase 1.
fn headscale_linux_download_url(version: &str) -> String {
    format!(
        "https://github.com/juanfont/headscale/releases/download/v{version}/headscale_{version}_linux_amd64"
    )
}

// ── Cloudflare tunnel registration (R091-F7) ──────────────────────────────────

/// POST a tunnel route registration to the cloudflared API (or mock).
///
/// Called by the `/workloads/deploy` handler when a `WorkloadSpec` has
/// `expose.public` set and `ServerState::cloudflared_url` is configured.
///
/// On failure, the caller is expected to tear down the just-deployed workload
/// and return an error response — see the deploy handler for the full sequence.
async fn register_cloudflare_tunnel(
    cf_url: &str,
    hostname: &str,
    service_url: &str,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("building reqwest client for cloudflared")?;
    let url = format!("{cf_url}/v1/tunnels");
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "hostname": hostname,
            "service_url": service_url,
        }))
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("cloudflared POST {url} returned {status}: {body}");
    }
    Ok(())
}

// ── Headscale preauth-key registration (R091-F8) ─────────────────────────────

/// POST a preauth-key creation request to the Headscale API (or mock).
///
/// Called by the `/workloads/deploy` handler when a `WorkloadSpec` has
/// `expose.operator` set, `headscale_url` is configured, and
/// `YAH_OPERATOR_BRIDGE_MODE` is not `"mesh-peer"`.
///
/// Returns the preauth key token on success. On failure, the caller tears
/// down the just-deployed workload.
async fn register_headscale_preauthkey(
    hs_url: &str,
    tailscale_tag: &str,
) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("building reqwest client for headscale")?;
    let url = format!("{hs_url}/api/v1/preauthkey");
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "user": "yah-cluster",
            "acl_tags": [tailscale_tag],
            "reusable": false,
            "ephemeral": true,
        }))
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("headscale POST {url} returned {status}: {body}");
    }
    let body: serde_json::Value = resp.json().await.context("parsing headscale response")?;
    let key = body["preAuthKey"]["key"]
        .as_str()
        .context("headscale response missing preAuthKey.key")?
        .to_string();
    Ok(key)
}

// ── Raft RPC handlers (R040-F20) ─────────────────────────────────────────────

/// Helper: extract raft node or return 503.
macro_rules! require_raft {
    ($state:expr) => {
        match $state.raft.as_ref() {
            Some(r) => r,
            None => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "raft not configured (Phase 2 only — start with --raft-node-id)".to_string(),
                ))
            }
        }
    };
}

// The raft-internal RPC handlers serialize the full `Result<Resp, RaftError>`
// (openraft 0.10 convention) — the peer's `RaftNetworkV2` client decodes exactly
// that. `require_raft!` still short-circuits with a 503 when raft is unconfigured.
type RaftRpcReply<Resp> = Result<
    Json<Result<Resp, openraft::error::RaftError<raft::YubabaRaftConfig>>>,
    (StatusCode, String),
>;

async fn raft_append_entries(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<openraft::raft::AppendEntriesRequest<raft::YubabaRaftConfig>>,
) -> RaftRpcReply<openraft::raft::AppendEntriesResponse<raft::YubabaRaftConfig>> {
    let raft = require_raft!(s);
    Ok(Json(raft.append_entries(req).await))
}

async fn raft_vote(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<openraft::raft::VoteRequest<raft::YubabaRaftConfig>>,
) -> RaftRpcReply<openraft::raft::VoteResponse<raft::YubabaRaftConfig>> {
    let raft = require_raft!(s);
    Ok(Json(raft.vote(req).await))
}

/// `POST /raft/snapshot` — receive a full snapshot (openraft 0.10 streaming
/// snapshot). The leader's `RaftNetworkV2::full_snapshot` POSTs the whole
/// `(vote, meta, bytes)` payload here in one shot (yubaba snapshots are KB
/// scale); we rebuild the [`Snapshot`](openraft::Snapshot) and install it.
async fn raft_snapshot(
    State(s): State<Arc<ServerState>>,
    Json((vote, meta, data)): Json<(
        openraft::type_config::alias::VoteOf<raft::YubabaRaftConfig>,
        openraft::type_config::alias::SnapshotMetaOf<raft::YubabaRaftConfig>,
        Vec<u8>,
    )>,
) -> RaftRpcReply<openraft::raft::SnapshotResponse<raft::YubabaRaftConfig>> {
    let raft = require_raft!(s);
    let snapshot = openraft::Snapshot {
        meta,
        snapshot: std::io::Cursor::new(data),
    };
    Ok(Json(
        raft.install_full_snapshot(vote, snapshot)
            .await
            .map_err(openraft::error::RaftError::Fatal),
    ))
}

/// `POST /raft/transfer-leader-msg` — receive an openraft TransferLeader message
/// (R608-B11). The sitting leader's `RaftNetworkV2::transfer_leader` posts here;
/// `handle_transfer_leader` lets this node campaign at once — the openraft-native
/// handoff that bypasses the follower leader-lease (which is why the old
/// force-elect workaround could not unseat a healthy leader).
async fn raft_transfer_leader_msg(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<openraft::raft::TransferLeaderRequest<raft::YubabaRaftConfig>>,
) -> RaftRpcReply<openraft::raft::TransferLeaderResponse<raft::YubabaRaftConfig>> {
    let raft = require_raft!(s);
    Ok(Json(
        raft.handle_transfer_leader(req)
            .await
            .map_err(openraft::error::RaftError::Fatal),
    ))
}

/// `GET /raft/status` — human-readable cluster state.
async fn raft_status(
    State(s): State<Arc<ServerState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raft = require_raft!(s);
    let metrics = raft.metrics().borrow_watched().clone();
    Ok(Json(serde_json::json!({
        "node_id": metrics.id,
        "state": format!("{:?}", metrics.state),
        "current_leader": metrics.current_leader,
        "current_term": metrics.current_term,
        "last_log_index": metrics.last_log_index,
        "last_applied": metrics.last_applied,
        "membership_config": metrics.membership_config,
    })))
}

/// `POST /raft/initialize` request — founding membership for a fresh cluster.
#[derive(Deserialize)]
struct RaftInitializeRequest {
    /// node_id → mesh address (`host:port`) of every founding voter,
    /// including the node receiving this call.
    members: std::collections::BTreeMap<raft::YubabaNodeId, String>,
}

/// `POST /raft/initialize` — one-time cluster bootstrap (R570-F1).
///
/// Writes the initial membership log entry and kicks off the first leader
/// election. Call it once, on one founding voter, after every member is up
/// with `--raft-node-id`; the others receive membership via AppendEntries.
/// Re-calling on an already-initialized node returns success without
/// touching state, so operator retries are safe.
async fn raft_initialize(
    State(s): State<Arc<ServerState>>,
    Json(body): Json<RaftInitializeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raft = require_raft!(s);
    let members: std::collections::BTreeMap<raft::YubabaNodeId, openraft::BasicNode> = body
        .members
        .into_iter()
        .map(|(id, addr)| (id, openraft::BasicNode { addr }))
        .collect();
    match raft.initialize(members).await {
        Ok(()) => Ok(Json(serde_json::json!({ "initialized": true }))),
        // NotAllowed = this node already has vote/log state, i.e. the cluster
        // is (or was) bootstrapped — idempotent success.
        Err(openraft::error::RaftError::APIError(
            openraft::error::InitializeError::NotAllowed(_),
        )) => Ok(Json(
            serde_json::json!({ "initialized": false, "already_initialized": true }),
        )),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// `POST /raft/write` request — write a [`raft::YubabaRequest`] through consensus.
#[derive(Deserialize)]
struct RaftWriteRequest {
    request: raft::YubabaRequest,
}

/// `POST /raft/write` — apply a `YubabaRequest` to the cluster state.
///
/// Must be called on the leader; followers return a redirect hint in the
/// error body (`"ForwardToLeader"` with `leader_id` + `leader_node`).
async fn raft_write(
    State(s): State<Arc<ServerState>>,
    Json(body): Json<RaftWriteRequest>,
) -> Result<Json<raft::YubabaResponse>, (StatusCode, String)> {
    let raft = require_raft!(s);
    let resp = raft
        .client_write(body.request)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(resp.data))
}

/// `POST /raft/transfer-leader` request body (operator/rollout-facing).
#[derive(Deserialize)]
struct TransferLeaderBody {
    /// Raft node id to hand leadership to. Must be a current voter.
    to: raft::YubabaNodeId,
}

/// How long [`raft_transfer_leader`] waits for leadership to actually move to
/// the target before giving up. Covers a couple of election cycles
/// (`election_timeout_max` is 3s — see [`raft::open`]).
const TRANSFER_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Outcome of validating a transfer-leader request against the receiving node's
/// current raft state. Pure decision, split out from [`raft_transfer_leader`]
/// so the preconditions are unit-testable without a live cluster.
#[derive(Debug, PartialEq, Eq)]
enum TransferPlan {
    /// `to` already leads — nothing to do; reply success (idempotent).
    NoopAlreadyLeader,
    /// Preconditions met — ask openraft to transfer leadership to `to`.
    Proceed,
    /// Request cannot proceed; reply with this status + message.
    Reject(StatusCode, String),
}

/// Decide whether a transfer-leader to `to` can proceed, given a snapshot of the
/// receiving node's raft metrics.
///
/// openraft 0.10's `Trigger::transfer_leader` does the actual handoff (a
/// TimeoutNow to the target that bypasses the follower leader-lease and keeps
/// membership — hence quorum — intact). These are the guards around it:
/// - idempotent if `to` already leads (also covers `to == my_id` on the leader);
/// - only the leader can drive a handoff (a stale caller hitting a follower gets
///   a 409, never a silent success);
/// - `to` must be a current voter (never hand leadership to a learner/unknown).
///
/// Catch-up is deliberately NOT gated here: openraft's transfer_leader targets a
/// sufficiently up-to-date node, and if leadership fails to move the confirm
/// timeout in [`raft_transfer_leader`] surfaces it — so there is no lag check.
fn plan_transfer(
    my_id: raft::YubabaNodeId,
    current_leader: Option<raft::YubabaNodeId>,
    to: raft::YubabaNodeId,
    is_voter: bool,
) -> TransferPlan {
    if current_leader == Some(to) {
        return TransferPlan::NoopAlreadyLeader;
    }
    if current_leader != Some(my_id) {
        return TransferPlan::Reject(
            StatusCode::CONFLICT,
            format!(
                "transfer-leader must be called on the current leader; this node ({my_id}) \
                 is not the leader (current_leader={current_leader:?})"
            ),
        );
    }
    if !is_voter {
        return TransferPlan::Reject(
            StatusCode::BAD_REQUEST,
            format!("transfer-leader target {to} is not a voter in the current membership"),
        );
    }
    TransferPlan::Proceed
}

/// `POST /raft/transfer-leader` — perform a controlled leadership handoff to `to`.
///
/// openraft 0.10 exposes the real primitive (R608-B11): after validating
/// ([`plan_transfer`]) that this node is the leader and `to` is a voter, we call
/// `Trigger::transfer_leader(to)`. openraft sends the target a TimeoutNow so it
/// campaigns immediately — bypassing the follower leader-lease that made the
/// earlier 0.9 force-elect workaround unable to unseat a healthy leader — while
/// **never touching membership**, so the cluster keeps every voter (no quorum
/// reduction) throughout. We then poll until leadership actually lands on `to`.
///
/// Idempotent: if `to` already leads, returns 202 without acting. Returns a
/// clear error (never a silent success) if leadership does not move within
/// [`TRANSFER_CONFIRM_TIMEOUT`], so the rollout executor never drains a node that
/// is still the leader.
async fn raft_transfer_leader(
    State(s): State<Arc<ServerState>>,
    Json(body): Json<TransferLeaderBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    let raft = require_raft!(s);
    let to = body.to;

    // Snapshot metrics once; clone so no borrow is held across an await point.
    let m = raft.metrics().borrow_watched().clone();
    let is_voter = m
        .membership_config
        .membership()
        .voter_ids()
        .any(|v| v == to);

    match plan_transfer(m.id, m.current_leader, to, is_voter) {
        TransferPlan::NoopAlreadyLeader => return Ok(StatusCode::ACCEPTED),
        TransferPlan::Reject(code, msg) => return Err((code, msg)),
        TransferPlan::Proceed => {}
    }

    // Hand off: openraft routes a TimeoutNow to `to` via RaftNetworkV2 and steps
    // this leader down. Membership is untouched, so quorum tolerance is retained.
    raft.trigger().transfer_leader(to).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("transfer-leader: {e}"),
        )
    })?;

    // Confirm leadership actually moved to `to`. A silent success here would let
    // the rollout proceed to drain a node that is still leader.
    let deadline = std::time::Instant::now() + TRANSFER_CONFIRM_TIMEOUT;
    loop {
        if raft.metrics().borrow_watched().current_leader == Some(to) {
            return Ok(StatusCode::ACCEPTED);
        }
        if std::time::Instant::now() >= deadline {
            let seen = raft.metrics().borrow_watched().current_leader;
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                format!(
                    "transfer-leader: leadership did not move to {to} within \
                     {TRANSFER_CONFIRM_TIMEOUT:?} (current_leader={seen:?}); \
                     the target may be lagging — retry"
                ),
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

// ── Rollout API (R278-F1) ─────────────────────────────────────────────────────

/// `POST /v1/rollouts` request body.
#[derive(Deserialize, Debug)]
struct CreateRolloutBody {
    /// Artifact URI, e.g. `"release:yah-marketing@v1.2.3"`.
    artifact: String,
    /// Inline rollout policy. The `policy_ref` (path in the release bundle)
    /// form will be added once artifact resolution (R278 v2) is wired.
    policy: workload_spec::rollout::RolloutPolicy,
    /// Opaque trigger metadata (source, run_id, sha, etc.).
    #[serde(default)]
    trigger: serde_json::Value,
}

/// `POST /self-update` request body (R608-F10). Mirrors
/// `cloud_client::SelfUpdateRequest` by JSON shape — carries only
/// manifest-derived values so the node builds its own trusted install script.
#[derive(serde::Deserialize)]
struct SelfUpdateBody {
    version: String,
    url: String,
    sha256: String,
    #[serde(default)]
    operator_signature: Option<String>,
}

/// Build the `systemd-run` argv (after the program name) that runs the install
/// `script` as a **detached, transient** system unit named `unit`.
///
/// Pure + testable (systemd is unavailable in CI). The unit runs OUTSIDE
/// yubaba's mount sandbox — yubaba.service is `ProtectSystem=strict` with a
/// narrow `ReadWritePaths`, so the yubaba process itself cannot write
/// `/usr/local/bin` or `/etc/systemd/system`. Because the unit is a child of
/// PID1 (not of yubaba.service), the `systemctl restart yubaba.service` the
/// script ends with does not kill the installer. `--collect` reaps the unit
/// after it exits; `Type=oneshot` makes systemd-run return once the job is
/// registered (not when the install finishes), so the handler can 202 promptly.
fn self_update_systemd_argv(unit: &str, script: &str) -> Vec<String> {
    vec![
        format!("--unit={unit}"),
        "--collect".to_string(),
        "--property=Type=oneshot".to_string(),
        "--".to_string(),
        "bash".to_string(),
        "-c".to_string(),
        script.to_string(),
    ]
}

/// `POST /self-update` (R608-F10) — mesh-native, SSH-free control-plane roll.
///
/// The orchestrator (or another mesh peer) POSTs a signed release ref; the node
/// fetches + verifies it and self-installs the yubaba+kamaji pair. This is the
/// transport twin of the SSH apply (`app/yah/cli/src/rollout/apply.rs`): both
/// run the *same* `workload_spec::control_plane_install::build_install_script`,
/// the difference is only where it executes. Returns 202 with the transient
/// unit name; the orchestrator polls `GET /health` for the new version.
async fn self_update(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<SelfUpdateBody>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // A remote-triggered self-binary-swap is high blast radius — gate it on raft
    // quorum exactly like a workload deploy (rejects when no leader is elected).
    if let Some(err_resp) = quorum_write_guard(&s) {
        return err_resp;
    }

    if req.operator_signature.is_none() {
        // Same posture as deploy_workload_spec: warn now, enforce with R044.
        tracing::warn!(
            version = %req.version,
            "self-update received without operator signature \
             (unsigned accepted until R044 key vault enforces rejection)"
        );
    }

    // Same trusted builder the SSH path uses; sudo=false because the transient
    // unit runs as root. Integrity is the manifest sha256 the script verifies.
    let script = workload_spec::control_plane_install::build_install_script(
        &req.version,
        &req.url,
        &req.sha256,
        false,
    );

    let unit = format!(
        "yah-self-update-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    let argv = self_update_systemd_argv(&unit, &script);

    tracing::info!(version = %req.version, unit = %unit, "self-update: launching detached install unit");
    // std::process (yubaba's tokio has no `process` feature) in spawn_blocking:
    // systemd-run returns once the transient unit is registered with PID1, so
    // this is a quick call — the install + restart happen in the detached unit.
    let exec = tokio::task::spawn_blocking(move || {
        std::process::Command::new("systemd-run")
            .args(&argv)
            .output()
    })
    .await;

    match exec {
        Ok(Ok(out)) if out.status.success() => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "status": "accepted",
                "version": req.version,
                "unit": unit,
            })),
        )
            .into_response(),
        Ok(Ok(out)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": "error",
                "version": req.version,
                "error": format!(
                    "systemd-run failed ({}): {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            })),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": "error",
                "version": req.version,
                "error": format!("spawning systemd-run: {e}"),
            })),
        )
            .into_response(),
        Err(join) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": "error",
                "version": req.version,
                "error": format!("self-update worker join failed: {join}"),
            })),
        )
            .into_response(),
    }
}

/// `POST /v1/rollouts` — accept a new rollout request.
///
/// Validates the policy (linear-only for v1), creates a `RolloutRecord`,
/// spawns the engine as a background task, and returns 202 immediately.
///
/// Gate evaluation uses the Prometheus URL configured on the server
/// (`YAH_PROMETHEUS_URL` or `with_prometheus_url`). When no URL is set the
/// engine runs in stub mode and all gates auto-pass.
async fn create_rollout(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<CreateRolloutBody>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use workload_spec::rollout::RolloutStrategy;

    if req.policy.strategy != RolloutStrategy::Linear {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "only strategy='linear' is supported in yubaba v1",
                "hint": "canary-fraction is planned for v2"
            })),
        )
            .into_response();
    }

    let rollout_id = {
        let mut store = s.rollout_store.lock().unwrap();
        store.create(req.artifact.clone(), req.policy.clone(), req.trigger)
    };

    // Spawn the rollout engine as a background task.
    let engine = rollout::engine::RolloutEngine::new(
        rollout_id.clone(),
        req.artifact,
        req.policy,
        Arc::clone(&s.rollout_store),
        s.prometheus_url.clone(),
    );
    tokio::spawn(engine.run());

    tracing::info!(rollout_id = %rollout_id, "rollout accepted");

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "rollout_id": rollout_id,
            "status": "pending",
        })),
    )
        .into_response()
}

/// `GET /v1/rollouts` — list all rollouts on this yubaba node, newest first.
async fn list_rollouts(State(s): State<Arc<ServerState>>) -> Json<serde_json::Value> {
    let store = s.rollout_store.lock().unwrap();
    let records: Vec<serde_json::Value> = store
        .list()
        .into_iter()
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();
    Json(serde_json::json!({ "rollouts": records }))
}

/// `GET /v1/rollouts/{id}` — fetch a single rollout by ID.
async fn get_rollout(
    State(s): State<Arc<ServerState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    match rollout::snapshot_record(&s.rollout_store, &id) {
        Some(r) => {
            Json(serde_json::to_value(&r).unwrap_or(serde_json::Value::Null)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("rollout '{id}' not found") })),
        )
            .into_response(),
    }
}

/// `POST /v1/rollouts/{id}/override` request body.
#[derive(Deserialize, Debug)]
struct OverrideRolloutBody {
    action: rollout::OverrideAction,
    /// Human-readable identifier of the operator performing the override.
    #[serde(default = "unknown_operator")]
    by: String,
}

fn unknown_operator() -> String {
    "unknown".to_string()
}

/// `POST /v1/rollouts/{id}/override` — force-promote or force-rollback.
///
/// Overrides are logged with the operator ID. The engine continues running
/// after a promote; after a rollback the engine's next gate check will see
/// the `Overridden` status and can exit gracefully.
async fn override_rollout(
    State(s): State<Arc<ServerState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<OverrideRolloutBody>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let action_str = match req.action {
        rollout::OverrideAction::Promote => "promote",
        rollout::OverrideAction::Rollback => "rollback",
    };

    {
        let mut store = s.rollout_store.lock().unwrap();
        if store.get(&id).is_none() {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("rollout '{id}' not found") })),
            )
                .into_response();
        }
        store.update_status(
            &id,
            rollout::RolloutStatus::Overridden {
                action: action_str.to_string(),
                by: req.by.clone(),
            },
        );
    }

    tracing::info!(rollout_id = %id, action = action_str, by = %req.by, "rollout overridden by operator");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "rollout_id": id,
            "action": action_str,
            "by": req.by,
        })),
    )
        .into_response()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const SAMPLE_PUBKEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDXJ8MNVqHbLfqVNvKkz9Cp9TQyOjP3OEajjqJD2c95P";
    const SAMPLE_FP: &str = "SHA256:HAo2DsB7cN+GmrEbJ8SR305rJagwQhgP2dNyUemUBbU";

    fn fresh_state() -> (tempfile::TempDir, Arc<ServerState>) {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("identity.json");
        let state = Arc::new(ServerState::load(path).unwrap());
        (tmp, state)
    }

    /// Mint a fresh, valid admission credential from the state's own registry
    /// — the happy-path bootstrap token a caller presents on
    /// `/register-hostkey` (R593-F8). Single-use, so a test doing N POSTs
    /// mints N times.
    fn mint_admission_token(state: &ServerState) -> String {
        state
            .bootstrap_tokens
            .mint(
                unix_now_secs(),
                identity::bootstrap::DEFAULT_BOOTSTRAP_TTL_SECONDS,
                None,
            )
            .token
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// `/node` answers on every platform this is built for, with the OTel
    /// semantic-convention keys the desktop Infra tab and peer yubabas read.
    #[tokio::test]
    async fn node_reports_specs_with_semconv_keys() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let resp = app
            .oneshot(Request::get("/node").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;

        assert_eq!(body["schema_version"], node::NODE_SCHEMA_VERSION);
        // Repo vocabulary (comparable to MachineRecord::arch) and OTel
        // vocabulary are both present and are NOT the same string on the
        // architectures we actually run.
        assert_eq!(body["yah.arch"], std::env::consts::ARCH);
        assert_eq!(body["host.arch"], node::otel_arch(std::env::consts::ARCH));
        assert!(body["os.type"].is_string());
        assert!(body["yah.collector"].is_string());

        // On a supported platform the measured allocatable numbers — the whole
        // reason this endpoint exists — must be real.
        if !matches!(node::Collector::detect(), node::Collector::Unsupported) {
            assert!(
                body["yah.allocatable.memory_mb"].as_u64().unwrap_or(0) > 0,
                "{body}"
            );
            assert!(
                body["yah.allocatable.cpu_millis"].as_u64().unwrap_or(0) > 0,
                "{body}"
            );
        }
    }

    /// With nothing deployed, committed capacity is zero — not absent, not
    /// stale. `available = allocatable − committed` must be computable from a
    /// fresh node.
    #[tokio::test]
    async fn node_usage_reports_zero_committed_when_idle() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::get("/node/usage?window_ms=50")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;

        assert_eq!(body["yah.workloads.count"], 0);
        assert_eq!(body["yah.committed.memory_mb"], 0);
        assert_eq!(body["yah.committed.cpu_millis"], 0);
        assert!(body["yah.cpu.source"].is_string());
    }

    /// Committed totals are the sum of admitted workload requests. The
    /// registry is populated by the deploy handler; driving it directly here
    /// keeps the assertion on the reporting path rather than on a full
    /// containerd deploy.
    #[tokio::test]
    async fn node_usage_sums_committed_workload_requests() {
        let (_tmp, state) = fresh_state();
        {
            let mut reg = state.workload_resources.lock().unwrap();
            reg.insert(
                "api.pdx".into(),
                node::WorkloadResources {
                    memory_mb: 512,
                    cpu_millis: 250,
                },
            );
            reg.insert(
                "worker.pdx".into(),
                node::WorkloadResources {
                    memory_mb: 1024,
                    cpu_millis: 500,
                },
            );
        }
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::get("/node/usage?window_ms=50")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["yah.workloads.count"], 2);
        assert_eq!(body["yah.committed.memory_mb"], 1536);
        assert_eq!(body["yah.committed.cpu_millis"], 750);
    }

    /// `GET /workloads` carries each workload's declared resource request.
    /// This is the field the scheduler's missing bin-packer needs; without it
    /// `committed` can only ever be a node-wide total.
    #[tokio::test]
    async fn workloads_carry_resource_requests() {
        let (_tmp, state) = fresh_state();
        state.workload_resources.lock().unwrap().insert(
            "api.pdx".into(),
            node::WorkloadResources {
                memory_mb: 512,
                cpu_millis: 250,
            },
        );
        let app = build_router(state);

        let resp = app
            .oneshot(Request::get("/workloads").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // No runtime and no kamaji client in the test state, so this is the
        // documented stub path — an empty list, still well-formed.
        assert_eq!(
            resp.headers().get("x-workload-source").unwrap(),
            "stub",
            "enrichment must not change which backend the header reports"
        );
        let body = body_json(resp).await;
        assert_eq!(body["workloads"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["name"], "yubaba");
        // R276-F4: single-node mode when no raft is configured (the test state
        // never wires a raft node).
        assert_eq!(body["mode"], "single-node");
        // R569-B2: a node that auto-generated its hostkey reports it, so a
        // fleet probe can distinguish a real member from an identity-less one
        // that still answers `status: "ok"`.
        assert_eq!(body["hostkey"], "present");
    }

    #[tokio::test]
    async fn health_reports_absent_hostkey_when_identity_generation_failed() {
        // The rootless-macOS shape (R569-B2): generation failed, ServerState
        // logged and carried on, so the node serves with no identity at all.
        // `status` stays "ok" — that is the point; `hostkey` is what tells a
        // probe the node cannot join a mesh or be admitted.
        let (_tmp, state) = fresh_state();
        let mut inner = std::sync::Arc::try_unwrap(state).expect("sole owner");
        inner.state.get_mut().unwrap().identity = None;
        let app = build_router(std::sync::Arc::new(inner));

        let resp = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["hostkey"], "absent");

        // And the paired symptom the ticket names, on the same state.
        let resp = app
            .oneshot(Request::get("/identity").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn hostkey_dir_falls_back_to_cwd_for_a_bare_state_filename() {
        // R569-B2: `Path::parent` yields Some("") — not None — for a bare
        // filename, so the old `.unwrap_or(".")` never fired and an empty path
        // reached create_dir_all, which fails ENOENT and surfaces as an
        // unexplained "hostkey generation failed".
        assert_eq!(
            hostkey_dir_for(std::path::Path::new("identity.json")),
            PathBuf::from(".")
        );
        assert_eq!(
            hostkey_dir_for(std::path::Path::new("/Users/yah/.yah/yubaba/identity.json")),
            PathBuf::from("/Users/yah/.yah/yubaba")
        );
        assert_eq!(
            hostkey_dir_for(std::path::Path::new("yubaba/identity.json")),
            PathBuf::from("yubaba")
        );
    }

    #[test]
    fn load_generates_an_identity_when_the_state_dir_does_not_exist() {
        // The rootless first-boot shape end-to-end: nothing pre-created the
        // state dir (no systemd `StateDirectory=`), so `ServerState::load`
        // itself has to, and must come up WITH an identity rather than
        // logging and serving a 404 /identity.
        let tmp = tempfile::TempDir::new().unwrap();
        let state_path = tmp.path().join("Users/yah/.yah/yubaba/identity.json");
        assert!(!state_path.parent().unwrap().exists());

        let state = ServerState::load(state_path.clone()).expect("load should succeed");
        assert!(
            state.snapshot().identity.is_some(),
            "a missing state dir must be created, not reported as a failure"
        );
        assert!(state_path.exists(), "state file should be persisted");
    }

    #[tokio::test]
    async fn identity_auto_generates_on_startup() {
        // R092-F8: yubaba generates its own Ed25519 hostkey on first boot;
        // /identity returns 200 immediately without a register-hostkey call.
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let resp = app
            .oneshot(Request::get("/identity").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["algorithm"], "ssh-ed25519");
        let fp = body["hostkey_fingerprint"].as_str().unwrap();
        assert!(
            fp.starts_with("SHA256:"),
            "fingerprint should start with SHA256:, got: {fp}"
        );
        // R593-T2: /identity now also reports the mshr NodeId (hex-encoded
        // Ed25519 public key) — W268 §Verification.
        let node_id = body["node_id"].as_str().unwrap();
        assert_eq!(
            node_id.len(),
            64,
            "hex-encoded 32-byte NodeId should be 64 chars, got: {node_id}"
        );
        assert!(
            node_id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "node_id should be lowercase hex, got: {node_id}"
        );
    }

    #[tokio::test]
    async fn register_then_identity_returns_fingerprint() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state.clone());

        // Register (with a valid single-use admission token — R593-F8)
        let req_body = serde_json::json!({ "pubkey": SAMPLE_PUBKEY, "bootstrap_token": mint_admission_token(&state) });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/register-hostkey")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["hostkey_fingerprint"], SAMPLE_FP);

        // Identity now reflects it
        let resp = app
            .oneshot(Request::get("/identity").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["hostkey_fingerprint"], SAMPLE_FP);
        assert_eq!(body["algorithm"], "ssh-ed25519");
    }

    #[tokio::test]
    async fn register_persists_to_state_file() {
        let (tmp, state) = fresh_state();
        let app = build_router(state.clone());

        let req_body = serde_json::json!({ "pubkey": SAMPLE_PUBKEY, "bootstrap_token": mint_admission_token(&state) });
        let resp = app
            .oneshot(
                Request::post("/register-hostkey")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Re-read directly from disk: a fresh ServerState should see the same id.
        let path = tmp.path().join("identity.json");
        let reloaded = ServerState::load(path).unwrap();
        let id = reloaded.snapshot().identity.unwrap();
        assert_eq!(id.hostkey_fingerprint, SAMPLE_FP);
    }

    #[tokio::test]
    async fn register_rejects_garbage_pubkey() {
        let (_tmp, state) = fresh_state();
        // A VALID token so the request clears admission (R593-F8) and reaches
        // pubkey parsing — the point under test is the 400 on bad input, not
        // the 401 on bad auth (which auth-first would otherwise mask).
        let req_body = serde_json::json!({ "pubkey": "not a real key", "bootstrap_token": mint_admission_token(&state) });
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::post("/register-hostkey")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn services_returns_empty_array_when_no_scryer_endpoint_configured() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/services").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body.is_array(), "expected array, got {body}");
        assert_eq!(body.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn services_advertises_scryer_when_endpoint_configured() {
        let (_tmp, state_base) = fresh_state();
        let state = {
            let raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(raw.with_scryer_endpoint("http://100.64.0.7:6543"))
        };
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/services").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let arr = body.as_array().expect("services is an array");
        assert_eq!(arr.len(), 1, "expected single scryer entry, got {body}");
        let entry = &arr[0];
        assert_eq!(entry["name"], "scryer");
        assert_eq!(entry["endpoint"], "http://100.64.0.7:6543");
        assert_eq!(entry["managed_by"], "kamaji");
        let caps = entry["capabilities"]
            .as_array()
            .expect("capabilities array");
        assert!(caps.iter().any(|c| c == "events.query"));
        assert!(caps.iter().any(|c| c == "events.aggregate"));
    }

    #[tokio::test]
    async fn headscale_deploy_writes_files_to_headscale_dir() {
        let (_tmp, state_base) = fresh_state();
        // Override headscale_dir to a temp directory so we don't touch /etc.
        let headscale_tmp = tempfile::TempDir::new().unwrap();
        let state = {
            let state_raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(state_raw.with_headscale_dir(headscale_tmp.path()))
        };

        let app = build_router(state);

        use base64::Engine as _;
        let engine = base64::engine::general_purpose::STANDARD;
        let req_body = serde_json::json!({
            "headscale_version": "0.23.0",
            "db_base64": engine.encode(b"test-db"),
            "private_key_base64": engine.encode(b"test-private-key"),
            "noise_key_base64": engine.encode(b"test-noise-key"),
            "acl_policy": "---\nacls: []",
            "server_url": "https://mesh.example.com"
        });

        let resp = app
            .oneshot(
                Request::post("/headscale/deploy")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // The response may fail at the curl/systemctl step, but files must be written first.
        // We check status is either 200 (files+systemd ok) or 500 (curl/systemd unavailable).
        let status = resp.status();
        assert!(
            status.is_success() || status == StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected status {status}"
        );

        // State files must have been written regardless of systemd availability.
        assert_eq!(
            std::fs::read(headscale_tmp.path().join("headscale.db")).unwrap(),
            b"test-db"
        );
        assert_eq!(
            std::fs::read(headscale_tmp.path().join("private.key")).unwrap(),
            b"test-private-key"
        );
        assert_eq!(
            std::fs::read(headscale_tmp.path().join("noise_private.key")).unwrap(),
            b"test-noise-key"
        );
        assert!(headscale_tmp.path().join("acls.yaml").exists());
        assert!(headscale_tmp.path().join("config.yaml").exists());

        let config = std::fs::read_to_string(headscale_tmp.path().join("config.yaml")).unwrap();
        assert!(config.contains("server_url: https://mesh.example.com"));
    }

    #[tokio::test]
    async fn headscale_deploy_rejects_bad_base64() {
        let (_tmp, state_base) = fresh_state();
        let headscale_tmp = tempfile::TempDir::new().unwrap();
        let state = {
            let state_raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(state_raw.with_headscale_dir(headscale_tmp.path()))
        };
        let app = build_router(state);

        let req_body = serde_json::json!({
            "headscale_version": "0.23.0",
            "db_base64": "!!!not-valid-base64!!!",
            "private_key_base64": "also-bad",
            "noise_key_base64": "bad",
            "acl_policy": "",
            "server_url": "https://mesh.example.com"
        });

        let resp = app
            .oneshot(
                Request::post("/headscale/deploy")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn headscale_health_returns_json() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::get("/headscale/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        // On a dev machine headscale is not running — check the field exists and is a string.
        assert!(body["headscale"].is_string());
        assert!(body["api_reachable"].is_boolean());
    }

    #[test]
    fn letsencrypt_hostname_strips_scheme_and_port() {
        assert_eq!(
            letsencrypt_hostname("https://cloud.mesh.yah.dev").as_deref(),
            Some("cloud.mesh.yah.dev")
        );
        assert_eq!(
            letsencrypt_hostname("https://cloud.mesh.yah.dev:443/path").as_deref(),
            Some("cloud.mesh.yah.dev")
        );
        assert_eq!(
            letsencrypt_hostname("cloud.mesh.yah.dev").as_deref(),
            Some("cloud.mesh.yah.dev")
        );
        assert_eq!(letsencrypt_hostname("https://").as_deref(), None);
    }

    #[test]
    fn bootstrap_config_has_letsencrypt_and_public_listen() {
        let dir = std::path::Path::new("/etc/yah-cloud/headscale");
        let cfg = generate_bootstrap_headscale_config(
            "https://cloud.mesh.yah.dev",
            "cloud.mesh.yah.dev",
            dir,
        );
        // Public listener + self-terminated TLS (no CF proxy in the noise path).
        assert!(cfg.contains("listen_addr: 0.0.0.0:443"));
        assert!(cfg.contains("tls_letsencrypt_hostname: cloud.mesh.yah.dev"));
        assert!(cfg.contains("tls_letsencrypt_challenge_type: HTTP-01"));
        assert!(cfg.contains("server_url: https://cloud.mesh.yah.dev"));
        // Keys + DB live under the headscale dir; headscale creates them itself.
        assert!(cfg.contains("/etc/yah-cloud/headscale/private.key"));
        assert!(cfg.contains("/etc/yah-cloud/headscale/headscale.db"));
        // ACL policy is referenced by path (file mode).
        assert!(cfg.contains("mode: file"));
    }

    #[tokio::test]
    async fn headscale_bootstrap_writes_config_before_start() {
        let (_tmp, state_base) = fresh_state();
        let headscale_tmp = tempfile::TempDir::new().unwrap();
        let state = {
            let state_raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(state_raw.with_headscale_dir(headscale_tmp.path()))
        };
        let app = build_router(state);

        let req_body = serde_json::json!({ "server_url": "https://cloud.mesh.yah.dev" });
        let resp = app
            .oneshot(
                Request::post("/headscale/bootstrap")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // 200 (full bootstrap) or 500 (download/systemd unavailable in CI) — but
        // config + ACL must be written first either way.
        let status = resp.status();
        assert!(
            status.is_success() || status == StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected status {status}"
        );
        assert!(headscale_tmp.path().join("acls.yaml").exists());
        let cfg = std::fs::read_to_string(headscale_tmp.path().join("config.yaml")).unwrap();
        assert!(cfg.contains("server_url: https://cloud.mesh.yah.dev"));
        assert!(cfg.contains("tls_letsencrypt_hostname: cloud.mesh.yah.dev"));
    }

    #[tokio::test]
    async fn headscale_bootstrap_rejects_url_without_host() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);
        let req_body = serde_json::json!({ "server_url": "https://" });
        let resp = app
            .oneshot(
                Request::post("/headscale/bootstrap")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── health (R608-T3) ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn health_returns_ok_without_kamaji_version_when_no_uds() {
        // No constable_client attached (in-process fallback / single-node):
        // /health is 200 and omits kamaji_version entirely (W275 OQ5 / R608-T3).
        let (_tmp, state) = fresh_state();
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        // Absent (not null) when no kamaji UDS is attached — skip_serializing_if.
        assert!(
            body.get("kamaji_version").is_none(),
            "kamaji_version must be omitted under in-process fallback, got {body}"
        );
    }

    // ── compose (R040-F7) ────────────────────────────────────────────────────

    #[tokio::test]
    async fn compose_deploy_writes_files() {
        let (tmp, state_base) = fresh_state();
        let compose_tmp = tempfile::TempDir::new().unwrap();
        let state = {
            let raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(raw.with_compose_dir(compose_tmp.path()))
        };
        let app = build_router(state);

        let req_body = serde_json::json!({
            "compose_yaml": "version: \"3.8\"\nservices:\n  foo:\n    image: foo:v1\n",
            "caddyfile": ":8080 {\n    reverse_proxy foo:8080\n}\n"
        });
        let resp = app
            .oneshot(
                Request::post("/compose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Status may be 200 (systemd started) or 200 with files-written
        // (systemd unavailable on dev machine — both are OK responses).
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "unexpected non-2xx from /compose"
        );

        let body = body_json(resp).await;
        assert!(body["status"].is_string(), "status field missing");

        // Files must be written regardless of systemd outcome.
        let compose = std::fs::read_to_string(compose_tmp.path().join("compose.yml")).unwrap();
        assert!(
            compose.contains("image: foo:v1"),
            "compose.yml content wrong"
        );

        let caddyfile = std::fs::read_to_string(compose_tmp.path().join("Caddyfile")).unwrap();
        assert!(
            caddyfile.contains("reverse_proxy foo:8080"),
            "Caddyfile content wrong"
        );

        // Suppress unused-var warning from the tmpdir used for state_path.
        drop(tmp);
    }

    #[tokio::test]
    async fn compose_deploy_without_caddyfile_ok() {
        let (tmp, state_base) = fresh_state();
        let compose_tmp = tempfile::TempDir::new().unwrap();
        let state = {
            let raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(raw.with_compose_dir(compose_tmp.path()))
        };
        let app = build_router(state);

        let req_body = serde_json::json!({
            "compose_yaml": "version: \"3.8\"\nservices: {}\n",
            "caddyfile": null
        });
        let resp = app
            .oneshot(
                Request::post("/compose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            !compose_tmp.path().join("Caddyfile").exists(),
            "Caddyfile written unexpectedly"
        );
        drop(tmp);
    }

    #[tokio::test]
    async fn services_is_compose_independent_post_r556_f7_t3() {
        // /services no longer shells out to podman compose ps — that path moved
        // to /workloads via kamaji. Even with a compose.yml present, /services
        // is empty until something is explicitly advertised (e.g. scryer).
        let (tmp, state_base) = fresh_state();
        let compose_tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            compose_tmp.path().join("compose.yml"),
            "version: \"3.8\"\nservices: {}\n",
        )
        .unwrap();
        let state = {
            let raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(raw.with_compose_dir(compose_tmp.path()))
        };
        let app = build_router(state);

        let resp = app
            .oneshot(Request::get("/services").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body.is_array(), "expected array, got {body}");
        assert_eq!(body.as_array().unwrap().len(), 0);
        drop(tmp);
    }

    // ── R092-F3: drain + diagnostics ──────────────────────────────────────

    #[tokio::test]
    async fn drain_workloads_returns_empty_until_runtime() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::post("/workloads/drain")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["drained"].as_array().unwrap().len(), 0);
        assert_eq!(body["runtime"], "stub");
    }

    #[tokio::test]
    async fn diagnostics_default_lines_returns_200() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/diagnostics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // /var/log/cloud-init.log won't exist on dev hosts; should still be 200
        // with empty strings rather than 404.
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["lines"], 200);
        assert!(body.get("cloud_init_log").is_some());
    }

    #[test]
    fn read_tail_handles_missing_files_silently() {
        let mut errs = Vec::new();
        let s = read_tail(std::path::Path::new("/no/such/file"), 50, &mut errs);
        assert_eq!(s, "");
        assert!(errs.is_empty(), "missing files must not surface as errors");
    }

    #[test]
    fn read_tail_returns_last_n_lines() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = tmp.path().join("log");
        let body = (1..=100)
            .map(|i| format!("line{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&p, &body).unwrap();
        let mut errs = Vec::new();
        let tail = read_tail(&p, 10, &mut errs);
        assert!(errs.is_empty());
        let lines: Vec<&str> = tail.lines().collect();
        assert_eq!(lines.len(), 10);
        assert_eq!(lines[0], "line91");
        assert_eq!(lines[9], "line100");
    }

    #[test]
    fn read_diagnostics_combines_both_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let a = tmp.path().join("cloud-init.log");
        let b = tmp.path().join("cloud-init-output.log");
        std::fs::write(&a, "alpha\nbeta\ngamma\n").unwrap();
        std::fs::write(&b, "one\ntwo\n").unwrap();
        let body = read_diagnostics(&a, &b, 5);
        assert_eq!(body.lines, 5);
        assert!(body.cloud_init_log.contains("gamma"));
        assert!(body.cloud_init_output_log.contains("two"));
        assert!(body.errors.is_empty());
    }

    // ── Rollout API tests (R278-F1) ───────────────────────────────────────────

    fn minimal_rollout_body() -> serde_json::Value {
        serde_json::json!({
            "artifact": "release:yah-marketing@v1.0.0",
            "policy": {
                "strategy": "linear",
                "window_seconds": 600,
                "gates": [
                    { "metric": "http_5xx_rate", "condition": "< 0.01", "window": "5m" }
                ],
                "steps": [
                    { "mirrors": ["staging"], "gate_window_seconds": 0 },
                    { "mirrors": ["prod"], "gate_window_seconds": 0, "on_failure": "rollback-step" }
                ]
            },
            "trigger": { "source": "test" }
        })
    }

    #[tokio::test]
    async fn create_rollout_returns_202_with_id() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let body = minimal_rollout_body();
        let resp = app
            .oneshot(
                Request::post("/v1/rollouts")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let b = body_json(resp).await;
        assert!(b["rollout_id"].as_str().unwrap().starts_with("rt-"));
        assert_eq!(b["status"], "pending");
    }

    #[test]
    fn self_update_argv_wraps_script_in_a_detached_oneshot_unit() {
        let script = workload_spec::control_plane_install::build_install_script(
            "0.8.20",
            "https://cdn.yah.dev/yubaba/0.8.20/pair.tar.gz",
            "deadbeef",
            false,
        );
        let argv = self_update_systemd_argv("yah-self-update-42", &script);
        // Named transient unit, garbage-collected, oneshot (returns on register).
        assert!(argv.contains(&"--unit=yah-self-update-42".to_string()));
        assert!(argv.contains(&"--collect".to_string()));
        assert!(argv.contains(&"--property=Type=oneshot".to_string()));
        // The install runs under bash -c and the LAST arg is the whole script,
        // passed as a single argv element (never shell-interpolated on the way in).
        let dashc = argv
            .iter()
            .position(|a| a == "-c")
            .expect("bash -c present");
        assert_eq!(argv[dashc - 1], "bash");
        assert_eq!(argv.last().unwrap(), &script);
        // The script the node will run carries the manifest-verified digest.
        assert!(argv.last().unwrap().contains("deadbeef"));
        assert!(argv.last().unwrap().contains("sha256sum -c -"));
    }

    #[tokio::test]
    async fn self_update_route_is_wired_and_parses_the_body() {
        // Proves the route + typed body are wired without depending on systemd
        // (systemd-run is absent in CI/dev, so execution 500s; a missing route
        // would 404 and a bad body 422 — this asserts neither).
        let (_tmp, state) = fresh_state();
        let app = build_router(state);
        let body = serde_json::json!({
            "version": "0.8.20",
            "url": "https://cdn.yah.dev/yubaba/0.8.20/pair.tar.gz",
            "sha256": "deadbeef",
        });
        let resp = app
            .oneshot(
                Request::post("/self-update")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::NOT_FOUND, "route must be wired");
        assert_ne!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "typed body must parse"
        );
    }

    #[tokio::test]
    async fn create_rollout_rejects_non_linear_strategy() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let body = serde_json::json!({
            "artifact": "release:yah-marketing@v1.0.0",
            "policy": {
                "strategy": "canary-fraction",
                "window_seconds": 600,
                "steps": []
            }
        });
        let resp = app
            .oneshot(
                Request::post("/v1/rollouts")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let b = body_json(resp).await;
        assert!(b["error"].as_str().unwrap().contains("linear"));
    }

    #[tokio::test]
    async fn get_rollout_returns_record() {
        let (_tmp, state) = fresh_state();
        let app = build_router(Arc::clone(&state));

        // Create via the handler.
        let body = minimal_rollout_body();
        let create_resp = app
            .clone()
            .oneshot(
                Request::post("/v1/rollouts")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let create_body = body_json(create_resp).await;
        let id = create_body["rollout_id"].as_str().unwrap().to_string();

        // Fetch by ID.
        let get_resp = app
            .oneshot(
                Request::get(format!("/v1/rollouts/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let get_body = body_json(get_resp).await;
        assert_eq!(get_body["rollout_id"], id);
        assert_eq!(get_body["artifact"], "release:yah-marketing@v1.0.0");
    }

    #[tokio::test]
    async fn get_rollout_404_for_unknown_id() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::get("/v1/rollouts/rt-nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn override_rollout_promote_ok() {
        let (_tmp, state) = fresh_state();

        // Create a rollout directly in the store.
        let id = {
            let mut store = state.rollout_store.lock().unwrap();
            store.create(
                "release:test@v1".into(),
                serde_json::from_value(serde_json::json!({
                    "strategy": "linear",
                    "window_seconds": 60,
                    "steps": [{ "mirrors": ["staging"], "gate_window_seconds": 0 }]
                }))
                .unwrap(),
                serde_json::Value::Null,
            )
        };

        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::post(format!("/v1/rollouts/{id}/override"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "action": "promote",
                            "by": "test-operator"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert_eq!(b["action"], "promote");
        assert_eq!(b["by"], "test-operator");
    }

    #[tokio::test]
    async fn list_rollouts_returns_array() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let resp = app
            .oneshot(Request::get("/v1/rollouts").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert!(b["rollouts"].is_array());
    }

    // ── R427-F1: destroy endpoint + ownership revoke ────────────────────────

    /// Spawn an in-process axum server that pretends to be cheers's
    /// `/ownership` surface. Returns `(url, deletes, fail_with)` — `deletes`
    /// records every DELETE id; `fail_with`, when set, makes the next
    /// DELETE return that status code so the failure paths can be exercised.
    async fn spawn_cheers_mock() -> (
        String,
        Arc<tokio::sync::Mutex<Vec<String>>>,
        Arc<tokio::sync::Mutex<Option<StatusCode>>>,
    ) {
        let deletes = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let fail_with = Arc::new(tokio::sync::Mutex::new(None::<StatusCode>));
        let d = deletes.clone();
        let f = fail_with.clone();
        let app = axum::Router::new().route(
            "/ownership/{id}",
            axum::routing::delete(
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let d = d.clone();
                    let f = f.clone();
                    async move {
                        if let Some(status) = *f.lock().await {
                            return status;
                        }
                        d.lock().await.push(id);
                        StatusCode::NO_CONTENT
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), deletes, fail_with)
    }

    fn test_cheers_client(issuer_url: &str) -> Arc<CheersClient> {
        use pasetors::keys::{AsymmetricKeyPair, Generate};
        let kp = AsymmetricKeyPair::<pasetors::version4::V4>::generate().unwrap();
        let cfg = cheers_client::CheersConfig {
            issuer_url: issuer_url.to_string(),
            principal_id: "yubaba-test".into(),
            kid: "yubaba-test-1".into(),
        };
        Arc::new(CheersClient::new(cfg, kp.secret.as_bytes()).unwrap())
    }

    #[tokio::test]
    async fn destroy_without_cheers_succeeds_with_revoked_false() {
        // No cheers client, no runtime — destroy is a no-op-style success.
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::post("/workloads/abc/destroy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert_eq!(b["status"], "destroyed");
        assert_eq!(b["ident"], "abc");
        assert_eq!(b["revoked"], false);
    }

    #[tokio::test]
    async fn destroy_revokes_registered_ownership_row() {
        let (cheers_url, deletes, _fail) = spawn_cheers_mock().await;
        let (_tmp, state_raw) = fresh_state();
        // Replace the Arc so we can pre-populate ownership_rows.
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        s.ownership_rows
            .lock()
            .unwrap()
            .insert("svc-xyz".into(), "01HOWNROW".into());
        let state = Arc::new(s);
        let app = build_router(state.clone());

        let resp = app
            .oneshot(
                Request::post("/workloads/svc-xyz/destroy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert_eq!(b["revoked"], true);
        assert_eq!(b["status"], "destroyed");

        let got = deletes.lock().await.clone();
        assert_eq!(got, vec!["01HOWNROW".to_string()]);

        // Map entry consumed.
        assert!(state
            .ownership_rows
            .lock()
            .unwrap()
            .get("svc-xyz")
            .is_none());
    }

    #[tokio::test]
    async fn destroy_treats_cheers_404_as_already_revoked() {
        let (cheers_url, _deletes, fail) = spawn_cheers_mock().await;
        *fail.lock().await = Some(StatusCode::NOT_FOUND);
        let (_tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        s.ownership_rows
            .lock()
            .unwrap()
            .insert("svc-ghost".into(), "01HGONE".into());
        let state = Arc::new(s);
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::post("/workloads/svc-ghost/destroy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // 404 from cheers is idempotent — destroy still succeeds; revoked
        // reports false because no new revoke landed this turn.
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert_eq!(b["revoked"], false);
        assert_eq!(b["status"], "destroyed");
        assert!(
            b.get("revoke_error").is_none(),
            "404 is benign, must not surface as revoke_error: {b:?}"
        );
    }

    #[tokio::test]
    async fn destroy_with_revoke_5xx_returns_200_with_revoke_error() {
        let (cheers_url, _deletes, fail) = spawn_cheers_mock().await;
        *fail.lock().await = Some(StatusCode::INTERNAL_SERVER_ERROR);
        let (_tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        s.ownership_rows
            .lock()
            .unwrap()
            .insert("svc-glitch".into(), "01HROW".into());
        let state = Arc::new(s);
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::post("/workloads/svc-glitch/destroy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Teardown succeeded (no runtime), revoke failed — workload state
        // on-host is consistent, surface the revoke error for reconciliation.
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert_eq!(b["revoked"], false);
        let err = b["revoke_error"].as_str().unwrap();
        assert!(
            err.contains("500"),
            "revoke_error should carry the upstream status: {err}"
        );
    }

    // ── R593-F4: node admission enrollment + eviction ────────────────────────

    /// Shared state for [`spawn_ownership_mock`] — a stand-in for cheers's
    /// ownership ledger. `live_rows` holds unrevoked rows; `posts` records
    /// every POST body; `deletes` every DELETE id.
    #[derive(Clone, Default)]
    struct OwnershipMockState {
        live_rows: Arc<tokio::sync::Mutex<Vec<serde_json::Value>>>,
        posts: Arc<tokio::sync::Mutex<Vec<serde_json::Value>>>,
        deletes: Arc<tokio::sync::Mutex<Vec<String>>>,
        next_id: Arc<std::sync::atomic::AtomicU64>,
    }

    /// Spawn an in-process axum server standing in for cheers's full
    /// `/ownership` surface (POST + GET + DELETE) — unlike
    /// [`spawn_cheers_mock`], which only needs DELETE for the destroy-path
    /// tests above, node admission needs POST and the post-restart
    /// eviction fallback needs GET.
    ///
    /// Mirrors the R593-F4 semantics of the real handlers
    /// (oss/cheers/crates/cheers-axum/src/ownership.rs): POST is
    /// idempotent — an identical LIVE row (same principal_id/
    /// resource_kind/resource_id/relationship) is returned with 200
    /// instead of inserting a duplicate; a fresh row gets 201. GET lists
    /// live rows filtered by the `principal_id` query param. DELETE
    /// removes the row from the live set. This lets the restart
    /// re-admission/eviction tests below prove yubaba converges on ONE
    /// row and can still revoke after forgetting its in-memory state.
    async fn spawn_ownership_mock() -> (String, OwnershipMockState) {
        let state = OwnershipMockState::default();
        let post_state = state.clone();
        let get_state = state.clone();
        let delete_state = state.clone();
        let app = axum::Router::new()
            .route(
                "/ownership",
                axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let s = post_state.clone();
                    async move {
                        s.posts.lock().await.push(body.clone());
                        let mut rows = s.live_rows.lock().await;
                        // Idempotent create: identical live row → 200 it.
                        if let Some(existing) = rows.iter().find(|r| {
                            r["principal_id"] == body["principal_id"]
                                && r["resource_kind"] == body["resource_kind"]
                                && r["resource_id"] == body["resource_id"]
                                && r["relationship"] == body["relationship"]
                        }) {
                            return (StatusCode::OK, axum::Json(existing.clone()));
                        }
                        let n = s.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        let row = serde_json::json!({
                            "id": format!("own-{n}"),
                            "principal_id": body["principal_id"],
                            "resource_kind": body["resource_kind"],
                            "resource_id": body["resource_id"],
                            "relationship": body["relationship"],
                            "granted_by": body["principal_id"],
                            "on_behalf_of": body["on_behalf_of"],
                            "granted_at": 1_700_000_000_i64,
                            "revoked_at": serde_json::Value::Null,
                        });
                        rows.push(row.clone());
                        (StatusCode::CREATED, axum::Json(row))
                    }
                })
                .get(
                    move |axum::extract::Query(q): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| {
                        let s = get_state.clone();
                        async move {
                            let principal = q.get("principal_id").cloned().unwrap_or_default();
                            let rows: Vec<serde_json::Value> = s
                                .live_rows
                                .lock()
                                .await
                                .iter()
                                .filter(|r| r["principal_id"] == principal.as_str())
                                .cloned()
                                .collect();
                            axum::Json(rows)
                        }
                    },
                ),
            )
            .route(
                "/ownership/{id}",
                axum::routing::delete(
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        let s = delete_state.clone();
                        async move {
                            s.live_rows.lock().await.retain(|r| r["id"] != id.as_str());
                            s.deletes.lock().await.push(id);
                            StatusCode::NO_CONTENT
                        }
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), state)
    }

    /// Build a syntactically valid `ssh-ed25519` pubkey line whose key
    /// bytes are `key` — used to simulate hostkey ROTATION (a second
    /// /register-hostkey with a different key). The blob is the SSH wire
    /// format `parse_pubkey`/`node_id_hex` read: len-prefixed algorithm +
    /// len-prefixed 32-byte key, so the derived NodeId is exactly `key`.
    fn pubkey_line_for(key: [u8; 32]) -> String {
        use base64::Engine as _;
        let mut blob = Vec::new();
        blob.extend_from_slice(&(b"ssh-ed25519".len() as u32).to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&key);
        format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(blob)
        )
    }

    #[tokio::test]
    async fn register_hostkey_admits_node_enrollment_row() {
        // Admission fixture: POST /register-hostkey (the seam this ticket
        // picked — see ServerState::admit_node's doc for why) writes a
        // cheers ownership row with kind=node and resource_id equal to the
        // same mshr NodeId /identity reports for this hostkey.
        let (cheers_url, mock) = spawn_ownership_mock().await;
        let (_tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        let state = Arc::new(s);
        let app = build_router(state.clone());

        let req_body = serde_json::json!({ "pubkey": SAMPLE_PUBKEY, "bootstrap_token": mint_admission_token(&state) });
        let resp = app
            .oneshot(
                Request::post("/register-hostkey")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The enrollment write happened exactly once, with the right shape.
        let got = mock.posts.lock().await.clone();
        assert_eq!(
            got.len(),
            1,
            "expected exactly one ownership POST, got {got:?}"
        );
        let body = &got[0];
        assert_eq!(body["principal_id"], "svc:yubaba-test");
        assert_eq!(body["resource_kind"], "node");
        assert_eq!(body["relationship"], "owns");
        assert!(body["on_behalf_of"].is_null());

        // resource_id is the SAME mshr NodeId /identity now reports —
        // proves the enrolled id round-trips through the collapsed T2
        // identity, not some independently-derived value.
        let expected_node_id = {
            let id = state.snapshot().identity.unwrap();
            identity::node_id_hex(&id).unwrap()
        };
        assert_eq!(body["resource_id"], expected_node_id);

        // (node_id, row_id) pair stashed for a future evict_node() call.
        assert_eq!(
            state.node_enrollment.lock().unwrap().clone(),
            Some(NodeEnrollment {
                node_id: expected_node_id,
                row_id: "own-1".into()
            })
        );
        assert_eq!(mock.live_rows.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn double_register_hostkey_enrolls_exactly_once() {
        // Idempotency (process-local guard): /register-hostkey is re-POSTed
        // by design (cloud-init re-runs). The second call must not re-hit
        // cheers — one live row, same row id, exactly one POST on the wire.
        let (cheers_url, mock) = spawn_ownership_mock().await;
        let (_tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        let state = Arc::new(s);
        let app = build_router(state.clone());

        // Each POST carries its OWN single-use token — a cloud-init re-run
        // presents a fresh credential (token replay is deliberately rejected;
        // the process-local admission guard, not the token, provides the
        // "re-POST is a no-op" idempotency under test here).
        for _ in 0..2 {
            let req_body = serde_json::json!({
                "pubkey": SAMPLE_PUBKEY,
                "bootstrap_token": mint_admission_token(&state),
            });
            let resp = app
                .clone()
                .oneshot(
                    Request::post("/register-hostkey")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        assert_eq!(
            mock.posts.lock().await.len(),
            1,
            "second /register-hostkey must be a process-local no-op, not a re-POST"
        );
        assert_eq!(
            mock.live_rows.lock().await.len(),
            1,
            "exactly one live node row"
        );
        assert_eq!(
            state
                .node_enrollment
                .lock()
                .unwrap()
                .as_ref()
                .map(|e| e.row_id.clone()),
            Some("own-1".to_string()),
            "row id unchanged by the second registration"
        );
    }

    #[tokio::test]
    async fn restart_re_admission_converges_on_one_live_row() {
        // Idempotency (server-side): a daemon restart forgets the in-memory
        // node_enrollment pair, so re-admission DOES go out on the wire —
        // and cheers's idempotent POST /ownership (which the mock mirrors)
        // returns the existing live row instead of stacking a duplicate.
        let (cheers_url, mock) = spawn_ownership_mock().await;
        let (tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        let state1 = Arc::new(s);

        // First lifetime: admit.
        let first = state1.admit_node().await;
        assert!(
            matches!(first, Some(Ok(_))),
            "first admission should enroll: {first:?}"
        );
        assert_eq!(mock.live_rows.lock().await.len(), 1);

        // "Restart": fresh ServerState from the same state file (identity
        // persists on disk; node_enrollment does not), same cheers.
        drop(state1);
        let path = tmp.path().join("identity.json");
        let mut s2 = ServerState::load(path).unwrap();
        s2.cheers_client = Some(test_cheers_client(&cheers_url));
        let state2 = Arc::new(s2);
        assert!(state2.node_enrollment.lock().unwrap().is_none());

        let second = state2.admit_node().await;
        let row = match second {
            Some(Ok(row)) => row,
            other => panic!("re-admission after restart should succeed: {other:?}"),
        };

        // Two POSTs went out (restart forgot the guard) but the ledger
        // still holds exactly ONE live row, and the re-admission got the
        // SAME row id back — so a later evict_node() revokes the one true
        // enrollment, preserving W268's eviction semantics.
        assert_eq!(mock.posts.lock().await.len(), 2);
        assert_eq!(
            mock.live_rows.lock().await.len(),
            1,
            "no duplicate enrollment row"
        );
        assert_eq!(row.id, "own-1", "re-admission must return the original row");
        assert_eq!(
            state2
                .node_enrollment
                .lock()
                .unwrap()
                .as_ref()
                .map(|e| e.row_id.clone()),
            Some("own-1".to_string())
        );
    }

    #[tokio::test]
    async fn rotated_hostkey_re_enrolls_new_node_id_and_revokes_old() {
        // FIX 1 fixture (key-rotation drift): the admission guard is
        // identity-aware. A second /register-hostkey with a DIFFERENT key
        // must not be skipped — it enrolls the new NodeId and revokes the
        // stale row, so the ledger converges on exactly the current
        // identity (one live row, pointing at the NEW NodeId).
        let (cheers_url, mock) = spawn_ownership_mock().await;
        let (_tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        let state = Arc::new(s);
        let app = build_router(state.clone());

        // Each registration mints its own single-use admission token (R593-F8).
        let register = |pubkey: String| {
            Request::post("/register-hostkey")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "pubkey": pubkey,
                        "bootstrap_token": mint_admission_token(&state),
                    }))
                    .unwrap(),
                ))
                .unwrap()
        };

        // Key A.
        let key_a = [0xAAu8; 32];
        let resp = app
            .clone()
            .oneshot(register(pubkey_line_for(key_a)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let node_a: String = key_a.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(mock.live_rows.lock().await[0]["resource_id"], node_a);

        // Rotation: key B.
        let key_b = [0xBBu8; 32];
        let resp = app
            .clone()
            .oneshot(register(pubkey_line_for(key_b)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let node_b: String = key_b.iter().map(|b| format!("{b:02x}")).collect();

        // Exactly ONE live row, for the NEW NodeId; the old row is revoked.
        let live = mock.live_rows.lock().await.clone();
        assert_eq!(
            live.len(),
            1,
            "ledger must converge on one live row: {live:?}"
        );
        assert_eq!(live[0]["resource_id"], node_b);
        assert_eq!(live[0]["id"], "own-2");
        assert_eq!(
            mock.deletes.lock().await.clone(),
            vec!["own-1".to_string()],
            "the rotated-out NodeId's row must be revoked"
        );
        // In-memory pair tracks the new identity.
        assert_eq!(
            state.node_enrollment.lock().unwrap().clone(),
            Some(NodeEnrollment {
                node_id: node_b,
                row_id: "own-2".into()
            })
        );
    }

    #[tokio::test]
    async fn register_hostkey_without_cheers_client_skips_enrollment() {
        // Dev tiers with no cheers instance: admission is a no-op, but
        // hostkey registration itself must still succeed (R427-F1's
        // established "provision but skip the write" shape).
        let (_tmp, state) = fresh_state();
        let app = build_router(state.clone());

        let req_body = serde_json::json!({ "pubkey": SAMPLE_PUBKEY, "bootstrap_token": mint_admission_token(&state) });
        let resp = app
            .oneshot(
                Request::post("/register-hostkey")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(state.node_enrollment.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn register_hostkey_without_token_is_rejected_and_writes_no_enrollment() {
        // R593-F8 adversarial re-run (the F4 High finding): an
        // unauthenticated caller POSTs its OWN attacker pubkey. With a
        // cheers_client wired, an admitted registration WOULD write
        // `svc:<operator> owns node:<attacker-id>`. The token gate must
        // reject with 401 BEFORE any identity work — no ownership POST, no
        // enrollment pair, and the node's own boot identity is untouched
        // (replace_identity never runs).
        let (cheers_url, mock) = spawn_ownership_mock().await;
        let (_tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        let state = Arc::new(s);
        let identity_before = state.snapshot().identity;
        let app = build_router(state.clone());

        // Attacker key, NO bootstrap_token field at all.
        let attacker = pubkey_line_for([0xEEu8; 32]);
        let req_body = serde_json::json!({ "pubkey": attacker });
        let resp = app
            .oneshot(
                Request::post("/register-hostkey")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            mock.posts.lock().await.is_empty(),
            "rejected admission must not write any ownership row"
        );
        assert!(state.node_enrollment.lock().unwrap().is_none());
        assert_eq!(
            state.snapshot().identity.map(|i| i.hostkey_fingerprint),
            identity_before.map(|i| i.hostkey_fingerprint),
            "a rejected register must not replace the node's identity"
        );
    }

    #[tokio::test]
    async fn register_hostkey_with_invalid_token_is_rejected() {
        // A present-but-bogus token is indistinguishable (to the caller) from
        // a missing one: still 401, still no enrollment.
        let (cheers_url, mock) = spawn_ownership_mock().await;
        let (_tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        let state = Arc::new(s);
        let app = build_router(state.clone());

        let req_body = serde_json::json!({
            "pubkey": SAMPLE_PUBKEY,
            "bootstrap_token": "ybt1_not-a-real-token",
        });
        let resp = app
            .oneshot(
                Request::post("/register-hostkey")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(mock.posts.lock().await.is_empty());
        assert!(state.node_enrollment.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn register_hostkey_rejects_a_replayed_token() {
        // Single-use is enforced at the endpoint: a token that already
        // admitted one registration is spent — a replay collapses to the same
        // undifferentiated 401 as any other bad token.
        let (_tmp, state) = fresh_state();
        let app = build_router(state.clone());
        let token = mint_admission_token(&state);

        let post = |token: String| {
            Request::post("/register-hostkey")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "pubkey": SAMPLE_PUBKEY,
                        "bootstrap_token": token,
                    }))
                    .unwrap(),
                ))
                .unwrap()
        };

        // First presentation consumes the token.
        let resp = app.clone().oneshot(post(token.clone())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Replay of the same token: rejected.
        let resp = app.oneshot(post(token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn evict_node_revokes_enrollment_row_without_touching_the_key() {
        // Removal path fixture (callable + hook-note per the ticket — no
        // removal HTTP route exists yet): evict_node() revokes the cheers
        // row by id. Per W268 §The two axes, eviction must NOT touch the
        // on-disk hostkey/NodeId — only the ledger row goes away.
        let (cheers_url, mock) = spawn_ownership_mock().await;
        let (_tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        *s.node_enrollment.lock().unwrap() = Some(NodeEnrollment {
            node_id: "aa11".into(),
            row_id: "01HNODEROW".into(),
        });
        let identity_before = s.snapshot().identity;
        let state = Arc::new(s);

        let result = state.evict_node().await;
        assert!(
            matches!(result, Some(Ok(()))),
            "expected evict_node to succeed, got {result:?}"
        );

        let got = mock.deletes.lock().await.clone();
        assert_eq!(got, vec!["01HNODEROW".to_string()]);
        assert!(
            state.node_enrollment.lock().unwrap().is_none(),
            "enrollment pair should be consumed on successful revoke"
        );
        // The key itself is untouched — same identity before and after.
        assert_eq!(state.snapshot().identity, identity_before);
    }

    #[tokio::test]
    async fn evict_node_after_restart_falls_back_to_ledger_lookup() {
        // FIX 2 fixture (restart no-op): enroll, then simulate a restart
        // (fresh ServerState — in-memory node_enrollment lost), then
        // evict. The fallback must rediscover the row via the ownership
        // list (kind=node + resource_id=current NodeId) and revoke it —
        // including any historical duplicates.
        let (cheers_url, mock) = spawn_ownership_mock().await;
        let (tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        let state1 = Arc::new(s);

        let first = state1.admit_node().await;
        assert!(
            matches!(first, Some(Ok(_))),
            "admission should enroll: {first:?}"
        );
        let node_id = {
            let id = state1.snapshot().identity.unwrap();
            identity::node_id_hex(&id).unwrap()
        };

        // Plant a historical duplicate live row for the same NodeId (can't
        // arise via the idempotent POST — push straight into the ledger) so
        // the fallback's revoke-ALL-matches behaviour is exercised.
        mock.live_rows.lock().await.push(serde_json::json!({
            "id": "own-99",
            "principal_id": "svc:yubaba-test",
            "resource_kind": "node",
            "resource_id": node_id,
            "relationship": "owns",
            "granted_by": "svc:yubaba-test",
            "on_behalf_of": serde_json::Value::Null,
            "granted_at": 1_600_000_000_i64,
            "revoked_at": serde_json::Value::Null,
        }));

        // "Restart": fresh ServerState from the same state file; the
        // in-memory enrollment pair is gone.
        drop(state1);
        let path = tmp.path().join("identity.json");
        let mut s2 = ServerState::load(path).unwrap();
        s2.cheers_client = Some(test_cheers_client(&cheers_url));
        let state2 = Arc::new(s2);
        assert!(state2.node_enrollment.lock().unwrap().is_none());

        let result = state2.evict_node().await;
        assert!(
            matches!(result, Some(Ok(()))),
            "post-restart evict must revoke via the lookup fallback, got {result:?}"
        );

        let mut deletes = mock.deletes.lock().await.clone();
        deletes.sort();
        assert_eq!(
            deletes,
            vec!["own-1".to_string(), "own-99".to_string()],
            "ALL live rows for this NodeId must be revoked, duplicates included"
        );
        assert!(
            mock.live_rows.lock().await.is_empty(),
            "no live enrollment rows may survive eviction"
        );
    }

    #[tokio::test]
    async fn evict_node_without_prior_enrollment_is_noop() {
        let (_tmp, state) = fresh_state();
        let result = state.evict_node().await;
        assert!(
            result.is_none(),
            "no cheers_client configured — evict_node must no-op"
        );
    }

    #[tokio::test]
    async fn admit_node_without_identity_is_noop() {
        // No identity persisted yet (state cleared out from under a fresh
        // ServerState — same shape /identity's own 404 branch guards
        // against): admit_node must not panic and must not call cheers.
        let (cheers_url, mock) = spawn_ownership_mock().await;
        let (_tmp, state_raw) = fresh_state();
        let mut s = Arc::try_unwrap(state_raw).ok().unwrap();
        *s.state.lock().unwrap() = identity::StateOnDisk::default();
        s.cheers_client = Some(test_cheers_client(&cheers_url));
        let state = Arc::new(s);

        let result = state.admit_node().await;
        assert!(result.is_none(), "no identity — admit_node must no-op");
        assert!(
            mock.posts.lock().await.is_empty(),
            "cheers must not be called with no identity"
        );
    }

    #[test]
    fn workload_deploy_body_accepts_cheers_attribution_fields() {
        // Wire-shape check: requesting_camp_id + on_behalf_of_user parse and
        // default to None when absent. R427-T2 consumers depend on this
        // contract.
        let body: WorkloadDeployBody = serde_json::from_value(serde_json::json!({
            "spec": { "stub": true },
            "requesting_camp_id": "camp:C-abc",
            "on_behalf_of_user": "user:U-1",
        }))
        .unwrap();
        assert_eq!(body.requesting_camp_id.as_deref(), Some("camp:C-abc"));
        assert_eq!(body.on_behalf_of_user.as_deref(), Some("user:U-1"));

        let without: WorkloadDeployBody = serde_json::from_value(serde_json::json!({
            "spec": { "stub": true },
        }))
        .unwrap();
        assert!(without.requesting_camp_id.is_none());
        assert!(without.on_behalf_of_user.is_none());
    }

    // ── R608-B11: transfer-leader precondition logic ──────────────────────────

    #[test]
    fn plan_transfer_proceeds_when_leader_and_target_is_voter() {
        // Leader is node 1, cluster {1,2,3}, target is voter 2 → hand off.
        assert_eq!(plan_transfer(1, Some(1), 2, true), TransferPlan::Proceed);
    }

    #[test]
    fn plan_transfer_noop_when_target_already_leader() {
        // `to` (2) already leads → idempotent success, no handoff triggered.
        assert_eq!(
            plan_transfer(1, Some(2), 2, true),
            TransferPlan::NoopAlreadyLeader
        );
    }

    #[test]
    fn plan_transfer_rejects_when_this_node_is_not_leader() {
        // This node (1) thinks node 3 leads → misdirected; caller's view is stale.
        match plan_transfer(1, Some(3), 2, true) {
            TransferPlan::Reject(code, _) => assert_eq!(code, StatusCode::CONFLICT),
            other => panic!("expected Reject(CONFLICT), got {other:?}"),
        }
    }

    #[test]
    fn plan_transfer_rejects_when_no_leader_known() {
        // Mid-election, current_leader is None → not the leader here.
        assert!(matches!(
            plan_transfer(1, None, 2, true),
            TransferPlan::Reject(StatusCode::CONFLICT, _)
        ));
    }

    #[test]
    fn plan_transfer_rejects_non_voter_target() {
        // Target 4 is a learner / unknown, not a voter.
        match plan_transfer(1, Some(1), 4, false) {
            TransferPlan::Reject(code, _) => assert_eq!(code, StatusCode::BAD_REQUEST),
            other => panic!("expected Reject(BAD_REQUEST), got {other:?}"),
        }
    }

    // ── R572-F4: archetype-aware drain + single-instance guard ────────────────

    fn appliance_spec(ident: &str) -> serde_json::Value {
        use workload_spec::{ImageRef, MeshIdent, TierTag, WorkloadSpec};
        let mut spec = WorkloadSpec::for_forge(
            "fixture",
            ImageRef {
                registry: "localhost".into(),
                repository: "test".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            TierTag("infra".into()),
            vec![],
        );
        spec.expose.mesh.identity = MeshIdent(ident.into());
        spec.archetype = Some(LifecycleArchetype::Appliance);
        serde_json::json!({ "spec": serde_json::to_value(&spec).unwrap() })
    }

    #[tokio::test]
    async fn appliance_single_instance_guard_rejects_redeploy() {
        let (_tmp, state) = fresh_state();
        // Pre-insert: simulate a live appliance with this ident.
        state
            .archetype_registry
            .lock()
            .unwrap()
            .insert("my-appliance".into(), LifecycleArchetype::Appliance);

        let app = build_router(state);
        let body = appliance_spec("my-appliance");
        let resp = app
            .oneshot(
                Request::post("/workloads/deploy")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let b = body_json(resp).await;
        assert_eq!(b["ident"], "my-appliance");
        assert!(
            b["error"]
                .as_str()
                .unwrap()
                .contains("appliance already live"),
            "error should mention 'appliance already live', got: {}",
            b["error"]
        );
    }

    #[tokio::test]
    async fn server_not_blocked_by_single_instance_guard() {
        let (_tmp, state) = fresh_state();
        // Pre-insert a Server archetype — the guard must not block it.
        state
            .archetype_registry
            .lock()
            .unwrap()
            .insert("my-server".into(), LifecycleArchetype::Server);

        let app = build_router(state);
        let mut body = appliance_spec("my-server");
        // Override to Server archetype so the spec itself is a server.
        body["spec"]["archetype"] = serde_json::Value::String("server".into());
        let resp = app
            .oneshot(
                Request::post("/workloads/deploy")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Stub mode (no runtime) → 202 Accepted; the guard did NOT fire 409.
        assert_ne!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn destroy_clears_archetype_registry() {
        let (_tmp, state) = fresh_state();
        state
            .archetype_registry
            .lock()
            .unwrap()
            .insert("my-appliance".into(), LifecycleArchetype::Appliance);
        assert!(
            !state.archetype_registry.lock().unwrap().is_empty(),
            "registry should be non-empty before destroy"
        );

        let app = build_router(state.clone());
        let resp = app
            .oneshot(
                Request::post("/workloads/my-appliance/destroy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            state.archetype_registry.lock().unwrap().is_empty(),
            "registry should be empty after destroy"
        );
    }
}

// ── R599-T5: bundle deploys through POST /workloads/deploy ──────────────────

#[cfg(test)]
mod bundle_deploy_tests {
    use super::*;

    fn state() -> (tempfile::TempDir, Arc<ServerState>) {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("identity.json");
        (tmp, Arc::new(ServerState::load(path).unwrap()))
    }

    fn bundle_workload(digest: &str) -> workload_spec::Workload {
        workload_spec::Workload::MesofactStatic(workload_spec::MesofactStaticWorkload {
            schema_version: workload_spec::SchemaVersion::V1,
            build: workload_spec::BuildConfig {
                command: "bun run build".into(),
                out_dir: "dist".into(),
                render_command: None,
            },
            routes: "./mesofact.routes.ts".into(),
            build_mode: Default::default(),
            ssr_runtime: None,
            serve_bundle: Some(workload_spec::MesofactServeBundle {
                digest: workload_spec::BlakeHash(digest.to_string()),
                runtime: "self".into(),
                lifecycle: workload_spec::BundleLifecycle::KeepAlive,
            }),
        })
    }

    async fn body_json(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// The externally-tagged envelope is what a bundle deploy must send. Pinning
    /// the wire shape here because it is easy to get wrong: `Workload` has NO
    /// `serde(tag = "kind")`, so the JSON nests under the variant name rather
    /// than carrying a flat `kind` field.
    #[test]
    fn bundle_workload_json_is_externally_tagged() {
        let json = serde_json::to_value(bundle_workload(&"a".repeat(64))).unwrap();
        assert!(
            json.get("mesofact-static").is_some(),
            "expected external tagging under \"mesofact-static\", got {json}"
        );
        assert!(
            json.get("kind").is_none(),
            "Workload is NOT internally tagged — a flat `kind` field would not round-trip"
        );
    }

    /// A bare `WorkloadSpec` must still parse as `Container`: every deployed
    /// client sends that pre-migration shape, and the two forms are
    /// distinguishable because the envelope is externally tagged.
    #[test]
    fn bare_spec_is_not_mistaken_for_an_envelope() {
        let spec = serde_json::json!({
            "schema_version": "V1",
            "name": "probe",
            "image": "docker.io/library/busybox:1@sha256:aa",
        });
        assert!(
            serde_json::from_value::<workload_spec::Workload>(spec).is_err(),
            "a bare spec must NOT parse as a Workload envelope, or the \
             back-compat fallback would silently take the wrong branch"
        );
    }

    /// Without `serve_bundle` this is the build-and-publish form, which belongs
    /// to yubaba's own reconciler — it must be rejected with that pointer, not
    /// forwarded to kamaji.
    #[tokio::test]
    async fn mesofact_static_without_serve_bundle_is_rejected() {
        let (_tmp, s) = state();
        let mut w = bundle_workload(&"b".repeat(64));
        if let workload_spec::Workload::MesofactStatic(ref mut m) = w {
            m.serve_bundle = None;
        }
        let (status, body) =
            body_json(deploy_non_container(&s, w, Some("yah-marketing".into())).await).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"].as_str().unwrap().contains("reconciler"),
            "error should point at the mesofact-static reconciler, got {body}"
        );
    }

    /// The digest is the content, not the handle — it changes on every rebuild,
    /// so a deploy without an operator-chosen id is refused rather than
    /// silently registering an unstable workload name.
    #[tokio::test]
    async fn bundle_deploy_requires_an_operator_supplied_id() {
        let (_tmp, s) = state();
        let (status, body) =
            body_json(deploy_non_container(&s, bundle_workload(&"c".repeat(64)), None).await).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].as_str().unwrap().contains("\"id\""));
    }

    /// Whitespace is not a name.
    #[tokio::test]
    async fn blank_id_is_refused_like_a_missing_one() {
        let (_tmp, s) = state();
        let (status, _) = body_json(
            deploy_non_container(&s, bundle_workload(&"d".repeat(64)), Some("   ".into())).await,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// A bundle needs the sibling kamaji: the legacy in-process runtime has no
    /// native fork backend, so with no kamaji attached the caller gets a 503
    /// naming the flags rather than a confusing deeper failure.
    #[tokio::test]
    async fn bundle_deploy_without_kamaji_is_a_clear_503() {
        let (_tmp, s) = state();
        let (status, body) = body_json(
            deploy_non_container(
                &s,
                bundle_workload(&"e".repeat(64)),
                Some("yah-marketing".into()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let err = body["error"].as_str().unwrap();
        assert!(err.contains("--bundle-origin"), "got {err}");
    }
}

/// R624-T2 — the mesh-IP bind race. These tests drive the backoff through a
/// fake attempt closure: a real `127.0.0.1:0` bind exercises none of this.
#[cfg(test)]
mod bind_retry_tests {
    use super::{bind_error_is_retryable, bind_with_backoff};
    use std::io::{Error, ErrorKind};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    #[test]
    fn only_addr_not_available_is_worth_waiting_on() {
        assert!(bind_error_is_retryable(ErrorKind::AddrNotAvailable));
        // These never resolve by waiting — they must fail fast and loudly.
        assert!(!bind_error_is_retryable(ErrorKind::AddrInUse));
        assert!(!bind_error_is_retryable(ErrorKind::PermissionDenied));
        assert!(!bind_error_is_retryable(ErrorKind::InvalidInput));
        assert!(!bind_error_is_retryable(ErrorKind::Other));
    }

    #[tokio::test]
    async fn fatal_error_fails_on_the_first_attempt() {
        let attempts = AtomicU32::new(0);
        let err = bind_with_backoff::<(), _, _>("100.64.0.2:7443", Duration::from_secs(90), || {
            attempts.fetch_add(1, Ordering::Relaxed);
            async { Err(Error::from(ErrorKind::AddrInUse)) }
        })
        .await
        .expect_err("AddrInUse must not be retried");
        assert_eq!(err.kind(), ErrorKind::AddrInUse);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn gives_up_at_the_budget_rather_than_looping_forever() {
        let attempts = AtomicU32::new(0);
        let budget = Duration::from_millis(600);
        let started = std::time::Instant::now();
        let err = bind_with_backoff::<(), _, _>("100.64.0.2:7443", budget, || {
            attempts.fetch_add(1, Ordering::Relaxed);
            async { Err(Error::from(ErrorKind::AddrNotAvailable)) }
        })
        .await
        .expect_err("must give up once the budget is spent");
        assert_eq!(err.kind(), ErrorKind::AddrNotAvailable);
        let elapsed = started.elapsed();
        assert!(elapsed >= budget, "gave up early after {elapsed:?}");
        // Bounded: the loop backs off rather than spinning, and stops near the
        // budget instead of overshooting it by a whole delay step.
        assert!(
            elapsed < budget + Duration::from_secs(5),
            "overshot: {elapsed:?}"
        );
        let n = attempts.load(Ordering::Relaxed);
        assert!(n > 1, "should have retried, got {n} attempt(s)");
    }

    #[tokio::test]
    async fn succeeds_once_the_address_appears() {
        let attempts = AtomicU32::new(0);
        let listener = bind_with_backoff("100.64.0.2:7443", Duration::from_secs(90), || {
            let n = attempts.fetch_add(1, Ordering::Relaxed) + 1;
            async move {
                if n < 3 {
                    Err(Error::from(ErrorKind::AddrNotAvailable))
                } else {
                    Ok("bound")
                }
            }
        })
        .await
        .expect("a late address should be survivable");
        assert_eq!(listener, "bound");
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }
}
