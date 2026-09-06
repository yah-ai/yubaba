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
//! @yah:handoff("DONE — the demux this note deferred is landed in oss/kamaji/crates/kamaji/src/sibling.rs. It turned out to be a correctness fix, not the forward-looking cleanup this note framed it as: the Mutex+serial shape correlated replies by POSITION, so cancelling a caller between its write and its read (exactly what axum does to a handler when the HTTP client times out) consumed a request id while kamaji's reply stayed queued, handing it to the next caller and leaving the connection off-by-one PERMANENTLY -- 'request_id mismatch (expected 89, got 88)' until yubaba restarts. Observed live on a cold W272 bundle materialize that outran cloud-client's 5s deploy timeout. Reader task demuxes by RequestId; writer task owns write_all so a cancel can't truncate a frame; ClientError::RequestIdMismatch is GONE because the mismatch can no longer occur. Pushes (WorkloadStarted/WorkloadExited, no RequestId) are now dropped instead of being served to a caller as its reply, which is the part this note anticipated.")
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
//! @yah:ticket(R556-T10, "yubaba: advertise local scryer in /services discovery (one entry, no proxy)")
//! @yah:status(review)
//! @yah:at(2026-06-30T06:24:56Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P1)
//! @yah:parent(R556)
//! @yah:next("When kamaji is running a scryer on this node, add a /services entry: {name:'scryer', endpoint:'http://<tailnet-ip>:6543', capabilities:['events.query','events.aggregate'], managed_by:'kamaji'} per W264 §Discovery. Existing get_services route at oss/yubaba/crates/yubaba/src/lib.rs:579.")
//! @yah:next("Endpoint discovery entry is tag-gated (it leaks endpoint location); the data-path ACL stays at scryer's HTTP listener (W264 §Trust boundary).")
//! @yah:next("No proxy route — yubaba is not in the query data path. Consumers connect to scryer directly using the advertised endpoint.")
//! @yah:next("Sequencing gotcha: ship scryer's HTTP listener (R556-T9) before this entry resolves to a live endpoint.")
//! @yah:next("Tier: Thief — single discovery entry added to an existing surface; rote integration, no novel logic.")
//! @arch:see(.yah/docs/working/W264-kamaji-managed-scryer.md)
//!
//!
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
//! @yah:handoff("DETERMINISM VERIFIED (not assumed): two independent builds an hour apart produced byte-identical tars, sha256 e856a18d14146fd199040c2557881c38e7275a911e3f6c2076587e5acbb42d01. That validated pasting the recorded hashes into .yah/services/yah-cloud/components/rusty-v8-musl/workload.toml, closing R546-T3's code side.")
//! @yah:handoff("TEST GAP (deliberate, not done): the reap guard is NOT unit-tested -- workload_spec::forge_produced::HOST_ROOT is a hardcoded absolute /var/lib path, so a test would touch the real host fs. Making HOST_ROOT injectable is the prerequisite; I did not refactor that unprompted.")
//! @yah:handoff("FLEET NOT YET PROTECTED: us-west-002 still runs the hand-patched unit + a yubaba binary WITHOUT the reap guard. The repo fixes only reach it on the next cross-build+redeploy. Fine for now (the timeout fix removes the trigger; the guard is defense-in-depth), but a fresh node provisioned before that redeploy would still hit the EROFS mkdir failure.")
//! @yah:next("DESTROY SEMANTICS BUG — ROOT-CAUSED under R823-B4 (2026-09-03), read that ticket before acting on the bullet above. The incoherence that note describes (\"reaps the produced dir but leaves the container running\") is not a semantics choice; it is a key mismatch. yubaba's Stop carries the workload's MESH ident (forge.&lt;uuid&gt;) while kamaji-bin's containerd backend NAMES the container from spec.name (forge-&lt;uuid&gt;, R590-B9), so teardown probed a container that never existed and returned Ok — destroy answered \"destroyed\" over a live container. Fixed in oss/kamaji/crates/kamaji-bin/src/containerd.rs by resolving the Stop key through the yah.mesh-ident label. Retire this bullet once R823-B4's live roll proves it on a node.")
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
//! @yah:status(review)
//! @yah:at(2026-07-23T19:04:42Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R626)
//! @yah:gotcha("This is what actually blocks tag:build-worker on us-west-015 (and any future darwin/pond node). Found 2026-07-22 while clearing that node's other three blockers: kamaji there now has a working docker backend on a yah-owned Colima, and GET /workloads already reports x-workload-source: kamaji — but a qed forge job arrives via POST /workloads/deploy (app/yah/cli/src/yubaba_client.rs:348), which is still the legacy in-process ContainerRuntime path. On a build WITHOUT containerd-integration (every macOS node) that path is STUB MODE, so the job is accepted and then does not run.")
//! @yah:gotcha("The READ side is already migrated and must not be re-done: GET /workloads, GET /workloads/{id}/state and POST /workloads/drain all prefer the kamaji client already (R406-T8). Only deploy is stranded. Verified live on us-west-015 2026-07-22 — a labelled container surfaced correctly through yubaba with the right pid.")
//! @yah:gotcha("yubaba on macOS is built WITHOUT containerd-integration and always will be (containerd is Linux-only), so 'just enable the feature' is not an out for darwin nodes. Dispatching to kamaji is the only path that gives a Mac a working deploy.")
//! @yah:handoff("VERIFIED COMPLETE + closed the test gap. FINDING: the deploy->kamaji routing is ALREADY committed in the current tree — F5's premise ('POST /workloads/deploy is still the legacy in-process path / stub mode') is STALE. deploy_workload_spec (oss/yubaba/crates/yubaba/src/lib.rs:2229) does `let backend = s.active_backend()` and deploys through it; active_backend() (lib.rs:1071) prefers the sibling KamajiClient (constable_client) over the legacy runtime, falling back to stub ONLY when neither is set. KamajiClient::deploy_workload (oss/kamaji/crates/kamaji/src/sibling.rs:472) is fully implemented — wraps the spec in Workload::Container and sends YubabaToKamaji::Deploy, awaiting the Deploy Ack. So on a darwin/pond node launched with --kamaji-socket (R626-F2 already added it to DEFAULT_WARDEN_ARGS), a forge job's POST /workloads/deploy dispatches to kamaji, whose docker backend (R626-F1) runs the container. This is the R406-T9 follow-on the T8/T9 notes anticipated; it landed in an earlier commit without closing F5.")
//! @yah:handoff("THE REAL REMAINING GAP was test coverage, exactly as the old T8/T9 notes flagged ('test churn is the real cost'). integration_constable_client.rs covers list/drain/stop through a real kamaji but its own header (line 11) says deploy was never covered ('the Kamaji handler short-circuits'). CLOSED: new hermetic test crates/yubaba/tests/integration_deploy_through_kamaji.rs — spawns a real kamaji sibling, builds a ServerState.with_constable_client, POSTs a container workload to /workloads/deploy through build_router, and asserts it is NOT stub-accepted (status != 202, body.runtime != 'stub') and instead surfaces kamaji's backend-refused as a 5xx. That refusal (a bare kamaji has no docker/containerd backend) is the proof the deploy reached kamaji rather than being handled in-process — the exact inversion of the darwin build-worker bug.")
//! @yah:handoff("ATTRIBUTION: I did NOT author the deploy-routing code (it was committed before this session); I verified it end-to-end and added the missing regression coverage. The T8-era @yah:gotcha at lib.rs:94 ('deploy is still on the legacy path on purpose') is now superseded by the current code + comment at lib.rs:2216 — left in place as R406-T8's point-in-time historical record rather than rewriting a reviewed ticket's annotation on a shared tree.")
//! @yah:verify("cargo test -p yubaba --test integration_deploy_through_kamaji — 1 pass (the new deploy-routes-to-kamaji-not-stub regression)")
//! @yah:verify("cargo test -p yubaba --lib — 253 pass, 0 fail (includes R626-F4's teardown_one tests; no regression)")
//! @yah:verify("cargo test -p yubaba --test integration_constable_client — 3 pass (list/drain/stop wire round-trips still green)")
//! @yah:verify("CODE-REVIEW BAR (the substance of this ticket): deploy_workload_spec at lib.rs:2229 routes through active_backend(); active_backend() at lib.rs:1071 prefers the sibling KamajiClient; KamajiClient::deploy_workload at oss/kamaji/.../sibling.rs:472 sends a real Deploy frame. Stub mode (lib.rs:2586) is reached only when NO backend is attached — correct.")
//! @yah:verify("LIVE BAR (operator/infra step, cannot run from a dev box — needs the node + a rebuilt+re-pinned pond/yubaba image per R626-F2's standing gotcha, since the pinned image predates the docker backend): on us-west-015, POST a container workload to the node's /workloads/deploy and confirm `docker ps` shows it running (not silently stubbed); boot log's '/workloads/deploy runs in stub mode' warning is now harmless because --kamaji-socket routes deploy to kamaji.")
//! @yah:next("LIVE VERIFY on a real node once the pond/yubaba image is rebuilt + re-pinned (blocked on that image bump per R626-F2 — the host-side --kamaji-socket wiring is already in place and inert against the old binary). This is the only thing between 'code + tests done' and 'darwin build-workers actually run forge jobs'.")
//! @yah:next("OPTIONAL cleanup, not blocking: the T8-era @yah:gotcha at oss/yubaba/crates/yubaba/src/lib.rs:94 still reads 'POST /workloads/deploy is still on the legacy in-process path on purpose' — factually superseded by the code at lib.rs:2216. Left as R406-T8's historical record; a maintainer touching that reviewed ticket's block could strike it.")
//! @yah:next("tag:build-worker on us-west-015: this ticket removes the deploy-path blocker, but adding the tag still needs the node on 0.8.20 + a docker daemon reachable by the runtime account (per R626-F1's note). Separate infra step.")
//!
//! @yah:relay(R635, "Rename acme-engine (squatted on crates.io at 0.4.0) to a yah- name; unblocks yubaba publish")
//! @yah:status(review)
//! @yah:at(2026-07-24T05:00:55Z)
//! @yah:assignee(bundle-anthropic-miravel)
//! @yah:parent(Q538)
//! @yah:next("Verified against the crates.io sparse index 2026-07-22: `acme-engine` exists but holds only 0.4.0, published by an unrelated project. Our oss/passway crate declares 0.8.20, so the version can never resolve from the registry — root Cargo.toml already calls this bridge 'load-bearing until (if ever) we publish under our own name'.")
//! @yah:next("This is the SOLE remaining blocker on publishing the `yubaba` crate (R542). Everything else yubaba depends on is already on crates.io at 0.8.20: yah-workload-spec, yah-local-driver, kamaji, kamaji-proto, mshr, and yubaba-client (publishable as of R542).")
//! @yah:next("Work: rename the package in oss/passway/crates/acme-engine to a free yah- name (check the target on the sparse index first — https://index.crates.io/ya/h-/<name>), update the root [patch.crates-io] key, oss/yubaba/Cargo.toml's sibling patch key, and yubaba's dependency line. Consumers can keep the short `acme_engine` extern name via `acme-engine = { package = \"yah-acme-engine\", version = \"0.8.20\" }` — that alias trick is what R542 used for cloud -> yah-cloud with zero source churn.")
//! @yah:next("Then fill description/keywords/categories on the renamed crate, cargo publish --dry-run --allow-dirty -p <name>, and hand back to R542 to flip yubaba's publish flag.")
//! @yah:verify("cargo publish --dry-run --allow-dirty -p <renamed acme crate> exits 0")
//! @yah:verify("cargo check -p yubaba (from oss/yubaba) is clean after the rename")
//! @yah:handoff("VERIFIED COMPLETE — the rename landed in commit ebfdd3f2 (already in the tree, not authored by this session). oss/passway/crates/acme-engine now packages as `passway-acme` (name chosen by the operator, scoped like kamaji-proto/srcgraph-core) with `[lib] name = \"acme_engine\"`, so zero .rs changed at any consumer.")
//! @yah:handoff("Consumers alias via `package =`: root Cargo.toml [patch.crates-io] key `passway-acme = { path = \"oss/passway/crates/acme-engine\" }` (Cargo.toml:737), oss/yubaba/Cargo.toml's sibling patch key (line 35), and yubaba's own dependency line `acme-engine = { package = \"passway-acme\", version = \"0.8.21\" }` (oss/yubaba/crates/yubaba/Cargo.toml:85).")
//! @yah:handoff("Description/keywords/categories were already filled on the renamed crate (acme-engine/Cargo.toml:13-15). yubaba's Cargo.toml carries no publish=false — the R542 gate is cleared, per its own in-manifest comment at line 11-14.")
//! @yah:handoff("This session's contribution: found the work already landed but not reflected on the board, re-verified all three claims (sparse-index 404, publish --dry-run, cargo check) fresh, and closes the loop so R542 (blocked_by R635) can proceed.")
//! @yah:handoff("Tree anchor at handoff: ccee2a6b17b85dc6c9ffc42fcf4e528120a83673 — the shared tree as I left it. Diff against it (`git diff ccee2a6b17b85dc6c9ffc42fcf4e528120a83673..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("Nothing further needed on this ticket's side — R542 can proceed once this lands in review.")
//! @yah:verify("crates.io sparse index confirms passway-acme genuinely free: https://index.crates.io/pa/ss/passway-acme -> 404, re-checked 2026-07-24")
//! @yah:verify("cargo publish --dry-run --allow-dirty -p passway-acme (from oss/passway) — packages, verifies, compiles, exits 0")
//! @yah:verify("cargo check -p yubaba (from oss/yubaba) — clean, 0 errors")
//!
//! @yah:ticket(R734-T3, "Close the membership loop: a remove-member operator command + a joint-consensus grow-3-to-5-and-shrink test")
//! @yah:status(review)
//! @yah:at(2026-08-10T19:38:07Z)
//! @yah:assignee(agent:claude)
//! @yah:phase(P1)
//! @yah:parent(R734)
//! @yah:next("Tier: Cleric — add-learner and promote-voter already shipped; this is the symmetric third verb plus the transition test.")
//! @yah:next("VERIFIED 2026-08-09: routes /raft/initialize, /raft/add-learner, /raft/promote-voter, /raft/transfer-leader all exist (lib.rs:1463-1475) with tests raft_add_learner.rs, raft_promote_voter.rs, raft_transfer_leader.rs. There is NO remove-member route — `rg 'remove.member|remove_member|RemoveVoter'` over oss/yubaba returns nothing.")
//! @yah:next("The remaining W253 section 10 box is 'membership-change mechanism exercised and tested': grow 3 -> 5 voters and remove one, asserting no split-brain across the joint-consensus transition.")
//! @yah:verify("cargo test -p yubaba --test raft_add_learner")
//! @yah:verify("cargo test -p yubaba --test raft_promote_voter")
//! @yah:handoff("LANDED. POST /raft/remove-member + fn raft_remove_member (lib.rs), `yubaba raft remove-member --node-id N` (repeatable), and tests/raft_membership_loop.rs — five real nodes on loopback, grow 3->4->5 by add-learner+promote, then shrink 5->3 in one change. This closes W253 §10's last open box, 'membership-change mechanism exercised and tested'.")
//! @yah:handoff("THE API TAKES A SET, and that is load-bearing rather than convenient. The surviving voter count must stay odd, so shrinking 5 -> 3 has to remove two members in ONE membership change. A single-id verb would have made the only legal shrink inexpressible and left operators removing one node 'temporarily' into an even set. Removed nodes leave entirely (retain: false) rather than being demoted to learners — a decommissioned box should stop receiving replication, and a node left as a silent learner is a machine still holding full cluster state that nobody remembers is running.")
//! @yah:handoff("THE GATE: the SURVIVING voter set is judged by QuorumGeography::judge_voter_count before anything is proposed, so 3 -> 2 and 5 -> 4 are refused with 400. That is the drain-a-machine mistake — an operator removes one voter, lands in an even set that tolerates no failures while requiring every node for every write, and it looks healthy until either survivor blinks. Learners are NOT judged, because removing one cannot touch quorum; a gate that judged 'membership size' rather than 'voter count' would refuse that and be wrong in a way that looks principled, which is why there is a test for it.")
//! @yah:handoff("REFACTOR ON F2's WORK: split the policy-independent clauses out of QuorumGeography::judge into a public judge_voter_count(count). Founding and removal can answer different amounts of the same question — at founding the operator supplies region tags in the same call so the spread clause is always answerable, but at removal the regions live in replicated state the operator never wrote. Splitting it lets removal check what it CAN check instead of either fabricating region data or skipping the check entirely.")
//! @yah:handoff("ORDERING DECISION, pinned by its own test: validation runs BEFORE the leader check, so a follower answers an invalid change with 400 rather than 421. Membership metrics are replicated, so every node judges the count identically, and a change that is invalid is invalid at the leader too — answering 'retarget at the leader' first would send the operator to do the same thing again and learn the real answer on the second try. a_follower_refuses_an_invalid_change_before_redirecting exists so that stays a decision.")
//! @yah:handoff("EPOCH VERDICT: cluster_protocol re-recorded, stays at 4; state_epoch untouched and GREEN. The route is additive and operator-facing — no node dials it at a peer, and an old build's 404 is a missing operator capability, exactly the precedent the 2026-08-02 entry set for /raft/promote-voter. The membership change itself is openraft's ordinary joint consensus, replicated as the same Membership log entry both builds already implement.")
//! @yah:handoff("SEPARATE AND MORE IMPORTANT: this ticket's test is what surfaced the R734-T1 pre-vote defect. Building a five-node loaded test was enough to expose that enable_pre_vote against openraft 0.10.0-alpha.30 strands a node as leader-per-peers and not-leader-per-itself, permanently. I switched the flag off, retracted T1's claim on its own ticket, and corrected cluster-epochs.json, W247, W253 and tests/raft_pre_vote.rs. Full account on R734-T1. Everything T1 BUILT survives; only the flag changed.")
//! @yah:next("NO yah-CLI SURFACE WAS ADDED, per the standing instruction not to touch app/yah/cli/src/camp.rs while @Ashguard:polaris is live in it on R728. The yubaba-side API and its own CLI are complete and tested. IF a `yah cloud raft remove-member` wrapper is wanted, the insertion point is app/yah/cli/src/camp.rs alongside the existing raft subcommands, forwarding to POST /raft/remove-member on the leader with body {\"node_ids\": [..]} and surfacing 400 (invalid change, body names the rule) and 421 (retarget at the leader named in the body) distinctly — collapsing those two into one error message is the thing to avoid, since one means 'do something else' and the other means 'do the same thing elsewhere'.")
//! @yah:next("The removal gate cannot check region SPREAD, only count — openraft's node type is BasicNode{addr} so raft membership carries no region, and R734-F2's MemberInfo.region is written by nothing in production. So a removal can still worsen quorum geography (5 voters as 2-2-1 down to an odd-but-lopsided 2-1) without being refused. Named in the handler's doc comment and in cluster-epochs.json residual_risk. Closes when member rows carry regions.")
//! @yah:verify("cargo test -p yubaba --test raft_membership_loop = 5 passed / 0 failed. Repeated 6 consecutive times in debug and 12 of 13 times in release with no flakes (the one release failure was a 0/5 whole-suite wipeout I could not reproduce in 14 further runs and could not capture — recorded because it is unexplained, not because it looks related).")
//! @yah:verify("TEETH: every transition asserts membership is a SINGLE UNIFORM CONFIG, not just that the voter list is right. A cluster stranded mid-joint-consensus still answers /raft/status with a plausible voter list — it just carries two configs and silently needs a quorum of each. Reading voters without checking config count is exactly how that state passes for healthy.")
//! @yah:verify("Refusals are asserted INERT: after a refused removal the membership is re-read and must be byte-identical, so a gate that refused after proposing would be caught.")
//! @yah:verify("cargo test -p yubaba --lib = 384 passed / 0 failed. Full yubaba suite green: bootstrap_single_node 2/0, raft_add_learner 1/0, raft_pre_vote 3/0, raft_promote_voter 2/0, raft_quorum_geography 5/0, raft_transfer_leader 1/0, rig_singleton_ownership 2/0, integration_mesh --features containerd-integration 7/0/1.")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift = 8 passed / 0 failed after re-recording.")
//! @yah:verify("cargo clippy -p yubaba -p yubaba-test-harness --all-targets: no warnings on any file this ticket touched.")
//!
//! @yah:ticket(R743-T1, "yubaba: 19 test binaries to 4, merging by required-features group")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-08-11T01:16:48Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R743)
//! @yah:next("Set autotests = false in oss/yubaba/crates/yubaba/Cargo.toml; declare four [[test]] targets: main (12 ungated files), testing (integration_public_ingress, integration_operator_bridge, integration_ownership_smoke, integration_service_records; required-features = [\"testing\"]), containerd (integration_single_node, integration_mesh; required-features = [\"containerd-integration\"]), and integration_smoke_filter kept standalone (needs both features).")
//! @yah:next("Each group root mod's its members. The 7 existing [[test]] blocks at Cargo.toml lines 140-183 are the input — read their required-features, do not assume.")
//! @yah:verify("cargo test -p yubaba -- --list count unchanged; three green runs; one commit so the oss subtree split stays clean.")
//! @yah:gotcha("Tests with different required-features cannot share a binary without widening the merged target's feature set, which would make it unbuildable where containerd is absent. That is why this crate is 19 to 4, not 19 to 1.")
//! @yah:gotcha("tests/integration_constable_client.rs, integration_single_node.rs and pond_reconciler_smoke.rs host live @yah: annotations — leave the files in place.")
//! @yah:tier(Warrior)
//! @yah:handoff("DONE, commit 25731ad. 22 -> 4 test targets in oss/yubaba/crates/yubaba: autotests=false plus [[test]] main (16 ungated mods), testing (3, required-features=[testing]), containerd (2, [containerd-integration]), and integration_smoke_filter kept standalone. Group roots tests/{main,testing,containerd}.rs only 'mod' the files - nothing moved, renamed or deleted, so the live @yah: annotations in integration_constable_client.rs / integration_single_node.rs / pond_reconciler_smoke.rs are untouched. Test NAMES are unchanged: a module path reproduces the old target name (raft_add_learner::adds_a_learner). WIN: 2.3 GB of test binaries vs ~16 GB before (~85% less), 4 link steps vs 22 - each yubaba test binary statically links the whole dep closure at ~730 MB.")
//! @yah:verify("Per-target --list inventory captured before and after is identical: 82 tests both ways. Three consecutive green runs of the newly-concurrent main group (51 passed, ~39s each, zero variance); testing 17 passed/1 ignored; containerd 8 passed/2 ignored; integration_smoke_filter 2 passed/1 ignored. cargo check --all-targets clean - the 12 warnings are pre-existing library ones, none in tests/.")
//! @yah:gotcha("Ticket text was stale on specifics and said so ('read their required-features, do not assume') - correctly. Actual tree has 22 test files, not 19, and 16 ungated, not 12. The file it named for the testing group, integration_public_ingress, does not exist. Counts in the ticket should not be trusted; the [[test]] blocks were the real input.")
//! @yah:gotcha("integration_smoke_filter must stay standalone: it is the ONLY file requiring containerd-integration AND testing, so folding it into the containerd group would force 'testing' onto integration_single_node and integration_mesh. That is why this is 4 targets, not 3.")
//! @yah:gotcha("autotests=false means a NEW tests/*.rs file is no longer auto-discovered - it compiles nowhere and runs never until someone adds a 'mod' line to the group root matching its feature set. Documented in [package] and in tests/main.rs, but it is a real footgun for the next person adding a test.")
//! @yah:gotcha("Grouping changes concurrency semantics: cargo runs test BINARIES sequentially but tests inside one binary in parallel, so 16 formerly-separate modules now run concurrently. Safe here - audited before merging: every test allocates its own tempfile::TempDir and binds 127.0.0.1:0, no shared fixed port/path and no process-global init anywhere in tests/ or yubaba-test-harness. One theoretical residual: harness restart_node (lib.rs:542) rebinds a node's original ephemeral port after a 200ms window, which another test could in principle have taken. Pre-existing, not introduced here, but the window is wider now.")
//!
//! @yah:relay(R780, "expose.public never registers a Cloudflare tunnel: ServerState::cloudflared_url is None in every production yubaba")
//! @yah:at(2026-08-17T01:05:37Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("Two children: a spike that settles which mechanism owns workload expose.public, then a task that wires the winner and deletes or documents the loser.")
//! @yah:gotcha("Proven 2026-08-16: ServerState::cloudflared_url is set ONLY by with_cloudflared_url (lib.rs:1351), whose three callers are two tests in tests/integration_public_ingress.rs and one doc comment in testing/cloudflared_mock.rs. The shipping startup chain is load().with_cluster_policy().with_bind_addr() (main.rs:520) plus the litestream/runtime/kamaji/pond attachers; main.rs has zero matches for 'cloudflared'. Every production yubaba therefore takes the lib.rs:3089 fallback ('no cloudflared URL configured; using port-mapping fallback for expose.public') on every node, regardless of what is installed on the box.")
//! @yah:gotcha("A second, newer mechanism exists and may be the real owner: reconciler::ingress::ensure_tunnel_ingress (oss/yubaba/crates/cloud/src/reconciler/ingress.rs) + local_driver::cloudflared_ingress::CloudflaredIngressSpec (oss/yah-base), driven from handle_cloudflared_deploy at app/yah/cli/src/cloud.rs:3509 — one cloudflared per (machine, cohort), keyed on MachineConfig.cloudflared. Do not wire the ServerState path before settling which of the two owns workload expose.public; wiring both is two tunnels for one route.")
//! @yah:assumes("Reported by the noisetable camp (its R131-T6, app.noisetable.com public origin). Whether us-west-001 actually runs cloudflared is UNVERIFIED: machine.toml's cloudflared field only injects an install block into cloud-init at provision time, and us-west-001 is provider = static — an attached box cloud-init may never have run for. Settle with: ssh debian@15.204.89.240 'systemctl is-active cloudflared'.")
//! @arch:see(.yah/docs/architecture/A053-yah-yubaba-integration-testing.md)
//!
//! @yah:ticket(R780-S1, "Settle which cloudflared mechanism owns workload expose.public: ServerState POST /v1/tunnels, or reconciler ensure_tunnel_ingress")
//! @yah:status(review)
//! @yah:at(2026-08-19T05:35:47Z)
//! @yah:kind(spike)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R780)
//! @yah:next("Trace a `yah cloud workload deploy` with expose.public end to end and record which code actually runs. Two candidates: (a) ServerState::cloudflared_url -> post_tunnel_route (lib.rs:4519, POST <url>/v1/tunnels), reached from the deploy handler at lib.rs:3056; (b) reconciler::ingress::ensure_tunnel_ingress + CloudflaredIngressSpec, per (machine, cohort), keyed on MachineConfig.cloudflared. Output is a one-paragraph verdict naming the owner, plus whether the other is dead code to delete or a different layer (connector stand-up vs per-workload route) that legitimately coexists.")
//! @yah:next("Tier: Wizard — three crates (yubaba, cloud, yah-base) plus the CLI, and the answer decides what R780's task wires.")
//! @yah:verify("cd /Users/leif/ss/yah && rg -n 'cloudflared' oss/yubaba/crates/yubaba/src/main.rs")
//! @yah:verify("cd /Users/leif/ss/yah && rg -rn 'ensure_tunnel_ingress' --glob '*.rs'")
//! @yah:handoff("Verdict: reconciler::ingress::ensure_tunnel_ingress (oss/yubaba/crates/cloud/src/reconciler/ingress.rs:610) is the real production owner of Cloudflare Tunnel route registration. It's driven by `yah cloud apply`/`mirror up` over MirrorConfig-declared zone/port slots (W267/R594-F11, landed 2026-08-03), talks to the actual Cloudflare REST API via CloudflareClient::tunnel_configuration/put_tunnel_configuration (GET-merge-PUT), and coexists legitimately with `yah cloud ingress deploy` (handle_cloudflared_deploy, app/yah/cli/src/cloud.rs:3509) which stands up the per-machine cloudflared connector appliance itself — connector bring-up and route publishing are correctly split.")
//! @yah:handoff("ServerState::cloudflared_url -> register_cloudflare_tunnel -> POST <url>/v1/tunnels (R091-F7, 2026-05-08, A053 doc) is the ONLY code that reads WorkloadSpec.expose.public, but its wire protocol (`POST /v1/tunnels {hostname, service_url}`) is fictional -- it matches nothing but its own test double testing/cloudflared_mock.rs. No real cloudflared daemon or Cloudflare API exposes that shape. It predates W267 by 3 months, was never wired into main.rs's startup chain, and its own --ignored smoke test (public_ingress__smoke, asserting a real CF tunnel serves a 200 from outside the cluster) has no evidence of ever having been run against a live account. This is dead scaffolding superseded by the mirror-ingress redesign, not a second legitimate layer.")
//! @yah:handoff("us-west-001 cloudflared install status stays UNVERIFIED -- no SSH reachability from this sandbox (debian@15.204.89.240: Permission denied (publickey)). Doesn't change the verdict: ownership is a code-level fact, independent of what's installed on that specific box.")
//! @yah:next("T2: delete cloudflared_url, with_cloudflared_url, register_cloudflare_tunnel, the deploy-handler expose.public branch, and tests/integration_public_ingress.rs, since expose.public should route through the mirror-ingress system instead. Making the port-mapping fallback loud (or failing the deploy) applies to that path's absence, not the deleted one.")
//! @yah:handoff("Verdict delivered (see prior handoff entries) and consumed directly into R780-T2, which deleted the dead ServerState::cloudflared_url path and wired a loud warning pointing at the real mechanism (reconciler::ingress::ensure_tunnel_ingress via mirror declarations).")
//!
//! @yah:ticket(R780-T2, "Wire the cloudflared path S1 names, so expose.public stops silently falling back to port-mapping")
//! @yah:status(review)
//! @yah:at(2026-08-19T05:35:36Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R780)
//! @yah:next("If S1 says the ServerState path owns it: give yubaba a source for cloudflared_url (machine manifest field, config, or env) and attach it in main.rs's startup chain next to with_cluster_policy/with_bind_addr. If S1 says the reconciler path owns it: delete cloudflared_url, post_tunnel_route, and the two integration tests that are its only production-shaped callers, so the dead branch stops looking wired.")
//! @yah:next("Either way the port-mapping fallback must stop being silent-on-purpose in a deployment that asked for expose.public — warn-and-continue is right for a node with no tunnel, wrong for one that declared cloudflared in its machine manifest. Make that case loud (or fail the deploy).")
//! @yah:next("Tier: Warrior — the design decision is S1's; this is plumbing plus a test.")
//! @yah:verify("cd /Users/leif/ss/yah && cargo test -p yubaba --test integration_public_ingress")
//! @yah:verify("cd /Users/leif/ss/yah && cargo check -p yubaba -p yah")
//! @yah:depends_on(R780-S1)
//! @yah:handoff("Deleted the dead ServerState::cloudflared_url path per S1's verdict: cloudflared_url field, with_cloudflared_url builder, register_cloudflare_tunnel(), the expose.public branch in the deploy handler (lib.rs), tests/integration_public_ingress.rs, testing/cloudflared_mock.rs, and its [[test]] entry in Cargo.toml.")
//! @yah:handoff("Replaced the deploy-handler branch with a tracing::warn! (was info!) that fires whenever spec.expose.public is set, naming the real mechanism (declare a mirror with ingress = \"cloudflare-tunnel\" + `yah cloud apply`) instead of silently no-op'ing. Chose loud-warn-and-continue over hard-failing the deploy: expose.public is a documented, still-valid WorkloadSpec field, and failing every such deploy would be more disruptive than the bug being fixed, especially since a camp that also declares a matching mirror gets real ingress anyway via the reconciler path -- expose.public on the deploy request itself was never load-bearing for that.")
//! @yah:handoff("DISCOVERED, not fixed (adjacent, separable, not named in this ticket): oss/yubaba/crates/yubaba/src/deploy/env_validate.rs has a second, fully-tested but entirely UNWIRED expose.public pipeline (CfTunnel trait, stage_cf_tunnel, EnvValidateCause::CfTunnelFailed) -- env_validate::run() has zero callers anywhere in production code, only its own test module. Its module doc claims it 'runs as part of the deploy sequence' which is false. Left alone since it also covers stage_image_pull/healthcheck/mesh_peering (out of R780's cloudflared-only scope) and touching it means deciding whether the whole deploy handler should migrate onto that pipeline -- a bigger call than this ticket. Worth its own ticket.")
//! @yah:verify("cargo test --manifest-path oss/yah-base/crates/workload-spec/Cargo.toml --all-features (unaffected by this change, sanity only)")
//! @yah:verify("cd oss/yubaba && cargo build -p yubaba --features testing -- BLOCKED as of 2026-08-19: fails in oss/kamaji/crates/kamaji/src/sibling.rs (2 call sites) due to @Ashguard:griffin's in-flight R783-F1 ContainerManifest split (uncommitted, unrelated to this change -- git diff --stat on oss/yah-base/crates/workload-spec/src/lib.rs shows +427/-18 uncommitted). camp.scratch.acquire also unavailable here (missing local image cr.yah.dev/yah-rust-warm:dev). Re-run once R783-F1 lands.")
//! @yah:verify("cd oss/yubaba && cargo test -p yubaba --features testing (same blocker as above)")
//! @yah:verify("rg -n 'cloudflared_url|register_cloudflare_tunnel|CloudflaredMock' oss/yubaba app/ -- should return zero hits outside annotation-block history")
//! @yah:gotcha("Full build/test verification could not be run this session due to shared-tree contention from R783-F1 (see verify notes). The change itself is a straightforward deletion + one log-statement swap, reviewed by hand for brace/type correctness, but has NOT been compiler-checked. Whoever signs off should run the verify commands once the workspace is green again.")
//! @yah:handoff("Filed R784 for the env_validate.rs discovery above (was previously just a prose note here) -- see R784 for the full keep-vs-delete decision.")
//!
//! @yah:relay(R854, "Back-to-back redeploy 500s with \"containerd: task already exists\" and leaves a healthy workload Failed with its secrets reaped")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-09-03T07:50:55Z)
//! @yah:next("Decide the contract first: should deploy be idempotent over a running workload? If yes, the deploy path must reap-or-adopt the existing containerd task instead of letting create collide. If no, it should return a typed 409-shaped refusal that does NOT tear the running workload down, rather than a 500 that leaves it Failed.")
//! @yah:next("Whichever way that goes, a deploy that fails at the backend must not leave a previously-healthy workload in Failed with no retry. Recovery here was one more deploy; that should not be something an operator has to know.")
//! @yah:next("Reconsider the two teardown_secret_dir sites at lib.rs around 3457 and 3607 with R848's secret_dir_exists guard in hand. They reaped a still-declared workload's secrets on this path.")
//! @yah:verify("Deploy the same workload twice back to back on one node and require both to return 200. This is also R848's end-to-end verify, which is blocked by this bug and cannot be closed until it is fixed.")
//! @yah:verify("After a deliberately failed backend deploy, assert the previously-running workload is still Running (or is restored) and that /run/yah/secrets/<ident>/ still holds its file.")
//! @yah:gotcha("REPRODUCED LIVE 2026-09-03 on us-west-001 running yubaba/kamaji 0.8.31, while closing R848's end-to-end verify. Two `yah cloud workload deploy yah-cloud-admin --where=node:us-west-001` calls back to back: the first returned deployed, the second returned 500 with kamaji BackendRefused, containerd 'creating task for yah-cloud-admin: Some entity that we attempted to create already exists / task yah-cloud-admin: already exists'. This is NOT R848 and not secrets: the deploy got PAST secret materialization to the container backend. R848's writer fix succeeded on all three deploys in that session.")
//! @yah:gotcha("IT IS NOT IDEMPOTENT AND NOT SELF-HEALING. The failed deploy left the workload in state Failed (GET /workloads reported state Failed) - a redeploy of a HEALTHY production workload took it down. A third deploy a moment later succeeded and restored it (Running, /__mesofact/health 200, / 401), so recovery is one more deploy, but nothing does that automatically and an operator who walks away after the 500 leaves the service down.")
//! @yah:gotcha("THE FAILURE PATH ALSO REAPS THE RUNNING WORKLOAD'S SECRET DIR. After the 500, /run/yah/secrets/yah-cloud-admin/ was gone. That is the backend-failure teardown at lib.rs around 3457 / 3607 - the two sites R848 deliberately left alone because they follow rt.teardown_workload, where reaping is normally correct. R848 fixed the equivalent overreach on the materialization-failure path only. Worth deciding whether these two want the same secret_dir_exists guard: here the reap fired on a workload that was still declared and about to be recovered.")
//! @yah:gotcha("LIKELY A RACE, NOT A LOGIC BUG - the second deploy arrives before the first deploy's containerd task has been reaped, so task creation collides with a task on its way out. Matches the timing (back-to-back CLI calls, seconds apart). It also explains why R848's filing gotcha recorded 'deploying the IDENTICAL spec a second time succeeded' on 0.8.30: there the first attempt 422'd early on secrets and never created a task, so the second never collided.")
//! @yah:handoff("ROOT CAUSE FOUND AND FIXED, and it is not where the ticket guessed. kamaji-bin's reap_container (oss/kamaji/crates/kamaji-bin/src/containerd.rs:715) fired SIGKILL and then deleted the task record in the very next breath with the result discarded (`let _ = tasks.delete(...)`). Containerd refuses to delete a task that has not reached STOPPED, so on a back-to-back redeploy that delete lost the race and was thrown away; the CONTAINER delete on the next line succeeded anyway (containerd's metadata store does not hold container and task together), leaving an orphan task with no container record. The redeploy then recreated the container fine and collided at CreateTask -- exactly the observed 'task yah-cloud-admin: already exists'. The inlined kamaji backend had the same bug wearing a blind `sleep(500ms)`.")
//! @yah:handoff("CONTRACT DECIDED, no operator call needed: deploy IS idempotent over a running workload. The code already said so -- oss/kamaji/crates/kamaji/src/containerd.rs:790 comments 'Idempotent redeploy: reap any prior generation(s)' -- so this was a broken implementation of a settled contract, not an open design question. The fix makes the claim true rather than renegotiating it.")
//! @yah:handoff("FIX (kamaji-containerd-core, the crate that exists so the two containerd backends cannot drift): new `reap_task(tasks, ns, container_id, timeout)` kills, waits on the shim's exit event (Tasks.Wait, bounded), deletes, and RE-PROBES -- it returns Ok only once containerd reports no task, and an Err naming the survivor's status otherwise. New `create_task_reaping_stale(...)` wraps Tasks.Create: on AlreadyExists it reaps the survivor and retries the create exactly once. Both containerd backends now call both. TASK_REAP_TIMEOUT = 15s.")
//! @yah:handoff("SELF-HEALING, so the 'operator walks away after the 500' failure mode is gone: the AlreadyExists retry means the collision that produced R854 now resolves inside the one deploy instead of needing a third one. The reap wait means it should not arise at all.")
//! @yah:handoff("SECRET REAP (the ticket's third next-step), both sites reconsidered with R848's guard in hand. lib.rs backend-failure arm (now ~3693) is GUARDED: `secret_dir_is_new` is hoisted to ~3311 and the reap only fires when THIS request created the dir. Rationale in-code: several kamaji refusals (tier guard, admission, unpullable image) reject BEFORE the running container is touched, so the files that arm unlinked were the live generation's. The headscale arm (~3497) is deliberately LEFT unguarded, with a comment saying why: the line above it has just called teardown_workload, so nothing is running off those files and reaping is correct there, not overreach.")
//! @yah:handoff("DISCOVERED AND FIXED -- a second, independent reason 'deploy twice, both 200' could not pass. Materializing a File secret APPENDS a read-only bind volume to the spec, `effective_archetype()` infers Appliance from any non-empty volumes, and the archetype registry was recorded from the MATERIALIZED spec. So every secret-mounting workload with no explicit `archetype` was registered as an Appliance, and the single-instance guard refused its every later deploy with 409 'appliance already live' -- before the request ever reached containerd. The archetype is now sampled from the operator-authored spec before materialization (`authored_archetype`, lib.rs ~3300 / ~3660). A declared appliance is unaffected; there is a test for each half.")
//! @yah:handoff("TESTABILITY WORK the fix needed: (a) kcc's reap loop is factored behind a small `TaskOps` trait (`reap_task_with`) so the retry/deadline logic -- the part that was wrong -- is exercised on a machine with no containerd; (b) yubaba gained `ServerState.local_secret_store_root` + `with_local_secret_store()`, because the handler hardcoded `SECRET_STORE_ROOT` and no test could otherwise resolve a LocalFile secret at all. Same value in production; the rotation task still uses the constant (noted in the field doc).")
//! @yah:verify("cargo test -p kamaji-containerd-core --features containerd-integration = 36 passed / 0 failed (4 new in `reap_tests`: retries until the task is actually gone; a never-dying task errors instead of reporting a phantom reap; a STOPPED-but-undeletable record says so distinctly; no task at all is a silent no-op that does not SIGKILL).")
//! @yah:verify("cargo test --workspace --features kamaji/containerd-integration (in oss/kamaji) = all green, 0 failed.")
//! @yah:verify("cargo check -p kamaji --features containerd-integration / -p kamaji-bin --features containerd-integration = clean (the two pre-existing warnings in pidfd.rs + server.rs are not mine).")
//! @yah:verify("cargo test -p yubaba --features testing --test testing -- integration_redeploy_failure:: = 4 passed / 0 failed. New file crates/yubaba/tests/integration_redeploy_failure.rs, registered in tests/testing.rs: a failed redeploy leaves the running generation's secret file byte-intact and the workload still declared, and the next deploy recovers; a failed FIRST deploy still reaps what it materialized; a secret-mounting server stays redeployable; a declared appliance is still single-instance.")
//! @yah:verify("cargo test -p yubaba --features testing = 605 lib tests passed / 0 failed. The tests/main.rs raft group showed failures in raft_member_registration / raft_membership_loop / raft_quorum_geography -- that is the PRE-EXISTING red W267 documents verbatim ('the SAME pre-existing raft red F1 documented ... the count still moves between runs'), it is containerd-free cluster-timing flake under a loaded camp, and nothing I touched is on its path.")
//! @yah:verify("NOT RUN, and it is the ticket's headline verify: two back-to-back deploys on us-west-001 both returning 200. That needs kamaji rebuilt and deployed to a live production node, which is an operator action, not a session one. Sequence when someone takes it: cross-build kamaji (DOCKER_DEFAULT_PLATFORM=linux/amd64), ship it to us-west-001, then `yah cloud workload deploy yah-cloud-admin --where=node:us-west-001` twice in a row -- both 200 -- and confirm /run/yah/secrets/yah-cloud-admin/ still holds its file after. That also closes R848's blocked verify.")
//! @yah:gotcha("THE LIVE ASSERTION IS STILL OPEN. Everything here is proven by unit + handler tests on a containerd-free host; the two-deploys-on-a-node assertion needs a kamaji rebuild shipped to us-west-001, which is an operator action. Do not read 'R854 fixed' as 'reproduced fixed on the box' until that runs.")
//! @yah:gotcha("SHARED-TREE NOTE: @Ashguard:vortex is live on R848 in the SAME function (deploy_workload_spec, oss/yubaba/crates/yubaba/src/lib.rs), and another session was mid-landing `Workload::TenantPassway` + oss/yubaba/crates/yubaba/src/tenant_passway.rs while this shipped -- which left yubaba's lib non-exhaustive at lib.rs:2965 and made the final yubaba re-run un-runnable. That break is theirs and transient; my hunks (secret_dir_is_new at ~3311, the guarded reap at ~3693, authored_archetype at ~3300/~3660, local_secret_store_root) were verified present by content afterwards. @Ashguard:vortex was notified over party.chat with the full hunk list.")
//! @yah:handoff("Done, pending the live assertion. Root cause was kamaji's task reap, not yubaba's secret handling: kamaji-bin's reap_container discarded the result of a Tasks.Delete it fired immediately after SIGKILL, containerd refuses to delete a non-STOPPED task, and the orphan collided with the redeploy's CreateTask. Fixed in kamaji-containerd-core (reap_task waits + verifies; create_task_reaping_stale reaps-and-retries once on AlreadyExists) and wired into both containerd backends. yubaba's backend-failure arm now applies R848's secret_dir_exists guard; the headscale arm is deliberately left unguarded with an in-code reason. Also fixed a second, independent blocker to 'deploy twice, both 200': secret materialization appends a bind volume, which made effective_archetype() infer Appliance, so the single-instance guard 409'd every redeploy of a secret-mounting workload before it reached containerd -- the archetype is now sampled from the authored spec. 8 new tests, all green. The peer collision noted in the gotchas is @Ashguard:blade (R852, tenant_passway); the one lib-test failure on the final run is theirs, in their own new module.")
//! @yah:verify("Final tree state, after @Ashguard:blade's tenant_passway landing: cargo test -p yubaba --features testing --test testing = 21 passed / 0 failed (my 4 among them); cargo test -p yubaba --features testing --lib = 611 passed / 1 failed, the failure being tenant_passway::tests::the_ident_is_the_domain_until_it_would_exceed_the_mesh_ident_cap, a peer's in-flight module.")
//! @yah:gotcha("DESTROY GOT SLOWER IN THE PATHOLOGICAL CASE, and anyone timing a rolling replace should know. POST /workloads/{ident}/destroy routes to kamaji-bin reap_container, which now WAITS for the task to actually die (kcc::TASK_REAP_TIMEOUT = 15s, bounded) instead of firing a delete and discarding the result. Normal case is unchanged -- it returns the moment the shim publishes the exit, which it always could have. A reap that exhausts the budget is still non-fatal: it logs 'kamaji: task reap did not complete' at warn and destroy still answers 'destroyed', so no new error surface. That warn line is the thing to grep if a redeploy ever still hits 'already exists' -- it means 15s was not enough, not that the retry is broken. Relevant to R848-B1's rolling verb (@Ashguard:vortex), which does destroy-then-deploy per machine; notified.")
//! @yah:gotcha("YOUR 15s REAP BOUND IS NOW LOAD-BEARING ON A CLIENT TIMEOUT (from R848-B1, Ashguard:vortex). Making destroy WAIT for the containerd task to reach STOPPED before deleting the record means POST /workloads/{ident}/destroy is no longer a control-plane decision, and cloud-client's destroy_workload was still inheriting DEFAULT_TIMEOUT = 5s. A destroy that actually used its reap budget would therefore fail client-side while the server was doing the right thing. Fixed in R848-B1: new DESTROY_TIMEOUT = 60s at crates/yah/cloud-client/src/lib.rs, applied per-request the same way DEPLOY_TIMEOUT is. If the 15s bound in kamaji's reap_task ever moves, re-check that 60s. The failure mode is silent and asymmetric - too short and `yah cloud workload rolling` (destroy-then-deploy per machine, R848-B1) reports a teardown failure for a teardown that succeeded, skips its re-deploy, and leaves the workload DOWN. The other caller with the same exposure was Remote-QED's MeshWardenClient reaping forge containers; it is covered by the same change.")

pub mod acme_issuer;
/// R858-T3: who owns the pinned-singleton appliance, elected from an
/// eligibility set instead of aliased to raft leadership.
pub mod appliance_ownership;
/// Per-domain TLS material in an object store instead of raft (R779 / W267) —
/// the store W267's free-tier ingress needs at 10k domains, where one
/// `PutSecret` per cert would rewrite the whole raft state on every node.
pub mod cert_store;
/// Deliver the fleet-shared cert to a passway that **systemd** supervises
/// (R600-F10) — the edge [`secret_reload`] cannot reach, because it walks the
/// deployed-workload registry and the live yah.dev doors are not workloads.
pub mod cert_materialize;
/// Publish `passway-demux`'s route table from the [`cert_store`] enrollment set
/// (R779 / W267) — the allowlist that keeps an SNI flood from reaching any
/// passway, made structural.
pub mod demux_routes;
/// Registering a custom tenant domain and printing the DNS its owner must
/// create (R779 / W267 §Decision 2) — the operator's end of [`cert_store`]'s
/// enrollment set, and the one place the `_acme-challenge` CNAME contract is
/// rendered for a human.
pub mod domain_admin;
/// Per-domain ACME issuance for custom tenant domains (R779 / W267 §Decision 2)
/// — sweeps the [`cert_store`] enrollment set, validates by DNS-01 CNAME
/// delegation, and writes the sealed pair to the object store rather than raft.
pub mod domain_issuer;
/// Arm one cold passway per enrolled custom domain (R852-F1 / W267) — the
/// far end of the splice [`demux_routes`] publishes, deployed through kamaji's
/// JIT tier so 10k idle domains cost 10k held fds rather than 10k processes.
pub mod tenant_passway;
/// The camp-RPC lane of the yah control plane (R609-F2): serve a
/// workspace's `yah camp --stdio` JSON-RPC to a NodeId dial, so a desktop
/// reaches a BYO VPS exactly as it reaches a managed rig. Opt-in via
/// `serve --camp-rpc-root <PATH>`.
pub mod camp_rpc;
/// The cell this raft group is: its id (the sovereign-group label) and the
/// jurisdiction that binds it, plus the gate that keeps a cell from taking a
/// voter outside its own jurisdiction (R736-T3, W250).
pub mod cell;
pub mod cheers_client;
/// The cluster-compatibility epochs this build declares (W275 / R625-F2) —
/// `cluster_protocol` (wire) and `state_epoch` (on-disk), read at compile time
/// from the same `cluster-epochs.json` the release manifest is built from.
pub mod cluster_epoch;
/// The deployment-wide rules this cluster runs under — voter admission,
/// external-ingress ownership, raft timings — named as a value instead of
/// hardcoded at the sites that obey them (R118-T9).
pub mod cluster_policy;
/// The yah control plane (R609-F1): an `mshr::Endpoint` bound on this
/// machine's hostkey, so yah-aware callers dial the node by `NodeId` over
/// NAT-punched QUIC instead of by IP/SSH. Opt-in via `serve --control-plane`.
pub mod control_plane;
pub mod deploy;
/// The "is that node still there?" port and its default raft-heartbeat impl
/// (R118-T9). Deployments with a second evidence channel supply their own.
pub mod failure_detector;
/// N+1 (N+2 across regions) warm-spare headroom accounting, and the
/// leader-only background loop that watches it (R737-T4, W253 §8).
pub mod headroom;
/// The second evidence channel W253 §7 asks for: a lease nodes renew over
/// plain HTTP, judged on a monotonic clock, plus the hysteresis and
/// readiness-gate logic a placement scheduler needs on top of it (R737-F2).
pub mod lease_detector;
/// Every node's client-side push onto `lease_detector`'s channel — the
/// `POST /mesh/lease-renew` caller, without which nothing ever renews
/// (R737-F3).
pub mod lease_renewal;
/// The headscale appliance's `WorkloadSpec` — the mesh coordinator described
/// as an ordinary pinned singleton so kamaji, not systemd, supervises it
/// (R591-F1).
pub mod headscale_appliance;
/// Headscale's on-disk state dir: the single writer for `headscale_dir`, and
/// the pre-start materialization of the coordinator's noise identity (R858-T2).
pub mod headscale_state;
pub mod identity;
pub mod leader;
/// Soft-prefer an anchor region for raft leadership, without ever blocking a
/// failover away from it (R734-T4).
pub mod leader_pin;
pub mod litestream;
/// Each node's own raft member row — the `region` tag the quorum-geography rule
/// is judged on, kept live rather than only checked at founding (R734-F5).
pub mod member_registration;
pub mod mesh;
pub mod node;
pub mod pond;
/// Live quorum health (R859-F2): `yubaba-failover.md`'s "do not fail over out
/// of a degraded quorum" pre-check, as a pure function over the voter set and
/// one detector's report.
pub mod quorum_health;
pub mod raft;
pub mod rollout;
pub mod runtime;
/// Leader-resident tenant placement scheduler (R737-F3, W246): re-places a
/// tenant off a confirmed-dead owner onto live, admitting capacity.
pub mod scheduler;
pub mod secret_reload;
pub mod secrets;
pub mod service_records;
/// R742-F1 (W305): the sovereign-group gate on `POST /raft/add-learner`.
pub mod sovereign_group;

#[cfg(feature = "testing")]
pub mod testing;

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    middleware::{self, Next},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use openraft::async_runtime::watch::WatchReceiver;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cheers_client::CheersClient;
use cluster_policy::{ClusterPolicy, GeographyVerdict, PromotionVerdict};
use failure_detector::FailureDetector;
use kamaji::sibling::KamajiSibling;
use kamaji::Kamaji as ContainerRuntime;
/// R605-F12. Re-exported because [`ServerState::sovereign_role`] is a public
/// field of this type and `yubaba serve --sovereign-role` parses it, so a
/// consumer would otherwise have to reach into `workload_spec` to name what
/// this crate's own API hands back.
pub use workload_spec::sovereign::SovereignRole;
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
/// `policy.mode` emitted by both headscale config renderers below (R861-T2).
///
/// `database` keeps the ACL policy inside `headscale.db`, which litestream
/// replicates, rather than in an `acls.yaml` that nothing replicates — and it
/// is the only mode in which headscale accepts `PUT /api/v1/policy`, so it is
/// what makes a declared policy pushable instead of merely readable. Verified
/// against the pinned v0.23.0 source: the value must be exactly `"file"` or
/// `"database"` or headscale `log.Fatal`s at startup.
///
/// Kept in lockstep with `cloud::mesh::POLICY_MODE` the same way
/// [`DEFAULT_HEADSCALE_VERSION`] is — there is no dependency edge from this
/// crate to `yah-cloud`.
pub const HEADSCALE_POLICY_MODE: &str = "database";
/// Permissive default ACL — all nodes may reach all nodes. Headscale's
/// file-policy loader parses HuJSON (JSON-with-comments), NOT YAML, so this
/// must stay JSON (a leading `---` fails with "invalid literal: ---").
pub const DEFAULT_ACL_POLICY_HUJSON: &str = "{\n  \"acls\": [\n    { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"] }\n  ]\n}\n";

/// Whether a `HeadscaleDeployRequest::acl_policy` carries nothing a
/// database-mode coordinator would lose (R861-T2).
///
/// True for an empty field and for [`DEFAULT_ACL_POLICY_HUJSON`] in any
/// formatting; false for anything else, which the deploy handler refuses.
///
/// The comparison is deliberately coarse — all whitespace is dropped and the
/// remainder compared to the same constant treated the same way. It is not a
/// HuJSON parser and does not try to be: this crate has none, and the only
/// question being asked is "is this byte-for-byte the permissive default we
/// already know we can drop?". Whitespace inside a JSON string literal would be
/// mangled by the strip, but that can only turn a match into a mismatch, and a
/// mismatch is the *safe* answer here (refuse the transplant) rather than the
/// dangerous one.
pub fn carried_policy_is_permissive_default(carried: &str) -> bool {
    fn squeeze(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }
    let carried = squeeze(carried);
    carried.is_empty() || carried == squeeze(DEFAULT_ACL_POLICY_HUJSON)
}
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
    /// R646-B1: where `download_headscale_binary` fetches the headscale binary
    /// from. `None` (the default) means the upstream GitHub release URL for the
    /// requested version — see [`headscale_linux_download_url`].
    ///
    /// Exists because `/headscale/deploy` and `/headscale/bootstrap` otherwise
    /// pull ~30MB off the public internet on the request path, which made every
    /// test touching those routes both slow and network-dependent: their outcome
    /// flipped between 200 and 500 with the weather, and against a client with a
    /// request timeout (`cloud_client`'s 5s) it surfaced as a transport error
    /// rather than as either. Tests point this at a `file://` fixture, which
    /// keeps the real curl/chmod/systemd path under test with a local source.
    pub headscale_download_url: Option<String>,
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

    /// R734-F5 (W247 §2): this node's geo region — the label `yubaba serve
    /// --region` was given, which an operator takes from the `region` this
    /// machine declares in `.yah/infra/machines/<name>.toml`.
    ///
    /// This is what the node knows about *itself*, and the only region it is in
    /// a position to assert. It reaches the cluster through
    /// [`member_registration`], which writes it into this node's
    /// [`MemberInfo`](raft::MemberInfo) row; every *other* node's region is read
    /// back out of that replicated map, never guessed here.
    ///
    /// `None` means untagged. A rig's voters legitimately have none (one failure
    /// domain — see
    /// [`QuorumGeography::SingleFailureDomain`](cluster_policy::QuorumGeography::SingleFailureDomain)),
    /// and a fleet node without one still runs: the founding gate refuses an
    /// untagged *founding set*, which is a separate check on a separate path.
    pub region: Option<String>,

    /// R742-F1 (W305 §F1): which sovereign group this node votes in — the label
    /// `yubaba serve --sovereign-group` was given, copied from the
    /// `sovereign_group` its machine declares in
    /// `.yah/infra/machines/<name>.toml`.
    ///
    /// A sovereign group is a **blast radius**, not a placement constraint: its
    /// own quorum, its own upgrade cadence, destroyable and rebuildable without
    /// touching anything else. Nothing here filters workloads, and
    /// `RequiredSpec::matches` deliberately cannot see it.
    ///
    /// What it does is refuse. [`sovereign_group::judge`] gates
    /// `POST /raft/add-learner` on it, so a `raft join` typed in a shell
    /// pointed at the wrong cluster is declined instead of trusted. That gate
    /// is in force exactly when this is `Some`: a node declaring no group has
    /// asserted no blast radius, so there is nothing to cross — see the module
    /// docs for why that is not a loophole.
    ///
    /// `None` is *this node's* answer only. Every other node's group is asked
    /// of that node ([`sovereign_group::ask_peer`]), never assumed here, and
    /// never taken from a request body.
    pub sovereign_group: Option<String>,

    /// R605-F12: whether this node may hold a seat in its group's quorum — the
    /// value `yubaba serve --sovereign-role` was given, copied from the
    /// `sovereign_role` its machine declares in
    /// `.yah/infra/machines/<name>.toml`.
    ///
    /// Membership and eligibility are different questions.
    /// [`sovereign_group`](Self::sovereign_group) says which blast radius this
    /// box shares — secrets, upgrade cadence, destruction — and this says
    /// whether it votes in it. us-west-003 is the case: prod's build worker on
    /// a residential uplink, which must never be able to stall the prod raft.
    ///
    /// Defaults to [`SovereignRole::Voter`], which is what declaring a group
    /// alone has always meant, so a node that never passes the flag behaves
    /// exactly as it did before this field existed.
    ///
    /// Read by [`sovereign_group::judge`] on both sides of a join: a non-voting
    /// *joiner* is refused, and a non-voting node that finds itself *serving*
    /// `add-learner` refuses too, because it is holding a raft seat its own
    /// declaration says it should not have.
    pub sovereign_role: SovereignRole,

    /// R736-T3 (W250): the legal jurisdiction this node's data is bound to — the
    /// label `yubaba serve --jurisdiction` was given, which an operator takes
    /// from the machine's own `.yah/infra/machines/<name>.toml`.
    ///
    /// Declaring one is what turns this node's
    /// [`sovereign_group`](Self::sovereign_group) into a **cell**: one raft
    /// group bound to one jurisdiction, named in the global tenant pointer by
    /// the group's own label. A group without this is a blast radius that is not
    /// a cell — the dev raft is the case — and it is `None` across the whole
    /// fleet until an operator says otherwise.
    ///
    /// Like [`region`](Self::region) and unlike anything replicated, this is
    /// only ever what *this process* was started with; every other node's
    /// jurisdiction is asked of that node ([`sovereign_group::ask_peer`]) and
    /// judged by [`cell::judge`] on the join path.
    pub jurisdiction: Option<String>,

    /// R118-T9: the rules this cluster runs under — whether learners can be
    /// promoted to voters, whether the raft leader carries the cluster's
    /// external identity, and what network the raft timers are sized for.
    ///
    /// Every decision point reads the *field* that answers its question; there
    /// is deliberately nothing here that says which preset built the value, so
    /// no handler can grow an `if this_is_a_gallery` branch. Defaults to
    /// [`ClusterPolicy::fleet`] — the behaviour yubaba had before the policy
    /// was named. See [`cluster_policy`] for why this shape.
    pub cluster_policy: ClusterPolicy,

    /// R118-T9: how this node answers "is that peer still there?".
    ///
    /// `None` until wired (`main.rs` attaches a
    /// [`RaftHeartbeatDetector`](failure_detector::RaftHeartbeatDetector)
    /// whenever raft is configured). `GET /raft/status` omits its liveness
    /// section rather than guessing when no detector is attached.
    pub failure_detector: Option<Arc<dyn FailureDetector>>,

    /// R737-F2 (W246, W253 §7): the lease-based evidence channel a placement
    /// scheduler is allowed to trust — distinct from `failure_detector`
    /// above, which stays wired to raft heartbeats for `/raft/status`'s
    /// operator-facing "who has raft heard from" view. `None` until wired
    /// (`main.rs`, alongside `failure_detector`, whenever raft is
    /// configured); `POST /mesh/lease-renew` answers 503 without it.
    pub lease_detector: Option<Arc<lease_detector::LeaseFailureDetector>>,

    /// R782 (W253 §7): the streamer-RPO evidence channel a placement
    /// scheduler is allowed to trust — the value-carrying, per-`(node,
    /// tenant)` sibling of `lease_detector` above, and pushed the same way
    /// (`POST /mesh/rpo-report`, never a raft write). `None` until wired
    /// (`main.rs`, alongside `lease_detector`, whenever raft is configured);
    /// `POST /mesh/rpo-report` answers 503 without it. See
    /// [`lease_detector::RpoWatermarkRegistry`]'s doc.
    pub rpo_registry: Option<Arc<lease_detector::RpoWatermarkRegistry>>,

    /// R737-T4 (W253 §8): the last headroom report the `headroom` background
    /// loop computed, or `None` before its first tick / on a node that never
    /// leads. Cached rather than recomputed per-request because computing it
    /// needs `TransitionTracker` state the loop owns, not a snapshot a
    /// request handler could rebuild cheaply. Surfaced on `GET /raft/status`.
    pub headroom: Mutex<Option<headroom::HeadroomReport>>,

    /// Read handle to this node's **locally-applied** raft state.
    ///
    /// Clones the same `Arc<RwLock<…>>` the raft node applies into, so every
    /// read here observes committed state with no round-trip, no quorum and no
    /// `.await` on consensus. `None` outside the raft cluster; wired in
    /// `main.rs` from [`raft::open_with_state_machine`].
    ///
    /// Two consumers, and the second is why this is named for the *state* and
    /// not for either of them (R118-T1 — it was `secret_state`):
    ///
    /// - R600-F6 (W273): admission resolves `SecretRef::Cluster` File mounts
    ///   from the replicated ciphertext map. A `None` here makes any
    ///   cluster-secret deploy fail closed.
    /// - R118-T1 (W138): `GET /cluster/singletons` answers "who owns this role"
    ///   for a realtime sibling process. That path may never block on a commit,
    ///   which is exactly what a locally-applied read handle buys.
    pub cluster_state: Option<raft::YubabaStateMachine>,

    /// R600-F6 (W273): node-local cluster KEK path (default
    /// [`secrets::CLUSTER_KEK_PATH`]; override in tests). Loaded per-deploy
    /// only when a spec carries a `SecretRef::Cluster` mount.
    pub cluster_kek_path: PathBuf,

    /// R779 (W267): object-store fallback for per-domain TLS material.
    ///
    /// Layered *behind* the raft replica by [`cert_store::LayeredSecretStore`],
    /// so raft answers everything it holds and only a `tls/<domain>/cert|key`
    /// name raft has never seen reaches the object store. `None` on an
    /// unconfigured node (see [`cert_store::CertStoreConfig::parse`]), which
    /// resolves exactly as it did before R779.
    ///
    /// The object-store trait is synchronous, so a fallback hit blocks the
    /// calling thread on an HTTPS GET. Acceptable here and nowhere hotter: the
    /// fallback is consulted only on a raft miss, on the deploy path, for a
    /// secret name that is per-domain TLS material.
    pub cert_store: Option<std::sync::Arc<cert_store::ObjectCertStore>>,

    /// R852-F2: this deployment's **public** ingress address(es) — the host
    /// running `passway-demux` on `:443` — as `GET /domains/{d}/onboarding`
    /// reports them to a tenant.
    ///
    /// Resolved once at boot from [`PUBLIC_INGRESS_ENV`] rather than read per
    /// request, so the handler holds no process-global state and a test can
    /// build a node with a known answer instead of racing `set_var` against
    /// whatever else the test binary is running.
    ///
    /// Empty means **unknown, and say so** — never guessed. The one address the
    /// daemon could otherwise reach for is the enrollment's `tls_backend`,
    /// which is the internal address the demux splices to; handing that to a
    /// tenant as their A record is the failure this field exists to avoid.
    pub public_ingress: Vec<String>,

    /// R852-F2: the zone `_acme-challenge.<domain>` is CNAME'd into, resolved
    /// at boot from `domain_issuer::DELEGATE_ZONE_ENV` — the same value the
    /// issuer runs with, so the record this node *reports* and the record it
    /// *publishes under* cannot disagree.
    ///
    /// `None` is a misconfiguration for a custom domain (the TXT would have to
    /// live in a zone we do not hold), and the onboarding payload renders it as
    /// one rather than printing a record the tenant cannot usefully create.
    pub domain_delegate_zone: Option<String>,

    /// R600-F6 (W273): root for materialized secret tmpfs files (default
    /// [`deploy::secret_mount::DEFAULT_SECRET_MOUNT_ROOT`]; override in tests).
    /// Each workload gets a `<root>/<ident>/` subdir, reaped on destroy.
    pub secret_mount_root: PathBuf,

    /// Root of the per-machine yubaba secret store a `SecretRef::LocalFile`
    /// resolves against (default [`secrets::SECRET_STORE_ROOT`]).
    ///
    /// R854: a field rather than the constant inlined at the resolver's
    /// construction, so a test can point it at a tempdir and drive the deploy
    /// handler's *whole* secret path — which is the only way to assert what
    /// the failure arms do with an already-materialized dir.
    ///
    /// Read by the deploy handler only. The rotation task
    /// ([`secret_reload::reload_once`]) still builds its resolver on the
    /// constant; identical in production, and its own tests construct
    /// resolvers directly rather than going through this state.
    pub local_secret_store_root: PathBuf,

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
    ///
    /// `KamajiSibling` (not a bare `KamajiClient`) so a `systemctl restart
    /// kamaji` on the fleet — e.g. a binary swap — doesn't strand yubaba
    /// answering every call with `PeerClosed` until yubaba itself restarts
    /// (live incident, 2026-08-13). `.current()` returns `None` while a
    /// reconnect is in flight, same as "no backend configured".
    pub constable_client: Option<KamajiSibling>,

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

    /// R860-T6 (W338): what each live workload's *requirement edges* committed
    /// this node to — the `supply = "self"` providers it stood up, and the
    /// placement group it belongs to. Keyed on mesh ident, with exactly the
    /// lifecycle of [`Self::archetype_registry`]: written by the deploy handler
    /// on success, removed by destroy.
    ///
    /// This is the rail R860-T4 said was missing. Placement computes a group
    /// camp-side (`cloud::config::placement_group`), but the node knew only
    /// per-workload archetypes — so `drain_workloads` skipped an Appliance and
    /// then happily drained the Server a `local` edge binds to it, and destroy
    /// left a self-supplied sidecar running with nothing left to serve. Both
    /// now read this map; see [`crate::deploy::self_supply`], which also
    /// explains why the node computes its own group view rather than calling
    /// cloud's (yubaba has no runtime dependency on cloud, by design).
    pub requirement_graph: Mutex<HashMap<String, crate::deploy::self_supply::DeployedRequirements>>,

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

    /// R594-F3/F6: upstream-discovery read-model — serving workload →
    /// mesh-IP:port + health, for an ingress proxy to consume. Always
    /// present; populated by `deploy_workload_spec`, retracted by
    /// `destroy_workload`, and health-refreshed by
    /// [`service_records::run`]'s sweep.
    ///
    /// Backed by a port ledger beside `identity.json` (see
    /// [`service_records`] §The port ledger) so records survive a yubaba
    /// restart without redeploying every serving workload — ports are
    /// admission-time knowledge that `list_workloads()` cannot re-derive.
    pub service_records: Arc<service_records::ServiceRecords>,

    /// R609-F1: the yah control-plane endpoint, bound on this machine's
    /// hostkey so yah-aware callers can dial it by `NodeId` (see
    /// [`control_plane`]). `None` unless the daemon was started with
    /// `serve --control-plane` — single-node dev and the containerized pond
    /// path have no use for it and shouldn't pay for a second socket.
    ///
    /// Held here rather than dropped into the accept task so later phases
    /// have a handle to it: R609-F2's desktop RPC surface registers a second
    /// ALPN on this same endpoint, and `/identity` reads its presence to
    /// advertise that the node is dialable at all.
    pub control_plane: Option<mshr::Endpoint>,

    /// R609-F2: which lanes [`control_plane`] is actually serving on that
    /// endpoint. Kept alongside the endpoint so `/identity` advertises
    /// exactly the ALPNs a caller may dial — derived from the same value
    /// that built the handler map, never re-stated.
    pub control_plane_planes: control_plane::Planes,

    /// This **node's own** mesh address — the one yubaba itself is bound to
    /// (R599-F12). Set from `--bind` in `main.rs`; `None` when yubaba is bound
    /// to loopback, to `0.0.0.0`, or to a non-IP host, i.e. whenever there is
    /// no mesh IP plane to place anything on.
    ///
    /// **The only mesh address this node ever hands out** (R844-B11). There
    /// used to be a second source — a `next_mesh_ip: AtomicU32` counter seeded
    /// to `100.64.0.1` on every node, drawn from by `alloc_mesh_ip()` for the
    /// container deploy path. Nothing ever *configured* the address it
    /// produced (`MeshAssignment::stub` applies no WireGuard), but containerd
    /// wrote it as the `yah.mesh_ip` label, `ServiceRecords::reconcile` read
    /// it back, and the record then advertised it as a dialable endpoint. Since
    /// the counter drew from the same `100.64.0.0/10` the real node addresses
    /// live in, allocation *n* of a process was `100.64.0.n` — a **different,
    /// real node**. Measured on us-west-001 2026-09-03: its `yah-cloud-admin`
    /// record advertised `100.64.0.3:4325` (us-east-001, connection refused)
    /// while the workload answered on `100.64.0.1:4325`, west's own address.
    /// Both the counter and `alloc_mesh_ip` are gone; see
    /// [`Self::workload_bind_ip`] for what replaced them.
    node_mesh_ip: Option<std::net::Ipv4Addr>,
}

/// Extract this node's own mesh address from a `--bind` argument (R599-F12).
///
/// Accepts `"<ip>:<port>"` or a bare `"<ip>"`. Returns `None` — meaning "this
/// node has no mesh IP plane, keep binding loopback" — for anything a workload
/// could not usefully be reached at from another node:
///
/// - `0.0.0.0` / `[::]`: a wildcard is not an address anything can be told to
///   dial, and handing it to a native workload would publish a bind that is
///   also reachable on the node's *public* interface.
/// - loopback: the pre-R599-F12 behaviour, and correct on a dev host.
/// - a hostname, or an IPv6 address: the mesh plane is IPv4 (`100.64.0.0/10`),
///   and `MeshAssignment.mesh_ip` is an `Ipv4Addr`.
fn parse_node_mesh_ip(bind: &str) -> Option<std::net::Ipv4Addr> {
    use std::net::{Ipv4Addr, SocketAddr};

    let ip = bind
        .parse::<SocketAddr>()
        .ok()
        .map(|s| s.ip())
        .or_else(|| bind.parse::<std::net::IpAddr>().ok())?;
    let std::net::IpAddr::V4(v4) = ip else {
        return None;
    };
    if v4 == Ipv4Addr::UNSPECIFIED || v4.is_loopback() {
        return None;
    }
    Some(v4)
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("state_path", &self.state_path)
            .field("headscale_dir", &self.headscale_dir)
            .field("compose_dir", &self.compose_dir)
            .field("raft_configured", &self.raft.is_some())
            .field("node_id", &self.node_id)
            .field("region", &self.region)
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
            .field(
                "constable_connected",
                &self
                    .constable_client
                    .as_ref()
                    .is_some_and(|c| c.current().is_some()),
            )
            .field("cheers_client_configured", &self.cheers_client.is_some())
            .field(
                "node_enrolled",
                &self.node_enrollment.lock().unwrap().is_some(),
            )
            .field("headscale_url", &self.headscale_url)
            .field("operator_bridge_mode", &self.operator_bridge_mode)
            .field("prometheus_url", &self.prometheus_url)
            .field(
                "pond_local_runtime_configured",
                &self.pond_local_runtime.is_some(),
            )
            .field(
                "control_plane_node_id",
                &self.control_plane.as_ref().map(|ep| ep.node_id()),
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

/// @yah:ticket(R844-B11, "Container service records advertise a counter-allocated mesh IP that collides with real node addresses")
/// @yah:status(review)
/// @yah:at(2026-09-03T22:13:27Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R844)
/// @yah:severity(high)
/// @yah:gotcha("MEASURED LIVE 2026-09-03, not inferred. `curl http://100.64.0.1:7443/service-records` (us-west-001) returns {\"ident\":\"yah-cloud-admin\",\"mesh_ip\":\"100.64.0.3\",\"ports\":[4325],\"endpoints\":[\"100.64.0.3:4325\"],\"health\":\"ready\"}. 100.64.0.3 is us-east-001 (raft voter 3), which does NOT run cloud-admin: `curl http://100.64.0.3:4325/` gets exit 7 connection-refused, while `curl http://100.64.0.1:4325/` answers 401. So the record is advertising an endpoint that is a DIFFERENT NODE and is dead, while the workload it describes is alive one address over. The record is not stale and not a replication artifact — west stamped the wrong address onto its own record at deploy time.")
/// @yah:gotcha("ROOT CAUSE, end to end, all five hops read on disk. (1) `ServerState::next_mesh_ip` is seeded `AtomicU32::new(u32::from_be_bytes([100,64,0,1]))` at oss/yubaba/crates/yubaba/src/lib.rs:1213 — the SAME constant on every node, no node identity in it. (2) `alloc_mesh_ip` (lib.rs:1564) is a bare `fetch_add(1)` → `Ipv4Addr::from(n)`, so allocation n of a process is 100.64.0.n. (3) The container deploy path takes that value: `MeshAssignment::stub(s.alloc_mesh_ip())` at lib.rs:3475. (4) It is never applied to anything — `MeshAssignment::stub` is a pure alias for `inlined` (oss/kamaji/crates/kamaji/src/lib.rs), which sets `wg_private_key: String::new()` so `has_wireguard()` is false; containerd only writes it as the `yah.mesh_ip` LABEL (containerd.rs:391) and echoes it in DeployResult (containerd.rs:459), per its own module doc at containerd.rs:20 (\"only uses the mesh_ip field in F1\"). (5) `ServiceRecords::reconcile` reads that label straight back off `WorkloadState::mesh_ip` into the record (service_records.rs:797, containerd.rs:845). So a container workload's advertised mesh_ip is a per-process counter drawn from the SAME 100.64.0.0/10 the real node addresses live in. cloud-admin was west's 3rd container deploy since yubaba start; .1/.2/.3 are west-001/south-001/east-001.")
/// @yah:gotcha("DO NOT CONCLUDE FROM A HEALTHY-LOOKING RECORD THAT THE FLEET IS FINE — the tier decides, not the node. W272 bundles go through `ServiceRecords::admit_bundle`, which uses `ServerState::node_mesh_ip` (a REAL address, service_records.rs:35, :703-727), so their records are correct. Container workloads go through the counter and are wrong. That is the entire reason us-east-001's `yah-marketing` record reads {\"mesh_ip\":\"100.64.0.3\",\"endpoints\":[\"100.64.0.3:8080\"]} and looks perfect: marketing is a bundle and .3 genuinely IS east's node address. The R844 relay's 2026-09-03 \"discovery works, blocker is gone\" gotchas were all measured against that ONE bundle record. No container record was checked. Re-measure per tier before trusting any of them.")
/// @yah:gotcha("THE EXISTING TEST LOOKS LIKE IT COVERS THIS AND DOES NOT. oss/yubaba/crates/yubaba/src/lib.rs:9545 asserts `assert_ne!(mesh.alloc_mesh_ip(), Ipv4Addr::new(100,64,0,3))` with the comment \"The allocator hands out a *different* address entirely — one that belongs to a workload, not to this node.\" It passes ONLY because it is the first allocation in that test (returns 100.64.0.1). Call `alloc_mesh_ip()` twice more before the assert and it fails. Do not treat it as a regression guard; replace it with one that pins the invariant it is gesturing at.")
/// @yah:next("THE BLAST RADIUS IS R844-T10 AND ONLY R844-T10, which is why this is filed here rather than as a standalone yubaba bug. Nothing is broken in production TODAY because the apex pins (`upstream_host` / `ingress_machines` in .yah/services/*/mirrors/cloud.toml) still name the address literally, so passway never consults `endpoints`. T10 deletes exactly those pins. The moment it lands, every FRONTED CONTAINER workload resolves to whatever node address the counter happened to hand it — a wrong-node, connection-refused upstream that reads as a healthy Ready record. That is precisely the \"renders a SUBSET rather than an empty set, which is worse than the failure R772 refused to ship because it looks like it worked\" failure mode R844-F4 exists to prevent, arriving through a different door.")
/// @yah:next("THE FIX IS TO STOP INVENTING AN ADDRESS, NOT TO PICK A BETTER RANGE. Since `stub`/`inlined` applies no WireGuard and containerd shares the host network namespace, a container on node N is reachable at N's own address — so the honest value for a container record is `ServerState::node_mesh_ip`, exactly what `admit_bundle` already uses. Preferred shape: make the record's address come from `node_mesh_ip` for BOTH tiers, and either delete `alloc_mesh_ip` or confine it behind `MeshAssignment::has_wireguard()` so it can only ever produce an address that something actually configures. Second-best if a per-workload identifier is still wanted for labels: keep the counter for the `yah.mesh_ip` label but STOP letting `reconcile` promote a label into a routable `endpoints` entry. Do not \"fix\" this by moving the counter to an unused sub-range — that keeps a fabricated address in the routing path and only delays the collision.")
/// @yah:next("Tier: Warrior — the code change is small and localized, but the call about what a container record's address MEANS spans yubaba, kamaji's mesh contract and R844-F4/F5's discovery semantics, and it gates a live-traffic cutover on the node fronting yah.dev.")
/// @yah:verify("LIVE, and it is the only verification that counts — a unit test cannot see this. After the fix, roll the node and re-read: `curl -s http://100.64.0.1:7443/service-records` must report yah-cloud-admin at 100.64.0.1:4325 (west's own address), and `curl -o /dev/null -w '%{http_code}' http://<advertised endpoint>` must answer 401, not connection-refused. Assert the general form on every clustered node, not just west: for each record, `mesh_ip` MUST equal that node's own `tailscale ip -4`.")
/// @yah:verify("cargo test -p yubaba --lib  # plus a NEW test replacing the false guard at lib.rs:9545: exhaust several allocations before asserting, so it fails if a record's address can ever equal a declared node address in .yah/infra/machines/*.toml")
/// @yah:handoff("FIXED AT THE SOURCE, and the class is gone rather than narrowed. `ServerState::alloc_mesh_ip` and its `next_mesh_ip: AtomicU32` are DELETED (they had exactly one production caller). The container deploy path at oss/yubaba/crates/yubaba/src/lib.rs now takes `crate::mesh::MeshAssignment::stub(s.workload_bind_ip())`, and `workload_bind_ip()` is `self.node_mesh_ip.unwrap_or(Ipv4Addr::LOCALHOST)` — the same answer the bundle path and `ServiceRecords::admit_bundle` already used, so BOTH tiers now advertise the answering node's own address and there is no second source to drift.")
/// @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib = 625 passed / 0 failed. cargo test -p yubaba --features testing --test testing -- integration_service_records:: = 11 passed / 0 failed. cargo check --manifest-path oss/yubaba/Cargo.toml --workspace --all-targets = exit 0 (only the two pre-existing unused-import warnings in mesofact_static.rs).")
/// @yah:handoff("WHY `node_mesh_ip` IS THE HONEST VALUE AND NOT JUST A BETTER GUESS, corrected from the ticket's own reasoning. The ticket said containerd \"shares the host network namespace\"; it does not — containerd.rs:461 says a container gets its OWN netns and its test `netns_present` at :1325 asserts \"default workload must get an isolated netns\". The real argument is narrower and stronger: `MeshAssignment::stub` leaves `wg_private_key` empty so `has_wireguard()` is false, `mesh.netns_name` is None, and containerd writes `mesh_ip` ONLY as the `yah.mesh_ip` label — so NOTHING configures the address on any interface, in any tier. The value was never routable; it only looked routable because it was drawn from 100.64.0.0/10. Reachability therefore comes from host networking, and the one container workload this fleet runs has it: .yah/infra/workloads/yah-cloud-admin.toml:133 sets `\"yah.network\" = \"host\"` (gated on tier = \"infra\"), which is exactly why cloud-admin answers on us-west-001's own 100.64.0.1:4325. Loopback is the fallback for a node with no mesh plane and is also the honest answer for a hypothetical isolated-netns container: unreachable, and VISIBLY so, unlike a neighbour's address.")
/// @yah:handoff("THE FALSE GUARD IS REPLACED, AND A SECOND STALE ASSERTION WAS FOUND BY THE FIX. (1) lib.rs's `assert_ne!(mesh.alloc_mesh_ip(), 100.64.0.3)` is gone; `the_node_mesh_address_comes_from_the_bind_flag` keeps only the part that was real, and a new `a_deployed_workloads_address_is_this_nodes_own_however_many_came_before` asserts STABILITY over 8 consecutive deploys plus the loopback fallback — repetition is the property the counter failed, so asserting it is what makes it a guard instead of a restatement. (2) DISCOVERED, not in the ticket: oss/yubaba/crates/yubaba/tests/integration_service_records.rs:178 asserted `record.mesh_ip.octets()[0] == 100` — \"somewhere in the CGNAT pool\", which is precisely the property THE BUG SATISFIED, since the counter drew from that pool and its third draw was us-east-001's real address. Replaced with `assert_eq!(record.mesh_ip, state.node_mesh_ip().unwrap())` on a node booted at 100.64.0.7 via a new `boot_on_mesh` helper (`.7` chosen because `.1/.2/.3` are both the counter's first three draws and the fleet's first three node addresses, so the old assertion could not discriminate). Reported to me by @Ashguard:dove, who hit it on R844-F15; fixed here because it is B11's semantics.")
/// @yah:verify("STILL OWED, AND IT IS THE VERIFICATION THAT COUNTS — a unit test cannot see this. The fleet must be rolled onto a yubaba carrying this change, then re-read per tier: `curl -s http://100.64.0.1:7443/service-records` must report yah-cloud-admin at 100.64.0.1:4325 (west's OWN address, not .3), and `curl -o /dev/null -w '%{http_code}' http://<advertised endpoint>` must answer 401 rather than connection-refused. General form on EVERY clustered node: each record's `mesh_ip` equals that node's own `tailscale ip -4`. Until that read is taken, this fix is proven in tests and unproven in production.")
/// @yah:gotcha("UNBLOCKS R844-F12's STATED LIMIT. F12 depends_on this ticket because its `upstream_host` derivation reads a machine's declared `mesh_ipv4`, and F12's own gotcha said that is \"sound for node-bound NATIVE workloads and its general validity depends on how B11 resolves\". It resolves in F12's favour: after this change EVERY tier's record address is the node's own mesh address, which is the same fact `.yah/infra/machines/<node>.toml` declares as `[registration].mesh_ipv4`. So the derivation is now valid for containers too, and the two sources agree by construction rather than by coincidence. F12 no longer needs to \"scope the fallback explicitly to the native shape and make it refuse rather than guess for containers\".")
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
        // R594-F6: the port ledger lives beside the hostkey/identity file, in
        // the same operator-provisioned state dir (`--state`'s parent), so it
        // inherits that directory's systemd StateDirectory grant rather than
        // needing a second writable path.
        let service_records = Arc::new(service_records::ServiceRecords::with_ledger(
            hostkey_dir_for(&state_path).join(service_records::LEDGER_FILE_NAME),
        ));

        Ok(Self {
            state_path,
            state: Mutex::new(state),
            service_records,
            headscale_dir: PathBuf::from(DEFAULT_HEADSCALE_DIR),
            compose_dir: PathBuf::from(DEFAULT_COMPOSE_DIR),
            headscale_download_url: None,
            scryer_endpoint: None,
            raft: None,
            node_id: None,
            region: None,
            sovereign_group: None,
            sovereign_role: SovereignRole::default(),
            jurisdiction: None,
            cluster_policy: ClusterPolicy::default(),
            failure_detector: None,
            lease_detector: None,
            rpo_registry: None,
            headroom: Mutex::new(None),
            cluster_state: None,
            cluster_kek_path: PathBuf::from(secrets::CLUSTER_KEK_PATH),
            cert_store: None,
            public_ingress: Vec::new(),
            domain_delegate_zone: None,
            secret_mount_root: PathBuf::from(deploy::secret_mount::DEFAULT_SECRET_MOUNT_ROOT),
            local_secret_store_root: PathBuf::from(secrets::SECRET_STORE_ROOT),
            secret_workloads: Default::default(),
            litestream_s3_url: None,
            session_id: new_session_id(),
            runtime: None,
            constable_client: None,
            cheers_client: None,
            ownership_rows: Mutex::new(HashMap::new()),
            archetype_registry: Mutex::new(HashMap::new()),
            requirement_graph: Mutex::new(HashMap::new()),
            workload_resources: Default::default(),
            node_probe: node::NodeProbe::new(),
            node_enrollment: Mutex::new(None),
            bootstrap_tokens: identity::bootstrap::BootstrapTokenRegistry::new(),
            headscale_url: None,
            operator_bridge_mode: OperatorBridgeMode::from_env(),
            rollout_store: Arc::new(std::sync::Mutex::new(rollout::RolloutStore::new())),
            prometheus_url: std::env::var("YAH_PROMETHEUS_URL").ok(),
            pond_local_runtime: None,
            pond_registry: Arc::new(pond::PondRegistry::new()),
            control_plane: None,
            control_plane_planes: control_plane::Planes::default(),
            // Start at 100.64.0.1 (first usable in the CGNAT /10 pool).
            node_mesh_ip: None,
        })
    }

    /// Record this node's own mesh address, derived from the `--bind` argument
    /// (R599-F12). See [`ServerState::node_mesh_ip`] for why a natively forked
    /// workload needs this rather than an allocated per-workload address.
    ///
    /// Only a genuinely node-local unicast address counts: loopback,
    /// `0.0.0.0`, and a non-IP host all mean "no mesh plane here", and are
    /// stored as `None` so kamaji keeps the pre-R599-F12 loopback bind.
    pub fn with_bind_addr(mut self, bind: &str) -> Self {
        self.node_mesh_ip = parse_node_mesh_ip(bind);
        self
    }

    /// This node's own mesh address, if it has one.
    pub fn node_mesh_ip(&self) -> Option<std::net::Ipv4Addr> {
        self.node_mesh_ip
    }

    /// The directory this node's hostkey — and therefore mshr's identity
    /// file, and therefore the control-plane `NodeId` — lives in, derived
    /// from the `--state` path. Exposed so the binary can bind the
    /// control-plane endpoint on the same key `load` generated, rather than
    /// re-deriving the convention at the call site (R609-F1).
    pub fn hostkey_dir(&self) -> PathBuf {
        hostkey_dir_for(&self.state_path)
    }

    /// R609-F1: attach the yah control-plane endpoint. Its `NodeId` is this
    /// machine's hostkey, so callers dial the node by the same `node_id`
    /// `GET /identity` reports.
    pub fn with_control_plane(mut self, endpoint: mshr::Endpoint) -> Self {
        self.control_plane = Some(endpoint);
        self
    }

    /// R609-F2: attach the endpoint together with the lanes it serves, so
    /// `/identity` can advertise the camp-RPC ALPN only when that lane is
    /// actually handled.
    pub fn with_control_plane_planes(
        mut self,
        endpoint: mshr::Endpoint,
        planes: control_plane::Planes,
    ) -> Self {
        self.control_plane = Some(endpoint);
        self.control_plane_planes = planes;
        self
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

    /// Attach a Kamaji UDS sibling (R406-T8). When set, workload-lifecycle
    /// handlers prefer this over the legacy in-process [`Self::runtime`]
    /// field. Build it with [`KamajiSibling::new`] (already connected once)
    /// before passing it in — the sibling owns its own reconnect watchdog
    /// from that point on.
    pub fn with_constable_client(mut self, client: KamajiSibling) -> Self {
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

    /// The mesh address a workload deployed by this node is reachable at
    /// (R844-B11).
    ///
    /// Replaces `alloc_mesh_ip`, which invented one. The distinction that
    /// matters is not "node vs workload" but **configured vs fabricated**: an
    /// address is only dialable if something wrote it onto an interface, and
    /// nothing in this tree does. `MeshAssignment::stub` leaves
    /// `wg_private_key` empty, so `has_wireguard()` is false and no WireGuard
    /// is ever applied; containerd's own module doc says it "only uses the
    /// `mesh_ip` field", writing it as the `yah.mesh_ip` label and nothing
    /// else. So a per-workload address is a string that travels from this
    /// function into a service record and out to passway without ever becoming
    /// true — and because it was drawn from `100.64.0.0/10`, it collided with
    /// the fleet's real node addresses.
    ///
    /// The node's own address, by contrast, *is* configured — yubaba is bound
    /// to it. A host-networked container (the only container shape the fleet
    /// runs: `.yah/infra/workloads/yah-cloud-admin.toml` sets
    /// `"yah.network" = "host"`, and kamaji permits it only for `tier =
    /// "infra"`) binds host ports directly, so the node's address is exactly
    /// where it answers. Same reasoning the bundle path already relies on for
    /// its native fork, and the same as `ServiceRecords::admit_bundle`.
    ///
    /// Loopback when this node has no mesh plane (`--bind 0.0.0.0` on a dev
    /// host), matching the bundle path's fallback. It is the honest answer for
    /// the isolated-netns shape too: such a container gets a fresh empty
    /// namespace with nothing but `lo` in it, so there is no address another
    /// node could dial. A record carrying `127.0.0.1` is visibly unreachable;
    /// one carrying a neighbour's address is not, and that is the failure this
    /// replaces.
    pub fn workload_bind_ip(&self) -> std::net::Ipv4Addr {
        self.node_mesh_ip.unwrap_or(std::net::Ipv4Addr::LOCALHOST)
    }

    /// Attach an already-opened raft node to the server state.
    pub fn with_raft(mut self, raft: raft::YubabaRaft) -> Self {
        self.raft = Some(raft);
        self
    }

    /// Set the [`ClusterPolicy`] this deployment runs under (R118-T9).
    ///
    /// Static for the life of the process — chosen by the operator at startup
    /// (`yubaba serve --cluster-profile`), never negotiated with peers. The raft
    /// node must be opened with the *same* policy, since its timings configure
    /// openraft itself; see [`raft::open`].
    pub fn with_cluster_policy(mut self, policy: ClusterPolicy) -> Self {
        self.cluster_policy = policy;
        self
    }

    /// Attach the [`FailureDetector`] this node answers liveness questions with
    /// (R118-T9).
    ///
    /// Wired in `main.rs` to a [`RaftHeartbeatDetector`] whenever raft is
    /// configured. A deployment with a second evidence channel (a local radio
    /// link, a management network) supplies its own implementation here instead
    /// of patching the raft view.
    ///
    /// [`RaftHeartbeatDetector`]: failure_detector::RaftHeartbeatDetector
    pub fn with_failure_detector(mut self, detector: Arc<dyn FailureDetector>) -> Self {
        self.failure_detector = Some(detector);
        self
    }

    /// Attach the [`lease_detector::LeaseFailureDetector`] `POST
    /// /mesh/lease-renew` writes into (R737-F2).
    ///
    /// Wired in `main.rs` alongside [`Self::with_failure_detector`], built
    /// from the same [`ClusterPolicy::liveness_thresholds`] so a LAN rig and
    /// a WAN fleet get channel-appropriate patience on both detectors.
    pub fn with_lease_detector(mut self, detector: Arc<lease_detector::LeaseFailureDetector>) -> Self {
        self.lease_detector = Some(detector);
        self
    }

    /// Attach the [`lease_detector::RpoWatermarkRegistry`] `POST
    /// /mesh/rpo-report` writes into (R782).
    ///
    /// Wired in `main.rs` alongside [`Self::with_lease_detector`]. Unlike
    /// that detector this one needs no [`ClusterPolicy`] thresholds — it
    /// records a reported value, not a liveness judgement — so it can be
    /// constructed unconditionally wherever raft is configured.
    pub fn with_rpo_registry(mut self, registry: Arc<lease_detector::RpoWatermarkRegistry>) -> Self {
        self.rpo_registry = Some(registry);
        self
    }

    /// Set this node's raft node ID — needed by [`GET /mesh/leader-health`].
    pub fn with_node_id(mut self, id: raft::YubabaNodeId) -> Self {
        self.node_id = Some(id);
        self
    }

    /// R734-F5: declare this node's geo region (`yubaba serve --region`).
    ///
    /// Setting it here does not by itself put the tag in replicated state —
    /// [`member_registration::spawn`] is what writes this node's row. See
    /// [`ServerState::region`] for the label space.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// R742-F1: declare this node's sovereign group
    /// (`yubaba serve --sovereign-group`).
    ///
    /// Setting it turns on the `POST /raft/add-learner` gate for this node —
    /// see [`ServerState::sovereign_group`] and [`sovereign_group`].
    pub fn with_sovereign_group(mut self, group: impl Into<String>) -> Self {
        self.sovereign_group = Some(group.into());
        self
    }

    /// R605-F12: declare whether this node votes in its sovereign group
    /// (`yubaba serve --sovereign-role`).
    ///
    /// Only meaningful alongside [`Self::with_sovereign_group`] — a node in no
    /// group has no quorum to be eligible for. See
    /// [`ServerState::sovereign_role`].
    pub fn with_sovereign_role(mut self, role: SovereignRole) -> Self {
        self.sovereign_role = role;
        self
    }

    /// R736-T3: declare this node's jurisdiction (`yubaba serve
    /// --jurisdiction`), which makes its sovereign group a **cell**.
    ///
    /// See [`ServerState::jurisdiction`] and [`cell`]. `main.rs` validates the
    /// pair through [`cell::identify`] before calling this, so a daemon never
    /// reaches a state where it holds a jurisdiction that names no cell.
    pub fn with_jurisdiction(mut self, jurisdiction: impl Into<String>) -> Self {
        self.jurisdiction = Some(jurisdiction.into());
        self
    }

    /// Which cell this node is in, derived from the two labels it declares —
    /// `None` when it is in none (R736-T3).
    ///
    /// Derived rather than stored so the id and the jurisdiction cannot drift
    /// apart: the cell id *is* [`sovereign_group`](Self::sovereign_group), never
    /// a copy of it. An invalid combination — a jurisdiction with no group, or a
    /// label the global tenant pointer would refuse — answers `None` here, which
    /// is the safe degrade (the gate is simply not in force). `main.rs` refuses
    /// to start on exactly those inputs, so on a daemon this branch is
    /// unreachable; it exists for a `ServerState` assembled directly in a test.
    pub fn cell(&self) -> Option<cell::CellIdentity> {
        cell::identify(self.sovereign_group.as_deref(), self.jurisdiction.as_deref())
            .ok()
            .flatten()
    }

    /// R600-F6 (W273): attach the read handle to the raft-replicated
    /// cluster-secret map so admission can resolve `SecretRef::Cluster` File
    /// mounts. Wired in `main.rs` from [`raft::open_with_state_machine`]; a
    /// `None` `cluster_state` makes any cluster-secret deploy fail closed, and
    /// leaves `GET /cluster/singletons` answering 503 rather than guessing.
    pub fn with_cluster_state(mut self, sm: raft::YubabaStateMachine) -> Self {
        self.cluster_state = Some(sm);
        self
    }

    /// The active workload backend, preferring the sibling `KamajiClient`
    /// (cloud-tier deploys via `kamaji.service`) over the legacy in-process
    /// `runtime`. `None` in stub mode (no backend configured). The deploy
    /// handler and the R600-F4 [`secret_reload`] rotation task both route
    /// through this so they drive the same supervisor.
    pub fn active_backend(&self) -> Option<Arc<dyn ContainerRuntime + Send + Sync>> {
        self.constable_client
            .as_ref()
            .and_then(KamajiSibling::current)
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

    /// Override the per-machine secret store a `SecretRef::LocalFile` reads
    /// from (R854) — the third path the deploy handler touches, and the one a
    /// test needs redirected before a `LocalFile` secret can resolve at all.
    pub fn with_local_secret_store(mut self, root: impl Into<PathBuf>) -> Self {
        self.local_secret_store_root = root.into();
        self
    }

    /// R779 (W267): attach the object-store fallback for per-domain TLS material.
    ///
    /// Built from the daemon environment at startup
    /// ([`cert_store::CertStoreConfig::parse`] then `connect`); an unconfigured
    /// node never calls this and keeps resolving from raft alone.
    pub fn with_cert_store(mut self, store: cert_store::ObjectCertStore) -> Self {
        self.cert_store = Some(std::sync::Arc::new(store));
        self
    }

    /// R852-F2: what `GET /domains/{d}/onboarding` reports. `delegate_zone` is
    /// the issuer's own; `ingress` is this deployment's public address(es), and
    /// an empty list is the honest "not known here".
    pub fn with_domain_onboarding(
        mut self,
        delegate_zone: Option<String>,
        ingress: Vec<String>,
    ) -> Self {
        self.domain_delegate_zone = delegate_zone
            .map(|z| z.trim().trim_matches('.').to_string())
            .filter(|z| !z.is_empty());
        self.public_ingress = ingress;
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

    /// R646-B1: override where the headscale binary is downloaded from, so a
    /// test can exercise `/headscale/deploy` and `/headscale/bootstrap` without
    /// reaching the internet. `url` is passed to `curl` verbatim, so a
    /// `file://` path to a fixture works; see [`ServerState::headscale_download_url`].
    pub fn with_headscale_download_url(mut self, url: impl Into<String>) -> Self {
        self.headscale_download_url = Some(url.into());
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
        // R646: the open half of the telemetry surface — a producer publishes
        // domain metrics this node cannot measure for itself (audio xruns, BLE
        // advert rate) and they merge flat into `/node/usage`.
        .route("/node/metrics", post(report_node_metrics))
        .route("/node/metrics", get(get_node_metrics))
        .route("/node/metrics/{source}", delete(withdraw_node_metrics))
        .route("/register-hostkey", post(register_hostkey))
        .route("/headscale/deploy", post(headscale_deploy))
        .route("/headscale/bootstrap", post(headscale_bootstrap))
        .route("/headscale/health", get(headscale_health_check))
        // R040-F21: Cloudflare healthcheck — 200 iff raft leader + headscale running
        .route("/mesh/leader-health", get(mesh_leader_health))
        // R737-F2: every node's periodic push onto the leader's node-lease
        // evidence channel — see `lease_detector` module doc for why this is
        // separate from raft's own heartbeat.
        .route("/mesh/lease-renew", post(mesh_lease_renew))
        .route("/mesh/rpo-report", post(mesh_rpo_report))
        // R040-F7: service management (R040-era compose path, superseded by /workloads)
        // R706 (W294): metadata only — name, updated_at, access-rule summary.
        .route("/secrets", get(list_secrets))
        // R118-T1 (W138): singleton-role ownership, served from locally-applied
        // state so a realtime sibling process never awaits a raft commit.
        .route("/cluster/singletons", get(cluster_singletons))
        // R732-T4 (W245): the epoch transport. Read-only, served from this
        // node's LOCAL applied state — no leader round-trip. There is
        // deliberately no matching write route: ClaimTenant / TransferTenant /
        // RenewTenantLease already ride the generic `POST /raft/write`.
        .route("/tenants/{id}", get(get_tenant_ownership))
        .route("/services", get(get_services))
        .route("/compose", post(deploy_compose))
        // R091-F1: WorkloadSpec-based orchestration (replaces compose path)
        .route("/workloads", get(list_workloads))
        .route("/workloads/{ident}/state", get(get_workload_state))
        .route(
            "/workloads/{ident}/deploy-status",
            get(get_workload_deploy_status),
        )
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
        // R734-T1: Pre-Vote. A peer asks whether we *would* grant it a vote at
        // a hypothetical next term, before it inflates the cluster's term by
        // campaigning for real. A build without this route answers 404, which
        // the caller (raft/network.rs) reads as a grant so a mixed-version roll
        // stays live.
        .route("/raft/pre-vote", post(raft_pre_vote))
        // openraft 0.10 streaming snapshot (replaces chunked /raft/install-snapshot)
        .route("/raft/snapshot", post(raft_snapshot))
        // R040-F20: raft operator API
        .route("/raft/status", get(raft_status))
        .route("/raft/initialize", post(raft_initialize))
        // R569-F3: add a node to a *running* quorum as a non-voting learner
        // (dynamic membership). `/raft/initialize` only founds a fresh cluster;
        // this is the join-an-existing-cluster path a macOS fleet node takes.
        .route("/raft/add-learner", post(raft_add_learner))
        // R118-T9: the counterpart — promote a caught-up learner to voter, if
        // the cluster policy's VoterAdmission allows it (the fleet's does not).
        .route("/raft/promote-voter", post(raft_promote_voter))
        // R734-T3: the third membership verb — take nodes out of the cluster.
        // Takes a SET, because the surviving voter count must stay odd and so
        // 5 -> 3 is one change removing two members.
        .route("/raft/remove-member", post(raft_remove_member))
        .route("/raft/write", post(raft_write))
        .route("/raft/transfer-leader", post(raft_transfer_leader))
        // R608-B11: openraft-native TransferLeader message — the leader's
        // RaftNetworkV2 posts here so the target campaigns at once.
        .route("/raft/transfer-leader-msg", post(raft_transfer_leader_msg))
        // R594-F8: upstream discovery for an ingress proxy. `?ready=true`
        // filters to routable records. Read-only, same mesh-bound posture as
        // GET /workloads — this is the sovereign twin of the rented arm's
        // "generate tunnel ingress rules from deployed workloads" API call.
        .route(
            service_records::DISCOVERY_PATH,
            get(service_records::get_service_records),
        )
        // R852-F2 (W267 §Decision 2): the two DNS records a custom domain's
        // owner must create, for a UI to render. Read-only and derivation-only
        // — see the handler for why this is a GET on the daemon while
        // `yubaba domain enroll` deliberately is not.
        .route("/domains/{domain}/onboarding", get(get_domain_onboarding))
        // R374-F2: pond (sim-tier mesofact-static) status surface
        .route("/pond/deploy", post(pond::deploy))
        .route("/pond/teardown", post(pond::teardown))
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
    tokio::spawn(service_records::run(Arc::clone(&state)));
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
    // R594-F6: same refresh sweep as `serve`. Spawned here rather than in
    // `build_router` because the router is also built by tests, which want no
    // background task; both real entry points are exactly these two.
    tokio::spawn(service_records::run(Arc::clone(&state)));
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
    /// Wire-compatibility epoch this build speaks
    /// ([`cluster_epoch::CLUSTER_PROTOCOL`]) — may a node running this binary
    /// sit in one raft cluster with a node running some other build. Two nodes
    /// may mix iff these are equal (W275 "Cluster compatibility epochs").
    ///
    /// This is here because a **version string cannot answer that question**.
    /// yubaba went 0.8.18 → 0.8.20 — a patch-looking bump — while the raft
    /// snapshot route and payload changed underneath, and two different builds
    /// both call themselves `0.8.20`. `.yah/infra/machines/*.toml` records only
    /// the version, no build SHA, so today the only way to tell which protocol
    /// a live voter speaks is to probe `/raft/snapshot` vs
    /// `/raft/install-snapshot` and read the 404. This field replaces that
    /// guesswork with a declaration (R625-F4).
    ///
    /// Always `Some` on a build that carries R625; the executor sees `None` from
    /// an *older* node, and must treat that as **unproven**, never as a match.
    cluster_protocol: u32,
    /// On-disk state epoch ([`cluster_epoch::STATE_EPOCH`]) — can this binary
    /// read the previous binary's raft log/snapshot, and can you roll *back* to
    /// it. Tracked separately from `cluster_protocol` on purpose: openraft
    /// 0.9→0.10 broke both at once, and one combined flag would have hidden the
    /// rollback hazard (W275 §5 "Roll-back is symmetric").
    state_epoch: u32,
}

async fn health(State(s): State<Arc<ServerState>>) -> Json<HealthBody> {
    Json(HealthBody {
        status: "ok",
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        cluster_protocol: cluster_epoch::CLUSTER_PROTOCOL,
        state_epoch: cluster_epoch::STATE_EPOCH,
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
            .and_then(KamajiSibling::current)
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

/// Env key naming this deployment's **public** ingress address(es), comma- or
/// space-separated — the host running `passway-demux` on `:443` (R852-F2).
///
/// Asked for, never derived, exactly as `yubaba domain enroll --ingress` is and
/// for the same reason: the only address the daemon can otherwise reach for is
/// the enrollment's `tls_backend`, which is the *internal* address the demux
/// splices to. Handing a tenant a loopback address as their A record is a
/// worse answer than "I do not know", so unset renders as unknown rather than
/// as a guess.
pub const PUBLIC_INGRESS_ENV: &str = "YUBABA_PUBLIC_INGRESS";

/// Read [`PUBLIC_INGRESS_ENV`] into the address list an onboarding payload
/// carries. Unset, blank, or all-separators yields an empty list.
///
/// Public so `main.rs` can resolve it once at boot into
/// [`ServerState::public_ingress`] — the request path must not read the
/// environment, both because a handler with hidden global inputs is untestable
/// and because this test binary runs its modules in parallel.
pub fn public_ingress_targets(raw: Option<String>) -> Vec<String> {
    raw.unwrap_or_default()
        .split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// `GET /domains/{domain}/onboarding` — the two DNS records the owner of a
/// custom domain must create (R852-F2 / W267 §Decision 2).
///
/// **Why this read is on the daemon while the writes are not.** `yubaba domain
/// enroll` reads and writes the bucket directly — no daemon, no quorum, no
/// leader — because the enrollment set is not raft state and routing an admin
/// write through the daemon would add a dependency the data does not have. That
/// argument is about *writes needing no coordination*; it does not say a
/// tenant-facing UI should hold R2 credentials in order to render two DNS
/// names. This is derivation plus one existence check, and it is the same
/// mesh-bound read posture `GET /service-records` and `GET /workloads` already
/// have.
///
/// **404 for a domain that was never enrolled**, deliberately: the enrollment
/// set is the structural allowlist (R779 P5), so rendering onboarding for a
/// name outside it would walk a tenant through creating records that can never
/// validate — and would let anyone use this endpoint to mint plausible-looking
/// instructions for a domain this deployment will not serve.
///
/// The payload is `domain_admin::Onboarding::to_json` verbatim; the record
/// names come from `acme_engine::dns01_record_name`, the same function the
/// issuer publishes under. Nothing here formats a name.
async fn get_domain_onboarding(
    State(s): State<Arc<ServerState>>,
    axum::extract::Path(domain): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let Some(store) = s.cert_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!(
                    "no cert store configured on this node — set {} so the enrollment set \
                     can be read",
                    cert_store::BUCKET_ENV
                )
            })),
        )
            .into_response();
    };

    let enrolled = {
        let domain = domain.clone();
        tokio::task::spawn_blocking(move || store.enrollment(&domain)).await
    };
    match enrolled {
        Ok(Ok(Some(_))) => {}
        Ok(Ok(None)) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!(
                        "{domain} is not enrolled — `yubaba domain enroll {domain} \
                         --tls-backend <addr>` first. The enrollment set is the allowlist, \
                         so a name outside it cannot be issued for."
                    )
                })),
            )
                .into_response();
        }
        Ok(Err(e)) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("reading the enrollment set: {e}") })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("enrollment lookup panicked: {e}") })),
            )
                .into_response();
        }
    }

    // Both inputs were resolved at boot (see `ServerState::public_ingress`):
    // the request path reads no environment, so this handler's answer is a pure
    // function of the node's configuration plus the enrollment check above.
    let onboarding = domain_admin::Onboarding::new(
        &domain,
        domain_admin::validation(&domain, s.domain_delegate_zone.as_deref()),
        s.public_ingress.clone(),
    );
    Json(onboarding.to_json()).into_response()
}

/// `POST /node/metrics` — publish domain metrics this node cannot measure.
///
/// The open half of the telemetry surface. yubaba knows how to read CPU,
/// memory and disk; it has no idea what an audio xrun is, and hardcoding a
/// struct for every consumer's domain would grow a private telemetry path per
/// downstream. A producer instead publishes `{source, metrics, ttl_ms}` here
/// and the keys merge flat into `GET /node/usage` beside the built-in ones.
///
/// The body **replaces** that source's previous set, so a metric the producer
/// stops sending disappears rather than pinning its last value. `ttl_ms`
/// bounds how long the values are trusted if the producer goes silent — see
/// [`node::DomainMetrics`] for why a dead producer must stop reading healthy.
///
/// 204 on success. 400 names the offending source or key: the producer is
/// remote, and the response body is the only debugging channel it has.
async fn report_node_metrics(
    State(s): State<Arc<ServerState>>,
    Json(report): Json<node::MetricReport>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    match s.node_probe.domain().report(report) {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )),
    }
}

/// `GET /node/metrics` — just the domain-metric contribution to `/node/usage`.
///
/// Same keys the usage payload carries, without the machine measurements.
/// Exists because verifying a push should not cost a CPU sampling window:
/// `/node/usage` sleeps for the sample interval, and a producer confirming its
/// own publish landed has no reason to pay for that.
async fn get_node_metrics(
    State(s): State<Arc<ServerState>>,
) -> Json<std::collections::BTreeMap<String, serde_json::Value>> {
    Json(s.node_probe.domain().snapshot())
}

/// `DELETE /node/metrics/{source}` — withdraw a source immediately.
///
/// The clean-shutdown path: a producer that knows it is going away says so,
/// rather than leaving its scope to look slow for a TTL and stale for twenty
/// more. 204 if it was there, 404 if it wasn't.
async fn withdraw_node_metrics(
    State(s): State<Arc<ServerState>>,
    axum::extract::Path(source): axum::extract::Path<String>,
) -> StatusCode {
    if s.node_probe.domain().withdraw(&source) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

#[derive(Serialize)]
struct IdentityBody {
    hostkey_fingerprint: String,
    algorithm: String,
    /// Hex-encoded mshr NodeId — same key as `hostkey_fingerprint`, added by
    /// R593-T2 so `/identity` reports the mshr machine identity directly.
    node_id: String,
    /// R609-F1: ALPN of this node's yah control-plane listener, present
    /// **only** when one is actually bound (`serve --control-plane`).
    ///
    /// `node_id` alone can't tell a caller whether the node is dialable over
    /// iroh — every node has one, because it is the hostkey. This field is
    /// the advertisement: present means "you may dial `node_id` on this
    /// ALPN"; absent means the node is HTTP-only and a dial would hang until
    /// it timed out.
    #[serde(skip_serializing_if = "Option::is_none")]
    control_plane_alpn: Option<String>,

    /// R609-F2: ALPN of this node's camp-RPC lane, present **only** when
    /// the operator enabled it (`serve --camp-rpc-root <PATH>`).
    ///
    /// Separate from `control_plane_alpn` rather than folded into a list
    /// because they answer different questions: the control ALPN says "this
    /// node is dialable at all", this one says "and it will serve you a
    /// camp". A desktop that sees the first but not the second should show
    /// the node as reachable and its camps as SSH-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    camp_rpc_alpn: Option<String>,
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
                control_plane_alpn: s
                    .control_plane
                    .as_ref()
                    .map(|_| control_plane::CONTROL_PLANE_ALPN_STR.to_string()),
                // `camp_rpc_lane()`, not `camp_rpc`: a lane withheld for
                // want of an admission policy (R609-F3) is not served, and
                // advertising it would send a desktop into a dial that
                // fails at ALPN negotiation.
                camp_rpc_alpn: s.control_plane.as_ref().and_then(|_| {
                    s.control_plane_planes
                        .camp_rpc_lane()
                        .map(|_| camp_rpc::CAMP_RPC_ALPN_STR.to_string())
                }),
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
///   - Headscale is running on this node, per [`headscale_liveness`].
///
/// Returns **503** in all other cases (follower, raft not configured, headscale
/// stopped).  Cloudflare will route Headscale HTTPS traffic only to nodes that
/// return 200, so leader changes flip ingress automatically within the CF LB
/// health-check cadence (~10 s).
///
/// R858-B11: this used to call `probe_headscale_local` **alone** — no supervisor
/// query and not even the systemd fallback `/headscale/health` had. So on a
/// coordinator running the appliance the way yubaba deploys it, this endpoint
/// answered 503 unconditionally: not merely a wrong dashboard field, but the
/// signal an external load balancer uses to decide the leader is not serving.
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

    let headscale_running = headscale_liveness(&s).await.running();

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

// ── Node-lease renewal (R737-F2, W253 §7) ─────────────────────────────────────

/// `POST /mesh/lease-renew` — the node-lease evidence channel's only write.
///
/// Every node calls this periodically against whatever it currently believes
/// is the raft leader (the same `current_leader` discovery `POST /raft/write`
/// forwards against). Deliberately unconditional: a renewal landing on a
/// follower is recorded and then simply never read (nothing but the
/// leader-resident scheduler consults `lease_detector`), the same graceful
/// degradation `RaftHeartbeatDetector` already has for the analogous case.
#[derive(Deserialize)]
struct LeaseRenewRequest {
    node_id: raft::YubabaNodeId,
}

async fn mesh_lease_renew(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<LeaseRenewRequest>,
) -> StatusCode {
    match &s.lease_detector {
        Some(detector) => {
            detector.renew(req.node_id);
            StatusCode::OK
        }
        None => StatusCode::SERVICE_UNAVAILABLE,
    }
}

// ── Streamer RPO reporting (R782, W253 §7) ────────────────────────────────────

/// `POST /mesh/rpo-report` — the streamer-RPO evidence channel's only write.
///
/// Every `tenant-streamer` process pushes here after each tail tick, against
/// whatever it currently believes is the raft leader (discovered over HTTP —
/// see `tenant_streamer::rpo_report`'s module doc, since that process has no
/// `raft.metrics()` of its own to read leadership from directly). Same
/// posture as [`mesh_lease_renew`]: recorded unconditionally, even on a
/// follower, and simply never read there — the leader-resident scheduler is
/// the only consumer.
#[derive(Deserialize)]
struct RpoReportRequest {
    node_id: raft::YubabaNodeId,
    tenant: String,
    watermark_age_secs: Option<u64>,
}

async fn mesh_rpo_report(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<RpoReportRequest>,
) -> StatusCode {
    match &s.rpo_registry {
        Some(registry) => {
            registry.report(
                req.node_id,
                workload_spec::TenantId(req.tenant),
                req.watermark_age_secs.map(std::time::Duration::from_secs),
            );
            StatusCode::OK
        }
        None => StatusCode::SERVICE_UNAVAILABLE,
    }
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

    if let Some(client) = s.constable_client.as_ref().and_then(KamajiSibling::current) {
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
/// `GET /workloads/{ident}/deploy-status` (R330-F33) — progress of an
/// **asynchronous** bundle deploy.
///
/// Distinct from `/state` on purpose. `/state` answers from kamaji's `List`,
/// which only knows workloads a backend is already supervising, so a bundle
/// that is still materializing is simply absent there and reads as a 404.
/// That is exactly the window a caller needs to observe, which is what this
/// route exists to expose.
///
/// `200 { state, detail }` — `state` is one of kamaji's `WorkloadState`s,
/// `detail` is the failure reason when `state` is `Failed` and `null`
/// otherwise. `404` means kamaji has no deploy on record for the ident: it was
/// never admitted here, or kamaji restarted (deploy progress is in-memory).
/// `501` when this yubaba has no kamaji client — the legacy in-process runtime
/// has no asynchronous deploy to report on.
/// How long `/deploy-status` waits on kamaji before answering `504`
/// (R746-B11). This is a registry lookup on the far side, not work — the
/// budget is generous only so a momentarily busy kamaji isn't reported as
/// stalled.
const DEPLOY_STATUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn get_workload_deploy_status(
    State(s): State<Arc<ServerState>>,
    axum::extract::Path(ident): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let freshness = raft_freshness(&s);
    let headers = [
        ("x-state-freshness", freshness),
        ("x-workload-source", "kamaji"),
    ];

    let Some(client) = s.constable_client.as_ref().and_then(KamajiSibling::current) else {
        let (status, error) = if s.constable_client.is_some() {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "kamaji sibling is reconnecting — retry shortly",
            )
        } else {
            (
                StatusCode::NOT_IMPLEMENTED,
                "deploy status needs a kamaji backend; this yubaba has none",
            )
        };
        return (
            status,
            [
                ("x-state-freshness", freshness),
                ("x-workload-source", "runtime"),
            ],
            Json(serde_json::json!({ "error": error })),
        )
            .into_response();
    };

    let id = kamaji_proto::WorkloadId::new(ident.clone());
    // R746-B11. Every other failure mode below answers with a status code —
    // 503 reconnecting, 501 no kamaji, 404 UnknownWorkload, 502 anything else
    // — so a kamaji that simply never replies was the one case that produced
    // an unbounded hang and parked the caller's connection instead. Reading a
    // registry entry is a sub-millisecond operation on the far side; anything
    // past this deadline is a stalled sibling, and the caller needs to be told
    // that rather than left to wait for it.
    let answered = tokio::time::timeout(DEPLOY_STATUS_TIMEOUT, client.deploy_status(&id)).await;
    let Ok(answered) = answered else {
        return (
            StatusCode::GATEWAY_TIMEOUT,
            headers,
            Json(serde_json::json!({
                "error": format!(
                    "kamaji did not answer DeployStatus for {ident} within {}s",
                    DEPLOY_STATUS_TIMEOUT.as_secs()
                )
            })),
        )
            .into_response();
    };
    match answered {
        Ok((state, detail)) => (
            StatusCode::OK,
            headers,
            Json(serde_json::json!({ "state": state, "detail": detail })),
        )
            .into_response(),
        // kamaji distinguishes "no deploy on record" from every other failure,
        // and a polling caller has to see that as terminal rather than retrying
        // against an ident that will never appear.
        Err(kamaji::sibling::ClientError::Remote {
            code: kamaji_proto::ErrorCode::UnknownWorkload,
            message,
        }) => (
            StatusCode::NOT_FOUND,
            headers,
            Json(serde_json::json!({ "error": message })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            headers,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn get_workload_state(
    State(s): State<Arc<ServerState>>,
    axum::extract::Path(ident): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let freshness = raft_freshness(&s);

    if let Some(client) = s.constable_client.as_ref().and_then(KamajiSibling::current) {
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
    if let Some(client) = s.constable_client.as_ref().and_then(KamajiSibling::current) {
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
            // R860-T6 (W338 §"Placement consequences" 2), the gap R860-T4
            // inherited to this ticket: the check above is PER-WORKLOAD, so a
            // Server bound to an Appliance by a `local` edge was drained alone —
            // which breaks the group the same way placing it alone would. A
            // group moves together or not at all. The predicate is
            // `workload_spec::group_is_drainable`, the single implementation
            // `cloud::config::group_is_drainable` also delegates to: placement
            // and drain disagreeing about drainability is precisely the drift
            // the requirement graph was plumbed to the node to close.
            let blocking = {
                let graph = s.requirement_graph.lock().unwrap();
                crate::deploy::self_supply::group_blocking_drain(&graph, ident_key)
            };
            if let Some(requirer) = blocking {
                tracing::info!(
                    id = entry.id.as_str(),
                    ident = ident_key,
                    requirer = %requirer,
                    "drain: skipping a member of a non-drainable placement group (W338)"
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
        // R852-F1: a per-tenant passway IS deployed to a node, but not through
        // this HTTP verb. Its declaration is generated from the enrollment set
        // by `tenant_passway::reconcile_once`, which goes straight to
        // `KamajiClient::deploy_envelope` — there is no operator-authored
        // manifest to POST here, and a hand-posted one would be overwritten by
        // the next sweep. Reject with that pointer rather than half-supporting
        // a path nothing drives.
        workload_spec::Workload::TenantPassway(w) => (
            w.domain.clone(),
            Some(
                "tenant-passway workloads are generated from the cert-store enrollment set by \
                 yubaba's tenant_passway reconciler, not posted — enroll the domain with \
                 `yubaba domain enroll <domain> --tls-backend <addr>` and the next sweep arms it"
                    .into(),
            ),
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
    let Some(kamaji) = s.constable_client.as_ref().and_then(KamajiSibling::current) else {
        let error = if s.constable_client.is_some() {
            "kamaji sibling is reconnecting — retry shortly".to_string()
        } else {
            "no kamaji sibling attached — bundle workloads need kamaji \
             (start yubaba with --kamaji-socket and kamaji with \
             --bundle-cache-dir + --bundle-origin)"
                .to_string()
        };
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "rejected",
                "ident": ident,
                "error": error,
            })),
        )
            .into_response();
    };

    // R599-F12: hand kamaji this node's own mesh address so the forked serve
    // process binds something reachable from another node, instead of the
    // loopback it was previously pinned to. A native workload is a plain host
    // process with no namespace of its own, so an *allocated* per-workload
    // address would simply fail to bind — the node address is the only correct
    // answer here. `None` (dev host, `0.0.0.0`) keeps the loopback bind. R844-
    // B11 retired the allocator this contrasted with; the container branch now
    // reaches the same answer through `ServerState::workload_bind_ip`.
    let mesh = s.node_mesh_ip.map(crate::mesh::MeshAssignment::stub);

    match kamaji.deploy_envelope(&id, &workload, mesh.as_ref()).await {
        Ok(()) => {
            tracing::info!(
                ident = %ident,
                bind_ip = ?s.node_mesh_ip,
                "bundle workload deployed via kamaji"
            );

            // R844-F1: register the bundle as a discoverable upstream. This is
            // the bundle tier's analogue of the container branch's
            // `upsert_deployed` call, and it has to live here because this is
            // the only point that holds all three facts at once — the
            // operator-facing workload name, this node's mesh IP, and the
            // bundle's own declared serve port. Without it the entire W272
            // tier deployed and served while `GET /service-records` stayed
            // empty forever: the sweep's `reconcile` deliberately never
            // backfills an ident nothing admitted, so there was no later
            // recovery point.
            //
            // Keyed on `name`, NOT on `ident`. `ident` above is the bundle
            // DIGEST (the content, which changes on every rebuild); `name` is
            // the stable handle kamaji's `list()` reports as `mesh_ident`, and
            // `reconcile` keys on exactly that. A digest-keyed record would be
            // retracted by the very first 15s sweep.
            let declared_port = match &workload {
                workload_spec::Workload::MesofactStatic(w) => {
                    w.serve_bundle.as_ref().and_then(|b| b.port)
                }
                _ => None,
            };
            s.service_records.admit_bundle(
                &workload_spec::MeshIdent(name.clone()),
                s.node_mesh_ip,
                declared_port,
            );

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

/// Type-erased re-entry into [`deploy_workload_spec`] — R860-T6.
///
/// A `supply = "self"` provider is deployed by the deploy handler calling
/// itself, and an `async fn` cannot name its own future's type. Erasing to
/// `dyn Future` here breaks that cycle; the recursion is bounded at one level by
/// `validate::shape`, which forbids a `provides` spec from self-provisioning.
fn deploy_workload_spec_boxed(
    s: Arc<ServerState>,
    body: WorkloadDeployBody,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = axum::response::Response> + Send>> {
    Box::pin(deploy_workload_spec(State(s), Json(body)))
}

/// Type-erased re-entry into [`destroy_workload`] — R860-T6. Same reason as
/// [`deploy_workload_spec_boxed`]: the teardown cascade destroys a workload's
/// self-supplied providers by re-entering the destroy handler for each, so every
/// provider gets the same cheers revoke, secret reap and registry clearing the
/// requirer gets.
fn destroy_workload_boxed(
    s: Arc<ServerState>,
    ident: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = axum::response::Response> + Send>> {
    Box::pin(destroy_workload(State(s), axum::extract::Path(ident)))
}

/// Tear down the providers a requirer stood up before its own deploy failed
/// (R860-T6).
///
/// A `self` provider exists only to serve its requirer, so a requirer that never
/// started must not leave one running: that is the same ownership claim the
/// teardown cascade makes, applied to a deploy that got partway. Best-effort and
/// idempotent — destroy answers `not_found` for anything already gone.
async fn rollback_self_supplied(s: &Arc<ServerState>, requirer: &str, provisioned: &[String]) {
    for p_ident in provisioned.iter().rev() {
        tracing::warn!(
            ident = %requirer,
            provider = %p_ident,
            "requirer deploy failed after its provider was stood up; tearing the provider back down"
        );
        let _ = destroy_workload_boxed(Arc::clone(s), p_ident.clone()).await;
    }
}

/// Roll back and refuse: the requirer could not stand one of its carried
/// providers up, so it cannot run (R860-T6).
///
/// `FAILED_DEPENDENCY` for the same reason the R860-B3 gate uses it — an
/// unsatisfiable requirement, named, rather than a generic 500 that makes the
/// operator guess which half of the group failed.
async fn self_supply_refusal(
    s: &Arc<ServerState>,
    ident: &str,
    provider: &str,
    secret_dir_is_new: bool,
    provisioned: Vec<String>,
    reason: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    rollback_self_supplied(s, ident, &provisioned).await;
    if secret_dir_is_new {
        crate::deploy::secret_mount::teardown_secret_dir(&s.secret_mount_root, ident);
    }
    tracing::warn!(
        ident = %ident,
        provider = %provider,
        reason = %reason,
        "deploy refused: a self-supplied provider could not be stood up"
    );
    (
        StatusCode::FAILED_DEPENDENCY,
        Json(serde_json::json!({
            "status": "rejected",
            "ident": ident,
            "error": format!(
                "self-supplied provider {provider:?} could not be deployed: {reason}"
            ),
        })),
    )
        .into_response()
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
                    Ok(spec) => workload_spec::Workload::container(spec),
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
        workload_spec::Workload::Container(manifest) => match manifest.into_spec() {
            Ok(spec) => spec,
            // R783-F1 / W324: `kind = "container"` also names a local
            // Dockerfile RECIPE, which has no digest until it is built and so
            // has nothing yubaba can admit. It cannot arrive over the postcard
            // wire (the serializer refuses it), but this endpoint takes JSON.
            Err(recipe) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({
                        "status": "rejected",
                        "ident": recipe.name,
                        "runtime": "stub",
                        "error": "this is a local container BUILD RECIPE (a [build] table), \
                                  not a digest-pinned WorkloadSpec — build it first and deploy \
                                  the lowered spec",
                    })),
                )
                    .into_response();
            }
        },
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

    // R555-F5: admission runs HERE, before anything is resolved on this spec's
    // behalf — not only in kamaji, where F4 put it.
    //
    // Two reasons, and the first is the ticket. Secret resolution happens in
    // yubaba (the KEK never leaves the node) and *precedes* the backend call, so
    // a gate that lives only in kamaji sees the spec after the credentials have
    // already been decrypted onto tmpfs, and sees `spec.secrets` emptied into
    // binds — it is checking a document from which the thing it is meant to
    // authorize has been erased. Second, and more mundane: a workload that will
    // be refused should not first have a cluster secret decrypted for it.
    //
    // Same posture, same pinned keys, same env vars as kamaji — but yubaba and
    // kamaji are separate units, so both need `YAH_ADMISSION_KEYS`. Under the
    // default permissive policy an ungranted spec is untouched, which is every
    // service on the fleet today.
    let admitted_grant = match workload_spec::admission::check_grant(&spec) {
        Ok(g) => g,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "status": "rejected",
                    "ident": spec.expose.mesh.identity.0,
                    "error": format!("workload not admitted: {e}"),
                })),
            )
                .into_response();
        }
    };

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
    // it, so `active_backend()` (which resolves `s.constable_client`'s
    // current, possibly-reconnecting client) coerces straight into the same
    // trait object the rest of this handler already drives — deploy_workload
    // + the failure teardowns below stay backend-agnostic, untouched.
    //
    // This closes the deploy/state split-brain: `list`, `get_state`, and
    // `drain` already prefer Kamaji, so a Kamaji-attached yubaba that
    // deployed via the legacy runtime would never find its own workloads when
    // reading them back. Deploy must use the same backend the read handlers do.
    let backend: Option<Arc<dyn ContainerRuntime + Send + Sync>> = s.active_backend();

    if let Some(rt) = backend {
        // R844-B11: this node's OWN mesh address, never an invented one. The
        // value travels straight through to the workload's service record —
        // containerd writes it as the `yah.mesh_ip` label, echoes it back in
        // `DeployResult.mesh_ip`, and `upsert_deployed` below publishes it as
        // the endpoint passway dials. It was an `alloc_mesh_ip()` counter draw,
        // which made the third container deploy of any yubaba process advertise
        // `100.64.0.3` — us-east-001. See `ServerState::workload_bind_ip`.
        let mesh = crate::mesh::MeshAssignment::stub(s.workload_bind_ip());
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
        // R854: the archetype as the OPERATOR declared it, sampled before
        // secret materialization rewrites `spec`.
        //
        // `effective_archetype()` infers `Appliance` from a non-empty
        // `volumes`, and materializing a File secret *appends a read-only bind
        // volume* — so registering the materialized spec's archetype silently
        // reclassified every secret-mounting workload as an appliance, and the
        // single-instance guard above then refused its every later deploy with
        // 409 "appliance already live". A yubaba-injected secret bind is not
        // the per-ident state that guard exists to protect (W244 §Schema gaps
        // #1); the operator's own spec is what decides.
        let authored_archetype = spec.effective_archetype();
        // R860-T6 (W338): the requirement edges as the OPERATOR declared them,
        // sampled here for the same reason `authored_archetype` is. Secret
        // materialization appends bind volumes, and `group_is_drainable` asks
        // `effective_archetype()`, which infers `Appliance` from a non-empty
        // `volumes` — reading the materialized spec would classify every
        // secret-mounting group as non-drainable (the R854 trap, one layer up).
        let carried_providers = crate::deploy::self_supply::self_supplied_providers(&spec);
        let placement_group = crate::deploy::self_supply::local_group_members(&spec);
        // R854: does the secret dir belong to THIS request? Hoisted out of the
        // materialization block below because every failure path from here to
        // the backend's answer has to know it. `false` until proven otherwise,
        // so a workload with no File secrets — nothing was materialized — never
        // reaps a dir it did not create.
        let mut secret_dir_is_new = false;

        // R603-T5: create the host-persistent produced dir before the backend
        // binds it. kamaji's OCI mapper is a pure mapper — it does not mkdir a
        // Bind source, and runc refuses a bind whose source is missing. The dir
        // lives outside the container rootfs so the produced tar survives the
        // container being reaped after a daemon outage; yubaba serves reads from
        // it (GET /workloads/{ident}/produced) and reaps it on destroy. Also
        // opportunistically sweep stale produced dirs so orphans (a run whose
        // consumer never came back) don't accumulate unbounded.
        ensure_forge_state_dirs(&spec).await;
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
                let Some(sm) = &s.cluster_state else {
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
                // R706 (W294): bind the resolver to THIS spec's identity, so
                // every cluster secret it reads is checked against the record's
                // access rule. The consumer is derived from the spec yubaba is
                // about to run — not from anything the caller asserts — so a
                // hand-rolled deploy cannot claim to be a workload it isn't
                // without also actually being deployed under that name.
                // R555-F5: a dispatched build's workload name is a fresh
                // `forge-<uuid>` every run, so `SecretAccess::Workloads` can
                // never name it and `AllowAny` was the only rule under which it
                // could read a credential at all. The verified grant carries a
                // durable identity underneath the ephemeral one — the signed
                // recipe name plus the key that vouched for it — which
                // `SecretAccess::Recipes` matches on. `admitted_grant` is
                // `Some` only past attribution, signature AND coverage, so this
                // cannot be asserted by a caller.
                let consumer = crate::deploy::secret_mount::consumer_for(
                    &spec,
                    admitted_grant.as_ref(),
                );
                // R779 (W267): raft first, object cert store second. Per-domain
                // TLS material is deliberately not in raft — 10k certs would
                // rewrite the whole state on every PutSecret — so a
                // `tls/<domain>/cert|key` name raft has never seen falls through
                // to R2. Everything raft does hold answers locally, unchanged,
                // and an unconfigured node's `None` fallback holds nothing.
                let secret_store =
                    crate::cert_store::LayeredSecretStore::new(sm.clone(), s.cert_store.clone());
                match crate::secrets::ClusterResolver::from_kek_file(
                    secret_store,
                    &s.cluster_kek_path,
                    &s.local_secret_store_root,
                    consumer,
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
                    s.local_secret_store_root.clone(),
                ))
            };

            // R848: only reap on failure if this materialization is the one that
            // created the dir. On a *re*deploy the dir already holds the running
            // container's secrets — reaping it there unlinks live material on a
            // failure path that never touched the running workload, which is how
            // a deterministic redeploy bug (write_secret_file's EACCES) came to
            // look flaky: the reap made every retry a first materialization.
            secret_dir_is_new = !crate::deploy::secret_mount::secret_dir_exists(
                &s.secret_mount_root,
                &ident,
            );
            if let Err(e) = crate::deploy::secret_mount::materialize_file_secrets(
                &mut spec,
                &ident,
                resolver.as_ref(),
                &s.secret_mount_root,
            ) {
                // Fail closed: a missing / undecryptable cluster secret rejects
                // the deploy rather than starting a workload without its cert.
                if secret_dir_is_new {
                    crate::deploy::secret_mount::teardown_secret_dir(&s.secret_mount_root, &ident);
                }
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

        // R860-T6 (W338 §"Design"): stand up every `supply = "self"` provider
        // this spec carries, before the gate and before the requirer itself.
        //
        // Each provider goes through THIS SAME HANDLER, re-entered with its own
        // spec. That is the load-bearing choice, not an implementation
        // convenience: W338 §"Each member keeps its own mesh identity" requires
        // a provider to be independently discoverable, and re-entry is what
        // gives it its own admission check, its own secret materialization, its
        // own archetype-registry entry and its own service record. A helper that
        // shortcut to `rt.deploy_workload` would collapse the group under the
        // requirer's identity and make the `anywhere` case unexpressible.
        //
        // Locality needs no branch here. The provider lands on whichever node
        // received the requirer's deploy, which is what `local` demands and what
        // `prefer-local` prefers; `anywhere` + `self` is satisfied by a local
        // provider like any other. Camp-side, `elect_node` picks that node once
        // for the whole group — see the R860-T4 note in cloud/src/config.rs.
        //
        // Recursion terminates: `validate::shape` (`check_requires`) forbids a
        // `provides` spec from itself carrying a `self` requirement, so this is
        // one level deep by construction.
        let mut provisioned: Vec<String> = Vec::new();
        for provider in &carried_providers {
            let p_ident = provider.expose.mesh.identity.0.clone();
            // Already standing on this node — a redeploy of the requirer must
            // not try to stand its sidecars up a second time. For an Appliance
            // provider the single-instance guard would refuse with 409 and take
            // the requirer's redeploy down with it; for a Server it would be a
            // pointless restart of a healthy provider mid-flight.
            if s.archetype_registry.lock().unwrap().contains_key(&p_ident) {
                tracing::info!(
                    ident = %ident,
                    provider = %p_ident,
                    "self-supplied provider is already live on this node; not redeploying it"
                );
                continue;
            }
            let p_body = match serde_json::to_value(provider) {
                Ok(spec_json) => WorkloadDeployBody {
                    spec: spec_json,
                    operator_signature: None,
                    requesting_camp_id: req.requesting_camp_id.clone(),
                    on_behalf_of_user: req.on_behalf_of_user.clone(),
                    id: None,
                },
                Err(e) => {
                    return self_supply_refusal(
                        &s,
                        &ident,
                        &p_ident,
                        secret_dir_is_new,
                        provisioned,
                        format!("serializing the carried provider spec: {e}"),
                    )
                    .await;
                }
            };
            let resp = deploy_workload_spec_boxed(Arc::clone(&s), p_body).await;
            if !resp.status().is_success() {
                return self_supply_refusal(
                    &s,
                    &ident,
                    &p_ident,
                    secret_dir_is_new,
                    provisioned,
                    format!("provider deploy answered {}", resp.status()),
                )
                .await;
            }
            tracing::info!(
                ident = %ident,
                provider = %p_ident,
                "self-supplied provider deployed ahead of its requirer"
            );
            provisioned.push(p_ident);
        }

        // R860-B3: the dependency gate and the `FromMesh` env resolver, at the
        // last point before the workload starts.
        //
        // `deploy::mesh_resolve` had been written, tested and documented for
        // three relays without a single production caller — `depends_on` was
        // documented as enforced and enforced nothing, and an
        // `EnvValue::FromMesh` reference was never rendered from real cluster
        // state (kamaji refused the unresolved value outright, so such a
        // workload simply could not deploy). Both are wired here.
        //
        // Placement is deliberate: AFTER secret materialization, so a spec that
        // will be refused for a missing dependency has already been fully
        // admitted and can be torn down by the same failure paths; and BEFORE
        // `rt.deploy_workload`, because "block until the dependency appears"
        // means nothing once the container is running.
        //
        // R860-T2: satisfaction is Ready-and-local-aware, not presence. The
        // node's own mesh address is threaded in because that is the only thing
        // a provider's record `mesh_ip` can be compared against to decide a
        // `locality = "local"` requirement — there is no node identifier on
        // this seam. `None` (yubaba on loopback / 0.0.0.0) makes a `local`
        // requirement unsatisfiable, deliberately: see `requirement_satisfied`.
        {
            let mesh_state = crate::deploy::mesh_resolve::ServiceRecordMeshState::new(
                &s.service_records,
                s.node_mesh_ip(),
            );
            let deadline = crate::deploy::mesh_resolve::compute_dependency_deadline(
                &spec,
                &mesh_state,
                crate::deploy::mesh_resolve::DEFAULT_DEPENDENCY_WAIT_PER_DEP,
            );
            let gate = crate::deploy::mesh_resolve::await_dependencies(
                &spec,
                &mesh_state,
                deadline,
                crate::deploy::mesh_resolve::DEFAULT_POLL_INTERVAL,
            )
            .await;
            if let Err(e) = gate {
                // R860-T6: the requirer will not run, so its carried providers
                // have nothing left to serve.
                rollback_self_supplied(&s, &ident, &provisioned).await;
                if secret_dir_is_new {
                    crate::deploy::secret_mount::teardown_secret_dir(&s.secret_mount_root, &ident);
                }
                tracing::warn!(
                    ident = %ident,
                    error = %e,
                    "deploy refused: a declared dependency never appeared on the mesh"
                );
                return (
                    StatusCode::FAILED_DEPENDENCY,
                    Json(serde_json::json!({
                        "status": "rejected",
                        "ident": ident,
                        "error": format!("dependency wait failed: {e}"),
                    })),
                )
                    .into_response();
            }

            let resolver = crate::deploy::mesh_resolve::StateMeshResolver::new(&mesh_state);
            let rendered = workload_spec::validate::resolve_env_from_mesh(&spec.env, &resolver);
            match rendered {
                Ok(env) => spec.env = env,
                Err(e) => {
                    // R860-T6: same reasoning as the gate arm above.
                    rollback_self_supplied(&s, &ident, &provisioned).await;
                    if secret_dir_is_new {
                        crate::deploy::secret_mount::teardown_secret_dir(
                            &s.secret_mount_root,
                            &ident,
                        );
                    }
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(serde_json::json!({
                            "status": "rejected",
                            "ident": ident,
                            "error": format!("mesh env resolution failed: {e}"),
                        })),
                    )
                        .into_response();
                }
            }
        }

        match rt.deploy_workload(&spec, &mesh).await {
            Ok(result) => {
                // Public ingress (R780): yubaba's own deploy handler has no
                // mechanism to register a Cloudflare Tunnel route for a
                // workload — that's owned by the mirror-declared reconciler
                // path (reconciler::ingress::ensure_tunnel_ingress, W267 /
                // R594-F11), driven externally by `yah cloud apply` /
                // `mirror up` over a MirrorConfig zone/port slot, not by this
                // deploy request. `expose.public` on a raw workload deploy is
                // therefore always port-mapping only; warn loudly (not
                // silently) so the operator knows to declare a mirror
                // instead of assuming this call publishes anything.
                if let Some(pub_expose) = &spec.expose.public {
                    tracing::warn!(
                        ident = %ident,
                        hostname = %pub_expose.hostname,
                        port = pub_expose.port,
                        "expose.public is set but yubaba's deploy handler does not register \
                         Cloudflare tunnels; declare a mirror with ingress = \"cloudflare-tunnel\" \
                         (zone/port matching this workload) and run `yah cloud apply` to publish \
                         it — this workload is reachable only via port-mapping on \
                         localhost until then"
                    );
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
                                        // R854 reviewed this site and left the
                                        // reap unguarded on purpose: unlike the
                                        // backend-failure arm below, the line
                                        // above has just torn the workload down,
                                        // so no generation is left running off
                                        // these files and the dir is genuinely
                                        // nobody's. Reaping is the correct
                                        // behaviour, not overreach.
                                        let _ = rt.teardown_workload(&mesh_ident).await;
                                        // R860-T6: the requirer has just been
                                        // torn down, so its carried providers
                                        // go with it.
                                        rollback_self_supplied(&s, &ident, &provisioned).await;
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
                    // Borrowed, not moved — `result` is read again below to
                    // publish the service record (R594-F6).
                    "container_id": &result.container_id,
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
                // guard can branch without re-parsing the spec. R854: the
                // authored one — see where it's sampled for why the
                // materialized spec is the wrong thing to ask.
                s.archetype_registry
                    .lock()
                    .unwrap()
                    .insert(ident.clone(), authored_archetype);
                // R860-T6: record this workload's requirement edges beside its
                // archetype, same lifecycle. Destroy reads `self_supplied` to
                // cascade along `self` edges; drain reads `group` to answer the
                // set-valued drainability question a per-workload archetype
                // cannot. Both were sampled pre-materialization — see
                // `carried_providers`.
                s.requirement_graph.lock().unwrap().insert(
                    ident.clone(),
                    crate::deploy::self_supply::DeployedRequirements {
                        self_supplied: carried_providers
                            .iter()
                            .map(|p| p.expose.mesh.identity.0.clone())
                            .collect(),
                        group: placement_group,
                    },
                );
                // Record what this workload asked for, so `GET /node/usage`
                // can report committed capacity and `GET /workloads` can
                // attach a per-workload request. Recorded here (post-success,
                // beside the archetype) rather than at admission so a failed
                // deploy never counts against the node's committed total.
                // `memory_request_mb()`, not `resources.memory_mb`: this feeds
                // `available = allocatable − committed`, so it must be what the
                // workload asked to be GIVEN, not the ceiling past which it is
                // killed. Summing ceilings would book a single forge run as
                // 32 GiB committed on an 8 GiB node — i.e. the node reports
                // itself full the moment one build lands.
                s.workload_resources.lock().unwrap().insert(
                    ident.clone(),
                    node::WorkloadResources {
                        memory_mb: spec.memory_request_mb(),
                        cpu_millis: spec.resources.cpu_millis,
                    },
                );
                // R594-F6: publish the upstream-discovery record. This is the
                // one moment yubaba holds both halves at once — the spec's
                // declared mesh ports and the mesh IP the backend just
                // assigned — and `list_workloads()` carries no ports, so
                // nothing downstream can re-derive this later (see
                // `service_records` §The port ledger). Also writes the ledger,
                // so the record survives a yubaba restart.
                //
                // Gated on a non-empty port list: a workload exposing no mesh
                // ports can never be an ingress upstream, and admitting one
                // would only pad the registry (and its ledger) with entries no
                // proxy can dial — which on a qed forge node is most of them.
                // The else-arm matters for a *redeploy* that drops its ports:
                // without it the previous generation's record would linger and
                // advertise a port this generation no longer serves.
                if !spec.expose.mesh.ports.is_empty() {
                    s.service_records
                        .upsert_deployed(&spec, result.mesh_ip, &result.container_id);
                } else {
                    s.service_records.retract(&mesh_ident);
                }
                return (StatusCode::CREATED, Json(resp_json)).into_response();
            }
            Err(e) => {
                // `{:#}` renders the full anyhow chain (e.g. the containerd /
                // runc message under "creating task for ..."), not just the
                // top context — essential for diagnosing deploy failures.
                tracing::error!(ident = %ident, error = format!("{e:#}"), "workload deploy failed");
                // R860-T6: the requirer never started; its carried providers
                // exist only to serve it.
                rollback_self_supplied(&s, &ident, &provisioned).await;
                // Reap any secret files materialized before the failed deploy so
                // decrypted PEM doesn't linger for a workload that never started.
                //
                // R854: only when THIS request created the dir. A redeploy that
                // fails at the backend leaves the ident still declared, and the
                // prior generation may still be running off exactly these files
                // — every one of kamaji's pre-teardown refusals (tier guard,
                // admission, an unpullable image) rejects without touching the
                // live container. Reaping there unlinked a healthy workload's
                // mounted cert material, which is how R854 came in: a 500 from
                // the redeploy AND an empty /run/yah/secrets/<ident>/. The dir
                // is the running generation's until a destroy says otherwise.
                if secret_dir_is_new {
                    crate::deploy::secret_mount::teardown_secret_dir(&s.secret_mount_root, &ident);
                } else {
                    tracing::warn!(
                        ident = %ident,
                        "deploy failed at the backend; leaving the pre-existing secret dir in \
                         place for the generation that already owns it (R854)"
                    );
                }
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
    // R860-T6 (W338 §"Placement consequences" 4): take this workload's
    // requirement edges out of the graph. Removed BEFORE the cascade below runs,
    // so a graph that somehow described a cycle closes instead of recursing
    // forever, and so a concurrent destroy of the same ident cannot cascade
    // twice.
    let cascade = s
        .requirement_graph
        .lock()
        .unwrap()
        .remove(&ident)
        .map(|deployed| deployed.self_supplied)
        .unwrap_or_default();
    // Release its committed capacity — a destroyed workload must stop
    // counting against `yah.committed.*` or the node slowly reports itself
    // full while sitting idle.
    s.workload_resources.lock().unwrap().remove(&ident);
    // R594-F6: stop advertising it as an ingress upstream, and drop it from
    // the port ledger so it does not come back on the next boot. Retract
    // rather than delete: the record stays queryable as `Retracted` for
    // diagnostics, and `is_ready()` — the only thing a proxy routes on — is
    // already false. No-op when the ident was never a serving workload.
    s.service_records.retract(&mesh_ident);

    // R860-T6 / W338 §"Placement consequences" 4: **teardown cascades along
    // `self` edges and never along `wait` edges.**
    //
    // `self_supplied` holds only the providers this workload carried inline and
    // stood up itself (`deploy::self_supply::self_supplied_idents`). A `wait`
    // provider — at any locality, including `local` — belongs to whoever
    // declared it, so following that edge here would destroy another operator's
    // workload out from under every other requirer of it.
    //
    // Each provider goes through this same handler, so it gets the same runtime
    // teardown, secret reap, registry clearing and cheers revoke the requirer
    // just got — the mesh identity it kept on the way up is the one it is torn
    // down by. Requirer first, providers after: the thing using the sidecar
    // stops before the sidecar does. One level deep, because a provider cannot
    // itself self-provision (`validate::shape`).
    let mut cascaded: Vec<String> = Vec::new();
    for provider in cascade {
        tracing::info!(
            ident = %ident,
            provider = %provider,
            "destroy cascading into a self-supplied provider (W338)"
        );
        let _ = destroy_workload_boxed(Arc::clone(&s), provider.clone()).await;
        cascaded.push(provider);
    }

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
        // R860-T6: the self-supplied providers torn down with this workload.
        // Reported rather than silent so an operator can see that destroying a
        // requirer took its sidecars, and see that it took nothing else.
        "cascaded": cascaded,
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

/// Create the host-persistent state dir(s) a forge spec declares, so runc can
/// bind them — the OCI mapper never mkdirs a Bind source and runc refuses a
/// bind with a missing source. Best-effort: a failure is logged, not fatal (the
/// deploy proceeds and surfaces the bind failure with its own error).
///
/// R636-B1 widened this from "the produced dir" to "any bind under the forge
/// state root" ([`workload_spec::forge_state`]). Matching on one hardcoded
/// container path meant every *other* forge mount had to rediscover, on a live
/// box and minutes into a build, that nothing creates its host dir — which is
/// exactly how the first offloaded `build-image` step died on
/// `/var/lib/yah/qed/build-out`. The prefix check is also the security bound:
/// a spec can only get yubaba to mkdir inside qed's own state root.
async fn ensure_forge_state_dirs(spec: &workload_spec::WorkloadSpec) {
    for vol in &spec.volumes {
        let workload_spec::VolumeSource::Bind { host_path } = &vol.source else {
            continue;
        };
        if !workload_spec::forge_state::is_forge_state_path(host_path) {
            continue;
        }
        if let Err(e) = tokio::fs::create_dir_all(host_path).await {
            tracing::warn!(
                dir = %host_path.display(),
                error = %e,
                "failed to create forge state dir; forge bind mount may fail"
            );
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

    // Reconcile the systemd unit to what this binary generates, on every deploy.
    // It used to be written only when absent, which meant a node that took the
    // unit once kept it forever — a corrected directive could never reach a
    // machine that had already been deployed to, and the only way to find out
    // was to read the unit on the box. Same failure shape as the headscale unit
    // in `write_and_start_headscale_unit`: the fix lands in the generator and
    // the fleet never sees it. Written only when the text actually differs, so
    // the common redeploy still skips the `daemon-reload`.
    let unit_path = format!("/etc/systemd/system/{COMPOSE_UNIT}.service");
    let unit = compose_unit_text(dir);
    let current = std::fs::read_to_string(&unit_path).unwrap_or_default();
    if current != unit {
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

/// The `yah-cloud-services.service` unit text, split out of [`deploy_compose`]
/// so it is assertable without a systemd host — `/etc/systemd/system` is not
/// writable in a test. Mirrors [`headscale_unit_text`].
fn compose_unit_text(dir: &std::path::Path) -> String {
    format!(
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
    )
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
    /// R858-B11: whether this node's own supervisor (kamaji) reports the
    /// appliance `Running` here. This is the authoritative signal in the shape
    /// yubaba actually deploys, and the one a reader needs in order to tell
    /// "genuinely stopped" from "running, but not the way the other two probes
    /// happen to look for it". `#[serde(default)]` so a client can still parse a
    /// pre-B11 yubaba's body, where the field is simply absent.
    #[serde(default)]
    pub supervised: bool,
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
            // R858-T2: one writer for `headscale_dir`, shared with
            // `leader::start_headscale`'s noise-identity materialization, so
            // the owner-only mode on this coordinator's key material cannot
            // drift between the transplant path and the failover path.
            crate::headscale_state::write_state_file(dir, $filename, &bytes).map_err(|e| {
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

    // R861-T2: the carried policy is NOT written to `acls.yaml` any more —
    // under [`HEADSCALE_POLICY_MODE`] = `database` headscale reads policy from
    // `headscale.db`, which this request already transplants wholesale, and
    // never opens `policy.path`. A carried policy that is the permissive
    // default is therefore redundant (an absent policy row compiles to
    // `tailcfg.FilterAllowAll` in the pinned v0.23.0, the same tailnet). A
    // carried policy that is anything ELSE means the source coordinator was
    // still file-mode, its `headscale.db` has no policy row, and writing the
    // file would no longer carry it — so the transplant is refused rather than
    // silently widening the destination tailnet to allow-all.
    if !carried_policy_is_permissive_default(&req.acl_policy) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "acl_policy carries a non-permissive policy, but this coordinator runs \
                 `policy.mode: {HEADSCALE_POLICY_MODE}` and reads its policy from headscale.db, \
                 not from acls.yaml — writing the file would drop the policy and leave the \
                 destination allow-all. Migrate the SOURCE coordinator's policy into its \
                 headscale.db first (R861-T2), so the transplanted DB carries it, then re-deploy \
                 with an empty acl_policy."
            ),
        ));
    }

    // Generate a config.yaml appropriate for remote paths.
    let config_yaml = generate_remote_headscale_config(&req.server_url, dir);
    std::fs::write(dir.join("config.yaml"), &config_yaml).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write config.yaml: {e}"),
        )
    })?;

    // Download headscale binary (Linux-only; this binary runs on Hetzner machines).
    let bin_path = download_headscale_binary(
        dir,
        &req.headscale_version,
        s.headscale_download_url.as_deref(),
    )?;

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

/// @yah:ticket(R858-B11, "/headscale/health reports the HEALTHY appliance as \"stopped\" — both halves of its OR are false in the configuration yubaba itself deploys")
/// @yah:status(review)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:at(2026-09-05T20:36:19Z)
/// @yah:parent(R858)
/// @yah:severity(high)
/// @yah:next("THE 8080 LEG IS R858-B9's, DO NOT FIX IT TWICE. B9 already owns the port disagreement: `generate_remote_headscale_config` binds 127.0.0.1:8080 (lib.rs:4734), HEADSCALE_PORTS advertises [443, 80], and this probe hardcodes 127.0.0.1:8080 — three places disagreeing with no production value forcing agreement. Whoever takes B9 should take this probe's port with it; what is left here is the systemd-vs-kamaji half, which is independent and is the one that inverts the answer.")
/// @yah:gotcha("IT HAS ALREADY NEARLY CAUSED A SECOND OUTAGE, which is why this is filed at high severity rather than as tidy-up. @Ashguard:griffin (R600-F10, 2026-09-05) was about to restart yubaba on us-west-001 to activate the fleet ACME issuer drop-in, read `\"headscale\":\"stopped\"`, and stopped only because they independently found the process with `ps` and asked. A yubaba restart on west drops raft leadership, and R858's root-cause chain then reproduces the Sept 3 outage exactly — us-south-001's kamaji has no `--native-exec-dir` and no headscale.service to fall back to. So the cost of this field is not a confusing dashboard: it actively argues for the one action that decapitates the mesh, at the moment the mesh is healthy.")
/// @yah:handoff("FILED, NOT FIXED — full diagnosis, measured on us-west-001 2026-09-05, so the next agent can go straight to the edit. `headscale_health_check` (oss/yubaba/crates/yubaba/src/lib.rs:4744) reports \"running\" if EITHER `systemctl is-active --quiet headscale` succeeds OR `probe_headscale_local()` returns true. Both are false whenever yubaba has deployed the appliance the way yubaba is designed to deploy it, so the healthy state reports as \"stopped\" and the field is effectively INVERTED — it can only read \"running\" in the degraded systemd-fallback configuration. HALF ONE, the systemd probe: leader.rs deploys headscale as a KAMAJI NATIVE workload and stops+disables the systemd unit in the same second, so `is-active` is `inactive` by construction. Measured: `systemctl is-active headscale.service` = inactive, `is-enabled` = disabled, while `ps -o ppid,lstart,cmd -p 517125` shows the live headscale started Sat Sep 5 01:54:01 2026 with ppid 515908 = `/usr/local/bin/kamaji --native-exec-dir /var/lib/yah/kamaji/native`, and `/proc/517125/cgroup` = `0::/yubaba.slice/kamaji.service/native`. HALF TWO, the HTTP probe: `probe_headscale_local` (lib.rs:4766) hardcodes `http://127.0.0.1:8080/health`, but the live appliance serves TLS on *:443 and *:80 (`ss -lntp`), nothing on 8080 — so the probe times out and returns false. Independent public confirmation that the thing is fine: `https://cloud.mesh.yah.dev/key?v=138` = HTTP 200, and `/health` = 200 from the open internet (griffin's own measurement). THE RIGHT FIX IS TO ASK KAMAJI, NOT SYSTEMD: kamaji is the supervisor in the deployed shape, it holds the workload's state, and the appliance's mesh_ip and port are what leader.rs already wrote when it deployed. A probe that asks the process's actual supervisor cannot go stale the way a hardcoded unit name and a hardcoded port both did. Keep the systemd check as a fallback if you like — it is the fallback path's signal — but it must not be the only one that can say yes.")
/// @yah:verify("Reproduce before fixing (it reproduces on the live fleet right now, no setup needed): `ssh -i ~/.ssh/yah debian@15.204.89.240 'systemctl is-active headscale.service; systemctl is-enabled headscale.service; ss -lntp | grep -E \":443|:8080\"'` — expect inactive / disabled / headscale on *:443 with nothing on 8080. Then `curl -s https://cloud.mesh.yah.dev/key?v=138 -o /dev/null -w '%{http_code}'` = 200, i.e. the appliance the field calls \"stopped\" is serving the public internet. AFTER the fix, the acceptance test is that the field reads \"running\" in the NORMAL kamaji-supervised state — a test that only exercises the systemd-fallback shape is the test that let this ship.")
/// @yah:gotcha("THE TICKET'S OWN @yah:assumes WAS FALSE AND IS NOW REMOVED — traced, not inherited. It guessed that `/mesh/leader-health`'s headscale field is fed by `headscale_health_check`. IT IS NOT: `mesh_leader_health` called `probe_headscale_local()` DIRECTLY (was lib.rs:2720), with no systemd fallback at all. So leader-health was the MORE inverted of the two endpoints — on any kamaji-supervised coordinator it could only ever answer `\"stopped\"` + HTTP 503, unconditionally, and 503 there is the signal an external load balancer reads to decide the leader is not serving. The diagnosis under-counted the blast radius by one endpoint; both are fixed here and both now route through one `headscale_liveness`.")
/// @yah:handoff("FIXED. Both health endpoints now ask the appliance's ACTUAL SUPERVISOR first. New `headscale_liveness(&ServerState) -> HeadscaleLiveness { supervised, systemd_active, api_reachable }` in oss/yubaba/crates/yubaba/src/lib.rs, with `running() = supervised || systemd_active || api_reachable`. `supervised` comes from `leader::observe_local_appliance` — the probe R858-T3 already built, which asks this node's own kamaji via `get_workload(appliance_ident())` — promoted from private to `pub(crate)` (leader.rs, one visibility keyword, body untouched, agreed with @Ashguard:spade before the edit). The systemd and HTTP legs are KEPT as fallbacks per the ticket: the unit is the real signal on a node whose kamaji predates `--native-exec-dir`, which during a rolling upgrade is most of the fleet. `headscale_health_check` gained `State<Arc&lt;ServerState&gt;>`; `mesh_leader_health` swapped its bare `probe_headscale_local()` for the same helper.")
/// @yah:handoff("SCOPE HELD: THE 8080 LEG IS UNTOUCHED AND STILL R858-B9's. `probe_headscale_local` is byte-for-byte unchanged — still hardcodes `http://127.0.0.1:8080/health`, still returns false on the live fleet — and `api_reachable` still reports exactly what it measures rather than being papered over. Nothing in the port disagreement was fixed twice.")
/// @yah:handoff("A THIRD INSTANCE OF THE SAME INVERSION, FOUND AND FIXED IN THIS PASS — and without it the yubaba fix would NOT have reached the reader who was actually misled. crates/yah/agent-tools/src/cloud_tools.rs computed `headscale_ok = (h.headscale == \"running\") && h.api_reachable`, re-ANDing one signal back on top of the verdict over all of them. That is the field behind `cloud.mesh_diagnose`, so it would have kept emitting the finding \"headscale island: 'us-west-001' is reachable but headscale is not running/healthy\" against a coordinator serving the public internet, forever, because `api_reachable` is false for R858-B9's unrelated port reason. Now `h.headscale == \"running\"`. Also added `supervised: bool` to `HeadscaleHealthResponse` (yubaba + crates/yah/cloud-client, `#[serde(default)]` on both so a pre-B11 yubaba still deserializes) and surfaced it in the single-machine health JSON, so a reader sees WHICH signal said yes — `api_reachable:false` with `supervised:true` is the normal healthy shape on this fleet, not a fault.")
/// @yah:verify("REPRODUCED LIVE BEFORE AND MEASURED BY ME (read-only, no live node changed), us-west-001 2026-09-05. `systemctl is-active headscale.service` = inactive; `is-enabled` = disabled; `ss -lntp` = headscale pid 517125 on `*:443` and `*:80` with NOTHING on 8080 (so B9's hand-move to 8080 has not happened yet); `GET 100.64.0.1:7443/headscale/health` = `{\"headscale\":\"stopped\",\"api_reachable\":false}`; `GET 100.64.0.1:7443/mesh/leader-health` = `{\"leader\":false,\"headscale\":\"stopped\"}` with HTTP 503 — while `https://cloud.mesh.yah.dev/key?v=138` = 200 in 0.14s and `/health` = 200. Note yubaba binds the mesh IP (100.64.0.1:7443), NOT loopback:7443; a curl at 127.0.0.1:7443 returns nothing and looks like a dead yubaba.")
/// @yah:verify("THE ACCEPTANCE TEST EXERCISES THE NORMAL KAMAJI-SUPERVISED STATE, as the ticket demanded, AND IT IS FALSIFIED. 4 new tests in lib.rs on a new `ApplianceSupervisorFake` (a kamaji answering `get_workload` and recording what it was asked): (1) `the_health_field_reads_running_on_a_kamaji_supervised_appliance` — through the REAL router, asserts headscale==\"running\", supervised==true, and that the probe asked for HEADSCALE_IDENT; neither old signal can be true in the fixture (no systemd unit under a tempdir, nothing on any port), so only the supervisor query can make it pass. (2) `the_supervisor_signal_alone_is_enough_to_say_running` — the decision rule alone, deliberately NOT through HTTP so a dev box with something on :8080 cannot make it green for an environmental reason; also asserts the systemd fallback can still say yes. (3) `a_supervisor_reporting_a_stopped_appliance_does_not_claim_it_is_supervised` (Stopped, and never-heard-of). (4) `leader_health_asks_the_supervisor_not_only_the_hardcoded_port` — the second endpoint, asserting 503 for the leader half (no raft in the fixture) but headscale==\"running\". FALSIFICATION RUN: dropping `self.supervised ||` out of `running()` fails 3 of the 4, and they fail reporting exactly the live symptom, `left: String(\"stopped\") right: \"running\"`. Rule restored and re-run green.")
/// @yah:verify("SUITES, all green on the shared tree as of this write: `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib` = 759 passed / 0 failed (743 at my first run; @Ashguard:spade's R858-T7 tests landed under me in between, which is why the count moved). `cargo test -p yah-agent-tools --lib` = 1221 passed / 0 failed. Parent relay smoke: `cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib cloud_init` = 27 passed (note: `-p yah-cloud` needs the yubaba manifest — from the repo root it errors \"not a member of the workspace\", which reads like a broken crate and is not); `cargo test -p yah --test main camp_systemd_unit_emit` = 8 passed. `cargo clippy --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib`: zero findings on any line I touched (the 10 crate warnings are pre-existing, in pond/minio.rs, rollout/engine.rs and others). cloud-client + agent-tools check clean.")
/// @yah:gotcha("THE DEPLOYED BINARY STILL LIES UNTIL 0.8.33 ROLLS — this fix is code, and NOTHING was rolled and no live node was touched. Until the fleet carries it, `/headscale/health` and `/mesh/leader-health` on us-west-001 keep answering \"stopped\" / 503 exactly as measured above. So the operational rule stands unchanged for now: DO NOT read \"stopped\" from a yubaba on 0.8.32 as grounds to restart yubaba on the coordinator — check `ps`/`ss` on the box, or curl `https://cloud.mesh.yah.dev/key?v=138`. After the roll, the tell that the fix is live is the new `supervised` field appearing in the `/headscale/health` body at all; a pre-B11 yubaba omits it.")
/// @yah:gotcha("SHARED-TREE STATE, UNCOMMITTED — verify by CONTENT, not by `git status` (peers wip-commit constantly here). Tree anchor at pickup: 00ee20d1; quote that SHA, never HEAD, in any revert instruction. Four files carry my hunks: oss/yubaba/crates/yubaba/src/lib.rs (grep `headscale_liveness`, `HeadscaleLiveness`, `ApplianceSupervisorFake`), oss/yubaba/crates/yubaba/src/leader.rs (grep `pub(crate) async fn observe_local_appliance` — line number MOVED from 729 to ~892 under spade's edits, which is why you grep rather than seek), crates/yah/cloud-client/src/lib.rs (grep `supervised`), crates/yah/agent-tools/src/cloud_tools.rs (grep `R858-B11`). Any commit of this must be pathspec-scoped: @Ashguard:spade (session:1be15e4f, R858-T7) was editing appliance_ownership.rs / lease_detector.rs / leader.rs / cert_store.rs / tests/raft_appliance_ownership.rs concurrently. No collision — coordinated with them by party.chat before the first edit and they confirmed they are not rewriting observe_local_appliance.")
/// @yah:gotcha("MEASURED IN PASSING, AND IT CHANGES HOW `/mesh/leader-health` SHOULD BE READ: us-west-001 answers `leader: false` while it is the node actually running the appliance. Raft leadership sits elsewhere and west owns the appliance anyway — the decoupled state R858-T3 deliberately produced, working as intended. Consequence: that endpoint's `leader` field is now ORTHOGONAL to appliance ownership, so anything reading it as \"is this the coordinator\" is wrong on the live fleet TODAY, not just in theory. Before this fix the same endpoint also returned 503 unconditionally on any kamaji-supervised node, so both of its fields were misleading at once. Relayed to @Ashguard:spade for R858-T7's detection design.")
async fn headscale_health_check(
    State(s): State<Arc<ServerState>>,
) -> Json<HeadscaleHealthResponse> {
    let live = headscale_liveness(&s).await;

    Json(HeadscaleHealthResponse {
        headscale: if live.running() { "running" } else { "stopped" }.into(),
        api_reachable: live.api_reachable,
        supervised: live.supervised,
    })
}

/// The three independent answers to "is headscale up on this node", kept apart
/// so the endpoints can report *which* one said yes rather than only the OR.
struct HeadscaleLiveness {
    /// This node's kamaji reports the appliance `Running`.
    supervised: bool,
    /// `systemctl is-active headscale` succeeded.
    systemd_active: bool,
    /// The localhost HTTP probe got a success status.
    api_reachable: bool,
}

impl HeadscaleLiveness {
    fn running(&self) -> bool {
        self.supervised || self.systemd_active || self.api_reachable
    }
}

/// Ask every supervisor that could plausibly be holding headscale on this node.
///
/// # Why this asks kamaji first (R858-B11)
///
/// Until R858-B11 the answer was `systemd_active || api_reachable`, and **both
/// halves are false in the configuration yubaba itself deploys**, so the field
/// was effectively inverted — it could only read `running` in the degraded
/// systemd-fallback shape.
///
/// - [`leader::start_headscale`] deploys the appliance as a *kamaji native
///   workload* and runs `systemctl disable --now headscale` in the same breath
///   (deliberately — two supervisors both want `:443`). So `is-active` is
///   `inactive` **by construction** on a healthy coordinator.
/// - The HTTP probe hardcodes `127.0.0.1:8080`, which the live appliance does
///   not bind. That port disagreement is R858-B9's; it is *not* fixed here, and
///   `api_reachable` is left reporting exactly what it measures.
///
/// Measured on us-west-001 2026-09-05: `is-active` = `inactive`, `is-enabled` =
/// `disabled`, nothing on 8080 — while the appliance was serving
/// `https://cloud.mesh.yah.dev/key?v=138` to the open internet with a live pid
/// parented to `kamaji --native-exec-dir`.
///
/// The cost was not a confusing dashboard. On 2026-09-05 an agent about to
/// restart yubaba on us-west-001 read `"headscale":"stopped"` and nearly took
/// the action that drops raft leadership and decapitates the mesh; they stopped
/// only because they checked `ps` themselves. A probe that asks the process's
/// **actual supervisor** cannot go stale the way a hardcoded unit name and a
/// hardcoded port both did.
///
/// The other two are kept as fallbacks, not retired: the systemd unit is the
/// real signal on a node whose kamaji predates `--native-exec-dir`, which
/// during a rolling upgrade is most of the fleet.
async fn headscale_liveness(s: &Arc<ServerState>) -> HeadscaleLiveness {
    HeadscaleLiveness {
        supervised: crate::leader::observe_local_appliance(s).await.is_some(),
        systemd_active: std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "headscale"])
            .status()
            .map(|st| st.success())
            .unwrap_or(false),
        api_reachable: probe_headscale_local().await,
    }
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
           mode: {HEADSCALE_POLICY_MODE}\n\
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

    // Write config FIRST so it exists regardless of whether the
    // download/start/mint steps succeed (mirrors headscale_deploy ordering).
    //
    // R861-T2: no `acls.yaml` is written any more. Under
    // [`HEADSCALE_POLICY_MODE`] = `database` headscale never reads that path,
    // and a fresh coordinator simply has no policy row — which the pinned
    // v0.23.0 treats as a nil `*ACLPolicy` whose `CompileFilterRules` returns
    // `tailcfg.FilterAllowAll`. That is byte-for-byte the same tailnet
    // behaviour [`DEFAULT_ACL_POLICY_HUJSON`] produced, so bootstrapping loses
    // nothing; a non-permissive policy now arrives as declared config through
    // the `kind = "headscale"` reconciler, which can finally push it.
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
    let bin_path = download_headscale_binary(dir, &version, s.headscale_download_url.as_deref())?;
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
///
/// `url_override` is [`ServerState::headscale_download_url`]: when set it
/// replaces the upstream release URL entirely (tests pass a `file://` fixture),
/// and `version` is then unused.
fn download_headscale_binary(
    dir: &std::path::Path,
    version: &str,
    url_override: Option<&str>,
) -> Result<PathBuf, (StatusCode, String)> {
    let bin_path = dir.join("headscale");
    let dl_url = match url_override {
        Some(u) => u.to_string(),
        None => headscale_linux_download_url(version),
    };
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
///
/// # `Restart=always`, not `on-failure` (R591-F1)
///
/// `headscale serve` exits **0** on SIGTERM. `Restart=on-failure` does not
/// restart a clean exit by definition, so a boot-race SIGTERM on 2026-07-09
/// stopped the fleet's mesh coordinator and nothing brought it back for seven
/// days — two of three raft voters and the operator's laptop off-tailnet. The
/// live unit on us-west-001 was hand-patched to `always` on 2026-07-16; this
/// function is what *writes* the unit, so until now the next
/// `POST /headscale/deploy` would have reinstalled the outage.
///
/// This unit is the fallback path. The supervised path is
/// [`crate::headscale_appliance`] — a kamaji workload with
/// `RestartPolicy::Always`, which is the same guarantee with observable
/// restart state attached.
fn write_and_start_headscale_unit(bin_path: &std::path::Path, dir: &std::path::Path) -> bool {
    let unit = headscale_unit_text(bin_path, dir);
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

/// The `headscale.service` unit text, split out from
/// [`write_and_start_headscale_unit`] so the restart directive is assertable
/// without a systemd host — `/etc/systemd/system` is not writable in a test.
fn headscale_unit_text(bin_path: &std::path::Path, dir: &std::path::Path) -> String {
    format!(
        "[Unit]\n\
         Description=Headscale coordinator (yah-managed)\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={bin} serve --config {dir}/config.yaml\n\
         Restart=always\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        bin = bin_path.display(),
        dir = dir.display()
    )
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
         \x20\x20mode: {HEADSCALE_POLICY_MODE}\n\
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

/// `POST /raft/pre-vote` — answer a peer's Pre-Vote probe (R734-T1).
///
/// Same request and response types as `/raft/vote`, and judged by the same
/// leader-lease and last-log-id rules, with one decisive difference: handling
/// it persists **no** vote and changes **no** term on this node. That is the
/// whole point — a peer that has been partitioned or has just restarted can ask
/// "would you elect me?" and be told no without the asking itself having
/// disturbed a healthy leader.
///
/// Deliberately a separate route rather than a flag on `/raft/vote`: openraft
/// dispatches Pre-Vote through its own `RaftNetworkV2::pre_vote` RPC, and a
/// build that lacks this route must answer 404 so the caller can degrade to the
/// no-Pre-Vote behaviour (see [`raft::YubabaNetwork`]'s `pre_vote`). A shared
/// route with an in-band flag would instead have an old node silently handle a
/// Pre-Vote as a real vote — persisting it, which is the one thing Pre-Vote
/// exists not to do.
async fn raft_pre_vote(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<openraft::raft::VoteRequest<raft::YubabaRaftConfig>>,
) -> RaftRpcReply<openraft::raft::VoteResponse<raft::YubabaRaftConfig>> {
    let raft = require_raft!(s);
    Ok(Json(raft.pre_vote(req).await))
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

/// `GET /secrets` — cluster-secret **index** (R706 / W294).
///
/// Names, last-write timestamps, access-rule summaries, and keyed digests
/// (R720-F1) for every cluster secret in this node's raft replica. Never
/// ciphertext, never plaintext — see
/// [`raft::YubabaStateMachine::cluster_secret_index`] for why the digest is
/// safe to serve while the ciphertext is not.
///
/// Backs `yah cloud secret ls`, and is how an operator confirms a rule actually
/// landed on the fleet rather than only in the camp's declaration file.
async fn list_secrets(State(s): State<Arc<ServerState>>) -> impl IntoResponse {
    let Some(sm) = &s.cluster_state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "this node is not part of a raft cluster (no cluster state)",
            })),
        )
            .into_response();
    };
    let secrets: Vec<serde_json::Value> = sm
        .cluster_secret_index()
        .into_iter()
        .map(|(name, updated_at, access, digest)| {
            serde_json::json!({
                "name": name,
                "updated_at": updated_at,
                "access": access,
                "digest": digest,
            })
        })
        .collect();
    Json(serde_json::json!({ "secrets": secrets })).into_response()
}

/// `GET /cluster/singletons` — who owns each singleton role, read from this
/// node's **locally-applied** state (R118-T1 / W138).
///
/// This is the read surface a realtime sibling process uses. On a gallery rig
/// the audio process runs beside this daemon in its own cgroup and needs to
/// know which node is currently the egress gateway, the telemetry aggregator,
/// the holder of a hardware handle — and W138's non-negotiable rule is that
/// **nothing on the audio or graph path may synchronously await a raft
/// commit.** So this handler:
///
/// - never calls `client_write`, `ensure_linearizable`, or anything else that
///   needs the leader or a quorum — it reads the replica this process already
///   has, under a `std::sync::RwLock` it holds for the length of a clone;
/// - answers identically on a follower, on a partitioned minority, and on a
///   node whose cluster has entirely gone away. Losing quorum degrades
///   *authority* — nobody can take the role from its holder — never the ability
///   to read who holds it;
/// - reports its own staleness rather than hiding it. `applied_index` is the
///   raft log index this answer is true as of; a consumer that watches it stop
///   advancing knows it is coasting on last-known-good.
///
/// Contrast `GET /raft/status`, which is about the *cluster's* health and is an
/// operator surface. This one is about the *role assignment* and is a runtime
/// surface — the distinction matters because the two have opposite failure
/// postures: status should say "I cannot see the cluster", this should keep
/// answering anyway.
async fn cluster_singletons(State(s): State<Arc<ServerState>>) -> impl IntoResponse {
    let Some(sm) = &s.cluster_state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "this node is not part of a raft cluster (no cluster state)",
            })),
        )
            .into_response();
    };

    let roles: serde_json::Map<String, serde_json::Value> = sm
        .singleton_owners()
        .into_iter()
        .map(|(key, entry)| {
            (
                key,
                serde_json::json!({
                    "owner": entry.owner,
                    "acquired_at": entry.acquired_at,
                    "ttl_secs": entry.ttl_secs,
                }),
            )
        })
        .collect();

    Json(serde_json::json!({
        "node_id": s.node_id,
        "applied_index": sm.applied_index(),
        "roles": roles,
        "ingress_owner": sm.ingress_owner(),
    }))
    .into_response()
}

/// `GET /tenants/{id}` query. `node` is the id asking, so this node can answer
/// "may *you* write?" rather than making every caller re-derive the
/// owner-and-lease predicate.
#[derive(Deserialize)]
struct TenantQuery {
    node: Option<raft::YubabaNodeId>,
}

/// `GET /tenants/{id}?node=<n>` — R732-T4 (W245): the fencing token transport.
///
/// This is how a node's tenant streamer learns the epoch it may write under.
/// It is a **local** read of this node's applied state: no leader round-trip,
/// no linearizable read, no quorum cost on a path the data plane walks every
/// few seconds.
///
/// **That read can be stale, and that is the design, not a compromise.** This
/// node may not have applied a transfer yet, or may be partitioned from the
/// leader and still believe it owns everything. Both are safe because
/// enforcement is at the R2 sink, not here:
///
/// - a **stale-low** token bounces at the sink as `StreamOutcome::Fenced` —
///   a wasted round trip, never a second writer;
/// - a **stale-high** token cannot exist, because only committed entries ever
///   reach a state machine.
///
/// W253 tenet 5 states the principle this implements: stale routing must be
/// *safe*, not *impossible*. A design that needed this answer to be fresh
/// would be one where a partition corrupts a tenant.
///
/// `fencing_token` is present only when `node` is supplied, and is computed by
/// [`raft::YubabaStateMachine::tenant_fencing_token`] rather than re-derived
/// from the record below — one predicate, one place. The record itself is
/// reported for diagnostics and to tell the caller when to renew.
async fn get_tenant_ownership(
    State(s): State<Arc<ServerState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<TenantQuery>,
) -> impl IntoResponse {
    let Some(sm) = &s.cluster_state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "this node is not part of a raft cluster (no cluster state)",
            })),
        )
            .into_response();
    };
    let tenant = workload_spec::TenantId(id.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let Some(record) = sm.tenant_ownership(&tenant) else {
        // No record means nobody owns this tenant, which is a perfectly good
        // answer — and the *safe* one, since no record yields no token. 404
        // rather than a null body so a caller can tell "unknown tenant" from
        // "known tenant, not yours".
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "tenant": id,
                "now": now,
                "error": "no ownership record for this tenant",
            })),
        )
            .into_response();
    };

    Json(serde_json::json!({
        "tenant": id,
        "owner": record.owner,
        "epoch": record.epoch,
        "lease_expires": record.lease_expires,
        "live": record.is_live(now),
        // The serving node's clock, so a caller does lease arithmetic against
        // one clock instead of differencing two skewed ones.
        "now": now,
        // Null unless `?node=` was supplied. Null also means "you may not
        // write" — the two cases are distinguishable by whether the caller
        // asked, and a caller that did ask and got null must not stream.
        "fencing_token": q.node.and_then(|n| sm.tenant_fencing_token(&tenant, n, now)),
        // Which applied index this answer reflects, so a stale reply is
        // *visibly* stale to an operator debugging a fence.
        "applied_index": sm.applied_index(),
    }))
    .into_response()
}

/// `GET /raft/status` — human-readable cluster state.
///
/// Carries a `liveness` section when a [`FailureDetector`] is attached
/// (R118-T9): membership tells you which peers the cluster *believes* in, and
/// liveness tells you which of them anything has actually heard from and how
/// long ago. The section is absent — never faked — when no detector is wired,
/// and its `peers` map is empty on a node whose detector has no view (the
/// raft-heartbeat detector only sees acknowledgements on the leader).
///
/// Carries a `lease_liveness` section (R737-F2) the same way, when a
/// [`lease_detector::LeaseFailureDetector`] is attached — the node-lease
/// channel a placement scheduler is allowed to trust, kept deliberately
/// separate from `liveness` above; see the `lease_detector` module doc for
/// why the two must not be conflated.
///
/// Carries a `members` section (R734-F5) when this node holds a read handle on
/// applied state: the replicated member rows, each with the `region` the node it
/// describes declared for itself. Three sections, three different questions —
/// `membership_config` is who raft *counts*, `liveness` is who anything has
/// *heard from*, `members` is what those nodes *say about themselves*. They can
/// legitimately disagree: a node that just joined is in membership with no row
/// yet, and a removed node's row can outlive its membership entry.
///
/// Carries `sovereign_group` (R742-F1) — the group *this* node declares, or
/// `null` when it declares none. Always present on a build that has the field,
/// which is what lets a leader tell an unstamped daemon (`null`) from one whose
/// build predates sovereign groups (key absent) when it asks a prospective
/// learner which blast radius it belongs to; those two get different
/// instructions. Unlike the three sections above, this is not replicated state
/// and never a claim about anyone else: it is only ever what this process was
/// started with. See [`sovereign_group`].
///
/// Carries `sovereign_role` beside it (R605-F12) — whether this node votes in
/// that group. Always a value, never `null`: the role has a default where the
/// group does not, so a *missing* key is the only signal a reader needs, and it
/// means the build predates the field.
///
/// Carries `jurisdiction` (R736-T3) on the same present-vs-`null` contract as
/// the group, and — when one is declared — a `cell` section naming the cell this
/// raft group is: its id (the sovereign-group label), its jurisdiction, and the
/// distinct regions its member rows declare. `cell` is absent on a group that
/// has not been bound to a jurisdiction, which is every cluster in the fleet
/// today; see [`cell`] for why that is a group and not a cell.
async fn raft_status(
    State(s): State<Arc<ServerState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raft = require_raft!(s);
    let metrics = raft.metrics().borrow_watched().clone();
    let mut body = serde_json::json!({
        "node_id": metrics.id,
        "state": format!("{:?}", metrics.state),
        "current_leader": metrics.current_leader,
        "current_term": metrics.current_term,
        "last_log_index": metrics.last_log_index,
        "last_applied": metrics.last_applied,
        "membership_config": metrics.membership_config,
        // R742-F1: emitted even when None. A leader asking a joiner which
        // sovereign group it is in needs `null` (no flag) and a missing key
        // (older build) to stay distinguishable — see `sovereign_group`.
        "sovereign_group": s.sovereign_group,
        // R605-F12: always a value, never null — the role has a default where
        // the group does not, so there is no "unset" state to signal. A peer
        // reading a *missing* key here knows it is talking to a build older
        // than this field and resolves it to `voter` itself.
        "sovereign_role": s.sovereign_role,
        // R736-T3: emitted even when None, for the same present-vs-null reason
        // as `sovereign_group` — a cell asking a joiner which jurisdiction it is
        // in has to tell an unflagged daemon (`null`) from one whose build
        // predates cell tagging (key absent), because one needs a restart and
        // the other a roll.
        "jurisdiction": s.jurisdiction,
    });

    // R736-T3: the cell this raft group *is* — present only when a jurisdiction
    // has been declared, since that is what makes a sovereign group a cell. A
    // convenience view over two keys already above plus the regions its members
    // declare, so a mover reading W250's global pointer can check "is this the
    // cell the pointer names, and is it in the jurisdiction policy allows"
    // against one object rather than reassembling it.
    if let Some(identity) = s.cell() {
        let regions = s
            .cluster_state
            .as_ref()
            .map(|sm| {
                sm.members()
                    .into_values()
                    .filter_map(|info| info.region)
                    .collect()
            })
            .unwrap_or_default();
        body["cell"] = cell::describe(&identity, regions);
    }

    if let Some(sm) = &s.cluster_state {
        let members: serde_json::Map<String, serde_json::Value> = sm
            .members()
            .into_iter()
            .map(|(id, info)| {
                (
                    id.to_string(),
                    serde_json::json!({
                        "addr": info.addr,
                        "region": info.region,
                    }),
                )
            })
            .collect();
        body["members"] = serde_json::Value::Object(members);
    }

    if let Some(detector) = &s.failure_detector {
        let peers: serde_json::Map<String, serde_json::Value> = detector
            .observe()
            .await
            .into_iter()
            .map(|(node, obs)| {
                (
                    node.to_string(),
                    serde_json::json!({
                        "state": obs.liveness.as_str(),
                        "silent_for_ms": obs.silent_for_ms,
                    }),
                )
            })
            .collect();
        body["liveness"] = serde_json::json!({
            "channel": detector.channel(),
            "peers": peers,
        });
    }

    // R737-F2: the node-lease channel a placement scheduler is allowed to
    // trust — deliberately a separate section from `liveness` above, which
    // stays raft-heartbeat evidence. See `lease_detector` module doc.
    if let Some(detector) = &s.lease_detector {
        let peers: serde_json::Map<String, serde_json::Value> = detector
            .observe()
            .await
            .into_iter()
            .map(|(node, obs)| {
                (
                    node.to_string(),
                    serde_json::json!({
                        "state": obs.liveness.as_str(),
                        "silent_for_ms": obs.silent_for_ms,
                    }),
                )
            })
            .collect();
        body["lease_liveness"] = serde_json::json!({
            "channel": detector.channel(),
            "peers": peers,
        });
    }

    // R737-T4 (W253 §8): the last N+1 headroom verdict the background loop
    // computed. Absent (not faked as satisfied) before the loop's first tick
    // or on a node that has never led — see `headroom`'s module doc.
    if let Some(report) = s.headroom.lock().unwrap().clone() {
        body["headroom"] = serde_json::json!({
            "spare": report.spare,
            "required": report.required,
            "satisfied": report.satisfied(),
        });
    }

    Ok(Json(body))
}

/// `POST /raft/initialize` request — founding membership for a fresh cluster.
#[derive(Deserialize)]
struct RaftInitializeRequest {
    /// node_id → founding voter, including the node receiving this call.
    members: std::collections::BTreeMap<raft::YubabaNodeId, RaftInitializeMember>,
}

/// One founding voter in a [`RaftInitializeRequest`].
///
/// Accepts two spellings on purpose (R734-F2). The bare string `"host:port"` is
/// the pre-region form every existing operator script and runbook writes; the
/// object form `{"addr": …, "region": …}` carries the region tag the
/// quorum-geography rule is judged on. Keeping the old form parsing means the
/// refusal an untagged fleet bootstrap now gets is a *policy* refusal with an
/// actionable message, rather than a deserialization error that reads like the
/// operator typed the JSON wrong.
#[derive(Deserialize)]
#[serde(untagged)]
enum RaftInitializeMember {
    /// `"100.64.0.1:7443"` — pre-R734-F2 form, no region.
    Addr(String),
    /// `{"addr": "100.64.0.1:7443", "region": "us-west"}`.
    Tagged {
        addr: String,
        #[serde(default)]
        region: Option<String>,
    },
}

impl RaftInitializeMember {
    fn addr(&self) -> &str {
        match self {
            Self::Addr(addr) => addr,
            Self::Tagged { addr, .. } => addr,
        }
    }

    fn region(&self) -> Option<&str> {
        match self {
            Self::Addr(_) => None,
            Self::Tagged { region, .. } => region.as_deref(),
        }
    }
}

/// `POST /raft/initialize` — one-time cluster bootstrap (R570-F1).
///
/// Writes the initial membership log entry and kicks off the first leader
/// election. Call it once, on one founding voter, after every member is up
/// with `--raft-node-id`; the others receive membership via AppendEntries.
/// Re-calling on an already-initialized node returns success without
/// touching state, so operator retries are safe.
///
/// # The quorum-geography gate (R734-F2, W247 §2)
///
/// The founding set is judged by
/// [`ClusterPolicy::quorum_geography`](cluster_policy::ClusterPolicy::quorum_geography)
/// *before* openraft is asked to write anything, and a violation is a `400`
/// naming the layout to use instead. This is the one moment the whole voter set
/// is in one place and nothing has been committed yet — after initialize, fixing
/// the geography means a membership change on a live cluster, and before it
/// there is no cluster to ask.
///
/// The gate is on this route, not inside [`raft::open`], and that boundary is
/// worth stating plainly: `openraft::Raft::initialize` is reachable directly by
/// anything holding the raft handle (the test harness founds its clusters that
/// way), so this refuses *operator* mistakes rather than making the invariant
/// structurally unbreakable. Enforcing it deeper would mean wrapping openraft's
/// own API, which is a larger change than the invariant is worth.
async fn raft_initialize(
    State(s): State<Arc<ServerState>>,
    Json(body): Json<RaftInitializeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raft = require_raft!(s);

    let regions: std::collections::BTreeMap<raft::YubabaNodeId, Option<String>> = body
        .members
        .iter()
        .map(|(id, m)| (*id, m.region().map(str::to_string)))
        .collect();
    if let GeographyVerdict::Refuse(reason) = s.cluster_policy.quorum_geography.judge(&regions) {
        return Err((StatusCode::BAD_REQUEST, reason));
    }

    let members: std::collections::BTreeMap<raft::YubabaNodeId, openraft::BasicNode> = body
        .members
        .iter()
        .map(|(id, m)| {
            (
                *id,
                openraft::BasicNode {
                    addr: m.addr().to_string(),
                },
            )
        })
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

/// `POST /raft/add-learner` request — add a node to a running cluster (R569-F3).
#[derive(Deserialize)]
struct RaftAddLearnerRequest {
    /// The joining node's raft node id (u64, unique fleet-wide). The node must
    /// already be up with `--raft-node-id <this>` and *uninitialised* (no
    /// `raft init`, no `--bootstrap-single-node`), so the leader's AppendEntries
    /// establishes it.
    node_id: raft::YubabaNodeId,
    /// The joining node's mesh address (`host:port`) the leader will dial to
    /// replicate to it — e.g. the Tailscale mesh IP `100.64.0.7:7443`. Never a
    /// LAN address: those drift (see W301).
    addr: String,
}

/// `POST /raft/add-learner` — add a node to a **running** quorum as a non-voting
/// learner (R569-F3, W301 §"Mesh / raft join").
///
/// This is the join-an-existing-cluster counterpart to [`raft_initialize`],
/// which only founds a *fresh* cluster from a known genesis membership. A
/// learner receives full log/snapshot replication (so it holds the complete
/// cluster state — service placement, secrets, rollout mirror — and can serve
/// linearizable-free local reads) but does **not** vote and does **not** count
/// toward quorum.
///
/// Promotion to voter is a separate, deliberate step ([`raft_promote_voter`])
/// governed by [`VoterAdmission`](cluster_policy::VoterAdmission) — under the
/// fleet policy it is refused outright, so a macOS home-lab node stays a
/// learner and a flaky residential-network box can never endanger the cloud
/// voters' quorum (dovetails with the R569-F4 taint intent — schedulable, but
/// never cluster-critical). Until R118-T9 that rule lived only in this
/// paragraph; it is now a field on [`ClusterPolicy`].
///
/// Must be called on the current **leader** (only the leader can change
/// membership). A follower returns 421 Misdirected with openraft's
/// forward-to-leader hint in the body so the caller can retarget. Blocking:
/// waits until the leader believes the learner's log is caught up, so a 200
/// means replication is actually established, not merely requested. Re-adding an
/// existing learner/voter is a harmless no-op (openraft re-adds it).
///
/// # The sovereign-group gate (R742-F1, W305 §F1)
///
/// When this node declares a [`sovereign_group`](ServerState::sovereign_group),
/// the join must be *within* it: the leader dials the joiner and reads the group
/// that node declares about itself, and refuses `409` on anything else. This is
/// the one guard between a dev Pi and the prod quorum — until R742-F1 it was
/// three TOML comments saying "never run a raft join against this box from a
/// shell pointed at prod", which is exactly the shell this call arrives from.
///
/// Two properties of the gate are load-bearing:
///
/// - **The joiner is asked, not believed.** Its group comes from the joiner's
///   own `/raft/status`, never from [`RaftAddLearnerRequest`] and never from a
///   flag on this node. A request body cannot be the source of a fact whose
///   whole purpose is to catch a mis-aimed request.
/// - **It runs before `add_learner`, so it also fires on a follower.** A
///   follower would otherwise answer 421 and send the operator to retarget a
///   join at the leader that is going to be refused there anyway. When the gate
///   is *not* in force (this node declares no group) nothing is dialed at all,
///   so an unstamped cluster pays nothing and behaves exactly as it did before.
///
/// Status codes on top of the ones above:
/// - `409` — refused by the gate. Not a retry: the body names both declared
///   groups and the edit that makes the join legal.
/// - `502` — the joiner could not be asked (unreachable, timed out, no raft
///   there). Retryable, and distinct from `409` on purpose — "the box did not
///   answer" and "the box answered, with the wrong group" call for different
///   operator actions.
///
/// The 200 body carries `sovereign_group_judged`, so a join that the gate never
/// evaluated is never mistaken for one that passed it.
///
/// R736-T3 runs a second gate on the same answer: when this node declares a
/// `--jurisdiction` — which is what makes its group a **cell** — a joiner in a
/// different jurisdiction is refused `409` even though it is in the right group,
/// because one voter across a legal boundary breaks the residency promise for
/// every tenant already in the cell. The 200 body carries `cell_judged` beside
/// `sovereign_group_judged` on the same contract. See [`cell`].
async fn raft_add_learner(
    State(s): State<Arc<ServerState>>,
    Json(body): Json<RaftAddLearnerRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raft = require_raft!(s);

    // R742-F1: refuse a cross-group join before touching membership. R736-T3
    // adds the cell gate on the same declaration, so both questions are answered
    // from one status read of the joiner.
    let me = s
        .node_id
        .map(|id| format!("node {id}"))
        .unwrap_or_else(|| "this node".to_string());
    let joiner_label = format!("node {} at {}", body.node_id, body.addr);
    let (gate, cell_gate) = match s.sovereign_group.as_deref() {
        // Nothing declared here means no blast radius asserted, so there is
        // nothing to cross — and no reason to dial the joiner. A cell cannot
        // exist without a group either (`cell::identify`), so the cell gate is
        // off here by construction rather than by a second check.
        None => (sovereign_group::Gate::NotInForce, cell::Gate::NotInForce),
        Some(mine) => {
            let joiner = sovereign_group::ask_peer(&body.addr).await.map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!(
                        "join refused: could not ask the joiner (node {} at {}) which sovereign \
                     group it is in, and this cluster is in {mine:?} — growing a declared \
                     quorum with a node nothing could check is the join this gate exists to \
                     stop. Underlying error: {e}",
                        body.node_id, body.addr,
                    ),
                )
            })?;
            (
                sovereign_group::judge(
                    Some(mine),
                    s.sovereign_role,
                    &me,
                    &joiner.group,
                    &joiner_label,
                ),
                cell::judge(
                    s.jurisdiction.as_deref(),
                    &me,
                    &joiner.jurisdiction,
                    &joiner_label,
                ),
            )
        }
    };
    // Blast radius first, residency second: a jurisdiction refusal for a node
    // that was never in this raft group would send the operator to fix the wrong
    // label. See `cell::judge`.
    let judged_group = match gate {
        sovereign_group::Gate::Refuse(reason) => return Err((StatusCode::CONFLICT, reason)),
        sovereign_group::Gate::Permit(group) => Some(group),
        sovereign_group::Gate::NotInForce => None,
    };
    let judged_jurisdiction = match cell_gate {
        cell::Gate::Refuse(reason) => return Err((StatusCode::CONFLICT, reason)),
        cell::Gate::Permit(jurisdiction) => Some(jurisdiction),
        cell::Gate::NotInForce => None,
    };

    let node = openraft::BasicNode {
        addr: body.addr.clone(),
    };
    match raft.add_learner(body.node_id, node, true).await {
        Ok(resp) => Ok(Json(serde_json::json!({
            "added": true,
            "node_id": body.node_id,
            "addr": body.addr,
            "log_id": format!("{:?}", resp.log_id),
            // R742-F1: `false` means this cluster declares no sovereign group,
            // so the join was permitted without one being checked. Distinct
            // from a check that passed, which is the distinction W305 finding 3
            // is about.
            "sovereign_group_judged": judged_group.is_some(),
            "sovereign_group": judged_group,
            // R736-T3: same contract one axis over — `false` means this cluster
            // is a sovereign group but not a cell, so residency was not checked
            // rather than checked and found equal.
            "cell_judged": judged_jurisdiction.is_some(),
            "jurisdiction": judged_jurisdiction,
        }))),
        // Not the leader: hand back the redirect hint (leader id + node) so the
        // operator/orchestrator can retarget the call at the actual leader,
        // rather than a bare 500. Same class of error the write path can hit.
        Err(openraft::error::RaftError::APIError(
            openraft::error::ClientWriteError::ForwardToLeader(fwd),
        )) => Err((
            StatusCode::MISDIRECTED_REQUEST,
            format!(
                "add-learner must be called on the raft leader; forward to leader \
                 {:?} at {:?}",
                fwd.leader_id, fwd.leader_node
            ),
        )),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// `POST /raft/promote-voter` request — promote a caught-up learner (R118-T9).
#[derive(Deserialize)]
struct RaftPromoteVoterRequest {
    /// The learner's raft node id. It must already be in membership (added via
    /// [`raft_add_learner`]) — promotion never introduces a node.
    node_id: raft::YubabaNodeId,
}

/// `POST /raft/promote-voter` — promote an existing learner to a voter, if the
/// cluster policy allows it (R118-T9, closing the R625-S1/R608 thread).
///
/// The counterpart to [`raft_add_learner`]. Whether this is allowed at all is
/// read from [`ClusterPolicy::voter_admission`] rather than decided here: under
/// the fleet's [`LearnerOnly`] rule every request is refused with 403 and an
/// explanation, so the fixed founding voter set is preserved; a policy that
/// permits promotion allows it up to its voter cap.
///
/// [`LearnerOnly`]: cluster_policy::VoterAdmission::LearnerOnly
///
/// Must be called on the current **leader** (only the leader changes
/// membership); a follower answers 421 Misdirected with the forward hint.
/// Status codes:
/// - `200` — promoted, or already a voter (idempotent).
/// - `400` — the node is not in membership at all; add it as a learner first.
/// - `403` — refused by cluster policy. Permanent under this policy, not a retry.
/// - `421` — not the leader; retarget at the leader named in the body.
///
/// The membership change is `AddVoterIds`, which upgrades an existing learner
/// in place and leaves every other voter untouched — openraft drives the joint
/// consensus, so quorum is never reduced below the original voter set at any
/// point in the transition.
async fn raft_promote_voter(
    State(s): State<Arc<ServerState>>,
    Json(body): Json<RaftPromoteVoterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raft = require_raft!(s);
    let node = body.node_id;

    let membership = raft
        .metrics()
        .borrow_watched()
        .membership_config
        .membership()
        .clone();
    let voters: Vec<raft::YubabaNodeId> = membership.voter_ids().collect();
    let is_voter = voters.contains(&node);
    let known = membership.nodes().any(|(id, _)| *id == node);

    // A node the cluster has never heard of cannot be promoted — that would be
    // an add disguised as an upgrade, skipping the log catch-up that makes a
    // learner safe to hand a vote to.
    if !known && !is_voter {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "node {node} is not in this cluster's membership; add it as a learner \
                 (POST /raft/add-learner) and let it catch up before promoting it"
            ),
        ));
    }

    match s
        .cluster_policy
        .voter_admission
        .judge(node, voters.len(), is_voter)
    {
        PromotionVerdict::AlreadyVoter => {
            return Ok(Json(serde_json::json!({
                "promoted": false,
                "already_voter": true,
                "node_id": node,
                "voters": voters,
            })));
        }
        PromotionVerdict::Refuse(reason) => return Err((StatusCode::FORBIDDEN, reason)),
        PromotionVerdict::Promote => {}
    }

    let change = openraft::ChangeMembers::AddVoterIds(std::collections::BTreeSet::from([node]));
    match raft.change_membership(change, false).await {
        Ok(resp) => {
            let voters: Vec<raft::YubabaNodeId> = resp
                .membership()
                .as_ref()
                .map(|m| m.voter_ids().collect())
                .unwrap_or_default();
            tracing::info!(node_id = node, ?voters, "promoted learner to voter");
            Ok(Json(serde_json::json!({
                "promoted": true,
                "node_id": node,
                "voters": voters,
            })))
        }
        Err(openraft::error::RaftError::APIError(
            openraft::error::ClientWriteError::ForwardToLeader(fwd),
        )) => Err((
            StatusCode::MISDIRECTED_REQUEST,
            format!(
                "promote-voter must be called on the raft leader; forward to leader \
                 {:?} at {:?}",
                fwd.leader_id, fwd.leader_node
            ),
        )),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// `POST /raft/remove-member` request — take nodes out of the cluster (R734-T3).
#[derive(Deserialize)]
struct RaftRemoveMemberRequest {
    /// The node ids to remove. A **set**, not a single id, and that is the
    /// load-bearing part of this API rather than a convenience: the voter count
    /// must stay odd, so shrinking 5 → 3 has to remove two members in one
    /// membership change. Offering only a single-id verb would have made the
    /// legal shrink impossible to express and left operators removing one node
    /// "temporarily" into an even set.
    node_ids: std::collections::BTreeSet<raft::YubabaNodeId>,
}

/// `POST /raft/remove-member` — remove nodes from the cluster (R734-T3, W247 §4).
///
/// The third membership verb, symmetric with `/raft/add-learner` (join as a
/// non-voter) and `/raft/promote-voter` (learner → voter). Removed nodes leave
/// the cluster entirely — `retain: false` — rather than being demoted to
/// learners: a decommissioned box should stop receiving replication, and a node
/// left as a silent learner is a machine still holding full cluster state that
/// nobody remembers is there.
///
/// # The count gate
///
/// The **surviving** voter set is judged by
/// [`QuorumGeography::judge_voter_count`](cluster_policy::QuorumGeography::judge_voter_count)
/// before anything is proposed, so removing one voter from three is refused: it
/// would leave two, which tolerates no failures at all while requiring both
/// nodes for every write. That refusal is the point of the endpoint having a
/// gate — an operator draining a machine reaches for "remove one", and the even
/// set they land in looks healthy right up until either survivor blinks.
///
/// # The spread gate (R734-F5)
///
/// The region-spread half of [`QuorumGeography`](cluster_policy::QuorumGeography)
/// now applies here too, which it could not before: openraft's node type is
/// `BasicNode { addr }` and carries no region, so the only place a survivor's
/// region can come from is the replicated [`MemberInfo`](raft::MemberInfo) map —
/// and until [`member_registration`] nothing wrote it. Judging spread against
/// that empty map would have refused every removal on every real cluster, which
/// is why R734-T3 shipped with the count clause alone.
///
/// The clause matters because the count says nothing about *where* the
/// survivors are: removing both `us-west` voters from a 2-2-1 five-voter fleet
/// leaves three voters — odd, and perfectly happy — of which two are in
/// `us-east`. That cluster now dies with one datacenter, which is the exact
/// failure spanning regions exists to prevent, and nothing about it looks
/// different until the day it happens.
///
/// **It is judged only when it can be judged.** If this node holds no
/// applied-state handle, or any surviving voter has no member row yet, or has
/// one carrying no region, the spread clause is skipped and the count clause
/// stands alone. That is a deliberate trade against the stricter alternative of
/// refusing: a node that has not registered yet — a fresh join, a node on an
/// older build, a node that is *down*, which is the usual reason to be removing
/// something — would otherwise make every removal impossible, including the one
/// that would fix the cluster. A gate that can lock an operator out of the
/// repair verb is worse than one that occasionally cannot check. The response
/// says which happened in `spread_judged` rather than leaving it to be inferred.
///
/// Must be called on the current **leader**; a follower returns 421 with the
/// forward-to-leader hint. Removing the sitting leader is allowed — it commits
/// the new configuration and then steps down, which is what decommissioning it
/// means.
async fn raft_remove_member(
    State(s): State<Arc<ServerState>>,
    Json(body): Json<RaftRemoveMemberRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raft = require_raft!(s);

    let membership = raft
        .metrics()
        .borrow_watched()
        .membership_config
        .membership()
        .clone();
    let voters: std::collections::BTreeSet<raft::YubabaNodeId> = membership.voter_ids().collect();
    let known: std::collections::BTreeSet<raft::YubabaNodeId> =
        membership.nodes().map(|(id, _)| *id).collect();

    // Nodes the cluster has never heard of are already absent — report them so
    // a typo is visible, but do not fail: removal is idempotent, and an
    // operator re-running a drain script must not get an error for work that is
    // already done.
    let absent: Vec<raft::YubabaNodeId> = body
        .node_ids
        .iter()
        .copied()
        .filter(|id| !known.contains(id))
        .collect();
    let targets: std::collections::BTreeSet<raft::YubabaNodeId> = body
        .node_ids
        .iter()
        .copied()
        .filter(|id| known.contains(id))
        .collect();

    if targets.is_empty() {
        return Ok(Json(serde_json::json!({
            "removed": false,
            "already_absent": absent,
            "voters": voters.iter().copied().collect::<Vec<_>>(),
        })));
    }

    let target_voters: std::collections::BTreeSet<raft::YubabaNodeId> =
        targets.intersection(&voters).copied().collect();
    let target_learners: std::collections::BTreeSet<raft::YubabaNodeId> =
        targets.difference(&voters).copied().collect();

    // Only a change to the VOTER set can endanger quorum; removing learners
    // leaves it untouched, so they are not judged.
    let mut spread_judged = false;
    if !target_voters.is_empty() {
        let surviving: std::collections::BTreeSet<raft::YubabaNodeId> =
            voters.difference(&target_voters).copied().collect();
        if let GeographyVerdict::Refuse(reason) =
            cluster_policy::QuorumGeography::judge_voter_count(surviving.len())
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "removing {} voter(s) would leave {}: {reason}",
                    target_voters.len(),
                    surviving.len()
                ),
            ));
        }

        // R734-F5: the survivors' regions, if every one of them has published a
        // row carrying one. A single unknown makes the whole set unjudgeable —
        // `judge` would read the gap as an untagged voter and refuse, which is
        // the right answer at founding (the operator supplied those tags in the
        // same call) and the wrong one here (the operator did not write this
        // map, and the node that would have is possibly the one being removed).
        let survivor_regions: Option<std::collections::BTreeMap<_, _>> =
            s.cluster_state.as_ref().and_then(|sm| {
                let members = sm.members();
                surviving
                    .iter()
                    .map(|id| {
                        members
                            .get(id)
                            .and_then(|row| row.region.clone())
                            .map(|region| (*id, Some(region)))
                    })
                    .collect()
            });
        if let Some(regions) = survivor_regions {
            spread_judged = true;
            if let GeographyVerdict::Refuse(reason) =
                s.cluster_policy.quorum_geography.judge(&regions)
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "removing {:?} would leave a voter set that violates this cluster's \
                         quorum geography: {reason}",
                        target_voters
                    ),
                ));
            }
        }
    }

    let forward_to_leader = |fwd: openraft::error::ForwardToLeader<raft::YubabaRaftConfig>| {
        (
            StatusCode::MISDIRECTED_REQUEST,
            format!(
                "remove-member must be called on the raft leader; forward to leader \
                 {:?} at {:?}",
                fwd.leader_id, fwd.leader_node
            ),
        )
    };

    // Voters first. `retain: false` takes them out of the cluster rather than
    // demoting them; openraft drives the joint-consensus transition, so quorum
    // is never below the *intersection* of the old and new voter sets at any
    // point.
    if !target_voters.is_empty() {
        let change = openraft::ChangeMembers::RemoveVoters(target_voters.clone());
        if let Err(e) = raft.change_membership(change, false).await {
            return match e {
                openraft::error::RaftError::APIError(
                    openraft::error::ClientWriteError::ForwardToLeader(fwd),
                ) => Err(forward_to_leader(fwd)),
                e => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
            };
        }
    }

    if !target_learners.is_empty() {
        let change = openraft::ChangeMembers::RemoveNodes(target_learners.clone());
        if let Err(e) = raft.change_membership(change, false).await {
            return match e {
                openraft::error::RaftError::APIError(
                    openraft::error::ClientWriteError::ForwardToLeader(fwd),
                ) => Err(forward_to_leader(fwd)),
                e => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
            };
        }
    }

    // R734-F5: membership is the authority on who is in the cluster, but the
    // member-row map is what carries their regions, and a departed node's row
    // outlives its membership entry unless someone clears it. The departing node
    // cannot do it — its own registration loop goes quiet the moment it leaves
    // membership, which is correct (a node outside the cluster must not write to
    // it) and is exactly why the removing leader has to.
    //
    // Best-effort, deliberately: the membership change has already committed and
    // is the part that matters, so a failure here leaves a stale row rather than
    // reporting a removal that did happen as a failure. The one case that
    // reliably hits it is a leader removing itself — it steps down as the new
    // configuration commits, so this write finds no leader. `stale_rows` in the
    // response names what was left behind instead of hiding it.
    let mut stale_rows: Vec<raft::YubabaNodeId> = Vec::new();
    for id in &targets {
        if let Err(e) = raft
            .client_write(raft::YubabaRequest::RemoveMember { node_id: *id })
            .await
        {
            tracing::warn!(
                node_id = *id,
                "removed from membership but its member row could not be cleared \
                 (the row is stale metadata; membership is unaffected): {e}"
            );
            stale_rows.push(*id);
        }
    }

    let remaining: Vec<raft::YubabaNodeId> = raft
        .metrics()
        .borrow_watched()
        .membership_config
        .membership()
        .voter_ids()
        .collect();
    tracing::info!(
        removed_voters = ?target_voters,
        removed_learners = ?target_learners,
        voters = ?remaining,
        "removed members from the cluster"
    );
    Ok(Json(serde_json::json!({
        "removed": true,
        "removed_voters": target_voters.iter().copied().collect::<Vec<_>>(),
        "removed_learners": target_learners.iter().copied().collect::<Vec<_>>(),
        "already_absent": absent,
        "voters": remaining,
        // R734-F5: ids whose member row survived the removal. Empty on the
        // ordinary path; non-empty means the map still describes a node the
        // cluster no longer has.
        "stale_rows": stale_rows,
        // R734-F5: whether the region-spread clause was evaluated, or only the
        // voter count. False means some survivor had no published region, so
        // this removal was allowed without checking where it left the quorum.
        "spread_judged": spread_judged,
    })))
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

    // ── R732-T4: GET /tenants/{id}, the fencing-token transport ──────────────

    /// A node with no cluster state cannot answer an ownership question, and
    /// must say so rather than reporting "no owner" — those mean opposite
    /// things to a streamer deciding whether it may write.
    #[tokio::test]
    async fn tenant_ownership_is_unavailable_without_a_raft_cluster() {
        let (_tmp, state) = fresh_state();
        let resp = build_router(state)
            .oneshot(Request::get("/tenants/acme").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    async fn state_with_cluster() -> (
        tempfile::TempDir,
        Arc<ServerState>,
        raft::YubabaStateMachine,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let sm = raft::YubabaStateMachine::open(tmp.path().join("raft"))
            .await
            .unwrap();
        let state = ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_cluster_state(sm.clone());
        (tmp, Arc::new(state), sm)
    }

    /// An unknown tenant is a 404, not a 200 with nulls. "No record" and
    /// "record exists but is not yours" are different facts and an operator
    /// debugging a stalled streamer needs to tell them apart.
    #[tokio::test]
    async fn an_unknown_tenant_is_a_404() {
        let (_tmp, state, _sm) = state_with_cluster().await;
        let resp = build_router(state)
            .oneshot(Request::get("/tenants/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// The load-bearing behaviour: the endpoint hands the *owning* node its
    /// fencing token and hands every other node nothing. This is the entire
    /// transport R732-T4 exists to build — if it ever answered a non-owner
    /// with a token, the epoch would stop fencing anything.
    #[tokio::test]
    async fn the_owner_gets_a_fencing_token_and_nobody_else_does() {
        let (_tmp, state, sm) = state_with_cluster().await;
        let now = unix_now_secs() as u64;
        sm.apply_for_test(&raft::YubabaRequest::ClaimTenant {
            tenant: workload_spec::TenantId("acme".into()),
            node: 7,
            lease_secs: 300,
            now,
        });
        let app = build_router(state);

        let owner = body_json(
            app.clone()
                .oneshot(
                    Request::get("/tenants/acme?node=7")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(owner["fencing_token"], 1, "the owner must get its token");
        assert_eq!(owner["owner"], 7);
        assert_eq!(owner["epoch"], 1);
        assert_eq!(owner["live"], true);
        assert!(owner["lease_expires"].as_u64().unwrap() > owner["now"].as_u64().unwrap());

        let other = body_json(
            app.clone()
                .oneshot(
                    Request::get("/tenants/acme?node=8")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert!(
            other["fencing_token"].is_null(),
            "a non-owner must get no token, got {}",
            other["fencing_token"]
        );
        // ...but it still sees who *does* own it. That is the diagnostic half,
        // and it must not leak into the write decision.
        assert_eq!(other["owner"], 7);
        assert_eq!(other["epoch"], 1);

        // No `?node=` at all: a pure diagnostic read, never a token.
        let anon = body_json(
            app.oneshot(Request::get("/tenants/acme").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert!(anon["fencing_token"].is_null());
        assert_eq!(anon["epoch"], 1);
    }

    /// An expired lease yields no token even to the recorded owner, and the
    /// record is *retained* rather than deleted — R732-F1 is explicit that
    /// dropping it would let a zombie at a high epoch outrank a legitimate new
    /// owner who restarted counting at 1.
    #[tokio::test]
    async fn an_expired_lease_yields_no_token_but_keeps_the_record() {
        let (_tmp, state, sm) = state_with_cluster().await;
        // Claim far enough in the past that the lease has certainly lapsed by
        // the time the handler stamps its own `now`.
        let long_ago = unix_now_secs() as u64 - 10_000;
        sm.apply_for_test(&raft::YubabaRequest::ClaimTenant {
            tenant: workload_spec::TenantId("acme".into()),
            node: 7,
            lease_secs: 30,
            now: long_ago,
        });

        let body = body_json(
            build_router(state)
                .oneshot(
                    Request::get("/tenants/acme?node=7")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert!(
            body["fencing_token"].is_null(),
            "an expired lease must not yield a token even to the recorded owner"
        );
        assert_eq!(body["live"], false);
        assert_eq!(body["owner"], 7, "the record survives expiry");
        assert_eq!(
            body["epoch"], 1,
            "and so does the epoch, so it cannot regress"
        );
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

    /// R646: the end-to-end producer path. A consumer publishes metrics yubaba
    /// has no idea how to measure, and they come back out of `/node/usage`
    /// beside the built-in ones — the whole point of the metric set being open
    /// rather than a hardcoded struct per downstream.
    #[tokio::test]
    async fn published_domain_metrics_come_back_out_of_node_usage() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::post("/node/metrics")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "source": "plinth-3",
                            "metrics": {
                                "noisetable.audio.xruns": 4,
                                "noisetable.audio.deadline_misses": 0,
                                "noisetable.ble.advert_hz": 9.5
                            },
                            "ttl_ms": 30000
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let body = body_json(
            app.clone()
                .oneshot(
                    Request::get("/node/usage?window_ms=50")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;

        // Flat siblings of the machine measurements, not nested.
        assert_eq!(body["noisetable.audio.xruns"], 4);
        assert_eq!(body["noisetable.audio.deadline_misses"], 0);
        assert_eq!(body["noisetable.ble.advert_hz"], 9.5);
        assert_eq!(body["yah.metrics.plinth-3.stale"], false);
        assert!(body["yah.metrics.plinth-3.age_ms"].is_number());
        // The built-in half is untouched by the merge.
        assert!(body["yah.cpu.source"].is_string());
        assert_eq!(body["yah.committed.memory_mb"], 0);

        // `GET /node/metrics` is the same contribution without paying for a
        // CPU sampling window — the confirm-my-push path.
        let only = body_json(
            app.clone()
                .oneshot(Request::get("/node/metrics").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(only["noisetable.audio.xruns"], 4);
        assert!(only.get("yah.cpu.source").is_none());

        // Clean withdrawal removes the keys at once; a second one is a 404.
        let resp = app
            .clone()
            .oneshot(
                Request::delete("/node/metrics/plinth-3")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let resp = app
            .clone()
            .oneshot(
                Request::delete("/node/metrics/plinth-3")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let after = body_json(
            app.oneshot(Request::get("/node/metrics").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(after, serde_json::json!({}));
    }

    /// A rejected publish must name what was wrong in the response body: the
    /// producer is remote and this is the only debugging channel it has.
    #[tokio::test]
    async fn a_reserved_metric_key_is_refused_with_a_named_400() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::post("/node/metrics")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "source": "rogue",
                            "metrics": { "system.cpu.utilization": 0.0 }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = body_json(resp).await;
        assert!(
            err["error"]
                .as_str()
                .unwrap()
                .contains("system.cpu.utilization"),
            "{err}"
        );

        // Nothing was written, so the real measurement is still the only
        // `system.cpu.utilization` in the payload.
        let usage = body_json(
            app.oneshot(
                Request::get("/node/usage?window_ms=50")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert!(usage.get("yah.metrics.sources").is_none());
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

    /// R609-F1: `node_id` alone can't tell a caller whether the node is
    /// dialable over iroh — every node has one, because it IS the hostkey.
    /// A node started without `--control-plane` must therefore omit the
    /// advertisement, so a desktop reading `/identity` doesn't dial into a
    /// timeout.
    #[tokio::test]
    async fn identity_omits_the_control_plane_advert_when_none_is_bound() {
        let (_tmp, state) = fresh_state();
        assert!(state.control_plane.is_none());
        let app = build_router(state);

        let resp = app
            .oneshot(Request::get("/identity").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(
            body.get("control_plane_alpn").is_none(),
            "an HTTP-only node must not advertise a control-plane ALPN: {body}"
        );
    }

    /// The other half: with an endpoint bound, `/identity` advertises the
    /// ALPN **and** the advertised `node_id` is the endpoint's own — i.e.
    /// the value a caller reads here is the value it dials, not a
    /// fingerprint that merely looks like one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identity_advertises_the_bound_control_plane() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = ServerState::load(tmp.path().join("identity.json")).unwrap();
        let endpoint = control_plane::bind(&state.hostkey_dir()).await.unwrap();
        let endpoint_node_id = endpoint.node_id().to_string();
        let state = state.with_control_plane(endpoint.clone());
        let app = build_router(Arc::new(state));

        let resp = app
            .oneshot(Request::get("/identity").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(
            body["control_plane_alpn"],
            control_plane::CONTROL_PLANE_ALPN_STR
        );
        assert_eq!(
            body["node_id"], endpoint_node_id,
            "the advertised node_id must be the endpoint's own — otherwise \
             the advert points somewhere undialable"
        );

        endpoint.close().await;
    }

    /// R609-F3: `/identity` advertises the camp-RPC lane only when the lane
    /// is actually served. An ungated endpoint withholds it (admitting a
    /// camp-RPC dial spawns a process), and advertising a withheld lane
    /// would send a desktop into an ALPN negotiation that fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identity_withholds_the_camp_rpc_advert_until_admission_gates_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let camp_rpc = Some(camp_rpc::CampRpcConfig {
            yah_bin: "yah".into(),
            roots: vec![tmp.path().to_path_buf()],
        });

        let ungated = control_plane::Planes {
            camp_rpc: camp_rpc.clone(),
            admission: control_plane::Admission::AllowAll,
            ..control_plane::Planes::default()
        };
        let state = ServerState::load(tmp.path().join("identity.json")).unwrap();
        let endpoint = control_plane::bind(&state.hostkey_dir()).await.unwrap();
        let state = state.with_control_plane_planes(endpoint.clone(), ungated);
        let body = body_json(
            build_router(Arc::new(state))
                .oneshot(Request::get("/identity").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert!(
            body.get("camp_rpc_alpn").is_none(),
            "an ungated node must not advertise a lane it refuses to serve: {body}"
        );

        let gated = control_plane::Planes {
            camp_rpc,
            admission: control_plane::Admission::entitled(
                control_plane::Entitlement::new().allow(endpoint.node_id()),
            ),
            ..control_plane::Planes::default()
        };
        let state = ServerState::load(tmp.path().join("identity.json")).unwrap();
        let state = state.with_control_plane_planes(endpoint.clone(), gated);
        let body = body_json(
            build_router(Arc::new(state))
                .oneshot(Request::get("/identity").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["camp_rpc_alpn"], camp_rpc::CAMP_RPC_ALPN_STR);

        endpoint.close().await;
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

    /// R646-B1: write a throwaway stand-in for the headscale binary into `dir`
    /// and return the `file://` URL for it. Paired with
    /// `with_headscale_download_url`, this keeps the `/headscale/deploy` and
    /// `/headscale/bootstrap` tests off the public internet — they used to curl
    /// a ~30MB GitHub release on every run, which made them slow and made their
    /// pass/fail depend on the network rather than on the code.
    fn headscale_fixture_url(dir: &std::path::Path) -> String {
        let fixture = dir.join("headscale-fixture-binary");
        std::fs::write(&fixture, HEADSCALE_FIXTURE_BYTES).unwrap();
        format!("file://{}", fixture.display())
    }

    const HEADSCALE_FIXTURE_BYTES: &[u8] = b"#!/bin/sh\n# not really headscale\nexit 0\n";

    #[tokio::test]
    async fn headscale_deploy_writes_files_to_headscale_dir() {
        let (tmp, state_base) = fresh_state();
        // Override headscale_dir to a temp directory so we don't touch /etc.
        let headscale_tmp = tempfile::TempDir::new().unwrap();
        let dl_url = headscale_fixture_url(tmp.path());
        let state = {
            let state_raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(
                state_raw
                    .with_headscale_dir(headscale_tmp.path())
                    .with_headscale_download_url(dl_url),
            )
        };

        let app = build_router(state);

        use base64::Engine as _;
        let engine = base64::engine::general_purpose::STANDARD;
        let req_body = serde_json::json!({
            "headscale_version": "0.23.0",
            "db_base64": engine.encode(b"test-db"),
            "private_key_base64": engine.encode(b"test-private-key"),
            "noise_key_base64": engine.encode(b"test-noise-key"),
            // R861-T2: nothing carried. The transplanted headscale.db is the
            // policy source under `policy.mode: database`. (This fixture used
            // to send `---\nacls: []`, which headscale's HuJSON loader would
            // have refused outright — it was never a policy headscale could
            // have booted on.)
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

        // The download now comes from a local fixture, so the only remaining
        // environment-dependent step is systemd — and that one is best-effort
        // (`write_and_start_headscale_unit` returns false rather than erroring).
        // 500 stays accepted for a host whose curl lacks the `file` protocol;
        // either way the state files below must already be on disk.
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
        // R861-T2: acls.yaml is NOT recreated. A newly-deployed coordinator
        // must not carry back the very file the migration deletes.
        assert!(!headscale_tmp.path().join("acls.yaml").exists());
        assert!(headscale_tmp.path().join("config.yaml").exists());

        let config = std::fs::read_to_string(headscale_tmp.path().join("config.yaml")).unwrap();
        assert!(config.contains("server_url: https://mesh.example.com"));
    }

    /// R861-T2. Under `policy.mode: database` the policy travels inside the
    /// transplanted `headscale.db`, so a carried non-permissive `acl_policy`
    /// means the SOURCE was still file-mode and its DB has no policy row.
    /// Writing `acls.yaml` would no longer carry it and the destination would
    /// come up allow-all — a silent widening. Refuse instead.
    #[tokio::test]
    async fn headscale_deploy_refuses_a_carried_non_default_policy() {
        let (_tmp, state_base) = fresh_state();
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
            "acl_policy": "{\"acls\":[{\"action\":\"accept\",\"src\":[\"tag:ci\"],\"dst\":[\"*:22\"]}]}",
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
        // And it refused BEFORE laying anything down.
        assert!(!headscale_tmp.path().join("acls.yaml").exists());
    }

    #[test]
    fn permissive_default_is_recognised_through_reformatting() {
        // Empty = nothing carried.
        assert!(carried_policy_is_permissive_default(""));
        assert!(carried_policy_is_permissive_default("\n  \n"));
        // The constant itself, and the exact 77 bytes measured on us-west-001's
        // live acls.yaml 2026-09-04 — same document, different formatting.
        assert!(carried_policy_is_permissive_default(
            DEFAULT_ACL_POLICY_HUJSON
        ));
        assert!(carried_policy_is_permissive_default(
            "{\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}]}"
        ));
        // Anything that restricts anything is not the default.
        assert!(!carried_policy_is_permissive_default(
            "{\"acls\":[{\"action\":\"accept\",\"src\":[\"tag:ci\"],\"dst\":[\"*:*\"]}]}"
        ));
        // Not even an empty ruleset — that is MORE restrictive, not less, and
        // dropping it would widen the tailnet.
        assert!(!carried_policy_is_permissive_default("{\"acls\":[]}"));
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

    /// R646-B1: the anti-regression for the download seam itself. The two tests
    /// above only assert on files the handler writes *before* the download, so
    /// they'd still pass if `headscale_download_url` were silently ignored and
    /// the handler went back to curling GitHub. This one reads the downloaded
    /// binary back: it can only hold the fixture bytes if the override reached
    /// `download_headscale_binary`.
    #[tokio::test]
    async fn headscale_deploy_downloads_from_url_override() {
        let (tmp, state_base) = fresh_state();
        let headscale_tmp = tempfile::TempDir::new().unwrap();
        let dl_url = headscale_fixture_url(tmp.path());
        let state = {
            let state_raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(
                state_raw
                    .with_headscale_dir(headscale_tmp.path())
                    .with_headscale_download_url(dl_url),
            )
        };
        let app = build_router(state);

        use base64::Engine as _;
        let engine = base64::engine::general_purpose::STANDARD;
        let req_body = serde_json::json!({
            "headscale_version": "0.23.0",
            "db_base64": engine.encode(b"test-db"),
            "private_key_base64": engine.encode(b"test-private-key"),
            "noise_key_base64": engine.encode(b"test-noise-key"),
            // R861-T2: nothing carried — the transplanted headscale.db is the
            // policy source under `policy.mode: database`.
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
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "deploy from a local fixture should not fail at the download step"
        );

        let downloaded = headscale_tmp.path().join("headscale");
        assert_eq!(
            std::fs::read(&downloaded).unwrap(),
            HEADSCALE_FIXTURE_BYTES,
            "handler curled something other than the override URL"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&downloaded).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755, "downloaded binary not made executable");
        }
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

    /// R591-F1. `headscale serve` exits 0 on SIGTERM, so `Restart=on-failure`
    /// — what this function wrote until now — leaves a gracefully-stopped
    /// coordinator dead. That is not a hypothetical: it cost seven days of
    /// tailnet outage on 2026-07-09. The live unit was hand-patched; this
    /// asserts the *generator* can no longer reinstall the outage on the next
    /// `POST /headscale/deploy`.
    #[test]
    fn the_headscale_unit_restarts_on_a_graceful_exit() {
        let unit = headscale_unit_text(
            std::path::Path::new("/var/lib/yah-cloud/headscale/headscale"),
            std::path::Path::new("/var/lib/yah-cloud/headscale"),
        );
        assert!(
            unit.contains("Restart=always"),
            "unit must restart on a clean exit 0, got:\n{unit}"
        );
        assert!(
            !unit.contains("Restart=on-failure"),
            "on-failure does not restart headscale's graceful SIGTERM exit"
        );
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
        // R861-T2: policy lives in headscale.db (litestream replicates it), not
        // in an acls.yaml that nothing replicates. This site is the one that
        // spells the block with escaped spaces (`\x20\x20mode:`), so a grep for
        // a literal two-space prefix misses it — assert on it explicitly.
        assert!(cfg.contains(&format!("mode: {HEADSCALE_POLICY_MODE}")));
        assert!(!cfg.contains("acls.yaml"));
    }

    #[tokio::test]
    async fn headscale_bootstrap_writes_config_before_start() {
        let (tmp, state_base) = fresh_state();
        let headscale_tmp = tempfile::TempDir::new().unwrap();
        let dl_url = headscale_fixture_url(tmp.path());
        let state = {
            let state_raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(
                state_raw
                    .with_headscale_dir(headscale_tmp.path())
                    .with_headscale_download_url(dl_url),
            )
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
        // config must be written first either way.
        let status = resp.status();
        assert!(
            status.is_success() || status == StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected status {status}"
        );
        // R861-T2: a fresh coordinator gets no acls.yaml. Under
        // `policy.mode: database` an absent policy row is allow-all, which is
        // exactly what DEFAULT_ACL_POLICY_HUJSON used to write.
        assert!(!headscale_tmp.path().join("acls.yaml").exists());
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

    // ── cluster compatibility epochs on /health (R625-F4) ────────────────────

    #[tokio::test]
    async fn health_declares_both_cluster_compatibility_epochs() {
        // The point of the field: a version string cannot say which raft
        // protocol a node speaks (two different builds both called "0.8.20"),
        // so the rolling-upgrade preflight needs the node to *declare* it.
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

        // Both present, both integers — NOT skip_serializing_if. A build that
        // carries R625 always declares; only an older node omits them, and the
        // executor treats that omission as unproven.
        assert_eq!(
            body["cluster_protocol"],
            serde_json::json!(cluster_epoch::CLUSTER_PROTOCOL),
            "got {body}"
        );
        assert_eq!(
            body["state_epoch"],
            serde_json::json!(cluster_epoch::STATE_EPOCH),
            "got {body}"
        );
    }

    #[tokio::test]
    async fn health_epochs_come_from_the_declaration_file_not_the_version() {
        // Guard against someone "simplifying" these into a derivation of
        // CARGO_PKG_VERSION — the entire premise of W275's epoch addendum is
        // that the compatibility boundary is NOT the product version.
        let (_tmp, state) = fresh_state();
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let declared: serde_json::Value =
            serde_json::from_str(include_str!("../cluster-epochs.json")).unwrap();
        assert_eq!(body["cluster_protocol"], declared["cluster_protocol"]);
        assert_eq!(body["state_epoch"], declared["state_epoch"]);
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

    /// `deploy_compose` now rewrites the unit whenever the generated text
    /// differs from what is on disk, instead of only writing when the file is
    /// absent. Two properties hold that up: the text must be a pure function of
    /// the compose dir (otherwise the compare rewrites and `daemon-reload`s on
    /// every single deploy), and it must actually *vary* with the dir (a node
    /// deployed once under an old `compose_dir` kept a stale `WorkingDirectory`
    /// forever under the old guard).
    #[test]
    fn the_compose_unit_text_is_stable_and_tracks_the_dir() {
        let a = compose_unit_text(std::path::Path::new("/var/lib/yah-cloud/compose"));
        assert_eq!(
            a,
            compose_unit_text(std::path::Path::new("/var/lib/yah-cloud/compose")),
            "same dir must yield byte-identical text, or every deploy rewrites"
        );
        assert!(a.contains("WorkingDirectory=/var/lib/yah-cloud/compose"));

        let b = compose_unit_text(std::path::Path::new("/srv/compose"));
        assert_ne!(a, b, "a moved compose dir must reach the unit");
        assert!(b.contains("WorkingDirectory=/srv/compose"));
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

    // ── R860-B3: the deploy handler REACHES the dependency gate ──────────────
    //
    // Every test here drives `POST /workloads/deploy` through the real router.
    // That is the whole point of the ticket: `deploy::mesh_resolve` had a full
    // unit suite and zero production callers, so a test that called
    // `await_dependencies` directly passed for three relays while `depends_on`
    // enforced nothing. These assert on what the BACKEND was handed — an empty
    // recording means the gate ran before the workload could start.

    /// A `Kamaji` backend that records the specs it is asked to deploy.
    #[derive(Default)]
    struct RecordingRuntime {
        deployed: std::sync::Mutex<Vec<workload_spec::WorkloadSpec>>,
        /// R860-T6: idents this backend was asked to tear down, in order. The
        /// teardown cascade's whole claim is about *which* workloads die with a
        /// requirer, so the test has to read the backend's teardowns and not
        /// only the registries yubaba keeps beside them.
        torn_down: std::sync::Mutex<Vec<String>>,
    }

    impl RecordingRuntime {
        fn specs(&self) -> Vec<workload_spec::WorkloadSpec> {
            self.deployed.lock().unwrap().clone()
        }

        /// Mesh idents of everything deployed, in the order the backend saw
        /// them — which is the order the group was stood up in.
        fn deploy_order(&self) -> Vec<String> {
            self.specs()
                .iter()
                .map(|s| s.expose.mesh.identity.0.clone())
                .collect()
        }

        fn teardown_order(&self) -> Vec<String> {
            self.torn_down.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl kamaji::Kamaji for RecordingRuntime {
        fn backend(&self) -> kamaji::Backend {
            kamaji::Backend::Containerd
        }
        async fn deploy_workload(
            &self,
            spec: &workload_spec::WorkloadSpec,
            mesh: &kamaji::MeshAssignment,
        ) -> anyhow::Result<kamaji::DeployResult> {
            self.deployed.lock().unwrap().push(spec.clone());
            Ok(kamaji::DeployResult {
                container_id: "recorded".into(),
                mesh_ip: mesh.mesh_ip,
                task_pid: 1,
                ports: std::collections::BTreeMap::new(),
            })
        }
        async fn list_workloads(&self) -> anyhow::Result<Vec<kamaji::WorkloadState>> {
            Ok(vec![])
        }
        async fn get_workload(
            &self,
            _ident: &workload_spec::MeshIdent,
        ) -> anyhow::Result<Option<kamaji::WorkloadState>> {
            Ok(None)
        }
        async fn stream_logs(
            &self,
            _ident: &workload_spec::MeshIdent,
            _opts: kamaji::LogOpts,
        ) -> anyhow::Result<kamaji::LogStream> {
            anyhow::bail!("RecordingRuntime: no logs")
        }
        async fn restart_workload(&self, _ident: &workload_spec::MeshIdent) -> anyhow::Result<()> {
            Ok(())
        }
        async fn teardown_workload(&self, ident: &workload_spec::MeshIdent) -> anyhow::Result<()> {
            self.torn_down.lock().unwrap().push(ident.0.clone());
            Ok(())
        }
        async fn health(&self) -> anyhow::Result<kamaji::RuntimeHealth> {
            anyhow::bail!("RecordingRuntime: no health")
        }
    }

    fn state_with_recording_runtime() -> (tempfile::TempDir, Arc<ServerState>, Arc<RecordingRuntime>)
    {
        let tmp = tempfile::TempDir::new().unwrap();
        let rt = Arc::new(RecordingRuntime::default());
        let state = ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_runtime(rt.clone());
        (tmp, Arc::new(state), rt)
    }

    /// A container spec the deploy handler will accept, with one anonymous
    /// mesh port so it is a serving workload.
    fn mesh_spec(ident: &str, port: u16) -> workload_spec::WorkloadSpec {
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
            vec![port],
        );
        spec.expose.mesh.identity = MeshIdent(ident.into());
        spec
    }

    async fn post_deploy(
        state: Arc<ServerState>,
        spec: &workload_spec::WorkloadSpec,
    ) -> axum::response::Response {
        let body = serde_json::json!({ "spec": serde_json::to_value(spec).unwrap() });
        build_router(state)
            .oneshot(
                Request::post("/workloads/deploy")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    // ── R858-B11: the health field must read the shape yubaba deploys ────────

    /// A kamaji that answers `get_workload` for the appliance and records what
    /// it was asked about — the supervisor half of the deployed shape, without
    /// needing a Linux box, a systemd unit, or a bound port.
    #[derive(Default)]
    struct ApplianceSupervisorFake {
        status: Option<kamaji::WorkloadStatus>,
        asked: std::sync::Mutex<Vec<String>>,
    }

    impl ApplianceSupervisorFake {
        fn reporting(status: kamaji::WorkloadStatus) -> Self {
            Self {
                status: Some(status),
                asked: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl kamaji::Kamaji for ApplianceSupervisorFake {
        fn backend(&self) -> kamaji::Backend {
            kamaji::Backend::Native
        }
        async fn deploy_workload(
            &self,
            _spec: &workload_spec::WorkloadSpec,
            mesh: &kamaji::MeshAssignment,
        ) -> anyhow::Result<kamaji::DeployResult> {
            Ok(kamaji::DeployResult {
                container_id: "native:517125".into(),
                mesh_ip: mesh.mesh_ip,
                task_pid: 517125,
                ports: std::collections::BTreeMap::new(),
            })
        }
        async fn list_workloads(&self) -> anyhow::Result<Vec<kamaji::WorkloadState>> {
            Ok(vec![])
        }
        async fn get_workload(
            &self,
            ident: &workload_spec::MeshIdent,
        ) -> anyhow::Result<Option<kamaji::WorkloadState>> {
            self.asked.lock().unwrap().push(ident.0.clone());
            Ok(self
                .status
                .clone()
                .map(|status| kamaji::WorkloadState {
                    ident: ident.clone(),
                    container_id: "native:517125".into(),
                    status,
                    mesh_ip: None,
                    ports: std::collections::BTreeMap::new(),
                }))
        }
        async fn stream_logs(
            &self,
            _ident: &workload_spec::MeshIdent,
            _opts: kamaji::LogOpts,
        ) -> anyhow::Result<kamaji::LogStream> {
            anyhow::bail!("ApplianceSupervisorFake: no logs")
        }
        async fn restart_workload(&self, _ident: &workload_spec::MeshIdent) -> anyhow::Result<()> {
            Ok(())
        }
        async fn teardown_workload(&self, _ident: &workload_spec::MeshIdent) -> anyhow::Result<()> {
            Ok(())
        }
        async fn health(&self) -> anyhow::Result<kamaji::RuntimeHealth> {
            anyhow::bail!("ApplianceSupervisorFake: no health")
        }
    }

    fn state_with_supervisor(
        fake: ApplianceSupervisorFake,
    ) -> (tempfile::TempDir, Arc<ServerState>, Arc<ApplianceSupervisorFake>) {
        let tmp = tempfile::TempDir::new().unwrap();
        let rt = Arc::new(fake);
        let state = ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_runtime(rt.clone());
        (tmp, Arc::new(state), rt)
    }

    /// **The acceptance test for R858-B11**, and the one whose absence let the
    /// defect ship: it exercises the NORMAL kamaji-supervised state.
    ///
    /// The old field was `systemd_active || api_reachable`, and on a coordinator
    /// running the appliance the way `leader::start_headscale` deploys it, both
    /// are false by construction — the systemd unit is stopped and disabled in
    /// the same second the kamaji workload starts. A test written against the
    /// systemd-fallback shape passes on code that reports every healthy
    /// coordinator as "stopped", which is exactly what happened.
    ///
    /// Neither of the two old signals can be true here: there is no systemd unit
    /// under a tempdir and nothing is deployed on any port. The only thing that
    /// can make this pass is the supervisor query.
    #[tokio::test]
    async fn the_health_field_reads_running_on_a_kamaji_supervised_appliance() {
        let (_tmp, state, rt) = state_with_supervisor(ApplianceSupervisorFake::reporting(
            kamaji::WorkloadStatus::Running,
        ));

        let resp = build_router(state)
            .oneshot(Request::get("/headscale/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;

        assert_eq!(
            body["headscale"], "running",
            "a kamaji-supervised appliance is RUNNING; reporting it as stopped is the \
             defect that argued for restarting yubaba on the live coordinator"
        );
        assert_eq!(
            body["supervised"], true,
            "the supervisor is what answered, and the body must say so"
        );
        assert_eq!(
            rt.asked.lock().unwrap().as_slice(),
            [headscale_appliance::HEADSCALE_IDENT],
            "the probe must ask about the appliance by its stable ident"
        );
    }

    /// The falsification probe, written to be independent of the host: drop the
    /// `supervised ||` arm out of `running()` and the first assertion fails.
    ///
    /// Deliberately not routed through the HTTP handler — `api_reachable` dials
    /// `127.0.0.1:8080`, and on a dev machine something unrelated may be
    /// listening there. This asserts the decision rule itself, so it cannot go
    /// green for an environmental reason.
    #[test]
    fn the_supervisor_signal_alone_is_enough_to_say_running() {
        assert!(
            HeadscaleLiveness {
                supervised: true,
                systemd_active: false,
                api_reachable: false,
            }
            .running(),
            "kamaji reporting the appliance Running must be sufficient on its own — \
             this is the exact combination the live fleet is in"
        );
        assert!(
            !HeadscaleLiveness {
                supervised: false,
                systemd_active: false,
                api_reachable: false,
            }
            .running(),
            "with nothing reporting it up, the answer is still stopped"
        );
        // The fallbacks are kept, not retired: a node whose kamaji predates
        // `--native-exec-dir` runs the appliance under systemd, and that is the
        // real signal there.
        assert!(
            HeadscaleLiveness {
                supervised: false,
                systemd_active: true,
                api_reachable: false,
            }
            .running(),
            "the systemd fallback must still be able to say yes"
        );
    }

    /// A supervisor that answers, and answers something other than `Running`,
    /// is not evidence the appliance is up. Only the `supervised` field is
    /// asserted, so the host's port 8080 cannot make this pass or fail.
    #[tokio::test]
    async fn a_supervisor_reporting_a_stopped_appliance_does_not_claim_it_is_supervised() {
        let (_tmp, state, _rt) = state_with_supervisor(ApplianceSupervisorFake::reporting(
            kamaji::WorkloadStatus::Stopped,
        ));
        assert!(
            !headscale_liveness(&state).await.supervised,
            "a Stopped workload must not read as a live appliance"
        );

        let (_tmp2, absent, _rt2) = state_with_supervisor(ApplianceSupervisorFake::default());
        assert!(
            !headscale_liveness(&absent).await.supervised,
            "a supervisor that has never heard of the appliance must not vouch for it"
        );
    }

    /// `/mesh/leader-health` had the same inversion and a worse consequence: it
    /// called `probe_headscale_local` *alone*, with not even the systemd
    /// fallback, so on a kamaji-supervised coordinator it answered 503
    /// unconditionally — the signal an external load balancer reads to decide
    /// the leader is not serving.
    ///
    /// 503 here is correct and expected for the *leader* half: this fixture
    /// configures no raft, so `leader` is legitimately false. The field under
    /// test is `headscale`.
    #[tokio::test]
    async fn leader_health_asks_the_supervisor_not_only_the_hardcoded_port() {
        let (_tmp, state, rt) = state_with_supervisor(ApplianceSupervisorFake::reporting(
            kamaji::WorkloadStatus::Running,
        ));

        let resp = build_router(state)
            .oneshot(
                Request::get("/mesh/leader-health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "no raft configured, so this node is not the leader"
        );
        let body = body_json(resp).await;

        assert_eq!(body["leader"], false);
        assert_eq!(
            body["headscale"], "running",
            "the headscale half must reflect the supervisor, not a port the \
             appliance does not bind"
        );
        assert_eq!(
            rt.asked.lock().unwrap().as_slice(),
            [headscale_appliance::HEADSCALE_IDENT],
            "leader-health must route through the same one probe"
        );
    }

    /// The bug this ticket exists for: a workload declaring `depends_on` used
    /// to start immediately, because nothing called the gate. It must now be
    /// refused, and — the load-bearing half — the backend must never have been
    /// asked to run it.
    ///
    /// `start_paused` fast-forwards the poll loop's real 30s-per-dep budget;
    /// the deadline arithmetic is exercised for real, just not in wall time.
    #[tokio::test(start_paused = true)]
    async fn a_deploy_whose_dependency_never_appears_is_refused_before_the_backend_is_called() {
        let (_tmp, state, rt) = state_with_recording_runtime();
        let mut spec = mesh_spec("consumer", 8080);
        spec.depends_on = vec![workload_spec::MeshIdent("absent-dep".into())];

        let resp = post_deploy(state, &spec).await;

        assert_eq!(resp.status(), StatusCode::FAILED_DEPENDENCY);
        let body = body_json(resp).await;
        assert!(
            body["error"].as_str().unwrap().contains("dependency wait"),
            "error should name the dependency wait, got: {}",
            body["error"]
        );
        assert!(
            rt.specs().is_empty(),
            "the gate must run BEFORE the workload starts — backend was called anyway"
        );
    }

    /// The other side of the same gate: a dependency already in the node's
    /// service-record registry satisfies it, and the deploy proceeds.
    #[tokio::test(start_paused = true)]
    async fn a_dependency_present_in_the_service_records_satisfies_the_gate() {
        let (_tmp, state, rt) = state_with_recording_runtime();
        let dep = mesh_spec("db", 5432);
        state
            .service_records
            .upsert_deployed(&dep, std::net::Ipv4Addr::new(100, 64, 0, 7), "dep-container");

        let mut spec = mesh_spec("consumer", 8080);
        spec.depends_on = vec![workload_spec::MeshIdent("db".into())];

        let resp = post_deploy(state, &spec).await;

        assert_eq!(
            rt.specs().len(),
            1,
            "a satisfied dependency must not block the deploy (status was {})",
            resp.status()
        );
    }

    // ── R860-T2: the gate knows WHICH node, and knows Ready from present ─────
    //
    // The decision logic is unit-tested in `deploy::mesh_resolve`; these three
    // exist because that logic needs two things only the real deploy path can
    // supply — the node's own mesh address (`ServerState::node_mesh_ip`,
    // threaded into `ServiceRecordMeshState`) and a real `ServiceRecord`'s
    // health. A unit test cannot tell a correctly-threaded address from a
    // hardcoded one.

    fn state_with_recording_runtime_on_node(
        node_ip: &str,
    ) -> (tempfile::TempDir, Arc<ServerState>, Arc<RecordingRuntime>) {
        let tmp = tempfile::TempDir::new().unwrap();
        let rt = Arc::new(RecordingRuntime::default());
        let state = ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_bind_addr(&format!("{node_ip}:9443"))
            .with_runtime(rt.clone());
        (tmp, Arc::new(state), rt)
    }

    fn local_requirement(ident: &str) -> workload_spec::Requirement {
        workload_spec::Requirement {
            ident: workload_spec::MeshIdent(ident.into()),
            locality: workload_spec::Locality::Local,
            supply: workload_spec::Supply::Wait,
            provides: None,
        }
    }

    /// W338: `local` means "only a provider on **this node** satisfies it".
    /// Before this ticket the gate did a plain presence check for every
    /// locality, so this deploy succeeded against a provider one hop away —
    /// which for the motivating case (a replicator that must open the same
    /// sqlite file on the same filesystem) is silent data corruption.
    #[tokio::test(start_paused = true)]
    async fn a_local_requirement_is_refused_when_its_only_provider_is_on_another_node() {
        let (_tmp, state, rt) = state_with_recording_runtime_on_node("100.64.0.7");
        let dep = mesh_spec("replicator", 5432);
        // The record's mesh_ip is the answering node's own address (R844-B11),
        // so a record carrying .9 is a provider on node .9 — not on us.
        state
            .service_records
            .upsert_deployed(&dep, std::net::Ipv4Addr::new(100, 64, 0, 9), "dep-container");

        let mut spec = mesh_spec("consumer", 8080);
        spec.requires = vec![local_requirement("replicator")];

        let resp = post_deploy(state, &spec).await;

        assert_eq!(resp.status(), StatusCode::FAILED_DEPENDENCY);
        assert!(
            rt.specs().is_empty(),
            "the backend must never have been asked to run a workload whose \
             local requirement is satisfied only remotely"
        );
    }

    /// The same spec, the same registry, one address changed: the provider is
    /// on this node, so the gate opens. This is the assertion that proves
    /// `node_mesh_ip` is actually threaded through — flip the wiring to a
    /// hardcoded `None` and this test fails while the one above still passes.
    #[tokio::test(start_paused = true)]
    async fn a_local_requirement_is_satisfied_by_a_provider_on_this_node() {
        let (_tmp, state, rt) = state_with_recording_runtime_on_node("100.64.0.7");
        let dep = mesh_spec("replicator", 5432);
        state
            .service_records
            .upsert_deployed(&dep, std::net::Ipv4Addr::new(100, 64, 0, 7), "dep-container");

        let mut spec = mesh_spec("consumer", 8080);
        spec.requires = vec![local_requirement("replicator")];

        let resp = post_deploy(state, &spec).await;

        assert_eq!(
            rt.specs().len(),
            1,
            "a co-located provider satisfies `local` (status was {})",
            resp.status()
        );
    }

    /// W338 §Ordering and readiness. The record is still in the registry — a
    /// retracted record is exactly the "present but not Ready" shape
    /// `ServiceRecords::get` keeps answering for — and the gate must block on
    /// it. Presence was the old rule; a WAL-replaying restore is why it was
    /// wrong.
    #[tokio::test(start_paused = true)]
    async fn a_present_but_not_ready_record_does_not_satisfy_the_gate() {
        let (_tmp, state, rt) = state_with_recording_runtime_on_node("100.64.0.7");
        let dep = mesh_spec("db", 5432);
        state
            .service_records
            .upsert_deployed(&dep, std::net::Ipv4Addr::new(100, 64, 0, 7), "dep-container");
        state
            .service_records
            .retract(&workload_spec::MeshIdent("db".into()));
        assert!(
            state
                .service_records
                .get(&workload_spec::MeshIdent("db".into()))
                .is_some(),
            "the record must still be present — this test is about readiness, \
             not about absence"
        );

        let mut spec = mesh_spec("consumer", 8080);
        spec.depends_on = vec![workload_spec::MeshIdent("db".into())];

        let resp = post_deploy(state, &spec).await;

        assert_eq!(resp.status(), StatusCode::FAILED_DEPENDENCY);
        assert!(rt.specs().is_empty(), "an unready dependency must block");
    }

    /// `EnvValue::FromMesh` is rendered from real registry state on the deploy
    /// path. Before this ticket the resolver had no production caller at all,
    /// so such a workload could not deploy: kamaji refuses an unresolved
    /// `FromMesh` outright (`kamaji-bin/src/native.rs`).
    ///
    /// The rendered host is the record's `mesh_ip`, not the ident — nothing
    /// publishes mesh idents into DNS, so the ident is not a dialable address.
    #[tokio::test(start_paused = true)]
    async fn from_mesh_env_is_rendered_from_the_service_record_before_the_backend_sees_it() {
        let (_tmp, state, rt) = state_with_recording_runtime();
        let dep = mesh_spec("db", 5432);
        state
            .service_records
            .upsert_deployed(&dep, std::net::Ipv4Addr::new(100, 64, 0, 7), "dep-container");

        let mut spec = mesh_spec("consumer", 8080);
        spec.depends_on = vec![workload_spec::MeshIdent("db".into())];
        spec.env = vec![workload_spec::EnvVar {
            name: "DATABASE_URL".into(),
            value: workload_spec::EnvValue::FromMesh {
                ident: workload_spec::MeshIdent("db".into()),
                kind: workload_spec::MeshLookup::Url,
            },
        }];

        let resp = post_deploy(state, &spec).await;
        let specs = rt.specs();
        assert_eq!(specs.len(), 1, "deploy did not reach the backend (status {})", resp.status());

        let rendered = specs[0]
            .env
            .iter()
            .find(|e| e.name == "DATABASE_URL")
            .expect("DATABASE_URL survived to the backend");
        assert_eq!(
            rendered.value,
            workload_spec::EnvValue::Literal {
                value: "http://100.64.0.7:5432".into()
            },
            "the backend must receive a literal, never an unresolved FromMesh"
        );
    }

    /// A `FromMesh` reference to something that is not on the mesh is a
    /// rejection, not a workload started with a broken environment.
    #[tokio::test(start_paused = true)]
    async fn an_unresolvable_from_mesh_reference_rejects_the_deploy() {
        let (_tmp, state, rt) = state_with_recording_runtime();
        let mut spec = mesh_spec("consumer", 8080);
        spec.env = vec![workload_spec::EnvVar {
            name: "DATABASE_URL".into(),
            value: workload_spec::EnvValue::FromMesh {
                ident: workload_spec::MeshIdent("nowhere".into()),
                kind: workload_spec::MeshLookup::Url,
            },
        }];

        let resp = post_deploy(state, &spec).await;

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(resp).await;
        assert!(
            body["error"].as_str().unwrap().contains("mesh env resolution"),
            "error should name mesh env resolution, got: {}",
            body["error"]
        );
        assert!(rt.specs().is_empty(), "backend must not be called");
    }

    // ── R860-T6: `supply = "self"` provisioning + the teardown cascade ───────
    //
    // Same posture as the R860-B3 tests above and for the same reason: every
    // one of these drives the real `POST /workloads/deploy` / `POST
    // /workloads/{ident}/destroy` through the router and asserts on what the
    // BACKEND was handed. A test that called `self_supplied_providers` directly
    // would prove the helper and nothing about whether a provider is actually
    // stood up before its requirer.

    async fn post_destroy(state: Arc<ServerState>, ident: &str) -> axum::response::Response {
        build_router(state)
            .oneshot(
                Request::post(format!("/workloads/{ident}/destroy"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    fn self_supplied(ident: &str, provider: workload_spec::WorkloadSpec) -> workload_spec::Requirement {
        workload_spec::Requirement {
            ident: workload_spec::MeshIdent(ident.into()),
            locality: workload_spec::Locality::Local,
            supply: workload_spec::Supply::SelfProvision,
            provides: Some(Box::new(provider)),
        }
    }

    /// A requirement on a provider **someone else** declares and owns.
    ///
    /// R860-T2 changed the locality here from `local` to `anywhere`, which is
    /// what these tests always meant. `local` was inert when they were written
    /// — the gate did a plain presence check for every locality — and became
    /// load-bearing the moment locality was enforced: these fixtures run on a
    /// `ServerState` with no bind address, so `node_mesh_ip()` is `None`, and a
    /// `local` requirement on a node that cannot say where it is now fails
    /// closed (424) by design. Nothing in these three tests is about locality;
    /// they are about `supply`, and `anywhere` is the locality of "belongs to
    /// whoever declared it". The `local` axis is covered by
    /// `a_local_requirement_is_refused_when_its_only_provider_is_on_another_node`
    /// and its co-located twin.
    fn waits_on(ident: &str) -> workload_spec::Requirement {
        workload_spec::Requirement {
            ident: workload_spec::MeshIdent(ident.into()),
            locality: workload_spec::Locality::Anywhere,
            supply: workload_spec::Supply::Wait,
            provides: None,
        }
    }

    /// Part 1 of the ticket, and W338's motivating case: the replicator the
    /// headscale spec carries inline is stood up FIRST, on this node, and the
    /// requirer follows it. Order is the assertion — a group whose members both
    /// exist but started in the wrong order is exactly the bug the design is
    /// meant to remove from `on_became_leader`.
    #[tokio::test(start_paused = true)]
    async fn a_self_supplied_provider_is_deployed_before_its_requirer() {
        let (_tmp, state, rt) = state_with_recording_runtime();
        let mut requirer = mesh_spec("headscale", 8080);
        requirer.requires = vec![self_supplied(
            "headscale-replicator",
            mesh_spec("headscale-replicator", 9000),
        )];

        let resp = post_deploy(Arc::clone(&state), &requirer).await;

        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "requirer deploy was refused: {}",
            body_json(resp).await
        );
        assert_eq!(
            rt.deploy_order(),
            vec!["headscale-replicator".to_string(), "headscale".to_string()],
            "the carried provider must reach the backend BEFORE its requirer"
        );
    }

    /// W338 §"Each member keeps its own mesh identity" — the load-bearing
    /// constraint. The provider is not folded into the requirer: it reaches the
    /// backend as its own spec under its own identity and publishes its own
    /// service record, which is what makes it independently discoverable and
    /// what makes the `anywhere` locality expressible at all.
    #[tokio::test(start_paused = true)]
    async fn each_group_member_keeps_its_own_identity_and_service_record() {
        let (_tmp, state, rt) = state_with_recording_runtime();
        let mut requirer = mesh_spec("headscale", 8080);
        requirer.requires = vec![self_supplied(
            "headscale-replicator",
            mesh_spec("headscale-replicator", 9000),
        )];

        post_deploy(Arc::clone(&state), &requirer).await;

        for ident in ["headscale", "headscale-replicator"] {
            let mesh_ident = workload_spec::MeshIdent(ident.into());
            assert!(
                state.service_records.get(&mesh_ident).is_some(),
                "{ident} must have its OWN service record — collapsing the group \
                 under one identity is what W338 forbids"
            );
            assert!(
                state
                    .archetype_registry
                    .lock()
                    .unwrap()
                    .contains_key(ident),
                "{ident} must be registered as a live workload in its own right"
            );
        }
        assert_eq!(rt.specs().len(), 2, "two workloads, two specs, two identities");
    }

    /// The other half of Part 1, and the one that protects other people's
    /// workloads: a `wait` requirement names a provider SOMEONE ELSE declares,
    /// so the requirer must never deploy it — it may only wait for it.
    #[tokio::test(start_paused = true)]
    async fn a_wait_provider_is_never_deployed_by_its_requirer() {
        let (_tmp, state, rt) = state_with_recording_runtime();
        let dep = mesh_spec("headscale-db", 5432);
        state.service_records.upsert_deployed(
            &dep,
            std::net::Ipv4Addr::new(100, 64, 0, 7),
            "db-container",
        );

        let mut requirer = mesh_spec("headscale", 8080);
        requirer.requires = vec![waits_on("headscale-db")];

        let resp = post_deploy(Arc::clone(&state), &requirer).await;

        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            rt.deploy_order(),
            vec!["headscale".to_string()],
            "a wait provider belongs to whoever declared it; the requirer must \
             not stand one up"
        );
    }

    /// The gate had been reading `spec.depends_on` alone, so a requirement
    /// declared in `requires` was gated on nothing — which would have let a
    /// requirer start ahead of the very provider W338 exists to order it
    /// against. It now reads `effective_requirements()`, the one supported
    /// accessor.
    #[tokio::test(start_paused = true)]
    async fn a_requires_declared_wait_provider_that_never_appears_refuses_the_deploy() {
        let (_tmp, state, rt) = state_with_recording_runtime();
        let mut requirer = mesh_spec("headscale", 8080);
        requirer.requires = vec![waits_on("headscale-db")];

        let resp = post_deploy(Arc::clone(&state), &requirer).await;

        assert_eq!(resp.status(), StatusCode::FAILED_DEPENDENCY);
        assert!(
            rt.specs().is_empty(),
            "the gate must cover `requires`, not only the legacy `depends_on`"
        );
    }

    /// Part 2 — W338 §"Placement consequences" 4, both halves in one test
    /// because the claim is a *distinction*: teardown cascades along `self`
    /// edges and NEVER along `wait` edges. Cascading into the waited-on provider
    /// would delete a workload this requirer never owned.
    #[tokio::test(start_paused = true)]
    async fn destroy_cascades_into_self_providers_and_leaves_wait_providers_standing() {
        let (_tmp, state, rt) = state_with_recording_runtime();

        // Somebody else's workload: present on the mesh and live in the
        // registry, but declared and owned elsewhere.
        let waited = mesh_spec("headscale-db", 5432);
        state.service_records.upsert_deployed(
            &waited,
            std::net::Ipv4Addr::new(100, 64, 0, 7),
            "db-container",
        );
        state
            .archetype_registry
            .lock()
            .unwrap()
            .insert("headscale-db".into(), LifecycleArchetype::Server);

        let mut requirer = mesh_spec("headscale", 8080);
        requirer.requires = vec![
            self_supplied(
                "headscale-replicator",
                mesh_spec("headscale-replicator", 9000),
            ),
            waits_on("headscale-db"),
        ];
        assert_eq!(
            post_deploy(Arc::clone(&state), &requirer).await.status(),
            StatusCode::CREATED
        );

        let resp = post_destroy(Arc::clone(&state), "headscale").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(
            body["cascaded"],
            serde_json::json!(["headscale-replicator"]),
            "destroy must report exactly what it took with the requirer"
        );

        assert_eq!(
            rt.teardown_order(),
            vec!["headscale".to_string(), "headscale-replicator".to_string()],
            "requirer first, then its self-supplied provider — and the waited-on \
             provider not at all"
        );
        assert!(
            !state
                .archetype_registry
                .lock()
                .unwrap()
                .contains_key("headscale-replicator"),
            "the self-supplied provider must be fully deregistered, not just stopped"
        );
        assert!(
            state
                .archetype_registry
                .lock()
                .unwrap()
                .contains_key("headscale-db"),
            "the wait provider belongs to someone else and must still be standing"
        );
    }

    /// Redeploying a requirer must not try to stand its sidecar up a second
    /// time. For an Appliance provider the single-instance guard would answer
    /// 409 and take the requirer's redeploy down with it.
    #[tokio::test(start_paused = true)]
    async fn a_redeploy_does_not_stand_an_already_live_provider_up_again() {
        let (_tmp, state, rt) = state_with_recording_runtime();
        let mut requirer = mesh_spec("headscale", 8080);
        requirer.archetype = Some(LifecycleArchetype::Server);
        let mut provider = mesh_spec("headscale-replicator", 9000);
        provider.archetype = Some(LifecycleArchetype::Appliance);
        requirer.requires = vec![self_supplied("headscale-replicator", provider)];

        assert_eq!(
            post_deploy(Arc::clone(&state), &requirer).await.status(),
            StatusCode::CREATED
        );
        let resp = post_deploy(Arc::clone(&state), &requirer).await;

        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "redeploy was refused: {}",
            body_json(resp).await
        );
        assert_eq!(
            rt.deploy_order(),
            vec![
                "headscale-replicator".to_string(),
                "headscale".to_string(),
                "headscale".to_string()
            ],
            "the live provider must be left alone; only the requirer redeploys"
        );
    }

    /// The R860-T4 gap this ticket inherited, at the handler that had it: the
    /// per-workload archetype skip let a Server bound to an Appliance by a
    /// `local` edge drain alone. The requirement graph the deploy handler now
    /// records is what `drain_workloads` consults to refuse that.
    #[tokio::test(start_paused = true)]
    async fn a_deployed_group_records_the_membership_drain_consults() {
        let (_tmp, state, _rt) = state_with_recording_runtime();
        let mut requirer = mesh_spec("headscale", 8080);
        requirer.archetype = Some(LifecycleArchetype::Appliance);
        let mut provider = mesh_spec("headscale-replicator", 9000);
        provider.archetype = Some(LifecycleArchetype::Server);
        requirer.requires = vec![self_supplied("headscale-replicator", provider)];

        post_deploy(Arc::clone(&state), &requirer).await;

        let graph = state.requirement_graph.lock().unwrap();
        assert_eq!(
            crate::deploy::self_supply::group_blocking_drain(&graph, "headscale-replicator")
                .as_deref(),
            Some("headscale"),
            "the Server must be undrainable because its group holds an Appliance"
        );
    }

    // ── R555-F5: admission at yubaba's front door, before secret resolution ──

    /// Secret resolution happens in yubaba, ahead of the backend call — so a
    /// gate that lives only in kamaji sees the spec after the credentials have
    /// been decrypted onto tmpfs and after `spec.secrets` has been rewritten
    /// into binds. This is the check that has to fire first.
    ///
    /// The test process pins no keys (`YAH_ADMISSION_KEYS` unset), so any
    /// attached grant is signed by an untrusted key — which is the shape a
    /// tampered dispatch has, and the refusal lands before anything is read.
    #[tokio::test]
    async fn deploy_refuses_a_workload_whose_admission_grant_does_not_verify() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);

        let mut spec: workload_spec::WorkloadSpec =
            serde_json::from_value(appliance_spec("granted-workload")["spec"].clone()).unwrap();
        spec.archetype = Some(LifecycleArchetype::Server);
        let grant = workload_spec::admission::AdmissionGrant::from_spec("rusty-v8-musl", &spec);
        workload_spec::admission::attach(&mut spec, &grant.encode(), &"aa".repeat(64), &"bb".repeat(32));
        let body = serde_json::json!({ "spec": serde_json::to_value(&spec).unwrap() });

        let resp = app
            .oneshot(
                Request::post("/workloads/deploy")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let b = body_json(resp).await;
        assert!(
            b["error"].as_str().unwrap().contains("not admitted"),
            "got: {}",
            b["error"]
        );
    }

    /// The other half, and the one that keeps the fleet running: under the
    /// default permissive policy a workload carrying no grant — every service
    /// deployed today — is untouched by the new gate.
    #[tokio::test]
    async fn deploy_leaves_an_ungranted_workload_alone() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state);
        let mut body = appliance_spec("plain-server");
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
        assert_ne!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
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
                command: Some("bun run build".into()),
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
                port: None,
                env: Default::default(),
            }),
            revalidate_receiver: None,
        })
    }

    async fn body_json(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// The envelope shape a bundle deploy must send. Pinned here because it is
    /// easy to get wrong, and because it CHANGED under R546-B7: `Workload` now
    /// hand-writes `Serialize`/`Deserialize` and branches on
    /// `is_human_readable`, so JSON is *internally* tagged on `kind` (the flat
    /// on-disk shape) while postcard stays externally tagged (the kamaji UDS
    /// shape R590-B3 established). This test previously asserted external
    /// tagging for JSON and was invalidated by that change; both halves are
    /// pinned now so a future single-shape "simplification" fails loudly on
    /// whichever half it drops.
    #[test]
    fn bundle_workload_is_kind_tagged_in_json_and_variant_indexed_on_the_wire() {
        let w = bundle_workload(&"a".repeat(64));

        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(
            json.get("kind").and_then(|k| k.as_str()),
            Some("mesofact-static"),
            "JSON/TOML is internally tagged on `kind` (R546-B7), got {json}"
        );
        assert!(
            json.get("mesofact-static").is_none(),
            "the human-readable shape is flat, not nested under the variant name"
        );
        assert_eq!(
            serde_json::from_value::<workload_spec::Workload>(json).unwrap(),
            w,
            "the shape yubaba's deploy handler parses must be the one it emits"
        );

        // The binary half — the actual frame that crosses the kamaji UDS,
        // carrying R599-F12's mesh assignment alongside the envelope.
        let frame = kamaji_proto::YubabaToKamaji::Deploy {
            request_id: kamaji_proto::RequestId(1),
            id: kamaji_proto::WorkloadId::new("yah-marketing"),
            spec: w.clone(),
            mesh: Some(kamaji_proto::MeshAssignment {
                mesh_ip: std::net::Ipv4Addr::new(100, 64, 0, 3),
                wg_private_key: String::new(),
                wg_listen_port: 0,
                peers: vec![],
                netns_name: None,
            }),
        };
        let bytes = kamaji_proto::encode_frame(&frame).unwrap();
        let (decoded, _) = kamaji_proto::decode_frame::<kamaji_proto::YubabaToKamaji>(&bytes)
            .expect(
                "postcard must stay externally tagged; internal tagging needs \
                 deserialize_any, which postcard refuses (R590-B3)",
            );
        assert_eq!(decoded, frame);
    }

    /// R599-F12: which address a bundle deploy tells kamaji to bind.
    ///
    /// Deliberately derived from `--bind`. A bundle is a natively forked host
    /// process with no network namespace of its own, so it can only bind an
    /// address the node already holds; a per-workload address would fail with
    /// "Address not available". The wildcard and loopback cases must stay
    /// `None` — a wildcard bind would also publish the site on the node's
    /// *public* interface.
    #[test]
    fn the_node_mesh_address_comes_from_the_bind_flag() {
        use std::net::Ipv4Addr;

        let (_tmp, s) = state();
        let mesh = Arc::try_unwrap(s)
            .map(|s| s.with_bind_addr("100.64.0.3:7443"))
            .unwrap_or_else(|_| unreachable!("sole owner"));
        assert_eq!(mesh.node_mesh_ip(), Some(Ipv4Addr::new(100, 64, 0, 3)));

        for no_mesh_plane in [
            "0.0.0.0:7443",
            "127.0.0.1:7443",
            "localhost:7443",
            "[::]:7443",
        ] {
            let (_t, s) = state();
            let s = Arc::try_unwrap(s)
                .map(|s| s.with_bind_addr(no_mesh_plane))
                .unwrap_or_else(|_| unreachable!("sole owner"));
            assert_eq!(
                s.node_mesh_ip(),
                None,
                "{no_mesh_plane} is not an address another node can dial — \
                 kamaji must keep binding loopback"
            );
        }
    }

    /// R844-B11: the address a container deploy advertises is this node's own,
    /// and stays that way however many workloads the process has deployed.
    ///
    /// This replaces a guard that looked like it pinned this and did not. It
    /// read `assert_ne!(s.alloc_mesh_ip(), Ipv4Addr::new(100, 64, 0, 3))`,
    /// commented "the allocator hands out a *different* address entirely", and
    /// passed only because it was that state's **first** allocation, returning
    /// `100.64.0.1`. Two more calls first and it failed — the counter walked
    /// straight onto the node's own address, and past it onto every other
    /// node's. On us-west-001 the third container deploy is what published
    /// `yah-cloud-admin` at `100.64.0.3:4325`, us-east-001.
    ///
    /// The invariant is *stability*, not inequality: repetition is precisely
    /// what the counter failed, so asserting it is what makes this a guard
    /// rather than a restatement. A function that returns one node address for
    /// every call cannot return a different node's, whatever the fleet's
    /// addresses turn out to be — which is why this does not need to read
    /// `.yah/infra/machines/*.toml` (unreachable from this standalone
    /// workspace anyway). The live per-node form of the same check is in the
    /// ticket's verify: every record's `mesh_ip` must equal the answering
    /// node's `tailscale ip -4`.
    #[test]
    fn a_deployed_workloads_address_is_this_nodes_own_however_many_came_before() {
        use std::net::Ipv4Addr;

        let (_tmp, s) = state();
        let s = Arc::try_unwrap(s)
            .map(|s| s.with_bind_addr("100.64.0.3:7443"))
            .unwrap_or_else(|_| unreachable!("sole owner"));

        for nth in 1..=8 {
            assert_eq!(
                s.workload_bind_ip(),
                Ipv4Addr::new(100, 64, 0, 3),
                "deploy #{nth} advertised an address that is not this node's — \
                 a per-workload counter drawn from 100.64.0.0/10 walks onto \
                 real node addresses (R844-B11)"
            );
        }

        // No mesh plane: loopback, matching the bundle path's fallback. Wrong
        // to dial from another node, but *visibly* wrong — unlike a
        // neighbour's address, which reads as a healthy Ready record.
        let (_t, dev) = state();
        let dev = Arc::try_unwrap(dev)
            .map(|s| s.with_bind_addr("0.0.0.0:7443"))
            .unwrap_or_else(|_| unreachable!("sole owner"));
        assert_eq!(dev.node_mesh_ip(), None);
        assert_eq!(dev.workload_bind_ip(), Ipv4Addr::LOCALHOST);
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
