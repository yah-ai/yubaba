//! yah-yubaba: per-machine infrastructure daemon for yah-managed mirrors.
//!
//! Phase 1 (R040-F8) ships the minimum HTTP surface needed to unblock live
//! provisioning (R040-T6):
//!
//! - `GET /health` — daemon liveness, version
//! - `GET /identity` — machine's hostkey fingerprint (404 until registered)
//! - `POST /register-hostkey` — accept a pubkey, persist + return fingerprint
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
//! @yah:handoff("WARDEN-SIDE CONSTABLE DISPATCH LANDED. New crate dep + module crates/yah/yubaba/src/constable_client.rs ConstableClient owns a persistent UnixStream (tokio::net), serial-mutex'd via Inner { rd, wr, buf }. Surface: connect()/connect_with_timeout() runs Hello→Welcome handshake (captures ConstableInfo{version, constable_version}); list()/stop()/drain(budget)/probe() each allocate a fresh RequestId, write a postcard frame, await one ConstableToWarden reply, and check the rid matches. Remote Error{code,message} surfaces as ClientError::Remote so yubaba HTTP handlers can branch on category. ServerState gained constable_client: Option<Arc<ConstableClient>> + with_constable_client() builder; yah-yubaba serve grew --kamaji-socket <path> with attach_constable_client() that warns + falls back to in-process runtime on connect failure (5s timeout — short enough not to stall systemd, long enough to ride the kamaji.service unit settling).")
//! @yah:handoff("HANDLERS WIRED TO PREFER CONSTABLE. GET /workloads, GET /workloads/{id}/state, POST /workloads/drain all check s.constable_client first and dispatch through the UDS when set; legacy s.runtime is the fallback. New response header x-workload-source: kamaji|runtime|stub lets callers branch on row shape (kamaji returns WorkloadEntry {id,state,pid}; runtime returns the existing rich WorkloadState). drain_workloads sends a structured Drain{flush_ms=5000, checkpoint_ms=1000} per workload — matches the parity floor in W154 §Runtime parity contract. POST /workloads/deploy is INTENTIONALLY still on the legacy path: Kamaji's Deploy arm returns Error{Internal, 'backend driver not implemented (R406-T4..T6/T11)'}; routing deploy through it before R406-T9 would break every single-node and clustered deploy. The handler doc-comment documents this explicitly.")
//! @yah:handoff("TESTS GREEN. 6 unit tests in constable_client::tests (handshake, list, stop, drain ack, remote-error, connect-timeout) using one-shot in-process UDS servers. 3 new integration tests in crates/yah/yubaba/tests/integration_constable_client.rs that spawn kamaji::serve_with_shutdown against a tempdir socket and round-trip handshake+list, drain-unknown, stop-unknown via the real yubaba client (no mocks on either side — proves wire compatibility). Full suite: 92 yubaba lib + 3 new yubaba integration + 47 kamaji + 19 kamaji-proto pass. cargo check -p yubaba --features containerd-integration also clean — no feature-flag regression.")
//! @yah:next("R406-T9 follow-on: once Kamaji's Deploy arm is wired (containerd backend), migrate POST /workloads/deploy in crates/yah/yubaba/src/lib.rs to dispatch via client.deploy(id, Workload::Container(spec)) — the validation + signature check + mesh-IP allocation + cloudflare ingress + headscale operator-bridge stays in yubaba (they are admission decisions, not supervision). The natural ordering inside the handler is: validate → allocate ident+mesh_ip → kamaji.deploy → on Ok, run cloudflare/headscale registration → on registration failure, kamaji.stop(id) for cleanup → respond. Tests-side: integration_smoke_filter / integration_single_node / integration_public_ingress currently use the legacy runtime; either give them a kamaji fixture or keep them on the runtime path and add a parallel kamaji-fixture suite. Pick whichever is less churn at T9 time.")
//! @yah:next("ConstableClient currently uses a request/response Mutex + serial. Kamaji will eventually push WorkloadStarted/WorkloadExited/DrainCompleted events (see ConstableToWarden::DrainCompleted rustdoc) — at that point the client needs a background reader that demuxes responses from pushes by RequestId. The public API stays the same; the change is internal to constable_client.rs. Track as a separate sub-ticket once Kamaji grows the push channel; not in scope for T8.")
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
//! @yah:next("MIGRATE yubaba's POST /workloads/deploy through ConstableClient.deploy(). The wire payload is constable_proto::WardenToConstable::Deploy { request_id, id, spec: Workload::Container(spec) }. The migration order inside the handler: validate (already done) → allocate ident+mesh_ip (already done) → resolve EnvValue::FromMesh / FromSecret on yubaba's side (admission) → kamaji.deploy(id, Workload::Container(enriched_spec)) → on Ack, run cloudflared + headscale registration → on registration failure, kamaji.stop(id) for cleanup → respond. Add a deploy() method on yubaba's ConstableClient that sends WardenToConstable::Deploy and awaits ConstableToWarden::Ack { kind: Deploy } | Error. This was deferred from R406-T8; T9 now unblocks it.")
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
//! @yah:at(2026-06-08T01:17:24Z)
//! @yah:status(open)
//! @yah:phase(P2)
//! @yah:parent(R482)
//! @yah:next("Cluster-of-one raft init per W197 §'Single-node raft'. No peers, no leader election complexity. Future multi-machine join uses yubaba's existing join-by-NodeId flow.")
//! @yah:next("Bring up wireguard0 + register with xlb-net so desktop can dial via iroh per A043 2026-05-22 update. Default seed list shipped in camp binary; --xlb-seed <node-id> override per W197 §Open questions 2.")
//! @yah:next("Out-of-scope: certificate/identity provisioning (W197 §Open questions 3 — TOFU lives in T5).")
//! @yah:verify("cargo test -p yubaba --test bootstrap_single_node")
//! @arch:see(.yah/docs/working/W197-camp-bootstraps-yubaba.md)
//! @arch:see(.yah/docs/architecture/A032-yah-cluster-mesh.md)
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
//! @yah:handoff("Yubaba has been fully rewired off the kamaji-core shims. Deleted: crates/yah/yubaba/src/runtime/{containerd,docker,fake}.rs (~2.4k LoC of dead-since-T2 duplicates the shim layer was hiding) and crates/yah/yubaba/src/constable_client.rs (the T4 re-export shim). Migrated all yubaba call sites and integration tests: lib.rs `use constable_client::ConstableClient` → `use constable_core::sibling::ConstableClient`; `use runtime::ContainerRuntime` → `use constable_core::Kamaji as ContainerRuntime`; main.rs `yubaba::runtime::containerd::ContainerdRuntime` → `constable_core::containerd::ContainerdRuntime`; `yubaba::constable_client::connect_with_timeout` → `constable_core::sibling::connect_with_timeout`; six yubaba integration tests rewritten to import constable_core directly.")
//! @yah:handoff("yubaba-test-harness (which the integration tests pull in) followed the same path — `yubaba::runtime::{WorkloadState,WorkloadStatus,ContainerRuntime}` → `constable_core::*`; added `kamaji-core = { path = \"../kamaji\" }` to its Cargo.toml. yubaba-test-macros's proc-macro now emits `::constable_core::containerd::ContainerdRuntime` instead of `yubaba::runtime::containerd::ContainerdRuntime` in the generated `__local` variant; the smoke variant still references `yubaba::runtime::DummyRuntime` because DummyRuntime correctly stays in yubaba (it's yubaba-smoke-tier specific).")
//! @yah:handoff("crates/yah/yubaba/src/runtime/mod.rs was kept (not deleted) for two reasons: (1) DummyRuntime lives there and is referenced by the smoke-test macro path; (2) the file is the source-of-truth line anchor for several review-status tickets (R091-F1, R256-F10, R471-T2, R471-F3, R484, R484-T2, R484-T3) plus R484-T4 which was relocated from the deleted constable_client.rs into this file. The `pub use constable_core::*` shim re-exports were removed; only the DummyRuntime impl and the historical annotations remain. The file's module doc was rewritten to reflect its new minimal role.")
//! @yah:handoff("app/yah/kamaji binary intentionally NOT rewired to import kamaji-core. The binary is the SERVER side of the W154 UDS protocol — it accepts kamaji-proto frames and dispatches to its own containerd/native/cgroup/pidfd impls. The Kamaji trait in kamaji-core is the CLIENT-facing contract; ConstableClient (in kamaji-core::sibling) talks to this binary over UDS. Both crates already depend on kamaji-proto for the wire format; that IS the wiring. Reshaping the binary to internally use kamaji-core::Kamaji trait dispatch would be a substantial refactor (it'd need to convert kamaji-proto's WorkloadState wire enum to kamaji-core's WorkloadState struct on every call) and is out of scope here.")
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

pub mod cheers_client;
pub mod deploy;
pub mod identity;
pub mod leader;
pub mod litestream;
pub mod mesh;
pub mod pond;
pub mod raft;
pub mod rollout;
pub mod runtime;
pub mod secrets;

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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cheers_client::CheersClient;
use kamaji::sibling::ConstableClient;
use kamaji::Kamaji as ContainerRuntime;

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
    /// Phase 2 (R040-F20): raft coordination node.  `None` until the server
    /// is started with `--raft-node-id` / `--raft-dir`.
    pub raft: Option<raft::WardenRaft>,
    /// Phase 2 (R040-F21): this node's raft node ID.  Used by
    /// `GET /mesh/leader-health` to check "am I the current leader?"
    /// without re-passing the ID through every handler.
    pub node_id: Option<raft::WardenNodeId>,
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
    pub constable_client: Option<Arc<ConstableClient>>,

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
            .field("constable_socket", &self.constable_client.as_ref().map(|c| c.socket().to_path_buf()))
            .field("cheers_client_configured", &self.cheers_client.is_some())
            .field("cloudflared_url", &self.cloudflared_url)
            .field("headscale_url", &self.headscale_url)
            .field("operator_bridge_mode", &self.operator_bridge_mode)
            .field("prometheus_url", &self.prometheus_url)
            .field("pond_local_runtime_configured", &self.pond_local_runtime.is_some())
            .finish()
    }
}

impl ServerState {
    pub fn load(state_path: PathBuf) -> Result<Self> {
        let mut state = identity::load_state(&state_path)?;
        if state.identity.is_none() {
            let hostkey_dir = state_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            match identity::generate_or_load_hostkey(hostkey_dir) {
                Ok(id) => {
                    state.identity = Some(id);
                    identity::save_state(&state_path, &state)
                        .context("persisting auto-generated hostkey to state file")?;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "hostkey generation failed; /identity will return 404 until registered"
                    );
                }
            }
        }
        Ok(Self {
            state_path,
            state: Mutex::new(state),
            headscale_dir: PathBuf::from(DEFAULT_HEADSCALE_DIR),
            compose_dir: PathBuf::from(DEFAULT_COMPOSE_DIR),
            raft: None,
            node_id: None,
            litestream_s3_url: None,
            session_id: new_session_id(),
            runtime: None,
            constable_client: None,
            cheers_client: None,
            ownership_rows: Mutex::new(HashMap::new()),
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
    pub fn with_pond_local_runtime(
        mut self,
        runtime: Arc<local_driver::LocalRuntime>,
    ) -> Self {
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
    /// [`constable_client::ConstableClient::connect`] or
    /// [`constable_client::connect_with_timeout`] before passing it in.
    pub fn with_constable_client(mut self, client: Arc<ConstableClient>) -> Self {
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
    pub fn with_raft(mut self, raft: raft::WardenRaft) -> Self {
        self.raft = Some(raft);
        self
    }

    /// Set this node's raft node ID — needed by [`GET /mesh/leader-health`].
    pub fn with_node_id(mut self, id: raft::WardenNodeId) -> Self {
        self.node_id = Some(id);
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
        // R092-F3: cloud-init log tail for `yah cloud machine provision`
        // failure surfacing. Reads /var/log/cloud-init{,-output}.log.
        .route("/diagnostics", get(get_diagnostics))
        // R278-F1: rollout API — linear strategy + Prometheus gate evaluation
        .route("/v1/rollouts", post(create_rollout))
        .route("/v1/rollouts", get(list_rollouts))
        .route("/v1/rollouts/{id}", get(get_rollout))
        .route("/v1/rollouts/{id}/override", post(override_rollout))
        // R040-F20: raft RPC (peer-to-peer, Tailscale mesh only)
        .route("/raft/append-entries", post(raft_append_entries))
        .route("/raft/vote", post(raft_vote))
        .route("/raft/install-snapshot", post(raft_install_snapshot))
        // R040-F20: raft operator API
        .route("/raft/status", get(raft_status))
        .route("/raft/write", post(raft_write))
        .route("/raft/transfer-leader", post(raft_transfer_leader))
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
    let request_id = format!(
        "req-{:x}",
        REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
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

/// Bind to `addr`, accept connections forever. Cancellation is up to the caller.
pub async fn serve(addr: &str, state: Arc<ServerState>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
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
}

async fn health(State(s): State<Arc<ServerState>>) -> Json<HealthBody> {
    Json(HealthBody {
        status: "ok",
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        mode: if s.raft.is_some() { "clustered" } else { "single-node" },
    })
}

#[derive(Serialize)]
struct IdentityBody {
    hostkey_fingerprint: String,
    algorithm: String,
}

async fn get_identity(State(s): State<Arc<ServerState>>) -> Result<Json<IdentityBody>, StatusCode> {
    match s.snapshot().identity {
        Some(id) => Ok(Json(IdentityBody {
            hostkey_fingerprint: id.hostkey_fingerprint,
            algorithm: id.algorithm,
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
struct RegisterRequest {
    /// Full OpenSSH public-key line, e.g. `"ssh-ed25519 AAAA… [comment]"`.
    pubkey: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    hostkey_fingerprint: String,
}

async fn register_hostkey(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    let id = identity::parse_pubkey(&req.pubkey).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid pubkey: {e}"),
        )
    })?;
    let fp = id.hostkey_fingerprint.clone();
    s.replace_identity(id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("persist: {e}")))?;
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

async fn mesh_leader_health(
    State(s): State<Arc<ServerState>>,
) -> impl IntoResponse {
    let is_leader = match (&s.raft, s.node_id) {
        (Some(raft), Some(my_id)) => {
            let metrics = raft.metrics().borrow().clone();
            metrics.current_leader == Some(my_id)
        }
        _ => false,
    };

    let headscale_running = probe_headscale_local().await;

    let body = LeaderHealthBody {
        leader: is_leader,
        headscale: if headscale_running { "running" } else { "stopped" }.into(),
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
        Some(raft) if raft.metrics().borrow().current_leader.is_none() => "stale",
        _ => "fresh",
    }
}

/// Check whether write operations are allowed. Returns `Some(error_response)`
/// when raft quorum is unavailable (no leader elected), which callers should
/// return early. Returns `None` when writes are permitted.
fn quorum_write_guard(state: &ServerState) -> Option<axum::response::Response> {
    if let Some(raft) = &state.raft {
        if raft.metrics().borrow().current_leader.is_none() {
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
            Ok(entries) => (
                StatusCode::OK,
                headers,
                Json(serde_json::json!({ "workloads": entries })),
            )
                .into_response(),
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
        return (StatusCode::OK, headers, Json(serde_json::json!({ "workloads": [] }))).into_response();
    };
    let headers = [
        ("x-state-freshness", freshness),
        ("x-workload-source", "runtime"),
    ];
    match rt.list_workloads().await {
        Ok(workloads) => (StatusCode::OK, headers, Json(serde_json::json!({ "workloads": workloads }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            headers,
            Json(serde_json::json!({ "error": e.to_string() })),
        ).into_response(),
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
        let id = kamaji_proto::WorkloadId::new(ident);
        return match client.list().await {
            Ok(entries) => {
                if let Some(entry) = entries.into_iter().find(|e| e.id == id) {
                    let body = serde_json::to_value(&entry).unwrap_or_else(|e| {
                        serde_json::json!({ "error": format!("serialize: {e}") })
                    });
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

    let headers = [("x-state-freshness", freshness), ("x-workload-source", "runtime")];
    let Some(rt) = &s.runtime else {
        let headers = [("x-state-freshness", freshness), ("x-workload-source", "stub")];
        return (
            StatusCode::NOT_IMPLEMENTED,
            headers,
            Json(serde_json::json!({ "error": "workload runtime not yet configured" })),
        ).into_response();
    };
    let mesh_ident = workload_spec::MeshIdent(ident);
    match rt.get_workload(&mesh_ident).await {
        Ok(Some(state)) => {
            let body = serde_json::to_value(&state).unwrap_or_else(|e| {
                serde_json::json!({ "error": format!("serialize: {e}") })
            });
            (StatusCode::OK, headers, Json(body)).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            headers,
            Json(serde_json::json!({ "error": "workload not found" })),
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            headers,
            Json(serde_json::json!({ "error": e.to_string() })),
        ).into_response(),
    }
}

/// `POST /workloads/drain` — gracefully stop all workloads on this machine
/// before a tear-down. Always returns 200 so the destroy CLI can call it
/// unconditionally — empty `drained` list means "nothing to drain right now."
///
/// R406-T8: when a Kamaji client is configured, list workloads via UDS
/// and send each a structured [`constable_proto::WardenToConstable::Drain`]
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
async fn deploy_workload_spec(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<WorkloadDeployBody>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Reject writes when raft quorum is unavailable.
    if let Some(err_resp) = quorum_write_guard(&s) {
        return err_resp;
    }

    let spec: workload_spec::WorkloadSpec = match serde_json::from_value(req.spec) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "status": "rejected",
                    "ident": "",
                    "runtime": "stub",
                    "error": format!("spec JSON parse error: {e}"),
                })),
            ).into_response();
        }
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
        ).into_response();
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

    // R406-T9: route deploy through Kamaji (the W154 supervision backend)
    // when it is wired, falling back to the legacy in-process ContainerRuntime
    // otherwise. `ContainerRuntime` is an alias of `constable_core::Kamaji`
    // (see the `use` at the top of this file) and `ConstableClient` implements
    // it, so `s.constable_client` coerces straight into the same trait object
    // the rest of this handler already drives — deploy_workload + the failure
    // teardowns below stay backend-agnostic, untouched.
    //
    // This closes the deploy/state split-brain: `list`, `get_state`, and
    // `drain` already prefer Kamaji, so a Kamaji-attached yubaba that
    // deployed via the legacy runtime would never find its own workloads when
    // reading them back. Deploy must use the same backend the read handlers do.
    let backend: Option<Arc<dyn ContainerRuntime + Send + Sync>> = s
        .constable_client
        .clone()
        .map(|c| {
            let backend: Arc<dyn ContainerRuntime + Send + Sync> = c;
            backend
        })
        .or_else(|| s.runtime.clone());

    if let Some(rt) = backend {
        let mesh = crate::mesh::MeshAssignment::stub(s.alloc_mesh_ip());
        let mesh_ident = workload_spec::MeshIdent(ident.clone());
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
                if let (Some(cheers), Some(camp_id)) =
                    (&s.cheers_client, &req.requesting_camp_id)
                {
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
                return (StatusCode::CREATED, Json(resp_json)).into_response();
            }
            Err(e) => {
                // `{:#}` renders the full anyhow chain (e.g. the containerd /
                // runc message under "creating task for ..."), not just the
                // top context — essential for diagnosing deploy failures.
                tracing::error!(ident = %ident, error = format!("{e:#}"), "workload deploy failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "status": "error",
                        "ident": ident,
                        "error": format!("{e:#}"),
                    })),
                ).into_response();
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
    ).into_response()
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
        (StatusCode::INTERNAL_SERVER_ERROR, format!("mkdir {}: {e}", dir.display()))
    })?;

    std::fs::write(dir.join("compose.yml"), &req.compose_yaml).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("write compose.yml: {e}"))
    })?;

    if let Some(cf) = &req.caddyfile {
        std::fs::write(dir.join("Caddyfile"), cf).map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("write Caddyfile: {e}"))
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
        let _ = std::process::Command::new("systemctl").args(["daemon-reload"]).status();
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

    let status = if svc_ok { "started" } else { "files-written-systemd-unavailable" };
    Ok(Json(ComposeDeployResponse { status: status.into() }))
}

/// `GET /services` — list running containers from the Podman Compose stack.
///
/// Returns the raw JSON array from `podman compose ps --format json`. When
/// the compose file doesn't exist yet (machine not yet deployed) returns an
/// empty array rather than an error. When `podman` is unavailable returns a
/// descriptive error body with 500.
async fn get_services(
    State(s): State<Arc<ServerState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let compose_file = s.compose_dir.join("compose.yml");
    if !compose_file.exists() {
        let empty: Vec<serde_json::Value> = vec![];
        return Ok((StatusCode::OK, Json(serde_json::json!(empty))));
    }

    let output = std::process::Command::new("podman")
        .args([
            "compose",
            "-f",
            &compose_file.to_string_lossy(),
            "ps",
            "--format",
            "json",
        ])
        .output()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("podman not found or not executable: {e}"),
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("podman compose ps: {stderr}")));
    }

    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or(serde_json::json!([]));
    Ok((StatusCode::OK, Json(parsed)))
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
        (StatusCode::INTERNAL_SERVER_ERROR, format!("mkdir {}: {e}", dir.display()))
    })?;

    // Decode and write state files.
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;

    macro_rules! write_b64 {
        ($field:expr, $filename:expr) => {{
            let bytes = engine.decode(&$field).map_err(|e| {
                (StatusCode::BAD_REQUEST, format!("decode {}: {e}", $filename))
            })?;
            std::fs::write(dir.join($filename), &bytes).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("write {}: {e}", $filename))
            })?;
        }};
    }

    write_b64!(req.db_base64, "headscale.db");
    write_b64!(req.private_key_base64, "private.key");
    write_b64!(req.noise_key_base64, "noise_private.key");

    std::fs::write(dir.join("acls.yaml"), &req.acl_policy).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("write acls.yaml: {e}"))
    })?;

    // Generate a config.yaml appropriate for remote paths.
    let config_yaml = generate_remote_headscale_config(&req.server_url, dir);
    std::fs::write(dir.join("config.yaml"), &config_yaml).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("write config.yaml: {e}"))
    })?;

    // Download headscale binary (Linux-only; this binary runs on Hetzner machines).
    let bin_path = download_headscale_binary(dir, &req.headscale_version)?;

    // Write + start the systemd unit — best-effort on non-systemd hosts (tests, Mac).
    let svc_ok = write_and_start_headscale_unit(&bin_path, dir);

    let status = if svc_ok { "started" } else { "files-written-systemd-unavailable" };
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
    let noise_key = headscale_dir.join("noise_private.key").display().to_string();
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
        (StatusCode::BAD_REQUEST, format!("server_url has no host: {}", req.server_url))
    })?;

    std::fs::create_dir_all(dir).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("mkdir {}: {e}", dir.display()))
    })?;

    // Write config + permissive ACL FIRST so they exist regardless of whether
    // the download/start/mint steps succeed (mirrors headscale_deploy ordering).
    std::fs::write(dir.join("acls.yaml"), DEFAULT_ACL_POLICY_HUJSON).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("write acls.yaml: {e}"))
    })?;
    let config_yaml = generate_bootstrap_headscale_config(&req.server_url, &le_hostname, dir);
    std::fs::write(dir.join("config.yaml"), &config_yaml).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("write config.yaml: {e}"))
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
        mint_bootstrap_preauth_key(&bin_path, dir).await.unwrap_or_default()
    } else {
        String::new()
    };

    // Also mint an API key (R330-F30) so the operator's provision JOIN path can
    // create single-use-per-node preauth keys instead of sharing the reusable
    // one. Only attempt once preauth minting confirmed the CLI socket is live;
    // best-effort, so an empty key just means the reusable-preauth fallback
    // stays in play (no status downgrade — the mesh still works).
    let api_key = if svc_ok && !preauth_key.is_empty() {
        mint_bootstrap_api_key(&bin_path, dir).await.unwrap_or_default()
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
        let _ = std::process::Command::new("ufw").args(["allow", port]).status();
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("curl spawn: {e}")))?
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
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("stat headscale: {e}")))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&bin_path, perms).map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("chmod headscale: {e}"))
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
    let _ = std::process::Command::new("systemctl").args(["daemon-reload"]).status();
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
    let noise_key = headscale_dir.join("noise_private.key").display().to_string();
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

async fn raft_append_entries(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<openraft::raft::AppendEntriesRequest<raft::WardenRaftConfig>>,
) -> Result<Json<openraft::raft::AppendEntriesResponse<raft::WardenNodeId>>, (StatusCode, String)> {
    let raft = require_raft!(s);
    raft.append_entries(req)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn raft_vote(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<openraft::raft::VoteRequest<raft::WardenNodeId>>,
) -> Result<Json<openraft::raft::VoteResponse<raft::WardenNodeId>>, (StatusCode, String)> {
    let raft = require_raft!(s);
    raft.vote(req)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn raft_install_snapshot(
    State(s): State<Arc<ServerState>>,
    Json(req): Json<openraft::raft::InstallSnapshotRequest<raft::WardenRaftConfig>>,
) -> Result<Json<openraft::raft::InstallSnapshotResponse<raft::WardenNodeId>>, (StatusCode, String)>
{
    let raft = require_raft!(s);
    raft.install_snapshot(req)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// `GET /raft/status` — human-readable cluster state.
async fn raft_status(
    State(s): State<Arc<ServerState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raft = require_raft!(s);
    let metrics = raft.metrics().borrow().clone();
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

/// `POST /raft/write` request — write a [`raft::WardenRequest`] through consensus.
#[derive(Deserialize)]
struct RaftWriteRequest {
    request: raft::WardenRequest,
}

/// `POST /raft/write` — apply a `WardenRequest` to the cluster state.
///
/// Must be called on the leader; followers return a redirect hint in the
/// error body (`"ForwardToLeader"` with `leader_id` + `leader_node`).
async fn raft_write(
    State(s): State<Arc<ServerState>>,
    Json(body): Json<RaftWriteRequest>,
) -> Result<Json<raft::WardenResponse>, (StatusCode, String)> {
    let raft = require_raft!(s);
    let resp = raft
        .client_write(body.request)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(resp.data))
}

/// `POST /raft/transfer-leader` request body.
#[derive(Deserialize)]
struct TransferLeaderRequest {
    #[allow(dead_code)]
    to: raft::WardenNodeId,
}

/// `POST /raft/transfer-leader` — initiate a graceful leadership handoff.
///
/// In openraft 0.9, explicit transfer-leader is not available via `Trigger`.
/// The workaround is to call `raft.change_membership` with a config that
/// excludes the current leader, forcing an election on the remaining nodes.
/// Full `transfer_leader` lands in openraft 0.10+ (R040-F20 follow-on).
async fn raft_transfer_leader(
    State(s): State<Arc<ServerState>>,
    Json(_body): Json<TransferLeaderRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _raft = require_raft!(s);
    Err((
        StatusCode::NOT_IMPLEMENTED,
        "transfer-leader: openraft 0.9 does not expose an explicit transfer API; \
         upgrade to openraft 0.10+ or use raft.change_membership to force re-election"
            .to_string(),
    ))
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
        Some(r) => Json(serde_json::to_value(&r).unwrap_or(serde_json::Value::Null)).into_response(),
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

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
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
        assert!(fp.starts_with("SHA256:"), "fingerprint should start with SHA256:, got: {fp}");
    }

    #[tokio::test]
    async fn register_then_identity_returns_fingerprint() {
        let (_tmp, state) = fresh_state();
        let app = build_router(state.clone());

        // Register
        let req_body = serde_json::json!({ "pubkey": SAMPLE_PUBKEY });
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

        let req_body = serde_json::json!({ "pubkey": SAMPLE_PUBKEY });
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
        let app = build_router(state);

        let req_body = serde_json::json!({ "pubkey": "not a real key" });
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
    async fn services_returns_empty_array_when_compose_not_deployed() {
        let (tmp, state_base) = fresh_state();
        // Override compose_dir to the tempdir so it doesn't find a real compose.yml.
        let state = {
            let raw = Arc::try_unwrap(state_base).unwrap();
            Arc::new(raw.with_compose_dir(tmp.path()))
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
        assert_eq!(std::fs::read(headscale_tmp.path().join("headscale.db")).unwrap(), b"test-db");
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
            .oneshot(Request::get("/headscale/health").body(Body::empty()).unwrap())
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
        assert_eq!(letsencrypt_hostname("cloud.mesh.yah.dev").as_deref(), Some("cloud.mesh.yah.dev"));
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
        assert_eq!(resp.status(), StatusCode::OK, "unexpected non-2xx from /compose");

        let body = body_json(resp).await;
        assert!(body["status"].is_string(), "status field missing");

        // Files must be written regardless of systemd outcome.
        let compose = std::fs::read_to_string(compose_tmp.path().join("compose.yml")).unwrap();
        assert!(compose.contains("image: foo:v1"), "compose.yml content wrong");

        let caddyfile = std::fs::read_to_string(compose_tmp.path().join("Caddyfile")).unwrap();
        assert!(caddyfile.contains("reverse_proxy foo:8080"), "Caddyfile content wrong");

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
        assert!(!compose_tmp.path().join("Caddyfile").exists(), "Caddyfile written unexpectedly");
        drop(tmp);
    }

    #[tokio::test]
    async fn compose_deploy_then_services_returns_empty_before_podman() {
        // After deploy, /services will try podman compose ps — which fails on
        // dev/CI (no podman). We verify the endpoint returns a non-5xx when
        // compose.yml exists but the file is the only thing we can test without
        // a running Podman daemon.
        let (tmp, state_base) = fresh_state();
        let compose_tmp = tempfile::TempDir::new().unwrap();
        // Write a compose.yml directly to simulate a prior deploy.
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

        // Either 200 (podman ran + returned JSON) or 500 (podman not found).
        // What we forbid is 501 (the old stub).
        assert_ne!(resp.status(), StatusCode::NOT_IMPLEMENTED, "got old 501 stub");
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
        let app = axum::Router::new()
            .route(
                "/ownership/{id}",
                axum::routing::delete(move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let d = d.clone();
                    let f = f.clone();
                    async move {
                        if let Some(status) = *f.lock().await {
                            return status;
                        }
                        d.lock().await.push(id);
                        StatusCode::NO_CONTENT
                    }
                }),
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
        assert!(state.ownership_rows.lock().unwrap().get("svc-xyz").is_none());
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
        assert!(b.get("revoke_error").is_none(),
            "404 is benign, must not surface as revoke_error: {b:?}");
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
        assert!(err.contains("500"), "revoke_error should carry the upstream status: {err}");
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
}
