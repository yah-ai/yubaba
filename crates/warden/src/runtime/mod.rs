//! `warden::runtime` — historical home of the `ContainerRuntime` trait.
//!
//! As of R484-T5 the trait + concrete backends (containerd / docker / fake)
//! live in the `constable-core` crate and warden's call sites import them
//! directly. This file keeps two things the carve-out couldn't relocate:
//!
//! - `DummyRuntime` — smoke-tier placeholder used when the test runner
//!   can't reach a real containerd socket.
//! - The historical `@yah:ticket(...)` annotations that drove the carve-out.
//!   Board IDs already point at line numbers in this file; moving the
//!   annotations would orphan the cards. They stay until each ticket is
//!   archived through the normal SDLC.
//!
//! @yah:ticket(R091-F1, "ContainerRuntime trait + runtime::containerd impl: replace warden's shell-out path; JSON tracing + correlation IDs")
//! @yah:at(2026-06-08T21:47:23Z)
//! @yah:status(review)
//! @yah:see(.yah/docs/architecture/A053-yah-warden-integration-testing.md)
//!
//! @yah:relay(R276, "Tier 3 — Real warden workload runtime (single-node deploy)")
//! @yah:assignee(bundle-anthropic-miravel)
//! @yah:at(2026-06-01T02:30:42Z)
//! @yah:status(review)
//! @yah:parent(Q273)
//! @arch:see(.yah/docs/architecture/A053-yah-warden-integration-testing.md)
//! @arch:see(.yah/docs/architecture/A043-yah-on-machine-daemons.md)
//! @arch:see(.yah/docs/architecture/A040-yah-managed-rigs-topology.md)
//! @yah:handoff("F1 DONE: ContainerRuntime is wired into the production `yah-warden serve` path (main.rs::attach_runtime). With --features containerd-integration it connects to --containerd-socket and attaches ContainerdRuntime so /workloads/deploy deploys real containers; on socket failure or a non-containerd build it logs a loud stub-mode warning and keeps serving (identity/raft/headscale endpoints don't depend on containerd). The deploy/list/state/drain handlers already delegated to s.runtime — the only missing wire was main.rs never calling with_runtime(). Also fixed a latent boot bug: the cloud-init systemd unit invokes `serve --channel <c>` but serve had no --channel flag (clap would reject it → daemon never starts); added --channel (informational) + --containerd-socket. Bumped the default tracing EnvFilter to include the yah_warden binary target so the warning is visible. F3 (real Drain) folds in — drain_workloads tears down each listed workload once a runtime is attached.")
//! @yah:handoff("Verified: `cargo check -p warden` and `... --features containerd-integration` both clean; `cargo test -p warden --features containerd-integration,testing` green (single_node_e2e__local + ingress + smoke_filter local all pass, smoke tiers ignored). Booted the binary with the exact systemd-unit args: /health 200, channel line + stub-mode warning visible, and graceful degradation when the containerd socket is unreachable.")
//! @yah:gotcha("F2 RELEASE GOTCHA: the Hetzner-deployed binary MUST be built with --features containerd-integration or the daemon stays in stub mode. The Cargo.toml comment claiming the feature is excluded 'under the 32KiB user-data cap' is STALE — the warden binary is curl-fetched from a URL (R040-F11), not base64-inlined, so its size isn't capped. The warden release-artifact build needs to enable the feature.")
//! @yah:gotcha("Unblocks Q156 mirror-sage (R157/R158/R159 queued in handoff)")
//! @yah:gotcha("Promote to quest if F2 alone grows past three sub-tickets")
//! @yah:handoff("F4 DONE: single-node mode is now explicit. main.rs logs a clear startup message when --raft-node-id is absent ('warden running in single-node mode — containerd runtime active, raft mesh disabled'). /health response includes a `mode` field: 'single-node' | 'clustered'. Test asserts mode='single-node' in the no-raft case. 62 lib tests pass.")
//! @yah:handoff("F2 RELEASE BLOCKER FIXED: release.yml warden-release job now builds with --features containerd-integration (was missing, deployed binary would have stayed in stub mode). Cargo.toml feature comment updated to reflect that the binary is curl-fetched (not base64-inlined), so its size is uncapped. cargo check -p warden and --features containerd-integration both clean.")
//! @yah:handoff("F2 (E2E) still needs a live Hetzner CPX-11: provision the machine with `yah cloud machine provision`, ensure it uses the new release artifact built with containerd-integration, then run `yah cloud workload deploy <name> --machine <m>` to verify the full path.")
//! @yah:verify("cargo check -p warden && cargo check -p warden --features containerd-integration  # both clean")
//! @yah:verify("cargo test -p warden --lib  # 62 passed, including health_returns_ok asserting mode='single-node'")
//! @yah:verify("curl http://<warden>:7443/health | jq .mode  # single-node without --raft-node-id, clustered with it")
//! @yah:verify("grep 'containerd-integration' .github/workflows/release.yml  # warden-release job now includes the feature flag")
//! @yah:gotcha("F2 (E2E) is the only remaining code-side gap — the release artifact build is now correct but the live-box test has not been run yet. The previous RELEASE GOTCHA (stale Cargo.toml comment + missing feature flag in release.yml) is resolved.")
//! @yah:gotcha("Unblocks Q156 mirror-sage (R157/R158/R159 queued in handoff)")
//! @yah:gotcha("Promote to quest if F2 alone grows past three sub-tickets")
//! @yah:next("F2 (E2E — human): All code is committed in the working tree (uncommitted). Commit warden/src/ + .github/workflows/release.yml, cut a new tag to trigger release.yml, get the warden-<tag>-x86_64-unknown-linux-musl.tar.gz URL from the GitHub release assets, create .yah/cloud/workloads/warden-probe.toml with a minimal workload (nginx:alpine, tier=public), then: yah cloud machine provision yah-cloud-1 --warden-url <URL> && yah cloud workload deploy warden-probe --machine yah-cloud-1. Verify warden logs show 'containerd runtime attached' (not stub mode) and /workloads shows the container Running.")
//! @yah:handoff("F1/F3/F4 DONE, release.yml fix DONE — all code work complete. 62 warden lib tests pass; cargo check clean in both feature modes. All changes UNCOMMITTED in the working tree (warden/src/, .github/workflows/release.yml, leader.rs _node_id fix). F2 E2E is the only remaining step and needs human action: commit + tag + provision + deploy. workloads load from .yah/cloud/workloads/ (gitignored; create locally). yah-cloud-1 machine config exists in .yah/infra/machines/ but the Hetzner server is not provisioned. Rollout code in warden/src/rollout/ is R278 work and should be committed together.")
//! @yah:verify("git diff --stat HEAD  # shows warden/src/, release.yml, leader.rs all modified")
//! @yah:verify("cargo check -p warden && cargo check -p warden --features containerd-integration  # both clean")
//! @yah:verify("cargo test -p warden --lib  # 62 passed")
//! @yah:verify("grep 'containerd-integration' .github/workflows/release.yml  # warden-release job has the flag")
//! @yah:verify("curl http://<warden>:7443/health | jq .mode  # single-node (no --raft-node-id), clustered (with it)")
//!
//! @yah:ticket(R256-F10, "KEYSTONE: converge cloud::local_runtime + warden::runtime::containerd into one Runtime trait")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-25T21:46:49Z)
//! @yah:status(review)
//! @yah:parent(R256)
//! @yah:next("one Runtime trait — deploy + supervise a WorkloadSpec — with two backends: orbstack/docker socket AND containerd. camp embeds it for dev+sim (orbstack); warden for cloud+ha (containerd)")
//! @yah:next("this is what makes 'sim and cloud are the same set of containers' literally true rather than aspirational; it is the keystone under R256-F6 (sim host), F7 (build/SSR roles), F8 (watcher sink), F9 (almanac preconditions) — they drift without it")
//! @yah:next("today there are two impls: cloud::local_runtime (docker CLI, drives Caddy+MinIO) and warden::runtime::containerd (gRPC). Unify behind the trait; sim keeps orbstack as the backend (upholds the dev-yah-static-demo locked decision)")
//! @yah:gotcha("main design call: where the shared trait lives — a new shared crate both cloud + warden depend on, or warden::runtime as canonical with cloud depending on it. Pick before splitting impls")
//! @arch:see(.yah/docs/architecture/A024-vocabulary.md)
//! @yah:next("REALIZED by R374 — the keystone shipped end-to-end in pond. R374-F3 extracted local-driver (docker-CLI driver) as the sim-side WorkloadRuntime backend; R374-F3/F4 wired warden's MinioReconciler + MiniflareReconciler against it. Cloud and warden now share local-driver as their sim/pond container lifecycle path — the camp-on-bespoke-docker shortcut is gone. Containerd-side WorkloadRuntime impl still lands under R276 (warden's ContainerRuntime), as F10's original handoff foretold. See W142 §Crate layout + .yah/docs/working/W142-pond.md.")
//! @yah:handoff("WorkloadRuntime trait added to workload-spec (async_trait + anyhow added as deps). Trait has 4 methods: deploy_workload/teardown_workload/is_running/runtime_health. ImageRef::docker_ref() helper added. LocalDockerRuntime added to cloud/src/local_runtime.rs with workload_spec_to_crs translator (literal env only, bind mounts only, mesh/secrets skipped with warn). LocalDockerRuntime exported from cloud::lib. 6 unit tests covering translation, env filtering, port mapping, command override, and ImageRef::docker_ref. 171 cloud tests pass. Design decision: trait lives in workload-spec (already depended on by both cloud and warden, no new crate). Warden's ContainerRuntime (mesh-aware gRPC impl) implements WorkloadRuntime in R276 Tier-3; the sim tier (camp) uses LocalDockerRuntime now. Reconcilers calling LocalRuntime directly are unchanged; LocalDockerRuntime is available for callers that want to deploy arbitrary WorkloadSpec containers at sim tier.")
//! @yah:verify("cargo test -p cloud --lib  # 171 passed")
//! @yah:verify("cargo check -p workload-spec -p cloud -p yah -p desktop  # clean")
//!
//! @yah:ticket(R471-T2, "Extend WorkloadStatus with Restarting { last_exit_code, restart_count, last_finished_at }; update containerd + fake impls + tests")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-06T20:35:07Z)
//! @yah:status(review)
//! @yah:parent(R471)
//! @yah:verify("WorkloadStatus enum has Restarting variant; serde tag round-trips through the warden HTTP API.")
//! @yah:verify("containerd impl populates Restarting from task-exit + restart-policy state per S1 verdict.")
//! @yah:verify("fake runtime can be driven into Restarting from tests.")
//! @yah:verify("mirror_observation::Degraded decision documented (subsume vs coexist).")
//! @yah:depends_on(R471-S1)
//! @yah:gotcha("S1 verdict: containerd has NO native Restarting state and NO restart-count. The containerd Status enum is {Unknown, Created, Running, Stopped, Paused, Pausing}. Restart loop is warden's job per RestartPolicy in workload-spec.rs:1186.")
//! @yah:gotcha("Containerd impl needs a RestartLedger — in-memory HashMap<ContainerId, RestartRecord { count: u32, last_exit_code: u32, last_finished_at: SystemTime }> updated on each task recreate cycle. Populate Restarting variant from the ledger + 'currently in-flight recreate' bit.")
//! @yah:gotcha("Docker impl reads State.Restarting / State.RestartCount / State.ExitCode / State.FinishedAt directly — NO ledger needed (see R471-F3 gotchas).")
//! @yah:gotcha("mirror_observation::Degraded subsume-vs-coexist decision: subsume. Both today's Degraded and the new Restarting describe 'workload is in-flight restarting' — Restarting is strictly richer (carries exit_code + count). Delete Degraded after T5 lands.")
//! @yah:handoff("WorkloadStatus::Restarting { last_exit_code: i32, restart_count: u32, last_finished_at_unix_ms: u64 } landed in runtime/mod.rs:162. is_terminal() unchanged (Restarting is NOT terminal). Subsume decision documented in the enum's rustdoc — once T5 wires consumers to WorkloadStatus, pond::PondPhase::Degraded should be deleted.")
//! @yah:handoff("containerd impl: new RestartLedger { record_exit, mark_running, forget, get } struct exposed via ContainerdRuntime::ledger(). Per S1 verdict, containerd has no native restart signal — the supervisor (RestartPolicy applier) will call record_exit on each non-zero exit and mark_running once the replacement task is up. list_workloads / get_workload route the base task-state through apply_ledger(), which upgrades Stopped/Failed → Restarting when in_flight && count > 0. teardown_workload calls ledger.forget(). Wiring the supervisor side is out of scope for T2 (lives wherever RestartPolicy is applied; not located in this slice).")
//! @yah:handoff("fake runtime: FakeRuntime::mark_restarting(ident, exit_code, count, finished_at_ms) public helper added — drives a workload into Restarting from tests without needing a real crash loop. Used by the new mark_restarting_drives_status_for_crash_loop_fixture test.")
//! @yah:handoff("Tests: 7 new (6 in runtime::containerd::tests, 1 in runtime::fake::tests) — ledger record/clear semantics, apply_ledger upgrade matrix, serde round-trip through JSON ({type:\"restarting\",...}), fake mark_restarting fixture. cargo test -p warden --features containerd-integration,testing --lib → 119 passed (was 109).")
//! @yah:next("Sign-off check: read crates/yah/warden/src/runtime/mod.rs:160-205 (enum + is_terminal) and crates/yah/warden/src/runtime/containerd.rs:30-205 (RestartLedger + apply_ledger). If shape looks right, archive R471-T2 — then R471-F3 (docker impl) and R471-T5 (Services grid wiring) can both pick up the enum.")
//! @yah:next("Follow-on (NOT this ticket): the supervisor side that actually calls ledger.record_exit / ledger.mark_running on each restart cycle lives wherever RestartPolicy is applied in warden's deploy/monitor loop — needs its own ticket if it isn't already covered by an existing sub-ticket of R276 or B7.")
//! @yah:verify("cargo check -p warden && cargo check -p warden --features containerd-integration  # both clean")
//! @yah:verify("cargo test -p warden --features containerd-integration,testing --lib  # 119 passed (7 new)")
//! @yah:verify("grep -n 'Restarting' crates/yah/warden/src/runtime/mod.rs  # WorkloadStatus::Restarting present")
//!
//! @yah:ticket(R471-F3, "runtime::docker — third ContainerRuntime impl backing pond/OrbStack (populates Restarting from `docker inspect .State`)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-06T20:35:17Z)
//! @yah:status(review)
//! @yah:parent(R471)
//! @yah:verify("deploy/list/get/restart/teardown all green against a local OrbStack daemon.")
//! @yah:verify("list_workloads on a crash-looping container returns Restarting { restart_count: N, last_exit_code: E } matching `docker inspect`.")
//! @yah:verify("Same trait, same WorkloadState — zero pond-specific code leaks into desktop consumers.")
//! @yah:depends_on(R471-T2)
//! @yah:gotcha("bollard vs docker CLI shell-out: bollard is the right shape for streaming logs/events but adds a dep; docker CLI is zero-dep but adds parse risk. Pick once, document in the file's module doc.")
//! @yah:gotcha("S1 verdict: docker's State surfaces Restarting / RestartCount / ExitCode / FinishedAt natively — NO ledger needed. Populate WorkloadStatus::Restarting straight from State.Restarting==true. Containerd impl needs a ledger (see R471-T2); docker doesn't.")
//! @yah:gotcha("When State.Status == 'restarting' AND RestartCount > 0, return Restarting. When State.Status == 'exited' AND policy is 'no', return Stopped or Failed based on ExitCode. Mirror docker's own status→our-enum table in the impl's module doc.")
//! @yah:handoff("DONE. crates/yah/warden/src/runtime/docker.rs added: DockerRuntime struct + full ContainerRuntime impl (deploy/list/get/stream_logs/restart/teardown/health) via docker CLI shell-out. Decision: docker CLI over bollard — no extra deps, stable JSON schema from `docker inspect`. Status mapping table in module doc. map_docker_state() reads State.Restarting flag + Status=='restarting' → WorkloadStatus::Restarting without a ledger (S1 verdict). parse_docker_timestamp_ms() converts ISO8601 FinishedAt to unix ms. Feature-gated on `docker-integration` (no new deps; gate mirrors containerd-integration for consistency). 16 unit tests: 12 pure-logic (map_docker_state variants + timestamp parsing + missing-container detection) + 4 live-docker (health, get_workload returns None, list_workloads, teardown idempotent). All pass against OrbStack. Live crash-loop fixture (alpine exit 2 --restart=always, RestartCount=9) verified → Restarting { exit_code: 2, restart_count: 9 }. 132 total warden lib tests pass.")
//! @yah:handoff("stream_logs: follow mode deferred (docker logs -f would need a spawned process + async stream; non-follow drain is implemented and sufficient for F4/F6 log-tail use case). task_pid: returns 0 (docker CLI doesn't surface the host PID in the run output; add a `docker inspect --format={{.State.Pid}}` call if needed later). `--restart` policy is caller's concern — DockerRuntime.deploy_workload does not set a restart policy on the container (warden's RestartPolicy loop manages restarts).")
//!
//! @yah:relay(R484, "Constable library crate carve-out — runtime/ out of warden, shared by binary + desktop-inlined")
//! @yah:at(2026-06-08T02:30:36Z)
//! @yah:status(open)
//! @yah:phase(P1)
//! @yah:parent(Q405)
//! @arch:see(.yah/docs/working/W199-constable-universal-supervisor.md)
//! @arch:see(.yah/docs/working/W154-warden-dual-runtime.md)
//! @arch:see(.yah/docs/architecture/A043-yah-on-machine-daemons.md)
//!
//! @yah:ticket(R484-T2, "Move runtime/{native,containerd,docker} from warden into crates/yah/constable")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-08T02:30:57Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R484)
//! @arch:see(.yah/docs/working/W199-constable-universal-supervisor.md)
//! @yah:depends_on(R484-T1)
//! @yah:handoff("Moved warden/src/runtime/{containerd,docker,fake}.rs into crates/yah/constable/src/. ~2.4k LoC relocated verbatim, imports rewired (`use crate::mesh::MeshAssignment; use super::{...}` → `use crate::{Backend, Constable, MeshAssignment, ...}`). Each impl block was renamed `impl ContainerRuntime for X` → `impl Constable for X` and got a `fn backend() -> Backend` returning Containerd / Docker / Containerd (FakeRuntime stands in for the containerd backend in unit tests). `MeshAssignment::stub(ip)` kept as an alias of `MeshAssignment::inlined(ip)` so existing warden call sites compile untouched.")
//! @yah:handoff("warden::mesh::MeshAssignment + WireguardPeer are now re-exports of constable_core types (warden/src/mesh/mod.rs is 16 lines, no struct defs left). warden/src/runtime/mod.rs is a re-export shim: `pub use constable_core::{Constable as ContainerRuntime, DeployResult, LogEvent, LogOpts, LogStream, LogStreamKind, RuntimeHealth, WorkloadState, WorkloadStatus};` plus feature-gated module re-exports (`pub use constable_core::containerd`, `::docker`, `::fake`). DummyRuntime stays in warden::runtime since it's smoke-tier-specific; updated to `impl Constable` with `fn backend()` returning Backend::Containerd. R484-T5 deletes this shim and migrates callers onto `constable_core::*` directly.")
//! @yah:handoff("Cargo wiring: constable-core got `[features] containerd-integration/docker-integration/testing` matching warden's; optional `containerd-client = 0.9` + `prost-types = 0.14` moved into constable-core's deps gated on containerd-integration. constable-core's regular deps: anyhow, async-trait, futures-core, serde, serde_json, thiserror, tokio (rt+macros+net+io-util+sync+fs+time+process), tokio-stream, tracing, workload-spec. warden's three matching features now forward via `constable-core/containerd-integration` etc.; warden keeps its own copies of containerd-client + prost-types because main.rs / cloud-init still references containerd types directly (cleanable in T5). warden picks up `constable-core = { path = \"../constable\" }` as a regular dep.")
//! @yah:handoff("@yah:ticket annotation handling: original R091-F1 lives in warden/src/runtime/mod.rs (not duplicated to the moved containerd.rs — dropped from the copy with a comment line pointing back). R091-F2 (the runtime::fake ticket) MOVED with fake.rs into constable/src/fake.rs since mod.rs didn't have a copy — the annotation source-of-truth follows the file. R484-T2's own annotation stays in warden/src/runtime/mod.rs since the board IDs the relay's source from there (line 122).")
//! @yah:handoff("Verified: `cargo check -p constable-core --all-features` clean, `cargo test -p constable-core --all-features` 42 passed (3 in lib::tests + 12 in fake + 12 in docker + 12 in containerd + 3 verifying serde tags / inlined sentinel / terminal matrix). `cargo check -p warden` clean, `cargo check -p warden --features containerd-integration,testing,docker-integration` clean, `cargo test -p warden --lib --features containerd-integration,testing,docker-integration` 108 passed (matches previous baseline; runtime tests now run in constable-core, not warden — expected). `cargo check --workspace --all-targets` clean, `cargo check -p warden --tests --features containerd-integration,testing,docker-integration` clean (integration tests compile via the shim).")
//! @yah:next("Sign-off check: skim crates/yah/constable/src/lib.rs (trait + types), crates/yah/constable/src/{containerd,docker,fake}.rs (impl blocks now `impl Constable for X` with `backend()`), and the warden shim crates/yah/warden/src/runtime/mod.rs. Then archive R484-T2.")
//! @yah:next("T3 picks up: Backend probe-at-init wiring (R484-T3). The Backend enum + BackendUnavailable error landed in T1; T3 adds the connect()-test probes for docker/containerd sockets at Constable init and uses BackendUnavailable when callers ask for an absent backend. Probe semantics already described in W199 §Backend availability — lift the install-hint strings from there.")
//! @yah:verify("cargo check -p constable-core --all-features  # clean")
//! @yah:verify("cargo test -p constable-core --all-features  # 42 passed")
//! @yah:verify("cargo check -p warden --features containerd-integration,testing,docker-integration  # clean")
//! @yah:verify("cargo test -p warden --lib --features containerd-integration,testing  # 108 passed")
//! @yah:verify("cargo check --workspace --all-targets  # clean (warnings only, no errors)")
//! @yah:verify("grep -c 'pub use constable_core' crates/yah/warden/src/runtime/mod.rs crates/yah/warden/src/mesh/mod.rs  # both > 0")
//!
//! @yah:ticket(R484-T3, "Backend probe-at-init: connect()-test docker/containerd sockets; structured BackendUnavailable with install hint")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-08T02:31:03Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R484)
//! @arch:see(.yah/docs/working/W199-constable-universal-supervisor.md)
//! @yah:depends_on(R484-T2)
//! @yah:handoff("Added crates/yah/constable/src/probe.rs with BackendAvailability::probe() — connect()-tests well-known docker + containerd UDS paths and returns a per-backend BackendProbe { available, socket_path, detail, install_hint }. Honors DOCKER_HOST + CONTAINERD_ADDRESS env vars (unix:// prefix stripped). Native backend reported as always-available (fork+exec has no daemon to probe). 250ms connect timeout per path so a broken-but-present socket can't stall init.")
//! @yah:handoff("BackendAvailability::require(Backend) returns the structured BackendUnavailable error already added in T1, carrying the install hint ('Install Docker Desktop, OrbStack, or Colima …' / 'Install containerd …'). BackendProbe::require() is also exposed for direct use on a single probe result. This is the surface T4's two constructors (inlined / sibling) will gate on at init time, and T6's desktop will surface as 'install Docker' UI when Backend::Docker is unavailable.")
//! @yah:handoff("Wired up via `pub mod probe;` + `pub use probe::{BackendAvailability, BackendProbe};` in lib.rs:31. tempfile + tokio rt-multi-thread/macros/test-util were already in dev-dependencies — 8 new tests cover: native-always-available, missing-socket → install hint + require() returns BackendUnavailable, reachable socket → available + path captured, first-reachable-wins ordering, per-backend routing through availability.require(), and env-var precedence over default paths.")
//! @yah:handoff("Verified: cargo test -p constable-core --all-features → 50 passed (was 42 in T2; 8 new probe tests). cargo check -p warden --features containerd-integration,testing,docker-integration clean. No changes to existing impls — probe is additive.")
//! @yah:next("Sign-off check: skim crates/yah/constable/src/probe.rs end-to-end (~270 LoC; one file, no impl-block changes elsewhere). If shape looks right, archive R484-T3 — T4 (two-constructor API) gates on probe results at init.")
//! @yah:next("T4 wires probe into the two constructors: inlined builder calls BackendAvailability::probe() once at init and stores it on the Constable instance; sibling ConstableClient receives the probe snapshot from the server side over the W154 UDS protocol so the client knows which backends to surface in UI.")
//! @yah:verify("cargo test -p constable-core --all-features  # 50 passed (8 new probe tests)")
//! @yah:verify("cargo check -p warden --features containerd-integration,testing,docker-integration  # clean")
//! @yah:verify("grep -n 'pub use probe::' crates/yah/constable/src/lib.rs  # BackendAvailability + BackendProbe re-exported")
//! @yah:verify("grep -c 'install_hint' crates/yah/constable/src/probe.rs  # >0 (structured install hints surface in BackendUnavailable)")
//!
//! @yah:ticket(R484-T4, "Two-constructor API: inlined (Arc&lt;dyn Constable&gt;) and sibling (ConstableClient over UDS+postcard) re-targeted at new crate")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-08T02:31:09Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R484)
//! @arch:see(.yah/docs/working/W199-constable-universal-supervisor.md)
//! @yah:depends_on(R484-T2)
//! @yah:handoff("Two-constructor API now lives in constable-core. (1) Sibling: ~640 LoC moved from warden into crates/yah/constable/src/sibling.rs behind a new `sibling` cargo feature (pulls constable-proto as an optional dep). Warden's constable_client.rs became a 13-line re-export shim, then was deleted by R484-T5 along with this annotation's prior home.")
//! @yah:handoff("(2) Inlined: new crates/yah/constable/src/inlined.rs exposes Inlined::pick(&availability, &[Backend…], factory) -> Result<Arc<dyn Constable>, BackendUnavailable>. Walks the caller's preference list in order, returns the first backend whose probe came back available, invokes the factory exactly once with the chosen Backend tag. When none are available it returns BackendUnavailable for the LAST preference so callers who prefer Docker, else Containerd see the Containerd install hint when both are missing.")
//! @yah:handoff("Cargo wiring: constable-core gained `sibling = [\"dep:constable-proto\"]`; warden's constable-core dep is now `{ path = \"../constable\", features = [\"sibling\"] }`. Desktop (T6) leaves the sibling feature off.")
//! @yah:handoff("Verified at handoff: cargo test -p constable-core --all-features → 61 passed (was 50; +6 sibling +5 inlined). cargo test -p warden --lib --features containerd-integration,testing,docker-integration → 102 passed. cargo test -p warden --test integration_constable_client → 3 passed.")
//! @yah:verify("cargo test -p constable-core --all-features  # 61 passed (6 sibling + 5 inlined new)")
//! @yah:verify("cargo test -p warden --lib --features containerd-integration,testing,docker-integration  # 102 passed")
//! @yah:verify("cargo test -p warden --test integration_constable_client --features containerd-integration,testing,docker-integration  # 3 passed")

use async_trait::async_trait;
use constable_core::{
    Backend, Constable, DeployResult, LogOpts, LogStream, MeshAssignment, RuntimeHealth,
    WorkloadState,
};
use workload_spec::{MeshIdent, WorkloadSpec};

// ── DummyRuntime ──────────────────────────────────────────────────────────────

/// No-op `Constable` used as a placeholder in the smoke test tier.
///
/// The smoke tier provisions real Hetzner machines via cloud-init; the
/// `Constable` parameter in `test_cluster` is only used by the local tier.
/// `DummyRuntime` satisfies the generic bound without requiring a live
/// containerd socket on the test-runner machine.
///
/// All methods return `Err` — if a smoke test accidentally calls a runtime
/// method directly (rather than via the warden HTTP API), it will fail loudly.
pub struct DummyRuntime;

#[async_trait]
impl Constable for DummyRuntime {
    fn backend(&self) -> Backend {
        Backend::Containerd
    }
    async fn deploy_workload(&self, _spec: &WorkloadSpec, _mesh: &MeshAssignment) -> anyhow::Result<DeployResult> {
        anyhow::bail!("DummyRuntime: smoke tier does not use a local Constable")
    }
    async fn list_workloads(&self) -> anyhow::Result<Vec<WorkloadState>> {
        anyhow::bail!("DummyRuntime: smoke tier does not use a local Constable")
    }
    async fn get_workload(&self, _ident: &MeshIdent) -> anyhow::Result<Option<WorkloadState>> {
        anyhow::bail!("DummyRuntime: smoke tier does not use a local Constable")
    }
    async fn stream_logs(&self, _ident: &MeshIdent, _opts: LogOpts) -> anyhow::Result<LogStream> {
        anyhow::bail!("DummyRuntime: smoke tier does not use a local Constable")
    }
    async fn restart_workload(&self, _ident: &MeshIdent) -> anyhow::Result<()> {
        anyhow::bail!("DummyRuntime: smoke tier does not use a local Constable")
    }
    async fn teardown_workload(&self, _ident: &MeshIdent) -> anyhow::Result<()> {
        anyhow::bail!("DummyRuntime: smoke tier does not use a local Constable")
    }
    async fn health(&self) -> anyhow::Result<RuntimeHealth> {
        anyhow::bail!("DummyRuntime: smoke tier does not use a local Constable")
    }
}
