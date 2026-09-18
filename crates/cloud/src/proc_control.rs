//! The **process-control channel** — how a yah-supervised process describes
//! itself to its supervisor and to an agent, instead of being guessed at from
//! the outside.
//!
//! ## Why this is opinionated
//!
//! Everything yah runs is supervised by something in the kamaji family, and
//! until now the supervisor's only questions were "is the pid alive?" and "is
//! the port open?". Both are proxies. A process that has finished booting, a
//! process still replaying a WAL, and a process wedged on a lock all answer
//! them identically — so the only richer signal available to an operator or
//! an agent was grepping the log tail for a line somebody hopefully logged.
//!
//! So: **any process built to run under a yah camp SHOULD expose a control
//! channel**, dev tier or prod tier, port or no port. It is the difference
//! between an agent reading `state = "starting", detail = "migrating 3/7"`
//! and an agent tailing stdout hoping for a sentence.
//!
//! ## The contract
//!
//! One required verb. A conforming process answers a `status` request with a
//! **status document**:
//!
//! ```json
//! {"state":"running","ready":true,"pid":71455,"uptime_secs":41,
//!  "detail":"3 windows open","endpoints":{"gui":"winit://main"},
//!  "metrics":{"frames_per_sec":59.9}}
//! ```
//!
//! `state` is the only required field, and its vocabulary is *exactly*
//! kamaji's [`WorkloadState`](https://docs.rs/kamaji-proto) —
//! `pending | starting | running | draining | exited | failed`. That is the
//! compatibility rule that matters: the supervisor already has this enum in
//! its wire protocol and already answers a `Probe` verb with it, so a
//! workload that reports in the same words can be believed verbatim rather
//! than translated. Everything else in the document is optional.
//!
//! ## Two transports, one document
//!
//! | Transport | Where | How |
//! |---|---|---|
//! | Unix socket | dev tier, portless or not | newline-delimited JSON: write `{"cmd":"status"}\n`, read one JSON line back |
//! | HTTP | any tier that already serves HTTP | `GET <base><path>` (conventionally `/_yah/status`) returning the same document |
//!
//! The prod tier gets this for free: a `Healthcheck { probe: Http { path } }`
//! in `workload-spec` pointed at the status path is the *same* endpoint the
//! dev tier reads over a socket. One document, two transports, no per-tier
//! fork — which is the same rule W265 applies to everything else here.
//!
//! ## Why newline-JSON and not the kamaji postcard wire
//!
//! Because the producer side has to be implementable in twenty lines with no
//! dependency, in any language, by someone whose actual job that day is their
//! own app. kamaji's `kamaji-proto` is postcard over a framed UDS: excellent
//! between two Rust processes that both link it, a non-starter as a thing you
//! ask every workload in the fleet to adopt. A strict-subset JSON document
//! that a Bun script or a Python daemon can emit is the version that actually
//! gets adopted, and it is trivially bridged into `kamaji-proto`'s
//! `WorkloadState` because the vocabulary was chosen to match.
//!
//! ## Where the socket path comes from
//!
//! The supervisor picks it and hands it over in the environment as
//! **`YAH_CONTROL_SOCK`**. A conforming process binds `$YAH_CONTROL_SOCK` if
//! it is set and does nothing if it isn't — so the same binary runs unchanged
//! outside a camp.
//!
//! @arch:see(.yah/docs/working/W315-process-control-channel.md)
//! @arch:see(.yah/docs/working/W265-service-capabilities-and-drivers.md)
//!
//! @yah:ticket(R715-F3, "Process-control channel phase 2: producer helper crate, run.spawn injection, kamaji Probe bridge")
//! @yah:status(review)
//! @yah:at(2026-08-14T22:30:16Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R715)
//! @arch:see(.yah/docs/working/W315-process-control-channel.md)
//! @yah:next("Producer-side helper crate so conforming is two lines for a Rust workload (bind the socket, answer status from a Fn() -> ProcStatus). CRATE HOME IS AN OPERATOR CALL: oss/kamaji/crates/* (nearest owner, but an independent workspace and a publish surface) versus a standalone oss/procctl. It cannot live in yah-cloud where the client is, because external consumers (noisetable, in the entambi repo) need it from crates.io.")
//! @yah:next("run.spawn does not inject YAH_CONTROL_SOCK, so agent-spawned processes have no channel even if they speak it. Injecting the var is trivial; the value only appears once the camp daemon exposes a run.status RPC to read it back. Do both together.")
//! @yah:next("kamaji bridge: kamaji already answers a Probe verb with WorkloadState, and ProcState was chosen to match it word for word, but nothing wires the two. A workload that reports `starting` is currently believed by the reconciler and invisible to kamaji.")
//! @yah:next("Run tab polls the status once at bring-up (surfaced via RunningWorkloadSummary.notes). Live polling - a status line that moves starting -> running while you watch - needs an RPC, not new protocol.")
//! @yah:next("Nothing enforces the SHOULD. A lint over workload.toml (long-running component, no [process.control], no healthcheck) would turn W315 into a gate. One implementation was judged too little evidence to start failing builds over.")
//! @yah:gotcha("The protocol is deliberately dependency-free (one newline-delimited JSON verb), so nothing REQUIRES a crate to conform. The helper is ergonomics, not a gate - do not let its crate-home question block anyone from implementing the channel by hand.")
//! @yah:gotcha("Do not switch the wire to kamaji-proto's postcard framing to unify them. That was considered and rejected in W315: the producer side has to be implementable in twenty lines in any language, and postcard-over-framed-UDS is a Rust-links-the-crate contract.")
//! @yah:next("DECIDED 2026-08-14 by the operator, do not re-litigate: the producer helper crate lives at oss/kamaji/crates/procctl. Kamaji already owns the WorkloadState vocabulary this protocol reuses, so helper and enum move together; accepted cost is one more publish surface in kamaji's workspace. Rejected alternative: a standalone oss/procctl. Note kamaji is an INDEPENDENT cargo workspace with an export mirror - no workspace = true inheritance from yah's root, and the crate ships outward via scripts/export-oss.sh.")
//! @yah:handoff("All three titled items shipped. (1) PRODUCER CRATE: oss/kamaji/crates/procctl, package kamaji-procctl, lib name procctl (dir per the operator's call; package name follows the kamaji-* convention and is now listed in scripts/reserve-crate-names.sh + scripts/set-trusted-publishers.sh). Default build is std + serde only - a winit GUI with no runtime can adopt it, which was the motivating case. serve_env() returns Ok(None) when YAH_CONTROL_SOCK is unset; the server stamps pid and uptime when the producer omits them; a dead predecessor socket is reclaimed but a LIVE one is refused rather than stolen. Optional features: client (async consumer, tokio) and kamaji (ProcState -> WorkloadState).")
//! @yah:handoff("(2) KAMAJI BRIDGE: procctl's kamaji feature holds the From impl as an exhaustive match, so a state added to either vocabulary stops compiling - that compile error is the entire mechanism keeping W315's believed-verbatim claim true. The reverse direction is deliberately absent (WorkloadState is non_exhaustive, so matching it needs a wildcard, which is the silent drift the design refuses). ProbeTarget gained control: Option<PathBuf> and healthcheck became Option<Healthcheck> (a portless GUI has no port to probe and inventing a healthcheck for it is a lie); constructors ProbeTarget::healthcheck / ::control replace the struct literals. A control socket is the WHOLE probe when present - unreachable reads Starting, never a fallback to the port, per W315. Registered on the native-exec deploy path only, read from the spec's own YAH_CONTROL_SOCK literal, because a container's socket path names a location inside its mount namespace kamaji has no route to.")
//! @yah:handoff("(3) RUN.SPAWN INJECTION + RUN.STATUS: every spawn is now offered the channel unconditionally (a conforming process binds when set, does nothing when unset, so this costs a declining process nothing). New rpc::method::RUN_STATUS + RunStatusParams/RunStatusResult, run_status_handler in camp.rs, and a read-only run.status agent tool. The result relays the document verbatim (serde_json::Value) so a producer's own metrics/endpoints reach the caller intact. run.stop now unlinks the socket.")
//! @yah:verify("cargo test --workspace --all-features in oss/kamaji: all green. kamaji-procctl 26 passed + 1 doc-test; kamaji-bin lib 248 passed (was 216, +5 control-channel probe tests, +3 server tests).")
//! @yah:verify("cargo test -p yah --lib camp:: - 298 passed, including 5 new r715_f3_control_channel_tests that drive real child processes through run_spawn_handler / run_status_handler / run_stop_handler.")
//! @yah:verify("cargo test -p yah-agent-tools --lib run_tools - 16 passed. cargo test -p yah-rpc --lib - 45 passed. cargo test -p yah-cloud --lib proc_control (oss/yubaba) - 10 passed, untouched.")
//! @yah:verify("cargo check --workspace (root) and cargo check -p yubaba (oss/yubaba) clean; scripts/check-workspace-members.sh resolves all 58 members. kamaji-procctl also checked with default features (no client, no kamaji) so the producer half stays std-only.")
//! @yah:verify("The sandbox rule is pinned by a test that binds from INSIDE the sandbox - a_sandboxed_child_can_bind_the_socket_it_is_handed (camp.rs), a ~15-line stdlib-Python producer spawned through run_spawn_handler. Every other test in that module binds from the test process, which is outside the sandbox and proves nothing about it. It skips (does not fail) where no python3 exists.")
//! @yah:gotcha("MACOS SANDBOX BUG FOUND AND FIXED, and it would have made the whole injection useless on macOS. run.spawn puts the control socket at <workload_dir>/.yah-control.sock because that is the only writable path both sandbox facilities agree on (Seatbelt allows file-write* under WORKLOAD; bwrap binds workload_dir and nothing else - .yah/jit/ is not even present inside the bwrap namespace). But file-write* is NOT sufficient: Seatbelt gates AF_UNIX bind under network-bind, so a child got EPERM binding a path it could otherwise create any file at. MACOS_SANDBOX_PROFILE now carries (allow network-bind (local unix-socket (subpath (param WORKLOAD)))). Reproduced by hand with sandbox-exec before and after. plugin_host.rs shares the same profile constant and passes the same -D WORKLOAD, so it inherits the rule.")
//! @yah:gotcha("DISCOVERED, NOT FIXED (deliberately): kamaji never registers a ProbeTarget from a spec's own healthcheck on any path except the mesofact-bundle deploy. insert_probe has exactly three call sites (server.rs registry decl, the bundle deploy, and now the native control-channel registration), so a container workload declaring a healthcheck is probed as Ready unconditionally. Fixing it means live fleet workloads that report Ready today would start reporting real probe status - a behaviour change on running infra, not a drive-by. The control registration added here cannot regress that: it only fires when the spec declares YAH_CONTROL_SOCK, so a spec without it registers nothing and behaves exactly as before.")
//! @yah:cleanup("kamaji-procctl is not on crates.io. In-tree consumers resolve it by path so nothing is blocked, but kamaji-bin now depends on it and cargo publish --workspace publishes in topological order - the name must be reserved (scripts/reserve-crate-names.sh, entry added) before the next kamaji release, or that release fails on an unpublished dep. The external consumers this crate exists for (noisetable, entambi repo) need it published anyway.")
//!
//! @yah:ticket(R918-F5, "Windows leg wall 3: yubaba cloud's local-process reconciler is Unix process semantics, not a gatable module")
//! @yah:status(review)
//! @yah:at(2026-09-17T08:57:18Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R918)
//! @arch:see(.yah/docs/working/W352-windows-and-macos-build-targets.md)
//! @yah:gotcha("MEASURED, not predicted — this is exactly where `cargo check --target x86_64-pc-windows-gnu -p yah` stops once R918-T1's kamaji and mesofact-core fixes are in. 5 errors, all in yah-cloud (oss/yubaba/crates/cloud): proc_control.rs:278 `tokio::net::UnixStream` in `fetch_status_uds`; reconciler/local_process.rs:935 `libc::SIGKILL`, :949 and :957 `libc::kill` (`pid_alive` / `signal_pid`); reconciler/pond_door.rs:536 `libc::geteuid` (`is_root`). Reproduce with the R918-T1 verify line (windres shim + isolated CARGO_TARGET_DIR) — it is in that ticket's verify.")
//! @yah:next("DO NOT REACH FOR `#[cfg(unix)]` ON THE MODULE — that is what worked for walls 1 and 2 and it is the wrong tool here, which is the whole reason this is a separate ticket rather than folded into R918-T1. kamaji and mesofact-core each had a cleanly separable Unix DAEMON half sitting beside a neutral half; gating the daemon half cost four one-line attributes and changed no behaviour. Here the Unix primitives are load-bearing inside the live fleet reconciler's semantics, so each one is a DECISION about what it means on Windows, not a cfg: (a) `pid_alive`/`signal_pid` are `kill(pid,0)` liveness plus SIGTERM-then-SIGKILL escalation — Windows needs a real OpenProcess/TerminateProcess implementation or the local-process reconciler must be declared Unix-only; (b) `is_root()` is documented as \"running under sudo, the only way to bind --port 443 on macOS\" and has NO Windows equivalent — elevation is a different concept, not a renamed one; (c) `fetch_status_uds` is the ProcStatus poll — Windows 10+ has AF_UNIX but tokio does not expose `UnixStream` there, so this is a transport choice (named pipe vs loopback TCP) that changes a wire contract.")
//! @yah:next("SETTLE THE SCOPE QUESTION FIRST, because it may delete most of the work: does a Windows yah CLI need the local-process reconciler AT ALL? These paths supervise workloads on a fleet node. If the Windows target is a CLIENT CLI (talk to a camp, submit builds) rather than a fleet node, the honest answer is that yubaba's reconciler is Unix-only by design and the fix is to stop the CLI linking it — the same graph problem W352 named for kamaji, one layer out. That is a cheaper and more truthful change than three Windows syscall implementations nobody will exercise. Read W352's goals before picking.")
//! @yah:gotcha("LIVE-FLEET BLAST RADIUS — oss/yubaba/crates/cloud operates the real nodes in .yah/infra/machines/. The root CLAUDE.md's pre-1.0 \"break it, don't tape it\" rule explicitly does NOT extend to breaking a running fleet carelessly: design the code as if one version exists, sequence the roll as if two do. A change to pid reaping or SIGKILL escalation is exactly the kind that looks inert in a diff and strands processes on a node. Whatever shape is chosen, the Unix behaviour must be byte-identical afterwards.")
//! @yah:handoff("SHAPE CHOSEN: option 1 (gate the Unix-only surfaces inside yah-cloud), NOT option 2 (cut the CLI's edge to yah-cloud). Evidence for rejecting option 2, measured before editing: the CLI is not incidentally linked to yah-cloud — `app/yah/cli/src/camp.rs` and `cloud.rs` reach `cloud::` at 60+ sites for CloudConfig/ServiceConfig/ServiceComponent/MirrorConfig/Provider/LocalRuntime/ReconcileCtx and the whole `reconciler::pond` surface. There is no thin neutral-types edge to cut. The failing surface, by contrast, was three isolated things with almost no internal fan-in: `is_root` had ONE caller in the whole repo (pond_door.rs's own `ensure_pond_cert`); `LocalProcessReconciler`/`local_process::` had exactly two outside the crate (app/yah/cli/src/cloud.rs:11138 and app/yah/desktop/src/mirror_run.rs:1008); `proc_control` is consumed by camp.rs only for CONTROL_SOCK_ENV + ControlEndpoint + fetch_status. So the Unix-only part was cleanly separable after all — the ticket's warning that a cfg was the wrong tool was written against a scope question that had not yet been answered.")
//! @yah:handoff("WHAT LANDED, three gates in yah-cloud plus their downstream. (1) reconciler/local_process.rs — the module is `#[cfg(unix)]` WHOLE, not half-ported, with the reasoning written at the gate: its contract is \"replace the predecessor\" (kill(pid,0) liveness + SIGTERM-grace-SIGKILL), and a build with that ladder stripped would still spawn and would silently double-spawn instead of reaping, which is precisely the stranded-process failure this ticket's own gotcha warns about. Re-exports gated in reconciler/mod.rs:179 and lib.rs. (2) reconciler/pond_door.rs — `is_root` (geteuid) and `ensure_pond_cert` (its only caller) are `#[cfg(unix)]`; deliberately NO non-unix counterpart, because Windows elevation is an integrity level plus a token privilege, not a renamed euid, so answering `false` there would be a guess dressed as a fact. `ensure_pond_cert_as` — the version with the privilege injected — stays portable and ungated, and is the portable half of that API. (3) proc_control.rs — `fetch_status_uds` is `#[cfg(unix)]` and `fetch_status`'s `Socket` arm gets a `#[cfg(not(unix))]` arm returning a precise error. The ENUM VARIANT was deliberately kept on all platforms: gating it would have forced surgery on app/yah/cli/src/camp.rs (run.spawn/run.status), a 38k-line file three peers were editing during this session, for no gain — a PathBuf variant is perfectly representable and `fetch_status` already documents \"errors mean unreachable\" as its vocabulary, so a platform with no such transport is inside that contract rather than beside it. Four UDS-backed tests + the `serve_once` helper gated to match.")
//! @yah:handoff("DOWNSTREAM, four sites, all outside camp.rs: app/yah/cli/src/cloud.rs — `LocalProcessReconciler` moved out of the big `use cloud::{...}` list into its own `#[cfg(unix)] use`, and the `\"container\" if local_process::slot_declared(..)` match arm carries `#[cfg(unix)]` (an attribute on a match arm is legal and is the smallest correct edit); `handle_pond` split into a `#[cfg(unix)]` original plus a `#[cfg(not(unix))]` counterpart that bails naming mkcert and passway, with `handle_pond_door` gated alongside its only caller. app/yah/desktop/src/mirror_run.rs — same two edits (import + match arm). `cargo check -p desktop` EXIT=0 confirms the desktop half.")
//! @yah:handoff("DISCOVERED WORK FIXED IN THIS PASS, not filed as a followup. (a) WALL 4 was one line: crates/yah/agent-tools/src/daemon_client.rs:228 `SCRATCH_ACQUIRE_TIMEOUT` was the ONLY one of four `const …: Duration` in that file missing the `#[cfg(unix)]` its three siblings carry (RPC_TIMEOUT :197, MID_TIMEOUT :217, WORKLOAD_ACTUATE_TIMEOUT :243), and `Duration` is imported under that gate — so a non-unix build failed there with `cannot find type Duration`. Attributed, not guessed: `git diff --stat` on that file was EMPTY, so it is committed state and not a peer's in-flight edit. (b) Three items went dead-on-Windows once local_process was gated and are now gated to match, so the Windows leg does not accumulate dead-code noise: reconciler/native_support.rs `spawn_native_log_supervisor` and `FileTail` (the latter `#[cfg(any(unix, test))]` — its other callers are in that file's own test module), and reconciler/mod.rs `wait_for_port`. (c) proc_control.rs's `use tokio::io::{…}` is `#[cfg(unix)]`, since only the UDS transport reads or writes a stream (the HTTP arm goes through reqwest); `use std::path::{Path, PathBuf}` narrowed to `PathBuf` with `fetch_status_uds` spelling `std::path::Path` inline.")
//! @yah:verify("WINDOWS PROBE — baseline re-measured by me on this tree before editing (NOT taken on the dispatch's word): EXIT=101, 6 error lines, 5 of them the yah-cloud errors named in this ticket's gotcha at their current line numbers (proc_control.rs:288, local_process.rs:935/:949/:957, pond_door.rs:536 — the gotcha's :278 is one tree-state stale), 0 in kamaji. AFTER: EXIT=101, 22 error lines, 21 real errors and ZERO of them in yah-cloud or yah-agent-tools — every one is in app/yah/cli/src/ (venue.rs 8, qed_worktrees.rs 3, camp_control_plane.rs 3, cli.rs 2, qed.rs/plugin_host.rs/plugin_grants.rs/plugin_broker.rs/lan_tunnel.rs 1 each). That is wall 5, filed as R918-F7 with the same measurement. Attribution method for the file counts: `awk '/^error/{e=$0; getline; print $0}' probe.log` pairs each error with ITS location — a bare grep for the crate path also matches warning lines and this ticket's own annotation prose and reports 8 phantom yah-cloud hits.")
//! @yah:verify("UNIX DID NOT REGRESS — all measured on this tree after the edits: `cargo check -p yah` EXIT=0; `cargo check -p desktop` EXIT=0; `cargo check --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --all-targets` EXIT=0; `cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib` = 1253 passed / 0 failed / 4 ignored, EXIT=0. BASELINE CAVEAT, stated rather than papered over: my pre-edit `cargo test -p yah-cloud` baseline never ran — from the repo root cargo answers \"package `yah-cloud` cannot be tested because it requires dev-dependencies and is not a member of the workspace\" (the --manifest-path form is the only one that works; config.rs's R918-era annotation says the same). So the yah-cloud test number is an after-only measurement. It is still load-bearing evidence: every Unix-side edit here is a `#[cfg(unix)]` that evaluates TRUE on the test host, plus re-export relocations, so the Unix path is byte-identical by construction and 0 failures is the expected result rather than a lucky one. The pre-edit `cargo check -p yah` baseline DID run and was EXIT=0.")
//! @yah:gotcha("SCOPE ANSWER USED, recorded so it is not re-litigated: the relay leader ruled the Windows yah CLI is a CLIENT (talks to a camp, submits builds, is not a fleet node and will not supervise workloads), so yubaba's local-process reconciler is Unix-only BY DESIGN and the fix is to stop linking it on Windows rather than to implement OpenProcess/TerminateProcess, a Windows elevation check and a named-pipe transport. Reversing that costs exactly one ticket implementing those three, at the point someone actually wants a Windows fleet node; it costs nothing now. NOTE FOR THE NEXT READER: this ticket's own `@yah:next` says \"DO NOT REACH FOR #[cfg(unix)] ON THE MODULE\" — that instruction was written BEFORE the scope question it also asks was answered, and the answer inverts it. With the reconciler declared unix-only, a module gate is not a half-port dodging a decision; it IS the decision, written where the compiler enforces it.")
//! @yah:gotcha("BEHAVIOUR CHANGE ON WINDOWS ONLY, listed so nobody discovers it at runtime: `yah cloud pond door` and `yah cloud pond cert` fail with a message naming mkcert and passway; a mirror binding its compute slot to `local-process` no longer matches the local-process arm and falls through to the container reconciler, failing there with that reconciler's own diagnostic rather than silently double-spawning an unreaped process; `cloud::proc_control::fetch_status` on a `Socket` endpoint returns an error naming the transport. All three are non-unix-only. Unix is untouched — no `pid_alive`, `signal_pid` or `is_root` BEHAVIOUR was modified, which was this ticket's stated live-fleet constraint.")
//! @yah:handoff("Wall 3 cleared and verified; wall 4 (agent-tools, one line) absorbed; wall 5 measured and filed as R918-F7 rather than absorbed. Wall 5 is genuinely separable, not a fourth cfg attribute: it is 21 errors across 9 files of the CLI's OWN Unix surfaces (plugin sandbox, venue flock, lan-tunnel signals, camp control plane, qed worktree reaping), its eight candidate modules carry 125 intra-CLI reference sites, and it turns on an operator call this relay has NOT made — W352 frames Windows as a build TARGET and R919 calls us-west-002 a build WORKER, but `yah qed run --in-process` is the local-build path and it reaches `libc::kill` and `crate::camp`. Declaring that unix-only is the precedent-matching default and may defeat the point of the Windows leg. Full measurement and the question are on R918-F7.")
//! @yah:handoff("LEADER SIGN-OFF (R918 relay). The scope call I made at dispatch — Windows yah CLI is a CLIENT, so stop it linking yubaba's reconciler rather than implement Windows syscall equivalents — was executed as Shape 1 (gate the Unix-only surfaces inside yah-cloud): local_process gated whole, is_root/ensure_pond_cert gated, fetch_status_uds gated with an explicit non-unix error arm, plus four downstream sites in app/yah/cli/src/cloud.rs and app/yah/desktop/src/mirror_run.rs. Shape 2 (cut the CLI's edge to yah-cloud) was rejected on measured evidence rather than taste — the CLI reaches `cloud::` at 60+ sites, so there is no thin edge to cut. That is the right call and the evidence is the reason it is the right call.</handoff>\n<parameter name=\"verify\">RE-VERIFIED BY THE LEADER, both halves, independently of the courier's return. WINDOWS: the ticket's probe gives EXIT=101 with 22 error lines, and bucketing every error's `-->` location by directory gives **21 in app/yah/cli/src and ZERO anywhere else** — no yah-cloud, no yah-agent-tools, no kamaji, no mesofact-core. The 6→21 error count is progress, not regression: three crates went clean and a previously-unreachable surface became visible, and the distribution matches R918-F7's independently-filed per-file breakdown. UNIX DID NOT REGRESS, which is the half that actually carried risk given this crate operates the live fleet: `cargo check --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --all-targets` CHECK_EXIT=0 with 0 errors, and `cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib` TEST_EXIT=0, **1253 passed / 0 failed / 4 ignored**. The ticket's own gotcha demanded Unix behaviour be byte-identical afterwards; a full green test suite on the reconciler is the evidence for that.</verify>\n<parameter name=\"gotcha\">WALL 4 WAS ABSORBED HERE RATHER THAN FILED, correctly — app/yah/cli/src/daemon_client.rs:228 had one of four `Duration` consts missing the `#[cfg(unix)]` its three siblings carry. That is committed state, not a peer's in-flight edit, and it is a one-line fix standing directly in this ticket's path; filing it would have cost a ticket, a dispatch and a cold agent re-deriving context. WALL 5 was correctly NOT absorbed and is filed as R918-F7: it is 21 errors across eight CLI modules with 125 intra-CLI reference sites, and it turns on an operator scope question this ticket's ruling does not settle.</gotcha>\n<parameter name=\"assumes\">EVIDENCE CAVEAT on the Windows probe above, stated rather than left for a reader to find: the camp daemon attached a deferred skew verdict reporting 2 build inputs changed mid-run (app/yah/cli/src/camp.rs and crates/yah/camp-service/src/bite/mod.rs), so that run describes a tree that had already moved. The conclusion survives it — the error-location histogram is a directory-level fact, R918-F7's per-file breakdown lists no camp.rs error site, and the Unix half above ran clean and skew-free — but the exact count of 21 should be re-measured rather than quoted as gospel by whoever picks up F7.</assumes>\n</invoke>\n")

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
// R918-F5 — only the unix-socket transport (and the tests that exercise it)
// reads or writes a stream here; the HTTP arm goes through reqwest.
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Environment variable naming the control socket a supervised process should
/// bind. Absent → the process is not running under a supervisor that wants a
/// control channel, and MUST NOT fail for its absence.
pub const CONTROL_SOCK_ENV: &str = "YAH_CONTROL_SOCK";

/// Conventional HTTP path for the status document on a process that already
/// serves HTTP. Not enforced — `[process.control] http_path` overrides it —
/// but a service with no reason to differ should use this one.
pub const DEFAULT_HTTP_PATH: &str = "/_yah/status";

/// Lifecycle vocabulary of a supervised process.
///
/// Deliberately identical to `kamaji_proto::WorkloadState` so a workload's own
/// report can be handed to the supervisor without a translation table that
/// would rot the first time either side gained a state. Kept as a separate
/// type rather than a re-export only because this crate must not force a
/// `kamaji-proto` dependency on every consumer of the status document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcState {
    /// Accepted, nothing started yet.
    Pending,
    /// Started, not yet serving — booting, migrating, warming a cache.
    Starting,
    /// Serving. This is the only state that counts as ready.
    Running,
    /// Shutting down gracefully.
    Draining,
    /// Exited cleanly.
    Exited,
    /// Exited with a failure, or reported itself unrecoverable.
    Failed,
}

impl ProcState {
    /// Whether a process in this state is ready to be used.
    ///
    /// `Starting` is deliberately *not* ready: the entire point of the channel
    /// is to distinguish "the port is open" from "I am serving".
    pub fn is_ready(self) -> bool {
        matches!(self, ProcState::Running)
    }

    /// Whether this state is terminal — no amount of further polling changes
    /// it, so a readiness wait should fail fast rather than burn its timeout.
    pub fn is_terminal(self) -> bool {
        matches!(self, ProcState::Exited | ProcState::Failed)
    }
}

/// A workload's self-description. Only [`Self::state`] is required.
///
/// @yah:relay(R866, "Deployed-credential drift: apply-time value fingerprints reported back over the ProcStatus rail")
/// @yah:at(2026-09-05T08:47:33Z)
/// @yah:status(open)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @arch:see(.yah/docs/working/W337-credential-health-and-rotation.md)
/// @yah:depends_on(R556-F6)
/// @yah:next("THE PROBLEM. A credential used by a cloud workload is injected at `yah cloud apply` time from the local vault via resolve_serve_env (grep `fn resolve_serve_env` in app/yah/cli/src/cloud.rs — :7979 on 2026-09-05, but it has moved three times). That splits rot in two: (a) the vault copy rotted, which a local `yah keys doctor` probe already catches, and (b) THE DEPLOYED COPY DRIFTED FROM THE VAULT COPY — someone rotated the vault and never re-applied, or applied and the workload never restarted. In case (b) the vault probe is GREEN and the service is DOWN. This relay is (b) and only (b).")
/// @yah:next("SCOPE THE DELTA. The apply-time PRESENCE half is already built and must NOT be rebuilt: resolve_serve_env is FATAL on an empty resolution, with an error naming the slot and the `yah keys set` fix, so a serve process is never forked with a blank credential. What it cannot catch is a value that resolves fine and is DEAD, or one that DRIFTED after apply.")
/// @yah:next("SHAPE. At apply time store a SALTED hash of each injected value; have the workload report the hash of what it is actually running with; compare. That detects (b) without moving a secret anywhere. HARD CONSTRAINT: no secret value, and no secret LENGTH, may appear in the fingerprint path, in the reported status document, or in any log.")
/// @yah:next("USE THE EXISTING ProcStatus RAIL — do not build a bespoke per-workload health endpoint. Right here in this file: workloads publish a `ProcStatus` self-description document (:155), fetched by `fetch_status` (:234) over a `ControlEndpoint` that is `Socket(PathBuf)` OR `Http(String)` (:211, doc: \\\"for a process that already serves HTTP, including every cloud-tier workload\\\"), at conventional path DEFAULT_HTTP_PATH = \\\"/_yah/status\\\" (:111, overridable per-workload via `[process.control] http_path`). Producer side is a published two-line helper crate, oss/kamaji/crates/procctl (serve_env / serve_at / ControlServer, lib.rs:78). Riding this rail makes the feature work for EVERY procctl-conforming workload rather than mesofact alone.")
/// @yah:next("THE ONE GAP, and it is the first edit: ProcStatus has NO field a hex fingerprint fits. `metrics` is `BTreeMap<String, f64>` (numeric only), `endpoints` is addresses, `detail` is documented as ONE HUMAN LINE. Add a string-valued field — `env_fingerprint`, or a general free-form `labels: BTreeMap<String, String>`; THAT CHOICE IS A NAMING CALL, make it deliberately — carrying #[serde(default)] so workloads built before this change keep deserializing.")
/// @yah:next("SURFACE IT IN THE EXISTING TABLE, not a new command. `yah cloud mirror-status` already does declared-vs-observed comparison for replicas and already has a --drift filter: `handle_mirror_status` at app/yah/cli/src/cloud.rs:11862, row type `MirrorStatusRow` at :6774, --drift applied at :11929. Add a row type; do not add a command. (Older prose cites :9684 for this — that was never a mirror-status line.)")
/// @yah:gotcha("THERE IS NO LIVE CONSUMER YET, AND THAT GATES THIS RELAY — it is why depends_on(R556-F6) is set. Measured 2026-09-05: ZERO uncommented `vault:` declarations in any tracked TOML. All four hits are commented out — .yah/services/yah-analytics/mirrors/cloud.toml:616-618 (the `#!` cut-over block) and .yah/qed/gha-actions.toml:25 — so today there is nothing for an apply-time hash to hash and the reporting half would be dead code on both ends. Step (4) of R556-F6's cut-over uncomments that block and creates the first live declaration. Confirm the field shape against what R556-T12 actually SHIPPED, not against the comment: the comment predates it and names `cloudflare-r2-endpoint`, a slot the vault does not have.")
/// @yah:gotcha("RIPGREP TRAP that has already cost two sessions a false reading: rg skips hidden directories by default, and every `vault:` declaration in this tree lives under .yah/. So `rg '=\\s*\"vault:\"' --glob '*.toml'` WITHOUT --hidden returns clean over a tree that is not clean. Always pass --hidden when re-measuring the trigger.")
/// @yah:gotcha("BLAST RADIUS IS WIDER THAN IT LOOKS — weigh it before starting. This touches oss/yubaba AND oss/kamaji, which are INDEPENDENT Cargo workspaces excluded from the yah root workspace (so no `workspace = true` inheritance from the root inside them), and procctl is a crates.io PUBLISH surface, meaning a ProcStatus field change is a wire-format change for external consumers (noisetable, in the entambi repo, is named as one in this file's own R-notes). #[serde(default)] on the new field is not optional politeness; it is what keeps already-deployed workloads deserializing.")
/// @yah:gotcha("HISTORY: this was R856-F8, deferred unbuilt across three sessions (2026-09-03/04/05) because the trigger never fired. Operator decision 2026-09-05 re-filed it here as its own relay rather than holding R856 open — R856's remaining work is vault-local and finished, while this spans two oss workspaces and a publish surface. R856-F8 is archived; its design record is W337 §5.")
/// @yah:verify("Rotating a vault slot without re-applying shows as drift in `yah cloud mirror-status --drift`, while the local `yah keys doctor` probe still reports Valid on the same slot")
/// @yah:verify("No secret value and no secret LENGTH appears in the fingerprint path, in the reported ProcStatus document, or in any log")
/// @yah:verify("A workload built before the new ProcStatus field still deserializes (pin it with a test that feeds the pre-change JSON through serde), so a partial fleet roll cannot break status reporting")
/// @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud proc_control  # the rail's existing serde round-trip tests still pass (see proc_control.rs:493)")
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcStatus {
    /// Lifecycle state, in kamaji's vocabulary.
    pub state: ProcState,
    /// Redundant convenience mirror of `state == running`, accepted from
    /// producers that emit it. Never trusted over `state` — a document
    /// claiming `{"state":"starting","ready":true}` is a producer bug, and
    /// believing the optimistic half of it is how a supervisor reports a
    /// half-booted process as up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    /// Process id, when the process knows and cares to say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Seconds since the process considered itself started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    /// Build/version string, for an operator staring at two of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// One human line elaborating on `state` — "replaying WAL 3/7",
    /// "waiting for GPU". This is the field that replaces log-grepping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Named addresses the process serves — `{"http":"http://127.0.0.1:4325"}`.
    /// A portless process may legitimately name a non-URL surface here.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub endpoints: std::collections::BTreeMap<String, String>,
    /// Numeric gauges the process wants surfaced. Free-form on purpose: this
    /// is a status channel, not a metrics pipeline.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub metrics: std::collections::BTreeMap<String, f64>,
}

impl ProcStatus {
    /// Ready iff the *state* says so. See [`Self::ready`] for why the
    /// producer-supplied boolean does not get a vote.
    pub fn is_ready(&self) -> bool {
        self.state.is_ready()
    }

    /// One-line rendering for an operator-facing note or log line.
    pub fn summary(&self) -> String {
        let mut s = format!("{:?}", self.state).to_lowercase();
        if let Some(detail) = &self.detail {
            s.push_str(" — ");
            s.push_str(detail);
        }
        if let Some(v) = &self.version {
            s.push_str(&format!(" (v{v})"));
        }
        s
    }
}

/// Where to ask for the status document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEndpoint {
    /// Newline-JSON over a unix domain socket — the dev-tier default.
    Socket(PathBuf),
    /// `GET <url>` returning the status document — for a process that already
    /// serves HTTP, including every cloud-tier workload.
    Http(String),
}

impl std::fmt::Display for ControlEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlEndpoint::Socket(p) => write!(f, "unix:{}", p.display()),
            ControlEndpoint::Http(u) => write!(f, "{u}"),
        }
    }
}

/// Ask a process for its status document once.
///
/// Errors mean *unreachable or unparseable*, which is not the same as
/// unhealthy: a process that has not yet bound its socket is indistinguishable
/// here from one that never will. Callers deciding readiness should poll with
/// [`wait_ready`] rather than treating one error as a verdict.
pub async fn fetch_status(endpoint: &ControlEndpoint) -> anyhow::Result<ProcStatus> {
    match endpoint {
        #[cfg(unix)]
        ControlEndpoint::Socket(path) => fetch_status_uds(path).await,
        // R918-F5 — the dev-tier transport is a unix domain socket, and tokio
        // exposes `UnixStream` on unix only (Windows 10+ has AF_UNIX; tokio
        // does not surface it). A non-unix `yah` is a *client* — it talks to a
        // camp and submits builds rather than supervising workloads — so no
        // producer it can reach binds one of these. Reporting the endpoint as
        // unreachable is this function's documented vocabulary for exactly
        // that; inventing a named-pipe transport here would change a wire
        // contract no producer speaks.
        #[cfg(not(unix))]
        ControlEndpoint::Socket(path) => anyhow::bail!(
            "control socket {} is unreachable: the newline-JSON unix-socket transport is \
             unix-only and this is a non-unix build",
            path.display()
        ),
        ControlEndpoint::Http(url) => {
            let body = reqwest::Client::new()
                .get(url)
                .timeout(Duration::from_secs(2))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            Ok(serde_json::from_str(&body)?)
        }
    }
}

/// Newline-JSON round trip: write one request line, read one response line.
///
/// The connection is not reused. A status poll happens every few seconds at
/// most, and a per-call connection means a wedged reader on the producer side
/// cannot poison later polls — worth far more here than the syscalls saved.
#[cfg(unix)]
async fn fetch_status_uds(path: &std::path::Path) -> anyhow::Result<ProcStatus> {
    let mut stream = tokio::net::UnixStream::connect(path).await?;
    stream.write_all(b"{\"cmd\":\"status\"}\n").await?;
    stream.flush().await?;

    let mut line = String::new();
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        BufReader::new(stream).read_line(&mut line),
    )
    .await
    .map_err(|_| anyhow::anyhow!("control socket {} did not answer within 2s", path.display()))??;
    if read == 0 {
        anyhow::bail!(
            "control socket {} closed without answering",
            path.display()
        );
    }
    Ok(serde_json::from_str(line.trim())?)
}

/// Outcome of waiting for a process to report itself ready.
#[derive(Debug)]
pub enum ReadyOutcome {
    /// The process reported [`ProcState::Running`].
    Ready(ProcStatus),
    /// The process reported a terminal state — it is not coming up. Failing
    /// here rather than burning the whole timeout is the practical difference
    /// between a five-second and a twenty-second edit loop.
    Terminal(ProcStatus),
    /// The deadline passed. `last` is the most recent document read, or `None`
    /// when the endpoint never answered at all — a distinction worth keeping
    /// in the error message, since "never bound its socket" and "stuck in
    /// starting" are different bugs with different fixes.
    TimedOut { last: Option<ProcStatus> },
}

/// Poll `endpoint` until the process reports ready, reports terminal, or the
/// timeout expires.
pub async fn wait_ready(endpoint: &ControlEndpoint, timeout: Duration) -> ReadyOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last: Option<ProcStatus> = None;
    loop {
        if let Ok(status) = fetch_status(endpoint).await {
            if status.is_ready() {
                return ReadyOutcome::Ready(status);
            }
            if status.state.is_terminal() {
                return ReadyOutcome::Terminal(status);
            }
            last = Some(status);
        }
        if tokio::time::Instant::now() >= deadline {
            return ReadyOutcome::TimedOut { last };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Minimal conforming producer: accept, read a line, answer one document.
    /// This is also the reference for how little a workload has to implement.
    ///
    /// R918-F5 — unix-only alongside the transport it exercises.
    #[cfg(unix)]
    fn serve_once(path: PathBuf, docs: Vec<String>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            for doc in docs {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (read_half, mut write_half) = stream.into_split();
                let mut line = String::new();
                BufReader::new(read_half).read_line(&mut line).await.ok();
                write_half.write_all(doc.as_bytes()).await.ok();
                write_half.write_all(b"\n").await.ok();
                write_half.flush().await.ok();
            }
        })
    }

    #[test]
    fn the_state_vocabulary_matches_kamajis_workload_state_on_the_wire() {
        // If this ever drifts, a workload's own report can no longer be handed
        // to the supervisor verbatim — which is the entire compatibility claim
        // this module makes.
        for (state, wire) in [
            (ProcState::Pending, "\"pending\""),
            (ProcState::Starting, "\"starting\""),
            (ProcState::Running, "\"running\""),
            (ProcState::Draining, "\"draining\""),
            (ProcState::Exited, "\"exited\""),
            (ProcState::Failed, "\"failed\""),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), wire);
            assert_eq!(
                serde_json::from_str::<ProcState>(wire).unwrap(),
                state,
                "{wire} must round-trip"
            );
        }
    }

    #[test]
    fn state_is_the_only_required_field() {
        let s: ProcStatus = serde_json::from_str(r#"{"state":"running"}"#).unwrap();
        assert!(s.is_ready());
        assert_eq!(s.pid, None);
        assert!(s.endpoints.is_empty());
        assert!(s.metrics.is_empty());
    }

    #[test]
    fn a_full_document_parses() {
        let s: ProcStatus = serde_json::from_str(
            r#"{"state":"starting","ready":false,"pid":71455,"uptime_secs":41,
                "version":"0.8.20","detail":"replaying WAL 3/7",
                "endpoints":{"gui":"winit://main"},"metrics":{"fps":59.9}}"#,
        )
        .unwrap();
        assert_eq!(s.state, ProcState::Starting);
        assert!(!s.is_ready(), "starting is not ready");
        assert_eq!(s.pid, Some(71455));
        assert_eq!(s.detail.as_deref(), Some("replaying WAL 3/7"));
        assert_eq!(s.endpoints.get("gui").map(String::as_str), Some("winit://main"));
        assert_eq!(s.metrics.get("fps"), Some(&59.9));
        assert_eq!(s.summary(), "starting — replaying WAL 3/7 (v0.8.20)");
    }

    /// A producer that contradicts itself must not be believed on the
    /// optimistic half — that is precisely how a half-booted process gets
    /// reported as up, which is the failure this channel exists to end.
    #[test]
    fn a_ready_flag_never_overrides_a_not_running_state() {
        let s: ProcStatus =
            serde_json::from_str(r#"{"state":"starting","ready":true}"#).unwrap();
        assert_eq!(s.ready, Some(true), "the claim is preserved verbatim");
        assert!(!s.is_ready(), "but state decides");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fetch_status_reads_a_document_over_a_unix_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_once(
            sock.clone(),
            vec![r#"{"state":"running","detail":"3 windows"}"#.to_string()],
        );
        // Give the listener a moment to bind.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let got = fetch_status(&ControlEndpoint::Socket(sock)).await.unwrap();
        assert_eq!(got.state, ProcState::Running);
        assert_eq!(got.detail.as_deref(), Some("3 windows"));
        server.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wait_ready_polls_through_starting_to_running() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_once(
            sock.clone(),
            vec![
                r#"{"state":"starting"}"#.to_string(),
                r#"{"state":"starting"}"#.to_string(),
                r#"{"state":"running"}"#.to_string(),
            ],
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        let outcome = wait_ready(&ControlEndpoint::Socket(sock), Duration::from_secs(5)).await;
        assert!(
            matches!(&outcome, ReadyOutcome::Ready(s) if s.state == ProcState::Running),
            "{outcome:?}"
        );
        server.abort();
    }

    /// `failed` must short-circuit. Burning the full readiness timeout on a
    /// process that has already said it is not coming up is the slow-edit-loop
    /// failure this outcome exists to prevent.
    #[cfg(unix)]
    #[tokio::test]
    async fn wait_ready_fails_fast_on_a_terminal_state() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_once(
            sock.clone(),
            vec![r#"{"state":"failed","detail":"no GPU"}"#.to_string()],
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        let started = std::time::Instant::now();
        let outcome = wait_ready(&ControlEndpoint::Socket(sock), Duration::from_secs(30)).await;
        assert!(
            matches!(&outcome, ReadyOutcome::Terminal(s) if s.detail.as_deref() == Some("no GPU")),
            "{outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must not burn the 30s timeout on a terminal state"
        );
        server.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wait_ready_times_out_when_nothing_is_listening() {
        let tmp = tempfile::tempdir().unwrap();
        let outcome = wait_ready(
            &ControlEndpoint::Socket(tmp.path().join("never-bound.sock")),
            Duration::from_millis(300),
        )
        .await;
        assert!(
            matches!(outcome, ReadyOutcome::TimedOut { last: None }),
            "an endpoint that never answered must report no last document"
        );
    }

    #[test]
    fn endpoints_render_distinguishably() {
        assert_eq!(
            ControlEndpoint::Socket(PathBuf::from("/tmp/c.sock")).to_string(),
            "unix:/tmp/c.sock"
        );
        assert_eq!(
            ControlEndpoint::Http("http://127.0.0.1:4325/_yah/status".into()).to_string(),
            "http://127.0.0.1:4325/_yah/status"
        );
    }

    #[test]
    fn a_status_document_round_trips_through_serialization() {
        let mut endpoints = BTreeMap::new();
        endpoints.insert("http".to_string(), "http://127.0.0.1:4325".to_string());
        let original = ProcStatus {
            state: ProcState::Running,
            ready: None,
            pid: Some(9),
            uptime_secs: Some(3),
            version: None,
            detail: None,
            endpoints,
            metrics: BTreeMap::new(),
        };
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(serde_json::from_str::<ProcStatus>(&json).unwrap(), original);
        assert!(
            !json.contains("\"ready\""),
            "absent optionals must not be emitted: {json}"
        );
    }
}
