//! `[providers.compute] kind = "local-process"` — run a service's own compute
//! component as a **kamaji-supervised host process** at the dev tier.
//!
//! ## Why this exists
//!
//! A component's `kind` says what the service *is*; the mirror's provider slot
//! says how *this tier* runs it. That split already exists for storage —
//! `mesofact-static` runs off `local-static` (files on disk) at dev and
//! `miniflare-container` (containers) at pond, one component kind, two
//! runtimes — and this is the same split for compute. A `kind = "container"`
//! component now runs natively at dev and in docker at pond without the
//! service declaring itself twice.
//!
//! The alternative — a `local-process` *component kind* — was rejected: it
//! would make the artifact shape a property of the service rather than of the
//! tier, which is exactly the fork that W265 exists to prevent.
//!
//! ## Why not just run the container at dev
//!
//! Because a container is a different filesystem, and at the dev tier that is
//! a lie you have to maintain. yah-cloud-admin is the worked example: it reads
//! `.yah/infra/machines/*.toml`, so its dev container has to bind-mount
//! `.yah/infra` read-only into `/workspace/.yah/infra` and override
//! `YAH_CLOUD_ADMIN_WORKSPACE_ROOT` to find it (see
//! `crates/yah/cloud-admin/workload.toml`). Get the mount wrong and the
//! service comes up *running, healthy, and describing a fleet of zero
//! machines*. A host process inherits the operator's actual workspace and the
//! whole class of failure disappears — along with a docker build per edit.
//!
//! ## Config
//!
//! The mirror opts in:
//!
//! ```toml
//! # .yah/services/<svc>/mirrors/dev.toml
//! shape = "local"
//!
//! [providers.compute]
//! kind = "local-process"
//! ```
//!
//! and the component's `workload.toml` describes the process:
//!
//! ```toml
//! [process]
//! # Cargo package to build before spawning. Omit for a prebuilt binary.
//! cargo_package = "yah-cloud-admin"
//! # Binary to exec, relative to the workspace root. Defaults to
//! # target/<profile>/<cargo_package>.
//! bin = "target/debug/yah-cloud-admin"
//! # Extra argv after the binary.
//! args = []
//! # Port the process listens on. OPTIONAL. When present it is the readiness
//! # signal and the mirror's `dev_url`. Omit it for a process that never
//! # listens — a native GUI, a daemon on a unix socket, a batch loop — and
//! # readiness falls back to "still alive after a short grace window",
//! # with no `dev_url` for the Run tab to open.
//! port = 4325
//!
//! [process.env]
//! YAH_CLOUD_ADMIN_ADDR = "127.0.0.1:4325"
//! ```
//!
//! ## Per-mirror `profile` override, and non-cargo builds
//!
//! `workload.toml` is one file shared by every mirror bound to this slot, so
//! `profile` can be overridden per mirror — the only field that can, since
//! it's the only one where two tiers of the *same* component legitimately
//! want different values (a debug dev loop next to a release build, both
//! pointed at the same `[process]` block):
//!
//! ```toml
//! # .yah/services/<svc>/mirrors/release.toml
//! shape = "local"
//!
//! [providers.compute]
//! kind = "local-process"
//! profile = "release"
//! ```
//!
//! For a component with no runnable top-level binary from a plain
//! `cargo build -p pkg` — a native macOS/iOS app, where Rust only supplies a
//! static lib for Xcode to link — `pre_build` replaces `cargo_package`
//! entirely: an operator-authored argv (same trust model as `compose.rs`'s
//! post-write shell commands, R592-T2) run in `workspace_root` before `bin`
//! is resolved, streamed into the Run tab's log tail exactly like a cargo
//! build:
//!
//! ```toml
//! [process]
//! pre_build = ["./build-dist.sh", "arm64", "--sign"]
//! bin = "app/macos/dist/NoiseTable.app/Contents/MacOS/NoiseTable"
//! ```
//!
//! ## Portless components
//!
//! A process with no TCP listener is a first-class case, not a degenerate
//! one: noisetable's desktop dev loop is a winit window with zero network
//! surface. Do not paper over the gap by declaring a port the process never
//! binds — that trips the readiness timeout below and tears down a perfectly
//! healthy child, or (worse) adopts an unrelated listener that happens to
//! answer. Omit `port` and the Run tab renders the row as a log-tail plus
//! stop card instead of an iframe.
//!
//! ## …and what a portless component SHOULD do instead
//!
//! Dropping the port drops the only structured thing the supervisor knew
//! about the process, which leaves log-grepping — for an operator and, worse,
//! for an agent. So the house default for anything long-running is the
//! **process-control channel** ([`crate::proc_control`]): a unix socket
//! speaking one verb, `status`, answering with a document whose `state` uses
//! kamaji's own `WorkloadState` vocabulary.
//!
//! ```toml
//! [process]
//! cargo_package = "dev"
//! # no `port` — a winit window has nothing to bind
//!
//! [process.control]
//! # nothing to configure: the socket path arrives as $YAH_CONTROL_SOCK
//! ```
//!
//! With it, readiness stops being a guess: the process says `starting` while
//! it loads and `running` when it is up, and an agent can ask what it is
//! doing instead of parsing sentences out of stdout. A component that already
//! serves HTTP declares `http_path` instead and shares one endpoint with the
//! cloud tier's `Healthcheck`. The channel is optional — a process that
//! declines it still runs, on liveness alone.
//!
//! @yah:relay(R715, "local-process compute provider: a dev tier that runs the binary, not a container")
//! @yah:at(2026-08-03T22:21:13Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("T1 (landed): LocalProcessReconciler + Provider::LocalProcess + native_support dedup + both dispatchers + the yah-cloud-admin dev/pond split. See the T1 handoff.")
//! @yah:next("Follow-on: mesofact-dev's local-static arm and this reconciler now differ only in argv construction. W265 already plans to retire local-static when local-s3-fs lands - that is the moment to consider collapsing them.")
//! @yah:next("Follow-on: the desktop mirror_run_up has no adopt-probe for local-process the way it does for mesofact-dev. Correct today because the reconciler reaps its predecessor, but an adopt path would let a re-click return the running URL without a rebuild.")
//! @yah:gotcha("Naming rule this relay encodes, from the operator: if it runs in a container it is pond. Dev is the tier that runs against the operator's real filesystem. No service is required to have all three tiers - a service whose lowest tier is pond is fine.")
//! @yah:gotcha("The runtime is a property of the MIRROR, not the component. A kind=container component runs natively at dev and in docker at pond, selected by the mirror's compute slot - the same split mesofact-static already had via providers.static (local-static at dev, miniflare-container at pond). Do NOT add a local-process COMPONENT kind: that makes artifact shape a property of the service and reintroduces the per-tier fork W265 exists to prevent.")
//! @arch:see(.yah/docs/working/W265-service-capabilities-and-drivers.md)
//!
//! @yah:ticket(R715-T1, "LocalProcessReconciler + Provider::LocalProcess, wired into both dispatchers; yah-cloud-admin dev/pond split")
//! @yah:status(review)
//! @yah:at(2026-08-05T04:54:16Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P1)
//! @yah:parent(R715)
//! @yah:next("R714-B1 (stop button no-ops on container mirrors) and R714-B2 (tier chip prints 'axum') were found during this work and filed separately - they predate it and are not regressions from it.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib - 688 passed, 0 failed")
//! @yah:verify("cargo test -p yah --lib cloud:: - 108 passed")
//! @yah:verify("cargo test -p xtask --test schema_drift --test workload_envelope - 4 passed")
//! @yah:verify("MANUAL (done): yah cloud mirror up yah-cloud-admin --env dev binds 127.0.0.1:4325 with no container, and the process logs workspace=/Users/leif/ss/yah - the real checkout, not /workspace")
//! @yah:verify("MANUAL (done): running mirror up twice in a row replaces the child (pid changes) instead of leaving a dead second instance behind an Address-already-in-use")
//! @yah:gotcha("NativeRuntime's workload table is IN-MEMORY, so a second `mirror up` from a fresh process cannot see the first one's child. Without the owner.json sidecar + reap the new child dies on Address-already-in-use, wait_for_port sees the OLD listener answering, and the reconcile reports success while the just-edited binary is not what is running. This was observed live before the fix, not theorised. Do not remove the sidecar.")
//! @yah:gotcha("yah-cloud-admin's pond tier moved to host port 4326 so both tiers can run at once. The container still listens on 4325 internally.")
//! @yah:next("RESOLVED (R715-T1, 2026-08-04): the cloud.toml blocker comment was corrected by the peer whose uncommitted edits blocked it - lines 34-60 now carry the 2026-08-03 status (published image DONE, workload declaration DONE, cheers key STILL BLOCKED on both an issuer and a 0.8.21 yubaba roll). Nothing left to do there.")
//! @yah:handoff("Re-verified independently on 2026-08-04 (session:5fe4274e, rune) rather than trusting the prior run's claims. All three automated suites green; counts are HIGHER than the ones recorded above because peers added tests since: yah-cloud lib 698 passed / 0 failed (was 688), yah lib cloud:: 111 passed (was 108), xtask schema_drift + workload_envelope 4 passed (unchanged).")
//! @yah:verify("RE-VERIFIED 2026-08-04, sidecar survives across sessions: the owner.json left by the 2026-08-03 run ({pid:54869,port:4325}) still matched the live listener a day later - lsof -t on 4325 returned exactly 54869. That is the cross-process ownership link working in the wild, not in a test.")
//! @yah:verify("RE-VERIFIED 2026-08-04, reap-and-replace: `cargo run -p yah -- cloud mirror up yah-cloud-admin --env dev` reaped pid 54869 (kill -0 confirms gone), spawned 71455, rewrote owner.json to {pid:71455,port:4325}, and 127.0.0.1:4325/ answers HTTP 200. No dead second instance, no Address-already-in-use.")
//! @yah:verify("RE-VERIFIED 2026-08-04, the failure mode this tier exists to prevent: child cwd is /Users/leif/ss/yah (lsof -d cwd), `docker ps` shows NO cloud-admin container, and /partial/machines renders 9 machine rows against 9 files in .yah/infra/machines/ - us-west-001/002/003 + mac-builder among them. Not a fleet of zero.")
//! @yah:verify("RE-VERIFIED 2026-08-04, both dispatcher arms compile: `cargo build -p yah` (app/yah/cli/src/cloud.rs:4705) and `cargo check -p desktop --lib` (app/yah/desktop/src/mirror_run.rs:624) are both clean.")
//! @yah:gotcha("LEFT RUNNING: the re-verification above spawned yah-cloud-admin pid 71455 on 127.0.0.1:4325 and did not stop it - that matches the state found at session start (a dev-tier process was already up). Kill it with `kill $(lsof -nP -iTCP:4325 -sTCP:LISTEN -t)`, or just re-run `mirror up`, which reaps it.")
//! @yah:gotcha("TRANSIENT, NOT THIS TICKET: `cargo run -p yah` failed once with E0599 mid-verification and compiled clean on immediate retry with no edit from this session - a peer's in-flight change on the shared tree. Same shape as the note in crates/yah/camp-service/tests/e2e.rs:35. If you see it, retry before investigating.")
//!
//! @yah:ticket(R715-T2, "Portless `local-process` compute slot — Run tab support for native GUI processes with no TCP listener")
//! @yah:status(review)
//! @yah:at(2026-08-14T21:27:45Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R715)
//! @yah:next("Make `[process].port` optional in `ProcessSpec` (this file). When absent, readiness = process spawned and still alive after a short grace window, instead of `wait_for_port`; the `up()` path returns `dev_url = None` to `into_running(...)` (RunningWorkload's dev_url is already `Option`, so this is a narrowing of ProcessSpec, not a new field anywhere downstream).")
//! @yah:next("Mirror the same required->optional change for `port` on `run.spawn`'s schema and `SpawnArgs` (crates/yah/agent-tools/src/run_tools.rs) so an agent can supervise a portless process through the same tool used for app servers.")
//! @yah:next("Run tab: a mirror/spawn with no dev_url should render as a log-tail + kill/restart card, no iframe, no URL bar — this is the `stdio` process row A046 (.yah/docs/architecture/A046-yah-run-tab.md) already sketches (`yah-rig (noise) stdio pid 4598 ... [logs] [kill]`) but neither shipped mechanism implements.")
//! @yah:next("Real external consumer blocked on this today: noisetable's desktop dev loop (`cargo run -p dev` / `cargo run --release -p dev`, a winit native GUI window with zero network surface — no port to bind, ever). Full writeup + the service.toml/mirror.toml/workload.toml shape noisetable wants to declare once this lands: entambi repo, .yah/docs/working/W145-desktop-dev-run-tab.md.")
//! @yah:gotcha("Do not let a consumer route around this by having the process bind a throwaway port it never uses for anything real — that just trips this reconciler's own `wait_for_port` timeout/teardown, or makes `run.spawn` poll a port that happens to be open for unrelated reasons. Both are worse than the honest gap. The fix belongs in this reconciler (and run_tools.rs), not in a consumer's workload.toml.")
//! @yah:assumes("Readiness-as-'process alive after N ms grace window' is assumed to be an acceptable v1 fallback (matches what a bare `[kill]`-only scoreboard row needs). A richer readiness probe (e.g. an optional stdout regex match) would be nicer but isn't required to unblock the noisetable use case named above — confirm with whoever picks this up whether the simple version is sufficient, or whether R322-F4's LivePanel / RunStatePanel state model expects something richer for a 'ready' vs 'starting' distinction on portless rows.")
//! @arch:see(.yah/docs/working/W265-service-capabilities-and-drivers.md)
//! @arch:see(.yah/docs/architecture/A046-yah-run-tab.md)
//! @arch:see(crates/yah/agent-tools/src/run_tools.rs)
//! @yah:handoff("[process].port is now Option<u16> in the local-process reconciler. A portless component skips the port-contention check and wait_for_port; readiness falls back to ALIVE_GRACE (750ms) + pid_alive, dev_url is None, and OwnerRecord.port became Option<u16> with a serde default so sidecars written before this still parse (tested).")
//! @yah:handoff("run.spawn: SpawnArgs.port is Option<u16> and the JSON schema no longer requires it; the wire still encodes portless as 0. The camp daemon's run_spawn_handler applies the same 750ms grace and fails the spawn with a log tail when a portless child exits immediately - it previously registered a healthy scoreboard row over a corpse. rpc::RunSpawnParams.port's doc claimed 0 meant OS-assigned, which the handler never did; corrected to say portless.")
//! @yah:handoff("Run tab: MirrorPanel's running-with-no-dev_url state was the placeholder reading 'paste a local URL to preview it here' - advice that cannot be followed for a process that will never have one. Replaced with PortlessCard (host-process chip, what it is, pointer to the log panel and Stop, plus whatever the process reported). LivePanel's port column reads 'stdio' for a portless mirror or spawn and keeps the dash for task runs, via an exported transportLabel with 6 tests.")
//! @yah:handoff("SCOPE ADDED MID-TICKET, at the operator's direction: the process-control channel. Dropping the port drops the only structured signal a supervisor had, leaving log-grepping - so portless is now paired with an opinionated default that anything long-running SHOULD expose. New module oss/yubaba/crates/cloud/src/proc_control.rs (client + wire types), new optional [process.control] in the reconciler, and W315-process-control-channel.md as the canon. Phase 2 filed as R715-F3.")
//! @yah:handoff("The contract: one verb, `status`, over newline-JSON on a unix socket (path handed down as $YAH_CONTROL_SOCK) or GET /_yah/status for anything already serving HTTP - same document, two transports, so the cloud tier's Healthcheck{Http} probes the same endpoint the dev tier reads over a socket. `state` is the only required field and its vocabulary is EXACTLY kamaji_proto::WorkloadState, which is the whole compatibility claim: a workload's own report can be handed to the supervisor verbatim. Pinned by a test that fails if either side drifts.")
//! @yah:handoff("Readiness in the reconciler is now a ladder: control channel > port bind > alive-after-grace. A declared channel supersedes the port because a bound port says nothing about whether the thing behind it finished booting, and a terminal state (failed/exited) short-circuits instead of burning the 20s timeout.")
//! @yah:handoff("DISCOVERED AND FIXED, wider than the ticket: RunningWorkloadSummary dropped RunningWorkload.notes, so every operator-facing note a reconciler attached since R546-B12 was written into a struct nobody read. Added the field (+ TS type, + three desktop construction sites in mirror_observation.rs). It is what carries the process's own status line to the Run tab.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib - 830 passed / 0 failed (827 before the last batch). 20 in local_process, 10 in proc_control.")
//! @yah:verify("END-TO-END, not just unit: three tests drive the real reconciler through kamaji's native backend against a temp workspace. a_portless_component_comes_up_with_no_dev_url spawns /bin/sleep with no port and asserts dev_url None, the liveness-only note, and an owner.json whose port is ABSENT rather than a placeholder zero. a_portless_component_that_exits_immediately_fails_the_reconcile runs /usr/bin/false and asserts the bring-up fails. a_control_channel_decides_readiness_when_declared holds the component at not-ready through a `starting` document and passes on `running`.")
//! @yah:verify("cargo test -p yah-agent-tools --lib run_tools - 14 passed (was 12; +2 for the optional port).")
//! @yah:verify("packages/yah/ui - bun run typecheck clean, bun run build clean, bun test src/components/run/ 111 passed / 0 failed.")
//! @yah:verify("Full bun test 1717 pass / 14 fail / 8 errors. Identical failure counts to what R714-B2 recorded, and the failing names are the same pre-existing four files (StatusPill, dispatchNav, first-run, truncateArg) - no regression from this ticket.")
//! @yah:verify("cargo check -p yah, cargo check -p desktop --lib, cargo test -p xtask --test schema_drift (3 passed) - all clean.")
//! @yah:verify("NOT RUN: any manual desktop check. Nobody has looked at the rendered PortlessCard or the stdio transport chip in a running app - there is no portless service declared in this camp to bring up. The e2e reconciler tests cover the backend claim; the two UI changes are covered by tests and typecheck only.")
//! @yah:gotcha("PRE-EXISTING RED GATE, not from this ticket: `cargo test -p xtask --test workload_envelope` fails on app/yah/web/chat/workload.toml and oss/mesofact/examples/hello/workload.toml, both `missing field routes`. That is R658-B1's known bug (routes written after [build], so TOML scopes it into build.routes) spread to two more files that were never added to KNOWN_GAPS. Both files are committed and untouched by this ticket. Deliberately NOT pinned into KNOWN_GAPS - silently widening the pin is what R658-B1 exists to stop; noted on that ticket instead.")
//! @yah:gotcha("The reconciler unlinks the control socket path before spawning, because a leftover socket file makes bind fail with EADDRINUSE even with nobody listening. Consequence for anyone writing a test: a producer that binds BEFORE up() has its socket deleted out from under it. Bind after, which is the order a real child sees anyway.")
//! @yah:gotcha("RESOLVED 2026-08-18 by R658-B1 (@Ashguard:libra): the red gate this ticket's gotcha flagged is now GREEN. app/yah/web/chat/workload.toml and oss/mesofact/examples/hello/workload.toml were migrated to put routes ABOVE [build], along with the other four files and the yah cloud site init scaffold. workload_spec::BuildConfig now carries serde(deny_unknown_fields) so the misplacement is a parse error naming routes. cargo test -p xtask --test workload_envelope passes. Nothing was pinned into KNOWN_GAPS - the four missing-field-routes entries were DELETED. No action needed here; this note exists so the gotcha is not read as still-true.")

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use kamaji::native::NativeRuntime;
use kamaji::{Kamaji, MeshAssignment, MeshIdent};
use serde::Deserialize;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tracing::{info, warn};
use workload_spec::EnvVar;
use workload_spec::MeshExpose;

use super::native_support::{
    capture_paths, native_spec, sanitize_ident, spawn_native_log_supervisor,
};
use super::{
    into_running, wait_for_port, LogBuffer, PhaseCursor, ReconcileCtx, Reconciler, RunningWorkload,
};
use crate::proc_control::{self, ControlEndpoint, ReadyOutcome};
use crate::{MirrorProviderSlot, MirrorShape, Provider};

/// The slot role a natively-run compute component occupies on its mirror.
const SLOT: &str = "compute";

/// How long to wait for the process to bind its declared port before calling
/// the reconcile failed. Generous because the first `cargo build` of a cold
/// target dir is included in the caller's patience, not in this window — the
/// build finishes before the spawn.
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Readiness window for a component with no declared port: if the child is
/// still alive this long after `deploy_workload` returned, call it up.
///
/// This is deliberately not a health check — a portless process has no
/// surface to check. What it catches is the common failure the operator
/// would otherwise see as a green row and an empty window: a binary that
/// execs and dies immediately (missing dylib, bad argv, panic at startup).
/// Anything that fails later shows up in the log tail, which is the only
/// signal a portless process has.
const ALIVE_GRACE: Duration = Duration::from_millis(750);

/// True when `mirror` binds its compute slot to `local-process`. This is the
/// dispatch predicate — callers use it to choose this reconciler over the
/// container one for the same component kind.
pub fn slot_declared(mirror: &crate::MirrorConfig) -> bool {
    matches!(
        mirror.providers.get(SLOT),
        Some(MirrorProviderSlot::Inline {
            kind: Provider::LocalProcess,
            ..
        })
    )
}

/// `profile` from this mirror's `[providers.compute]` inline extra fields, if
/// declared — the per-mirror override described on [`ProcessSpec::pre_build`]
/// above `up()`. `None` for a `Reference` slot or an `Inline` slot with no
/// `profile` key, both of which fall back to `workload.toml`'s own value.
fn mirror_profile_override(mirror: &crate::MirrorConfig) -> Option<String> {
    match mirror.providers.get(SLOT) {
        Some(MirrorProviderSlot::Inline { fields, .. }) => fields
            .get("profile")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        _ => None,
    }
}

/// Reconciler for components bound to a `local-process` compute slot.
#[derive(Debug, Default)]
pub struct LocalProcessReconciler {
    /// External sink to stream build+run output into, in place of the
    /// private buffer `up()` would otherwise create. Lets a caller register
    /// the buffer for polling BEFORE calling `up()`, so a slow `cargo build`
    /// is visible to a poller while the reconcile is still in flight rather
    /// than only after `up()` returns.
    log_buf: Option<LogBuffer>,
    /// Published the moment the build phase finishes (before readiness/spawn
    /// even starts), so a caller polling an in-flight `up()` can render a
    /// build→run transition live instead of only learning about it from the
    /// finished [`RunningWorkload::build_log_end`].
    build_log_end_sink: Option<PhaseCursor>,
}

impl LocalProcessReconciler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stream into a caller-owned [`LogBuffer`] instead of a private one.
    pub fn with_log_buf(mut self, log_buf: LogBuffer) -> Self {
        self.log_buf = Some(log_buf);
        self
    }

    /// Publish the build→run boundary into a caller-owned [`PhaseCursor`] as
    /// soon as it's known, rather than only once `up()` returns it.
    pub fn with_build_log_end_sink(mut self, sink: PhaseCursor) -> Self {
        self.build_log_end_sink = Some(sink);
        self
    }
}

/// On-disk `workload.toml` shape — only the `[process]` section is read here.
/// Other sections (`[build]`, `[run]`) belong to the container reconciler and
/// are ignored, so one component file can describe both tiers.
#[derive(Debug, Default, Deserialize)]
struct ProcessComponent {
    #[serde(default)]
    process: Option<ProcessSpec>,
}

#[derive(Debug, Deserialize)]
struct ProcessSpec {
    /// Argv of an operator-authored command to run before `cargo_package`'s
    /// build (or standalone, when there is no `cargo_package` — e.g. a native
    /// macOS/iOS component where the runnable artifact comes out of
    /// `xcodebuild`, not `cargo build -p`, and Rust only supplies a static
    /// lib for Xcode to link). Runs in `workspace_root`, streamed into
    /// `log_buf` exactly like `cargo_build`, via the same [`run_streaming`].
    /// Same trust model as `compose.rs`'s post-write shell commands (R592-T2:
    /// operator-authored, not attacker input) — this is TOML the operator
    /// wrote, not a request body.
    #[serde(default)]
    pre_build: Option<Vec<String>>,
    /// Cargo package to `cargo build -p` before spawning. `None` → the binary
    /// is expected to already exist.
    #[serde(default)]
    cargo_package: Option<String>,
    /// Binary path relative to the workspace root (absolute taken as-is).
    /// `None` → `target/<profile>/<cargo_package>`.
    #[serde(default)]
    bin: Option<String>,
    /// Extra argv appended after the binary.
    #[serde(default)]
    args: Vec<String>,
    /// Port the process listens on. Optional: when set it is both the
    /// readiness signal and the `dev_url`; when absent the component is
    /// portless (native GUI, unix socket, batch loop) and readiness falls
    /// back to [`ALIVE_GRACE`].
    #[serde(default)]
    port: Option<u16>,
    /// Environment for the child.
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Cargo profile used for both the build and the default binary path.
    #[serde(default = "default_profile")]
    profile: String,
    /// Opt in to the process-control channel ([`crate::proc_control`]) — the
    /// house default for anything long-running. When present, the process's
    /// own report decides readiness, which is strictly better than both other
    /// signals: a bound port says nothing about whether the thing behind it
    /// has finished booting, and a live pid says nothing at all.
    #[serde(default)]
    control: Option<ControlSpec>,
}

/// `[process.control]` — where to ask the process how it is doing.
///
/// Both fields optional and mutually exclusive in practice: give `http_path`
/// for a process that already serves HTTP (it then shares an endpoint with
/// the cloud tier's healthcheck), otherwise the channel is a unix socket
/// whose path this reconciler chooses and passes down as `$YAH_CONTROL_SOCK`.
#[derive(Debug, Default, Deserialize)]
struct ControlSpec {
    /// Override the supervisor-chosen socket path. Rarely needed — a process
    /// that reads `$YAH_CONTROL_SOCK` needs nothing here.
    #[serde(default)]
    socket: Option<String>,
    /// Serve the status document over HTTP at this path instead, against the
    /// component's declared `port`. Defaults to
    /// [`proc_control::DEFAULT_HTTP_PATH`] when set to an empty string.
    #[serde(default)]
    http_path: Option<String>,
}

fn default_profile() -> String {
    "debug".to_string()
}

#[async_trait]
impl Reconciler for LocalProcessReconciler {
    fn kind(&self) -> &'static str {
        "local-process"
    }

    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        ctx.materialize().await?;

        // A host process is the operator's own machine by definition. Refusing
        // non-local shapes here keeps a `local-process` slot from silently
        // meaning "run it on my laptop" in a mirror that describes a fleet.
        if !matches!(ctx.mirror.shape, MirrorShape::Local) {
            bail!(
                "component {}: `local-process` is a dev-tier compute slot — mirror shape is \
                 {:?}, not `local`. Deploy the cloud tier via `yah cloud workload deploy`.",
                ctx.component.id,
                ctx.mirror.shape,
            );
        }

        let mut spec = load_process_spec(&ctx)?;
        // A mirror can override `profile` (and only `profile` — everything
        // else about the process is one declaration shared by every tier)
        // via `[providers.compute]`'s inline extra fields, same pattern the
        // schema already documents for other inline provider kinds ("bucket,
        // zone, dns, …"). Without this, two mirrors pointing at the same
        // component's workload.toml (e.g. noisetable-desktop's dev + release
        // tiers) would be unable to build different profiles from one file.
        if let Some(profile) = mirror_profile_override(ctx.mirror) {
            spec.profile = profile;
        }

        // Created here, before the build, rather than down where the
        // supervisor is spawned: `cargo_build` streams into it live, and
        // `build_log_end` below records the cursor where build output stops
        // and the spawned process's own stdout/stderr begins. A caller-
        // supplied buffer (`with_log_buf`) is reused as-is so it can already
        // be registered for polling before this call started.
        let log_buf = self.log_buf.clone().unwrap_or_default();

        // Build first, if asked. Doing this before the port probe means a
        // compile error surfaces as a compile error, rather than as a bind
        // timeout on a binary that was never rebuilt. Streamed into
        // `log_buf` as it runs (not buffered until exit) so a slow or
        // failing build shows progress in the Run tab instead of going
        // silent until it's done — and, unlike the old `.output()` capture,
        // a *successful* build's output is no longer discarded outright.
        if let Some(argv) = &spec.pre_build {
            run_pre_build(ctx.workspace_root, argv, &log_buf).await?;
        }

        let mut build_log_end = None;
        if let Some(pkg) = &spec.cargo_package {
            cargo_build(ctx.workspace_root, pkg, &spec.profile, &log_buf).await?;
            let cursor = log_buf.cursor().await;
            build_log_end = Some(cursor);
            if let Some(sink) = &self.build_log_end_sink {
                sink.set(cursor).await;
            }
        }

        let bin = resolve_binary(&spec, ctx.workspace_root)?;

        // Kamaji's native backend captures stdio under this dir; scope it per
        // workspace so concurrent camps don't collide on the same ident.
        let state_dir = ctx.workspace_root.join(".yah/jit/native");
        let ident_str = sanitize_ident(&format!(
            "local-process-{}-{}-{}",
            ctx.service.name, ctx.env, ctx.component.id
        ));
        let ident = MeshIdent(ident_str.clone());

        // Replace any predecessor before spawning. `ContainerReconciler` has
        // the same semantics ("run clears any prior container of the same name
        // first"), and here it is load-bearing rather than tidy: NativeRuntime
        // keeps its workload table **in memory**, so a second `mirror up` from
        // a fresh process knows nothing about the first. Without this the new
        // child dies on `Address already in use`, `wait_for_port` sees the
        // *old* listener still answering, and the reconcile reports success
        // while the binary the operator just edited is not the one running.
        // That is the R602-B4 foreign-listener failure with a friendlier
        // disguise, and on the dev tier it is the single most costly thing
        // this reconciler could get wrong.
        let owner_path = state_dir.join(&ident_str).join("owner.json");
        reap_predecessor(&owner_path).await;

        // Anything still holding the port now is not ours. Refuse rather than
        // adopt it: a `dev_url` that answers with someone else's service is
        // worse than a failed bring-up. A portless component has no address to
        // contend over, so there is nothing to check.
        let addr = spec
            .port
            .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        if let Some(addr) = addr {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                bail!(
                    "component {}: {addr} is already held by a process this reconciler did not \
                     start. Stop it, or give [process] a different `port`.",
                    ctx.component.id,
                );
            }
        }

        let mut argv = vec![bin.display().to_string()];
        argv.extend(spec.args.iter().cloned());

        // Process-control channel. Resolved before the spawn because the
        // socket variant has to reach the child in its environment — a
        // conforming process binds `$YAH_CONTROL_SOCK` and does nothing when
        // it is unset, so the same binary runs outside a camp untouched.
        let control = control_endpoint(&spec, &state_dir, &ident_str);
        if let Some(ControlEndpoint::Socket(path)) = &control {
            // A socket file left by the predecessor makes `bind` fail with
            // EADDRINUSE even though nothing is listening on it. Reaping the
            // process does not remove it; unlinking here does.
            if let Some(dir) = path.parent() {
                tokio::fs::create_dir_all(dir).await.ok();
            }
            tokio::fs::remove_file(path).await.ok();
        }

        let mut env: Vec<EnvVar> = spec
            .env
            .iter()
            .map(|(name, value)| EnvVar {
                name: name.clone(),
                value: workload_spec::EnvValue::Literal {
                    value: value.clone(),
                },
            })
            .collect();
        if let Some(ControlEndpoint::Socket(path)) = &control {
            // Declared `[process.env]` wins: an operator who set the variable
            // by hand meant it.
            if !spec.env.contains_key(proc_control::CONTROL_SOCK_ENV) {
                env.push(EnvVar {
                    name: proc_control::CONTROL_SOCK_ENV.to_string(),
                    value: workload_spec::EnvValue::Literal {
                        value: path.display().to_string(),
                    },
                });
            }
        }

        let mut workload = native_spec(&ident_str, argv, env);
        // A declared `[process] port` reaches the child as `PORT` / `PORT_HTTP`
        // (R844-T13) by riding the spec, not by a per-caller string. Declared
        // `[process.env]` still wins — the native backend layers spec env last.
        // A portless component contributes nothing and gets neither variable.
        workload.expose.mesh.ports = MeshExpose::anonymous_ports(spec.port);
        let runtime = Arc::new(NativeRuntime::new(&state_dir));
        let mesh = MeshAssignment::inlined(Ipv4Addr::LOCALHOST);

        info!(
            binary = %bin.display(),
            port = ?spec.port,
            ident = %ident_str,
            "spawning local-process component (kamaji native backend)",
        );

        let deployed = runtime
            .deploy_workload(&workload, &mesh)
            .await
            .with_context(|| {
                format!(
                    "deploying component {} via kamaji native backend (binary {})",
                    ctx.component.id,
                    bin.display(),
                )
            })?;

        let (stdout_path, stderr_path) = capture_paths(&state_dir, &ident_str);

        // Record ownership so the *next* reconcile — in a different process,
        // with a different in-memory NativeRuntime — can find and reap this
        // child instead of colliding with it.
        write_owner(&owner_path, deployed.task_pid as i32, spec.port).await;

        // Readiness, best signal first.
        //
        // 1. The control channel, when declared: the process says when it is
        //    serving. Nothing else here can distinguish "bound" from "ready".
        // 2. The port bind: a dead process must not hand the Run tab a URL
        //    that will never answer.
        // 3. Still alive after a grace window: all a portless process that
        //    declines the channel can offer.
        let mut notes: Vec<String> = Vec::new();

        if let Some(endpoint) = &control {
            match proc_control::wait_ready(endpoint, READY_TIMEOUT).await {
                ReadyOutcome::Ready(status) => {
                    info!(
                        endpoint = %endpoint,
                        status = %status.summary(),
                        "local-process reported ready over its control channel",
                    );
                    notes.push(format!("control: {}", status.summary()));
                }
                ReadyOutcome::Terminal(status) => {
                    let tail = read_capture_tail(&stdout_path, &stderr_path).await;
                    runtime.teardown_workload(&ident).await.ok();
                    bail!(
                        "component {} reported `{}` on its control channel ({}){tail}",
                        ctx.component.id,
                        status.summary(),
                        endpoint,
                    );
                }
                ReadyOutcome::TimedOut { last } => {
                    let tail = read_capture_tail(&stdout_path, &stderr_path).await;
                    runtime.teardown_workload(&ident).await.ok();
                    let seen = match last {
                        Some(s) => format!("last reported `{}`", s.summary()),
                        None => "never answered — is it binding $YAH_CONTROL_SOCK?".to_string(),
                    };
                    bail!(
                        "component {} was not ready within {READY_TIMEOUT:?} on {endpoint} \
                         ({seen}){tail}",
                        ctx.component.id,
                    );
                }
            }
        }

        let dev_url = match addr {
            Some(addr) => {
                // Already ready per the control channel? Then the bind has
                // happened by definition, and re-waiting would only add
                // latency to a process that already said it is serving.
                if control.is_none() && !wait_for_port(addr, READY_TIMEOUT).await {
                    warn!(addr = %addr, "local-process did not bind within timeout; tearing down");
                    let tail = read_capture_tail(&stdout_path, &stderr_path).await;
                    runtime.teardown_workload(&ident).await.ok();
                    bail!(
                        "component {} did not bind {addr} within {READY_TIMEOUT:?}{tail}",
                        ctx.component.id,
                    );
                }
                Some(format!("http://{addr}"))
            }
            None => {
                if control.is_none() {
                    tokio::time::sleep(ALIVE_GRACE).await;
                    if !pid_alive(deployed.task_pid as i32) {
                        let tail = read_capture_tail(&stdout_path, &stderr_path).await;
                        runtime.teardown_workload(&ident).await.ok();
                        bail!(
                            "component {} (portless) exited within {ALIVE_GRACE:?} of \
                             starting{tail}",
                            ctx.component.id,
                        );
                    }
                    notes.push(
                        "portless with no [process.control] — readiness is liveness only; \
                         see yah-cloud's proc_control module"
                            .to_string(),
                    );
                }
                None
            }
        };
        info!(dev_url = ?dev_url, pid = deployed.task_pid, "local-process ready");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let supervisor = spawn_native_log_supervisor(
            runtime,
            ident,
            log_buf.clone(),
            stdout_path,
            stderr_path,
            shutdown_rx,
        );

        Ok(into_running(
            "local-process",
            SLOT,
            dev_url,
            None,
            Some(log_buf),
            shutdown_tx,
            supervisor,
        )
        .with_notes(notes)
        .with_control(control)
        .with_build_log_end(build_log_end))
    }
}

/// Resolve `[process.control]` into an endpoint to poll, or `None` when the
/// component declines the channel.
///
/// HTTP needs a port to hang off — a component asking for `http_path` without
/// a `port` has contradicted itself, and falling back to the socket silently
/// would hide that. It is reported as no endpoint at all rather than guessed
/// at; the caller then treats the process as unmonitored, which is the honest
/// reading of a self-contradicting declaration.
fn control_endpoint(
    spec: &ProcessSpec,
    state_dir: &std::path::Path,
    ident: &str,
) -> Option<ControlEndpoint> {
    let control = spec.control.as_ref()?;
    if let Some(path) = &control.http_path {
        let port = spec.port?;
        let path = if path.is_empty() {
            proc_control::DEFAULT_HTTP_PATH
        } else {
            path
        };
        return Some(ControlEndpoint::Http(format!(
            "http://127.0.0.1:{port}{path}"
        )));
    }
    let sock = match &control.socket {
        Some(s) => PathBuf::from(s),
        None => state_dir.join(ident).join("control.sock"),
    };
    Some(ControlEndpoint::Socket(sock))
}

/// Read `<workload_dir>/workload.toml` and pull out its `[process]` section.
fn load_process_spec(ctx: &ReconcileCtx<'_>) -> Result<ProcessSpec> {
    let path = ctx.workload_dir().join("workload.toml");
    let src =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let parsed: ProcessComponent =
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
    parsed.process.with_context(|| {
        format!(
            "component {} is bound to a `local-process` compute slot but {} declares no \
             [process] section — add one with at least `bin` or `cargo_package`",
            ctx.component.id,
            path.display(),
        )
    })
}

/// Resolve the binary to exec: explicit `bin`, else the cargo convention.
fn resolve_binary(spec: &ProcessSpec, workspace_root: &std::path::Path) -> Result<PathBuf> {
    let rel = match (&spec.bin, &spec.cargo_package) {
        (Some(bin), _) => PathBuf::from(bin),
        (None, Some(pkg)) => PathBuf::from(format!("target/{}/{pkg}", spec.profile)),
        (None, None) => bail!(
            "[process] declares neither `bin` nor `cargo_package` — one is needed to know \
             what to run"
        ),
    };
    let path = if rel.is_absolute() {
        rel
    } else {
        workspace_root.join(rel)
    };
    if !path.exists() {
        bail!(
            "[process] binary {} does not exist — set `cargo_package` to have it built, or \
             point `bin` at an existing file",
            path.display(),
        );
    }
    Ok(path)
}

/// Run `[process.pre_build]`'s argv to completion in `workspace_root`,
/// streamed live into `log_buf` via the same [`run_streaming`] `cargo_build`
/// uses. Runs before `cargo_package`'s build (if any) so a failing pre_build
/// step surfaces as its own error rather than as a confusing downstream
/// build/spawn failure.
async fn run_pre_build(
    workspace_root: &std::path::Path,
    argv: &[String],
    log_buf: &LogBuffer,
) -> Result<()> {
    let (program, args) = argv
        .split_first()
        .context("[process.pre_build] argv must have at least one element")?;
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    cmd.current_dir(workspace_root);

    info!(cmd = %argv.join(" "), "running [process.pre_build] for local-process component");
    let (ok, stderr_tail) = run_streaming(cmd, log_buf)
        .await
        .with_context(|| format!("spawning pre_build command `{}`", argv.join(" ")))?;
    if !ok {
        bail!(
            "[process.pre_build] `{}` failed:\n{}",
            argv.join(" "),
            stderr_tail.join("\n")
        );
    }
    Ok(())
}

/// Lines of trailing stderr [`run_streaming`] keeps in memory to fold into a
/// failure's error message. Compiler diagnostics are what an operator needs
/// to act on a failed build; the full transcript is in `log_buf` regardless.
const STDERR_TAIL_CAP: usize = 30;

/// `cargo build -p <pkg>` in the workspace root, streamed live into `log_buf`
/// (R715 follow-up — the desktop has no console to inherit stdout/stderr
/// into, so this is the only way build progress reaches the Run tab, and
/// unlike a buffer-then-discard capture it doesn't drop a *successful*
/// build's output on the floor).
async fn cargo_build(
    workspace_root: &std::path::Path,
    pkg: &str,
    profile: &str,
    log_buf: &LogBuffer,
) -> Result<()> {
    let mut cmd = tokio::process::Command::new("cargo");
    cmd.arg("build").arg("-p").arg(pkg);
    if profile == "release" {
        cmd.arg("--release");
    } else if profile != "debug" {
        cmd.arg("--profile").arg(profile);
    }
    cmd.current_dir(workspace_root);

    info!(
        package = pkg,
        profile, "cargo build for local-process component"
    );
    let (ok, stderr_tail) = run_streaming(cmd, log_buf)
        .await
        .with_context(|| format!("spawning `cargo build -p {pkg}`"))?;
    if !ok {
        bail!("cargo build -p {pkg} failed:\n{}", stderr_tail.join("\n"));
    }
    Ok(())
}

/// Run `cmd` to completion, streaming stdout and stderr into `log_buf`
/// line-by-line as they're produced — not buffered until exit, so a slow
/// command shows progress instead of going silent until it's done. Returns
/// whether it exited successfully plus the last [`STDERR_TAIL_CAP`] stderr
/// lines, which a caller can fold into its own error on failure without
/// re-reading `log_buf` (a compiler's diagnostics land on stderr, so that's
/// the stream worth quoting back).
async fn run_streaming(mut cmd: tokio::process::Command, log_buf: &LogBuffer) -> Result<(bool, Vec<String>)> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().context("spawning command")?;
    let stdout = child.stdout.take().expect("stdout piped above");
    let stderr = child.stderr.take().expect("stderr piped above");

    let stderr_tail: Arc<AsyncMutex<VecDeque<String>>> = Arc::new(AsyncMutex::new(VecDeque::new()));

    let out_task = {
        let log_buf = log_buf.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log_buf.push(line).await;
            }
        })
    };
    let err_task = {
        let log_buf = log_buf.clone();
        let tail = stderr_tail.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log_buf.push(line.clone()).await;
                let mut t = tail.lock().await;
                t.push_back(line);
                if t.len() > STDERR_TAIL_CAP {
                    t.pop_front();
                }
            }
        })
    };

    let status = child
        .wait()
        .await
        .context("waiting on spawned command")?;
    // The drain tasks were spawned onto the runtime above, so they've been
    // reading concurrently with `wait()` regardless of join order; awaiting
    // them here just confirms both pipes hit EOF before returning the tail.
    let _ = out_task.await;
    let _ = err_task.await;

    let tail = stderr_tail.lock().await.iter().cloned().collect();
    Ok((status.success(), tail))
}

/// What a previous `up()` recorded about the child it left running.
///
/// This exists because [`NativeRuntime`]'s workload table is in-memory: a
/// `yah cloud mirror up` from the shell and a ▶ click in the desktop are
/// different processes, and neither can see the other's children. The sidecar
/// is the only thing that makes "replace the predecessor" possible across them.
#[derive(Debug, serde::Serialize, Deserialize)]
struct OwnerRecord {
    pid: i32,
    /// The port the recorded child bound, when it declared one. `default` so a
    /// sidecar written before portless components existed still parses — those
    /// records always carry a port, and a missing one now means portless.
    #[serde(default)]
    port: Option<u16>,
}

/// Record the child we just spawned. Best-effort: failing to write the sidecar
/// must not fail an otherwise-successful bring-up — the cost is a manual kill
/// on the next re-run, not a broken mirror.
async fn write_owner(path: &std::path::Path, pid: i32, port: Option<u16>) {
    if let Some(dir) = path.parent() {
        if tokio::fs::create_dir_all(dir).await.is_err() {
            return;
        }
    }
    if let Ok(json) = serde_json::to_vec(&OwnerRecord { pid, port }) {
        if let Err(e) = tokio::fs::write(path, json).await {
            warn!(path = %path.display(), error = %e, "could not record local-process owner");
        }
    }
}

/// Stop the child a previous `up()` left behind, if it is still alive.
///
/// SIGTERM, a short grace, then SIGKILL — the same ladder kamaji's own teardown
/// uses. The sidecar is removed either way, including when the pid is already
/// gone, so a stale record can't linger and make the next run think it has a
/// predecessor to wait on.
async fn reap_predecessor(owner_path: &std::path::Path) {
    let Ok(bytes) = tokio::fs::read(owner_path).await else {
        return;
    };
    let _ = tokio::fs::remove_file(owner_path).await;
    let Ok(owner) = serde_json::from_slice::<OwnerRecord>(&bytes) else {
        return;
    };
    if !pid_alive(owner.pid) {
        return;
    }

    info!(
        pid = owner.pid,
        port = ?owner.port,
        "replacing predecessor local-process"
    );
    signal_pid(owner.pid, libc::SIGTERM);
    for _ in 0..50 {
        if !pid_alive(owner.pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    warn!(
        pid = owner.pid,
        "predecessor ignored SIGTERM; sending SIGKILL"
    );
    signal_pid(owner.pid, libc::SIGKILL);
    // Give the kernel a moment to release the port before we probe it.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// `kill(pid, 0)` — true when a process with this pid exists and we may signal
/// it. Cannot prove the pid is still *our* child (pids are reused), which is
/// why the sidecar is written next to this workload's capture dir and removed
/// on every read: the window where a recycled pid could be signalled is one
/// reconcile wide, and the alternative (never reaping) is a guaranteed
/// collision rather than a theoretical one.
fn pid_alive(pid: i32) -> bool {
    // SAFETY: `kill` with signal 0 performs error checking only and never
    // delivers a signal; any pid value is a defined input.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn signal_pid(pid: i32, sig: i32) {
    // SAFETY: same contract as above — `kill` is defined for any pid/signal
    // pair and reports failure through its return value, which we ignore
    // because a vanished process is the outcome we wanted anyway.
    unsafe {
        libc::kill(pid, sig);
    }
}

/// Last few lines of the capture files, formatted for an error message. A bind
/// timeout with no output is nearly impossible to act on; the process almost
/// always said why on the way down.
async fn read_capture_tail(stdout_path: &std::path::Path, stderr_path: &std::path::Path) -> String {
    let mut lines: Vec<String> = Vec::new();
    for path in [stderr_path, stdout_path] {
        if let Ok(s) = tokio::fs::read_to_string(path).await {
            lines.extend(s.lines().rev().take(10).map(str::to_string));
        }
    }
    if lines.is_empty() {
        return String::new();
    }
    lines.reverse();
    format!("\nlast output:\n{}", lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `run_streaming` interleaves stdout/stderr into `log_buf` as the child
    /// produces them (not buffered until exit), reports success/failure by
    /// exit status, and keeps a bounded stderr tail for the caller's error
    /// message — the shape `cargo_build` builds on, exercised here without
    /// depending on an actual `cargo` invocation.
    #[tokio::test]
    async fn run_streaming_captures_both_streams_and_reports_failure() {
        let log_buf = LogBuffer::new();
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg("echo out-line; echo err-line >&2; exit 3");

        let (ok, tail) = run_streaming(cmd, &log_buf).await.unwrap();
        assert!(!ok, "exit 3 must be reported as failure");
        assert_eq!(tail, vec!["err-line".to_string()]);

        let (lines, _) = log_buf.since(0).await;
        assert!(lines.contains(&"out-line".to_string()), "{lines:?}");
        assert!(lines.contains(&"err-line".to_string()), "{lines:?}");
    }

    /// The tail exists so a failure's error message doesn't have to re-read
    /// `log_buf` — but it must stay bounded, or a build that fails after
    /// paging through thousands of warnings dumps all of them into the error.
    #[tokio::test]
    async fn run_streaming_bounds_the_stderr_tail() {
        let log_buf = LogBuffer::new();
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg("for i in $(seq 1 50); do echo \"e$i\" >&2; done; exit 1");

        let (ok, tail) = run_streaming(cmd, &log_buf).await.unwrap();
        assert!(!ok);
        assert_eq!(tail.len(), STDERR_TAIL_CAP);
        assert_eq!(tail.first(), Some(&"e21".to_string()));
        assert_eq!(tail.last(), Some(&"e50".to_string()));

        // Every line still reached the log buffer, unbounded — only the
        // in-memory tail kept for the error message is capped.
        let (lines, _) = log_buf.since(0).await;
        assert_eq!(lines.len(), 50);
    }

    fn spec(bin: Option<&str>, pkg: Option<&str>) -> ProcessSpec {
        ProcessSpec {
            pre_build: None,
            cargo_package: pkg.map(str::to_string),
            bin: bin.map(str::to_string),
            args: vec![],
            port: Some(4325),
            env: BTreeMap::new(),
            profile: "debug".to_string(),
            control: None,
        }
    }

    #[test]
    fn parses_a_process_section_alongside_container_sections() {
        // One workload.toml describes both tiers; each reconciler reads its own
        // section and ignores the other's.
        let src = r#"
schema_version = 1
kind = "container"

[build]
image = "yah-local/x:dev"

[run]
port = 4325

[process]
cargo_package = "yah-cloud-admin"
port = 4325
args = ["--verbose"]

[process.env]
YAH_CLOUD_ADMIN_ADDR = "127.0.0.1:4325"
"#;
        let c: ProcessComponent = toml::from_str(src).unwrap();
        let p = c.process.unwrap();
        assert_eq!(p.cargo_package.as_deref(), Some("yah-cloud-admin"));
        assert_eq!(p.port, Some(4325));
        assert_eq!(p.args, vec!["--verbose".to_string()]);
        assert_eq!(p.profile, "debug");
        assert_eq!(
            p.env.get("YAH_CLOUD_ADMIN_ADDR").map(String::as_str),
            Some("127.0.0.1:4325")
        );
    }

    /// R715-T2: the noisetable shape — a native GUI with no network surface.
    /// `port` must be *absent*, not zero: a zero would be a real port number
    /// to every layer downstream that reads one.
    #[test]
    fn a_process_section_without_a_port_is_portless() {
        let src = r#"
[process]
cargo_package = "dev"
profile = "release"
args = ["--window"]
"#;
        let p: ProcessComponent = toml::from_str(src).unwrap();
        let p = p.process.unwrap();
        assert_eq!(p.port, None, "an omitted port must stay absent");
        assert_eq!(p.cargo_package.as_deref(), Some("dev"));
        assert_eq!(p.profile, "release");
    }

    /// The macOS/iOS shape: no `cargo_package` (there is no runnable
    /// top-level binary from a plain `cargo build -p pkg` — Rust only
    /// supplies a static lib for Xcode), the entire build is `pre_build`.
    #[test]
    fn parses_a_pre_build_argv() {
        let src = r#"
[process]
pre_build = ["./build-dist.sh", "arm64", "--sign"]
bin = "app/macos/dist/NoiseTable.app/Contents/MacOS/NoiseTable"
"#;
        let p: ProcessComponent = toml::from_str(src).unwrap();
        let p = p.process.unwrap();
        assert_eq!(
            p.pre_build,
            Some(vec![
                "./build-dist.sh".to_string(),
                "arm64".to_string(),
                "--sign".to_string(),
            ])
        );
        assert_eq!(p.cargo_package, None);
    }

    /// The house default: a portless component opting into the control
    /// channel with an empty `[process.control]` and nothing else. The socket
    /// path is the supervisor's to choose — the process reads it from
    /// `$YAH_CONTROL_SOCK`.
    #[test]
    fn an_empty_control_section_yields_the_supervisor_chosen_socket() {
        let src = r#"
[process]
cargo_package = "dev"

[process.control]
"#;
        let c: ProcessComponent = toml::from_str(src).unwrap();
        let spec = c.process.unwrap();
        let got = control_endpoint(&spec, std::path::Path::new("/s"), "svc-dev-app");
        assert_eq!(
            got,
            Some(ControlEndpoint::Socket(PathBuf::from(
                "/s/svc-dev-app/control.sock"
            ))),
        );
    }

    #[test]
    fn no_control_section_means_no_channel() {
        assert_eq!(
            control_endpoint(&spec(Some("bin/x"), None), std::path::Path::new("/s"), "id"),
            None,
        );
    }

    #[test]
    fn an_http_path_binds_the_channel_to_the_declared_port() {
        let src = r#"
[process]
cargo_package = "svc"
port = 4325

[process.control]
http_path = "/_yah/status"
"#;
        let spec = toml::from_str::<ProcessComponent>(src).unwrap().process.unwrap();
        assert_eq!(
            control_endpoint(&spec, std::path::Path::new("/s"), "id"),
            Some(ControlEndpoint::Http(
                "http://127.0.0.1:4325/_yah/status".into()
            )),
        );
    }

    /// An empty `http_path` means "the conventional one" rather than a URL
    /// ending in the port — the shape most likely to be written by hand.
    #[test]
    fn an_empty_http_path_falls_back_to_the_conventional_one() {
        let src = r#"
[process]
cargo_package = "svc"
port = 4325

[process.control]
http_path = ""
"#;
        let spec = toml::from_str::<ProcessComponent>(src).unwrap().process.unwrap();
        assert_eq!(
            control_endpoint(&spec, std::path::Path::new("/s"), "id"),
            Some(ControlEndpoint::Http(format!(
                "http://127.0.0.1:4325{}",
                crate::proc_control::DEFAULT_HTTP_PATH
            ))),
        );
    }

    /// `http_path` with no port is a contradiction. Silently falling back to a
    /// socket would give the component a channel it never agreed to serve, and
    /// then fail readiness twenty seconds later with a message about a socket
    /// nobody mentioned.
    #[test]
    fn an_http_path_without_a_port_yields_no_endpoint() {
        let src = r#"
[process]
cargo_package = "svc"

[process.control]
http_path = "/_yah/status"
"#;
        let spec = toml::from_str::<ProcessComponent>(src).unwrap().process.unwrap();
        assert_eq!(control_endpoint(&spec, std::path::Path::new("/s"), "id"), None);
    }

    #[test]
    fn an_explicit_socket_path_overrides_the_default() {
        let src = r#"
[process]
cargo_package = "svc"

[process.control]
socket = "/tmp/mine.sock"
"#;
        let spec = toml::from_str::<ProcessComponent>(src).unwrap().process.unwrap();
        assert_eq!(
            control_endpoint(&spec, std::path::Path::new("/s"), "id"),
            Some(ControlEndpoint::Socket(PathBuf::from("/tmp/mine.sock"))),
        );
    }

    /// The sidecar gained an optional `port` when portless components landed.
    /// Records written before that carry a bare `u16` and must still parse —
    /// otherwise the first reconcile after an upgrade silently fails to reap
    /// its predecessor, which is the exact collision the sidecar exists for.
    #[test]
    fn an_owner_record_written_before_portless_components_still_parses() {
        let old: OwnerRecord = serde_json::from_str(r#"{"pid":54869,"port":4325}"#).unwrap();
        assert_eq!(old.pid, 54869);
        assert_eq!(old.port, Some(4325));

        let portless: OwnerRecord = serde_json::from_str(r#"{"pid":71455}"#).unwrap();
        assert_eq!(portless.port, None);
    }

    #[test]
    fn a_workload_without_a_process_section_parses_as_none() {
        let c: ProcessComponent = toml::from_str("[run]\nport = 1\n").unwrap();
        assert!(c.process.is_none());
    }

    #[test]
    fn binary_defaults_to_the_cargo_convention() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("target/debug")).unwrap();
        std::fs::write(tmp.path().join("target/debug/yah-cloud-admin"), b"").unwrap();
        let got = resolve_binary(&spec(None, Some("yah-cloud-admin")), tmp.path()).unwrap();
        assert_eq!(got, tmp.path().join("target/debug/yah-cloud-admin"));
    }

    #[test]
    fn explicit_bin_wins_over_the_cargo_convention() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("bin")).unwrap();
        std::fs::write(tmp.path().join("bin/custom"), b"").unwrap();
        let got = resolve_binary(&spec(Some("bin/custom"), Some("pkg")), tmp.path()).unwrap();
        assert_eq!(got, tmp.path().join("bin/custom"));
    }

    /// Spawning a path that isn't there fails with an exec error several
    /// layers down; naming the missing file here is the actionable version.
    #[test]
    fn a_missing_binary_is_named_before_we_try_to_exec_it() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_binary(&spec(None, Some("nope")), tmp.path()).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn neither_bin_nor_package_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_binary(&spec(None, None), tmp.path()).unwrap_err();
        assert!(err.to_string().contains("neither"), "{err}");
    }

    /// The bug this whole path exists to prevent: a second `up()` in a fresh
    /// process must stop the first one's child. NativeRuntime's table is
    /// in-memory, so the sidecar is the only link between the two runs.
    ///
    /// The assertion is on the child's exit status, not on [`pid_alive`],
    /// because this test *is* the child's parent: a signalled child it has not
    /// waited on stays a zombie, and `kill(pid, 0)` succeeds against a zombie.
    /// In production the spawning process is either gone (CLI — init reaps) or
    /// still holding kamaji's supervisor task (desktop — that reaps), so
    /// neither leaves one behind.
    #[tokio::test]
    async fn reap_stops_a_live_predecessor_and_clears_the_record() {
        let tmp = tempfile::tempdir().unwrap();
        let owner_path = tmp.path().join("owner.json");

        let mut child = tokio::process::Command::new("sleep")
            .arg("120")
            .spawn()
            .unwrap();
        let pid = child.id().unwrap() as i32;
        assert!(pid_alive(pid));

        write_owner(&owner_path, pid, Some(4325)).await;
        reap_predecessor(&owner_path).await;

        let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("a signalled `sleep 120` must have exited well inside 5s")
            .unwrap();
        assert!(!status.success(), "predecessor should have been signalled");
        assert!(!owner_path.exists(), "sidecar should be cleared");
    }

    /// A record left behind by a crash names a pid that is gone. Reaping it
    /// must be a no-op that still clears the file — a stale record that
    /// survives would make every later run wait on a corpse.
    #[tokio::test]
    async fn reap_clears_a_stale_record_without_signalling_anything() {
        let tmp = tempfile::tempdir().unwrap();
        let owner_path = tmp.path().join("owner.json");

        // Exited process: spawn and wait, so the pid is definitely dead.
        let mut child = tokio::process::Command::new("true").spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        child.wait().await.unwrap();

        write_owner(&owner_path, pid, Some(4325)).await;
        reap_predecessor(&owner_path).await;
        assert!(!owner_path.exists());
    }

    #[tokio::test]
    async fn reap_with_no_record_is_a_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        reap_predecessor(&tmp.path().join("owner.json")).await;
    }

    // ── End-to-end: a portless component through the real reconciler ────────
    //
    // The unit tests above pin parsing and endpoint resolution. This one runs
    // `up()` itself — kamaji native backend, real child process, real sidecar
    // — because the claim R715-T2 makes is not "the struct has an Option", it
    // is "a component with no port comes up and reports no dev_url", and only
    // the whole path can say that.

    fn portless_service() -> crate::ServiceConfig {
        crate::ServiceConfig {
            schema_version: 1,
            name: "noisy".into(),
            domain: "noisy.example".into(),
            components: vec![crate::ServiceComponent {
                mount: None,
                id: "gui".into(),
                kind: "container".into(),
                path: "gui".into(),
                role: "compute".into(),
                publishes: None,
                wave: 0,
                git: None,
                deploy: Default::default(),
            }],
            db: crate::DbCatalog::default(),
        }
    }

    fn local_process_mirror() -> crate::MirrorConfig {
        let mut providers = BTreeMap::new();
        providers.insert(
            SLOT.to_string(),
            MirrorProviderSlot::Inline {
                kind: Provider::LocalProcess,
                fields: Default::default(),
            },
        );
        crate::MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::Local,
            providers,
            ingress: Default::default(),
            ingress_machines: Vec::new(),
            drivers: Default::default(),
            asset_aliases: Default::default(),
        }
    }

    /// The noisetable shape end to end: no `port`, no control channel. Comes
    /// up, reports no `dev_url`, and says in its notes that readiness here is
    /// liveness only — so nobody reads a green row as a health claim.
    #[tokio::test]
    async fn a_portless_component_comes_up_with_no_dev_url() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ws.path().join("gui")).unwrap();
        std::fs::write(
            ws.path().join("gui/workload.toml"),
            "schema_version = 1\nkind = \"container\"\n\n[process]\nbin = \"/bin/sleep\"\nargs = [\"30\"]\n",
        )
        .unwrap();

        let svc = portless_service();
        let mirror = local_process_mirror();
        let ctx = ReconcileCtx {
            workspace_root: ws.path(),
            service: &svc,
            component: &svc.components[0],
            mirror: &mirror,
            env: "dev",
            scope: crate::ProviderScope::singleton(),
        };

        let mut running = LocalProcessReconciler::new().up(ctx).await.unwrap();
        assert_eq!(running.dev_url, None, "a portless component has no URL");
        assert_eq!(running.slot, SLOT);
        assert_eq!(
            running.build_log_end, None,
            "no cargo_package was declared, so nothing was built"
        );
        assert!(
            running.notes.iter().any(|n| n.contains("portless")),
            "the liveness-only caveat must be visible to an operator: {:?}",
            running.notes,
        );

        // The sidecar is what lets a later reconcile in another process reap
        // this child. Portless or not, it must be written — and its `port`
        // must be absent rather than a placeholder zero.
        let owner: OwnerRecord = serde_json::from_slice(
            &std::fs::read(
                ws.path()
                    .join(".yah/jit/native")
                    .join(sanitize_ident("local-process-noisy-dev-gui"))
                    .join("owner.json"),
            )
            .expect("owner sidecar must exist"),
        )
        .unwrap();
        assert_eq!(owner.port, None);
        assert!(pid_alive(owner.pid), "the child should still be running");

        if let Some(tx) = running.shutdown.take() {
            tx.send(()).ok();
        }
        if let Some(sup) = running.supervisor.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), sup).await;
        }
    }

    /// The house default, end to end: a portless component that declares
    /// `[process.control]` is held at "not ready" until something answers
    /// `status` with `running`.
    ///
    /// The child here is `/bin/sleep` and the socket is served by the test,
    /// which is the point — the reconciler must not care *who* answers, only
    /// that the declared endpoint does. A real workload binds the same path
    /// out of `$YAH_CONTROL_SOCK`.
    #[tokio::test]
    async fn a_control_channel_decides_readiness_when_declared() {
        let ws = tempfile::tempdir().unwrap();
        let sock = ws.path().join("control.sock");
        std::fs::create_dir_all(ws.path().join("gui")).unwrap();
        std::fs::write(
            ws.path().join("gui/workload.toml"),
            format!(
                "schema_version = 1\nkind = \"container\"\n\n[process]\nbin = \"/bin/sleep\"\n\
                 args = [\"30\"]\n\n[process.control]\nsocket = \"{}\"\n",
                sock.display()
            ),
        )
        .unwrap();

        // Stand-in producer: answers `starting` once, then `running`.
        //
        // It binds *after* a delay on purpose. `up()` unlinks a predecessor's
        // socket file before spawning (a leftover file makes `bind` fail with
        // EADDRINUSE even with nobody listening), so a producer that bound
        // first would have its socket deleted out from under it — which is
        // exactly the order a real child sees: supervisor unlinks, child
        // starts, child binds.
        let server = {
            let sock = sock.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(400)).await;
                let listener = tokio::net::UnixListener::bind(&sock).unwrap();
                for doc in [r#"{"state":"starting","detail":"loading"}"#, r#"{"state":"running","detail":"1 window"}"#] {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let (rd, mut wr) = stream.into_split();
                    let mut line = String::new();
                    tokio::io::AsyncBufReadExt::read_line(
                        &mut tokio::io::BufReader::new(rd),
                        &mut line,
                    )
                    .await
                    .ok();
                    tokio::io::AsyncWriteExt::write_all(&mut wr, format!("{doc}\n").as_bytes())
                        .await
                        .ok();
                }
            })
        };

        let svc = portless_service();
        let mirror = local_process_mirror();
        let ctx = ReconcileCtx {
            workspace_root: ws.path(),
            service: &svc,
            component: &svc.components[0],
            mirror: &mirror,
            env: "dev",
            scope: crate::ProviderScope::singleton(),
        };

        let mut running = LocalProcessReconciler::new().up(ctx).await.unwrap();
        assert_eq!(running.dev_url, None);
        assert!(
            running
                .notes
                .iter()
                .any(|n| n.contains("control:") && n.contains("1 window")),
            "the process's own words should reach the operator: {:?}",
            running.notes,
        );
        assert!(
            !running.notes.iter().any(|n| n.contains("liveness only")),
            "a component WITH a channel must not be labelled liveness-only: {:?}",
            running.notes,
        );

        server.abort();
        if let Some(tx) = running.shutdown.take() {
            tx.send(()).ok();
        }
        if let Some(sup) = running.supervisor.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), sup).await;
        }
    }

    /// A portless component that dies on exec must fail the reconcile, not
    /// register a healthy row over a corpse. `/usr/bin/false` is the smallest
    /// honest stand-in for "binary exits immediately".
    #[tokio::test]
    async fn a_portless_component_that_exits_immediately_fails_the_reconcile() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ws.path().join("gui")).unwrap();
        std::fs::write(
            ws.path().join("gui/workload.toml"),
            "schema_version = 1\nkind = \"container\"\n\n[process]\nbin = \"/usr/bin/false\"\n",
        )
        .unwrap();

        let svc = portless_service();
        let mirror = local_process_mirror();
        let ctx = ReconcileCtx {
            workspace_root: ws.path(),
            service: &svc,
            component: &svc.components[0],
            mirror: &mirror,
            env: "dev",
            scope: crate::ProviderScope::singleton(),
        };

        let err = LocalProcessReconciler::new()
            .up(ctx)
            .await
            .expect_err("a process that exits immediately is not a successful bring-up");
        assert!(
            err.to_string().contains("portless"),
            "the error should name why it was judged this way: {err}"
        );
    }

    /// A failing `[process.pre_build]` must fail the reconcile before ever
    /// touching `cargo_package`/spawn — a broken xcodebuild/codesign step
    /// should surface as its own error, not as a confusing "binary not
    /// found" from a later stage that never should have run.
    #[tokio::test]
    async fn a_failing_pre_build_fails_the_reconcile_before_spawn() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ws.path().join("gui")).unwrap();
        std::fs::write(
            ws.path().join("gui/workload.toml"),
            "schema_version = 1\nkind = \"container\"\n\n[process]\npre_build = [\"sh\", \"-c\", \"exit 1\"]\nbin = \"/bin/sleep\"\nargs = [\"30\"]\n",
        )
        .unwrap();

        let svc = portless_service();
        let mirror = local_process_mirror();
        let ctx = ReconcileCtx {
            workspace_root: ws.path(),
            service: &svc,
            component: &svc.components[0],
            mirror: &mirror,
            env: "dev",
            scope: crate::ProviderScope::singleton(),
        };

        let err = LocalProcessReconciler::new()
            .up(ctx)
            .await
            .expect_err("a failing pre_build must not be treated as a successful bring-up");
        assert!(
            err.to_string().contains("pre_build"),
            "the error should name the stage that failed: {err}"
        );
    }

    #[test]
    fn mirror_profile_override_reads_the_inline_extra_field() {
        let mut mirror = local_process_mirror();
        if let Some(MirrorProviderSlot::Inline { fields, .. }) = mirror.providers.get_mut(SLOT) {
            fields.insert("profile".to_string(), toml::Value::String("release".to_string()));
        }
        assert_eq!(
            mirror_profile_override(&mirror),
            Some("release".to_string())
        );
    }

    #[test]
    fn mirror_profile_override_is_absent_by_default() {
        // No `profile` key declared on the mirror's compute slot — falls back
        // to whatever workload.toml itself declares.
        assert_eq!(mirror_profile_override(&local_process_mirror()), None);
    }

    #[test]
    fn slot_declared_only_matches_the_local_process_compute_slot() {
        let mut m = crate::MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::Local,
            ingress: Default::default(),
            ingress_machines: Vec::new(),
            providers: Default::default(),
            drivers: Default::default(),
            asset_aliases: Default::default(),
        };
        assert!(!slot_declared(&m));
        m.providers.insert(
            SLOT.to_string(),
            MirrorProviderSlot::Inline {
                kind: Provider::LocalContainer,
                fields: Default::default(),
            },
        );
        assert!(!slot_declared(&m), "a container slot is not a process slot");
        m.providers.insert(
            SLOT.to_string(),
            MirrorProviderSlot::Inline {
                kind: Provider::LocalProcess,
                fields: Default::default(),
            },
        );
        assert!(slot_declared(&m));
    }
}
