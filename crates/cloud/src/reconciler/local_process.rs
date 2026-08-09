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
//! # Port the process listens on. Required — it is the readiness signal.
//! port = 4325
//!
//! [process.env]
//! YAH_CLOUD_ADMIN_ADDR = "127.0.0.1:4325"
//! ```
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

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use kamaji::native::NativeRuntime;
use kamaji::{Kamaji, MeshAssignment, MeshIdent};
use serde::Deserialize;
use tokio::sync::oneshot;
use tracing::{info, warn};
use workload_spec::EnvVar;

use super::native_support::{
    capture_paths, native_spec, sanitize_ident, spawn_native_log_supervisor,
};
use super::{into_running, wait_for_port, LogBuffer, ReconcileCtx, Reconciler, RunningWorkload};
use crate::{MirrorProviderSlot, MirrorShape, Provider};

/// The slot role a natively-run compute component occupies on its mirror.
const SLOT: &str = "compute";

/// How long to wait for the process to bind its declared port before calling
/// the reconcile failed. Generous because the first `cargo build` of a cold
/// target dir is included in the caller's patience, not in this window — the
/// build finishes before the spawn.
const READY_TIMEOUT: Duration = Duration::from_secs(20);

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

/// Reconciler for components bound to a `local-process` compute slot.
#[derive(Debug, Default)]
pub struct LocalProcessReconciler;

impl LocalProcessReconciler {
    pub fn new() -> Self {
        Self::default()
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
    /// Port the process listens on. Required: it is how readiness is decided,
    /// and a component with no port has nothing for the Run tab to open.
    port: u16,
    /// Environment for the child.
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Cargo profile used for both the build and the default binary path.
    #[serde(default = "default_profile")]
    profile: String,
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

        let spec = load_process_spec(&ctx)?;

        // Build first, if asked. Doing this before the port probe means a
        // compile error surfaces as a compile error, rather than as a bind
        // timeout on a binary that was never rebuilt.
        if let Some(pkg) = &spec.cargo_package {
            cargo_build(ctx.workspace_root, pkg, &spec.profile).await?;
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
        // worse than a failed bring-up.
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), spec.port);
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            bail!(
                "component {}: {addr} is already held by a process this reconciler did not \
                 start. Stop it, or give [process] a different `port`.",
                ctx.component.id,
            );
        }

        let mut argv = vec![bin.display().to_string()];
        argv.extend(spec.args.iter().cloned());

        let env: Vec<EnvVar> = spec
            .env
            .iter()
            .map(|(name, value)| EnvVar {
                name: name.clone(),
                value: workload_spec::EnvValue::Literal {
                    value: value.clone(),
                },
            })
            .collect();

        let workload = native_spec(&ident_str, argv, env);
        let runtime = Arc::new(NativeRuntime::new(&state_dir));
        let mesh = MeshAssignment::inlined(Ipv4Addr::LOCALHOST);

        info!(
            binary = %bin.display(),
            port = spec.port,
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

        // Wait for the bind. A dead process must not hand the Run tab a URL
        // that will never answer.
        if !wait_for_port(addr, READY_TIMEOUT).await {
            warn!(addr = %addr, "local-process did not bind within timeout; tearing down");
            let tail = read_capture_tail(&stdout_path, &stderr_path).await;
            runtime.teardown_workload(&ident).await.ok();
            bail!(
                "component {} did not bind {addr} within {READY_TIMEOUT:?}{tail}",
                ctx.component.id,
            );
        }

        let dev_url = format!("http://{addr}");
        info!(dev_url = %dev_url, pid = deployed.task_pid, "local-process ready");

        let log_buf = LogBuffer::new();
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
            Some(dev_url),
            None,
            Some(log_buf),
            shutdown_tx,
            supervisor,
        ))
    }
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
             [process] section — add one with at least `port`",
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

/// `cargo build -p <pkg>` in the workspace root, surfacing compiler output on
/// failure. Inherits stdout/stderr is *not* an option here (the desktop has no
/// console), so output is captured and the tail is folded into the error.
async fn cargo_build(workspace_root: &std::path::Path, pkg: &str, profile: &str) -> Result<()> {
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
    let out = cmd
        .output()
        .await
        .with_context(|| format!("spawning `cargo build -p {pkg}`"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail: Vec<&str> = stderr.lines().rev().take(30).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        bail!("cargo build -p {pkg} failed:\n{}", tail.join("\n"));
    }
    Ok(())
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
    port: u16,
}

/// Record the child we just spawned. Best-effort: failing to write the sidecar
/// must not fail an otherwise-successful bring-up — the cost is a manual kill
/// on the next re-run, not a broken mirror.
async fn write_owner(path: &std::path::Path, pid: i32, port: u16) {
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
        port = owner.port,
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

    fn spec(bin: Option<&str>, pkg: Option<&str>) -> ProcessSpec {
        ProcessSpec {
            cargo_package: pkg.map(str::to_string),
            bin: bin.map(str::to_string),
            args: vec![],
            port: 4325,
            env: BTreeMap::new(),
            profile: "debug".to_string(),
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
        assert_eq!(p.port, 4325);
        assert_eq!(p.args, vec!["--verbose".to_string()]);
        assert_eq!(p.profile, "debug");
        assert_eq!(
            p.env.get("YAH_CLOUD_ADMIN_ADDR").map(String::as_str),
            Some("127.0.0.1:4325")
        );
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

        write_owner(&owner_path, pid, 4325).await;
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

        write_owner(&owner_path, pid, 4325).await;
        reap_predecessor(&owner_path).await;
        assert!(!owner_path.exists());
    }

    #[tokio::test]
    async fn reap_with_no_record_is_a_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        reap_predecessor(&tmp.path().join("owner.json")).await;
    }

    #[test]
    fn slot_declared_only_matches_the_local_process_compute_slot() {
        let mut m = crate::MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::Local,
            ingress: Default::default(),
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
