//! Live proof that pond's slots are supervised by the container daemon
//! (R626-F2), not by a yubaba loop.
//!
//! Spawns a real kamaji with its docker backend attached, drives it through
//! the same [`KamajiLauncher`] pond's deploy handler uses, and inspects the
//! resulting container on the daemon. The unit tests either side of this
//! (the argv renderer in `kamaji::docker`, the `ContainerRunSpec` lowering in
//! `yubaba::pond::launcher`) each prove half a contract; only a live round-trip
//! proves the halves meet.
//!
//! Two properties matter, and they are the two this asserts:
//!
//! 1. **A crash is restarted by dockerd.** The container is created with a
//!    restart policy, so nothing in yubaba has to resurrect it.
//! 2. **A deliberate stop stays stopped.** This is what pond got wrong before:
//!    a `docker stop` lost a race against the reconciler's `ensure_*_running`.
//!    `unless-stopped` (not `always`) is what makes the stop stick, including
//!    across a daemon restart.
//!
//! Self-skips when no docker daemon is reachable, so `cargo test -p yubaba`
//! stays green on a machine without one.
//!
//! ```bash
//! cargo test -p yubaba --features docker-integration --test pond_kamaji_supervision -- --nocapture
//! ```
//!
//! Part of R626-F2 — the ticket annotation lives in
//! `oss/yubaba/crates/yubaba/src/pond.rs`.

#![cfg(feature = "docker-integration")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use local_driver::{ContainerLauncher, ContainerRunSpec};
use tempfile::TempDir;
use tokio::sync::oneshot;
use yubaba::pond::launcher::KamajiLauncher;

/// Tiny, universally-cached image; the container just has to exist and stay up.
const TEST_IMAGE: &str = "docker.io/alpine:3.20";

async fn docker_available() -> bool {
    matches!(
        tokio::process::Command::new("docker")
            .args(["version"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await,
        Ok(s) if s.success()
    )
}

/// `docker inspect --format <fmt> <name>`, trimmed. `None` when the container
/// doesn't exist.
async fn inspect(name: &str, fmt: &str) -> Option<String> {
    let out = tokio::process::Command::new("docker")
        .args(["inspect", "--format", fmt, name])
        .output()
        .await
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn docker_rm_f(name: &str) {
    let _ = tokio::process::Command::new("docker")
        .args(["rm", "-f", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
}

/// Spawn a kamaji with the docker backend attached, and wait for its UDS.
async fn spawn_kamaji_with_docker(
    socket: &Path,
) -> (tokio::task::JoinHandle<()>, oneshot::Sender<()>) {
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let ctx = Arc::new(
        kamaji_bin::server::ServerCtx::new().with_docker(kamaji::docker::DockerRuntime::new()),
    );
    let path = socket.to_path_buf();
    let handle = tokio::spawn(async move {
        let _ = kamaji_bin::server::serve_with_ctx(&path, ctx, async move {
            let _ = stop_rx.await;
        })
        .await;
    });

    for _ in 0..100 {
        if tokio::net::UnixStream::connect(socket).await.is_ok() {
            return (handle, stop_tx);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("kamaji never bound {}", socket.display());
}

fn pond_shaped_run_spec(name: &str, host_port: u16, state_dir: &Path) -> ContainerRunSpec {
    let mut env = BTreeMap::new();
    env.insert("POND_SLOT".to_string(), "object_store".to_string());
    ContainerRunSpec {
        name: name.to_string(),
        image: TEST_IMAGE.to_string(),
        label: "r626-f2:pond:object_store".to_string(),
        // Published host port — the docker-only concern pond needs and the
        // cross-backend WorkloadSpec has no field for.
        ports: vec![(host_port, 80)],
        env,
        volumes: vec![(state_dir.to_path_buf(), "/data".to_string())],
        cmd: vec!["sleep".into(), "600".into()],
        cap_add: vec![],
        cgroupns: None,
        network: None,
        network_aliases: vec![],
        extra_hosts: vec![],
    }
}

#[tokio::test]
async fn pond_slot_deployed_through_kamaji_is_daemon_supervised() {
    if !docker_available().await {
        eprintln!("SKIP: docker not reachable");
        return;
    }

    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("kamaji.sock");
    let (server, stop) = spawn_kamaji_with_docker(&sock).await;

    let client = kamaji::sibling::KamajiClient::connect(sock)
        .await
        .expect("kamaji handshake");
    let launcher = KamajiLauncher::new(Arc::new(client));

    let name = format!("yah-r626-f2-{}", std::process::id());
    let host_port = 38900 + (std::process::id() % 90) as u16;
    let state_dir: PathBuf = dir.path().join("data");
    std::fs::create_dir_all(&state_dir).unwrap();
    docker_rm_f(&name).await;

    let spec = pond_shaped_run_spec(&name, host_port, &state_dir);
    launcher.run(&spec).await.expect("deploy through kamaji");

    // ── 1. dockerd owns restart ───────────────────────────────────────────
    let policy = inspect(&name, "{{.HostConfig.RestartPolicy.Name}}")
        .await
        .expect("container exists after deploy");
    assert_eq!(
        policy, "unless-stopped",
        "pond's resurrect loops are gone, so the daemon must carry the restart \
         policy; `always` would additionally undo an operator stop on daemon \
         restart"
    );

    // ── 2. the docker-only spec fields actually rendered ──────────────────
    let published = inspect(&name, "{{json .NetworkSettings.Ports}}")
        .await
        .unwrap_or_default();
    assert!(
        published.contains(&host_port.to_string()),
        "host port {host_port} must be published (yah.docker.publish annotation), got {published}"
    );
    let mounts = inspect(&name, "{{json .Mounts}}").await.unwrap_or_default();
    assert!(
        mounts.contains("/data"),
        "the state-dir bind mount must be rendered, got {mounts}"
    );
    let label = inspect(&name, "{{index .Config.Labels \"yah.pond\"}}")
        .await
        .unwrap_or_default();
    assert_eq!(
        label, "r626-f2:pond:object_store",
        "the pond label must survive the lowering so `docker ps --filter \
         label=yah.pond` still finds pond containers"
    );

    // ── 3. a deliberate stop stays stopped ────────────────────────────────
    // This is the bug R626 was filed against, inverted into an assertion:
    // under `unless-stopped` the daemon does NOT bring the container back, and
    // pond's reconciler no longer does either.
    let stopped = tokio::process::Command::new("docker")
        .args(["stop", "-t", "1", &name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .expect("docker stop");
    assert!(stopped.success(), "docker stop {name} failed");

    tokio::time::sleep(Duration::from_secs(2)).await;
    let state = inspect(&name, "{{.State.Status}}")
        .await
        .unwrap_or_default();
    assert_eq!(
        state, "exited",
        "an explicitly stopped pond slot must stay stopped; it came back as {state:?}"
    );

    // ── 4. teardown through kamaji removes it ─────────────────────────────
    launcher
        .stop_and_remove(&name, Duration::from_secs(2))
        .await
        .expect("teardown through kamaji");
    assert!(
        inspect(&name, "{{.State.Status}}").await.is_none(),
        "teardown must remove the container record, not just stop it"
    );

    docker_rm_f(&name).await;
    let _ = stop.send(());
    let _ = server.await;
}

/// A crashed slot comes back without yubaba doing anything — the other half of
/// moving supervision to the daemon.
///
/// The crash is a non-zero *exit of the container's own process*, not
/// `docker kill`: dockerd records `docker stop` **and** `docker kill` alike as
/// manual stops and suppresses the restart policy for both. That is convenient
/// for R626 (an operator's `docker kill` also stays stopped) but it means a
/// test that killed the container from outside would prove nothing about crash
/// recovery.
#[tokio::test]
async fn crashed_pond_slot_is_restarted_by_the_daemon() {
    if !docker_available().await {
        eprintln!("SKIP: docker not reachable");
        return;
    }

    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("kamaji.sock");
    let (server, stop) = spawn_kamaji_with_docker(&sock).await;
    let client = kamaji::sibling::KamajiClient::connect(sock)
        .await
        .expect("kamaji handshake");
    let launcher = KamajiLauncher::new(Arc::new(client));

    let name = format!("yah-r626-f2-restart-{}", std::process::id());
    let state_dir = dir.path().join("data");
    std::fs::create_dir_all(&state_dir).unwrap();
    docker_rm_f(&name).await;

    let host_port = 39100 + (std::process::id() % 90) as u16;
    let mut spec = pond_shaped_run_spec(&name, host_port, &state_dir);
    // Crash on its own: run briefly, then exit non-zero.
    spec.cmd = vec!["sh".into(), "-c".into(), "sleep 1; exit 137".into()];
    launcher.run(&spec).await.expect("deploy through kamaji");

    // dockerd's restart backoff starts at ~100ms and doubles; give it a
    // generous budget rather than a fixed sleep so a loaded machine can't flake.
    let mut restarts = 0u32;
    for _ in 0..80 {
        restarts = inspect(&name, "{{.RestartCount}}")
            .await
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if restarts >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        restarts >= 1,
        "dockerd must restart a crashed pond slot with no help from yubaba; \
         RestartCount stayed at {restarts}"
    );

    docker_rm_f(&name).await;
    let _ = stop.send(());
    let _ = server.await;
}
