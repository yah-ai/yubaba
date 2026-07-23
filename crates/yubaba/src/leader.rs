//! Leadership watcher — Phase 2 (R040-F21).
//!
//! Spawns a background tokio task that subscribes to the openraft metrics
//! watch channel and orchestrates Headscale + litestream on leader transitions:
//!
//! **On becoming leader:**
//! 1. Run `litestream restore` (no-op if S3 has no snapshot yet).
//! 2. Enable + start `headscale.service`.
//! 3. Start `litestream-headscale.service` sidecar.
//! 4. Write `SetIngressOwner` to raft so `/raft/status` reflects the
//!    current Headscale host.
//!
//! **On losing leadership:**
//! 1. Stop `litestream-headscale.service`.
//! 2. Stop `headscale.service`.
//!    (`/mesh/leader-health` automatically returns 503 once headscale stops,
//!    so Cloudflare stops routing to this node without an extra step.)
//!
//! The watcher exits cleanly when the raft metrics channel closes (daemon
//! shutdown).  It is tolerant of systemctl/litestream errors — it logs them
//! but does not panic, since a follower that fails to stop headscale will
//! surface as two nodes returning 200 on the Cloudflare healthcheck, which
//! the operator can detect and fix.
//!
//! @yah:relay(R591, "Headscale HA: exactly-one appliance whose external identity follows placement (W242 P4)")
//! @yah:at(2026-07-02T17:34:43Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:depends_on(R570)
//! @yah:next("Reframe from 'leader election' to an EXACTLY-ONE appliance workload (R572 archetype): the reconciler places headscale on some node per the cluster's agreed state; leader.rs already implements the follow-the-placement half (on-become: litestream restore → start headscale → replicate; on-lose: stop).")
//! @yah:next("The only property that makes headscale special vs a normal internal workload: its placement must COMMAND AN EXTERNAL INGRESS to follow it, because its clients (tailnet nodes + operator) live OUTSIDE the mesh. That external-identity-follows-placement is the whole point of this relay.")
//! @yah:next("Gated on R570: leader.rs's follow-placement code is inert until there is a real multi-voter raft to re-place the singleton on.")
//! @yah:gotcha("TODAY is the fragile path (verified 2026-07-01): cloud.mesh.yah.dev is a DIRECT A-record → us-west-001 (15.204.89.240), cloudflared inactive, headscale self-terminates Let's Encrypt (HTTP-01 on :80, serving :443). So a failover requires the new head to BOTH (a) take the A-record AND (b) re-mint the LE cert via HTTP-01 — a chicken-and-egg with a hard connectivity gap (DNS must already point at the new node to pass HTTP-01), and litestream restores the DB but NOT the acme-cache. The Cloudflare Tunnel (T2) dissolves both: stable CNAME (DNS never moves) + TLS at the CF edge (no per-node cert). The `cloudflare-tunnel-token-mesh` vault key is already provisioned but unused — the tunnel path was staged and never wired.")
//!
//! @yah:ticket(R591-F1, "Re-home headscale as a kamaji-supervised pinned-singleton appliance (retire raw systemctl)")
//! @yah:at(2026-07-02T17:35:04Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R591)
//! @yah:next("leader.rs::on_became_leader drives headscale via `systemctl enable --now headscale` (raw systemd). Re-home it as a kamaji-supervised workload with the R572 'appliance' archetype (pinned, single-instance, non-drainable). Placement start/stop flows through kamaji, not systemctl — same supervisor as every other workload.")
//! @yah:next("INTERIM (applied 2026-07-16): the raw headscale.service was hardened `Restart=on-failure` -> `Restart=always` as a reboot-safety bridge for the SPOF coordinator. Cutover to kamaji MUST preserve an equivalent always-restart-including-graceful-exit guarantee — do NOT retire the systemd unit until kamaji actively supervises the appliance (see gotchas + R406).")
//! @yah:gotcha("MOTIVATING INCIDENT (2026-07-16): the SPOF mesh coordinator's raw headscale.service was DEAD for 7 days. Root cause — `headscale serve` exits 0 on SIGTERM (graceful shutdown), and the unit's `Restart=on-failure` does NOT restart a clean exit-0; a boot-race SIGTERM at boot (2026-07-09 09:00:47 UTC, us-west-001) killed it and it never came back. Whole tailnet degraded: operator laptop + us-east-001/us-south-001 (2 of 3 raft voters) fell off-mesh. A kamaji pinned-singleton appliance MUST treat graceful-exit as restart-worthy, not just crash.")
//! @yah:gotcha("TWO native backends — the FLEET gate is kamaji-bin, NOT kamaji-core. The coordinator (us-west-001) runs kamaji.service = the kamaji-bin binary (pid observed: /usr/local/bin/kamaji --socket /run/kamaji/kamaji.sock); yubaba deploys to it over UDS via the sibling KamajiClient. oss/kamaji/crates/kamaji-bin/src/native.rs fork+execs + reaps zombies (R406-T6 pidfd loop) but has ZERO RestartPolicy handling — no respawn. oss/kamaji/crates/kamaji/src/native.rs (kamaji-core) is a SEPARATE inlined backend (desktop/CI + yubaba's in-process `runtime` fallback). So re-homing headscale via leader.rs active_backend() routes to kamaji-bin on the fleet, which won't restart it — the same regression one layer over. The fleet restart loop must hook restart-per-policy into kamaji-bin's pidfd-reaper ExitEvent path (R406-T6 territory, in review).")
//! @yah:gotcha("STATUS 2026-07-16: kamaji-core native restart loop DONE + tested — spec-retaining supervisor task (Always w/ fixed delay, OnFailure w/ max_attempts+exp backoff, Never), publishes WorkloadStatus::Restarting, restart_workload now works in-place, graceful_upgrade preserved; 24 kamaji lib tests green (3 new) + example + `cargo check --workspace --all-features` clean. This covers the INLINED backend ONLY. Remaining gate before leader.rs can retire systemctl: the same loop in kamaji-bin's native supervisor. leader.rs re-home intentionally NOT written yet to avoid routing the coordinator's headscale to an unsupervised backend.")

use std::sync::Arc;

use openraft::async_runtime::watch::WatchReceiver;
use tracing::{error, info, warn};

use crate::litestream;
use crate::raft::{YubabaNodeId, YubabaRaft, YubabaRequest};
use crate::ServerState;

/// Spawn the leadership watcher.  The returned `JoinHandle` can be aborted on
/// daemon shutdown, but the watcher will also exit on its own when the raft
/// metrics channel closes.
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state: Arc<ServerState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state).await;
    })
}

async fn run(node_id: YubabaNodeId, raft: YubabaRaft, state: Arc<ServerState>) {
    let mut watch = raft.metrics();
    let mut prev_is_leader = false;

    loop {
        let is_leader = {
            let metrics = watch.borrow_watched();
            metrics.current_leader == Some(node_id)
        };

        if is_leader != prev_is_leader {
            info!(node_id, is_leader, "raft leader state changed");
            if is_leader {
                on_became_leader(node_id, &raft, &state).await;
            } else {
                on_lost_leader(&state).await;
            }
            prev_is_leader = is_leader;
        }

        if watch.changed().await.is_err() {
            warn!("raft metrics watch closed — leader watcher exiting");
            break;
        }
    }
}

async fn on_became_leader(_node_id: YubabaNodeId, raft: &YubabaRaft, state: &Arc<ServerState>) {
    let headscale_db = state.headscale_dir.join("headscale.db");

    // 1. Restore from S3 (no-op if no snapshot exists yet).
    if let Some(s3_url) = &state.litestream_s3_url {
        match litestream::restore(&headscale_db, s3_url).await {
            Ok(()) => info!("litestream restore complete"),
            Err(e) => warn!(
                "litestream restore failed (continuing — headscale may start from local DB): {e}"
            ),
        }
    }

    // 2. Start headscale.
    let hs_ok = std::process::Command::new("systemctl")
        .args(["enable", "--now", "headscale"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !hs_ok {
        warn!("systemctl start headscale failed — may already be running or systemd unavailable");
    } else {
        info!("headscale started");
    }

    // 3. Start litestream sidecar.
    if state.litestream_s3_url.is_some() {
        litestream::start();
        info!("litestream-headscale sidecar started");
    }

    // 4. Claim ingress owner in raft state machine so `yah mesh status` can
    //    show which machine is serving Headscale.
    if let Some(machine) = derive_machine_name() {
        let req = YubabaRequest::SetIngressOwner { machine };
        match raft.client_write(req).await {
            Ok(_) => info!("ingress owner set in raft state"),
            Err(e) => error!("failed to set ingress owner in raft: {e}"),
        }
    }
}

async fn on_lost_leader(state: &Arc<ServerState>) {
    // 1. Stop litestream replicate (followers don't replicate).
    if state.litestream_s3_url.is_some() {
        litestream::stop();
        info!("litestream-headscale sidecar stopped");
    }

    // 2. Stop headscale.  `/mesh/leader-health` will return 503 automatically.
    let _ = std::process::Command::new("systemctl")
        .args(["stop", "headscale"])
        .status();
    info!("headscale stopped on leadership loss");
}

/// Best-effort: derive a human-readable machine name for the ingress-owner
/// claim.  Reads `/etc/hostname` (Linux cloud VMs), then falls back to the
/// `HOSTNAME` env var.
fn derive_machine_name() -> Option<String> {
    if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
        let name = s.trim().to_string();
        if !name.is_empty() {
            return Some(name);
        }
    }
    std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty())
}
