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

use std::sync::Arc;
use tracing::{error, info, warn};

use crate::litestream;
use crate::raft::{WardenNodeId, WardenRaft, WardenRequest};
use crate::ServerState;

/// Spawn the leadership watcher.  The returned `JoinHandle` can be aborted on
/// daemon shutdown, but the watcher will also exit on its own when the raft
/// metrics channel closes.
pub fn spawn(
    node_id: WardenNodeId,
    raft: WardenRaft,
    state: Arc<ServerState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state).await;
    })
}

async fn run(node_id: WardenNodeId, raft: WardenRaft, state: Arc<ServerState>) {
    let mut watch = raft.metrics();
    let mut prev_is_leader = false;

    loop {
        let is_leader = {
            let metrics = watch.borrow();
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

async fn on_became_leader(_node_id: WardenNodeId, raft: &WardenRaft, state: &Arc<ServerState>) {
    let headscale_db = state.headscale_dir.join("headscale.db");

    // 1. Restore from S3 (no-op if no snapshot exists yet).
    if let Some(s3_url) = &state.litestream_s3_url {
        match litestream::restore(&headscale_db, s3_url).await {
            Ok(()) => info!("litestream restore complete"),
            Err(e) => warn!("litestream restore failed (continuing — headscale may start from local DB): {e}"),
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
        let req = WardenRequest::SetIngressOwner { machine };
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
