//! Leader-resident rollout supervisor (R118-T5, W138 §"Coordinated N-node
//! rollout with rollback").
//!
//! The half of the power-loss case that replication alone does not solve.
//! Committing rollout state to raft means a new leader *can* see that a rollout
//! was in flight; it does not mean anybody picks it back up. R278-F1 spawned
//! the engine from the `POST /v1/rollouts` handler as a bare, unsupervised
//! `tokio::spawn`, so when that node lost power the rollout simply stopped —
//! mid-fleet, with half the rig on the new image and nothing left running that
//! knew it.
//!
//! This loop is what picks it up.
//!
//! # Shape: the same loop as `scheduler` and `leader_pin`
//!
//! [`spawn`]ed **unconditionally on every node**. A follower's tick finds it is
//! not the leader and does nothing, so there is no start/stop edge to get wrong
//! across an election. It carries no rollout state of its own between ticks:
//! every tick re-reads [`YubabaStateMachine::rollouts`], which is the committed
//! log replayed, so a node that has never run a rollout in its life reaches the
//! same conclusions its dead predecessor would have, one tick later.
//!
//! # Starting is resuming
//!
//! `POST /v1/rollouts` commits a `Pending` record and returns. It does *not*
//! spawn an engine. The leader's supervisor claims that record on its next tick
//! through the identical code path that claims a rollout inherited from a dead
//! leader — so the resume path is exercised by every rollout the fleet ever
//! runs, instead of being a branch that only executes during the incident it
//! was written for.
//!
//! # Why one node drives, and how it stops
//!
//! Two drivers on one rig means two image generations playing, which is the
//! failure W138 names. Three things prevent it, and each covers a case the
//! others do not:
//!
//! 1. **Only the leader claims.** A follower never spawns an engine.
//! 2. **Losing leadership aborts.** The moment a tick sees this node is not the
//!    leader it aborts every engine it started, rather than waiting for them to
//!    notice.
//! 3. **Every engine write is a leader write.** Between (2)'s ticks an engine's
//!    `client_write` fails with `ForwardToLeader` and it terminates itself —
//!    see [`super::engine`]. The abort is the fast path, this is the guarantee.
//!
//! A returning node re-drives nothing, for a simpler reason: it reads the same
//! committed record everyone else does, and a rollout somebody finished is not
//! `is_in_flight`.

use std::collections::HashMap;
use std::time::Duration;

use tracing::{info, warn};

use super::{engine::RolloutEngine, RolloutRecord};
use crate::cluster_policy::RaftTiming;
use crate::raft::{RolloutWriteOutcome, YubabaNodeId, YubabaRaft, YubabaStateMachine};

/// How long a terminal rollout is kept in cluster state before the leader
/// clears it.
///
/// Long enough that an operator investigating the morning after a failed
/// overnight rollout still finds it, and the bound on how far
/// `YubabaState::rollouts` can grow.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

pub struct SupervisorConfig {
    /// How often to look for rollouts to claim.
    pub evaluate_every: Duration,
    /// Prometheus base URL handed to each engine's gate evaluator. `None` puts
    /// gates in stub mode — see [`super::gate`].
    pub prometheus_url: Option<String>,
    /// Age past which a *terminal* rollout is cleared from cluster state.
    ///
    /// Measured from the rollout's start, not its end, because the record
    /// carries no completion time. The difference only shows for a rollout that
    /// ran for longer than the retention itself, and then only by retiring it
    /// promptly rather than late — acceptable for a record nothing acts on.
    pub retention: Duration,
}

impl SupervisorConfig {
    /// Paced off the cluster's own raft heartbeat, like
    /// [`crate::scheduler::SchedulerConfig::new`]: a WAN fleet and a LAN rig
    /// should not be swept at the same rate.
    pub fn new(timing: RaftTiming, prometheus_url: Option<String>) -> Self {
        Self {
            evaluate_every: Duration::from_millis(timing.heartbeat_interval_ms.max(1)) * 2,
            prometheus_url,
            retention: DEFAULT_RETENTION,
        }
    }
}

/// Spawn the rollout supervisor. Safe — and required — on every node.
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    config: SupervisorConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state_machine, config).await;
    })
}

async fn run(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    config: SupervisorConfig,
) {
    use openraft::async_runtime::watch::WatchReceiver;

    info!(
        node_id,
        evaluate_every = ?config.evaluate_every,
        "rollout supervisor active"
    );
    let watch = raft.metrics();
    // Engines this node is driving right now, keyed by rollout id. Not a
    // record of what has been done — that is in raft — only of what is
    // in-process, so it is correct for this loop to lose it on demotion.
    let mut driving: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();

    loop {
        tokio::time::sleep(config.evaluate_every).await;

        if watch.borrow_watched().current_leader != Some(node_id) {
            for (rollout_id, handle) in driving.drain() {
                warn!(
                    node_id,
                    %rollout_id,
                    "no longer the leader; abandoning this rollout to whoever is"
                );
                handle.abort();
            }
            continue;
        }

        driving.retain(|_, handle| !handle.is_finished());

        let now = super::now_unix_secs();
        for (rollout_id, raw) in state_machine.rollouts() {
            if driving.contains_key(&rollout_id) {
                continue;
            }
            let record = RolloutRecord::from_raft(&raw);
            if !record.status.is_in_flight() {
                if now.saturating_sub(record.created_at) >= config.retention.as_secs() {
                    clear(&raft, record.revision, &rollout_id).await;
                }
                continue;
            }

            info!(
                node_id,
                %rollout_id,
                artifact = %record.artifact,
                step = record.current_step,
                status = ?record.status,
                "claiming rollout"
            );
            let engine = RolloutEngine::new(
                record,
                raft.clone(),
                state_machine.clone(),
                config.prometheus_url.clone(),
            );
            driving.insert(rollout_id, tokio::spawn(engine.run()));
        }
    }
}

/// Retire a terminal rollout from cluster state, guarded on the revision it was
/// read at.
///
/// Neither failure here is an event worth escalating: the record stays, and the
/// next tick re-reads and tries again. A `Stale` rejection specifically means
/// the record moved between this tick's read and this write — somebody
/// overrode or revived it — and deleting it anyway is precisely the clobber the
/// revision exists to refuse.
async fn clear(raft: &YubabaRaft, expected_revision: u64, rollout_id: &str) {
    match super::clear_guarded(raft, expected_revision, rollout_id).await {
        Ok(RolloutWriteOutcome::Committed { .. }) => {
            info!(%rollout_id, "cleared retired rollout from cluster state")
        }
        Ok(RolloutWriteOutcome::Stale { current_revision }) => info!(
            %rollout_id,
            expected_revision,
            current_revision,
            "retired rollout moved under the retirement decision; leaving it alone"
        ),
        Err(e) => warn!(%rollout_id, error = %e, "could not clear retired rollout; will retry"),
    }
}
