//! Rollout subsystem — in-process store + engine + gate evaluator.
//!
//! In yubaba v1 (degenerate-raft mode, R277 not yet live), rollout state
//! lives in `RolloutStore` behind an `Arc<Mutex<>>` on `ServerState`. When
//! R277 lands, the store migrates to raft state (`YubabaState.rollouts`); the
//! `YubabaRequest` variants for rollout writes are already defined in
//! `crates/yah/yubaba/src/raft/mod.rs` so the raft path compiles even today.

pub mod engine;
pub mod gate;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use workload_spec::rollout::RolloutPolicy;

// ── ID generation ─────────────────────────────────────────────────────────────

static ROLLOUT_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_rollout_id() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let seq = ROLLOUT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("rt-{t:x}-{seq:04x}")
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// In-process rollout registry (degenerate-raft v1).
///
/// Replaced by raft-replicated state (see `YubabaState.rollouts`) once
/// R277 cluster-mesh-1 lands and raft is live.
#[derive(Default)]
pub struct RolloutStore {
    rollouts: HashMap<String, RolloutRecord>,
}

impl RolloutStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new rollout record, return its ID.
    pub fn create(
        &mut self,
        artifact: String,
        policy: RolloutPolicy,
        trigger: serde_json::Value,
    ) -> String {
        let rollout_id = next_rollout_id();
        self.rollouts.insert(
            rollout_id.clone(),
            RolloutRecord {
                rollout_id: rollout_id.clone(),
                artifact,
                policy,
                trigger,
                status: RolloutStatus::Pending,
                current_step: 0,
                created_at: now_unix_secs(),
            },
        );
        rollout_id
    }

    pub fn get(&self, id: &str) -> Option<&RolloutRecord> {
        self.rollouts.get(id)
    }

    /// List all rollouts, newest first.
    pub fn list(&self) -> Vec<&RolloutRecord> {
        let mut v: Vec<&RolloutRecord> = self.rollouts.values().collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        v
    }

    pub fn update_status(&mut self, id: &str, status: RolloutStatus) {
        if let Some(r) = self.rollouts.get_mut(id) {
            r.status = status;
        }
    }

    pub fn update_step(&mut self, id: &str, step: usize) {
        if let Some(r) = self.rollouts.get_mut(id) {
            r.current_step = step;
        }
    }
}

// ── Domain types ──────────────────────────────────────────────────────────────

/// A single rollout in progress (or completed).
#[derive(Debug, Clone, Serialize)]
pub struct RolloutRecord {
    pub rollout_id: String,
    /// Artifact URI, e.g. `"release:yah-marketing@v1.2.3"`.
    pub artifact: String,
    /// Resolved rollout policy.
    pub policy: RolloutPolicy,
    /// Trigger metadata from the HTTP request (opaque JSON).
    pub trigger: serde_json::Value,
    pub status: RolloutStatus,
    /// Index of the next step to execute (0-based).
    pub current_step: usize,
    /// Unix seconds at creation time.
    pub created_at: u64,
}

/// Lifecycle state of a rollout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RolloutStatus {
    /// Accepted; engine not yet started.
    Pending,
    /// Engine is running (deploying or waiting gate window).
    Running,
    /// All steps promoted; rollout complete.
    Succeeded,
    /// A gate failed or an unrecoverable error occurred.
    Failed { reason: String },
    /// A gate failed and the on_failure action rolled back mirrors.
    RolledBack { step: usize, reason: String },
    /// Operator forced a state change via `POST /v1/rollouts/{id}/override`.
    Overridden { action: String, by: String },
}

// ── Override action ───────────────────────────────────────────────────────────

/// Valid override actions for `POST /v1/rollouts/{id}/override`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverrideAction {
    /// Skip the current gate window and promote the current step.
    Promote,
    /// Abort the rollout and roll back all promoted steps.
    Rollback,
}

/// Helper to snapshot the store behind a shared lock for serialization.
pub fn snapshot_record(
    store: &Arc<std::sync::Mutex<RolloutStore>>,
    id: &str,
) -> Option<RolloutRecord> {
    store.lock().unwrap().get(id).cloned()
}
