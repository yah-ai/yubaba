//! R869 (W339): the off-fleet copy of the applied [`YubabaState`].
//!
//! Every other input a cluster needs to exist already survives the loss of all
//! its machines — the KEK and the declared secret plaintexts are in the fob
//! vault, the machine config is in `.yah/infra/machines/`, and the certs plus
//! the enrollment set are object-store-backed by R779. Only the raft state
//! machine had no copy anywhere but the three voters' disks, which is why the
//! de-facto total-loss procedure on 2026-08-31 was *wipe the raft dir*
//! (`raft/store.rs:40`). This module is that missing copy.
//!
//! ## Why an object and not a replicator
//!
//! `raft/store.rs` already rewrites `raft_state.json` whole on every mutation
//! and the state is KB-scale, so "the copy" is one small JSON object per
//! cluster. There is nothing to stream and nothing to reconcile: the leader
//! PUTs the applied state, and a rebuild GETs it. Litestream and turso-backup
//! both replicate a sqlite database; this is a map of maps.
//!
//! ## The guard is the load-bearing part
//!
//! An unguarded backup would have been *worthless in the incident it exists
//! for*. On 2026-08-31 the recovery was to wipe the raft dir on all three
//! voters; a backup task that simply PUT whatever the local state machine held
//! would have overwritten the only good copy with the empty state within one
//! tick of the first node coming back. So [`StateBackup::store`] refuses to
//! write a snapshot whose `applied_index` is **below** the stored one and says
//! so loudly, and the fleet's backup stays parked on the last good copy until
//! an operator says otherwise.
//!
//! "Otherwise" is [`StateBackup::adopt`]: it archives the current object under
//! `lineage/<n>.json` — the one moment that copy would otherwise become
//! unreachable — and bumps `lineage`, resetting the `applied_index` floor to 0
//! so the rebuilt cluster's next tick takes over. No node carries a lineage
//! locally; each one carries forward whatever `latest.json` says, so the object
//! is the only authority and a node needs no state of its own to participate.
//!
//! ## What a restore does and does not buy
//!
//! [`restorable`] is the state to seed a fresh raft dir with
//! ([`crate::raft::store::seed_state_machine`]). It drops `locks` and
//! `rollouts` deliberately — see its doc.
//!
//! It also restores `tenants`, which means the rebuilt cluster keeps the
//! fencing epochs the dead one granted instead of restarting at 1. That closes
//! most of W339's correctness half: a survivor's epoch is fixed at its last
//! applied `ClaimTenant`, so it is at most the snapshot's, and the rebuilt
//! cluster's next claim grants snapshot + 1 and out-fences it. **Most, not
//! all** — epochs granted after the last snapshot are not in the copy, and no
//! number readable from R2 bounds them. Only the off-fleet
//! `yah_tenant_pointer` generation closes that remainder, and carrying it is
//! R736-F6's ratified call, not this module's.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use yah_object_store::{Error as ObjectError, ObjectStore, Precondition};

use crate::raft::{YubabaNodeId, YubabaState};

/// Env key naming the cluster whose state this node backs up. Its presence is
/// what turns the backup on.
///
/// It is a name, not a derivation: two clusters sharing one bucket must not
/// share one key, and nothing else a node knows about itself is stable across
/// the rebuild this exists for (node ids are reused, addresses move, the raft
/// dir is gone by definition).
pub const CLUSTER_ENV: &str = "YUBABA_STATE_BACKUP_CLUSTER";

/// Env key overriding how often the leader ships a copy, in seconds.
pub const INTERVAL_ENV: &str = "YUBABA_STATE_BACKUP_INTERVAL_SECS";

/// Default cadence. The write is skipped entirely when nothing has been applied
/// since the last one, so on an idle cluster this costs one GET per minute.
pub const DEFAULT_INTERVAL_SECS: u64 = 60;

/// Key root, under the same bucket [`crate::cert_store`] uses.
///
/// Deliberately the same bucket and the same credentials: a disaster-recovery
/// mechanism that needs config the fleet does not already carry is one that is
/// not there when the disaster happens.
pub const KEY_ROOT: &str = "cluster-state";

/// Where the current copy lives.
pub fn latest_key(cluster: &str) -> String {
    format!("{KEY_ROOT}/{cluster}/latest.json")
}

/// Where [`StateBackup::adopt`] parks the copy a lineage bump retires.
pub fn lineage_key(cluster: &str, lineage: u64) -> String {
    format!("{KEY_ROOT}/{cluster}/lineage/{lineage:020}.json")
}

/// One off-fleet copy of the applied state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Which incarnation of this cluster wrote it. Bumped only by
    /// [`StateBackup::adopt`]; carried forward untouched by every ordinary
    /// write, so a node never has to know its own.
    pub lineage: u64,
    /// The raft applied index `state` is true as of. The monotonicity guard
    /// compares on this and nothing else.
    pub applied_index: u64,
    /// Unix seconds the copy was taken, for an operator reading staleness.
    pub taken_at: u64,
    /// Which node shipped it — the leader at the time.
    pub node_id: YubabaNodeId,
    /// `CARGO_PKG_VERSION` of the writer, so a restore can see whether the copy
    /// predates a state-machine schema move.
    pub version: String,
    /// The payload.
    pub state: YubabaState,
}

/// What one [`StateBackup::store`] attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    /// The copy advanced.
    Wrote { lineage: u64, applied_index: u64 },
    /// Nothing has been applied since the last copy. The common case on an idle
    /// cluster, and not worth a PUT.
    Unchanged { applied_index: u64 },
    /// **Refused.** The local state machine is behind the stored copy, which is
    /// what a wiped raft dir looks like from here. The stored copy is left
    /// alone; an operator resolves it with [`StateBackup::adopt`].
    Regressed { stored: u64, local: u64 },
    /// Another node's CAS landed first. Harmless — that node wrote a copy at
    /// least as new as ours would have been. Retried on the next tick.
    Raced,
}

/// Reader/writer for one cluster's off-fleet copy.
pub struct StateBackup {
    objects: Arc<dyn ObjectStore>,
    cluster: String,
}

impl StateBackup {
    pub fn new(objects: Arc<dyn ObjectStore>, cluster: impl Into<String>) -> Self {
        Self {
            objects,
            cluster: cluster.into(),
        }
    }

    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// Where the current copy lives, in a form an operator can act on.
    pub fn locate_latest(&self) -> String {
        self.objects.locate(&latest_key(&self.cluster))
    }

    /// The current copy, or `None` when this cluster has never shipped one.
    ///
    /// `None` is not `StateSnapshot::default()`: "no cluster has ever backed up
    /// here" and "a cluster backed up an empty state" are different answers, and
    /// a rebuild about to seed a raft dir needs the difference.
    pub fn read_latest(&self) -> Result<Option<StateSnapshot>, ObjectError> {
        self.read_key(&latest_key(&self.cluster))
    }

    /// A copy retired by an earlier [`Self::adopt`] — the state as it stood
    /// immediately before that lineage bump.
    pub fn read_lineage(&self, lineage: u64) -> Result<Option<StateSnapshot>, ObjectError> {
        self.read_key(&lineage_key(&self.cluster, lineage))
    }

    /// Every retired lineage, oldest first.
    pub fn lineages(&self) -> Result<Vec<u64>, ObjectError> {
        let prefix = format!("{KEY_ROOT}/{}/lineage/", self.cluster);
        let mut out: Vec<u64> = self
            .objects
            .list_prefix(&prefix)?
            .iter()
            .filter_map(|k| k.strip_prefix(&prefix))
            .filter_map(|n| n.strip_suffix(".json"))
            .filter_map(|n| n.parse().ok())
            .collect();
        out.sort_unstable();
        Ok(out)
    }

    fn read_key(&self, key: &str) -> Result<Option<StateSnapshot>, ObjectError> {
        let Some(bytes) = self.objects.get(key)? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes).map(Some).map_err(|e| {
            ObjectError::Backend(format!(
                "{} is not a readable state snapshot: {e}",
                self.objects.locate(key)
            ))
        })
    }

    /// Ship `state` as of `applied_index`, if it is newer than what is stored.
    ///
    /// The whole decision is `applied_index` against the stored one — see
    /// [`Stored`] for each outcome. The write is a compare-and-swap against the
    /// ETag read in the same call, so two nodes that both believe they are
    /// leader cannot interleave a stale copy over a fresh one.
    pub fn store(
        &self,
        state: &YubabaState,
        applied_index: u64,
        node_id: YubabaNodeId,
        now: u64,
    ) -> Result<Stored, ObjectError> {
        let key = latest_key(&self.cluster);
        // ETag BEFORE bytes, and the order is load-bearing. Read the other way
        // round, a copy that lands between the two reads is decided against the
        // *old* bytes and CAS'd under the *new* ETag — so a stale write wins and
        // the monotonicity guard, the entire point of this method, is bypassed.
        // This way a write landing in the gap can only make the CAS fail, which
        // is `Raced` and harmless.
        let etag = self.objects.etag(&key)?;
        let current = self.objects.get(&key)?;
        let (lineage, cond) = match (&current, etag) {
            (None, _) => (1, Precondition::IfAbsent),
            (Some(bytes), etag) => {
                let stored: StateSnapshot = serde_json::from_slice(bytes).map_err(|e| {
                    ObjectError::Backend(format!(
                        "{} is not a readable state snapshot: {e}",
                        self.objects.locate(&key)
                    ))
                })?;
                if applied_index < stored.applied_index {
                    return Ok(Stored::Regressed {
                        stored: stored.applied_index,
                        local: applied_index,
                    });
                }
                if applied_index == stored.applied_index {
                    return Ok(Stored::Unchanged { applied_index });
                }
                // No ETag but bytes present: the object appeared in the gap, so
                // an IfAbsent CAS is the honest comparand — it fails, and the
                // next tick reads the object that beat us.
                let cond = match etag {
                    Some(e) => Precondition::IfMatch(e),
                    None => Precondition::IfAbsent,
                };
                (stored.lineage, cond)
            }
        };

        let snapshot = StateSnapshot {
            lineage,
            applied_index,
            taken_at: now,
            node_id,
            version: crate::VERSION.to_string(),
            state: state.clone(),
        };
        match self
            .objects
            .put_if(&key, serde_json::to_vec(&snapshot).unwrap(), cond)
        {
            Ok(_) => Ok(Stored::Wrote {
                lineage,
                applied_index,
            }),
            Err(ObjectError::PreconditionFailed(_)) => Ok(Stored::Raced),
            Err(e) => Err(e),
        }
    }

    /// Accept that the live cluster is a new incarnation, and let it start
    /// backing up again.
    ///
    /// Archives the current copy under [`lineage_key`] *first* — that copy is
    /// the pre-rebuild state, i.e. the only thing worth having — then rewrites
    /// `latest.json` with the next lineage and an `applied_index` of 0, so the
    /// leader's next tick wins the monotonicity check.
    ///
    /// The archived copy is left as the *payload* of the reset object too, on
    /// purpose: until the rebuilt cluster has applied anything, the honest
    /// answer to "what would a restore give me" is still the old state.
    ///
    /// Returns the new lineage. Refuses when nothing is stored — there is no
    /// incarnation to succeed, and the ordinary write path already handles a
    /// cluster that has never backed up.
    pub fn adopt(&self, now: u64) -> Result<u64, ObjectError> {
        let key = latest_key(&self.cluster);
        // ETag before bytes — see the note in `store`.
        let etag = self.objects.etag(&key)?;
        let Some(bytes) = self.objects.get(&key)? else {
            return Err(ObjectError::NotFound(format!(
                "{} holds no state copy to adopt — nothing has ever been backed up for cluster \
                 {}, so the ordinary backup path will claim it on the next tick",
                self.objects.locate(&key),
                self.cluster
            )));
        };
        let etag = etag.ok_or_else(|| {
            ObjectError::PreconditionFailed(format!(
                "{} appeared while adopting it — a node is still writing copies. Stop the fleet's \
                 leader, or re-run once it is quiet.",
                self.objects.locate(&key)
            ))
        })?;
        let stored: StateSnapshot = serde_json::from_slice(&bytes).map_err(|e| {
            ObjectError::Backend(format!(
                "{} is not a readable state snapshot: {e}",
                self.objects.locate(&key)
            ))
        })?;

        self.objects
            .put(&lineage_key(&self.cluster, stored.lineage), bytes.clone())?;

        let reset = StateSnapshot {
            lineage: stored.lineage + 1,
            applied_index: 0,
            taken_at: now,
            ..stored
        };
        self.objects
            .put_if(
                &key,
                serde_json::to_vec(&reset).unwrap(),
                Precondition::IfMatch(etag),
            )
            .map_err(|e| match e {
                ObjectError::PreconditionFailed(_) => ObjectError::PreconditionFailed(format!(
                    "{} changed while adopting it — a node is still writing copies. Stop the \
                     fleet's leader, or re-run once it is quiet.",
                    self.objects.locate(&key)
                )),
                other => other,
            })?;
        Ok(reset.lineage)
    }
}

/// The state to seed a fresh raft dir with, given an off-fleet copy.
///
/// Two maps are dropped, and both drops are the point rather than a
/// simplification:
///
/// - **`locks`** are liveness leases, and on a rebuild every holder is dead by
///   construction. Carrying one in would stall the new cluster for the rest of
///   its TTL on a lock nobody will ever release — R600-F10 spent a day blocked
///   on exactly that shape, a squatted `acme-issuer/yah.dev` lease with an
///   86400s TTL and no renewer, and that was a *live* cluster with a real
///   owner. In a disaster it is strictly worse.
/// - **`rollouts`** are in-flight deploy state. W339 calls this out: a rebuild
///   may legitimately abandon it, and resuming a rollout whose orchestrator no
///   longer exists is not a recovery, it is a second incident.
///
/// Everything else is kept, including `tenants` — see the module docs for what
/// keeping the fencing epochs does and does not buy.
pub fn restorable(snapshot: StateSnapshot) -> YubabaState {
    YubabaState {
        locks: Default::default(),
        rollouts: Default::default(),
        ..snapshot.state
    }
}

/// Node-level config: which cluster, how often.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateBackupConfig {
    pub cluster: String,
    pub interval: Duration,
}

impl StateBackupConfig {
    /// `Ok(None)` when [`CLUSTER_ENV`] is unset — the backup is opt-in.
    ///
    /// A cluster name with no cert-store bucket is a hard error rather than a
    /// silent skip, for the same reason [`crate::cert_store::CertStoreConfig`]
    /// treats a half-configured store that way: an off-fleet copy that quietly
    /// does not exist is discovered during the disaster.
    pub fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let cluster = match get(CLUSTER_ENV) {
            Some(c) if !c.trim().is_empty() => c.trim().to_string(),
            _ => return Ok(None),
        };
        if crate::cert_store::CertStoreConfig::parse(&get)?.is_none() {
            return Err(format!(
                "{CLUSTER_ENV} is set but {} is not — the state backup writes to the same bucket \
                 the cert store uses, so both must be configured together",
                crate::cert_store::BUCKET_ENV
            ));
        }
        let interval = match get(INTERVAL_ENV) {
            Some(s) if !s.trim().is_empty() => s
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("{INTERVAL_ENV} must be whole seconds: {e}"))?,
            _ => DEFAULT_INTERVAL_SECS,
        };
        if interval == 0 {
            return Err(format!("{INTERVAL_ENV} must be greater than zero"));
        }
        Ok(Some(Self {
            cluster,
            interval: Duration::from_secs(interval),
        }))
    }
}

/// Open a [`StateBackup`] straight from the environment — the `yubaba state`
/// verbs' entry point.
///
/// Needs no daemon, no quorum and no leader: the copy is an object, and the
/// machine a rebuild runs from is by definition not part of a cluster yet.
pub fn connect_from_env(get: impl Fn(&str) -> Option<String>) -> Result<StateBackup, String> {
    let cfg = StateBackupConfig::parse(&get)?.ok_or(format!(
        "{CLUSTER_ENV} is unset — name the cluster whose off-fleet copy to act on"
    ))?;
    // `parse` already refused a cluster without a bucket, so this is present.
    let store = crate::cert_store::CertStoreConfig::parse(&get)?
        .expect("cert store config validated by StateBackupConfig::parse");
    let objects = store
        .connect_objects()
        .map_err(|e| format!("opening bucket {}: {e}", store.bucket))?;
    Ok(StateBackup::new(objects, cfg.cluster))
}

/// Start the backup loop. Runs on every node; only the leader ships a copy, so
/// a follower's tick is a no-op — the same shape as [`crate::headroom`].
pub fn spawn(
    node_id: YubabaNodeId,
    raft: crate::raft::YubabaRaft,
    state_machine: crate::raft::store::YubabaStateMachine,
    objects: Arc<dyn ObjectStore>,
    config: StateBackupConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state_machine, objects, config).await;
    })
}

async fn run(
    node_id: YubabaNodeId,
    raft: crate::raft::YubabaRaft,
    state_machine: crate::raft::store::YubabaStateMachine,
    objects: Arc<dyn ObjectStore>,
    config: StateBackupConfig,
) {
    use openraft::async_runtime::watch::WatchReceiver;

    let backup = StateBackup::new(objects, config.cluster.clone());
    tracing::info!(
        node_id,
        cluster = %config.cluster,
        object = %backup.locate_latest(),
        interval_secs = config.interval.as_secs(),
        "off-fleet state backup active"
    );
    let watch = raft.metrics();
    // Logged once per transition, not once per tick: a refusal is a standing
    // condition an operator resolves, and repeating it every minute would bury
    // the line that says it cleared.
    let mut warned_regressed = false;

    loop {
        tokio::time::sleep(config.interval).await;

        if watch.borrow_watched().current_leader != Some(node_id) {
            continue;
        }
        let (state, applied_index) = state_machine.applied_state();
        let Some(applied_index) = applied_index else {
            continue;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match backup.store(&state, applied_index, node_id, now) {
            Ok(Stored::Wrote {
                lineage,
                applied_index,
            }) => {
                warned_regressed = false;
                tracing::debug!(
                    node_id,
                    lineage,
                    applied_index,
                    "off-fleet state backup written"
                );
            }
            Ok(Stored::Unchanged { .. }) | Ok(Stored::Raced) => {}
            Ok(Stored::Regressed { stored, local }) => {
                if !warned_regressed {
                    warned_regressed = true;
                    tracing::error!(
                        node_id,
                        stored_applied_index = stored,
                        local_applied_index = local,
                        object = %backup.locate_latest(),
                        "off-fleet state backup REFUSED and is now stale: this node has applied \
                         only up to {local} but the stored copy is at {stored}. That is what a \
                         wiped raft dir looks like from here, so the copy is being protected \
                         rather than overwritten. If this cluster was deliberately rebuilt, run \
                         `yubaba state adopt` to accept the new incarnation; the pre-rebuild copy \
                         is archived first."
                    );
                }
            }
            Err(e) => tracing::warn!(
                node_id,
                object = %backup.locate_latest(),
                "off-fleet state backup failed (will retry next tick): {e}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::{LockEntry, RolloutRaftRecord};
    use std::collections::BTreeMap;
    use yah_object_store::InMemoryObjectStore;

    fn store() -> (Arc<InMemoryObjectStore>, StateBackup) {
        let mem = Arc::new(InMemoryObjectStore::new());
        let backup = StateBackup::new(mem.clone() as Arc<dyn ObjectStore>, "fleet");
        (mem, backup)
    }

    fn state_with(placement: &[(&str, &str)]) -> YubabaState {
        YubabaState {
            service_placement: placement
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn the_first_copy_starts_lineage_one() {
        let (mem, backup) = store();
        assert!(backup.read_latest().unwrap().is_none());
        assert_eq!(
            backup
                .store(&state_with(&[("web", "m1")]), 7, 1, 100)
                .unwrap(),
            Stored::Wrote {
                lineage: 1,
                applied_index: 7
            }
        );
        assert!(mem.contains_key(&latest_key("fleet")));
        let got = backup.read_latest().unwrap().unwrap();
        assert_eq!(got.lineage, 1);
        assert_eq!(got.applied_index, 7);
        assert_eq!(got.node_id, 1);
        assert_eq!(got.state.service_placement["web"], "m1");
    }

    /// The idle-cluster case: `applied_index` has not moved, so no PUT.
    #[test]
    fn an_unmoved_applied_index_costs_no_write() {
        let (mem, backup) = store();
        backup.store(&state_with(&[]), 7, 1, 100).unwrap();
        let before = mem.get(&latest_key("fleet")).unwrap().unwrap();
        assert_eq!(
            backup
                .store(&state_with(&[("web", "m1")]), 7, 1, 200)
                .unwrap(),
            Stored::Unchanged { applied_index: 7 }
        );
        assert_eq!(mem.get(&latest_key("fleet")).unwrap().unwrap(), before);
    }

    /// THE TEST THIS MODULE EXISTS FOR — the 2026-08-31 incident replayed.
    ///
    /// Three voters had their raft dirs wiped and came back with an empty state
    /// machine. An unguarded backup would have PUT that empty state over the
    /// only surviving copy of the cluster within one tick. Falsify by deleting
    /// the `applied_index < stored.applied_index` arm in [`StateBackup::store`].
    /// MEASURED, not predicted: it fails with `Wrote { lineage: 1,
    /// applied_index: 1 }` and the object is left holding the empty state —
    /// the incident, reproduced in a unit test.
    #[test]
    fn a_wiped_raft_dir_cannot_overwrite_the_good_copy() {
        let (_mem, backup) = store();
        let mut good = state_with(&[("web", "m1"), ("api", "m2")]);
        good.ingress_owner = Some("us-west-001".into());
        backup.store(&good, 193_466, 1, 100).unwrap();

        // The wiped node re-forms and applies its own founding membership.
        assert_eq!(
            backup.store(&YubabaState::default(), 1, 1, 200).unwrap(),
            Stored::Regressed {
                stored: 193_466,
                local: 1
            }
        );
        let still = backup.read_latest().unwrap().unwrap();
        assert_eq!(still.applied_index, 193_466);
        assert_eq!(still.state.service_placement.len(), 2);
        assert_eq!(still.state.ingress_owner.as_deref(), Some("us-west-001"));
    }

    /// And the way out of that refusal: `adopt` archives the good copy where a
    /// restore can still name it, then lets the new incarnation take over.
    #[test]
    fn adopt_archives_the_pre_rebuild_copy_before_yielding_to_the_new_one() {
        let (_mem, backup) = store();
        let good = state_with(&[("web", "m1")]);
        backup.store(&good, 193_466, 1, 100).unwrap();

        assert_eq!(backup.adopt(300).unwrap(), 2);
        assert_eq!(backup.lineages().unwrap(), vec![1]);
        let archived = backup.read_lineage(1).unwrap().unwrap();
        assert_eq!(archived.applied_index, 193_466);
        assert_eq!(archived.state.service_placement["web"], "m1");

        // The rebuilt cluster's small index now wins the guard.
        assert_eq!(
            backup.store(&YubabaState::default(), 1, 2, 400).unwrap(),
            Stored::Wrote {
                lineage: 2,
                applied_index: 1
            }
        );
        // …and the pre-rebuild copy is still exactly where adopt put it.
        assert_eq!(
            backup
                .read_lineage(1)
                .unwrap()
                .unwrap()
                .state
                .service_placement["web"],
            "m1"
        );
    }

    #[test]
    fn adopt_refuses_when_nothing_was_ever_backed_up() {
        let (_mem, backup) = store();
        let err = backup.adopt(100).unwrap_err();
        assert!(
            matches!(err, ObjectError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
    }

    /// Two nodes both believing they lead must not interleave a stale copy over
    /// a fresh one. The loser reports `Raced` and retries on its own clock.
    #[test]
    fn a_lost_compare_and_swap_is_reported_not_forced() {
        let (mem, backup) = store();
        backup.store(&state_with(&[]), 7, 1, 100).unwrap();

        // Hand-build the interleaving: read what node 1 would compare against,
        // then let node 2 land first.
        let stale_etag = mem.etag(&latest_key("fleet")).unwrap().unwrap();
        backup
            .store(&state_with(&[("web", "m9")]), 9, 2, 150)
            .unwrap();
        let fresh = mem.etag(&latest_key("fleet")).unwrap().unwrap();
        assert_ne!(stale_etag, fresh);

        let snapshot = StateSnapshot {
            lineage: 1,
            applied_index: 8,
            taken_at: 200,
            node_id: 1,
            version: "test".into(),
            state: YubabaState::default(),
        };
        let err = mem
            .put_if(
                &latest_key("fleet"),
                serde_json::to_vec(&snapshot).unwrap(),
                Precondition::IfMatch(stale_etag),
            )
            .unwrap_err();
        assert!(matches!(err, ObjectError::PreconditionFailed(_)));
        // Node 2's copy is intact.
        assert_eq!(
            backup
                .read_latest()
                .unwrap()
                .unwrap()
                .state
                .service_placement["web"],
            "m9"
        );
    }

    /// An object store that lets one write land **between the two reads**
    /// `store` makes, whichever order they are in.
    ///
    /// Keyed on the read *count*, not on which method — that is the whole
    /// point. A double that injected on `get` specifically would pass under
    /// either read order and pin nothing, which is what the first version of
    /// this test did.
    struct WritesAfterTheFirstRead {
        inner: Arc<InMemoryObjectStore>,
        reads: std::sync::atomic::AtomicUsize,
        inject: std::sync::Mutex<Option<Vec<u8>>>,
    }

    impl WritesAfterTheFirstRead {
        /// Serve `served`, then — if this was read #1 — land the racing write.
        fn after_first_read<T>(&self, key: &str, served: T) -> Result<T, ObjectError> {
            if self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                if let Some(bytes) = self.inject.lock().unwrap().take() {
                    self.inner.put(key, bytes)?;
                }
            }
            Ok(served)
        }
    }

    impl ObjectStore for WritesAfterTheFirstRead {
        fn put(&self, key: &str, data: Vec<u8>) -> Result<(), ObjectError> {
            self.inner.put(key, data)
        }
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ObjectError> {
            let served = self.inner.get(key)?;
            self.after_first_read(key, served)
        }
        fn delete(&self, key: &str) -> Result<(), ObjectError> {
            self.inner.delete(key)
        }
        fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, ObjectError> {
            self.inner.list_prefix(prefix)
        }
        fn put_if(
            &self,
            key: &str,
            data: Vec<u8>,
            cond: Precondition,
        ) -> Result<String, ObjectError> {
            self.inner.put_if(key, data, cond)
        }
        fn etag(&self, key: &str) -> Result<Option<String>, ObjectError> {
            let served = self.inner.etag(key)?;
            self.after_first_read(key, served)
        }
    }

    /// THE READ ORDER IS LOAD-BEARING, and this is the test that says so.
    ///
    /// FALSIFIED, not assumed: swapping the `etag` and `get` calls at the top of
    /// [`StateBackup::store`] fails this with `Wrote { lineage: 1,
    /// applied_index: 6 }` and leaves the object at applied index 6 — the copy
    /// walked backwards from 9. Read `get`-first, the decision is made against
    /// the stale bytes (applied 5, so 6 looks like an advance) and then CAS'd
    /// under the *fresh* ETag, so the CAS succeeds and the monotonicity guard is
    /// bypassed by a race rather than by a missing check. Read `etag`-first, a
    /// write in the gap can only make the CAS fail.
    ///
    /// The double keys on read *count* rather than on `get` specifically; an
    /// earlier version keyed on `get` and passed under both orders, pinning
    /// nothing.
    #[test]
    fn a_copy_landing_between_the_two_reads_cannot_be_overwritten_by_a_stale_one() {
        let mem = Arc::new(InMemoryObjectStore::new());
        let key = latest_key("fleet");
        let at = |applied_index: u64| {
            serde_json::to_vec(&StateSnapshot {
                lineage: 1,
                applied_index,
                taken_at: 100,
                node_id: 1,
                version: "test".into(),
                state: YubabaState::default(),
            })
            .unwrap()
        };
        mem.put(&key, at(5)).unwrap();

        let racing = Arc::new(WritesAfterTheFirstRead {
            inner: mem.clone(),
            reads: std::sync::atomic::AtomicUsize::new(0),
            inject: std::sync::Mutex::new(Some(at(9))),
        });
        let backup = StateBackup::new(racing as Arc<dyn ObjectStore>, "fleet");

        assert_eq!(
            backup.store(&YubabaState::default(), 6, 1, 200).unwrap(),
            Stored::Regressed {
                stored: 9,
                local: 6
            }
        );
        let survived: StateSnapshot =
            serde_json::from_slice(&mem.get(&key).unwrap().unwrap()).unwrap();
        assert_eq!(survived.applied_index, 9);
    }

    #[test]
    fn a_corrupt_object_is_an_error_not_an_empty_state() {
        let (mem, backup) = store();
        mem.put(&latest_key("fleet"), b"{not json".to_vec())
            .unwrap();
        assert!(backup.read_latest().is_err());
        assert!(backup.store(&YubabaState::default(), 5, 1, 100).is_err());
    }

    /// A restore drops the two maps whose holders are dead by construction.
    #[test]
    fn restorable_drops_leases_and_in_flight_rollouts_and_keeps_the_rest() {
        let mut state = state_with(&[("web", "m1")]);
        state.ingress_owner = Some("us-west-001".into());
        state.locks = BTreeMap::from([(
            "acme-issuer/yah.dev".to_string(),
            LockEntry {
                owner: "1".into(),
                acquired_at: 1_788_850_794,
                ttl_secs: 86_400,
            },
        )]);
        state.rollouts = BTreeMap::from([(
            "web".to_string(),
            RolloutRaftRecord {
                rollout_id: "r1".into(),
                artifact: "web:1".into(),
                status_json: "{}".into(),
                current_step: 1,
                started_at: 1_788_850_000,
                // R118-T5 widened the record with the policy a new leader needs
                // to resume. Irrelevant to this assertion — `restorable` drops
                // the whole map — but it has to be a well-formed record.
                policy: serde_json::from_value(serde_json::json!({
                    "strategy": "linear",
                    "window_seconds": 60,
                    "steps": [{ "mirrors": ["web"], "gate_window_seconds": 0 }]
                }))
                .expect("a linear one-step policy"),
                trigger: serde_json::Value::Null,
                revision: 1,
            },
        )]);

        let restored = restorable(StateSnapshot {
            lineage: 1,
            applied_index: 7,
            taken_at: 100,
            node_id: 1,
            version: "test".into(),
            state,
        });
        assert!(
            restored.locks.is_empty(),
            "a dead node's lease must not survive the rebuild"
        );
        assert!(restored.rollouts.is_empty());
        assert_eq!(restored.service_placement["web"], "m1");
        assert_eq!(restored.ingress_owner.as_deref(), Some("us-west-001"));
    }

    #[test]
    fn the_backup_is_off_until_a_cluster_is_named() {
        assert_eq!(StateBackupConfig::parse(|_| None).unwrap(), None);
    }

    #[test]
    fn a_cluster_without_a_bucket_is_an_error_not_a_silent_skip() {
        let err = StateBackupConfig::parse(|k| (k == CLUSTER_ENV).then(|| "fleet".to_string()))
            .unwrap_err();
        assert!(err.contains(crate::cert_store::BUCKET_ENV), "got {err}");
    }

    #[test]
    fn a_named_cluster_with_a_bucket_parses_and_defaults_its_interval() {
        let cfg = StateBackupConfig::parse(|k| match k {
            CLUSTER_ENV => Some("fleet".into()),
            crate::cert_store::BUCKET_ENV => Some("yah-certs".into()),
            crate::cert_store::ACCOUNT_ID_ENV => Some("acct123".into()),
            _ => None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(cfg.cluster, "fleet");
        assert_eq!(cfg.interval, Duration::from_secs(DEFAULT_INTERVAL_SECS));
    }

    #[test]
    fn a_zero_interval_is_refused() {
        let err = StateBackupConfig::parse(|k| match k {
            CLUSTER_ENV => Some("fleet".into()),
            INTERVAL_ENV => Some("0".into()),
            crate::cert_store::BUCKET_ENV => Some("yah-certs".into()),
            crate::cert_store::ACCOUNT_ID_ENV => Some("acct123".into()),
            _ => None,
        })
        .unwrap_err();
        assert!(err.contains(INTERVAL_ENV), "got {err}");
    }

    /// Lineage keys sort lexicographically in numeric order — zero-padded, so
    /// lineage 2 does not sort before lineage 10 in a bucket listing.
    #[test]
    fn lineage_keys_sort_in_numeric_order() {
        let mut keys = vec![
            lineage_key("fleet", 10),
            lineage_key("fleet", 2),
            lineage_key("fleet", 1),
        ];
        keys.sort();
        assert_eq!(
            keys,
            vec![
                lineage_key("fleet", 1),
                lineage_key("fleet", 2),
                lineage_key("fleet", 10)
            ]
        );
    }
}
