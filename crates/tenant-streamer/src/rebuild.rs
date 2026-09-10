//! Rebuilding a cluster from nothing: clearing the R2 fence a dead raft group
//! left behind (W339, R869).
//!
//! # The problem this exists for
//!
//! `ClaimTenant` grants `current_epoch + 1`, and `current_epoch` is `0` when
//! there is no record. Wipe the raft dir, re-form, and the first claim grants
//! epoch 1 — while the sink's `latest.stream-watermark` still carries the dead
//! fleet's epoch. `turso_backup::stream::tail_frames` bounces a writer when
//!
//! ```text
//! sidecar.epoch > cfg.epoch  ||  sidecar.pointer_generation > cfg.pointer_generation
//! ```
//!
//! so the rebuilt cluster is locked out of its own tenants' sinks, **silently**:
//! `TenantStreamer` treats `Fenced` as authoritative and drops the tenant
//! (`streamer.rs`), so the tenant just stops being backed up with nothing to
//! page on.
//!
//! # The procedure, and why the order is load-bearing
//!
//! Per tenant, in this order (W339 §The procedure):
//!
//! 1. **Bump the pointer generation** — [`bump_pointer_generation`]. This is
//!    the only fence a rebuilt cluster can raise against a *resurrected node*,
//!    because it is minted by compare-and-swap on an object the dead cluster
//!    cannot reach. An epoch floor cannot do it: the sidecar records the
//!    highest epoch anyone *wrote under*, not the highest the dead group
//!    *granted*, so a node claimed twice while idle holds a number strictly
//!    above anything readable from the bucket.
//! 2. **Read the epoch floor** — `turso_backup::stream::read_fence_state`.
//! 3. **Lift this cluster's epoch over the floor** — repeated plain
//!    `ClaimTenant` writes. There is no `min_epoch` request field and there
//!    must not be one: it would be `#[serde(default)]` and therefore tolerated
//!    in both directions, so one log entry would apply as two different epochs
//!    on a mixed cluster. Full verdict in `cluster-epochs.json`
//!    `surface_rerecords[2026-09-06]`.
//! 4. **Start streaming** — i.e. run this binary normally. Not this module's
//!    job.
//!
//! Bumping first does not stop a survivor *immediately*: the sidecar carries
//! the old generation until somebody stamps a new one, so a survivor writing in
//! that window is accepted and raises the floor above the one just read,
//! bouncing the rebuild. That is why [`clear_tenant_fence`] re-reads the fence
//! after lifting and runs another round if it moved.
//!
//! **It terminates**, and the termination argument is the whole reason there is
//! no backoff policy here: a dead raft group cannot mint an epoch, so a
//! survivor's number is frozen at its last applied `ClaimTenant`. Re-reading
//! after a bounce yields a floor already above it and round two wins for good.
//! If it *doesn't* terminate, the premise is false — something is still
//! granting epochs for this tenant, which means this is not a rebuild — and
//! [`RebuildOptions::max_rounds`] turns that into a loud error instead of a
//! spin.
//!
//! # What is inert today
//!
//! Step 1 fences nothing yet, because the data plane still passes
//! `pointer_generation: 0` (`streamer.rs`) — carrying the real value into a
//! cell's raft is **R736-F6**'s ratified design call, deliberately not
//! pre-empted here. Until it lands, a rebuild is *available* (half (a)) but not
//! absolutely *safe* against a deliberately-resurrected node (half (b)); with
//! `yubaba state restore` in front of it the residual is bounded by snapshot
//! lag rather than unbounded. The bump is implemented and tested now so that
//! F6 landing needs no change here.
//!
//! @arch:see(.yah/docs/working/W339-rebuilding-a-cluster-from-nothing.md)
//! @arch:see(.yah/docs/working/W250-multi-cell-tenant-mobility.md)

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use turso_backup::snapshot::BackupTarget;
use turso_backup::stream::{read_fence_state, FenceState};
use workload_spec::TenantId;
use yah_object_store::ObjectStore;

use crate::config::tenant_path_segment;
use crate::ownership::{HttpOwnership, TenantOutcome};

/// How hard [`clear_tenant_fence`] is allowed to try.
///
/// Both bounds exist to convert a wrong premise into a diagnosis rather than
/// into a very long wait — see this module's docs.
#[derive(Debug, Clone, Copy)]
pub struct RebuildOptions {
    /// Lease length stamped on each recovery claim.
    pub lease_secs: u64,
    /// How many times the fence may be read before giving up. A clean rebuild
    /// spends two (read, lift, confirm) and W339's survivor race spends three;
    /// exhausting this means the fence is still moving, which means the
    /// predecessor cluster is not dead.
    pub max_rounds: u32,
    /// Ceiling on committed raft entries spent lifting one tenant. Each claim
    /// is one entry, so a floor in the millions is a reason to restore from the
    /// off-fleet state copy rather than to count up to it.
    pub max_claims: u64,
}

impl Default for RebuildOptions {
    fn default() -> Self {
        Self {
            lease_secs: crate::config::DEFAULT_LEASE_SECS,
            max_rounds: 4,
            max_claims: 10_000,
        }
    }
}

/// What step 1 did to a tenant's global pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerStep {
    /// No pointer object exists. The tenant has never been placed through
    /// W250's pointer, so there is no generation to advance and nothing to
    /// fence a survivor with. This is the answer for **every** tenant until
    /// something starts minting pointers (R736-F6).
    Absent,
    /// The generation was advanced, in place, to the same cell.
    Bumped {
        cell: String,
        before: u64,
        after: u64,
    },
}

/// What steps 2 and 3 did to a tenant's sink fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceClearance {
    /// No sidecar at this prefix: nothing has ever streamed here, so there is
    /// no fence at all and any writer is accepted. Distinguished from a fence
    /// of zero on purpose — `read_fence_state`'s `Option` exists for exactly
    /// this caller.
    NeverStreamed,
    /// The cluster's epoch already clears the sink's floor.
    Cleared {
        /// The sink's epoch as first read.
        floor: u64,
        /// The epoch this cluster now holds for the tenant.
        epoch: u64,
        /// Committed `ClaimTenant` entries spent.
        claims: u64,
        /// Read-fence/lift rounds taken. `> 1` means a survivor wrote into the
        /// window and was overtaken.
        rounds: u32,
    },
}

/// Step 2's collaborator: whatever can report the fence a writer would be
/// checked against.
///
/// A trait rather than a bare `&BackupTarget` so the round/retry loop — the
/// load-bearing part, and the part a happy-path test skips — can be driven
/// against a fence that *moves under it*, which is the survivor race W339
/// describes. [`SinkFence`] is the production impl and adds nothing.
#[async_trait]
pub trait FenceSource: Send + Sync {
    async fn fence(&self, tenant: &TenantId) -> Result<Option<FenceState>>;
}

/// Step 3's collaborator: whatever can commit a `ClaimTenant`.
#[async_trait]
pub trait TenantClaims: Send + Sync {
    async fn claim(&self, tenant: &TenantId, lease_secs: u64) -> Result<TenantOutcome>;
}

/// Production [`FenceSource`]: `read_fence_state` against the tenant's own
/// prefix in the sink.
pub struct SinkFence {
    target: BackupTarget,
}

impl SinkFence {
    pub fn new(target: BackupTarget) -> Self {
        Self { target }
    }
}

#[async_trait]
impl FenceSource for SinkFence {
    async fn fence(&self, tenant: &TenantId) -> Result<Option<FenceState>> {
        read_fence_state(&self.target)
            .await
            .with_context(|| format!("reading tenant {}'s sink fence", tenant.0))
    }
}

#[async_trait]
impl TenantClaims for HttpOwnership {
    async fn claim(&self, tenant: &TenantId, lease_secs: u64) -> Result<TenantOutcome> {
        self.claim_tenant(tenant, lease_secs).await
    }
}

/// **Step 1** — advance `tenant`'s global pointer generation in place.
///
/// A same-cell bump, which is why this calls the raw
/// `yah_tenant_pointer::compare_and_swap` and not `commit_cell`: the latter
/// reports `AlreadyCommitted` and writes nothing when the tenant is already in
/// the named cell, which is precisely the situation here. The raw CAS
/// explicitly permits it — *"re-pointing a tenant at the cell it is already in
/// is a legitimate (if unusual) generation bump."*
///
/// A lost CAS is an error, not a retry: something else is moving this tenant's
/// pointer, and on a rebuild that means a second recovery is running or the
/// predecessor is not as dead as assumed. Both want a human, not a louder
/// attempt.
pub fn bump_pointer_generation(store: &dyn ObjectStore, tenant: &TenantId) -> Result<PointerStep> {
    // The pointer key is a path segment; reject the ids that would forge one
    // with the same check the sink prefix and the db path already use.
    let id = tenant_path_segment(tenant)?;
    let Some(current) = yah_tenant_pointer::read(store, id)
        .with_context(|| format!("reading tenant {id}'s cell pointer"))?
    else {
        return Ok(PointerStep::Absent);
    };
    let cell = current.record.cell.clone();
    let before = current.record.generation;
    let bumped =
        yah_tenant_pointer::compare_and_swap(store, &current, &cell).with_context(|| {
            format!(
            "bumping tenant {id}'s pointer generation from {before} (cell {cell}) — a lost CAS \
             means something else is repointing this tenant right now"
        )
        })?;
    Ok(PointerStep::Bumped {
        cell,
        before,
        after: bumped.record.generation,
    })
}

/// Read `tenant`'s pointer without writing — the dry-run half of step 1.
///
/// `Ok(None)` means no pointer object exists; otherwise `(cell, generation)`.
pub fn read_pointer_generation(
    store: &dyn ObjectStore,
    tenant: &TenantId,
) -> Result<Option<(String, u64)>> {
    let id = tenant_path_segment(tenant)?;
    Ok(yah_tenant_pointer::read(store, id)
        .with_context(|| format!("reading tenant {id}'s cell pointer"))?
        .map(|p| (p.record.cell, p.record.generation)))
}

/// **Steps 2 and 3** — lift this cluster's epoch for `tenant` over whatever
/// floor the sink carries, re-reading the fence to catch a survivor that wrote
/// into the window.
pub async fn clear_tenant_fence(
    fence: &dyn FenceSource,
    claims: &dyn TenantClaims,
    tenant: &TenantId,
    opts: &RebuildOptions,
) -> Result<FenceClearance> {
    let mut spent = 0u64;
    let mut epoch = 0u64;
    let mut first_floor = None;

    for round in 1..=opts.max_rounds {
        let Some(state) = fence.fence(tenant).await? else {
            // No sidecar. On round 1 that means nothing ever streamed here and
            // there is nothing to do. It cannot appear on a later round without
            // somebody deleting the sidecar mid-recovery, which is not a case
            // to paper over — but it is also not a fence, so report the same
            // way and let the operator read `claims > 0` as the tell.
            return Ok(match first_floor {
                None => FenceClearance::NeverStreamed,
                Some(floor) => FenceClearance::Cleared {
                    floor,
                    epoch,
                    claims: spent,
                    rounds: round - 1,
                },
            });
        };
        let floor = state.epoch;
        first_floor.get_or_insert(floor);

        // Already over it (round 2+ after a bounce, or a claim that overshot).
        if epoch > floor {
            return Ok(FenceClearance::Cleared {
                floor: first_floor.expect("set above"),
                epoch,
                claims: spent,
                rounds: round - 1,
            });
        }

        // Each grant advances by exactly one, so the distance is known before
        // spending a single raft entry — check it against the ceiling first.
        let needed = floor
            .checked_sub(epoch)
            .and_then(|gap| gap.checked_add(1))
            .context("epoch arithmetic overflowed")?;
        if spent.saturating_add(needed) > opts.max_claims {
            bail!(
                "tenant {}: clearing the sink's epoch floor of {floor} from {epoch} would take \
                 {needed} ClaimTenant writes, past the {} ceiling — that is {needed} committed \
                 raft entries. Restore the off-fleet state copy first (`yubaba state restore`), \
                 which brings the epochs back with it, instead of counting up from nothing.",
                tenant.0,
                opts.max_claims,
            );
        }

        for _ in 0..needed {
            if epoch > floor {
                // A grant that advanced by more than one (or a concurrent
                // reclaim) already cleared it — stop spending raft entries.
                break;
            }
            match claims.claim(tenant, opts.lease_secs).await? {
                TenantOutcome::Granted { epoch: granted } => {
                    spent += 1;
                    epoch = granted;
                }
                TenantOutcome::Fenced {
                    current_epoch,
                    current_owner,
                } => bail!(
                    "tenant {}: refused at epoch {current_epoch} by owner {current_owner:?} with \
                     a live lease. A rebuild claims tenants nobody is holding; something in this \
                     cluster still owns this one, so this is not a total-loss recovery.",
                    tenant.0,
                ),
            }
        }
    }

    bail!(
        "tenant {}: the sink's fence is still at or above this cluster's epoch {epoch} after {} \
         rounds and {spent} claims. A dead raft group cannot mint an epoch, so a fence that keeps \
         advancing means the predecessor cluster is NOT dead — find the live writer before \
         claiming anything else.",
        tenant.0,
        opts.max_rounds,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use yah_object_store::InMemoryObjectStore;

    fn tenant(name: &str) -> TenantId {
        TenantId(name.to_string())
    }

    /// A sink fence the test can move under the loop, which is the survivor
    /// race the ordering argument is about. Each call pops the next scripted
    /// answer; the last one repeats.
    struct ScriptedFence {
        answers: Mutex<Vec<Option<FenceState>>>,
        reads: Mutex<u32>,
    }

    impl ScriptedFence {
        fn new(answers: Vec<Option<FenceState>>) -> Self {
            Self {
                answers: Mutex::new(answers),
                reads: Mutex::new(0),
            }
        }
        fn at(epoch: u64) -> Self {
            Self::new(vec![Some(FenceState {
                epoch,
                pointer_generation: 0,
            })])
        }
        fn reads(&self) -> u32 {
            *self.reads.lock().unwrap()
        }
    }

    #[async_trait]
    impl FenceSource for ScriptedFence {
        async fn fence(&self, _tenant: &TenantId) -> Result<Option<FenceState>> {
            *self.reads.lock().unwrap() += 1;
            let mut answers = self.answers.lock().unwrap();
            Ok(if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0]
            })
        }
    }

    /// A raft group that grants `current + 1` on every claim — the arithmetic
    /// `raft::tests::repeated_self_reclaims_lift_a_rebuilt_cluster_over_the_sinks_epoch`
    /// pins against the real state machine.
    struct CountingClaims {
        epoch: Mutex<u64>,
        refuse_at: Option<u64>,
    }

    impl CountingClaims {
        fn fresh() -> Self {
            Self {
                epoch: Mutex::new(0),
                refuse_at: None,
            }
        }
        fn refusing() -> Self {
            Self {
                epoch: Mutex::new(0),
                refuse_at: Some(0),
            }
        }
        fn granted(&self) -> u64 {
            *self.epoch.lock().unwrap()
        }
    }

    #[async_trait]
    impl TenantClaims for CountingClaims {
        async fn claim(&self, _tenant: &TenantId, _lease_secs: u64) -> Result<TenantOutcome> {
            if let Some(at) = self.refuse_at {
                if *self.epoch.lock().unwrap() == at {
                    return Ok(TenantOutcome::Fenced {
                        current_epoch: 42,
                        current_owner: Some(7),
                    });
                }
            }
            let mut e = self.epoch.lock().unwrap();
            *e += 1;
            Ok(TenantOutcome::Granted { epoch: *e })
        }
    }

    /// The availability half of W339, driven: a cluster rebuilt from nothing
    /// starts at epoch 0 and has to reach 6 to write past a sidecar stamped 5.
    #[tokio::test]
    async fn a_rebuilt_cluster_lifts_itself_exactly_one_epoch_past_the_sinks_floor() {
        let fence = ScriptedFence::at(5);
        let claims = CountingClaims::fresh();
        let got = clear_tenant_fence(&fence, &claims, &tenant("acme"), &RebuildOptions::default())
            .await
            .unwrap();
        assert_eq!(
            got,
            FenceClearance::Cleared {
                floor: 5,
                epoch: 6,
                claims: 6,
                rounds: 1
            }
        );
        assert_eq!(claims.granted(), 6);
    }

    /// No sidecar is not a fence of zero. Collapsing the two would spend a raft
    /// entry on every tenant that has never streamed.
    #[tokio::test]
    async fn a_tenant_that_never_streamed_costs_no_raft_entries() {
        let fence = ScriptedFence::new(vec![None]);
        let claims = CountingClaims::fresh();
        assert_eq!(
            clear_tenant_fence(&fence, &claims, &tenant("acme"), &RebuildOptions::default())
                .await
                .unwrap(),
            FenceClearance::NeverStreamed
        );
        assert_eq!(claims.granted(), 0, "nothing was claimed");
    }

    /// A sidecar stamped 0 IS a fence — an old writer wrote under it — but one
    /// claim clears it. This is the other side of the `Option` distinction.
    #[tokio::test]
    async fn an_unfenced_sidecar_still_costs_the_one_claim_that_clears_it() {
        let fence = ScriptedFence::at(0);
        let claims = CountingClaims::fresh();
        assert_eq!(
            clear_tenant_fence(&fence, &claims, &tenant("acme"), &RebuildOptions::default())
                .await
                .unwrap(),
            FenceClearance::Cleared {
                floor: 0,
                epoch: 1,
                claims: 1,
                rounds: 1
            }
        );
    }

    /// **The ordering race, and its termination argument.** FALSIFIED, not
    /// assumed: deleting the re-read (returning `Cleared` straight after the
    /// claim loop) makes this fail with `Cleared { epoch: 6, rounds: 1 }` — the
    /// rebuild walks away believing it won while the sink stands at 9, which is
    /// the silent `drop_tenant` this whole relay exists to prevent. The
    /// live-predecessor test below fails with it too; the other seven stay
    /// green, so nothing else in the setup is quietly doing the work.
    ///
    /// A survivor writes
    /// into the window after the first floor is read, raising the sink to 9
    /// while the rebuild is climbing to 6. The rebuild must notice on the
    /// re-read and win on round two — and it must not need a third, because the
    /// survivor's epoch is frozen at its last applied claim.
    #[tokio::test]
    async fn the_rebuild_overtakes_a_survivor_that_wrote_into_the_window() {
        let fence = ScriptedFence::new(vec![
            Some(FenceState {
                epoch: 5,
                pointer_generation: 0,
            }),
            // Re-read after lifting to 6: the survivor got there first at 9.
            Some(FenceState {
                epoch: 9,
                pointer_generation: 0,
            }),
            // Frozen — a dead raft group cannot mint another one.
            Some(FenceState {
                epoch: 9,
                pointer_generation: 0,
            }),
        ]);
        let claims = CountingClaims::fresh();
        let got = clear_tenant_fence(&fence, &claims, &tenant("acme"), &RebuildOptions::default())
            .await
            .unwrap();
        assert_eq!(
            got,
            FenceClearance::Cleared {
                floor: 5,
                epoch: 10,
                claims: 10,
                rounds: 2
            },
            "six claims to clear 5, four more to clear 9"
        );
        assert_eq!(fence.reads(), 3, "read, lift, re-read, lift, confirm");
    }

    /// A fence that keeps advancing is not a retry problem, it is a wrong
    /// premise: something is still granting epochs, so the predecessor is
    /// alive. The loop must say that rather than spin.
    ///
    /// The double is a fence that *tracks the claimer* — it always reads three
    /// above whatever the rebuild last got granted, which is exactly what a
    /// still-live predecessor looks like from the bucket.
    #[tokio::test]
    async fn a_fence_that_never_stops_moving_is_reported_as_a_live_predecessor() {
        struct LivePredecessor {
            granted: Mutex<u64>,
        }
        #[async_trait]
        impl FenceSource for LivePredecessor {
            async fn fence(&self, _t: &TenantId) -> Result<Option<FenceState>> {
                Ok(Some(FenceState {
                    epoch: *self.granted.lock().unwrap() + 3,
                    pointer_generation: 0,
                }))
            }
        }
        #[async_trait]
        impl TenantClaims for LivePredecessor {
            async fn claim(&self, _t: &TenantId, _l: u64) -> Result<TenantOutcome> {
                let mut g = self.granted.lock().unwrap();
                *g += 1;
                Ok(TenantOutcome::Granted { epoch: *g })
            }
        }
        let live = LivePredecessor {
            granted: Mutex::new(0),
        };
        let err = clear_tenant_fence(
            &live,
            &live,
            &tenant("acme"),
            &RebuildOptions {
                max_rounds: 3,
                ..RebuildOptions::default()
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("predecessor cluster is NOT dead"),
            "unexpected error: {err}"
        );
    }

    /// A live owner refusing the claim means this is not a total-loss recovery.
    /// Reporting it as a fence-clearing failure would send an operator to the
    /// bucket; reporting the owner sends them to the node.
    #[tokio::test]
    async fn a_refused_claim_names_the_live_owner_instead_of_retrying() {
        let err = clear_tenant_fence(
            &ScriptedFence::at(5),
            &CountingClaims::refusing(),
            &tenant("acme"),
            &RebuildOptions::default(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("owner Some(7)"), "unexpected error: {err}");
        assert!(err.contains("not a total-loss recovery"), "{err}");
    }

    /// The ceiling is checked BEFORE the first claim, not after N of them — the
    /// whole point is to not commit a million raft entries discovering that the
    /// distance is a million.
    #[tokio::test]
    async fn an_absurd_floor_is_refused_before_a_single_raft_entry_is_committed() {
        let claims = CountingClaims::fresh();
        let err = clear_tenant_fence(
            &ScriptedFence::at(1_000_000),
            &claims,
            &tenant("acme"),
            &RebuildOptions {
                max_claims: 10,
                ..RebuildOptions::default()
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(claims.granted(), 0, "nothing was committed");
        assert!(
            err.contains("yubaba state restore"),
            "unexpected error: {err}"
        );
    }

    /// Step 1 against a tenant that has never been placed. This is the answer
    /// for every tenant today, and it must not be an error — a rebuild that
    /// aborted here would refuse to clear a fence it can perfectly well clear.
    #[test]
    fn a_tenant_with_no_pointer_reports_absent_rather_than_failing() {
        let store = InMemoryObjectStore::new();
        assert_eq!(
            bump_pointer_generation(&store, &tenant("acme")).unwrap(),
            PointerStep::Absent
        );
    }

    /// The same-cell bump, which `commit_cell` cannot do (it reports
    /// `AlreadyCommitted` and writes nothing). The generation is the comparand
    /// that fences a survivor, so a step 1 that silently wrote nothing would
    /// leave half (b) open while reporting success.
    #[test]
    fn the_generation_advances_in_place_without_moving_the_tenant() {
        let store = InMemoryObjectStore::new();
        yah_tenant_pointer::create_if_absent(&store, "acme", "us-west").unwrap();

        assert_eq!(
            bump_pointer_generation(&store, &tenant("acme")).unwrap(),
            PointerStep::Bumped {
                cell: "us-west".to_string(),
                before: 1,
                after: 2,
            }
        );
        // Twice, because a rebuild that is re-run must keep advancing rather
        // than settle: each attempt has to out-rank every survivor.
        assert_eq!(
            bump_pointer_generation(&store, &tenant("acme")).unwrap(),
            PointerStep::Bumped {
                cell: "us-west".to_string(),
                before: 2,
                after: 3,
            }
        );
        let after = yah_tenant_pointer::read(&store, "acme").unwrap().unwrap();
        assert_eq!(after.record.cell, "us-west", "the tenant did not move");
        assert_eq!(after.record.generation, 3);
    }

    /// The id reaches an object key, so it is checked with the same rule the
    /// sink prefix and the db path use rather than trusted.
    #[test]
    fn a_tenant_id_that_would_forge_a_key_is_refused() {
        let store = InMemoryObjectStore::new();
        assert!(bump_pointer_generation(&store, &tenant("../etc")).is_err());
    }
}
