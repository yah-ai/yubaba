//! R869 — **what a rebuild-from-nothing does to the two-level fence**, proven
//! against the production sink rather than argued from the docs.
//!
//! ```bash
//! cargo test -p yubaba --test main -- raft_rebuild_fencing::
//! ```
//!
//! ## The scenario these tests exist for
//!
//! On 2026-08-31 all three production voters crash-looped on a cold start
//! (`raft/store.rs:40`) and the recovery was to **wipe the raft dir and
//! re-form**. That is also the recovery for the case R869 is actually about:
//! every machine gone, new hardware. Either way `YubabaState` comes back
//! `default()` — `tenants` empty — while the R2 sink still holds every tenant's
//! `latest.stream-watermark`, stamped with the *old* cluster's fencing epoch.
//!
//! `raft/mod.rs`'s single-writer invariant ("a stale-high token cannot exist —
//! only committed entries reach the state machine") holds for every failure
//! mode except this one. Rebuilding restarts `TenantOwnership::epoch` at 1
//! (`ClaimTenant` is `current.map_or(0, ..) + 1`), so a node that comes back
//! from the dead holding a higher epoch outranks the fresh cluster.
//!
//! ## What the sink actually checks, and why it takes two fixes
//!
//! `turso_backup::stream::tail_frames` bounces a writer when
//!
//! ```text
//! sidecar.epoch > cfg.epoch  ||  sidecar.pointer_generation > cfg.pointer_generation
//! ```
//!
//! It is an **or**, so writing requires *both* comparands to be at least the
//! sink's. That splits R869's acceptance property in two, and the halves want
//! different mechanisms:
//!
//! * **(a) the rebuilt cluster can serve** needs `epoch >= sidecar.epoch`. The
//!   number is already off-fleet — it is field 4 of the watermark sidecar — so
//!   an *epoch floor* closes this half, and `read_fence_state` (turso-backup,
//!   landed with these tests) is how a rebuild reads it. The floor reaches raft
//!   through repeated plain `ClaimTenant` writes — see [`reclaim_until_above`]
//!   for why it is a loop and not a request field.
//! * **(b) a resurrected node is refused** needs something a survivor cannot
//!   match. The epoch floor alone does **not** give it
//!   ([`an_epoch_floor_alone_loses_to_a_survivor_that_outranks_it`]): a survivor
//!   can hold an epoch its dead cluster *granted but never wrote under*, and no
//!   number readable from the sink is an upper bound on that. The off-fleet
//!   `yah_tenant_pointer` generation is, because it is minted by a
//!   compare-and-swap on an object the survivor cannot re-read.
//!
//! So the rebuild procedure is: **bump the pointer generation, then take the
//! epoch floor from the sidecar, then write.** [`the_rebuild_wins_in_one_retry`]
//! covers the race that ordering leaves, and why it terminates.
//!
//! ## Scope note
//!
//! `pointer_generation` is passed as a literal `0` by the data plane today
//! (`tenant-streamer/src/streamer.rs:144`, `:441`) — carrying the real value is
//! R736-F6's ratified design call, and these tests deliberately do not
//! pre-empt it. What they establish is that the *mechanism* R869 needs is the
//! one already shipped in `tail_frames`, so R869's half is the rebuild
//! procedure, not a third monotonic counter.
//!
//! Home: its own file rather than `integration_mesh.rs`'s `split_brain` module,
//! for the reason `raft_tenant_placement.rs` records — that module sits behind
//! `containerd-integration`, so a fencing proof parked there is one the default
//! `cargo test` never runs.

use std::cell::RefCell;
use std::sync::Arc;

use futures_util::StreamExt;
use object_store::memory::InMemory;
use object_store::ObjectStore;
use turso_backup::snapshot::BackupTarget;
use turso_backup::stream::{
    tail_frames, FrameInfo, StreamConfig, StreamOutcome, WalSeam, Watermark, WAL_FRAME_HEADER_SIZE,
};
use workload_spec::TenantId;
use yubaba::raft::{apply, TenantOutcome, YubabaRequest, YubabaResponse, YubabaState};

const PAGE_SIZE: usize = 4096;
/// The node that owned the tenant before the fleet died, and the one that comes
/// back from the dead in every test below.
const SURVIVOR: u64 = 1;
/// A node in the rebuilt cluster. New hardware, so a new id.
const REBUILT: u64 = 7;

/// The tenant's WAL. One fill byte per frame; contents are irrelevant — every
/// assertion here is about which writer the *sink* accepts, not about bytes.
struct TinyWal {
    frames: RefCell<Vec<u8>>,
}

impl TinyWal {
    fn new() -> Self {
        Self {
            frames: RefCell::new(Vec::new()),
        }
    }
    fn write(&self, n: usize) {
        let mut f = self.frames.borrow_mut();
        for _ in 0..n {
            let next = f.len() as u8;
            f.push(next);
        }
    }
}

impl WalSeam for TinyWal {
    fn wal_state(&self) -> anyhow::Result<Watermark> {
        Ok(Watermark {
            checkpoint_seq: 0,
            last_frame: self.frames.borrow().len() as u64,
        })
    }
    fn wal_get_frame(&self, frame_no: u64, buf: &mut [u8]) -> anyhow::Result<FrameInfo> {
        let fill = *self
            .frames
            .borrow()
            .get(frame_no as usize - 1)
            .ok_or_else(|| anyhow::anyhow!("frame {frame_no} out of range"))?;
        let info = FrameInfo {
            page_no: frame_no as u32,
            db_size: frame_no as u32,
        };
        buf[0..4].copy_from_slice(&info.page_no.to_be_bytes());
        buf[4..8].copy_from_slice(&info.db_size.to_be_bytes());
        buf[8..WAL_FRAME_HEADER_SIZE].fill(0);
        buf[WAL_FRAME_HEADER_SIZE..].fill(fill);
        Ok(info)
    }
    fn wal_auto_actions_disable(&self) {}
}

fn tenant() -> TenantId {
    TenantId("acme".into())
}

fn target() -> BackupTarget {
    BackupTarget {
        store: Arc::new(InMemory::new()),
        prefix: "tenants/acme".into(),
    }
}

fn cfg<'a>(base: &'a str, epoch: u64, generation: u64, owner: &'a str) -> StreamConfig<'a> {
    StreamConfig {
        base_snapshot_key: base,
        page_size: PAGE_SIZE,
        backpressure: Default::default(),
        rpo_target: None,
        epoch,
        owner: Some(owner),
        pointer_generation: generation,
    }
}

/// Every object under the sink, counted — the strongest available form of
/// "wrote nothing": it catches a stray frame, manifest or sidecar rewrite
/// anywhere in the prefix, not just at keys the test thought to name.
async fn objects_at(sink: &BackupTarget) -> usize {
    sink.store
        .list(None)
        .filter(|r| {
            let ok = r.is_ok();
            async move { ok }
        })
        .count()
        .await
}

/// Drive a real `ClaimTenant` through the real state machine and return the
/// epoch it granted.
fn claim(state: &mut YubabaState, node: u64, lease_secs: u64, now: u64) -> u64 {
    let req = YubabaRequest::ClaimTenant {
        tenant: tenant(),
        node,
        lease_secs,
        now,
    };
    match apply(state, &req) {
        YubabaResponse::Tenant(TenantOutcome::Granted { epoch }) => epoch,
        other => panic!("expected a grant, got {other:?}"),
    }
}

/// **The recovery, as the runbook performs it.** Re-claim the tenant until its
/// epoch clears `floor` — the number `turso_backup::stream::read_fence_state`
/// reported for this sink.
///
/// A loop rather than one request carrying the floor, and that is a decision
/// rather than an omission. A `min_epoch` field on `ClaimTenant` would be
/// `#[serde(default)]` and therefore *tolerated* by an older binary, which
/// drops it and applies `current + 1` while an upgraded node applies
/// `max(current, floor) + 1` — one log entry, two applied epochs, state
/// machines diverged. Buying safety from that costs a `cluster_protocol` AND a
/// `state_epoch` bump (the R706 precedent in `cluster-epochs.json`), and a
/// disaster-recovery mechanism that cannot be used until the whole fleet has
/// been upgraded is a worse mechanism. Every request this loop sends is already
/// accepted by the binaries running today, over the generic `POST /raft/write`
/// (raft/mod.rs:98).
///
/// Cost is one committed raft entry per epoch of the gap, on a path that runs
/// once per disaster.
fn reclaim_until_above(state: &mut YubabaState, node: u64, floor: u64, now: u64) -> u64 {
    let mut epoch = 0;
    let mut writes = 0u64;
    while epoch <= floor {
        epoch = claim(state, node, 600, now);
        writes += 1;
        assert!(
            writes <= floor + 1,
            "the recovery must terminate in at most floor+1 claims, took {writes}"
        );
    }
    epoch
}

/// The live cluster before the fleet dies: five ownership events (restarts and
/// failovers, each a self-reclaim past an expired lease) take the tenant to
/// epoch 5, and the last owner streams — so the sink's sidecar is stamped
/// `epoch 5`.
///
/// Returns that cluster's applied state, which every test below then keeps as
/// the survivor's private copy. Nothing can advance it once the raft group is
/// gone, and that fact is what makes [`the_rebuild_wins_in_one_retry`]
/// terminate.
async fn a_fleet_that_streamed_up_to_epoch_5(
    sink: &BackupTarget,
    wal: &TinyWal,
    base: &str,
) -> YubabaState {
    let mut state = YubabaState::default();
    for (i, now) in [1_000u64, 1_020, 1_040, 1_060, 1_080].iter().enumerate() {
        assert_eq!(claim(&mut state, SURVIVOR, 10, *now), i as u64 + 1);
    }
    wal.write(3);
    let out = tail_frames(wal, sink, &cfg(base, 5, 0, "survivor"))
        .await
        .unwrap();
    assert!(matches!(out, StreamOutcome::Streamed { .. }), "got {out:?}");
    state
}

/// **The gap, stated as a failing property of production code.** Wipe the raft
/// dir, re-form, and the rebuilt cluster is refused by its own tenant's sink.
///
/// This is the half of R869 that is an *availability* failure rather than a
/// correctness one, and it is the one that hides: `tenant-streamer` treats
/// `Fenced` as authoritative and calls `drop_tenant` (streamer.rs:153), so the
/// tenant silently stops being backed up. Nothing crashes and nothing logs an
/// error the fleet would page on — the cluster just quietly stops carrying
/// state it is supposed to carry, which is exactly the outcome the operator
/// ruled out on 2026-09-05 ("losing track of state required for cluster
/// health").
#[tokio::test]
async fn a_rebuilt_cluster_is_locked_out_of_its_own_tenants_sink() {
    let sink = target();
    let wal = TinyWal::new();
    let base = "tenants/acme/snapshots/base.db".to_string();
    let _dead = a_fleet_that_streamed_up_to_epoch_5(&sink, &wal, &base).await;

    // Total loss. `YubabaState::default()` IS the recovery the 2026-08-31
    // incident used and the one new hardware starts from — there is no third
    // option today, which is the ticket.
    let mut rebuilt = YubabaState::default();
    assert_eq!(
        claim(&mut rebuilt, REBUILT, 300, 2_000),
        1,
        "a re-formed cluster restarts the tenant epoch at 1, because the record \
         that would have carried it forward died with the raft dir"
    );

    let objects_before = objects_at(&sink).await;
    wal.write(2);
    let out = tail_frames(&wal, &sink, &cfg(&base, 1, 0, "rebuilt"))
        .await
        .unwrap();

    assert_eq!(
        out,
        StreamOutcome::Fenced {
            current_epoch: 5,
            our_epoch: 1,
            current_pointer_generation: 0,
            our_pointer_generation: 0,
        },
        "the rebuilt cluster is fenced out by the epoch its own predecessor left \
         at the sink"
    );
    assert_eq!(
        objects_at(&sink).await,
        objects_before,
        "a fenced writer must write nothing at all"
    );
}

/// **Why an epoch floor is necessary but not sufficient**, which is the finding
/// that decides R869's design.
///
/// Reading the sidecar's epoch and starting above it does let the rebuilt
/// cluster serve. It does *not* fence a survivor, because the sidecar records
/// the highest epoch anyone **wrote under** — not the highest epoch the dead
/// raft group **granted**. A tenant that was claimed twice while idle (a restart
/// loop, a failover with no traffic) leaves a node holding an epoch strictly
/// above anything the sink ever saw, and no number readable from the bucket
/// bounds it.
///
/// So the resurrected node legitimately outranks the fresh cluster and takes
/// the sink back — acceptance criterion (b), failing, exactly where a
/// happy-path rebuild test would have reported success.
#[tokio::test]
async fn an_epoch_floor_alone_loses_to_a_survivor_that_outranks_it() {
    let sink = target();
    let wal = TinyWal::new();
    let base = "tenants/acme/snapshots/base.db".to_string();
    let mut survivor = a_fleet_that_streamed_up_to_epoch_5(&sink, &wal, &base).await;

    // Two more ownership events with no traffic between them. Both are ordinary
    // — `ClaimTenant` always advances on grant, including self-reclaim, so a
    // node that restarts twice outranks its own last write by two.
    assert_eq!(claim(&mut survivor, SURVIVOR, 10, 1_200), 6);
    assert_eq!(claim(&mut survivor, SURVIVOR, 600, 1_220), 7);
    assert_eq!(
        survivor.tenant_fencing_token(&tenant(), SURVIVOR, 1_230),
        Some(7),
        "the survivor holds epoch 7 on a live lease, and the sink has only ever \
         seen epoch 5"
    );

    // The fleet dies here. The rebuild reads the best floor available off-fleet
    // — the sidecar's epoch, 5 — and claims above it through the real
    // real `ClaimTenant` path rather than a hand-built record.
    let mut rebuilt = YubabaState::default();
    assert_eq!(reclaim_until_above(&mut rebuilt, REBUILT, 5, 2_000), 6);

    wal.write(2);
    let out = tail_frames(&wal, &sink, &cfg(&base, 6, 0, "rebuilt"))
        .await
        .unwrap();
    assert!(
        matches!(out, StreamOutcome::Streamed { .. }),
        "the floor does close the availability half — the rebuilt cluster serves: {out:?}"
    );

    // The survivor is brought back — deliberately, as the chaos drill does.
    wal.write(2);
    let out = tail_frames(&wal, &sink, &cfg(&base, 7, 0, "survivor"))
        .await
        .unwrap();
    assert!(
        matches!(out, StreamOutcome::Streamed { .. }),
        "THE HAZARD: the resurrected node's granted-but-never-written epoch 7 \
         outranks the floor-derived 6, so the sink accepts it: {out:?}"
    );

    // And now the legitimate cluster is the one that is fenced.
    wal.write(1);
    let out = tail_frames(&wal, &sink, &cfg(&base, 6, 0, "rebuilt"))
        .await
        .unwrap();
    assert_eq!(
        out,
        StreamOutcome::Fenced {
            current_epoch: 7,
            our_epoch: 6,
            current_pointer_generation: 0,
            our_pointer_generation: 0,
        },
        "the zombie won and the live cluster lost its own tenant"
    );
}

/// **The fix, end to end**: the epoch floor closes (a), and the off-fleet
/// pointer-generation bump closes (b) — including against a survivor whose
/// epoch is *higher* than the rebuilt cluster's.
///
/// Note the shape of the `Fenced` the survivor gets: `current_epoch 6` is
/// *below* its own `our_epoch 7`. The epoch comparand does not fence it and
/// cannot; the generation does. That asymmetry is the whole reason R869 cannot
/// be solved on the raft-epoch axis alone — raft is the authority that just
/// died, and the pointer's authority is the object store, which did not.
///
/// FALSIFIED, not assumed: handing the survivor the *same* generation (`2`)
/// instead of the stale `1` makes this assertion report `Streamed` — the
/// survivor at epoch 7 takes the sink back — while the other three tests in
/// this file stay green. So the generation comparand is doing the fencing here
/// on its own, and nothing else in the setup is quietly responsible.
#[tokio::test]
async fn a_generation_bump_fences_a_survivor_the_epoch_floor_cannot() {
    let sink = target();
    let wal = TinyWal::new();
    let base = "tenants/acme/snapshots/base.db".to_string();
    let mut survivor = a_fleet_that_streamed_up_to_epoch_5(&sink, &wal, &base).await;
    assert_eq!(claim(&mut survivor, SURVIVOR, 10, 1_200), 6);
    assert_eq!(claim(&mut survivor, SURVIVOR, 600, 1_220), 7);

    // Rebuild: pointer generation CAS'd 1 → 2 off-fleet, and the fresh raft
    // group claims above the sidecar's epoch 5.
    let mut rebuilt = YubabaState::default();
    assert_eq!(reclaim_until_above(&mut rebuilt, REBUILT, 5, 2_000), 6);
    wal.write(2);
    let out = tail_frames(&wal, &sink, &cfg(&base, 6, 2, "rebuilt"))
        .await
        .unwrap();
    assert!(matches!(out, StreamOutcome::Streamed { .. }), "got {out:?}");

    // The survivor still believes generation 1 — and cannot learn otherwise,
    // because the generation reaches a node through its own cell's raft
    // (R736-F6), and its cell is gone.
    let objects_before = objects_at(&sink).await;
    wal.write(2);
    let out = tail_frames(&wal, &sink, &cfg(&base, 7, 1, "survivor"))
        .await
        .unwrap();
    assert_eq!(
        out,
        StreamOutcome::Fenced {
            current_epoch: 6,
            our_epoch: 7,
            current_pointer_generation: 2,
            our_pointer_generation: 1,
        },
        "the survivor outranks the rebuilt cluster on epoch and is refused anyway"
    );
    assert_eq!(
        objects_at(&sink).await,
        objects_before,
        "a fenced writer writes nothing"
    );
}

/// **The race the ordering leaves, and why it costs one retry rather than
/// unbounded ones.**
///
/// Bumping the pointer generation does not stop a survivor immediately: the
/// *sidecar* still carries the old generation until somebody stamps a new one,
/// so a survivor that writes in that window is accepted and raises the sink's
/// epoch above the floor the rebuild just read. The rebuild's write then
/// bounces.
///
/// It terminates because **a dead raft group cannot mint an epoch.** The
/// survivor's number is fixed at whatever its last applied `ClaimTenant`
/// granted; re-reading the sidecar after a bounce therefore yields a floor that
/// is already above it, and the second attempt wins for good. A rebuild loop
/// needs no backoff policy and no bound beyond "re-read and retry".
#[tokio::test]
async fn the_rebuild_wins_in_one_retry() {
    let sink = target();
    let wal = TinyWal::new();
    let base = "tenants/acme/snapshots/base.db".to_string();
    let mut survivor = a_fleet_that_streamed_up_to_epoch_5(&sink, &wal, &base).await;
    assert_eq!(claim(&mut survivor, SURVIVOR, 10, 1_200), 6);
    assert_eq!(claim(&mut survivor, SURVIVOR, 600, 1_220), 7);

    // The survivor gets in first, between the generation CAS and the rebuild's
    // first write. Still on generation 1, and still accepted, because the
    // sidecar has not been restamped yet.
    wal.write(2);
    let out = tail_frames(&wal, &sink, &cfg(&base, 7, 1, "survivor"))
        .await
        .unwrap();
    assert!(matches!(out, StreamOutcome::Streamed { .. }), "got {out:?}");

    // Attempt 1 — the floor was read before that write, so it is stale.
    let mut rebuilt = YubabaState::default();
    assert_eq!(reclaim_until_above(&mut rebuilt, REBUILT, 5, 2_000), 6);
    wal.write(1);
    let out = tail_frames(&wal, &sink, &cfg(&base, 6, 2, "rebuilt"))
        .await
        .unwrap();
    let StreamOutcome::Fenced {
        current_epoch,
        our_epoch: 6,
        ..
    } = out
    else {
        panic!("the stale floor must bounce: {out:?}");
    };
    assert_eq!(current_epoch, 7, "the sink learned the survivor's epoch");

    // Attempt 2 — re-claim with the epoch the bounce just reported as the floor.
    // Note this is the SAME node re-claiming, so it takes the self-reclaim arm
    // and the floor is what does the work: `max(6, 7) + 1`.
    assert_eq!(
        reclaim_until_above(&mut rebuilt, REBUILT, current_epoch, 2_100),
        8,
        "one re-claim clears the survivor, and it terminates because a dead raft \
         group cannot mint an epoch 9 to answer with"
    );
    let out = tail_frames(&wal, &sink, &cfg(&base, 8, 2, "rebuilt"))
        .await
        .unwrap();
    assert!(matches!(out, StreamOutcome::Streamed { .. }), "got {out:?}");

    // And the survivor is now fenced on both comparands at once, permanently:
    // it can raise neither.
    wal.write(1);
    let out = tail_frames(&wal, &sink, &cfg(&base, 7, 1, "survivor"))
        .await
        .unwrap();
    assert_eq!(
        out,
        StreamOutcome::Fenced {
            current_epoch: 8,
            our_epoch: 7,
            current_pointer_generation: 2,
            our_pointer_generation: 1,
        },
    );
}
