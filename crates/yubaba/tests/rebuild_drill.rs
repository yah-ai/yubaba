//! R869 P5 — the end-to-end rebuild drill, driven in-process against the
//! REAL production code paths rather than a doubled-up reimplementation.
//!
//! ```bash
//! cargo test -p yubaba --test main -- rebuild_drill::
//! ```
//!
//! ## Why this file, and why now
//!
//! P1-P4 each proved one piece of the total-loss recovery in isolation: P1 the
//! fence arithmetic (`raft_rebuild_fencing.rs`, against a real
//! `turso_backup::stream::tail_frames`), P2 the CAS/monotonicity guard
//! (`state_backup.rs`'s 14 unit tests, against `InMemoryObjectStore`), P3 the
//! rebuild-step logic (`tenant-streamer/src/rebuild.rs`'s 9), P4 the operator
//! runbook (`.yah/docs/guides/yubaba-total-loss-recovery.md`). Nothing proved
//! the pieces COMPOSE — that `state show` -> `state restore --dir` -> `raft
//! init` -> `tenant-streamer rebuild` -> `state adopt` -> verify is a sequence
//! that actually produces a cluster that (a) serves and (b) fences a
//! survivor. The relay's own sign-off criterion is that chaos drill, and it is
//! blocked on live hardware today — no fleet node runs a tenant streamer.
//!
//! This file is the slice of that drill that needs none. Once the raft dir is
//! gone, "does the rebuilt cluster serve and does it fence a survivor" is a
//! state-machine property, provable against the exact functions the runbook
//! names — [`yubaba::state_backup::StateBackup`],
//! [`yubaba::state_backup::restorable`],
//! [`yubaba::raft::store::seed_state_machine`], `YubabaStateMachine::open`,
//! and turso-backup's real `tail_frames` — not a quorum property that needs a
//! live raft group to observe.
//!
//! ## What is deliberately NOT covered here
//!
//! `raft init`'s founding-membership commit and the ordinary openraft write
//! path are quorum properties; this file stops at proving the seeded dir is
//! legible to `YubabaStateMachine::open`, which is as far as a single-process
//! test can honestly reach without a live cluster. `tenant-streamer
//! rebuild`'s pointer-generation bump is out of scope too — it is already
//! unit-tested in `rebuild.rs`, and R736-F6 (not R869) is what makes the
//! pointer generation carry real data on the wire; wiring it in here would
//! test a mechanism that does not exist yet.
//! `a_survivor_granted_an_epoch_after_the_last_copy_still_outranks_the_restored_cluster`
//! pins that residual explicitly rather than pretending it is closed.
//!
//! ## Home
//!
//! `tests/main.rs`, not `integration_mesh.rs` — the latter is reachable only
//! from `tests/containerd.rs` behind `required-features =
//! ["containerd-integration"]`, so a test parked there never runs under a
//! default `cargo test` (R732-T6, the same trap `raft_rebuild_fencing.rs`'s
//! own docs call out).

use futures_util::StreamExt;
use object_store::memory::InMemory;
use object_store::ObjectStore as _;
use std::sync::Arc;
use tempfile::TempDir;
use turso_backup::snapshot::BackupTarget;
use turso_backup::stream::{
    tail_frames, FrameInfo, StreamConfig, StreamOutcome, WalSeam, Watermark, WAL_FRAME_HEADER_SIZE,
};
use workload_spec::secrets::SecretAccess;
use workload_spec::TenantId;
use yah_object_store::InMemoryObjectStore;
use yubaba::raft::store::seed_state_machine;
use yubaba::raft::{
    apply, TenantOutcome, YubabaNodeId, YubabaRequest, YubabaResponse, YubabaState,
    YubabaStateMachine,
};
use yubaba::state_backup::{restorable, StateBackup, Stored};

const PAGE_SIZE: usize = 4096;
/// The node that owned the tenant before the fleet died — same role
/// `raft_rebuild_fencing.rs` gives it, so a reader who has that file open
/// recognizes it immediately.
const SURVIVOR: YubabaNodeId = 1;
/// A node in the rebuilt cluster. New hardware, so a new id.
const REBUILT: YubabaNodeId = 7;

// ── Shared fixtures, modeled on raft_rebuild_fencing.rs ─────────────────────

struct TinyWal {
    frames: std::cell::RefCell<Vec<u8>>,
}

impl TinyWal {
    fn new() -> Self {
        Self {
            frames: std::cell::RefCell::new(Vec::new()),
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

fn sink() -> BackupTarget {
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
/// "wrote nothing" (see raft_rebuild_fencing.rs for why: it catches a stray
/// write anywhere in the prefix, not just at keys the test thought to name).
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

fn new_backup() -> (Arc<InMemoryObjectStore>, StateBackup) {
    let mem = Arc::new(InMemoryObjectStore::new());
    let backup = StateBackup::new(
        mem.clone() as Arc<dyn yah_object_store::ObjectStore>,
        "fleet",
    );
    (mem, backup)
}

/// Drive a real `ClaimTenant` through the real state machine and return the
/// granted epoch — never a hand-built `TenantOwnership`.
fn claim(state: &mut YubabaState, node: YubabaNodeId, lease_secs: u64, now: u64) -> u64 {
    match apply(
        state,
        &YubabaRequest::ClaimTenant {
            tenant: tenant(),
            node,
            lease_secs,
            now,
        },
    ) {
        YubabaResponse::Tenant(TenantOutcome::Granted { epoch }) => epoch,
        other => panic!("expected a grant, got {other:?}"),
    }
}

/// A fleet with non-trivial state in every map `restorable` has an opinion
/// about: members, service placement, a lock, a rollout, a secret, and a
/// tenant fenced up to epoch 5 — built entirely through `apply()`, the same
/// entry point a real committed raft log uses, never a hand-built struct
/// literal.
fn a_disaster_ready_fleet() -> YubabaState {
    let mut state = YubabaState::default();

    assert!(matches!(
        apply(
            &mut state,
            &YubabaRequest::SetMember {
                node_id: SURVIVOR,
                addr: "100.64.0.1:7443".into(),
                region: Some("us-west".into()),
                capacity: None,
                machine: Some("us-west-001".into()),
                provider: None,
                location: None,
                ingress_floating_ip: None,
                public_address: None,
            },
        ),
        YubabaResponse::Ok
    ));

    assert!(matches!(
        apply(
            &mut state,
            &YubabaRequest::SetServicePlacement {
                service: "web".into(),
                machine: "us-west-001".into(),
            },
        ),
        YubabaResponse::Ok
    ));

    assert!(matches!(
        apply(
            &mut state,
            &YubabaRequest::AcquireLock {
                key: "acme-issuer/yah.dev".into(),
                owner: "1".into(),
                ttl_secs: 86_400,
                acquired_at: 100,
            },
        ),
        YubabaResponse::LockGranted(true)
    ));

    let policy: workload_spec::rollout::RolloutPolicy =
        serde_json::from_value(serde_json::json!({ "strategy": "linear", "window_seconds": 600 }))
            .expect("policy fixture");
    assert!(matches!(
        apply(
            &mut state,
            &YubabaRequest::SetRolloutState {
                rollout_id: "rig-image-v2".into(),
                artifact: "release:rig-image@v2".into(),
                status_json: r#"{"kind":"running"}"#.into(),
                current_step: 0,
                started_at: 100,
                policy,
                trigger: serde_json::Value::Null,
                expected_revision: 0,
            },
        ),
        YubabaResponse::Rollout(_)
    ));

    assert!(matches!(
        apply(
            &mut state,
            &YubabaRequest::PutSecret {
                name: "tls/yah.dev".into(),
                ciphertext: vec![1, 2, 3, 4],
                nonce: vec![0; 12],
                updated_at: 100,
                access: SecretAccess::default(),
                digest: None,
                sans: None,
                ari: None,
            },
        ),
        YubabaResponse::Ok
    ));

    // Five ownership events (restarts / failovers) land the tenant at epoch 5
    // — the same shape raft_rebuild_fencing.rs's live-fleet fixture uses.
    for (i, now) in [1_000u64, 1_020, 1_040, 1_060, 1_080].iter().enumerate() {
        assert_eq!(claim(&mut state, SURVIVOR, 600, *now), i as u64 + 1);
    }

    state
}

// ── Steps 1-4: back up, lose everything, restore, re-open ───────────────────

/// **The composition, steps 1 through 4 of the runbook.** Back up a populated
/// state, throw away the in-memory copy (the raft dir is gone — a fresh
/// `TempDir` is all that is left), restore through `restorable` +
/// `seed_state_machine`, and re-open with the real `YubabaStateMachine` — not
/// just parse the JSON back, but hand it to the exact code a rebuilt node
/// would run and ask it what it thinks it holds.
#[tokio::test]
async fn end_to_end_rebuild_restores_everything_but_locks_and_rollouts() {
    let (_mem, backup) = new_backup();
    assert!(backup.read_latest().unwrap().is_none());

    // 1. Back up.
    let fleet = a_disaster_ready_fleet();
    assert_eq!(
        backup.store(&fleet, 193_466, SURVIVOR, 1_090).unwrap(),
        Stored::Wrote {
            lineage: 1,
            applied_index: 193_466
        }
    );

    // 2. Lose everything. The raft dir is gone; only the object store
    // survives. `fleet` itself is dropped rather than reused for the seed —
    // the object store's copy is the only thing a rebuild is allowed to read.
    drop(fleet);
    let raft_dir = TempDir::new().unwrap();

    // 3. Restore.
    let snapshot = backup
        .read_latest()
        .unwrap()
        .expect("the copy survived the loss");
    assert_eq!(snapshot.applied_index, 193_466);
    let restored = restorable(snapshot);
    assert!(
        restored.locks.is_empty(),
        "a lock from a dead holder must not survive a restore"
    );
    assert!(
        restored.rollouts.is_empty(),
        "in-flight rollout state must not survive a restore"
    );
    assert_eq!(restored.secrets.len(), 1, "secrets must survive");
    assert_eq!(
        restored.members.len(),
        1,
        "member records must survive (they get overwritten by the new founding \
         membership, but restorable() itself does not touch them)"
    );
    assert_eq!(
        restored.tenants.get(&tenant()).map(|t| t.epoch),
        Some(5),
        "tenant fencing epochs must survive, or the whole point of this ticket is moot"
    );

    seed_state_machine(raft_dir.path(), &restored).expect("seeding a fresh dir must succeed");

    // 4. Re-open — legible to the code that actually consumes it, not just to
    // serde.
    let sm = YubabaStateMachine::open(raft_dir.path().to_path_buf())
        .await
        .expect("opening a freshly seeded dir must succeed");
    let (reopened, applied_index) = sm.applied_state();
    assert_eq!(
        applied_index, None,
        "openraft must believe nothing has been applied, so the founding init \
         can still land membership at index 1"
    );
    assert_eq!(reopened.tenants.get(&tenant()).map(|t| t.epoch), Some(5));
    assert_eq!(reopened.secrets.len(), 1);
    assert!(reopened.locks.is_empty());
    assert!(reopened.rollouts.is_empty());

    // Seeding twice must be refused — `seed_state_machine` only ever applies
    // to a dir with no history of its own (R841-B1).
    let err = seed_state_machine(raft_dir.path(), &reopened).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
}

// ── Step 5: the acceptance property, both halves ─────────────────────────

/// A fleet that both streamed to the real sink at epoch 5 AND was backed up
/// at that same moment — so the raft-side epoch and the sink-side stamped
/// epoch agree, exactly as they would on a live fleet.
async fn a_fleet_that_streamed_and_was_backed_up_at_epoch_5(
    backup: &StateBackup,
    sink: &BackupTarget,
    wal: &TinyWal,
    base: &str,
) -> YubabaState {
    let mut state = YubabaState::default();
    for (i, now) in [1_000u64, 1_020, 1_040, 1_060, 1_080].iter().enumerate() {
        assert_eq!(claim(&mut state, SURVIVOR, 600, *now), i as u64 + 1);
    }
    wal.write(3);
    let out = tail_frames(wal, sink, &cfg(base, 5, 0, "survivor"))
        .await
        .unwrap();
    assert!(matches!(out, StreamOutcome::Streamed { .. }), "got {out:?}");
    assert_eq!(
        backup.store(&state, 500, SURVIVOR, 1_090).unwrap(),
        Stored::Wrote {
            lineage: 1,
            applied_index: 500
        }
    );
    state
}

/// **The acceptance property, end to end.** Restore through the exact path
/// `end_to_end_rebuild_restores_everything_but_locks_and_rollouts` proved
/// legible, then check both halves against the real sink: (a) the rebuilt
/// cluster serves, because its next claim is `snapshot_epoch + 1` and not 1;
/// (b) the survivor — who was never claimed again after the backup, so it
/// holds at most the snapshot's epoch — is refused.
///
/// FALSIFIED, not assumed: temporarily changing `restorable` to also drop
/// `tenants` (in addition to `locks`/`rollouts`) makes this test fail before
/// the sink is even touched — MEASURED, not predicted:
/// `assertion left == right failed: the rebuilt cluster's next claim must be
/// snapshot_epoch + 1, not 1 / left: 1 / right: 6`. Dropping the restored
/// epoch means the rebuilt cluster's own claim restarts at 1 exactly as an
/// un-backed-up rebuild would, which is the entire defect this ticket exists
/// to close. Probe reverted.
#[tokio::test]
async fn a_rebuilt_cluster_serves_and_a_stale_survivor_is_refused() {
    let (_mem, backup) = new_backup();
    let sink = sink();
    let wal = TinyWal::new();
    let base = "tenants/acme/snapshots/base.db".to_string();
    let _pre_loss =
        a_fleet_that_streamed_and_was_backed_up_at_epoch_5(&backup, &sink, &wal, &base).await;

    // Total loss, restore, re-open — the same production path as the test
    // above.
    let raft_dir = TempDir::new().unwrap();
    let snapshot = backup.read_latest().unwrap().expect("a copy exists");
    let restored = restorable(snapshot);
    seed_state_machine(raft_dir.path(), &restored).unwrap();
    let sm = YubabaStateMachine::open(raft_dir.path().to_path_buf())
        .await
        .unwrap();
    let (mut rebuilt, applied_index) = sm.applied_state();
    assert_eq!(applied_index, None);

    // (a) the rebuilt cluster serves.
    assert_eq!(
        claim(&mut rebuilt, REBUILT, 300, 2_000),
        6,
        "the rebuilt cluster's next claim must be snapshot_epoch + 1, not 1"
    );
    wal.write(2);
    let out = tail_frames(&wal, &sink, &cfg(&base, 6, 0, "rebuilt"))
        .await
        .unwrap();
    assert!(
        matches!(out, StreamOutcome::Streamed { .. }),
        "the rebuilt cluster must serve: {out:?}"
    );

    // (b) a resurrected survivor, holding at most the snapshot's epoch, is
    // refused.
    let objects_before = objects_at(&sink).await;
    wal.write(2);
    let out = tail_frames(&wal, &sink, &cfg(&base, 5, 0, "survivor"))
        .await
        .unwrap();
    assert_eq!(
        out,
        StreamOutcome::Fenced {
            current_epoch: 6,
            our_epoch: 5,
            current_pointer_generation: 0,
            our_pointer_generation: 0,
        },
        "a survivor at the snapshot's own epoch must lose to the rebuilt cluster"
    );
    assert_eq!(
        objects_at(&sink).await,
        objects_before,
        "a fenced writer must write nothing at all"
    );
}

/// **The bounded-staleness residual, pinned as a currently-passing property so
/// nobody mistakes silence for it being closed.**
///
/// The backup closes MOST of acceptance half (b): a survivor's epoch is fixed
/// at its last applied `ClaimTenant`, so ordinarily it is at most the
/// snapshot's and the rebuild out-fences it (proven above). But a survivor
/// claimed again — with no traffic — AFTER the last copy shipped holds an
/// epoch the snapshot never saw, and no number readable from the object store
/// bounds it. That survivor still outranks the restored cluster here, exactly
/// as it does in `raft_rebuild_fencing::an_epoch_floor_alone_loses_to_a_survivor_that_outranks_it`.
///
/// Only R736-F6's off-fleet pointer generation closes this — see the module
/// docs and R869's own `@yah:next`. Until then, `state show`'s applied-index
/// age is what an operator uses to judge how wide this window actually is;
/// this test does not narrow it, it documents it.
#[tokio::test]
async fn a_survivor_granted_an_epoch_after_the_last_copy_still_outranks_the_restored_cluster() {
    let (_mem, backup) = new_backup();
    let sink = sink();
    let wal = TinyWal::new();
    let base = "tenants/acme/snapshots/base.db".to_string();
    let mut survivor =
        a_fleet_that_streamed_and_was_backed_up_at_epoch_5(&backup, &sink, &wal, &base).await;

    // Two more ownership events after the last backup, with no traffic in
    // between — ordinary restarts, nothing malicious.
    assert_eq!(claim(&mut survivor, SURVIVOR, 10, 1_200), 6);
    assert_eq!(claim(&mut survivor, SURVIVOR, 600, 1_220), 7);

    // The fleet dies here. Restore from the now-stale snapshot.
    let raft_dir = TempDir::new().unwrap();
    let snapshot = backup.read_latest().unwrap().unwrap();
    assert_eq!(
        snapshot.state.tenants.get(&tenant()).map(|t| t.epoch),
        Some(5),
        "setup: the copy predates the survivor's last two claims"
    );
    let restored = restorable(snapshot);
    seed_state_machine(raft_dir.path(), &restored).unwrap();
    let sm = YubabaStateMachine::open(raft_dir.path().to_path_buf())
        .await
        .unwrap();
    let (mut rebuilt, _) = sm.applied_state();

    assert_eq!(claim(&mut rebuilt, REBUILT, 300, 2_000), 6);
    wal.write(2);
    let out = tail_frames(&wal, &sink, &cfg(&base, 6, 0, "rebuilt"))
        .await
        .unwrap();
    assert!(
        matches!(out, StreamOutcome::Streamed { .. }),
        "the restored copy does close the availability half: {out:?}"
    );

    // The survivor is resurrected, deliberately, as the chaos drill does.
    wal.write(2);
    let out = tail_frames(&wal, &sink, &cfg(&base, 7, 0, "survivor"))
        .await
        .unwrap();
    assert!(
        matches!(out, StreamOutcome::Streamed { .. }),
        "THE RESIDUAL: an epoch the snapshot never saw still outranks the \
         restored cluster: {out:?}"
    );

    // And the legitimate, rebuilt cluster is now the one fenced.
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
        "the zombie won and the rebuilt cluster lost its own tenant"
    );
}

// ── Step 6: re-arm ────────────────────────────────────────────────────────

/// **Step 6, the one P3's summary omitted and P4 caught.** Without `adopt`,
/// the rebuilt cluster's own low `applied_index` looks exactly like a wiped
/// node to `StateBackup::store`'s monotonicity guard — so a rebuild that
/// skips this step silently never backs itself up again, forever, with
/// nothing to page on.
///
/// FALSIFIED, not assumed: temporarily disabling the
/// `applied_index < stored.applied_index` arm in `StateBackup::store` — the
/// exact style state_backup.rs's own probe used — makes the first assertion
/// below fail. MEASURED, not predicted:
/// `assertion left == right failed: an un-adopted rebuild must not be able to
/// overwrite the pre-rebuild copy / left: Wrote { lineage: 1, applied_index: 1 }
/// / right: Regressed { stored: 193466, local: 1 }` — the exact 2026-08-31
/// incident, reproduced through this test's own restore path rather than P2's
/// isolated one. Probe reverted.
#[tokio::test]
async fn adopt_is_what_lets_the_rebuilt_cluster_back_itself_up_again() {
    let (_mem, backup) = new_backup();
    let fleet = a_disaster_ready_fleet();
    assert_eq!(
        backup.store(&fleet, 193_466, SURVIVOR, 1_090).unwrap(),
        Stored::Wrote {
            lineage: 1,
            applied_index: 193_466
        }
    );
    drop(fleet);

    let raft_dir = TempDir::new().unwrap();
    let snapshot = backup.read_latest().unwrap().unwrap();
    let restored = restorable(snapshot);
    seed_state_machine(raft_dir.path(), &restored).unwrap();
    let sm = YubabaStateMachine::open(raft_dir.path().to_path_buf())
        .await
        .unwrap();
    let (rebuilt_state, _) = sm.applied_state();

    // The fresh cluster applies its founding membership and tries to resume
    // backing up. Refused: to the guard this looks identical to a wiped node.
    assert_eq!(
        backup.store(&rebuilt_state, 1, REBUILT, 2_000).unwrap(),
        Stored::Regressed {
            stored: 193_466,
            local: 1
        },
        "an un-adopted rebuild must not be able to overwrite the pre-rebuild copy"
    );

    // An operator runs `state adopt`: the pre-rebuild copy is archived first…
    let lineage = backup.adopt(2_100).unwrap();
    assert_eq!(lineage, 2);
    let archived = backup.read_lineage(1).unwrap().unwrap();
    assert_eq!(
        archived.state.tenants.get(&tenant()).map(|t| t.epoch),
        Some(5),
        "the archived copy is the pre-rebuild state, untouched"
    );

    // …and now the exact write the guard just refused is accepted.
    assert_eq!(
        backup.store(&rebuilt_state, 1, REBUILT, 2_200).unwrap(),
        Stored::Wrote {
            lineage: 2,
            applied_index: 1
        },
        "adopt must be what re-arms the guard for the new incarnation"
    );
}
