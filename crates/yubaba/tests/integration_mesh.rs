//! Multi-node local mesh integration tests — R091-F6.
//!
//! Exercises the full 3-node yubaba cluster: raft consensus, workload deploy
//! + state replication, partition recovery, and quorum-loss behavior.
//!
//! ## Running
//!
//! ```bash
//! # Local tier — requires a running containerd socket (Colima on macOS):
//! cargo test -p yubaba --features containerd-integration \
//!     --test containerd -- integration_mesh::
//!
//! # With the __local filter (matches expanded macro names):
//! cargo test -p yubaba --features containerd-integration \
//!     --test containerd -- integration_mesh::multi_node_mesh__local
//!
//! # Smoke tier — provisions real Hetzner CPX-11s (est. $0.15):
//! YAH_SMOKE=1 \
//! HETZNER_API_TOKEN=... \
//! YAH_WARDEN_URL=https://... \
//! YAH_WARDEN_SHA256=<sha256> \
//! cargo test -p yubaba --features containerd-integration \
//!     --test containerd -- integration_mesh:: --ignored
//! ```
//!
//! ## What is and isn't tested here
//!
//! **Tested (local tier)**:
//! - 3-node openraft cluster bootstraps and elects a leader.
//! - Workload deployed on node 0 reaches Running via the FakeRuntime.
//! - Node 1 can resolve the workload by mesh identity (raft state replication).
//! - Partition: killing a non-leader follower leaves 2/3 quorum intact; the
//!   leader continues to accept writes.
//! - Partition recovery: restarted node re-joins and its `/health` returns 200.
//! - Quorum-loss: killing 2/3 nodes (losing quorum) causes the surviving node
//!   to report `X-State-Freshness: stale` on reads and 503 on writes.
//!
//! **NOT tested (KNOWN-LOCAL-GAP)**:
//! - WireGuard-routed traffic between nodes — local tier uses loopback HTTP;
//!   see yah-yubaba-integration-testing.md §KNOWN-LOCAL-GAPS.
//! - Real cloud-init boot path, real WireGuard NAT traversal, real CF tunnels.
//!   These are exercised in the smoke tier.
//!
//! @arch:see(.yah/docs/architecture/A053-yah-yubaba-integration-testing.md)
//! @arch:see(.yah/docs/architecture/A032-yah-cluster-mesh.md)
//!
//! @yah:ticket(R732-T6, "R732-T5's split-brain fencing tests never run by default — extract from integration_mesh.rs like R737-T5 did")
//! @yah:at(2026-09-08T08:00:22Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R732)
//! @yah:next("Extract the split_brain module out of integration_mesh.rs into its own gate-free test file (mirror raft_tenant_placement.rs's approach for R737-T5), register it in tests/main.rs, and confirm it still passes with zero cargo features. Leave multi_node_mesh and the other containerd-integration-gated tests in integration_mesh.rs untouched.")
//! @yah:verify("cargo test -p yubaba --test main -- split_brain:: passes with no feature flags; cargo test -p yubaba --features containerd-integration --test containerd -- integration_mesh:: still passes for the tests that remain there.")
//! @yah:gotcha("The split_brain module (4 tests, R732-T5) drives two in-process YubabaState instances through real raft::apply and a real turso-backup BackupTarget over an in-memory object store — it never touches containerd or the Cluster/FakeRuntime harness. It is gated behind --features containerd-integration only because it lives in integration_mesh.rs alongside multi_node_mesh, which DOES need that feature. Default `cargo test -p yubaba` therefore never runs W253 §9's canonical proof — the exact 'passes vacuously' trap raft_tenant_placement.rs:22 documents R737-T5 hitting and fixing for the same reason.")
//! @arch:see(oss/yubaba/crates/yubaba/tests/raft_tenant_placement.rs)

use std::time::Duration;

use cloud::provider::MachineProvider;
use kamaji::Kamaji as ContainerRuntime;
use workload_spec::{
    ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits, RestartPolicy,
    SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
};
use yubaba_test_harness::{test_cluster, wait_for_state, WorkloadStatus};
use yubaba_test_macros::test_with_provider;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn test_workload_spec(name: &str) -> WorkloadSpec {
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: name.to_string(),
        image: ImageRef {
            registry: "docker.io".into(),
            repository: "library/alpine".into(),
            tag: "latest".into(),
            digest: workload_spec::testing::test_digest(),
        },
        tier: TierTag("infra".into()),
        tenant: workload_spec::TenantId::singleton(),
        namespace: workload_spec::NamespaceId::singleton(),
        replicas: 1,
        command: Some(vec!["sh".into(), "-c".into(), "sleep 300".into()]),
        entrypoint: None,
        workdir: None,
        user: None,
        env: vec![],
        secrets: vec![],
        volumes: vec![],
        resources: ResourceLimits {
            memory_mb: 64,
            cpu_millis: 128,
            ephemeral_storage_mb: 128,
        },
        depends_on: vec![],
        requires: vec![],
        healthcheck: None,
        restart_policy: RestartPolicy::Never,
        archetype: None,
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(5),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent(name.to_string()),
                ports: MeshExpose::anonymous_ports([]),
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: Default::default(),
        annotations: Default::default(),
    }
}

// ── Multi-node mesh test ──────────────────────────────────────────────────────

/// Multi-node cluster: happy path + partition recovery + quorum-loss.
///
/// A 3-node yubaba cluster is used throughout (raft quorum = 2/3). The test
/// runs three sequential scenarios to avoid provisioning overhead:
///
/// 1. **Happy path**: deploy on node 0, assert node 1 can see it (raft replication).
/// 2. **Partition**: kill a non-leader, assert leader continues accepting writes,
///    restart the killed node and assert it re-joins cleanly.
/// 3. **Quorum-loss**: kill 2 followers, assert read path survives with stale
///    header and write path returns 503.
///
/// Local tier: all nodes are in-process yubaba servers connected by real
/// openraft over loopback HTTP. Container runtimes are wired in but workload
/// containers aren't actually running (raft + orchestration logic is exercised).
///
/// Smoke tier: 3 real Hetzner machines across regions with real WireGuard mesh.
#[test_with_provider(local, smoke)]
async fn multi_node_mesh<P, R>(p: P, rt: R)
where
    P: MachineProvider + Clone + Send + Sync + 'static,
    R: ContainerRuntime + 'static,
{
    // ── Setup: 3-node cluster ─────────────────────────────────────────────────
    let mut cluster = test_cluster(&p, rt, 3)
        .await
        .expect("3-node cluster should provision");

    // Wait for raft to elect a leader before any workload operations.
    let leader_idx = cluster
        .wait_for_leader(Duration::from_secs(15))
        .await
        .expect("raft leader should be elected within 15s of bootstrap");

    // ── Scenario 1: Happy path ────────────────────────────────────────────────

    let spec = test_workload_spec("mesh-app");
    cluster
        .yubaba(leader_idx)
        .deploy_workload(&spec)
        .await
        .expect("deploy on leader should succeed");

    wait_for_state(
        cluster.yubaba(leader_idx),
        &spec.expose.mesh.identity,
        WorkloadStatus::Running,
        Duration::from_secs(60),
    )
    .await
    .expect("mesh-app should reach Running on the leader node");

    // Pick a non-leader node to verify state replication.
    let peer_idx = (0..3).find(|&i| i != leader_idx).unwrap();

    // Node `peer_idx` can resolve the workload by mesh identity via raft
    // replication.
    //
    // KNOWN-LOCAL-GAP: in the local tier this verifies raft state replication
    // (workload state is visible on peer via raft-replicated runtime), NOT
    // actual WireGuard-routed HTTP traffic. Smoke tier exercises real wire routing.
    let resp = cluster
        .yubaba(peer_idx)
        .mesh_get(&spec.expose.mesh.identity, 8080, "/health")
        .await
        .expect("mesh_get from peer node should succeed");
    assert_eq!(
        resp.status, 200,
        "peer node {peer_idx} should see Running workload via raft; got body: {}",
        resp.body,
    );

    // Deploy a second workload on the peer node to verify any member can deploy.
    let spec_peer = test_workload_spec("mesh-app-peer");
    cluster
        .yubaba(peer_idx)
        .deploy_workload(&spec_peer)
        .await
        .expect("any node can dispatch a deploy (raft routes to leader)");

    // ── Scenario 2: Partition — kill non-leader, leader continues ─────────────

    // Kill a follower that is not the leader (and not peer_idx if possible, to
    // keep peer_idx alive for the quorum-loss phase).
    let victim_idx = (0..3)
        .find(|&i| i != leader_idx)
        .expect("must find a non-leader to kill");

    cluster
        .kill_node(victim_idx)
        .await
        .expect("kill non-leader follower");

    // 2/3 quorum remains: leader should continue accepting writes.
    let spec_after_partition = test_workload_spec("mesh-app-post-partition");
    cluster
        .yubaba(leader_idx)
        .deploy_workload(&spec_after_partition)
        .await
        .expect("leader must accept writes with 2/3 quorum after one follower killed");

    // Restart the killed node. It re-opens its raft state from disk and
    // re-joins the cluster by receiving AppendEntries from the leader.
    cluster
        .restart_node(victim_idx)
        .await
        .expect("killed node should restart cleanly");

    // Give raft time to send the restarted node the missed entries.
    tokio::time::sleep(Duration::from_secs(5)).await;

    cluster
        .yubaba(victim_idx)
        .health_check()
        .await
        .expect("restarted node should be healthy after re-joining cluster");

    // ── Scenario 3: Quorum-loss — 2/3 nodes dead ──────────────────────────────

    // Kill the victim again (it was restarted in scenario 2) and one other
    // follower. The leader survives but loses quorum.
    let second_victim_idx = (0..3)
        .find(|&i| i != leader_idx && i != victim_idx)
        .unwrap_or(victim_idx); // fallback if victim_idx == leader_idx somehow

    cluster
        .kill_node(victim_idx)
        .await
        .expect("kill first node for quorum-loss test");

    // Only kill a second node if it's distinct (avoid killing the leader).
    if second_victim_idx != victim_idx && second_victim_idx != leader_idx {
        cluster
            .kill_node(second_victim_idx)
            .await
            .expect("kill second node for quorum-loss test");
    } else {
        // Kill the other follower (different from victim_idx and leader_idx).
        let alt_victim = (0..3)
            .find(|&i| i != leader_idx && i != victim_idx)
            .expect("must find a second node to kill");
        cluster
            .kill_node(alt_victim)
            .await
            .expect("kill alt second node for quorum-loss test");
    }

    // Give raft time to detect quorum loss. The leader's heartbeats to
    // followers will start timing out (election_timeout_max = 3s). After the
    // timeout, the leader steps down (current_leader becomes None).
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Read path stays up on the surviving node with X-State-Freshness: stale.
    let raw_client = reqwest::Client::new();
    let state_url = format!(
        "{}/workloads/{}/state",
        cluster.yubaba(leader_idx).base_url,
        spec.expose.mesh.identity.0,
    );
    let read_resp = raw_client
        .get(&state_url)
        .send()
        .await
        .expect("GET /workloads/{ident}/state should be reachable on surviving node");

    assert!(
        read_resp.status().is_success() || read_resp.status().as_u16() == 404,
        "read path must stay up when quorum lost (got HTTP {})",
        read_resp.status(),
    );

    let freshness = read_resp
        .headers()
        .get("x-state-freshness")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing");
    assert_eq!(
        freshness, "stale",
        "x-state-freshness must be 'stale' when quorum is lost (raft leader stepped down)"
    );

    // Write path returns 503 when quorum is lost.
    let write_spec =
        serde_json::to_value(test_workload_spec("quorum-rejected")).expect("serialize spec");
    let write_resp = raw_client
        .post(format!(
            "{}/workloads/deploy",
            cluster.yubaba(leader_idx).base_url,
        ))
        .json(&serde_json::json!({ "spec": write_spec }))
        .send()
        .await
        .expect("POST /workloads/deploy should be reachable even with quorum lost");

    assert_eq!(
        write_resp.status().as_u16(),
        503,
        "write path must return 503 when quorum is lost (got HTTP {})",
        write_resp.status(),
    );

    // Cluster teardown happens in Drop (aborts all remaining tasks).
}

// ── R732-T5 (W245 / W253 §9): the canonical split-brain test ─────────────────

/// **Deliberate split-brain attempt.** W253 §9: *"partition a tenant's master
/// so the control plane fails it over to a new node; heal the partition;
/// confirm the old master is fenced (stale epoch ⇒ R2 writes bounce). If only
/// one experiment ever runs, it's this one."*
///
/// ## What this models, and what it does not
///
/// A network partition is, at the layer this property lives on, exactly one
/// thing: **the isolated node's applied raft state stops advancing while the
/// quorum's continues.** So the partition is modelled by driving two
/// independent `YubabaState`s through `raft::apply` — the real state-machine
/// transition function, with the real `TransferTenant` CAS — and feeding the
/// isolated node's copy nothing during the partition window. The old master
/// keeps running the whole time, which is the point: a killed node writes
/// nothing and would prove nothing.
///
/// openraft's own partition/election/quorum-loss behaviour is not re-tested
/// here — `multi_node_mesh` above already covers it over real loopback HTTP.
/// What that test cannot do is keep a partitioned master *alive and writing*,
/// which is the only interesting case for fencing.
///
/// The R2 sink is a real `turso-backup` `BackupTarget` over an in-memory
/// object store, driven through the real `tail_frames`, so the fence itself —
/// epoch comparison, watermark CAS, frame keys, manifests — is not simulated.
///
/// ## The oracle (W253 §9 "no chaos without measurement")
///
/// A client-side ledger records every write and whether it was **acked**, an
/// ack meaning "a `tail_frames` call covering this frame reported success".
/// After recovery the ledger is reconciled against what a restore would
/// actually replay, and the run reports **RTO** (partition → new owner serving)
/// and **RPO** (acked writes lost). The steady-state hypothesis under test is
/// W253's: *split-brain is never observable* — RPO for acked writes is 0.
mod split_brain {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Instant;

    use futures_util::StreamExt;
    use object_store::memory::InMemory;
    use object_store::ObjectStore;
    use turso_backup::snapshot::BackupTarget;
    use turso_backup::stream::{
        list_and_parse_generation_manifests, tail_frames, FrameInfo, StreamConfig, StreamOutcome,
        WalSeam, Watermark, WAL_FRAME_HEADER_SIZE,
    };
    use workload_spec::TenantId;
    use yubaba::raft::{apply, TenantOutcome, YubabaRequest, YubabaResponse, YubabaState};

    const PAGE_SIZE: usize = 4096;
    const NODE_A: u64 = 1;
    const NODE_B: u64 = 2;

    /// The tenant's WAL. Both nodes read the same logical database — B has
    /// hydrated the tenant's local copy — so this is one frame log that each
    /// node's seam view is taken over.
    struct LedgerWal {
        frames: RefCell<Vec<u8>>, // one fill byte per frame; contents are irrelevant
    }

    impl LedgerWal {
        fn new() -> Self {
            Self {
                frames: RefCell::new(Vec::new()),
            }
        }
        /// Accept a write. Returns the frame number the client is waiting on
        /// an ack for.
        fn write(&self) -> u64 {
            let mut f = self.frames.borrow_mut();
            let next = f.len() as u8;
            f.push(next);
            f.len() as u64
        }
        fn len(&self) -> u64 {
            self.frames.borrow().len() as u64
        }
    }

    impl WalSeam for LedgerWal {
        fn wal_state(&self) -> anyhow::Result<Watermark> {
            Ok(Watermark {
                checkpoint_seq: 0,
                last_frame: self.len(),
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

    /// One client-visible write and its fate.
    #[derive(Debug)]
    struct LedgerEntry {
        frame_no: u64,
        acked: bool,
    }

    /// Every object under the sink, counted. The strongest available form of
    /// "wrote zero frames": it catches a stray frame, manifest, or watermark
    /// rewrite anywhere in the prefix, not just at keys the test thought to
    /// name.
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

    fn target() -> BackupTarget {
        BackupTarget {
            store: Arc::new(InMemory::new()),
            prefix: "tenants/acme".into(),
        }
    }

    fn cfg<'a>(base: &'a str, epoch: u64, owner: &'a str) -> StreamConfig<'a> {
        StreamConfig {
            base_snapshot_key: base,
            page_size: PAGE_SIZE,
            backpressure: Default::default(),
            rpo_target: None,
            epoch,
            owner: Some(owner),
            pointer_generation: 0,
        }
    }

    /// Ask raft (this node's applied state) for a fencing token, exactly as
    /// `TenantStreamer` does in production.
    fn token(state: &YubabaState, tenant: &TenantId, node: u64, now: u64) -> Option<u64> {
        state.tenant_fencing_token(tenant, node, now)
    }

    #[tokio::test]
    async fn the_old_master_is_fenced_after_the_partition_heals() {
        let tenant = TenantId("acme".into());
        let base = "tenants/acme/snapshots/base.db".to_string();
        let sink = target();
        let wal = LedgerWal::new();
        let mut ledger: Vec<LedgerEntry> = Vec::new();

        // Node A's applied state and the quorum's applied state start
        // identical. `quorum` is what the surviving majority converges on;
        // `a_state` is node A's private copy, which the partition freezes.
        let mut a_state = YubabaState::default();
        let mut quorum = YubabaState::default();

        // ── Steady state: A claims the tenant and streams ─────────────────
        // A deliberately long lease. The dangerous window is not "the old
        // master's lease expired and it kept writing anyway" — that one is
        // easy. It is "the old master's lease is still perfectly valid, it has
        // every local reason to believe it owns the tenant, and the quorum
        // transferred it away regardless" (TransferTenant is the authorized
        // takeover path and does not wait for expiry). If the fence only held
        // once the lease lapsed, the epoch would be redundant with the timeout
        // — and this test would be proving the wrong thing.
        let claim = YubabaRequest::ClaimTenant {
            tenant: tenant.clone(),
            node: NODE_A,
            lease_secs: 300,
            now: 1_000,
        };
        for st in [&mut a_state, &mut quorum] {
            assert!(matches!(
                apply(st, &claim),
                YubabaResponse::Tenant(TenantOutcome::Granted { epoch: 1 })
            ));
        }
        let a_epoch = token(&a_state, &tenant, NODE_A, 1_005).expect("A owns the tenant");
        assert_eq!(a_epoch, 1);

        let mut pending: Vec<u64> = (0..3).map(|_| wal.write()).collect();
        let out = tail_frames(&wal, &sink, &cfg(&base, a_epoch, "node-a"))
            .await
            .unwrap();
        assert!(matches!(out, StreamOutcome::Streamed { .. }), "got {out:?}");
        for frame_no in pending.drain(..) {
            ledger.push(LedgerEntry {
                frame_no,
                acked: true,
            });
        }

        // ── Partition begins. A keeps serving; the quorum stops hearing it ─
        let partition_at = Instant::now();

        // A is isolated from raft but NOT from R2, and it is still the
        // recorded owner at epoch 1 — so these writes are correctly acked.
        // This window is legitimate, and a design that broke it would be
        // trading availability for a safety property it already has.
        let during: Vec<u64> = (0..2).map(|_| wal.write()).collect();
        let out = tail_frames(&wal, &sink, &cfg(&base, a_epoch, "node-a"))
            .await
            .unwrap();
        assert!(
            matches!(out, StreamOutcome::Streamed { .. }),
            "a partitioned-but-still-owning master must keep streaming: {out:?}"
        );
        for frame_no in during {
            ledger.push(LedgerEntry {
                frame_no,
                acked: true,
            });
        }

        // ── Failover: the quorum transfers the tenant to B. A never sees it ─
        let transfer = YubabaRequest::TransferTenant {
            tenant: tenant.clone(),
            to: NODE_B,
            from_epoch: 1,
            lease_secs: 30,
            now: 1_100,
        };
        assert!(matches!(
            apply(&mut quorum, &transfer),
            YubabaResponse::Tenant(TenantOutcome::Granted { epoch: 2 })
        ));
        assert_eq!(
            token(&a_state, &tenant, NODE_A, 1_105),
            Some(1),
            "the isolated node still believes it owns the tenant at its old epoch, \
             on a lease that has NOT expired — this is the whole hazard, and it \
             must not be papered over"
        );

        // B hydrates and takes over. RTO stops when B first serves.
        let b_epoch = token(&quorum, &tenant, NODE_B, 1_105).expect("B owns the tenant");
        assert_eq!(b_epoch, 2);
        let after: Vec<u64> = (0..3).map(|_| wal.write()).collect();
        let out = tail_frames(&wal, &sink, &cfg(&base, b_epoch, "node-b"))
            .await
            .unwrap();
        assert!(matches!(out, StreamOutcome::Streamed { .. }), "got {out:?}");
        let rto = partition_at.elapsed();
        for frame_no in after {
            ledger.push(LedgerEntry {
                frame_no,
                acked: true,
            });
        }

        // ── The split-brain attempt ───────────────────────────────────────
        // The partition heals. A never stopped: it accepted more writes and
        // now tries to stream them under the token it still holds.
        let manifests_before = list_and_parse_generation_manifests(&sink).await.unwrap();
        let objects_before = objects_at(&sink).await;
        let orphaned: Vec<u64> = (0..4).map(|_| wal.write()).collect();
        let stale_epoch = token(&a_state, &tenant, NODE_A, 1_200).expect("A still thinks it owns");
        let out = tail_frames(&wal, &sink, &cfg(&base, stale_epoch, "node-a"))
            .await
            .unwrap();

        assert_eq!(
            out,
            StreamOutcome::Fenced {
                current_epoch: 2,
                our_epoch: 1,
                current_pointer_generation: 0,
                our_pointer_generation: 0,
            },
            "THE assertion: the old master's R2 writes must bounce"
        );
        for frame_no in orphaned {
            // Never acked — the client's write never reached durable storage,
            // and the client was told so.
            ledger.push(LedgerEntry {
                frame_no,
                acked: false,
            });
        }

        // …and it wrote ZERO frames doing it.
        assert_eq!(
            list_and_parse_generation_manifests(&sink).await.unwrap(),
            manifests_before,
            "a fenced master must not publish a generation"
        );
        assert_eq!(
            objects_at(&sink).await,
            objects_before,
            "a fenced master must leave the sink byte-for-byte as the winner left it — \
             not one frame, not one manifest, not a watermark rewrite"
        );

        // ── Reconciliation + the two numbers ──────────────────────────────
        // Every ACKED write must be replayable from the sink.
        let chain = list_and_parse_generation_manifests(&sink).await.unwrap();
        let replayable: u64 = chain.iter().map(|m| m.last_frame).max().unwrap_or(0);
        let acked: Vec<u64> = ledger
            .iter()
            .filter(|e| e.acked)
            .map(|e| e.frame_no)
            .collect();
        let lost: Vec<u64> = acked.iter().copied().filter(|f| *f > replayable).collect();

        assert!(
            lost.is_empty(),
            "RPO violation — acked writes {lost:?} are not replayable (chain reaches {replayable})"
        );
        assert_eq!(
            acked.len(),
            8,
            "3 steady + 2 during partition + 3 under the new owner"
        );
        assert_eq!(
            replayable, 8,
            "the chain must cover exactly the acked writes and none of the fenced ones"
        );

        // Both owners' generations survive, in epoch order, and the chain the
        // restore path would actually take is valid.
        let epochs: Vec<u64> = chain.iter().map(|m| m.epoch).collect();
        assert_eq!(epochs, vec![1, 1, 2], "A's two generations, then B's");
        let owners: Vec<Option<&str>> = chain.iter().map(|m| m.owner.as_deref()).collect();
        assert_eq!(owners, vec![Some("node-a"), Some("node-a"), Some("node-b")]);

        eprintln!(
            "R732-T5 split-brain: RTO={rto:?} RPO=0 acked writes lost \
             (of {} acked; {} writes bounced un-acked at the fence)",
            acked.len(),
            ledger.iter().filter(|e| !e.acked).count(),
        );
    }

    /// The other half of the steady-state hypothesis: **graceful drain loses
    /// zero acked writes.** A hands over deliberately instead of being
    /// partitioned, so there is no un-streamed tail to lose.
    #[tokio::test]
    async fn a_graceful_transfer_loses_no_acked_writes() {
        let tenant = TenantId("acme".into());
        let base = "tenants/acme/snapshots/base.db".to_string();
        let sink = target();
        let wal = LedgerWal::new();
        let mut state = YubabaState::default();

        apply(
            &mut state,
            &YubabaRequest::ClaimTenant {
                tenant: tenant.clone(),
                node: NODE_A,
                lease_secs: 30,
                now: 1_000,
            },
        );
        for _ in 0..4 {
            wal.write();
        }
        // Drain: stream everything, THEN hand over.
        tail_frames(&wal, &sink, &cfg(&base, 1, "node-a"))
            .await
            .unwrap();
        apply(
            &mut state,
            &YubabaRequest::TransferTenant {
                tenant: tenant.clone(),
                to: NODE_B,
                from_epoch: 1,
                lease_secs: 30,
                now: 1_010,
            },
        );

        // B picks up with nothing outstanding.
        let b_epoch = token(&state, &tenant, NODE_B, 1_015).unwrap();
        let out = tail_frames(&wal, &sink, &cfg(&base, b_epoch, "node-b"))
            .await
            .unwrap();
        assert!(
            matches!(out, StreamOutcome::Empty { .. }),
            "a drained handover leaves nothing for the new owner to catch up: {out:?}"
        );
        let chain = list_and_parse_generation_manifests(&sink).await.unwrap();
        assert_eq!(chain.iter().map(|m| m.last_frame).max(), Some(4), "RPO = 0");
    }

    /// A node that has been fenced must not be able to keep its lease alive
    /// under the stale token either — otherwise it would look healthy to
    /// every readiness gate while being unable to write a byte.
    #[tokio::test]
    async fn a_fenced_node_cannot_renew_its_lease() {
        let tenant = TenantId("acme".into());
        let mut state = YubabaState::default();
        apply(
            &mut state,
            &YubabaRequest::ClaimTenant {
                tenant: tenant.clone(),
                node: NODE_A,
                lease_secs: 30,
                now: 1_000,
            },
        );
        apply(
            &mut state,
            &YubabaRequest::TransferTenant {
                tenant: tenant.clone(),
                to: NODE_B,
                from_epoch: 1,
                lease_secs: 30,
                now: 1_010,
            },
        );
        let resp = apply(
            &mut state,
            &YubabaRequest::RenewTenantLease {
                tenant: tenant.clone(),
                node: NODE_A,
                epoch: 1,
                lease_secs: 30,
                now: 1_015,
            },
        );
        assert!(matches!(
            resp,
            YubabaResponse::Tenant(TenantOutcome::Fenced {
                current_epoch: 2,
                ..
            })
        ));
        assert_eq!(
            token(&state, &tenant, NODE_A, 1_015),
            None,
            "a fenced node must get no token at all"
        );
    }

    /// Ownership drives the streamer end to end, through the real
    /// `yubaba-tenant-streamer` tail loop rather than a re-implementation of
    /// it: an unowned tenant is never attempted and writes nothing, and the
    /// same loop starts streaming the instant raft grants a token.
    ///
    /// The loop runs in-process here because it is a library
    /// ([`yubaba_test_harness::LocalOwnership`] hands it this test's own
    /// `YubabaState` instead of an HTTP endpoint). In production the same code
    /// runs as a separate kamaji-managed service and pulls the token over
    /// `GET /tenants/{id}` — W253 tenet 1 keeps the byte mover out of the
    /// consensus process.
    #[tokio::test]
    async fn the_streamer_only_tails_tenants_this_node_owns() {
        use std::sync::Mutex;
        use yubaba_tenant_streamer::streamer::{TenantSink, TenantStreamer, TenantTick};
        use yubaba_test_harness::LocalOwnership;

        let tenant = TenantId("acme".into());
        let sink = target();
        let state = Arc::new(Mutex::new(YubabaState::default()));
        let ownership = LocalOwnership::new(state.clone(), NODE_A, 1_000);

        let streamer = TenantStreamer::new(
            ownership,
            BTreeMap::from([(
                tenant.clone(),
                TenantSink {
                    target: BackupTarget {
                        store: sink.store.clone(),
                        prefix: sink.prefix.clone(),
                    },
                    base_snapshot_key: "tenants/acme/snapshots/base.db".into(),
                    page_size: PAGE_SIZE,
                },
            )]),
            streamer_config(),
        );

        // No ownership record: nothing is attempted, and — asserted as a full
        // object count, not a check of keys we thought to name — nothing at all
        // reaches the sink.
        let wal = LedgerWal::new();
        wal.write();
        let seams = BTreeMap::from([(tenant.clone(), wal)]);
        let ticks = streamer.tick(&seams).await;
        assert_eq!(ticks.len(), 1);
        assert!(
            matches!(ticks[0].1, TenantTick::NotOwner),
            "an unowned tenant must not be tailed: {:?}",
            ticks[0].1
        );
        assert_eq!(
            objects_at(&sink).await,
            0,
            "an unowned tenant must write nothing"
        );

        // Grant ownership through the real state machine, and the very next
        // tick streams — under the epoch raft minted, with no restart and no
        // reconfiguration. Ownership is the only input that changed.
        let granted = apply(
            &mut state.lock().unwrap(),
            &YubabaRequest::ClaimTenant {
                tenant: tenant.clone(),
                node: NODE_A,
                lease_secs: 300,
                now: 1_000,
            },
        );
        assert!(matches!(
            granted,
            YubabaResponse::Tenant(TenantOutcome::Granted { epoch: 1 })
        ));

        let ticks = streamer.tick(&seams).await;
        match &ticks[0].1 {
            TenantTick::Tailed {
                epoch,
                outcome: StreamOutcome::Streamed { last_frame, .. },
            } => {
                assert_eq!(*epoch, 1, "the streamer must use the epoch raft granted");
                assert_eq!(*last_frame, 1);
            }
            other => panic!("expected a stream under epoch 1, got {other:?}"),
        }
        assert!(objects_at(&sink).await > 0);
    }

    /// The wire contract between yubaba and the streamer, which is otherwise
    /// unchecked in either direction.
    ///
    /// `yubaba-tenant-streamer` deliberately does NOT link this crate (that
    /// dependency is exactly the control/data coupling W253 tenet 1 forbids),
    /// so it hand-builds the `POST /raft/write` body for a lease renewal. That
    /// makes the field names a wire contract with no compiler behind it: rename
    /// `lease_secs` on the enum and the streamer keeps compiling, keeps
    /// deploying, and silently stops being able to renew a lease — every node
    /// would lose every tenant one lease-TTL after the rename shipped.
    ///
    /// This test is the compiler for that seam. It is the literal JSON
    /// `HttpOwnership::renew_lease` sends.
    #[test]
    fn the_streamer_lease_renewal_body_deserializes_into_a_raft_request() {
        let body = serde_json::json!({
            "RenewTenantLease": {
                "tenant": "acme",
                "node": 7u64,
                "epoch": 3u64,
                "lease_secs": 300u64,
                "now": 1_000u64,
            }
        });
        let req: YubabaRequest = serde_json::from_value(body)
            .expect("the streamer's renewal body must deserialize into YubabaRequest");
        match req {
            YubabaRequest::RenewTenantLease {
                tenant,
                node,
                epoch,
                lease_secs,
                now,
            } => {
                assert_eq!(tenant, TenantId("acme".into()));
                assert_eq!((node, epoch, lease_secs, now), (7, 3, 300, 1_000));
            }
            other => panic!("expected RenewTenantLease, got {other:?}"),
        }
    }

    /// The other half of the same seam: the streamer parses yubaba's reply by
    /// hand, so the response shape is a contract too. A `Granted` that stopped
    /// decoding would read as an error and stall every renewal; a `Fenced` that
    /// stopped decoding would leave a fenced node believing it still owns the
    /// tenant, which is the direction that actually costs data.
    #[test]
    fn the_raft_write_reply_matches_what_the_streamer_parses() {
        let granted =
            serde_json::to_value(YubabaResponse::Tenant(TenantOutcome::Granted { epoch: 4 }))
                .unwrap();
        assert_eq!(
            granted,
            serde_json::json!({ "Tenant": { "Granted": { "epoch": 4 } } }),
            "HttpOwnership::renew_lease reads exactly this shape"
        );

        let fenced = serde_json::to_value(YubabaResponse::Tenant(TenantOutcome::Fenced {
            current_epoch: 9,
            current_owner: Some(2),
        }))
        .unwrap();
        assert_eq!(
            fenced,
            serde_json::json!({
                "Tenant": { "Fenced": { "current_epoch": 9, "current_owner": 2 } }
            })
        );
    }

    /// A config for the loop with the lease knobs the split-brain scenario
    /// needs: a long lease, so that at the moment of the fenced write attempt
    /// the old master still holds a perfectly valid lease and has every local
    /// reason to believe it owns the tenant. Only the epoch stops it. (A short
    /// lease is how the first draft of this suite passed for the wrong reason.)
    fn streamer_config() -> yubaba_tenant_streamer::StreamerConfig {
        yubaba_tenant_streamer::StreamerConfig {
            node_id: NODE_A,
            yubaba_url: "http://127.0.0.1:1".into(),
            data_root: std::path::PathBuf::from("/nonexistent"),
            sink: yubaba_tenant_streamer::SinkConfig {
                bucket: "test".into(),
                endpoint: "http://127.0.0.1:1".into(),
                region: "auto".into(),
                prefix: String::new(),
                access_key_env: None,
                secret_key_env: None,
            },
            tenants: vec![],
            rpo_secs: 30,
            lease_secs: 300,
        }
    }
}
