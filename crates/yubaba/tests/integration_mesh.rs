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
//!     --test integration_mesh
//!
//! # With the __local filter (matches expanded macro names):
//! cargo test -p yubaba --features containerd-integration \
//!     --test integration_mesh multi_node_mesh__local
//!
//! # Smoke tier — provisions real Hetzner CPX-11s (est. $0.15):
//! YAH_SMOKE=1 \
//! HETZNER_API_TOKEN=... \
//! YAH_WARDEN_URL=https://... \
//! YAH_WARDEN_SHA256=<sha256> \
//! cargo test -p yubaba --features containerd-integration \
//!     --test integration_mesh -- --ignored
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

use std::time::Duration;

use cloud::provider::MachineProvider;
use kamaji::Kamaji as ContainerRuntime;
use yubaba_test_harness::{test_cluster, wait_for_state, WorkloadStatus};
use yubaba_test_macros::test_with_provider;
use workload_spec::{
    ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits, RestartPolicy,
    SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
};

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
            cpu_shares: 128,
            ephemeral_storage_mb: 128,
        },
        depends_on: vec![],
        healthcheck: None,
        restart_policy: RestartPolicy::Never,
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(5),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent(name.to_string()),
                ports: vec![],
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
    let write_spec = serde_json::to_value(test_workload_spec("quorum-rejected"))
        .expect("serialize spec");
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
