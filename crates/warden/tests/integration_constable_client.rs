//! Warden ↔ Constable end-to-end UDS smoke test (R406-T8).
//!
//! Spawns `constable::serve_with_shutdown` against a tempdir socket, opens
//! a `warden::constable_client::ConstableClient`, and exercises the handshake
//! + `list` + `drain(unknown)` round-trip. This is the smallest test that
//! proves the warden side and constable side encode/decode the same frames
//! over a real UDS — pure unit tests in either crate use stubs on the other
//! end, so a wire-shape regression would slip through them.
//!
//! When `R406-T9` ships Constable's containerd backend, this test gains a
//! `deploy` round-trip (currently the Constable handler short-circuits to
//! `Error { Internal, "backend driver not implemented" }`).
//!
//! @yah:ticket(R427-T2, "E2E smoke: agent → constable → warden → cheers ownership write → camp refresh → 2nd deploy")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T22:46:04Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R427)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R427-F1)
//! @yah:depends_on(R426-F3)
//! @yah:handoff("E2E ownership-write smoke landed at crates/yah/warden/tests/integration_ownership_smoke.rs. Spawns an in-process axum cheers mock (POST /ownership returning 201 + monotonic 01HROW#### ids; DELETE /ownership/{id} returning 204; failure injection toggle for the 5xx-during-register case) and a real warden ServerState wired with FakeRuntime + a real CheersClient pointed at the mock. Each test verifies the Bearer token cheers received by re-running PASETO v4.public verification against the same Ed25519 keypair warden minted with — same JWKS-shape path cheers's actual ownership router uses, just shrunk to a single test.")
//! @yah:handoff("FOUR CASES COVERED. (1) deploy_registers_then_destroy_revokes: full happy path — POST body matches the canonical CreateOwnershipBody shape (principal_id/resource_kind/resource_id/relationship/on_behalf_of), Bearer token sub=svc:warden-smoke + scope=[ownership:write] + iss==aud==issuer_url + TTL inside the W159 5–15 min band, returned row_id round-trips into warden's ownership_rows map, destroy DELETE hits the same id with a freshly-minted token, map entry consumed. (2) second_deploy_writes_a_distinct_row: two sequential deploys against the same camp — distinct PASETO jti's (warden's monotonic counter is the same-second replay backstop), distinct resource_ids on the wire, distinct row_ids in the map. This is the 'camp refresh → 2nd deploy' half of the T2 narrative reduced to what's testable today. (3) deploy_without_camp_id_skips_register: no requesting_camp_id ⇒ no cheers call at all (dev-tier shape). (4) register_failure_does_not_tear_down_workload: cheers returns 500 on POST — deploy still returns 200 deployed, no row stored on warden's side, workload stays up (W159 'auth-table blip is worse than audit gap' invariant).")
//! @yah:handoff("DEFERRED FROM THE FULL T2 NARRATIVE (documented in the test file header). Two pieces of 'agent → constable → warden → cheers → camp refresh → 2nd deploy' need design work outside this relay: (a) the authed transport in front of warden (R426-F2 hub-cheers-rpc adapter) for the agent→constable hop — today this test POSTs straight to warden's HTTP surface, which is exactly what the adapter will do once it lands; (b) cheers's token-mint endpoint + camp refresh path — today the tests stub camp:/user: ids on the deploy body; R428 replaces them with derivation from verified MCP claims. Neither gap is a behavioral hole in R427-F1 — they're upstream wiring that mints the inputs to what this relay landed.")
//! @yah:verify("cargo test -p warden --features testing --test integration_ownership_smoke  # 4 passed")
//! @yah:verify("cargo test -p warden --features testing  # 121 lib + 4 ownership_smoke + integration suites green")

use std::path::PathBuf;
use std::time::Duration;

use constable_proto::{DrainBudget, WorkloadId};
use tempfile::TempDir;
use tokio::sync::oneshot;
use constable_core::sibling::{ClientError, ConstableClient};

/// Spawn a Constable on `socket`, then poll the path until the listener is
/// bound. Returns the join handle + a shutdown sender; callers fire the
/// sender after asserts and `.await` the handle.
async fn spawn_constable(socket: PathBuf) -> (tokio::task::JoinHandle<()>, oneshot::Sender<()>) {
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server_path = socket.clone();
    let handle = tokio::spawn(async move {
        let _ = constable::serve_with_shutdown(&server_path, async move {
            let _ = stop_rx.await;
        })
        .await;
    });

    // Wait up to ~1s for the listener to bind. The skeleton binds quickly
    // but the spawn-then-bind ordering means a connect right after spawn
    // races with the bind syscall.
    for _ in 0..50 {
        if tokio::net::UnixStream::connect(&socket).await.is_ok() {
            return (handle, stop_tx);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("constable never bound the UDS at {}", socket.display());
}

#[tokio::test]
async fn handshake_and_list_round_trip_against_real_constable() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("constable.sock");
    let (server, stop) = spawn_constable(sock.clone()).await;

    let client = ConstableClient::connect(sock)
        .await
        .expect("constable handshake");
    let info = client.info();
    assert_eq!(info.constable_version, env!("CARGO_PKG_VERSION").to_string());

    let entries = client.list().await.expect("list");
    assert!(entries.is_empty(), "fresh constable has no workloads");

    let _ = stop.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn drain_unknown_workload_surfaces_constable_reason() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("constable.sock");
    let (server, stop) = spawn_constable(sock.clone()).await;

    let client = ConstableClient::connect(sock).await.unwrap();
    let (accepted, reason) = client
        .drain(
            &WorkloadId::new("never-registered"),
            DrainBudget {
                flush_ms: 50,
                checkpoint_ms: 50,
            },
        )
        .await
        .expect("drain RPC");
    assert!(!accepted);
    let reason = reason.expect("constable populates a reason");
    assert!(
        reason.contains("unknown"),
        "expected 'unknown' in {reason}"
    );

    let _ = stop.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn stop_unknown_workload_returns_ack_for_idempotency() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("constable.sock");
    let (server, stop) = spawn_constable(sock.clone()).await;

    let client = ConstableClient::connect(sock).await.unwrap();
    // R406-T9: Stop is idempotent — without a containerd backend attached,
    // Constable acks because the absence of the workload already satisfies
    // the requested end-state. (The ClientError import below is kept for
    // future tests that exercise actual remote-error paths.)
    let _ = std::mem::size_of::<ClientError>();
    client
        .stop(&WorkloadId::new("nope"))
        .await
        .expect("stop without backend should ack");

    let _ = stop.send(());
    server.await.unwrap();
}
