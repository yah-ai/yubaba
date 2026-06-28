use std::time::Duration;

use kamaji_proto::{
    decode_frame, encode_frame, AckKind, ConstableToWarden, DrainBudget, ProtocolVersion,
    RequestId, WardenToConstable, WorkloadId,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

async fn read_one_reply(stream: &mut UnixStream) -> ConstableToWarden {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        match decode_frame::<ConstableToWarden>(&buf) {
            Ok((msg, _)) => return msg,
            Err(kamaji_proto::Error::Truncated { .. }) => {
                let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut tmp))
                    .await
                    .expect("client read timed out")
                    .expect("client read failed");
                assert!(n > 0, "server closed before sending a full frame");
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => panic!("client decode failed: {e}"),
        }
    }
}

#[tokio::test]
async fn end_to_end_hello_list_and_stop_skeleton() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("kamaji.sock");

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server_path = socket.clone();
    let server = tokio::spawn(async move {
        kamaji_bin::serve_with_shutdown(&server_path, async move {
            let _ = stop_rx.await;
        })
        .await
    });

    // Wait for the listener to bind. The skeleton is fast but we still need a
    // retry loop because UnixListener::bind happens inside the spawned task.
    let mut client = None;
    for _ in 0..50 {
        match UnixStream::connect(&socket).await {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let mut client = client.expect("server never bound the UDS");

    // Hello → Welcome.
    let frame = encode_frame(&WardenToConstable::Hello {
        version: ProtocolVersion::CURRENT,
    })
    .unwrap();
    client.write_all(&frame).await.unwrap();
    match read_one_reply(&mut client).await {
        ConstableToWarden::Welcome { version, .. } => {
            assert_eq!(version, ProtocolVersion::CURRENT)
        }
        other => panic!("expected Welcome, got {other:?}"),
    }

    // List → empty WorkloadList (no backend yet).
    let frame = encode_frame(&WardenToConstable::List {
        request_id: RequestId(1),
    })
    .unwrap();
    client.write_all(&frame).await.unwrap();
    match read_one_reply(&mut client).await {
        ConstableToWarden::WorkloadList {
            request_id,
            entries,
        } => {
            assert_eq!(request_id, RequestId(1));
            assert!(entries.is_empty());
        }
        other => panic!("expected WorkloadList, got {other:?}"),
    }

    // Stop without a backend attached → Ack (R406-T9: stop is idempotent;
    // the absence of the workload satisfies the end-state). Backend-attached
    // teardown is exercised in the yubaba↔kamaji integration test once
    // R406-T9 lands the containerd backend.
    let frame = encode_frame(&WardenToConstable::Stop {
        request_id: RequestId(2),
        id: WorkloadId::new("does-not-exist"),
    })
    .unwrap();
    client.write_all(&frame).await.unwrap();
    match read_one_reply(&mut client).await {
        ConstableToWarden::Ack { request_id, kind } => {
            assert_eq!(request_id, RequestId(2));
            assert_eq!(kind, AckKind::Stop);
        }
        other => panic!("expected Ack, got {other:?}"),
    }

    // Drain { id="does-not-exist" } → DrainAck { accepted: false }.
    // The Drain dispatch is wired through enforce_drain (R406-T7); for a
    // workload not in the registry it short-circuits without touching pidfd.
    let frame = encode_frame(&WardenToConstable::Drain {
        request_id: RequestId(3),
        id: WorkloadId::new("does-not-exist"),
        budget: DrainBudget {
            flush_ms: 50,
            checkpoint_ms: 50,
        },
    })
    .unwrap();
    client.write_all(&frame).await.unwrap();
    match read_one_reply(&mut client).await {
        ConstableToWarden::DrainAck {
            request_id,
            id,
            accepted,
            reason,
        } => {
            assert_eq!(request_id, RequestId(3));
            assert_eq!(id, WorkloadId::new("does-not-exist"));
            assert!(!accepted, "unknown workload must surface as not-accepted");
            let r = reason.expect("reason populated");
            assert!(r.contains("unknown"), "reason should mention 'unknown', got: {r}");
        }
        other => panic!("expected DrainAck, got {other:?}"),
    }

    drop(client);
    let _ = stop_tx.send(());
    server.await.unwrap().unwrap();
}
