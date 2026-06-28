use postcard::Error as PostcardError;
use serde::{de::DeserializeOwned, Serialize};

/// Maximum frame payload size the codec accepts.
///
/// UDS control messages are tiny — workload specs are the largest realistic
/// payload and they cap at the low-kB range. 1 MiB is a generous ceiling that
/// still rejects framing bugs and hostile peers cheaply.
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// Codec error surface.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Postcard refused to encode or decode the payload.
    #[error("postcard error: {0}")]
    Postcard(#[from] PostcardError),
    /// Payload exceeded [`MAX_FRAME_BYTES`].
    #[error("frame too large: {size} > {max}", max = MAX_FRAME_BYTES)]
    FrameTooLarge { size: usize },
    /// Buffer did not contain a complete frame — caller should read more
    /// bytes and retry.
    #[error("frame truncated: need {needed} bytes, have {have}")]
    Truncated { needed: usize, have: usize },
}

/// Encode a message as a length-prefix-framed postcard payload.
///
/// Wire shape: `[u32 LE length][postcard bytes]`. The returned `Vec<u8>` can
/// be handed directly to `tokio::io::AsyncWriteExt::write_all`.
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, Error> {
    let payload = postcard::to_stdvec(msg)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge {
            size: payload.len(),
        });
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Try to decode one frame from the start of `buf`.
///
/// On success returns `(parsed_msg, bytes_consumed)`; the caller should advance
/// its read buffer by `bytes_consumed` and call again to drain additional
/// frames. On [`Error::Truncated`] the caller should read more bytes from the
/// socket and retry — the buffer is otherwise untouched.
pub fn decode_frame<T: DeserializeOwned>(buf: &[u8]) -> Result<(T, usize), Error> {
    if buf.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            have: buf.len(),
        });
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[..4]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge { size: len });
    }
    let need = 4 + len;
    if buf.len() < need {
        return Err(Error::Truncated {
            needed: need,
            have: buf.len(),
        });
    }
    let msg = postcard::from_bytes::<T>(&buf[4..need])?;
    Ok((msg, need))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::*;
    use crate::version::ProtocolVersion;

    #[test]
    fn hello_round_trip() {
        let msg = WardenToConstable::Hello {
            version: ProtocolVersion::V1,
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame::<WardenToConstable>(&bytes).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn welcome_round_trip() {
        let msg = ConstableToWarden::Welcome {
            version: ProtocolVersion::V1,
            constable_version: "0.0.1".into(),
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<ConstableToWarden>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn drain_request_round_trip() {
        let msg = WardenToConstable::Drain {
            request_id: RequestId(42),
            id: WorkloadId::new("yubaba-1"),
            budget: DrainBudget {
                flush_ms: 5_000,
                checkpoint_ms: 1_000,
            },
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<WardenToConstable>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn workload_list_round_trip() {
        let msg = ConstableToWarden::WorkloadList {
            request_id: RequestId(1),
            entries: vec![
                WorkloadEntry {
                    id: WorkloadId::new("a"),
                    state: WorkloadState::Running,
                    pid: Some(1234),
                },
                WorkloadEntry {
                    id: WorkloadId::new("b"),
                    state: WorkloadState::Draining,
                    pid: Some(1235),
                },
                WorkloadEntry {
                    id: WorkloadId::new("c"),
                    state: WorkloadState::Pending,
                    pid: None,
                },
            ],
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<ConstableToWarden>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn error_round_trip_with_no_request_id() {
        let msg = ConstableToWarden::Error {
            request_id: None,
            code: ErrorCode::InvalidSpec,
            message: "missing resources block".into(),
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<ConstableToWarden>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn exit_status_variants_round_trip() {
        for exit in [
            ExitStatus::Exited(0),
            ExitStatus::Exited(137),
            ExitStatus::Signaled(15),
            ExitStatus::DrainTimeout,
        ] {
            let msg = ConstableToWarden::WorkloadExited {
                id: WorkloadId::new("w"),
                exit,
            };
            let bytes = encode_frame(&msg).unwrap();
            let (decoded, _) = decode_frame::<ConstableToWarden>(&bytes).unwrap();
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn probe_unhealthy_round_trip() {
        let msg = ConstableToWarden::ProbeResult {
            request_id: RequestId(9),
            id: WorkloadId::new("w"),
            status: ProbeStatus::Unhealthy {
                reason: "db connection lost".into(),
            },
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<ConstableToWarden>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn truncated_at_length_prefix_reports_need_4() {
        let err = decode_frame::<WardenToConstable>(&[0, 0]).unwrap_err();
        match err {
            Error::Truncated { needed, have } => {
                assert_eq!(needed, 4);
                assert_eq!(have, 2);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn truncated_inside_payload_reports_full_need() {
        let msg = WardenToConstable::Stop {
            request_id: RequestId(1),
            id: WorkloadId::new("yubaba-1"),
        };
        let bytes = encode_frame(&msg).unwrap();
        let partial = &bytes[..bytes.len() - 1];
        let err = decode_frame::<WardenToConstable>(partial).unwrap_err();
        match err {
            Error::Truncated { needed, have } => {
                assert_eq!(needed, bytes.len());
                assert_eq!(have, partial.len());
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn multiple_frames_in_one_buffer_decode_independently() {
        let m1 = WardenToConstable::Hello {
            version: ProtocolVersion::V1,
        };
        let m2 = WardenToConstable::Stop {
            request_id: RequestId(7),
            id: WorkloadId::new("w-7"),
        };
        let mut buf = Vec::new();
        buf.extend(encode_frame(&m1).unwrap());
        buf.extend(encode_frame(&m2).unwrap());

        let (d1, consumed) = decode_frame::<WardenToConstable>(&buf).unwrap();
        assert_eq!(d1, m1);
        let (d2, _) = decode_frame::<WardenToConstable>(&buf[consumed..]).unwrap();
        assert_eq!(d2, m2);
    }

    #[test]
    fn oversized_length_prefix_is_rejected_before_allocation() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_le_bytes());
        let err = decode_frame::<WardenToConstable>(&buf).unwrap_err();
        assert!(matches!(err, Error::FrameTooLarge { .. }));
    }

    // ── R406-T7: structured drain protocol round-trips ──────────────────────

    #[test]
    fn drain_budget_total_ms_saturates() {
        let budget = DrainBudget {
            flush_ms: u32::MAX,
            checkpoint_ms: 100,
        };
        assert_eq!(budget.total_ms(), u32::MAX);

        let budget = DrainBudget {
            flush_ms: 5_000,
            checkpoint_ms: 1_000,
        };
        assert_eq!(budget.total_ms(), 6_000);
    }

    #[test]
    fn drain_outcome_flushed_round_trips() {
        let outcome = DrainOutcome::Flushed {
            exit: ExitStatus::Exited(0),
            elapsed_ms: 250,
        };
        let bytes = postcard::to_stdvec(&outcome).unwrap();
        let decoded: DrainOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn drain_outcome_checkpointed_round_trips() {
        let outcome = DrainOutcome::Checkpointed {
            exit: ExitStatus::Signaled(15),
            elapsed_ms: 5_800,
        };
        let bytes = postcard::to_stdvec(&outcome).unwrap();
        let decoded: DrainOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn drain_outcome_force_killed_round_trips() {
        let outcome = DrainOutcome::ForceKilled { elapsed_ms: 6_100 };
        let bytes = postcard::to_stdvec(&outcome).unwrap();
        let decoded: DrainOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn drain_outcome_unit_variants_round_trip() {
        for outcome in [DrainOutcome::UnknownWorkload, DrainOutcome::Unsupported] {
            let bytes = postcard::to_stdvec(&outcome).unwrap();
            let decoded: DrainOutcome = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(decoded, outcome);
        }
    }

    #[test]
    fn drain_completed_message_round_trips() {
        let msg = ConstableToWarden::DrainCompleted {
            request_id: RequestId(99),
            id: WorkloadId::new("svc-1"),
            outcome: DrainOutcome::Flushed {
                exit: ExitStatus::Exited(0),
                elapsed_ms: 1_234,
            },
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<ConstableToWarden>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn drain_phase_round_trips() {
        for phase in [DrainPhase::Flush, DrainPhase::Checkpoint] {
            let bytes = postcard::to_stdvec(&phase).unwrap();
            let decoded: DrainPhase = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(decoded, phase);
        }
    }

    #[test]
    fn protocol_version_serializes_compactly() {
        // Sanity: the version envelope is a single byte in postcard (single
        // variant unit enum encodes as a varint discriminant).
        let bytes = postcard::to_stdvec(&ProtocolVersion::V1).unwrap();
        assert_eq!(bytes.len(), 1);
    }
}
