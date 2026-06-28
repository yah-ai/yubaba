//! `kamaji-proto` — Yubaba ↔ Kamaji wire protocol.
//!
//! Wire shape:
//!
//! ```text
//! [u32 LE length][postcard-encoded payload]
//! ```
//!
//! The crate has no I/O. Callers (yubaba, kamaji) own the
//! [`tokio::net::UnixStream`](https://docs.rs/tokio/latest/tokio/net/struct.UnixStream.html)
//! and push/pull framed bytes through [`encode_frame`] / [`decode_frame`].
//!
//! Both directions are versioned via [`ProtocolVersion`]; peers exchange
//! [`WardenToConstable::Hello`] / [`ConstableToWarden::Welcome`] at connection
//! start so a rolling cluster can decode multiple versions during upgrades.
//!
//! @arch:see(.yah/docs/working/W154-yubaba-dual-runtime.md)

pub mod codec;
pub mod messages;
pub mod version;

pub use codec::{decode_frame, encode_frame, Error, MAX_FRAME_BYTES};
pub use messages::{
    AckKind, ConstableToWarden, DrainBudget, DrainOutcome, DrainPhase, ErrorCode, ExitStatus,
    ProbeStatus, RequestId, WardenToConstable, WorkloadEntry, WorkloadId, WorkloadState,
};
pub use version::ProtocolVersion;
