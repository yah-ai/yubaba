//! Cluster-internal mesh types.
//!
//! `MeshAssignment` is the output of yubaba's raft consensus layer: a
//! concrete WireGuard interface config + mesh IP assigned for one workload.
//! The `Kamaji` (formerly `ContainerRuntime`) trait takes it as a
//! parameter so the runtime can wire the container's network namespace to
//! the mesh at deploy time.
//!
//! Per R484-T2 (W199 Kamaji carve-out), the type itself now lives in
//! `kamaji-core` so both yubaba (the producer / mesh assigner) and the
//! kamaji library (the consumer / runtime backend) share one definition.
//! This module remains as the yubaba-facing import path so existing call
//! sites compile without churn; T5 will collapse remaining yubaba callers
//! onto the kamaji-core path directly.

pub use kamaji::{MeshAssignment, WireguardPeer};
