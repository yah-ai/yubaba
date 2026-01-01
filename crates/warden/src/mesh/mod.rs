//! Cluster-internal mesh types.
//!
//! `MeshAssignment` is the output of warden's raft consensus layer: a
//! concrete WireGuard interface config + mesh IP assigned for one workload.
//! The `Constable` (formerly `ContainerRuntime`) trait takes it as a
//! parameter so the runtime can wire the container's network namespace to
//! the mesh at deploy time.
//!
//! Per R484-T2 (W199 Constable carve-out), the type itself now lives in
//! `constable-core` so both warden (the producer / mesh assigner) and the
//! constable library (the consumer / runtime backend) share one definition.
//! This module remains as the warden-facing import path so existing call
//! sites compile without churn; T5 will collapse remaining warden callers
//! onto the constable-core path directly.

pub use constable_core::{MeshAssignment, WireguardPeer};
