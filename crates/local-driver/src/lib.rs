//! Local-tier infrastructure primitives shared by `cloud` (sim/pond reconciler)
//! and `yubaba` (pond MinIO slot lifecycle).
//!
//! Two concerns live here:
//!
//! 1. **`local_runtime`** — detect an orbstack/docker-desktop/colima/podman/
//!    docker socket and drive appliance containers via the docker CLI. The
//!    docker-CLI driver was previously `cloud::local_runtime`; yubaba grew a
//!    dep on it in R374-F3 when MinIO lifecycle moved into the pond
//!    workload-status surface.
//!
//! 2. **`s3_sign`** — AWS Signature Version 4 helpers for S3-compatible object
//!    storage. Used by cloud's Hetzner driver, the R2 publisher, and yubaba's
//!    MinIO bucket-public bring-up.
//!
//! The crate is intentionally backend-agnostic: no cloud-config types, no
//! yubaba-config types. Callers wire it in via small adapters in their own
//! crates (see `cloud::local_container_spec_from_provider`).
//!
//! @yah:ticket(R374-F3, "Extracted from cloud crate so yubaba owns MinIO lifecycle without a yubaba→cloud dep")
//! @yah:status(in-progress)
//! @yah:parent(R374)
//! @arch:see(.yah/docs/working/W142-pond.md)

pub mod cloud_mesofact_runner;
pub mod local_runtime;
pub mod pond_mesofact_dev;
pub mod pond_miniflare;
pub mod pond_minio;
pub mod pond_ssr_runtime;
pub mod pond_warden;
pub mod s3_sign;

pub use local_runtime::{
    canonical_label, canonical_name, pond_network_name, ContainerRunSpec, ContainerState,
    CustomDockerHostProvider, DetectedRuntime, LocalContainerSpec, LocalDockerRuntime,
    LocalRuntime, OwnedContainer, RuntimePref, RuntimeProvider, SocketRuntimeProvider, LABEL_KEY,
    NAME_PREFIX,
};
