//! Smoke-filter sanity test for `#[test_with_provider]`.
//!
//! Verifies two things about the macro's tier gating:
//!
//! 1. `__local` variants are included in the default test run.
//! 2. `__smoke` variants carry `#[ignore]` and are excluded without
//!    `YAH_SMOKE=1`.
//!
//! ## Running
//!
//! ```bash
//! # Local variants only (default) — no YAH_SMOKE needed:
//! cargo test -p warden --features containerd-integration,testing \
//!     --test integration_smoke_filter
//!
//! # Smoke variants (skips without real creds even when running ignored):
//! cargo test -p warden --features containerd-integration,testing \
//!     --test integration_smoke_filter -- --ignored
//! ```
//!
//! The `__local` variants skip gracefully (print + early return) when
//! containerd / Colima is unavailable, so this test is safe to run in CI
//! without a running container runtime.
//!
//! @arch:see(.yah/docs/architecture/A053-yah-warden-integration-testing.md)
//!
//! @arch:see(.github/workflows/smoke.yml)
//! @arch:see(crates/yah/warden/src/lib.rs)

use cloud::provider::MachineProvider;
use constable_core::Constable as ContainerRuntime;
use warden_test_macros::test_with_provider;

/// Local-only annotation — `filter_local__local` runs by default;
/// no `__smoke` variant is emitted.
#[test_with_provider(local)]
async fn filter_local<P, R>(_p: P, _rt: R)
where
    P: MachineProvider,
    R: ContainerRuntime,
{
    // Body intentionally empty — verifies the variant is reachable.
}

/// Both-tier annotation — `filter_both__local` runs by default;
/// `filter_both__smoke` carries `#[ignore]` and is skipped without YAH_SMOKE=1.
#[test_with_provider(local, smoke)]
async fn filter_both<P, R>(_p: P, _rt: R)
where
    P: MachineProvider,
    R: ContainerRuntime,
{
    // Body intentionally empty — the __smoke variant's YAH_SMOKE guard exits
    // before reaching here when YAH_SMOKE!=1.
}