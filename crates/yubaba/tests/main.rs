//! R743-T1: ungated integration-test group root.
//!
//! Every module below was its own `[[test]]` target until this consolidation.
//! Each one linked a full ~730 MB debug binary containing the whole yubaba
//! dependency closure; 22 such targets cost ~16 GB of `target/debug/deps` and
//! 22 separate link steps. Folding them into a handful of group binaries keeps
//! the same tests (same names, since the module path reproduces the old target
//! name) at a fraction of the link and disk cost.
//!
//! Grouping rule: a test file belongs here when it needs no cargo features.
//! Feature-gated files live in the sibling group roots — `testing.rs`
//! (`testing`), `containerd.rs` (`containerd-integration`) — and
//! `integration_smoke_filter.rs` stays a standalone target because it is the
//! only file requiring `containerd-integration` *and* `testing`.
//!
//! Adding a test file: drop it in `tests/` and add a `mod` line to the group
//! root whose feature set it needs. `autotests = false` in Cargo.toml means a
//! new file is NOT picked up automatically — an unreferenced file silently
//! never runs, so the `mod` line is the registration step.
//!
//! Note on concurrency: cargo runs test *binaries* sequentially but the tests
//! inside one binary in parallel, so these modules' tests now run concurrently
//! with each other. That is safe here — every test allocates its own
//! `tempfile::TempDir` for state and binds `127.0.0.1:0` for listeners; there
//! is no shared fixed port, fixed path, or process-global initialization.

mod bootstrap_single_node;
mod integration_constable_client;
mod integration_deploy_through_kamaji;
mod pond_kamaji_supervision;
mod pond_reconciler_smoke;
mod raft_add_learner;
mod raft_cell_tagging;
mod raft_leader_pin;
mod raft_member_registration;
mod raft_membership_loop;
mod raft_pre_vote;
mod raft_promote_voter;
mod raft_quorum_geography;
mod raft_sovereign_group;
mod raft_tenant_placement;
mod raft_transfer_leader;
mod rig_singleton_ownership;
