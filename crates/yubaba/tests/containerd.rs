//! R743-T1: group root for integration tests requiring
//! `containerd-integration` (real `ContainerdRuntime`). Both modules skip
//! gracefully when containerd / Colima is unavailable. See `tests/main.rs` for
//! the rationale and for the rule on registering a new test file.
//!
//! `integration_smoke_filter` is deliberately NOT here: it needs
//! `containerd-integration` *and* `testing`, so it stays a standalone target
//! rather than forcing `testing` onto these two.

mod integration_mesh;
mod integration_single_node;
