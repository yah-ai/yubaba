//! R743-T1: group root for integration tests requiring the `testing` feature
//! (in-memory `FakeRuntime` / fake provider). See `tests/main.rs` for the
//! rationale and for the rule on registering a new test file.

mod integration_operator_bridge;
mod integration_ownership_smoke;
mod integration_service_records;
