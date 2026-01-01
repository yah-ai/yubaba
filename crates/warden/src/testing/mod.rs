//! In-process test helpers for warden integration tests.
//!
//! Gated behind the `testing` cargo feature so these modules are excluded from
//! release builds.

pub mod cloudflared_mock;
pub mod headscale_mock;
