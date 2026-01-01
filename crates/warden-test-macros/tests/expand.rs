//! Golden-file macro expansion tests.
//!
//! Each `.rs` file in `tests/fixtures/` is expanded via `cargo expand` and
//! compared against the corresponding `.expanded.rs` golden file.
//!
//! ## Regenerating golden files
//!
//! When the macro output changes (intentionally), regenerate all golden files:
//!
//! ```bash
//! MACROTEST=overwrite cargo test -p warden-test-macros expand_tests
//! ```
//!
//! Commit both the `.rs` fixture and the updated `.expanded.rs` file.
//!
//! ## Prerequisites
//!
//! `cargo-expand` must be installed (`cargo install cargo-expand`) and
//! `rustfmt` must be available. Both are present in the standard dev setup.

#[test]
fn expand_tests() {
    macrotest::expand("tests/fixtures/*.rs");
}
