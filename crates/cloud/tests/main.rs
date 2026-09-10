//! Single integration-test binary for `yah-cloud` (R743-T7).
//!
//! `autotests = false` in `Cargo.toml` turns off cargo's per-file test-target
//! autodiscovery; this file is the `main` target and `mod`s in the siblings, so
//! four former binaries link once instead of four times. Each module keeps its
//! own file — the live `@yah:` annotation blocks in `mesofact_static_e2e.rs`
//! stay where the harvester expects them, and `CARGO_MANIFEST_DIR` (which three
//! of the four walk up from) is unchanged.
//!
//! Test *names* gain a module prefix (`whisper_derive_e2e::derive_pipeline_…`),
//! so filters written against the old flat names still match — `cargo test -p
//! yah-cloud --test main -- derive_pipeline` is unaffected. What does change is
//! `--test <file-stem>`: use `--test main -- <module>::` instead.
//!
//! # `pond_smoke` is deliberately NOT in here
//!
//! It stays its own `[[test]]` target. Three reasons, strongest first:
//!
//! 1. **A committed pipeline addresses it by target name.**
//!    `.yah/qed/pond-smoke.toml`'s `pond-spinup-budget` step shells out to
//!    `cargo test --release --locked -p cloud --test pond_smoke -- --nocapture`.
//!    Folding it into `main` turns that step into a hard cargo error, and the
//!    pipeline file is outside this crate.
//!
//! 2. **It is the only test in the crate that reaches for a fixed external
//!    address.** MinIO at `http://127.0.0.1:9000` (`pond_smoke.rs`'s
//!    `minio_endpoint`) plus named docker containers it `docker rm -f`s in a
//!    `Drop` guard. Its blast radius on failure is outside the process, so a
//!    standalone runnable handle is worth keeping. (xtask's census —
//!    `xtask/src/lib.rs`, `@yah:assumes` — independently found this to be the
//!    only real port bind across all ten in-scope crates; nothing else here has
//!    global state to collide over.)
//!
//! 3. **It is benchmark-shaped, and libtest parallelises within a binary.**
//!    Both its tests assert wall-clock budgets (`WARM_RESTART_BUDGET` = 3 s,
//!    `WARDEN_COLD_BUDGET` = 5 s). Merging would drop `whisper_derive_e2e`
//!    (two in-process axum servers + BLAKE3 + tempdir IO, ungated) and
//!    `live_workspace_smoke` (a full `CloudConfig::load` walk of the real
//!    workspace, ungated) into the measurement window on sibling threads. The
//!    pipeline also runs it `--nocapture` for the timing report, which merging
//!    would interleave with every other test's output.
//!
//! The five modules below have no such conflict: `live_workspace_smoke` is
//! read-only filesystem, `mesofact_static_e2e` binds `127.0.0.1:0` and is gated
//! on `YAH_RECONCILER_E2E_BIN`, `pg_driver_live` is `#[ignore]`d and tempdir
//! -scoped, `passway_apex_live` is `#[ignore]`d and reaches the network
//! read-only (R859-F1), and `whisper_derive_e2e` is entirely in-process on
//! ephemeral ports inside a tempdir. No shared ports, no shared paths, no
//! process-global state.

mod live_workspace_smoke;
mod mesofact_static_e2e;
mod passway_apex_live;
mod pg_driver_live;
mod whisper_derive_e2e;
