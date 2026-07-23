//! Reconciler for `kind = "static-asset"` components (R429-F2).
//!
//! Syncs a content-addressed file catalog declared in `workload.toml` to the
//! mirror's `providers.object_store` slot (Cloudflare R2 or pond MinIO).
//!
//! ## Per-asset pipeline
//!
//! For each `[[asset]]` row:
//! 1. Read the source file from disk.
//! 2. Compute its BLAKE3 hash; compare to `entry.blake3`. Mismatch → surface
//!    as a hard error and skip upload (don't push bad data).
//! 3. HEAD the object key in the bucket — if already present, skip PUT.
//! 4. PUT the file (single-part; R2 accepts up to 5 GB per PUT).
//!
//! ## Drift detection (v1)
//!
//! A `_yah-asset-catalog.json` sidecar stored in the bucket records what was
//! uploaded. On the next run, the manifest∖current-catalog delta surfaces as
//! prune candidates (logged as warnings; nothing is deleted). Exhaustive bucket
//! listing via S3 ListObjects (which would find bucket∖catalog stragglers added
//! outside of yah) is deferred to v2 when an XML list response parser exists.
//!
//! ## Auto-delete is OFF
//!
//! The reconciler NEVER deletes from the bucket. Prune candidates are reported
//! for operator review; deletion requires `yah service prune`.
//!
//! @arch:see(.yah/docs/working/W164-derived-static-assets.md)
//!
//! @yah:ticket(R438-T8, "Worked examples: whisper-derive e2e + mesofact in-container build")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T21:07:41Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R438)
//! @yah:next("Whisper-derive e2e against fake R2: cargo run --example whisper_derive_e2e — two consecutive runs upload-then-skip")
//! @yah:next("Post-prune --derive run re-materializes from scratch and produces bit-identical bytes (reproducibility check)")
//! @yah:next("In-tree mesofact-static workload with build_mode=in_container builds green in CI")
//! @yah:verify("Examples run green in CI matrix")
//! @yah:verify("Reproducibility: independent operator/machine yields identical output blake3 (pinned container guarantees this)")
//! @arch:see(.yah/docs/working/W164-derived-static-assets.md)
//! @arch:see(.yah/docs/working/W165-mesofact-build-mode-lowering.md)
//! @yah:depends_on(R438-T7)
//! @yah:handoff("T8 landed. Three artifacts: (1) crates/yah/cloud/testdata/mesofact-in-container/workload.toml — in-tree fixture with build_mode = { mode = \"in_container\", image = \"oven/bun:1.2.13@sha256:aaa...\" }; (2) new test in_container_fixture_roundtrips_as_container_build_mode in mesofact_static.rs tests: loads fixture via read_mesofact_build, asserts BuildMode::InContainer returned, runs in CI without docker — passes; (3) crates/yah/cloud/tests/whisper_derive_e2e.rs — integration test derive_pipeline_upload_skip_prune_reproducibility. Uses in-process axum fake-S3 (HEAD/GET/PUT, state map) + fake upstream HTTP server + MockCopyExecutor (copies argv[1]→argv[2], counts invocations). Three-run scenario: run1=cold→executor invoked 1x, model.bin PUT; run2=warm→executor NOT invoked again, HEAD 200 skip; run3=prune cache+evict S3 object→executor invoked again, re-uploaded bytes have identical BLAKE3. cargo test -p cloud --lib: 304 pass, 5 pre-existing failures (port collision + cloud_init drift, same as T6 gotcha). cargo test -p cloud --test whisper_derive_e2e: 1 pass. cargo check --workspace --locked: clean.")
//! @yah:verify("cargo test -p cloud --lib reconciler::mesofact_static::tests::in_container_fixture_roundtrips_as_container_build_mode  # 1 pass")
//! @yah:verify("cargo test -p cloud --test whisper_derive_e2e  # 1 pass")
//! @yah:verify("cargo check --workspace --locked  # clean")
//!
//! @yah:ticket(R438-F11, "HTTP fetch retry/resume policy for materialize step (W164 OQ#4)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T21:08:05Z)
//! @yah:status(review)
//! @yah:parent(R438)
//! @yah:next("Exponential backoff with bounded attempts on transient network failures")
//! @yah:next("Range: header for resumable downloads on multi-GB blobs (whisper-large is 1.5GB)")
//! @yah:next("Surface progress to yah QED/task-pane per long-running→yah-surface rule (not Bash bg)")
//! @yah:verify("Simulated 50%-mid-download disconnect resumes via Range and completes")
//! @arch:see(.yah/docs/working/W164-derived-static-assets.md)
//! @yah:depends_on(R438-T5)
//! @yah:handoff("F11 landed. HTTP fetch retry + Range resume for materialize_fetch (W164 OQ#4). Changes: (1) Added stream feature to reqwest in cloud/Cargo.toml. (2) Replaced the single-shot reqwest::get+bytes() call in materialize_fetch with: FETCH_MAX_ATTEMPTS=5 (1 in test) retry loop with exponential backoff (FETCH_BASE_DELAY_MS=1000ms, capped at 30s; 1ms/5ms in tests so suite stays fast); fetch_once helper streams via resp.chunk() to a <hash>.partial file; Range: bytes=<offset>- header sent on retry when partial file exists; 206 response appended, 200 response truncates-and-restarts, 416 clears partial and retries fresh, 4xx is fatal (no retry), 5xx/429 is transient (retry). (3) Progress logged via info!() every 100MiB (FETCH_LOG_INTERVAL_BYTES) to surface through task-pane. (4) FetchOnceFail enum (Fatal/Transient) separates non-retriable from transient outcomes. After successful fetch_once, blake3 is verified on the partial file then atomic renamed to <hash>.bin. (5) Two new tests: materialize_fetch_retries_on_server_error (500 first, 200 second, asserts 2 requests made) and materialize_fetch_resumes_via_range_header (pre-writes half to .partial, server verifies Range header and returns 206+second-half, asserts full body in cache). cargo test -p cloud --lib reconciler::static_asset: 34 pass. cargo check -p cloud: clean.")
//! @yah:verify("cargo test -p cloud --lib reconciler::static_asset::tests::materialize_fetch_retries_on_server_error  # passes")
//! @yah:verify("cargo test -p cloud --lib reconciler::static_asset::tests::materialize_fetch_resumes_via_range_header  # passes, Range header asserted")
//! @yah:verify("cargo check -p cloud  # clean")
//!
//! @yah:ticket(R438-T15, "cloud reconciler materialize step: HTTP fetch + recipe lowering + content-addressed cache")
//! @yah:at(2026-06-05T00:03:49Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R438)
//! @yah:next("Inject executor: Arc<dyn ForgeExecutor> via StaticAssetReconciler::with_executor(...) setter (defaults to Arc::new(LocalForgeDriver::default())).")
//! @yah:verify("Two consecutive runs against a fake R2 / MinIO mock: upload-then-skip; derive-mode assets resolve through cache and round-trip.")
//! @arch:see(.yah/docs/working/W164-derived-static-assets.md)
//! @yah:depends_on(R438-T13)
//! @yah:handoff("T15 landed. Cloud reconciler materialize step (W164) wired end-to-end. Changes: (1) StaticAssetReconciler gains `executor: Arc<dyn ForgeExecutor>` field + `with_executor(...)` setter; default Arc::new(LocalForgeDriver::default()). Threaded through up→sync_to_r2/sync_to_minio→sync_assets. (2) New materialize_asset() in crates/yah/cloud/src/reconciler/static_asset.rs lifts legacy `source=...` to disk path verbatim; derive-mode lowers to materialize_fetch() + optional materialize_transform(). (3) materialize_fetch: HTTP GET cached by upstream-blake3 to .yah/cache/derive/fetch/<hex>.bin; cache HIT verifies hash to catch bit-rot; cache MISS does atomic tmp+rename. (4) materialize_transform: TransformRecipeLoader.load → substitute_argv binds YAH_TRANSFORM_IN_0/_OUT + recipe.params at argv-element granularity → lowers each step to ForgeSpec{Subprocess{argv, image}, TaskPlacement{Local, recipe.runtime}, timeout, label, initiator=Gnome{static-asset-reconciler}}, hands to executor.execute(); cached by output-blake3. Unresolved {{placeholder}} after substitute_argv is a hard error. (5) Materialized path replaces entry.source for the existing BLAKE3-verify + S3 PUT loop — derive-mode assets ride the same upload path as legacy ones.")
//! @yah:next("Sign off → archive R438-T15.")
//! @yah:next("R422-F11 unblocked. Picker can resume: workload.toml gets [[asset]] + [asset.derive.fetch] + [asset.derive.transform], and the recipe TOML at .yah/qed/transforms/whisper-quantize.toml needs to be authored (R438-T8 worked-example covers the e2e verification).")
//! @yah:next("Follow-up R438-F11 (HTTP fetch retry/resume policy) is the natural next-step for production whisper-large fetches; today's path single-shots reqwest::get.")
//! @yah:verify("cargo test -p cloud --lib reconciler::static_asset  # 32 pass including 7 new W164 tests: materialize_legacy_source_returns_workload_dir_path + materialize_fetch_cache_miss_then_hit + materialize_fetch_blake3_mismatch_is_hard_error + materialize_transform_cache_miss_then_hit + materialize_transform_blake3_mismatch_on_output_is_hard_error + materialize_transform_recipe_failure_surfaces_stderr + materialize_derive_fetch_only_uses_fetch_path_for_upload")
//! @yah:verify("cargo check --workspace  # clean (only pre-existing warnings in desktop)")
//! @yah:verify("no new cloud→qed dep edge — cloud's new dep is task only (verified via cloud/Cargo.toml diff)")
//! @yah:gotcha("Architectural decision during T15: moved qed::transforms → task::transforms because cloud cannot dep on qed (per the original T5 verify clause). transforms.rs only deps on task::TaskRuntime + workload_spec::ImageRef; task is the right home. qed re-exports dropped (no external callers existed). Added `toml = '0.8'` + `pub mod transforms;` to task/Cargo.toml + task/src/lib.rs. Cloud's Cargo.toml now has `task = { path = '../task' }`. The W164 doc's piece-placement table that says 'Recipe TOML loader | qed (existing)' is now stale; transforms lives in task.")
//! @yah:gotcha("Stale test fixed: task::transforms::tests::rejects_recipe_with_struct_image_missing_digest now expects RecipeError::Parse (was ImageNotPinned). After R438-T3 tightened ImageRef.digest to non-Optional String, struct-form bare-tag fails at serde-deserialize, not at the post-parse ImageNotPinned check (which is now belt-and-braces against an empty-string digest).")
//! @yah:gotcha("Reconciler is per-asset sequential — W164 calls for bounded semaphore (default 4) cross-asset concurrency. Filed as R438-F11-style follow-up rather than added in this ticket to keep the diff focused on correctness. Not blocking for R422-F11.")
//!
//! @yah:ticket(R546-B6, "yah cloud cache seed computes the fetched-input blake3 then discards it — leaves [asset.derive.fetch].blake3 sentinel unfilled, silently disarming the shared lock fast-path")
//! @yah:at(2026-07-20T23:24:24Z)
//! @yah:status(open)
//! @yah:parent(R546)
//! @yah:next("Make `yah cloud cache seed` print the fetched-input blake3 alongside the other three, e.g. `[asset.derive.fetch].blake3 = \"<fetched_hash>\"`, so the operator can paste all four and arm BOTH skip layers. The value is already in scope as `fetched_hash` in seed_derivation_for_target — this is a print-line change plus threading it out through SeededDerivation.")
//! @yah:next("Verified fix shape by hand for the x86_64 row: fetch.blake3 = 3568931fb074a4e1b4d43098db5810e683cdadd06887a8bdd964a5719bca6481 (b3sum of the rusty_v8-149.4.0 archive; the fetch cache is content-addressed so the blob FILENAME is the blake3). After pasting, a re-seed reproduces the identical derive_key 6238d80e..., i.e. lock_skip_hash's recomputation now matches the lock.")
//! @yah:next("Consider also asserting it: if seed writes a lock whose fast-path cannot engage (fetch pin still sentinel), emit a warning rather than printing a success message that implies the job is done.")
//! @yah:gotcha("Surfaced 2026-07-20 by leif while closing R546-T3: 'why wasn't fetch.blake3 filled in already?'. `seed_derivation_for_target` ALREADY has the value — it calls materialize_fetch(&derive.fetch, ...) and binds `fetched_hash`, uses it to compute the derive_key, then prints ONLY [[asset]].blake3 + lock.input_hash + lock.output_blake3. The fetched-input hash is dropped on the floor.")
//! @yah:gotcha("CONSEQUENCE (non-obvious, cost real time to find): with [asset.derive.fetch].blake3 left as the zero sentinel, lock_skip_hash() bails at its FIRST guard (`is_bootstrap_sentinel(&derive.fetch.blake3.0) -> return None`, static_asset.rs ~line 770). So the W212 substituter fast-path never engages. The local action cache still skips the build, which MASKS the problem on the seeding machine — but a clean checkout / CI / another operator gets no skip at all. The seed command's whole purpose is 'prepare a no-rebuild apply', so leaving this unfilled defeats the shared half of it.")
//!
//! @yah:ticket(R546-B8, "static-asset transform passes a RELATIVE YAH_TRANSFORM_OUT into the container — any recipe that chdirs writes its artifact inside the container and silently loses it (cost a ~2h rusty-v8 arm64 build)")
//! @yah:at(2026-07-21T02:08:04Z)
//! @yah:status(open)
//! @yah:parent(R546)
//! @yah:next("FIX LANDED: canonicalize `cache_dir` and join the filename (the tmp file itself does not exist yet so it cannot be canonicalized directly); also canonicalize `input_path` for the YAH_TRANSFORM_IN_0 binding for the same reason. static_asset tests 46/46 green.")
//! @yah:next("ADD A REGRESSION TEST that asserts both YAH_TRANSFORM_IN_0 and YAH_TRANSFORM_OUT bindings are absolute after substitution. Not added yet — the existing tests exercise recipes that never chdir, so they cannot catch this class. A cheap version: assert Path::new(&params[ENV_TRANSFORM_OUT]).is_absolute().")
//! @yah:next("HARDENING: the reconciler should fail LOUDLY when a transform step exits 0 but produces no output at YAH_TRANSFORM_OUT — today the missing-file error surfaces as a confusing BLAKE3 read failure that reads like cache corruption rather than 'your recipe never wrote its output'.")
//! @yah:gotcha("FAILURE MODE IS SILENT AND EXPENSIVE: the step exits 0, no 'step failed' is reported, and the reconciler dies afterwards on `reading transform output ./.yah/cache/derive/transform/<derive_key>.tmp for BLAKE3: No such file or directory`. Hit 2026-07-20 after a ~2h native arm64 V8 build that had actually SUCCEEDED — the finished tar was written inside the container and thrown away with it.")
//! @yah:gotcha("ROOT CAUSE: materialize_transform built `tmp_output = cache_dir.join(\"<derive_key>.tmp\")` from `workspace_root`, which is \".\" by CLI default, then bound that RELATIVE string into the recipe argv as {{YAH_TRANSFORM_OUT}}. Note the code immediately below it already canonicalized `workspace_abs` for the container cwd (docker rejects `-w .`) — the OUT binding just never got the same treatment. A relative OUT only survives if the recipe never leaves its cwd: true for the whisper recipes (which is why this went unnoticed for months), FALSE for rusty-v8 because build-v8.sh chdirs into /tmp/tmp.XXXX/v8src to build V8.")
//! @yah:gotcha("CONTRAST: the QED/P018 offload path was unaffected because it passes an ABSOLUTE container path (/yah/produced/...). Only the LOCAL static-asset transform path had the relative binding.")
//!
//! @yah:ticket(R546-B10, "static-asset publish skips PUT on key EXISTENCE (HEAD), not content — bucket keeps stale bytes while the manifest records the new hash")
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:at(2026-07-21T21:00:26Z)
//! @yah:parent(R546)
//! @yah:severity(high)
//! @yah:next("Repro (real, cost this relay a wrong pin): static_asset.rs:670 does `if object_exists(...) { report.already_synced.push(key); new_manifest.insert(key, actual_hash); continue; }`. object_exists issues an existence-only probe (HTTP-verb HEAD) with no content comparison. So when the locally-materialized artifact differs from the object already at that key, the reconciler skips the PUT (bucket keeps the OLD bytes) yet still records the NEW locally-computed hash in the manifest. The published _yah-asset-catalog.json then advertises a hash that describes bytes which were never uploaded.")
//! @yah:next("Live evidence: cdn.yah.dev/yah-cloud/rusty-v8/v149.4.0/rusty-v8-aarch64-unknown-linux-musl.tar.gz serves blake3 d322b4a1… (last-modified 2026-06-20, hand-uploaded), while _yah-asset-catalog.json claims ebdd842d… — the artifact the 2026-07-20 apply built and then silently declined to upload. Both hashes are real; they describe different tarballs.")
//! @yah:next("Fix shape: when the object already exists, compare its hash against actual_hash before skipping. Cheapest probe is the ETag when it is a plain MD5 (single-part upload), but ETag is NOT a content hash for multipart uploads — do not key correctness on it alone. Preferred: store the blake3 as object metadata (x-amz-meta-blake3) at PUT time and compare that on the existence probe; fall back to re-PUT when the metadata is absent (older objects). Re-PUT on mismatch instead of skipping.")
//! @yah:next("Also decide the drift POSTURE, not just the mechanism: a content mismatch at a stable key is exactly the DriftBucket condition the journal already models (AssetState::DriftBucket, used at static_asset.rs:645 for source-vs-declared mismatch). Emitting the same event here, rather than silently overwriting, is probably the right default for a published CDN object — make it explicit rather than incidental.")
//! @yah:verify("Regression test: seed a bucket object at key K with bytes A, run the reconciler with a workload whose materialized artifact for K is bytes B (B != A), assert the object at K afterwards is B (or that a DriftBucket event was emitted) AND that the manifest never records B while the bucket still holds A.")
//! @yah:gotcha("Latent for most assets, which is why it went unnoticed for so long: W164 catalogs put the VERSION IN THE PATH (yah-cloud/rusty-v8/v149.4.0/…), so bytes at a given key normally never change and the skip is correct. It only bites when an object is placed at a key out-of-band (hand-uploaded) or when a rebuild is non-deterministic — both true for rusty-v8 arm64.")
//! @yah:gotcha("The manifest is NOT load-bearing for consumer correctness, so do not overstate the blast radius: prior_manifest is read only for PRUNE-candidate detection (static_asset.rs:534-549), and consumers verify pulled bytes against [[asset]].blake3 in workload.toml, not against the catalog JSON. The damage is a lying audit record + a silently-skipped publish, not corrupted downloads.")
//! @yah:assumes("Tier: Cleric — mechanism is a few lines, but the drift posture (overwrite vs refuse-and-report) is a real design call, and the ETag/multipart trap makes the naive fix wrong.")

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use super::{ReconcileCtx, Reconciler, RunningWorkload};
use crate::asset_journal::{AssetState, AssetStatusEvent, AssetStatusJournal};
use crate::provider::cloudflare::CloudflareClient;
use crate::reconciler::pond::DEFAULT_MINIO_PASSWORD;
use crate::reconciler::pond::DEFAULT_MINIO_USER;
use crate::{MirrorProviderSlot, Provider};

use local_driver::s3_sign::{sign_s3_empty_body, sign_s3_put_object};
use velveteen_exec::transforms::{
    substitute_argv, RecipeStep, TransformRecipe, TransformRecipeLoader, ENV_TRANSFORM_IN_0,
    ENV_TRANSFORM_OUT,
};
use velveteen::{ForgeCommand, ForgeSpec, Initiator, MeshAccess, TaskLocation, TaskPlacement};
use velveteen_exec::{ExecContext, ForgeExecutor, LocalForgeDriver};
use workload_spec::validate::shape_static_asset;
use workload_spec::{AssetEntry, FetchSource, Millis, StaticAssetWorkload, TransformSpec};

/// Workload kind handled by this reconciler.
pub const WORKLOAD_KIND: &str = "static-asset";

/// S3 region string for Cloudflare R2.
const R2_REGION: &str = "auto";
/// S3 region string for MinIO (SigV4 requires a non-empty value).
const MINIO_REGION: &str = "us-east-1";

/// Bucket key for the per-run catalog manifest sidecar.
const CATALOG_MANIFEST_KEY: &str = "_yah-asset-catalog.json";

/// 64 zero hex digits — the "not yet pinned" sentinel for `BlakeHash`.
///
/// Bootstrap mode: a derive-mode asset can ship with this value in any
/// `blake3` field (`[[asset]].blake3` or `[asset.derive.fetch].blake3`)
/// before its first apply. The reconciler computes the actual hash, accepts
/// the bytes, uploads, and surfaces the discovered hash in the report for
/// paste-back. Once pinned, subsequent runs verify normally. Treats the
/// `blake3` field as the lockfile's *output*, not its precondition — first
/// publish or disaster-recovery hydration just works.
#[allow(dead_code)] // referenced by tests + serves as documentation of the sentinel literal
const ZERO_SENTINEL_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// True when `hex` is the 64-zero "not pinned yet" sentinel for `BlakeHash`.
fn is_bootstrap_sentinel(hex: &str) -> bool {
    hex.len() == 64 && hex.bytes().all(|b| b == b'0')
}

/// W209/F4: per-bootstrap output key on `$YAH_OUTPUTS`. The filename is
/// included so multi-asset workloads round-trip — each asset's bind in the
/// publish-assets pipeline TOML references its own key. Key shape:
///   - `discovered_asset_blake3:<filename>` for post-transform output
///   - `discovered_fetch_blake3:<filename>` for upstream content pin
fn bootstrap_output_key(b: &BootstrappedHash) -> String {
    let prefix = match b.kind {
        BootstrapHashKind::Output => "discovered_asset_blake3",
        BootstrapHashKind::Fetch => "discovered_fetch_blake3",
        // W212/R518: the derivation key for the in-tree `[asset.derive.lock]`.
        BootstrapHashKind::Input => "discovered_input_hash",
    };
    format!("{prefix}:{}", b.filename)
}

/// Append discovered BLAKE3 values to `$YAH_OUTPUTS` so the QED runner's
/// per-step output collector picks them up after `yah cloud apply` returns
/// (W209/F4). No-op outside a QED pipeline (env var unset).
fn write_bootstrap_outputs(bootstrapped: &[BootstrappedHash]) -> std::io::Result<()> {
    let Some(path) = std::env::var_os("YAH_OUTPUTS") else {
        return Ok(());
    };
    append_bootstrap_outputs(Path::new(&path), bootstrapped)
}

/// Inner write — extracted so unit tests can exercise the format without
/// racing on the `YAH_OUTPUTS` env var (cargo's parallel test runner makes
/// process-wide env mutation unsafe).
fn append_bootstrap_outputs(path: &Path, bootstrapped: &[BootstrappedHash]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    for b in bootstrapped {
        writeln!(file, "{}={}", bootstrap_output_key(b), b.hash)?;
    }
    Ok(())
}

/// Where a discovered BLAKE3 belongs in `workload.toml` for paste-back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapHashKind {
    /// `[[asset]].blake3` — post-transform (or post-fetch when no transform) output.
    Output,
    /// `[asset.derive.fetch].blake3` — upstream content pin.
    Fetch,
    /// W212/R518: `[asset.derive.lock].input_hash` — the input-addressed
    /// derivation key. Emitted on every successful transform build so the bind
    /// path refreshes the lock whenever the inputs change.
    Input,
}

/// One BLAKE3 value discovered during a bootstrap-mode apply.
///
/// Operator pastes `hash` into the field named by `kind` for the row matching
/// `filename`. Subsequent runs verify against the pinned value.
#[derive(Debug, Clone)]
pub struct BootstrappedHash {
    pub filename: String,
    pub kind: BootstrapHashKind,
    pub hash: String,
}

/// In-bucket sidecar: maps object key → blake3_hex for what was last uploaded.
/// Used to detect prune candidates across runs without listing the bucket.
type CatalogManifest = HashMap<String, String>;

/// Summary of a completed static-asset sync.
#[derive(Debug, Default)]
pub struct StaticAssetSyncReport {
    /// Asset filenames that were already present in the bucket with a matching
    /// BLAKE3 stamp (genuinely skipped — the bytes are known to be current).
    pub already_synced: Vec<String>,
    /// Asset filenames uploaded this run.
    pub uploaded: Vec<String>,
    /// R546-B10: filenames whose bucket object existed but did NOT match the
    /// declared artifact — either drifted content or a legacy object with no
    /// `x-amz-meta-blake3` stamp — and was therefore re-uploaded. A key showing
    /// up here repeatedly across runs means something outside this reconciler
    /// keeps rewriting it; a key appearing exactly once is the expected
    /// one-time heal of a pre-metadata object.
    pub republished: Vec<String>,
    /// Asset filenames whose source BLAKE3 hash didn't match the manifest.
    /// These are NOT uploaded — operator must rebuild or fix the declaration.
    pub hash_mismatch: Vec<String>,
    /// Asset filenames that were in the stored catalog manifest but are no
    /// longer in the current `workload.toml`. Prune candidates — not deleted.
    pub prune_candidates: Vec<String>,
    /// BLAKE3 values discovered during a bootstrap-mode apply (a `blake3` field
    /// shipped as the zero sentinel). Operator pastes these into the catalog
    /// to pin it; the assets were nonetheless uploaded this run.
    pub bootstrapped: Vec<BootstrappedHash>,
}

/// Reconciles `kind = "static-asset"` components.
///
/// The `executor` field handles W164 transform recipes for derive-mode assets
/// (R438-T15). Default is `LocalForgeDriver` — the cloud reconciler runs the
/// recipe on the same host that owns the cache. Callers wanting to redirect
/// transforms to a different `ForgeExecutor` (e.g. for tests with a mock
/// executor) use [`Self::with_executor`].
pub struct StaticAssetReconciler {
    executor: Arc<dyn ForgeExecutor>,
}

impl StaticAssetReconciler {
    pub fn new() -> Self {
        Self {
            executor: Arc::new(LocalForgeDriver::default()),
        }
    }

    /// Swap the [`ForgeExecutor`] used to materialize derive-mode transforms.
    /// Used by tests to inject a mock executor; production paths take the
    /// `LocalForgeDriver` default.
    pub fn with_executor(mut self, executor: Arc<dyn ForgeExecutor>) -> Self {
        self.executor = executor;
        self
    }
}

impl Default for StaticAssetReconciler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Reconciler for StaticAssetReconciler {
    fn kind(&self) -> &'static str {
        WORKLOAD_KIND
    }

    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        let workload_dir = ctx.workload_dir();

        // Load and shape-validate the workload.
        let workload = load_workload(&workload_dir)?;
        shape_static_asset(&workload).with_context(|| {
            format!(
                "{}/workload.toml: closed-catalog invariant violated",
                workload_dir.display()
            )
        })?;

        // Resolve the object_store provider slot.
        let slot = ctx.slot("object_store").with_context(|| {
            format!(
                "mirror has no `providers.object_store` slot — required for \
                 kind=\"static-asset\" (service={}, env={})",
                ctx.service.name, ctx.env,
            )
        })?;

        let journal = AssetStatusJournal::at_workspace(ctx.workspace_root);
        let service_name = ctx.service.name.as_str();

        let report = match slot {
            MirrorProviderSlot::Reference {
                provider_id,
                fields,
            } => {
                // Any cloudflare-*kind* provider routes here (dispatch is on
                // the resolved kind, not the literal name) so a workspace can
                // declare several — e.g. `cloudflare` + `cloudflare-scrabcake`.
                let cf = super::cf_creds::CfProvider::resolve_scoped(
                    ctx.workspace_root,
                    provider_id,
                    &ctx.scope.tenant,
                    &ctx.scope.namespace,
                )?;
                anyhow::ensure!(
                    matches!(cf.cfg.kind, Provider::Cloudflare),
                    "providers.object_store.use = {provider_id:?} (kind={:?}) not supported \
                     for static-asset — only cloudflare-kind reference providers are",
                    cf.cfg.kind,
                );
                sync_to_r2(
                    &ctx,
                    cf,
                    &workload,
                    fields,
                    self.executor.clone(),
                    service_name,
                    &journal,
                )
                .await?
            }
            MirrorProviderSlot::Inline {
                kind: Provider::MinioContainer,
                fields,
            } => {
                sync_to_minio(
                    &ctx,
                    &workload,
                    fields,
                    self.executor.clone(),
                    service_name,
                    &journal,
                )
                .await?
            }
            MirrorProviderSlot::Inline { kind, .. } => {
                anyhow::bail!(
                    "providers.object_store.kind = {kind:?} not supported for static-asset \
                     (expected minio-container or a cloudflare reference)"
                );
            }
        };

        if !report.hash_mismatch.is_empty() {
            warn!(
                files = ?report.hash_mismatch,
                "BLAKE3 mismatch for {} asset(s) — rebuild source files before syncing",
                report.hash_mismatch.len(),
            );
            anyhow::bail!(
                "static-asset sync failed: {} source file(s) have BLAKE3 mismatches: {:?}",
                report.hash_mismatch.len(),
                report.hash_mismatch,
            );
        }

        if !report.prune_candidates.is_empty() {
            warn!(
                files = ?report.prune_candidates,
                "{} file(s) no longer in catalog — run `yah service prune` to remove",
                report.prune_candidates.len(),
            );
        }

        // Surface bootstrap-mode discoveries as pipeline outputs (W209 §
        // Migration #1). When this reconciler runs inside a QED step, the
        // runner sets `$YAH_OUTPUTS` to a per-step KEY=VALUE sidechannel;
        // discovered BLAKE3s flow into the run's OutputMap and feed any
        // `[[bind]]` declarations in the publish-assets pipeline TOML — the
        // applier writes them back into workload.toml mid-pipeline. Key
        // shape encodes the asset filename so multi-asset workloads round-
        // trip: `discovered_asset_blake3:<filename>=<hex>`.
        if !report.bootstrapped.is_empty() {
            if let Err(err) = write_bootstrap_outputs(&report.bootstrapped) {
                // A write failure shouldn't poison the apply — the operator
                // still has the summary info! line below for triage.
                warn!(error = %err, "failed to write discovered BLAKE3s to $YAH_OUTPUTS");
            }
            info!(
                count = report.bootstrapped.len(),
                discoveries = ?report
                    .bootstrapped
                    .iter()
                    .map(|b| format!("{}={}", bootstrap_output_key(b), b.hash))
                    .collect::<Vec<_>>(),
                "discovered {} BLAKE3 value(s) — surfaced via $YAH_OUTPUTS for pipeline bind",
                report.bootstrapped.len(),
            );
        }

        info!(
            uploaded = report.uploaded.len(),
            already_synced = report.already_synced.len(),
            prune_candidates = report.prune_candidates.len(),
            bootstrapped = report.bootstrapped.len(),
            "static-asset sync complete",
        );

        Ok(RunningWorkload::adopted(
            WORKLOAD_KIND,
            "object_store",
            None,
        ))
    }
}

// ── Backend dispatch ──────────────────────────────────────────────────────────

async fn sync_to_r2(
    ctx: &ReconcileCtx<'_>,
    cf_provider: super::cf_creds::CfProvider,
    workload: &StaticAssetWorkload,
    slot_fields: &std::collections::BTreeMap<String, toml::Value>,
    executor: Arc<dyn ForgeExecutor>,
    service_name: &str,
    journal: &AssetStatusJournal,
) -> Result<StaticAssetSyncReport> {
    // `cf_provider` resolved from the mirror slot's `use = "<id>"` — supplies
    // account_id + management token + R2 S3 keys, all per-provider.
    let account_id = cf_provider.account_id.clone();

    let bucket = slot_fields
        .get("bucket")
        .and_then(|v| v.as_str())
        .context("providers.object_store missing `bucket` field for cloudflare static-asset sync")?
        .to_string();

    let (access_key, secret_key) = cf_provider.r2_keys()?;
    let api_token = cf_provider.api_token()?;

    ensure_r2_bucket(&api_token, &account_id, &bucket).await?;

    let endpoint = format!("https://{account_id}.r2.cloudflarestorage.com");
    let client = reqwest::Client::new();

    sync_assets(
        workload,
        ctx.workspace_root,
        &ctx.workload_dir(),
        &client,
        &endpoint,
        &bucket,
        R2_REGION,
        &access_key,
        &secret_key,
        executor,
        service_name,
        journal,
    )
    .await
}

async fn sync_to_minio(
    ctx: &ReconcileCtx<'_>,
    workload: &StaticAssetWorkload,
    slot_fields: &std::collections::BTreeMap<String, toml::Value>,
    executor: Arc<dyn ForgeExecutor>,
    service_name: &str,
    journal: &AssetStatusJournal,
) -> Result<StaticAssetSyncReport> {
    use super::slot_field_u16;
    use crate::reconciler::pond::DEFAULT_MINIO_API_PORT;

    let api_port = slot_field_u16(slot_fields, "api_port").unwrap_or(DEFAULT_MINIO_API_PORT);
    let bucket = slot_fields
        .get("bucket")
        .and_then(|v| v.as_str())
        .context(
            "providers.object_store missing `bucket` field for minio-container static-asset sync",
        )?
        .to_string();

    let endpoint = format!("http://127.0.0.1:{api_port}");
    let client = reqwest::Client::new();

    sync_assets(
        workload,
        ctx.workspace_root,
        &ctx.workload_dir(),
        &client,
        &endpoint,
        &bucket,
        MINIO_REGION,
        DEFAULT_MINIO_USER,
        DEFAULT_MINIO_PASSWORD,
        executor,
        service_name,
        journal,
    )
    .await
}

// ── Core sync logic ───────────────────────────────────────────────────────────

async fn sync_assets(
    workload: &StaticAssetWorkload,
    workspace_root: &Path,
    workload_dir: &Path,
    client: &reqwest::Client,
    endpoint: &str,
    bucket: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    executor: Arc<dyn ForgeExecutor>,
    service_name: &str,
    journal: &AssetStatusJournal,
) -> Result<StaticAssetSyncReport> {
    let mut report = StaticAssetSyncReport::default();
    let endpoint = endpoint.trim_end_matches('/');

    // Load the stored catalog manifest to detect prune candidates.
    let prior_manifest =
        load_catalog_manifest(client, endpoint, bucket, region, access_key, secret_key).await;

    // Catalog set for prune detection: current catalog filenames.
    let current_filenames: std::collections::HashSet<&str> = workload
        .assets
        .iter()
        .map(|a| a.filename.as_str())
        .collect();

    // Prune candidates: filenames in the stored manifest but not in current catalog.
    for prior_key in prior_manifest.keys() {
        if !current_filenames.contains(prior_key.as_str()) {
            report.prune_candidates.push(prior_key.clone());
        }
    }

    // Updated manifest built from this run.
    let mut new_manifest = CatalogManifest::new();

    for entry in &workload.assets {
        // W212/R518: substituter fast-path. When the committed `[asset.derive.lock]`
        // still matches the inputs recomputed from the current pins (purely
        // local — no fetch) AND the bucket already holds the output, skip the
        // entire build: no model download, no Docker transform, no PUT. This is
        // the Nix-substituter / Bazel-remote-cache behaviour, backed by the
        // checked-in lock as the action cache and R2 as the CAS.
        if let Some(out_hash) = lock_skip_hash(entry, workspace_root).await {
            let object_url = format!("{endpoint}/{bucket}/{}", entry.filename);
            // R546-B10: the lock says WHAT the output should be; the bucket must
            // actually hold it. An unstamped legacy object is not evidence of a
            // match, so it falls through and rebuilds rather than blessing bytes
            // we cannot identify — the expensive-but-correct direction.
            let remote = head_object(client, &object_url, region, access_key, secret_key).await?;
            if remote.matches(&out_hash) {
                debug!(
                    filename = %entry.filename,
                    "derivation lock in sync + object content matches — skipping build",
                );
                report.already_synced.push(entry.filename.clone());
                new_manifest.insert(entry.filename.clone(), out_hash);
                continue;
            }
            if remote.exists() {
                debug!(
                    filename = %entry.filename,
                    "derivation lock in sync but bucket object is unstamped or drifted \
                     — not trusting it, falling through to build/publish",
                );
            }
        }

        // R438-T15: derive-mode assets materialize to a content-addressed cache
        // path (W164); legacy `source = "..."` assets read straight from disk.
        // Both arms return a real on-disk path that the existing BLAKE3 verify +
        // S3 PUT loop below treats uniformly.
        let materialized =
            materialize_asset(entry, workspace_root, workload_dir, executor.as_ref())
                .await
                .with_context(|| format!("materializing asset {:?}", entry.filename))?;
        let source_path = materialized.path;
        // Capture before the discovered_fetch_hash is moved out below.
        let fetch_was_bootstrap = materialized.discovered_fetch_hash.is_some();
        // W212/R518: derivation key for this build — emitted below so the bind
        // path refreshes `[asset.derive.lock].input_hash`.
        let build_derive_key = materialized.derive_key.clone();

        // Surface any discovered upstream BLAKE3 (bootstrap mode for
        // `[asset.derive.fetch].blake3`). Collected into `report.bootstrapped`
        // and emitted to `$YAH_OUTPUTS` by the summary block in `up` (W209/F4).
        if let Some(hash) = materialized.discovered_fetch_hash {
            debug!(
                filename = %entry.filename,
                discovered = %hash,
                "bootstrap discovered upstream blake3",
            );
            report.bootstrapped.push(BootstrappedHash {
                filename: entry.filename.clone(),
                kind: BootstrapHashKind::Fetch,
                hash,
            });
        }

        // Read source file.
        let body = tokio::fs::read(&source_path).await.with_context(|| {
            format!(
                "reading source file {} for asset {:?}",
                source_path.display(),
                entry.filename
            )
        })?;

        // BLAKE3 verification — strict mode rejects mismatch and skips upload;
        // bootstrap mode (entry.blake3 == zero sentinel) accepts the computed
        // hash and surfaces it in the report for paste-back. The bytes are
        // uploaded either way — the difference is whether the pin is being
        // *verified against* (strict) or *discovered* (bootstrap).
        let actual_hash = blake3_hex(&body);
        if is_bootstrap_sentinel(&entry.blake3.0) {
            debug!(
                filename = %entry.filename,
                discovered = %actual_hash,
                "bootstrap discovered asset blake3",
            );
            report.bootstrapped.push(BootstrappedHash {
                filename: entry.filename.clone(),
                kind: BootstrapHashKind::Output,
                hash: actual_hash.clone(),
            });
        } else if !hashes_equal(&actual_hash, &entry.blake3.0) {
            warn!(
                filename = %entry.filename,
                declared = %entry.blake3.0,
                actual = %actual_hash,
                "BLAKE3 mismatch — source file doesn't match declared hash",
            );
            report.hash_mismatch.push(entry.filename.clone());
            journal
                .append(&AssetStatusEvent {
                    at: Utc::now(),
                    asset: format!("{service_name}:{}", entry.filename),
                    from: None,
                    to: AssetState::DriftBucket,
                    bytes: None,
                    blake3: None,
                })
                .await;
            continue;
        }

        // W212/R518: a verified build emits its derivation key so the bind path
        // refreshes `[asset.derive.lock].input_hash`. Paired with the output
        // hash above, this records the action-cache entry the next run's
        // substituter fast-path consults. Only emitted when a build actually
        // ran (the lock-skip path `continue`d before reaching here).
        if let Some(dk) = &build_derive_key {
            report.bootstrapped.push(BootstrappedHash {
                filename: entry.filename.clone(),
                kind: BootstrapHashKind::Input,
                hash: dk.clone(),
            });
        }

        let key = &entry.filename;
        let object_url = format!("{endpoint}/{bucket}/{key}");

        // R546-B10: skip the PUT only when the bucket demonstrably holds THESE
        // bytes. Existence alone is not enough — an object placed at this key
        // out-of-band, or a rebuild that isn't byte-reproducible, leaves content
        // that differs from the artifact we just verified. Skipping on mere
        // existence let the bucket keep stale bytes while `new_manifest` below
        // recorded the new hash, so the published catalog described bytes that
        // were never uploaded.
        //
        // Note `actual_hash` is already verified equal to the declared
        // `entry.blake3` at this point (the mismatch arm above `continue`s), so
        // re-PUTting on drift converges the bucket toward the committed catalog
        // rather than clobbering it with something unvetted.
        let remote = head_object(client, &object_url, region, access_key, secret_key).await?;
        if remote.matches(&actual_hash) {
            debug!(key, "already present with matching blake3 — skipping PUT");
            report.already_synced.push(key.clone());
            new_manifest.insert(key.clone(), actual_hash);
            continue;
        }
        if remote.exists() {
            // Drifted, or a legacy object predating the metadata stamp. Either
            // way re-PUT: identical bytes make it a cheap idempotent overwrite
            // that heals the missing stamp, and differing bytes are exactly the
            // case that must not be skipped. Legacy objects therefore cost ONE
            // re-upload, after which the stamp makes the skip work again.
            warn!(
                key,
                expected = %actual_hash,
                remote = ?match &remote {
                    RemoteObject::Present { blake3 } => blake3.as_deref(),
                    RemoteObject::Absent => None,
                },
                "bucket object does not match the declared artifact — re-publishing",
            );
            report.republished.push(key.clone());
        }

        // PUT the file.
        let body_sha256 = sha256_hex(&body);
        let content_length = body.len();
        let content_type = content_type_for(&source_path);
        let headers = sign_s3_put_object(
            &object_url,
            &body_sha256,
            content_type,
            content_length,
            region,
            access_key,
            secret_key,
            // R546-B10: stamp the content hash so a later run can tell whether
            // the bucket already holds these exact bytes.
            Some(actual_hash.as_str()),
        )
        .with_context(|| format!("signing PUT {object_url}"))?;

        let resp = client
            .put(&object_url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .with_context(|| format!("PUT {object_url}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            anyhow::bail!("PUT {object_url} → {status}: {}", body_text.trim());
        }

        info!(key, "uploaded");
        report.uploaded.push(key.clone());
        new_manifest.insert(key.clone(), actual_hash.clone());
        let from_state = if fetch_was_bootstrap {
            AssetState::PlaceholderFetch
        } else if is_bootstrap_sentinel(&entry.blake3.0) {
            AssetState::PlaceholderOutput
        } else {
            AssetState::PinnedNotPublished
        };
        journal
            .append(&AssetStatusEvent {
                at: Utc::now(),
                asset: format!("{service_name}:{key}"),
                from: Some(from_state),
                to: AssetState::Published,
                bytes: Some(content_length as u64),
                blake3: Some(actual_hash),
            })
            .await;
    }

    // Save the updated manifest (non-fatal: data is already in the bucket).
    if let Err(e) = save_catalog_manifest(
        client,
        endpoint,
        bucket,
        &new_manifest,
        region,
        access_key,
        secret_key,
    )
    .await
    {
        warn!(
            error = %e,
            "failed to save asset catalog manifest (non-fatal) — prune detection may miss \
             candidates on the next run"
        );
    }

    Ok(report)
}

// ── W164 materialize step (R438-T15) ──────────────────────────────────────────

/// Output of [`materialize_asset`]: the on-disk path the upload loop reads,
/// plus any BLAKE3 discovered during bootstrap-mode fetch.
struct MaterializedAsset {
    path: PathBuf,
    /// Set when `derive.fetch.blake3` was the zero sentinel and the reconciler
    /// computed the actual upstream hash. Operator pastes this back into
    /// `[asset.derive.fetch].blake3`. `None` in strict mode and for legacy
    /// `source = "..."` assets.
    discovered_fetch_hash: Option<String>,
    /// W212/R518: the input-addressed derivation key for this build, emitted to
    /// `$YAH_OUTPUTS` so the bind path refreshes `[asset.derive.lock].input_hash`.
    /// `None` for `source` / no-transform assets.
    derive_key: Option<String>,
}

/// BLAKE3 of a transform recipe's TOML bytes — an input to the derivation key
/// (W212). The file carries the pinned container digest, steps, and placement,
/// so hashing it captures every recipe-side input in one value. `None` when the
/// recipe file is unreadable (the caller treats that as "can't memoize").
async fn recipe_blake3(workspace_root: &Path, recipe: &str) -> Option<String> {
    let path = workspace_root
        .join(".yah/qed/transforms")
        .join(format!("{recipe}.toml"));
    let bytes = tokio::fs::read(&path).await.ok()?;
    Some(blake3_hex(&bytes))
}

/// W212/R518: the substituter fast-path. Returns `Some(output_hash)` when the
/// asset's committed `[asset.derive.lock]` is *current* — i.e. the derivation
/// key recomputed from the COMMITTED pins (no network) equals `lock.input_hash`
/// and the lock describes the currently-pinned output. The caller still
/// confirms the bytes exist in the bucket before skipping the build. Returns
/// `None` (→ build normally) for source assets, no-transform assets, bootstrap
/// rows, a missing lock, or any input drift.
async fn lock_skip_hash(entry: &AssetEntry, workspace_root: &Path) -> Option<String> {
    let derive = entry.derive.as_ref()?;
    let transform = derive.transform.as_ref()?;
    let lock = derive.lock.as_ref()?;
    // A sentinel pin means nothing has been pinned yet → must build.
    if is_bootstrap_sentinel(&entry.blake3.0) || is_bootstrap_sentinel(&derive.fetch.blake3.0) {
        return None;
    }
    // The lock must describe the currently-pinned output, else it's stale.
    if !hashes_equal(&lock.output_blake3, &entry.blake3.0) {
        return None;
    }
    // Recompute the derivation key from the committed pins — purely local, no
    // fetch. The fetch pin is the declared input identity (a fixed-output
    // derivation), so in strict mode it equals the bytes that fed the build.
    let recipe_bk = recipe_blake3(workspace_root, &transform.recipe).await?;
    let key = derivation_key(&derive.fetch.blake3.0, &recipe_bk, &transform.params);
    (key == lock.input_hash).then(|| entry.blake3.0.clone())
}

/// Resolve an `[[asset]]` row to an on-disk path the upload loop can read.
///
/// Two modes:
///
/// - **Legacy `source`**: returns `workload_dir.join(source_rel)` — bytes are
///   already on disk, the rest of the pipeline is unchanged.
/// - **Derive (`derive.fetch[+transform]`)**: fetches the upstream blob into
///   `.yah/cache/derive/fetch/<upstream-blake3>.bin`, optionally runs the
///   transform recipe into `.yah/cache/derive/transform/<output-blake3>.bin`,
///   and returns whichever cache path holds the final bytes. The shape
///   validator (`shape_static_asset`) guarantees exactly one of the two is
///   set, so the `else` branch is total.
///
/// **Bootstrap mode.** When `derive.fetch.blake3` or `entry.blake3` is the
/// zero sentinel, the reconciler discovers the actual hash instead of
/// verifying against the pinned value. The discovered upstream hash is
/// returned in `discovered_fetch_hash`; the discovered output hash is
/// computed at the upload site (the bytes are read there anyway) and
/// surfaced separately.
async fn materialize_asset(
    entry: &AssetEntry,
    workspace_root: &Path,
    workload_dir: &Path,
    executor: &dyn ForgeExecutor,
) -> Result<MaterializedAsset> {
    if let Some(source_rel) = entry.source.as_ref() {
        return Ok(MaterializedAsset {
            path: workload_dir.join(source_rel),
            discovered_fetch_hash: None,
            derive_key: None,
        });
    }

    let derive = entry
        .derive
        .as_ref()
        .expect("AssetEntry shape: exactly one of source/derive must be set (shape_static_asset)");

    let cache_root = workspace_root.join(".yah/cache/derive");
    let fetch_bootstrap = is_bootstrap_sentinel(&derive.fetch.blake3.0);
    let (fetched_path, fetched_hash) =
        materialize_fetch(&derive.fetch, &cache_root.join("fetch")).await?;
    let discovered_fetch_hash = fetch_bootstrap.then(|| fetched_hash.clone());

    let path = if let Some(transform) = &derive.transform {
        materialize_transform(
            transform,
            &fetched_path,
            &fetched_hash,
            &entry.blake3.0,
            &cache_root.join("transform"),
            workspace_root,
            executor,
        )
        .await?
    } else {
        // No transform — the fetched bytes ARE the output. In strict mode,
        // fetch.blake3 must equal entry.blake3; let the upload loop's BLAKE3
        // verify surface any mismatch. In bootstrap mode the upload loop
        // discovers entry.blake3 directly from the file bytes.
        fetched_path
    };

    // W212/R518: derivation key for this build — the same value the local action
    // cache used (fetched-input hash ⊕ recipe-file hash ⊕ params). Surfaced so
    // the bind path can refresh `[asset.derive.lock].input_hash`.
    let derive_key = match &derive.transform {
        Some(transform) => recipe_blake3(workspace_root, &transform.recipe)
            .await
            .map(|rb| derivation_key(&fetched_hash, &rb, &transform.params)),
        None => None,
    };

    Ok(MaterializedAsset {
        path,
        discovered_fetch_hash,
        derive_key,
    })
}

/// Maximum number of fetch attempts (initial try + retries).
#[cfg(not(test))]
const FETCH_MAX_ATTEMPTS: u32 = 5;
#[cfg(test)]
const FETCH_MAX_ATTEMPTS: u32 = 3; // fewer retries in tests

/// Initial backoff between retries in milliseconds (doubles each attempt).
#[cfg(not(test))]
const FETCH_BASE_DELAY_MS: u64 = 1_000;
#[cfg(test)]
const FETCH_BASE_DELAY_MS: u64 = 1; // near-instant in tests

/// Ceiling on retry backoff in milliseconds.
#[cfg(not(test))]
const FETCH_MAX_DELAY_MS: u64 = 30_000;
#[cfg(test)]
const FETCH_MAX_DELAY_MS: u64 = 5; // near-instant in tests

/// Log download progress every N bytes.
const FETCH_LOG_INTERVAL_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

/// Outcome of a single download attempt that did not fully succeed. Used by
/// [`fetch_once`] to distinguish a transient failure (retry + Range resume)
/// from a non-retriable 4xx (bail immediately).
enum FetchOnceFail {
    /// Server returned a non-retriable 4xx. Caller should surface and stop.
    Fatal(reqwest::StatusCode),
    /// Network error or retriable server response (5xx / 429). Partial file
    /// is preserved on disk for Range-header resumption on the next attempt.
    Transient(anyhow::Error),
}

/// Fetch `fetch.url` into `<cache_dir>/<fetch.blake3>.bin`, verifying BLAKE3.
///
/// On cache HIT the network is skipped entirely; a hash mismatch surfaces as a
/// hard error (bit-rot / hand-edited cache, not silently re-fetched).
///
/// Cache MISS downloads the blob with:
/// - **Streaming to disk** — `Response::chunk()` rather than buffering the full
///   body in RAM (required for multi-GB blobs like whisper-large at 1.5 GB).
/// - **Exponential-backoff retry** — up to [`FETCH_MAX_ATTEMPTS`] attempts on
///   transient network errors and 5xx / 429 HTTP responses.
/// - **Range-header resume** — if a `.partial` file exists from a prior attempt,
///   subsequent tries send `Range: bytes=<offset>-` to avoid re-downloading
///   already-received bytes.
/// - **Progress logging** — `info!()` every 100 MiB surfaces download progress
///   through the task-pane / QED log surface (W164 OQ#4).
async fn materialize_fetch(fetch: &FetchSource, cache_dir: &Path) -> Result<(PathBuf, String)> {
    let bootstrap = is_bootstrap_sentinel(&fetch.blake3.0);

    tokio::fs::create_dir_all(cache_dir)
        .await
        .with_context(|| format!("creating fetch cache dir {}", cache_dir.display()))?;

    // Cache HIT — only meaningful when we know the expected hash. Bootstrap
    // mode has no stable cache key to look up; it always re-downloads on the
    // first run, then strict mode (after the operator pins the discovered
    // hash) takes the HIT path on subsequent runs.
    if !bootstrap {
        let cache_path = cache_dir.join(format!("{}.bin", fetch.blake3.0));
        if tokio::fs::try_exists(&cache_path).await.unwrap_or(false) {
            verify_blake3_path(&cache_path, &fetch.blake3.0)
                .await
                .with_context(|| {
                    format!(
                        "fetch cache HIT for {} but bytes don't match pinned BLAKE3 — \
                     rm the cache entry or fix the pin",
                        cache_path.display()
                    )
                })?;
            debug!(url = %fetch.url, "fetch cache HIT");
            return Ok((cache_path, fetch.blake3.0.clone()));
        }
    }

    // Partial filename: stable per (URL, mode) so Range resume works across
    // attempts. In bootstrap mode every fetch shares the zero "expected" hash,
    // so partials are namespaced by URL hash to avoid cross-asset collisions.
    let partial_path = if bootstrap {
        cache_dir.join(format!(
            "bootstrap-{}.partial",
            blake3_hex(fetch.url.as_bytes())
        ))
    } else {
        cache_dir.join(format!("{}.partial", fetch.blake3.0))
    };

    let client = reqwest::Client::new();
    let mut last_err = anyhow::anyhow!("no attempt made");

    for attempt in 0..FETCH_MAX_ATTEMPTS {
        if attempt > 0 {
            let delay_ms = (FETCH_BASE_DELAY_MS << (attempt - 1)).min(FETCH_MAX_DELAY_MS);
            warn!(
                url = %fetch.url,
                attempt,
                delay_ms,
                err = %last_err,
                "fetch transient failure; retrying with backoff",
            );
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }

        match fetch_once(&client, &fetch.url, &partial_path).await {
            Ok(()) => {
                // Compute hash once — used for verify (strict) and cache
                // naming (both modes; bootstrap mode names by the discovered
                // value rather than the zero placeholder).
                let bytes = tokio::fs::read(&partial_path)
                    .await
                    .with_context(|| format!("reading {} for BLAKE3", partial_path.display()))?;
                let actual = blake3_hex(&bytes);
                drop(bytes);

                if !bootstrap && !hashes_equal(&actual, &fetch.blake3.0) {
                    anyhow::bail!(
                        "downloaded {} but BLAKE3 doesn't match pin — \
                         check the pin in workload.toml (actual {actual} != expected {})",
                        fetch.url,
                        fetch.blake3.0,
                    );
                }

                let cache_path = cache_dir.join(format!("{actual}.bin"));
                tokio::fs::rename(&partial_path, &cache_path)
                    .await
                    .with_context(|| {
                        format!(
                            "promoting {} → {}",
                            partial_path.display(),
                            cache_path.display()
                        )
                    })?;
                if bootstrap {
                    info!(url = %fetch.url, discovered = %actual, "fetch complete (bootstrap)");
                } else {
                    info!(url = %fetch.url, "fetch complete");
                }
                return Ok((cache_path, actual));
            }
            Err(FetchOnceFail::Fatal(status)) => {
                anyhow::bail!("GET {} → HTTP {status} (not retriable)", fetch.url);
            }
            Err(FetchOnceFail::Transient(e)) => {
                last_err = e;
            }
        }
    }

    Err(last_err).with_context(|| {
        format!(
            "GET {} failed after {FETCH_MAX_ATTEMPTS} attempts",
            fetch.url
        )
    })
}

/// Single download attempt: GET `url` (with `Range` if `partial_path` is non-empty),
/// stream the response body to `partial_path`, and return once the body is exhausted.
///
/// Returns `Ok(())` when all bytes were received and flushed to disk.
/// Returns `Err(FetchOnceFail::Fatal)` for non-retriable 4xx responses.
/// Returns `Err(FetchOnceFail::Transient)` for connection errors, 5xx, or 429;
/// the partial file is left intact so the next attempt can resume via `Range`.
async fn fetch_once(
    client: &reqwest::Client,
    url: &str,
    partial_path: &Path,
) -> Result<(), FetchOnceFail> {
    use tokio::io::AsyncWriteExt;

    let resume_offset = tokio::fs::metadata(partial_path)
        .await
        .ok()
        .map(|m| m.len())
        .filter(|&n| n > 0);

    let mut req = client.get(url);
    if let Some(offset) = resume_offset {
        req = req.header(reqwest::header::RANGE, format!("bytes={offset}-"));
        info!(url, offset, "resuming partial download");
    } else {
        info!(url, "downloading");
    }

    let resp = req
        .send()
        .await
        .map_err(|e| FetchOnceFail::Transient(anyhow::anyhow!("connecting to {url}: {e}")))?;

    let status = resp.status();
    let is_partial_response = status == reqwest::StatusCode::PARTIAL_CONTENT;

    if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
        // Partial file may already hold all bytes (prior complete-but-not-verified
        // attempt). Delete it and let the next retry start fresh.
        let _ = tokio::fs::remove_file(partial_path).await;
        return Err(FetchOnceFail::Transient(anyhow::anyhow!(
            "GET {url} → 416 Range Not Satisfiable; partial cleared"
        )));
    }
    if status.is_client_error() {
        return Err(FetchOnceFail::Fatal(status));
    }
    if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(FetchOnceFail::Transient(anyhow::anyhow!(
            "GET {url} → HTTP {status}"
        )));
    }
    if !status.is_success() && !is_partial_response {
        return Err(FetchOnceFail::Fatal(status));
    }

    // Server returned 200 instead of 206 — it ignored our Range request.
    // Discard any partial bytes and stream the full body fresh.
    if !is_partial_response && resume_offset.is_some() {
        let _ = tokio::fs::remove_file(partial_path).await;
    }

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(is_partial_response)
        .truncate(!is_partial_response)
        .open(partial_path)
        .await
        .map_err(|e| {
            FetchOnceFail::Transient(anyhow::anyhow!("opening {}: {e}", partial_path.display()))
        })?;

    let mut downloaded = if is_partial_response {
        resume_offset.unwrap_or(0)
    } else {
        0
    };
    let mut resp = resp;
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                file.write_all(&chunk).await.map_err(|e| {
                    FetchOnceFail::Transient(anyhow::anyhow!(
                        "writing chunk to {}: {e}",
                        partial_path.display()
                    ))
                })?;
                let prev = downloaded;
                downloaded += chunk.len() as u64;
                if downloaded / FETCH_LOG_INTERVAL_BYTES > prev / FETCH_LOG_INTERVAL_BYTES {
                    info!(
                        url,
                        downloaded_mib = downloaded / (1024 * 1024),
                        "fetch progress",
                    );
                }
            }
            Ok(None) => break,
            Err(e) => {
                return Err(FetchOnceFail::Transient(anyhow::anyhow!(
                    "reading body from {url}: {e}"
                )));
            }
        }
    }

    file.flush().await.map_err(|e| {
        FetchOnceFail::Transient(anyhow::anyhow!("flushing {}: {e}", partial_path.display()))
    })?;

    Ok(())
}

/// Run the transform recipe against `input_path`, writing the output to
/// `<cache_dir>/<actual_blake3>.bin`. In strict mode the actual hash is
/// verified against `output_blake3`; in bootstrap mode (`output_blake3` ==
/// zero sentinel) the actual hash is accepted as-is and named accordingly.
/// Cache HIT (file present + hash matches) skips recipe execution; bootstrap
/// mode has no stable cache key and always re-runs the recipe.
/// W212 schema version for the derivation key. Bump when the *way* we hash or
/// lower inputs changes (not when an individual recipe changes — that's
/// captured by the recipe-file hash). A bump invalidates every action-cache
/// entry, forcing a clean rebuild under the new keying.
const DERIVE_KEY_SCHEMA: u32 = 1;

/// Compute the input-addressed action-cache key for a derive-mode transform
/// (W212). A pure function of the complete declared input set:
///
/// - `input_hash` — BLAKE3 of the fetched transform input (the fixed-output /
///   version anchor; for whisper this is `config.json`, which the model's repo
///   version tracks).
/// - `recipe_blake3` — BLAKE3 of the recipe TOML bytes. The file carries the
///   pinned container digest, the steps, and the placement, so hashing it
///   covers all three: a digest bump or a step edit flips the key.
/// - `params` — the workload-side invocation params (`BTreeMap` is already
///   sorted, so the encoding is deterministic).
///
/// **Hermeticity invariant:** every input that can change the output bytes MUST
/// feed this key. A missing dimension reintroduces the W164/R438 silent-stale
/// cache bug. The per-dimension unit test guards this.
fn derivation_key(
    input_hash: &str,
    recipe_blake3: &str,
    params: &BTreeMap<String, String>,
) -> String {
    let mut buf = String::new();
    buf.push_str(&format!("derive-key-v{DERIVE_KEY_SCHEMA}\n"));
    buf.push_str(&format!("input={input_hash}\n"));
    buf.push_str(&format!("recipe={recipe_blake3}\n"));
    for (k, v) in params {
        buf.push_str(&format!("param.{k}={v}\n"));
    }
    blake3_hex(buf.as_bytes())
}

/// Read a recorded action-cache output hash, if present. A missing or
/// unreadable / empty entry is a cache miss, never an error.
async fn read_action_cache(ac_path: &Path) -> Option<String> {
    let raw = tokio::fs::read_to_string(ac_path).await.ok()?;
    let hash = raw.trim();
    (!hash.is_empty()).then(|| hash.to_string())
}

/// Record an action-cache entry (`derive_key → output hash`). Written
/// atomically via tmp + rename so a crashed run never leaves a half-written
/// entry a later run would trust.
async fn write_action_cache(ac_path: &Path, output_hash: &str) -> Result<()> {
    if let Some(parent) = ac_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating action-cache dir {}", parent.display()))?;
    }
    let tmp = ac_path.with_extension("out.tmp");
    tokio::fs::write(&tmp, format!("{output_hash}\n"))
        .await
        .with_context(|| format!("writing action-cache tmp {}", tmp.display()))?;
    tokio::fs::rename(&tmp, ac_path)
        .await
        .with_context(|| format!("promoting action-cache entry {}", ac_path.display()))?;
    Ok(())
}

async fn materialize_transform(
    transform: &TransformSpec,
    input_path: &Path,
    input_hash: &str,
    output_blake3: &str,
    cache_dir: &Path,
    workspace_root: &Path,
    executor: &dyn ForgeExecutor,
) -> Result<PathBuf> {
    let bootstrap = is_bootstrap_sentinel(output_blake3);

    tokio::fs::create_dir_all(cache_dir)
        .await
        .with_context(|| format!("creating transform cache dir {}", cache_dir.display()))?;

    // Load + hash the recipe up front: the recipe TOML's bytes are an INPUT to
    // the derivation key (W212), so the key — and therefore the cache decision —
    // depends on them. The file carries the pinned container digest, steps, and
    // placement, so a change to any of those flips the key and forces a rebuild.
    let transforms_dir = workspace_root.join(".yah/qed/transforms");
    let loader = TransformRecipeLoader::new(&transforms_dir);
    let recipe_path = loader.recipe_path(&transform.recipe);
    let recipe = loader.load(&transform.recipe).with_context(|| {
        format!(
            "loading recipe {:?} from {}",
            transform.recipe,
            transforms_dir.display()
        )
    })?;
    let recipe_bytes = tokio::fs::read(&recipe_path).await.with_context(|| {
        format!(
            "reading recipe {} for derivation key",
            recipe_path.display()
        )
    })?;
    let recipe_blake3 = blake3_hex(&recipe_bytes);

    // W212: input-addressed action cache. The skip decision is a pure function
    // of the declared INPUTS (fetched input content ⊕ recipe definition ⊕
    // invocation params ⊕ lowering-schema version), not of the expected output
    // hash. A recipe / digest / param change flips `derive_key` → guaranteed
    // miss → rebuild, eliminating the warm-cache silent-stale skip (the
    // W164/R438 defect this fixes). Applies in bootstrap mode too: identical
    // inputs surface the recorded output without re-running.
    let derive_key = derivation_key(input_hash, &recipe_blake3, &transform.params);
    let ac_path = cache_dir.join("ac").join(format!("{derive_key}.out"));

    if let Some(recorded) = read_action_cache(&ac_path).await {
        let cas_path = cache_dir.join(format!("{recorded}.bin"));
        if tokio::fs::try_exists(&cas_path).await.unwrap_or(false)
            && verify_blake3_path(&cas_path, &recorded).await.is_ok()
        {
            // The output pin (`entry.blake3`) is still enforced downstream by
            // the upload loop's strict BLAKE3 verify, so a pin that has drifted
            // from the inputs surfaces there even though we skip the transform.
            debug!(recipe = %recipe.name, derive_key, "derivation cache HIT — skipping transform");
            return Ok(cas_path);
        }
        // AC entry present but the CAS bytes are gone / corrupt → fall through
        // and re-materialise (the AC records what the output should be; the CAS
        // lost the bytes).
    }

    // Absolute workspace_root for the container bind-mount — docker rejects
    // `-w .` ("the working directory '.' is invalid"). Callers may pass a
    // relative path (the CLI `--path` default is "."), so canonicalize once.
    let workspace_abs = workspace_root
        .canonicalize()
        .with_context(|| format!("canonicalizing workspace root {}", workspace_root.display()))?;

    // R546-B8: the IN/OUT bindings handed to the recipe MUST be absolute.
    // `cache_dir` is derived from workspace_root, which is "." by CLI default,
    // so these used to be relative (`./.yah/cache/derive/transform/<key>.tmp`).
    // A relative path only survives if the recipe never leaves its cwd — true
    // for whisper's recipes, FALSE for rusty-v8: build-v8.sh chdirs into a
    // scratch dir (/tmp/tmp.XXXX/v8src) to build V8, so it wrote its finished
    // tar to "<scratch>/./.yah/cache/..." INSIDE the container, invisible to the
    // host. The step then exited 0 and the reconciler failed reading a file that
    // was never going to be there — after a ~2h build. Canonicalize the parent
    // (it exists; created above) and join the filename, since the tmp output
    // itself does not exist yet and cannot be canonicalized directly.
    let cache_dir_abs = cache_dir
        .canonicalize()
        .with_context(|| format!("canonicalizing transform cache dir {}", cache_dir.display()))?;

    // Tmp output is named by the derivation key — unique per input set, so
    // concurrent rows (and zero-sentinel bootstrap rows) never collide on it.
    let tmp_output = cache_dir_abs.join(format!("{derive_key}.tmp"));

    let input_abs = input_path
        .canonicalize()
        .unwrap_or_else(|_| input_path.to_path_buf());

    let mut params: BTreeMap<String, String> = BTreeMap::new();
    params.insert(
        ENV_TRANSFORM_IN_0.to_string(),
        input_abs.to_string_lossy().into_owned(),
    );
    params.insert(
        ENV_TRANSFORM_OUT.to_string(),
        tmp_output.to_string_lossy().into_owned(),
    );
    for (k, v) in &transform.params {
        params.insert(k.clone(), v.clone());
    }

    info!(recipe = %recipe.name, "transform cache MISS, running");
    for step in &recipe.steps {
        let argv = substitute_argv(&step.argv, &params);
        // substitute_argv preserves `{{key}}` for unknown keys (no shell, no
        // string concat). Surface a missing-binding bug as a hard error rather
        // than letting the subprocess receive a literal placeholder.
        if let Some(unresolved) = argv.iter().find(|a| a.contains("{{")) {
            anyhow::bail!(
                "recipe {:?} step {:?}: unresolved placeholder in argv element {:?}",
                recipe.name,
                step.name,
                unresolved,
            );
        }
        let spec = lower_recipe_step_to_forge_spec(&recipe, step, argv);
        let mut ctx = ExecContext::default().with_cwd(workspace_abs.clone());
        if let Some(platform) = &recipe.placement.platform {
            ctx = ctx.with_platform(platform.clone());
        }
        let outcome = executor
            .execute(spec, ctx, None)
            .await
            .with_context(|| format!("executing recipe {:?} step {:?}", recipe.name, step.name))?;
        if !outcome.succeeded() {
            anyhow::bail!(
                "recipe {:?} step {:?} failed ({}): {}",
                recipe.name,
                step.name,
                outcome.status.discriminant(),
                outcome.stderr_tail
            );
        }
    }

    // Compute the actual hash once — used for verify (strict) and cache
    // naming (both modes). Bootstrap mode names by the discovered value;
    // strict mode names by the expected value (which equals actual after
    // the verify below).
    let output_bytes = tokio::fs::read(&tmp_output).await.with_context(|| {
        format!(
            "reading transform output {} for BLAKE3",
            tmp_output.display()
        )
    })?;
    let actual = blake3_hex(&output_bytes);
    drop(output_bytes);

    if !bootstrap && !hashes_equal(&actual, output_blake3) {
        anyhow::bail!(
            "transform output from recipe {:?} doesn't match pinned BLAKE3 \
             (actual {actual} != expected {output_blake3})",
            recipe.name
        );
    }

    // tmp_output already lives in cache_dir — atomic publish is one rename.
    let cache_path = cache_dir.join(format!("{actual}.bin"));
    tokio::fs::rename(&tmp_output, &cache_path)
        .await
        .with_context(|| {
            format!(
                "renaming {} → {}",
                tmp_output.display(),
                cache_path.display()
            )
        })?;

    // W212: record the action-cache entry (derive_key → output hash) so the
    // next run with identical inputs skips this transform entirely.
    write_action_cache(&ac_path, &actual)
        .await
        .with_context(|| format!("recording action-cache entry {}", ac_path.display()))?;

    if bootstrap {
        info!(
            recipe = %recipe.name,
            discovered = %actual,
            "transform complete (bootstrap)",
        );
    }

    Ok(cache_path)
}

/// Outcome of seeding the transform derivation cache from a pre-built artifact
/// (the qed→W164 bridge, R546-T3).
#[derive(Debug, Clone)]
pub struct SeededDerivation {
    /// The W212 derivation key the seeded action-cache entry is filed under —
    /// byte-identical to the one [`materialize_transform`] will look up, so the
    /// next `yah cloud apply` HITs it. Equals the value to paste into
    /// `[asset.derive.lock].input_hash`.
    pub derive_key: String,
    /// BLAKE3 of the pre-built artifact — the transform output hash. Equals the
    /// value to paste into `[[asset]].blake3` and `[asset.derive.lock].output_blake3`.
    pub output_blake3: String,
    /// The content-addressed store path the artifact was landed at.
    pub cas_path: PathBuf,
}

/// Seed the transform derivation cache (AC + CAS) from an artifact built OUT OF
/// BAND — the qed→W164 bridge (R546-T3).
///
/// # Why this exists
///
/// The static-asset reconciler lowers every transform to
/// [`TaskLocation::Local`](task::TaskLocation::Local) (see
/// [`lower_recipe_step_to_forge_spec`]) — it has no fleet-offload path, so on a
/// foreign-arch host it can only build the recipe under emulation (which OOMs for
/// the rusty_v8 musl build, the reason R546 exists). `yah qed run <pipeline>`
/// (e.g. P018) DOES offload to an arch-matched build-worker and, via R590-F6,
/// retrieves the produced tar content-addressed onto the caller. This function
/// bridges that pre-built tar into the W164 substituter: it writes the exact
/// action-cache + CAS entries [`materialize_transform`] would have written, so
/// the next `yah cloud apply` finds a HIT and PUBLISHES the pre-built bytes to
/// the consumer key + records the lock, instead of re-running the transform.
///
/// # Hermeticity
///
/// The derivation key is computed with the reconciler's OWN [`derivation_key`] +
/// [`recipe_blake3`], keyed on the SAME `fetched_hash` the reconciler derives
/// from the version anchor. Reusing those (not reimplementing) is what makes the
/// seeded key byte-identical to the lookup key — a drift would reintroduce the
/// W164/R438 silent-stale-cache bug. `fetched_hash` MUST be the value
/// [`materialize_fetch`] returns for `derive.fetch` (see [`seed_derivation_for_target`]).
pub async fn seed_transform_derivation(
    workspace_root: &Path,
    transform: &TransformSpec,
    fetched_hash: &str,
    artifact_path: &Path,
) -> Result<SeededDerivation> {
    let recipe_bk = recipe_blake3(workspace_root, &transform.recipe)
        .await
        .ok_or_else(|| {
            anyhow::anyhow!(
                "recipe {:?} unreadable under .yah/qed/transforms — cannot compute derivation key",
                transform.recipe,
            )
        })?;
    let derive_key = derivation_key(fetched_hash, &recipe_bk, &transform.params);

    let bytes = tokio::fs::read(artifact_path)
        .await
        .with_context(|| format!("reading pre-built artifact {}", artifact_path.display()))?;
    let output_blake3 = blake3_hex(&bytes);

    let cache_dir = workspace_root.join(".yah/cache/derive/transform");
    tokio::fs::create_dir_all(&cache_dir)
        .await
        .with_context(|| format!("creating transform cache dir {}", cache_dir.display()))?;

    // CAS: <cache_dir>/<output_blake3>.bin — the exact name materialize_transform
    // renames its output to (so its HIT-path verify_blake3_path passes). Atomic
    // tmp+rename; idempotent when the entry already exists.
    let cas_path = cache_dir.join(format!("{output_blake3}.bin"));
    if !tokio::fs::try_exists(&cas_path).await.unwrap_or(false) {
        let tmp = cache_dir.join(format!("{output_blake3}.seed.tmp"));
        tokio::fs::write(&tmp, &bytes)
            .await
            .with_context(|| format!("writing CAS tmp {}", tmp.display()))?;
        tokio::fs::rename(&tmp, &cas_path)
            .await
            .with_context(|| format!("promoting CAS entry {}", cas_path.display()))?;
    }

    // Action cache: <cache_dir>/ac/<derive_key>.out = <output_blake3>. Reuses the
    // reconciler's writer so the on-disk format can't drift from the reader.
    let ac_path = cache_dir.join("ac").join(format!("{derive_key}.out"));
    write_action_cache(&ac_path, &output_blake3)
        .await
        .with_context(|| format!("recording seeded action-cache entry {}", ac_path.display()))?;

    info!(
        recipe = %transform.recipe,
        derive_key,
        output_blake3,
        "seeded transform derivation cache from pre-built artifact (qed→W164 bridge)",
    );

    Ok(SeededDerivation {
        derive_key,
        output_blake3,
        cas_path,
    })
}

/// CLI-facing entry for the qed→W164 bridge (R546-T3): seed the derivation cache
/// for the `[[asset]]` row whose `derive.transform.params["target"]` equals
/// `target`, from a pre-built `artifact_path`.
///
/// Loads the static-asset workload, resolves the matching asset row, computes the
/// fetched-input hash via the reconciler's own [`materialize_fetch`] (downloading
/// the version anchor once; cached thereafter), then delegates to
/// [`seed_transform_derivation`]. After this returns, `yah cloud apply` on the
/// same service publishes the pre-built bytes without re-running the transform.
pub async fn seed_derivation_for_target(
    workspace_root: &Path,
    workload_path: &Path,
    target: &str,
    artifact_path: &Path,
) -> Result<SeededDerivation> {
    let raw = tokio::fs::read_to_string(workload_path)
        .await
        .with_context(|| format!("reading workload {}", workload_path.display()))?;
    let workload: StaticAssetWorkload = toml::from_str(&raw)
        .with_context(|| format!("parsing static-asset workload {}", workload_path.display()))?;

    let entry = workload
        .assets
        .iter()
        .find(|a| {
            a.derive
                .as_ref()
                .and_then(|d| d.transform.as_ref())
                .map(|t| t.params.get("target").map(String::as_str) == Some(target))
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no [[asset]] with derive.transform.params.target = {target:?} in {}",
                workload_path.display(),
            )
        })?;

    let derive = entry
        .derive
        .as_ref()
        .expect("asset matched by derive.transform above");
    let transform = derive
        .transform
        .as_ref()
        .expect("asset matched by derive.transform above");

    // Recompute the fetched-input hash exactly as the reconciler will — same
    // fetch source, same cache dir.
    let cache_root = workspace_root.join(".yah/cache/derive");
    let (_fetched_path, fetched_hash) =
        materialize_fetch(&derive.fetch, &cache_root.join("fetch")).await?;

    seed_transform_derivation(workspace_root, transform, &fetched_hash, artifact_path).await
}

/// Lower a single recipe step to a [`ForgeSpec`] (W164).
///
/// - `image` is always `Some(recipe.image)` — recipes always run inside the
///   pinned container.
/// - `where_` mirrors `recipe.placement` (Local + recipe-declared runtime).
/// - `timeout=0` in the recipe means "no timeout" (omitted from the spec).
/// - `label = "transform:<recipe>:<step>"`; initiator carries the reconciler
///   identity in the Gnome variant so audit traces attribute the run.
///
/// Pure function: callers feed it the already-substituted argv (or the raw
/// one in tests) and decide what to do with the resulting spec. Exposed at
/// `pub(crate)` for golden-test parity with the BuildMode lowering helper
/// (R438-T7).
pub(crate) fn lower_recipe_step_to_forge_spec(
    recipe: &TransformRecipe,
    step: &RecipeStep,
    substituted_argv: Vec<String>,
) -> ForgeSpec {
    ForgeSpec {
        command: ForgeCommand::Subprocess {
            argv: substituted_argv,
            image: Some(recipe.image.clone()),
        },
        where_: TaskPlacement::new(TaskLocation::Local, recipe.placement.runtime),
        timeout: if step.timeout == 0 {
            None
        } else {
            Some(Millis::from_secs(step.timeout))
        },
        label: Some(format!("transform:{}:{}", recipe.name, step.name)),
        initiator: Initiator::Gnome {
            camp: "static-asset-reconciler".into(),
            shift: format!("derive-{}", recipe.name),
        },
        mesh_access: MeshAccess::default(),
    }
}

/// Read `path` and assert its BLAKE3 hex matches `expected_hex` (case-insensitive).
async fn verify_blake3_path(path: &Path, expected_hex: &str) -> Result<()> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading {} for BLAKE3 verify", path.display()))?;
    let actual = blake3_hex(&bytes);
    if !hashes_equal(&actual, expected_hex) {
        anyhow::bail!(
            "BLAKE3 mismatch for {}: actual {} != expected {}",
            path.display(),
            actual,
            expected_hex,
        );
    }
    Ok(())
}

// ── Manifest helpers ──────────────────────────────────────────────────────────

async fn load_catalog_manifest(
    client: &reqwest::Client,
    endpoint: &str,
    bucket: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> CatalogManifest {
    let url = format!("{endpoint}/{bucket}/{CATALOG_MANIFEST_KEY}");
    let Ok(headers) = sign_s3_empty_body("GET", &url, region, access_key, secret_key) else {
        return HashMap::new();
    };
    let Ok(resp) = client.get(&url).headers(headers).send().await else {
        return HashMap::new();
    };
    if !resp.status().is_success() {
        return HashMap::new();
    }
    let Ok(bytes) = resp.bytes().await else {
        return HashMap::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

async fn save_catalog_manifest(
    client: &reqwest::Client,
    endpoint: &str,
    bucket: &str,
    manifest: &CatalogManifest,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<()> {
    let body = serde_json::to_vec(manifest).context("serializing catalog manifest")?;
    let body_sha256 = sha256_hex(&body);
    let url = format!("{endpoint}/{bucket}/{CATALOG_MANIFEST_KEY}");
    let headers = sign_s3_put_object(
        &url,
        &body_sha256,
        "application/json",
        body.len(),
        region,
        access_key,
        secret_key,
        // The manifest sidecar is rewritten every run by definition — stamping it
        // would be noise, and nothing skips a PUT on it (R546-B10).
        None,
    )
    .context("signing manifest PUT")?;
    let resp = client
        .put(&url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .context("PUT catalog manifest")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("PUT {url} → {status}: {}", body_text.trim());
    }
    Ok(())
}

// ── S3 helpers ────────────────────────────────────────────────────────────────

/// What a HEAD probe found at an object key (R546-B10).
///
/// The distinction that matters is *not* present-vs-absent but whether the
/// present bytes are the ones we are about to publish. `Present { blake3: None }`
/// is an object written before we started stamping `x-amz-meta-blake3` — its
/// content is unknowable from a HEAD, so callers must treat it as "might be
/// stale" rather than "matches".
#[derive(Debug, Clone, PartialEq, Eq)]
enum RemoteObject {
    Absent,
    Present { blake3: Option<String> },
}

impl RemoteObject {
    /// True only when the remote object is known to hold exactly `expected`.
    /// Unknown provenance (no metadata) is deliberately NOT a match.
    fn matches(&self, expected: &str) -> bool {
        matches!(self, RemoteObject::Present { blake3: Some(b3) } if hashes_equal(b3, expected))
    }

    fn exists(&self) -> bool {
        matches!(self, RemoteObject::Present { .. })
    }
}

/// HEAD an object key and report existence *plus* the recorded BLAKE3.
///
/// R546-B10: the previous `object_exists` returned a bare bool, so the publish
/// loop could not tell "same bytes already there" from "different bytes already
/// there" and skipped the PUT for both — leaving stale content in the bucket
/// while the catalog manifest advertised the new hash. We read our own
/// `x-amz-meta-blake3` stamp rather than the ETag, because ETag is only an MD5
/// of the content for single-part uploads; for multipart it is a digest-of-
/// digests and comparing it to a content hash is simply wrong.
async fn head_object(
    client: &reqwest::Client,
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<RemoteObject> {
    let headers = sign_s3_empty_body("HEAD", url, region, access_key, secret_key)
        .with_context(|| format!("signing HEAD {url}"))?;
    let resp = client
        .head(url)
        .headers(headers)
        .send()
        .await
        .with_context(|| format!("HEAD {url}"))?;
    if !resp.status().is_success() {
        return Ok(RemoteObject::Absent);
    }
    let blake3 = resp
        .headers()
        .get("x-amz-meta-blake3")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    Ok(RemoteObject::Present { blake3 })
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

fn blake3_hex(body: &[u8]) -> String {
    hex::encode(blake3::hash(body).as_bytes())
}

fn sha256_hex(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Case-insensitive hex comparison (BLAKE3 crate outputs lowercase; stored
/// hashes may have been authored in uppercase).
fn hashes_equal(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

// ── Content-type ──────────────────────────────────────────────────────────────

fn content_type_for(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "bin" => "application/octet-stream",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

// ── Bucket auto-create ────────────────────────────────────────────────────────

/// List R2 buckets under `account_id`; create `bucket_name` only when absent.
///
/// Takes the management `api_token` already resolved from the service's
/// provider (see [`super::cf_creds::CfProvider`]). Mirrors the idempotent pattern in
/// `cloudflare_worker.rs::ensure_r2_bucket` — list-first keeps the reconcile
/// loop safe to re-run without depending on CF's 4xx error shape on duplicate
/// create. R422-T12: lets the first `yah cloud apply --env cloud --service <s>`
/// against a static-asset mirror provision its bucket without an out-of-band
/// dashboard step.
async fn ensure_r2_bucket(api_token: &str, account_id: &str, bucket_name: &str) -> Result<()> {
    let cf = CloudflareClient::new(api_token.to_string());
    let existing = cf
        .list_r2_buckets(account_id)
        .await
        .context("listing R2 buckets")?;
    if existing.iter().any(|b| b.name == bucket_name) {
        debug!(bucket_name, "R2 bucket already exists — skipping create");
        return Ok(());
    }
    cf.create_r2_bucket(account_id, bucket_name)
        .await
        .with_context(|| format!("creating R2 bucket {bucket_name}"))?;
    info!(bucket_name, "R2 bucket created");
    Ok(())
}

// ── Workload loading ──────────────────────────────────────────────────────────

fn load_workload(workload_dir: &Path) -> Result<StaticAssetWorkload> {
    let path = workload_dir.join("workload.toml");
    let src =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    // R546-B7: do NOT route this through the `workload_spec::Workload` envelope.
    // That enum derives Deserialize with only `rename_all` — no
    // `#[serde(tag = "kind")]` — so it is EXTERNALLY tagged and only accepts the
    // nested `[[static-asset.asset]]` shape. Every real on-disk workload.toml is
    // flat (`kind = "static-asset"` alongside `[[asset]]`), which serde rejects
    // with "wanted exactly 1 element, more than 1 element" — the whole document
    // is a multi-key map where it wanted a single variant key. That broke
    // `yah cloud apply` for EVERY static-asset component (verified against the
    // long-published whisper catalog, not just rusty-v8).
    //
    // The envelope is not fixed here on purpose: `Workload` is also a
    // postcard wire type on the kamaji RPC path, and postcard (non
    // self-describing) cannot decode an internally-tagged enum — so slapping
    // `tag = "kind"` on it risks breaking that wire. Deserializing the payload
    // directly and checking `kind` by hand is the same thing
    // `seed_derivation_for_target` already does successfully. See R546-B7 for
    // the envelope-level fix.
    #[derive(serde::Deserialize)]
    struct KindProbe {
        kind: String,
    }
    let probe: KindProbe =
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;
    if probe.kind != "static-asset" {
        anyhow::bail!(
            "{}: expected kind=\"static-asset\" but found kind={:?}",
            path.display(),
            probe.kind
        );
    }
    let workload: StaticAssetWorkload =
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;

    // R546-B7: enforce the closed-catalog invariant the type's docs promise
    // ("every value in [aliases] must be a filename that exists in [[asset]],
    // enforced by validate::shape_static_asset"). It was NOT actually being run
    // here — `up_bails_when_catalog_alias_orphaned` only passed because the old
    // fixture failed to PARSE, so the expected error came from the wrong place.
    // With parsing fixed, an orphaned alias would have silently reconciled.
    workload_spec::validate::shape_static_asset(&workload)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;

    Ok(workload)
}

fn workload_kind_str(w: &workload_spec::Workload) -> &'static str {
    match w {
        workload_spec::Workload::MesofactStatic(_) => "mesofact-static",
        workload_spec::Workload::Container(_) => "container",
        workload_spec::Workload::Almanac(_) => "almanac",
        workload_spec::Workload::StaticAsset(_) => "static-asset",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset_journal::AssetStatusJournal;
    use crate::{MirrorConfig, MirrorShape, ServiceComponent, ServiceConfig};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tempfile::tempdir;
    use workload_spec::{AssetEntry, BlakeHash};

    const HASH_64: &str = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    /// Minimal test fixture that mirrors the mesofact_static test pattern.
    struct Fixture {
        _workspace: tempfile::TempDir,
        workspace_root: PathBuf,
        service: ServiceConfig,
        component: ServiceComponent,
        mirror: MirrorConfig,
        env: String,
    }

    impl Fixture {
        fn new(slot: MirrorProviderSlot) -> Self {
            let workspace = tempdir().unwrap();
            let workspace_root = workspace.path().to_path_buf();
            let workload_dir = workspace_root.join("app/assets/whisper");
            std::fs::create_dir_all(&workload_dir).unwrap();

            let mut providers = BTreeMap::new();
            providers.insert("object_store".to_string(), slot);
            let mirror = MirrorConfig {
                schema_version: 1,
                shape: MirrorShape::Local,
                providers,
                asset_aliases: BTreeMap::new(),
            };
            let service = ServiceConfig {
                schema_version: 1,
                name: "yah-desktop".to_string(),
                domain: "releases.yah.dev".to_string(),
                components: vec![],
                db: crate::DbCatalog::default(),
            };
            let component = ServiceComponent {
                id: "whisper-models".to_string(),
                kind: "static-asset".to_string(),
                path: "app/assets/whisper".to_string(),
                role: "assets".to_string(),
                publishes: None,
                wave: 0,
                git: None,
            };
            Self {
                _workspace: workspace,
                workspace_root,
                service,
                component,
                mirror,
                env: "pond".to_string(),
            }
        }

        fn ctx(&self) -> ReconcileCtx<'_> {
            ReconcileCtx {
                workspace_root: &self.workspace_root,
                service: &self.service,
                component: &self.component,
                mirror: &self.mirror,
                env: &self.env,
                scope: crate::reconciler::ProviderScope::singleton(),
            }
        }

        fn workload_dir(&self) -> PathBuf {
            self.workspace_root.join("app/assets/whisper")
        }

        fn write_workload(&self, extra: &str) {
            // R546-B7: emit the FLAT shape every real on-disk workload.toml uses
            // (`kind = "static-asset"` beside `schema_version`), not the
            // externally-tagged `[static-asset]` wrapper. The old fixture encoded
            // the `workload_spec::Workload` enum's (untagged) representation,
            // which NO real file has ever used — so these tests were asserting a
            // shape that could not occur in production and masked the fact that
            // `yah cloud apply` could not parse any actual catalog.
            let toml = format!(
                r#"schema_version = "V1"
kind = "static-asset"
{extra}
"#
            );
            std::fs::write(self.workload_dir().join("workload.toml"), toml).unwrap();
        }

        fn write_source_file(&self, name: &str, content: &[u8]) -> PathBuf {
            let path = self.workload_dir().join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, content).unwrap();
            path
        }
    }

    fn minio_slot() -> MirrorProviderSlot {
        let mut fields = BTreeMap::new();
        fields.insert("api_port".to_string(), toml::Value::Integer(9000));
        fields.insert(
            "bucket".to_string(),
            toml::Value::String("yah-dev".to_string()),
        );
        MirrorProviderSlot::Inline {
            kind: Provider::MinioContainer,
            fields,
        }
    }

    /// Default executor for tests that don't exercise transforms — legacy
    /// `source = "..."` assets never touch the executor, so any impl works.
    fn test_executor() -> Arc<dyn ForgeExecutor> {
        Arc::new(LocalForgeDriver::default())
    }

    // ── Mock executor for W164 materialize-transform tests ────────────────────

    use velveteen_exec::executor::{ExecEvent, ExecOutcome, ForgeExecutorError};
    use velveteen::ForgeStatus;
    use tokio::sync::mpsc::UnboundedSender;
    use tokio::sync::Mutex;

    /// Executor that writes a caller-supplied byte string to whatever path the
    /// recipe sets `YAH_TRANSFORM_OUT` to (via the substituted argv). Returns
    /// success unless `fail_with` is set. Tracks invocation count for HIT/MISS
    /// assertions.
    struct MockExecutor {
        out_bytes: Vec<u8>,
        invocations: Arc<Mutex<u32>>,
        fail_with: Option<String>,
    }

    impl MockExecutor {
        fn new(out_bytes: Vec<u8>) -> (Arc<Self>, Arc<Mutex<u32>>) {
            let counter = Arc::new(Mutex::new(0));
            let me = Arc::new(Self {
                out_bytes,
                invocations: counter.clone(),
                fail_with: None,
            });
            (me, counter)
        }

        fn failing(reason: String) -> Arc<Self> {
            Arc::new(Self {
                out_bytes: Vec::new(),
                invocations: Arc::new(Mutex::new(0)),
                fail_with: Some(reason),
            })
        }
    }

    #[async_trait]
    impl ForgeExecutor for MockExecutor {
        async fn execute(
            &self,
            spec: ForgeSpec,
            _ctx: ExecContext,
            _sink: Option<UnboundedSender<ExecEvent>>,
        ) -> Result<ExecOutcome, ForgeExecutorError> {
            *self.invocations.lock().await += 1;
            if let Some(reason) = &self.fail_with {
                return Ok(ExecOutcome {
                    status: ForgeStatus::Done {
                        exit_code: 1,
                        ended_at: 0,
                    },
                    stderr_tail: reason.clone(),
                });
            }
            // Find the YAH_TRANSFORM_OUT path in the substituted argv. The
            // recipe convention is that {{YAH_TRANSFORM_OUT}} resolves to the
            // tmp path we want to write to; it appears as a positional arg.
            let ForgeCommand::Subprocess { argv, .. } = &spec.command else {
                return Err(ForgeExecutorError::Unsupported(
                    "mock only handles Subprocess",
                ));
            };
            // The test recipes follow the W164 convention: argv contains the
            // tmp output path verbatim. materialize_transform writes to
            // `<cache_dir>/<output_blake3>.tmp` (then renames to .bin on hash
            // match), so the output element is the one ending in `.tmp`.
            let out_path = argv.iter().find(|a| a.ends_with(".tmp")).ok_or(
                ForgeExecutorError::Unsupported("mock recipe must pass a .tmp output path"),
            )?;
            std::fs::write(out_path, &self.out_bytes).map_err(ForgeExecutorError::Io)?;
            Ok(ExecOutcome {
                status: ForgeStatus::Done {
                    exit_code: 0,
                    ended_at: 0,
                },
                stderr_tail: String::new(),
            })
        }
    }

    /// Write a `whisper-quantize.toml`-style recipe under
    /// `<workspace>/.yah/qed/transforms/<name>.toml`. Returns nothing — the
    /// recipe loader resolves the path itself.
    fn write_recipe(workspace_root: &Path, name: &str) {
        let transforms_dir = workspace_root.join(".yah/qed/transforms");
        std::fs::create_dir_all(&transforms_dir).unwrap();
        let toml = format!(
            r#"
name  = "{name}"
label = "test recipe"
image = "ghcr.io/test/tool:v1@sha256:{HASH_64}"

[placement]
location = "local"
runtime  = "container"

[[steps]]
name = "transform"
argv = ["./tool", "{{{{YAH_TRANSFORM_IN_0}}}}", "{{{{YAH_TRANSFORM_OUT}}}}"]
"#
        );
        std::fs::write(transforms_dir.join(format!("{name}.toml")), toml).unwrap();
    }

    /// Like [`write_recipe`] but with a caller-chosen container digest, so a
    /// test can simulate a digest bump (which must invalidate the W212 action
    /// cache and force a re-run).
    fn write_recipe_with_digest(workspace_root: &Path, name: &str, digest: &str) {
        let transforms_dir = workspace_root.join(".yah/qed/transforms");
        std::fs::create_dir_all(&transforms_dir).unwrap();
        let toml = format!(
            r#"
name  = "{name}"
label = "test recipe"
image = "ghcr.io/test/tool:v1@sha256:{digest}"

[placement]
location = "local"
runtime  = "container"

[[steps]]
name = "transform"
argv = ["./tool", "{{{{YAH_TRANSFORM_IN_0}}}}", "{{{{YAH_TRANSFORM_OUT}}}}"]
"#
        );
        std::fs::write(transforms_dir.join(format!("{name}.toml")), toml).unwrap();
    }

    // ── Slot validation ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn up_bails_when_object_store_slot_missing() {
        let mut fx = Fixture::new(minio_slot());
        fx.mirror.providers.clear();
        fx.write_workload("");
        let err = StaticAssetReconciler::new().up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("providers.object_store"), "got: {msg}");
    }

    #[tokio::test]
    async fn up_bails_on_unsupported_inline_slot_kind() {
        let slot = MirrorProviderSlot::Inline {
            kind: Provider::LocalStatic,
            fields: BTreeMap::new(),
        };
        let fx = Fixture::new(slot);
        fx.write_workload("");
        let err = StaticAssetReconciler::new().up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("minio-container"), "got: {msg}");
    }

    #[tokio::test]
    async fn up_bails_on_unsupported_reference_provider() {
        let slot = MirrorProviderSlot::Reference {
            provider_id: "hetzner".to_string(),
            fields: BTreeMap::new(),
        };
        let fx = Fixture::new(slot);
        fx.write_workload("");
        // Declare a real non-cloudflare provider so dispatch resolves it and
        // reaches the kind check (the new dispatch keys on kind, not name).
        let providers_dir = fx.workspace_root.join(".yah/infra/providers");
        std::fs::create_dir_all(&providers_dir).unwrap();
        std::fs::write(
            providers_dir.join("hetzner.toml"),
            "schema_version = 1\nid = \"hetzner\"\nkind = \"hetzner\"\naccount_id = \"x\"\n",
        )
        .unwrap();
        let err = StaticAssetReconciler::new().up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cloudflare-kind"), "got: {msg}");
    }

    #[tokio::test]
    async fn up_bails_when_workload_toml_missing() {
        let fx = Fixture::new(minio_slot());
        // No workload.toml written.
        let err = StaticAssetReconciler::new().up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("workload.toml"), "got: {msg}");
    }

    #[tokio::test]
    async fn up_bails_when_catalog_alias_orphaned() {
        // Alias points at a filename not in the catalog — shape_static_asset rejects it.
        let fx = Fixture::new(minio_slot());
        fx.write_workload(
            r#"[aliases]
"default" = "nonexistent/file.bin"
"#,
        );
        let err = StaticAssetReconciler::new().up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("closed-catalog") || msg.contains("aliases"),
            "got: {msg}"
        );
    }

    // ── BLAKE3 verification ───────────────────────────────────────────────────

    #[test]
    fn blake3_mismatch_detected() {
        let body = b"hello world";
        let actual = blake3_hex(body);
        // Fabricate a hash that's wrong.
        let wrong = HASH_64;
        assert!(!hashes_equal(&actual, wrong));
    }

    #[test]
    fn blake3_match_is_case_insensitive() {
        let body = b"hello world";
        let lower = blake3_hex(body);
        let upper = lower.to_uppercase();
        assert!(hashes_equal(&lower, &upper));
    }

    #[test]
    fn sha256_hex_is_64_chars() {
        let h = sha256_hex(b"test");
        assert_eq!(h.len(), 64);
    }

    /// Core scenario: source file whose BLAKE3 matches the declared hash should
    /// be identified as upload-ready (no mismatch). Tests the in-memory path
    /// without hitting any S3 endpoint.
    #[test]
    fn matching_blake3_produces_no_mismatch_entry() {
        let body = b"real model weights here";
        let real_hash = blake3_hex(body);
        // Simulate what the reconciler checks.
        let stored = BlakeHash(real_hash.clone());
        assert!(hashes_equal(&real_hash, &stored.0));
    }

    #[tokio::test]
    async fn blake3_mismatch_on_source_file_is_caught() {
        let fx = Fixture::new(minio_slot());
        let body = b"real model content";
        let real_hash = blake3_hex(body);
        // Write a workload that declares the correct hash but we'll give it
        // a different file content to verify the check fires before any network.
        let wrong_content = b"tampered content";
        fx.write_source_file("model.bin", wrong_content);
        let wrong_hash_for_real = blake3_hex(wrong_content);
        // Sanity: the wrong content should produce a different hash.
        assert_ne!(real_hash, wrong_hash_for_real);

        let workload = StaticAssetWorkload {
            schema_version: workload_spec::SchemaVersion::V1,
            assets: vec![AssetEntry {
                filename: "model.bin".to_string(),
                source: Some("model.bin".into()),
                derive: None,
                blake3: BlakeHash(real_hash),
            }],
            aliases: BTreeMap::new(),
        };

        // Drive the sync with a non-existent MinIO so it would fail on network
        // if it ever got past the BLAKE3 check.
        let client = reqwest::Client::new();
        let journal = AssetStatusJournal::new(fx.workspace_root.join(".yah/cloud/status.jsonl"));
        let report = sync_assets(
            &workload,
            &fx.workspace_root,
            &fx.workload_dir(),
            &client,
            "http://127.0.0.1:19999", // unreachable
            "test-bucket",
            MINIO_REGION,
            "user",
            "pass",
            test_executor(),
            "test-service",
            &journal,
        )
        .await
        .unwrap();

        assert_eq!(report.hash_mismatch, vec!["model.bin"]);
        assert!(report.uploaded.is_empty());
    }

    #[tokio::test]
    async fn correct_blake3_proceeds_to_s3_head() {
        let fx = Fixture::new(minio_slot());
        let body = b"correct content";
        let hash = blake3_hex(body);
        fx.write_source_file("model.bin", body);

        let workload = StaticAssetWorkload {
            schema_version: workload_spec::SchemaVersion::V1,
            assets: vec![AssetEntry {
                filename: "model.bin".to_string(),
                source: Some("model.bin".into()),
                derive: None,
                blake3: BlakeHash(hash),
            }],
            aliases: BTreeMap::new(),
        };

        // BLAKE3 passes → reconciler proceeds to HEAD the S3 endpoint.
        // The unreachable endpoint causes a network error (not a BLAKE3 error).
        let client = reqwest::Client::new();
        let journal = AssetStatusJournal::new(fx.workspace_root.join(".yah/cloud/status.jsonl"));
        let err = sync_assets(
            &workload,
            &fx.workspace_root,
            &fx.workload_dir(),
            &client,
            "http://127.0.0.1:19999", // unreachable
            "test-bucket",
            MINIO_REGION,
            "user",
            "pass",
            test_executor(),
            "test-service",
            &journal,
        )
        .await
        .unwrap_err();

        // Error must be about network, not BLAKE3.
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("BLAKE3") && !msg.contains("mismatch"),
            "should fail at network, not BLAKE3; got: {msg}"
        );
    }

    // ── Catalog manifest ──────────────────────────────────────────────────────

    #[test]
    fn catalog_manifest_roundtrip() {
        let mut m = CatalogManifest::new();
        m.insert("whisper/model-v1.bin".to_string(), HASH_64.to_string());
        let json = serde_json::to_vec(&m).unwrap();
        let m2: CatalogManifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(m, m2);
    }

    // ── R546-B10: publish-skip must be content-aware, not existence-aware ─────

    /// The defect this encodes: an object that EXISTS is not evidence that the
    /// object holds the bytes we are about to publish. Skipping the PUT on mere
    /// existence left stale bytes in the bucket while the catalog manifest
    /// advertised the new hash — the published catalog described bytes that were
    /// never uploaded (real incident: rusty-v8 aarch64, bucket held d322b4a1
    /// while the manifest claimed ebdd842d).
    #[test]
    fn remote_object_matches_only_on_identical_content() {
        let expected = "a".repeat(64);
        let other = "b".repeat(64);

        // Same bytes → genuine no-op, safe to skip the PUT.
        assert!(RemoteObject::Present { blake3: Some(expected.clone()) }.matches(&expected));

        // Different bytes → MUST NOT be treated as synced. This is the bug.
        assert!(!RemoteObject::Present { blake3: Some(other) }.matches(&expected));

        // Absent → nothing to match.
        assert!(!RemoteObject::Absent.matches(&expected));
        assert!(!RemoteObject::Absent.exists());
    }

    /// A legacy object written before we stamped `x-amz-meta-blake3` has
    /// unknowable content. It must NOT count as a match — otherwise every
    /// pre-existing object keeps its old bytes forever. It re-PUTs once, which
    /// installs the stamp and restores the cheap skip on subsequent runs.
    #[test]
    fn unstamped_remote_object_is_not_a_match_but_does_exist() {
        let expected = "c".repeat(64);
        let legacy = RemoteObject::Present { blake3: None };
        assert!(!legacy.matches(&expected), "unstamped object must not be trusted as current");
        assert!(legacy.exists(), "it does exist — caller re-publishes rather than treating as absent");
    }

    /// Hashes may have been authored in either case; comparison goes through
    /// `hashes_equal`, so an uppercase stamp must still match.
    #[test]
    fn remote_object_match_is_case_insensitive() {
        let lower = "abcdef".repeat(10) + "abcd";
        let upper = lower.to_uppercase();
        assert_eq!(lower.len(), 64);
        assert!(RemoteObject::Present { blake3: Some(upper) }.matches(&lower));
    }

    // ── Prune candidate detection ─────────────────────────────────────────────

    #[tokio::test]
    async fn prune_candidate_from_prior_manifest() {
        let fx = Fixture::new(minio_slot());
        let body = b"current content";
        let hash = blake3_hex(body);
        fx.write_source_file("current.bin", body);

        // Workload only has "current.bin"; prior manifest also had "old.bin".
        let workload = StaticAssetWorkload {
            schema_version: workload_spec::SchemaVersion::V1,
            assets: vec![AssetEntry {
                filename: "current.bin".to_string(),
                source: Some("current.bin".into()),
                derive: None,
                blake3: BlakeHash(hash),
            }],
            aliases: BTreeMap::new(),
        };

        // We can't inject a prior manifest without a real/mock server, but we
        // can verify the prune detection logic directly.
        let current_filenames: std::collections::HashSet<&str> = workload
            .assets
            .iter()
            .map(|a| a.filename.as_str())
            .collect();
        let prior: CatalogManifest = [("old.bin".to_string(), HASH_64.to_string())]
            .into_iter()
            .collect();

        let prune: Vec<_> = prior
            .keys()
            .filter(|k| !current_filenames.contains(k.as_str()))
            .cloned()
            .collect();
        assert_eq!(prune, vec!["old.bin"]);
    }

    // ── W164 materialize step (R438-T15) ──────────────────────────────────────

    use workload_spec::{AssetDerive, FetchSource, License, TransformSpec};

    /// Helper: build an `AssetEntry` whose `source` is already on disk —
    /// the legacy arm of `materialize_asset` should return the disk path
    /// verbatim without ever consulting `derive`/cache/executor.
    fn legacy_entry(filename: &str, source_rel: &str, hash: &str) -> AssetEntry {
        AssetEntry {
            filename: filename.to_string(),
            source: Some(source_rel.into()),
            derive: None,
            blake3: BlakeHash(hash.to_string()),
        }
    }

    #[tokio::test]
    async fn materialize_legacy_source_returns_workload_dir_path() {
        let fx = Fixture::new(minio_slot());
        let body = b"on-disk bytes";
        fx.write_source_file("model.bin", body);
        let entry = legacy_entry("model.bin", "model.bin", &blake3_hex(body));

        let materialized = materialize_asset(
            &entry,
            &fx.workspace_root,
            &fx.workload_dir(),
            test_executor().as_ref(),
        )
        .await
        .expect("legacy materialize must succeed");

        assert_eq!(materialized.path, fx.workload_dir().join("model.bin"));
        assert!(
            materialized.discovered_fetch_hash.is_none(),
            "legacy source mode has no fetch step → never bootstrap-discovers"
        );
    }

    #[tokio::test]
    async fn materialize_fetch_cache_miss_then_hit() {
        let fx = Fixture::new(minio_slot());
        let body = b"upstream bytes";
        let hash = blake3_hex(body);

        // Server returns the body once; second call would 500 if hit.
        use axum::routing::get;
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter_c = counter.clone();
        let body_c = body.to_vec();
        let app = axum::Router::new().route(
            "/blob.bin",
            get(move || {
                let counter = counter_c.clone();
                let body = body_c.clone();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    body
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let fetch = FetchSource {
            url: format!("http://{addr}/blob.bin"),
            blake3: BlakeHash(hash.clone()),
            license: License::Mit,
        };
        let cache_dir = fx.workspace_root.join(".yah/cache/derive/fetch");

        // MISS — fetch + write to cache.
        let (p1, h1) = materialize_fetch(&fetch, &cache_dir).await.unwrap();
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(p1.exists(), "cache file must exist after MISS");
        assert_eq!(h1, hash, "strict mode returns the pinned hash");

        // HIT — no second HTTP call.
        let (p2, h2) = materialize_fetch(&fetch, &cache_dir).await.unwrap();
        assert_eq!(p1, p2);
        assert_eq!(h1, h2, "HIT returns the same hash");
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "cache HIT must not re-fetch"
        );
    }

    #[tokio::test]
    async fn materialize_fetch_blake3_mismatch_is_hard_error() {
        let fx = Fixture::new(minio_slot());
        let actual_body = b"real bytes";
        let actual_hash = blake3_hex(actual_body);
        let pinned_hash = HASH_64; // deliberately wrong
        assert_ne!(actual_hash, pinned_hash);

        use axum::routing::get;
        let body_c = actual_body.to_vec();
        let app = axum::Router::new().route(
            "/blob.bin",
            get(move || {
                let body = body_c.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let fetch = FetchSource {
            url: format!("http://{addr}/blob.bin"),
            blake3: BlakeHash(pinned_hash.to_string()),
            license: License::Mit,
        };
        let err = materialize_fetch(&fetch, &fx.workspace_root.join(".yah/cache/derive/fetch"))
            .await
            .expect_err("BLAKE3 mismatch must surface as hard error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("BLAKE3") || msg.contains(&actual_hash),
            "got: {msg}"
        );
        assert!(msg.contains(pinned_hash), "diff must mention pin: {msg}");
    }

    #[tokio::test]
    async fn materialize_fetch_retries_on_server_error() {
        // First request returns 500 (transient); second returns 200 with the body.
        // Verifies exponential-backoff retry (W164 OQ#4, R438-F11).
        use axum::http::StatusCode;
        use axum::routing::get;

        let fx = Fixture::new(minio_slot());
        let body: Vec<u8> = b"retry-me bytes".to_vec();
        let hash = blake3_hex(&body);

        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter_c = counter.clone();
        let body_c = body.clone();
        let app = axum::Router::new().route(
            "/blob.bin",
            get(move || {
                let n = counter_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let body = body_c.clone();
                async move {
                    if n == 0 {
                        (StatusCode::INTERNAL_SERVER_ERROR, vec![])
                    } else {
                        (StatusCode::OK, body)
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let fetch = FetchSource {
            url: format!("http://{addr}/blob.bin"),
            blake3: BlakeHash(hash.clone()),
            license: License::Mit,
        };
        let cache_dir = fx.workspace_root.join(".yah/cache/derive/fetch");
        let (path, _hash) = materialize_fetch(&fetch, &cache_dir).await.unwrap();
        assert!(
            path.exists(),
            "cache file must exist after successful retry"
        );
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "exactly two attempts: one 500 + one 200"
        );
        assert_eq!(tokio::fs::read(&path).await.unwrap(), body);
    }

    #[tokio::test]
    async fn materialize_fetch_resumes_via_range_header() {
        // Pre-populate the partial file with the first half of the blob. The
        // server should receive a Range header and return 206 + the second half.
        // Verifies Range-resume logic (W164 OQ#4, R438-F11).
        use axum::body::Body;
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::get;

        let fx = Fixture::new(minio_slot());
        let body: Vec<u8> = (0u8..100u8).collect();
        let half = body.len() / 2;
        let hash = blake3_hex(&body);

        // Pre-write first half to the .partial file.
        let cache_dir = fx.workspace_root.join(".yah/cache/derive/fetch");
        tokio::fs::create_dir_all(&cache_dir).await.unwrap();
        let partial_path = cache_dir.join(format!("{hash}.partial"));
        tokio::fs::write(&partial_path, &body[..half])
            .await
            .unwrap();

        let body_c = body.clone();
        let received_range: Arc<std::sync::Mutex<Option<String>>> =
            Arc::new(std::sync::Mutex::new(None));
        let received_range_c = received_range.clone();
        let app = axum::Router::new().route(
            "/blob.bin",
            get(move |headers: HeaderMap| {
                let body = body_c.clone();
                let received = received_range_c.clone();
                async move {
                    let range_hdr = headers
                        .get("range")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    *received.lock().unwrap() = range_hdr.clone();

                    let Some(range) = range_hdr else {
                        return axum::response::Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::empty())
                            .unwrap();
                    };
                    let offset: usize = range
                        .strip_prefix("bytes=")
                        .and_then(|s| s.strip_suffix('-'))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    let total = body.len();
                    axum::response::Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .header(
                            "Content-Range",
                            format!("bytes {offset}-{}/{total}", total - 1),
                        )
                        .body(Body::from(body[offset..].to_vec()))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let fetch = FetchSource {
            url: format!("http://{addr}/blob.bin"),
            blake3: BlakeHash(hash.clone()),
            license: License::Mit,
        };
        let (path, _hash) = materialize_fetch(&fetch, &cache_dir).await.unwrap();

        // Range header must carry the pre-existing partial size.
        let range = received_range.lock().unwrap().clone().unwrap();
        assert_eq!(
            range,
            format!("bytes={half}-"),
            "Range header must resume from partial offset"
        );
        // Final cache file must contain the complete body.
        assert_eq!(
            tokio::fs::read(&path).await.unwrap(),
            body,
            "cache file must contain the full blob after Range resume"
        );
    }

    #[tokio::test]
    async fn materialize_transform_cache_miss_then_hit() {
        let fx = Fixture::new(minio_slot());
        write_recipe(&fx.workspace_root, "noop-recipe");
        let out_bytes = b"transformed output".to_vec();
        let out_hash = blake3_hex(&out_bytes);
        let (mock, invocations) = MockExecutor::new(out_bytes.clone());
        let executor: Arc<dyn ForgeExecutor> = mock;

        // Pre-seed a fetch cache entry the transform reads from.
        let fetch_path = fx.workspace_root.join(".yah/cache/derive/fetch/in.bin");
        std::fs::create_dir_all(fetch_path.parent().unwrap()).unwrap();
        std::fs::write(&fetch_path, b"fetch bytes").unwrap();

        let transform = TransformSpec {
            recipe: "noop-recipe".to_string(),
            params: BTreeMap::new(),
        };
        let cache_dir = fx.workspace_root.join(".yah/cache/derive/transform");

        // MISS — runs the recipe.
        let p1 = materialize_transform(
            &transform,
            &fetch_path,
            &blake3_hex(b"fetch bytes"),
            &out_hash,
            &cache_dir,
            &fx.workspace_root,
            executor.as_ref(),
        )
        .await
        .unwrap();
        assert!(p1.exists());
        assert_eq!(*invocations.lock().await, 1);

        // HIT — recipe NOT re-run.
        let p2 = materialize_transform(
            &transform,
            &fetch_path,
            &blake3_hex(b"fetch bytes"),
            &out_hash,
            &cache_dir,
            &fx.workspace_root,
            executor.as_ref(),
        )
        .await
        .unwrap();
        assert_eq!(p1, p2);
        assert_eq!(*invocations.lock().await, 1, "cache HIT must not re-run");
    }

    /// R546-T3 qed→W164 bridge: seeding the derivation cache from a pre-built
    /// artifact makes the NEXT `materialize_transform` a HIT that returns the
    /// seeded bytes without running the recipe. This is the whole point —
    /// offload the arch-locked, expensive build to a fleet worker (P018), retrieve
    /// its tar (R590-F6), seed the cache, and let `yah cloud apply` publish the
    /// pre-built bytes instead of re-building under emulation.
    #[tokio::test]
    async fn seed_transform_derivation_makes_next_transform_a_hit() {
        let fx = Fixture::new(minio_slot());
        write_recipe(&fx.workspace_root, "noop-recipe");

        let transform = TransformSpec {
            recipe: "noop-recipe".to_string(),
            params: BTreeMap::new(),
        };
        let fetched_hash = blake3_hex(b"fetch bytes");

        // A pre-built artifact standing in for the F6-retrieved rusty_v8 tar.
        let prebuilt = fx.workspace_root.join("prebuilt.tar.gz");
        let prebuilt_bytes = b"prebuilt rusty_v8 tarball".to_vec();
        std::fs::write(&prebuilt, &prebuilt_bytes).unwrap();

        let seeded =
            seed_transform_derivation(&fx.workspace_root, &transform, &fetched_hash, &prebuilt)
                .await
                .unwrap();
        assert_eq!(seeded.output_blake3, blake3_hex(&prebuilt_bytes));
        assert!(seeded.cas_path.exists(), "CAS entry must be written");

        // A materialize_transform with the SAME inputs must HIT the seeded cache:
        // the executor is never invoked and the returned bytes are the seeded
        // artifact (NOT what the recipe would have produced).
        let fetch_path = fx.workspace_root.join(".yah/cache/derive/fetch/in.bin");
        std::fs::create_dir_all(fetch_path.parent().unwrap()).unwrap();
        std::fs::write(&fetch_path, b"fetch bytes").unwrap();
        let cache_dir = fx.workspace_root.join(".yah/cache/derive/transform");
        let (mock, invocations) = MockExecutor::new(b"RECIPE OUTPUT (must not appear)".to_vec());

        let out = materialize_transform(
            &transform,
            &fetch_path,
            &fetched_hash,
            &seeded.output_blake3,
            &cache_dir,
            &fx.workspace_root,
            mock.as_ref(),
        )
        .await
        .unwrap();

        assert_eq!(
            *invocations.lock().await,
            0,
            "seeded derivation cache must make the transform a HIT (no recipe run)"
        );
        assert_eq!(
            std::fs::read(&out).unwrap(),
            prebuilt_bytes,
            "HIT must return the seeded pre-built bytes",
        );
    }

    /// W212/R518: the derivation key is hermetic — every declared input
    /// dimension flips it, and identical inputs reproduce it. This is the
    /// correctness invariant that makes the silent-stale-cache bug impossible:
    /// a missing dimension would let two distinct inputs collide on one key.
    #[test]
    fn derivation_key_is_hermetic_over_every_input_dimension() {
        let input = "a".repeat(64);
        let recipe = "b".repeat(64);
        let mut params = BTreeMap::new();
        params.insert("quant".to_string(), "q5_1".to_string());

        let base = derivation_key(&input, &recipe, &params);

        // Fetched-input content (the model/version anchor) flips it.
        assert_ne!(base, derivation_key(&"c".repeat(64), &recipe, &params));
        // Recipe-file bytes (steps / pinned container digest / placement) flip it.
        assert_ne!(base, derivation_key(&input, &"d".repeat(64), &params));
        // A changed param value flips it.
        let mut p2 = params.clone();
        p2.insert("quant".to_string(), "q4_0".to_string());
        assert_ne!(base, derivation_key(&input, &recipe, &p2));
        // An added param flips it.
        let mut p3 = params.clone();
        p3.insert("extra".to_string(), "x".to_string());
        assert_ne!(base, derivation_key(&input, &recipe, &p3));
        // Identical inputs reproduce the key (deterministic, order-stable).
        assert_eq!(base, derivation_key(&input, &recipe, &params));
    }

    /// W212/R518: the action cache is keyed on INPUTS, so a recipe change (here
    /// a container-digest bump) forces a re-run even on a warm cache. This is
    /// the regression guard against the W164/R438 output-keyed silent-stale
    /// skip — the exact defect this relay fixes.
    #[tokio::test]
    async fn transform_recipe_change_busts_cache_and_reruns() {
        let fx = Fixture::new(minio_slot());
        let digest_a = HASH_64;
        let digest_b = "1".repeat(64);
        write_recipe_with_digest(&fx.workspace_root, "pinned", digest_a);

        let out_bytes = b"transformed output".to_vec();
        let out_hash = blake3_hex(&out_bytes);
        let (mock, invocations) = MockExecutor::new(out_bytes);
        let executor: Arc<dyn ForgeExecutor> = mock;

        let fetch_path = fx.workspace_root.join(".yah/cache/derive/fetch/in.bin");
        std::fs::create_dir_all(fetch_path.parent().unwrap()).unwrap();
        std::fs::write(&fetch_path, b"fetch bytes").unwrap();
        let in_hash = blake3_hex(b"fetch bytes");

        let transform = TransformSpec {
            recipe: "pinned".to_string(),
            params: BTreeMap::new(),
        };
        let cache_dir = fx.workspace_root.join(".yah/cache/derive/transform");
        let wr = &fx.workspace_root;

        // Run 1 — cold, digest A.
        materialize_transform(
            &transform,
            &fetch_path,
            &in_hash,
            &out_hash,
            &cache_dir,
            wr,
            executor.as_ref(),
        )
        .await
        .unwrap();
        assert_eq!(*invocations.lock().await, 1);

        // Re-run with the SAME recipe → warm HIT, no re-run.
        materialize_transform(
            &transform,
            &fetch_path,
            &in_hash,
            &out_hash,
            &cache_dir,
            wr,
            executor.as_ref(),
        )
        .await
        .unwrap();
        assert_eq!(*invocations.lock().await, 1, "identical inputs must skip");

        // Bump the container digest A → B. Output-keyed caching silently
        // skipped this; input-addressed caching MUST re-run.
        write_recipe_with_digest(&fx.workspace_root, "pinned", &digest_b);
        materialize_transform(
            &transform,
            &fetch_path,
            &in_hash,
            &out_hash,
            &cache_dir,
            wr,
            executor.as_ref(),
        )
        .await
        .unwrap();
        assert_eq!(
            *invocations.lock().await,
            2,
            "a digest bump must invalidate the cache and re-run",
        );
    }

    /// W212/R518-P2b: the substituter fast-path honours the committed lock —
    /// `Some(output)` when the key recomputed from the pins matches, `None` the
    /// moment any input drifts (here a recipe-digest bump).
    #[tokio::test]
    async fn lock_skip_hash_honours_committed_lock() {
        let fx = Fixture::new(minio_slot());
        write_recipe_with_digest(&fx.workspace_root, "pinned", HASH_64);

        let fetch_pin = "a".repeat(64);
        let out_pin = "b".repeat(64);
        // The lock's input_hash must equal the key the reconciler recomputes
        // from the committed pins.
        let recipe_bk = recipe_blake3(&fx.workspace_root, "pinned").await.unwrap();
        let key = derivation_key(&fetch_pin, &recipe_bk, &BTreeMap::new());

        let toml = format!(
            r#"kind = "static-asset"
schema_version = "V1"

[[asset]]
filename = "whisper/coreml.tar.gz"
blake3   = "{out_pin}"

[asset.derive.fetch]
url     = "https://example/config.json"
blake3  = "{fetch_pin}"
license = "mit"

[asset.derive.transform]
recipe = "pinned"

[asset.derive.lock]
input_hash    = "{key}"
output_blake3 = "{out_pin}"
"#
        );
        let workload: StaticAssetWorkload = toml::from_str(&toml).unwrap();
        let entry = &workload.assets[0];

        // Lock current → Some(output hash) (caller then HEADs the bucket).
        assert_eq!(
            lock_skip_hash(entry, &fx.workspace_root).await.as_deref(),
            Some(out_pin.as_str()),
        );

        // Bump the recipe digest → recipe-file hash changes → recomputed key no
        // longer matches the lock → None (must rebuild). The exact drift the
        // output-keyed cache missed.
        write_recipe_with_digest(&fx.workspace_root, "pinned", &"1".repeat(64));
        assert!(
            lock_skip_hash(entry, &fx.workspace_root).await.is_none(),
            "a stale recipe must not skip the build",
        );
    }

    /// W212/R518-P2b: a bootstrap (zero-sentinel) row never short-circuits via
    /// the lock — there is no pinned output to trust yet.
    #[tokio::test]
    async fn lock_skip_hash_declines_bootstrap_rows() {
        let fx = Fixture::new(minio_slot());
        write_recipe_with_digest(&fx.workspace_root, "pinned", HASH_64);
        let sentinel = "0".repeat(64);
        let toml = format!(
            r#"kind = "static-asset"
schema_version = "V1"

[[asset]]
filename = "whisper/coreml.tar.gz"
blake3   = "{sentinel}"

[asset.derive.fetch]
url     = "https://example/config.json"
blake3  = "{sentinel}"
license = "mit"

[asset.derive.transform]
recipe = "pinned"

[asset.derive.lock]
input_hash    = "whatever"
output_blake3 = "{sentinel}"
"#
        );
        let workload: StaticAssetWorkload = toml::from_str(&toml).unwrap();
        assert!(
            lock_skip_hash(&workload.assets[0], &fx.workspace_root)
                .await
                .is_none(),
            "bootstrap rows must always build",
        );
    }

    #[test]
    fn bootstrap_output_key_input_variant() {
        let b = BootstrappedHash {
            filename: "whisper/coreml.tar.gz".into(),
            kind: BootstrapHashKind::Input,
            hash: "deadbeef".into(),
        };
        assert_eq!(
            bootstrap_output_key(&b),
            "discovered_input_hash:whisper/coreml.tar.gz",
        );
    }

    #[tokio::test]
    async fn materialize_transform_blake3_mismatch_on_output_is_hard_error() {
        let fx = Fixture::new(minio_slot());
        write_recipe(&fx.workspace_root, "wrong-output");
        let out_bytes = b"actual output".to_vec();
        let actual_hash = blake3_hex(&out_bytes);
        let pinned_hash = HASH_64; // deliberately wrong
        assert_ne!(actual_hash, pinned_hash);
        let (mock, _) = MockExecutor::new(out_bytes);
        let executor: Arc<dyn ForgeExecutor> = mock;

        let fetch_path = fx.workspace_root.join(".yah/cache/derive/fetch/in.bin");
        std::fs::create_dir_all(fetch_path.parent().unwrap()).unwrap();
        std::fs::write(&fetch_path, b"fetch bytes").unwrap();

        let transform = TransformSpec {
            recipe: "wrong-output".to_string(),
            params: BTreeMap::new(),
        };
        let err = materialize_transform(
            &transform,
            &fetch_path,
            &blake3_hex(b"fetch bytes"),
            pinned_hash,
            &fx.workspace_root.join(".yah/cache/derive/transform"),
            &fx.workspace_root,
            executor.as_ref(),
        )
        .await
        .expect_err("transform output mismatch must surface");
        let msg = format!("{err:#}");
        assert!(msg.contains("BLAKE3"), "{msg}");
        assert!(msg.contains(pinned_hash), "{msg}");
    }

    #[tokio::test]
    async fn materialize_transform_recipe_failure_surfaces_stderr() {
        let fx = Fixture::new(minio_slot());
        write_recipe(&fx.workspace_root, "failing-recipe");
        let executor: Arc<dyn ForgeExecutor> = MockExecutor::failing("tool exploded".to_string());

        let fetch_path = fx.workspace_root.join(".yah/cache/derive/fetch/in.bin");
        std::fs::create_dir_all(fetch_path.parent().unwrap()).unwrap();
        std::fs::write(&fetch_path, b"fetch bytes").unwrap();

        let transform = TransformSpec {
            recipe: "failing-recipe".to_string(),
            params: BTreeMap::new(),
        };
        let err = materialize_transform(
            &transform,
            &fetch_path,
            &blake3_hex(b"fetch bytes"),
            HASH_64,
            &fx.workspace_root.join(".yah/cache/derive/transform"),
            &fx.workspace_root,
            executor.as_ref(),
        )
        .await
        .expect_err("failing recipe must surface");
        let msg = format!("{err:#}");
        assert!(msg.contains("failing-recipe"), "{msg}");
        assert!(msg.contains("tool exploded"), "{msg}");
    }

    #[tokio::test]
    async fn materialize_derive_fetch_only_uses_fetch_path_for_upload() {
        // No transform — materialize_asset returns the fetch cache path
        // directly. The downstream BLAKE3 verify happens in sync_assets.
        let fx = Fixture::new(minio_slot());
        let body = b"weights v1";
        let hash = blake3_hex(body);

        use axum::routing::get;
        let body_c = body.to_vec();
        let app = axum::Router::new().route(
            "/w.bin",
            get(move || {
                let body = body_c.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let entry = AssetEntry {
            filename: "w.bin".to_string(),
            source: None,
            derive: Some(AssetDerive {
                fetch: FetchSource {
                    url: format!("http://{addr}/w.bin"),
                    blake3: BlakeHash(hash.clone()),
                    license: License::Mit,
                },
                transform: None,
                lock: None,
            }),
            blake3: BlakeHash(hash.clone()),
        };
        let materialized = materialize_asset(
            &entry,
            &fx.workspace_root,
            &fx.workload_dir(),
            test_executor().as_ref(),
        )
        .await
        .expect("fetch-only materialize");
        assert!(materialized
            .path
            .to_string_lossy()
            .contains(".yah/cache/derive/fetch/"));
        assert_eq!(std::fs::read(&materialized.path).unwrap(), body);
        assert!(
            materialized.discovered_fetch_hash.is_none(),
            "strict mode: pinned fetch.blake3 → no discovery"
        );
    }

    #[tokio::test]
    async fn materialize_fetch_bootstrap_sentinel_accepts_actual_hash() {
        // fetch.blake3 ships as the zero sentinel; reconciler accepts the
        // computed hash and names the cache by the discovered value.
        let fx = Fixture::new(minio_slot());
        let body = b"discovered-upstream";
        let actual_hash = blake3_hex(body);

        use axum::routing::get;
        let body_c = body.to_vec();
        let app = axum::Router::new().route(
            "/blob.bin",
            get(move || {
                let body = body_c.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let fetch = FetchSource {
            url: format!("http://{addr}/blob.bin"),
            blake3: BlakeHash(ZERO_SENTINEL_HEX.to_string()),
            license: License::Mit,
        };
        let cache_dir = fx.workspace_root.join(".yah/cache/derive/fetch");
        let (path, discovered) = materialize_fetch(&fetch, &cache_dir).await.unwrap();
        assert!(path.exists(), "cache file must exist after bootstrap fetch");
        assert_eq!(
            discovered, actual_hash,
            "discovered hash = actual content hash"
        );
        assert!(
            path.file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with(&actual_hash))
                .unwrap_or(false),
            "bootstrap mode names cache by discovered hash, got {path:?}",
        );
    }

    #[tokio::test]
    async fn materialize_derive_fetch_bootstrap_surfaces_discovered_hash() {
        // End-to-end: AssetEntry with sentinel fetch.blake3 → materialize_asset
        // populates discovered_fetch_hash so sync_assets can surface it.
        let fx = Fixture::new(minio_slot());
        let body = b"upstream-bytes";
        let actual_hash = blake3_hex(body);

        use axum::routing::get;
        let body_c = body.to_vec();
        let app = axum::Router::new().route(
            "/w.bin",
            get(move || {
                let body = body_c.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let entry = AssetEntry {
            filename: "w.bin".to_string(),
            source: None,
            derive: Some(AssetDerive {
                fetch: FetchSource {
                    url: format!("http://{addr}/w.bin"),
                    blake3: BlakeHash(ZERO_SENTINEL_HEX.to_string()),
                    license: License::Mit,
                },
                transform: None,
                lock: None,
            }),
            // entry.blake3 still sentinel — upload-side verify in sync_assets
            // handles the output-hash discovery; here we only assert the
            // fetch-side discovery threads up correctly.
            blake3: BlakeHash(ZERO_SENTINEL_HEX.to_string()),
        };
        let materialized = materialize_asset(
            &entry,
            &fx.workspace_root,
            &fx.workload_dir(),
            test_executor().as_ref(),
        )
        .await
        .expect("bootstrap materialize");
        assert_eq!(
            materialized.discovered_fetch_hash.as_deref(),
            Some(actual_hash.as_str()),
            "fetch.blake3 sentinel → discovered hash returned",
        );
    }

    /// W209/F4: discovered hashes write to `$YAH_OUTPUTS` with one line per
    /// (kind, filename) pair so the QED runner can route them through
    /// OutputMap into pipeline binds. Key shape encodes the filename so
    /// multi-asset workloads round-trip; the value is the raw blake3 hex.
    #[test]
    fn bootstrap_outputs_format_round_trip() {
        let dir = tempdir().unwrap();
        let outputs = dir.path().join("outputs");
        let bootstrapped = vec![
            BootstrappedHash {
                filename: "yah-desktop/whisper/distil-large-v3-coreml.tar.gz".to_string(),
                kind: BootstrapHashKind::Output,
                hash: "fb0afc9f3d966f5347c6dfd335adab12f1dc8ee6df18cf9e9ff90fe86f0416c0"
                    .to_string(),
            },
            BootstrappedHash {
                filename: "yah-desktop/whisper/distil-large-v3-coreml.tar.gz".to_string(),
                kind: BootstrapHashKind::Fetch,
                hash: "050ffe562134208781dc316181b146a725821fff005fb4ffb6de2a6ada334a9b"
                    .to_string(),
            },
        ];
        append_bootstrap_outputs(&outputs, &bootstrapped).expect("write outputs");
        let content = std::fs::read_to_string(&outputs).expect("read outputs");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "one line per discovery");
        assert!(
            lines.contains(
                &"discovered_asset_blake3:yah-desktop/whisper/distil-large-v3-coreml.tar.gz=\
                  fb0afc9f3d966f5347c6dfd335adab12f1dc8ee6df18cf9e9ff90fe86f0416c0"
            ),
            "asset output key encodes filename: {content:?}",
        );
        assert!(
            lines.contains(
                &"discovered_fetch_blake3:yah-desktop/whisper/distil-large-v3-coreml.tar.gz=\
                  050ffe562134208781dc316181b146a725821fff005fb4ffb6de2a6ada334a9b"
            ),
            "fetch output key encodes filename: {content:?}",
        );
    }

    /// Append, not truncate: a step that materializes N assets and emits
    /// other outputs in the same step must not clobber what's already in
    /// the file.
    #[test]
    fn bootstrap_outputs_append_preserves_prior_lines() {
        let dir = tempdir().unwrap();
        let outputs = dir.path().join("outputs");
        std::fs::write(&outputs, "prior_key=prior_value\n").unwrap();
        let bootstrapped = vec![BootstrappedHash {
            filename: "a.bin".to_string(),
            kind: BootstrapHashKind::Output,
            hash: HASH_64.to_string(),
        }];
        append_bootstrap_outputs(&outputs, &bootstrapped).expect("append");
        let content = std::fs::read_to_string(&outputs).expect("read");
        assert!(content.starts_with("prior_key=prior_value\n"), "prior kept");
        assert!(
            content.contains(&format!("discovered_asset_blake3:a.bin={HASH_64}")),
            "new line appended: {content:?}",
        );
    }
}
