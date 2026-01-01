//! @yah:ticket(R438-F10, "Almanac ReleaseSource: adopt shared FetchSource + License")
//! @yah:at(2026-06-04T21:08:01Z)
//! @yah:status(review)
//! @yah:parent(R438)
//! @yah:next("Migrate ReleaseSource impls (GhReleases, R2Channel) to use FetchSource for url + blake3 + license")
//! @yah:next("License is Option<License> here (release manifests often have no distribution license per se)")
//! @yah:next("One license validator across asset.derive.fetch (required) and almanac (optional)")
//! @yah:verify("Existing almanac feeds round-trip through new FetchSource shape with no behavior change")
//! @arch:see(.yah/docs/working/W164-derived-static-assets.md)
//! @yah:depends_on(R438-T1)
//! @yah:handoff("ReleaseAsset.sha256: Option<String> replaced with blake3: Option<BlakeHash> + license: Option<License> (both from workload-spec). workload-spec added as almanac dep. Both fields skip_serializing_if=None so wire format unchanged for GhReleases/R2Channel (which both set None). License uses same closed-set enum as asset.derive.fetch — non-permissive rejected at deserialize. 4 new tests in feed::tests: round-trip without optionals, round-trip with blake3+license, license_rejects_non_permissive, release_feed_round_trips. 26/26 pass (22+4).")
//!
//! @yah:ticket(R443-S5, "OQ1 spike: verify turso multi-process read-only file open")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-05T02:37:26Z)
//! @yah:kind(spike)
//! @yah:status(review)
//! @yah:parent(R443)
//! @yah:handoff("VERDICT: D5 breaks. turso 0.6.1 takes an exclusive file lock for the lifetime of any open `Database` handle. Six scenarios in external/db_test/harness/src/bin/multi_proc_spike.rs, all consistent on macOS 14: any second-process opener (turso OR vanilla sqlite3) gets SQLITE_BUSY / `Locking error: Failed locking file '...spike.db-wal'. File is locked by another process`. Tested: writer idle, writer in autocommit insert loop, writer mid-BEGIN-no-COMMIT, writer just-dropped (lock still held — drop within a process doesn't release until process exit), writer with experimental_multiprocess_wal=true (same lock), and a control scenario where a short-writer subproc exits cleanly then a reader succeeds (proves the .db format is fine; only the held lock blocks).")
//! @yah:handoff("Three side findings: (1) `experimental_multiprocess_wal=true` does NOT help — same exclusive lock semantics. (2) Drop within the same process does NOT release the lock — process exit appears required. spike.db-wal stays on disk after `drop(conn) + drop(db) + sleep 500ms`. (3) The lock applies to `.db-wal` specifically — the spike's error message names `spike.db-wal`, not `spike.db`.")
//! @yah:handoff("Architecture impact: W179 D5 (almanac opens the same .db read-only via the turso crate) is dead. Two viable paths documented in W179 § Findings → OQ1: (D5'-A, preferred) almanac collapses into the issue-tracker process — IssuesSource becomes a library call on Arc<IssueStore>; one binary, two roles. (D5'-B) almanac stays a separate process and reads issues via `GET /issues` HTTP from issue-tracker — D7 already requires issue-tracker to be HTTP-shaped, so the surface delta is small. Recommend A unless deployment topology argues otherwise. Updates T6 (almanac IssuesSource shape) + F7 (issue-tracker crate layout); F8 is mostly unchanged either way.")
//! @yah:verify("cd external/db_test/harness && cargo run --bin multi_proc_spike — reproduces all six scenarios + emits 'VERDICT: D5 breaks — collapse almanac IssuesSource into the issue-tracker process'")
//! @yah:next("User: decide D5'-A vs D5'-B. A is preferred per the 'library deps over process deps' rule; B is cheaper to ship and keeps the two services independently deployable. Either way, R443-T6 + R443-F7 need re-shaping before claiming.")
//! @yah:next("On A: T6 turns into 'almanac IssuesSource as in-process library call'; F7 adds an 'embed almanac feed loop' axis. F8 (TOML + E2E) stays largely as-is.")
//! @yah:next("On B: T6 turns into 'almanac IssuesSource = HTTP GET /issues'; F7 adds GET /issues to its HTTP surface alongside POST /issues. Auth concern (OQ4) escalates from optional to load-bearing.")
//! @yah:gotcha("Side finding #2 above (drop doesn't release the lock until process exit) is unrelated to OQ1 but worth knowing: if issue-tracker ever wants to hand its DB to another in-process role without restarting, it can't. Not a problem for the current architecture, but flag for any future multi-tenant-per-process plan.")
//! @yah:gotcha("Tested with turso 0.6.1 against macOS 14 (Darwin 25.5.0). Behavior may differ on Linux — fcntl locking semantics are POSIX but the WAL lock path goes through turso_core's IO layer which has platform-specific code. Worth re-running the spike on Linux before locking in D5'-A/B definitively if production is Linux-first.")
//! @yah:gotcha("external/db_test's harness/writer.rs drops the write connection BEFORE snapshot — they avoid the multi-process question entirely. We can't, because almanac reads on a different schedule than issue-tracker writes. (Kept from the original spike framing; finding above proves the assumption.)")
//! @arch:see(.yah/docs/working/W179-issues-feed-turso-derisk.md)
//!
//! @yah:ticket(R443-T6, "Almanac: IssuesSource trait + IssuesFeed::run loop (in-process, no file open)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-05T02:37:39Z)
//! @yah:status(review)
//! @yah:parent(R443)
//! @yah:next("Add IssuesFeed { fetched_at, items: Vec<Issue> } + Issue { id, title, body, kind, created_at } in a new crates/yah/almanac/src/issues_feed.rs. Field name is 'items' (NOT 'issues') to match the mesofact prerender.from_data convention that R443-F2 already shipped — mesofact-build expects items_key='items'.")
//! @yah:next("Add IssuesSource trait in crates/yah/almanac/src/issues_source.rs — `async fn list(&self) -> Result<Vec<Issue>, SourceError>`. NO turso/file-path impl in this crate; the impl is owned by issue-tracker (F7), which wraps its in-process IssueStore. Almanac stays storage-agnostic.")
//! @yah:next("Add IssuesFeed::run(source: Arc<dyn IssuesSource>, sink: ArtifactSink, on_change: OnChange, trigger: mpsc::Receiver<RevalidateRequest>) — tokio task that awaits a trigger, calls source.list(), writes the sink (JSON file), fires on_change (mesofact-rebuild webhook). Same on_change pipeline as the release feed.")
//! @yah:next("Drop the SourceConfig::Issues TOML variant from the previous draft — issue-tracker constructs the store + source at bootstrap, almanac is a library called directly. TOML now wires only sink + on_change (see W179 D8).")
//! @yah:next("Tests: a MockIssuesSource (no turso) feeds the loop. Drive a triggered tick → assert artifact written + on_change fired. Drive an empty source → empty items[] in JSON. Source error → loop logs + retries on next trigger (no panic).")
//! @yah:verify("cargo test -p almanac --lib — existing release tests unchanged; new issues_feed tests green using MockIssuesSource (zero turso dep on almanac).")
//! @yah:gotcha("F2 shipped src/data/issues.json with shape {fetched_at, items: []} — field is 'items', NOT 'issues'. Mismatch would break mesofact's prerender.from_data binding silently (empty params → no detail pages emitted) and the SSR /issues page (items.length undefined → empty-state). Pin the IssuesFeed serde field via #[serde(rename = \"items\")] if the Rust struct calls it something else.")
//! @arch:see(.yah/docs/working/W179-issues-feed-turso-derisk.md)
//! @yah:depends_on(R443-S5)
//! @yah:handoff("Shipped: IssuesSource trait + IssuesFeed::run loop. New files: issues_source.rs (IssuesSource trait — async fn list() -> Result<Vec<Issue>, SourceError>; no turso dep in almanac); issues_feed.rs (Issue, IssuesFeed{fetched_at, items:Vec<Issue>}, ArtifactSink::file(), OnChange{new/no_op/mesofact_rebuild}, RevalidateRequest, IssuesFeed::run loop). Field is 'items' not 'issues' as required. OnChange::mesofact_rebuild logs the trigger; HTTP dispatch deferred to R443-F8. IssuesFeed::run: await trigger, list(), write sink, fire on_change; source error → log+continue; write error → log+skip on_change; trigger drop → clean exit. lib.rs: two new modules + re-exports. 22/22 tests pass (18 pre-existing + 4 new IssuesFeed tests). Zero turso dep on almanac.")
//! @yah:verify("cargo test -p almanac --lib — VERIFIED 22/22 pass (18 existing release/receiver tests unchanged; 4 new: triggered_tick_writes_artifact_and_fires_on_change, empty_source_writes_empty_items_array, source_error_skips_artifact_write_and_on_change_but_no_panic, loop_ends_cleanly_when_trigger_sender_dropped)")
//! @yah:handoff("IMPLEMENTED + GREEN. crates/yah/almanac/src/issues_feed.rs has IssuesFeed { fetched_at, items: Vec<Issue> } with #[serde] field 'items' (NOT 'issues'); Issue { id, title, body: Option, kind: Option, created_at } matching mesofact prerender.from_data shape. crates/yah/almanac/src/issues_source.rs has the IssuesSource trait — storage-agnostic, no turso, no file path. IssuesFeed::run(Arc<dyn IssuesSource>, ArtifactSink, OnChange, mpsc::Receiver<RevalidateRequest>) drives the loop: await trigger → source.list() → write sink → fire on_change. Source error → log + skip tick (no write, no on_change). Write error → log + skip on_change. Trigger sender drop → loop ends cleanly, no panic. OnChange::mesofact_rebuild logs the intent — actual HTTP dispatch deferred to R443-F8.")
//! @yah:handoff("Tests (4 new in issues_feed::tests): triggered_tick_writes_artifact_and_fires_on_change (asserts 'items' field present, 'issues' absent), empty_source_writes_empty_items_array, source_error_skips_artifact_write_and_on_change_but_no_panic (verifies retry on next trigger), loop_ends_cleanly_when_trigger_sender_dropped. cargo test -p almanac --lib → 22 passed (4 new + 18 existing release tests unchanged). almanac/Cargo.toml: zero turso dep confirmed.")
//! @yah:handoff("Ready for F7 (issue-tracker crate) to consume: bootstrap constructs IssueStore + StoreIssuesSource(Arc<IssueStore>), spawns tokio::spawn(IssuesFeed::run(source, ArtifactSink::file(issues.json), OnChange::mesofact_rebuild('yah-marketing','/issues'), trigger_rx)), POST /issues handler sends RevalidateRequest on trigger_tx after successful INSERT.")
//! @yah:next("R443-F7: build crates/yah/issue-tracker using the IssuesSource trait from this ticket — wire StoreIssuesSource(Arc<IssueStore>) into IssuesFeed::run on bootstrap.")
//! @yah:next("R443-F8: replace OnChange::mesofact_rebuild's log-only stub with the actual HTTP webhook dispatch to mesofact-dev, and decide whether issues.toml lives in .yah/almanac/ or stays in issue-tracker bootstrap (per W179 D8 open question).")

use async_trait::async_trait;
use thiserror::Error;

use crate::feed::ReleaseFeed;

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("response parse error: {0}")]
    Parse(String),
}

/// Adapter trait: fetch the current release list from one authoritative source.
///
/// The push is always "revalidate" — almanac re-fetches from the adapter on
/// every incoming webhook, regardless of who sent it.
#[async_trait]
pub trait ReleaseSource: Send + Sync {
    async fn fetch(&self) -> Result<ReleaseFeed, SourceError>;
    /// Short identifier used in log messages and error context.
    fn source_id(&self) -> &str;
}
