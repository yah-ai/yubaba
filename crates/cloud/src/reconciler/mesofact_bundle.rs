//! W272 bundle tier for `mesofact-static` / `mesofact-spa` components — the
//! config half of the services-tab sync arm.
//!
//! Part of R599-F8 — the canonical ticket annotation lives in
//! `app/yah/cli/src/cloud.rs`, which owns the orchestration half. This module
//! only owns *what the mirror declares*: parsing the `[providers.bundle]` slot
//! and resolving which machines the built bundle gets deployed to.
//!
//! **The component kind does not change.** A mesofact site is a mesofact site;
//! the mirror decides how its bytes are distributed. A mirror with a
//! `[providers.static]` slot rides the historical build-and-publish-to-CDN path
//! ([`super::mesofact_static`]); a mirror that declares `[providers.bundle]`
//! rides the W272 chain instead:
//!
//! ```text
//! build → bundle assembly (per-file blake3) → R2 publish → workload deploy
//!   → node materializes → kamaji forks the serve binary
//! ```
//!
//! The deploy leg lives at the apply layer (`app/yah/cli/src/cloud.rs`) rather
//! than in a `Reconciler::up`, for the same reason
//! [`super::mesofact_runner`] does: machine resolution needs [`CloudConfig`],
//! which [`ReconcileCtx`] deliberately does not carry. What runs here is the
//! validation a desktop-side bring-up can still do offline —
//! [`MesofactBundleReconciler`] checks the slot parses and the placement
//! resolves, then bails with a pointer at the CLI.
//!
//! @yah:ticket(R703-T7, "Stamp a publish beacon into the W272 bundle so a passway apex can be serving-verified too")
//! @yah:status(review)
//! @yah:at(2026-08-08T23:55:25Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R703)
//! @yah:next("R703-B4 added a publish beacon (prefix/.well-known/yah-publish.json, oss/yubaba/crates/cloud/src/reconciler/publish_beacon.rs) written by the R2 publish path, and the reconciler fetches it back through the declared front door to fail an apply whose bytes nobody serves. A passway apex serves a W272 bundle, NOT the R2 prefix, so it has nothing to answer that probe with -- the front-door check can only ever pass there once the bundle carries an equivalent stamp.")
//! @yah:next("SCOPE: stamp a PublishBeacon into the bundle at build time using the same digest shape (PublishBeacon::new + digest_of are already public and take a BTreeMap of key -> sha256; reuse them rather than inventing a second digest). It must be reachable at /.well-known/yah-publish.json through mesofact serve, which serves bundle paths directly, so it needs to be a bundle entry at exactly that path.")
//! @yah:next("THEN: the mesofact_bundle sync path gains the same call mesofact_static::verify_serving makes. That is where the check becomes symmetric -- today only the R2 arm can prove it is being read.")
//! @yah:verify("A bundle built for yah-marketing contains /.well-known/yah-publish.json, and curl https://yah.dev/.well-known/yah-publish.json through a passway apex returns a beacon whose digest matches the bundle that was synced.")
//! @yah:gotcha("GATED ON R546 REGARDLESS. The bundle tier cannot sync at all until the musl serve_bins at target/x86_64-unknown-linux-musl/release/mesofact exists; slot_ready is false and .yah/services/yah-marketing/mirrors/cloud.toml falls back to the static chain. There is nothing to verify until that lands, which is why R703-B4 filed this rather than doing it in-pass.")
//! @yah:tier(Cleric) — the digest and probe shapes are already built and public; this is threading a known artifact through the bundle builder, not a design.
//! @yah:handoff("SHIPPED. A W272 bundle now carries a publish beacon and the bundle sync arm verifies it through the apex, so both serving tiers can prove they are being read rather than merely written.")
//! @yah:handoff("publish_beacon.rs: BUNDLE_BEACON_PATH = app/dist/html/.well-known/yah-publish.json (the one bundle entry mesofact serve answers /.well-known/yah-publish.json from), PublishBeacon::for_bundle, bundle_beacon(), stamp_bundle(). Reuses digest_of over a BTreeMap of path -> hash as the ticket asked; no second digest was invented.")
//! @yah:handoff("DESIGN CALL worth reviewing: the bundle stamp is clock-free. published_at became Option<String> (serde default, so beacons already in R2 still parse) and for_bundle sets None. A wall clock inside an entry of a content-addressed unit would flip the bundle digest on every assembly, breaking W272 immutability, the blob dedupe that makes a re-publish a no-op, and the assembly_is_deterministic test. The digest already names the exact immutable unit, so nothing diagnostic is lost; messages render via published_label().")
//! @yah:handoff("Symmetry, the third next bullet: mesofact_static::verify_serving and the new cloud.rs verify_bundle_serving both call one shared publish_beacon::check_serving -> ServingVerdict, rather than the bundle arm growing a second copy that drifts. probe_urls() is the pure half (three collapses: static probes prefix + apex separately, a bundle collapses onto the apex, bucket-direct collapses onto the origin) so it is testable with no network. Probe budgets split: EDGE_PROBE (4 x 5s, CDN propagation) vs NODE_PROBE (20 x 6s) because a bundle deploy has to fetch blobs, materialize, and restart the serve process.")
//! @yah:handoff("Stamped in assemble_component_bundle_with_sidecars (app/yah/cli/src/cloud.rs), not in the sync arm, so yah cloud bundle build and a sync still emit byte-identical trees. BundleSlot gained verify_serving (default true, non-bool rejected rather than defaulted) and an optional zone (defaults to the service domain) + serving_zone(). Documented both in the [providers.bundle] block of .yah/services/yah-marketing/mirrors/cloud.toml.")
//! @yah:handoff("DISCOVERED WORK, outside the ticket title, done in-pass. Two claims this ticket rests on were inference, not verification, so I pinned them. (1) oss/mesofact/crates/mesofact/src/server.rs:1450 — serves_the_publish_beacon_from_a_dot_well_known_path proves GET /.well-known/yah-publish.json really returns 200 application/json through Server::from_bundle (a leading-dot directory is exactly the shape a static server tends to reject or rewrite), plus an_unstamped_bundle_does_not_answer_the_beacon_url_with_200 so an unstamped bundle 404s instead of 200-ing HTML. (2) oss/yah-base/crates/mesofact-bundle/src/store.rs:439 — a_dot_directory_entry_publishes_and_materializes proves publish_bundle + materialize_bundle round-trip the first dot-directory entry a bundle has ever carried; if checked_rel were ever tightened to a naive no-dot-segment rule, a node would refuse to materialize a bundle it had already accepted.")
//! @yah:verify("cargo test -p yah-cloud --lib (in oss/yubaba): 741 passed, 0 failed. 23 in reconciler::publish_beacon (13 new), 34 in reconciler::mesofact_bundle (4 new).")
//! @yah:verify("cargo test -p yah --lib: 1035 passed, 0 failed. Includes the new cloud::bundle_assembly_tests::an_assembled_bundle_carries_its_publish_beacon, and assembly_is_deterministic still passes with the stamp in place, which is the evidence the clock-free design holds W272 immutability.")
//! @yah:verify("cargo test -p mesofact --lib server:: (in oss/mesofact): 34 passed, 0 failed. cargo test -p yah-mesofact-bundle --features store (in oss/yah-base): 31 passed, 0 failed.")
//! @yah:verify("cargo check --workspace --exclude desktop: clean. cargo check --workspace in oss/yubaba: clean. cargo test -p xtask --test schema_drift: 3 passed, so no generated-artifact drift. yah cloud validate --path .: ok, no alias or port collisions, re-run after the mirror comment edit.")
//! @yah:gotcha("THE SECOND HALF OF THE VERIFY LINE IS NOT DONE AND COULD NOT BE. curl https://yah.dev/.well-known/yah-publish.json still 404s, because the bundle tier cannot sync at all until R546 produces target/x86_64-unknown-linux-musl/release/{mesofact,almanac-feed}. slot_ready is false, yah-marketing still falls back to the static chain, and no bundle has been assembled by this code against the live apex. Everything is proven by test, nothing by a live apply. R703 now carries a notify_on(R546) that spells out the live run.")
//! @yah:gotcha("When the bundle tier first turns on, expect the apply to FAIL the serving check for a while, and read that as the check working. us-east-001 is serving a hand-placed bundle from before this code existed, which carries no stamp, so the apex will answer the probe 404 (Missing) until a bundle assembled by THIS code is deployed there. Do not reach for verify_serving = false; deploy the stamped bundle.")
//! @yah:next("LIVE VERIFY, gated on R546 and the only thing left: build the two musl binaries, yah cloud apply --service yah-marketing --env cloud, confirm it takes the bundle arm, then curl https://yah.dev/.well-known/yah-publish.json and check the digest equals bundle_beacon() over the synced manifest.")
//!
//! @yah:ticket(R752-B7, "revalidate routes allowlist is parsed, shipped, then dropped - the receiver accepts pokes for every route")
//! @yah:status(review)
//! @yah:at(2026-08-13T00:22:14Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R752)
//! @yah:severity(medium)
//! @yah:gotcha("Found 2026-08-12 while wiring R330-F13's sidecar to the live receiver. `[providers.bundle.revalidate] routes` is documented as an allowlist ('empty = all routes', mesofact_bundle.rs:218), is parsed into RevalidateSlot.routes, is copied into MesofactRevalidateReceiver.routes (mesofact_bundle.rs:264), and is shipped over the wire to kamaji. kamaji then never reads it: bundle_workload_spec_revalidate (oss/kamaji/crates/kamaji-bin/src/server.rs:2117) builds the receiver's argv from publish_config + listen and its env from receiver.env, and `routes` appears nowhere. grep confirms server.rs touches receiver.feeds / feed_interval_secs / feed_project_prefix / publish_config / env and never receiver.routes.")
//! @yah:gotcha("MEASURED, not inferred: with .yah/services/yah-marketing/mirrors/cloud.toml declaring routes = [\"/releases\"], POST http://100.64.0.3:8081/revalidate {\"routes\":[\"/issues\"]} returned 202 on us-east-001 and went on to re-render and republish /issues. An undeclared route was accepted and acted on.")
//! @yah:gotcha("Severity is medium not high because the receiver is not publicly reachable (mesh IP, and it is the tenant's own render path) — but it IS an unauthenticated write-shaped endpoint today: its process env carries no MESOFACT_MIRROR_KEY, so mirror_key_env is unresolved too. The declared scoping control and the declared bearer are BOTH inert, which is worth knowing before anyone treats either as a boundary.")
//! @yah:next("Decide whether the allowlist is real. If yes, pass it to the receiver (argv or env) in bundle_workload_spec_revalidate and enforce it there; if no, delete the field rather than leaving a documented control that does nothing.")
//! @yah:next("If it becomes enforced, .yah/services/yah-marketing/mirrors/cloud.toml already lists both \"/releases\" and \"/issues\" — R330-F13 added /issues precisely so enforcement does not silently break the now-working issue-filing path.")
//! @yah:next("Same question for mirror_key_env: it resolves to nothing today, so the receiver runs open. Whatever change starts resolving it must set the matching ALMANAC_MIRROR_KEY on the issue-tracker unit on us-east-001 in the SAME change, or the sidecar's poke starts 401ing and /issues silently stops updating.")
//! @yah:handoff("OPERATOR CALL 2026-08-12: the allowlist is real - enforce it IF present. Auth is a separate, pluggable axis (cheers auth, preshared key, or unauthenticated are all legitimate for an almanac route); the allowlist is scoping, not authentication, and the two are now independent controls end to end.")
//! @yah:handoff("Node leg (oss/kamaji/crates/kamaji-bin/src/server.rs, bundle_workload_spec_revalidate): each declared route is rendered as one `--allow-route <route>` on the receiver's argv. An empty list emits no flag at all, which keeps the documented 'empty = all routes' meaning - `--allow-route \"\"` would have scoped the receiver to a route that cannot exist and silently killed every revalidation.")
//! @yah:handoff("Receiver leg (oss/mesofact/crates/mesofact/src/revalidate.rs): RevalidateConfig gained `routes`, fed by a new repeatable `--allow-route` flag on `mesofact serve`. Enforced in BOTH shapes a poke can take - an explicit `{\"route\": ...}` outside the list gets a synchronous 403 and never enqueues, and a whole-site poke (no route named) is NARROWED to the list at render time. The narrowing is the half that matters: the escape actually measured on us-east-001 sent {\"routes\":[\"/issues\"]}, which the receiver's body type does not have a field for, so it deserialized to route=None and ran as a whole-site render. A handler-only check would still have let that through.")
//! @yah:handoff("Route selection was split out of render_routes into a pure `render_targets(workload, route, allow)` so the scoping rule is testable without booting V8 - a security-shaped control whose only evidence was 'it compiles' is how this got shipped inert in the first place. It also errors on a disallowed explicit route rather than rendering nothing, so an in-process caller cannot get a silent success.")
//! @yah:handoff("The allowlist is intersected with the manifest, not unioned: a listed route the manifest cannot render (ssr, deferred, or a typo) is skipped instead of turning every whole-site poke into an error.")
//! @yah:handoff("Config docs corrected where they now lie: RevalidateSlot.routes in oss/yubaba/crates/cloud/src/reconciler/mesofact_bundle.rs and the block in .yah/services/yah-marketing/mirrors/cloud.toml both said the field was inert. The cloud.toml note now says the list is LOAD-BEARING - a route absent from it stops being republished after the next deploy of that mirror.")
//! @yah:handoff("tenants.rs (multi-tenant receiver) passes an empty allowlist with a comment naming the shape to copy - tenants/<id>.toml has no routes key yet, so per-tenant scoping is unmodelled rather than silently unenforced.")
//! @yah:verify("cargo test -p mesofact --all-features (oss/mesofact) - 104 passed, 0 failed, including 8 new: out-of-list route 403s and does not enqueue, in-list route accepted, a correct mirror_key does NOT widen the allowlist, empty allowlist accepts anything, whole-site poke accepted then narrowed, whole-site targets = manifest INTERSECT allowlist, an allowlisted route absent from the manifest is not rendered, explicit disallowed route errors at render time.")
//! @yah:verify("cargo test -p kamaji-bin --all-features (oss/kamaji) - 239 passed, 0 failed. The pre-existing revalidate_spec_argv_matches_mesofact_serve_clap_shape test is the one that should have caught this: it declared routes = [\"/releases\"] and pinned an argv that never mentioned it, green the whole time. It now asserts the --allow-route pair, plus two new tests for the empty-list and two-route cases.")
//! @yah:verify("cargo test -p yah-cloud --lib mesofact_bundle (oss/yubaba) - 44 passed, 0 failed.")
//! @yah:verify("cargo test -p xtask --test schema_drift - 3 passed; the doc-comment edits touch no schemars-derived type, so no generated artifact moved.")
//! @yah:verify("cargo clippy --all-features --all-targets on both changed crates - no new warnings from the changed files (mesofact-core/mesofact-build/server.rs warnings are pre-existing).")
//! @yah:verify("Checked the roll is safe BEFORE it happens: the only mirror in the tree declaring [providers.bundle.revalidate] is yah-marketing/cloud.toml, and it lists both /releases and /issues. The only live pokers name exactly those - issue-tracker sends Poke::route(\"/issues\") (crates/yah/issue-tracker/src/main.rs:86) and the almanac on_change arms in .yah/almanac/{releases,yah-desktop}.toml both name /releases. fleet.toml uses kind=\"reload\", which pokes almanac's own receiver, not this one. So nothing that works today starts 403ing.")
//! @yah:gotcha("NOT DEPLOYED - code only. Enforcement starts at the next `yah cloud` sync of yah-marketing, which re-forks the receiver with the new argv. Deliberately not rolled from this session: it is an outward-facing change to a live node, and deployment belongs to R330-F13/R523. Before that roll, the live receiver still accepts a poke for any route.")
//! @yah:next("mirror_key_env is still inert and the receiver still runs OPEN - untouched here, because the operator's call put auth on its own axis. Whatever change starts resolving it must set the matching ALMANAC_MIRROR_KEY on the issue-tracker unit on us-east-001 in the SAME change, or the sidecar's poke starts 403ing and /issues silently stops updating.")
//! @yah:next("Public front door: R752-F9 filed for the low-security platform key that ships with the browser bundle for POST /api/issues (the operator's second decision). Different endpoint, different key namespace - do not collapse it with MESOFACT_MIRROR_KEY.")
//! @yah:gotcha("BEHAVIOUR CHANGE worth knowing: after the roll, a whole-site poke at yah-marketing re-renders ONLY /releases and /issues, not / and /404. That is the intended reading of the declared list, but it means the landing page can no longer be refreshed by poking the receiver - it is republished by a full deploy. If someone wants / kept fresh from a feed, add it to routes in cloud.toml.")

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use workload_spec::{
    BlakeHash, BundleLifecycle, MesofactRevalidateReceiver, MesofactServeBundle, Millis,
};

use super::{ReconcileCtx, Reconciler, RunningWorkload};
use crate::config::CloudConfig;
use crate::MirrorConfig;

/// Mirror provider role that opts a mesofact component into the bundle tier.
pub const SLOT_ROLE: &str = "bundle";

/// Sub-key under `[providers.bundle]` that declares the revalidate receiver
/// (R330-F12 almanac push endpoint).
pub const REVALIDATE_KEY: &str = "revalidate";

/// Default idle TTL for an `on-demand` (JIT) bundle when the slot doesn't name
/// one: five minutes with zero connections before kamaji reaps the process.
pub const DEFAULT_IDLE_TTL_MS: u64 = 300_000;

/// Every key `[providers.bundle]` is allowed to carry (R556-B14).
///
/// The mirror schema's `MirrorProviderSlot` is `additionalProperties: true` by
/// construction — it is one flattened `BTreeMap<String, toml::Value>` shared by
/// every provider role, so it cannot know what any single role reads. That
/// leniency is fine at the schema layer and is the wrong default here: a slot
/// whose key nobody reads is not "extra metadata", it is an operator's
/// instruction being ignored. Both instances that motivated this were
/// **parses clean, deploys, wrong at request time** — a typo'd `prot = 8081`
/// falls back to kamaji's node default, which post-R599-F12 is whatever OTHER
/// bundle already holds 8080 on that node; and a `[providers.bundle.env]` block
/// was, before R556-T12, read by nothing at all while looking exactly like it
/// worked.
///
/// The set is the UNION of what every consumer of this slot reads, not just
/// what [`BundleSlot::parse`] reads — `plan_ingress` reads four of its own off
/// the same table (`reconciler::ingress`), and `MirrorProviderSlot::required`
/// reads `required`. Scoping it to one consumer would reject live mirrors.
///
/// `use` / `kind` are absent deliberately: they are captured by the
/// `MirrorProviderSlot` enum variant itself and never appear in `fields()`.
const ALLOWED_SLOT_KEYS: &[&str] = &[
    // BundleSlot::parse
    "account",
    "bucket",
    "env",
    "idle_ttl_ms",
    "lifecycle",
    "machines",
    "name",
    "port",
    REVALIDATE_KEY,
    "runtime_version",
    "serve_bins",
    "serve_build",
    "verify_serving",
    "zone",
    // MirrorProviderSlot::required — F16 placement, read via the slot, not here
    "required",
    // reconciler::ingress::plan_ingress — the front-door planner reads the same
    // table. `machines`, `port` and `zone` are shared with the list above.
    "machine",
    "upstream_host",
    // R844-F5 split participation from the port value, but only taught the
    // planner about it — so a bundle slot spelling the portless shape it
    // introduced (`fronted = true`, no `port`) was rejected here as an unknown
    // key, and the deletion that ticket exists to enable would have failed the
    // apply. Found and fixed from R844-F8.
    "fronted",
];

/// True when this mirror opts its mesofact components into the W272 bundle
/// tier — i.e. declares a `[providers.bundle]` slot.
///
/// Checked at the dispatch layer before the static reconciler runs, so the
/// two tiers are mutually exclusive per mirror rather than per component.
pub fn slot_declared(mirror: &MirrorConfig) -> bool {
    mirror.providers.contains_key(SLOT_ROLE)
}

/// Resolve a slot-declared binary path against the workspace root.
///
/// Slot paths are workspace-relative unless absolute — the operator writes them
/// in a mirror file, not from a shell cwd.
pub fn resolve_slot_path(workspace_root: &std::path::Path, path: &std::path::Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    }
}

/// Declared-but-absent binaries, as `(label, resolved path)`.
///
/// The label is the config coordinate (`providers.bundle.serve_bins.<triple>`)
/// so a caller can name the exact line an operator has to fix.
pub fn missing_bins(slot: &BundleSlot, workspace_root: &std::path::Path) -> Vec<(String, PathBuf)> {
    let serve = slot
        .serve_bins
        .iter()
        .map(|(triple, path)| (format!("providers.{SLOT_ROLE}.serve_bins.{triple}"), path));
    let feed = slot.revalidate.iter().flat_map(|rv| {
        rv.feed_bins.iter().map(|(triple, path)| {
            (
                format!("providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feed_bins.{triple}"),
                path,
            )
        })
    });
    serve
        .chain(feed)
        .filter_map(|(label, path)| {
            let resolved = resolve_slot_path(workspace_root, path);
            (!resolved.is_file()).then_some((label, resolved))
        })
        .collect()
}

/// True when the bundle tier can actually **serve**, not merely when it has
/// been declared.
///
/// R330-B43 — THIS DISTINCTION IS THE WHOLE POINT, and getting it wrong froze
/// yah.dev for 19 days. Dispatch used to switch tiers on [`slot_declared`]
/// alone, so writing a `[providers.bundle]` block instantly disabled the
/// working `[providers.static]` publish chain — while the bundle tier itself
/// could not come up, because its `serve_bins` binaries had never been built.
/// The old path was off, the new path could not turn on, and the site quietly
/// served stale bytes at HTTP 200 with no error anywhere.
///
/// A cut-over must never be able to disable a serving path before its
/// successor can serve. So the switch keys on the binaries EXISTING, and a
/// declared-but-unready slot falls back to the static chain (loudly) instead
/// of taking over and stranding the site.
///
/// A slot with no `serve_bins` at all is "ready" here on purpose: that is the
/// vanilla-runtime shape, which fails later for a different, well-reported
/// reason rather than being a half-built self-contained bundle.
///
/// R746-F2: a `serve_build` slot is likewise ready, and for a stronger reason —
/// the sync can *produce* the binary it needs by dispatching the declared QED
/// recipe, so there is no such thing as a path an operator forgot to build.
/// That is the whole point of the declaration: B43's failure was "declared but
/// nobody can build it here", and a recipe is exactly the thing that removes
/// the "here".
pub fn slot_ready(slot: &BundleSlot, workspace_root: &std::path::Path) -> bool {
    missing_bins(slot, workspace_root).is_empty()
}

/// Parsed `[providers.bundle]` slot — everything the sync arm needs that is
/// *declared* rather than *derived*.
///
/// ```toml
/// [providers.bundle]
/// use = "cloudflare"                  # R2 credentials resolve via this provider
/// bucket = "yah-dev-bundles"          # the append-only bundle store
/// machines = ["us-east-001"]          # explicit placement (or `required = {…}`)
/// name = "yah-marketing"              # stable workload handle; defaults to the service name
/// lifecycle = "keep-alive"            # or "on-demand"
/// idle_ttl_ms = 300000                # on-demand only
/// runtime_version = "0.8.20"          # vanilla bundles only (no serve binary)
/// serve_bins = { x86_64-unknown-linux-musl = "target/…/mesofact-serve" }
/// # …or, instead of naming pre-built paths, name the recipe that builds them:
/// # [providers.bundle.serve_build]
/// # pipeline = "mesofact-musl"
/// # binary   = "mesofact"
/// # triples  = ["x86_64-unknown-linux-musl"]
/// zone = "yah.dev"                    # front door to serving-verify; defaults
///                                     # to the service's own domain
/// verify_serving = true               # default; see the field docs
///
/// # Environment for the serve process, as source URIs resolved at deploy
/// # (R556-T12). An SSR route reading a private source needs this or it gets
/// # a credential-less server on the node.
/// [providers.bundle.env]
/// ANALYTICS_R2_ACCESS_KEY = "vault:cloudflare-r2-access-key-id"
/// ANALYTICS_R2_BUCKET     = "yah-analytics"      # bare literal: not a secret
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSlot {
    /// R2 bucket holding the bundle store. Append-only, blob-deduped.
    pub bucket: String,
    /// Cloudflare account id override. `None` → resolve from the workspace's
    /// cloudflare provider config / `CF_ACCOUNT_ID`.
    pub account: Option<String>,
    /// Stable operator-facing workload name. yubaba requires one for a bundle
    /// deploy: the digest is the *content* and changes on every rebuild, so it
    /// is not a usable handle for `list` / `stop`.
    pub name: Option<String>,
    /// Explicitly named target machines, in deploy order. Empty → fall back to
    /// the slot's `required = {…}` placement spec.
    pub machines: Vec<String>,
    /// Stock runtime version recorded as `runtime = "mesofact/<version>"` for a
    /// vanilla bundle. Ignored when `serve_bins` is non-empty. `None` → the
    /// caller's own version.
    pub runtime_version: Option<String>,
    /// `<triple> → <path to serve binary>`. Any entry makes this a
    /// `runtime = "self"` bundle that carries its own serve binaries.
    pub serve_bins: BTreeMap<String, PathBuf>,
    /// Build the serve binaries on demand instead of naming pre-built paths
    /// (R746-F2). Mutually exclusive with `serve_bins`; either one makes this a
    /// `runtime = "self"` bundle.
    pub serve_build: Option<BinBuild>,
    /// How kamaji supervises the served bundle.
    pub lifecycle: BundleLifecycle,
    /// Port the served bundle listens on (R599-F12). `None` → kamaji's
    /// node-wide default (8080), which is only correct while the node hosts a
    /// single bundle; declare one per workload to put several on a node.
    pub port: Option<u16>,
    /// `[providers.bundle.env]` — environment for the **serve** process, as
    /// `NAME → source URI` (R556-T12).
    ///
    /// Values are the source *declaration*, kept verbatim and resolved
    /// deploy-side by `yah cloud apply` — `vault:<slot>`, `env:<VAR>`, a
    /// pipe-joined fallback chain of either, or a bare literal for a
    /// known-non-secret value. Same grammar `~/.yah/qed/secrets.toml` uses, so
    /// there is one source-URI vocabulary in the camp rather than two.
    ///
    /// Parsing stays here and resolution does not: this crate is offline by
    /// construction (a misconfigured mirror must fail before a build runs), and
    /// only the syncing machine has the vault. The `RevalidateSlot::mirror_key_env`
    /// → [`RevalidateSlot::to_workload_payload`] split is the same shape one
    /// level down.
    pub env: BTreeMap<String, String>,
    /// Optional revalidate receiver config (R330-F12). `Some` → the deploy
    /// also stands up a `mesofact serve --revalidate` process.
    pub revalidate: Option<RevalidateSlot>,
    /// Public zone whose front door is checked after a deploy (R703-T7).
    /// `None` → the service's own `domain`, which is the shape every mirror in
    /// tree uses; declare one only when the bundle serves a zone that isn't it.
    ///
    /// Unlike `[providers.static]`, this is optional: the static slot's `zone`
    /// is load-bearing for the Worker route and cache purge, whereas here it
    /// only names what to probe.
    pub zone: Option<String>,
    /// Whether a deploy is checked against the live front door (R703-T7).
    ///
    /// Defaults to **true**, and the only reason to turn it off is a
    /// deliberately in-flight front-door migration — with a comment naming the
    /// ticket. It is declared in config rather than passed as a CLI flag for
    /// the same reason the static slot's is: switching it off should be a
    /// reviewable diff, not an invocation habit that quietly becomes permanent.
    pub verify_serving: bool,
}

/// A binary the bundle needs, declared as **the recipe that builds it** rather
/// than as a path someone is expected to have already produced (R746-F2).
///
/// ```toml
/// [providers.bundle.serve_build]
/// pipeline = "mesofact-musl"                   # .yah/qed/<name>.toml
/// binary   = "mesofact"                        # matches a step's `produces.binary`
/// triples  = ["x86_64-unknown-linux-musl"]     # what the placed nodes run
/// ```
///
/// # Why this is a declaration and not a fallback
///
/// The alternative shape — "use `serve_bins` if the path exists, otherwise
/// build" — makes the deployed artifact a function of what happens to be on the
/// operator's disk. Two machines syncing the same mirror would then ship
/// different binaries, and the one with a stale path would ship the stale one
/// silently. The mirror says which shape it is; the sync obeys.
///
/// Declaring both this and `serve_bins` is refused for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinBuild {
    /// QED pipeline name, resolved under `.yah/qed/<pipeline>.toml`.
    pub pipeline: String,
    /// Logical binary name, matched against a step's `[[steps.produces]]
    /// binary`.
    pub binary: String,
    /// Target triples to resolve, in declaration order. Non-empty: a build
    /// declaration that names no target builds nothing.
    pub triples: Vec<String>,
}

/// Parsed `[providers.bundle.revalidate]` sub-slot — declares the almanac
/// revalidate receiver to fork alongside the static bundle server (R330-F12).
///
/// ```toml
/// [providers.bundle.revalidate]
/// routes = ["/releases"]             # allowlist (empty = all routes)
/// mirror_key_env = "YAH_MARKETING_MIRROR_KEY"   # env var holding the bearer
/// publish_config = "mesofact.config.toml"        # default
/// feeds = ["releases"]               # .yah/almanac/<name>.toml to keep fresh
/// feed_interval_secs = 300           # default
/// feed_runtime = "almanac-feed/0.8.22"   # vanilla: node resolves the fetcher
/// # …or, for a self-contained bundle, stage it in and name the built paths:
/// # feed_bins = { x86_64-unknown-linux-musl = "target/…/almanac-feed" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevalidateSlot {
    /// Routes the receiver accepts pokes for (allowlist).
    /// Empty → all routes in the workload manifest.
    ///
    /// Enforced on the node since R752-B7: kamaji renders this list as one
    /// `--allow-route` per entry on the receiver's argv, `mesofact serve`
    /// refuses an explicit poke outside it (403) and narrows a whole-site poke
    /// to it. Before that it was parsed here, shipped over the wire, and read
    /// by nobody — declaring it bought exactly nothing. Scoping only: `who may
    /// poke` is `mirror_key_env`, and the two are independent.
    pub routes: Vec<String>,
    /// Env var name holding the tenant bearer secret. Deploy resolves it
    /// and sets `MESOFACT_MIRROR_KEY` on the receiver process.
    /// `None` → open receiver (no bearer check).
    pub mirror_key_env: Option<String>,
    /// Path to `mesofact.config.toml` with the `[publish]` block, relative
    /// to the workload directory. `None` → default `"mesofact.config.toml"`.
    pub publish_config: Option<PathBuf>,
    /// Almanac feed names (`.yah/almanac/<name>.toml`) the on-node fetch tier
    /// keeps fresh (R330-F31). Empty → no fetcher, and the receiver re-renders
    /// whatever data the bundle was built with.
    pub feeds: Vec<String>,
    /// Seconds between feed-fetch ticks. `None` → the spec default.
    pub feed_interval_secs: Option<u64>,
    /// Per-triple path to the `almanac-feed` binary staged into the bundle as a
    /// sidecar. The self-contained shape's answer to "how does the fetcher
    /// reach the node".
    ///
    /// Mutually exclusive with [`feed_runtime`](Self::feed_runtime), for the
    /// same reason `serve_bins` and `serve_build` are: the mirror declares
    /// which shape it is, and a use-whichever-exists fallback would make the
    /// deployed binary a function of the syncing machine's disk.
    pub feed_bins: BTreeMap<String, PathBuf>,
    /// Runtime ref the fetcher resolves from the node's shared runtime-asset
    /// cache — `feed_runtime = "almanac-feed/0.8.22"` (R746-T3).
    ///
    /// This is the **vanilla** shape's answer, and it is what makes a vanilla
    /// bundle with a feed tier possible at all: `feed_bins` is a path someone
    /// must have cross-built, so a bundle that carries no serve binary but
    /// still needs a sidecar path has only moved the toolchain requirement,
    /// not removed it.
    pub feed_runtime: Option<String>,
}

impl RevalidateSlot {
    /// Build the [`MesofactRevalidateReceiver`] payload for the workload spec,
    /// given the env vars resolved at deploy time and the feed definitions read
    /// from the camp's `.yah/almanac/` tree.
    ///
    /// Feed definitions travel by value: reading them is the deploy side's job
    /// (it is the only participant that has the camp checkout), and the node
    /// gets a self-contained payload.
    pub fn to_workload_payload(
        &self,
        env: BTreeMap<String, String>,
        feeds: Vec<workload_spec::AlmanacFeed>,
        feed_project_prefix: Option<String>,
    ) -> MesofactRevalidateReceiver {
        MesofactRevalidateReceiver {
            routes: self.routes.clone(),
            publish_config: self
                .publish_config
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "mesofact.config.toml".to_string()),
            mirror_key_env: self.mirror_key_env.clone(),
            env,
            feeds,
            feed_interval_secs: self
                .feed_interval_secs
                .unwrap_or(DEFAULT_FEED_INTERVAL_SECS),
            feed_project_prefix,
            feed_runtime: self.feed_runtime.clone(),
        }
    }
}

/// Mirrors `workload_spec`'s own default. Duplicated rather than exported
/// because the spec keeps its serde defaults private; the parse tests below
/// pin the two together.
pub const DEFAULT_FEED_INTERVAL_SECS: u64 = 300;

/// Bundle path segment the fetch tier's sidecar binary is staged under —
/// `bins/<triple>/almanac-feed`, next to `bins/<triple>/serve` — and the
/// filename it lands under in the node runtime-asset cache when a *vanilla*
/// bundle resolves it by name instead (R746-T3).
///
/// Re-exported from `yah_mesofact_bundle` rather than re-typed: this crate and
/// kamaji both used to declare their own copy, pinned together only by an
/// argv-shape test. One `const` in the crate they both already depend on
/// removes the drift instead of detecting it.
pub use yah_mesofact_bundle::FEED_BIN as FEED_BIN_NAME;

impl BundleSlot {
    /// Parse the mirror's `[providers.bundle]` slot.
    ///
    /// Every failure names the offending field plus the service and env, so the
    /// operator gets a file to open rather than a type error. Validation is
    /// total and offline — nothing here touches the network, so a misconfigured
    /// mirror fails before a build runs (R330-B5 fail-fast discipline).
    pub fn parse(mirror: &MirrorConfig, service: &str, env: &str) -> Result<Self> {
        let slot = mirror.providers.get(SLOT_ROLE).with_context(|| {
            format!(
                "mirror has no `providers.{SLOT_ROLE}` slot — required for the W272 bundle tier \
                 (service={service}, env={env})"
            )
        })?;
        let fields = slot.fields();

        // R556-B14. Unknown keys are rejected BEFORE anything is read, so the
        // operator gets the typo rather than a downstream complaint about the
        // field the typo was supposed to be. Nearest-match is offered because
        // the realistic failure is one transposed character, and an error that
        // only says "unknown" makes the reader diff the docs by eye.
        for key in fields.keys() {
            if ALLOWED_SLOT_KEYS.contains(&key.as_str()) {
                continue;
            }
            let hint = nearest_slot_key(key)
                .map(|k| format!(" — did you mean `{k}`?"))
                .unwrap_or_default();
            bail!(
                "providers.{SLOT_ROLE} has an unknown key `{key}`{hint} (service={service}, \
                 env={env}). Every key this slot reads is one of: {}. An unrecognized key is \
                 refused rather than ignored because the failure it hides is silent: a typo'd \
                 `port` deploys onto whatever bundle already holds the node default, and a \
                 mistyped credential block deploys a serve process with no credentials at all.",
                ALLOWED_SLOT_KEYS.join(", "),
            );
        }

        let bucket = fields
            .get("bucket")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .with_context(|| {
                format!(
                    "providers.{SLOT_ROLE} has no `bucket` — name the R2 bundle store in \
                     .yah/services/{service}/mirrors/{env}.toml"
                )
            })?
            .to_string();

        let account = fields
            .get("account")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let name = fields
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let machines = match fields.get("machines") {
            None => Vec::new(),
            Some(v) => {
                let list = v.as_array().with_context(|| {
                    format!(
                        "providers.{SLOT_ROLE}.machines must be an array of machine names \
                         (service={service}, env={env})"
                    )
                })?;
                list.iter()
                    .map(|entry| {
                        entry
                            .as_str()
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .with_context(|| {
                                format!(
                                    "providers.{SLOT_ROLE}.machines holds a non-string (or empty) \
                                     entry (service={service}, env={env})"
                                )
                            })
                    })
                    .collect::<Result<Vec<_>>>()?
            }
        };

        let runtime_version = fields
            .get("runtime_version")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let serve_bins = match fields.get("serve_bins") {
            None => BTreeMap::new(),
            Some(v) => {
                let table = v.as_table().with_context(|| {
                    format!(
                        "providers.{SLOT_ROLE}.serve_bins must be a table of \
                         <target-triple> = <path> (service={service}, env={env})"
                    )
                })?;
                table
                    .iter()
                    .map(|(triple, path)| {
                        let path = path.as_str().filter(|s| !s.is_empty()).with_context(|| {
                            format!(
                                "providers.{SLOT_ROLE}.serve_bins.{triple} must be a non-empty \
                                 path (service={service}, env={env})"
                            )
                        })?;
                        Ok((triple.clone(), PathBuf::from(path)))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?
            }
        };

        let serve_build = parse_bin_build(
            fields.get("serve_build"),
            &format!("providers.{SLOT_ROLE}.serve_build"),
            service,
            env,
        )?;

        if serve_build.is_some() && !serve_bins.is_empty() {
            bail!(
                "providers.{SLOT_ROLE} declares BOTH `serve_bins` and `serve_build` — pick one \
                 (service={service}, env={env}). `serve_bins` names binaries you have already \
                 built; `serve_build` names the QED recipe that builds them. Accepting both \
                 would make the deployed binary depend on what happens to be on the syncing \
                 machine's disk, which is how one operator ships a stale binary while another \
                 ships a fresh one from the same mirror."
            );
        }

        // R599-F12. Parsed strictly: a port is either absent or a real one, and
        // a typo that silently fell back to 8080 would collide with whatever
        // bundle already holds that port on the node — a failure that surfaces
        // as the wrong site being served, not as an error.
        let port = match fields.get("port") {
            None => None,
            Some(v) => {
                let n = v.as_integer().with_context(|| {
                    format!(
                        "providers.{SLOT_ROLE}.port must be an integer TCP port \
                         (service={service}, env={env})"
                    )
                })?;
                Some(u16::try_from(n).ok().filter(|p| *p != 0).with_context(|| {
                    format!(
                        "providers.{SLOT_ROLE}.port = {n} is not a usable TCP port \
                         (1..=65535) (service={service}, env={env})"
                    )
                })?)
            }
        };

        // R556-T12. Env for the serve process. Declared as source URIs and
        // stored verbatim — resolution is the deploy side's job (see the field
        // docs). Every value is required to be a non-empty string: an empty
        // source is a var that would silently reach the node unset, which is
        // the exact failure mode this slot exists to remove.
        let serve_env = match fields.get("env") {
            None => BTreeMap::new(),
            Some(v) => {
                let table = v.as_table().with_context(|| {
                    format!(
                        "providers.{SLOT_ROLE}.env must be a table of <ENV_NAME> = \
                         \"<source-uri>\" (service={service}, env={env})"
                    )
                })?;
                table
                    .iter()
                    .map(|(name, source)| {
                        let source = source
                            .as_str()
                            .filter(|s| !s.trim().is_empty())
                            .with_context(|| {
                                format!(
                                    "providers.{SLOT_ROLE}.env.{name} must be a non-empty source \
                                     string — \"vault:<slot>\", \"env:<VAR>\", a pipe-joined \
                                     chain of either, or a bare literal for a non-secret \
                                     (service={service}, env={env})"
                                )
                            })?;
                        Ok((name.clone(), source.to_string()))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?
            }
        };

        let lifecycle = parse_lifecycle(
            fields.get("lifecycle").and_then(|v| v.as_str()),
            fields.get("idle_ttl_ms").and_then(|v| v.as_integer()),
            service,
            env,
        )?;

        let revalidate = parse_revalidate_slot(fields, service, env)?;

        let zone = fields
            .get("zone")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // R703-T7. Parsed strictly rather than `unwrap_or(true)` on a bad type:
        // `verify_serving = "false"` silently reading as *enabled* is the
        // friendlier-looking failure, but an operator who typed it believes the
        // check is off and will be surprised by an apply that fails on a
        // migration they thought they had silenced.
        let verify_serving = match fields.get("verify_serving") {
            None => true,
            Some(v) => v.as_bool().with_context(|| {
                format!(
                    "providers.{SLOT_ROLE}.verify_serving must be a boolean \
                     (service={service}, env={env})"
                )
            })?,
        };

        // R746-T3: a vanilla bundle carries no `bins/` by construction, so a
        // sidecar declared as a PATH has nowhere to be staged into. Caught here
        // rather than at assembly so the operator gets the mirror file and the
        // remedy, offline, before a build runs.
        let slot = Self {
            bucket,
            account,
            name,
            machines,
            runtime_version,
            serve_bins,
            serve_build,
            lifecycle,
            port,
            env: serve_env,
            revalidate,
            zone,
            verify_serving,
        };
        if !slot.is_self_contained() {
            if let Some(rv) = slot.revalidate.as_ref() {
                if !rv.feed_bins.is_empty() {
                    anyhow::bail!(
                        "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feed_bins is declared but this is \
                         a VANILLA bundle (no serve_bins / serve_build), which carries no bins/ \
                         at all — replace it with feed_runtime = \"{FEED_BIN_NAME}/<version>\" \
                         and publish that asset once per triple with `yah cloud bundle \
                         publish-runtime` (service={service}, env={env})"
                    );
                }
            }
        }
        Ok(slot)
    }

    /// The zone whose front door a deploy of this bundle is checked against:
    /// the slot's `zone`, else the service's own domain.
    pub fn serving_zone<'a>(&'a self, service_domain: &'a str) -> &'a str {
        self.zone.as_deref().unwrap_or(service_domain)
    }

    /// Stable workload handle: the slot's `name`, else the service name.
    pub fn workload_name<'a>(&'a self, service: &'a str) -> &'a str {
        self.name.as_deref().unwrap_or(service)
    }

    /// True when the assembled bundle carries its own serve binaries
    /// (`runtime = "self"`) rather than resolving a stock node runtime asset.
    ///
    /// Keyed on the *declaration*, not on what is on disk: a `serve_build` slot
    /// is self-contained before its binary has ever been built, because the
    /// mirror said so. Deriving the shape from disk state instead is the bug
    /// this relay exists to remove — it makes a bundle's shape depend on which
    /// machine ran the sync.
    pub fn is_self_contained(&self) -> bool {
        !self.serve_bins.is_empty() || self.serve_build.is_some()
    }

    /// Build the `{digest, runtime, lifecycle}` triple a `mesofact-static`
    /// workload carries once its bundle is published.
    ///
    /// `runtime` wire-mirrors `yah_mesofact_bundle::BundleRuntime`, so it is
    /// taken from the manifest the assembler actually wrote rather than
    /// re-derived here — the manifest is what the node will verify against.
    ///
    /// `env` is the **resolved** serve environment, passed in rather than read
    /// off `self.env`: this crate holds source URIs, and only the syncing
    /// machine can turn a `vault:<slot>` into a value. Same by-value handoff
    /// [`RevalidateSlot::to_workload_payload`] takes, for the same reason —
    /// the node must never see a keystore slot name (R556-T12).
    pub fn serve_bundle(
        &self,
        digest: &str,
        runtime: &str,
        env: BTreeMap<String, String>,
    ) -> MesofactServeBundle {
        MesofactServeBundle {
            digest: BlakeHash(digest.to_string()),
            runtime: runtime.to_string(),
            lifecycle: self.lifecycle.clone(),
            // R599-F12: the slot's declared `port`, or `None` for kamaji's
            // node-wide default. (@Ashguard:blade parked a `None` here to
            // unblock the camp's build while this ticket was mid-flight; this
            // is the real threading it named.)
            port: self.port,
            env,
        }
    }
}

/// Closest [`ALLOWED_SLOT_KEYS`] entry to `key`, or `None` when nothing is
/// close enough to be worth suggesting (R556-B14).
///
/// The threshold scales with the key's length — one edit for a short key like
/// `port`, two for a longer one — so `prot` suggests `port` while an entirely
/// invented key suggests nothing. A confidently wrong suggestion is worse than
/// none: it sends the operator to fix a line that was never the problem.
fn nearest_slot_key(key: &str) -> Option<&'static str> {
    let budget = if key.len() <= 5 { 1 } else { 2 };
    ALLOWED_SLOT_KEYS
        .iter()
        .map(|candidate| (edit_distance(key, candidate), *candidate))
        .filter(|(d, _)| *d <= budget)
        .min()
        .map(|(_, candidate)| candidate)
}

/// Optimal string alignment (Damerau-Levenshtein restricted to adjacent
/// transpositions), three-row DP. Byte-wise: every key in this grammar is
/// ASCII, and a multi-byte typo is not a case worth carrying a char-vec for.
///
/// Transposition counts as ONE edit, not two, and that is the whole reason to
/// carry the extra row: `prot` for `port` is the motivating typo of R556-B14,
/// and plain Levenshtein scores it 2 — far enough away that a threshold tight
/// enough to avoid nonsense suggestions would refuse to suggest the one that
/// matters.
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut prev2 = vec![0usize; b.len() + 1];
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, &ac) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, &bc) in b.iter().enumerate() {
            let mut d = (prev[j] + usize::from(ac != bc))
                .min(prev[j + 1] + 1)
                .min(cur[j] + 1);
            if i > 0 && j > 0 && ac == b[j - 1] && a[i - 1] == bc {
                d = d.min(prev2[j - 1] + 1);
            }
            cur[j + 1] = d;
        }
        std::mem::swap(&mut prev2, &mut prev);
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Parse a `[…serve_build]`-shaped table into a [`BinBuild`] (R746-F2).
///
/// Taken as a helper rather than inlined because the revalidate tier's
/// `feed_bins` has the identical "a path someone must have built" problem and
/// will want the identical declaration once a recipe produces `almanac-feed`.
/// Every message names the full config coordinate so the operator gets a line
/// to open.
fn parse_bin_build(
    value: Option<&toml::Value>,
    label: &str,
    service: &str,
    env: &str,
) -> Result<Option<BinBuild>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let table = value.as_table().with_context(|| {
        format!("{label} must be a table of pipeline/binary/triples (service={service}, env={env})")
    })?;

    let pipeline = table
        .get("pipeline")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .with_context(|| {
            format!(
                "{label}.pipeline must name a QED pipeline (.yah/qed/<name>.toml) \
                 (service={service}, env={env})"
            )
        })?
        .to_string();

    let binary = table
        .get("binary")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .with_context(|| {
            format!(
                "{label}.binary must name the produced binary — it is matched against the \
                 pipeline's `[[steps.produces]] binary` (service={service}, env={env})"
            )
        })?
        .to_string();

    let triples = table
        .get("triples")
        .and_then(|v| v.as_array())
        .with_context(|| {
            format!("{label}.triples must be an array of target triples (service={service}, env={env})")
        })?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .with_context(|| {
                    format!("{label}.triples holds a non-string (or empty) entry (service={service}, env={env})")
                })
        })
        .collect::<Result<Vec<_>>>()?;

    if triples.is_empty() {
        bail!(
            "{label}.triples is empty — a build declaration that names no target builds \
             nothing, and the bundle would assemble with no serve binary at all \
             (service={service}, env={env})"
        );
    }

    Ok(Some(BinBuild {
        pipeline,
        binary,
        triples,
    }))
}

/// `lifecycle = "keep-alive" | "on-demand"` (+ `idle_ttl_ms` for the latter).
fn parse_lifecycle(
    raw: Option<&str>,
    idle_ttl_ms: Option<i64>,
    service: &str,
    env: &str,
) -> Result<BundleLifecycle> {
    match raw.unwrap_or("keep-alive") {
        "keep-alive" | "keepalive" => {
            if idle_ttl_ms.is_some() {
                bail!(
                    "providers.{SLOT_ROLE}.idle_ttl_ms only applies to `lifecycle = \"on-demand\"` \
                     — a keep-alive bundle is never reaped (service={service}, env={env})"
                );
            }
            Ok(BundleLifecycle::KeepAlive)
        }
        "on-demand" | "ondemand" | "jit" => {
            let ttl = idle_ttl_ms.unwrap_or(DEFAULT_IDLE_TTL_MS as i64);
            if ttl <= 0 {
                bail!(
                    "providers.{SLOT_ROLE}.idle_ttl_ms must be positive, got {ttl} \
                     (service={service}, env={env})"
                );
            }
            Ok(BundleLifecycle::OnDemand {
                idle_ttl: Millis::from_ms(ttl as u64),
            })
        }
        other => bail!(
            "providers.{SLOT_ROLE}.lifecycle must be \"keep-alive\" or \"on-demand\", got \
             {other:?} (service={service}, env={env})"
        ),
    }
}

/// Parse the optional `[providers.bundle.revalidate]` sub-table.
///
/// `None` → no revalidate receiver declared (the common case). `Some` → the
/// deploy also stands up a `mesofact serve --revalidate` process.
fn parse_revalidate_slot(
    fields: &BTreeMap<String, toml::Value>,
    service: &str,
    env: &str,
) -> Result<Option<RevalidateSlot>> {
    let sub = match fields.get(REVALIDATE_KEY) {
        None => return Ok(None),
        Some(v) => v.as_table().with_context(|| {
            format!(
                "providers.{SLOT_ROLE}.{REVALIDATE_KEY} must be a TOML table \
                     (service={service}, env={env})"
            )
        })?,
    };

    let routes = match sub.get("routes") {
        None => Vec::new(),
        Some(v) => {
            let list = v.as_array().with_context(|| {
                format!(
                    "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.routes must be an array of route \
                     patterns (service={service}, env={env})"
                )
            })?;
            list.iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .with_context(|| {
                            format!(
                                "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.routes holds a non-string \
                                 (or empty) entry (service={service}, env={env})"
                            )
                        })
                })
                .collect::<Result<Vec<_>>>()?
        }
    };

    let mirror_key_env = sub
        .get("mirror_key_env")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let publish_config = sub
        .get("publish_config")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    // ── Feed-fetch tier (R330-F31) ──────────────────────────────────────────
    let feeds = match sub.get("feeds") {
        None => Vec::new(),
        Some(v) => {
            let list = v.as_array().with_context(|| {
                format!(
                    "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feeds must be an array of almanac \
                     feed names (service={service}, env={env})"
                )
            })?;
            list.iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .with_context(|| {
                            format!(
                                "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feeds holds a non-string \
                                 (or empty) entry (service={service}, env={env})"
                            )
                        })
                })
                .collect::<Result<Vec<_>>>()?
        }
    };

    let feed_interval_secs = match sub.get("feed_interval_secs") {
        None => None,
        Some(v) => {
            let secs = v.as_integer().filter(|n| *n > 0).with_context(|| {
                format!(
                    "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feed_interval_secs must be a positive \
                     integer number of seconds (service={service}, env={env})"
                )
            })?;
            Some(secs as u64)
        }
    };

    let feed_bins = match sub.get("feed_bins") {
        None => BTreeMap::new(),
        Some(v) => {
            let table = v.as_table().with_context(|| {
                format!(
                    "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feed_bins must be a table of \
                     <target-triple> = <path> (service={service}, env={env})"
                )
            })?;
            table
                .iter()
                .map(|(triple, path)| {
                    let p = path.as_str().filter(|s| !s.is_empty()).with_context(|| {
                        format!(
                            "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feed_bins.{triple} must be \
                                 a non-empty path string (service={service}, env={env})"
                        )
                    })?;
                    Ok((triple.clone(), PathBuf::from(p)))
                })
                .collect::<Result<BTreeMap<_, _>>>()?
        }
    };

    // R746-T3: the vanilla shape's fetcher. A ref, not a path — the node
    // resolves it from the shared runtime-asset cache the same way it resolves
    // `serve`, so no cross-built binary has to exist on the syncing machine.
    let feed_runtime = match sub.get("feed_runtime") {
        None => None,
        Some(v) => {
            let s = v.as_str().filter(|s| !s.is_empty()).with_context(|| {
                format!(
                    "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feed_runtime must be a non-empty \
                     runtime reference like \"{FEED_BIN_NAME}/0.8.22\" (service={service}, \
                     env={env})"
                )
            })?;
            // Parse offline so a typo fails the apply with a file to open,
            // rather than a node failing to resolve it twenty minutes later.
            yah_mesofact_bundle::RuntimeRef::parse(s).with_context(|| {
                format!(
                    "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feed_runtime (service={service}, \
                     env={env})"
                )
            })?;
            Some(s.to_string())
        }
    };

    // Declared, never inferred — the same rule serve_bins/serve_build follow.
    // "Use the path if it happens to exist, else the ref" would make the
    // deployed fetcher a function of the syncing machine's disk.
    if !feed_bins.is_empty() && feed_runtime.is_some() {
        anyhow::bail!(
            "providers.{SLOT_ROLE}.{REVALIDATE_KEY} declares BOTH feed_bins and feed_runtime — \
             pick one: feed_bins stages the `{FEED_BIN_NAME}` fetcher into the bundle (the \
             self-contained shape), feed_runtime resolves it from the node's runtime-asset \
             cache (the vanilla shape) (service={service}, env={env})"
        );
    }

    // Declaring feeds without shipping the fetcher is the failure that looks
    // like success: the deploy goes green, the receiver serves, and the data
    // never moves again. Catch it here, offline, with the file to edit.
    if !feeds.is_empty() && feed_bins.is_empty() && feed_runtime.is_none() {
        anyhow::bail!(
            "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feeds declares {} feed(s) but neither \
             feed_bins nor feed_runtime — the node has no way to get the `{FEED_BIN_NAME}` \
             fetcher, so nothing would ever refresh them (service={service}, env={env})",
            feeds.len()
        );
    }

    Ok(Some(RevalidateSlot {
        routes,
        mirror_key_env,
        publish_config,
        feeds,
        feed_interval_secs,
        feed_bins,
        feed_runtime,
    }))
}

/// Resolve the machines a published bundle deploys to, in deploy order.
///
/// Two declaration forms, checked in that order:
/// 1. `machines = ["us-east-001", …]` — explicit, ordered, and the shape to
///    prefer while a bundle binds loopback (F10: one bundle per node, passway
///    co-located), because *which* nodes serve is then an operator decision
///    rather than a scheduler outcome.
/// 2. `required = { regions = […], mesh_tags = […], replicas = N }` — F16
///    placement. Resolves to the first `N` machines the constraint matches
///    (`replicas` absent = one, the only shape on disk before R844-F8).
///
/// An undeclared / unresolvable placement is an error, not an empty deploy —
/// silently publishing a bundle nobody serves is the failure mode this avoids.
/// So is a *short* one: `replicas = 2` matching a single machine fails here
/// rather than deploying one copy, because the front door would then publish a
/// hostname whose backend set is quietly half of what the mirror declared.
///
/// **R844-F8: the constraint arm shares its selector with the ingress
/// planner's.** [`CloudConfig::resolve_machines`] and
/// [`super::ingress::resolve_ingress_placements`] both bottom out in the same
/// N-selecting `select_matching` over the same `cfg.machines` slice, so the
/// deployer and the discovery fanout cannot pick different subsets of a
/// scale-N placement. The `machines = [...]` arm above needs no such
/// guarantee — the planner reads that literal list off the slot directly.
pub fn resolve_bundle_machines<'a>(
    cfg: &'a CloudConfig,
    mirror: &MirrorConfig,
    slot: &BundleSlot,
    service: &str,
    env: &str,
) -> Result<Vec<&'a crate::MachineConfig>> {
    if !slot.machines.is_empty() {
        return slot
            .machines
            .iter()
            .map(|name| {
                cfg.machine(name).with_context(|| {
                    format!(
                        "providers.{SLOT_ROLE}.machines names {name:?}, which is not declared in \
                         .yah/infra/machines/ (service={service}, env={env})"
                    )
                })
            })
            .collect();
    }

    let required = mirror
        .providers
        .get(SLOT_ROLE)
        .and_then(|s| s.required())
        .filter(|r| !r.is_unconstrained())
        .with_context(|| {
            format!(
                "providers.{SLOT_ROLE} declares neither `machines = [...]` nor a constrained \
                 `required = {{ … }}` placement — a bundle must name the nodes that serve it \
                 (service={service}, env={env})"
            )
        })?;

    cfg.resolve_machines(&required).with_context(|| {
        format!(
            "F16 placement: cannot place providers.{SLOT_ROLE}.required ({}) onto {} machine(s) \
             — check .yah/services/{service}/mirrors/{env}.toml against .yah/infra/machines/*.toml",
            required.describe(),
            required.replica_count(),
        )
    })
}

/// Desktop-side (offline) half of the bundle tier: validate the mirror's
/// declaration and bail with a pointer at the CLI.
///
/// The real chain — build, assemble, publish, deploy — runs at the apply layer
/// where [`CloudConfig`] is in hand. This exists so a desktop bring-up of a
/// bundle-tier mirror reports a *configuration* verdict instead of "no
/// reconciler wired".
pub struct MesofactBundleReconciler;

impl MesofactBundleReconciler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MesofactBundleReconciler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Reconciler for MesofactBundleReconciler {
    fn kind(&self) -> &'static str {
        super::mesofact_static::WORKLOAD_KIND
    }

    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        let slot = BundleSlot::parse(ctx.mirror, &ctx.service.name, ctx.env)?;
        // Name the DECLARED shape, not a count. R746-F2 added a third shape, and
        // a bare `0 serve binaries` reads identically for "vanilla, resolves the
        // node's stock runtime" and "self-contained, builds its binary on
        // demand" — two different deploys.
        let shape = match (&slot.serve_build, slot.serve_bins.len()) {
            (Some(build), _) => format!(
                "self-contained, serve binary built by QED recipe `{}` for [{}]",
                build.pipeline,
                build.triples.join(", "),
            ),
            (None, 0) => format!(
                "vanilla, node resolves runtime mesofact/{}",
                slot.runtime_version.as_deref().unwrap_or("<caller version>"),
            ),
            (None, n) => format!("self-contained, {n} declared serve binary path(s)"),
        };
        bail!(
            "bundle tier validated (bucket={}, workload={}, {shape}) for service={}, \
             env={}, but the sync arm runs at the apply layer — deploy with \
             `yah cloud mirror up {} --env {}` (machine placement needs the workspace's \
             machine set, which a desktop bring-up does not load)",
            slot.bucket,
            slot.workload_name(&ctx.service.name),
            ctx.service.name,
            ctx.env,
            ctx.service.name,
            ctx.env,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MachineConfig, MirrorProviderSlot, MirrorShape, TopologyConfig};
    use std::path::PathBuf;

    fn mirror_from(slots: BTreeMap<String, MirrorProviderSlot>) -> MirrorConfig {
        MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::SingleMachine,
            providers: slots,
            ingress: Default::default(),
            ingress_machines: Vec::new(),
            drivers: Default::default(),
            asset_aliases: BTreeMap::new(),
        }
    }

    /// Build a mirror whose `[providers.bundle]` slot is exactly `slot_toml`.
    fn mirror_with(slot_toml: &str) -> MirrorConfig {
        let slot: MirrorProviderSlot = toml::from_str(slot_toml).unwrap();
        let mut providers = BTreeMap::new();
        providers.insert(SLOT_ROLE.to_string(), slot);
        mirror_from(providers)
    }

    fn machine(name: &str, region: &str) -> MachineConfig {
        MachineConfig {
            name: name.into(),
            provider: "static".into(),
            location: None,
            server_type: None,
            hosts_mirrors: vec![],
            mesh_tags: vec![],
            region: Some(region.into()),
            zone: None,
            arch: Some("x86_64".into()),
            bucket: None,
            vendor: None,
            nickname: None,
            legacy_hostkey_fingerprint: None,
            registration: Default::default(),
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
            allocatable: None,
            taints: vec![],
            sovereign_group: None,
            sovereign_role: None,
        }
    }

    fn cfg_with(machines: Vec<MachineConfig>) -> CloudConfig {
        CloudConfig {
            workspace_root: PathBuf::new(),
            machines,
            providers: vec![],
            machine_origins: BTreeMap::new(),
            provider_origins: BTreeMap::new(),
            services: BTreeMap::new(),
            domains: BTreeMap::new(),
            legacy_mirrors: vec![],
            workloads: vec![],
            topology: TopologyConfig::default(),
            legacy_services: vec![],
        }
    }

    #[test]
    fn slot_declared_keys_off_the_bundle_role() {
        assert!(slot_declared(&mirror_with(
            r#"use = "cloudflare"
bucket = "b""#
        )));
        assert!(!slot_declared(&mirror_from(BTreeMap::new())));
    }

    /// R330-B43 regression pin. This is the exact shape that froze yah.dev:
    /// a fully-valid `[providers.bundle]` slot whose serve binary was never
    /// built. `slot_declared` says yes (it only reads config), so dispatching
    /// on it alone handed the component to a tier that could not come up while
    /// taking the working static chain out of the picture. `slot_ready` is what
    /// the dispatch gate must ask instead.
    #[test]
    fn a_declared_slot_whose_serve_bin_is_absent_is_not_ready() {
        let root = tempfile::tempdir().unwrap();
        let mirror = mirror_with(
            r#"
use = "cloudflare"
bucket = "yah-dev"

[serve_bins]
x86_64-unknown-linux-musl = "target/x86_64-unknown-linux-musl/release/mesofact"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "yah-marketing", "cloud").unwrap();

        assert!(slot_declared(&mirror), "config declares the slot");
        assert!(
            !slot_ready(&slot, root.path()),
            "but it cannot serve — the binary does not exist"
        );

        let missing = missing_bins(&slot, root.path());
        assert_eq!(missing.len(), 1);
        assert_eq!(
            missing[0].0, "providers.bundle.serve_bins.x86_64-unknown-linux-musl",
            "the label must name the exact config line to fix"
        );
    }

    #[test]
    fn a_slot_becomes_ready_once_its_bins_exist() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("target/x86_64-unknown-linux-musl/release");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("mesofact"), b"#!/bin/sh\n").unwrap();

        let mirror = mirror_with(
            r#"
use = "cloudflare"
bucket = "yah-dev"

[serve_bins]
x86_64-unknown-linux-musl = "target/x86_64-unknown-linux-musl/release/mesofact"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "yah-marketing", "cloud").unwrap();
        assert!(slot_ready(&slot, root.path()));
        assert!(missing_bins(&slot, root.path()).is_empty());
    }

    /// R746-F2. The shape B43 could not express: self-contained, declared, and
    /// buildable *from any machine* — so it is ready without anyone having a
    /// binary on disk, and there is no `missing:` line to print because nothing
    /// was ever promised to be there.
    #[test]
    fn a_serve_build_slot_is_self_contained_and_ready_with_no_binary_on_disk() {
        let root = tempfile::tempdir().unwrap();
        let mirror = mirror_with(
            r#"
use = "cloudflare"
bucket = "yah-dev"

[serve_build]
pipeline = "mesofact-musl"
binary = "mesofact"
triples = ["x86_64-unknown-linux-musl"]
"#,
        );
        let slot = BundleSlot::parse(&mirror, "yah-marketing", "cloud").unwrap();

        let build = slot.serve_build.as_ref().expect("serve_build parsed");
        assert_eq!(build.pipeline, "mesofact-musl");
        assert_eq!(build.binary, "mesofact");
        assert_eq!(build.triples, vec!["x86_64-unknown-linux-musl".to_string()]);

        assert!(slot.is_self_contained(), "declared shape, not disk state");
        assert!(slot_ready(&slot, root.path()));
        assert!(missing_bins(&slot, root.path()).is_empty());
    }

    /// R746-F2 verify #1, at the only layer that can pin it offline: a vanilla
    /// slot carries no build declaration at all, so the sync has nothing to
    /// dispatch. The cheapness of the vanilla path is structural, not a
    /// heuristic someone has to keep true.
    #[test]
    fn a_vanilla_slot_declares_no_build_so_a_sync_has_nothing_to_dispatch() {
        let mirror = mirror_with(
            r#"
use = "cloudflare"
bucket = "yah-dev"
runtime_version = "0.8.22"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "yah-marketing", "cloud").unwrap();
        assert!(slot.serve_build.is_none());
        assert!(slot.serve_bins.is_empty());
        assert!(!slot.is_self_contained());
        assert_eq!(slot.runtime_version.as_deref(), Some("0.8.22"));
    }

    /// The shape must stay DECLARED, never derived — so the two ways of naming
    /// a serve binary are mutually exclusive rather than one falling back to
    /// the other. A fallback would make the deployed binary a function of the
    /// syncing machine's disk.
    #[test]
    fn serve_bins_and_serve_build_together_are_refused() {
        let mirror = mirror_with(
            r#"
use = "cloudflare"
bucket = "yah-dev"

[serve_bins]
x86_64-unknown-linux-musl = "some/path/mesofact"

[serve_build]
pipeline = "mesofact-musl"
binary = "mesofact"
triples = ["x86_64-unknown-linux-musl"]
"#,
        );
        let err = BundleSlot::parse(&mirror, "yah-marketing", "cloud").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("BOTH `serve_bins` and `serve_build`"), "{msg}");
    }

    /// Each field is load-bearing, so each absence is refused by name rather
    /// than defaulted into a build that produces nothing.
    #[test]
    fn a_serve_build_missing_a_field_is_refused_naming_the_coordinate() {
        let cases = [
            (
                r#"[serve_build]
binary = "mesofact"
triples = ["x86_64-unknown-linux-musl"]"#,
                "serve_build.pipeline",
            ),
            (
                r#"[serve_build]
pipeline = "mesofact-musl"
triples = ["x86_64-unknown-linux-musl"]"#,
                "serve_build.binary",
            ),
            (
                r#"[serve_build]
pipeline = "mesofact-musl"
binary = "mesofact""#,
                "serve_build.triples",
            ),
            (
                r#"[serve_build]
pipeline = "mesofact-musl"
binary = "mesofact"
triples = []"#,
                "serve_build.triples is empty",
            ),
        ];
        for (fragment, expected) in cases {
            let mirror = mirror_with(&format!(
                "use = \"cloudflare\"\nbucket = \"yah-dev\"\n\n{fragment}\n"
            ));
            let err = BundleSlot::parse(&mirror, "yah-marketing", "cloud").unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains(expected),
                "expected {expected:?} in error, got: {msg}"
            );
        }
    }

    /// A declared feed tier is part of "can it serve" — R330-F31 stages the
    /// fetcher as a sidecar, so a missing feed_bin strands the feed tier the
    /// same way a missing serve_bin strands the server.
    #[test]
    fn a_missing_feed_bin_also_blocks_readiness() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("target/musl");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("mesofact"), b"x").unwrap();

        let mirror = mirror_with(
            r#"
use = "cloudflare"
bucket = "yah-dev"

[serve_bins]
x86_64-unknown-linux-musl = "target/musl/mesofact"

[revalidate]
routes = ["/releases"]
feeds = ["releases"]

[revalidate.feed_bins]
x86_64-unknown-linux-musl = "target/musl/almanac-feed"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "yah-marketing", "cloud").unwrap();
        let missing = missing_bins(&slot, root.path());
        assert_eq!(missing.len(), 1, "only the feed binary is absent");
        assert!(missing[0].0.contains("revalidate.feed_bins"));
        assert!(!slot_ready(&slot, root.path()));
    }

    /// A vanilla-runtime slot declares no binaries at all. That is a different
    /// shape, not a half-built one, so it stays "ready" here and fails later
    /// with its own specific message rather than being silently downgraded.
    #[test]
    fn a_vanilla_slot_declaring_no_bins_is_ready() {
        let root = tempfile::tempdir().unwrap();
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b""#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        assert!(!slot.is_self_contained());
        assert!(slot_ready(&slot, root.path()));
    }

    #[test]
    fn parses_a_self_contained_keep_alive_slot() {
        let mirror = mirror_with(
            r#"
use = "cloudflare"
bucket = "yah-dev-bundles"
machines = ["us-east-001"]
name = "yah-marketing"

[serve_bins]
x86_64-unknown-linux-musl = "target/x86_64-unknown-linux-musl/release/mesofact-serve"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "yah-marketing", "ha").unwrap();
        assert_eq!(slot.bucket, "yah-dev-bundles");
        assert_eq!(slot.machines, vec!["us-east-001".to_string()]);
        assert_eq!(slot.workload_name("yah-marketing"), "yah-marketing");
        assert!(slot.is_self_contained());
        assert_eq!(slot.lifecycle, BundleLifecycle::KeepAlive);
    }

    #[test]
    fn workload_name_falls_back_to_the_service_name() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b""#,
        );
        let slot = BundleSlot::parse(&mirror, "scrabcake", "ha").unwrap();
        assert_eq!(slot.workload_name("scrabcake"), "scrabcake");
        assert!(!slot.is_self_contained());
    }

    #[test]
    fn on_demand_takes_the_default_idle_ttl() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
lifecycle = "on-demand""#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        assert_eq!(
            slot.lifecycle,
            BundleLifecycle::OnDemand {
                idle_ttl: Millis::from_ms(DEFAULT_IDLE_TTL_MS)
            }
        );
    }

    #[test]
    fn on_demand_honors_an_explicit_idle_ttl() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
lifecycle = "on-demand"
idle_ttl_ms = 15000"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        assert_eq!(
            slot.lifecycle,
            BundleLifecycle::OnDemand {
                idle_ttl: Millis::from_ms(15_000)
            }
        );
    }

    /// An idle TTL on a keep-alive bundle is a config mistake that would
    /// otherwise be silently ignored — the process is never reaped.
    #[test]
    fn idle_ttl_on_a_keep_alive_slot_is_rejected() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
idle_ttl_ms = 15000"#,
        );
        let err = BundleSlot::parse(&mirror, "s", "e")
            .unwrap_err()
            .to_string();
        assert!(err.contains("idle_ttl_ms"), "{err}");
        assert!(err.contains("on-demand"), "{err}");
    }

    #[test]
    fn unknown_lifecycle_names_the_legal_values() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
lifecycle = "serverless""#,
        );
        let err = BundleSlot::parse(&mirror, "s", "e")
            .unwrap_err()
            .to_string();
        assert!(err.contains("keep-alive"), "{err}");
        assert!(err.contains("on-demand"), "{err}");
    }

    /// R599-F12: the declared serving port reaches the workload spec. Without
    /// it every bundle rides kamaji's node-wide default, so a node can host
    /// exactly one.
    #[test]
    fn a_declared_port_reaches_the_serve_bundle() {
        let slot = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b"
port = 8081"#,
            ),
            "s",
            "e",
        )
        .unwrap();
        assert_eq!(slot.port, Some(8081));
        assert_eq!(
            slot.serve_bundle("a".repeat(64).as_str(), "self", BTreeMap::new())
                .port,
            Some(8081)
        );

        // Absent → kamaji's node default, the pre-R599-F12 behaviour.
        let bare = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b""#,
            ),
            "s",
            "e",
        )
        .unwrap();
        assert_eq!(bare.port, None);
        assert_eq!(
            bare.serve_bundle("a".repeat(64).as_str(), "self", BTreeMap::new())
                .port,
            None
        );
    }

    /// R556-B14: a misspelled key fails the parse naming itself, rather than
    /// deploying a wrong-but-plausible workload.
    ///
    /// `prot = 8081` is the motivating instance: it parses clean today, the
    /// port falls back to kamaji's node-wide default, and post-R599-F12 that
    /// default is whatever OTHER bundle already holds 8080 on the node. The
    /// operator sees the wrong site served, with nothing in any log naming the
    /// typo.
    #[test]
    fn an_unknown_slot_key_is_rejected_naming_the_key() {
        let err = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b"
prot = 8081"#,
            ),
            "yah-marketing",
            "cloud",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("prot"), "the error must name the typo: {err}");
        assert!(
            err.contains("did you mean `port`"),
            "one transposed character is the realistic failure — suggest the \
             fix rather than making the operator diff the docs: {err}"
        );
    }

    /// The suggester's distance metric counts a transposition as ONE edit.
    /// Plain Levenshtein scores `prot`→`port` at 2, which is far enough away
    /// that any threshold tight enough to suppress nonsense suggestions would
    /// also suppress the single typo this ticket was filed about.
    #[test]
    fn the_key_suggester_treats_a_transposition_as_one_edit() {
        assert_eq!(edit_distance("prot", "port"), 1);
        assert_eq!(edit_distance("bukcet", "bucket"), 1);
        assert_eq!(nearest_slot_key("prot"), Some("port"));
        assert_eq!(nearest_slot_key("bucket"), Some("bucket"));
        assert_eq!(nearest_slot_key("zzzzzzzzzzzzzz"), None);
    }

    /// No suggestion when nothing is close. A confidently wrong hint sends the
    /// operator to edit a line that was never the problem.
    #[test]
    fn an_unrecognizable_slot_key_is_rejected_without_a_bogus_suggestion() {
        let err = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b"
ingress_tunnel_hostname = "analytics.yah.dev""#,
            ),
            "yah-analytics",
            "cloud",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("ingress_tunnel_hostname"), "{err}");
        assert!(!err.contains("did you mean"), "{err}");
    }

    /// R556-B14's regression criterion: the allowed set is the UNION of every
    /// consumer's reads, not just `BundleSlot::parse`'s. `plan_ingress` reads
    /// `machine` / `machines` / `port` / `upstream_host` off this same table
    /// and `MirrorProviderSlot::required` reads `required` — scoping the set to
    /// one consumer would reject the live yah-marketing mirror, which carries
    /// `upstream_host`.
    #[test]
    fn keys_read_by_other_consumers_of_this_slot_are_allowed() {
        // Every non-comment key of .yah/services/yah-marketing/mirrors/cloud.toml's
        // [providers.bundle] block, as of R556-B14.
        let slot = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
verify_serving = false
bucket = "yah-dev"
name = "yah-marketing"
machines = ["us-east-001"]
port = 8080
zone = "yah.dev"
upstream_host = "100.64.0.3"
lifecycle = "keep-alive"
runtime_version = "0.8.23"

[revalidate]
routes = ["/releases", "/issues"]
mirror_key_env = "YAH_MARKETING_MIRROR_KEY"
feeds = ["releases", "yah-desktop"]
feed_interval_secs = 5
feed_runtime = "almanac-feed/0.8.22""#,
            ),
            "yah-marketing",
            "cloud",
        )
        .unwrap();
        assert_eq!(slot.bucket, "yah-dev");
        assert_eq!(slot.port, Some(8080));
        assert!(!slot.verify_serving);

        // …and the F16 placement form, whose `required` is read through the
        // slot rather than by `parse`.
        BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "yah-dev"

[required]
regions = ["us-east"]"#,
            ),
            "s",
            "e",
        )
        .unwrap();

        // …and R844-F5's portless shape: `fronted = true` with no `port`. This
        // is the same union rule one ticket later — the key is read only by
        // `plan_ingress`, but it is declared on THIS table, so rejecting it here
        // would have made the pin deletion R844-F5 exists to enable fail the
        // apply rather than land as a no-op.
        let portless = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "yah-dev"
zone = "yah.dev"
fronted = true"#,
            ),
            "s",
            "e",
        )
        .unwrap();
        assert_eq!(portless.port, None);
    }

    /// R556-T12: `[providers.bundle.env]` parses into source URIs, kept
    /// verbatim. Resolution is deliberately NOT done here — this crate is
    /// offline by construction and only the syncing machine holds the vault.
    #[test]
    fn env_sources_are_parsed_verbatim_and_not_resolved() {
        let slot = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b"

[env]
ANALYTICS_R2_ACCESS_KEY = "vault:cloudflare-r2-access-key-id"
ANALYTICS_R2_SECRET_KEY = "vault:cloudflare-r2-secret-key|env:R2_SECRET"
ANALYTICS_R2_BUCKET     = "yah-analytics""#,
            ),
            "s",
            "e",
        )
        .unwrap();
        assert_eq!(slot.env.len(), 3);
        assert_eq!(
            slot.env.get("ANALYTICS_R2_ACCESS_KEY").map(String::as_str),
            Some("vault:cloudflare-r2-access-key-id"),
            "the SOURCE is stored, never a resolved secret — this struct is \
             parsed on any machine and printed by diagnostics",
        );
        assert_eq!(
            slot.env.get("ANALYTICS_R2_SECRET_KEY").map(String::as_str),
            Some("vault:cloudflare-r2-secret-key|env:R2_SECRET"),
            "a pipe-joined fallback chain survives parsing intact",
        );
        assert_eq!(
            slot.env.get("ANALYTICS_R2_BUCKET").map(String::as_str),
            Some("yah-analytics"),
            "a bare literal is a legitimate non-secret source",
        );

        // Absent block → empty, and the serve bundle carries whatever the
        // deploy resolved (nothing, here).
        let bare = BundleSlot::parse(
            &mirror_with("use = \"cloudflare\"\nbucket = \"b\""),
            "s",
            "e",
        )
        .unwrap();
        assert!(bare.env.is_empty());
    }

    /// The resolved env reaches the workload payload — the leg that was missing
    /// entirely (R556-T12). Before it, `MesofactServeBundle` had nowhere to put
    /// credentials, so kamaji forked the serve process with an empty
    /// environment and an SSR route reading a private source 500'd per request.
    #[test]
    fn resolved_env_reaches_the_serve_bundle() {
        let slot = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b"

[env]
ANALYTICS_R2_ACCESS_KEY = "vault:cloudflare-r2-access-key-id""#,
            ),
            "s",
            "e",
        )
        .unwrap();

        let mut resolved = BTreeMap::new();
        resolved.insert("ANALYTICS_R2_ACCESS_KEY".to_string(), "AKIA".to_string());
        let sb = slot.serve_bundle(&"a".repeat(64), "self", resolved);

        assert_eq!(
            sb.env.get("ANALYTICS_R2_ACCESS_KEY").map(String::as_str),
            Some("AKIA"),
            "the node receives the VALUE; a keystore slot name must never \
             cross the wire",
        );
    }

    /// An env entry that is not a usable source string must fail the parse.
    /// The whole point of the slot is that a credential problem surfaces at
    /// sync, in milliseconds, rather than as a per-request 500 on a node.
    #[test]
    fn an_unusable_env_source_is_rejected() {
        for bad in [
            "[env]\nFOO = \"\"",
            "[env]\nFOO = \"   \"",
            "[env]\nFOO = 8081",
            "env = \"vault:x\"",
        ] {
            let toml = format!("use = \"cloudflare\"\nbucket = \"b\"\n{bad}");
            let err = BundleSlot::parse(&mirror_with(&toml), "yah-marketing", "ha")
                .unwrap_err()
                .to_string();
            assert!(err.contains("env"), "{bad}: {err}");
        }
    }

    /// A port typo must fail the parse, not silently fall back to 8080 — that
    /// fallback would land the workload on whatever bundle already holds the
    /// default port, and surface as the wrong site being served.
    #[test]
    fn an_unusable_port_is_rejected_rather_than_defaulted() {
        for bad in ["port = 0", "port = 70000", r#"port = "8081""#] {
            let toml = format!("use = \"cloudflare\"\nbucket = \"b\"\n{bad}");
            let err = BundleSlot::parse(&mirror_with(&toml), "yah-marketing", "ha")
                .unwrap_err()
                .to_string();
            assert!(err.contains("port"), "{bad}: {err}");
        }
    }

    // ── serving verification (R703-T7) ──────────────────────────────────────

    /// The check is on by default and probes the service's own domain, so a
    /// mirror that says nothing about it still gets verified.
    #[test]
    fn serving_verification_is_on_by_default_and_targets_the_service_domain() {
        let slot = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b""#,
            ),
            "yah-marketing",
            "cloud",
        )
        .unwrap();
        assert!(slot.verify_serving);
        assert_eq!(slot.zone, None);
        assert_eq!(slot.serving_zone("yah.dev"), "yah.dev");
    }

    #[test]
    fn an_explicit_zone_overrides_the_service_domain() {
        let slot = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b"
zone = "staging.yah.dev""#,
            ),
            "yah-marketing",
            "cloud",
        )
        .unwrap();
        assert_eq!(slot.serving_zone("yah.dev"), "staging.yah.dev");
    }

    #[test]
    fn verify_serving_can_be_switched_off_for_an_in_flight_migration() {
        let slot = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b"
verify_serving = false"#,
            ),
            "s",
            "e",
        )
        .unwrap();
        assert!(!slot.verify_serving);
    }

    /// `verify_serving = "false"` reading as *enabled* would leave an operator
    /// certain they had silenced a check that then fails their apply.
    #[test]
    fn a_non_boolean_verify_serving_is_rejected_rather_than_defaulted() {
        let err = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b"
verify_serving = "false""#,
            ),
            "yah-marketing",
            "cloud",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("verify_serving"), "{err}");
        assert!(err.contains("boolean"), "{err}");
    }

    #[test]
    fn a_slot_without_a_bucket_names_the_file_to_edit() {
        let mirror = mirror_with(r#"use = "cloudflare""#);
        let err = BundleSlot::parse(&mirror, "yah-marketing", "ha")
            .unwrap_err()
            .to_string();
        assert!(err.contains("bucket"), "{err}");
        assert!(
            err.contains(".yah/services/yah-marketing/mirrors/ha.toml"),
            "{err}"
        );
    }

    #[test]
    fn explicit_machines_resolve_in_declaration_order() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
machines = ["us-south-001", "us-east-001"]"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let cfg = cfg_with(vec![
            machine("us-east-001", "us-east"),
            machine("us-south-001", "us-south"),
        ]);
        let resolved = resolve_bundle_machines(&cfg, &mirror, &slot, "s", "e").unwrap();
        let names: Vec<_> = resolved.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["us-south-001", "us-east-001"]);
    }

    #[test]
    fn an_undeclared_machine_is_an_error_not_a_skip() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
machines = ["us-west-999"]"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let cfg = cfg_with(vec![machine("us-east-001", "us-east")]);
        let err = resolve_bundle_machines(&cfg, &mirror, &slot, "s", "e")
            .unwrap_err()
            .to_string();
        assert!(err.contains("us-west-999"), "{err}");
        assert!(err.contains(".yah/infra/machines/"), "{err}");
    }

    #[test]
    fn falls_back_to_f16_required_placement() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
required = { regions = ["us-east"] }"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let cfg = cfg_with(vec![
            machine("us-east-001", "us-east"),
            machine("us-south-001", "us-south"),
        ]);
        let resolved = resolve_bundle_machines(&cfg, &mirror, &slot, "s", "e").unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "us-east-001");
    }

    /// R844-F8: a constraint with `replicas = N` places N machines, and the
    /// ingress planner's resolver picks the SAME N.
    ///
    /// The set-for-set half is the assertion that matters. Both sides returning
    /// two while disagreeing about *which* two aims the discovery fanout at a
    /// node the bundle was never deployed to, and the front door then renders a
    /// subset of the backends with every line in the mirror still reading
    /// correctly. They agree here because they are one selector over one
    /// candidate slice, not two implementations that happen to match.
    #[test]
    fn a_replica_count_places_n_machines_and_the_ingress_planner_picks_the_same_n() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
zone = "scaled.yah.dev"
port = 8080
required = { regions = ["us-east"], replicas = 2 }"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let cfg = cfg_with(vec![
            machine("us-east-001", "us-east"),
            machine("us-east-002", "us-east"),
            machine("us-east-003", "us-east"),
            machine("us-south-001", "us-south"),
        ]);

        let deployed: Vec<&str> = resolve_bundle_machines(&cfg, &mirror, &slot, "s", "e")
            .unwrap()
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert_eq!(
            deployed,
            vec!["us-east-001", "us-east-002"],
            "two asked for, two placed — NOT the three the constraint matches, or \
             adding a box to the fleet would scale a production front door"
        );

        let planned = super::super::ingress::resolve_ingress_placements(&cfg.machines, &mirror)
            .unwrap()
            .remove("bundle")
            .expect("the constraint slot resolves for the planner too");
        assert_eq!(planned, deployed, "set for set, not merely in count");
    }

    /// Never a partial placement. One of two reported as success is the
    /// failure that looks like it worked.
    #[test]
    fn fewer_matches_than_replicas_fails_the_deploy_resolver() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
required = { regions = ["us-east"], replicas = 2 }"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let cfg = cfg_with(vec![
            machine("us-east-001", "us-east"),
            machine("us-south-001", "us-south"),
        ]);
        // `{:#}` — the shortfall is the *source* of the placement failure, and
        // the outer context only names the constraint and the count wanted.
        let err = format!(
            "{:#}",
            resolve_bundle_machines(&cfg, &mirror, &slot, "s", "e").unwrap_err()
        );
        assert!(err.contains("onto 2 machine(s)"), "{err}");
        assert!(err.contains("only 1 of 2"), "{err}");
        assert!(err.contains("required.regions=[us-east]"), "{err}");
        assert!(
            err.contains("us-south-001"),
            "names the pool it searched: {err}"
        );
    }

    /// Publishing a bundle no node serves is the silent failure this guards.
    #[test]
    fn no_placement_at_all_is_rejected() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b""#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let cfg = cfg_with(vec![machine("us-east-001", "us-east")]);
        let err = resolve_bundle_machines(&cfg, &mirror, &slot, "s", "e")
            .unwrap_err()
            .to_string();
        assert!(err.contains("machines"), "{err}");
        assert!(err.contains("required"), "{err}");
    }

    #[test]
    fn serve_bundle_carries_the_manifest_runtime_verbatim() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b""#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let digest = "a".repeat(64);
        let sb = slot.serve_bundle(&digest, "mesofact/0.8.20", BTreeMap::new());
        assert_eq!(sb.digest.0, digest);
        assert_eq!(sb.runtime, "mesofact/0.8.20");
        assert_eq!(sb.lifecycle, BundleLifecycle::KeepAlive);
    }

    // ── revalidate receiver parsing (R330-F12) ──────────────────────────────

    #[test]
    fn parses_revalidate_slot_with_routes_and_mirror_key_env() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
machines = ["us-east-001"]

[revalidate]
routes = ["/releases"]
mirror_key_env = "YAH_MARKETING_MIRROR_KEY"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "yah-marketing", "cloud").unwrap();
        let rv = slot.revalidate.expect("revalidate slot should parse");
        assert_eq!(rv.routes, vec!["/releases"]);
        assert_eq!(
            rv.mirror_key_env.as_deref(),
            Some("YAH_MARKETING_MIRROR_KEY")
        );
        assert!(rv.publish_config.is_none());
    }

    #[test]
    fn parses_revalidate_with_custom_publish_config() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
machines = ["us-east-001"]

[revalidate]
routes = ["/releases", "/downloads"]
publish_config = "custom-mesofact.config.toml"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let rv = slot.revalidate.unwrap();
        assert_eq!(rv.routes.len(), 2);
        assert_eq!(
            rv.publish_config.unwrap(),
            PathBuf::from("custom-mesofact.config.toml")
        );
        assert!(rv.mirror_key_env.is_none());
    }

    #[test]
    fn no_revalidate_when_section_absent() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b""#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        assert!(slot.revalidate.is_none());
    }

    #[test]
    fn revalidate_with_empty_routes_is_open_allowlist() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"

[revalidate]
mirror_key_env = "BEARER"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let rv = slot.revalidate.unwrap();
        assert!(rv.routes.is_empty());
        assert_eq!(rv.mirror_key_env.as_deref(), Some("BEARER"));
    }

    #[test]
    fn to_workload_payload_maps_fields() {
        let slot = RevalidateSlot {
            routes: vec!["/releases".into()],
            mirror_key_env: Some("MY_KEY".into()),
            publish_config: Some(PathBuf::from("cfg.toml")),
            ..bare_revalidate_slot()
        };
        let mut env = BTreeMap::new();
        env.insert("MESOFACT_S3_ACCESS_KEY_ID".into(), "ak".into());
        env.insert("MESOFACT_MIRROR_KEY".into(), "bearer1".into());
        let payload = slot.to_workload_payload(env.clone(), vec![], None);
        assert_eq!(payload.routes, vec!["/releases"]);
        assert_eq!(payload.publish_config, "cfg.toml");
        assert_eq!(payload.mirror_key_env.as_deref(), Some("MY_KEY"));
        assert_eq!(payload.env.get("MESOFACT_S3_ACCESS_KEY_ID").unwrap(), "ak");
        assert_eq!(payload.env.get("MESOFACT_MIRROR_KEY").unwrap(), "bearer1");
    }

    #[test]
    fn to_workload_payload_defaults_publish_config() {
        let payload = bare_revalidate_slot().to_workload_payload(BTreeMap::new(), vec![], None);
        assert_eq!(payload.publish_config, "mesofact.config.toml");
        assert!(payload.mirror_key_env.is_none());
        assert!(payload.routes.is_empty());
    }

    // ── Feed-fetch tier (R330-F31) ──────────────────────────────────────────

    fn bare_revalidate_slot() -> RevalidateSlot {
        RevalidateSlot {
            routes: vec![],
            mirror_key_env: None,
            publish_config: None,
            feeds: vec![],
            feed_interval_secs: None,
            feed_bins: BTreeMap::new(),
            feed_runtime: None,
        }
    }

    #[test]
    fn parses_feed_tier_declaration() {
        // A staged sidecar belongs to a self-contained bundle, so this fixture
        // declares one — R746-T3 refuses feed_bins on a vanilla slot.
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"

[serve_bins]
x86_64-unknown-linux-musl = "target/x86_64-unknown-linux-musl/release/mesofact"

[revalidate]
routes = ["/releases"]
feeds = ["releases", "yah-desktop"]
feed_interval_secs = 60

[revalidate.feed_bins]
x86_64-unknown-linux-musl = "target/x86_64-unknown-linux-musl/release/almanac-feed"
"#,
        );
        let rv = BundleSlot::parse(&mirror, "s", "e")
            .unwrap()
            .revalidate
            .unwrap();
        assert_eq!(rv.feeds, vec!["releases", "yah-desktop"]);
        assert_eq!(rv.feed_interval_secs, Some(60));
        assert_eq!(rv.feed_bins.len(), 1);
        assert!(rv.feed_bins["x86_64-unknown-linux-musl"].ends_with("almanac-feed"));
        assert!(rv.feed_runtime.is_none());
    }

    /// R746-T3: the vanilla shape's feed tier. This is the declaration that
    /// makes yah-marketing deployable from a machine with no Rust toolchain —
    /// no path to a cross-built fetcher anywhere in it.
    #[test]
    fn a_vanilla_slot_declares_its_fetcher_as_a_runtime_ref() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
runtime_version = "0.8.22"

[revalidate]
routes = ["/releases"]
feeds = ["releases"]
feed_runtime = "almanac-feed/0.8.22"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        assert!(!slot.is_self_contained());
        let rv = slot.revalidate.unwrap();
        assert_eq!(rv.feed_runtime.as_deref(), Some("almanac-feed/0.8.22"));
        assert!(rv.feed_bins.is_empty());
    }

    /// The whole point: a vanilla slot with a feed tier is READY with nothing
    /// on disk. `feed_bins` would have kept the cross-built-binary requirement
    /// alive on the syncing machine while pretending the bundle was vanilla.
    #[test]
    fn a_vanilla_feed_tier_needs_no_binary_on_the_syncing_machine() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
runtime_version = "0.8.22"

[revalidate]
feeds = ["releases"]
feed_runtime = "almanac-feed/0.8.22"
"#,
        );
        let slot = BundleSlot::parse(&mirror, "s", "e").unwrap();
        let empty = std::path::Path::new("/nonexistent-workspace-root");
        assert!(missing_bins(&slot, empty).is_empty());
        assert!(slot_ready(&slot, empty));
    }

    /// Declared, never inferred — the rule serve_bins/serve_build already
    /// follow. "Use the path if it exists, else the ref" would make the
    /// deployed fetcher a function of the syncing machine's disk.
    #[test]
    fn feed_bins_and_feed_runtime_together_are_refused() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"

[serve_bins]
x86_64-unknown-linux-musl = "target/mesofact"

[revalidate]
feeds = ["releases"]
feed_runtime = "almanac-feed/0.8.22"

[revalidate.feed_bins]
x86_64-unknown-linux-musl = "target/almanac-feed"
"#,
        );
        let err = BundleSlot::parse(&mirror, "s", "e").unwrap_err().to_string();
        assert!(err.contains("feed_bins") && err.contains("feed_runtime"), "got {err}");
    }

    /// A vanilla bundle carries no `bins/`, so a path-declared sidecar has
    /// nowhere to be staged. Caught at parse, with the remedy in the message.
    #[test]
    fn feed_bins_on_a_vanilla_slot_is_refused_naming_feed_runtime() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
runtime_version = "0.8.22"

[revalidate]
feeds = ["releases"]

[revalidate.feed_bins]
x86_64-unknown-linux-musl = "target/almanac-feed"
"#,
        );
        let err = BundleSlot::parse(&mirror, "s", "e").unwrap_err().to_string();
        assert!(err.contains("VANILLA"), "got {err}");
        assert!(err.contains("feed_runtime"), "got {err}");
    }

    /// A typo in the ref fails the apply offline, not on a node twenty minutes
    /// into a deploy.
    #[test]
    fn an_unparseable_feed_runtime_is_refused_at_parse() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"
runtime_version = "0.8.22"

[revalidate]
feeds = ["releases"]
feed_runtime = "almanac-feed"
"#,
        );
        let err = BundleSlot::parse(&mirror, "s", "e").unwrap_err().to_string();
        assert!(err.contains("feed_runtime"), "got {err}");
    }

    /// The payload the node acts on must carry the ref, or kamaji has nothing
    /// to resolve and the fetcher silently never forks.
    #[test]
    fn the_feed_runtime_ref_reaches_the_workload_payload() {
        let mut slot = bare_revalidate_slot();
        slot.feed_runtime = Some("almanac-feed/0.8.22".to_string());
        let payload = slot.to_workload_payload(BTreeMap::new(), vec![], None);
        assert_eq!(payload.feed_runtime.as_deref(), Some("almanac-feed/0.8.22"));
    }

    /// A receiver with no feed tier is the existing shape and must keep parsing
    /// — the fetcher is additive, not a new requirement on every mirror.
    #[test]
    fn revalidate_without_a_feed_tier_stays_empty() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"

[revalidate]
routes = ["/releases"]
"#,
        );
        let rv = BundleSlot::parse(&mirror, "s", "e")
            .unwrap()
            .revalidate
            .unwrap();
        assert!(rv.feeds.is_empty());
        assert!(rv.feed_bins.is_empty());
        assert_eq!(rv.feed_interval_secs, None);
    }

    /// Feeds declared with no fetcher binary is the silent-staleness trap: the
    /// deploy would go green and the data would never move. Fail at parse.
    #[test]
    fn feeds_without_feed_bins_is_rejected() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"

[revalidate]
feeds = ["releases"]
"#,
        );
        let err = BundleSlot::parse(&mirror, "s", "e")
            .unwrap_err()
            .to_string();
        assert!(err.contains("feed_bins"), "got {err}");
        assert!(err.contains("feed_runtime"), "got {err}");
        assert!(err.contains(FEED_BIN_NAME), "got {err}");
    }

    #[test]
    fn zero_feed_interval_is_rejected() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"

[revalidate]
feed_interval_secs = 0
"#,
        );
        let err = BundleSlot::parse(&mirror, "s", "e")
            .unwrap_err()
            .to_string();
        assert!(err.contains("positive integer"), "got {err}");
    }

    /// The reconciler's default and the workload-spec serde default are two
    /// copies of one number; this pins them together.
    #[test]
    fn feed_interval_default_matches_the_workload_spec_default() {
        let payload = bare_revalidate_slot().to_workload_payload(BTreeMap::new(), vec![], None);
        assert_eq!(payload.feed_interval_secs, DEFAULT_FEED_INTERVAL_SECS);

        let from_spec: workload_spec::MesofactRevalidateReceiver =
            serde_json::from_str("{}").expect("all receiver fields have serde defaults");
        assert_eq!(from_spec.feed_interval_secs, DEFAULT_FEED_INTERVAL_SECS);
    }
}
