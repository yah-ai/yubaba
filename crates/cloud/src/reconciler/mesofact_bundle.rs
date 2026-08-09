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
/// runtime_version = "0.8.20"          # vanilla bundles only (no serve_bins)
/// serve_bins = { x86_64-unknown-linux-musl = "target/…/mesofact-serve" }
/// zone = "yah.dev"                    # front door to serving-verify; defaults
///                                     # to the service's own domain
/// verify_serving = true               # default; see the field docs
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
    /// How kamaji supervises the served bundle.
    pub lifecycle: BundleLifecycle,
    /// Port the served bundle listens on (R599-F12). `None` → kamaji's
    /// node-wide default (8080), which is only correct while the node hosts a
    /// single bundle; declare one per workload to put several on a node.
    pub port: Option<u16>,
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
/// feed_bins = { x86_64-unknown-linux-musl = "target/…/almanac-feed" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevalidateSlot {
    /// Routes the receiver accepts pokes for (allowlist).
    /// Empty → all routes in the workload manifest.
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
    /// sidecar. Required when `feeds` is non-empty — the node has no other way
    /// to get it.
    pub feed_bins: BTreeMap<String, PathBuf>,
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
        }
    }
}

/// Mirrors `workload_spec`'s own default. Duplicated rather than exported
/// because the spec keeps its serde defaults private; the parse tests below
/// pin the two together.
pub const DEFAULT_FEED_INTERVAL_SECS: u64 = 300;

/// Bundle path segment the fetch tier's sidecar binary is staged under —
/// `bins/<triple>/almanac-feed`, next to `bins/<triple>/serve`.
pub const FEED_BIN_NAME: &str = "almanac-feed";

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

        Ok(Self {
            bucket,
            account,
            name,
            machines,
            runtime_version,
            serve_bins,
            lifecycle,
            port,
            revalidate,
            zone,
            verify_serving,
        })
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
    pub fn is_self_contained(&self) -> bool {
        !self.serve_bins.is_empty()
    }

    /// Build the `{digest, runtime, lifecycle}` triple a `mesofact-static`
    /// workload carries once its bundle is published.
    ///
    /// `runtime` wire-mirrors `yah_mesofact_bundle::BundleRuntime`, so it is
    /// taken from the manifest the assembler actually wrote rather than
    /// re-derived here — the manifest is what the node will verify against.
    pub fn serve_bundle(&self, digest: &str, runtime: &str) -> MesofactServeBundle {
        MesofactServeBundle {
            digest: BlakeHash(digest.to_string()),
            runtime: runtime.to_string(),
            lifecycle: self.lifecycle.clone(),
            // R599-F12: the slot's declared `port`, or `None` for kamaji's
            // node-wide default. (@Ashguard:blade parked a `None` here to
            // unblock the camp's build while this ticket was mid-flight; this
            // is the real threading it named.)
            port: self.port,
        }
    }
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

    // Declaring feeds without shipping the fetcher is the failure that looks
    // like success: the deploy goes green, the receiver serves, and the data
    // never moves again. Catch it here, offline, with the file to edit.
    if !feeds.is_empty() && feed_bins.is_empty() {
        anyhow::bail!(
            "providers.{SLOT_ROLE}.{REVALIDATE_KEY}.feeds declares {} feed(s) but no feed_bins — \
             the node has no other way to get the `{FEED_BIN_NAME}` fetcher, so nothing would \
             ever refresh them (service={service}, env={env})",
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
    }))
}

/// Resolve the machines a published bundle deploys to, in deploy order.
///
/// Two declaration forms, checked in that order:
/// 1. `machines = ["us-east-001", …]` — explicit, ordered, and the shape to
///    prefer while a bundle binds loopback (F10: one bundle per node, passway
///    co-located), because *which* nodes serve is then an operator decision
///    rather than a scheduler outcome.
/// 2. `required = { regions = […], mesh_tags = […] }` — F16 placement, same
///    grammar [`super::mesofact_runner::resolve_runner_machine`] uses. Resolves
///    to exactly one machine.
///
/// An undeclared / unresolvable placement is an error, not an empty deploy —
/// silently publishing a bundle nobody serves is the failure mode this avoids.
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

    let machine = cfg.resolve_machine(&required).with_context(|| {
        format!(
            "F16 placement: no machine satisfies providers.{SLOT_ROLE}.required ({}) — check \
             .yah/services/{service}/mirrors/{env}.toml against .yah/infra/machines/*.toml",
            required.describe(),
        )
    })?;
    Ok(vec![machine])
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
        bail!(
            "bundle tier validated (bucket={}, workload={}, {} serve binar{}) for service={}, \
             env={}, but the sync arm runs at the apply layer — deploy with \
             `yah cloud mirror up {} --env {}` (machine placement needs the workspace's \
             machine set, which a desktop bring-up does not load)",
            slot.bucket,
            slot.workload_name(&ctx.service.name),
            slot.serve_bins.len(),
            if slot.serve_bins.len() == 1 {
                "y"
            } else {
                "ies"
            },
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
            slot.serve_bundle("a".repeat(64).as_str(), "self").port,
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
            bare.serve_bundle("a".repeat(64).as_str(), "self").port,
            None
        );
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
        let sb = slot.serve_bundle(&digest, "mesofact/0.8.20");
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
        }
    }

    #[test]
    fn parses_feed_tier_declaration() {
        let mirror = mirror_with(
            r#"use = "cloudflare"
bucket = "b"

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
