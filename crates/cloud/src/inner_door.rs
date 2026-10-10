//! The **inner door** planner (R870-F23) — the `service.toml` +
//! domain-manifest join that produces a passway `PASSWAY_PATH_ROUTES_FILE`.
//!
//! ## What an inner door is, and what it is not
//!
//! R870-F15 landed path routing in passway; R870-T18 gave it a config surface
//! (a JSON mount table named by `PASSWAY_PATH_ROUTES_FILE`). Both are the
//! *consumer*. This module is the producer: given a service's declared
//! components and the domain manifest that routes them, it answers "what mount
//! table does this service's own door need, if any".
//!
//! It is an **inner** door because it sits behind the service's public one, on
//! loopback. The public door owns a hostname and terminates TLS; the inner door
//! owns one hostname's *paths* and splits them across units that deploy
//! independently. That split is the only thing it does — and it is the thing
//! the public door structurally cannot do, because the public tier routes by
//! SNI/Host and a request's path is not visible until after that.
//!
//! ## The join carries no new vocabulary
//!
//! R870-F15 claimed the join needs nothing new, and that holds up. Every input
//! already exists:
//!
//! | Field | Source |
//! |---|---|
//! | `mount` | [`ServiceComponent::mount`], normalized by [`normalize_mount`] |
//! | `headers` | the route the domain's table gives that mount's path ([`DomainConfig::route_for_path`]) |
//! | tier | [`ServiceComponent::deploy`] — the one thing R870-F23 added |
//! | `upstreams` | placement-time, so it is [`InnerDoorPlan::routes_file`]'s argument, not a config field |
//!
//! The mount/route agreement is not re-derived here: [`CloudConfig::cross_ref_validate`]
//! already *proves* a component's mount and its route's path prefix are the
//! same string, so the lookup below cannot silently mismatch — a config where
//! it would have does not load.
//!
//! ## Headers come from the ONE route table (R898-F2)
//!
//! The header column is not this module's to derive. R898-F1 compiled a
//! domain's declared routes into one ordered [`RouteTable`], and every tier —
//! the Worker, mesofact, the outer door's `ROUTE_HEADERS` — answers "what
//! governs this path" by that table's rule. [`headers_for`] therefore asks the
//! table's rule too, rather than re-deriving the join; two producers of one
//! fact is precisely what the R898 relay exists to delete.
//!
//! **And this tier is the only one that applies those headers.** Operator call,
//! 2026-09-12: the outer passway door stays a pure HOST router (path routing and
//! host routing are mutually exclusive at its boot — `HOST_ROUTING_ENV` in
//! passway's `main.rs`), so it applies no per-path headers and cannot
//! double-apply these. That settles R870-F23's open ownership question, and it
//! is what makes a bundle-tier component at a non-root mount keeping its own
//! entry here CORRECT rather than redundant: the entry points at the same bundle
//! upstream as the root and exists purely to carry that mount's headers.
//! Deleting it as a duplicate would silently strip them.
//!
//! [`RouteTable`]: crate::route_table::RouteTable
//! [`ServiceComponent::mount`]: crate::config::ServiceComponent::mount
//! [`ServiceComponent::deploy`]: crate::config::ServiceComponent::deploy
//!
//! ## The two admission rules
//!
//! Both belong here, never to passway: passway proxies whatever `PathRouter`
//! it is handed and has no view of how many components a service declares.
//!
//! 1. **A service with one independently-deployed unit gets no inner tier at
//!    all.** Enforced by construction — [`plan`] answers `Ok(None)` below two
//!    units, so there is no config to write and no process to supervise. That
//!    makes the negative assertable on the *absence* of a plan rather than on
//!    a site staying up, which is the only form of that assertion that can
//!    fail loudly.
//! 2. **A component cannot be both bundle-staged and its own workload.**
//!    Enforced by [`DeployTier`] being one field with two values rather than
//!    two independent flags: the contradictory state has no spelling. What
//!    remains checkable — that two components do not claim one mount — lives
//!    in `cross_ref_validate`'s existing loop, widened rather than duplicated.
//!
//! ## Grouping is by deployed UNIT, not by component
//!
//! Every bundle-tier component of a service shares ONE bundle workload (config
//! 1, R870-B11), so they contribute one upstream between them —
//! [`DeployedUnit::Bundle`]. They still contribute their own *mounts*, because
//! a mount is where the bundle stores that component's output
//! (`app/dist/<mount>/`) and because the domain manifest may give that path
//! response headers the root does not have. So N bundle components produce N
//! mounts and one unit, and it is the unit count that rule 1 keys on.
//!
//! @yah:ticket(R931-B4, "Inner door deploy is routed to kamaji's containerd backend and 500s on local/passway:inner-door@ (empty digest)")
//! @yah:status(review)
//! @yah:at(2026-09-22T01:09:31Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R931)
//! @yah:handoff("Tier: Warrior — this blocks the whole inner-door feature on a real hostname; it is the first use of it outside yah and it does not work. MEASURED 2026-09-21 on prod. SYMPTOM: `yah cloud mirror up noisetable-marketing --env prod` reconciled both static components fine, then failed deploying passway-inner-noisetable-marketing with `yubaba returned 500: kamaji deploy_workload: BackendRefused: containerd: image not found in containerd: cr-less ref \"local/passway:inner-door@\" — pre-pull required`. NOTE THE EMPTY DIGEST after the @. WHY THAT IS WRONG RATHER THAN A MISSING IMAGE: InnerDoorPlan::workload (inner_door.rs:553) constructs exactly that ImageRef — registry \"local\", repository \"passway\", tag \"inner-door\", digest \"\" — and the comment at the site says \"Identity metadata only — the native backend pulls nothing\". The surrounding module doc adds that the route table travels as WorkloadSpec::files and that \"only kamaji's NATIVE backend materializes those; every other backend refuses the spec by name rather than starting the door against a file that is not there\", and deploy_inner_door (app/yah/cli/src/cloud.rs:12173) has a \"rejected\" arm whose message says the same. What happened is NEITHER: the spec reached containerd and came back as a 500 asking for a pull, so it never reached a native backend to be accepted or refused by name. WHAT I CHECKED: both us-east-001 and us-west-001 run kamaji with `--native-exec-dir /var/lib/yah/kamaji/native`, so the flag is present on both; both native dirs are effectively empty (west has only a `headscale` subdir), so nothing named passway is staged; /usr/local/bin/passway DOES exist on the node but as a systemd-managed host binary — passway, passway-demux and passway-http-router are all systemd units, so the OUTER door is not a container workload at all. HYPOTHESIS, NOT ESTABLISHED: kamaji's native supervisor is behind `#[cfg(feature = \"native-exec\")]` (seen in oss/kamaji/crates/kamaji-bin/src/server.rs), so a deployed kamaji built without that feature would behave exactly like this; I could not confirm the installed binary's feature set and stopped rather than guess. Start there. CLEANUP DONE: the half-created record was destroyed via POST /workloads/passway-inner-noisetable-marketing/destroy on us-east-001, so a retry starts clean; a leftover /run/netns/passway-inner-noisetable-marketing mount unit was still active on that node afterwards.")
//! @yah:handoff("ITEM 1 (backend-selection site): oss/kamaji/crates/kamaji-bin/src/server.rs:2205 deploy_container_backend(). Predicate is spec.wants_native_exec() at line 2212 (falls to deploy_native_exec if true), then spec.wants_microvm() at 2216, then the #[cfg(feature=\"containerd-integration\")] containerd arm at 2220 if ctx.containerd is Some. wants_native_exec() (oss/yah-base/crates/workload-spec/src/lib.rs:3411) is purely annotation-based: annotations[\"yah.exec\"] == \"native\" (NATIVE_EXEC_ANNOTATION/NATIVE_EXEC_VALUE, lib.rs:4356/4361). Routing has nothing to do with runtime flags at this call site — it only reads the spec.")
//! @yah:handoff("ITEM 2 (why it landed on containerd): CONFIRMED, and the prior hypothesis (kamaji built without the native-exec cargo feature) is KILLED, not just unconfirmed. Root cause: InnerDoorPlan::workload() (oss/yubaba/crates/cloud/src/inner_door.rs, was line 617) built its WorkloadSpec with `annotations: HashMap::new()` -- the native-exec marker was simply never set on the inner-door spec. Confirmed by contrast with the one other native-exec appliance in the tree, headscale_appliance.rs:356 appliance_spec(), which explicitly does `annotations.insert(NATIVE_EXEC_ANNOTATION, NATIVE_EXEC_VALUE)` with a comment naming exactly this routing. Since wants_native_exec() reads only spec.annotations, the inner-door spec would have fallen through to containerd regardless of whether the installed kamaji has --native-exec-dir configured or the native-exec cargo feature compiled in -- both of which were already confirmed present on both prod nodes by the prior courier, making the feature-flag theory moot even before this fix.")
//! @yah:handoff("ITEM 3 (guard landed): Fixed at the true source -- oss/yubaba/crates/cloud/src/inner_door.rs InnerDoorPlan::workload(): added `annotations.insert(NATIVE_EXEC_ANNOTATION, NATIVE_EXEC_VALUE)` and wired `annotations` (was `HashMap::new()`) into the WorkloadSpec literal, plus a NATIVE_EXEC_ANNOTATION/NATIVE_EXEC_VALUE import. This makes the spec actually reach deploy_native_exec (server.rs:2429), which ALREADY HAD the exact diagnosable-refusal guard item 3 asked for and just never got exercised: if ctx.native is None it returns BackendRefused naming the missing capability verbatim -- \"native backend not configured -- start kamaji with --native-exec-dir\" (feature present, --native-exec-dir unset) or \"kamaji built without the native-exec feature\" (feature absent) -- rather than silently falling through to containerd. No change was needed in kamaji itself; the guard was already correct, just unreachable for this workload.")
//! @yah:verify("Baseline BEFORE any edit, measured via revert-with-Edit (git stash is blocked in this camp) + `cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib inner_door -- --test-threads=1`: 21 passed, 0 failed (inner_door::tests + reconciler::ingress::tests::an_inner_door_overrides...).")
//! @yah:verify("AFTER the fix, same command: 21 passed, 0 failed -- no regression, no new test needed since no assertion in this module reads spec.annotations.")
//! @yah:verify("`cargo check --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --all-targets`: Finished clean (0 errors); the 3 warnings present are pre-existing and in files this change did not touch (app_manifest.rs:765 dead field, pond_door.rs:921 dead fn, reconciler/mod.rs:1092 non-snake-case test name).")
//! @yah:gotcha("This fix has NOT been verified live on prod -- I do not have a way to redeploy noisetable-marketing from this session per the ticket's mandate (three things only, then stop). Whoever next runs `yah cloud mirror up noisetable-marketing --env prod` should expect one of two outcomes: the inner door now deploys via kamaji's native backend (success), or it now gets a clean BackendRefused naming the missing native-exec capability on that node (which would mean us-east-001/us-west-001's --native-exec-dir wiring needs a second look despite the prior courier's check) -- either is a real diagnostic improvement over the empty-digest containerd 500.")
//! @yah:gotcha("Did not touch app/yah/cli/src/cloud.rs (owned by another courier) or oss/yubaba/crates/cloud/src/config.rs (dirty under @Miravel:eclipse) -- neither needed a change for this fix.")
//! @yah:gotcha("git-policy is `defer` in this camp right now, so the fix is left as an uncommitted working-tree edit for the operator/git-sweep to commit -- commit_sha is null by design, not an omission.")
//! @yah:handoff("FOLLOW-UP (same session, warm context): landed the guard the operator asked for, at a DIFFERENT and more precise invariant than item 3's first pass argued for. Q1 (construction sites): grepped every non-empty `WorkloadSpec{files:...}` literal and every real (non-test) `NATIVE_EXEC_ANNOTATION`/`MICROVM_EXEC_VALUE` write in oss/+app/+crates/. Found THREE production construction/mutation sites, not two: (a) oss/yubaba/crates/yubaba/src/headscale_appliance.rs:356 appliance_spec() -- builds from scratch, sets the annotation correctly. (b) oss/yubaba/crates/cloud/src/inner_door.rs InnerDoorPlan::workload() -- built from scratch, annotation MISSING, now fixed this session. (c) oss/qed/crates/velveteen-exec/src/remote.rs:989/1025 mark_native_exec()/mark_microvm() -- MUTATES an already-built container-shaped forge spec into native/microvm form and correctly sets the annotation, but that spec keeps a REAL non-empty digest (a resolved build image), so it was never exposed to this bug class regardless. Every other NATIVE_EXEC_ANNOTATION/MICROVM_EXEC_VALUE hit in the tree (oss/yubaba/crates/yubaba/src/service_records.rs, oss/yubaba/crates/cloud/src/config.rs, several kamaji test files) is inside #[cfg(test)] -- test fixtures, not deploy-path construction. So: 2 from-scratch sites total, exactly matching the ticket's original count, one of which was the bug.")
//! @yah:handoff("Q1 ALSO SURFACED A STALE DOC CLAIM WORTH RECORDING: inner_door.rs's own module doc says 'every other backend refuses the spec by name rather than starting the door against a file that is not there' about WorkloadSpec::files. That is FALSE as of R870-F27 (oss/kamaji/crates/kamaji-containerd-core/src/lib.rs plan_spec_files/stage_spec_files, wired into containerd's deploy path at oss/kamaji/crates/kamaji/src/containerd.rs:425): containerd now materializes files too (bind-mounts them into the container), and a real container spec CAN legitimately carry files -- proved by oss/yubaba/crates/yubaba/src/spec_redact.rs's own redaction test building a plain container_spec with files. Only the DOCKER backend still has no file-staging code at all. This means 'files present + no native annotation' is NOT a safe general invariant (it would reject legitimate containerd config-injection workloads) -- I did not write that check. Did not edit the stale doc comment itself since it lives in inner_door.rs's module header, outside what this follow-up touched; flagging it here rather than silently leaving a wrong claim uncorrected.")
//! @yah:handoff("Q2/DECISION (guard landed): the real, general invariant is about `image.digest`, not `files`: an empty digest is only valid on a spec whose exec_substrate() is Native or MicroVm (both backends document image as 'identity metadata only, nothing is pulled' -- wants_native_exec/wants_microvm doc comments in oss/yah-base/crates/workload-spec/src/lib.rs). A Container-substrate spec with an empty digest has no backend that can serve it: containerd/docker both resolve-by-digest before anything else runs (confirmed by reading oss/kamaji/crates/kamaji/src/containerd.rs:389's resolve_image_target_digest call, which is exactly where the original prod 500 fired). Landed the check in oss/yah-base/crates/workload-spec/src/validate.rs shape() -- the ONE shape gate both POST /workloads/deploy and POST /workloads/validate run via check_deploy_body() in oss/yubaba/crates/yubaba/src/lib.rs:5866 (read-only; not edited, and not one of the two restricted files), before admission or any backend selection. This is a shared crate (yah-base/workload-spec), not kamaji internals and not cloud.rs/config.rs -- in blast radius. I did NOT reach into kamaji-bin/src/server.rs's deploy_container_backend (server.rs:2205) or wants_native_exec's caller (server.rs:2212) even though the operator listed it as an option: that file is a 9000+ line hot spot with multiple concurrently-referenced live tickets (R850-F1, R870-F27, R881-T3, R908-T1 all cited in the very functions this ticket touches) and editing it as a one-shot courier without live-peer context felt like exactly the case CLAUDE.md's shared-tree doctrine says to yield on rather than force -- naming it here per the operator's own fallback instruction. New Err: ShapeError::Field{path: FieldPath::Image, reason: names both missing-annotation values and the unpullable ref}. Added one bad-fixture regression test (tests/fixtures/bad/image_digest_empty_no_native_marker.json, a copy of the actual inner-door shape pre-fix) and one valid-fixture regression test (tests/fixtures/valid/native_exec_empty_digest.json, the same shape WITH the annotation, to prove the check does not over-fire) -- both wired into the existing table-driven tests in tests/shape_fixtures.rs.")
//! @yah:verify("OPEN QUESTION FOR THE REVIEWER — the second-pass guard reports 108 passed / 0 failed BEFORE and AFTER, while also claiming \"regression fixtures for both the rejected and accepted shape\" were added. An unchanged test count is consistent with fixtures added INSIDE an existing table-driven test (coverage rises, count does not), but it is equally consistent with fixtures that no assertion actually reads. Confirm by reading oss/yah-base/crates/workload-spec/src/validate.rs: check that the empty-digest-requires-Native/MicroVm rule is asserted by a test that FAILS when the check is removed. A guard that cannot fail is not a guard. The leader did not re-run any of this — see the relay-level note on R931.")
//! @yah:verify("OPEN QUESTION ABOVE IS NOW ANSWERED — THE GUARD IS REAL. A separate verifying courier mutation-tested it rather than trusting the unchanged count: disabling the check in validate.rs (`if false && spec.image.digest.is_empty() && ...`) via Edit made shape_fixtures::bad_fixtures_produce_expected_shape_error FAIL with \"expected ShapeError for fixture image_digest_empty_no_native_marker but got Ok([])\". The guard was then restored by hand with Edit (never git) and the suite returned to green; git diff on validate.rs afterwards shows only the implementing courier's own added lines, so the round-trip left no residue. So the 108/108-before-and-after count was the benign case — fixtures folded into an existing table-driven test, coverage genuinely added. Also independently confirmed: InnerDoorPlan::workload() sets NATIVE_EXEC_ANNOTATION/NATIVE_EXEC_VALUE at inner_door.rs:583-584 with imports at :114-115. Note on the \"108\": that is the tests/main.rs integration suite; the crate also runs 207 lib tests, green in the same runs. cargo build -p yah exit 0.")
//!
//! @yah:ticket(R931-B8, "SSR self-fetch to own public hostname (noisetable.com/api/issues) 500s from inside mesofact-spa even though the same URL succeeds externally")
//! @yah:status(review)
//! @yah:at(2026-09-22T16:17:38Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R931)
//! @yah:severity(medium)
//! @yah:next("Get SSR-side logs/stderr for the site (mesofact-spa) component on us-east-001 for a request to /issues to see what fetch('https://noisetable.com/api/issues') actually throws or returns from inside the container.")
//! @yah:next("Confirm whether other mesofact-spa routes that self-fetch their own public origin have the same failure, or if this is specific to issues.tsx's URL construction.")
//! @yah:next("Once root-caused, the fix likely belongs in mesofact/passway (egress/hairpin routing for self-referential fetches) or in a documented convention for SSR handlers to use an internal mesh address instead of the public hostname.")
//! @yah:handoff("DIAGNOSED 2026-09-22 by noisetable R733-T26: NOT a hairpin/egress defect, and the page never fetched https://noisetable.com at all. mesofact's SSR dispatch strips Host and synthesizes req.url = \"http://dev{path_and_query}\" (oss/mesofact/crates/mesofact/src/server.rs:1006, dispatch_to_ssr). noisetable's web/landing/src/issues.tsx built its API URL as new URL(\"/api/issues\", new URL(request.url).origin), i.e. http://dev/api/issues, which resolves nowhere -> caught -> 500 'Unable to load issues'. Fixed on the noisetable side (base = SITE_ORIGIN = https://noisetable.com) and redeployed; live /issues now 200 listing the fixture, so a self-fetch to the site's own public hostname from inside mesofact-spa WORKS. Recommend closing this bug, or re-scoping it to a mesofact docs/API gap: SSR fetch handlers get a synthetic origin with no documented way to learn the public host (no Host / X-Forwarded-Host passthrough), which is a trap for any handler that reads request.url's origin.")
//! @yah:handoff("Re-scoped per the R733-T26 diagnosis (not a hairpin/egress bug; the SSR request URL had a fake origin) and fixed in mesofact: dispatch_to_ssr no longer hardcodes http://dev. The new public_origin() (oss/mesofact/crates/mesofact/src/server.rs, beside should_retry_status) builds request.url from X-Forwarded-Host, falling back to Host. The scheme comes from X-Forwarded-Proto (https only), otherwise http. A host value that is not authority-shaped, or is missing, becomes http://localhost. So new URL(request.url).origin is now the site's own public origin. Test fixtures in ssr.rs / mesofact-ssr that use http://dev/... were left alone: they are hand-built DispatchRequests, not the server path.")
//! @yah:verify("cd oss/mesofact && cargo test -p mesofact --features ssr --lib server:: — 72 passed, including the new ssr_request_url_carries_public_origin, which covers 4 cases: plain Host; XFH+XFP overriding an internal Host; an injection-shaped Host rejected; no Host.")
//! @yah:gotcha("Not deployed. Prod picks this up only after a mesofact release and a noisetable site redeploy. Passway does not set X-Forwarded-Proto (grep found none in oss/yubaba), so behind a TLS edge the origin reads http://noisetable.com. That is right for host-based self-fetch, but it is not the https origin. noisetable's SITE_ORIGIN workaround stays valid either way.")
//! @yah:handoff("HOTSHIPPED 2026-09-22 (operator call A). Runtime `mesofact/0.8.41-r931b8` was built from the yah tree by `yah qed run mesofact-musl` (run dbce5363, no CDN publish). It went out through `yah cloud bundle publish-runtime`: x86_64-musl (blake3 f62bba56…) to bucket noisetable-marketing, aarch64-musl (5505a05b…) to noisetable-staging. The noisetable mirrors now pin 0.8.41-r931b8: prod.toml was 0.8.32 (rollback note inline), staging.toml was 0.8.40. PROD: `yah cloud apply --env prod --service noisetable-marketing` EXIT=0, bundle 2aae406a…, us-east-001 Running. Live after the apply: / 200, /issues 200 (lists issues), /api/issues 200, /app/ 200; COOP/COEP present on / and /app/. STAGING (canary) apply EXIT=1, for a reason unrelated to the runtime: the inner door refused because staging's `issues` component (kind=binary) has no resolved address. The bundle is Running on us-west-011 on the new runtime, / and /app/ serve with COOP/COEP, and /issues renders its 'Unable to load issues' fallback because staging /api/issues is 404.")
//! @yah:cleanup("noisetable's prod.toml and staging.toml pin the prerelease runtime `0.8.41-r931b8`, which exists only in the noisetable-marketing and noisetable-staging buckets. After the next real mesofact release, move both pins to it; x86_64 and aarch64 runtime assets must be published to those buckets first. Staging's `issues` workload component has no address, so the staging inner door refuses; this is in the inner-door area the R931 parent covers.")

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde::Serialize;
use workload_spec::{
    EnvValue, EnvVar, ExposeSpec, HealthProbe, Healthcheck, ImageRef, InlineFile,
    LifecycleArchetype, MeshExpose, MeshIdent, Millis, NamespaceId, ResourceLimits, RestartPolicy,
    StopPolicy, TenantId, TierTag, Workload, WorkloadSpec, NATIVE_EXEC_ANNOTATION,
    NATIVE_EXEC_VALUE, RESUME_AFTER_RESTART_ANNOTATION, RESUME_AFTER_RESTART_VALUE,
};

use crate::config::{
    domain_serving_service, normalize_mount, DeployTier, DomainConfig, ServiceConfig,
};

/// Route-table `schema_version` for a table whose mounts all name fixed
/// `upstreams` — readable by every passway ever shipped.
///
/// R876-B20: this module writes the MINIMUM version that expresses the table
/// ([`routes_schema_for`]), and the node refuses to admit a table its
/// installed passway cannot read (yubaba's `inner_door_schema` module). passway's
/// `path_routes_file::SCHEMA_VERSIONS` is the reader's side of the same
/// contract.
pub const ROUTES_SCHEMA_FIXED: u32 = 1;

/// Route-table `schema_version` for a table in which any mount `discover`s.
/// The highest version this producer can write.
pub const ROUTES_SCHEMA_DISCOVER: u32 = 2;

/// Which deployed thing serves a mount.
///
/// The distinction the whole module turns on: several components can share one
/// of these, and rule 1 counts *these*, not components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeployedUnit {
    /// The service's single assembled W272 bundle — every [`DeployTier::Bundle`]
    /// component, collapsed.
    Bundle,
    /// One [`DeployTier::Workload`] component, by component id.
    Component(String),
}

/// One mount of an inner door's table, before upstream addresses exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerDoorMount {
    /// passway's mount spelling: `""` for the service root, otherwise
    /// `/segment[/segment…]`. The `service.toml` side spells the same mount
    /// without the leading slash — see [`passway_mount`].
    pub mount: String,
    /// What serves it.
    pub unit: DeployedUnit,
    /// Response headers the domain manifest gives this path (R746) — the
    /// answer of the domain's one route table, not a second join. Empty when
    /// the route governing this mount declares none, or when no route governs
    /// it at all.
    ///
    /// This tier is their sole owner; see the module doc for why the outer door
    /// cannot double-apply them, and why a bundle sub-mount's entry is not
    /// redundant.
    pub headers: BTreeMap<String, String>,
    /// The same route's `cors_origins` (R826), owned by this tier on the same
    /// terms as `headers`.
    pub cors_origins: Vec<String>,
}

/// A service's inner door, as configuration — everything but the addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerDoorPlan {
    /// Service name, for error messages and the workload name.
    pub service: String,
    /// Mounts in declaration order. Precedence is `PathRouter`'s (longest
    /// mount wins), not this vector's, so the order is presentational.
    pub mounts: Vec<InnerDoorMount>,
}

/// Translate a normalized mount (`""`, `"app"`) to passway's spelling (`""`,
/// `"/app"`).
///
/// The twin of [`normalize_mount`] on the wire side, and deliberately built by
/// composing with it rather than trimming slashes again: `/app`, `app/` and
/// `/app/` all mean one mount, and this crate already has exactly one place
/// that knows so.
///
/// passway has its own `path_route::mount_from_component` doing the same job on
/// the reading side. That is a genuine two-sided format rather than a
/// duplicated normalizer — passway is a separately released crate with its own
/// workspace, and yubaba cannot call into it — and it is handled the way the
/// wire format handles every other such risk: `PathRouter::new` is the ONE
/// validator of mount well-formedness, so a disagreement here is a loud boot
/// failure on the door, never a silently mis-served prefix.
pub fn passway_mount(raw: Option<&str>) -> String {
    match raw.map(normalize_mount) {
        Some(m) if !m.is_empty() => format!("/{m}"),
        _ => String::new(),
    }
}

/// Plan the inner door for one service, or answer `None` when it should not
/// have one.
///
/// `None` is rule 1 and is the common answer: a service whose components all
/// ship in one bundle has a single upstream, and a proxy in front of a single
/// upstream is a hop that can only add latency and a failure mode.
///
/// `Err` is reserved for a service that *needs* a door and cannot have a
/// working one — today that is exactly one case, no root mount, which would
/// produce a table that 503s every unclaimed path.
pub fn plan(
    service: &ServiceConfig,
    domains: &BTreeMap<String, DomainConfig>,
) -> Result<Option<InnerDoorPlan>> {
    let domain = domain_serving_service(domains, &service.name);

    let mut mounts: Vec<InnerDoorMount> = Vec::new();
    for component in &service.components {
        let unit = match component.deploy {
            DeployTier::Bundle => DeployedUnit::Bundle,
            DeployTier::Workload => DeployedUnit::Component(component.id.clone()),
        };
        let mount = passway_mount(component.mount.as_deref());
        let (headers, cors_origins) = headers_for(domain, &mount);
        mounts.push(InnerDoorMount {
            headers,
            cors_origins,
            mount,
            unit,
        });
    }

    // Rule 1, counted on UNITS. Three bundle components are one unit and get
    // no door; one bundle component plus one workload component are two and
    // do.
    let units: std::collections::BTreeSet<&DeployedUnit> = mounts.iter().map(|m| &m.unit).collect();
    if units.len() < 2 {
        return Ok(None);
    }

    if !mounts.iter().any(|m| m.mount.is_empty()) {
        bail!(
            "services/{}/service.toml declares {} independently-deployed units but no component \
             at the service root — every component sets a `mount`. An inner door's table needs a \
             root (\"\") mount as its catch-all; without one every path outside the declared \
             mounts 503s, which is indistinguishable from an outage. Drop the `mount` from \
             whichever component serves `/`.",
            service.name,
            units.len(),
        );
    }

    Ok(Some(InnerDoorPlan {
        service: service.name.clone(),
        mounts,
    }))
}

/// The response headers `domain`'s route table gives `mount` (passway spelling:
/// `""` or `/app`).
///
/// ## One join, not two
///
/// This used to be its own walk — the [`DomainRoute`] whose `route_path_prefix`
/// equalled the component's [`normalize_mount`], skipping headerless routes.
/// R898-F1 made a domain's routes a compiled [`RouteTable`] with ONE matching
/// rule, and the Worker, mesofact and the outer door's `ROUTE_HEADERS` all
/// answer by that rule. An inner door answering by a *different* one would serve
/// different headers on the same path than the table says are served there — two
/// producers of one fact. So the lookup goes through
/// [`DomainConfig::route_for_path`], which is [`RouteTable::match_path`]'s walk
/// over the declared routes.
///
/// Matched on the mount's PATH rather than on the route's `component`
/// reference, so a route declared as a bare prefix still contributes:
/// `cross_ref_validate` has already proved the two agree for every route that
/// names a component, and matching on the path is what makes the lookup total.
///
/// ## The consequence: the answer is order-dependent now
///
/// First-match-wins is, and the old prefix-equality join was not. A manifest
/// that puts `/*` above `/app/*` gives the ROOT's headers to `/app` — at every
/// tier, now including this one. That is the table being right rather than this
/// being wrong: `/app` is what such a manifest actually serves through the
/// outer tier, and `yah-dev.toml:108` states the contract ("routes above this
/// catch-all … Vec order = match order"). A headerless route that matches is
/// likewise an answer of "no headers", not a reason to keep looking — no
/// merging across rules (R746).
///
/// ## Why this takes a `DomainConfig` and not a compiled `RouteTable`
///
/// It would be circular. `CdnPlacement::backend_origin` resolves a route's
/// origin out of the plan's resolved unit addresses (R898-F1), so no
/// table can be compiled until the plan this function is helping build exists.
/// [`DomainConfig::route_for_path`] is the placement-free half of that same
/// table, in exactly the relationship `route_headers_json` already has to
/// [`RouteTable::headers_json`].
///
/// [`DomainRoute`]: crate::config::DomainRoute
/// [`RouteTable`]: crate::route_table::RouteTable
/// [`RouteTable::match_path`]: crate::route_table::RouteTable::match_path
/// [`RouteTable::headers_json`]: crate::route_table::RouteTable::headers_json
///
/// The route's `cors_origins` (R826) come back beside its headers: one walk
/// decides both, so a mount can never carry one route's headers and another's
/// CORS list.
fn headers_for(
    domain: Option<&DomainConfig>,
    mount: &str,
) -> (BTreeMap<String, String>, Vec<String>) {
    // passway spells the root mount `""`; a request for it is `/`.
    let path = if mount.is_empty() { "/" } else { mount };
    domain
        .and_then(|d| d.route_for_path(path))
        .map(|r| (r.headers.clone(), r.cors_origins.clone()))
        .unwrap_or_default()
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// Serialization mirror of passway's `path_routes_file::PathRoutesFile`. Kept
/// private: the supported output is [`InnerDoorPlan::routes_file`]'s string, so
/// nothing can construct a half-filled table and write it.
#[derive(Debug, Serialize)]
struct RoutesFile<'a> {
    schema_version: u32,
    routes: Vec<RouteEntry<'a>>,
}

#[derive(Debug, Serialize)]
struct RouteEntry<'a> {
    mount: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    discover: Option<RouteDiscover<'a>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    headers: &'a BTreeMap<String, String>,
    /// Omitted when empty, and that is roll safety rather than tidiness:
    /// passway parses this file with `deny_unknown_fields`, so a release that
    /// predates R826 refuses any file carrying the key. Only a mount that
    /// actually declares origins needs the newer passway (the R876-B20 shape,
    /// confined to the domains that opt in).
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    cors_origins: &'a [String],
}

/// Mirror of passway's `path_routes_file::MountDiscovery` (R936-B12).
///
/// @yah:ticket(R876-B20, "yubaba 0.8.43 writes `discover` into passway's path-routes file under schema_version 1, so any node with an older passway crash-loops its inner door; rollouts ship yubaba without the passway that can read its output")
/// @yah:status(review)
/// @yah:at(2026-10-10T03:46:38Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R876)
/// @yah:severity(high)
/// @yah:next("Bump the path-routes schema for the `discover` shape: oss/passway/crates/passway/src/path_routes_file.rs SCHEMA_VERSION 1 -> 2, so a reader that cannot parse it fails at boot naming both numbers (the mechanism that module documents) instead of 'unknown field `discover`'.")
/// @yah:next("Producer side (inner_door.rs): never write a routes schema the node's installed passway cannot read. The node has to advertise which schema its passway reads (e.g. passway reports it via a flag or its health, and yubaba reads it before writing). On a mismatch yubaba should refuse with a named error in its own log/health, not hand passway a file it will panic on.")
/// @yah:next("Rollout side: scripts/hotship.sh and roll-node.sh already refuse kamaji/yubaba protocol skew (--allow-proto-skew). Give passway the same pairing with yubaba: refuse to ship yubaba alone onto a node whose passway reads an older routes schema than the new yubaba writes. The 0.8.43-h3..h6 dev rolls shipped kamaji+yubaba only, and nothing objected.")
/// @yah:verify("Old passway (v1) + new yubaba (v2): yubaba reports the schema mismatch by name and leaves the existing routes file alone. No passway panic, no 503 for a door that was serving.")
/// @yah:verify("`scripts/hotship.sh --nodes <n> --binaries yubaba` onto a node whose passway reads v1 refuses and names the passway that also has to ship (with an explicit override flag).")
/// @yah:verify("path_routes_file.rs: a v1 file and a v2 file each parse in the binary that claims them; a v2 file in a v1-only reader fails at boot naming both numbers.")
/// @yah:gotcha("Measured 2026-10-08 on dev (us-west-011, which hosts staging.noisetable.com): yubaba+kamaji 0.8.43-h6 came from /data/yah-bin/0.8.43-h6, which contains ONLY kamaji and yubaba (installed 2026-10-07 23:52 local), while /usr/local/bin/passway dated from 2026-09-22. passway-inner-noisetable-marketing panicked 1,526 times: 'invalid PASSWAY_PATH_ROUTES_FILE ... unknown field `discover`, expected one of `mount`, `upstreams`, `headers`'. staging.noisetable.com returned 503 'no ready upstreams' until working-tree passway 0.8.44-h2 was hotshipped to 011 around 06:59Z (013/014 got 0.8.44-h3). These are hotship bytes, not a release.")
/// @yah:gotcha("Prod (us-west-001, us-east-001, us-south-001) runs a passway dated 2026-10-02 whose routes already carry `discover` and serve fine, so prod is not exposed today. Any node that skips a passway update is.")
/// @yah:gotcha("path_routes_file.rs's own design note: schema_version exists because 'producer and consumer are separately released, so a rolling upgrade genuinely sees two versions at once'. Adding `discover` while keeping v1 bypassed the one mechanism built for this case.")
/// @yah:files(oss/yubaba/crates/cloud/src/inner_door.rs)
/// @yah:files(oss/passway/crates/passway/src/path_routes_file.rs)
/// @yah:files(scripts/hotship.sh)
/// @yah:handoff("IMPLEMENTED (courier Ashguard, 2026-10-09; code only, nothing shipped). PASSWAY: path_routes_file.rs SCHEMA_VERSION -> SCHEMA_VERSIONS=&[1,2]; v1 still accepts discover (yubaba 0.8.43-0.8.45 wrote that onto live nodes; the module doc's new section 'Which versions this binary reads' records it as a consumer reading what producers in the field write). Any other version fails, naming the file's number and [1, 2]. New SCHEMAS_FLAG='--path-routes-schemas' + schemas_line() -> 'path-routes-schemas 1 2'; main.rs checks argv[1] at the top of main() and prints/exits 0 before logging/TLS/listener. Passway had NO argv parsing before, so an OLD passway ignores the flag and tries to start; the probe defends against that with env -i (no TLS env, so it panics fast) plus a timeout. passway reads the routes file once at process start (path_routes_from_env in main.rs; the reloads there are TLS-only), so there is no runtime hot-reload ordering to handle.")
/// @yah:handoff("YUBABA RENDERER (cloud/src/inner_door.rs): ROUTES_SCHEMA_VERSION replaced by ROUTES_SCHEMA_FIXED=1 / ROUTES_SCHEMA_DISCOVER=2. RouteEntry.discover is now Option (skip if None), and routes_schema_for() writes the minimum version. NOTE: routes_file() makes every mount discover (R936-B12), so today's renderer always emits v2; the v1 branch is exercised only by a unit test on routes_schema_for.")
/// @yah:handoff("NODE-SIDE GATE (new oss/yubaba/crates/yubaba/src/inner_door_schema.rs, `pub mod inner_door_schema` in lib.rs). The routes file is rendered off-node and written on-node by kamaji materialize_files at spawn. So the check sits at yubaba admission: inner_door_schema_refusal() in lib.rs runs in deploy_workload_spec_as (after the deploy lock, BEFORE any appliance-replace teardown or the kamaji handoff) and in validate_workload_spec. A refusal returns 422 {status: rejected, error} and logs tracing::error. The error names the needed schema, the passway's readable set, and 'Ship passway alongside yubaba'. kamaji never receives the spec, so the existing routes file stays as it was. The probe (PasswaySchemaProbe) runs `passway --path-routes-schemas` with env_clear, null stdin and a 2s kill timeout, caches per path+mtime+size, and runs on spawn_blocking. Missing binary, nonzero exit, timeout or unparseable output all read as {1}. It lives in yubaba, not cloud, because yubaba deliberately has no runtime dep on cloud (Cargo.toml note). INNER_DOOR_BINARY/ROUTES_DIR are therefore restated there, with a pointer to cloud's.")
/// @yah:handoff("ROLLOUT: scripts/hotship.sh has a new --allow-routes-skew flag (documented beside --allow-proto-skew) and a 'yubaba/passway pairing' guard after the kamaji/yubaba one. When yubaba ships without passway, it ssh-probes each node with `timeout 5 env -i /usr/local/bin/passway --path-routes-schemas`. If a node does not read schema 2, it refuses and prints the --binaries line with passway added, plus the override. ACTIVATION_ORDER is unchanged: all bytes are installed before the activation loop restarts any unit, and passway reads routes only at start, so a paired ship is already correctly ordered. roll-node.sh is NOT changed: it installs passway from the same release tarball as yubaba (since 0.8.33), so it cannot half-ship the pair.")
/// @yah:verify("Baseline -> after (darwin, durable logs /tmp/r876b20-*.log). passway `cargo test --manifest-path oss/passway/Cargo.toml -p passway`: lib 250 -> 252, 45 -> 45, tests/main 42 -> 43, all EXIT=0 (new: every_schema_producers_in_the_field_write_parses, the_schemas_line_names_every_version_this_binary_reads, and the forked-binary test the_binary_names_the_route_schemas_it_reads_and_exits; a_wrong_schema_version_* now uses v3 and asserts 'reads versions [1, 2]'). yah-cloud `--lib inner_door`: 21 -> 22 passed (new: a_table_writes_v1_unless_a_mount_discovers; two existing assertions moved from schema_version 1 to 2). yubaba `--lib inner_door_schema`: 5 new passed (v1-only refusal by name, admit when readable, non-door never probed, schemas-line parse, no-answer -> {1}). `cargo check -p yubaba -p yah-cloud --tests` EXIT=0. `bash -n scripts/hotship.sh` OK, and the parse/refuse logic was simulated locally on three outputs. The hotship dry-run was NOT run: its guard ssh-probes real nodes, which was out of scope (no live-fleet actions).")
/// @yah:verify("NOT RUN: the full `cargo test -p yubaba --lib` suite (only the new module's tests ran). No live verification (old passway + new yubaba on a node); that needs a fleet roll.")
/// @yah:handoff("Leader re-verified 2026-10-09 (courier @Ashguard:hydra, session:01fcc8e2). passway reads path-routes schemas {1,2}. A v1 file may still carry discover, which is the shape yubaba 0.8.43-0.8.45 wrote onto live nodes. passway now answers --path-routes-schemas. yah-cloud inner_door renders the lowest schema the table needs: v1 when no mount discovers, v2 otherwise. New oss/yubaba/crates/yubaba/src/inner_door_schema.rs is node-side and lives in yubaba because yubaba has no runtime dep on cloud. It probes /usr/local/bin/passway with env cleared and a 2s timeout, caches per path+mtime+size, and treats a silent binary as {1}. At deploy/validate it refuses with a 422 a table that passway can't read, before anything is torn down or written. scripts/hotship.sh refuses yubaba-without-passway onto a node whose passway doesn't read schema 2, overridable with --allow-routes-skew. scripts/roll-node.sh needed no change: it already installs passway with yubaba from the release manifest (since 0.8.33).")
/// @yah:verify("Leader re-run: cargo test --manifest-path oss/passway/Cargo.toml -p passway = 252 + 45 + 43 passed / 0 failed (courier's baseline 250/45/42). yah-cloud --lib inner_door = 22 passed (baseline 21). yubaba --lib (full) = 1089 passed / 0 failed, including inner_door_schema. bash -n scripts/hotship.sh OK. NOT run: the hotship refusal against a live node (no fleet action in scope).")
#[derive(Debug, Serialize)]
struct RouteDiscover<'a> {
    ident: String,
    yubaba: &'a [String],
}

/// How often an inner door re-reads its units' service records, in seconds.
/// See [`InnerDoorPlan::workload`].
pub const DISCOVERY_INTERVAL_SECS: u64 = 2;

/// @yah:ticket(R931-B6, "Inner-door render refuses noisetable-marketing route table: Bundle mount has no resolved address yet")
/// @yah:status(review)
/// @yah:at(2026-09-22T05:45:52Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R931)
/// @yah:severity(high)
/// @yah:gotcha("FOUND BY THE NOISETABLE CAMP (R733-T26, @Miravel:libra) while re-running `yah cloud mirror up noisetable-marketing --env prod` after yah R931-B5's kamaji.service fix (StateDirectory/ReadWritePaths for passway/routes) was rolled to us-east-001 and kamaji restarted (2026-09-22). R931-B5 IS CONFIRMED WORKING for its own scope — the read-only-filesystem EROFS on /var/lib/passway/routes/*.routes.json is GONE. This is the next layer down, not a regression of B5.")
/// @yah:assumes("The `site`/`app` mesofact-spa/mesofact-static components published and went Running cleanly (bundle digest 8e77c1b448fafabe172bf774f931c1426cace9fe1f0f8f5eebee658c1af21dd6, build_id 9481d540db93867ce8727ce2b7bffd8b, runtime mesofact/0.8.32) throughout this run; only the `issues` (binary/inner-door) component failed.")
/// @yah:next("Gate for R733-T26: once this reaches review, re-run `yah cloud mirror up noisetable-marketing --env prod` and redo the five-point verification (root 200+title, /app/ 200, GET /api/issues 200 body-free projection, POST tests/fixtures/chloro_edit_failure_post.json -> 201+ULID, /issues renders the list).")
/// @yah:gotcha("Exact error from `yah cloud mirror up noisetable-marketing --env prod` (run 2026-09-22, ready service records [\"us-east-001\", \"us-south-001\", \"us-west-001\"]): `Error: rendering the inner door for noisetable-marketing/prod from the ready service records of [\"us-east-001\", \"us-south-001\", \"us-west-001\"]: service noisetable-marketing: mount \"\" is served by Bundle, which has no resolved address yet. Refusing to write a partial route table -- a missing mount does not 503, it falls through to the root mount and serves the wrong component with a 200.` Source: oss/yubaba/crates/cloud/src/inner_door.rs:348-349. Live verification after the failed attempt: https://noisetable.com/ 200 (title correct), /app/ 200, GET /api/issues 404 (body is the marketing SPA HTML shell, not the issues service's body-free projection), GET /issues 500 (F25's client error page). No rollback needed -- / and /app/ never left 200.")
/// @yah:handoff("FIXED in app/yah/cli/src/cloud.rs. Root cause is R931-B7 defect (2), not an ident or config fault: deploy_inner_door read ready service records ONCE right after the deploy phase (re)deployed the bundle, so the bundle ident had no record yet and InnerDoorPlan::workload refused the table. B7's own measurements show the identical error passing on a re-run a minute later. FIX: ReadyRecordWait gained a generic `resolve_with<T>(read, attempt, idle)` loop (resolve_plan is now a thin wrapper over it — one loop, two consumers), and deploy_inner_door runs resolve_addresses + workload() inside it under ReadyRecordWait::APPLY (90s budget, 5s interval), with a one-time stderr notice. The refusal in inner_door.rs:349 is unchanged — a partial table is still never written; it is now retried rather than surfaced on the first read. This also closes B7's defect (2); B7 keeps only defect (1), the needless re-fork.")
/// @yah:verify("LIVE GATE (not run by me, prod-facing): re-run `yah cloud mirror up noisetable-marketing --env prod`, then the five-point check in this ticket's next — R733-T26's gate.")
/// @yah:assumes("resolve_workload_ident(mirror, 'noisetable-marketing', 'prod') yields the ident the bundle actually registers ('noisetable' per the west passway log in B7). Inferred from B7's 'next run a minute later succeeded', not re-read against the mirror toml.")
/// @yah:verify("`cargo test -p yah --lib ready_record_wait` = 5 passed / 0 failed, EXIT 0 (new: the_inner_door_waits_for_the_bundle_record_instead_of_refusing_the_table). Log /tmp/r931b6-t2.log.")
/// @yah:verify("LIVE, 2026-09-22, CLI installed via `cargo xtask install`: five `yah cloud mirror up noisetable-marketing --env prod` runs from ~/ss/noisetable, all EXIT 0. Each rendered the inner door (/ and /app → 100.64.0.3:41507, /api/issues → 10.128.1.2:4333) and ended 'noisetable.com is serving this bundle'. Not one hit the 'no resolved address yet' refusal, including the runs where the bundle was re-forked just before.")
impl InnerDoorPlan {
    /// Every distinct unit this door proxies to, in a stable order. What a
    /// caller resolving addresses has to answer for.
    pub fn units(&self) -> Vec<DeployedUnit> {
        let set: std::collections::BTreeSet<DeployedUnit> =
            self.mounts.iter().map(|m| m.unit.clone()).collect();
        set.into_iter().collect()
    }

    /// Render the JSON passway reads: each mount names its unit's mesh ident
    /// and every yubaba that could hold that unit's service record.
    ///
    /// No addresses (R936-B12). The table used to bake each unit's
    /// `host:port` in at deploy time, so it pointed at whichever node ran the
    /// unit THEN, and a unit the cluster later moved — or a node that died —
    /// left every door routing to an address nothing answered. noisetable.com
    /// went 503 on all three doors that way when us-east-001 was powered off.
    /// Discovering by ident makes the door follow the unit on its next poll.
    ///
    /// `yubaba` must name every node a unit may run on: a unit is only found
    /// where it is polled for. An empty list is refused, since every mount
    /// would then discover nothing and 503.
    pub fn routes_file(&self, bundle_ident: &str, yubaba: &[String]) -> Result<String> {
        if yubaba.is_empty() {
            bail!(
                "service {}: an inner door needs at least one yubaba to discover its units \
                 from, and was given none",
                self.service
            );
        }
        let mut routes = Vec::with_capacity(self.mounts.len());
        for m in &self.mounts {
            routes.push(RouteEntry {
                mount: &m.mount,
                discover: Some(RouteDiscover {
                    ident: self.unit_ident(&m.unit, bundle_ident),
                    yubaba,
                }),
                headers: &m.headers,
                cors_origins: &m.cors_origins,
            });
        }
        Ok(serde_json::to_string(&RoutesFile {
            schema_version: routes_schema_for(&routes),
            routes,
        })?)
    }
}

/// The lowest `schema_version` that expresses `routes` (R876-B20): v1 unless a
/// mount discovers, so a table that needs nothing new is readable by every
/// passway in the field.
fn routes_schema_for(routes: &[RouteEntry<'_>]) -> u32 {
    if routes.iter().any(|r| r.discover.is_some()) {
        ROUTES_SCHEMA_DISCOVER
    } else {
        ROUTES_SCHEMA_FIXED
    }
}

// ── Supervision ──────────────────────────────────────────────────────────────

/// The passway binary every node carries, installed by the yubaba release
/// tarball's `control_plane_install`. The inner door is the *same* binary as
/// the public door — one door implementation, two configurations, which is the
/// property R870-F15 built path routing to preserve.
pub const INNER_DOOR_BINARY: &str = "/usr/local/bin/passway";

/// Where a node keeps generated route tables. Same directory the demux and
/// http-router tables already live in.
pub const ROUTES_DIR: &str = "/var/lib/passway/routes";

/// The only address an inner door ever binds, and the only one the outer door
/// ever dials it at. Literal rather than a parameter — see
/// [`InnerDoorPlan::workload`].
pub const INNER_DOOR_HOST: &str = "127.0.0.1";

/// Where every door host keeps its sovereign group's cluster key (R876-T18
/// step 2, 0600 root). Every door — outer and inner — names it as
/// `PASSWAY_YUBABA_CLUSTER_KEY_FILE` so its yubaba polls carry a peer token.
/// A door naming a key file it cannot read refuses to boot, so a new door host
/// needs the key before any door is placed on it.
pub const DOOR_CLUSTER_KEY_FILE: &str = "/etc/yah-cloud/cluster.key";

/// Low end of the window [`listen_port`] picks from, inclusive.
pub const INNER_DOOR_PORT_LOW: u16 = 10_000;
/// High end of the window [`listen_port`] picks from, inclusive.
pub const INNER_DOOR_PORT_HIGH: u16 = 19_999;

/// The loopback port a service's inner door listens on — derived from the
/// service name, so every apply of an unchanged tree renders the same number.
///
/// ## Why a derived pin rather than kamaji's ledger
///
/// R870-F23 phase 2 preferred taking the number from `kamaji::ports`
/// ([`LedgerPorts`], `oss/kamaji/crates/kamaji/src/ports.rs`). Read rather than
/// assumed, that ledger cannot answer here, for three reasons that also happen
/// to make a pin safe:
///
/// 1. **It is node-local and has no RPC.** `LedgerPorts` persists
///    `(ident, name) -> port` to a JSON file beside the supervisor's state dir,
///    and yubaba's HTTP surface exposes no allocation verb (`yubaba/src/lib.rs`
///    routes `/workloads/*`, `/services`, `/node/*` — nothing for ports). An
///    apply running on an operator's laptop has no way to ask.
/// 2. **A pin is honoured, not rejected, on the path this workload takes.**
///    R844-F14's rule — a non-world-fixed pin is an error — bites in
///    `LedgerPorts::resolve_set`, and `NativeRuntime::resolve_declared_ports`
///    (`kamaji/src/native.rs:280`) filters `pin.is_none()` *before* calling it.
///    A stated number is therefore passed through, which is what
///    `PASSWAY_LISTEN` needs: the door's own env has to carry the number, and
///    a number the node picked after the spec was rendered could not be in it.
/// 3. **A collision is not even representable.** The ledger allocates on the
///    workload's *mesh* IP; an inner door binds loopback. `100.64.0.3:14210`
///    and `127.0.0.1:14210` are different sockets.
///
/// The window is deliberately below Linux's default ephemeral range
/// (32768-60999), which is where `pick_free_port`'s `bind(:0)` draws from — so
/// a derived number cannot land on one the ledger is about to hand out even on
/// the same interface.
///
/// The hash is FNV-1a written out here rather than `DefaultHasher`, whose
/// output std explicitly does not promise to keep stable across releases. This
/// number is written into a deployed door's environment and into the outer
/// door's upstream list; a toolchain bump silently moving it would repoint one
/// tier and not the other.
pub fn listen_port(service: &str) -> u16 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in service.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let span = u64::from(INNER_DOOR_PORT_HIGH - INNER_DOOR_PORT_LOW) + 1;
    INNER_DOOR_PORT_LOW + (hash % span) as u16
}

/// The mesh identity a [`DeployTier::Workload`] component registers its service
/// record under.
///
/// **This is the naming rule, not a lookup**, and it is stated here because
/// nothing else states it. A bundle's ident comes from the mirror
/// (`BundleSlot::workload_name`, overridable by `name = "…"`), but a
/// workload-tier component has no slot of its own — `[providers.*]` is
/// per-kind, per-mirror, which is exactly the gap [`DeployTier`] was added to
/// close. So the ident has to be derivable from the two names the service
/// already declares, and this is that derivation.
///
/// Getting it wrong is a *loud* failure rather than a quiet one:
/// [`InnerDoorPlan::routes_file`] refuses a mount whose unit resolved to no
/// address, naming the unit, so a component that registered under some other
/// ident fails the apply instead of falling through to the root mount.
pub fn component_workload_ident(service: &str, component_id: &str) -> String {
    crate::reconciler::native_support::sanitize_ident(&format!("{service}-{component_id}"))
}

impl InnerDoorPlan {
    /// The workload name / mesh identity for this service's inner door.
    pub fn workload_name(&self) -> String {
        format!("passway-inner-{}", self.service)
    }

    /// Where this door's route table is materialized on the node.
    pub fn routes_path(&self) -> PathBuf {
        Path::new(ROUTES_DIR).join(format!("{}.routes.json", self.service))
    }

    /// This door's loopback port — [`listen_port`] of the service name.
    pub fn listen_port(&self) -> u16 {
        listen_port(&self.service)
    }

    /// The mesh identity whose ready service record carries `unit`'s address.
    ///
    /// The two arms come from different places on purpose, and neither is
    /// derivable from the other. A bundle's ident is a *mirror* fact —
    /// `BundleSlot::workload_name`, which a slot may rename with `name = "…"` —
    /// so it is handed in. A workload-tier component has no slot to rename it,
    /// so its ident is derived ([`component_workload_ident`]).
    pub fn unit_ident(&self, unit: &DeployedUnit, bundle_ident: &str) -> String {
        match unit {
            DeployedUnit::Bundle => bundle_ident.to_string(),
            DeployedUnit::Component(id) => component_workload_ident(&self.service, id),
        }
    }

    /// Render the supervisable workload: a passway process serving this
    /// service's mount table on loopback.
    ///
    /// ## Cleartext, and the invariant that makes it safe
    ///
    /// `PASSWAY_TLS_MODE=plaintext` (operator call, 2026-09-09 — see
    /// `passway::tls::parse_listener_tls_mode` for the full argument). The
    /// short version: no CA issues for `127.0.0.1`, so "TLS everywhere" here
    /// means a self-signed leaf plus a way to switch OFF upstream certificate
    /// verification on the *public* door — a real trust-boundary knob traded
    /// for encrypting a hop that never leaves the loopback interface.
    ///
    /// This function cannot violate that invariant even if `listen_port` is
    /// wrong, because it binds `127.0.0.1` literally and passway refuses the
    /// mode on anything else. The bind is not a parameter.
    ///
    /// ## Why `listen_port` is an argument
    ///
    /// It is placement-time knowledge, exactly like the upstream addresses:
    /// which port is free is a property of the node, not of the config. The
    /// caller allocates and passes it, so this stays a pure function of
    /// (plan, port, addresses) and is testable without a node.
    ///
    /// ## The route table travels IN the spec
    ///
    /// Not written beside it: [`WorkloadSpec::files`] makes the table and the
    /// process that reads it one deploy rather than two, so a redeploy cannot
    /// leave a door serving a stale table. Only kamaji's native backend
    /// materializes those; every other backend refuses the spec by name rather
    /// than starting the door against a file that is not there.
    ///
    /// ## Why `Workload::Container` and not a new `Workload` variant
    ///
    /// `TenantPasswayWorkload` is a typed variant, so the precedent for one
    /// exists — but it earns that by carrying config kamaji itself must act on
    /// (a domain to match, a PEM pair to re-read on every cold start, an idle
    /// TTL to reap against). An inner door carries none of it: its entire
    /// configuration is an argv, three env vars and one file, all of which
    /// `WorkloadSpec` already expresses. A variant would buy nothing but
    /// exhaustive-match churn in peer-owned `kamaji-proto`, which is the trade
    /// R572-F1 already made and recorded.
    pub fn workload(
        &self,
        listen_port: u16,
        bundle_ident: &str,
        yubaba: &[String],
    ) -> Result<Workload> {
        let routes_path = self.routes_path();
        let name = self.workload_name();
        let listen = format!("127.0.0.1:{listen_port}");

        let env = vec![
            literal_env("PASSWAY_TLS_MODE", "plaintext".to_string()),
            literal_env("PASSWAY_LISTEN", listen),
            literal_env(
                "PASSWAY_PATH_ROUTES_FILE",
                routes_path.display().to_string(),
            ),
            // R936-B12: every mount discovers its unit, so how fast the door
            // notices a unit moving IS this interval. passway's 30s default
            // would spend half of a one-minute re-home budget on noticing.
            literal_env("PASSWAY_UPDATE_INTERVAL_SECS", DISCOVERY_INTERVAL_SECS.to_string()),
            literal_env(
                "PASSWAY_HEALTH_CHECK_INTERVAL_SECS",
                DISCOVERY_INTERVAL_SECS.to_string(),
            ),
            // R876-T18: every `discover` mount polls Peer-class
            // /service-records, which a require-mode yubaba 401s unsigned.
            literal_env(
                "PASSWAY_YUBABA_CLUSTER_KEY_FILE",
                DOOR_CLUSTER_KEY_FILE.to_string(),
            ),
        ];

        let mut annotations = HashMap::new();
        // R931-B4: the marker kamaji's `deploy_container_backend` actually
        // routes on (`WorkloadSpec::wants_native_exec`). Without it the spec
        // above's empty-digest `ImageRef` — deliberately unpullable, per the
        // comment below — falls through to the containerd arm instead of ever
        // reaching kamaji's native backend, and containerd 500s asking to
        // pre-pull an image that was never meant to exist. A kamaji with no
        // native backend configured now refuses this by name
        // (`deploy_native_exec`'s "native backend not configured" /
        // "built without the native-exec feature" `BackendRefused`) instead of
        // silently mis-routing to containerd.
        annotations.insert(
            NATIVE_EXEC_ANNOTATION.to_string(),
            NATIVE_EXEC_VALUE.to_string(),
        );
        // R936-B11: survive a reboot. A native workload dies with every kamaji
        // restart and nothing else on the node remembers a direct deploy, so
        // until this the door was simply gone after one — and its outer door
        // 503'd with it. Safe to replay here because an inner door is pinned
        // to its front door by construction; see the annotation's docs for
        // why a yubaba-placed appliance must never set it.
        annotations.insert(
            RESUME_AFTER_RESTART_ANNOTATION.to_string(),
            RESUME_AFTER_RESTART_VALUE.to_string(),
        );

        let spec = WorkloadSpec {
            name: name.clone(),
            // Identity metadata only — the native backend pulls nothing.
            image: ImageRef {
                registry: "local".into(),
                repository: "passway".into(),
                tag: "inner-door".into(),
                digest: String::new(),
            },
            tier: TierTag("infra".into()),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            replicas: 1,
            command: Some(vec![INNER_DOOR_BINARY.to_string()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env,
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 128,
                cpu_millis: 256,
                memory_request_mb: None,
                cpu_limit_millis: None,
                pids_max: None,
                scratch_floor_mb: None,
            },
            depends_on: vec![],
            requires: vec![],
            healthcheck: Some(Healthcheck {
                // A cleartext listener would answer an HttpGet probe, but a
                // bare connect is the same liveness signal without asking the
                // door to route a synthetic path through a mount table that
                // may legitimately not have a catch-all for it.
                probe: HealthProbe::TcpConnect { port: listen_port },
                interval: Millis::from_secs(10),
                timeout: Millis::from_secs(2),
                initial_delay: Millis::from_secs(5),
                failure_threshold: 3,
            }),
            restart_policy: RestartPolicy::Always,
            // Pinned and non-drainable: the service's public door proxies to
            // this on loopback, so moving it to another node does not relocate
            // the thing that reaches it — it severs it.
            archetype: Some(LifecycleArchetype::Appliance),
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name),
                    ports: MeshExpose::anonymous_ports([listen_port]),
                    allow_from: vec![],
                },
                // Loopback only. Nothing off this node reaches an inner door,
                // which is the premise the cleartext listener rests on.
                public: None,
                operator: None,
            },
            labels: HashMap::new(),
            durability: None,
            db: Vec::new(),
            capabilities: Vec::new(),
            annotations,
            files: vec![InlineFile {
                path: routes_path,
                content: self.routes_file(bundle_ident, yubaba)?,
                mode: Some(0o600),
            }],
        };

        Ok(Workload::container(spec))
    }
}

fn literal_env(name: &str, value: String) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: EnvValue::Literal { value },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DomainRoute, FrontDoor, RouteMode, ServiceComponent};
    use crate::route_table::{CdnPlacement, RouteTable};

    fn component(id: &str, mount: Option<&str>, deploy: DeployTier) -> ServiceComponent {
        ServiceComponent {
            id: id.to_string(),
            kind: "mesofact-spa".to_string(),
            path: format!("app/{id}"),
            git: None,
            role: "static".to_string(),
            publishes: Some("static".to_string()),
            mount: mount.map(str::to_string),
            wave: 0,
            deploy,
            workload: None,
        }
    }

    fn service(name: &str, components: Vec<ServiceComponent>) -> ServiceConfig {
        ServiceConfig {
            schema_version: 1,
            name: name.to_string(),
            address: crate::config::ServiceAddress::front_door(format!("{name}.test")),
            description: None,
            components,
        }
    }

    fn domains(service: &str, routes: &[(&str, &[(&str, &str)])]) -> BTreeMap<String, DomainConfig> {
        let mut map = BTreeMap::new();
        map.insert(
            "test".to_string(),
            DomainConfig {
                schema_version: 1,
                name: "test".to_string(),
                domain: format!("{service}.test"),
                front_door: FrontDoor::Passway,
                cdn_bucket: "cdn".to_string(),
                worker_bundle_path: None,
                routes: routes
                    .iter()
                    .map(|(path, headers)| DomainRoute {
                        cors_origins: Vec::new(),
                        path: path.to_string(),
                        headers: headers
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect(),
                        mode: RouteMode::Static {
                            component: format!("{service}/root"),
                        },
                    })
                    .collect(),
            },
        );
        map
    }

    /// Rule 1's negative, and the cheap half of this ticket's verify list: a
    /// single-component service produces no plan at all, so there is no config
    /// to write and no process to supervise.
    #[test]
    fn a_single_unit_service_gets_no_inner_door() {
        let svc = service(
            "yah-marketing",
            vec![component("site", None, DeployTier::Bundle)],
        );
        assert_eq!(plan(&svc, &BTreeMap::new()).unwrap(), None);
    }

    /// The same negative one step further out, and the one that would be easy
    /// to get wrong: THREE components still share one bundle, so they are one
    /// unit and still earn no door.
    #[test]
    fn several_bundle_components_are_one_unit_and_still_get_no_door() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("app", Some("app"), DeployTier::Bundle),
                component("docs", Some("docs"), DeployTier::Bundle),
            ],
        );
        assert_eq!(plan(&svc, &BTreeMap::new()).unwrap(), None);
    }

    #[test]
    fn one_bundle_component_plus_one_workload_component_is_two_units() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().expect("two units");
        assert_eq!(
            plan.mounts.iter().map(|m| m.mount.as_str()).collect::<Vec<_>>(),
            ["", "/app"]
        );
        assert_eq!(
            plan.units(),
            vec![
                DeployedUnit::Bundle,
                DeployedUnit::Component("account".into())
            ]
        );
    }

    /// The header half of the join: a mount picks up exactly the headers its
    /// own route declares, and the root picks up none when its route declares
    /// none. This is the config-side half of the ticket's live assertion that
    /// `/app/` carries COOP/COEP while `/` carries neither.
    ///
    /// R898-F2 REORDERED THIS FIXTURE and changed nothing else. The assertions
    /// and the property they pin are untouched; the route list now declares
    /// `/app/*` ABOVE `/*`, which is what a legal manifest looks like under the
    /// route table's first-match-wins contract (`yah-dev.toml:108`,
    /// `noisetable-com.toml`). The old fixture declared the catch-all first,
    /// which the previous prefix-equality join was blind to and the shared
    /// matching rule is not — see [`headers_for`].
    #[test]
    fn each_mount_carries_only_its_own_routes_headers() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let domains = domains(
            "noisetable",
            &[
                (
                    "/app/*",
                    &[
                        ("cross-origin-opener-policy", "same-origin"),
                        ("cross-origin-embedder-policy", "require-corp"),
                    ],
                ),
                ("/*", &[]),
            ],
        );
        let plan = plan(&svc, &domains).unwrap().expect("two units");

        let root = &plan.mounts[0];
        assert_eq!(root.mount, "");
        assert!(root.headers.is_empty(), "{:?}", root.headers);

        let app = &plan.mounts[1];
        assert_eq!(app.mount, "/app");
        assert_eq!(
            app.headers.get("cross-origin-opener-policy").map(String::as_str),
            Some("same-origin")
        );
        assert_eq!(
            app.headers
                .get("cross-origin-embedder-policy")
                .map(String::as_str),
            Some("require-corp")
        );
    }

    /// A bundle-tier component at a non-root mount keeps its own headers even
    /// though it shares the bundle's upstream — the reason mounts are per
    /// COMPONENT while units are per deployed thing.
    #[test]
    fn a_bundle_components_sub_mount_keeps_its_headers_and_the_bundle_upstream() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("docs", Some("docs"), DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let domains = domains(
            "noisetable",
            &[("/docs/*", &[("x-frame-options", "DENY")])],
        );
        let plan = plan(&svc, &domains).unwrap().expect("two units");

        let docs = &plan.mounts[1];
        assert_eq!(docs.mount, "/docs");
        assert_eq!(docs.unit, DeployedUnit::Bundle);
        assert_eq!(docs.headers.get("x-frame-options").map(String::as_str), Some("DENY"));
        // Two units, three mounts.
        assert_eq!(plan.units().len(), 2);
        assert_eq!(plan.mounts.len(), 3);
    }

    #[test]
    fn a_table_with_no_root_mount_is_refused_rather_than_written() {
        let svc = service(
            "noisetable",
            vec![
                component("app", Some("app"), DeployTier::Bundle),
                component("account", Some("account"), DeployTier::Workload),
            ],
        );
        let err = plan(&svc, &BTreeMap::new()).unwrap_err().to_string();
        assert!(err.contains("no component at the service root"), "{err}");
    }

    #[test]
    fn rendering_produces_the_exact_shape_passway_reads() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let domains = domains(
            "noisetable",
            &[("/app/*", &[("cross-origin-opener-policy", "same-origin")])],
        );
        let plan = plan(&svc, &domains).unwrap().unwrap();

        let yubaba = vec![
            "http://100.64.0.1:7443".to_string(),
            "http://100.64.0.3:7443".to_string(),
        ];
        let json = plan.routes_file("noisetable", &yubaba).unwrap();
        let account = plan.unit_ident(&DeployedUnit::Component("account".into()), "noisetable");

        assert_eq!(
            json,
            format!(
                r#"{{"schema_version":2,"routes":[{{"mount":"","discover":{{"ident":"noisetable","yubaba":["http://100.64.0.1:7443","http://100.64.0.3:7443"]}}}},{{"mount":"/app","discover":{{"ident":"{account}","yubaba":["http://100.64.0.1:7443","http://100.64.0.3:7443"]}},"headers":{{"cross-origin-opener-policy":"same-origin"}}}}]}}"#
            )
        );
        assert!(!json.contains("upstreams"), "R936-B12: no baked addresses: {json}");
    }

    /// R876-B20: the table carries the lowest schema that expresses it.
    #[test]
    fn a_table_writes_v1_unless_a_mount_discovers() {
        let empty = BTreeMap::new();
        let fixed = RouteEntry { mount: "", discover: None, headers: &empty, cors_origins: &[] };
        assert_eq!(routes_schema_for(&[fixed]), ROUTES_SCHEMA_FIXED);
        let yubaba = ["http://y:7443".to_string()];
        let fixed = RouteEntry { mount: "", discover: None, headers: &empty, cors_origins: &[] };
        let disc = RouteEntry {
            mount: "/app",
            discover: Some(RouteDiscover { ident: "x".into(), yubaba: &yubaba }),
            headers: &empty,
            cors_origins: &[],
        };
        assert_eq!(routes_schema_for(&[fixed, disc]), ROUTES_SCHEMA_DISCOVER);
    }


    /// R826: the governing route's `cors_origins` reach the mount and the file
    /// passway reads — on that mount only, and absent (not `[]`) elsewhere, so a
    /// passway older than the key still parses every table that does not use it.
    #[test]
    fn cors_origins_travel_with_their_own_mount_into_the_routes_file() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let mut domains = domains("noisetable", &[("/app/*", &[]), ("/*", &[])]);
        domains.get_mut("test").unwrap().routes[0].cors_origins =
            vec!["https://noisetable.com".to_string()];
        let plan = plan(&svc, &domains).unwrap().unwrap();

        assert!(plan.mounts[0].cors_origins.is_empty());
        assert_eq!(plan.mounts[1].cors_origins, vec!["https://noisetable.com".to_string()]);

        let json = plan
            .routes_file("noisetable", &["http://100.64.0.1:7443".to_string()])
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["routes"][0].get("cors_origins").is_none(), "{json}");
        assert_eq!(
            parsed["routes"][1]["cors_origins"],
            serde_json::json!(["https://noisetable.com"])
        );
    }

    /// With nowhere to discover from, every mount would 503; refuse instead.
    #[test]
    fn a_table_with_no_yubaba_to_poll_is_refused() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().unwrap();
        let err = plan.routes_file("noisetable", &[]).unwrap_err().to_string();
        assert!(err.contains("at least one yubaba"), "{err}");
        assert!(plan.workload(8443, "noisetable", &[]).is_err());
    }

    /// The rendered door, pinned on the four properties that are not
    /// cosmetic: cleartext ONLY on loopback, the routes file travelling inside
    /// the spec, and the env var passway selects path routing by.
    #[test]
    fn the_rendered_door_is_cleartext_on_loopback_and_carries_its_own_table() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().unwrap();
        let workload = plan
            .workload(8443, "noisetable", &["http://100.64.0.3:7443".to_string()])
            .unwrap();
        let spec = workload.container_spec().expect("container-shaped");

        let env: BTreeMap<&str, &str> = spec
            .env
            .iter()
            .filter_map(|e| match &e.value {
                EnvValue::Literal { value } => Some((e.name.as_str(), value.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(env.get("PASSWAY_TLS_MODE"), Some(&"plaintext"));
        // The invariant: cleartext is bound to loopback by construction, not
        // by whoever picked the port.
        assert_eq!(env.get("PASSWAY_LISTEN"), Some(&"127.0.0.1:8443"));
        assert!(spec.expose.public.is_none(), "an inner door is never public");

        // The routes file rides the spec, and the env var points AT it.
        assert_eq!(spec.files.len(), 1);
        let file = &spec.files[0];
        assert_eq!(
            env.get("PASSWAY_PATH_ROUTES_FILE").map(|s| s.to_string()),
            Some(file.path.display().to_string())
        );
        assert!(file.content.contains("\"schema_version\":2"), "{}", file.content);
        assert!(file.content.contains("http://100.64.0.3:7443"), "{}", file.content);
        assert_eq!(spec.command.as_deref(), Some(&[INNER_DOOR_BINARY.to_string()][..]));
        // R936-B12: the door notices a unit move within one short poll.
        assert_eq!(env.get("PASSWAY_UPDATE_INTERVAL_SECS"), Some(&"2"));
        // R876-T18: the door's discovery polls are signed.
        assert_eq!(
            env.get("PASSWAY_YUBABA_CLUSTER_KEY_FILE"),
            Some(&DOOR_CLUSTER_KEY_FILE)
        );
    }

    /// R936-B11: the door is native AND asks its node's kamaji to replay it
    /// after a restart. Without the second marker a reboot of a front door
    /// took the door down for good and the outer door 503'd.
    #[test]
    fn the_rendered_door_is_native_and_survives_a_kamaji_restart() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().unwrap();
        let workload = plan
            .workload(8443, "noisetable", &["http://100.64.0.3:7443".to_string()])
            .unwrap();
        let spec = workload.container_spec().expect("container-shaped");
        assert!(spec.wants_native_exec());
        assert!(spec.wants_resume_after_restart());
        assert!(!spec.wants_float(), "a door is pinned to its front door, never a floater");
    }

    #[test]
    fn the_mount_spelling_matches_passways_convention_in_both_directions() {
        assert_eq!(passway_mount(None), "");
        assert_eq!(passway_mount(Some("")), "");
        assert_eq!(passway_mount(Some("/")), "");
        // Every spelling of one mount collapses to one string — the whole
        // reason this composes with `normalize_mount` instead of formatting.
        for raw in ["app", "/app", "app/", "/app/"] {
            assert_eq!(passway_mount(Some(raw)), "/app", "{raw}");
        }
        assert_eq!(passway_mount(Some("/a/b/")), "/a/b");
    }

    // ── Phase 2: placement (R870-F23 steps 2 and 3) ─────────────────────────

    /// The property the whole pin rests on: same service, same number, forever.
    /// The outer door's upstream list and the inner door's `PASSWAY_LISTEN` are
    /// rendered by two different call sites in two different apply phases; if
    /// this drifted, one tier would be repointed and the other would not.
    #[test]
    fn the_derived_port_is_stable_and_inside_its_declared_window() {
        assert_eq!(listen_port("noisetable"), listen_port("noisetable"));
        for service in ["noisetable", "yah-marketing", "", "a", "a-very-long-service-name"] {
            let port = listen_port(service);
            assert!(
                (INNER_DOOR_PORT_LOW..=INNER_DOOR_PORT_HIGH).contains(&port),
                "{service} -> {port}"
            );
            // Below the Linux default ephemeral floor, which is where
            // `kamaji::ports::pick_free_port`'s `bind(:0)` draws from. A number
            // inside that range could collide with a ledger allocation.
            assert!(port < 32_768, "{service} -> {port}");
        }
    }

    /// Different services get different doors. Not a guarantee the hash can
    /// make in general — 10_000 slots, so a collision is possible — but two
    /// services co-tenant on one node colliding is what this is checked
    /// against, and the two real ones do not.
    #[test]
    fn two_services_do_not_share_a_door() {
        assert_ne!(listen_port("noisetable"), listen_port("yah-marketing"));
    }

    /// Step 3's identity mapping. The two arms come from different places and
    /// the test says so: the bundle's ident is handed in (a mirror may rename
    /// it), a component's is derived from names the service already declares.
    #[test]
    fn each_unit_resolves_through_its_own_identity_rule() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().unwrap();

        assert_eq!(
            plan.unit_ident(&DeployedUnit::Bundle, "renamed-bundle"),
            "renamed-bundle",
            "a slot's `name = \"…\"` override has to win — it is what the record carries"
        );
        assert_eq!(
            plan.unit_ident(&DeployedUnit::Component("account".into()), "renamed-bundle"),
            "noisetable-account",
        );
    }

    /// A component id that is not already a legal mesh ident is folded, not
    /// passed through — the ident travels into a service-record lookup and a
    /// `MeshIdent`, both of which are lowercase-and-dash.
    #[test]
    fn a_derived_component_ident_is_folded_like_every_other_mesh_ident() {
        assert_eq!(
            component_workload_ident("Noise_Table", "Account.API"),
            "noise-table-account-api"
        );
    }

    /// Steps 2 and 3 joined: a two-unit service renders a door whose table
    /// names both resolved addresses and whose listener is the derived port.
    /// The positive half of the ticket's verify list, at the config tier.
    #[test]
    fn resolved_units_render_a_door_on_the_derived_port() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let domains = domains(
            "noisetable",
            &[(
                "/app/*",
                &[
                    ("cross-origin-opener-policy", "same-origin"),
                    ("cross-origin-embedder-policy", "require-corp"),
                ],
            )],
        );
        let plan = plan(&svc, &domains).unwrap().unwrap();

        let workload = plan
            .workload(plan.listen_port(), "noisetable", &["http://100.64.0.3:7443".to_string()])
            .unwrap();
        let spec = workload.container_spec().expect("container-shaped");
        let listen = spec
            .env
            .iter()
            .find(|e| e.name == "PASSWAY_LISTEN")
            .and_then(|e| match &e.value {
                EnvValue::Literal { value } => Some(value.clone()),
                _ => None,
            })
            .expect("a door always declares its listener");
        assert_eq!(listen, format!("127.0.0.1:{}", listen_port("noisetable")));

        let table = &spec.files[0].content;
        assert!(table.contains(r#""ident":"noisetable""#), "{table}");
        assert!(table.contains(r#""ident":"noisetable-account""#), "{table}");
        assert!(table.contains("cross-origin-embedder-policy"), "{table}");
    }

    // ── R898-F2: the inner door and the compiled table are one join ──────────

    /// A placement that resolves the fixture's `static` routes. Nothing here
    /// asserts on origins — the point is that the HEADER answer the door plans
    /// and the header answer the compiled table carries come from one walk.
    fn placement() -> CdnPlacement {
        CdnPlacement {
            cdn_base: "https://cdn.test".to_string(),
            env: "prod".to_string(),
            ..Default::default()
        }
    }

    fn compiled(domains: &BTreeMap<String, DomainConfig>) -> RouteTable {
        domains["test"]
            .route_table(&placement())
            .expect("the fixture's routes all resolve")
    }

    /// passway spells the root mount `""`; the request that reaches it is `/`.
    fn mount_path(mount: &str) -> &str {
        if mount.is_empty() {
            "/"
        } else {
            mount
        }
    }

    /// A two-unit service whose domain declares a headered `/app/*` above a
    /// headerless catch-all — a legal manifest under first-match-wins.
    fn seam_fixture() -> (ServiceConfig, BTreeMap<String, DomainConfig>) {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let domains = domains(
            "noisetable",
            &[
                (
                    "/app/*",
                    &[("cross-origin-opener-policy", "same-origin")],
                ),
                ("/*", &[("x-frame-options", "DENY")]),
            ],
        );
        (svc, domains)
    }

    /// **THE SEAM (R898-F2).** Every mount's headers are the compiled route
    /// table's answer for that mount's path — not a second join that happens to
    /// agree. If the two ever diverge, the inner door serves headers the table
    /// says are served somewhere else.
    #[test]
    fn every_mounts_headers_are_the_compiled_route_tables_answer() {
        let (svc, domains) = seam_fixture();
        let table = compiled(&domains);
        let plan = plan(&svc, &domains).unwrap().expect("two units");

        for m in &plan.mounts {
            let expected = table
                .match_path(mount_path(&m.mount))
                .map(|e| e.headers.clone())
                .unwrap_or_default();
            assert_eq!(m.headers, expected, "mount {:?}", m.mount);
        }

        // Non-trivially: the fixture gives both mounts headers, and DIFFERENT
        // ones, so an implementation that returned `Default::default()` for
        // everything could not pass the loop above.
        assert_eq!(
            plan.mounts
                .iter()
                .map(|m| m.headers.keys().cloned().collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            vec![
                vec!["x-frame-options".to_string()],
                vec!["cross-origin-opener-policy".to_string()],
            ]
        );
    }

    /// The property the seam exists for: a header edited in the domain manifest
    /// reaches the inner door's table without a second join being touched, and
    /// both tiers move together.
    #[test]
    fn a_header_changed_in_the_manifest_moves_both_tiers_at_once() {
        let (svc, mut domains) = seam_fixture();
        let before = plan(&svc, &domains).unwrap().unwrap();
        assert_eq!(
            before.mounts[1]
                .headers
                .get("cross-origin-opener-policy")
                .map(String::as_str),
            Some("same-origin")
        );

        // One edit, in the manifest, to the route that governs `/app`.
        let route = domains
            .get_mut("test")
            .unwrap()
            .routes
            .iter_mut()
            .find(|r| r.path == "/app/*")
            .unwrap();
        route.headers.insert(
            "cross-origin-embedder-policy".to_string(),
            "require-corp".to_string(),
        );

        let after = plan(&svc, &domains).unwrap().unwrap();
        let table = compiled(&domains);
        assert_eq!(
            after.mounts[1].headers,
            table.match_path("/app").unwrap().headers,
            "the door's mount and the compiled entry must move together"
        );
        assert_eq!(
            after.mounts[1]
                .headers
                .get("cross-origin-embedder-policy")
                .map(String::as_str),
            Some("require-corp")
        );
        // And only that mount moved — no merging across rules.
        assert_eq!(before.mounts[0].headers, after.mounts[0].headers);
    }

    /// The order-dependence the shared rule brings, stated as a test rather
    /// than left to be discovered: a catch-all declared ABOVE `/app/*` claims
    /// `/app` at every tier, and the inner door now agrees instead of quietly
    /// disagreeing. This is the manifest being wrong, not the door.
    #[test]
    fn a_catch_all_declared_first_claims_every_mount_at_both_tiers() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let domains = domains(
            "noisetable",
            &[
                ("/*", &[("x-frame-options", "DENY")]),
                ("/app/*", &[("cross-origin-opener-policy", "same-origin")]),
            ],
        );
        let table = compiled(&domains);
        let plan = plan(&svc, &domains).unwrap().unwrap();

        assert_eq!(
            table.match_path("/app").unwrap().path,
            "/*",
            "first match wins over the compiled table"
        );
        assert_eq!(plan.mounts[1].mount, "/app");
        assert_eq!(
            plan.mounts[1].headers.keys().cloned().collect::<Vec<_>>(),
            vec!["x-frame-options".to_string()],
            "and the inner door reports the same route's headers, not a second join's"
        );
    }
}
