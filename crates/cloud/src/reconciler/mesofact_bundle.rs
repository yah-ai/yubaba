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
//!
//! @yah:relay(R876, "Node-side mesofact: prove the hot-ship loop on real hardware, then prove the load can move off us-east-001")
//! @yah:at(2026-09-09T04:10:09Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @yah:next("SESSION CONTEXT (2026-09-08, chat session, ashguard/spade). This relay exists because the node-side mesofact iteration loop was measured end-to-end and found not to close, a hot-ship arm was built to close it, and the first live exercise of that arm turned up a separate availability problem worth its own drill. Both children are LIVE-FLEET work that a chat session deliberately did not run.")
//! @yah:next("WHAT ALREADY LANDED IN THE TREE (uncommitted; camp git-policy is `defer`). (1) scripts/hotship.sh: registry gained `source` and `dest` columns + a `mesofact` entry `mesofact|mesofact||oss/mesofact|bundle-serve|artifact:mesofact|runtime:mesofact`; new `bundle-serve` activation; new `unpack_artifact` resolving the newest qed-produced tarball out of .yah/cache/artifacts/named/; runtime-asset install arm that overwrites only RUNNING versions and writes a `serve.hotship` stamp. (2) .yah/qed/hotship.toml: `binaries` param description updated. (3) oss/qed/crates/qed/src/runner.rs: execute_step_local_container now publishes/injects/discards `source_context` — that is the arm-leg fix, with two new tests.")
//! @yah:verify("Measured, not assumed — `mesofact-musl` x86_64 leg took 9m56s / 9m57s / 11m10s across its three successful runs (qed run records 23ef24bb, 936d0be1, d62e9bdd). Its aarch64 leg failed in ~1.4s on all 13 recorded runs, so the pipeline never reached `[[pipeline.on_success]]` and its publish has NEVER fired.")
//! @yah:gotcha("THE CACHE-HIT SHORT-CIRCUIT IS THE LOAD-BEARING FACT FOR BOTH CHILDREN. `ensure_runtime_asset` (oss/yah-base/crates/mesofact-bundle/src/runtime.rs:488) returns on a bare `dest.is_file()` — no re-hash, no manifest GET, deliberately and documented. Consequences, both real: (a) a node that has ever resolved `mesofact/<ver>` will NEVER re-fetch it, so the pre-hotship iteration loop required a new version + a bundle republish + an apply for every single change; (b) dropping bytes at that path IS a working hot ship needing no R2 write — which is what makes the arm fit hotship's never-writes-the-CDN charter — but it is also invisible afterwards unless something records it. That is why the arm writes a `serve.hotship` stamp beside each binary. R746-T3 (us-east-001 reporting `kamaji 0.8.22` while carrying none of it) is the same failure this prevents.")
//!
//! @yah:ticket(R876-S2, "Failover drill: move the yah.dev mesofact load off us-east-001 and back, and find out what actually blocks it")
//! @yah:status(review)
//! @yah:at(2026-09-09T07:33:42Z)
//! @yah:kind(spike)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R876)
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @yah:next("Tier: Cleric — the answer is a design call about the production apex's availability, not a mechanical edit. OPERATOR-REQUESTED 2026-09-08, verbatim intent: \"run a drill to move a mesofact load from us-east-001 to another and back (by tainting or something)\", framed by the standing observation \"I've been pretty clear nodes go down in this system\".")
//! @yah:gotcha("THE MISSING RUNTIME ASSET ON THE OTHER NODES IS A SYMPTOM, NOT THE CONSTRAINT — do not start by seeding caches. The runtime asset is a lazy cache: `ensure_runtime_asset` fetches on miss from KAMAJI_BUNDLE_ORIGIN (https://cdn.yah.dev) and blake3-verifies, and mesofact/0.8.32's manifest is published and serving 200. A cold node can pull it. us-south-001 has none simply because it has never been asked to run one.")
//! @yah:gotcha("WHAT ACTUALLY PINS IT — TWO INDEPENDENT PINS, both in .yah/services/yah-marketing/mirrors/cloud.toml, and a drill that only clears one will still fail. (1) The bundle slot declares `required = { regions = [\"us-east\"], mesh_tags = [\"tag:cloud-runner\"] }`. Measured: us-east-001, us-south-001 and us-west-001 ALL carry tag:cloud-runner + arch:x86 + os:linux + tag:voter-candidate, so `regions = [\"us-east\"]` is doing 100% of the narrowing and exactly one machine declares that region. Candidate set of one. (2) `upstream_host` is hardcoded to 100.64.0.3, so even if placement moved, the front door keeps sending traffic to the old node. `shape = \"single-machine\"`.")
//! @yah:gotcha("READ R772's ANNOTATIONS AT THE TOP OF THAT MIRROR BEFORE EDITING IT — the obvious fix was already tried and reverted, with the reason recorded at the pin. Dropping `regions` ALONE makes things worse, not better: `plan_ingress` is deliberately pure (no network, no credentials, no CloudConfig) so it cannot resolve a constraint, and `IngressPlan::workload_machine()` goes Some(us-east-001) -> None, which is what upstream discovery is aimed at (app/yah/cli/src/cloud.rs ~4935). Today that damage is INVISIBLE because upstream_host is pinned. The recorded order is: teach the ingress planner to resolve a placement (or hand it a pre-resolved one) FIRST, then convert the slot. Preferred shape, also recorded: the CALLER resolves and passes the machine in, rather than plan_ingress growing a CloudConfig parameter.")
//! @yah:next("SHAPE OF THE DRILL. Off: taint or otherwise make us-east-001 ineligible, and observe what the system actually does rather than what it should do — does anything attempt a re-place at all, does the bundle materialize on the new node, does the runtime asset cold-fetch from cdn.yah.dev, does the front door follow. Back: reverse it and confirm the load returns and yah.dev stays 200 throughout. The deliverable is the WRITTEN ANSWER to \"what breaks first, and in what order\" — a spike, not a fix. Expect the honest outcome to be that nothing moves, because of the two pins above; that result is worth having recorded and measured rather than inferred.")
//! @yah:next("GUARD THE DRILL ITSELF. yah.dev is live and 200 on / and /releases; us-east-001 is also PROD raft voter 3 (100.64.0.3), so a taint that reaches raft membership is a quorum event, not just a placement one. Establish the rollback and the blast radius before tainting anything, and do not run this in the same window as R876-T1's activation — one unproven change at a time against the only node serving the apex.")
//! @yah:next("SIBLING WORK, do not duplicate: R869 covers raft state having no off-fleet copy, and R870 covers the second-tenant/sovereign-front-door tiers — both live near this. This spike is narrower: can ONE declared-singleton workload move between nodes at all. If the answer needs a design change, file it under R870 or as its own relay rather than growing this spike.")
//! @yah:gotcha("PIN #2 AS FILED IS STALE — `upstream_host` IS ALREADY GONE. Removed by R844-T10 on 2026-09-04; .yah/services/yah-marketing/mirrors/cloud.toml:262 records the removal, `fronted = true` (line 254) replaced `port = 8080`, and xtask/tests/mirror_ingress.rs::the_apex_derives_the_backend_host_it_no_longer_pins asserts on the real file that NO pin is declared. So the filed claim `upstream_host is hardcoded to 100.64.0.3` was five days out of date at filing. Pin #1 is still exactly right: `required = { regions = [\"us-east\"], mesh_tags = [\"tag:cloud-runner\"] }` at line 213, and only us-east-001 declares region = \"us-east\".")
//! @yah:gotcha("THE FRONT-DOOR PIN DID NOT GO AWAY, IT MOVED OUT OF THE TREE — and that is worse for this drill, because no test, no `ingress collate` and no mirror diff can see it any more. Measured live 2026-09-09: BOTH yah.dev doors carry `PASSWAY_YUBABA_URL=http://100.64.0.3:7443` — us-east-001 /etc/passway-test.env and us-south-001 /etc/passway.env. SOUTH'S POINTS AT EAST, NOT AT ITSELF. And /service-records is strictly node-local, which I proved by query rather than reading the invariant: 100.64.0.2 (south) answers only `headscale`; 100.64.0.3 (east) answers `noisetable` + `yah-marketing`. So if yah-marketing moved off east, both doors keep polling 100.64.0.3, find no yah-marketing record, and yah.dev 503s no matter where the workload actually landed. app/yah/cli/src/mesh.rs:119 already records the south-points-at-east half; the 503-on-move consequence for yah.dev is the part to carry into the drill.")
//! @yah:handoff("WHAT BREAKS FIRST, AND IN WHAT ORDER — the ticket's deliverable, answered from read-only measurement on 2026-09-09 with NOTHING tainted and NOTHING mutated. (1) PLACEMENT NEVER MOVES. `required.regions = [\"us-east\"]` matches exactly one machine, so tainting us-east-001 empties the candidate set rather than selecting a new node; the reconciler has nowhere to put the workload and the drill stops here. (2) IF you widen `regions`, THE FRONT DOOR DOES NOT FOLLOW. `passway_discovery_env` (app/yah/cli/src/cloud.rs:4429) renders the correct `PASSWAY_YUBABA_URL` from the placement node's mesh_ipv4 — but the apply PRINTS that env (cloud.rs:566 handoff) rather than writing /etc/passway.env on the node, so both doors keep polling 100.64.0.3 until a human edits two files on two boxes and reloads. Nothing reports an error; yah.dev just 503s. (3) ONLY THEN does the runtime-asset cold-fetch matter, and that half is genuinely fine — the filed gotcha is right that it is a lazy cache and https://cdn.yah.dev/runtimes/mesofact/0.8.32/x86_64-unknown-linux-musl.toml is live and 200. The honest answer the ticket predicted is confirmed, and the reason is one step earlier than filed.")
//! @yah:handoff("GROUNDING FOR STEP (2) ABOVE, read from code rather than from an annotation: the ONLY production caller of `passway_discovery_env` is the `cloud::IngressProvider::Passway` arm at app/yah/cli/src/cloud.rs:7527, and it pushes the rendered lines into `out` — the vec the apply PRINTS. Nothing in that path writes /etc/passway.env or reloads a door. Independently, the `CoordinatorPin` doc at cloud.rs:4460-4475 already states the structural half in as many words (\"a **remote** door can never discover a workload placed on another node\"), and cites the same R844-B11 per-node invariant. So the design limit was known and written down; what this spike adds is the live measurement that BOTH yah.dev doors are currently the remote case with respect to any move — us-south-001's /etc/passway.env points at 100.64.0.3, not at itself — and therefore that the apex 503s on a move regardless of destination, not merely for the N-1 doors the doc anticipates.")
//! @yah:handoff("THE DRILL IS SAFE TO RUN AND WILL NOT MOVE ANYTHING — both halves grounded in code, so the taint does not have to be spent to learn it. `select_matching` (oss/yubaba/crates/cloud/src/config.rs:2010) BAILS with \"no candidates matching {req} — {pool}: {names}\" whenever fewer machines match than `want`, and its doc says why in as many words: it \"never [returns] a one-element vec: a half-placed workload that reports success is worse than a failed apply\". So tainting us-east-001 out makes `yah cloud apply` fail at RESOLUTION, before any deploy or teardown — the running yah-marketing workload is untouched and yah.dev keeps serving. That is the good news and the disappointing news at once: nothing attempts a re-place, so the taint measures the resolver's refusal and nothing downstream of it. Note also that a taint in .yah/infra/machines/*.toml is inert until someone runs an apply; it is a tree edit, not a live fleet action.")
//! @yah:gotcha("CORRECTION TO MY OWN EARLIER ENTRY, AND IT NARROWS THE GAP CONSIDERABLY: passway DOES know how to follow a moving backend. R844-F23 (shipped 2026-09-05, oss/passway/crates/passway/src/discovery.rs) makes `PASSWAY_YUBABA_URL` a LIST — the door polls N yubabas, unions the matching records, and holds last-known-good PER SOURCE so one node's yubaba restarting cannot drain the other's backends. It is tested end to end through the real LoadBalancer + TcpHealthCheck. So the mechanism for following a move exists and works. THE ACTUAL GAP IS ONE STEP UPSTREAM: `passway_discovery_env` renders one URL per PLACEMENT node — where the workload IS — not per CANDIDATE node, where it MAY GO. A single-machine placement therefore renders a single-yubaba door by construction, which is why all three apex doors list only 100.64.0.3. The failover-capable rail was handed a candidate set of one.")
//! @yah:next("THE FIX THIS SPIKE ARGUES FOR, small and with an obvious home: render the door's yubaba list from the slot's `required = {...}` CANDIDATE SET rather than from the resolved placement. `CloudConfig::resolve_machines` (oss/yubaba/crates/cloud/src/config.rs:1788) already returns a Vec of matching machines, so the shape exists. Polling a node that does not hold the workload is harmless by design — discovery.rs's \"answered with none retires only its own share\" rule — and the budget fits: `base_urls.len() * PASSWAY_YUBABA_TIMEOUT_SECS` must stay under PASSWAY_UPDATE_INTERVAL_SECS, which at the 5s/30s defaults allows six nodes, and only four machines in the fleet carry tag:cloud-runner (us-east-001, us-south-001, us-west-001, us-west-003). With that change a `regions` edit, a taint, or a node dying moves the workload and every door follows within one 30s tick with no human edit. SECOND HALF, still needed: the apply must WRITE the door env rather than print it, or the re-render never reaches the node.")
//! @yah:verify("THE SINGLE-DISCOVERY-SOURCE RISK IS NOT THEORETICAL — IT WAS MEASURED ACCIDENTALLY BY R876-T1 THIRTY MINUTES AGO. During T1's activation on us-east-001, a ~2-second gap in east's mesofact serve process 502'd the yah.dev apex on EVERY probe in that window (04:39:16 and 04:39:17, one GET/s), not one probe in three. yah.dev is round-robin across three origins — us-east-001, us-south-001, us-west-001 (west promoted to origin 3 on 2026-09-08, oss/yubaba/crates/yubaba/src/cert_store.rs:90) — so a third of requests should have survived if the origins were independent. They are not: all three doors carry PASSWAY_YUBABA_URL=http://100.64.0.3:7443, so east's serve process is a single point of failure for the whole apex regardless of how many origins front it. Three doors, one backend, one blast radius.")
//! @yah:gotcha("GROUNDED FROM CODE, replacing the annotation-derived version of this claim: `passway_discovery_env` (app/yah/cli/src/cloud.rs:4370) opens with `let placed = plan.workload_machines()` and builds one poll URL per entry, under a comment that states the design assumption in as many words — \"One poll URL per placement node. The record store is node-local, so this list IS the set of places the workload can be seen from.\" That comment is TRUE IN THE PRESENT TENSE and is exactly why the door cannot follow a move: the set of places a workload can be seen from RIGHT NOW is not the set it could be seen from after it moves, and the door is configured with the former. The refusals in the same function (unplaced, machine absent, no mesh_ipv4, no hostname rules) confirm there is no candidate-set path — every branch resolves against `placed`. So the change R876-S2 argues for is one line of intent: feed this loop the slot's resolved CANDIDATE set instead of `plan.workload_machines()`.")
//! @yah:handoff("DRILL RUN FOR REAL 2026-09-09 (session:d9a29d70), off and back, apex 200 throughout — and IT DID NOT MATCH THE PREDICTION. The prediction was \"taint us-east-001 and resolution refuses\". The refusal half is confirmed; the TAINT half is wrong, and that is the most valuable thing this drill produced. THE TAINT LEVER DOES NOT EXIST FOR THIS WORKLOAD CLASS. Node taints repel by ARCHETYPE: `RequiredSpec::matches` (oss/yubaba/crates/cloud/src/config.rs:4182) reads `machine.taints` only inside `for arch in &self.repel_archetypes`, and that field is `#[serde(skip)]` (config.rs:4067). A mirror's `required = { regions, mesh_tags }` is deserialized straight from TOML, so on the `resolve_bundle_machines` -> `resolve_machines` path the set is ALWAYS empty, the loop body never runs, and the taint list is never read at all. Only `admit_workload`, which builds the spec from a WorkloadSpec, populates the axis. MEASURED AGAINST THE REAL FILE, not just in a fixture: with `taints = [\"public-ip\", \"no-server\"]` written into .yah/infra/machines/us-east-001.toml, `mirror_ingress::the_apex_bundle_places_on_the_node_set_its_upstreams_are_pinned_to` still passed — us-east-001, unchanged. All three repelling keys at once (`no-server`, `no-appliance`, `no-job`) are equally inert. CONSEQUENCE WORTH CARRYING: every placement declared by a mirror's `required` is DRAIN-PROOF, while every placement that arrives through `admit_workload` is not. An operator told \"drain a node by tainting it\" would edit the file, see the lint pass (`no-server` is a legal key, so `check_inert_taints` does not fire), run an apply, and get a successful deploy onto the node they meant to evacuate.")
//! @yah:handoff("THE ONE LEVER THAT WORKS, AND THE ACTUAL ERROR TEXT VERBATIM. With no taint lever, the only way to make us-east-001 ineligible is the membership axis — `region`. Pulled it for real (`region = \"us-east\"` -> `\"us-east-DRAINED\"` in .yah/infra/machines/us-east-001.toml) and the deploy-side resolver refused. NOTE THE TWO LAYERS, because they say different things and `{}` shows only the first: OUTER (anyhow `to_string()`) = `F16 placement: cannot place providers.bundle.required (required.regions=[us-east] + required.mesh_tags=[tag:cloud-runner]) onto 1 machine(s) - check .yah/services/yah-marketing/mirrors/cloud.toml against .yah/infra/machines/*.toml`. FULL CHAIN (`{:#}`) appends `: no candidates matching required.regions=[us-east] + required.mesh_tags=[tag:cloud-runner] - declared machines: us-east-001, us-south-001, us-west-001, us-west-002, us-west-003, us-west-011, us-west-013, us-west-014, us-west-015`. The inner layer is the one naming the pool searched, so an operator who sees only the outer line is told a placement failed but not what was considered and rejected. The ingress planner refuses too, and more thinly: `resolving placement for [providers.bundle] required = { ... }` with the same cause beneath it. AGAINST THE REAL TREE this took SEVEN of the eleven mirror_ingress tests down at once, including `the_whole_camp_collates_onto_its_nodes_without_conflict` — so the camp has a real standing guard against this drift, which is the reassuring half.")
//! @yah:handoff("\"AND BACK\", AND THE DRILL LEFT NOTHING BEHIND. Restored `region = \"us-east\"` by editor write (never `git checkout`/`restore` — shared tree) and proved it byte-exact three independent ways: `diff` against a pre-edit `cp` at /tmp/us-east-001.toml.R876S2-orig was empty, sha256 back to 17dd15e29a0a8cf185879b5b0f49b7a54a134f5837a9ef80e01e3d065efe42d2 (identical to pre-drill), and `git status --porcelain` on the path empty, i.e. matching HEAD blob d66ab6d84d63a2c15b5eeec931e76139069a789e. Post-restore: mirror_ingress 11 passed / 0 failed, apex_failover 4 passed / 0 failed, https://yah.dev/ 200 and /releases 200 — same as the pre-drill baseline. THE PROD-SAFETY ARGUMENT, now measured rather than reasoned: no mutating `yah cloud apply` was run, and none was needed. The drill window against the real machine file was seconds, because the test binary was already compiled and was invoked directly (./target/debug/deps/main-<hash>) instead of through cargo. Even had a peer run an apply inside that window, `select_matching` (config.rs:2010) bails on a shortfall rather than half-placing, so the failure mode is a refused apply and an untouched running workload — the resolver fails CLOSED. Nothing on any node was touched: no headscale, no raft membership, no /etc/passway*.env.")
//! @yah:handoff("THE DRILL IS NOW A STANDING TEST, not a story about an afternoon — NEW FILE xtask/tests/apex_failover.rs (4 tests, registered in xtask/tests/main.rs). It loads the REAL .yah/services/yah-marketing/mirrors/cloud.toml and the REAL .yah/infra/machines/, then makes us-east-001 ineligible in the loaded CloudConfig — which is the same experiment as a tree edit, since `CloudConfig::load` is the only thing between those files and the resolver, and it is repeatable by anyone with no window of wrong bytes on disk. The four: (1) `every_repelling_taint_at_once_leaves_the_apex_bundle_exactly_where_it_was` — pins the headline finding so that if someone ever wires `repel_archetypes` through the mirror path, this test fails and tells them the drain lever just started working; (2) `making_the_apex_node_ineligible_refuses_to_resolve_rather_than_failing_over` — asserts BOTH error layers, and asserts the chain names the pool, so the diagnostic quality itself is now guarded; (3) `restoring_the_region_puts_the_apex_bundle_back_on_the_same_node` — the \"and back\" half, proving the refusal is not sticky; (4) `the_apex_candidate_set_has_exactly_one_member_and_regions_is_why` — measures that exactly one machine declares region us-east while FOUR carry tag:cloud-runner, so it records which half of the constraint is doing the pinning and will fail the day someone widens it.")
//! @yah:handoff("FIX FILED AS R870-F16 (child of R870, which is live/active), NOT implemented here — the spike says the design change belongs elsewhere and it does. Title: \"Render the door's yubaba poll list from the slot's CANDIDATE set, and WRITE the door env onto the node instead of printing it\". Annotation anchored in app/yah/cli/src/cloud.rs. Both halves are in the ticket body as separate @yah:next entries with the argument for why NEITHER works alone: (a) alone renders a better list nobody installs, (b) alone installs the same one-node list. It carries the measured single-point-of-failure fact (three yah.dev doors, all `PASSWAY_YUBABA_URL=http://100.64.0.3:7443`, R876-T1's ~2s outage 502ing every probe), the budget constraint VERIFIED from source rather than quoted (`env_secs(\"PASSWAY_YUBABA_TIMEOUT_SECS\", 5)` at oss/passway/crates/passway/src/main.rs:976 and `env_secs(\"PASSWAY_UPDATE_INTERVAL_SECS\", 30)` at main.rs:1139 — 5s/30s, six nodes fit, four machines carry the tag), and a SCOPE BOUNDARY gotcha stating that F16 makes the door FOLLOW a move but does not make a move POSSIBLE: the `regions` candidate-set-of-one and the missing drain lever both remain, and F16 should land BEFORE the slot is widened (the recorded R772 order).")
//! @yah:verify("HOW EVERY CLAIM ABOVE WAS CHECKED, with exit-visible results rather than inference. BASELINE before touching anything: `curl -sS -o /dev/null -w '%{http_code}' https://yah.dev/` = 200, /releases = 200. FILE BASELINE: `git status --porcelain .yah/infra/machines/us-east-001.toml` empty (clean), HEAD blob `git rev-parse HEAD:.yah/infra/machines/us-east-001.toml` = d66ab6d84d63a2c15b5eeec931e76139069a789e, worktree sha256 = 17dd15e29a0a8cf185879b5b0f49b7a54a134f5837a9ef80e01e3d065efe42d2, copy saved to /tmp/us-east-001.toml.R876S2-orig. TAINT ARM: added `\"no-server\"` to the real file, ran the prebuilt binary directly — `mirror_ingress::the_apex_bundle_places_on_the_node_set_its_upstreams_are_pinned_to` = 1 passed / 0 failed (taint inert, confirmed). REGION ARM: `region = \"us-east-DRAINED\"` in the real file, `mirror_ingress::` = 4 passed / 7 FAILED, error text captured verbatim (recorded in the handoff above). RESTORE: editor write, then `diff` vs the /tmp copy = empty, sha256 = 17dd15e2... (unchanged), `git status --porcelain` on the path = empty. AFTER: `mirror_ingress::` 11 passed / 0 failed; `apex_failover::` 4 passed / 0 failed; yah.dev / = 200 and /releases = 200, matching the opening baseline exactly.")
//! @yah:verify("CAVEATS ON THE ABOVE, stated rather than buried. (1) The first `cargo test` invocation of apex_failover.rs came back with a PostToolUse advisory that two build inputs (crates/yah/cloud-client/src/lib.rs, oss/yubaba/crates/yubaba/src/domain_issuer.rs) were edited by a peer mid-run. Neither is on this drill's path, and the one failure in that run was my own assertion targeting the wrong anyhow formatting (`{}` shows only the outer context; the pool-naming layer needs `{:#}`) — fixed in the test and the re-run was clean, so the advisory is noted but did not affect the result. (2) The real-file arms deliberately ran the ALREADY-COMPILED test binary (./target/debug/deps/main-<hash>) rather than `cargo test`, to keep the window of wrong bytes on the prod machine file to seconds instead of a build. That means those two arms exercised the source as of the immediately preceding compile, which is the same source the clean 11/0 and 4/0 runs used. (3) NOT DONE, and deliberately: no mutating `yah cloud apply`, so the drill measures the RESOLVER's refusal and nothing downstream of it. Whether a re-place would actually materialize a bundle on a cold node, cold-fetch the runtime asset, and come up serving is STILL UNMEASURED — it is unreachable without either widening `regions` for real or landing R870-F16 first.")
//! @yah:next("RECOMMENDATION FOR THE LEADER — a SECOND ticket this drill argues for, deliberately not filed (the brief scoped this session to one). The missing drain lever is separable from R870-F16 and is arguably the more dangerous of the two, because it fails SILENTLY in the operator's favour: `taints = [\"no-server\"]` on a node is accepted by `check_inert_taints` (it is a legal repelling key), passes lint, and then places the workload onto the node anyway, because a mirror-declared `required` never populates `RequiredSpec::repel_archetypes` (`#[serde(skip)]`, config.rs:4067). Shape of the fix, if wanted: either populate `repel_archetypes` on the mirror path from the slot's known archetype, or give `RequiredSpec` an explicit deserialized drain axis — and either way extend xtask/tests/fleet_taints.rs, which today only checks that no node declares an INERT taint and would not have caught this. The pinning test `apex_failover::every_repelling_taint_at_once_leaves_the_apex_bundle_exactly_where_it_was` will fail the moment that lands, which is the intended signal, not a regression.")
//! @yah:handoff("THE DESIGN FIX THIS SPIKE ARGUED FOR IS FILED, NOT GROWN INTO THE SPIKE, per the ticket's own routing instruction: R870-F16 under the live R870 relay, carrying both halves — (a) render the door's yubaba poll list from the slot's `required` CANDIDATE set instead of `plan.workload_machines()`, and (b) make the apply WRITE the door env onto the node rather than print it. The 5s/30s PASSWAY_YUBABA_TIMEOUT_SECS / PASSWAY_UPDATE_INTERVAL_SECS budget constants were re-read from oss/passway/crates/passway/src/discovery.rs rather than copied from the annotation.")
//! @yah:verify("LEADER RE-VERIFICATION, by a second independent courier session (session:8e21f595) rather than self-report: `apex_failover` 4 passed / 0 failed, and `git status --porcelain .yah/infra/machines/us-east-001.toml` empty. Both as claimed.")
//! @yah:handoff("DRILL RUN FOR REAL 2026-09-09 (the operator-requested empirical step a prior read-only session declined to spend), AND IT REFUTED HALF THE PREDICTION. The refusal half held; the TAINT half did not — there is no working drain lever for this workload class at all. `taints = [\"public-ip\", \"no-server\"]` written onto the real .yah/infra/machines/us-east-001.toml left the apex placing on us-east-001, unchanged, because taint repulsion keys off `RequiredSpec::repel_archetypes`, which is `#[serde(skip)]`, so a mirror-declared `required = {...}` always has it empty and `matches` never consults `machine.taints`. It fails silently — `no-server` is a legal key and the lint passes. Filed as R876-B7. The only lever that moves anything is `region`, and pulling it REFUSES at resolution rather than failing over.")
//!
//! @yah:ticket(R870-B11, "Bundle tier is one workload per SERVICE, so a multi-component service loses every component but the last")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:at(2026-09-09T08:02:46Z)
//! @yah:parent(R870)
//! @yah:severity(high)
//! @yah:verify("The isolation headers survive the merge: 'curl -sI https://noisetable.com/app/' carries cross-origin-opener-policy: same-origin AND cross-origin-embedder-policy: require-corp, from the /app/* route in .yah/domains/noisetable-com.toml. Without both, SharedArrayBuffer is undefined and the wasm demo throws — the R749-F3 failure mode, one route over.")
//! @yah:verify("Single-component regression: yah-marketing (one component, no mount) deploys byte-identically — same workload name, same digest for an unchanged tree.")
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @yah:tier(Wizard)
//! @yah:next("THE STANDARD, settled by the operator 2026-09-09. THREE supported configurations for composing paths on one hostname, each with an owner, and they are NOT three implementations — (2) and (3) are one passway feature at two scopes, filed as R870-F15, and (1) is assembly plus what mesofact's server already does. (1) MESOFACT SPLITS: one bundle, one serve process, components staged at their mounts inside dist/. One digest, one restart, no extra hop. Use when the components deploy together. (2) OUTER PASSWAY SPLITS: the public door path-routes to N bundle workloads. RESERVED for surfaces the door itself owns and that must answer while the upstream is down — /.well-known/*, the holding page, status. (3) INNER PASSWAY: the service runs its own non-TLS door. The DEFAULT for path-splitting an application, because a service's routes are a build-time fact about its own site and do not belong in shared public ingress. The decision rule is one question: do these components deploy together? Together -> 1. Independently -> 3. (1) and (3) compose; they are not a ladder.")
//! @yah:next("AN EARLIER DRAFT OF THIS TICKET PROPOSED CONTRACT V2 — a manifest carrying [[components]] with per-component kind and a mount dispatcher in serve. That is NOT the plan and should not be revived for the static case: the flat content map already expresses it, and mesofact's static handler already serves it. A contract bump only becomes necessary if a single bundle must carry TWO components with DIFFERENT SERVE-TIME KINDS — e.g. a second SSR project at its own mount, which needs a second isolate. Nothing declares that today. When something does, that is a new ticket, not a widening of this one.")
//! @yah:next("DO NOT LET CONFIG 1 AND CONFIG 3 BOTH CLAIM A MOUNT. mesofact's route table dispatches WITHIN a bundle; passway's dispatches BETWEEN bundles. A mount is owned by exactly one of them, and yah should refuse a config where a component is both staged into another component's bundle and given its own workload.")
//! @yah:gotcha("REPORTED BY THE NOISETABLE CAMP while standing up noisetable.com, immediately after R870-B6 made a second tenant's bundle materializable at all. noisetable-marketing declares TWO static components — 'site' (mesofact-spa, web/landing, no mount) and 'app' (mesofact-static, app/browser, mount = \"/app\", the Trunk-built wasm demo). One apply reconciles both. Both assemble their OWN bundle and both deploy it under the SAME workload name — [providers.bundle].name = \"noisetable\" in the mirror — so the second reconcile replaces the first and the last component in service.toml becomes the whole of the hostname.")
//! @yah:gotcha("MEASURED 2026-09-09 on the live apply, both orderings. With 'site' first: 'component site -> bundle \"noisetable\": 26 file(s) digest 21dabdf8', then 'component app -> bundle \"noisetable\": 7 file(s) digest c130e77e', and the door served the 7-file app bundle — https://noisetable.com/ = 404 AND https://noisetable.com/app/ = 404, because Trunk output is rooted at '/' so that bundle holds neither the landing index nor anything under /app/. With 'app' first the marketing page comes back 200 and /app/ stays 404. Two components, one upstream, no ordering that serves both.")
//! @yah:gotcha("ROOT CAUSE, read not guessed: 'mount' has ZERO occurrences in mesofact_bundle.rs. It is honoured only by the STATIC tier, where publish_prefix(service, env, mount) extends the R2 key (mesofact_static.rs:903, :1435) — that is what kept these two components from colliding under the retired Cloudflare Worker door, which resolved a request by path out of R2. passway has no path resolver in front: it proxies a hostname to ONE upstream, and the upstream is the single mesofact-serve workload. So the separation that exists in the object store does not exist at the door, and the bundle tier never learned about mounts.")
//! @yah:gotcha("THIS IS THE SAME DEFECT CLASS AS R870-B6 AND MesofactServeBundle::port BEFORE R844-F2 — a per-service or per-node singleton where a per-workload value belongs. B6 was the store axis (one KAMAJI_BUNDLE_ORIGIN per node), R844-F2 was the port axis (one KAMAJI_BUNDLE_PORT per node), this is the identity axis (one bundle workload per service). Each was invisible while exactly one thing existed and became a silent overwrite the moment there were two.")
//! @yah:handoff("CONFIG1-INTERNAL GUARD LANDED AND TESTED, in oss/yubaba/crates/cloud/src/config.rs's `cross_ref_validate` (NOT cloud.rs — this file had no live-peer WIP). For every service, if two or more `mesofact-static`/`mesofact-spa` components declare the same normalized mount (via `normalize_mount`, None treated as the service root), CloudConfig::load now bails naming both component ids and the mount, before anything stages to disk. This is the config1-internal half of the ticket's overlap guard: a mount is owned by exactly one bundle-tier component. Three new tests added directly below `mount_and_route_prefix_normalization_agree` in config.rs's test module: two_bundle_components_at_the_same_mount_are_rejected, two_bundle_components_with_no_mount_are_rejected (the literal noisetable-shape footgun if `app`'s mount had been omitted instead of declared), bundle_components_at_distinct_mounts_still_load (regression guard using the existing write_two_component_service fixture, the noisetable.com shape). cargo test -p yah-cloud --lib: 1120 passed/0 failed/4 ignored before these 3 tests existed (verified by inspection — the new validation is a wholly new, early-return-free loop no pre-existing test path could have hit; git stash to get a literal pre-edit number was refused by this camp's git policy, defer mode), 1123 passed/0 failed/4 ignored after. Zero regressions.")
//! @yah:handoff("COLLISION DISCOVERED AND RESPECTED, exactly the shape the dispatch note pre-authorized reporting rather than resolving. app/yah/cli/src/cloud.rs, oss/yah-base/crates/mesofact-bundle/src/assemble.rs, and oss/yah-base/crates/mesofact-bundle/src/lib.rs are ALL currently mid-turn-edited (party.agent_status on session:6c6bce91 read in_progress:true at the time of this session) by @Ashguard:blade under leader session:241139dd/R877 — NOT the B12-determinism work the dispatch note attributed to that session's cloud.rs dirtiness. The in-flight code is titled 'R870-B11' in its own comments and already implements the OPERATOR-MANDATED design, not the earlier contract-v2 draft: oss/yah-base/crates/mesofact-bundle/src/assemble.rs gained `pub fn collect_component_files(project_root, out_dir, mount: Option<&str>, include_config: bool)`, which stages a component's dist tree at `app/dist/<mount>/` (root when mount is None) exactly as the ticket's `next` specifies, and re-exports it from lib.rs. cloud.rs's `deploy_mesofact_bundle` and `reconcile_component` already detect multi-component bundle-tier services (`bundle_component_ids.len() > 1`, filtered on kind mesofact-static/mesofact-spa) and pick a shared `.yah/infra/state/bundles/<service>/__service` staging dir instead of one per component, and non-primary components now return `RunningWorkload::adopted(...)` as a no-op instead of deploying separately.")
//! @yah:handoff("THAT WIRING IS INCOMPLETE AS OF THIS SESSION, not a design disagreement — grepped cloud.rs for every call site of `collect_component_files`: zero. `deploy_mesofact_bundle` picks the shared staging dir and the primary component's build info, but nothing in the current diff actually calls the new primitive to merge each component's dist/ tree into that shared staging dir before the manifest is assembled, so as committed today the merge would still produce a bundle containing only the primary component (an improvement over the current silent-overwrite bug — the second component would be a clean no-op instead of clobbering the workload — but not yet the fix: /app/ would still 404, not 200).")
//! @yah:handoff("Tree anchor at handoff: 5f4c7b8b956196ae292ffba3c6b50aec52e81760 — the shared tree as I left it. Diff against it (`git diff 5f4c7b8b956196ae292ffba3c6b50aec52e81760..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:verify("cargo test -p yah-cloud --lib (from oss/yubaba) — 1123 passed, 0 failed, 4 ignored, run twice (once confirming the 3 new tests individually, once the full suite) after the config.rs guard landed.")
//! @yah:notify_on(R877-F2, "R877-F2's courier edited one character inside deploy_mesofact_bundle while it was your in-flight, uncommitted work — re-check it. The call to component_workload_dir passed `cfg.workspace_root` (a PathBuf) where the fn takes `&Path`, which red-lined the whole `yah` crate for every session in the camp; it was fixed forward with a `&` rather than reverted, because the fn is new and no last-good SHA existed. Your logic is untouched — the site is now `component_workload_dir(&cfg.workspace_root, ctx.service, primary)` (app/yah/cli/src/cloud.rs, in the is_multi_component arm). Overwrite freely if your own version differs; just don't drop the borrow.")
//! @yah:handoff("AUTHORSHIP RESOLVED PER THE LEADER'S CORRECTION: no camp.who_wrote tool exists in this build (ToolSearch for that name and for \"who wrote\"/\"authorship\" returned nothing), so I used party.btw on the R870 leader (session:abde2cbb) instead. Its transcript recall: R870-B11 was first dispatched to @Kriek:polaris (bundle-kimi-krieg), flagged immediately as the wrong tier for a Rust refactor and superseded — that session is no longer in camp.roster/camp.sessions (confirmed absent from both just now), so nothing live owns it. @Ashguard:blade (session:6c6bce91) was independently confirmed NOT the author — its parentSessionId is the R877 leader, its activeToolCall was a musl cargo check (read-only), and party.agent_status showed in_progress:true but on that unrelated build, not a Write/Edit. So the mount-staging code sitting in the tree was Kriek's abandoned WIP: unowned, matching the operator-mandated design, safe to finish.")
//! @yah:handoff("WIRED END TO END, in the three files the abandoned WIP had already started (I finished, did not restart): oss/yah-base/crates/mesofact-bundle/src/assemble.rs gained `assemble_bundle_from_files(dest, name, runtime_version, files, serve_bins, sidecar_bins, built_against)` — the multi-component counterpart to `assemble_self_bundle_with`/`assemble_vanilla_bundle`, picking vanilla vs self-contained the same way, but taking an already-merged `Vec<BundleFile>` instead of collecting from one `(project_root, out_dir)`. Re-exported from lib.rs. app/yah/cli/src/cloud.rs gained `assemble_multi_component_bundle`, called from `deploy_mesofact_bundle` in a new `is_multi_component` branch: for each bundle-tier component it resolves the project dir (`component_workload_dir`, already present), runs its build, and calls `yah_mesofact_bundle::collect_component_files(project, out_dir, mount, include_config = idx==0)` — the mount-aware primitive the abandoned WIP had already written — merging every component's files into ONE list before calling `assemble_bundle_from_files`. `reconcile_component`'s pre-existing guard (unchanged, verified consistent: same filter predicate and iteration order) already only calls `deploy_mesofact_bundle` for the first bundle-tier component, so `ctx.component` is provably the primary throughout.")
//! @yah:handoff("TESTED AT EVERY LEVEL AVAILABLE WITHOUT A LIVE APPLY. New assembler-level tests in cloud.rs's `bundle_assembly_tests` module (the ticket's own required tests): `two_mounted_components_merge_into_one_bundle` — a site (no mount) + app (mount /app) component assemble into ONE manifest whose content map carries `app/dist/index.html` AND `app/dist/app/index.html`, both files verified present on disk with their distinct content. `single_component_via_multi_path_matches_single_component_path` — the multi-component assembler, given exactly one component, produces a byte-identical manifest (same digest, same content keys) to the pre-existing single-component path for the same fixture — the strongest available form of \"yah-marketing deploys byte-identically\", since the single-component code path in `deploy_mesofact_bundle` is untouched by this change (still calls `assemble_component_bundle_with_sidecars` exactly as before) and is now also proven equivalent at the primitive level.")
//! @yah:handoff("ISOLATION HEADERS SURVIVE THE MERGE BY CONSTRUCTION, not by a change I made: `add_declared_route_headers(&mut serve_env, ...)` in `deploy_mesofact_bundle` already reads ALL of a service's declared route headers from the domain config (service-scoped, not component-scoped) and runs once regardless of is_multi_component — so the /app/* COOP/COEP rule was already flowing into the one shared `serve_env` before this change and still does now that there's only one bundle to carry it. Not independently re-verified by a new test (would need full domain-config + `mesofact::Server` integration, out of assembler-test scope) — the live `curl -sI` check from the ticket's own verify list is the real proof and is part of the unrun live gate below.")
//! @yah:verify("cargo test -p yah-mesofact-bundle --lib (from oss/yah-base): 34 passed, 0 failed — no regressions from assemble_bundle_from_files.")
//! @yah:verify("cargo test -p yah --lib -- cloud:: (whole cloud module, from workspace root): 165 passed, 0 failed, 1 ignored — includes both new R870-B11 assembler tests plus every pre-existing bundle_assembly_tests test (assembly_is_deterministic, sidecars_without_serve_bins_are_rejected, a_self_contained_bundle_carries_the_feed_sidecar, etc.), all still green.")
//! @yah:verify("cargo test -p yah-cloud --lib (from oss/yubaba): 1128 passed, 0 failed, 4 ignored — includes the three R870-B11 mount-ownership-guard tests from the prior handoff. Re-run twice across both edit sessions; camp build-skew advisories fired on shared, unrelated files each time (demux_routes.rs, validate.rs, qed/publish.rs) — none overlapped my four touched files, confirmed by content, not just by filename absence from the warning.")
//! @yah:verify("All four touched files (assemble.rs, lib.rs, cloud.rs, config.rs) are captured in the camp's automatic sync commits c6cd94fd and 718dfacb (verified by `git show <sha>:<path> | grep` for my actual function/test names, not just diffstat line counts) — nothing was lost when the working tree went clean mid-session.")
//! @yah:verify("LEADER RE-VERIFICATION (session:abde2cbb, 2026-09-09), independent of the courier: `cargo test --manifest-path oss/yah-base/Cargo.toml -p yah-mesofact-bundle` = 34 passed / 0 failed, and `cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib` = 1128 passed / 0 failed / 4 ignored. Both match the courier's reported counts exactly. (Note for anyone re-running these: neither crate is a member of the ROOT workspace, so a bare `cargo test -p yah-cloud` fails with \"requires dev-dependencies and is not a member of the workspace\" — the manifest-path form above is the one that works.)")
//! @yah:gotcha("PROCESS NOTE WORTH MORE THAN THE FIX, because it nearly cost this ticket twice. The mount-staging work was started by a FIRST courier that was superseded mid-flight (a Kimi-tier carrier misrouted by the R879-B1 slot-allocator bug), which left half-wired code in the tree with no live owner. The SECOND courier found it, inferred from the dispatch's shared-tree warning that a live peer (@Ashguard:blade) owned it, and stopped — returning `ok` on a ticket whose core was unbuilt. The premise was wrong: camp.roster showed blade's parentSessionId was session:241139dd, the R877 relay leader, and its activeToolCall was a musl cross-check. ABANDONED WIP IS NOT A PEER'S IN-FLIGHT WORK, and the two are indistinguishable from `git status` alone — the discriminator is the roster's parent/ticket/activeToolCall, not the dirty-file list. Also recorded because the doctrine points at a tool that does not exist on this surface: the second courier reported `camp.who_wrote` is unavailable and had to establish authorship via party.btw instead.")
//! @yah:gotcha("THE LIVE GATE HAS NOW BEEN RUN AND IT PASSES — 2026-09-10, from the noisetable camp, on a yah CLI built from this fix (0.8.37, `yah qed run yah-cli-install`). `yah cloud apply --env cloud --service noisetable-marketing` -> 2 components reconciled, one merged bundle. Every route on the hostname: / 200, /market 200, /account 200, /credits 200, /app 200, /app/ 200. `curl -sI https://noisetable.com/app/` carries BOTH cross-origin-opener-policy: same-origin and cross-origin-embedder-policy: require-corp. The mount's real assets serve, not just its index: /app/noise_table_browser-4fa9b4e37cb997d3.js 200 (87928 B), the same-hash _bg.wasm 200 (22822173 B, content-type application/wasm), /app/audio_worklet_processor.js 200. /.well-known/yah-publish.json 200, which also proves the site stayed the config-owning primary. This ticket's own verify list is met end to end.")
//! @yah:gotcha("THE FIX WAS ONE LINE PLUS ITS TEST, and it is NOT the design choice the earlier gotcha left open. `collect_component_files` (oss/yah-base/crates/mesofact-bundle/src/assemble.rs) now builds `dist_prefix = format!(\"app/dist/html/{m}\")` for a mounted component instead of `format!(\"app/dist/{m}\")`. The server was left alone deliberately: `app/dist/html/` is a SERVER-SIDE CONSTANT, not a build-output coincidence — `Server::from_bundle` hands `from_workload` the bundle's `app/` dir and `from_workload` does `DistPointer::new(workload.join(\"dist\").join(\"html\"))` (oss/mesofact/crates/mesofact/src/server.rs:268). Corroborated independently by BUNDLE_BEACON_PATH in yubaba's publish_beacon.rs, which is already `app/dist/html/.well-known/yah-publish.json`. So `dist/html` is where a bundle's servable tree lives, full stop, and teaching the server a SECOND root at `dist/<mount>/` would have added a resolution rule to serve files that simply belong one directory over. The unmounted primary still stages at `app/dist` and needs no `html/` of its own: a mesofact-spa/static build already emits one inside its out_dir. Grepped for a second staging site before editing — `format!(\"app/dist` has exactly one occurrence in the tree, so there is no other path to keep in step.")
//! @yah:verify("cargo test --manifest-path oss/yah-base/Cargo.toml -p yah-mesofact-bundle: 36 passed, 0 failed (34 before, +2 for the new served-root tests). No regressions from the prefix change — the unmounted path is untouched.")
//! @yah:verify("cargo test -p yah --lib -- cloud:: (workspace root): 175 passed, 0 failed, 1 ignored — includes the repointed two_mounted_components_merge_into_one_bundle and single_component_via_multi_path_matches_single_component_path plus every pre-existing bundle_assembly_tests case. The single-component byte-identical test still passes, so yah-marketing's shape is unchanged by the mount fix.")
//! @yah:verify("LIVE, 2026-09-10 from ~/ss/noisetable: `yah cloud apply --env cloud --service noisetable-marketing` then / 200, /market 200, /account 200, /credits 200, /app 200, /app/ 200; `curl -sI /app/` carries both isolation headers; /app/*.js, /app/*_bg.wasm (application/wasm, 22.8 MB) and /app/audio_worklet_processor.js all 200. The stopgap ordering question is settled separately — see the note below.")
//! @yah:gotcha("WHY THE UNIT TEST WENT GREEN ON A BROKEN PATH, AND WHAT THE FIXTURE NOW DOES INSTEAD — the durable half of this ticket, because it is the reason a wrong path reached a live deploy at all. `two_mounted_components_merge_into_one_bundle` used to assert the content map carried `app/dist/index.html` AND `app/dist/app/index.html`. Both keys were exactly what the code produced and NEITHER was what mesofact serves: the shared `component()` fixture wrote `dist/index.html`, a convenience shape no real mesofact build emits (a mesofact-spa build emits `dist/html/index.html`). The fixture encoded the same wrong layout the implementation had, so both halves could stage outside the served root and still agree — the test's oracle WAS the implementation's own path construction, which proves only self-consistency. FIXED, not just noted: a new `spa_component()` fixture in app/yah/cli/src/cloud.rs writes `dist/html/index.html` (kind = mesofact-spa, the served layout) and the merge test uses it instead of `component()` — deliberately a NEW fixture, since `component()` is shared by many unrelated tests and its dist-root shape is fine for them. `mounted_component()` keeps `dist/index.html`, which IS correct: that is Trunk's real output. The assertions now derive from the server: a `SERVED_ROOT = \"app/dist/html/\"` constant, a loop asserting every `app/dist/**` key starts with it, then the two specific keys. Two more tests in assemble.rs cover the primitive directly — `a_mounted_component_stages_inside_the_served_root` and `an_unmounted_component_stages_its_own_html_tree_at_the_dist_root`, both asserting against hand-written literals rather than a recomputed prefix.")
//! @yah:verify("Ordering: both routes serve 200 with 'site' declared first. NOT verified in the reverse order, and deliberately so — see the gotcha on why order remains load-bearing for config staging. Serving is order-independent; the staged config is not.")
//! @yah:gotcha("THE ORDERING NOTE IN noisetable's service.toml DOES NOT GET DELETED, and this ticket's original verify item asking for that is WRONG — repointed rather than quietly dropped. The premise was 'order stops mattering once the overwrite race is gone'. The overwrite race IS gone, but declaration order stayed load-bearing for an unrelated reason the merge introduced: `assemble_multi_component_bundle` calls `collect_component_files(..., include_config = idx == 0)`, so `mesofact.routes.ts`, `mesofact.config.toml` and the built manifest's `data_inputs` are staged from the FIRST bundle-tier component only, and `deploy_mesofact_bundle` likewise takes the workload envelope's build provenance from `bundle_components[0]`. On noisetable.com only web/landing owns those files — app/browser is a Trunk project with none — so 'app' first stages NO config and silently drops the site's. Proven on a real apply, not argued: with 'site' first, `app/mesofact.routes.ts` appears in the staged manifest and /.well-known/yah-publish.json serves 200; the old order dropped it. So the note was REWRITTEN to name the new reason (and the `app/dist/html/<mount>/` staging path), not removed. If yah wants order to genuinely stop mattering, that is a separate ticket: pick the config-owning primary declaratively — the component that HAS a `routes` field, or an explicit `primary = true` — instead of by index.")
//! @yah:next("SCOPE AS SHIPPED — CONFIG 1, ASSEMBLY-ONLY. No contract bump, no serving change: `BundleManifest.content` is a flat path map and contract v1 clause 2 only requires built assets under `app/dist/**`, so `app/dist/html/<mount>/**` is expressible on contract 1 today. mesofact::Server already serves any file under its dist root by path, with a clean-URL .html fallback, and already applies the per-route header table as its outermost layer. The fix was the assembler staging each mounted component's build output INSIDE the served root at `app/dist/html/<normalized mount>/` — an earlier draft of this line said `app/dist/<mount>/`, which is the bug that reached production. The serving half needed nothing.")
//!
//! @yah:ticket(R870-B12, "A mesofact-spa component rebuilds to a different bundle digest every apply, defeating W272 blob dedupe")
//! @yah:status(review)
//! @yah:at(2026-09-09T07:53:11Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R870)
//! @yah:severity(medium)
//! @yah:gotcha("MEASURED, not inferred (R870-T9, 2026-09-08). Three consecutive `yah cloud apply --service noisetable-marketing --env cloud` runs from an UNCHANGED bundle source tree produced three different bundle stamps for the `site` component, read straight off the live door at https://noisetable.com/.well-known/yah-publish.json: 44c3268ca235 -> eb800ef6a775 -> 78d4396f8d51, all reporting `files: 25`. Same file COUNT, different content digest, so some entry's bytes change on every build. The only edits between runs were to the mirror TOML (.yah/services/noisetable-marketing/mirrors/cloud.toml), which is not bundle content.")
//! @yah:gotcha("DO NOT GO LOOKING IN THE ASSEMBLER — it is not the assembler. `assembly_is_deterministic` (app/yah/cli/src/cloud.rs) passes and is genuinely testing what it claims: identical inputs assemble to an identical digest, and R703-T7 deliberately made the publish beacon clock-free to keep that true. The inputs are what differ. `site` is `kind = \"mesofact-spa\"` (web/landing), and a mesofact-spa build emits a per-build id that lands in the prerendered HTML and the hydrate paths (`/{build_id}/hydrate/...`, oss/mesofact/crates/mesofact/src/server.rs), so the built tree is different bytes each time. That last sentence is INFERENCE from the shape of the evidence plus the hydrate-path convention — the exact generation site was not located, and locating it is step one.")
//! @yah:next("STEP 1, LOCALIZE: find where a mesofact-spa build derives its build id and confirm it is the (only) source of per-build drift. Cheapest proof: assemble the same component twice with `yah cloud bundle build`, diff the two staging trees entry-by-entry, and name the files whose hashes moved. If it is only the build-id-bearing files, the fix is to derive the id from content (a hash over the build inputs) instead of from a clock/counter — which is the same move R703-T7 already made for the publish beacon and for the same reason.")
//! @yah:next("WHY IT MATTERS, so nobody files this as cosmetic. W272 §1 immutability is what makes a re-publish a no-op: matching blobs dedupe, the node skips materializing, and an unchanged site does not restart its serve process. A digest that moves on every apply defeats all three — every apply re-uploads, re-materializes and re-forks, which costs a real ~2s of 502 on whatever that serve process fronts (measured on us-east-001 2026-09-09, R876-T1, recorded in scripts/hotship.sh's header). So an apply that changes nothing still takes the site down for two seconds.")
//! @yah:verify("Two `yah cloud bundle build` runs of .yah/services/noisetable-marketing component `site`, from an unchanged tree, produce the same manifest digest — and the door's beacon at https://noisetable.com/.well-known/yah-publish.json stops moving across repeated no-op applies.")
//! @yah:handoff("ROOT CAUSE CONFIRMED, and the ticket's INFERENCE was right: mesofact_build::pipeline::default_build_id() (oss/mesofact/crates/mesofact-build/src/pipeline.rs:59, pre-change) was a SystemTime::now() UTC stamp at one-second resolution. LOCALIZED BY MEASUREMENT, not by reading: built the `spa` fixture twice with the PRE-CHANGE binary and diffed entry-by-entry. Exactly three files drifted and no others -- dist/html/app.html (the hydration weave bakes `/{build_id}/hydrate/app.CZuUyrnp.js`), dist/manifest.json (`build_id` field), dist/tag-index.json (`build_id` field). Hydrate bundle names are content-hashed by rolldown and did NOT move, which is why the live door reported the same `files: 25` on all three drifting stamps. Second half of step 1 (is the build id the ONLY drift source): built four richer fixtures -- head-sitemap, static-assets, spa-parametric, static-islands -- twice each with an EXPLICIT fixed --build-id; every pair was byte-identical, so with the clock pinned nothing else in the pipeline is non-deterministic.")
//! @yah:verify("GATE MET on the real component. Two `yah cloud bundle build web/landing --out <tmp> --run-build` runs from ~/ss/noisetable (component `site` of .yah/services/noisetable-marketing), each doing a full `bun run build:cloud`, both printed `files: 34, digest: 896b4c39fcba7492a28c337df2565ace94de7c118bfe07ead2ff59c9934cdb6a`. Also ran the raw binary twice against /Users/leif/ss/noisetable/web/landing into two /tmp out-dirs: same 23-file tree byte-for-byte, same build_id 441813d4564564aae8524b8500e3c57a. TESTS: cargo test -p mesofact-build -> lib 111 passed / 0 failed / 3 ignored; tests/pipeline.rs 12 passed (9 pre-existing + 3 new); check_cli 5, conformance 4, render 7; all green, exit 0. Baseline caveat stated plainly: the pre-change baseline I measured was BEHAVIOURAL (the three-file drift above, with the pre-change binary); I did not run the cargo suite before editing, so the no-regression claim rests on all 9 pre-existing pipeline tests plus all 111 lib tests passing after.")
//! @yah:handoff("FIX LANDED in oss/mesofact/crates/mesofact-build/src/pipeline.rs (+ tests/pipeline.rs). default_build_id() and its civil_from_days() date helper are DELETED -- no clock left in the build. The id is now derived from the built tree, following R703-T7's shape (compute after the artifacts exist; the self-referential part is excluded because a digest covering itself has no fixed point). Mechanism, three new items in pipeline.rs: (1) BUILD_ID_PLACEHOLDER = \"__mesofact_build_id__\" is woven by prerender in place of the id, breaking the cycle where the id names a tree that cannot be finished without it; (2) scan_staged_tree() walks out_dir after prerender, hashing every file to BLAKE3 (yah_mesofact_bundle::BundleHash, the same hash the W272 bundle uses) and noting which files carry the placeholder -- it skips .mesofact-build/ (scratch, deleted before return) and top-level manifest.json / tag-index.json / sitemap.xml, which are written later and whose stale copies from a previous build must not feed the id; (3) derive_build_id() hashes that path->hash map plus the serialized manifest and keeps 32 hex digits (128 bits -- collision-proof, short enough to read in the `/{build_id}/hydrate/...` and `<build_id>/html/...` paths where it is actually seen), then substitute_build_id() rewrites the placeholder in place. An explicit BuildOptions.build_id still wins and skips derivation entirely, so every existing caller and test is unaffected. Hashing the OUTPUT rather than the input sources is deliberate and stronger than the ticket's suggested \"hash over the build inputs\": noisetable's `build:cloud` differs from `build` only by the NOISETABLE_API_ORIGIN env var, and a data_inputs change moves prerendered HTML without moving any source file -- an input hash would miss both, an output hash cannot. Three tests pin it in tests/pipeline.rs: two_builds_of_an_unchanged_tree_are_byte_identical (fails on exactly the three files named above without the fix, and its assert names the drifting paths), a_different_project_derives_a_different_build_id (guards the opposite failure -- a stable-but-constant id would pass the first test while serving stale bytes from an immutable prefix forever), and no_placeholder_survives_into_the_built_tree.")
//! @yah:gotcha("THE LIVE HALF OF THE VERIFY IS UNRUN. Repeated no-op applies against noisetable.com are an outward-facing deploy to live infra, so this session stopped short of them. Exact command, from ~/ss/noisetable: run `yah cloud apply --service noisetable-marketing --env cloud` two or three times with NO edits in between, reading `curl -s https://noisetable.com/.well-known/yah-publish.json` after each -- the `digest` must be identical across all runs (it moved 44c3268ca235 -> eb800ef6a775 -> 78d4396f8d51 on 2026-09-08, which is what filed this ticket). Note the bundle the apply assembles is NOT digest-comparable to the local `yah cloud bundle build` runs recorded in verify: the reconciler names it per the service component and stamps the publish beacon, so its digest differs by construction. The invariant to check is that it stops MOVING, not that it matches any local value. Note also that the site component's `dist/` is now content-addressed while the `app` component (mesofact-static, Trunk) was never checked for its own per-build drift -- if the beacon still moves after this, `app` is the next place to diff.")
//! @yah:cleanup("The TS pipeline still has the identical clock bug: defaultBuildId() at oss/mesofact/packages/mesofact-build/src/index.ts:422 is `new Date().toISOString()`, consumed at index.ts:135. Deliberately NOT fixed here. Nothing in this camp builds through it -- app/yah/web/{marketing,dashboard,analytics} and noisetable's web/landing all shell to the Rust binary (scripts/mesofact-build.sh / `cargo run -p mesofact-build`), and tests/pipeline.rs:160 already records that the Rust pipeline is the sole production build path. Porting the derivation to TS means reimplementing the placeholder weave in prerender.ts plus a tree walk and BLAKE3 in TS, with no camp build that would catch a divergence. Worth doing if the TS pipeline ever regains a production consumer.")
//! @yah:verify("LEADER RE-VERIFICATION (session:abde2cbb, 2026-09-09), run independently of the courier. Read the change by content first: `oss/mesofact/crates/mesofact-build/src/pipeline.rs` deletes `default_build_id()`'s `std::time::SystemTime::now()` stamp outright (not shimmed beside it), weaves a `BUILD_ID_PLACEHOLDER` through prerender, then derives the real id in `derive_build_id(&StagedTree, manifest_json)` and substitutes it via `substitute_build_id` — R703-T7's content-hash shape, applied to the same defect one layer down. An explicit `opts.build_id` still wins, so the caller-supplied path is unchanged. Then ran the suite myself: `cargo test -p mesofact-build` is fully green — 12 passed / 0 failed in tests/pipeline.rs (including the two that pin this ticket, `two_builds_of_an_unchanged_tree_are_byte_identical` and `a_different_project_derives_a_different_build_id`), 7 passed / 0 failed in tests/render.rs, 0 failures anywhere. The determinism is pinned by test rather than by a one-off manual run, which is what this ticket needed — its failure mode was \"works today, drifts again in a month\".")
//!
//! @yah:ticket(R870-B13, "A borrowing camp cannot render sovereign apex A records: domain phase demands .yah/infra/machines/ the camp does not have")
//! @yah:status(review)
//! @yah:at(2026-09-09T08:07:39Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R870)
//! @yah:severity(medium)
//! @yah:gotcha("SURFACED 2026-09-08 (R870-T9) AND IT WAS PREVIOUSLY MASKED — read that before assuming it is a regression. `yah cloud apply --service noisetable-marketing --env cloud` from ~/ss/noisetable now reaches its domain phase for the first time (the marketing service used to hard-fail at the serving check before domains ran) and reports: `domain api-noisetable-com (api.noisetable.com): rendering sovereign apex A records from the ingress collation (DNS-only)` -> `FAILED: front door collated onto machine \"us-east-001\", which has no .yah/infra/machines/*.toml — cannot resolve its public address`. The SERVICE half is green in the same run (`noisetable-marketing  ok  2 component(s) reconciled`), so noisetable.com is unaffected and serving; what fails is the api.noisetable.com DNS render.")
//! @yah:gotcha("THE CAUSE IS ALREADY WRITTEN DOWN, in ~/ss/noisetable/.yah/services/noisetable-marketing/mirrors/cloud.toml's placement note: this camp BORROWS yah's fleet without importing its inventory — `.yah/infra/machines/` under ~/ss/noisetable is an EMPTY DIRECTORY, while the machine files live in ~/ss/yah and are read-only from there. That is the same constraint that forces `[providers.bundle]` to pin `machines = [\"us-east-001\"]` instead of declaring `required = { regions, mesh_tags }`, and the same reason noisetable-api's `[providers.compute]` writes `kind = \"static\"` + `machine = \"us-west-001\"` rather than `use = \"hetzner\"`. A pin is expressible because it is just a name; resolving that name to a PUBLIC ADDRESS is not, and the apex A-record render needs the address.")
//! @yah:next("THE SHAPE OF THE FIX IS AN OPERATOR CALL, not a code call, which is why this is filed rather than fixed. Two expressible answers and they are not equivalent: (a) the borrowing camp declares its own `.yah/infra/machines/` entries — cheap, immediate, and a second copy of the fleet inventory that will drift from ~/ss/yah's silently; (b) yah exposes its inventory to borrowing camps over some read path, so there is one copy — the right shape, more work, and it decides how a camp names another camp's fleet. The mirror's own placement note already anticipates exactly this fork (\"TO CONVERT TO CONSTRAINTS LATER, one of two things has to happen first\"), so whichever is chosen also unblocks constraint-based placement in that camp, not just this DNS render.")
//! @yah:next("OPERATOR ANSWERED 2026-09-09 (asked by the R870 relay leader, session:abde2cbb): option (b) — yah exposes its inventory to borrowing camps over a read path, so there is ONE copy. Option (a) (the borrowing camp declaring its own .yah/infra/machines/ entries) is REJECTED: a second copy of the fleet inventory drifts from ~/ss/yah silently and nothing detects the drift until a render is already wrong. So this ticket is no longer blocked on a decision — it is a design-plus-implementation task. Its scope now includes deciding how a camp NAMES another camp's fleet, because option (b) cannot be built without that, and per the mirror's own placement note the same answer also unblocks constraint-based placement (`required = { regions, mesh_tags }`) in the borrowing camp rather than only this DNS render.")
//! @yah:handoff("DESIGN, AND WHAT IT REPLACES. The defect was not in the apex renderer — it was that a camp's machine inventory had TWO readers that disagreed about what the inventory is. CloudConfig::load applied the .yah/infra/sources.toml overlay inline (R615-F2, landed long ago); validate::load_machine_tomls did not, and the two callers that resolve a machine NAME to a machine — collate_workspace_ingress and reconciler::domain::plan_passway_apex — both read the latter. So in a borrowing camp (empty local machines/, one [[source]] link) the apex render failed on a machine that was declared all along, one directory over. The fix is one function: config::resolve_fleet_inventory(workspace_root) -> FleetInventory, extracted OUT of CloudConfig::load, which is now a caller of it rather than a second implementation. Three callers, one answer.")
//! @yah:handoff("THE NAMING DECISION (the design call this ticket assigned, made and justified rather than escalated): a camp names another camp's fleet through the [[source]] entry R615-F1 already defines — `owner` is the logical name an operator sees, `kind = \"path\"` resolves against the borrowing camp's own root, `kind = \"git\"` against `yah infra sync`'s cache. NO second naming scheme was invented, deliberately. A camp that could name a foreign fleet two ways is a camp whose inventory can drift from itself, which is precisely what option (a) was rejected for. It also honours the ticket's camp-boundary constraint by construction: kind=path resolves to <path>/.yah/infra, i.e. inside the same .yah/ whose camp.toml defines the boundary — noisetable's existing sources.toml already spells it and needed no change.")
//! @yah:handoff("ONE COPY, argued rather than asserted. kind=path reads the owner's live tree at <path>/.yah/infra/ on EVERY load — the borrowing camp persists nothing, so the two cannot disagree. kind=git reads a synced checkout, which IS a copy, but an explicit one with a named refresh verb (yah infra sync) and a pinned ref; that is the cache-with-an-invalidation-story the brief allows, as against a hand-maintained second inventory. noisetable uses kind=path, so for the camp in the defect there is literally one copy of the fleet, in ~/ss/yah.")
//! @yah:handoff("BREAK-DON'T-TAPE, no fallback added. validate::MachineLoadMode is DELETED (its Strict variant existed only for the two resolution callers, which now read the inventory). load_machine_tomls is RENAMED to load_camp_local_machine_tomls, unconditionally tolerant, and its doc now states it is the LINT loader and not the fleet inventory — camp-local is its whole contract, because a lint exists to name a file the operator can edit and a borrowed machine lives in a tree they cannot. There is no read-local-then-fall-back-to-borrowed path anywhere: resolve_fleet_inventory is always camp-local-then-overlay, with camp-local winning any name collision and earlier sources beating later ones (R615-F2's rules, unchanged, now in one place).")
//! @yah:handoff("FILES (all in ~/ss/yah — nothing in ~/ss/noisetable was touched). oss/yubaba/crates/cloud/src/config.rs: new pub FleetInventory { machines, origins, sources, contributions } + pub SourceContribution + pub resolve_fleet_inventory(); overlay_infra_sources() split into overlay_source_machines() (returns per-source contributions) and overlay_source_providers(); CloudConfig::load now calls resolve_fleet_inventory for its machine half (the legacy .yah/cloud/machines/ merge moved in with it, precedence preserved) and overlay_source_providers for providers. oss/yubaba/crates/cloud/src/validate.rs: MachineLoadMode deleted, loader renamed, collate_workspace_ingress reads the inventory. oss/yubaba/crates/cloud/src/reconciler/domain.rs: plan_passway_apex reads the inventory; public_origins' error text no longer says \"has no .yah/infra/machines/*.toml\" (it was wrong even in spirit) but names both surfaces.")
//! @yah:handoff("THE DIAGNOSTIC SEAM, added because the failure class is indistinguishable from the name alone. \"no such machine\" reads identically whether a camp declared no link, aimed one at a directory that is not a camp, or filtered the machine out with `select`. So SourceContribution records per-source { owner, source, root, root_exists, machines-added } and FleetInventory::describe_sources() renders it; plan_passway_apex attaches it to the error ONLY on failure (map_err, and only when non-empty, so a camp with no sources gets no dangling header). A source contributing zero machines is deliberately NOT an error at load time — an unsynced kind=git source is legitimately empty and CloudConfig::load must stay offline (R615-F2) — so the fact is carried to whoever actually fails for want of a machine.")
//! @yah:handoff("CONSTRAINT-BASED PLACEMENT IS UNBLOCKED IN THE BORROWING CAMP — the mirror's own \"TO CONVERT TO CONSTRAINTS LATER\" fork is answered, and this reaches further than the DNS render. The quoted failure in that placement note (`ingress declaration does not plan — ... no candidates matching required.regions=[us-east] + required.mesh_tags=[tag:cloud-runner] — declared machines: (no machines declared under .yah/infra/machines/)`) is IngressProblem::Declaration raised from collate_workspace_ingress, which is exactly the caller fixed here: resolve_ingress_placements now gets the borrowed fleet as its candidate set. Pinned by a_borrowing_camp_can_place_by_constraint_rather_than_by_pin (validate.rs), which plans a mirror carrying only `required = { regions, mesh_tags }` and no pin. The apply path was never affected — it resolves from cfg.machines off CloudConfig::load, which already had the overlay.")
//! @yah:handoff("CONVERTING NOISETABLE'S PINS IS A SEPARATE TICKET AND NOT MINE TO FILE OR MAKE. ~/ss/noisetable is a different camp; the edits would be to .yah/services/noisetable-marketing/mirrors/cloud.toml ([providers.bundle] machines = [\"us-east-001\"] -> required = {...}) and .yah/services/noisetable-api/mirrors/cloud.toml ([providers.compute] kind=\"static\" + machine=\"us-west-001\" -> use=\"hetzner\" + required). Two reasons to keep them separate rather than fold them in: (1) that camp's own mirror documents why us-east-001 is NOT an arbitrary pick — the three live doors poll http://100.64.0.3:7443 because service records are node-local, so a constraint that resolved elsewhere would need PASSWAY_YUBABA_URL repointed in /etc/passway-noisetable.env on all three nodes; converting is a fleet change, not a config tidy. (2) The inline `required = {...}` form is mandatory there — the [providers.bundle.required] header form silently reparents fronted/zone/origin and drops the service out of the ingress plan (R844/R772). Recommend the noisetable camp file it against its own board.")
//! @yah:verify("BASELINE MEASURED FIRST, before any edit: cargo test -p yah-cloud --lib (from oss/yubaba) = 1123 passed / 0 failed / 4 ignored. AFTER: 1128 passed / 0 failed / 4 ignored — +5, exactly the five tests added, zero regressions. Full crate incl. integration targets: 1128 + 3 (2 ignored, live/network) + 2, all green. cargo check --workspace --all-targets in oss/yubaba: 0 errors. cargo build -p yah and cargo check -p yah -p xtask --all-targets in the root workspace: 0 errors.")
//! @yah:verify("REAL-TREE REGRESSION, the suite that plans yah's actual .yah/ through the changed collation: cargo test -p xtask --test main -- mirror_ingress apex = 15 passed / 0 failed, including the_yah_dev_apex_plans_one_front_door_per_declared_origin, the_apex_collates_onto_both_live_origins and all four apex_failover cases. yah's own camp (camp-local machines, no sources.toml) is byte-unchanged in behaviour: `yah cloud validate -p .` ok, `yah cloud ingress collate -p .` still renders us-east-001 + us-south-001 fronting yah.dev.")
//! @yah:verify("THE FIVE NEW TESTS, and why none is vacuous. validate.rs: a_borrowing_camp_collates_a_front_door_on_a_machine_it_declares_nowhere (asserts the camp-local loader returns EMPTY in the same test that the inventory returns the machine — that control is the non-vacuity proof); a_borrowing_camp_can_place_by_constraint_rather_than_by_pin; a_broken_link_is_reported_as_absent_rather_than_as_an_empty_fleet; the_fleet_inventory_fails_the_whole_load_on_one_unparseable_camp_local_toml (the Strict property, re-homed off the deleted MachineLoadMode); the_lint_loader_skips_... (renamed). domain.rs: a_borrowing_camp_renders_its_apex_from_the_owners_machine_declaration (the ticket's defect end to end, borrower + owner camps on disk, through plan_passway_apex) and an_unresolvable_front_door_names_the_links_that_were_consulted.")
//! @yah:verify("LIVE PROOF AGAINST THE REAL BORROWING CAMP, read-only, with the rebuilt binary (target/debug/yah, NOT ~/.local/bin/yah): `yah cloud ingress collate -p .` from ~/ss/noisetable now renders `us-east-001 — passway ... api.noisetable.com → 100.64.0.3:4332` and the same for us-south-001, and `yah cloud validate -p .` reports `ok ... 2 node front door(s) collate cleanly`. THE 100.64.0.3 IS THE PROOF, not decoration: the api mirror pins no upstream_host, so that address is resolved by machine_mesh_addrs from us-east-001's [registration].mesh_ipv4 — and 100.64.0.3 appears NOWHERE in ~/ss/noisetable/.yah except inside one prose comment. It can only have come from ~/ss/yah/.yah/infra/machines/us-east-001.toml through the [[source]] link. Both front-door nodes carry taints=[\"public-ip\"] and a public [connect].address (51.81.85.145 / 45.32.194.254), so public_origins resolves both.")
//! @yah:verify("SCHEMA/ARTIFACT GATES: ./scripts/check-schema-drift.sh exits 0, and git status on .yah/schema/ + packages/yah/workload-spec/ is clean — the new types (FleetInventory, SourceContribution) carry no schemars derive and feed no generated artifact, as expected.")
//! @yah:gotcha("I DID NOT RUN THE MUTATING CROSS-CAMP APPLY, deliberately, and this is the one item left for the operator. `yah cloud apply` has NO --dry-run (checked the clap definition in app/yah/cli/src/cloud.rs: Apply takes env/path/service/continue-on-error/format/config-root/namespace and nothing else), so running it would write live A records at api.noisetable.com AND reconcile two components of a different camp's production service. That is outward-facing and irreversible, so I proved the resolution path read-only instead (see the verify entries) rather than performing it. EXACT COMMAND when the operator wants it: cd ~/ss/noisetable && /Users/leif/ss/yah/target/debug/yah cloud apply --service noisetable-marketing --env cloud . Expect the domain phase to reach `domain api-noisetable-com (api.noisetable.com): rendering sovereign apex A records from the ingress collation (DNS-only)` WITHOUT the `no .yah/infra/machines/*.toml` failure, and `noisetable-marketing ok 2 component(s) reconciled` in the same run.")
//! @yah:gotcha("THE FIX IS NOT INSTALLED. It is in the source and in target/debug/yah only. ~/.local/bin/yah (the operator's shell, every QED step's argv=[\"yah\"]) and /Applications/yah.app/Contents/MacOS/yah (every agent's MCP surface) both still serve the old binary, so the noisetable apply will keep failing the same way until `cargo xtask install` and, for agent sessions, `cargo xtask install --dest /Applications/yah.app/Contents/MacOS/yah`. Not done here: installing over the live app is an operator action per app/yah/cli/CLAUDE.md.")
//! @yah:gotcha("ADJACENT GAP, FOUND NOT FIXED, and named so it is not re-derived: crates/yah/agent-tools/src/cloud_tools.rs has its OWN camp-local walk of .yah/infra/machines/ for the cloud.machines / cloud.mirror_state agent tools, so those tools still report an empty fleet in a borrowing camp. It is a DISPLAY surface, not a resolution one — nothing renders wrong from it, it just shows less than the camp has — and it is a different crate outside this ticket's blast radius, so I did not widen into it. The one-line fix once someone owns that crate: swap the walk for cloud::config::resolve_fleet_inventory and badge borrowed rows off FleetInventory::origins, the same provenance the Infra tab (R615-F4) already uses.")
//! @yah:handoff("Option (b) built: `config::resolve_fleet_inventory` is now the single reader of a camp's machine inventory (camp-local + legacy + every fleet borrowed through `.yah/infra/sources.toml`), extracted out of `CloudConfig::load` and adopted by the two resolution callers that were stuck on a camp-local-only loader — `validate::collate_workspace_ingress` and `reconciler::domain::plan_passway_apex`. `MachineLoadMode` deleted, `load_machine_tomls` renamed to `load_camp_local_machine_tomls` and doc'd as lint-only; no fallback shim anywhere. Naming reuses R615-F1's `[[source]]` owner/kind rather than inventing a second scheme, so there stays exactly one copy of the fleet. Full design rationale, file-level account and the noisetable-side follow-on are in the appended handoff entries above.")
//! @yah:verify("Baseline measured first: `cargo test -p yah-cloud --lib` 1123/0/4 -> after 1128/0/4 (+5, the five tests added, zero regressions). `cargo test -p xtask --test main -- mirror_ingress apex` 15/0 against the real tree. Root workspace and oss/yubaba `--all-targets` clean. Live read-only proof from ~/ss/noisetable with the rebuilt binary; the mutating apply was NOT run (no `--dry-run`, writes live DNS on another camp) — exact command recorded in a gotcha.")
//! @yah:verify("LEADER RE-VERIFICATION (session:abde2cbb, 2026-09-09), independent of the courier. Tests: `cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib` = 1128 passed / 0 failed / 4 ignored, matching the courier's count against the 1123 baseline it measured first (+5). Then checked the two structural properties the ticket actually turned on, rather than trusting the count. (1) ONE READER: `resolve_fleet_inventory` exists once, at config.rs:3283, and `load_camp_local_machine_tomls` at validate.rs:345 is now explicitly the lint loader. (2) NO SHIM: a repo-wide grep for `MachineLoadMode` across oss/yubaba/crates/cloud/src/ and app/yah/ returns hits ONLY inside annotation prose describing its deletion — zero live references. That matters more than the tests here, because the rejected option (a) would have reappeared as a read-local-then-fall-back-to-borrowed path, which is exactly the shim the root CLAUDE.md forbids and exactly the drift the operator rejected. The courier also declined to run the mutating cross-camp apply (it writes live DNS in another camp and has no --dry-run) and recorded the exact command instead — correct call, and the read-only proof from ~/ss/noisetable was run.")

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
    "origin",
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
/// origin = "https://cdn.yah.dev"      # public origin serving that bucket;
///                                     # omit on a fleet whose nodes already
///                                     # point at it (R870-B6)
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
    /// Public HTTPS origin serving `bucket` — the R2 custom domain bound to it,
    /// e.g. `"https://cdn.noisetable.com"` (R870-B6).
    ///
    /// `None` → the node fetches from its own `KAMAJI_BUNDLE_ORIGIN`, which is
    /// correct exactly while the store the mirror publishes to is the store the
    /// fleet was configured for. A second tenant publishing to its own bucket
    /// must declare this or the node materializes from the wrong store and
    /// fails with `missing blob manifests/<digest>` after a clean admission.
    ///
    /// Declared rather than derived from `bucket` or `zone`: the bucket→origin
    /// mapping is a Cloudflare R2 custom-domain binding that exists or doesn't,
    /// and guessing `https://cdn.<zone>` would put an unreachable URL on the
    /// wire for every mirror that has not bound one. Same call
    /// `providers.static.asset_origin` makes, one tier over.
    pub origin: Option<String>,
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

        // R870-B6. Parsed strictly, and with the scheme required: the value's
        // only consumer is `HttpReadOnlyObjectStore`, which joins keys onto it
        // as path segments, so a bare hostname (`cdn.noisetable.com`) produces
        // a relative URL that fails on the node — after a clean apply, at
        // materialize time, which is the far side of the feedback loop this
        // slot's validation exists to stay on.
        let origin = match fields.get("origin") {
            None => None,
            Some(v) => {
                let raw = v
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .with_context(|| {
                        format!(
                            "providers.{SLOT_ROLE}.origin must be a non-empty public HTTPS origin \
                             serving the bundle bucket, e.g. \"https://cdn.{service}.example\" \
                             (service={service}, env={env})"
                        )
                    })?;
                if !(raw.starts_with("https://") || raw.starts_with("http://")) {
                    bail!(
                        "providers.{SLOT_ROLE}.origin = {raw:?} has no scheme (service={service}, \
                         env={env}) — kamaji fetches bundle objects by joining keys onto this \
                         value, so it must be a full origin URL like \
                         \"https://cdn.example.com\", not a bucket or hostname"
                    );
                }
                Some(raw.trim_end_matches('/').to_string())
            }
        };

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
            origin,
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
            // R870-B6: the store this bundle was published to, so the node
            // fetches from it rather than from whichever store the *node* was
            // pointed at. `None` keeps the node-wide `KAMAJI_BUNDLE_ORIGIN`,
            // which is why no yah-owned mirror needs an edit.
            origin: self.origin.clone(),
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
            ingress_floating_ip: None,
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

    /// R870-B6: the store the mirror publishes to reaches the workload, so the
    /// node fetches from it rather than from whatever the *node* was pointed at.
    /// A second tenant on the fleet publishes to its own bucket; before this,
    /// its deploy passed admission and then failed to materialize.
    #[test]
    fn a_declared_origin_reaches_the_serve_bundle() {
        let slot = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "noisetable-marketing"
origin = "https://cdn.noisetable.com""#,
            ),
            "noisetable-marketing",
            "cloud",
        )
        .unwrap();
        assert_eq!(slot.origin.as_deref(), Some("https://cdn.noisetable.com"));
        assert_eq!(
            slot.serve_bundle("a".repeat(64).as_str(), "self", BTreeMap::new())
                .origin
                .as_deref(),
            Some("https://cdn.noisetable.com")
        );
    }

    /// The single-tenant regression, asserted at the wire type rather than by
    /// watching yah.dev stay up: a mirror that declares no `origin` — which is
    /// every yah-owned mirror — produces the same spec it did before R870-B6,
    /// so the node keeps using `KAMAJI_BUNDLE_ORIGIN` and needs no edit.
    #[test]
    fn no_declared_origin_leaves_the_node_wide_one_in_charge() {
        let slot = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "yah-dev""#,
            ),
            "yah-marketing",
            "cloud",
        )
        .unwrap();
        assert_eq!(slot.origin, None);
        assert_eq!(
            slot.serve_bundle("a".repeat(64).as_str(), "self", BTreeMap::new())
                .origin,
            None
        );
    }

    /// A trailing slash is trimmed at parse rather than at three consumers:
    /// `HttpReadOnlyObjectStore` joins keys onto this value, and
    /// `https://cdn.x//blobs/…` is a different object to an S3-shaped origin.
    #[test]
    fn a_trailing_slash_on_the_origin_is_trimmed() {
        let slot = BundleSlot::parse(
            &mirror_with(
                r#"use = "cloudflare"
bucket = "b"
origin = "https://cdn.example.com/""#,
            ),
            "s",
            "e",
        )
        .unwrap();
        assert_eq!(slot.origin.as_deref(), Some("https://cdn.example.com"));
    }

    /// A bucket name (or bare hostname) where an origin belongs is refused
    /// offline. Accepted, it would deploy clean and fail on the node at
    /// materialize time — the far side of the feedback loop.
    #[test]
    fn an_origin_without_a_scheme_is_refused_naming_the_shape() {
        for bad in ["cdn.noisetable.com", "noisetable-marketing"] {
            let err = BundleSlot::parse(
                &mirror_with(&format!(
                    "use = \"cloudflare\"\nbucket = \"b\"\norigin = {bad:?}"
                )),
                "s",
                "e",
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("scheme"), "{err}");
            assert!(err.contains(bad), "{err}");
        }
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
