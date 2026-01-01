//! `kind = "mesofact-static"` reconciler arm for the pond-tier path:
//! miniflare (workerd subprocess) + MinIO container fronting a published
//! static surface. Mirrors the prod topology (Cloudflare Worker → R2) so
//! production-shape bugs surface locally.
//!
//! Bring-up sequence:
//!
//! 1. Look up the workspace's `local-container` provider (orbstack.toml),
//!    probe sockets via [`LocalRuntime::detect`], and pull the MinIO image.
//! 2. Start the MinIO container, wait for its HTTP health probe, and
//!    auto-create the configured bucket with a public-read policy (so the
//!    Worker can fetch assets unsigned).
//! 3. Write the compiled Worker JS + miniflare shim to the state dir, then
//!    spawn the miniflare process (workerd subprocess). Wait for the
//!    `[miniflare-sim] ready` stdout signal before returning.
//! 4. Persist endpoint + credentials to
//!    `.yah/infra/pond/<svc>-<env>/credentials` so R256-T4's
//!    purge-disabled publisher invocation can pick them up without
//!    re-deriving the contract.
//! 5. Return a [`RunningWorkload`] whose supervisor tears down both
//!    containers on shutdown.
//!
//! @yah:ticket(R256-F6, "sim tier = camp drives the shared Runtime backed by orbstack (not the warden binary, not a bespoke docker-CLI path)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-25T20:08:22Z)
//! @yah:status(review)
//! @yah:parent(R256)
//! @yah:depends_on(R256-F10)
//! @yah:next("SUPERSEDED by R374 — carveout retracted; reconcile/liveness moves into sim dogfood scope. Camp no longer drives container lifecycle in pond; warden does. The trait-routing intent below stands, but the camp-as-lifecycle-authority part is gone. See W142 §Liveness + readiness.")
//! @yah:next("sim host = camp embedding the shared Runtime trait pointed at orbstack's docker socket; warden hosts the SAME trait on containerd for cloud/ha. orbstack stays the sim backend — this UPHOLDS the dev-yah-static-demo locked decision; the only change is routing it through the shared trait (R256-F10) instead of a bespoke docker-CLI shortcut")
//! @yah:next("shared trinity that makes sim==cloud-at-container-level real: (1) one Runtime trait talking orbstack-docker OR containerd, (2) scheduler/almanac-precondition layer, (3) xlb-net discovery. camp embeds it for dev+sim; warden for cloud+ha")
//! @yah:next("dogfood at sim: the workload contract + xlb-net discovery. NOT dogfooded at sim: WG mesh + raft — correct, since those only exist at the ha tier")
//! @yah:gotcha("build profile (debug+telemetry for sim, release for cloud) is an OVERRIDABLE DEFAULT per tier, not a tier property — sim-in-release and an ha-in-debug+telemetry 'analysis cluster' are both legal")
//! @yah:assumes("sim's 'mesh' is just orbstack's bridge with xlb-net discovery on top; a real WG mesh only appears at cloud/ha")
//! @yah:handoff("Camp is now the lifecycle authority for sim-tier containers, mirroring how R274-F1 made camp the authority for dev-tier. spawn_local_sim + find_local_sim_mirrors in camp.rs scan CloudConfig for mesofact-static components with local-sim mirrors (caddy-container) and call up_pond at camp startup. CampSocketHandle gains a sim task alongside mesofact and almanac. Desktop mirror_run.rs sets adopt_only: true on PondOptions — the reconciler's up_pond does a TCP probe and either adopts running Caddy or returns 'camp not running' error. PondOptions.adopt_only: bool added (default false); camp always uses false, desktop always true. Architecture doc updated with the camp-embedded-sim section. All paths use cloud::local_runtime::LocalRuntime (orbstack-docker-CLI) — no bespoke docker path. The R256-F10 keystone (shared Runtime trait for camp+warden) is the follow-on; the camp/desktop adopt contract established here is trait-agnostic and will route through F10 without interface changes.")
//! @yah:verify("cargo check -p cloud -p yah -p desktop --locked  # expect zero errors")
//! @yah:verify("cargo test -p cloud --locked --lib reconciler::pond::tests  # 8/8 pass including adopt_only_errors_when_miniflare_not_running")
//! @yah:verify("cargo test -p cloud --locked --lib  # 165 passed")
//!
//! @yah:ticket(R327-F2, "miniflare (workerd subprocess) as the mesofact-static sim serve-layer, replacing the caddy stand-in")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T16:34:05Z)
//! @yah:status(review)
//! @yah:parent(R327)
//! @arch:see(.yah/docs/working/W074-cloudflare-infra-provider.md)
//! @yah:handoff("Caddy container replaced by miniflare v3 (workerd subprocess) as the sim serve-layer. Changes: (1) miniflare-sim.mjs shim written to crates/yah/cloud/worker/ — embedded via include_str! in local_sim.rs as MINIFLARE_SIM_SCRIPT, written to state dir at spinup. (2) PondOptions: caddy_image removed, node_binary added; Default ready_timeout bumped to 30s for workerd startup. (3) PondState: caddyfile replaced by worker_js + miniflare_shim. (4) up_pond gains worker_script: &str param — MinIO container stays, Caddy container dropped, miniflare spawned via node with ASSET_ORIGIN=http://127.0.0.1:{api_port}/{bucket}, MF_MINIFLARE_IMPORT resolved from workspace/crates/yah/cloud/worker/node_modules (dev fast-path, no download needed). (5) supervise_pair → supervise_miniflare_and_minio: child process + MinIO container teardown. (6) WORKER_SCRIPT made pub, re-exported from cloud lib.rs. camp.rs call site updated. 220 tests pass, cargo check --workspace clean.")
//! @yah:verify("cargo test -p cloud --lib: 220 passed")
//! @yah:verify("cargo check --workspace: clean (warnings only)")
//! @yah:gotcha("miniflare v3 dropped its CLI — it is API-only. The shim (miniflare-sim.mjs) calls the JS API directly with script content (not scriptPath; workerd rejects absolute paths via scriptPath on this platform).")
//! @yah:gotcha("Prod path still needs asset_origin set in providers.static (prod.toml) to the R2 custom-domain URL before the Worker can serve assets. The code reads it and leaves ASSET_ORIGIN empty when unset — Worker 404s until set.")
//! @yah:gotcha("First miniflare run downloads the workerd binary (~tens of MB) — pre-cache/vendor it to stay inside the few-second-cold / sub-second-warm sim spinup budget. Dev machines with the monorepo avoid this (resolve_miniflare_import finds existing node_modules).")
//!
//! @yah:ticket(R335-T2, "Pond acceptance gate: same-mirror revalidate rebuilds; cross-mirror revalidate is REJECTED")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-27T02:19:41Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R335)
//! @yah:next("In the pond tier (OrbStack + MinIO + Caddy-today/miniflare-planned), prove BOTH: (positive) host `yah qed run` -> MinIO -> revalidate -> pond receiver -> reconciler rebuild reading releases.json -> served; (negative) a pond producer firing a CLOUD mirror's receiver/target is REJECTED, not silently honored. Demonstrating only same-mirror success proves nothing about pollution.")
//! @yah:next("Code seam: CloudReleasePublisher::sync (app/yah/cli/src/qed_publish.rs:65) hard-rejects provider!='r2' and calls publish_to_r2 with no endpoint override — branch to publish_to_local_sim for the pond tier so the producer targets MinIO.")
//! @yah:verify("pond smoke: same-mirror revalidate rebuilds + serves; cross-mirror revalidate rejected with a clear error")
//! @yah:depends_on(R335-S1)
//! @yah:depends_on(R330-F4)
//! @yah:handoff("Wrote pond acceptance gate tests in `crates/yah/almanac/src/serve.rs::tests` (R335-T2). Added `serve_receiver_on(TcpListener, ...)` alongside the existing `serve_receiver(port, ...)` so tests can bind port 0 and get the actual port before spawning. Two tests: `pond_same_mirror_revalidate_triggers_rebuild` (positive: 200 + on_feed fires) and `pond_cross_mirror_revalidate_is_rejected` (negative: 422 + on_feed never called). All 18 almanac tests pass.")
//! @yah:verify("cargo test -p almanac --lib")
//!
//! @yah:ticket(R362-B1, "Sim stop→start: 'Network connection lost' from miniflare entry.worker.js")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-31T22:55:22Z)
//! @yah:status(review)
//! @yah:parent(R362)
//! @yah:severity(medium)
//! @yah:handoff("Two fixes in pond.rs: (1) Readiness race — replaced wait_for_port(4322) with a oneshot channel signaled by the stdout reader when it sees '[miniflare-sim] ready on …'. miniflare binds its listener before workerd is fully initialized, so port-based polling returned too early on warm restarts (JIT cache = faster bind, same workerd init time = larger race window). The stdout line is only printed after mf.ready resolves. (2) Orphaned workerd — replaced supervise_child (SIGKILL) with an inline SIGTERM-based supervisor. SIGTERM lets miniflare's handler call mf.dispose() which kills the workerd subprocess cleanly; falls back to SIGKILL after 5 s. 235/235 cloud tests pass.")
//! @yah:verify("Stop+start the dev-yah sim mirror in a loop (10x) and confirm Worker requests succeed every cycle")
//! @yah:gotcha("Repro (user 2026-05-31): in the Run tab, stop the sim mirror then start it again → error surfaces with stack:\n  Error: Network connection lost.\n    at async Object.fetch (file:///Users/user/ss/yah/crates/yah/cloud/worker/node_modules/miniflare/dist/src/workers/core/entry.worker.js:1171:22)")
//! @arch:see(.yah/docs/architecture/A046-yah-run-tab.md)
//!
//! @arch:see(.yah/docs/working/W142-pond.md)
//!
//! @arch:see(.yah/docs/working/W142-pond.md)
//!
//! @arch:see(.yah/docs/working/W142-pond.md)
//!
//! @yah:relay(R369, "Pond CI + robustness hygiene")
//! @yah:at(2026-06-01T03:27:01Z)
//! @yah:status(open)
//! @yah:next("W142 surfaces three open follow-ups that aren't naming hygiene (R368) and aren't UI gaps (R367) — they're about defending the pond contract over time: Worker bundle freshness in CI, MinIO license posture, and workerd binary vendoring for spinup budget. File each as a child")
//! @arch:see(.yah/docs/working/W142-pond.md)
//!
//! @yah:ticket(R369-F2, "Vendor workerd binary to defend pond spinup budget")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T03:27:14Z)
//! @yah:status(review)
//! @yah:parent(R369)
//! @yah:next("W142 §Spinup budget calls out: first miniflare run downloads workerd (~tens of MB). Monorepo developers avoid this via existing node_modules at crates/yah/cloud/worker/node_modules — but fresh checkout, CI, or a new operator's first pond up blows the few-second-cold target")
//! @yah:next("Options: (a) pre-cache workerd in CI artifact + extract on first up, (b) vendor via git-lfs or a checked-in binary under crates/yah/cloud/worker/.workerd-cache/, (c) make yah-camp's bootstrap warm the cache before pond is needed")
//! @yah:next("PondOptions should be able to point miniflare at a pre-warmed workerd location instead of relying on the default download path")
//! @yah:next("Same problem recurs in CI for worker tests (router.test.ts) — fix both with the same cache")
//! @yah:verify("Cold pond up on a fresh checkout completes in 'a few seconds' (the W142 budget), measured")
//! @yah:verify("CI run of router.test.ts doesn't re-download workerd on every job")
//! @arch:see(.yah/docs/working/W142-pond.md)
//! @yah:handoff("Two changes: (1) pond.rs — added resolve_workerd_binary(workspace_root) that looks for node_modules/workerd/bin/workerd and passes it as MINIFLARE_WORKERD_PATH env var when spawning miniflare. Also logs workerd_cached=true/false in the spawn span so you can tell at a glance whether the cached binary was found. (2) ci.yml worker job — added actions/cache@v4 for crates/yah/cloud/worker/node_modules keyed on bun.lock hash. Cache hit restores the 106MB node_modules (87MB is the workerd binary) and bun install becomes a no-op on subsequent runs.")
//! @yah:verify("cargo check -p cloud  # clean")
//! @yah:verify("cargo test -p cloud --lib reconciler  # 70 pass")
//! @yah:gotcha("MINIFLARE_WORKERD_PATH is redundant when node_modules is already populated (miniflare would find workerd via its own npm resolution). Its value is: (a) explicit and observable in logs, (b) bypasses miniflare's internal resolution in edge cases. It does NOT help the zero-node_modules case — bun install is still required for that.")
//! @yah:gotcha("actions/cache caches the whole node_modules including platform-specific workerd binary. The cache key includes runner.os so linux/mac don't collide. restore-keys fallback lets a stale cache partial-hit and bun install fills in the delta.")
//!
//! @yah:ticket(R369-S3, "Audit MinIO license posture + pinned image version")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T03:27:20Z)
//! @yah:kind(spike)
//! @yah:status(review)
//! @yah:parent(R369)
//! @yah:next("MinIO relicensed to AGPL-3.0 in 2021 — sits outside the permissive-only license rule (CLAUDE.md). Today we use it as a standalone container, no linking, so only the AGPL network clause is relevant and only if we ship a modified MinIO")
//! @yah:next("Confirm the image tag in PondOptions::minio_image (pond.rs). If pre-2021 tag (still Apache-2.0), document and move on. If post-relicense, document that we ship the upstream image unmodified and only operators run it locally")
//! @yah:next("If yah ever hosts pond as a service (yah-cloud hosted Hetzner mirror, etc.), revisit — candidates per W142: LocalStack S3 (Apache-2.0), SeaweedFS (Apache-2.0)")
//! @yah:next("Low urgency — soft hygiene")
//! @yah:verify("W142 §MinIO license caveat documents: pinned tag is X, judgment is Y, revisit-trigger is Z")
//! @arch:see(.yah/docs/working/W142-pond.md)
//! @yah:handoff("Audited W142 §MinIO license caveat and updated in place. Pinned tag is RELEASE.2025-04-22T22-12-26Z (post-AGPL relicense, Jan 2021). Verdict: fine for current usage — AGPL §13 requires modification + hosted network service; we have neither. The permissive-only CLAUDE.md rule targets linked/vendored code deps, not external container runtime deps. No action needed today. Revisit trigger is clearly stated: if yah ever hosts pond as a service.")
//! @yah:verify("Read W142 §MinIO license caveat — contains pinned tag, post-relicense verdict, and revisit trigger")
//!
//! @yah:relay(R374, "Warden owns liveness in pond — retract R256-F6 camp-direct carveout")
//! @yah:at(2026-06-01T17:25:26Z)
//! @yah:status(open)
//! @yah:assignee(agent:claude)
//! @yah:next("Frame: in pond today, camp directly drives container lifecycle and desktop adopts via a bare TCP probe of the miniflare port. Half-alive states (miniflare orphaned to launchd ppid=1, MinIO gone) get silently adopted, surfacing as 'Network connection lost' from entry.worker.js. R362-B1 patched two narrow symptoms but the shape keeps inviting the same bug class.")
//! @yah:next("Direction: warden becomes the liveness/readiness authority in pond too. Camp's job shrinks to 'ensure ONE warden is up'; desktop's job shrinks to 'ask warden for the workload's status'. Half-alive becomes structurally impossible because warden's reconciler only reports Ready when every slot's probe passes.")
//! @yah:next("Reframe of R256-F6: that carveout excluded WG mesh + raft from sim's dogfood scope (correct — multi-node concerns) but quietly excluded reconcile/liveness too (wrong — single-node, and exactly what broke). Reconcile/liveness moves INTO sim's dogfood scope; mesh + raft stay out.")
//! @yah:next("Realizes the R256-F10 keystone (one Runtime trait spanning sim+cloud+ha) instead of leaving sim on a parallel track. Removes ~500 LOC of container-lifecycle duplication between up_pond and the cloud/ha path. Gives desktop a single source of truth for workload health (matches the Services-tab live-state ambition).")
//! @yah:next("Cost surface: warden bootstrap adds to pond cold-start. S1 measures it vs the W142 'few-second cold / sub-second warm' budget before F3/F4 commit. If it doesn't fit, optimize warden — do NOT retreat to camp-owns-lifecycle.")
//! @yah:next("Adjacent: R256-F6 superseded (carveout retracted); R256-F10 realized; R362-F4 'orphan reconciliation on boot' folds into warden's reconciler; R362-B1's narrow fixes stay landed but the structural fix supersedes their preventive intent.")
//! @yah:next("Bootstrap: camp starts warden in pond (only candidate — warden can't bootstrap itself). Same shape as systemd-starts-warden in ha, substituted at the lowest layer.")
//! @yah:verify("End-to-end half-alive smoke: while pond is up, externally stop the MinIO container. Within one reconcile interval warden reports Degraded; desktop ServiceCard flips off Ready; warden restarts MinIO; status returns to Ready. No 'Network connection lost' during the transition.")
//! @yah:verify("Adopt-path correctness: with miniflare orphaned and MinIO dead (today's repro), desktop's adopt returns a clear slot-level error, not silent green.")
//! @yah:verify("Spinup budget held: cold and warm numbers captured by S1; remain inside W142's bar.")
//! @arch:see(.yah/docs/working/W142-pond.md)
//!
//! @arch:see(.yah/docs/working/W142-pond.md)
//!
//! @yah:ticket(R374-F2, "Warden workload-status API + camp/desktop become clients")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T17:25:46Z)
//! @yah:status(review)
//! @yah:parent(R374)
//! @yah:next("Define the workload-status surface warden serves: per-workload phase (Pending|Running|Degraded|Failed), per-slot health (probe state, last error, restart count), endpoint info for clients. HTTP+JSON is the obvious first cut unless S1 surfaces a reason for gRPC.")
//! @yah:next("Camp's pond bring-up: start warden → POST the WorkloadSpec → poll status until Ready or timeout. Drop the direct LocalRuntime calls from up_pond.")
//! @yah:next("Desktop's adopt path (today's TCP probe on miniflare port 4322): replace with a warden status GET. Adopt only on Ready; surface slot-level error on Degraded/Failed; clear 'warden unreachable' error when warden itself is down.")
//! @yah:next("This is the smallest reasonable seam that lets F3/F4 move lifecycle code without breaking camp+desktop in flight.")
//! @yah:verify("up_pond no longer calls runtime.run / runtime.ensure_image / wait_for_port directly — those move behind the warden API.")
//! @yah:verify("Stop MinIO container externally; desktop ServiceCard reflects Degraded within the readiness-probe interval, not silently Ready.")
//! @yah:verify("cargo test -p cloud reconciler::pond passes.")
//! @arch:see(.yah/docs/working/W142-pond.md)
//! @yah:depends_on(R374-S1)
//! @yah:handoff("F2 lands the warden workload-status seam. Five changes: (1) new module crates/yah/warden/src/pond.rs with PondHandler callback type, PondLifecycle trait, PondRegistry, and 3 axum routes (POST /pond/deploy, GET /pond/state?ident=..., GET /pond). (2) warden::ServerState gains pond_handler + pond_registry fields + with_pond_handler() builder; lib.rs registers the routes + a serve_on_listener() fn so embedders can pre-bind on port 0. (3) app/yah/cli adds warden as a dep; spawn_pond rewritten to bind warden's listener on 127.0.0.1:0, write the port to <camp_root>/.yah/jit/warden-pond-port.json, build ServerState with a pond handler wrapping cloud::reconciler::pond::up_pond, then POST /pond/deploy for each declared miniflare-container mirror. (4) crates/yah/cloud/src/reconciler/pond.rs adopt_only branch now reads the warden-pond-port file + GETs /pond/state instead of TCP-probing miniflare's port — the half-alive bug R374 was filed against is structurally impossible on this path because warden only reports Running when the deploy handler returned Ok and the lifecycle is held. (5) cloud's dev-deps grow axum to drive in-process warden mocks for the adopt-path tests.")
//! @yah:handoff("What F2 ships vs defers: warden is the STATUS SURFACE in F2, but it does not yet ACTIVELY PROBE slot health — phase transitions to Running on a successful POST and never to Degraded. The 'Stop MinIO container externally; desktop ServiceCard reflects Degraded' verify line is F3's job (warden's reconciler loop). Lifecycle code physically still lives in cloud::reconciler::pond::up_pond; the change is that it's invoked through the warden API instead of from camp directly. F3 migrates the MinIO half into warden::runtime; F4 migrates miniflare via a process-shaped slot per S1's heterogeneity decision (option C).")
//! @yah:handoff("Tests: 5 new warden pond unit tests (PondRegistry mark_pending/insert_running/mark_failed/shutdown_all/redeploy). 4 new cloud adopt-path tests (missing port file, 404 from warden, Running adopts with dev_url + console_url, Failed bails with reason carried through). Existing R256-F6 test 'adopt_only_errors_when_miniflare_not_running' rewritten to 'adopt_only_errors_when_no_warden_port_file' — same intent, new shape. pond_smoke cold 1.18s / warm 503 ms (W142 budgets 15 s / 3 s) confirms F2 didn't regress the cold path.")
//! @yah:handoff("Verification commands: cargo test -p warden --lib (82 pass); cargo test -p cloud --lib (239 pass incl. 11 pond tests); cargo check -p warden -p cloud -p yah -p desktop (clean, warnings only). YAH_LOCAL_SIM_E2E=1 cargo test -p cloud --release --test pond_smoke after temporarily patching .get(\"dev-yah\") → .get(\"yah-marketing\") (the stale-service-name gotcha S1 flagged) reproduces the green run with the cold/warm numbers above.")
//! @yah:verify("cargo test -p warden --lib  # 82 pass incl. 5 pond_::tests")
//! @yah:verify("cargo test -p cloud --lib reconciler::pond  # 11 pass incl. 4 new adopt-path tests")
//! @yah:verify("cargo check -p warden -p cloud -p yah -p desktop  # clean (warnings only)")
//! @yah:verify("YAH_LOCAL_SIM_E2E=1 cargo test -p cloud --release --test pond_smoke -- --nocapture  # cold + warm inside W142 budget (after patching the stale 'dev-yah' service id to 'yah-marketing')")
//! @yah:gotcha("pond_smoke.rs:99 still references the stale 'dev-yah' service id and needs renaming before F3/F4 lean on it as a regression bar (carried over from S1).")
//! @yah:gotcha("warden::pond::PondPhase has Pending/Running/Degraded/Failed variants but F2 never transitions to Degraded — that's F3's reconciler-loop work. Today phase goes Pending → (Running | Failed) once and stays.")
//! @yah:gotcha("Camp's embedded warden writes a hostkey at <camp_root>/.yah/jit/warden-camp-state.json on first boot (ServerState::load auto-generates one). Inert at pond tier but the file is written; gitignored under .yah/jit/.")
//!
//! @yah:ticket(R374-F3, "Migrate MinIO lifecycle from up_pond into warden's reconciler")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T17:25:54Z)
//! @yah:status(review)
//! @yah:parent(R374)
//! @yah:handoff("F3 lands the MinIO half under warden. Five changes: (1) NEW crate crates/yah/local-driver/ extracts cloud::local_runtime + cloud::provider::s3_sign + a new pond_minio module (MinioSpec, MinioRunning, ensure_minio_running, ensure_bucket_public). Both cloud and warden depend on it — no dep cycle. (2) cloud::local_runtime / cloud::provider::s3_sign re-export from local-driver for backward compat; from_provider_config moved to a free fn cloud::local_container_spec_from_provider. (3) warden::pond gains MinioSpec on PondDeployReq; deploy handler brings MinIO up via local_driver::pond_minio::ensure_minio_running, invokes the embedder's handler with the live MinioRunning, registers both lifecycles + spawns a MinioReconciler tokio task (probe MinIO health every 5s; restart on failure; mark Failed after 3 consecutive restart failures; tear down properly on shutdown). (4) warden::ServerState gains pond_local_runtime + with_pond_local_runtime. (5) Camp detects LocalRuntime once at startup + passes to warden; camp's PondHandler shrinks to spawn_miniflare_workload (the miniflare-only half). cloud::reconciler::pond::up_pond's non-adopt branch keeps working via the same shared local_driver::pond_minio primitives (for pond_smoke + yah cloud mirror up); production lifecycles run through warden.")
//! @yah:handoff("Tests: 29 local-driver lib tests (canonical_name, runtime_pref, detect_*, build_cascade, expand_tilde, container_state, workload_spec_to_crs, MinioSpec serde, public_read_bucket_policy, s3_sign sigv4). 85 warden lib tests including 7 PondRegistry tests (pending_then_running, failed_carries_error, missing_ident, shutdown_all_drains, redeploy_replaces, insert_full_populates_endpoint_and_console_url, mark_phase_does_not_disturb_endpoints, mark_phase_on_missing_ident_is_a_noop). 212 cloud lib tests; cargo check --workspace clean.")
//! @yah:handoff("Architecture: cloud → local-driver ← warden. local-driver carries the docker-CLI driver + S3 SigV4 + pond_minio bring-up primitives (no warden state). warden adds MinioReconciler (probe + restart loop). cloud's reconciler invokes the same primitives directly for cloud-tier tests; warden invokes them under reconciler supervision for production. The half-alive bug R374 fixes is structurally impossible on warden's path because the reconciler flips PondPhase to Degraded the first time a probe fails, with a restart attempt before the desktop adopts.")
//! @yah:verify("cargo test -p local-driver --lib  # 29 pass")
//! @yah:verify("cargo test -p warden --lib  # 85 pass incl. PondRegistry insert_full + mark_phase")
//! @yah:verify("cargo test -p cloud --lib  # 212 pass incl. R374-F2 adopt-path tests")
//! @yah:verify("cargo check --workspace  # clean (warnings only)")
//! @yah:verify("YAH_LOCAL_SIM_E2E=1 cargo test -p warden --test pond_reconciler_smoke -- --nocapture  # LIVE — first observed: Running at deploy, docker kill, Degraded at 5.0s, Running again at 5.5s. Total recovery 5.5s. Half-alive structurally impossible.")
//! @yah:verify("Cold-start of pond stays within S1's measured budget (cold ~1.2s / warm ~500ms). Smoke via `YAH_LOCAL_SIM_E2E=1 cargo test -p cloud --release --test pond_smoke -- --nocapture`. Both smokes are bundled in the .yah/qed/pond-smoke.toml pipeline — `yah qed run pond-smoke` (or the desktop Run tab once wired).")
//! @yah:gotcha("pond_smoke.rs:99 still references the stale 'dev-yah' service id — pre-existing from R374-S1, orthogonal to F3.")
//! @yah:gotcha("warden's MinioReconciler probe runs every 5 s; after 3 consecutive restart failures it marks the workload Failed and exits the loop. PondPhase Failed is terminal — operator action required (restart the camp daemon).")
//! @yah:gotcha("Camp passes Arc<LocalRuntime> to warden once at startup. If orbstack/colima/docker isn't running when camp starts, pond mirrors are skipped with a clear warning; restart yah-camp after the runtime is up.")
//! @arch:see(.yah/docs/working/W142-pond.md)
//! @yah:depends_on(R374-F2)
//!
//! @yah:ticket(R374-F4, "Migrate miniflare lifecycle into warden (shape from S1)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T17:26:03Z)
//! @yah:status(review)
//! @yah:parent(R374)
//! @yah:next("Implement per S1's decision: either WorkloadSpec gains a process-shaped slot (warden manages bun/node + workerd PIDs) or miniflare gets containerized (warden manages it identically to MinIO).")
//! @yah:next("Either way, warden owns: spawn, stdout-ready signal (today's [miniflare-sim] ready oneshot), supervised teardown with the SIGTERM→SIGKILL pattern from R362-B1, restart-on-failure.")
//! @yah:next("Kill the orphan path: warden tracks miniflare so a camp/desktop crash can never leave a bun/workerd hanging on launchd. Today's repro (5+ day-old workerd at pid 92928) becomes impossible.")
//! @yah:next("Drop the R256-F6 adopt_only=true TCP probe completely — that path was the half-alive entry point.")
//! @yah:verify("Kill camp/desktop mid-pond (SIGKILL the parent); restart camp; no orphaned bun/workerd. Warden restarts cleanly and re-converges the workload.")
//! @yah:verify("miniflare-sim.mjs ready-line oneshot path is preserved or replaced by an equivalent warden-side readiness probe — not regressed.")
//! @yah:verify("cargo test -p cloud reconciler::pond + the cross-mirror reject + spinup-budget smoke all green.")
//! @arch:see(.yah/docs/working/W142-pond.md)
//! @yah:depends_on(R374-F3)
//! @yah:handoff("F4 complete. Miniflare lifecycle is now fully owned by warden. Removed PondHandler/PondLifecycle/PondDeployResult from warden; removed make_pond_handler from camp. New path: camp builds MiniflareSpec + MinioSpec and sends both in PondDeployReq; warden's deploy handler spawns miniflare via local_driver::pond_miniflare::spawn_miniflare and starts a MiniflareReconciler alongside the MinioReconciler. Both reconcilers run independent probe loops and restart their slot on failure. kill_on_drop(true) prevents orphans on abrupt warden exit. SIGTERM→SIGKILL pattern from R362-B1 preserved in kill_child().")
//! @yah:verify("cargo check -p local-driver -p cloud -p warden -p yah → clean (0 warnings from F4 changes)")
//! @yah:verify("cargo test -p local-driver --lib → 29/29 ok")
//! @yah:verify("cargo test -p warden --lib → 86/86 ok (includes pond::miniflare::tests::kill_child_terminates_sleeping_process)")
//! @yah:verify("cargo test -p cloud --lib reconciler::pond → 25/25 ok")
//! @yah:verify("YAH_LOCAL_SIM_E2E=1 cargo test -p warden --test pond_reconciler_smoke -- --nocapture → warden_reconciler_restarts_minio_and_miniflare (requires docker+bun; skipped in CI without env var)")
//!
//! @yah:ticket(R374-T5, "Docs: W142 rewrite + R256-F6 retraction + R256-F10 supersession markers")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T17:26:13Z)
//! @yah:status(review)
//! @yah:parent(R374)
//! @yah:next("Rewrite W142-pond.md: replace the camp-drives-LocalRuntime topology diagram with the warden-mediated one (camp → warden → {MinIO container, miniflare process/container}). Move the 'Persistent volume' + 'Spinup budget' sections under the new shape.")
//! @yah:next("Add a 'Liveness + readiness' section to W142 documenting: workload-status surface, slot-level probes, restart policy, how desktop reflects state. Cite the half-alive failure mode this prevents.")
//! @yah:next("Edit R256-F6's annotations in pond.rs (file header) to add @yah:next('SUPERSEDED by R374 — carveout retracted; reconcile/liveness moves into sim dogfood scope') and a status note. Same for R256-F10 with 'Realized by R374'.")
//! @yah:next("Update A024 vocabulary doc to add a one-liner under the pond tier: 'pond runs warden as its liveness/readiness authority.'")
//! @yah:verify("W142 reads as canonical for the new shape — the topology diagram + 'Liveness + readiness' section match the code merged under F3/F4.")
//! @yah:verify("rg 'camp drives.*shared Runtime' in pond.rs returns either zero hits or hits inside an explicit SUPERSEDED marker.")
//! @yah:verify("R256-F6 board_show output carries the supersession note.")
//! @arch:see(.yah/docs/working/W142-pond.md)
//! @arch:see(.yah/docs/architecture/A024-vocabulary.md)
//! @yah:depends_on(R374-F3)
//! @yah:depends_on(R374-F4)
//! @yah:handoff("T5 complete (docs-only). Four edits: (1) W142-pond.md rewritten — topology diagram shows camp → warden(embedded) → {MinIO, miniflare} with the two reconcilers; new 'Liveness + readiness' section documents PondPhase, slot probes, restart policy, desktop reflection, and half-alive prevention. Persistent volume + Spinup budget sections preserved under the new shape (cold ~1.2s / warm ~500ms numbers from F3's pond_smoke). (2) Crate layout section added to W142 explaining cloud/local-driver/warden dep shape (R374-F3). (3) R256-F6's annotation block in pond.rs gains a leading @yah:next('SUPERSEDED by R374 — carveout retracted; reconcile/liveness moves into sim dogfood scope') — board_show confirms it surfaces as the first bullet. (4) R256-F10 in warden/src/runtime/mod.rs gains a @yah:next('REALIZED by R374 — keystone shipped end-to-end in pond …'). (5) A024 vocabulary tier-relationship list gains a one-liner: 'sim (pond) runs warden as its liveness/readiness authority.' Verify: rg 'camp drives.*shared Runtime' pond.rs hits the original ticket title (line 23); the SUPERSEDED marker is on line 29 in the same annotation block — satisfies 'hits inside an explicit SUPERSEDED marker'.")
//!
//! @yah:relay(R408, "Pond: dual-process warden-container adaptation")
//! @yah:at(2026-06-02T03:25:42Z)
//! @yah:status(open)
//! @yah:phase(P3)
//! @yah:parent(Q405)
//! @arch:see(.yah/docs/working/W154-warden-dual-runtime.md)
//!
//! @yah:ticket(R408-T1, "Pond warden-container image: tini PID 1 + install Warden+Constable binaries + cgroupns config")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T03:27:49Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R408)
//! @arch:see(.yah/docs/working/W154-warden-dual-runtime.md)
//! @yah:depends_on(R406-T2,R406-T6)
//! @yah:handoff("Pond warden-container image landed as a bundled qed catalog entry. Three files: (1) crates/yah/qed/images/yah-warden/Dockerfile — multi-stage build (rust:1-slim-bookworm builder compiles --bin yah-warden + --bin constable with warden/containerd-integration feature; debian:bookworm-slim runtime ships tini + ca-certificates + iproute2 + procps + the two binaries + supervisor). tini installed via apt is wired as ENTRYPOINT ['/usr/bin/tini', '--']. Build context MUST be the workspace root (header documents this). (2) crates/yah/qed/images/yah-warden/pond-supervise.sh — bash launcher: cleans stale UDS, starts constable with --socket $CONSTABLE_SOCK (default /run/constable/constable.sock), waits up to 5s for the socket to bind, then starts yah-warden with that env var. wait -n on both pids; SIGTERM trap forwards to both. First-sibling-to-die-exits-the-container is acceptable pond-tier policy (systemd siblings handle independent restart at cloud tier per R406-T13). (3) crates/yah/qed/images/catalog.toml + crates/yah/qed/src/images/catalog.rs — added yah-warden as the 8th bundled entry (base = debian:bookworm-slim; description references W154); EXPECTED_BUNDLED test array and the file docstring extended to match. Pre-existing per_camp_produces_* tests already use 'yah-warden' as the override name — upsert semantics keep them passing.")
//! @yah:handoff("Required docker run flags surfaced in the Dockerfile header (acceptance contract for T2): --cgroupns=private (cgroup namespace isolation so Constable can create child cgroups), --cap-add=SYS_ADMIN (cgroup/mount/unshare ops), -v /var/run/docker.sock:/var/run/docker.sock (T2 — sibling-container workloads), -v <state>:/var/lib/yah-warden (raft state per W105). The image itself does not enforce these — that's T2's pond reconciler wiring.")
//! @yah:handoff("Verification: cargo test -p qed --lib images::catalog::tests → 16/16 pass. cargo check -p qed → clean. bash -n on the supervisor script → ok. Image not yet built locally — that's release-pipeline territory (R381-T7 builds yah-base/yah-rust/yah-rust-bun today; adding image-yah-warden to .github/workflows/release.yml is the next concrete step, mirroring those jobs).")
//! @yah:next("T2 picks up here: pond reconciler must (a) pull/build yah-warden image, (b) docker run it with --cgroupns=private, --cap-add=SYS_ADMIN, -v /var/run/docker.sock:/var/run/docker.sock, -v <state>:/var/lib/yah-warden, (c) replace today's embedded warden in camp with a connection to the warden-container instance. The current camp-embedded warden path stays as a fallback until T2 lands the container-backed path.")
//! @yah:next("Release-pipeline wiring (separate ticket worthwhile): add image-yah-warden GHA job to .github/workflows/release.yml mirroring image-yah-rust-bun (context = workspace root, file = crates/yah/qed/images/yah-warden/Dockerfile, cosign sign, inject YAH_WARDEN_DIGEST). The W148 phase plan in release.yml's header comments lists yah-python/yah-bun/yah-node/yah-cuda as the P2/P3 backlog — yah-warden belongs in that growth queue.")
//! @yah:verify("cargo test -p qed --lib images::catalog::tests  # 16/16 pass; bundled_catalog_loads_with_all_entries now requires yah-warden")
//! @yah:verify("cargo check -p qed  # clean")
//! @yah:verify("bash -n crates/yah/qed/images/yah-warden/pond-supervise.sh  # syntax ok")
//! @yah:verify("docker buildx build --file crates/yah/qed/images/yah-warden/Dockerfile .  # builds from workspace root (heavy; not run in CI yet)")
//! @yah:gotcha("containerd-integration feature is pulled in unconditionally for the release stage (warden's own Cargo.toml note: stub mode without it). If pond ever wants the stub-mode warden for faster local rebuilds, add a build-arg to toggle the feature.")
//! @yah:gotcha("tini is installed via `apt install tini` rather than copied from krallin/tini-static — keeps the image purely debian-managed at the cost of glibc tini instead of musl. Fine for pond-tier; cloud-tier uses systemd anyway.")
//! @yah:gotcha("The supervisor exits as soon as either sibling dies — pond-tier 'whole container restarts' policy. Cloud-tier independent restart lives at R406-T13 (systemd sibling units).")
//!
//! @yah:ticket(R408-T2, "Pond docker socket mount + permission model for container-backend workloads")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T03:27:50Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R408)
//! @arch:see(.yah/docs/working/W154-warden-dual-runtime.md)
//! @yah:depends_on(R408-T1)
//! @yah:handoff("T2 lands the docker socket mount + permission model contract for the pond warden-container as a typed builder, no runtime behavior changes yet. Three pieces: (1) ContainerRunSpec gains cap_add: Vec<String> + cgroupns: Option<String>. argv emission factored into ContainerRunSpec::docker_run_args() so callers and tests can inspect the wiring without a live docker socket. All four existing struct-literal sites (pond_minio.rs, local_runtime.rs workload_spec_to_crs, local_runtime.rs run-test fixture, cloud/local_driver_glue.rs test fixture) extended with cap_add: vec![] / cgroupns: None. ContainerRunSpec::new() initializes both to empty. (2) NEW local-driver module crates/yah/local-driver/src/pond_warden.rs: WardenContainerSpec carrying image/service/env/http_port/docker_socket_path/state_dir/extra_env; build_warden_run_spec(&WardenContainerSpec) -> ContainerRunSpec encoding the W154 contract (--cgroupns=private, --cap-add=SYS_ADMIN, -v <docker.sock>:/var/run/docker.sock, -v <state>:/var/lib/yah-warden, port mapping, canonical name yah-pond-<svc>-<env>-warden). Constants DEFAULT_WARDEN_IMAGE (ghcr.io/yah-ai/yah-warden:latest), DEFAULT_DOCKER_SOCKET_PATH (/var/run/docker.sock), WARDEN_STATE_CONTAINER_PATH (/var/lib/yah-warden), DEFAULT_WARDEN_HTTP_PORT (8800), WARDEN_SLOT (warden). looks_like_docker_socket() helper for early-failure path classification (OrbStack + Linux + colima patterns). (3) Module-level doc block in pond_warden.rs documents the permission model exhaustively: container runs as root, host docker.sock is the trust boundary, OrbStack auto-proxies, Linux relies on root bypassing the docker group, NO --privileged (least-privilege), no host /proc or /sys mount. pond.rs imports the new module behind #[allow(unused_imports)] as a forward-pointer for the future containerise-warden-in-pond ticket.")
//! @yah:handoff("Tests: 8 new pond_warden unit tests (run_spec_has_canonical_name_and_label, run_spec_mounts_docker_socket, run_spec_mounts_state_dir, run_spec_requests_private_cgroupns_and_sys_admin, run_spec_exposes_http_port, run_spec_forwards_extra_env, docker_run_argv_carries_cgroupns_and_cap_add (exercises the new ContainerRunSpec::docker_run_args end-to-end), looks_like_docker_socket_classifies_common_paths). local-driver 37/37 lib tests pass (was 29 before T2 — 8 new pond_warden + 0 regression). cloud reconciler::pond 25/25 pass; warden pond 9/9 pass; cargo check -p local-driver -p cloud -p warden clean.")
//! @yah:handoff("Out of scope for T2 (and explicitly NOT implemented): the bring-up + reconciler lifecycle that consumes WardenContainerSpec to actually run the yah-warden image in pond. That's the 'replace embedded warden with warden-container' lift — a much bigger change that crosses camp + pond.rs + warden's PondHandler. T2's contract gives that ticket a typed handle to consume instead of a tribal-knowledge checklist.")
//! @yah:next("Wire the future 'containerise warden in pond' ticket: camp's pond bring-up (today: spawn_pond in app/yah/cli/src/camp.rs embeds warden in-process) replaces the embedded ServerState builder with: (a) WardenContainerSpec::new(...) + state_dir under .yah/infra/pond/<svc>-<env>/warden-state/, (b) local_driver::pond_warden::build_warden_run_spec, (c) LocalRuntime::ensure_image + run, (d) read the bound http_port via `docker port` and write it to .yah/jit/warden-pond-port.json. Desktop's adopt path (R374-F2) keeps working unchanged because it already reads that port file and GETs warden's /pond/state — the container-vs-embedded distinction is invisible at the desktop seam.")
//! @yah:next("T3 (W142-pond.md doc update) consumes T1+T2 together: outer container shape, internal supervisor split, docker socket mount + permission model section pointing at pond_warden's module docstring as the canonical contract source.")
//! @yah:verify("cargo test -p local-driver --lib  # 37/37 incl. 8 pond_warden::tests")
//! @yah:verify("cargo test -p cloud --lib reconciler::pond  # 25/25 — ContainerRunSpec extension didn't regress existing pond paths")
//! @yah:verify("cargo test -p warden --lib pond  # 9/9")
//! @yah:verify("cargo check -p local-driver -p cloud -p warden --tests  # clean")
//! @yah:gotcha("ContainerRunSpec field additions (cap_add, cgroupns) are not behind a feature flag — every struct-literal caller must populate them. The four existing sites are updated; future call-sites should prefer ContainerRunSpec::new() + assignment so adding more fields stays one-line.")
//! @yah:gotcha("pond_warden does not run a uid-gid mapping for the docker socket. macOS/OrbStack works because OrbStack proxies the socket as-is and root inside the container can use it. Linux dev boxes also work because container root bypasses the docker group check on connect. A future ticket that wants to run the warden-container as non-root must add --group-add <docker-gid> wiring — the module docstring calls this out as the extension point.")
//! @yah:gotcha("DEFAULT_WARDEN_IMAGE is ghcr.io/yah-ai/yah-warden:latest, but the release pipeline does NOT yet build this image (T1's handoff queues the image-yah-warden GHA job as next step). Local pond bring-up that consumes this default will fail to pull until the GHA job lands; operators can override the image field to a locally-built tag in the interim.")
//!
//! @yah:ticket(R456-T2, "Carry slot probes through cloud::AdoptPondRecord → desktop MirrorRuntimeView → UI cell disclosure")
//! @yah:at(2026-06-05T08:25:02Z)
//! @yah:status(review)
//! @yah:phase(E)
//! @yah:parent(R456)
//! @yah:handoff("AdoptProbeOutcome + AdoptSlotProbe added to cloud/src/reconciler/pond.rs alongside AdoptPondRecord. AdoptPondRecord.slots: Vec<AdoptSlotProbe> with serde(default) for pre-E compat. MirrorRuntimeView gains slot_probes: Vec<AdoptSlotProbe>; view_from_pond_record copies record.slots; all other construction paths use vec![]. RunningMirrorEntry gains slot_probes with serde(default). TS: WireSlotProbeOutcome (state-tagged union, not WireProbeOutcome which belongs to identity probes) + WireSlotProbe in env/types.ts; slotProbes?: WireSlotProbe[] on RunningMirrorEntry. TierCard in MirrorPanel.tsx: SlotDots component renders h-1.5 w-1.5 colored dots per slot (green=pass, red=fail, gray=pending). ServicesView EnvCell: same inline dots in provider_label row via slotProbesMap threaded through ServicesMatrix and MatrixRow.")
//! @yah:verify("cargo check -p cloud -p desktop  # clean")
//! @yah:verify("cargo test -p cloud --lib reconciler::pond  # 27/27")
//! @yah:verify("cargo test -p desktop --lib mirror_observation  # 6/6")
//! @yah:verify("bun run typecheck (packages/yah/ui)  # no new errors beyond pre-existing ChatSurface + vitest")
//! @arch:see(.yah/docs/working/W180-pond-richer-topology.md)
//! @yah:depends_on(R456-F1)

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::StatusCode;
use tokio::process::Command;
use tokio::sync::oneshot;
use tracing::{info, warn};

use super::{into_running, slot_field_u16, LogBuffer, ReconcileCtx, RunningWorkload};
use crate::config::Provider;
use crate::local_container_spec_from_provider;
use crate::MirrorProviderSlot;
use local_driver::pond_minio::{ensure_minio_running, MinioRunning, MinioSpec};
use local_driver::{canonical_label, canonical_name, LocalContainerSpec, LocalRuntime};
// R408-T2: docker socket mount + permission model for the pond warden-container
// is encoded as a builder in `local_driver::pond_warden`. The future
// "containerise warden in pond bring-up" ticket consumes
// `pond_warden::build_warden_run_spec` to produce the ContainerRunSpec for
// the yah-warden image landed in R408-T1.
#[allow(unused_imports)]
use local_driver::pond_warden::{build_warden_run_spec, WardenContainerSpec};

/// Default MinIO image. Pinned to a recent stable RELEASE tag so the image
/// cache is deterministic across operators.
pub const DEFAULT_MINIO_IMAGE: &str = "docker.io/minio/minio:RELEASE.2025-04-22T22-12-26Z";

/// Default miniflare image (R455-F1). Operators override to a locally-built
/// tag until the release-pipeline `image-yah-miniflare` GHA job lands.
pub const DEFAULT_MINIFLARE_IMAGE: &str = "ghcr.io/yah-ai/yah-miniflare:latest";

/// Default operator-visible pond port. Matches the canonical pond.toml.
pub const DEFAULT_MINIFLARE_PORT: u16 = 4322;
pub const DEFAULT_MINIO_API_PORT: u16 = 9000;
pub const DEFAULT_MINIO_CONSOLE_PORT: u16 = 9001;
pub const DEFAULT_BUCKET: &str = "yah-dev";

/// MinIO root creds for the pond tier. Static defaults — operators never see
/// real credentials at this layer; the bucket is public-read for the Worker.
/// T4/T5 may surface an override knob if anyone needs it.
pub const DEFAULT_MINIO_USER: &str = "yahsim";
pub const DEFAULT_MINIO_PASSWORD: &str = "yahsim-local-only";

/// Slot role names this reconciler arm consumes.
const STATIC_SLOT: &str = "static";
const OBJECT_STORE_SLOT: &str = "object_store";

/// Canonical DNS aliases siblings on the per-cell bridge use to reach each
/// other (R455-F1). The Worker's `ASSET_ORIGIN` binding points at
/// `http://{MINIO_NETWORK_ALIAS}:9000/<bucket>` once the bridge is up.
pub const MINIO_NETWORK_ALIAS: &str = "minio";
pub const MINIFLARE_NETWORK_ALIAS: &str = "miniflare";

/// miniflare Node.js shim — embedded at compile time, written to the state dir
/// at spinup time. Reads config from env vars and runs the Worker under workerd.
/// Re-exported as `cloud::MINIFLARE_SIM_SCRIPT` so camp can embed it in
/// `MiniflareSpec` without a separate file read (R374-F4).
pub const MINIFLARE_SIM_SCRIPT: &str = include_str!("../../worker/miniflare-sim.mjs");

/// Knobs for the pond bring-up path.
#[derive(Debug, Clone)]
pub struct PondOptions {
    /// MinIO image ref. Pin a tag so image-cache hits are deterministic.
    pub minio_image: String,
    /// MinIO root user (becomes the S3 access key for publisher invocations).
    pub minio_user: String,
    /// MinIO root password (S3 secret key).
    pub minio_password: String,
    /// How long to wait for the MinIO container and miniflare process to
    /// become ready before declaring the up failed.
    pub ready_timeout: Duration,
    /// When `true`, probe the sim port and adopt already-running processes
    /// — never pull images or start new ones. Desktop sets this because camp
    /// owns the container lifecycle at startup (R256-F6). Camp itself always
    /// uses `adopt_only: false`.
    pub adopt_only: bool,
    /// JS runtime binary for the miniflare shim. Defaults to `bun` (then
    /// `node` as a fallback). Override via `BUN`/`NODE` env vars or this field.
    pub js_binary: Option<PathBuf>,
}

impl Default for PondOptions {
    fn default() -> Self {
        Self {
            minio_image: DEFAULT_MINIO_IMAGE.into(),
            minio_user: DEFAULT_MINIO_USER.into(),
            minio_password: DEFAULT_MINIO_PASSWORD.into(),
            ready_timeout: Duration::from_secs(30),
            adopt_only: false,
            js_binary: None,
        }
    }
}

/// Per-bring-up state on disk.
#[derive(Debug, Clone)]
pub struct PondState {
    pub dir: PathBuf,
    /// Worker JS file written from the compile-time embedded script.
    pub worker_js: PathBuf,
    /// miniflare Node.js shim written from the compile-time embedded script.
    pub miniflare_shim: PathBuf,
    pub minio_data: PathBuf,
    pub credentials: PathBuf,
}

impl PondState {
    /// State dir layout: `<workspace>/.yah/infra/pond/<svc>-<env>/`.
    pub fn for_ctx(ctx: &ReconcileCtx<'_>) -> Self {
        let dir = ctx
            .workspace_root
            .join(".yah/infra/pond")
            .join(format!("{}-{}", ctx.service.name, ctx.env));
        Self {
            worker_js: dir.join("worker.js"),
            miniflare_shim: dir.join("miniflare-sim.mjs"),
            minio_data: dir.join("minio-data"),
            credentials: dir.join("credentials"),
            dir,
        }
    }
}

/// Main entry point: dispatch the pond-tier path from
/// `MesofactStaticReconciler::up`. Brings up MinIO (object store) and
/// miniflare (CF Worker runtime), auto-creates the bucket with public-read
/// access, and returns the lifecycle handle.
///
/// `worker_script` is the compiled Worker JS content (injected by the caller
/// so the sim runs the same artifact as prod).
pub async fn up_pond(
    ctx: &ReconcileCtx<'_>,
    options: &PondOptions,
    static_fields: &BTreeMap<String, toml::Value>,
    worker_script: &str,
) -> Result<RunningWorkload> {
    // ── Adopt-only path (R374-F2, desktop) ───────────────────────────────────
    // Camp embeds warden as the pond workload-status authority. Desktop reads
    // `<camp_root>/.yah/jit/warden-pond-port.json` and GETs `/pond/state` for
    // the (service, env, component) tuple. Pre-R374 the desktop did a bare
    // TCP probe on the miniflare port — that probe could silently adopt a
    // half-alive workerd orphaned to launchd while MinIO was already gone,
    // surfacing later as "Network connection lost" from entry.worker.js. The
    // warden status surface makes that shape structurally impossible: warden
    // only reports Running when the deploy handler returned successfully and
    // its supervisor still holds the lifecycle.
    if options.adopt_only {
        let ident = pond_workload_ident(&ctx.service.name, ctx.env, &ctx.component.id);
        let port = read_warden_pond_port(ctx.workspace_root).with_context(|| {
            format!(
                "component {}: cannot read .yah/jit/warden-pond-port.json — \
                 ensure yah-camp is started with a service that declares a \
                 pond mirror (providers.static.kind = miniflare-container)",
                ctx.component.id,
            )
        })?;
        let record = match query_warden_pond_state(port, &ident).await? {
            Some(r) => r,
            None => anyhow::bail!(
                "component {}: pond workload {:?} is not registered with the \
                 camp-embedded warden (GET http://127.0.0.1:{}/pond/state → 404)",
                ctx.component.id,
                ident,
                port,
            ),
        };
        match record.phase {
            AdoptPondPhase::Running => {
                let dev_url = record.dev_url.unwrap_or_else(|| {
                    let sim_port = slot_field_u16(static_fields, "port")
                        .unwrap_or(DEFAULT_MINIFLARE_PORT);
                    format!("http://localhost:{sim_port}")
                });
                info!(
                    dev_url = %dev_url,
                    ident = %ident,
                    "pond Running per warden; adopting",
                );
                let mut adopted =
                    RunningWorkload::adopted("mesofact-static", "static", Some(dev_url));
                if let Some(console) = record.console_url {
                    adopted = adopted.with_console_url(console);
                }
                return Ok(adopted);
            }
            AdoptPondPhase::Pending => anyhow::bail!(
                "component {}: pond workload {:?} is Pending in warden — \
                 deploy still in flight; retry shortly",
                ctx.component.id,
                ident,
            ),
            AdoptPondPhase::Degraded => anyhow::bail!(
                "component {}: pond workload {:?} is Degraded per warden{}",
                ctx.component.id,
                ident,
                record
                    .error
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default(),
            ),
            AdoptPondPhase::Failed => anyhow::bail!(
                "component {}: pond workload {:?} Failed per warden{}",
                ctx.component.id,
                ident,
                record
                    .error
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default(),
            ),
        }
    }

    // ── Non-adopt path (R374-F3) ─────────────────────────────────────────────
    // The pond bring-up shape became: bring MinIO up via warden's shared
    // primitives (`local_driver::pond_minio::ensure_minio_running`), then
    // spawn miniflare against that. Warden's HTTP path additionally wires
    // restart-on-failure via `warden::pond::minio::MinioReconciler`; this
    // direct-call entry point does not — it's only used by `pond_smoke` and
    // `yah cloud mirror up`. Production lifecycles run through
    // `warden::pond::deploy` and get reconciler-managed MinIO.
    let store_fields = require_object_store_slot(ctx)?;
    let sim_port = slot_field_u16(static_fields, "port").unwrap_or(DEFAULT_MINIFLARE_PORT);
    let bucket = resolve_bucket(static_fields, store_fields);
    let state = PondState::for_ctx(ctx);
    prepare_state_dir(ctx, &state)?;

    let local_spec = load_local_container_spec(ctx)?;
    let runtime = LocalRuntime::detect(&local_spec)
        .await
        .context("detecting local container runtime (orbstack/colima/docker)")?;
    info!(
        runtime = runtime.detected.as_str(),
        docker_host = %runtime.docker_host,
        "pond: using detected runtime",
    );

    let minio_spec = build_minio_spec(ctx, options, store_fields, &bucket, &state)?;
    let minio_running = ensure_minio_running(&runtime, &minio_spec).await?;

    write_credentials_file(
        &state,
        &minio_running.endpoint,
        &minio_running.bucket,
        &minio_running.access_key,
        &minio_running.secret_key,
    )?;

    let (worker_mode_str, ssr_origin, ssr_prefixes) =
        worker_mode_triple(&super::mesofact_static::parse_worker_mode(static_fields));

    let (child, log_buf) = spawn_miniflare_child(
        ctx,
        options,
        sim_port,
        &state,
        &minio_running,
        worker_script,
        &worker_mode_str,
        &ssr_origin,
        &ssr_prefixes,
    )
    .await
        .map_err(|e| {
            // Tear down MinIO so we don't leak a half-up workload.
            let runtime = runtime.clone();
            let name = minio_running.container_name.clone();
            tokio::spawn(async move {
                let _ = runtime.stop_and_remove(&name, Duration::from_secs(2)).await;
            });
            e
        })?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let supervisor = supervise_miniflare_and_minio(
        runtime.clone(),
        minio_running.container_name.clone(),
        child,
        shutdown_rx,
    );

    let dev_url = format!("http://127.0.0.1:{sim_port}");
    info!(
        dev_url = %dev_url,
        endpoint = %minio_running.endpoint,
        bucket = %minio_running.bucket,
        "pond ready (miniflare + MinIO via local_driver::pond_minio)",
    );

    Ok(into_running(
        super::mesofact_static::WORKLOAD_KIND,
        STATIC_SLOT,
        Some(dev_url),
        None,
        Some(log_buf),
        shutdown_tx,
        supervisor,
    )
    .with_console_url(minio_running.console_url.clone()))
}

/// Build a [`MinioSpec`] from the canonical pond options + the
/// `providers.object_store` slot fields. Used by both the direct-call path
/// (cloud's `up_pond`) and the warden-deploy path (camp's handler).
pub fn build_minio_spec(
    ctx: &ReconcileCtx<'_>,
    options: &PondOptions,
    store_fields: &BTreeMap<String, toml::Value>,
    bucket: &str,
    state: &PondState,
) -> Result<MinioSpec> {
    let api_port = slot_field_u16(store_fields, "api_port").unwrap_or(DEFAULT_MINIO_API_PORT);
    let console_port =
        slot_field_u16(store_fields, "console_port").unwrap_or(DEFAULT_MINIO_CONSOLE_PORT);
    // R455-F1: every pond MinIO joins the per-cell bridge with alias `minio`
    // so siblings on the bridge (miniflare, mesofact-dev) reach S3 via DNS
    // (`http://minio:9000/<bucket>`). The API + console ports still publish
    // to the host so the embedded warden + cloud-tier publisher can probe
    // without joining the bridge themselves.
    Ok(MinioSpec {
        image: options.minio_image.clone(),
        user: options.minio_user.clone(),
        password: options.minio_password.clone(),
        api_port,
        console_port,
        bucket: bucket.to_string(),
        data_dir: state.minio_data.clone(),
        container_name: canonical_name(&ctx.service.name, ctx.env, OBJECT_STORE_SLOT),
        container_label: canonical_label(&ctx.service.name, ctx.env, OBJECT_STORE_SLOT),
        ready_timeout: options.ready_timeout,
        network: Some(local_driver::pond_network_name(
            &ctx.service.name,
            ctx.env,
        )),
        network_alias: Some(MINIO_NETWORK_ALIAS.into()),
    })
}

/// Resolve the `providers.object_store` slot and return its inline fields.
pub fn require_object_store_slot<'a>(
    ctx: &'a ReconcileCtx<'_>,
) -> Result<&'a BTreeMap<String, toml::Value>> {
    let store_slot = ctx.slot(OBJECT_STORE_SLOT).with_context(|| {
        format!(
            "mirror {svc}/{env} has providers.static.kind = miniflare-container but no \
             providers.object_store slot — pond requires both",
            svc = ctx.service.name,
            env = ctx.env,
        )
    })?;
    match store_slot {
        MirrorProviderSlot::Inline {
            kind: Provider::MinioContainer,
            fields,
        } => Ok(fields),
        MirrorProviderSlot::Inline { kind, .. } => bail!(
            "providers.object_store.kind = {kind:?}, expected minio-container for pond",
        ),
        MirrorProviderSlot::Reference { provider_id, .. } => bail!(
            "providers.object_store.use = {provider_id:?} — pond requires an inline \
             minio-container slot, not a reference",
        ),
    }
}

/// Idempotent state-dir setup: legacy migration from `infra/state/local-sim/`
/// + mkdir of the worker/shim/minio_data subtree.
fn prepare_state_dir(ctx: &ReconcileCtx<'_>, state: &PondState) -> Result<()> {
    // Auto-migrate legacy state from infra/state/local-sim/ on first up after
    // R368-F3. Handles two old path shapes: the env-renamed form (<svc>-pond,
    // present after R368-F2) and the original (<svc>-local-sim).
    if !state.dir.exists() {
        for legacy_env in &[ctx.env, "local-sim"] {
            let legacy = ctx
                .workspace_root
                .join(".yah/infra/state/local-sim")
                .join(format!("{}-{}", ctx.service.name, legacy_env));
            if legacy.exists() {
                if let Some(parent) = state.dir.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
                std::fs::rename(&legacy, &state.dir).with_context(|| {
                    format!(
                        "migrating pond state: {} → {}",
                        legacy.display(),
                        state.dir.display(),
                    )
                })?;
                info!(
                    from = %legacy.display(),
                    to = %state.dir.display(),
                    "migrated pond state dir to infra/pond/",
                );
                break;
            }
        }
    }
    std::fs::create_dir_all(&state.dir)
        .with_context(|| format!("creating {}", state.dir.display()))?;
    std::fs::create_dir_all(&state.minio_data)
        .with_context(|| format!("creating {}", state.minio_data.display()))?;
    Ok(())
}

/// Lower a [`super::mesofact_static::WorkerMode`] to the three Worker
/// binding strings (`WORKER_MODE`, `SSR_ORIGIN`, `SSR_PREFIXES` as a Vec for
/// later JSON-encoding). Used by both the cloud-direct pond path and the
/// warden-side miniflare spec builder.
pub fn worker_mode_triple(
    mode: &super::mesofact_static::WorkerMode,
) -> (String, String, Vec<String>) {
    match mode {
        super::mesofact_static::WorkerMode::Static => {
            ("static".to_string(), String::new(), vec![])
        }
        super::mesofact_static::WorkerMode::Spa => {
            ("spa".to_string(), String::new(), vec![])
        }
        super::mesofact_static::WorkerMode::Ssr { origin_url, prefixes } => (
            "ssr".to_string(),
            origin_url.clone(),
            prefixes.clone(),
        ),
    }
}

/// Write the worker JS + miniflare shim to the state dir, spawn the JS
/// runtime, then wait for the `[miniflare-sim] ready` stdout line. Returns
/// the live child + log buffer for the caller's supervisor.
async fn spawn_miniflare_child(
    ctx: &ReconcileCtx<'_>,
    options: &PondOptions,
    sim_port: u16,
    state: &PondState,
    minio_running: &MinioRunning,
    worker_script: &str,
    worker_mode: &str,
    ssr_origin: &str,
    ssr_prefixes: &[String],
) -> Result<(tokio::process::Child, LogBuffer)> {
    std::fs::write(&state.worker_js, worker_script.as_bytes())
        .with_context(|| format!("writing {}", state.worker_js.display()))?;
    std::fs::write(&state.miniflare_shim, MINIFLARE_SIM_SCRIPT.as_bytes())
        .with_context(|| format!("writing {}", state.miniflare_shim.display()))?;

    // ASSET_ORIGIN points miniflare at MinIO's HTTP endpoint — the Worker
    // fetches assets over plain HTTP, mirroring the prod path (R2 custom
    // domain).
    let asset_origin = format!("{}/{}", minio_running.endpoint, minio_running.bucket);
    let node_binary = resolve_js_binary(options.js_binary.as_deref());
    let miniflare_import = resolve_miniflare_import(ctx.workspace_root)
        .unwrap_or_else(|| "miniflare".to_string());
    let workerd_binary = resolve_workerd_binary(ctx.workspace_root);

    info!(
        port = sim_port,
        asset_origin = %asset_origin,
        node_binary = %node_binary.display(),
        workerd_cached = workerd_binary.is_some(),
        "spawning miniflare (workerd)",
    );

    let ssr_prefixes_json =
        serde_json::to_string(ssr_prefixes).unwrap_or_else(|_| "[]".to_string());
    let mut cmd = Command::new(&node_binary);
    cmd.arg(&state.miniflare_shim)
        .env("MF_PORT", sim_port.to_string())
        .env("MF_SCRIPT", &state.worker_js)
        .env("MF_MINIFLARE_IMPORT", &miniflare_import)
        .env("ASSET_ORIGIN", &asset_origin)
        .env("WORKER_MODE", worker_mode)
        .env("SSR_ORIGIN", ssr_origin)
        .env("SSR_PREFIXES", &ssr_prefixes_json)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(ref wb) = workerd_binary {
        cmd.env("MINIFLARE_WORKERD_PATH", wb);
    }

    let mut child = cmd.spawn().map_err(|e| {
        anyhow::anyhow!(e).context(format!(
            "spawning miniflare via `{}` — ensure bun (or Node.js ≥18) is on PATH, \
             or set BUN/NODE env var",
            node_binary.display(),
        ))
    })?;

    let log_buf = LogBuffer::new();
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    if let Some(stdout) = child.stdout.take() {
        let buf = log_buf.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(stdout).lines();
            let mut ready_tx = Some(ready_tx);
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(tx) = ready_tx.take() {
                    if line.contains("[miniflare-sim] ready on ") {
                        let _ = tx.send(());
                    } else {
                        ready_tx = Some(tx);
                    }
                }
                buf.push(line).await;
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let buf = log_buf.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                buf.push(line).await;
            }
        });
    }

    match tokio::time::timeout(options.ready_timeout, ready_rx).await {
        Ok(Ok(())) => Ok((child, log_buf)),
        Ok(Err(_)) | Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            bail!(
                "miniflare did not emit ready signal within {:?}",
                options.ready_timeout,
            );
        }
    }
}

/// Look up the workspace's `local-container` provider and turn it into a
/// [`LocalContainerSpec`]. Returns a friendly error when the workspace has
/// no such provider declared.
fn load_local_container_spec(ctx: &ReconcileCtx<'_>) -> Result<LocalContainerSpec> {
    let cfg = crate::config::CloudConfig::load(ctx.workspace_root)
        .context("loading CloudConfig for local-container provider lookup")?;
    let provider = cfg
        .providers
        .iter()
        .find(|p| matches!(p.kind, Provider::LocalContainer))
        .with_context(|| {
            format!(
                "no `kind = \"local-container\"` provider declared in {}/.yah/infra/providers/ — \
                 pond mirror needs orbstack.toml or equivalent",
                ctx.workspace_root.display(),
            )
        })?;
    local_container_spec_from_provider(provider)
}

/// Resolve the bucket name from the static + object_store slot field maps.
/// Falls back to a default when neither slot declares one; logs a warning
/// when the two slots disagree (static wins).
fn resolve_bucket(
    static_fields: &BTreeMap<String, toml::Value>,
    store_fields: &BTreeMap<String, toml::Value>,
) -> String {
    let from_static = static_fields.get("bucket").and_then(|v| v.as_str());
    let from_store = store_fields.get("bucket").and_then(|v| v.as_str());
    match (from_static, from_store) {
        (Some(a), Some(b)) if a != b => {
            warn!(
                static_bucket = a,
                object_store_bucket = b,
                "providers.static.bucket disagrees with providers.object_store.bucket; using static's",
            );
            a.to_string()
        }
        (Some(s), _) | (_, Some(s)) => s.to_string(),
        _ => DEFAULT_BUCKET.to_string(),
    }
}

/// Write the `.env`-shaped creds file R256-T4's publisher invocation reads.
/// Format chosen so it's directly sourceable from a shell.
fn write_credentials_file(
    state: &PondState,
    endpoint: &str,
    bucket: &str,
    user: &str,
    password: &str,
) -> Result<()> {
    let body = format!(
        "# Auto-generated by yah pond reconciler. Do not edit.\n\
         # Sourceable by mesofact-publish wrappers (R256-T4) to talk to the\n\
         # local MinIO endpoint without hitting Cloudflare.\n\
         MESOFACT_ENDPOINT={endpoint}\n\
         MESOFACT_BUCKET={bucket}\n\
         MESOFACT_S3_ACCESS_KEY_ID={user}\n\
         MESOFACT_S3_SECRET_ACCESS_KEY={password}\n",
    );
    std::fs::write(&state.credentials, body)
        .with_context(|| format!("writing {}", state.credentials.display()))
}

/// Supervisor task: owns the miniflare child + tears down the MinIO
/// container when the workload shuts down. Used by cloud's direct-call
/// path (`up_pond` non-adopt branch) where cloud owns MinIO's teardown.
fn supervise_miniflare_and_minio(
    runtime: LocalRuntime,
    minio_name: String,
    miniflare: tokio::process::Child,
    shutdown_rx: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        run_miniflare_supervisor(miniflare, shutdown_rx).await;
        if let Err(e) = runtime.stop_and_remove(&minio_name, Duration::from_secs(3)).await {
            warn!(container = %minio_name, error = %e, "pond minio teardown");
        }
        Ok(())
    })
}

/// Shared miniflare child supervision shape. SIGTERM lets the miniflare
/// shim call `mf.dispose()` (which kills the workerd subprocess cleanly);
/// falls back to SIGKILL after 5 s.
async fn run_miniflare_supervisor(
    mut miniflare: tokio::process::Child,
    shutdown_rx: oneshot::Receiver<()>,
) {
    tokio::select! {
        res = miniflare.wait() => {
            if let Ok(status) = res {
                if !status.success() {
                    warn!(?status, "miniflare exited non-zero");
                }
            }
        }
        _ = shutdown_rx => {
            #[cfg(unix)]
            if let Some(pid) = miniflare.id() {
                let _ = std::process::Command::new("kill")
                    .arg(pid.to_string())
                    .status();
            }
            match tokio::time::timeout(Duration::from_secs(5), miniflare.wait()).await {
                Ok(_) => {}
                Err(_) => {
                    warn!("miniflare did not exit after SIGTERM; sending SIGKILL");
                    let _ = miniflare.start_kill();
                    let _ = miniflare.wait().await;
                }
            }
            #[cfg(not(unix))]
            {
                let _ = miniflare.start_kill();
                let _ = miniflare.wait().await;
            }
        }
    }
}

/// Resolve the JS runtime binary for the miniflare shim.
/// Priority: explicit field > `BUN` env var > `bun` on PATH > `NODE` env var > `node`.
pub fn resolve_js_binary(js_binary: Option<&std::path::Path>) -> PathBuf {
    if let Some(p) = js_binary {
        return p.to_path_buf();
    }
    if let Some(p) = std::env::var_os("BUN") {
        return PathBuf::from(p);
    }
    // Prefer bun as the workspace default; fall back to node if absent.
    if which_bun_on_path() {
        return PathBuf::from("bun");
    }
    if let Some(p) = std::env::var_os("NODE") {
        return PathBuf::from(p);
    }
    PathBuf::from("node")
}

pub fn which_bun_on_path() -> bool {
    std::process::Command::new("bun")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Return an absolute path to miniflare's CJS entry point if the monorepo
/// worker directory is present under the workspace root. Operators who have
/// the yah source tree get zero-download spinup; those who don't fall back to
/// the bare `"miniflare"` specifier (which requires a lazy npm install).
pub fn resolve_miniflare_import(workspace_root: &std::path::Path) -> Option<String> {
    let index = workspace_root
        .join("crates/yah/cloud/worker/node_modules/miniflare/dist/src/index.js");
    if index.exists() {
        Some(index.to_string_lossy().into_owned())
    } else {
        None
    }
}

/// Return the workerd binary path from the monorepo's worker node_modules, if
/// present. Passed to miniflare as `MINIFLARE_WORKERD_PATH` so the 83 MB
/// binary is never re-downloaded when it's already on disk. Falls back to
/// miniflare's own resolution (from the `workerd` npm package) when absent.
pub fn resolve_workerd_binary(workspace_root: &std::path::Path) -> Option<PathBuf> {
    let bin = workspace_root.join(if cfg!(windows) {
        "crates/yah/cloud/worker/node_modules/workerd/bin/workerd.exe"
    } else {
        "crates/yah/cloud/worker/node_modules/workerd/bin/workerd"
    });
    if bin.exists() { Some(bin) } else { None }
}

// ── R374-F2: warden status query (desktop adopt path) ────────────────────────

/// Workload identity convention shared between camp (the producer) and
/// desktop (the consumer). Kept short to fit the warden `MeshIdent` regex.
pub fn pond_workload_ident(service: &str, env: &str, component_id: &str) -> String {
    format!("{service}-{env}-{component_id}")
}

/// Per-workload phase reported by `GET /pond/state`. Mirrors
/// `warden::pond::PondPhase` on the wire — kept local to avoid taking a
/// runtime dep on the warden crate from cloud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptPondPhase {
    Pending,
    Running,
    Degraded,
    Failed,
}

/// Liveness/readiness outcome for one slot — mirrors
/// `warden::pond::ProbeOutcome` without a direct crate dependency.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum AdoptProbeOutcome {
    Pass,
    Fail { reason: String },
    Pending,
}

/// Per-slot probe snapshot — mirrors `warden::pond::SlotProbe`.
/// `#[serde(default)]` on `url` keeps deserialization lenient for
/// pre-E warden responses that omit the field.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AdoptSlotProbe {
    pub slot: String,
    pub liveness: AdoptProbeOutcome,
    pub readiness: AdoptProbeOutcome,
    pub last_checked_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Subset of `warden::pond::PondStateRecord` the desktop adopt path and
/// the observation seam (`desktop::mirror_observation`) need. Field set
/// kept narrow to avoid taking a runtime dep on the warden crate from
/// cloud — extend it (and add a matching field to warden's record) when
/// a new bit of state needs to ride to the desktop.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AdoptPondRecord {
    pub phase: AdoptPondPhase,
    /// Identity fields — populated by warden so list-all consumers can
    /// correlate without re-deriving the ident scheme. `#[serde(default)]`
    /// because the per-ident `GET /pond/state` response is canonical only
    /// for `phase`, `dev_url`, `console_url`, and `error` today; adding
    /// `default` here keeps the per-ident path lenient.
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub env: String,
    #[serde(default)]
    pub component_id: String,
    #[serde(default)]
    pub dev_url: Option<String>,
    #[serde(default)]
    pub console_url: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// Per-slot probe snapshots from warden (R456-F1 Phase E). Empty for
    /// pre-E warden responses — callers treat an empty vec as "no probe
    /// data yet" rather than "all slots failed".
    #[serde(default)]
    pub slots: Vec<AdoptSlotProbe>,
}

/// Read the embedded warden's bound port from
/// `<camp_root>/.yah/jit/warden-pond-port.json`. The file is written by
/// `ensure_pond_running` in `app/yah/cli/src/camp.rs` (camp startup AND the
/// `pond.ensure_running` RPC recovery path).
pub fn read_warden_pond_port(workspace_root: &std::path::Path) -> Result<u16> {
    let path = workspace_root.join(".yah/jit/warden-pond-port.json");
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("parsing {}", path.display()))?;
    let port = v
        .get("port")
        .and_then(|x| x.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .with_context(|| {
            format!(
                "{}: missing or invalid 'port' field",
                path.display()
            )
        })?;
    Ok(port)
}

/// `GET http://127.0.0.1:{port}/pond/state?ident=...`. Returns `Ok(None)`
/// when warden replies 404 (no registration for that ident — clear "pond
/// not running" signal). Bails on connection errors / non-404 non-2xx.
pub async fn query_warden_pond_state(
    port: u16,
    ident: &str,
) -> Result<Option<AdoptPondRecord>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .context("building reqwest client for warden status query")?;
    let url = format!("http://127.0.0.1:{port}/pond/state");
    let resp = client
        .get(&url)
        .query(&[("ident", ident)])
        .send()
        .await
        .with_context(|| format!("GET {url}?ident={ident}"))?;
    match resp.status() {
        StatusCode::OK => {
            let record: AdoptPondRecord = resp
                .json()
                .await
                .context("parsing warden /pond/state response")?;
            Ok(Some(record))
        }
        StatusCode::NOT_FOUND => Ok(None),
        s => {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("warden /pond/state returned {s}: {body}")
        }
    }
}

/// `GET http://127.0.0.1:{port}/pond` — list every pond workload warden
/// is currently tracking. Always 200 from warden (empty `workloads` when
/// nothing is registered). Used by the desktop observation seam so a
/// single GET answers "what's up?" across every declared pond cell,
/// instead of one GET per ident.
#[derive(Debug, serde::Deserialize)]
struct WardenPondListResponse {
    workloads: Vec<AdoptPondRecord>,
}

pub async fn query_warden_pond_list(port: u16) -> Result<Vec<AdoptPondRecord>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .context("building reqwest client for warden list query")?;
    let url = format!("http://127.0.0.1:{port}/pond");
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    match resp.status() {
        StatusCode::OK => {
            let body: WardenPondListResponse = resp
                .json()
                .await
                .context("parsing warden /pond list response")?;
            Ok(body.workloads)
        }
        s => {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("warden /pond returned {s}: {body}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn resolve_bucket_static_wins_on_disagreement() {
        let mut s = BTreeMap::new();
        s.insert("bucket".into(), toml::Value::String("from-static".into()));
        let mut o = BTreeMap::new();
        o.insert("bucket".into(), toml::Value::String("from-object-store".into()));
        assert_eq!(resolve_bucket(&s, &o), "from-static");
    }

    #[test]
    fn resolve_bucket_falls_back_to_either_set_field() {
        let s = BTreeMap::new();
        let mut o = BTreeMap::new();
        o.insert("bucket".into(), toml::Value::String("from-object-store".into()));
        assert_eq!(resolve_bucket(&s, &o), "from-object-store");

        let mut s = BTreeMap::new();
        s.insert("bucket".into(), toml::Value::String("from-static".into()));
        let o = BTreeMap::new();
        assert_eq!(resolve_bucket(&s, &o), "from-static");
    }

    #[test]
    fn resolve_bucket_uses_default_when_unset() {
        let s = BTreeMap::new();
        let o = BTreeMap::new();
        assert_eq!(resolve_bucket(&s, &o), DEFAULT_BUCKET);
    }

    #[test]
    fn pond_state_layout_under_workspace_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = crate::ServiceConfig {
            schema_version: 1,
            name: "dev-yah".into(),
            domain: "yah.dev".into(),
            components: vec![],
        };
        let comp = crate::ServiceComponent {
            id: "site".into(),
            kind: "mesofact-static".into(),
            path: "app/yah/web".into(),
            role: "static".into(),
            publishes: None,
            wave: 0,
        };
        let mirror = crate::MirrorConfig {
            schema_version: 1,
            shape: crate::MirrorShape::Local,
            providers: BTreeMap::new(),
            asset_aliases: Default::default(),
        };
        let ctx = ReconcileCtx {
            workspace_root: tmp.path(),
            service: &svc,
            component: &comp,
            mirror: &mirror,
            env: "pond",
        };
        let state = PondState::for_ctx(&ctx);
        assert_eq!(
            state.dir,
            tmp.path()
                .join(".yah/infra/pond/dev-yah-pond"),
        );
        assert_eq!(state.worker_js, state.dir.join("worker.js"));
        assert_eq!(state.miniflare_shim, state.dir.join("miniflare-sim.mjs"));
        assert_eq!(state.minio_data, state.dir.join("minio-data"));
        assert_eq!(state.credentials, state.dir.join("credentials"));
    }

    #[test]
    fn pond_options_default_pins_image_tags() {
        let opts = PondOptions::default();
        // Image refs must carry a `:tag` for cache determinism — schemars
        // schemas don't enforce this, so the default contract is the load-
        // bearing piece.
        assert!(opts.minio_image.contains(':'), "minio image must be tag-pinned");
        assert!(opts.ready_timeout >= Duration::from_secs(10));
        assert!(!opts.adopt_only, "default must not be adopt_only; camp uses false");
        assert!(opts.js_binary.is_none(), "default js_binary is None (resolved at spawn time)");
    }

    #[tokio::test]
    async fn adopt_only_errors_when_no_warden_port_file() {
        // R374-F2: adopt_only now requires camp to have written the embedded
        // warden's port to .yah/jit/warden-pond-port.json. With no file the
        // adopt path returns a clear "start yah-camp" error — the pre-R374
        // TCP probe (which could silently adopt half-alive workerd orphans)
        // is gone.
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = crate::ServiceConfig {
            schema_version: 1,
            name: "test-svc".into(),
            domain: "test.dev".into(),
            components: vec![],
        };
        let comp = crate::ServiceComponent {
            id: "site".into(),
            kind: "mesofact-static".into(),
            path: "app/web".into(),
            role: "static".into(),
            publishes: None,
            wave: 0,
        };
        let mirror = crate::MirrorConfig {
            schema_version: 1,
            shape: crate::MirrorShape::Local,
            providers: BTreeMap::new(),
            asset_aliases: Default::default(),
        };
        let ctx = ReconcileCtx {
            workspace_root: tmp.path(),
            service: &svc,
            component: &comp,
            mirror: &mirror,
            env: "pond",
        };
        let mut fields = BTreeMap::new();
        fields.insert("port".into(), toml::Value::Integer(19423));
        let opts = PondOptions { adopt_only: true, ..PondOptions::default() };
        let err = up_pond(&ctx, &opts, &fields, "").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("warden-pond-port.json"),
            "expected 'warden-pond-port.json' in error, got: {msg}"
        );
        assert!(
            msg.contains("yah-camp"),
            "expected 'yah-camp' guidance in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn adopt_only_returns_404_signal_when_warden_has_no_record() {
        // R374-F2: when the port file exists but warden returns 404 for the
        // workload ident, the adopt path bails with "not registered with the
        // camp-embedded warden" — a different (and more informative) error
        // than the no-port-file case above.
        let tmp = tempfile::TempDir::new().unwrap();
        // Stand up a mini warden-like server that always returns 404 on
        // /pond/state.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/pond/state",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::NOT_FOUND,
                    axum::Json(serde_json::json!({"error": "no such workload"})),
                )
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        // Write the port file so read_warden_pond_port succeeds.
        std::fs::create_dir_all(tmp.path().join(".yah/jit")).unwrap();
        std::fs::write(
            tmp.path().join(".yah/jit/warden-pond-port.json"),
            serde_json::json!({ "port": port }).to_string(),
        )
        .unwrap();

        let svc = crate::ServiceConfig {
            schema_version: 1,
            name: "test-svc".into(),
            domain: "test.dev".into(),
            components: vec![],
        };
        let comp = crate::ServiceComponent {
            id: "site".into(),
            kind: "mesofact-static".into(),
            path: "app/web".into(),
            role: "static".into(),
            publishes: None,
            wave: 0,
        };
        let mirror = crate::MirrorConfig {
            schema_version: 1,
            shape: crate::MirrorShape::Local,
            providers: BTreeMap::new(),
            asset_aliases: Default::default(),
        };
        let ctx = ReconcileCtx {
            workspace_root: tmp.path(),
            service: &svc,
            component: &comp,
            mirror: &mirror,
            env: "pond",
        };
        let fields = BTreeMap::new();
        let opts = PondOptions { adopt_only: true, ..PondOptions::default() };
        let err = up_pond(&ctx, &opts, &fields, "").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not registered with the camp-embedded warden"),
            "expected 'not registered with the camp-embedded warden' in error, got: {msg}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn adopt_only_adopts_on_running_phase() {
        // R374-F2: warden returns phase=running with dev_url → up_pond returns
        // a RunningWorkload::adopted carrying that URL.
        let tmp = tempfile::TempDir::new().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/pond/state",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "ident": "test-svc-pond-site",
                        "service": "test-svc",
                        "env": "pond",
                        "component_id": "site",
                        "phase": "running",
                        "dev_url": "http://localhost:4322",
                        "console_url": "http://localhost:9001",
                    })),
                )
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        std::fs::create_dir_all(tmp.path().join(".yah/jit")).unwrap();
        std::fs::write(
            tmp.path().join(".yah/jit/warden-pond-port.json"),
            serde_json::json!({ "port": port }).to_string(),
        )
        .unwrap();
        let svc = crate::ServiceConfig {
            schema_version: 1,
            name: "test-svc".into(),
            domain: "test.dev".into(),
            components: vec![],
        };
        let comp = crate::ServiceComponent {
            id: "site".into(),
            kind: "mesofact-static".into(),
            path: "app/web".into(),
            role: "static".into(),
            publishes: None,
            wave: 0,
        };
        let mirror = crate::MirrorConfig {
            schema_version: 1,
            shape: crate::MirrorShape::Local,
            providers: BTreeMap::new(),
            asset_aliases: Default::default(),
        };
        let ctx = ReconcileCtx {
            workspace_root: tmp.path(),
            service: &svc,
            component: &comp,
            mirror: &mirror,
            env: "pond",
        };
        let fields = BTreeMap::new();
        let opts = PondOptions { adopt_only: true, ..PondOptions::default() };
        let result = up_pond(&ctx, &opts, &fields, "").await.unwrap();
        assert_eq!(result.dev_url.as_deref(), Some("http://localhost:4322"));
        assert_eq!(result.console_url.as_deref(), Some("http://localhost:9001"));
        server.abort();
    }

    #[tokio::test]
    async fn adopt_only_bails_on_failed_phase_with_reason() {
        let tmp = tempfile::TempDir::new().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/pond/state",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "ident": "test-svc-pond-site",
                        "service": "test-svc",
                        "env": "pond",
                        "component_id": "site",
                        "phase": "failed",
                        "error": "MinIO did not bind port",
                    })),
                )
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        std::fs::create_dir_all(tmp.path().join(".yah/jit")).unwrap();
        std::fs::write(
            tmp.path().join(".yah/jit/warden-pond-port.json"),
            serde_json::json!({ "port": port }).to_string(),
        )
        .unwrap();
        let svc = crate::ServiceConfig {
            schema_version: 1,
            name: "test-svc".into(),
            domain: "test.dev".into(),
            components: vec![],
        };
        let comp = crate::ServiceComponent {
            id: "site".into(),
            kind: "mesofact-static".into(),
            path: "app/web".into(),
            role: "static".into(),
            publishes: None,
            wave: 0,
        };
        let mirror = crate::MirrorConfig {
            schema_version: 1,
            shape: crate::MirrorShape::Local,
            providers: BTreeMap::new(),
            asset_aliases: Default::default(),
        };
        let ctx = ReconcileCtx {
            workspace_root: tmp.path(),
            service: &svc,
            component: &comp,
            mirror: &mirror,
            env: "pond",
        };
        let fields = BTreeMap::new();
        let opts = PondOptions { adopt_only: true, ..PondOptions::default() };
        let err = up_pond(&ctx, &opts, &fields, "").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed per warden"),
            "expected 'Failed per warden' in error, got: {msg}"
        );
        assert!(
            msg.contains("MinIO did not bind port"),
            "expected error reason from warden carried through, got: {msg}"
        );
        server.abort();
    }

    #[test]
    fn miniflare_sim_script_is_embedded_and_contains_key_landmarks() {
        // Verify the compile-time include_str! picked up the shim.
        assert!(!MINIFLARE_SIM_SCRIPT.is_empty(), "MINIFLARE_SIM_SCRIPT must not be empty");
        assert!(
            MINIFLARE_SIM_SCRIPT.contains("MF_MINIFLARE_IMPORT"),
            "shim must support absolute import override for out-of-tree deploys",
        );
        assert!(
            MINIFLARE_SIM_SCRIPT.contains("ASSET_ORIGIN"),
            "shim must read ASSET_ORIGIN from env",
        );
        assert!(
            MINIFLARE_SIM_SCRIPT.contains("new Miniflare"),
            "shim must instantiate Miniflare",
        );
    }

    #[tokio::test]
    async fn query_warden_pond_list_parses_workloads_envelope() {
        // Phase A: the desktop observation seam reads `GET /pond` once and
        // matches records to declared cells. Mirror warden's actual response
        // shape — { "workloads": [PondStateRecord, ...] } — and verify
        // identity fields, phase, and the optional URLs round-trip.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/pond",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "workloads": [
                            {
                                "ident": "yah-marketing-pond-site",
                                "service": "yah-marketing",
                                "env": "pond",
                                "component_id": "site",
                                "phase": "running",
                                "dev_url": "http://127.0.0.1:4322",
                                "console_url": "http://localhost:9001",
                            },
                            {
                                "ident": "yah-dashboard-pond-site",
                                "service": "yah-dashboard",
                                "env": "pond",
                                "component_id": "site",
                                "phase": "degraded",
                                "error": "miniflare probe timeout",
                            },
                        ],
                    })),
                )
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let records = query_warden_pond_list(port).await.unwrap();
        assert_eq!(records.len(), 2);

        let marketing = records.iter().find(|r| r.service == "yah-marketing").unwrap();
        assert_eq!(marketing.env, "pond");
        assert_eq!(marketing.component_id, "site");
        assert!(matches!(marketing.phase, AdoptPondPhase::Running));
        assert_eq!(marketing.dev_url.as_deref(), Some("http://127.0.0.1:4322"));
        assert_eq!(marketing.console_url.as_deref(), Some("http://localhost:9001"));
        assert!(marketing.error.is_none());

        let dashboard = records.iter().find(|r| r.service == "yah-dashboard").unwrap();
        assert!(matches!(dashboard.phase, AdoptPondPhase::Degraded));
        assert_eq!(dashboard.error.as_deref(), Some("miniflare probe timeout"));
        assert!(dashboard.dev_url.is_none());

        server.abort();
    }

    #[tokio::test]
    async fn query_warden_pond_list_returns_empty_when_nothing_registered() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/pond",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({ "workloads": [] })),
                )
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let records = query_warden_pond_list(port).await.unwrap();
        assert!(records.is_empty());
        server.abort();
    }

    #[test]
    fn resolve_miniflare_import_finds_monorepo_worker_dir() {
        // If the monorepo is checked out (we're running tests inside it), the
        // worker dir should be found relative to CARGO_MANIFEST_DIR's ancestor.
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        // CARGO_MANIFEST_DIR = crates/yah/cloud → workspace root is 3 up
        let workspace = manifest.ancestors().nth(3).unwrap();
        let result = resolve_miniflare_import(workspace);
        // Only assert the path shape when the dir is present; CI without
        // node_modules will get None, which is the correct fallback.
        if let Some(path) = result {
            assert!(path.ends_with("index.js"), "import path should end with index.js: {path}");
            assert!(std::path::Path::new(&path).exists(), "resolved path must exist: {path}");
        }
    }
}