//! [`Reconciler`] implementation for `kind = "mesofact-static"` components.
//!
//! Dispatches on the mirror's `providers.static` slot:
//!
//! - **`kind = "local-static"` (inline)** — spawn `mesofact-dev` as a child
//!   process on `127.0.0.1:<port>`. Pointer-swap + auto-rebuild come from
//!   the binary's built-in watcher (R255-T2); the reconciler just owns
//!   start/stop and the dev URL.
//! - **`use = "cloudflare"` (reference)** — not yet implemented; production
//!   pipeline integrates `mesofact-publisher` once R157 catches up.
//!
//! Binary discovery for the local path: caller may pass an explicit path
//! via [`LocalStaticOptions::binary`]; otherwise the reconciler reads the
//! `MESOFACT_DEV_BIN` env var; otherwise it relies on PATH resolution of
//! the bare name `mesofact-dev`.
//!
//! @yah:ticket(R255-F6, "Split tier-1 into native fast-path vs managed-subprocess fallback")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-25T20:08:16Z)
//! @yah:status(review)
//! @yah:parent(R255)
//! @yah:next("native fast-path: blessed mesofact stack, bun in-process, axum-as-ingress, camp daemon runs the build job (current mesofact-dev watcher path)")
//! @yah:next("managed-subprocess fallback: generic app runs as a managed child subprocess behind axum-as-ingress")
//! @yah:next("make reconciler dispatch select the two paths explicitly rather than branching on if-compatible inside one arm")
//! @yah:assumes("not all projects have a valid in-process tier-1 — only the blessed mesofact stack (in-process bun, axum ingress) qualifies")
//! @yah:handoff("Two-path dispatch already landed in R274 (filed after F6 was opened). Native fast-path = spawn_mesofact_dev in-process in camp.rs:575 (R274-F1). Managed-subprocess fallback = adopt_only:false arm in MesofactStaticReconciler.up_local_static (mesofact_static.rs:168). Desktop sets adopt_only:true so it adopts the camp server; CLI/CI path sets adopt_only:false and spawns the binary. The 'generic app subprocess behind axum-as-ingress for non-mesofact workloads' vision is a future ticket, not R255 scope. No code change needed here.")
//! @yah:verify("Verify dispatch: (1) cargo check --workspace --locked; (2) with camp running, mirror_run_up adopts the in-process server (jit port file); (3) with camp NOT running and adopt_only:false, reconciler spawns mesofact-dev binary.")
//!
//! @yah:relay(R320, "Cloudflare first-class Infra provider + yah.dev R2 publish")
//! @yah:at(2026-05-26T00:19:09Z)
//! @yah:status(open)
//! @arch:see(.yah/docs/working/W074-cloudflare-infra-provider.md)
//!
//! @yah:ticket(R320-T8, "Wire cloudflare reference path into MesofactStaticReconciler")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T00:42:37Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R320)
//! @yah:depends_on(R320-F7)
//! @yah:handoff("Cloudflare reference path wired into MesofactStaticReconciler.up(). Reference arm now dispatches to up_cloudflare_r2() for provider_id=cloudflare, bails for any other reference provider. Method loads ProviderConfig from .yah/infra/providers/cloudflare.toml (needs account_id field), resolves R2 S3 keys from keystore/env, calls publish_to_r2, returns RunningWorkload with public_url=https://<zone>. CDN purge fires if cloudflare-api-token is present in keystore. read_workload_out_dir helper reads build.out_dir from workload.toml (defaults to dist).")
//! @yah:verify("cargo check -p cloud — clean (verified)")
//! @yah:verify("cargo test -p cloud --lib — 175 passed (verified)")
//! @yah:verify("yah cloud mirror up dev-yah --env prod (requires account_id in cloudflare.toml + R2 S3 keys in keystore)")
//!
//! @yah:relay(R327, "CF Worker provisioner: static→R2 + SSR/SPA→origin routing for mesofact sites")
//! @yah:at(2026-05-26T07:25:51Z)
//! @yah:status(review)
//! @yah:next("Design the Worker script template: static routes fetch from R2 bucket binding, SSR routes proxy to origin (yubaba service URL), SPA shell falls back to R2 index.html for unmatched paths")
//! @yah:next("Add CF Workers API calls to up_cloudflare_r2: upload Worker script, create KV/R2 bucket binding, wire Routes or Custom Domain to the Worker")
//! @yah:next("Worker replaces the Transform Rule workaround (R320-T11) as the general solution — both static-only and SSR/SPA sites go through the Worker")
//! @yah:gotcha("Pure-static sites (Mode 1) still need the Worker to serve index.html for / — R2 custom domains alone don't auto-index")
//! @yah:gotcha("Worker script must be idempotent across mirror up re-runs: re-deploy only when content hash changes")
//! @yah:gotcha("R2 bucket binding in the Worker requires the bucket name matches the mirror config — keep them in sync")
//! @yah:handoff("Worker script provisioner implemented. CloudflareClient gained deploy_worker_script (multipart PUT, ES module format, R2 ASSETS binding) and upsert_worker_route (idempotent GET+POST/PUT). MesofactStaticReconciler.up_cloudflare_r2 now: (1) parses mode/origin_url/ssr_prefixes from slot_fields; (2) renders WorkerMode-aware JS script (static/spa/ssr); (3) compares SHA256 hash against .yah/jit/worker-script-hashes.json — skips redeploy if unchanged; (4) upserts zone route {zone}/* → {service.name}-worker. Transform Rule call removed. Worker script handles / → index.html, trailing-slash directory indexes, SSR proxy to origin, SPA/SSR fallback to index.html. 21 new unit tests + 215 total passing.")
//! @yah:next("Validate live E2E: yah cloud mirror up dev-yah --env prod — Worker script deployed to CF, route yah.dev/* → dev-yah-worker, curl https://yah.dev serves index.html via Worker (not Transform Rule)")
//! @yah:next("Update MESOFACT_STATIC_GRANTS to add 'Workers Scripts Write' + 'Zone Workers Routes Write' permission groups (need to validate their CF permission-group UUIDs live against /accounts/{id}/tokens/permission_groups)")
//! @yah:next("Consider whether to keep upsert_index_rewrite as belt-and-suspenders or drop it entirely once Worker is confirmed stable")
//! @yah:verify("cargo test -p cloud --lib: 215 passed (verified)")
//! @yah:verify("cargo check --workspace: clean (verify before merge)")
//! @yah:gotcha("cloudflare-api-token must have Workers Scripts: Edit (account-scoped) + Zone Workers Routes: Edit (zone-scoped) — both now in MESOFACT_STATIC_GRANTS as 'Workers Scripts Write' + 'Workers Routes Write' with fallback IDs sourced from global CF catalog (2026-05-26)")
//! @yah:gotcha("build_worker_multipart uses a manual multipart body (reqwest multipart feature not enabled in cloud Cargo.toml) — boundary is 'yahWorkerUpload0'")
//! @yah:gotcha("Worker route pattern is '{zone}/*' not '*{zone}/*' — only catches apex requests, not subdomains. Add a wildcard route if subdomains need Worker routing")
//! @yah:gotcha("CF Workers ES module format requires 'main_module' in metadata and the part name must match that filename ('worker.js')")
//! @yah:handoff("Added Workers Scripts Write (account-scoped, fallback e086da7e...) + Workers Routes Write (zone-scoped, fallback 28f4b596...) to MESOFACT_STATIC_GRANTS. IDs sourced from the global CF permission-groups catalog (gist.github.com/f3l1x/13d3e43933e6d770aabee95410f8ee1d, validated against CF naming conventions). Test token_body_splits_scopes_and_resolves_ids extended to assert both new fallback IDs. Gotcha annotation updated: Workers grants are now in MESOFACT_STATIC_GRANTS. 215 tests pass, cargo check --workspace clean.")
//! @yah:verify("cargo test -p cloud --lib — 215 passed")
//! @yah:verify("cargo check --workspace — clean (warnings only, no errors)")
//! @yah:verify("Live E2E (user must run): yah cloud mirror up dev-yah --env prod — Worker script deployed to CF, zone route yah.dev/* → dev-yah-worker, curl https://yah.dev returns index.html served by the Worker (not the old Transform Rule)")
//!
//! @yah:ticket(R327-F1, "Extract Worker router from Rust string literal to a typechecked TS source + miniflare test")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T16:33:58Z)
//! @yah:status(review)
//! @yah:parent(R327)
//! @yah:next("render_worker_script (mesofact_static.rs:536) builds the Worker as JS interpolated inside a Rust format! — untyped, validated only by string.contains() tests. Move the router to a real .ts source, typecheck + bundle (esbuild/bun), embed the bundled output.")
//! @yah:next("Inject mode/bucket/ssr_prefixes/origin_url as a binding or generated config module rather than string interpolation, so the router source is static and unit-testable.")
//! @yah:next("Add a miniflare test asserting routing behaviour (static index-at-root, SPA index fallback, SSR proxy to origin) against real workerd, replacing the substring assertions.")
//! @yah:next("Keep the deploy hash-gate (read_worker_script_hash) working on the bundled output.")
//! @yah:gotcha("The extracted TS router reads assets via fetch(ASSET_ORIGIN + key), NOT the R2 binding (see R327-F2 decision 2026-05-26) — take ASSET_ORIGIN as config/env, drop the ASSETS binding and the writeHttpMetadata/httpEtag handling. The router becomes a generic 'route + fetch from an origin' script, not CF-coupled.")
//! @yah:gotcha("deploy_worker_script (cloudflare.rs:743) uploads a single JS main_module part; if bundling emits multiple modules, build_worker_multipart must emit each as its own multipart part.")
//! @yah:gotcha("wasm intentionally out of scope: React-based mesofact SSR is JS, so the heavy-lifting path stays JS. wasm only enters if heavy compute becomes Rust (a Rust SSR engine / image transforms), which a React mesofact never introduces.")
//! @yah:handoff("Router extracted from Rust format! string to crates/yah/cloud/worker/router.ts (TypeScript, typechecked). Bundle at router.bundle.js is embedded via include_str! as WORKER_SCRIPT const in mesofact_static.rs. Config injected via plain_text Worker bindings: ASSET_ORIGIN (read from slot_fields.asset_origin, defaults empty), WORKER_MODE (static/spa/ssr), SSR_ORIGIN, SSR_PREFIXES (JSON array). deploy_worker_script + build_worker_multipart in cloudflare.rs updated: R2 bucket binding dropped, plain_text bindings accepted instead. render_worker_script removed; replaced by worker_config_bindings(mode, asset_origin) returning Vec<(String,String)>. Hash-gate now covers script + bindings (sha256 of bundle bytes + NUL + JSON-encoded bindings). 11 miniflare tests in worker/tests/router.test.ts cover static index-at-root, 404.html fallback, plain 404 when absent, SPA fallback, known-asset passthrough, SSR prefix proxy, SSR non-prefix fallback. 220 cargo tests pass; cargo check --workspace clean.")
//! @yah:verify("cargo test -p cloud --lib — 220 passed")
//! @yah:verify("bun test tests/ in crates/yah/cloud/worker — 11 passed")
//! @yah:verify("cargo check --workspace — clean (warnings only)")
//! @yah:verify("Live E2E (user): set slot_fields.asset_origin to the R2 bucket public URL, run yah cloud mirror up dev-yah --env prod")
//!
//! @yah:ticket(R432-B2, "Stale jit ports file: don't re-probe a dead recorded port and call it a 'dynamic fallback'")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:13:39Z)
//! @yah:status(review)
//! @yah:parent(R432)
//! @yah:severity(minor)
//! @yah:next("In up_local_static, after reading read_jit_port: if the recorded port == the configured port AND the first probe already failed, skip the second probe — it's the same dead address.")
//! @yah:next("If the jit file claims a different port and that also fails to connect, treat the file as stale (don't pretend we exhaustively probed).")
//! @yah:next("Consider: should camp purge the entry on shutdown? Lower priority; the read-side fix above is enough to clear the misleading error.")
//! @yah:verify("With stale .yah/jit/mesofact-dev-ports.json (port not bound), the error no longer contains 'or any dynamic fallback port' — instead it says camp isn't running.")
//! @yah:handoff("Fixed in mesofact_static.rs::up_local_static. Lifted jit_port outside the conditional block so the error arm can inspect it. Error message now: no jit note when file absent or records same port as configured; precise 'jit file recorded port N — also not bound' note when a genuinely different port was probed and also dead. Phrase 'or any dynamic fallback port' removed in all cases. Also fixed pre-existing MirrorConfig asset_aliases missing-field compile errors across cloud/config.rs, pond.rs, cloudflare_worker.rs, mesofact_static.rs, camp.rs (all tests now compile).")
//! @yah:verify("cargo test -p cloud --lib reconciler::mesofact_static — 26 passed (includes two new R432-B2 regression tests)")
//! @yah:verify("adopt_only_stale_jit_same_port_omits_dynamic_fallback_phrase: passes")
//! @yah:verify("adopt_only_stale_jit_different_port_names_it: passes")
//!
//! @yah:ticket(R432-F3, "Split adopt_only error: distinguish 'camp not running' from 'camp running but didn't bind'")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:13:52Z)
//! @yah:status(review)
//! @yah:parent(R432)
//! @yah:next("Detect camp presence (e.g., socket path exists / camp_socket connectable) before composing the error.")
//! @yah:next("Case A — no camp: 'mesofact-dev not running for component {id}; attach this workspace in the desktop or run yah camp from a terminal.'")
//! @yah:next("Case B — camp up, no listener: 'camp is up but mesofact-dev did not bind for component {id} (configured port {port}, jit recorded {actual?}); check spawn_mesofact_dev workspace gating.'")
//! @yah:next("Drop the 'or any dynamic fallback port' phrasing — it implies a probe that didn't actually happen.")
//! @yah:verify("Both error variants surface in the desktop Up flow under the right conditions; neither mentions a probe we didn't run.")
//! @yah:depends_on(R432-B2)
//! @yah:handoff("Added camp_socket: Option<PathBuf> to LocalStaticOptions. In up_local_static adopt_only error arm: probes the socket via is_unix_socket_live helper (sync UnixStream::connect, cfg(unix) + no-op cfg(not(unix))). Case A (socket absent/unreachable) — 'mesofact-dev not running for this workspace — attach the workspace in the desktop or run yah camp from a terminal.' Case B (socket reachable, mesofact-dev not bound) — 'camp is up but mesofact-dev did not bind on port {port}{jit_note} — check spawn_mesofact_dev workspace gating or camp logs.' Desktop mirror_run.rs now passes camp_socket: Some(rpc::camp_socket_path(&workspace_root)). Updated B2 test adopt_only_stale_jit_different_port_names_it to use a live socket so jit note appears in Case-B path. 28 tests pass, desktop check clean.")
//! @yah:verify("cargo test -p cloud --lib reconciler::mesofact_static — 28 passed")
//! @yah:verify("cargo check -p desktop — clean")
//! @yah:verify("adopt_only_no_camp_socket_gives_attach_message: passes")
//! @yah:verify("adopt_only_live_camp_socket_gives_didnt_bind_message: passes")
//!
//! @yah:ticket(R434-F4, "Pond reconciler: spin ssr_runtime container when service has any mode:\"ssr\" route")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T19:12:09Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R434)
//! @arch:see(.yah/docs/working/W173-mesofact-render-cube.md)
//! @yah:next("Live smoke: declare a workload.toml [ssr_runtime] block + a mirror.toml mode=\"ssr\" route, start camp, confirm bun container + miniflare proxy work end-to-end via YAH_LOCAL_SIM_E2E pond_smoke")
//! @yah:next("R434-F5 (open) — convert one marketing route to mode:\"ssr\" — unblocked by F4; that's the first real SSR consumer")
//! @yah:next("Optional: persist read_manifest_ssr_prefixes results across pond rebuilds so a stale dist/manifest.json fall-back doesn't bite (not needed today — manifest is always fresh after a mesofact-dev rebuild)")
//! @yah:handoff("Phase A — Worker matcher + miniflare env plumbing. (1) router.ts:39 now uses segment-aware `path === p || path.startsWith(p + \"/\")`; rebuilt router.bundle.js; 4 new miniflare tests cover /api/health vs /api/healthcheck + trailing-slash boundary (16/16 pass). (2) local_driver::pond_miniflare::MiniflareSpec gained worker_mode/ssr_origin/ssr_prefixes fields; spawn_miniflare reads them from spec instead of hardcoding static. (3) cloud::reconciler::pond::spawn_miniflare_child + up_pond mirror the change; new public helpers parse_worker_mode and worker_mode_triple let camp derive the triple from mirror slot_fields. (4) camp::build_miniflare_deploy_spec calls parse_worker_mode → worker_mode_triple so flipping a mirror.toml to mode=ssr now works end-to-end.")
//! @yah:handoff("Phase B — SSR runtime container slot in yubaba. (1) New local_driver::pond_ssr_runtime module with SsrRuntimeSpec, ensure_ssr_runtime_running, SsrRuntimeRunning, and lower_workload_spec(ws, host_port, name, label, timeout) → SsrRuntimeSpec. Lowering pulls image (with digest preference), command, literal env vars (FromSecret/FromMesh rejected with clear errors), Bind volumes, and expose.mesh.ports[0] as container_port (default 3000). 8/8 unit tests pass. (2) New yubaba::pond::ssr_runtime module with SsrRuntimeReconciler (probe + restart) and SsrRuntimeSupervision, mirroring MinioReconciler. (3) yubaba::pond::PondDeployReq gained ssr_runtime: Option<SsrRuntimeSpec>. The deploy handler brings SSR up BETWEEN MinIO and miniflare, overriding effective_miniflare.ssr_origin to point at the bound container so miniflare proxies correctly. RegistryEntry tracks ssr_runtime supervision alongside minio + miniflare; shutdown_all + mark_failed drain it.")
//! @yah:handoff("Phase C — manifest-derived SSR_PREFIXES + camp wiring. (1) camp::build_ssr_runtime_deploy_spec reads <workload_dir>/workload.toml's MesofactStaticWorkload.ssr_runtime: Option<WorkloadSpec> and lowers it. Host port comes from static_fields.ssr_port (default 4324); collision with miniflare's port is rejected up-front. (2) camp::read_manifest_ssr_prefixes reads <workload_dir>/dist/manifest.json's top-level ssr_prefixes (R015-F2 contract). When present + non-empty, overrides miniflare's spec.ssr_prefixes (mirror.toml override path stays as fallback). (3) Camp's deploy loop now: builds miniflare → builds optional ssr_runtime → overrides miniflare.worker_mode=ssr + ssr_origin when runtime is present → overrides ssr_prefixes from manifest when available → POSTs full req. 9 new camp::r434_f4_ssr_pond_tests pass.")
//! @yah:handoff("Verify lines satisfied: (a) Worker test /api/health vs /api/healthcheck DIRECTLY covered by tests/router.test.ts segment-aware matcher tests. (b) Pure static/spa pond mirrors still reconcile without spinning ssr_runtime — covered by build_ssr_runtime_deploy_spec_returns_none_without_ssr_runtime_field + existing 25 cloud reconciler::pond tests stay green. (c) End-to-end 'spins bun container and miniflare proxies prefix' is wired and unit-tested at the spec-build/registry layer; live smoke requires an actual workload with ssr_runtime declared + docker available (pond_smoke or YAH_LOCAL_SIM_E2E run). 5 pre-existing mesofact_static test flakes ignored — caused by a real desktop process on 127.0.0.1:4321 on the dev box, not by F4.")
//! @yah:verify("cd crates/yah/cloud/worker && bun test tests/ → 16 pass (4 new R434-F4 segment-aware tests)")
//! @yah:verify("cargo test -p local-driver --lib → 46 pass (8 new pond_ssr_runtime tests)")
//! @yah:verify("cargo test -p yubaba --lib pond → 9 pass (registry handles ssr_runtime supervision)")
//! @yah:verify("cargo test -p cloud --lib -- reconciler::pond:: reconciler::mesofact_static::tests::config_bindings reconciler::mesofact_static::tests::parse_worker_mode reconciler::mesofact_static::tests::worker_script → 21 pass")
//! @yah:verify("cargo test -p yah --lib r434_f4_ssr_pond_tests → 9 pass (camp helpers: workload.toml subtree read, manifest ssr_prefixes read, build_ssr_runtime_deploy_spec)")
//! @yah:verify("cargo check -p local-driver -p yubaba -p cloud -p yah → clean (warnings only, none from F4)")
//! @yah:verify("Live smoke (user): workload.toml with [ssr_runtime] block + mirror.toml with providers.static.mode=\"ssr\" → yah camp → desktop adopts pond and the SSR prefix routes to the bun container")
//!
//! @yah:ticket(R438-T6, "W165 wiring: lower MesofactStaticWorkload.build_mode to ForgeCommand")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T21:07:20Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R438)
//! @yah:next("Replace run_build_command shell-out with run_build(workload_dir, &BuildConfig, &BuildMode)")
//! @yah:next("Lower BuildMode::HostSide → ForgeSpec{Subprocess, TaskRuntime::Native}; InContainer{image} → {Subprocess(image), TaskRuntime::Container}")
//! @yah:next("Hand ForgeSpec to task::local::execute — same path QED uses for image-build steps")
//! @yah:next("TaskLocation::Local; cwd = workload_dir bind-mounted into container")
//! @yah:verify("BuildMode::HostSide lowers to TaskRuntime::Native; InContainer{image} lowers to TaskRuntime::Container with pinned digest")
//! @yah:verify("In-tree workload with build_mode=in_container runs build in configured image; host_side runs on host; identical out_dir bytes")
//! @yah:gotcha("local-static arm behavior decision deferred to F1 (W165 OQ#1) — default-skip with warning is the proposed initial behavior")
//! @arch:see(.yah/docs/working/W165-mesofact-build-mode-lowering.md)
//! @yah:depends_on(R438-T3)
//! @yah:handoff("T6 landed. (1) MesofactStaticReconciler gains executor: Arc<dyn ForgeExecutor> field + with_executor() setter; default Arc::new(LocalForgeDriver::default()) — mirrors T15's static_asset pattern. (2) rebuild_static now reads (BuildConfig, BuildMode) from workload.toml via new read_mesofact_build helper and hands them to run_build, which lowers to ForgeSpec{Subprocess{sh -c <cmd>, image?}, TaskPlacement{Local, runtime}} and dispatches through ForgeExecutor::execute. BuildMode::HostSide → image=None + TaskRuntime::Native; InContainer{image} → Some(image) + TaskRuntime::Container. ExecContext::default().with_cwd(workload_dir). (3) Old shell-out (sh -c with tokio::process::Command) deleted. (4) Critical: read_mesofact_build uses raw toml::Value subtree extraction (kind→build→build_mode), NOT the full workload_spec::Workload envelope — production marketing/dashboard workload.tomls carry schema_version = 1 (integer) which the typed envelope rejects; the subtree reader stays tolerant of that legacy shape while still typed-deserializing the build/build_mode subtrees to BuildConfig/BuildMode. ImageRef digest-pin enforcement inherits automatically via T3 (rejects bare-tag at deserialize). (5) 7 new tests under reconciler::mesofact_static::tests: read_mesofact_build_extracts_host_side_default, _extracts_in_container_with_digest, _rejects_in_container_without_digest, _returns_none_for_other_kinds, _returns_none_when_file_absent, rebuild_static_lifts_build_mode_through_executor (e2e: workload.toml→executor with digest round-trip), rebuild_static_defaults_to_host_side_when_build_mode_omitted, rebuild_static_skips_build_when_workload_toml_missing, plus run_build_host_side_lowers_to_native_subprocess, _in_container_lowers_to_container_runtime_with_pinned_digest, _surfaces_stderr_on_nonzero_exit (CaptureExecutor + FailingExecutor mocks). cargo test -p cloud --lib: 293 pass; 5 pre-existing failures (4 adopt_only port-4321 dev-box collision + 1 cloud_init drift — R441-B4 umbrella, unrelated). cargo check --workspace clean.")
//! @yah:next("Sign off → archive R438-T6")
//! @yah:next("R438-F9 (local-static arm: respect or skip container build_mode) is now unblocked — picker can decide default-skip vs honor for the local arm")
//! @yah:next("R438-T8 (worked examples) can now add a mesofact-static workload with build_mode=in_container as an e2e fixture")
//! @yah:verify("cargo test -p cloud --lib reconciler::mesofact_static — 35 pass; 4 R441-B4 adopt_only failures pre-existing")
//! @yah:verify("cargo check --workspace --locked — clean (warnings only)")
//! @yah:verify("BuildMode::HostSide → TaskRuntime::Native, image=None; InContainer{image} → TaskRuntime::Container, Some(pinned_image) (asserted by run_build_*_lowers_to_* tests)")
//! @yah:verify("Legacy schema_version = 1 (integer) workload.tomls still parse — read_mesofact_build uses raw toml::Value subtree extraction")
//! @yah:gotcha("read_mesofact_build uses raw toml::Value subtree extraction rather than the workload_spec::Workload envelope — production marketing/dashboard workload.tomls carry schema_version = 1 (integer) which the typed envelope rejects (SchemaVersion is enum V1, expects \"V1\" string). Until the workspace-wide schema_version migration ships, T4-style envelope parsing is unsafe in this path. If/when that migration lands, swap read_mesofact_build for a full envelope load.")
//! @yah:gotcha("rebuild_static is only called from almanac_dispatch (OnChange::MesofactRebuild) — local-static arm bring-up via up() does NOT run the build step (the host watcher handles rebuilds). That gates W165 OQ#1 (R438-F9): the local arm question is purely about whether OnChange feeds should honor container build_mode locally.")
//!
//! @yah:ticket(R438-F9, "local-static arm: respect or skip container build_mode? (W165 OQ#1)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T21:07:57Z)
//! @yah:status(review)
//! @yah:parent(R438)
//! @yah:next("Decide: container build for CI parity vs default-skip (no docker dependency for dev)")
//! @yah:next("Default-skip with one-line warning is the proposed initial behavior")
//! @yah:next("If skip: ensure log line is visible in dashboard/task-pane (per long-running→yah surface rule)")
//! @arch:see(.yah/docs/working/W165-mesofact-build-mode-lowering.md)
//! @yah:depends_on(R438-T6)
//! @yah:handoff("F9 landed. Decision: local-static arm + InContainer build_mode → warn + fall back to HostSide (W165 OQ#1). Implementation: rebuild_static gains a 3-line pattern-guard before calling run_build; if slot is local-static and build_mode is InContainer, emit warn!(\"build_mode = in_container ignored for local-static; running host-side\") and override to BuildMode::HostSide. No new fields, no new types. Two test changes: (1) rebuild_static_lifts_build_mode_through_executor switched from local_static_slot(0) to cloudflare_reference_slot() — it now covers the CF publish arm (still asserts TaskRuntime::Container); (2) new rebuild_static_local_static_in_container_falls_back_to_host_side asserts TaskRuntime::Native + image=None when slot=local-static + build_mode=InContainer. cargo test -p cloud --lib reconciler::mesofact_static: 37 pass; 4 pre-existing R441-B4 adopt_only failures. cargo check -p cloud: clean.")
//! @yah:verify("cargo test -p cloud --lib reconciler::mesofact_static::tests::rebuild_static_local_static_in_container_falls_back_to_host_side -- passes (TaskRuntime::Native, image=None)")
//! @yah:verify("cargo test -p cloud --lib reconciler::mesofact_static::tests::rebuild_static_lifts_build_mode_through_executor -- passes (CF arm still uses TaskRuntime::Container)")
//! @yah:verify("cargo check -p cloud -- clean")
//!
//! @yah:relay(R441, "Workspace test breakage on main (surfaced via R438-T3 sweep)")
//! @yah:at(2026-06-04T22:55:58Z)
//! @yah:status(open)
//! @yah:next("4 independent pre-existing test failures on main, all caught while running `cargo test --workspace` during R438-T3 ImageRef tightening. Each surfaces test signal that's been silently broken; pick up the child tickets and route them to the right owner per area.")
//! @yah:gotcha("These aren't ImageRef-related and didn't break during R438-T3 — they were broken on main before that work started. The umbrella is a discovery channel, not a regression.")
//! @arch:see(.yah/docs/working/W164-derived-static-assets.md)
//!
//! @yah:ticket(R441-B4, "mesofact_static adopt_only_* tests expect Err but get Ok(RunningWorkload)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T22:56:20Z)
//! @yah:status(review)
//! @yah:parent(R441)
//! @yah:next("Four tests panic at mesofact_static.rs:1188 with `called Result::unwrap_err() on an Ok value: RunningWorkload {...}`: adopt_only_no_camp_socket_gives_attach_message, adopt_only_live_camp_socket_gives_didnt_bind_message, adopt_only_stale_jit_same_port_omits_dynamic_fallback_phrase, adopt_only_stale_jit_different_port_names_it.")
//! @yah:next("Reconciler changed: adopt-only paths now succeed (return RunningWorkload) where they used to error with operator-facing messages. This is a real behavior question, not a mechanical fix — either revert the reconciler change or update the four tests to assert on the new Ok-shape contract (likely the latter; check the most recent reconciler commit for intent).")
//! @yah:next("Coordinate with whoever last touched the mesofact-static reconciler before flipping the assertions.")
//! @yah:verify("cargo test -p cloud --lib reconciler::mesofact_static::tests::adopt_only_  # all 4 pass")
//! @yah:handoff("Root cause: all four tests used hardcoded port 4321 which a running camp's mesofact-dev occupies, causing up_local_static to adopt it as Ok instead of reaching the adopt_only error path. Fix: added pick_unused_port() helper (bind :0, read port, drop listener) and replaced local_static_slot(4321) with pick_unused_port() in all four tests. stale_jit_different_port_names_it also replaced hardcoded 9999 with a second pick_unused_port() so the assertion checks the dynamic value. All 4 pass.")
//!
//! R535-T1 ("Split rebuild_static: revalidate-only path... called by
//! almanac_dispatch", W225 §3) landed here: see [`MesofactStaticReconciler::
//! revalidate_static`] and [`MesofactStaticReconciler::rebuild_static`]'s docs
//! for the split, and `crate::almanac_dispatch` for the caller-side switch.
//! Ticket record lives in `.yah/docs/working/W225-mesofact-consumer-deployment-model.md`
//! (single declaration site — not duplicated here per Rule11).

/// Bundled Worker script embedded at compile time from `worker/router.bundle.js`.
///
/// The source of truth is `@mesofact/edge`
/// (`oss/mesofact/packages/mesofact-edge`) — the manifest-driven serving
/// artifact mesofact owns (W270 §3, R595-F3). Its built bundle is *vendored*
/// into `worker/router.bundle.js` by `scripts/check-worker-bundle.sh` so this
/// crate stays standalone-exportable across the OSS mirror boundary (a
/// cross-boundary `include_str!` into `oss/mesofact` would break yubaba's
/// export). Run `scripts/check-worker-bundle.sh --update` after editing the
/// worker; do NOT hand-edit `router.bundle.js`.
///
/// Used both for prod deployment and as the miniflare-sim artifact in the pond
/// tier.
pub const WORKER_SCRIPT: &str = include_str!("../../worker/router.bundle.js");

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::oneshot;
use tracing::{info, warn};

use kamaji::native::NativeRuntime;
use kamaji::{Kamaji, MeshAssignment, MeshIdent};
use velveteen::{
    ForgeCommand, ForgeSpec, Initiator, MeshAccess, TaskLocation, TaskPlacement, TaskRuntime,
};
use velveteen_exec::{ExecContext, ForgeExecutor, LocalForgeDriver};
use workload_spec::{
    BuildConfig, BuildMode, EnvVar, ExposeSpec, ImageRef, MeshExpose, Millis, NamespaceId,
    ResourceLimits, RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, WorkloadSpec,
};

use super::{
    into_running, pond, slot_field_u16, wait_for_port, LogBuffer, ReconcileCtx, Reconciler,
    RunningWorkload,
};
use crate::{MirrorProviderSlot, Provider};

/// Native workloads are a fork+exec of an already-present host binary — the
/// kamaji Native backend treats `ImageRef` as identity metadata only and
/// never pulls. The schema still demands a valid-format digest, so native
/// specs stamp a fixed all-zeros marker: impossible for any real image, so a
/// leak into a registry-pull path surfaces obviously. (Mirrors
/// `workload_spec::testing::TEST_DIGEST` without reaching into a test-only
/// helper from production code.)
const NATIVE_IDENTITY_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Workload kind this reconciler handles. Matches `ServiceComponent.kind`
/// and the `kind = "..."` line in `workload.toml`.
pub const WORKLOAD_KIND: &str = "mesofact-static";

/// SPA sibling of [`WORKLOAD_KIND`]: mesofact emits a hydrate-bundle-loading
/// HTML shell instead of a fully-rendered page per route. The serving path is
/// identical (assets in a bucket behind the Worker/miniflare router); the only
/// behavioral difference is the Worker's fallback mode, so the same reconciler
/// handles both kinds.
pub const WORKLOAD_KIND_SPA: &str = "mesofact-spa";

/// True for the component kinds served by [`MesofactStaticReconciler`].
pub fn is_mesofact_site_kind(kind: &str) -> bool {
    kind == WORKLOAD_KIND || kind == WORKLOAD_KIND_SPA
}

/// Default port for the `local-static` provider slot — matches
/// `mesofact-dev`'s `DEFAULT_PORT` and the canonical
/// `.yah/services/dev-yah/mirrors/local.toml`.
pub const DEFAULT_LOCAL_STATIC_PORT: u16 = 4321;

/// Knobs for the `local-static` bring-up path.
#[derive(Debug, Clone, Default)]
pub struct LocalStaticOptions {
    /// Explicit path to the `mesofact-dev` binary. Overrides the env-var
    /// and PATH lookup.
    pub binary: Option<PathBuf>,
    /// Extra args to pass after the workload directory (e.g. `--no-watch`).
    pub extra_args: Vec<String>,
    /// How long to wait for the spawned process's port to start accepting
    /// connections before declaring the up failed. Default: 10s.
    pub ready_timeout: Option<Duration>,
    /// When `true`, adopt an already-running server (TCP probe + jit file)
    /// but never fall through to spawning a subprocess. Desktop sets this
    /// because the server is embedded in yah-camp; there is no separate
    /// binary to spawn.
    pub adopt_only: bool,
    /// Unix socket path of the camp daemon for this workspace. When set and
    /// `adopt_only` is true, the error message distinguishes "camp not
    /// running" (socket unreachable) from "camp up but server didn't bind"
    /// (socket reachable, mesofact-dev port not bound).
    pub camp_socket: Option<PathBuf>,
}

impl LocalStaticOptions {
    /// Resolve the binary path: explicit > `MESOFACT_DEV_BIN` env > bare
    /// `mesofact-dev` (will be looked up on `PATH` at spawn time).
    pub fn resolved_binary(&self) -> PathBuf {
        if let Some(ref p) = self.binary {
            return p.clone();
        }
        if let Some(p) = std::env::var_os("MESOFACT_DEV_BIN") {
            return PathBuf::from(p);
        }
        PathBuf::from("mesofact-dev")
    }
}

/// Reconciles `kind = "mesofact-static"` components.
///
/// The `executor` field handles the build step (W165): `build.command` is
/// lowered to a [`ForgeSpec`] and dispatched through
/// [`ForgeExecutor::execute`]. Default is [`LocalForgeDriver`]; callers
/// wanting to redirect (e.g. tests with a mock executor) use
/// [`Self::with_executor`].
pub struct MesofactStaticReconciler {
    pub local_static: LocalStaticOptions,
    pub pond: pond::PondOptions,
    executor: Arc<dyn ForgeExecutor>,
}

impl MesofactStaticReconciler {
    pub fn new() -> Self {
        Self {
            local_static: LocalStaticOptions::default(),
            pond: pond::PondOptions::default(),
            executor: Arc::new(LocalForgeDriver::default()),
        }
    }

    pub fn with_local_static(mut self, opts: LocalStaticOptions) -> Self {
        self.local_static = opts;
        self
    }

    pub fn with_pond(mut self, opts: pond::PondOptions) -> Self {
        self.pond = opts;
        self
    }

    /// Swap the [`ForgeExecutor`] used to run the build step. Production
    /// callers take the [`LocalForgeDriver`] default; tests inject a mock
    /// to assert the lowered [`ForgeSpec`] without spawning a subprocess.
    pub fn with_executor(mut self, executor: Arc<dyn ForgeExecutor>) -> Self {
        self.executor = executor;
        self
    }
}

impl Default for MesofactStaticReconciler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Reconciler for MesofactStaticReconciler {
    fn kind(&self) -> &'static str {
        WORKLOAD_KIND
    }

    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        // BYO git (R561-F1): if the component is git-sourced, shallow-clone it
        // into the source cache before anything reads workload_dir(). No-op for
        // in-tree components.
        ctx.materialize().await?;

        // Validate that the workload manifest agrees with the component's
        // declared kind. Mismatch is an authoring error (service.toml
        // points at a workload of the wrong shape).
        let kind = ctx.workload_kind().context("loading workload.toml")?;
        if kind != ctx.component.kind {
            anyhow::bail!(
                "component {component_id} kind=\"{component_kind}\" but {workload_dir}/workload.toml declares kind=\"{kind}\"",
                component_id = ctx.component.id,
                component_kind = ctx.component.kind,
                workload_dir = ctx.workload_dir().display(),
            );
        }

        let slot = ctx.slot("static").with_context(|| {
            format!(
                "mirror has no `providers.static` slot — required for kind=\"mesofact-static\" (service={}, env={})",
                ctx.service.name, ctx.env,
            )
        })?;

        match slot {
            MirrorProviderSlot::Inline {
                kind: Provider::LocalStatic,
                fields,
            } => {
                let port = slot_field_u16(fields, "port").unwrap_or(DEFAULT_LOCAL_STATIC_PORT);
                self.up_local_static(&ctx, port).await
            }
            MirrorProviderSlot::Inline {
                kind: Provider::MiniflareContainer,
                fields,
            } => pond::up_pond(&ctx, &self.pond, fields, WORKER_SCRIPT).await,
            MirrorProviderSlot::Inline { kind, .. } => {
                anyhow::bail!(
                    "providers.static.kind = \"{kind:?}\" not supported by mesofact-static reconciler (only local-static + miniflare-container for now)",
                )
            }
            MirrorProviderSlot::Reference {
                provider_id,
                fields,
            } => {
                // Dispatch on the resolved provider *kind*, not the literal
                // name, so a workspace can name several cloudflare providers
                // (e.g. `cloudflare` + `cloudflare-scrabcake`).
                let cf = super::cf_creds::CfProvider::resolve_scoped(
                    ctx.workspace_root,
                    provider_id,
                    &ctx.scope.tenant,
                    &ctx.scope.namespace,
                )?;
                anyhow::ensure!(
                    matches!(cf.cfg.kind, Provider::Cloudflare),
                    "providers.static.use = {provider_id:?} (kind={:?}) — only cloudflare-kind \
                     reference providers are supported for mesofact-static",
                    cf.cfg.kind,
                );
                self.up_cloudflare_r2(&ctx, cf, fields).await
            }
        }
    }
}

impl MesofactStaticReconciler {
    /// Re-sync a *running* mirror in place — re-publish the built dist without
    /// rebuilding or restarting the serve stack. Only the pond
    /// (miniflare-container) slot supports this: it re-publishes `dist/` into
    /// the already-running MinIO bucket via [`pond::sync_pond`], returning the
    /// number of assets uploaded.
    ///
    /// This is what the desktop's `⟳` affordance calls for local mirrors.
    /// `up`'s desktop adopt path returns before the publish step, so a re-click
    /// of `▶` never re-publishes; `sync` is the correct re-sync entry point.
    /// local-static (dev) serves from disk and cloudflare goes through the
    /// publish-assets pipeline, so neither has an in-place bucket re-sync.
    pub async fn sync(&self, ctx: ReconcileCtx<'_>) -> Result<usize> {
        ctx.materialize().await?;
        let slot = ctx.slot("static").with_context(|| {
            format!(
                "mirror has no `providers.static` slot — required for kind=\"mesofact-static\" (service={}, env={})",
                ctx.service.name, ctx.env,
            )
        })?;
        match slot {
            MirrorProviderSlot::Inline {
                kind: Provider::MiniflareContainer,
                fields,
            } => pond::sync_pond(&ctx, &self.pond, fields).await,
            MirrorProviderSlot::Inline { kind, .. } => anyhow::bail!(
                "providers.static.kind = \"{kind:?}\" has no in-place re-sync — only miniflare-container (pond) supports ⟳ sync",
            ),
            MirrorProviderSlot::Reference { .. } => anyhow::bail!(
                "reference (cloud) providers re-sync through the publish-assets pipeline, not the pond reconciler",
            ),
        }
    }

    /// Build the workload (re-running `build.command`) then publish it to its
    /// configured provider slot.
    ///
    /// This is the **full rebuild** path — source/template changes, a fresh
    /// `mirror up`, or any case where the compiled bundle itself may be
    /// stale. It is *not* what `almanac_dispatch` calls for a data-only feed
    /// change — see [`Self::revalidate_static`] for that (W225 §3: a data
    /// change is "revalidate", not "build", and never needs the bundler).
    ///
    /// For the Cloudflare reference arm this publishes the freshly-built
    /// `dist/` to R2 and purges the CDN cache-tag `page:releases`. For the
    /// `local-static` arm the build still runs (useful for verifying the
    /// output) but no publish happens — the watcher handles hot-reload.
    pub async fn rebuild_static(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        let workload_dir = ctx.workload_dir();
        if let Some((build, build_mode)) = read_mesofact_build(&workload_dir)? {
            // For the local-static arm, container build_mode is skipped — the host
            // watcher drives rebuilds and dev machines may not have docker (W165 OQ#1).
            let effective_mode = match &build_mode {
                BuildMode::InContainer { .. }
                    if ctx.slot("static").and_then(|s| s.inline_kind())
                        == Some(Provider::LocalStatic) =>
                {
                    warn!(
                        workload = %workload_dir.display(),
                        "build_mode = in_container ignored for local-static; running host-side"
                    );
                    BuildMode::HostSide
                }
                _ => build_mode,
            };
            run_build(&workload_dir, &build, &effective_mode, &*self.executor).await?;
        }
        self.up(ctx).await
    }

    /// Publish the workload's **already-built** artifact directory — never
    /// runs `build.command` (W225 §3, R535-T1).
    ///
    /// This is the path `almanac_dispatch` calls for
    /// `OnChangeConfig::MesofactRebuild`: an almanac feed change is *data*,
    /// not a source/template change, so re-running the bundler is wasted
    /// work (and, for CI-gated `in_container` builds, wasted pull/cold-start
    /// too). Per the doc: "almanac = revalidate = data → SSG output on the
    /// already-built bundle... no recompilation, no CI gate, because nothing
    /// executable changed."
    ///
    /// When the workload declares `build.render_command` (R535-T7), the
    /// data-only re-render runs first — `{route}` substituted with the
    /// invalidated route pattern, executed against the **already-built**
    /// bundle via the same [`ForgeExecutor`] lowering as the build step
    /// (host-side or in-container per `build_mode`), but never
    /// `build.command` itself. The canonical command is `mesofact-build
    /// render <dir> --route {route} --all`, which re-expands the route's
    /// prerender params fresh and rewrites `out_dir`'s HTML for that route
    /// only. Without `render_command` this republishes whatever bytes sit in
    /// `build.out_dir` (the pre-T7 behavior, still correct when the bundle's
    /// HTML was refreshed by some other actor).
    ///
    /// The `local-static` arm skips the render entirely — the host
    /// `mesofact-dev` watcher already re-renders on data-file changes
    /// independently of this reconciler (see the `rebuild_static` doc on the
    /// pre-existing "local watcher handles rebuilds" behavior it inherits).
    pub async fn revalidate_static(
        &self,
        ctx: ReconcileCtx<'_>,
        route: &str,
    ) -> Result<RunningWorkload> {
        let workload_dir = ctx.workload_dir();
        let is_local_static =
            ctx.slot("static").and_then(|s| s.inline_kind()) == Some(Provider::LocalStatic);
        if !is_local_static {
            if let Some((build, build_mode)) = read_mesofact_build(&workload_dir)? {
                if let Some(render_command) = &build.render_command {
                    let render = BuildConfig {
                        command: render_command.replace("{route}", route),
                        out_dir: build.out_dir.clone(),
                        render_command: None,
                    };
                    run_build(&workload_dir, &render, &build_mode, &*self.executor).await?;
                }
            }
        }
        self.up(ctx).await
    }

    async fn up_local_static(&self, ctx: &ReconcileCtx<'_>, port: u16) -> Result<RunningWorkload> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let svc = &ctx.service.name;
        let comp = &ctx.component.id;

        // If a mesofact-dev server is already running on the configured port
        // (e.g. a prior `mirror up` in this session), adopt it rather than
        // spawning a second instance — keeps re-runs idempotent. But adopt ONLY
        // when it identifies as THIS (service, component): a bare port probe is
        // identity-blind, so a different service's dev server (or a foreign
        // process) on a colliding host port would be silently hijacked and
        // serve the wrong site (R602-B4). `/__mesofact/info` is the oracle;
        // identity mismatch is a hard error, not a fall-through to spawn (the
        // port is taken — there is nothing safe to do but surface it).
        if let Some(adopted) = try_adopt_identified(addr, svc, comp, "configured").await? {
            return Ok(adopted);
        }

        // Camp may have fallen back to a dynamic port (OS-assigned when configured
        // port was taken). Check the jit ports file it writes after binding.
        let jit_port = read_jit_port(ctx.workspace_root, &ctx.service.name, &ctx.component.id);
        if let Some(actual_port) = jit_port {
            if actual_port != port {
                let actual_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), actual_port);
                if let Some(adopted) = try_adopt_identified(actual_addr, svc, comp, "dynamic").await? {
                    return Ok(adopted);
                }
            }
        }

        if self.local_static.adopt_only {
            let jit_note = jit_port
                .filter(|&p| p != port)
                .map(|p| format!(" (jit file recorded port {p} — also not bound)"))
                .unwrap_or_default();

            // Distinguish "camp not attached" from "camp up but server didn't bind"
            // so the operator gets an actionable message.
            let camp_live = self
                .local_static
                .camp_socket
                .as_deref()
                .map(is_unix_socket_live)
                .unwrap_or(false);

            if camp_live {
                anyhow::bail!(
                    "component {}: a yah daemon is up but mesofact-dev did not bind on port {}{} \
                     — check that the mesofact-dev workload reconciled, or inspect its logs",
                    ctx.component.id,
                    port,
                    jit_note,
                );
            } else {
                anyhow::bail!(
                    "component {}: mesofact-dev not running for this workspace \
                     — attach the workspace in the desktop or run `yah camp` from a terminal",
                    ctx.component.id,
                );
            }
        }

        let binary = self.local_static.resolved_binary();
        let workload_dir = ctx.workload_dir();

        // Prefer the configured port; fall back to OS-assigned when it's taken.
        // Web entrypoints are browser handles — the port number itself doesn't
        // matter to the operator, so floating to any free port is fine.
        let spawn_port = {
            let preferred = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
            );
            match std::net::TcpListener::bind(preferred) {
                Ok(_probe) => {
                    // Probe succeeded: preferred port is free. Drop the probe
                    // so the child can bind it. Tiny race window; fine for dev.
                    port
                }
                Err(_) => {
                    let fallback = std::net::TcpListener::bind("127.0.0.1:0")
                        .context("could not bind any port for mesofact-dev")?;
                    let p = fallback.local_addr()?.port();
                    if port != 0 {
                        info!(
                            preferred = port,
                            actual = p,
                            "preferred port taken; mesofact-dev will use OS-assigned port"
                        );
                    }
                    p
                }
            }
        };

        // R490-F2: spawn mesofact-dev through kamaji's Native (fork+exec)
        // backend rather than a bespoke Command::spawn. NativeRuntime owns the
        // fork+exec, stdio capture, and SIGTERM→grace→SIGKILL teardown; the
        // reconciler keeps only the WorkloadSpec lowering, the readiness probe,
        // and a file-tail→LogBuffer bridge that preserves the Run-tab's live
        // log surface (NativeRuntime captures stdio to files, not a pipe).
        self.spawn_via_constable(ctx, &binary, &workload_dir, spawn_port)
            .await
    }

    /// Lower the mesofact-dev invocation to a [`WorkloadSpec`], deploy it on a
    /// per-bring-up [`NativeRuntime`], wait for the port, and wrap the result
    /// in a [`RunningWorkload`] whose shutdown tears the workload back down.
    async fn spawn_via_constable(
        &self,
        ctx: &ReconcileCtx<'_>,
        binary: &Path,
        workload_dir: &Path,
        spawn_port: u16,
    ) -> Result<RunningWorkload> {
        // NativeRuntime captures stdout/stderr under <state_dir>/<ident>/.
        // Scope it per-workspace so concurrent camps don't collide.
        let state_dir = ctx.workspace_root.join(".yah/jit/native");
        let ident_str = native_ident(&ctx.service.name, &ctx.component.id);
        let ident = MeshIdent(ident_str.clone());

        let mut argv: Vec<String> = vec![
            binary.display().to_string(),
            workload_dir.display().to_string(),
            "--port".to_string(),
            spawn_port.to_string(),
            // Stamp logical identity so the child answers /__mesofact/info and a
            // later adopt re-run can confirm the port holds *this* server rather
            // than a colliding foreign listener (R602-B4).
            "--service".to_string(),
            ctx.service.name.clone(),
            "--component".to_string(),
            ctx.component.id.clone(),
        ];
        argv.extend(self.local_static.extra_args.iter().cloned());
        let spec = native_mesofact_spec(&ident_str, argv);

        let runtime = Arc::new(NativeRuntime::new(&state_dir));
        let mesh = MeshAssignment::inlined(Ipv4Addr::LOCALHOST);

        info!(
            binary = %binary.display(),
            workload = %workload_dir.display(),
            port = spawn_port,
            ident = %ident_str,
            "spawning mesofact-dev (kamaji native backend)",
        );

        let deployed = runtime
            .deploy_workload(&spec, &mesh)
            .await
            .with_context(|| {
                format!(
                    "deploying mesofact-dev via kamaji native backend \
                     — install with `cargo install --path oss/mesofact/crates/mesofact-dev` \
                     or ensure the bundled sidecar is on the path ({})",
                    binary.display(),
                )
            })?;

        // Mirror NativeRuntime's capture layout (documented in native.rs).
        let workload_log_dir = state_dir.join(&ident_str);
        let stdout_path = workload_log_dir.join("stdout.log");
        let stderr_path = workload_log_dir.join("stderr.log");

        // Wait for the server to bind. If it doesn't, tear it down and return
        // an error so the caller doesn't hand the UI a dead URL.
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), spawn_port);
        let timeout = self
            .local_static
            .ready_timeout
            .unwrap_or(Duration::from_secs(10));
        if !wait_for_port(addr, timeout).await {
            warn!(addr = %addr, "mesofact-dev did not bind within timeout; tearing down");
            runtime.teardown_workload(&ident).await.ok();
            anyhow::bail!("mesofact-dev failed to bind {addr} within {:?}", timeout);
        }

        let dev_url = format!("http://{addr}");
        info!(dev_url = %dev_url, port = spawn_port, pid = deployed.task_pid, "mesofact-dev ready");

        // Bridge NativeRuntime's file capture into the Run-tab LogBuffer and
        // own teardown on shutdown.
        let log_buf = LogBuffer::new();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let supervisor = spawn_native_log_supervisor(
            runtime,
            ident,
            log_buf.clone(),
            stdout_path,
            stderr_path,
            shutdown_rx,
        );

        Ok(into_running(
            "mesofact-static",
            "static",
            Some(dev_url),
            None,
            Some(log_buf),
            shutdown_tx,
            supervisor,
        ))
    }

    /// Cloudflare R2 publish path: upload `dist/` to R2, optionally purge CDN
    /// cache tags, and return a `RunningWorkload` with `public_url` set.
    async fn up_cloudflare_r2(
        &self,
        ctx: &ReconcileCtx<'_>,
        cf_provider: super::cf_creds::CfProvider,
        slot_fields: &std::collections::BTreeMap<String, toml::Value>,
    ) -> Result<RunningWorkload> {
        use super::r2_publish::{publish_to_r2, R2PurgeOpts};
        use crate::provider::cloudflare::{CloudflareClient, WorkerBinding};

        // account_id + credentials come from the resolved provider.
        let account_id = cf_provider.account_id.clone();

        // Extract bucket + zone from the mirror's static slot.
        let bucket = slot_fields
            .get("bucket")
            .and_then(|v| v.as_str())
            .context("providers.static missing `bucket` field for cloudflare R2 publish")?
            .to_string();
        let zone = slot_fields
            .get("zone")
            .and_then(|v| v.as_str())
            .context("providers.static missing `zone` field for cloudflare R2 publish")?
            .to_string();

        // asset_origin is the public HTTP URL the Worker fetches assets from.
        // publish_to_r2 lays files down under `<svc>/<env>/<key>`, so this URL
        // must include the same prefix. Validate up front — without it the
        // Worker would 404 every request in prod.
        let asset_origin =
            slot_fields
                .get("asset_origin")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .with_context(|| {
                    format!(
                "providers.static.asset_origin missing or empty (service={svc}, env={env}) — \
                 set it to the R2 public URL with the publish prefix, e.g. \
                 \"https://cdn.{zone}/{svc}/{env}\"",
                svc = ctx.service.name, env = ctx.env, zone = zone,
            )
                })?
                .to_string();

        // R2 S3 access keys (distinct from the management API token).
        let (access_key, secret_key) = cf_provider.r2_keys()?;

        // Management API token — used for cache-tag purge and Transform Rules.
        // Optional: publish itself only needs the R2 S3 keys.
        let cf_api_token: Option<String> = cf_provider.api_token_opt();
        let purge = cf_api_token.clone().map(|token| R2PurgeOpts {
            zone_name: zone.clone(),
            api_token: token,
        });

        // Resolve dist dir from workload.toml build.out_dir (default: "dist").
        let workload_dir = ctx.workload_dir();
        let out_dir = read_workload_out_dir(&workload_dir).unwrap_or_else(|| "dist".to_string());
        let dist_dir = workload_dir.join(&out_dir);

        let mirror_prefix = format!("{}/{}", ctx.service.name, ctx.env);
        let report = publish_to_r2(
            &dist_dir,
            &account_id,
            &bucket,
            &access_key,
            &secret_key,
            Some(&mirror_prefix),
            purge,
        )
        .await
        .with_context(|| format!("publishing to R2 bucket {bucket:?} (account {account_id})"))?;

        info!(
            uploaded = report.uploaded.len(),
            purged = report.purged_tags.len(),
            bucket,
            zone,
            "R2 publish complete",
        );

        // Deploy CF Worker script (replaces the Transform Rule workaround).
        // Worker serves assets via ASSET_ORIGIN with mode-aware routing:
        // static 404-fallback, SPA index.html fallback, or SSR proxy to origin.
        // Non-fatal: warn if token lacks Workers Scripts: Edit scope.
        if let Some(ref token) = cf_api_token {
            let cf = CloudflareClient::new(token.clone());
            let mode = parse_worker_mode(&ctx.component.kind, slot_fields);
            let worker_name = slot_fields
                .get("worker_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{}-worker", ctx.service.name));
            let bindings = worker_config_bindings(&mode, &asset_origin);
            let worker_bindings: Vec<WorkerBinding<'_>> = bindings
                .iter()
                .map(|(k, v)| WorkerBinding::PlainText {
                    name: k.as_str(),
                    text: v.as_str(),
                })
                .collect();
            // Hash script + bindings so config changes trigger redeploy.
            let script_hash = {
                let mut input = WORKER_SCRIPT.as_bytes().to_vec();
                input.push(0);
                input.extend_from_slice(
                    serde_json::to_string(&bindings)
                        .unwrap_or_default()
                        .as_bytes(),
                );
                sha256_hex(&input)
            };

            let worker_result = async {
                let zone_id = cf.zone_id_for_name(&zone).await?;

                // Skip redeploy when script + config are unchanged across re-runs.
                let cached = read_worker_script_hash(ctx.workspace_root, &worker_name);
                if cached.as_deref() != Some(&script_hash) {
                    cf.deploy_worker_script(
                        &account_id,
                        &worker_name,
                        WORKER_SCRIPT,
                        &worker_bindings,
                    )
                    .await?;
                    let _ =
                        write_worker_script_hash(ctx.workspace_root, &worker_name, &script_hash);
                    info!(worker_name, "CF Worker script deployed");
                } else {
                    info!(
                        worker_name,
                        "CF Worker script unchanged — skipping redeploy"
                    );
                }

                // Upsert zone route: `{zone}/*` → worker script.
                let route_pattern = format!("{zone}/*");
                cf.upsert_worker_route(&zone_id, &route_pattern, &worker_name)
                    .await?;
                anyhow::Ok(())
            }
            .await;

            if let Err(e) = worker_result {
                warn!(
                    zone,
                    worker_name,
                    error = %e,
                    "CF Worker deploy/route failed (non-fatal) — \
                     ensure cloudflare-api-token has Workers Scripts: Edit \
                     and Zone Workers Routes: Edit scope"
                );
            }
        }

        Ok(RunningWorkload::adopted("mesofact-static", "static", None)
            .with_public_url(format!("https://{zone}")))
    }
}

/// Read the `[build]` + `[build_mode]` subtrees from
/// `<workload_dir>/workload.toml`. Used by [`MesofactStaticReconciler::rebuild_static`]
/// to drive [`run_build`] without forcing the whole workload through the
/// `workload_spec::Workload` envelope — many in-tree workload manifests
/// still carry `schema_version = 1` (integer) which the typed envelope
/// rejects. Parsing only the subtrees we use keeps this path tolerant of
/// the legacy shape while still giving us typed [`BuildConfig`] and
/// [`BuildMode`] values to lower.
///
/// Returns:
/// - `Ok(None)` when `workload.toml` is absent, isn't a `mesofact-static`
///   workload, or has no `[build]` table — `rebuild_static` then skips the
///   build step (the subsequent `up()` will surface the missing-manifest
///   error if relevant).
/// - `Ok(Some((build, build_mode)))` on success; `build_mode` defaults to
///   `HostSide` when the field is absent.
fn read_mesofact_build(workload_dir: &std::path::Path) -> Result<Option<(BuildConfig, BuildMode)>> {
    let path = workload_dir.join("workload.toml");
    let src = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
    };
    let value: toml::Value =
        toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))?;

    if value.get("kind").and_then(|v| v.as_str()) != Some(WORKLOAD_KIND) {
        return Ok(None);
    }

    let Some(build_value) = value.get("build") else {
        return Ok(None);
    };
    let build: BuildConfig = build_value
        .clone()
        .try_into()
        .with_context(|| format!("parsing [build] table in {}", path.display()))?;

    let build_mode = match value.get("build_mode") {
        Some(v) => v
            .clone()
            .try_into()
            .with_context(|| format!("parsing [build_mode] table in {}", path.display()))?,
        None => BuildMode::default(),
    };

    Ok(Some((build, build_mode)))
}

/// Lower (`build`, `build_mode`) to a [`ForgeSpec`] (W165).
///
/// - [`BuildMode::HostSide`] → `TaskRuntime::Native`, `image=None` — the
///   build inherits the host's PATH and toolchain.
/// - [`BuildMode::InContainer { image }`] → `TaskRuntime::Container` with
///   the pinned image attached to the `Subprocess` command. The executor
///   bind-mounts `workload_dir` as the container's working directory via
///   the [`ExecContext`] passed alongside.
///
/// Pure function: no I/O, no subprocess. Exposed at `pub(crate)` for
/// golden-test parity with the recipe-lowering helper (R438-T7).
pub(crate) fn lower_build_to_forge_spec(
    workload_dir: &std::path::Path,
    build: &BuildConfig,
    build_mode: &BuildMode,
) -> ForgeSpec {
    let (image, runtime) = match build_mode {
        BuildMode::HostSide => (None, TaskRuntime::Native),
        BuildMode::InContainer { image } => (Some(image.clone()), TaskRuntime::Container),
    };
    ForgeSpec {
        command: ForgeCommand::Subprocess {
            argv: vec!["sh".into(), "-c".into(), build.command.clone()],
            image,
        },
        where_: TaskPlacement::new(TaskLocation::Local, runtime),
        timeout: None,
        label: Some(format!("mesofact-static-build:{}", workload_dir.display())),
        initiator: Initiator::Gnome {
            camp: "mesofact-static-reconciler".into(),
            shift: "build".into(),
        },
        mesh_access: MeshAccess::default(),
    }
}

/// Lower (`build`, `build_mode`) to a [`ForgeSpec`] and run it through the
/// supplied [`ForgeExecutor`] (W165). Thin wrapper over
/// [`lower_build_to_forge_spec`] — separated so the lowering is testable
/// without spawning a subprocess.
async fn run_build(
    workload_dir: &std::path::Path,
    build: &BuildConfig,
    build_mode: &BuildMode,
    executor: &dyn ForgeExecutor,
) -> Result<()> {
    let mode_tag = match build_mode {
        BuildMode::HostSide => "host_side",
        BuildMode::InContainer { .. } => "in_container",
    };
    tracing::info!(
        workload = %workload_dir.display(),
        cmd = %build.command,
        mode = mode_tag,
        "running mesofact-static build"
    );

    let spec = lower_build_to_forge_spec(workload_dir, build, build_mode);
    let cmd_str = build.command.clone();
    let exec_ctx = ExecContext::default().with_cwd(workload_dir.to_path_buf());

    let outcome = executor
        .execute(spec, exec_ctx, None)
        .await
        .with_context(|| format!("executing build command: {cmd_str}"))?;

    if !outcome.succeeded() {
        anyhow::bail!(
            "build command failed ({}): {} — {}",
            outcome.status.discriminant(),
            cmd_str,
            outcome.stderr_tail,
        );
    }
    Ok(())
}

/// Read `build.out_dir` from a workload's `workload.toml`. Returns `None`
/// when the file is absent, unreadable, or the field is missing — callers
/// default to `"dist"`.
pub(crate) fn read_workload_out_dir(workload_dir: &std::path::Path) -> Option<String> {
    let path = workload_dir.join("workload.toml");
    let src = std::fs::read_to_string(&path).ok()?;
    let value: toml::Value = toml::from_str(&src).ok()?;
    value
        .get("build")?
        .get("out_dir")?
        .as_str()
        .map(str::to_string)
}

// ---------- CF Worker script rendering ----------

/// Routing mode baked into the Worker script at deploy time. Shared between
/// the Cloudflare-Worker arm (this file) and the pond arm via `pub` so camp's
/// `build_miniflare_deploy_spec` can derive the same mode from a mirror's
/// static slot when populating `local_driver::pond_miniflare::MiniflareSpec`.
pub enum WorkerMode {
    /// All routes served from R2; `/` and directory paths → `index.html`;
    /// unknown paths → `404.html` (if present) or a 404 response.
    Static,
    /// Unknown paths fall back to `index.html` for client-side routing.
    Spa,
    /// Paths matching `prefixes` are proxied to `origin_url`; the rest uses
    /// the SPA index.html fallback.
    Ssr {
        origin_url: String,
        prefixes: Vec<String>,
    },
}

/// Parse the Worker routing mode from the mirror's static slot fields. Public
/// so camp's pond bring-up can mirror the cloudflare-arm semantics without
/// duplicating the field-name conventions.
///
/// When the slot declares no explicit `mode`, the default derives from the
/// component's kind: `mesofact-spa` → SPA fallback, everything else → static.
/// An explicit `mode` field always wins.
pub fn parse_worker_mode(
    component_kind: &str,
    fields: &std::collections::BTreeMap<String, toml::Value>,
) -> WorkerMode {
    let default_mode = if component_kind == WORKLOAD_KIND_SPA {
        "spa"
    } else {
        "static"
    };
    match fields
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or(default_mode)
    {
        "spa" => WorkerMode::Spa,
        "ssr" => {
            let origin_url = fields
                .get("origin_url")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let prefixes = fields
                .get("ssr_prefixes")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            WorkerMode::Ssr {
                origin_url,
                prefixes,
            }
        }
        _ => WorkerMode::Static,
    }
}

/// Build the plain_text Worker binding values for the given routing mode.
///
/// These are uploaded alongside [`WORKER_SCRIPT`] as `plain_text` bindings
/// and appear as `env.ASSET_ORIGIN`, `env.WORKER_MODE`, etc. inside the Worker.
fn worker_config_bindings(mode: &WorkerMode, asset_origin: &str) -> Vec<(String, String)> {
    let (mode_str, ssr_origin, ssr_prefixes) = match mode {
        WorkerMode::Static => ("static", String::new(), "[]".to_string()),
        WorkerMode::Spa => ("spa", String::new(), "[]".to_string()),
        WorkerMode::Ssr {
            origin_url,
            prefixes,
        } => (
            "ssr",
            origin_url.clone(),
            serde_json::to_string(prefixes).unwrap_or_else(|_| "[]".to_string()),
        ),
    };
    vec![
        ("ASSET_ORIGIN".to_string(), asset_origin.to_string()),
        // Pointer-store origin for instance-addressed routes (W270 §3): the
        // @mesofact/edge worker reads `p/<key>` records here. Pointers live
        // under the `p/` prefix in the same bucket as content, so this defaults
        // to ASSET_ORIGIN; it stays a distinct binding so a future consumer can
        // front the (uncached) pointer reads separately.
        ("POINTER_ORIGIN".to_string(), asset_origin.to_string()),
        // Reserved upload seam (R490-T8): prod has no upload origin yet, so the
        // binding is empty and the Worker returns 404 on /uploads/*. A future
        // dynamic-bucket consumer sets this to the user-writable origin.
        ("UPLOAD_ORIGIN".to_string(), String::new()),
        ("WORKER_MODE".to_string(), mode_str.to_string()),
        ("SSR_ORIGIN".to_string(), ssr_origin),
        ("SSR_PREFIXES".to_string(), ssr_prefixes),
    ]
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

/// Read the last deployed Worker script hash from the jit cache.
fn read_worker_script_hash(workspace_root: &std::path::Path, worker_name: &str) -> Option<String> {
    let path = workspace_root.join(".yah/jit/worker-script-hashes.json");
    let s = std::fs::read_to_string(&path).ok()?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&s).ok()?;
    map.get(worker_name)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Write the deployed Worker script hash to the jit cache.
fn write_worker_script_hash(
    workspace_root: &std::path::Path,
    worker_name: &str,
    hash: &str,
) -> std::io::Result<()> {
    let path = workspace_root.join(".yah/jit/worker-script-hashes.json");
    let mut map: serde_json::Map<String, serde_json::Value> = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        serde_json::Map::new()
    };
    map.insert(
        worker_name.to_string(),
        serde_json::Value::String(hash.to_string()),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap_or_default(),
    )
}

/// Return `true` when a Unix-domain socket at `path` accepts connections.
/// Uses a blocking connect so it can be called from sync or async context
/// without spawning a task. The connect attempt is instantaneous for a live
/// listener and fails immediately for a missing/stale socket file.
#[cfg(unix)]
fn is_unix_socket_live(path: &std::path::Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(not(unix))]
fn is_unix_socket_live(_path: &std::path::Path) -> bool {
    false
}

/// Adopt a mesofact-dev already listening on `addr` — but only when it
/// identifies as `(expected_service, expected_component)` via `/__mesofact/info`
/// (R602-B4). Returns:
/// - `Ok(None)` — nothing is listening on `addr` (caller falls through to the
///   next candidate / spawns a fresh server).
/// - `Ok(Some(_))` — a matching mesofact-dev is running; adopt it.
/// - `Err(_)` — a listener is present but is a *different* service/component,
///   or is not an identifiable mesofact-dev at all. Adoption is refused; the
///   port is taken by a foreign workload, so there is nothing to spawn — surface
///   the collision instead of silently serving the wrong site.
///
/// `label` distinguishes the "configured" vs jit "dynamic" port in logs.
async fn try_adopt_identified(
    addr: SocketAddr,
    expected_service: &str,
    expected_component: &str,
    label: &str,
) -> Result<Option<RunningWorkload>> {
    // Liveness gate first: no listener → nothing to adopt (spawn path).
    if tokio::net::TcpStream::connect(addr).await.is_err() {
        return Ok(None);
    }

    match probe_dev_identity(addr).await {
        Some((svc, comp)) if svc == expected_service && comp == expected_component => {
            let dev_url = format!("http://{addr}");
            info!(
                dev_url = %dev_url,
                port = addr.port(),
                %label,
                "mesofact-dev already running; identity matches, adopting"
            );
            Ok(Some(RunningWorkload::adopted(
                "mesofact-static",
                "static",
                Some(dev_url),
            )))
        }
        Some((svc, comp)) => anyhow::bail!(
            "port {} is serving {svc}/{comp}, but component {expected_component} of service \
             {expected_service} expected it — refusing to adopt another workload's dev server. \
             This is a host-port collision; give each service a distinct port \
             (check `.yah/services/*/mirrors/*.toml`, or run `yah cloud validate`).",
            addr.port(),
        ),
        None => anyhow::bail!(
            "port {} is occupied by a process that is not an identifiable mesofact-dev \
             (no /__mesofact/info) — refusing to adopt a foreign listener for component \
             {expected_component} of service {expected_service}. Free the port or point this \
             component at an unused one.",
            addr.port(),
        ),
    }
}

/// Query `GET http://{addr}/__mesofact/info` and return the server's logical
/// `(service, component)` identity. `None` when the endpoint is unreachable,
/// non-2xx (older/identity-less mesofact-dev, or a foreign server), or the body
/// is not the expected JSON shape. Short timeout — this is a loopback probe on
/// the reconcile hot path.
async fn probe_dev_identity(addr: SocketAddr) -> Option<(String, String)> {
    let url = format!("http://{addr}/__mesofact/info");
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let svc = body.get("service")?.as_str()?.to_string();
    let comp = body.get("component")?.as_str()?.to_string();
    Some((svc, comp))
}

/// Read the actual port recorded in `.yah/jit/mesofact-dev-ports.json` after
/// a mesofact-dev bind. Returns `None` when the file is absent or the entry
/// is missing. `pub` since R490 follow-through: the desktop's dev-cell
/// observation probes this port when the camp's `mesofact_dev.list` has no
/// entry (the camp stopped spawning mesofact-dev in R490-F2, so its list no
/// longer sees desktop-spawned processes).
pub fn read_jit_port(workspace_root: &std::path::Path, svc: &str, component: &str) -> Option<u16> {
    let path = workspace_root
        .join(".yah")
        .join("jit")
        .join("mesofact-dev-ports.json");
    let s = std::fs::read_to_string(&path).ok()?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&s).ok()?;
    map.get(&format!("{svc}/{component}"))
        .and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
}

/// Sanitize `service`/`component` into a [`MeshIdent`] that is DNS-segment
/// shaped (kamaji contract) and safe as a filesystem path component
/// (NativeRuntime joins it under its state dir for log capture). Lowercase;
/// every non-alphanumeric collapses to `-`.
fn native_ident(service: &str, component: &str) -> String {
    let raw = format!("mesofact-dev-{service}-{component}");
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// Lower a mesofact-dev invocation to a native [`WorkloadSpec`]. `argv[0]` is
/// the host binary; the remaining entries are its arguments (kamaji's
/// Native backend uses container `command` semantics — see
/// `constable_core::native`). `image` is identity metadata only: native never
/// pulls, so it carries the [`NATIVE_IDENTITY_DIGEST`] marker.
fn native_mesofact_spec(ident: &str, argv: Vec<String>) -> WorkloadSpec {
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: ident.to_string(),
        image: ImageRef {
            registry: "localhost".to_string(),
            repository: format!("native/{ident}"),
            tag: "dev".to_string(),
            digest: NATIVE_IDENTITY_DIGEST.to_string(),
        },
        tier: TierTag("dev".to_string()),
        replicas: 1,
        command: Some(argv),
        entrypoint: None,
        workdir: None,
        user: None,
        env: Vec::<EnvVar>::new(),
        secrets: vec![],
        volumes: vec![],
        resources: ResourceLimits {
            memory_mb: 512,
            cpu_millis: 512,
            ephemeral_storage_mb: 512,
        },
        depends_on: vec![],
        healthcheck: None,
        restart_policy: RestartPolicy::Never,
        archetype: None,
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(5),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent(ident.to_string()),
                ports: vec![],
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        tenant: TenantId::singleton(),
        namespace: NamespaceId::singleton(),
        labels: Default::default(),
        annotations: Default::default(),
    }
}

/// Supervisor task for a kamaji-native mesofact-dev workload.
///
/// NativeRuntime captures stdout/stderr to files with no follow, but the
/// Run-tab expects a live [`LogBuffer`]. This task incrementally tails both
/// capture files into `log_buf`, watches for a terminal child state, and on
/// shutdown (operator signal or self-exit) tears the workload down. Returned
/// as the `RunningWorkload` supervisor so the existing lifecycle contract is
/// unchanged.
fn spawn_native_log_supervisor(
    runtime: Arc<NativeRuntime>,
    ident: MeshIdent,
    log_buf: LogBuffer,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let mut out_tail = FileTail::new(stdout_path);
        let mut err_tail = FileTail::new(stderr_path);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    out_tail.drain_into(&log_buf).await;
                    err_tail.drain_into(&log_buf).await;
                    runtime.teardown_workload(&ident).await.ok();
                    return Ok(());
                }
                _ = tokio::time::sleep(Duration::from_millis(200)) => {
                    out_tail.drain_into(&log_buf).await;
                    err_tail.drain_into(&log_buf).await;
                    match runtime.get_workload(&ident).await {
                        // Still running — keep tailing.
                        Ok(Some(state)) if !state.status.is_terminal() => {}
                        // Exited on its own — final drain, then stop.
                        Ok(Some(_)) => {
                            out_tail.drain_into(&log_buf).await;
                            err_tail.drain_into(&log_buf).await;
                            return Ok(());
                        }
                        // Torn down elsewhere or runtime gone — stop.
                        Ok(None) | Err(_) => return Ok(()),
                    }
                }
            }
        }
    })
}

/// Incremental line-oriented tail of a capture file. Tracks the byte offset
/// already consumed plus any partial trailing line, so each drain emits only
/// whole new lines into the [`LogBuffer`].
struct FileTail {
    path: PathBuf,
    offset: u64,
    partial: String,
}

impl FileTail {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            partial: String::new(),
        }
    }

    async fn drain_into(&mut self, log_buf: &LogBuffer) {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let Ok(mut file) = tokio::fs::File::open(&self.path).await else {
            return;
        };
        if file
            .seek(std::io::SeekFrom::Start(self.offset))
            .await
            .is_err()
        {
            return;
        }
        let mut buf = Vec::new();
        let Ok(n) = file.read_to_end(&mut buf).await else {
            return;
        };
        if n == 0 {
            return;
        }
        self.offset += n as u64;
        // Carry any incomplete trailing line over to the next drain.
        self.partial.push_str(&String::from_utf8_lossy(&buf));
        while let Some(idx) = self.partial.find('\n') {
            let line: String = self.partial.drain(..=idx).collect();
            log_buf
                .push(line.trim_end_matches(['\n', '\r']).to_string())
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MirrorConfig, MirrorShape, ServiceComponent, ServiceConfig};
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    /// Build a minimal in-memory ctx for unit tests, with the component's
    /// workload dir set up to look like a mesofact-static workload.
    struct Fixture {
        _workspace: tempfile::TempDir,
        workspace_root: PathBuf,
        service: ServiceConfig,
        component: ServiceComponent,
        mirror: MirrorConfig,
        env: String,
    }

    impl Fixture {
        fn new(slot: MirrorProviderSlot, write_workload: bool) -> Self {
            let workspace = tempdir().unwrap();
            let workspace_root = workspace.path().to_path_buf();
            let workload_dir = workspace_root.join("app/web");
            std::fs::create_dir_all(workload_dir.join("dist/html")).unwrap();
            std::fs::write(workload_dir.join("dist/html/index.html"), "<h1>x</h1>").unwrap();
            if write_workload {
                std::fs::write(
                    workload_dir.join("workload.toml"),
                    r#"schema_version = 1
kind = "mesofact-static"
routes = "./routes.ts"

[build]
command = "echo built"
out_dir = "dist"
"#,
                )
                .unwrap();
            }

            let mut providers = BTreeMap::new();
            providers.insert("static".to_string(), slot);
            let mirror = MirrorConfig {
                schema_version: 1,
                shape: MirrorShape::Local,
                providers,
                asset_aliases: Default::default(),
            };
            let service = ServiceConfig {
                schema_version: 1,
                name: "test-svc".to_string(),
                domain: "test.local".to_string(),
                components: vec![],
                db: crate::DbCatalog::default(),
            };
            let component = ServiceComponent {
                id: "site".to_string(),
                kind: "mesofact-static".to_string(),
                path: "app/web".to_string(),
                role: "static".to_string(),
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
                env: "local".to_string(),
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
    }

    fn local_static_slot(port: u16) -> MirrorProviderSlot {
        let mut fields = BTreeMap::new();
        fields.insert("port".to_string(), toml::Value::Integer(port as i64));
        MirrorProviderSlot::Inline {
            kind: Provider::LocalStatic,
            fields,
        }
    }

    /// Bind to 127.0.0.1:0, read the assigned port, drop the listener.
    /// Used in adopt_only tests that must exercise the "port not bound" path:
    /// a dynamically chosen port is almost certainly free immediately after
    /// the listener drops, unlike the hardcoded 4321 which a running camp will
    /// have occupied.
    fn pick_unused_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    fn cloudflare_reference_slot() -> MirrorProviderSlot {
        MirrorProviderSlot::Reference {
            provider_id: "cloudflare".to_string(),
            fields: BTreeMap::new(),
        }
    }

    #[test]
    fn resolved_binary_prefers_explicit_path() {
        let opts = LocalStaticOptions {
            binary: Some(PathBuf::from("/explicit/path")),
            ..Default::default()
        };
        assert_eq!(opts.resolved_binary(), PathBuf::from("/explicit/path"));
    }

    #[test]
    fn resolved_binary_falls_back_to_bare_name() {
        // Clearing the env var requires unsafe in test isolation; instead
        // assume MESOFACT_DEV_BIN is unset (best-effort).
        let opts = LocalStaticOptions::default();
        if std::env::var_os("MESOFACT_DEV_BIN").is_none() {
            assert_eq!(opts.resolved_binary(), PathBuf::from("mesofact-dev"));
        }
    }

    #[test]
    fn slot_field_u16_extracts_port() {
        let mut fields = BTreeMap::new();
        fields.insert("port".to_string(), toml::Value::Integer(4321));
        assert_eq!(slot_field_u16(&fields, "port"), Some(4321));
    }

    #[test]
    fn slot_field_u16_returns_none_for_missing_key() {
        let fields = BTreeMap::new();
        assert_eq!(slot_field_u16(&fields, "port"), None);
    }

    #[tokio::test]
    async fn up_bails_when_workload_toml_missing() {
        let fx = Fixture::new(local_static_slot(4321), /*write_workload*/ false);
        let reconciler = MesofactStaticReconciler::new();
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("workload.toml"), "got: {msg}");
    }

    #[tokio::test]
    async fn up_bails_when_workload_kind_mismatches() {
        let fx = Fixture::new(local_static_slot(4321), /*write_workload*/ false);
        // Hand-write a container-kind workload at the right path. We
        // don't need the full container schema; the reconciler dispatches
        // off the `kind` field alone.
        std::fs::write(
            fx.workspace_root.join("app/web/workload.toml"),
            r#"schema_version = 1
kind = "container"
"#,
        )
        .unwrap();
        let reconciler = MesofactStaticReconciler::new();
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("kind=\"container\""), "got: {msg}");
    }

    #[tokio::test]
    async fn up_bails_when_static_slot_missing() {
        let mut fx = Fixture::new(local_static_slot(4321), true);
        fx.mirror.providers.clear();
        let reconciler = MesofactStaticReconciler::new();
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("providers.static"), "got: {msg}");
    }

    fn miniflare_container_slot(port: u16) -> MirrorProviderSlot {
        let mut fields = BTreeMap::new();
        fields.insert("port".to_string(), toml::Value::Integer(port as i64));
        fields.insert(
            "bucket".to_string(),
            toml::Value::String("yah-dev".to_string()),
        );
        MirrorProviderSlot::Inline {
            kind: Provider::MiniflareContainer,
            fields,
        }
    }

    #[tokio::test]
    async fn up_miniflare_container_bails_when_object_store_slot_missing() {
        // MiniflareContainer dispatches into pond::up_pond, which
        // requires a sibling providers.object_store slot. Missing → clear
        // error before we attempt to talk to docker.
        let fx = Fixture::new(miniflare_container_slot(4322), true);
        let reconciler = MesofactStaticReconciler::new();
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("providers.object_store"),
            "error must mention the missing sibling slot; got: {msg}"
        );
        assert!(
            msg.contains("pond"),
            "error must name the requesting code path; got: {msg}"
        );
    }

    #[tokio::test]
    async fn up_miniflare_container_bails_when_object_store_kind_wrong() {
        let mut fx = Fixture::new(miniflare_container_slot(4322), true);
        // Drop in a non-MinIO inline slot at object_store.
        fx.mirror.providers.insert(
            "object_store".into(),
            MirrorProviderSlot::Inline {
                kind: Provider::LocalStatic,
                fields: BTreeMap::new(),
            },
        );
        let reconciler = MesofactStaticReconciler::new();
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("minio-container"),
            "error must name the expected kind; got: {msg}"
        );
    }

    #[tokio::test]
    async fn up_bails_on_cloudflare_reference_slot() {
        let cloudflare = MirrorProviderSlot::Reference {
            provider_id: "cloudflare".to_string(),
            fields: BTreeMap::new(),
        };
        let fx = Fixture::new(cloudflare, true);
        let reconciler = MesofactStaticReconciler::new();
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cloudflare"), "got: {msg}");
    }

    /// Regression for R330-B5: a cloud mirror that supplies bucket+zone but
    /// omits `asset_origin` must fail loudly at reconcile time. Otherwise the
    /// Worker silently gets `env.ASSET_ORIGIN=""` and 404s every request in
    /// prod (R327-F2 gotcha).
    #[tokio::test]
    async fn up_bails_on_cloudflare_reference_missing_asset_origin() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "bucket".to_string(),
            toml::Value::String("yah-dev".to_string()),
        );
        fields.insert(
            "zone".to_string(),
            toml::Value::String("yah.dev".to_string()),
        );
        let cloudflare = MirrorProviderSlot::Reference {
            provider_id: "cloudflare".to_string(),
            fields,
        };
        let fx = Fixture::new(cloudflare, true);
        // Write a minimal cloudflare provider config so the asset_origin
        // check is the first thing that fails (otherwise the missing
        // provider file aborts the run earlier).
        let providers_dir = fx.workspace_root.join(".yah/infra/providers");
        std::fs::create_dir_all(&providers_dir).unwrap();
        std::fs::write(
            providers_dir.join("cloudflare.toml"),
            r#"schema_version = 1
id = "cloudflare"
kind = "cloudflare"
account_id = "test-account"
"#,
        )
        .unwrap();
        let reconciler = MesofactStaticReconciler::new();
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("asset_origin"),
            "error must name asset_origin; got: {msg}"
        );
    }

    /// R432-B2: stale jit file claiming the configured port must not produce
    /// "dynamic fallback" language — no second probe was attempted.
    #[tokio::test]
    async fn adopt_only_stale_jit_same_port_omits_dynamic_fallback_phrase() {
        let port = pick_unused_port();
        let fx = Fixture::new(local_static_slot(port), true);
        let jit_dir = fx.workspace_root.join(".yah/jit");
        std::fs::create_dir_all(&jit_dir).unwrap();
        std::fs::write(
            jit_dir.join("mesofact-dev-ports.json"),
            format!(r#"{{"test-svc/site": {port}}}"#),
        )
        .unwrap();
        let reconciler = MesofactStaticReconciler::new().with_local_static(LocalStaticOptions {
            adopt_only: true,
            ..Default::default()
        });
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("dynamic fallback"),
            "stale jit at configured port must not claim a dynamic probe; got: {msg}"
        );
        assert!(
            !msg.contains("jit file"),
            "same-port jit entry must not appear in the error; got: {msg}"
        );
    }

    /// R432-B2: when camp is up but jit records a different dead port, name it.
    /// Requires a live socket so the error takes the Case-B "camp up" branch.
    #[cfg(unix)]
    #[tokio::test]
    async fn adopt_only_stale_jit_different_port_names_it() {
        use std::os::unix::net::UnixListener;

        let port = pick_unused_port();
        let jit_port = pick_unused_port();
        let fx = Fixture::new(local_static_slot(port), true);
        let jit_dir = fx.workspace_root.join(".yah/jit");
        std::fs::create_dir_all(&jit_dir).unwrap();
        std::fs::write(
            jit_dir.join("mesofact-dev-ports.json"),
            format!(r#"{{"test-svc/site": {jit_port}}}"#),
        )
        .unwrap();
        let socket_path = fx.workspace_root.join("camp.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let reconciler = MesofactStaticReconciler::new().with_local_static(LocalStaticOptions {
            adopt_only: true,
            camp_socket: Some(socket_path),
            ..Default::default()
        });
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&jit_port.to_string()),
            "error must name the dead jit port; got: {msg}"
        );
        assert!(
            !msg.contains("dynamic fallback"),
            "precise port naming replaces generic 'dynamic fallback'; got: {msg}"
        );
    }

    /// R432-F3: no camp socket → "not running" / attach message (no socket probe noise).
    #[tokio::test]
    async fn adopt_only_no_camp_socket_gives_attach_message() {
        let fx = Fixture::new(local_static_slot(pick_unused_port()), true);
        let reconciler = MesofactStaticReconciler::new().with_local_static(LocalStaticOptions {
            adopt_only: true,
            camp_socket: None, // no socket path — treated as camp not running
            ..Default::default()
        });
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not running") || msg.contains("attach"),
            "no-socket path must indicate camp is not attached; got: {msg}"
        );
    }

    /// R432-F3: live camp socket but no server → "camp is up but didn't bind".
    #[cfg(unix)]
    #[tokio::test]
    async fn adopt_only_live_camp_socket_gives_didnt_bind_message() {
        use std::os::unix::net::UnixListener;

        let fx = Fixture::new(local_static_slot(pick_unused_port()), true);
        let socket_path = fx.workspace_root.join("camp.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();

        let reconciler = MesofactStaticReconciler::new().with_local_static(LocalStaticOptions {
            adopt_only: true,
            camp_socket: Some(socket_path),
            ..Default::default()
        });
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("a yah daemon is up but"),
            "live socket must give 'daemon is up but didn't bind' message; got: {msg}"
        );
        assert!(
            msg.contains("did not bind"),
            "message must name the bind failure; got: {msg}"
        );
    }

    #[tokio::test]
    async fn up_bails_when_binary_not_found() {
        let fx = Fixture::new(local_static_slot(0), true);
        let reconciler = MesofactStaticReconciler::new().with_local_static(LocalStaticOptions {
            binary: Some(PathBuf::from("/definitely/not/a/binary")),
            ready_timeout: Some(Duration::from_millis(50)),
            ..Default::default()
        });
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("spawning"), "got: {msg}");
    }

    /// R490-F2: native_ident produces a DNS-/path-safe slug.
    #[test]
    fn native_ident_sanitizes_to_path_safe_slug() {
        assert_eq!(
            native_ident("dev-yah", "static"),
            "mesofact-dev-dev-yah-static"
        );
        // Non-alphanumerics (incl. slashes, dots) collapse to '-'; lowercased.
        assert_eq!(native_ident("Foo.Bar", "a/b"), "mesofact-dev-foo-bar-a-b");
    }

    /// R490-F2: native_mesofact_spec lowers argv into the Native backend's
    /// container-`command` shape with the no-pull identity digest.
    #[test]
    fn native_mesofact_spec_lowers_argv_and_identity() {
        let spec = native_mesofact_spec(
            "mesofact-dev-site-static",
            vec![
                "/bin/mesofact-dev".into(),
                "/wd".into(),
                "--port".into(),
                "4321".into(),
            ],
        );
        assert_eq!(spec.name, "mesofact-dev-site-static");
        assert_eq!(spec.entrypoint, None);
        assert_eq!(spec.command.as_deref().unwrap()[0], "/bin/mesofact-dev");
        assert_eq!(spec.expose.mesh.identity.0, "mesofact-dev-site-static");
        assert_eq!(spec.image.digest, NATIVE_IDENTITY_DIGEST);
        assert_eq!(spec.replicas, 1);
    }

    /// R490-F2: FileTail emits only whole lines and carries a partial trailing
    /// line over to the next drain (the Run-tab log bridge over kamaji's
    /// file capture).
    #[tokio::test]
    async fn file_tail_emits_whole_lines_and_carries_partial() {
        use tokio::io::AsyncWriteExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("stdout.log");
        let log = LogBuffer::new();
        let mut tail = FileTail::new(path.clone());

        // No file yet → no-op, no lines.
        tail.drain_into(&log).await;
        let (l0, c0) = log.since(0).await;
        assert!(l0.is_empty());

        // Two whole lines + a partial third (no trailing newline).
        let mut f = tokio::fs::File::create(&path).await.unwrap();
        f.write_all(b"alpha\nbeta\npar").await.unwrap();
        f.flush().await.unwrap();
        tail.drain_into(&log).await;
        let (l1, c1) = log.since(c0).await;
        assert_eq!(l1, vec!["alpha".to_string(), "beta".to_string()]);

        // Completing the partial line surfaces it whole on the next drain.
        f.write_all(b"tial\ngamma\n").await.unwrap();
        f.flush().await.unwrap();
        tail.drain_into(&log).await;
        let (l2, _) = log.since(c1).await;
        assert_eq!(l2, vec!["partial".to_string(), "gamma".to_string()]);
    }

    /// Wait-for-port: bind a local TCP listener in-process, confirm
    /// `wait_for_port` returns true within timeout.
    #[tokio::test]
    async fn wait_for_port_returns_true_when_port_bound() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(wait_for_port(addr, Duration::from_millis(500)).await);
        drop(listener);
    }

    #[tokio::test]
    async fn wait_for_port_returns_false_when_port_idle() {
        // Bind + drop to get an ephemeral port that's now definitely
        // unbound (modulo races; ignore the rare false flake).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(!wait_for_port(addr, Duration::from_millis(100)).await);
    }

    // ---------- Worker script + config bindings ----------

    #[test]
    fn worker_script_maps_root_to_index_html() {
        assert!(
            WORKER_SCRIPT.contains("index.html"),
            "bundled Worker must route / to index.html; got: {WORKER_SCRIPT}"
        );
    }

    #[test]
    fn worker_script_has_no_r2_binding_calls() {
        assert!(
            !WORKER_SCRIPT.contains("env.ASSETS"),
            "bundled Worker must not reference R2 binding env.ASSETS; got: {WORKER_SCRIPT}"
        );
        assert!(
            !WORKER_SCRIPT.contains("writeHttpMetadata"),
            "bundled Worker must not use R2 writeHttpMetadata; got: {WORKER_SCRIPT}"
        );
    }

    #[test]
    fn worker_script_uses_asset_origin_fetch() {
        assert!(
            WORKER_SCRIPT.contains("ASSET_ORIGIN"),
            "bundled Worker must fetch from ASSET_ORIGIN; got: {WORKER_SCRIPT}"
        );
    }

    /// The vendored @mesofact/edge bundle must carry the W270 §3 serving logic:
    /// manifest read, pointer-store resolution for instance-addressed routes,
    /// and manifest error_routes. Substring markers (not behavior — behavior is
    /// covered by the miniflare tests in oss/mesofact/packages/mesofact-edge).
    #[test]
    fn worker_script_resolves_pointers_and_error_routes() {
        assert!(
            WORKER_SCRIPT.contains("manifest.json"),
            "bundled Worker must read the published manifest; got: {WORKER_SCRIPT}"
        );
        assert!(
            WORKER_SCRIPT.contains("POINTER_ORIGIN"),
            "bundled Worker must resolve pointers via POINTER_ORIGIN; got: {WORKER_SCRIPT}"
        );
        assert!(
            WORKER_SCRIPT.contains("error_routes"),
            "bundled Worker must honor manifest error_routes; got: {WORKER_SCRIPT}"
        );
    }

    #[test]
    fn config_bindings_static_mode() {
        let b: std::collections::HashMap<_, _> =
            worker_config_bindings(&WorkerMode::Static, "https://assets.example.com")
                .into_iter()
                .collect();
        assert_eq!(b["WORKER_MODE"], "static");
        assert_eq!(b["ASSET_ORIGIN"], "https://assets.example.com");
        // Pointer origin defaults to the asset origin (W270 §3).
        assert_eq!(b["POINTER_ORIGIN"], "https://assets.example.com");
        assert_eq!(b["SSR_ORIGIN"], "");
        assert_eq!(b["SSR_PREFIXES"], "[]");
    }

    #[test]
    fn config_bindings_spa_mode() {
        let b: std::collections::HashMap<_, _> =
            worker_config_bindings(&WorkerMode::Spa, "https://assets.example.com")
                .into_iter()
                .collect();
        assert_eq!(b["WORKER_MODE"], "spa");
        assert_eq!(b["SSR_ORIGIN"], "");
    }

    #[test]
    fn config_bindings_ssr_mode() {
        let mode = WorkerMode::Ssr {
            origin_url: "https://ssr.example.com".to_string(),
            prefixes: vec!["/api/".to_string(), "/rpc/".to_string()],
        };
        let b: std::collections::HashMap<_, _> =
            worker_config_bindings(&mode, "https://assets.example.com")
                .into_iter()
                .collect();
        assert_eq!(b["WORKER_MODE"], "ssr");
        assert_eq!(b["SSR_ORIGIN"], "https://ssr.example.com");
        let prefixes: Vec<String> = serde_json::from_str(&b["SSR_PREFIXES"]).unwrap();
        assert!(prefixes.contains(&"/api/".to_string()));
        assert!(prefixes.contains(&"/rpc/".to_string()));
    }

    #[test]
    fn worker_script_hash_roundtrip() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        assert!(read_worker_script_hash(root, "test-worker").is_none());
        write_worker_script_hash(root, "test-worker", "abc123").unwrap();
        assert_eq!(
            read_worker_script_hash(root, "test-worker").as_deref(),
            Some("abc123")
        );
        // Writing a second worker doesn't clobber the first.
        write_worker_script_hash(root, "other-worker", "def456").unwrap();
        assert_eq!(
            read_worker_script_hash(root, "test-worker").as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn parse_worker_mode_defaults_to_static() {
        let fields = BTreeMap::new();
        assert!(matches!(
            parse_worker_mode(WORKLOAD_KIND, &fields),
            WorkerMode::Static
        ));
    }

    #[test]
    fn parse_worker_mode_spa_kind_defaults_to_spa() {
        let fields = BTreeMap::new();
        assert!(matches!(
            parse_worker_mode(WORKLOAD_KIND_SPA, &fields),
            WorkerMode::Spa
        ));
    }

    #[test]
    fn parse_worker_mode_explicit_mode_beats_kind_default() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "mode".to_string(),
            toml::Value::String("static".to_string()),
        );
        assert!(matches!(
            parse_worker_mode(WORKLOAD_KIND_SPA, &fields),
            WorkerMode::Static
        ));
    }

    #[test]
    fn parse_worker_mode_spa() {
        let mut fields = BTreeMap::new();
        fields.insert("mode".to_string(), toml::Value::String("spa".to_string()));
        assert!(matches!(
            parse_worker_mode(WORKLOAD_KIND, &fields),
            WorkerMode::Spa
        ));
    }

    #[test]
    fn parse_worker_mode_ssr_extracts_origin_and_prefixes() {
        let mut fields = BTreeMap::new();
        fields.insert("mode".to_string(), toml::Value::String("ssr".to_string()));
        fields.insert(
            "origin_url".to_string(),
            toml::Value::String("https://origin.example.com".to_string()),
        );
        fields.insert(
            "ssr_prefixes".to_string(),
            toml::Value::Array(vec![toml::Value::String("/api/".to_string())]),
        );
        if let WorkerMode::Ssr {
            origin_url,
            prefixes,
        } = parse_worker_mode(WORKLOAD_KIND, &fields)
        {
            assert_eq!(origin_url, "https://origin.example.com");
            assert_eq!(prefixes, vec!["/api/"]);
        } else {
            panic!("expected Ssr mode");
        }
    }

    // ---------- W165: BuildMode → ForgeSpec lowering (R438-T6) ----------

    use std::sync::Mutex as StdMutex;
    use velveteen_exec::executor::{ExecEvent, ExecOutcome, ForgeExecutorError};
    use velveteen::ForgeStatus;
    use tokio::sync::mpsc::UnboundedSender;

    /// Captures the [`ForgeSpec`] handed to `execute(...)` and returns
    /// success without spawning anything.
    struct CaptureExecutor {
        captured: Arc<StdMutex<Vec<(ForgeSpec, ExecContext)>>>,
    }

    impl CaptureExecutor {
        fn new() -> (Arc<Self>, Arc<StdMutex<Vec<(ForgeSpec, ExecContext)>>>) {
            let captured = Arc::new(StdMutex::new(Vec::new()));
            (
                Arc::new(Self {
                    captured: captured.clone(),
                }),
                captured,
            )
        }
    }

    #[async_trait]
    impl ForgeExecutor for CaptureExecutor {
        async fn execute(
            &self,
            spec: ForgeSpec,
            ctx: ExecContext,
            _sink: Option<UnboundedSender<ExecEvent>>,
        ) -> Result<ExecOutcome, ForgeExecutorError> {
            self.captured.lock().unwrap().push((spec, ctx));
            Ok(ExecOutcome {
                status: ForgeStatus::Done {
                    exit_code: 0,
                    ended_at: 0,
                },
                stderr_tail: String::new(),
            })
        }
    }

    /// Executor whose runs all return a non-zero exit + canned stderr —
    /// used to assert error-message shape from [`run_build`].
    struct FailingExecutor {
        stderr: String,
    }

    #[async_trait]
    impl ForgeExecutor for FailingExecutor {
        async fn execute(
            &self,
            _spec: ForgeSpec,
            _ctx: ExecContext,
            _sink: Option<UnboundedSender<ExecEvent>>,
        ) -> Result<ExecOutcome, ForgeExecutorError> {
            Ok(ExecOutcome {
                status: ForgeStatus::Done {
                    exit_code: 2,
                    ended_at: 0,
                },
                stderr_tail: self.stderr.clone(),
            })
        }
    }

    fn host_side_build() -> (BuildConfig, BuildMode) {
        (
            BuildConfig {
                command: "bun run build".into(),
                out_dir: PathBuf::from("dist"),
                render_command: None,
            },
            BuildMode::HostSide,
        )
    }

    fn in_container_build() -> (BuildConfig, BuildMode) {
        let image = workload_spec::ImageRef {
            registry: "ghcr.io".into(),
            repository: "org/app-build".into(),
            tag: "v1.2".into(),
            digest: workload_spec::testing::test_digest(),
        };
        (
            BuildConfig {
                command: "bun run build".into(),
                out_dir: PathBuf::from("dist"),
                render_command: None,
            },
            BuildMode::InContainer { image },
        )
    }

    #[tokio::test]
    async fn run_build_host_side_lowers_to_native_subprocess() {
        let (capture, captured) = CaptureExecutor::new();
        let tmp = tempdir().unwrap();
        let (build, mode) = host_side_build();
        run_build(tmp.path(), &build, &mode, &*capture)
            .await
            .unwrap();

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1, "build executed exactly once");
        let (spec, ctx) = &captured[0];
        assert_eq!(spec.where_.runtime, TaskRuntime::Native);
        assert_eq!(spec.where_.location, TaskLocation::Local);
        match &spec.command {
            ForgeCommand::Subprocess { argv, image } => {
                assert!(image.is_none(), "host_side carries no image; got {image:?}");
                assert_eq!(
                    argv,
                    &vec!["sh".to_string(), "-c".into(), "bun run build".into()]
                );
            }
            other => panic!("expected Subprocess, got {other:?}"),
        }
        assert_eq!(ctx.cwd.as_deref(), Some(tmp.path()));
    }

    #[tokio::test]
    async fn run_build_in_container_lowers_to_container_runtime_with_pinned_digest() {
        let (capture, captured) = CaptureExecutor::new();
        let tmp = tempdir().unwrap();
        let (build, mode) = in_container_build();
        run_build(tmp.path(), &build, &mode, &*capture)
            .await
            .unwrap();

        let captured = captured.lock().unwrap();
        let (spec, ctx) = &captured[0];
        assert_eq!(spec.where_.runtime, TaskRuntime::Container);
        assert_eq!(spec.where_.location, TaskLocation::Local);
        match &spec.command {
            ForgeCommand::Subprocess { argv, image } => {
                let image = image.as_ref().expect("in_container lowers with an image");
                assert_eq!(image.registry, "ghcr.io");
                assert_eq!(image.repository, "org/app-build");
                assert_eq!(image.tag, "v1.2");
                assert_eq!(image.digest, workload_spec::testing::test_digest());
                assert_eq!(
                    argv,
                    &vec!["sh".to_string(), "-c".into(), "bun run build".into()]
                );
            }
            other => panic!("expected Subprocess, got {other:?}"),
        }
        assert_eq!(ctx.cwd.as_deref(), Some(tmp.path()));
    }

    #[tokio::test]
    async fn run_build_surfaces_stderr_on_nonzero_exit() {
        let executor = Arc::new(FailingExecutor {
            stderr: "TypeError: Cannot find module 'react'".into(),
        });
        let tmp = tempdir().unwrap();
        let (build, mode) = host_side_build();
        let err = run_build(tmp.path(), &build, &mode, &*executor)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Cannot find module 'react'"), "got: {msg}");
        assert!(msg.contains("bun run build"), "got: {msg}");
    }

    #[tokio::test]
    async fn read_mesofact_build_extracts_host_side_default() {
        let tmp = tempdir().unwrap();
        // Use the legacy `schema_version = 1` integer shape — production
        // marketing/dashboard workload.tomls carry this and rebuild_static
        // must keep working against them. The subtree reader skips the
        // envelope so this round-trips.
        std::fs::write(
            tmp.path().join("workload.toml"),
            r#"schema_version = 1
kind = "mesofact-static"
routes = "./routes.ts"

[build]
command = "bun run build"
out_dir = "dist"
"#,
        )
        .unwrap();
        let (build, mode) = read_mesofact_build(tmp.path()).unwrap().unwrap();
        assert_eq!(build.command, "bun run build");
        assert_eq!(build.out_dir, PathBuf::from("dist"));
        assert!(matches!(mode, BuildMode::HostSide));
    }

    #[tokio::test]
    async fn read_mesofact_build_extracts_in_container_with_digest() {
        let tmp = tempdir().unwrap();
        let digest = workload_spec::testing::test_digest();
        std::fs::write(
            tmp.path().join("workload.toml"),
            format!(
                r#"schema_version = 1
kind = "mesofact-static"
routes = "./routes.ts"

[build]
command = "bun run build"
out_dir = "dist"

[build_mode.in_container.image]
registry = "ghcr.io"
repository = "org/app-build"
tag = "v1.2"
digest = "{digest}"
"#
            ),
        )
        .unwrap();
        let (build, mode) = read_mesofact_build(tmp.path()).unwrap().unwrap();
        assert_eq!(build.command, "bun run build");
        match mode {
            BuildMode::InContainer { image } => {
                assert_eq!(image.registry, "ghcr.io");
                assert_eq!(image.repository, "org/app-build");
                assert_eq!(image.tag, "v1.2");
                assert_eq!(image.digest, digest);
            }
            other => panic!("expected InContainer, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_mesofact_build_rejects_in_container_without_digest() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("workload.toml"),
            r#"schema_version = 1
kind = "mesofact-static"
routes = "./routes.ts"

[build]
command = "bun run build"
out_dir = "dist"

[build_mode.in_container]
image = "ghcr.io/org/app-build:v1.2"
"#,
        )
        .unwrap();
        let err = read_mesofact_build(tmp.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("digest") || msg.contains("sha256"),
            "in_container with bare tag must reject at parse; got: {msg}"
        );
    }

    #[tokio::test]
    async fn read_mesofact_build_returns_none_for_other_kinds() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("workload.toml"),
            r#"schema_version = 1
kind = "static-asset"
"#,
        )
        .unwrap();
        assert!(read_mesofact_build(tmp.path()).unwrap().is_none());
    }

    #[tokio::test]
    async fn read_mesofact_build_returns_none_when_file_absent() {
        let tmp = tempdir().unwrap();
        assert!(read_mesofact_build(tmp.path()).unwrap().is_none());
    }

    #[tokio::test]
    async fn rebuild_static_lifts_build_mode_through_executor() {
        // End-to-end smoke through rebuild_static → run_build → executor for
        // the cloudflare publish arm. InContainer build_mode must reach the
        // executor as TaskRuntime::Container (the CF path does not skip container
        // builds — only local-static does, per W165 OQ#1, tested separately).
        // up_cloudflare_r2 will fail (no provider config), but the build step
        // runs first so the CaptureExecutor still records the lowered ForgeSpec.
        let fx = Fixture::new(cloudflare_reference_slot(), /*write_workload*/ false);
        let workload_dir = fx.workspace_root.join("app/web");
        let digest = workload_spec::testing::test_digest();
        std::fs::write(
            workload_dir.join("workload.toml"),
            format!(
                r#"schema_version = 1
kind = "mesofact-static"
routes = "./routes.ts"

[build]
command = "bun run build"
out_dir = "dist"

[build_mode.in_container.image]
registry = "ghcr.io"
repository = "org/app-build"
tag = "v1.2"
digest = "{digest}"
"#
            ),
        )
        .unwrap();

        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());

        // up_cloudflare_r2 will fail (no provider config on disk) but only
        // AFTER the build step ran. We only care that the build path produced
        // a captured ForgeSpec with the right runtime.
        let _ = reconciler.rebuild_static(fx.ctx()).await;

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1, "build step executed exactly once");
        let (spec, _ctx) = &captured[0];
        assert_eq!(spec.where_.runtime, TaskRuntime::Container);
        match &spec.command {
            ForgeCommand::Subprocess { image, .. } => {
                let image = image.as_ref().unwrap();
                assert_eq!(image.digest, digest, "digest survives the round-trip");
            }
            other => panic!("expected Subprocess, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rebuild_static_local_static_in_container_falls_back_to_host_side() {
        // W165 OQ#1 (R438-F9): local-static arm + in_container build_mode must
        // warn and fall back to host-side (TaskRuntime::Native). Dev machines
        // may not have docker, and the host watcher handles hot-reload.
        let fx = Fixture::new(local_static_slot(0), /*write_workload*/ false);
        let workload_dir = fx.workspace_root.join("app/web");
        let digest = workload_spec::testing::test_digest();
        std::fs::write(
            workload_dir.join("workload.toml"),
            format!(
                r#"schema_version = 1
kind = "mesofact-static"
routes = "./routes.ts"

[build]
command = "bun run build"
out_dir = "dist"

[build_mode.in_container.image]
registry = "ghcr.io"
repository = "org/app-build"
tag = "v1.2"
digest = "{digest}"
"#
            ),
        )
        .unwrap();

        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new()
            .with_executor(capture.clone())
            .with_local_static(LocalStaticOptions {
                binary: Some(PathBuf::from("/definitely/not/a/binary")),
                ready_timeout: Some(Duration::from_millis(50)),
                ..Default::default()
            });
        let _ = reconciler.rebuild_static(fx.ctx()).await;

        let captured = captured.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "build step still ran (host-side fallback)"
        );
        let (spec, _) = &captured[0];
        assert_eq!(
            spec.where_.runtime,
            TaskRuntime::Native,
            "in_container overridden to Native for local-static arm"
        );
        match &spec.command {
            ForgeCommand::Subprocess { image, .. } => {
                assert!(
                    image.is_none(),
                    "image must be stripped when falling back to host-side; got {image:?}"
                );
            }
            other => panic!("expected Subprocess, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rebuild_static_defaults_to_host_side_when_build_mode_omitted() {
        // Fixture writes a workload.toml without [build_mode] (the common
        // shape today). rebuild_static must default to HostSide.
        let fx = Fixture::new(local_static_slot(0), /*write_workload*/ true);
        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new()
            .with_executor(capture.clone())
            .with_local_static(LocalStaticOptions {
                binary: Some(PathBuf::from("/definitely/not/a/binary")),
                ready_timeout: Some(Duration::from_millis(50)),
                ..Default::default()
            });
        let _ = reconciler.rebuild_static(fx.ctx()).await;
        let captured = captured.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "default build_mode still runs the build step"
        );
        assert_eq!(captured[0].0.where_.runtime, TaskRuntime::Native);
    }

    #[tokio::test]
    async fn rebuild_static_skips_build_when_workload_toml_missing() {
        // No workload.toml on disk — rebuild_static must not panic in the
        // build step; the subsequent up() call surfaces the missing-manifest
        // error to the operator.
        let fx = Fixture::new(local_static_slot(0), /*write_workload*/ false);
        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());
        let err = reconciler.rebuild_static(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("workload.toml"), "got: {msg}");
        assert!(
            captured.lock().unwrap().is_empty(),
            "no build executed when manifest missing",
        );
    }

    // ── revalidate_static (R535-T1) ──────────────────────────────────────────

    #[tokio::test]
    async fn revalidate_static_without_render_command_never_touches_executor() {
        // W225 §3 / R535-T1: an almanac on_change is a data-only trigger — it
        // must never re-run build.command, regardless of provider arm or
        // whether the subsequent publish step succeeds. The fixture's
        // workload.toml carries a real [build] table (write_workload=true)
        // but NO render_command — so the executor must record zero calls
        // (R535-T7 only runs the executor for a declared render_command).
        let fx = Fixture::new(cloudflare_reference_slot(), /*write_workload*/ true);
        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());

        // up_cloudflare_r2 will fail (no provider config on disk) — that's
        // expected and irrelevant here; only the executor call count matters.
        let _ = reconciler.revalidate_static(fx.ctx(), "/releases").await;

        assert!(
            captured.lock().unwrap().is_empty(),
            "revalidate_static without render_command must never invoke the executor"
        );
    }

    #[tokio::test]
    async fn revalidate_static_delegates_to_up() {
        // Without a render_command, revalidate_static's publish behavior must
        // be indistinguishable from calling up() directly. Same fixture, same
        // reconciler, two independent ReconcileCtx borrows: both arms must
        // hit the identical error (missing
        // .yah/infra/providers/cloudflare.toml) with byte-identical text.
        let fx = Fixture::new(cloudflare_reference_slot(), /*write_workload*/ true);
        let reconciler = MesofactStaticReconciler::new();

        let revalidate_err =
            reconciler.revalidate_static(fx.ctx(), "/releases").await.unwrap_err();
        let up_err = reconciler.up(fx.ctx()).await.unwrap_err();

        assert_eq!(
            format!("{revalidate_err:#}"),
            format!("{up_err:#}"),
            "revalidate_static must delegate straight to up() with no extra behavior"
        );
    }

    #[tokio::test]
    async fn revalidate_static_skips_build_when_workload_toml_missing() {
        // Mirrors rebuild_static_skips_build_when_workload_toml_missing:
        // revalidate_static must not panic when workload.toml is absent (no
        // [build] table → no render_command → no executor call); the
        // missing-manifest error surfaces from deeper in up().
        let fx = Fixture::new(local_static_slot(0), /*write_workload*/ false);
        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());
        let err = reconciler.revalidate_static(fx.ctx(), "/releases").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("workload.toml"), "got: {msg}");
        assert!(
            captured.lock().unwrap().is_empty(),
            "no build executed by revalidate_static",
        );
    }

    // ── revalidate_static render_command (R535-T7) ───────────────────────────

    fn write_workload_with_render_command(fx: &Fixture) {
        std::fs::write(
            fx.workspace_root.join("app/web/workload.toml"),
            r#"schema_version = 1
kind = "mesofact-static"
routes = "./routes.ts"

[build]
command = "echo built"
out_dir = "dist"
render_command = "echo render {route} --all"
"#,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn revalidate_static_runs_render_command_with_route_substituted() {
        // R535-T7: a declared render_command runs exactly once before the
        // publish step — {route} substituted, host-side lowering (Native, no
        // image), cwd = workload dir — and NEVER build.command.
        let fx = Fixture::new(cloudflare_reference_slot(), /*write_workload*/ true);
        write_workload_with_render_command(&fx);
        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());

        // up_cloudflare_r2 still fails after the render step (no provider
        // config on disk) — only the executor capture matters here.
        let _ = reconciler.revalidate_static(fx.ctx(), "/issues/:id").await;

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1, "render executed exactly once");
        let (spec, ctx) = &captured[0];
        assert_eq!(spec.where_.runtime, TaskRuntime::Native);
        match &spec.command {
            ForgeCommand::Subprocess { argv, image } => {
                assert!(image.is_none(), "host_side render carries no image");
                assert_eq!(
                    argv,
                    &vec!["sh".to_string(), "-c".into(), "echo render /issues/:id --all".into()],
                    "route pattern substituted into {{route}}"
                );
            }
            other => panic!("expected Subprocess, got {other:?}"),
        }
        assert_eq!(ctx.cwd.as_deref(), Some(fx.workspace_root.join("app/web").as_path()));
    }

    #[tokio::test]
    async fn revalidate_static_local_static_skips_render_command() {
        // The local-static arm never runs the render step — the host
        // mesofact-dev watcher re-renders on data-file changes independently.
        let fx = Fixture::new(local_static_slot(0), /*write_workload*/ true);
        write_workload_with_render_command(&fx);
        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());

        let _ = reconciler.revalidate_static(fx.ctx(), "/issues/:id").await;

        assert!(
            captured.lock().unwrap().is_empty(),
            "local-static revalidate must not run render_command"
        );
    }

    /// Validate the in-tree fixture at `testdata/mesofact-in-container/workload.toml`.
    ///
    /// Verifies that `read_mesofact_build` returns `BuildMode::InContainer` for an
    /// on-disk workload that declares `[build_mode] mode = "in_container"`.  No
    /// build is executed — this is a parse + lowering-shape test that runs in CI
    /// without docker (R438-T8 "in-tree mesofact-static workload with
    /// build_mode=in_container builds green in CI").
    #[test]
    fn in_container_fixture_roundtrips_as_container_build_mode() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture_dir = manifest_dir.join("testdata/mesofact-in-container");
        let (build, build_mode) = read_mesofact_build(&fixture_dir)
            .expect("testdata/mesofact-in-container/workload.toml must parse cleanly")
            .expect("fixture must have a [build] section");
        assert!(
            matches!(build_mode, BuildMode::InContainer { .. }),
            "expected BuildMode::InContainer but got {build_mode:?}",
        );
        assert!(!build.command.is_empty(), "build.command must be non-empty");
    }

    /// Spin up a throwaway loopback server that answers `/__mesofact/info` with
    /// `identity` (Some → 200 JSON `{service,component}`, None → 404), for the
    /// adopt identity-check tests (R602-B4). Returns the bound port.
    async fn spawn_info_server(identity: Option<(&str, &str)>) -> u16 {
        use axum::response::IntoResponse;
        use axum::routing::get;
        use axum::Router;

        let json = identity.map(|(s, c)| format!(r#"{{"service":"{s}","component":"{c}"}}"#));
        let app = Router::new().route(
            "/__mesofact/info",
            get(move || {
                let json = json.clone();
                async move {
                    match json {
                        Some(b) => (
                            [(reqwest::header::CONTENT_TYPE, "application/json")],
                            b,
                        )
                            .into_response(),
                        None => axum::http::StatusCode::NOT_FOUND.into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        // Let the accept loop come up before the probe connects.
        tokio::time::sleep(Duration::from_millis(50)).await;
        port
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[tokio::test]
    async fn adopt_identified_matches_and_adopts() {
        let port = spawn_info_server(Some(("scrabcake", "site"))).await;
        let got = try_adopt_identified(loopback(port), "scrabcake", "site", "configured")
            .await
            .unwrap();
        assert!(got.is_some(), "matching identity should adopt");
    }

    #[tokio::test]
    async fn adopt_identified_mismatch_bails_naming_both() {
        // The headline repro: scrabcake dev finds yah-marketing on the port.
        let port = spawn_info_server(Some(("yah-marketing", "pond"))).await;
        let err = try_adopt_identified(loopback(port), "scrabcake", "site", "configured")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("yah-marketing/pond"), "msg was: {msg}");
        assert!(msg.contains("scrabcake"), "msg was: {msg}");
    }

    #[tokio::test]
    async fn adopt_identified_foreign_listener_bails() {
        // Listener present but no /__mesofact/info (a foreign server, e.g.
        // workerd, or an identity-less mesofact-dev) → refuse to adopt.
        let port = spawn_info_server(None).await;
        let err = try_adopt_identified(loopback(port), "scrabcake", "site", "configured")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not an identifiable mesofact-dev"),
            "msg was: {err}"
        );
    }

    #[tokio::test]
    async fn adopt_identified_no_listener_returns_none() {
        let port = pick_unused_port();
        let got = try_adopt_identified(loopback(port), "scrabcake", "site", "configured")
            .await
            .unwrap();
        assert!(got.is_none(), "no listener → nothing to adopt");
    }
}
