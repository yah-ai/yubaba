//! [`Reconciler`] implementation for `kind = "mesofact-static"` components.
//!
//! Dispatches on the mirror's `providers.static` slot:
//!
//! - **`kind = "miniflare-native"` (inline)** — the dev tier. Publish the
//!   built `dist/` into the bucket the mirror's `[drivers.s3]` binding names,
//!   then serve it with miniflare on `127.0.0.1:<port>`. See
//!   [`super::dev_door`].
//! - **`kind = "miniflare-container"` (inline)** — the pond tier. Same door,
//!   MinIO in a container underneath. See [`super::pond`].
//! - **`use = "cloudflare"` (reference)** — publish to R2 and deploy the same
//!   Worker to Cloudflare.
//!
//! All three run the identical `worker/router.bundle.js`; the only thing that
//! varies is which implementation of the `s3` capability sits behind it, and
//! that is declared in the mirror rather than branched on here (W265,
//! R584-F4). Until that ticket the dev tier instead spawned `mesofact-dev` to
//! serve `dist/` straight off the filesystem under `kind = "local-static"` —
//! a storage interface no other tier had, and the fork W265 exists to delete.
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
//! @yah:handoff("F9 landed. Decision: local-static arm + InContainer build_mode → warn + fall back to HostSide (W165 OQ#1). Implementation: rebuild_static gains a 3-line pattern-guard before calling run_build; if slot is local-static and build_mode is InContainer, emit warn!(\"build_mode = in_container ignored for local-static; running host-side\") and override to BuildMode::HostSide. No new fields, no new types. Two test changes: (1) rebuild_static_lifts_build_mode_through_executor switched from dev_door_slot(0) to cloudflare_reference_slot() — it now covers the CF publish arm (still asserts TaskRuntime::Container); (2) new rebuild_static_local_static_in_container_falls_back_to_host_side asserts TaskRuntime::Native + image=None when slot=local-static + build_mode=InContainer. cargo test -p cloud --lib reconciler::mesofact_static: 37 pass; 4 pre-existing R441-B4 adopt_only failures. cargo check -p cloud: clean.")
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
//! @yah:handoff("Root cause: all four tests used hardcoded port 4321 which a running camp's mesofact-dev occupies, causing up_local_static to adopt it as Ok instead of reaching the adopt_only error path. Fix: added pick_unused_port() helper (bind :0, read port, drop listener) and replaced dev_door_slot(4321) with pick_unused_port() in all four tests. stale_jit_different_port_names_it also replaced hardcoded 9999 with a second pick_unused_port() so the assertion checks the dynamic value. All 4 pass.")
//!
//! R535-T1 ("Split rebuild_static: revalidate-only path... called by
//! almanac_dispatch", W225 §3) landed here: see [`MesofactStaticReconciler::
//! revalidate_static`] and [`MesofactStaticReconciler::rebuild_static`]'s docs
//! for the split, and `crate::almanac_dispatch` for the caller-side switch.
//! Ticket record lives in `.yah/docs/working/W225-mesofact-consumer-deployment-model.md`
//! (single declaration site — not duplicated here per Rule11).
//!
//! @yah:ticket(R875-B1, "Adopted mesofact-dev gets a no-op shutdown and no logs — dev-tier Stop lies, log pane is empty")
//! @yah:at(2026-09-09T01:58:02Z)
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R875)
//! @yah:severity(high)
//! @yah:gotcha("Reproduced live on this camp 2026-09-08: three orphaned mesofact-dev processes, all PPID 1 (yah-marketing/site on 4321, scrabcake/site on 4353, and a leaked test-svc on 55506 from a 13:12 test run). The 4321 one survived both a desktop quit and a camp-daemon restart, which is the operator report that opened this relay.")
//! @yah:gotcha("\"Stop makes it go away for a second then it comes back\" is NOT a respawn and NOT kamaji. The dev cell's running-state is a live port probe, not the registry: mirror_run_list -> observe_mirrors -> probe_dev_cell (app/yah/desktop/src/mirror_observation.rs:268), polled every 3s by MirrorPanel. Stop empties the desktop registry, the row briefly renders from the stopped snapshot, the next poll re-probes 4321, finds the server still serving, and the row returns. The UI was reporting honestly; the stop was the lie.")
//! @yah:handoff("FIXED. Mechanism: try_adopt_identified returned RunningWorkload::adopted(), whose shutdown() is a documented no-op (shutdown/supervisor/teardown all None) and whose log_buffer is None. mirror_run_down called it, got Ok(()), set stopped=true and reported success. The spawn arm has always had a real teardown and a LogBuffer — but the desktop re-adopts on every launch, so the only run that ever got a live handle was the one that first spawned the server. This is R714-B1 one reconciler over, and that ticket's own handoff had already decided the adopt arm must carry teardown too; the decision was applied to container.rs and not here.")
//! @yah:handoff("Landed in four parts. (1) try_adopt_identified is now identity-verification only, returning Result<Option<SocketAddr>>; the new MesofactStaticReconciler::adopted_workload builds the handle where ReconcileCtx is in scope. (2) native_support::stop_process_listening_on(addr, grace) — SIGTERM, wait for the port to go quiet, SIGKILL, then FAIL if the port is still accepting. (3) native_support::spawn_capture_tail — a tail-only supervisor for a workload this process does not hold a NativeRuntime handle for, plus FileTail::from_end. (4) RunningWorkload::owns_teardown() replaces mirror_run_down's `kind == \"container\"` test.")
//! @yah:handoff("DESIGN CALL, and the one a reviewer should push on: teardown resolves the pid FROM THE PORT (`lsof -nP -iTCP:<port> -sTCP:LISTEN -t`) rather than from a pid recorded at spawn time. local_process.rs already has the pid-sidecar shape (owner.json, write_owner/reap_owner) and reusing it was the obvious move — rejected because a sidecar is only ever stale in exactly the orphan case this exists to fix, and a recycled pid on a long-lived mac names an innocent process. The port has no staleness window: the caller has already confirmed via /__mesofact/info that the listener IS this service+component, and success is verified by effect (the port stops accepting), so a kill that misses is reported as a failed stop instead of a silent success. Cost: a shell-out to lsof, and an honest error if lsof is absent.")
//! @yah:handoff("BUG MY OWN TESTS CAUGHT, worth knowing before touching the log half: the adopt tail must start at end-of-file, not offset 0. An adopted server is not reliably the process that wrote the capture file — the mesofact-dev holding 4321 here started at 17:43 while .yah/jit/native/mesofact-dev-yah-marketing-site/stdout.log had not been touched since 17:39 — so draining from 0 replays a dead run's output as the live server's. FileTail::from_end seeds the offset at the current length; the spawn path keeps FileTail::new (offset 0) because NativeRuntime truncated the file for that child. Both arms pinned by tests.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib -- native_support teardown_tests adopt_identified  # 17 passed, 0 failed (2026-09-08)")
//! @yah:verify("MANUAL, blocked on a desktop rebuild+install (app/yah/desktop/install-app.sh): with mesofact-dev orphaned on 4321 (PPID 1), press Stop on the yah-marketing dev cell — `lsof -nP -iTCP:4321 -sTCP:LISTEN` must come back empty and the cell must stay idle across the next 3s poll, not flip back to running.")
//! @yah:verify("MANUAL: a Stop that cannot free the port must surface the error chip, never a silent success — mirror_run_down now returns Err for any workload whose owns_teardown() is true.")

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

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::{info, warn};

use velveteen::{
    ForgeCommand, ForgeSpec, Initiator, MeshAccess, TaskLocation, TaskPlacement, TaskRuntime,
};
use velveteen_exec::{ExecContext, ForgeExecutor, LocalForgeDriver};
use workload_spec::{BuildConfig, BuildMode};

use super::{dev_door, pond, ReconcileCtx, Reconciler, RunningWorkload};
use crate::route_table::WorkerAssets;
use crate::{MirrorProviderSlot, Provider};

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


/// Reconciles `kind = "mesofact-static"` components.
///
/// The `executor` field handles the build step (W165): `build.command` is
/// lowered to a [`ForgeSpec`] and dispatched through
/// [`ForgeExecutor::execute`]. Default is [`LocalForgeDriver`]; callers
/// wanting to redirect (e.g. tests with a mock executor) use
/// [`Self::with_executor`].
pub struct MesofactStaticReconciler {
    /// Knobs for the miniflare door. Shared by the dev and pond arms — the
    /// door is one piece of machinery at both tiers, and the fields that
    /// differ (MinIO's image and credentials) are simply unread at dev.
    pub pond: pond::PondOptions,
    executor: Arc<dyn ForgeExecutor>,
}

impl MesofactStaticReconciler {
    pub fn new() -> Self {
        Self {
            pond: pond::PondOptions::default(),
            executor: Arc::new(LocalForgeDriver::default()),
        }
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
            // Dev: miniflare in front of whatever the mirror bound to `s3`.
            // Both halves are load-bearing — a `miniflare-native` door with no
            // store to read is a misconfiguration, not a tier, so the arm
            // requires the binding rather than inventing a default.
            MirrorProviderSlot::Inline {
                kind: Provider::MiniflareNative,
                fields,
            } => {
                anyhow::ensure!(
                    dev_door::binds_dev_store(&ctx),
                    "providers.static.kind = \"miniflare-native\" but the mirror binds no \
                     dev-tier s3 driver — add `[drivers.s3]` / `kind = \"local-s3-fs\"` \
                     (service={}, env={})",
                    ctx.service.name,
                    ctx.env,
                );
                dev_door::up_dev_door(&ctx, &self.pond, fields, WORKER_SCRIPT).await
            }
            // Pond: the same door, in front of a MinIO container.
            MirrorProviderSlot::Inline {
                kind: Provider::MiniflareContainer,
                fields,
            } => pond::up_pond(&ctx, &self.pond, fields, WORKER_SCRIPT).await,
            MirrorProviderSlot::Inline { kind, .. } => {
                anyhow::bail!(
                    "providers.static.kind = \"{kind:?}\" not supported by mesofact-static reconciler (only miniflare-native + miniflare-container for now)",
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
    /// rebuilding or restarting the serve stack. Both miniflare doors support
    /// it, because both serve out of a bucket: dev re-publishes into the
    /// `yah-s3-fs` driver via [`dev_door::sync_dev_door`], pond into the
    /// already-running MinIO via [`pond::sync_pond`]. Returns the number of
    /// assets uploaded.
    ///
    /// This is what the desktop's `⟳` affordance calls for local mirrors.
    /// Re-running `up` would collide on the already-bound door port, so `sync`
    /// is the correct re-sync entry point. Cloudflare goes through the
    /// publish-assets pipeline and has no in-place bucket re-sync.
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
                kind: Provider::MiniflareNative,
                fields,
            } => dev_door::sync_dev_door(&ctx, fields).await,
            MirrorProviderSlot::Inline {
                kind: Provider::MiniflareContainer,
                fields,
            } => pond::sync_pond(&ctx, &self.pond, fields).await,
            MirrorProviderSlot::Inline { kind, .. } => anyhow::bail!(
                "providers.static.kind = \"{kind:?}\" has no in-place re-sync — only the miniflare doors (dev, pond) support ⟳ sync",
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
    /// `dist/` to R2 and purges the CDN cache-tag `page:releases`; the two
    /// miniflare arms publish into their bucket inside [`Self::up`]. Every
    /// arm honours the workload's declared `build_mode`, including
    /// `in_container` — the dev tier used to override that to host-side
    /// (W165 OQ#1, R438-F9) because it had no bucket to publish into and no
    /// docker guarantee; with dev on the same publish path as pond, the
    /// override was a per-tier fork with nothing left to justify it.
    pub async fn rebuild_static(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        let workload_dir = ctx.workload_dir();
        let override_ = ctx.build_override();
        if let Some((mut build, build_mode)) = read_mesofact_build(&workload_dir)? {
            apply_build_override(&mut build, override_);
            run_build(
                &workload_dir,
                &build,
                &build_mode,
                &build_env(override_),
                &*self.executor,
            )
            .await?;
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
    /// Every arm runs the render, dev included. The dev tier used to skip it
    /// on the grounds that `mesofact-dev`'s own watcher re-rendered on
    /// data-file changes; there is no such watcher behind the miniflare door,
    /// and a tier that silently served pre-invalidation HTML while its
    /// siblings re-rendered was exactly the kind of divergence W265 removes.
    pub async fn revalidate_static(
        &self,
        ctx: ReconcileCtx<'_>,
        route: &str,
    ) -> Result<RunningWorkload> {
        let workload_dir = ctx.workload_dir();
        let override_ = ctx.build_override();
        if let Some((mut build, build_mode)) = read_mesofact_build(&workload_dir)? {
            apply_build_override(&mut build, override_);
            if let Some(render_command) = &build.render_command {
                let render = BuildConfig {
                    command: Some(render_command.replace("{route}", route)),
                    out_dir: build.out_dir.clone(),
                    render_command: None,
                };
                run_build(
                    &workload_dir,
                    &render,
                    &build_mode,
                    &build_env(override_),
                    &*self.executor,
                )
                .await?;
            }
        }
        self.up(ctx).await
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

        let mirror_prefix =
            publish_prefix(&ctx.service.name, ctx.env, ctx.component.mount.as_deref());
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
            let backends = BackendOrigins::from_slot_fields(slot_fields);
            let domain =
                crate::config::domain_for_service(ctx.workspace_root, &ctx.service.name)?;
            let bindings =
                worker_config_bindings(
                    &mode,
                    WorkerAssets::Deployed(&asset_origin),
                    &backends,
                    domain.as_ref(),
                )?;
            let worker_bindings: Vec<WorkerBinding<'_>> = bindings
                .iter()
                .map(ConfigBinding::as_worker_binding)
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

            // R703-B4 — how loudly this fails depends on whether the Worker is
            // the door the public actually comes through.
            //
            // It was unconditionally non-fatal, and that is how the yah.dev
            // Worker ended up 19 days behind the router bundle in-tree: the
            // token lacked `Workers Scripts: Edit`, every apply warned into a
            // logger the CLI never installed, and every apply reported ok. A
            // front door that cannot be updated is not a warning — it is the
            // failure. When the zone's manifest declares `front_door =
            // "worker"`, a failed deploy is fatal.
            //
            // For any other declared front door the Worker is a warm rollback
            // lever rather than the live door, so a warning remains right: it
            // should not be able to fail an apply for a surface serving no
            // traffic.
            if let Err(e) = worker_result {
                let is_live_front_door = matches!(
                    super::publish_beacon::declared_front_door(ctx.workspace_root, &zone),
                    Some((_, crate::config::FrontDoor::Worker))
                );
                if is_live_front_door {
                    return Err(e).with_context(|| {
                        format!(
                            "deploying the Cloudflare Worker for {zone} (script {worker_name}).\n\
                         \n\
                         .yah/domains/*.toml declares front_door = \"worker\" for this zone, so \
                         this Worker IS the public front door — it cannot be left at whatever \
                         version happens to be deployed. The publish above succeeded; what \
                         failed is updating the thing that serves it.\n\
                         \n\
                         An `Authentication error` here means the configured Cloudflare \
                         token cannot touch Workers. Test that DIRECTLY — a token-validity \
                         check will not tell you, because the token is almost certainly \
                         valid and merely under-scoped:\n\
                         \n\
                           curl -sS -H \"Authorization: Bearer $(yah keys get <slot>)\" \\\n\
                             https://api.cloudflare.com/client/v4/accounts/<acct>/workers/scripts\n\
                         \n\
                         DO NOT reach for https://api.cloudflare.com/client/v4/user/tokens/verify \
                         to triage this. An account-scoped token (`cfat_` prefix) is rejected \
                         there with a flat `code 1000, Invalid API Token`, which reads \
                         exactly like a revoked credential and sends you hunting for a token \
                         that is fine. That misdiagnosis has now happened twice. The valid \
                         health check for an account token is \
                         /accounts/<acct>/tokens/verify.\n\
                         \n\
                         THE FIX, if the workers/scripts GET is denied: mint a token that \
                         carries the grants, rather than editing one by hand —\n\
                         \n\
                           yah cloud cf token create --zone <zone> \\\n\
                             --store-slot cloudflare-mesofact-static \\\n\
                             --bootstrap-slot <a slot holding API Tokens: Edit>\n\
                         \n\
                         then point `credentials` in .yah/infra/providers/cloudflare.toml at \
                         that slot. It builds MESOFACT_STATIC_GRANTS, which includes \
                         `Workers Scripts: Write` (account) and `Workers Routes: Write` \
                         (zone). The command's own summary line prints only five scopes and \
                         omits both — that text is stale, the policy is not.\n\
                         \n\
                         Whatever the cause, it is silent everywhere else: the R2 publish \
                         uses separate S3 keys and keeps working, so the bucket stays \
                         current while the Worker — the thing that serves it — freezes."
                        )
                    });
                }
                warn!(
                    zone,
                    worker_name,
                    error = %e,
                    "CF Worker deploy/route failed (non-fatal — this zone's declared \
                     front door is not the Worker, so it serves no traffic today) — \
                     ensure cloudflare-api-token has Workers Scripts: Edit \
                     and Zone Workers Routes: Edit scope"
                );
            }
        }

        // R703-B4 — the publish is not the deliverable; the served page is.
        self.verify_serving(ctx, slot_fields, &zone, &asset_origin, &report.beacon)
            .await?;

        Ok(RunningWorkload::adopted("mesofact-static", "static", None)
            .with_public_url(format!("https://{zone}")))
    }

    /// Fetch the just-written publish beacon back through the origin and the
    /// public front door, and fail the apply if the front door is serving
    /// anything else.
    ///
    /// R703-B4. Everything upstream of here reports success on the *write*:
    /// R2 accepted the objects, the Worker API accepted the script, the apply
    /// exits 0. None of that is evidence that the bytes reached a reader, and
    /// twice now they did not — once because a declared-but-unready bundle
    /// tier disabled this chain, once because the apex had been cut over to an
    /// origin nothing republishes. Both presented as HTTP 200 on a stale page.
    ///
    /// The origin probe is checked first and separately on purpose: it splits
    /// "the publish did not land" from "the publish landed and the front door
    /// is elsewhere", which are different tickets with identical symptoms.
    async fn verify_serving(
        &self,
        ctx: &ReconcileCtx<'_>,
        slot_fields: &std::collections::BTreeMap<String, toml::Value>,
        zone: &str,
        asset_origin: &str,
        beacon: &super::publish_beacon::PublishBeacon,
    ) -> Result<()> {
        use super::publish_beacon as pb;

        // Opt-out for a deliberately in-flight front-door migration. Declared
        // in config rather than passed as a CLI flag so that turning it off is
        // a reviewable diff next to a comment naming the ticket, not an
        // invocation habit that quietly becomes permanent.
        let verify = slot_fields
            .get("verify_serving")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if !verify {
            warn!(
                zone,
                "verify_serving = false — publish NOT checked against the live \
                 front door; the site can go stale without this apply failing"
            );
            return Ok(());
        }

        let verdict = pb::check_serving(
            ctx.workspace_root,
            zone,
            Some(asset_origin),
            beacon,
            pb::EDGE_PROBE_ATTEMPTS,
            pb::EDGE_PROBE_DELAY,
        )
        .await;

        if verdict.is_ok() {
            info!(
                zone,
                digest = %beacon.digest,
                files = beacon.files,
                "front door is serving this publish"
            );
            return Ok(());
        }

        // A stale or absent front door means the deployed Worker (if any) may
        // be older than the bundle this build embeds, and the local hash cache
        // would otherwise skip redeploying it forever — that cache is a claim
        // about the live Worker made from an untracked file on one laptop.
        // Drop the entry so the next apply cannot take the skip branch.
        if !verdict.front_door.is_match() {
            let worker_name = slot_fields
                .get("worker_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{}-worker", ctx.service.name));
            forget_worker_script_hash(ctx.workspace_root, &worker_name);
        }

        Err(verdict.into_error(beacon))
    }
}

/// Read the `[build]` + `[build_mode]` subtrees from
/// `<workload_dir>/workload.toml`. Used by [`MesofactStaticReconciler::rebuild_static`]
/// to drive [`run_build`] without forcing the whole workload through the
/// `workload_spec::Workload` envelope, while still giving us typed [`BuildConfig`] and
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

/// Fold a mirror's `[build.<component>]` override into the `BuildConfig` read
/// from the component's `workload.toml` (R905).
///
/// Field-wise replacement, not a whole-table swap: a mirror that only names an
/// `env` keeps the workload's commands, and one that only names a `command`
/// keeps its `render_command`. `out_dir` is never overridden — see
/// [`MirrorBuildOverride`](crate::config::MirrorBuildOverride) for why.
///
/// `None` (no override, or an override that changes nothing) leaves `build`
/// byte-identical, which is what keeps every environment that declares no
/// override on exactly the pre-R905 path.
pub(crate) fn apply_build_override(
    build: &mut BuildConfig,
    override_: Option<&crate::config::MirrorBuildOverride>,
) {
    let Some(o) = override_ else { return };
    if let Some(command) = &o.command {
        build.command = Some(command.clone());
    }
    if let Some(render_command) = &o.render_command {
        build.render_command = Some(render_command.clone());
    }
}

/// The env pairs a mirror's build override exports to the build subprocess —
/// empty when there is no override (R905).
pub(crate) fn build_env(
    override_: Option<&crate::config::MirrorBuildOverride>,
) -> Vec<(String, String)> {
    override_.map(|o| o.env_pairs()).unwrap_or_default()
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
/// `None` when the manifest declares no `build.command` (R838-B1) — there is
/// no subprocess to lower, because the project builds through the in-process
/// `mesofact-dev` pipeline rather than an external bundler. Callers skip the
/// build step rather than lowering an empty `sh -c ""`, which would "succeed"
/// having produced nothing.
///
/// Pure function: no I/O, no subprocess. Exposed at `pub(crate)` for
/// golden-test parity with the recipe-lowering helper (R438-T7).
pub(crate) fn lower_build_to_forge_spec(
    workload_dir: &std::path::Path,
    build: &BuildConfig,
    build_mode: &BuildMode,
) -> Option<ForgeSpec> {
    let command = build.command.clone()?;
    let (image, runtime) = match build_mode {
        BuildMode::HostSide => (None, TaskRuntime::Native),
        BuildMode::InContainer { image } => (Some(image.clone()), TaskRuntime::Container),
    };
    Some(ForgeSpec {
        command: ForgeCommand::Subprocess {
            argv: vec!["sh".into(), "-c".into(), command],
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
        cache_key: None,
    })
}

/// Lower (`build`, `build_mode`) to a [`ForgeSpec`] and run it through the
/// supplied [`ForgeExecutor`] (W165). Thin wrapper over
/// [`lower_build_to_forge_spec`] — separated so the lowering is testable
/// without spawning a subprocess.
///
/// A manifest with no `build.command` is a no-op here (R838-B1): the project
/// has no external bundler step, so there is nothing for this reconciler to
/// shell out to. Same outcome as a workload with no `workload.toml` at all,
/// which `rebuild_static` has always skipped.
async fn run_build(
    workload_dir: &std::path::Path,
    build: &BuildConfig,
    build_mode: &BuildMode,
    env: &[(String, String)],
    executor: &dyn ForgeExecutor,
) -> Result<()> {
    let mode_tag = match build_mode {
        BuildMode::HostSide => "host_side",
        BuildMode::InContainer { .. } => "in_container",
    };
    let Some(spec) = lower_build_to_forge_spec(workload_dir, build, build_mode) else {
        tracing::info!(
            workload = %workload_dir.display(),
            "workload.toml declares no [build] command — skipping the build step \
             (the project builds in-process)"
        );
        return Ok(());
    };
    let cmd_str = build
        .command
        .clone()
        .expect("lower_build_to_forge_spec returns Some only when command is Some");
    tracing::info!(
        workload = %workload_dir.display(),
        cmd = %cmd_str,
        mode = mode_tag,
        env_overrides = env.len(),
        "running mesofact-static build"
    );

    let exec_ctx = ExecContext::default()
        .with_cwd(workload_dir.to_path_buf())
        .with_env(env.to_vec());

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

/// Backend origins the edge router proxies `/api/*` prefixes to (R455-T4).
///
/// Distinct from `SSR_ORIGIN`: SSR proxies *page* routes to a renderer, these
/// proxy *API* routes to a service that owns state. Both are read off the
/// mirror's static slot (`issues_origin` / `backend_origin`).
///
/// These MUST be emitted here rather than set by hand on the Worker. Every
/// apply re-uploads the whole binding list, so a binding this function does
/// not produce is *deleted* on the next `yah cloud apply` — which is how a
/// hand-set `ISSUES_ORIGIN` silently reverts to a 404 (R330-F13, R752-B2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackendOrigins {
    /// `ISSUES_ORIGIN` — issue-tracker surface; `/api/issues*` proxied here.
    pub issues: String,
    /// `MESOFACT_BACKEND_ORIGIN` — almanac surface; `/api/releases*`.
    pub releases: String,
}

impl BackendOrigins {
    /// The two prefixes these origins serve, and the path each becomes at the
    /// origin — `(route pattern, origin, origin path)`.
    ///
    /// This mapping was two hardcoded `if` blocks in the Worker until R898-F3
    /// deleted them (`/api/issues` → `ISSUES_ORIGIN` + `/issues` + rest). It is
    /// route data, so it now travels as table entries the Worker walks like any
    /// other. It still originates HERE, in slot fields, rather than in the
    /// domain manifest's `[[routes]]` — moving the declaration is R898-T4's
    /// half, and it needs the manifest to be able to name an origin that is not
    /// a deployed mesh unit.
    ///
    /// An empty origin emits no entry at all, which is the same "leave that
    /// prefix unrouted" the `env.X &&` guard used to give: a real 404 from the
    /// static tier, never a half-configured proxy.
    fn table_routes(&self) -> Vec<(&'static str, &str, &'static str)> {
        [
            ("/api/issues*", self.issues.as_str(), "/issues"),
            ("/api/releases*", self.releases.as_str(), "/releases"),
        ]
        .into_iter()
        .filter(|(_, origin, _)| !origin.is_empty())
        .collect()
    }

    /// Read the optional backend-origin fields off a mirror's static slot.
    /// Absent or empty → an empty binding, and the router's `env.X &&` guard
    /// leaves that prefix unrouted (a real 404, never a half-configured proxy).
    pub fn from_slot_fields(fields: &std::collections::BTreeMap<String, toml::Value>) -> Self {
        let field = |name: &str| {
            fields
                .get(name)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .trim_end_matches('/')
                .to_string()
        };
        Self {
            issues: field("issues_origin"),
            releases: field("backend_origin"),
        }
    }
}

/// The R2 key prefix a static component publishes under (R746).
///
/// `<service>/<env>` for an unmounted component — every pre-R746 component, and
/// the only shape `asset_origin` in a mirror manifest is written against.
/// `mount` appends its normalized form, which is what lets two static
/// components of one service coexist: before it, both wrote `index.html` to the
/// same key and the second deploy of the day silently replaced the first site
/// with the other.
///
/// The front door resolves a request by its own path (`${ASSET_ORIGIN}/<path>`),
/// so the mount is simultaneously the storage prefix and the URL prefix — by
/// construction, not by two manifests agreeing.
fn publish_prefix(service: &str, env: &str, mount: Option<&str>) -> String {
    let base = format!("{service}/{env}");
    match mount.map(crate::config::normalize_mount) {
        None => base,
        Some(m) if m.is_empty() => base,
        Some(m) => format!("{base}/{m}"),
    }
}

/// The `ROUTE_TABLE` binding — the ONE ordered table the edge router walks
/// (R898-F3), in the order it is matched.
///
/// Until R898-F3 the Worker carried four hardcoded prefix seams
/// (`ISSUES_ORIGIN`, `MESOFACT_BACKEND_ORIGIN`, `SSR_PREFIXES`,
/// `UPLOAD_ORIGIN`) plus a separate `ROUTE_HEADERS` table, so a fifth prefix
/// meant a fifth binding and a fifth `if`. They are all entries here now, and
/// the Worker walks them first-match-wins.
///
/// **Order is the contract.** The interception seams precede the manifest's
/// declared routes because that is the precedence the Worker had: the two
/// `/api/*` backends took priority over SSR, SSR over uploads, and everything
/// over the static catch-all. Getting this backwards serves `/api/releases`
/// from the asset bucket with a 200, which is the failure W348 exists to close.
///
/// Each synthesized entry carries the headers its path would have been given by
/// the declared table, because the Worker now applies the headers of the ONE
/// entry that claimed the path — where it used to route and header
/// independently. Without the stamp, a domain's catch-all headers would
/// silently stop reaching its proxied paths.
pub fn worker_route_table_json(
    mode: &WorkerMode,
    assets: WorkerAssets<'_>,
    upload_origin: &str,
    backends: &BackendOrigins,
    domain: Option<&crate::config::DomainConfig>,
) -> Result<String> {
    let entries = worker_route_table(mode, assets, upload_origin, backends, domain)?;
    Ok(serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string()))
}

/// The entries [`worker_route_table_json`] serializes, before serialization —
/// what [`worker_config_bindings`] also derives the R2 bucket bindings from, so
/// the table and the binding list are two views of one value (R560-F13).
fn worker_route_table(
    mode: &WorkerMode,
    assets: WorkerAssets<'_>,
    upload_origin: &str,
    backends: &BackendOrigins,
    domain: Option<&crate::config::DomainConfig>,
) -> Result<Vec<crate::route_table::RouteTableEntry>> {
    use crate::route_table::{ResolvedRouteMode, RouteAuth, RouteRewrite, RouteTableEntry};

    // `slot:<field>` rather than a component ref: these entries are declared by
    // a mirror's static slot, not by the manifest, and saying so in the wire
    // value is what makes a deployed table traceable back to its source.
    let synth = |path: String, origin: &str, slot: &'static str, origin_path: Option<&str>| {
        let prefix = path.strip_suffix('*').unwrap_or(&path);
        let prefix = prefix.trim_end_matches('/');
        let rewrite = origin_path.filter(|to| *to != prefix).map(|to| RouteRewrite {
            from: prefix.to_string(),
            to: to.to_string(),
        });
        RouteTableEntry {
            headers: domain
                .and_then(|d| d.route_for_path(prefix))
                .map(|r| r.headers.clone())
                .unwrap_or_default(),
            path,
            mode: ResolvedRouteMode::Backend {
                component: format!("slot:{slot}"),
                origin: origin.trim_end_matches('/').to_string(),
                rewrite,
            },
            auth: RouteAuth::Anonymous,
        }
    };

    let mut entries: Vec<RouteTableEntry> = Vec::new();
    for (path, origin, origin_path) in backends.table_routes() {
        entries.push(synth(
            path.to_string(),
            origin,
            if path.starts_with("/api/issues") {
                "issues_origin"
            } else {
                "backend_origin"
            },
            Some(origin_path),
        ));
    }
    if let WorkerMode::Ssr {
        origin_url,
        prefixes,
    } = mode
    {
        if !origin_url.is_empty() {
            for prefix in prefixes {
                // `<prefix>*` is the same segment-aware match the Worker's own
                // SSR matcher made (W173): exact prefix or descendant under it,
                // never a bare `starts_with`.
                entries.push(synth(format!("{prefix}*"), origin_url, "ssr_origin", None));
            }
        }
    }
    if !upload_origin.is_empty() {
        entries.push(synth(
            "/uploads/*".to_string(),
            upload_origin,
            "upload_origin",
            None,
        ));
    }
    if let Some(d) = domain {
        entries.extend(
            d.route_table(&crate::route_table::WorkerPlacement { assets, domain: d })?
                .entries,
        );
    }
    Ok(entries)
}

/// One binding a Worker is uploaded with, owned — what
/// [`worker_config_bindings`] produces and both deploy arms upload.
///
/// The owned twin of [`WorkerBinding`](crate::provider::cloudflare::WorkerBinding),
/// which borrows: a plan has to hold its bindings past the call that computed
/// them. Serialized into the redeploy hash, so an added or retargeted bucket
/// binding redeploys like any other config change.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConfigBinding {
    /// A runtime config string (`env.ASSET_ORIGIN`, `env.ROUTE_TABLE`, …).
    PlainText { name: String, text: String },
    /// An R2 bucket a `static` table entry reads through (R560-F13).
    R2Bucket { name: String, bucket_name: String },
}

impl ConfigBinding {
    /// The binding's name — what the Worker reads it as on `env`.
    pub fn name(&self) -> &str {
        match self {
            Self::PlainText { name, .. } | Self::R2Bucket { name, .. } => name,
        }
    }

    /// The borrowed form `CloudflareClient::deploy_worker_script` takes.
    pub fn as_worker_binding(&self) -> crate::provider::cloudflare::WorkerBinding<'_> {
        use crate::provider::cloudflare::WorkerBinding;
        match self {
            Self::PlainText { name, text } => WorkerBinding::PlainText { name, text },
            Self::R2Bucket { name, bucket_name } => WorkerBinding::R2Bucket { name, bucket_name },
        }
    }
}

/// Build the plain_text Worker binding values for the given routing mode.
///
/// These are uploaded alongside [`WORKER_SCRIPT`] as `plain_text` bindings
/// and appear as `env.ASSET_ORIGIN`, `env.WORKER_MODE`, etc. inside the Worker.
///
/// R898-T4: this is the **one** producer of a Worker's binding set. The
/// alias-tier planner ([`crate::reconciler::domain::plan_domain_worker`]) used
/// to keep a `static_worker_bindings` twin "in lockstep with this by hand", and
/// it had already drifted — the twin was still emitting `UPLOAD_ORIGIN`,
/// `SSR_ORIGIN`, `SSR_PREFIXES` and `ROUTE_HEADERS` after R898-F3 deleted all
/// four from the Worker. A hand-synced binding set is a silent 404 waiting for
/// the next binding to move, so there is one, and both arms call it.
pub(crate) fn worker_config_bindings(
    mode: &WorkerMode,
    assets: WorkerAssets<'_>,
    backends: &BackendOrigins,
    domain: Option<&crate::config::DomainConfig>,
) -> Result<Vec<ConfigBinding>> {
    // Reserved upload seam (R490-T8): prod has no upload origin yet, so no
    // `/uploads/*` entry is emitted and the path falls to the static tier. A
    // future dynamic-bucket consumer sets this to the user-writable origin.
    const UPLOAD_ORIGIN: &str = "";
    let mode_str = match mode {
        WorkerMode::Static => "static",
        WorkerMode::Spa => "spa",
        WorkerMode::Ssr { .. } => "ssr",
    };
    // The fall-through origin for a path no table entry claims; every static
    // route's own origin rides the table instead.
    let asset_origin = assets.fallback_origin(domain).unwrap_or_default();
    let entries = worker_route_table(mode, assets, UPLOAD_ORIGIN, backends, domain)?;
    let plain = |name: &str, text: String| ConfigBinding::PlainText {
        name: name.to_string(),
        text,
    };
    let mut bindings = vec![
        plain("ASSET_ORIGIN", asset_origin.clone()),
        // Pointer-store origin for instance-addressed routes (W270 §3): the
        // @mesofact/edge worker reads `p/<key>` records here. Pointers live
        // under the `p/` prefix in the same bucket as content, so this defaults
        // to ASSET_ORIGIN; it stays a distinct binding so a future consumer can
        // front the (uncached) pointer reads separately.
        plain("POINTER_ORIGIN", asset_origin),
        // Still a binding after R898-F3, and deliberately: `WORKER_MODE` no
        // longer selects a ROUTE — it selects what a static MISS becomes (the
        // branded 404 of a static site, or the SPA/SSR shell). The routing half
        // it used to gate lives in ROUTE_TABLE.
        plain("WORKER_MODE", mode_str.to_string()),
        plain(
            "ROUTE_TABLE",
            serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string()),
        ),
    ];
    // R560-F13: one R2 binding per distinct bucket a table entry reads through,
    // derived from the same entries ROUTE_TABLE carries. A domain with no
    // bucket route adds nothing, so every existing Worker's set is unchanged.
    bindings.extend(
        crate::route_table::r2_bucket_bindings(&entries)
            .into_iter()
            .map(|(name, bucket_name)| ConfigBinding::R2Bucket { name, bucket_name }),
    );
    Ok(bindings)
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

/// Drop a Worker's cached script hash so the next reconcile redeploys it.
///
/// R703-B4. The cache at `.yah/jit/worker-script-hashes.json` is an untracked
/// local file asserting something about a *remote* Worker, so it can be right
/// on one machine and wrong on the next — and while it is wrong, every apply
/// takes the "unchanged — skipping redeploy" branch and the live Worker never
/// catches up. It sat 19 days behind the in-tree router bundle that way. When
/// the front door is demonstrably not serving the current publish, the cache
/// has lost the right to be believed.
///
/// Best-effort: a cache we could not clear only costs one more manual redeploy,
/// and the serving check that called us is already returning an error.
fn forget_worker_script_hash(workspace_root: &std::path::Path, worker_name: &str) {
    let path = workspace_root.join(".yah/jit/worker-script-hashes.json");
    let Ok(s) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(mut map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&s) else {
        return;
    };
    if map.remove(worker_name).is_none() {
        return;
    }
    let _ = std::fs::write(
        &path,
        serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap_or_default(),
    );
    warn!(
        worker_name,
        "cleared cached Worker script hash — next apply will redeploy the script"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconciler::slot_field_u16;
    use crate::{MirrorConfig, MirrorShape, ServiceComponent, ServiceConfig};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
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
                ingress: Default::default(),
                ingress_machines: Vec::new(),
                drivers: Default::default(),
                asset_aliases: Default::default(),
                build: Default::default(),
            };
            let service = ServiceConfig {
                schema_version: 1,
                name: "test-svc".to_string(),
                address: crate::config::ServiceAddress::front_door("test.local".to_string()),
                description: None,
                components: vec![],
                db: crate::DbCatalog::default(),
            };
            let component = ServiceComponent {
                mount: None,
                id: "site".to_string(),
                kind: "mesofact-static".to_string(),
                path: "app/web".to_string(),
                role: "static".to_string(),
                publishes: None,
                wave: 0,
                git: None,
                deploy: Default::default(),
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

    /// The dev-tier static door. Note it carries no `[drivers.s3]` binding —
    /// fixtures that need the arm to actually run must add one.
    fn dev_door_slot(port: u16) -> MirrorProviderSlot {
        let mut fields = BTreeMap::new();
        fields.insert("port".to_string(), toml::Value::Integer(port as i64));
        MirrorProviderSlot::Inline {
            kind: Provider::MiniflareNative,
            fields,
        }
    }


    fn cloudflare_reference_slot() -> MirrorProviderSlot {
        MirrorProviderSlot::Reference {
            provider_id: "cloudflare".to_string(),
            fields: BTreeMap::new(),
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
        let fx = Fixture::new(dev_door_slot(4321), /*write_workload*/ false);
        let reconciler = MesofactStaticReconciler::new();
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("workload.toml"), "got: {msg}");
    }

    #[tokio::test]
    async fn up_bails_when_workload_kind_mismatches() {
        let fx = Fixture::new(dev_door_slot(4321), /*write_workload*/ false);
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
        let mut fx = Fixture::new(dev_door_slot(4321), true);
        fx.mirror.providers.clear();
        let reconciler = MesofactStaticReconciler::new();
        let err = reconciler.up(fx.ctx()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("providers.static"), "got: {msg}");
    }

    /// R602-B4 follow-up: a service with two static-kind components sharing
    /// one mirror (e.g. `site` + `app`) must be able to give them distinct
    /// ports. `slot()` resolves the component-qualified key
    /// (`"static:<id>"`) before the bare role, so `providers."static:site"`
    /// wins over `providers.static` for a component whose id is `site`.
    #[test]
    fn slot_prefers_component_qualified_key_over_bare_role() {
        let mut fx = Fixture::new(dev_door_slot(4321), true);
        fx.mirror
            .providers
            .insert("static:site".to_string(), dev_door_slot(9999));
        let slot = fx.ctx().slot("static").expect("slot present");
        let MirrorProviderSlot::Inline { fields, .. } = slot else {
            panic!("expected inline slot");
        };
        assert_eq!(slot_field_u16(fields, "port"), Some(9999));
    }

    /// A component whose id has no qualified entry falls back to the bare
    /// role — the pre-existing single-slot-per-mirror behavior is unchanged
    /// for services that never declared a qualified key.
    #[test]
    fn slot_falls_back_to_bare_role_for_unqualified_component() {
        let mut fx = Fixture::new(dev_door_slot(4321), true);
        fx.mirror
            .providers
            .insert("static:other-component".to_string(), dev_door_slot(9999));
        let slot = fx.ctx().slot("static").expect("slot present");
        let MirrorProviderSlot::Inline { fields, .. } = slot else {
            panic!("expected inline slot");
        };
        assert_eq!(slot_field_u16(fields, "port"), Some(4321));
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
                kind: Provider::MiniflareNative,
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










    // ---------- Worker script + config bindings ----------

    #[test]
    fn worker_script_maps_root_to_index_html() {
        assert!(
            WORKER_SCRIPT.contains("index.html"),
            "bundled Worker must route / to index.html; got: {WORKER_SCRIPT}"
        );
    }

    #[test]
    fn worker_script_reads_r2_only_through_route_bindings() {
        // R560-F13: R2 reads are allowed only through a ROUTE_TABLE entry's
        // per-bucket binding. The Worker must never write to a bucket, and
        // the retired single `env.ASSETS` binding must not come back.
        assert!(
            !WORKER_SCRIPT.contains("env.ASSETS"),
            "bundled Worker must not reference retired binding env.ASSETS"
        );
        assert!(
            WORKER_SCRIPT.contains("env[entry.binding]"),
            "bundled Worker must read buckets through the matched entry's binding"
        );
        assert!(!WORKER_SCRIPT.contains(".put("), "bundled Worker must not write to R2 (put)");
        assert!(
            !WORKER_SCRIPT.contains(".delete("),
            "bundled Worker must not write to R2 (delete)"
        );
        assert!(
            !WORKER_SCRIPT.contains("createMultipartUpload"),
            "bundled Worker must not write to R2 (multipart)"
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

    /// The bindings are only useful if the vendored bundle actually reads
    /// them — `scripts/check-worker-bundle.sh` keeps source and vendored copy
    /// in sync, and this catches a bundle vendored from before R898-F3.
    ///
    /// The negative half is the load-bearing one: a bundle still naming
    /// `ISSUES_ORIGIN` is a bundle that was never rebuilt, and it would route
    /// `/api/issues` off a binding this reconciler no longer emits — i.e. the
    /// silent 404 the whole relay exists to close.
    #[test]
    fn bundled_worker_walks_the_route_table() {
        assert!(
            WORKER_SCRIPT.contains("ROUTE_TABLE"),
            "bundled Worker must walk the compiled route table; got: {WORKER_SCRIPT}"
        );
        for retired in [
            "ISSUES_ORIGIN",
            "MESOFACT_BACKEND_ORIGIN",
            "SSR_PREFIXES",
            "UPLOAD_ORIGIN",
            "ROUTE_HEADERS",
        ] {
            assert!(
                !WORKER_SCRIPT.contains(retired),
                "vendored bundle still reads the retired binding {retired} — \
                 it predates R898-F3; re-run scripts/check-worker-bundle.sh"
            );
        }
    }

    // ── R746: component mount → publish prefix ──

    #[test]
    fn unmounted_component_publishes_at_the_service_root() {
        assert_eq!(publish_prefix("noisetable-marketing", "prod", None), "noisetable-marketing/prod");
    }

    #[test]
    fn a_mount_extends_the_prefix_and_is_slash_insensitive() {
        for m in ["/app", "app", "app/", "/app/"] {
            assert_eq!(
                publish_prefix("noisetable-marketing", "prod", Some(m)),
                "noisetable-marketing/prod/app",
                "mount {m:?}"
            );
        }
    }

    /// A root mount is the same thing as no mount — not a trailing-slash key
    /// prefix, which would publish every asset one directory too deep.
    #[test]
    fn a_root_mount_is_the_service_root() {
        assert_eq!(publish_prefix("svc", "prod", Some("/")), "svc/prod");
        assert_eq!(publish_prefix("svc", "prod", Some("")), "svc/prod");
    }

    /// The whole point: two static components of one service must not collide.
    #[test]
    fn two_components_of_one_service_get_disjoint_prefixes() {
        let site = publish_prefix("noisetable-marketing", "prod", None);
        let app = publish_prefix("noisetable-marketing", "prod", Some("/app"));
        assert_ne!(site, app);
        assert!(app.starts_with(&format!("{site}/")), "{app} under {site}");
    }

    fn worker_domain(routes: Vec<crate::config::DomainRoute>) -> crate::config::DomainConfig {
        crate::config::DomainConfig {
            schema_version: 1,
            name: "example".into(),
            domain: "example.com".into(),
            front_door: crate::config::FrontDoor::Worker,
            cdn_bucket: "example".into(),
            worker_bundle_path: None,
            routes,
        }
    }

    /// The plain-text half of a binding set, by name.
    fn plain_text(bindings: &[ConfigBinding]) -> std::collections::HashMap<String, String> {
        bindings
            .iter()
            .filter_map(|b| match b {
                ConfigBinding::PlainText { name, text } => Some((name.clone(), text.clone())),
                ConfigBinding::R2Bucket { .. } => None,
            })
            .collect()
    }

    fn table_of(bindings: &[ConfigBinding]) -> Vec<serde_json::Value> {
        let raw = plain_text(bindings)
            .remove("ROUTE_TABLE")
            .expect("ROUTE_TABLE binding");
        serde_json::from_str(&raw).expect("ROUTE_TABLE parses as JSON")
    }

    /// R746's header table is a COLUMN of the one table now, not a second
    /// binding: the entry that claims a path carries the headers for it.
    #[test]
    fn config_bindings_carry_the_declared_routes_and_their_headers() {
        let domain = worker_domain(vec![crate::config::DomainRoute {
            path: "/app/*".into(),
            headers: [(
                "Cross-Origin-Opener-Policy".to_string(),
                "same-origin".to_string(),
            )]
            .into_iter()
            .collect(),
            mode: crate::config::RouteMode::Static {
                component: "acme/app".into(),
            },
        }]);
        let b = worker_config_bindings(
            &WorkerMode::Static,
            WorkerAssets::Deployed("https://assets.example.com"),
            &BackendOrigins::default(),
            Some(&domain),
        )
        .unwrap();
        let table = table_of(&b);
        assert_eq!(table.len(), 1);
        assert_eq!(table[0]["path"], "/app/*");
        assert_eq!(table[0]["mode"], "static");
        assert_eq!(table[0]["origin"], "https://assets.example.com");
        assert_eq!(
            table[0]["headers"]["Cross-Origin-Opener-Policy"],
            "same-origin"
        );
    }

    #[test]
    fn config_bindings_static_mode() {
        let b = worker_config_bindings(
            &WorkerMode::Static,
            WorkerAssets::Deployed("https://assets.example.com"),
            &BackendOrigins::default(),
            None,
        )
        .unwrap();
        let map = plain_text(&b);
        assert_eq!(map["WORKER_MODE"], "static");
        assert_eq!(map["ASSET_ORIGIN"], "https://assets.example.com");
        // Pointer origin defaults to the asset origin (W270 §3).
        assert_eq!(map["POINTER_ORIGIN"], "https://assets.example.com");
        // Nothing declared and no backends — an EMPTY table, emitted rather
        // than omitted: the binding list is authoritative, so a missing key
        // would leave a previous deploy's table in place.
        assert_eq!(map["ROUTE_TABLE"], "[]");
        assert!(table_of(&b).is_empty());
    }

    #[test]
    fn config_bindings_spa_mode() {
        let b = worker_config_bindings(
            &WorkerMode::Spa,
            WorkerAssets::Deployed("https://assets.example.com"),
            &BackendOrigins::default(),
            None,
        )
        .unwrap();
        let map = plain_text(&b);
        assert_eq!(map["WORKER_MODE"], "spa");
    }

    /// R330-F13, re-pinned on the table: `/api/issues*` reaches the issue
    /// tracker only when the static slot's `issues_origin` becomes an entry —
    /// and it must carry the PREFIX REWRITE, or the upstream sees
    /// `/api/issues` instead of `/issues` (R898-F3 decision 1).
    #[test]
    fn config_bindings_carry_backend_origins_with_their_rewrites() {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "issues_origin".to_string(),
            // Trailing slash trimmed — the entry's origin is concatenated with
            // the rewritten path.
            toml::Value::String("https://issues.example.com/".to_string()),
        );
        fields.insert(
            "backend_origin".to_string(),
            toml::Value::String("https://almanac.example.com".to_string()),
        );
        let backends = BackendOrigins::from_slot_fields(&fields);
        assert_eq!(backends.issues, "https://issues.example.com");

        let b = worker_config_bindings(
            &WorkerMode::Static,
            WorkerAssets::Deployed("https://assets.example.com"),
            &backends,
            None,
        )
        .unwrap();
        let table = table_of(&b);
        assert_eq!(table[0]["path"], "/api/issues*");
        assert_eq!(table[0]["mode"], "backend");
        assert_eq!(table[0]["origin"], "https://issues.example.com");
        assert_eq!(
            table[0]["rewrite"],
            serde_json::json!({"from": "/api/issues", "to": "/issues"})
        );
        assert_eq!(table[1]["path"], "/api/releases*");
        assert_eq!(table[1]["origin"], "https://almanac.example.com");
        assert_eq!(
            table[1]["rewrite"],
            serde_json::json!({"from": "/api/releases", "to": "/releases"})
        );
    }

    /// An undeclared backend emits NO entry, which is the same "leave that
    /// prefix unrouted" the Worker's `env.X &&` guard used to give: the path
    /// falls to the static tier and 404s honestly instead of proxying to "".
    #[test]
    fn an_undeclared_backend_emits_no_entry() {
        let b = worker_config_bindings(
            &WorkerMode::Static,
            WorkerAssets::Deployed("https://assets.example.com"),
            &BackendOrigins::default(),
            None,
        )
        .unwrap();
        assert!(table_of(&b).is_empty());
    }

    /// SSR prefixes are entries like everything else, and the interception
    /// entries precede the manifest's declared routes — the precedence the
    /// four hardcoded `if` blocks had.
    #[test]
    fn config_bindings_ssr_mode() {
        let mode = WorkerMode::Ssr {
            origin_url: "https://ssr.example.com".to_string(),
            prefixes: vec!["/api/".to_string(), "/rpc/".to_string()],
        };
        let domain = worker_domain(vec![crate::config::DomainRoute {
            path: "/*".into(),
            headers: Default::default(),
            mode: crate::config::RouteMode::Static {
                component: "acme/site".into(),
            },
        }]);
        let b = worker_config_bindings(
            &mode,
            WorkerAssets::Deployed("https://assets.example.com"),
            &BackendOrigins::default(),
            Some(&domain),
        )
        .unwrap();
        let map = plain_text(&b);
        assert_eq!(map["WORKER_MODE"], "ssr");
        let table = table_of(&b);
        assert_eq!(table[0]["path"], "/api/*");
        assert_eq!(table[0]["origin"], "https://ssr.example.com");
        assert!(
            table[0].get("rewrite").is_none(),
            "an SSR proxy is an identity proxy — the origin serves the public path"
        );
        assert_eq!(table[1]["path"], "/rpc/*");
        assert_eq!(
            table[2]["path"], "/*",
            "the catch-all is LAST — first match wins, so a declared route \
             above the SSR prefixes would swallow them"
        );
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
    use tokio::sync::mpsc::UnboundedSender;
    use velveteen::ForgeStatus;
    use velveteen_exec::executor::{ExecEvent, ExecOutcome, ForgeExecutorError};

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
                command: Some("bun run build".into()),
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
                command: Some("bun run build".into()),
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
        run_build(tmp.path(), &build, &mode, &[], &*capture)
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
        run_build(tmp.path(), &build, &mode, &[], &*capture)
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
        let err = run_build(tmp.path(), &build, &mode, &[], &*executor)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Cannot find module 'react'"), "got: {msg}");
        assert!(msg.contains("bun run build"), "got: {msg}");
    }

    #[tokio::test]
    async fn read_mesofact_build_extracts_host_side_default() {
        let tmp = tempdir().unwrap();
        // Keeps a legacy `schema_version = 1` key — older workload.tomls
        // (including ones outside this repo) still carry it, and since
        // R896-T4 deleted the field it must be ignored, not rejected.
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
        assert_eq!(build.command.as_deref(), Some("bun run build"));
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
        assert_eq!(build.command.as_deref(), Some("bun run build"));
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

    /// R838-B1: a `[build]` table declaring only `out_dir` is the shape
    /// `mesofact new` scaffolds — the project builds through the in-process
    /// pipeline and has no shell command to run.
    #[tokio::test]
    async fn read_mesofact_build_accepts_a_build_table_with_no_command() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("workload.toml"),
            r#"schema_version = 1
kind = "mesofact-static"
routes = "./mesofact.routes.ts"

[build]
out_dir = "dist"
"#,
        )
        .unwrap();
        let (build, mode) = read_mesofact_build(tmp.path()).unwrap().unwrap();
        assert_eq!(build.command, None);
        assert_eq!(build.out_dir, PathBuf::from("dist"));
        assert!(matches!(mode, BuildMode::HostSide));
    }

    /// R838-B1: no `build.command` → no build step, not `sh -c ""`.
    ///
    /// An empty shell command exits 0 having produced nothing, so the
    /// reconciler would report a successful build and then publish whatever
    /// stale bytes were in `out_dir`. The skip has to happen at the lowering,
    /// which is what `lower_build_to_forge_spec` returning `None` pins.
    #[tokio::test]
    async fn rebuild_static_skips_the_build_step_when_no_command_is_declared() {
        let fx = Fixture::new(cloudflare_reference_slot(), /*write_workload*/ false);
        let workload_dir = fx.workspace_root.join("app/web");
        std::fs::write(
            workload_dir.join("workload.toml"),
            r#"schema_version = 1
kind = "mesofact-static"
routes = "./mesofact.routes.ts"

[build]
out_dir = "dist"
"#,
        )
        .unwrap();

        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());

        // As in the sibling tests, up_cloudflare_r2 fails for want of provider
        // config — but only AFTER the build step would have run.
        let _ = reconciler.rebuild_static(fx.ctx()).await;

        assert!(
            captured.lock().unwrap().is_empty(),
            "a manifest with no build.command must dispatch nothing to the executor"
        );
    }

    /// The lowering itself is the seam, so pin it directly too — a future
    /// caller that reaches `lower_build_to_forge_spec` without going through
    /// `run_build` inherits the same refusal.
    #[test]
    fn lowering_a_build_with_no_command_yields_no_forge_spec() {
        let build = BuildConfig {
            command: None,
            out_dir: PathBuf::from("dist"),
            render_command: None,
        };
        assert!(lower_build_to_forge_spec(
            std::path::Path::new("/workspace/app/web"),
            &build,
            &BuildMode::HostSide,
        )
        .is_none());
    }

    #[tokio::test]
    async fn rebuild_static_lifts_build_mode_through_executor() {
        // End-to-end smoke through rebuild_static → run_build → executor for
        // the cloudflare publish arm. InContainer build_mode must reach the
        // executor as TaskRuntime::Container (the CF path does not skip container
        // builds — every arm now honours the declared build_mode, R584-F4).
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
    async fn rebuild_static_defaults_to_host_side_when_build_mode_omitted() {
        // Fixture writes a workload.toml without [build_mode] (the common
        // shape today). rebuild_static must default to HostSide.
        let fx = Fixture::new(dev_door_slot(0), /*write_workload*/ true);
        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());
        let _ = reconciler.rebuild_static(fx.ctx()).await;
        let captured = captured.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "default build_mode still runs the build step"
        );
        assert_eq!(captured[0].0.where_.runtime, TaskRuntime::Native);
    }

    // ── per-environment build overrides (R905) ───────────────────────────────

    #[test]
    fn apply_build_override_replaces_only_the_fields_it_names() {
        let mut build = BuildConfig {
            command: Some("bun run build:cloud".into()),
            out_dir: PathBuf::from("dist"),
            render_command: Some("mesofact-build render . --route {route}".into()),
        };
        apply_build_override(
            &mut build,
            Some(&crate::config::MirrorBuildOverride {
                command: Some("bun run build:staging".into()),
                render_command: None,
                env: Default::default(),
            }),
        );
        assert_eq!(build.command.as_deref(), Some("bun run build:staging"));
        assert_eq!(
            build.render_command.as_deref(),
            Some("mesofact-build render . --route {route}"),
            "an override naming only `command` must not erase the renderer",
        );
        assert_eq!(
            build.out_dir,
            PathBuf::from("dist"),
            "out_dir is never per-environment",
        );
    }

    #[test]
    fn apply_build_override_is_a_no_op_without_one() {
        let (mut build, _) = host_side_build();
        let before = build.clone();
        apply_build_override(&mut build, None);
        assert_eq!(build.command, before.command);
        assert_eq!(build.render_command, before.render_command);
        assert!(build_env(None).is_empty());
    }

    #[tokio::test]
    async fn rebuild_static_runs_the_mirrors_overridden_command_with_its_env() {
        // The R905 defect in one test: the component declares one command, the
        // environment needs another, and before this the mirror had nowhere to
        // say so. Fixture's component id is "site".
        let mut fx = Fixture::new(dev_door_slot(0), /*write_workload*/ true);
        fx.mirror.build.insert(
            "site".to_string(),
            crate::config::MirrorBuildOverride {
                command: Some("echo staging".into()),
                render_command: None,
                env: [(
                    "NOISETABLE_API_ORIGIN".to_string(),
                    "https://api-staging.noisetable.com".to_string(),
                )]
                .into_iter()
                .collect(),
            },
        );

        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());
        let _ = reconciler.rebuild_static(fx.ctx()).await;

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1, "build step executed exactly once");
        let (spec, exec_ctx) = &captured[0];
        match &spec.command {
            ForgeCommand::Subprocess { argv, .. } => assert_eq!(
                argv,
                &vec!["sh".to_string(), "-c".to_string(), "echo staging".to_string()],
                "the mirror's command reached the executor, not the workload's `echo built`",
            ),
            other => panic!("expected Subprocess, got {other:?}"),
        }
        assert_eq!(
            exec_ctx.env,
            vec![(
                "NOISETABLE_API_ORIGIN".to_string(),
                "https://api-staging.noisetable.com".to_string()
            )],
            "the override's env reaches the build subprocess",
        );
    }

    #[tokio::test]
    async fn rebuild_static_leaves_a_sibling_component_on_its_own_command() {
        // The override is keyed by component id. A mirror that overrides `app`
        // must not change how `site` builds — otherwise a merged bundle would
        // build every component for whichever component the operator named.
        let mut fx = Fixture::new(dev_door_slot(0), /*write_workload*/ true);
        fx.mirror.build.insert(
            "app".to_string(),
            crate::config::MirrorBuildOverride {
                command: Some("echo wrong-component".into()),
                render_command: None,
                env: Default::default(),
            },
        );

        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());
        let _ = reconciler.rebuild_static(fx.ctx()).await;

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        match &captured[0].0.command {
            ForgeCommand::Subprocess { argv, .. } => {
                assert_eq!(argv[2], "echo built", "site kept its declared command")
            }
            other => panic!("expected Subprocess, got {other:?}"),
        }
        assert!(captured[0].1.env.is_empty());
    }

    #[tokio::test]
    async fn rebuild_static_skips_build_when_workload_toml_missing() {
        // No workload.toml on disk — rebuild_static must not panic in the
        // build step; the subsequent up() call surfaces the missing-manifest
        // error to the operator.
        let fx = Fixture::new(dev_door_slot(0), /*write_workload*/ false);
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

        let revalidate_err = reconciler
            .revalidate_static(fx.ctx(), "/releases")
            .await
            .unwrap_err();
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
        let fx = Fixture::new(dev_door_slot(0), /*write_workload*/ false);
        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());
        let err = reconciler
            .revalidate_static(fx.ctx(), "/releases")
            .await
            .unwrap_err();
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

    /// R905: the data-only re-render runs through the same override, so an
    /// environment that renders differently is not silently on production's
    /// renderer the moment an almanac feed changes.
    #[tokio::test]
    async fn revalidate_static_honours_the_mirrors_render_override_and_env() {
        let mut fx = Fixture::new(cloudflare_reference_slot(), /*write_workload*/ true);
        write_workload_with_render_command(&fx);
        fx.mirror.build.insert(
            "site".to_string(),
            crate::config::MirrorBuildOverride {
                command: None,
                render_command: Some("echo staging-render {route}".into()),
                env: [("API_ORIGIN".to_string(), "https://staging".to_string())]
                    .into_iter()
                    .collect(),
            },
        );

        let (capture, captured) = CaptureExecutor::new();
        let reconciler = MesofactStaticReconciler::new().with_executor(capture.clone());
        let _ = reconciler.revalidate_static(fx.ctx(), "/issues/:id").await;

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1, "render executed exactly once");
        let (spec, exec_ctx) = &captured[0];
        match &spec.command {
            ForgeCommand::Subprocess { argv, .. } => assert_eq!(
                argv[2], "echo staging-render /issues/:id",
                "the mirror's render_command ran, with {{route}} still substituted",
            ),
            other => panic!("expected Subprocess, got {other:?}"),
        }
        assert_eq!(
            exec_ctx.env,
            vec![("API_ORIGIN".to_string(), "https://staging".to_string())],
        );
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
                    &vec![
                        "sh".to_string(),
                        "-c".into(),
                        "echo render /issues/:id --all".into()
                    ],
                    "route pattern substituted into {{route}}"
                );
            }
            other => panic!("expected Subprocess, got {other:?}"),
        }
        assert_eq!(
            ctx.cwd.as_deref(),
            Some(fx.workspace_root.join("app/web").as_path())
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
        assert!(
            build.command.as_deref().is_some_and(|c| !c.is_empty()),
            "build.command must be declared and non-empty"
        );
    }






}
