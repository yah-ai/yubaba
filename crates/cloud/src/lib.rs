//! @yah:relay(R040, "yah-cloud Phase 1: mirror bootstrap (Hetzner driver, Podman runtime, yah-warden)")
//! @yah:status(review)
//! @yah:parent(Q058)
//! @yah:next("yah-A track (8 tickets) — substrate for noisetable cloud + future managed camps; gates noisetable C6 (E2E) and D1–D5 (corpus migration)")
//! @yah:next("Adjacent relays: R019 (SSH-RPC remote camps), R032 (yah-agentd), R034 (identity registry — hostkeys overlap)")
//! @yah:next("Reparented under Q058 cloud quest 2026-05-07. Largely superseded by R091 (warden orchestration + integration testing) and R092 (managed-camps CLI + .yah/cloud/ schema) — net new work should land on those relays. Remaining unique R040 scope (Cloudflare Tunnel cookbook F15, pg-on-mesh recipe F16, mesh-promote phasing F18-F19) stays here as historical/operational reference; consider archiving once R091+R092 reach review.")
//! @yah:next("Refinement open questions: subcommand framework alignment with yah arch/board, where hostkey fingerprints live, reverse proxy choice. Crate-layout question soft-answered by this stub being a sibling crate; A1 may still refactor into a sub-module of an existing crate if desired (move the //! block + delete this stub).")
//! @arch:see(architecture/PHASE_1_MIRROR_BOOTSTRAP.md)
//! @arch:see(architecture/yah-managed-camps-topology.md)
//!
//! @yah:ticket(R040-F1, "A1: .yah/cloud/ schema + parser (MachineConfig, MirrorConfig, ServiceConfig)")
//! @yah:at(2026-05-05T00:29:11Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R040)
//! @yah:next("Per-file TOML layout: machines/<name>.toml, mirrors/<camp>.toml, services/<name>.toml — diffability + parallel editing")
//! @yah:next("Sketch types in arch doc; refine to fit actual yah crate structure (this stub crate is one option; folding into an existing crate is the other)")
//! @yah:verify("cargo test -p cloud config::tests round-trips all three config types")
//! @arch:see(architecture/PHASE_1_MIRROR_BOOTSTRAP.md)
//! @yah:handoff("Schema + parser complete: MachineConfig, MirrorConfig, ServiceConfig, BucketSpec, PortMapping in crates/yah/cloud/src/config.rs. Per-file TOML layout via CloudConfig::load. MachineConfig::save for write-back (A4 hostkey). 6 tests pass (round-trips + tempdir integration + save/reload). tempfile dev-dep added. No warnings.")
//! @yah:next("A2: yah cloud subcommand stub — wire into yah CLI using same clap/subcommand pattern as yah board/arch. Commands: machine {status,provision,destroy}, mirror {show,status}, service {deploy,status}, agent {ping,services,logs}. All no-op except status/show which dump parsed .yah/cloud/ config. Verify: yah cloud mirror show noisetable prints declared regions/services.")
//!
//! @yah:ticket(R040-F3, "A3: Hetzner driver — MachineProvider trait + hcloud impl (server, bucket, status, destroy)")
//! @yah:at(2026-05-05T00:29:11Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R040)
//! @yah:next("API token from HETZNER_API_TOKEN env; document in .yah/cloud/SECRETS.md")
//! @yah:next("Gotcha: Hetzner has TWO APIs (Cloud and Robot) — Phase 1 is Cloud only; Object Storage is S3-compat, separate surface")
//! @yah:next("Verify before A6: Hetzner Hillsboro + Ashburn Object Storage both GA; CPX-22 available in PDX/IAD/FSN")
//! @yah:verify("cargo test -p cloud provider::hetzner -- --ignored (gated; needs token)")
//! @arch:see(architecture/PHASE_1_MIRROR_BOOTSTRAP.md)
//! @yah:handoff("MachineProvider trait + HetznerDriver impl complete in crates/yah/cloud/src/provider/. Cloud API (create_server, server_status, destroy_server) uses HETZNER_API_TOKEN via reqwest+bearer. create_bucket uses Hetzner Object Storage S3-compat with AWS Sig V4 signing (HETZNER_S3_ACCESS_KEY + HETZNER_S3_SECRET_KEY). Location enum maps pdx/iad/fsn to hetzner cloud IDs and S3 endpoints. 9 unit tests pass; 2 integration tests behind #[ignore] gate. .yah/cloud/SECRETS.md created documenting all three token types.")
//! @yah:next("A2: wire yah cloud subcommand stub into CLI (yah board/arch pattern). All commands no-op except machine status + mirror show which dump parsed .yah/cloud/ config. Verify: yah cloud mirror show noisetable prints declared regions/services.")
//!
//! @yah:ticket(R040-F4, "A4: cloud-init YAML + yah cloud machine provision (Debian + Podman + Tailscale + yah-warden)")
//! @yah:at(2026-05-05T00:29:11Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R040)
//! @yah:next("Template at .yah/cloud/cloud-init/mirror.yml; renderer substitutes YAH_WARDEN_BASE64 + HEADSCALE_PREAUTH_KEY + TAGS per machine")
//! @yah:next("Hostkey generated ON the machine (ssh-keygen in cloud-init); private half never touches dev machines")
//! @yah:next("Provision command polls cloud-init done, reads back hostkey fingerprint via yah-warden /identity, writes back to machine.toml")
//! @yah:next("Surface /var/log/cloud-init.log and /var/log/cloud-init-output.log on failure")
//! @yah:verify("yah cloud machine provision noisetable-pdx-1 --dry-run prints rendered cloud-init YAML")
//! @arch:see(architecture/PHASE_1_MIRROR_BOOTSTRAP.md)
//! @yah:handoff("Cloud-init template + renderer + provision command landed. Template at .yah/cloud/cloud-init/mirror.yml (canonical) with embedded copy at crates/yah/cloud/templates/mirror.yml (drift-test in cloud_init::tests::embedded_template_matches_workspace_canonical). Renderer at crates/yah/cloud/src/cloud_init.rs substitutes {{KEY}} (no-spaces) for MACHINE_NAME, YAH_WARDEN_BASE64, HEADSCALE_PREAUTH_KEY, TAGS; doc comments use {{ KEY }} (with spaces) so they survive rendering. find_unsubstituted() trips on any unsubstituted real placeholder. Provision orchestrator at crates/yah/cloud/src/provision.rs decoupled from concrete provider (takes &dyn MachineProvider). CLI wired in app/yah/cli/src/cloud.rs: yah cloud machine provision <name> [--dry-run] [--warden <path>]; --dry-run with no flags uses placeholders for the warden binary + preauth key (with NOTE lines explaining); live path requires --warden + HEADSCALE_PREAUTH_KEY + HETZNER_API_TOKEN. 20 unit tests pass (8 new for cloud_init + provision). Vocab: per-node infra daemon is yah-warden (was yah-mirror-agent — renamed 2026-05-01 because mirror is a deployment, not a node).")
//! @yah:next("A8 yah-warden /identity endpoint: poll cloud-init done after Hetzner accepts the create_server call, GET /identity for hostkey fingerprint, write back to .yah/cloud/machines/<name>.toml via MachineConfig::save(). Wiring stub already in handle_provision after rt.block_on — replace the next: print with the real poll loop.")
//! @yah:next("Optional polish: surface /var/log/cloud-init.log + /var/log/cloud-init-output.log on cloud-init failure (probably via the yah-warden /diagnostics endpoint when A8 lands, since direct SSH from the dev machine isn't part of Phase 1).")
//!
//! @yah:ticket(R040-T5, "A5: yah cloud machine status — drift report (declared vs Hetzner vs agent health)")
//! @yah:at(2026-05-05T00:29:11Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R040)
//! @yah:next("Drift categories: missing-server, wrong-machine-type, missing-bucket, hostkey-fingerprint-mismatch, missing-co-tenant, agent-unreachable, service-unhealthy")
//! @yah:next("Exit non-zero on drift unless --quiet; bare 'yah cloud machine status' dumps all declared machines")
//! @yah:next("Can land any time after A4 (parallel-safe with A6/A7/A8)")
//! @yah:verify("Pre-A6: reports 'not provisioned' for each declared machine")
//! @yah:verify("Post-A6+A7+A8: all three report 'in sync'")
//! @arch:see(architecture/PHASE_1_MIRROR_BOOTSTRAP.md)
//! @yah:handoff("Drift module landed at crates/yah/cloud/src/status.rs (DriftFinding + MachineReport + collect_machine_report). MachineProvider trait gained find_server_by_name (GET /servers?name=) + bucket_exists (S3 HEAD) — Hetzner impls share a refactored sign_s3_empty_body helper for PUT/HEAD signing. CLI: `yah cloud machine status [name] [--quiet]` queries Hetzner, prints declared+live state with per-finding [drift]/[note ] tags, and bails non-zero on real drift unless --quiet. Soft findings (missing creds, A8-not-landed, bucket-uncheckable) are surfaced as notes only. Pre-A6 verify: smoke-tested against this workspace's noisetable-pdx-1 declaration with no token — reports 'unknown' + provider-error note, exit 0. 7 new drift unit tests pass via in-memory FakeProvider; 27 total pass in crates/yah/cloud.")
//! @yah:next("A8 will plug in real agent-ping (yah-warden /health + /identity). The HostkeyFingerprintMismatch + AgentUnreachable variants are wired through the report rendering — A8 just needs to flip the AgentUnreachable emit-site in collect_machine_report() from the always-emit pre-A8 stub to a live probe.")
//!
//! @yah:ticket(R040-T6, "A6: provision noisetable-{pdx,iad,fsn}-1 (operational; yah dogfoods on noisetable's mirror, no yah-cloud SaaS)")
//! @yah:at(2026-05-05T00:29:11Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R040)
//! @yah:verify("yah cloud machine status --path /Users/user/ss/noisetable — all three 'in sync'")
//! @yah:verify("aws s3 ls --endpoint-url <hetzner-region-endpoint> s3://noisetable-assets-<region>-1 — all three list")
//! @arch:see(architecture/PHASE_1_MIRROR_BOOTSTRAP.md)
//! @yah:handoff("Code path complete across R040-F1..F8 + cloud-init runcmd alignment. Gated on operator runbook (release tag → live provision against Hetzner). Open repo-config decision (noisetable side, not yah): noisetable/.yah/.gitignore line 3 ignores '/cloud' wholesale — blocks tracking machines/, mirrors/, SECRETS.md. 30 cloud-crate + 17 yah cloud:: tests pass.")
//! @yah:next("Operator runbook lives in events.jsonl history; the strategic next is the live mirror-status verify (`yah cloud machine status --path /Users/user/ss/noisetable` → all three 'in sync') which is gated on the release-tag + provision steps.")
//!
//! @yah:ticket(R040-F7, "A7: yah cloud service deploy — Podman compose generation + Cloudflare front + tier isolation")
//! @yah:at(2026-05-05T00:29:11Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R040)
//! @yah:next("Resolves service configs + mirror declarations → per-machine compose.yml → push via yah-warden (A8) → systemctl restart yah-cloud-services")
//! @yah:next("Tier isolation at SOFTWARE layer: separate PG roles per service set, distinct Headscale tags (tier:t0 yah meta vs tier:t2 noisetable assets), mesh_only flag controls Cloudflare exposure")
//! @yah:next("Cloudflare DNS records (manual, in SECRETS.md): pdx.cloud.noisetable.example etc. → public IPs via orange-cloud")
//! @yah:next("Gotcha: Cloudflare free tier proxies HTTP/HTTPS but NOT raw TCP/UDP — Headscale mesh uses direct WireGuard between machines")
//! @yah:next("Assumes: Cloudflare account exists + noisetable.example DNS delegated to it (else spawns Cloudflare-bootstrap sub-ticket)")
//! @yah:next("Open question (refinement): Caddy vs nginx vs direct-to-Cloudflare for per-machine reverse proxy")
//! @yah:verify("curl https://pdx.cloud.noisetable.example/healthz (asset-registry) returns 200")
//! @yah:verify("curl https://pdx.cloud.yah.example/healthz (yah meta-directory) returns 200")
//! @yah:verify("yah cloud service status --all — all green on all 3 machines")
//! @arch:see(architecture/PHASE_1_MIRROR_BOOTSTRAP.md)
//! @yah:handoff("Compose generation + warden service deploy + CLI wiring landed. New file: crates/yah/cloud/src/compose.rs (generate_compose_bundle: tier-named networks, Caddy service for mesh_only:false, Caddyfile with hostname when cloud_domain is set in mirrors/*.toml). MirrorConfig gained cloud_domain: Option<String>. Warden: replaced 501 stubs with real /services (podman compose ps --format json; empty array when no compose.yml) and /compose (write compose.yml + Caddyfile + write yah-cloud-services.service unit + systemctl enable --now). ServerState gained compose_dir: PathBuf (default /etc/yah-cloud) + with_compose_dir() builder. cloud-client: added ComposeDeployRequest / ComposeDeployResponse wire types + deploy_compose() method. CLI: yah cloud service deploy <name> resolves machines via mirror→service lookup, generates per-machine bundle (using location+cloud_domain as public hostname when available), and POSTs to each machine's warden. yah cloud service status [name|--all] queries /services on each machine and prints [+]/[-] per container. All tests pass: 18 warden, 47 cloud, 8 cloud-client, 120 yah bin.")
//! @yah:next("Caddy in compose needs a Cloudflare origin cert or Let's Encrypt config once real domains land — Caddyfile currently uses :port placeholders which work for testing. Operator action: set cloud_domain in mirrors/<camp>.toml then re-run yah cloud service deploy to regenerate with real hostnames.")
//! @yah:next("Cloudflare Tunnel integration (R040-F15): add a cloudflared service to the compose stack — currently services are exposed via Caddy on public ports 80/443 (orange-cloud model). F15 will replace with no-public-port cloudflared tunnel approach.")
//! @yah:next("podman compose ps --format json output format varies by podman-compose version — current implementation passes raw JSON through. If operators hit parse issues, add a normalization layer in get_services() that extracts Name+State from both podman-compose and Podman 4.x native formats.")
//! @yah:next("yah cloud service rolling <name> not yet implemented — stub left in place. Compose rolling restarts are just podman compose up --no-deps <svc>; wire it when rolling deploys are needed.")
//!
//! @yah:ticket(R040-F8, "A8: yah-warden (Rust binary on machine) + yah-cloud-client + desktop Cloud panel")
//! @yah:at(2026-05-05T00:29:11Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R040)
//! @yah:verify("cargo test -p warden -p cloud -p cloud-client + cargo test -p yah --bin yah cloud:: — 18 + 47 + 9 + 17 tests pass")
//! @yah:verify("cargo run -p warden -- serve --bind 127.0.0.1:7450 --state /tmp/i.json then curl POST /register-hostkey with a real ssh-ed25519 pubkey, then `yah cloud machine attach <machine> --host 127.0.0.1:7450 --wait 5 --path <camp>` prints `attached: <machine> (fingerprint recorded: SHA256:…)` and writes the line into .yah/cloud/machines/<name>.toml")
//! @arch:see(architecture/PHASE_1_MIRROR_BOOTSTRAP.md)
//! @arch:see(architecture/yah-managed-camps-topology.md)
//! @yah:handoff("Session 3 landed `yah cloud machine attach <name>` (the hostkey write-back follow-on). app/yah/cli/src/cloud.rs::handle_attach loads MachineConfig, polls cloud-client GET /identity until success or --wait seconds elapse (default 180s, retry every 3s on NotRegistered or Transport errors), then calls MachineConfig::save() with the fingerprint. Decision logic in `decide_attach_action` covers all four states: Write (no fingerprint on file), Idempotent (match — no-op write), Mismatch (bail with --force hint), Overwrite (mismatch + --force). Subcommand args harmonized with agent ping: --host (default http://<machine>:7443), --wait <seconds>, --force, --path. handle_provision's stale stub print (`next: hostkey fingerprint write-back lands with A8`) replaced with `next: once cloud-init finishes, run yah cloud machine attach <name>`. End-to-end smoke verified all four AttachAction paths against a live warden on 127.0.0.1:7450 — pre-registration polling + bail, fresh-write, idempotent re-run, mismatch refusal, --force overwrite. 5 new unit tests (decide_attach_action_{writes_when_no_declared,idempotent_on_match,bails_on_mismatch_without_force,overwrites_with_force,force_is_idempotent_when_match}) — total 9 cloud:: tests in the yah bin. Cumulative R040-F8 deliverables across sessions 1–3: warden binary (12 tests), cloud-client crate (6 tests + doctest), AgentProbe trait + drift wire-up (4 new in cloud, 29 total), `yah cloud agent {ping,services,logs}` CLI, `yah cloud machine attach`, provision next-step hint correctly points at attach. Out of scope still: Tailscale-mesh discovery, desktop Cloud panel, mTLS hardening.")
//! @yah:next("Tailscale-mesh discovery for --host: `yah cloud agent ping/services/attach` defaults to http://<machine>:7443 which only resolves inside the mesh. Smart discovery would query `tailscale status --json` for the machine's mesh IP. Until then, operators pass --host explicitly. Add a TS_DEVICES env shortcut or `yah cloud agent ip <machine>` helper if the manual path stays painful.")
//! @yah:next("Desktop Cloud panel (out of session, larger): packages/yah/ui/src/cloud/ — machines list, per-machine service list, log tail. Tauri command bridges in app/yah/desktop/src/. Pulls on the cloud-client crate (already in workspace). Defer until at least Hostkey write-back lands so the panel has something useful to display per-machine.")
//! @yah:next("Hardening parking lot (post-Phase-1): mTLS (server cert from machine hostkey, client cert from desktop user identity); /metrics endpoint (Prometheus); streaming /logs from journald with heartbeat. None of these gate Phase 1 verify; cloud-client's CloudClient::with_timeout exists so log streaming has a hook.")
//! @yah:gotcha("warden binds 0.0.0.0:7443 by default; cloud-init template adds ufw rules to restrict to tailscale0. If a future deployment skips ufw, public IP exposure is a real risk. Better long-term: bind to tailscale0 IP directly (cloud-init systemd unit can compute it via `ip -4 addr show tailscale0`).")
//! @yah:gotcha("Re-running register-hostkey with a different pubkey replaces the stored identity (idempotent for same key, swaps for different). Probably what you want, but worth flagging if someone designs an audit log around 'first registration wins'.")
//! @yah:gotcha("Default URL resolution (`http://<machine.name>:7443`) is shared between WardenHealthProbe (status drift), agent ping/services, and machine attach — outside Tailscale mesh every default-host call against a real Hetzner machine will fail. Status emits AgentUnreachable as a soft note; agent/attach surface the transport error directly. Once mesh discovery lands, all three call sites should resolve via Tailscale before falling back to plain hostname.")
//!
//! @yah:ticket(R040-F18, "Phase 1a — yah mesh start: camp bootstrap with stable URL from day 1")
//! @yah:at(2026-05-05T00:29:11Z)
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:parent(R040)
//! @yah:phase(P1)
//! @yah:next("Implements Phase 1a from .yah/docs/architecture/A041-yah-mesh-bootstrap.md — design committed 2026-05-04. Phase 1b lands as R040-F19, Phase 2 (HA) as R040-F20+F21.")
//! @yah:next("Subcommand surface: `yah mesh start` brings up Headscale locally (yah-desktop or camp daemon); auto-detects direct vs. cloudflared reachability; configures DNS for mesh.<your-domain>; stores URL in vault as `mesh-url` so provision picks it up.")
//! @yah:next("Cloudflared bundling: yah-desktop should manage the cloudflared binary so the operator doesn't need a separate install. Same daemon can carry yah serve ingress + Headscale tunnel under one install — that's the user-acceptable story.")
//! @yah:next("Stable URL contract: `mesh.<your-domain>` set ONCE here and never changes across Phase 1b promotion or Phase 2 leader changes. Nodes embed this URL in their tailscale config; downstream phases re-point DNS, not nodes.")
//! @yah:next("Headscale binary provisioning: download + manage like cloudflared (precedent: yah already shells out to cloudflared/tailscale/cargo). Config template per arch doc 'Headscale config' section. Initial ACL writes a permissive `tag:*` policy.")
//! @yah:next("Provision integration: when `mesh-url` is set, `yah cloud machine provision` calls Headscale API for a single-use preauth key and embeds {MESH_URL, PREAUTH_KEY, TAGS} into cloud-init's `tailscale up` line. Static `headscale-preauth-key` in vault becomes optional.")
//! @yah:next("Also lands `yah mesh status` (coordinator location, connected nodes, preauth count). `yah mesh backup`/`restore` can be Phase-1a stubs; full litestream comes with R040-F21.")
//! @yah:verify("yah mesh start on a fresh camp brings up Headscale + DNS, prints stable URL, stores in vault")
//! @yah:verify("yah cloud machine provision <name> with mesh-url set generates preauth key and joins the new machine to the camp's Headscale")
//! @yah:verify("tailscale status on the new machine shows it connected via the camp's tunnel; node-to-node ping works")
//! @arch:see(.yah/docs/architecture/A041-yah-mesh-bootstrap.md)
//! @yah:handoff("Phase 1a landed. New files: crates/yah/cloud/src/mesh.rs (HeadscaleClient + generate_headscale_config + headscale_download_url + DEFAULT_ACL_POLICY), app/yah/cli/src/mesh.rs (yah mesh start/status/stop/backup-stub/restore-stub). cloud_init::RenderInput gained mesh_url: Option<String>; renderer substitutes {{MESH_LOGIN_SERVER_ARG}} → ' --login-server <url>' or '' depending on field. provision::build_request now takes mesh_url: Option<String>. template mirror.yml updated with MESH_LOGIN_SERVER_ARG placeholder. cloud.rs::handle_provision now reads mesh-url from vault/HEADSCALE_URL env; when set, calls HeadscaleClient::from_vault_or_env() to auto-generate a single-use preauth key (falls back to static headscale-preauth-key when no API key is available). yah mesh start downloads headscale binary from GitHub (HEADSCALE_VERSION=0.23.0), writes config.yaml + acls.yaml, creates default user, spawns headscale serve in background, saves PID, stores mesh-url in vault, prints DNS/tunnel operator instructions. yah mesh status shows PID, mesh-url, node count + per-node online status. yah mesh stop does SIGTERM+SIGKILL with 5s grace. Cloud crate: 36 tests pass (+4 new: render_with_mesh_url_adds_login_server, render_without_mesh_url_no_login_server, provision::build_request_with_mesh_url_adds_login_server, mesh::config_contains_server_url, mesh::config_all_paths_in_data_dir, mesh::download_url_current_platform). yah lib: 116 unit tests pass (+4 new mesh:: tests). arch dogfood integration tests are pre-existing failures unrelated to this work.")
//! @yah:next("Operator runbook for Phase 1a: (1) run yah mesh start --url https://mesh.<domain> on the camp; (2) set up DNS + cloudflared (or direct port-forward) for that URL; (3) headscale apikeys create to get an API key; (4) yah keys set headscale-api-key; (5) yah cloud machine provision <name> --warden-url <URL> --warden <PATH> --path /Users/user/ss/noisetable — provision now auto-generates a preauth key from Headscale.")
//! @yah:next("Phase 1b (R040-F19): yah mesh promote <machine> — migrates Headscale from camp to first cluster machine. The stable-URL contract from this ticket means no node reconfiguration is needed; only DNS re-points.")
//! @yah:next("Cloudflared bundling (R040-F15): cloud-init template needs cloudflared install + token. yah mesh start should detect reachability and auto-configure cloudflared when --url points through a Cloudflare Tunnel. The operator-instruction path this session is the MVP fallback.")
//! @yah:next("Headscale API key auto-generation: currently the operator must manually run headscale apikeys create. A future improvement: yah mesh start can use the local UNIX socket (headscale.sock) to generate the API key and store it in the vault automatically without needing the binary in PATH.")
//!
//! @yah:ticket(R040-F19, "Phase 1b — yah mesh promote: migrate Headscale from camp to first cluster machine")
//! @yah:at(2026-05-05T00:29:11Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R040)
//! @yah:next("Implements Phase 1b from .yah/docs/architecture/A041-yah-mesh-bootstrap.md. Depends on R040-F18 (Phase 1a) shipping the stable-URL contract and camp Headscale.")
//! @yah:next("Subcommand: yah mesh promote <machine-name>. Refuses if target machine isn't healthy (warden /health) or hostkey not registered.")
//! @yah:next("Migration sequence: (1) stop Headscale on camp, (2) copy SQLite DB + config + private keys to target via warden, (3) start Headscale on target as a systemd unit warden manages, (4) update Cloudflare DNS A/AAAA for mesh.<your-domain> to point at target, (5) tear down camp Headscale + (if used) cloudflared.")
//! @yah:next("Single-member raft is the degenerate case at this point — warden runs on the target, no quorum partners yet. Acceptable; HA shows up in Phase 2. Mark cluster as 'single-machine' in mesh status output so the operator knows the SPOF is real.")
//! @yah:next("Atomicity / failure recovery: keep a snapshot of camp Headscale state until target is verified serving traffic. yah mesh promote --abort restores the camp coordinator if the new target proves unhealthy mid-migration. Dry-run mode prints the plan without executing.")
//! @yah:next("Brief control-plane outage (~10s) is expected during DNS cutover. Data plane (existing WireGuard tunnels) is unaffected — verify by leaving a node-to-node ping running across the migration.")
//! @yah:next("Out of scope: litestream replication, openraft, multi-member promotion. All of that lands in R040-F20/F21.")
//! @yah:verify("yah mesh promote noisetable-pdx-1 migrates the coordinator; yah mesh status shows the new location; yah cloud machine provision <new-machine> against the migrated coordinator joins successfully")
//! @yah:verify("Existing nodes' tailnet connectivity uninterrupted across the migration (continuous ping from one node to another stays green)")
//! @arch:see(.yah/docs/architecture/A041-yah-mesh-bootstrap.md)
//! @yah:handoff("Phase 1b landed. New command: yah mesh promote <machine> [--dry-run] [--abort] [--host <URL>] [--path <dir>]. Migration sequence: (1) verify warden health + hostkey registered, (2) stop camp headscale, (3) POST SQLite DB + WireGuard keys + ACL policy to warden POST /headscale/deploy (warden downloads headscale binary from GitHub, writes files to configurable headscale_dir, starts systemd unit), (4) poll GET /headscale/health until running (90s timeout), (5) update Cloudflare DNS A record via CF API (CLOUDFLARE_API_TOKEN + CLOUDFLARE_ZONE_ID) or print manual instructions, (6) persist coordinator type to vault (mesh-coordinator-type=cluster, mesh-coordinator-machine=<name>). --abort restarts camp headscale from existing local state. Rollback on mid-migration failure auto-restarts camp headscale. yah mesh status updated: shows 'cluster [<machine>] (single-machine — SPOF)' after promote, camp PID status before. New warden endpoints: POST /headscale/deploy (accepts base64-encoded state files, writes to configurable headscale_dir, curl-downloads binary, systemctl enable --now), GET /headscale/health (systemctl is-active + localhost:8080 HTTP probe). ServerSummary gained public_ipv4: Option<String> (parsed from Hetzner public_net.ipv4.ip). Cloudflare DNS helper: update_cloudflare_dns() + cloudflare_credentials() in cloud::mesh. cloud-client: deploy_headscale() + headscale_health() methods. Tests: +8 warden (15 total), +2 cloud-client (9 total), +4 yah mesh:: (120 total). All pass.")
//! @yah:next("Operator runbook: (1) yah mesh start --url https://mesh.<domain> on camp, (2) provision a machine, (3) yah cloud machine attach <name>, (4) yah mesh promote <name> [--host <warden-ip>:7443 pre-mesh]. DNS update needs CLOUDFLARE_API_TOKEN + CLOUDFLARE_ZONE_ID or manual update.")
//! @yah:next("Mesh URL connectivity: before Tailscale mesh is up, --host must be the machine's public IP (pre-mesh access). Once mesh is established, the default http://<machine>:7443 works. Consider yah cloud agent ip <machine> helper or mesh-discovery to auto-resolve (same gap as R040-F8 Tailscale discovery).")
//! @yah:next("HEADSCALE_VERSION is pinned to 0.23.0. If the operator's local headscale.db was created by a different version, the remote headscale may reject the database. Add a version-mismatch warning to the deploy step.")
//!
//! @yah:relay(R085, "Infra-info MCP — warden / machine / mirror status read surface")
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:parent(Q082)
//! @yah:handoff("Four read-only cloud.* MCP tools landed in crates/yah/agent-tools/src/cloud_tools.rs. Registration: KgToolRegistry::with_cloud() in tools.rs (same builder pattern as with_board/with_scryer/with_task). cloud-client dep added to agent-tools Cargo.toml. Local-config tools (cloud.machines, cloud.mirror_state) read .yah/cloud/{machines,mirrors,services}/*.toml from ctx.camp_root with lightweight serde structs — no cloud crate dep, no network. Network tools (cloud.warden_status, cloud.service_ports) probe warden HTTP API via cloud_client::CloudClient and return reachable:false rather than error when unreachable. 14 unit tests, all pass. Total agent-tools tests: 140.")
//! @yah:next("Wire with_cloud() into the agent session startup (camp.rs or agent.rs in app/yah/cli) alongside with_board() and with_scryer() so the tools appear in the agent's tool list automatically.")
//! @yah:next("Feed cloud.warden_status into the drift detection surface (status.rs AgentProbe) so warden reachability populates machine status reports rather than being a separate probe path.")
//! @yah:verify("cargo test -p agent-tools -- cloud 2>&1 | grep 'test result' shows 14 passed; 0 failed")
//! @yah:verify("KgToolRegistry::standard_read_only(ctx).with_cloud().schemas() returns 4 tools all named cloud.*")
//! @arch:see(.yah/quests.md)
//!
//! @yah:relay(R168, "yah-cloud TOML config schema + validation")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-13T19:07:07Z)
//! @yah:status(review)
//! @yah:parent(Q156)
//! @yah:handoff("Schema doc written at .yah/docs/architecture/A031-yah-cloud-config-shape.md. MirrorConfig.camp renamed to .camp with serde alias 'camp' for migration compat (R137 rename). load_mirrors() added to handle both flat mirrors/<id>.toml and folder mirrors/<id>/mirror.toml layouts — yah-com/mirror.toml now loads. cloud_tools.rs local stub updated to match. All 90 cloud-crate tests pass + 4 new layout tests. agent-tools + yah bin check clean.")
//! @yah:next("Remove serde alias 'camp' from MirrorConfig once all known mirrors are migrated (tracked in R137)")
//! @yah:verify("cargo test -p cloud — 90 tests pass including mirror_folder_layout_loads + mirror_malformed_fails_with_field_path")
//! @yah:verify("Schema doc links back to yah-public-site.md deployment-shape section")
//! @arch:see(.yah/docs/architecture/A031-yah-cloud-config-shape.md)
//! @arch:see(.yah/docs/architecture/A045-yah-public-site.md)
//!
//! @yah:relay(R260, "OpenRouter model almanac — track top-weekly models for backend selection")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-20T22:23:52Z)
//! @yah:kind(spike)
//! @yah:status(in-progress)
//! @arch:see(architecture/yah-cloud-config-shape.md)
//! @yah:next("Unique signal: popularity + freshness + capability tags. Pricing is already covered by `crates/yah/probe/data/pricing.json` (LiteLLM snapshot) — almanac does NOT duplicate $/token; it adds rank, `:free` flag, modality, capability tags (code / vision / tool-use / long-context), and a last_seen_at so consumers can tell when an entry has gone stale.")
//! @yah:next("Primary consumer: the OpenRouter character bundle at `crates/yah/kg/preroll/openrouter/{agents,subclasses}.json`. Currently a single preroll agent (\"Quick Hand\") pinned to `qwen/qwen3-coder:free` — this WILL silently break when OpenRouter rotates the free-tier list. Almanac's first job is to keep that subclass pointed at a currently-available free model (and let the bundle expand into a roster of currently-hot free models, not just one).")
//! @yah:next("Free-model rotation is the load-bearing constraint. Refresh cadence has to match how often OpenRouter shuffles the `:free` set (empirically weekly-ish). Storage options ranked by how well they handle rotation: (1) scheduled daemon refresh writing back into `crates/yah/kg/preroll/openrouter/` — auto-heals; (2) on-demand fetch+cache in the runner — never stale at session start but offline-fragile; (3) build-time embedded snapshot like `probe/data/pricing.json` — simplest, goes stale between releases (probably wrong shape for free-tier).")
//! @yah:next("Two approaches to evaluate side-by-side: (A) straight call to `https://openrouter.ai/api/v1/models` (free, no key, structured JSON — already returns `context_length`, `pricing.prompt`/`pricing.completion`, `architecture.modality`; `crates/yah/runner/src/resolver/openrouter.rs` already talks to OpenRouter so a `fetch_models()` sibling to its existing `GET /api/v1/credits` is the natural home); (B) inference-based tool that distills `https://openrouter.ai/models?order=top-weekly` HTML into our schema. Confirm (A) first — if the JSON exposes the top-weekly ordering and `:free` flag, (B) is unnecessary; if not, (B) becomes the rotation-detector.")
//! @yah:next("Query-resolvable subclass (the real primitive): `AgentSubclass.model` at `crates/yah/kg/src/party.rs:520` is a hard `provider:model` string today. Promote it to a sum type — literal `provider:model` OR `ModelQuery { tier, capability_tags, min_context_tokens, max_price_per_token, … }` — resolved by the almanac at session start. Slots into the existing `fallbacks: Vec<FallbackRule>` machinery at party.rs:540: emit `ConfigSwitch{ModelResolved}` (sibling of `FallbackTriggered`) when the query lands, so the UI can show \"Quick Hand → qwen3-coder:free (current pick, refreshed 2h ago)\". The preroll bundle then declares intent (\"Thief-shaped, free, code-tuned\") instead of a brittle pin.")
//! @yah:next("Constraint vocabulary — the hard numbers behind \"Thief-shaped, free, code-tuned\", layered by cost-to-implement so we ship something useful at T0 and can grow. **T0 (already free from /models):** `context_length`, `pricing.prompt`/`pricing.completion`, `architecture.modality` come back in the same fetch. MVP heuristic = Pareto frontier of (context_window, price_per_token); at `:free` tier price collapses to 0 so it cleanly reduces to \"max context with matching capability tag\". This is enough to pick a non-broken Quick Hand. **T1 (external quality scores):** join on canonical model id against artificialanalysis.ai's quality index (general + code subscore), Aider's code leaderboard, or LiveBench. Cheap to add once the T0 pipe exists; lets queries express `min_quality` or `prefer_code_subscore`. **T2 (almanac-as-evaluator):** spend a few credits running a small fixed corpus (lint-fix, summarize, ack-and-route) through each new free candidate, score against a reference, persist scores into the almanac. The dogfood option — most signal, most expensive, most interesting. Out of scope for the spike; file as a follow-up child once T0/T1 are in flight.")
//! @yah:next("Recommendation surface: popularity-ranked picker entries in `packages/yah/ui/src/components/agent/Picker/toPickerAgents.ts` + `AgentProvidersPanel.tsx` so adding an OpenRouter backend surfaces the currently-hot models first; query-resolved subclasses display their resolved pick + a freshness chip; stale literal-pinned `:free` references show a warning.")
//! @yah:next("Spike output: a design note at `.yah/docs/working/W091-openrouter-almanac.md` + a working (A) prototype printing the top 10 models in our T0 schema (id, context_length, price, `:free` flag, capability tags, popularity rank). From there, refine into child tickets for: (i) refresh mechanism, (ii) `ModelSpec::Literal | ModelSpec::Query` sum type + T0 resolver, (iii) preroll-bundle migration from pinned-model to ModelQuery, (iv) UI recommendation + freshness chips, (v) T1 external-benchmark join, (vi) T2 self-eval as a stretch/follow-up.")
//! @yah:handoff("Spike output delivered: working prototype + design note + 6 child tickets. Prototype lives in crates/yah/runner/src/resolver/openrouter.rs (AlmanacEntry struct + fetch_models() against /api/frontend/models/find?order=top-weekly + derive_capability_tags) plus app/yah/cli/src/agent.rs (yah agent almanac --top N --free-only --tag code --json). Design note at .yah/docs/working/W091-openrouter-almanac.md. Six follow-ups filed: R260-F1 (refresh scheduler), R260-F2 (ModelSpec sum type + T0 resolver), R260-T3 (preroll bundle migration → ModelSpec::Query), R260-F4 (UI freshness chips + stale-pin warning), R260-F5 (T1 benchmark join), R260-S6 (T2 self-eval, stretch). T0 prototype confirms the rotation problem: `yah agent almanac --top 10 --free-only --tag code` shows qwen/qwen3-coder:free (Quick Hand's current pin) is NO LONGER in the top-10 free code models — current leaders are openrouter/owl-alpha, nvidia/nemotron-3-super, poolside/laguna-m.1.")
//! @yah:verify("cargo run -p yah -- agent almanac --top 10 — prints OpenRouter top-10 weekly models in T0 schema")
//! @yah:verify("cargo run -p yah -- agent almanac --top 10 --free-only --tag code — shows the currently-hot free-tier code-tuned roster (the Quick Hand replacement set)")
//! @yah:verify("cargo check -p runner -p yah — clean (note: cargo test -p runner --lib is blocked by pre-existing R258-F3 test breakage on AgentSession; tracked as gotcha)")
//! @yah:gotcha("Pre-existing R258-F3 test breakage in crates/yah/runner/src/{anthropic.rs:833, sessions.rs} — `cargo test -p runner --lib` fails with E0063 (AgentSession initialiser missing last_text + slot_id fields). R258-F3 is currently in review. R260's new resolver::openrouter::tests entries are byte-perfect but un-runnable until R258-F3's test fixtures are updated.")
//! @yah:gotcha("OpenRouter's /api/frontend/models/find?order=top-weekly is undocumented. The almanac treats it as best-effort and the design (see openrouter-almanac.md) calls for graceful degradation to public /api/v1/models alone when the join fails. ?order= is silently ignored on the documented endpoint (it always returns newest-first); approach (B) HTML scraping is unnecessary and was ruled out.")
//!
//! @yah:relay(R414, "yah-cloud pill sync + publish + Pills panel")
//! @yah:assignee(bundle-anthropic-miravel)
//! @yah:at(2026-06-03T07:07:03Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(Q410)
//! @arch:see(.yah/docs/working/W141-pill-rings.md)
//! @arch:see(.yah/docs/architecture/A031-yah-cloud-config-shape.md)
//! @yah:depends_on(R411)
//! @yah:handoff("P2 delivered: resolve_pill_catalog (chips crate) + party_resolve_pill_catalog Tauri command + env wiring + PillsPanel in FullCharacterEditor. Pills panel shows all categorized pills grouped by category with per-character tri-state toggle (always-on/discoverable/off); edits agent.persona.chips.pill_state map via patchAgent.")
//! @yah:next("P3: local pills.toml loader — add ~/.yah/pills.toml and .yah/pills.toml as new resolution layers (separate from chips.toml) per W141 layer stack")
//! @yah:next("P3: MCP URL trust display — when a content-pill with mcp[] is toggled always-on, show one-time approval dialog listing the URLs before activating")
//! @yah:next("P4: cloud sync stub — 'Share to my account' button in PillsPanel (disabled until account system exists)")
//! @yah:verify("cargo test -p chips — 84 passed (3 new resolve_pill_catalog tests)")
//! @yah:verify("bun run typecheck — no new errors (6 pre-existing unchanged)")
//!
//! @arch:see(.yah/docs/working/W193-asset-dependency-status-surface.md)

pub mod almanac_dispatch;
pub mod app_manifest;
pub mod asset_journal;
pub mod asset_status;
pub mod cloud_init;
pub mod compose;
pub mod config;
pub mod envoy;
pub mod identities;
// R374-F3: `local_runtime` + `provider::s3_sign` moved to the `local-driver`
// crate so warden can own MinIO lifecycle without a reverse warden→cloud dep.
// `local_driver_glue` carries the cloud-config adapter that used to live as
// `LocalContainerSpec::from_provider_config`.
pub mod local_driver_glue;
pub mod mesh;
pub mod mesh_service;
pub mod paths;
pub mod provider;
pub mod provision;
pub mod reconciler;
pub mod release_manifest;
pub mod state;
pub mod status;
pub mod validate;

pub use compose::{generate_compose_bundle, ComposeBundle};
pub use config::{
    BucketLogEntry, CloudConfig, LegacyMirrorConfig, LegacyServiceConfig, MachineConfig,
    MirrorAssignment, MirrorConfig, MirrorProviderSlot, MirrorShape, Provider, ProviderConfig,
    ServiceComponent, ServiceConfig, TopologyConfig, WorkloadConfig, WorkloadConfigError,
};
pub use local_driver::{
    canonical_label, canonical_name, ContainerRunSpec, ContainerState, CustomDockerHostProvider,
    DetectedRuntime, LocalContainerSpec, LocalDockerRuntime, LocalRuntime, OwnedContainer,
    RuntimePref, RuntimeProvider, SocketRuntimeProvider, LABEL_KEY, NAME_PREFIX,
};
pub use local_driver_glue::local_container_spec_from_provider;
pub use provider::{
    BucketAcl, BucketRef, CfAccountInfo, CloudflareClient, CloudflareEnvoy, CreateR2BucketResult,
    CreateTokenResult, CreateTunnelResult, DigitalOceanEnvoy, GrantScope, HetznerDriver,
    HetznerEnvoy, Location, MachineProvider, ProjectId, R2BucketInfo, R2CustomDomain, ServerId,
    ServerSpec, ServerStatus, ServerSummary, TokenGrant, TunnelConnState, TunnelDnsRecord,
    TunnelDriftRow, TunnelDriftState, WorkerDeployResult, MESOFACT_STATIC_GRANTS,
};
#[cfg(feature = "local-docker")]
pub use provider::{LocalDockerEnvoy, LocalDockerProvider};
pub use reconciler::{
    collect_live_derive_hashes, compute_derive_cache_candidates, compute_live_set,
    compute_prune_candidates, compute_service, derive_minio_key, execute_derive_cache_prune,
    execute_prune, load_service_and_mirror, mesofact_static::WORKER_SCRIPT, new_sync_id,
    pond::MINIFLARE_SIM_SCRIPT,
    publish_to_pond, summarize, CellStatus, CloudflareWorkerReconciler, DeriveCacheLiveHashes,
    WireContainerStatus,
    DerivePruneCandidate, DriftEntry, HealthState, LocalStaticOptions, MesofactStaticReconciler,
    MirrorObservation, PondOptions, PondPublishReport, PondState, PruneCandidate, PruneOutcome,
    PruneReport, ReconcileCtx, Reconciler, Runtime, RunningWorkload, RunningWorkloadSummary,
    ServiceStatus, StaticAssetReconciler, StatusSummary, SyncHistoryEntry, SyncOutcome, SyncState,
};
pub use almanac_dispatch::dispatch_on_change;
pub use asset_journal::{AssetState, AssetStatusEvent, AssetStatusJournal};
pub use status::{collect_machine_report, AgentProbe, DriftFinding, MachineReport};
