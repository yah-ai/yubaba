//! `yah-yubaba` — per-machine infrastructure daemon.
//!
//! Modes:
//!
//! - `serve` — long-running HTTP daemon (systemd unit on the machine).
//!   Pass `--raft-node-id` + `--raft-dir` to enable Phase 2 raft coordination.
//! - `register-hostkey <path>` — one-shot: parse an SSH pubkey file,
//!   compute its fingerprint, write it to the state file.
//! - `raft status|peers|transfer-leader` — operator commands for the
//!   raft coordination layer (Phase 2, R040-F20).
//!
//! @yah:ticket(R471-B7, "yah-yubaba container launches without `serve` subcommand → prints help, exits 2, restart-loops")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-06T20:35:57Z)
//! @yah:status(review)
//! @yah:parent(R471)
//! @yah:severity(P1)
//! @yah:verify("Fresh container reaches `kamaji UDS listening` AND stays running >30s with `docker inspect` showing State.Status=running (not restarting).")
//! @yah:verify("RestartCount stops climbing.")
//! @yah:verify("Doubles as the verify fixture for R471-T5 / R471-F6 — once fixed, induce a different crash (e.g. bad config) to keep exercising the status pipeline.")
//! @yah:gotcha("Discovered as the proximate cause of the pond crash-loop that motivated R471. Container 37a1652... with image ghcr.io/yah-ai/yah-yubaba:latest: 14 restarts in 1m, exit code 2, policy=unless-stopped. Entry runs `yah-yubaba` with no subcommand. Either the Dockerfile CMD/ENTRYPOINT dropped `serve` or the clap root recently lost the implicit default. Check oss/qed/crates/qed/images/yah-yubaba/Dockerfile + pond-supervise.sh, the wrapper script that exec's yah-yubaba.")
//! @yah:handoff("Root cause: `Cli::cmd: Cmd` was a required subcommand — a bare `yah-yubaba` invocation made clap print help and exit 2. That's what's crash-looping the pond container (Dockerfile CMD = pond-supervise.sh → `yah-yubaba ${YAH_WARDEN_ARGS:-}` with no subcommand).")
//! @yah:handoff("Fix is two-pronged: (1) main.rs flips `cmd` to `Option<Cmd>` and treats `None` as `Cmd::Serve` with every field at its declared default via a new `default_serve()` helper kept in lockstep with the variant; (2) pond-supervise.sh now invokes `yah-yubaba serve` explicitly so YAH_WARDEN_ARGS attaches unambiguously to the serve subcommand. Either fix alone would unstick pond; both ship for defense in depth.")
//! @yah:handoff("Verified locally: `/Users/user/ss/yah/target/debug/yah-yubaba` (no args) logs `INFO yah-yubaba serve` then `yah-yubaba listening` on 0.0.0.0:7443 (debug build is featureless so /workloads/deploy stays in stub mode — expected); `yah-yubaba --help` still lists serve/register-hostkey/raft. cargo test -p yubaba --lib → 96 passed.")
//! @yah:handoff("Image rebuild needed before the live pond container actually picks this up: `.yah/qed/build-yah-yubaba.toml` (arm64 local) rebuilds ghcr.io/yah-ai/yah-yubaba:latest into the local docker daemon; the GHA image-yah-yubaba job needs to retag for amd64 once main lands. Until that ships, the pond container at 37a1652... will keep crash-looping on the old image — that's a deploy step, not a code fix.")
//! @yah:next("Sign-off: skim main.rs::default_serve to confirm field-for-field parity with Cmd::Serve—if either drifts in future, the default-boot path silently picks the wrong value. Consider a compile-time assertion (Cmd::Serve::default() trait + derive) in a follow-up if drift becomes a worry.")
//! @yah:next("Rebuild + push ghcr.io/yah-ai/yah-yubaba:latest so the pond container actually picks up the fix — this is the gating step for R471's outer verify (`Restarting (2) · N restarts in 1m` chip on the Services grid). Until then, B7's code is correct but the live fixture stays broken.")
//! @yah:verify("cargo build -p yubaba --bin yah-yubaba  # clean")
//! @yah:verify("cargo test -p yubaba --lib  # 96 passed")
//! @yah:verify("./target/debug/yah-yubaba  # logs 'yah-yubaba serve' + 'yah-yubaba listening', does NOT print help and exit 2")
//! @yah:verify("./target/debug/yah-yubaba --help  # still lists subcommands (root-level help unchanged)")
//! @yah:verify("Rebuild + reload the pond image (`yah qed run build-yah-yubaba` or equivalent), then `docker inspect <pond-yubaba>` shows State.Restarting=false and RestartCount stops climbing.")
//!
//! @yah:ticket(R590-B9, "yubaba GET /workloads/{id}/state returns 404 for kamaji-deployed forge workloads — CLI can't poll state, marks fleet runs Failed")
//! @yah:at(2026-07-12T15:24:47Z)
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:parent(R590)
//! @yah:severity(blocks-on-box-green)
//! @yah:next("Register kamaji-dispatched workloads in yubaba's state map at deploy time (or proxy GET /workloads/{id}/state through the kamaji UDS list/state RPC, which IS attached), so the ident is queryable for the run's lifetime and terminal state (Exited 0 / Failed) is observable. Cross-check R590-F2's MeshYubabaClient::connect_logs which polls this endpoint for terminal status.")
//! @yah:verify("After deploying a forge workload, GET http://<node>:7443/workloads/{ident}/state returns the live state (not 404) through to a terminal Exited/Failed; `yah qed run rusty-v8-musl` reflects the container's real exit instead of failing on the 404 poll.")
//! @yah:gotcha("PROVEN live (2026-07-11): a workload deploy succeeds (kamaji logs 'containerd workload deployed container_id=forge-... pid=...'), but the qed CLI's state poll gets `404 Not Found {\"error\":\"workload not found\"}` from GET /workloads/{id}/state on the SAME ident — so RemoteForgeDriver marks the run Failed regardless of the container's real outcome. Even a green long build would be reported Failed. The deploy goes yubaba->kamaji->containerd, but yubaba's queryable state registry doesn't hold the deployed ident.")

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use yubaba::{identity, serve, ServerState, DEFAULT_BIND, DEFAULT_STATE_PATH};

/// Default raft state directory. Writable runtime state → under the systemd
/// StateDirectory (/var/lib/yah-cloud), not read-only /etc (R330-F28 #14).
const DEFAULT_RAFT_DIR: &str = "/var/lib/yah-cloud/raft";

/// Default containerd socket. Mirrors `runtime::containerd::DEFAULT_SOCKET`,
/// duplicated here so `--containerd-socket` has a default even when the binary
/// is built without the `containerd-integration` feature.
const DEFAULT_CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";

/// Per-attempt timeout on a single Kamaji UDS handshake. Short enough that a
/// dead socket fails fast so the outer retry loop can back off and try again.
const CONSTABLE_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Total wall-clock budget yubaba spends retrying the Kamaji UDS handshake at
/// startup before falling back to the legacy in-process `ContainerRuntime`.
///
/// R589-T2 boot race: `yubaba.service` orders `After=kamaji.service`, but
/// kamaji is `Type=simple`, so systemd considers it "active" the instant it
/// forks — *before* it has bound `/run/kamaji/kamaji.sock`. On a slow node
/// (e.g. the Raspberry Pi worker) yubaba would win the race, get
/// ECONNREFUSED on its single connect attempt, and silently fall back to the
/// in-process runtime — leaving kamaji unused until a manual
/// `systemctl restart yubaba`, and recurring on every reboot. Retrying with
/// backoff for this budget rides out the socket-bind gap without a
/// per-box shim or a kamaji-side `Type=notify` change.
const KAMAJI_CONNECT_BUDGET_SECS: u64 = 30;

#[derive(Parser)]
#[command(version, about = "yah per-machine infrastructure daemon")]
struct Cli {
    /// Subcommand; defaults to `serve` so bare `yah-yubaba` boots the daemon.
    ///
    /// Historically the root command implicitly ran `serve`; the explicit
    /// subcommand structure was added in R040-F11 (raft commands) and that
    /// silently flipped the bare-binary path to "print help, exit 2", which
    /// crash-looped the pond container under image
    /// `ghcr.io/yah-ai/yah-yubaba:latest`. We treat `None` as Serve-with-defaults
    /// so any invocation that drops the subcommand (Dockerfile CMD, k8s
    /// args:, systemd ExecStart) keeps working. See R471-B7.
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the HTTP daemon.
    Serve {
        /// Address to bind (prefer the tailscale0 IP in production).
        #[arg(long, default_value = DEFAULT_BIND)]
        bind: String,
        /// State file path (hostkey identity persistence).
        #[arg(long, default_value = DEFAULT_STATE_PATH)]
        state: PathBuf,
        /// Release channel the cloud-init systemd unit was provisioned for
        /// (`stable` | `beta`). Informational at runtime — the deployed binary
        /// already reflects the channel — but accepted so the unit's
        /// `serve --channel <c>` invocation boots cleanly.
        #[arg(long, default_value = "stable")]
        channel: String,
        /// containerd socket to drive workloads through. Production:
        /// `/run/containerd/containerd.sock`; Colima on macOS:
        /// `~/.colima/default/containerd.sock`. Only used when the binary is
        /// built with the `containerd-integration` feature; otherwise
        /// `/workloads/deploy` stays in stub mode.
        #[arg(long, default_value = DEFAULT_CONTAINERD_SOCKET)]
        containerd_socket: String,
        /// R406-T8: UDS path for the Kamaji sibling process. When set,
        /// yubaba dispatches workload list/state/drain through Kamaji
        /// over postcard-framed messages. If the connection fails at
        /// startup, yubaba retries with backoff (rides out kamaji settling
        /// on a fresh boot) and then falls back to the legacy in-process
        /// `ContainerRuntime` (with a warning) so existing single-node
        /// deploys keep working.
        ///
        /// Flag name tracks the constable→kamaji rename: the sibling unit
        /// (`kamaji.service`) and the cloud-init drop-ins spell it
        /// `--kamaji-socket`, so the binary must too (R589-T2 — the shipped
        /// v0.8.17 skew where the unit passed `--kamaji-socket` but the
        /// binary only accepted `--constable-socket` fails `serve` with
        /// exit 2).
        #[arg(long = "kamaji-socket")]
        kamaji_socket: Option<PathBuf>,
        /// Phase 2: this node's raft node ID (u64, unique per yubaba instance).
        /// When set, the raft coordination layer is started and `/raft/*`
        /// routes become active.
        #[arg(long)]
        raft_node_id: Option<u64>,
        /// Phase 2: directory for raft persistence files.
        #[arg(long, default_value = DEFAULT_RAFT_DIR)]
        raft_dir: PathBuf,
        /// W197 §"Single-node raft" / A032 cluster-mesh-1 (R482-T3): on the
        /// BYO-VPS bootstrap path, auto-initialise this node as a raft
        /// cluster-of-one at startup instead of waiting for an operator
        /// `raft init --member …` call. Requires `--raft-node-id`. Idempotent
        /// across restarts. Do NOT combine with the multi-node founding flow —
        /// a self-initialised node is its own cluster and cannot later merge
        /// with a separately-founded one; fleet growth is join-by-NodeId.
        #[arg(long)]
        bootstrap_single_node: bool,
        /// Membership address recorded for this node when self-initialising a
        /// cluster-of-one (`--bootstrap-single-node`). Defaults to `--bind`.
        /// Self-referential for a cluster-of-one and never dialed.
        #[arg(long)]
        raft_advertise_addr: Option<String>,
        /// Phase 2: S3 URL for litestream Headscale DB replication.
        /// Format: `s3://bucket/path?endpoint=https://fsn1.your-objectstorage.com`
        /// When set, the leader watcher manages litestream replicate + restore.
        #[arg(long)]
        litestream_s3_url: Option<String>,
    },
    /// Parse an SSH pubkey file, compute its SHA256 fingerprint, and write
    /// it to the state file. Idempotent.
    RegisterHostkey {
        /// Path to the SSH public key file (e.g. `/etc/yah-cloud/hostkey.pub`).
        pubkey_path: PathBuf,
        #[arg(long, default_value = DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
    /// Raft coordination commands (Phase 2 — R040-F20).
    Raft {
        /// Yubaba daemon address to query (default: localhost).
        #[arg(long, default_value = "http://127.0.0.1:7443")]
        daemon: String,
        #[command(subcommand)]
        cmd: RaftCmd,
    },
}

#[derive(Subcommand)]
enum RaftCmd {
    /// Show raft cluster status (leader, term, last log).
    Status,
    /// One-time cluster bootstrap: write the founding membership (R570-F1).
    ///
    /// Run against exactly one founding voter after every member is up with
    /// `--raft-node-id`; the rest learn membership from the elected leader.
    Init {
        /// Founding voter as `id=host:port`, repeatable
        /// (e.g. --member 1=100.64.0.1:7443 --member 2=100.64.0.2:7443).
        #[arg(long = "member", required = true)]
        members: Vec<String>,
    },
    /// List raft peers and their current state.
    Peers,
    /// Add a node to a *running* cluster as a non-voting learner (R569-F3).
    ///
    /// The join-an-existing-quorum path (vs `init`, which founds a fresh
    /// cluster). Run against the current **leader** (`--daemon <leader-mesh>`).
    /// The joining node must already be up with `--raft-node-id <node-id>` and
    /// uninitialised (no `init`, no `--bootstrap-single-node`). The learner
    /// receives full replicated state but never votes or counts toward quorum;
    /// promotion to voter is a separate, deliberate step (not this command) —
    /// a home-lab macOS node stays a learner by design (W255).
    AddLearner {
        /// The joining node's raft node id (u64, unique fleet-wide).
        #[arg(long)]
        node_id: u64,
        /// The joining node's mesh address `host:port` the leader will dial —
        /// e.g. its Tailscale mesh IP `100.64.0.7:7443`, never a LAN address.
        #[arg(long)]
        addr: String,
    },
    /// Transfer raft leadership to another node.
    TransferLeader {
        /// Target node ID to become leader.
        to: u64,
    },
}

/// Default-construct a `Cmd::Serve` matching every `default_value` declared on
/// the variant. Kept in lockstep with the `Cmd::Serve` struct above.
fn default_serve() -> Cmd {
    Cmd::Serve {
        bind: DEFAULT_BIND.to_string(),
        state: PathBuf::from(DEFAULT_STATE_PATH),
        channel: "stable".to_string(),
        containerd_socket: DEFAULT_CONTAINERD_SOCKET.to_string(),
        kamaji_socket: None,
        raft_node_id: None,
        raft_dir: PathBuf::from(DEFAULT_RAFT_DIR),
        bootstrap_single_node: false,
        raft_advertise_addr: None,
        litestream_s3_url: None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    // None → default to `serve` with every flag at its declared default. This
    // mirrors how the binary used to behave before raft subcommands shipped
    // and keeps bare-binary launchers (pond Dockerfile CMD) booting cleanly.
    let cmd = cli.cmd.unwrap_or_else(default_serve);
    match cmd {
        Cmd::Serve {
            bind,
            state,
            channel,
            containerd_socket,
            kamaji_socket,
            raft_node_id,
            raft_dir,
            bootstrap_single_node,
            raft_advertise_addr,
            litestream_s3_url,
        } => {
            tracing::info!(channel = %channel, "yah-yubaba serve");
            let mut server_state = ServerState::load(state)?;

            if let Some(s3_url) = litestream_s3_url {
                server_state = server_state.with_litestream_s3_url(s3_url);
            }

            // Wire the container runtime. This is what flips `/workloads/deploy`
            // from `runtime=stub` to a daemon that actually deploys containers.
            // Attached before the raft branch so both single-node and clustered
            // wardens deploy workloads.
            server_state = attach_runtime(server_state, &containerd_socket).await;

            // R406-T8: connect to Kamaji when --kamaji-socket is set.
            // Failure here is non-fatal so an operator can boot yubaba alone
            // for triage, but the warning makes it clear the requested
            // dispatch path is unavailable.
            server_state = attach_constable_client(server_state, kamaji_socket).await;

            // Pond (R454-F1 seam): the containerized pond yubaba drives
            // MinIO/miniflare as sibling containers through the host docker
            // socket mounted at /var/run/docker.sock. Wire the LocalRuntime
            // whenever that socket exists so `POST /pond/deploy` works;
            // without it the pond routes answer 503 and every camp deploy
            // silently fails. Cloud/systemd deployments don't mount the
            // socket, so this is a no-op there.
            server_state = attach_pond_runtime(server_state).await;

            if let Some(node_id) = raft_node_id {
                tracing::info!(node_id, dir = ?raft_dir, "starting raft coordination layer");
                let (raft_node, state_machine) =
                    yubaba::raft::open_with_state_machine(node_id, raft_dir).await?;
                server_state = server_state
                    .with_raft(raft_node.clone())
                    .with_node_id(node_id)
                    // R600-F6 (W273): share the raft state-machine handle so
                    // admission can resolve `SecretRef::Cluster` File mounts.
                    // Cloned here because the ACME issuer (F3) also moves a
                    // handle in below.
                    .with_secret_state(state_machine.clone());
                // W197 §"Single-node raft" (R482-T3): the BYO-VPS bootstrap
                // path self-initialises a cluster-of-one so the node comes up
                // as a live one-voter raft with no operator `raft init` call.
                // Idempotent across restarts; a no-op once the node has
                // vote/log state. Runs before the leader watcher spawns so the
                // watcher observes the self-election on its first tick.
                if bootstrap_single_node {
                    let addr = raft_advertise_addr.clone().unwrap_or_else(|| bind.clone());
                    match yubaba::raft::bootstrap_single_node(&raft_node, node_id, addr).await {
                        Ok(true) => tracing::info!(
                            node_id,
                            "raft cluster-of-one initialised (single-node bootstrap)"
                        ),
                        Ok(false) => tracing::info!(
                            node_id,
                            "raft already initialised — single-node bootstrap is a no-op"
                        ),
                        Err(e) => return Err(e.context("single-node raft bootstrap")),
                    }
                }
                let shared_state = Arc::new(server_state);
                // Spawn leadership watcher before serving so Headscale starts
                // immediately on the first leader election.
                let _watcher =
                    yubaba::leader::spawn(node_id, raft_node.clone(), Arc::clone(&shared_state));
                // R600-F4 (W273): every node consuming a cluster cert runs the
                // rotation watcher — not just the elected issuer. On a replicated
                // cert renewal it re-renders the local tmpfs mount and graceful-
                // upgrades the consuming workload. No-op until a workload with a
                // cluster File secret is deployed on this node.
                tokio::spawn(yubaba::secret_reload::run(Arc::clone(&shared_state)));
                // R600-F3 (W273): the fleet-shared ACME issuer. Opt-in — only
                // spawns when YUBABA_ACME_DOMAIN et al are set (the HA fleet),
                // and only one node issues at a time (raft-lock elected). Reads
                // the stored cert's age via the state-machine handle to decide
                // renewal; seals cert+key under the node KEK and PutSecrets them.
                match yubaba::acme_issuer::parse_issuer_config(|k| std::env::var(k).ok()) {
                    Ok(Some(issuer_cfg)) => {
                        let _issuer = yubaba::acme_issuer::spawn(
                            node_id,
                            raft_node,
                            state_machine,
                            issuer_cfg,
                        );
                    }
                    Ok(None) => {}
                    Err(e) => tracing::error!(
                        "acme issuer config invalid — issuer not started (fix YUBABA_ACME_*): {e}"
                    ),
                }
                serve(&bind, shared_state).await
            } else {
                // Single-node mode: real containerd runtime, no raft mesh.
                // This is the intentional surface tested before adding HA (R276-F4).
                // Use --raft-node-id to enable the cluster coordination layer.
                tracing::info!(
                    "yubaba running in single-node mode — \
                     containerd runtime active, raft mesh disabled. \
                     Deploy workloads with `yah cloud workload deploy`. \
                     Pass --raft-node-id to enable cluster coordination."
                );
                serve(&bind, Arc::new(server_state)).await
            }
        }

        Cmd::RegisterHostkey { pubkey_path, state } => {
            let id = identity::parse_pubkey_file(&pubkey_path)
                .with_context(|| format!("parsing {}", pubkey_path.display()))?;
            let mut on_disk = identity::load_state(&state)?;
            on_disk.identity = Some(id.clone());
            identity::save_state(&state, &on_disk)?;
            println!("{}", id.hostkey_fingerprint);
            Ok(())
        }

        Cmd::Raft { daemon, cmd } => match cmd {
            RaftCmd::Status => {
                let body: serde_json::Value = reqwest::get(format!("{daemon}/raft/status"))
                    .await?
                    .json()
                    .await?;
                println!("{}", serde_json::to_string_pretty(&body)?);
                Ok(())
            }
            RaftCmd::Init { members } => {
                let mut parsed = std::collections::BTreeMap::new();
                for m in &members {
                    let (id, addr) = m.split_once('=').ok_or_else(|| {
                        anyhow::anyhow!("--member must be id=host:port, got {m:?}")
                    })?;
                    let id: u64 = id
                        .parse()
                        .with_context(|| format!("--member node id must be a u64, got {id:?}"))?;
                    parsed.insert(id, addr.to_string());
                }
                let client = reqwest::Client::new();
                let resp = client
                    .post(format!("{daemon}/raft/initialize"))
                    .json(&serde_json::json!({ "members": parsed }))
                    .send()
                    .await?;
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    println!("{body}");
                } else {
                    anyhow::bail!("raft init failed ({status}): {body}");
                }
                Ok(())
            }
            RaftCmd::AddLearner { node_id, addr } => {
                let client = reqwest::Client::new();
                let resp = client
                    .post(format!("{daemon}/raft/add-learner"))
                    .json(&serde_json::json!({ "node_id": node_id, "addr": addr }))
                    .send()
                    .await?;
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    println!("{body}");
                } else {
                    anyhow::bail!("raft add-learner failed ({status}): {body}");
                }
                Ok(())
            }
            RaftCmd::Peers => {
                // Peers are included in the metrics membership_config field.
                let body: serde_json::Value = reqwest::get(format!("{daemon}/raft/status"))
                    .await?
                    .json()
                    .await?;
                let peers = &body["membership_config"];
                println!("{}", serde_json::to_string_pretty(peers)?);
                Ok(())
            }
            RaftCmd::TransferLeader { to } => {
                let client = reqwest::Client::new();
                let resp = client
                    .post(format!("{daemon}/raft/transfer-leader"))
                    .json(&serde_json::json!({ "to": to }))
                    .send()
                    .await?;
                if resp.status().is_success() {
                    println!("leadership transfer to node {to} initiated");
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    anyhow::bail!("transfer-leader failed ({status}): {body}");
                }
                Ok(())
            }
        },
    }
}

/// Attach a `ContainerRuntime` to the server state when one is available.
///
/// With the `containerd-integration` feature, connect to the containerd socket
/// and wire `ContainerdRuntime` so `/workloads/*` deploy real containers. On
/// connection failure the daemon stays up in stub mode — the other endpoints
/// (`/identity`, `/raft/*`, `/headscale/*`) don't depend on containerd, and a
/// loud warning tells the operator workloads won't deploy until it's reachable.
///
/// Without the feature, the binary has no container backend compiled in, so
/// `/workloads/deploy` reports `runtime=stub`. The single-node deploy path
/// (R276) requires a binary built with `--features containerd-integration`.
#[allow(unused_variables, unused_mut)]
async fn attach_runtime(mut state: ServerState, containerd_socket: &str) -> ServerState {
    #[cfg(feature = "containerd-integration")]
    {
        match kamaji::containerd::ContainerdRuntime::connect_at(containerd_socket).await {
            Ok(rt) => {
                tracing::info!(
                    socket = %containerd_socket,
                    "containerd runtime attached; /workloads/* are live"
                );
                state = state.with_runtime(Arc::new(rt));
            }
            Err(e) => {
                tracing::warn!(
                    socket = %containerd_socket,
                    error = %e,
                    "containerd unreachable; /workloads/deploy runs in stub mode \
                     until the socket is available"
                );
            }
        }
    }
    #[cfg(not(feature = "containerd-integration"))]
    {
        tracing::warn!(
            "yah-yubaba built without the containerd-integration feature; \
             /workloads/deploy runs in stub mode (rebuild with \
             --features containerd-integration to deploy real containers)"
        );
    }
    state
}

/// Wire the pond [`local_driver::LocalRuntime`] when a docker socket is
/// reachable, flipping `POST /pond/deploy` from 503 to live.
///
/// The containerized pond yubaba (R454-F1) gets the host docker socket
/// bind-mounted at `/var/run/docker.sock` (see
/// `local_driver::pond_warden::build_warden_run_spec`); sibling MinIO/
/// miniflare containers spawn through it as host siblings, never
/// docker-in-docker. `DOCKER_HOST` overrides the socket path for
/// non-standard runtimes. When neither is present (cloud/systemd nodes),
/// pond stays unwired and the routes answer 503 — that's the correct
/// shape for non-pond deployments.
async fn attach_pond_runtime(state: ServerState) -> ServerState {
    let docker_host = match std::env::var("DOCKER_HOST") {
        Ok(h) if !h.trim().is_empty() => h,
        _ => {
            let sock =
                std::path::Path::new(local_driver::pond_warden::DOCKER_SOCKET_CONTAINER_PATH);
            if !sock.exists() {
                tracing::info!(
                    socket = %sock.display(),
                    "no docker socket mounted; pond deploy routes stay 503 \
                     (expected outside pond)"
                );
                return state;
            }
            format!("unix://{}", sock.display())
        }
    };

    let spec = local_driver::LocalContainerSpec {
        runtime: local_driver::RuntimePref::Custom,
        discovery: Default::default(),
        custom_docker_host: Some(docker_host.clone()),
    };
    match local_driver::LocalRuntime::detect(&spec).await {
        Ok(rt) => {
            tracing::info!(
                docker_host = %docker_host,
                probe_host = %local_driver::pond_probe_host(),
                "pond LocalRuntime attached; /pond/deploy is live"
            );
            state.with_pond_local_runtime(Arc::new(rt))
        }
        Err(e) => {
            tracing::warn!(
                docker_host = %docker_host,
                error = %e,
                "pond LocalRuntime detect failed; /pond/deploy stays 503"
            );
            state
        }
    }
}

/// Connect to Kamaji when `--kamaji-socket` is set, retrying with backoff to
/// ride out the sibling unit's socket-bind gap on a fresh boot (see
/// [`KAMAJI_CONNECT_BUDGET_SECS`]). If the whole budget is exhausted, log a
/// warning and leave `constable_client = None` so yubaba falls back to the
/// legacy in-process runtime.
async fn attach_constable_client(state: ServerState, socket: Option<PathBuf>) -> ServerState {
    let Some(socket) = socket else {
        return state;
    };
    let per_attempt = std::time::Duration::from_secs(CONSTABLE_CONNECT_TIMEOUT_SECS);
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(KAMAJI_CONNECT_BUDGET_SECS);
    let mut backoff = std::time::Duration::from_millis(500);
    let last_err = loop {
        match kamaji::sibling::connect_with_timeout(socket.clone(), per_attempt).await {
            Ok(client) => {
                tracing::info!(
                    socket = %socket.display(),
                    kamaji_version = %client.info().kamaji_version,
                    "kamaji client attached; workload list/state/drain dispatch \
                     through UDS"
                );
                return state.with_constable_client(Arc::new(client));
            }
            Err(e) => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    break e;
                }
                // Never sleep past the budget deadline.
                let nap = backoff.min(deadline - now);
                tracing::debug!(
                    socket = %socket.display(),
                    error = %e,
                    retry_in = ?nap,
                    "kamaji UDS not ready yet (sibling unit still settling); retrying"
                );
                tokio::time::sleep(nap).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(3));
            }
        }
    };
    tracing::warn!(
        socket = %socket.display(),
        error = %last_err,
        budget_secs = KAMAJI_CONNECT_BUDGET_SECS,
        "kamaji UDS connect failed within budget; falling back to in-process \
         ContainerRuntime for workload lifecycle"
    );
    state
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    // `yubaba` = lib target; `yah_warden` = this binary crate (where the
    // serve-time runtime-attach + channel lines are emitted). Include both so
    // the stub-mode warning is visible by default.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("yubaba=info,yah_warden=info,axum=info"));
    // JSON format: one structured line per event, carrying all tracing fields
    // (including the request_id + session_id stamped by the correlation-ID
    // middleware). Agents and scryer ingest these lines directly; the desktop
    // pretty-prints them for humans.
    fmt().with_env_filter(filter).json().init();
}
