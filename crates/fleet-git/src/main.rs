//! `fleet-git serve` (the workload), `fleet-git hook <stage>` (what the repo
//! hooks exec), `fleet-git probe` (check this host's git and exit).

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use fleet_git::auth::GitAuth;
use fleet_git::fence::{Fence, FENCE_PERIOD};
use fleet_git::hook::{self, Stage};
use fleet_git::hydrate::{self, Startup};
use fleet_git::serve::{serve, PushLocks, ServeConfig, ServeExit};
use fleet_git::snapshot::{self, SnapshotPolicy};
use fleet_git::stream::R2Log;
use fleet_git::gitbin;
use object_store::aws::{AmazonS3Builder, S3ConditionalPut};
use object_store::ObjectStore;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use store_claim::BackupTarget;

#[derive(Parser)]
#[command(name = "fleet-git", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server.
    Serve(ServeArgs),
    /// Hook mode: forward a pre/post-receive to the supervisor over $FLEET_GIT_SOCK.
    Hook { stage: String },
    /// Check this host's git (present, new enough, http-backend executable).
    Probe,
}

#[derive(Clone, Copy, ValueEnum)]
enum StoreKind {
    /// An S3-compatible bucket (R2 in prod).
    S3,
    /// In-process only, for local runs: the claim dies with the process.
    Memory,
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Repo root (the named volume).
    #[arg(long, env = "FLEET_GIT_ROOT", default_value = "/var/lib/fleet-git")]
    root: PathBuf,
    /// Listen address. Default: $YAH_MESH_IP:$PORT (the placement contract
    /// kamaji injects), else 127.0.0.1:4330. Never a wildcard by default.
    #[arg(long, env = "FLEET_GIT_LISTEN")]
    listen: Option<SocketAddr>,
    /// Hook socket. Default: <root>/fleet-git.sock.
    #[arg(long, env = "FLEET_GIT_SOCK_PATH")]
    sock: Option<PathBuf>,
    /// Claim owner label. Default: fleet-git@<hostname>.
    #[arg(long, env = "FLEET_GIT_OWNER")]
    owner: Option<String>,
    /// The git key's public half (32 raw bytes or 64 hex).
    #[arg(long, env = "FLEET_GIT_AUTH_PUBLIC_KEY_FILE")]
    auth_key_file: PathBuf,
    #[arg(long, env = "FLEET_GIT_AUTH_ISS", default_value = "yah-camp")]
    auth_iss: String,
    #[arg(long, env = "FLEET_GIT_STORE", value_enum, default_value = "s3")]
    store: StoreKind,
    #[arg(long, env = "FLEET_GIT_S3_ENDPOINT")]
    s3_endpoint: Option<String>,
    #[arg(long, env = "FLEET_GIT_S3_BUCKET", default_value = "yah-fleet-git")]
    s3_bucket: String,
    #[arg(long, env = "FLEET_GIT_S3_REGION", default_value = "auto")]
    s3_region: String,
    #[arg(long, env = "FLEET_GIT_S3_ACCESS_KEY_ID_FILE")]
    s3_access_key_id_file: Option<PathBuf>,
    #[arg(long, env = "FLEET_GIT_S3_SECRET_KEY_FILE")]
    s3_secret_key_file: Option<PathBuf>,
    /// Key prefix inside the bucket. Empty in prod (W363 §2: dedicated bucket).
    #[arg(long, env = "FLEET_GIT_PREFIX", default_value = "")]
    prefix: String,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Hook { stage } => match Stage::parse(&stage) {
            Some(s) => hook::run_client(s),
            None => {
                eprintln!("fleet-git: unknown hook stage {stage:?}");
                2
            }
        },
        Cmd::Probe => match gitbin::probe() {
            Ok(g) => {
                println!(
                    "git {}.{}.{} at {}; http-backend {}",
                    g.version.0,
                    g.version.1,
                    g.version.2,
                    g.exec_path.display(),
                    g.http_backend.display()
                );
                0
            }
            Err(e) => {
                eprintln!("fleet-git: {e:#}");
                1
            }
        },
        Cmd::Serve(args) => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            match rt.block_on(run_serve(args)) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("fleet-git: {e:#}");
                    1
                }
            }
        }
    };
    std::process::exit(code);
}

async fn run_serve(a: ServeArgs) -> Result<()> {
    // Startup probe first: a host without a usable git exits non-zero here,
    // before touching the claim.
    let git = gitbin::probe()?;
    tracing::info!(version = ?git.version, backend = %git.http_backend.display(), "using the host's git");
    let auth = GitAuth::from_key_file(&a.auth_key_file, &a.auth_iss)?;
    tracing::info!(kid = auth.kid(), iss = %a.auth_iss, "token verify key loaded");

    let store: Arc<dyn ObjectStore> = match a.store {
        StoreKind::Memory => {
            tracing::warn!("in-memory claim store: for local runs only, nothing is fenced across processes");
            Arc::new(object_store::memory::InMemory::new())
        }
        StoreKind::S3 => {
            let endpoint = a.s3_endpoint.context("--s3-endpoint / FLEET_GIT_S3_ENDPOINT is required")?;
            let read = |p: &Option<PathBuf>, what: &str| -> Result<String> {
                let p = p.as_ref().with_context(|| format!("{what} file is required"))?;
                Ok(std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?.trim().to_string())
            };
            Arc::new(
                AmazonS3Builder::new()
                    .with_endpoint(&endpoint)
                    .with_bucket_name(&a.s3_bucket)
                    .with_region(&a.s3_region)
                    .with_access_key_id(read(&a.s3_access_key_id_file, "S3 access key id")?)
                    .with_secret_access_key(read(&a.s3_secret_key_file, "S3 secret key")?)
                    .with_conditional_put(S3ConditionalPut::ETagMatch)
                    .with_allow_http(true)
                    .with_virtual_hosted_style_request(false)
                    .build()?,
            )
        }
    };

    let owner = match a.owner {
        Some(o) => o,
        None => format!("fleet-git@{}", hostname()),
    };
    // W363 §4 steps 1–2: probe conditional puts (Degraded refuses), acquire
    // (Lost exits non-zero).
    let target = BackupTarget { store: Arc::clone(&store), prefix: a.prefix.clone() };
    let fence = Fence::establish(BackupTarget { store: Arc::clone(&store), prefix: a.prefix.clone() }, &owner).await?;
    // Steps 3–6: rehydrate every repo, assert the claim, connectivity-check.
    let hook_exe = std::env::current_exe()?;
    match hydrate::startup(&target, &fence, &git, &a.root, &hook_exe).await? {
        Startup::Ready(reports) => {
            for r in &reports {
                tracing::info!(repo = %r.repo, mode = ?r.mode, base = r.base, replayed = r.replayed.len(), seq = r.seq, ms = r.elapsed.as_millis() as u64, "rehydrated");
            }
        }
        Startup::Superseded(why) => {
            tracing::warn!(%why, "writer claim superseded during rehydrate; exiting 0");
            return Ok(());
        }
    }
    let log = Arc::new(R2Log::new(
        BackupTarget { store, prefix: a.prefix },
        Arc::clone(&fence),
        &owner,
        git.git.clone(),
    ));
    let locks = Arc::new(PushLocks::default());

    let listen = match a.listen {
        Some(l) => l,
        None => default_listen()?,
    };
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    tracing::info!(%listen, epoch = fence.epoch(), %owner, "fleet-git serving");
    let sock = a.sock.unwrap_or_else(|| a.root.join("fleet-git.sock"));
    let cfg = ServeConfig {
        root: a.root,
        hook_sock: sock,
        hook_exe,
        git,
        auth,
        fence_period: FENCE_PERIOD,
        locks: Arc::clone(&locks),
    };
    let maintenance = tokio::spawn(snapshot::maintain(
        Arc::clone(&log),
        locks,
        cfg.root.clone(),
        SnapshotPolicy::default(),
        std::time::Duration::from_secs(300),
    ));
    let exit = serve(cfg, fence, log, listener, shutdown_signal()).await;
    maintenance.abort();
    match exit? {
        ServeExit::FenceLost(why) => {
            // Exit 0 so restart_policy = on-failure does not re-acquire (W363 §3).
            tracing::warn!(%why, "writer claim lost; exiting 0");
            Ok(())
        }
        ServeExit::Signalled => Ok(()),
    }
}

fn default_listen() -> Result<SocketAddr> {
    let port: u16 = match std::env::var("PORT") {
        Ok(p) => p.parse().with_context(|| format!("PORT={p:?} is not a port"))?,
        Err(_) => 4330,
    };
    let ip = match std::env::var("YAH_MESH_IP") {
        Ok(ip) => ip.parse().with_context(|| format!("YAH_MESH_IP={ip:?} is not an IP"))?,
        Err(_) => std::net::IpAddr::from([127, 0, 0, 1]),
    };
    if ip.is_unspecified() {
        bail!("refusing to bind a wildcard address by default; pass --listen explicitly");
    }
    Ok(SocketAddr::new(ip, port))
}

fn hostname() -> String {
    let raw = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| {
            std::process::Command::new("hostname").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        })
        .unwrap_or_default();
    let h: String = raw.trim().chars().filter(|c| !c.is_whitespace()).collect();
    if h.is_empty() {
        "unknown".into()
    } else {
        h
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => {}
        _ = term.recv() => {}
    }
}
