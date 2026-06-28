use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

const DEFAULT_SOCKET: &str = "/run/kamaji/kamaji.sock";
const ABOUT: &str = "kamaji — Yubaba's sibling process supervisor.\n\nReads workload-control messages from Yubaba over a unix domain socket and dispatches them to the containerd backend (R406-T9) or the native fork+exec path (R406-T5/T6). Run with --containerd-socket to enable container workloads.";

struct Args {
    socket: PathBuf,
    containerd_socket: Option<PathBuf>,
}

fn parse_args() -> std::result::Result<Args, ParseError> {
    let mut socket: PathBuf = std::env::var_os("CONSTABLE_SOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    let mut containerd_socket: Option<PathBuf> = std::env::var_os("CONTAINERD_SOCK").map(PathBuf::from);

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--socket" | "-s" => {
                socket = iter
                    .next()
                    .map(PathBuf::from)
                    .ok_or(ParseError::MissingValue("--socket"))?;
            }
            "--containerd-socket" => {
                containerd_socket = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--containerd-socket"))?,
                );
            }
            "--help" | "-h" => return Err(ParseError::HelpRequested),
            "--version" | "-V" => return Err(ParseError::VersionRequested),
            other => return Err(ParseError::Unknown(other.to_string())),
        }
    }
    Ok(Args {
        socket,
        containerd_socket,
    })
}

enum ParseError {
    MissingValue(&'static str),
    Unknown(String),
    HelpRequested,
    VersionRequested,
}

fn print_help() {
    println!("{ABOUT}");
    println!();
    println!("Usage: kamaji [--socket PATH] [--containerd-socket PATH]");
    println!();
    println!("Options:");
    println!(
        "  -s, --socket PATH         UDS path to bind (default: ${{CONSTABLE_SOCK:-{DEFAULT_SOCKET}}})"
    );
    println!(
        "      --containerd-socket PATH  containerd UDS to dispatch Container workloads to"
    );
    println!("                                (default: $CONTAINERD_SOCK, else container deploys are refused)");
    println!("  -h, --help                Print this message and exit");
    println!("  -V, --version             Print version and exit");
}

fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = match parse_args() {
        Ok(a) => a,
        Err(ParseError::HelpRequested) => {
            print_help();
            return Ok(());
        }
        Err(ParseError::VersionRequested) => {
            println!("kamaji {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Err(ParseError::MissingValue(flag)) => {
            anyhow::bail!("flag {flag} requires a value");
        }
        Err(ParseError::Unknown(arg)) => {
            anyhow::bail!("unknown argument: {arg}");
        }
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let ctx = build_ctx(args.containerd_socket).await?;
        kamaji_bin::serve_with_ctx(
            &args.socket,
            ctx,
            async {
                let _ = tokio::signal::ctrl_c().await;
            },
        )
        .await
    })
}

/// Assemble the [`kamaji_bin::ServerCtx`]. Attaches a containerd backend when
/// the operator passed `--containerd-socket` (or set `CONTAINERD_SOCK`) and
/// the binary was built with `--features containerd-integration`. Failures
/// here are fatal — if the operator asked for containerd, missing it means
/// container deploys would silently refuse and that should surface at
/// startup, not on the first deploy.
///
/// The log sink is the journald datagram socket (R406-T10). On hosts
/// without journald reachable, [`kamaji_bin::JournalSender::connect`] falls
/// back to tracing — see `crate::journal` for the fallback path.
async fn build_ctx(
    containerd_socket: Option<PathBuf>,
) -> Result<Arc<kamaji_bin::ServerCtx>> {
    let log_sink: std::sync::Arc<dyn kamaji_bin::LogSink> =
        std::sync::Arc::new(kamaji_bin::JournalSender::connect());
    #[cfg(feature = "containerd-integration")]
    {
        let ctx = kamaji_bin::ServerCtx::new().with_log_sink(log_sink.clone());
        let ctx = if let Some(sock) = containerd_socket {
            let backend = kamaji_bin::containerd::ContainerdBackend::connect_at(&sock)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to connect to containerd at {}: {e}",
                        sock.display()
                    )
                })?
                .with_log_sink(log_sink);
            tracing::info!(
                socket = %sock.display(),
                "containerd backend attached"
            );
            ctx.with_containerd(std::sync::Arc::new(backend))
        } else {
            tracing::warn!(
                "no --containerd-socket; Deploy {{ Container }} will refuse with BackendRefused. \
                 Pass --containerd-socket /run/containerd/containerd.sock for the production path."
            );
            ctx
        };
        Ok(Arc::new(ctx))
    }
    #[cfg(not(feature = "containerd-integration"))]
    {
        if containerd_socket.is_some() {
            anyhow::bail!(
                "--containerd-socket requires the kamaji binary be built with \
                 --features containerd-integration"
            );
        }
        Ok(Arc::new(
            kamaji_bin::ServerCtx::new().with_log_sink(log_sink),
        ))
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kamaji: {e:#}");
            ExitCode::FAILURE
        }
    }
}
