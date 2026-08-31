//! @arch:layer(core)
//! @arch:role(net)
//!
//! The **camp-RPC** lane of the yah control plane — serve a workspace's
//! `yah camp --stdio` JSON-RPC over the same [`mshr::Endpoint`] the
//! `yah/control/1` greeting listens on.
//!
//! Part of R609-F2 — annotation in
//! `.yah/docs/working/W242-yubaba-mesh-raft-roadmap.md`.
//!
//! Today the desktop reaches a remote camp by shelling out to `ssh` and
//! running `yah camp --stdio --workspace <path>` on the far host
//! (A043 §"Desktop dispatch"). This lane is the same thing minus SSH:
//! the caller dials this machine's `NodeId` over NAT-punched QUIC, names
//! a workspace, and gets the identical line-delimited JSON-RPC byte
//! stream back. Because the bytes match, the desktop's `CampRpcClient`
//! is unchanged — only its transport swaps, which is what makes a BYO
//! VPS reachable exactly like a managed rig (W197 §"mode A vs B").
//!
//! ## Wire protocol on [`CAMP_RPC_ALPN`]
//!
//! ```text
//! client → {"v":1,"workspace":"/srv/code"}\n     (one line)
//! server → {"ok":true}\n                          (one line)
//!          {"ok":false,"error":"…"}\n             (and closes)
//! … thereafter: line-delimited JSON-RPC 2.0, both directions …
//! ```
//!
//! SSH carries the workspace in the remote command line; QUIC has no
//! command line, so the dialer states it in-band. The ack exists so a
//! refused workspace fails with a reason instead of hanging until the
//! caller's first RPC times out.
//!
//! ## Why this is opt-in and root-scoped
//!
//! Admitting a dial here means **spawning a process** on this machine.
//! R609-F3 (cheers entitlement via [`mshr::Acceptor`]) has not landed,
//! so the QUIC handshake proves *which* NodeId called and nothing about
//! whether it is allowed to. Two containments stand in until F3:
//!
//! 1. The lane is off unless the operator passes `--camp-rpc-root`.
//! 2. Every requested workspace must sit under one of those roots —
//!    an empty root list serves nothing at all.
//!
//! Neither is a substitute for authentication. Do not enable this lane
//! on a node reachable by NodeIds you do not control until F3 lands.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// ALPN for the camp-RPC lane, as a string.
///
/// **Mirrored** by `CAMP_RPC_ALPN_STR` in the yah monorepo at
/// `crates/yah/rpc-ssh/src/mshr.rs`. yubaba must stay buildable as a
/// standalone export (see the yah CLAUDE.md §"Co-developed OSS repos"),
/// so no crate can own this constant for both sides. A mismatch fails
/// loudly at ALPN negotiation — but if you change one spelling, change
/// the other.
pub const CAMP_RPC_ALPN_STR: &str = "yah/camp-rpc/1";

/// ALPN for the camp-RPC lane. Versioned in the string so an
/// incompatible framing is a second ALPN rather than a flag day.
pub const CAMP_RPC_ALPN: &[u8] = CAMP_RPC_ALPN_STR.as_bytes();

/// Cap on the opening hello frame. A caller that sends more than this
/// without a newline is not speaking this protocol; the cap keeps an
/// unauthenticated dialer from making us buffer without bound.
const MAX_HELLO_BYTES: usize = 8 * 1024;

/// Opening frame: which workspace on this host to serve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampRpcHello {
    /// Protocol version of *this* framing (not the JSON-RPC surface).
    pub v: u32,
    /// Absolute workspace path on this host.
    pub workspace: String,
}

/// Answer to a [`CampRpcHello`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampRpcAck {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CampRpcAck {
    fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }

    fn refused(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(reason.into()),
        }
    }
}

/// What this node will serve on the camp-RPC lane.
#[derive(Debug, Clone)]
pub struct CampRpcConfig {
    /// The `yah` binary to exec. Bare `"yah"` resolves through `$PATH`,
    /// matching what the SSH path does on the far side today.
    pub yah_bin: String,
    /// Workspace roots this node is willing to open. A request outside
    /// every root is refused; an empty list refuses everything, which is
    /// the correct posture for a misconfigured deployment (fail closed).
    pub roots: Vec<PathBuf>,
}

impl CampRpcConfig {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            yah_bin: "yah".to_string(),
            roots,
        }
    }

    /// Resolve a requested workspace against the allowed roots.
    ///
    /// Canonicalizes both sides before comparing: without that, `..`
    /// segments walk straight out of a root and the containment is
    /// decorative. A workspace that does not exist is refused here
    /// rather than handed to `yah camp`, whose own error would reach the
    /// caller as an opaque RPC failure after the ack said yes.
    pub fn resolve(&self, requested: &str) -> Result<PathBuf, String> {
        if self.roots.is_empty() {
            return Err("this node serves no camp-rpc roots".to_string());
        }
        let path = Path::new(requested);
        if !path.is_absolute() {
            return Err(format!("workspace {requested:?} is not an absolute path"));
        }
        let real = path
            .canonicalize()
            .map_err(|e| format!("workspace {requested:?} is not openable: {e}"))?;
        for root in &self.roots {
            // A root that cannot be canonicalized (deleted after start,
            // typo'd on the command line) matches nothing rather than
            // matching everything.
            let Ok(root) = root.canonicalize() else {
                continue;
            };
            if real.starts_with(&root) {
                return Ok(real);
            }
        }
        Err(format!(
            "workspace {requested:?} is outside every camp-rpc root"
        ))
    }
}

/// Build the [`mshr::endpoint::AlpnHandler`] for this lane.
pub fn handler(config: CampRpcConfig) -> mshr::endpoint::AlpnHandler {
    let config = Arc::new(config);
    Arc::new(move |conn: mshr::Connection| {
        let config = Arc::clone(&config);
        Box::pin(async move { serve_connection(conn, config).await })
    })
}

/// Register this lane in an `accept_dispatch` handler map.
pub fn install(
    handlers: &mut HashMap<mshr::endpoint::Alpn, mshr::endpoint::AlpnHandler>,
    config: CampRpcConfig,
) {
    handlers.insert(CAMP_RPC_ALPN.to_vec(), handler(config));
}

/// Serve every bidirectional stream on one connection as an independent
/// camp session.
///
/// One connection can carry several: the desktop pays for one handshake
/// and can then open a second workspace (or reopen after a daemon
/// restart) without re-punching NAT.
async fn serve_connection(conn: mshr::Connection, config: Arc<CampRpcConfig>) -> Result<()> {
    let remote = conn.remote_id();
    tracing::debug!(remote = %remote, "camp-rpc connection accepted");
    while let Ok((send, recv)) = conn.accept_bi().await {
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = serve_stream(send, recv, config, remote).await {
                tracing::warn!(remote = %remote, error = format!("{e:#}"), "camp-rpc stream failed");
            }
        });
    }
    Ok(())
}

/// Drive one camp session: read the hello, ack, exec `yah camp --stdio`,
/// then pump bytes in both directions until either side closes.
async fn serve_stream(
    mut send: mshr::SendStream,
    recv: mshr::RecvStream,
    config: Arc<CampRpcConfig>,
    remote: mshr::NodeId,
) -> Result<()> {
    let mut reader = BufReader::new(recv);
    let Some(line) = read_capped_line(&mut reader, MAX_HELLO_BYTES).await? else {
        // Peer opened a stream and closed it without saying anything —
        // a reachability probe, not a fault.
        return Ok(());
    };

    let workspace = match serde_json::from_str::<CampRpcHello>(line.trim()) {
        Ok(hello) => match config.resolve(&hello.workspace) {
            Ok(path) => path,
            Err(reason) => {
                tracing::warn!(remote = %remote, reason = %reason, "camp-rpc workspace refused");
                return refuse(&mut send, reason).await;
            }
        },
        Err(e) => {
            return refuse(&mut send, format!("malformed camp-rpc hello: {e}")).await;
        }
    };

    let mut child = match Command::new(&config.yah_bin)
        .arg("camp")
        .arg("--stdio")
        .arg("--workspace")
        .arg(&workspace)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            let reason = format!("failed to spawn {}: {e}", config.yah_bin);
            tracing::warn!(remote = %remote, reason = %reason, "camp-rpc spawn failed");
            return refuse(&mut send, reason).await;
        }
    };

    write_frame(&mut send, &CampRpcAck::ok()).await?;
    tracing::info!(
        remote = %remote,
        workspace = %workspace.display(),
        "camp-rpc session open"
    );

    let mut stdin = child
        .stdin
        .take()
        .context("yah camp child missing stdin handle")?;
    let mut stdout = child
        .stdout
        .take()
        .context("yah camp child missing stdout handle")?;

    // Both directions run concurrently; the first to finish ends the
    // session. `select!` rather than joining because a dead child must
    // tear the QUIC stream down (and vice versa) instead of leaving the
    // peer waiting on a half that will never produce another byte.
    let to_child = tokio::io::copy(&mut reader, &mut stdin);
    let to_peer = tokio::io::copy(&mut stdout, &mut send);
    tokio::select! {
        r = to_child => { r.context("pumping peer → yah camp")?; }
        r = to_peer  => { r.context("pumping yah camp → peer")?; }
    }

    // `kill_on_drop` reaps the child when this future returns; finishing
    // the send half tells the peer this was an orderly end rather than a
    // connection reset.
    let _ = send.finish();
    tracing::info!(
        remote = %remote,
        workspace = %workspace.display(),
        "camp-rpc session closed"
    );
    Ok(())
}

async fn refuse(send: &mut mshr::SendStream, reason: impl Into<String>) -> Result<()> {
    write_frame(send, &CampRpcAck::refused(reason)).await?;
    let _ = send.finish();
    Ok(())
}

async fn write_frame(send: &mut mshr::SendStream, ack: &CampRpcAck) -> Result<()> {
    let mut frame = serde_json::to_vec(ack).context("serializing camp-rpc ack")?;
    frame.push(b'\n');
    send.write_all(&frame)
        .await
        .context("writing camp-rpc ack")?;
    send.flush().await.context("flushing camp-rpc ack")?;
    Ok(())
}

/// Read one `\n`-terminated line, refusing to buffer more than `max`
/// bytes. `Ok(None)` is a clean EOF before any byte arrived.
///
/// Hand-rolled rather than `read_line` (no cap) or `AsyncReadExt::take`
/// (`Take` is not `AsyncBufRead`, and the same `BufReader` must survive
/// into the byte pump — it may already hold JSON-RPC bytes that arrived
/// in the same datagram as the hello).
async fn read_capped_line<R>(reader: &mut R, max: usize) -> std::io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
{
    let mut out: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if out.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&out).into_owned())
            });
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            out.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            return Ok(Some(String::from_utf8_lossy(&out).into_owned()));
        }
        let taken = available.len();
        out.extend_from_slice(available);
        reader.consume(taken);
        if out.len() > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("camp-rpc hello exceeded {max} bytes without a newline"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ALPN string is duplicated in the yah monorepo's
    /// `crates/yah/rpc-ssh/src/mshr.rs` because the two workspaces cannot
    /// share a crate. Pin the exact bytes so a careless edit here is
    /// caught by a test rather than by a failed handshake in the field.
    #[test]
    fn the_alpn_is_the_versioned_spelling_the_desktop_dials() {
        assert_eq!(CAMP_RPC_ALPN_STR, "yah/camp-rpc/1");
        assert_eq!(CAMP_RPC_ALPN, b"yah/camp-rpc/1");
    }

    /// Fail closed: a node whose operator enabled the lane but named no
    /// root must serve nothing, not everything.
    #[test]
    fn no_roots_means_no_workspaces() {
        let cfg = CampRpcConfig::new(vec![]);
        let err = cfg.resolve("/tmp").unwrap_err();
        assert!(err.contains("no camp-rpc roots"), "unexpected: {err}");
    }

    #[test]
    fn a_workspace_under_a_root_resolves() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ws = tmp.path().join("code");
        std::fs::create_dir(&ws).unwrap();
        let cfg = CampRpcConfig::new(vec![tmp.path().to_path_buf()]);
        assert_eq!(
            cfg.resolve(ws.to_str().unwrap()).unwrap(),
            ws.canonicalize().unwrap()
        );
    }

    #[test]
    fn a_workspace_outside_every_root_is_refused() {
        let allowed = tempfile::TempDir::new().unwrap();
        let elsewhere = tempfile::TempDir::new().unwrap();
        let cfg = CampRpcConfig::new(vec![allowed.path().to_path_buf()]);
        let err = cfg.resolve(elsewhere.path().to_str().unwrap()).unwrap_err();
        assert!(
            err.contains("outside every camp-rpc root"),
            "unexpected: {err}"
        );
    }

    /// The containment this actually has to survive: `..` segments that
    /// spell a path *inside* a root but resolve *outside* it. Comparing
    /// the unresolved strings would admit this.
    #[test]
    fn dot_dot_cannot_escape_a_root() {
        let allowed = tempfile::TempDir::new().unwrap();
        let escape = allowed.path().join("..");
        let cfg = CampRpcConfig::new(vec![allowed.path().join("inner")]);
        std::fs::create_dir(allowed.path().join("inner")).unwrap();
        let err = cfg.resolve(escape.to_str().unwrap()).unwrap_err();
        assert!(
            err.contains("outside every camp-rpc root"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn a_relative_workspace_is_refused_before_touching_the_filesystem() {
        let cfg = CampRpcConfig::new(vec![PathBuf::from("/")]);
        let err = cfg.resolve("code").unwrap_err();
        assert!(err.contains("not an absolute path"), "unexpected: {err}");
    }

    #[test]
    fn a_nonexistent_workspace_is_refused_rather_than_handed_to_yah_camp() {
        let allowed = tempfile::TempDir::new().unwrap();
        let missing = allowed.path().join("nope");
        let cfg = CampRpcConfig::new(vec![allowed.path().to_path_buf()]);
        let err = cfg.resolve(missing.to_str().unwrap()).unwrap_err();
        assert!(err.contains("not openable"), "unexpected: {err}");
    }

    #[tokio::test]
    async fn a_capped_line_stops_at_the_newline_and_leaves_the_rest_buffered() {
        let data: &[u8] = b"{\"v\":1}\nleftover\n";
        let mut reader = BufReader::new(data);
        let first = read_capped_line(&mut reader, 1024).await.unwrap();
        assert_eq!(first.as_deref(), Some("{\"v\":1}"));
        let second = read_capped_line(&mut reader, 1024).await.unwrap();
        assert_eq!(second.as_deref(), Some("leftover"));
    }

    #[tokio::test]
    async fn a_newlineless_flood_is_cut_off_rather_than_buffered() {
        let flood = vec![b'x'; MAX_HELLO_BYTES * 2];
        let mut reader = BufReader::new(&flood[..]);
        let err = read_capped_line(&mut reader, MAX_HELLO_BYTES)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    // ── End-to-end over a real QUIC dial ──────────────────────────────
    //
    // These stand in for `yah camp --stdio` with a shell script that
    // echoes stdin back. That is enough to prove the parts this module
    // actually owns — ALPN registration, the hello/ack handshake, the
    // spawn, and the bidirectional pump — without needing the yah binary
    // (which lives in the other workspace) on the test machine.

    /// Write an executable stand-in for `yah` that ignores its arguments
    /// and echoes stdin to stdout, so a round-trip through the pump is
    /// observable.
    #[cfg(unix)]
    fn fake_yah(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("fake-yah");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    async fn serving_node(
        config: CampRpcConfig,
    ) -> (
        mshr::Endpoint,
        mshr::EndpointAddr,
        tokio::task::JoinHandle<()>,
    ) {
        let endpoint = mshr::Endpoint::builder()
            .keypair(mshr::Keypair::generate())
            .alpns([CAMP_RPC_ALPN])
            .bind()
            .await
            .unwrap();
        let addr = endpoint.endpoint_addr();
        let mut handlers = HashMap::new();
        install(&mut handlers, config);
        let accept = endpoint.clone();
        let task = tokio::spawn(async move {
            let _ = accept.accept_dispatch(handlers).await;
        });
        (endpoint, addr, task)
    }

    #[cfg(unix)]
    async fn dial(
        addr: mshr::EndpointAddr,
        workspace: &str,
    ) -> (
        mshr::Endpoint,
        mshr::Connection,
        mshr::SendStream,
        BufReader<mshr::RecvStream>,
        CampRpcAck,
    ) {
        let dialer = mshr::Endpoint::builder()
            .keypair(mshr::Keypair::generate())
            .alpns([CAMP_RPC_ALPN])
            .bind()
            .await
            .unwrap();
        let conn = dialer.connect_alpn(addr, CAMP_RPC_ALPN).await.unwrap();
        let (mut send, recv) = conn.open_bi().await.unwrap();
        let hello = CampRpcHello {
            v: 1,
            workspace: workspace.to_string(),
        };
        let mut frame = serde_json::to_vec(&hello).unwrap();
        frame.push(b'\n');
        send.write_all(&frame).await.unwrap();
        send.flush().await.unwrap();
        let mut reader = BufReader::new(recv);
        let line = read_capped_line(&mut reader, MAX_HELLO_BYTES)
            .await
            .unwrap()
            .expect("server closed without acking");
        let ack: CampRpcAck = serde_json::from_str(line.trim()).unwrap();
        (dialer, conn, send, reader, ack)
    }

    /// The headline: a caller that reaches this node by NodeId gets a
    /// live byte pipe to a process spawned for its workspace. Nothing
    /// below the QUIC dial is stubbed.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_dialer_gets_a_live_pipe_to_the_spawned_camp() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ws = tmp.path().join("code");
        std::fs::create_dir(&ws).unwrap();
        let config = CampRpcConfig {
            yah_bin: fake_yah(tmp.path(), "exec cat").display().to_string(),
            roots: vec![tmp.path().to_path_buf()],
        };

        let (server, addr, task) = serving_node(config).await;
        let (dialer, conn, mut send, mut reader, ack) = dial(addr, ws.to_str().unwrap()).await;
        assert!(ack.ok, "workspace refused: {:?}", ack.error);

        send.write_all(b"{\"jsonrpc\":\"2.0\"}\n").await.unwrap();
        send.flush().await.unwrap();
        let echoed = read_capped_line(&mut reader, 4096).await.unwrap();
        assert_eq!(echoed.as_deref(), Some("{\"jsonrpc\":\"2.0\"}"));

        drop(conn);
        dialer.close().await;
        server.close().await;
        task.abort();
    }

    /// A refused workspace must come back as a *reason* on the wire. If
    /// the server just closed, the caller could not distinguish "not
    /// allowed" from "still connecting" and would wait out its timeout.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_workspace_outside_the_roots_is_refused_on_the_wire() {
        let tmp = tempfile::TempDir::new().unwrap();
        let allowed = tmp.path().join("allowed");
        std::fs::create_dir(&allowed).unwrap();
        let config = CampRpcConfig {
            yah_bin: fake_yah(tmp.path(), "exec cat").display().to_string(),
            roots: vec![allowed],
        };

        let (server, addr, task) = serving_node(config).await;
        let (dialer, conn, _send, _reader, ack) = dial(addr, tmp.path().to_str().unwrap()).await;

        assert!(!ack.ok);
        assert!(
            ack.error
                .as_deref()
                .unwrap_or_default()
                .contains("outside every camp-rpc root"),
            "unexpected error: {:?}",
            ack.error
        );

        drop(conn);
        dialer.close().await;
        server.close().await;
        task.abort();
    }

    /// A node whose `yah` binary is missing must say so in the ack rather
    /// than ack success and then hand the caller a dead pipe.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unspawnable_yah_binary_is_refused_before_the_ack() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = CampRpcConfig {
            yah_bin: tmp.path().join("does-not-exist").display().to_string(),
            roots: vec![tmp.path().to_path_buf()],
        };

        let (server, addr, task) = serving_node(config).await;
        let (dialer, conn, _send, _reader, ack) = dial(addr, tmp.path().to_str().unwrap()).await;

        assert!(!ack.ok);
        assert!(
            ack.error
                .as_deref()
                .unwrap_or_default()
                .contains("failed to spawn"),
            "unexpected error: {:?}",
            ack.error
        );

        drop(conn);
        dialer.close().await;
        server.close().await;
        task.abort();
    }
}
