//! Workload health probe runner (R406-T11).
//!
//! ## Decision
//!
//! Kamaji polls the [`Healthcheck`](workload_spec::Healthcheck) declared in
//! the workload spec. Three executors map to the three [`HealthProbe`] variants:
//! `HttpGet`, `Exec`, `TcpConnect`. Stdio sentinel was considered and rejected
//! — see `.yah/docs/working/W154-yubaba-dual-runtime.md` §"Resolved decisions".
//!
//! ## Surface
//!
//! - [`ProbeTarget`] — per-workload data Kamaji retains across deploy:
//!   the [`Healthcheck`] spec plus the network endpoint to dial (`addr`,
//!   resolved at deploy time — `127.0.0.1` for native and pond, the
//!   containerd bridge IP for cloud-tier container workloads).
//! - [`run_probe`] — execute one probe and return [`ProbeStatus`]. Honors
//!   `Healthcheck.timeout`; on a `None` target returns `ProbeStatus::Ready`
//!   (no probe declared ↔ "trust the workload's existence as readiness").
//!
//! Yubaba drives cadence by re-issuing
//! [`constable_proto::WardenToConstable::Probe`]; this module answers one
//! probe per call. `Healthcheck.interval` / `initial_delay` /
//! `failure_threshold` live in Yubaba's policy layer.
//!
//! ## HTTP client choice
//!
//! HttpGet uses a hand-rolled HTTP/1.1 GET over `tokio::net::TcpStream` rather
//! than reqwest/hyper. Kamaji's memory budget is tight (W154 §"Memory
//! budget for cheap boxes" targets 15-25 MB RSS for the whole binary); the
//! +5-10 MB an HTTP client crate brings is hard to justify when the only
//! request shape is "GET <path> HTTP/1.1, read enough to extract the status
//! line". Probes are localhost-or-bridge anyway — no TLS, no redirect chains,
//! no proxy logic.

use std::net::SocketAddr;
use std::time::Duration;

use kamaji_proto::ProbeStatus;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use workload_spec::{HealthProbe, Healthcheck};

/// Per-workload probe configuration Kamaji retains across deploy.
///
/// `addr` is the host:port to dial for `HttpGet` / `TcpConnect`. The deploy
/// path resolves it at admission time:
///
/// - Native workload: `127.0.0.1` (host networking, port from the probe spec).
/// - Container workload: the containerd-assigned bridge IP, or `127.0.0.1`
///   for pond-tier container workloads on the docker socket.
///
/// `Exec` ignores `addr` — argv runs in the workload's namespace and doesn't
/// need a network endpoint.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub healthcheck: Healthcheck,
    pub addr: SocketAddr,
}

/// Execute a single probe against `target` and return its [`ProbeStatus`].
///
/// `target = None` is the "no healthcheck declared" path — surface
/// [`ProbeStatus::Ready`] so Yubaba's admission logic doesn't have to special-
/// case workloads without a spec'd probe.
pub async fn run_probe(target: Option<&ProbeTarget>) -> ProbeStatus {
    let Some(target) = target else {
        return ProbeStatus::Ready;
    };
    let deadline = Duration::from_millis(target.healthcheck.timeout.as_ms());
    match &target.healthcheck.probe {
        HealthProbe::HttpGet {
            path,
            port,
            expect_status,
        } => {
            let addr = with_port(target.addr, *port);
            run_http_get(addr, path, *expect_status, deadline).await
        }
        HealthProbe::TcpConnect { port } => {
            let addr = with_port(target.addr, *port);
            run_tcp_connect(addr, deadline).await
        }
        HealthProbe::Exec { argv } => run_exec(argv, deadline).await,
    }
}

fn with_port(addr: SocketAddr, port: u16) -> SocketAddr {
    let mut a = addr;
    a.set_port(port);
    a
}

async fn run_http_get(
    addr: SocketAddr,
    path: &str,
    expect_status: Option<u16>,
    deadline: Duration,
) -> ProbeStatus {
    match timeout(deadline, http_get_once(addr, path)).await {
        Ok(Ok(status)) => classify_http(status, expect_status),
        Ok(Err(HttpError::ConnectRefused)) => ProbeStatus::Starting,
        Ok(Err(HttpError::Io(e))) => ProbeStatus::Unhealthy {
            reason: format!("http probe i/o error: {e}"),
        },
        Ok(Err(HttpError::MalformedResponse(reason))) => ProbeStatus::Unhealthy { reason },
        Err(_) => ProbeStatus::Timeout,
    }
}

fn classify_http(status: u16, expect: Option<u16>) -> ProbeStatus {
    match expect {
        Some(want) if status == want => ProbeStatus::Ready,
        Some(want) => ProbeStatus::Unhealthy {
            reason: format!("http {status}, expected {want}"),
        },
        None if (200..300).contains(&status) => ProbeStatus::Ready,
        None => ProbeStatus::Unhealthy {
            reason: format!("http {status}"),
        },
    }
}

#[derive(Debug)]
enum HttpError {
    ConnectRefused,
    Io(std::io::Error),
    MalformedResponse(String),
}

async fn http_get_once(addr: SocketAddr, path: &str) -> Result<u16, HttpError> {
    let mut stream = TcpStream::connect(addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::ConnectionRefused {
            HttpError::ConnectRefused
        } else {
            HttpError::Io(e)
        }
    })?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: kamaji-probe\r\n\
         Accept: */*\r\nConnection: close\r\n\r\n",
        path = path,
        addr = addr,
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(HttpError::Io)?;
    stream.flush().await.map_err(HttpError::Io)?;

    // Read the status line. We don't need to consume the body — a probe only
    // cares about the response code, and the workload will see the connection
    // close once we drop the stream.
    let mut head = [0u8; 64];
    let mut filled = 0usize;
    loop {
        let n = stream
            .read(&mut head[filled..])
            .await
            .map_err(HttpError::Io)?;
        if n == 0 {
            break;
        }
        filled += n;
        if head[..filled].windows(2).any(|w| w == b"\r\n") {
            break;
        }
        if filled == head.len() {
            return Err(HttpError::MalformedResponse(
                "no CRLF in first 64 bytes of response".into(),
            ));
        }
    }
    parse_status_line(&head[..filled])
}

/// Extract the numeric status code from an HTTP/1.x status line.
/// Pure — easy to unit-test without a live socket.
fn parse_status_line(buf: &[u8]) -> Result<u16, HttpError> {
    let end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| HttpError::MalformedResponse("missing CRLF terminator".into()))?;
    let line = std::str::from_utf8(&buf[..end])
        .map_err(|_| HttpError::MalformedResponse("status line not utf-8".into()))?;
    let mut parts = line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or_else(|| HttpError::MalformedResponse("empty status line".into()))?;
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::MalformedResponse(format!(
            "unsupported version: {version}"
        )));
    }
    let code = parts
        .next()
        .ok_or_else(|| HttpError::MalformedResponse("missing status code".into()))?;
    code.parse::<u16>().map_err(|_| {
        HttpError::MalformedResponse(format!("status code {code:?} not a u16"))
    })
}

async fn run_tcp_connect(addr: SocketAddr, deadline: Duration) -> ProbeStatus {
    match timeout(deadline, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => ProbeStatus::Ready,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            ProbeStatus::Starting
        }
        Ok(Err(e)) => ProbeStatus::Unhealthy {
            reason: format!("tcp connect failed: {e}"),
        },
        Err(_) => ProbeStatus::Timeout,
    }
}

async fn run_exec(argv: &[String], deadline: Duration) -> ProbeStatus {
    if argv.is_empty() {
        return ProbeStatus::Unhealthy {
            reason: "exec probe argv is empty".into(),
        };
    }
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ProbeStatus::Unhealthy {
                reason: format!("exec probe spawn failed: {e}"),
            };
        }
    };

    match timeout(deadline, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            if output.status.success() {
                ProbeStatus::Ready
            } else {
                let stderr_tail = tail_utf8_lossy(&output.stderr, 256);
                let code_part = output
                    .status
                    .code()
                    .map(|c| format!("exit {c}"))
                    .unwrap_or_else(|| "signaled".to_string());
                let reason = if stderr_tail.is_empty() {
                    format!("exec probe failed: {code_part}")
                } else {
                    format!("exec probe failed: {code_part}: {stderr_tail}")
                };
                ProbeStatus::Unhealthy { reason }
            }
        }
        Ok(Err(e)) => ProbeStatus::Unhealthy {
            reason: format!("exec probe wait failed: {e}"),
        },
        Err(_) => ProbeStatus::Timeout,
    }
}

/// Take the last `cap` bytes (utf-8 lossy) so we surface the most-recent
/// stderr fragment without unbounded message growth.
fn tail_utf8_lossy(buf: &[u8], cap: usize) -> String {
    let start = buf.len().saturating_sub(cap);
    String::from_utf8_lossy(&buf[start..]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;
    use workload_spec::Millis;

    fn hc(probe: HealthProbe, timeout_ms: u64) -> Healthcheck {
        Healthcheck {
            probe,
            interval: Millis::from_ms(1000),
            timeout: Millis::from_ms(timeout_ms),
            initial_delay: Millis::from_ms(0),
            failure_threshold: 3,
        }
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    // ── parse_status_line ──────────────────────────────────────────────────────

    #[test]
    fn parse_status_line_extracts_2xx() {
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200 OK\r\nServer: x\r\n").unwrap(),
            200
        );
    }

    #[test]
    fn parse_status_line_extracts_5xx_with_no_reason_phrase() {
        // Some minimal servers omit the reason phrase entirely.
        assert_eq!(parse_status_line(b"HTTP/1.1 503 \r\n").unwrap(), 503);
    }

    #[test]
    fn parse_status_line_rejects_http2() {
        let err = parse_status_line(b"HTTP/2.0 200\r\n").unwrap_err();
        match err {
            HttpError::MalformedResponse(m) => assert!(m.contains("unsupported")),
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[test]
    fn parse_status_line_rejects_missing_crlf() {
        let err = parse_status_line(b"HTTP/1.1 200 OK").unwrap_err();
        assert!(matches!(err, HttpError::MalformedResponse(_)));
    }

    // ── classify_http ──────────────────────────────────────────────────────────

    #[test]
    fn classify_http_2xx_with_no_expect_is_ready() {
        assert!(matches!(classify_http(200, None), ProbeStatus::Ready));
        assert!(matches!(classify_http(204, None), ProbeStatus::Ready));
    }

    #[test]
    fn classify_http_5xx_with_no_expect_is_unhealthy() {
        match classify_http(500, None) {
            ProbeStatus::Unhealthy { reason } => assert!(reason.contains("500")),
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[test]
    fn classify_http_expect_match_is_ready() {
        assert!(matches!(
            classify_http(418, Some(418)),
            ProbeStatus::Ready
        ));
    }

    #[test]
    fn classify_http_expect_mismatch_is_unhealthy() {
        match classify_http(200, Some(204)) {
            ProbeStatus::Unhealthy { reason } => {
                assert!(reason.contains("200") && reason.contains("204"));
            }
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    // ── tail_utf8_lossy ────────────────────────────────────────────────────────

    #[test]
    fn tail_caps_message_length() {
        let buf = vec![b'A'; 1024];
        let t = tail_utf8_lossy(&buf, 256);
        assert_eq!(t.len(), 256);
    }

    #[test]
    fn tail_short_buf_is_passed_through() {
        assert_eq!(tail_utf8_lossy(b"  short ", 256), "short");
    }

    // ── run_probe: TcpConnect ──────────────────────────────────────────────────

    #[tokio::test]
    async fn tcp_connect_ready_when_listener_accepts() {
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = ProbeTarget {
            healthcheck: hc(HealthProbe::TcpConnect { port }, 1000),
            addr: loopback(port),
        };
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Ready), "got {status:?}");
    }

    #[tokio::test]
    async fn tcp_connect_starting_when_port_refused() {
        // Bind then drop to release the port; if the OS reuses it instantly
        // before the probe connects we'd flake, but this is the standard
        // "find a free port" pattern.
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let target = ProbeTarget {
            healthcheck: hc(HealthProbe::TcpConnect { port }, 200),
            addr: loopback(port),
        };
        let status = run_probe(Some(&target)).await;
        assert!(
            matches!(status, ProbeStatus::Starting | ProbeStatus::Timeout),
            "got {status:?}",
        );
    }

    // ── run_probe: HttpGet ─────────────────────────────────────────────────────

    /// Tiny one-shot HTTP server that accepts a single connection and replies
    /// with the given status. Returns the bound port.
    async fn spawn_one_shot(reply: &'static [u8]) -> u16 {
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Drain the request — best-effort.
                let mut buf = [0u8; 1024];
                let _ = tokio::time::timeout(
                    Duration::from_millis(200),
                    sock.read(&mut buf),
                )
                .await;
                let _ = sock.write_all(reply).await;
                let _ = sock.shutdown().await;
            }
        });
        port
    }

    #[tokio::test]
    async fn http_get_ready_on_200() {
        let port = spawn_one_shot(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let target = ProbeTarget {
            healthcheck: hc(
                HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port,
                    expect_status: None,
                },
                1000,
            ),
            addr: loopback(port),
        };
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Ready), "got {status:?}");
    }

    #[tokio::test]
    async fn http_get_unhealthy_on_503() {
        let port = spawn_one_shot(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n").await;
        let target = ProbeTarget {
            healthcheck: hc(
                HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port,
                    expect_status: None,
                },
                1000,
            ),
            addr: loopback(port),
        };
        let status = run_probe(Some(&target)).await;
        match status {
            ProbeStatus::Unhealthy { reason } => assert!(reason.contains("503")),
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn http_get_expect_status_match_is_ready() {
        let port = spawn_one_shot(b"HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\n\r\n").await;
        let target = ProbeTarget {
            healthcheck: hc(
                HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port,
                    expect_status: Some(418),
                },
                1000,
            ),
            addr: loopback(port),
        };
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Ready), "got {status:?}");
    }

    #[tokio::test]
    async fn http_get_starting_when_port_refused() {
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let target = ProbeTarget {
            healthcheck: hc(
                HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port,
                    expect_status: None,
                },
                200,
            ),
            addr: loopback(port),
        };
        let status = run_probe(Some(&target)).await;
        assert!(
            matches!(status, ProbeStatus::Starting | ProbeStatus::Timeout),
            "got {status:?}",
        );
    }

    #[tokio::test]
    async fn http_get_timeout_when_server_never_replies() {
        // Bind a listener that accepts and then hangs without replying — the
        // probe's 100ms timeout should fire before our 5s wait_forever
        // sentinel.
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(5)).await;
                drop(sock);
            }
        });
        let target = ProbeTarget {
            healthcheck: hc(
                HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port,
                    expect_status: None,
                },
                100,
            ),
            addr: loopback(port),
        };
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Timeout), "got {status:?}");
    }

    // ── run_probe: Exec ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn exec_exit_zero_is_ready() {
        let target = ProbeTarget {
            healthcheck: hc(
                HealthProbe::Exec {
                    argv: vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
                },
                1000,
            ),
            addr: loopback(0),
        };
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Ready), "got {status:?}");
    }

    #[tokio::test]
    async fn exec_nonzero_is_unhealthy_with_exit_in_reason() {
        let target = ProbeTarget {
            healthcheck: hc(
                HealthProbe::Exec {
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "echo broken >&2; exit 7".into(),
                    ],
                },
                1000,
            ),
            addr: loopback(0),
        };
        let status = run_probe(Some(&target)).await;
        match status {
            ProbeStatus::Unhealthy { reason } => {
                assert!(reason.contains("exit 7"), "reason: {reason}");
                assert!(reason.contains("broken"), "reason: {reason}");
            }
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn exec_timeout_when_command_hangs() {
        let target = ProbeTarget {
            healthcheck: hc(
                HealthProbe::Exec {
                    argv: vec!["/bin/sh".into(), "-c".into(), "sleep 10".into()],
                },
                100,
            ),
            addr: loopback(0),
        };
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Timeout), "got {status:?}");
    }

    #[tokio::test]
    async fn exec_empty_argv_is_unhealthy() {
        let target = ProbeTarget {
            healthcheck: hc(HealthProbe::Exec { argv: vec![] }, 1000),
            addr: loopback(0),
        };
        let status = run_probe(Some(&target)).await;
        match status {
            ProbeStatus::Unhealthy { reason } => assert!(reason.contains("empty")),
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn exec_unknown_binary_is_unhealthy() {
        let target = ProbeTarget {
            healthcheck: hc(
                HealthProbe::Exec {
                    argv: vec!["/no/such/binary/zzz".into()],
                },
                1000,
            ),
            addr: loopback(0),
        };
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Unhealthy { .. }), "got {status:?}");
    }

    // ── run_probe: None target ─────────────────────────────────────────────────

    #[tokio::test]
    async fn no_target_returns_ready() {
        let status = run_probe(None).await;
        assert!(matches!(status, ProbeStatus::Ready));
    }
}
