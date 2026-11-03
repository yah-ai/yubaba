//! One request = one `git http-backend` child, spoken to as CGI (W363 §1).
//!
//! git is GPLv2 and stays a separate program: this module talks to it only
//! through environment variables and stdin/stdout pipes.

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Response, StatusCode};
use futures_util::StreamExt;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio_util::io::ReaderStream;

pub struct CgiRequest {
    pub method: String,
    /// `/<repo>.git/<rest>`.
    pub path_info: String,
    pub query: String,
    pub content_type: Option<String>,
    pub content_length: Option<String>,
    /// Clients gzip upload-pack request bodies; http-backend decodes them.
    pub content_encoding: Option<String>,
    /// From the `Git-Protocol` header (protocol v2).
    pub git_protocol: Option<String>,
    /// The token's `sub`.
    pub remote_user: String,
    /// The token's write grant, handed to the hooks as `$FLEET_GIT_REFS`.
    pub ref_grant: crate::auth::RefGrant,
    /// The token's `git_ref` claim, handed to the hooks as `$FLEET_GIT_REF_ONLY`.
    pub ref_only: Option<String>,
}

pub struct CgiEnv {
    pub http_backend: PathBuf,
    pub project_root: PathBuf,
    pub hook_sock: PathBuf,
}

/// Run http-backend for `req`. `hold` (the repo's push lock, for
/// receive-pack) is released only when the child exits, so it spans the hooks.
pub async fn run<G: Send + 'static>(
    env: &CgiEnv,
    req: CgiRequest,
    body: Body,
    hold: Option<G>,
) -> Result<Response<Body>> {
    let mut cmd = Command::new(&env.http_backend);
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()))
        // No operator or user gitconfig leaks into the server's behaviour.
        .env("HOME", &env.project_root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GATEWAY_INTERFACE", "CGI/1.1")
        .env("GIT_PROJECT_ROOT", &env.project_root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env(crate::hook::SOCK_ENV, &env.hook_sock)
        .env("REQUEST_METHOD", &req.method)
        .env("PATH_INFO", &req.path_info)
        .env("QUERY_STRING", &req.query)
        .env("REMOTE_USER", &req.remote_user)
        .env(crate::hook::REFS_ENV, req.ref_grant.to_env())
        .env("REMOTE_ADDR", "127.0.0.1");
    if let Some(v) = &req.ref_only {
        cmd.env(crate::hook::REF_ONLY_ENV, v);
    }
    if let Some(v) = &req.content_type {
        cmd.env("CONTENT_TYPE", v);
    }
    if let Some(v) = &req.content_length {
        cmd.env("CONTENT_LENGTH", v);
    }
    if let Some(v) = &req.content_encoding {
        cmd.env("HTTP_CONTENT_ENCODING", v);
    }
    if let Some(v) = &req.git_protocol {
        cmd.env("GIT_PROTOCOL", v);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", env.http_backend.display()))?;

    let mut stdin = child.stdin.take().expect("piped");
    tokio::spawn(async move {
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else { break };
            if stdin.write_all(&chunk).await.is_err() {
                break;
            }
        }
        // Dropping stdin is the EOF http-backend reads to.
    });

    let mut stdout = BufReader::new(child.stdout.take().expect("piped"));
    tokio::spawn(async move {
        match child.wait().await {
            Ok(s) if !s.success() => tracing::warn!(status = %s, "git http-backend exited non-zero"),
            Err(e) => tracing::warn!(error = %e, "waiting on git http-backend"),
            _ => {}
        }
        drop(hold);
    });

    let mut resp = Response::builder();
    let mut status = StatusCode::OK;
    loop {
        let mut line = String::new();
        if stdout.read_line(&mut line).await? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        if k.eq_ignore_ascii_case("status") {
            let code = v.split_whitespace().next().unwrap_or("500");
            status = code.parse::<u16>().ok().and_then(|c| StatusCode::from_u16(c).ok()).unwrap_or(StatusCode::BAD_GATEWAY);
        } else if let (Ok(k), Ok(v)) = (HeaderName::try_from(k.trim()), HeaderValue::try_from(v)) {
            resp = resp.header(k, v);
        }
    }
    Ok(resp.status(status).body(Body::from_stream(ReaderStream::new(stdout)))?)
}
