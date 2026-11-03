//! The HTTP supervisor: routing, auth, the per-repo push lock, and the
//! fence-driven shutdown (W363 §1, §3, §4).

use crate::auth::{AuthError, GitAuth, Op};
use crate::cgi::{self, CgiEnv, CgiRequest};
use crate::fence::{Fence, FENCE_PERIOD};
use crate::gitbin::GitInstall;
use crate::hook::{HookServer, PushLog};
use crate::repo;
use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, Response, StatusCode};
use axum::routing::get;
use axum::Router;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct ServeConfig {
    /// Where bare repos live (the named volume, a cache of the bucket).
    pub root: PathBuf,
    /// The hook socket path.
    pub hook_sock: PathBuf,
    /// This binary, which the repo hooks exec in hook mode.
    pub hook_exe: PathBuf,
    pub git: GitInstall,
    pub auth: GitAuth,
    pub fence_period: Duration,
    /// The per-repo push lock, shared with the snapshot (W363 §2 "Snapshot").
    pub locks: Arc<PushLocks>,
}

/// One async mutex per repo. `git-receive-pack` holds its repo's for the whole
/// request (so pre- and post-receive both run under it); the snapshot capture
/// and the local `repack -a -d -l` take it too.
#[derive(Default)]
pub struct PushLocks(Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>);

impl PushLocks {
    pub async fn lock(&self, repo: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let m = Arc::clone(self.0.lock().unwrap().entry(repo.to_string()).or_default());
        m.lock_owned().await
    }
}

/// Why [`serve`] returned.
#[derive(Debug)]
pub enum ServeExit {
    /// Another instance holds the claim. Exit 0 (W363 §3).
    FenceLost(String),
    /// SIGTERM / ctrl-c.
    Signalled,
}

struct AppState {
    root: PathBuf,
    git: GitInstall,
    auth: GitAuth,
    cgi: CgiEnv,
    fence: Arc<Fence>,
    hook_exe: PathBuf,
    locks: Arc<PushLocks>,
}

/// Run the server on `listener` under an already-established `fence` until the
/// fence is lost or `shutdown` resolves.
pub async fn serve(
    cfg: ServeConfig,
    fence: Arc<Fence>,
    log: Arc<dyn PushLog>,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<ServeExit> {
    std::fs::create_dir_all(&cfg.root)?;
    let root = cfg.root.canonicalize()?;
    for name in repo::list(&root)? {
        repo::ensure(&cfg.git, &root, &name, &cfg.hook_exe)?;
    }

    let _ = std::fs::remove_file(&cfg.hook_sock);
    let hook_listener = tokio::net::UnixListener::bind(&cfg.hook_sock)
        .with_context(|| format!("binding the hook socket {}", cfg.hook_sock.display()))?;
    let hooks = Arc::new(HookServer {
        root: root.clone(),
        git: cfg.git.git.clone(),
        fence: Arc::clone(&fence),
        log,
    });
    let hook_task = tokio::spawn(hooks.serve(hook_listener));

    // W363 §4 step 4: confirm the claim survived the setup above.
    if let crate::fence::FenceCheck::Lost(lost) = fence.check().await {
        hook_task.abort();
        return Ok(ServeExit::FenceLost(lost.to_string()));
    }
    let timer = fence.spawn_timer(cfg.fence_period.min(FENCE_PERIOD));

    let state = Arc::new(AppState {
        cgi: CgiEnv {
            http_backend: cfg.git.http_backend.clone(),
            project_root: root.clone(),
            hook_sock: cfg.hook_sock.clone(),
        },
        root,
        git: cfg.git,
        auth: cfg.auth,
        fence: Arc::clone(&fence),
        hook_exe: cfg.hook_exe,
        locks: cfg.locks,
    });
    let app = Router::new()
        .route("/healthz", get(healthz))
        .fallback(git_request)
        .with_state(Arc::clone(&state));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ServeExit>(2);
    {
        let tx = tx.clone();
        let fence = Arc::clone(&fence);
        tokio::spawn(async move {
            let why = fence.wait_lost().await;
            let _ = tx.send(ServeExit::FenceLost(why)).await;
        });
    }
    tokio::spawn(async move {
        shutdown.await;
        let _ = tx.send(ServeExit::Signalled).await;
    });
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let exit = rx.recv().await.unwrap_or(ServeExit::Signalled);
        let _ = exit_tx.send(exit);
    });
    server.await?;
    timer.abort();
    hook_task.abort();
    let _ = std::fs::remove_file(&cfg.hook_sock);
    Ok(exit_rx.await.unwrap_or(ServeExit::Signalled))
}

async fn healthz(State(st): State<Arc<AppState>>) -> Response<Body> {
    if st.fence.is_lost() {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "fence lost\n");
    }
    let root = st.root.clone();
    // A probe must never fail on the journal lines: an unreadable marker just
    // drops that repo's line.
    let heads = tokio::task::spawn_blocking(move || journal_heads(&root)).await.unwrap_or_default();
    plain(StatusCode::OK, &healthz_body(st.fence.epoch(), &heads))
}

/// Each repo's journal position as this volume applied it (the
/// [`crate::stream::VolumeMarker`] `seq`; between a push's pre-receive and
/// post-receive it trails the journal by that one entry). Local file reads,
/// no object-store LIST, so a liveness probe stays cheap. Repos with no
/// marker (never pushed) are omitted.
pub fn journal_heads(root: &std::path::Path) -> Vec<(String, u64)> {
    let Ok(names) = repo::list(root) else { return Vec::new() };
    names
        .into_iter()
        .filter_map(|n| {
            let m = crate::stream::read_marker(&repo::repo_dir(root, &n)).ok().flatten()?;
            Some((n, m.seq))
        })
        .collect()
}

/// `/healthz` body (R978-T22): `ok epoch <n>` then one `journal <repo> <seq>`
/// line per repo. The first line is unchanged, so older probes still match.
/// The counters carry no refs, content or identities, hence no auth, same as
/// the epoch beside them.
pub fn healthz_body(epoch: u64, heads: &[(String, u64)]) -> String {
    let mut s = format!("ok epoch {epoch}\n");
    for (repo, seq) in heads {
        s.push_str(&format!("journal {repo} {seq}\n"));
    }
    s
}

/// Body of the 404 a read gets for a repo that has never been pushed to
/// (repos are created on first write). A stable wire marker: git prints a
/// text/plain error body as `remote: <line>`, and the yah lander
/// (`app/yah/cli/src/lander/mod.rs`, R978-B16) matches this exact line to
/// tell "repo absent → seed" from an outage. Change both together.
pub const NO_SUCH_REPO: &str = "fleet-git: no such repo";

fn plain(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(msg.to_string()))
        .expect("static response")
}

/// `/<repo>.git/<rest>` → `(repo, rest)`.
pub fn split_path(path: &str) -> Option<(&str, &str)> {
    let p = path.strip_prefix('/')?;
    let (repo, rest) = p.split_once(".git/")?;
    repo::valid_name(repo).then_some((repo, rest))
}

/// Smart HTTP only; `None` for anything else (dumb HTTP is not served).
pub fn op_for(rest: &str, query: &str) -> Option<Op> {
    match rest {
        "git-upload-pack" => Some(Op::Read),
        "git-receive-pack" => Some(Op::Write),
        "info/refs" => match query.split('&').find_map(|kv| kv.strip_prefix("service=")) {
            Some("git-upload-pack") => Some(Op::Read),
            Some("git-receive-pack") => Some(Op::Write),
            _ => None,
        },
        _ => None,
    }
}

async fn git_request(State(st): State<Arc<AppState>>, req: Request) -> Response<Body> {
    match handle(&st, req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "request failed");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "fleet-git: internal error\n")
        }
    }
}

async fn handle(st: &Arc<AppState>, req: Request) -> Result<Response<Body>> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let Some((repo, rest)) = split_path(&path) else {
        return Ok(plain(StatusCode::NOT_FOUND, "not found\n"));
    };
    let Some(op) = op_for(rest, &query) else {
        return Ok(plain(StatusCode::NOT_FOUND, "fleet-git serves smart HTTP only\n"));
    };
    if st.fence.is_lost() {
        return Ok(plain(StatusCode::SERVICE_UNAVAILABLE, "fleet-git: this instance lost the writer claim\n"));
    }
    let hdr = |n: header::HeaderName| parts.headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let grant = match st.auth.authorize(hdr(header::AUTHORIZATION).as_deref(), repo, op, now) {
        Ok(grant) => grant,
        Err(AuthError::Missing) => {
            let mut r = plain(StatusCode::UNAUTHORIZED, "fleet-git: bearer token required\n");
            r.headers_mut().insert(header::WWW_AUTHENTICATE, "Bearer realm=\"fleet-git\"".parse().unwrap());
            return Ok(r);
        }
        Err(AuthError::Invalid(why)) => return Ok(plain(StatusCode::UNAUTHORIZED, &format!("fleet-git: {why}\n"))),
        Err(AuthError::Forbidden(why)) => return Ok(plain(StatusCode::FORBIDDEN, &format!("fleet-git: {why}\n"))),
    };

    let dir = repo::repo_dir(&st.root, repo);
    if !dir.join("HEAD").exists() {
        if op != Op::Write {
            return Ok(plain(StatusCode::NOT_FOUND, &format!("{NO_SUCH_REPO}\n")));
        }
        // First push creates the repo.
        let (git, root, name, exe) = (st.git.clone(), st.root.clone(), repo.to_string(), st.hook_exe.clone());
        tokio::task::spawn_blocking(move || repo::ensure(&git, &root, &name, &exe)).await??;
    }

    let hold = if rest == "git-receive-pack" {
        Some(st.locks.lock(repo).await)
    } else {
        None
    };
    let cgi_req = CgiRequest {
        method: parts.method.to_string(),
        path_info: path.clone(),
        query,
        content_type: hdr(header::CONTENT_TYPE),
        content_length: hdr(header::CONTENT_LENGTH),
        content_encoding: hdr(header::CONTENT_ENCODING),
        git_protocol: parts.headers.get("git-protocol").and_then(|v| v.to_str().ok()).map(str::to_string),
        remote_user: grant.sub,
        ref_grant: grant.refs,
        ref_only: grant.only,
    };
    cgi::run(&st.cgi, cgi_req, body, hold).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        assert_eq!(split_path("/yah.git/info/refs"), Some(("yah", "info/refs")));
        assert_eq!(split_path("/../x.git/info/refs"), None);
        assert_eq!(split_path("/yah/info/refs"), None);
        assert_eq!(op_for("info/refs", "service=git-receive-pack"), Some(Op::Write));
        assert_eq!(op_for("info/refs", "service=git-upload-pack"), Some(Op::Read));
        assert_eq!(op_for("info/refs", ""), None);
        assert_eq!(op_for("git-upload-pack", ""), Some(Op::Read));
        assert_eq!(op_for("git-receive-pack", ""), Some(Op::Write));
        assert_eq!(op_for("objects/info/packs", ""), None);
    }

    #[test]
    fn healthz_body_keeps_the_epoch_line_first() {
        assert_eq!(healthz_body(7, &[]), "ok epoch 7\n");
        let b = healthz_body(7, &[("yah".into(), 12), ("other".into(), 0)]);
        assert_eq!(b, "ok epoch 7\njournal yah 12\njournal other 0\n");
    }

    #[test]
    fn journal_heads_reads_markers_and_skips_unpushed_repos() {
        let t = tempfile::tempdir().unwrap();
        for n in ["yah", "fresh"] {
            std::fs::create_dir_all(repo::repo_dir(t.path(), n)).unwrap();
        }
        crate::stream::write_marker(
            &repo::repo_dir(t.path(), "yah"),
            &crate::stream::VolumeMarker { seq: 9, refs_digest: "d".into() },
        )
        .unwrap();
        assert_eq!(journal_heads(t.path()), vec![("yah".to_string(), 9)]);
    }
}
