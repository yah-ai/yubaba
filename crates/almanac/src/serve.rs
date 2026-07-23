use std::future::Future;
use std::path::PathBuf;

use anyhow::{Context, Result};
use axum::{routing::get, Router};
use tokio::sync::mpsc;

use crate::receiver::{router, MirrorBind, RevalidateTx};
use crate::{FeedLoader, FeedRunner};

/// Configuration for [`run`] — the full receiver-plus-dispatch loop that the
/// `almanac-serve` binary previously inlined. Constructed by the binary from
/// env vars, or by an in-process embedder (e.g. the cloud-tier
/// `mesofact-runner` workload) from mirror metadata.
///
/// Fields mirror the env knobs the bin once consumed:
///
/// | Field             | Env (bin)               | Default        |
/// |-------------------|-------------------------|----------------|
/// | `port`            | `ALMANAC_PORT`          | 4323           |
/// | `almanac_dir`     | `ALMANAC_DIR`           | `None`         |
/// | `project_root`    | `ALMANAC_PROJECT_ROOT`  | `/data`        |
/// | `service_id`      | `ALMANAC_SERVICE_ID`    | `None`         |
/// | `env_label`       | `ALMANAC_ENV`           | `"pond"`       |
/// | `mirror_key`      | `ALMANAC_MIRROR_KEY`    | `None`         |
#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub port: u16,
    pub almanac_dir: Option<PathBuf>,
    pub project_root: PathBuf,
    pub service_id: Option<String>,
    pub env_label: String,
    pub mirror_key: Option<String>,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            port: 4323,
            almanac_dir: None,
            project_root: PathBuf::from("/data"),
            service_id: None,
            env_label: "pond".into(),
            mirror_key: None,
        }
    }
}

/// Run the full almanac receiver: bind a listener on `cfg.port`, expose
/// `/healthz` + `/readyz` alongside the [`receiver::router`] endpoints, and
/// spawn the feed-dispatch loop that runs [`FeedRunner`] on every accepted
/// `/revalidate` poke.
///
/// This is the in-process embedding point. The `almanac-serve` binary is a
/// thin shell over this function (read env → build [`ServeConfig`] → call
/// `run`); the cloud-tier mesofact-runner workload (R330-F11) can call it
/// directly to avoid spawning a child binary.
pub async fn run(cfg: ServeConfig) -> Result<()> {
    tracing::info!(
        port = cfg.port,
        almanac_dir = ?cfg.almanac_dir,
        project_root = %cfg.project_root.display(),
        "almanac-serve starting",
    );

    let bind = match (cfg.almanac_dir.as_ref(), cfg.service_id.as_ref()) {
        (Some(dir), Some(svc)) => Some(MirrorBind {
            service_id: svc.clone(),
            env: cfg.env_label.clone(),
            almanac_dir: dir.clone(),
        }),
        _ => None,
    };

    let (tx, mut rx) = mpsc::channel::<String>(16);
    let receiver = router(tx, cfg.mirror_key.clone(), bind);
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        .merge(receiver);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("almanac-serve: binding to :{}", cfg.port))?;
    tracing::info!(port = cfg.port, "almanac-serve listening");

    let almanac_dir = cfg.almanac_dir.clone();
    let project_root = cfg.project_root.clone();
    // Per-feed conflation. The dispatch loop below MUST stay non-blocking:
    // each admitted run is spawned, never awaited inline. That is what keeps
    // the mpsc channel drained, and a drained channel is what stops
    // receiver.rs from returning 503 and DROPPING a trigger — the one failure
    // mode that actually loses a change (see coalesce.rs's module docs).
    let coalescer = crate::coalesce::Coalescer::new();
    tokio::spawn(async move {
        while let Some(feed_name) = rx.recv().await {
            tracing::info!(%feed_name, "almanac: revalidate received");
            let Some(ref dir) = almanac_dir else {
                tracing::warn!(%feed_name, "ALMANAC_DIR not set; skipping feed run");
                continue;
            };

            if coalescer.admit(&feed_name) == crate::coalesce::Admission::Coalesced {
                tracing::info!(
                    %feed_name,
                    "almanac: run already in flight — coalesced into the queued re-run"
                );
                continue;
            }

            let dir = dir.clone();
            let project_root = project_root.clone();
            let coalescer = coalescer.clone();
            tokio::spawn(async move {
                // Loop rather than return: finish() reports whether a trigger
                // landed mid-run. Because the source is absolute, this single
                // extra pass subsumes every trigger that arrived, however many.
                loop {
                    run_feed_once(&feed_name, &dir, &project_root).await;
                    if !coalescer.finish(&feed_name) {
                        break;
                    }
                    tracing::info!(%feed_name, "almanac: draining coalesced re-run");
                }
            });
        }
    });

    async fn run_feed_once(
        feed_name: &str,
        dir: &std::path::Path,
        project_root: &std::path::Path,
    ) {
        let loader = FeedLoader::new(dir);
        match loader.load(feed_name) {
            Ok(fcfg) => {
                let runner = FeedRunner::new(fcfg, project_root);
                match runner.run().await {
                    Ok(result) => tracing::info!(
                        %feed_name,
                        destination = %result.destination,
                        "almanac: feed rebuilt"
                    ),
                    Err(e) => {
                        tracing::error!(%feed_name, err = %e, "almanac: feed run failed")
                    }
                }
            }
            Err(e) => tracing::warn!(%feed_name, err = %e, "almanac: feed not found"),
        }
    }

    axum::serve(listener, app)
        .await
        .context("almanac-serve: server error")?;
    Ok(())
}

/// Start the almanac HTTP receiver on a pre-bound [`tokio::net::TcpListener`].
///
/// Prefer this over [`serve_receiver`] when you need the actual port before
/// spawning (e.g. tests: bind to port 0, read `listener.local_addr()`, then
/// pass the listener in). For each feed name that passes validation
/// (`mirror_key` auth + `bind` service-matching), `on_feed(feed_name)` is
/// called in sequence.
///
/// The server runs until a hard I/O error occurs or the dispatch channel is
/// drained (both legs race via `tokio::select!`).
pub async fn serve_receiver_on<F, Fut>(
    listener: tokio::net::TcpListener,
    mirror_key: Option<String>,
    bind: Option<MirrorBind>,
    on_feed: F,
) -> Result<()>
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (tx, mut rx): (RevalidateTx, _) = mpsc::channel(16);
    let app = router(tx, mirror_key, bind);

    let addr = listener.local_addr().context("almanac receiver: local_addr")?;
    tracing::info!(?addr, "almanac receiver started");

    tokio::select! {
        result = axum::serve(listener, app) => {
            result.context("almanac receiver: server error")?;
        }
        () = async move {
            while let Some(feed_name) = rx.recv().await {
                on_feed(feed_name).await;
            }
        } => {}
    }

    Ok(())
}

/// Start the almanac HTTP receiver on `port` and drive the dispatch loop.
///
/// For each feed name that passes validation (`mirror_key` auth + `bind`
/// service-matching), `on_feed(feed_name)` is called in sequence.
///
/// ## Mirror-binding
///
/// When `bind` is `Some`, every `/revalidate` request is checked against the
/// feed's `on_change.service`. Feeds not bound to this mirror are rejected
/// with 422 before `on_feed` is ever called.
pub async fn serve_receiver<F, Fut>(
    port: u16,
    mirror_key: Option<String>,
    bind: Option<MirrorBind>,
    on_feed: F,
) -> Result<()>
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("almanac receiver: binding to :{port}"))?;
    serve_receiver_on(listener, mirror_key, bind, on_feed).await
}

#[cfg(test)]
mod tests {
    //! R335-T2 — Pond acceptance gate.
    //!
    //! These tests exercise `serve_receiver_on` over a real TCP connection to
    //! verify the mirror-binding property end-to-end:
    //!   - same-mirror revalidate → 200 + on_feed callback fires (rebuild triggered)
    //!   - cross-mirror revalidate → 422 + on_feed never called (rebuild blocked)
    //!
    //! The F3 unit tests in receiver.rs cover the HTTP layer in isolation via
    //! `tower::oneshot`; these acceptance tests drive the full serve loop.

    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    fn write_feed(dir: &std::path::Path, name: &str, service: &str) {
        let toml = format!(
            "[feed]\nname = \"{name}\"\n\n\
             [feed.source]\nkind = \"gh-releases\"\nrepo = \"o/r\"\n\n\
             [feed.trigger]\nkind = \"webhook\"\n\n\
             [feed.emit]\nartifact = \"out.json\"\n\n\
             [feed.emit.on_change]\nkind = \"mesofact-rebuild\"\nservice = \"{service}\"\nroute = \"/releases\"\n"
        );
        fs::write(dir.join(format!("{name}.toml")), toml).unwrap();
    }

    async fn spawn_pond_receiver(
        almanac_dir: std::path::PathBuf,
        service_id: &str,
        env: &str,
    ) -> (u16, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (fired_tx, fired_rx) = mpsc::channel::<String>(4);
        let bind = MirrorBind {
            service_id: service_id.to_string(),
            env: env.to_string(),
            almanac_dir,
        };
        tokio::spawn(async move {
            serve_receiver_on(listener, None, Some(bind), move |feed_name| {
                let fired_tx = fired_tx.clone();
                async move { let _ = fired_tx.send(feed_name).await; }
            })
            .await
            .ok();
        });
        // Let the spawned task reach `axum::serve` before we send requests.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        (port, fired_rx)
    }

    /// Positive case: a revalidate for a feed bound to this mirror's service
    /// returns 200 and triggers the on_feed callback (rebuild fires).
    #[tokio::test]
    async fn pond_same_mirror_revalidate_triggers_rebuild() {
        let tmp = TempDir::new().unwrap();
        write_feed(tmp.path(), "releases", "dev-yah");

        let (port, mut fired_rx) =
            spawn_pond_receiver(tmp.path().to_path_buf(), "dev-yah", "pond").await;

        let resp = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{port}/revalidate"))
            .json(&serde_json::json!({"feed": "releases"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "same-mirror revalidate must succeed");

        let feed_name = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            fired_rx.recv(),
        )
        .await
        .expect("on_feed not called within 500 ms")
        .expect("on_feed channel closed");
        assert_eq!(feed_name, "releases", "on_feed must receive the feed name");
    }

    /// Negative case: a revalidate for a feed bound to a *different* service
    /// returns 422 and on_feed is never called (rebuild blocked).
    #[tokio::test]
    async fn pond_cross_mirror_revalidate_is_rejected() {
        let tmp = TempDir::new().unwrap();
        // Feed is bound to "dev-yah" (pond). Receiver claims "cloud-yah".
        write_feed(tmp.path(), "releases", "dev-yah");

        let (port, mut fired_rx) =
            spawn_pond_receiver(tmp.path().to_path_buf(), "cloud-yah", "cloud").await;

        let resp = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{port}/revalidate"))
            .json(&serde_json::json!({"feed": "releases"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 422, "cross-mirror revalidate must be rejected");

        assert!(
            fired_rx.try_recv().is_err(),
            "on_feed must not be called for a cross-mirror revalidate"
        );
    }
}
