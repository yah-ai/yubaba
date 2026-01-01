use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::issues_source::IssuesSource;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Issue {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Serialized form written to the sink JSON file.
///
/// Field name is `items` — not `issues` — to match the mesofact
/// `prerender.from_data` binding that R443-F2 shipped (items_key='items').
/// Changing this field name would silently break detail-page enumeration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuesFeed {
    pub fetched_at: DateTime<Utc>,
    pub items: Vec<Issue>,
}

/// In-process trigger for a single feed revalidation tick.
#[derive(Debug, Clone)]
pub struct RevalidateRequest;

// ---------------------------------------------------------------------------
// ArtifactSink
// ---------------------------------------------------------------------------

/// Write destination for the materialized `IssuesFeed` JSON.
pub struct ArtifactSink {
    path: PathBuf,
}

impl ArtifactSink {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    async fn write(&self, feed: &IssuesFeed) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let json = serde_json::to_string_pretty(feed)?;
        tokio::fs::write(&self.path, json.as_bytes()).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OnChange
// ---------------------------------------------------------------------------

type OnChangeFut = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Downstream action fired after a successful artifact write.
///
/// # Dev tier
/// `mesofact-dev` watches `<workload>/src/` (including `src/data/`). Writing
/// `issues.json` there is enough to trigger an automatic rebuild — no HTTP
/// call from issue-tracker is needed. `OnChange::mesofact_rebuild` therefore
/// logs the event for observability and is otherwise a no-op in dev.
///
/// # Cloud / pond tier
/// The caller (issue-tracker's `main.rs` or a warden workload) constructs the
/// `OnChange` closure to invoke `cloud::almanac_dispatch::dispatch_on_change`
/// with the workspace root and target env. That function calls
/// `MesofactStaticReconciler::rebuild_static` on the named service mirror.
#[derive(Clone)]
pub struct OnChange(Arc<dyn Fn() -> OnChangeFut + Send + Sync>);

impl OnChange {
    pub fn new(f: impl Fn() -> OnChangeFut + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    pub fn no_op() -> Self {
        Self::new(|| Box::pin(std::future::ready(())))
    }

    /// Construct a mesofact-rebuild on_change for the dev tier (logs the
    /// trigger; file-watch handles the actual rebuild). For cloud/pond, supply
    /// a closure that calls `cloud::almanac_dispatch::dispatch_on_change`.
    pub fn mesofact_rebuild(service: impl Into<String>, route: impl Into<String>) -> Self {
        let service = service.into();
        let route = route.into();
        Self::new(move || {
            let service = service.clone();
            let route = route.clone();
            Box::pin(async move {
                info!(%service, %route, "IssuesFeed on_change: mesofact-dev file-watch rebuild triggered");
            })
        })
    }

    pub async fn fire(&self) {
        (self.0)().await;
    }
}

// ---------------------------------------------------------------------------
// IssuesFeed::run
// ---------------------------------------------------------------------------

impl IssuesFeed {
    /// Long-running task: await trigger ticks, re-materialize the feed, fire
    /// on_change. Runs until the trigger sender is dropped.
    ///
    /// Error handling:
    /// - Source error → log + skip this tick (no artifact write, no on_change).
    /// - Artifact write error → log + skip on_change for this tick.
    /// Never panics.
    pub async fn run(
        source: Arc<dyn IssuesSource>,
        sink: ArtifactSink,
        on_change: OnChange,
        mut trigger: mpsc::Receiver<RevalidateRequest>,
    ) {
        while trigger.recv().await.is_some() {
            let items = match source.list().await {
                Ok(v) => v,
                Err(e) => {
                    error!(err = %e, "IssuesFeed: source.list() failed; skipping tick");
                    continue;
                }
            };
            let count = items.len();
            let feed = IssuesFeed { fetched_at: Utc::now(), items };
            if let Err(e) = sink.write(&feed).await {
                error!(
                    err = %e,
                    path = %sink.path().display(),
                    "IssuesFeed: artifact write failed; skipping on_change",
                );
                continue;
            }
            info!(path = %sink.path().display(), items = count, "IssuesFeed: artifact written");
            on_change.fire().await;
        }
        // trigger channel closed — loop ends cleanly
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    use crate::sources::SourceError;

    struct MockIssuesSource {
        responses: Mutex<Vec<Result<Vec<Issue>, SourceError>>>,
    }

    impl MockIssuesSource {
        fn new(responses: Vec<Result<Vec<Issue>, SourceError>>) -> Self {
            Self { responses: Mutex::new(responses) }
        }
    }

    #[async_trait::async_trait]
    impl IssuesSource for MockIssuesSource {
        async fn list(&self) -> Result<Vec<Issue>, SourceError> {
            self.responses.lock().unwrap().remove(0)
        }
    }

    fn make_issue(id: &str, title: &str) -> Issue {
        Issue {
            id: id.into(),
            title: title.into(),
            body: None,
            kind: None,
            created_at: DateTime::from_timestamp(0, 0).unwrap(),
        }
    }

    // Helper: run IssuesFeed::run in a background task; sends one trigger and
    // waits for on_change to fire before asserting.
    async fn run_one_tick(
        source: Arc<dyn IssuesSource>,
        sink: ArtifactSink,
    ) -> (mpsc::Sender<RevalidateRequest>, tokio::sync::oneshot::Receiver<()>) {
        let (trigger_tx, trigger_rx) = mpsc::channel::<RevalidateRequest>(4);
        let (fired_tx, fired_rx) = tokio::sync::oneshot::channel::<()>();
        let fired_tx = std::sync::Mutex::new(Some(fired_tx));
        let on_change = OnChange::new(move || {
            let tx = fired_tx.lock().unwrap().take();
            Box::pin(async move {
                if let Some(t) = tx {
                    let _ = t.send(());
                }
            })
        });
        tokio::spawn(IssuesFeed::run(source, sink, on_change, trigger_rx));
        (trigger_tx, fired_rx)
    }

    #[tokio::test]
    async fn triggered_tick_writes_artifact_and_fires_on_change() {
        let dir = TempDir::new().unwrap();
        let artifact = dir.path().join("issues.json");

        let issues = vec![make_issue("01ABC", "Test issue")];
        let source = Arc::new(MockIssuesSource::new(vec![Ok(issues.clone())]));
        let sink = ArtifactSink::file(&artifact);
        let (tx, fired_rx) = run_one_tick(source, sink).await;

        tx.send(RevalidateRequest).await.unwrap();
        // Wait for on_change to signal
        fired_rx.await.unwrap();

        let raw = std::fs::read_to_string(&artifact).unwrap();
        let feed: IssuesFeed = serde_json::from_str(&raw).unwrap();
        assert_eq!(feed.items.len(), 1);
        assert_eq!(feed.items[0].id, "01ABC");
        // Verify the JSON field is named "items", not "issues"
        assert!(raw.contains("\"items\""));
        assert!(!raw.contains("\"issues\""));
    }

    #[tokio::test]
    async fn empty_source_writes_empty_items_array() {
        let dir = TempDir::new().unwrap();
        let artifact = dir.path().join("issues.json");

        let source = Arc::new(MockIssuesSource::new(vec![Ok(vec![])]));
        let sink = ArtifactSink::file(&artifact);
        let (tx, fired_rx) = run_one_tick(source, sink).await;

        tx.send(RevalidateRequest).await.unwrap();
        fired_rx.await.unwrap();

        let raw = std::fs::read_to_string(&artifact).unwrap();
        let feed: IssuesFeed = serde_json::from_str(&raw).unwrap();
        assert!(feed.items.is_empty());
    }

    #[tokio::test]
    async fn source_error_skips_artifact_write_and_on_change_but_no_panic() {
        let dir = TempDir::new().unwrap();
        let artifact = dir.path().join("issues.json");

        // First tick: error. Second tick: success.
        let issues = vec![make_issue("01DEF", "Recovery issue")];
        let source: Arc<dyn IssuesSource> = Arc::new(MockIssuesSource::new(vec![
            Err(SourceError::Parse("mock error".into())),
            Ok(issues),
        ]));
        let sink = ArtifactSink::file(&artifact);
        let (trigger_tx, trigger_rx) = mpsc::channel::<RevalidateRequest>(4);
        let (fired_tx, fired_rx) = tokio::sync::oneshot::channel::<()>();
        let fired_tx = std::sync::Mutex::new(Some(fired_tx));
        let on_change = OnChange::new(move || {
            let tx = fired_tx.lock().unwrap().take();
            Box::pin(async move {
                if let Some(t) = tx {
                    let _ = t.send(());
                }
            })
        });
        tokio::spawn(IssuesFeed::run(Arc::clone(&source), sink, on_change, trigger_rx));

        // First tick: source errors — artifact must NOT be written
        trigger_tx.send(RevalidateRequest).await.unwrap();
        // Small sleep to let the task process the error tick
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!artifact.exists(), "artifact must not be written on source error");

        // Second tick: source succeeds — artifact written + on_change fires
        trigger_tx.send(RevalidateRequest).await.unwrap();
        fired_rx.await.unwrap();
        assert!(artifact.exists(), "artifact must be written on successful tick");
    }

    #[tokio::test]
    async fn loop_ends_cleanly_when_trigger_sender_dropped() {
        let dir = TempDir::new().unwrap();
        let (trigger_tx, trigger_rx) = mpsc::channel::<RevalidateRequest>(4);
        let source = Arc::new(MockIssuesSource::new(vec![]));
        let sink = ArtifactSink::file(dir.path().join("issues.json"));
        let handle = tokio::spawn(IssuesFeed::run(source, sink, OnChange::no_op(), trigger_rx));

        drop(trigger_tx);
        // Task should complete without panic
        handle.await.unwrap();
    }
}
