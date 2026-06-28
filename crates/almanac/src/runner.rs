use std::path::Path;
use thiserror::Error;

use crate::config::{FeedConfig, OnChangeConfig, SourceConfig};
use crate::feed::ReleaseFeed;
use crate::gh::GhReleases;
use crate::r2::R2Channel;
use crate::sink::{FeedSink, SinkError, SinkTarget};
use crate::sources::{ReleaseSource, SourceError};

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("source fetch failed: {0}")]
    Source(#[from] SourceError),
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Sink(#[from] SinkError),
}

/// Result of a single feed run.
#[derive(Debug)]
pub struct RunResult {
    /// Where the artifact landed (local file or tenant object key).
    pub destination: SinkTarget,
    /// The feed that was written.
    pub feed: ReleaseFeed,
    /// Downstream action to fire (caller's responsibility to dispatch).
    pub on_change: Option<OnChangeConfig>,
}

/// Fetches a feed from its source adapter and writes the artifact to a sink.
///
/// The sink decouples *what* is written from *where*: the single-tenant /
/// dev path writes a local file ([`FeedRunner::new`]); the cloud multi-tenant
/// path writes into a tenant's object store ([`FeedRunner::with_sink`] with a
/// [`FeedSink::Object`]).
pub struct FeedRunner {
    config: FeedConfig,
    sink: FeedSink,
}

impl FeedRunner {
    /// Local-file sink rooted at `project_root` joined with the feed's
    /// `emit.artifact` (the historical single-tenant behaviour).
    pub fn new(config: FeedConfig, project_root: impl AsRef<Path>) -> Self {
        let sink = crate::sink::local_file(project_root.as_ref(), &config.feed.emit.artifact);
        Self { config, sink }
    }

    /// Run the feed into an explicit sink — e.g. a tenant's object store.
    pub fn with_sink(config: FeedConfig, sink: FeedSink) -> Self {
        Self { config, sink }
    }

    pub async fn run(&self) -> Result<RunResult, RunnerError> {
        let source = make_source(&self.config.feed.source);
        tracing::info!(source = source.source_id(), feed = %self.config.feed.name, "fetching feed");
        let feed = source.fetch().await?;

        let json = serde_json::to_string_pretty(&feed)?;
        let destination = self.sink.write(json.into_bytes()).await?;

        tracing::info!(
            destination = %destination,
            releases = feed.releases.len(),
            "artifact written"
        );

        Ok(RunResult {
            destination,
            feed,
            on_change: self.config.feed.emit.on_change.clone(),
        })
    }

    pub fn config(&self) -> &FeedConfig {
        &self.config
    }

    pub fn sink(&self) -> &FeedSink {
        &self.sink
    }
}

fn make_source(cfg: &SourceConfig) -> Box<dyn ReleaseSource> {
    match cfg {
        SourceConfig::GhReleases { repo } => Box::new(GhReleases::new(repo)),
        SourceConfig::R2Channel { binary, base_url } => {
            Box::new(R2Channel::new(binary, base_url))
        }
    }
}
