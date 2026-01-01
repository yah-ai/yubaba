use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::config::{FeedConfig, OnChangeConfig, SourceConfig};
use crate::feed::ReleaseFeed;
use crate::gh::GhReleases;
use crate::r2::R2Channel;
use crate::sources::{ReleaseSource, SourceError};

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("source fetch failed: {0}")]
    Source(#[from] SourceError),
    #[error("I/O error writing artifact {path}: {source}")]
    Io { path: PathBuf, #[source] source: std::io::Error },
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("tokio I/O error: {0}")]
    TokioIo(#[from] tokio::io::Error),
}

/// Result of a single feed run.
#[derive(Debug)]
pub struct RunResult {
    /// Absolute path to the written artifact.
    pub artifact_path: PathBuf,
    /// The feed that was written.
    pub feed: ReleaseFeed,
    /// Downstream action to fire (caller's responsibility to dispatch).
    pub on_change: Option<OnChangeConfig>,
}

/// Fetches a feed from its source adapter and writes the artifact.
pub struct FeedRunner {
    config: FeedConfig,
    project_root: PathBuf,
}

impl FeedRunner {
    pub fn new(config: FeedConfig, project_root: impl Into<PathBuf>) -> Self {
        Self { config, project_root: project_root.into() }
    }

    pub async fn run(&self) -> Result<RunResult, RunnerError> {
        let source = make_source(&self.config.feed.source);
        tracing::info!(source = source.source_id(), feed = %self.config.feed.name, "fetching feed");
        let feed = source.fetch().await?;

        let artifact_path = self.project_root.join(&self.config.feed.emit.artifact);
        if let Some(parent) = artifact_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let json = serde_json::to_string_pretty(&feed)?;
        tokio::fs::write(&artifact_path, json.as_bytes())
            .await
            .map_err(|source| RunnerError::Io { path: artifact_path.clone(), source })?;

        tracing::info!(
            path = %artifact_path.display(),
            releases = feed.releases.len(),
            "artifact written"
        );

        Ok(RunResult {
            artifact_path,
            feed,
            on_change: self.config.feed.emit.on_change.clone(),
        })
    }

    pub fn config(&self) -> &FeedConfig {
        &self.config
    }

    pub fn project_root(&self) -> &Path {
        &self.project_root
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
