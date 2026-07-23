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

        // Did anything actually change? `emit.on_change` is documented as
        // firing "when the artifact changes", but firing it unconditionally
        // means every trigger costs a full mesofact rebuild + R2 publish + CDN
        // purge even when the bytes are identical. That is the common case:
        // triggers are nudges, and a re-publish of unchanged content is pure
        // waste. Pairs with the coalescer — that collapses redundant *runs*,
        // this suppresses redundant *rebuilds*.
        //
        // `fetched_at` is excluded from the comparison because it is wall-clock
        // and would differ on every run, defeating the check entirely.
        let changed = self.artifact_changed(&feed);

        let destination = self.sink.write(json.into_bytes()).await?;

        tracing::info!(
            destination = %destination,
            releases = feed.releases.len(),
            changed,
            "artifact written"
        );

        let on_change = if changed {
            self.config.feed.emit.on_change.clone()
        } else {
            tracing::info!(
                feed = %self.config.feed.name,
                "artifact unchanged — suppressing on_change"
            );
            None
        };

        Ok(RunResult { destination, feed, on_change })
    }

    /// Whether the feed content differs from what is already at the sink.
    ///
    /// Only the local-file sink can be read back cheaply; for object sinks a
    /// read is a network round-trip, so those conservatively report `true`
    /// (fire on_change) rather than risk suppressing a real change. Being
    /// wrong in that direction costs a redundant rebuild; being wrong the
    /// other way silently serves stale bytes.
    fn artifact_changed(&self, feed: &ReleaseFeed) -> bool {
        let FeedSink::LocalFile(ref path) = self.sink else {
            return true;
        };
        let Ok(existing) = std::fs::read(path) else {
            return true; // no prior artifact — everything is new
        };
        // Compared as serialized JSON rather than by deriving PartialEq down
        // the whole Release tree: the wire form is what downstream actually
        // consumes, so it is the honest thing to diff, and it keeps this check
        // from constraining the derives on feed.rs's public types.
        match serde_json::from_slice::<ReleaseFeed>(&existing) {
            // Compare the payload, NOT fetched_at (see run()).
            Ok(prev) => {
                serde_json::to_value(&prev.releases).ok()
                    != serde_json::to_value(&feed.releases).ok()
            }
            Err(_) => true, // unparseable/corrupt — rewrite and rebuild
        }
    }

    pub fn config(&self) -> &FeedConfig {
        &self.config
    }

    pub fn sink(&self) -> &FeedSink {
        &self.sink
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::Release;
    use chrono::{TimeZone, Utc};

    fn runner_for(root: &std::path::Path) -> FeedRunner {
        let cfg: FeedConfig = toml::from_str(
            r#"
[feed]
name = "releases"
[feed.source]
kind = "r2-manifest"
url = "https://example.invalid/m.json"
[feed.trigger]
kind = "webhook"
[feed.emit]
artifact = "out.json"
on_change = { kind = "mesofact-rebuild", service = "svc", route = "/releases" }
"#,
        )
        .unwrap();
        FeedRunner::new(cfg, root)
    }

    fn feed_with(version: &str) -> ReleaseFeed {
        ReleaseFeed {
            fetched_at: Utc::now(),
            releases: vec![Release {
                version: version.to_string(),
                tag: format!("v{version}"),
                published_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
                notes: None,
                assets: vec![],
            }],
        }
    }

    #[test]
    fn missing_artifact_counts_as_changed() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(runner_for(tmp.path()).artifact_changed(&feed_with("1.0.0")));
    }

    #[test]
    fn identical_payload_is_not_a_change_even_though_fetched_at_differs() {
        let tmp = tempfile::tempdir().unwrap();
        let r = runner_for(tmp.path());
        let first = feed_with("1.0.0");
        std::fs::write(
            tmp.path().join("out.json"),
            serde_json::to_string_pretty(&first).unwrap(),
        )
        .unwrap();

        // A later run re-fetches: same releases, new wall-clock fetched_at.
        // That must NOT count as a change, or every nudge would trigger a
        // full rebuild + publish + purge.
        let second = feed_with("1.0.0");
        assert_ne!(first.fetched_at, second.fetched_at, "precondition");
        assert!(!r.artifact_changed(&second));
    }

    #[test]
    fn different_payload_is_a_change() {
        let tmp = tempfile::tempdir().unwrap();
        let r = runner_for(tmp.path());
        std::fs::write(
            tmp.path().join("out.json"),
            serde_json::to_string_pretty(&feed_with("1.0.0")).unwrap(),
        )
        .unwrap();
        assert!(r.artifact_changed(&feed_with("1.0.1")));
    }

    #[test]
    fn corrupt_artifact_counts_as_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let r = runner_for(tmp.path());
        std::fs::write(tmp.path().join("out.json"), b"{not json").unwrap();
        assert!(r.artifact_changed(&feed_with("1.0.0")));
    }
}

fn make_source(cfg: &SourceConfig) -> Box<dyn ReleaseSource> {
    match cfg {
        SourceConfig::GhReleases { repo } => Box::new(GhReleases::new(repo)),
        SourceConfig::R2Channel { binary, base_url } => {
            Box::new(R2Channel::new(binary, base_url))
        }
        SourceConfig::R2Manifest { url, id } => Box::new(R2Channel::at_url(
            url,
            id.clone().unwrap_or_else(|| "r2-manifest".to_string()),
        )),
    }
}
