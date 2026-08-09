use std::path::Path;
use thiserror::Error;

use crate::config::{FeedConfig, OnChangeConfig, SourceConfig};
use crate::gh::GhReleases;
use crate::r2::{R2Channel, R2Index, R2Private, R2Triples};
use crate::sink::{FeedSink, SinkError, SinkTarget};
use crate::sources::{FeedPayload, FeedSource, SourceError};

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
    /// What was fetched and written. `payload` rather than `feed` since R707-F4:
    /// not every feed carries a release list (see [`FeedPayload`]).
    pub payload: FeedPayload,
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
        let source = make_source(&self.config.feed.source).await?;
        tracing::info!(source = source.source_id(), feed = %self.config.feed.name, "fetching feed");
        let payload = source.fetch_payload().await?;

        let json = payload.to_json_pretty()?;

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
        let changed = self.artifact_changed(&payload);

        let destination = self.sink.write(json.into_bytes()).await?;

        tracing::info!(
            destination = %destination,
            releases = payload.release_count(),
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

        Ok(RunResult { destination, payload, on_change })
    }

    /// Whether the feed content differs from what is already at the sink.
    ///
    /// Only the local-file sink can be read back cheaply; for object sinks a
    /// read is a network round-trip, so those conservatively report `true`
    /// (fire on_change) rather than risk suppressing a real change. Being
    /// wrong in that direction costs a redundant rebuild; being wrong the
    /// other way silently serves stale bytes.
    fn artifact_changed(&self, payload: &FeedPayload) -> bool {
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
        match payload {
            FeedPayload::Releases(feed) => {
                match serde_json::from_slice::<crate::feed::ReleaseFeed>(&existing) {
                    // Compare the payload, NOT fetched_at (see run()).
                    Ok(prev) => {
                        serde_json::to_value(&prev.releases).ok()
                            != serde_json::to_value(&feed.releases).ok()
                    }
                    Err(_) => true, // unparseable/corrupt — rewrite and rebuild
                }
            }
            // No field to exclude here, and none should be invented. The
            // wall-clock exclusion above exists because *almanac* stamps
            // `fetched_at` on every fetch; a passthrough payload is stamped by
            // its own producer, which runs only when the thing it publishes
            // actually changed. Skipping a field on this side would mean
            // guessing at a schema this crate deliberately does not own.
            FeedPayload::Passthrough(value) => {
                serde_json::from_slice::<serde_json::Value>(&existing).ok().as_ref() != Some(value)
            }
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

    use crate::feed::ReleaseFeed;

    /// Every release feed reaches `artifact_changed` wrapped — the wrapper is
    /// what lets a passthrough feed share the same change-suppression.
    fn payload(version: &str) -> FeedPayload {
        FeedPayload::Releases(feed_with(version))
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
        assert!(runner_for(tmp.path()).artifact_changed(&payload("1.0.0")));
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
        assert!(!r.artifact_changed(&FeedPayload::Releases(second)));
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
        assert!(r.artifact_changed(&payload("1.0.1")));
    }

    #[test]
    fn corrupt_artifact_counts_as_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let r = runner_for(tmp.path());
        std::fs::write(tmp.path().join("out.json"), b"{not json").unwrap();
        assert!(r.artifact_changed(&payload("1.0.0")));
    }

    // ── passthrough feeds get the same change suppression (R707-F4) ──────────

    fn fleet_index(commit: &str) -> FeedPayload {
        FeedPayload::Passthrough(serde_json::json!({
            "schema_version": 1,
            "source_commit": commit,
            "generated_at": "2026-08-05T00:00:00Z",
            "machines": [{"name": "us-west-001"}],
        }))
    }

    /// The whole reason change-suppression matters for a passthrough feed: a
    /// poke that found nothing new must not tell every consumer to re-read.
    #[test]
    fn an_identical_passthrough_payload_is_not_a_change() {
        let tmp = tempfile::tempdir().unwrap();
        let r = runner_for(tmp.path());
        std::fs::write(
            tmp.path().join("out.json"),
            fleet_index("abc123").to_json_pretty().unwrap(),
        )
        .unwrap();
        assert!(!r.artifact_changed(&fleet_index("abc123")));
    }

    /// ...but a real republish is, and the whole value is compared — there is no
    /// almanac-side field exclusion for a schema almanac does not own.
    #[test]
    fn a_different_passthrough_payload_is_a_change() {
        let tmp = tempfile::tempdir().unwrap();
        let r = runner_for(tmp.path());
        std::fs::write(
            tmp.path().join("out.json"),
            fleet_index("abc123").to_json_pretty().unwrap(),
        )
        .unwrap();
        assert!(r.artifact_changed(&fleet_index("def456")));
    }

    /// The artifact holds the payload itself, not an almanac wrapper around it.
    /// A consumer parsing the emitted file must not have to know almanac ran.
    #[test]
    fn a_passthrough_artifact_is_the_payload_verbatim() {
        let rendered = fleet_index("abc123").to_json_pretty().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["source_commit"], "abc123");
        assert_eq!(parsed["machines"][0]["name"], "us-west-001");
        assert!(
            parsed.get("releases").is_none() && parsed.get("fetched_at").is_none(),
            "no release-feed envelope may be wrapped around a passthrough payload: {rendered}"
        );
    }

    /// A corrupt artifact is a change on this path too — the same
    /// rewrite-and-recover direction the release path takes.
    #[test]
    fn a_corrupt_artifact_counts_as_changed_for_passthrough_too() {
        let tmp = tempfile::tempdir().unwrap();
        let r = runner_for(tmp.path());
        std::fs::write(tmp.path().join("out.json"), b"<html>403</html>").unwrap();
        assert!(r.artifact_changed(&fleet_index("abc123")));
    }
}

/// Build the adapter a feed's `source` declares.
///
/// Fallible *and* async only because of the authenticated arm. Every public
/// source is a URL and a name, built infallibly and instantly. The private one:
///
/// - resolves a credential reference off the filesystem or the environment, and
///   a missing secret must surface as *this reference did not resolve* rather
///   than as a `403` from the edge three layers down; and
/// - **must not be constructed on an async worker.** `R2ObjectStore` is backed
///   by a `reqwest::blocking::Client`, and building one spins up a temporary
///   tokio runtime and drops it, which panics outright with "Cannot drop a
///   runtime in a context where blocking is not allowed" when it happens inside
///   a future. Not a lint and not a slow path — the feed's very first run aborts
///   the task. Hence `spawn_blocking` around the whole construction, matching
///   what [`crate::sink`] already does around the write.
async fn make_source(cfg: &SourceConfig) -> Result<Box<dyn FeedSource>, SourceError> {
    if matches!(cfg, SourceConfig::R2Private { .. }) {
        let cfg = cfg.clone();
        return tokio::task::spawn_blocking(move || make_private_source(&cfg))
            .await
            .map_err(|e| {
                SourceError::Credential(format!("source construction task panicked: {e}"))
            })?;
    }
    Ok(match cfg {
        SourceConfig::GhReleases { repo } => Box::new(GhReleases::new(repo)),
        SourceConfig::R2Channel { binary, base_url } => {
            Box::new(R2Channel::new(binary, base_url))
        }
        SourceConfig::R2Manifest { url, id } => Box::new(R2Channel::at_url(
            url,
            id.clone().unwrap_or_else(|| "r2-manifest".to_string()),
        )),
        SourceConfig::R2Triples { url, id } => Box::new(R2Triples::at_url(
            url,
            id.clone().unwrap_or_else(|| "r2-triples".to_string()),
        )),
        SourceConfig::R2Index { url, id } => Box::new(R2Index::at_url(
            url,
            id.clone().unwrap_or_else(|| "r2-index".to_string()),
        )),
        // Handled above, off the async worker.
        SourceConfig::R2Private { .. } => unreachable!("routed through make_private_source"),
    })
}

/// The blocking half of [`make_source`] — credential reads and the
/// `reqwest::blocking` client build. Runs on a blocking thread; see the caller
/// for why that is load-bearing rather than tidy.
fn make_private_source(cfg: &SourceConfig) -> Result<Box<dyn FeedSource>, SourceError> {
    let SourceConfig::R2Private {
        account_id,
        bucket,
        key,
        access_key_id,
        secret_access_key,
        endpoint,
        id,
    } = cfg
    else {
        unreachable!("only called for SourceConfig::R2Private")
    };
    let access = access_key_id
        .resolve("access_key_id")
        .map_err(SourceError::Credential)?;
    let secret = secret_access_key
        .resolve("secret_access_key")
        .map_err(SourceError::Credential)?;
    Ok(Box::new(R2Private::new(
        id.clone().unwrap_or_else(|| "r2-private".to_string()),
        account_id,
        bucket,
        key,
        &access,
        &secret,
        endpoint.as_deref(),
    )?))
}
