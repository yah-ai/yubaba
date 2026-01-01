use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("feed config not found: {0}")]
    NotFound(String),
    #[error("I/O error reading {path}: {source}")]
    Io { path: PathBuf, #[source] source: std::io::Error },
    #[error("TOML parse error in {path}: {source}")]
    Toml { path: PathBuf, #[source] source: toml::de::Error },
}

/// Top-level shape of `.yah/almanac/<name>.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    pub feed: FeedDef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedDef {
    pub name: String,
    pub source: SourceConfig,
    pub trigger: TriggerConfig,
    pub emit: EmitConfig,
}

/// Where to fetch release data from. The adapter is a config choice; the
/// presenter never knows which produced the artifact.
///
/// Note: this is intentionally different from `workload_spec::AlmanacManifest`
/// which is a general command-runner. Feed configs have `source`/`trigger`/`emit`
/// semantics that don't map to `command`/`cadence`/`inputs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SourceConfig {
    /// GitHub Releases API — `GET /repos/{repo}/releases`.
    GhReleases {
        /// `"owner/repo"`, e.g. `"yah-labs/yah"`.
        repo: String,
    },
    /// Public R2 release channel — reads `{base_url}/{binary}/release-manifest.json`.
    R2Channel {
        binary: String,
        /// Public-facing root URL (no trailing slash),
        /// e.g. `"https://releases.yah.dev"`.
        base_url: String,
    },
}

/// What event fires a revalidation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TriggerConfig {
    /// A QED hook or GitHub webhook POSTs to `/revalidate` with `{"feed":"<name>"}`.
    Webhook,
    /// Almanac receiver fires on a UTC cron schedule (warden cron, TBD).
    Cron { expression: String },
}

/// What to do after a successful fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmitConfig {
    /// Path (relative to project root) where `ReleaseFeed` JSON is written.
    /// e.g. `"app/yah/web/src/data/releases.json"`.
    pub artifact: String,
    /// Optional downstream action when the artifact changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_change: Option<OnChangeConfig>,
}

/// Downstream action triggered after the artifact is written.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OnChangeConfig {
    /// Trigger a mesofact static rebuild + R2 publish + CDN purge for one route.
    MesofactRebuild {
        /// Service id (from `.yah/services/<id>/service.toml`), e.g. `"dev-yah"`.
        service: String,
        /// Route to rebuild, e.g. `"/releases"`.
        route: String,
    },
}

/// Loads feed configs from `.yah/almanac/*.toml`.
#[derive(Clone)]
pub struct FeedLoader {
    almanac_dir: PathBuf,
}

impl FeedLoader {
    pub fn new(almanac_dir: impl Into<PathBuf>) -> Self {
        Self { almanac_dir: almanac_dir.into() }
    }

    /// Load by name. Looks for `<almanac_dir>/<name>.toml`.
    pub fn load(&self, name: &str) -> Result<FeedConfig, ConfigError> {
        let path = self.almanac_dir.join(format!("{name}.toml"));
        if !path.exists() {
            return Err(ConfigError::NotFound(name.to_string()));
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|source| ConfigError::Io { path: path.clone(), source })?;
        toml::from_str(&raw).map_err(|source| ConfigError::Toml { path, source })
    }

    /// List the names of all feeds available (`.toml` stems in almanac_dir).
    pub fn list_all(&self) -> Result<Vec<String>, ConfigError> {
        let dir = &self.almanac_dir;
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(dir)
            .map_err(|source| ConfigError::Io { path: dir.clone(), source })?
        {
            let entry = entry
                .map_err(|source| ConfigError::Io { path: dir.clone(), source })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn almanac_dir(&self) -> &Path {
        &self.almanac_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_feed(dir: &Path, name: &str, toml: &str) {
        fs::write(dir.join(format!("{name}.toml")), toml).unwrap();
    }

    #[test]
    fn load_gh_releases_feed() {
        let tmp = TempDir::new().unwrap();
        write_feed(
            tmp.path(),
            "releases",
            r#"
[feed]
name = "releases"

[feed.source]
kind = "gh-releases"
repo = "yah-labs/yah"

[feed.trigger]
kind = "webhook"

[feed.emit]
artifact = "app/yah/web/src/data/releases.json"

[feed.emit.on_change]
kind = "mesofact-rebuild"
service = "dev-yah"
route = "/releases"
"#,
        );
        let loader = FeedLoader::new(tmp.path());
        let cfg = loader.load("releases").unwrap();
        assert_eq!(cfg.feed.name, "releases");
        assert!(matches!(cfg.feed.source, SourceConfig::GhReleases { .. }));
        assert!(matches!(cfg.feed.trigger, TriggerConfig::Webhook));
        let on_change = cfg.feed.emit.on_change.unwrap();
        assert!(matches!(on_change, OnChangeConfig::MesofactRebuild { .. }));
    }

    #[test]
    fn load_r2_channel_feed() {
        let tmp = TempDir::new().unwrap();
        write_feed(
            tmp.path(),
            "releases-r2",
            r#"
[feed]
name = "releases-r2"

[feed.source]
kind = "r2-channel"
binary = "yah"
base_url = "https://releases.yah.dev"

[feed.trigger]
kind = "cron"
expression = "0 */6 * * *"

[feed.emit]
artifact = "app/yah/web/src/data/releases.json"
"#,
        );
        let loader = FeedLoader::new(tmp.path());
        let cfg = loader.load("releases-r2").unwrap();
        assert!(matches!(cfg.feed.source, SourceConfig::R2Channel { .. }));
        assert!(matches!(cfg.feed.trigger, TriggerConfig::Cron { .. }));
        assert!(cfg.feed.emit.on_change.is_none());
    }

    #[test]
    fn missing_feed_returns_not_found() {
        let tmp = TempDir::new().unwrap();
        let loader = FeedLoader::new(tmp.path());
        assert!(matches!(loader.load("nope"), Err(ConfigError::NotFound(_))));
    }

    #[test]
    fn list_all_returns_stems() {
        let tmp = TempDir::new().unwrap();
        write_feed(tmp.path(), "alpha", "[feed]\nname=\"a\"\n[feed.source]\nkind=\"gh-releases\"\nrepo=\"o/r\"\n[feed.trigger]\nkind=\"webhook\"\n[feed.emit]\nartifact=\"a.json\"");
        write_feed(tmp.path(), "beta", "[feed]\nname=\"b\"\n[feed.source]\nkind=\"gh-releases\"\nrepo=\"o/r\"\n[feed.trigger]\nkind=\"webhook\"\n[feed.emit]\nartifact=\"b.json\"");
        let loader = FeedLoader::new(tmp.path());
        let names = loader.list_all().unwrap();
        assert_eq!(names, vec!["alpha", "beta"]);
    }
}
