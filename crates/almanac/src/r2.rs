use chrono::Utc;
use serde::Deserialize;
use std::collections::HashMap;

use crate::feed::{Release, ReleaseAsset, ReleaseFeed};
use crate::sources::{ReleaseSource, SourceError};

/// Fetches releases from a yah R2 release channel by reading the publicly
/// accessible `release-manifest.json` at the channel root.
///
/// The R2 release channel is public (users download directly from it for
/// self-updates), so no S3 credentials are needed to read the manifest.
/// `base_url` is the public-facing root, e.g. `"https://releases.yah.dev"`.
/// `binary` is the sub-path prefix, e.g. `"yah"`.
///
/// The manifest at `{base_url}/{binary}/release-manifest.json` is produced by
/// the QED release-build pipeline (R330-F3) and follows the updater crate's
/// `release-manifest.json` schema (just the fields almanac needs are deserialized).
pub struct R2Channel {
    binary: String,
    base_url: String,
}

impl R2Channel {
    pub fn new(binary: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self { binary: binary.into(), base_url: base_url.into() }
    }
}

#[async_trait::async_trait]
impl ReleaseSource for R2Channel {
    fn source_id(&self) -> &str {
        &self.binary
    }

    async fn fetch(&self) -> Result<ReleaseFeed, SourceError> {
        let url = format!("{}/{}/release-manifest.json", self.base_url, self.binary);
        let resp: ChannelManifest =
            reqwest::get(&url).await?.json().await?;

        let release = Release {
            version: resp.version.trim_start_matches('v').to_string(),
            tag: format!("v{}", resp.version.trim_start_matches('v')),
            published_at: resp
                .pub_date
                .parse()
                .unwrap_or_else(|_| Utc::now()),
            notes: resp.notes,
            assets: resp
                .host
                .bundle
                .into_iter()
                .map(|(triple, bundle)| ReleaseAsset {
                    platform: platform_from_triple(&triple),
                    filename: filename_from_url(&bundle.url),
                    url: bundle.url,
                    blake3: None,
                    license: None,
                    size_bytes: bundle.size,
                })
                .collect(),
        };

        Ok(ReleaseFeed { fetched_at: Utc::now(), releases: vec![release] })
    }
}

fn platform_from_triple(triple: &str) -> String {
    // Mirror gh.rs logic for known patterns.
    if triple.contains("aarch64-apple") || triple.contains("arm64-apple") {
        "macos-arm64".to_string()
    } else if triple.contains("x86_64-apple") {
        "macos-x86_64".to_string()
    } else if triple.contains("aarch64-unknown-linux") {
        "linux-arm64".to_string()
    } else if triple.contains("x86_64-unknown-linux") || triple.contains("x86_64-linux") {
        "linux-x86_64".to_string()
    } else if triple.contains("x86_64-pc-windows") || triple.contains("x86_64-windows") {
        "windows-x86_64".to_string()
    } else {
        triple.to_string()
    }
}

fn filename_from_url(url: &str) -> String {
    url.rsplit('/').next().unwrap_or(url).to_string()
}

// ── Channel wire types (mirrors updater::manifest fields we need) ─────────────

#[derive(Deserialize)]
struct ChannelManifest {
    version: String,
    pub_date: String,
    #[serde(default)]
    notes: Option<String>,
    host: ChannelHost,
}

#[derive(Deserialize)]
struct ChannelHost {
    /// Keyed by target triple shorthand (mirrors updater::HostSection.bundle).
    bundle: HashMap<String, ChannelBundle>,
}

#[derive(Deserialize)]
struct ChannelBundle {
    url: String,
    #[serde(default)]
    size: Option<u64>,
}
