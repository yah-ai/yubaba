use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;

use crate::feed::{Release, ReleaseAsset, ReleaseFeed};
use crate::sources::{ReleaseSource, SourceError};

/// Fetches releases from the GitHub Releases API.
///
/// `repo` is `"owner/repo"`. An optional `GITHUB_TOKEN` env var is used to
/// raise the rate limit and access private repos.
pub struct GhReleases {
    repo: String,
}

impl GhReleases {
    pub fn new(repo: impl Into<String>) -> Self {
        Self { repo: repo.into() }
    }

    fn client() -> reqwest::Result<reqwest::Client> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("almanac/1.0"));
        headers.insert("Accept", HeaderValue::from_static("application/vnd.github+json"));
        headers.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(AUTHORIZATION, v);
            }
        }
        reqwest::Client::builder().default_headers(headers).build()
    }
}

#[async_trait::async_trait]
impl ReleaseSource for GhReleases {
    fn source_id(&self) -> &str {
        &self.repo
    }

    async fn fetch(&self) -> Result<ReleaseFeed, SourceError> {
        let client = Self::client().map_err(SourceError::Http)?;
        let url = format!("https://api.github.com/repos/{}/releases", self.repo);
        let resp: Vec<GhRelease> = client.get(&url).send().await?.json().await?;
        let releases = resp.into_iter().filter_map(into_release).collect();
        Ok(ReleaseFeed { fetched_at: Utc::now(), releases })
    }
}

fn into_release(gh: GhRelease) -> Option<Release> {
    // Skip drafts and pre-releases.
    if gh.draft || gh.prerelease {
        return None;
    }
    let published_at = gh.published_at?;
    let version = gh.tag_name.trim_start_matches('v').to_string();
    let assets = gh.assets.into_iter().map(|a| ReleaseAsset {
        platform: platform_from_filename(&a.name),
        filename: a.name,
        url: a.browser_download_url,
        blake3: None,
        license: None,
        size_bytes: Some(a.size),
    });
    Some(Release {
        version,
        tag: gh.tag_name,
        published_at,
        notes: gh.body.filter(|s| !s.is_empty()),
        assets: assets.collect(),
    })
}

/// Best-effort platform token from a binary filename.
///
/// e.g. `yah-aarch64-apple-darwin` → `"macos-arm64"`,
///      `yah-x86_64-unknown-linux-gnu` → `"linux-x86_64"`.
fn platform_from_filename(name: &str) -> String {
    if name.contains("aarch64-apple") || name.contains("arm64-apple") {
        "macos-arm64".to_string()
    } else if name.contains("x86_64-apple") {
        "macos-x86_64".to_string()
    } else if name.contains("aarch64-unknown-linux") {
        "linux-arm64".to_string()
    } else if name.contains("x86_64-unknown-linux") || name.contains("x86_64-linux") {
        "linux-x86_64".to_string()
    } else if name.contains("x86_64-pc-windows") || name.contains("x86_64-windows") {
        "windows-x86_64".to_string()
    } else {
        // Preserve the raw triple portion after the binary name.
        name.splitn(2, '-').nth(1).unwrap_or(name).to_string()
    }
}

// ── GitHub API wire types ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    published_at: Option<DateTime<Utc>>,
    body: Option<String>,
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

#[cfg(test)]
mod tests {
    use super::platform_from_filename;

    #[test]
    fn maps_known_triples() {
        assert_eq!(platform_from_filename("yah-aarch64-apple-darwin"), "macos-arm64");
        assert_eq!(platform_from_filename("yah-x86_64-apple-darwin"), "macos-x86_64");
        assert_eq!(platform_from_filename("yah-x86_64-unknown-linux-gnu"), "linux-x86_64");
        assert_eq!(platform_from_filename("yah-aarch64-unknown-linux-gnu"), "linux-arm64");
        assert_eq!(platform_from_filename("yah-x86_64-pc-windows-msvc.exe"), "windows-x86_64");
    }
}
