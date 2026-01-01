use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
pub use workload_spec::{BlakeHash, License};

/// Normalized feed output written to the declared `emit.artifact` path.
/// Both GhReleases and R2Channel produce this schema; the presenter never
/// knows which adapter ran.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseFeed {
    pub fetched_at: DateTime<Utc>,
    pub releases: Vec<Release>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    /// Semver string (no leading `v`), e.g. `"0.8.6"`.
    pub version: String,
    /// Git tag, e.g. `"v0.8.6"`.
    pub tag: String,
    pub published_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    /// Platform token (e.g. `"macos-arm64"`, `"linux-x86_64"`, `"windows-x86_64"`).
    pub platform: String,
    pub filename: String,
    pub url: String,
    /// BLAKE3 hex hash of the download. `None` when the source does not supply
    /// content hashes (GitHub Releases list endpoint, current R2 manifests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3: Option<BlakeHash>,
    /// Upstream distribution license. `None` when the release manifest does not
    /// declare one. Uses the same closed-set [`License`] enum as
    /// `asset.derive.fetch.license` — non-permissive values are rejected at
    /// parse time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<License>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_asset(blake3: Option<BlakeHash>, license: Option<License>) -> ReleaseAsset {
        ReleaseAsset {
            platform: "macos-arm64".into(),
            filename: "yah-aarch64-apple-darwin".into(),
            url: "https://releases.yah.dev/yah/v1.0/yah-aarch64-apple-darwin".into(),
            blake3,
            license,
            size_bytes: Some(1_234_567),
        }
    }

    #[test]
    fn release_asset_round_trips_without_optional_fields() {
        let asset = sample_asset(None, None);
        let json = serde_json::to_string(&asset).unwrap();
        // Neither blake3 nor license should appear in the output.
        assert!(!json.contains("blake3"), "blake3 absent when None");
        assert!(!json.contains("license"), "license absent when None");
        let back: ReleaseAsset = serde_json::from_str(&json).unwrap();
        assert_eq!(back.blake3, None);
        assert_eq!(back.license, None);
    }

    #[test]
    fn release_asset_round_trips_with_blake3_and_license() {
        let hash = BlakeHash("a".repeat(64));
        let asset = sample_asset(Some(hash.clone()), Some(License::Mit));
        let json = serde_json::to_string(&asset).unwrap();
        let back: ReleaseAsset = serde_json::from_str(&json).unwrap();
        assert_eq!(back.blake3.as_ref().unwrap().0, "a".repeat(64));
        assert_eq!(back.license, Some(License::Mit));
    }

    #[test]
    fn license_rejects_non_permissive_on_deserialize() {
        let json = r#"{"platform":"macos-arm64","filename":"f","url":"u","license":"gpl-3.0"}"#;
        assert!(
            serde_json::from_str::<ReleaseAsset>(json).is_err(),
            "non-permissive license must be rejected at deserialize"
        );
    }

    #[test]
    fn release_feed_round_trips() {
        let feed = ReleaseFeed {
            fetched_at: Utc::now(),
            releases: vec![Release {
                version: "1.0.0".into(),
                tag: "v1.0.0".into(),
                published_at: Utc::now(),
                notes: None,
                assets: vec![sample_asset(None, None)],
            }],
        };
        let json = serde_json::to_string(&feed).unwrap();
        let back: ReleaseFeed = serde_json::from_str(&json).unwrap();
        assert_eq!(back.releases.len(), 1);
        assert_eq!(back.releases[0].version, "1.0.0");
    }
}
