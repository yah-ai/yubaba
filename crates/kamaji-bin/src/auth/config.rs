//! Auth-surface configuration. Defaults track W159 §Kamaji startup and
//! JWKS lifecycle exactly:
//!
//! - JWKS cache at `${XDG_CACHE_HOME:-~/.cache}/kamaji/jwks.json`
//! - Background refresh interval: 1h
//! - Kid-miss out-of-band refresh: rate-limited 1/sec per process
//! - Serve-from-stale when AS unreachable at steady state (warn only)

use std::path::PathBuf;
use std::time::Duration;

/// Required + default-tunable knobs for the verifier.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Cheers AS — e.g. `https://cheers.staging`. JWKS fetched at
    /// `${cheers_issuer}/.well-known/jwks.json`; tokens must carry this
    /// exact value in `iss`.
    pub cheers_issuer: String,

    /// This kamaji's resource URI — tokens must carry it in `aud`.
    pub expected_aud: String,

    /// On-disk JWKS cache path. Atomic-rename writes here on refresh.
    pub cache_path: PathBuf,

    /// Background refresh interval. W159 default: 1 hour.
    pub refresh_interval: Duration,

    /// Minimum gap between back-to-back out-of-band refreshes triggered by
    /// kid-miss. W159 default: 1 second. Bounds attacker-driven JWKS hammer.
    pub kid_miss_rate_limit: Duration,

    /// If the AS is unreachable at *steady state*, keep serving from the
    /// stale cache and only fail-closed on new-`kid` tokens. W159 default:
    /// true (matches the "Cache present + AS unreachable" arm of restart
    /// resilience). First-start fetch failure is always fatal regardless.
    pub serve_stale_on_failure: bool,
}

impl AuthConfig {
    /// Build a config with W159 defaults. `cheers_issuer` and `expected_aud`
    /// are required; the cache path defaults to
    /// `${XDG_CACHE_HOME:-${HOME}/.cache}/kamaji/jwks.json`.
    pub fn new(cheers_issuer: impl Into<String>, expected_aud: impl Into<String>) -> Self {
        Self {
            cheers_issuer: cheers_issuer.into(),
            expected_aud: expected_aud.into(),
            cache_path: default_cache_path(),
            refresh_interval: Duration::from_secs(60 * 60),
            kid_miss_rate_limit: Duration::from_secs(1),
            serve_stale_on_failure: true,
        }
    }

    /// Override the on-disk cache path (system installs point at
    /// `/var/lib/kamaji/jwks.json`; tests use a `tempfile::TempDir`).
    pub fn with_cache_path(mut self, path: PathBuf) -> Self {
        self.cache_path = path;
        self
    }

    /// URL for fetching the JWKS doc.
    pub fn jwks_url(&self) -> String {
        let mut url = self.cheers_issuer.trim_end_matches('/').to_string();
        url.push_str("/.well-known/jwks.json");
        url
    }

    /// Absolute URL of *this* kamaji's `/.well-known/oauth-protected-resource`
    /// endpoint (F4). Used as the `resource_metadata` parameter on
    /// `WWW-Authenticate` headers so MCP clients without a cached AS can
    /// discover cheers's issuer in one hop (W159 §Failure responses + the
    /// desktop Connect-Remote modal's URL-shape detector).
    pub fn resource_metadata_url(&self) -> String {
        let mut url = self.expected_aud.trim_end_matches('/').to_string();
        url.push_str("/.well-known/oauth-protected-resource");
        url
    }
}

fn default_cache_path() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| {
                let mut p = PathBuf::from(home);
                p.push(".cache");
                p
            })
        })
        .unwrap_or_else(|| PathBuf::from("."));
    let mut p = base;
    p.push("kamaji");
    p.push("jwks.json");
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_url_handles_trailing_slash() {
        let c = AuthConfig::new("https://cheers.example/", "https://kamaji.example");
        assert_eq!(c.jwks_url(), "https://cheers.example/.well-known/jwks.json");
    }

    #[test]
    fn jwks_url_no_trailing_slash() {
        let c = AuthConfig::new("https://cheers.example", "https://kamaji.example");
        assert_eq!(c.jwks_url(), "https://cheers.example/.well-known/jwks.json");
    }

    #[test]
    fn defaults_match_w159() {
        let c = AuthConfig::new("https://i", "https://a");
        assert_eq!(c.refresh_interval, Duration::from_secs(3600));
        assert_eq!(c.kid_miss_rate_limit, Duration::from_secs(1));
        assert!(c.serve_stale_on_failure);
    }

    #[test]
    fn resource_metadata_url_handles_trailing_slash() {
        let c = AuthConfig::new("https://i", "https://kamaji.example/");
        assert_eq!(
            c.resource_metadata_url(),
            "https://kamaji.example/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn resource_metadata_url_no_trailing_slash() {
        let c = AuthConfig::new("https://i", "https://kamaji.example");
        assert_eq!(
            c.resource_metadata_url(),
            "https://kamaji.example/.well-known/oauth-protected-resource"
        );
    }
}
