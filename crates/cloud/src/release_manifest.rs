//! Yubaba release-manifest fetch + per-triple resolution (R330-F21).
//!
//! `.github/workflows/release.yml`'s `yubaba-release-manifest` job publishes
//! `https://cdn.yah.dev/yubaba/release-manifest.json` after every release tag
//! (R330-F19). Operators do not need to memorise per-release URLs and sha256s —
//! `yah cloud machine provision <name>` fetches the manifest once, looks up
//! the entry matching the machine's architecture, and threads the resolved
//! URL + sha256 + sig/cert URLs into the cloud-init render.
//!
//! Per W203 §1.5 + R330-F19's per-triple entries:
//!
//! ```json
//! {
//!   "version": "0.9.0",
//!   "triples": {
//!     "x86_64-unknown-linux-musl": {
//!       "url":      "https://cdn.yah.dev/yubaba/0.9.0/x86_64-unknown-linux-musl/yah-yubaba-x86_64-unknown-linux-musl.tar.gz",
//!       "size":     2345678,
//!       "sha256":   "abc…",
//!       "sig_url":  "https://cdn.yah.dev/yubaba/.../...tar.gz.sig",
//!       "cert_url": "https://cdn.yah.dev/yubaba/.../...tar.gz.cert"
//!     },
//!     "aarch64-unknown-linux-musl": { … }
//!   }
//! }
//! ```
//!
//! Identity-regexp is *not* per-release — it identifies the workspace's
//! GitHub OIDC identity (matches the cosign sign-blob step in release.yml).
//! See [`DEFAULT_YUBABA_COSIGN_IDENTITY`].
//!
//! @yah:ticket(R599-F1, "R2 bundle store: append-only blob/manifest publish + node-side materialize into kamaji LRU cache")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-07-20T04:20:25Z)
//! @yah:phase(P1)
//! @yah:parent(R599)
//! @yah:depends_on(R599-F2)
//! @yah:next("R599-F2: wire mesofact-build to EMIT a BundleManifest during a build (add yah-mesofact-bundle default-features=false; assemble app/ + optional bins/ tree, per-file blake3, write manifest.toml). Type already exists -> F2 is 'emit', not 'define'.")
//! @yah:next("R599-F4: kamaji deploy dispatch calls materialize_bundle/BundleCache into kamaji state dir on Deploy of the mesofact bundle variant (add yah-mesofact-bundle features=store + yah-object-store to kamaji).")
//! @yah:next("R599-F8: services-tab sync arm calls cloud reconciler::bundle_store::publish_bundle_to_r2 after building a bundle.")
//! @yah:handoff("LANDED (types + store, 16 tests). New crate oss/yah-base/crates/mesofact-bundle (yah-mesofact-bundle). Default features = serde+blake3+toml TYPES ONLY: BundleManifest, BundleRuntime (self | mesofact/<ver>), BundleHash 64-hex, digest() over canonical length-prefixed fields, blob_key/manifest_key layout. This is what R599-F2's mesofact-build consumes via default-features=false.")
//! @yah:handoff("Feature `store` adds yah-object-store + publish_bundle (append-only blob dedupe via HEAD + blake3 verify + immutable manifest-by-digest PUT), materialize_bundle (fetch+verify+atomic-rename into cache tree, idempotent, path-traversal guarded), BundleCache (LRU-by-digest, bytes budget, 0=unbounded). Store tests via InMemoryObjectStore+tempdir.")
//! @yah:handoff("Canonical annotation kept here in release_manifest.rs (one-block-per-ID); the real work is the new crate (its lib.rs has a prose pointer, not a 2nd @yah block). Wired: yah-base workspace member + root + oss/yubaba [patch.crates-io]. cloud deps it (features=store) -> reconciler::bundle_store::publish_bundle_to_r2 (spawn_blocking R2ObjectStore wrapper) + BundlePublishReport re-export. Type home = new minimal crate (user-approved via ask_user): NOT workload-spec (avoids ts-rs/schemars weight at mesofact boundary), NOT mesofact-build (avoids drift); store logic feature-gated so the boundary stays serde-only.")
//! @yah:verify("cd oss/yah-base && cargo test -p yah-mesofact-bundle (8 pass, types-only)")
//! @yah:verify("cd oss/yah-base && cargo test -p yah-mesofact-bundle --features store (16 pass)")
//! @yah:verify("cd oss/yubaba && cargo test -p cloud --lib reconciler::bundle_store (1 pass)")

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

/// Canonical manifest URL published by `.github/workflows/release.yml`'s
/// `yubaba-release-manifest` job. Hardcoded so operators don't need to memorise
/// it; operators *can* still override by passing `--yubaba-manifest-url`.
pub const DEFAULT_RELEASE_MANIFEST_URL: &str = "https://cdn.yah.dev/yubaba/release-manifest.json";

/// Default cosign keyless OIDC identity regexp the yubaba release pipeline
/// signs against. Matches the `cosign sign-blob` certificate identity emitted
/// by GitHub Actions when running under `yah-ai/yah` (R330-F19). Operators
/// override with `--yubaba-cosign-identity` to point at a fork's OIDC subject.
pub const DEFAULT_YUBABA_COSIGN_IDENTITY: &str = r"^https://github\.com/yah-ai/yah/";

/// One per-triple entry in the manifest. Field order matches what
/// release.yml's `Emit per-triple manifest fragment` step writes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestTripleEntry {
    pub url: String,
    pub size: u64,
    pub sha256: String,
    pub sig_url: String,
    pub cert_url: String,
}

/// Top-level shape of `release-manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubabaReleaseManifest {
    pub version: String,
    pub triples: BTreeMap<String, ManifestTripleEntry>,
}

impl YubabaReleaseManifest {
    /// Look up the manifest entry for the given Rust target triple. Returns a
    /// descriptive error listing the available triples so operators can spot a
    /// typo or a missing matrix leg at a glance.
    pub fn entry(&self, triple: &str) -> Result<&ManifestTripleEntry> {
        self.triples.get(triple).ok_or_else(|| {
            let available: Vec<_> = self.triples.keys().cloned().collect();
            anyhow!(
                "release-manifest has no entry for triple '{triple}' (available: {available:?})"
            )
        })
    }
}

/// Map a Hetzner server-type code to a Rust target triple. The current matrix
/// (W203 §1.2) is x86_64 + aarch64 Linux musl. Hetzner's ARM line uses the
/// `cax` prefix (cax11 / cax21 / …) — every other prefix (cpx*, ccx*, cx*) is
/// Intel/AMD x86_64. This is operational truth, not heuristic — Hetzner
/// publishes that mapping in their public pricing page and the catalog crate.
pub fn server_type_to_triple(server_type: &str) -> Result<&'static str> {
    if server_type.starts_with("cax") {
        Ok("aarch64-unknown-linux-musl")
    } else if server_type.starts_with("cpx")
        || server_type.starts_with("ccx")
        || server_type.starts_with("cx")
    {
        Ok("x86_64-unknown-linux-musl")
    } else {
        bail!(
            "unknown Hetzner server_type '{server_type}' — cannot infer architecture. \
             Pass --yubaba-url + --yubaba-sha256 explicitly to skip manifest resolution."
        )
    }
}

/// Fetch the release-manifest from the canonical URL. Caller picks the runtime;
/// inside `yah cloud machine provision` the existing `tokio::runtime::Runtime`
/// drives this. Surfaces every failure mode loud (no silent placeholder
/// fallback) — operators see an actionable message and pass `--yubaba-url`
/// explicitly to bypass.
pub async fn fetch_release_manifest(url: &str) -> Result<YubabaReleaseManifest> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("yah/cloud release-manifest fetcher")
        .build()
        .context("building http client for release-manifest fetch")?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching release-manifest from {url}"))?;
    if !resp.status().is_success() {
        bail!(
            "release-manifest fetch from {url} returned HTTP {} — \
             pass --yubaba-url explicitly if the manifest is unreachable",
            resp.status()
        );
    }
    let body = resp
        .bytes()
        .await
        .with_context(|| format!("reading release-manifest body from {url}"))?;
    let manifest: YubabaReleaseManifest = serde_json::from_slice(&body).with_context(|| {
        format!(
            "parsing release-manifest from {url} — pass --yubaba-url explicitly if the manifest is malformed"
        )
    })?;
    if manifest.triples.is_empty() {
        bail!(
            "release-manifest from {url} has no triples — \
             pass --yubaba-url explicitly to bypass manifest resolution"
        );
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_type_to_triple_maps_arm_prefix() {
        assert_eq!(
            server_type_to_triple("cax11").unwrap(),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            server_type_to_triple("cax21").unwrap(),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            server_type_to_triple("cax41").unwrap(),
            "aarch64-unknown-linux-musl"
        );
    }

    #[test]
    fn server_type_to_triple_maps_x86_prefixes() {
        assert_eq!(
            server_type_to_triple("cpx22").unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            server_type_to_triple("ccx13").unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            server_type_to_triple("cx32").unwrap(),
            "x86_64-unknown-linux-musl"
        );
    }

    #[test]
    fn server_type_to_triple_rejects_unknown_prefix() {
        let err = server_type_to_triple("xxx99").unwrap_err().to_string();
        assert!(err.contains("unknown Hetzner server_type"), "msg: {err}");
        assert!(
            err.contains("--yubaba-url"),
            "msg points to override: {err}"
        );
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let raw = r#"{
            "version": "0.9.0",
            "triples": {
                "x86_64-unknown-linux-musl": {
                    "url": "https://cdn.yah.dev/yubaba/0.9.0/x86_64-unknown-linux-musl/yah-yubaba-x86_64-unknown-linux-musl.tar.gz",
                    "size": 2345678,
                    "sha256": "abc123",
                    "sig_url": "https://cdn.yah.dev/yubaba/0.9.0/x86_64-unknown-linux-musl/yah-yubaba-x86_64-unknown-linux-musl.tar.gz.sig",
                    "cert_url": "https://cdn.yah.dev/yubaba/0.9.0/x86_64-unknown-linux-musl/yah-yubaba-x86_64-unknown-linux-musl.tar.gz.cert"
                }
            }
        }"#;
        let parsed: YubabaReleaseManifest = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.version, "0.9.0");
        let entry = parsed.entry("x86_64-unknown-linux-musl").unwrap();
        assert_eq!(entry.size, 2345678);
        assert_eq!(entry.sha256, "abc123");
        assert!(entry.sig_url.ends_with(".tar.gz.sig"));
        assert!(entry.cert_url.ends_with(".tar.gz.cert"));
    }

    #[test]
    fn manifest_entry_missing_triple_lists_available() {
        let raw = r#"{"version":"0.9.0","triples":{"x86_64-unknown-linux-musl":{"url":"u","size":1,"sha256":"s","sig_url":"u.sig","cert_url":"u.cert"}}}"#;
        let parsed: YubabaReleaseManifest = serde_json::from_str(raw).unwrap();
        let err = parsed
            .entry("aarch64-unknown-linux-musl")
            .unwrap_err()
            .to_string();
        assert!(err.contains("aarch64-unknown-linux-musl"));
        assert!(
            err.contains("x86_64-unknown-linux-musl"),
            "lists available: {err}"
        );
    }

    #[test]
    fn default_identity_regexp_matches_yah_ai_yah() {
        // Sanity: the constant matches what release.yml's cosign sign-blob
        // step emits as the keyless certificate identity. Bumping the org
        // requires updating both this constant AND release.yml in lockstep.
        assert!(DEFAULT_YUBABA_COSIGN_IDENTITY.contains("yah-ai/yah"));
    }
}
