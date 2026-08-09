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

/// Sigstore Fulcio OIDC issuer for GitHub-Actions-rooted keyless signing —
/// what `.github/workflows/release.yml`'s `cosign sign-blob` step produces
/// (R330-F19). The canonical copy; `cloud_init` and the yah CLI's
/// `yubaba_fetch` both read it from here so the two verify paths can't drift.
pub const COSIGN_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Prefix that selects key-based verification in a cosign-identity spec.
/// See [`ReleaseTrust::parse`].
pub const KEY_TRUST_PREFIX: &str = "key:";

/// How a consumer proves a release artifact is ours (R605-F1).
///
/// The two arms are the verify-side mirror of `yah_qed::SigningIdentity`, and
/// they exist for the same reason: a release cut on QED instead of GitHub
/// cannot use Fulcio keyless, because the public-good Fulcio only issues certs
/// for OIDC issuers on its own configured allowlist. W235 §"Off-GHA forfeits
/// GitHub OIDC keyless cosign" makes the call — key-based cosign, key vaulted
/// in kamaji — so every consumer that verifies a yubaba/CLI artifact has to be
/// able to express both.
///
/// This is carried through the config plumbing as a plain string (the existing
/// `--yubaba-cosign-identity` value, the `RenderInput` field, the manifest's
/// identity regexp) and parsed at the two points that actually shell `cosign`.
/// Keeping the wire type a string is deliberate: it means flipping a fleet to
/// key-based trust is a value change, not a schema migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseTrust {
    /// Fulcio keyless: pin the certificate identity + the OIDC issuer.
    Keyless {
        identity_regexp: String,
        oidc_issuer: String,
    },
    /// Key-based: pin the cosign *public* key. `key_ref` is whatever
    /// `cosign verify-blob --key` accepts — a `.pub` path, an `https://` URL,
    /// or a KMS URI (`awskms://…`, `hashivault://…`).
    Key { key_ref: String },
}

impl ReleaseTrust {
    /// Parse an operator-supplied cosign-identity spec.
    ///
    /// `key:<ref>` selects key-based verification; anything else is a keyless
    /// certificate-identity regexp against [`COSIGN_OIDC_ISSUER`]. The prefix
    /// is explicit rather than sniffed, because a KMS URI and a regexp are
    /// both arbitrary strings and guessing between them would silently pick
    /// the wrong trust model.
    pub fn parse(spec: &str) -> Self {
        match spec.strip_prefix(KEY_TRUST_PREFIX) {
            Some(key_ref) => Self::Key {
                key_ref: key_ref.trim().to_string(),
            },
            None => Self::Keyless {
                identity_regexp: spec.to_string(),
                oidc_issuer: COSIGN_OIDC_ISSUER.to_string(),
            },
        }
    }

    /// Whether verification consumes the `.cert` sidecar. Key-based signatures
    /// have no Fulcio certificate, so a consumer must not fail the download
    /// when the release published no `.cert` alongside the `.sig`.
    pub fn needs_certificate(&self) -> bool {
        matches!(self, Self::Keyless { .. })
    }

    /// The `cosign verify-blob` flags this trust model contributes, in order.
    /// The caller appends `--signature`/`--certificate`/the blob itself.
    pub fn verify_flags(&self) -> Vec<String> {
        match self {
            Self::Keyless {
                identity_regexp,
                oidc_issuer,
            } => vec![
                "--certificate-identity-regexp".into(),
                identity_regexp.clone(),
                "--certificate-oidc-issuer".into(),
                oidc_issuer.clone(),
            ],
            Self::Key { key_ref } => vec!["--key".into(), key_ref.clone()],
        }
    }
}

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
///
/// The two epoch fields (R625-F2) are **release-wide, not per-triple** — the
/// raft protocol and on-disk layout are architecture-independent, so they sit
/// alongside `version` rather than inside each [`ManifestTripleEntry`]. They are
/// `Option` because manifests published before this field existed carry neither;
/// see [`YubabaReleaseManifest::cluster_epochs`] for why absent must never be
/// read as "compatible".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubabaReleaseManifest {
    pub version: String,
    /// Wire-compatibility epoch: may a node running this release sit in one raft
    /// cluster with a node running some other release. Mixed operation is
    /// permitted iff every node shares this integer (W275 "Cluster compatibility
    /// epochs"). Sourced from `oss/yubaba/crates/yubaba/cluster-epochs.json`,
    /// the same file the binary parses at compile time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_protocol: Option<u32>,
    /// On-disk state epoch: can this release read the previous release's raft
    /// log/snapshot, and can you roll **back** to it. Tracked separately from
    /// `cluster_protocol` on purpose — openraft 0.9→0.10 broke both at once,
    /// which is exactly how one combined flag would have hidden the rollback
    /// hazard (W275 §5 "Roll-back is symmetric").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_epoch: Option<u32>,
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

    // ── R605-F1 release trust spec ────────────────────────────────────────

    #[test]
    fn bare_spec_is_keyless_against_the_default_issuer() {
        // Every existing config value must keep meaning exactly what it meant
        // before the key arm existed.
        assert_eq!(
            ReleaseTrust::parse(DEFAULT_YUBABA_COSIGN_IDENTITY),
            ReleaseTrust::Keyless {
                identity_regexp: DEFAULT_YUBABA_COSIGN_IDENTITY.into(),
                oidc_issuer: COSIGN_OIDC_ISSUER.into(),
            }
        );
    }

    #[test]
    fn key_prefix_selects_key_trust_and_trims() {
        assert_eq!(
            ReleaseTrust::parse("key: awskms:///alias/yah-release "),
            ReleaseTrust::Key {
                key_ref: "awskms:///alias/yah-release".into()
            }
        );
    }

    #[test]
    fn a_kms_uri_without_the_prefix_stays_keyless() {
        // Deliberate: sniffing a URI scheme out of a free-form regexp would
        // silently swap the trust model. The prefix is the only signal.
        assert!(matches!(
            ReleaseTrust::parse("awskms:///alias/yah-release"),
            ReleaseTrust::Keyless { .. }
        ));
    }

    #[test]
    fn verify_flags_and_cert_need_track_the_arm() {
        let keyless = ReleaseTrust::parse(DEFAULT_YUBABA_COSIGN_IDENTITY);
        assert!(keyless.needs_certificate());
        assert_eq!(
            keyless.verify_flags(),
            vec![
                "--certificate-identity-regexp".to_string(),
                DEFAULT_YUBABA_COSIGN_IDENTITY.to_string(),
                "--certificate-oidc-issuer".to_string(),
                COSIGN_OIDC_ISSUER.to_string(),
            ]
        );

        let keyed = ReleaseTrust::parse("key:cosign.pub");
        assert!(!keyed.needs_certificate());
        assert_eq!(
            keyed.verify_flags(),
            vec!["--key".to_string(), "cosign.pub".to_string()]
        );
    }

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
        // This manifest predates R625-F2 — the epochs are absent, not zero.
        assert_eq!(parsed.cluster_protocol, None);
        assert_eq!(parsed.state_epoch, None);
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
    fn manifest_carries_the_two_cluster_epochs() {
        // R625-F2. The shape release.yml now publishes: two release-wide
        // integers alongside `version`, NOT per-triple (raft protocol and
        // on-disk layout are architecture-independent).
        let raw = r#"{
            "version": "0.8.22",
            "cluster_protocol": 2,
            "state_epoch": 2,
            "triples": {
                "x86_64-unknown-linux-musl": {
                    "url": "u", "size": 1, "sha256": "s", "sig_url": "a", "cert_url": "b"
                }
            }
        }"#;
        let parsed: YubabaReleaseManifest = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.cluster_protocol, Some(2));
        assert_eq!(parsed.state_epoch, Some(2));

        // Round-trip keeps them, and a manifest that declares nothing emits
        // nothing (rather than an implicit 0, which would read as "declared").
        let back: YubabaReleaseManifest =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(back.cluster_protocol, Some(2));
        assert_eq!(back.state_epoch, Some(2));

        let undeclared = YubabaReleaseManifest {
            version: "0.8.20".into(),
            cluster_protocol: None,
            state_epoch: None,
            triples: BTreeMap::new(),
        };
        let json = serde_json::to_string(&undeclared).unwrap();
        assert!(!json.contains("cluster_protocol"), "{json}");
        assert!(!json.contains("state_epoch"), "{json}");
    }

    #[test]
    fn default_identity_regexp_matches_yah_ai_yah() {
        // Sanity: the constant matches what release.yml's cosign sign-blob
        // step emits as the keyless certificate identity. Bumping the org
        // requires updating both this constant AND release.yml in lockstep.
        assert!(DEFAULT_YUBABA_COSIGN_IDENTITY.contains("yah-ai/yah"));
    }
}
