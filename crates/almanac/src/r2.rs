use chrono::Utc;
use serde::Deserialize;
use std::collections::HashMap;

use crate::config::SourceConfig;
use crate::feed::{AssetHash, BlakeHash, Release, ReleaseAsset, ReleaseFeed, Sha256Hash};
use crate::sources::{decode_json, FeedPayload, FeedSource, ReleaseSource, SourceError};

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
    /// When set, addresses the manifest directly instead of deriving the path
    /// from `base_url` + `binary`.
    manifest_url: Option<String>,
}

impl R2Channel {
    pub fn new(binary: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self { binary: binary.into(), base_url: base_url.into(), manifest_url: None }
    }

    /// Read the same manifest schema from an explicit URL.
    ///
    /// Lets the blobs live under content-addressed keys while the manifest
    /// stays at one stable, overwritten key — see [`crate::config::SourceConfig::R2Manifest`].
    pub fn at_url(url: impl Into<String>, id: impl Into<String>) -> Self {
        Self { binary: id.into(), base_url: String::new(), manifest_url: Some(url.into()) }
    }

    fn manifest_url(&self) -> String {
        match &self.manifest_url {
            Some(u) => u.clone(),
            None => format!("{}/{}/release-manifest.json", self.base_url, self.binary),
        }
    }
}

#[async_trait::async_trait]
impl ReleaseSource for R2Channel {
    fn source_id(&self) -> &str {
        &self.binary
    }

    async fn fetch(&self) -> Result<ReleaseFeed, SourceError> {
        let url = self.manifest_url();
        let resp: ChannelManifest = decode_json(reqwest::get(&url).await?).await?;

        Ok(feed_from_manifest(resp))
    }
}

/// Pure manifest → feed mapping, split out of [`R2Channel::fetch`] so the
/// wire-schema translation is testable without an HTTP round trip.
fn feed_from_manifest(resp: ChannelManifest) -> ReleaseFeed {
    single_release_feed(
        &resp.version,
        &resp.pub_date,
        resp.notes,
        resp.host
            .bundle
            .into_iter()
            .map(|(triple, bundle)| {
                let mut asset = ReleaseAsset {
                    platform: platform_from_triple(&triple),
                    filename: filename_from_url(&bundle.url),
                    url: bundle.url,
                    hash: bundle.hash,
                    bootstrap_hash: bundle.bootstrap_hash,
                    blake3: bundle.blake3,
                    sha256: None,
                    license: None,
                    size_bytes: bundle.size,
                };
                asset.normalize_hashes();
                asset
            })
            .collect(),
    )
}

/// One version's assets as a [`Release`].
///
/// Sorts the assets, which is load-bearing rather than cosmetic: every manifest
/// schema here keys its per-target section by triple in a `HashMap`, whose
/// iteration order is randomized per process. The runner detects change by
/// diffing the *serialized* `releases` array
/// ([`crate::runner::FeedRunner::artifact_changed`]), so an unsorted feed
/// reshuffles its own asset order on every fetch and reads as changed every
/// single time — firing a full mesofact rebuild + R2 publish + CDN purge for a
/// release that did not move. Sorting makes an unchanged release serialize
/// byte-identically, which is what makes the no-op case actually a no-op.
fn release_from_parts(
    version: &str,
    pub_date: &str,
    notes: Option<String>,
    mut assets: Vec<ReleaseAsset>,
) -> Release {
    assets.sort_by(|a, b| (&a.platform, &a.filename).cmp(&(&b.platform, &b.filename)));
    let version = version.trim_start_matches('v').to_string();
    Release {
        tag: format!("v{version}"),
        version,
        published_at: pub_date.parse().unwrap_or_else(|_| Utc::now()),
        notes,
        assets,
    }
}

/// Wraps one version's assets into the feed shape both single-version R2
/// manifests produce. See [`release_from_parts`] for why the sort matters.
fn single_release_feed(
    version: &str,
    pub_date: &str,
    notes: Option<String>,
    assets: Vec<ReleaseAsset>,
) -> ReleaseFeed {
    ReleaseFeed {
        fetched_at: Utc::now(),
        releases: vec![release_from_parts(version, pub_date, notes, assets)],
    }
}

/// Fetches releases from the *install-pointer* object — the flat
/// `{name, version, pub_date, triples: {<triple>: {...}}}` manifest the
/// `cli-release-manifest` GHA job publishes to `cdn.yah.dev/yah/latest.json`.
///
/// A distinct adapter from [`R2Channel`] because the two producers genuinely
/// emit different shapes and the pointer object's shape is not ours to change:
/// `app/yah/web/marketing/public/install.sh` reads `.triples[$t][$f]` out of
/// it, so `curl yah.dev/install.sh | sh` is a live consumer of that exact
/// layout. See [`crate::config::SourceConfig::R2Triples`] for why the consumer
/// adapts and not the producer.
///
/// The object is a single version (it is the "what does `install.sh` fetch
/// right now" pointer), so the feed it produces is a one-entry list by
/// construction. The accumulating multi-version index the /releases page
/// eventually wants is a separate object — the immutable per-version
/// `yah/<version>/manifest.json` keys are already published to build it from.
pub struct R2Triples {
    id: String,
    url: String,
}

impl R2Triples {
    pub fn at_url(url: impl Into<String>, id: impl Into<String>) -> Self {
        Self { id: id.into(), url: url.into() }
    }
}

#[async_trait::async_trait]
impl ReleaseSource for R2Triples {
    fn source_id(&self) -> &str {
        &self.id
    }

    async fn fetch(&self) -> Result<ReleaseFeed, SourceError> {
        let resp: TriplesManifest = decode_json(reqwest::get(&self.url).await?).await?;
        Ok(feed_from_triples(resp))
    }
}

/// Pure manifest → feed mapping, split out of [`R2Triples::fetch`] so the
/// wire-schema translation is testable without an HTTP round trip.
fn feed_from_triples(resp: TriplesManifest) -> ReleaseFeed {
    single_release_feed(&resp.version, &resp.pub_date, resp.notes, assets_from_triples(resp.triples))
}

/// The per-triple map → [`ReleaseAsset`] mapping, shared by the install pointer
/// and the accumulating index because both carry the *same* entry shape — the
/// index literally stores the pointer's entries (minus the legacy bare digests,
/// which it never grandfathers). One mapping means an index entry and a pointer
/// entry can never render differently.
fn assets_from_triples(triples: HashMap<String, TripleEntry>) -> Vec<ReleaseAsset> {
    triples
        .into_iter()
        .map(|(triple, entry)| {
            let mut asset = ReleaseAsset {
                // The producer already resolved the platform token and vetted
                // it against the page's PLATFORM_LABELS, so prefer it over
                // re-deriving. Not merely redundant: `platform_from_triple`
                // matches on the `x86_64-unknown-linux` prefix and so collapses
                // the musl and gnu legs onto one token, listing two
                // non-interchangeable binaries as the same download.
                platform: entry.platform.unwrap_or_else(|| platform_from_triple(&triple)),
                filename: entry.filename.unwrap_or_else(|| filename_from_url(&entry.url)),
                url: entry.url,
                hash: entry.hash,
                bootstrap_hash: entry.bootstrap_hash,
                blake3: entry.blake3,
                sha256: entry.sha256,
                license: None,
                size_bytes: entry.size_bytes,
            };
            asset.normalize_hashes();
            asset
        })
        .collect()
}

/// Fetches the **whole published history** from the accumulating version index
/// — the object `cli-release-manifest` appends to at
/// `cdn.yah.dev/yah/index.json` on every tagged release (R330-F38).
///
/// [`R2Triples`] reads the install pointer and therefore yields exactly one
/// release; that is correct for "what does `install.sh` fetch right now" and
/// wrong for a page whose whole content is the version list. This source reads
/// the index instead, so `/releases` gets every version — cards above the fold
/// and the full history below — from ONE unauthenticated conditional GET.
///
/// See [`crate::config::SourceConfig::R2Index`] for why an index object and not
/// a prefix listing, and why it is tagged-hash-only.
pub struct R2Index {
    id: String,
    url: String,
}

impl R2Index {
    pub fn at_url(url: impl Into<String>, id: impl Into<String>) -> Self {
        Self { id: id.into(), url: url.into() }
    }
}

#[async_trait::async_trait]
impl ReleaseSource for R2Index {
    fn source_id(&self) -> &str {
        &self.id
    }

    async fn fetch(&self) -> Result<ReleaseFeed, SourceError> {
        let resp: IndexManifest = decode_json(reqwest::get(&self.url).await?).await?;
        Ok(feed_from_index(resp))
    }
}

/// Fetches one **credential-gated** R2 object with a SigV4-signed S3 `GET` and
/// hands it on verbatim (R707-F4).
///
/// Sibling of [`R2Index`], not a variant of it: same one-mutable-object
/// change-detector, same webhook cadence, inverted credential posture. See
/// [`crate::config::SourceConfig::R2Private`] for why that inversion exists and
/// why the public sources must not be routed through here.
///
/// This is a [`FeedSource`] rather than a [`ReleaseSource`] because its payload
/// is not a release list and pretending otherwise would mean inventing a mapping
/// for a schema almanac does not own.
pub struct R2Private {
    id: String,
    /// Label only — the bucket is fixed by `store`. Carried so a failure names
    /// it, since a wrong-bucket credential and a wrong key look identical
    /// otherwise.
    bucket: String,
    key: String,
    store: std::sync::Arc<dyn yah_object_store::ObjectStore>,
}

impl R2Private {
    /// Build from already-resolved credentials.
    ///
    /// Resolution stays in [`crate::runner`] so a missing secret is reported as
    /// a feed-config problem naming the reference that failed, rather than as an
    /// opaque signature mismatch from the edge.
    pub fn new(
        id: impl Into<String>,
        account_id: &str,
        bucket: impl Into<String>,
        key: impl Into<String>,
        access_key_id: &str,
        secret_access_key: &str,
        endpoint: Option<&str>,
    ) -> Result<Self, SourceError> {
        let bucket = bucket.into();
        let mut store = yah_object_store::R2ObjectStore::new(
            account_id,
            &bucket,
            access_key_id,
            secret_access_key,
        )
        .map_err(|e| SourceError::Credential(format!("building the R2 client: {e}")))?;
        if let Some(endpoint) = endpoint {
            store = store.with_endpoint(endpoint);
        }
        Ok(Self::with_store(id, bucket, key, std::sync::Arc::new(store)))
    }

    /// Read from an explicit store — the seam the hermetic tests use
    /// (`InMemoryObjectStore`), and the one a pond-tier MinIO would use.
    pub fn with_store(
        id: impl Into<String>,
        bucket: impl Into<String>,
        key: impl Into<String>,
        store: std::sync::Arc<dyn yah_object_store::ObjectStore>,
    ) -> Self {
        Self { id: id.into(), bucket: bucket.into(), key: key.into(), store }
    }
}

#[async_trait::async_trait]
impl FeedSource for R2Private {
    fn source_id(&self) -> &str {
        &self.id
    }

    async fn fetch_payload(&self) -> Result<FeedPayload, SourceError> {
        // `ObjectStore` is a synchronous trait whose R2 impl blocks on reqwest
        // internally — keep it off the async runtime worker, exactly as
        // `crate::sink` does on the write side.
        let bytes = {
            let store = std::sync::Arc::clone(&self.store);
            let (bucket, key) = (self.bucket.clone(), self.key.clone());
            tokio::task::spawn_blocking(move || {
                store
                    .get(&key)
                    .map_err(|e| SourceError::ObjectRead { bucket, key, detail: e.to_string() })
            })
            .await
            .map_err(|e| SourceError::ObjectRead {
                bucket: self.bucket.clone(),
                key: self.key.clone(),
                detail: format!("read task panicked: {e}"),
            })??
        };

        // A MISSING KEY IS AN ERROR, never an empty payload. This is R568-T7's
        // failure one layer down: a consumer handed `{}` renders a healthy,
        // confident fleet of zero machines, and the operator has no way to tell
        // that apart from a fleet that really is empty.
        let Some(bytes) = bytes else {
            return Err(SourceError::ObjectRead {
                bucket: self.bucket.clone(),
                key: self.key.clone(),
                detail: "no such key — the publisher has not run, or the key is \
                         wrong. Refusing to emit an empty artifact for it"
                    .to_string(),
            });
        };

        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            SourceError::Parse(format!(
                "{} in bucket {} is not JSON ({} bytes): {e}",
                self.key,
                self.bucket,
                bytes.len()
            ))
        })?;
        Ok(FeedPayload::Passthrough(value))
    }
}

/// Pure index → feed mapping, split out of [`R2Index::fetch`] so the
/// wire-schema translation is testable without an HTTP round trip.
///
/// Sorts newest-first here rather than trusting the producer's order. The
/// producer does sort, but this feed is a *change-detector* as well as a
/// renderer: if the order it wrote ever wobbled, every fetch would diff as
/// changed and fire a full rebuild + CDN purge for a history that did not move.
/// Re-establishing the order on read makes that impossible by construction —
/// the same reasoning as the asset sort in [`release_from_parts`].
fn feed_from_index(resp: IndexManifest) -> ReleaseFeed {
    let mut releases: Vec<Release> = resp
        .versions
        .into_iter()
        .map(|v| release_from_parts(&v.version, &v.pub_date, v.notes, assets_from_triples(v.triples)))
        .collect();
    // Newest first. `version` breaks a tie deterministically — two entries
    // sharing a `pub_date` must not be free to swap places between fetches.
    releases.sort_by(|a, b| {
        b.published_at.cmp(&a.published_at).then_with(|| b.version.cmp(&a.version))
    });
    ReleaseFeed { fetched_at: Utc::now(), releases }
}

// ── Producer-side reuse of the manifest → feed mapping (R330-T14) ────────────

/// Why a raw manifest could not be turned into a [`ReleaseFeed`].
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// The bytes do not parse as the shape this source declares. The common
    /// cause is a producer that writes one manifest layout while the feed
    /// sources the other (channel `host.bundle` vs install-pointer `triples`).
    #[error("manifest does not parse as the {kind} layout this feed sources: {source}")]
    Shape {
        kind: &'static str,
        #[source]
        source: serde_json::Error,
    },
    /// The source is not manifest-backed, so there is nothing to map from.
    #[error("source kind {0} is not manifest-backed — nothing to map a published manifest onto")]
    NotManifestBacked(&'static str),
}

/// Map the raw bytes of a published channel `release-manifest.json` onto the
/// feed shape [`R2Channel`]/[`SourceConfig::R2Manifest`] would have fetched.
pub fn feed_from_channel_manifest(raw: &str) -> Result<ReleaseFeed, ManifestError> {
    serde_json::from_str(raw)
        .map(feed_from_manifest)
        .map_err(|source| ManifestError::Shape { kind: "channel host.bundle", source })
}

/// Map the raw bytes of a published install-pointer `latest.json` onto the feed
/// shape [`R2Triples`] would have fetched.
pub fn feed_from_triples_manifest(raw: &str) -> Result<ReleaseFeed, ManifestError> {
    serde_json::from_str(raw)
        .map(feed_from_triples)
        .map_err(|source| ManifestError::Shape { kind: "install-pointer triples", source })
}

/// Map the raw bytes of a published `index.json` onto the feed shape
/// [`R2Index`] would have fetched.
pub fn feed_from_index_manifest(raw: &str) -> Result<ReleaseFeed, ManifestError> {
    serde_json::from_str(raw)
        .map(feed_from_index)
        .map_err(|source| ManifestError::Shape { kind: "accumulating version index", source })
}

/// The producer-side half of the fetch tier: given the feed's own `source`
/// config and the manifest the producer just published, build the exact
/// [`ReleaseFeed`] that feed's next fetch would have produced.
///
/// This is what lets a CI run that just cut a release **hand the fact over**
/// in its revalidate poke instead of publishing it and waiting for a poller to
/// notice (W059 §1, R330-F33). Dispatching on the feed's declared `source` —
/// rather than letting the caller pick a mapping — is the load-bearing part:
/// the payload must be byte-equal to what the fetch tier would write, or the
/// sidecar's next tick sees a spurious change and re-renders. A producer whose
/// manifest layout disagrees with what its feed sources therefore gets a
/// [`ManifestError::Shape`] and should degrade to a payload-less poke, not
/// ship bytes the feed would never have produced.
pub fn feed_from_source_manifest(
    source: &SourceConfig,
    raw: &str,
) -> Result<ReleaseFeed, ManifestError> {
    match source {
        SourceConfig::R2Channel { .. } | SourceConfig::R2Manifest { .. } => {
            feed_from_channel_manifest(raw)
        }
        SourceConfig::R2Triples { .. } => feed_from_triples_manifest(raw),
        SourceConfig::R2Index { .. } => feed_from_index_manifest(raw),
        // The GitHub releases API is queried, not published to — there is no
        // producer-written manifest for a poke to carry.
        SourceConfig::GhReleases { .. } => Err(ManifestError::NotManifestBacked("gh-releases")),
        // Deliberate, and not merely "no mapping exists". A carried payload
        // rides the `/revalidate` HTTP body, and this source kind exists
        // precisely because its object must not be readable by whoever can reach
        // that endpoint — handing it over in the poke would route the thing the
        // credential protects around the credential. It also breaks the property
        // `coalesce.rs` rests on: an almanac source is ABSOLUTE and its ping
        // carries nothing but a feed name, so the consumer's own authenticated
        // fetch is both the safe path and the complete one.
        SourceConfig::R2Private { .. } => Err(ManifestError::NotManifestBacked("r2-private")),
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
    /// Tagged canonical hash, `blake3:<hex>` (R330-F40). Optional only because
    /// manifests published before that ticket carry the bare `blake3` key
    /// below; `scripts/publish-desktop.sh` now fails the publish rather than
    /// emit an asset with no hash at all.
    #[serde(default)]
    hash: Option<AssetHash>,
    /// Tagged `sha256:<hex>` bootstrap-verification aid.
    #[serde(default)]
    bootstrap_hash: Option<AssetHash>,
    /// LEGACY bare BLAKE3 hex, written by `scripts/publish-desktop.sh` before
    /// R330-F40. Absent on manifests published before R157-F1, which is why it
    /// stays optional — but when present it must be 64 hex digits, or
    /// [`BlakeHash`]'s Deserialize fails the whole manifest.
    #[serde(default)]
    blake3: Option<BlakeHash>,
}

// ── Install-pointer wire types (`cli-release-manifest` → yah/latest.json) ─────

/// Mirrors the `jq -n` object built by the `cli-release-manifest` job in
/// `.github/workflows/release.yml`; the per-triple entries are the fragments
/// `publish-cli` emits, minus their own `triple` key (the merge uses it as the
/// map key and deletes it).
#[derive(Deserialize)]
struct TriplesManifest {
    version: String,
    pub_date: String,
    #[serde(default)]
    notes: Option<String>,
    /// Keyed by full target triple, e.g. `"aarch64-apple-darwin"`.
    triples: HashMap<String, TripleEntry>,
}

/// One published target. Extra producer fields (`name`, `sig_url`, `cert_url`,
/// `bins`) are deliberately not deserialized: they belong to `install.sh`'s
/// contract with the pointer object, not to the release *feed*, and serde
/// ignores them. Only `url` is required — the fragment always carries the rest,
/// but a hand-written or trimmed pointer should degrade to a plain download
/// link rather than fail the whole fetch.
#[derive(Deserialize)]
struct TripleEntry {
    url: String,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
    /// Tagged canonical hash, `blake3:<hex>` (R330-F40).
    #[serde(default)]
    hash: Option<AssetHash>,
    /// Tagged `sha256:<hex>` — the digest `install.sh` can actually check on a
    /// box with no `b3sum`. Same value as the legacy bare `sha256` below.
    #[serde(default)]
    bootstrap_hash: Option<AssetHash>,
    /// LEGACY bare `sha256sum` of the tarball. Still emitted, and still read by
    /// every `install.sh` in the wild — see [`crate::feed::LEGACY_BARE_HEX_PATHS`].
    #[serde(default)]
    sha256: Option<Sha256Hash>,
    /// LEGACY bare BLAKE3 hex. Never emitted by the CLI leg (which writes the
    /// tagged `hash` instead); accepted so a hand-written pointer still maps.
    #[serde(default)]
    blake3: Option<BlakeHash>,
}

// ── Accumulating version index (`cli-release-manifest` → yah/index.json) ─────

/// Mirrors the object the release job read-modify-writes at
/// `s3://yah-dev/yah/index.json`. **Fat by design**: every version carries its
/// full per-triple asset info inline (a few KB per release), so the whole
/// /releases page — cards above the fold and the version history below — comes
/// from one fetch rather than one per version.
///
/// `schema` is read but not matched on: a future producer bump should be able
/// to add fields without stranding a deployed node, and serde already ignores
/// unknown ones. A *breaking* change gets a new key, not a version discriminant
/// nobody can roll out atomically.
#[derive(Deserialize)]
struct IndexManifest {
    /// REQUIRED, and not `#[serde(default)]` — that was the first cut and it
    /// was a silent-data-loss bug. With a default, the install *pointer*
    /// (which has no `versions` key) parses cleanly as an index with zero
    /// entries, so handing the wrong manifest to this feed publishes an empty
    /// history over a real one instead of being refused. Requiring the key is
    /// what makes the two layouts mutually exclusive, which is the whole
    /// premise of [`feed_from_source_manifest`] dispatching on the feed's own
    /// declared source. An index with genuinely no releases yet writes
    /// `"versions": []`, which still parses.
    versions: Vec<IndexVersion>,
}

/// One published version inside the index. The `triples` map is the same shape
/// [`TriplesManifest`] carries — the producer stores the pointer's own entries,
/// minus the legacy bare digests. See [`crate::config::SourceConfig::R2Index`].
#[derive(Deserialize)]
struct IndexVersion {
    version: String,
    pub_date: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    triples: HashMap<String, TripleEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::HashAlgo;

    const MANIFEST: &str = r#"{
      "version": "v0.8.20",
      "pub_date": "2026-07-24T00:00:00Z",
      "notes": "yah 0.8.20",
      "host": {
        "bundle": {
          "aarch64-apple-darwin": {
            "url": "https://cdn.yah.dev/yah-desktop/releases/0.8.20/yah_0.8.20_aarch64.dmg",
            "blake3": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "size": 1234
          }
        }
      }
    }"#;

    #[test]
    fn manifest_blake3_reaches_the_asset() {
        let manifest: ChannelManifest = serde_json::from_str(MANIFEST).unwrap();
        let feed = feed_from_manifest(manifest);
        let asset = &feed.releases[0].assets[0];

        assert_eq!(asset.platform, "macos-arm64");
        assert_eq!(asset.filename, "yah_0.8.20_aarch64.dmg");
        assert_eq!(asset.size_bytes, Some(1234));
        assert_eq!(
            asset.blake3.as_ref().map(|h| h.0.as_str()),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        );
    }

    #[test]
    fn manifest_without_blake3_still_parses() {
        // Pre-R157-F1 manifests carry url+size only; the feed must degrade to a
        // hashless asset rather than failing the fetch.
        let json = MANIFEST.replace(
            "\"blake3\": \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\n",
            "",
        );
        let manifest: ChannelManifest = serde_json::from_str(&json).unwrap();
        let feed = feed_from_manifest(manifest);

        assert_eq!(feed.releases[0].version, "0.8.20");
        assert_eq!(feed.releases[0].tag, "v0.8.20");
        assert_eq!(feed.releases[0].assets[0].blake3, None);
    }

    /// Byte-faithful copy of what `cli-release-manifest` writes: the `jq -n`
    /// object in `.github/workflows/release.yml` with the five fragments
    /// `publish-cli` emits (its own `jq -n` object, `triple` deleted by the
    /// merge). Held as a literal rather than constructed so a drift in the
    /// producer's shape shows up here as a failing parse.
    const LATEST_JSON: &str = r#"{
      "name": "yah",
      "version": "0.8.21",
      "pub_date": "2026-08-04T11:22:33Z",
      "triples": {
        "aarch64-apple-darwin": {
          "platform": "macos-arm64",
          "filename": "yah-aarch64-apple-darwin.tar.gz",
          "url": "https://cdn.yah.dev/yah/0.8.21/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz",
          "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
          "size_bytes": 11,
          "sig_url": "https://cdn.yah.dev/yah/0.8.21/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz.sig",
          "cert_url": "https://cdn.yah.dev/yah/0.8.21/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz.cert",
          "bins": ["yah", "yahh", "yahb", "yaha"]
        },
        "x86_64-apple-darwin": {
          "platform": "macos-x86_64",
          "filename": "yah-x86_64-apple-darwin.tar.gz",
          "url": "https://cdn.yah.dev/yah/0.8.21/x86_64-apple-darwin/yah-x86_64-apple-darwin.tar.gz",
          "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
          "size_bytes": 22,
          "sig_url": "https://cdn.yah.dev/yah/0.8.21/x86_64-apple-darwin/yah-x86_64-apple-darwin.tar.gz.sig",
          "cert_url": "https://cdn.yah.dev/yah/0.8.21/x86_64-apple-darwin/yah-x86_64-apple-darwin.tar.gz.cert",
          "bins": ["yah", "yahh", "yahb", "yaha"]
        },
        "x86_64-unknown-linux-gnu": {
          "platform": "linux-x86_64",
          "filename": "yah-x86_64-unknown-linux-gnu.tar.gz",
          "url": "https://cdn.yah.dev/yah/0.8.21/x86_64-unknown-linux-gnu/yah-x86_64-unknown-linux-gnu.tar.gz",
          "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
          "size_bytes": 33,
          "sig_url": "https://cdn.yah.dev/yah/0.8.21/x86_64-unknown-linux-gnu/yah-x86_64-unknown-linux-gnu.tar.gz.sig",
          "cert_url": "https://cdn.yah.dev/yah/0.8.21/x86_64-unknown-linux-gnu/yah-x86_64-unknown-linux-gnu.tar.gz.cert",
          "bins": ["yah", "yahh", "yahb", "yaha"]
        },
        "x86_64-unknown-linux-musl": {
          "platform": "linux-x86_64-musl",
          "filename": "yah-x86_64-unknown-linux-musl.tar.gz",
          "url": "https://cdn.yah.dev/yah/0.8.21/x86_64-unknown-linux-musl/yah-x86_64-unknown-linux-musl.tar.gz",
          "sha256": "4444444444444444444444444444444444444444444444444444444444444444",
          "size_bytes": 44,
          "sig_url": "https://cdn.yah.dev/yah/0.8.21/x86_64-unknown-linux-musl/yah-x86_64-unknown-linux-musl.tar.gz.sig",
          "cert_url": "https://cdn.yah.dev/yah/0.8.21/x86_64-unknown-linux-musl/yah-x86_64-unknown-linux-musl.tar.gz.cert",
          "bins": ["yah", "yahh", "yahb", "yaha"]
        },
        "aarch64-unknown-linux-musl": {
          "platform": "linux-aarch64-musl",
          "filename": "yah-aarch64-unknown-linux-musl.tar.gz",
          "url": "https://cdn.yah.dev/yah/0.8.21/aarch64-unknown-linux-musl/yah-aarch64-unknown-linux-musl.tar.gz",
          "sha256": "5555555555555555555555555555555555555555555555555555555555555555",
          "size_bytes": 55,
          "sig_url": "https://cdn.yah.dev/yah/0.8.21/aarch64-unknown-linux-musl/yah-aarch64-unknown-linux-musl.tar.gz.sig",
          "cert_url": "https://cdn.yah.dev/yah/0.8.21/aarch64-unknown-linux-musl/yah-aarch64-unknown-linux-musl.tar.gz.cert",
          "bins": ["yah", "yahh", "yahb", "yaha"]
        }
      }
    }"#;

    fn latest_feed() -> ReleaseFeed {
        feed_from_triples(serde_json::from_str(LATEST_JSON).unwrap())
    }

    #[test]
    fn install_pointer_becomes_a_one_entry_release() {
        let feed = latest_feed();
        assert_eq!(feed.releases.len(), 1, "latest.json is a single version");
        let rel = &feed.releases[0];
        assert_eq!(rel.version, "0.8.21");
        assert_eq!(rel.tag, "v0.8.21");
        assert_eq!(rel.published_at.to_rfc3339(), "2026-08-04T11:22:33+00:00");
        assert_eq!(rel.assets.len(), 5, "every published triple is downloadable");
    }

    #[test]
    fn producer_platform_tokens_keep_musl_and_gnu_apart() {
        // platform_from_triple() would map both x86_64 linux legs to
        // "linux-x86_64"; taking the producer's token keeps them distinct so
        // the page does not list two different binaries as one download.
        let feed = latest_feed();
        let platforms: Vec<&str> =
            feed.releases[0].assets.iter().map(|a| a.platform.as_str()).collect();
        assert!(platforms.contains(&"linux-x86_64"));
        assert!(platforms.contains(&"linux-x86_64-musl"));
        assert!(platforms.contains(&"linux-aarch64-musl"));
    }

    #[test]
    fn the_fragments_sha256_reaches_the_asset() {
        let feed = latest_feed();
        let mac = feed.releases[0]
            .assets
            .iter()
            .find(|a| a.platform == "macos-arm64")
            .expect("macos-arm64 asset");
        assert_eq!(mac.sha256.as_ref().map(|h| h.0.as_str()), Some("1".repeat(64).as_str()));
        assert_eq!(mac.blake3, None, "the CLI leg hashed with sha256sum, not b3sum");
        assert_eq!(mac.size_bytes, Some(11));
        assert_eq!(mac.filename, "yah-aarch64-apple-darwin.tar.gz");
        // R330-F40: a pre-tagging manifest still comes out of the feed with a
        // hash that states its own algorithm, rather than a bare hex value the
        // page has to infer one for.
        assert_eq!(mac.hash.as_ref().map(|h| h.to_string()), Some(format!("sha256:{}", "1".repeat(64))));
        assert_eq!(mac.bootstrap_hash, mac.hash);
    }

    // ── R330-F40: the tagged producer shape ─────────────────────────────────

    /// What `publish-cli` emits after R330-F40: blake3 identity + a tagged
    /// sha256 bootstrap aid, with the bare `sha256` retained for the copies of
    /// `install.sh` already in the wild.
    const LATEST_JSON_TAGGED: &str = r#"{
      "name": "yah",
      "version": "0.8.22",
      "pub_date": "2026-08-05T11:22:33Z",
      "triples": {
        "aarch64-apple-darwin": {
          "platform": "macos-arm64",
          "filename": "yah-aarch64-apple-darwin.tar.gz",
          "url": "https://cdn.yah.dev/yah/0.8.22/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz",
          "hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "bootstrap_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
          "size_bytes": 11,
          "sig_url": "https://cdn.yah.dev/yah/0.8.22/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz.sig",
          "cert_url": "https://cdn.yah.dev/yah/0.8.22/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz.cert",
          "bins": ["yah", "yahh", "yahb", "yaha"]
        }
      }
    }"#;

    #[test]
    fn a_tagged_manifest_yields_a_blake3_identity_and_a_sha256_bootstrap_aid() {
        let feed = feed_from_triples(serde_json::from_str(LATEST_JSON_TAGGED).unwrap());
        let asset = &feed.releases[0].assets[0];
        let hash = asset.hash.as_ref().expect("tagged identity");
        assert_eq!(hash.algo(), HashAlgo::Blake3, "blake3 is THE asset hash");
        assert_eq!(hash.hex(), "a".repeat(64));
        let boot = asset.bootstrap_hash.as_ref().expect("bootstrap aid");
        assert_eq!(boot.algo(), HashAlgo::Sha256);
        assert_eq!(boot.hex(), "1".repeat(64));
        // …and the bare mirrors an older consumer reads agree with both.
        assert_eq!(asset.blake3.as_ref().map(|h| h.0.as_str()), Some("a".repeat(64).as_str()));
        assert_eq!(asset.sha256.as_ref().map(|h| h.0.as_str()), Some("1".repeat(64).as_str()));
    }

    #[test]
    fn an_untagged_hash_field_fails_the_manifest_parse() {
        // The producer writing raw hex into `hash` is exactly the mistake this
        // ticket exists to make impossible. It must not reach the page.
        let json = LATEST_JSON_TAGGED.replace("blake3:aaa", "aaa");
        let err = match serde_json::from_str::<TriplesManifest>(&json) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an untagged `hash` must fail the parse, not reach the page"),
        };
        assert!(err.contains("bare hex"), "the parse must name the problem, got {err:?}");
    }

    #[test]
    fn the_feed_of_a_tagged_manifest_carries_no_new_untyped_hex() {
        // Guard (b) applied to the real producer shape rather than a synthetic
        // asset: only the two grandfathered legacy keys may be bare.
        let feed = feed_from_triples(serde_json::from_str(LATEST_JSON_TAGGED).unwrap());
        let value = serde_json::to_value(&feed).unwrap();
        assert_eq!(crate::feed::untyped_hash_fields(&value), Vec::<String>::new());
    }

    /// Byte-faithful copy of the `release-manifest.json` heredoc in
    /// `scripts/publish-desktop.sh` after R330-F40, down to the key order.
    /// A literal for the same reason [`LATEST_JSON`] is one: drift in the
    /// producer shows up here as a failing parse rather than in production.
    const DESKTOP_MANIFEST_TAGGED: &str = r#"{
  "version": "9.9.9",
  "pub_date": "2026-07-30T00:00:00Z",
  "notes": "yah 9.9.9",
  "host": {
    "bundle": {
      "aarch64-apple-darwin": {
        "url": "https://cdn.yah.dev/yah-desktop/releases/9.9.9/yah_9.9.9_aarch64.dmg",
        "hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bootstrap_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "blake3": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "size": 123456
      }
    }
  }
}"#;

    #[test]
    fn a_tagged_channel_manifest_reaches_the_asset() {
        let feed = feed_from_manifest(serde_json::from_str(DESKTOP_MANIFEST_TAGGED).unwrap());
        let asset = &feed.releases[0].assets[0];
        assert_eq!(asset.platform, "macos-arm64");
        assert_eq!(
            asset.hash.as_ref().map(|h| h.to_string()),
            Some(format!("blake3:{}", "a".repeat(64)))
        );
        assert_eq!(
            asset.bootstrap_hash.as_ref().map(|h| h.to_string()),
            Some(format!("sha256:{}", "b".repeat(64))),
            "the desktop leg now publishes a bootstrap aid too, tagged as one"
        );
        // The bare mirror is retained for pre-R330-F40 consumers.
        assert_eq!(asset.blake3.as_ref().map(|h| h.0.as_str()), Some("a".repeat(64).as_str()));
        // And nothing new arrived untagged.
        let value = serde_json::to_value(&feed).unwrap();
        assert_eq!(crate::feed::untyped_hash_fields(&value), Vec::<String>::new());
    }

    // ── R330-F38: the accumulating version index ────────────────────────────

    /// Byte-faithful copy of what the `cli-release-manifest` job's index-append
    /// step writes to `yah/index.json`. Held as a literal for the same reason
    /// [`LATEST_JSON`] is: drift in the producer surfaces here as a failing
    /// parse instead of as a blank page.
    ///
    /// Note what is NOT here: no bare `sha256`, no bare `blake3`. The index is
    /// tagged-only from its first byte — see [`the_index_is_tagged_only`].
    const INDEX_JSON: &str = r#"{
      "name": "yah",
      "schema": 1,
      "updated_at": "2026-08-05T11:22:33Z",
      "versions": [
        {
          "version": "0.8.22",
          "pub_date": "2026-08-05T11:22:33Z",
          "manifest_url": "https://cdn.yah.dev/yah/0.8.22/manifest.json",
          "triples": {
            "aarch64-apple-darwin": {
              "platform": "macos-arm64",
              "filename": "yah-aarch64-apple-darwin.tar.gz",
              "url": "https://cdn.yah.dev/yah/0.8.22/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz",
              "hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "bootstrap_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
              "size_bytes": 11,
              "sig_url": "https://cdn.yah.dev/yah/0.8.22/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz.sig",
              "cert_url": "https://cdn.yah.dev/yah/0.8.22/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz.cert",
              "bins": ["yah", "yahh", "yahb", "yaha"]
            },
            "x86_64-unknown-linux-gnu": {
              "platform": "linux-x86_64",
              "filename": "yah-x86_64-unknown-linux-gnu.tar.gz",
              "url": "https://cdn.yah.dev/yah/0.8.22/x86_64-unknown-linux-gnu/yah-x86_64-unknown-linux-gnu.tar.gz",
              "hash": "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
              "bootstrap_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
              "size_bytes": 33,
              "sig_url": "https://cdn.yah.dev/yah/0.8.22/x86_64-unknown-linux-gnu/yah-x86_64-unknown-linux-gnu.tar.gz.sig",
              "cert_url": "https://cdn.yah.dev/yah/0.8.22/x86_64-unknown-linux-gnu/yah-x86_64-unknown-linux-gnu.tar.gz.cert",
              "bins": ["yah", "yahh", "yahb", "yaha"]
            }
          }
        },
        {
          "version": "0.8.21",
          "pub_date": "2026-08-04T11:22:33Z",
          "manifest_url": "https://cdn.yah.dev/yah/0.8.21/manifest.json",
          "triples": {
            "aarch64-apple-darwin": {
              "platform": "macos-arm64",
              "filename": "yah-aarch64-apple-darwin.tar.gz",
              "url": "https://cdn.yah.dev/yah/0.8.21/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz",
              "hash": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              "bootstrap_hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
              "size_bytes": 22,
              "sig_url": "https://cdn.yah.dev/yah/0.8.21/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz.sig",
              "cert_url": "https://cdn.yah.dev/yah/0.8.21/aarch64-apple-darwin/yah-aarch64-apple-darwin.tar.gz.cert",
              "bins": ["yah", "yahh", "yahb", "yaha"]
            }
          }
        }
      ]
    }"#;

    fn index_feed() -> ReleaseFeed {
        feed_from_index(serde_json::from_str(INDEX_JSON).unwrap())
    }

    #[test]
    fn the_index_lists_every_version_newest_first() {
        // THE feature. `latest.json` is one version by construction, so the
        // page it fed was a one-entry list; this is the history it wanted.
        let feed = index_feed();
        let versions: Vec<&str> = feed.releases.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(versions, vec!["0.8.22", "0.8.21"], "newest first");
        assert_eq!(feed.releases[0].tag, "v0.8.22");
        assert_eq!(feed.releases[0].published_at.to_rfc3339(), "2026-08-05T11:22:33+00:00");
        // …and each version keeps its OWN per-triple downloads, which is what
        // makes the per-version links work rather than all aiming at latest.
        assert_eq!(feed.releases[0].assets.len(), 2);
        assert_eq!(feed.releases[1].assets.len(), 1);
        for release in &feed.releases {
            for asset in &release.assets {
                assert!(
                    asset.url.contains(&format!("/yah/{}/", release.version)),
                    "{} links to {} — a per-version link must not point at another version",
                    release.version,
                    asset.url
                );
            }
        }
    }

    #[test]
    fn every_index_asset_carries_a_tagged_blake3_identity() {
        let feed = index_feed();
        for release in &feed.releases {
            for asset in &release.assets {
                let hash = asset.hash.as_ref().expect("every index asset has an identity");
                assert_eq!(hash.algo(), HashAlgo::Blake3, "blake3 is THE asset hash");
                assert_eq!(
                    asset.bootstrap_hash.as_ref().map(|h| h.algo()),
                    Some(HashAlgo::Sha256)
                );
            }
        }
    }

    #[test]
    fn the_index_is_tagged_only() {
        // R330-F38's hard constraint, and the reason F40 was sequenced first.
        // The index is a PERMANENT accumulating record: a bare digest written
        // into it is bare forever. Unlike the install pointer it has no
        // in-the-wild consumer to grandfather, so it gets no entry in
        // LEGACY_BARE_HEX_PATHS — and this asserts the producer keeps its side.
        let doc: serde_json::Value = serde_json::from_str(INDEX_JSON).unwrap();
        assert_eq!(
            crate::feed::untyped_hash_fields(&doc),
            Vec::<String>::new(),
            "the index must carry no untagged digest at all"
        );
        for version in doc["versions"].as_array().unwrap() {
            for (triple, entry) in version["triples"].as_object().unwrap() {
                assert!(
                    entry.get("sha256").is_none() && entry.get("blake3").is_none(),
                    "{triple} in {} carries a legacy bare key; the index copies the \
                     pointer's entries MINUS those, and widening LEGACY_BARE_HEX_PATHS \
                     to admit them would invert that list's purpose",
                    version["version"],
                );
            }
        }
    }

    #[test]
    fn the_allowlist_does_not_reach_into_the_index() {
        // The other half of the property above: prove the grandfathered paths
        // are genuinely scoped away from the index rather than accidentally
        // covering it. `$.triples.*.sha256` excuses a bare digest in the
        // POINTER; the same key one level deeper in the index must be flagged.
        let hex = "e".repeat(64);
        let doc = serde_json::json!({
            "versions": [{ "triples": { "aarch64-apple-darwin": { "sha256": hex } } }]
        });
        assert_eq!(
            crate::feed::untyped_hash_fields(&doc),
            vec!["$.versions[0].triples.aarch64-apple-darwin.sha256"],
            "a bare digest in the index must be caught, not waved through by the \
             pointer's grandfathered path"
        );
    }

    #[test]
    fn an_untagged_index_hash_fails_the_parse() {
        let json = INDEX_JSON.replace("blake3:aaa", "aaa");
        let err = match serde_json::from_str::<IndexManifest>(&json) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an untagged index `hash` must fail the parse"),
        };
        assert!(err.contains("bare hex"), "the parse must name the problem, got {err:?}");
    }

    #[test]
    fn repeated_fetches_of_the_index_serialize_identically() {
        // Same change-detector property the single-version sources have, and it
        // matters more here: the index has BOTH a per-triple HashMap and a
        // multi-entry version list, so two orderings could wobble. An unstable
        // serialization fires a full rebuild + CDN purge on every tick.
        let a = serde_json::to_value(index_feed().releases).unwrap();
        let b = serde_json::to_value(index_feed().releases).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_mis_sorted_index_is_re_sorted_on_read() {
        // The producer sorts, but the reader does not take its word for it —
        // see feed_from_index. An index whose entries arrive oldest-first must
        // still render newest-first AND serialize identically to the sorted one,
        // or the page order depends on which way the producer last wrote it.
        let sorted = serde_json::to_value(index_feed().releases).unwrap();
        let mut doc: serde_json::Value = serde_json::from_str(INDEX_JSON).unwrap();
        doc["versions"].as_array_mut().unwrap().reverse();
        let reversed = feed_from_index(serde_json::from_value(doc).unwrap());
        assert_eq!(
            serde_json::to_value(reversed.releases).unwrap(),
            sorted,
            "read order must not depend on write order"
        );
    }

    #[test]
    fn an_empty_index_is_a_blank_page_not_a_failed_fetch() {
        // The state between "the index key exists" and "a release has been
        // appended". A hard parse failure here would read in the log as a
        // broken feed rather than an empty one.
        let feed = feed_from_index(serde_json::from_str(r#"{"name":"yah","versions":[]}"#).unwrap());
        assert!(feed.releases.is_empty());
    }

    #[test]
    fn the_index_source_maps_the_index_layout_and_refuses_the_pointer() {
        let cfg = SourceConfig::R2Index { url: "https://x/index.json".into(), id: None };
        let feed = feed_from_source_manifest(&cfg, INDEX_JSON).unwrap();
        assert_eq!(feed.releases.len(), 2);
        // Handing this feed the install POINTER must be a loud refusal: the
        // pointer has no `versions` key, so coercing it would silently publish
        // an empty history over a real one.
        let err = feed_from_source_manifest(&cfg, LATEST_JSON).unwrap_err();
        assert!(
            matches!(err, ManifestError::Shape { kind: "accumulating version index", .. }),
            "expected a shape error naming the layout, got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_missing_index_reports_the_status_not_a_decode_error() {
        // Same contract as the pointer: until the next tagged release appends,
        // yah/index.json 404s, and the operator's log must say so.
        let app = axum::Router::new()
            .fallback(|| async { (axum::http::StatusCode::NOT_FOUND, "<html>404</html>") });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        let url = format!("http://{addr}/yah/index.json");
        let err = R2Index::at_url(&url, "yah").fetch().await.unwrap_err();
        assert!(matches!(err, SourceError::Status { status, .. } if status == 404));
        assert!(err.to_string().contains(&url));
    }

    #[test]
    fn repeated_fetches_of_one_version_serialize_identically() {
        // The change-detector diffs the serialized `releases` array, and the
        // manifest's per-triple map is a HashMap — without the sort in
        // single_release_feed() the asset order would differ between these two
        // parses and every unchanged fetch would fire a full rebuild.
        let a = serde_json::to_value(&latest_feed().releases).unwrap();
        let b = serde_json::to_value(&latest_feed().releases).unwrap();
        assert_eq!(a, b, "an unchanged release must serialize byte-identically");
    }

    #[test]
    fn a_trimmed_entry_degrades_to_a_plain_download() {
        // url only: no platform, no filename, no hash, no size.
        let json = r#"{
          "version": "1.2.3", "pub_date": "2026-08-04T00:00:00Z",
          "triples": { "aarch64-apple-darwin": {
            "url": "https://cdn.yah.dev/yah/1.2.3/aarch64-apple-darwin/yah.tar.gz" } }
        }"#;
        let feed = feed_from_triples(serde_json::from_str(json).unwrap());
        let asset = &feed.releases[0].assets[0];
        assert_eq!(asset.platform, "macos-arm64", "derived from the triple key");
        assert_eq!(asset.filename, "yah.tar.gz", "derived from the url");
        assert_eq!(asset.sha256, None);
        assert_eq!(asset.size_bytes, None);
    }

    #[test]
    fn malformed_sha256_is_rejected_at_parse() {
        let json = LATEST_JSON.replace(&"1".repeat(64), "not-a-hash");
        assert!(
            serde_json::from_str::<TriplesManifest>(&json).is_err(),
            "a non-64-hex sha256 must fail the manifest parse, not reach the page"
        );
    }

    #[tokio::test]
    async fn a_missing_pointer_reports_the_status_not_a_decode_error() {
        // The live case today: cdn.yah.dev/yah/latest.json 404s until the next
        // tagged release runs `cli-release-manifest`. That must read as "404
        // Not Found from <url>" in the operator's log, NOT as reqwest's
        // "error decoding response body" — the misdiagnosis that hid this
        // feed's real (private-repo) failure for two months. See
        // `sources::decode_json`.
        let app = axum::Router::new().fallback(|| async {
            (axum::http::StatusCode::NOT_FOUND, "<html>404</html>")
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        let url = format!("http://{addr}/yah/latest.json");
        let err = R2Triples::at_url(&url, "yah").fetch().await.unwrap_err();

        assert!(
            matches!(err, SourceError::Status { status, .. } if status == 404),
            "expected a status-bearing error, got {err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("404"), "the reason must name the status: {msg}");
        assert!(msg.contains(&url), "the reason must name the URL: {msg}");
    }

    /// The producer-side seam must reproduce the fetch tier's answer exactly.
    /// If it did not, a poke carrying the payload would differ from what the
    /// sidecar writes on its next tick, and every release would render twice —
    /// once from the poke, once from the "change" the sidecar then detects.
    #[test]
    fn the_producer_mapping_equals_what_the_fetch_tier_would_have_written() {
        let via_source = feed_from_source_manifest(
            &SourceConfig::R2Manifest { url: "https://x/m.json".into(), id: None },
            MANIFEST,
        )
        .unwrap();
        let via_fetch = feed_from_manifest(serde_json::from_str(MANIFEST).unwrap());

        // `fetched_at` is a wall-clock stamp the change-detector ignores; the
        // `releases` array is the part that must agree.
        assert_eq!(
            serde_json::to_value(&via_source.releases).unwrap(),
            serde_json::to_value(&via_fetch.releases).unwrap(),
        );
    }

    #[test]
    fn the_triples_source_maps_the_install_pointer_layout() {
        let feed = feed_from_source_manifest(
            &SourceConfig::R2Triples { url: "https://x/latest.json".into(), id: None },
            LATEST_JSON,
        )
        .unwrap();
        assert_eq!(feed.releases[0].version, "0.8.21");
        assert_eq!(feed.releases[0].assets.len(), 5);
    }

    /// The whole reason the mapping is chosen by the *feed's* source rather
    /// than by the caller: `yah qed run release-build` writes the channel
    /// `host.bundle` layout, while the `releases` feed sources the
    /// install-pointer `triples` object. Handing one to the other must be a
    /// loud refusal, not a plausible-looking feed built from defaults — the
    /// producer degrades to a payload-less poke instead of publishing bytes
    /// the feed would never have produced.
    #[test]
    fn a_manifest_in_the_other_layout_is_refused_rather_than_coerced() {
        let err = feed_from_source_manifest(
            &SourceConfig::R2Triples { url: "https://x/latest.json".into(), id: None },
            MANIFEST,
        )
        .unwrap_err();
        assert!(
            matches!(err, ManifestError::Shape { kind: "install-pointer triples", .. }),
            "expected a shape error naming the layout, got {err:?}"
        );

        let err = feed_from_source_manifest(
            &SourceConfig::R2Manifest { url: "https://x/m.json".into(), id: None },
            LATEST_JSON,
        )
        .unwrap_err();
        assert!(matches!(err, ManifestError::Shape { kind: "channel host.bundle", .. }));
    }

    #[test]
    fn a_queried_source_has_no_manifest_to_carry() {
        let err = feed_from_source_manifest(
            &SourceConfig::GhReleases { repo: "yah-ai/yah".into() },
            MANIFEST,
        )
        .unwrap_err();
        assert!(matches!(err, ManifestError::NotManifestBacked("gh-releases")));
    }

    #[test]
    fn malformed_blake3_is_rejected_at_parse() {
        let json = MANIFEST.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "not-a-hash",
        );
        assert!(
            serde_json::from_str::<ChannelManifest>(&json).is_err(),
            "a non-64-hex blake3 must fail the manifest parse, not silently pass through"
        );
    }

    // ── R2Private: the authenticated, passthrough source (R707-F4) ──────────

    use std::sync::Arc;
    use yah_object_store::{InMemoryObjectStore, ObjectStore};

    const FLEET_INDEX: &str = r#"{
      "schema_version": 1,
      "source_commit": "6433bc76612da5faa88a41417a2f7ef009f28101",
      "generated_at": "2026-08-05T00:00:00Z",
      "machines": [{"name": "us-west-001", "region": "us-west"}]
    }"#;

    fn private_source_over(store: Arc<InMemoryObjectStore>) -> R2Private {
        R2Private::with_store("fleet", "yah-fleet", "fleet/index.json", store)
    }

    /// The point of the variant: almanac transports the consumer's own schema
    /// and adds nothing to it. A `ReleaseFeed` envelope here would mean the
    /// fleet index arrived at `PublishedIndexInventory` unparseable.
    #[tokio::test]
    async fn the_object_is_handed_on_verbatim_with_no_release_envelope() {
        let store = Arc::new(InMemoryObjectStore::new());
        store
            .put("fleet/index.json", FLEET_INDEX.as_bytes().to_vec())
            .unwrap();

        let payload = private_source_over(store).fetch_payload().await.unwrap();
        assert!(
            payload.releases().is_none(),
            "a fleet index is not a release list and must not be coerced into one"
        );
        let rendered = payload.to_json_pretty().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(
            parsed["source_commit"],
            "6433bc76612da5faa88a41417a2f7ef009f28101"
        );
        assert_eq!(parsed["machines"][0]["name"], "us-west-001");
    }

    /// R568-T7's failure, one layer up. A monitor handed an empty artifact
    /// renders a healthy, confident fleet of ZERO machines and the operator
    /// cannot tell that from a fleet that really is empty — so a key that is not
    /// there has to fail the run, loudly, naming the bucket and the key.
    #[tokio::test]
    async fn a_missing_key_errors_rather_than_emitting_an_empty_artifact() {
        let store = Arc::new(InMemoryObjectStore::new());
        let err = private_source_over(store).fetch_payload().await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("yah-fleet"), "names the bucket: {msg}");
        assert!(msg.contains("fleet/index.json"), "names the key: {msg}");
        assert!(msg.contains("no such key"), "says what happened: {msg}");
    }

    /// A 403 page, a truncated read, or an HTML error body must fail the fetch
    /// rather than be written to the artifact — the consumer's strictness cannot
    /// distinguish "we could not read it" from "we read it and it was junk" once
    /// the junk is on disk.
    #[tokio::test]
    async fn a_non_json_body_fails_the_fetch_instead_of_landing_in_the_artifact() {
        let store = Arc::new(InMemoryObjectStore::new());
        store
            .put(
                "fleet/index.json",
                b"<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code></Error>".to_vec(),
            )
            .unwrap();
        let err = private_source_over(store).fetch_payload().await.unwrap_err();
        assert!(err.to_string().contains("is not JSON"), "got: {err}");
    }

    /// The producer-side mapping refuses this source kind ON PURPOSE, and the
    /// distinction matters: `ManifestError::Shape` means "wrong layout, try
    /// another", while this means "never carry this payload in a poke body at
    /// all". `RevalidateHook` degrades to a payload-less poke either way, which
    /// is exactly the behaviour wanted here.
    #[test]
    fn a_private_source_never_carries_its_payload_in_a_poke() {
        let source = SourceConfig::R2Private {
            account_id: "acct".into(),
            bucket: "yah-fleet".into(),
            key: "fleet/index.json".into(),
            access_key_id: crate::config::CredentialRef::Env("A".into()),
            secret_access_key: crate::config::CredentialRef::Env("S".into()),
            endpoint: None,
            id: Some("fleet".into()),
        };
        assert!(matches!(
            feed_from_source_manifest(&source, FLEET_INDEX),
            Err(ManifestError::NotManifestBacked("r2-private"))
        ));
    }
}
