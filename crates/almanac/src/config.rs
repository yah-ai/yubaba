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
        /// `"owner/repo"`, e.g. `"yah-ai/yah"`.
        repo: String,
    },
    /// Public R2 release channel — reads `{base_url}/{binary}/release-manifest.json`.
    R2Channel {
        binary: String,
        /// Public-facing root URL (no trailing slash),
        /// e.g. `"https://releases.yah.dev"`.
        base_url: String,
    },
    /// Public manifest at an arbitrary URL, same `release-manifest.json` schema
    /// as [`SourceConfig::R2Channel`].
    ///
    /// Deliberately NOT a new schema. W059 §3 makes the manifest do double duty
    /// — self-update pointer *and* almanac source input — and a competing wire
    /// format would break that. This variant only lifts the *path* constraint:
    /// `R2Channel` can only address `{base_url}/{binary}/release-manifest.json`,
    /// which cannot express a content-addressed bucket layout.
    ///
    /// That layout works unchanged because the manifest's per-triple
    /// `host.bundle[..].url` entries are absolute: the blobs may live at hashed
    /// keys while only the manifest sits at a stable, overwritten key. The
    /// stable key is the *only* mutable object, which is what makes a single
    /// conditional GET a complete change-detector for the whole release.
    R2Manifest {
        /// Fully-qualified public URL of the manifest,
        /// e.g. `"https://releases.yah.dev/yah-desktop/manifest.json"`.
        url: String,
        /// Identifier used in logs. Defaults to the feed name when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// Public manifest in the *install-pointer* layout — the flat
    /// `{name, version, pub_date, triples: {<triple>: {...}}}` object the
    /// `cli-release-manifest` job publishes to
    /// `https://cdn.yah.dev/yah/latest.json` (`.github/workflows/release.yml`).
    ///
    /// A second shape rather than a normalization of the producer, and that
    /// direction is deliberate (R330-T32). That object is what
    /// `app/yah/web/marketing/public/install.sh` resolves the user's triple
    /// out of (`.triples[$t][$f]`), so it is a *published wire format with a
    /// live consumer* — rewriting it into [`SourceConfig::R2Manifest`]'s
    /// `host.bundle` layout would break `curl yah.dev/install.sh | sh` for
    /// everyone. Teaching almanac the shape that already ships keeps W059 §3's
    /// one-manifest-double-duty (self-update pointer *and* almanac input)
    /// without minting a third format.
    ///
    /// Supersedes `kind = "gh-releases"` for the `yah` CLI: the GitHub
    /// releases of `yah-ai/yah` are assets of a PRIVATE repo, so their download
    /// URLs 401 for the public and the source's unauthenticated fetch 404s
    /// outright. A public download page has to source artifacts from what we
    /// publish publicly, which is exactly this object.
    R2Triples {
        /// Fully-qualified public URL of the pointer object,
        /// e.g. `"https://cdn.yah.dev/yah/latest.json"`.
        url: String,
        /// Identifier used in logs. Defaults to the feed name when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// Public **accumulating version index** — the
    /// `{name, schema, updated_at, versions: [{version, pub_date, triples}]}`
    /// object the `cli-release-manifest` job maintains at
    /// `https://cdn.yah.dev/yah/index.json` (R330-F38).
    ///
    /// [`SourceConfig::R2Triples`] reads the install *pointer*, which is one
    /// version by construction — correct for "what does `install.sh` fetch
    /// right now", and a one-entry list on a page whose whole point is the
    /// history. This variant reads the index the same release job appends to,
    /// so `/releases` renders every published version from ONE fetch.
    ///
    /// It is a separate object rather than a prefix listing on purpose. Walking
    /// the versioned `yah/<version>/manifest.json` keys would need
    /// `ListObjectsV2` credentials at READ time, and the node tier deliberately
    /// holds none — materialize is unauthenticated by design. A single publicly
    /// readable object keeps the property the rest of this enum relies on: one
    /// conditional GET against one mutable key is a complete change-detector.
    ///
    /// The index is **tagged-hash-only** (R330-F40). It is a permanent,
    /// accumulating record, so a bare digest written into it is bare forever;
    /// unlike the install pointer it has no in-the-wild consumer to grandfather.
    /// Nothing about it appears in [`crate::feed::LEGACY_BARE_HEX_PATHS`], and
    /// that absence is the enforcement.
    R2Index {
        /// Fully-qualified public URL of the index object,
        /// e.g. `"https://cdn.yah.dev/yah/index.json"`.
        url: String,
        /// Identifier used in logs. Defaults to the feed name when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// **Credential-gated** R2 object, fetched with a SigV4-signed S3 `GET` and
    /// written to the artifact **verbatim** (R707-F4, W295 §Gap 2).
    ///
    /// Every other variant above fetches over anonymous HTTP, and that is not an
    /// accident of implementation — it is the releases feed's stated design:
    /// *"materialize is unauthenticated by design"*, *"the node tier
    /// deliberately holds none"* (see [`SourceConfig::R2Index`]). This variant
    /// is the inversion of exactly that one property, and nothing else: same
    /// envelope, same webhook cadence, same one-mutable-object change-detector.
    ///
    /// It exists because a published *fleet* index names machines, mesh IPs,
    /// `mesh_tags` and hostkey fingerprints — a map of the attack surface, which
    /// cannot live at a public URL the way `cdn.yah.dev/yah/index.json`
    /// deliberately does. So the object sits in a bucket with no public custom
    /// domain and the consumer authenticates. Do **not** route the public feeds
    /// through here to share code: an anonymous fetch that silently gained a
    /// credential requirement would break the public path the first time a
    /// credential expired, and the public path is the one with users on it.
    ///
    /// ## Why the payload is passed through instead of mapped
    ///
    /// The variants above all normalize a release manifest into
    /// [`crate::feed::ReleaseFeed`], because their consumer is a release page
    /// and almanac owns that schema. This one's consumer owns its own
    /// (`yah_fleet_metrics::FleetIndex`, whose publisher and reader are pinned
    /// to one another by a round-trip test), so almanac transports the bytes and
    /// stays out of the schema entirely — see
    /// [`crate::sources::FeedPayload::Passthrough`]. The one thing it does
    /// enforce is that the body parses as JSON, so a 403 error page or a
    /// truncated read fails the run instead of landing in the artifact.
    ///
    /// ## Credentials are references, never values
    ///
    /// A feed TOML is git-tracked. `account_id` is a plain string because it
    /// already is one in `.yah/infra/providers/cloudflare.toml`; the key pair is
    /// a [`CredentialRef`] the deploy layer satisfies.
    R2Private {
        /// Cloudflare account id — the subdomain in
        /// `<account_id>.r2.cloudflarestorage.com`. Not a secret: it is
        /// committed in `.yah/infra/providers/cloudflare.toml` today.
        account_id: String,
        /// Bucket holding the object. Must be one with **no public custom
        /// domain** — that is the property being relied on.
        bucket: String,
        /// Object key, e.g. `"fleet/index.json"`.
        key: String,
        /// Read half of an S3 key pair scoped to `bucket`.
        access_key_id: CredentialRef,
        /// Secret half of the same pair.
        secret_access_key: CredentialRef,
        /// Override the derived `https://<account_id>.r2.cloudflarestorage.com`
        /// — the pond tier's MinIO, or a test's stub. Same knob
        /// `yah_object_store::R2ObjectStore::with_endpoint` exposes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
        /// Identifier used in logs. Defaults to the feed name when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
}

/// Where an authenticated [`SourceConfig`] reads one credential component from.
///
/// **Never the value itself.** A feed TOML is git-tracked, and an authenticated
/// feed exists precisely because its object must not be world-readable — a
/// literal key written here would publish the thing the credential protects, to
/// the same audience, in the same repo.
///
/// Both forms are references the *deploy* layer satisfies, which is why there is
/// no third "inline" variant to reach for. W294's cluster-secret rail already
/// delivers a declared secret as either a tmpfs-backed file
/// (`[target] kind = "file"`) or an environment variable (`kind = "env-var"`),
/// and this enum is those two and nothing more. Prefer `file`, for the reason
/// that rail states on its own `EnvVar` arm: env vars leak through subprocess
/// environments and log dumps.
///
/// ```toml
/// access_key_id     = { file = "/run/secrets/fleet-r2-access-key-id" }
/// secret_access_key = { env  = "YAH_FLEET_R2_SECRET_KEY" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialRef {
    /// Read from a process environment variable, by name.
    Env(String),
    /// Read the file's contents (trimmed). The shape W294's secret rail prefers.
    File(PathBuf),
}

impl CredentialRef {
    /// Resolve to the credential value.
    ///
    /// Trailing whitespace is trimmed: a secret written by `echo`, or shipped by
    /// a rail that newline-terminates, must not resolve to a key that differs by
    /// one byte from the one that was stored — an S3 signature failure gives no
    /// hint that the cause was a `\n`.
    ///
    /// `component` names which credential failed. Errors carry the *reference*
    /// (a variable name or a path) and never the value, so they are safe to log.
    pub fn resolve(&self, component: &str) -> Result<String, String> {
        let raw = match self {
            Self::Env(name) => std::env::var(name).map_err(|_| {
                format!("{component}: environment variable {name} is unset or not valid UTF-8")
            })?,
            Self::File(path) => std::fs::read_to_string(path)
                .map_err(|e| format!("{component}: reading {} failed: {e}", path.display()))?,
        };
        let value = raw.trim();
        if value.is_empty() {
            // An empty credential otherwise reaches the edge as a signature
            // mismatch, which reads as "the wrong key" rather than "no key".
            return Err(match self {
                Self::Env(name) => format!("{component}: environment variable {name} is empty"),
                Self::File(path) => format!("{component}: {} is empty", path.display()),
            });
        }
        Ok(value.to_string())
    }
}

/// What event fires a revalidation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TriggerConfig {
    /// A QED hook or GitHub webhook POSTs to `/revalidate` with `{"feed":"<name>"}`.
    Webhook,
    /// Almanac receiver fires on a UTC cron schedule (yubaba cron, TBD).
    Cron { expression: String },
}

/// What to do after a successful fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmitConfig {
    /// Path (relative to project root) where `ReleaseFeed` JSON is written.
    /// e.g. `"app/yah/web/src/data/releases.json"`.
    pub artifact: String,
    /// Downstream action when the artifact changes — **and the feed's mirror
    /// binding**, which is why it is only nominally optional.
    ///
    /// `Option` here reads as "a feed that just materializes an artifact needs
    /// no action", and that is true of the *action* half. It is not true of the
    /// other half: [`crate::receiver`]'s binding gate reads `on_change.service`
    /// to answer *whose feed is this*, and rejects a feed with no `on_change`
    /// with `422 UNPROCESSABLE_ENTITY` before it ever runs (R335-F3). So any
    /// feed reachable by `POST /revalidate` must carry one, even when there is
    /// nothing to rebuild — that is what [`OnChangeConfig::Reload`] is for.
    ///
    /// Leaving it `None` is correct only for a feed driven purely by
    /// [`crate::fetch::FeedFetcher`]'s timer, which has no receiver in front of
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_change: Option<OnChangeConfig>,
}

/// Downstream action triggered after the artifact is written.
///
/// Every variant names a `service`, and that field does double duty: it is the
/// action's target *and* the mirror binding [`crate::receiver`] authorizes
/// against (see [`EmitConfig::on_change`]).
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
    /// **The artifact is the product.** Rewriting it *is* the action; live
    /// consumers re-read it. Nothing is rebuilt and no route is rendered.
    ///
    /// This is not a rendering variant that happens to render nothing — it
    /// exists for the *authorization* half of `on_change` (W295 §Gap 1). A feed
    /// whose consumer reads the emitted file directly (the fleet index, read by
    /// `yah_fleet_metrics::PublishedIndexInventory`) has no route to rebuild,
    /// and the obvious simplification — omit `on_change` entirely, since it is
    /// an `Option` — produces exactly the shape the receiver's binding gate
    /// `422`s. So the feed declares a `reload` naming the service that owns it,
    /// and the gate has the grain it needs.
    ///
    /// Do **not** "simplify" this by making `on_change` optional at the
    /// receiver: that deletes the cross-mirror-pollution gate for every feed,
    /// to save one enum arm on this one.
    ///
    /// ## Before adding a second non-rendering feed, apply this test
    ///
    /// This arm makes almanac usable for things that are not release pages, so
    /// it is also the thing that could turn almanac into the hammer. The
    /// discriminator is [`crate::coalesce`]'s own invariant: almanac is safe
    /// exactly when the source is **absolute** — a fetch returns the complete
    /// current state — and the `/revalidate` POST carries nothing but a feed
    /// name. Then conflating N triggers into one run loses nothing, which is the
    /// property the coalescer is built on. If the **payload** carries the change
    /// (a delta), almanac is not merely overkill, it is *unsafe*: coalescing two
    /// deltas drops one, and a plain endpoint is the correct tool. The fleet
    /// index is one object holding the whole fleet and its ping is empty, which
    /// is what makes it the archetype rather than a stretch.
    ///
    /// The reload itself is a no-op by construction on both dispatch paths, and
    /// deliberately so:
    ///
    /// - [`crate::runner::FeedRunner`] has already written the artifact by the
    ///   time this is returned. A consumer that reads the file per request
    ///   (cloud-admin is stateless per render) is refreshed the moment the write
    ///   lands; there is nothing left to tell it.
    /// - `cloud::dispatch_on_change` therefore logs and returns `Ok`. A consumer
    ///   that ever needs an explicit in-process nudge should get it from the
    ///   process embedding [`crate::serve::run`], not from the control-plane
    ///   reconciler, which cannot reach into someone else's address space.
    Reload {
        /// Service id (from `.yah/services/<id>/service.toml`) that owns this
        /// feed — e.g. `"yah-cloud-admin"`. The mirror binding.
        service: String,
    },
}

impl OnChangeConfig {
    /// The service this feed is bound to — the grain
    /// [`crate::receiver`]'s authorization gate compares against its own
    /// identity. Every variant has one; a variant that could not name a service
    /// would be unroutable through the receiver.
    pub fn service(&self) -> &str {
        match self {
            Self::MesofactRebuild { service, .. } | Self::Reload { service } => service,
        }
    }
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
    fn load_r2_manifest_feed_at_an_arbitrary_url() {
        let tmp = TempDir::new().unwrap();
        write_feed(
            tmp.path(),
            "desktop",
            r#"
[feed]
name = "desktop"

[feed.source]
kind = "r2-manifest"
url = "https://releases.yah.dev/yah-desktop/manifest.json"
id = "yah-desktop"

[feed.trigger]
kind = "webhook"

[feed.emit]
artifact = "app/yah/web/marketing/src/data/releases.json"
on_change = { kind = "mesofact-rebuild", service = "yah-marketing", route = "/releases" }
"#,
        );
        let loader = FeedLoader::new(tmp.path());
        let cfg = loader.load("desktop").unwrap();
        match cfg.feed.source {
            SourceConfig::R2Manifest { ref url, ref id } => {
                assert_eq!(url, "https://releases.yah.dev/yah-desktop/manifest.json");
                assert_eq!(id.as_deref(), Some("yah-desktop"));
            }
            ref other => panic!("expected R2Manifest, got {other:?}"),
        }
        assert!(cfg.feed.emit.on_change.is_some());
    }

    #[test]
    fn r2_manifest_id_is_optional() {
        let tmp = TempDir::new().unwrap();
        write_feed(
            tmp.path(),
            "d2",
            r#"
[feed]
name = "d2"

[feed.source]
kind = "r2-manifest"
url = "https://cdn.example/m.json"

[feed.trigger]
kind = "webhook"

[feed.emit]
artifact = "out.json"
"#,
        );
        let cfg = FeedLoader::new(tmp.path()).load("d2").unwrap();
        assert!(matches!(
            cfg.feed.source,
            SourceConfig::R2Manifest { ref id, .. } if id.is_none()
        ));
    }

    #[test]
    fn load_r2_triples_feed() {
        // Mirrors the shipped .yah/almanac/releases.toml.
        let tmp = TempDir::new().unwrap();
        write_feed(
            tmp.path(),
            "releases",
            r#"
[feed]
name = "releases"

[feed.source]
kind = "r2-triples"
url = "https://cdn.yah.dev/yah/latest.json"
id = "yah"

[feed.trigger]
kind = "webhook"

[feed.emit]
artifact = "app/yah/web/marketing/src/data/releases.json"

[feed.emit.on_change]
kind = "mesofact-rebuild"
service = "yah-marketing"
route = "/releases"
"#,
        );
        let cfg = FeedLoader::new(tmp.path()).load("releases").unwrap();
        match cfg.feed.source {
            SourceConfig::R2Triples { ref url, ref id } => {
                assert_eq!(url, "https://cdn.yah.dev/yah/latest.json");
                assert_eq!(id.as_deref(), Some("yah"));
            }
            ref other => panic!("expected R2Triples, got {other:?}"),
        }
        assert!(cfg.feed.emit.on_change.is_some());
    }

    #[test]
    fn load_r2_index_feed() {
        // Mirrors the shipped .yah/almanac/releases.toml after R330-F38.
        let tmp = TempDir::new().unwrap();
        write_feed(
            tmp.path(),
            "releases",
            r#"
[feed]
name = "releases"

[feed.source]
kind = "r2-index"
url = "https://cdn.yah.dev/yah/index.json"
id = "yah"

[feed.trigger]
kind = "webhook"

[feed.emit]
artifact = "app/yah/web/marketing/src/data/releases.json"

[feed.emit.on_change]
kind = "mesofact-rebuild"
service = "yah-marketing"
route = "/releases"
"#,
        );
        let cfg = FeedLoader::new(tmp.path()).load("releases").unwrap();
        match cfg.feed.source {
            SourceConfig::R2Index { ref url, ref id } => {
                assert_eq!(url, "https://cdn.yah.dev/yah/index.json");
                assert_eq!(id.as_deref(), Some("yah"));
            }
            ref other => panic!("expected R2Index, got {other:?}"),
        }
    }

    #[test]
    fn the_shipped_releases_feed_parses() {
        // Guards the real file, not a copy of it: a kind rename in config.rs
        // that forgot .yah/almanac/releases.toml would leave the /releases page
        // silently un-fed, which is exactly the failure R330-T32 was opened for.
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("almanac lives at <root>/oss/yubaba/crates/almanac");
        let almanac_dir = repo_root.join(".yah/almanac");
        if !almanac_dir.join("releases.toml").exists() {
            // Exported standalone (no yah monorepo around it) — nothing to guard.
            return;
        }
        let cfg = FeedLoader::new(&almanac_dir).load("releases").unwrap();
        assert!(
            matches!(cfg.feed.source, SourceConfig::R2Index { .. }),
            "releases.toml must source the accumulating index (R330-F38). \
             gh-releases cannot work at all against the private yah-ai/yah repo \
             (R330-T32), and r2-triples reads the single-version install pointer, \
             which renders /releases as a one-entry list"
        );
    }

    // ── the authenticated source + render-free reload (R707-F4) ─────────────

    #[test]
    fn load_r2_private_feed() {
        // Mirrors the shipped .yah/almanac/fleet.toml.
        let tmp = TempDir::new().unwrap();
        write_feed(
            tmp.path(),
            "fleet",
            r#"
[feed]
name = "fleet"

[feed.source]
kind = "r2-private"
account_id = "3948dc292e724e71b0deefde0ea95999"
bucket = "yah-fleet"
key = "fleet/index.json"
id = "fleet"
access_key_id = { file = "/run/secrets/fleet-r2-access-key-id" }
secret_access_key = { file = "/run/secrets/fleet-r2-secret-key" }

[feed.trigger]
kind = "webhook"

[feed.emit]
artifact = ".yah/infra/state/fleet-index.json"

[feed.emit.on_change]
kind = "reload"
service = "yah-cloud-admin"
"#,
        );
        let cfg = FeedLoader::new(tmp.path()).load("fleet").unwrap();
        match cfg.feed.source {
            SourceConfig::R2Private {
                ref bucket,
                ref key,
                ref access_key_id,
                ref endpoint,
                ..
            } => {
                assert_eq!(bucket, "yah-fleet");
                assert_eq!(key, "fleet/index.json");
                assert!(matches!(access_key_id, CredentialRef::File(_)));
                assert!(endpoint.is_none(), "endpoint is the pond/test override");
            }
            ref other => panic!("expected R2Private, got {other:?}"),
        }
        match cfg.feed.emit.on_change {
            Some(OnChangeConfig::Reload { ref service }) => {
                assert_eq!(service, "yah-cloud-admin")
            }
            ref other => panic!("expected a reload on_change, got {other:?}"),
        }
    }

    /// Both `on_change` variants answer "whose feed is this". The receiver's
    /// binding gate reads exactly this, so a variant added without a `service`
    /// would be unroutable — the accessor is what makes that impossible to
    /// forget.
    #[test]
    fn every_on_change_variant_names_its_binding_service() {
        assert_eq!(
            OnChangeConfig::MesofactRebuild {
                service: "yah-marketing".into(),
                route: "/releases".into(),
            }
            .service(),
            "yah-marketing"
        );
        assert_eq!(
            OnChangeConfig::Reload { service: "yah-cloud-admin".into() }.service(),
            "yah-cloud-admin"
        );
    }

    /// A credential is a REFERENCE. If a value could be written inline the
    /// git-tracked feed file would publish the thing the credential protects.
    #[test]
    fn a_bare_string_credential_is_rejected_rather_than_read_as_a_value() {
        let tmp = TempDir::new().unwrap();
        write_feed(
            tmp.path(),
            "oops",
            r#"
[feed]
name = "oops"
[feed.source]
kind = "r2-private"
account_id = "acct"
bucket = "b"
key = "k"
access_key_id = "AKIAREALKEYPASTEDINLINE"
secret_access_key = { env = "S" }
[feed.trigger]
kind = "webhook"
[feed.emit]
artifact = "out.json"
"#,
        );
        assert!(matches!(
            FeedLoader::new(tmp.path()).load("oops"),
            Err(ConfigError::Toml { .. })
        ));
    }

    #[test]
    fn credential_ref_reads_a_file_and_trims_the_trailing_newline() {
        // `echo secret > file` and every secret rail that newline-terminates
        // would otherwise produce a key one byte off, which reaches the edge as
        // an unexplained signature mismatch.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("key");
        fs::write(&path, "abc123\n").unwrap();
        assert_eq!(
            CredentialRef::File(path).resolve("access_key_id").unwrap(),
            "abc123"
        );
    }

    #[test]
    fn an_empty_credential_file_is_an_error_not_an_empty_key() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("key");
        fs::write(&path, "   \n").unwrap();
        let err = CredentialRef::File(path.clone())
            .resolve("secret_access_key")
            .unwrap_err();
        assert!(err.contains("secret_access_key"), "names the component: {err}");
        assert!(err.contains("is empty"), "says what is wrong: {err}");
    }

    #[test]
    fn a_missing_credential_names_the_reference_and_never_a_value() {
        let err = CredentialRef::Env("YAH_TEST_DEFINITELY_UNSET_R707".into())
            .resolve("access_key_id")
            .unwrap_err();
        assert!(err.contains("YAH_TEST_DEFINITELY_UNSET_R707"), "got: {err}");
        assert!(err.contains("access_key_id"), "got: {err}");
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
