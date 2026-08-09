//! Publish beacon — the object that makes "did the front door actually get
//! the bytes I just published?" a question with an answer.
//!
//! ## Why this exists
//!
//! `yah.dev` froze twice, nineteen days apart, by two unrelated mechanisms,
//! and both times every signal on the path was green. A declared-but-unready
//! bundle tier silently disabled the static publish chain (R330-B43); later
//! the apex was cut over to a sovereign origin whose bytes nothing
//! republishes (R703-B4). In both failures `yah cloud apply` exited 0, the
//! R2 objects were correct, and `curl https://yah.dev/releases` returned
//! HTTP 200 — with a page months out of date. Nothing in the pipeline ever
//! compared *what was published* against *what the front door serves*,
//! because no artifact existed that could be compared.
//!
//! The beacon is that artifact. Every publish writes
//! `<prefix>/.well-known/yah-publish.json` carrying a digest over the exact
//! key→sha256 set that was uploaded, plus the wall-clock time. It is written
//! **last**, so its presence also means the publish ran to completion.
//! Fetching it back through a front door and comparing digests turns a
//! silent stale-serve into a failed apply that names both URLs.
//!
//! ## The two probes
//!
//! - **Origin** (`asset_origin`, e.g. `https://cdn.yah.dev/yah-marketing/cloud`)
//!   — did the bytes reach the bucket at the prefix the front door reads?
//! - **Front door** (`https://<zone>`) — does the thing the public hits
//!   actually serve that prefix? This is the probe that was missing; it is
//!   the only one that can catch an apex pointed somewhere else entirely.
//!
//! [`classify`] is pure so the interesting cases are unit-testable without a
//! network; [`probe`] is the thin HTTP wrapper around it, and [`check_serving`]
//! is the whole two-probe verdict both serving tiers share.
//!
//! ## Two tiers, one beacon (R703-T7)
//!
//! The R2 static chain publishes mutable objects at fixed keys, so its beacon
//! is written by the publish itself ([`PublishBeacon::new`], wall-clocked).
//! The W272 bundle tier serves a *content-addressed* unit from a node behind a
//! passway apex — it reads no R2 prefix, so it had nothing to answer the
//! front-door probe with and the check could only ever fail there. A bundle
//! therefore carries its beacon as a bundle entry at [`BUNDLE_BEACON_PATH`],
//! stamped by [`stamp_bundle`], and `mesofact serve` answers the same
//! `/.well-known/yah-publish.json` GET out of the bundle it materialized.
//!
//! @arch:layer(infra)
//! @arch:role(verification)
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//!
//! Part of R703-B4 — annotation in .yah/docs/working/W267-sovereign-public-ingress.md

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use yah_mesofact_bundle::{BundleHash, BundleManifest};

use crate::config::{DomainConfig, FrontDoor};

/// Object key (relative to the mirror's publish prefix) the beacon is written
/// to. Dotted last segment on purpose: the Worker's clean-URL fallback only
/// fires for extensionless paths, so this never takes the `.html` detour.
pub const BEACON_KEY: &str = ".well-known/yah-publish.json";

/// Bundle path a W272 bundle carries its beacon at (R703-T7).
///
/// `mesofact serve` points `Server::from_workload` at `<bundle>/app` and serves
/// `dist/html/` from there, so this is the one bundle entry that answers a GET
/// for `/{BEACON_KEY}` at the apex. Pinned against [`BEACON_KEY`] by a test —
/// the two must stay one URL.
pub const BUNDLE_BEACON_PATH: &str = "app/dist/html/.well-known/yah-publish.json";

/// What a publish claims it put in the bucket.
///
/// `digest` is the load-bearing field: a sha256 over every `key\0sha256`
/// line of the uploaded set, sorted, so it changes if and only if the served
/// content changes. `published_at` is for humans reading a failure message —
/// "the front door is serving something from three weeks ago" is a far more
/// actionable sentence than a digest mismatch alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishBeacon {
    /// R2 key prefix this publish wrote under, e.g. `yah-marketing/cloud`; for
    /// a bundle stamp, `bundle/<name>` (see [`bundle_prefix`]).
    pub prefix: String,
    /// RFC3339 wall-clock time of the publish, or `None` for a content-addressed
    /// bundle stamp that deliberately has no clock in it — see
    /// [`PublishBeacon::for_bundle`]. Read it through
    /// [`PublishBeacon::published_label`] rather than unwrapping.
    #[serde(default)]
    pub published_at: Option<String>,
    /// sha256 over the sorted `key\0content-sha256` set. See [`digest_of`].
    pub digest: String,
    /// How many objects the digest covers.
    pub files: usize,
}

impl PublishBeacon {
    /// Build a beacon for the key→sha256 map a publish just wrote.
    pub fn new(prefix: &str, contents: &BTreeMap<String, String>) -> Self {
        Self {
            prefix: prefix.trim_end_matches('/').to_string(),
            published_at: Some(chrono::Utc::now().to_rfc3339()),
            digest: digest_of(contents),
            files: contents.len(),
        }
    }

    /// Build the beacon a **W272 bundle** carries as one of its own entries
    /// (R703-T7). `contents` is the bundle's `path → blake3` map with the
    /// beacon entry itself excluded.
    ///
    /// Deliberately clock-free, which is the one way it differs from
    /// [`PublishBeacon::new`]. The stamp is a file *inside* the unit being
    /// content-addressed, so a wall clock would flip the bundle digest on every
    /// assembly — breaking W272 §1 immutability, the blob-dedupe that makes a
    /// re-publish a no-op, and the `assembly_is_deterministic` invariant the CLI
    /// pins. Nothing is lost: for a mutable R2 prefix the timestamp is the only
    /// way to say "three weeks stale", but a bundle's digest already names the
    /// exact immutable unit being served.
    pub fn for_bundle(name: &str, contents: &BTreeMap<String, String>) -> Self {
        Self {
            prefix: bundle_prefix(name),
            published_at: None,
            digest: digest_of(contents),
            files: contents.len(),
        }
    }

    /// How to render `published_at` in a message. A bundle stamp says so rather
    /// than printing an empty slot a reader would take for a bug.
    pub fn published_label(&self) -> &str {
        self.published_at
            .as_deref()
            .unwrap_or("(content-addressed bundle — no publish clock)")
    }
}

/// The `prefix` label a bundle stamp carries. Not an R2 key prefix — a bundle
/// publishes as content-addressed blobs — but the failure message reads
/// "N files under <prefix>", and naming the bundle is what makes that useful.
pub fn bundle_prefix(name: &str) -> String {
    format!("bundle/{name}")
}

/// Stable digest over a published key→content-sha256 map.
///
/// `BTreeMap` iteration is already sorted, which is what makes this stable
/// across runs that upload the same set in a different order.
pub fn digest_of(contents: &BTreeMap<String, String>) -> String {
    let mut h = Sha256::new();
    for (key, hash) in contents {
        h.update(key.as_bytes());
        h.update([0u8]);
        h.update(hash.as_bytes());
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

/// What a front door (or origin) came back with when asked for the beacon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServedState {
    /// Serving exactly what was published.
    Match,
    /// Serving a real beacon, but an older one — the classic stale front door.
    Stale { served: PublishBeacon },
    /// Answered 2xx, but not with a beacon. Almost always means the URL is
    /// being handled by something that 200s everything (an SPA shell, a
    /// branded-404-at-200 handler), which is exactly the shape that hid the
    /// last two freezes.
    NotABeacon { status: u16, body_preview: String },
    /// Non-2xx. The front door does not serve this prefix at all.
    Missing { status: u16 },
    /// Never got an answer.
    Unreachable { error: String },
}

impl ServedState {
    pub fn is_match(&self) -> bool {
        matches!(self, ServedState::Match)
    }

    /// One line for a log or an error message.
    pub fn summary(&self) -> String {
        match self {
            ServedState::Match => "OK (digest matches)".to_string(),
            ServedState::Stale { served } => format!(
                "STALE — serving digest {} published {} ({} files)",
                short(&served.digest),
                served.published_label(),
                served.files
            ),
            ServedState::NotABeacon {
                status,
                body_preview,
            } => format!("HTTP {status} but not a publish beacon: {body_preview}"),
            ServedState::Missing { status } => format!("HTTP {status}"),
            ServedState::Unreachable { error } => format!("unreachable: {error}"),
        }
    }
}

fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
}

/// Decide what a response means. Pure — no I/O — so every branch is testable.
///
/// `body` is only inspected for 2xx; a non-2xx response body is whatever the
/// front door's error page happens to be and carries no signal.
pub fn classify(status: u16, body: &[u8], expected: &PublishBeacon) -> ServedState {
    if !(200..300).contains(&status) {
        return ServedState::Missing { status };
    }
    match serde_json::from_slice::<PublishBeacon>(body) {
        Ok(served) if served.digest == expected.digest => ServedState::Match,
        Ok(served) => ServedState::Stale { served },
        Err(_) => ServedState::NotABeacon {
            status,
            body_preview: preview(body),
        },
    }
}

fn preview(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let flat: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let trimmed = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.chars().count() > 120 {
        format!("{}…", trimmed.chars().take(120).collect::<String>())
    } else if trimmed.is_empty() {
        "<empty body>".to_string()
    } else {
        trimmed
    }
}

/// Full URL the beacon is fetched from for a given base.
pub fn beacon_url(base: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), BEACON_KEY)
}

/// Fetch the beacon from `base` once and classify the answer.
pub async fn probe(base: &str, expected: &PublishBeacon) -> ServedState {
    let url = beacon_url(base);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ServedState::Unreachable {
                error: e.to_string(),
            }
        }
    };
    // `Cache-Control: no-cache` is a request the edge may decline, but it
    // costs nothing and removes the most common source of a false STALE.
    let resp = client
        .get(&url)
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .send()
        .await;
    match resp {
        Err(e) => ServedState::Unreachable {
            error: e.to_string(),
        },
        Ok(r) => {
            let status = r.status().as_u16();
            match r.bytes().await {
                Ok(body) => classify(status, &body, expected),
                Err(e) => ServedState::Unreachable {
                    error: e.to_string(),
                },
            }
        }
    }
}

/// [`probe`], retried while the answer is wrong.
///
/// A publish takes effect at an edge over seconds, not instantly, so a single
/// probe would make this check flaky in exactly the way that gets a check
/// deleted. Only non-matching answers are retried; a match returns at once.
pub async fn probe_with_retry(
    base: &str,
    expected: &PublishBeacon,
    attempts: u32,
    delay: Duration,
) -> ServedState {
    let mut last = ServedState::Unreachable {
        error: "no attempts made".to_string(),
    };
    for attempt in 0..attempts.max(1) {
        if attempt > 0 {
            tokio::time::sleep(delay).await;
        }
        last = probe(base, expected).await;
        if last.is_match() {
            return last;
        }
        tracing::debug!(
            url = %beacon_url(base),
            attempt = attempt + 1,
            state = %last.summary(),
            "publish beacon not yet served"
        );
    }
    last
}

/// The domain manifest that claims this zone, if one does.
///
/// Returned as `(manifest name, declared front door)` purely so a failure can
/// say *which file to edit*. A zone with no manifest is not an error here —
/// plenty of publishes target a zone this repo does not route.
pub fn declared_front_door(workspace_root: &Path, zone: &str) -> Option<(String, FrontDoor)> {
    let dir = workspace_root.join(".yah").join("domains");
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        // A manifest that fails validation is someone else's error to report;
        // skip it rather than turning a serving check into a config check.
        if let Ok(dom) = DomainConfig::load(&path) {
            if dom.domain.eq_ignore_ascii_case(zone) {
                return Some((dom.name.clone(), dom.front_door));
            }
        }
    }
    None
}

/// Which URL to probe as "the front door" for a zone, if any.
///
/// `None` means the zone has no front door distinct from its origin: a
/// `bucket-direct` domain *is* the R2 custom domain, so `https://<zone>` is
/// the bucket root and the site lives under the publish prefix. Probing the
/// bare zone there would 404 and report a fault that does not exist.
///
/// A zone with no manifest still gets probed. Absence of a manifest is not
/// evidence of a bucket-direct shape, and the whole class of bug being fixed
/// here is a front door nobody wrote down.
pub fn front_door_probe_url(zone: &str, declared: Option<&FrontDoor>) -> Option<String> {
    match declared {
        Some(FrontDoor::BucketDirect) => None,
        _ => Some(format!("https://{zone}")),
    }
}

/// The message a stale or absent front door produces.
///
/// Deliberately long. The failure it describes has now happened twice and
/// both times the expensive part was not the fix but working out *which of
/// three identical-looking causes* it was, so the message names the commands
/// that tell them apart.
pub fn serving_failure(
    zone: &str,
    front_door_url: &str,
    front_door_state: &ServedState,
    origin_url: &str,
    origin_state: &ServedState,
    expected: &PublishBeacon,
    declared: Option<(String, FrontDoor)>,
) -> anyhow::Error {
    let declared_line = match declared {
        Some((name, fd)) => format!("{} (.yah/domains/{}.toml)", fd.as_str(), name),
        None => format!("none — no .yah/domains manifest claims {zone}"),
    };
    let origin_beacon = beacon_url(origin_url);
    let front_door_beacon = beacon_url(front_door_url);
    anyhow::anyhow!(
        "published bytes are not being served at {zone}\n\
         \n\
         \x20 published      : digest {} at {} ({} files under {})\n\
         \x20 declared door  : {}\n\
         \x20 origin         : {} -> {}\n\
         \x20 front door     : {} -> {}\n\
         \n\
         The publish itself may well have succeeded — what failed is that the \
         public front door for this zone is serving something other than the \
         prefix this apply wrote to. This exact shape (green apply, HTTP 200, \
         a months-old page) froze yah.dev twice; it is a hard error so it \
         cannot do so a third time.\n\
         \n\
         To tell the causes apart:\n\
         \x20 scripts/cf-inspect-zone.sh {zone}   # what actually terminates the apex\n\
         \x20 scripts/cf-apex-mode.sh status      # worker / grey / orange\n\
         \x20 curl -sI {}   # is the object even in the bucket\n\
         \n\
         If a front-door migration is deliberately in flight, set \
         `verify_serving = false` in the mirror's [providers.static] block and \
         name the ticket in a comment — do not delete this check.",
        short(&expected.digest),
        expected.published_label(),
        expected.files,
        expected.prefix,
        declared_line,
        origin_beacon,
        origin_state.summary(),
        front_door_beacon,
        front_door_state.summary(),
        origin_beacon,
    )
}

// ── W272 bundle stamp (R703-T7) ──────────────────────────────────────────────

/// The beacon a given bundle manifest does (or would) carry.
///
/// Pure, and a total function of the manifest — which is what makes the stamp
/// recomputable. The sync arm reads the beacon back off the stamped manifest
/// with this rather than threading it out of the assembler through five
/// call sites, and gets a value identical to the bytes on disk because
/// [`PublishBeacon::for_bundle`] carries no clock.
///
/// Any existing stamp entry is excluded, so this is stable under re-stamping.
pub fn bundle_beacon(manifest: &BundleManifest) -> PublishBeacon {
    let contents: BTreeMap<String, String> = manifest
        .content
        .iter()
        .filter(|(path, _)| path.as_str() != BUNDLE_BEACON_PATH)
        .map(|(path, hash)| (path.clone(), hash.as_str().to_string()))
        .collect();
    PublishBeacon::for_bundle(&manifest.name, &contents)
}

/// Stamp a publish beacon into an already-assembled W272 bundle tree.
///
/// Writes `<bundle_dir>/{BUNDLE_BEACON_PATH}`, adds it to `manifest.content`,
/// and rewrites `manifest.toml`, so the tree stays internally consistent and
/// the bundle digest the caller then computes covers the stamp. Returns the
/// beacon so the sync arm can probe for exactly these bytes.
///
/// **After assembly, not inside it**: the stamp's contents are a function of
/// every other entry's hash, which only exists once the assembler has walked
/// them. The digest therefore covers every entry *except* the stamp — the same
/// self-exclusion the R2 arm has (its beacon key is never in the publish
/// manifest either), and not an optimisation: a digest covering itself has no
/// fixed point.
///
/// Idempotent. Re-stamping drops any prior stamp before hashing, so a bundle
/// assembled twice from identical inputs is byte-identical both times.
pub fn stamp_bundle(
    bundle_dir: &Path,
    manifest: &mut BundleManifest,
) -> anyhow::Result<PublishBeacon> {
    let beacon = bundle_beacon(manifest);
    manifest.content.remove(BUNDLE_BEACON_PATH);

    let bytes = serde_json::to_vec(&beacon).context("serializing bundle publish beacon")?;
    let out = bundle_dir.join(BUNDLE_BEACON_PATH);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;

    manifest
        .content
        .insert(BUNDLE_BEACON_PATH.to_string(), BundleHash::of(&bytes));
    let toml = manifest
        .to_toml_string()
        .context("re-serializing bundle manifest after stamping the publish beacon")?;
    let manifest_path = bundle_dir.join("manifest.toml");
    std::fs::write(&manifest_path, toml)
        .with_context(|| format!("rewriting {}", manifest_path.display()))?;

    Ok(beacon)
}

// ── the shared two-probe verdict (R703-T7) ───────────────────────────────────

/// What both probes said, kept as data so the caller can act on a mismatch
/// before turning it into an error.
///
/// [`serving_failure`] wants seven arguments that are all decided here;
/// carrying them together is what let the bundle tier reuse the static tier's
/// check instead of growing a second, drifting copy of it.
#[derive(Debug, Clone)]
pub struct ServingVerdict {
    pub zone: String,
    pub front_door_url: String,
    pub front_door: ServedState,
    pub origin_url: String,
    pub origin: ServedState,
    pub declared: Option<(String, FrontDoor)>,
}

impl ServingVerdict {
    /// True only when every reader probed is serving the published bytes.
    pub fn is_ok(&self) -> bool {
        self.front_door.is_match() && self.origin.is_match()
    }

    /// The long, deliberately-specific failure this verdict describes.
    pub fn into_error(self, expected: &PublishBeacon) -> anyhow::Error {
        serving_failure(
            &self.zone,
            &self.front_door_url,
            &self.front_door,
            &self.origin_url,
            &self.origin,
            expected,
            self.declared,
        )
    }
}

/// Probe budget for a publish that lands at a CDN edge: propagation is
/// seconds-shaped, and a single probe would make the check flaky in exactly the
/// way that gets a check deleted.
pub const EDGE_PROBE_ATTEMPTS: u32 = 4;
/// Delay between [`EDGE_PROBE_ATTEMPTS`].
pub const EDGE_PROBE_DELAY: Duration = Duration::from_secs(5);

/// Probe budget for a publish that lands on a serving node: the node has to
/// fetch the new blobs, materialize the bundle tree, and kamaji has to restart
/// the serve process behind the apex. That is minutes-shaped, so a budget sized
/// for a CDN edge would report a stale front door for a deploy that was merely
/// still in progress — a false hard failure, which is how a real check earns a
/// reputation for lying and gets switched off.
pub const NODE_PROBE_ATTEMPTS: u32 = 20;
/// Delay between [`NODE_PROBE_ATTEMPTS`].
pub const NODE_PROBE_DELAY: Duration = Duration::from_secs(6);

/// The `(origin, front door)` URL pair [`check_serving`] probes. Pure, so the
/// three collapses below are testable without a network.
///
/// Both readers get a URL in every case; when a tier has only one reader the
/// pair collapses onto it and the probe runs once. The pair is never empty —
/// see [`check_serving`] for why a skip is not an option.
pub fn probe_urls(
    zone: &str,
    origin: Option<&str>,
    declared: Option<&FrontDoor>,
) -> (String, String) {
    let door = front_door_probe_url(zone, declared);
    let origin_url = match (origin, &door) {
        // The static chain: an R2 prefix a reader can hit directly.
        (Some(o), _) => o.to_string(),
        // The bundle tier: the node behind the door is the only reader.
        (None, Some(d)) => d.clone(),
        // No R2 prefix AND a bucket-direct manifest is a contradiction — a
        // bundle-served zone has no bucket. Probe the apex rather than skip: a
        // check that silently switches itself off is the bug this file exists
        // to prevent.
        (None, None) => format!("https://{zone}"),
    };
    // `bucket-direct` (no door distinct from the origin) is the mirror image of
    // the bundle case: the origin doubles as the door.
    let front_door_url = door.unwrap_or_else(|| origin_url.clone());
    (origin_url, front_door_url)
}

/// Probe a zone's front door — and its origin, where it has one distinct from
/// the door — for the beacon a publish just wrote.
///
/// `origin` is `Some(asset_origin)` for the R2 static chain, where the bucket
/// prefix is a second reader worth distinguishing: "the publish did not land"
/// and "the publish landed and the front door is elsewhere" are different
/// tickets with identical symptoms. It is `None` for the W272 bundle tier,
/// where the serving node behind the apex is the only reader there is, so the
/// door doubles as the origin. A `bucket-direct` zone is the mirror image of
/// that (the origin doubles as the door) and has always collapsed the same way.
pub async fn check_serving(
    workspace_root: &Path,
    zone: &str,
    origin: Option<&str>,
    expected: &PublishBeacon,
    attempts: u32,
    delay: Duration,
) -> ServingVerdict {
    let declared = declared_front_door(workspace_root, zone);
    let (origin_url, front_door_url) =
        probe_urls(zone, origin, declared.as_ref().map(|(_, fd)| fd));

    let origin_state = probe_with_retry(&origin_url, expected, attempts, delay).await;
    let front_door_state = if front_door_url == origin_url {
        origin_state.clone()
    } else {
        probe_with_retry(&front_door_url, expected, attempts, delay).await
    };

    ServingVerdict {
        zone: zone.to_string(),
        front_door_url,
        front_door: front_door_state,
        origin_url,
        origin: origin_state,
        declared,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon() -> PublishBeacon {
        let mut c = BTreeMap::new();
        c.insert(
            "yah-marketing/cloud/index.html".to_string(),
            "aa".repeat(32),
        );
        c.insert(
            "yah-marketing/cloud/releases.html".to_string(),
            "bb".repeat(32),
        );
        PublishBeacon::new("yah-marketing/cloud", &c)
    }

    #[test]
    fn digest_is_order_independent_and_content_sensitive() {
        let mut a = BTreeMap::new();
        a.insert("b.html".to_string(), "2".to_string());
        a.insert("a.html".to_string(), "1".to_string());
        let mut b = BTreeMap::new();
        b.insert("a.html".to_string(), "1".to_string());
        b.insert("b.html".to_string(), "2".to_string());
        assert_eq!(digest_of(&a), digest_of(&b));

        let mut changed = b.clone();
        changed.insert("a.html".to_string(), "1x".to_string());
        assert_ne!(digest_of(&b), digest_of(&changed));

        // A key rename with identical bytes must also move the digest: the
        // served URL set is part of what we are asserting, not just content.
        let mut renamed = b.clone();
        renamed.remove("a.html");
        renamed.insert("a2.html".to_string(), "1".to_string());
        assert_ne!(digest_of(&b), digest_of(&renamed));
    }

    /// Field separators matter: without them `{"ab" -> "c"}` and
    /// `{"a" -> "bc"}` would hash identically.
    #[test]
    fn digest_separates_key_from_hash() {
        let mut a = BTreeMap::new();
        a.insert("ab".to_string(), "c".to_string());
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), "bc".to_string());
        assert_ne!(digest_of(&a), digest_of(&b));
    }

    #[test]
    fn matching_beacon_classifies_as_match() {
        let expected = beacon();
        let body = serde_json::to_vec(&expected).unwrap();
        assert_eq!(classify(200, &body, &expected), ServedState::Match);
    }

    #[test]
    fn older_beacon_classifies_as_stale_and_names_its_date() {
        let expected = beacon();
        let old = PublishBeacon {
            prefix: expected.prefix.clone(),
            published_at: Some("2026-07-15T09:00:00Z".to_string()),
            digest: "cc".repeat(32),
            files: 9,
        };
        let body = serde_json::to_vec(&old).unwrap();
        let state = classify(200, &body, &expected);
        match &state {
            ServedState::Stale { served } => assert_eq!(served.published_at, old.published_at),
            other => panic!("expected Stale, got {other:?}"),
        }
        assert!(
            state.summary().contains("2026-07-15"),
            "{}",
            state.summary()
        );
    }

    /// The failure mode this whole module exists for: HTTP 200 with a page
    /// instead of the beacon. Must never be read as success.
    #[test]
    fn two_hundred_with_html_is_not_a_match() {
        let expected = beacon();
        let state = classify(200, b"<!doctype html><title>yah</title>", &expected);
        assert!(!state.is_match());
        match state {
            ServedState::NotABeacon { status, .. } => assert_eq!(status, 200),
            other => panic!("expected NotABeacon, got {other:?}"),
        }
    }

    #[test]
    fn non_2xx_is_missing_and_does_not_inspect_the_body() {
        let expected = beacon();
        // A styled 404 page that happens to contain valid beacon JSON must
        // still be Missing — the status is the answer.
        let body = serde_json::to_vec(&expected).unwrap();
        assert_eq!(
            classify(404, &body, &expected),
            ServedState::Missing { status: 404 }
        );
    }

    #[test]
    fn beacon_url_is_prefix_joined_without_double_slash() {
        assert_eq!(
            beacon_url("https://cdn.yah.dev/yah-marketing/cloud/"),
            "https://cdn.yah.dev/yah-marketing/cloud/.well-known/yah-publish.json"
        );
        assert_eq!(
            beacon_url("https://yah.dev"),
            "https://yah.dev/.well-known/yah-publish.json"
        );
    }

    /// The beacon key must not be extensionless, or the Worker's clean-URL
    /// fallback would go looking for `yah-publish.json.html`.
    #[test]
    fn beacon_key_last_segment_has_an_extension() {
        let last = BEACON_KEY.rsplit('/').next().unwrap();
        assert!(last.contains('.'), "BEACON_KEY last segment: {last}");
    }

    #[test]
    fn beacon_round_trips_through_json() {
        let b = beacon();
        let bytes = serde_json::to_vec(&b).unwrap();
        assert_eq!(serde_json::from_slice::<PublishBeacon>(&bytes).unwrap(), b);
    }

    #[test]
    fn declared_front_door_finds_the_manifest_for_a_zone() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".yah").join("domains");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("yah-dev.toml"),
            r#"schema_version = 1
name = "yah-dev"
domain = "yah.dev"
front_door = "passway"
cdn_bucket = "yah-dev"

[[routes]]
path = "/*"
mode = "static"
component = "yah-marketing/site"
"#,
        )
        .unwrap();

        let found = declared_front_door(tmp.path(), "yah.dev").unwrap();
        assert_eq!(found.0, "yah-dev");
        assert_eq!(found.1, FrontDoor::Passway);
        assert!(declared_front_door(tmp.path(), "example.com").is_none());
    }

    #[test]
    fn bucket_direct_has_no_front_door_distinct_from_its_origin() {
        assert_eq!(
            front_door_probe_url("cdn.yah.dev", Some(&FrontDoor::BucketDirect)),
            None
        );
        assert_eq!(
            front_door_probe_url("yah.dev", Some(&FrontDoor::Worker)),
            Some("https://yah.dev".to_string())
        );
        assert_eq!(
            front_door_probe_url("yah.dev", Some(&FrontDoor::Passway)),
            Some("https://yah.dev".to_string())
        );
        // An unrouted zone is still probed — an undeclared front door is
        // exactly the case this check exists to catch.
        assert_eq!(
            front_door_probe_url("yah.dev", None),
            Some("https://yah.dev".to_string())
        );
    }

    #[test]
    fn serving_failure_names_both_urls_and_the_manifest() {
        let expected = beacon();
        let err = serving_failure(
            "yah.dev",
            "https://yah.dev",
            &ServedState::Missing { status: 404 },
            "https://cdn.yah.dev/yah-marketing/cloud",
            &ServedState::Match,
            &expected,
            Some(("yah-dev".to_string(), FrontDoor::Passway)),
        )
        .to_string();
        assert!(
            err.contains("https://yah.dev/.well-known/yah-publish.json"),
            "{err}"
        );
        assert!(err.contains("cdn.yah.dev/yah-marketing/cloud"), "{err}");
        assert!(err.contains(".yah/domains/yah-dev.toml"), "{err}");
        assert!(err.contains("passway"), "{err}");
        assert!(err.contains("verify_serving"), "{err}");
    }

    // ── W272 bundle stamp (R703-T7) ─────────────────────────────────────────

    fn bundle_manifest() -> BundleManifest {
        let mut content = BTreeMap::new();
        content.insert(
            "app/dist/html/index.html".to_string(),
            BundleHash::of(b"<html>home</html>"),
        );
        content.insert(
            "app/dist/html/releases.html".to_string(),
            BundleHash::of(b"<html>releases</html>"),
        );
        BundleManifest {
            schema_version: yah_mesofact_bundle::SCHEMA_VERSION,
            name: "yah-marketing".to_string(),
            runtime: yah_mesofact_bundle::BundleRuntime::SelfContained,
            content,
        }
    }

    /// The bundle stamp and the R2 object must answer the SAME public URL, or
    /// the front-door probe is checking two different things per tier.
    #[test]
    fn the_bundle_stamp_answers_the_same_url_as_the_r2_beacon() {
        assert!(
            BUNDLE_BEACON_PATH.ends_with(BEACON_KEY),
            "{BUNDLE_BEACON_PATH}"
        );
        // `mesofact serve` serves <bundle>/app/dist/html/ at the apex root, so
        // stripping that prefix must leave exactly the public path.
        assert_eq!(
            BUNDLE_BEACON_PATH.strip_prefix("app/dist/html/"),
            Some(BEACON_KEY)
        );
    }

    #[test]
    fn stamp_bundle_writes_the_beacon_and_records_it_in_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = bundle_manifest();
        let beacon = stamp_bundle(dir.path(), &mut manifest).unwrap();

        // On disk at the served path, and parseable as the beacon a probe reads.
        let bytes = std::fs::read(dir.path().join(BUNDLE_BEACON_PATH)).unwrap();
        assert_eq!(classify(200, &bytes, &beacon), ServedState::Match);

        // In the manifest, hashed, so materialize verifies it like any entry.
        assert_eq!(
            manifest.content.get(BUNDLE_BEACON_PATH),
            Some(&BundleHash::of(&bytes))
        );
        // And manifest.toml on disk agrees with the mutated manifest, so the
        // digest the caller computes next covers the stamp.
        let text = std::fs::read_to_string(dir.path().join("manifest.toml")).unwrap();
        assert_eq!(BundleManifest::from_toml_str(&text).unwrap(), manifest);

        assert_eq!(beacon.prefix, "bundle/yah-marketing");
        assert_eq!(beacon.files, 2, "the stamp excludes itself");

        // Recomputable from the STAMPED manifest — this is what lets the sync
        // arm probe for the right bytes without the assembler handing it out.
        assert_eq!(bundle_beacon(&manifest), beacon);
    }

    /// The stamp's digest must cover every OTHER entry and nothing else — a
    /// digest over itself has no fixed point, and one that missed a file would
    /// let that file go stale invisibly.
    #[test]
    fn the_stamp_digest_covers_the_rest_of_the_bundle_and_not_itself() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = bundle_manifest();
        let beacon = stamp_bundle(dir.path(), &mut manifest).unwrap();

        let expected: BTreeMap<String, String> = bundle_manifest()
            .content
            .iter()
            .map(|(k, h)| (k.clone(), h.as_str().to_string()))
            .collect();
        assert_eq!(beacon.digest, digest_of(&expected));

        // Change one served file → the stamp moves.
        let mut changed = bundle_manifest();
        changed.content.insert(
            "app/dist/html/index.html".to_string(),
            BundleHash::of(b"<html>edited</html>"),
        );
        let dir2 = tempfile::tempdir().unwrap();
        let moved = stamp_bundle(dir2.path(), &mut changed).unwrap();
        assert_ne!(beacon.digest, moved.digest);
    }

    /// W272 §1: identical inputs must produce an identical bundle. The stamp is
    /// an entry in that bundle, so it has to be clock-free — otherwise every
    /// `yah cloud apply` would flip the digest and re-materialize an unchanged
    /// site on the node. Re-stamping must also drop the prior stamp rather than
    /// fold it into the digest.
    #[test]
    fn stamping_is_deterministic_and_idempotent() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let mut a = bundle_manifest();
        let mut b = bundle_manifest();
        let beacon_a = stamp_bundle(a_dir.path(), &mut a).unwrap();
        let beacon_b = stamp_bundle(b_dir.path(), &mut b).unwrap();

        assert_eq!(beacon_a, beacon_b);
        assert_eq!(a.digest(), b.digest());
        assert!(beacon_a.published_at.is_none(), "no clock in a bundle stamp");

        // Re-stamp in place: same bytes, same digest.
        let digest_once = a.digest();
        let beacon_again = stamp_bundle(a_dir.path(), &mut a).unwrap();
        assert_eq!(beacon_again, beacon_a);
        assert_eq!(a.digest(), digest_once);
    }

    /// A clock-free beacon must still round-trip, and must never render as a
    /// blank a reader would take for a bug.
    #[test]
    fn a_bundle_stamp_round_trips_and_says_it_has_no_clock() {
        let mut m = bundle_manifest();
        let dir = tempfile::tempdir().unwrap();
        let beacon = stamp_bundle(dir.path(), &mut m).unwrap();
        let bytes = serde_json::to_vec(&beacon).unwrap();
        assert_eq!(
            serde_json::from_slice::<PublishBeacon>(&bytes).unwrap(),
            beacon
        );
        assert!(beacon.published_label().contains("content-addressed"));

        let stale = ServedState::Stale {
            served: beacon.clone(),
        };
        assert!(stale.summary().contains("content-addressed"), "{}", stale.summary());
    }

    // ── probe-url collapse (R703-T7) ────────────────────────────────────────

    #[test]
    fn a_static_publish_probes_its_prefix_and_its_apex_separately() {
        let (origin, door) = probe_urls(
            "yah.dev",
            Some("https://cdn.yah.dev/yah-marketing/cloud"),
            Some(&FrontDoor::Passway),
        );
        assert_eq!(origin, "https://cdn.yah.dev/yah-marketing/cloud");
        assert_eq!(door, "https://yah.dev");
        assert_ne!(origin, door, "two distinct readers → two probes");
    }

    /// The bundle tier reads no R2 prefix: the node behind the apex is the only
    /// reader, so both slots collapse onto the apex and it is probed once.
    #[test]
    fn a_bundle_publish_probes_only_its_apex() {
        let (origin, door) = probe_urls("yah.dev", None, Some(&FrontDoor::Passway));
        assert_eq!(origin, "https://yah.dev");
        assert_eq!(door, origin);
    }

    /// `bucket-direct` is the mirror image — the origin IS the door.
    #[test]
    fn a_bucket_direct_zone_collapses_onto_its_origin() {
        let (origin, door) = probe_urls(
            "cdn.yah.dev",
            Some("https://cdn.yah.dev/svc/cloud"),
            Some(&FrontDoor::BucketDirect),
        );
        assert_eq!(origin, "https://cdn.yah.dev/svc/cloud");
        assert_eq!(door, origin);
    }

    /// A bundle tier on a bucket-direct manifest is a contradiction. It must
    /// still probe the apex — never silently pass with nothing checked.
    #[test]
    fn a_contradictory_declaration_still_probes_something() {
        let (origin, door) = probe_urls("yah.dev", None, Some(&FrontDoor::BucketDirect));
        assert_eq!(origin, "https://yah.dev");
        assert_eq!(door, origin);
    }

    #[test]
    fn a_verdict_is_ok_only_when_every_reader_matches() {
        let mk = |front: ServedState, origin: ServedState| ServingVerdict {
            zone: "yah.dev".into(),
            front_door_url: "https://yah.dev".into(),
            front_door: front,
            origin_url: "https://cdn.yah.dev/x".into(),
            origin,
            declared: None,
        };
        assert!(mk(ServedState::Match, ServedState::Match).is_ok());
        assert!(!mk(ServedState::Missing { status: 404 }, ServedState::Match).is_ok());
        assert!(!mk(ServedState::Match, ServedState::Missing { status: 404 }).is_ok());

        let err = mk(ServedState::Missing { status: 404 }, ServedState::Match)
            .into_error(&beacon())
            .to_string();
        assert!(err.contains("https://yah.dev/.well-known/yah-publish.json"), "{err}");
    }

    #[test]
    fn serving_failure_says_so_when_no_manifest_claims_the_zone() {
        let err = serving_failure(
            "example.com",
            "https://example.com",
            &ServedState::Missing { status: 404 },
            "https://cdn.example.com/svc/cloud",
            &ServedState::Match,
            &beacon(),
            None,
        )
        .to_string();
        assert!(
            err.contains("no .yah/domains manifest claims example.com"),
            "{err}"
        );
    }
}
