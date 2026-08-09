use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
pub use workload_spec::{BlakeHash, License};

// ── Typed asset hashes (R330-F40) ────────────────────────────────────────────
//
// POLICY, in the operator's words: one asset hash across the whole yah
// ecosystem, and every hash explicitly TYPED in metadata rather than bare —
// because the thing to avoid at all costs is a mess of random hex values that
// nobody knows don't align because the algo is wrong.
//
// Those are not two competing rules. The first is the policy; the second is the
// mechanism that makes the first survivable. BLAKE3 is THE yah asset hash —
// canonical identity, matching xlb, the blob store, kg ids and the desktop
// updater's `blake3:<hex>` blob refs. SHA-256 is a *bootstrap-verification aid*
// for the public `curl | sh` path and nothing else: a bare POSIX box has three
// ways to check sha256 (`sha256sum`, `shasum -a 256`, `openssl dgst`) and zero
// to check blake3, so verifying blake3 there would mean downloading an
// unverified `b3sum` to verify with. Both are emitted; both carry their tag; a
// consumer therefore never has to *guess* which algorithm it is holding, which
// is exactly the failure mode the policy exists to prevent.

/// The hash algorithms the yah ecosystem publishes, and the roles they play.
///
/// A closed set on purpose: a manifest carrying an algorithm nobody here knows
/// about fails the parse instead of reaching a consumer that would silently
/// compare it against the wrong digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgo {
    /// **The** yah asset hash — canonical content identity, ecosystem-wide.
    Blake3,
    /// Bootstrap-verification aid for the POSIX `curl | sh` installer. Never
    /// identity: nothing internal should key off it.
    Sha256,
}

impl HashAlgo {
    /// The wire tag, i.e. the part before the `:` in `blake3:abc…`.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
        }
    }

    /// The command a human runs to check this hash themselves — what the
    /// marketing /releases card prints next to the digest.
    pub const fn verify_tool(self) -> &'static str {
        match self {
            Self::Blake3 => "b3sum",
            Self::Sha256 => "shasum -a 256",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "blake3" => Some(Self::Blake3),
            "sha256" => Some(Self::Sha256),
            _ => None,
        }
    }
}

impl std::fmt::Display for HashAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.tag())
    }
}

/// Why a string is not a valid tagged asset hash.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HashParseError {
    /// The single most important variant: a value that *is* a digest but says
    /// nothing about which algorithm produced it. Rejecting this is what makes
    /// bare hex unrepresentable in [`AssetHash`].
    #[error(
        "asset hash {0:?} is bare hex with no algorithm tag — write it as \
         `blake3:<64 hex>` (identity) or `sha256:<64 hex>` (bootstrap aid)"
    )]
    Untagged(String),
    #[error("unknown hash algorithm {0:?} — yah publishes `blake3` (identity) and `sha256` (bootstrap aid)")]
    UnknownAlgo(String),
    #[error("{algo} digest must be exactly 64 hex digits, got {hex:?}")]
    BadDigest { algo: HashAlgo, hex: String },
}

/// A hash that carries its own algorithm, so no consumer ever has to infer one
/// from a field name.
///
/// Wire form is a single string, `"<algo>:<64 lowercase hex>"` — deliberately
/// not a nested object. That shape survives every consumer this ecosystem has:
/// POSIX `sh` splits it with `${h#*:}`, `jq` reads it with no nested access,
/// the TS page destructures it with one `split(":")`, and serde parses it
/// straight into this type. The desktop updater manifest already uses exactly
/// this form for its blob refs (`crates/yah/updater/src/manifest.rs` `BlobRef`).
///
/// Fields are private and there is no bare-hex constructor: the only ways in
/// are [`AssetHash::parse`] (which demands a tag) and the per-algorithm
/// constructors (which name the algorithm at the call site). That is guard (a)
/// of R330-F40 — bare hex is not merely discouraged, it is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetHash {
    algo: HashAlgo,
    hex: String,
}

impl AssetHash {
    /// Build from an explicitly-named algorithm plus a bare digest.
    ///
    /// Bare hex is fine as an *argument* — the caller has just named the
    /// algorithm — it is only bare hex as a *value* that this type forbids.
    pub fn new(algo: HashAlgo, hex: impl Into<String>) -> Result<Self, HashParseError> {
        let hex = hex.into();
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(HashParseError::BadDigest { algo, hex });
        }
        Ok(Self { algo, hex: hex.to_ascii_lowercase() })
    }

    /// The canonical yah asset hash.
    pub fn blake3(hex: impl Into<String>) -> Result<Self, HashParseError> {
        Self::new(HashAlgo::Blake3, hex)
    }

    /// The `curl | sh` bootstrap-verification aid. Not an identity.
    pub fn sha256(hex: impl Into<String>) -> Result<Self, HashParseError> {
        Self::new(HashAlgo::Sha256, hex)
    }

    /// Parse the `<algo>:<hex>` wire form. An untagged 64-hex string is an
    /// error, not a guess.
    pub fn parse(s: &str) -> Result<Self, HashParseError> {
        let Some((tag, hex)) = s.split_once(':') else {
            return Err(HashParseError::Untagged(s.to_string()));
        };
        let algo = HashAlgo::from_tag(tag).ok_or_else(|| HashParseError::UnknownAlgo(tag.into()))?;
        Self::new(algo, hex)
    }

    pub fn algo(&self) -> HashAlgo {
        self.algo
    }

    /// The bare digest, for the one place that legitimately needs it: comparing
    /// against the output of a hashing tool. Named so that reaching for it is a
    /// visible decision.
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

impl std::fmt::Display for AssetHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algo.tag(), self.hex)
    }
}

impl Serialize for AssetHash {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for AssetHash {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// The exact locations where a bare-hex digest predating R330-F40 is still
/// written for backward compatibility — scoped by PATH, not by key name.
///
/// Key-name scoping was the first cut and it was too weak: `"sha256"` as a bare
/// name grandfathers a bare digest under that name *at any depth, anywhere in
/// the document*, and a new nested field reusing one of these very ordinary
/// names is the single most likely shape for the drift this guard exists to
/// catch. Pinning each entry to the one path where the legacy key legitimately
/// lives means a bare `blake3` appearing somewhere new is flagged instead of
/// waved through.
///
/// Pattern syntax: `.` separates segments, a `*` segment matches any single key
/// (the target-triple map keys), and a `[*]` suffix matches any array index.
///
/// Every entry is here because something outside this repo reads it:
/// `sha256` in the install pointer is read by every copy of
/// `app/yah/web/marketing/public/install.sh` already in the wild, and `blake3`
/// in the channel manifest by any almanac deployment older than this change.
/// They stay until those age out. Deleting an entry here is what *arms*
/// [`untyped_hash_fields`] against that location — the transition ends by
/// shrinking this list, not by remembering to.
pub const LEGACY_BARE_HEX_PATHS: &[&str] = &[
    // Normalized feed (`ReleaseFeed`) — the bare mirrors on each asset.
    "$.releases[*].assets[*].blake3",
    "$.releases[*].assets[*].sha256",
    // Install-pointer manifest (`yah/latest.json`, `mesofact/latest.json`).
    "$.triples.*.sha256",
    "$.triples.*.blake3",
    // Channel manifest (`yah-desktop/release-manifest.json`).
    "$.host.bundle.*.blake3",
    // One per-triple fragment, before the merge job folds it into `.triples`.
    "$.sha256",
];

fn looks_like_bare_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// One segment of a JSON path: an object key or an array index.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Key(String),
    Index(usize),
}

fn render_path(segs: &[Seg]) -> String {
    let mut out = String::from("$");
    for s in segs {
        match s {
            Seg::Key(k) => {
                out.push('.');
                out.push_str(k);
            }
            Seg::Index(i) => out.push_str(&format!("[{i}]")),
        }
    }
    out
}

/// True when `segs` is described by one of the `LEGACY_BARE_HEX_PATHS` patterns.
fn is_grandfathered(segs: &[Seg]) -> bool {
    LEGACY_BARE_HEX_PATHS.iter().any(|pat| pattern_matches(pat, segs))
}

fn pattern_matches(pattern: &str, segs: &[Seg]) -> bool {
    let body = pattern.strip_prefix("$.").unwrap_or(pattern);
    let mut want: Vec<Seg> = Vec::new();
    for piece in body.split('.') {
        // `releases[*]` → the key, then any index.
        if let Some(key) = piece.strip_suffix("[*]") {
            want.push(Seg::Key(key.to_string()));
            // A sentinel index; compared loosely below.
            want.push(Seg::Index(usize::MAX));
        } else {
            want.push(Seg::Key(piece.to_string()));
        }
    }
    if want.len() != segs.len() {
        return false;
    }
    want.iter().zip(segs).all(|(w, s)| match (w, s) {
        // `*` matches any single key — the target-triple map keys.
        (Seg::Key(k), Seg::Key(_)) if k == "*" => true,
        (Seg::Key(a), Seg::Key(b)) => a == b,
        // `[*]` matches any index.
        (Seg::Index(usize::MAX), Seg::Index(_)) => true,
        (Seg::Index(a), Seg::Index(b)) => a == b,
        _ => false,
    })
}

/// Every place in a manifest or feed document where a digest appears with no
/// algorithm tag and no grandfathered excuse, as dotted paths.
///
/// This is guard (b) of R330-F40, and the reason it is a function rather than a
/// code review habit: documentation is precisely what failed here already.
/// A new producer field that carries raw hex fails the tests that call this the
/// moment it is added, and the failure names the path.
///
/// The producers build their JSON in bash and `jq`, so they cannot call this on
/// the way out. The loop is closed instead by committed byte-faithful fixtures
/// of each producer's real output (`tests/fixtures/producer/`), which this runs
/// over in `tests/producer_shapes.rs`, and which
/// `scripts/check-producer-fixtures.sh` regenerates from the actual workflow
/// and publish script so drift fails rather than passing quietly.
pub fn untyped_hash_fields(value: &serde_json::Value) -> Vec<String> {
    let mut found = Vec::new();
    let mut segs = Vec::new();
    walk_for_bare_hex(value, &mut segs, &mut found);
    found
}

fn walk_for_bare_hex(value: &serde_json::Value, segs: &mut Vec<Seg>, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                segs.push(Seg::Key(key.clone()));
                if let serde_json::Value::String(s) = child {
                    if looks_like_bare_digest(s) && !is_grandfathered(segs) {
                        found.push(render_path(segs));
                    }
                } else {
                    walk_for_bare_hex(child, segs, found);
                }
                segs.pop();
            }
        }
        serde_json::Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                segs.push(Seg::Index(i));
                if let serde_json::Value::String(s) = child {
                    // An array element has no key of its own, but its enclosing
                    // path can still be grandfathered.
                    if looks_like_bare_digest(s) && !is_grandfathered(segs) {
                        found.push(render_path(segs));
                    }
                } else {
                    walk_for_bare_hex(child, segs, found);
                }
                segs.pop();
            }
        }
        _ => {}
    }
}

/// SHA-256 hex digest, validated at deserialize the same way
/// [`BlakeHash`] validates BLAKE3.
///
/// A hash is rendered to users as a *verification instruction* ("run
/// `shasum -a 256` and compare"), so a malformed one is worse than an absent
/// one — it invites a comparison that can never match. Failing the parse means
/// a corrupt manifest is rejected at the feed boundary instead of reaching the
/// page. Same digest width as BLAKE3 (64 hex digits), different algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Sha256Hash(pub String);

impl<'de> Deserialize<'de> for Sha256Hash {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom(format!(
                "sha256 hash must be exactly 64 hex digits, got {s:?}"
            )));
        }
        Ok(Self(s))
    }
}

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
    /// THE asset hash — tagged, canonical, `blake3:<hex>` whenever the producer
    /// can compute one (R330-F40). Falls back to a *tagged* `sha256:<hex>` for
    /// manifests published before every producer emitted blake3, so a consumer
    /// reading this field still never has to guess the algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<AssetHash>,
    /// The `curl | sh` bootstrap-verification aid — always `sha256:<hex>`, and
    /// never an identity. Split from [`ReleaseAsset::hash`] so that "the hash
    /// of this artifact" and "the digest a bare POSIX box can check" are two
    /// different questions with two different answers, rather than one field
    /// whose meaning depends on which producer happened to fill it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_hash: Option<AssetHash>,
    /// LEGACY bare-hex mirror of a `blake3:` [`ReleaseAsset::hash`]. Kept only
    /// so consumers older than R330-F40 keep rendering a checksum; new code
    /// reads `hash`. See [`LEGACY_BARE_HEX_PATHS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3: Option<BlakeHash>,
    /// LEGACY bare-hex mirror of [`ReleaseAsset::bootstrap_hash`]. Kept because
    /// every `install.sh` already in the wild reads `.triples[$t].sha256` out
    /// of the pointer manifest; removing it breaks installs that are already
    /// running. See [`LEGACY_BARE_HEX_PATHS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256Hash>,
    /// Upstream distribution license. `None` when the release manifest does not
    /// declare one. Uses the same closed-set [`License`] enum as
    /// `asset.derive.fetch.license` — non-permissive values are rejected at
    /// parse time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<License>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

impl ReleaseAsset {
    /// Reconcile the tagged hashes and their legacy bare mirrors so the two can
    /// never disagree.
    ///
    /// Every manifest → feed mapper runs this, which is what lets producers
    /// migrate one at a time: a manifest carrying only the old bare `sha256`
    /// still comes out of the feed with a properly tagged `hash`, and a
    /// manifest carrying only the new tagged form still comes out with the bare
    /// mirrors the old marketing bundle and the in-the-wild `install.sh` read.
    /// Doing it in one place is the point — the failure this ticket exists to
    /// prevent is two hex values that nobody notices are misaligned.
    pub fn normalize_hashes(&mut self) {
        // Identity first: an explicitly tagged hash wins, then legacy blake3
        // (which IS the canonical algorithm), then legacy sha256 — tagged, so
        // that even the fallback says out loud what it is.
        if self.hash.is_none() {
            self.hash = self
                .blake3
                .as_ref()
                .and_then(|b| AssetHash::blake3(b.0.clone()).ok())
                .or_else(|| {
                    self.sha256.as_ref().and_then(|s| AssetHash::sha256(s.0.clone()).ok())
                });
        }
        if self.bootstrap_hash.is_none() {
            self.bootstrap_hash = self
                .sha256
                .as_ref()
                .and_then(|s| AssetHash::sha256(s.0.clone()).ok())
                .or_else(|| match &self.hash {
                    Some(h) if h.algo() == HashAlgo::Sha256 => Some(h.clone()),
                    _ => None,
                });
        }
        // Then mirror back out for consumers that predate the tagged fields.
        if self.blake3.is_none() {
            if let Some(h) = self.hash.as_ref().filter(|h| h.algo() == HashAlgo::Blake3) {
                self.blake3 = Some(BlakeHash(h.hex().to_string()));
            }
        }
        if self.sha256.is_none() {
            if let Some(h) = &self.bootstrap_hash {
                self.sha256 = Some(Sha256Hash(h.hex().to_string()));
            }
        }
    }
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
            hash: None,
            bootstrap_hash: None,
            blake3,
            sha256: None,
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
        assert!(!json.contains("sha256"), "sha256 absent when None");
        assert!(!json.contains("license"), "license absent when None");
        let back: ReleaseAsset = serde_json::from_str(&json).unwrap();
        assert_eq!(back.blake3, None);
        assert_eq!(back.sha256, None);
        assert_eq!(back.license, None);
    }

    #[test]
    fn sha256_round_trips_as_a_bare_hex_string() {
        // The marketing page reads `asset.sha256` as a plain string, so the
        // newtype must be transparent on the wire.
        let mut asset = sample_asset(None, None);
        asset.sha256 = Some(Sha256Hash("b".repeat(64)));
        let json = serde_json::to_string(&asset).unwrap();
        assert!(json.contains(&format!("\"sha256\":\"{}\"", "b".repeat(64))));
        let back: ReleaseAsset = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sha256, Some(Sha256Hash("b".repeat(64))));
    }

    #[test]
    fn malformed_sha256_is_rejected_at_deserialize() {
        let json = r#"{"platform":"macos-arm64","filename":"f","url":"u","sha256":"nope"}"#;
        assert!(
            serde_json::from_str::<ReleaseAsset>(json).is_err(),
            "a non-64-hex sha256 must fail the parse rather than reach the page"
        );
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

    // ── R330-F40 guard (a): bare hex is unrepresentable ──────────────────────

    #[test]
    fn a_bare_hex_digest_cannot_be_deserialized_as_an_asset_hash() {
        let bare = "a".repeat(64);
        let err = AssetHash::parse(&bare).unwrap_err();
        assert_eq!(err, HashParseError::Untagged(bare.clone()));
        // …and the same holds through serde, which is the path a manifest takes.
        let json = format!("\"{bare}\"");
        let de = serde_json::from_str::<AssetHash>(&json).unwrap_err().to_string();
        assert!(de.contains("bare hex"), "the error must name the actual problem, got {de:?}");
    }

    #[test]
    fn an_asset_hash_always_serializes_with_its_algorithm() {
        let b3 = AssetHash::blake3("a".repeat(64)).unwrap();
        assert_eq!(serde_json::to_string(&b3).unwrap(), format!("\"blake3:{}\"", "a".repeat(64)));
        let sha = AssetHash::sha256("B".repeat(64)).unwrap();
        // Digests normalize to lowercase so two spellings of one hash compare equal.
        assert_eq!(serde_json::to_string(&sha).unwrap(), format!("\"sha256:{}\"", "b".repeat(64)));
        assert_eq!(AssetHash::parse(&sha.to_string()).unwrap(), sha);
    }

    #[test]
    fn an_unknown_algorithm_is_rejected_rather_than_assumed() {
        // The whole point of the tag is that a consumer never guesses; an
        // algorithm we don't publish must fail loudly, not fall through to a
        // default and get compared against the wrong digest.
        let err = AssetHash::parse(&format!("md5:{}", "a".repeat(64))).unwrap_err();
        assert_eq!(err, HashParseError::UnknownAlgo("md5".into()));
        let err = AssetHash::parse("blake3:nope").unwrap_err();
        assert!(matches!(err, HashParseError::BadDigest { algo: HashAlgo::Blake3, .. }));
    }

    #[test]
    fn the_typed_hash_round_trips_through_a_release_asset() {
        let mut asset = sample_asset(None, None);
        asset.hash = Some(AssetHash::blake3("c".repeat(64)).unwrap());
        asset.bootstrap_hash = Some(AssetHash::sha256("d".repeat(64)).unwrap());
        let json = serde_json::to_string(&asset).unwrap();
        assert!(json.contains(&format!("\"hash\":\"blake3:{}\"", "c".repeat(64))));
        assert!(json.contains(&format!("\"bootstrap_hash\":\"sha256:{}\"", "d".repeat(64))));
        let back: ReleaseAsset = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hash, asset.hash);
        assert_eq!(back.bootstrap_hash, asset.bootstrap_hash);
    }

    // ── R330-F40: the typed form and its legacy mirrors cannot diverge ───────

    #[test]
    fn normalize_lifts_legacy_bare_hashes_into_tagged_ones() {
        // A manifest published before this ticket: bare keys only.
        let mut asset = sample_asset(Some(BlakeHash("a".repeat(64))), None);
        asset.sha256 = Some(Sha256Hash("b".repeat(64)));
        asset.normalize_hashes();
        assert_eq!(asset.hash, Some(AssetHash::blake3("a".repeat(64)).unwrap()));
        assert_eq!(asset.bootstrap_hash, Some(AssetHash::sha256("b".repeat(64)).unwrap()));
    }

    #[test]
    fn normalize_mirrors_tagged_hashes_back_out_for_old_consumers() {
        // A manifest published after this ticket, read by a consumer (or
        // rendered into a page bundle) that only knows the bare keys.
        let mut asset = sample_asset(None, None);
        asset.hash = Some(AssetHash::blake3("a".repeat(64)).unwrap());
        asset.bootstrap_hash = Some(AssetHash::sha256("b".repeat(64)).unwrap());
        asset.normalize_hashes();
        assert_eq!(asset.blake3, Some(BlakeHash("a".repeat(64))));
        assert_eq!(asset.sha256, Some(Sha256Hash("b".repeat(64))));
    }

    #[test]
    fn a_sha256_only_producer_still_gets_a_tagged_identity() {
        // The CLI leg before it learned b3sum. `hash` must never be silently
        // absent AND never be an untagged value the page has to guess about.
        let mut asset = sample_asset(None, None);
        asset.sha256 = Some(Sha256Hash("b".repeat(64)));
        asset.normalize_hashes();
        let hash = asset.hash.expect("a sha256-only producer still publishes a hash");
        assert_eq!(hash.algo(), HashAlgo::Sha256, "and it says so, rather than posing as blake3");
        assert_eq!(asset.bootstrap_hash, Some(hash));
        assert_eq!(asset.blake3, None, "no blake3 is invented out of a sha256");
    }

    #[test]
    fn normalize_never_overwrites_what_the_producer_stated() {
        let mut asset = sample_asset(Some(BlakeHash("a".repeat(64))), None);
        asset.hash = Some(AssetHash::blake3("c".repeat(64)).unwrap());
        asset.normalize_hashes();
        assert_eq!(asset.hash.unwrap().hex(), "c".repeat(64));
        assert_eq!(asset.blake3.unwrap().0, "a".repeat(64));
    }

    // ── R330-F40 guard (b): no untyped hex anywhere new ──────────────────────

    #[test]
    fn the_allowlist_is_scoped_to_a_path_not_to_a_key_name() {
        // THE 2b PROPERTY. `blake3` and `sha256` are extremely ordinary names;
        // grandfathering them by name alone waves through a bare digest under
        // those names ANYWHERE at ANY depth, and a new nested field reusing one
        // is the likeliest drift shape. Each of these reuses a legacy NAME at a
        // path that is not the grandfathered one, and each must be flagged.
        let hex = "e".repeat(64);
        let cases = [
            // A new sibling object inside an asset.
            serde_json::json!({
                "releases": [{ "assets": [{ "signature": { "blake3": hex } }] }]
            }),
            // A new top-level section of the install pointer.
            serde_json::json!({ "attestation": { "sha256": hex } }),
            // The right key at the wrong depth (missing the `assets` level).
            serde_json::json!({ "releases": [{ "blake3": hex }] }),
            // The right key one level too deep in the channel manifest.
            serde_json::json!({ "host": { "bundle": { "t": { "extra": { "blake3": hex } } } } }),
        ];
        for (i, case) in cases.iter().enumerate() {
            assert_eq!(
                untyped_hash_fields(case).len(),
                1,
                "case {i} reuses a legacy key name off its grandfathered path and \
                 must still be flagged: {case}"
            );
        }
    }

    #[test]
    fn the_grandfathered_paths_are_matched_exactly() {
        // The other half: the real locations must NOT be flagged, or the guard
        // is useless noise and someone will disable it.
        let hex = "e".repeat(64);
        let allowed = [
            serde_json::json!({ "releases": [{ "assets": [{ "blake3": hex }] }] }),
            serde_json::json!({ "releases": [{ "assets": [{ "sha256": hex }] }] }),
            serde_json::json!({ "triples": { "aarch64-apple-darwin": { "sha256": hex } } }),
            serde_json::json!({ "triples": { "aarch64-apple-darwin": { "blake3": hex } } }),
            serde_json::json!({ "host": { "bundle": { "aarch64-apple-darwin": { "blake3": hex } } } }),
            serde_json::json!({ "sha256": hex }),
        ];
        for (i, case) in allowed.iter().enumerate() {
            assert!(
                untyped_hash_fields(case).is_empty(),
                "case {i} is a real published location and must not be flagged: {case}"
            );
        }
        // A bare blake3 at the fragment top level is NOT grandfathered — only
        // sha256 is, because only sha256 is what a pre-F40 fragment carried.
        assert_eq!(untyped_hash_fields(&serde_json::json!({ "blake3": hex })).len(), 1);
    }

    #[test]
    fn untyped_hash_fields_finds_bare_hex_under_an_unknown_key() {
        let v = serde_json::json!({
            "triples": { "aarch64-apple-darwin": { "digest": "e".repeat(64) } }
        });
        assert_eq!(untyped_hash_fields(&v), vec!["$.triples.aarch64-apple-darwin.digest"]);
        // Nested in an array, where no key can grandfather it.
        let v = serde_json::json!({ "hashes": ["f".repeat(64)] });
        assert_eq!(untyped_hash_fields(&v), vec!["$.hashes[0]"]);
        // Tagged values are invisible to it, whatever the key.
        let v = serde_json::json!({ "digest": format!("blake3:{}", "e".repeat(64)) });
        assert!(untyped_hash_fields(&v).is_empty());
    }

    #[test]
    fn a_serialized_feed_carries_no_untyped_hex_outside_the_legacy_keys() {
        // THE anti-"mess of random hex values" guard. Every hash a fully
        // populated asset can carry, serialized exactly as the feed writes it:
        // the only bare digests permitted are the two grandfathered keys, and
        // the moment a new field carries raw hex this fails and names it.
        let mut asset = sample_asset(Some(BlakeHash("a".repeat(64))), Some(License::Mit));
        asset.sha256 = Some(Sha256Hash("b".repeat(64)));
        asset.normalize_hashes();
        let feed = ReleaseFeed {
            fetched_at: Utc::now(),
            releases: vec![Release {
                version: "1.0.0".into(),
                tag: "v1.0.0".into(),
                published_at: Utc::now(),
                notes: None,
                assets: vec![asset],
            }],
        };
        let value = serde_json::to_value(&feed).unwrap();
        assert_eq!(
            untyped_hash_fields(&value),
            Vec::<String>::new(),
            "an untagged digest reached the feed — tag it, or grandfather its \
             exact path in LEGACY_BARE_HEX_PATHS with a reason"
        );
        // And the grandfathering is doing real work rather than vacuously
        // passing: those keys ARE present and ARE bare.
        assert_eq!(value["releases"][0]["assets"][0]["blake3"], serde_json::json!("a".repeat(64)));
        assert_eq!(value["releases"][0]["assets"][0]["sha256"], serde_json::json!("b".repeat(64)));
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
