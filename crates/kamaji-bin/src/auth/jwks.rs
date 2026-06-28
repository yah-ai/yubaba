//! JWKS document, runtime cache, and atomic on-disk persistence.
//!
//! W159 §Kamaji startup and JWKS lifecycle pins the behavior we implement:
//!
//! - Boot: synchronous fetch + persist; no-cache+AS-unreachable is fatal.
//! - Steady state: serve from RAM; refresh on a tick; write atomically
//!   (temp file + rename) so concurrent verifies never see a torn key set.
//! - Rotation: cheers publishes overlap window; we just replace the cache
//!   on refresh.
//! - kid-miss: triggers an out-of-band refresh elsewhere ([`verifier`]).
//!
//! The JWK shape we accept is OKP+Ed25519 — `kty="OKP"`, `crv="Ed25519"`,
//! `x` = base64url(32-byte public key), `kid` required. Other key types are
//! skipped silently (forward-compatible — future cheers JWKS may also publish
//! Ed448 / X25519 / etc. for adjacent purposes, none of which we verify here).

use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

use super::error::AuthError;

/// One published JWK entry, in JWKS doc form.
///
/// Only `kty` is required so foreign-`kty` entries (RSA, EC, X25519, …) round-
/// trip cleanly even when they omit fields that are mandatory for THEIR shape
/// — we don't validate them, we skip them. `x` and `kid` are required for
/// the OKP/Ed25519 path; [`JwksCache::from_doc`] enforces that locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkKey {
    /// Key type. We accept `"OKP"` for Ed25519.
    pub kty: String,
    /// Curve. We accept `"Ed25519"`.
    #[serde(default)]
    pub crv: Option<String>,
    /// Base64url-encoded 32-byte public key. Required when `kty == "OKP"`.
    #[serde(default)]
    pub x: Option<String>,
    /// Rotation handle. Required for our lookup path.
    #[serde(default)]
    pub kid: Option<String>,
    /// `"sig"` for signing keys. Optional in the JWKS spec; we don't enforce.
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// Algorithm hint. Optional. `"EdDSA"` for Ed25519.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

/// JWKS document — the on-wire shape published at
/// `${cheers_issuer}/.well-known/jwks.json` and the on-disk shape we persist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDoc {
    pub keys: Vec<JwkKey>,
}

/// In-memory verifier-ready form. Decoded Ed25519 pubkeys, indexed by `kid`.
#[derive(Debug, Clone)]
pub struct JwksCache {
    keys: HashMap<String, [u8; 32]>,
    /// Original doc — what we persist back to disk. Keeps round-trip cheap
    /// (no re-encoding from bytes) and preserves the published `alg`/`use`
    /// metadata for operator visibility.
    doc: JwksDoc,
    /// Wall-clock time of the last successful fetch. Used by the
    /// serve-stale-with-warning arm of restart resilience.
    last_refresh: SystemTime,
}

impl JwksCache {
    /// Decode a fetched JWKS document into the runtime cache. Unknown `kty`
    /// entries are skipped (forward-compatible); a doc with zero usable
    /// Ed25519 keys is treated as a parse failure — there is nothing to
    /// verify with.
    pub fn from_doc(doc: JwksDoc) -> Result<Self, AuthError> {
        let mut keys = HashMap::with_capacity(doc.keys.len());
        for k in &doc.keys {
            if k.kty != "OKP" || k.crv.as_deref() != Some("Ed25519") {
                continue;
            }
            let kid = k.kid.clone().ok_or_else(|| AuthError::BadKey {
                kid: "<missing>".into(),
                reason: "OKP/Ed25519 entry missing kid".into(),
            })?;
            let x = k.x.as_ref().ok_or_else(|| AuthError::BadKey {
                kid: kid.clone(),
                reason: "OKP/Ed25519 entry missing x".into(),
            })?;
            let bytes = Base64UrlUnpadded::decode_vec(x).map_err(|e| AuthError::BadKey {
                kid: kid.clone(),
                reason: format!("base64url decode: {e}"),
            })?;
            let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| AuthError::BadKey {
                kid: kid.clone(),
                reason: format!("expected 32 bytes, got {}", v.len()),
            })?;
            keys.insert(kid, arr);
        }
        if keys.is_empty() {
            return Err(AuthError::Parse(
                "JWKS contained no OKP/Ed25519 keys".into(),
            ));
        }
        Ok(Self {
            keys,
            doc,
            last_refresh: SystemTime::now(),
        })
    }

    /// Look up a public key by `kid`. Cache hit → ready to verify.
    pub fn get(&self, kid: &str) -> Option<&[u8; 32]> {
        self.keys.get(kid)
    }

    /// Number of usable Ed25519 keys in the cache.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// `true` when the cache holds no keys (only constructible via the
    /// from-disk path, since [`Self::from_doc`] rejects empty docs).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Wall-clock time of the last successful refresh.
    pub fn last_refresh(&self) -> SystemTime {
        self.last_refresh
    }

    /// The published JWKS document — for re-serialization on persist.
    pub fn doc(&self) -> &JwksDoc {
        &self.doc
    }

    /// Load a previously-persisted cache. Returns `Ok(None)` when the cache
    /// file does not exist (boot path branches on this).
    pub async fn load_from_disk(path: &Path) -> Result<Option<Self>, AuthError> {
        match tokio::fs::read(path).await {
            Ok(bytes) => {
                let stored: StoredCache =
                    serde_json::from_slice(&bytes).map_err(AuthError::Serialize)?;
                let mut cache = Self::from_doc(stored.doc)?;
                // Preserve the persisted refresh wall-clock so the
                // serve-stale-with-warning arm can compute staleness across
                // restarts.
                if let Some(secs) = stored.last_refresh_secs {
                    cache.last_refresh = std::time::UNIX_EPOCH
                        .checked_add(std::time::Duration::from_secs(secs))
                        .unwrap_or_else(SystemTime::now);
                }
                Ok(Some(cache))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(AuthError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Atomic persist: write to a sibling temp file, fsync, rename. A
    /// concurrent reader either sees the prior cache or the new one — never
    /// a torn key set.
    pub async fn write_atomic(&self, path: &Path) -> Result<(), AuthError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|source| AuthError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
        }
        let stored = StoredCache {
            doc: self.doc.clone(),
            last_refresh_secs: self
                .last_refresh
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
        };
        let body = serde_json::to_vec_pretty(&stored)?;
        let tmp = tmp_sibling(path);
        tokio::fs::write(&tmp, &body)
            .await
            .map_err(|source| AuthError::Io {
                path: tmp.clone(),
                source,
            })?;
        tokio::fs::rename(&tmp, path)
            .await
            .map_err(|source| AuthError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(())
    }

    /// Replace this cache's data with a freshly-fetched doc, updating
    /// `last_refresh`. Used by the refresh path so we never construct a new
    /// `Arc<RwLock<…>>` shell mid-flight.
    pub fn replace_with(&mut self, doc: JwksDoc) -> Result<(), AuthError> {
        let next = Self::from_doc(doc)?;
        *self = next;
        Ok(())
    }
}

/// What we actually write to disk — the JWKS doc plus the wall-clock of the
/// last successful fetch. Wrapping rather than inlining lets us extend the
/// on-disk shape (e.g. ETag) without breaking forward compatibility.
#[derive(Debug, Serialize, Deserialize)]
struct StoredCache {
    doc: JwksDoc,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_refresh_secs: Option<u64>,
}

fn tmp_sibling(path: &Path) -> std::path::PathBuf {
    let mut tmp = path.to_path_buf();
    let mut name = tmp
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("jwks.json"));
    name.push(".tmp");
    tmp.set_file_name(name);
    tmp
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jwks_doc_with(kid: &str, pubkey: &[u8; 32]) -> JwksDoc {
        let x = Base64UrlUnpadded::encode_string(pubkey);
        let doc = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
                "kid": kid,
                "use": "sig",
                "alg": "EdDSA",
            }]
        });
        serde_json::from_value(doc).unwrap()
    }

    #[test]
    fn parses_okp_ed25519_skips_unknown_kty() {
        let known_pub = [7u8; 32];
        let x = Base64UrlUnpadded::encode_string(&known_pub);
        let doc: JwksDoc = serde_json::from_value(json!({
            "keys": [
                {"kty": "RSA", "n": "...", "e": "AQAB", "kid": "rsa-1"},
                {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "ed-1"},
                {"kty": "OKP", "crv": "X25519", "x": "AA", "kid": "x25519-skip"},
            ]
        }))
        .unwrap();
        let cache = JwksCache::from_doc(doc).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("ed-1"), Some(&known_pub));
        assert!(cache.get("rsa-1").is_none());
        assert!(cache.get("x25519-skip").is_none());
    }

    #[test]
    fn rejects_doc_with_no_ed25519_keys() {
        let doc: JwksDoc = serde_json::from_value(json!({
            "keys": [
                {"kty": "RSA", "n": "...", "e": "AQAB", "kid": "rsa-1"},
            ]
        }))
        .unwrap();
        assert!(matches!(
            JwksCache::from_doc(doc),
            Err(AuthError::Parse(_))
        ));
    }

    #[test]
    fn rejects_wrong_length_pubkey() {
        let too_short = Base64UrlUnpadded::encode_string(&[1u8; 16]);
        let doc: JwksDoc = serde_json::from_value(json!({
            "keys": [{"kty": "OKP", "crv": "Ed25519", "x": too_short, "kid": "ed-bad"}]
        }))
        .unwrap();
        let err = JwksCache::from_doc(doc).unwrap_err();
        match err {
            AuthError::BadKey { kid, .. } => assert_eq!(kid, "ed-bad"),
            other => panic!("expected BadKey, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn atomic_round_trip_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("jwks.json");
        let pubkey = [42u8; 32];
        let cache = JwksCache::from_doc(jwks_doc_with("ed-rt", &pubkey)).unwrap();
        cache.write_atomic(&path).await.unwrap();
        // The .tmp sibling MUST be gone after rename succeeds.
        assert!(!tmp.path().join("jwks.json.tmp").exists());
        let loaded = JwksCache::load_from_disk(&path).await.unwrap().unwrap();
        assert_eq!(loaded.get("ed-rt"), Some(&pubkey));
    }

    #[tokio::test]
    async fn load_from_disk_missing_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.json");
        assert!(JwksCache::load_from_disk(&path).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn write_atomic_creates_parent_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/sub/jwks.json");
        let cache = JwksCache::from_doc(jwks_doc_with("ed-nest", &[9u8; 32])).unwrap();
        cache.write_atomic(&path).await.unwrap();
        assert!(path.exists());
    }
}
