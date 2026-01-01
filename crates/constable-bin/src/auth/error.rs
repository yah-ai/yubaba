//! Error types for the auth surface.
//!
//! Split into [`AuthError`] (lifecycle: boot, fetch, persist) and
//! [`VerifyError`] (per-request: signature, claims, kid). The split matches
//! the W159 §Failure responses split between "constable cannot serve" (401
//! shape) and "this token isn't good for this call" (403 shape) — though the
//! response-shape mapping itself is F3.

use std::path::PathBuf;
use thiserror::Error;

/// Lifecycle errors — fetching cheers's JWKS, persisting the cache, parsing.
#[derive(Debug, Error)]
pub enum AuthError {
    /// First-start fetch failed and there is no cached JWKS to fall back to.
    /// W159: "Fetch failure on first start is fatal — operator must fix the
    /// AS URL or seed the cache out-of-band before retry."
    #[error("cheers JWKS unreachable at boot and no cache present at {cache_path:?}: {source}")]
    BootFetchFatal {
        cache_path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// JWKS HTTP fetch failed (non-fatal at steady state — we keep serving
    /// stale until the next refresh succeeds).
    #[error("JWKS fetch failed: {0}")]
    Fetch(#[from] reqwest::Error),

    /// JWKS body couldn't be parsed as the expected document shape.
    #[error("JWKS parse failed: {0}")]
    Parse(String),

    /// A JWK entry's `x` field wasn't a 32-byte Ed25519 public key after
    /// base64url decode.
    #[error("JWK {kid:?} has invalid Ed25519 public key: {reason}")]
    BadKey { kid: String, reason: String },

    /// Disk I/O failure (load or atomic write of the cache file).
    #[error("JWKS cache I/O failure at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Serializing the cache to disk failed.
    #[error("JWKS cache serialize failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Per-request verification errors. Mapped to W159 §Failure responses by F3.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Token couldn't be parsed as PASETO v4.public.
    #[error("malformed token: {0}")]
    Malformed(String),

    /// Footer didn't contain a usable `kid`.
    #[error("token footer missing or unreadable kid")]
    MissingKid,

    /// `kid` not in cache after a single rate-limited refresh attempt.
    /// W159: rotation handles this — overlap window means new `kid` is in the
    /// next JWKS publication. If still unknown, the token's signer isn't ours.
    #[error("unknown kid {0:?} after refresh")]
    UnknownKid(String),

    /// Ed25519 signature didn't verify against the cached pubkey.
    #[error("signature verification failed")]
    SignatureMismatch,

    /// `exp` claim is in the past.
    #[error("token expired at {exp}, now {now}")]
    Expired { exp: i64, now: i64 },

    /// `iss` claim didn't match the configured cheers issuer.
    #[error("issuer mismatch: expected {expected:?}, got {got:?}")]
    BadIssuer { expected: String, got: String },

    /// `aud` claim didn't match this constable's resource URI.
    #[error("audience mismatch: expected {expected:?}, got {got:?}")]
    BadAudience { expected: String, got: String },

    /// Required claim absent or wrong shape (e.g. `sub` not a string, `scope`
    /// not an array). Per W159 these are wire-contract violations — distinct
    /// from "valid token, wrong scope" which is `insufficient_scope` (F3).
    #[error("claim shape violation: {0}")]
    BadClaims(String),
}
