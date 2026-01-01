//! Token verifier — the load-bearing public surface of the auth module.
//!
//! Composes the JWKS cache, the rate-limited kid-miss refresh, and pasetors'
//! PASETO v4.public signature check into one async `verify` call. Matches
//! W159 §The wire — Layer 1 line-for-line:
//!
//! - Signature verifies against the JWKS (cheers key *or* a service-principal
//!   pubkey published in the same JWKS).
//! - `iss` is the expected cheers AS.
//! - `aud` matches this constable's resource URI.
//! - `exp` is in the future.
//!
//! Layer 2 (scope + `owns:[...]` membership) is F3 — this module exposes the
//! parsed [`McpClaims`] and stops there.

use std::sync::Arc;
use std::time::Duration;

use pasetors::keys::AsymmetricPublicKey;
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;

use super::claims::McpClaims;
use super::config::AuthConfig;
use super::error::{AuthError, VerifyError};
use super::jwks::{JwksCache, JwksDoc};

/// Footer payload — we only care about `kid`. Other footer fields (alg, etc.)
/// are accepted-and-ignored so a future minter can carry hints without
/// breaking the verifier.
#[derive(Debug, Deserialize)]
struct Footer {
    kid: String,
}

/// The verifier. Construct once via [`AuthVerifier::boot`]; share via `Arc`.
/// `verify` is `&self`-callable concurrently — JWKS reads are RwLock'd.
#[derive(Debug)]
pub struct AuthVerifier {
    config: AuthConfig,
    jwks: Arc<RwLock<JwksCache>>,
    http: reqwest::Client,
    /// Last out-of-band refresh time (kid-miss path). `None` until first
    /// kid-miss. Rate-limited by `config.kid_miss_rate_limit`.
    kid_miss_last: Arc<Mutex<Option<Instant>>>,
}

impl AuthVerifier {
    /// Boot the verifier. Implements W159 §Restart resilience verbatim:
    ///
    /// - Cache present + fresh → start from cache, refresh in background.
    /// - Cache present + stale → synchronous refresh before serving (best-effort;
    ///   falls through to cache+warn on AS failure if `serve_stale_on_failure`).
    /// - Cache present + AS unreachable → serve from stale cache with a warn.
    /// - No cache + AS unreachable → [`AuthError::BootFetchFatal`].
    pub async fn boot(config: AuthConfig) -> Result<Self, AuthError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(AuthError::Fetch)?;

        let on_disk = JwksCache::load_from_disk(&config.cache_path).await?;

        let cache = match on_disk {
            Some(cached) => {
                let stale = cached
                    .last_refresh()
                    .elapsed()
                    .map(|age| age > config.refresh_interval)
                    .unwrap_or(true);
                if stale {
                    // Try a sync refresh; if AS unreachable, fall through to
                    // cache with a warn (serve-stale arm).
                    match fetch_jwks(&http, &config).await {
                        Ok(doc) => {
                            let next = JwksCache::from_doc(doc)?;
                            if let Err(e) = next.write_atomic(&config.cache_path).await {
                                tracing::warn!(error = ?e, "JWKS cache persist failed at boot");
                            }
                            next
                        }
                        Err(e) if config.serve_stale_on_failure => {
                            tracing::warn!(
                                error = ?e,
                                "cheers AS unreachable at boot; serving from stale JWKS cache"
                            );
                            cached
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    cached
                }
            }
            None => {
                // No cache. First-start fetch is fatal if it fails.
                let doc = fetch_jwks(&http, &config)
                    .await
                    .map_err(|e| AuthError::BootFetchFatal {
                        cache_path: config.cache_path.clone(),
                        source: Box::new(e),
                    })?;
                let next = JwksCache::from_doc(doc)?;
                next.write_atomic(&config.cache_path).await?;
                next
            }
        };

        Ok(Self {
            config,
            jwks: Arc::new(RwLock::new(cache)),
            http,
            kid_miss_last: Arc::new(Mutex::new(None)),
        })
    }

    /// Verify a PASETO v4.public token. Returns parsed [`McpClaims`] on
    /// success. Per-failure error variants map 1:1 to the W159 §Failure
    /// responses table (F3 turns these into HTTP shapes).
    pub async fn verify(&self, token: &str, now: i64) -> Result<McpClaims, VerifyError> {
        let untrusted = UntrustedToken::<pasetors::token::Public, V4>::try_from(token)
            .map_err(|e| VerifyError::Malformed(format!("{e:?}")))?;

        // Parse footer to get kid BEFORE signature verification — the footer
        // is bound into the signature so a forged footer fails verify anyway.
        let footer_bytes = untrusted.untrusted_footer();
        if footer_bytes.is_empty() {
            return Err(VerifyError::MissingKid);
        }
        let footer: Footer = serde_json::from_slice(footer_bytes)
            .map_err(|e| VerifyError::Malformed(format!("footer: {e}")))?;

        // Cache lookup with a single rate-limited refresh retry on miss.
        let pubkey_bytes = {
            let cache = self.jwks.read().await;
            cache.get(&footer.kid).copied()
        };
        let pubkey_bytes = match pubkey_bytes {
            Some(b) => b,
            None => {
                self.try_kid_miss_refresh().await;
                let cache = self.jwks.read().await;
                cache
                    .get(&footer.kid)
                    .copied()
                    .ok_or_else(|| VerifyError::UnknownKid(footer.kid.clone()))?
            }
        };

        let pubkey = AsymmetricPublicKey::<V4>::from(&pubkey_bytes)
            .map_err(|e| VerifyError::Malformed(format!("pubkey: {e:?}")))?;

        // Use the low-level v4 PublicToken API directly. The high-level
        // `pasetors::public::verify` would route the payload through
        // `Claims::from_string`, which rejects any registered claim
        // (`iss`/`sub`/`aud`/`exp`/`iat`/`jti`/`nbf`) that isn't a string —
        // incompatible with W159 §Canonical claim schema's i64 `exp`/`iat`.
        // The signature + footer-binding check is identical between the two
        // entry points (the high level wraps this one).
        let trusted = PublicToken::verify(&pubkey, &untrusted, None, None).map_err(|e| match e {
            pasetors::errors::Error::TokenValidation => VerifyError::SignatureMismatch,
            other => VerifyError::Malformed(format!("{other:?}")),
        })?;

        let claims: McpClaims = serde_json::from_str(trusted.payload())
            .map_err(|e| VerifyError::BadClaims(e.to_string()))?;

        // Standard-claim checks (W159 Layer 1).
        if claims.iss != self.config.cheers_issuer {
            return Err(VerifyError::BadIssuer {
                expected: self.config.cheers_issuer.clone(),
                got: claims.iss.clone(),
            });
        }
        if claims.aud != self.config.expected_aud {
            return Err(VerifyError::BadAudience {
                expected: self.config.expected_aud.clone(),
                got: claims.aud.clone(),
            });
        }
        if claims.exp <= now {
            return Err(VerifyError::Expired {
                exp: claims.exp,
                now,
            });
        }

        Ok(claims)
    }

    /// Refresh JWKS from the AS. Used by the background refresh task and
    /// directly available so an operator surface can trigger a manual
    /// refresh (e.g. after a known-good key rotation).
    pub async fn refresh(&self) -> Result<(), AuthError> {
        let doc = fetch_jwks(&self.http, &self.config).await?;
        let next = JwksCache::from_doc(doc)?;
        next.write_atomic(&self.config.cache_path).await?;
        let mut guard = self.jwks.write().await;
        *guard = next;
        Ok(())
    }

    /// Spawn the background refresh task. Returns the join handle so the
    /// caller can abort on shutdown. The task ticks at
    /// `config.refresh_interval`; AS failures are logged but do not cancel
    /// the loop (W159: rotation is overlap-windowed, so missing one tick
    /// rarely loses verifiability).
    pub fn spawn_refresh_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = self.config.refresh_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate fire — boot already populated the cache.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = self.refresh().await {
                    tracing::warn!(error = ?e, "background JWKS refresh failed; continuing");
                }
            }
        })
    }

    /// Read-only access to the cached JWKS — for operator surfaces and
    /// tests. Holds a read lock for the duration of the closure.
    pub async fn with_jwks<R>(&self, f: impl FnOnce(&JwksCache) -> R) -> R {
        let guard = self.jwks.read().await;
        f(&guard)
    }

    async fn try_kid_miss_refresh(&self) {
        let mut last = self.kid_miss_last.lock().await;
        let now = Instant::now();
        if let Some(prev) = *last {
            if now.duration_since(prev) < self.config.kid_miss_rate_limit {
                tracing::debug!("kid-miss refresh suppressed by rate limit");
                return;
            }
        }
        *last = Some(now);
        drop(last);
        if let Err(e) = self.refresh().await {
            tracing::warn!(error = ?e, "kid-miss JWKS refresh failed");
        }
    }
}

async fn fetch_jwks(http: &reqwest::Client, config: &AuthConfig) -> Result<JwksDoc, AuthError> {
    let resp = http.get(config.jwks_url()).send().await?;
    let resp = resp.error_for_status()?;
    let doc: JwksDoc = resp.json().await?;
    Ok(doc)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwks::{JwkKey, JwksDoc};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricSecretKey, Generate};

    fn keypair() -> AsymmetricKeyPair<V4> {
        AsymmetricKeyPair::<V4>::generate().expect("keypair gen")
    }

    fn pubkey_bytes(kp: &AsymmetricKeyPair<V4>) -> [u8; 32] {
        let bytes = kp.public.as_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        out
    }

    fn jwks_doc_for(kid: &str, kp: &AsymmetricKeyPair<V4>) -> JwksDoc {
        JwksDoc {
            keys: vec![JwkKey {
                kty: "OKP".into(),
                crv: Some("Ed25519".into()),
                x: Some(Base64UrlUnpadded::encode_string(&pubkey_bytes(kp))),
                kid: Some(kid.into()),
                use_: Some("sig".into()),
                alg: Some("EdDSA".into()),
            }],
        }
    }

    fn mint_token(
        secret: &AsymmetricSecretKey<V4>,
        kid: &str,
        payload: serde_json::Value,
    ) -> String {
        // Mint via the low-level v4 PublicToken API. Mirrors the verifier's
        // path: raw JSON bytes in, raw JSON bytes out — sidestepping
        // pasetors's high-level Claims wrapper that constrains registered
        // claims to be strings (W159 wants i64 `exp`/`iat`).
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let footer_bytes = format!(r#"{{"kid":"{kid}"}}"#).into_bytes();
        PublicToken::sign(secret, &payload_bytes, Some(&footer_bytes), None)
            .expect("sign succeeds")
    }

    fn good_payload(
        iss: &str,
        aud: &str,
        exp: i64,
        iat: i64,
        sub: &str,
        scope: &[&str],
    ) -> serde_json::Value {
        serde_json::json!({
            "iss": iss,
            "aud": aud,
            "exp": exp,
            "iat": iat,
            "jti": "01HTEST",
            "sub": sub,
            "scope": scope,
        })
    }

    async fn build_verifier_with_doc(doc: JwksDoc) -> AuthVerifier {
        let tmp = tempfile::tempdir().unwrap();
        let cache_path = tmp.path().join("jwks.json");
        // Persist a synthetic cache so `boot` takes the cache-present arm
        // without making a real HTTP fetch.
        let cache = JwksCache::from_doc(doc).unwrap();
        cache.write_atomic(&cache_path).await.unwrap();
        let config = AuthConfig::new("https://cheers.test", "https://constable.test")
            .with_cache_path(cache_path);
        // Keep the temp dir alive via leak — tests exit before it matters.
        std::mem::forget(tmp);
        AuthVerifier::boot(config).await.unwrap()
    }

    #[tokio::test]
    async fn verifies_well_formed_token() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;

        let token = mint_token(
            &kp.secret,
            "k1",
            good_payload(
                "https://cheers.test",
                "https://constable.test",
                2_000_000_000,
                1_700_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );

        let claims = verifier.verify(&token, 1_800_000_000).await.unwrap();
        assert_eq!(claims.sub, "user:abc");
        assert_eq!(claims.scope, vec!["cloud:deploy"]);
    }

    #[tokio::test]
    async fn rejects_unknown_kid() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;

        let token = mint_token(
            &kp.secret,
            "k-unknown",
            good_payload(
                "https://cheers.test",
                "https://constable.test",
                2_000_000_000,
                1_700_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );
        // Cheers is unreachable in tests, so the kid-miss refresh path is a
        // no-op and we get UnknownKid back.
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::UnknownKid(kid) if kid == "k-unknown"));
    }

    #[tokio::test]
    async fn rejects_signature_mismatch() {
        let signing_kp = keypair();
        let other_kp = keypair();
        // JWKS publishes the WRONG key for kid k1.
        let doc = jwks_doc_for("k1", &other_kp);
        let verifier = build_verifier_with_doc(doc).await;

        let token = mint_token(
            &signing_kp.secret,
            "k1",
            good_payload(
                "https://cheers.test",
                "https://constable.test",
                2_000_000_000,
                1_700_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::SignatureMismatch));
    }

    #[tokio::test]
    async fn rejects_expired() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        let token = mint_token(
            &kp.secret,
            "k1",
            good_payload(
                "https://cheers.test",
                "https://constable.test",
                1_500_000_000,
                1_400_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::Expired { .. }));
    }

    #[tokio::test]
    async fn rejects_bad_issuer() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        let token = mint_token(
            &kp.secret,
            "k1",
            good_payload(
                "https://wrong.example",
                "https://constable.test",
                2_000_000_000,
                1_700_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::BadIssuer { .. }));
    }

    #[tokio::test]
    async fn rejects_bad_audience() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        let token = mint_token(
            &kp.secret,
            "k1",
            good_payload(
                "https://cheers.test",
                "https://wrong-constable.example",
                2_000_000_000,
                1_700_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::BadAudience { .. }));
    }

    #[tokio::test]
    async fn rejects_token_without_footer() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        // Mint a token with no footer at all (signature still valid against
        // the JWKS key — what fails is the lookup, because we cannot know
        // which key to verify against without a kid).
        let payload = good_payload(
            "https://cheers.test",
            "https://constable.test",
            2_000_000_000,
            1_700_000_000,
            "user:abc",
            &["cloud:read"],
        );
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let token = PublicToken::sign(&kp.secret, &payload_bytes, None, None).unwrap();
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::MissingKid), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_token_with_footer_missing_kid() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        // Footer is present but the kid field is missing — Deserialize fails
        // at the Footer struct, surfaced as Malformed("footer: ...").
        let payload = good_payload(
            "https://cheers.test",
            "https://constable.test",
            2_000_000_000,
            1_700_000_000,
            "user:abc",
            &["cloud:read"],
        );
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let token = PublicToken::sign(
            &kp.secret,
            &payload_bytes,
            Some(br#"{"other":"x"}"#),
            None,
        )
        .unwrap();
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(
            matches!(err, VerifyError::Malformed(ref m) if m.starts_with("footer:")),
            "got {err:?}"
        );
    }

    /// W159: out-of-band refresh on kid miss is rate-limited to ≤1 per
    /// `kid_miss_rate_limit` so attacker-controlled kid choices can't drive
    /// the AS into the ground. With AS unreachable in tests, both calls
    /// surface `UnknownKid`; what we verify is that the gate is set on the
    /// first attempt — observable by introspecting `kid_miss_last`.
    #[tokio::test]
    async fn kid_miss_refresh_is_rate_limited() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        let bad = |kid: &str| {
            mint_token(
                &kp.secret,
                kid,
                good_payload(
                    "https://cheers.test",
                    "https://constable.test",
                    2_000_000_000,
                    1_700_000_000,
                    "user:abc",
                    &["cloud:read"],
                ),
            )
        };
        // First miss spends the gate.
        let t1 = bad("k-miss-1");
        let _ = verifier.verify(&t1, 1_800_000_000).await;
        let gate_after_first = *verifier.kid_miss_last.lock().await;
        assert!(gate_after_first.is_some(), "gate must arm after first miss");

        // Second miss within the cooldown does not advance the gate (the
        // verifier returns early without calling refresh).
        let t2 = bad("k-miss-2");
        let _ = verifier.verify(&t2, 1_800_000_000).await;
        let gate_after_second = *verifier.kid_miss_last.lock().await;
        assert_eq!(
            gate_after_first, gate_after_second,
            "second kid-miss within cooldown must not re-arm the gate"
        );
    }

    #[tokio::test]
    async fn boot_no_cache_no_as_is_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_path = tmp.path().join("jwks.json");
        let config = AuthConfig::new(
            "http://127.0.0.1:1/",
            "https://constable.test",
        )
        .with_cache_path(cache_path);
        let result = AuthVerifier::boot(config).await;
        // `Result::unwrap_err` requires `T: Debug`; avoid that bound on
        // `AuthVerifier` by matching the result form directly.
        match result {
            Err(AuthError::BootFetchFatal { .. }) => {}
            Err(other) => panic!("expected BootFetchFatal, got {other:?}"),
            Ok(_) => panic!("expected boot failure with no cache + unreachable AS"),
        }
    }
}
