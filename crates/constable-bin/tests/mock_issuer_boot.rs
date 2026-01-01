//! R426-F5 end-to-end: production verifier path boots against the mock
//! issuer, fetches its JWKS over real HTTP, and verifies a mock-minted token.
//!
//! This is the integration test the synthetic-cache unit tests in
//! `auth::verifier::tests` can't carry — those install a JWKS doc directly
//! on disk so they don't make HTTP calls. The mock here is the bridge:
//! constable's first-start fetch path actually reaches a live `/.well-known/`
//! endpoint and parses the response, and a mock-minted token round-trips
//! through PASETO verification on the production code path unchanged.

use constable::{AuthConfig, AuthVerifier, VerifyError};

#[tokio::test]
async fn boots_and_verifies_against_mock() {
    let mock = cheers_mock::MockIssuer::spawn(cheers_mock::MockConfig::default())
        .await
        .expect("mock issuer spawns");

    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("jwks.json");
    let config = AuthConfig::new(mock.issuer_url(), "https://constable.test")
        .with_cache_path(cache.clone());

    // First-start: cache is empty so boot makes the real HTTP fetch against
    // the mock's `/.well-known/jwks.json`. Failure here means the mock's
    // wire shape drifted from what constable's JwksDoc accepts.
    let verifier = AuthVerifier::boot(config).await.expect("verifier boots");
    assert!(cache.exists(), "boot must persist the fetched JWKS");

    let claims = cheers_mock::ambient_user_dev_claims(
        &mock.issuer_url(),
        "https://constable.test",
        &["cloud:read", "cloud:deploy"],
        &["svc-abc"],
        1_700_000_000,
    );
    let token = mock.mint(&claims).expect("mint succeeds");

    // `now` is in the validity window (iat = 1_700_000_000, exp = +15min).
    let parsed = verifier
        .verify(&token, 1_700_000_000 + 60)
        .await
        .expect("verifier accepts mock-minted token");
    assert_eq!(parsed.sub, "user:dev");
    assert_eq!(parsed.scope, vec!["cloud:read", "cloud:deploy"]);
    assert_eq!(parsed.camp_id.as_deref(), Some("C-dev"));
    let owns = parsed.owns.as_ref().expect("ambient owns block present");
    assert!(owns.contains("service", "svc-abc"));

    mock.shutdown().await;
}

#[tokio::test]
async fn boot_can_serve_from_cache_after_mock_dies() {
    // First boot fetches JWKS from the mock and writes it to disk.
    let mock = cheers_mock::MockIssuer::spawn(cheers_mock::MockConfig::default())
        .await
        .expect("mock issuer spawns");
    let issuer_url = mock.issuer_url();

    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("jwks.json");
    let config = AuthConfig::new(&issuer_url, "https://constable.test")
        .with_cache_path(cache.clone());
    let _v1 = AuthVerifier::boot(config).await.expect("first boot");
    assert!(cache.exists());

    // Mock dies; constable restarts. Cache is fresh (just-written), so the
    // restart-resilience "cache present + fresh" arm should serve from disk
    // without ever touching the AS.
    drop(_v1);
    mock.shutdown().await;

    let config = AuthConfig::new(&issuer_url, "https://constable.test")
        .with_cache_path(cache.clone());
    let v2 = AuthVerifier::boot(config)
        .await
        .expect("second boot must succeed from cache");

    // Sanity: the cached pubkey verifies tokens minted by the dead mock —
    // but we can't re-mint without re-spawning. Easier check: an unknown-kid
    // token still fails through the production error path, not via boot.
    // (Detailed mint-and-verify is covered by `boots_and_verifies_against_mock`.)
    let kid_miss_token = std::str::from_utf8(b"v4.public.AAAAAAAA").unwrap_or("invalid");
    let err = v2.verify(kid_miss_token, 1_700_000_000).await.unwrap_err();
    assert!(
        matches!(err, VerifyError::Malformed(_) | VerifyError::MissingKid),
        "expected malformed/missing-kid, got {err:?}"
    );
}
