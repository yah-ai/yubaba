//! In-process mock cheers AS — W159 §Development mode → Mode 1.
//!
//! Spawns an axum HTTP server on a random localhost port that serves cheers's
//! discovery endpoints (`/.well-known/jwks.json` and
//! `/.well-known/oauth-protected-resource`) backed by an ephemeral Ed25519
//! keypair generated at spawn time. The same keypair is used to mint PASETO
//! v4.public tokens directly through a Rust API ([`MockIssuer::mint`]) — the
//! daemon hands the issuer a claim block, gets back a token, calls kamaji
//! with it; kamaji fetches the mock JWKS like it would cheers's and
//! verifies through the production code path unchanged.
//!
//! What this crate is NOT: a stand-in for cheers's grant / OAuth dance / etc.
//! It only stubs the *verifier-facing* surface — the public-key publication
//! and the minting envelope. Anything cheers-side that kamaji doesn't read
//! at verify time (e.g. `/token`, passkey assertion) is out of scope.
//!
//! ## Refusing the bypass
//!
//! `YAH_AUTH=off` is rejected at parse time per W159 §Not supported. Use
//! [`AuthMode::from_env`] to read the env-var triple — it returns
//! [`AuthModeError::BypassRefused`] on any unknown / `off` value.

pub mod env;
pub mod mock_issuer;

pub use env::{AuthMode, AuthModeError};
pub use mock_issuer::{ambient_user_dev_claims, MockConfig, MockIssuer, MockIssuerError};
