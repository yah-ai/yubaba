//! Cheers JWT verifier surface — local-only, no per-call AS round-trip.
//!
//! See `.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md`
//! §Canonical claim schema and §Kamaji startup and JWKS lifecycle. The
//! envelope is PASETO v4.public (W159 pinned 2026-06-03); `kid` rides in the
//! PASETO footer so the cache lookup is O(1) before signature verification.
//!
//! F2 scope: JWKS fetch + on-disk cache + atomic refresh + kid-miss refresh +
//! signature verification. Scope check, `owns:[...]` check, and the 401/403
//! response shapes are F3. The HTTPS server / JSON-RPC dispatch loop is later.

pub mod claims;
pub mod config;
pub mod deny;
pub mod error;
pub mod jwks;
pub mod metadata;
pub mod policy;
pub mod verifier;

pub use claims::{ActorClaim, AuthStrength, McpClaims, OwnsClaim};
pub use config::AuthConfig;
pub use deny::{Deny, DenyKind, DEFAULT_REALM};
pub use error::{AuthError, VerifyError};
pub use jwks::{JwkKey, JwksCache, JwksDoc};
pub use metadata::{ProtectedResourceMetadata, SCOPE_VOCABULARY};
pub use policy::{enforce, Requirement};
pub use verifier::AuthVerifier;
