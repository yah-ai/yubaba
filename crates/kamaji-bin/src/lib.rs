//! Kamaji — process supervisor sibling to Yubaba.
//!
//! This crate is a lib + bin. The library exposes the [`server`] surface so
//! integration tests can drive Kamaji in-process; the binary is a thin
//! single-threaded tokio runtime that calls [`server::serve`].
//!
//! Backend drivers (cgroup, fork+exec, pidfd, containerd) land in R406-T4
//! through R406-T7; this crate currently exposes only the wire skeleton.
//!
//! @arch:see(.yah/docs/working/W154-yubaba-dual-runtime.md)
//!
//! @yah:relay(R426, "JWT contract + verifier core (kamaji)")
//! @yah:at(2026-06-03T22:42:02Z)
//! @yah:status(open)
//! @yah:phase(P1)
//! @yah:parent(Q425)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//!
//! @yah:ticket(R426-F2, "Kamaji JWKS cache + signature verification (first-start, rotation, kid-miss refresh)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T22:46:00Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R426)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426-F1)
//! @yah:next("Verify: `cargo test -p kamaji --locked --lib auth::` (22 pass), `cargo test -p kamaji --locked` (107 + 1 pass), `cargo check -p kamaji --locked --features containerd-integration` (clean modulo pre-existing pidfd warning).")
//! @yah:next("R426-F3 unblocks: scope check + ownership-list check + canonical 401/403 + `WWW-Authenticate: Bearer ... resource_metadata=...` bodies — `AuthVerifier::verify` returns `McpClaims` with `scope: Vec<String>` + `owns: Option<OwnsClaim>` (with `contains(kind, id)` helper) for F3 to consume.")
//! @yah:next("R426-F4 (well-known endpoint) and R426-F5 (dev mock issuer) unblock similarly.")
//! @yah:next("Cross-side ask: ping cheers maintainer to confirm `mcp-auth-and-ownership.md` § 'Wire envelope' should now read 'PASETO v4.public (pinned by R426-F2, 2026-06-03)' and that `exp`/`iat` are i64 Unix seconds (not RFC3339) for MCP-call tokens — the cheers-side mint path needs the low-level `PublicToken::sign` call too, not `pasetors::public::sign`.")
//! @yah:next("Non-blocking polish (defer until F3+ surfaces it): background refresh task is built but `spawn_refresh_task` is not wired into the kamaji main loop yet (no `Arc<AuthVerifier>` in `ServerCtx` until the hub-cheers-rpc adapter lands in R426-F6); stale-cache restart branch is logic-tested but not test-covered (would need a clock-injection refactor of `last_refresh` to drive without sleeping).")
//! @yah:handoff("F2 landed in `app/yah/kamaji/src/auth/` (six modules: `mod`, `config`, `claims`, `error`, `jwks`, `verifier`). Wire envelope decision: PASETO v4.public (matches cheers's session-token envelope; resolves W159 §Open questions → 'Wire envelope' in favour of consistency with `cheers-verify`). Service principals also publish their Ed25519 pubkey in the same JWKS so one cache + one verify path handles cheers's signing key + every service key uniformly (R426-F1 contract).")
//! @yah:handoff("The verify path uses the low-level `pasetors::version4::PublicToken::sign/verify` with raw payload bytes, NOT the high-level `pasetors::public::sign/verify`. Reason: the high-level path routes the payload through `pasetors::claims::Claims::from_string`, which rejects any registered claim (`iss`/`sub`/`aud`/`exp`/`iat`/`jti`/`nbf`) that isn't a string — incompatible with the W159 canonical schema's i64 Unix-seconds `exp`/`iat`. The signature + footer-binding check is byte-identical between the two entry points (the high level wraps the low level), so we get full PAE security without the RFC3339 chokepoint.")
//! @yah:handoff("JWKS lifecycle: `JwksCache::load_from_disk` (NotFound → Ok(None)), `JwksCache::from_doc` (skips non-OKP/Ed25519, hard-fails on broken Ed25519 entry), `JwksCache::write_atomic` (temp + rename, creates parent). Boot state machine in `AuthVerifier::boot`: cache-fresh → load; cache-stale → sync refresh, fall back to stale-on-fail when `serve_stale_on_failure`; cache-missing → fatal `BootFetchFatal` if AS unreachable. Steady-state `refresh()` is callable directly and from the background ticker (`spawn_refresh_task`). Kid-miss out-of-band refresh via `try_kid_miss_refresh` — gated by `kid_miss_rate_limit` (default 1s) using `Mutex<Option<Instant>>`; gate is set BEFORE the network round-trip so concurrent kid-misses don't pile up.")
//! @yah:handoff("Standard-claim checks in `verify` (W159 Layer 1 only): `iss` exact match, `aud` exact match, `exp > now`. Scope + ownership-list check stays for R426-F3. Cargo.toml adds `pasetors 0.7 [serde]`, `reqwest 0.12 [json, rustls-tls]`, `base64ct 1 [alloc]`, `serde 1 [derive]` — all permissive (MIT or Apache-2.0). `containerd-client` + `prost-types` got version bumps along the way; pre-existing `pidfd.rs:123` dead_code warning is unrelated.")
//! @yah:handoff("Test coverage 22 in `auth::` (107 total `kamaji` lib tests + 1 integration green): claims round-trip (required-only + all-fields + principal-kind parse); config (jwks_url normalisation + defaults); jwks (parse OKP/Ed25519, skip foreign kty, reject broken entry + wrong length, atomic disk round-trip + parent-dir creation + load-NotFound); verifier (happy path, unknown-kid, signature mismatch, expired, bad iss, bad aud, missing footer = MissingKid, malformed footer = Malformed, boot-no-cache-no-AS = BootFetchFatal, kid-miss rate-limit gate behaviour).")
//! @yah:verify("cargo test -p kamaji --locked --lib auth::")
//! @yah:verify("cargo test -p kamaji --locked")
//! @yah:verify("cargo check -p kamaji --locked --features containerd-integration")

pub mod auth;
pub mod cgroup;
#[cfg(feature = "containerd-integration")]
pub mod containerd;
pub mod drain;
pub mod journal;
pub mod native;
pub mod pidfd;
pub mod probe;
pub mod server;

pub use auth::{
    ActorClaim, AuthConfig, AuthError, AuthStrength, AuthVerifier, JwksCache, JwksDoc, McpClaims,
    OwnsClaim, VerifyError,
};

pub use cgroup::{CgroupError, CgroupHandle, CgroupV2, DEFAULT_SLICE_ROOT};
pub use drain::{enforce_drain, DrainError, SIGKILL_SAFETY_WINDOW};
pub use journal::{
    build_journal_payload, forward_reader, JournalSender, LogPriority, LogSink, Stream,
    JOURNALD_SOCKET, MAX_MESSAGE_LEN,
};
pub use native::{
    spawn as spawn_native, LandlockAccess, LandlockPolicy, LandlockRule, NativeChild, SandboxPlan,
    SpawnError, UserGroup,
};
pub use pidfd::{pidfd_open, ExitEvent, PidfdError, PidfdReaper, PidfdReaperHandle};
pub use probe::{run_probe, ProbeTarget};
pub use server::{
    serve, serve_with_ctx, serve_with_shutdown, DrainableHandle, Registry, ServerCtx,
    CONSTABLE_VERSION,
};
