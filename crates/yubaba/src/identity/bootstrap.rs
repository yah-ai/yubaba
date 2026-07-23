//! Bootstrap-token validation core for the authenticated node-admission
//! ceremony (R593-F8, W268 §"Fleet machine" binding ceremony — INTERIM).
//!
//! ## Threat model / why this exists
//!
//! `POST /register-hostkey` (lib.rs, bound `0.0.0.0:7443` by default) has no
//! auth and no proof-of-possession, yet R593-F4 wired it into `admit_node` →
//! an `ownership:write` into cheers's ledger under yubaba's trusted service
//! principal. Any network-reachable caller can self-generate a keypair and
//! get `svc:<operator> owns node:<attacker-id>` durably written — exactly
//! the wrongly-present row R593-F6's token binding is meant to trust.
//!
//! The SANCTIONED endgame (W268) is moving admission onto the mshr QUIC
//! transport, where mutual machine auth is intrinsic (R593-T7 / R277 /
//! R570 — parked by design; do not implement around it). This module is the
//! sanctioned INTERIM: an **operator-issued provisioning bootstrap token**.
//! The provisioning flow (yubaba leader / operator tooling) mints a token at
//! node-create time and drops it into the node's cloud-init user-data; the
//! node presents it on `POST /register-hostkey`; the endpoint admits the
//! hostkey only when the token validates. The token authorizes the
//! **enroller** — proof-of-possession of the hostkey alone is insufficient,
//! because an attacker trivially holds their own self-generated key.
//!
//! ## Semantics
//!
//! - **Mint**: 32 bytes from the OS CSPRNG, encoded `ybt1_<base64url>` (the
//!   versioned prefix makes tokens greppable for log-redaction tooling and
//!   future format migration). Minting takes a TTL and an optional
//!   `node_hint` (e.g. the provider server id / hostname the operator is
//!   provisioning) that comes back to the caller on consume for
//!   cross-checking and audit.
//! - **Storage**: the registry keeps only the SHA-256 of the token, never
//!   the token itself — a state/heap dump of the daemon does not yield
//!   presentable tokens. Lookup is by hash-map key, so there is no
//!   value-dependent comparison loop to time.
//! - **Expiry**: `expires_at <= now` is expired (same convention as cheers's
//!   `Claims::is_expired_at`). Provisioning TTLs are minutes-scale — the
//!   token only needs to survive cloud-init boot.
//! - **Single-use**: the first successful validation consumes the token
//!   atomically (one `Mutex` guard covers lookup + consume, so two racing
//!   presenters cannot both win). A second presentation fails.
//!
//! The typed [`BootstrapTokenError`] variants exist for **internal audit
//! logging only** — the HTTP endpoint must collapse all of them to one
//! undifferentiated `401`, so a network probe cannot distinguish
//! "never existed" from "expired" from "already used".
//!
//! This is a plain in-process unit (no HTTP, no transport imports) so the
//! endpoint wiring — which lives in the R592-T4-churned lib.rs, a different
//! lane — can be a thin call-through once that lane clears.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Version prefix on every minted token. Bump (`ybt2_…`) on any format
/// change so mixed fleets can be told apart in logs.
pub const BOOTSTRAP_TOKEN_PREFIX: &str = "ybt1_";

/// Raw entropy per token, before encoding. 256 bits — brute-force infeasible
/// within any TTL.
pub const BOOTSTRAP_TOKEN_BYTES: usize = 32;

/// Default mint TTL: 15 minutes. The token only has to survive "provider
/// creates server" → "cloud-init runs" → "yubaba boots and self-registers";
/// on the observed providers that is single-digit minutes. Callers with
/// slower providers pass their own TTL to [`BootstrapTokenRegistry::mint`].
pub const DEFAULT_BOOTSTRAP_TTL_SECONDS: i64 = 15 * 60;

/// A freshly minted bootstrap token. `token` is the ONLY copy of the
/// presentable secret — the registry keeps just its hash. Hand it to the
/// provisioning path (cloud-init user-data) and drop it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MintedBootstrapToken {
    /// The presentable secret, `ybt1_<base64url-no-pad of 32 bytes>`.
    pub token: String,
    /// Unix-seconds mint time, as passed to `mint`.
    pub issued_at: i64,
    /// Unix-seconds expiry (`issued_at + ttl`).
    pub expires_at: i64,
}

/// What a successful [`BootstrapTokenRegistry::validate_and_consume`]
/// returns — the audit context the mint call stashed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConsumedBootstrapToken {
    /// The `node_hint` supplied at mint time (provider server id /
    /// hostname), for endpoint-side cross-checks and audit logs.
    pub node_hint: Option<String>,
    /// When the consumed token was minted.
    pub issued_at: i64,
}

/// Why a presented token failed validation.
///
/// INTERNAL granularity only — see the module doc: the HTTP layer must
/// collapse every variant into one undifferentiated 401.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BootstrapTokenError {
    /// Never minted here (or malformed / tampered — anything whose hash has
    /// no record). Also returned for records already purged.
    #[error("unknown bootstrap token")]
    Unknown,
    /// Minted, but `expires_at <= now`. Checked BEFORE the consumed flag —
    /// a replay of a consumed token after its expiry reads as Expired.
    #[error("bootstrap token expired")]
    Expired,
    /// Minted and still within TTL, but already consumed by an earlier
    /// successful validation — the single-use guarantee. Worth alerting on
    /// in audit logs: someone presented a token that was already spent.
    #[error("bootstrap token already used")]
    AlreadyUsed,
}

#[derive(Debug)]
struct TokenRecord {
    issued_at: i64,
    expires_at: i64,
    consumed_at: Option<i64>,
    node_hint: Option<String>,
}

/// In-process registry of outstanding bootstrap tokens.
///
/// Interim scope note: process-local on purpose. Admission is served by the
/// same yubaba process that runs provisioning, so mint and validate share
/// one registry; a daemon restart drops outstanding tokens, which fails
/// safe — the operator re-runs provisioning (same recovery story as F4's
/// process-local `ownership_rows` map). Durable storage would only widen
/// the window a stolen state file is useful for.
#[derive(Debug, Default)]
pub struct BootstrapTokenRegistry {
    inner: Mutex<HashMap<[u8; 32], TokenRecord>>,
}

impl BootstrapTokenRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh single-use token valid for `ttl_seconds` from `now`.
    ///
    /// `node_hint` is free-form audit context (provider server id,
    /// hostname); it is returned by the consuming validation, never matched
    /// against anything here — cross-checking it against the presenting
    /// caller is the endpoint's decision.
    pub fn mint(
        &self,
        now: i64,
        ttl_seconds: i64,
        node_hint: Option<&str>,
    ) -> MintedBootstrapToken {
        let mut raw = [0u8; BOOTSTRAP_TOKEN_BYTES];
        OsRng.fill_bytes(&mut raw);
        let token = format!(
            "{BOOTSTRAP_TOKEN_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        );
        let record = TokenRecord {
            issued_at: now,
            expires_at: now + ttl_seconds,
            consumed_at: None,
            node_hint: node_hint.map(str::to_owned),
        };
        let expires_at = record.expires_at;
        self.inner
            .lock()
            .expect("bootstrap token registry poisoned")
            .insert(hash_token(&token), record);
        MintedBootstrapToken {
            token,
            issued_at: now,
            expires_at,
        }
    }

    /// Validate `presented` at `now` and, on success, consume it atomically
    /// (single `Mutex` guard across lookup + consume — two racing presenters
    /// cannot both succeed).
    ///
    /// Check order (pinned by tests): unknown → expired → already-used.
    /// Consumed records are retained (not deleted) until [`purge`] so a
    /// replay yields the distinguishable-for-audit `AlreadyUsed` rather
    /// than decaying into `Unknown`.
    ///
    /// [`purge`]: Self::purge
    pub fn validate_and_consume(
        &self,
        presented: &str,
        now: i64,
    ) -> Result<ConsumedBootstrapToken, BootstrapTokenError> {
        let mut g = self
            .inner
            .lock()
            .expect("bootstrap token registry poisoned");
        let record = g
            .get_mut(&hash_token(presented))
            .ok_or(BootstrapTokenError::Unknown)?;
        if record.expires_at <= now {
            return Err(BootstrapTokenError::Expired);
        }
        if record.consumed_at.is_some() {
            return Err(BootstrapTokenError::AlreadyUsed);
        }
        record.consumed_at = Some(now);
        Ok(ConsumedBootstrapToken {
            node_hint: record.node_hint.clone(),
            issued_at: record.issued_at,
        })
    }

    /// Drop expired and consumed records; returns how many were removed.
    /// Call opportunistically (e.g. from mint, or a periodic tick) — the
    /// registry is small (one record per in-flight provisioning), so this
    /// is hygiene, not a scaling requirement.
    pub fn purge(&self, now: i64) -> usize {
        let mut g = self
            .inner
            .lock()
            .expect("bootstrap token registry poisoned");
        let before = g.len();
        g.retain(|_, r| r.consumed_at.is_none() && r.expires_at > now);
        before - g.len()
    }

    /// Count of live (unconsumed, unexpired) tokens at `now`.
    pub fn outstanding(&self, now: i64) -> usize {
        self.inner
            .lock()
            .expect("bootstrap token registry poisoned")
            .values()
            .filter(|r| r.consumed_at.is_none() && r.expires_at > now)
            .count()
    }
}

fn hash_token(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    digest.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn mint_produces_prefixed_high_entropy_unique_tokens() {
        let reg = BootstrapTokenRegistry::new();
        let a = reg.mint(NOW, DEFAULT_BOOTSTRAP_TTL_SECONDS, None);
        let b = reg.mint(NOW, DEFAULT_BOOTSTRAP_TTL_SECONDS, None);

        for t in [&a, &b] {
            assert!(t.token.starts_with(BOOTSTRAP_TOKEN_PREFIX), "{}", t.token);
            let body = &t.token[BOOTSTRAP_TOKEN_PREFIX.len()..];
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(body)
                .expect("token body is base64url-no-pad");
            assert_eq!(decoded.len(), BOOTSTRAP_TOKEN_BYTES);
            assert_eq!(t.issued_at, NOW);
            assert_eq!(t.expires_at, NOW + DEFAULT_BOOTSTRAP_TTL_SECONDS);
        }
        assert_ne!(a.token, b.token, "two mints must never collide");
        assert_eq!(reg.outstanding(NOW), 2);
    }

    #[test]
    fn happy_path_validates_once_and_returns_the_mint_context() {
        let reg = BootstrapTokenRegistry::new();
        let minted = reg.mint(NOW, 600, Some("hetzner-srv-42"));

        let consumed = reg
            .validate_and_consume(&minted.token, NOW + 60)
            .expect("fresh token validates");
        assert_eq!(consumed.node_hint.as_deref(), Some("hetzner-srv-42"));
        assert_eq!(consumed.issued_at, NOW);
        assert_eq!(
            reg.outstanding(NOW + 60),
            0,
            "consumed token is no longer live"
        );
    }

    #[test]
    fn second_presentation_is_already_used() {
        let reg = BootstrapTokenRegistry::new();
        let minted = reg.mint(NOW, 600, None);

        reg.validate_and_consume(&minted.token, NOW + 1).unwrap();
        let err = reg
            .validate_and_consume(&minted.token, NOW + 2)
            .expect_err("single-use: second presentation fails");
        assert_eq!(err, BootstrapTokenError::AlreadyUsed);
    }

    #[test]
    fn expiry_boundary_is_exclusive_of_expires_at() {
        let reg = BootstrapTokenRegistry::new();
        let minted = reg.mint(NOW, 600, None);

        // One second before expiry: fine. (Fresh token per case — consume
        // would otherwise interfere.)
        reg.validate_and_consume(&minted.token, NOW + 599).unwrap();

        let late = reg.mint(NOW, 600, None);
        // Exactly expires_at: expired (exp <= now convention).
        let err = reg
            .validate_and_consume(&late.token, NOW + 600)
            .unwrap_err();
        assert_eq!(err, BootstrapTokenError::Expired);
        // And after.
        let err = reg
            .validate_and_consume(&late.token, NOW + 601)
            .unwrap_err();
        assert_eq!(err, BootstrapTokenError::Expired);
    }

    #[test]
    fn consumed_then_expired_reads_expired_check_order_pin() {
        // Pin the documented check order: expiry is evaluated before the
        // consumed flag, so replaying a consumed token after expiry is
        // Expired, not AlreadyUsed.
        let reg = BootstrapTokenRegistry::new();
        let minted = reg.mint(NOW, 600, None);
        reg.validate_and_consume(&minted.token, NOW + 1).unwrap();
        let err = reg
            .validate_and_consume(&minted.token, NOW + 601)
            .unwrap_err();
        assert_eq!(err, BootstrapTokenError::Expired);
    }

    #[test]
    fn unknown_tampered_and_garbage_tokens_are_unknown() {
        let reg = BootstrapTokenRegistry::new();
        let minted = reg.mint(NOW, 600, None);

        // Never minted.
        assert_eq!(
            reg.validate_and_consume("ybt1_deadbeef", NOW).unwrap_err(),
            BootstrapTokenError::Unknown
        );
        // Tampered: flip the last character of a real token.
        let mut tampered = minted.token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            reg.validate_and_consume(&tampered, NOW).unwrap_err(),
            BootstrapTokenError::Unknown
        );
        // Garbage / empty — no panic, just Unknown.
        assert_eq!(
            reg.validate_and_consume("", NOW).unwrap_err(),
            BootstrapTokenError::Unknown
        );
        assert_eq!(
            reg.validate_and_consume("not-even-prefixed", NOW)
                .unwrap_err(),
            BootstrapTokenError::Unknown
        );
        // The real token is still live and consumable — failed probes must
        // not burn it.
        reg.validate_and_consume(&minted.token, NOW).unwrap();
    }

    #[test]
    fn tokens_are_independent_consuming_one_leaves_the_other_live() {
        let reg = BootstrapTokenRegistry::new();
        let a = reg.mint(NOW, 600, Some("node-a"));
        let b = reg.mint(NOW, 600, Some("node-b"));

        let got = reg.validate_and_consume(&a.token, NOW + 1).unwrap();
        assert_eq!(got.node_hint.as_deref(), Some("node-a"));
        assert_eq!(reg.outstanding(NOW + 1), 1);

        let got = reg.validate_and_consume(&b.token, NOW + 2).unwrap();
        assert_eq!(got.node_hint.as_deref(), Some("node-b"));
        assert_eq!(reg.outstanding(NOW + 2), 0);
    }

    #[test]
    fn purge_drops_expired_and_consumed_keeps_live() {
        let reg = BootstrapTokenRegistry::new();
        let consumed = reg.mint(NOW, 600, None);
        let _expired = reg.mint(NOW, 10, None);
        let live = reg.mint(NOW, 600, None);
        reg.validate_and_consume(&consumed.token, NOW + 1).unwrap();

        let removed = reg.purge(NOW + 60); // consumed + the 10s TTL one
        assert_eq!(removed, 2);
        assert_eq!(reg.outstanding(NOW + 60), 1);

        // The purged consumed token now reads Unknown (record gone) — the
        // AlreadyUsed audit signal only survives until purge, documented on
        // validate_and_consume.
        assert_eq!(
            reg.validate_and_consume(&consumed.token, NOW + 61)
                .unwrap_err(),
            BootstrapTokenError::Unknown
        );
        // The live one still validates.
        reg.validate_and_consume(&live.token, NOW + 61).unwrap();
    }

    #[test]
    fn racing_consumers_only_one_wins() {
        // The single-Mutex guarantee under actual thread contention: N
        // threads present the same token; exactly one Ok.
        use std::sync::Arc;
        let reg = Arc::new(BootstrapTokenRegistry::new());
        let minted = reg.mint(NOW, 600, None);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let reg = reg.clone();
            let token = minted.token.clone();
            handles.push(std::thread::spawn(move || {
                reg.validate_and_consume(&token, NOW + 1).is_ok()
            }));
        }
        let wins: usize = handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum();
        assert_eq!(wins, 1, "exactly one presenter may consume the token");
    }
}
