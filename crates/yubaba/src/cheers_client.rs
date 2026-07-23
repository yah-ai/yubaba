//! Privileged cheers client (R427-F1, W159 Phase 2).
//!
//! Yubaba is the **fleet-path** writer of cheers's ownership table: on
//! successful workload provision it `register_ownership(camp, kind, id,
//! on_behalf_of=user)`; on destroy it `revoke_ownership(row_id)`. Camps and
//! agents have no path into these writes — kamaji's `audit:write` scope is
//! deliberately split from yubaba's `ownership:write` so colocating kamaji on
//! a yubaba host doesn't leak ownership-write authority (W159 §Scope
//! vocabulary). The **device path** — LAN-pair enrolling a paired end-user
//! device to the pairing account (W268 §binding ceremonies) — is a separate
//! writer that lands under R593-F9 (server-mediated, no client secret); it is
//! not this client and does not share yubaba's service-principal key.
//!
//! ## Auth shape
//!
//! Per W159 §Service principals + the cheers producer spec §Service principal
//! bootstrap: yubaba holds an Ed25519 keypair allocated at install time
//! (`yubaba install` → `POST /admin/service-principals` → secret half written
//! once to yubaba's config dir, mode 0600). Cheers publishes the pubkey in its
//! JWKS so any verifier (cheers's own `/ownership` route, kamaji) can verify
//! yubaba-minted tokens through the same JWKS path it uses for cheers-minted
//! tokens — no separate fetch path.
//!
//! Tokens are PASETO v4.public, **minted locally** by yubaba — `sub: svc:<id>`,
//! `scope: ["ownership:write"]`, `aud: <cheers issuer URL>` (cheers verifies its
//! own routes' tokens against itself), 5-minute TTL per W159 §TTLs. Local
//! minting means yubaba keeps writing ownership even during brief cheers API
//! blips — the request still 5xxs at the cheers HTTP layer, but the auth path
//! never round-trips, so an outage on cheers's mint endpoint can't paralyze
//! yubaba's writes.
//!
//! ## Wire shape (cheers producer spec)
//!
//! - `POST /ownership` with `Authorization: Bearer <token>` and JSON body
//!   `{principal_id, resource_kind, resource_id, relationship, on_behalf_of?}`.
//!   `granted_by` is filled from the token's verified `sub` server-side — the
//!   client cannot impersonate a different service principal even with a
//!   valid `ownership:write` token (defense-in-depth at the cheers handler).
//!   Returns `201 Created` + `OwnershipRow{id, ...}`. The `id` is what yubaba
//!   stores to call `DELETE` later.
//! - `DELETE /ownership/{id}` — soft-deletes (sets `revoked_at`). Idempotent.
//!
//! See `external/cheers/.yah/docs/working/mcp-auth-and-ownership.md`
//! §Ownership table + `external/cheers/crates/cheers-axum/src/ownership.rs`
//! for the authoritative producer side.
//!
//! @yah:ticket(R593-F4, "node resource kind + admission enrollment write: fleet machine = device owned by the operator service principal")
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:at(2026-07-02T21:32:14Z)
//! @yah:phase(P3)
//! @yah:parent(R593)
//! @yah:next("Add the node resource kind to the owns[] vocabulary and make yubaba admission write the enrollment row: register_ownership(principal=<operator svc>, kind=node, id=<NodeId>) on node admission, revoke_ownership on node removal/eviction (eviction removes rows, never the key — W268 §two axes). The NodeId enrolled must be the collapsed mshr identity from T2. cheers_client.rs is already the ONLY ownership writer (W159) — extend it, do not add a second writer path.")
//! @yah:verify("cargo test -p yubaba; fixture: admission produces an ownership row (kind=node, id=NodeId); removal revokes it")
//! @yah:depends_on(R593-T2)
//! @yah:tier(Warrior)
//! @yah:handoff("Added the node resource kind to cheers's owns[] vocabulary (Owns.node field in cheers-core/src/mcp.rs + the \"node\" match arm in cheers-server's rows_to_owns), then wired yubaba's admission enrollment write through two new CheersClient wrapper methods (enroll_node/evict_node in cheers_client.rs, fixing resource_kind=node/relationship=owns) called from two new ServerState methods (admit_node/evict_node in lib.rs). admit_node is invoked from the POST /register-hostkey handler — chosen as the admission seam over ServerState::load's R092-F8 self-generate-at-boot branch because that branch runs sync, before a cheers_client exists in the builder chain. evict_node is implemented as a standalone callable (not wired to any handler — yubaba has no node-removal/decommission/raft-eviction route yet) with a doc comment pointing at where a future removal flow should hook it; it never touches the on-disk hostkey/NodeId, only the cheers row (W268 two-axes rule). 8 new fixture tests added (2 in cheers_client.rs, 6 in lib.rs) proving: admission posts principal=svc:<own principal>, kind=node, resource_id=the same mshr NodeId /identity reports; no-cheers-client and no-identity no-op paths; eviction revokes by row id without touching identity; eviction-without-prior-enrollment no-op. Full verify green: cargo test -p yubaba (119 lib + 3 integration + 1 pond, 0 failed), cargo check -p yubaba clean, cargo check --workspace + cargo test --workspace in oss/cheers all clean (no --locked used anywhere, no git writes, no new @yah: annotations added to cheers files, existing annotations preserved verbatim).")
//! @yah:handoff("COMPLETE incl. two review rounds. Core: node resource kind in cheers owns[] vocabulary (Owns.node field in cheers-core/src/mcp.rs + node arm in cheers-server rows_to_owns); yubaba admission writes the enrollment row from the POST /register-hostkey handler via ServerState::admit_node -> CheersClient::enroll_node (svc:<operator principal> owns node:<mshr NodeId hex>, on_behalf_of=None); eviction via ServerState::evict_node (callable, unwired — no removal route exists; hook-note in its rustdoc points future decommission/raft-remove work at it). Review-round hardening: (1) POST /ownership is now idempotent (cheers-axum ownership.rs create pre-queries list_for_principal; identical live row -> 200 existing, fresh -> 201; residual concurrent race documented as harmless set-membership); (2) admission guard is IDENTITY-AWARE — ServerState.node_enrollment holds a NodeEnrollment{node_id,row_id} pair, same-NodeId re-admission is a local no-op, hostkey ROTATION enrolls the new NodeId then revokes the stale row so the ledger converges on the current identity; (3) evict_node has a post-restart LOOKUP FALLBACK — when the in-memory pair is gone it lists live rows via the new GET /ownership?principal_id= route (added to cheers-axum, gated on ownership:write as the writer's management read; CheersClient::list_ownership is the client leg) and revokes ALL live kind=node rows matching the current NodeId, clearing historical duplicates; (4) rows_to_owns dedups (kind,resource_id) via push_unique across all arms. Known-latent: admit/evict mutex-drop-before-await interleave documented in evict_node rustdoc — belongs to whoever wires decommission (serialize there). NOT touched per coordinator: /register-hostkey auth posture (R593-F8, gated). Tests 14 new total: cheers_client enroll/evict wrappers; register-hostkey admission shape + NodeId round-trip; double-register single-enroll; restart re-admission converges on one row; ROTATION test (new NodeId enrolled, old row revoked, one live row); restart-eviction fallback test (revokes all matching rows incl. planted duplicate); no-client/no-identity no-ops; cheers-axum duplicate-POST idempotency (201->200 same id->post-revoke fresh 201) + GET list test (live-only, principal-filtered, 403 without scope); rows_to_owns dedup test. Verify green: cargo test -p yubaba = 123 lib + 3 integration + 1 pond, 0 failed; cargo check -p yubaba clean; cargo test --workspace + cargo check --workspace in oss/cheers all green (after peer R592-B7's verify_mcp_at kid migration landed — their mcp.rs sweep, not touched by me). No git writes, no new .md, no @yah: annotations in cheers files, peer-owned files untouched, no --locked.")

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pasetors::keys::AsymmetricSecretKey;
use pasetors::version4::{PublicToken, V4};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Token TTL for yubaba's ownership-write calls. Bottom of the W159 §TTLs
/// access-token band (5–15 min) — these calls are short, atomic, and minted
/// per-request, so a long TTL buys nothing and just widens the replay window
/// on a leaked transport-level capture.
const TOKEN_TTL_SECS: i64 = 5 * 60;

/// Canonical `resource_kind` for node-enrollment ownership rows (R593-F4,
/// W268 §"The binding: enrollment is an ownership row"). A row
/// `principal owns node:<NodeId>` records that a machine (fleet node or
/// paired end-user device) is enrolled to `principal`. `resource_id` is
/// the mshr `NodeId`, hex-encoded the same way yubaba's `/identity` route
/// serves it (`identity::node_id_hex`, R593-T2). Kept as a constant here —
/// `CheersClient` is the fleet-path ownership writer — so every admission
/// call site shares one spelling of the wire string instead of
/// hand-rolling `"node"` at each call site. The device-path writer (R593-F9,
/// LAN-pair) keeps its own copy of this literal in `cheers` (which cannot
/// depend on `yubaba`); the two are pinned equal by W268, not by shared code.
pub const NODE_RESOURCE_KIND: &str = "node";

/// Errors surfaced by [`CheersClient`] calls.
#[derive(Debug, thiserror::Error)]
pub enum CheersError {
    /// PASETO mint failed. Almost always indicates the secret half on disk
    /// is malformed (wrong length, wrong format) — operator should re-run
    /// `yubaba install --rotate` to provision a fresh keypair.
    #[error("paseto mint failed: {0:?}")]
    Mint(pasetors::errors::Error),

    /// HTTP transport failure — DNS, TCP, TLS, timeout. Distinct from
    /// `Status` so a caller can branch on "cheers is unreachable" vs
    /// "cheers rejected the request".
    #[error("cheers transport: {0}")]
    Http(#[from] reqwest::Error),

    /// Cheers returned a non-2xx status. Body (if any) is preserved verbatim
    /// — RFC 6750 error responses are stable and worth surfacing for audit.
    #[error("cheers returned {status}: {body}")]
    Status {
        status: reqwest::StatusCode,
        body: String,
    },

    /// Response body didn't decode as the expected shape — almost always a
    /// cheers-side wire-contract drift bug.
    #[error("cheers response decode: {0}")]
    Decode(String),
}

/// Configuration for [`CheersClient`]. All fields are sourced from the
/// install-time service-principal bootstrap (W159 §Service principals).
#[derive(Debug, Clone)]
pub struct CheersConfig {
    /// Cheers issuer URL, e.g. `https://cheers.yah.cloud`. Used as both
    /// `iss` and `aud` on minted tokens — cheers verifies its own
    /// ownership-write routes against itself.
    pub issuer_url: String,
    /// Service-principal id, e.g. `yubaba-prod-1`. Becomes the token's
    /// `sub` field (prefixed `svc:` on the wire per the canonical claim
    /// schema).
    pub principal_id: String,
    /// `kid` published in cheers's JWKS for yubaba's pubkey. Kamaji and
    /// cheers's own verifier read it from the PASETO footer to look up
    /// yubaba's pubkey.
    pub kid: String,
}

/// Privileged client for cheers's ownership-write endpoints. Holds the
/// service-principal secret + reusable HTTP client; thread-safe.
///
/// Construct once at yubaba startup via [`Self::new`] (reads the secret
/// from disk), then share via `Arc<CheersClient>` across handlers.
pub struct CheersClient {
    config: CheersConfig,
    secret: AsymmetricSecretKey<V4>,
    http: reqwest::Client,
    /// Random per-process nonce mixed into every `jti`. The counter alone
    /// resets to 1 on restart, so `(now_secs, counter)` could repeat if two
    /// mints land in the same wallclock second on either side of a restart —
    /// a jti collision that undermines replay/revocation tracking. A fresh
    /// 128-bit CSPRNG nonce per process namespaces the counter so jtis are
    /// globally unique across restarts without any durable state.
    instance: String,
    /// Monotonic counter for `jti`, unique within one process/`instance`.
    jti_counter: AtomicU64,
}

impl std::fmt::Debug for CheersClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheersClient")
            .field("issuer_url", &self.config.issuer_url)
            .field("principal_id", &self.config.principal_id)
            .field("kid", &self.config.kid)
            .finish_non_exhaustive()
    }
}

impl CheersClient {
    /// Build a client. `secret_bytes` is the raw PASETO v4 secret key
    /// (64 bytes: 32-byte seed + 32-byte pubkey) as written by
    /// `yubaba install` / `--rotate`.
    pub fn new(config: CheersConfig, secret_bytes: &[u8]) -> Result<Self, CheersError> {
        let secret = AsymmetricSecretKey::<V4>::from(secret_bytes).map_err(CheersError::Mint)?;
        Ok(Self {
            config,
            secret,
            http: reqwest::Client::new(),
            instance: random_instance_nonce(),
            jti_counter: AtomicU64::new(1),
        })
    }

    /// Configured cheers issuer URL — `iss`/`aud` on minted tokens.
    pub fn issuer_url(&self) -> &str {
        &self.config.issuer_url
    }

    /// Configured service-principal id (without the `svc:` prefix).
    pub fn principal_id(&self) -> &str {
        &self.config.principal_id
    }

    /// Mint a `ownership:write`-scoped token, signed locally with yubaba's
    /// service-principal key. Pure — no I/O — so it can be unit-tested
    /// against a known clock.
    fn mint_ownership_write_token(&self, now_secs: i64) -> Result<String, CheersError> {
        let jti = self.jti_counter.fetch_add(1, Ordering::Relaxed);
        let claims = serde_json::json!({
            "iss": self.config.issuer_url,
            "aud": self.config.issuer_url,
            "exp": now_secs + TOKEN_TTL_SECS,
            "iat": now_secs,
            // `instance` (random per process) namespaces the counter so the jti
            // stays globally unique across restarts, not just within one second.
            "jti": format!("yubaba-{now_secs}-{}-{jti}", self.instance),
            "sub": format!("svc:{}", self.config.principal_id),
            "scope": ["ownership:write"],
        });
        let payload = serde_json::to_vec(&claims)
            .map_err(|e| CheersError::Decode(format!("serialize claims: {e}")))?;
        let footer = format!(r#"{{"kid":"{}"}}"#, self.config.kid).into_bytes();
        PublicToken::sign(&self.secret, &payload, Some(&footer), None).map_err(CheersError::Mint)
    }

    /// `POST /ownership` — record that `principal_id` now `relationship`s
    /// the resource `(resource_kind, resource_id)`. `on_behalf_of` is the
    /// human who triggered the deploy (`user:<U>`); leave `None` for
    /// self-grants. Returns the `id` of the new row — store it so a later
    /// destroy can `DELETE /ownership/{id}`.
    pub async fn register_ownership(
        &self,
        principal_id: &str,
        resource_kind: &str,
        resource_id: &str,
        relationship: &str,
        on_behalf_of: Option<&str>,
    ) -> Result<OwnershipRow, CheersError> {
        let token = self.mint_ownership_write_token(now_unix())?;
        let body = serde_json::json!({
            "principal_id": principal_id,
            "resource_kind": resource_kind,
            "resource_id": resource_id,
            "relationship": relationship,
            "on_behalf_of": on_behalf_of,
        });
        let url = format!("{}/ownership", self.config.issuer_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(CheersError::Status { status, body: text });
        }
        serde_json::from_str(&text)
            .map_err(|e| CheersError::Decode(format!("OwnershipRow: {e} (body: {text})")))
    }

    /// `DELETE /ownership/{id}` — soft-delete by id. Idempotent on the
    /// cheers side; re-revoking an already-revoked row succeeds with
    /// `204 No Content`. `404 Not Found` surfaces as
    /// [`CheersError::Status`] so a destroy path can decide whether to
    /// treat "row missing" as a fatal mismatch or a benign retry.
    pub async fn revoke_ownership(&self, id: &str) -> Result<(), CheersError> {
        let token = self.mint_ownership_write_token(now_unix())?;
        let url = format!(
            "{}/ownership/{}",
            self.config.issuer_url.trim_end_matches('/'),
            id
        );
        let resp = self.http.delete(&url).bearer_auth(&token).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CheersError::Status { status, body });
        }
        Ok(())
    }

    /// Enroll a node (R593-F4, W268 §"The binding: enrollment is an
    /// ownership row"): record `svc:<principal_id> owns node:<node_id_hex>`
    /// in cheers's ownership table, where `principal_id` is THIS client's
    /// own configured service-principal id — "fleet machines are devices
    /// owned by the operator's service principal", and the operator's
    /// principal is exactly the one yubaba already mints ownership-write
    /// tokens as, so no separate principal needs to be threaded through.
    ///
    /// `node_id_hex` must be the mshr `NodeId` in the same lowercase-hex
    /// encoding `identity::node_id_hex` / yubaba's `/identity` route use.
    ///
    /// Thin wrapper over [`Self::register_ownership`] fixing
    /// `resource_kind = "node"` (see [`NODE_RESOURCE_KIND`]) and
    /// `relationship = "owns"` — kept here (not duplicated at call sites)
    /// because this is the fleet path's single ownership-write chokepoint.
    pub async fn enroll_node(&self, node_id_hex: &str) -> Result<OwnershipRow, CheersError> {
        let principal = format!("svc:{}", self.config.principal_id);
        self.register_ownership(&principal, NODE_RESOURCE_KIND, node_id_hex, "owns", None)
            .await
    }

    /// Evict a node — revoke its enrollment row by id (the counterpart to
    /// [`Self::enroll_node`]). Per W268 §"The two axes": eviction removes
    /// **enrollment rows, never the key** — this only soft-deletes the
    /// cheers ownership row; the NodeId's underlying Ed25519 keypair on
    /// disk is untouched, unlike account-side revocation.
    ///
    /// Thin wrapper over [`Self::revoke_ownership`]; `ownership_row_id` is
    /// the `id` returned by the [`OwnershipRow`] a prior `enroll_node` call
    /// produced.
    pub async fn evict_node(&self, ownership_row_id: &str) -> Result<(), CheersError> {
        self.revoke_ownership(ownership_row_id).await
    }

    /// `GET /ownership?principal_id=<p>` — live (non-revoked) ownership
    /// rows held by `principal_id`. The cheers route is gated on the same
    /// `ownership:write` scope as the writes — it is the writer's
    /// management read (R593-F4): a yubaba that lost its in-memory
    /// enrollment row id across a restart uses this to rediscover the
    /// row(s) it must revoke on eviction. Not a general query surface.
    pub async fn list_ownership(
        &self,
        principal_id: &str,
    ) -> Result<Vec<OwnershipRow>, CheersError> {
        let token = self.mint_ownership_write_token(now_unix())?;
        let url = format!("{}/ownership", self.config.issuer_url.trim_end_matches('/'));
        let resp = self
            .http
            .get(&url)
            .query(&[("principal_id", principal_id)])
            .bearer_auth(&token)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(CheersError::Status { status, body: text });
        }
        serde_json::from_str(&text)
            .map_err(|e| CheersError::Decode(format!("Vec<OwnershipRow>: {e} (body: {text})")))
    }
}

/// Subset of cheers's `OwnershipRow` shape — enough for yubaba to round-trip
/// the `id` between register and revoke. Cheers may add fields; serde's
/// default ignore-unknown behavior on structs would reject those, so the
/// fields yubaba doesn't care about land in `extra` as raw JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipRow {
    pub id: String,
    pub principal_id: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub relationship: String,
    pub granted_by: String,
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    pub granted_at: i64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A random 128-bit per-process nonce (hex) that namespaces the `jti` counter.
/// Drawn once at client construction from the OS CSPRNG, so a restarted yubaba
/// mints jtis in a fresh namespace and can't collide with its prior process.
fn random_instance_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{delete, post};
    use axum::{Json, Router};
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, Generate};
    use pasetors::token::{Public, UntrustedToken};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn fresh_keypair() -> AsymmetricKeyPair<V4> {
        AsymmetricKeyPair::<V4>::generate().expect("generate v4 keypair")
    }

    fn client_with(keypair: &AsymmetricKeyPair<V4>, issuer: &str) -> CheersClient {
        let cfg = CheersConfig {
            issuer_url: issuer.to_string(),
            principal_id: "yubaba-test".to_string(),
            kid: "yubaba-test-1".to_string(),
        };
        CheersClient::new(cfg, keypair.secret.as_bytes()).expect("build client")
    }

    #[test]
    fn mint_token_round_trips_and_carries_expected_claims() {
        let kp = fresh_keypair();
        let client = client_with(&kp, "https://cheers.test");
        let token = client.mint_ownership_write_token(1_700_000_000).unwrap();

        let untrusted = UntrustedToken::<Public, V4>::try_from(token.as_str()).unwrap();
        let pubkey_bytes: [u8; 32] = kp.public.as_bytes().try_into().unwrap();
        let pubkey = AsymmetricPublicKey::<V4>::from(&pubkey_bytes).unwrap();
        let trusted = PublicToken::verify(&pubkey, &untrusted, None, None).unwrap();
        let claims: serde_json::Value = serde_json::from_str(trusted.payload()).unwrap();

        assert_eq!(claims["sub"], "svc:yubaba-test");
        assert_eq!(claims["iss"], "https://cheers.test");
        assert_eq!(claims["aud"], "https://cheers.test");
        assert_eq!(claims["scope"][0], "ownership:write");
        assert_eq!(claims["iat"], 1_700_000_000);
        assert_eq!(claims["exp"], 1_700_000_000 + TOKEN_TTL_SECS);

        let footer = std::str::from_utf8(untrusted.untrusted_footer()).unwrap();
        assert!(footer.contains(r#""kid":"yubaba-test-1""#));
    }

    #[test]
    fn jti_is_unique_across_sequential_mints() {
        let kp = fresh_keypair();
        let client = client_with(&kp, "https://cheers.test");
        // Two mints at the same wallclock second still get distinct jtis
        // — the monotonic counter ensures replay-protection inside one second.
        let t1 = client.mint_ownership_write_token(1_700_000_000).unwrap();
        let t2 = client.mint_ownership_write_token(1_700_000_000).unwrap();

        let parse = |tok: &str| -> serde_json::Value {
            let u = UntrustedToken::<Public, V4>::try_from(tok).unwrap();
            let pk_bytes: [u8; 32] = kp.public.as_bytes().try_into().unwrap();
            let pk = AsymmetricPublicKey::<V4>::from(&pk_bytes).unwrap();
            let t = PublicToken::verify(&pk, &u, None, None).unwrap();
            serde_json::from_str(t.payload()).unwrap()
        };

        let c1 = parse(&t1);
        let c2 = parse(&t2);
        assert_ne!(c1["jti"], c2["jti"]);
    }

    #[test]
    fn jti_is_unique_across_process_restarts() {
        // Two independently-constructed clients model a restart: each draws a
        // fresh random `instance` nonce, so their jtis don't collide even at the
        // same wallclock second with the counter reset to 1 on both sides — the
        // failure mode the bare `(now_secs, counter)` jti had.
        let kp = fresh_keypair();
        let before = client_with(&kp, "https://cheers.test");
        let after = client_with(&kp, "https://cheers.test");

        let parse_jti = |tok: &str| -> String {
            let u = UntrustedToken::<Public, V4>::try_from(tok).unwrap();
            let pk_bytes: [u8; 32] = kp.public.as_bytes().try_into().unwrap();
            let pk = AsymmetricPublicKey::<V4>::from(&pk_bytes).unwrap();
            let t = PublicToken::verify(&pk, &u, None, None).unwrap();
            let claims: serde_json::Value = serde_json::from_str(t.payload()).unwrap();
            claims["jti"].as_str().unwrap().to_owned()
        };

        // Same second, both counters at 1 — only the instance nonce differs.
        let j_before = parse_jti(&before.mint_ownership_write_token(1_700_000_000).unwrap());
        let j_after = parse_jti(&after.mint_ownership_write_token(1_700_000_000).unwrap());
        assert_ne!(j_before, j_after, "restart must not reuse a jti namespace");
    }

    #[test]
    fn new_rejects_malformed_secret() {
        let cfg = CheersConfig {
            issuer_url: "https://cheers.test".into(),
            principal_id: "yubaba-test".into(),
            kid: "k1".into(),
        };
        // 3 bytes is nowhere near v4's required key length.
        let err = CheersClient::new(cfg, &[0u8, 1, 2]).unwrap_err();
        assert!(matches!(err, CheersError::Mint(_)));
    }

    // ── Mock cheers server for end-to-end HTTP tests ─────────────────────────

    #[derive(Clone, Default)]
    struct MockState {
        /// Last seen body on POST /ownership — tests assert against this.
        last_post: Arc<Mutex<Option<serde_json::Value>>>,
        last_auth: Arc<Mutex<Option<String>>>,
        last_delete_id: Arc<Mutex<Option<String>>>,
        /// When set, POST returns this status + body instead of the happy path.
        fail_post: Arc<Mutex<Option<(StatusCode, String)>>>,
    }

    async fn mock_post(
        State(state): State<MockState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        if let Some(auth) = headers.get("authorization") {
            *state.last_auth.lock().await = Some(auth.to_str().unwrap_or("").into());
        }
        *state.last_post.lock().await = Some(body.clone());
        if let Some((status, msg)) = state.fail_post.lock().await.clone() {
            return (status, Json(serde_json::json!({ "error": msg })));
        }
        let row = serde_json::json!({
            "id": "01HOWNROW",
            "principal_id": body["principal_id"],
            "resource_kind": body["resource_kind"],
            "resource_id": body["resource_id"],
            "relationship": body["relationship"],
            "granted_by": "svc:yubaba-test",
            "on_behalf_of": body["on_behalf_of"],
            "granted_at": 1_700_000_000_i64,
            "revoked_at": serde_json::Value::Null,
        });
        (StatusCode::CREATED, Json(row))
    }

    async fn mock_delete(State(state): State<MockState>, Path(id): Path<String>) -> StatusCode {
        *state.last_delete_id.lock().await = Some(id);
        StatusCode::NO_CONTENT
    }

    async fn spawn_mock() -> (String, MockState) {
        let state = MockState::default();
        let app = Router::new()
            .route("/ownership", post(mock_post))
            .route("/ownership/{id}", delete(mock_delete))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), state)
    }

    #[tokio::test]
    async fn register_ownership_posts_canonical_body_with_bearer() {
        let (url, mock) = spawn_mock().await;
        let kp = fresh_keypair();
        let client = client_with(&kp, &url);

        let row = client
            .register_ownership("camp:C-abc", "service", "svc-xyz", "owns", Some("user:U-1"))
            .await
            .unwrap();

        assert_eq!(row.id, "01HOWNROW");
        let body = mock.last_post.lock().await.clone().unwrap();
        assert_eq!(body["principal_id"], "camp:C-abc");
        assert_eq!(body["resource_kind"], "service");
        assert_eq!(body["resource_id"], "svc-xyz");
        assert_eq!(body["relationship"], "owns");
        assert_eq!(body["on_behalf_of"], "user:U-1");

        let auth = mock.last_auth.lock().await.clone().unwrap();
        assert!(
            auth.starts_with("Bearer v4.public."),
            "bearer auth header should carry a v4.public token, got: {auth}"
        );
    }

    #[tokio::test]
    async fn register_ownership_omits_on_behalf_of_when_none() {
        let (url, mock) = spawn_mock().await;
        let kp = fresh_keypair();
        let client = client_with(&kp, &url);

        client
            .register_ownership("svc:yubaba-test", "machine", "m-1", "owns", None)
            .await
            .unwrap();

        let body = mock.last_post.lock().await.clone().unwrap();
        // serde_json::json! writes None as null — cheers's CreateOwnershipBody
        // deserializes `Option<PrincipalId>` from missing OR null, so either
        // form is wire-compatible. Pin null here so a future shift to a
        // serde(skip_serializing_if = "Option::is_none") change is a
        // deliberate decision and not an accident.
        assert!(body["on_behalf_of"].is_null());
    }

    #[tokio::test]
    async fn register_ownership_surfaces_403_as_status_error() {
        let (url, mock) = spawn_mock().await;
        *mock.fail_post.lock().await = Some((StatusCode::FORBIDDEN, "insufficient_scope".into()));
        let kp = fresh_keypair();
        let client = client_with(&kp, &url);

        let err = client
            .register_ownership("camp:C-abc", "service", "svc-xyz", "owns", None)
            .await
            .unwrap_err();
        match err {
            CheersError::Status { status, body } => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert!(
                    body.contains("insufficient_scope"),
                    "body should preserve cheers's error: {body}"
                );
            }
            other => panic!("expected Status error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn revoke_ownership_calls_delete_with_id() {
        let (url, mock) = spawn_mock().await;
        let kp = fresh_keypair();
        let client = client_with(&kp, &url);

        client.revoke_ownership("01HOWNROW").await.unwrap();

        let id = mock.last_delete_id.lock().await.clone().unwrap();
        assert_eq!(id, "01HOWNROW");
    }

    // ── R593-F4: node enrollment/eviction wrappers ────────────────────────

    #[tokio::test]
    async fn enroll_node_posts_node_kind_owned_by_own_principal() {
        let (url, mock) = spawn_mock().await;
        let kp = fresh_keypair();
        let client = client_with(&kp, &url); // principal_id = "yubaba-test"

        let node_id = "a".repeat(64); // hex-encoded 32-byte NodeId shape
        let row = client.enroll_node(&node_id).await.unwrap();

        assert_eq!(row.resource_kind, "node");
        let body = mock.last_post.lock().await.clone().unwrap();
        assert_eq!(body["principal_id"], "svc:yubaba-test");
        assert_eq!(body["resource_kind"], "node");
        assert_eq!(body["resource_id"], node_id);
        assert_eq!(body["relationship"], "owns");
        assert!(
            body["on_behalf_of"].is_null(),
            "node enrollment is a self-grant by the operator principal, not on behalf of a user"
        );
    }

    #[tokio::test]
    async fn evict_node_calls_delete_with_ownership_row_id() {
        let (url, mock) = spawn_mock().await;
        let kp = fresh_keypair();
        let client = client_with(&kp, &url);

        client.evict_node("01HNODEROW").await.unwrap();

        let id = mock.last_delete_id.lock().await.clone().unwrap();
        assert_eq!(id, "01HNODEROW");
    }
}
