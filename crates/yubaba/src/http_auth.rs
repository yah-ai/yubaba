//! @arch:layer(core)
//! @arch:role(net)
//!
//! **Who may call this node's HTTP control plane** (R876-B15).
//!
//! yubaba has two control-plane transports and, until this module, only one
//! of them asked who was calling. The mshr/QUIC lane answers "which machine
//! is this connection?" from the peer's verified TLS certificate and then
//! asks [`control_plane::admission`](crate::control_plane::admission)
//! whether that `NodeId` is entitled. The axum lane on `:7443` asked
//! nothing at all: `build_router` applied exactly one layer
//! (`correlation_id_layer`), so a single unauthenticated reach to a node's
//! mesh address could read every workload's spec, deploy a workload, and
//! drive a self-update of the node's own binary. "It is on the mesh" was
//! the whole access-control story.
//!
//! ## The model
//!
//! Every route is in exactly one [`AuthClass`], and the class is
//! *structural* — [`crate::build_router`] builds one sub-router per class
//! and layers each with its own middleware. There is no path table to fall
//! out of sync with the routes, and adding a route means picking a
//! sub-router to add it to.
//!
//! | Class | Credential | Examples |
//! |---|---|---|
//! | [`AuthClass::Public`] | none | `GET /health`, `GET /mesh/leader-health` |
//! | [`AuthClass::Peer`] | peer **or** operator token | raft RPC, `/raft/write`, lease renew, service discovery, workload reads |
//! | [`AuthClass::Operator`] | operator token only | `/workloads/deploy`, `/workloads/{id}/spec`, `/self-update`, `/secrets`, raft membership |
//!
//! Two credential tiers, one verification path, and the split is
//! deliberate rather than incidental:
//!
//! - **Peer** tokens are PASETO **v4.local** — symmetric, under a
//!   cluster-wide key every node in the cluster holds. The holders are
//!   mutually-trusting members of one trust domain and they must verify
//!   each other with *no network round-trip*, because raft cannot depend on
//!   cheers (or anything else) being reachable to hold an election. One
//!   secret, N holders, no distribution graph.
//! - **Operator** tokens are PASETO **v4.public** — asymmetric, verified
//!   against operator public keys configured on the node. A node can
//!   *verify* an operator token and cannot *forge* one, which is the
//!   property that matters for `/self-update`: compromising a node must not
//!   yield the ability to order its peers to swap their own binaries.
//!
//! An operator token satisfies [`AuthClass::Peer`] as well; a peer token
//! never satisfies [`AuthClass::Operator`].
//!
//! ## Why there is a mode, and when it goes away
//!
//! Enforcing this is a flag day: every caller on the fleet today
//! (the `yah` CLI through `cloud-client`, the passway doors' discovery
//! poll, node-to-node raft) sends no credential at all, and this camp runs
//! a shared tree that ships to a live fleet serving tenant traffic. Landing
//! `Require` in one step would push a yubaba that refuses the fleet's own
//! traffic.
//!
//! So [`AuthMode`] is a *roll* sequencer, not a feature flag: the code is
//! written as if only `Require` exists, and `Warn` exists only so the roll
//! can see two versions at once. It defaults to [`AuthMode::Warn`] —
//! anonymous requests are logged and served, so a node upgraded ahead of
//! its callers keeps working. Flipping the default to `Require` and
//! deleting `Warn` is R876-T18.
//!
//! `Warn` is deliberately *not* "auth off". A credential that is present
//! and bad — bad signature, expired, wrong audience, wrong tier — is
//! refused in **both** modes. Only *absence* is tolerated under `Warn`.
//! That is what makes the soak meaningful: a caller wired up during the
//! roll gets real verification the moment it starts signing, so the flip
//! to `Require` is a no-op for everything already talking.
//!
//! @yah:ticket(R876-T18, "Finish the R876-B15 roll: sign the remaining yubaba callers, distribute the keys, then flip auth-mode to require and delete Warn")
//! @yah:at(2026-09-12T08:27:35Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R876)
//! @yah:depends_on(R876-B15)
//! @yah:next("STEP 1 — SIGN THE CALLERS THAT STILL SEND NOTHING. R876-B15 wired exactly one: cloud-client attaches `Authorization: Bearer <token>` as a reqwest DEFAULT HEADER (crates/yah/cloud-client/src/lib.rs, `CloudClient::build`), sourced from `YUBABA_OPERATOR_TOKEN_FILE` then `YUBABA_OPERATOR_TOKEN`, or passed explicitly via the new `CloudClient::with_token`. That covers the `yah` CLI, yah-agent-tools and rollout apply, because all three go through that client. STILL UNSIGNED, each needing a PEER-tier token minted from the cluster key: (a) oss/yubaba/crates/yubaba-consensus/src/raft/network.rs — its `request`/`post` helpers hit /raft/append-entries, /raft/vote, /raft/pre-vote, /raft/snapshot, /raft/transfer-leader-msg, and raft/mod.rs:2549 hand-rolls `format!(\"http://{}/raft/write\", leader.addr)` on ForwardToLeader; (b) oss/passway/crates/passway/src/discovery.rs — the door's poll of yubaba's service-records path; (c) oss/yubaba/crates/tenant-streamer/src/rpo_report.rs — POST /mesh/rpo-report; (d) yubaba's own in-process loops that dial a peer (lease_renewal.rs, member_registration.rs, headroom.rs, state_backup.rs). Each of these is AuthClass::Peer, so one cluster key opens all of them.")
//! @yah:next("STEP 2 — GET THE KEYS ONTO THE FLEET BEFORE ANY FLIP. `yubaba auth cluster-keygen --out <path>` once, then the SAME hex file on every node in the cluster at /etc/yah-cloud/cluster.key (0600), named by `--cluster-key-file` / `YUBABA_CLUSTER_KEY_FILE` in a systemd drop-in — the same delivery shape R881 used for --container-net. `yubaba auth keygen --secret-out <path>` once per operator; the PUBLIC hex goes on every node as `--operator-key` / `YUBABA_OPERATOR_KEYS` (comma-separated), the secret half into the operator's keys vault. Distribution is the whole cost of this step and it is a live-fleet change: a node with keys configured and mode=warn behaves identically to one with none, so the keys can go out well ahead of the flip and be soaked.")
//! @yah:next("STEP 3 — FLIP AND DELETE. Set `--auth-mode require` on one node, verify the fleet still elects and serves, then roll. Once every node is on require: delete `AuthMode::Warn`, delete the `--auth-mode` flag, make `HttpAuthPolicy::new` require a trust root unconditionally, and delete the anonymous branch of `http_auth::decide`. That is the pre-1.0 rule applied — the mode is a roll sequencer that earns its keep exactly once.")
//! @yah:gotcha("THE ORDER IS NOT NEGOTIABLE AND STEP 3 IS THE ONLY DANGEROUS ONE. `--auth-mode require` on a node whose PEERS do not yet send a peer token 401s every /raft/append-entries and /raft/vote that node receives, which takes it out of the quorum while systemd still reports it active — the same shape as the R876 protocol-skew gotcha, reached by a different mechanism. Steps 1 and 2 are individually safe to land and roll in any order: a signed caller against a warn-mode node is served (the token is verified, and a VALID token is accepted in both modes), and a keyed node with no signed callers behaves exactly like an unkeyed one.")
//! @yah:gotcha("WARN MODE IS NOT AUTH-OFF, AND THAT IS LOAD-BEARING FOR STEP 1. A credential that is PRESENT AND BAD — bad signature, expired, wrong audience, missing scope, peer token on an operator route — is refused with 401/403 in BOTH modes; only ABSENCE is tolerated under warn. So each caller wired in step 1 gets real verification the moment it starts signing, against nodes still in warn. That is what makes step 3 a no-op for everything already talking, and it is also the trap: a step-1 caller that mints with the wrong audience or the wrong tier breaks IMMEDIATELY rather than at the flip. Test each caller against a require-mode node locally first — `http_auth::router_tests` and cloud-client's `an_enforcing_yubaba_refuses_a_tokenless_client_and_serves_a_tokened_one` are both worked examples of that setup.")
//! @yah:gotcha("MAX_TOKEN_TTL_SECS IS 24h AND IT IS CHECKED AGAINST *NOW*, NOT AGAINST `iat`. A long-lived token pasted into a systemd unit will start 401ing a day later with `token exp is Ns out, beyond the ceiling` or `token is expired`. Peer-side callers must MINT PER PROCESS-START AT MINIMUM, and really should re-mint on a timer — `mint_peer_token` is pure and cheap (no I/O, no round-trip), so a fresh token per request is affordable and is the shape to prefer over caching one.")

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
use pasetors::token::{Local, Public, UntrustedToken};
use pasetors::version4::{LocalToken, PublicToken, V4};

use crate::ServerState;

/// `aud` every yubaba control-plane token must carry.
///
/// Present so a token minted for a *different* verifier that happens to
/// share a key — yubaba already mints cheers-audience tokens with its own
/// service-principal key, see [`crate::cheers_client`] — cannot be replayed
/// here. Audience separation is the cheap half of not reusing keys; the
/// expensive half is not reusing keys, which is why the operator trust set
/// is configured separately from the cheers principal.
pub const AUDIENCE: &str = "yubaba:control-plane";

/// `scope` entry an operator-tier token must carry.
pub const OPERATOR_SCOPE: &str = "yubaba:operator";

/// `scope` entry a peer-tier token must carry.
pub const PEER_SCOPE: &str = "yubaba:peer";

/// Default lifetime for a freshly minted token.
pub const DEFAULT_TOKEN_TTL_SECS: i64 = 300;

/// Longest `exp` this node will honour, measured from *now* rather than
/// from the token's `iat`.
///
/// Without a ceiling, a bearer token is a standing credential: mint one
/// with `exp` ten years out, paste it into a script, and the tier's whole
/// point (a short-lived, revocable-by-expiry grant) is gone. Measuring from
/// now rather than from `iat` means a minter cannot dodge it by backdating,
/// and it needs no clock agreement beyond the one `exp` already assumes.
pub const MAX_TOKEN_TTL_SECS: i64 = 24 * 60 * 60;

/// Which credential a route demands.
///
/// Carried as middleware state rather than looked up by path: see the
/// module header on why the classification is structural.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthClass {
    /// No credential. Reachable by anything that can open a socket, so this
    /// is reserved for liveness probes whose *purpose* is to answer before
    /// the node is configured — and which disclose nothing a port scan
    /// does not already.
    Public,
    /// A peer-tier **or** operator-tier token.
    Peer,
    /// An operator-tier token only.
    Operator,
}

/// Whether a missing credential is refused or merely logged.
///
/// See the module header — this is a roll sequencer with a removal ticket
/// (R876-T18), not a permanent knob.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthMode {
    /// Anonymous requests are served and logged at WARN. An *invalid*
    /// credential is still refused.
    #[default]
    Warn,
    /// Anonymous requests are refused with 401.
    Require,
}

impl AuthMode {
    /// Parse the `YUBABA_AUTH_MODE` / `--auth-mode` spelling.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "warn" => Ok(Self::Warn),
            "require" => Ok(Self::Require),
            other => Err(format!(
                "unknown auth mode {other:?} (expected \"warn\" or \"require\")"
            )),
        }
    }
}

/// Which trust root verified a credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// v4.local under the cluster key.
    Peer,
    /// v4.public under a configured operator key.
    Operator,
}

impl Tier {
    fn satisfies(self, class: AuthClass) -> bool {
        match class {
            AuthClass::Public => true,
            AuthClass::Peer => true,
            AuthClass::Operator => self == Tier::Operator,
        }
    }

    fn required_scope(self) -> &'static str {
        match self {
            Tier::Peer => PEER_SCOPE,
            Tier::Operator => OPERATOR_SCOPE,
        }
    }
}

/// The verified caller, stashed in the request extensions for handlers that
/// want to attribute an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// The token's `sub`.
    pub subject: String,
    /// Which trust root vouched for it.
    pub tier: Tier,
}

/// What [`authenticate`] found on the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// No `Authorization` header at all.
    Anonymous,
    /// A credential that verified.
    Allowed(Principal),
    /// A credential was presented and is not acceptable. The string is safe
    /// to log; it is deliberately *not* returned to the caller beyond a
    /// coarse reason, so the route is not an oracle for which key is
    /// configured.
    Invalid(String),
}

/// The node's configured trust roots plus the enforcement mode.
#[derive(Default)]
pub struct HttpAuthPolicy {
    mode: AuthMode,
    operator_keys: Vec<AsymmetricPublicKey<V4>>,
    cluster_key: Option<SymmetricKey<V4>>,
}

impl std::fmt::Debug for HttpAuthPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAuthPolicy")
            .field("mode", &self.mode)
            .field("operator_keys", &self.operator_keys.len())
            .field("cluster_key", &self.cluster_key.is_some())
            .finish()
    }
}

impl HttpAuthPolicy {
    /// Build a policy from raw config values.
    ///
    /// `operator_keys` are 64-char hex ed25519 *public* keys — the same
    /// spelling `--control-plane-allow` already uses for `NodeId`s, so an
    /// operator has one hex convention to learn rather than two.
    /// `cluster_key` is a 64-char hex 32-byte symmetric key.
    pub fn new(
        mode: AuthMode,
        operator_keys: &[String],
        cluster_key: Option<&str>,
    ) -> Result<Self, String> {
        let mut parsed_operator = Vec::with_capacity(operator_keys.len());
        for raw in operator_keys {
            let bytes = decode_hex32(raw.trim())
                .map_err(|e| format!("operator key {raw:?} is not a 64-char hex key: {e}"))?;
            parsed_operator.push(
                AsymmetricPublicKey::<V4>::from(&bytes)
                    .map_err(|e| format!("operator key {raw:?} is not a valid v4 key: {e:?}"))?,
            );
        }
        let parsed_cluster = match cluster_key {
            Some(raw) => {
                let bytes = decode_hex32(raw.trim())
                    .map_err(|e| format!("cluster key is not a 64-char hex key: {e}"))?;
                Some(
                    SymmetricKey::<V4>::from(&bytes)
                        .map_err(|e| format!("cluster key is not a valid v4 key: {e:?}"))?,
                )
            }
            None => None,
        };

        // A node that enforces with no trust root at all refuses every
        // authenticated route forever, which looks exactly like a network
        // partition and is far harder to diagnose than a refused boot.
        if mode == AuthMode::Require && parsed_operator.is_empty() && parsed_cluster.is_none() {
            return Err(
                "--auth-mode require with no trust root: pass at least one --operator-key \
                 or --cluster-key-file, or every authenticated route will 401"
                    .to_string(),
            );
        }

        Ok(Self {
            mode,
            operator_keys: parsed_operator,
            cluster_key: parsed_cluster,
        })
    }

    /// Read the policy off the environment.
    ///
    /// - `YUBABA_AUTH_MODE` — `warn` (default) or `require`.
    /// - `YUBABA_OPERATOR_KEYS` — comma-separated hex public keys.
    /// - `YUBABA_CLUSTER_KEY_FILE` — path to a file holding the hex cluster
    ///   key. A *file*, not an env var: the cluster key is a bearer secret,
    ///   and an env var is readable from `/proc/<pid>/environ`, inherited by
    ///   every child yubaba spawns, and printed by half the diagnostics in
    ///   this repo.
    pub fn from_env() -> Result<Self, String> {
        let mode = match std::env::var("YUBABA_AUTH_MODE") {
            Ok(raw) if !raw.trim().is_empty() => AuthMode::parse(&raw)?,
            _ => AuthMode::default(),
        };
        let operator_keys: Vec<String> = std::env::var("YUBABA_OPERATOR_KEYS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let cluster_key = match std::env::var("YUBABA_CLUSTER_KEY_FILE") {
            Ok(path) if !path.trim().is_empty() => Some(
                std::fs::read_to_string(path.trim())
                    .map_err(|e| format!("reading YUBABA_CLUSTER_KEY_FILE {path:?}: {e}"))?
                    .trim()
                    .to_string(),
            ),
            _ => None,
        };
        Self::new(mode, &operator_keys, cluster_key.as_deref())
    }

    /// Is a missing credential refused?
    pub fn is_enforcing(&self) -> bool {
        self.mode == AuthMode::Require
    }

    /// Does this node hold any trust root at all?
    pub fn has_trust_root(&self) -> bool {
        !self.operator_keys.is_empty() || self.cluster_key.is_some()
    }
}

/// Verify the `Authorization` header against the policy. Pure — `now` is
/// passed in so expiry is testable without a clock.
pub fn authenticate(policy: &HttpAuthPolicy, header: Option<&str>, now: i64) -> AuthOutcome {
    let Some(raw) = header else {
        return AuthOutcome::Anonymous;
    };
    let Some(token) = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
    else {
        return AuthOutcome::Invalid("Authorization header is not a Bearer credential".into());
    };
    let token = token.trim();
    if token.is_empty() {
        return AuthOutcome::Anonymous;
    }

    let (tier, payload) = if token.starts_with(PublicToken::HEADER) {
        match verify_operator(policy, token) {
            Ok(p) => (Tier::Operator, p),
            Err(e) => return AuthOutcome::Invalid(e),
        }
    } else if token.starts_with(LocalToken::HEADER) {
        match verify_peer(policy, token) {
            Ok(p) => (Tier::Peer, p),
            Err(e) => return AuthOutcome::Invalid(e),
        }
    } else {
        return AuthOutcome::Invalid("token is neither v4.public nor v4.local".into());
    };

    match validate_claims(&payload, tier, now) {
        Ok(subject) => AuthOutcome::Allowed(Principal { subject, tier }),
        Err(e) => AuthOutcome::Invalid(e),
    }
}

fn verify_operator(policy: &HttpAuthPolicy, token: &str) -> Result<String, String> {
    if policy.operator_keys.is_empty() {
        return Err("operator token presented but this node has no operator key".into());
    }
    let untrusted = UntrustedToken::<Public, V4>::try_from(token)
        .map_err(|_| "malformed v4.public token".to_string())?;
    for key in &policy.operator_keys {
        if let Ok(trusted) = PublicToken::verify(key, &untrusted, None, None) {
            return Ok(trusted.payload().to_string());
        }
    }
    Err("v4.public token matched no configured operator key".into())
}

fn verify_peer(policy: &HttpAuthPolicy, token: &str) -> Result<String, String> {
    let Some(key) = policy.cluster_key.as_ref() else {
        return Err("peer token presented but this node has no cluster key".into());
    };
    let untrusted = UntrustedToken::<Local, V4>::try_from(token)
        .map_err(|_| "malformed v4.local token".to_string())?;
    let trusted = LocalToken::decrypt(key, &untrusted, None, None)
        .map_err(|_| "v4.local token did not decrypt under the cluster key".to_string())?;
    Ok(trusted.payload().to_string())
}

/// Check `aud`, `exp` and `scope` on a token whose signature already
/// verified, and return its `sub`.
fn validate_claims(payload: &str, tier: Tier, now: i64) -> Result<String, String> {
    let claims: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| format!("token payload is not JSON: {e}"))?;

    match claims.get("aud").and_then(|v| v.as_str()) {
        Some(AUDIENCE) => {}
        Some(other) => return Err(format!("token audience {other:?} is not {AUDIENCE:?}")),
        None => return Err("token carries no aud".into()),
    }

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "token carries no numeric exp".to_string())?;
    if exp <= now {
        return Err("token is expired".into());
    }
    if exp - now > MAX_TOKEN_TTL_SECS {
        return Err(format!(
            "token exp is {}s out, beyond the {MAX_TOKEN_TTL_SECS}s ceiling",
            exp - now
        ));
    }

    let wanted = tier.required_scope();
    let has_scope = claims
        .get("scope")
        .and_then(|v| v.as_array())
        .is_some_and(|entries| entries.iter().any(|e| e.as_str() == Some(wanted)));
    if !has_scope {
        return Err(format!("token does not carry scope {wanted:?}"));
    }

    claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "token carries no sub".to_string())
}

/// The verdict the middleware acts on. `Ok` carries the principal (`None`
/// for a tolerated anonymous request); `Err` is the refusal to send.
pub fn decide(
    policy: &HttpAuthPolicy,
    class: AuthClass,
    outcome: AuthOutcome,
) -> Result<Option<Principal>, (StatusCode, &'static str)> {
    if class == AuthClass::Public {
        return Ok(None);
    }
    match outcome {
        // An invalid credential is refused in BOTH modes — see the module
        // header on why `Warn` is not "auth off".
        AuthOutcome::Invalid(_) => Err((StatusCode::UNAUTHORIZED, "invalid credential")),
        AuthOutcome::Anonymous => {
            if policy.is_enforcing() {
                Err((StatusCode::UNAUTHORIZED, "credential required"))
            } else {
                Ok(None)
            }
        }
        AuthOutcome::Allowed(p) => {
            if p.tier.satisfies(class) {
                Ok(Some(p))
            } else {
                // Valid credential, insufficient tier — refused in both
                // modes, because this is a caller bug rather than a
                // not-yet-upgraded caller.
                Err((StatusCode::FORBIDDEN, "credential tier insufficient"))
            }
        }
    }
}

/// The axum middleware. Layered per sub-router by [`crate::build_router`],
/// with the class baked into the state so there is no path matching here.
pub async fn auth_layer(
    State((state, class)): State<(Arc<ServerState>, AuthClass)>,
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let outcome = authenticate(&state.http_auth, header.as_deref(), now_unix());

    if let AuthOutcome::Invalid(ref why) = outcome {
        tracing::warn!(reason = %why, uri = %req.uri(), "rejecting request with a bad credential");
    }

    match decide(&state.http_auth, class, outcome) {
        Ok(principal) => {
            if principal.is_none() && class != AuthClass::Public {
                tracing::warn!(
                    uri = %req.uri(),
                    class = ?class,
                    "unauthenticated request served (auth mode is warn — R876-T18 flips this to \
                     require; wire this caller to send a token before then)"
                );
            }
            if let Some(p) = principal {
                req.extensions_mut().insert(p);
            }
            next.run(req).await
        }
        Err((status, reason)) => {
            (status, axum::Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

// ── Minting ──────────────────────────────────────────────────────────────────

/// Mint an operator-tier token. The secret half never leaves the operator's
/// key store; nodes hold only the public half.
pub fn mint_operator_token(
    secret: &AsymmetricSecretKey<V4>,
    subject: &str,
    ttl_secs: i64,
    now: i64,
) -> Result<String, String> {
    let payload = claims_json(subject, OPERATOR_SCOPE, ttl_secs, now)?;
    PublicToken::sign(secret, payload.as_bytes(), None, None)
        .map_err(|e| format!("signing operator token: {e:?}"))
}

/// Mint a peer-tier token under the cluster key.
pub fn mint_peer_token(
    key: &SymmetricKey<V4>,
    subject: &str,
    ttl_secs: i64,
    now: i64,
) -> Result<String, String> {
    let payload = claims_json(subject, PEER_SCOPE, ttl_secs, now)?;
    LocalToken::encrypt(key, payload.as_bytes(), None, None)
        .map_err(|e| format!("encrypting peer token: {e:?}"))
}

fn claims_json(subject: &str, scope: &str, ttl_secs: i64, now: i64) -> Result<String, String> {
    if ttl_secs <= 0 || ttl_secs > MAX_TOKEN_TTL_SECS {
        return Err(format!(
            "ttl {ttl_secs}s is outside (0, {MAX_TOKEN_TTL_SECS}]"
        ));
    }
    serde_json::to_string(&serde_json::json!({
        "aud": AUDIENCE,
        "sub": subject,
        "iat": now,
        "exp": now + ttl_secs,
        "scope": [scope],
    }))
    .map_err(|e| format!("serializing claims: {e}"))
}

// ── Key material helpers ─────────────────────────────────────────────────────

/// Generate an operator keypair, hex-encoded as `(public, secret)`.
///
/// The public half is what goes on each node as `--operator-key`; the secret
/// half is what mints. Returned as hex rather than as key objects so callers
/// outside this crate — `yubaba auth keygen`, cloud-client's round-trip test
/// — need no crypto dependency of their own.
pub fn generate_operator_keypair_hex() -> Result<(String, String), String> {
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    let kp = AsymmetricKeyPair::<V4>::generate()
        .map_err(|e| format!("generating operator keypair: {e:?}"))?;
    Ok((
        encode_hex(kp.public.as_bytes()),
        encode_hex(kp.secret.as_bytes()),
    ))
}

/// Generate a cluster key, hex-encoded. One per cluster, held by every node.
pub fn generate_cluster_key_hex() -> Result<String, String> {
    use pasetors::keys::Generate;
    let key =
        SymmetricKey::<V4>::generate().map_err(|e| format!("generating cluster key: {e:?}"))?;
    Ok(encode_hex(key.as_bytes()))
}

/// Parse a 128-char hex v4 asymmetric secret key (64 bytes: seed + pubkey).
pub fn operator_secret_from_hex(raw: &str) -> Result<AsymmetricSecretKey<V4>, String> {
    let bytes = decode_hex(raw.trim(), 64)?;
    AsymmetricSecretKey::<V4>::from(&bytes)
        .map_err(|e| format!("not a valid v4 secret key: {e:?}"))
}

/// Parse a 64-char hex 32-byte cluster key.
pub fn cluster_key_from_hex(raw: &str) -> Result<SymmetricKey<V4>, String> {
    let bytes = decode_hex32(raw.trim())?;
    SymmetricKey::<V4>::from(&bytes).map_err(|e| format!("not a valid v4 symmetric key: {e:?}"))
}

/// Lowercase hex, the spelling `--control-plane-allow` already uses.
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex32(raw: &str) -> Result<[u8; 32], String> {
    let v = decode_hex(raw, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn decode_hex(raw: &str, want_bytes: usize) -> Result<Vec<u8>, String> {
    if raw.len() != want_bytes * 2 {
        return Err(format!(
            "expected {} hex chars, got {}",
            want_bytes * 2,
            raw.len()
        ));
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(want_bytes);
    for pair in bytes.chunks(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(format!("{:?} is not a hex digit", other as char)),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasetors::keys::{AsymmetricKeyPair, Generate};

    /// A policy holding one operator key and one cluster key, plus the
    /// secret halves a caller would mint with.
    fn fixture(
        mode: AuthMode,
    ) -> (
        HttpAuthPolicy,
        AsymmetricSecretKey<V4>,
        SymmetricKey<V4>,
        String,
    ) {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let pub_hex = encode_hex(kp.public.as_bytes());
        let sym = SymmetricKey::<V4>::generate().unwrap();
        let sym_hex = encode_hex(sym.as_bytes());
        let policy = HttpAuthPolicy::new(mode, &[pub_hex.clone()], Some(&sym_hex)).unwrap();
        (policy, kp.secret, sym, pub_hex)
    }

    #[test]
    fn an_operator_token_verifies_and_carries_the_operator_tier() {
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let tok = mint_operator_token(&secret, "user:leif", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert_eq!(
            out,
            AuthOutcome::Allowed(Principal {
                subject: "user:leif".into(),
                tier: Tier::Operator
            })
        );
    }

    #[test]
    fn a_peer_token_verifies_and_carries_the_peer_tier() {
        let (policy, _secret, sym, _) = fixture(AuthMode::Require);
        let tok = mint_peer_token(&sym, "node:abc", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert_eq!(
            out,
            AuthOutcome::Allowed(Principal {
                subject: "node:abc".into(),
                tier: Tier::Peer
            })
        );
    }

    #[test]
    fn a_peer_token_never_satisfies_the_operator_class() {
        let (policy, _secret, sym, _) = fixture(AuthMode::Require);
        let tok = mint_peer_token(&sym, "node:abc", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Allowed(_)), "precondition");
        let verdict = decide(&policy, AuthClass::Operator, out);
        assert_eq!(verdict.unwrap_err().0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn an_operator_token_also_satisfies_the_peer_class() {
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let tok = mint_operator_token(&secret, "user:leif", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(decide(&policy, AuthClass::Peer, out).unwrap().is_some());
    }

    #[test]
    fn a_token_from_an_untrusted_operator_key_is_refused() {
        let (policy, _secret, _sym, _) = fixture(AuthMode::Require);
        let stranger = AsymmetricKeyPair::<V4>::generate().unwrap();
        let tok = mint_operator_token(&stranger.secret, "user:mallory", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Invalid(_)), "got {out:?}");
    }

    #[test]
    fn a_peer_token_under_a_foreign_cluster_key_is_refused() {
        let (policy, _secret, _sym, _) = fixture(AuthMode::Require);
        let foreign = SymmetricKey::<V4>::generate().unwrap();
        let tok = mint_peer_token(&foreign, "node:mallory", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Invalid(_)), "got {out:?}");
    }

    #[test]
    fn an_expired_token_is_refused() {
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let tok = mint_operator_token(&secret, "user:leif", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_301);
        assert!(matches!(out, AuthOutcome::Invalid(ref e) if e.contains("expired")), "got {out:?}");
    }

    #[test]
    fn a_token_with_an_absurd_exp_is_refused_even_though_it_signs() {
        // Mint by hand — `mint_operator_token` refuses the TTL itself, so a
        // hostile minter is the only way to produce this shape.
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let payload = serde_json::json!({
            "aud": AUDIENCE, "sub": "user:leif", "iat": 1_000,
            "exp": 1_000 + MAX_TOKEN_TTL_SECS * 365,
            "scope": [OPERATOR_SCOPE],
        })
        .to_string();
        let tok = PublicToken::sign(&secret, payload.as_bytes(), None, None).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Invalid(ref e) if e.contains("ceiling")), "got {out:?}");
    }

    #[test]
    fn a_cheers_audience_token_signed_by_a_trusted_key_is_still_refused_here() {
        // The replay this audience check exists to stop: yubaba mints
        // cheers-audience tokens with an Ed25519 service-principal key. If
        // that key were ever also in the operator trust set, the token must
        // still not open this surface.
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let payload = serde_json::json!({
            "aud": "https://cheers.yah.dev", "sub": "svc:yubaba", "iat": 1_000, "exp": 1_300,
            "scope": ["ownership:write", OPERATOR_SCOPE],
        })
        .to_string();
        let tok = PublicToken::sign(&secret, payload.as_bytes(), None, None).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Invalid(ref e) if e.contains("audience")), "got {out:?}");
    }

    #[test]
    fn a_token_missing_the_tier_scope_is_refused() {
        let (policy, secret, _sym, _) = fixture(AuthMode::Require);
        let payload = serde_json::json!({
            "aud": AUDIENCE, "sub": "user:leif", "iat": 1_000, "exp": 1_300,
            "scope": [PEER_SCOPE],
        })
        .to_string();
        let tok = PublicToken::sign(&secret, payload.as_bytes(), None, None).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert!(matches!(out, AuthOutcome::Invalid(ref e) if e.contains("scope")), "got {out:?}");
    }

    #[test]
    fn warn_mode_serves_anonymous_but_still_refuses_a_bad_credential() {
        let (policy, _secret, _sym, _) = fixture(AuthMode::Warn);
        assert!(
            decide(&policy, AuthClass::Operator, AuthOutcome::Anonymous)
                .unwrap()
                .is_none(),
            "warn mode must serve an anonymous caller"
        );
        let stranger = AsymmetricKeyPair::<V4>::generate().unwrap();
        let tok = mint_operator_token(&stranger.secret, "user:mallory", 300, 1_000).unwrap();
        let out = authenticate(&policy, Some(&format!("Bearer {tok}")), 1_010);
        assert_eq!(
            decide(&policy, AuthClass::Operator, out).unwrap_err().0,
            StatusCode::UNAUTHORIZED,
            "warn mode is not auth-off: a presented-and-bad credential is refused"
        );
    }

    #[test]
    fn require_mode_refuses_anonymous_on_peer_and_operator_but_not_public() {
        let (policy, _secret, _sym, _) = fixture(AuthMode::Require);
        for class in [AuthClass::Peer, AuthClass::Operator] {
            assert_eq!(
                decide(&policy, class, AuthOutcome::Anonymous).unwrap_err().0,
                StatusCode::UNAUTHORIZED,
                "{class:?} must refuse anonymous under require"
            );
        }
        assert!(decide(&policy, AuthClass::Public, AuthOutcome::Anonymous)
            .unwrap()
            .is_none());
    }

    #[test]
    fn require_with_no_trust_root_refuses_to_build() {
        let err = HttpAuthPolicy::new(AuthMode::Require, &[], None).unwrap_err();
        assert!(err.contains("no trust root"), "got {err}");
    }

    #[test]
    fn the_default_policy_is_warn_with_no_keys() {
        let policy = HttpAuthPolicy::default();
        assert!(!policy.is_enforcing());
        assert!(!policy.has_trust_root());
        assert_eq!(
            authenticate(&policy, None, 1_000),
            AuthOutcome::Anonymous,
            "no header is anonymous, not invalid"
        );
    }

    #[test]
    fn a_non_bearer_authorization_header_is_invalid_not_anonymous() {
        let (policy, _secret, _sym, _) = fixture(AuthMode::Warn);
        let out = authenticate(&policy, Some("Basic aGk6dGhlcmU="), 1_000);
        assert!(matches!(out, AuthOutcome::Invalid(_)), "got {out:?}");
    }

    #[test]
    fn auth_mode_parses_both_spellings_and_rejects_the_rest() {
        assert_eq!(AuthMode::parse("warn").unwrap(), AuthMode::Warn);
        assert_eq!(AuthMode::parse(" REQUIRE ").unwrap(), AuthMode::Require);
        assert!(AuthMode::parse("off").is_err());
    }

    #[test]
    fn a_hand_built_state_defaults_to_the_permissive_policy() {
        // Pins the invariant the ~900 credential-free router tests in this
        // crate depend on: a `ServerState` nobody configured serves them.
        let tmp = tempfile::TempDir::new().unwrap();
        let state = crate::ServerState::load(tmp.path().join("identity.json")).unwrap();
        assert!(!state.http_auth.is_enforcing());
        assert!(!state.http_auth.has_trust_root());
    }

    #[test]
    fn hex_round_trips_and_rejects_the_wrong_length() {
        let raw = [0xab_u8; 32];
        assert_eq!(decode_hex32(&encode_hex(&raw)).unwrap(), raw);
        assert!(decode_hex32("abcd").is_err());
        assert!(decode_hex32(&"z".repeat(64)).is_err());
    }
}

/// R876-B15's verify bar: the refusal asserted through the **real**
/// [`crate::build_router`], the way R876-B13's regression test drives the
/// real router rather than a hand-built one. A policy that only works in
/// [`authenticate`] is a policy that is not wired.
#[cfg(test)]
mod router_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use std::sync::Arc;
    use tower::ServiceExt;

    /// An enforcing node plus the two secret halves its callers mint with.
    fn enforcing_node() -> (
        tempfile::TempDir,
        Arc<crate::ServerState>,
        AsymmetricSecretKey<V4>,
        SymmetricKey<V4>,
    ) {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let sym = SymmetricKey::<V4>::generate().unwrap();
        let policy = HttpAuthPolicy::new(
            AuthMode::Require,
            &[encode_hex(kp.public.as_bytes())],
            Some(&encode_hex(sym.as_bytes())),
        )
        .unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let state = crate::ServerState::load(tmp.path().join("identity.json"))
            .unwrap()
            .with_http_auth(policy);
        (tmp, Arc::new(state), kp.secret, sym)
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    /// The three routes the ticket names by hand: reads a spec, deploys a
    /// workload, self-updates the binary. Plus `/secrets`, which is the one
    /// with a clean 200 to prove non-vacuity against.
    fn operator_probes() -> Vec<Request<Body>> {
        vec![
            Request::get("/workloads/yah-marketing/spec")
                .body(Body::empty())
                .unwrap(),
            Request::post("/workloads/deploy")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"spec":{}}"#))
                .unwrap(),
            // R892-B1. Same class as /workloads/deploy: it judges a deploy
            // body, and its answer states this node's admission policy.
            Request::post("/workloads/validate")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"spec":{}}"#))
                .unwrap(),
            Request::post("/self-update")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"version":"0.0.0","url":"http://x/y","sha256":"00"}"#,
                ))
                .unwrap(),
            Request::get("/secrets").body(Body::empty()).unwrap(),
        ]
    }

    #[tokio::test]
    async fn an_unauthenticated_request_is_refused_on_every_operator_route() {
        let (_tmp, state, _sk, _sym) = enforcing_node();
        for req in operator_probes() {
            let uri = req.uri().clone();
            let resp = crate::build_router(Arc::clone(&state))
                .oneshot(req)
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{uri} served an unauthenticated caller"
            );
        }
    }

    /// Non-vacuity. Without this, breaking the surface outright would pass
    /// the test above.
    #[tokio::test]
    async fn an_operator_token_still_gets_through_to_the_handler() {
        let (_tmp, state, sk, _sym) = enforcing_node();
        let token = mint_operator_token(&sk, "user:leif", 300, now_unix()).unwrap();
        for mut req in operator_probes() {
            req.headers_mut().insert(
                axum::http::header::AUTHORIZATION,
                bearer(&token).parse().unwrap(),
            );
            let uri = req.uri().clone();
            let resp = crate::build_router(Arc::clone(&state))
                .oneshot(req)
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{uri} refused a valid operator token"
            );
            assert_ne!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{uri} refused a valid operator token"
            );
        }
        // `POST /workloads/drain` is the one operator route that reaches a
        // clean 200 on a state with no runtime wired (see
        // `drain_workloads_returns_empty_until_runtime`), so this pins "the
        // handler RAN" rather than merely "the handler changed which error
        // it returns".
        let resp = crate::build_router(Arc::clone(&state))
            .oneshot(
                Request::post("/workloads/drain")
                    .header(axum::http::header::AUTHORIZATION, bearer(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Holding the cluster key makes you a member, not an administrator.
    #[tokio::test]
    async fn a_peer_token_cannot_deploy_or_self_update() {
        let (_tmp, state, _sk, sym) = enforcing_node();
        let token = mint_peer_token(&sym, "node:us-east-001", 300, now_unix()).unwrap();
        for mut req in operator_probes() {
            req.headers_mut().insert(
                axum::http::header::AUTHORIZATION,
                bearer(&token).parse().unwrap(),
            );
            let uri = req.uri().clone();
            let resp = crate::build_router(Arc::clone(&state))
                .oneshot(req)
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{uri} accepted a peer token"
            );
        }
    }

    /// The rolling-fleet half of the bar: node-to-node traffic keeps working
    /// with the cluster key alone, so a partially-upgraded fleet still holds
    /// elections and forwards writes.
    #[tokio::test]
    async fn a_peer_token_opens_the_node_to_node_routes() {
        let (_tmp, state, _sk, sym) = enforcing_node();
        let token = mint_peer_token(&sym, "node:us-east-001", 300, now_unix()).unwrap();
        for path in ["/capabilities", "/workloads", "/raft/status"] {
            let anon = crate::build_router(Arc::clone(&state))
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                anon.status(),
                StatusCode::UNAUTHORIZED,
                "{path} served an unauthenticated caller"
            );

            let authed = crate::build_router(Arc::clone(&state))
                .oneshot(
                    Request::get(path)
                        .header(axum::http::header::AUTHORIZATION, bearer(&token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                authed.status(),
                StatusCode::UNAUTHORIZED,
                "{path} refused a valid peer token"
            );
            assert_ne!(
                authed.status(),
                StatusCode::FORBIDDEN,
                "{path} refused a valid peer token"
            );
        }
    }

    /// `/health` has to answer before a node is configured — that is what it
    /// is for, and hotship polls it to decide whether a restart landed.
    #[tokio::test]
    async fn the_public_probes_stay_open_under_require() {
        let (_tmp, state, _sk, _sym) = enforcing_node();
        for path in ["/health", "/mesh/leader-health"] {
            let resp = crate::build_router(Arc::clone(&state))
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
    }

    /// `route_layer`, not `layer`: an unknown path must still 404. Otherwise
    /// the surface answers "401" for routes that exist and "401" for routes
    /// that do not, which is a probe oracle wearing a security control's hat.
    #[tokio::test]
    async fn an_unknown_path_is_a_404_not_a_401() {
        let (_tmp, state, _sk, _sym) = enforcing_node();
        let resp = crate::build_router(state)
            .oneshot(
                Request::get("/no/such/route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// The default (and therefore the fleet's behaviour the moment this
    /// ships) serves an unauthenticated deploy and logs it — and still
    /// refuses a credential that is present and bad.
    #[tokio::test]
    async fn warn_mode_serves_the_fleet_but_not_a_forged_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        let stranger = AsymmetricKeyPair::<V4>::generate().unwrap();
        let trusted = AsymmetricKeyPair::<V4>::generate().unwrap();
        let policy = HttpAuthPolicy::new(
            AuthMode::Warn,
            &[encode_hex(trusted.public.as_bytes())],
            None,
        )
        .unwrap();
        let state = Arc::new(
            crate::ServerState::load(tmp.path().join("identity.json"))
                .unwrap()
                .with_http_auth(policy),
        );

        let anon = crate::build_router(Arc::clone(&state))
            .oneshot(
                Request::post("/workloads/drain")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            anon.status(),
            StatusCode::OK,
            "warn mode must not break a caller that sends nothing"
        );

        let forged = mint_operator_token(&stranger.secret, "user:mallory", 300, now_unix()).unwrap();
        let resp = crate::build_router(state)
            .oneshot(
                Request::post("/workloads/drain")
                    .header(axum::http::header::AUTHORIZATION, bearer(&forged))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "warn mode is a roll sequencer, not auth-off"
        );
    }
}
