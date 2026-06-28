//! @yah:ticket(R335-F3, "Mirror-aware /revalidate receiver: reject feeds not bound to this mirror")
//! @yah:assignee(bundle-anthropic-miravel)
//! @yah:at(2026-05-27T07:09:31Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R335)
//! @yah:next("Construct the receiver with its own mirror identity (env + service id).")
//! @yah:next("On revalidate: load the feed, reject (4xx) unless on_change.service resolves to a mirror binding matching the receiver's own env.")
//! @yah:next("Lands with R330-F4 (wires receiver into the reconciler). Satisfies R335-T2's negative case WITHOUT auth.")
//!
//! @yah:ticket(R335-F5, "Per-mirror capability gate on /revalidate (yubaba/xlb-net node identity)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-27T02:39:12Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R335)
//! @yah:next("Design captured in .yah/docs/working/W058-almanac-mirror-binding.md §12. Implementation gated on yubaba control plane (authorized-signer-set provisioning + rotation) — file a fresh impl ticket when yubaba lands.")
//! @yah:next("Near-term mechanism = mode A (signed request over the existing HTTP receiver, asymmetric, request-bound); converges to mode C (xlb-net authenticated transport, verified peer NodeId) for cross-machine cloud/ha. mode B (macaroon) reserved for delegation/attenuation only.")
//! @yah:next("When buildable: add authorized_signers (from .yah/services/<id>/mirrors/<env>.toml) to MirrorBind; replace the mirror_key body field with {signer,nonce,expiry,sig}; 401 invalid sig / 403 signer-not-authorized; nonce+expiry freshness cache.")
//! @yah:next("Bootstrap = operator key seeded into the cloud receiver's signer set + revalidate port on ExposeSpec.operator (Tailscale tag) — mirror-sage.")
//! @yah:handoff("Design-only deliverable complete. §12 of .yah/docs/working/W058-almanac-mirror-binding.md specifies the per-mirror /revalidate capability gate: (1) why mirror_key is insufficient (static symmetric bearer secret, replayable, identity-blind, no freshness); (2) identity grain = yubaba/xlb-net Ed25519 node identity (yubaba/src/identity.rs hostkey + iroh NodeId), infra not cheers; (3) mechanism options A signed-request / B macaroon / C authenticated-transport with recommendation (A near-term on the existing HTTP receiver, converging to C for cross-machine cloud/ha); (4) authorized-signer set declared in .yah/services/<id>/mirrors/<env>.toml, composing with OnChangeConfig.service (not a new AlmanacManifest field); (5) operator-bridge bootstrap riding ExposeSpec.operator Tailscale tag (mirror-sage); (6) receiver-shape sketch + status codes. receiver.rs MirrorBind.env and mirror_key doc comments now point at §12. NO mechanism built — implementation gated on yubaba's control plane.")
//! @yah:gotcha("F5 SUPERSEDES mirror_key (R335-F2) — it is a replacement, not an additional auth knob. F3's feed-binding check (is-this-feed-mine) is orthogonal to F5 (are-you-allowed-to-ask) and stays.")
//!

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::config::{ConfigError, FeedLoader, OnChangeConfig};

/// Sender half of the revalidation channel. Clone and pass into `router()`.
pub type RevalidateTx = mpsc::Sender<String>;

/// Mirror identity for feed-binding validation.
///
/// When supplied to [`router`], every `/revalidate` request is checked: the
/// named feed must have an `on_change.service` matching `service_id`. Requests
/// for feeds bound to a different service (or with no binding) are rejected
/// with 422, keeping each receiver single-tenant.
#[derive(Clone)]
pub struct MirrorBind {
    /// Service id this receiver belongs to (`.yah/services/<id>/service.toml`).
    pub service_id: String,
    /// Mirror environment, e.g. `"cloud"`, `"pond"`, `"dev"`. Stored for
    /// logging; also the key the R335-F5 capability gate scopes its
    /// authorized-signer set by (per-`(service, env)` mirror). See the design
    /// in `.yah/docs/working/W058-almanac-mirror-binding.md` §12 — it supersedes the
    /// static `mirror_key` below with a node-identity signature once yubaba's
    /// control plane can provision the signer set.
    pub env: String,
    /// Directory containing feed TOML files (`.yah/almanac/`).
    pub almanac_dir: PathBuf,
}

#[derive(Clone)]
struct ReceiverState {
    tx: RevalidateTx,
    /// When `Some`, inbound requests must carry the same key or receive 403.
    /// Static shared bearer secret — the pre-capability stopgap (R335-F2) that
    /// R335-F5 supersedes with a node-identity signature (design §12 of
    /// `.yah/docs/working/W058-almanac-mirror-binding.md`).
    mirror_key: Option<String>,
    /// When `Some`, the receiver validates feed-level mirror binding before
    /// forwarding. Feed not found → 404; wrong/missing service → 422.
    bind: Option<Arc<MirrorBind>>,
}

/// Build an axum `Router` that accepts `POST /revalidate` with body
/// `{"feed": "<name>"}` and forwards the feed name over the provided channel.
///
/// `mirror_key`: when `Some`, the body must carry `"mirror_key": "<same value>"`
/// or the request is rejected with 403.
///
/// `bind`: when `Some`, each request is validated against the feed's
/// `on_change.service` — feeds not bound to this mirror's service are rejected
/// with 422. Satisfies R335-F3 (scope a feed to the mirror it affects).
///
/// Typical wiring:
/// ```rust,ignore
/// let (tx, mut rx) = tokio::sync::mpsc::channel(16);
/// let app = almanac::receiver::router(tx, None, None);
/// // axum::serve(listener, app) in a task
/// // tokio::spawn(async move { while let Some(feed) = rx.recv().await { … } });
/// ```
pub fn router(tx: RevalidateTx, mirror_key: Option<String>, bind: Option<MirrorBind>) -> Router {
    Router::new()
        .route("/revalidate", post(revalidate_handler))
        .with_state(ReceiverState { tx, mirror_key, bind: bind.map(Arc::new) })
}

async fn revalidate_handler(
    State(state): State<ReceiverState>,
    Json(body): Json<RevalidateBody>,
) -> StatusCode {
    // Mirror-key auth: reject cross-mirror revalidates.
    if let Some(ref expected) = state.mirror_key {
        match &body.mirror_key {
            Some(provided) if provided == expected => {}
            _ => {
                tracing::warn!(
                    feed = %body.feed,
                    "revalidate rejected — mirror_key mismatch (cross-mirror pollution blocked)"
                );
                return StatusCode::FORBIDDEN;
            }
        }
    }

    // Feed-level binding check: reject feeds not bound to this mirror's service.
    if let Some(ref bind) = state.bind {
        let loader = FeedLoader::new(&bind.almanac_dir);
        match loader.load(&body.feed) {
            Err(ConfigError::NotFound(_)) => {
                tracing::warn!(
                    feed = %body.feed,
                    service = %bind.service_id,
                    env = %bind.env,
                    "revalidate rejected — feed not found in almanac"
                );
                return StatusCode::NOT_FOUND;
            }
            Err(e) => {
                tracing::error!(
                    feed = %body.feed,
                    err = %e,
                    "revalidate — failed to load feed config"
                );
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
            Ok(cfg) => {
                let bound_service = match &cfg.feed.emit.on_change {
                    Some(OnChangeConfig::MesofactRebuild { service, .. }) => service.as_str(),
                    None => {
                        tracing::warn!(
                            feed = %body.feed,
                            service = %bind.service_id,
                            env = %bind.env,
                            "revalidate rejected — feed has no mirror binding (no on_change)"
                        );
                        return StatusCode::UNPROCESSABLE_ENTITY;
                    }
                };
                if bound_service != bind.service_id.as_str() {
                    tracing::warn!(
                        feed = %body.feed,
                        feed_bound_to = bound_service,
                        receiver_service = %bind.service_id,
                        receiver_env = %bind.env,
                        "revalidate rejected — feed is bound to a different mirror"
                    );
                    return StatusCode::UNPROCESSABLE_ENTITY;
                }
            }
        }
    }

    tracing::info!(feed = %body.feed, "revalidate request received");
    match state.tx.try_send(body.feed) {
        Ok(_) => StatusCode::OK,
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("revalidate channel full — dropping request");
            StatusCode::SERVICE_UNAVAILABLE
        }
        Err(mpsc::error::TrySendError::Closed(_)) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[derive(Deserialize)]
struct RevalidateBody {
    feed: String,
    /// Caller's mirror identity token. Must match the receiver's configured
    /// `mirror_key` when one is set; absent or mismatched → 403.
    #[serde(default)]
    mirror_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use std::fs;
    use tempfile::TempDir;
    use tower::util::ServiceExt;

    async fn post_json(app: Router, body: &'static str) -> axum::response::Response {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/revalidate")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        app.oneshot(req).await.unwrap()
    }

    fn write_feed(dir: &std::path::Path, name: &str, service: Option<&str>) {
        let on_change = match service {
            Some(svc) => format!(
                "\n[feed.emit.on_change]\nkind = \"mesofact-rebuild\"\nservice = \"{svc}\"\nroute = \"/releases\""
            ),
            None => String::new(),
        };
        let toml = format!(
            "[feed]\nname = \"{name}\"\n\n[feed.source]\nkind = \"gh-releases\"\nrepo = \"o/r\"\n\n[feed.trigger]\nkind = \"webhook\"\n\n[feed.emit]\nartifact = \"out.json\"{on_change}"
        );
        fs::write(dir.join(format!("{name}.toml")), toml).unwrap();
    }

    // ── mirror_key auth (R335-F2) ────────────────────────────────────────────

    #[tokio::test]
    async fn revalidate_sends_feed_name() {
        let (tx, mut rx) = mpsc::channel(4);
        let app = router(tx, None, None);
        let resp = post_json(app,r#"{"feed":"releases"}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(rx.try_recv().unwrap(), "releases");
    }

    #[tokio::test]
    async fn full_channel_returns_503() {
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send("already-full".to_string()).unwrap();
        let app = router(tx, None, None);
        let resp = post_json(app,r#"{"feed":"releases"}"#).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn correct_mirror_key_passes() {
        let (tx, mut rx) = mpsc::channel(4);
        let app = router(tx, Some("secret-abc".to_string()), None);
        let resp = post_json(app,r#"{"feed":"releases","mirror_key":"secret-abc"}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(rx.try_recv().unwrap(), "releases");
    }

    #[tokio::test]
    async fn wrong_mirror_key_returns_403() {
        let (tx, _rx) = mpsc::channel(4);
        let app = router(tx, Some("secret-abc".to_string()), None);
        let resp = post_json(app,r#"{"feed":"releases","mirror_key":"wrong-key"}"#).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn absent_mirror_key_returns_403_when_configured() {
        let (tx, _rx) = mpsc::channel(4);
        let app = router(tx, Some("secret-abc".to_string()), None);
        let resp = post_json(app,r#"{"feed":"releases"}"#).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn no_configured_key_accepts_any_request() {
        let (tx, mut rx) = mpsc::channel(4);
        let app = router(tx, None, None);
        let resp = post_json(app,r#"{"feed":"releases","mirror_key":"anything"}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(rx.try_recv().unwrap(), "releases");
    }

    // ── mirror binding (R335-F3) ─────────────────────────────────────────────

    fn bind(dir: &std::path::Path, service_id: &str) -> MirrorBind {
        MirrorBind {
            service_id: service_id.to_string(),
            env: "cloud".to_string(),
            almanac_dir: dir.to_path_buf(),
        }
    }

    #[tokio::test]
    async fn feed_matching_service_passes() {
        let tmp = TempDir::new().unwrap();
        write_feed(tmp.path(), "releases", Some("dev-yah"));
        let (tx, mut rx) = mpsc::channel(4);
        let app = router(tx, None, Some(bind(tmp.path(), "dev-yah")));
        let resp = post_json(app,r#"{"feed":"releases"}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(rx.try_recv().unwrap(), "releases");
    }

    #[tokio::test]
    async fn feed_wrong_service_returns_422() {
        let tmp = TempDir::new().unwrap();
        write_feed(tmp.path(), "releases", Some("other-service"));
        let (tx, _rx) = mpsc::channel(4);
        let app = router(tx, None, Some(bind(tmp.path(), "dev-yah")));
        let resp = post_json(app,r#"{"feed":"releases"}"#).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn feed_no_on_change_returns_422() {
        let tmp = TempDir::new().unwrap();
        write_feed(tmp.path(), "releases", None); // no on_change
        let (tx, _rx) = mpsc::channel(4);
        let app = router(tx, None, Some(bind(tmp.path(), "dev-yah")));
        let resp = post_json(app,r#"{"feed":"releases"}"#).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn feed_not_in_almanac_returns_404() {
        let tmp = TempDir::new().unwrap(); // empty almanac dir
        let (tx, _rx) = mpsc::channel(4);
        let app = router(tx, None, Some(bind(tmp.path(), "dev-yah")));
        let resp = post_json(app,r#"{"feed":"nonexistent"}"#).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn no_bind_skips_feed_check() {
        // Without a bind, any feed name is forwarded regardless of almanac state.
        let (tx, mut rx) = mpsc::channel(4);
        let app = router(tx, None, None);
        let resp = post_json(app,r#"{"feed":"unknown-feed"}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(rx.try_recv().unwrap(), "unknown-feed");
    }
}
