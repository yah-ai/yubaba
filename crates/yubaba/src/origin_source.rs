//! The fleet daemon's half of the joiner-lineage gate (noisetable R118-T11, `W158` §7.2(2)).
//!
//! [`membership_ratchet::judge_origin`] is pure and lives in `yubaba-consensus`.
//! *Reading* the lineage off the joiner is not: it is two GETs against
//! `/raft/status` and `/health`, and `/health` is a route THIS crate defines,
//! shaped by this crate's `cluster_epoch` constants. So the fetch stays here,
//! behind [`membership_ratchet::OriginSource`], and consensus depends on a trait
//! instead of on another crate's route schema.
//!
//! The wire behaviour is byte-for-byte what R118-F8 shipped as
//! `membership_ratchet::ask_origin` — same two routes, same timeout, same error
//! strings. Only the crate that names the routes changed.

use yubaba_consensus::membership_ratchet::{NodeOrigin, OriginSource, ASK_TIMEOUT};

/// Ask a joiner over plain HTTP, on the address the leader is about to start
/// replicating to.
///
/// A fresh client per call rather than a shared one: this runs once per join,
/// never on a hot path, and a connection pool held open to a node that may be
/// refused is worth less than the absence of one more long-lived resource on
/// `ServerState`.
pub struct HttpOriginSource;

#[async_trait::async_trait]
impl OriginSource for HttpOriginSource {
    async fn ask_origin(&self, addr: &str) -> Result<NodeOrigin, String> {
        let client = reqwest::Client::builder()
            .timeout(ASK_TIMEOUT)
            .build()
            .map_err(|e| format!("build http client: {e}"))?;

        let get_json = async |url: String| -> Result<serde_json::Value, String> {
            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("GET {url}: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("GET {url}: HTTP {}", resp.status()));
            }
            resp.json::<serde_json::Value>()
                .await
                .map_err(|e| format!("GET {url}: decoding body: {e}"))
        };

        let status = get_json(format!("http://{addr}/raft/status")).await?;
        // A node that has never been in a cluster reports term 0, which is the
        // ordinary "brand new plinth" case and passes every clause of
        // `judge_origin`.
        let last_seen_term = status
            .get("current_term")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("{addr}/raft/status carries no current_term"))?;

        let health = get_json(format!("http://{addr}/health")).await?;
        let epoch = |key: &str| -> Result<u32, String> {
            health
                .get(key)
                .and_then(serde_json::Value::as_u64)
                .map(|v| v as u32)
                .ok_or_else(|| format!("{addr}/health carries no {key}"))
        };

        Ok(NodeOrigin {
            cluster_protocol: epoch("cluster_protocol")?,
            state_epoch: epoch("state_epoch")?,
            last_seen_term,
        })
    }
}

/// This build's two cluster-compatibility integers, as consensus wants them.
///
/// The one place `cluster_epoch`'s compile-time constants are lifted into the
/// value consensus takes — the ratchet loop stamps them onto every
/// `MembershipRatchetRecord`, and the add-learner gate compares a joiner's
/// against them. Reading them in two places is how they would come to disagree.
pub fn build_epochs() -> yubaba_consensus::membership_ratchet::BuildEpochs {
    yubaba_consensus::membership_ratchet::BuildEpochs {
        cluster_protocol: crate::cluster_epoch::CLUSTER_PROTOCOL,
        state_epoch: crate::cluster_epoch::STATE_EPOCH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Json, Router};
    use tokio::net::TcpListener;

    async fn serve(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        addr
    }

    /// The happy path, end to end over a real socket: both routes answer and the
    /// three fields land where `judge_origin` expects them.
    #[tokio::test]
    async fn reads_the_term_from_raft_status_and_the_epochs_from_health() {
        let addr = serve(
            Router::new()
                .route(
                    "/raft/status",
                    get(|| async { Json(serde_json::json!({ "current_term": 9 })) }),
                )
                .route(
                    "/health",
                    get(|| async {
                        Json(serde_json::json!({ "cluster_protocol": 7, "state_epoch": 6 }))
                    }),
                ),
        )
        .await;

        let origin = HttpOriginSource.ask_origin(&addr).await.expect("asked");
        assert_eq!(
            origin,
            NodeOrigin {
                cluster_protocol: 7,
                state_epoch: 6,
                last_seen_term: 9,
            }
        );
    }

    /// A joiner that answers `/raft/status` but whose `/health` is missing an
    /// epoch must FAIL, not default. An absent epoch read as 0 would compare
    /// unequal to every real build and so refuse — but for the wrong reason, and
    /// with an operator message pointing at a build mismatch that isn't there.
    #[tokio::test]
    async fn a_health_body_missing_an_epoch_is_an_error_naming_the_key() {
        let addr = serve(
            Router::new()
                .route(
                    "/raft/status",
                    get(|| async { Json(serde_json::json!({ "current_term": 1 })) }),
                )
                .route(
                    "/health",
                    get(|| async { Json(serde_json::json!({ "cluster_protocol": 7 })) }),
                ),
        )
        .await;

        let err = HttpOriginSource
            .ask_origin(&addr)
            .await
            .expect_err("a health body with no state_epoch cannot answer this question");
        assert!(err.contains("state_epoch"), "{err}");
        assert!(err.contains(&addr), "the operator must be told WHICH node: {err}");
    }

    /// The epochs consensus stamps onto a record are this build's, not a
    /// hand-copied pair. Guards against the two readers drifting.
    #[test]
    fn build_epochs_reports_what_cluster_epoch_declares() {
        let e = build_epochs();
        assert_eq!(e.cluster_protocol, crate::cluster_epoch::CLUSTER_PROTOCOL);
        assert_eq!(e.state_epoch, crate::cluster_epoch::STATE_EPOCH);
        assert_eq!(
            e.lineage(4).current_term,
            4,
            "the term is a runtime reading and must not be baked into the build constants"
        );
    }
}
