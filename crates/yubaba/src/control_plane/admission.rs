//! @arch:layer(core)
//! @arch:role(net)
//!
//! **Who may dial this node's control plane** — the entitlement half of
//! W268's "machines are dialed, accounts are authorized, enrollment
//! marries them".
//!
//! Part of R609-F3 — canonical annotation in
//! `.yah/docs/working/W242-yubaba-mesh-raft-roadmap.md`.
//!
//! mshr's QUIC/TLS handshake answers W268's *first* question by
//! construction — **which machine is this connection?** — because the
//! `NodeId` handed to an [`mshr::Acceptor`] comes from the peer's verified
//! TLS certificate. It answers nothing about the *third* question,
//! **is that machine entitled to anything here?**, and mshr deliberately
//! never will: the crate-DAG rule in W268 §"What stays deliberately
//! separate" says mshr never depends on cheers, so the binding is *data in
//! cheers, enforced by services*. This module is yubaba's half of that
//! enforcement, and it runs at the listener — a denied `NodeId` is closed
//! before its ALPN handler ever runs, so no application byte is read, no
//! workspace is named, and no process is spawned.
//!
//! ## The two entitlement sources
//!
//! 1. **Static allowlist** — `NodeId`s the operator named on the command
//!    line (`serve --control-plane-allow <node-id>`), plus this node's own
//!    `NodeId`. This is the bootstrap path: a freshly-provisioned node has
//!    no cheers rows yet, and the operator's desktop has to get in
//!    somehow. R609-F5's TOFU pin lands in this same set.
//! 2. **Cheers enrollment** — the live `node` ownership rows this yubaba
//!    itself wrote via [`CheersClient::enroll_node`] (W268 §"The binding:
//!    enrollment is an ownership row"). This is the fleet path: admit
//!    every machine we admitted into the fleet, and stop admitting it the
//!    moment its row is revoked.
//!
//! A `NodeId` in either source is admitted; everything else is refused.
//!
//! ### What the cheers source cannot see, and why
//!
//! `GET /ownership?principal_id=` is the *writer's management read* — it
//! returns only rows whose `granted_by` matches the caller's own verified
//! `sub` (cheers-axum `ownership::list`, tightened by R593-F8/F9). So this
//! lookup sees fleet machines yubaba enrolled and **not** an end-user
//! device enrolled to a human principal by cheers's own LAN-pair
//! ceremony (R593-F9). Admitting those needs either a resource-side
//! lookup route on cheers (`who owns node:<id>` — a cross-tenant read that
//! wants its own design pass) or the local pin. Until then a desktop
//! reaches a node through source 1, which is exactly the shape R609-F5
//! specifies: TOFU on first connect, pinned thereafter.
//!
//! ## Failure posture
//!
//! Default-deny, with one deliberate exception: when a cheers lookup
//! *fails* and a previous snapshot exists, the stale snapshot is used and
//! the failure is logged at WARN. A cheers outage would otherwise lock an
//! operator out of every node in the fleet at once — the blast radius of
//! failing closed there is far worse than the blast radius of honouring a
//! revocation one refresh window late, and revocation already has that
//! window of slack by construction. With no snapshot at all (a cheers
//! outage spanning this process's whole life) the lookup fails closed and
//! only the static allowlist admits.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mshr::{AcceptDecision, NodeId};

use crate::cheers_client::{CheersClient, NODE_RESOURCE_KIND};

/// How long a cheers enrollment snapshot is served before it is refetched.
///
/// The upper bound on how late a revocation takes effect, and the lower
/// bound on how often a busy node hits cheers — one request per window
/// regardless of dial volume, because the whole enrolled set is cached as
/// one snapshot rather than per-`NodeId`. 30s keeps eviction prompt
/// (W268: machines are *evicted*, and an eviction that takes minutes is
/// not an eviction) without making the acceptor a load generator.
pub const DEFAULT_ENROLLMENT_TTL: Duration = Duration::from_secs(30);

/// Who may open a connection to this node's control-plane endpoint.
///
/// Registered on the endpoint via [`mshr::EndpointBuilder::acceptor`], so
/// the decision runs after the handshake (the `NodeId` is authenticated)
/// and before application dispatch (nothing has been served yet).
#[derive(Clone, Default)]
pub enum Admission {
    /// Every `NodeId` is admitted. The pre-F3 posture, kept as an
    /// explicit, named state rather than an absence — "no policy
    /// configured" and "policy is: everyone" should not be the same value
    /// in a security decision, because only one of them is a choice.
    ///
    /// Lanes that do more than greet refuse to serve under this variant;
    /// see [`super::Planes::camp_rpc_lane`].
    #[default]
    AllowAll,
    /// Default-deny: a `NodeId` is admitted only if some source entitles
    /// it.
    Entitled(Arc<Entitlement>),
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllowAll => f.write_str("Admission::AllowAll"),
            Self::Entitled(e) => f
                .debug_struct("Admission::Entitled")
                .field("allowlisted", &e.allow.len())
                .field("cheers_enrollment", &e.enrollment.is_some())
                .finish(),
        }
    }
}

impl Admission {
    /// Build the default-deny policy from an [`Entitlement`].
    pub fn entitled(entitlement: Entitlement) -> Self {
        Self::Entitled(Arc::new(entitlement))
    }

    /// Whether this is the admit-everyone posture. Lanes with side effects
    /// beyond a greeting key off this.
    pub fn is_allow_all(&self) -> bool {
        matches!(self, Self::AllowAll)
    }

    /// Decide one connection. Split out from the [`mshr::Acceptor`] impl so
    /// it is directly unit-testable without standing up an endpoint.
    pub async fn decide(&self, remote: NodeId) -> AcceptDecision {
        match self {
            Self::AllowAll => AcceptDecision::Accept,
            Self::Entitled(entitlement) => entitlement.decide(remote).await,
        }
    }
}

impl mshr::Acceptor for Admission {
    fn accept(&self, remote: NodeId) -> mshr::endpoint::BoxFut<'static, AcceptDecision> {
        // Cheap: `AllowAll` is a unit and `Entitled` is an `Arc`.
        let policy = self.clone();
        Box::pin(async move { policy.decide(remote).await })
    }
}

/// The sources that entitle a `NodeId` to reach this node.
pub struct Entitlement {
    /// Hex-encoded `NodeId`s admitted unconditionally.
    ///
    /// Hex rather than `NodeId` because `iroh`'s key type implements
    /// neither `Hash` nor `Ord`, and because hex is already the one
    /// spelling this system agrees on: it is what `GET /identity` serves,
    /// what `identity::node_id_hex` produces, and what cheers stores in
    /// `resource_id`. `NodeId`'s `Display` is that same lowercase hex, so
    /// a lookup is a plain string compare against `remote.to_string()`.
    allow: HashSet<String>,
    /// Cheers-backed fleet enrollment, when a cheers client is configured.
    enrollment: Option<Enrollment>,
}

impl Entitlement {
    /// An entitlement admitting nobody. Add sources with
    /// [`Self::allow`] / [`Self::with_cheers`].
    pub fn new() -> Self {
        Self {
            allow: HashSet::new(),
            enrollment: None,
        }
    }

    /// Add one `NodeId` to the static allowlist.
    pub fn allow(mut self, node: NodeId) -> Self {
        self.allow.insert(node.to_string());
        self
    }

    /// Add several `NodeId`s to the static allowlist.
    pub fn allow_all_of(mut self, nodes: impl IntoIterator<Item = NodeId>) -> Self {
        self.allow.extend(nodes.into_iter().map(|n| n.to_string()));
        self
    }

    /// Consult cheers for fleet enrollment rows, cached for `ttl`.
    /// Pass [`DEFAULT_ENROLLMENT_TTL`] unless there's a reason not to.
    pub fn with_cheers(mut self, cheers: Arc<CheersClient>, ttl: Duration) -> Self {
        self.enrollment = Some(Enrollment {
            cheers,
            ttl,
            cache: tokio::sync::Mutex::new(None),
        });
        self
    }

    /// How many `NodeId`s are on the static allowlist. For startup logging
    /// — an operator who sees `allowlisted=0, cheers=false` on a node they
    /// can no longer reach has their answer immediately.
    pub fn allowlisted(&self) -> usize {
        self.allow.len()
    }

    /// Whether a cheers enrollment source is configured.
    pub fn has_cheers(&self) -> bool {
        self.enrollment.is_some()
    }

    async fn decide(&self, remote: NodeId) -> AcceptDecision {
        let hex = remote.to_string();
        if self.allow.contains(&hex) {
            tracing::debug!(remote = %hex, "control-plane dial admitted (allowlist)");
            return AcceptDecision::Accept;
        }
        if let Some(enrollment) = &self.enrollment {
            if enrollment.contains(&hex).await {
                tracing::debug!(remote = %hex, "control-plane dial admitted (cheers enrollment)");
                return AcceptDecision::Accept;
            }
        }
        // INFO, not DEBUG: on a node that is supposed to be reachable this
        // is the single line that explains why it isn't, and it should not
        // require raising the log level to find after the fact.
        tracing::info!(
            remote = %hex,
            "control-plane dial refused — NodeId is not allowlisted and holds no live cheers \
             node-enrollment row"
        );
        AcceptDecision::Deny
    }
}

impl Default for Entitlement {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Entitlement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entitlement")
            .field("allowlisted", &self.allow.len())
            .field("cheers_enrollment", &self.enrollment.is_some())
            .finish()
    }
}

/// Cheers-backed enrollment lookup with a TTL'd snapshot of the whole
/// enrolled set.
struct Enrollment {
    cheers: Arc<CheersClient>,
    ttl: Duration,
    /// `tokio` mutex, held across the HTTP call on purpose: it collapses a
    /// burst of concurrent dials arriving on a cold cache into one cheers
    /// request instead of one per connection.
    cache: tokio::sync::Mutex<Option<Snapshot>>,
}

struct Snapshot {
    fetched_at: Instant,
    nodes: HashSet<String>,
}

impl Enrollment {
    async fn contains(&self, node_hex: &str) -> bool {
        let mut cache = self.cache.lock().await;
        let fresh = cache
            .as_ref()
            .is_some_and(|s| s.fetched_at.elapsed() < self.ttl);
        if !fresh {
            match self.fetch().await {
                Ok(nodes) => {
                    *cache = Some(Snapshot {
                        fetched_at: Instant::now(),
                        nodes,
                    });
                }
                Err(e) => {
                    // Stale-serve rather than fail closed — see the module
                    // doc §"Failure posture". With no snapshot at all the
                    // `match` below simply finds nothing and denies.
                    tracing::warn!(
                        error = %e,
                        stale_snapshot = cache.is_some(),
                        "cheers enrollment lookup failed; \
                         serving the last known enrollment set"
                    );
                }
            }
        }
        cache.as_ref().is_some_and(|s| s.nodes.contains(node_hex))
    }

    /// The live `node` rows this yubaba granted to its own service
    /// principal — i.e. the machines it admitted to the fleet.
    async fn fetch(&self) -> Result<HashSet<String>, crate::cheers_client::CheersError> {
        let principal = format!("svc:{}", self.cheers.principal_id());
        let rows = self.cheers.list_ownership(&principal).await?;
        Ok(rows
            .into_iter()
            // `list_ownership` is documented live-only; the `revoked_at`
            // re-check is belt-and-braces, and it is the one filter whose
            // absence would keep an evicted machine dialing.
            .filter(|r| r.revoked_at.is_none() && r.resource_kind == NODE_RESOURCE_KIND)
            .map(|r| r.resource_id.to_ascii_lowercase())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cheers_client::CheersConfig;
    use axum::extract::{Query, State};
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{Json, Router};
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version4::V4;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn node(seed: u8) -> NodeId {
        mshr::Keypair::from_secret(mshr::SecretKey::from_bytes(&[seed; 32])).node_id()
    }

    #[tokio::test]
    async fn allow_all_admits_any_node() {
        let policy = Admission::AllowAll;
        assert_eq!(policy.decide(node(1)).await, AcceptDecision::Accept);
        assert!(policy.is_allow_all());
    }

    #[tokio::test]
    async fn entitled_with_no_sources_admits_nobody() {
        let policy = Admission::entitled(Entitlement::new());
        assert_eq!(policy.decide(node(1)).await, AcceptDecision::Deny);
        assert!(!policy.is_allow_all());
    }

    #[tokio::test]
    async fn allowlisted_node_is_admitted_and_others_are_not() {
        let policy = Admission::entitled(Entitlement::new().allow(node(1)));
        assert_eq!(policy.decide(node(1)).await, AcceptDecision::Accept);
        assert_eq!(policy.decide(node(2)).await, AcceptDecision::Deny);
    }

    /// The allowlist is keyed on the canonical hex spelling `/identity`
    /// publishes, so an operator can copy a `node_id` out of that route
    /// (or out of a startup log) and paste it into `--control-plane-allow`.
    #[tokio::test]
    async fn allowlist_matches_the_identity_route_hex_spelling() {
        let n = node(7);
        let hex = n.to_string();
        assert_eq!(hex.len(), 64, "NodeId Display is 32-byte lowercase hex");
        let parsed: NodeId = hex.parse().expect("hex round-trips through FromStr");
        let policy = Admission::entitled(Entitlement::new().allow(parsed));
        assert_eq!(policy.decide(n).await, AcceptDecision::Accept);
    }

    // ── cheers-backed enrollment ─────────────────────────────────────────

    #[derive(Clone, Default)]
    struct MockCheers {
        /// `resource_id`s returned as live `node` rows.
        enrolled: Arc<tokio::sync::Mutex<Vec<String>>>,
        /// How many times `GET /ownership` was served — proves the cache.
        hits: Arc<AtomicUsize>,
        /// When set, the route 500s instead of answering.
        fail: Arc<AtomicUsize>,
    }

    #[derive(serde::Deserialize)]
    struct ListQuery {
        principal_id: String,
    }

    async fn mock_list(
        State(state): State<MockCheers>,
        Query(q): Query<ListQuery>,
    ) -> Result<Json<serde_json::Value>, StatusCode> {
        state.hits.fetch_add(1, Ordering::SeqCst);
        if state.fail.load(Ordering::SeqCst) > 0 {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let rows: Vec<serde_json::Value> = state
            .enrolled
            .lock()
            .await
            .iter()
            .map(|id| {
                serde_json::json!({
                    "id": format!("row-{id}"),
                    "principal_id": q.principal_id,
                    "resource_kind": "node",
                    "resource_id": id,
                    "relationship": "owns",
                    "granted_by": q.principal_id,
                    "on_behalf_of": serde_json::Value::Null,
                    "granted_at": 1_700_000_000_i64,
                    "revoked_at": serde_json::Value::Null,
                })
            })
            .collect();
        Ok(Json(serde_json::Value::Array(rows)))
    }

    async fn spawn_cheers() -> (Arc<CheersClient>, MockCheers) {
        let state = MockCheers::default();
        let app = Router::new()
            .route("/ownership", get(mock_list))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let client = CheersClient::new(
            CheersConfig {
                issuer_url: format!("http://{addr}"),
                principal_id: "yubaba-test".into(),
                kid: "yubaba-test-1".into(),
            },
            kp.secret.as_bytes(),
        )
        .unwrap();
        (Arc::new(client), state)
    }

    #[tokio::test]
    async fn cheers_enrolled_node_is_admitted_and_unenrolled_is_refused() {
        let (cheers, mock) = spawn_cheers().await;
        mock.enrolled.lock().await.push(node(1).to_string());

        let policy =
            Admission::entitled(Entitlement::new().with_cheers(cheers, DEFAULT_ENROLLMENT_TTL));

        assert_eq!(policy.decide(node(1)).await, AcceptDecision::Accept);
        assert_eq!(policy.decide(node(2)).await, AcceptDecision::Deny);
    }

    /// Eviction is a cheers-side revocation, so the acceptor must stop
    /// admitting once the row disappears — the whole point of consulting a
    /// ledger rather than baking a list in at startup.
    #[tokio::test]
    async fn revoking_the_enrollment_row_stops_admitting_after_the_ttl() {
        let (cheers, mock) = spawn_cheers().await;
        mock.enrolled.lock().await.push(node(1).to_string());

        // Zero TTL: every decision refetches, so the test isn't a sleep.
        let policy = Admission::entitled(Entitlement::new().with_cheers(cheers, Duration::ZERO));
        assert_eq!(policy.decide(node(1)).await, AcceptDecision::Accept);

        mock.enrolled.lock().await.clear();
        assert_eq!(policy.decide(node(1)).await, AcceptDecision::Deny);
    }

    #[tokio::test]
    async fn the_enrollment_set_is_cached_for_the_ttl() {
        let (cheers, mock) = spawn_cheers().await;
        mock.enrolled.lock().await.push(node(1).to_string());

        let policy =
            Admission::entitled(Entitlement::new().with_cheers(cheers, Duration::from_secs(300)));
        for _ in 0..5 {
            assert_eq!(policy.decide(node(1)).await, AcceptDecision::Accept);
        }
        assert_eq!(
            mock.hits.load(Ordering::SeqCst),
            1,
            "one snapshot fetch should serve every dial inside the TTL"
        );
    }

    /// A cheers outage must not lock the operator out of a fleet that was
    /// admitting fine a second ago (module doc §"Failure posture").
    #[tokio::test]
    async fn a_cheers_outage_serves_the_last_known_enrollment_set() {
        let (cheers, mock) = spawn_cheers().await;
        mock.enrolled.lock().await.push(node(1).to_string());

        let policy = Admission::entitled(Entitlement::new().with_cheers(cheers, Duration::ZERO));
        assert_eq!(policy.decide(node(1)).await, AcceptDecision::Accept);

        mock.fail.store(1, Ordering::SeqCst);
        assert_eq!(
            policy.decide(node(1)).await,
            AcceptDecision::Accept,
            "stale snapshot keeps a previously-enrolled node dialing"
        );
        assert_eq!(
            policy.decide(node(2)).await,
            AcceptDecision::Deny,
            "a stale snapshot is still a deny for anyone who was never in it"
        );
    }

    /// With no snapshot ever taken, a cheers outage fails closed — the
    /// static allowlist is the only way in, which is what makes
    /// `--control-plane-allow` the bootstrap path rather than a nicety.
    #[tokio::test]
    async fn a_cold_cheers_outage_fails_closed_but_the_allowlist_still_admits() {
        let (cheers, mock) = spawn_cheers().await;
        mock.fail.store(1, Ordering::SeqCst);
        mock.enrolled.lock().await.push(node(1).to_string());

        let policy = Admission::entitled(
            Entitlement::new()
                .allow(node(3))
                .with_cheers(cheers, DEFAULT_ENROLLMENT_TTL),
        );
        assert_eq!(policy.decide(node(1)).await, AcceptDecision::Deny);
        assert_eq!(policy.decide(node(3)).await, AcceptDecision::Accept);
    }
}
