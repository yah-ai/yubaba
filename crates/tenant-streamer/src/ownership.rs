//! Where the fencing token comes from, and how a lease is kept alive.
//!
//! ## Why this is a trait and not a function
//!
//! The streamer is a *separate process* from yubaba (W253 tenet 1: the control
//! plane and the data plane are separated), so in production it asks over
//! HTTP — [`HttpOwnership`]. But R732-T5's chaos test has to drive the tail
//! loop against two hand-driven raft state machines with no server anywhere,
//! and a test that had to stand up an HTTP listener to check a fencing
//! property would be testing the listener. One trait, two implementations, and
//! the loop cannot tell them apart.
//!
//! ## Why pull, and why staleness is not a bug here
//!
//! The token is *pulled* every tick from the node-local yubaba, and read from
//! that node's LOCAL applied state — no leader round-trip, no linearizable
//! read. That read can be stale: this node may not have applied a transfer
//! yet, or may be partitioned from the leader and still believe it owns
//! everything.
//!
//! That is safe by construction rather than by luck, and it is the whole point
//! of W245. Enforcement is at the R2 sink, not here:
//!
//! - A **stale-low** token (we think we still own it; someone else has taken
//!   it) is rejected at the sink as [`StreamOutcome::Fenced`]. It costs a
//!   wasted round trip, never a second writer.
//! - A **stale-high** token cannot exist. Only *committed* entries reach a
//!   state machine, so no node can read an epoch that the cluster has not
//!   already agreed on.
//!
//! A design that needed this read to be fresh would be a design where a
//! partition corrupts a tenant.
//!
//! [`StreamOutcome::Fenced`]: turso_backup::stream::StreamOutcome::Fenced

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use workload_spec::TenantId;

/// yubaba's `TenantOutcome`, as it comes back over `POST /raft/write`.
///
/// Every request in the tenant family — `ClaimTenant`, `TransferTenant`,
/// `RenewTenantLease` — answers with this one shape, so the decode lives here
/// once ([`parse_tenant_outcome`]) rather than at each caller.
///
/// [`LeaseRenewal`] stays a separate type over the same wire bytes on purpose:
/// its contract is *narrower* (a renewal never advances the epoch, which is
/// what makes heartbeating safe), and a claim's contract is the opposite —
/// a grant **always** advances it. Collapsing them would put one doc comment
/// on two invariants, only one of which is true at any call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantOutcome {
    /// The write landed; `epoch` is the token the caller now holds.
    Granted { epoch: u64 },
    /// Refused, with who really owns the tenant and at what epoch.
    Fenced {
        current_epoch: u64,
        current_owner: Option<u64>,
    },
}

/// What a lease renewal did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRenewal {
    /// The lease was extended; `epoch` is unchanged (renewal never advances
    /// it — that is what makes heartbeating safe, per R732-F1).
    Renewed { epoch: u64 },
    /// Refused: this node is not the owner at the epoch it renewed under.
    /// The streamer must stop renewing and drop the tenant — a fenced node
    /// that could still keep a lease alive would look healthy to every
    /// readiness gate while being unable to write a byte.
    Fenced { current_epoch: u64, current_owner: Option<u64> },
}

/// The control-plane facts the tail loop needs about one tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ownership {
    /// The epoch this node may stream under, or `None` if it may not stream at
    /// all (different owner, expired lease, or no record).
    pub fencing_token: Option<u64>,
    /// Unix-seconds lease deadline on the record, whoever holds it. Drives
    /// *when* to renew, never *whether* it is safe to write.
    pub lease_expires: u64,
    /// The serving node's clock, so lease arithmetic uses one clock rather
    /// than differencing two.
    pub now: u64,
}

impl Ownership {
    /// Seconds of lease left at the serving node's `now`, saturating at zero.
    pub fn lease_remaining(&self) -> u64 {
        self.lease_expires.saturating_sub(self.now)
    }
}

/// The control plane, as the tail loop sees it.
#[async_trait]
pub trait OwnershipSource: Send + Sync {
    /// Read this node's current standing on `tenant`.
    async fn ownership(&self, tenant: &TenantId) -> Result<Ownership>;

    /// Extend this node's lease, under the token it believes it holds.
    async fn renew_lease(&self, tenant: &TenantId, epoch: u64, lease_secs: u64)
        -> Result<LeaseRenewal>;
}

/// Production transport: the node-local yubaba's HTTP surface.
///
/// Two endpoints, and deliberately no new ones. Reads go to `GET
/// /tenants/{id}?node=<n>` (added by R732-T4). Writes go through the *generic*
/// `POST /raft/write` that already carries every `YubabaRequest`, so renewing a
/// lease needs no bespoke route.
pub struct HttpOwnership {
    client: reqwest::Client,
    base_url: String,
    node_id: u64,
}

impl HttpOwnership {
    pub fn new(base_url: impl Into<String>, node_id: u64) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            node_id,
        }
    }

    /// The node id this client writes as.
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Take ownership of `tenant`, advancing its fencing epoch by exactly one.
    ///
    /// This is **not** part of [`OwnershipSource`], and deliberately so: the
    /// tail loop must never claim (a claim as a heartbeat fences your own
    /// streamer every beat — `raft/mod.rs`'s `ClaimTenant` docs). The one
    /// caller is R869's rebuild, which lifts a rebuilt cluster's epoch back
    /// over the floor its dead predecessor left in the R2 sidecar; see
    /// [`crate::rebuild`].
    pub async fn claim_tenant(&self, tenant: &TenantId, lease_secs: u64) -> Result<TenantOutcome> {
        // Hand-built for the same reason `renew_lease` is: no dependency on the
        // yubaba server crate. Pinned on the other side by
        // `raft::tests::the_recovery_claim_is_the_wire_shape_already_deployed`,
        // which asserts this exact JSON round-trips with no added key — so a
        // node on an older binary applies the identical entry and the recovery
        // cannot diverge a mixed cluster.
        let body = serde_json::json!({
            "request": {
                "ClaimTenant": {
                    "tenant": tenant.0,
                    "node": self.node_id,
                    "lease_secs": lease_secs,
                    "now": unix_secs(),
                }
            }
        });
        parse_tenant_outcome(&self.raft_write(body).await?)
    }

    /// POST one `YubabaRequest` through the generic write route and hand back
    /// the decoded response body.
    async fn raft_write(&self, body: serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}/raft/write", self.base_url);
        self.client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?
            .error_for_status()
            .with_context(|| format!("POST {url} returned an error status"))?
            .json()
            .await
            .with_context(|| format!("decoding the write outcome from {url}"))
    }
}

/// `GET /tenants/{id}` response. Kept structurally minimal so the two sides
/// can drift only in ways serde catches.
#[derive(Debug, Deserialize)]
struct TenantView {
    fencing_token: Option<u64>,
    #[serde(default)]
    lease_expires: u64,
    now: u64,
}

#[async_trait]
impl OwnershipSource for HttpOwnership {
    async fn ownership(&self, tenant: &TenantId) -> Result<Ownership> {
        let url = format!("{}/tenants/{}?node={}", self.base_url, tenant.0, self.node_id);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        // 404 is a legitimate answer, not a failure: no record means nobody
        // owns this tenant, which is precisely "you may not write".
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Ownership { fencing_token: None, lease_expires: 0, now: unix_secs() });
        }
        let resp = resp
            .error_for_status()
            .with_context(|| format!("GET {url} returned an error status"))?;
        let view: TenantView = resp
            .json()
            .await
            .with_context(|| format!("decoding the ownership record from {url}"))?;
        Ok(Ownership {
            fencing_token: view.fencing_token,
            lease_expires: view.lease_expires,
            now: view.now,
        })
    }

    async fn renew_lease(
        &self,
        tenant: &TenantId,
        epoch: u64,
        lease_secs: u64,
    ) -> Result<LeaseRenewal> {
        // Hand-built rather than typed: this crate does NOT depend on the
        // yubaba server crate — that dependency is exactly the control/data
        // coupling W253 tenet 1 forbids, and taking it would drag axum and
        // openraft into a data-plane process. The shape is pinned instead by
        // a contract test on yubaba's side
        // (`the_streamer_lease_renewal_body_deserializes`), which fails if
        // anyone renames a field on `YubabaRequest::RenewTenantLease`.
        let body = serde_json::json!({
            "request": {
                "RenewTenantLease": {
                    "tenant": tenant.0,
                    "node": self.node_id,
                    "epoch": epoch,
                    "lease_secs": lease_secs,
                    "now": unix_secs(),
                }
            }
        });
        parse_renewal(&self.raft_write(body).await?)
    }
}

/// Decode a `YubabaResponse::Tenant(TenantOutcome)` body. Split out and pure so
/// the wire shape is testable without a server.
pub fn parse_tenant_outcome(value: &serde_json::Value) -> Result<TenantOutcome> {
    let tenant = value
        .get("Tenant")
        .with_context(|| format!("expected a Tenant outcome, got {value}"))?;
    if let Some(granted) = tenant.get("Granted") {
        let epoch = granted
            .get("epoch")
            .and_then(|e| e.as_u64())
            .context("Granted without an epoch")?;
        return Ok(TenantOutcome::Granted { epoch });
    }
    if let Some(fenced) = tenant.get("Fenced") {
        return Ok(TenantOutcome::Fenced {
            current_epoch: fenced.get("current_epoch").and_then(|e| e.as_u64()).unwrap_or(0),
            current_owner: fenced.get("current_owner").and_then(|o| o.as_u64()),
        });
    }
    bail!("unrecognised tenant outcome {tenant}")
}

/// The renewal reading of [`parse_tenant_outcome`] — same bytes, narrower
/// contract (see [`TenantOutcome`]).
fn parse_renewal(value: &serde_json::Value) -> Result<LeaseRenewal> {
    Ok(match parse_tenant_outcome(value)? {
        TenantOutcome::Granted { epoch } => LeaseRenewal::Renewed { epoch },
        TenantOutcome::Fenced {
            current_epoch,
            current_owner,
        } => LeaseRenewal::Fenced {
            current_epoch,
            current_owner,
        },
    })
}

pub(crate) fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact JSON yubaba's `raft_write` replies with for a granted
    /// renewal. If openraft's response envelope or the enum tagging changes,
    /// this is what notices.
    #[test]
    fn a_granted_renewal_decodes_to_its_epoch() {
        let v = serde_json::json!({ "Tenant": { "Granted": { "epoch": 7 } } });
        assert_eq!(parse_renewal(&v).unwrap(), LeaseRenewal::Renewed { epoch: 7 });
    }

    /// The case the loop acts on: a refused renewal carries who really owns
    /// the tenant, and the streamer must stop.
    #[test]
    fn a_refused_renewal_decodes_to_fenced_with_the_real_owner() {
        let v = serde_json::json!({
            "Tenant": { "Fenced": { "current_epoch": 9, "current_owner": 3 } }
        });
        assert_eq!(
            parse_renewal(&v).unwrap(),
            LeaseRenewal::Fenced { current_epoch: 9, current_owner: Some(3) }
        );

        // `current_owner` is `Option<YubabaNodeId>` — a tenant with no record
        // at all reports null, and that must not be read as node 0.
        let v = serde_json::json!({
            "Tenant": { "Fenced": { "current_epoch": 0, "current_owner": null } }
        });
        assert_eq!(
            parse_renewal(&v).unwrap(),
            LeaseRenewal::Fenced { current_epoch: 0, current_owner: None }
        );
    }

    /// An unrecognised body is an error, never a silent "renewed". Guessing
    /// here would keep a fenced node believing it holds a live lease.
    #[test]
    fn an_unrecognised_outcome_is_an_error_not_an_optimistic_renewal() {
        assert!(parse_renewal(&serde_json::json!({ "Ok": null })).is_err());
        assert!(parse_renewal(&serde_json::json!({ "Tenant": { "Something": {} } })).is_err());
    }

    #[test]
    fn lease_remaining_saturates_rather_than_wrapping() {
        let expired = Ownership { fencing_token: Some(1), lease_expires: 10, now: 99 };
        assert_eq!(expired.lease_remaining(), 0);
        let live = Ownership { fencing_token: Some(1), lease_expires: 100, now: 40 };
        assert_eq!(live.lease_remaining(), 60);
    }
}
