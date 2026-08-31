//! R782 (W246/R737): pushes each tick's `RpoStatus::watermark_age` back to
//! yubaba's leader-resident, non-raft `RpoWatermarkRegistry`, so the
//! placement scheduler's streamer-RPO gate (`lease_detector::judge_readiness`)
//! has a live evidence source instead of the permanent `None` it read before
//! this ticket.
//!
//! ## Why push, and why this process discovers the leader itself
//!
//! Mirrors `yubaba::lease_renewal`'s node-lease push exactly: a best-effort
//! HTTP nudge into the leader's local registry, never a raft write (the same
//! reasons `lease_detector`'s module doc gives for renewals apply here, more so
//! — a per-tenant-per-tick value would flood the log far faster than a per-node
//! liveness bit). The one structural difference is *why* leader discovery is
//! self-contained here rather than reading `raft.metrics()`: this process has
//! no raft of its own (`ownership`'s module doc — W253 tenet 1, control/data
//! separation), so it discovers the current leader the same way any external
//! client would, via `GET /raft/status` on its own node-local yubaba.
//!
//! ## Why best-effort, never propagated
//!
//! A report that lands late or not at all costs one stale tick of RPO gate
//! evidence — yubaba's `lease_detector::RpoWatermarkRegistry::watermark_age`
//! keeps extrapolating the last-known value forward, so the *worst* case is
//! the gate reading slightly staler than reality, never fresher. That is
//! exactly the fail-closed direction `judge_readiness` already wants, so an
//! error here is logged and dropped rather than turned into a tail-loop
//! failure — the same posture `lease_renewal::run` takes for a refused or
//! failed renewal POST. (This crate takes no dependency on that type — see
//! the module doc above for why.)

use std::time::Duration;

use tracing::{debug, warn};
use workload_spec::TenantId;

/// Discovers, and pushes to, the current raft leader's `POST
/// /mesh/rpo-report`, starting from this node's own node-local yubaba URL.
pub struct RpoReporter {
    client: reqwest::Client,
    base_url: String,
    node_id: u64,
}

#[derive(Debug, serde::Deserialize)]
struct RaftStatusView {
    current_leader: Option<u64>,
    #[serde(default)]
    members: std::collections::BTreeMap<String, MemberView>,
}

#[derive(Debug, serde::Deserialize)]
struct MemberView {
    addr: String,
}

impl RpoReporter {
    pub fn new(base_url: impl Into<String>, node_id: u64) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            node_id,
        }
    }

    /// Push this tenant's current watermark age toward the leader. Never
    /// propagates a failure — see the module doc.
    pub async fn report(&self, tenant: &TenantId, watermark_age: Option<Duration>) {
        let leader_addr = match self.leader_addr().await {
            Ok(Some(addr)) => addr,
            Ok(None) => {
                debug!(node_id = self.node_id, "rpo report: no leader known yet, skipping");
                return;
            }
            Err(e) => {
                warn!(node_id = self.node_id, "rpo report: could not discover the leader: {e:#}");
                return;
            }
        };
        let url = format!("http://{leader_addr}/mesh/rpo-report");
        let body = serde_json::json!({
            "node_id": self.node_id,
            "tenant": tenant.0,
            "watermark_age_secs": watermark_age.map(|d| d.as_secs()),
        });
        match self.client.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!(node_id = self.node_id, tenant = tenant.0.as_str(), %url, "rpo report: pushed");
            }
            Ok(resp) => warn!(
                node_id = self.node_id,
                tenant = tenant.0.as_str(),
                %url,
                status = %resp.status(),
                "rpo report: leader refused the report — will retry next tick"
            ),
            Err(e) => warn!(
                node_id = self.node_id,
                tenant = tenant.0.as_str(),
                %url,
                "rpo report: POST failed, will retry next tick: {e}"
            ),
        }
    }

    /// `current_leader`'s advertised address, read off this node's own local
    /// `GET /raft/status` — a local, potentially-stale read, exactly like
    /// `ownership`'s `GET /tenants/{id}` (see that module's doc for why
    /// staleness here is safe: a report landing on the wrong (non-leader) node
    /// is simply never read, per `mesh_rpo_report`'s "harmless on a follower"
    /// posture on the yubaba side).
    async fn leader_addr(&self) -> anyhow::Result<Option<String>> {
        use anyhow::Context;
        let url = format!("{}/raft/status", self.base_url);
        let view: RaftStatusView = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url} returned an error status"))?
            .json()
            .await
            .with_context(|| format!("decoding raft status from {url}"))?;
        Ok(view
            .current_leader
            .and_then(|id| view.members.get(&id.to_string()).map(|m| m.addr.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact JSON `GET /raft/status` replies with (lib.rs's `raft_status`
    /// handler) — if the field names or the member-map shape drift, this is
    /// what notices before a live report silently starts going nowhere.
    #[test]
    fn leader_addr_resolves_from_a_raft_status_body() {
        let body = serde_json::json!({
            "node_id": 1,
            "current_leader": 2,
            "members": {
                "1": { "addr": "100.64.0.1:7443", "region": null },
                "2": { "addr": "100.64.0.2:7443", "region": null },
            },
        });
        let view: RaftStatusView = serde_json::from_value(body).unwrap();
        let addr = view.current_leader.and_then(|id| view.members.get(&id.to_string()).map(|m| m.addr.clone()));
        assert_eq!(addr.as_deref(), Some("100.64.0.2:7443"));
    }

    /// No leader elected yet — `current_leader` is `null`, and there is
    /// nothing to resolve an address against.
    #[test]
    fn no_current_leader_resolves_to_no_address() {
        let body = serde_json::json!({ "node_id": 1, "current_leader": null, "members": {} });
        let view: RaftStatusView = serde_json::from_value(body).unwrap();
        assert!(view.current_leader.is_none());
    }
}
