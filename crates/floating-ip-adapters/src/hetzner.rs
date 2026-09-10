//! [`HetznerFloatingIp`] — Hetzner Cloud floating IPs (R594-F5).
//!
//! Hetzner floating IPs reassign via API within a **network zone** (+ same
//! project — a single envoy is already scoped to one Hetzner project by
//! convention, mirroring `cloud`'s `HetznerEnvoy`) — verified 2026-07,
//! W267 §Tier 1. [`hetzner_network_zone`] maps Hetzner's Cloud API location
//! codes onto the three network zones Hetzner documents (`eu-central`,
//! `us-east`, `us-west`); extend it as new locations open.
//!
//! A thin, purpose-built client scoped to exactly the floating-IP endpoints
//! this adapter needs (`GET /servers`, `GET /floating_ips/{id}`,
//! `POST /floating_ips/{id}/actions/assign`) rather than a reuse of `cloud`'s
//! `HetznerDriver` (which is VPS + S3 bucket lifecycle-scoped) or of the shared
//! `yah-hetzner` client. That separation is now structural rather than a
//! judgement call: R859-F3 moved this crate below `cloud`, and `yah-hetzner`
//! sits above it.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use floating_ip::{FloatingIpMachine, FloatingIpProvider, FloatingIpState, FloatingIpTarget};
use serde::Deserialize;

const HETZNER_BASE: &str = "https://api.hetzner.cloud/v1";

/// Hetzner Cloud floating-IP client. Bearer-token auth, same as `cloud`'s
/// `HetznerDriver` Cloud API calls.
#[derive(Clone)]
pub struct HetznerFloatingIp {
    http: reqwest::Client,
    token: String,
    base_url: String,
}

impl HetznerFloatingIp {
    /// Build against `api.hetzner.cloud`.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            token: token.into(),
            base_url: HETZNER_BASE.to_string(),
        }
    }

    /// Override the base URL — used by the in-process axum mocks below;
    /// production callers shouldn't need this.
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }
}

#[async_trait]
impl FloatingIpProvider for HetznerFloatingIp {
    fn id(&self) -> &'static str {
        "hetzner"
    }

    /// `GET /servers?name=<machine.name>` — same name→id lookup convention
    /// `cloud`'s `HetznerEnvoy` driver already relies on (cloud-init sets the
    /// Hetzner server's `name` to `MachineConfig.name`).
    async fn resolve_target(&self, machine: &FloatingIpMachine) -> Result<FloatingIpTarget> {
        let zone = hetzner_network_zone(machine.location()).with_context(|| {
            format!(
                "floating_ip: resolving target for machine {:?}",
                machine.name
            )
        })?;
        let resp = self
            .http
            .get(format!("{}/servers", self.base_url))
            .query(&[("name", machine.name.as_str())])
            .bearer_auth(&self.token)
            .send()
            .await
            .context("hetzner: GET /servers")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("hetzner GET /servers failed: {status} {body}");
        }
        let parsed: HetznerServersResponse = resp
            .json()
            .await
            .context("hetzner: decode GET /servers response")?;
        let server = parsed
            .servers
            .into_iter()
            .find(|s| s.name.as_deref() == Some(machine.name.as_str()))
            .with_context(|| format!("hetzner: no server named {:?}", machine.name))?;
        Ok(FloatingIpTarget {
            attach_id: server.id.to_string(),
            zone: zone.to_string(),
        })
    }

    /// `GET /floating_ips/{id}`.
    async fn current_assignment(&self, ip_id: &str) -> Result<FloatingIpState> {
        let resp = self
            .http
            .get(format!("{}/floating_ips/{}", self.base_url, ip_id))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("hetzner: GET /floating_ips/{id}")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("hetzner GET /floating_ips/{ip_id} failed: {status} {body}");
        }
        let parsed: HetznerFloatingIpResponse = resp
            .json()
            .await
            .context("hetzner: decode GET /floating_ips/{id} response")?;
        Ok(FloatingIpState {
            zone: parsed.floating_ip.home_location.network_zone,
            attached_to: parsed.floating_ip.server.map(|id| id.to_string()),
        })
    }

    /// `POST /floating_ips/{id}/actions/assign`.
    async fn reassign(&self, ip_id: &str, target: &FloatingIpTarget) -> Result<()> {
        let server_id: u64 = target.attach_id.parse().with_context(|| {
            format!(
                "hetzner: attach_id {:?} is not a numeric server id",
                target.attach_id
            )
        })?;
        let resp = self
            .http
            .post(format!(
                "{}/floating_ips/{}/actions/assign",
                self.base_url, ip_id
            ))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "server": server_id }))
            .send()
            .await
            .context("hetzner: POST /floating_ips/{id}/actions/assign")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("hetzner POST /floating_ips/{ip_id}/actions/assign failed: {status} {body}");
        }
        Ok(())
    }
}

/// Pure conversion: Hetzner Cloud API location code → Hetzner network
/// zone. Hetzner documents three network zones today (`eu-central`,
/// `us-east`, `us-west`); extend this table as Hetzner opens new
/// locations/zones.
fn hetzner_network_zone(location: &str) -> Result<&'static str> {
    match location {
        "hil" => Ok("us-west"),
        "ash" => Ok("us-east"),
        "fsn1" | "nbg1" | "hel1" => Ok("eu-central"),
        "sin" => Ok("ap-southeast"),
        "" => bail!("hetzner: machine has no `location` set — required to derive its network zone"),
        other => bail!("hetzner: unknown location {other:?}, cannot derive network zone"),
    }
}

#[derive(Deserialize)]
struct HetznerServersResponse {
    servers: Vec<HetznerServerLite>,
}

#[derive(Deserialize)]
struct HetznerServerLite {
    id: u64,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct HetznerFloatingIpResponse {
    floating_ip: HetznerFloatingIpBody,
}

#[derive(Deserialize)]
struct HetznerFloatingIpBody {
    home_location: HetznerHomeLocation,
    server: Option<u64>,
}

#[derive(Deserialize)]
struct HetznerHomeLocation {
    network_zone: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use floating_ip::on_ingress_owner_changed;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    fn hil_machine(name: &str) -> FloatingIpMachine {
        FloatingIpMachine {
            name: name.into(),
            provider: "hetzner".into(),
            location: Some("hil".into()),
            region: Some("us-west".into()),
            ingress_floating_ip: None,
        }
    }

    /// Spin up an in-process axum server standing in for Hetzner's Cloud
    /// API (same convention as `cloud`'s `reconciler/pond.rs` /
    /// `reconciler/static_asset.rs` tests: bind 127.0.0.1:0, serve
    /// canned/stateful JSON, point the client's `with_base_url` at it).
    /// `attached` is the floating IP's mutable current-server state so a test
    /// can drive two calls (flip, then re-apply) against one mock and observe
    /// the call count.
    async fn spawn_mock(
        network_zone: &'static str,
        initial_server: Option<u64>,
    ) -> (String, Arc<AtomicU32>, tokio::task::JoinHandle<()>) {
        let attached = Arc::new(Mutex::new(initial_server));
        let assign_calls = Arc::new(AtomicU32::new(0));

        let servers_route = {
            axum::routing::get(move || async move {
                axum::Json(serde_json::json!({ "servers": [ { "id": 555, "name": "edge-a" } ] }))
            })
        };

        let floating_ip_get = {
            let attached = attached.clone();
            axum::routing::get(move || {
                let attached = attached.clone();
                async move {
                    let server = *attached.lock().unwrap();
                    axum::Json(serde_json::json!({
                        "floating_ip": {
                            "home_location": { "network_zone": network_zone },
                            "server": server,
                        }
                    }))
                }
            })
        };

        let assign_route = {
            let attached = attached.clone();
            let calls = assign_calls.clone();
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let attached = attached.clone();
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let server = body.get("server").and_then(|v| v.as_u64());
                    *attached.lock().unwrap() = server;
                    axum::Json(serde_json::json!({ "action": { "status": "success" } }))
                }
            })
        };

        let app = axum::Router::new()
            .route("/servers", servers_route)
            .route("/floating_ips/{id}", floating_ip_get)
            .route("/floating_ips/{id}/actions/assign", assign_route);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        (format!("http://{addr}"), assign_calls, handle)
    }

    #[tokio::test]
    async fn ingress_owner_flip_drives_exactly_one_reassign_call() {
        // Floating IP currently attached to server 999 ("old" node);
        // resolving the new owner ("edge-a") always yields server 555 in
        // this mock — a real flip.
        let (base, calls, handle) = spawn_mock("us-west", Some(999)).await;
        let client = HetznerFloatingIp::new("test-token").with_base_url(base);
        let machine = hil_machine("edge-a");

        let outcome = on_ingress_owner_changed(&client, &machine, "42")
            .await
            .unwrap();
        assert!(outcome.reassigned, "owner flip must drive a reassign");
        assert_eq!(outcome.attached_to, "555");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn reapplying_the_same_owner_is_a_zero_call_noop() {
        // Floating IP already attached to server 555 == the resolved target.
        let (base, calls, handle) = spawn_mock("us-west", Some(555)).await;
        let client = HetznerFloatingIp::new("test-token").with_base_url(base);
        let machine = hil_machine("edge-a");

        let outcome = on_ingress_owner_changed(&client, &machine, "42")
            .await
            .unwrap();
        assert!(
            !outcome.reassigned,
            "re-applying the same owner must be a no-op"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "must not call the reassign endpoint"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn cross_zone_target_is_rejected_before_any_reassign_call() {
        // Floating IP is homed to eu-central; the target machine is us-west.
        let (base, calls, handle) = spawn_mock("eu-central", None).await;
        let client = HetznerFloatingIp::new("test-token").with_base_url(base);
        let machine = hil_machine("edge-a"); // us-west location

        let err = on_ingress_owner_changed(&client, &machine, "42")
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("zone"),
            "expected a zone-mismatch error, got: {msg}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "zone mismatch must never call reassign"
        );

        handle.abort();
    }

    #[test]
    fn hetzner_network_zone_maps_known_locations() {
        assert_eq!(hetzner_network_zone("hil").unwrap(), "us-west");
        assert_eq!(hetzner_network_zone("ash").unwrap(), "us-east");
        assert_eq!(hetzner_network_zone("fsn1").unwrap(), "eu-central");
        assert_eq!(hetzner_network_zone("nbg1").unwrap(), "eu-central");
        assert_eq!(hetzner_network_zone("hel1").unwrap(), "eu-central");
    }

    #[test]
    fn hetzner_network_zone_rejects_unknown_or_missing() {
        assert!(hetzner_network_zone("mars1").is_err());
        assert!(hetzner_network_zone("").is_err());
    }
}
