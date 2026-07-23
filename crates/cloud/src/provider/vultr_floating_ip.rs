//! [`VultrFloatingIp`] — `floating_ip.*` adapter for Vultr reserved IPs
//! (R594-F5).
//!
//! Vultr reserved IPs are **region-bound** (BGP-implemented inside
//! AS20473) — verified 2026-07, W267 §Tier 1. Unlike Hetzner (network
//! zone, a bucket of locations) or OVH (datacentre/country region, a
//! bucket of datacenters), Vultr's own region code *is* the mobility unit
//! — no further coarsening/mapping is needed, so this adapter uses
//! `MachineConfig.location()` (Vultr's region slug, e.g. `"ewr"`) directly
//! as the zone on both sides of the comparison in
//! [`crate::provider::reconcile_assignment`].
//!
//! `"vultr"` already has an auto-provision driver bucket in
//! [`crate::config::provider_has_machine_driver`], so a Vultr-provider
//! machine is expected to declare `location`.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use super::floating_ip::{reconcile_assignment, FloatingIpProvider, FloatingIpState, FloatingIpTarget};
use crate::config::MachineConfig;
use crate::envoy::floating_ip::{
    FloatingIpAssign, FloatingIpAssignInput, FloatingIpAssignOutput, FloatingIpStatus,
    FloatingIpStatusInput, FloatingIpStatusOutput,
};
use crate::envoy::{AdapterFlavor, EnvoyAdapter, InternalVerb, Tier};

const VULTR_BASE: &str = "https://api.vultr.com/v2";

/// Vultr reserved-IP client. Bearer-token auth (Vultr's personal-access-token
/// scheme).
#[derive(Clone)]
pub struct VultrFloatingIp {
    http: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl VultrFloatingIp {
    /// Build against `api.vultr.com`.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key: api_key.into(),
            base_url: VULTR_BASE.to_string(),
        }
    }

    /// Override the base URL — used by the in-process axum mocks below.
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Typed handler for `floating_ip.assign`.
    pub async fn floating_ip_assign(
        &self,
        input: FloatingIpAssignInput,
    ) -> Result<FloatingIpAssignOutput> {
        let target = FloatingIpTarget {
            attach_id: input.attach_id,
            zone: input.zone,
        };
        let outcome = reconcile_assignment(self, &input.ip_id, &target).await?;
        Ok(FloatingIpAssignOutput {
            reassigned: outcome.reassigned,
            attached_to: outcome.attached_to,
        })
    }

    /// Typed handler for `floating_ip.status`.
    pub async fn floating_ip_status(
        &self,
        input: FloatingIpStatusInput,
    ) -> Result<FloatingIpStatusOutput> {
        let state = self.current_assignment(&input.ip_id).await?;
        Ok(FloatingIpStatusOutput {
            zone: state.zone,
            attached_to: state.attached_to,
        })
    }
}

#[async_trait]
impl FloatingIpProvider for VultrFloatingIp {
    fn id(&self) -> &'static str {
        "vultr"
    }

    /// `GET /v2/instances?label=<machine.name>` — Vultr instances are
    /// looked up by their `label`, the same name-is-the-key convention
    /// as Hetzner's `GET /servers?name=`.
    async fn resolve_target(&self, machine: &MachineConfig) -> Result<FloatingIpTarget> {
        let zone = machine.location.clone().filter(|s| !s.is_empty()).with_context(|| {
            format!(
                "vultr: machine {:?} has no `location` set — required as its region (mobility zone)",
                machine.name
            )
        })?;
        let resp = self
            .http
            .get(format!("{}/instances", self.base_url))
            .query(&[("label", machine.name.as_str())])
            .bearer_auth(&self.api_key)
            .send()
            .await
            .context("vultr: GET /instances")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("vultr GET /instances failed: {status} {body}");
        }
        let parsed: VultrInstancesResponse = resp
            .json()
            .await
            .context("vultr: decode GET /instances response")?;
        let instance = parsed
            .instances
            .into_iter()
            .find(|i| i.label == machine.name)
            .with_context(|| format!("vultr: no instance labeled {:?}", machine.name))?;
        if instance.region != zone {
            bail!(
                "vultr: instance {:?} lives in region {:?}, but machine {:?} declares location {:?} — refusing to trust a mismatched declaration",
                instance.id,
                instance.region,
                machine.name,
                zone
            );
        }
        Ok(FloatingIpTarget {
            attach_id: instance.id,
            zone,
        })
    }

    /// `GET /v2/reserved-ips/{id}`.
    async fn current_assignment(&self, ip_id: &str) -> Result<FloatingIpState> {
        let resp = self
            .http
            .get(format!("{}/reserved-ips/{}", self.base_url, ip_id))
            .bearer_auth(&self.api_key)
            .send()
            .await
            .context("vultr: GET /reserved-ips/{id}")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("vultr GET /reserved-ips/{ip_id} failed: {status} {body}");
        }
        let parsed: VultrReservedIpResponse = resp
            .json()
            .await
            .context("vultr: decode GET /reserved-ips/{id} response")?;
        Ok(FloatingIpState {
            zone: parsed.reserved_ip.region,
            attached_to: parsed.reserved_ip.instance_id.filter(|s| !s.is_empty()),
        })
    }

    /// `POST /v2/reserved-ips/{id}/attach`.
    async fn reassign(&self, ip_id: &str, target: &FloatingIpTarget) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/reserved-ips/{}/attach", self.base_url, ip_id))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({ "instance_id": target.attach_id }))
            .send()
            .await
            .context("vultr: POST /reserved-ips/{id}/attach")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("vultr POST /reserved-ips/{ip_id}/attach failed: {status} {body}");
        }
        Ok(())
    }
}

#[async_trait]
impl EnvoyAdapter for VultrFloatingIp {
    fn id(&self) -> &str {
        "vultr"
    }
    fn tier(&self) -> Tier {
        Tier::S
    }
    fn flavor(&self) -> AdapterFlavor {
        AdapterFlavor::Native
    }
    fn supported_verb_ids(&self) -> Vec<&'static str> {
        vec![FloatingIpAssign::ID, FloatingIpStatus::ID]
    }
    async fn dispatch(&self, verb_id: &str, input: Value) -> Result<Value> {
        match verb_id {
            id if id == FloatingIpAssign::ID => {
                let args: FloatingIpAssignInput =
                    serde_json::from_value(input).with_context(|| format!("{id}: decode input"))?;
                let out = self.floating_ip_assign(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            id if id == FloatingIpStatus::ID => {
                let args: FloatingIpStatusInput =
                    serde_json::from_value(input).with_context(|| format!("{id}: decode input"))?;
                let out = self.floating_ip_status(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            other => bail!("vultr floating-ip envoy does not support verb {other:?}"),
        }
    }
}

#[derive(Deserialize)]
struct VultrInstancesResponse {
    instances: Vec<VultrInstanceLite>,
}

#[derive(Deserialize)]
struct VultrInstanceLite {
    id: String,
    label: String,
    region: String,
}

#[derive(Deserialize)]
struct VultrReservedIpResponse {
    reserved_ip: VultrReservedIpBody,
}

#[derive(Deserialize)]
struct VultrReservedIpBody {
    region: String,
    #[serde(default)]
    instance_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::floating_ip::on_ingress_owner_changed;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    fn ewr_machine(name: &str) -> MachineConfig {
        MachineConfig {
            name: name.into(),
            provider: "vultr".into(),
            location: Some("ewr".into()),
            server_type: Some("vc2-1c-1gb".into()),
            hosts_mirrors: vec![],
            mesh_tags: vec![],
            region: None,
            zone: None,
            arch: None,
            bucket: None,
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
            allocatable: None,
            taints: vec![],
        }
    }

    /// Spin up an in-process axum server standing in for Vultr's API. See
    /// `hetzner_floating_ip.rs`'s `spawn_mock` for the pattern this
    /// mirrors.
    async fn spawn_mock(
        instance_region: &'static str,
        reserved_ip_region: &'static str,
        initial_instance_id: Option<String>,
    ) -> (String, Arc<AtomicU32>, tokio::task::JoinHandle<()>) {
        let attached: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(initial_instance_id));
        let attach_calls = Arc::new(AtomicU32::new(0));

        let instances_route = axum::routing::get(move || async move {
            axum::Json(serde_json::json!({
                "instances": [ { "id": "inst-789", "label": "edge-c", "region": instance_region } ]
            }))
        });

        let reserved_ip_get = {
            let attached = attached.clone();
            axum::routing::get(move || {
                let attached = attached.clone();
                async move {
                    let instance_id = attached.lock().unwrap().clone();
                    axum::Json(serde_json::json!({
                        "reserved_ip": {
                            "region": reserved_ip_region,
                            "instance_id": instance_id,
                        }
                    }))
                }
            })
        };

        let attach_route = {
            let attached = attached.clone();
            let calls = attach_calls.clone();
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let attached = attached.clone();
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let instance_id = body
                        .get("instance_id")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    *attached.lock().unwrap() = instance_id;
                    axum::Json(serde_json::json!({}))
                }
            })
        };

        let app = axum::Router::new()
            .route("/instances", instances_route)
            .route("/reserved-ips/{id}", reserved_ip_get)
            .route("/reserved-ips/{id}/attach", attach_route);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        (format!("http://{addr}"), attach_calls, handle)
    }

    #[tokio::test]
    async fn ingress_owner_flip_drives_exactly_one_reassign_call() {
        let (base, calls, handle) =
            spawn_mock("ewr", "ewr", Some("old-instance".into())).await;
        let client = VultrFloatingIp::new("test-api-key").with_base_url(base);
        let machine = ewr_machine("edge-c");

        let outcome = on_ingress_owner_changed(&client, &machine, "res-ip-1")
            .await
            .unwrap();
        assert!(outcome.reassigned, "owner flip must drive a reassign");
        assert_eq!(outcome.attached_to, "inst-789");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn reapplying_the_same_owner_is_a_zero_call_noop() {
        let (base, calls, handle) =
            spawn_mock("ewr", "ewr", Some("inst-789".into())).await;
        let client = VultrFloatingIp::new("test-api-key").with_base_url(base);
        let machine = ewr_machine("edge-c");

        let outcome = on_ingress_owner_changed(&client, &machine, "res-ip-1")
            .await
            .unwrap();
        assert!(!outcome.reassigned, "re-applying the same owner must be a no-op");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "must not call attach");

        handle.abort();
    }

    #[tokio::test]
    async fn cross_region_target_is_rejected_before_any_reassign_call() {
        // Reserved IP is homed to lax; target instance lives in ewr.
        let (base, calls, handle) = spawn_mock("ewr", "lax", None).await;
        let client = VultrFloatingIp::new("test-api-key").with_base_url(base);
        let machine = ewr_machine("edge-c");

        let err = on_ingress_owner_changed(&client, &machine, "res-ip-1")
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("zone"), "expected a zone-mismatch error, got: {msg}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "region mismatch must never call attach");

        handle.abort();
    }

    #[tokio::test]
    async fn instance_region_mismatching_declared_location_is_rejected() {
        // The Vultr instance labeled "edge-c" actually lives in lax, but
        // the machine TOML declares location=ewr — a data-consistency
        // error the adapter must refuse to paper over.
        let (base, calls, handle) = spawn_mock("lax", "lax", None).await;
        let client = VultrFloatingIp::new("test-api-key").with_base_url(base);
        let machine = ewr_machine("edge-c"); // declares ewr

        let err = on_ingress_owner_changed(&client, &machine, "res-ip-1")
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("lax") && msg.contains("ewr"), "got: {msg}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        handle.abort();
    }
}
