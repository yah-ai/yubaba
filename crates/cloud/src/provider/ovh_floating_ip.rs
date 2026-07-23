//! [`OvhFloatingIp`] — `floating_ip.*` adapter for OVH Additional IPs
//! (R594-F5).
//!
//! OVH Additional IPs move via API within a **datacentre/country region**
//! (the eu-west GRA/RBX/SBG trio has cross-DC flexibility *within* that
//! region) — verified 2026-07, W267 §Tier 1. [`ovh_datacenter_region`] maps
//! OVH datacenter codes onto the coarse region buckets W267 names; extend
//! it as more OVH datacenters are onboarded.
//!
//! **No OVH driver exists anywhere in this codebase today** (OVH boxes in
//! `.yah/infra/machines/` are brought up over SSH as `provider = "static"`
//! — see `us-east-001.toml` / `us-west-001.toml`). This client is new,
//! purpose-built for exactly the floating-IP endpoints this verb family
//! needs, modeled on OVH's publicly documented `dedicated/server` +
//! `ip` API families (`ipMove` / IP routing lookup). **Auth is a
//! placeholder**: OVH's real API uses an application key + secret +
//! consumer key with a timestamped HMAC signature, not a bearer token —
//! modeling that signing scheme is out of scope for this ticket (code +
//! mock tests only, no live calls per the ticket's hard constraints). The
//! `consumer_key` field below is sent as a raw header so the *shape* of the
//! adapter is right; swap in real OVH request-signing before any live use.
//! Live-verification against OVH's actual API is explicitly deferred to
//! the operator (same as every other cloud envoy adapter in this crate).

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

const OVH_BASE: &str = "https://api.ovh.com/1.0";

/// OVH Additional-IP client. See module docs re: the auth placeholder.
#[derive(Clone)]
pub struct OvhFloatingIp {
    http: reqwest::Client,
    consumer_key: String,
    base_url: String,
}

impl OvhFloatingIp {
    /// Build against `api.ovh.com`.
    pub fn new(consumer_key: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            consumer_key: consumer_key.into(),
            base_url: OVH_BASE.to_string(),
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
impl FloatingIpProvider for OvhFloatingIp {
    fn id(&self) -> &'static str {
        "ovh"
    }

    /// Assumes the OVH `serviceName` equals `machine.name` (the same
    /// name-is-the-key convention the Hetzner adapter uses for its
    /// `GET /servers?name=` lookup) — `GET /dedicated/server/{serviceName}`
    /// confirms the box exists at OVH before anything is attempted.
    async fn resolve_target(&self, machine: &MachineConfig) -> Result<FloatingIpTarget> {
        let zone = ovh_zone_for(machine)?;
        let resp = self
            .http
            .get(format!(
                "{}/dedicated/server/{}",
                self.base_url, machine.name
            ))
            .header("X-Ovh-Consumer", &self.consumer_key)
            .send()
            .await
            .context("ovh: GET /dedicated/server/{serviceName}")?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            bail!("ovh: no dedicated server named {:?}", machine.name);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "ovh GET /dedicated/server/{} failed: {status} {body}",
                machine.name
            );
        }
        Ok(FloatingIpTarget {
            attach_id: machine.name.clone(),
            zone,
        })
    }

    /// `GET /ip/{ip}` — modeled on OVH's IP-service + routing info; see
    /// module docs re: exact endpoint shape needing live verification.
    async fn current_assignment(&self, ip_id: &str) -> Result<FloatingIpState> {
        let resp = self
            .http
            .get(format!("{}/ip/{}", self.base_url, ip_id))
            .header("X-Ovh-Consumer", &self.consumer_key)
            .send()
            .await
            .context("ovh: GET /ip/{ip}")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("ovh GET /ip/{ip_id} failed: {status} {body}");
        }
        let parsed: OvhIpInfo = resp
            .json()
            .await
            .context("ovh: decode GET /ip/{ip} response")?;
        Ok(FloatingIpState {
            zone: ovh_datacenter_region(&parsed.datacenter)?.to_string(),
            attached_to: parsed.routed_to.filter(|s| !s.is_empty()),
        })
    }

    /// `POST /dedicated/server/{serviceName}/ipMove` — moves `ip_id` onto
    /// the dedicated server named `target.attach_id`.
    async fn reassign(&self, ip_id: &str, target: &FloatingIpTarget) -> Result<()> {
        let resp = self
            .http
            .post(format!(
                "{}/dedicated/server/{}/ipMove",
                self.base_url, target.attach_id
            ))
            .header("X-Ovh-Consumer", &self.consumer_key)
            .json(&serde_json::json!({ "ip": ip_id }))
            .send()
            .await
            .context("ovh: POST /dedicated/server/{serviceName}/ipMove")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "ovh POST /dedicated/server/{}/ipMove failed: {status} {body}",
                target.attach_id
            );
        }
        Ok(())
    }
}

#[async_trait]
impl EnvoyAdapter for OvhFloatingIp {
    fn id(&self) -> &str {
        "ovh"
    }
    fn tier(&self) -> Tier {
        Tier::A
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
            other => bail!("ovh floating-ip envoy does not support verb {other:?}"),
        }
    }
}

/// Pure conversion: OVH datacenter code → coarse mobility region. The
/// eu-west trio (GRA/RBX/SBG) is called out explicitly in W267 as having
/// cross-DC flexibility within the region; extend as more OVH DCs are
/// onboarded.
fn ovh_datacenter_region(dc: &str) -> Result<&'static str> {
    match dc.to_ascii_lowercase().as_str() {
        "gra" | "rbx" | "sbg" => Ok("eu-west"),
        "bhs" => Ok("ca-east"),
        "waw" => Ok("eu-central-pl"),
        "syd" => Ok("au-east"),
        "sgp" => Ok("ap-southeast"),
        other => bail!("ovh: unknown datacenter {other:?}, cannot derive mobility region"),
    }
}

/// `MachineConfig.location` is provisioning-only and OVH has no
/// auto-provision driver in this codebase (`provider_has_machine_driver`
/// doesn't list `"ovh"`), so today's OVH machines declare `region` (the
/// coarser, provider-neutral geo label) but not `location`. Prefer the
/// precise datacenter-derived region when `location` happens to carry an
/// OVH DC code (future onboarding may start setting it informationally);
/// fall back to the already-coarse `region` field otherwise — our region
/// labels (`"us-east"`, `"eu-west"`, …) are deliberately at the same
/// granularity OVH's own zone concept needs.
fn ovh_zone_for(machine: &MachineConfig) -> Result<String> {
    if let Some(dc) = machine.location.as_deref().filter(|s| !s.is_empty()) {
        return Ok(ovh_datacenter_region(dc)?.to_string());
    }
    machine.region.clone().with_context(|| {
        format!(
            "ovh: machine {:?} has neither `location` nor `region` set — cannot derive its mobility zone",
            machine.name
        )
    })
}

#[derive(Deserialize)]
struct OvhIpInfo {
    datacenter: String,
    #[serde(rename = "routedTo", default)]
    routed_to: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::floating_ip::on_ingress_owner_changed;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    fn gra_machine(name: &str) -> MachineConfig {
        MachineConfig {
            name: name.into(),
            provider: "ovh".into(),
            location: None,
            server_type: None,
            hosts_mirrors: vec![],
            mesh_tags: vec![],
            region: Some("eu-west".into()),
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

    /// Spin up an in-process axum server standing in for OVH's API. See
    /// `hetzner_floating_ip.rs`'s `spawn_mock` for the pattern this
    /// mirrors.
    async fn spawn_mock(
        datacenter: &'static str,
        initial_routed_to: Option<String>,
    ) -> (String, Arc<AtomicU32>, tokio::task::JoinHandle<()>) {
        let routed_to: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(initial_routed_to));
        let move_calls = Arc::new(AtomicU32::new(0));

        let server_exists_route =
            axum::routing::get(|| async { axum::Json(serde_json::json!({ "datacenter": "gra" })) });

        let ip_get_route = {
            let routed_to = routed_to.clone();
            axum::routing::get(move || {
                let routed_to = routed_to.clone();
                async move {
                    let current = routed_to.lock().unwrap().clone();
                    axum::Json(serde_json::json!({
                        "datacenter": datacenter,
                        "routedTo": current,
                    }))
                }
            })
        };

        let ip_move_route = {
            let routed_to = routed_to.clone();
            let calls = move_calls.clone();
            axum::routing::post(move |axum::extract::Path(service_name): axum::extract::Path<String>, axum::Json(_body): axum::Json<serde_json::Value>| {
                let routed_to = routed_to.clone();
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    *routed_to.lock().unwrap() = Some(service_name);
                    axum::Json(serde_json::json!({}))
                }
            })
        };

        let app = axum::Router::new()
            .route("/dedicated/server/{service_name}", server_exists_route)
            .route("/ip/{ip}", ip_get_route)
            .route("/dedicated/server/{service_name}/ipMove", ip_move_route);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        (format!("http://{addr}"), move_calls, handle)
    }

    #[tokio::test]
    async fn ingress_owner_flip_drives_exactly_one_reassign_call() {
        let (base, calls, handle) = spawn_mock("gra", Some("old-server".into())).await;
        let client = OvhFloatingIp::new("test-consumer-key").with_base_url(base);
        let machine = gra_machine("edge-b");

        let outcome = on_ingress_owner_changed(&client, &machine, "51.81.85.200")
            .await
            .unwrap();
        assert!(outcome.reassigned, "owner flip must drive a reassign");
        assert_eq!(outcome.attached_to, "edge-b");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn reapplying_the_same_owner_is_a_zero_call_noop() {
        let (base, calls, handle) = spawn_mock("gra", Some("edge-b".into())).await;
        let client = OvhFloatingIp::new("test-consumer-key").with_base_url(base);
        let machine = gra_machine("edge-b");

        let outcome = on_ingress_owner_changed(&client, &machine, "51.81.85.200")
            .await
            .unwrap();
        assert!(!outcome.reassigned, "re-applying the same owner must be a no-op");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "must not call ipMove");

        handle.abort();
    }

    #[tokio::test]
    async fn cross_region_target_is_rejected_before_any_reassign_call() {
        // IP is homed to bhs (ca-east); target machine is eu-west.
        let (base, calls, handle) = spawn_mock("bhs", None).await;
        let client = OvhFloatingIp::new("test-consumer-key").with_base_url(base);
        let machine = gra_machine("edge-b"); // region = eu-west

        let err = on_ingress_owner_changed(&client, &machine, "51.81.85.200")
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("zone"), "expected a zone-mismatch error, got: {msg}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "region mismatch must never call ipMove");

        handle.abort();
    }

    #[test]
    fn ovh_datacenter_region_maps_eu_west_trio() {
        assert_eq!(ovh_datacenter_region("gra").unwrap(), "eu-west");
        assert_eq!(ovh_datacenter_region("rbx").unwrap(), "eu-west");
        assert_eq!(ovh_datacenter_region("sbg").unwrap(), "eu-west");
        assert_eq!(ovh_datacenter_region("bhs").unwrap(), "ca-east");
    }

    #[test]
    fn ovh_datacenter_region_rejects_unknown() {
        assert!(ovh_datacenter_region("xyz").is_err());
    }

    #[test]
    fn ovh_zone_for_prefers_location_over_region() {
        let mut m = gra_machine("edge-b");
        m.location = Some("bhs".into());
        assert_eq!(ovh_zone_for(&m).unwrap(), "ca-east");
    }

    #[test]
    fn ovh_zone_for_falls_back_to_region() {
        let m = gra_machine("edge-b"); // location: None, region: eu-west
        assert_eq!(ovh_zone_for(&m).unwrap(), "eu-west");
    }

    #[test]
    fn ovh_zone_for_errors_with_neither_field() {
        let mut m = gra_machine("edge-b");
        m.region = None;
        assert!(ovh_zone_for(&m).is_err());
    }
}
