//! [`DigitalOceanEnvoy`] — second native `cloud.vps.*` adapter, spike scope
//! (R409-T10). Together with [`HetznerEnvoy`] this is the catalog-shape
//! validator R409-T11's postmortem decides on.
//!
//! Layering differs from Hetzner: there is no separate `MachineProvider` impl
//! in the way. Hetzner has a long-lived [`HetznerDriver`] that the
//! orchestration code (`provision.rs`, `cloud_init.rs`) calls into, and the
//! envoy was retrofitted on top. DigitalOcean has never had such a driver, so
//! [`DigitalOceanClient`] is built thin and lives only behind
//! [`DigitalOceanEnvoy`] — no parallel `MachineProvider` impl. If T11 says
//! "expand", the client lifts into its own `crates/yah/digitalocean` crate
//! the way Hetzner did in R040-F14.
//!
//! The spike is **pre-envoy-host**: nothing wires `DigitalOceanEnvoy` through
//! `KgToolRegistry` (that's R409-T9). Verification is unit tests of the
//! conversion layer — the network methods are not exercised in tests.
//!
//! ## Post-T11 shape
//!
//! Three findings drove revisions in the R409-T11 postmortem (see W144
//! §"Catalog-shape postmortem"):
//!
//! - **D5**: wire `location` is now a coarse region tag (`na-west`,
//!   `na-east`, `eu-central`); [`do_region`] maps each tag to the nearest
//!   DO slug (`sfo3`, `nyc3`, `fra1`).
//! - **D6**: `CloudVpsCreateInput.project` is gone — DO Projects remain
//!   available as a future `cloud.project.*` verb tree but are no longer
//!   a free parameter on `cloud.vps.create`.
//! - **D7**: `ssh_keys` is now `Vec<String>`; DO accepts both numeric IDs
//!   and SHA-256 fingerprints as JSON strings, so the spec passes the
//!   values through verbatim.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::envoy::cloud_vps::{
    CloudVpsCreate, CloudVpsCreateInput, CloudVpsCreateOutput, CloudVpsDestroy,
    CloudVpsDestroyInput, CloudVpsDestroyOutput, CloudVpsStatus, CloudVpsStatusInput,
    CloudVpsStatusOutput, VpsPhase,
};
use crate::envoy::{AdapterFlavor, EnvoyAdapter, InternalVerb, Tier};

const DO_BASE: &str = "https://api.digitalocean.com/v2";

/// Minimal DigitalOcean Cloud API client — droplet lifecycle only.
///
/// Token-source policy stays out of the client: callers obtain the bearer
/// token (env, keystore, vault) and pass it in. Same convention as
/// [`hetzner::HetznerClient`].
#[derive(Clone)]
pub struct DigitalOceanClient {
    http: reqwest::Client,
    token: String,
    base_url: String,
}

impl DigitalOceanClient {
    /// Build a client against `api.digitalocean.com`.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            token: token.into(),
            base_url: DO_BASE.to_string(),
        }
    }

    /// Override the base URL — useful for integration tests against a
    /// mocked endpoint. Production callers shouldn't need this.
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// `POST /v2/droplets`. Returns the new droplet's numeric id.
    pub async fn create_droplet(&self, spec: &DoCreateDropletSpec) -> Result<u64> {
        let resp = self
            .http
            .post(format!("{}/droplets", self.base_url))
            .bearer_auth(&self.token)
            .json(spec)
            .send()
            .await
            .context("digitalocean: POST /droplets")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("digitalocean POST /droplets failed: {status} {body}");
        }
        let parsed: CreateDropletResponse = resp
            .json()
            .await
            .context("digitalocean: decode POST /droplets response")?;
        Ok(parsed.droplet.id)
    }

    /// `GET /v2/droplets/{id}`. Returns the raw droplet `status` string
    /// (one of `new`/`active`/`off`/`archive`, or something newer DO has
    /// added that we have not yet mapped).
    pub async fn droplet_status(&self, id: u64) -> Result<String> {
        let resp = self
            .http
            .get(format!("{}/droplets/{}", self.base_url, id))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("digitalocean: GET /droplets/{id}")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("digitalocean GET /droplets/{id} failed: {status} {body}");
        }
        let parsed: DropletResponse = resp
            .json()
            .await
            .context("digitalocean: decode GET /droplets/{id} response")?;
        Ok(parsed.droplet.status)
    }

    /// `DELETE /v2/droplets/{id}`. Idempotent — a 404 returns `Ok(())`.
    pub async fn destroy_droplet(&self, id: u64) -> Result<()> {
        let resp = self
            .http
            .delete(format!("{}/droplets/{}", self.base_url, id))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("digitalocean: DELETE /droplets/{id}")?;
        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(());
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("digitalocean DELETE /droplets/{id} failed: {status} {body}");
        }
        Ok(())
    }
}

/// Request body for `POST /v2/droplets`. Field names match DO's API
/// exactly so this serializes straight to the wire.
#[derive(Debug, Clone, Serialize)]
pub struct DoCreateDropletSpec {
    pub name: String,
    /// DO region slug (e.g. `"sfo3"`, `"fra1"`).
    pub region: String,
    /// DO size slug (e.g. `"s-1vcpu-1gb"`, `"s-2vcpu-4gb"`).
    pub size: String,
    /// DO image slug (e.g. `"debian-12-x64"`).
    pub image: String,
    /// SSH keys to authorize for `root`. DO accepts numeric ids or SHA-256
    /// fingerprints — W144 D7 lets both flow through as strings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ssh_keys: Vec<String>,
    /// cloud-init `user_data`. Omitted from the body when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
}

#[derive(Deserialize)]
struct CreateDropletResponse {
    droplet: RawDroplet,
}

#[derive(Deserialize)]
struct DropletResponse {
    droplet: RawDroplet,
}

#[derive(Deserialize)]
struct RawDroplet {
    id: u64,
    status: String,
}

/// Tier-S, native-flavored envoy adapter that bridges the DigitalOcean
/// droplet API to the `cloud.vps.*` verb framework. Spike scope (R409-T10):
/// only the three verbs from [`crate::envoy::cloud_vps`] are wired.
pub struct DigitalOceanEnvoy {
    client: Arc<DigitalOceanClient>,
}

impl DigitalOceanEnvoy {
    /// Wrap an owned client.
    pub fn new(client: DigitalOceanClient) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    /// Wrap a shared client.
    pub fn from_arc(client: Arc<DigitalOceanClient>) -> Self {
        Self { client }
    }

    /// Typed handler for `cloud.vps.create`. Public so integration tests
    /// can bypass [`EnvoyAdapter::dispatch`].
    pub async fn cloud_vps_create(
        &self,
        input: CloudVpsCreateInput,
    ) -> Result<CloudVpsCreateOutput> {
        let region = do_region(&input.location)
            .with_context(|| format!("cloud.vps.create: unknown location {:?}", input.location))?;
        let spec = DoCreateDropletSpec {
            name: input.name,
            region: region.to_string(),
            size: input.server_type,
            image: input.image,
            ssh_keys: input.ssh_keys,
            user_data: if input.user_data.is_empty() {
                None
            } else {
                Some(input.user_data)
            },
        };
        let id = self
            .client
            .create_droplet(&spec)
            .await
            .context("cloud.vps.create: create_droplet")?;
        Ok(CloudVpsCreateOutput { id: id.to_string() })
    }

    /// Typed handler for `cloud.vps.destroy`. Idempotent.
    pub async fn cloud_vps_destroy(
        &self,
        input: CloudVpsDestroyInput,
    ) -> Result<CloudVpsDestroyOutput> {
        let id = parse_droplet_id(&input.id, "cloud.vps.destroy")?;
        self.client
            .destroy_droplet(id)
            .await
            .context("cloud.vps.destroy: destroy_droplet")?;
        Ok(CloudVpsDestroyOutput::default())
    }

    /// Typed handler for `cloud.vps.status`. Maps DO's small status
    /// taxonomy onto the wire [`VpsPhase`] via [`do_status_to_output`].
    pub async fn cloud_vps_status(
        &self,
        input: CloudVpsStatusInput,
    ) -> Result<CloudVpsStatusOutput> {
        let id = parse_droplet_id(&input.id, "cloud.vps.status")?;
        let raw = self
            .client
            .droplet_status(id)
            .await
            .context("cloud.vps.status: droplet_status")?;
        Ok(do_status_to_output(&raw))
    }
}

#[async_trait]
impl EnvoyAdapter for DigitalOceanEnvoy {
    fn id(&self) -> &str {
        "digitalocean"
    }
    fn tier(&self) -> Tier {
        Tier::S
    }
    fn flavor(&self) -> AdapterFlavor {
        AdapterFlavor::Native
    }
    fn supported_verb_ids(&self) -> Vec<&'static str> {
        vec![CloudVpsCreate::ID, CloudVpsDestroy::ID, CloudVpsStatus::ID]
    }
    async fn dispatch(&self, verb_id: &str, input: Value) -> Result<Value> {
        match verb_id {
            id if id == CloudVpsCreate::ID => {
                let args: CloudVpsCreateInput =
                    serde_json::from_value(input).with_context(|| format!("{id}: decode input"))?;
                let out = self.cloud_vps_create(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            id if id == CloudVpsDestroy::ID => {
                let args: CloudVpsDestroyInput =
                    serde_json::from_value(input).with_context(|| format!("{id}: decode input"))?;
                let out = self.cloud_vps_destroy(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            id if id == CloudVpsStatus::ID => {
                let args: CloudVpsStatusInput =
                    serde_json::from_value(input).with_context(|| format!("{id}: decode input"))?;
                let out = self.cloud_vps_status(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            other => bail!("digitalocean envoy does not support verb {other:?}"),
        }
    }
}

/// Pure conversion: W144-D5 coarse region tag → DO region slug.
///
/// The tags promise *broad region*, not specific city: `na-west` lands in
/// the DO San Francisco region; `na-east` in New York; `eu-central` in
/// Frankfurt. New tags follow `<continent>-<direction>` and are added here
/// monotonically as DO opens more regions.
fn do_region(loc: &str) -> Result<&'static str> {
    match loc {
        "na-west" => Ok("sfo3"),
        "na-east" => Ok("nyc3"),
        "eu-central" => Ok("fra1"),
        other => Err(anyhow::anyhow!("unknown location: {other}")),
    }
}

/// Pure conversion: DO droplet status string → wire [`CloudVpsStatusOutput`].
///
/// DO has four documented statuses (`new`, `active`, `off`, `archive`). Newer
/// or vendor-internal values fall through to [`VpsPhase::Unknown`] with the
/// raw string preserved in `detail` so the caller can see what happened.
fn do_status_to_output(raw: &str) -> CloudVpsStatusOutput {
    let (phase, detail) = match raw {
        "new" => (VpsPhase::Initializing, None),
        "active" => (VpsPhase::Running, None),
        "off" => (VpsPhase::Off, None),
        "archive" => (VpsPhase::Deleting, None),
        other => (VpsPhase::Unknown, Some(other.to_string())),
    };
    CloudVpsStatusOutput { phase, detail }
}

fn parse_droplet_id(raw: &str, verb: &str) -> Result<u64> {
    raw.parse()
        .with_context(|| format!("{verb}: id {raw:?} is not a u64 droplet id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn do_region_maps_known_locations() {
        assert_eq!(do_region("na-west").unwrap(), "sfo3");
        assert_eq!(do_region("na-east").unwrap(), "nyc3");
        assert_eq!(do_region("eu-central").unwrap(), "fra1");
    }

    #[test]
    fn do_region_rejects_unknown() {
        let err = do_region("hil").unwrap_err();
        assert!(err.to_string().contains("hil"));
    }

    #[test]
    fn do_region_rejects_legacy_airport_codes() {
        // W144 D5: the old Hetzner-centric airport codes (pdx/iad/fsn) are
        // no longer wire-valid. Adapters must surface a clear error so the
        // caller updates their input to the new coarse region tag.
        for legacy in ["pdx", "iad", "fsn"] {
            let err = do_region(legacy).unwrap_err();
            assert!(
                err.to_string().contains(legacy),
                "expected error to name {legacy}"
            );
        }
    }

    #[test]
    fn do_status_new_maps_to_initializing() {
        let out = do_status_to_output("new");
        assert_eq!(out.phase, VpsPhase::Initializing);
        assert!(out.detail.is_none());
    }

    #[test]
    fn do_status_active_maps_to_running() {
        let out = do_status_to_output("active");
        assert_eq!(out.phase, VpsPhase::Running);
        assert!(out.detail.is_none());
    }

    #[test]
    fn do_status_off_maps_to_off() {
        let out = do_status_to_output("off");
        assert_eq!(out.phase, VpsPhase::Off);
        assert!(out.detail.is_none());
    }

    #[test]
    fn do_status_archive_maps_to_deleting() {
        let out = do_status_to_output("archive");
        assert_eq!(out.phase, VpsPhase::Deleting);
        assert!(out.detail.is_none());
    }

    #[test]
    fn do_status_unknown_carries_raw_string_as_detail() {
        // T11 input: DO may add states (e.g. `provisioning`) without notice.
        // The wire shape lets unknown values pass through with the raw string
        // so the caller can see what happened.
        let out = do_status_to_output("provisioning");
        assert_eq!(out.phase, VpsPhase::Unknown);
        assert_eq!(out.detail.as_deref(), Some("provisioning"));
    }

    #[test]
    fn create_spec_omits_optional_fields_when_empty() {
        let spec = DoCreateDropletSpec {
            name: "x".into(),
            region: "fra1".into(),
            size: "s-1vcpu-1gb".into(),
            image: "debian-12-x64".into(),
            ssh_keys: vec![],
            user_data: None,
        };
        let wire = serde_json::to_value(&spec).unwrap();
        assert!(wire.get("user_data").is_none());
        assert!(wire.get("ssh_keys").is_none());
        assert_eq!(wire["name"], "x");
        assert_eq!(wire["region"], "fra1");
        assert_eq!(wire["size"], "s-1vcpu-1gb");
        assert_eq!(wire["image"], "debian-12-x64");
    }

    #[test]
    fn create_spec_serializes_user_data_and_ssh_keys() {
        let spec = DoCreateDropletSpec {
            name: "x".into(),
            region: "fra1".into(),
            size: "s-1vcpu-1gb".into(),
            image: "debian-12-x64".into(),
            ssh_keys: vec!["123".into(), "e0:7a:1b".into()],
            user_data: Some("#cloud-config\n".into()),
        };
        let wire = serde_json::to_value(&spec).unwrap();
        assert_eq!(wire["user_data"], "#cloud-config\n");
        // W144 D7: DO accepts both numeric IDs and fingerprints — the wire
        // payload preserves whatever string form the caller supplied.
        assert_eq!(wire["ssh_keys"], serde_json::json!(["123", "e0:7a:1b"]));
    }

    #[test]
    fn envoy_advertises_three_cloud_vps_verbs() {
        let envoy = DigitalOceanEnvoy::new(DigitalOceanClient::new("stub-token"));
        let ids = envoy.supported_verb_ids();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"cloud.vps.create"));
        assert!(ids.contains(&"cloud.vps.destroy"));
        assert!(ids.contains(&"cloud.vps.status"));
        assert_eq!(envoy.id(), "digitalocean");
        assert_eq!(envoy.tier(), Tier::S);
        assert_eq!(envoy.flavor(), AdapterFlavor::Native);
    }

    #[tokio::test]
    async fn dispatch_unknown_verb_errors() {
        let envoy = DigitalOceanEnvoy::new(DigitalOceanClient::new("stub-token"));
        let err = envoy
            .dispatch("cloud.dns.upsert", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not support"));
    }

    #[tokio::test]
    async fn destroy_with_non_numeric_id_errors_before_http() {
        // The id parse fails before any HTTP call — so this exercises the
        // input-validation path against a stub-token client without needing
        // a mocked DO endpoint.
        let envoy = DigitalOceanEnvoy::new(DigitalOceanClient::new("stub-token"));
        let err = envoy
            .cloud_vps_destroy(CloudVpsDestroyInput {
                id: "not-a-number".into(),
            })
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not-a-number"), "{msg}");
    }

    #[tokio::test]
    async fn status_with_non_numeric_id_errors_before_http() {
        let envoy = DigitalOceanEnvoy::new(DigitalOceanClient::new("stub-token"));
        let err = envoy
            .cloud_vps_status(CloudVpsStatusInput {
                id: "droplet-abc".into(),
            })
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("droplet-abc"), "{msg}");
    }
}
