//! [`HetznerEnvoy`] — adapter that exposes the existing [`HetznerDriver`]
//! through the envoy framework's `cloud.vps.*` verbs (R409-T5).
//!
//! This is the spike scope per R409-T11 — only the three verbs from
//! [`crate::envoy::cloud_vps`] are wired up. The rest of `cloud.*` (object
//! storage, project, networking, firewalls, load balancers) lands after the
//! catalog-shape postmortem confirms this shape works against a second
//! native provider (DigitalOcean — R409-T10).
//!
//! Layering: `MachineProvider` (the existing in-crate trait) stays in place
//! and continues to be the substrate the orchestration code calls into.
//! `HetznerEnvoy` is a thin translation layer over a [`HetznerDriver`]
//! that converts wire types ↔ domain types and routes verb-id strings to
//! typed handler methods. The legacy `MachineProvider` surface retires in
//! R409-T9 once every caller has migrated to the verb framework.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde_json::Value;

use super::{HetznerDriver, Location, MachineProvider, ServerId, ServerSpec};
use crate::envoy::cloud_vps::{
    server_status_to_output, CloudVpsCreate, CloudVpsCreateInput, CloudVpsCreateOutput,
    CloudVpsDestroy, CloudVpsDestroyInput, CloudVpsDestroyOutput, CloudVpsStatus,
    CloudVpsStatusInput, CloudVpsStatusOutput,
};
use crate::envoy::{AdapterFlavor, EnvoyAdapter, InternalVerb, Tier};

/// Tier-S, native-flavored envoy adapter that bridges the existing
/// [`HetznerDriver`] to the verb framework.
pub struct HetznerEnvoy {
    driver: Arc<HetznerDriver>,
}

impl HetznerEnvoy {
    /// Wrap an owned driver.
    pub fn new(driver: HetznerDriver) -> Self {
        Self {
            driver: Arc::new(driver),
        }
    }

    /// Wrap a shared driver — useful when the same driver instance is also
    /// in use behind the legacy `MachineProvider` surface during the
    /// migration window.
    pub fn from_arc(driver: Arc<HetznerDriver>) -> Self {
        Self { driver }
    }

    /// Typed handler for `cloud.vps.create`. Public so callers that want
    /// to skip the JSON envelope (e.g. integration tests) can bypass
    /// [`EnvoyAdapter::dispatch`].
    ///
    /// Hetzner has no fingerprint variant for `ssh_keys` (W144 D7), so each
    /// wire string is parsed as a `u64`. A non-numeric entry is rejected
    /// before the create call hits the API.
    pub async fn cloud_vps_create(
        &self,
        input: CloudVpsCreateInput,
    ) -> Result<CloudVpsCreateOutput> {
        let location = Location::try_from(input.location.as_str())
            .with_context(|| format!("cloud.vps.create: unknown location {:?}", input.location))?;
        let ssh_keys = parse_ssh_keys(&input.ssh_keys)?;
        let spec = ServerSpec {
            name: input.name,
            server_type: input.server_type,
            image: input.image,
            location,
            ssh_keys,
        };
        // W144 D6: there is no per-call project on the wire. Hetzner's
        // existing project model is token-scoped (one envoy = one project),
        // so `ensure_project` is the no-op identity; the empty label below
        // is the convention for "use the envoy's ambient scope."
        let project = self
            .driver
            .ensure_project("")
            .await
            .context("cloud.vps.create: ensure_project")?;
        let id = self
            .driver
            .create_server(&project, &spec, &input.user_data)
            .await
            .context("cloud.vps.create: create_server")?;
        Ok(CloudVpsCreateOutput { id: id.0 })
    }

    /// Typed handler for `cloud.vps.destroy`. Idempotent — the underlying
    /// driver returns `Ok(())` if the server was already gone.
    pub async fn cloud_vps_destroy(
        &self,
        input: CloudVpsDestroyInput,
    ) -> Result<CloudVpsDestroyOutput> {
        self.driver
            .destroy_server(&ServerId(input.id))
            .await
            .context("cloud.vps.destroy: destroy_server")?;
        Ok(CloudVpsDestroyOutput::default())
    }

    /// Typed handler for `cloud.vps.status`. Converts the domain
    /// [`ServerStatus`] enum (with its free-form `Unknown(String)`) to the
    /// wire [`VpsPhase`] (closed enum) + optional `detail` string.
    pub async fn cloud_vps_status(
        &self,
        input: CloudVpsStatusInput,
    ) -> Result<CloudVpsStatusOutput> {
        let status = self
            .driver
            .server_status(&ServerId(input.id))
            .await
            .context("cloud.vps.status: server_status")?;
        Ok(server_status_to_output(status))
    }
}

#[async_trait]
impl EnvoyAdapter for HetznerEnvoy {
    fn id(&self) -> &str {
        "hetzner"
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
            other => bail!("hetzner envoy does not support verb {other:?}"),
        }
    }
}

/// Parse each `ssh_keys` wire string as a Hetzner-numeric key id. Hetzner
/// has no fingerprint variant (W144 D7), so non-numeric entries are a
/// caller-side mistake — fail fast with a message that names the bad
/// element so the caller can fix the input.
fn parse_ssh_keys(raw: &[String]) -> Result<Vec<u64>> {
    raw.iter()
        .map(|s| {
            s.parse::<u64>().with_context(|| {
                format!("cloud.vps.create: hetzner ssh_keys entry {s:?} is not a numeric key id")
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envoy::cloud_vps::VpsPhase;
    use crate::provider::ServerStatus;

    #[test]
    fn server_status_running_maps_to_running_phase_no_detail() {
        let out = server_status_to_output(ServerStatus::Running);
        assert_eq!(out.phase, VpsPhase::Running);
        assert!(out.detail.is_none());
    }

    #[test]
    fn server_status_unknown_carries_detail() {
        let out = server_status_to_output(ServerStatus::Unknown("rebuilding".into()));
        assert_eq!(out.phase, VpsPhase::Unknown);
        assert_eq!(out.detail.as_deref(), Some("rebuilding"));
    }

    #[test]
    fn parse_ssh_keys_accepts_numeric_strings() {
        let parsed = parse_ssh_keys(&["123".into(), "456".into()]).unwrap();
        assert_eq!(parsed, vec![123u64, 456u64]);
    }

    #[test]
    fn parse_ssh_keys_rejects_fingerprint_with_named_entry() {
        // W144 D7: Hetzner doesn't accept fingerprints; the adapter must
        // surface the offending element so the caller can fix the input.
        let err = parse_ssh_keys(&["e0:7a:1b".into()]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("e0:7a:1b"), "{msg}");
    }

    #[test]
    fn parse_ssh_keys_empty_round_trips() {
        let parsed = parse_ssh_keys(&[]).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn server_status_all_known_variants_lose_detail() {
        // The closed phases never carry detail — only Unknown does.
        for s in [
            ServerStatus::Initializing,
            ServerStatus::Starting,
            ServerStatus::Running,
            ServerStatus::Stopping,
            ServerStatus::Off,
            ServerStatus::Deleting,
        ] {
            let out = server_status_to_output(s);
            assert!(
                out.detail.is_none(),
                "phase {:?} should not carry detail",
                out.phase
            );
        }
    }
}
