//! `cloud.vps.*` verb signatures — the spike catalog (R409-T3).
//!
//! Per W144 §"What this doc is *not* deciding" and R409-T11 (catalog-shape
//! postmortem), the broader `cloud.*` / `dns.*` / etc. surface is gated on
//! validating this shape against a second native provider (R409-T10:
//! DigitalOcean). Only `cloud.vps.create`, `cloud.vps.destroy`, and
//! `cloud.vps.status` land here — the three verbs W144 explicitly calls out
//! as "already partially present in `MachineProvider`."
//!
//! Wire types are plain `serde` structs (with optional `schemars::JsonSchema`
//! under the `json-schema` feature). They are deliberately **not** the same
//! as the in-crate domain types ([`crate::provider::ServerSpec`],
//! [`crate::provider::ServerStatus`]) — the adapter is the boundary that
//! converts between them. Keeping wire and domain types separate is what
//! lets the same verb shape serve Hetzner, DigitalOcean, and (eventually)
//! a synthetic LocalDocker adapter without leaking vendor-specific fields.

use serde::{Deserialize, Serialize};

use super::{InternalVerb, VerbCategory};

// ── cloud.vps.create ─────────────────────────────────────────────────────

/// Marker type for the `cloud.vps.create` verb.
pub struct CloudVpsCreate;

/// Request body for `cloud.vps.create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudVpsCreateInput {
    /// Server name as it should appear in the provider's UI / API.
    pub name: String,
    /// Provider-side machine type slug (e.g. `"cpx22"` on Hetzner,
    /// `"s-2vcpu-4gb"` on DigitalOcean). Not normalized — vendors disagree
    /// on shape, so we pass through.
    pub server_type: String,
    /// Image slug (e.g. `"debian-12"`).
    pub image: String,
    /// Coarse region tag (W144 D5). One of `"na-west"`, `"na-east"`,
    /// `"eu-central"`; adapters pick the nearest vendor region within the
    /// tag. New tags follow `<continent>-<direction>` and land monotonically.
    pub location: String,
    /// Cloud-init `user_data` script.
    pub user_data: String,
    /// Provider-side SSH keys to authorize for `root` at create time.
    /// Strings — each adapter interprets per its vendor (W144 D7): Hetzner
    /// expects numeric IDs in string form; DigitalOcean accepts numeric IDs
    /// or SHA-256 fingerprints. Empty means "no key" — provider behavior on
    /// missing keys varies (Hetzner emails a random root password;
    /// DigitalOcean rejects).
    #[serde(default)]
    pub ssh_keys: Vec<String>,
}

/// Response body for `cloud.vps.create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudVpsCreateOutput {
    /// Opaque provider-issued id for the new server.
    pub id: String,
}

impl InternalVerb for CloudVpsCreate {
    type Input = CloudVpsCreateInput;
    type Output = CloudVpsCreateOutput;
    const ID: &'static str = "cloud.vps.create";
    const CATEGORY: VerbCategory = VerbCategory::Cloud;
}

// ── cloud.vps.destroy ────────────────────────────────────────────────────

/// Marker type for the `cloud.vps.destroy` verb.
pub struct CloudVpsDestroy;

/// Request body for `cloud.vps.destroy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudVpsDestroyInput {
    /// Opaque provider-issued id from a prior `cloud.vps.create`.
    pub id: String,
}

/// Response body for `cloud.vps.destroy`. Empty — adapters return `Ok({})`
/// whether the server existed or was already gone (idempotent).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudVpsDestroyOutput {}

impl InternalVerb for CloudVpsDestroy {
    type Input = CloudVpsDestroyInput;
    type Output = CloudVpsDestroyOutput;
    const ID: &'static str = "cloud.vps.destroy";
    const CATEGORY: VerbCategory = VerbCategory::Cloud;
}

// ── cloud.vps.status ─────────────────────────────────────────────────────

/// Marker type for the `cloud.vps.status` verb.
pub struct CloudVpsStatus;

/// Request body for `cloud.vps.status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudVpsStatusInput {
    /// Opaque provider-issued id from a prior `cloud.vps.create`.
    pub id: String,
}

/// Canonical VPS lifecycle phase. Maps onto [`crate::provider::ServerStatus`]
/// without the `Unknown(String)` payload — the free-form vendor detail rides
/// in [`CloudVpsStatusOutput::detail`] instead so the wire shape stays a
/// closed enum that downstream UI can render directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum VpsPhase {
    Initializing,
    Starting,
    Running,
    Stopping,
    Off,
    Deleting,
    Unknown,
}

/// Response body for `cloud.vps.status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudVpsStatusOutput {
    /// Canonical phase.
    pub phase: VpsPhase,
    /// Free-form vendor detail. Populated when `phase` is
    /// [`VpsPhase::Unknown`] (the adapter saw a status string it didn't
    /// recognise); may also carry a vendor-side reason string for known
    /// phases when one is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl InternalVerb for CloudVpsStatus {
    type Input = CloudVpsStatusInput;
    type Output = CloudVpsStatusOutput;
    const ID: &'static str = "cloud.vps.status";
    const CATEGORY: VerbCategory = VerbCategory::Cloud;
}

/// Pure conversion: domain [`crate::provider::ServerStatus`] →
/// wire [`CloudVpsStatusOutput`].
///
/// Extracted so both `HetznerEnvoy` and `LocalDockerEnvoy` share one
/// implementation without pulling the other adapter's module.
pub fn server_status_to_output(status: crate::provider::ServerStatus) -> CloudVpsStatusOutput {
    use crate::provider::ServerStatus;
    let (phase, detail) = match status {
        ServerStatus::Initializing => (VpsPhase::Initializing, None),
        ServerStatus::Starting => (VpsPhase::Starting, None),
        ServerStatus::Running => (VpsPhase::Running, None),
        ServerStatus::Stopping => (VpsPhase::Stopping, None),
        ServerStatus::Off => (VpsPhase::Off, None),
        ServerStatus::Deleting => (VpsPhase::Deleting, None),
        ServerStatus::Unknown(s) => (VpsPhase::Unknown, Some(s)),
    };
    CloudVpsStatusOutput { phase, detail }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_ids_match_canonical_namespace() {
        assert_eq!(CloudVpsCreate::ID, "cloud.vps.create");
        assert_eq!(CloudVpsDestroy::ID, "cloud.vps.destroy");
        assert_eq!(CloudVpsStatus::ID, "cloud.vps.status");
        for id in [CloudVpsCreate::ID, CloudVpsDestroy::ID, CloudVpsStatus::ID] {
            assert!(id.starts_with("cloud."), "{id}");
        }
    }

    #[test]
    fn verbs_are_under_cloud_category() {
        assert_eq!(CloudVpsCreate::CATEGORY, VerbCategory::Cloud);
        assert_eq!(CloudVpsDestroy::CATEGORY, VerbCategory::Cloud);
        assert_eq!(CloudVpsStatus::CATEGORY, VerbCategory::Cloud);
    }

    #[test]
    fn create_input_round_trips() {
        let input = CloudVpsCreateInput {
            name: "noisetable-na-west-1".into(),
            server_type: "cpx22".into(),
            image: "debian-12".into(),
            location: "na-west".into(),
            user_data: "#cloud-config\n".into(),
            ssh_keys: vec!["123".into(), "456".into()],
        };
        let wire = serde_json::to_string(&input).unwrap();
        let back: CloudVpsCreateInput = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.name, "noisetable-na-west-1");
        assert_eq!(back.ssh_keys, vec!["123".to_string(), "456".to_string()]);
    }

    #[test]
    fn create_input_defaults_ssh_keys_empty() {
        let wire = r#"{"name":"n","server_type":"t","image":"i","location":"na-west","user_data":""}"#;
        let parsed: CloudVpsCreateInput = serde_json::from_str(wire).unwrap();
        assert!(parsed.ssh_keys.is_empty());
    }

    #[test]
    fn create_input_rejects_legacy_project_field() {
        // D6: `project` is no longer a wire field. Inputs that still send it
        // round-trip cleanly because serde ignores unknown fields by default.
        let wire = r#"{"project":"old","name":"n","server_type":"t","image":"i","location":"na-west","user_data":""}"#;
        let parsed: CloudVpsCreateInput = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.name, "n");
    }

    #[test]
    fn create_input_accepts_fingerprint_ssh_key() {
        // D7: DigitalOcean accepts SHA-256 fingerprints — wire shape must
        // pass through arbitrary strings, not just numeric IDs.
        let wire = r#"{"name":"n","server_type":"t","image":"i","location":"na-west","user_data":"","ssh_keys":["e0:7a:1b:ff:00:11:22:33"]}"#;
        let parsed: CloudVpsCreateInput = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.ssh_keys, vec!["e0:7a:1b:ff:00:11:22:33".to_string()]);
    }

    #[test]
    fn destroy_output_serializes_to_empty_object() {
        let wire = serde_json::to_value(CloudVpsDestroyOutput::default()).unwrap();
        assert_eq!(wire, serde_json::json!({}));
    }

    #[test]
    fn status_phase_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&VpsPhase::Initializing).unwrap(),
            "\"initializing\""
        );
        assert_eq!(serde_json::to_string(&VpsPhase::Off).unwrap(), "\"off\"");
        assert_eq!(
            serde_json::to_string(&VpsPhase::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    #[test]
    fn status_output_omits_detail_when_absent() {
        let out = CloudVpsStatusOutput {
            phase: VpsPhase::Running,
            detail: None,
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(wire, serde_json::json!({ "phase": "running" }));
    }

    #[test]
    fn status_output_includes_detail_when_present() {
        let out = CloudVpsStatusOutput {
            phase: VpsPhase::Unknown,
            detail: Some("rebuilding".into()),
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({ "phase": "unknown", "detail": "rebuilding" })
        );
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn verbs_emit_schemas_via_for_verb() {
        use super::super::VerbDescriptor;

        let create = VerbDescriptor::for_verb::<CloudVpsCreate>();
        assert_eq!(create.id, "cloud.vps.create");
        assert!(create.input_schema.to_string().contains("user_data"));

        let destroy = VerbDescriptor::for_verb::<CloudVpsDestroy>();
        assert_eq!(destroy.id, "cloud.vps.destroy");
        assert!(destroy.input_schema.to_string().contains("\"id\""));

        let status = VerbDescriptor::for_verb::<CloudVpsStatus>();
        assert_eq!(status.id, "cloud.vps.status");
        assert!(status.output_schema.to_string().contains("phase"));
    }
}
