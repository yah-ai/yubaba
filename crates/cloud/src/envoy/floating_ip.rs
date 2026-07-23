//! `floating_ip.*` verb signatures (R594-F5).
//!
//! Two verbs, mirroring the `dns.*` shape (`envoy/dns_record.rs`):
//! `floating_ip.assign` moves a provider floating/reserved IP to a resolved
//! target, `floating_ip.status` reports where it lives today.
//!
//! This is the sovereign-tier ingress analog of the "external identity
//! follows placement" property [R591](yah://arch/symbol/R591) names for
//! Headscale via a Cloudflare Tunnel. R591 is peer-owned and gated on R570
//! (real multi-node raft HA, not yet up) — `floating_ip.*` is **not**
//! blocked on either: it builds directly on the raft `ingress_owner` seam,
//! which already exists and already has a passing test —
//! `oss/yubaba/crates/yubaba/src/raft/mod.rs`'s `YubabaRequest::SetIngressOwner`
//! / `YubabaRequest::ClearIngressOwner` and `RaftAppState::ingress_owner`
//! (raft/mod.rs is read-only from this ticket's side; it is not modified
//! here).
//!
//! ## Wire shape: already-resolved target, not a bare machine name
//!
//! `FloatingIpAssignInput` takes `attach_id` + `zone` rather than a machine
//! name — the same "adapter is the boundary, caller supplies resolved-enough
//! data" split `cloud.vps.create`'s `location` coarse-region tag uses. The
//! machine-TOML → `(attach_id, zone)` resolution is provider-specific
//! (Hetzner needs a live name→numeric-server-id lookup; OVH assumes
//! serviceName == machine name; Vultr looks up by instance label) and lives
//! on each adapter's [`crate::provider::FloatingIpProvider::resolve_target`]
//! impl, not the wire layer — matching the existing wire-vs-domain split
//! documented on [`super::cloud_vps`].
//!
//! The Rust-level entry point that *does* start from a machine (for the
//! raft-reconcile caller, which already has a `MachineConfig` in hand and
//! has no reason to round-trip through JSON) is
//! [`crate::provider::on_ingress_owner_changed`] — see its doc comment for
//! exactly where that gets wired to fire automatically on an
//! `ingress_owner` change.
//!
//! ## Provider mobility constraints
//!
//! Verified 2026-07, folded into W267 §Tier 1
//! (`.yah/docs/working/W267-sovereign-public-ingress.md`):
//!
//! - **Hetzner** floating IPs reassign via API within a **network zone**
//!   (+ same project — a single envoy is already scoped to one Hetzner
//!   project by convention, so cross-project moves are not a case this
//!   verb needs to handle).
//! - **OVH** Additional IPs move via API within a **datacentre/country
//!   region** (the eu-west GRA/RBX/SBG trio has cross-DC flexibility
//!   *within* that region, per W267).
//! - **Vultr** reserved IPs are **region-bound** (BGP-implemented inside
//!   AS20473).
//!
//! `floating_ip.assign` is idempotent — reassigning to the IP's current
//! target is a no-op (zero calls to the provider's reassign endpoint), and
//! a cross-zone target is rejected with an error *before* any reassign call
//! is attempted. See [`crate::provider::reconcile_assignment`] for the
//! shared core all three providers run through.

use serde::{Deserialize, Serialize};

use super::{InternalVerb, VerbCategory};

// ── floating_ip.assign ────────────────────────────────────────────────────

/// Marker type for the `floating_ip.assign` verb.
pub struct FloatingIpAssign;

/// Request body for `floating_ip.assign`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FloatingIpAssignInput {
    /// Provider-issued floating/reserved IP identifier (Hetzner numeric id
    /// as a string; OVH IP address, e.g. `"51.81.85.200"`; Vultr
    /// reserved-ip UUID).
    pub ip_id: String,
    /// Provider-native attach target the IP should point at — Hetzner
    /// numeric server id, OVH serviceName, Vultr instance UUID. Resolved
    /// by the caller (see module docs); the adapter treats it as opaque,
    /// the same convention `cloud.vps.destroy`'s `id` field uses.
    pub attach_id: String,
    /// Mobility zone `attach_id` lives in (Hetzner network zone / OVH
    /// datacentre-region / Vultr region). Checked against the floating
    /// IP's home zone before any reassign call — a mismatch is a hard
    /// error, never a silent fallback (the provider physically cannot
    /// move the IP there).
    pub zone: String,
}

/// Response body for `floating_ip.assign`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FloatingIpAssignOutput {
    /// `true` iff a reassign call was actually issued to the provider.
    /// `false` means the IP was already pointed at `attach_id` — an
    /// idempotent no-op, not an error.
    pub reassigned: bool,
    /// The attach target the IP now points at. Equals the input
    /// `attach_id` on success, whether or not a network call was needed.
    pub attached_to: String,
}

impl InternalVerb for FloatingIpAssign {
    type Input = FloatingIpAssignInput;
    type Output = FloatingIpAssignOutput;
    const ID: &'static str = "floating_ip.assign";
    const CATEGORY: VerbCategory = VerbCategory::FloatingIp;
}

// ── floating_ip.status ────────────────────────────────────────────────────

/// Marker type for the `floating_ip.status` verb.
pub struct FloatingIpStatus;

/// Request body for `floating_ip.status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FloatingIpStatusInput {
    /// Provider-issued floating/reserved IP identifier.
    pub ip_id: String,
}

/// Response body for `floating_ip.status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FloatingIpStatusOutput {
    /// The IP's home mobility zone — fixed for the IP's lifetime; this is
    /// the boundary the provider's API enforces on `floating_ip.assign`.
    pub zone: String,
    /// Provider-native id of whatever the IP is currently attached to, if
    /// anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_to: Option<String>,
}

impl InternalVerb for FloatingIpStatus {
    type Input = FloatingIpStatusInput;
    type Output = FloatingIpStatusOutput;
    const ID: &'static str = "floating_ip.status";
    const CATEGORY: VerbCategory = VerbCategory::FloatingIp;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_ids_match_canonical_namespace() {
        assert_eq!(FloatingIpAssign::ID, "floating_ip.assign");
        assert_eq!(FloatingIpStatus::ID, "floating_ip.status");
        for id in [FloatingIpAssign::ID, FloatingIpStatus::ID] {
            assert!(id.starts_with("floating_ip."), "{id}");
        }
    }

    #[test]
    fn verbs_are_under_floating_ip_category() {
        assert_eq!(FloatingIpAssign::CATEGORY, VerbCategory::FloatingIp);
        assert_eq!(FloatingIpStatus::CATEGORY, VerbCategory::FloatingIp);
    }

    #[test]
    fn assign_input_round_trips() {
        let input = FloatingIpAssignInput {
            ip_id: "42".into(),
            attach_id: "123".into(),
            zone: "eu-central".into(),
        };
        let wire = serde_json::to_string(&input).unwrap();
        let back: FloatingIpAssignInput = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.ip_id, "42");
        assert_eq!(back.attach_id, "123");
        assert_eq!(back.zone, "eu-central");
    }

    #[test]
    fn assign_output_round_trips() {
        let out = FloatingIpAssignOutput {
            reassigned: true,
            attached_to: "123".into(),
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(wire, serde_json::json!({ "reassigned": true, "attached_to": "123" }));
    }

    #[test]
    fn status_output_omits_attached_to_when_absent() {
        let out = FloatingIpStatusOutput {
            zone: "us-east".into(),
            attached_to: None,
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(wire, serde_json::json!({ "zone": "us-east" }));
    }

    #[test]
    fn status_output_includes_attached_to_when_present() {
        let out = FloatingIpStatusOutput {
            zone: "us-east".into(),
            attached_to: Some("123".into()),
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({ "zone": "us-east", "attached_to": "123" })
        );
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn verbs_emit_schemas_via_for_verb() {
        use super::super::VerbDescriptor;

        let assign = VerbDescriptor::for_verb::<FloatingIpAssign>();
        assert_eq!(assign.id, "floating_ip.assign");
        assert!(assign.input_schema.to_string().contains("attach_id"));

        let status = VerbDescriptor::for_verb::<FloatingIpStatus>();
        assert_eq!(status.id, "floating_ip.status");
        assert!(status.output_schema.to_string().contains("zone"));
    }
}
