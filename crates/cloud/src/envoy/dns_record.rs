//! `dns.*` verb signatures — initial catalog (R409-T6).
//!
//! Three verbs that cover the DNS plane with Cloudflare as the exemplar
//! tier-S provider (W144 §"dns.* — name resolution"):
//!
//! - `dns.record.upsert` — create or update a DNS record in a named zone
//! - `dns.record.delete` — remove matching records from a zone
//! - `dns.zone.list`    — enumerate accessible zones
//!
//! Zone resolution is by apex name (e.g. `"yah.dev"`), not by provider-issued
//! zone ID — the adapter owns the name→id lookup so callers stay
//! provider-agnostic. The `type` field follows the RFC 1035 convention
//! (uppercase strings: `"A"`, `"CNAME"`, `"TXT"`, etc.).

use serde::{Deserialize, Serialize};

use super::{InternalVerb, VerbCategory};

// ── dns.record.upsert ─────────────────────────────────────────────────────

/// Marker type for the `dns.record.upsert` verb.
pub struct DnsRecordUpsert;

/// Request body for `dns.record.upsert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordUpsertInput {
    /// Zone apex name, e.g. `"yah.dev"`. The adapter resolves it to a
    /// provider-issued zone ID.
    pub zone: String,
    /// Fully-qualified record name, e.g. `"yubaba.yah.dev"`. Apex records
    /// may also be passed as `"@"` — adapters normalise as needed.
    pub name: String,
    /// DNS record type (`"A"`, `"AAAA"`, `"CNAME"`, `"TXT"`, `"MX"`, …).
    #[serde(rename = "type")]
    pub record_type: String,
    /// Record value: for CNAME the target hostname; for A/AAAA the IP; for
    /// TXT the verbatim string content.
    pub content: String,
    /// TTL in seconds. `1` means "automatic" (effective TTL chosen by the
    /// provider). Defaults to `1`.
    #[serde(default = "ttl_auto")]
    pub ttl: u32,
    /// Route through Cloudflare's reverse proxy (orange-cloud). Only
    /// meaningful on Cloudflare for A/AAAA/CNAME records; adapters for
    /// other providers should ignore this field. Defaults to `false`.
    #[serde(default)]
    pub proxied: bool,
}

fn ttl_auto() -> u32 {
    1
}

/// Response body for `dns.record.upsert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordUpsertOutput {
    /// Provider-issued record ID. Stable for the lifetime of the record;
    /// can be used in `dns.record.delete` to target a specific record by ID
    /// instead of name+type once that verb shape grows an `id` field.
    pub id: String,
}

impl InternalVerb for DnsRecordUpsert {
    type Input = DnsRecordUpsertInput;
    type Output = DnsRecordUpsertOutput;
    const ID: &'static str = "dns.record.upsert";
    const CATEGORY: VerbCategory = VerbCategory::Dns;
}

// ── dns.record.delete ─────────────────────────────────────────────────────

/// Marker type for the `dns.record.delete` verb.
pub struct DnsRecordDelete;

/// Request body for `dns.record.delete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordDeleteInput {
    /// Zone apex name, e.g. `"yah.dev"`.
    pub zone: String,
    /// Record name to delete, e.g. `"yubaba.yah.dev"`.
    pub name: String,
    /// Filter by record type. When absent, all records matching `name` are
    /// deleted regardless of type. Pass `"CNAME"` to delete only CNAME
    /// records for the name, for example.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub record_type: Option<String>,
}

/// Response body for `dns.record.delete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordDeleteOutput {
    /// Count of records actually deleted. `0` is not an error — the record
    /// may already have been absent (idempotent).
    pub deleted: u32,
}

impl InternalVerb for DnsRecordDelete {
    type Input = DnsRecordDeleteInput;
    type Output = DnsRecordDeleteOutput;
    const ID: &'static str = "dns.record.delete";
    const CATEGORY: VerbCategory = VerbCategory::Dns;
}

// ── dns.zone.list ─────────────────────────────────────────────────────────

/// Marker type for the `dns.zone.list` verb.
pub struct DnsZoneList;

/// Request body for `dns.zone.list`. Empty — zone listing requires no
/// parameters beyond the adapter's credential scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsZoneListInput {}

/// One zone entry in the `dns.zone.list` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsZoneEntry {
    /// Provider-issued zone ID. Opaque; stable within a provider.
    pub id: String,
    /// Zone apex name, e.g. `"yah.dev"`.
    pub name: String,
}

/// Response body for `dns.zone.list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsZoneListOutput {
    pub zones: Vec<DnsZoneEntry>,
}

impl InternalVerb for DnsZoneList {
    type Input = DnsZoneListInput;
    type Output = DnsZoneListOutput;
    const ID: &'static str = "dns.zone.list";
    const CATEGORY: VerbCategory = VerbCategory::Dns;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_ids_match_canonical_namespace() {
        assert_eq!(DnsRecordUpsert::ID, "dns.record.upsert");
        assert_eq!(DnsRecordDelete::ID, "dns.record.delete");
        assert_eq!(DnsZoneList::ID, "dns.zone.list");
        for id in [DnsRecordUpsert::ID, DnsRecordDelete::ID, DnsZoneList::ID] {
            assert!(id.starts_with("dns."), "{id}");
        }
    }

    #[test]
    fn verbs_are_under_dns_category() {
        assert_eq!(DnsRecordUpsert::CATEGORY, VerbCategory::Dns);
        assert_eq!(DnsRecordDelete::CATEGORY, VerbCategory::Dns);
        assert_eq!(DnsZoneList::CATEGORY, VerbCategory::Dns);
    }

    #[test]
    fn upsert_input_defaults_ttl_to_auto_and_proxied_false() {
        let wire = r#"{"zone":"yah.dev","name":"yubaba.yah.dev","type":"CNAME","content":"t.cfargotunnel.com"}"#;
        let parsed: DnsRecordUpsertInput = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.ttl, 1, "default TTL should be 1 (automatic)");
        assert!(!parsed.proxied, "default proxied should be false");
    }

    #[test]
    fn upsert_input_type_renamed_in_wire() {
        let wire = r#"{"zone":"yah.dev","name":"a.yah.dev","type":"A","content":"1.2.3.4","ttl":300,"proxied":true}"#;
        let parsed: DnsRecordUpsertInput = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.record_type, "A");
        assert_eq!(parsed.ttl, 300);
        assert!(parsed.proxied);
        // Verify the Rust field serializes back as "type".
        let back = serde_json::to_value(&parsed).unwrap();
        assert!(back.get("type").is_some(), "should serialize as 'type'");
        assert!(
            back.get("record_type").is_none(),
            "should not serialize as 'record_type'"
        );
    }

    #[test]
    fn delete_input_type_optional() {
        let with_type = r#"{"zone":"yah.dev","name":"old.yah.dev","type":"CNAME"}"#;
        let parsed: DnsRecordDeleteInput = serde_json::from_str(with_type).unwrap();
        assert_eq!(parsed.record_type.as_deref(), Some("CNAME"));

        let no_type = r#"{"zone":"yah.dev","name":"old.yah.dev"}"#;
        let parsed: DnsRecordDeleteInput = serde_json::from_str(no_type).unwrap();
        assert!(parsed.record_type.is_none());
    }

    #[test]
    fn delete_input_omits_type_when_absent() {
        let input = DnsRecordDeleteInput {
            zone: "z".into(),
            name: "n".into(),
            record_type: None,
        };
        let wire = serde_json::to_value(&input).unwrap();
        assert!(!wire.as_object().unwrap().contains_key("type"));
    }

    #[test]
    fn delete_output_zero_is_not_an_error() {
        let out = DnsRecordDeleteOutput { deleted: 0 };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(wire["deleted"], 0);
    }

    #[test]
    fn zone_list_input_serializes_to_empty_object() {
        let wire = serde_json::to_value(DnsZoneListInput::default()).unwrap();
        assert_eq!(wire, serde_json::json!({}));
    }

    #[test]
    fn zone_list_output_round_trips() {
        let out = DnsZoneListOutput {
            zones: vec![
                DnsZoneEntry {
                    id: "z1".into(),
                    name: "yah.dev".into(),
                },
                DnsZoneEntry {
                    id: "z2".into(),
                    name: "noisetable.com".into(),
                },
            ],
        };
        let wire = serde_json::to_string(&out).unwrap();
        let back: DnsZoneListOutput = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.zones.len(), 2);
        assert_eq!(back.zones[0].name, "yah.dev");
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn verbs_emit_schemas_via_for_verb() {
        use super::super::VerbDescriptor;

        let upsert = VerbDescriptor::for_verb::<DnsRecordUpsert>();
        assert_eq!(upsert.id, "dns.record.upsert");
        assert!(upsert.input_schema.to_string().contains("content"));

        let delete = VerbDescriptor::for_verb::<DnsRecordDelete>();
        assert_eq!(delete.id, "dns.record.delete");
        assert!(delete.output_schema.to_string().contains("deleted"));

        let list = VerbDescriptor::for_verb::<DnsZoneList>();
        assert_eq!(list.id, "dns.zone.list");
        assert!(list.output_schema.to_string().contains("zones"));
    }
}
