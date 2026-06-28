//! `cloud.object.*` verb signatures — object-storage bucket lifecycle (R409-T6).
//!
//! Three verbs that cover the bucket plane shared by Cloudflare R2 and
//! Hetzner Object Storage:
//! - `cloud.object.bucket.create` — provision a bucket
//! - `cloud.object.bucket.delete` — tear it down
//! - `cloud.object.bucket.exists` — probe presence without side effects
//!
//! ACL management (`cloud.object.bucket.acl.set` from W144) is not modelled
//! here — Cloudflare R2 exposes public access via custom domains and Workers,
//! not per-bucket ACLs in the S3 sense. A future ticket can add it once a
//! second tier-S object-storage provider (Hetzner) is wired through the envoy
//! framework and the shape can be validated against both.
//!
//! `location_hint` is optional in `CloudObjectBucketCreateInput` so that
//! Cloudflare (global, hint-only) and Hetzner (region-required) can diverge
//! in adapter-side interpretation without changing the wire shape.

use serde::{Deserialize, Serialize};

use super::{InternalVerb, VerbCategory};

// ── cloud.object.bucket.create ────────────────────────────────────────────

/// Marker type for the `cloud.object.bucket.create` verb.
pub struct CloudObjectBucketCreate;

/// Request body for `cloud.object.bucket.create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudObjectBucketCreateInput {
    /// Bucket name. Provider-side naming rules apply (Cloudflare: 3–63 chars,
    /// lowercase alphanumeric + hyphens).
    pub name: String,
    /// Optional location hint. Adapter-specific: Cloudflare accepts CF
    /// location codes (`WEUR`, `ENAM`, `WNAM`, `EEUR`, `APAC`); a Hetzner
    /// adapter would expect region slugs (`fsn1`, `hil`, `ash`). `None`
    /// delegates placement to the provider's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location_hint: Option<String>,
}

/// Response body for `cloud.object.bucket.create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudObjectBucketCreateOutput {
    /// S3-compat base endpoint for this account (e.g.
    /// `https://<account-id>.r2.cloudflarestorage.com` on Cloudflare,
    /// `https://fsn1.your-objectstorage.com` on Hetzner).
    pub endpoint: String,
}

impl InternalVerb for CloudObjectBucketCreate {
    type Input = CloudObjectBucketCreateInput;
    type Output = CloudObjectBucketCreateOutput;
    const ID: &'static str = "cloud.object.bucket.create";
    const CATEGORY: VerbCategory = VerbCategory::Cloud;
}

// ── cloud.object.bucket.delete ────────────────────────────────────────────

/// Marker type for the `cloud.object.bucket.delete` verb.
pub struct CloudObjectBucketDelete;

/// Request body for `cloud.object.bucket.delete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudObjectBucketDeleteInput {
    /// Bucket name to delete. Adapters that require an empty bucket before
    /// deletion (e.g. Hetzner S3) must drain objects themselves; adapters
    /// where the API handles non-empty buckets (Cloudflare R2) can call
    /// the delete endpoint directly.
    pub name: String,
}

/// Response body for `cloud.object.bucket.delete`. Empty — idempotent; `Ok`
/// whether the bucket existed or was already gone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudObjectBucketDeleteOutput {}

impl InternalVerb for CloudObjectBucketDelete {
    type Input = CloudObjectBucketDeleteInput;
    type Output = CloudObjectBucketDeleteOutput;
    const ID: &'static str = "cloud.object.bucket.delete";
    const CATEGORY: VerbCategory = VerbCategory::Cloud;
}

// ── cloud.object.bucket.exists ────────────────────────────────────────────

/// Marker type for the `cloud.object.bucket.exists` verb.
pub struct CloudObjectBucketExists;

/// Request body for `cloud.object.bucket.exists`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudObjectBucketExistsInput {
    /// Bucket name to probe.
    pub name: String,
}

/// Response body for `cloud.object.bucket.exists`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CloudObjectBucketExistsOutput {
    pub exists: bool,
    /// S3-compat endpoint when `exists` is `true`; absent when `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl InternalVerb for CloudObjectBucketExists {
    type Input = CloudObjectBucketExistsInput;
    type Output = CloudObjectBucketExistsOutput;
    const ID: &'static str = "cloud.object.bucket.exists";
    const CATEGORY: VerbCategory = VerbCategory::Cloud;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_ids_match_canonical_namespace() {
        assert_eq!(CloudObjectBucketCreate::ID, "cloud.object.bucket.create");
        assert_eq!(CloudObjectBucketDelete::ID, "cloud.object.bucket.delete");
        assert_eq!(CloudObjectBucketExists::ID, "cloud.object.bucket.exists");
        for id in [
            CloudObjectBucketCreate::ID,
            CloudObjectBucketDelete::ID,
            CloudObjectBucketExists::ID,
        ] {
            assert!(id.starts_with("cloud."), "{id}");
        }
    }

    #[test]
    fn verbs_are_under_cloud_category() {
        assert_eq!(CloudObjectBucketCreate::CATEGORY, VerbCategory::Cloud);
        assert_eq!(CloudObjectBucketDelete::CATEGORY, VerbCategory::Cloud);
        assert_eq!(CloudObjectBucketExists::CATEGORY, VerbCategory::Cloud);
    }

    #[test]
    fn create_input_location_hint_is_optional() {
        let with_hint = CloudObjectBucketCreateInput {
            name: "my-bucket".into(),
            location_hint: Some("WEUR".into()),
        };
        let wire = serde_json::to_string(&with_hint).unwrap();
        let back: CloudObjectBucketCreateInput = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.location_hint.as_deref(), Some("WEUR"));

        let no_hint = r#"{"name":"my-bucket"}"#;
        let parsed: CloudObjectBucketCreateInput = serde_json::from_str(no_hint).unwrap();
        assert!(parsed.location_hint.is_none());
    }

    #[test]
    fn create_input_omits_hint_when_absent() {
        let input = CloudObjectBucketCreateInput {
            name: "b".into(),
            location_hint: None,
        };
        let wire = serde_json::to_value(&input).unwrap();
        assert!(!wire.as_object().unwrap().contains_key("location_hint"));
    }

    #[test]
    fn delete_output_serializes_to_empty_object() {
        let wire = serde_json::to_value(CloudObjectBucketDeleteOutput::default()).unwrap();
        assert_eq!(wire, serde_json::json!({}));
    }

    #[test]
    fn exists_output_omits_endpoint_when_absent() {
        let out = CloudObjectBucketExistsOutput {
            exists: false,
            endpoint: None,
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(wire, serde_json::json!({ "exists": false }));
    }

    #[test]
    fn exists_output_includes_endpoint_when_present() {
        let out = CloudObjectBucketExistsOutput {
            exists: true,
            endpoint: Some("https://acct.r2.cloudflarestorage.com".into()),
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(wire["exists"], true);
        assert!(wire["endpoint"].as_str().is_some());
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn verbs_emit_schemas_via_for_verb() {
        use super::super::VerbDescriptor;

        let create = VerbDescriptor::for_verb::<CloudObjectBucketCreate>();
        assert_eq!(create.id, "cloud.object.bucket.create");
        assert!(create.input_schema.to_string().contains("name"));

        let delete = VerbDescriptor::for_verb::<CloudObjectBucketDelete>();
        assert_eq!(delete.id, "cloud.object.bucket.delete");

        let exists = VerbDescriptor::for_verb::<CloudObjectBucketExists>();
        assert_eq!(exists.id, "cloud.object.bucket.exists");
        assert!(exists.output_schema.to_string().contains("exists"));
    }
}
