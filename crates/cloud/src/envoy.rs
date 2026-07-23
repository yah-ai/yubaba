//! Envoy framework types — `Tier`, `AdapterFlavor`, `VerbCategory`,
//! `InternalVerb`, `VerbDescriptor`.
//!
//! W144 D1–D4 scaffold (R409-T2). Concrete verb structs (e.g. `cloud.vps.create`)
//! land in R409-T3 onward; this module establishes only the type framework
//! so adapters and the host can refer to it before any verb is defined.
//!
//! ## D1 — schemars-derived schemas
//!
//! Verb input/output shapes are Rust types decorated with `serde` +
//! (optionally) `schemars::JsonSchema`. The trait itself is schema-agnostic
//! so the `cloud` crate doesn't pull schemars unconditionally — schema
//! emission lives in [`VerbDescriptor::for_verb`] under the `json-schema`
//! feature, which is what xtask + the verb-registration entrypoint enable.
//!
//! ## D3 — `AdapterFlavor::Synthetic`
//!
//! Orthogonal to [`Tier`]: `LocalDockerProvider` is tier-S with adapter
//! flavor [`AdapterFlavor::Synthetic`]. Tier drives policy (drift, naming,
//! contract-test scope); flavor drives implementation strategy.

use anyhow::Result;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod ci;
pub mod cloud_object;
pub mod cloud_vps;
pub mod dns_record;
pub mod floating_ip;
pub mod messaging;
pub mod observability;
pub mod payments;

/// Provider tier — policy bucket (drift handling, naming rules, contract-test
/// coverage). Cardinality is roughly fixed; new tiers are a deliberate design
/// move, not an extension point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// First-class (≤ 7). Full contract tests, drift→deny, no vendor-named
    /// passthrough. Today: Hetzner, Cloudflare, LocalDocker.
    S,
    /// Semi-automated (≤ 25). OpenAPI- or MCP-bound, drift→warn, vendor-named
    /// passthrough allowed for non-mappable operations.
    A,
    /// Bring-your-own (200+). Vendor surface verbatim under
    /// `mcp__yah__envoy__<id>__<tool>`; no internal-verb mapping; untrusted
    /// by default (see W145).
    B,
}

/// How an adapter is built. Orthogonal to [`Tier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AdapterFlavor {
    /// Hand-written Rust against the vendor's SDK or REST API.
    Native,
    /// Code-generated from the vendor's OpenAPI/Swagger spec.
    OpenApiBound,
    /// Proxy to a vendor-supplied MCP server.
    McpBridged,
    /// Local emulation, no upstream vendor (e.g. `LocalDockerProvider`).
    /// Contract tests apply but drift detection is a no-op — there is no
    /// upstream to drift from.
    Synthetic,
}

/// Verb category — the namespace prefix in `<category>.<verb>`
/// (e.g. `cloud.vps.create`). Marked non-exhaustive: the catalog grows
/// through diligence/refine (see W144 §"What the internal contract covers").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
// `snake_case` (not `lowercase`) so multi-word variants like `FloatingIp`
// serialize with the underscore its `as_str()` / verb-id prefix needs
// (`"floating_ip"`, not `"floatingip"`) — a no-op change for every
// existing single-word variant (Cloud/Dns/Observability/Ci/Payments/
// Messaging serialize identically under both).
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerbCategory {
    /// `cloud.*` — VPS, object storage, networking, firewalls, load balancers.
    Cloud,
    /// `dns.*` — record CRUD, zone listing.
    Dns,
    /// `floating_ip.*` — provider floating/reserved-IP assign + status
    /// (R594-F5: raft `ingress_owner` follow-placement for sovereign-tier
    /// public ingress, W267 §Tier 1).
    FloatingIp,
    /// `observability.*` — alerts, incidents, dashboards.
    Observability,
    /// `ci.*` — pipelines, artifacts (external CI; yah's own scheduler is qed).
    Ci,
    /// `payments.*` — charges, subscriptions, webhook verify (yubaba-side).
    Payments,
    /// `messaging.*` — email, SMS, webhook dispatch.
    Messaging,
}

impl VerbCategory {
    /// Lowercase namespace prefix used in verb ids.
    pub fn as_str(self) -> &'static str {
        match self {
            VerbCategory::Cloud => "cloud",
            VerbCategory::Dns => "dns",
            VerbCategory::FloatingIp => "floating_ip",
            VerbCategory::Observability => "observability",
            VerbCategory::Ci => "ci",
            VerbCategory::Payments => "payments",
            VerbCategory::Messaging => "messaging",
        }
    }
}

/// One internal verb. Implementors are zero-sized marker types (e.g.
/// `pub struct CloudVpsCreate;`); the associated `Input` / `Output` types
/// carry the wire shape.
///
/// Per W144 D1, schemas are derived from the Rust types via `schemars` at
/// registration time — see [`VerbDescriptor::for_verb`]. The trait itself
/// stays schema-agnostic so the crate doesn't pull schemars unconditionally.
///
/// Example (will land in R409-T3):
/// ```ignore
/// pub struct CloudVpsCreate;
///
/// #[derive(serde::Deserialize, schemars::JsonSchema)]
/// pub struct CloudVpsCreateInput { /* ... */ }
///
/// #[derive(serde::Serialize, schemars::JsonSchema)]
/// pub struct CloudVpsCreateOutput { /* ... */ }
///
/// impl InternalVerb for CloudVpsCreate {
///     type Input = CloudVpsCreateInput;
///     type Output = CloudVpsCreateOutput;
///     const ID: &'static str = "cloud.vps.create";
///     const CATEGORY: VerbCategory = VerbCategory::Cloud;
/// }
/// ```
pub trait InternalVerb: 'static {
    /// Wire input type. Typically derives `Deserialize` + `schemars::JsonSchema`.
    type Input: DeserializeOwned + Send + 'static;
    /// Wire output type. Typically derives `Serialize` + `schemars::JsonSchema`.
    type Output: Serialize + Send + 'static;
    /// Stable verb id, e.g. `"cloud.vps.create"`. Must begin with
    /// `Self::CATEGORY.as_str()` followed by `'.'`.
    const ID: &'static str;
    /// Verb category — drives namespace and tool naming.
    const CATEGORY: VerbCategory;
}

/// Type-erased verb descriptor — what an adapter registers with the host.
///
/// D2 puts `supported_verbs: [String]` on the adapter manifest; at load time
/// the host iterates that list, resolves each id back to its `VerbDescriptor`,
/// and registers the (id, input_schema, dispatch_fn) tuple under
/// `mcp__yah__<category>_<verb>` (R409-T9).
#[derive(Debug, Clone)]
pub struct VerbDescriptor {
    /// Stable verb id, e.g. `"cloud.vps.create"`.
    pub id: &'static str,
    /// Verb category. Redundant with the id's prefix but cached for routing.
    pub category: VerbCategory,
    /// JSON Schema for the verb's request body. Derived from the Rust type
    /// via `schemars::schema_for!` when constructed via [`Self::for_verb`].
    pub input_schema: serde_json::Value,
    /// JSON Schema for the verb's response body.
    pub output_schema: serde_json::Value,
}

impl VerbDescriptor {
    /// Build a descriptor with hand-supplied schemas. Useful for adapters
    /// whose verbs are expressed as raw JSON Schema (OpenAPI-bound) rather
    /// than typed Rust structs.
    ///
    /// Debug-asserts that `id` is prefixed with `category.as_str() + "."`.
    pub fn new(
        id: &'static str,
        category: VerbCategory,
        input_schema: serde_json::Value,
        output_schema: serde_json::Value,
    ) -> Self {
        debug_assert!(
            id.starts_with(category.as_str())
                && id.as_bytes().get(category.as_str().len()) == Some(&b'.'),
            "verb id {id:?} must start with {:?} followed by '.'",
            category.as_str()
        );
        Self {
            id,
            category,
            input_schema,
            output_schema,
        }
    }

    /// Build a descriptor from a typed verb by deriving the input/output
    /// schemas via `schemars::schema_for!`. Requires the `json-schema`
    /// feature on the `cloud` crate and `JsonSchema` impls on
    /// `V::Input` / `V::Output`.
    #[cfg(feature = "json-schema")]
    pub fn for_verb<V>() -> Self
    where
        V: InternalVerb,
        V::Input: schemars::JsonSchema,
        V::Output: schemars::JsonSchema,
    {
        let input_schema = serde_json::to_value(schemars::schema_for!(V::Input))
            .expect("schemars schema serializes to Value");
        let output_schema = serde_json::to_value(schemars::schema_for!(V::Output))
            .expect("schemars schema serializes to Value");
        Self::new(V::ID, V::CATEGORY, input_schema, output_schema)
    }
}

/// Provider adapter — what the host registers to expose a vendor's verbs.
///
/// Each adapter declares which verb ids it supports and accepts dispatch
/// calls with raw JSON input/output. The host (R409-T9) is responsible for
/// validating the input against the verb's schemars-derived schema *before*
/// calling [`EnvoyAdapter::dispatch`]; the adapter only needs to handle
/// shape errors caused by adapter-side translation (e.g. a `location` string
/// the adapter doesn't recognise).
///
/// Why untyped JSON at the trait boundary instead of typed associated
/// types: an adapter typically supports several unrelated verbs (Hetzner
/// implements `cloud.vps.create`, `cloud.vps.destroy`, `cloud.vps.status`).
/// A single trait that fans out over verb ids keeps registration uniform —
/// the host stores `Vec<Arc<dyn EnvoyAdapter>>` and routes by id rather
/// than juggling per-verb generic parameters. Adapter-side, the typed
/// translation lives in private methods (see `HetznerEnvoy`) where the
/// JSON is decoded once into `V::Input` and re-encoded from `V::Output`.
#[async_trait]
pub trait EnvoyAdapter: Send + Sync {
    /// Stable provider id, e.g. `"hetzner"`. Used for tool-namespace
    /// composition (`mcp__yah__envoy__hetzner__<verb>`) and for matching
    /// against `.yah/envoys/<id>/`.
    fn id(&self) -> &str;
    /// Tier this adapter is registered at.
    fn tier(&self) -> Tier;
    /// How the adapter is built.
    fn flavor(&self) -> AdapterFlavor;
    /// Verb ids this adapter supports. The host calls this once at
    /// registration time; per W144 D2 the result becomes the adapter's
    /// "supported_verbs" claim in its manifest.
    fn supported_verb_ids(&self) -> Vec<&'static str>;
    /// Dispatch one verb call. `verb_id` is one of the entries in
    /// [`Self::supported_verb_ids`]; `input` is the raw JSON request body.
    /// Returns the verb's response body as JSON.
    ///
    /// Unsupported ids should return `Err` — they are a programmer error
    /// (the host shouldn't dispatch unsupported verbs), not a runtime
    /// vendor failure.
    async fn dispatch(&self, verb_id: &str, input: serde_json::Value) -> Result<serde_json::Value>;
}

/// Every [`VerbDescriptor`] for a verb at least one shipped adapter
/// implements, keyed by [`VerbDescriptor::id`] via the caller.
///
/// R409-T9: the host (`KgToolRegistry`) resolves each adapter's
/// [`EnvoyAdapter::supported_verb_ids`] against this catalog to build the
/// (schema, dispatch) pair it registers per verb — one call site instead of
/// every host needing to know the full concrete verb-type list.
///
/// Deliberately hand-enumerated rather than reflected: W144 D1 wants the
/// Rust structs to be the source of truth and adding a verb to the catalog
/// is a deliberate diligence/refine act (W144 §"What the internal contract
/// covers"), not something that should silently expand via a derive macro.
/// Extend this list when a new verb type lands in one of the `envoy::*`
/// submodules — a verb an adapter claims but that's missing here just
/// doesn't get registered (see the host's skip-with-warning behavior).
#[cfg(feature = "json-schema")]
pub fn known_verb_descriptors() -> Vec<VerbDescriptor> {
    use cloud_object::{CloudObjectBucketCreate, CloudObjectBucketDelete, CloudObjectBucketExists};
    use cloud_vps::{CloudVpsCreate, CloudVpsDestroy, CloudVpsStatus};
    use dns_record::{DnsRecordDelete, DnsRecordUpsert, DnsZoneList};
    use floating_ip::{FloatingIpAssign, FloatingIpStatus};

    vec![
        VerbDescriptor::for_verb::<CloudVpsCreate>(),
        VerbDescriptor::for_verb::<CloudVpsDestroy>(),
        VerbDescriptor::for_verb::<CloudVpsStatus>(),
        VerbDescriptor::for_verb::<CloudObjectBucketCreate>(),
        VerbDescriptor::for_verb::<CloudObjectBucketDelete>(),
        VerbDescriptor::for_verb::<CloudObjectBucketExists>(),
        VerbDescriptor::for_verb::<DnsRecordUpsert>(),
        VerbDescriptor::for_verb::<DnsRecordDelete>(),
        VerbDescriptor::for_verb::<DnsZoneList>(),
        VerbDescriptor::for_verb::<FloatingIpAssign>(),
        VerbDescriptor::for_verb::<FloatingIpStatus>(),
    ]
}

/// Construct the tier-S adapters this process can source live credentials
/// for from ambient env/vault state alone — no camp-scoped config needed.
///
/// R409-T9: this is the "host" half of the classification process W144
/// describes — rather than every call site (the `yah-mcp` binary, tests,
/// future hosts) re-deriving "which providers do we have tokens for," the
/// policy lives once here. A provider with no credentials present is
/// silently absent from the result (possibly empty) rather than an error —
/// same graceful-degradation convention as `cloud.yubaba_status` and
/// friends: the KgToolRegistry ends up simply not offering that provider's
/// verbs rather than every session erroring at startup for lack of a
/// Hetzner token.
///
/// Excluded on purpose:
/// - **Cloudflare** (`dns.*` / `cloud.object.*`) — `CloudflareEnvoy` needs an
///   `account_id`, which today is camp-scoped config
///   (`.yah/infra/providers/cloudflare.toml`), not ambient env/vault state.
///   A caller with a `camp_root` can build one directly
///   (`CloudflareEnvoy::new(token, account_id)`) and register it alongside
///   this function's output via `KgToolRegistry::with_envoy_adapters`.
/// - **LocalDocker** — needs a live containerd socket and sits behind the
///   `local-docker` cargo feature; wiring it in by default would make every
///   consumer of this function require a reachable containerd, which most
///   don't have. Same opt-in path as Cloudflare.
///
/// Both are natural follow-ups once a caller has the extra context to
/// build them; nothing about the verb-tool wiring itself is Hetzner/DO-
/// specific.
pub fn default_adapters() -> Vec<std::sync::Arc<dyn EnvoyAdapter>> {
    let mut adapters: Vec<std::sync::Arc<dyn EnvoyAdapter>> = Vec::new();

    if let Ok(driver) = crate::provider::HetznerDriver::from_default_sources() {
        adapters.push(std::sync::Arc::new(crate::provider::HetznerEnvoy::new(
            driver,
        )));
    }

    if let Ok(Some(token)) = fob::get_or_env("digitalocean-api-token", "DIGITALOCEAN_TOKEN") {
        let client = crate::provider::DigitalOceanClient::new(token);
        adapters.push(std::sync::Arc::new(crate::provider::DigitalOceanEnvoy::new(
            client,
        )));
    }

    adapters
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verb_category_str_matches_serde_repr() {
        for c in [
            VerbCategory::Cloud,
            VerbCategory::Dns,
            VerbCategory::FloatingIp,
            VerbCategory::Observability,
            VerbCategory::Ci,
            VerbCategory::Payments,
            VerbCategory::Messaging,
        ] {
            let serde_str = serde_json::to_string(&c).unwrap();
            let unquoted = serde_str.trim_matches('"');
            assert_eq!(unquoted, c.as_str(), "{c:?}");
        }
    }

    #[test]
    fn tier_round_trips_lowercase() {
        assert_eq!(serde_json::to_string(&Tier::S).unwrap(), "\"s\"");
        assert_eq!(serde_json::to_string(&Tier::A).unwrap(), "\"a\"");
        assert_eq!(serde_json::to_string(&Tier::B).unwrap(), "\"b\"");
        let parsed: Tier = serde_json::from_str("\"s\"").unwrap();
        assert_eq!(parsed, Tier::S);
    }

    #[test]
    fn adapter_flavor_snake_case() {
        assert_eq!(
            serde_json::to_string(&AdapterFlavor::OpenApiBound).unwrap(),
            "\"open_api_bound\""
        );
        assert_eq!(
            serde_json::to_string(&AdapterFlavor::McpBridged).unwrap(),
            "\"mcp_bridged\""
        );
        assert_eq!(
            serde_json::to_string(&AdapterFlavor::Synthetic).unwrap(),
            "\"synthetic\""
        );
    }

    #[test]
    fn descriptor_new_accepts_well_prefixed_id() {
        let d = VerbDescriptor::new(
            "cloud.vps.create",
            VerbCategory::Cloud,
            json!({}),
            json!({}),
        );
        assert_eq!(d.id, "cloud.vps.create");
        assert_eq!(d.category, VerbCategory::Cloud);
    }

    #[test]
    #[should_panic(expected = "must start with")]
    fn descriptor_new_rejects_mismatched_prefix() {
        // Debug-only; cargo test runs debug profile.
        let _ = VerbDescriptor::new(
            "dns.record.upsert",
            VerbCategory::Cloud,
            json!({}),
            json!({}),
        );
    }

    #[test]
    #[should_panic(expected = "must start with")]
    fn descriptor_new_rejects_category_substring_without_dot() {
        // `clouds.x` starts with `cloud` but the next byte is `s`, not `.`.
        let _ = VerbDescriptor::new("clouds.x", VerbCategory::Cloud, json!({}), json!({}));
    }

    // A minimal typed verb to exercise `for_verb` under the json-schema feature.
    #[cfg(feature = "json-schema")]
    mod feature_gated {
        use super::*;

        pub struct PingVerb;

        #[derive(serde::Deserialize, schemars::JsonSchema)]
        #[allow(dead_code)]
        pub struct PingInput {
            pub project: String,
        }

        #[derive(serde::Serialize, schemars::JsonSchema)]
        #[allow(dead_code)]
        pub struct PingOutput {
            pub ok: bool,
        }

        impl InternalVerb for PingVerb {
            type Input = PingInput;
            type Output = PingOutput;
            const ID: &'static str = "cloud.ping";
            const CATEGORY: VerbCategory = VerbCategory::Cloud;
        }

        #[test]
        fn for_verb_derives_schemas() {
            let d = VerbDescriptor::for_verb::<PingVerb>();
            assert_eq!(d.id, "cloud.ping");
            assert_eq!(d.category, VerbCategory::Cloud);
            // The input schema must mention the `project` field.
            assert!(d.input_schema.to_string().contains("project"));
            assert!(d.output_schema.to_string().contains("ok"));
        }
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn known_verb_descriptors_covers_every_implemented_verb() {
        let ids: Vec<&str> = known_verb_descriptors().iter().map(|d| d.id).collect();
        for expected in [
            "cloud.vps.create",
            "cloud.vps.destroy",
            "cloud.vps.status",
            "cloud.object.bucket.create",
            "cloud.object.bucket.delete",
            "cloud.object.bucket.exists",
            "dns.record.upsert",
            "dns.record.delete",
            "dns.zone.list",
            "floating_ip.assign",
            "floating_ip.status",
        ] {
            assert!(ids.contains(&expected), "missing descriptor for {expected}");
        }
        assert_eq!(ids.len(), 11, "add new verbs here as they land: {ids:?}");
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn known_verb_descriptors_all_have_nonempty_schemas() {
        for d in known_verb_descriptors() {
            assert!(d.input_schema.is_object(), "{}: input schema not an object", d.id);
        }
    }

    #[test]
    fn default_adapters_never_panics_regardless_of_ambient_env() {
        // No assertion on count — this runs in a shared process where
        // HETZNER_API_TOKEN / DIGITALOCEAN_TOKEN may or may not be set by
        // other tests or the CI environment. The contract under test is
        // "never panics, never errors" — a credential-less box gets an
        // empty Vec instead of a startup failure (W144's graceful-
        // degradation convention).
        let adapters = default_adapters();
        for adapter in &adapters {
            assert!(!adapter.id().is_empty());
            assert_eq!(adapter.tier(), Tier::S);
        }
    }
}
