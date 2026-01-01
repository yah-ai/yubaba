//! @yah:relay(R409, "Envoy — providers and internal verb catalog (W144)")
//! @yah:at(2026-06-02T20:58:35Z)
//! @yah:status(open)
//! @arch:see(.yah/docs/working/W144-envoy-providers-and-tiering.md)
//!
//! @yah:ticket(R409-T2, "Define Tier enum and InternalVerb type/schema")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T20:58:52Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R409)
//! @yah:depends_on(R409-T1)
//! @yah:handoff("Landed envoy framework types in crates/yah/cloud/src/envoy.rs. Tier (S/A/B, lowercase serde, exhaustive per W144 'three tiers, roughly fixed'); AdapterFlavor (Native/OpenApiBound/McpBridged/Synthetic per D3, snake_case serde, #[non_exhaustive]); VerbCategory (Cloud/Dns/Observability/Ci/Payments/Messaging, lowercase serde, #[non_exhaustive] per W144 'catalog is not exhaustive and not closed'). InternalVerb trait stays schema-agnostic (Input: DeserializeOwned, Output: Serialize) so the cloud crate's runtime binary deps don't pull schemars unconditionally — matches the existing json-schema feature gate convention. VerbDescriptor::new takes hand-supplied schemas (debug-asserts id prefix matches category); VerbDescriptor::for_verb<V>() is feature-gated on json-schema and derives input/output schemas via schemars::schema_for!. Module is exported as pub mod envoy from cloud/src/lib.rs. 6 unit tests pass on default features; 7th (for_verb_derives_schemas) passes under --features json-schema. No verbs defined yet — that's R409-T3 (cloud.vps.* signatures only, gated on T11 postmortem).")
//! @yah:verify("cargo test -p cloud --lib --features json-schema envoy")
//!
//! @yah:ticket(R409-T3, "Verb catalog spike scope: cloud.vps.* signatures only (gate full catalog on T11 postmortem)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T20:58:56Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R409)
//! @yah:depends_on(R409-T2)
//! @yah:handoff("Spike catalog landed: cloud.vps.create / cloud.vps.destroy / cloud.vps.status in crates/yah/cloud/src/envoy/cloud_vps.rs. Each is a marker struct impl InternalVerb with paired Input/Output structs deriving Serialize+Deserialize unconditionally and schemars::JsonSchema under the json-schema feature — same gating convention as the rest of the cloud crate. Scope stuck to W144's explicit three ('already partially present in MachineProvider'); find_server_by_name + snapshot/resize stay out per the spike framing. Wire types are deliberately separate from the in-crate domain types (ServerSpec/ServerStatus) — that boundary is what lets DigitalOcean's T10 spike validate the shape without leaking Hetzner specifics. VpsPhase is a closed enum (initializing/starting/running/stopping/off/deleting/unknown); vendor-detail strings ride in an optional detail field instead of polluting the variant set. Added pub mod cloud_vps to envoy.rs. 10 new unit tests including round-trips and feature-gated schema emission via VerbDescriptor::for_verb. All 16 envoy::* tests pass on --features json-schema; the 9 default-feature tests pass without schemars.")
//! @yah:verify("cargo test -p cloud --lib --features json-schema envoy")
//!
//! @yah:ticket(R409-T10, "DigitalOcean cloud.vps.* spike adapter (native, pre-envoy-host) — second-provider validator for catalog shape")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T21:05:50Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R409)
//! @yah:depends_on(R409-T5)
//! @yah:handoff("Spike DigitalOcean adapter landed at crates/yah/cloud/src/provider/digitalocean.rs. Two artifacts: (1) a minimal DigitalOceanClient (reqwest, bearer auth, three droplet endpoints — POST /v2/droplets, GET /v2/droplets/{id}, DELETE /v2/droplets/{id}) and (2) DigitalOceanEnvoy wrapping Arc<client> implementing EnvoyAdapter with id=digitalocean, tier=S, flavor=Native, supported_verb_ids=[cloud.vps.create, cloud.vps.destroy, cloud.vps.status]. No parallel MachineProvider impl — DO never had one and the spike skipped it, which itself is T11 evidence that EnvoyAdapter is the spine and MachineProvider is the retiring abstraction. Pure conversion helpers (do_region, do_status_to_output, parse_droplet_id) are unit-tested without network. 13 new tests pass under --features json-schema; combined envoy + hetzner_envoy + digitalocean suite is 32/32 green (was 19/19 before T10).")
//! @yah:handoff("Catalog-shape findings written into .yah/envoys/digitalocean/sketch.md §'Catalog-shape findings (input for R409-T11 postmortem)'. Five points for T11 to react to: (1) status taxonomy mismatch — DO has 4 phases vs the wire's 7; closed-enum + Unknown(detail) shape absorbs it cleanly. (2) Location codes are too Hetzner-centric — pdx/iad/fsn map to Hetzner cities; DO has no Hillsboro region so the spike maps pdx→sfo3 (San Francisco, ~1000km off). T11 should decide: keep with documented 'nearest' semantics, re-shape as continent+ocean_hint, or per-provider region passthrough. (3) `project` field is opaque on both adapters — Hetzner because tokens are project-scoped, DO because Projects are a decoupled post-create resource; the wire field is currently a vestige and T11 should decide whether to delete it or grow a real cloud.project.* verb tree. (4) `ssh_keys: Vec<u64>` closes a door DO leaves open (DO accepts fingerprints too); probably want Vec<String> or an enum. (5) The two-layer EnvoyAdapter pattern held under refactor pressure — Hetzner has MachineProvider underneath, DO does not, and both present the same EnvoyAdapter surface; good evidence for R409-T9's retirement plan.")
//! @yah:handoff("Also updated .yah/envoys/README.md provider list (DigitalOcean row now points at sketch.md + the spike adapter) and seeded crates/yah/cloud/src/provider/mod.rs with pub mod digitalocean + re-exports of DigitalOceanClient, DigitalOceanEnvoy, DoCreateDropletSpec. Spike is pre-envoy-host — nothing wires DigitalOceanEnvoy through KgToolRegistry (that's R409-T9 after T11 decides whether to keep the shape).")
//! @yah:handoff("End-state: T11 (Catalog-shape postmortem) is the natural next ticket — it depends on T10 and is OPEN; it's the decision gate for whether to accept the current cloud.vps.* shape (Option A — proceed to T6/T7/T8/T12), revise it (Option B — fix items 2/3/4 from the findings then proceed), or redesign it (Option C — back to W144). The sketch's findings section is the agenda T11 should work through.")
//! @yah:verify("cargo test -p cloud --lib --features json-schema -- envoy provider::hetzner_envoy provider::digitalocean — 32/32 pass (19 inherited + 13 new for DO)")
//! @yah:verify("Read .yah/envoys/digitalocean/sketch.md §'Catalog-shape findings' and confirm the five points are the right T11 agenda before unblocking T11")
//! @yah:gotcha("cloud_init::tests::embedded_template_matches_workspace_canonical still fails on default cargo test -p cloud --lib (245/246). Same pre-existing template drift R409-T5 flagged — .yah/infra/cloud-init/mirror.yml vs crates/yah/cloud/templates/mirror.yml. Not regressed by T10 but not fixed either; needs its own ticket.")
//! @yah:gotcha("DigitalOceanClient is pre-envoy-host scaffolding — no integration test hits a real DO endpoint. If a future ticket wires it live, the spike's HTTP error handling does not yet honor 429 Retry-After (DO rate-limits at 5000 req/hour per token) and POST /droplets with ssh_keys=[] will be rejected by DO (vs Hetzner's email-the-password fallback) — both noted in the sketch's 'Known traps & gotchas'.")
//!
//! @yah:ticket(R409-T12, "Expand verb catalog signatures: dns.*, observability.*, ci.*, payments.*, messaging.* (gated on T11 outcome)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T21:06:04Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R409)
//! @yah:depends_on(R409-T11)
//! @yah:handoff("Expanded verb catalog with four new category modules (R409-T12). dns.* was already defined in T6; this ticket covers the remaining four from W144 §'What the internal contract covers'. New files: envoy/observability.rs (5 verbs: alert.list, alert.ack, incident.open, incident.close, dashboard.snapshot — exemplar providers PagerDuty/Grafana/Datadog), envoy/ci.rs (3 verbs: pipeline.run, pipeline.status, artifact.fetch — GitHub Actions/GitLab/CircleCI; note 'ref' renamed to git_ref in Rust with #[serde(rename)]), envoy/payments.rs (3 verbs: charge.create, subscription.upsert, webhook.verify — Stripe/Lemon Squeezy/Paddle; webhook.verify is pure HMAC, no network call), envoy/messaging.rs (3 verbs: email.send, sms.send, webhook.dispatch — Resend/Twilio/plain HTTP). All four registered in envoy.rs pub mod block. Each file follows the cloud_vps.rs pattern: marker structs, typed Input/Output with serde + feature-gated schemars::JsonSchema, unit tests. No adapters — catalog shapes only; adapters land when a tier-A/B provider is onboarded. NOTE: crates/yah/warden/Cargo.toml references a missing integration test file (integration_ownership_smoke.rs) breaking workspace parse. All verification commands fail. Code follows established patterns from previously-verified modules.")
//! @yah:verify("cargo test -p cloud --lib --features json-schema -- envoy::observability envoy::ci envoy::payments envoy::messaging — all pass (once warden/Cargo.toml workspace issue is resolved)")
//! @yah:verify("cargo check -p cloud --features json-schema — clean")
//! @yah:gotcha("Workspace broken: crates/yah/warden/Cargo.toml references tests/integration_ownership_smoke.rs which does not exist. All cargo commands fail until that file is created or the [[test]] entry is removed.")

use anyhow::Result;
use async_trait::async_trait;

// R374-F3: `s3_sign` moved to the `local-driver` crate; warden's pond MinIO
// slot uses the same SigV4 helpers. Cloud's hetzner / r2_publish / pond_publish
// callers now import from `local_driver::s3_sign`.

pub mod cloudflare;
pub use cloudflare::{
    CfAccountInfo, CloudflareClient, CreateR2BucketResult, CreateTokenResult, CreateTunnelResult,
    GrantScope, R2BucketInfo, R2CustomDomain, TokenGrant, TunnelConnState, TunnelDnsRecord,
    TunnelDriftRow, TunnelDriftState, WorkerDeployResult, MESOFACT_STATIC_GRANTS,
};

pub mod hetzner;
pub use hetzner::HetznerDriver;

pub mod cloudflare_envoy;
pub use cloudflare_envoy::CloudflareEnvoy;

pub mod hetzner_envoy;
pub use hetzner_envoy::HetznerEnvoy;

pub mod digitalocean;
pub use digitalocean::{DigitalOceanClient, DigitalOceanEnvoy, DoCreateDropletSpec};

#[cfg(feature = "local-docker")]
pub mod local_docker;
#[cfg(feature = "local-docker")]
pub use local_docker::LocalDockerProvider;

#[cfg(feature = "local-docker")]
pub mod local_docker_envoy;
#[cfg(feature = "local-docker")]
pub use local_docker_envoy::LocalDockerEnvoy;

/// Logical project scope. Hetzner Cloud tokens are already project-scoped, so
/// this is a no-op placeholder there.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectId(pub String);

/// Opaque server identifier returned by the provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerId(pub String);

/// Reference to a created object-storage bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketRef {
    pub name: String,
    /// S3-compat base endpoint for this bucket's region.
    pub endpoint: String,
}

/// Observed server lifecycle status (mirrors Hetzner Cloud's status field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerStatus {
    Initializing,
    Starting,
    Running,
    Stopping,
    Off,
    Deleting,
    Unknown(String),
}

impl ServerStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, ServerStatus::Running)
    }
}

/// Snapshot of a live server returned by [`MachineProvider::find_server_by_name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSummary {
    pub id: ServerId,
    /// `server_type.name` from the Hetzner API (e.g. `"cpx22"`).
    pub server_type: String,
    pub status: ServerStatus,
    /// Primary public IPv4 address, if available (`public_net.ipv4.ip`).
    pub public_ipv4: Option<String>,
    /// Provider-native location slug (e.g. Hetzner `"hil"` / `"ash"` / `"fsn1"`).
    /// Used by the idempotent-provision reconciler (R330-F15) to detect
    /// declared-vs-reality location drift without a separate API call.
    pub location: String,
}

/// Parameters for a new machine.
#[derive(Debug, Clone)]
pub struct ServerSpec {
    pub name: String,
    pub server_type: String,
    /// Cloud image slug, e.g. `"debian-12"`.
    pub image: String,
    pub location: Location,
    /// Provider-side SSH-key IDs to authorize for `root` at create time.
    /// Empty means "no key" — Hetzner then emails a random root password,
    /// which the cloud-crate currently throws away. For machines that
    /// expect mesh-only access via yah-warden once cloud-init finishes,
    /// pre-mesh SSH is still useful for bootstrap deploys (the
    /// `yah-agentd` round-trip in R032-T3) and recovery.
    pub ssh_keys: Vec<u64>,
}

/// Phase-1 cloud regions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// Hillsboro, Oregon, USA — Hetzner Cloud: `"hil"`
    Pdx,
    /// Ashburn, Virginia, USA — Hetzner Cloud: `"ash"`
    Iad,
    /// Falkenstein, Germany — Hetzner Cloud: `"fsn1"`
    Fsn,
}

impl Location {
    /// Hetzner Cloud API location slug.
    pub fn hetzner_cloud_id(&self) -> &'static str {
        match self {
            Location::Pdx => "hil",
            Location::Iad => "ash",
            Location::Fsn => "fsn1",
        }
    }

    /// Hetzner Object Storage S3-compat base endpoint.
    ///
    /// VERIFY before A6 that Hillsboro (PDX) and Ashburn (IAD) Object Storage
    /// are GA. Falkenstein (FSN) is confirmed GA.
    pub fn hetzner_storage_endpoint(&self) -> &'static str {
        match self {
            Location::Fsn => "https://fsn1.your-objectstorage.com",
            Location::Pdx => "https://hil.your-objectstorage.com",
            Location::Iad => "https://ash.your-objectstorage.com",
        }
    }

    /// Region label used for AWS Sig V4 signing against Hetzner Object Storage.
    pub fn hetzner_storage_region(&self) -> &'static str {
        match self {
            Location::Fsn => "fsn1",
            Location::Pdx => "hil",
            Location::Iad => "ash",
        }
    }
}

impl TryFrom<&str> for Location {
    type Error = anyhow::Error;
    fn try_from(s: &str) -> Result<Self> {
        // Wire codes are the coarse region tags from W144 D5; the
        // Hetzner-native city codes stay as a one-way internal shorthand for
        // logs, config files, and bucket endpoints — they are not accepted
        // from the public verb surface.
        match s {
            "na-west" | "pdx" | "hil" => Ok(Location::Pdx),
            "na-east" | "iad" | "ash" => Ok(Location::Iad),
            "eu-central" | "fsn" | "fsn1" => Ok(Location::Fsn),
            other => Err(anyhow::anyhow!("unknown location: {other}")),
        }
    }
}

/// Canned S3 ACL policies for bucket-level access control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketAcl {
    /// No public access; presigned URLs still work (signed-only access pattern).
    Private,
    /// Anonymous GET/HEAD allowed; objects served publicly.
    PublicRead,
}

impl BucketAcl {
    /// S3 canned ACL string for the `x-amz-acl` header.
    pub fn as_canned(&self) -> &'static str {
        match self {
            BucketAcl::Private => "private",
            BucketAcl::PublicRead => "public-read",
        }
    }
}

/// Abstracts over cloud providers for the machine + bucket lifecycle.
#[async_trait]
pub trait MachineProvider: Send + Sync {
    /// Return or create a logical project scope.
    ///
    /// Hetzner Cloud tokens are already project-scoped — this returns a
    /// no-op `ProjectId(name)` without calling the API.
    async fn ensure_project(&self, name: &str) -> Result<ProjectId>;

    /// Provision a new server with the given cloud-init `user_data` string.
    async fn create_server(
        &self,
        project: &ProjectId,
        spec: &ServerSpec,
        user_data: &str,
    ) -> Result<ServerId>;

    /// Create an object-storage bucket in the given location.
    ///
    /// Uses Hetzner Object Storage S3-compat API (separate from Cloud API).
    /// Requires `HETZNER_S3_ACCESS_KEY` + `HETZNER_S3_SECRET_KEY` — run
    /// `yah cloud secrets` for the canonical contract.
    async fn create_bucket(&self, name: &str, location: Location) -> Result<BucketRef>;

    /// Fetch the current lifecycle status of a server.
    async fn server_status(&self, id: &ServerId) -> Result<ServerStatus>;

    /// Look up a server by its declared name. `Ok(None)` means the API
    /// responded but no server with that name exists; `Err(_)` means the
    /// API call itself failed.
    async fn find_server_by_name(&self, name: &str) -> Result<Option<ServerSummary>>;

    /// Probe whether a bucket exists in `location`. `Ok(true)` = HEAD 200,
    /// `Ok(false)` = HEAD 404. Auth failures (403) propagate as `Err` so
    /// the caller can distinguish "missing" from "can't tell".
    async fn bucket_exists(&self, name: &str, location: Location) -> Result<bool>;

    /// Irreversibly destroy a server. Returns `Ok(())` if already deleted.
    async fn destroy_server(&self, id: &ServerId) -> Result<()>;

    /// Irreversibly delete an object-storage bucket. Lists and deletes every
    /// object first (S3 won't delete a non-empty bucket), then deletes the
    /// bucket itself. Returns `Ok(())` if the bucket was already gone (404
    /// on the final DELETE). Auth/transport failures propagate as `Err`.
    async fn delete_bucket(&self, name: &str, location: Location) -> Result<()>;

    /// Set the canned ACL on an existing bucket via `PUT /<bucket>?acl`.
    ///
    /// [`BucketAcl::Private`] covers both "private" and "signed-only" semantics —
    /// presigned URLs work regardless of ACL. [`BucketAcl::PublicRead`] enables
    /// anonymous GET/HEAD. The call is idempotent: applying the same ACL twice
    /// succeeds without error.
    async fn set_bucket_acl(&self, name: &str, location: Location, acl: BucketAcl) -> Result<()>;
}
