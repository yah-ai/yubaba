//! @yah:relay(R409, "Envoy — providers and internal verb catalog (W144)")
//! @yah:at(2026-06-02T20:58:35Z)
//! @yah:status(open)
//! @arch:see(.yah/docs/working/W144-envoy-providers-and-tiering.md)
//!
//!
//!
//!

use anyhow::Result;
use async_trait::async_trait;

// R374-F3: `s3_sign` moved to the `local-driver` crate; yubaba's pond MinIO
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

// R594-F5: `floating_ip.*` envoy verb — raft `ingress_owner` follow-placement
// for sovereign-tier public ingress (W267 §Tier 1). `floating_ip` holds the
// provider-abstracted trait + idempotent reconcile core; the three
// `*_floating_ip` modules are the Hetzner/OVH/Vultr adapters.
pub mod floating_ip;
pub use floating_ip::{
    on_ingress_owner_changed, reconcile_assignment, FloatingIpAssignOutcome, FloatingIpProvider,
    FloatingIpState, FloatingIpTarget,
};

pub mod hetzner_floating_ip;
pub use hetzner_floating_ip::HetznerFloatingIp;

pub mod ovh_floating_ip;
pub use ovh_floating_ip::OvhFloatingIp;

pub mod vultr_floating_ip;
pub use vultr_floating_ip::VultrFloatingIp;

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
    /// expect mesh-only access via yah-yubaba once cloud-init finishes,
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
