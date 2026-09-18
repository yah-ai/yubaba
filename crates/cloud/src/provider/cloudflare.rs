//! Cloudflare management API client — accounts, tunnels, R2 buckets, DNS.
//!
//! Shared by the desktop Tauri commands, the CLI, and the reconciler.
//! Callers resolve the API token themselves (keychain, env, vault) and pass
//! it to [`CloudflareClient::new`]; this module never reads credentials.
//!
//! Two distinct API surfaces:
//! - **Management API** (this module) — accounts, R2-bucket CRUD, tunnels, DNS, cache purge.
//! - **R2 object publish** — S3 SigV4, lives in `reconciler::r2_publish` and
//!   reuses the existing `s3_sign` helper. Not part of this module.
//!
//! @yah:ticket(R320-F12, "yah cloud: mint scoped Cloudflare API token from a policy template (one-command onboarding for a new CF account)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T14:57:46Z)
//! @yah:status(review)
//! @yah:parent(R320)
//! @arch:see(.yah/docs/working/W074-cloudflare-infra-provider.md)
//! @yah:next("Resolve permission-group UUIDs at runtime from GET /accounts/{id}/tokens/permission_groups — CF references groups by ID not name; the policy template stores names and resolves to IDs at create time")
//! @yah:next("Build the minimal mesofact-static policy: account-scoped block (Account Settings:Read + Workers R2 Storage:Edit) + zone-scoped block (Zone:Read + Transform Rules:Edit + Cache Purge). Keep scope blocks separate — mixing account- and zone-scoped groups in one block fails token-create validation")
//! @yah:next("POST /accounts/{id}/tokens to create an ACCOUNT-OWNED token (DECIDED by user: survives the creating user, correct for a shared tool credential). Print the secret once and offer to store it in the cloudflare-api-token keystore slot")
//! @yah:next("Expose as 'yah cloud cf token create --account <id> --zone <name>' so a fresh CF account is one command. The policy template is the checked-in artifact CF won't let you save dashboard-side")
//! @yah:gotcha("Bootstrap credential needs ONLY API Tokens:Edit — VALIDATED live: the created token is bounded by the account's own access, not the bootstrap token's perms, so a minimal bootstrap suffices. Brand-new account still needs one such token minted manually (or Global Key) once.")
//! @yah:gotcha("TRAP — two Transform Rules groups: 'Transform Rules Write' (ae16e88b…) is ACCOUNT-scoped = WRONG. upsert_index_rewrite hits /zones/{id}/rulesets so it needs ZONE-scoped 'Zone Transform Rules Write'. Zone Read + Cache Purge are also zone-scoped, not account-scoped.")
//! @yah:gotcha("Permission-group IDs (global constants, validated 2026-05-26): acct-scoped Account Settings Read=c1fde68c7bcc44588cbb6ddbc16d6480, Workers R2 Storage Write=bf7481a1826f439697cb59a20b22293e; zone-scoped Zone Read=c8fed203ed3043cba015a93ad1616f1f, Zone Transform Rules Write=0ac90a90249747bca6b047d97f0803e9, Cache Purge=e17beae8b8cb423a99b1730f21238bed")
//! @yah:gotcha("account-owned token verify = GET /accounts/{id}/tokens/verify; /user/tokens/verify returns success:false for account-owned tokens (NOT a failure — seen in live test)")
//! @yah:assumes("VALIDATED live 2026-05-26: POST /accounts/{id}/tokens with the 2-block policy created 'yah-mesofact-static-yahdev' which lists R2 buckets successfully. R2 object upload still uses SEPARATE S3 keys (SigV4), not this management token.")
//! @yah:handoff("Implemented + verified live end-to-end. CloudflareClient gained create_account_token (cloudflare.rs) + list_permission_group_ids; MESOFACT_STATIC_GRANTS const carries the 5 validated permission-group IDs (account: Account Settings Read, Workers R2 Storage Write; zone: Zone Read, Zone Transform Rules Write, Cache Purge) with group-name→id resolved against the live catalog at create time, baked-in IDs as fallback. Pure helpers build_token_body/resolve_grant_id split account- vs zone-scoped policy blocks (2 unit tests). CLI: 'yah cloud cf token create --zone <name> [--account <id>] [--store-slot <slot>] [--name <n>] [--bootstrap-slot <slot>]' in cloud.rs handle_cf_token_create — resolves account from --account or .yah/infra/providers/cloudflare.toml, resolves zone name→id, mints account-owned token via POST /accounts/{id}/tokens, stores to keystore (fail-fast on occupied slot, BEFORE minting) or prints once. Bootstrap defaults to cloudflare-api-token slot / $CLOUDFLARE_API_TOKEN.")
//! @yah:next("Follow-ups (not in scope): 'yah cloud cf token revoke <id>' (DELETE endpoint already proven), and broader grant presets beyond MESOFACT_STATIC_GRANTS (e.g. + Tunnel:Read/DNS:Read for the Infra panel)")
//! @yah:verify("cargo test -p cloud --lib — 207 passed (incl. token_body_splits_scopes_and_resolves_ids, token_body_omits_empty_scope_block)")
//! @yah:verify("Live E2E 2026-05-26: 'yah cloud cf token create --zone yah.dev --store-slot cf-clitest' minted account-owned token, minted token listed R2 buckets successfully, then DELETE /accounts/{id}/tokens/{id} revoked it cleanly")
//!
//!
//! @yah:ticket(R324-F5, "Tunnel connection status + uptime in the Tunnels table")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T15:33:48Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R324)
//! @yah:handoff("Tunnel connection state fully wired end-to-end. Rust: TunnelConnState enum (Active/Inactive/Degraded/Unknown) added to cloud crate; CfTunnel wire struct extended with status + conns_active_at; TunnelMeta private struct carries enriched data; list_tunnels_meta() fetches status in one pass; TunnelDriftRow gained conn_state + conn_since (RFC3339 optional); tunnel_dns_drift() refactored to walk accounts→tunnels_meta→configs in a single list_accounts pass instead of calling tunnel_dns_records() separately (avoids duplicate API round-trip). Re-exported TunnelConnState through provider/mod.rs + cloud/src/lib.rs + desktop cloudflare.rs. TS: TunnelConnState type + connState/connSince on TunnelDriftRow in types.ts. UI: DriftPill now shows 'connected · <uptime>' (pulsing forest dot) for synced+active, 'inactive' neutral pill for synced+inactive, 'degraded' warn for synced+degraded. fmtUptime() formats ISO → '<1m'/'45m'/'12h'/'3d'. TunnelsSection right label changed to 'N active' (or 'N active · M drift'). collectCfSlots test drift() fixture updated with connState: 'unknown'.")
//! @yah:verify("cargo test -p cloud --lib cloudflare — 15 passed (incl. 8 drift unit tests)")
//! @yah:verify("cargo check -p desktop — clean (TunnelConnState re-exported + TunnelDriftRow extended)")
//! @yah:verify("cd packages/yah/ui && bun test src/components/infra/CloudflarePanel.collectCfSlots.test.ts — 8 pass")
//! @yah:verify("cd packages/yah/ui && bun run typecheck — no errors in infra/ or env/ (pre-existing failures elsewhere unchanged)")
//!
//! @yah:ticket(R324-F6, "R2 bucket size + object count + region in Accounts section")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T15:33:49Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R324)
//! @yah:next("Extend R2BucketInfo + list_r2_buckets with size/object-count/region; design AccountBlock shows '412 MB · 142 obj'. Needs extra R2 (or S3 list) calls per bucket.")
//! @yah:next("Render the new fields in CloudflarePanel AccountBlock bucket rows.")
//! @yah:handoff("Added location + creation_date to R2BucketInfo (Rust struct + TS interface). Both fields come from the existing GET /accounts/{id}/r2/buckets list call — no extra round-trips. fmtR2Location() maps CF location codes (WEUR/EEUR/WNAM/ENAM/APAC) to short labels. AccountBlock bucket cards now show the region badge on the right when present. Note: bucket size + object count are not available from the CF management API without per-bucket S3 calls (paginated ListObjectsV2 + S3 credentials); deferred to a future ticket.")
//! @yah:verify("cargo check -p cloud -p desktop — clean (R2BucketInfo extended, deserialized from BucketEntry, re-exported unchanged)")
//! @yah:verify("cd packages/yah/ui && bun run typecheck — no new errors in infra/ or env/")
//!
//!
//! @yah:ticket(R419-F1, "Extend deploy_worker_script for r2_bucket bindings")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T08:02:38Z)
//! @yah:status(review)
//! @yah:parent(R419)
//! @yah:handoff("Widened deploy_worker_script + build_worker_multipart to typed bindings. New pub enum WorkerBinding<'a> { PlainText { name, text }, R2Bucket { name, bucket_name } } encodes both shapes; multipart metadata.bindings now emits the matching CF wire JSON. Single existing caller (mesofact_static.rs:505) maps its (String,String) plain_text vec into WorkerBinding::PlainText refs — runtime behavior unchanged. F2's CloudflareWorkerReconciler now has the surface it needs: pass [WorkerBinding::R2Bucket { name: binding_name_from_workload_toml, bucket_name: from_mirror_providers_cache }, ...].")
//! @yah:verify("cargo check -p cloud --lib — clean")
//! @yah:verify("cargo test -p cloud --lib provider::cloudflare — 12 passed, incl. multipart_includes_r2_bucket_binding_metadata + multipart_mixes_plain_text_and_r2_bindings")
//! @yah:next("F2 pickup: bind via WorkerBinding::R2Bucket { name: <workload.toml [[bindings]].name>, bucket_name: <mirror providers.cache.bucket> } after fail-fast on workload<->mirror binding-name drift.")
//!
//! @yah:ticket(R893-T22, "MESOFACT_STATIC_GRANTS gains account + zone Analytics Read, so the re-minted token can serve R893-F8")
//! @yah:at(2026-09-12T22:27:26Z)
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P4)
//! @yah:parent(R893)
//! @yah:next("Tier: Cleric — a small, well-specified addition to one const array, but the permission-group ids must be resolved against the live Cloudflare catalog rather than guessed, and three stale prose enumerations need correcting in the same pass.")
//! @yah:handoff("Added Account Analytics Read (account, id b89a480218d04ceb98b4fe57ca29dc1f) and Analytics Read (zone, id 9c88f9c5bce24ce7af9a958ba9c504db) to MESOFACT_STATIC_GRANTS in oss/yubaba/crates/cloud/src/provider/cloudflare.rs (now 11 grants: 4 account + 7 zone). Both group names + ids resolved live 2026-09-12 via GET /accounts/3948dc292e724e71b0deefde0ea95999/tokens/permission_groups using the cloudflare-legacy-yah keystore slot (the token the operator granted Analytics on) — never printed, only piped through curl+python filtering.")
//! @yah:handoff("Updated the three stale enumerations named in the ticket: app/yah/cli/src/cloud.rs:1212-1218 doc comment now lists Account Analytics:Read + Analytics:Read; .yah/infra/providers/cloudflare.toml:37-52 gained a third dated paragraph ('eleven total') rather than editing the historical seven/nine paragraphs in place; oss/yah-base/crates/keys/src/spec.rs:695 now says 'eleven' and its cloudflare.toml consumer line reference corrected from :47 to :53.")
//! @yah:handoff("No mint performed — scope fence respected. cargo test -p yah-cloud --lib: 1205 passed both before and after (baseline established fresh, same run). cargo check -p desktop --lib, -p yah --lib, -p fob --lib all clean (pre-existing warnings only, no new errors).")
//! @yah:verify("cd oss/yubaba && cargo test -p yah-cloud --lib — 1205 passed, 0 failed (matches pre-change baseline)")
//! @yah:verify("cargo check -p desktop --lib — clean")
//! @yah:verify("cargo check -p yah --lib -p fob --lib — clean")
//! @yah:assumes("cloudflare-legacy-yah keystore slot is the same bootstrap token the operator granted Analytics on 2026-09-12 per the ticket description; its successful GET on /tokens/permission_groups (API Tokens:Read/Edit scope) is what proved that grant reached the account, not an independent verification of the Analytics grant itself.")
//! @yah:verify("Leader re-ran the gate independently: `cd oss/yubaba && cargo test -p yah-cloud --lib` = 1205 passed / 0 failed / 4 ignored, identical to the leader's own pre-change baseline measured before dispatch. The camp build rail reported \"input closure unchanged across the whole run: no skew\" on that baseline, so both numbers describe the same tree. Leader also read the grants array directly: `Account Analytics Read` (account scope) and `Analytics Read` (zone scope) are present with the live-resolved ids, and the doc comment at cloudflare.rs:382-388 records that the two groups are genuinely distinct and were validated against the catalog rather than inferred from their names.")

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

const CF_API: &str = "https://api.cloudflare.com/client/v4";

// ---------- internal wire types ----------

#[derive(Deserialize)]
struct CfPage<T> {
    success: bool,
    result: Option<Vec<T>>,
    errors: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct CfSingle<T> {
    success: bool,
    result: Option<T>,
    errors: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct CfTunnel {
    id: String,
    name: String,
    /// Cloudflare's live status: `"active"` | `"inactive"` | `"degraded"` | `"unknown"`.
    #[serde(default)]
    status: Option<String>,
    /// RFC 3339 timestamp — when the tunnel last became active. `null` when
    /// never active or the field is absent.
    #[serde(default)]
    conns_active_at: Option<String>,
}

/// Enriched tunnel record used internally when walking accounts for drift.
struct TunnelMeta {
    id: String,
    name: String,
    conn_state: TunnelConnState,
    conn_since: Option<String>,
}

#[derive(Deserialize)]
struct CfTunnelConfig {
    config: Option<CfIngressConfig>,
}

#[derive(Deserialize)]
struct CfIngressConfig {
    ingress: Option<Vec<CfIngressRule>>,
}

#[derive(Deserialize)]
struct CfIngressRule {
    hostname: Option<String>,
}

/// One live DNS record from `GET /zones/{id}/dns_records`. We only read the
/// name + content (the target); record type and proxy flags are ignored —
/// drift is decided by whether *some* record routes the hostname to the
/// expected tunnel target.
#[derive(Debug, Clone, Deserialize)]
struct CfDnsRecord {
    name: String,
    content: String,
}

/// One live DNS record with everything a reconciler needs to decide what to
/// change — R859-F1, the read side of [`CloudflareClient::list_dns_records`].
///
/// Distinct from the private [`CfDnsRecord`] above, which deliberately reads
/// only name + content because tunnel-drift detection asks a narrower
/// question. Reconciling a record set needs the `id` (to delete one member of
/// a multi-valued RRset) and `proxied` (an orange-clouded record at an apex
/// that should be grey is drift, even when the content is right).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DnsRecordDetail {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    #[serde(default)]
    pub ttl: u32,
    #[serde(default)]
    pub proxied: bool,
}

// ---------- public output types ----------

/// A Cloudflare account the API token can access.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CfAccountInfo {
    pub id: String,
    pub name: String,
}

/// One CNAME record a user needs to create in their external DNS registrar
/// to route a hostname through a Cloudflare Tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelDnsRecord {
    /// Human-readable tunnel name as entered in Cloudflare.
    pub tunnel_name: String,
    /// Hostname from the tunnel ingress rule (e.g. `yah.example.com`).
    pub hostname: String,
    /// CNAME target to enter in the registrar: `{tunnel_id}.cfargotunnel.com`.
    pub cname_target: String,
}

/// Result of creating a Cloudflare Named Tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTunnelResult {
    pub tunnel_id: String,
    pub tunnel_name: String,
    /// JWT token for `cloudflared tunnel run --token <TOKEN>`.
    pub connector_token: String,
    /// CNAME target: `{tunnel_id}.cfargotunnel.com`.
    pub cname_target: String,
}

/// Result of creating a Cloudflare R2 bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateR2BucketResult {
    pub name: String,
    /// S3-compatible endpoint for object operations against this account.
    pub endpoint: String,
}

/// Result of deploying a Cloudflare Worker script.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerDeployResult {
    pub id: String,
    pub etag: Option<String>,
}

/// One binding to inject into a Worker's `env` at deploy time.
///
/// Each variant maps to a `{"type": …}` entry under `metadata.bindings` in the
/// Workers upload multipart body. R2 buckets are bind-only — the Worker reads
/// the bucket via `env.<name>` and no script-side change is needed beyond the
/// metadata declaration.
#[derive(Debug, Clone, Copy)]
pub enum WorkerBinding<'a> {
    /// `{"type":"plain_text","name":…,"text":…}` — runtime config string.
    PlainText { name: &'a str, text: &'a str },
    /// `{"type":"r2_bucket","name":…,"bucket_name":…}` — R2 bucket reference.
    R2Bucket { name: &'a str, bucket_name: &'a str },
}

/// R2 bucket information from the list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct R2BucketInfo {
    pub name: String,
    /// CF location hint, e.g. `"WEUR"`, `"ENAM"`, `"APAC"`. `None` when the
    /// bucket was created without specifying a hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// ISO 8601 bucket creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
}

/// One R2 custom-domain binding from
/// `GET /accounts/{id}/r2/buckets/{bucket}/domains/custom`.
///
/// The CF response carries nested status + min_tls fields we don't act on
/// today; the reconciler only needs the hostname + enabled flag to decide
/// idempotency.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct R2CustomDomain {
    pub domain: String,
    #[serde(default)]
    pub enabled: bool,
}

/// Live connection state of a Cloudflare Tunnel connector.
///
/// Derived from the `status` field returned by
/// `GET /accounts/{id}/cfd_tunnel?is_deleted=false`. Falls back to
/// [`TunnelConnState::Unknown`] when the field is absent or unrecognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelConnState {
    /// At least one healthy `cloudflared` connector is active.
    Active,
    /// No connectors are running.
    Inactive,
    /// Connectors are running but unhealthy.
    Degraded,
    /// Status couldn't be determined (field absent or unrecognised value).
    Unknown,
}

impl TunnelConnState {
    fn from_cf_status(s: &str) -> Self {
        match s {
            "active" | "healthy" => Self::Active,
            "inactive" | "down" => Self::Inactive,
            "degraded" | "unhealthy" => Self::Degraded,
            _ => Self::Unknown,
        }
    }
}

/// Drift verdict for one tunnel ingress hostname: does live Cloudflare DNS
/// route it to the tunnel's CNAME target?
///
/// Maps onto the designed Tunnels table (`infra-cloudflare.jsx`): `Synced`
/// renders as a healthy pill, everything else as a `drift` pill (`Missing`
/// is the "DNS record missing" case the design calls out).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelDriftState {
    /// A live DNS record points the hostname at the expected tunnel target.
    Synced,
    /// No live DNS record exists for the hostname — the tunnel can't route to it.
    Missing,
    /// A live record exists but points somewhere other than the tunnel target.
    Mismatch,
    /// The hostname's zone couldn't be resolved or read (token lacks
    /// `Zone: Read` / `DNS: Read`, or the apex isn't a zone in any accessible
    /// account) — drift indeterminate, not a failure.
    ZoneUnknown,
}

/// One row of the tunnel DNS-drift report: a tunnel ingress hostname paired
/// with whether live Cloudflare DNS routes it to the tunnel, plus the live
/// connector connection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelDriftRow {
    /// Human-readable tunnel name as entered in Cloudflare.
    pub tunnel_name: String,
    /// Hostname from the tunnel's ingress rule, e.g. `yubaba.yah.dev`.
    pub hostname: String,
    /// CNAME target the DNS record should point at: `{tunnel_id}.cfargotunnel.com`.
    pub expected_target: String,
    pub state: TunnelDriftState,
    /// For [`TunnelDriftState::Mismatch`], the target the live record actually
    /// points at. `None` for every other state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_target: Option<String>,
    /// Live connector state from `GET /cfd_tunnel`. [`TunnelConnState::Unknown`]
    /// when the field was absent or unrecognised.
    pub conn_state: TunnelConnState,
    /// RFC 3339 `conns_active_at` timestamp — when this tunnel last became
    /// active. `None` when the tunnel has never connected or the field was
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn_since: Option<String>,
}

// ---------- API-token provisioning (R320-F12) ----------

/// Resource scope a permission group applies at when building a token policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantScope {
    /// Granted on the whole account (`com.cloudflare.api.account.<id>`).
    Account,
    /// Granted on a single zone (`com.cloudflare.api.account.zone.<id>`).
    Zone,
}

/// One permission to bake into a minted token: a Cloudflare permission-group
/// display name, the scope it applies at, and a validated fallback ID.
///
/// Names are resolved to IDs against the live permission-groups catalog at
/// create time ([`CloudflareClient::list_permission_group_ids`]); `fallback_id`
/// is used only when the catalog lookup can't resolve the name. The IDs are
/// global Cloudflare constants (validated 2026-05-26), not per-account.
#[derive(Debug, Clone, Copy)]
pub struct TokenGrant {
    pub group_name: &'static str,
    pub scope: GrantScope,
    pub fallback_id: &'static str,
}

/// Minimal permission set for a mesofact-static publish token: see the account,
/// list/create R2 buckets, deploy Worker scripts, resolve the zone, manage
/// Worker routes + the index-rewrite Transform Rule, purge the CDN cache, and
/// read GraphQL Analytics (account + zone, R893-T22 — backs the front-door
/// latency panel in `app/yah/desktop/src/front_door.rs`).
///
/// Account-scoped: `Account Settings Read`, `Workers R2 Storage Write`,
/// `Workers Scripts Write`, `Account Analytics Read`.
/// Zone-scoped: `Zone Read`, `Zone Transform Rules Write`,
/// `Workers Routes Write`, `Cache Purge`, `DNS Read`, `DNS Write`,
/// `Analytics Read`.
///
/// NB the Transform Rules group is the *zone-scoped* `Zone Transform Rules
/// Write`, not the account-scoped `Transform Rules Write` —
/// [`CloudflareClient::upsert_index_rewrite`] hits `/zones/{id}/rulesets`.
/// NB likewise there are two distinct Analytics groups, resolved live
/// 2026-09-12 against `GET /accounts/{id}/tokens/permission_groups`:
/// `Account Analytics Read` (`com.cloudflare.api.account`) and `Analytics
/// Read` (`com.cloudflare.api.account.zone`) — same trap shape as Transform
/// Rules, a scoped and an unscoped group sharing a name fragment.
/// Fallback IDs sourced from the global permission-groups catalog
/// (validated 2026-05-26, Analytics pair added 2026-09-12); catalog
/// resolution at create-time takes precedence.
pub const MESOFACT_STATIC_GRANTS: &[TokenGrant] = &[
    TokenGrant {
        group_name: "Account Settings Read",
        scope: GrantScope::Account,
        fallback_id: "c1fde68c7bcc44588cbb6ddbc16d6480",
    },
    TokenGrant {
        group_name: "Workers R2 Storage Write",
        scope: GrantScope::Account,
        fallback_id: "bf7481a1826f439697cb59a20b22293e",
    },
    TokenGrant {
        group_name: "Workers Scripts Write",
        scope: GrantScope::Account,
        fallback_id: "e086da7e2179491d91ee5f35b3ca210a",
    },
    // R893-T22: backs the front-door latency panel's GraphQL Analytics query
    // (app/yah/desktop/src/front_door.rs). Resolved live 2026-09-12 against
    // GET /accounts/3948dc292e724e71b0deefde0ea95999/tokens/permission_groups.
    TokenGrant {
        group_name: "Account Analytics Read",
        scope: GrantScope::Account,
        fallback_id: "b89a480218d04ceb98b4fe57ca29dc1f",
    },
    TokenGrant {
        group_name: "Zone Read",
        scope: GrantScope::Zone,
        fallback_id: "c8fed203ed3043cba015a93ad1616f1f",
    },
    TokenGrant {
        group_name: "Zone Transform Rules Write",
        scope: GrantScope::Zone,
        fallback_id: "0ac90a90249747bca6b047d97f0803e9",
    },
    TokenGrant {
        group_name: "Workers Routes Write",
        scope: GrantScope::Zone,
        fallback_id: "28f4b596e7d643029c524985477ae49a",
    },
    TokenGrant {
        group_name: "Cache Purge",
        scope: GrantScope::Zone,
        fallback_id: "e17beae8b8cb423a99b1730f21238bed",
    },
    // R859-F1: deploy_domain_passway (the sovereign-apex A-record reconciler)
    // is the first production consumer of the dns.* envoy verbs against this
    // token, and it both lists and upserts/prunes A records — hence both
    // Read and Write, not just Read as the R324-F5 @yah:next follow-up noted.
    TokenGrant {
        group_name: "DNS Read",
        scope: GrantScope::Zone,
        fallback_id: "82e64a83756745bbbb1c9c2701bf816b",
    },
    TokenGrant {
        group_name: "DNS Write",
        scope: GrantScope::Zone,
        fallback_id: "4755a26eedb94da69e1066d98aa820be",
    },
    // R893-T22: the zone-scoped counterpart to Account Analytics Read above —
    // NOT the same permission group despite the near-identical name.
    TokenGrant {
        group_name: "Analytics Read",
        scope: GrantScope::Zone,
        fallback_id: "9c88f9c5bce24ce7af9a958ba9c504db",
    },
];

/// Account-scoped grant for a token that only needs to publish and read back
/// a Cloudflare Tunnel's ingress configuration (`ensure_tunnel_ingress` in
/// `reconciler/ingress.rs` — a PUT, so it needs the Write/"Edit" group, not
/// the Read one). Group name + fallback ID resolved live 2026-09-15 against
/// `GET /accounts/3948dc292e724e71b0deefde0ea95999/tokens/permission_groups`
/// (R912-F1) — Cloudflare's own catalog calls the group "Cloudflare Tunnel
/// Write", which is what the dashboard/docs render as "Cloudflare Tunnel:
/// Edit". Deliberately account-scoped only, no zone grants: a tunnel's
/// ingress config is an account-level resource, not a per-zone one.
pub const TUNNEL_EDIT_GRANTS: &[TokenGrant] = &[TokenGrant {
    group_name: "Cloudflare Tunnel Write",
    scope: GrantScope::Account,
    fallback_id: "c07321b023e944ff818fec44d8203567",
}];

/// Result of minting an account-owned API token. `value` is the secret and is
/// returned by Cloudflare exactly once — store it immediately.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTokenResult {
    pub id: String,
    pub name: String,
    /// The token secret. Shown once by Cloudflare; never retrievable again.
    pub value: String,
}

// ---------- client ----------

/// Cloudflare management API client.
///
/// Construct with [`CloudflareClient::new`] passing a pre-resolved API token.
/// The token scope required per method is noted on each method.
pub struct CloudflareClient {
    token: String,
    http: reqwest::Client,
}

/// @yah:relay(R907, "A cloudflare-tunnel edge cannot be brought up by apply alone when its tunnel has no configuration yet")
/// @yah:at(2026-09-14T19:14:34Z)
/// @yah:status(open)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:gotcha("FILED FROM THE noisetable CAMP 2026-09-14 (its R704-T4), where it blocks the staging API door end to end. Filed here rather than there because the fix is entirely in this repo. NOT parented to R845 deliberately: R845 is the right neighbourhood — it landed the edge-first `use` resolution this camp's own fix relies on — but it sits in `review`, and a defect filed onto a review-column relay reaches nobody.")
/// @yah:gotcha("THE CALLER'S ABORT-BEFORE-PUT BEHAVIOUR AT reconciler/ingress.rs:1272-1276 IS CORRECT AND DELIBERATE, and is not what this relay is about. Its doc says a failed API call is never read as \"delete every hostname rule\", and one tunnel multiplexes every service on a node, so a GET that failed for a real reason must keep aborting before the PUT.")
///
/// @yah:ticket(R907-B1, "ensure_tunnel_ingress cannot bootstrap a tunnel that has no configuration yet")
/// @yah:status(review)
/// @yah:at(2026-09-14T19:34:22Z)
/// @yah:assignee(agent:bundle-anthropic-miravel)
/// @yah:parent(R907)
/// @yah:severity(high)
/// @yah:next("Tier: Cleric — a small, well-located error-classification fix in one function, but it sits on a live credentialed write path where the empty-vs-failed distinction has already been reasoned about once and must not be blurred.")
/// @yah:next("THE FIX BELONGS IN THE GET'S CLASSIFICATION, NOT IN THE CALLER: `tunnel_configuration` should return `Ok(json!({}))` for the specific not-found error code and `Err` for everything else. Do NOT loosen the abort-before-PUT guard at reconciler/ingress.rs:1272-1276 — that guard is correct and is what stops a transient API failure being read as \"delete every hostname rule\" on a tunnel that multiplexes every service on a node.")
/// @yah:next("Worth a sweep while in here: any other `cf_get` whose \"resource has never been created\" answer arrives as an error object rather than an empty result has the same latent shape.")
/// @yah:verify("REPRO, MEASURED 2026-09-14 from the noisetable camp: tunnel 1b41587a-7298-4f29-97bf-40d51ed79397, created by `yah cloud cf tunnel ensure` WITHOUT `--hostname` so it has never had a configuration PUT, then `yah cloud apply --env staging --service noisetable-api`. Result: `FAILED: reading ingress configuration of tunnel 1b41587a-…: Configuration for tunnel not found`, apply stops at first failure, no connector workload is deployed.")
/// @yah:verify("THE CREDENTIAL WAS RULED OUT SEPARATELY, and that is what isolates the defect: with a token lacking Tunnel grants the same call fails with `Not authorized` instead, and moving the edge onto a Tunnel-capable provider changed the error from `Not authorized` to `Configuration for tunnel not found`. Two different failures at the same line means the second one is not an auth problem.")
/// @yah:verify("FIXED when a tunnel with no configuration takes its first ingress rule through `yah cloud apply` alone, AND a GET that fails for a genuine reason (revoked token) still aborts before any PUT. Both halves — the first alone re-introduces the wholesale-delete risk ingress.rs:1272-1276 exists to prevent.")
/// @yah:gotcha("MECHANISM, TRACED AND READ RATHER THAN INFERRED. `CloudflareClient::tunnel_configuration` (oss/yubaba/crates/cloud/src/provider/cloudflare.rs:774) already handles an EMPTY configuration correctly further down — `.and_then(|r| r.get(\"config\")).cloned().unwrap_or_else(|| json!({}))` at :787, plus the non-object guard at :790 whose own comment covers a tunnel whose config reads back as an explicit JSON null. But it checks `self.ok(&resp.success, &resp.errors)?` FIRST, at :781. Cloudflare answers `success: false` / `Configuration for tunnel not found` for a token-form tunnel that has never had a configuration PUT, so that guard fires and the tolerant path at :787 is unreachable for exactly the case it looks like it already covers.")
/// @yah:gotcha("WHY IT IS A BUG AND NOT A MISSING FEATURE: \"no configuration exists\" is an EMPTY read, not a FAILED one. The function already draws that distinction correctly for a null config body; it simply does not draw it for the API's own not-found answer. Same fact, two doors — one arrives as `result.config = null`, the other as an error object.")
/// @yah:gotcha("CONSEQUENCE: the only code path that would CREATE a first configuration is gated behind READING a configuration that cannot exist until it has been created. Any cloudflare-tunnel edge whose tunnel was minted without `--hostname` is permanently un-bootstrappable through `yah cloud apply`. The apparent workaround is not one: `yah cloud cf tunnel ensure --hostname` also upserts a DNS CNAME, so it takes a live hostname dark if the connector is not up yet.")
/// @yah:assumes("NOT VERIFIED FROM THE REPORTING CAMP, because settling it would have meant a write to live Cloudflare: whether the GET returns a 404 status specifically, or HTTP 200 with `success: false` in the body. `Configuration for tunnel not found` is the text that surfaced through the `with_context` at reconciler/ingress.rs:1291. Classify on the Cloudflare error CODE in `resp.errors`, not on the message string and not on an assumed status — a message match would layer a second lexical guess on the first.")
/// @yah:verify("THE NON-WORKAROUND IS PINNED BY A NEGATIVE RESULT, so nobody re-tries it: run `cf tunnel ensure --hostname` against a tunnel with no configuration, then `yah cloud apply` — apply must still fail `Configuration for tunnel not found`. If a future change makes `cf tunnel ensure` write config, that is a DIFFERENT fix and this assertion should flip deliberately rather than quietly.")
/// @yah:gotcha("SEVERITY IS HIGHER THAN THIS TICKET FIRST STATED, AND THE OBVIOUS ESCAPE HATCH IS NOT ONE. `yah cloud cf tunnel ensure --name <n> --hostname <h> --api-token-slot cloudflare-legacy-yah` DOES NOT WRITE INGRESS CONFIGURATION — measured 2026-09-14 against tunnel 1b41587a-7298-4f29-97bf-40d51ed79397, not reasoned from the source. It printed `reusing existing 'noisetable-account-staging'`, then `existing connector token preserved in keystore slot`, then went STRAIGHT to the DNS upsert. `yah cloud apply --env staging --service noisetable-api` immediately afterwards failed with the byte-identical `Configuration for tunnel not found`. Its own `--help` confirms the scope in one sentence: ensure the tunnel exists, fetch/store the connector token, OPTIONALLY upsert a CNAME — nothing about configuration.")
/// @yah:gotcha("THEREFORE THERE IS NO VERB IN THE CAMP THAT CAN WRITE A TUNNEL'S FIRST INGRESS CONFIGURATION. This is not 'apply takes an awkward path to a reachable state' — it is a complete dead end for any tunnel minted without `--hostname`, with no CLI escape hatch at all. `apply` is gated behind the GET this ticket describes; `cf tunnel ensure` never writes config; `yah cloud cf` exposes only `token` and `tunnel`. The only two routes out are (a) fixing the GET's error classification, i.e. this ticket, or (b) a human creating the configuration by hand in the Cloudflare dashboard. A consumer camp cannot unblock itself.")
/// @yah:gotcha("READ THIS BESIDE THE SIBLING R907-B2 BEFORE DESIGNING THE FIX. The reporting camp hit BOTH of R907's children on the same door in the same hour, and they compose badly: with no config (this ticket) and no connector, a DNS cutover (B2) has no end date for its dark window. Fixing this one first is what makes the other one safe to sequence.")
/// @yah:handoff("Fixed the root cause: tunnel_configuration (cloudflare.rs) now classifies a failed GET on /cfd_tunnel/{id}/configurations as an EMPTY read (Ok(json!({}))) when the Cloudflare error carries code 1003 (the generic 'not found' family), and still returns Err for every other error (auth, rate-limit, transient). Classification is on the numeric code in resp.errors, not the message text, via a new private CloudflareClient::is_resource_not_found(&Option<Vec<Value>>) helper.")
/// @yah:handoff("Grounding for code 1003: NOT in Cloudflare's own published API reference (checked developers.cloudflare.com's error-response schema for this endpoint 2026-09-14 — it documents only the generic {code, message} shape, no per-condition table). Grounded instead from convergent third-party Cloudflare API clients that hardcode it for this exact family: vana-com/vana-connect's gcp.ts comment '1003: tunnel not found', mandar-karhade/dockflare's error table '1003 | Zone not found', plus independent test fixtures (ratazzi/coulson, MauroDruwel/TunnelDashDesktop) using 1003 for 'Invalid or missing account id' / 'Account not found'. Full sourcing is in the doc comment on is_resource_not_found (cloudflare.rs, just above it). Confirming against a live token was out of scope (ticket forbids live CF calls) and would be worth a follow-up if the sourcing is judged insufficient.")
/// @yah:handoff("Left reconciler/ingress.rs:1272-1276 (the abort-before-PUT guard) untouched, per the ticket's explicit constraint — only read it, did not edit it.")
/// @yah:handoff("Sweep for the same latent shape found two more sites with the identical bug: tunnel_dns_records and tunnel_dns_drift (both in cloudflare.rs) each GET a tunnel's configuration and previously called self.ok(...)? unconditionally, so ANY unconfigured tunnel among many would abort the whole DNS-records listing / drift report with an Err instead of contributing zero ingress hostnames for that tunnel. Fixed both the same way, reusing is_resource_not_found. No other cf_get call site in the file shares this shape — the rest are LIST endpoints (naturally return an empty array when nothing exists, not an error) or are already documented as tolerant (upsert_index_rewrite already treats a missing ruleset entrypoint as empty).")
/// @yah:handoff("Added 3 unit tests pinning is_resource_not_found in both directions plus the None case: resource_not_found_classifies_missing_tunnel_config_as_empty (code 1003 -> true), resource_not_found_does_not_classify_auth_error_as_empty (code 10000 -> false), resource_not_found_false_when_no_errors_present. Tests exercise the classifier directly rather than the full async tunnel_configuration end-to-end, because the crate has no HTTP-mocking dev-dependency (checked Cargo.toml dev-dependencies: tempfile, serde_yaml, tokio — no mockito/wiremock) and adding one is a bigger change than this leaf fix warrants; the classifier is the entire decision this fix adds, so it's what's under test.")
/// @yah:verify("cargo test -p yah-cloud --lib -- cloudflare: 29 pass / 0 fail (includes the 3 new tests), no skew reported.")
/// @yah:verify("cargo test -p yah-cloud --lib (whole crate): 1200 pass / 2 fail / 4 ignored. The 2 failures (reconciler::mesofact_static::tests::a_mount_extends_the_prefix_and_is_slash_insensitive, bundled_worker_walks_the_route_table) are in mesofact_static.rs, which was already modified and uncommitted by a peer at session start (per git status) and is untouched by this ticket's diff -- confirmed unrelated via git diff --stat on that file.")
/// @yah:verify("cargo check -p yah-cloud --lib: clean (1 pre-existing unrelated warning in mesofact_static.rs).")
/// @yah:verify("CloudflareClient::ok now surfaces the numeric Cloudflare error code in its returned message (e.g. \"Cloudflare error 1003: Configuration for tunnel not found\") instead of dropping it, so the FIRST live run of this fix from the reporting camp will either confirm 1003 or name the real code plainly, closing the sourcing gap.")
/// @yah:assumes("The not-found classification code (1003) is UNCONFIRMED against a live Cloudflare account — sourced only from convergent third-party API clients (see is_resource_not_found's doc comment), not from Cloudflare's own docs or a live call. Disproved by: a live `yah cloud apply` against an unconfigured tunnel either (a) succeeding, confirming 1003, or (b) still failing with a message now showing a different numeric code, in which case update CF_ERR_NOT_FOUND in is_resource_not_found to that code.")
/// @yah:handoff("Addendum landed: CloudflareClient::ok now renders every error entry as \\\"Cloudflare error <code>: <message>\\\" (joined with \\\"; \\\" for multiple), instead of dropping the code -- so the reporting camp's next live run will show the real code plainly. Added 3 more unit tests (ok_error_message_carries_the_cloudflare_code, ok_error_message_joins_multiple_errors, ok_error_message_falls_back_when_no_errors_present) via CloudflareClient::new(\\\"test-token\\\"). Grepped the crate for callers/tests asserting the old bare-message string -- none exist outside cloudflare.rs itself; reconciler/ingress.rs:1291 only wraps the error with with_context, doesn't match on it.")
/// @yah:verify("cargo check -p yah-cloud --lib: clean, no errors, after the ok() change. cargo test -p yah-cloud --lib currently fails to COMPILE (19 errors, all `missing field build in initializer of MirrorConfig` across mesofact_static.rs/pond.rs/local_process.rs/static_asset.rs/mod.rs/mesofact_bundle.rs/cloudflare_worker.rs/ingress.rs) -- confirmed zero of those 19 reference provider/cloudflare.rs; this is a live peer's in-flight MirrorConfig migration (git status showed mesofact_static.rs already modified at session start), not this ticket's diff. The cloudflare-module test run that passed 29/29 (prior handoff entry) was taken before that peer's edit progressed to this state; could not re-run cloudflare-scoped tests after the ok() addendum because the whole test binary now fails to link for an unrelated reason. Re-run `cargo test -p yah-cloud --lib -- cloudflare` once that peer's migration lands.")
/// @yah:handoff("Addendum complete: CloudflareClient::ok surfaces the numeric Cloudflare error code in its message text instead of discarding it, so the 1003 guess is now self-diagnosing on the first live run. See appended handoff/verify entries for detail and the peer-breakage caveat on re-running the test suite.")
/// @yah:verify("RE-VERIFIED after the peer's MirrorConfig migration landed: cargo test -p yah-cloud --lib (whole crate) = 1213 pass / 0 fail / 4 ignored, no skew (baseline was 1200/2/4 with the 2 failures being that same peer's in-flight breakage, now resolved). cargo test -p yah-cloud --lib -- cloudflare = 32 pass / 0 fail, includes all 6 new tests (3 for is_resource_not_found, 3 for the ok() addendum).")
///
/// @yah:ticket(R907-B2, "yah cloud cf has no DNS-record verb, so a tunnel hostname whose name already holds A records cannot be moved")
/// @yah:status(review)
/// @yah:at(2026-09-14T20:23:53Z)
/// @yah:assignee(agent:bundle-anthropic-miravel)
/// @yah:parent(R907)
/// @yah:severity(medium)
/// @yah:next("Tier: Cleric — small surface to add, but the sequencing semantics are the whole point and a naive delete-then-create verb would be worse than none.")
/// @yah:next("THE ORDERING HAZARD IS THE DESIGN CONSTRAINT, NOT A CAVEAT. Deleting the incumbent A records BEFORE a connector is up takes a live hostname dark, and when the tunnel also has no configuration (sibling R907-B1) that window has NO END DATE — nothing is standing by to answer. So a DNS verb here should not be a thin delete+create wrapper. Prefer a cutover that is atomic, or gated on connector readiness (tunnel has >=1 healthy connector AND an ingress rule for the hostname) before it touches the incumbent record, with the unsafe ordering available only behind an explicit flag that names the outage it buys.")
/// @yah:next("Worth deciding deliberately: whether the verb belongs on `yah cloud cf` as a general record CRUD, or whether the tunnel cutover should stay a single higher-level operation (`cf tunnel cutover --hostname`) that owns the safe ordering internally. The second is harder to misuse and matches how `cf tunnel ensure` already hides the record shape from the caller.")
/// @yah:next("Fix R907-B1 FIRST or in the same change. Sequencing this one alone still leaves a consumer unable to get a configuration onto the tunnel, so the connector-readiness gate above could never be satisfied.")
/// @yah:verify("REPRO: point `cf tunnel ensure --name <tunnel> --hostname <h> --api-token-slot cloudflare-legacy-yah` at a hostname that currently resolves via A records. Observed: the tunnel-reuse and token-preserve lines print normally, then `Error: upserting CNAME <h> → <id>.cfargotunnel.com: An A, AAAA, or CNAME record with that host already exists.` The API token is not the issue — cloudflare-legacy-yah carries both Tunnel:Edit and DNS:Edit, and the same invocation's tunnel half succeeded in the same run.")
/// @yah:verify("FIXED when a hostname on A records can be moved onto a tunnel through the CLI alone, AND the safe-ordering property holds — i.e. an attempt to cut over to a tunnel with no healthy connector either refuses or is explicitly opted into. Both halves: the first alone just automates the outage.")
/// @yah:gotcha("THE SURFACE IS TWO SUBCOMMANDS WIDE. `yah cloud cf --help` lists exactly `token` (mint scoped account-owned tokens) and `tunnel` (idempotent ensure). There is no verb that reads, creates, updates or deletes a DNS record. The only DNS write anywhere in `yah cloud cf` is the CNAME upsert bolted onto `cf tunnel ensure --hostname`.")
/// @yah:gotcha("AND THAT UPSERT IS NOT A GENERAL UPSERT. Cloudflare forbids a CNAME coexisting with an A/AAAA record at the same name, so the call fails with `An A, AAAA, or CNAME record with that host already exists` whenever the incumbent record is not ALREADY a CNAME. The `--help` text's promise that it 'upserts a CNAME ... so the public hostname is wired even before the origin daemon comes up' therefore holds only for a name that is unused or already CNAME'd — precisely NOT the migration case, where a hostname is being moved onto a tunnel from something else.")
/// @yah:gotcha("CONCRETE INSTANCE, MEASURED 2026-09-14 from the noisetable camp: api-staging.noisetable.com holds A records 51.81.85.145 and 45.32.194.254 (its production passway edge, currently serving 200), and cannot be moved to tunnel 1b41587a-7298-4f29-97bf-40d51ed79397 because those two records must be DELETED first. With no DNS verb in the CLI, the only route is hand-editing the Cloudflare dashboard or hand-calling the API — which is exactly the class of action a camp's own rules put out of bounds for an agent, so the cutover stalls with no in-tool path.")
/// @yah:handoff("Built the higher-level operation as directed: `yah cloud cf tunnel cutover --hostname <h> --name <tunnel> [--force-dark-window]` (app/yah/cli/src/cloud.rs). No general DNS CRUD exposed on the CLI -- the DNS methods it needed (list_dns_records, delete_dns_records_matching, upsert_dns_record) already existed as CloudflareClient methods from prior work (R859-F1); only one new client method was added: CloudflareClient::tunnel_conn_state(account_id, tunnel_id) -> Result<TunnelConnState>, a thin wrapper around the existing (private) list_tunnels_meta that surfaces just the connector state for one tunnel by id.")
/// @yah:handoff("Ordering: lists existing DNS records at the hostname first. If already a correct CNAME with no A/AAAA left beside it, no-op success (idempotent, matches `ensure`'s contract). Otherwise, if A/AAAA records are present, gates on readiness (tunnel_conn_state == Active AND tunnel_configuration's ingress array contains a rule for the hostname) before deleting them -- refuses with a message naming both missing preconditions and the outage it would cause, unless --force-dark-window is passed (which prints an explicit warning naming the outage before proceeding). Deletes only the incumbent A/AAAA records (delete_dns_records_matching, scoped by type+content so a round-robin sibling isn't touched), then upserts the CNAME.")
/// @yah:handoff("Composes R907-B1 directly: the readiness check's ingress-rule half calls tunnel_configuration, which is what B1 made tolerant of a never-configured tunnel -- so a tunnel with a connector up but no ingress yet correctly reads as not-ready (has_ingress_rule=false) instead of erroring out of the whole cutover attempt.")
/// @yah:handoff("Pure decision logic extracted and unit-tested directly (not through the async handler, matching how the R907-B1 classifier was tested): cutover_already_complete(records, cname_target), tunnel_ready_for_cutover(conn_state, has_ingress_rule), tunnel_ingress_has_hostname(ingress_json, hostname). 7 new tests in a cf_tunnel_cutover_tests module pin: no-op when already correct CNAME alone; not-complete when an A record remains beside the CNAME; not-complete when only A records present; not-complete when CNAME points elsewhere; readiness requires BOTH Active connector state AND an ingress rule (every other TunnelConnState variant fails the gate even with the rule present); ingress-hostname matching is exact and returns false on an empty/malformed config.")
/// @yah:handoff("Plumbing: DnsRecordDetail and TunnelConnState were not previously re-exported through cloud::provider::mod.rs / cloud::lib.rs (only used internally); added both to the existing pub-use lists so app/yah/cli can name them. No new pub surface beyond that plus tunnel_conn_state.")
/// @yah:verify("cargo check -p yah --lib: clean (0 errors), 26 pre-existing warnings none of which touch the new code (spot-checked: the only two cloud.rs warnings, a pre-existing unused `mut` at line ~16965 and an unused `stub` fn at line ~3625, predate this change).")
/// @yah:verify("cargo test -p yah --lib -- cf_tunnel_cutover_tests: 7 pass / 0 fail, no skew on the final run (an earlier run in this same session hit a transient 92-error compile while a peer's kg-store/blake3 and slot_table.rs edits were mid-flight -- confirmed unrelated by re-running clean after they landed; see gotcha).")
/// @yah:verify("cargo check -p yah-cloud --lib and cargo test -p yah-cloud --lib both re-verified green after this ticket's additions (1213 pass / 0 fail / 4 ignored) -- the new tunnel_conn_state method didn't regress anything.")
/// @yah:verify("NOT verified live (explicitly out of scope): no live Cloudflare account was hit. The connector-readiness gate's real-world shape (does list_tunnels_meta's status field actually read 'active' the way TunnelConnState::from_cf_status expects for a freshly-up connector) is asserted only by the existing TunnelConnState tests from prior work, not newly re-verified here.")
/// @yah:gotcha("Mid-session this crate hit two DIFFERENT transient shared-tree compile breaks, both from live peers, both now resolved and neither touching this ticket's files: (1) oss/yubaba/crates/cloud/src/reconciler/mesofact_static.rs's MirrorConfig gained a `build` field mid-session, breaking `cargo test -p yah-cloud --lib` (test-only, `cargo check --lib` stayed clean throughout) -- landed and reverified 1213/0/4. (2) crates/yah/kg-store/src/camp_config.rs referenced `blake3::hash` before its Cargo.toml dependency landed, breaking `cargo check -p yah --lib` entirely for a window -- also since resolved. Neither was touched by this session; noted here only so a reviewer re-running the same commands mid-flight doesn't misattribute a stale failure to R907-B2.")
/// @yah:verify("RE-RUN 2026-09-14 ~13:30 per @Ashguard:rose's R897 heads-up: an unattributed git stash wiped the tree at 13:09:46, restored ~13:14 (faba56a4 + pop), and this ticket's two flagged commands (cargo check -p yah --lib, cf_tunnel_cutover_tests) had run inside that window on a prior pass. Confirmed by content first that nothing was lost (git show HEAD still had handle_cf_tunnel_cutover / Cutover variant / cf_tunnel_cutover_tests module, all committed pre-wipe in 30c2c02c per the operator's own diff verification) -- nothing to re-author. Re-ran fresh anyway: cargo check -p yah --lib clean (no skew); cf_tunnel_cutover_tests 7/7 pass (no skew); cargo test -p yah-cloud --lib 1213/0/4 (no skew). All three identical to the pre-wipe results.")
impl CloudflareClient {
    /// Create a client for the given API token.
    pub fn new(token: String) -> Self {
        Self {
            token,
            http: reqwest::Client::new(),
        }
    }

    /// List accounts the token can access.
    /// Requires: `Account: Read`.
    pub async fn list_accounts(&self) -> Result<Vec<CfAccountInfo>> {
        #[derive(Deserialize)]
        struct Entry {
            id: String,
            name: String,
        }
        let resp: CfPage<Entry> = self.cf_get("/accounts").await?;
        self.ok(&resp.success, &resp.errors)?;
        Ok(resp
            .result
            .unwrap_or_default()
            .into_iter()
            .map(|a| CfAccountInfo {
                id: a.id,
                name: a.name,
            })
            .collect())
    }

    /// List non-deleted Cloudflare Tunnels in `account_id` with connection state.
    /// Requires: `Cloudflare Tunnel: Read`.
    async fn list_tunnels_meta(&self, account_id: &str) -> Result<Vec<TunnelMeta>> {
        let resp: CfPage<CfTunnel> = self
            .cf_get(&format!(
                "/accounts/{account_id}/cfd_tunnel?is_deleted=false"
            ))
            .await?;
        self.ok(&resp.success, &resp.errors)?;
        Ok(resp
            .result
            .unwrap_or_default()
            .into_iter()
            .map(|t| TunnelMeta {
                conn_state: t
                    .status
                    .as_deref()
                    .map(TunnelConnState::from_cf_status)
                    .unwrap_or(TunnelConnState::Unknown),
                conn_since: t.conns_active_at,
                id: t.id,
                name: t.name,
            })
            .collect())
    }

    /// List non-deleted Cloudflare Tunnels in `account_id` as `(id, name)` pairs.
    /// Requires: `Cloudflare Tunnel: Read`.
    pub async fn list_tunnels(&self, account_id: &str) -> Result<Vec<(String, String)>> {
        Ok(self
            .list_tunnels_meta(account_id)
            .await?
            .into_iter()
            .map(|m| (m.id, m.name))
            .collect())
    }

    /// Live connection state for one tunnel, by id — the connector-readiness
    /// half of a safe DNS cutover (R907-B2). `Unknown` when the tunnel
    /// doesn't appear in the account's tunnel list at all (deleted, wrong
    /// account) rather than erroring, since a caller gating on `Active` — the
    /// only value that clears the gate — treats every other variant the
    /// same way.
    ///
    /// Requires: `Cloudflare Tunnel: Read`.
    pub async fn tunnel_conn_state(
        &self,
        account_id: &str,
        tunnel_id: &str,
    ) -> Result<TunnelConnState> {
        Ok(self
            .list_tunnels_meta(account_id)
            .await?
            .into_iter()
            .find(|t| t.id == tunnel_id)
            .map(|t| t.conn_state)
            .unwrap_or(TunnelConnState::Unknown))
    }

    /// Collect CNAME records for all tunnels across all accessible accounts.
    ///
    /// Walks accounts → tunnels → ingress configurations. Returns an empty
    /// vec when the token has no tunnels or no configured ingress hostnames.
    pub async fn tunnel_dns_records(&self) -> Result<Vec<TunnelDnsRecord>> {
        let mut records = Vec::new();
        let accounts = self.list_accounts().await?;

        for account in &accounts {
            let tunnels = self.list_tunnels(&account.id).await?;
            for (tunnel_id, tunnel_name) in &tunnels {
                let cname_target = format!("{tunnel_id}.cfargotunnel.com");
                let path = format!(
                    "/accounts/{}/cfd_tunnel/{tunnel_id}/configurations",
                    account.id
                );
                let config_resp: CfSingle<CfTunnelConfig> = self.cf_get(&path).await?;
                let ingress = if !config_resp.success
                    && Self::is_resource_not_found(&config_resp.errors)
                {
                    Vec::new()
                } else {
                    self.ok(&config_resp.success, &config_resp.errors)?;
                    config_resp
                        .result
                        .and_then(|c| c.config)
                        .and_then(|c| c.ingress)
                        .unwrap_or_default()
                };
                for rule in ingress {
                    if let Some(hostname) = rule.hostname.filter(|h| !h.is_empty()) {
                        records.push(TunnelDnsRecord {
                            tunnel_name: tunnel_name.clone(),
                            hostname,
                            cname_target: cname_target.clone(),
                        });
                    }
                }
            }
        }
        Ok(records)
    }

    /// Compute DNS drift for every tunnel ingress hostname, enriched with live
    /// connector connection state.
    ///
    /// The declared side is the tunnel ingress config; the live side is the
    /// zone's DNS records. Each ingress hostname is classified:
    /// [`TunnelDriftState::Synced`] when a record points at the tunnel's CNAME
    /// target, `Missing` when none exists, `Mismatch` when one points elsewhere.
    ///
    /// Connection state (`conn_state` / `conn_since`) comes from the `status`
    /// and `conns_active_at` fields on the tunnel list response — fetched in the
    /// same pass as the ingress configs to avoid an extra `list_accounts` round-trip.
    ///
    /// Degrades gracefully — a hostname whose zone can't be resolved or read is
    /// reported `ZoneUnknown` rather than failing the whole report. Returns an
    /// empty vec when the token has no tunnels or no ingress hostnames.
    ///
    /// Requires: `Cloudflare Tunnel: Read`, `Zone: Read`, `DNS: Read`.
    pub async fn tunnel_dns_drift(&self) -> Result<Vec<TunnelDriftRow>> {
        // Walk accounts → tunnels (with live connection state) → ingress configs
        // in one pass, collecting both declared DNS records and conn-state in a
        // single list_accounts round-trip.
        let accounts = self.list_accounts().await?;
        let mut declared: Vec<TunnelDnsRecord> = Vec::new();
        let mut conn_by_tunnel: std::collections::HashMap<
            String,
            (TunnelConnState, Option<String>),
        > = Default::default();

        for account in &accounts {
            let metas = self.list_tunnels_meta(&account.id).await?;
            for meta in &metas {
                conn_by_tunnel.insert(
                    meta.name.clone(),
                    (meta.conn_state, meta.conn_since.clone()),
                );
                let cname_target = format!("{}.cfargotunnel.com", meta.id);
                let path = format!(
                    "/accounts/{}/cfd_tunnel/{}/configurations",
                    account.id, meta.id
                );
                let config_resp: CfSingle<CfTunnelConfig> = self.cf_get(&path).await?;
                let ingress = if !config_resp.success
                    && Self::is_resource_not_found(&config_resp.errors)
                {
                    Vec::new()
                } else {
                    self.ok(&config_resp.success, &config_resp.errors)?;
                    config_resp
                        .result
                        .and_then(|c| c.config)
                        .and_then(|c| c.ingress)
                        .unwrap_or_default()
                };
                for rule in ingress {
                    if let Some(hostname) = rule.hostname.filter(|h| !h.is_empty()) {
                        declared.push(TunnelDnsRecord {
                            tunnel_name: meta.name.clone(),
                            hostname,
                            cname_target: cname_target.clone(),
                        });
                    }
                }
            }
        }

        if declared.is_empty() {
            return Ok(Vec::new());
        }

        // Resolve zones once. A permission failure leaves the set empty, so
        // every hostname falls through to `ZoneUnknown` instead of erroring.
        let zones = self.list_zones().await.unwrap_or_default();

        let mut rows = Vec::with_capacity(declared.len());
        for rec in declared {
            let (conn_state, conn_since) = conn_by_tunnel
                .remove(&rec.tunnel_name)
                .unwrap_or((TunnelConnState::Unknown, None));
            let (state, live_target) = match best_zone_for(&rec.hostname, &zones) {
                None => (TunnelDriftState::ZoneUnknown, None),
                Some(zone_id) => match self.dns_records_named(zone_id, &rec.hostname).await {
                    Ok(live) => classify_tunnel_drift(&rec.hostname, &rec.cname_target, &live),
                    Err(_) => (TunnelDriftState::ZoneUnknown, None),
                },
            };
            rows.push(TunnelDriftRow {
                tunnel_name: rec.tunnel_name,
                hostname: rec.hostname,
                expected_target: rec.cname_target,
                state,
                live_target,
                conn_state,
                conn_since,
            });
        }
        Ok(rows)
    }

    /// List zones the token can read, as `(zone_id, zone_name)` pairs.
    /// Requires: `Zone: Read`.
    pub async fn list_zones(&self) -> Result<Vec<(String, String)>> {
        #[derive(Deserialize)]
        struct ZoneEntry {
            id: String,
            name: String,
        }
        let resp: CfPage<ZoneEntry> = self.cf_get("/zones?per_page=50").await?;
        self.ok(&resp.success, &resp.errors)?;
        Ok(resp
            .result
            .unwrap_or_default()
            .into_iter()
            .map(|z| (z.id, z.name))
            .collect())
    }

    /// Fetch DNS records in `zone_id` whose name exactly matches `name`.
    /// Requires: `DNS: Read`.
    async fn dns_records_named(&self, zone_id: &str, name: &str) -> Result<Vec<CfDnsRecord>> {
        let resp: CfPage<CfDnsRecord> = self
            .cf_get(&format!("/zones/{zone_id}/dns_records?name={name}"))
            .await?;
        self.ok(&resp.success, &resp.errors)?;
        Ok(resp.result.unwrap_or_default())
    }

    /// Create a new Named Tunnel under `account_id` and return the connector token.
    /// Requires: `Cloudflare Tunnel: Edit`.
    pub async fn create_tunnel(&self, account_id: &str, name: &str) -> Result<CreateTunnelResult> {
        use base64::Engine as _;

        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes)
            .map_err(|e| anyhow!("generate tunnel secret: {e}"))?;
        let tunnel_secret = base64::engine::general_purpose::STANDARD.encode(secret_bytes);

        #[derive(Serialize)]
        struct CreateBody<'a> {
            name: &'a str,
            tunnel_secret: String,
        }
        #[derive(Deserialize)]
        struct CreatedTunnel {
            id: String,
            name: String,
        }
        let create_resp: CfSingle<CreatedTunnel> = self
            .cf_post(
                &format!("/accounts/{account_id}/cfd_tunnel"),
                &CreateBody {
                    name,
                    tunnel_secret,
                },
            )
            .await?;
        self.ok(&create_resp.success, &create_resp.errors)?;
        let created = create_resp
            .result
            .ok_or_else(|| anyhow!("tunnel create: no result in response"))?;

        // Fetch the connector JWT.
        #[derive(Deserialize)]
        struct TokenResp {
            success: bool,
            result: Option<String>,
            errors: Option<Vec<serde_json::Value>>,
        }
        let token_resp: TokenResp = self
            .cf_get(&format!(
                "/accounts/{account_id}/cfd_tunnel/{}/token",
                created.id
            ))
            .await?;
        self.ok(&token_resp.success, &token_resp.errors)?;
        let connector_token = token_resp
            .result
            .ok_or_else(|| anyhow!("no connector token in response"))?;

        Ok(CreateTunnelResult {
            cname_target: format!("{}.cfargotunnel.com", created.id),
            tunnel_id: created.id,
            tunnel_name: created.name,
            connector_token,
        })
    }

    /// Read a tunnel's remotely-managed configuration body as raw JSON
    /// (R594-F11).
    ///
    /// Returns the `result.config` object — the thing a PUT round-trips — or an
    /// empty object when the tunnel has never been configured. Deliberately
    /// untyped: the `ingress` list is the only key this crate owns, and every
    /// sibling (`warp-routing`, `originRequest`, …) must survive a
    /// read-modify-write untouched.
    ///
    /// Requires: `Cloudflare Tunnel: Read`.
    pub async fn tunnel_configuration(
        &self,
        account_id: &str,
        tunnel_id: &str,
    ) -> Result<serde_json::Value> {
        let path = format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations");
        let resp: CfSingle<serde_json::Value> = self.cf_get(&path).await?;
        if !resp.success && Self::is_resource_not_found(&resp.errors) {
            return Ok(serde_json::json!({}));
        }
        self.ok(&resp.success, &resp.errors)?;
        let config = resp
            .result
            .as_ref()
            .and_then(|r| r.get("config"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        // A tunnel configured with an explicit JSON `null` config reads back as
        // Value::Null, which has no object to insert `ingress` into.
        Ok(if config.is_object() {
            config
        } else {
            serde_json::json!({})
        })
    }

    /// Replace a tunnel's remotely-managed configuration (R594-F11).
    ///
    /// `config` is the whole config body, not a patch — Cloudflare replaces it
    /// wholesale, which is why callers must GET-merge-PUT rather than PUT a
    /// freshly-built list. See
    /// [`reconciler::ingress::ensure_tunnel_ingress`](crate::reconciler::ingress::ensure_tunnel_ingress).
    ///
    /// Requires: `Cloudflare Tunnel: Edit`.
    pub async fn put_tunnel_configuration(
        &self,
        account_id: &str,
        tunnel_id: &str,
        config: &serde_json::Value,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct ConfigBody<'a> {
            config: &'a serde_json::Value,
        }
        let path = format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations");
        let resp: CfSingle<serde_json::Value> = self.cf_put(&path, &ConfigBody { config }).await?;
        self.ok(&resp.success, &resp.errors)?;
        Ok(())
    }

    /// Create a new R2 bucket under `account_id`.
    /// Requires: `Account: Cloudflare R2: Edit`.
    pub async fn create_r2_bucket(
        &self,
        account_id: &str,
        bucket_name: &str,
    ) -> Result<CreateR2BucketResult> {
        #[derive(Serialize)]
        struct CreateBody<'a> {
            name: &'a str,
        }
        let resp: CfSingle<serde_json::Value> = self
            .cf_post(
                &format!("/accounts/{account_id}/r2/buckets"),
                &CreateBody { name: bucket_name },
            )
            .await?;
        self.ok(&resp.success, &resp.errors)?;

        Ok(CreateR2BucketResult {
            endpoint: format!("https://{account_id}.r2.cloudflarestorage.com"),
            name: bucket_name.to_string(),
        })
    }

    /// Resolve a zone name (e.g. `"yah.dev"`) to its Cloudflare zone ID.
    /// Requires: `Zone: Read`.
    pub async fn zone_id_for_name(&self, zone_name: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct ZoneEntry {
            id: String,
            name: String,
        }
        let resp: CfPage<ZoneEntry> = self.cf_get(&format!("/zones?name={zone_name}")).await?;
        self.ok(&resp.success, &resp.errors)?;
        resp.result
            .unwrap_or_default()
            .into_iter()
            .find(|z| z.name == zone_name)
            .map(|z| z.id)
            .ok_or_else(|| anyhow!("no Cloudflare zone found for name {zone_name:?}"))
    }

    /// Purge content by cache tags from a zone.
    ///
    /// Cache tags must be applied to responses via the `Cache-Tag` header or
    /// Cloudflare page rules. Returns `Ok(())` when all tags are queued for
    /// purge. Requires: `Zone: Cache Purge`.
    pub async fn purge_cache_tags(&self, zone_id: &str, tags: &[String]) -> Result<()> {
        if tags.is_empty() {
            return Ok(());
        }
        #[derive(Serialize)]
        struct PurgeBody<'a> {
            tags: &'a [String],
        }
        let resp: CfSingle<serde_json::Value> = self
            .cf_post(
                &format!("/zones/{zone_id}/purge_cache"),
                &PurgeBody { tags },
            )
            .await?;
        self.ok(&resp.success, &resp.errors)
    }

    /// Upsert the Transform Rule that rewrites `GET /` → `/index.html` on the
    /// zone, identified by the stable description tag `"yah:static-index"`.
    ///
    /// Idempotent: fetches the existing `http_request_transform` entrypoint,
    /// drops any prior `"yah:static-index"` rule, appends the current one,
    /// and PUTs the merged list back. Treats a missing entrypoint (no rules
    /// yet) as an empty list.
    ///
    /// Requires: `Zone: Transform Rules: Edit`.
    pub async fn upsert_index_rewrite(&self, zone_id: &str) -> Result<()> {
        const RULE_DESC: &str = "yah:static-index";
        let path = format!("/zones/{zone_id}/rulesets/phases/http_request_transform/entrypoint");

        // Fetch existing rules; a missing entrypoint is not an error.
        let existing: Vec<serde_json::Value> = {
            #[derive(Deserialize)]
            struct Rs {
                rules: Option<Vec<serde_json::Value>>,
            }
            match self.cf_get::<CfSingle<Rs>>(&path).await {
                Ok(resp) if resp.success => resp.result.and_then(|r| r.rules).unwrap_or_default(),
                _ => Vec::new(),
            }
        };

        // Keep every rule except the one we manage, then append ours.
        let mut rules: Vec<serde_json::Value> = existing
            .into_iter()
            .filter(|r| r.get("description").and_then(|v| v.as_str()) != Some(RULE_DESC))
            .collect();
        rules.push(serde_json::json!({
            "action": "rewrite",
            "description": RULE_DESC,
            "expression": "(http.request.uri.path eq \"/\")",
            "action_parameters": {
                "uri": { "path": { "value": "/index.html" } }
            },
            "enabled": true
        }));

        let resp: CfSingle<serde_json::Value> = self
            .cf_put(&path, &serde_json::json!({ "rules": rules }))
            .await?;
        self.ok(&resp.success, &resp.errors)
    }

    /// Deploy an ES-module Worker script with typed bindings for runtime config.
    ///
    /// Each entry in `bindings` becomes one `metadata.bindings[…]` declaration in
    /// the upload payload — see [`WorkerBinding`] for the supported variants
    /// (plain_text config, R2 bucket references).
    ///
    /// Uses a manual multipart/form-data upload (CF Workers API requires multipart
    /// when metadata/bindings are attached). Idempotent: re-uploading the same script
    /// is safe but costs one CF API round-trip — callers should hash-guard this.
    ///
    /// Requires: `Workers Scripts: Edit` (account-scoped).
    pub async fn deploy_worker_script(
        &self,
        account_id: &str,
        script_name: &str,
        script_js: &str,
        bindings: &[WorkerBinding<'_>],
    ) -> Result<WorkerDeployResult> {
        let url = format!("{CF_API}/accounts/{account_id}/workers/scripts/{script_name}");
        let (content_type, body) = build_worker_multipart(script_js, bindings);
        let resp = self
            .http
            .put(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", content_type)
            .body(body)
            .send()
            .await
            .map_err(|e| anyhow!("PUT {url}: {e}"))?;
        let result: CfSingle<WorkerDeployResult> = resp
            .json()
            .await
            .map_err(|e| anyhow!("PUT {url} parse: {e}"))?;
        self.ok(&result.success, &result.errors)?;
        result
            .result
            .ok_or_else(|| anyhow!("deploy worker: no result in response"))
    }

    /// Upsert a Worker route for `pattern` on `zone_id`, pointing at `script_name`.
    ///
    /// Idempotent: fetches existing routes, skips PUT/POST when the pattern already
    /// points at the right script, updates an existing pattern pointing elsewhere,
    /// or creates a new route entry.
    ///
    /// Requires: `Zone: Workers Routes: Edit` (zone-scoped).
    pub async fn upsert_worker_route(
        &self,
        zone_id: &str,
        pattern: &str,
        script_name: &str,
    ) -> Result<()> {
        let list_path = format!("/zones/{zone_id}/workers/routes");

        #[derive(Deserialize)]
        struct RouteEntry {
            id: String,
            pattern: String,
            #[serde(default)]
            script: Option<String>,
        }
        let list: CfPage<RouteEntry> = self.cf_get(&list_path).await?;
        self.ok(&list.success, &list.errors)?;
        let routes = list.result.unwrap_or_default();

        #[derive(Serialize)]
        struct RouteBody<'a> {
            pattern: &'a str,
            script: &'a str,
        }

        if let Some(existing) = routes.iter().find(|r| r.pattern == pattern) {
            if existing.script.as_deref() == Some(script_name) {
                return Ok(());
            }
            let resp: CfSingle<serde_json::Value> = self
                .cf_put(
                    &format!("/zones/{zone_id}/workers/routes/{}", existing.id),
                    &RouteBody {
                        pattern,
                        script: script_name,
                    },
                )
                .await?;
            self.ok(&resp.success, &resp.errors)
        } else {
            let resp: CfSingle<serde_json::Value> = self
                .cf_post(
                    &list_path,
                    &RouteBody {
                        pattern,
                        script: script_name,
                    },
                )
                .await?;
            self.ok(&resp.success, &resp.errors)
        }
    }

    /// Idempotently attach `hostname` (e.g. `cr.yah.dev`) as a Workers Custom
    /// Domain on `script_name`. Custom Domains route every request for the
    /// hostname into the Worker — distinct from a Worker Route, which only
    /// matches a URL pattern within an already-proxied zone.
    ///
    /// Walks the existing Custom Domains list first; if `hostname` is already
    /// bound to `script_name` on `zone_id`, returns Ok without an extra PUT.
    /// Otherwise PUTs `/accounts/{account_id}/workers/domains`, which CF treats
    /// as an upsert keyed on `(hostname, environment)`.
    ///
    /// Requires: `Workers Scripts: Edit` (account-scoped).
    pub async fn upsert_worker_custom_domain(
        &self,
        account_id: &str,
        zone_id: &str,
        hostname: &str,
        script_name: &str,
    ) -> Result<()> {
        let list_path = format!("/accounts/{account_id}/workers/domains");

        #[derive(Deserialize)]
        struct DomainEntry {
            #[serde(default)]
            hostname: Option<String>,
            #[serde(default)]
            service: Option<String>,
            #[serde(default, rename = "zone_id")]
            zone_id: Option<String>,
        }
        let list: CfPage<DomainEntry> = self.cf_get(&list_path).await?;
        self.ok(&list.success, &list.errors)?;
        let domains = list.result.unwrap_or_default();
        if domains.iter().any(|d| {
            d.hostname.as_deref() == Some(hostname)
                && d.service.as_deref() == Some(script_name)
                && d.zone_id.as_deref() == Some(zone_id)
        }) {
            return Ok(());
        }

        #[derive(Serialize)]
        struct DomainBody<'a> {
            environment: &'a str,
            hostname: &'a str,
            service: &'a str,
            zone_id: &'a str,
        }
        let resp: CfSingle<serde_json::Value> = self
            .cf_put(
                &list_path,
                &DomainBody {
                    environment: "production",
                    hostname,
                    service: script_name,
                    zone_id,
                },
            )
            .await?;
        self.ok(&resp.success, &resp.errors)
    }

    /// Delete an R2 bucket under `account_id`.
    ///
    /// Cloudflare's management API handles non-empty buckets — objects do not
    /// need to be drained first. Returns `Ok(())` on success, `Err` if the
    /// API returns a failure (including "bucket not found" — callers that
    /// need idempotency should probe [`Self::list_r2_buckets`] first).
    ///
    /// Requires: `Account: Cloudflare R2: Edit`.
    pub async fn delete_r2_bucket(&self, account_id: &str, bucket_name: &str) -> Result<()> {
        let resp: CfSingle<serde_json::Value> = self
            .cf_delete(&format!("/accounts/{account_id}/r2/buckets/{bucket_name}"))
            .await?;
        self.ok(&resp.success, &resp.errors)
    }

    /// Idempotently upsert a DNS record in `zone_id`. Fetches existing records
    /// with the same name and type: updates the first match if found, creates
    /// a new record otherwise. Returns the provider-issued record ID.
    ///
    /// Requires: `DNS: Edit` (zone-scoped).
    pub async fn upsert_dns_record(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
        content: &str,
        ttl: u32,
        proxied: bool,
    ) -> Result<String> {
        self.upsert_dns_record_matching(zone_id, name, record_type, content, ttl, proxied, false)
            .await
    }

    /// [`upsert_dns_record`](Self::upsert_dns_record) with control over what
    /// counts as "the existing record" — R859-F1.
    ///
    /// `match_content = false` reproduces the original behaviour: the first
    /// record sharing `name` + `record_type` is updated in place. That is right
    /// for a single-valued name (one CNAME at `cdn.yah.dev`) and **wrong for a
    /// multi-valued RRset**: adding the second A record of a round-robin apex
    /// would rewrite the first one's content, silently halving the origin set
    /// to one box.
    ///
    /// `match_content = true` keys the lookup on `(name, type, content)`, so
    /// the call means "ensure exactly this record exists" — a no-op update when
    /// it already does, a create when it does not, and never a mutation of a
    /// sibling record at the same name.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_dns_record_matching(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
        content: &str,
        ttl: u32,
        proxied: bool,
        match_content: bool,
    ) -> Result<String> {
        let existing_id = if match_content {
            self.list_dns_records(zone_id, Some(name), Some(record_type))
                .await?
                .into_iter()
                .find(|r| r.content == content)
                .map(|r| r.id)
        } else {
            self.find_dns_record(zone_id, name, record_type).await?
        };

        #[derive(Serialize)]
        struct RecordBody<'a> {
            name: &'a str,
            #[serde(rename = "type")]
            record_type: &'a str,
            content: &'a str,
            ttl: u32,
            proxied: bool,
        }
        let body = RecordBody {
            name,
            record_type,
            content,
            ttl,
            proxied,
        };

        #[derive(Deserialize)]
        struct RecordResult {
            id: String,
        }

        if let Some(id) = existing_id {
            let resp: CfSingle<RecordResult> = self
                .cf_put(&format!("/zones/{zone_id}/dns_records/{id}"), &body)
                .await?;
            self.ok(&resp.success, &resp.errors)?;
            resp.result
                .map(|r| r.id)
                .ok_or_else(|| anyhow!("dns record update: no id in response"))
        } else {
            let resp: CfSingle<RecordResult> = self
                .cf_post(&format!("/zones/{zone_id}/dns_records"), &body)
                .await?;
            self.ok(&resp.success, &resp.errors)?;
            resp.result
                .map(|r| r.id)
                .ok_or_else(|| anyhow!("dns record create: no id in response"))
        }
    }

    /// Read the DNS records in `zone_id`, optionally narrowed to one `name`
    /// and/or one `record_type` — R859-F1, the read half the `dns.*` catalog
    /// was missing.
    ///
    /// Unlike [`dns_records_named`](Self::dns_records_named) (drift-detection
    /// only, name + content) this returns the record **id**, type, ttl and
    /// proxy flag, which is what a reconciler needs to decide what to change.
    ///
    /// Requires: `DNS: Read` (zone-scoped).
    pub async fn list_dns_records(
        &self,
        zone_id: &str,
        name: Option<&str>,
        record_type: Option<&str>,
    ) -> Result<Vec<DnsRecordDetail>> {
        let mut query = format!("/zones/{zone_id}/dns_records?per_page=100");
        if let Some(n) = name {
            query.push_str(&format!("&name={n}"));
        }
        if let Some(t) = record_type {
            query.push_str(&format!("&type={t}"));
        }
        let resp: CfPage<DnsRecordDetail> = self.cf_get(&query).await?;
        self.ok(&resp.success, &resp.errors)?;
        Ok(resp.result.unwrap_or_default())
    }

    /// Delete all DNS records in `zone_id` whose name matches `name` (and
    /// optionally `record_type`). Returns the count of records deleted.
    /// A count of 0 is not an error — the records may already have been absent.
    ///
    /// Requires: `DNS: Edit` (zone-scoped).
    pub async fn delete_dns_records(
        &self,
        zone_id: &str,
        name: &str,
        record_type: Option<&str>,
    ) -> Result<u32> {
        self.delete_dns_records_matching(zone_id, name, record_type, None)
            .await
    }

    /// [`delete_dns_records`](Self::delete_dns_records) narrowed to records
    /// carrying one exact value — R859-F1.
    ///
    /// A round-robin apex holds several A records under one name, so
    /// "delete the A records at `yah.dev`" is not a way to withdraw *one*
    /// origin: it takes the live ones with it. `content = Some(ip)` deletes
    /// only the withdrawn member.
    ///
    /// Requires: `DNS: Edit` (zone-scoped).
    pub async fn delete_dns_records_matching(
        &self,
        zone_id: &str,
        name: &str,
        record_type: Option<&str>,
        content: Option<&str>,
    ) -> Result<u32> {
        let ids: Vec<String> = self
            .list_dns_records(zone_id, Some(name), record_type)
            .await?
            .into_iter()
            .filter(|r| content.is_none_or(|c| r.content == c))
            .map(|r| r.id)
            .collect();
        let mut deleted = 0u32;
        for id in &ids {
            let del: CfSingle<serde_json::Value> = self
                .cf_delete(&format!("/zones/{zone_id}/dns_records/{id}"))
                .await?;
            self.ok(&del.success, &del.errors)?;
            deleted += 1;
        }
        Ok(deleted)
    }

    /// Fetch the ID of the first DNS record matching `name` and `record_type`.
    /// Returns `None` when no matching record exists.
    async fn find_dns_record(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> Result<Option<String>> {
        #[derive(Deserialize)]
        struct RecordEntry {
            id: String,
        }
        let resp: CfPage<RecordEntry> = self
            .cf_get(&format!(
                "/zones/{zone_id}/dns_records?name={name}&type={record_type}"
            ))
            .await?;
        self.ok(&resp.success, &resp.errors)?;
        Ok(resp
            .result
            .unwrap_or_default()
            .into_iter()
            .next()
            .map(|r| r.id))
    }

    /// List R2 buckets in `account_id`.
    /// Requires: `Account: Cloudflare R2: Read`.
    ///
    /// Unlike `/accounts` and `/zones`, the R2 list endpoint nests the array
    /// under `result.buckets` rather than returning `result` as a bare array,
    /// so it needs `CfSingle<R2ListResult>` and not `CfPage<BucketEntry>`.
    pub async fn list_r2_buckets(&self, account_id: &str) -> Result<Vec<R2BucketInfo>> {
        #[derive(Deserialize)]
        struct BucketEntry {
            name: String,
            #[serde(default)]
            location: Option<String>,
            #[serde(default)]
            creation_date: Option<String>,
        }
        #[derive(Deserialize)]
        struct R2ListResult {
            #[serde(default)]
            buckets: Vec<BucketEntry>,
        }
        let resp: CfSingle<R2ListResult> = self
            .cf_get(&format!("/accounts/{account_id}/r2/buckets"))
            .await?;
        self.ok(&resp.success, &resp.errors)?;
        Ok(resp
            .result
            .map(|r| r.buckets)
            .unwrap_or_default()
            .into_iter()
            .map(|b| R2BucketInfo {
                name: b.name,
                location: b.location,
                creation_date: b.creation_date,
            })
            .collect())
    }

    /// List R2 custom-domain bindings on `bucket_name`.
    ///
    /// Requires: `Workers R2 Storage: Read` (or Write, which implies Read).
    /// The response nests the array under `result.domains`, mirroring
    /// `list_r2_buckets`'s `result.buckets` shape.
    pub async fn list_r2_custom_domains(
        &self,
        account_id: &str,
        bucket_name: &str,
    ) -> Result<Vec<R2CustomDomain>> {
        #[derive(Deserialize)]
        struct DomainEntry {
            domain: String,
            #[serde(default)]
            enabled: bool,
        }
        #[derive(Deserialize)]
        struct R2DomainListResult {
            #[serde(default)]
            domains: Vec<DomainEntry>,
        }
        let resp: CfSingle<R2DomainListResult> = self
            .cf_get(&format!(
                "/accounts/{account_id}/r2/buckets/{bucket_name}/domains/custom"
            ))
            .await?;
        self.ok(&resp.success, &resp.errors)?;
        Ok(resp
            .result
            .map(|r| r.domains)
            .unwrap_or_default()
            .into_iter()
            .map(|d| R2CustomDomain {
                domain: d.domain,
                enabled: d.enabled,
            })
            .collect())
    }

    /// Bind a custom domain to an R2 bucket.
    ///
    /// `zone_id` names the zone that owns `domain` (resolve via
    /// [`Self::zone_id_for_name`]). CF requires it so the CNAME write into
    /// that zone is authorized — even though the caller is the bucket-side
    /// API. CF creates the CNAME automatically; no separate DNS-side call.
    /// Requires: `Workers R2 Storage: Edit` (account-scoped).
    ///
    /// `enabled: true` activates the binding immediately. CF still has to
    /// validate ownership + provision TLS in the background — the binding
    /// returns success the moment the record is queued, not when the
    /// hostname is fully resolvable. First-time DNS propagation is on the
    /// order of seconds to a minute.
    pub async fn add_r2_custom_domain(
        &self,
        account_id: &str,
        bucket_name: &str,
        domain: &str,
        zone_id: &str,
    ) -> Result<()> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct AddBody<'a> {
            domain: &'a str,
            enabled: bool,
            zone_id: &'a str,
        }
        let resp: CfSingle<serde_json::Value> = self
            .cf_post(
                &format!("/accounts/{account_id}/r2/buckets/{bucket_name}/domains/custom"),
                &AddBody {
                    domain,
                    enabled: true,
                    zone_id,
                },
            )
            .await?;
        self.ok(&resp.success, &resp.errors)
    }

    /// Fetch the account's permission-group catalog as a name → id map, used
    /// to resolve [`TokenGrant`] names before minting a token. Requires the
    /// calling token to carry `API Tokens: Read` (implied by `Write`).
    pub async fn list_permission_group_ids(
        &self,
        account_id: &str,
    ) -> Result<std::collections::BTreeMap<String, String>> {
        #[derive(Deserialize)]
        struct PgEntry {
            id: String,
            name: String,
        }
        let resp: CfPage<PgEntry> = self
            .cf_get(&format!(
                "/accounts/{account_id}/tokens/permission_groups?per_page=500"
            ))
            .await?;
        self.ok(&resp.success, &resp.errors)?;
        Ok(resp
            .result
            .unwrap_or_default()
            .into_iter()
            .map(|p| (p.name, p.id))
            .collect())
    }

    /// Mint an **account-owned** API token under `account_id` from `grants`
    /// scoped to `account_id` + `zone_id`.
    ///
    /// Resolves each grant's permission-group name against the live catalog
    /// (falling back to its baked-in ID), groups the IDs into account- and
    /// zone-scoped policy blocks, and POSTs to `/accounts/{id}/tokens`.
    /// Requires the calling token to carry `API Tokens: Write` — but the
    /// minted token is bounded by the *account's* access, not the calling
    /// token's, so the caller may hold only `API Tokens: Write`.
    ///
    /// The returned [`CreateTokenResult::value`] is the secret — Cloudflare
    /// reveals it only here.
    pub async fn create_account_token(
        &self,
        account_id: &str,
        zone_id: &str,
        token_name: &str,
        grants: &[TokenGrant],
    ) -> Result<CreateTokenResult> {
        // A catalog lookup failure is non-fatal: build_token_body falls back
        // to the baked-in IDs for any name the (empty) catalog can't resolve.
        let catalog = self
            .list_permission_group_ids(account_id)
            .await
            .unwrap_or_default();
        let body = build_token_body(token_name, account_id, zone_id, grants, &catalog);

        let resp: CfSingle<CreateTokenResult> = self
            .cf_post(&format!("/accounts/{account_id}/tokens"), &body)
            .await?;
        self.ok(&resp.success, &resp.errors)?;
        resp.result
            .ok_or_else(|| anyhow!("token create: no result in response"))
    }

    // ---------- HTTP helpers ----------

    async fn cf_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{CF_API}{path}");
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("GET {url}: {e}"))?;
        resp.json::<T>()
            .await
            .map_err(|e| anyhow!("GET {url} parse: {e}"))
    }

    async fn cf_post<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = format!("{CF_API}{path}");
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow!("POST {url}: {e}"))?;
        resp.json::<T>()
            .await
            .map_err(|e| anyhow!("POST {url} parse: {e}"))
    }

    async fn cf_put<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = format!("{CF_API}{path}");
        let resp = self
            .http
            .put(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow!("PUT {url}: {e}"))?;
        resp.json::<T>()
            .await
            .map_err(|e| anyhow!("PUT {url} parse: {e}"))
    }

    async fn cf_delete<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{CF_API}{path}");
        let resp = self
            .http
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("DELETE {url}: {e}"))?;
        resp.json::<T>()
            .await
            .map_err(|e| anyhow!("DELETE {url} parse: {e}"))
    }

    /// R907-B1 addendum: the numeric error CODE is carried into the returned
    /// message alongside the text, not dropped. Before this, a caller (and
    /// anyone debugging from outside the process) could only see the
    /// message string — which is exactly why `is_resource_not_found`'s 1003
    /// had to be sourced from third-party reverse-engineering instead of
    /// read off a live failure. The next live "Configuration for tunnel not
    /// found" this produces will show its real code plainly.
    fn ok(&self, success: &bool, errors: &Option<Vec<serde_json::Value>>) -> Result<()> {
        if *success {
            return Ok(());
        }
        let entries = errors.as_deref().unwrap_or(&[]);
        if entries.is_empty() {
            return Err(anyhow!("Cloudflare returned an error"));
        }
        let rendered: Vec<String> = entries
            .iter()
            .map(|e| {
                let msg = e
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("(no message)");
                match e.get("code").and_then(|c| c.as_i64()) {
                    Some(code) => format!("Cloudflare error {code}: {msg}"),
                    None => format!("Cloudflare error: {msg}"),
                }
            })
            .collect();
        Err(anyhow!("{}", rendered.join("; ")))
    }

    /// Classifies a failed response as "the resource has never been
    /// created" (an EMPTY read, safe to treat as absent) rather than a
    /// genuine failure (auth, rate limit, transient API error). Callers
    /// must still call [`Self::ok`] for anything this returns `false` for —
    /// it only tells you when NOT to.
    ///
    /// Classified on the error CODE, not the message text: Cloudflare
    /// answers a not-yet-created tunnel configuration with code 1003, the
    /// same generic "not found" family it uses for a missing account or
    /// zone lookup. That code is not in Cloudflare's own published API
    /// reference as of 2026-09-14 (checked: the docs site lists only the
    /// generic `{code, message}` error shape, no per-condition table) —
    /// grounded instead from convergent third-party Cloudflare API clients
    /// that hardcode it: `vana-com/vana-connect`'s
    /// `connect/src/lib/server-provider/gcp.ts` comment "1003: tunnel not
    /// found", `mandar-karhade/dockflare`'s
    /// `docs/design/03-cloudflare-integration.md` error table "1003 | Zone
    /// not found", and several independent test fixtures (e.g.
    /// `ratazzi/coulson`, `MauroDruwel/TunnelDashDesktop`) using 1003 for
    /// "Invalid or missing account id" / "Account not found". Confirming
    /// against a live Cloudflare token is out of scope for R907-B1.
    fn is_resource_not_found(errors: &Option<Vec<serde_json::Value>>) -> bool {
        const CF_ERR_NOT_FOUND: i64 = 1003;
        errors
            .iter()
            .flatten()
            .filter_map(|e| e.get("code").and_then(|c| c.as_i64()))
            .any(|code| code == CF_ERR_NOT_FOUND)
    }
}

// ---------- worker-upload helpers (pure, network-free) ----------

/// Build a `multipart/form-data` body for uploading a CF Worker script with
/// typed bindings for runtime config.
///
/// Each [`WorkerBinding`] becomes one entry in the Worker metadata's
/// `bindings` array — plain_text strings, R2 bucket references, etc.
///
/// Returns `(content_type_header_value, raw_body_bytes)`.
fn build_worker_multipart(script_js: &str, bindings: &[WorkerBinding<'_>]) -> (String, Vec<u8>) {
    const BOUNDARY: &str = "yahWorkerUpload0";
    const SCRIPT_FILENAME: &str = "worker.js";
    let binding_json: Vec<serde_json::Value> = bindings
        .iter()
        .map(|b| match *b {
            WorkerBinding::PlainText { name, text } => serde_json::json!({
                "type": "plain_text",
                "name": name,
                "text": text,
            }),
            WorkerBinding::R2Bucket { name, bucket_name } => serde_json::json!({
                "type": "r2_bucket",
                "name": name,
                "bucket_name": bucket_name,
            }),
        })
        .collect();
    let metadata = serde_json::json!({
        "main_module": SCRIPT_FILENAME,
        "bindings": binding_json,
    });
    let mut body: Vec<u8> = Vec::new();
    let push = |v: &mut Vec<u8>, s: &str| v.extend_from_slice(s.as_bytes());
    // metadata part
    push(&mut body, &format!("--{BOUNDARY}\r\n"));
    push(
        &mut body,
        "Content-Disposition: form-data; name=\"metadata\"\r\n",
    );
    push(&mut body, "Content-Type: application/json\r\n\r\n");
    push(&mut body, &metadata.to_string());
    push(&mut body, "\r\n");
    // script part
    push(&mut body, &format!("--{BOUNDARY}\r\n"));
    push(&mut body, &format!(
        "Content-Disposition: form-data; name=\"{SCRIPT_FILENAME}\"; filename=\"{SCRIPT_FILENAME}\"\r\n"
    ));
    push(
        &mut body,
        "Content-Type: application/javascript+module\r\n\r\n",
    );
    push(&mut body, script_js);
    push(&mut body, &format!("\r\n--{BOUNDARY}--\r\n"));
    (format!("multipart/form-data; boundary={BOUNDARY}"), body)
}

// ---------- token-create helpers (pure, network-free) ----------

/// Resolve a grant's permission-group ID: prefer the live catalog entry for its
/// name, fall back to the baked-in constant.
fn resolve_grant_id(
    grant: &TokenGrant,
    catalog: &std::collections::BTreeMap<String, String>,
) -> String {
    catalog
        .get(grant.group_name)
        .cloned()
        .unwrap_or_else(|| grant.fallback_id.to_string())
}

/// Build the `POST /accounts/{id}/tokens` request body for `grants`, grouping
/// account- and zone-scoped permission groups into separate policy blocks
/// (Cloudflare rejects a single block mixing the two scopes). A scope with no
/// grants produces no block.
fn build_token_body(
    token_name: &str,
    account_id: &str,
    zone_id: &str,
    grants: &[TokenGrant],
    catalog: &std::collections::BTreeMap<String, String>,
) -> serde_json::Value {
    let ids_for = |scope: GrantScope| -> Vec<serde_json::Value> {
        grants
            .iter()
            .filter(|g| g.scope == scope)
            .map(|g| serde_json::json!({ "id": resolve_grant_id(g, catalog) }))
            .collect()
    };
    let block = |resource: String, groups: Vec<serde_json::Value>| -> Option<serde_json::Value> {
        if groups.is_empty() {
            return None;
        }
        let mut resources = serde_json::Map::new();
        resources.insert(resource, serde_json::Value::String("*".into()));
        Some(serde_json::json!({
            "effect": "allow",
            "resources": serde_json::Value::Object(resources),
            "permission_groups": groups,
        }))
    };

    let policies: Vec<serde_json::Value> = [
        block(
            format!("com.cloudflare.api.account.{account_id}"),
            ids_for(GrantScope::Account),
        ),
        block(
            format!("com.cloudflare.api.account.zone.{zone_id}"),
            ids_for(GrantScope::Zone),
        ),
    ]
    .into_iter()
    .flatten()
    .collect();

    serde_json::json!({ "name": token_name, "policies": policies })
}

// ---------- drift helpers (pure, network-free) ----------

/// Normalise a DNS name/target for comparison: trim, drop a single trailing
/// dot, lowercase. So `yah.dev.` and `YAH.DEV` both compare equal to `yah.dev`.
fn norm_dns(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Pick the most specific accessible zone for `hostname` — the longest
/// zone-name suffix that is the apex of, or a parent of, the hostname.
/// Returns the matching zone id, or `None` when no accessible zone covers it.
fn best_zone_for<'a>(hostname: &str, zones: &'a [(String, String)]) -> Option<&'a str> {
    let h = norm_dns(hostname);
    zones
        .iter()
        .filter(|(_, name)| {
            let z = norm_dns(name);
            h == z || h.ends_with(&format!(".{z}"))
        })
        .max_by_key(|(_, name)| name.len())
        .map(|(id, _)| id.as_str())
}

/// Classify drift for one ingress hostname against the live records fetched
/// for it. `live` is the zone's records (filtered by name upstream, but we
/// re-filter defensively so this stays a self-contained pure function).
fn classify_tunnel_drift(
    hostname: &str,
    expected_target: &str,
    live: &[CfDnsRecord],
) -> (TunnelDriftState, Option<String>) {
    let h = norm_dns(hostname);
    let matching: Vec<&CfDnsRecord> = live.iter().filter(|r| norm_dns(&r.name) == h).collect();
    if matching.is_empty() {
        return (TunnelDriftState::Missing, None);
    }
    let want = norm_dns(expected_target);
    if matching.iter().any(|r| norm_dns(&r.content) == want) {
        return (TunnelDriftState::Synced, None);
    }
    (
        TunnelDriftState::Mismatch,
        Some(matching[0].content.clone()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, content: &str) -> CfDnsRecord {
        CfDnsRecord {
            name: name.into(),
            content: content.into(),
        }
    }

    /// R907-B1: a tunnel that has never had a configuration PUT is an EMPTY
    /// read, not a failed one — pins the not-found code on the "treat as
    /// empty" side of `is_resource_not_found`.
    #[test]
    fn resource_not_found_classifies_missing_tunnel_config_as_empty() {
        let errors = Some(vec![serde_json::json!({
            "code": 1003,
            "message": "Configuration for tunnel not found",
        })]);
        assert!(CloudflareClient::is_resource_not_found(&errors));
    }

    /// R907-B1: a genuine failure (here, an auth error) must still surface
    /// as `Err` from `tunnel_configuration` — this is what keeps the
    /// abort-before-PUT guard at reconciler/ingress.rs:1272-1276 correct.
    #[test]
    fn resource_not_found_does_not_classify_auth_error_as_empty() {
        let errors = Some(vec![serde_json::json!({
            "code": 10000,
            "message": "Authentication error",
        })]);
        assert!(!CloudflareClient::is_resource_not_found(&errors));
    }

    #[test]
    fn resource_not_found_false_when_no_errors_present() {
        assert!(!CloudflareClient::is_resource_not_found(&None));
    }

    /// R907-B1 addendum: `ok`'s error text must carry the numeric code, not
    /// just the message — that's what lets the next live failure name its
    /// real Cloudflare code instead of forcing another reverse-engineering
    /// pass like the one that produced `is_resource_not_found`'s 1003.
    #[test]
    fn ok_error_message_carries_the_cloudflare_code() {
        let client = CloudflareClient::new("test-token".to_string());
        let errors = Some(vec![serde_json::json!({
            "code": 1003,
            "message": "Configuration for tunnel not found",
        })]);
        let err = client.ok(&false, &errors).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Cloudflare error 1003: Configuration for tunnel not found"
        );
    }

    #[test]
    fn ok_error_message_joins_multiple_errors() {
        let client = CloudflareClient::new("test-token".to_string());
        let errors = Some(vec![
            serde_json::json!({"code": 1003, "message": "first"}),
            serde_json::json!({"code": 9109, "message": "second"}),
        ]);
        let err = client.ok(&false, &errors).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Cloudflare error 1003: first; Cloudflare error 9109: second"
        );
    }

    #[test]
    fn ok_error_message_falls_back_when_no_errors_present() {
        let client = CloudflareClient::new("test-token".to_string());
        let err = client.ok(&false, &None).unwrap_err();
        assert_eq!(err.to_string(), "Cloudflare returned an error");
    }

    #[test]
    fn drift_synced_when_live_matches() {
        let live = vec![rec("yubaba.yah.dev", "9e4d.cfargotunnel.com")];
        let (state, target) =
            classify_tunnel_drift("yubaba.yah.dev", "9e4d.cfargotunnel.com", &live);
        assert_eq!(state, TunnelDriftState::Synced);
        assert!(target.is_none());
    }

    #[test]
    fn drift_missing_when_no_matching_record() {
        let live = vec![rec("other.yah.dev", "x.cfargotunnel.com")];
        let (state, target) =
            classify_tunnel_drift("yubaba.yah.dev", "9e4d.cfargotunnel.com", &live);
        assert_eq!(state, TunnelDriftState::Missing);
        assert!(target.is_none());
    }

    #[test]
    fn drift_missing_when_zone_empty() {
        let (state, _) = classify_tunnel_drift("yubaba.yah.dev", "9e4d.cfargotunnel.com", &[]);
        assert_eq!(state, TunnelDriftState::Missing);
    }

    #[test]
    fn drift_mismatch_surfaces_live_target() {
        let live = vec![rec("yubaba.yah.dev", "stale.cfargotunnel.com")];
        let (state, target) =
            classify_tunnel_drift("yubaba.yah.dev", "9e4d.cfargotunnel.com", &live);
        assert_eq!(state, TunnelDriftState::Mismatch);
        assert_eq!(target.as_deref(), Some("stale.cfargotunnel.com"));
    }

    #[test]
    fn drift_normalises_trailing_dot_and_case() {
        // Cloudflare returns FQDNs and CNAME content with/without trailing dots
        // and arbitrary case; normalisation must treat these as synced.
        let live = vec![rec("Yubaba.YAH.dev.", "9E4D.cfargotunnel.com.")];
        let (state, _) = classify_tunnel_drift("yubaba.yah.dev", "9e4d.cfargotunnel.com", &live);
        assert_eq!(state, TunnelDriftState::Synced);
    }

    #[test]
    fn best_zone_picks_longest_suffix() {
        let zones = vec![
            ("z_apex".to_string(), "dev".to_string()),
            ("z_zone".to_string(), "yah.dev".to_string()),
        ];
        assert_eq!(best_zone_for("yubaba.yah.dev", &zones), Some("z_zone"));
        assert_eq!(best_zone_for("yah.dev", &zones), Some("z_zone"));
    }

    #[test]
    fn best_zone_none_when_no_suffix_covers() {
        let zones = vec![("z1".to_string(), "yah.dev".to_string())];
        assert_eq!(best_zone_for("example.com", &zones), None);
        // A label that merely ends in the zone string but isn't a subdomain
        // must NOT match: `notyah.dev` is not under `yah.dev`.
        assert_eq!(best_zone_for("notyah.dev", &zones), None);
    }

    #[test]
    fn best_zone_apex_self_match() {
        let zones = vec![("z1".to_string(), "yah.dev".to_string())];
        assert_eq!(best_zone_for("yah.dev", &zones), Some("z1"));
    }

    #[test]
    fn token_body_splits_scopes_and_resolves_ids() {
        use std::collections::BTreeMap;
        // Catalog overrides Zone Read's id; everything else falls back to the
        // baked-in constant.
        let mut catalog = BTreeMap::new();
        catalog.insert("Zone Read".to_string(), "CATALOG_ZONE_READ".to_string());

        let body = build_token_body("t", "ACCT", "ZONE", MESOFACT_STATIC_GRANTS, &catalog);
        let policies = body["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 2, "one account block + one zone block");

        let acct = &policies[0];
        assert_eq!(acct["resources"]["com.cloudflare.api.account.ACCT"], "*");
        let acct_ids: Vec<&str> = acct["permission_groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["id"].as_str().unwrap())
            .collect();
        assert!(acct_ids.contains(&"c1fde68c7bcc44588cbb6ddbc16d6480")); // Account Settings Read
        assert!(acct_ids.contains(&"bf7481a1826f439697cb59a20b22293e")); // R2 Storage Write
        assert!(acct_ids.contains(&"e086da7e2179491d91ee5f35b3ca210a")); // Workers Scripts Write

        let zone = &policies[1];
        assert_eq!(
            zone["resources"]["com.cloudflare.api.account.zone.ZONE"],
            "*"
        );
        let zone_ids: Vec<&str> = zone["permission_groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["id"].as_str().unwrap())
            .collect();
        assert!(
            zone_ids.contains(&"CATALOG_ZONE_READ"),
            "catalog id wins over fallback"
        );
        assert!(zone_ids.contains(&"0ac90a90249747bca6b047d97f0803e9")); // Zone Transform Rules Write
        assert!(zone_ids.contains(&"28f4b596e7d643029c524985477ae49a")); // Workers Routes Write
        assert!(zone_ids.contains(&"e17beae8b8cb423a99b1730f21238bed")); // Cache Purge
    }

    #[test]
    fn token_body_omits_empty_scope_block() {
        use std::collections::BTreeMap;
        let only_zone = &[TokenGrant {
            group_name: "Zone Read",
            scope: GrantScope::Zone,
            fallback_id: "ZR",
        }];
        let body = build_token_body("t", "A", "Z", only_zone, &BTreeMap::new());
        let policies = body["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 1, "no account block when no account grants");
        assert_eq!(
            policies[0]["resources"]["com.cloudflare.api.account.zone.Z"],
            "*"
        );
    }

    /// R912-F1: TUNNEL_EDIT_GRANTS is account-scoped only, so a token built
    /// from it must carry exactly one policy block (no zone block at all,
    /// not an empty one), with the Tunnel Write permission group.
    #[test]
    fn tunnel_edit_grants_build_account_only_policy() {
        use std::collections::BTreeMap;
        let body = build_token_body("t", "ACCT", "ZONE", TUNNEL_EDIT_GRANTS, &BTreeMap::new());
        let policies = body["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 1, "no zone block for an account-only profile");
        assert_eq!(
            policies[0]["resources"]["com.cloudflare.api.account.ACCT"],
            "*"
        );
        let ids: Vec<&str> = policies[0]["permission_groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["c07321b023e944ff818fec44d8203567"]);
    }

    /// Decode the multipart `metadata` part and return its parsed JSON.
    fn extract_metadata_json(body: &[u8]) -> serde_json::Value {
        let s = std::str::from_utf8(body).expect("multipart body is utf-8 for these tests");
        let (_, after) = s
            .split_once("name=\"metadata\"")
            .expect("metadata part present");
        let (_, after) = after
            .split_once("\r\n\r\n")
            .expect("metadata body delimited");
        let (json, _) = after
            .split_once("\r\n--")
            .expect("metadata terminated by boundary");
        serde_json::from_str(json).expect("metadata JSON parses")
    }

    #[test]
    fn multipart_includes_r2_bucket_binding_metadata() {
        let bindings = [WorkerBinding::R2Bucket {
            name: "CACHE",
            bucket_name: "yah-cr-cache",
        }];
        let (content_type, body) = build_worker_multipart("export default {}", &bindings);

        assert!(
            content_type.starts_with("multipart/form-data; boundary="),
            "content-type advertises multipart with boundary: got {content_type}",
        );

        let metadata = extract_metadata_json(&body);
        assert_eq!(metadata["main_module"], "worker.js");
        let bindings = metadata["bindings"].as_array().expect("bindings array");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0]["type"], "r2_bucket");
        assert_eq!(bindings[0]["name"], "CACHE");
        assert_eq!(bindings[0]["bucket_name"], "yah-cr-cache");
    }

    #[test]
    fn multipart_mixes_plain_text_and_r2_bindings() {
        let bindings = [
            WorkerBinding::PlainText {
                name: "MODE",
                text: "cache",
            },
            WorkerBinding::R2Bucket {
                name: "CACHE",
                bucket_name: "yah-cr-cache",
            },
        ];
        let (_, body) = build_worker_multipart("export default {}", &bindings);

        let metadata = extract_metadata_json(&body);
        let entries = metadata["bindings"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["type"], "plain_text");
        assert_eq!(entries[0]["text"], "cache");
        assert_eq!(entries[1]["type"], "r2_bucket");
        assert_eq!(entries[1]["bucket_name"], "yah-cr-cache");
    }
}
