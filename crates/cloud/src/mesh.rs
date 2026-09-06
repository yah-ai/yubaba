//! Headscale API client and configuration helpers for `yah mesh` operations.
//!
//! The mesh layer manages the Headscale coordinator that all yah-provisioned
//! machines join via Tailscale. Phase 1a runs Headscale on the operator's camp
//! (bootstrap coordinator); Phase 1b promotes it to a cluster machine (R040-F19);
//! Phase 2 adds openraft-based HA (R040-F20/F21).
//!
//! Consumers:
//! - `app/yah/cli/src/mesh.rs` — `yah mesh start/status/backup/restore`
//! - `app/yah/cli/src/cloud.rs` — `yah cloud machine provision` (auto-generates
//!   a Headscale preauth key when `mesh-url` is set in the vault)
//!
//! @yah:relay(R861, "Reconcile an appliance's own API objects: headscale ACLs, users and preauth keys as declared config")
//! @yah:at(2026-09-04T21:07:28Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:gotcha("NOT A NEW CONCEPT — this is the DOMAIN-OBJECT half of a pattern yah already has twice. Framing that produced it (operator, 2026-09-04): asked what \"manage headscale on kubernetes with a rust controller\" looks like, the answer is a CRD + controller for \"deployment instances, users, and pre-auth keys\". yah ALREADY HAS the CRD half (Workload/WorkloadSpec + workload.toml + .yah/schema/workload.toml.schema.json + generated TS) and the controller half (the `Reconciler` trait at oss/yubaba/crates/cloud/src/reconciler/mod.rs:612, ~20 implementations dispatched by `kind`). What is missing is reconciling things INSIDE an appliance rather than the appliance itself. So: no new noun, no operator framework — one more Reconciler implementation, owning headscale's API objects the way cloudflare_worker.rs owns what lives in a Cloudflare account.")
//! @yah:gotcha("THE EVIDENCE THIS IS A LIVE GAP, not a speculative nicety. (1) `headscale-preauth-key` is classified `Band::Automatable` in oss/yah-base/crates/keys/src/spec.rs:768 and its own purpose text says outright \"Automatable: headscale-api-key mints these, and does so per-machine when mesh-url is configured\" — the credential system already knows it should not be a human-held static secret. (2) That automation EXISTS but only ad hoc, in one place, at one moment: provision-time per-machine minting via headscale-api-key. There is no reconciled desired state. (3) `acls.yaml` (77 bytes, mtime Jun 22) sits in /var/lib/yah-cloud/headscale/ and is replicated by NOTHING — litestream carries only headscale.db — so it is failover state nobody enumerated (see R858-T2). Declaring ACLs and reconciling them is what stops that file mattering at all.")
//!
//! @yah:ticket(R861-T1, "Establish whether headscale reads acls.yaml or the DB, then declare ACLs as reconciled config")
//! @yah:status(review)
//! @yah:at(2026-09-04T22:48:06Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R861)
//! @yah:next("THE PATTERN TO COPY IS cloudflare_worker.rs, not a new abstraction: validate declared config fully BEFORE any API call (the R330-B5 fail-fast discipline the reconciler docs already name), then list-first/idempotent writes against headscale's admin API using the existing `headscale-api-key` slot. Consumers of that slot are already listed in the credential spec: oss/yubaba/crates/cloud/src/mesh.rs, app/yah/cli/src/mesh.rs, crates/yah/cloud-client/src/lib.rs.")
//! @yah:gotcha("START WITH THE FACT, NOT THE DESIGN. headscale 0.23 can source policy from a FILE or from the DATABASE depending on its policy mode, and the config block read on us-west-001 2026-09-04 showed no `policy:` section at all — so acls.yaml may be live or may be vestigial. `grep -i policy /var/lib/yah-cloud/headscale/config.yaml` settles it in one look. If vestigial: delete the file so the next reader does not re-discover the same question, and this ticket collapses to the users/preauth half. If live: it is unreplicated failover state today and declaring it is the fix.")
//! @yah:gotcha("PHASE 1 SETTLED — acls.yaml IS LIVE, NOT VESTIGIAL. Measured over SSH on us-west-001 (15.204.89.240) 2026-09-04 by @Ashguard:griffin. /var/lib/yah-cloud/headscale/config.yaml lines 32-34 read exactly `policy:` / `  mode: file` / `  path: /var/lib/yah-cloud/headscale/acls.yaml`. The earlier read that reported no `policy:` section was wrong — the file is 1060 bytes and the block is there. acls.yaml is 77 bytes, mtime Jun 22, and contains the permissive HuJSON default `{\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}]}`. In-tree agrees: ALL THREE renderers emit the same three lines — crate::mesh::generate_headscale_config (oss/yubaba/crates/cloud/src/mesh.rs), generate_remote_headscale_config (oss/yubaba/crates/yubaba/src/lib.rs:4729ff) and generate_bootstrap_headscale_config (same file, :5134ff). So file mode is the DESIRED state today, not drift. Nothing was deleted; the vestigial branch of this ticket does not apply.")
//! @yah:gotcha("POLICY MODE BOUNDS WHAT ANY RECONCILER CAN DO ABOUT ACLS — both halves measured against the live v0.23.0 coordinator 2026-09-04, not inferred. (1) GET /api/v1/policy WORKS IN FILE MODE: authenticated with the vault's headscale-api-key against https://cloud.mesh.yah.dev it returned HTTP 200 and {\"policy\": \"<the acls.yaml bytes>\", \"updatedAt\": null}. (2) PUT /api/v1/policy IS REFUSED IN FILE MODE: the pinned binary carries the string \"This command only works when the acl.policy_mode is set to \" and \", and the policy will be stored in the database.\" — headscale only accepts a policy write in database mode, because in file mode the file is the source of truth and a write would be overwritten at the next reload. CONSEQUENCE, and it is the design of the ACL step: declared-vs-live drift is ALWAYS DETECTABLE, and correctable only on a database-mode coordinator. Also verified from the same binary: /api/v1/user, /api/v1/user/{name}, /api/v1/preauthkey, /api/v1/preauthkey/expire, /api/v1/policy all exist; GET /api/v1/preauthkey?user=yah returned 200 with {\"preAuthKeys\":[{user,id,key,reusable,ephemeral,used,expiration,createdAt,aclTags}]} and 4 live keys. Coordinator has exactly one user, `yah`.")
//! @yah:handoff("LANDED: HeadscaleReconciler, kind=\"headscale\" — one more Reconciler impl, cloudflare_worker.rs's shape, no new noun. NEW FILE oss/yubaba/crates/cloud/src/reconciler/headscale.rs (~700 lines incl. 17 tests). up() order: materialize() -> workload_kind agrees -> DeclaredHeadscale::load() validates EVERYTHING (R330-B5 fail-fast, nothing below runs until every field is checked) -> resolve base_url (declared server_url, else mesh-url/HEADSCALE_URL) + headscale-api-key/HEADSCALE_API_KEY -> users list-then-create (NEVER deletes: a headscale user owns the nodes registered under it) -> preauth keys list-then-mint-if-unsatisfied -> ACL compare-then-push. Returns RunningWorkload::adopted(WORKLOAD_KIND, role, None).with_notes(...); the minted key value never reaches a log line or a note.")
//! @yah:handoff("CLIENT SURFACE ADDED to oss/yubaba/crates/cloud/src/mesh.rs (added alongside the peer hunks already in that file; nothing reverted). New types PreauthKeyRecord (with is_usable_at) and PreauthKeyRequest. New HeadscaleClient methods: create_user (POST /api/v1/user — deliberately does NOT swallow a conflict, since headscale answers 500 for an existing name with no discriminator, so a 500 here means something other than \"already there\"), list_preauth_keys (GET /api/v1/preauthkey?user=), create_preauth_key_with (the general mint), get_policy (GET /api/v1/policy), set_policy (PUT /api/v1/policy). The pre-existing create_preauth_key now delegates to create_preauth_key_with with its historical fixed shape (single-use, 1 hour) so every existing caller is behaviourally untouched. Parsing split into the free fn parse_preauth_key_list, following choose_user's precedent (this crate has no HTTP mock); entries missing id/user/key are DROPPED rather than defaulted, because a half-parsed record would read as \"no matching key exists\" and cause a redundant mint.")
//! @yah:handoff("DECISION I MADE, since the brief left it open: declared config lives in the component's workload.toml under kind-specific tables ([headscale] with users / acl_policy / server_url, and [[headscale.preauth_keys]] with user / tags / reusable / ephemeral / ttl_hours / store_as), parsed ad hoc via toml::Value. This is exactly how cloudflare-worker already reads its [build] and [[bindings]] — the strong workload_spec::Workload types do not model per-kind tables, and I checked .yah/schema/workload.toml.schema.json: no branch of its root oneOf sets additionalProperties:false, so extra tables validate. CONSEQUENCE: oss/yah-base/crates/workload-spec/ was NOT touched, so NO emit-schemas and NO export-ts regen was needed or run. That also kept me clear of oss/yah-base/crates/keys/src/spec.rs, which I read (line 768's Band::Automatable classification) but did not modify, per the leader's read-only instruction — @Ashguard:polaris is live on it for R856-F2.")
//! @yah:handoff("THE ACL STEP IS COMPARE-FIRST, AND THAT IS THE WHOLE POINT ON A FILE-MODE COORDINATOR. get_policy() -> policies_equivalent() -> only on drift does it set_policy(). Comparison is SEMANTIC, not byte: both sides are normalized from HuJSON to serde_json::Value and compared as values, so reformatting or re-commenting the declared file never triggers a spurious push and a genuinely different rule always does. There is no HuJSON crate in this workspace, so parse_hujson strips // and /* */ comments and trailing commas with string-literal tracking (a `//` or a comma inside a value is left alone — tested) and hands the rest to serde_json. On a database-mode coordinator the push lands and the policy ends up in headscale.db, which litestream already replicates — that is the moment acls.yaml stops being unreplicated failover state. On today's file-mode coordinator the push is refused by headscale and the reconciler surfaces that as an error naming the declared file's path and the mode flip that makes it pushable, rather than a silent no-op that reads like success.")
//! @yah:handoff("DELIBERATELY NOT DONE, and it is the one operator call left: I did NOT flip the fleet's rendered policy.mode from file to database. It is a live-coordinator config change that reaches nodes only via a yubaba release + scripts/roll-node.sh, it touches all three renderers, and its correctness turns on what a database-mode headscale with no policy row does to an existing tailnet — which I did not measure and would not guess at fleet scale. It also sits squarely in the operator's stated R858 rehearsal (\"bring us-west-001 down and get a repaired headscale\"), so it wants that rehearsal rather than a reconciler's side effect. Until it flips, this reconciler makes ACL drift LOUD on the current file-mode box; after it flips, the same code makes ACLs actually reconciled and the file irrelevant. Nothing else about the reconciler changes either way.")
//! @yah:handoff("WIRING (all additive, no rewrites): oss/yubaba/crates/cloud/src/reconciler/mod.rs gains `pub mod headscale;` and a re-export of HeadscaleReconciler + DeclaredHeadscale/DeclaredPolicy/DeclaredPreauthKey + WORKLOAD_KIND as HEADSCALE_WORKLOAD_KIND. oss/yubaba/crates/cloud/src/lib.rs: ONE additive name (HeadscaleReconciler) inserted into the existing `pub use reconciler::{...}` list — the single-line limit the leader set for that peer-owned file (@Ashguard:spade is live on it for R850); I touched nothing else there. Both dispatchers gain a \"headscale\" match arm next to \"cloudflare-worker\": app/yah/cli/src/cloud.rs:reconcile_component (~:7091) plus its import at ~:601, and app/yah/desktop/src/mirror_run.rs (~:988) plus its import at ~:168. Cleared with @Glimmerstone:vortex, whose R858-T1 courier (session:9f8108d4) is editing app/yah/cli/src/cloud.rs concurrently — my two regions do not overlap theirs (:1466, :4250-4310, :4871-4909, :7909-8006), and I told them line numbers below :7091 shift by 3.")
//! @yah:verify("cargo build -p yah-cloud: clean (the 2 warnings are pre-existing unused imports in reconciler/mesofact_static.rs:240,245, not mine). cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib = 1059 passed / 0 failed / 4 ignored, against a pre-change baseline of 1042 passed / 0 failed on the same crate — the delta is exactly the 17 new reconciler::headscale::tests, all green. Note yah-cloud is in the oss/yubaba workspace, not the root one: `cargo test -p yah-cloud` from the repo root fails with \"requires dev-dependencies and is not a member of the workspace\"; the --manifest-path form above is the one that runs. cargo check -p desktop: clean (9 pre-existing dead-code warnings). The 17 tests cover: full workload-dir load off disk incl. the HuJSON policy file; a preauth key naming an undeclared user (the R608-B19 typo class, which must fail BEFORE any user is created); tag prefix + lowercase rules; non-positive ttl; duplicate user; non-http server_url; a policy with no top-level `acls` array; a missing policy file naming the path it looked for; reformat-is-not-drift vs a-different-rule-is-drift against the exact bytes live on us-west-001; comment markers inside string values surviving the stripper; and expired / spent / reusable / never-expiring key usability.")
//! @yah:verify("cargo check -p yah = exit 0, Finished clean, no error lines (warnings are the crate's pre-existing 19: unused imports Verdict / CommandFact / NodeId / store / Version and unused variables dt / config_path / acl_path / pid_path, plus dead-code fields — none in a file I touched). Re-run once after reflowing the two `use` blocks, so the green describes the final tree. NOT VERIFIED, STATED PLAINLY: the reconciler has never been executed against a live coordinator — no `yah cloud apply` was run, no user was created, no key was minted, no policy was pushed. Every claim about headscale's API in this ticket comes from read-only GETs against https://cloud.mesh.yah.dev with the vault's headscale-api-key, plus string extraction from the pinned v0.23.0 binary on us-west-001. There is also no live service/mirror definition wired for kind=\"headscale\" anywhere in .yah/services/ — deliberately, since committing one arms a reconcile against the production coordinator, and that is the operator's call, not a courier's. The shape is instead pinned by a test that loads a full workload dir (workload.toml + acls.hujson) off disk and asserts it is already in sync with the exact bytes the live coordinator serves.")
//! @yah:handoff("DISCOVERED WORK DONE, not filed as a followup: R858-T2's own @yah:gotcha on oss/yubaba/crates/yubaba/src/headscale_appliance.rs asks the exact question I answered (\"establish whether this file is live or vestigial ... before designing carriage for it\"), and leaving it open would make the next reader repeat the SSH trip. Wrote a durable @yah:notify_on(R861-T1) into R858-T2 carrying the verdict and what it means for that ticket: while the fleet stays in file mode, acls.yaml is still state a move must carry alongside noise_private.key, and it stops being carriable state only when policy.mode flips to database. That is the only edit I made outside this ticket's own path list, and it is an additive annotation line.")
//! @yah:handoff("PHASE 1 SETTLED BY MEASUREMENT, NOT INFERENCE — acls.yaml is LIVE, not vestigial. us-west-001's /var/lib/yah-cloud/headscale/config.yaml carries `policy:` / `mode: file` / `path: /var/lib/yah-cloud/headscale/acls.yaml` (read over SSH 2026-09-04), and all three in-tree renderers emit the same block. The file was therefore NOT deleted, and the ticket did NOT collapse to the users/preauth half — the ACL half is real work and was done. The 'no policy: section' observation in the filing gotcha was a truncated read of the config.")
//! @yah:handoff("WHAT LANDED: HeadscaleReconciler (kind = \"headscale\") in oss/yubaba/crates/cloud/src/reconciler/headscale.rs, built on cloudflare_worker.rs's shape rather than any new abstraction — exactly the relay's framing of \"one more Reconciler implementation, no new noun\". It reconciles three classes of headscale's own API objects: list-then-create users, list-then-mint preauth keys, and a semantic HuJSON compare-then-push for ACLs. All declared config is validated in full BEFORE the first network call (the R330-B5 fail-fast discipline); independently confirmed at headscale.rs:463, where a preauth key naming an undeclared user is a genuine pre-network bail rather than a doc-comment claim.")
//! @yah:handoff("SUPPORTING SURFACE: five methods added to HeadscaleClient in oss/yubaba/crates/cloud/src/mesh.rs — create_user, list_preauth_keys, create_preauth_key_with, get_policy, set_policy — all against the existing headscale-api-key credential slot, no new credential. This closes the gap R861's evidence named: headscale-preauth-key was already classified Band::Automatable (oss/yah-base/crates/keys/src/spec.rs:768) with automation that existed only ad hoc at provision time, one machine at a time, with no reconciled desired state. There is now a desired state.")
//! @yah:verify("cargo test -p yah-cloud --lib = 1060 passed / 0 failed / 4 ignored. Baseline arithmetic reconciled independently rather than taken on trust: committed baseline is 1019, +17 new tests in headscale.rs (this ticket), +24 in topology.rs (@Ashguard:spade's R850, a separate module that landed concurrently) = 1060. The courier reported 1059 against a 1042 baseline; the off-by-one is a mid-run tree move, not a missing test. Fail-fast validation and the reconciler wiring were re-verified by a second agent reading the source, not by re-reading the courier's claim.")
//! @yah:gotcha("`cargo check -p yah` is RED right now and it is NOT this ticket. Both failure snapshots land entirely in app/yah/cli/src/keys_doctor.rs — 2x E0425 'cannot find value `decision`' at :1574 and :1583 (a half-applied local rename), plus an earlier 9-error E0308/E0599 snapshot consistent with oss/yah-base/crates/keys/src/spec.rs moving underneath it (~207 insertions on `pub enum Provider`, the MINT_* consts, and ~8 points in CREDENTIAL_SPECS). That is @Ashguard:polaris's live R856 work, caught mid-edit; the diagnosis was handed to them directly. Nothing in either trace names headscale, reconciler or mesh, and R861-T1 treated spec.rs as strictly read-only — verified, not assumed.")
//! @yah:gotcha("SHARED-TREE SEAM, disclosed and acknowledged: the HeadscaleReconciler re-export needed one added name in the `pub use reconciler::{…}` list in oss/yubaba/crates/cloud/src/lib.rs (~:307), a file @Ashguard:spade holds for R850. Purely additive — nothing removed or rewritten — but inserting the name pushed MesofactStaticReconciler past the column limit and rustfmt reflowed the pair, so the diff footprint reads -1/+2 rather than +1. @Ashguard:spade was notified and confirmed no conflict: their only line in that file is `pub mod topology;` at ~:272, a different region. Separately, the crate has NO rustfmt.toml and is pervasively fmt-dirty (~30 files, config.rs alone has 28 sites), so this reflow adds no new gate risk.")
//! @yah:gotcha("DO NOT run rustfmt in write mode against oss/yubaba/crates/cloud/src/lib.rs. rustfmt follows `mod` declarations, so a write-mode run on that one file rewrites ~30 files and 100+ sites across the crate — most of it peers' uncommitted in-flight code. That is precisely the shape of the 2026-08-28 incident recorded in CLAUDE.md, where a cargo fmt followed path deps into a peer's crate and undoing it cost 827 uncommitted lines. Use `rustfmt --check` and read the file list first. Surfaced by @Ashguard:spade while checking this ticket's reflow.")
//! @yah:handoff("NOT COMMITTED, deliberately. The shared index currently reads as staged by someone other than this ticket's worker, so nothing here was committed — a bare `git commit` on this tree would sweep in peers' work. Whoever signs this off should commit pathspec-scoped: oss/yubaba/crates/cloud/src/reconciler/headscale.rs, oss/yubaba/crates/cloud/src/reconciler/mod.rs, oss/yubaba/crates/cloud/src/mesh.rs, and the single-line lib.rs hunk. Tree anchor at dispatch: 6f193f90c6533329877804577c02d75ca57b2f98.")
//! @yah:handoff("REMAINING WORK IS FILED, NOT PARKED HERE: R861-T2 (blocked_on operator) carries the one open call — the fleet is still on `policy.mode: file`, so the reconciler WRITES acls.yaml rather than making it stop existing. litestream replicates only headscale.db, so policy is now reconstructible-from-declared-config but is still unreplicated on-disk state. Flipping to mode=database closes it completely; that is a live-infrastructure change with a migration sequence and no defensible default, so it was deliberately left alone.")

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Headscale REST API client
// ---------------------------------------------------------------------------

/// HTTP client for a running Headscale coordinator.
///
/// The Headscale REST API lives at `<server_url>/api/v1/…`. Requests are
/// authenticated with an API key in the `Authorization: Bearer <key>` header.
/// The API key must be created on the coordinator with `headscale apikeys create`
/// or the equivalent API call; store it in the vault as `headscale-api-key`.
pub struct HeadscaleClient {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
}

/// A Headscale pre-authentication key for onboarding a new node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreauthKey {
    /// The key string to pass to `tailscale up --auth-key=<key>`.
    pub key: String,
    /// ACL tags the new node will be advertised with.
    pub acl_tags: Vec<String>,
}

/// One pre-auth key as the coordinator reports it (`GET /api/v1/preauthkey`).
///
/// Field names are the protojson camelCase spelling headscale's grpc-gateway
/// emits; the shape was read off the live v0.23.0 coordinator on 2026-09-04:
/// `{"preAuthKeys":[{user,id,key,reusable,ephemeral,used,expiration,createdAt,aclTags}]}`.
/// `expiration` is RFC3339 and may be absent for a never-expiring key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreauthKeyRecord {
    pub id: String,
    pub user: String,
    pub key: String,
    pub reusable: bool,
    pub ephemeral: bool,
    pub used: bool,
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
    pub acl_tags: Vec<String>,
}

impl PreauthKeyRecord {
    /// Whether this key can still onboard a node at `now`: not past its
    /// expiry, and either reusable or not yet spent.
    pub fn is_usable_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        let unexpired = self.expiration.map(|e| e > now).unwrap_or(true);
        unexpired && (self.reusable || !self.used)
    }
}

/// Everything `POST /api/v1/preauthkey` needs. Split out from
/// [`HeadscaleClient::create_preauth_key`]'s fixed single-use/1-hour shape so a
/// reconciler can mint the standing, reusable keys a declared spec asks for.
#[derive(Debug, Clone)]
pub struct PreauthKeyRequest {
    pub user: String,
    pub tags: Vec<String>,
    pub reusable: bool,
    pub ephemeral: bool,
    pub ttl_hours: i64,
}

/// Summary information about a node in the Headscale tailnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub name: String,
    pub ip_addresses: Vec<String>,
    pub online: bool,
}

/// Headscale version + health response.
#[derive(Debug, Clone)]
pub struct HeadscaleHealth {
    pub reachable: bool,
    pub status_code: u16,
}

impl HeadscaleClient {
    /// Construct a client from explicit credentials.
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("building Headscale HTTP client")?;
        Ok(Self {
            base_url,
            api_key: api_key.into(),
            http,
        })
    }

    /// Open a client from the vault (slot `headscale-api-key` + `mesh-url`)
    /// with env-var fallbacks (`HEADSCALE_API_KEY` + `HEADSCALE_URL`).
    ///
    /// Returns `Ok(None)` when either credential is absent — callers can
    /// decide whether that's fatal.
    pub fn from_vault_or_env() -> Result<Option<Self>> {
        let api_key = match fob::get_or_env("headscale-api-key", "HEADSCALE_API_KEY")? {
            Some(k) => k,
            None => return Ok(None),
        };
        let url = match fob::get_or_env("mesh-url", "HEADSCALE_URL")? {
            Some(u) => u,
            None => return Ok(None),
        };
        Ok(Some(Self::new(url, api_key)?))
    }

    /// Generate a single-use pre-auth key for the given ACL tags.
    ///
    /// The key expires in 1 hour and is non-reusable — suitable for one-shot
    /// machine onboarding via cloud-init. Each `yah cloud machine provision`
    /// call that uses Headscale mesh should request its own key.
    pub async fn create_preauth_key(&self, user: &str, tags: &[String]) -> Result<PreauthKey> {
        self.create_preauth_key_with(&PreauthKeyRequest {
            user: user.to_string(),
            tags: tags.to_vec(),
            reusable: false,
            ephemeral: false,
            ttl_hours: 1,
        })
        .await
    }

    /// Mint a pre-auth key with an explicit lifetime and reuse policy.
    ///
    /// The general form behind [`create_preauth_key`](Self::create_preauth_key).
    /// A reconciled desired state wants a *standing* key (reusable, long TTL)
    /// rather than the one-shot hour-long key a single provision needs, and
    /// both shapes are the same `POST /api/v1/preauthkey`.
    pub async fn create_preauth_key_with(&self, req: &PreauthKeyRequest) -> Result<PreauthKey> {
        let expiration = chrono::Utc::now()
            + chrono::TimeDelta::try_hours(req.ttl_hours).ok_or_else(|| {
                anyhow::anyhow!("overflow computing {}-hour expiry", req.ttl_hours)
            })?;
        let user = req.user.as_str();
        let tags = req.tags.as_slice();
        let body = serde_json::json!({
            "user": user,
            "expiration": expiration.to_rfc3339(),
            "reusable": req.reusable,
            "ephemeral": req.ephemeral,
            "aclTags": tags,
        });
        let resp = self
            .http
            .post(format!("{}/api/v1/preauthkey", self.base_url))
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .context("POST /api/v1/preauthkey")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Headscale API {status} on POST /api/v1/preauthkey: {text}");
        }
        let resp_json: serde_json::Value =
            resp.json().await.context("parsing preauthkey response")?;
        let key = resp_json["preAuthKey"]["key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing preAuthKey.key in response: {resp_json}"))?;
        Ok(PreauthKey {
            key: key.to_string(),
            acl_tags: tags.to_vec(),
        })
    }

    /// List all nodes currently in the tailnet.
    ///
    /// Uses Headscale's `GET /api/v1/node` (the endpoint was renamed from the
    /// pre-v0.23 `/api/v1/machine`, with the response key `machines` → `nodes`,
    /// when Headscale retired "machine" for "node"). The per-node JSON shape is
    /// otherwise unchanged (`id`, `name`, `ipAddresses`, `online`).
    pub async fn list_nodes(&self) -> Result<Vec<NodeInfo>> {
        let resp = self
            .http
            .get(format!("{}/api/v1/node", self.base_url))
            .bearer_auth(&self.api_key)
            .send()
            .await
            .context("GET /api/v1/node")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Headscale API {status} on GET /api/v1/node: {text}");
        }
        let resp_json: serde_json::Value = resp.json().await.context("parsing node list")?;
        let nodes = resp_json["nodes"].as_array().cloned().unwrap_or_default();
        Ok(nodes
            .iter()
            .filter_map(|m| {
                Some(NodeInfo {
                    id: m["id"].as_str()?.to_string(),
                    name: m["name"].as_str()?.to_string(),
                    ip_addresses: m["ipAddresses"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default(),
                    online: m["online"].as_bool().unwrap_or(false),
                })
            })
            .collect())
    }

    /// List the Headscale users (namespaces) preauth keys can be minted against.
    ///
    /// `GET /api/v1/user`. Headscale scopes every preauth key to a user, and a
    /// key minted against a user that does not exist fails at mint time.
    pub async fn list_users(&self) -> Result<Vec<String>> {
        let resp = self
            .http
            .get(format!("{}/api/v1/user", self.base_url))
            .bearer_auth(&self.api_key)
            .send()
            .await
            .context("GET /api/v1/user")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Headscale API {status} on GET /api/v1/user: {text}");
        }
        let resp_json: serde_json::Value = resp.json().await.context("parsing user list")?;
        Ok(resp_json["users"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|u| u["name"].as_str().map(str::to_string))
            .collect())
    }

    /// Resolve the user to mint a preauth key against, asking the coordinator
    /// instead of assuming a name.
    ///
    /// R608-B19: this used to be the literal `"default"` at the
    /// `yah cloud machine provision` call site, and against the live
    /// coordinator that is simply wrong — `POST /api/v1/preauthkey` answers
    /// **500** for a user that does not exist. The two halves of the system
    /// disagree on the name: [`crate::mesh`]'s camp-local `yah mesh start` path
    /// creates `default` (its `--user` default), while `yah mesh bootstrap`
    /// creates `yah` (`mint_bootstrap_preauth_key` in yubaba's lib.rs runs
    /// `headscale users create yah`). The production coordinator was
    /// bootstrapped, so it has only `yah` — every provision against it would
    /// have failed at the preauth step with an opaque 500.
    ///
    /// Rather than swap one hardcoded guess for the other:
    ///
    /// - `preferred` present and known to the coordinator → use it;
    /// - `preferred` absent and the coordinator has exactly one user → use it,
    ///   which is every yah mesh in existence today;
    /// - otherwise → error naming the users that DO exist, so the operator can
    ///   pick, instead of a 500 that names nothing.
    pub async fn resolve_user(&self, preferred: Option<&str>) -> Result<String> {
        let users = self.list_users().await?;
        choose_user(&self.base_url, &users, preferred)
    }

    /// Create a Headscale user (namespace). `POST /api/v1/user`.
    ///
    /// NOT idempotent on headscale's side — creating a name that already
    /// exists answers 500 with no useful discriminator — so every caller must
    /// [`list_users`](Self::list_users) first. That list-then-create shape is
    /// what [`HeadscaleReconciler`](crate::reconciler::HeadscaleReconciler)
    /// does, and it is why this method deliberately does not try to swallow a
    /// conflict itself: a 500 here means something other than "already there".
    pub async fn create_user(&self, name: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/api/v1/user", self.base_url))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({ "name": name }))
            .send()
            .await
            .context("POST /api/v1/user")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Headscale API {status} on POST /api/v1/user (name={name}): {text}");
        }
        Ok(())
    }

    /// List the pre-auth keys minted against `user`.
    /// `GET /api/v1/preauthkey?user=<user>`.
    pub async fn list_preauth_keys(&self, user: &str) -> Result<Vec<PreauthKeyRecord>> {
        let resp = self
            .http
            .get(format!("{}/api/v1/preauthkey", self.base_url))
            .query(&[("user", user)])
            .bearer_auth(&self.api_key)
            .send()
            .await
            .context("GET /api/v1/preauthkey")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Headscale API {status} on GET /api/v1/preauthkey (user={user}): {text}");
        }
        let resp_json: serde_json::Value =
            resp.json().await.context("parsing preauth key list")?;
        Ok(parse_preauth_key_list(&resp_json))
    }

    /// Read the ACL policy the coordinator currently has loaded.
    /// `GET /api/v1/policy` → `{"policy": "<HuJSON>", "updatedAt": …}`.
    ///
    /// Works in BOTH policy modes — measured against the live v0.23.0
    /// coordinator on 2026-09-04, which was still on `policy.mode: file` and
    /// answered 200 with the file's contents. That is what makes drift
    /// *detectable* on a not-yet-migrated coordinator even though
    /// [`set_policy`](Self::set_policy) cannot correct it there.
    ///
    /// R861-T2 read the pinned v0.23.0 `GetPolicy` handler rather than
    /// inferring: in `database` mode it returns the stored row's `Data` string
    /// verbatim, in `file` mode the file's bytes as-is. Same field, same
    /// document, so a caller never has to know which mode answered.
    ///
    /// One consequence worth knowing: a `database`-mode coordinator with no
    /// policy row yet answers with a gRPC error, not an empty string — the
    /// migration treats that as "nothing pushed yet", not as a fault.
    pub async fn get_policy(&self) -> Result<String> {
        let resp = self
            .http
            .get(format!("{}/api/v1/policy", self.base_url))
            .bearer_auth(&self.api_key)
            .send()
            .await
            .context("GET /api/v1/policy")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Headscale API {status} on GET /api/v1/policy: {text}");
        }
        let resp_json: serde_json::Value = resp.json().await.context("parsing policy response")?;
        resp_json["policy"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("missing `policy` string in response: {resp_json}"))
    }

    /// Replace the ACL policy. `PUT /api/v1/policy`.
    ///
    /// **Only legal when the coordinator runs `policy.mode: database`** — the
    /// mode [`POLICY_MODE`] now renders. In `file` mode the pinned v0.23.0
    /// `SetPolicy` handler returns `ErrPolicyUpdateIsDisabled` before looking
    /// at the payload at all, because the file on disk is the source of truth
    /// and a write here would be silently overwritten at the next reload.
    /// Callers get that refusal as an error rather than a no-op success.
    ///
    /// Two properties R861-T2 established from that handler, both load-bearing
    /// for the migration:
    ///
    /// - It validates before storing: the document is parsed with the same
    ///   `LoadACLPolicyFromBytes` a file-mode startup uses, then compiled
    ///   against the live node list (`CompileFilterRules`, and `CompileSSHPolicy`
    ///   when any node exists). A policy headscale would refuse to boot on is
    ///   refused here too, which is why a failed push is safe.
    /// - It APPENDS: `db.SetPolicy` inserts a new `policies` row every call and
    ///   `GetPolicy` reads `ORDER BY id DESC LIMIT 1`. Repeating a push is
    ///   therefore idempotent in effect but not in storage — which is why the
    ///   reconciler and the migration both compare before writing.
    pub async fn set_policy(&self, hujson: &str) -> Result<()> {
        let resp = self
            .http
            .put(format!("{}/api/v1/policy", self.base_url))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({ "policy": hujson }))
            .send()
            .await
            .context("PUT /api/v1/policy")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Headscale API {status} on PUT /api/v1/policy: {text}");
        }
        Ok(())
    }

    /// Light health check — HEAD or GET the Headscale root, no auth required.
    pub async fn health(&self) -> HeadscaleHealth {
        match self
            .http
            .get(format!("{}/health", self.base_url))
            .send()
            .await
        {
            Ok(r) => HeadscaleHealth {
                reachable: r.status().is_success(),
                status_code: r.status().as_u16(),
            },
            Err(_) => HeadscaleHealth {
                reachable: false,
                status_code: 0,
            },
        }
    }
}

/// The parsing half of [`HeadscaleClient::list_preauth_keys`], split out for
/// the same reason [`choose_user`] is: the interesting behaviour is the shape
/// translation, and this crate carries no HTTP mock.
///
/// Entries missing the fields a reconciler needs to *compare* (`id`, `user`,
/// `key`) are dropped rather than defaulted — a half-parsed record would
/// otherwise read as "no matching key exists" and cause a redundant mint.
fn parse_preauth_key_list(resp_json: &serde_json::Value) -> Vec<PreauthKeyRecord> {
    resp_json["preAuthKeys"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|k| {
            Some(PreauthKeyRecord {
                id: k["id"].as_str()?.to_string(),
                user: k["user"].as_str()?.to_string(),
                key: k["key"].as_str()?.to_string(),
                reusable: k["reusable"].as_bool().unwrap_or(false),
                ephemeral: k["ephemeral"].as_bool().unwrap_or(false),
                used: k["used"].as_bool().unwrap_or(false),
                expiration: k["expiration"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&chrono::Utc)),
                acl_tags: k["aclTags"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect()
}

/// The user-selection half of [`HeadscaleClient::resolve_user`], split out so it
/// is testable without standing up an HTTP server — this crate carries no HTTP
/// mock, and the interesting behaviour is entirely in the choice, not the GET.
fn choose_user(base_url: &str, users: &[String], preferred: Option<&str>) -> Result<String> {
    if users.is_empty() {
        anyhow::bail!(
            "Headscale at {base_url} has no users — preauth keys are scoped to one. \
             Create it with `headscale users create yah`."
        );
    }
    if let Some(want) = preferred {
        if users.iter().any(|u| u == want) {
            return Ok(want.to_string());
        }
        anyhow::bail!(
            "Headscale at {base_url} has no user '{want}' — preauth keys are scoped to \
             a user, and minting against a missing one fails with an opaque 500. \
             Existing users: {}.",
            users.join(", ")
        );
    }
    if let [only] = users {
        return Ok(only.clone());
    }
    anyhow::bail!(
        "Headscale at {base_url} has several users ({}) — pass one explicitly rather \
         than letting this pick.",
        users.join(", ")
    )
}

// ---------------------------------------------------------------------------
// Headscale config + ACL generation
// ---------------------------------------------------------------------------

/// The `policy.mode` every in-tree renderer emits (R861-T2).
///
/// `database` puts the ACL policy in `headscale.db`, which litestream already
/// replicates, instead of in an `acls.yaml` that nothing replicates. It is also
/// the only mode in which `PUT /api/v1/policy` is accepted, so it is the mode
/// that makes [`super::reconciler::headscale`]'s declared policy pushable
/// rather than merely observable.
///
/// Verified against the pinned headscale v0.23.0 source: `policy.mode` takes
/// exactly `"file"` or `"database"` (`hscontrol/types/config.go`), and an
/// unrecognised value is a `log.Fatal` at startup — so this string is
/// load-bearing and must not be reworded.
///
/// `policy.path` is deliberately absent: headscale reads it only in file mode
/// (`hscontrol/grpcv1.go` `GetPolicy`, `hscontrol/app.go` `loadACLPolicy`), so
/// leaving it set would document a file that is no longer the source of truth.
///
/// yubaba's `generate_remote_headscale_config` /
/// `generate_bootstrap_headscale_config` emit the same value from their own
/// crate (no dependency edge exists between them and this one) and are kept in
/// lockstep by convention, the way `DEFAULT_HEADSCALE_VERSION` already is.
pub const POLICY_MODE: &str = "database";

/// Generate a headscale YAML configuration for Phase 1a (camp-local coordinator).
///
/// All state files (private keys, SQLite DB, socket) go under `data_dir`.
/// `server_url` is the publicly-reachable stable URL (`https://mesh.<domain>`)
/// that provisioned machines embed as their `--login-server`. It must be
/// stable across Phase 1b promotion and Phase 2 leader changes — only DNS
/// gets re-pointed, not the nodes.
pub fn generate_headscale_config(server_url: &str, data_dir: &std::path::Path) -> String {
    let private_key = data_dir.join("private.key").display().to_string();
    let noise_key = data_dir.join("noise_private.key").display().to_string();
    let db_path = data_dir.join("headscale.db").display().to_string();
    let socket_path = data_dir.join("headscale.sock").display().to_string();

    // listen_addr is localhost-only; production-facing traffic goes through
    // cloudflared or a port-forward — the stable URL is the public face.
    format!(
        r#"---
server_url: {server_url}
listen_addr: 127.0.0.1:8080
grpc_listen_addr: 127.0.0.1:50443
metrics_listen_addr: 127.0.0.1:9090
private_key_path: {private_key}
noise:
  private_key_path: {noise_key}
database:
  type: sqlite
  sqlite:
    path: {db_path}
unix_socket: {socket_path}
unix_socket_permission: "0770"
dns:
  magic_dns: true
  base_domain: mesh.internal
  nameservers:
    global:
      - 1.1.1.1
      - 8.8.8.8
log:
  level: info
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
policy:
  mode: {POLICY_MODE}
derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  auto_update_enabled: false
  update_frequency: 24h
"#
    )
}

/// A permissive ACL policy that allows all nodes to communicate.
/// Can be refined later with `yah mesh acl edit`.
///
/// Headscale's file-based policy loader parses HuJSON (JSON-with-comments),
/// NOT YAML — a leading `---` fails with "invalid literal: ---". Keep this
/// JSON.
pub const DEFAULT_ACL_POLICY: &str = r#"{
  "acls": [
    { "action": "accept", "src": ["*"], "dst": ["*:*"] }
  ]
}
"#;

// ---------------------------------------------------------------------------
// Binary management helpers
// ---------------------------------------------------------------------------

/// Pinned Headscale release version used by `yah mesh start`.
pub const HEADSCALE_VERSION: &str = "0.23.0";

/// Return the GitHub release download URL for headscale on this platform.
///
/// Only supports darwin (amd64/arm64) and linux (amd64/arm64) — the
/// platforms where `yah mesh start` makes sense. Returns `Err` for others.
pub fn headscale_download_url() -> Result<String> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        other => anyhow::bail!(
            "unsupported OS '{other}' for `yah mesh start`; \
             install headscale manually from https://headscale.net"
        ),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => anyhow::bail!(
            "unsupported architecture '{other}' for `yah mesh start`; \
             install headscale manually from https://headscale.net"
        ),
    };
    Ok(format!(
        "https://github.com/juanfont/headscale/releases/download/v{HEADSCALE_VERSION}/headscale_{HEADSCALE_VERSION}_{os}_{arch}"
    ))
}

// ---------------------------------------------------------------------------
// Cloudflare DNS helpers
// ---------------------------------------------------------------------------

/// Update (or create) the A record for `record_name` in the given Cloudflare
/// zone, pointing it at `new_ip`. Credentials come from the caller — use
/// [`cloudflare_credentials`] to load them from the vault / env.
///
/// The record is matched by listing all A records in the zone that match
/// `record_name`. Fails fast if zero or multiple records are found so we
/// don't silently skip or duplicate.
pub async fn update_cloudflare_dns(
    api_token: &str,
    zone_id: &str,
    record_name: &str,
    new_ip: &str,
) -> Result<()> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building Cloudflare HTTP client")?;

    let list_url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");

    let resp = http
        .get(&list_url)
        .bearer_auth(api_token)
        .query(&[("name", record_name), ("type", "A")])
        .send()
        .await
        .context("GET Cloudflare DNS records")?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Cloudflare list DNS records failed: {text}");
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .context("parsing Cloudflare records list")?;
    let records = body["result"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("unexpected Cloudflare response shape: missing 'result'"))?;

    let record_id = match records.len() {
        // Create-if-missing (R330-T9 follow-up b): on a fresh zone the A record
        // won't exist yet. POST a new one instead of bailing, so `yah mesh
        // bootstrap` is self-sufficient — no manual one-time DNS step. Same
        // endpoint as the list (POST /zones/{zone}/dns_records), same body shape
        // as the PATCH below. DNS-only (proxied: false) so Let's Encrypt HTTP-01
        // can reach the node directly.
        0 => {
            println!("  A record '{record_name}' absent — creating it (→ {new_ip}) ...");
            let create_body = serde_json::json!({
                "type": "A",
                "name": record_name,
                "content": new_ip,
                "ttl": 120,
                "proxied": false
            });
            let resp = http
                .post(&list_url)
                .bearer_auth(api_token)
                .json(&create_body)
                .send()
                .await
                .context("POST Cloudflare DNS record (create-if-missing)")?;
            if !resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("Cloudflare create DNS record failed: {text}");
            }
            println!("  DNS record created.");
            return Ok(());
        }
        1 => records[0]["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing 'id' in Cloudflare record"))?
            .to_string(),
        n => anyhow::bail!(
            "{n} A records named '{record_name}' found — expected exactly one; \
             resolve the ambiguity in your Cloudflare dashboard"
        ),
    };

    let patch_url = format!("{list_url}/{record_id}");
    let patch_body = serde_json::json!({
        "type": "A",
        "name": record_name,
        "content": new_ip,
        "ttl": 120,
        "proxied": false
    });

    let resp = http
        .patch(&patch_url)
        .bearer_auth(api_token)
        .json(&patch_body)
        .send()
        .await
        .context("PATCH Cloudflare DNS record")?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Cloudflare PATCH DNS record failed: {text}");
    }

    Ok(())
}

/// Load Cloudflare credentials from vault or environment.
///
/// Vault slots → env var fallbacks:
/// - `cloudflare-api-token` ↔ `CLOUDFLARE_API_TOKEN`
/// - `cloudflare-zone-id`   ↔ `CLOUDFLARE_ZONE_ID`
///
/// Returns `Ok(None)` when either credential is absent so callers can decide
/// whether to proceed with manual-DNS instructions or bail.
pub fn cloudflare_credentials() -> Result<Option<(String, String)>> {
    let token = fob::get_or_env("cloudflare-api-token", "CLOUDFLARE_API_TOKEN")?;
    let zone_id = fob::get_or_env("cloudflare-zone-id", "CLOUDFLARE_ZONE_ID")?;
    match (token, zone_id) {
        (Some(t), Some(z)) => Ok(Some((t, z))),
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_contains_server_url() {
        let dir = std::path::PathBuf::from("/tmp/test-mesh");
        let config = generate_headscale_config("https://mesh.example.com", &dir);
        assert!(config.contains("server_url: https://mesh.example.com"));
        assert!(config.contains("127.0.0.1:8080"));
        assert!(config.contains("base_domain: mesh.internal"));
        // R861-T2: policy lives in headscale.db, which litestream replicates.
        // The renderer must emit the mode AND must NOT emit a `policy.path` —
        // a leftover path documents a file that is no longer read.
        assert!(config.contains(&format!("mode: {POLICY_MODE}")));
        assert!(!config.contains("acls.yaml"));
        assert!(!config.contains("policy.path"));
        // Regression (R330-T9): base_domain must not be a substring of the
        // server_url host, or headscale 0.23+ refuses to start ("server_url
        // cannot contain the base_domain"). mesh.internal is decoupled from
        // any mesh.yah.dev-style coordinator hostname.
        let cfg2 = generate_headscale_config("https://mesh.yah.dev", &dir);
        assert!(!cfg2.contains("base_domain: mesh.yah\n"));
    }

    #[test]
    fn config_all_paths_in_data_dir() {
        let dir = std::path::PathBuf::from("/home/user/.yah/mesh");
        let config = generate_headscale_config("https://mesh.example.com", &dir);
        assert!(config.contains("/home/user/.yah/mesh/private.key"));
        assert!(config.contains("/home/user/.yah/mesh/headscale.db"));
    }

    #[test]
    fn download_url_current_platform() {
        // Just ensure it doesn't panic on the current CI platform.
        let result = headscale_download_url();
        assert!(result.is_ok(), "unsupported platform: {result:?}");
        let url = result.unwrap();
        assert!(url.contains(HEADSCALE_VERSION));
        assert!(url.starts_with("https://github.com"));
    }

    // -- choose_user (R608-B19) ---------------------------------------------
    //
    // The regression these pin down: `yah cloud machine provision` minted its
    // preauth key against the literal `"default"`, which the production
    // coordinator does not have. It was bootstrapped, so its only user is
    // `yah` (`headscale users create yah`, yubaba lib.rs
    // `mint_bootstrap_preauth_key`), while the camp-local `yah mesh start` path
    // creates `default`. Headscale answers a mint against a missing user with a
    // bare 500 naming nothing, so this failed opaquely on every provision.

    fn users(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_lone_user_is_chosen_without_being_named() {
        // The live shape: one bootstrapped coordinator, one user, and no reason
        // to make the caller know whether it is called `yah` or `default`.
        assert_eq!(
            choose_user("https://mesh.test", &users(&["yah"]), None).unwrap(),
            "yah"
        );
        assert_eq!(
            choose_user("https://mesh.test", &users(&["default"]), None).unwrap(),
            "default"
        );
    }

    #[test]
    fn a_preferred_user_that_exists_wins() {
        assert_eq!(
            choose_user("https://mesh.test", &users(&["yah", "ops"]), Some("ops")).unwrap(),
            "ops"
        );
    }

    #[test]
    fn a_preferred_user_that_does_not_exist_is_refused_by_name() {
        // THE bug, as a test: asking for "default" on a coordinator that only
        // has "yah" must fail here, locally, saying what does exist — not reach
        // the API and come back with a 500 that names nothing.
        let err = choose_user("https://mesh.test", &users(&["yah"]), Some("default"))
            .expect_err("a missing user must not be requested from the API");
        let msg = err.to_string();
        assert!(msg.contains("default"), "names what was asked for: {msg}");
        assert!(msg.contains("yah"), "names what actually exists: {msg}");
    }

    #[test]
    fn several_users_and_no_preference_refuses_rather_than_guessing() {
        // Silently taking the first would reintroduce the same class of bug:
        // a name picked by the code that the operator never chose.
        let err = choose_user("https://mesh.test", &users(&["yah", "default"]), None)
            .expect_err("an ambiguous mint target must not be guessed");
        let msg = err.to_string();
        assert!(msg.contains("yah") && msg.contains("default"), "{msg}");
    }

    #[test]
    fn no_users_at_all_says_how_to_create_one() {
        let err = choose_user("https://mesh.test", &[], None).expect_err("no users is fatal");
        assert!(err.to_string().contains("headscale users create"));
    }
}
