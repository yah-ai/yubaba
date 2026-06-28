//! @yah:ticket(R040-F9, "Lift KeysStore into shared crate; cloud reads vault then env")
//! @yah:at(2026-05-05T00:33:17Z)
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:parent(R040)
//! @yah:handoff("DRY-up landed: app/yah/cli/src/keys.rs lifted to crates/yah/keys (own Cargo.toml, ProjectDirs::data_dir() unchanged so the existing on-disk vault keeps working). app/yah/cli now `keys = { path = ... }` deps the new crate; aes-gcm and rand drops out of the CLI's direct deps (transitive now). main.rs/agent.rs/agentd.rs swapped `mod keys;`/`crate::keys::` for the external crate path. cloud crate gained `keys` dep + `HetznerDriver::from_default_sources()` that tries KeysStore::open().get(slot) per-key then falls back to env: hetzner-api-token↔HETZNER_API_TOKEN, hetzner-s3-access-key↔HETZNER_S3_ACCESS_KEY, hetzner-s3-secret-key↔HETZNER_S3_SECRET_KEY. Vault open errors are swallowed (no vault → fall back to env). yah cloud callsites (app/yah/cli/src/cloud.rs:257 + :423) flipped to from_default_sources(). Tests: 6/6 green for keys (moved from CLI), 26/26 green for cloud (no test changes — all existing). cargo check -p keys + -p cloud + -p yah --bin yah-agentd clean.")
//! @yah:next("Follow-up scoped as R043 (relay) with phases F1 bridge / F2 naming / F3 cleanup — unify desktop api_keys with this vault, KeysStore as canonical, drop keyring dep once soaked.")
//! @yah:next("Optional: yah keys CLI could grow `--from-keychain <provider>` flag to one-shot import a desktop-vault token without typing it. Not urgent; the user can already pipe via `security find-generic-password ... | yah keys set --from-stdin <slot>`.")
//! @yah:verify("cargo test -p keys")
//! @yah:verify("cargo test -p cloud")
//! @yah:verify("cargo check -p yah --bin yah-agentd")
//! @yah:gotcha("cargo check --workspace currently fails on app/yah/cli/src/cloud.rs:210 because handle_agent is referenced but not yet defined — that's parallel R040-F7 WIP (yah cloud agent ping/services/logs against yah-yubaba), not this refactor. The `keys = ...` and HetznerDriver::from_default_sources additions compile clean on their own.")
//!
//! @yah:ticket(R040-F10, "Pass ssh_keys through to Hetzner create_server (pre-mesh SSH access)")
//! @yah:at(2026-05-05T00:33:17Z)
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:parent(R040)
//! @yah:handoff("Threaded ssh_keys end-to-end. MachineConfig.ssh_keys: Vec<u64> with #[serde(default)] (existing toml files unaffected). ServerSpec.ssh_keys mirrors. hetzner.rs::create_server attaches `\"ssh_keys\": [...]` to the POST body when non-empty (Hetzner ignores empty arrays anyway). provision.rs threads MachineConfig.ssh_keys → ProvisionRequest → ServerSpec. 6 test sites updated to add the field; 29/29 cloud tests green.")
//! @yah:handoff("Live-verified: provisioned yah-cloud-1 (cpx11, hil) via direct API (cloud-crate provision flow blew the 32KiB user_data cap embedding yubaba — separate ticket). With ssh_keys=[111513970, 111525493] the box accepted SSH on first boot via ~/.ssh/yah, no out-of-band root password recovery needed. The agentd round-trip succeeded over the socket: agent.list_sessions returned {sessions:[]}, bogus method returned -32601, stop-unknown returned {stopped:false}.")
//! @yah:next("Follow-up R040-Tx: 32KiB user_data cap blocks the canonical `yah cloud machine provision` path because the yubaba binary embeds at ~3MB after base64. Refactor cloud-init to fetch yubaba from a URL (GitHub release artifact during cloud-init runcmd) instead of inlining the bytes. Until then, provision flows that need yubaba need a different transport (post-boot scp + register-hostkey).")
//! @yah:verify("cargo test -p cloud")
//! @yah:verify("cargo run -p yah --bin yah -- cloud machine status (sees ssh_keys field via the new yah-cloud-1.toml in .yah/cloud/machines/)")
//!
//! @yah:ticket(R040-F14, "Extract shared crates/yah/hetzner: lift transport+DTOs out of desktop and cloud parallel impls")
//! @yah:at(2026-05-05T00:33:17Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:parent(R040)
//! @yah:handoff("app/yah/desktop/src/hetzner.rs (~641 LOC) and crates/yah/cloud/src/provider/hetzner.rs (~560 LOC) are parallel HTTP clients. Both ship their own auth_client/check_status, RawServer/HetznerServer DTOs, error types. Lift the shared core into crates/yah/hetzner; both call sites become thin layers over it. Surfaced in R040-F12 + F13 (destroy-button work) where the obvious DRY move would have ballooned the change set.")
//! @yah:next("New crate crates/yah/hetzner: HetznerClient (reqwest+bearer + check_status), wire DTOs (RawServer/RawSshKey/RawLocation/RawImage), HetznerError")
//! @yah:next("Desktop hetzner.rs becomes UI-flow operations (list_server_types/_locations/_images stay desktop-only — catalog browse for the form) over the shared client")
//! @yah:next("Cloud hetzner.rs becomes reconcile-flow operations (find_server_by_name, server_status, destroy_server, bucket APIs) over the shared client")
//! @yah:next("Token-source convergence is a separate ticket: shared client takes &str token, desktop reads keychain blob, cloud reads KeysStore vault — unifying those vaults is its own refactor")
//! @yah:next("Estimate: 2-4 hours; tests on both sides pass without functional change")
//!
//! @yah:ticket(R040-T17, "Decision-recorded: do NOT build floating-IP plumbing (superseded by Cloudflare Tunnels + Headscale mesh)")
//! @yah:at(2026-05-05T00:33:17Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:parent(R040)
//! @yah:kind(task)
//! @yah:handoff("Question raised this session: 'should yah cloud have one floating IP per region as an ingress target?' Answer recorded so future-self doesn't redo the analysis. NO — combination of R040-F15 (Cloudflare Tunnel for public ingress) + R040-F16 (Headscale mesh for inter-node TCP) means the entire stable-IP question evaporates. Public DNS points at <tunnel-id>.cfargotunnel.com (CF-managed). Inter-node uses 100.64.x.x mesh IPs that survive box replacement. Hetzner inline IPs can churn weekly without consequence. Floating IPs in this design would just be ~€0.50/mo per IP burned to solve a problem we don't have. Future-self: do NOT re-litigate without a concrete TCP/UDP public-ingress requirement that CF Spectrum (paid) can't cover.")
//! @yah:next("Archive condition: this task is purely a design-decision marker. Archive it once R040-F15 lands (the architectural commitment is real). Until then it stays here as a tripwire so a future claim of 'we should add primary-IP support' surfaces the prior reasoning before the work starts.")
//! @yah:next("Reopen condition: a concrete service requirement that needs raw TCP/UDP from the public internet AND can't justify CF Spectrum's pricing. If reopened, the natural shape is MachineConfig.primary_ip: Option<u64> + ServerSpec.primary_ip + a `yah cloud ip {create,list,destroy}` subcommand — but DON'T pre-build any of that until reopened.")
//!
//! @yah:ticket(R409-T4, "Establish .yah/envoys/<provider>/ convention; seed Hetzner sketch.md to validate the model")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T20:59:01Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R409)
//! @yah:handoff("Established .yah/envoys/ convention. Two files: README.md documents the directory layout (sketch.md required; manifest.toml lands with W145; notes/ optional), the relationship to .yah/infra/providers/ (operational vs catalog split with same provider id), and the provider list table; hetzner/sketch.md is the worked example that validates the model by retrofitting onto the existing Hetzner integration. The sketch answers W144's five classification-process questions — vendor surface (Cloud API + S3-compat Object Storage, two creds), auth model (cheers keystore slots, env fallback), license (Apache-2.0/MIT, no GPL/LGPL SDK pulled), verb coverage (3 implemented + 6 gaps mapped against W144's catalog), decision (Tier S, Native, categories=[cloud]) — plus a gotchas section drawn from existing driver comments (rate limits, bucket-delete two-step, 403 vs 404 on HEAD) so a picking-up agent inherits the operational history W144 promised.")
//! @yah:verify("ls .yah/envoys/ — README.md + hetzner/ present")
//! @yah:verify("Read .yah/envoys/README.md and .yah/envoys/hetzner/sketch.md, confirm structure matches W144 §'Classification process' (surface / auth / license / verb gaps / tier rationale) and the README's promised file list matches reality")
//!
//! @yah:ticket(R409-T5, "Refactor Hetzner behind cloud.vps.* verbs only (spike scope; rest of cloud.* lands after T11)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-02T20:59:07Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R409)
//! @yah:depends_on(R409-T3)
//! @yah:handoff("HetznerEnvoy adapter landed in crates/yah/cloud/src/provider/hetzner_envoy.rs, wired through provider/mod.rs (pub mod hetzner_envoy + re-export). Wraps an Arc<HetznerDriver>; impls EnvoyAdapter with id=hetzner, tier=S, flavor=Native, supported_verb_ids=[cloud.vps.create, cloud.vps.destroy, cloud.vps.status]. Dispatch decodes JSON into the typed Input, calls the typed handler, re-encodes the typed Output — unsupported verb ids bail with a programmer-error message (host shouldn't dispatch what's not registered). Typed handlers are public so integration tests can bypass the JSON envelope. server_status_to_output is a pure function so the wire mapping (ServerStatus::Unknown(s) → VpsPhase::Unknown + detail=Some(s); all closed phases drop detail) is unit-tested without touching the driver. Also added the EnvoyAdapter trait to crates/yah/cloud/src/envoy.rs alongside Tier/AdapterFlavor/VerbCategory. MachineProvider intentionally left in place — it's still the substrate the orchestration code calls into; R409-T9 retires it after T11+T6+T7+T8.")
//! @yah:verify("cargo test -p cloud --lib --features json-schema envoy — 19/19 pass")
//! @yah:verify("cargo test -p cloud --lib hetzner_envoy — 3/3 pass")
//! @yah:gotcha("cloud_init::tests::embedded_template_matches_workspace_canonical fails on default cargo test -p cloud --lib (228/229). Pre-existing template drift between .yah/infra/cloud-init/mirror.yml (modified, unstaged) and the embedded crates/yah/cloud/templates/mirror.yml — unrelated to T5; do not regress it but don't try to fix from this ticket either.")

use super::{
    BucketAcl, BucketRef, Location, MachineProvider, ProjectId, ServerId, ServerSpec, ServerStatus,
    ServerSummary,
};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use yah_hetzner::{HetznerClient, HetznerCreateServerSpec};
use local_driver::s3_sign::{
    sign_s3_delete_bucket, sign_s3_head_bucket, sign_s3_put_bucket, sign_s3_put_bucket_acl,
};
use reqwest::StatusCode;

/// Hetzner Cloud + Object Storage driver for Phase-1 mirror bootstrap.
///
/// Cloud operations (server lifecycle) use `HETZNER_API_TOKEN`.
/// Bucket operations use the Hetzner Object Storage S3-compat API
/// (`HETZNER_S3_ACCESS_KEY` + `HETZNER_S3_SECRET_KEY`).
/// Run `yah cloud secrets` for the canonical contract (vault slots + env).
#[derive(Clone)]
pub struct HetznerDriver {
    hclient: HetznerClient,
    s3_access_key: Option<String>,
    s3_secret_key: Option<String>,
    /// Overrides the computed S3 base endpoint (useful for integration tests).
    s3_endpoint_override: Option<String>,
}

impl HetznerDriver {
    /// Build with a Cloud API token only. Bucket operations will fail until
    /// S3 credentials are added via [`with_storage`].
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            hclient: HetznerClient::new(token),
            s3_access_key: None,
            s3_secret_key: None,
            s3_endpoint_override: None,
        }
    }

    /// Attach Hetzner Object Storage S3 credentials.
    pub fn with_storage(
        mut self,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        self.s3_access_key = Some(access_key.into());
        self.s3_secret_key = Some(secret_key.into());
        self
    }

    /// Override the S3 base endpoint (e.g. `"http://localhost:9000"` for MinIO in tests).
    pub fn with_s3_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.s3_endpoint_override = Some(endpoint.into());
        self
    }

    /// Build from environment variables.
    ///
    /// Required: `HETZNER_API_TOKEN`.
    /// Optional: `HETZNER_S3_ACCESS_KEY` + `HETZNER_S3_SECRET_KEY` (needed for `create_bucket`).
    pub fn from_env() -> Result<Self> {
        let token = std::env::var("HETZNER_API_TOKEN")
            .context("HETZNER_API_TOKEN not set — run `yah cloud secrets` for the contract")?;
        let mut driver = Self::new(token);
        if let (Ok(ak), Ok(sk)) = (
            std::env::var("HETZNER_S3_ACCESS_KEY"),
            std::env::var("HETZNER_S3_SECRET_KEY"),
        ) {
            driver = driver.with_storage(ak, sk);
        }
        Ok(driver)
    }

    /// Build from the shared `keys` vault first, then fall back to env vars.
    ///
    /// Slot ↔ env mapping:
    /// - `hetzner-api-token` ↔ `HETZNER_API_TOKEN` (required)
    /// - `hetzner-s3-access-key` ↔ `HETZNER_S3_ACCESS_KEY` (optional pair)
    /// - `hetzner-s3-secret-key` ↔ `HETZNER_S3_SECRET_KEY` (optional pair)
    ///
    /// The vault path is the production-default for `yah` callers; env is
    /// kept as a fallback so CI / one-shot scripts (and hosts that don't
    /// have a vault yet) keep working. The two are checked per-key, so a
    /// vault-stored API token combined with env-supplied S3 creds is fine.
    /// Vault open errors (missing machine.key, etc.) are swallowed — they
    /// just mean "no vault here, try env."
    pub fn from_default_sources() -> Result<Self> {
        let token = fob::get_or_env("hetzner-api-token", "HETZNER_API_TOKEN")?.context(
            "no Hetzner API token — set one with `yah keys set hetzner-api-token` \
                 or export HETZNER_API_TOKEN; run `yah cloud secrets` for the full contract",
        )?;
        let mut driver = Self::new(token);
        if let (Some(ak), Some(sk)) = (
            fob::get_or_env("hetzner-s3-access-key", "HETZNER_S3_ACCESS_KEY")?,
            fob::get_or_env("hetzner-s3-secret-key", "HETZNER_S3_SECRET_KEY")?,
        ) {
            driver = driver.with_storage(ak, sk);
        }
        Ok(driver)
    }

    fn s3_endpoint(&self, location: &Location) -> String {
        self.s3_endpoint_override
            .clone()
            .unwrap_or_else(|| location.hetzner_storage_endpoint().to_string())
    }
}

// ─── MachineProvider ─────────────────────────────────────────────────────────

#[async_trait]
impl MachineProvider for HetznerDriver {
    async fn ensure_project(&self, name: &str) -> Result<ProjectId> {
        // Hetzner Cloud API tokens are already project-scoped; no API call needed.
        Ok(ProjectId(name.to_string()))
    }

    async fn create_server(
        &self,
        _project: &ProjectId,
        spec: &ServerSpec,
        user_data: &str,
    ) -> Result<ServerId> {
        let hspec = HetznerCreateServerSpec {
            name: spec.name.clone(),
            server_type: spec.server_type.clone(),
            location: spec.location.hetzner_cloud_id().to_string(),
            image: spec.image.clone(),
            ssh_keys: spec.ssh_keys.clone(),
            user_data: if user_data.is_empty() {
                None
            } else {
                Some(user_data.to_string())
            },
        };
        let server = self
            .hclient
            .create_server(&hspec)
            .await
            .context("create_server")?;
        Ok(ServerId(server.id.to_string()))
    }

    async fn server_status(&self, id: &ServerId) -> Result<ServerStatus> {
        let server_id: u64 = id.0.parse().context("invalid server id")?;
        match self
            .hclient
            .get_server(server_id)
            .await
            .context("server_status")?
        {
            None => Ok(ServerStatus::Unknown("not-found".into())),
            Some(s) => Ok(parse_server_status(&s.status)),
        }
    }

    async fn find_server_by_name(&self, name: &str) -> Result<Option<ServerSummary>> {
        let servers = self
            .hclient
            .find_servers_by_name(name)
            .await
            .context("find_server_by_name")?;
        Ok(servers.into_iter().next().map(|s| ServerSummary {
            id: ServerId(s.id.to_string()),
            server_type: s.server_type,
            status: parse_server_status(&s.status),
            public_ipv4: s.ipv4,
            location: s.location,
        }))
    }

    async fn bucket_exists(&self, name: &str, location: Location) -> Result<bool> {
        let (ak, sk) = match (&self.s3_access_key, &self.s3_secret_key) {
            (Some(a), Some(s)) => (a.as_str(), s.as_str()),
            _ => bail!(
                "S3 credentials not configured — set HETZNER_S3_ACCESS_KEY and \
                 HETZNER_S3_SECRET_KEY (run `yah cloud secrets` for the contract)"
            ),
        };

        let endpoint = self.s3_endpoint(&location);
        let region = location.hetzner_storage_region();
        let url = format!("{endpoint}/{name}");

        let headers = sign_s3_head_bucket(&url, region, ak, sk)?;

        let resp = self
            .hclient
            .raw_client()
            .head(&url)
            .headers(headers)
            .send()
            .await
            .context("HEAD bucket")?;

        let http_status = resp.status();
        match http_status {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => {
                let text = resp.text().await.unwrap_or_default();
                bail!("bucket_exists failed ({http_status}): {text}")
            }
        }
    }

    async fn destroy_server(&self, id: &ServerId) -> Result<()> {
        let server_id: u64 = id.0.parse().context("invalid server id")?;
        self.hclient
            .destroy_server(server_id)
            .await
            .context("destroy_server")?;
        Ok(())
    }

    async fn delete_bucket(&self, name: &str, location: Location) -> Result<()> {
        let (ak, sk) = match (&self.s3_access_key, &self.s3_secret_key) {
            (Some(a), Some(s)) => (a.as_str(), s.as_str()),
            _ => bail!(
                "S3 credentials not configured — set HETZNER_S3_ACCESS_KEY and \
                 HETZNER_S3_SECRET_KEY (run `yah cloud secrets` for the contract)"
            ),
        };

        let endpoint = self.s3_endpoint(&location);
        let region = location.hetzner_storage_region();
        let url = format!("{endpoint}/{name}");

        let headers = sign_s3_delete_bucket(&url, region, ak, sk)?;

        let resp = self
            .hclient
            .raw_client()
            .delete(&url)
            .headers(headers)
            .send()
            .await
            .context("DELETE bucket")?;

        let http_status = resp.status();
        match http_status {
            StatusCode::NO_CONTENT | StatusCode::OK | StatusCode::NOT_FOUND => Ok(()),
            StatusCode::CONFLICT => {
                let text = resp.text().await.unwrap_or_default();
                bail!(
                    "delete_bucket failed ({http_status} likely BucketNotEmpty): {text}\n\
                     yah doesn't yet list-and-delete objects — empty the bucket first \
                     via aws-cli (`aws s3 rm --recursive --endpoint-url <region-endpoint> \
                     s3://{name}`) and retry."
                )
            }
            _ => {
                let text = resp.text().await.unwrap_or_default();
                bail!("delete_bucket failed ({http_status}): {text}")
            }
        }
    }

    async fn create_bucket(&self, name: &str, location: Location) -> Result<BucketRef> {
        let (ak, sk) = match (&self.s3_access_key, &self.s3_secret_key) {
            (Some(a), Some(s)) => (a.as_str(), s.as_str()),
            _ => bail!(
                "S3 credentials not configured — set HETZNER_S3_ACCESS_KEY and \
                 HETZNER_S3_SECRET_KEY (run `yah cloud secrets` for the contract)"
            ),
        };

        let endpoint = self.s3_endpoint(&location);
        let region = location.hetzner_storage_region();
        // Path-style: https://<endpoint>/<bucket>
        let url = format!("{endpoint}/{name}");

        let headers = sign_s3_put_bucket(&url, region, ak, sk)?;

        let resp = self
            .hclient
            .raw_client()
            .put(&url)
            .headers(headers)
            .body("")
            .send()
            .await
            .context("PUT bucket")?;

        let http_status = resp.status();
        // 200 OK or 409 Conflict (bucket already exists and belongs to caller) are both fine.
        if http_status.is_success() || http_status == StatusCode::CONFLICT {
            return Ok(BucketRef {
                name: name.to_string(),
                endpoint,
            });
        }
        let text = resp.text().await.unwrap_or_default();
        bail!("create_bucket failed ({http_status}): {text}");
    }

    async fn set_bucket_acl(&self, name: &str, location: Location, acl: BucketAcl) -> Result<()> {
        let (ak, sk) = match (&self.s3_access_key, &self.s3_secret_key) {
            (Some(a), Some(s)) => (a.as_str(), s.as_str()),
            _ => bail!(
                "S3 credentials not configured — set HETZNER_S3_ACCESS_KEY and \
                 HETZNER_S3_SECRET_KEY (run `yah cloud secrets` for the contract)"
            ),
        };

        let endpoint = self.s3_endpoint(&location);
        let region = location.hetzner_storage_region();
        let url = format!("{endpoint}/{name}?acl");

        let headers = sign_s3_put_bucket_acl(&url, region, ak, sk, acl.as_canned())?;

        let resp = self
            .hclient
            .raw_client()
            .put(&url)
            .headers(headers)
            .body("")
            .send()
            .await
            .context("PUT bucket?acl")?;

        let http_status = resp.status();
        if http_status.is_success() {
            return Ok(());
        }
        let text = resp.text().await.unwrap_or_default();
        bail!("set_bucket_acl failed ({http_status}): {text}");
    }
}

fn parse_server_status(s: &str) -> ServerStatus {
    match s {
        "initializing" => ServerStatus::Initializing,
        "starting" => ServerStatus::Starting,
        "running" => ServerStatus::Running,
        "stopping" => ServerStatus::Stopping,
        "off" => ServerStatus::Off,
        "deleting" => ServerStatus::Deleting,
        other => ServerStatus::Unknown(other.to_string()),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_known_values() {
        assert_eq!(parse_server_status("running"), ServerStatus::Running);
        assert_eq!(parse_server_status("off"), ServerStatus::Off);
        assert_eq!(
            parse_server_status("initializing"),
            ServerStatus::Initializing
        );
        assert_eq!(
            parse_server_status("banana"),
            ServerStatus::Unknown("banana".into())
        );
    }

    #[test]
    fn location_ids_correct() {
        assert_eq!(Location::Pdx.hetzner_cloud_id(), "hil");
        assert_eq!(Location::Iad.hetzner_cloud_id(), "ash");
        assert_eq!(Location::Fsn.hetzner_cloud_id(), "fsn1");
    }

    #[tokio::test]
    #[ignore = "requires HETZNER_API_TOKEN"]
    async fn integration_create_and_destroy_server() {
        let driver = HetznerDriver::from_env().unwrap();
        let project = driver.ensure_project("yah-test").await.unwrap();
        let spec = ServerSpec {
            name: "yah-test-ephemeral".into(),
            server_type: "cpx11".into(),
            image: "debian-12".into(),
            location: Location::Fsn,
            ssh_keys: vec![],
        };
        let id = driver
            .create_server(&project, &spec, "#cloud-config\n")
            .await
            .unwrap();
        println!("created server {}", id.0);

        let status = driver.server_status(&id).await.unwrap();
        println!("initial status: {status:?}");
        assert!(matches!(
            status,
            ServerStatus::Running | ServerStatus::Initializing | ServerStatus::Starting
        ));

        driver.destroy_server(&id).await.unwrap();
        println!("destroyed");
    }

    #[tokio::test]
    #[ignore = "requires HETZNER_API_TOKEN + HETZNER_S3_ACCESS_KEY + HETZNER_S3_SECRET_KEY"]
    async fn integration_create_bucket() {
        let driver = HetznerDriver::from_env().unwrap();
        let bucket = driver
            .create_bucket("yah-ci-test-bucket-fsn1", Location::Fsn)
            .await
            .unwrap();
        println!("bucket: {} @ {}", bucket.name, bucket.endpoint);
    }
}
