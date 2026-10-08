//! archived: R040 — history: `yah board history oss/yubaba/crates/cloud/src/provider/hetzner.rs`

use super::{
    BucketAcl, BucketRef, Location, MachineProvider, ProjectId, ServerId, ServerSpec, ServerStatus,
    ServerSummary,
};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use local_driver::s3_sign::{
    sign_s3_delete_bucket, sign_s3_head_bucket, sign_s3_put_bucket, sign_s3_put_bucket_acl,
};
use reqwest::StatusCode;
use yah_hetzner::{HetznerClient, HetznerCreateServerSpec};

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
