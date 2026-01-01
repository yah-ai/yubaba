//! Shared Hetzner Cloud API client.
//!
//! Both the `desktop` crate (Tauri UI) and the `cloud` crate (CLI provision)
//! talk to the same Hetzner Cloud endpoints. This crate lifts the common
//! HTTP client, bearer-auth plumbing, error type, and wire DTOs so neither
//! call site carries its own parallel implementation.
//!
//! Token-source policy is NOT handled here: callers are responsible for
//! obtaining the bearer token (keychain, vault, or env var). This keeps
//! the crate free of `keys` and any platform-specific deps.

use serde::{Deserialize, Serialize};
use thiserror::Error;

const HCLOUD_BASE: &str = "https://api.hetzner.cloud/v1";

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum HetznerError {
    #[error("Hetzner token rejected: 401 unauthorized")]
    Unauthorized,
    #[error("Hetzner API returned {status}: {body}")]
    Upstream { status: u16, body: String },
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),
}

async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response, HetznerError> {
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(HetznerError::Unauthorized);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(HetznerError::Upstream {
            status: status.as_u16(),
            body,
        });
    }
    Ok(resp)
}

// ── Client ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct HetznerClient {
    client: reqwest::Client,
    token: String,
}

impl HetznerClient {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            token: token.into(),
        }
    }

    /// Expose the inner `reqwest::Client` for callers that need it for
    /// additional request types (e.g. S3-compat bucket ops in the `cloud` crate).
    pub fn raw_client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Expose the bearer token for callers that build their own request pipelines.
    pub fn token(&self) -> &str {
        &self.token
    }

    async fn get_checked(&self, url: &str) -> Result<reqwest::Response, HetznerError> {
        let resp = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await?;
        check_status(resp).await
    }

    // ── Servers ──────────────────────────────────────────────────────────────

    pub async fn list_servers(&self) -> Result<Vec<HetznerServer>, HetznerError> {
        let resp = self.get_checked(&format!("{HCLOUD_BASE}/servers")).await?;
        let parsed: ServersResponse = resp.json().await?;
        Ok(parsed.servers.into_iter().map(Into::into).collect())
    }

    /// Return the server with the given numeric id, or `None` if not found (404).
    pub async fn get_server(&self, id: u64) -> Result<Option<HetznerServer>, HetznerError> {
        let resp = self
            .client
            .get(&format!("{HCLOUD_BASE}/servers/{id}"))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = check_status(resp).await?;
        let parsed: ServerResponse = resp.json().await?;
        Ok(Some(parsed.server.into()))
    }

    /// Return servers whose name matches `name`. Hetzner filters server-side
    /// via the `?name=` query parameter; the caller takes the first hit for
    /// a unique lookup.
    pub async fn find_servers_by_name(
        &self,
        name: &str,
    ) -> Result<Vec<HetznerServer>, HetznerError> {
        let resp = self
            .client
            .get(&format!("{HCLOUD_BASE}/servers"))
            .bearer_auth(&self.token)
            .query(&[("name", name)])
            .send()
            .await?;
        let resp = check_status(resp).await?;
        let parsed: ServersResponse = resp.json().await?;
        Ok(parsed.servers.into_iter().map(Into::into).collect())
    }

    /// Provision a new server. `spec.user_data` is sent only when `Some`.
    /// `automount: false` and `public_net: {enable_ipv4: true, enable_ipv6: true}`
    /// are always included (they match Hetzner defaults and the cloud-init bootstrap
    /// path that expects public IPs).
    pub async fn create_server(
        &self,
        spec: &HetznerCreateServerSpec,
    ) -> Result<HetznerServer, HetznerError> {
        let mut body = serde_json::json!({
            "name": spec.name,
            "server_type": spec.server_type,
            "image": spec.image,
            "location": spec.location,
            "automount": false,
            "public_net": { "enable_ipv4": true, "enable_ipv6": true },
        });
        if !spec.ssh_keys.is_empty() {
            body["ssh_keys"] = serde_json::json!(spec.ssh_keys);
        }
        if let Some(ud) = &spec.user_data {
            body["user_data"] = serde_json::json!(ud);
        }
        let resp = self
            .client
            .post(&format!("{HCLOUD_BASE}/servers"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;
        let resp = check_status(resp).await?;
        let parsed: CreateServerResponse = resp.json().await?;
        Ok(parsed.server.into())
    }

    /// Delete a server. Returns `Ok(true)` on success, `Ok(false)` if the
    /// server was already gone (404 → idempotent, mirrors the SSH-key contract).
    pub async fn destroy_server(&self, id: u64) -> Result<bool, HetznerError> {
        let resp = self
            .client
            .delete(&format!("{HCLOUD_BASE}/servers/{id}"))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        let _ = check_status(resp).await?;
        Ok(true)
    }

    // ── SSH keys ─────────────────────────────────────────────────────────────

    pub async fn list_ssh_keys(&self) -> Result<Vec<HetznerSshKey>, HetznerError> {
        let resp = self.get_checked(&format!("{HCLOUD_BASE}/ssh_keys")).await?;
        let parsed: SshKeysResponse = resp.json().await?;
        Ok(parsed.ssh_keys.into_iter().map(Into::into).collect())
    }

    pub async fn upload_ssh_key(
        &self,
        name: &str,
        public_key: &str,
    ) -> Result<HetznerSshKey, HetznerError> {
        #[derive(Serialize)]
        struct Body<'a> {
            name: &'a str,
            public_key: &'a str,
        }
        let resp = self
            .client
            .post(&format!("{HCLOUD_BASE}/ssh_keys"))
            .bearer_auth(&self.token)
            .json(&Body { name, public_key })
            .send()
            .await?;
        let resp = check_status(resp).await?;
        let parsed: SshKeyResponse = resp.json().await?;
        Ok(parsed.ssh_key.into())
    }

    /// Delete an SSH key from the project. Returns `Ok(false)` on 404
    /// (idempotent deauthorize path).
    pub async fn delete_ssh_key(&self, id: u64) -> Result<bool, HetznerError> {
        let resp = self
            .client
            .delete(&format!("{HCLOUD_BASE}/ssh_keys/{id}"))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        let _ = check_status(resp).await?;
        Ok(true)
    }
}

// ── Public DTOs ───────────────────────────────────────────────────────────────

/// Renderer-facing server summary. `status` is the raw Hetzner lifecycle
/// string (e.g. `"running"`, `"off"`, `"initializing"`); callers that need
/// a typed enum can map it themselves.
#[derive(Debug, Clone, Serialize)]
pub struct HetznerServer {
    pub id: u64,
    pub name: String,
    pub status: String,
    pub server_type: String,
    pub location: String,
    pub ipv4: Option<String>,
    pub created: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HetznerSshKey {
    pub id: u64,
    pub name: String,
    pub fingerprint: String,
    pub public_key: String,
    pub created: String,
}

/// Spec for `POST /v1/servers`. `location` must be the Hetzner Cloud slug
/// (e.g. `"fsn1"`, `"ash"`, `"hil"`). `user_data` is cloud-init content;
/// omit for desktop provision where cloud-init is not needed.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HetznerCreateServerSpec {
    pub name: String,
    pub server_type: String,
    pub location: String,
    pub image: String,
    #[serde(default)]
    pub ssh_keys: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
}

// ── Private wire types ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ServersResponse {
    servers: Vec<RawServer>,
}

#[derive(Deserialize)]
struct ServerResponse {
    server: RawServer,
}

#[derive(Deserialize)]
struct CreateServerResponse {
    server: RawServer,
}

#[derive(Deserialize)]
struct RawServer {
    id: u64,
    name: String,
    status: String,
    created: String,
    #[serde(default)]
    server_type: Option<RawServerType>,
    #[serde(default)]
    datacenter: Option<RawDatacenter>,
    #[serde(default)]
    public_net: Option<RawPublicNet>,
}

#[derive(Deserialize)]
struct RawServerType {
    name: String,
}

#[derive(Deserialize)]
struct RawDatacenter {
    location: RawLocation,
}

#[derive(Deserialize)]
struct RawLocation {
    name: String,
}

#[derive(Deserialize, Default)]
struct RawPublicNet {
    #[serde(default)]
    ipv4: Option<RawIpv4>,
}

#[derive(Deserialize)]
struct RawIpv4 {
    ip: Option<String>,
}

impl From<RawServer> for HetznerServer {
    fn from(r: RawServer) -> Self {
        Self {
            id: r.id,
            name: r.name,
            status: r.status,
            server_type: r.server_type.map(|t| t.name).unwrap_or_default(),
            location: r
                .datacenter
                .map(|d| d.location.name)
                .unwrap_or_default(),
            ipv4: r.public_net.and_then(|n| n.ipv4).and_then(|v| v.ip),
            created: r.created,
        }
    }
}

#[derive(Deserialize)]
struct SshKeysResponse {
    ssh_keys: Vec<RawSshKey>,
}

#[derive(Deserialize)]
struct SshKeyResponse {
    ssh_key: RawSshKey,
}

#[derive(Deserialize)]
struct RawSshKey {
    id: u64,
    name: String,
    fingerprint: String,
    public_key: String,
    created: String,
}

impl From<RawSshKey> for HetznerSshKey {
    fn from(r: RawSshKey) -> Self {
        Self {
            id: r.id,
            name: r.name,
            fingerprint: r.fingerprint,
            public_key: r.public_key,
            created: r.created,
        }
    }
}
