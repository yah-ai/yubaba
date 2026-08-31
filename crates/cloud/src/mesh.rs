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
        let expiration = chrono::Utc::now()
            + chrono::TimeDelta::try_hours(1)
                .ok_or_else(|| anyhow::anyhow!("overflow computing 1-hour expiry"))?;
        let body = serde_json::json!({
            "user": user,
            "expiration": expiration.to_rfc3339(),
            "reusable": false,
            "ephemeral": false,
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
    let acl_path = data_dir.join("acls.yaml").display().to_string();

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
  mode: file
  path: {acl_path}
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
        assert!(config.contains("acls.yaml"));
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
