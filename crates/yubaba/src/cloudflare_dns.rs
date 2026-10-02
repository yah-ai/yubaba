//! R936-B7: the fleet's one Cloudflare DNS client, shared by both of the
//! leader's DNS writers — [`crate::ingress_effector`]'s apex withdrawal and
//! [`crate::door_dns`]'s door-record reconciler.
//!
//! Three zone-scoped calls and nothing else: list the A records at a name,
//! create one, delete one by id. `cloud::provider::cloudflare::CloudflareClient`
//! can do R2, Workers, tunnels and token minting, and none of that belongs on a
//! fleet node, so this stays deliberately narrow. The zone is a per-call
//! argument rather than a field because the door reconciler manages names in
//! several zones (`yah.dev`, `noisetable.com`, `scrabcake.com`) with one token.
//!
//! What each caller is *allowed* to do with these calls is that caller's
//! policy, not this client's: the apex withdrawal only ever deletes, the door
//! reconciler adds and deletes within a declared door set. Keep policy out of
//! here.

use anyhow::{Context, Result};
use serde::Deserialize;

/// Cloudflare's public API root. Overridden by tests against a local stub.
pub const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";

/// One A record as Cloudflare reports it — the fields a content-matched delete
/// and a shape-preserving re-add need.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ARecord {
    pub id: String,
    pub content: String,
    /// Seconds; `1` is Cloudflare's "automatic".
    #[serde(default = "auto_ttl")]
    pub ttl: u32,
    #[serde(default)]
    pub proxied: bool,
}

fn auto_ttl() -> u32 {
    1
}

/// Zone-scoped Cloudflare DNS over a bearer token.
pub struct CloudflareDns {
    http: reqwest::Client,
    token: String,
    base_url: String,
}

impl CloudflareDns {
    /// Construct directly from a token — the test/embedding path.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            token: token.into(),
            base_url: CLOUDFLARE_API.to_string(),
        }
    }

    /// Build from a `fob`-injected token file.
    ///
    /// The read happens once at construction rather than per call: a rotated
    /// token takes effect on the next daemon restart, which is the same
    /// contract the ACME issuer's token file has.
    pub fn from_token_file(path: &str) -> Result<Self> {
        let token = std::fs::read_to_string(path)
            .with_context(|| format!("reading Cloudflare token file {path}"))?
            .trim()
            .to_string();
        anyhow::ensure!(!token.is_empty(), "Cloudflare token file {path} is empty");
        Ok(Self::new(token))
    }

    /// Point at a stub server instead of `api.cloudflare.com`.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Every A record at exactly `name` in `zone_id`.
    ///
    /// Filtered locally on `name` as well as by the query string: a server-side
    /// filter that silently stopped working must not widen what a caller
    /// believes is "the records at this name" to the whole zone.
    pub async fn list_a(&self, zone_id: &str, name: &str) -> Result<Vec<ARecord>> {
        #[derive(Deserialize)]
        struct Listed {
            name: String,
            #[serde(flatten)]
            record: ARecord,
        }
        let listed: CfPage<Listed> = self
            .http
            .get(format!(
                "{}/zones/{zone_id}/dns_records?name={name}&type=A&per_page=100",
                self.base_url
            ))
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("listing A records at {name}"))?
            .json()
            .await
            .with_context(|| format!("decoding the A records at {name}"))?;
        cf_ok(listed.success, &listed.errors)?;
        Ok(listed
            .result
            .into_iter()
            .filter(|l| l.name.eq_ignore_ascii_case(name))
            .map(|l| l.record)
            .collect())
    }

    /// Create one A record `name -> content`.
    pub async fn create_a(
        &self,
        zone_id: &str,
        name: &str,
        content: &str,
        ttl: u32,
        proxied: bool,
    ) -> Result<()> {
        let resp: CfUnit = self
            .http
            .post(format!("{}/zones/{zone_id}/dns_records", self.base_url))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "type": "A",
                "name": name,
                "content": content,
                "ttl": ttl,
                "proxied": proxied,
            }))
            .send()
            .await
            .with_context(|| format!("creating A record {name} -> {content}"))?
            .json()
            .await
            .with_context(|| format!("decoding the create of A record {name} -> {content}"))?;
        cf_ok(resp.success, &resp.errors)
    }

    /// Delete one record by id.
    pub async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<()> {
        let resp: CfUnit = self
            .http
            .delete(format!(
                "{}/zones/{zone_id}/dns_records/{record_id}",
                self.base_url
            ))
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("deleting DNS record {record_id}"))?
            .json()
            .await
            .with_context(|| format!("decoding the delete of DNS record {record_id}"))?;
        cf_ok(resp.success, &resp.errors)
    }
}

#[derive(Deserialize)]
struct CfPage<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default = "Vec::new")]
    result: Vec<T>,
}

#[derive(Deserialize)]
struct CfUnit {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
}

#[derive(Deserialize)]
struct CfError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

fn cf_ok(success: bool, errors: &[CfError]) -> Result<()> {
    anyhow::ensure!(
        success,
        "cloudflare API rejected the call: {}",
        if errors.is_empty() {
            "no error detail returned".to_string()
        } else {
            errors
                .iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; ")
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, Query, State};
    use axum::routing::{delete, get};
    use axum::{Json, Router};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// A one-zone Cloudflare stand-in holding `(id, name, content)` rows and a
    /// log of every mutating call, so tests assert on the wire, not on a fake.
    #[derive(Default)]
    struct Zone {
        rows: Vec<(String, String, String)>,
        log: Vec<String>,
        next_id: u32,
    }

    type Shared = Arc<Mutex<Zone>>;

    async fn list(
        State(z): State<Shared>,
        Path(zone): Path<String>,
        Query(q): Query<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        assert_eq!(zone, "zone-1");
        assert_eq!(q.get("type").map(String::as_str), Some("A"));
        let z = z.lock().unwrap();
        // Deliberately ignores `name` — models a server-side filter that
        // stopped working, which the client must survive.
        let result: Vec<_> = z
            .rows
            .iter()
            .map(|(id, name, content)| {
                serde_json::json!({"id": id, "name": name, "content": content, "ttl": 300, "proxied": false, "type": "A"})
            })
            .collect();
        Json(serde_json::json!({"success": true, "errors": [], "result": result}))
    }

    async fn create(
        State(z): State<Shared>,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let mut z = z.lock().unwrap();
        z.next_id += 1;
        let id = format!("new-{}", z.next_id);
        let name = body["name"].as_str().unwrap().to_string();
        let content = body["content"].as_str().unwrap().to_string();
        z.log.push(format!(
            "create {name} {content} ttl={} proxied={}",
            body["ttl"], body["proxied"]
        ));
        z.rows.push((id, name, content));
        Json(serde_json::json!({"success": true, "errors": []}))
    }

    async fn remove(
        State(z): State<Shared>,
        Path((_zone, id)): Path<(String, String)>,
    ) -> Json<serde_json::Value> {
        let mut z = z.lock().unwrap();
        let before = z.rows.len();
        z.rows.retain(|(rid, _, _)| *rid != id);
        if z.rows.len() == before {
            return Json(
                serde_json::json!({"success": false, "errors": [{"code": 81044, "message": "Record does not exist."}]}),
            );
        }
        z.log.push(format!("delete {id}"));
        Json(serde_json::json!({"success": true, "errors": []}))
    }

    async fn stub(rows: &[(&str, &str, &str)]) -> (CloudflareDns, Shared) {
        let zone: Shared = Arc::new(Mutex::new(Zone {
            rows: rows
                .iter()
                .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
                .collect(),
            ..Default::default()
        }));
        let app = Router::new()
            .route("/zones/{zone}/dns_records", get(list).post(create))
            .route("/zones/{zone}/dns_records/{id}", delete(remove))
            .with_state(zone.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (
            CloudflareDns::new("tok").with_base_url(format!("http://{addr}")),
            zone,
        )
    }

    #[tokio::test]
    async fn list_keeps_only_the_asked_name_even_when_the_server_filter_is_broken() {
        let (cf, _) = stub(&[
            ("r1", "yah.dev", "1.1.1.1"),
            ("r2", "www.yah.dev", "2.2.2.2"),
            ("r3", "YAH.DEV", "3.3.3.3"),
        ])
        .await;
        let got: Vec<String> = cf
            .list_a("zone-1", "yah.dev")
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.content)
            .collect();
        assert_eq!(got, vec!["1.1.1.1", "3.3.3.3"]);
    }

    #[tokio::test]
    async fn create_and_delete_round_trip_on_the_wire() {
        let (cf, zone) = stub(&[("r1", "yah.dev", "1.1.1.1")]).await;
        cf.create_a("zone-1", "yah.dev", "2.2.2.2", 300, false)
            .await
            .unwrap();
        cf.delete_record("zone-1", "r1").await.unwrap();
        let z = zone.lock().unwrap();
        assert_eq!(
            z.log,
            vec!["create yah.dev 2.2.2.2 ttl=300 proxied=false", "delete r1"]
        );
        assert_eq!(z.rows.len(), 1);
    }

    #[tokio::test]
    async fn a_rejected_call_surfaces_cloudflares_error() {
        let (cf, _) = stub(&[]).await;
        let err = cf.delete_record("zone-1", "nope").await.unwrap_err();
        assert!(format!("{err:#}").contains("81044"), "{err:#}");
    }
}
