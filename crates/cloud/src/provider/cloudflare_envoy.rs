//! [`CloudflareEnvoy`] — tier-S adapter for Cloudflare R2 (`cloud.object.*`)
//! and Cloudflare DNS (`dns.*`) verbs (R409-T6).
//!
//! Wraps [`CloudflareClient`] and exposes the envoy framework's verb dispatch
//! interface. The client is held behind `Arc` so the adapter can be shared
//! without copying the underlying token.
//!
//! ## Verb coverage
//!
//! | Verb | Cloudflare API |
//! |---|---|
//! | `cloud.object.bucket.create` | `POST /accounts/{id}/r2/buckets` |
//! | `cloud.object.bucket.delete` | `DELETE /accounts/{id}/r2/buckets/{name}` |
//! | `cloud.object.bucket.exists` | `GET /accounts/{id}/r2/buckets` + name scan |
//! | `dns.record.upsert` | `GET` + `POST`/`PUT` `/zones/{id}/dns_records` |
//! | `dns.record.delete` | `GET` + `DELETE` `/zones/{id}/dns_records` |
//! | `dns.zone.list` | `GET /zones` |
//!
//! `cloud.object.bucket.acl.set` is not wired — Cloudflare R2 does not have
//! per-bucket ACLs in the S3 sense; public access is managed via custom
//! domains and Workers.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde_json::Value;

use super::cloudflare::CloudflareClient;
use crate::envoy::cloud_object::{
    CloudObjectBucketCreate, CloudObjectBucketCreateInput, CloudObjectBucketCreateOutput,
    CloudObjectBucketDelete, CloudObjectBucketDeleteInput, CloudObjectBucketDeleteOutput,
    CloudObjectBucketExists, CloudObjectBucketExistsInput, CloudObjectBucketExistsOutput,
};
use crate::envoy::dns_record::{
    DnsRecordDelete, DnsRecordDeleteInput, DnsRecordDeleteOutput, DnsRecordUpsert,
    DnsRecordUpsertInput, DnsRecordUpsertOutput, DnsZoneEntry, DnsZoneList, DnsZoneListInput,
    DnsZoneListOutput,
};
use crate::envoy::{AdapterFlavor, EnvoyAdapter, InternalVerb, Tier};

/// Tier-S, native-flavored envoy adapter for Cloudflare.
///
/// Covers two verb categories via [`CloudflareClient`]:
/// - `cloud.object.*` — R2 bucket lifecycle.
/// - `dns.*` — DNS record management and zone listing.
///
/// `account_id` is required for R2 operations. DNS operations resolve zone
/// names via `GET /zones` — no account_id needed.
pub struct CloudflareEnvoy {
    client: Arc<CloudflareClient>,
    account_id: String,
}

impl CloudflareEnvoy {
    /// Create an envoy adapter wrapping a fresh client for the given token
    /// and Cloudflare account.
    pub fn new(token: String, account_id: String) -> Self {
        Self {
            client: Arc::new(CloudflareClient::new(token)),
            account_id,
        }
    }

    /// Wrap an already-constructed (potentially shared) client.
    pub fn from_arc(client: Arc<CloudflareClient>, account_id: String) -> Self {
        Self { client, account_id }
    }

    // ── cloud.object.* ────────────────────────────────────────────────────

    /// Typed handler for `cloud.object.bucket.create`.
    ///
    /// The `location_hint` input field is forwarded to Cloudflare as a
    /// bucket-create body field when the CF API accepts it; today's
    /// [`CloudflareClient::create_r2_bucket`] does not expose it, so the
    /// hint is noted but not forwarded. Extend when bucket-placement control
    /// becomes a requirement.
    pub async fn cloud_object_bucket_create(
        &self,
        input: CloudObjectBucketCreateInput,
    ) -> Result<CloudObjectBucketCreateOutput> {
        let result = self
            .client
            .create_r2_bucket(&self.account_id, &input.name)
            .await
            .with_context(|| {
                format!("cloud.object.bucket.create: create {:?}", input.name)
            })?;
        Ok(CloudObjectBucketCreateOutput { endpoint: result.endpoint })
    }

    /// Typed handler for `cloud.object.bucket.delete`.
    pub async fn cloud_object_bucket_delete(
        &self,
        input: CloudObjectBucketDeleteInput,
    ) -> Result<CloudObjectBucketDeleteOutput> {
        self.client
            .delete_r2_bucket(&self.account_id, &input.name)
            .await
            .with_context(|| {
                format!("cloud.object.bucket.delete: delete {:?}", input.name)
            })?;
        Ok(CloudObjectBucketDeleteOutput::default())
    }

    /// Typed handler for `cloud.object.bucket.exists`.
    ///
    /// Implemented by listing all R2 buckets and scanning for the name.
    /// Cloudflare has no dedicated HEAD endpoint for R2 buckets.
    pub async fn cloud_object_bucket_exists(
        &self,
        input: CloudObjectBucketExistsInput,
    ) -> Result<CloudObjectBucketExistsOutput> {
        let buckets = self
            .client
            .list_r2_buckets(&self.account_id)
            .await
            .context("cloud.object.bucket.exists: list buckets")?;
        let found = buckets.iter().any(|b| b.name == input.name);
        Ok(CloudObjectBucketExistsOutput {
            exists: found,
            endpoint: if found {
                Some(format!(
                    "https://{}.r2.cloudflarestorage.com",
                    self.account_id
                ))
            } else {
                None
            },
        })
    }

    // ── dns.* ─────────────────────────────────────────────────────────────

    /// Typed handler for `dns.record.upsert`. Resolves the zone name to an
    /// ID, then upserts the record via [`CloudflareClient::upsert_dns_record`].
    pub async fn dns_record_upsert(
        &self,
        input: DnsRecordUpsertInput,
    ) -> Result<DnsRecordUpsertOutput> {
        let zone_id = self
            .client
            .zone_id_for_name(&input.zone)
            .await
            .with_context(|| {
                format!("dns.record.upsert: resolve zone {:?}", input.zone)
            })?;
        let id = self
            .client
            .upsert_dns_record(
                &zone_id,
                &input.name,
                &input.record_type,
                &input.content,
                input.ttl,
                input.proxied,
            )
            .await
            .with_context(|| {
                format!(
                    "dns.record.upsert: {}/{} {}",
                    input.zone, input.name, input.record_type
                )
            })?;
        Ok(DnsRecordUpsertOutput { id })
    }

    /// Typed handler for `dns.record.delete`.
    pub async fn dns_record_delete(
        &self,
        input: DnsRecordDeleteInput,
    ) -> Result<DnsRecordDeleteOutput> {
        let zone_id = self
            .client
            .zone_id_for_name(&input.zone)
            .await
            .with_context(|| {
                format!("dns.record.delete: resolve zone {:?}", input.zone)
            })?;
        let deleted = self
            .client
            .delete_dns_records(&zone_id, &input.name, input.record_type.as_deref())
            .await
            .with_context(|| {
                format!("dns.record.delete: {}/{}", input.zone, input.name)
            })?;
        Ok(DnsRecordDeleteOutput { deleted })
    }

    /// Typed handler for `dns.zone.list`.
    pub async fn dns_zone_list(&self, _input: DnsZoneListInput) -> Result<DnsZoneListOutput> {
        let zones = self.client.list_zones().await.context("dns.zone.list")?;
        Ok(DnsZoneListOutput {
            zones: zones
                .into_iter()
                .map(|(id, name)| DnsZoneEntry { id, name })
                .collect(),
        })
    }
}

#[async_trait]
impl EnvoyAdapter for CloudflareEnvoy {
    fn id(&self) -> &str {
        "cloudflare"
    }
    fn tier(&self) -> Tier {
        Tier::S
    }
    fn flavor(&self) -> AdapterFlavor {
        AdapterFlavor::Native
    }
    fn supported_verb_ids(&self) -> Vec<&'static str> {
        vec![
            CloudObjectBucketCreate::ID,
            CloudObjectBucketDelete::ID,
            CloudObjectBucketExists::ID,
            DnsRecordUpsert::ID,
            DnsRecordDelete::ID,
            DnsZoneList::ID,
        ]
    }
    async fn dispatch(&self, verb_id: &str, input: Value) -> Result<Value> {
        match verb_id {
            id if id == CloudObjectBucketCreate::ID => {
                let args: CloudObjectBucketCreateInput = serde_json::from_value(input)
                    .with_context(|| format!("{id}: decode input"))?;
                let out = self.cloud_object_bucket_create(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            id if id == CloudObjectBucketDelete::ID => {
                let args: CloudObjectBucketDeleteInput = serde_json::from_value(input)
                    .with_context(|| format!("{id}: decode input"))?;
                let out = self.cloud_object_bucket_delete(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            id if id == CloudObjectBucketExists::ID => {
                let args: CloudObjectBucketExistsInput = serde_json::from_value(input)
                    .with_context(|| format!("{id}: decode input"))?;
                let out = self.cloud_object_bucket_exists(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            id if id == DnsRecordUpsert::ID => {
                let args: DnsRecordUpsertInput = serde_json::from_value(input)
                    .with_context(|| format!("{id}: decode input"))?;
                let out = self.dns_record_upsert(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            id if id == DnsRecordDelete::ID => {
                let args: DnsRecordDeleteInput = serde_json::from_value(input)
                    .with_context(|| format!("{id}: decode input"))?;
                let out = self.dns_record_delete(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            id if id == DnsZoneList::ID => {
                let args: DnsZoneListInput = serde_json::from_value(input)
                    .with_context(|| format!("{id}: decode input"))?;
                let out = self.dns_zone_list(args).await?;
                Ok(serde_json::to_value(out)?)
            }
            other => bail!("cloudflare envoy does not support verb {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_envoy_metadata() {
        let envoy = CloudflareEnvoy::new("tok".into(), "acct123".into());
        assert_eq!(envoy.id(), "cloudflare");
        assert_eq!(envoy.tier(), Tier::S);
        assert_eq!(envoy.flavor(), AdapterFlavor::Native);
    }

    #[test]
    fn supported_verb_ids_covers_both_categories() {
        let envoy = CloudflareEnvoy::new("tok".into(), "acct123".into());
        let ids = envoy.supported_verb_ids();
        // cloud.object.*
        assert!(ids.contains(&"cloud.object.bucket.create"), "{ids:?}");
        assert!(ids.contains(&"cloud.object.bucket.delete"), "{ids:?}");
        assert!(ids.contains(&"cloud.object.bucket.exists"), "{ids:?}");
        // dns.*
        assert!(ids.contains(&"dns.record.upsert"), "{ids:?}");
        assert!(ids.contains(&"dns.record.delete"), "{ids:?}");
        assert!(ids.contains(&"dns.zone.list"), "{ids:?}");
    }

    #[tokio::test]
    async fn dispatch_rejects_unsupported_verb() {
        let envoy = CloudflareEnvoy::new("tok".into(), "acct123".into());
        let err = envoy
            .dispatch("cloud.vps.create", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("cloud.vps.create"),
            "error should name the rejected verb: {err}"
        );
    }
}
