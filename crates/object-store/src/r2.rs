//! Cloudflare R2 implementation of [`ObjectStore`] over S3-compat SigV4.
//!
//! Uses `local_driver::s3_sign` helpers for signature computation and
//! `reqwest::blocking` for HTTP so the [`ObjectStore`] trait stays synchronous.
//! Async consumers wrap calls in `tokio::task::spawn_blocking`.
//!
//! ## Endpoint
//!
//! R2's S3-compat endpoint is `https://<account_id>.r2.cloudflarestorage.com`.
//! Region is always `"auto"`. Bucket lives in the URL path:
//! `https://<account_id>.r2.cloudflarestorage.com/<bucket>/<key>`.
//!
//! ## list_prefix
//!
//! Issues `GET /<bucket>?list-type=2&prefix=<encoded>` (ListObjectsV2) and
//! parses the `<Key>…</Key>` elements out of the XML body. Continues with
//! `&continuation-token=<…>` while `<IsTruncated>true</IsTruncated>` so
//! prefixes larger than the 1000-key page size return complete.

use std::time::Duration;

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, ETAG, IF_MATCH, IF_NONE_MATCH};
use reqwest::StatusCode;
use sha2::{Digest, Sha256};

use local_driver::s3_sign::{
    sign_s3_empty_body, sign_s3_get_with_query, sign_s3_no_body, sign_s3_put_object,
};

use crate::{Error, ObjectStore, Precondition};

/// R2's S3-compat region. The endpoint always accepts `"auto"`.
const R2_REGION: &str = "auto";

/// Keystore slot for the R2 S3 access key id.
pub const R2_ACCESS_KEY_SLOT: &str = "cloudflare-r2-access-key-id";
/// Keystore slot for the R2 S3 secret key.
pub const R2_SECRET_KEY_SLOT: &str = "cloudflare-r2-secret-key";
/// Env var fallback for the R2 access key id.
pub const R2_ACCESS_KEY_ENV: &str = "CF_R2_ACCESS_KEY_ID";
/// Env var fallback for the R2 secret key.
pub const R2_SECRET_KEY_ENV: &str = "CF_R2_SECRET_KEY";

/// Percent-encoding set for query-string values. SigV4 requires
/// unreserved characters (A-Z a-z 0-9 - _ . ~) to remain literal;
/// everything else gets percent-encoded.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Default content-type when the caller doesn't specify one.
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// R2-backed [`ObjectStore`].
///
/// Construct with [`R2ObjectStore::new`] when keys are already in hand,
/// or [`R2ObjectStore::from_vault`] to pull them from the yah keystore
/// (with env-var fallback).
pub struct R2ObjectStore {
    account_id: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    client: Client,
}

impl R2ObjectStore {
    /// Construct with explicit keys.
    ///
    /// `account_id` is the Cloudflare account id (the subdomain in
    /// `<account_id>.r2.cloudflarestorage.com`).
    pub fn new(
        account_id: impl Into<String>,
        bucket: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Result<Self, Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| Error::Backend(format!("reqwest client: {e}")))?;
        Ok(Self {
            account_id: account_id.into(),
            bucket: bucket.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            client,
        })
    }

    /// Construct from the yah keystore (vault), falling back to env vars.
    ///
    /// Reads `cloudflare-r2-access-key-id` / `cloudflare-r2-secret-key` slots
    /// (env fallback `CF_R2_ACCESS_KEY_ID` / `CF_R2_SECRET_KEY`). Returns
    /// [`Error::Auth`] if either is missing.
    pub fn from_vault(
        account_id: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Result<Self, Error> {
        let access_key = fob::get_or_env(R2_ACCESS_KEY_SLOT, R2_ACCESS_KEY_ENV)
            .map_err(|e| Error::Auth(format!("vault read {R2_ACCESS_KEY_SLOT}: {e}")))?
            .ok_or_else(|| {
                Error::Auth(format!(
                    "missing R2 credential: set vault slot {R2_ACCESS_KEY_SLOT} or env {R2_ACCESS_KEY_ENV}"
                ))
            })?;
        let secret_key = fob::get_or_env(R2_SECRET_KEY_SLOT, R2_SECRET_KEY_ENV)
            .map_err(|e| Error::Auth(format!("vault read {R2_SECRET_KEY_SLOT}: {e}")))?
            .ok_or_else(|| {
                Error::Auth(format!(
                    "missing R2 credential: set vault slot {R2_SECRET_KEY_SLOT} or env {R2_SECRET_KEY_ENV}"
                ))
            })?;
        Self::new(account_id, bucket, access_key, secret_key)
    }

    fn endpoint(&self) -> String {
        format!("https://{}.r2.cloudflarestorage.com", self.account_id)
    }

    fn object_url(&self, key: &str) -> String {
        format!("{}/{}/{}", self.endpoint(), self.bucket, key)
    }

    fn bucket_url(&self) -> String {
        format!("{}/{}", self.endpoint(), self.bucket)
    }
}

/// Convert a reqwest error into our generic [`Error`].
fn io_err(ctx: &str, e: impl std::fmt::Display) -> Error {
    Error::Io(format!("{ctx}: {e}"))
}

impl ObjectStore for R2ObjectStore {
    fn put(&self, key: &str, data: Vec<u8>) -> Result<(), Error> {
        let url = self.object_url(key);
        let body_sha256 = {
            let mut h = Sha256::new();
            h.update(&data);
            hex::encode(h.finalize())
        };
        let headers = sign_s3_put_object(
            &url,
            &body_sha256,
            DEFAULT_CONTENT_TYPE,
            data.len(),
            R2_REGION,
            &self.access_key,
            &self.secret_key,
        )
        .map_err(|e| Error::Backend(format!("sign PUT {key}: {e}")))?;

        let resp = self
            .client
            .put(&url)
            .headers(headers)
            .body(data)
            .send()
            .map_err(|e| io_err(&format!("PUT {key}"), e))?;
        check_status(resp, "PUT", key)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        let url = self.object_url(key);
        // GET has no body: reqwest drops the `content-length: 0` header on the
        // wire, so signing it (as `sign_s3_empty_body` does) yields a signature
        // the server can't reproduce → 403 SignatureDoesNotMatch. Sign with the
        // content-length-free helper instead, exactly like ListObjectsV2. The
        // empty query string is correct for a plain object GET.
        let headers = sign_s3_get_with_query(
            &url,
            "",
            R2_REGION,
            &self.access_key,
            &self.secret_key,
        )
        .map_err(|e| Error::Backend(format!("sign GET {key}: {e}")))?;

        let resp = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .map_err(|e| io_err(&format!("GET {key}"), e))?;

        match resp.status() {
            StatusCode::OK => {
                let bytes = resp
                    .bytes()
                    .map_err(|e| io_err(&format!("read GET {key}"), e))?;
                Ok(Some(bytes.to_vec()))
            }
            StatusCode::NOT_FOUND => Ok(None),
            s => Err(status_err("GET", key, s, resp.text().ok())),
        }
    }

    fn head(&self, key: &str) -> Result<bool, Error> {
        let url = self.object_url(key);
        // HEAD is body-less like GET: sign without content-length (see `get`).
        let headers = sign_s3_no_body(
            "HEAD",
            &url,
            "",
            R2_REGION,
            &self.access_key,
            &self.secret_key,
        )
        .map_err(|e| Error::Backend(format!("sign HEAD {key}: {e}")))?;

        let resp = self
            .client
            .head(&url)
            .headers(headers)
            .send()
            .map_err(|e| io_err(&format!("HEAD {key}"), e))?;

        match resp.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => Err(status_err("HEAD", key, s, None)),
        }
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        let url = self.object_url(key);
        let headers = sign_s3_empty_body(
            "DELETE",
            &url,
            R2_REGION,
            &self.access_key,
            &self.secret_key,
        )
        .map_err(|e| Error::Backend(format!("sign DELETE {key}: {e}")))?;

        let resp = self
            .client
            .delete(&url)
            .headers(headers)
            .send()
            .map_err(|e| io_err(&format!("DELETE {key}"), e))?;

        match resp.status() {
            // S3 DELETE on a missing key returns 204 too — both are success
            // semantics for an idempotent delete.
            StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => Ok(()),
            s => Err(status_err("DELETE", key, s, resp.text().ok())),
        }
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, Error> {
        Ok(self
            .list_prefix_detailed(prefix)?
            .into_iter()
            .map(|m| m.key)
            .collect())
    }

    fn put_if(&self, key: &str, data: Vec<u8>, cond: Precondition) -> Result<String, Error> {
        let url = self.object_url(key);
        let body_sha256 = {
            let mut h = Sha256::new();
            h.update(&data);
            hex::encode(h.finalize())
        };
        // Sign the same fixed header set as an unconditional PUT. The conditional
        // header (If-Match / If-None-Match) is added *unsigned* afterwards: SigV4
        // only covers the headers in `SignedHeaders`, and S3/R2 honor extra
        // unsigned headers — so the precondition is enforced server-side without
        // touching the signer.
        let mut headers = sign_s3_put_object(
            &url,
            &body_sha256,
            DEFAULT_CONTENT_TYPE,
            data.len(),
            R2_REGION,
            &self.access_key,
            &self.secret_key,
        )
        .map_err(|e| Error::Backend(format!("sign PUT {key}: {e}")))?;

        match &cond {
            Precondition::IfAbsent => {
                headers.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
            }
            Precondition::IfMatch(etag) => {
                let v = HeaderValue::from_str(etag)
                    .map_err(|e| Error::Backend(format!("invalid If-Match etag {etag:?}: {e}")))?;
                headers.insert(IF_MATCH, v);
            }
        }

        let resp = self
            .client
            .put(&url)
            .headers(headers)
            .body(data)
            .send()
            .map_err(|e| io_err(&format!("PUT(if) {key}"), e))?;

        let status = resp.status();
        if status == StatusCode::PRECONDITION_FAILED {
            return Err(Error::PreconditionFailed(format!(
                "put_if {key}: precondition not met ({cond:?})"
            )));
        }
        if !status.is_success() {
            return Err(status_err("PUT(if)", key, status, resp.text().ok()));
        }
        // Prefer the ETag echoed in the PUT response; fall back to a HEAD if a
        // backend ever omits it (R2 always returns it).
        match resp.headers().get(ETAG).and_then(|v| v.to_str().ok()) {
            Some(e) => Ok(e.to_string()),
            None => self
                .etag(key)?
                .ok_or_else(|| Error::Backend(format!("PUT(if) {key} returned no ETag"))),
        }
    }

    fn etag(&self, key: &str) -> Result<Option<String>, Error> {
        let url = self.object_url(key);
        // HEAD is body-less: sign without content-length (see `head`).
        let headers = sign_s3_no_body(
            "HEAD",
            &url,
            "",
            R2_REGION,
            &self.access_key,
            &self.secret_key,
        )
        .map_err(|e| Error::Backend(format!("sign HEAD {key}: {e}")))?;

        let resp = self
            .client
            .head(&url)
            .headers(headers)
            .send()
            .map_err(|e| io_err(&format!("HEAD(etag) {key}"), e))?;

        match resp.status() {
            StatusCode::OK => Ok(resp
                .headers()
                .get(ETAG)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())),
            StatusCode::NOT_FOUND => Ok(None),
            s => Err(status_err("HEAD(etag)", key, s, None)),
        }
    }
}

/// One `<Contents>` entry from an R2 `ListObjectsV2` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    /// Object key (full path including any prefix).
    pub key: String,
    /// Object size in bytes.
    pub size: u64,
    /// Last-modified timestamp in ISO-8601 / RFC-3339 (R2's `<LastModified>` value).
    pub last_modified: String,
}

impl R2ObjectStore {
    /// List objects under `prefix` returning key + size + last-modified.
    ///
    /// Same paginated request as [`ObjectStore::list_prefix`] but parses the
    /// `<Size>` and `<LastModified>` siblings of each `<Key>` element. Used by
    /// the data-tab bucket viewer to render a directory-style listing.
    pub fn list_prefix_detailed(&self, prefix: &str) -> Result<Vec<ObjectMeta>, Error> {
        let mut entries = Vec::new();
        let mut continuation_token: Option<String> = None;
        let bucket_url = self.bucket_url();
        let encoded_prefix = utf8_percent_encode(prefix, QUERY_VALUE).to_string();

        loop {
            // Canonical query MUST be sorted by parameter name (SigV4).
            // Parameters: continuation-token (optional), list-type, prefix.
            let mut params: Vec<(String, String)> =
                vec![("list-type".to_string(), "2".to_string())];
            if let Some(token) = &continuation_token {
                let encoded = utf8_percent_encode(token, QUERY_VALUE).to_string();
                params.push(("continuation-token".to_string(), encoded));
            }
            params.push(("prefix".to_string(), encoded_prefix.clone()));
            params.sort_by(|a, b| a.0.cmp(&b.0));
            let canonical_query = params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");

            let url_with_query = format!("{bucket_url}?{canonical_query}");

            let headers = sign_s3_get_with_query(
                &bucket_url,
                &canonical_query,
                R2_REGION,
                &self.access_key,
                &self.secret_key,
            )
            .map_err(|e| Error::Backend(format!("sign LIST {prefix}: {e}")))?;

            let resp = self
                .client
                .get(&url_with_query)
                .headers(headers)
                .send()
                .map_err(|e| io_err(&format!("LIST {prefix}"), e))?;

            if !resp.status().is_success() {
                return Err(status_err("LIST", prefix, resp.status(), resp.text().ok()));
            }
            let body = resp
                .text()
                .map_err(|e| io_err(&format!("LIST {prefix} body"), e))?;
            let (page_entries, next_token) = parse_list_v2_detailed(&body);
            entries.extend(page_entries);
            if let Some(t) = next_token {
                continuation_token = Some(t);
            } else {
                break;
            }
        }
        Ok(entries)
    }
}

fn check_status(resp: reqwest::blocking::Response, verb: &str, key: &str) -> Result<(), Error> {
    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().ok();
        Err(status_err(verb, key, status, body))
    }
}

fn status_err(verb: &str, key: &str, status: StatusCode, body: Option<String>) -> Error {
    let snippet = body
        .as_deref()
        .map(|s| s.chars().take(200).collect::<String>())
        .unwrap_or_default();
    let msg = format!("{verb} {key} → {status} {snippet}");
    match status {
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Error::Auth(msg),
        StatusCode::NOT_FOUND => Error::NotFound(msg),
        _ => Error::Backend(msg),
    }
}

/// Parse a `ListObjectsV2` XML response for keys + next continuation token.
///
/// Deliberately tiny — full XML parsing is overkill for the two elements we
/// care about. Looks for `<Key>...</Key>` and `<NextContinuationToken>...`
/// inside the body. If R2 ever changes the element shape (it won't — it's
/// S3-compat), the integration test catches it.
fn parse_list_v2(body: &str) -> (Vec<String>, Option<String>) {
    let keys = extract_all_tags(body, "Key");
    let next = extract_first_tag(body, "NextContinuationToken");
    let truncated = extract_first_tag(body, "IsTruncated")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    (keys, if truncated { next } else { None })
}

/// Parse `<Contents>` blocks for key + size + last-modified.
///
/// R2's `<Contents>` always has `<Key>` followed by `<LastModified>` and
/// `<Size>` siblings. We walk `<Contents>...</Contents>` blocks and pull the
/// three tags from each — order-insensitive within the block. Entries missing
/// any of the three are skipped (defensive — R2 always emits all three).
fn parse_list_v2_detailed(body: &str) -> (Vec<ObjectMeta>, Option<String>) {
    let blocks = extract_all_tags(body, "Contents");
    let entries = blocks
        .into_iter()
        .filter_map(|block| {
            let key = extract_first_tag(&block, "Key")?;
            let size = extract_first_tag(&block, "Size")?.trim().parse::<u64>().ok()?;
            let last_modified = extract_first_tag(&block, "LastModified")?;
            Some(ObjectMeta { key, size, last_modified })
        })
        .collect();
    let next = extract_first_tag(body, "NextContinuationToken");
    let truncated = extract_first_tag(body, "IsTruncated")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    (entries, if truncated { next } else { None })
}

fn extract_all_tags(body: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut search = body;
    while let Some(start) = search.find(&open) {
        let content_start = start + open.len();
        if let Some(end) = search[content_start..].find(&close) {
            out.push(search[content_start..content_start + end].to_string());
            search = &search[content_start + end + close.len()..];
        } else {
            break;
        }
    }
    out
}

fn extract_first_tag(body: &str, tag: &str) -> Option<String> {
    extract_all_tags(body, tag).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_v2_extracts_keys() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
            <ListBucketResult>
                <IsTruncated>false</IsTruncated>
                <Contents><Key>yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz</Key></Contents>
                <Contents><Key>yubaba/release-manifest.json</Key></Contents>
            </ListBucketResult>"#;
        let (keys, next) = parse_list_v2(body);
        assert_eq!(
            keys,
            vec![
                "yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz".to_string(),
                "yubaba/release-manifest.json".to_string(),
            ]
        );
        assert!(next.is_none());
    }

    #[test]
    fn parse_list_v2_returns_continuation_when_truncated() {
        let body = r#"<ListBucketResult>
                <IsTruncated>true</IsTruncated>
                <NextContinuationToken>abc123</NextContinuationToken>
                <Contents><Key>a</Key></Contents>
            </ListBucketResult>"#;
        let (keys, next) = parse_list_v2(body);
        assert_eq!(keys, vec!["a".to_string()]);
        assert_eq!(next.as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_list_v2_ignores_token_when_not_truncated() {
        // Some S3-compat impls emit NextContinuationToken with IsTruncated=false.
        // We treat IsTruncated as load-bearing.
        let body = r#"<ListBucketResult>
                <IsTruncated>false</IsTruncated>
                <NextContinuationToken>stale</NextContinuationToken>
                <Contents><Key>a</Key></Contents>
            </ListBucketResult>"#;
        let (_, next) = parse_list_v2(body);
        assert!(next.is_none());
    }

    #[test]
    fn parse_list_v2_detailed_extracts_size_and_mtime() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
            <ListBucketResult>
                <IsTruncated>false</IsTruncated>
                <Contents>
                    <Key>yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz</Key>
                    <LastModified>2026-06-08T20:14:32.000Z</LastModified>
                    <ETag>"abc"</ETag>
                    <Size>4823104</Size>
                    <StorageClass>STANDARD</StorageClass>
                </Contents>
                <Contents>
                    <Key>yubaba/release-manifest.json</Key>
                    <LastModified>2026-06-08T20:14:35.000Z</LastModified>
                    <Size>412</Size>
                </Contents>
            </ListBucketResult>"#;
        let (entries, next) = parse_list_v2_detailed(body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz");
        assert_eq!(entries[0].size, 4823104);
        assert_eq!(entries[0].last_modified, "2026-06-08T20:14:32.000Z");
        assert_eq!(entries[1].key, "yubaba/release-manifest.json");
        assert_eq!(entries[1].size, 412);
        assert!(next.is_none());
    }

    #[test]
    fn r2_object_store_constructs_with_explicit_keys() {
        let s = R2ObjectStore::new("acct", "yah-dev", "AK", "SK").unwrap();
        assert_eq!(s.object_url("k"), "https://acct.r2.cloudflarestorage.com/yah-dev/k");
        assert_eq!(s.bucket_url(), "https://acct.r2.cloudflarestorage.com/yah-dev");
    }

    #[test]
    fn object_url_preserves_slashes_in_key() {
        let s = R2ObjectStore::new("acct", "b", "AK", "SK").unwrap();
        assert_eq!(
            s.object_url("yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz"),
            "https://acct.r2.cloudflarestorage.com/b/yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz"
        );
    }
}
