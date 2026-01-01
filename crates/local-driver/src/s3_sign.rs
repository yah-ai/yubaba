//! AWS Signature Version 4 helpers for S3-compatible object storage.
//!
//! Shared by `provider::hetzner` (Hetzner Object Storage) and
//! `provider::local_docker` (MinIO). Both speak S3 + AWS SigV4 for bucket
//! create/head/delete; only the endpoint and region differ.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use reqwest::header::HeaderMap;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// AWS Sig V4 for any S3 verb that sends no body (PUT CreateBucket, HEAD,
/// DELETE bucket). Callers supply the full `url`, S3 `region` string, and
/// HMAC credentials.
pub fn sign_s3_empty_body(
    method: &str,
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed = reqwest::Url::parse(url).context("parsing S3 URL")?;
    let host = parsed.host_str().context("no host in S3 URL")?.to_string();
    let uri = parsed.path().to_string();

    let empty_hash = {
        let mut h = Sha256::new();
        h.update(b"");
        hex::encode(h.finalize())
    };

    let canonical_headers = format!(
        "content-length:0\nhost:{host}\nx-amz-content-sha256:{empty_hash}\nx-amz-date:{datetime}\n"
    );
    let signed_headers = "content-length;host;x-amz-content-sha256;x-amz-date";

    let canonical_request =
        format!("{method}\n{uri}\n\n{canonical_headers}\n{signed_headers}\n{empty_hash}");

    let cr_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let credential_scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    let hmac_sign = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };

    let date_key = hmac_sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sign(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sign(&date_region_key, b"s3");
    let signing_key = hmac_sign(&date_region_service_key, b"aws4_request");
    let signature = hex::encode(hmac_sign(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse()?);
    headers.insert("x-amz-date", datetime.parse()?);
    headers.insert("x-amz-content-sha256", empty_hash.parse()?);
    headers.insert("content-length", "0".parse()?);
    headers.insert("authorization", authorization.parse()?);
    Ok(headers)
}

pub fn sign_s3_put_bucket(
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    sign_s3_empty_body("PUT", url, region, access_key, secret_key)
}

pub fn sign_s3_head_bucket(
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    sign_s3_empty_body("HEAD", url, region, access_key, secret_key)
}

pub fn sign_s3_delete_bucket(
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    sign_s3_empty_body("DELETE", url, region, access_key, secret_key)
}

/// AWS Sig V4 for a `GET` with an empty body and a canonical query string.
///
/// `canonical_query` is the already-formed query (no leading `?`) sorted
/// lexicographically by parameter name with URL-encoded keys + values, e.g.
/// `"list-type=2&prefix=whisper%2F"`. The caller is responsible for ordering
/// and encoding; this helper signs the request as given.
///
/// Used by `ListObjectsV2`. The returned headers are suitable for `reqwest`'s
/// `GET <url>` where `<url>` already includes the `?<canonical_query>` suffix.
pub fn sign_s3_get_with_query(
    url: &str,
    canonical_query: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed = reqwest::Url::parse(url).context("parsing S3 URL")?;
    let host = parsed.host_str().context("no host in S3 URL")?.to_string();
    let uri = parsed.path().to_string();

    let empty_hash = {
        let mut h = Sha256::new();
        h.update(b"");
        hex::encode(h.finalize())
    };

    let canonical_headers = format!(
        "host:{host}\nx-amz-content-sha256:{empty_hash}\nx-amz-date:{datetime}\n"
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request = format!(
        "GET\n{uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{empty_hash}"
    );

    let cr_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let credential_scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    let hmac_sign = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };

    let date_key = hmac_sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sign(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sign(&date_region_key, b"s3");
    let signing_key = hmac_sign(&date_region_service_key, b"aws4_request");
    let signature = hex::encode(hmac_sign(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse()?);
    headers.insert("x-amz-date", datetime.parse()?);
    headers.insert("x-amz-content-sha256", empty_hash.parse()?);
    headers.insert("authorization", authorization.parse()?);
    Ok(headers)
}

/// AWS Sig V4 for `PUT /<bucket>/<key>` with an object body.
///
/// The caller pre-computes `body_sha256 = hex(sha256(body))` and passes
/// `content_length = body.len()` separately so the headers can be computed
/// without holding the bytes in this function.
pub fn sign_s3_put_object(
    url: &str,
    body_sha256: &str,
    content_type: &str,
    content_length: usize,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed = reqwest::Url::parse(url).context("parsing S3 object URL")?;
    let host = parsed.host_str().context("no host in S3 object URL")?.to_string();
    let uri = parsed.path().to_string();

    // Headers in lexicographic order (SigV4 requirement).
    let canonical_headers = format!(
        "content-length:{content_length}\ncontent-type:{content_type}\nhost:{host}\n\
         x-amz-content-sha256:{body_sha256}\nx-amz-date:{datetime}\n"
    );
    let signed_headers = "content-length;content-type;host;x-amz-content-sha256;x-amz-date";

    let canonical_request =
        format!("PUT\n{uri}\n\n{canonical_headers}\n{signed_headers}\n{body_sha256}");

    let cr_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let credential_scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    let hmac_sign = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };

    let date_key = hmac_sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sign(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sign(&date_region_key, b"s3");
    let signing_key = hmac_sign(&date_region_service_key, b"aws4_request");
    let signature = hex::encode(hmac_sign(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse()?);
    headers.insert("x-amz-date", datetime.parse()?);
    headers.insert("x-amz-content-sha256", body_sha256.parse()?);
    headers.insert("content-length", content_length.to_string().parse()?);
    headers.insert("content-type", content_type.parse()?);
    headers.insert("authorization", authorization.parse()?);
    Ok(headers)
}

/// AWS Sig V4 for `PUT /<bucket>?policy` with a JSON body.
///
/// Modern MinIO dropped the `?acl` endpoint; use this to apply an S3 bucket
/// policy document instead. The caller provides the raw JSON bytes; this
/// function hashes them for the signature and returns headers suitable for a
/// `reqwest` PUT with that body.
pub fn sign_s3_put_bucket_policy(
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    policy_json: &[u8],
) -> Result<HeaderMap> {
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed = reqwest::Url::parse(url).context("parsing S3 URL")?;
    let host = parsed.host_str().context("no host in S3 URL")?.to_string();
    let uri = parsed.path().to_string();
    let canonical_query = "policy=";
    let content_length = policy_json.len();

    let body_hash = {
        let mut h = Sha256::new();
        h.update(policy_json);
        hex::encode(h.finalize())
    };

    let canonical_headers = format!(
        "content-length:{content_length}\ncontent-type:application/json\nhost:{host}\nx-amz-content-sha256:{body_hash}\nx-amz-date:{datetime}\n"
    );
    let signed_headers = "content-length;content-type;host;x-amz-content-sha256;x-amz-date";

    let canonical_request =
        format!("PUT\n{uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{body_hash}");

    let cr_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let credential_scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    let hmac_sign = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };

    let date_key = hmac_sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sign(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sign(&date_region_key, b"s3");
    let signing_key = hmac_sign(&date_region_service_key, b"aws4_request");
    let signature = hex::encode(hmac_sign(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse()?);
    headers.insert("x-amz-date", datetime.parse()?);
    headers.insert("x-amz-content-sha256", body_hash.parse()?);
    headers.insert("content-length", content_length.to_string().parse()?);
    headers.insert("content-type", "application/json".parse()?);
    headers.insert("authorization", authorization.parse()?);
    Ok(headers)
}

/// AWS Sig V4 for `PUT /<bucket>?acl` with a canned-ACL header.
///
/// **Deprecated for MinIO**: modern MinIO does not implement the ACL endpoint.
/// Use [`sign_s3_put_bucket_policy`] for pond/local-docker targets and
/// keep this only for S3-compatible providers that still honour canned ACLs
/// (e.g. Hetzner Object Storage).
pub fn sign_s3_put_bucket_acl(
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    acl: &str,
) -> Result<HeaderMap> {
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed = reqwest::Url::parse(url).context("parsing S3 URL")?;
    let host = parsed.host_str().context("no host in S3 URL")?.to_string();
    let uri = parsed.path().to_string();
    let canonical_query = "acl=";

    let empty_hash = {
        let mut h = Sha256::new();
        h.update(b"");
        hex::encode(h.finalize())
    };

    // Headers listed in lexicographic order (required by SigV4).
    let canonical_headers = format!(
        "content-length:0\nhost:{host}\nx-amz-acl:{acl}\nx-amz-content-sha256:{empty_hash}\nx-amz-date:{datetime}\n"
    );
    let signed_headers = "content-length;host;x-amz-acl;x-amz-content-sha256;x-amz-date";

    let canonical_request =
        format!("PUT\n{uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{empty_hash}");

    let cr_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let credential_scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    let hmac_sign = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };

    let date_key = hmac_sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sign(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sign(&date_region_key, b"s3");
    let signing_key = hmac_sign(&date_region_service_key, b"aws4_request");
    let signature = hex::encode(hmac_sign(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse()?);
    headers.insert("x-amz-date", datetime.parse()?);
    headers.insert("x-amz-content-sha256", empty_hash.parse()?);
    headers.insert("content-length", "0".parse()?);
    headers.insert("x-amz-acl", acl.parse()?);
    headers.insert("authorization", authorization.parse()?);
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_produces_required_headers() {
        let headers = sign_s3_put_bucket(
            "https://fsn1.your-objectstorage.com/test-bucket",
            "fsn1",
            "AK",
            "SK",
        )
        .unwrap();
        assert!(headers.contains_key("authorization"));
        assert!(headers.contains_key("x-amz-date"));
        assert!(headers.contains_key("x-amz-content-sha256"));
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AK/"));
        assert!(
            auth.contains("SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date")
        );
    }

    #[test]
    fn sign_get_with_query_signed_headers_omit_content_length() {
        let headers = sign_s3_get_with_query(
            "https://acct.r2.cloudflarestorage.com/yah-dev",
            "list-type=2&prefix=whisper%2F",
            "auto",
            "AK",
            "SK",
        )
        .unwrap();
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AK/"));
        assert!(
            auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"),
            "GET with query must NOT include content-length in SignedHeaders: {auth}"
        );
        assert!(!headers.contains_key("content-length"));
    }

    #[test]
    fn sign_put_bucket_acl_includes_acl_header_and_query() {
        let headers = sign_s3_put_bucket_acl(
            "https://fsn1.your-objectstorage.com/test-bucket?acl",
            "fsn1",
            "AK",
            "SK",
            "public-read",
        )
        .unwrap();
        assert!(headers.contains_key("authorization"));
        assert!(headers.contains_key("x-amz-acl"));
        assert_eq!(headers.get("x-amz-acl").unwrap().to_str().unwrap(), "public-read");
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AK/"));
        assert!(auth.contains("x-amz-acl"));
        assert!(auth.contains("SignedHeaders=content-length;host;x-amz-acl;x-amz-content-sha256;x-amz-date"));
    }
}
