//! Litestream sidecar management for Headscale HA (R040-F21).
//!
//! On Phase 2 leader election:
//! 1. Run `litestream restore` to pull the latest Headscale SQLite snapshot
//!    from S3 before starting Headscale.
//! 2. Enable + start `litestream-replicate.service` so WAL frames are
//!    continuously streamed to S3 while this node is the leader.
//!
//! On leadership loss:
//! 1. Stop `litestream-replicate.service` so only the leader replicates.
//!    (Followers pre-warm by periodic snapshot pulls — not implemented here
//!    yet; relevant only when promotion latency matters at >100 nodes.)
//!
//! ## Credentials
//!
//! Litestream reads S3 credentials from environment variables:
//!   `LITESTREAM_ACCESS_KEY_ID` / `LITESTREAM_SECRET_ACCESS_KEY`
//! These must be present in the systemd unit's environment (via
//! `EnvironmentFile=/etc/yah-cloud/litestream.env` or a direct
//! `Environment=` directive).  The yubaba does not manage the credentials
//! themselves; inject them at provision time via cloud-init.
//!
//! ## S3 URL format
//!
//! `s3://bucket/prefix?endpoint=https://fsn1.your-objectstorage.com`
//!
//! The `?endpoint=` query parameter is passed through to litestream's
//! `endpoint` config key (Hetzner Object Storage, Backblaze B2, MinIO, etc.).

use std::path::Path;
use anyhow::Result;

/// Name of the litestream replicate systemd unit.
pub const LITESTREAM_UNIT: &str = "litestream-headscale.service";
/// Default litestream config path on the machine.
pub const LITESTREAM_CONFIG_PATH: &str = "/etc/yah-cloud/litestream.yml";

/// Generate a litestream config YAML for replicating `headscale_db` to `s3_url`.
///
/// The `?endpoint=` query parameter in `s3_url` is extracted and written as a
/// separate `endpoint:` key in the replica config.
pub fn generate_config(headscale_db: &Path, s3_url: &str) -> String {
    let (url_without_query, endpoint) = split_s3_url(s3_url);
    let endpoint_line = match endpoint {
        Some(ep) => format!("        endpoint: {ep}\n"),
        None => String::new(),
    };
    format!(
        "---\ndbs:\n  - path: {db_path}\n    replicas:\n      - url: {s3_url}\n{endpoint_line}\
         access-key-id: ${{LITESTREAM_ACCESS_KEY_ID}}\n        secret-access-key: ${{LITESTREAM_SECRET_ACCESS_KEY}}\n",
        db_path = headscale_db.display(),
        s3_url = url_without_query,
    )
}

/// Write the litestream config to `LITESTREAM_CONFIG_PATH` and install
/// the `litestream-headscale.service` systemd unit (idempotent).
///
/// Credentials are read from `LITESTREAM_ACCESS_KEY_ID` /
/// `LITESTREAM_SECRET_ACCESS_KEY` in the environment — inject via
/// `/etc/yah-cloud/litestream.env` or cloud-init `EnvironmentFile`.
pub fn install(headscale_db: &Path, s3_url: &str) -> Result<()> {
    let config = generate_config(headscale_db, s3_url);
    std::fs::write(LITESTREAM_CONFIG_PATH, &config)?;

    let unit = format!(
        "[Unit]\n\
         Description=Litestream Headscale replication (yah-yubaba Phase 2)\n\
         After=headscale.service\n\
         BindsTo=headscale.service\n\
         \n\
         [Service]\n\
         EnvironmentFile=-/etc/yah-cloud/litestream.env\n\
         ExecStart=/usr/local/bin/litestream replicate -config {cfg}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=headscale.service\n",
        cfg = LITESTREAM_CONFIG_PATH,
    );
    let unit_path = format!("/etc/systemd/system/{LITESTREAM_UNIT}");
    std::fs::write(&unit_path, unit)?;
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();
    Ok(())
}

/// Start `litestream-headscale.service` (idempotent — no-op if already running).
pub fn start() {
    let _ = std::process::Command::new("systemctl")
        .args(["start", LITESTREAM_UNIT])
        .status();
}

/// Stop `litestream-headscale.service`.
pub fn stop() {
    let _ = std::process::Command::new("systemctl")
        .args(["stop", LITESTREAM_UNIT])
        .status();
}

/// Run `litestream restore` to pull the latest Headscale DB snapshot from S3
/// before starting Headscale on a newly-elected leader.
///
/// Uses `-if-replica-exists` so the call is a no-op on first bootstrap (no
/// snapshot in S3 yet).  Runs the blocking child process in a `spawn_blocking`
/// task so it doesn't stall the async runtime.
pub async fn restore(headscale_db: &Path, s3_url: &str) -> Result<()> {
    let (url_without_query, _) = split_s3_url(s3_url);
    let db_path = headscale_db.to_string_lossy().into_owned();
    let url_clone = url_without_query.clone();

    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("litestream")
            .args([
                "restore",
                "-if-replica-exists",
                "-config",
                LITESTREAM_CONFIG_PATH,
                "-o",
                &db_path,
                &url_clone,
            ])
            .status()
    })
    .await??;

    if !status.success() {
        anyhow::bail!(
            "litestream restore from {url_without_query} failed (exit {})",
            status.code().unwrap_or(-1)
        );
    }
    tracing::info!("litestream restore complete from {}", url_without_query);
    Ok(())
}

/// Split `s3://bucket/path?endpoint=https://...` into
/// `(s3://bucket/path, Some("https://..."))`.
fn split_s3_url(url: &str) -> (String, Option<String>) {
    match url.split_once('?') {
        None => (url.to_owned(), None),
        Some((base, query)) => {
            let endpoint = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("endpoint="))
                .map(|v| v.to_owned());
            (base.to_owned(), endpoint)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn split_url_no_query() {
        let (base, ep) = split_s3_url("s3://my-bucket/headscale");
        assert_eq!(base, "s3://my-bucket/headscale");
        assert!(ep.is_none());
    }

    #[test]
    fn split_url_with_endpoint() {
        let (base, ep) = split_s3_url(
            "s3://my-bucket/headscale?endpoint=https://fsn1.your-objectstorage.com",
        );
        assert_eq!(base, "s3://my-bucket/headscale");
        assert_eq!(ep.as_deref(), Some("https://fsn1.your-objectstorage.com"));
    }

    #[test]
    fn generate_config_contains_db_path() {
        let cfg = generate_config(
            &PathBuf::from("/etc/yah-cloud/headscale/headscale.db"),
            "s3://bucket/headscale",
        );
        assert!(cfg.contains("/etc/yah-cloud/headscale/headscale.db"), "db path missing");
        assert!(cfg.contains("s3://bucket/headscale"), "s3 url missing");
        assert!(cfg.contains("LITESTREAM_ACCESS_KEY_ID"), "cred placeholder missing");
    }
}
