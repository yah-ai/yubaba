//! Where a feed's materialized JSON artifact lands (R330-F12).
//!
//! Almanac feeds fetch from a source adapter, serialize a [`ReleaseFeed`], and
//! write the bytes somewhere. Two destinations exist:
//!
//!   - [`FeedSink::LocalFile`] — the single-tenant / dev path. The bytes become
//!     a file under the workload's project root, which the mesofact build reads
//!     as a route `data_input` (file-watch rebuild in `mesofact-dev`). This is
//!     what the `almanac-serve` binary has always done.
//!
//!   - [`FeedSink::Object`] — the cloud multi-tenant path. The bytes are PUT to
//!     a key in a tenant's object store. This is the crux of F12 and its lead
//!     gotcha: **output is the tenant's storage, not the runner's**. The runner
//!     writes into each tenant's bucket via that tenant's provider-scoped creds.
//!
//! Credential resolution (provider id → R2 account + S3 keys, keystore-ref →
//! secret) is the *caller's* job — it lives at the service-deployment layer
//! where infra creds are reachable. This module only takes an already-built
//! [`ObjectStore`] (or explicit R2 keys via [`FeedSink::r2`]) and writes, so the
//! sink stays hermetically testable with [`yah_object_store::InMemoryObjectStore`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use yah_object_store::{ObjectStore, R2ObjectStore};

/// Errors raised while writing an artifact to a [`FeedSink`].
#[derive(Debug, Error)]
pub enum SinkError {
    #[error("I/O error writing artifact {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("object-store write to key {key} failed: {source}")]
    ObjectStore {
        key: String,
        #[source]
        source: yah_object_store::Error,
    },
    #[error("object-store write task panicked: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("building R2 object store: {0}")]
    Build(String),
}

/// A feed-artifact write destination.
#[derive(Clone)]
pub enum FeedSink {
    /// Write to a local file (single-tenant / dev `data_input` path).
    LocalFile(PathBuf),
    /// PUT the bytes to `key` in a tenant's object store (cloud multi-tenant).
    Object {
        store: Arc<dyn ObjectStore>,
        key: String,
    },
}

/// Where an artifact actually landed — for logging and [`crate::RunResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkTarget {
    /// A local filesystem path.
    File(PathBuf),
    /// An object-store key (the bucket is fixed by the store the sink holds).
    Object { key: String },
}

impl std::fmt::Display for SinkTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SinkTarget::File(p) => write!(f, "file://{}", p.display()),
            SinkTarget::Object { key } => write!(f, "object://{key}"),
        }
    }
}

impl FeedSink {
    /// Build an R2-backed sink from explicit S3 credentials.
    ///
    /// `account_id` is the Cloudflare account (the subdomain in
    /// `<account_id>.r2.cloudflarestorage.com`); `bucket` is the tenant's
    /// bucket; `key` is the object key the artifact is written to. The caller
    /// resolves these from the tenant's `TenantOutput` + the named provider's
    /// creds (`.yah/infra/providers/<id>.toml` / keystore).
    pub fn r2(
        account_id: impl Into<String>,
        bucket: impl Into<String>,
        key: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Result<Self, SinkError> {
        let store = R2ObjectStore::new(account_id, bucket, access_key, secret_key)
            .map_err(|e| SinkError::Build(e.to_string()))?;
        Ok(FeedSink::Object {
            store: Arc::new(store),
            key: key.into(),
        })
    }

    /// Write `bytes` to the sink, returning where they landed.
    pub async fn write(&self, bytes: Vec<u8>) -> Result<SinkTarget, SinkError> {
        match self {
            FeedSink::LocalFile(path) => {
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(|source| SinkError::Io {
                            path: path.clone(),
                            source,
                        })?;
                }
                tokio::fs::write(path, &bytes)
                    .await
                    .map_err(|source| SinkError::Io {
                        path: path.clone(),
                        source,
                    })?;
                Ok(SinkTarget::File(path.clone()))
            }
            FeedSink::Object { store, key } => {
                // `ObjectStore` is a synchronous trait whose R2 impl blocks on
                // reqwest internally — keep it off the async runtime worker.
                let store = Arc::clone(store);
                let key_owned = key.clone();
                tokio::task::spawn_blocking(move || store.put(&key_owned, bytes))
                    .await?
                    .map_err(|source| SinkError::ObjectStore {
                        key: key.clone(),
                        source,
                    })?;
                Ok(SinkTarget::Object { key: key.clone() })
            }
        }
    }

    /// A short description of the sink target without performing a write — used
    /// for startup logging of a resolved tenant view.
    pub fn target(&self) -> SinkTarget {
        match self {
            FeedSink::LocalFile(path) => SinkTarget::File(path.clone()),
            FeedSink::Object { key, .. } => SinkTarget::Object { key: key.clone() },
        }
    }
}

impl std::fmt::Debug for FeedSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Arc<dyn ObjectStore>` isn't Debug; describe the target instead.
        f.debug_tuple("FeedSink").field(&self.target()).finish()
    }
}

/// Convenience: a local-file sink rooted at `project_root` + a relative
/// `artifact` path (the historical single-tenant behaviour).
pub fn local_file(project_root: &Path, artifact: &str) -> FeedSink {
    FeedSink::LocalFile(project_root.join(artifact))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use yah_object_store::InMemoryObjectStore;

    #[tokio::test]
    async fn local_file_sink_writes_and_creates_parents() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nested/dir/releases.json");
        let sink = FeedSink::LocalFile(path.clone());

        let target = sink.write(b"{\"hello\":1}".to_vec()).await.unwrap();
        assert_eq!(target, SinkTarget::File(path.clone()));
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"hello\":1}");
    }

    #[tokio::test]
    async fn object_sink_puts_bytes_at_key() {
        let store = Arc::new(InMemoryObjectStore::new());
        let sink = FeedSink::Object {
            store: Arc::clone(&store) as Arc<dyn ObjectStore>,
            key: "data/releases.json".to_string(),
        };

        let target = sink.write(b"payload".to_vec()).await.unwrap();
        assert_eq!(
            target,
            SinkTarget::Object {
                key: "data/releases.json".to_string()
            }
        );
        assert_eq!(
            store.get("data/releases.json").unwrap().as_deref(),
            Some(&b"payload"[..])
        );
    }

    #[tokio::test]
    async fn object_sink_overwrites_on_rerun() {
        let store = Arc::new(InMemoryObjectStore::new());
        let sink = FeedSink::Object {
            store: Arc::clone(&store) as Arc<dyn ObjectStore>,
            key: "k".to_string(),
        };
        sink.write(b"v1".to_vec()).await.unwrap();
        sink.write(b"v2".to_vec()).await.unwrap();
        assert_eq!(store.get("k").unwrap().as_deref(), Some(&b"v2"[..]));
    }

    #[test]
    fn sink_target_display_forms() {
        assert_eq!(
            SinkTarget::File(PathBuf::from("/data/r.json")).to_string(),
            "file:///data/r.json"
        );
        assert_eq!(
            SinkTarget::Object {
                key: "data/r.json".into()
            }
            .to_string(),
            "object://data/r.json"
        );
    }

    #[test]
    fn target_describes_without_writing() {
        let store = Arc::new(InMemoryObjectStore::new());
        let sink = FeedSink::Object {
            store: store as Arc<dyn ObjectStore>,
            key: "data/x.json".into(),
        };
        assert_eq!(
            sink.target(),
            SinkTarget::Object {
                key: "data/x.json".into()
            }
        );
        // Nothing was written.
    }
}
