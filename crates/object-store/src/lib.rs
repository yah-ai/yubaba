//! Object-store trait (put/get/head/delete/list_prefix) shared by scryer's
//! long-tier Parquet shard storage, the cloud reconciler's R2 mirror publish,
//! and the upcoming `yah cloud bucket` CLI + data-tab bucket viewer.
//!
//! Lifted from `scryer::long_tier` in R498-F1. `R2ObjectStore` lands in F2.
//!
//! @yah:ticket(R498-F1, "lift ObjectStore trait + InMemoryObjectStore into crates/yah/object-store/")
//! @yah:at(2026-06-09T03:37:49Z)
//! @yah:status(review)
//! @yah:parent(R498)
//! @yah:handoff("Lifted ObjectStore trait + InMemoryObjectStore from scryer::long_tier into new crates/yah/object-store/ crate (yah-object-store package, yah_object_store lib). Trait gained head() with default impl over get(), and delete() (idempotent). Generic Error enum (NotFound/Io/Auth/Backend) replaces the old LongTierError::ObjectStore(String) error path. scryer/long_tier.rs now does pub use yah_object_store::{Error as ObjectStoreError, InMemoryObjectStore, ObjectStore} — every existing call site keeps working unchanged. LongTierError gained #[from] ObjectStoreError variant. cargo check --workspace exit 0; 5/5 object-store unit tests pass. NOTE: scryer's full lib test target was already broken on main (pre-existing missing-.await calls in adapters/journald.rs, adapters/containerd_logs.rs, service.rs — touching 20+ sites) — those are NOT introduced by F1; isolated long_tier tests cannot be run until that gets cleaned up separately.")

pub mod r2;

pub use r2::{ObjectMeta, R2ObjectStore};

use std::collections::HashMap;
use std::sync::Mutex;

use thiserror::Error;

/// Errors a backend may raise.
///
/// Variants are deliberately coarse — a backend reports the failure mode
/// it can plausibly recover or message about, not every wire-level detail.
#[derive(Debug, Error)]
pub enum Error {
    /// The key does not exist (read-side miss). `put` never raises this.
    #[error("not found: {0}")]
    NotFound(String),

    /// Network / IO / protocol error from a remote backend.
    #[error("io: {0}")]
    Io(String),

    /// Authentication / authorization failure (e.g. SigV4 rejected).
    #[error("auth: {0}")]
    Auth(String),

    /// Backend-specific error the caller doesn't need to discriminate.
    #[error("backend: {0}")]
    Backend(String),
}

/// Minimal synchronous object-store surface.
///
/// Production impls connect to R2 / MinIO via AWS Sig V4. Tests inject
/// [`InMemoryObjectStore`] so no network is required.
///
/// All methods are synchronous; async backends should block_on internally or
/// expose a separate async trait alongside this one if the consumer is in
/// a tokio context. (Scryer's long-tier rollover runs on a blocking thread.)
pub trait ObjectStore: Send + Sync {
    /// Write `data` at `key`. Overwrites any existing object.
    fn put(&self, key: &str, data: Vec<u8>) -> Result<(), Error>;

    /// Read bytes at `key`. Returns `None` when the key does not exist —
    /// `NotFound` is reserved for ambiguous cases (HEAD-then-GET race etc.).
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error>;

    /// Returns true when `key` exists. Cheaper than `get` for backends that
    /// support HEAD; the default impl falls back to `get(...).is_some()`.
    fn head(&self, key: &str) -> Result<bool, Error> {
        Ok(self.get(key)?.is_some())
    }

    /// Remove `key`. Idempotent — succeeds whether or not the key existed.
    fn delete(&self, key: &str) -> Result<(), Error>;

    /// List all keys with the given prefix (prefix-match, not glob).
    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, Error>;
}

/// In-memory object store for tests and local development.
///
/// Thread-safe; all ops hold a `Mutex` for the minimum duration.
pub struct InMemoryObjectStore {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl Default for InMemoryObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryObjectStore {
    pub fn new() -> Self {
        Self { objects: Mutex::new(HashMap::new()) }
    }

    /// Returns true when `key` exists (test helper — synchronous, no Result).
    pub fn contains_key(&self, key: &str) -> bool {
        self.objects.lock().unwrap().contains_key(key)
    }

    /// Keys currently stored (test helper).
    pub fn keys(&self) -> Vec<String> {
        self.objects.lock().unwrap().keys().cloned().collect()
    }
}

impl ObjectStore for InMemoryObjectStore {
    fn put(&self, key: &str, data: Vec<u8>) -> Result<(), Error> {
        self.objects.lock().unwrap().insert(key.to_string(), data);
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.objects.lock().unwrap().get(key).cloned())
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, Error> {
        let g = self.objects.lock().unwrap();
        Ok(g.keys().filter(|k| k.starts_with(prefix)).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_round_trip() {
        let s = InMemoryObjectStore::new();
        s.put("k", b"v".to_vec()).unwrap();
        assert_eq!(s.get("k").unwrap().as_deref(), Some(&b"v"[..]));
    }

    #[test]
    fn get_missing_returns_none() {
        let s = InMemoryObjectStore::new();
        assert!(s.get("absent").unwrap().is_none());
    }

    #[test]
    fn head_reflects_presence() {
        let s = InMemoryObjectStore::new();
        assert!(!s.head("k").unwrap());
        s.put("k", b"v".to_vec()).unwrap();
        assert!(s.head("k").unwrap());
    }

    #[test]
    fn delete_is_idempotent() {
        let s = InMemoryObjectStore::new();
        s.delete("absent").unwrap();
        s.put("k", b"v".to_vec()).unwrap();
        s.delete("k").unwrap();
        assert!(!s.head("k").unwrap());
        s.delete("k").unwrap();
    }

    #[test]
    fn list_prefix_filters() {
        let s = InMemoryObjectStore::new();
        s.put("a/1", vec![]).unwrap();
        s.put("a/2", vec![]).unwrap();
        s.put("b/1", vec![]).unwrap();
        let mut got = s.list_prefix("a/").unwrap();
        got.sort();
        assert_eq!(got, vec!["a/1".to_string(), "a/2".to_string()]);
    }
}
