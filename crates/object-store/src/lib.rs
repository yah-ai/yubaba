//! Object-store trait (put/get/head/delete/list_prefix + conditional `put_if`)
//! shared by scryer's long-tier Parquet shard storage, the cloud reconciler's
//! R2 mirror publish, turso-backup's WAL→R2 sink, and the `yah cloud bucket`
//! CLI + data-tab bucket viewer.
//!
//! Lifted from `scryer::long_tier` in R498-F1. `R2ObjectStore` landed in F2.
//! `put_if` / `etag` (linearizable compare-and-swap on a single object) added
//! for the W243 global tenant→cell pointer — see `.yah/docs/working/
//! W243-multi-cell-tenant-mobility.md`.
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

use sha2::{Digest, Sha256};
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

    /// A conditional write's precondition was not met (S3/R2 `412`). The
    /// compare-and-swap lost the race: the object changed (or appeared, or
    /// vanished) since the comparand was read. Re-read and retry. Only
    /// [`ObjectStore::put_if`] raises this.
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),

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

/// Precondition for a conditional write ([`ObjectStore::put_if`]).
///
/// Maps onto S3/R2 conditional-write headers so a caller can perform a
/// linearizable compare-and-swap on a single object — e.g. the global
/// tenant→cell pointer in W243 — without any external lock or consensus.
#[derive(Debug, Clone)]
pub enum Precondition {
    /// Write only if no object exists at the key yet (create-only).
    /// Wire form: `If-None-Match: *`. Fails with [`Error::PreconditionFailed`]
    /// if any object already exists at the key.
    IfAbsent,

    /// Write only if the current object's ETag equals this value (optimistic
    /// concurrency). Wire form: `If-Match: <etag>`. Fails with
    /// [`Error::PreconditionFailed`] if the stored ETag differs or the key is
    /// absent. The comparand is an ETag returned by a prior [`ObjectStore::put_if`]
    /// or [`ObjectStore::etag`].
    IfMatch(String),
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
    /// Write `data` at `key`. Overwrites any existing object unconditionally.
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

    /// Conditionally write `data` at `key`, returning the resulting ETag.
    ///
    /// An atomic compare-and-swap against `cond`. On a failed precondition the
    /// store is left untouched and [`Error::PreconditionFailed`] is returned —
    /// the caller re-reads ([`etag`](ObjectStore::etag)) and retries. The
    /// returned ETag is the comparand for the next [`Precondition::IfMatch`] in
    /// a CAS chain, so a single writer can advance a pointer without re-reading.
    ///
    /// The default impl returns [`Error::Backend`]: a backend that cannot offer
    /// an atomic conditional write must **not** silently emulate it with
    /// `get`-then-`put` — that would break the linearizability callers depend on
    /// (W243's cross-cell pointer fence). Backends that support it override this.
    fn put_if(&self, _key: &str, _data: Vec<u8>, _cond: Precondition) -> Result<String, Error> {
        Err(Error::Backend(
            "conditional put (put_if) not supported by this backend".into(),
        ))
    }

    /// Current ETag of `key`, or `None` if absent.
    ///
    /// The comparand a caller reads before a [`Precondition::IfMatch`] CAS. The
    /// default impl returns [`Error::Backend`]; backends supporting `put_if`
    /// override it.
    fn etag(&self, _key: &str) -> Result<Option<String>, Error> {
        Err(Error::Backend("etag not supported by this backend".into()))
    }
}

/// ETag for an object's bytes. S3/R2 return the quoted hex MD5 of the body for
/// a single-part PUT; the in-memory double uses a quoted hex SHA-256 instead —
/// the exact digest is opaque to callers, only equality across reads matters.
fn etag_of(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("\"{}\"", hex::encode(h.finalize()))
}

/// In-memory object store for tests and local development.
///
/// Thread-safe; all ops hold a `Mutex` for the minimum duration. `put_if` holds
/// the lock across the read+write so the compare-and-swap is genuinely atomic,
/// matching R2's server-side conditional-write semantics.
pub struct InMemoryObjectStore {
    /// key → (bytes, etag). The etag is recomputed on every write.
    objects: Mutex<HashMap<String, (Vec<u8>, String)>>,
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
        let etag = etag_of(&data);
        self.objects.lock().unwrap().insert(key.to_string(), (data, etag));
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.objects.lock().unwrap().get(key).map(|(d, _)| d.clone()))
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, Error> {
        let g = self.objects.lock().unwrap();
        Ok(g.keys().filter(|k| k.starts_with(prefix)).cloned().collect())
    }

    fn etag(&self, key: &str) -> Result<Option<String>, Error> {
        Ok(self.objects.lock().unwrap().get(key).map(|(_, e)| e.clone()))
    }

    fn put_if(&self, key: &str, data: Vec<u8>, cond: Precondition) -> Result<String, Error> {
        // One lock across check-then-write = atomic CAS.
        let mut g = self.objects.lock().unwrap();
        match (&cond, g.get(key)) {
            (Precondition::IfAbsent, Some(_)) => {
                return Err(Error::PreconditionFailed(format!(
                    "IfAbsent: {key} already exists"
                )));
            }
            (Precondition::IfAbsent, None) => {}
            (Precondition::IfMatch(want), Some((_, have))) if have == want => {}
            (Precondition::IfMatch(want), Some((_, have))) => {
                return Err(Error::PreconditionFailed(format!(
                    "IfMatch {want} != current {have} for {key}"
                )));
            }
            (Precondition::IfMatch(want), None) => {
                return Err(Error::PreconditionFailed(format!(
                    "IfMatch {want}: {key} absent"
                )));
            }
        }
        let etag = etag_of(&data);
        g.insert(key.to_string(), (data, etag.clone()));
        Ok(etag)
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

    #[test]
    fn etag_is_none_when_absent_some_after_write() {
        let s = InMemoryObjectStore::new();
        assert!(s.etag("k").unwrap().is_none());
        s.put("k", b"v".to_vec()).unwrap();
        let e = s.etag("k").unwrap();
        assert!(e.is_some());
        // Same bytes via the plain `put` path produce the same etag.
        assert_eq!(e, Some(etag_of(b"v")));
    }

    #[test]
    fn put_if_absent_creates_then_refuses_overwrite() {
        let s = InMemoryObjectStore::new();
        let e1 = s.put_if("p", b"gen1".to_vec(), Precondition::IfAbsent).unwrap();
        assert_eq!(s.get("p").unwrap().as_deref(), Some(&b"gen1"[..]));
        assert_eq!(s.etag("p").unwrap().as_deref(), Some(e1.as_str()));

        // A second create-only write must lose — object already exists.
        let err = s
            .put_if("p", b"gen2".to_vec(), Precondition::IfAbsent)
            .unwrap_err();
        assert!(matches!(err, Error::PreconditionFailed(_)), "got {err:?}");
        // Untouched.
        assert_eq!(s.get("p").unwrap().as_deref(), Some(&b"gen1"[..]));
    }

    #[test]
    fn put_if_match_drives_a_cas_chain() {
        // Models the W243 global tenant→cell pointer: each generation bump is an
        // IfMatch CAS against the prior etag.
        let s = InMemoryObjectStore::new();
        let e1 = s.put_if("ptr", b"cell=US,gen=1".to_vec(), Precondition::IfAbsent).unwrap();

        let e2 = s
            .put_if("ptr", b"cell=EU,gen=2".to_vec(), Precondition::IfMatch(e1.clone()))
            .unwrap();
        assert_ne!(e1, e2);
        assert_eq!(s.get("ptr").unwrap().as_deref(), Some(&b"cell=EU,gen=2"[..]));

        // A stale comparand (e1) must now bounce.
        let err = s
            .put_if("ptr", b"cell=US,gen=3".to_vec(), Precondition::IfMatch(e1))
            .unwrap_err();
        assert!(matches!(err, Error::PreconditionFailed(_)), "got {err:?}");
        assert_eq!(s.get("ptr").unwrap().as_deref(), Some(&b"cell=EU,gen=2"[..]));

        // The fresh comparand (e2) wins.
        s.put_if("ptr", b"cell=US,gen=3".to_vec(), Precondition::IfMatch(e2)).unwrap();
        assert_eq!(s.get("ptr").unwrap().as_deref(), Some(&b"cell=US,gen=3"[..]));
    }

    #[test]
    fn put_if_match_two_writers_only_one_wins() {
        // The cross-cell fence in miniature: source + target both read the same
        // pointer etag; exactly one IfMatch may succeed.
        let s = InMemoryObjectStore::new();
        let shared = s.put_if("ptr", b"v0".to_vec(), Precondition::IfAbsent).unwrap();

        let a = s.put_if("ptr", b"from-A".to_vec(), Precondition::IfMatch(shared.clone()));
        let b = s.put_if("ptr", b"from-B".to_vec(), Precondition::IfMatch(shared));
        assert!(a.is_ok(), "first writer should win: {a:?}");
        assert!(
            matches!(b, Err(Error::PreconditionFailed(_))),
            "second writer must lose: {b:?}"
        );
        assert_eq!(s.get("ptr").unwrap().as_deref(), Some(&b"from-A"[..]));
    }

    #[test]
    fn put_if_match_absent_key_fails() {
        let s = InMemoryObjectStore::new();
        let err = s
            .put_if("nope", b"x".to_vec(), Precondition::IfMatch("\"whatever\"".into()))
            .unwrap_err();
        assert!(matches!(err, Error::PreconditionFailed(_)), "got {err:?}");
        assert!(!s.contains_key("nope"));
    }

    /// A backend that implements only the required methods inherits the default
    /// `put_if`/`etag` — they must report unsupported rather than silently
    /// emulating a non-atomic CAS. Guards the non-breaking default-impl contract.
    struct MinimalStore;
    impl ObjectStore for MinimalStore {
        fn put(&self, _k: &str, _d: Vec<u8>) -> Result<(), Error> {
            Ok(())
        }
        fn get(&self, _k: &str) -> Result<Option<Vec<u8>>, Error> {
            Ok(None)
        }
        fn delete(&self, _k: &str) -> Result<(), Error> {
            Ok(())
        }
        fn list_prefix(&self, _p: &str) -> Result<Vec<String>, Error> {
            Ok(vec![])
        }
    }

    #[test]
    fn default_conditional_methods_report_unsupported() {
        let s = MinimalStore;
        assert!(matches!(
            s.put_if("k", vec![], Precondition::IfAbsent),
            Err(Error::Backend(_))
        ));
        assert!(matches!(s.etag("k"), Err(Error::Backend(_))));
    }
}
