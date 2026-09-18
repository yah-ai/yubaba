//! The fleet's one cluster-secret store: sealed [`SecretRecord`]s in the fleet
//! object store (R2), read by every node (R911-F1, W294 Decision 8).
//!
//! Before R911 a cluster secret lived in each sovereign group's raft state, and
//! per-domain TLS material lived in the object store behind a raft-first
//! `LayeredSecretStore`. Two stores answering for one name is the shape R911
//! removes: [`FleetSecretStore`] is now the only [`ClusterSecretStore`], so
//! there is no "whichever answered" to reason about.
//!
//! # Key layout
//!
//! | logical name | object key |
//! |---|---|
//! | `tls/<domain>/cert` | `certs/<issuer>/<domain>/cert.sealed` |
//! | `tls/<domain>/key` | `certs/<issuer>/<domain>/key.sealed` |
//! | anything else, e.g. `noisetable/account/session-key` | `secrets/<group>/noisetable/account/session-key.sealed` |
//!
//! The `tls/` half is [`cert_store::object_key`](crate::cert_store::object_key)
//! unchanged, so the per-domain issuer's writes and this store's reads can never
//! disagree about where a cert lives. The whole `tls/` namespace is reserved for
//! it: a `tls/` name that is not a cert or key is refused rather than falling
//! through to the group prefix, so one logical name never has two candidate keys.
//!
//! `<group>` is the node's sovereign group, so separate rafts (dev, prod) stay
//! separate namespaces in one bucket. **There is no default group.** A node that
//! declares none has no fleet secret store ([`MissingRail::NoSovereignGroup`]),
//! and every cluster-secret read there fails closed by name. A fallback name
//! would silently put every undeclared group on one shared prefix — and as of
//! 2026-09-14 every live voter, prod and dev alike, ran without
//! `--sovereign-group` (R911-T6 sets it before the roll).
//!
//! # Names
//!
//! A name may contain `/`, but never an empty, `.` or `..` segment, a leading
//! `/`, a backslash, or a control character. Refused rather than sanitised, so a
//! crafted name cannot address an object outside its group's prefix and a
//! caller never believes it wrote somewhere it did not.
//!
//! # Blocking
//!
//! The object-store trait is synchronous (`reqwest::blocking` under R2), so each
//! verb is an HTTPS round-trip on the calling thread. An async caller must run
//! it through [`off_runtime`], which moves it to tokio's blocking pool (R911-F2).
//! Debug builds enforce that: a verb called on a runtime thread outside
//! [`off_runtime`] panics, naming the fix, so a call site that regresses to
//! blocking a worker fails its first test instead of stalling a node.

use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use yah_object_store::ObjectStore;

use crate::cert_store::{issuer_prefix, object_key, ObjectCertStore, CERT_OBJECT, KEY_OBJECT};
use crate::raft::SecretRecord;
use crate::secrets::{cert_secret_name, key_secret_name, ClusterSecretStore, SecretStoreError};

/// Top-level key prefix for every non-TLS cluster secret.
pub const SECRETS_PREFIX: &str = "secrets";

/// Suffix on every sealed-record object this store addresses.
pub const SEALED_SUFFIX: &str = ".sealed";

/// The logical namespace owned by per-domain TLS material.
const TLS_NAMESPACE: &str = "tls/";

thread_local! {
    /// True on a blocking-pool thread for the duration of an [`off_runtime`]
    /// call, and only then.
    static OFF_RUNTIME: Cell<bool> = const { Cell::new(false) };
}

/// Run blocking fleet-store work on tokio's blocking pool and await it
/// (R911-F2) — the one way an async caller touches [`FleetSecretStore`].
///
/// Same shape as the demux route publisher's `spawn_blocking` sweep, plus the
/// marker [`FleetSecretStore`]'s debug tripwire checks. A panic inside `f` is
/// resumed on the caller, so a failing assertion reads as itself.
pub async fn off_runtime<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let joined = tokio::task::spawn_blocking(move || {
        // Blocking-pool threads are reused: clear the marker even if `f` panics.
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                OFF_RUNTIME.with(|c| c.set(false));
            }
        }
        OFF_RUNTIME.with(|c| c.set(true));
        let _reset = Reset;
        f()
    })
    .await;
    match joined {
        Ok(v) => v,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => panic!("off_runtime: blocking task did not complete: {e}"),
    }
}

/// Debug-build tripwire for a store verb called on a tokio runtime thread
/// without [`off_runtime`].
///
/// `Handle::try_current` alone cannot tell: a `spawn_blocking` thread is inside
/// the runtime's context too. The marker is what says the caller took the
/// blocking pool on purpose. A plain synchronous caller (no runtime at all) is
/// never flagged.
fn assert_off_runtime() {
    #[cfg(debug_assertions)]
    if tokio::runtime::Handle::try_current().is_ok() && !OFF_RUNTIME.with(Cell::get) {
        panic!(
            "FleetSecretStore does blocking object-store I/O and was called on a tokio runtime \
             thread; wrap the caller in fleet_secrets::off_runtime (R911-F2)"
        );
    }
}

/// One row of [`FleetSecretStore::index`]: metadata only, never ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretIndexRow {
    /// Logical secret name, e.g. `tls/yah.dev/cert` or `headscale/noise-private-key`.
    pub name: String,
    /// Writer-stamped unix seconds of the last write.
    pub updated_at: u64,
    /// The record's access rule, as [`SecretAccess::summary`](workload_spec::secrets::SecretAccess::summary).
    pub access: String,
    /// Lowercase hex of the record's keyed plaintext digest, when it carries one.
    pub digest: Option<String>,
}

/// Sealed cluster secrets in the fleet object store — see the module doc.
///
/// Cheap to clone: the backing store is behind an `Arc`.
#[derive(Clone)]
pub struct FleetSecretStore {
    objects: Arc<dyn ObjectStore>,
    issuer: String,
    group: String,
}

impl std::fmt::Debug for FleetSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The object store may hold credentials; only the key segments print.
        f.debug_struct("FleetSecretStore")
            .field("issuer", &self.issuer)
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

impl FleetSecretStore {
    /// Build a store over `objects`. `issuer` is the cert store's issuer
    /// segment ([`ObjectCertStore::issuer`]); `group` is the node's sovereign
    /// group — required, see the module doc.
    ///
    /// Infallible on purpose: a group that cannot be a key segment is reported
    /// as [`SecretStoreError::InvalidGroup`] by the first verb that needs it.
    pub fn new(
        objects: Arc<dyn ObjectStore>,
        issuer: impl Into<String>,
        group: impl Into<String>,
    ) -> Self {
        Self {
            objects,
            issuer: issuer.into(),
            group: group.into(),
        }
    }

    /// The store a node with these rails has: its cert store's bucket
    /// connection, keyed under its sovereign group. Checked in that order, so
    /// a node missing both reports the object store first.
    pub fn for_rails(certs: Option<&ObjectCertStore>, group: Option<&str>) -> NodeSecretStore {
        let certs = certs.ok_or(MissingRail::NoObjectStore)?;
        let group = group.ok_or(MissingRail::NoSovereignGroup)?;
        Ok(Self::new(certs.objects(), certs.issuer(), group))
    }

    /// This node's store. Resolvers are built over the result directly: a
    /// missing rail answers its named [`SecretStoreError`] at resolve time.
    pub fn for_node(state: &crate::ServerState) -> NodeSecretStore {
        Self::for_rails(state.cert_store.as_deref(), state.sovereign_group.as_deref())
    }

    /// The group segment non-TLS names are keyed under.
    pub fn group(&self) -> &str {
        &self.group
    }

    /// The issuer segment `tls/` names are keyed under.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Map a logical name onto its object key — see the module doc's table.
    pub fn object_key(&self, name: &str) -> Result<String, SecretStoreError> {
        if name.starts_with(TLS_NAMESPACE) {
            return object_key(&self.issuer, name).ok_or_else(|| invalid_name(name));
        }
        validate_secret_name(name)?;
        Ok(format!("{}{name}{SEALED_SUFFIX}", self.group_prefix()?))
    }

    /// `secrets/<group>/`, or the group refusal.
    fn group_prefix(&self) -> Result<String, SecretStoreError> {
        if !is_safe_segment(&self.group) {
            return Err(SecretStoreError::InvalidGroup {
                group: self.group.clone(),
            });
        }
        Ok(format!("{SECRETS_PREFIX}/{}/", self.group))
    }

    /// The sealed record at `name`: `Ok(None)` only when the store answered and
    /// holds no object there.
    pub fn read_secret(&self, name: &str) -> Result<Option<SecretRecord>, SecretStoreError> {
        assert_off_runtime();
        let key = self.object_key(name)?;
        let Some(bytes) = self.objects.get(&key)? else {
            return Ok(None);
        };
        parse_record(&key, &bytes).map(Some)
    }

    /// Write the sealed `rec` at `name`. Overwrites.
    pub fn write_secret(&self, name: &str, rec: &SecretRecord) -> Result<(), SecretStoreError> {
        assert_off_runtime();
        let key = self.object_key(name)?;
        let body = serde_json::to_vec(rec)
            .map_err(|source| SecretStoreError::Malformed { key: key.clone(), source })?;
        self.objects.put(&key, body)?;
        Ok(())
    }

    /// Remove the record at `name`. Idempotent.
    pub fn delete_secret(&self, name: &str) -> Result<(), SecretStoreError> {
        assert_off_runtime();
        let key = self.object_key(name)?;
        self.objects.delete(&key)?;
        Ok(())
    }

    /// Every record this store would resolve, sorted by name: the TLS pairs
    /// under this issuer plus every secret under this group.
    ///
    /// Only keys that map back from a valid name are listed — an issuance
    /// claim, another group's objects, or a hand-written key with a traversing
    /// name never appears. A malformed record is an error, not a skipped row.
    pub fn index(&self) -> Result<Vec<SecretIndexRow>, SecretStoreError> {
        assert_off_runtime();
        let mut rows = Vec::new();
        for (key, name) in self.record_keys()? {
            rows.extend(self.row(&key, name)?);
        }
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(rows)
    }

    /// A fingerprint of every record [`index`](Self::index) would list: a hash
    /// over each `(object key, ETag)`, with the record's `updated_at` standing
    /// in where the backend reports no ETag (R911-F2).
    ///
    /// Equal fingerprints mean nothing this node resolves has changed. It is
    /// only comparable within one process (the hasher is not stable across
    /// builds), which is all the secret watch needs. An object that vanishes
    /// between the listing and its HEAD is left out rather than failing the
    /// poll; any backend error fails it.
    pub fn fingerprint(&self) -> Result<u64, SecretStoreError> {
        assert_off_runtime();
        let mut versions: Vec<(String, String)> = Vec::new();
        for (key, _name) in self.record_keys()? {
            let version = match self.objects.etag(&key)? {
                Some(etag) => format!("etag:{etag}"),
                None => match self.objects.get(&key)? {
                    Some(bytes) => format!("updated_at:{}", parse_record(&key, &bytes)?.updated_at),
                    None => continue,
                },
            };
            versions.push((key, version));
        }
        versions.sort();
        let mut hasher = DefaultHasher::new();
        versions.hash(&mut hasher);
        Ok(hasher.finish())
    }

    /// Every `(object key, logical name)` this store would resolve: the TLS
    /// pairs under this issuer plus every valid name under this group.
    fn record_keys(&self) -> Result<Vec<(String, String)>, SecretStoreError> {
        let mut out = Vec::new();

        let certs = issuer_prefix(&self.issuer);
        for key in self.objects.list_prefix(&certs)? {
            let Some((domain, leaf)) = key.strip_prefix(&certs).and_then(|r| r.split_once('/'))
            else {
                continue;
            };
            let name = match leaf {
                CERT_OBJECT => cert_secret_name(domain),
                KEY_OBJECT => key_secret_name(domain),
                _ => continue,
            };
            if object_key(&self.issuer, &name).as_deref() != Some(key.as_str()) {
                continue;
            }
            out.push((key, name));
        }

        let group = self.group_prefix()?;
        for key in self.objects.list_prefix(&group)? {
            let Some(name) = key
                .strip_prefix(&group)
                .and_then(|r| r.strip_suffix(SEALED_SUFFIX))
            else {
                continue;
            };
            if name.starts_with(TLS_NAMESPACE) || validate_secret_name(name).is_err() {
                continue;
            }
            let name = name.to_string();
            out.push((key, name));
        }

        Ok(out)
    }

    /// One index row, or `None` if the object vanished between list and get.
    fn row(&self, key: &str, name: String) -> Result<Option<SecretIndexRow>, SecretStoreError> {
        let Some(bytes) = self.objects.get(key)? else {
            return Ok(None);
        };
        let rec = parse_record(key, &bytes)?;
        Ok(Some(SecretIndexRow {
            name,
            updated_at: rec.updated_at,
            access: rec.access.summary(),
            digest: rec.digest.as_deref().map(to_hex),
        }))
    }
}

impl ClusterSecretStore for FleetSecretStore {
    fn get_secret(&self, name: &str) -> Result<Option<SecretRecord>, SecretStoreError> {
        self.read_secret(name)
    }
}

/// Why a node has no fleet secret store. Each is a named, fail-closed answer at
/// resolve time — never an empty store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MissingRail {
    /// No cert-store config, so no bucket connection.
    #[error("no fleet object store configured (YUBABA_CERT_STORE_*)")]
    NoObjectStore,
    /// No sovereign group, so no key prefix this node's secrets could live under.
    #[error("no sovereign group declared (--sovereign-group)")]
    NoSovereignGroup,
}

/// What a node resolves cluster secrets through: its [`FleetSecretStore`], or
/// the rail it is missing. Every resolver site builds over
/// [`FleetSecretStore::for_node`] unconditionally, so a spec with no cluster
/// mounts never notices a missing rail and one with cluster mounts is refused
/// naming it.
pub type NodeSecretStore = Result<FleetSecretStore, MissingRail>;

impl ClusterSecretStore for NodeSecretStore {
    fn get_secret(&self, name: &str) -> Result<Option<SecretRecord>, SecretStoreError> {
        match self {
            Ok(store) => store.get_secret(name),
            Err(MissingRail::NoObjectStore) => Err(SecretStoreError::Unconfigured),
            Err(MissingRail::NoSovereignGroup) => Err(SecretStoreError::NoSovereignGroup),
        }
    }
}

fn parse_record(key: &str, bytes: &[u8]) -> Result<SecretRecord, SecretStoreError> {
    serde_json::from_slice(bytes).map_err(|source| SecretStoreError::Malformed {
        key: key.to_string(),
        source,
    })
}

fn invalid_name(name: &str) -> SecretStoreError {
    SecretStoreError::InvalidName {
        name: name.to_string(),
    }
}

/// One key segment: non-empty, not `.`/`..`, no `/`, `\` or control character.
fn is_safe_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg != "."
        && seg != ".."
        && !seg.contains(['/', '\\'])
        && !seg.chars().any(char::is_control)
}

/// A `/`-separated logical name whose every segment is [`is_safe_segment`].
/// Rejects a leading `/` (an empty first segment) along the way.
///
/// These are the rules for a non-`tls/` name. Public so the node's write routes
/// (R911-F3) refuse a bad name before they touch a store, with the same
/// verdict the store itself would reach.
pub fn validate_secret_name(name: &str) -> Result<(), SecretStoreError> {
    if name.split('/').all(is_safe_segment) {
        Ok(())
    } else {
        Err(invalid_name(name))
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Object stores that fail every call, for tests that need an outage.
#[cfg(test)]
pub(crate) mod test_support {
    use yah_object_store::{Error, ObjectStore};

    /// Every verb answers a backend error — a bucket that is down.
    pub(crate) struct UnreachableObjectStore;

    impl ObjectStore for UnreachableObjectStore {
        fn put(&self, _key: &str, _data: Vec<u8>) -> Result<(), Error> {
            Err(Error::Backend("bucket unreachable".into()))
        }
        fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, Error> {
            Err(Error::Backend("bucket unreachable".into()))
        }
        fn delete(&self, _key: &str) -> Result<(), Error> {
            Err(Error::Backend("bucket unreachable".into()))
        }
        fn list_prefix(&self, _prefix: &str) -> Result<Vec<String>, Error> {
            Err(Error::Backend("bucket unreachable".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::UnreachableObjectStore;
    use super::*;
    use crate::cert_store::ObjectCertStore;
    use crate::secrets::{seal_cluster_secret, ClusterResolver, LocalFileResolver};
    use workload_spec::secrets::{SecretAccess, SecretConsumer, SecretError, SecretResolver};
    use workload_spec::SecretRef;
    use yah_object_store::InMemoryObjectStore;

    const LE: &str = "https://acme-v02.api.letsencrypt.org/directory";
    const LE_ISSUER: &str = "acme-v02.api.letsencrypt.org";
    const KEK: [u8; 32] = [11u8; 32];

    fn rec(body: &[u8]) -> SecretRecord {
        SecretRecord {
            ciphertext: body.to_vec(),
            nonce: vec![0u8; 12],
            updated_at: 1_700_000_000,
            access: SecretAccess::AllowAny,
            digest: None,
            sans: None,
            ari: None,
        }
    }

    fn fleet(group: &str) -> (Arc<InMemoryObjectStore>, FleetSecretStore) {
        let mem = Arc::new(InMemoryObjectStore::new());
        let store = FleetSecretStore::new(mem.clone(), LE_ISSUER, group);
        (mem, store)
    }

    #[test]
    fn tls_names_keep_the_cert_store_layout() {
        let (_mem, store) = fleet("prod");
        assert_eq!(
            store.object_key("tls/yah.dev/cert").unwrap(),
            format!("certs/{LE_ISSUER}/yah.dev/cert.sealed")
        );
        assert_eq!(
            store.object_key("tls/yah.dev/key").unwrap(),
            format!("certs/{LE_ISSUER}/yah.dev/key.sealed")
        );
    }

    #[test]
    fn a_cert_written_by_the_cert_store_reads_back_through_the_fleet_store() {
        // The issuer writes through ObjectCertStore; nodes read through this
        // store. Same bucket, same key, or the fleet cert never arrives.
        let mem = Arc::new(InMemoryObjectStore::new());
        let certs = ObjectCertStore::new(mem.clone(), LE);
        certs.write_secret("tls/tenant.example.com/cert", &rec(b"chain")).unwrap();
        let store = FleetSecretStore::new(mem, certs.issuer(), "default");
        assert_eq!(
            store.read_secret("tls/tenant.example.com/cert").unwrap(),
            Some(rec(b"chain"))
        );
    }

    #[test]
    fn other_names_map_under_the_group_and_may_contain_slashes() {
        let (_mem, store) = fleet("dev");
        assert_eq!(
            store.object_key("noisetable/account/session-key").unwrap(),
            "secrets/dev/noisetable/account/session-key.sealed"
        );
        assert_eq!(
            store.object_key("headscale/noise-private-key").unwrap(),
            "secrets/dev/headscale/noise-private-key.sealed"
        );
    }

    /// Leader decision 2026-09-14: no sovereign group is no store, never a
    /// shared default prefix.
    #[test]
    fn a_node_needs_both_rails_and_names_the_missing_one() {
        let mem = Arc::new(InMemoryObjectStore::new());
        let certs = ObjectCertStore::new(mem, LE);

        assert_eq!(
            FleetSecretStore::for_rails(None, Some("prod")).unwrap_err(),
            MissingRail::NoObjectStore
        );
        assert_eq!(
            FleetSecretStore::for_rails(Some(&certs), None).unwrap_err(),
            MissingRail::NoSovereignGroup
        );
        assert_eq!(
            FleetSecretStore::for_rails(None, None).unwrap_err(),
            MissingRail::NoObjectStore
        );
        let store = FleetSecretStore::for_rails(Some(&certs), Some("prod")).unwrap();
        assert_eq!((store.issuer(), store.group()), (LE_ISSUER, "prod"));
    }

    #[test]
    fn traversing_and_malformed_names_are_refused_and_touch_nothing() {
        let (mem, store) = fleet("prod");
        for bad in [
            "",
            "/",
            "/etc/passwd",
            "a//b",
            "a/",
            ".",
            "..",
            "a/./b",
            "a/../b",
            "../prod2/x",
            "a\\b",
            "a\nb",
            // The tls/ namespace is reserved for cert material.
            "tls/yah.dev/account",
            "tls/a/b/cert",
            "tls/../cert",
            "tls/./cert",
            "tls//cert",
        ] {
            let err = store.object_key(bad).unwrap_err();
            assert!(
                matches!(err, SecretStoreError::InvalidName { .. }),
                "{bad:?} must be refused, got {err:?}"
            );
            assert!(store.write_secret(bad, &rec(b"x")).is_err(), "{bad:?} written");
            assert!(store.read_secret(bad).is_err(), "{bad:?} read");
            assert!(store.delete_secret(bad).is_err(), "{bad:?} deleted");
        }
        assert!(mem.keys().is_empty(), "nothing may be written under a bad name");
    }

    #[test]
    fn an_unusable_group_is_refused_by_name() {
        for group in ["", "..", "a/b"] {
            let (_mem, store) = fleet(group);
            let err = store.object_key("x").unwrap_err();
            assert!(
                matches!(err, SecretStoreError::InvalidGroup { .. }),
                "group {group:?}: got {err:?}"
            );
        }
    }

    #[test]
    fn write_read_delete_round_trip_and_absence_is_ok_none() {
        let (mem, store) = fleet("prod");
        let name = "noisetable/account/smtp-password";
        assert_eq!(store.read_secret(name).unwrap(), None);

        store.write_secret(name, &rec(b"sealed")).unwrap();
        assert!(mem
            .get("secrets/prod/noisetable/account/smtp-password.sealed")
            .unwrap()
            .is_some());
        assert_eq!(store.read_secret(name).unwrap(), Some(rec(b"sealed")));
        assert_eq!(store.get_secret(name).unwrap(), Some(rec(b"sealed")));

        store.delete_secret(name).unwrap();
        assert_eq!(store.read_secret(name).unwrap(), None);
        store.delete_secret(name).unwrap();
    }

    #[test]
    fn groups_do_not_see_each_other() {
        let mem = Arc::new(InMemoryObjectStore::new());
        let dev = FleetSecretStore::new(mem.clone(), LE_ISSUER, "dev");
        let prod = FleetSecretStore::new(mem, LE_ISSUER, "prod");
        dev.write_secret("cf/dns-token", &rec(b"dev-only")).unwrap();
        assert_eq!(prod.read_secret("cf/dns-token").unwrap(), None);
        assert!(prod.index().unwrap().is_empty());
    }

    #[test]
    fn a_malformed_object_is_an_error_not_a_miss() {
        let (mem, store) = fleet("default");
        mem.put("secrets/default/x.sealed", b"{ not json".to_vec()).unwrap();
        let err = store.read_secret("x").unwrap_err();
        assert!(matches!(err, SecretStoreError::Malformed { .. }), "got {err:?}");
    }

    #[test]
    fn a_backend_outage_is_an_error_not_a_miss() {
        let store = FleetSecretStore::new(Arc::new(UnreachableObjectStore), LE_ISSUER, "default");
        for name in ["headscale/noise-private-key", "tls/yah.dev/cert"] {
            let err = store.read_secret(name).unwrap_err();
            assert!(matches!(err, SecretStoreError::Backend(_)), "got {err:?}");
        }
        assert!(store.index().is_err());
    }

    #[test]
    fn index_lists_both_prefixes_sorted_with_metadata_only() {
        let (mem, store) = fleet("prod");
        let mut session = rec(b"s");
        session.access = SecretAccess::workloads(["noisetable-account"]);
        session.digest = Some(vec![0xde, 0xad, 0x01]);
        session.updated_at = 42;
        store.write_secret("noisetable/account/session-key", &session).unwrap();
        store.write_secret("tls/yah.dev/key", &rec(b"k")).unwrap();
        store.write_secret("tls/yah.dev/cert", &rec(b"c")).unwrap();
        store.write_secret("headscale/noise-private-key", &rec(b"n")).unwrap();

        // Noise the index must not surface: a claim object, another group, a
        // key that no valid name maps to, and a non-sealed object.
        mem.put(&format!("certs/{LE_ISSUER}/yah.dev/issuing"), b"{}".to_vec()).unwrap();
        mem.put("secrets/dev/other.sealed", serde_json::to_vec(&rec(b"o")).unwrap())
            .unwrap();
        mem.put("secrets/prod/a/../b.sealed", serde_json::to_vec(&rec(b"t")).unwrap())
            .unwrap();
        mem.put("secrets/prod/readme.txt", b"hi".to_vec()).unwrap();

        let rows = store.index().unwrap();
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "headscale/noise-private-key",
                "noisetable/account/session-key",
                "tls/yah.dev/cert",
                "tls/yah.dev/key",
            ]
        );
        let row = &rows[1];
        assert_eq!(row.updated_at, 42);
        assert_eq!(row.access, session.access.summary());
        assert_eq!(row.digest.as_deref(), Some("dead01"));
        assert_eq!(rows[0].digest, None);
    }

    fn resolver<S: ClusterSecretStore>(store: S) -> ClusterResolver<S> {
        let root = tempfile::TempDir::new().unwrap();
        ClusterResolver::new(
            store,
            KEK,
            LocalFileResolver::new(root.path()),
            SecretConsumer::workload("headscale"),
        )
    }

    fn cluster(name: &str) -> SecretRef {
        SecretRef::Cluster { name: name.into() }
    }

    #[test]
    fn the_resolver_opens_a_record_from_the_fleet_store() {
        let (_mem, store) = fleet("prod");
        store
            .write_secret(
                "headscale/noise-private-key",
                &seal_cluster_secret(
                    &KEK,
                    "headscale/noise-private-key",
                    b"privkey:abc",
                    1,
                    SecretAccess::AllowAny,
                ),
            )
            .unwrap();
        let bytes = resolver(store).resolve(&cluster("headscale/noise-private-key")).unwrap();
        assert_eq!(bytes, b"privkey:abc");
    }

    #[test]
    fn through_the_resolver_absent_is_not_found_but_an_error_is_unavailable() {
        let (_mem, store) = fleet("default");
        let err = resolver(store).resolve(&cluster("a/b")).unwrap_err();
        assert!(matches!(err, SecretError::ClusterNotFound { .. }), "got {err:?}");

        let down = FleetSecretStore::new(Arc::new(UnreachableObjectStore), LE_ISSUER, "default");
        let err = resolver(down).resolve(&cluster("a/b")).unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterUnavailable { ref name } if name == "a/b"),
            "a store outage must not read as absent, got {err:?}"
        );
        // The message names the secret and nothing from the backend.
        assert!(!err.to_string().contains("bucket unreachable"), "{err}");

        let (mem, store) = fleet("default");
        mem.put("secrets/default/a/b.sealed", b"garbage".to_vec()).unwrap();
        let err = resolver(store).resolve(&cluster("a/b")).unwrap_err();
        assert!(matches!(err, SecretError::ClusterUnavailable { .. }), "got {err:?}");

        let (_mem, store) = fleet("default");
        let err = resolver(store).resolve(&cluster("../escape")).unwrap_err();
        assert!(matches!(err, SecretError::ClusterUnavailable { .. }), "got {err:?}");
    }

    #[test]
    fn the_fingerprint_moves_only_when_a_resolvable_record_does() {
        let (mem, store) = fleet("prod");
        let empty = store.fingerprint().unwrap();
        assert_eq!(store.fingerprint().unwrap(), empty, "an unchanged store is stable");

        store.write_secret("a/b", &rec(b"v1")).unwrap();
        let one = store.fingerprint().unwrap();
        assert_ne!(one, empty);

        store.write_secret("a/b", &rec(b"v2")).unwrap();
        let rotated = store.fingerprint().unwrap();
        assert_ne!(rotated, one, "a rewrite of the same name is a change");

        store.write_secret("tls/yah.dev/cert", &rec(b"c")).unwrap();
        let with_cert = store.fingerprint().unwrap();
        assert_ne!(with_cert, rotated, "the certs/ half is watched too");

        // Objects this store never resolves are not changes.
        mem.put(&format!("certs/{LE_ISSUER}/yah.dev/issuing"), b"{}".to_vec()).unwrap();
        mem.put("secrets/dev/a/b.sealed", serde_json::to_vec(&rec(b"o")).unwrap())
            .unwrap();
        assert_eq!(store.fingerprint().unwrap(), with_cert);

        store.delete_secret("a/b").unwrap();
        assert_ne!(store.fingerprint().unwrap(), with_cert, "a delete is a change");
    }

    #[test]
    fn the_fingerprint_of_an_unreachable_store_is_an_error() {
        let store = FleetSecretStore::new(Arc::new(UnreachableObjectStore), LE_ISSUER, "default");
        assert!(matches!(store.fingerprint(), Err(SecretStoreError::Backend(_))));
    }

    /// R911-F2: the tripwire itself. If this stops panicking, a call site that
    /// regresses to blocking a tokio worker stops failing its tests.
    #[cfg(debug_assertions)]
    #[tokio::test(flavor = "multi_thread")]
    #[should_panic(expected = "off_runtime")]
    async fn a_store_verb_on_a_runtime_thread_trips_the_guard() {
        let (_mem, store) = fleet("default");
        let _ = store.read_secret("x");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn off_runtime_runs_the_store_and_does_not_leak_its_marker() {
        let (_mem, store) = fleet("default");
        let s = store.clone();
        assert_eq!(off_runtime(move || s.read_secret("x").unwrap()).await, None);

        // A bare spawn_blocking afterwards — possibly on the same pool thread —
        // must not inherit the marker.
        let leaked = tokio::task::spawn_blocking(|| OFF_RUNTIME.with(Cell::get))
            .await
            .unwrap();
        assert!(!leaked, "the off-runtime marker leaked onto a reused pool thread");
    }

    #[test]
    fn a_node_missing_a_rail_fails_closed_by_name() {
        let no_bucket: NodeSecretStore = Err(MissingRail::NoObjectStore);
        assert!(matches!(
            no_bucket.get_secret("x").unwrap_err(),
            SecretStoreError::Unconfigured
        ));
        let no_group: NodeSecretStore = Err(MissingRail::NoSovereignGroup);
        assert!(matches!(
            no_group.get_secret("x").unwrap_err(),
            SecretStoreError::NoSovereignGroup
        ));
        for node in [no_bucket, no_group] {
            let err = resolver(node).resolve(&cluster("x")).unwrap_err();
            assert!(matches!(err, SecretError::ClusterUnavailable { .. }), "got {err:?}");
        }
    }
}
