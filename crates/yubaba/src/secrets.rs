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

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use workload_spec::secrets::{SecretError, SecretResolver};
use workload_spec::{SecretMount, SecretRef, SecretTarget};
use zeroize::{Zeroize, Zeroizing};

use crate::raft::{SecretRecord, YubabaStateMachine};

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

/// Read-only view over the local raft replica's cluster-secret map (R600-F1).
///
/// Abstracted as a trait so [`ClusterResolver`] is unit-testable without a live
/// raft node. The production impl is on [`YubabaStateMachine`].
pub trait ClusterSecretStore {
    /// The ciphertext record stored under `name`, or `None` if absent from the
    /// local replica.
    fn get_secret(&self, name: &str) -> Option<SecretRecord>;
}

impl ClusterSecretStore for YubabaStateMachine {
    fn get_secret(&self, name: &str) -> Option<SecretRecord> {
        self.cluster_secret(name)
    }
}

/// Resolves both secret arms on a fleet node:
///
/// - `SecretRef::LocalFile` → delegated to an inner [`LocalFileResolver`].
/// - `SecretRef::Cluster` → read the AES-256-GCM ciphertext from the local raft
///   replica ([`ClusterSecretStore`]) and decrypt it with the node-local KEK.
///
/// The KEK is held for the resolver's lifetime as [`Zeroizing`] key material
/// (scrubbed on drop), is never logged, and never leaves the node. Every
/// failure mode — missing secret, wrong KEK, tampered ciphertext, malformed
/// nonce — fails closed with an error that carries only the logical secret
/// name.
pub struct ClusterResolver<S: ClusterSecretStore> {
    store: S,
    kek: Zeroizing<[u8; 32]>,
    local: LocalFileResolver,
}

impl<S: ClusterSecretStore> ClusterResolver<S> {
    /// Build a resolver from an already-loaded 32-byte KEK. Prefer
    /// [`ClusterResolver::from_kek_file`] in production; this constructor exists
    /// for tests and callers that hold the key by other means.
    ///
    /// Accepts anything convertible into `Zeroizing<[u8; 32]>` so a caller
    /// holding the key in a `Zeroizing` wrapper (e.g. from [`load_cluster_kek`])
    /// can move it in without materialising an unprotected plain-array copy on
    /// the stack.
    pub fn new(store: S, kek: impl Into<Zeroizing<[u8; 32]>>, local: LocalFileResolver) -> Self {
        Self {
            store,
            kek: kek.into(),
            local,
        }
    }

    /// Load the node-local KEK from `kek_path` and build a resolver whose
    /// `LocalFile` arm is rooted at `local_store_root` (production default:
    /// [`SECRET_STORE_ROOT`]). Fails closed if the KEK is missing or malformed.
    pub fn from_kek_file(
        store: S,
        kek_path: impl AsRef<Path>,
        local_store_root: impl Into<PathBuf>,
    ) -> Result<Self, SecretError> {
        // Move the `Zeroizing`-wrapped key straight in — no plain-array copy.
        let kek = load_cluster_kek(kek_path.as_ref())?;
        Ok(Self::new(
            store,
            kek,
            LocalFileResolver::new(local_store_root),
        ))
    }

    /// Read + decrypt the cluster secret named `name`. Returns plaintext bytes
    /// on success; every failure is a fail-closed `SecretError` naming only the
    /// logical secret.
    fn resolve_cluster(&self, name: &str) -> Result<Vec<u8>, SecretError> {
        let rec = self
            .store
            .get_secret(name)
            .ok_or_else(|| SecretError::ClusterNotFound {
                name: name.to_string(),
            })?;

        // GCM nonces are 12 bytes. A record with any other nonce length is
        // treated as a decrypt failure rather than panicking in `from_slice`.
        if rec.nonce.len() != 12 {
            return Err(SecretError::ClusterDecrypt {
                name: name.to_string(),
            });
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.kek.as_ref()));
        let nonce = Nonce::from_slice(&rec.nonce);
        // A wrong KEK or tampered ciphertext fails the GCM tag check here; the
        // error is opaque on purpose — no key, nonce, or ciphertext is logged.
        cipher
            .decrypt(nonce, rec.ciphertext.as_ref())
            .map_err(|_| SecretError::ClusterDecrypt {
                name: name.to_string(),
            })
    }
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
pub fn seal_cluster_secret(kek: &[u8; 32], plaintext: &[u8], updated_at: u64) -> SecretRecord {
    use aes_gcm::aead::{AeadCore, OsRng};

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM seal of a KB-scale secret cannot fail on length");
    SecretRecord {
        ciphertext,
        nonce: nonce.to_vec(),
        updated_at,
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
    // `Aes256Gcm`, `Key`, `KeyInit`, `Nonce`, and the `Aead` trait are already
    // in scope via `use super::*`; only `HashMap` is new here.

    use std::collections::HashMap;

    const TEST_KEK: [u8; 32] = [7u8; 32];
    const TEST_NONCE: [u8; 12] = [3u8; 12];
    // A realistic worked example: PEM cert material, the payload W273 targets.
    const TLS_PEM: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nMIIB...fleet-shared\n-----END CERTIFICATE-----\n";

    /// AES-256-GCM-seal `plaintext` under `kek`/`nonce` into a `SecretRecord`,
    /// mirroring what the F3 issuer writes into raft.
    fn seal(kek: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> SecretRecord {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(nonce), plaintext)
            .expect("seal");
        SecretRecord {
            ciphertext,
            nonce: nonce.to_vec(),
            updated_at: 0,
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
        fn get_secret(&self, name: &str) -> Option<SecretRecord> {
            self.secrets.get(name).cloned()
        }
    }

    fn cluster_resolver(
        store: FakeClusterStore,
        kek: [u8; 32],
    ) -> ClusterResolver<FakeClusterStore> {
        // An empty local root — these tests only exercise the Cluster arm unless
        // they populate the store dir explicitly.
        let root = tempfile::TempDir::new().unwrap();
        ClusterResolver::new(store, kek, LocalFileResolver::new(root.path()))
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
        let rec = seal_cluster_secret(&TEST_KEK, TLS_PEM, 1234);
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
        let a = seal_cluster_secret(&TEST_KEK, TLS_PEM, 0);
        let b = seal_cluster_secret(&TEST_KEK, TLS_PEM, 0);
        assert_ne!(a.nonce, b.nonce, "nonce must be random per seal");
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "distinct nonce → distinct ciphertext"
        );
    }

    #[test]
    fn seal_under_one_kek_does_not_open_under_another() {
        // A record sealed with KEK-A must fail closed against KEK-B.
        let rec = seal_cluster_secret(&TEST_KEK, TLS_PEM, 0);
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
}
