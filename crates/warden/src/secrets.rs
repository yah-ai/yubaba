//! Secret resolution and injection for warden's containerd-spec assembly.
//!
//! `LocalFileResolver` reads from the per-machine warden secret store at
//! `/var/lib/yah/warden/secrets/`. `SecretRef::Cluster` is reserved for V2
//! (raft-replicated cluster secrets) and returns `SecretError::ClusterNotImplemented`
//! in V1.
//!
//! Call [`resolve_secrets`] with a slice of `SecretMount`s and a resolver to
//! produce a [`ContainerSecrets`] ready for containerd-spec assembly: env vars
//! are injected directly, file mounts are written into tmpfs at the specified
//! path and mode.

use std::path::PathBuf;

use workload_spec::{SecretMount, SecretRef, SecretTarget};
use workload_spec::secrets::{SecretError, SecretResolver};

/// Default per-machine warden secret store root.
pub const SECRET_STORE_ROOT: &str = "/var/lib/yah/warden/secrets";

/// Reads secrets from the per-machine warden secret store at `root/<path>`.
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
                let full = self.root.join(rel);
                std::fs::read(&full).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        SecretError::NotFound { path: full }
                    } else {
                        SecretError::Io { path: full, source: e }
                    }
                })
            }
            SecretRef::Cluster { .. } => Err(SecretError::ClusterNotImplemented),
        }
    }
}

// ── Container spec output ────────────────────────────────────────────────────

/// Resolved secrets ready to inject into a containerd OCI spec.
#[derive(Debug, Default)]
pub struct ContainerSecrets {
    /// Env vars to inject as `(name, value)` pairs. The value is the resolved
    /// secret content decoded as UTF-8 (lossy). Most secret values — tokens,
    /// passwords, PEM keys — are ASCII; prefer `File` for binary secrets.
    pub env_vars: Vec<(String, String)>,

    /// Tmpfs-backed files to mount. Each is written under a tmpfs at
    /// `path` with `mode`; the content is the raw resolved bytes.
    pub file_mounts: Vec<SecretFileMount>,
}

/// A single secret mounted as a file inside the container.
#[derive(Debug)]
pub struct SecretFileMount {
    /// Absolute path inside the container, e.g. `"/run/secrets/tls.crt"`.
    pub path: PathBuf,
    /// Unix permission bits, e.g. `0o400` for read-only by owner.
    pub mode: u32,
    /// Resolved secret bytes to write at `path`.
    pub content: Vec<u8>,
}

/// Resolve all `SecretMount`s in `mounts` using `resolver`, splitting results
/// into env-var injections and file mounts for containerd-spec assembly.
///
/// Returns the first `SecretError` encountered; processing stops at the first
/// failure (warden marks the workload `Failed` and surfaces the error via
/// `warden.workloads_status`).
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
            Self { secrets: std::collections::HashMap::new() }
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
            source: SecretRef::LocalFile { path: "/api-key".into() },
            target: SecretTarget::EnvVar { name: "API_KEY".into() },
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
            source: SecretRef::LocalFile { path: "/db-password".into() },
            target: SecretTarget::File {
                path: "/run/secrets/db".into(),
                mode: 0o600,
            },
        }];

        let resolved = resolve_secrets(&mounts, &resolver).unwrap();

        assert!(resolved.env_vars.is_empty(), "no env vars expected");
        assert_eq!(resolved.file_mounts.len(), 1, "one file mount expected");
        assert_eq!(resolved.file_mounts[0].path, PathBuf::from("/run/secrets/db"));
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
                source: SecretRef::LocalFile { path: "/api-key".into() },
                target: SecretTarget::EnvVar { name: "API_TOKEN".into() },
            },
            SecretMount {
                source: SecretRef::LocalFile { path: "/tls-cert".into() },
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
        assert_eq!(resolved.file_mounts[0].path, PathBuf::from("/run/secrets/tls.crt"));
        assert_eq!(resolved.file_mounts[0].mode, 0o400);
    }

    #[test]
    fn missing_secret_returns_not_found() {
        let resolver = FakeResolver::new().with("/other-key", b"value");
        let mounts = vec![SecretMount {
            source: SecretRef::LocalFile { path: "/missing".into() },
            target: SecretTarget::EnvVar { name: "KEY".into() },
        }];

        let err = resolve_secrets(&mounts, &resolver).unwrap_err();
        assert!(matches!(err, SecretError::NotFound { .. }), "expected NotFound, got {err}");
    }

    #[test]
    fn cluster_secret_returns_not_implemented() {
        let resolver = FakeResolver::new();
        let mounts = vec![SecretMount {
            source: SecretRef::Cluster { name: "cluster-secret".into() },
            target: SecretTarget::EnvVar { name: "CLUSTER_KEY".into() },
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
            .resolve(&SecretRef::LocalFile { path: "db-password".into() })
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
            .resolve(&SecretRef::LocalFile { path: "/api-key".into() })
            .unwrap();
        assert_eq!(result, b"token123");
    }

    #[test]
    fn local_file_resolver_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = LocalFileResolver::new(tmp.path());
        let err = resolver
            .resolve(&SecretRef::LocalFile { path: "nonexistent".into() })
            .unwrap_err();
        assert!(matches!(err, SecretError::NotFound { .. }), "expected NotFound, got {err}");
    }
}
