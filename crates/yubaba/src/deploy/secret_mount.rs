//! Deploy-time materialization of File-target secret mounts (R600-F6 / W273).
//!
//! At yubaba admission — after shape validation, before the spec is handed to
//! the container backend — each [`SecretMount`] whose target is
//! [`SecretTarget::File`] is:
//!
//!   1. resolved via F2's resolver (a `SecretRef::Cluster` ciphertext decrypted
//!      with the node-local KEK, or a per-machine `SecretRef::LocalFile`),
//!   2. written to a per-workload RAM-backed tmpfs file under
//!      [`DEFAULT_SECRET_MOUNT_ROOT`] (mode per the mount, typically `0o400`),
//!   3. dropped from `spec.secrets` and re-expressed as a read-only `Bind`
//!      [`VolumeMount`] so kamaji bind-mounts the host file yubaba prepared.
//!
//! Kamaji stays secret-unaware: it renders the injected `Bind` through its
//! existing OCI bind path and never sees plaintext. Decryption stays in yubaba
//! (the KEK never leaves the node); decrypted PEM lives only in the tmpfs file
//! and the container's read-only bind — never in raft, never in a log.
//!
//! Trust boundary: this materialization runs *after*
//! `workload_spec::validate::shape`, so the operator-authored spec is still
//! tier-gated against arbitrary `Bind` mounts. The binds injected here are
//! yubaba-controlled (host paths under a per-workload tmpfs dir it created),
//! and kamaji does not re-gate binds — so no tier widening is required to carry
//! an admission-materialized secret bind.

use std::path::Path;

use workload_spec::secrets::{SecretError, SecretResolver};
use workload_spec::{SecretMount, SecretTarget, VolumeMount, VolumeSource, WorkloadSpec};

use crate::secrets::{resolve_secrets, ContainerSecrets};

/// Default RAM-backed root for materialized secret files. `/run` is a tmpfs on
/// systemd nodes, so decrypted PEM never touches disk. Each workload gets a
/// `<root>/<ident>/` subdir, reaped on workload destroy.
pub const DEFAULT_SECRET_MOUNT_ROOT: &str = "/run/yah/secrets";

/// Materialize every `SecretTarget::File` mount in `spec` into a per-workload
/// tmpfs file and rewrite it as a read-only `Bind` volume. Returns the number
/// of secrets materialized (0 when the spec has no File-target secrets).
///
/// `ident` names the per-workload subdir; `root` is the tmpfs base
/// (production: [`DEFAULT_SECRET_MOUNT_ROOT`]; a tempdir in tests).
///
/// EnvVar-target mounts are left untouched — the shared-cert case (R600 F4/F5)
/// is File-target, and kamaji already ignores unresolved `SecretMount`s.
///
/// Fails closed: on any resolve or IO error the spec is left **unmodified** and
/// the error is returned so admission rejects the deploy. All secrets are
/// resolved before any file is written, so a resolve failure never leaves a
/// half-materialized dir behind.
pub fn materialize_file_secrets(
    spec: &mut WorkloadSpec,
    ident: &str,
    resolver: &dyn SecretResolver,
    root: &Path,
) -> Result<usize, SecretError> {
    // Split File-target mounts (materialized here) from the rest (left as-is).
    let (file_mounts, rest): (Vec<SecretMount>, Vec<SecretMount>) = spec
        .secrets
        .iter()
        .cloned()
        .partition(|m| matches!(m.target, SecretTarget::File { .. }));

    if file_mounts.is_empty() {
        return Ok(0);
    }

    // Resolve everything BEFORE touching the filesystem so a resolve failure
    // (missing / undecryptable cluster secret) leaves no partial dir behind.
    // `resolved.file_mounts` is 1:1 with `file_mounts` (all File targets).
    let resolved = resolve_secrets(&file_mounts, resolver)?;

    let workload_dir = root.join(sanitize_component(ident));
    std::fs::create_dir_all(&workload_dir).map_err(|source| SecretError::Io {
        path: workload_dir.clone(),
        source,
    })?;
    // Owner-only dir (defence in depth on top of tmpfs). Best-effort: a dir
    // that already exists from a redeploy keeps whatever mode it had.
    set_mode(&workload_dir, 0o700);

    let mut binds = Vec::with_capacity(resolved.file_mounts.len());
    for fm in &resolved.file_mounts {
        // Host filename derived from the container target path so sibling
        // secrets (e.g. tls.crt / tls.key) never collide within the dir.
        let host_path = workload_dir.join(host_file_name(&fm.path));
        write_secret_file(&host_path, &fm.content, fm.mode)?;
        binds.push(VolumeMount {
            source: VolumeSource::Bind { host_path },
            target: fm.path.clone(),
            read_only: true,
        });
    }

    // Commit the rewrite only after every write succeeded.
    let n = binds.len();
    spec.secrets = rest;
    spec.volumes.extend(binds);
    Ok(n)
}

/// Re-render already-materialized `File` secrets **in place** (R600-F4 / W273):
/// rewrite each secret's host tmpfs file with freshly-resolved bytes at the same
/// host path [`materialize_file_secrets`] used, *without* touching any spec. The
/// running container's read-only `Bind` still points at these host files, so the
/// new bytes are visible inside the container immediately; a subsequent graceful
/// upgrade makes the workload actually re-read them.
///
/// `secrets` is the freshly-[`resolve_secrets`]-d [`ContainerSecrets`] for the
/// workload's original `File` mounts. Returns the host paths rewritten (1:1 with
/// `secrets.file_mounts`).
///
/// Only call this when the resolved content has actually changed — an unchanged
/// rewrite would momentarily truncate a file the container may be reading. The
/// rotation task ([`crate::secret_reload`]) gates on a content digest before
/// calling in, so the truncate window only opens on a genuine rotation.
pub fn rerender_file_secrets(
    root: &Path,
    ident: &str,
    secrets: &ContainerSecrets,
) -> Result<Vec<std::path::PathBuf>, SecretError> {
    let workload_dir = root.join(sanitize_component(ident));
    // The dir already exists from the initial materialization; recreate it
    // defensively (idempotent) so a manual reap between deploy and rotation
    // can't wedge the reload.
    std::fs::create_dir_all(&workload_dir).map_err(|source| SecretError::Io {
        path: workload_dir.clone(),
        source,
    })?;
    set_mode(&workload_dir, 0o700);

    let mut written = Vec::with_capacity(secrets.file_mounts.len());
    for fm in &secrets.file_mounts {
        let host_path = workload_dir.join(host_file_name(&fm.path));
        write_secret_file(&host_path, &fm.content, fm.mode)?;
        written.push(host_path);
    }
    Ok(written)
}

/// Reap a workload's materialized-secret directory. Idempotent — a missing dir
/// (no File secrets, or already reaped) is a no-op. Called on workload destroy
/// so decrypted PEM does not outlive the container.
pub fn teardown_secret_dir(root: &Path, ident: &str) {
    let dir = root.join(sanitize_component(ident));
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => tracing::debug!(dir = %dir.display(), "reaped materialized secret dir"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            dir = %dir.display(),
            error = %e,
            "failed to reap materialized secret dir; plaintext lingers until reboot (tmpfs)"
        ),
    }
}

/// Write `content` to `path`, truncating any prior file, at `mode` perms.
fn write_secret_file(path: &Path, content: &[u8], mode: u32) -> Result<(), SecretError> {
    use std::io::Write;
    let io_err = |source| SecretError::Io {
        path: path.to_path_buf(),
        source,
    };

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    let mut f = opts.open(path).map_err(io_err)?;
    f.write_all(content).map_err(io_err)?;
    // O_CREAT|O_TRUNC keeps a pre-existing file's old perms; force `mode`.
    set_mode(path, mode);
    Ok(())
}

/// Best-effort chmod. Perms are defence-in-depth (the file already lives in an
/// owner-only dir on tmpfs), so a chmod failure is logged, not fatal.
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
            tracing::warn!(path = %path.display(), error = %e, "could not set secret file mode");
        }
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// Collapse a value into a single safe path component: every char outside
/// `[A-Za-z0-9_-]` becomes `_` (dots included, so `.` / `..` can never
/// traverse). Empty input maps to `_`.
fn sanitize_component(s: &str) -> String {
    let mapped: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if mapped.is_empty() {
        "_".into()
    } else {
        mapped
    }
}

/// Derive a collision-free host filename from a container target path: strip
/// the leading `/`, keep `.` for extensions, and replace path separators (and
/// any other non-`[A-Za-z0-9_.-]` char) with `_`. A target that reduces to
/// nothing or a dots-only name falls back to `secret`. The result is always a
/// single flat filename (no separators), so it cannot traverse out of the
/// per-workload dir.
fn host_file_name(target: &Path) -> String {
    let raw = target.to_string_lossy();
    let trimmed = raw.trim_start_matches('/');
    let mapped: String = trimmed
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if mapped.is_empty() || mapped.chars().all(|c| c == '.') {
        "secret".into()
    } else {
        mapped
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use workload_spec::{SecretRef, TierTag};

    /// In-memory resolver keyed on the `SecretRef` variant's identifier so the
    /// materialization logic is exercised without a live raft node or KEK.
    struct FakeResolver {
        by_local: HashMap<PathBuf, Vec<u8>>,
        by_cluster: HashMap<String, Vec<u8>>,
    }

    impl FakeResolver {
        fn new() -> Self {
            Self {
                by_local: HashMap::new(),
                by_cluster: HashMap::new(),
            }
        }
        fn local(mut self, path: &str, v: &[u8]) -> Self {
            self.by_local.insert(PathBuf::from(path), v.to_vec());
            self
        }
        fn cluster(mut self, name: &str, v: &[u8]) -> Self {
            self.by_cluster.insert(name.to_string(), v.to_vec());
            self
        }
    }

    impl SecretResolver for FakeResolver {
        fn resolve(&self, r: &SecretRef) -> Result<Vec<u8>, SecretError> {
            match r {
                SecretRef::LocalFile { path } => self
                    .by_local
                    .get(path)
                    .cloned()
                    .ok_or_else(|| SecretError::NotFound { path: path.clone() }),
                SecretRef::Cluster { name } => self
                    .by_cluster
                    .get(name)
                    .cloned()
                    .ok_or_else(|| SecretError::ClusterNotFound { name: name.clone() }),
            }
        }
    }

    fn file_mount(source: SecretRef, path: &str, mode: u32) -> SecretMount {
        SecretMount {
            source,
            target: SecretTarget::File {
                path: path.into(),
                mode,
            },
        }
    }

    fn spec_with_secrets(secrets: Vec<SecretMount>) -> WorkloadSpec {
        let mut spec = WorkloadSpec::for_forge(
            "test",
            workload_spec::ImageRef {
                registry: "localhost".into(),
                repository: "img".into(),
                tag: "latest".into(),
                digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
            },
            TierTag("public".into()),
            vec![],
        );
        spec.secrets = secrets;
        spec
    }

    #[test]
    fn cluster_cert_becomes_readonly_bind_and_hits_tmpfs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pem = b"-----BEGIN CERTIFICATE-----\nfleet\n-----END CERTIFICATE-----\n";
        let resolver = FakeResolver::new().cluster("tls/yah.dev", pem);
        let mut spec = spec_with_secrets(vec![file_mount(
            SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            },
            "/run/secrets/tls.crt",
            0o400,
        )]);

        let n = materialize_file_secrets(&mut spec, "ingress", &resolver, tmp.path()).unwrap();
        assert_eq!(n, 1);

        // The File secret is gone from spec.secrets…
        assert!(spec.secrets.is_empty(), "File secret consumed");
        // …and re-expressed as a read-only Bind targeting the same container path.
        assert_eq!(spec.volumes.len(), 1);
        let vol = &spec.volumes[0];
        assert!(vol.read_only, "secret bind must be read-only");
        assert_eq!(vol.target, PathBuf::from("/run/secrets/tls.crt"));
        let host_path = match &vol.source {
            VolumeSource::Bind { host_path } => host_path.clone(),
            other => panic!("expected Bind, got {other:?}"),
        };
        // Host file exists under the per-workload dir and carries the plaintext.
        assert!(host_path.starts_with(tmp.path().join("ingress")));
        assert_eq!(std::fs::read(&host_path).unwrap(), pem);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&host_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o400, "host secret file is owner-read-only");
        }
    }

    #[test]
    fn sibling_secrets_do_not_collide() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = FakeResolver::new()
            .cluster("tls/yah.dev/cert", b"CERT")
            .cluster("tls/yah.dev/key", b"KEY");
        let mut spec = spec_with_secrets(vec![
            file_mount(
                SecretRef::Cluster {
                    name: "tls/yah.dev/cert".into(),
                },
                "/run/secrets/tls.crt",
                0o400,
            ),
            file_mount(
                SecretRef::Cluster {
                    name: "tls/yah.dev/key".into(),
                },
                "/run/secrets/tls.key",
                0o400,
            ),
        ]);

        let n = materialize_file_secrets(&mut spec, "ingress", &resolver, tmp.path()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(spec.volumes.len(), 2);

        let mut contents: Vec<Vec<u8>> = spec
            .volumes
            .iter()
            .map(|v| match &v.source {
                VolumeSource::Bind { host_path } => std::fs::read(host_path).unwrap(),
                _ => panic!("expected Bind"),
            })
            .collect();
        contents.sort();
        assert_eq!(contents, vec![b"CERT".to_vec(), b"KEY".to_vec()]);
    }

    #[test]
    fn envvar_secrets_are_left_in_place() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = FakeResolver::new().local("/api-key", b"token");
        let mut spec = spec_with_secrets(vec![SecretMount {
            source: SecretRef::LocalFile {
                path: "/api-key".into(),
            },
            target: SecretTarget::EnvVar {
                name: "API_KEY".into(),
            },
        }]);

        let n = materialize_file_secrets(&mut spec, "svc", &resolver, tmp.path()).unwrap();
        assert_eq!(n, 0, "no File secrets to materialize");
        assert_eq!(spec.secrets.len(), 1, "EnvVar secret untouched");
        assert!(spec.volumes.is_empty());
        // No dir is created when nothing is materialized.
        assert!(!tmp.path().join("svc").exists());
    }

    #[test]
    fn local_and_env_mix_materializes_only_the_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = FakeResolver::new()
            .local("/api-key", b"token")
            .local("/tls", b"PEMBYTES");
        let mut spec = spec_with_secrets(vec![
            SecretMount {
                source: SecretRef::LocalFile {
                    path: "/api-key".into(),
                },
                target: SecretTarget::EnvVar {
                    name: "API_KEY".into(),
                },
            },
            file_mount(
                SecretRef::LocalFile {
                    path: "/tls".into(),
                },
                "/run/secrets/tls.pem",
                0o440,
            ),
        ]);

        let n = materialize_file_secrets(&mut spec, "svc", &resolver, tmp.path()).unwrap();
        assert_eq!(n, 1);
        // EnvVar mount survives; File mount became a bind.
        assert_eq!(spec.secrets.len(), 1);
        assert!(matches!(
            spec.secrets[0].target,
            SecretTarget::EnvVar { .. }
        ));
        assert_eq!(spec.volumes.len(), 1);
    }

    #[test]
    fn missing_cluster_secret_fails_closed_and_leaves_spec_untouched() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = FakeResolver::new(); // empty — the secret isn't replicated yet
        let original = vec![file_mount(
            SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            },
            "/run/secrets/tls.crt",
            0o400,
        )];
        let mut spec = spec_with_secrets(original.clone());

        let err =
            materialize_file_secrets(&mut spec, "ingress", &resolver, tmp.path()).unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterNotFound { .. }),
            "unresolved cluster secret must fail closed, got {err}"
        );
        // Spec is untouched (no partial rewrite) and no dir was left behind.
        assert_eq!(spec.secrets, original, "spec unchanged on failure");
        assert!(spec.volumes.is_empty());
        assert!(!tmp.path().join("ingress").exists());
    }

    #[test]
    fn teardown_is_idempotent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = FakeResolver::new().cluster("tls/yah.dev", b"PEM");
        let mut spec = spec_with_secrets(vec![file_mount(
            SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            },
            "/run/secrets/tls.crt",
            0o400,
        )]);
        materialize_file_secrets(&mut spec, "ingress", &resolver, tmp.path()).unwrap();
        assert!(tmp.path().join("ingress").exists());

        teardown_secret_dir(tmp.path(), "ingress");
        assert!(!tmp.path().join("ingress").exists(), "dir reaped");
        // Second call on an absent dir is a no-op (no panic).
        teardown_secret_dir(tmp.path(), "ingress");
    }

    #[test]
    fn ident_and_target_are_sanitized_against_traversal() {
        // A hostile ident / target must not escape `root`.
        assert_eq!(sanitize_component("../../etc"), "______etc");
        // "forge.abc/../x": the `.` plus the four chars of `/../` each map to
        // `_` → one underscore then four (never a real `.`/`..` traversal).
        assert_eq!(sanitize_component("forge.abc/../x"), "forge_abc____x");
        assert_eq!(sanitize_component(""), "_");
        // host_file_name flattens separators and never yields `.`/`..`.
        assert_eq!(
            host_file_name(Path::new("/run/secrets/tls.crt")),
            "run_secrets_tls.crt"
        );
        assert_eq!(host_file_name(Path::new("/..")), "secret");
        assert!(!host_file_name(Path::new("/a/../b")).contains('/'));
    }
}
