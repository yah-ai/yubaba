//! A live appliance's lifecycle across a replace and across a yubaba restart
//! (R966).
//!
//! Two halves, both about the R572-F4 single-instance guard in
//! `deploy_workload_spec_as`:
//!
//! - **What the guard remembers survives a restart.** The digest of the spec
//!   a workload was POSTed with (R931-B7) is stamped onto the spec yubaba hands
//!   kamaji as [`REQUEST_DIGEST_STAMP`], and read back at boot by
//!   `rehydrate_appliance_guard`. The archetype needs no stamp: it is the
//!   deployed spec's own [`WorkloadSpec::effective_archetype`]. Before this
//!   the guard's two maps were in-memory only, so a changed-spec deploy 409'd
//!   or silently replaced depending on whether yubaba had happened to restart.
//! - **A replace proves it kept the volumes.** [`Replacement`] is the evidence
//!   a `replace: true` deploy takes around its teardown: the replacement must
//!   mount every named volume the incumbent did, at the same target, and each
//!   volume's host directory must be the same directory (device + inode)
//!   before the teardown, after it, and after the replacement started.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use workload_spec::{VolumeSource, WorkloadSpec};

/// Host directory kamaji binds a [`VolumeSource::Named`] from — the volume
/// root of the containerd backend (`kamaji-containerd-core`) and of kamaji's
/// hydrate. Duplicated rather than imported: yubaba's production build links
/// neither crate. `the_volume_root_is_kamajis` pins it to kamaji-bin's own
/// constant, so a move on that side fails a test here instead of every
/// replace refusing with "cannot be identified".
pub const KAMAJI_VOLUME_ROOT: &str = "/var/lib/yah/kamaji/volumes";

/// Annotation carrying the request digest (`request_spec_digest`) on the spec
/// kamaji supervises, as 16 lowercase hex digits. Written by yubaba at deploy,
/// read by yubaba at boot; never authored by an operator.
pub const REQUEST_DIGEST_STAMP: &str = "yah.deploy.request-digest";

/// Stamp `digest` onto the spec about to be handed to the backend.
pub fn stamp_request_digest(spec: &mut WorkloadSpec, digest: u64) {
    spec.annotations
        .insert(REQUEST_DIGEST_STAMP.to_string(), format!("{digest:016x}"));
}

/// The request digest a deployed spec was stamped with. `None` for a spec no
/// yubaba stamped (deployed before R966) or a malformed stamp — the guard then
/// cannot call a re-POST unchanged, which keeps its 409: the safe answer.
pub fn stamped_request_digest(spec: &WorkloadSpec) -> Option<u64> {
    spec.annotations
        .get(REQUEST_DIGEST_STAMP)
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
}

/// The operator's named volumes on a spec, as `(name, target)` pairs. A
/// yubaba-materialized secret bind is not one (R854), and neither is a bind
/// or tmpfs: only a named volume is per-ident state a replace can lose.
fn named_mounts(spec: &WorkloadSpec) -> Vec<(String, PathBuf)> {
    spec.volumes
        .iter()
        .filter(|v| !v.from_secret_mount)
        .filter_map(|v| match &v.source {
            VolumeSource::Named { name } => Some((name.clone(), v.target.clone())),
            _ => None,
        })
        .collect()
}

/// Device + inode of a volume's host directory: what "the same volume" means
/// across a replace. Writes by either generation leave it alone; deleting and
/// recreating the directory, or mounting a different one, does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct VolumeIdentity {
    pub dev: u64,
    pub ino: u64,
}

/// Read a directory's identity. `Err` names why it could not be read.
pub fn volume_identity(path: &Path) -> Result<VolumeIdentity, String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }
    Ok(VolumeIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

/// A metadata manifest of a quiesced volume: entry count, regular-file bytes,
/// and a SHA-256 over every entry's (relative path, kind, size, mtime) in path
/// order. Metadata only, deliberately — it is taken while the workload is DOWN,
/// so hashing contents would lengthen the outage by the volume's read time.
/// It is the record of exactly what the replacement started on; nothing
/// compares it automatically, because the replacement writes from its first
/// second and a later manifest differing is not evidence of loss.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VolumeManifest {
    pub entries: u64,
    pub bytes: u64,
    pub sha256: String,
}

/// Walk `root` without following symlinks and build its [`VolumeManifest`].
pub fn volume_manifest(root: &Path) -> std::io::Result<VolumeManifest> {
    use std::os::unix::fs::MetadataExt;
    let mut paths = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if std::fs::symlink_metadata(&path)?.is_dir() {
                stack.push(path.clone());
            }
            paths.push(path);
        }
    }
    paths.sort();
    let mut hasher = Sha256::new();
    let (mut entries, mut bytes) = (0u64, 0u64);
    for path in &paths {
        let meta = std::fs::symlink_metadata(path)?;
        let kind = if meta.is_dir() {
            b'd'
        } else if meta.file_type().is_symlink() {
            b'l'
        } else if meta.is_file() {
            bytes += meta.len();
            b'f'
        } else {
            b'o'
        };
        let rel = path.strip_prefix(root).unwrap_or(path);
        hasher.update(rel.as_os_str().as_encoded_bytes());
        hasher.update([0, kind]);
        hasher.update(meta.len().to_le_bytes());
        hasher.update(meta.mtime().to_le_bytes());
        hasher.update(meta.mtime_nsec().to_le_bytes());
        entries += 1;
    }
    let sha256 = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(VolumeManifest {
        entries,
        bytes,
        sha256,
    })
}

/// One named volume's evidence across a replace.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VolumeCheck {
    pub name: String,
    pub path: PathBuf,
    /// Identity before the teardown. Always `Some` once planned:
    /// [`Replacement::plan`] refuses a volume it cannot identify.
    pub identity: VolumeIdentity,
    /// Taken between the teardown and the replacement's start.
    pub quiesced: Option<VolumeManifest>,
    /// Same directory before the teardown, after it, and after the
    /// replacement started. `false` until [`Replacement::verify_started`]
    /// proves it.
    pub preserved: bool,
    pub error: Option<String>,
}

/// The volume evidence a `replace: true` deploy carries through the handler.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Replacement {
    pub volumes: Vec<VolumeCheck>,
    /// Set once the incumbent's teardown succeeded: from then on a failure
    /// leaves nothing running under this ident, and the handler must forget it.
    #[serde(skip)]
    pub torn_down: bool,
}

impl Replacement {
    /// Refuse a replace that cannot keep the incumbent's volumes, before
    /// anything is torn down.
    ///
    /// Two refusals. The replacement does not mount one of the incumbent's
    /// named volumes at the same target — it would start on a different
    /// (likely empty) directory while the data sits unmounted. Or a volume's
    /// host directory under `volume_root` cannot be identified, so nothing
    /// after the teardown could prove it was kept. Either way the caller wants
    /// a deliberate destroy, not a replace.
    pub fn plan(
        incumbent: &WorkloadSpec,
        replacement: &WorkloadSpec,
        volume_root: &Path,
    ) -> Result<Self, String> {
        let wanted = named_mounts(replacement);
        let mut volumes = Vec::new();
        let mut refusals = Vec::new();
        for (name, target) in named_mounts(incumbent) {
            if !wanted.iter().any(|(n, t)| *n == name && *t == target) {
                refusals.push(format!(
                    "the replacement does not mount named volume `{name}` at {} — it would \
                     start without the data the live instance holds",
                    target.display()
                ));
                continue;
            }
            let path = volume_root.join(&name);
            match volume_identity(&path) {
                Ok(identity) => volumes.push(VolumeCheck {
                    name,
                    path,
                    identity,
                    quiesced: None,
                    preserved: false,
                    error: None,
                }),
                Err(e) => refusals.push(format!(
                    "named volume `{name}` cannot be identified on this node ({e}), so a \
                     replace could not prove it kept it"
                )),
            }
        }
        if refusals.is_empty() {
            Ok(Self {
                volumes,
                torn_down: false,
            })
        } else {
            Err(format!(
                "refusing to replace the live appliance — {}. Nothing was torn down. If losing \
                 or moving that data is intended, destroy the workload deliberately and deploy \
                 the new spec.",
                refusals.join("; ")
            ))
        }
    }

    /// Between the teardown and the replacement's start: every volume must
    /// still be the directory it was, and its quiesced manifest is recorded.
    /// `Err` means DO NOT start the replacement — it would run on something
    /// other than the data the incumbent left.
    pub fn verify_quiesced(&mut self) -> Result<(), String> {
        let mut changed = Vec::new();
        for v in &mut self.volumes {
            match volume_identity(&v.path) {
                Ok(now) if now == v.identity => {}
                Ok(now) => changed.push(format!(
                    "`{}` at {} is now dev {} ino {}, was dev {} ino {}",
                    v.name,
                    v.path.display(),
                    now.dev,
                    now.ino,
                    v.identity.dev,
                    v.identity.ino
                )),
                Err(e) => changed.push(format!("`{}` is gone: {e}", v.name)),
            }
            match volume_manifest(&v.path) {
                Ok(m) => v.quiesced = Some(m),
                Err(e) => v.error = Some(format!("quiesced manifest: {e}")),
            }
        }
        if changed.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "volume(s) changed during the teardown — {}. The live instance is DOWN and the \
                 replacement was NOT started; restore the volume before deploying",
                changed.join("; ")
            ))
        }
    }

    /// After the replacement started: each volume is still the same directory.
    pub fn verify_started(&mut self) {
        for v in &mut self.volumes {
            match volume_identity(&v.path) {
                Ok(now) => {
                    v.preserved = now == v.identity;
                    if !v.preserved {
                        v.error = Some(format!(
                            "after the replacement started the directory is dev {} ino {}",
                            now.dev, now.ino
                        ));
                    }
                }
                Err(e) => {
                    v.preserved = false;
                    v.error = Some(format!("after the replacement started: {e}"));
                }
            }
        }
    }

    /// `true` when every volume is proven kept (vacuously, with none).
    pub fn preserved(&self) -> bool {
        self.volumes.iter().all(|v| v.preserved)
    }

    /// The `replaced` object of the deploy response.
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "preserved": self.preserved(),
            "volumes": self.volumes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::VolumeMount;

    fn spec_with(volumes: Vec<VolumeMount>) -> WorkloadSpec {
        let mut spec = WorkloadSpec::for_forge(
            "acct",
            workload_spec::ImageRef {
                registry: "localhost".into(),
                repository: "acct".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            workload_spec::TierTag("infra".into()),
            vec![],
        );
        spec.volumes = volumes;
        spec
    }

    fn named(name: &str, target: &str) -> VolumeMount {
        VolumeMount {
            source: VolumeSource::Named { name: name.into() },
            target: PathBuf::from(target),
            read_only: false,
            from_secret_mount: false,
        }
    }

    #[test]
    fn the_volume_root_is_kamajis() {
        assert_eq!(KAMAJI_VOLUME_ROOT, kamaji_bin::hydrate::VOLUME_ROOT);
    }

    #[test]
    fn the_digest_stamp_round_trips_and_an_unstamped_spec_reads_none() {
        let mut spec = spec_with(vec![]);
        assert_eq!(stamped_request_digest(&spec), None);
        stamp_request_digest(&mut spec, 0x00ab_cdef_0123_4567);
        assert_eq!(
            spec.annotations.get(REQUEST_DIGEST_STAMP).map(String::as_str),
            Some("00abcdef01234567")
        );
        assert_eq!(stamped_request_digest(&spec), Some(0x00ab_cdef_0123_4567));
        spec.annotations
            .insert(REQUEST_DIGEST_STAMP.into(), "not-hex".into());
        assert_eq!(stamped_request_digest(&spec), None);
    }

    #[test]
    fn a_replacement_that_drops_or_moves_a_volume_is_refused_before_teardown() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("data")).unwrap();
        let incumbent = spec_with(vec![named("data", "/data")]);

        let dropped = Replacement::plan(&incumbent, &spec_with(vec![]), root.path()).unwrap_err();
        assert!(dropped.contains("does not mount named volume `data`"), "{dropped}");
        assert!(dropped.contains("Nothing was torn down"), "{dropped}");

        let moved = spec_with(vec![named("data", "/var/data")]);
        assert!(Replacement::plan(&incumbent, &moved, root.path()).is_err());

        let renamed = spec_with(vec![named("data2", "/data")]);
        assert!(Replacement::plan(&incumbent, &renamed, root.path()).is_err());
    }

    #[test]
    fn a_volume_whose_directory_cannot_be_identified_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let spec = spec_with(vec![named("data", "/data")]);
        let err = Replacement::plan(&spec, &spec, root.path()).unwrap_err();
        assert!(err.contains("cannot be identified"), "{err}");
    }

    #[test]
    fn secret_binds_and_added_volumes_do_not_block_a_replace() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("data")).unwrap();
        let secret = VolumeMount {
            source: VolumeSource::Bind {
                host_path: PathBuf::from("/run/yah/secrets/acct/tls.key"),
            },
            target: PathBuf::from("/etc/tls.key"),
            read_only: true,
            from_secret_mount: true,
        };
        let incumbent = spec_with(vec![named("data", "/data"), secret]);
        let replacement = spec_with(vec![named("data", "/data"), named("cache", "/cache")]);
        let plan = Replacement::plan(&incumbent, &replacement, root.path()).unwrap();
        assert_eq!(plan.volumes.len(), 1, "only the incumbent's named volume is checked");
        assert_eq!(plan.volumes[0].name, "data");
    }

    #[test]
    fn writes_keep_the_volume_but_a_recreated_directory_aborts_before_start() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("db.sqlite"), b"rows").unwrap();
        let spec = spec_with(vec![named("data", "/data")]);

        let mut kept = Replacement::plan(&spec, &spec, root.path()).unwrap();
        std::fs::write(data.join("db.sqlite"), b"more rows").unwrap();
        kept.verify_quiesced().expect("writes leave the directory's identity alone");
        let quiesced = kept.volumes[0].quiesced.clone().expect("manifest recorded");
        assert_eq!(quiesced.entries, 1);
        assert_eq!(quiesced.bytes, 9);
        kept.verify_started();
        assert!(kept.preserved());
        assert_eq!(kept.report()["preserved"], serde_json::json!(true));

        let mut wiped = Replacement::plan(&spec, &spec, root.path()).unwrap();
        // Move the old directory aside rather than deleting it, so the
        // recreated one cannot reuse its inode number.
        std::fs::rename(&data, root.path().join("old")).unwrap();
        std::fs::create_dir(&data).unwrap();
        let err = wiped.verify_quiesced().unwrap_err();
        assert!(err.contains("changed during the teardown"), "{err}");
        assert!(err.contains("NOT started"), "{err}");
    }

    #[test]
    fn a_volume_gone_after_start_is_reported_not_preserved() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let spec = spec_with(vec![named("data", "/data")]);
        let mut plan = Replacement::plan(&spec, &spec, root.path()).unwrap();
        plan.verify_quiesced().unwrap();
        std::fs::remove_dir(&data).unwrap();
        plan.verify_started();
        assert!(!plan.preserved());
        assert_eq!(plan.report()["preserved"], serde_json::json!(false));
    }

    #[test]
    fn the_manifest_tracks_layout_and_does_not_follow_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("sub")).unwrap();
        std::fs::write(root.path().join("sub/a"), b"abc").unwrap();
        std::os::unix::fs::symlink("/etc", root.path().join("link")).unwrap();
        let one = volume_manifest(root.path()).unwrap();
        assert_eq!(one.entries, 3, "sub, sub/a, link — not /etc's contents");
        assert_eq!(one.bytes, 3);
        assert_eq!(one, volume_manifest(root.path()).unwrap(), "stable");
        std::fs::write(root.path().join("b"), b"").unwrap();
        assert_ne!(one.sha256, volume_manifest(root.path()).unwrap().sha256);
    }
}
