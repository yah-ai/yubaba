//! Deliver the fleet-shared cert to a passway that systemd supervises (R600-F10).
//!
//! [`crate::acme_issuer`] issues the fleet cert once and `PutSecret`s the sealed
//! pair into raft; [`crate::secret_reload`] hands that pair to a *workload* by
//! re-rendering its [`SecretMount`] and asking kamaji to graceful-upgrade it.
//! That chain terminates at a consumer the live fleet does not have: the two
//! public yah.dev origins are hand-rolled systemd units (`passway-test.service`
//! on us-east-001, `passway.service` on us-south-001) that read
//! `/var/lib/passway/{cert,key}.pem` off disk. `secret_reload` walks the
//! deployed-workload registry, so on those nodes it is a documented no-op and
//! the issued cert reaches nothing.
//!
//! This module is the missing edge, and deliberately nothing more: resolve
//! `tls/<domain>/cert` and `tls/<domain>/key` through the same
//! [`ClusterResolver`] R600-F2 already ships, write them to two configured
//! paths, and run one configured command when — and only when — the bytes
//! changed.
//!
//! ## Why this is not just `secret_reload` with a different target
//!
//! `secret_reload` is keyed on a `WorkloadSpec`: it needs one to find the
//! mounts, to name the consumer for the R706 access check, and to hand kamaji
//! something to upgrade. A systemd door has no spec. Rather than mint a fake
//! one — which would put a synthetic workload in the registry and make
//! `graceful_upgrade_workload` reachable for a process kamaji does not
//! supervise — this takes the consumer identity from config
//! ([`SecretConsumer::workload`]) and leaves the reload to a command the
//! operator writes down.
//!
//! ## Trust boundary, and one honest difference from R600-F6
//!
//! Decryption stays here: the node-local KEK is loaded per pass, never leaves
//! yubaba, and never reaches passway — the R777 invariant that a compromised
//! passway costs one tenant's key, not the fleet's. The R706 access rule is
//! checked before the KEK is touched, because that check lives inside
//! [`ClusterResolver`] and there is no constructor that skips it.
//!
//! The difference worth stating plainly: F6 renders workload secrets into a
//! **tmpfs**, and these paths are ordinary disk. That is not a regression this
//! module introduces — `/var/lib/passway/key.pem` is where the door's private
//! key already lives, and has since R330-F37 — but it does mean the fleet key
//! is at rest on two more disks than the workload path would put it on. Moving
//! the doors to kamaji workloads (R600-F5 as designed) is what retires that;
//! this module is explicitly the interim.
//!
//! ## What triggers a write
//!
//! The same watch `secret_reload` uses ([`YubabaStateMachine::subscribe_secrets`]),
//! with the same [`DEBOUNCE`] — the issuer writes key-first/cert-last, so an
//! un-debounced pass would render a new-key/old-cert pair and hand the door a
//! cert that does not match its key — and the same per-node
//! [`rolling_stagger`], so a fleet-wide rotation does not cycle every origin at
//! once. A pass also runs at startup, so a node that boots after a rotation
//! converges without waiting for the next one.
//!
//! Writes are content-gated: an epoch bump that leaves these two records
//! unchanged (a different secret rotated, or a snapshot replaying identical
//! state) writes nothing and runs no command. Without that gate every unrelated
//! cluster-secret write would bounce the public door.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use workload_spec::secrets::{SecretConsumer, SecretError};
use workload_spec::{SecretMount, SecretRef, SecretTarget};

use crate::acme_issuer::{cert_secret_name, key_secret_name};
use crate::secret_reload::{rolling_stagger, DEBOUNCE};
use crate::secrets::{
    load_cluster_kek, resolve_secrets, ClusterResolver, LocalFileResolver, SECRET_STORE_ROOT,
};
use crate::ServerState;

/// Set to the domain whose fleet cert this node should materialize. Unset
/// disables the whole module — like the issuer, it is opt-in.
pub const DOMAIN_ENV: &str = "YUBABA_CERT_FILES_DOMAIN";
/// Destination for the certificate chain PEM.
pub const CERT_PATH_ENV: &str = "YUBABA_CERT_FILES_CERT_PATH";
/// Destination for the private key PEM.
pub const KEY_PATH_ENV: &str = "YUBABA_CERT_FILES_KEY_PATH";
/// Workload identity this node resolves *as*, checked against the record's
/// R706 access rule. Must appear in the issuer's `YUBABA_ACME_CONSUMERS`.
pub const CONSUMER_ENV: &str = "YUBABA_CERT_FILES_CONSUMER";
/// Command run after the pair changes on disk (e.g. `systemctl restart passway`).
pub const RELOAD_CMD_ENV: &str = "YUBABA_CERT_FILES_RELOAD_CMD";

/// Mode for the certificate chain — world-readable, like every other cert.
const CERT_MODE: u32 = 0o644;
/// Mode for the private key. passway reads it as root.
const KEY_MODE: u32 = 0o600;

/// Where the fleet cert should land on this node, and what to run once it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializeConfig {
    /// Domain whose `tls/<domain>/{cert,key}` records to follow.
    pub domain: String,
    /// Absolute path for the chain PEM.
    pub cert_path: PathBuf,
    /// Absolute path for the key PEM.
    pub key_path: PathBuf,
    /// Consumer identity for the R706 access check.
    pub consumer: String,
    /// Command to run after a change, or `None` to write the files and stop.
    pub reload_command: Option<String>,
}

/// Parse the config from a `key -> value` lookup — a pure function over the
/// environment, so the whole contract is unit-testable without `std::env`.
///
/// `Ok(None)` when [`DOMAIN_ENV`] is unset. Every other field is required when
/// it is set, except the reload command: writing the files and leaving the
/// reload to a human is a coherent (if manual) deployment, whereas a defaulted
/// path would put the fleet's private key somewhere nobody chose.
pub fn parse_config(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<MaterializeConfig>, String> {
    let non_empty = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());

    let Some(domain) = non_empty(DOMAIN_ENV) else {
        return Ok(None);
    };
    let cert_path = non_empty(CERT_PATH_ENV)
        .ok_or_else(|| format!("{CERT_PATH_ENV} is required when {DOMAIN_ENV} is set"))?;
    let key_path = non_empty(KEY_PATH_ENV)
        .ok_or_else(|| format!("{KEY_PATH_ENV} is required when {DOMAIN_ENV} is set"))?;
    // No default. The issuer refuses to store a record without an access rule
    // (R706); resolving one requires claiming an identity, and a defaulted
    // identity would be this module quietly claiming to be whatever the rule
    // happens to allow.
    let consumer = non_empty(CONSUMER_ENV)
        .ok_or_else(|| format!("{CONSUMER_ENV} is required when {DOMAIN_ENV} is set: the workload name the issuer's YUBABA_ACME_CONSUMERS allows (e.g. \"ingress\")"))?;

    if cert_path == key_path {
        return Err(format!(
            "{CERT_PATH_ENV} and {KEY_PATH_ENV} are both {cert_path} — the chain would \
             overwrite the key"
        ));
    }

    Ok(Some(MaterializeConfig {
        domain,
        cert_path: PathBuf::from(cert_path),
        key_path: PathBuf::from(key_path),
        consumer,
        reload_command: non_empty(RELOAD_CMD_ENV),
    }))
}

/// The two mounts this module resolves, in the issuer's own naming.
///
/// Expressed as [`SecretMount`]s rather than two bare secret names so the
/// resolution path is byte-for-byte the one every other consumer takes —
/// including the access check — instead of a second, subtly different one.
pub fn secret_mounts(cfg: &MaterializeConfig) -> Vec<SecretMount> {
    vec![
        SecretMount {
            source: SecretRef::Cluster {
                name: cert_secret_name(&cfg.domain),
            },
            target: SecretTarget::File {
                path: cfg.cert_path.clone(),
                mode: CERT_MODE,
            },
        },
        SecretMount {
            source: SecretRef::Cluster {
                name: key_secret_name(&cfg.domain),
            },
            target: SecretTarget::File {
                path: cfg.key_path.clone(),
                mode: KEY_MODE,
            },
        },
    ]
}

/// Order-independent digest of what a pass resolved, so an epoch bump that does
/// not change *these* records writes nothing. In-process only (compared across
/// bumps within one daemon lifetime), so a non-portable hasher is fine.
fn digest(mounts: &[(PathBuf, Vec<u8>)]) -> u64 {
    let mut pairs: Vec<(&Path, &[u8])> = mounts
        .iter()
        .map(|(p, b)| (p.as_path(), b.as_slice()))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut hasher = DefaultHasher::new();
    for (path, bytes) in pairs {
        path.hash(&mut hasher);
        bytes.hash(&mut hasher);
    }
    hasher.finish()
}

/// Write `bytes` to `path` atomically at `mode`.
///
/// Via a temp file in the same directory plus `rename`, so a reader — passway
/// starting up, or its ACME renewal check — never observes a half-written PEM
/// or a cert whose key has not landed yet. The mode is set on the temp file
/// *before* the rename, so the key is never briefly world-readable at its final
/// path.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", path.display()),
        )
    })?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "cert".to_string()),
        std::process::id()
    ));
    // Best-effort cleanup of a temp file left by a previous crash.
    let _ = std::fs::remove_file(&tmp);
    std::fs::write(&tmp, bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// What one pass did — the return shape exists so the loop can log precisely
/// and tests can assert without reading the filesystem twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassOutcome {
    /// Both records resolved and the bytes match what was last written.
    Unchanged,
    /// Both records resolved, differed, and were written.
    Wrote,
    /// At least one record was absent or unresolvable — nothing was written.
    /// The stored digest is left alone so the retry still sees a change.
    Skipped,
}

/// Resolve the pair and write it if it changed. `last` is the digest of the
/// previous successful pass; the new digest is returned alongside the outcome.
///
/// Writes the **key first, then the chain**, mirroring the issuer's own write
/// order for the same reason `passway::acme::write_cert_atomic` does: if the
/// process dies between the two, a cert newer than its key is the pair that
/// fails closed on the next renewal check, whereas a fresh key under a stale
/// cert would be served.
fn materialize_once(
    sm: &crate::raft::YubabaStateMachine,
    kek_path: &Path,
    cfg: &MaterializeConfig,
    last: Option<u64>,
) -> (PassOutcome, Option<u64>) {
    let kek = match load_cluster_kek(kek_path) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "cert_materialize: cannot load the node KEK; skipping this pass"
            );
            return (PassOutcome::Skipped, last);
        }
    };
    let resolver = ClusterResolver::new(
        sm.clone(),
        kek,
        LocalFileResolver::new(SECRET_STORE_ROOT),
        SecretConsumer::workload(&cfg.consumer),
    );
    let mounts = secret_mounts(cfg);
    let resolved = match resolve_secrets(&mounts, &resolver) {
        Ok(r) => r,
        Err(SecretError::Forbidden { name }) => {
            // Distinct from the transient arm below and worth its own line: this
            // never recovers on its own. The consumer identity does not satisfy
            // the record's access rule, which in practice means CONSUMER_ENV and
            // the issuer's YUBABA_ACME_CONSUMERS disagree.
            tracing::error!(
                secret = %name,
                consumer = %cfg.consumer,
                "cert_materialize: access rule denies this node's consumer identity — the \
                 fleet cert will never reach this door until {CONSUMER_ENV} matches the \
                 issuer's YUBABA_ACME_CONSUMERS"
            );
            return (PassOutcome::Skipped, last);
        }
        Err(e) => {
            // The ordinary case early on: the issuer has not written yet, or
            // only one of the two records has replicated so far.
            tracing::debug!(
                error = %e,
                domain = %cfg.domain,
                "cert_materialize: fleet cert not resolvable yet; will retry on the next bump"
            );
            return (PassOutcome::Skipped, last);
        }
    };

    let pairs: Vec<(PathBuf, Vec<u8>)> = resolved
        .file_mounts
        .iter()
        .map(|fm| (fm.path.clone(), fm.content.clone()))
        .collect();
    let fresh = digest(&pairs);
    if last == Some(fresh) {
        return (PassOutcome::Unchanged, last);
    }

    // Key first, chain last — see the doc comment.
    let mut ordered: Vec<&crate::secrets::SecretFileMount> = resolved.file_mounts.iter().collect();
    ordered.sort_by_key(|fm| if fm.path == cfg.key_path { 0 } else { 1 });
    for fm in ordered {
        if let Err(e) = write_atomic(&fm.path, &fm.content, fm.mode) {
            tracing::error!(
                path = %fm.path.display(),
                error = %e,
                "cert_materialize: failed to write the fleet cert; leaving the digest unchanged \
                 so the next bump retries"
            );
            return (PassOutcome::Skipped, last);
        }
    }
    tracing::info!(
        domain = %cfg.domain,
        cert = %cfg.cert_path.display(),
        key = %cfg.key_path.display(),
        "cert_materialize: fleet cert written"
    );
    (PassOutcome::Wrote, Some(fresh))
}

/// Run the configured reload command, if any. Failure is logged, never fatal:
/// the new pair is already on disk, and a door that did not reload is serving
/// the *old* cert — degraded, not down — which is not worth killing yubaba over.
async fn run_reload(cfg: &MaterializeConfig) {
    let Some(cmd) = &cfg.reload_command else {
        tracing::warn!(
            "cert_materialize: fleet cert changed on disk and no {RELOAD_CMD_ENV} is set — the \
             door keeps serving the previous cert until it is restarted by hand"
        );
        return;
    };
    match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .await
    {
        Ok(status) if status.success() => {
            tracing::info!(command = %cmd, "cert_materialize: reload command succeeded")
        }
        Ok(status) => tracing::error!(
            command = %cmd,
            code = status.code().unwrap_or(-1),
            "cert_materialize: reload command failed — the door is still serving the previous cert"
        ),
        Err(e) => tracing::error!(
            command = %cmd,
            error = %e,
            "cert_materialize: could not run the reload command"
        ),
    }
}

/// Watch cluster secrets and keep this node's cert files in step with the fleet
/// cert. Returns immediately (logging why) when the module is not configured or
/// the node has no raft state — there is nothing to follow in either case.
pub async fn run(state: Arc<ServerState>) {
    let cfg = match parse_config(|k| std::env::var(k).ok()) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return,
        Err(e) => {
            tracing::error!(
                "cert_materialize: config invalid — the fleet cert will NOT be delivered to \
                 this node's door (fix YUBABA_CERT_FILES_*): {e}"
            );
            return;
        }
    };
    let Some(sm) = state.cluster_state.clone() else {
        tracing::warn!(
            "cert_materialize: configured but this node has no cluster state; nothing to follow"
        );
        return;
    };
    let stagger = state.node_id.map(rolling_stagger).unwrap_or_default();

    let mut rx = sm.subscribe_secrets();
    let _ = rx.borrow_and_update();
    tracing::info!(
        domain = %cfg.domain,
        cert = %cfg.cert_path.display(),
        consumer = %cfg.consumer,
        stagger_ms = stagger.as_millis() as u64,
        "cert_materialize: following the fleet cert into this node's door"
    );

    // Converge at startup rather than waiting for the next rotation: a node that
    // reboots after an issuance would otherwise serve a stale cert for up to a
    // full renewal interval.
    let mut last = None;
    let (outcome, digest) = materialize_once(&sm, &state.cluster_kek_path, &cfg, last);
    last = digest;
    if outcome == PassOutcome::Wrote {
        run_reload(&cfg).await;
    }

    loop {
        if rx.changed().await.is_err() {
            // Sender dropped — the daemon is shutting down.
            break;
        }
        let _ = rx.borrow_and_update();
        // Coalesce the issuer's two writes into one consistent pair.
        tokio::time::sleep(DEBOUNCE).await;
        if !stagger.is_zero() {
            tokio::time::sleep(stagger).await;
        }
        let _ = rx.borrow_and_update();

        let (outcome, digest) = materialize_once(&sm, &state.cluster_kek_path, &cfg, last);
        last = digest;
        if outcome == PassOutcome::Wrote {
            run_reload(&cfg).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| {
            pairs
                .iter()
                .find(|(pk, _)| *pk == k)
                .map(|(_, v)| v.to_string())
        }
    }

    fn full() -> Vec<(&'static str, &'static str)> {
        vec![
            (DOMAIN_ENV, "yah.dev"),
            (CERT_PATH_ENV, "/var/lib/passway/cert.pem"),
            (KEY_PATH_ENV, "/var/lib/passway/key.pem"),
            (CONSUMER_ENV, "ingress"),
        ]
    }

    #[test]
    fn unset_domain_disables_the_module() {
        assert_eq!(parse_config(env(&[])).unwrap(), None);
    }

    #[test]
    fn a_blank_domain_is_the_same_as_unset() {
        assert_eq!(parse_config(env(&[(DOMAIN_ENV, "   ")])).unwrap(), None);
    }

    #[test]
    fn paths_and_consumer_are_required_once_the_domain_is_set() {
        for missing in [CERT_PATH_ENV, KEY_PATH_ENV, CONSUMER_ENV] {
            let pairs: Vec<_> = full().into_iter().filter(|(k, _)| *k != missing).collect();
            let err = parse_config(env(&pairs)).unwrap_err();
            assert!(
                err.contains(missing),
                "error should name the missing key {missing}, got: {err}"
            );
        }
    }

    #[test]
    fn the_chain_may_not_overwrite_the_key() {
        let mut pairs = full();
        pairs.retain(|(k, _)| *k != KEY_PATH_ENV);
        pairs.push((KEY_PATH_ENV, "/var/lib/passway/cert.pem"));
        let err = parse_config(env(&pairs)).unwrap_err();
        assert!(err.contains("overwrite the key"), "got: {err}");
    }

    #[test]
    fn the_reload_command_is_optional() {
        let cfg = parse_config(env(&full())).unwrap().unwrap();
        assert_eq!(cfg.reload_command, None);
        assert_eq!(cfg.domain, "yah.dev");
        assert_eq!(cfg.consumer, "ingress");
    }

    #[test]
    fn mounts_name_the_issuers_records_and_keep_the_key_unreadable() {
        let cfg = parse_config(env(&full())).unwrap().unwrap();
        let mounts = secret_mounts(&cfg);
        assert_eq!(mounts.len(), 2);
        assert_eq!(
            mounts[0].source,
            SecretRef::Cluster {
                name: "tls/yah.dev/cert".into()
            }
        );
        assert_eq!(
            mounts[1].source,
            SecretRef::Cluster {
                name: "tls/yah.dev/key".into()
            }
        );
        match &mounts[1].target {
            SecretTarget::File { mode, .. } => assert_eq!(*mode, 0o600, "the key must not be world-readable"),
            other => panic!("expected a File target, got {other:?}"),
        }
        match &mounts[0].target {
            SecretTarget::File { mode, .. } => assert_eq!(*mode, 0o644),
            other => panic!("expected a File target, got {other:?}"),
        }
    }

    #[test]
    fn digest_is_order_independent_but_content_sensitive() {
        let a = vec![
            (PathBuf::from("/c"), b"cert".to_vec()),
            (PathBuf::from("/k"), b"key".to_vec()),
        ];
        let reordered = vec![
            (PathBuf::from("/k"), b"key".to_vec()),
            (PathBuf::from("/c"), b"cert".to_vec()),
        ];
        let rotated = vec![
            (PathBuf::from("/c"), b"cert2".to_vec()),
            (PathBuf::from("/k"), b"key".to_vec()),
        ];
        assert_eq!(digest(&a), digest(&reordered));
        assert_ne!(digest(&a), digest(&rotated));
    }

    #[test]
    fn write_atomic_sets_the_mode_and_replaces_content() {
        let dir = std::env::temp_dir().join(format!("cert-mat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.pem");

        write_atomic(&path, b"first", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key must land at 0600, got {mode:o}");

        write_atomic(&path, b"second", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");

        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "left temp files: {leftovers:?}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
