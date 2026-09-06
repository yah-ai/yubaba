//! Headscale's on-disk state directory — the one writer, and the pre-start
//! materialization of the coordinator's noise identity (R858-T2).
//!
//! Two things live here:
//!
//! 1. [`write_state_file`] — the **only** place that writes a file into
//!    `headscale_dir`. Both the `POST /headscale/deploy` transplant
//!    (`crate::headscale_deploy`) and [`materialize_noise_key`] go through it,
//!    so the permission bits on the coordinator's key material cannot drift
//!    between the two paths.
//! 2. [`materialize_noise_key`] — places `noise_private.key` on disk from the
//!    raft-replicated cluster secret store *before* headscale is started.
//!
//! # Why the ordering in (2) is the entire ticket
//!
//! `noise_private.key` is the coordinator's **identity**, not its data.
//! headscale mints a fresh one at startup when the file is absent, and from
//! that moment the file exists and looks right. Every node already registered
//! against the old identity then rejects the new server — silently, fleet-wide,
//! on a coordinator whose `GET /health` returns `200 {"status":"pass"}`. So the
//! key must be on disk *before* `headscale serve` runs, and placing it
//! afterwards is indistinguishable from never placing it at all.
//!
//! # Why this is not a `SecretMount` on the appliance spec
//!
//! The obvious shape — `SecretRef::Cluster` + a `SecretTarget::File` mount on
//! [`crate::headscale_appliance::appliance_spec`] — would ship a silent no-op,
//! for two independent reasons:
//!
//! - `deploy::secret_mount::materialize_file_secrets` has exactly one
//!   production caller, the `POST /workloads/deploy` handler. `leader.rs`
//!   deploys the appliance **straight through the backend**, deliberately (see
//!   `crate::leader::start_headscale`), so a `secrets: vec![...]` on the spec
//!   would look correct in review and never execute.
//! - File-target mounts materialize under `/run/yah/secrets`, which is
//!   **tmpfs** (`RuntimeDirectory=yubaba yah/secrets` in `yubaba.service`). It
//!   is wiped on reboot, so a headscale that came up before yubaba
//!   re-materialized would find no key and mint a fresh identity — the exact
//!   failure this module exists to prevent.
//!
//! Writing into the persistent `headscale_dir` instead is also why none of the
//! three config generators need to change: they all already build the path as
//! `headscale_dir.join("noise_private.key")`.
//!
//! # Why only the noise key — `private.key` is NOT identity, and this is settled
//!
//! `private.key` sits beside the noise key in `headscale_dir` and all three
//! generators emit a top-level `private_key_path` for it, so it looks like a
//! second identity that needs the same carriage. It is not, and R858-T2
//! measured this rather than inferring it:
//!
//! - headscale **v0.23.0 has no top-level `private_key_path` config key.** The
//!   pinned binary's config-key table carries `noise.private_key_path` and
//!   `derp.server.private_key_path`; the bare key the generators emit is a
//!   v0.22-era leftover that 0.23 ignores.
//! - Measured on this camp's own mesh dir: headscale v0.23.0 ran a full clean
//!   serve→shutdown against a `config.yaml` that *does* set the top-level
//!   `private_key_path`, minted `noise_private.key` (72 bytes, `0600`), and
//!   **never created `private.key`**. Both keys are minted at startup, not at
//!   first registration — the dir had zero registered nodes and got the noise
//!   key anyway — so the asymmetry is about the config key, not about traffic.
//! - The only thing that key would ever be is the embedded DERP server's, and
//!   all three generators set `derp.server.enabled: false` and never set
//!   `derp.server.private_key_path`. It is never minted and never read.
//!
//! So there is nothing to carry: a coordinator that comes up without
//! `private.key` on 0.23 behaves identically to one that has it. Do not add a
//! second declaration for it.
//!
//! **Latent bug this uncovered, filed nowhere yet (out of R858-T2's scope):**
//! `yah mesh promote` treats `private.key` as a REQUIRED transplant input —
//! `app/yah/cli/src/mesh.rs` bails if the file is absent, and
//! `build_deploy_request` hard-errors on `read_b64("private.key")`. Since 0.23
//! never creates it, promote fails its preflight on a file that will never
//! exist for any coordinator that has only ever run 0.23. The live us-west-001
//! copy exists only because an older headscale made it.

use std::path::{Path, PathBuf};

use tracing::{error, info};
use workload_spec::secrets::{SecretError, SecretResolver};
use workload_spec::SecretRef;

/// Logical cluster-secret name carrying the coordinator's noise identity.
///
/// Declared at `.yah/infra/secrets/headscale-noise-private-key.toml`; seeded by
/// an operator with [`SEED_COMMAND`]. Deliberately **not** auto-seeded from
/// local disk — during a split brain the losing node would publish its own
/// identity over the real one.
pub const NOISE_KEY_SECRET: &str = "headscale/noise-private-key";

/// Filename headscale reads its noise identity from, inside `headscale_dir`.
///
/// Matches what `generate_remote_headscale_config`,
/// `generate_bootstrap_headscale_config` and `cloud::mesh` all emit.
pub const NOISE_KEY_FILE: &str = "noise_private.key";

/// The exact operator sequence that seeds [`NOISE_KEY_SECRET`], quoted verbatim
/// into every error path so the log line is actionable rather than alarming.
pub const SEED_COMMAND: &str = "yah keys set headscale-noise-private-key \
     < /var/lib/yah-cloud/headscale/noise_private.key && \
     yah cloud secret put headscale/noise-private-key";

/// Owner-only. Everything this module writes is coordinator key material — the
/// noise key, the legacy DERP `private.key`, and `headscale.db` (which holds
/// every node's registration). The live key on us-west-001 is already `0600`;
/// this keeps a transplanted or materialized one from landing looser.
const STATE_FILE_MODE: u32 = 0o600;

/// What happened to the noise identity before headscale was started.
///
/// Returned rather than only logged so the behaviour is assertable without a
/// tracing subscriber; the doc on each variant records the level it logs at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseIdentity {
    /// The cluster store held the key and it is now on disk. Logs at `info`.
    /// This is the portable state: the appliance can move.
    Carried,

    /// The store does not hold the key, but one already exists on disk. The
    /// coordinator keeps working and is **not portable** — a failover to
    /// another node would mint a fresh identity there. Logs at `error`.
    ///
    /// This is the live state of the fleet as of 2026-09-04, which is why the
    /// message names [`SEED_COMMAND`] instead of merely complaining.
    LocalOnly,

    /// Neither the store nor the disk has it: headscale is about to mint a
    /// fresh identity. Logs at `error`.
    Fresh,
}

/// Why the noise identity could not be placed, and therefore why headscale must
/// not be started.
#[derive(Debug, thiserror::Error)]
pub enum NoiseKeyError {
    /// The store almost certainly holds the identity but this node cannot use
    /// it — a denied access rule, a wrong KEK, a tampered record.
    ///
    /// Fatal on purpose. Starting anyway would either mint a fresh identity (no
    /// key on disk) or run on one nobody can verify against the cluster's copy,
    /// and a coordinator that refuses to start is recoverable in a way a
    /// coordinator that rejects the whole fleet is not.
    #[error(
        "cluster secret `{name}` is present but unusable ({source}); refusing to start headscale \
         — starting it would run a DIFFERENT server identity and every already-registered node \
         would reject this coordinator"
    )]
    Unusable { name: String, source: SecretError },

    /// The store held the identity and it could not be written to disk.
    #[error(
        "writing {path}: {source}; refusing to start headscale — the cluster holds this \
         coordinator's identity and starting without it would mint a new one"
    )]
    Write { path: PathBuf, source: std::io::Error },
}

/// Write one headscale state file into `dir` with owner-only permissions.
///
/// Creates `dir` if absent: on a failover node nothing has made it yet.
///
/// The mode is applied twice on unix, and both are load-bearing —
/// `OpenOptions::mode` only takes effect when the file is *created*, so an
/// already-present world-readable file would otherwise keep its bits; and
/// setting permissions only after the write would leave a window in which fresh
/// key material sits at the umask default.
pub fn write_state_file(dir: &Path, filename: &str, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(filename);

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(STATE_FILE_MODE)
            .open(&path)?;
        f.write_all(bytes)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(STATE_FILE_MODE))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, bytes)?;
    }

    Ok(())
}

/// Place the coordinator's noise identity on disk from the cluster secret
/// store, if the store has it. Call this **before** starting headscale.
///
/// `resolver` is `None` on a node with no cluster-secret rail at all (no raft
/// state, or no node-local KEK) — indistinguishable from an unprovisioned dev
/// box, and treated the same as a store that simply lacks the record. That
/// direction is deliberate: refusing to start every coordinator whose KEK is
/// missing would take the mesh down over a provisioning detail, whereas the
/// failure this guards against needs *evidence* that the cluster holds an
/// identity we are about to contradict.
///
/// Never seeds the store from local disk. Publishing whatever this node happens
/// to hold is exactly the wrong move during a split brain — the losing node
/// would overwrite the real identity with its own. Seeding is an operator act;
/// see [`SEED_COMMAND`].
pub fn materialize_noise_key(
    resolver: Option<&dyn SecretResolver>,
    headscale_dir: &Path,
) -> Result<NoiseIdentity, NoiseKeyError> {
    let key_path = headscale_dir.join(NOISE_KEY_FILE);

    let carried = match resolver {
        Some(r) => {
            let r#ref = SecretRef::Cluster {
                name: NOISE_KEY_SECRET.to_string(),
            };
            match r.resolve(&r#ref) {
                Ok(bytes) => Some(bytes),
                // The one non-fatal read failure: the record is genuinely not
                // in the local replica, so there is no identity to contradict.
                Err(SecretError::ClusterNotFound { .. }) => None,
                Err(source) => {
                    return Err(NoiseKeyError::Unusable {
                        name: NOISE_KEY_SECRET.to_string(),
                        source,
                    })
                }
            }
        }
        None => None,
    };

    if let Some(bytes) = carried {
        write_state_file(headscale_dir, NOISE_KEY_FILE, &bytes).map_err(|source| {
            NoiseKeyError::Write {
                path: key_path.clone(),
                source,
            }
        })?;
        info!(
            path = %key_path.display(),
            bytes = bytes.len(),
            "headscale noise identity materialized from the cluster secret store — this \
             appliance is portable"
        );
        return Ok(NoiseIdentity::Carried);
    }

    if key_path.exists() {
        error!(
            secret = NOISE_KEY_SECRET,
            path = %key_path.display(),
            "cluster secret store does not hold this coordinator's noise identity, but a key \
             exists on local disk — THE APPLIANCE IS NOT PORTABLE: a failover to another node \
             would mint a fresh identity and every already-registered node would reject it. \
             Seed the store with: {SEED_COMMAND}"
        );
        return Ok(NoiseIdentity::LocalOnly);
    }

    error!(
        secret = NOISE_KEY_SECRET,
        path = %key_path.display(),
        "cluster secret store does not hold this coordinator's noise identity and there is no \
         key on local disk — headscale is about to MINT A FRESH IDENTITY that no existing node \
         will accept. Once it is up, seed the store before any failover: {SEED_COMMAND}"
    );
    Ok(NoiseIdentity::Fresh)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the stubbed store answers with. `SecretError` is not `Clone`, so
    /// the variant is described here and minted fresh on each `resolve`.
    enum Answer {
        Bytes(Vec<u8>),
        NotFound,
        Forbidden,
        Decrypt,
    }

    struct FakeResolver(Answer);

    impl SecretResolver for FakeResolver {
        fn resolve(&self, r: &SecretRef) -> Result<Vec<u8>, SecretError> {
            // The whole point is that we ask for the cluster secret by name.
            let SecretRef::Cluster { name } = r else {
                panic!("the noise identity must be read as a cluster secret");
            };
            assert_eq!(name, NOISE_KEY_SECRET);
            match &self.0 {
                Answer::Bytes(b) => Ok(b.clone()),
                Answer::NotFound => Err(SecretError::ClusterNotFound { name: name.clone() }),
                Answer::Forbidden => Err(SecretError::Forbidden { name: name.clone() }),
                Answer::Decrypt => Err(SecretError::ClusterDecrypt { name: name.clone() }),
            }
        }
    }

    fn has(bytes: &[u8]) -> FakeResolver {
        FakeResolver(Answer::Bytes(bytes.to_vec()))
    }

    fn lacks() -> FakeResolver {
        FakeResolver(Answer::NotFound)
    }

    #[test]
    fn a_carried_key_lands_with_the_right_bytes_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let r = has(b"privkey:deadbeef");

        let outcome = materialize_noise_key(Some(&r), dir.path()).unwrap();

        assert_eq!(outcome, NoiseIdentity::Carried);
        let path = dir.path().join(NOISE_KEY_FILE);
        assert_eq!(std::fs::read(&path).unwrap(), b"privkey:deadbeef");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, STATE_FILE_MODE, "noise key must be owner-only");
        }
    }

    /// The dir does not exist yet on a node taking the appliance over for the
    /// first time — materialization must not need someone else to have made it.
    #[test]
    fn a_carried_key_creates_the_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("headscale");
        let r = has(b"privkey:abc");

        assert_eq!(
            materialize_noise_key(Some(&r), &dir).unwrap(),
            NoiseIdentity::Carried
        );
        assert_eq!(std::fs::read(dir.join(NOISE_KEY_FILE)).unwrap(), b"privkey:abc");
    }

    /// A carried key OVERWRITES whatever this node had: the cluster's copy is
    /// the identity of record, and a stale local key is the thing that makes a
    /// moved appliance reject the fleet.
    #[test]
    fn a_carried_key_replaces_a_stale_local_one_and_retightens_the_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(NOISE_KEY_FILE);
        std::fs::write(&path, b"privkey:stale-and-wrong").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let r = has(b"privkey:real");
        assert_eq!(
            materialize_noise_key(Some(&r), dir.path()).unwrap(),
            NoiseIdentity::Carried
        );

        assert_eq!(std::fs::read(&path).unwrap(), b"privkey:real");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, STATE_FILE_MODE, "a pre-existing loose mode is retightened");
        }
    }

    #[test]
    fn store_lacks_it_but_disk_has_it_is_local_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(NOISE_KEY_FILE), b"privkey:local").unwrap();

        assert_eq!(
            materialize_noise_key(Some(&lacks()), dir.path()).unwrap(),
            NoiseIdentity::LocalOnly
        );
        // Untouched — we do not rewrite what headscale is already using.
        assert_eq!(
            std::fs::read(dir.path().join(NOISE_KEY_FILE)).unwrap(),
            b"privkey:local"
        );
    }

    #[test]
    fn store_lacks_it_and_no_disk_key_is_a_fresh_identity() {
        let dir = tempfile::tempdir().unwrap();

        assert_eq!(
            materialize_noise_key(Some(&lacks()), dir.path()).unwrap(),
            NoiseIdentity::Fresh
        );
        assert!(!dir.path().join(NOISE_KEY_FILE).exists());
    }

    /// No cluster rail at all (no raft state, or no node-local KEK) reads the
    /// same as a store that lacks the record — it is not evidence of an
    /// identity we would be contradicting.
    #[test]
    fn no_resolver_falls_through_to_the_disk_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            materialize_noise_key(None, dir.path()).unwrap(),
            NoiseIdentity::Fresh
        );

        std::fs::write(dir.path().join(NOISE_KEY_FILE), b"privkey:local").unwrap();
        assert_eq!(
            materialize_noise_key(None, dir.path()).unwrap(),
            NoiseIdentity::LocalOnly
        );
    }

    /// A write failure must be FATAL, not a warning: the store holds the
    /// identity, so starting headscale would contradict it.
    #[test]
    fn a_write_failure_refuses_to_start() {
        let tmp = tempfile::tempdir().unwrap();
        // `headscale_dir` is a regular FILE, so `create_dir_all` fails.
        let dir = tmp.path().join("not-a-dir");
        std::fs::write(&dir, b"").unwrap();

        let err = materialize_noise_key(Some(&has(b"privkey:real")), &dir).unwrap_err();
        assert!(
            matches!(err, NoiseKeyError::Write { .. }),
            "expected a fatal write error, got {err:?}"
        );
    }

    /// A denied access rule / wrong KEK / tampered record is evidence the
    /// cluster HOLDS an identity we cannot honour — also fatal, and explicitly
    /// not the same as `ClusterNotFound`.
    #[test]
    fn an_unusable_cluster_record_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();

        for answer in [Answer::Forbidden, Answer::Decrypt] {
            let err =
                materialize_noise_key(Some(&FakeResolver(answer)), dir.path()).unwrap_err();
            assert!(
                matches!(err, NoiseKeyError::Unusable { .. }),
                "expected a fatal unusable-record error, got {err:?}"
            );
        }
        assert!(!dir.path().join(NOISE_KEY_FILE).exists());
    }

    #[test]
    fn write_state_file_is_owner_only_for_every_state_file() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["headscale.db", "private.key", NOISE_KEY_FILE] {
            write_state_file(dir.path(), name, b"x").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(dir.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, STATE_FILE_MODE, "{name} must be owner-only");
            }
        }
    }

    /// The error text an operator reads must contain the command that fixes it.
    #[test]
    fn the_seed_command_names_both_halves() {
        assert!(SEED_COMMAND.contains("yah keys set headscale-noise-private-key"));
        assert!(SEED_COMMAND.contains("yah cloud secret put headscale/noise-private-key"));
    }
}
