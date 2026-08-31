//! Publishing the SNI demux's route table from the enrollment set (R779 / W267).
//!
//! [`crate::cert_store`] holds the enrollment set — one `enrolled/<domain>`
//! object per registered domain, naming the per-tenant passway that serves it.
//! `passway-demux` on `:443` routes on a `host=addr` table. This module is the
//! one-way pipe between them: sweep the set, render the table, write it where
//! the demux reloads it.
//!
//! ## Why a file and not a socket
//!
//! The demux is a trust-boundary process that deliberately links no TLS stack
//! and no HTTP client (`sni-demux/src/lib.rs`), and giving it an R2 client and
//! this bucket's credentials would hand a compromise of the *shared* process a
//! read of every tenant's routing — and a set of credentials — that it currently
//! cannot reach. A file it re-reads is the smallest surface that closes the
//! loop: yubaba (which already holds the credentials, and the KEK) writes; the
//! demux reads bytes off local disk.
//!
//! ## Fail-closed, which here means *fail-stale*
//!
//! Two refusals, both about the same failure: this node's view of the bucket is
//! not authority over the fleet's routing.
//!
//! - **A listing failure never writes.** The previous file stays, and the demux
//!   keeps serving the routes it has. An R2 blip must not de-route the fleet.
//! - **An empty render never writes.** A successful listing of an empty bucket
//!   and a bucket pointed at the wrong prefix produce the identical answer, and
//!   one of them is an outage for every tenant. The cost is that unenrolling the
//!   *last* domain does not propagate until the demux is restarted, which is the
//!   right way round.
//!
//! The write itself is tmp-plus-rename, so a demux polling the file never reads
//! a half-written table.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tracing::{info, warn};

use crate::cert_store::{route_entries, CertStoreError, ObjectCertStore};

/// Env key naming the file to publish. Its presence turns the publisher on.
pub const ROUTES_FILE_ENV: &str = "YUBABA_DEMUX_ROUTES_FILE";
/// Env key overriding the sweep cadence.
pub const SWEEP_SECS_ENV: &str = "YUBABA_DEMUX_ROUTES_SWEEP_SECS";

/// Default seconds between sweeps.
///
/// Minutes, not seconds: a sweep is one `list_prefix` plus one `get` per
/// enrolled domain (see [`ObjectCertStore::enrolled`]), so at 10k domains a
/// tight loop would be a five-figure hourly object-op bill for data that changes
/// when a human registers a domain. Enrollment is not a hot path; the latency
/// that matters (a *new* domain becoming routable) is bounded by this plus the
/// demux's own reload poll.
pub const DEFAULT_SWEEP_SECS: u64 = 300;

/// Where and how often to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePublisherConfig {
    /// File the demux reloads (`PASSWAY_DEMUX_ROUTES_FILE`).
    pub routes_file: PathBuf,
    /// Seconds between sweeps.
    pub sweep: Duration,
}

/// Parse the publisher config from a `key -> value` lookup — a pure function
/// over the environment, same shape (and for the same testability reason) as
/// [`crate::cert_store::CertStoreConfig::parse`].
///
/// `Ok(None)` when [`ROUTES_FILE_ENV`] is unset: publishing is opt-in, and a
/// node that is not fronting a demux should not be sweeping the bucket.
pub fn parse_publisher_config(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<RoutePublisherConfig>, String> {
    let routes_file = match get(ROUTES_FILE_ENV) {
        Some(p) if !p.trim().is_empty() => PathBuf::from(p.trim()),
        _ => return Ok(None),
    };
    let sweep_secs = match get(SWEEP_SECS_ENV) {
        Some(v) => v
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{SWEEP_SECS_ENV}: expected a non-negative integer"))?,
        None => DEFAULT_SWEEP_SECS,
    };
    if sweep_secs == 0 {
        return Err(format!("{SWEEP_SECS_ENV} must be greater than zero"));
    }
    Ok(Some(RoutePublisherConfig {
        routes_file,
        sweep: Duration::from_secs(sweep_secs),
    }))
}

/// What one sweep did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    /// The rendered table differed from the file on disk and was replaced.
    Written { domains: usize },
    /// The render matched the file byte-for-byte; nothing was written, so the
    /// file's mtime still reads as the last real change.
    Unchanged { domains: usize },
    /// The enrollment set is empty. Deliberately not written — see the module
    /// doc.
    EmptySkipped,
}

/// A sweep that could not complete.
#[derive(Debug, Error)]
pub enum PublishError {
    #[error("reading the enrollment set: {0}")]
    Store(#[from] CertStoreError),
    #[error("writing {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// One sweep: list the enrollment set, render the table, write it if it changed.
///
/// Synchronous — [`ObjectCertStore`] is, like every other object-store consumer
/// in the tree — so an async caller runs it on a blocking thread. See
/// [`spawn`].
pub fn publish_once(
    store: &ObjectCertStore,
    routes_file: &Path,
) -> Result<Published, PublishError> {
    let enrolled = store.enrolled()?;
    let entries = route_entries(enrolled.iter().map(|(d, e)| (d.as_str(), e)));
    if entries.is_empty() {
        return Ok(Published::EmptySkipped);
    }
    // One entry per line, trailing newline: a 10k-domain table has to be
    // diffable and `grep`-able by an operator, and the demux's loader takes
    // newlines as separators.
    let rendered = format!("{}\n", entries.join("\n"));
    let domains = entries.len();

    if std::fs::read(routes_file).is_ok_and(|current| current == rendered.as_bytes()) {
        return Ok(Published::Unchanged { domains });
    }
    write_atomic(routes_file, rendered.as_bytes()).map_err(|source| PublishError::Io {
        path: routes_file.to_path_buf(),
        source,
    })?;
    Ok(Published::Written { domains })
}

/// Write `bytes` to `path` via a sibling temp file and a rename.
///
/// The rename is atomic within a filesystem, so a demux reading the file
/// concurrently sees either the whole old table or the whole new one — never a
/// truncated one, which would parse as a *shorter* route table and silently
/// de-route the tenants past the cut.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Spawn the publisher loop. Sweeps immediately, then every `cfg.sweep`.
///
/// Every failure is logged and the loop continues: a publisher that exited on
/// the first R2 error would leave the route table frozen at whatever it held
/// when the bucket blipped, and nothing would say so again.
pub fn spawn(
    store: Arc<ObjectCertStore>,
    cfg: RoutePublisherConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            routes_file = %cfg.routes_file.display(),
            sweep_secs = cfg.sweep.as_secs(),
            issuer = %store.issuer(),
            "demux routes: publishing the enrollment set for passway-demux"
        );
        loop {
            let (store, path) = (store.clone(), cfg.routes_file.clone());
            match tokio::task::spawn_blocking(move || publish_once(&store, &path)).await {
                Ok(Ok(Published::Written { domains })) => info!(
                    routes_file = %cfg.routes_file.display(),
                    domains,
                    "demux routes: route table published"
                ),
                Ok(Ok(Published::Unchanged { .. })) => {}
                Ok(Ok(Published::EmptySkipped)) => warn!(
                    routes_file = %cfg.routes_file.display(),
                    "demux routes: the enrollment set is empty — leaving the existing \
                     route table in place rather than de-routing every tenant"
                ),
                Ok(Err(e)) => warn!("demux routes: sweep failed (retry next sweep): {e}"),
                Err(e) => warn!("demux routes: sweep task failed: {e}"),
            }
            tokio::time::sleep(cfg.sweep).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::Enrollment;
    use std::net::SocketAddr;
    use std::time::{SystemTime, UNIX_EPOCH};
    use yah_object_store::{InMemoryObjectStore, ObjectStore};

    const LE: &str = "https://acme-v02.api.letsencrypt.org/directory";

    fn store() -> (Arc<InMemoryObjectStore>, ObjectCertStore) {
        let mem = Arc::new(InMemoryObjectStore::new());
        let certs = ObjectCertStore::new(mem.clone(), LE);
        (mem, certs)
    }

    fn enrollment(port: u16) -> Enrollment {
        Enrollment::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
    }

    #[test]
    fn config_is_off_unless_a_routes_file_is_named() {
        assert_eq!(parse_publisher_config(|_| None).unwrap(), None);
        assert_eq!(
            parse_publisher_config(|k| (k == ROUTES_FILE_ENV).then(|| "  ".to_string())).unwrap(),
            None
        );
    }

    #[test]
    fn config_defaults_the_sweep_and_rejects_a_zero_one() {
        let cfg = parse_publisher_config(|k| {
            (k == ROUTES_FILE_ENV).then(|| "/etc/passway/routes".to_string())
        })
        .unwrap()
        .unwrap();
        assert_eq!(cfg.routes_file, PathBuf::from("/etc/passway/routes"));
        assert_eq!(cfg.sweep, Duration::from_secs(DEFAULT_SWEEP_SECS));

        let get = |k: &str| match k {
            ROUTES_FILE_ENV => Some("/etc/passway/routes".to_string()),
            SWEEP_SECS_ENV => Some("0".to_string()),
            _ => None,
        };
        assert!(parse_publisher_config(get).is_err(), "a zero sweep is a spin");
    }

    #[test]
    fn publishes_one_entry_per_line_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("routes");
        let (_mem, certs) = store();
        certs.enroll("b.example.com", &enrollment(8444)).unwrap();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();

        assert_eq!(
            publish_once(&certs, &path).unwrap(),
            Published::Written { domains: 2 }
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "a.example.com=127.0.0.1:8443\nb.example.com=127.0.0.1:8444\n"
        );
    }

    #[test]
    fn an_unchanged_set_is_not_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();

        assert_eq!(
            publish_once(&certs, &path).unwrap(),
            Published::Written { domains: 1 }
        );
        assert_eq!(
            publish_once(&certs, &path).unwrap(),
            Published::Unchanged { domains: 1 }
        );
        // And a real change writes again.
        certs.enroll("b.example.com", &enrollment(8444)).unwrap();
        assert_eq!(
            publish_once(&certs, &path).unwrap(),
            Published::Written { domains: 2 }
        );
    }

    #[test]
    fn an_empty_enrollment_set_never_blanks_a_live_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        publish_once(&certs, &path).unwrap();

        certs.unenroll("a.example.com").unwrap();
        assert_eq!(publish_once(&certs, &path).unwrap(), Published::EmptySkipped);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "a.example.com=127.0.0.1:8443\n",
            "an empty listing must leave the last good table on disk"
        );
    }

    #[test]
    fn a_malformed_enrollment_costs_only_its_own_route() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (mem, certs) = store();
        certs.enroll("good.example.com", &enrollment(8443)).unwrap();
        mem.put("enrolled/bad.example.com", b"{".to_vec()).unwrap();

        assert_eq!(
            publish_once(&certs, &path).unwrap(),
            Published::Written { domains: 1 }
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "good.example.com=127.0.0.1:8443\n"
        );
    }

    #[test]
    fn no_temp_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        publish_once(&certs, &path).unwrap();

        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("routes")]);
    }

    #[test]
    fn a_stamp_only_change_does_not_rewrite_the_table() {
        // Enrollment records carry `enrolled_at`, which the render must not
        // include: a table rewritten every sweep would make the demux reload
        // (and an operator's mtime) meaningless.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        publish_once(&certs, &path).unwrap();

        let later = Enrollment::new(
            SocketAddr::from(([127, 0, 0, 1], 8443)),
            SystemTime::now(),
        );
        mem.put(
            "enrolled/a.example.com",
            serde_json::to_vec(&later).unwrap(),
        )
        .unwrap();
        assert_eq!(
            publish_once(&certs, &path).unwrap(),
            Published::Unchanged { domains: 1 }
        );
    }
}
