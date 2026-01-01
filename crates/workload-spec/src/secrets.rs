//! Pluggable secret resolver for [`crate::SecretRef`] values.
//!
//! The trait lives in `workload-spec` so consumers can construct specs and
//! invoke the resolver without linking warden's containerd client. Warden
//! provides the production impl in `crates/yah/warden/src/secrets.rs`.

use std::path::PathBuf;

use thiserror::Error;

use crate::SecretRef;

/// Errors returned by [`SecretResolver::resolve`].
#[derive(Debug, Error)]
pub enum SecretError {
    /// The referenced secret file does not exist in the warden secret store.
    #[error("secret not found at {path}")]
    NotFound { path: PathBuf },

    /// `SecretRef::Cluster` is reserved for V2 (raft-replicated cluster
    /// secrets). V1 returns this error for any cluster secret reference.
    #[error("cluster secrets are not implemented in V1 — raft replication is a follow-on")]
    ClusterNotImplemented,

    /// I/O error reading the secret file.
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Resolves a [`SecretRef`] to its raw byte content.
///
/// The trait is defined here (in `workload-spec`) so callers don't need to
/// link warden. Warden's `LocalFileResolver` reads from the per-machine secret
/// store at `/var/lib/yah/warden/secrets/`. Tests use an inline `FakeResolver`.
pub trait SecretResolver {
    fn resolve(&self, r: &SecretRef) -> Result<Vec<u8>, SecretError>;
}
