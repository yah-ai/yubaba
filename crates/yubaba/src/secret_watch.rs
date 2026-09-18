//! The node's fleet secret watch: poll the fleet object store and bump
//! [`ServerState::secret_epoch`] when a record this node resolves changes
//! (R911-F2).
//!
//! Before R911 the wake signal for `secret_reload` and `cert_materialize` was
//! the raft state machine's secret epoch, bumped on every applied `PutSecret`.
//! Secrets now live in the fleet object store, and R2 has no change
//! notifications, so every node polls: each [`interval`] it takes the store's
//! [`fingerprint`](FleetSecretStore::fingerprint) — the ETags of everything
//! under `secrets/<group>/` and `certs/<issuer>/` — on the blocking pool, and
//! bumps the epoch only when that fingerprint differs from the last one it
//! read.
//!
//! A poll error is never a change. It neither bumps nor replaces the last good
//! fingerprint, so a bucket that blips and comes back unchanged wakes nobody.
//! It is logged once per outage, on the transition, not on every tick.
//!
//! The consumers keep their own `DEBOUNCE` and `rolling_stagger`: this module
//! only says *that* something changed, never what.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::fleet_secrets::{off_runtime, FleetSecretStore, MissingRail};
use crate::secrets::SecretStoreError;
use crate::ServerState;

/// Poll interval override, in whole seconds. Unset, blank, zero or unparsable
/// means [`DEFAULT_INTERVAL`].
pub const INTERVAL_ENV: &str = "YUBABA_SECRET_WATCH_INTERVAL_SECS";

/// How often a node polls the fleet secret store when [`INTERVAL_ENV`] is unset.
///
/// A rotation reaches a consumer within one interval plus the consumer's own
/// debounce and stagger. Each poll is two LISTs plus one HEAD per record.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// The poll interval from `get` (the process environment in production).
pub fn interval(get: impl Fn(&str) -> Option<String>) -> Duration {
    let Some(raw) = get(INTERVAL_ENV).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    else {
        return DEFAULT_INTERVAL;
    };
    match raw.parse::<u64>() {
        Ok(secs) if secs > 0 => Duration::from_secs(secs),
        _ => {
            tracing::warn!(
                value = %raw,
                default_secs = DEFAULT_INTERVAL.as_secs(),
                "secret watch: {INTERVAL_ENV} is not a positive whole number of seconds; using \
                 the default"
            );
            DEFAULT_INTERVAL
        }
    }
}

/// Watch this node's fleet secret store for its lifetime. Returns immediately
/// on a node with no cert-store config: there is no store to watch, and every
/// cluster-secret read there already fails closed by name.
pub async fn run(state: Arc<ServerState>) {
    let store = match FleetSecretStore::for_node(&state) {
        Ok(store) => store,
        Err(MissingRail::NoObjectStore) => {
            tracing::info!("secret watch: no fleet object store configured on this node; idle");
            return;
        }
        // The one startup line for a node that has the bucket but no group:
        // every cluster-secret read on it fails closed until the flag is set.
        Err(rail @ MissingRail::NoSovereignGroup) => {
            tracing::error!(
                "secret watch: {rail} — this node has a fleet object store but cluster secrets \
                 are keyed per sovereign group and there is no default, so every cluster-secret \
                 read here fails closed. Start yubaba with --sovereign-group <group>"
            );
            return;
        }
    };
    let every = interval(|k| std::env::var(k).ok());
    tracing::info!(
        issuer = %store.issuer(),
        group = %store.group(),
        interval_secs = every.as_secs(),
        "secret watch: polling the fleet secret store for rotations"
    );
    poll_loop(store, every, state.secret_epoch.clone()).await;
}

/// The loop behind [`run`], with its inputs injected so a test can drive it.
pub(crate) async fn poll_loop(store: FleetSecretStore, every: Duration, epoch: watch::Sender<u64>) {
    let mut tracker = Tracker::default();
    loop {
        let s = store.clone();
        let polled = off_runtime(move || s.fingerprint()).await;
        if tracker.observe(polled) {
            epoch.send_modify(|e| *e = e.wrapping_add(1));
        }
        tokio::time::sleep(every).await;
    }
}

/// What the watch remembers between polls. Pure, so the bump rules are
/// testable without a clock or a bucket.
#[derive(Debug, Default)]
struct Tracker {
    /// The last fingerprint a poll actually read.
    last: Option<u64>,
    /// Inside an outage: the transition has been logged.
    failing: bool,
    /// Polls failed before any baseline existed, so the first good read cannot
    /// be assumed to match what the consumers converged on at startup.
    missed_baseline: bool,
}

impl Tracker {
    /// Record one poll; `true` means bump the epoch.
    ///
    /// - The first successful poll is the baseline and does not bump, unless
    ///   polls had already failed before it (the consumers' own startup pass
    ///   may have hit the same outage, so they are woken to retry).
    /// - A later poll bumps exactly when its fingerprint differs from the last
    ///   good one.
    /// - An error never bumps and never replaces the last good fingerprint.
    fn observe(&mut self, polled: Result<u64, SecretStoreError>) -> bool {
        match polled {
            Err(e) => {
                if !self.failing {
                    tracing::warn!(
                        error = %e,
                        "secret watch: cannot poll the fleet secret store; rotations will not be \
                         seen until it is reachable again"
                    );
                    self.failing = true;
                }
                if self.last.is_none() {
                    self.missed_baseline = true;
                }
                false
            }
            Ok(fingerprint) => {
                if std::mem::take(&mut self.failing) {
                    tracing::info!("secret watch: the fleet secret store is reachable again");
                }
                let changed = match self.last {
                    Some(prev) => prev != fingerprint,
                    None => self.missed_baseline,
                };
                self.last = Some(fingerprint);
                changed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_secrets::test_support::UnreachableObjectStore;
    use crate::secrets::seal_cluster_secret;
    use workload_spec::secrets::SecretAccess;
    use yah_object_store::InMemoryObjectStore;

    fn outage() -> Result<u64, SecretStoreError> {
        Err(SecretStoreError::Backend(yah_object_store::Error::Backend(
            "down".into(),
        )))
    }

    #[test]
    fn the_baseline_does_not_bump_and_an_unchanged_poll_does_not_either() {
        let mut t = Tracker::default();
        assert!(!t.observe(Ok(7)), "the first read is the baseline");
        assert!(!t.observe(Ok(7)));
        assert!(!t.observe(Ok(7)));
    }

    #[test]
    fn a_change_bumps_exactly_once() {
        let mut t = Tracker::default();
        t.observe(Ok(7));
        assert!(t.observe(Ok(8)));
        assert!(!t.observe(Ok(8)), "the same fingerprint again is not a second change");
    }

    #[test]
    fn an_error_is_not_a_change_and_does_not_move_the_baseline() {
        let mut t = Tracker::default();
        t.observe(Ok(7));
        assert!(!t.observe(outage()));
        assert!(!t.observe(outage()));
        assert!(!t.observe(Ok(7)), "recovering to the same state wakes nobody");
        assert!(!t.observe(outage()));
        assert!(t.observe(Ok(9)), "a change made during the outage is seen on recovery");
    }

    #[test]
    fn an_outage_before_any_baseline_wakes_the_consumers_on_the_first_good_read() {
        let mut t = Tracker::default();
        assert!(!t.observe(outage()));
        assert!(t.observe(Ok(7)));
        assert!(!t.observe(Ok(7)));
    }

    #[test]
    fn the_interval_defaults_and_is_overridable() {
        let env = |v: Option<&'static str>| move |k: &str| (k == INTERVAL_ENV).then(|| v).flatten().map(String::from);
        assert_eq!(interval(env(None)), DEFAULT_INTERVAL);
        assert_eq!(interval(env(Some("  "))), DEFAULT_INTERVAL);
        assert_eq!(interval(env(Some("5"))), Duration::from_secs(5));
        assert_eq!(interval(env(Some("0"))), DEFAULT_INTERVAL);
        assert_eq!(interval(env(Some("soon"))), DEFAULT_INTERVAL);
    }

    /// End to end on a multi-thread runtime: the poll runs through
    /// `off_runtime` (the store's debug tripwire would panic otherwise), an
    /// unchanged store never bumps, and one write bumps once.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_loop_bumps_once_per_change() {
        let mem = Arc::new(InMemoryObjectStore::new());
        let store = FleetSecretStore::new(mem, "le", "prod");
        let (tx, mut rx) = watch::channel(0u64);
        let task = tokio::spawn(poll_loop(store.clone(), Duration::from_millis(10), tx));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!rx.has_changed().unwrap(), "baseline and unchanged polls must not bump");

        let s = store.clone();
        off_runtime(move || {
            s.write_secret(
                "cf/dns-token",
                &seal_cluster_secret(&[1u8; 32], "cf/dns-token", b"token", 1, SecretAccess::AllowAny),
            )
        })
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("a write must bump the epoch")
            .unwrap();
        assert_eq!(*rx.borrow_and_update(), 1);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!rx.has_changed().unwrap(), "one change, one bump");
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_store_never_bumps() {
        let store = FleetSecretStore::new(Arc::new(UnreachableObjectStore), "le", "prod");
        let (tx, rx) = watch::channel(0u64);
        let task = tokio::spawn(poll_loop(store, Duration::from_millis(10), tx));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!rx.has_changed().unwrap(), "a poll error is not a change");
        assert_eq!(*rx.borrow(), 0);
        task.abort();
    }
}
