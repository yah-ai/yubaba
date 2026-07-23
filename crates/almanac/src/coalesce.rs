//! Per-feed run coalescing — "at most one in flight, at most one queued".
//!
//! ## Why this is safe, and why it is the *right* shape
//!
//! An almanac feed source is **absolute, not a delta**: `ReleaseSource::fetch`
//! returns the complete current state of the world, and the `/revalidate` POST
//! carries nothing but a feed name. The change lives in the feed, never in the
//! request body.
//!
//! That single property is what makes conflation correct. If N triggers arrive
//! while a run is in flight, running N times would produce N identical results,
//! because each run re-reads the same absolute source. Collapsing them to one
//! follow-up run loses nothing:
//!
//! > For any trigger at time `T`, either (a) it arrives before a run begins, so
//! > that run's fetch — which happens after `T` — observes it; or (b) it
//! > arrives during a run, which sets the pending bit and forces a follow-up
//! > run whose fetch strictly follows `T`. In both cases some fetch happens
//! > after `T`. No change can be missed.
//!
//! Note the asymmetry this buys: dropping *intermediate* runs is free, but
//! dropping the *last* one is not. A plain "reject while busy" (the 503 that
//! `receiver.rs` returns on a full channel) drops the last one and silently
//! loses the change until something else happens to trigger. That is the bug
//! this type exists to make unrepresentable.
//!
//! ## Concurrency notes
//!
//! The lock is a `std::sync::Mutex` and is **never held across an await** — it
//! guards two `HashMap` operations and nothing else. Callers do their slow work
//! (network fetch, artifact write, rebuild dispatch) entirely outside it.
//!
//! Coalescing is per feed: two different feeds run concurrently, so a slow
//! rebuild of one cannot head-of-line block another.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// What the caller should do with a revalidation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Nothing was in flight. The caller now owns this feed and MUST drive it
    /// with [`Coalescer::finish`] until that returns `false`, or the feed stays
    /// permanently marked busy and every later trigger is silently coalesced
    /// into a run that will never happen.
    Run,
    /// A run is already in flight. The pending bit is now set, guaranteeing
    /// exactly one follow-up run. The caller does nothing.
    Coalesced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// A run is in flight and no trigger has arrived since it started.
    Running,
    /// A run is in flight and at least one trigger arrived since it started.
    /// Collapses any number of triggers into exactly one follow-up run.
    RunningWithPending,
}

/// Tracks which feeds are running and which have a re-run queued.
///
/// Cheap to clone — clones share one map.
#[derive(Debug, Clone, Default)]
pub struct Coalescer {
    inner: Arc<Mutex<HashMap<String, State>>>,
}

impl Coalescer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a trigger for `feed`.
    ///
    /// See [`Admission`] for the caller's obligation on [`Admission::Run`].
    pub fn admit(&self, feed: &str) -> Admission {
        let mut map = self.lock();
        match map.get(feed) {
            None => {
                map.insert(feed.to_string(), State::Running);
                Admission::Run
            }
            // Already pending — a second trigger adds nothing, which is the
            // whole point: N triggers during one run cost exactly one re-run.
            Some(State::Running) | Some(State::RunningWithPending) => {
                map.insert(feed.to_string(), State::RunningWithPending);
                Admission::Coalesced
            }
        }
    }

    /// Report that a run of `feed` finished.
    ///
    /// Returns `true` if a trigger arrived during that run and the caller must
    /// immediately run again. The feed stays marked busy across that handoff,
    /// so no other task can start a concurrent run in the gap.
    #[must_use = "ignoring the return value drops a queued re-run and loses a change"]
    pub fn finish(&self, feed: &str) -> bool {
        let mut map = self.lock();
        match map.get(feed) {
            Some(State::RunningWithPending) => {
                map.insert(feed.to_string(), State::Running);
                true
            }
            Some(State::Running) => {
                map.remove(feed);
                false
            }
            // Defensive: finish() without a matching admit(). Nothing to
            // release and nothing queued.
            None => false,
        }
    }

    /// Release `feed` without running, discarding any queued re-run.
    ///
    /// For the failure path where a caller got [`Admission::Run`] but could not
    /// start the work at all (e.g. the feed failed to load). Using this instead
    /// of leaking the busy marker keeps a broken feed from wedging permanently.
    pub fn abandon(&self, feed: &str) {
        self.lock().remove(feed);
    }

    /// Number of feeds currently marked busy. Diagnostics and tests.
    pub fn in_flight(&self) -> usize {
        self.lock().len()
    }

    /// Whether `feed` has a re-run queued. Diagnostics and tests.
    pub fn is_pending(&self, feed: &str) -> bool {
        matches!(self.lock().get(feed), Some(State::RunningWithPending))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, State>> {
        // A panic inside the critical section cannot leave a torn value — the
        // section is a single map insert/remove — so recovering is sound and
        // strictly better than poisoning the whole receiver.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_trigger_runs() {
        let c = Coalescer::new();
        assert_eq!(c.admit("releases"), Admission::Run);
        assert_eq!(c.in_flight(), 1);
    }

    #[test]
    fn trigger_during_run_is_coalesced_into_exactly_one_rerun() {
        let c = Coalescer::new();
        assert_eq!(c.admit("releases"), Admission::Run);

        // Ten triggers land while the first run is in flight.
        for _ in 0..10 {
            assert_eq!(c.admit("releases"), Admission::Coalesced);
        }

        // They collapse to ONE re-run, not ten.
        assert!(c.finish("releases"), "queued re-run expected");
        assert!(!c.finish("releases"), "only one re-run should be queued");
        assert_eq!(c.in_flight(), 0);
    }

    #[test]
    fn quiet_run_releases_the_feed() {
        let c = Coalescer::new();
        assert_eq!(c.admit("releases"), Admission::Run);
        assert!(!c.finish("releases"));
        assert_eq!(c.in_flight(), 0);
        // And the feed is immediately runnable again.
        assert_eq!(c.admit("releases"), Admission::Run);
    }

    #[test]
    fn feeds_do_not_block_each_other() {
        let c = Coalescer::new();
        assert_eq!(c.admit("releases"), Admission::Run);
        // A different feed is unaffected by the first being busy.
        assert_eq!(c.admit("issues"), Admission::Run);
        assert_eq!(c.in_flight(), 2);
    }

    #[test]
    fn pending_survives_the_handoff_so_no_gap_lets_a_second_runner_in() {
        let c = Coalescer::new();
        assert_eq!(c.admit("releases"), Admission::Run);
        assert_eq!(c.admit("releases"), Admission::Coalesced);

        // finish() returns true AND keeps the feed marked busy, so a racing
        // trigger during the handoff still coalesces rather than starting a
        // second concurrent run.
        assert!(c.finish("releases"));
        assert_eq!(c.admit("releases"), Admission::Coalesced);
        assert_eq!(c.in_flight(), 1);
    }

    #[test]
    fn abandon_clears_without_running() {
        let c = Coalescer::new();
        assert_eq!(c.admit("releases"), Admission::Run);
        assert_eq!(c.admit("releases"), Admission::Coalesced);
        c.abandon("releases");
        assert_eq!(c.in_flight(), 0);
        assert_eq!(c.admit("releases"), Admission::Run);
    }

    #[test]
    fn finish_without_admit_is_a_noop() {
        let c = Coalescer::new();
        assert!(!c.finish("never-started"));
    }

    /// The property that matters under real concurrency: however many threads
    /// hammer one feed, exactly one of them is ever told to run at a time, and
    /// the total number of runs never exceeds triggers.
    #[test]
    fn concurrent_triggers_admit_exactly_one_runner() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        let c = Coalescer::new();
        let runners = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..32)
            .map(|_| {
                let c = c.clone();
                let runners = Arc::clone(&runners);
                thread::spawn(move || {
                    if c.admit("releases") == Admission::Run {
                        runners.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            runners.load(Ordering::SeqCst),
            1,
            "exactly one thread may own the run"
        );
        assert!(c.is_pending("releases"), "the other 31 must be queued as one");
    }
}
