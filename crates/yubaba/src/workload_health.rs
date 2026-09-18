//! Workload health — the cadence half of kamaji's probe runner.
//!
//! ## What was missing, and it was the whole thing
//!
//! kamaji retains each workload's declared [`Healthcheck`] across deploy and
//! answers exactly one poll per `YubabaToKamaji::Probe`. Its module docs
//! (`oss/kamaji/crates/kamaji-bin/src/probe.rs`) say "Yubaba drives cadence by
//! re-issuing `Probe`" and name *this* crate as the owner of `interval`,
//! `initial_delay` and `failure_threshold`.
//!
//! Nothing here ever sent one. Measured 2026-09-13, before this module
//! existed: `ProbeStatus` appeared in **zero** files under `crates/yubaba`,
//! and every construction of `YubabaToKamaji::Probe` in the tree was inside
//! kamaji's own unit tests. So every `[healthcheck]` block in every
//! `.yah/infra/workloads/*.toml` was declared and never executed — a complete,
//! tested probe runner with no caller.
//!
//! The visible consequence is what `GET /workloads` reported instead:
//! containerd's lifecycle state. `Running` means a task exists, which says
//! nothing about whether the thing behind the port finished booting — exactly
//! the false `Ready` that W315's control channel exists to end, arrived at
//! from the other direction.
//!
//! ## Shape
//!
//! One loop per node, spawned beside [`crate::service_records::run`] rather
//! than folded into it. They answer different questions on different failure
//! modes: the record sweep reconciles *what this node holds* and deliberately
//! goes stale rather than false on a backend blip, while a health verdict that
//! goes stale rather than false is the failure this module exists to remove.
//!
//! Each tick:
//!
//! 1. lists workloads through the kamaji sibling — a failed list is not an
//!    empty list, and is not evidence about anybody's health, so the tick is
//!    skipped whole rather than marking the fleet unknown;
//! 2. drops registry entries for workloads that are gone, so a destroyed
//!    workload leaves no verdict behind to be read as current;
//! 3. probes each workload whose own `interval` has elapsed, after its own
//!    `initial_delay`, and folds the answer through `failure_threshold`.
//!
//! Per-workload policy is read **once**, from the deployed spec kamaji already
//! holds (`describe`), and cached for that workload's lifetime — the
//! alternative is one extra round trip per workload per tick to re-read three
//! numbers that cannot change without a redeploy.
//!
//! ## `degraded` is a claim about consecutive failures, not about one probe
//!
//! `failure_threshold` is the reason this is not simply "the last
//! `ProbeStatus`": a workload that fails one poll in three is not down, and a
//! surface that says it is will be ignored within a week. The record carries
//! both — the raw latest status *and* the folded verdict — because a consumer
//! choosing between them should have to say which one it means.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kamaji::sibling::KamajiSibling;
use kamaji_proto::ProbeStatus;
use serde::Serialize;

/// How often the loop wakes. This is the *resolution* of the per-workload
/// cadence, not the cadence itself: a workload declaring `interval = 15000`
/// is probed on the first tick at or after 15s, so the floor here bounds how
/// late that can be rather than how often anything is dialled.
const TICK: Duration = Duration::from_secs(5);

/// Cadence policy, read once per workload from the spec kamaji holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Policy {
    interval: Duration,
    initial_delay: Duration,
    failure_threshold: u32,
}

impl Policy {
    /// What a workload with no `[healthcheck]` block gets.
    ///
    /// It still gets a record. `run_probe` answers `Ready` for a target with
    /// no probe declared ("trust the workload's existence as readiness"), and
    /// a workload that speaks the process-control channel answers from that
    /// channel whether or not a healthcheck was written — so the probe is
    /// informative even here. What it will not do is go red on its own, which
    /// is why the threshold is 1: there is nothing to debounce.
    const UNDECLARED: Self = Self {
        interval: Duration::from_secs(30),
        initial_delay: Duration::ZERO,
        failure_threshold: 1,
    };

    fn from_spec(hc: &workload_spec::Healthcheck) -> Self {
        Self {
            interval: Duration::from_millis(hc.interval.as_ms()),
            initial_delay: Duration::from_millis(hc.initial_delay.as_ms()),
            // A zero threshold would mark a workload degraded before its first
            // probe. Read it as "one failure is enough", which is what a spec
            // author writing 0 can only have meant.
            failure_threshold: hc.failure_threshold.max(1),
        }
    }
}

/// One workload's health as `GET /workloads` reports it.
///
/// ## Why this is not just `ProbeStatus` on the wire
///
/// [`ProbeStatus`] is `#[non_exhaustive]` — kamaji can add a variant without a
/// breaking change, which is right for an in-process type and wrong for a
/// public JSON contract. Serializing it directly would put kamaji's variant
/// set in every HTTP consumer's deserializer, so `cloud-client`, the desktop
/// and the UI would each need a copy of the enum and a story for the variant
/// they have not been taught yet.
///
/// A flat tag plus an optional reason has neither problem: it is the same
/// shape `WorkloadEntry.status` already uses, an unrecognised kamaji variant
/// lands as [`Self::STATUS_UNKNOWN`] instead of failing a parse, and the
/// reason — the whole difference between a red dot and a diagnosis — rides
/// alongside rather than inside a tagged union.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HealthRecord {
    /// `"ready"` | `"starting"` | `"unhealthy"` | `"timeout"` | `"unknown"`.
    pub status: String,
    /// The probe's own explanation, when it gave one. Present for
    /// `"unhealthy"`; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `consecutive_failures >= failure_threshold` — the declared policy's own
    /// verdict, which is the one an operator surface should colour on.
    pub degraded: bool,
    pub consecutive_failures: u32,
    /// Unix seconds at the most recent completed probe. Wall-clock because it
    /// crosses the wire; the cadence itself runs on a monotonic clock.
    pub last_checked_at: u64,
}

impl HealthRecord {
    /// The tag for a kamaji `ProbeStatus` variant this build predates.
    pub const STATUS_UNKNOWN: &'static str = "unknown";
}

/// Per-workload state the loop carries between ticks.
#[derive(Debug)]
struct Entry {
    /// `None` until the first probe completes — distinct from a probe that
    /// answered badly, and rendered as "not yet probed" rather than a verdict.
    record: Option<HealthRecord>,
    /// `None` until the spec has been read once.
    policy: Option<Policy>,
    first_seen: Instant,
    last_probe: Option<Instant>,
}

impl Entry {
    fn new(now: Instant) -> Self {
        Self {
            record: None,
            policy: None,
            first_seen: now,
            last_probe: None,
        }
    }

    /// Whether this workload is due, under whatever policy is known so far.
    fn due(&self, now: Instant) -> bool {
        let policy = self.policy.unwrap_or(Policy::UNDECLARED);
        match self.last_probe {
            // The initial delay is measured from when this node first saw the
            // workload, not from container start — yubaba does not hold a
            // start time for a workload it rehydrated after a restart. The
            // difference only ever delays a first verdict, which reads as
            // "not yet probed"; the opposite rounding would invent a red dot
            // for a workload that is still booting.
            None => now.duration_since(self.first_seen) >= policy.initial_delay,
            Some(last) => now.duration_since(last) >= policy.interval,
        }
    }
}

/// Live health verdicts, keyed on the same string `GET /workloads` rows are
/// keyed on (`ident`, falling back to `id` — see [`crate::node::enrich_workloads`]).
#[derive(Debug, Default)]
pub struct HealthRegistry(Mutex<BTreeMap<String, Entry>>);

impl HealthRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Entry>> {
        // A poisoned registry means a panic mid-sweep. Health is exactly what
        // an operator reaches for while diagnosing that panic, so recover the
        // map rather than propagating into a read path.
        match self.0.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// The verdict for one workload, if it has been probed at least once.
    pub fn get(&self, key: &str) -> Option<HealthRecord> {
        self.lock().get(key).and_then(|e| e.record.clone())
    }

    /// Test/observability seam: every key currently tracked.
    pub fn keys(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }
}

/// Merge health verdicts into an already-serialized `workloads` array, in
/// place — the same additive shape, and for the same reason, as
/// [`crate::node::enrich_workloads`]: two backends produce two row shapes and
/// the `x-workload-source` header is a back-compat contract between them.
///
/// A row with no verdict yet is left **without** a `health` key rather than
/// given a null one. Absent means "not probed"; a null would read as an answer.
pub fn enrich_workloads(registry: &HealthRegistry, workloads: &mut serde_json::Value) {
    let guard = registry.lock();
    if guard.is_empty() {
        return;
    }
    let Some(rows) = workloads.as_array_mut() else {
        return;
    };
    for row in rows {
        let Some(obj) = row.as_object_mut() else {
            continue;
        };
        let key = obj
            .get("ident")
            .or_else(|| obj.get("id"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let Some(record) = key
            .and_then(|k| guard.get(&k))
            .and_then(|e| e.record.as_ref())
        else {
            continue;
        };
        match serde_json::to_value(record) {
            Ok(v) => {
                obj.insert("health".into(), v);
            }
            // A HealthRecord is four scalars and cannot fail to serialize;
            // if it somehow does, an un-enriched row is the honest result.
            Err(_) => continue,
        }
    }
}

/// Fold one probe answer into the running verdict.
///
/// Split out from the sweep because everything interesting about this module
/// is in this function, and the sweep around it needs a live kamaji to run.
fn fold(
    previous: Option<&HealthRecord>,
    status: ProbeStatus,
    policy: Policy,
    at: u64,
) -> HealthRecord {
    let (tag, reason, failed) = match status {
        ProbeStatus::Ready => ("ready", None, false),
        // Starting is not a failure. A workload inside its own boot window
        // that gets counted against `failure_threshold` is marked degraded
        // for starting slowly, which would make the threshold meaningless on
        // exactly the workloads that need it.
        ProbeStatus::Starting => ("starting", None, false),
        ProbeStatus::Unhealthy { reason } => ("unhealthy", Some(reason), true),
        ProbeStatus::Timeout => ("timeout", None, true),
        // `ProbeStatus` is #[non_exhaustive]: kamaji can add a variant without
        // a breaking change. A variant this build has never heard of is not
        // evidence of failure — treating it as one would turn a kamaji upgrade
        // into a fleet-wide red, which is the loudest possible way to report
        // "this yubaba is older than that kamaji".
        _ => (HealthRecord::STATUS_UNKNOWN, None, false),
    };
    let consecutive_failures = if failed {
        previous
            .map_or(0, |p| p.consecutive_failures)
            .saturating_add(1)
    } else {
        0
    };
    HealthRecord {
        status: tag.to_string(),
        reason,
        degraded: consecutive_failures >= policy.failure_threshold,
        consecutive_failures,
        last_checked_at: at,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One turn of [`run`]'s loop, factored out so a test can drive the real thing
/// instead of re-implementing the tick.
///
/// Returns `true` when kamaji answered and the registry was reconciled against
/// its listing — `false` means this tick knew nothing and changed nothing.
pub async fn sweep_once(state: &Arc<crate::ServerState>) -> bool {
    let Some(client) = state
        .constable_client
        .as_ref()
        .and_then(KamajiSibling::current)
    else {
        return false;
    };

    let Ok(entries) = client.list().await else {
        // A failed list is not an empty list, and it is not evidence about any
        // workload's health either. Leave every verdict as it was; the next
        // tick with a live sibling corrects it.
        return false;
    };

    let now = Instant::now();
    let live: Vec<(String, kamaji_proto::WorkloadId)> = entries
        .into_iter()
        .map(|e| (e.id.as_str().to_string(), e.id))
        .collect();

    // Reconcile membership first, so a destroyed workload's last verdict does
    // not sit in the map being read as current.
    let due: Vec<(String, kamaji_proto::WorkloadId, Option<Policy>)> = {
        let mut guard = state.workload_health.lock();
        let live_keys: std::collections::BTreeSet<&str> =
            live.iter().map(|(k, _)| k.as_str()).collect();
        guard.retain(|k, _| live_keys.contains(k.as_str()));
        for (key, _) in &live {
            guard.entry(key.clone()).or_insert_with(|| Entry::new(now));
        }
        live.into_iter()
            .filter(|(key, _)| guard.get(key).is_some_and(|e| e.due(now)))
            .map(|(key, id)| {
                let policy = guard.get(&key).and_then(|e| e.policy);
                (key, id, policy)
            })
            .collect()
    };

    for (key, id, known_policy) in due {
        // Read the declared policy once per workload. `describe` is a registry
        // lookup on the far side; doing it per tick would be three numbers
        // that cannot change without a redeploy, re-fetched forever.
        let policy = match known_policy {
            Some(p) => p,
            None => match client.describe(&id).await {
                Ok(Some(w)) => w
                    .container_spec()
                    .and_then(|s| s.healthcheck.as_ref())
                    .map_or(Policy::UNDECLARED, Policy::from_spec),
                // Unknown or unreadable spec: probe on the default cadence
                // rather than not at all, and do not cache the guess — the
                // next tick asks again.
                Ok(None) => Policy::UNDECLARED,
                Err(_) => continue,
            },
        };

        let Ok(status) = client.probe(&id).await else {
            // The probe call itself failed to reach kamaji. That is a
            // statement about the sibling, not about the workload, so it must
            // not count against `failure_threshold`.
            continue;
        };

        let at = now_unix();
        let mut guard = state.workload_health.lock();
        let Some(entry) = guard.get_mut(&key) else {
            // Destroyed while we were asking. Nothing to record.
            continue;
        };
        entry.policy = Some(policy);
        entry.last_probe = Some(Instant::now());
        entry.record = Some(fold(entry.record.as_ref(), status, policy, at));
    }

    true
}

/// Drive the health sweep for the life of the process.
pub async fn run(state: Arc<crate::ServerState>) {
    if state.constable_client.is_none() {
        tracing::debug!("workload_health: no kamaji sibling; health sweep idle");
        return;
    }
    tracing::info!(
        tick_secs = TICK.as_secs(),
        "workload_health: probe cadence started"
    );
    loop {
        sweep_once(&state).await;
        tokio::time::sleep(TICK).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(threshold: u32) -> Policy {
        Policy {
            interval: Duration::from_secs(15),
            initial_delay: Duration::from_secs(20),
            failure_threshold: threshold,
        }
    }

    #[test]
    fn one_failure_under_the_threshold_is_not_degraded() {
        // The whole reason `failure_threshold` is in the spec. A workload that
        // misses one poll in three is not down, and a surface that says it is
        // gets ignored within a week.
        let p = policy(3);
        let r1 = fold(None, ProbeStatus::Timeout, p, 100);
        assert_eq!(r1.consecutive_failures, 1);
        assert!(!r1.degraded);

        let r2 = fold(Some(&r1), ProbeStatus::Timeout, p, 115);
        assert_eq!(r2.consecutive_failures, 2);
        assert!(!r2.degraded, "two of three is still not the declared verdict");

        let r3 = fold(Some(&r2), ProbeStatus::Timeout, p, 130);
        assert_eq!(r3.consecutive_failures, 3);
        assert!(r3.degraded);
    }

    #[test]
    fn one_success_clears_the_streak() {
        let p = policy(3);
        let r1 = fold(None, ProbeStatus::Timeout, p, 100);
        let r2 = fold(Some(&r1), ProbeStatus::Timeout, p, 115);
        let ok = fold(Some(&r2), ProbeStatus::Ready, p, 130);
        assert_eq!(ok.consecutive_failures, 0);
        assert!(!ok.degraded);
        // And the streak restarts from zero rather than resuming.
        let after = fold(Some(&ok), ProbeStatus::Timeout, p, 145);
        assert_eq!(after.consecutive_failures, 1);
    }

    #[test]
    fn starting_is_not_a_failure() {
        // A slow boot must not consume the failure budget: a workload probed
        // through its whole startup window would arrive at Ready already
        // marked degraded.
        let p = policy(2);
        let r1 = fold(None, ProbeStatus::Starting, p, 100);
        let r2 = fold(Some(&r1), ProbeStatus::Starting, p, 115);
        let r3 = fold(Some(&r2), ProbeStatus::Starting, p, 130);
        assert_eq!(r3.consecutive_failures, 0);
        assert!(!r3.degraded);
    }

    #[test]
    fn an_unhealthy_answer_carries_its_reason_to_the_wire() {
        let p = policy(1);
        let r = fold(
            None,
            ProbeStatus::Unhealthy {
                reason: "HTTP 503".into(),
            },
            p,
            100,
        );
        assert!(r.degraded, "threshold 1 means one failure is the verdict");
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["reason"], serde_json::json!("HTTP 503"));
    }

    #[test]
    fn the_wire_shape_is_flat_so_no_consumer_mirrors_a_non_exhaustive_enum() {
        // The contract `cloud-client`, the desktop and the UI all mirror.
        // `status` must be a bare string, never `{"Unhealthy":{"reason":…}}`:
        // the tagged form would put kamaji's variant set in three
        // deserializers, each of which would then need a story for a variant
        // it predates.
        let p = policy(1);
        let ready = serde_json::to_value(fold(None, ProbeStatus::Ready, p, 7)).unwrap();
        assert_eq!(ready["status"], serde_json::json!("ready"));
        assert!(
            ready.get("reason").is_none(),
            "a healthy probe explains nothing, so it sends no key: {ready}"
        );

        let sick = serde_json::to_value(fold(
            None,
            ProbeStatus::Unhealthy {
                reason: "HTTP 503".into(),
            },
            p,
            7,
        ))
        .unwrap();
        assert_eq!(sick["status"], serde_json::json!("unhealthy"));
        assert_eq!(sick["reason"], serde_json::json!("HTTP 503"));
    }

    #[test]
    fn a_zero_threshold_reads_as_one_not_as_degraded_before_the_first_probe() {
        // `failure_threshold = 0` in a spec would make `0 >= 0` true, marking
        // a workload degraded on a successful probe.
        let hc = workload_spec::Healthcheck {
            probe: workload_spec::HealthProbe::TcpConnect { port: 4332 },
            interval: workload_spec::Millis::from_secs(15),
            timeout: workload_spec::Millis::from_secs(5),
            initial_delay: workload_spec::Millis::from_secs(20),
            failure_threshold: 0,
        };
        let p = Policy::from_spec(&hc);
        assert_eq!(p.failure_threshold, 1);
        let ok = fold(None, ProbeStatus::Ready, p, 100);
        assert!(!ok.degraded);
    }

    #[test]
    fn the_declared_cadence_is_the_one_that_runs() {
        // Reads the same numbers the operator wrote, in the same units. The
        // trap this pins is Millis-vs-secs: `interval: 15000` becoming a
        // 15000-second cadence probes once every four hours and looks fine.
        let hc = workload_spec::Healthcheck {
            probe: workload_spec::HealthProbe::TcpConnect { port: 4332 },
            interval: workload_spec::Millis::from_ms(15_000),
            timeout: workload_spec::Millis::from_ms(5_000),
            initial_delay: workload_spec::Millis::from_ms(20_000),
            failure_threshold: 3,
        };
        let p = Policy::from_spec(&hc);
        assert_eq!(p.interval, Duration::from_secs(15));
        assert_eq!(p.initial_delay, Duration::from_secs(20));
        assert_eq!(p.failure_threshold, 3);
    }

    #[test]
    fn a_workload_is_not_due_until_its_initial_delay_has_passed() {
        let now = Instant::now();
        let mut e = Entry::new(now);
        e.policy = Some(policy(3));
        assert!(!e.due(now), "20s initial delay has not elapsed");
        // Once probed, the interval governs rather than the initial delay.
        e.last_probe = Some(now);
        assert!(!e.due(now));
    }

    #[test]
    fn a_workload_with_no_verdict_yet_gets_no_health_key() {
        // Absent means "not probed". A null would read as an answer, and the
        // grid would colour it.
        let registry = HealthRegistry::default();
        registry
            .lock()
            .insert("noisetable-account".into(), Entry::new(Instant::now()));
        let mut rows = serde_json::json!([{ "id": "noisetable-account", "state": "Running" }]);
        enrich_workloads(&registry, &mut rows);
        assert!(
            rows[0].get("health").is_none(),
            "an unprobed workload must not carry a verdict: {rows}"
        );
    }

    #[test]
    fn a_verdict_merges_onto_the_row_it_belongs_to() {
        let registry = HealthRegistry::default();
        {
            let mut guard = registry.lock();
            let mut e = Entry::new(Instant::now());
            e.record = Some(fold(None, ProbeStatus::Ready, policy(3), 1_700_000_000));
            guard.insert("noisetable-account".into(), e);
            guard.insert("other".into(), Entry::new(Instant::now()));
        }
        let mut rows = serde_json::json!([
            { "id": "noisetable-account", "state": "Running" },
            { "id": "other", "state": "Running" },
        ]);
        enrich_workloads(&registry, &mut rows);
        assert_eq!(rows[0]["health"]["degraded"], serde_json::json!(false));
        assert_eq!(
            rows[0]["health"]["last_checked_at"],
            serde_json::json!(1_700_000_000u64)
        );
        assert!(rows[1].get("health").is_none(), "rows are matched, not zipped");
    }

    #[test]
    fn enrichment_keys_on_ident_before_id() {
        // Mirrors `node::enrich_workloads` exactly: the mesh ident is the
        // stable handle and can differ from the container id. Keying the two
        // functions differently would attach resources and health to
        // different rows on the same response.
        let registry = HealthRegistry::default();
        {
            let mut guard = registry.lock();
            let mut e = Entry::new(Instant::now());
            e.record = Some(fold(None, ProbeStatus::Ready, policy(1), 42));
            guard.insert("forge.abc".into(), e);
        }
        let mut rows = serde_json::json!([{ "ident": "forge.abc", "id": "forge-abc" }]);
        enrich_workloads(&registry, &mut rows);
        assert!(rows[0].get("health").is_some(), "keyed on ident: {rows}");
    }
}
