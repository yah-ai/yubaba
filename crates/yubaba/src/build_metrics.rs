//! R1006-F14: what a node's grant table tells `placement.rank`, published as
//! usage metrics beside `relay.mounts.*` (W384 section 3 and 6).
//!
//! - `holder.dirs.<dir>.warm`: `true` while a live grant names the holder,
//!   `false` while its `target/<dir>/` still exists on the machine after the
//!   grant ended, absent once the dir is gone. The dir name is
//!   `workload_spec::holder_dir`'s, the same spelling the camp keys the ask on.
//!   Warmth-false comes from the directory, never from a Released record,
//!   which outlives the dir (retention).
//! - `build.grants.free` / `.limit` / `.free_memory_mb` / `.free_cpu_millis` /
//!   `.free_disk_mb`: the headroom `GrantTable::acquire` would compare against
//!   (the grant limit minus live grants; capacity minus live memory and cpu;
//!   disk minus every grant still counted until its bytes are deleted).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use workload_spec::holder_dir;

use crate::build_grants::{GrantTable, GrantView};
use crate::node::{MetricReport, MetricValue};

pub const SOURCE: &str = "yubaba-build-grants";

/// Metric key cap per source is 128 (node.rs); stay one under.
const MAX_KEYS: usize = 127;

/// Where a grant's `target/<dir>/` dirs live: the lease it binds into, else
/// its own lease dir (an outpost's standing lease).
fn base_of(v: &GrantView, lease_root: &Path) -> std::path::PathBuf {
    match &v.bound_into {
        Some(b) => lease_root.join(&b.lease_id).join(&b.path),
        None => lease_root.join(&v.id),
    }
}

/// `None` while the table has no capacity (`max_grants == 0`: grants not
/// initialised on this node): publishing `free: 0` there would make
/// `placement.rank` refuse a node that simply does not run grants yet.
pub fn report(table: &GrantTable, lease_root: &Path) -> Option<MetricReport> {
    if table.capacity().max_grants == 0 {
        return None;
    }
    let views = table.views();
    let cap = table.capacity();
    let live: Vec<&GrantView> = views.iter().filter(|v| v.state.is_live()).collect();
    let sub = |total: u32, used: u32| u64::from(total.saturating_sub(used));
    let mut metrics: BTreeMap<String, MetricValue> = BTreeMap::new();
    metrics.insert("build.grants.limit".into(), MetricValue::from(u64::from(cap.max_grants)));
    metrics.insert("build.grants.free".into(), MetricValue::from(sub(cap.max_grants, live.len() as u32)));
    metrics.insert(
        "build.grants.free_memory_mb".into(),
        MetricValue::from(sub(cap.memory_mb, live.iter().map(|v| v.needs.memory_mb).sum())),
    );
    metrics.insert(
        "build.grants.free_cpu_millis".into(),
        MetricValue::from(sub(cap.cpu_millis, live.iter().map(|v| v.needs.cpu_millis).sum())),
    );
    metrics.insert(
        "build.grants.free_disk_mb".into(),
        MetricValue::from(sub(cap.disk_mb, views.iter().map(|v| v.needs.disk_mb).sum())),
    );

    let live_dirs: BTreeSet<String> =
        live.iter().filter_map(|v| holder_dir::of_grant_holder(v.holder.ticket.as_deref(), v.holder.session.as_deref())).collect();
    let mut warm: BTreeMap<String, bool> = live_dirs.iter().map(|d| (d.clone(), true)).collect();
    let bases: BTreeSet<_> = views.iter().map(|v| base_of(v, lease_root)).collect();
    for base in bases {
        let Ok(rd) = std::fs::read_dir(base.join("target")) else { continue };
        for e in rd.filter_map(|e| e.ok()).filter(|e| e.path().is_dir()) {
            if let Some(name) = e.file_name().to_str() {
                warm.entry(name.to_string()).or_insert(false);
            }
        }
    }
    let room = MAX_KEYS.saturating_sub(metrics.len());
    // Live holders first when the cap bites: a live lease is the stronger signal.
    let mut dirs: Vec<(String, bool)> = warm.into_iter().collect();
    dirs.sort_by_key(|(_, w)| !*w);
    for (dir, w) in dirs.into_iter().take(room) {
        metrics.insert(holder_dir::warm_key(&dir), MetricValue::Bool(w));
    }
    Some(MetricReport { source: SOURCE.into(), metrics, ttl_ms: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_grants::{AcquireRequest, Capacity, Holder, Needs};
    use std::time::Instant;

    fn table() -> GrantTable {
        GrantTable::new(
            Capacity { memory_mb: 16_000, cpu_millis: 8_000, disk_mb: 100_000, max_grants: 3, arch: "x86_64".into(), deadline_enforced: true },
            1,
        )
    }

    fn req(ticket: &str) -> AcquireRequest {
        AcquireRequest {
            holder: Holder { camp: "yah".into(), session: Some("session:s".into()), ticket: Some(ticket.into()) },
            needs: Needs { memory_mb: 4_000, cpu_millis: 2_000, disk_mb: 1_000, ..Needs::default() },
            ..AcquireRequest::default()
        }
    }

    fn get(r: &MetricReport, k: &str) -> Option<MetricValue> {
        r.metrics.get(k).cloned()
    }

    #[test]
    fn a_live_grant_is_warm_true_a_released_one_with_its_dir_false_and_a_gone_dir_has_no_key() {
        let root = tempfile::tempdir().unwrap();
        let mut t = table();
        let now = Instant::now();
        let g = t.acquire(req("R1"), now).unwrap();
        std::fs::create_dir_all(root.path().join(&g.id).join("target").join("ticket-R1")).unwrap();
        let r = report(&t, root.path()).unwrap();
        assert_eq!(get(&r, "holder.dirs.ticket-R1.warm"), Some(MetricValue::Bool(true)));
        assert_eq!(get(&r, "build.grants.free"), Some(MetricValue::from(2u64)));
        assert_eq!(get(&r, "build.grants.free_memory_mb"), Some(MetricValue::from(12_000u64)));

        t.release(&g.id, g.epoch, "ok".into(), now).unwrap();
        let r = report(&t, root.path()).unwrap();
        assert_eq!(get(&r, "holder.dirs.ticket-R1.warm"), Some(MetricValue::Bool(false)), "dir exists after release");
        assert_eq!(get(&r, "build.grants.free"), Some(MetricValue::from(3u64)));

        std::fs::remove_dir_all(root.path().join(&g.id).join("target").join("ticket-R1")).unwrap();
        let r = report(&t, root.path()).unwrap();
        assert_eq!(get(&r, "holder.dirs.ticket-R1.warm"), None, "no dir, no live grant: no key");
    }

    #[test]
    fn a_table_without_capacity_publishes_nothing() {
        let root = tempfile::tempdir().unwrap();
        assert!(report(&GrantTable::new(Capacity::default(), 1), root.path()).is_none());
    }

    #[test]
    fn a_full_table_publishes_zero_free_grants() {
        let root = tempfile::tempdir().unwrap();
        let mut t = table();
        for i in 0..3 {
            t.acquire(req(&format!("R{i}")), Instant::now()).unwrap();
        }
        assert_eq!(get(&report(&t, root.path()).unwrap(), "build.grants.free"), Some(MetricValue::from(0u64)));
    }
}
