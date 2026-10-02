//! Cluster floaters (R936-B12): a workload whose placement belongs to the
//! cluster, re-homed off a dead node with no human touch.
//!
//! # Built on the tenant layer, not beside it
//!
//! yubaba already had every placement primitive a floater needs, and none of
//! them was wired to a workload:
//!
//! - **Who runs it** is a raft tenant ([`crate::raft::TenantOwnership`]), keyed
//!   [`tenant_for`]. `ClaimTenant` places it, `RenewTenantLease` keeps it, and
//!   the fencing epoch makes a mid-failover double-place impossible.
//! - **Moving it off a dead node** is [`crate::scheduler`]'s job, unchanged: it
//!   already transfers any tenant whose owner the lease channel confirms
//!   `Down`. On the fleet profile that is `down_after` 5s plus a 5s confirm
//!   dwell, well inside a one-minute budget.
//!
//! What was missing is the **effector**: nothing turned "node N owns tenant T"
//! into "workload T runs on node N, and nowhere else". That is this module.
//!
//! # Every member holds the spec
//!
//! A re-home happens precisely when the node that admitted the workload is
//! gone, so the spec cannot live only there. Admission records it on every raft
//! member ([`FloaterRecords`], one 0600 file per ident, the same shape kamaji's
//! deploy records use) and the owner re-publishes its records to its peers
//! every [`REPUBLISH_EVERY_TICKS`], so a member that was down at admission
//! catches up on its own. The raft log carries only the tenant record, never
//! the spec, so this needs no state-machine or protocol change.
//!
//! # The effector is a loop on every node, and it only converges
//!
//! Each [`TICK`], every node reads its own applied state and, per recorded
//! floater, runs [`decide`]: the owner starts a missing copy and renews its
//! lease; a non-owner stops any copy it holds (that is what stops a returning
//! node from double-serving); a vacant or lease-expired tenant is claimed. A
//! failed action is retried on the next tick; there is no other state.
//!
//! Stateful floaters need nothing extra here. Their spec's `[durability]`
//! block makes kamaji hydrate the volume from the store before the workload
//! starts, on whichever node the deploy lands (R858-F17 / R936-B2).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use workload_spec::TenantId;

use crate::raft::{TenantOutcome, TenantOwnership, YubabaNodeId, YubabaRequest, YubabaResponse};

/// Lease a floater's owner holds. Matches the scheduler's transfer lease.
pub const FLOATER_LEASE_SECS: u64 = 300;

/// Renew once the remaining lease drops below this. Half the lease, so a
/// single missed renewal never lets it lapse.
pub const RENEW_BELOW_SECS: u64 = FLOATER_LEASE_SECS / 2;

/// How often every node reconciles its floaters.
pub const TICK: Duration = Duration::from_secs(2);

/// The owner re-publishes its records to every peer this often (in ticks).
pub const REPUBLISH_EVERY_TICKS: u64 = 30;

/// A record admitted through this node's API is left alone by the effector for
/// this long, so the admitting deploy and the effector never race for the
/// ident's deploy lock. Records received from a peer carry no grace.
pub const ADMIT_GRACE_SECS: u64 = 20;

/// The raft tenant that carries floater `ident`'s placement. Namespaced so a
/// floater can never alias a tenant-streamer tenant.
pub fn tenant_for(ident: &str) -> TenantId {
    TenantId(format!("float/{ident}"))
}

/// One floater's spec, as admitted: the `POST /workloads/deploy` body's
/// `spec`, secrets still as references (materialization happens per node at
/// deploy time).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FloaterRecord {
    pub ident: String,
    pub spec: serde_json::Value,
    /// Unix seconds this node admitted it through its own API, or `0` when it
    /// arrived from a peer. Only drives [`ADMIT_GRACE_SECS`].
    #[serde(default)]
    pub admitted_at: u64,
}

/// This node's copy of every floater spec, one file per ident.
#[derive(Debug, Clone)]
pub struct FloaterRecords {
    dir: PathBuf,
}

impl FloaterRecords {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, ident: &str) -> PathBuf {
        self.dir.join(format!("{ident}.json"))
    }

    /// Store `record`. A record whose spec is unchanged keeps its existing
    /// `admitted_at` unless the new one is a local admission, so a peer's
    /// periodic re-publish can never re-arm the grace window and delay a
    /// re-home.
    pub fn save(&self, record: &FloaterRecord) -> std::io::Result<()> {
        validate_ident(&record.ident)?;
        let mut to_write = record.clone();
        if let Some(existing) = self.get(&record.ident) {
            if existing.spec == record.spec && record.admitted_at == 0 {
                return Ok(());
            }
            if record.admitted_at == 0 {
                to_write.admitted_at = 0;
            }
        }
        create_private_dir(&self.dir)?;
        let bytes = serde_json::to_vec_pretty(&to_write).map_err(std::io::Error::other)?;
        let tmp = self.dir.join(format!(".{}.tmp", record.ident));
        write_private(&tmp, &bytes)?;
        std::fs::rename(&tmp, self.path(&record.ident))
    }

    pub fn get(&self, ident: &str) -> Option<FloaterRecord> {
        validate_ident(ident).ok()?;
        let bytes = std::fs::read(self.path(ident)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Forget `ident`. Absent is success.
    pub fn remove(&self, ident: &str) -> std::io::Result<()> {
        validate_ident(ident)?;
        match std::fs::remove_file(self.path(ident)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Every readable record. An unreadable file is skipped with a warning
    /// rather than failing the whole set: one corrupt record must not stop
    /// every other floater from being re-homed.
    pub fn list(&self) -> Vec<FloaterRecord> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut out: Vec<FloaterRecord> = entries
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.ends_with(".json") && !name.starts_with('.')
            })
            .filter_map(|e| {
                let path = e.path();
                match std::fs::read(&path)
                    .map_err(|e| e.to_string())
                    .and_then(|b| serde_json::from_slice::<FloaterRecord>(&b).map_err(|e| e.to_string()))
                {
                    Ok(r) => Some(r),
                    Err(e) => {
                        warn!(path = %path.display(), "floater: skipping unreadable record: {e}");
                        None
                    }
                }
            })
            .collect();
        out.sort_by(|a, b| a.ident.cmp(&b.ident));
        out
    }
}

/// An ident becomes a file name, so it is held to the mesh-ident alphabet.
fn validate_ident(ident: &str) -> std::io::Result<()> {
    let ok = !ident.is_empty()
        && ident.len() <= 128
        && !ident.starts_with('.')
        && ident
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("floater ident {ident:?} is not a valid mesh ident"),
        ))
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// What one node does about one floater on one tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloatAction {
    /// No owner, or the owner's lease lapsed: claim it for this node. The
    /// scheduler is the fast path off a dead owner; this is the backstop for a
    /// tenant the scheduler never judged (vacant, or no eligible candidate).
    Claim,
    /// This node owns it and runs no copy: start one.
    Run,
    /// This node owns it, runs it, and the lease is due for renewal.
    Renew { epoch: u64 },
    /// Another node owns it and this node still runs a copy: stop it.
    Stop,
    /// Converged.
    Hold,
}

/// What this node's runtime holds for one floater.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCopy {
    /// Nothing under this ident.
    Absent,
    /// Present but not `Running` — measured on prod 2026-09-22: after a
    /// reboot kamaji lists a container with no task as `Pending` and never
    /// starts it again. Present is not the same as serving.
    Dead,
    Running,
}

/// After a start attempt, an owner waits this long before trying again, so a
/// crash-looping spec is retried at a bounded rate rather than every tick.
pub const RESTART_BACKOFF_SECS: u64 = 30;

/// The whole effector policy, as arithmetic.
pub fn decide(
    me: YubabaNodeId,
    ownership: Option<&TenantOwnership>,
    local: LocalCopy,
    now: u64,
) -> FloatAction {
    match ownership {
        None => FloatAction::Claim,
        // Our own lease lapsed: any peer may claim it now, so re-claim (a
        // self-reclaim, which advances the epoch) before anything else.
        Some(o) if o.owner == me && !o.is_live(now) => FloatAction::Claim,
        Some(o) if o.owner == me => {
            if local != LocalCopy::Running {
                FloatAction::Run
            } else if o.lease_expires.saturating_sub(now) < RENEW_BELOW_SECS {
                FloatAction::Renew { epoch: o.epoch }
            } else {
                FloatAction::Hold
            }
        }
        Some(_) if local != LocalCopy::Absent => FloatAction::Stop,
        Some(o) if !o.is_live(now) => FloatAction::Claim,
        Some(_) => FloatAction::Hold,
    }
}

/// Everything the effector needs from a node, so [`tick`] is testable without
/// a cluster or a container runtime.
#[async_trait::async_trait]
pub trait FloatHost: Send + Sync {
    fn node_id(&self) -> YubabaNodeId;
    /// This node's applied view of the floater's tenant.
    fn ownership(&self, tenant: &TenantId) -> Option<TenantOwnership>;
    /// Every ident the local runtime holds, `true` when it is `Running`.
    /// `Err` means "could not look", which is never read as "nothing runs".
    async fn local_workloads(&self) -> anyhow::Result<BTreeMap<String, bool>>;
    /// Whether a deploy or destroy of `ident` is in flight on this node.
    fn busy(&self, ident: &str) -> bool;
    async fn run(&self, record: &FloaterRecord) -> anyhow::Result<()>;
    async fn stop(&self, ident: &str) -> anyhow::Result<()>;
    /// A raft write, forwarded to the leader when this node is a follower.
    async fn write(&self, req: YubabaRequest) -> anyhow::Result<YubabaResponse>;
    /// Push `record` to every other member. Best effort.
    async fn publish(&self, record: &FloaterRecord);
}

/// One reconcile pass over every recorded floater. Returns what was decided,
/// per ident, for logging and tests.
pub async fn tick(
    host: &dyn FloatHost,
    records: &[FloaterRecord],
    now: u64,
    republish: bool,
    started: &mut BTreeMap<String, u64>,
) -> Vec<(String, FloatAction)> {
    if records.is_empty() {
        return Vec::new();
    }
    let local = match host.local_workloads().await {
        Ok(r) => r,
        Err(e) => {
            warn!("floater: could not list local workloads, skipping this tick: {e}");
            return Vec::new();
        }
    };
    let me = host.node_id();
    let mut decided = Vec::with_capacity(records.len());
    for record in records {
        let ident = record.ident.as_str();
        if host.busy(ident) || now < record.admitted_at.saturating_add(ADMIT_GRACE_SECS) {
            continue;
        }
        let tenant = tenant_for(ident);
        let ownership = host.ownership(&tenant);
        let copy = match local.get(ident) {
            None => LocalCopy::Absent,
            Some(false) => LocalCopy::Dead,
            Some(true) => LocalCopy::Running,
        };
        let action = decide(me, ownership.as_ref(), copy, now);
        if action == FloatAction::Run
            && started
                .get(ident)
                .is_some_and(|at| now < at.saturating_add(RESTART_BACKOFF_SECS))
        {
            continue;
        }
        match &action {
            FloatAction::Hold => {}
            FloatAction::Claim => {
                let req = YubabaRequest::ClaimTenant {
                    tenant: tenant.clone(),
                    node: me,
                    lease_secs: FLOATER_LEASE_SECS,
                    now,
                };
                match host.write(req).await {
                    Ok(YubabaResponse::Tenant(TenantOutcome::Granted { epoch })) => {
                        info!(ident, node = me, epoch, "floater: claimed (vacant or lease lapsed)")
                    }
                    Ok(other) => debug!(ident, "floater: claim not granted: {other:?}"),
                    Err(e) => warn!(ident, "floater: claim failed, will retry: {e}"),
                }
            }
            FloatAction::Run => {
                started.insert(ident.to_string(), now);
                // FENCE BEFORE START. `ownership` is this node's APPLIED view,
                // which lags the leader right after a boot: measured
                // 2026-09-23, us-east-001 came back from a power-off still
                // applying epoch 1 (itself), started noisetable-account, and
                // its hydrate minted a store claim that fenced and killed the
                // real owner's copy on south. A renewal is linearized through
                // the leader and only granted to the current owner AT this
                // epoch, so a stale view gets `Fenced` here and starts nothing.
                let epoch = ownership.as_ref().map_or(0, |o| o.epoch);
                let confirm = YubabaRequest::RenewTenantLease {
                    tenant: tenant.clone(),
                    node: me,
                    epoch,
                    lease_secs: FLOATER_LEASE_SECS,
                    now,
                };
                match host.write(confirm).await {
                    Ok(YubabaResponse::Tenant(TenantOutcome::Granted { .. })) => {}
                    Ok(other) => {
                        warn!(ident, node = me, epoch, "floater: NOT starting — the leader says this node no longer owns it at this epoch ({other:?}); its applied view is stale");
                        decided.push((ident.to_string(), action));
                        continue;
                    }
                    Err(e) => {
                        warn!(ident, "floater: NOT starting — could not confirm ownership with the leader, will retry: {e}");
                        decided.push((ident.to_string(), action));
                        continue;
                    }
                }
                info!(ident, node = me, ?copy, epoch, "floater: this node owns it (confirmed by the leader) and runs no live copy — starting it");
                if let Err(e) = host.run(record).await {
                    warn!(ident, "floater: start failed, will retry next tick: {e:#}");
                }
            }
            FloatAction::Renew { epoch } => {
                let req = YubabaRequest::RenewTenantLease {
                    tenant: tenant.clone(),
                    node: me,
                    epoch: *epoch,
                    lease_secs: FLOATER_LEASE_SECS,
                    now,
                };
                if let Err(e) = host.write(req).await {
                    warn!(ident, "floater: lease renewal failed, will retry: {e}");
                }
            }
            FloatAction::Stop => {
                info!(
                    ident,
                    node = me,
                    owner = ?ownership.as_ref().map(|o| o.owner),
                    "floater: another node owns it — stopping this node's copy"
                );
                if let Err(e) = host.stop(ident).await {
                    warn!(ident, "floater: stop failed, will retry next tick: {e:#}");
                }
            }
        }
        if republish && ownership.as_ref().is_some_and(|o| o.owner == me) {
            host.publish(record).await;
        }
        decided.push((ident.to_string(), action));
    }
    decided
}

/// Run [`tick`] forever. Spawned on every raft member; a node with no records
/// does nothing but read a directory.
pub fn spawn(
    host: std::sync::Arc<dyn FloatHost>,
    records: FloaterRecords,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(dir = %records.dir().display(), "floater effector active (R936-B12)");
        let mut n: u64 = 0;
        let mut started = BTreeMap::new();
        loop {
            let list = records.list();
            let now = unix_now_secs();
            tick(host.as_ref(), &list, now, n % REPUBLISH_EVERY_TICKS == 0, &mut started).await;
            n = n.wrapping_add(1);
            tokio::time::sleep(TICK).await;
        }
    })
}

pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn own(owner: YubabaNodeId, epoch: u64, lease_expires: u64) -> TenantOwnership {
        TenantOwnership {
            owner,
            epoch,
            lease_expires,
        }
    }

    use LocalCopy::{Absent, Dead, Running};

    #[test]
    fn a_vacant_floater_is_claimed() {
        assert_eq!(decide(1, None, Absent, 1000), FloatAction::Claim);
    }

    #[test]
    fn the_owner_starts_a_missing_copy() {
        assert_eq!(decide(1, Some(&own(1, 3, 1300)), Absent, 1000), FloatAction::Run);
    }

    /// A container kamaji lists as `Pending` after a reboot is present but
    /// not serving; the owner must start it again, not hold on it forever.
    #[test]
    fn an_owner_whose_lease_lapsed_reclaims_before_anything_else() {
        assert_eq!(decide(1, Some(&own(1, 3, 999)), Running, 1000), FloatAction::Claim);
        assert_eq!(decide(1, Some(&own(1, 3, 999)), Absent, 1000), FloatAction::Claim);
    }

    #[test]
    fn the_owner_restarts_a_dead_copy() {
        assert_eq!(decide(1, Some(&own(1, 3, 1300)), Dead, 1000), FloatAction::Run);
    }

    #[test]
    fn the_owner_renews_only_once_the_lease_is_half_spent() {
        assert_eq!(decide(1, Some(&own(1, 3, 1300)), Running, 1000), FloatAction::Hold);
        assert_eq!(
            decide(1, Some(&own(1, 3, 1100)), Running, 1000),
            FloatAction::Renew { epoch: 3 }
        );
    }

    /// The double-serve guard: a node that comes back after its floater was
    /// re-homed stops its copy on its first tick, dead or alive.
    #[test]
    fn a_non_owner_stops_its_copy_even_while_the_owner_is_live() {
        assert_eq!(decide(1, Some(&own(2, 4, 1300)), Running, 1000), FloatAction::Stop);
        assert_eq!(decide(1, Some(&own(2, 4, 1300)), Dead, 1000), FloatAction::Stop);
    }

    #[test]
    fn a_non_owner_holds_while_the_owner_lease_is_live_and_claims_once_it_lapses() {
        assert_eq!(decide(1, Some(&own(2, 4, 1300)), Absent, 1000), FloatAction::Hold);
        assert_eq!(decide(1, Some(&own(2, 4, 999)), Absent, 1000), FloatAction::Claim);
    }

    #[test]
    fn records_round_trip_private_and_a_peer_republish_never_rearms_the_grace() {
        let tmp = tempfile::tempdir().unwrap();
        let recs = FloaterRecords::new(tmp.path().join("floaters"));
        let spec = serde_json::json!({"name": "acct"});
        recs.save(&FloaterRecord {
            ident: "acct".into(),
            spec: spec.clone(),
            admitted_at: 500,
        })
        .unwrap();
        // A peer's re-publish of the same spec leaves the local admission alone.
        recs.save(&FloaterRecord {
            ident: "acct".into(),
            spec: spec.clone(),
            admitted_at: 0,
        })
        .unwrap();
        assert_eq!(recs.get("acct").unwrap().admitted_at, 500);
        // A peer's CHANGED spec lands with no grace.
        recs.save(&FloaterRecord {
            ident: "acct".into(),
            spec: serde_json::json!({"name": "acct", "v": 2}),
            admitted_at: 0,
        })
        .unwrap();
        assert_eq!(recs.get("acct").unwrap().admitted_at, 0);
        assert_eq!(recs.list().len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(recs.dir()), 0o700);
            assert_eq!(mode(&recs.dir().join("acct.json")), 0o600);
        }
        recs.remove("acct").unwrap();
        recs.remove("acct").unwrap();
        assert!(recs.list().is_empty());
        assert!(recs.save(&FloaterRecord {
            ident: "../escape".into(),
            spec,
            admitted_at: 0,
        })
        .is_err());
    }

    /// A fake node: ownership is a shared "raft", writes apply to it directly.
    struct FakeNode {
        me: YubabaNodeId,
        raft: std::sync::Arc<Mutex<Option<TenantOwnership>>>,
        running: Mutex<BTreeMap<String, bool>>,
        list_fails: bool,
        log: Mutex<Vec<String>>,
        started: Mutex<BTreeMap<String, u64>>,
        stale_view: Mutex<Option<TenantOwnership>>,
    }

    impl FakeNode {
        fn new(me: YubabaNodeId, raft: std::sync::Arc<Mutex<Option<TenantOwnership>>>) -> Self {
            Self {
                me,
                raft,
                running: Mutex::new(BTreeMap::new()),
                list_fails: false,
                log: Mutex::new(Vec::new()),
                started: Mutex::new(BTreeMap::new()),
                stale_view: Mutex::new(None),
            }
        }
        fn is_running(&self, ident: &str) -> bool {
            self.running.lock().unwrap().get(ident) == Some(&true)
        }
        /// One tick with this node's own persistent restart-backoff memory.
        async fn tick(&self, records: &[FloaterRecord], now: u64, republish: bool) -> Vec<(String, FloatAction)> {
            let mut started = self.started.lock().unwrap().clone();
            let out = tick(self, records, now, republish, &mut started).await;
            *self.started.lock().unwrap() = started;
            out
        }
    }

    #[async_trait::async_trait]
    impl FloatHost for FakeNode {
        fn node_id(&self) -> YubabaNodeId {
            self.me
        }
        fn ownership(&self, _t: &TenantId) -> Option<TenantOwnership> {
            // A lagging applied view, when set, is what this node believes;
            // writes still land on the shared "leader" state.
            self.stale_view
                .lock()
                .unwrap()
                .clone()
                .or_else(|| self.raft.lock().unwrap().clone())
        }
        async fn local_workloads(&self) -> anyhow::Result<BTreeMap<String, bool>> {
            if self.list_fails {
                anyhow::bail!("kamaji unreachable");
            }
            Ok(self.running.lock().unwrap().clone())
        }
        fn busy(&self, _ident: &str) -> bool {
            false
        }
        async fn run(&self, r: &FloaterRecord) -> anyhow::Result<()> {
            self.running.lock().unwrap().insert(r.ident.clone(), true);
            self.log.lock().unwrap().push(format!("run {}", r.ident));
            Ok(())
        }
        async fn stop(&self, ident: &str) -> anyhow::Result<()> {
            self.running.lock().unwrap().remove(ident);
            self.log.lock().unwrap().push(format!("stop {ident}"));
            Ok(())
        }
        async fn write(&self, req: YubabaRequest) -> anyhow::Result<YubabaResponse> {
            let mut raft = self.raft.lock().unwrap();
            match req {
                YubabaRequest::ClaimTenant { node, lease_secs, now, .. } => {
                    if let Some(o) = raft.as_ref() {
                        if o.owner != node && o.is_live(now) {
                            return Ok(YubabaResponse::Tenant(TenantOutcome::Fenced {
                                current_epoch: o.epoch,
                                current_owner: Some(o.owner),
                            }));
                        }
                    }
                    let epoch = raft.as_ref().map_or(0, |o| o.epoch) + 1;
                    *raft = Some(own(node, epoch, now + lease_secs));
                    Ok(YubabaResponse::Tenant(TenantOutcome::Granted { epoch }))
                }
                // Same arms as raft `apply`: granted only to the owner at its epoch.
                YubabaRequest::RenewTenantLease { node, epoch, lease_secs, now, .. } => {
                    match raft.as_mut() {
                        Some(o) if o.owner == node && o.epoch == epoch => {
                            o.lease_expires = o.lease_expires.max(now + lease_secs);
                            Ok(YubabaResponse::Tenant(TenantOutcome::Granted { epoch }))
                        }
                        other => Ok(YubabaResponse::Tenant(TenantOutcome::Fenced {
                            current_epoch: other.as_ref().map_or(0, |o| o.epoch),
                            current_owner: other.as_ref().map(|o| o.owner),
                        })),
                    }
                }
                other => anyhow::bail!("unexpected write {other:?}"),
            }
        }
        async fn publish(&self, r: &FloaterRecord) {
            self.log.lock().unwrap().push(format!("publish {}", r.ident));
        }
    }

    fn rec(ident: &str) -> FloaterRecord {
        FloaterRecord {
            ident: ident.into(),
            spec: serde_json::json!({}),
            admitted_at: 0,
        }
    }

    /// The acceptance shape end to end over the effector: two nodes, the owner
    /// dies, the scheduler's transfer lands, the survivor starts it on its next
    /// tick, and the returning old owner stops its stale copy.
    #[tokio::test]
    async fn a_transfer_re_homes_the_floater_and_the_returning_node_does_not_double_serve() {
        let raft = std::sync::Arc::new(Mutex::new(None));
        let a = FakeNode::new(1, raft.clone());
        let b = FakeNode::new(2, raft.clone());
        let records = vec![rec("acct")];

        // First tick on A claims, second runs.
        a.tick(&records, 1000, false).await;
        assert_eq!(raft.lock().unwrap().as_ref().unwrap().owner, 1);
        a.tick(&records, 1002, false).await;
        assert!(a.is_running("acct"));
        // B holds: A's lease is live and B runs nothing.
        assert_eq!(b.tick(&records, 1002, false).await, vec![("acct".into(), FloatAction::Hold)]);
        assert!(!b.is_running("acct"));

        // A dies; the scheduler transfers to B (what TransferTenant commits).
        *raft.lock().unwrap() = Some(own(2, 2, 1010 + FLOATER_LEASE_SECS));
        b.tick(&records, 1010, false).await;
        assert!(b.is_running("acct"), "the new owner starts it on its next tick");

        // A comes back still holding its old copy and stops it.
        a.tick(&records, 1030, false).await;
        assert!(!a.is_running("acct"));
        assert_eq!(a.log.lock().unwrap().last().unwrap(), "stop acct");
        assert!(b.is_running("acct"));
    }

    /// The 2026-09-23 prod regression: a node back from a power-off still
    /// applies the pre-failover record naming itself. It must ask the leader
    /// before starting, and the leader's answer (moved on) must win.
    #[tokio::test]
    async fn a_returning_node_with_a_stale_view_does_not_start_the_floater() {
        let raft = std::sync::Arc::new(Mutex::new(Some(own(1, 2, 5000))));
        let east = FakeNode::new(3, raft.clone());
        *east.stale_view.lock().unwrap() = Some(own(3, 1, 5000));
        east.running.lock().unwrap().insert("acct".into(), false);
        east.tick(&[rec("acct")], 1000, false).await;
        assert!(
            !east.log.lock().unwrap().iter().any(|l| l == "run acct"),
            "a stale self-view must not start a copy: {:?}",
            east.log.lock().unwrap()
        );
        assert_eq!(raft.lock().unwrap().as_ref().unwrap().owner, 1, "the real owner is untouched");
    }

    /// The post-reboot owner: kamaji lists the floater `Pending`, so the owner
    /// starts it — once, then not again until the backoff elapses.
    #[tokio::test]
    async fn an_owner_restarts_a_dead_copy_at_a_bounded_rate() {
        let raft = std::sync::Arc::new(Mutex::new(Some(own(1, 1, 5000))));
        let a = FakeNode::new(1, raft);
        a.running.lock().unwrap().insert("acct".into(), false);
        // A start that does not take (the copy stays dead).
        a.tick(&[rec("acct")], 1000, false).await;
        a.running.lock().unwrap().insert("acct".into(), false);
        assert!(a.tick(&[rec("acct")], 1000 + RESTART_BACKOFF_SECS - 1, false).await.is_empty());
        a.tick(&[rec("acct")], 1000 + RESTART_BACKOFF_SECS, false).await;
        assert_eq!(
            a.log.lock().unwrap().iter().filter(|l| *l == "run acct").count(),
            2,
            "one start per backoff window"
        );
        assert!(a.is_running("acct"));
    }

    #[tokio::test]
    async fn an_unlistable_runtime_skips_the_tick_rather_than_reading_as_nothing_running() {
        let raft = std::sync::Arc::new(Mutex::new(Some(own(1, 1, 5000))));
        let mut a = FakeNode::new(1, raft);
        a.list_fails = true;
        assert!(a.tick(&[rec("acct")], 1000, false).await.is_empty());
        assert!(a.log.lock().unwrap().is_empty(), "no start was attempted blind");
    }

    #[tokio::test]
    async fn a_fresh_local_admission_is_left_to_the_admitting_deploy() {
        let raft = std::sync::Arc::new(Mutex::new(Some(own(1, 1, 5000))));
        let a = FakeNode::new(1, raft);
        let mut r = rec("acct");
        r.admitted_at = 1000;
        assert!(a.tick(&[r.clone()], 1000 + ADMIT_GRACE_SECS - 1, false).await.is_empty());
        a.tick(&[r], 1000 + ADMIT_GRACE_SECS, false).await;
        assert!(a.is_running("acct"));
    }

    #[tokio::test]
    async fn only_the_owner_republishes() {
        let raft = std::sync::Arc::new(Mutex::new(Some(own(1, 1, 5000))));
        let a = FakeNode::new(1, raft.clone());
        let b = FakeNode::new(2, raft);
        a.running.lock().unwrap().insert("acct".into(), true);
        a.tick(&[rec("acct")], 1000, true).await;
        b.tick(&[rec("acct")], 1000, true).await;
        assert!(a.log.lock().unwrap().contains(&"publish acct".to_string()));
        assert!(!b.log.lock().unwrap().iter().any(|l| l.starts_with("publish")));
    }
}
