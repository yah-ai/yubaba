//! The machine's grant table (R1019-F3, W384 §2.2 / §2.3).
//!
//! Each machine's yubaba is the ledger for its own capacity. A grant is a
//! compare-and-reserve against this machine's committed sum, taken under one
//! lock, in arrival order, with no per-camp cap (W384 §6). Grants never enter
//! raft: a machine that dies takes its leases with it, which is correct,
//! because the work dies too. A restart rebuilds `Running` leases from
//! kamaji's List + Describe (the `lease_id` rides the supervised spec); a
//! `Granted` lease that never deployed is lost, its holder's next renewal
//! fails and the camp re-acquires.
//!
//! Everything here is pure over an injected [`Instant`]; the kamaji half is
//! the [`LeasedWorkloads`] trait so expiry and rehydration test without a
//! socket.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// W384 open question 1. A crashed camp's slot comes back within this; a
/// renewal every TTL/3 rides out a slow wake. Overridable at acquire.
pub const DEFAULT_TTL: Duration = Duration::from_secs(90);
pub const MIN_TTL: Duration = Duration::from_secs(15);
pub const MAX_TTL: Duration = Duration::from_secs(15 * 60);
/// Hard runtime cap when the acquire names none, by verb (W384 OQ1).
pub const DEFAULT_DEADLINE_CHECK: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_DEADLINE_TEST: Duration = Duration::from_secs(60 * 60);
pub const DEFAULT_DEADLINE_ETUDE: Duration = Duration::from_secs(90 * 60);
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(45 * 60);
pub const MAX_DEADLINE: Duration = Duration::from_secs(4 * 60 * 60);

/// W384 §2.4 / open question 6 (R1019-F5): how long a terminal lease keeps its
/// bytes (the lease dir and the workload's produced dir) before the machine
/// deletes them, fetched or not. An attached caller fetches within seconds of
/// exit, so an hour is generous for one that is slow or briefly asleep, and short
/// enough that a dead caller's outputs stop counting against `disk_mb` the same
/// morning. Retained bytes count against the machine's `disk_mb` until deletion.
pub const OUTPUT_RETENTION: Duration = Duration::from_secs(60 * 60);

const LEASE_ID_PREFIX: &str = "lease-";

/// R1019-F21: each lease's machine-local directory is
/// `<LEASE_HOST_ROOT>/<lease id>/`. An outpost's standing lease keeps its kache
/// `store/` and `target/<holder>/` dirs there; a build lease binds one path
/// under it (W384 §3.1).
pub const LEASE_HOST_ROOT: &str = workload_spec::lease_dir::HOST_ROOT;

/// R1019-F9: the grant's `disk_mb`, stamped on a leased spec at bind so a
/// rehydrated lease keeps counting its disk. A spec's resources carry memory
/// and CPU but no disk, so without this a restart forgot an outpost's store.
pub const LEASE_DISK_MB_ANNOTATION: &str = "yah.lease.disk-mb";

pub fn lease_host_dir(lease_id: &str) -> std::path::PathBuf {
    workload_spec::lease_dir::host_dir(lease_id)
}

/// R1019-F21: a build lease's bind into another lease of the same camp on
/// this machine. `path` is relative to that lease's dir and names ONE parent
/// holding both `store/` and `target/<holder>/`: two binds put the store and
/// the target dir on separate mounts, and `link(2)` across mounts is `EXDEV`,
/// so every kache hardlink restore would become a copy (W384 §3.1, R1019-S19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bind {
    pub lease_id: String,
    #[serde(default)]
    pub path: String,
}

impl Bind {
    pub fn host_path(&self) -> std::path::PathBuf {
        lease_host_dir(&self.lease_id).join(&self.path)
    }
}

fn bind_path_ok(path: &str) -> bool {
    let p = std::path::Path::new(path);
    !p.is_absolute()
        && p.components().all(|c| matches!(c, std::path::Component::Normal(_)))
}

/// The default deadline for a verb (`check`, `test`, `etude`; anything else
/// gets [`DEFAULT_DEADLINE`]).
pub fn default_deadline_for(verb: Option<&str>) -> Duration {
    match verb {
        Some("check") => DEFAULT_DEADLINE_CHECK,
        Some("test") => DEFAULT_DEADLINE_TEST,
        Some("etude") | Some("étude") => DEFAULT_DEADLINE_ETUDE,
        _ => DEFAULT_DEADLINE,
    }
}

/// The lease id carries its epoch, so a spec's `lease_id` alone names both
/// the grant and its fence token, and rehydration recovers the epoch from it.
pub fn lease_id_for(epoch: u64) -> String {
    format!("{LEASE_ID_PREFIX}{epoch}")
}

pub fn epoch_of(lease_id: &str) -> Option<u64> {
    lease_id.strip_prefix(LEASE_ID_PREFIX)?.parse().ok()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holder {
    pub camp: String,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub ticket: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Needs {
    pub memory_mb: u32,
    pub cpu_millis: u32,
    #[serde(default)]
    pub disk_mb: u32,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GrantState {
    Granted,
    Running { ident: String },
    Released { outcome: String },
    Expired { reason: String },
}

impl GrantState {
    pub fn is_live(&self) -> bool {
        matches!(self, GrantState::Granted | GrantState::Running { .. })
    }
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub id: String,
    pub epoch: u64,
    pub holder: Holder,
    pub needs: Needs,
    pub ttl: Duration,
    pub deadline: Duration,
    pub state: GrantState,
    pub renewed_at: Instant,
    /// R1019-F21: the lease this one binds a path out of. Its bytes count
    /// against that lease's `disk_mb`, and it dies with that lease.
    pub bound_into: Option<Bind>,
    /// R1019-F20: a standing lease (an outpost's, W384 §3). Only its renewals
    /// hold it: it has no deadline, and it takes no build slot.
    pub standing: bool,
    /// When the grant went `Running`. Absence from kamaji's listing within
    /// [`BIND_GRACE`] of this is a deploy still in flight, not a teardown.
    pub bound_at: Option<Instant>,
    /// The workload ident the grant was bound to, kept past the terminal state
    /// so retention can find that workload's produced dir.
    pub workload: Option<String>,
    /// When the grant went terminal; [`OUTPUT_RETENTION`] runs from here.
    pub ended_at: Option<Instant>,
}

impl Grant {
    fn end(&mut self, state: GrantState, now: Instant) {
        self.state = state;
        self.ended_at = Some(now);
    }
}

/// How long after a deploy binds its grant a workload may be missing from
/// kamaji's listing before the grant reads it as torn down.
pub const BIND_GRACE: Duration = Duration::from_secs(30);

/// One workload as kamaji lists it: `terminal` is the outcome it ended with,
/// `None` while it is live.
#[derive(Debug, Clone)]
pub struct Observed {
    pub ident: String,
    pub terminal: Option<String>,
}

/// What `GET /grants` and every grant verb answer with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantView {
    pub id: String,
    pub epoch: u64,
    pub holder: Holder,
    pub needs: Needs,
    pub ttl_ms: u64,
    pub deadline_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_into: Option<Bind>,
    /// R1019-F20: `deadline_ms` is 0 and means none.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub standing: bool,
    #[serde(flatten)]
    pub state: GrantState,
}

impl Grant {
    pub fn view(&self) -> GrantView {
        GrantView {
            id: self.id.clone(),
            epoch: self.epoch,
            holder: self.holder.clone(),
            needs: self.needs.clone(),
            ttl_ms: self.ttl.as_millis() as u64,
            deadline_ms: self.deadline.as_millis() as u64,
            bound_into: self.bound_into.clone(),
            standing: self.standing,
            state: self.state.clone(),
        }
    }
}

/// This machine's grantable capacity. Derived from the node probe at boot
/// (W384 §6: capacity is derived, never configured); `max_grants` is the
/// per-machine grant limit that replaces `CARGO_LANE_CONCURRENCY` here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capacity {
    pub memory_mb: u32,
    pub cpu_millis: u32,
    pub disk_mb: u32,
    pub max_grants: u32,
    pub arch: String,
    /// kamaji's `NodeCapabilities::deadline_enforced` (R1019-F2). Every lease
    /// carries a deadline (W384 §2.4 rule 3), so a machine whose kamaji would
    /// silently drop it grants nothing.
    pub deadline_enforced: bool,
}

/// `POST /grants` body.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AcquireRequest {
    pub holder: Holder,
    pub needs: Needs,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// `check` / `test` / `etude`, picks the default deadline.
    #[serde(default)]
    pub verb: Option<String>,
    /// R1019-F21: bind a path out of another live lease (an outpost's).
    #[serde(default)]
    pub bind: Option<Bind>,
    /// R1019-F20: a standing lease, the outpost's (W384 §3). Rule 3's deadline
    /// catches a stuck BUILD; an outpost is a cache its camp keeps renewing,
    /// so it gets none and only the TTL reclaims it. It is not a build, so it
    /// takes no slot of [`Capacity::max_grants`]; its memory, CPU and disk
    /// still count. `deadline_ms` / `verb` are ignored, and it may not bind.
    #[serde(default)]
    pub standing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "refused", rename_all = "snake_case")]
pub enum Refusal {
    DeadlineUnenforced,
    ArchMismatch { want: String, have: String },
    AtGrantLimit { limit: u32 },
    Insufficient { resource: &'static str, want: u32, free: u32 },
    InvalidTtl { ttl_ms: u64 },
    InvalidDeadline { deadline_ms: u64 },
    UnknownLease { id: String },
    StaleEpoch { id: String, epoch: u64, current: u64 },
    NotLive { id: String },
    BindUnknownLease { id: String },
    BindNotLive { id: String },
    BindForeignCamp { id: String },
    BindChained { id: String },
    InvalidBindPath { path: String },
    /// R1019-F20: a standing lease is what builds bind into, never a binder.
    StandingBind { id: String },
    /// The spec's binds under [`LEASE_HOST_ROOT`] are not what the grant allows.
    BindMismatch { detail: String },
}

/// One machine's grants. Hold it behind one mutex: the reserve is the
/// compare under that lock, so two concurrent acquires cannot both fit.
#[derive(Debug)]
pub struct GrantTable {
    capacity: Capacity,
    next_epoch: u64,
    grants: BTreeMap<String, Grant>,
}

impl GrantTable {
    /// `epoch_floor` seeds the fence counter (boot passes the unix-ms clock)
    /// so epochs keep increasing across a restart that kept no state.
    pub fn new(capacity: Capacity, epoch_floor: u64) -> Self {
        Self {
            capacity,
            next_epoch: epoch_floor.max(1),
            grants: BTreeMap::new(),
        }
    }

    pub fn capacity(&self) -> &Capacity {
        &self.capacity
    }

    pub fn set_capacity(&mut self, capacity: Capacity) {
        self.capacity = capacity;
    }

    pub fn views(&self) -> Vec<GrantView> {
        self.grants.values().map(Grant::view).collect()
    }

    pub fn get(&self, id: &str) -> Option<&Grant> {
        self.grants.get(id)
    }

    fn committed(&self) -> (u32, u32, u32, u32) {
        let live = self.grants.values().filter(|g| g.state.is_live());
        // The grant limit counts builds; a standing lease is not one.
        let (n, m, c, _) = live.fold((0, 0, 0, 0), |(n, m, c, d), g| {
            (n + u32::from(!g.standing), m + g.needs.memory_mb, c + g.needs.cpu_millis, d + g.needs.disk_mb)
        });
        // Disk is committed until the bytes are deleted, not until the lease
        // ends: a terminal grant stays in the table through its retention window.
        let d = self.grants.values().map(|g| g.needs.disk_mb).sum();
        (n, m, c, d)
    }

    pub fn acquire(&mut self, req: AcquireRequest, now: Instant) -> Result<GrantView, Refusal> {
        let cap = &self.capacity;
        if !cap.deadline_enforced {
            return Err(Refusal::DeadlineUnenforced);
        }
        if let Some(want) = &req.needs.arch {
            if want != &cap.arch {
                return Err(Refusal::ArchMismatch { want: want.clone(), have: cap.arch.clone() });
            }
        }
        // `needs.tags` is recorded, not checked: tag eligibility is
        // `admit_workload`'s, over the inventory (W384 §2.2).
        let ttl = match req.ttl_ms {
            None => DEFAULT_TTL,
            Some(ms) => {
                let ttl = Duration::from_millis(ms);
                if ttl < MIN_TTL || ttl > MAX_TTL {
                    return Err(Refusal::InvalidTtl { ttl_ms: ms });
                }
                ttl
            }
        };
        let deadline = match req.deadline_ms {
            _ if req.standing => Duration::ZERO,
            None => default_deadline_for(req.verb.as_deref()),
            Some(ms) => {
                let d = Duration::from_millis(ms);
                if d.is_zero() || d > MAX_DEADLINE {
                    return Err(Refusal::InvalidDeadline { deadline_ms: ms });
                }
                d
            }
        };
        if let Some(bind) = &req.bind {
            if req.standing {
                return Err(Refusal::StandingBind { id: bind.lease_id.clone() });
            }
            if !bind_path_ok(&bind.path) {
                return Err(Refusal::InvalidBindPath { path: bind.path.clone() });
            }
            let parent = self
                .grants
                .get(&bind.lease_id)
                .ok_or_else(|| Refusal::BindUnknownLease { id: bind.lease_id.clone() })?;
            if !parent.state.is_live() {
                return Err(Refusal::BindNotLive { id: bind.lease_id.clone() });
            }
            if parent.holder.camp != req.holder.camp {
                return Err(Refusal::BindForeignCamp { id: bind.lease_id.clone() });
            }
            if parent.bound_into.is_some() {
                return Err(Refusal::BindChained { id: bind.lease_id.clone() });
            }
        }
        let (n, mem, cpu, disk) = self.committed();
        if !req.standing && cap.max_grants > 0 && n >= cap.max_grants {
            return Err(Refusal::AtGrantLimit { limit: cap.max_grants });
        }
        for (resource, want, used, total) in [
            ("memory_mb", req.needs.memory_mb, mem, cap.memory_mb),
            ("cpu_millis", req.needs.cpu_millis, cpu, cap.cpu_millis),
            ("disk_mb", req.needs.disk_mb, disk, cap.disk_mb),
        ] {
            let free = total.saturating_sub(used);
            if want > free {
                return Err(Refusal::Insufficient { resource, want, free });
            }
        }
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        let grant = Grant {
            id: lease_id_for(epoch),
            epoch,
            holder: req.holder,
            needs: req.needs,
            ttl,
            deadline,
            state: GrantState::Granted,
            renewed_at: now,
            bound_into: req.bind,
            standing: req.standing,
            bound_at: None,
            workload: None,
            ended_at: None,
        };
        let view = grant.view();
        self.grants.insert(grant.id.clone(), grant);
        Ok(view)
    }

    fn live_mut(&mut self, id: &str, epoch: Option<u64>) -> Result<&mut Grant, Refusal> {
        let grant = self
            .grants
            .get_mut(id)
            .ok_or_else(|| Refusal::UnknownLease { id: id.to_string() })?;
        if let Some(epoch) = epoch {
            if epoch != grant.epoch {
                return Err(Refusal::StaleEpoch { id: id.to_string(), epoch, current: grant.epoch });
            }
        }
        if !grant.state.is_live() {
            return Err(Refusal::NotLive { id: id.to_string() });
        }
        Ok(grant)
    }

    pub fn renew(&mut self, id: &str, epoch: u64, now: Instant) -> Result<GrantView, Refusal> {
        let grant = self.live_mut(id, Some(epoch))?;
        grant.renewed_at = now;
        Ok(grant.view())
    }

    /// Close a live lease with the holder's outcome. Returns the view and,
    /// for a `Running` lease, the workload ident the caller should stop.
    pub fn release(
        &mut self,
        id: &str,
        epoch: u64,
        outcome: String,
        now: Instant,
    ) -> Result<(GrantView, Option<String>), Refusal> {
        let grant = self.live_mut(id, Some(epoch))?;
        let ident = match &grant.state {
            GrantState::Running { ident } => Some(ident.clone()),
            _ => None,
        };
        grant.end(GrantState::Released { outcome }, now);
        Ok((grant.view(), ident))
    }

    /// The deploy gate: a workload carrying `lease_id` must name a live grant
    /// on this machine (the id embeds the epoch, so a re-placed run's old id
    /// is refused). Moves the grant to `Running` and returns the deadline the
    /// spec must carry: `None` for a standing lease, whose workload kamaji
    /// never kills on the clock (R1019-F20).
    pub fn bind_deploy(&mut self, lease_id: &str, ident: &str, now: Instant) -> Result<Option<Duration>, Refusal> {
        let epoch = epoch_of(lease_id).ok_or_else(|| Refusal::UnknownLease { id: lease_id.into() })?;
        let grant = self.live_mut(lease_id, Some(epoch))?;
        if let GrantState::Running { ident: bound } = &grant.state {
            if bound != ident {
                return Err(Refusal::NotLive { id: lease_id.into() });
            }
        }
        if grant.state == GrantState::Granted {
            grant.state = GrantState::Running { ident: ident.to_string() };
            grant.bound_at = Some(now);
            grant.workload = Some(ident.to_string());
        }
        Ok((!grant.standing).then_some(grant.deadline))
    }

    /// The grant's `disk_mb`, for [`LEASE_DISK_MB_ANNOTATION`].
    pub fn disk_mb_of(&self, lease_id: &str) -> Option<u32> {
        self.grants.get(lease_id).map(|g| g.needs.disk_mb)
    }

    /// Whether `lease_id` is a live grant already bound to `ident`: the check
    /// every placement path makes before it runs a leased spec.
    pub fn is_bound(&self, lease_id: &str, ident: &str) -> bool {
        self.grants.get(lease_id).is_some_and(|g| {
            epoch_of(lease_id) == Some(g.epoch)
                && g.state == GrantState::Running { ident: ident.to_string() }
        })
    }

    /// Expire every live lease whose renewals stopped. Returns `(lease id,
    /// ident)` for each expired `Running` lease: the workloads to stop.
    pub fn expire(&mut self, now: Instant) -> Vec<(String, String)> {
        let mut stop = Vec::new();
        for grant in self.grants.values_mut() {
            if !grant.state.is_live() || now.saturating_duration_since(grant.renewed_at) < grant.ttl {
                continue;
            }
            if let GrantState::Running { ident } = &grant.state {
                stop.push((grant.id.clone(), ident.clone()));
            }
            grant.end(GrantState::Expired { reason: "renewals stopped".into() }, now);
        }
        stop.extend(self.cascade(now));
        stop
    }

    /// R1019-F21: a lease bound into one that is no longer live dies with it
    /// (its mount is gone). Returns `(lease id, ident)` to stop.
    fn cascade(&mut self, now: Instant) -> Vec<(String, String)> {
        let dead_parents: Vec<String> = self
            .grants
            .values()
            .filter_map(|g| g.bound_into.as_ref())
            .map(|b| b.lease_id.clone())
            .filter(|id| !self.grants.get(id).is_some_and(|p| p.state.is_live()))
            .collect();
        let mut stop = Vec::new();
        for grant in self.grants.values_mut() {
            let Some(bind) = &grant.bound_into else { continue };
            if !grant.state.is_live() || !dead_parents.contains(&bind.lease_id) {
                continue;
            }
            if let GrantState::Running { ident } = &grant.state {
                stop.push((grant.id.clone(), ident.clone()));
            }
            let reason = format!("bound lease {} ended", bind.lease_id);
            grant.end(GrantState::Expired { reason }, now);
        }
        stop
    }

    /// R1019-F21: the deploy-side mount check. Every bind a spec makes under
    /// [`LEASE_HOST_ROOT`] must be inside its own lease's dir, or be exactly
    /// the one granted cross-lease bind; an unleased spec may make none.
    pub fn check_lease_binds(
        &self,
        lease_id: Option<&str>,
        binds: &[std::path::PathBuf],
    ) -> Result<(), Refusal> {
        let root = std::path::Path::new(LEASE_HOST_ROOT);
        let granted = lease_id
            .and_then(|id| self.grants.get(id))
            .and_then(|g| g.bound_into.as_ref())
            .map(Bind::host_path);
        let own = lease_id.map(lease_host_dir);
        let mut cross = 0;
        for bind in binds.iter().filter(|b| b.starts_with(root)) {
            if own.as_ref().is_some_and(|own| bind.starts_with(own)) {
                continue;
            }
            if granted.as_ref() == Some(bind) {
                cross += 1;
                continue;
            }
            return Err(Refusal::BindMismatch {
                detail: format!("{} is not this lease's dir or its granted bind", bind.display()),
            });
        }
        if cross > 1 {
            return Err(Refusal::BindMismatch {
                detail: "the cross-lease bind must be one mount (EXDEV across mounts)".into(),
            });
        }
        Ok(())
    }

    /// Close every `Running` lease whose workload kamaji reports terminal
    /// (exit, failure, `OomKilled`, `DeadlineExceeded`) or no longer lists
    /// (torn down) — the reservation comes back without a release call.
    pub fn reconcile(&mut self, observed: &[Observed], now: Instant) -> Vec<String> {
        let mut closed = Vec::new();
        for grant in self.grants.values_mut() {
            let GrantState::Running { ident } = &grant.state else { continue };
            let outcome = match observed.iter().find(|o| &o.ident == ident) {
                Some(Observed { terminal: Some(outcome), .. }) => outcome.clone(),
                Some(_) => continue,
                None if grant
                    .bound_at
                    .is_some_and(|t| now.saturating_duration_since(t) < BIND_GRACE) =>
                {
                    continue
                }
                None => "torn down".to_string(),
            };
            closed.push(grant.id.clone());
            grant.end(GrantState::Released { outcome }, now);
        }
        closed
    }

    /// Terminal grants whose [`OUTPUT_RETENTION`] has passed: their bytes are
    /// due for deletion. They stay in the table (and keep counting against
    /// `disk_mb`) until [`forget`](Self::forget) is told the delete succeeded.
    pub fn due(&self, now: Instant) -> Vec<Retired> {
        self.grants
            .values()
            .filter(|g| g.ended_at.is_some_and(|t| now.saturating_duration_since(t) >= OUTPUT_RETENTION))
            .map(|g| Retired { lease_id: g.id.clone(), workload: g.workload.clone() })
            .collect()
    }

    /// Drop grants whose bytes are gone. From here the disk is free again.
    pub fn forget(&mut self, ids: &[String]) {
        self.grants.retain(|id, _| !ids.contains(id));
    }

    /// Whether a lease id has a record (live or retained).
    pub fn knows(&self, id: &str) -> bool {
        self.grants.contains_key(id)
    }

    /// Rebuild one `Running` lease from a workload kamaji supervises. The
    /// renewal window restarts at `now`, so a holder that is still alive
    /// keeps its lease and a dead one expires one TTL after boot.
    pub fn rehydrate(&mut self, found: RehydratedLease, now: Instant) -> bool {
        let Some(epoch) = epoch_of(&found.lease_id) else {
            return false;
        };
        self.next_epoch = self.next_epoch.max(epoch + 1);
        let grant = Grant {
            id: found.lease_id.clone(),
            epoch,
            holder: Holder::default(),
            needs: found.needs,
            ttl: DEFAULT_TTL,
            deadline: found.deadline.unwrap_or_default(),
            state: GrantState::Running { ident: found.ident.clone() },
            renewed_at: now,
            bound_into: found.bound_into,
            // A leased spec deployed without a deadline was a standing lease's
            // (`bind_deploy` writes one onto every other).
            standing: found.deadline.is_none(),
            bound_at: Some(now),
            workload: Some(found.ident),
            ended_at: None,
        };
        self.grants.insert(found.lease_id, grant);
        true
    }
}

/// A terminal lease whose retention window has passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retired {
    pub lease_id: String,
    pub workload: Option<String>,
}

/// R1019-F5: yubaba owns the lifecycle of a lease's host bytes. It makes
/// `<lease_root>/<id>/` at grant (before a deploy can bind it) and removes it,
/// with the workload's produced dir, once the lease is terminal and
/// [`OUTPUT_RETENTION`] has passed. The roots are fields so tests use a tempdir.
#[derive(Debug, Clone)]
pub struct LeaseDirs {
    lease_root: std::path::PathBuf,
    produced_root: std::path::PathBuf,
}

impl LeaseDirs {
    pub fn host() -> Self {
        Self::new(LEASE_HOST_ROOT.into(), workload_spec::forge_produced::HOST_ROOT.into())
    }

    pub fn new(lease_root: std::path::PathBuf, produced_root: std::path::PathBuf) -> Self {
        Self { lease_root, produced_root }
    }

    pub async fn create(&self, lease_id: &str) -> std::io::Result<()> {
        tokio::fs::create_dir_all(self.lease_root.join(lease_id)).await
    }

    /// Remove a lease's dir and its workload's produced dir. Absent is done.
    pub async fn remove(&self, retired: &Retired) -> std::io::Result<()> {
        let mut dirs = vec![self.lease_root.join(&retired.lease_id)];
        if let Some(forge_id) = retired.workload.as_deref().and_then(workload_spec::forge_produced::forge_id_from_ident) {
            dirs.push(self.produced_root.join(forge_id));
        }
        for dir in dirs {
            match tokio::fs::remove_dir_all(&dir).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Lease ids that have a dir under the root.
    async fn present(&self) -> std::io::Result<Vec<String>> {
        let mut found = Vec::new();
        let mut entries = match tokio::fs::read_dir(&self.lease_root).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
            Err(e) => return Err(e),
        };
        while let Some(entry) = entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str().filter(|n| epoch_of(n).is_some()) {
                found.push(name.to_string());
            }
        }
        Ok(found)
    }
}

/// Boot, after rehydration: a lease dir with no grant is an orphan (its lease
/// was a `Granted` that never deployed, or a terminal one the restart forgot)
/// and its bytes are removed. Only `lease-<epoch>` names are touched.
pub async fn remove_orphan_dirs(table: &std::sync::Mutex<GrantTable>, dirs: &LeaseDirs) -> Vec<String> {
    let present = match dirs.present().await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "orphan lease dirs: listing the lease root failed");
            return Vec::new();
        }
    };
    let orphans: Vec<String> = {
        let table = table.lock().unwrap_or_else(|p| p.into_inner());
        present.into_iter().filter(|id| !table.knows(id)).collect()
    };
    let mut removed = Vec::new();
    for lease_id in orphans {
        match dirs.remove(&Retired { lease_id: lease_id.clone(), workload: None }).await {
            Ok(()) => removed.push(lease_id),
            Err(e) => tracing::warn!(%lease_id, error = %e, "orphan lease dir: removal failed"),
        }
    }
    removed
}

/// A lease-carrying workload as kamaji reports it.
#[derive(Debug, Clone)]
pub struct RehydratedLease {
    pub ident: String,
    pub lease_id: String,
    pub needs: Needs,
    pub deadline: Option<Duration>,
    /// Recovered from the spec's one bind under [`LEASE_HOST_ROOT`] that is
    /// not its own dir, so the cascade survives a restart.
    pub bound_into: Option<Bind>,
}

impl RehydratedLease {
    pub fn from_spec(ident: String, spec: &workload_spec::WorkloadSpec) -> Option<Self> {
        Some(Self {
            ident,
            lease_id: spec.lease_id.clone()?,
            needs: Needs {
                memory_mb: spec.memory_request_mb(),
                cpu_millis: spec.resources.cpu_millis,
                disk_mb: spec.annotations.get(LEASE_DISK_MB_ANNOTATION).and_then(|v| v.parse().ok()).unwrap_or(0),
                ..Needs::default()
            },
            deadline: spec.deadline.map(|d| Duration::from_millis(d.0)),
            bound_into: bound_into_of(spec),
        })
    }
}

fn bound_into_of(spec: &workload_spec::WorkloadSpec) -> Option<Bind> {
    let own = lease_host_dir(spec.lease_id.as_deref()?);
    spec.volumes.iter().find_map(|v| {
        let workload_spec::VolumeSource::Bind { host_path } = &v.source else { return None };
        let rest = host_path.strip_prefix(LEASE_HOST_ROOT).ok()?;
        if host_path.starts_with(&own) {
            return None;
        }
        let mut parts = rest.components();
        let lease_id = parts.next()?.as_os_str().to_str()?.to_string();
        let path = parts.as_path().to_str()?.to_string();
        Some(Bind { lease_id, path })
    })
}

/// The kamaji half: what expiry stops and what boot rebuilds from.
#[async_trait::async_trait]
pub trait LeasedWorkloads: Send + Sync {
    /// Every supervised workload that carries a `lease_id`.
    async fn leased(&self) -> anyhow::Result<Vec<RehydratedLease>>;
    /// Every supervised workload with its terminal outcome, if it has one.
    async fn observed(&self) -> anyhow::Result<Vec<Observed>>;
    /// Tear one down.
    async fn stop(&self, ident: &str) -> anyhow::Result<()>;
}

/// Boot: rebuild `Running` leases. Returns how many were restored.
pub async fn rehydrate(
    table: &std::sync::Mutex<GrantTable>,
    kamaji: &dyn LeasedWorkloads,
    now: Instant,
) -> anyhow::Result<usize> {
    let found = kamaji.leased().await?;
    let mut table = table.lock().unwrap_or_else(|p| p.into_inner());
    Ok(found.into_iter().filter(|f| table.rehydrate(f.clone(), now)).count())
}

/// One sweep: close leases whose workloads ended, expire the ones whose
/// renewals stopped (under the lock), then stop those workloads outside it.
/// A failed listing skips the close step rather than reading as "all gone".
pub async fn sweep(
    table: &std::sync::Mutex<GrantTable>,
    kamaji: &dyn LeasedWorkloads,
    dirs: &LeaseDirs,
    now: Instant,
) -> Vec<String> {
    let observed = kamaji.observed().await;
    let stop = {
        let mut table = table.lock().unwrap_or_else(|p| p.into_inner());
        match &observed {
            Ok(observed) => {
                table.reconcile(observed, now);
            }
            Err(e) => tracing::warn!(error = %e, "grant sweep: kamaji List failed; not closing leases this tick"),
        }
        table.expire(now)
    };
    let due = table.lock().unwrap_or_else(|p| p.into_inner()).due(now);
    let mut deleted = Vec::new();
    for retired in due {
        match dirs.remove(&retired).await {
            Ok(()) => deleted.push(retired.lease_id),
            Err(e) => tracing::warn!(lease = %retired.lease_id, error = %e, "retention: deleting a terminal lease's bytes failed; still counted, retrying next sweep"),
        }
    }
    table.lock().unwrap_or_else(|p| p.into_inner()).forget(&deleted);
    let mut stopped = Vec::new();
    for (lease, ident) in stop {
        match kamaji.stop(&ident).await {
            Ok(()) => stopped.push(ident),
            Err(e) => tracing::error!(%lease, %ident, error = %e, "expired lease: stopping its workload failed"),
        }
    }
    stopped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn cap() -> Capacity {
        Capacity {
            memory_mb: 8_000,
            cpu_millis: 8_000,
            disk_mb: 50_000,
            max_grants: 4,
            arch: "x86_64".into(),
            deadline_enforced: true,
        }
    }

    fn req(memory_mb: u32) -> AcquireRequest {
        AcquireRequest {
            holder: Holder { camp: "yah".into(), ..Holder::default() },
            needs: Needs { memory_mb, cpu_millis: 1_000, ..Needs::default() },
            ..AcquireRequest::default()
        }
    }

    /// Roots that do not exist: removal of an absent dir is success.
    fn no_dirs() -> LeaseDirs {
        LeaseDirs::new("/nonexistent/leases".into(), "/nonexistent/produced".into())
    }

    #[derive(Default)]
    struct FakeKamaji {
        leased: Vec<RehydratedLease>,
        observed: Mutex<Vec<Observed>>,
        stopped: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl LeasedWorkloads for FakeKamaji {
        async fn leased(&self) -> anyhow::Result<Vec<RehydratedLease>> {
            Ok(self.leased.clone())
        }
        async fn observed(&self) -> anyhow::Result<Vec<Observed>> {
            Ok(self.observed.lock().unwrap().clone())
        }
        async fn stop(&self, ident: &str) -> anyhow::Result<()> {
            self.stopped.lock().unwrap().push(ident.to_string());
            Ok(())
        }
    }

    #[test]
    fn two_concurrent_grants_that_together_exceed_memory_one_wins() {
        let table = Arc::new(Mutex::new(GrantTable::new(cap(), 1)));
        let now = Instant::now();
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let table = Arc::clone(&table);
                std::thread::spawn(move || table.lock().unwrap().acquire(req(5_000), now))
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1, "{results:?}");
        assert!(results.iter().any(|r| matches!(
            r,
            Err(Refusal::Insufficient { resource: "memory_mb", want: 5_000, free: 3_000 })
        )));
    }

    #[test]
    fn a_node_that_cannot_enforce_deadlines_grants_nothing() {
        let mut table = GrantTable::new(Capacity { deadline_enforced: false, ..cap() }, 1);
        assert_eq!(table.acquire(req(1), Instant::now()), Err(Refusal::DeadlineUnenforced));
    }

    #[test]
    fn the_grant_limit_caps_concurrency_and_defaults_are_overridable() {
        let mut table = GrantTable::new(cap(), 1);
        let now = Instant::now();
        let first = table
            .acquire(AcquireRequest { ttl_ms: Some(30_000), deadline_ms: Some(600_000), ..req(1) }, now)
            .unwrap();
        assert_eq!((first.ttl_ms, first.deadline_ms), (30_000, 600_000));
        let test = table.acquire(AcquireRequest { verb: Some("test".into()), ..req(1) }, now).unwrap();
        assert_eq!(test.ttl_ms, DEFAULT_TTL.as_millis() as u64);
        assert_eq!(test.deadline_ms, DEFAULT_DEADLINE_TEST.as_millis() as u64);
        table.acquire(req(1), now).unwrap();
        table.acquire(req(1), now).unwrap();
        assert_eq!(table.acquire(req(1), now), Err(Refusal::AtGrantLimit { limit: 4 }));
    }

    #[test]
    fn deploy_must_name_a_live_grant_and_a_released_one_frees_capacity() {
        let mut table = GrantTable::new(cap(), 10);
        let now = Instant::now();
        let g = table.acquire(req(6_000), now).unwrap();
        assert!(matches!(table.bind_deploy("lease-999", "w", now), Err(Refusal::UnknownLease { .. })));
        assert_eq!(table.bind_deploy(&g.id, "w", now).unwrap(), Some(DEFAULT_DEADLINE));
        assert!(table.acquire(req(6_000), now).is_err());
        assert!(matches!(table.renew(&g.id, g.epoch + 1, now), Err(Refusal::StaleEpoch { .. })));
        let (_, ident) = table.release(&g.id, g.epoch, "success".into(), now).unwrap();
        assert_eq!(ident.as_deref(), Some("w"));
        assert!(table.acquire(req(6_000), now).is_ok());
    }

    #[tokio::test]
    async fn a_lease_whose_renewals_stop_expires_and_its_workload_is_torn_down() {
        let table = Mutex::new(GrantTable::new(cap(), 1));
        let t0 = Instant::now();
        let (live, dead) = {
            let mut t = table.lock().unwrap();
            let live = t.acquire(req(1_000), t0).unwrap();
            let dead = t.acquire(req(1_000), t0).unwrap();
            t.bind_deploy(&live.id, "renewed", t0).unwrap();
            t.bind_deploy(&dead.id, "abandoned", t0).unwrap();
            (live, dead)
        };
        let kamaji = FakeKamaji::default();
        *kamaji.observed.lock().unwrap() = ["renewed", "abandoned"]
            .map(|i| Observed { ident: i.into(), terminal: None })
            .to_vec();
        let t1 = t0 + Duration::from_secs(60);
        table.lock().unwrap().renew(&live.id, live.epoch, t1).unwrap();
        assert!(sweep(&table, &kamaji, &no_dirs(), t1).await.is_empty());
        let t2 = t0 + DEFAULT_TTL + Duration::from_secs(1);
        assert_eq!(sweep(&table, &kamaji, &no_dirs(), t2).await, vec!["abandoned".to_string()]);
        assert_eq!(*kamaji.stopped.lock().unwrap(), vec!["abandoned".to_string()]);
        let t = table.lock().unwrap();
        assert!(!t.get(&dead.id).unwrap().state.is_live(), "expired grant is retained, not live");
        assert!(t.get(&live.id).unwrap().state.is_live());
    }

    #[tokio::test]
    async fn a_workload_that_completes_frees_its_grant_without_a_release_call() {
        let table = Mutex::new(GrantTable::new(cap(), 1));
        let t0 = Instant::now();
        let (done, gone, fresh) = {
            let mut t = table.lock().unwrap();
            let done = t.acquire(req(4_000), t0).unwrap();
            let gone = t.acquire(req(3_000), t0).unwrap();
            t.bind_deploy(&done.id, "finished", t0).unwrap();
            t.bind_deploy(&gone.id, "torn", t0).unwrap();
            let fresh = t.acquire(req(1_000), t0).unwrap();
            (done, gone, fresh)
        };
        let t1 = t0 + BIND_GRACE + Duration::from_secs(1);
        table.lock().unwrap().bind_deploy(&fresh.id, "deploying", t1).unwrap();
        let kamaji = FakeKamaji::default();
        *kamaji.observed.lock().unwrap() =
            vec![Observed { ident: "finished".into(), terminal: Some("exited".into()) }];
        assert!(sweep(&table, &kamaji, &no_dirs(), t1).await.is_empty(), "nothing is expired, nothing stopped");
        let t = table.lock().unwrap();
        assert!(!t.get(&done.id).unwrap().state.is_live() && !t.get(&gone.id).unwrap().state.is_live(), "both closed");
        assert!(t.is_bound(&fresh.id, "deploying"), "a deploy inside the grace window stays bound");
        drop(t);
        assert!(table.lock().unwrap().acquire(req(7_000), t1).is_ok(), "reservations came back");
    }

    #[test]
    fn a_leased_spec_is_bound_only_to_the_workload_its_grant_deployed() {
        let mut table = GrantTable::new(cap(), 1);
        let now = Instant::now();
        let g = table.acquire(req(1), now).unwrap();
        assert!(!table.is_bound(&g.id, "w"), "granted but never deployed");
        table.bind_deploy(&g.id, "w", now).unwrap();
        assert!(table.is_bound(&g.id, "w"));
        assert!(!table.is_bound(&g.id, "other"));
        assert!(!table.is_bound("lease-999", "w"));
    }

    fn outpost(t: &mut GrantTable, camp: &str, now: Instant) -> GrantView {
        t.acquire(
            AcquireRequest {
                holder: Holder { camp: camp.into(), ..Holder::default() },
                needs: Needs { memory_mb: 512, cpu_millis: 500, disk_mb: 40_000, ..Needs::default() },
                standing: true,
                ..AcquireRequest::default()
            },
            now,
        )
        .unwrap()
    }

    #[test]
    fn a_standing_lease_has_no_deadline_takes_no_build_slot_and_only_renewals_hold_it() {
        let mut t = GrantTable::new(cap(), 1);
        let t0 = Instant::now();
        let o = outpost(&mut t, "yah", t0);
        assert!(o.standing && o.deadline_ms == 0);
        // cap() allows 4 grants: all four still go to builds.
        for _ in 0..4 {
            t.acquire(req(100), t0).expect("the outpost takes no build slot");
        }
        assert!(matches!(t.acquire(req(100), t0), Err(Refusal::AtGrantLimit { limit: 4 })));
        // Its memory and disk still count.
        assert_eq!(t.committed().1, 512 + 4 * 100);
        assert_eq!(t.bind_deploy(&o.id, "outpost", t0).unwrap(), None, "kamaji arms no deadline");
        // Renewed well past MAX_DEADLINE, it stays live.
        let mut now = t0;
        while now < t0 + MAX_DEADLINE + Duration::from_secs(60) {
            now += Duration::from_secs(30);
            t.renew(&o.id, o.epoch, now).unwrap();
            assert!(t.expire(now).is_empty());
        }
        // Renewals stop: one TTL later it expires and its workload is stopped.
        let gone = now + DEFAULT_TTL;
        assert_eq!(t.expire(gone), vec![(o.id.clone(), "outpost".to_string())]);
    }

    #[test]
    fn a_standing_lease_may_not_bind_and_ignores_a_deadline() {
        let mut t = GrantTable::new(cap(), 1);
        let now = Instant::now();
        let o = outpost(&mut t, "yah", now);
        let binder = AcquireRequest { standing: true, ..bound("yah", &o.id) };
        assert_eq!(t.acquire(binder, now), Err(Refusal::StandingBind { id: o.id.clone() }));
        let asked = AcquireRequest { standing: true, deadline_ms: Some(1), ..req(1) };
        assert_eq!(t.acquire(asked, now).unwrap().deadline_ms, 0);
    }

    #[test]
    fn a_rehydrated_leased_spec_without_a_deadline_is_standing() {
        let mut t = GrantTable::new(cap(), 1);
        let now = Instant::now();
        let found = |id: u64, deadline| RehydratedLease {
            ident: format!("w{id}"),
            lease_id: lease_id_for(id),
            needs: Needs::default(),
            deadline,
            bound_into: None,
        };
        assert!(t.rehydrate(found(5, None), now));
        assert!(t.rehydrate(found(6, Some(DEFAULT_DEADLINE)), now));
        assert!(t.get("lease-5").unwrap().standing);
        assert!(!t.get("lease-6").unwrap().standing);
    }

    fn bound(camp: &str, into: &str) -> AcquireRequest {
        AcquireRequest {
            holder: Holder { camp: camp.into(), ..Holder::default() },
            needs: Needs { memory_mb: 1_000, cpu_millis: 1_000, ..Needs::default() },
            bind: Some(Bind { lease_id: into.into(), path: "rust".into() }),
            ..AcquireRequest::default()
        }
    }

    #[test]
    fn a_bind_into_another_camps_lease_is_refused() {
        let mut t = GrantTable::new(cap(), 1);
        let now = Instant::now();
        let o = outpost(&mut t, "noisetable", now);
        assert_eq!(t.acquire(bound("yah", &o.id), now), Err(Refusal::BindForeignCamp { id: o.id }));
    }

    #[test]
    fn a_bind_into_an_expired_lease_is_refused() {
        let mut t = GrantTable::new(cap(), 1);
        let now = Instant::now();
        let o = outpost(&mut t, "yah", now);
        t.expire(now + DEFAULT_TTL);
        assert_eq!(t.acquire(bound("yah", &o.id), now), Err(Refusal::BindNotLive { id: o.id.clone() }));
        t.forget(&[o.id.clone()]);
        assert!(matches!(t.acquire(bound("yah", &o.id), now), Err(Refusal::BindUnknownLease { .. })));
        let bad = AcquireRequest {
            bind: Some(Bind { lease_id: o.id, path: "../other".into() }),
            ..bound("yah", "")
        };
        assert!(matches!(t.acquire(bad, now), Err(Refusal::InvalidBindPath { .. })));
    }

    #[test]
    fn a_bind_into_the_same_camps_live_lease_counts_its_bytes_once() {
        let mut t = GrantTable::new(cap(), 1);
        let now = Instant::now();
        let o = outpost(&mut t, "yah", now);
        let b = t.acquire(bound("yah", &o.id), now).unwrap();
        assert_eq!(b.bound_into.as_ref().unwrap().host_path(), lease_host_dir(&o.id).join("rust"));
        assert_eq!(t.committed().3, 40_000, "the bound bytes are the outpost's disk_mb, once");
        // 50_000 capacity - 40_000 outpost: a 10_001 MB unbound ask does not fit.
        let big = AcquireRequest { needs: Needs { disk_mb: 10_001, ..Needs::default() }, ..req(1) };
        assert!(matches!(t.acquire(big, now), Err(Refusal::Insufficient { resource: "disk_mb", .. })));
        // The spec may carry exactly the granted bind, as one mount.
        let granted = lease_host_dir(&o.id).join("rust");
        t.bind_deploy(&b.id, "build", now).unwrap();
        assert!(t.check_lease_binds(Some(&b.id), &[granted.clone()]).is_ok());
        assert!(t.check_lease_binds(Some(&b.id), &[granted.clone(), granted.clone()]).is_err());
        assert!(t.check_lease_binds(Some(&b.id), &[granted.join("store"), granted.join("target")]).is_err());
        assert!(t.check_lease_binds(None, &[granted.clone()]).is_err(), "an unleased spec binds none");
        assert!(t.check_lease_binds(Some(&o.id), &[lease_host_dir(&o.id)]).is_ok(), "own dir");
    }

    #[tokio::test]
    async fn when_the_outpost_lease_expires_every_build_bound_into_it_is_torn_down() {
        let table = Mutex::new(GrantTable::new(cap(), 1));
        let t0 = Instant::now();
        let (o, b, free) = {
            let mut t = table.lock().unwrap();
            let o = outpost(&mut t, "yah", t0);
            let b = t.acquire(bound("yah", &o.id), t0).unwrap();
            let free = t.acquire(req(1_000), t0).unwrap();
            t.bind_deploy(&o.id, "outpost", t0).unwrap();
            t.bind_deploy(&b.id, "build", t0).unwrap();
            t.bind_deploy(&free.id, "unbound", t0).unwrap();
            (o, b, free)
        };
        let kamaji = FakeKamaji::default();
        *kamaji.observed.lock().unwrap() = ["outpost", "build", "unbound"]
            .map(|i| Observed { ident: i.into(), terminal: None })
            .to_vec();
        // Holder keeps renewing the build and the unbound lease; the outpost's renewals stop.
        let t1 = t0 + DEFAULT_TTL + Duration::from_secs(1);
        {
            let mut t = table.lock().unwrap();
            t.renew(&b.id, b.epoch, t1).unwrap();
            t.renew(&free.id, free.epoch, t1).unwrap();
        }
        let mut stopped = sweep(&table, &kamaji, &no_dirs(), t1).await;
        stopped.sort();
        assert_eq!(stopped, vec!["build".to_string(), "outpost".to_string()]);
        let t = table.lock().unwrap();
        assert!(!t.get(&o.id).unwrap().state.is_live() && !t.get(&b.id).unwrap().state.is_live());
        assert!(t.get(&free.id).unwrap().state.is_live(), "an unbound lease is untouched");
    }

    #[test]
    fn rehydration_recovers_the_cross_lease_bind_from_the_spec() {
        let mut spec = workload_spec::WorkloadSpec::for_forge(
            "forge",
            workload_spec::ImageRef {
                registry: "localhost".into(),
                repository: "test".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            workload_spec::TierTag("infra".into()),
            vec![],
        );
        spec.lease_id = Some(lease_id_for(9));
        spec.volumes.push(workload_spec::VolumeMount {
            source: workload_spec::VolumeSource::Bind { host_path: lease_host_dir("lease-3").join("rust") },
            target: "/yah/rust".into(),
            read_only: false,
            from_secret_mount: false,
        });
        let found = RehydratedLease::from_spec("forge".into(), &spec).unwrap();
        assert_eq!(found.bound_into, Some(Bind { lease_id: "lease-3".into(), path: "rust".into() }));
    }

    #[tokio::test]
    async fn a_restarted_yubaba_rebuilds_a_running_lease_from_kamaji() {
        let kamaji = FakeKamaji {
            leased: vec![RehydratedLease {
                ident: "forge-check-1".into(),
                lease_id: lease_id_for(42),
                needs: Needs { memory_mb: 7_000, cpu_millis: 1_000, ..Needs::default() },
                deadline: Some(Duration::from_secs(1_800)),
                bound_into: None,
            }],
            ..FakeKamaji::default()
        };
        let table = Mutex::new(GrantTable::new(cap(), 1));
        let now = Instant::now();
        assert_eq!(rehydrate(&table, &kamaji, now).await.unwrap(), 1);
        let mut t = table.lock().unwrap();
        let g = t.get("lease-42").unwrap();
        assert_eq!(g.state, GrantState::Running { ident: "forge-check-1".into() });
        assert_eq!(g.deadline, Duration::from_secs(1_800));
        // The holder renews the id it already holds; capacity stays reserved.
        assert!(t.renew("lease-42", 42, now).is_ok());
        assert!(matches!(t.acquire(req(2_000), now), Err(Refusal::Insufficient { .. })));
        // New epochs stay above every rehydrated one.
        assert!(t.acquire(req(500), now).unwrap().epoch > 42);
    }

    #[test]
    fn rehydration_reads_lease_id_and_deadline_off_the_spec() {
        let mut spec = workload_spec::WorkloadSpec::for_forge(
            "forge",
            workload_spec::ImageRef {
                registry: "localhost".into(),
                repository: "test".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            workload_spec::TierTag("infra".into()),
            vec![],
        );
        assert!(RehydratedLease::from_spec("forge".into(), &spec).is_none());
        spec.lease_id = Some(lease_id_for(7));
        spec.deadline = Some(workload_spec::Millis(5_000));
        let found = RehydratedLease::from_spec("forge".into(), &spec).unwrap();
        assert_eq!(found.deadline, Some(Duration::from_secs(5)));
        assert_eq!(epoch_of(&found.lease_id), Some(7));
        assert_eq!(found.needs.disk_mb, 0, "no stamp, no disk");
    }

    /// R1019-F9: the disk a grant asked for, stamped at bind, survives a
    /// restart and still holds the machine's disk against the next ask.
    #[tokio::test]
    async fn a_rehydrated_lease_keeps_counting_the_disk_its_grant_asked_for() {
        let mut spec = workload_spec::WorkloadSpec::for_forge(
            "outpost",
            workload_spec::ImageRef {
                registry: "localhost".into(),
                repository: "test".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            workload_spec::TierTag("infra".into()),
            vec![],
        );
        spec.lease_id = Some(lease_id_for(11));
        spec.annotations.insert(LEASE_DISK_MB_ANNOTATION.into(), "40000".into());
        let found = RehydratedLease::from_spec("outpost".into(), &spec).unwrap();
        assert_eq!(found.needs.disk_mb, 40_000);

        let kamaji = FakeKamaji { leased: vec![found], ..FakeKamaji::default() };
        let table = Mutex::new(GrantTable::new(cap(), 1));
        let now = Instant::now();
        assert_eq!(rehydrate(&table, &kamaji, now).await.unwrap(), 1);
        let t = table.lock().unwrap();
        assert_eq!(t.disk_mb_of("lease-11"), Some(40_000));
    }
    fn tmp_dirs() -> (tempfile::TempDir, LeaseDirs) {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = LeaseDirs::new(tmp.path().join("leases"), tmp.path().join("produced"));
        (tmp, dirs)
    }

    fn disk_req(disk_mb: u32) -> AcquireRequest {
        AcquireRequest { needs: Needs { disk_mb, ..req(1).needs }, ..req(1) }
    }

    #[tokio::test]
    async fn an_unfetched_terminal_workload_is_deleted_after_the_window_and_stops_counting_then() {
        let (tmp, dirs) = tmp_dirs();
        let table = Mutex::new(GrantTable::new(cap(), 1));
        let t0 = Instant::now();
        let g = table.lock().unwrap().acquire(disk_req(40_000), t0).unwrap();
        dirs.create(&g.id).await.unwrap();
        table.lock().unwrap().bind_deploy(&g.id, "forge.abc", t0).unwrap();
        let produced = tmp.path().join("produced/abc");
        std::fs::create_dir_all(&produced).unwrap();
        std::fs::write(produced.join("out.tar"), b"bytes").unwrap();
        std::fs::write(tmp.path().join("leases").join(&g.id).join("x"), b"bytes").unwrap();

        // The workload exits; nobody fetches.
        let kamaji = FakeKamaji::default();
        *kamaji.observed.lock().unwrap() =
            vec![Observed { ident: "forge.abc".into(), terminal: Some("exited".into()) }];
        let t1 = t0 + Duration::from_secs(60);
        sweep(&table, &kamaji, &dirs, t1).await;
        let big = || disk_req(20_000);
        // Terminal, inside the window: bytes present and still counted.
        assert!(produced.exists());
        assert!(matches!(
            table.lock().unwrap().acquire(big(), t1),
            Err(Refusal::Insufficient { resource: "disk_mb", free: 10_000, .. })
        ));
        // One tick before the window closes: unchanged.
        let almost = t1 + OUTPUT_RETENTION - Duration::from_secs(1);
        sweep(&table, &kamaji, &dirs, almost).await;
        assert!(produced.exists() && tmp.path().join("leases").join(&g.id).exists());
        assert!(table.lock().unwrap().acquire(big(), almost).is_err());
        // The window closes: gone, and the disk is free in the same sweep.
        sweep(&table, &kamaji, &dirs, t1 + OUTPUT_RETENTION).await;
        assert!(!produced.exists() && !tmp.path().join("leases").join(&g.id).exists());
        assert!(table.lock().unwrap().get(&g.id).is_none());
        assert!(table.lock().unwrap().acquire(big(), t1 + OUTPUT_RETENTION).is_ok());
    }

    #[tokio::test]
    async fn a_failed_delete_keeps_counting_the_bytes_and_retries() {
        let (tmp, dirs) = tmp_dirs();
        let table = Mutex::new(GrantTable::new(cap(), 1));
        let t0 = Instant::now();
        let g = table.lock().unwrap().acquire(disk_req(40_000), t0).unwrap();
        // A regular file where the lease dir should be: remove_dir_all fails.
        std::fs::create_dir_all(tmp.path().join("leases")).unwrap();
        std::fs::write(tmp.path().join("leases").join(&g.id), b"not a dir").unwrap();
        table.lock().unwrap().release(&g.id, g.epoch, "released".into(), t0).unwrap();
        let kamaji = FakeKamaji::default();
        let late = t0 + OUTPUT_RETENTION;
        sweep(&table, &kamaji, &dirs, late).await;
        assert!(table.lock().unwrap().get(&g.id).is_some(), "not forgotten while its bytes remain");
        assert!(table.lock().unwrap().acquire(disk_req(20_000), late).is_err());
        std::fs::remove_file(tmp.path().join("leases").join(&g.id)).unwrap();
        sweep(&table, &kamaji, &dirs, late).await;
        assert!(table.lock().unwrap().get(&g.id).is_none());
    }

    #[tokio::test]
    async fn the_lease_dir_exists_after_grant_and_is_gone_after_terminal_plus_window() {
        let (tmp, dirs) = tmp_dirs();
        let table = Mutex::new(GrantTable::new(cap(), 1));
        let t0 = Instant::now();
        let g = table.lock().unwrap().acquire(req(1_000), t0).unwrap();
        dirs.create(&g.id).await.unwrap();
        let dir = tmp.path().join("leases").join(&g.id);
        assert!(dir.is_dir());
        // A crashed holder: renewals stop, the lease expires, the dir lingers
        // for the window and then goes, with no release call ever made.
        let kamaji = FakeKamaji::default();
        let expired = t0 + DEFAULT_TTL;
        sweep(&table, &kamaji, &dirs, expired).await;
        assert!(!table.lock().unwrap().get(&g.id).unwrap().state.is_live());
        assert!(dir.is_dir(), "kept through the retention window");
        sweep(&table, &kamaji, &dirs, expired + OUTPUT_RETENTION).await;
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn a_lease_dir_with_no_grant_at_boot_is_removed_and_a_rehydrated_one_is_kept() {
        let (tmp, dirs) = tmp_dirs();
        let kamaji = FakeKamaji {
            leased: vec![RehydratedLease {
                ident: "forge.live".into(),
                lease_id: lease_id_for(42),
                needs: Needs::default(),
                deadline: None,
                bound_into: None,
            }],
            ..FakeKamaji::default()
        };
        let table = Mutex::new(GrantTable::new(cap(), 1));
        rehydrate(&table, &kamaji, Instant::now()).await.unwrap();
        let root = tmp.path().join("leases");
        for name in ["lease-42", "lease-7", "not-a-lease"] {
            std::fs::create_dir_all(root.join(name)).unwrap();
            std::fs::write(root.join(name).join("f"), b"x").unwrap();
        }
        let removed = remove_orphan_dirs(&table, &dirs).await;
        assert_eq!(removed, vec!["lease-7".to_string()]);
        assert!(root.join("lease-42").exists(), "a rehydrated lease keeps its dir");
        assert!(!root.join("lease-7").exists());
        assert!(root.join("not-a-lease").exists(), "only lease-<epoch> names are touched");
    }
}
