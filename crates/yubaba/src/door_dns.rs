//! R936-B7: keep each public hostname's A-record set equal to its **live**
//! front doors, driven from the raft leader.
//!
//! Every public site in this fleet resolves by DNS round-robin across the
//! front doors (`yah.dev`, `cloud.mesh.yah.dev`, `noisetable.com`,
//! `scrabcake.com` → the three door IPs). When a door dies, DNS keeps handing
//! out its address, and a client that resolves to it gets nothing — measured
//! on prod 2026-09-22 as 1/3 of requests failing for the whole 4m10s outage.
//!
//! Operator call 2026-09-22 (ask_user F4254), mechanism (b): the raft leader's
//! yubaba pulls a door's A record at Cloudflare when that door's node lease
//! expires, and puts it back once the lease reads live again. Not Cloudflare
//! load-balancer pools, which cost money. The accepted tradeoff is that DNS is
//! now a function of the cluster that just lost a node, which is what the
//! four invariants below are for.
//!
//! # Invariants
//!
//! 1. **Never empty a record set.** If every door of a hostname reads dead,
//!    the set is left exactly as it is and the tick logs at `error!`. More
//!    generally, no plan may leave a hostname with zero A records. A
//!    fleet-wide "everyone is dead" is far likelier to be the observer's
//!    problem than the fleet's, and an empty set is a guaranteed total outage
//!    where a stale one is a partial one.
//! 2. **Idempotent across leader changes.** The state lives in DNS, not in
//!    memory: each reconcile lists what Cloudflare holds, diffs it against
//!    what liveness wants, and writes only the difference. A new leader needs
//!    nothing from the old one, and re-running a finished plan writes nothing.
//! 3. **Only a settled leader writes** (the R858-B20 settle gate). The node
//!    lease detector stamps renewals with the `Instant` they arrived *at this
//!    node*, so a node that led once before and has just been re-elected holds
//!    renewal times from its previous term, and every door reads long-silent,
//!    i.e. `Down`. [`DoorDnsGate`] therefore (a) keeps its own
//!    [`TransitionTracker`], thrown away the moment leadership is lost, so no
//!    committed verdict survives a leadership gap, and (b) feeds it nothing
//!    until this node has led continuously for
//!    [`FenceTiming::settle_after`](crate::appliance_ownership::FenceTiming::settle_after),
//!    which is long enough for live doors' renewals to reach the new leader.
//!    After that the hysteresis still has to dwell before anything commits.
//!    Withdrawals additionally require that the leader can still commit
//!    ([`QuorumVerdict::quorate`](crate::quorum_health::QuorumVerdict::quorate)),
//!    so a partitioned stale leader, which sees every peer as dead, cannot
//!    withdraw the live side of the fleet.
//! 4. **Scoped to an explicit list.** Only the hostnames named in
//!    [`DoorDnsConfig`] are ever listed or written, and within a hostname only
//!    records whose content is the address of one of *that hostname's*
//!    declared doors. Any other A record at the name is never deleted. The
//!    door list is per hostname, not "every member with a public address",
//!    because the doors fronting a staging host are not the prod doors (the
//!    `plan_passway_apex` bug recorded on `us-west-001.toml`).
//!
//! # Withdraw on lease expiry, re-add on proven service
//!
//! The two directions deliberately read different evidence. A withdrawal is
//! keyed on the node lease expiring: that is the fastest honest signal that a
//! box is gone, and a dead box cannot answer a probe anyway. A re-add needs
//! more than "yubaba is back". The 2026-09-23 prod drill re-added us-south-001
//! 2 s after its lease went live, and its door then answered 503 to real
//! clients for about 20 s while passway came up behind it. So a re-add also
//! requires [`DoorView::ready`]: the leader probes the door's public IP for
//! that hostname over HTTPS, with SNI, the way a client would
//! ([`HttpsDoorProbe`]), and [`DoorReadiness`] only calls the door ready after
//! [`DoorReadiness::REQUIRED`] consecutive successes at the tick cadence. What
//! counts as a success is [`judge_probes`]'s rule.
//!
//! # Relationship to the other two DNS writers
//!
//! [`crate::ingress_effector`]'s apex withdrawal subtracts the dead *ingress
//! owner* from one apex, and its module doc forbids it from ever adding. That
//! rule is about that module and still holds: it has no declared door set to
//! bound an addition. This module does have one, so it may add, but only an
//! address that is (a) a declared door of that hostname and (b) confirmed up.
//! `yah cloud apply` renders the declared set and may re-add a dead door while
//! it is down. The next reconcile withdraws it again. That is a brief flap,
//! not a loop, because both writers converge on the declared set as soon as
//! the door is live.
//!
//! # Cadence
//!
//! The scheduler ticks every `2 x heartbeat` (about 1 s on the fleet), and one
//! reconcile lists every managed hostname. Doing that every tick would be about
//! 4 req/s per token, which is the scale of Cloudflare's per-token API rate
//! limit (not re-verified for this ticket; check Cloudflare's current published
//! limit before shortening the period). [`Cadence`]
//! reconciles immediately when the committed door liveness changes, otherwise
//! every [`DoorDns::PERIOD`] to repair drift, and backs off after a failure.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use crate::appliance_ownership::{record_is_settled, FenceTiming};
use crate::cloudflare_dns::{ARecord, CloudflareDns};
use crate::failure_detector::LivenessReport;
use crate::lease_detector::{Confirmed, HysteresisPolicy, TransitionTracker};
use crate::raft::{MemberInfo, YubabaNodeId};

/// Env var naming the door-DNS config file (TOML, see [`DoorDnsConfig`]).
/// Unset (the default, and every camp today) means the leader never touches
/// door records.
pub const CONFIG_ENV: &str = "YUBABA_DOOR_DNS_CONFIG";

/// The reconciler's whole authority, read from [`CONFIG_ENV`]:
///
/// ```toml
/// token_file = "/run/yah/secrets/<ident>/cf-dns.token"
///
/// [[host]]
/// name = "yah.dev"
/// zone_id = "..."
/// doors = ["us-west-001", "us-south-001", "us-east-001"]
/// ```
///
/// `doors` are machine names, matched against each raft member row's
/// `machine`. The addresses come from those rows' `public_address`, so the IP
/// set is derived from the fleet and only the *membership* of each hostname's
/// door set is declared here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoorDnsConfig {
    /// Path to the `fob`-injected Cloudflare token. It needs DNS edit on every
    /// zone named below.
    pub token_file: String,
    #[serde(rename = "host")]
    pub hosts: Vec<ManagedHost>,
}

/// One hostname whose A records track its doors' liveness.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedHost {
    /// Exact record name, e.g. `yah.dev` or `cloud.mesh.yah.dev`.
    pub name: String,
    /// Cloudflare zone id containing `name`. Taken directly rather than looked
    /// up, for the same reason `YUBABA_INGRESS_CLOUDFLARE_ZONE_ID` is.
    pub zone_id: String,
    /// Machine names of the doors fronting `name`.
    pub doors: Vec<String>,
}

/// Parse and validate a [`DoorDnsConfig`]. Every structural mistake is an
/// error rather than a default: a half-configured reconciler would find out
/// during the outage it exists for.
pub fn parse_config(text: &str) -> Result<DoorDnsConfig, String> {
    let cfg: DoorDnsConfig = toml::from_str(text).map_err(|e| e.to_string())?;
    if cfg.token_file.trim().is_empty() {
        return Err("token_file is empty".into());
    }
    if cfg.hosts.is_empty() {
        return Err("no [[host]] entries: nothing to manage".into());
    }
    let mut seen = BTreeSet::new();
    for h in &cfg.hosts {
        if h.name.trim().is_empty() || h.zone_id.trim().is_empty() {
            return Err(format!("host {:?}: name and zone_id are required", h.name));
        }
        if !seen.insert(h.name.to_ascii_lowercase()) {
            return Err(format!("host {} is listed twice", h.name));
        }
        if h.doors.is_empty() || h.doors.iter().any(|d| d.trim().is_empty()) {
            return Err(format!(
                "host {}: doors must be a non-empty list of machine names",
                h.name
            ));
        }
    }
    Ok(cfg)
}

/// A door's committed liveness, as far as this leader may act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DoorLiveness {
    /// Hysteresis committed `Up`.
    Up,
    /// Hysteresis committed `Down`.
    Down,
    /// No committed verdict, no member row, or an ambiguous one. Never grounds
    /// to add or to withdraw.
    Unconfirmed,
}

/// One declared door, resolved against the fleet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorView {
    pub machine: String,
    /// The member row's `public_address`. `None` means no row or no declared
    /// address, so this door can be neither added nor matched for withdrawal.
    pub address: Option<String>,
    pub liveness: DoorLiveness,
    /// Proven to be serving this hostname (see [`DoorReadiness`]). Only ever
    /// true for an `Up` door with an address. Gates ADDITIONS only;
    /// withdrawal reads `liveness` alone.
    pub ready: bool,
}

/// Why a plan held back some or all of its withdrawals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hold {
    /// Every addressed door reads `Down`. The set is left alone (invariant 1).
    AllDoorsDown,
    /// The withdrawals would have left the hostname with no A records: no door
    /// is confirmed up, the dead ones are the only records left, and the rest
    /// are unconfirmed.
    WouldEmpty,
    /// The leader cannot currently commit, so it may not withdraw.
    NotQuorate,
}

/// What one reconcile of one hostname should do. `add` and `delete` are
/// addresses, sorted, never overlapping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostPlan {
    pub add: Vec<String>,
    pub delete: Vec<String>,
    /// Set when withdrawals were computed and then withheld. `withheld` names
    /// them so the log line can say which dead door is still in rotation.
    pub hold: Option<(Hold, Vec<String>)>,
}

impl HostPlan {
    pub fn is_noop(&self) -> bool {
        self.add.is_empty() && self.delete.is_empty()
    }
}

/// The decision, as a pure function: declared doors with their liveness, plus
/// the A-record contents Cloudflare holds now, to the addresses to add and
/// withdraw.
///
/// - Add an address only if a door carrying it is `Up` **and ready** and the
///   address is absent. `Up` but not ready (lease live, door not yet serving)
///   adds nothing.
/// - Withdraw an address only if it is present and **every** door carrying it
///   is `Down`. An address shared with an `Up` or `Unconfirmed` door is kept.
/// - Addresses not belonging to any declared door are never touched.
/// - Withdrawals are withheld when the leader is not quorate, when no door is
///   up and at least one is down (invariant 1: leave the set alone), or when
///   applying them would leave the hostname with no records.
pub fn plan_host(doors: &[DoorView], actual: &BTreeSet<String>, quorate: bool) -> HostPlan {
    // Best liveness per address: Up beats Unconfirmed beats Down, so a shared
    // address is withdrawn only when every door behind it is down.
    let mut by_address: BTreeMap<&str, DoorLiveness> = BTreeMap::new();
    // Addresses that some Up door behind them has proven it serves.
    let mut ready: BTreeSet<&str> = BTreeSet::new();
    for d in doors {
        let Some(addr) = d.address.as_deref() else {
            continue;
        };
        if d.ready && d.liveness == DoorLiveness::Up {
            ready.insert(addr);
        }
        by_address
            .entry(addr)
            .and_modify(|cur| {
                *cur = match (*cur, d.liveness) {
                    (DoorLiveness::Up, _) | (_, DoorLiveness::Up) => DoorLiveness::Up,
                    (DoorLiveness::Unconfirmed, _) | (_, DoorLiveness::Unconfirmed) => {
                        DoorLiveness::Unconfirmed
                    }
                    _ => DoorLiveness::Down,
                }
            })
            .or_insert(d.liveness);
    }

    let add: Vec<String> = by_address
        .iter()
        .filter(|(a, l)| **l == DoorLiveness::Up && ready.contains(**a) && !actual.contains(**a))
        .map(|(a, _)| a.to_string())
        .collect();
    let delete: Vec<String> = by_address
        .iter()
        .filter(|(a, l)| **l == DoorLiveness::Down && actual.contains(**a))
        .map(|(a, _)| a.to_string())
        .collect();

    if delete.is_empty() {
        return HostPlan {
            add,
            delete,
            hold: None,
        };
    }

    // `delete` is non-empty, so `by_address` is too.
    let all_down = by_address.values().all(|l| *l == DoorLiveness::Down);
    // `delete` is a subset of `actual` and disjoint from `add`.
    let remaining = actual.len() + add.len() - delete.len();
    let hold = if all_down {
        Some(Hold::AllDoorsDown)
    } else if remaining == 0 {
        Some(Hold::WouldEmpty)
    } else if !quorate {
        Some(Hold::NotQuorate)
    } else {
        None
    };
    match hold {
        Some(h) => HostPlan {
            add,
            delete: Vec::new(),
            hold: Some((h, delete)),
        },
        None => HostPlan {
            add,
            delete,
            hold: None,
        },
    }
}

/// Resolve a hostname's declared doors against the replicated member rows and
/// the gate's committed liveness.
///
/// A machine name matching no row, or more than one row (a re-registered node
/// under a new id), resolves to `Unconfirmed`. Ambiguity is not evidence.
/// `ready` answers whether an address has proven it serves this hostname; it is
/// only consulted for an `Up` door.
pub fn door_views(
    doors: &[String],
    members: &BTreeMap<YubabaNodeId, MemberInfo>,
    committed: impl Fn(YubabaNodeId) -> Option<Confirmed>,
    ready: impl Fn(&str) -> bool,
) -> Vec<DoorView> {
    doors
        .iter()
        .map(|machine| {
            let rows: Vec<(&YubabaNodeId, &MemberInfo)> = members
                .iter()
                .filter(|(_, m)| m.machine.as_deref() == Some(machine.as_str()))
                .collect();
            match rows.as_slice() {
                [(id, row)] => DoorView {
                    machine: machine.clone(),
                    address: row.public_address.clone(),
                    liveness: match committed(**id) {
                        Some(Confirmed::Up) => DoorLiveness::Up,
                        Some(Confirmed::Down) => DoorLiveness::Down,
                        None => DoorLiveness::Unconfirmed,
                    },
                    ready: false,
                },
                [] => DoorView {
                    machine: machine.clone(),
                    address: None,
                    liveness: DoorLiveness::Unconfirmed,
                    ready: false,
                },
                many => DoorView {
                    machine: machine.clone(),
                    // Only keep the address if every row agrees, so the
                    // record stays recognisably "a door's" and is not added.
                    address: {
                        let addrs: BTreeSet<_> =
                            many.iter().map(|(_, m)| m.public_address.clone()).collect();
                        if addrs.len() == 1 {
                            addrs.into_iter().next().flatten()
                        } else {
                            None
                        }
                    },
                    liveness: DoorLiveness::Unconfirmed,
                    ready: false,
                },
            }
        })
        .map(|mut v| {
            v.ready = v.liveness == DoorLiveness::Up && v.address.as_deref().is_some_and(&ready);
            v
        })
        .collect()
}

/// What one HTTPS probe of one door for one hostname saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// TLS completed for the hostname's SNI and an HTTP response came back.
    Status(u16),
    /// Connect, TLS (including a certificate that does not match the
    /// hostname) or timeout failure.
    Failed(String),
}

/// One probe result, as [`judge_probes`] consumes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub address: String,
    /// Currently in the hostname's record set, i.e. serving real clients. These
    /// doors are probed only as the baseline a candidate is compared against.
    pub in_rotation: bool,
    pub outcome: ProbeOutcome,
}

/// Which re-add candidates passed this round, as a pure function.
///
/// A candidate (a door NOT in rotation) passes when it answers with a status
/// below 500. The one exception is a hostname that is already broken
/// everywhere: if no in-rotation door answers below 500 either, as
/// scrabcake.com did until R936-T14 published it, then a candidate that answers at all is
/// serving exactly as well as the doors clients already use, and holding it out
/// would strand it out of rotation for as long as the site is down. A transport
/// failure never passes.
pub fn judge_probes(results: &[ProbeResult]) -> BTreeMap<String, bool> {
    let healthy = |o: &ProbeOutcome| matches!(o, ProbeOutcome::Status(s) if *s < 500);
    let site_up = results.iter().any(|r| r.in_rotation && healthy(&r.outcome));
    results
        .iter()
        .filter(|r| !r.in_rotation)
        .map(|r| {
            let pass = match r.outcome {
                ProbeOutcome::Status(s) => s < 500 || !site_up,
                ProbeOutcome::Failed(_) => false,
            };
            (r.address.clone(), pass)
        })
        .collect()
}

/// Consecutive-success streaks per `(hostname, address)` re-add candidate.
#[derive(Debug, Default)]
pub struct DoorReadiness {
    streak: BTreeMap<(String, String), u32>,
}

impl DoorReadiness {
    /// Consecutive passing probes, one per leader tick, before a candidate is
    /// ready to re-add.
    pub const REQUIRED: u32 = 3;

    /// Fold one round of verdicts for `host`. A pass extends the streak, a
    /// failure resets it, and a candidate absent from `verdicts` (it re-entered
    /// rotation, went down, or lost its address) is forgotten, so a later
    /// return starts again from zero.
    pub fn observe(&mut self, host: &str, verdicts: &BTreeMap<String, bool>) {
        self.streak
            .retain(|(h, a), _| h != host || verdicts.contains_key(a));
        for (addr, pass) in verdicts {
            let n = self
                .streak
                .entry((host.to_string(), addr.clone()))
                .or_insert(0);
            *n = if *pass { n.saturating_add(1) } else { 0 };
        }
    }

    pub fn ready(&self, host: &str, addr: &str) -> bool {
        self.streak
            .get(&(host.to_string(), addr.to_string()))
            .is_some_and(|n| *n >= Self::REQUIRED)
    }

    /// Forget everything, as when leadership is lost.
    pub fn clear(&mut self) {
        self.streak.clear();
    }
}

/// Probe one door for one hostname. A trait so the reconciler is testable
/// without a network.
#[async_trait]
pub trait DoorProbe: Send + Sync {
    async fn probe(&self, host: &str, address: &str) -> ProbeOutcome;
}

/// [`DoorProbe`] over real HTTPS: `GET https://<host>/` with the connection
/// pinned to the door's address (reqwest's resolve override, so SNI and
/// certificate validation are the hostname's, as for a real client).
/// Redirects are not followed, since a 3xx already proves the door serves.
pub struct HttpsDoorProbe {
    timeout: Duration,
}

impl HttpsDoorProbe {
    pub const TIMEOUT: Duration = Duration::from_secs(2);

    pub fn new() -> Self {
        Self {
            timeout: Self::TIMEOUT,
        }
    }
}

impl Default for HttpsDoorProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DoorProbe for HttpsDoorProbe {
    async fn probe(&self, host: &str, address: &str) -> ProbeOutcome {
        let ip: std::net::IpAddr = match address.parse() {
            Ok(ip) => ip,
            Err(e) => return ProbeOutcome::Failed(format!("bad address {address}: {e}")),
        };
        let client = match reqwest::Client::builder()
            .resolve(host, std::net::SocketAddr::new(ip, 443))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.timeout)
            .build()
        {
            Ok(c) => c,
            Err(e) => return ProbeOutcome::Failed(format!("client: {e}")),
        };
        match client.get(format!("https://{host}/")).send().await {
            Ok(resp) => ProbeOutcome::Status(resp.status().as_u16()),
            Err(e) => ProbeOutcome::Failed(format!("{e:#}")),
        }
    }
}

/// Invariant 3: the leadership + settle gate and the leader-scoped liveness it
/// guards.
#[derive(Debug)]
pub struct DoorDnsGate {
    timing: FenceTiming,
    leader_since: Option<Instant>,
    tracker: TransitionTracker,
}

impl DoorDnsGate {
    pub fn new(timing: FenceTiming) -> Self {
        Self {
            timing,
            leader_since: None,
            tracker: TransitionTracker::new(),
        }
    }

    /// Feed one scheduler tick. Returns whether this node may reconcile on
    /// this tick.
    ///
    /// Losing leadership forgets everything, so a re-elected node starts from
    /// no committed verdicts. The report is only fed once the leader has held
    /// office for `settle_after` (R858-B20), so renewal times left over from
    /// a previous term cannot commit a `Down` on a live door.
    pub fn observe(
        &mut self,
        is_leader: bool,
        now: Instant,
        report: &LivenessReport,
        hysteresis: HysteresisPolicy,
    ) -> bool {
        if !is_leader {
            if self.leader_since.is_some() {
                self.leader_since = None;
                self.tracker = TransitionTracker::new();
            }
            return false;
        }
        let since = *self.leader_since.get_or_insert(now);
        if !record_is_settled(Some(now.saturating_duration_since(since)), self.timing) {
            return false;
        }
        self.tracker.observe(report, hysteresis, now);
        true
    }

    /// This leader's committed verdict for `node`.
    pub fn committed(&self, node: YubabaNodeId) -> Option<Confirmed> {
        self.tracker.committed(node)
    }
}

/// When to reconcile: at once when the door liveness snapshot changes,
/// otherwise every `period`, and not before `retry_after` has passed after a
/// failure.
#[derive(Debug)]
pub struct Cadence {
    period: Duration,
    retry_after: Duration,
    last_run: Option<Instant>,
    last_snapshot: Option<Vec<Vec<DoorView>>>,
    not_before: Option<Instant>,
}

impl Cadence {
    pub fn new(period: Duration, retry_after: Duration) -> Self {
        Self {
            period,
            retry_after,
            last_run: None,
            last_snapshot: None,
            not_before: None,
        }
    }

    pub fn due(&self, now: Instant, snapshot: &[Vec<DoorView>]) -> bool {
        if self.not_before.is_some_and(|t| now < t) {
            return false;
        }
        match (&self.last_run, &self.last_snapshot) {
            (Some(last), Some(prev)) => {
                prev.as_slice() != snapshot || now.saturating_duration_since(*last) >= self.period
            }
            _ => true,
        }
    }

    pub fn record(&mut self, now: Instant, snapshot: Vec<Vec<DoorView>>, ok: bool) {
        self.last_run = Some(now);
        if ok {
            self.last_snapshot = Some(snapshot);
            self.not_before = None;
        } else {
            self.last_snapshot = None;
            self.not_before = Some(now + self.retry_after);
        }
    }
}

/// The DNS operations the reconciler needs. A trait so [`reconcile_host`] is
/// testable without a network.
#[async_trait]
pub trait DoorRecords: Send + Sync {
    async fn list_a(&self, zone_id: &str, name: &str) -> Result<Vec<ARecord>>;
    async fn create_a(
        &self,
        zone_id: &str,
        name: &str,
        content: &str,
        ttl: u32,
        proxied: bool,
    ) -> Result<()>;
    async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<()>;
}

#[async_trait]
impl DoorRecords for CloudflareDns {
    async fn list_a(&self, zone_id: &str, name: &str) -> Result<Vec<ARecord>> {
        CloudflareDns::list_a(self, zone_id, name).await
    }
    async fn create_a(
        &self,
        zone_id: &str,
        name: &str,
        content: &str,
        ttl: u32,
        proxied: bool,
    ) -> Result<()> {
        CloudflareDns::create_a(self, zone_id, name, content, ttl, proxied).await
    }
    async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<()> {
        CloudflareDns::delete_record(self, zone_id, record_id).await
    }
}

/// List, plan, apply one hostname, returning the plan and the record contents
/// the hostname holds once it is applied. Adds go first, so a swap never passes
/// through an empty set. A re-added record copies `ttl`/`proxied` from a record
/// already at the name, so it matches its siblings; with none, it is DNS-only
/// with automatic TTL.
pub async fn reconcile_host(
    dns: &dyn DoorRecords,
    host: &ManagedHost,
    doors: &[DoorView],
    quorate: bool,
) -> Result<(HostPlan, BTreeSet<String>)> {
    let records = dns.list_a(&host.zone_id, &host.name).await?;
    let actual: BTreeSet<String> = records.iter().map(|r| r.content.clone()).collect();
    let plan = plan_host(doors, &actual, quorate);
    let after: BTreeSet<String> = actual
        .iter()
        .filter(|a| !plan.delete.contains(a))
        .cloned()
        .chain(plan.add.iter().cloned())
        .collect();
    let (ttl, proxied) = records.first().map_or((1, false), |r| (r.ttl, r.proxied));
    for addr in &plan.add {
        dns.create_a(&host.zone_id, &host.name, addr, ttl, proxied)
            .await
            .with_context(|| format!("re-adding door {addr} to {}", host.name))?;
    }
    for addr in &plan.delete {
        for r in records.iter().filter(|r| &r.content == addr) {
            dns.delete_record(&host.zone_id, &r.id)
                .await
                .with_context(|| format!("withdrawing dead door {addr} from {}", host.name))?;
        }
    }
    Ok((plan, after))
}

/// The reconciler the scheduler loop owns: config, transport, gate, cadence,
/// and the re-add readiness state.
pub struct DoorDns {
    hosts: Vec<ManagedHost>,
    dns: Arc<dyn DoorRecords>,
    probe: Arc<dyn DoorProbe>,
    gate: DoorDnsGate,
    cadence: Cadence,
    readiness: DoorReadiness,
    /// Each hostname's record contents as of this leader's last successful
    /// reconcile. It decides which Up doors are re-add candidates worth
    /// probing. It is a hint, not state: the reconcile itself always lists, and
    /// an unknown hostname (fresh leader) has no candidates until its first list.
    last_actual: BTreeMap<String, BTreeSet<String>>,
    armed: bool,
}

impl DoorDns {
    /// Drift-repair period when nothing changes.
    pub const PERIOD: Duration = Duration::from_secs(30);
    /// Back-off after a failed reconcile.
    pub const RETRY_AFTER: Duration = Duration::from_secs(10);

    pub fn new(
        hosts: Vec<ManagedHost>,
        dns: Arc<dyn DoorRecords>,
        probe: Arc<dyn DoorProbe>,
        timing: FenceTiming,
    ) -> Self {
        Self {
            hosts,
            dns,
            probe,
            gate: DoorDnsGate::new(timing),
            cadence: Cadence::new(Self::PERIOD, Self::RETRY_AFTER),
            readiness: DoorReadiness::default(),
            last_actual: BTreeMap::new(),
            armed: false,
        }
    }

    /// Production construction from [`CONFIG_ENV`]'s file.
    pub fn from_config(cfg: &DoorDnsConfig, timing: FenceTiming) -> Result<Self> {
        let dns = CloudflareDns::from_token_file(&cfg.token_file)?;
        Ok(Self::new(
            cfg.hosts.clone(),
            Arc::new(dns),
            Arc::new(HttpsDoorProbe::new()),
            timing,
        ))
    }

    pub fn hosts(&self) -> &[ManagedHost] {
        &self.hosts
    }

    /// Every scheduler tick, leader or not, before any early return.
    pub fn observe(
        &mut self,
        is_leader: bool,
        now: Instant,
        report: &LivenessReport,
        hysteresis: HysteresisPolicy,
    ) {
        self.armed = self.gate.observe(is_leader, now, report, hysteresis);
        if !is_leader {
            // Same rule as the gate's tracker: nothing survives a leadership gap.
            self.readiness.clear();
            self.last_actual.clear();
        }
    }

    /// Probe every re-add candidate (lease `Up`, has an address, absent from
    /// the last-known record set) of every hostname, plus that hostname's
    /// in-rotation doors as the baseline, concurrently, and fold the verdicts
    /// into [`DoorReadiness`]. No candidates means no probes.
    async fn probe_candidates(&mut self, members: &BTreeMap<YubabaNodeId, MemberInfo>) {
        let mut set = tokio::task::JoinSet::new();
        let mut hosts_with_candidates = BTreeSet::new();
        for host in &self.hosts {
            let Some(actual) = self.last_actual.get(&host.name) else {
                continue;
            };
            let views = door_views(
                &host.doors,
                members,
                |id| self.gate.committed(id),
                |_| false,
            );
            let candidates: BTreeSet<&str> = views
                .iter()
                .filter(|v| v.liveness == DoorLiveness::Up)
                .filter_map(|v| v.address.as_deref())
                .filter(|a| !actual.contains(*a))
                .collect();
            if candidates.is_empty() {
                continue;
            }
            hosts_with_candidates.insert(host.name.clone());
            let in_rotation = views
                .iter()
                .filter_map(|v| v.address.as_deref())
                .filter(|a| actual.contains(*a))
                .collect::<BTreeSet<_>>();
            for (addr, rot) in candidates
                .iter()
                .map(|a| (*a, false))
                .chain(in_rotation.iter().map(|a| (*a, true)))
            {
                let probe = self.probe.clone();
                let (h, a) = (host.name.clone(), addr.to_string());
                set.spawn(async move {
                    let outcome = probe.probe(&h, &a).await;
                    (
                        h,
                        ProbeResult {
                            address: a,
                            in_rotation: rot,
                            outcome,
                        },
                    )
                });
            }
        }
        let mut by_host: BTreeMap<String, Vec<ProbeResult>> = BTreeMap::new();
        while let Some(joined) = set.join_next().await {
            if let Ok((h, r)) = joined {
                if let ProbeOutcome::Failed(e) = &r.outcome {
                    debug!(host = %h, address = %r.address, "door DNS probe failed: {e}");
                }
                by_host.entry(h).or_default().push(r);
            }
        }
        for host in &self.hosts {
            let verdicts = if hosts_with_candidates.contains(&host.name) {
                judge_probes(by_host.get(&host.name).map_or(&[][..], |v| v.as_slice()))
            } else {
                BTreeMap::new()
            };
            self.readiness.observe(&host.name, &verdicts);
        }
    }

    /// On a leader tick, after the quorum verdict is known. No-op unless the
    /// gate armed on this tick's [`observe`](Self::observe) and the cadence is
    /// due. Returns each hostname's outcome for tests; logging happens here.
    pub async fn reconcile_if_due(
        &mut self,
        now: Instant,
        members: &BTreeMap<YubabaNodeId, MemberInfo>,
        quorate: bool,
    ) -> Option<Vec<(String, Result<HostPlan>)>> {
        if !self.armed {
            return None;
        }
        self.probe_candidates(members).await;
        let snapshot: Vec<Vec<DoorView>> = self
            .hosts
            .iter()
            .map(|h| {
                door_views(
                    &h.doors,
                    members,
                    |id| self.gate.committed(id),
                    |a| self.readiness.ready(&h.name, a),
                )
            })
            .collect();
        if !self.cadence.due(now, &snapshot) {
            return None;
        }
        let mut outcomes = Vec::with_capacity(self.hosts.len());
        let mut ok = true;
        for (host, doors) in self.hosts.iter().zip(&snapshot) {
            let res = match reconcile_host(self.dns.as_ref(), host, doors, quorate).await {
                Ok((plan, after)) => {
                    self.last_actual.insert(host.name.clone(), after);
                    Ok(plan)
                }
                Err(e) => Err(e),
            };
            log_outcome(host, doors, &res);
            ok &= res.is_ok();
            outcomes.push((host.name.clone(), res));
        }
        self.cadence.record(now, snapshot, ok);
        Some(outcomes)
    }
}

fn log_outcome(host: &ManagedHost, doors: &[DoorView], res: &Result<HostPlan>) {
    match res {
        Err(e) => warn!(host = %host.name, "door DNS reconcile failed, will retry: {e:#}"),
        Ok(plan) => {
            if !plan.add.is_empty() {
                info!(host = %host.name, added = ?plan.add, "door DNS: re-added live doors");
            }
            if !plan.delete.is_empty() {
                info!(host = %host.name, withdrawn = ?plan.delete, "door DNS: withdrew dead doors");
            }
            match &plan.hold {
                Some((Hold::AllDoorsDown, withheld)) => error!(
                    host = %host.name,
                    withheld = ?withheld,
                    doors = ?doors,
                    "door DNS: EVERY door of this hostname reads dead, so its record set is \
                     left untouched (never empty a set; R936-B7). Either the fleet is down or \
                     this leader's liveness is wrong. Check /raft/status lease_liveness."
                ),
                Some((Hold::WouldEmpty, withheld)) => error!(
                    host = %host.name,
                    withheld = ?withheld,
                    doors = ?doors,
                    "door DNS: withdrawing the dead doors would empty this hostname, so they \
                     stay in rotation (R936-B7)"
                ),
                Some((Hold::NotQuorate, withheld)) => warn!(
                    host = %host.name,
                    withheld = ?withheld,
                    "door DNS: leader is not quorate, so dead doors are not withdrawn this tick"
                ),
                None if plan.is_noop() => debug!(host = %host.name, "door DNS: in sync"),
                None => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure_detector::{NodeLiveness, NodeObservation};
    use std::sync::Mutex;

    const A: &str = "15.204.89.240";
    const B: &str = "51.81.85.145";
    const C: &str = "45.32.194.254";

    /// A door whose readiness matches its liveness (an Up door is serving);
    /// the readiness tests below build the not-ready case explicitly.
    fn door(machine: &str, addr: &str, l: DoorLiveness) -> DoorView {
        DoorView {
            machine: machine.into(),
            address: Some(addr.into()),
            liveness: l,
            ready: l == DoorLiveness::Up,
        }
    }

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    fn three(a: DoorLiveness, b: DoorLiveness, c: DoorLiveness) -> Vec<DoorView> {
        vec![door("west", A, a), door("south", B, b), door("east", C, c)]
    }

    use DoorLiveness::{Down, Unconfirmed as Unc, Up};

    // ---- plan_host --------------------------------------------------------

    #[test]
    fn a_dead_door_is_withdrawn_and_the_live_ones_stay() {
        let p = plan_host(&three(Up, Down, Up), &set(&[A, B, C]), true);
        assert_eq!(p.delete, vec![B.to_string()]);
        assert!(p.add.is_empty());
        assert_eq!(p.hold, None);
    }

    #[test]
    fn a_recovered_door_is_re_added() {
        let p = plan_host(&three(Up, Up, Up), &set(&[A, C]), true);
        assert_eq!(p.add, vec![B.to_string()]);
        assert!(p.delete.is_empty());
    }

    #[test]
    fn an_in_sync_set_plans_nothing() {
        assert!(plan_host(&three(Up, Up, Up), &set(&[A, B, C]), true).is_noop());
        // Already withdrawn: the ordinary steady state during an outage.
        assert!(plan_host(&three(Up, Down, Up), &set(&[A, C]), true).is_noop());
    }

    #[test]
    fn all_dead_leaves_the_set_alone() {
        let p = plan_host(&three(Down, Down, Down), &set(&[A, B, C]), true);
        assert!(p.is_noop(), "{p:?}");
        let (h, withheld) = p.hold.expect("must say why");
        assert_eq!(h, Hold::AllDoorsDown);
        assert_eq!(withheld.len(), 3);
    }

    #[test]
    fn all_dead_is_left_alone_even_with_an_unmanaged_record_present() {
        // Operator rule: "if every lease reads dead, leave the set alone",
        // not just "don't empty it".
        let p = plan_host(&three(Down, Down, Down), &set(&[A, B, C, "9.9.9.9"]), true);
        assert!(p.is_noop());
        assert_eq!(p.hold.unwrap().0, Hold::AllDoorsDown);
    }

    #[test]
    fn the_last_record_is_never_withdrawn() {
        // Only one door left in DNS, and it is the dead one, and the others
        // are unconfirmed (so nothing to add): refuse.
        let p = plan_host(&three(Unc, Down, Unc), &set(&[B]), true);
        assert!(p.is_noop());
        assert_eq!(p.hold.unwrap().0, Hold::WouldEmpty);
        // Two dead records, the rest unconfirmed and absent: still refuse.
        let p = plan_host(&three(Down, Down, Unc), &set(&[A, B]), true);
        assert!(p.is_noop());
        assert_eq!(p.hold.unwrap().0, Hold::WouldEmpty);
    }

    #[test]
    fn a_withdrawal_that_empties_the_set_is_refused_even_with_a_live_door_absent() {
        // Live door C can't be re-added (no address in its row), dead B is the
        // only record. Removing B would empty the name.
        let doors = vec![
            door("south", B, Down),
            DoorView {
                machine: "east".into(),
                address: None,
                liveness: Up,
                ready: false,
            },
        ];
        let p = plan_host(&doors, &set(&[B]), true);
        assert!(p.delete.is_empty());
        assert_eq!(p.hold.unwrap().0, Hold::AllDoorsDown);
    }

    #[test]
    fn a_swap_adds_before_it_withdraws_and_is_permitted() {
        // Only B in DNS and B is dead; A is live and absent. The plan may
        // withdraw B because A is added in the same plan.
        let p = plan_host(&three(Up, Down, Unc), &set(&[B]), true);
        assert_eq!(p.add, vec![A.to_string()]);
        assert_eq!(p.delete, vec![B.to_string()]);
    }

    #[test]
    fn unconfirmed_doors_are_neither_added_nor_withdrawn() {
        let p = plan_host(&three(Unc, Unc, Unc), &set(&[A]), true);
        assert!(p.is_noop());
        assert_eq!(p.hold, None);
    }

    #[test]
    fn records_outside_the_door_set_are_never_touched() {
        let p = plan_host(&three(Down, Up, Up), &set(&[A, B, C, "9.9.9.9"]), true);
        assert_eq!(p.delete, vec![A.to_string()]);
        assert!(!p.delete.contains(&"9.9.9.9".to_string()));
    }

    #[test]
    fn a_door_without_an_address_is_ignored() {
        let doors = vec![
            door("west", A, Up),
            DoorView {
                machine: "ghost".into(),
                address: None,
                liveness: Down,
                ready: false,
            },
        ];
        assert!(plan_host(&doors, &set(&[A]), true).is_noop());
    }

    #[test]
    fn a_shared_address_is_withdrawn_only_when_every_door_behind_it_is_down() {
        let doors = vec![door("a", A, Down), door("b", A, Unc), door("c", B, Up)];
        assert!(plan_host(&doors, &set(&[A, B]), true).delete.is_empty());
        let doors = vec![door("a", A, Down), door("b", A, Down), door("c", B, Up)];
        assert_eq!(
            plan_host(&doors, &set(&[A, B]), true).delete,
            vec![A.to_string()]
        );
    }

    #[test]
    fn a_non_quorate_leader_may_add_but_not_withdraw() {
        let p = plan_host(&three(Up, Down, Up), &set(&[A, B]), false);
        assert_eq!(p.add, vec![C.to_string()]);
        assert!(p.delete.is_empty());
        assert_eq!(p.hold, Some((Hold::NotQuorate, vec![B.to_string()])));
    }

    #[test]
    fn two_dead_of_three_keeps_the_survivor_only() {
        let p = plan_host(&three(Down, Down, Up), &set(&[A, B, C]), true);
        assert_eq!(p.delete, vec![A.to_string(), B.to_string()]);
    }

    #[test]
    fn flapping_liveness_plans_converge_and_are_idempotent() {
        // Apply each plan to a model zone; alternating verdicts must alternate
        // the record, never empty the set, and re-planning a converged state
        // must be a no-op.
        let mut zone = set(&[A, B, C]);
        for i in 0..20 {
            let b = if i % 2 == 0 { Down } else { Up };
            let doors = three(Up, b, Up);
            let p = plan_host(&doors, &zone, true);
            for a in &p.add {
                zone.insert(a.clone());
            }
            for d in &p.delete {
                zone.remove(d);
            }
            assert!(!zone.is_empty());
            assert_eq!(zone.contains(B), b == Up, "tick {i}");
            assert!(
                plan_host(&doors, &zone, true).is_noop(),
                "tick {i} not idempotent"
            );
        }
    }

    // ---- config -----------------------------------------------------------

    const CFG: &str = r#"
token_file = "/run/yah/secrets/x/cf.token"

[[host]]
name = "yah.dev"
zone_id = "z1"
doors = ["us-west-001", "us-south-001", "us-east-001"]

[[host]]
name = "cloud.mesh.yah.dev"
zone_id = "z1"
doors = ["us-west-001", "us-south-001", "us-east-001"]
"#;

    #[test]
    fn config_parses_and_validates() {
        let cfg = parse_config(CFG).unwrap();
        assert_eq!(cfg.hosts.len(), 2);
        assert_eq!(cfg.hosts[1].name, "cloud.mesh.yah.dev");
        assert!(parse_config("token_file = \"x\"\nhost = []").is_err());
        assert!(parse_config(&CFG.replace("\"us-east-001\"", "\"\"")).is_err());
        assert!(parse_config(&CFG.replace("cloud.mesh.yah.dev", "YAH.dev"))
            .unwrap_err()
            .contains("twice"));
        assert!(parse_config(&format!("{CFG}\nbogus = 1")).is_err());
    }

    // ---- door_views -------------------------------------------------------

    fn member(machine: &str, addr: Option<&str>) -> MemberInfo {
        serde_json::from_value(serde_json::json!({
            "addr": "100.64.0.1:7443",
            "machine": machine,
            "public_address": addr,
        }))
        .unwrap()
    }

    #[test]
    fn door_views_resolve_machine_to_row_and_verdict() {
        let members = BTreeMap::from([
            (1, member("us-west-001", Some(A))),
            (2, member("us-south-001", Some(B))),
            (3, member("dup", Some(C))),
            (4, member("dup", Some(C))),
        ]);
        let doors: Vec<String> = ["us-west-001", "us-south-001", "missing", "dup"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let v = door_views(
            &doors,
            &members,
            |id| match id {
                1 => Some(Confirmed::Up),
                2 => Some(Confirmed::Down),
                _ => Some(Confirmed::Down),
            },
            |_| true,
        );
        assert_eq!(v[0], door("us-west-001", A, Up));
        assert_eq!(v[1], door("us-south-001", B, Down));
        assert_eq!(v[2].address, None);
        assert_eq!(v[2].liveness, Unc);
        // Two rows for one machine: ambiguous, never acted on.
        assert_eq!(v[3], door("dup", C, Unc));
    }

    // ---- gate ---------------------------------------------------------------

    fn report(entries: &[(YubabaNodeId, NodeLiveness)]) -> LivenessReport {
        entries
            .iter()
            .map(|(id, l)| {
                (
                    *id,
                    NodeObservation {
                        liveness: *l,
                        silent_for_ms: Some(0),
                    },
                )
            })
            .collect()
    }

    fn timing(settle: Duration) -> FenceTiming {
        FenceTiming::from_thresholds(crate::cluster_policy::LivenessThresholds {
            suspect_after: settle / 2,
            down_after: settle,
        })
    }

    fn hyst() -> HysteresisPolicy {
        HysteresisPolicy {
            confirm_down_after: Duration::from_secs(5),
            confirm_up_after: Duration::from_millis(1500),
        }
    }

    #[test]
    fn a_follower_never_arms() {
        let mut g = DoorDnsGate::new(timing(Duration::from_secs(5)));
        let t0 = Instant::now();
        let r = report(&[(2, NodeLiveness::Down)]);
        for s in 0..60 {
            assert!(!g.observe(false, t0 + Duration::from_secs(s), &r, hyst()));
        }
        assert_eq!(g.committed(2), None);
    }

    #[test]
    fn a_fresh_leader_does_not_arm_until_settled_and_ignores_pre_settle_evidence() {
        let settle = Duration::from_secs(5);
        let mut g = DoorDnsGate::new(timing(settle));
        let t0 = Instant::now();
        // Stale renewal times make node 2 read Down the instant we lead.
        let stale = report(&[(2, NodeLiveness::Down)]);
        for ms in (0..5000).step_by(500) {
            assert!(!g.observe(true, t0 + Duration::from_millis(ms), &stale, hyst()));
        }
        assert_eq!(g.committed(2), None, "fed evidence before the settle gate");
        // Settled: renewals have arrived, node 2 is live.
        let live = report(&[(2, NodeLiveness::Live)]);
        assert!(g.observe(true, t0 + settle, &live, hyst()));
        assert!(g.observe(true, t0 + settle + Duration::from_secs(2), &live, hyst()));
        assert_eq!(g.committed(2), Some(Confirmed::Up));
    }

    #[test]
    fn losing_leadership_forgets_every_verdict() {
        let settle = Duration::from_secs(5);
        let mut g = DoorDnsGate::new(timing(settle));
        let t0 = Instant::now();
        let down = report(&[(2, NodeLiveness::Down)]);
        for s in 0..20 {
            g.observe(true, t0 + Duration::from_secs(s), &down, hyst());
        }
        assert_eq!(g.committed(2), Some(Confirmed::Down));

        // Leadership moves away and back. The old Down must not survive, and
        // the new term must settle again before anything commits.
        let t1 = t0 + Duration::from_secs(30);
        assert!(!g.observe(false, t1, &down, hyst()));
        assert_eq!(g.committed(2), None);
        assert!(!g.observe(true, t1 + Duration::from_secs(1), &down, hyst()));
        assert_eq!(g.committed(2), None);
    }

    // ---- cadence --------------------------------------------------------------

    #[test]
    fn cadence_runs_on_change_on_period_and_backs_off_after_failure() {
        let mut c = Cadence::new(Duration::from_secs(30), Duration::from_secs(10));
        let t0 = Instant::now();
        let s1 = vec![three(Up, Up, Up)];
        let s2 = vec![three(Up, Down, Up)];
        assert!(c.due(t0, &s1), "first run is always due");
        c.record(t0, s1.clone(), true);
        assert!(!c.due(t0 + Duration::from_secs(1), &s1));
        assert!(
            c.due(t0 + Duration::from_secs(1), &s2),
            "a liveness change is urgent"
        );
        assert!(
            c.due(t0 + Duration::from_secs(30), &s1),
            "drift repair period"
        );
        c.record(t0 + Duration::from_secs(31), s2.clone(), false);
        assert!(!c.due(t0 + Duration::from_secs(35), &s2), "backing off");
        assert!(c.due(t0 + Duration::from_secs(41), &s2));
    }

    // ---- reconcile_host / DoorDns over a fake zone --------------------------

    #[derive(Default)]
    struct FakeZone {
        rows: Mutex<Vec<ARecord>>,
        log: Mutex<Vec<String>>,
        fail_list: bool,
    }

    impl FakeZone {
        fn with(addrs: &[&str]) -> Self {
            let z = FakeZone::default();
            *z.rows.lock().unwrap() = addrs
                .iter()
                .enumerate()
                .map(|(i, a)| ARecord {
                    id: format!("r{i}"),
                    content: a.to_string(),
                    ttl: 60,
                    proxied: false,
                })
                .collect();
            z
        }
        fn contents(&self) -> BTreeSet<String> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.content.clone())
                .collect()
        }
    }

    #[async_trait]
    impl DoorRecords for FakeZone {
        async fn list_a(&self, zone_id: &str, name: &str) -> Result<Vec<ARecord>> {
            anyhow::ensure!(!self.fail_list, "cloudflare down");
            self.log
                .lock()
                .unwrap()
                .push(format!("list {zone_id} {name}"));
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn create_a(
            &self,
            _zone_id: &str,
            name: &str,
            content: &str,
            ttl: u32,
            proxied: bool,
        ) -> Result<()> {
            self.log.lock().unwrap().push(format!(
                "create {name} {content} ttl={ttl} proxied={proxied}"
            ));
            let mut rows = self.rows.lock().unwrap();
            let id = format!("n{}", rows.len() + 100);
            rows.push(ARecord {
                id,
                content: content.into(),
                ttl,
                proxied,
            });
            Ok(())
        }
        async fn delete_record(&self, _zone_id: &str, record_id: &str) -> Result<()> {
            self.log.lock().unwrap().push(format!("delete {record_id}"));
            self.rows.lock().unwrap().retain(|r| r.id != record_id);
            Ok(())
        }
    }

    fn host() -> ManagedHost {
        ManagedHost {
            name: "yah.dev".into(),
            zone_id: "z1".into(),
            doors: vec![
                "us-west-001".into(),
                "us-south-001".into(),
                "us-east-001".into(),
            ],
        }
    }

    #[tokio::test]
    async fn reconcile_adds_first_copies_shape_and_deletes_every_duplicate() {
        let zone = FakeZone::with(&[B, B]);
        let doors = three(Up, Down, Unc);
        let (_, after) = reconcile_host(&zone, &host(), &doors, true).await.unwrap();
        assert_eq!(after, set(&[A]));
        let log = zone.log.lock().unwrap().clone();
        assert_eq!(
            log,
            vec![
                "list z1 yah.dev".to_string(),
                format!("create yah.dev {A} ttl=60 proxied=false"),
                "delete r0".into(),
                "delete r1".into(),
            ]
        );
        assert_eq!(zone.contents(), set(&[A]));
    }

    /// Per-address probe answers (default 200), switchable mid-test, with a
    /// call log so "no probes in steady state" is assertable.
    #[derive(Default)]
    struct FakeProbe {
        answers: Mutex<BTreeMap<String, ProbeOutcome>>,
        calls: Mutex<Vec<(String, String)>>,
    }

    impl FakeProbe {
        fn ok() -> Arc<FakeProbe> {
            Arc::new(FakeProbe::default())
        }
        fn set(&self, addr: &str, o: ProbeOutcome) {
            self.answers.lock().unwrap().insert(addr.into(), o);
        }
    }

    #[async_trait]
    impl DoorProbe for FakeProbe {
        async fn probe(&self, host: &str, address: &str) -> ProbeOutcome {
            self.calls
                .lock()
                .unwrap()
                .push((host.into(), address.into()));
            self.answers
                .lock()
                .unwrap()
                .get(address)
                .cloned()
                .unwrap_or(ProbeOutcome::Status(200))
        }
    }

    // ---- readiness ------------------------------------------------------------

    fn not_ready(mut v: Vec<DoorView>, addr: &str) -> Vec<DoorView> {
        for d in &mut v {
            if d.address.as_deref() == Some(addr) {
                d.ready = false;
            }
        }
        v
    }

    #[test]
    fn lease_live_but_door_not_serving_adds_nothing() {
        let p = plan_host(&not_ready(three(Up, Up, Up), B), &set(&[A, C]), true);
        assert!(p.is_noop(), "{p:?}");
        // Once ready, it is added.
        let p = plan_host(&three(Up, Up, Up), &set(&[A, C]), true);
        assert_eq!(p.add, vec![B.to_string()]);
    }

    #[test]
    fn an_unready_swap_partner_cannot_justify_emptying_the_set() {
        // Only dead B is in DNS; A is lease-live but not serving yet. The swap
        // must not happen: no add, so the withdrawal would empty the name.
        let p = plan_host(&not_ready(three(Up, Down, Unc), A), &set(&[B]), true);
        assert!(p.is_noop());
        assert_eq!(p.hold.unwrap().0, Hold::WouldEmpty);
    }

    #[test]
    fn door_views_ready_only_for_up_doors() {
        let members = fleet_members();
        let doors: Vec<String> = vec!["us-west-001".into(), "us-south-001".into()];
        let v = door_views(
            &doors,
            &members,
            |id| (id == 1).then_some(Confirmed::Up).or(Some(Confirmed::Down)),
            |_| true,
        );
        assert!(v[0].ready);
        assert!(
            !v[1].ready,
            "a Down door is never ready, whatever the probe says"
        );
    }

    fn pr(addr: &str, in_rotation: bool, o: ProbeOutcome) -> ProbeResult {
        ProbeResult {
            address: addr.into(),
            in_rotation,
            outcome: o,
        }
    }

    #[test]
    fn judge_probes_rules() {
        use ProbeOutcome::{Failed, Status};
        // Healthy site: a candidate 503 fails, 200/301/404 pass, transport fails.
        let v = judge_probes(&[
            pr(A, true, Status(200)),
            pr(B, false, Status(503)),
            pr(C, false, Status(301)),
        ]);
        assert!(!v[B]);
        assert!(v[C]);
        let v = judge_probes(&[pr(A, true, Status(200)), pr(B, false, Failed("x".into()))]);
        assert!(!v[B]);
        // Site down everywhere (scrabcake's standing 503): a candidate that
        // answers at all is as good as the doors in rotation.
        let v = judge_probes(&[pr(A, true, Status(503)), pr(B, false, Status(503))]);
        assert!(v[B]);
        // ...but a transport failure still never passes.
        let v = judge_probes(&[pr(A, true, Status(503)), pr(B, false, Failed("x".into()))]);
        assert!(!v[B]);
        // Baselines are not candidates.
        assert!(!v.contains_key(A));
    }

    #[test]
    fn readiness_needs_consecutive_passes_and_forgets_on_absence() {
        let mut r = DoorReadiness::default();
        let pass = BTreeMap::from([(B.to_string(), true)]);
        let fail = BTreeMap::from([(B.to_string(), false)]);
        r.observe("yah.dev", &pass);
        r.observe("yah.dev", &pass);
        assert!(!r.ready("yah.dev", B));
        r.observe("yah.dev", &fail);
        r.observe("yah.dev", &pass);
        r.observe("yah.dev", &pass);
        assert!(!r.ready("yah.dev", B), "a failure resets the streak");
        r.observe("yah.dev", &pass);
        assert!(r.ready("yah.dev", B));
        assert!(!r.ready("noisetable.com", B), "readiness is per hostname");
        r.observe("yah.dev", &BTreeMap::new());
        assert!(!r.ready("yah.dev", B), "no longer a candidate: forgotten");
    }

    fn fleet_members() -> BTreeMap<YubabaNodeId, MemberInfo> {
        BTreeMap::from([
            (1, member("us-west-001", Some(A))),
            (2, member("us-south-001", Some(B))),
            (3, member("us-east-001", Some(C))),
        ])
    }

    /// Drive a [`DoorDns`] through leadership + a door outage + recovery
    /// against a fake zone, one second per tick, as the scheduler would.
    async fn run_ticks(
        d: &mut DoorDns,
        t0: Instant,
        from: u64,
        to: u64,
        is_leader: bool,
        south: NodeLiveness,
    ) {
        let members = fleet_members();
        for s in from..to {
            let now = t0 + Duration::from_secs(s);
            let r = report(&[(1, NodeLiveness::Live), (2, south), (3, NodeLiveness::Live)]);
            d.observe(is_leader, now, &r, hyst());
            if is_leader {
                d.reconcile_if_due(now, &members, true).await;
            }
        }
    }

    #[tokio::test]
    async fn outage_and_recovery_end_to_end() {
        let zone = Arc::new(FakeZone::with(&[A, B, C]));
        let mut d = DoorDns::new(
            vec![host()],
            zone.clone(),
            FakeProbe::ok(),
            timing(Duration::from_secs(5)),
        );
        let t0 = Instant::now();
        run_ticks(&mut d, t0, 0, 10, true, NodeLiveness::Live).await;
        assert_eq!(zone.contents(), set(&[A, B, C]));
        run_ticks(&mut d, t0, 10, 20, true, NodeLiveness::Down).await;
        assert_eq!(zone.contents(), set(&[A, C]), "dead south withdrawn");
        run_ticks(&mut d, t0, 20, 30, true, NodeLiveness::Live).await;
        assert_eq!(zone.contents(), set(&[A, B, C]), "south re-added");
    }

    #[tokio::test]
    async fn a_new_leader_converges_from_dns_alone_without_rewriting() {
        // Old leader withdrew south, then leadership moved. A brand-new
        // DoorDns (no memory) must see south still down, write nothing, and
        // re-add once south is live.
        let zone = Arc::new(FakeZone::with(&[A, C]));
        let mut d = DoorDns::new(
            vec![host()],
            zone.clone(),
            FakeProbe::ok(),
            timing(Duration::from_secs(5)),
        );
        let t0 = Instant::now();
        run_ticks(&mut d, t0, 0, 15, true, NodeLiveness::Down).await;
        assert!(
            zone.log
                .lock()
                .unwrap()
                .iter()
                .all(|l| l.starts_with("list")),
            "idempotent: {:?}",
            zone.log.lock().unwrap()
        );
        run_ticks(&mut d, t0, 15, 25, true, NodeLiveness::Live).await;
        assert_eq!(zone.contents(), set(&[A, B, C]));
    }

    #[tokio::test]
    async fn a_door_is_re_added_only_after_it_serves_three_ticks_running() {
        let zone = Arc::new(FakeZone::with(&[A, B, C]));
        let probe = FakeProbe::ok();
        let mut d = DoorDns::new(
            vec![host()],
            zone.clone(),
            probe.clone(),
            timing(Duration::from_secs(5)),
        );
        let t0 = Instant::now();
        run_ticks(&mut d, t0, 0, 10, true, NodeLiveness::Live).await;
        assert!(
            probe.calls.lock().unwrap().is_empty(),
            "no candidates, no probes"
        );
        run_ticks(&mut d, t0, 10, 20, true, NodeLiveness::Down).await;
        assert_eq!(zone.contents(), set(&[A, C]));
        // Lease live again from t=20, but the door answers 503 (the prod
        // 2026-09-23 shape) until t=35.
        probe.set(B, ProbeOutcome::Status(503));
        run_ticks(&mut d, t0, 20, 35, true, NodeLiveness::Live).await;
        assert_eq!(
            zone.contents(),
            set(&[A, C]),
            "re-added before the door served"
        );
        assert!(zone
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.starts_with("create")));
        // The in-rotation doors were probed as the baseline.
        assert!(probe.calls.lock().unwrap().iter().any(|(_, a)| a == A));
        probe.set(B, ProbeOutcome::Status(200));
        run_ticks(&mut d, t0, 35, 37, true, NodeLiveness::Live).await;
        assert_eq!(zone.contents(), set(&[A, C]), "two passes are not three");
        run_ticks(&mut d, t0, 37, 40, true, NodeLiveness::Live).await;
        assert_eq!(zone.contents(), set(&[A, B, C]));
        // Back in rotation: probing stops.
        let n = probe.calls.lock().unwrap().len();
        run_ticks(&mut d, t0, 40, 50, true, NodeLiveness::Live).await;
        assert_eq!(probe.calls.lock().unwrap().len(), n);
    }

    #[tokio::test]
    async fn a_site_down_everywhere_still_gets_its_door_back() {
        // A site that answers 503 on every door (scrabcake.com until
        // R936-T14): its returning door must still be re-added once it
        // answers like its peers.
        let zone = Arc::new(FakeZone::with(&[A, C]));
        let probe = FakeProbe::ok();
        for a in [A, B, C] {
            probe.set(a, ProbeOutcome::Status(503));
        }
        let mut d = DoorDns::new(
            vec![host()],
            zone.clone(),
            probe.clone(),
            timing(Duration::from_secs(5)),
        );
        let t0 = Instant::now();
        run_ticks(&mut d, t0, 0, 15, true, NodeLiveness::Live).await;
        assert_eq!(zone.contents(), set(&[A, B, C]));
    }

    #[tokio::test]
    async fn an_unreachable_door_is_never_re_added() {
        let zone = Arc::new(FakeZone::with(&[A, C]));
        let probe = FakeProbe::ok();
        probe.set(B, ProbeOutcome::Failed("connect refused".into()));
        let mut d = DoorDns::new(
            vec![host()],
            zone.clone(),
            probe.clone(),
            timing(Duration::from_secs(5)),
        );
        let t0 = Instant::now();
        run_ticks(&mut d, t0, 0, 60, true, NodeLiveness::Live).await;
        assert_eq!(zone.contents(), set(&[A, C]));
    }

    #[tokio::test]
    async fn a_follower_never_lists_or_writes() {
        let zone = Arc::new(FakeZone::with(&[A, B, C]));
        let mut d = DoorDns::new(
            vec![host()],
            zone.clone(),
            FakeProbe::ok(),
            timing(Duration::from_secs(5)),
        );
        let t0 = Instant::now();
        let members = fleet_members();
        for s in 0..30 {
            let now = t0 + Duration::from_secs(s);
            d.observe(false, now, &report(&[(2, NodeLiveness::Down)]), hyst());
            assert!(d.reconcile_if_due(now, &members, true).await.is_none());
        }
        assert!(zone.log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_re_elected_leader_with_stale_renewals_does_not_withdraw_a_live_door() {
        // Stale renewal Instants make south read Down for the first seconds of
        // the new term. Before the renewals refresh (inside the settle window)
        // that must commit nothing.
        let zone = Arc::new(FakeZone::with(&[A, B, C]));
        let mut d = DoorDns::new(
            vec![host()],
            zone.clone(),
            FakeProbe::ok(),
            timing(Duration::from_secs(5)),
        );
        let t0 = Instant::now();
        run_ticks(&mut d, t0, 0, 4, true, NodeLiveness::Down).await;
        run_ticks(&mut d, t0, 4, 30, true, NodeLiveness::Live).await;
        assert_eq!(zone.contents(), set(&[A, B, C]));
        assert!(zone
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.starts_with("delete")));
    }

    #[tokio::test]
    async fn a_failed_list_is_retried_after_backoff() {
        let zone = Arc::new(FakeZone {
            fail_list: true,
            ..FakeZone::default()
        });
        let mut d = DoorDns::new(
            vec![host()],
            zone.clone(),
            FakeProbe::ok(),
            timing(Duration::ZERO),
        );
        let t0 = Instant::now();
        let members = fleet_members();
        let r = report(&[(1, NodeLiveness::Live)]);
        d.observe(true, t0, &r, hyst());
        let out = d.reconcile_if_due(t0, &members, true).await.unwrap();
        assert!(out[0].1.is_err());
        d.observe(true, t0 + Duration::from_secs(1), &r, hyst());
        assert!(d
            .reconcile_if_due(t0 + Duration::from_secs(1), &members, true)
            .await
            .is_none());
        d.observe(true, t0 + DoorDns::RETRY_AFTER, &r, hyst());
        assert!(d
            .reconcile_if_due(t0 + DoorDns::RETRY_AFTER, &members, true)
            .await
            .is_some());
    }
}
