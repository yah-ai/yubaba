//! Upstream-discovery read-model (R594-F3): serving-workload → mesh-IP:port
//! + health, queryable by a future ingress proxy (R594-F4).
//!
//! ## Why this lives here, not in `cloud::mesh_service`
//!
//! `cloud/src/mesh_service.rs` is compose-recipe helpers — constants and
//! string-builders (`pg_hba_snippet`, `ufw_rules_for_mesh_port`,
//! `mesh_ip_env_runcmd`) that render config *before* a workload exists.
//! It has no notion of a live workload registry and holds no state. This
//! module is the opposite shape: a stateful, queryable record of workloads
//! yubaba has *already placed and knows the mesh address of* — that's
//! workload-placement bookkeeping, which is yubaba-proper's job (yubaba
//! already owns `ServerState`, `alloc_mesh_ip`, and the `ContainerRuntime` /
//! `kamaji::Kamaji` dispatch that this module reads from). Homing a
//! queryable service-record surface in the cloud crate would duplicate (or
//! reach back into) state yubaba already holds.
//!
//! ## Placement source of truth
//!
//! Yubaba never invents a parallel store of "what's running where" — it
//! already has two facts, at two different moments, and this module
//! combines them instead of re-deriving either:
//!
//! 1. **At deploy time** ([`ServiceRecords::upsert_deployed`]): the handler
//!    that calls `ContainerRuntime::deploy_workload` (`POST
//!    /workloads/deploy` in `lib.rs`) has both the [`WorkloadSpec`] (which
//!    carries `expose.mesh.ports` — the only place a workload's serving
//!    port(s) are declared) and the [`kamaji::DeployResult`] (which carries
//!    the mesh IP yubaba just allocated via `ServerState::alloc_mesh_ip`).
//!    That pairing is admission-time knowledge that exists nowhere else.
//! 2. **On every subsequent read** ([`ServiceRecords::reconcile`]): the
//!    exact same call `GET /workloads` already makes —
//!    `ContainerRuntime::list_workloads()` → `Vec<`[`WorkloadState`]`>` — is
//!    the authoritative "what does the runtime think is running right now"
//!    source. `WorkloadState` carries `status` + (usually) `mesh_ip` but
//!    *not* ports, which is exactly why step 1 must supply them first.
//!
//! `reconcile` therefore only refreshes/retracts idents it already knows
//! about — it does not fabricate a record for an ident it has never seen,
//! because it would have no port to publish for it (a record without a port
//! is not something an ingress proxy can dial). `reconcile` is purely a
//! health/liveness refresh; it is never a discovery path.
//!
//! Records enter the registry by exactly two routes, both carrying ports:
//! admission ([`ServiceRecords::upsert_deployed`]) and, on boot, the port
//! ledger written by prior admissions (§The port ledger below). Cold-
//! discovering a *never-admitted* workload's ports from `WorkloadState`
//! alone remains impossible until the wire/state shape grows a ports field
//! (the other option R594-F6 weighed — see that ticket, and `lib.rs`'s
//! R406-T8 handoff note about enriching `WorkloadEntry` with `mesh_ip` +
//! friends). That gap only bites a workload some *other* yubaba admitted,
//! which is not a shape this node can serve anyway.
//!
//! ## Push-on-change over polling
//!
//! Per the platform's mesh-cost rule (cost-of-deciding << cost-of-acting;
//! keep idle CPU near zero), this module publishes via
//! [`tokio::sync::watch`] rather than exposing only a poll-and-diff
//! snapshot API. `watch` is a single-slot "latest value" cell with waker
//! fanout: a subscriber's `changed().await` resolves only when
//! [`ServiceRecords::upsert_deployed`], [`ServiceRecords::reconcile`], or
//! [`ServiceRecords::retract`] actually publishes a new snapshot — no
//! background loop, no timer, nothing to poll. A synchronous
//! [`ServiceRecords::snapshot`] is also exposed for callers (or tests) that
//! just want the current state without subscribing.
//!
//! ## Health signal
//!
//! [`Health`] mirrors the `GET /mesh/leader-health` pattern already used
//! for the Cloudflare healthcheck: a boolean gate ([`Health::is_ready`])
//! plus enough detail to explain *why* not, so an ingress proxy can skip a
//! not-ready upstream instead of routing traffic into a black hole.
//! `Running` is the only ready state; every other [`WorkloadStatus`] value,
//! and a workload's absence from the runtime's own list, are not-ready.
//!
//! ## Wiring (R594-F6)
//!
//! R594-F3 shipped this as a tested-but-unwired mechanism. F6 makes it live:
//!
//! - **Producer**: `deploy_workload_spec` calls [`ServiceRecords::upsert_deployed`]
//!   on a successful deploy (beside the `archetype_registry` /
//!   `workload_resources` inserts it already does), and `destroy_workload`
//!   calls [`ServiceRecords::retract`] beside the matching removals.
//! - **Refresh**: [`run`] is a background sweep — `active_backend()`
//!   `.list_workloads()` → [`ServiceRecords::reconcile`] every
//!   [`SWEEP_INTERVAL`] — because health can change without a yubaba-initiated
//!   action (a container crash is nobody's HTTP request). This is the one
//!   poll in the design and it is deliberately slow; every *state-changing*
//!   event still pushes immediately through the `watch`.
//! - **Restart survival**: see §The port ledger below.
//!
//! ## The port ledger — why records survive a yubaba restart
//!
//! Ports are admission-time knowledge. `WorkloadState` (what
//! `list_workloads()` returns) carries `ident` / `container_id` / `status` /
//! `mesh_ip` but **no ports**, so after a yubaba restart the sweep alone can
//! never rebuild a dialable record: it would know a workload is `Running` and
//! know its mesh IP, and still have nothing to dial. Before this ticket the
//! only recovery was to redeploy every serving workload — the containers were
//! fine, yubaba had merely forgotten the one number it never re-derives.
//!
//! Two ways to close that, both named in the ticket: (a) grow a serving-port
//! field on `WorkloadState` / the kamaji list wire, or (b) persist the
//! deploy-time `ident → ports` map locally. This module takes **(b)** — it is
//! strictly node-local, touches no shared wire (`kamaji-proto` is a
//! cross-repo contract with its own sequencing), and the knowledge being
//! persisted is knowledge yubaba *originated*, so no other component has a
//! better claim to store it.
//!
//! The ledger is a small JSON file ([`LEDGER_FILE_NAME`]) written beside
//! `identity.json`, rewritten atomically (via `identity::atomic_write_json`)
//! on every publish. It holds exactly the currently-non-retracted records, so
//! a workload torn down before shutdown does not come back on boot.
//!
//! **Rehydrated records are deliberately NOT `Ready`.** They come back as
//! `NotReady { reason: "rehydrated" }`: the ports and mesh IP are recovered
//! facts, but "is it running *right now*" is not — the process may have died
//! while yubaba was down. The first successful sweep promotes a genuinely-
//! running workload to `Ready` and retracts one that is gone. An ingress proxy
//! gating on [`Health::is_ready`] therefore never routes traffic into a
//! black hole on the strength of a stale file (fail-ready, matching the
//! cold-start posture R594-F4's proxy already takes).
//!
//! ## The discovery surface (R594-F8) — how passway learns its upstreams
//!
//! Everything above is in-process. An ingress proxy is a *separate binary*,
//! typically on a separate rented-doorknob node, so the registry needs a
//! network surface before it can back a front door: [`DISCOVERY_PATH`]
//! (`GET /service-records`), served by [`get_service_records`] and wired into
//! `build_router`. `?ready=true` filters server-side to
//! [`Health::is_ready`] records, which is the only query an ingress proxy
//! actually makes.
//!
//! This is the sovereign twin of the rented arm. Both ingress providers
//! answer one question — *given the workloads this fleet has placed, make
//! them publicly reachable* — and both derive their config from the same
//! placement facts rather than from a hand-written upstream list:
//!
//! | | rented (`cloudflare-tunnel`) | sovereign (`passway`) |
//! |---|---|---|
//! | Where ingress rules live | Cloudflare's API (remotely-managed tunnel) | the proxy process's own `Backends` set |
//! | How they get there | an API call per deployed workload | passway polls [`DISCOVERY_PATH`] |
//! | Source of truth | this registry | this registry |
//!
//! Wire shape is [`ServiceRecordsWire`], deliberately a *separate* type from
//! [`ServiceRecord`]: passway lives in its own Cargo workspace and cannot
//! depend on this crate, so it re-declares the same JSON on its side
//! (`oss/passway/crates/passway/src/discovery.rs`). Keeping the wire type
//! distinct from the in-memory one means an internal refactor can't silently
//! reshape a cross-binary contract — [`WIRE_VERSION`] is the explicit knob
//! for when it must.
//!
//! **A failed fetch is not an empty record set**, on the consumer side too.
//! Serving zero ready records is authoritative ("nothing is up right now");
//! a connection error is not, and passway holds its last-known-good set
//! rather than draining every backend on a transient yubaba blip. That is the
//! same distinction [`run`]'s sweep makes when `list_workloads()` fails.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kamaji::{WorkloadState, WorkloadStatus};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use workload_spec::{MeshIdent, WorkloadSpec};

/// Readiness signal for one [`ServiceRecord`], modeled after the
/// `/mesh/leader-health` 503 pattern: a proxy checks [`Health::is_ready`]
/// before selecting an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// The workload's last-known [`WorkloadStatus`] is `Running`. Safe to
    /// route traffic to.
    Ready,
    /// The workload exists in the runtime's own listing but is not
    /// currently able to serve (`Pending`, `Stopping`, `Stopped`,
    /// `Restarting`, `Failed`). `reason` is a short machine-stable tag, not
    /// prose, so callers can match on it.
    NotReady { reason: &'static str },
    /// The workload no longer appears in the runtime's authoritative list
    /// (torn down / undeployed). Kept distinct from `NotReady` so a
    /// consumer can tell "temporarily unhealthy" from "gone" if it cares;
    /// [`Health::is_ready`] treats both as `false`.
    Retracted,
}

impl Health {
    /// `true` only for [`Health::Ready`] — the single condition under which
    /// an ingress proxy should select this record's endpoint(s).
    pub fn is_ready(&self) -> bool {
        matches!(self, Health::Ready)
    }

    fn from_status(status: &WorkloadStatus) -> Self {
        match status {
            WorkloadStatus::Running => Health::Ready,
            WorkloadStatus::Pending => Health::NotReady { reason: "pending" },
            WorkloadStatus::Stopping => Health::NotReady { reason: "stopping" },
            WorkloadStatus::Stopped => Health::NotReady { reason: "stopped" },
            WorkloadStatus::Restarting { .. } => Health::NotReady {
                reason: "restarting",
            },
            WorkloadStatus::Failed { .. } => Health::NotReady { reason: "failed" },
        }
    }
}

/// One serving-workload's mesh endpoint(s) + health, as known to yubaba.
///
/// This is the record shape a future ingress proxy consumes: enough to
/// dial (`mesh_ip` + `ports`) and enough to gate routing (`health`).
#[derive(Debug, Clone)]
pub struct ServiceRecord {
    /// Mesh identity (`expose.mesh.identity` on the [`WorkloadSpec`]) —
    /// the DNS-segment name other workloads (and now the ingress proxy)
    /// address this workload by.
    pub ident: MeshIdent,
    /// Mesh-plane IPv4 address (from `100.64.0.0/10`, per
    /// `ServerState::alloc_mesh_ip`).
    pub mesh_ip: Ipv4Addr,
    /// Container-side port(s) this workload listens on
    /// (`expose.mesh.ports`). A proxy dials `mesh_ip:port` for each.
    pub ports: Vec<u16>,
    /// Backend-assigned container/task id, useful for correlating a record
    /// with logs or `docker`/`containerd` inspection.
    pub container_id: String,
    /// Current readiness.
    pub health: Health,
    /// Wall-clock time (Unix ms) this record was last written. Lets a
    /// consumer notice a record that hasn't been refreshed in a long time
    /// even if `health` still says `Ready` (staleness, not correctness).
    pub observed_at_unix_ms: u64,
}

impl ServiceRecord {
    /// `mesh_ip:port` for every declared port. Empty if the workload
    /// declares no mesh ports (a valid but proxy-uninteresting shape).
    pub fn endpoints(&self) -> Vec<SocketAddrV4> {
        self.ports
            .iter()
            .map(|&port| SocketAddrV4::new(self.mesh_ip, port))
            .collect()
    }

    /// Convenience passthrough — see [`Health::is_ready`].
    pub fn is_ready(&self) -> bool {
        self.health.is_ready()
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// In-process, push-on-change registry of [`ServiceRecord`]s.
///
/// Cheap to hold behind an `Arc` on `ServerState` (mirrors how
/// `pond_registry` is already wired): interior state is a
/// `tokio::sync::watch` channel keyed by mesh identity, so both a
/// synchronous snapshot read and a push subscription come from the same
/// single-slot cell.
pub struct ServiceRecords {
    tx: watch::Sender<Arc<HashMap<String, ServiceRecord>>>,
    /// Where the port ledger lives. `None` disables persistence entirely
    /// (tests, and the embedded/camp path that has no durable state dir) —
    /// every other operation behaves identically either way.
    ledger_path: Option<PathBuf>,
}

/// File name of the port ledger, written beside `identity.json` in the
/// yubaba state directory. See module docs §The port ledger.
pub const LEDGER_FILE_NAME: &str = "service-records.json";

/// Schema version of [`LedgerFile`]. Bump when the on-disk shape changes
/// incompatibly; an unrecognized version is treated as "no ledger" (warn +
/// start empty) rather than an error, since a yubaba that refuses to boot
/// over a stale bookkeeping file is worse than one that re-learns on the
/// next deploy.
const LEDGER_VERSION: u32 = 1;

/// One persisted record. Deliberately only the *recovered facts* — health is
/// not persisted, because health is exactly the thing a restart invalidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerEntry {
    ident: String,
    mesh_ip: Ipv4Addr,
    ports: Vec<u16>,
    container_id: String,
}

/// On-disk shape of the port ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerFile {
    version: u32,
    services: Vec<LedgerEntry>,
}

impl Default for ServiceRecords {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceRecords {
    /// In-memory only — nothing is persisted and nothing is rehydrated.
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(Arc::new(HashMap::new()));
        Self {
            tx,
            ledger_path: None,
        }
    }

    /// Rehydrate from the port ledger at `path` (missing/corrupt → empty) and
    /// keep writing it on every subsequent publish.
    ///
    /// Recovered records come back `NotReady { reason: "rehydrated" }`, never
    /// `Ready` — see module docs §The port ledger for why.
    pub fn with_ledger(path: PathBuf) -> Self {
        let mut records = HashMap::new();
        for entry in load_ledger(&path) {
            records.insert(
                entry.ident.clone(),
                ServiceRecord {
                    ident: MeshIdent(entry.ident),
                    mesh_ip: entry.mesh_ip,
                    ports: entry.ports,
                    container_id: entry.container_id,
                    health: Health::NotReady {
                        reason: "rehydrated",
                    },
                    observed_at_unix_ms: now_unix_ms(),
                },
            );
        }
        if !records.is_empty() {
            tracing::info!(
                count = records.len(),
                ledger = %path.display(),
                "service_records: rehydrated port ledger; records stay not-ready \
                 until the first reconcile sweep confirms the workloads are live"
            );
        }
        let (tx, _rx) = watch::channel(Arc::new(records));
        Self {
            tx,
            ledger_path: Some(path),
        }
    }

    /// The ledger file this registry persists to, if any.
    pub fn ledger_path(&self) -> Option<&Path> {
        self.ledger_path.as_deref()
    }

    /// Subscribe for push-on-change snapshots. `receiver.changed().await`
    /// resolves only when a record is upserted, reconciled to a new health
    /// value, or retracted — no polling loop on either side.
    pub fn subscribe(&self) -> watch::Receiver<Arc<HashMap<String, ServiceRecord>>> {
        self.tx.subscribe()
    }

    /// Current snapshot, no subscription required.
    pub fn snapshot(&self) -> Arc<HashMap<String, ServiceRecord>> {
        self.tx.borrow().clone()
    }

    /// Look up one record by mesh identity.
    pub fn get(&self, ident: &MeshIdent) -> Option<ServiceRecord> {
        self.tx.borrow().get(ident.0.as_str()).cloned()
    }

    /// All currently-ready records — the shape an ingress proxy's
    /// upstream-selection loop actually wants.
    pub fn ready(&self) -> Vec<ServiceRecord> {
        self.tx
            .borrow()
            .values()
            .filter(|r| r.is_ready())
            .cloned()
            .collect()
    }

    fn publish(&self, next: HashMap<String, ServiceRecord>) {
        // Persist BEFORE publishing: a subscriber woken by the publish may
        // act on the new state immediately, and it should never be able to
        // observe a world the ledger hasn't caught up to. (Costs nothing —
        // both are sub-millisecond on a handful of records.)
        self.save_ledger(&next);
        // `Sender::send` is a no-op (returns `Err` without storing the
        // value!) when there are zero live receivers — and this registry
        // is designed to be correct even with no subscriber ever attached
        // (`snapshot`/`get`/`ready` must still reflect reality). Use
        // `send_replace`, which unconditionally stores the value and
        // notifies whatever receivers do exist, regardless of count.
        self.tx.send_replace(Arc::new(next));
    }

    /// Rewrite the port ledger to match `records`. Best-effort: a failed
    /// write is logged and swallowed, never propagated into the caller — the
    /// in-memory registry is still correct, and failing a live deploy over a
    /// bookkeeping-file write would trade a real outage for a recoverable
    /// one (the next publish rewrites the whole file, so a single failure
    /// self-heals rather than compounding).
    fn save_ledger(&self, records: &HashMap<String, ServiceRecord>) {
        let Some(path) = &self.ledger_path else {
            return;
        };
        // Retracted records are dropped: the workload is gone, and bringing
        // it back on the next boot would publish an undialable upstream.
        let mut services: Vec<LedgerEntry> = records
            .values()
            .filter(|r| r.health != Health::Retracted)
            .map(|r| LedgerEntry {
                ident: r.ident.0.clone(),
                mesh_ip: r.mesh_ip,
                ports: r.ports.clone(),
                container_id: r.container_id.clone(),
            })
            .collect();
        // Stable order so an unchanged registry produces a byte-identical
        // file (HashMap iteration order is not).
        services.sort_by(|a, b| a.ident.cmp(&b.ident));

        let file = LedgerFile {
            version: LEDGER_VERSION,
            services,
        };
        if let Err(e) = crate::identity::atomic_write_json(path, &file) {
            tracing::warn!(
                ledger = %path.display(),
                error = format!("{e:#}"),
                "service_records: failed to persist port ledger; records survive \
                 in memory but a restart before the next successful write will \
                 lose them"
            );
        }
    }

    /// Record (or refresh) a workload at the moment yubaba deploys it.
    /// `mesh_ip` / `container_id` come from the backend's
    /// [`kamaji::DeployResult`]; `ports` are read from
    /// `spec.expose.mesh.ports` — this is the one seam where yubaba knows
    /// both halves at once (see module docs §Placement source of truth).
    pub fn upsert_deployed(
        &self,
        spec: &WorkloadSpec,
        mesh_ip: Ipv4Addr,
        container_id: impl Into<String>,
    ) {
        let ident = spec.expose.mesh.identity.clone();
        let record = ServiceRecord {
            ident: ident.clone(),
            mesh_ip,
            ports: spec.expose.mesh.ports.clone(),
            container_id: container_id.into(),
            health: Health::Ready,
            observed_at_unix_ms: now_unix_ms(),
        };
        let mut next = (*self.tx.borrow()).as_ref().clone();
        next.insert(ident.0, record);
        self.publish(next);
    }

    /// Refresh health (and mesh IP, if it changed) against the runtime's
    /// own authoritative listing — the same data `GET /workloads` reads via
    /// `ContainerRuntime::list_workloads()`.
    ///
    /// Every already-tracked ident found in `states` gets its `health` (and
    /// `mesh_ip`, when the state reports one) refreshed. Every
    /// already-tracked ident **absent** from `states` — i.e. the runtime no
    /// longer knows about it, which is exactly what happens after a
    /// teardown — is retracted. Idents present in `states` but never
    /// previously admitted via [`Self::upsert_deployed`] are skipped (see
    /// module docs: this module never fabricates a portless record).
    pub fn reconcile(&self, states: &[WorkloadState]) {
        let mut next = (*self.tx.borrow()).as_ref().clone();
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();

        for state in states {
            let key = state.ident.0.as_str();
            match next.get_mut(key) {
                Some(record) => {
                    seen.insert(key);
                    if let Some(ip) = state.mesh_ip {
                        record.mesh_ip = ip;
                    }
                    record.container_id = state.container_id.clone();
                    record.health = Health::from_status(&state.status);
                    record.observed_at_unix_ms = now_unix_ms();
                }
                None => {
                    tracing::debug!(
                        ident = %state.ident.0,
                        "service_records: reconcile saw a workload with no prior \
                         upsert_deployed record (no known ports); skipping"
                    );
                }
            }
        }

        for (ident, record) in next.iter_mut() {
            if !seen.contains(ident.as_str()) && record.health != Health::Retracted {
                record.health = Health::Retracted;
                record.observed_at_unix_ms = now_unix_ms();
            }
        }

        self.publish(next);
    }

    /// Explicitly retract one record (e.g. an explicit `POST
    /// /workloads/{ident}/destroy` call site, once wired). Idempotent — a
    /// retract of an unknown or already-retracted ident is a no-op publish.
    pub fn retract(&self, ident: &MeshIdent) {
        let mut next = (*self.tx.borrow()).as_ref().clone();
        if let Some(record) = next.get_mut(ident.0.as_str()) {
            record.health = Health::Retracted;
            record.observed_at_unix_ms = now_unix_ms();
            self.publish(next);
        }
    }
}

/// Read the port ledger. Every failure mode — missing file, unreadable file,
/// malformed JSON, unknown schema version — degrades to "no ledger" rather
/// than an error, because none of them should stop a yubaba from booting:
/// the records are re-learned on the next deploy either way.
fn load_ledger(path: &Path) -> Vec<LedgerEntry> {
    if !path.exists() {
        return Vec::new();
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                ledger = %path.display(),
                error = %e,
                "service_records: port ledger unreadable; starting with no records"
            );
            return Vec::new();
        }
    };
    let file: LedgerFile = match serde_json::from_str(&content) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(
                ledger = %path.display(),
                error = %e,
                "service_records: port ledger is malformed; starting with no records"
            );
            return Vec::new();
        }
    };
    if file.version != LEDGER_VERSION {
        tracing::warn!(
            ledger = %path.display(),
            found = file.version,
            expected = LEDGER_VERSION,
            "service_records: port ledger schema version not recognized; \
             starting with no records"
        );
        return Vec::new();
    }
    file.services
}

// ── Discovery surface (R594-F8) ─────────────────────────────────────────────

/// Path of the discovery endpoint on yubaba's (mesh-bound) HTTP listener.
///
/// Named as a constant so the route registration in `build_router`, this
/// module's docs, and the ticket's verify step all reference one string.
/// passway's own client mirrors it in
/// `oss/passway/crates/passway/src/discovery.rs`.
pub const DISCOVERY_PATH: &str = "/service-records";

/// Schema version of [`ServiceRecordsWire`].
///
/// Bump on any incompatible change to the JSON shape. A consumer that reads a
/// version it doesn't recognize should treat the response as unusable — i.e.
/// as a *fetch failure*, keeping its last-known-good upstream set — rather
/// than as an empty record set, since "I can't read this" and "nothing is
/// running" are the distinction this whole module exists to preserve.
pub const WIRE_VERSION: u32 = 1;

/// Wire tag for [`Health::Ready`]. The one value an ingress proxy routes to.
pub const HEALTH_READY: &str = "ready";
/// Wire tag for [`Health::NotReady`]; the `reason` field carries the detail.
pub const HEALTH_NOT_READY: &str = "not-ready";
/// Wire tag for [`Health::Retracted`].
pub const HEALTH_RETRACTED: &str = "retracted";

/// JSON body of `GET` [`DISCOVERY_PATH`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecordsWire {
    /// Always [`WIRE_VERSION`]. See that constant for consumer behaviour on
    /// an unrecognized value.
    pub version: u32,
    /// Sorted by `ident`, so a consumer diffing two fetches sees a stable
    /// order and a byte-identical body when nothing changed.
    pub records: Vec<ServiceRecordWire>,
}

/// One [`ServiceRecord`] projected onto the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecordWire {
    pub ident: String,
    pub mesh_ip: Ipv4Addr,
    pub ports: Vec<u16>,
    /// `mesh_ip:port` for every declared port — exactly what
    /// [`ServiceRecord::endpoints`] computes, pre-joined so a consumer dials
    /// without re-deriving the pairing (and cannot get it wrong).
    pub endpoints: Vec<String>,
    pub container_id: String,
    /// [`HEALTH_READY`] / [`HEALTH_NOT_READY`] / [`HEALTH_RETRACTED`].
    pub health: String,
    /// Present only alongside [`HEALTH_NOT_READY`] — the machine-stable tag
    /// from [`Health::NotReady`], never prose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub observed_at_unix_ms: u64,
}

impl From<&ServiceRecord> for ServiceRecordWire {
    fn from(r: &ServiceRecord) -> Self {
        let (health, reason) = match &r.health {
            Health::Ready => (HEALTH_READY, None),
            Health::NotReady { reason } => (HEALTH_NOT_READY, Some((*reason).to_string())),
            Health::Retracted => (HEALTH_RETRACTED, None),
        };
        Self {
            ident: r.ident.0.clone(),
            mesh_ip: r.mesh_ip,
            ports: r.ports.clone(),
            endpoints: r.endpoints().iter().map(|e| e.to_string()).collect(),
            container_id: r.container_id.clone(),
            health: health.to_string(),
            reason,
            observed_at_unix_ms: r.observed_at_unix_ms,
        }
    }
}

/// Query string of `GET` [`DISCOVERY_PATH`].
#[derive(Debug, Default, Deserialize)]
pub struct DiscoveryQuery {
    /// `?ready=true` — return only [`Health::is_ready`] records. Default
    /// `false` (every tracked record, health tag included) so an operator
    /// debugging a not-ready upstream can see *why* it was skipped.
    #[serde(default)]
    pub ready: bool,
}

/// Build the wire body from a registry snapshot.
///
/// Split out from the handler so the projection is unit-testable without an
/// axum `State` or a live `ServerState`.
pub fn discovery_body(
    records: &HashMap<String, ServiceRecord>,
    ready_only: bool,
) -> ServiceRecordsWire {
    let mut rows: Vec<ServiceRecordWire> = records
        .values()
        .filter(|r| !ready_only || r.is_ready())
        .map(ServiceRecordWire::from)
        .collect();
    rows.sort_by(|a, b| a.ident.cmp(&b.ident));
    ServiceRecordsWire {
        version: WIRE_VERSION,
        records: rows,
    }
}

/// `GET /service-records[?ready=true]` — the upstream-discovery surface an
/// ingress proxy (passway, R594-F8) polls.
///
/// Always 200: an empty `records` array is a normal cold-start state, not an
/// error (see the module docs' fail-ready note). Read-only, and served on the
/// same mesh-bound listener as `GET /workloads`, whose posture it matches.
pub async fn get_service_records(
    axum::extract::State(state): axum::extract::State<Arc<crate::ServerState>>,
    axum::extract::Query(q): axum::extract::Query<DiscoveryQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let snapshot = state.service_records.snapshot();
    (
        axum::http::StatusCode::OK,
        axum::Json(discovery_body(&snapshot, q.ready)),
    )
        .into_response()
}

// ── Background refresh sweep ────────────────────────────────────────────────

/// How often [`run`] re-reads the runtime's workload list.
///
/// Deliberately slow. Every yubaba-initiated change (deploy, destroy) already
/// pushes synchronously through the `watch`; this sweep exists only to catch
/// changes nobody told yubaba about — a container that crashed, or a
/// rehydrated record whose workload is (or isn't) still running after a
/// restart. 15s bounds how long a rehydrated record stays not-ready on boot
/// while keeping idle cost to one cheap list call per interval.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Background task: refresh service-record health against the runtime's own
/// authoritative listing. Spawned from [`crate::serve`] /
/// [`crate::serve_on_listener`]; returns immediately (task ends) when the node
/// has no workload backend, which is the stub/dev case.
pub async fn run(state: Arc<crate::ServerState>) {
    let Some(backend) = state.active_backend() else {
        tracing::debug!("service_records: no workload backend; refresh sweep idle");
        return;
    };
    tracing::info!(
        interval_secs = SWEEP_INTERVAL.as_secs(),
        ledger = ?state.service_records.ledger_path(),
        "service_records: refresh sweep started"
    );
    loop {
        match backend.list_workloads().await {
            Ok(states) => state.service_records.reconcile(&states),
            // A failed list is NOT an empty list. Reconciling against `&[]`
            // here would retract every record on a transient backend blip
            // (kamaji socket restarting, containerd busy) and yank live
            // upstreams out from under the ingress proxy. Skip the tick.
            Err(e) => tracing::debug!(
                error = format!("{e:#}"),
                "service_records: workload list failed; skipping this refresh tick"
            ),
        }
        tokio::time::sleep(SWEEP_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, Millis, ResourceLimits, RestartPolicy, SchemaVersion,
        StopPolicy, TierTag,
    };

    /// Mirrors the `test_workload_spec` helper already used by
    /// `tests/integration_mesh.rs` / `integration_single_node.rs` — a
    /// minimal-but-real `WorkloadSpec` with a configurable mesh identity +
    /// ports.
    fn test_spec(name: &str, ports: Vec<u16>) -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.to_string(),
            image: ImageRef {
                registry: "docker.io".into(),
                repository: "library/alpine".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".into()),
            tenant: workload_spec::TenantId::singleton(),
            namespace: workload_spec::NamespaceId::singleton(),
            replicas: 1,
            command: Some(vec!["sh".into(), "-c".into(), "sleep 300".into()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 64,
                cpu_millis: 128,
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Never,
            archetype: None,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name.to_string()),
                    ports,
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        }
    }

    fn running_state(name: &str, mesh_ip: Option<Ipv4Addr>) -> WorkloadState {
        WorkloadState {
            ident: MeshIdent(name.to_string()),
            container_id: format!("container-{name}"),
            status: WorkloadStatus::Running,
            mesh_ip,
        }
    }

    #[test]
    fn deployed_workload_yields_ready_record_with_mesh_ip_port() {
        let records = ServiceRecords::new();
        let spec = test_spec("api", vec![8080]);
        let ip = Ipv4Addr::new(100, 64, 0, 5);

        records.upsert_deployed(&spec, ip, "container-abc");

        let record = records
            .get(&MeshIdent("api".into()))
            .expect("record present");
        assert!(record.is_ready(), "freshly deployed workload must be ready");
        assert_eq!(record.mesh_ip, ip);
        assert_eq!(record.ports, vec![8080]);
        assert_eq!(record.endpoints(), vec![SocketAddrV4::new(ip, 8080)]);
        assert_eq!(record.container_id, "container-abc");
    }

    #[test]
    fn deployed_workload_with_multiple_ports_yields_multiple_endpoints() {
        let records = ServiceRecords::new();
        let spec = test_spec("multi", vec![8080, 9090]);
        let ip = Ipv4Addr::new(100, 64, 0, 6);

        records.upsert_deployed(&spec, ip, "container-multi");

        let record = records.get(&MeshIdent("multi".into())).unwrap();
        assert_eq!(
            record.endpoints(),
            vec![SocketAddrV4::new(ip, 8080), SocketAddrV4::new(ip, 9090),]
        );
    }

    #[test]
    fn undeployed_workload_is_retracted_on_reconcile() {
        let records = ServiceRecords::new();
        let spec = test_spec("gone", vec![8080]);
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        records.upsert_deployed(&spec, ip, "container-gone");
        assert!(records.get(&MeshIdent("gone".into())).unwrap().is_ready());

        // Torn down: the runtime's own list_workloads() no longer includes
        // it (matches kamaji's FakeRuntime/real backends, which remove the
        // entry entirely on teardown).
        records.reconcile(&[]);

        let record = records.get(&MeshIdent("gone".into())).unwrap();
        assert!(!record.is_ready(), "retracted workload must not be ready");
        assert_eq!(record.health, Health::Retracted);
        // Endpoint/port bookkeeping survives retraction — useful for
        // diagnostics — but is_ready() is what a proxy must respect.
        assert_eq!(record.ports, vec![8080]);
    }

    #[test]
    fn stopped_workload_is_not_ready_but_not_retracted_while_still_listed() {
        let records = ServiceRecords::new();
        let spec = test_spec("stopping", vec![8080]);
        let ip = Ipv4Addr::new(100, 64, 0, 8);
        records.upsert_deployed(&spec, ip, "container-stopping");

        let stopped = WorkloadState {
            ident: MeshIdent("stopping".into()),
            container_id: "container-stopping".into(),
            status: WorkloadStatus::Stopping,
            mesh_ip: Some(ip),
        };
        records.reconcile(std::slice::from_ref(&stopped));

        let record = records.get(&MeshIdent("stopping".into())).unwrap();
        assert!(!record.is_ready());
        assert_eq!(record.health, Health::NotReady { reason: "stopping" });
    }

    #[test]
    fn reconcile_refreshes_mesh_ip_when_it_changes() {
        let records = ServiceRecords::new();
        let spec = test_spec("moved", vec![443]);
        let old_ip = Ipv4Addr::new(100, 64, 0, 9);
        records.upsert_deployed(&spec, old_ip, "container-moved");

        let new_ip = Ipv4Addr::new(100, 64, 0, 10);
        let state = running_state("moved", Some(new_ip));
        records.reconcile(std::slice::from_ref(&state));

        let record = records.get(&MeshIdent("moved".into())).unwrap();
        assert!(record.is_ready());
        assert_eq!(record.mesh_ip, new_ip);
        assert_eq!(record.ports, vec![443], "ports are untouched by reconcile");
    }

    #[test]
    fn reconcile_skips_unknown_idents_it_has_no_ports_for() {
        let records = ServiceRecords::new();
        let state = running_state("never-deployed-here", Some(Ipv4Addr::new(100, 64, 0, 11)));
        records.reconcile(std::slice::from_ref(&state));

        assert!(records
            .get(&MeshIdent("never-deployed-here".into()))
            .is_none());
        assert!(records.snapshot().is_empty());
    }

    #[test]
    fn explicit_retract_marks_not_ready_idempotently() {
        let records = ServiceRecords::new();
        let spec = test_spec("explicit", vec![8080]);
        records.upsert_deployed(&spec, Ipv4Addr::new(100, 64, 0, 12), "c1");

        let ident = MeshIdent("explicit".into());
        records.retract(&ident);
        assert!(!records.get(&ident).unwrap().is_ready());

        // Retracting again (or retracting an unknown ident) must not panic
        // or resurrect the record.
        records.retract(&ident);
        records.retract(&MeshIdent("unknown".into()));
        assert_eq!(records.get(&ident).unwrap().health, Health::Retracted);
    }

    #[tokio::test]
    async fn subscriber_is_notified_on_upsert_without_polling() {
        let records = ServiceRecords::new();
        let mut rx = records.subscribe();

        let spec = test_spec("pushed", vec![8080]);
        records.upsert_deployed(&spec, Ipv4Addr::new(100, 64, 0, 13), "c-pushed");

        rx.changed().await.expect("sender still alive");
        let snap = rx.borrow_and_update();
        let record = snap
            .get("pushed")
            .expect("record present in pushed snapshot");
        assert!(record.is_ready());
    }

    #[tokio::test]
    async fn subscriber_is_notified_on_retraction() {
        let records = ServiceRecords::new();
        let spec = test_spec("watched", vec![8080]);
        records.upsert_deployed(&spec, Ipv4Addr::new(100, 64, 0, 14), "c-watched");

        let mut rx = records.subscribe();
        // Baseline: mark the current value seen so the next `changed()`
        // only fires for the retraction below.
        rx.borrow_and_update();

        records.reconcile(&[]);

        rx.changed().await.expect("sender still alive");
        let snap = rx.borrow_and_update();
        assert_eq!(snap.get("watched").unwrap().health, Health::Retracted);
    }

    #[test]
    fn ready_filters_to_only_ready_records() {
        let records = ServiceRecords::new();
        records.upsert_deployed(
            &test_spec("healthy", vec![80]),
            Ipv4Addr::new(100, 64, 0, 15),
            "c-healthy",
        );
        records.upsert_deployed(
            &test_spec("sick", vec![80]),
            Ipv4Addr::new(100, 64, 0, 16),
            "c-sick",
        );
        records.retract(&MeshIdent("sick".into()));

        let ready = records.ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].ident, MeshIdent("healthy".into()));
    }

    // ── R594-F8: the discovery wire projection ──────────────────────────────

    #[test]
    fn wire_projection_carries_everything_needed_to_dial() {
        let records = ServiceRecords::new();
        let ip = Ipv4Addr::new(100, 64, 0, 20);
        records.upsert_deployed(&test_spec("api", vec![8080, 9090]), ip, "c-api");

        let body = discovery_body(&records.snapshot(), false);
        assert_eq!(body.version, WIRE_VERSION);
        assert_eq!(body.records.len(), 1);

        let row = &body.records[0];
        assert_eq!(row.ident, "api");
        assert_eq!(row.mesh_ip, ip);
        assert_eq!(row.ports, vec![8080, 9090]);
        assert_eq!(
            row.endpoints,
            vec![format!("{ip}:8080"), format!("{ip}:9090")],
            "one pre-paired endpoint per declared port, in port order"
        );
        assert_eq!(row.container_id, "c-api");
        assert_eq!(row.health, HEALTH_READY);
        assert_eq!(row.reason, None, "a ready record has nothing to explain");
        assert!(row.observed_at_unix_ms > 0);
    }

    #[test]
    fn wire_ready_filter_matches_the_registrys_own_ready_view() {
        let records = ServiceRecords::new();
        records.upsert_deployed(
            &test_spec("healthy", vec![80]),
            Ipv4Addr::new(100, 64, 0, 21),
            "c-healthy",
        );
        records.upsert_deployed(
            &test_spec("sick", vec![80]),
            Ipv4Addr::new(100, 64, 0, 22),
            "c-sick",
        );
        records.reconcile(&[running_state("healthy", None)]);

        let snapshot = records.snapshot();
        let filtered = discovery_body(&snapshot, true);
        assert_eq!(filtered.records.len(), 1);
        assert_eq!(filtered.records[0].ident, "healthy");

        // Unfiltered keeps the un-routable one, tagged with why.
        let all = discovery_body(&snapshot, false);
        assert_eq!(all.records.len(), 2);
        let sick = all.records.iter().find(|r| r.ident == "sick").unwrap();
        assert_eq!(sick.health, HEALTH_RETRACTED);
    }

    #[test]
    fn wire_not_ready_carries_the_machine_stable_reason() {
        let records = ServiceRecords::new();
        records.upsert_deployed(
            &test_spec("api", vec![80]),
            Ipv4Addr::new(100, 64, 0, 23),
            "c-api",
        );
        records.reconcile(&[WorkloadState {
            ident: MeshIdent("api".into()),
            container_id: "c-api".into(),
            status: WorkloadStatus::Stopping,
            mesh_ip: None,
        }]);

        let row = &discovery_body(&records.snapshot(), false).records[0];
        assert_eq!(row.health, HEALTH_NOT_READY);
        assert_eq!(row.reason.as_deref(), Some("stopping"));
    }

    #[test]
    fn wire_body_round_trips_through_json() {
        let records = ServiceRecords::new();
        records.upsert_deployed(
            &test_spec("api", vec![8080]),
            Ipv4Addr::new(100, 64, 0, 24),
            "c-api",
        );
        let body = discovery_body(&records.snapshot(), true);

        // The contract passway re-declares on its side lives or dies here.
        let json = serde_json::to_string(&body).unwrap();
        let back: ServiceRecordsWire = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, WIRE_VERSION);
        assert_eq!(back.records[0].endpoints, body.records[0].endpoints);
        assert!(
            !json.contains("\"reason\""),
            "reason is omitted, not null, when there is none"
        );
    }

    #[test]
    fn wire_body_is_sorted_by_ident() {
        let records = ServiceRecords::new();
        for (i, name) in ["zeta", "alpha", "mid"].iter().enumerate() {
            records.upsert_deployed(
                &test_spec(name, vec![80]),
                Ipv4Addr::new(100, 64, 0, 30 + i as u8),
                "c",
            );
        }
        let body = discovery_body(&records.snapshot(), true);
        let idents: Vec<&str> = body.records.iter().map(|r| r.ident.as_str()).collect();
        assert_eq!(idents, vec!["alpha", "mid", "zeta"]);
    }

    // ── R594-F6: the port ledger / restart survival ─────────────────────────

    /// Simulate a yubaba restart: drop the registry, build a fresh one over
    /// the same ledger path. Nothing carries over except the file.
    fn restart(path: &std::path::Path) -> ServiceRecords {
        ServiceRecords::with_ledger(path.to_path_buf())
    }

    #[test]
    fn deployed_record_survives_restart_with_ports_and_mesh_ip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        let ip = Ipv4Addr::new(100, 64, 0, 20);

        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.upsert_deployed(&test_spec("api", vec![8080, 9090]), ip, "container-api");
        }

        // This is the whole point of the ticket: the port — which
        // `list_workloads()` does not carry, so nothing could re-derive it —
        // comes back without a redeploy.
        let record = restart(&ledger)
            .get(&MeshIdent("api".into()))
            .expect("record rehydrated from ledger");
        assert_eq!(record.ports, vec![8080, 9090]);
        assert_eq!(record.mesh_ip, ip);
        assert_eq!(record.container_id, "container-api");
        assert_eq!(
            record.endpoints(),
            vec![SocketAddrV4::new(ip, 8080), SocketAddrV4::new(ip, 9090)]
        );
    }

    #[test]
    fn rehydrated_record_is_not_ready_until_a_sweep_confirms_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.upsert_deployed(
                &test_spec("api", vec![8080]),
                Ipv4Addr::new(100, 64, 0, 21),
                "c-api",
            );
        }

        let records = restart(&ledger);
        let record = records.get(&MeshIdent("api".into())).unwrap();
        assert!(
            !record.is_ready(),
            "a record read off disk says nothing about whether the workload \
             is running right now — routing to it would be a black hole"
        );
        assert_eq!(
            record.health,
            Health::NotReady {
                reason: "rehydrated"
            }
        );
        assert!(records.ready().is_empty(), "not a routable upstream yet");
    }

    #[test]
    fn first_sweep_promotes_a_rehydrated_record_to_ready() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        let ip = Ipv4Addr::new(100, 64, 0, 22);
        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.upsert_deployed(&test_spec("api", vec![8080]), ip, "c-api");
        }

        // The workload rode out the restart — the runtime still lists it.
        let records = restart(&ledger);
        let state = running_state("api", Some(ip));
        records.reconcile(std::slice::from_ref(&state));

        let ready = records.ready();
        assert_eq!(ready.len(), 1, "confirmed-live record becomes routable");
        assert_eq!(ready[0].endpoints(), vec![SocketAddrV4::new(ip, 8080)]);
    }

    #[test]
    fn first_sweep_retracts_a_rehydrated_record_whose_workload_died() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.upsert_deployed(
                &test_spec("ghost", vec![8080]),
                Ipv4Addr::new(100, 64, 0, 23),
                "c-ghost",
            );
        }

        // The container did not survive the restart.
        let records = restart(&ledger);
        records.reconcile(&[]);
        assert_eq!(
            records.get(&MeshIdent("ghost".into())).unwrap().health,
            Health::Retracted
        );

        // …and it is gone from the ledger, so a second restart doesn't
        // resurrect it.
        assert!(restart(&ledger).snapshot().is_empty());
    }

    #[test]
    fn retracted_record_does_not_come_back_after_restart() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join(LEDGER_FILE_NAME);
        {
            let records = ServiceRecords::with_ledger(ledger.clone());
            records.upsert_deployed(
                &test_spec("keep", vec![80]),
                Ipv4Addr::new(100, 64, 0, 24),
                "c-keep",
            );
            records.upsert_deployed(
                &test_spec("destroyed", vec![80]),
                Ipv4Addr::new(100, 64, 0, 25),
                "c-destroyed",
            );
            // The `destroy_workload` path.
            records.retract(&MeshIdent("destroyed".into()));
        }

        let records = restart(&ledger);
        assert!(records.get(&MeshIdent("keep".into())).is_some());
        assert!(
            records.get(&MeshIdent("destroyed".into())).is_none(),
            "an explicitly destroyed workload must not be advertised again"
        );
    }

    #[test]
    fn missing_ledger_starts_empty_and_is_created_on_first_publish() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ledger = tmp.path().join("nested/deeper").join(LEDGER_FILE_NAME);

        let records = ServiceRecords::with_ledger(ledger.clone());
        assert!(records.snapshot().is_empty());
        assert!(!ledger.exists(), "nothing to write yet");

        records.upsert_deployed(
            &test_spec("api", vec![8080]),
            Ipv4Addr::new(100, 64, 0, 26),
            "c-api",
        );
        assert!(ledger.exists(), "parent dirs created, ledger written");
    }

    #[test]
    fn corrupt_or_unversioned_ledger_degrades_to_empty_instead_of_failing() {
        let tmp = tempfile::TempDir::new().unwrap();

        // A yubaba that refuses to boot over a mangled bookkeeping file is
        // worse than one that re-learns its records on the next deploy.
        let garbage = tmp.path().join("garbage.json");
        std::fs::write(&garbage, "{not json at all").unwrap();
        assert!(ServiceRecords::with_ledger(garbage).snapshot().is_empty());

        let future = tmp.path().join("future.json");
        std::fs::write(
            &future,
            serde_json::json!({ "version": LEDGER_VERSION + 1, "services": [] }).to_string(),
        )
        .unwrap();
        assert!(ServiceRecords::with_ledger(future).snapshot().is_empty());
    }

    #[test]
    fn ledgerless_registry_writes_nothing() {
        let records = ServiceRecords::new();
        assert!(records.ledger_path().is_none());
        // Must not panic or try to write anywhere.
        records.upsert_deployed(
            &test_spec("ephemeral", vec![80]),
            Ipv4Addr::new(100, 64, 0, 27),
            "c-eph",
        );
        assert!(records.get(&MeshIdent("ephemeral".into())).is_some());
    }
}
