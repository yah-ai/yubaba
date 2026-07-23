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
//! about from a prior `upsert_deployed` — it does not fabricate a record
//! for an ident it has never seen admitted, because it would have no port
//! to publish for it (a record without a port is not something an ingress
//! proxy can dial). This is a deliberate v1 limitation: cold-discovering a
//! workload's ports from `WorkloadState` alone isn't possible until the
//! wire/state shape grows a ports field (tracked in `lib.rs`'s existing
//! R406-T8 handoff note about enriching `WorkloadEntry` with `mesh_ip` +
//! friends) — until then, admission (`upsert_deployed`) is the only
//! discovery path, and `reconcile` is purely a health/liveness refresh.
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
//! ## Wiring note
//!
//! This ticket intentionally does **not** call `upsert_deployed` /
//! `reconcile` from `lib.rs`'s HTTP handlers — `lib.rs` has a live
//! in-flight peer edit and this ticket's budget there is exactly one
//! `pub mod service_records;` line. The read-model and its tests prove the
//! surface works against the real types (`WorkloadSpec`, `WorkloadState`,
//! `kamaji::Kamaji`); wiring the two call sites into
//! `deploy_workload_spec` / `destroy_workload` (and a periodic
//! `list_workloads()` → `reconcile()` sweep for backends where health can
//! change without a yubaba-initiated action, e.g. a container crash) is
//! follow-up work for whoever lands R594-F4 or a small bridging ticket.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use kamaji::{WorkloadState, WorkloadStatus};
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
}

impl Default for ServiceRecords {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceRecords {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(Arc::new(HashMap::new()));
        Self { tx }
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
        // `Sender::send` is a no-op (returns `Err` without storing the
        // value!) when there are zero live receivers — and this registry
        // is designed to be correct even with no subscriber ever attached
        // (`snapshot`/`get`/`ready` must still reflect reality). Use
        // `send_replace`, which unconditionally stores the value and
        // notifies whatever receivers do exist, regardless of count.
        self.tx.send_replace(Arc::new(next));
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
}
