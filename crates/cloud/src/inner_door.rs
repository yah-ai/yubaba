//! The **inner door** planner (R870-F23) — the `service.toml` +
//! domain-manifest join that produces a passway `PASSWAY_PATH_ROUTES_FILE`.
//!
//! ## What an inner door is, and what it is not
//!
//! R870-F15 landed path routing in passway; R870-T18 gave it a config surface
//! (a JSON mount table named by `PASSWAY_PATH_ROUTES_FILE`). Both are the
//! *consumer*. This module is the producer: given a service's declared
//! components and the domain manifest that routes them, it answers "what mount
//! table does this service's own door need, if any".
//!
//! It is an **inner** door because it sits behind the service's public one, on
//! loopback. The public door owns a hostname and terminates TLS; the inner door
//! owns one hostname's *paths* and splits them across units that deploy
//! independently. That split is the only thing it does — and it is the thing
//! the public door structurally cannot do, because the public tier routes by
//! SNI/Host and a request's path is not visible until after that.
//!
//! ## The join carries no new vocabulary
//!
//! R870-F15 claimed the join needs nothing new, and that holds up. Every input
//! already exists:
//!
//! | Field | Source |
//! |---|---|
//! | `mount` | [`ServiceComponent::mount`], normalized by [`normalize_mount`] |
//! | `headers` | the [`DomainRoute`] whose [`route_path_prefix`] equals that mount |
//! | tier | [`ServiceComponent::deploy`] — the one thing R870-F23 added |
//! | `upstreams` | placement-time, so it is [`InnerDoorPlan::routes_file`]'s argument, not a config field |
//!
//! The mount/route agreement is not re-derived here: [`CloudConfig::cross_ref_validate`]
//! already *proves* a component's mount and its route's path prefix are the
//! same string, so the lookup below cannot silently mismatch — a config where
//! it would have does not load.
//!
//! ## The two admission rules
//!
//! Both belong here, never to passway: passway proxies whatever `PathRouter`
//! it is handed and has no view of how many components a service declares.
//!
//! 1. **A service with one independently-deployed unit gets no inner tier at
//!    all.** Enforced by construction — [`plan`] answers `Ok(None)` below two
//!    units, so there is no config to write and no process to supervise. That
//!    makes the negative assertable on the *absence* of a plan rather than on
//!    a site staying up, which is the only form of that assertion that can
//!    fail loudly.
//! 2. **A component cannot be both bundle-staged and its own workload.**
//!    Enforced by [`DeployTier`] being one field with two values rather than
//!    two independent flags: the contradictory state has no spelling. What
//!    remains checkable — that two components do not claim one mount — lives
//!    in `cross_ref_validate`'s existing loop, widened rather than duplicated.
//!
//! ## Grouping is by deployed UNIT, not by component
//!
//! Every bundle-tier component of a service shares ONE bundle workload (config
//! 1, R870-B11), so they contribute one upstream between them —
//! [`DeployedUnit::Bundle`]. They still contribute their own *mounts*, because
//! a mount is where the bundle stores that component's output
//! (`app/dist/<mount>/`) and because the domain manifest may give that path
//! response headers the root does not have. So N bundle components produce N
//! mounts and one unit, and it is the unit count that rule 1 keys on.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde::Serialize;
use workload_spec::{
    EnvValue, EnvVar, ExposeSpec, HealthProbe, Healthcheck, ImageRef, InlineFile,
    LifecycleArchetype, MeshExpose, MeshIdent, Millis, NamespaceId, ResourceLimits, RestartPolicy,
    SchemaVersion, StopPolicy, TenantId, TierTag, Workload, WorkloadSpec,
};

use crate::config::{
    domain_serving_service, normalize_mount, route_path_prefix, DeployTier, DomainConfig,
    DomainRoute, ServiceComponent, ServiceConfig,
};

/// `schema_version` of the route table this module writes. Must match
/// passway's `path_routes_file::SCHEMA_VERSION`; a mismatch is a boot failure
/// on the door naming both numbers, which is the intended way for a
/// producer/consumer skew to surface (see that module's doc).
pub const ROUTES_SCHEMA_VERSION: u32 = 1;

/// Which deployed thing serves a mount.
///
/// The distinction the whole module turns on: several components can share one
/// of these, and rule 1 counts *these*, not components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeployedUnit {
    /// The service's single assembled W272 bundle — every [`DeployTier::Bundle`]
    /// component, collapsed.
    Bundle,
    /// One [`DeployTier::Workload`] component, by component id.
    Component(String),
}

/// One mount of an inner door's table, before upstream addresses exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerDoorMount {
    /// passway's mount spelling: `""` for the service root, otherwise
    /// `/segment[/segment…]`. The `service.toml` side spells the same mount
    /// without the leading slash — see [`passway_mount`].
    pub mount: String,
    /// What serves it.
    pub unit: DeployedUnit,
    /// Response headers the domain manifest gives this path (R746). Empty when
    /// no route declares any.
    pub headers: BTreeMap<String, String>,
}

/// A service's inner door, as configuration — everything but the addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerDoorPlan {
    /// Service name, for error messages and the workload name.
    pub service: String,
    /// Mounts in declaration order. Precedence is `PathRouter`'s (longest
    /// mount wins), not this vector's, so the order is presentational.
    pub mounts: Vec<InnerDoorMount>,
}

/// Translate a normalized mount (`""`, `"app"`) to passway's spelling (`""`,
/// `"/app"`).
///
/// The twin of [`normalize_mount`] on the wire side, and deliberately built by
/// composing with it rather than trimming slashes again: `/app`, `app/` and
/// `/app/` all mean one mount, and this crate already has exactly one place
/// that knows so.
///
/// passway has its own `path_route::mount_from_component` doing the same job on
/// the reading side. That is a genuine two-sided format rather than a
/// duplicated normalizer — passway is a separately released crate with its own
/// workspace, and yubaba cannot call into it — and it is handled the way the
/// wire format handles every other such risk: `PathRouter::new` is the ONE
/// validator of mount well-formedness, so a disagreement here is a loud boot
/// failure on the door, never a silently mis-served prefix.
pub fn passway_mount(raw: Option<&str>) -> String {
    match raw.map(normalize_mount) {
        Some(m) if !m.is_empty() => format!("/{m}"),
        _ => String::new(),
    }
}

/// Plan the inner door for one service, or answer `None` when it should not
/// have one.
///
/// `None` is rule 1 and is the common answer: a service whose components all
/// ship in one bundle has a single upstream, and a proxy in front of a single
/// upstream is a hop that can only add latency and a failure mode.
///
/// `Err` is reserved for a service that *needs* a door and cannot have a
/// working one — today that is exactly one case, no root mount, which would
/// produce a table that 503s every unclaimed path.
pub fn plan(
    service: &ServiceConfig,
    domains: &BTreeMap<String, DomainConfig>,
) -> Result<Option<InnerDoorPlan>> {
    let routes = domain_serving_service(domains, &service.name).map(|d| d.routes.as_slice());

    let mut mounts: Vec<InnerDoorMount> = Vec::new();
    for component in &service.components {
        let unit = match component.deploy {
            DeployTier::Bundle => DeployedUnit::Bundle,
            DeployTier::Workload => DeployedUnit::Component(component.id.clone()),
        };
        mounts.push(InnerDoorMount {
            mount: passway_mount(component.mount.as_deref()),
            headers: headers_for(routes, component),
            unit,
        });
    }

    // Rule 1, counted on UNITS. Three bundle components are one unit and get
    // no door; one bundle component plus one workload component are two and
    // do.
    let units: std::collections::BTreeSet<&DeployedUnit> = mounts.iter().map(|m| &m.unit).collect();
    if units.len() < 2 {
        return Ok(None);
    }

    if !mounts.iter().any(|m| m.mount.is_empty()) {
        bail!(
            "services/{}/service.toml declares {} independently-deployed units but no component \
             at the service root — every component sets a `mount`. An inner door's table needs a \
             root (\"\") mount as its catch-all; without one every path outside the declared \
             mounts 503s, which is indistinguishable from an outage. Drop the `mount` from \
             whichever component serves `/`.",
            service.name,
            units.len(),
        );
    }

    Ok(Some(InnerDoorPlan {
        service: service.name.clone(),
        mounts,
    }))
}

/// The response headers the domain manifest gives `component`'s mount.
///
/// Matched on the mount rather than on the route's `component` reference, so a
/// path declared as a bare prefix still contributes: `cross_ref_validate` has
/// already proved the two agree for every route that names a component, and
/// matching on the prefix is what makes the lookup total.
fn headers_for(
    routes: Option<&[DomainRoute]>,
    component: &ServiceComponent,
) -> BTreeMap<String, String> {
    let wanted = component
        .mount
        .as_deref()
        .map(normalize_mount)
        .unwrap_or_default();
    routes
        .unwrap_or(&[])
        .iter()
        .find(|r| route_path_prefix(&r.path) == wanted && !r.headers.is_empty())
        .map(|r| r.headers.clone())
        .unwrap_or_default()
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// Serialization mirror of passway's `path_routes_file::PathRoutesFile`. Kept
/// private: the supported output is [`InnerDoorPlan::routes_file`]'s string, so
/// nothing can construct a half-filled table and write it.
#[derive(Debug, Serialize)]
struct RoutesFile<'a> {
    schema_version: u32,
    routes: Vec<RouteEntry<'a>>,
}

#[derive(Debug, Serialize)]
struct RouteEntry<'a> {
    mount: &'a str,
    upstreams: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    headers: &'a BTreeMap<String, String>,
}

impl InnerDoorPlan {
    /// Every distinct unit this door proxies to, in a stable order. What a
    /// caller resolving addresses has to answer for.
    pub fn units(&self) -> Vec<DeployedUnit> {
        let set: std::collections::BTreeSet<DeployedUnit> =
            self.mounts.iter().map(|m| m.unit.clone()).collect();
        set.into_iter().collect()
    }

    /// Render the JSON passway reads, resolving each unit to its address.
    ///
    /// `address` is placement-time knowledge — which node the unit landed on
    /// and which port kamaji gave it — so it arrives as a closure rather than
    /// as config. Returning `None` from it is refused rather than skipped: a
    /// mount whose upstream could not be resolved would be dropped from the
    /// table, and the door would then serve that path from whichever *shorter*
    /// mount matched — the root, usually — which is a wrong answer wearing a
    /// 200.
    pub fn routes_file(
        &self,
        address: impl Fn(&DeployedUnit) -> Option<String>,
    ) -> Result<String> {
        let mut routes = Vec::with_capacity(self.mounts.len());
        for m in &self.mounts {
            let Some(addr) = address(&m.unit) else {
                bail!(
                    "service {}: mount {:?} is served by {:?}, which has no resolved address yet. \
                     Refusing to write a partial route table — a missing mount does not 503, it \
                     falls through to the root mount and serves the wrong component with a 200.",
                    self.service,
                    m.mount,
                    m.unit,
                );
            };
            routes.push(RouteEntry {
                mount: &m.mount,
                upstreams: vec![addr],
                headers: &m.headers,
            });
        }
        Ok(serde_json::to_string(&RoutesFile {
            schema_version: ROUTES_SCHEMA_VERSION,
            routes,
        })?)
    }
}

// ── Supervision ──────────────────────────────────────────────────────────────

/// The passway binary every node carries, installed by the yubaba release
/// tarball's `control_plane_install`. The inner door is the *same* binary as
/// the public door — one door implementation, two configurations, which is the
/// property R870-F15 built path routing to preserve.
pub const INNER_DOOR_BINARY: &str = "/usr/local/bin/passway";

/// Where a node keeps generated route tables. Same directory the demux and
/// http-router tables already live in.
pub const ROUTES_DIR: &str = "/var/lib/passway/routes";

/// The only address an inner door ever binds, and the only one the outer door
/// ever dials it at. Literal rather than a parameter — see
/// [`InnerDoorPlan::workload`].
pub const INNER_DOOR_HOST: &str = "127.0.0.1";

/// Low end of the window [`listen_port`] picks from, inclusive.
pub const INNER_DOOR_PORT_LOW: u16 = 10_000;
/// High end of the window [`listen_port`] picks from, inclusive.
pub const INNER_DOOR_PORT_HIGH: u16 = 19_999;

/// The loopback port a service's inner door listens on — derived from the
/// service name, so every apply of an unchanged tree renders the same number.
///
/// ## Why a derived pin rather than kamaji's ledger
///
/// R870-F23 phase 2 preferred taking the number from `kamaji::ports`
/// ([`LedgerPorts`], `oss/kamaji/crates/kamaji/src/ports.rs`). Read rather than
/// assumed, that ledger cannot answer here, for three reasons that also happen
/// to make a pin safe:
///
/// 1. **It is node-local and has no RPC.** `LedgerPorts` persists
///    `(ident, name) -> port` to a JSON file beside the supervisor's state dir,
///    and yubaba's HTTP surface exposes no allocation verb (`yubaba/src/lib.rs`
///    routes `/workloads/*`, `/services`, `/node/*` — nothing for ports). An
///    apply running on an operator's laptop has no way to ask.
/// 2. **A pin is honoured, not rejected, on the path this workload takes.**
///    R844-F14's rule — a non-world-fixed pin is an error — bites in
///    `LedgerPorts::resolve_set`, and `NativeRuntime::resolve_declared_ports`
///    (`kamaji/src/native.rs:280`) filters `pin.is_none()` *before* calling it.
///    A stated number is therefore passed through, which is what
///    `PASSWAY_LISTEN` needs: the door's own env has to carry the number, and
///    a number the node picked after the spec was rendered could not be in it.
/// 3. **A collision is not even representable.** The ledger allocates on the
///    workload's *mesh* IP; an inner door binds loopback. `100.64.0.3:14210`
///    and `127.0.0.1:14210` are different sockets.
///
/// The window is deliberately below Linux's default ephemeral range
/// (32768-60999), which is where `pick_free_port`'s `bind(:0)` draws from — so
/// a derived number cannot land on one the ledger is about to hand out even on
/// the same interface.
///
/// The hash is FNV-1a written out here rather than `DefaultHasher`, whose
/// output std explicitly does not promise to keep stable across releases. This
/// number is written into a deployed door's environment and into the outer
/// door's upstream list; a toolchain bump silently moving it would repoint one
/// tier and not the other.
pub fn listen_port(service: &str) -> u16 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in service.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let span = u64::from(INNER_DOOR_PORT_HIGH - INNER_DOOR_PORT_LOW) + 1;
    INNER_DOOR_PORT_LOW + (hash % span) as u16
}

/// The mesh identity a [`DeployTier::Workload`] component registers its service
/// record under.
///
/// **This is the naming rule, not a lookup**, and it is stated here because
/// nothing else states it. A bundle's ident comes from the mirror
/// (`BundleSlot::workload_name`, overridable by `name = "…"`), but a
/// workload-tier component has no slot of its own — `[providers.*]` is
/// per-kind, per-mirror, which is exactly the gap [`DeployTier`] was added to
/// close. So the ident has to be derivable from the two names the service
/// already declares, and this is that derivation.
///
/// Getting it wrong is a *loud* failure rather than a quiet one:
/// [`InnerDoorPlan::routes_file`] refuses a mount whose unit resolved to no
/// address, naming the unit, so a component that registered under some other
/// ident fails the apply instead of falling through to the root mount.
pub fn component_workload_ident(service: &str, component_id: &str) -> String {
    crate::reconciler::native_support::sanitize_ident(&format!("{service}-{component_id}"))
}

impl InnerDoorPlan {
    /// The workload name / mesh identity for this service's inner door.
    pub fn workload_name(&self) -> String {
        format!("passway-inner-{}", self.service)
    }

    /// Where this door's route table is materialized on the node.
    pub fn routes_path(&self) -> PathBuf {
        Path::new(ROUTES_DIR).join(format!("{}.routes.json", self.service))
    }

    /// This door's loopback port — [`listen_port`] of the service name.
    pub fn listen_port(&self) -> u16 {
        listen_port(&self.service)
    }

    /// The mesh identity whose ready service record carries `unit`'s address.
    ///
    /// The two arms come from different places on purpose, and neither is
    /// derivable from the other. A bundle's ident is a *mirror* fact —
    /// `BundleSlot::workload_name`, which a slot may rename with `name = "…"` —
    /// so it is handed in. A workload-tier component has no slot to rename it,
    /// so its ident is derived ([`component_workload_ident`]).
    pub fn unit_ident(&self, unit: &DeployedUnit, bundle_ident: &str) -> String {
        match unit {
            DeployedUnit::Bundle => bundle_ident.to_string(),
            DeployedUnit::Component(id) => component_workload_ident(&self.service, id),
        }
    }

    /// Resolve every unit to a `host:port`, given a way to look an address up
    /// by mesh identity.
    ///
    /// The step between [`units`](Self::units) and the `address` closure
    /// [`routes_file`](Self::routes_file) and [`workload`](Self::workload)
    /// take: those two ask "where is this unit", this answers it from a
    /// discovery read. Split out rather than folded in so the identity mapping
    /// stays testable without a fleet.
    ///
    /// A unit with no answer is simply absent from the map — the refusal lives
    /// in `routes_file`, which is the single place a missing address is
    /// reported and which already explains why a dropped mount is worse than a
    /// failed apply.
    pub fn resolve_addresses(
        &self,
        bundle_ident: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> BTreeMap<DeployedUnit, String> {
        self.units()
            .into_iter()
            .filter_map(|unit| {
                let addr = lookup(&self.unit_ident(&unit, bundle_ident))?;
                Some((unit, addr))
            })
            .collect()
    }

    /// Render the supervisable workload: a passway process serving this
    /// service's mount table on loopback.
    ///
    /// ## Cleartext, and the invariant that makes it safe
    ///
    /// `PASSWAY_TLS_MODE=plaintext` (operator call, 2026-09-09 — see
    /// `passway::tls::parse_listener_tls_mode` for the full argument). The
    /// short version: no CA issues for `127.0.0.1`, so "TLS everywhere" here
    /// means a self-signed leaf plus a way to switch OFF upstream certificate
    /// verification on the *public* door — a real trust-boundary knob traded
    /// for encrypting a hop that never leaves the loopback interface.
    ///
    /// This function cannot violate that invariant even if `listen_port` is
    /// wrong, because it binds `127.0.0.1` literally and passway refuses the
    /// mode on anything else. The bind is not a parameter.
    ///
    /// ## Why `listen_port` is an argument
    ///
    /// It is placement-time knowledge, exactly like the upstream addresses:
    /// which port is free is a property of the node, not of the config. The
    /// caller allocates and passes it, so this stays a pure function of
    /// (plan, port, addresses) and is testable without a node.
    ///
    /// ## The route table travels IN the spec
    ///
    /// Not written beside it: [`WorkloadSpec::files`] makes the table and the
    /// process that reads it one deploy rather than two, so a redeploy cannot
    /// leave a door serving a stale table. Only kamaji's native backend
    /// materializes those; every other backend refuses the spec by name rather
    /// than starting the door against a file that is not there.
    ///
    /// ## Why `Workload::Container` and not a new `Workload` variant
    ///
    /// `TenantPasswayWorkload` is a typed variant, so the precedent for one
    /// exists — but it earns that by carrying config kamaji itself must act on
    /// (a domain to match, a PEM pair to re-read on every cold start, an idle
    /// TTL to reap against). An inner door carries none of it: its entire
    /// configuration is an argv, three env vars and one file, all of which
    /// `WorkloadSpec` already expresses. A variant would buy nothing but
    /// exhaustive-match churn in peer-owned `kamaji-proto`, which is the trade
    /// R572-F1 already made and recorded.
    pub fn workload(
        &self,
        listen_port: u16,
        address: impl Fn(&DeployedUnit) -> Option<String>,
    ) -> Result<Workload> {
        let routes_path = self.routes_path();
        let name = self.workload_name();
        let listen = format!("127.0.0.1:{listen_port}");

        let env = vec![
            literal_env("PASSWAY_TLS_MODE", "plaintext".to_string()),
            literal_env("PASSWAY_LISTEN", listen),
            literal_env(
                "PASSWAY_PATH_ROUTES_FILE",
                routes_path.display().to_string(),
            ),
        ];

        let spec = WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.clone(),
            // Identity metadata only — the native backend pulls nothing.
            image: ImageRef {
                registry: "local".into(),
                repository: "passway".into(),
                tag: "inner-door".into(),
                digest: String::new(),
            },
            tier: TierTag("infra".into()),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            replicas: 1,
            command: Some(vec![INNER_DOOR_BINARY.to_string()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env,
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 128,
                cpu_millis: 256,
                ephemeral_storage_mb: 64,
            },
            depends_on: vec![],
            requires: vec![],
            healthcheck: Some(Healthcheck {
                // A cleartext listener would answer an HttpGet probe, but a
                // bare connect is the same liveness signal without asking the
                // door to route a synthetic path through a mount table that
                // may legitimately not have a catch-all for it.
                probe: HealthProbe::TcpConnect { port: listen_port },
                interval: Millis::from_secs(10),
                timeout: Millis::from_secs(2),
                initial_delay: Millis::from_secs(5),
                failure_threshold: 3,
            }),
            restart_policy: RestartPolicy::Always,
            // Pinned and non-drainable: the service's public door proxies to
            // this on loopback, so moving it to another node does not relocate
            // the thing that reaches it — it severs it.
            archetype: Some(LifecycleArchetype::Appliance),
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name),
                    ports: MeshExpose::anonymous_ports([listen_port]),
                    allow_from: vec![],
                },
                // Loopback only. Nothing off this node reaches an inner door,
                // which is the premise the cleartext listener rests on.
                public: None,
                operator: None,
            },
            labels: HashMap::new(),
            annotations: HashMap::new(),
            files: vec![InlineFile {
                path: routes_path,
                content: self.routes_file(address)?,
                mode: Some(0o600),
            }],
        };

        Ok(Workload::container(spec))
    }
}

fn literal_env(name: &str, value: String) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: EnvValue::Literal { value },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FrontDoor, RouteMode};

    fn component(id: &str, mount: Option<&str>, deploy: DeployTier) -> ServiceComponent {
        ServiceComponent {
            id: id.to_string(),
            kind: "mesofact-spa".to_string(),
            path: format!("app/{id}"),
            git: None,
            role: "static".to_string(),
            publishes: Some("static".to_string()),
            mount: mount.map(str::to_string),
            wave: 0,
            deploy,
        }
    }

    fn service(name: &str, components: Vec<ServiceComponent>) -> ServiceConfig {
        ServiceConfig {
            schema_version: 1,
            name: name.to_string(),
            domain: format!("{name}.test"),
            components,
            db: Default::default(),
        }
    }

    fn domains(service: &str, routes: &[(&str, &[(&str, &str)])]) -> BTreeMap<String, DomainConfig> {
        let mut map = BTreeMap::new();
        map.insert(
            "test".to_string(),
            DomainConfig {
                schema_version: 1,
                name: "test".to_string(),
                domain: format!("{service}.test"),
                front_door: FrontDoor::Passway,
                cdn_bucket: "cdn".to_string(),
                worker_bundle_path: None,
                routes: routes
                    .iter()
                    .map(|(path, headers)| DomainRoute {
                        path: path.to_string(),
                        headers: headers
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect(),
                        mode: RouteMode::Static {
                            component: format!("{service}/root"),
                        },
                    })
                    .collect(),
            },
        );
        map
    }

    /// Rule 1's negative, and the cheap half of this ticket's verify list: a
    /// single-component service produces no plan at all, so there is no config
    /// to write and no process to supervise.
    #[test]
    fn a_single_unit_service_gets_no_inner_door() {
        let svc = service(
            "yah-marketing",
            vec![component("site", None, DeployTier::Bundle)],
        );
        assert_eq!(plan(&svc, &BTreeMap::new()).unwrap(), None);
    }

    /// The same negative one step further out, and the one that would be easy
    /// to get wrong: THREE components still share one bundle, so they are one
    /// unit and still earn no door.
    #[test]
    fn several_bundle_components_are_one_unit_and_still_get_no_door() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("app", Some("app"), DeployTier::Bundle),
                component("docs", Some("docs"), DeployTier::Bundle),
            ],
        );
        assert_eq!(plan(&svc, &BTreeMap::new()).unwrap(), None);
    }

    #[test]
    fn one_bundle_component_plus_one_workload_component_is_two_units() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().expect("two units");
        assert_eq!(
            plan.mounts.iter().map(|m| m.mount.as_str()).collect::<Vec<_>>(),
            ["", "/app"]
        );
        assert_eq!(
            plan.units(),
            vec![
                DeployedUnit::Bundle,
                DeployedUnit::Component("account".into())
            ]
        );
    }

    /// The header half of the join: a mount picks up exactly the headers its
    /// own route declares, and the root picks up none when its route declares
    /// none. This is the config-side half of the ticket's live assertion that
    /// `/app/` carries COOP/COEP while `/` carries neither.
    #[test]
    fn each_mount_carries_only_its_own_routes_headers() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let domains = domains(
            "noisetable",
            &[
                ("/*", &[]),
                (
                    "/app/*",
                    &[
                        ("cross-origin-opener-policy", "same-origin"),
                        ("cross-origin-embedder-policy", "require-corp"),
                    ],
                ),
            ],
        );
        let plan = plan(&svc, &domains).unwrap().expect("two units");

        let root = &plan.mounts[0];
        assert_eq!(root.mount, "");
        assert!(root.headers.is_empty(), "{:?}", root.headers);

        let app = &plan.mounts[1];
        assert_eq!(app.mount, "/app");
        assert_eq!(
            app.headers.get("cross-origin-opener-policy").map(String::as_str),
            Some("same-origin")
        );
        assert_eq!(
            app.headers
                .get("cross-origin-embedder-policy")
                .map(String::as_str),
            Some("require-corp")
        );
    }

    /// A bundle-tier component at a non-root mount keeps its own headers even
    /// though it shares the bundle's upstream — the reason mounts are per
    /// COMPONENT while units are per deployed thing.
    #[test]
    fn a_bundle_components_sub_mount_keeps_its_headers_and_the_bundle_upstream() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("docs", Some("docs"), DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let domains = domains(
            "noisetable",
            &[("/docs/*", &[("x-frame-options", "DENY")])],
        );
        let plan = plan(&svc, &domains).unwrap().expect("two units");

        let docs = &plan.mounts[1];
        assert_eq!(docs.mount, "/docs");
        assert_eq!(docs.unit, DeployedUnit::Bundle);
        assert_eq!(docs.headers.get("x-frame-options").map(String::as_str), Some("DENY"));
        // Two units, three mounts.
        assert_eq!(plan.units().len(), 2);
        assert_eq!(plan.mounts.len(), 3);
    }

    #[test]
    fn a_table_with_no_root_mount_is_refused_rather_than_written() {
        let svc = service(
            "noisetable",
            vec![
                component("app", Some("app"), DeployTier::Bundle),
                component("account", Some("account"), DeployTier::Workload),
            ],
        );
        let err = plan(&svc, &BTreeMap::new()).unwrap_err().to_string();
        assert!(err.contains("no component at the service root"), "{err}");
    }

    #[test]
    fn rendering_produces_the_exact_shape_passway_reads() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let domains = domains(
            "noisetable",
            &[("/app/*", &[("cross-origin-opener-policy", "same-origin")])],
        );
        let plan = plan(&svc, &domains).unwrap().unwrap();

        let json = plan
            .routes_file(|unit| match unit {
                DeployedUnit::Bundle => Some("127.0.0.1:8081".to_string()),
                DeployedUnit::Component(id) if id == "account" => {
                    Some("127.0.0.1:8082".to_string())
                }
                DeployedUnit::Component(_) => None,
            })
            .unwrap();

        assert_eq!(
            json,
            r#"{"schema_version":1,"routes":[{"mount":"","upstreams":["127.0.0.1:8081"]},{"mount":"/app","upstreams":["127.0.0.1:8082"],"headers":{"cross-origin-opener-policy":"same-origin"}}]}"#
        );
    }

    /// An unresolved address must stop the write. Dropping the mount would
    /// leave the door serving `/app` from the ROOT mount with a 200 — the
    /// silent wrong answer, not a 503.
    #[test]
    fn an_unresolved_upstream_refuses_the_whole_table() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().unwrap();
        let err = plan
            .routes_file(|unit| match unit {
                DeployedUnit::Bundle => Some("127.0.0.1:8081".to_string()),
                DeployedUnit::Component(_) => None,
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("no resolved address"), "{err}");
        assert!(err.contains("account"), "{err}");
    }

    /// The rendered door, pinned on the four properties that are not
    /// cosmetic: cleartext ONLY on loopback, the routes file travelling inside
    /// the spec, and the env var passway selects path routing by.
    #[test]
    fn the_rendered_door_is_cleartext_on_loopback_and_carries_its_own_table() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().unwrap();
        let workload = plan
            .workload(8443, |unit| match unit {
                DeployedUnit::Bundle => Some("127.0.0.1:8081".to_string()),
                DeployedUnit::Component(_) => Some("127.0.0.1:8082".to_string()),
            })
            .unwrap();
        let spec = workload.container_spec().expect("container-shaped");

        let env: BTreeMap<&str, &str> = spec
            .env
            .iter()
            .filter_map(|e| match &e.value {
                EnvValue::Literal { value } => Some((e.name.as_str(), value.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(env.get("PASSWAY_TLS_MODE"), Some(&"plaintext"));
        // The invariant: cleartext is bound to loopback by construction, not
        // by whoever picked the port.
        assert_eq!(env.get("PASSWAY_LISTEN"), Some(&"127.0.0.1:8443"));
        assert!(spec.expose.public.is_none(), "an inner door is never public");

        // The routes file rides the spec, and the env var points AT it.
        assert_eq!(spec.files.len(), 1);
        let file = &spec.files[0];
        assert_eq!(
            env.get("PASSWAY_PATH_ROUTES_FILE").map(|s| s.to_string()),
            Some(file.path.display().to_string())
        );
        assert!(file.content.contains("\"schema_version\":1"), "{}", file.content);
        assert!(file.content.contains("127.0.0.1:8082"), "{}", file.content);
        assert_eq!(spec.command.as_deref(), Some(&[INNER_DOOR_BINARY.to_string()][..]));
    }

    /// A door whose table cannot be rendered is not rendered at all — the
    /// refusal propagates out of `workload`, so there is no spec that deploys
    /// a door pointing at nothing.
    #[test]
    fn an_unresolvable_unit_stops_the_workload_being_built() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().unwrap();
        assert!(plan.workload(8443, |_| None).is_err());
    }

    #[test]
    fn the_mount_spelling_matches_passways_convention_in_both_directions() {
        assert_eq!(passway_mount(None), "");
        assert_eq!(passway_mount(Some("")), "");
        assert_eq!(passway_mount(Some("/")), "");
        // Every spelling of one mount collapses to one string — the whole
        // reason this composes with `normalize_mount` instead of formatting.
        for raw in ["app", "/app", "app/", "/app/"] {
            assert_eq!(passway_mount(Some(raw)), "/app", "{raw}");
        }
        assert_eq!(passway_mount(Some("/a/b/")), "/a/b");
    }

    // ── Phase 2: placement (R870-F23 steps 2 and 3) ─────────────────────────

    /// The property the whole pin rests on: same service, same number, forever.
    /// The outer door's upstream list and the inner door's `PASSWAY_LISTEN` are
    /// rendered by two different call sites in two different apply phases; if
    /// this drifted, one tier would be repointed and the other would not.
    #[test]
    fn the_derived_port_is_stable_and_inside_its_declared_window() {
        assert_eq!(listen_port("noisetable"), listen_port("noisetable"));
        for service in ["noisetable", "yah-marketing", "", "a", "a-very-long-service-name"] {
            let port = listen_port(service);
            assert!(
                (INNER_DOOR_PORT_LOW..=INNER_DOOR_PORT_HIGH).contains(&port),
                "{service} -> {port}"
            );
            // Below the Linux default ephemeral floor, which is where
            // `kamaji::ports::pick_free_port`'s `bind(:0)` draws from. A number
            // inside that range could collide with a ledger allocation.
            assert!(port < 32_768, "{service} -> {port}");
        }
    }

    /// Different services get different doors. Not a guarantee the hash can
    /// make in general — 10_000 slots, so a collision is possible — but two
    /// services co-tenant on one node colliding is what this is checked
    /// against, and the two real ones do not.
    #[test]
    fn two_services_do_not_share_a_door() {
        assert_ne!(listen_port("noisetable"), listen_port("yah-marketing"));
    }

    /// Step 3's identity mapping. The two arms come from different places and
    /// the test says so: the bundle's ident is handed in (a mirror may rename
    /// it), a component's is derived from names the service already declares.
    #[test]
    fn each_unit_resolves_through_its_own_identity_rule() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().unwrap();

        assert_eq!(
            plan.unit_ident(&DeployedUnit::Bundle, "renamed-bundle"),
            "renamed-bundle",
            "a slot's `name = \"…\"` override has to win — it is what the record carries"
        );
        assert_eq!(
            plan.unit_ident(&DeployedUnit::Component("account".into()), "renamed-bundle"),
            "noisetable-account",
        );
    }

    /// A component id that is not already a legal mesh ident is folded, not
    /// passed through — the ident travels into a service-record lookup and a
    /// `MeshIdent`, both of which are lowercase-and-dash.
    #[test]
    fn a_derived_component_ident_is_folded_like_every_other_mesh_ident() {
        assert_eq!(
            component_workload_ident("Noise_Table", "Account.API"),
            "noise-table-account-api"
        );
    }

    /// Steps 2 and 3 joined: a two-unit service renders a door whose table
    /// names both resolved addresses and whose listener is the derived port.
    /// The positive half of the ticket's verify list, at the config tier.
    #[test]
    fn resolved_units_render_a_door_on_the_derived_port() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let domains = domains(
            "noisetable",
            &[(
                "/app/*",
                &[
                    ("cross-origin-opener-policy", "same-origin"),
                    ("cross-origin-embedder-policy", "require-corp"),
                ],
            )],
        );
        let plan = plan(&svc, &domains).unwrap().unwrap();

        let addresses = plan.resolve_addresses("noisetable", |ident| match ident {
            "noisetable" => Some("100.64.0.3:8080".to_string()),
            "noisetable-account" => Some("100.64.0.3:14001".to_string()),
            _ => None,
        });
        assert_eq!(addresses.len(), 2);

        let workload = plan
            .workload(plan.listen_port(), |unit| addresses.get(unit).cloned())
            .unwrap();
        let spec = workload.container_spec().expect("container-shaped");
        let listen = spec
            .env
            .iter()
            .find(|e| e.name == "PASSWAY_LISTEN")
            .and_then(|e| match &e.value {
                EnvValue::Literal { value } => Some(value.clone()),
                _ => None,
            })
            .expect("a door always declares its listener");
        assert_eq!(listen, format!("127.0.0.1:{}", listen_port("noisetable")));

        let table = &spec.files[0].content;
        assert!(table.contains("100.64.0.3:8080"), "{table}");
        assert!(table.contains("100.64.0.3:14001"), "{table}");
        assert!(table.contains("cross-origin-embedder-policy"), "{table}");
    }

    /// A unit that resolved to nothing is ABSENT from the map rather than
    /// present-and-empty — which is what makes `routes_file`'s refusal the
    /// single place a missing address is reported.
    #[test]
    fn an_unresolvable_unit_is_absent_rather_than_defaulted() {
        let svc = service(
            "noisetable",
            vec![
                component("site", None, DeployTier::Bundle),
                component("account", Some("app"), DeployTier::Workload),
            ],
        );
        let plan = plan(&svc, &BTreeMap::new()).unwrap().unwrap();
        let addresses = plan.resolve_addresses("noisetable", |ident| {
            (ident == "noisetable").then(|| "100.64.0.3:8080".to_string())
        });
        assert_eq!(addresses.len(), 1);
        assert!(!addresses.contains_key(&DeployedUnit::Component("account".into())));
        assert!(plan
            .workload(plan.listen_port(), |unit| addresses.get(unit).cloned())
            .is_err());
    }
}
