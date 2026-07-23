//! Deploy-time mesh-address resolution for yubaba workloads (R090-F6).
//!
//! Bridges [`workload_spec::EnvValue::FromMesh`] references to literal env
//! values rendered from the cluster's currently-deployed mesh state. Two
//! pieces:
//!
//! 1. [`MeshState`] — read-only view of "which mesh idents are deployed and
//!    which ports they expose", abstracted so yubaba's production impl reads
//!    from raft and tests use an in-memory fake.
//! 2. [`StateMeshResolver`] — adapter implementing
//!    [`workload_spec::validate::MeshResolver`] from [`MeshState`]; resolves
//!    `Url` / `Host` / `Port` per the arch doc.
//!
//! Plus [`await_dependencies`], which polls [`MeshState`] every 250ms (or a
//! caller-supplied cadence) until every entry in `spec.depends_on` appears,
//! or fails with [`workload_spec::validate::MeshError::NotDeployed`] once the
//! deadline elapses.
//!
//! **Stage placement:** F4 stage 3 (mesh peering) → F6 (this module) →
//! containerd start. `EnvValue::FromMesh` stays a reference at the spec
//! layer; only becomes a literal when yubaba assembles the containerd spec
//! after this module renders it.

use std::collections::HashMap;
use std::time::Duration;

use tokio::time::Instant;
use workload_spec::validate::{MeshError, MeshResolver};
use workload_spec::{MeshIdent, MeshLookup, WorkloadSpec};

/// Snapshot of a deployed workload's mesh exposure as visible to the
/// resolver. Returned by [`MeshState::lookup`].
///
/// `dependency_wait_deadline` is the time yubaba should be willing to wait
/// for *this workload* to come up before failing dependents — i.e.
/// `failure_threshold × interval + initial_delay` from its `Healthcheck`,
/// or a sensible default for workloads without one. Used by
/// [`compute_dependency_deadline`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAddress {
    pub ident: MeshIdent,
    pub ports: Vec<u16>,
    pub dependency_wait_deadline: Option<Duration>,
}

/// Read-only view of the cluster's deployed mesh state.
///
/// Yubaba's production impl reads from raft; tests use an in-memory fake.
/// [`StateMeshResolver`] adapts any `MeshState` into a [`MeshResolver`].
pub trait MeshState: Send + Sync {
    /// Returns the deployed address for `ident`, or `None` if it's not yet on
    /// the mesh. Implementations should be cheap — [`await_dependencies`]
    /// calls this on every poll tick.
    fn lookup(&self, ident: &MeshIdent) -> Option<MeshAddress>;
}

/// Adapter that implements [`MeshResolver`] using a [`MeshState`] for lookups.
///
/// Resolution rules per the arch doc §"Mesh-derived env":
/// - `Url`  → `"http://<ident>:<first_port>"`
/// - `Host` → bare DNS-ish identity
/// - `Port` → first port stringified
///
/// All three rules use the **first** entry in
/// [`MeshAddress::ports`] — so a workload that exposes multiple ports must
/// list its primary port first to keep `Url` and `Port` consistent.
pub struct StateMeshResolver<'a> {
    state: &'a dyn MeshState,
}

impl<'a> StateMeshResolver<'a> {
    pub fn new(state: &'a dyn MeshState) -> Self {
        Self { state }
    }
}

impl<'a> MeshResolver for StateMeshResolver<'a> {
    fn resolve(&self, ident: &MeshIdent, kind: MeshLookup) -> Result<String, MeshError> {
        let addr = self
            .state
            .lookup(ident)
            .ok_or_else(|| MeshError::NotDeployed {
                ident: ident.0.clone(),
            })?;
        match kind {
            MeshLookup::Host => Ok(addr.ident.0.clone()),
            MeshLookup::Port => {
                addr.ports
                    .first()
                    .map(|p| p.to_string())
                    .ok_or(MeshError::NoPorts {
                        ident: ident.0.clone(),
                        lookup: kind,
                    })
            }
            MeshLookup::Url => addr
                .ports
                .first()
                .map(|p| format!("http://{}:{}", addr.ident.0, p))
                .ok_or(MeshError::NoPorts {
                    ident: ident.0.clone(),
                    lookup: kind,
                }),
        }
    }
}

// ── In-memory state used by tests and by yubaba's pre-raft single-node mode ──

/// Simple `HashMap`-backed [`MeshState`] for tests and for yubaba's
/// not-yet-on-raft single-machine mode.
///
/// The production multi-machine yubaba replaces this with a raft-state read
/// in `crates/yah/yubaba/src/raft/`.
#[derive(Debug, Default, Clone)]
pub struct InMemoryMeshState {
    by_ident: HashMap<String, MeshAddress>,
}

impl InMemoryMeshState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace an address for `ident`.
    pub fn insert(&mut self, addr: MeshAddress) {
        self.by_ident.insert(addr.ident.0.clone(), addr);
    }

    /// Remove an ident — used in tests that simulate a workload coming up
    /// after the dependent has started waiting.
    pub fn remove(&mut self, ident: &MeshIdent) {
        self.by_ident.remove(&ident.0);
    }
}

impl MeshState for InMemoryMeshState {
    fn lookup(&self, ident: &MeshIdent) -> Option<MeshAddress> {
        self.by_ident.get(&ident.0).cloned()
    }
}

// ── Dependency wait ──────────────────────────────────────────────────────────

/// Default poll cadence used when a caller doesn't override it.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Compute the dependency-wait deadline as the sum of each dep's
/// `dependency_wait_deadline`, defaulting to `default_per_dep` for any dep
/// not yet in `state` (or with no healthcheck).
///
/// Matches the arch doc rule "time out at sum(spec.depends_on healthchecks)"
/// — when a dep's healthcheck is known we use it, otherwise a fallback so
/// unknown deps don't make the wait infinite.
pub fn compute_dependency_deadline(
    spec: &WorkloadSpec,
    state: &dyn MeshState,
    default_per_dep: Duration,
) -> Duration {
    spec.depends_on
        .iter()
        .map(|dep| {
            state
                .lookup(dep)
                .and_then(|a| a.dependency_wait_deadline)
                .unwrap_or(default_per_dep)
        })
        .sum()
}

/// Wait until every entry in `spec.depends_on` is observable in `state`, or
/// fail with [`MeshError::NotDeployed`] once `deadline` elapses.
///
/// Polls every `poll_interval` (use [`DEFAULT_POLL_INTERVAL`] for the 250ms
/// production cadence). The first tick runs immediately so already-deployed
/// dependencies don't pay the poll-interval cost.
///
/// Returns `Ok(())` immediately when `spec.depends_on` is empty.
pub async fn await_dependencies(
    spec: &WorkloadSpec,
    state: &dyn MeshState,
    deadline: Duration,
    poll_interval: Duration,
) -> Result<(), MeshError> {
    if spec.depends_on.is_empty() {
        return Ok(());
    }
    let start = Instant::now();
    loop {
        let missing: Option<&MeshIdent> = spec
            .depends_on
            .iter()
            .find(|dep| state.lookup(dep).is_none());
        match missing {
            None => return Ok(()),
            Some(dep) if start.elapsed() >= deadline => {
                return Err(MeshError::NotDeployed {
                    ident: dep.0.clone(),
                });
            }
            Some(_) => tokio::time::sleep(poll_interval).await,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod mesh {
    mod resolve {
        //! Fake-raft-state coverage for Url/Host/Port + waiting-for-dependency
        //! + timeout-after-deps-deadline.

        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use workload_spec::validate::{MeshError, MeshResolver};
        use workload_spec::*;

        use crate::deploy::mesh_resolve::{
            await_dependencies, compute_dependency_deadline, InMemoryMeshState, MeshAddress,
            MeshState, StateMeshResolver,
        };

        // ── Minimal spec helper ──────────────────────────────────────────────

        fn spec_with_depends_on(deps: Vec<MeshIdent>) -> WorkloadSpec {
            WorkloadSpec {
                schema_version: SchemaVersion::V1,
                name: "consumer".into(),
                image: ImageRef {
                    registry: "ghcr.io".into(),
                    repository: "test/consumer".into(),
                    tag: "v1".into(),
                    digest: workload_spec::testing::test_digest(),
                },
                tier: TierTag("private".into()),
                tenant: workload_spec::TenantId::singleton(),
                namespace: workload_spec::NamespaceId::singleton(),
                replicas: 1,
                command: None,
                entrypoint: None,
                workdir: None,
                user: None,
                env: vec![],
                secrets: vec![],
                volumes: vec![],
                resources: ResourceLimits {
                    memory_mb: 64,
                    cpu_millis: 256,
                    ephemeral_storage_mb: 64,
                },
                depends_on: deps,
                healthcheck: None,
                restart_policy: RestartPolicy::Always,
                archetype: None,
                stop_policy: StopPolicy {
                    signal: 15,
                    grace_period: Millis::from_secs(5),
                },
                expose: ExposeSpec {
                    mesh: MeshExpose {
                        identity: MeshIdent("consumer".into()),
                        ports: vec![8080],
                        allow_from: vec![],
                    },
                    public: None,
                    operator: None,
                },
                labels: HashMap::new(),
                annotations: HashMap::new(),
            }
        }

        fn db_address() -> MeshAddress {
            MeshAddress {
                ident: MeshIdent("noisetable-db.pdx".into()),
                ports: vec![5432, 9100],
                dependency_wait_deadline: Some(Duration::from_secs(45)),
            }
        }

        // ── Url / Host / Port ────────────────────────────────────────────────

        #[test]
        fn url_renders_first_port_with_http_prefix() {
            let mut state = InMemoryMeshState::new();
            state.insert(db_address());
            let resolver = StateMeshResolver::new(&state);
            let value = resolver
                .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Url)
                .expect("resolve");
            assert_eq!(value, "http://noisetable-db.pdx:5432");
        }

        #[test]
        fn host_renders_bare_ident() {
            let mut state = InMemoryMeshState::new();
            state.insert(db_address());
            let resolver = StateMeshResolver::new(&state);
            let value = resolver
                .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Host)
                .expect("resolve");
            assert_eq!(value, "noisetable-db.pdx");
        }

        #[test]
        fn port_renders_first_port_as_string() {
            let mut state = InMemoryMeshState::new();
            state.insert(db_address());
            let resolver = StateMeshResolver::new(&state);
            let value = resolver
                .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Port)
                .expect("resolve");
            assert_eq!(value, "5432");
        }

        #[test]
        fn unknown_ident_returns_not_deployed() {
            let state = InMemoryMeshState::new();
            let resolver = StateMeshResolver::new(&state);
            let err = resolver
                .resolve(&MeshIdent("absent.pdx".into()), MeshLookup::Url)
                .unwrap_err();
            assert_eq!(
                err,
                MeshError::NotDeployed {
                    ident: "absent.pdx".into()
                }
            );
        }

        #[test]
        fn deployed_but_no_ports_returns_no_ports_for_url_and_port_lookups() {
            let mut state = InMemoryMeshState::new();
            state.insert(MeshAddress {
                ident: MeshIdent("portless".into()),
                ports: vec![],
                dependency_wait_deadline: None,
            });
            let resolver = StateMeshResolver::new(&state);

            assert_eq!(
                resolver
                    .resolve(&MeshIdent("portless".into()), MeshLookup::Url)
                    .unwrap_err(),
                MeshError::NoPorts {
                    ident: "portless".into(),
                    lookup: MeshLookup::Url,
                }
            );
            assert_eq!(
                resolver
                    .resolve(&MeshIdent("portless".into()), MeshLookup::Port)
                    .unwrap_err(),
                MeshError::NoPorts {
                    ident: "portless".into(),
                    lookup: MeshLookup::Port,
                }
            );
            // Host doesn't need a port and still resolves
            assert_eq!(
                resolver
                    .resolve(&MeshIdent("portless".into()), MeshLookup::Host)
                    .expect("host resolve"),
                "portless"
            );
        }

        // ── Wait for dependency ──────────────────────────────────────────────

        /// `MeshState` impl that flips an ident from absent to present after
        /// `appear_after` polls. Used by the wait-for-dep test.
        #[derive(Clone)]
        struct DelayedAppearance {
            counter: Arc<Mutex<u32>>,
            appear_after: u32,
            ident: MeshIdent,
            address: MeshAddress,
        }

        impl MeshState for DelayedAppearance {
            fn lookup(&self, ident: &MeshIdent) -> Option<MeshAddress> {
                if ident.0 != self.ident.0 {
                    return None;
                }
                let mut count = self.counter.lock().unwrap();
                *count += 1;
                if *count > self.appear_after {
                    Some(self.address.clone())
                } else {
                    None
                }
            }
        }

        #[tokio::test]
        async fn await_dependencies_returns_ok_when_dep_appears_during_polling() {
            let state = DelayedAppearance {
                counter: Arc::new(Mutex::new(0)),
                appear_after: 3, // present on the 4th poll
                ident: MeshIdent("noisetable-db.pdx".into()),
                address: db_address(),
            };
            let spec = spec_with_depends_on(vec![MeshIdent("noisetable-db.pdx".into())]);

            let result = await_dependencies(
                &spec,
                &state,
                Duration::from_secs(5),
                Duration::from_millis(1),
            )
            .await;
            assert!(
                result.is_ok(),
                "expected Ok once dep appears, got {result:?}"
            );
            assert!(
                *state.counter.lock().unwrap() >= 4,
                "polled at least 4 times before resolving"
            );
        }

        #[tokio::test]
        async fn await_dependencies_returns_ok_immediately_when_already_deployed() {
            let mut state = InMemoryMeshState::new();
            state.insert(db_address());
            let spec = spec_with_depends_on(vec![MeshIdent("noisetable-db.pdx".into())]);

            let result = await_dependencies(
                &spec,
                &state,
                Duration::from_secs(5),
                Duration::from_millis(1),
            )
            .await;
            assert!(result.is_ok(), "expected Ok, got {result:?}");
        }

        #[tokio::test]
        async fn await_dependencies_returns_ok_for_empty_deps() {
            let state = InMemoryMeshState::new();
            let spec = spec_with_depends_on(vec![]);
            let result = await_dependencies(
                &spec,
                &state,
                Duration::from_millis(1),
                Duration::from_millis(1),
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn await_dependencies_times_out_after_deps_deadline() {
            let state = InMemoryMeshState::new(); // dep never appears
            let spec = spec_with_depends_on(vec![MeshIdent("never-deploys".into())]);
            let err = await_dependencies(
                &spec,
                &state,
                Duration::from_millis(20),
                Duration::from_millis(1),
            )
            .await
            .unwrap_err();
            assert_eq!(
                err,
                MeshError::NotDeployed {
                    ident: "never-deploys".into()
                }
            );
        }

        #[tokio::test]
        async fn await_dependencies_times_out_on_first_missing_when_others_known() {
            let mut state = InMemoryMeshState::new();
            state.insert(db_address()); // first dep present
            let spec = spec_with_depends_on(vec![
                MeshIdent("noisetable-db.pdx".into()),
                MeshIdent("never-deploys".into()),
            ]);
            let err = await_dependencies(
                &spec,
                &state,
                Duration::from_millis(20),
                Duration::from_millis(1),
            )
            .await
            .unwrap_err();
            assert_eq!(
                err,
                MeshError::NotDeployed {
                    ident: "never-deploys".into()
                }
            );
        }

        // ── compute_dependency_deadline ──────────────────────────────────────

        #[test]
        fn deadline_sums_known_dep_healthchecks_and_falls_back_to_default() {
            let mut state = InMemoryMeshState::new();
            state.insert(MeshAddress {
                ident: MeshIdent("a".into()),
                ports: vec![1],
                dependency_wait_deadline: Some(Duration::from_secs(10)),
            });
            state.insert(MeshAddress {
                ident: MeshIdent("b".into()),
                ports: vec![2],
                dependency_wait_deadline: Some(Duration::from_secs(15)),
            });
            // c is not registered, so default applies.
            let spec = spec_with_depends_on(vec![
                MeshIdent("a".into()),
                MeshIdent("b".into()),
                MeshIdent("c".into()),
            ]);

            let deadline = compute_dependency_deadline(&spec, &state, Duration::from_secs(20));
            assert_eq!(deadline, Duration::from_secs(10 + 15 + 20));
        }

        #[test]
        fn deadline_uses_default_when_dep_lacks_healthcheck() {
            let mut state = InMemoryMeshState::new();
            state.insert(MeshAddress {
                ident: MeshIdent("a".into()),
                ports: vec![1],
                dependency_wait_deadline: None, // dep deployed but has no healthcheck
            });
            let spec = spec_with_depends_on(vec![MeshIdent("a".into())]);
            let deadline = compute_dependency_deadline(&spec, &state, Duration::from_secs(7));
            assert_eq!(deadline, Duration::from_secs(7));
        }
    }
}
