//! Bring-up for the dev-tier `pg` capability driver — the `yah-pg-dev`
//! workload (W265, R584-F1).
//!
//! # Why this is not a `Reconciler`
//!
//! Every other module here reconciles a *component* declared in a
//! `service.toml`. A driver isn't a component: it's the tier's implementation
//! of a capability, shared by every service on the tier. W265's P1 activation
//! model is "always-on at tier bring-up" — kamaji spawns the driver when the
//! dev tier comes up, before and independently of any particular component
//! reconcile. So the entry point here is a free function the camp daemon calls
//! once, not a [`super::Reconciler`] impl.
//!
//! # What kamaji does and doesn't do
//!
//! The workload manifest below is a plain native `WorkloadSpec` — a binary
//! path, its argv, and the kamaji Native backend's fork/exec, stdio capture and
//! SIGTERM→grace→SIGKILL teardown. There is no driver-specific machinery in
//! kamaji, which is the whole point of W265 §"Driver implementations ship as
//! default plugins" — a new driver is a new crate plus a manifest, and the camp
//! binary stays out of its hot path.
//!
//! Two honest gaps in that manifest, both deliberate:
//!
//! - `healthcheck` is declared but **kamaji's Native backend does not execute
//!   healthchecks today** (`kamaji::native` never reads the field). It is
//!   declared anyway so the contract is written down where the next reader
//!   looks, and so the containerd backend gets it for free. Readiness in the
//!   meantime is [`wait_for_coords`], which is a stronger signal than a TCP
//!   probe: the driver only publishes `coords.json` after initdb finished,
//!   the postmaster is listening, *and* every requested database exists.
//! - `restart_policy` is `Never`, matching [`super::native_support::native_spec`]'s
//!   reasoning: a driver that cannot start should surface its error once, not
//!   respawn behind a spinner. The F1 bullet asked for `restart=always`; that
//!   becomes correct when kamaji can distinguish "crashed after being healthy"
//!   from "never came up", and not before.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use kamaji::native::NativeRuntime;
use kamaji::{Kamaji, MeshAssignment, MeshIdent};
use tracing::{info, warn};

use super::native_support::{native_spec, sanitize_ident};
use crate::capability::Capability;
use crate::config::{MirrorConfig, Provider, ServiceWithMirrors};

/// Mesh ident of the camp's single pg driver. Camp-scoped, not per-service —
/// one cluster serves every service's database, the same way one MinIO serves
/// every pond bucket.
pub const PG_DRIVER_IDENT: &str = "yah-pg-dev";

/// Environment variable overriding the `yah-pg-dev` binary path, mirroring
/// `MESOFACT_DEV_BIN` for mesofact-dev.
pub const PG_DEV_BIN_ENV: &str = "YAH_PG_DEV_BIN";

/// Dev-tier mirror env name. The driver is a dev-tier implementation; sim
/// (pond) and cloud bind their own drivers for the same capability.
const DEV_ENV: &str = "dev";

/// How the camp brings the driver up.
#[derive(Debug, Clone, Default)]
pub struct PgDriverOptions {
    /// Explicit binary path. Falls back to [`PG_DEV_BIN_ENV`], then to bare
    /// `yah-pg-dev` resolved on `PATH` at spawn time.
    pub binary: Option<PathBuf>,
    /// How long to wait for `coords.json` after the workload is deployed.
    /// Default 180s — a *cold* camp downloads ~30 MB of PostgreSQL binaries and
    /// runs `initdb` inside this window; warm bring-up takes well under a
    /// second.
    pub ready_timeout: Option<Duration>,
}

impl PgDriverOptions {
    fn resolved_binary(&self) -> PathBuf {
        if let Some(ref p) = self.binary {
            return p.clone();
        }
        if let Some(p) = std::env::var_os(PG_DEV_BIN_ENV) {
            return PathBuf::from(p);
        }
        PathBuf::from("yah-pg-dev")
    }

    fn ready_timeout(&self) -> Duration {
        self.ready_timeout.unwrap_or(Duration::from_secs(180))
    }
}

/// A brought-up pg driver.
pub struct RunningPgDriver {
    /// Port the postmaster is listening on, read back out of `coords.json`.
    pub port: u16,
    /// Databases the driver was asked to create, in the order requested.
    pub databases: Vec<String>,
    runtime: Arc<NativeRuntime>,
    ident: MeshIdent,
}

impl RunningPgDriver {
    /// Stop the driver. The driver in turn stops the postmaster, so the cluster
    /// closes cleanly and `coords.json` is retracted.
    pub async fn teardown(&self) {
        self.runtime.teardown_workload(&self.ident).await.ok();
    }
}

/// Databases the dev tier should have, derived from the camp's config: one per
/// service whose `dev` mirror binds the `pg` capability to `local-pg-dev`.
///
/// Empty means no service asked for pg, and the caller should not spawn the
/// driver at all — W265's P1 activation is "always-on *for the tier*", and a
/// tier where nothing binds the capability has no driver to bring up. That is
/// what keeps a camp full of pure-static services from paying for a PostgreSQL
/// install it will never open.
pub fn declared_pg_databases(services: &BTreeMap<String, ServiceWithMirrors>) -> Vec<String> {
    let mut out = Vec::new();
    for (name, svc) in services {
        let Some(mirror) = svc.mirrors.get(DEV_ENV) else {
            continue;
        };
        if binds_local_pg_dev(mirror) {
            out.push(yah_pg_dev_database_name(name));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// `true` when this mirror binds `pg` to the dev-tier driver.
fn binds_local_pg_dev(mirror: &MirrorConfig) -> bool {
    mirror
        .driver(Capability::Pg)
        .and_then(|slot| slot.inline_kind())
        == Some(Provider::LocalPgDev)
}

/// Per-service database name. Kept byte-identical to `yah_pg_dev`'s own
/// `service_database_name(service, "dev")` — duplicated rather than depended on
/// because `cloud` must not take a dependency on the driver crate (the driver
/// is a separately-built plugin; that is the whole distribution model).
fn yah_pg_dev_database_name(service: &str) -> String {
    let sanitize = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect::<String>()
    };
    let mut name = format!("svc_{}_{}", sanitize(service), sanitize(DEV_ENV));
    name.truncate(63);
    name
}

/// Path of the driver's coordinates file. Mirrors `yah_pg_dev::coords_path`.
pub fn coords_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".yah/infra/state/dev/pg/coords.json")
}

/// Deploy `yah-pg-dev` on a kamaji [`NativeRuntime`] and wait for it to publish
/// coordinates.
///
/// Idempotent from the camp's point of view even across an unclean shutdown:
/// the driver itself adopts an already-running postmaster rather than
/// double-starting one, so a second bring-up converges on the same cluster.
pub async fn up_pg_driver(
    workspace_root: &Path,
    databases: Vec<String>,
    opts: &PgDriverOptions,
) -> Result<RunningPgDriver> {
    let binary = opts.resolved_binary();
    let ident_str = sanitize_ident(PG_DRIVER_IDENT);
    let ident = MeshIdent(ident_str.clone());

    let mut argv: Vec<String> = vec![
        binary.display().to_string(),
        "serve".to_string(),
        "--workspace".to_string(),
        workspace_root.display().to_string(),
    ];
    for db in &databases {
        argv.push("--database".to_string());
        argv.push(db.clone());
    }

    // Coordinates from a previous run describe a postmaster that may or may not
    // still be listening. Retract them first so `wait_for_coords` cannot
    // succeed on a stale file and hand the camp a dead port.
    let coords = coords_path(workspace_root);
    let _ = std::fs::remove_file(&coords);

    let spec = native_spec(&ident_str, argv, Vec::new());
    let state_dir = workspace_root.join(".yah/jit/native");
    let runtime = Arc::new(NativeRuntime::new(&state_dir));
    let mesh = MeshAssignment::inlined(Ipv4Addr::LOCALHOST);

    info!(
        binary = %binary.display(),
        databases = databases.len(),
        ident = %ident_str,
        "spawning yah-pg-dev (kamaji native backend)",
    );

    runtime
        .deploy_workload(&spec, &mesh)
        .await
        .with_context(|| {
            format!(
                "deploying the dev-tier pg driver via kamaji — install it with \
             `cargo install --path crates/yah/pg-dev` or point {PG_DEV_BIN_ENV} \
             at the binary ({})",
                binary.display(),
            )
        })?;

    let timeout = opts.ready_timeout();
    let Some(port) = wait_for_coords(&coords, timeout).await else {
        warn!(timeout = ?timeout, "yah-pg-dev did not publish coords; tearing down");
        runtime.teardown_workload(&ident).await.ok();
        let (_out, err) = super::native_support::capture_paths(&state_dir, &ident_str);
        anyhow::bail!(
            "the dev-tier pg driver did not become ready within {timeout:?} — \
             check {} for why",
            err.display(),
        );
    };

    info!(
        port,
        databases = databases.len(),
        "dev-tier pg driver ready"
    );
    Ok(RunningPgDriver {
        port,
        databases,
        runtime,
        ident,
    })
}

/// Poll for the driver's `coords.json` and return the port it advertises.
///
/// Polling rather than watching: the write is a rename into place, one file,
/// once per bring-up — an inotify/FSEvents watcher would be more machinery than
/// the thing it observes.
async fn wait_for_coords(path: &Path, timeout: Duration) -> Option<u16> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(port) = read_coords_port(path) {
            return Some(port);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Port advertised by a complete `coords.json`, or `None` when the file is
/// absent, half-written, or reports port 0 (a driver that has not bound yet).
fn read_coords_port(path: &Path) -> Option<u16> {
    let bytes = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let port = u16::try_from(v.get("port")?.as_u64()?).ok()?;
    (port != 0).then_some(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServiceConfig;

    fn service(name: &str, dev_mirror: Option<&str>) -> ServiceWithMirrors {
        let service: ServiceConfig = toml::from_str(&format!(
            "schema_version = 1\nname = \"{name}\"\ndomain = \"{name}.example\"\n"
        ))
        .expect("parse service");
        let mut mirrors = BTreeMap::new();
        if let Some(src) = dev_mirror {
            mirrors.insert(
                DEV_ENV.to_string(),
                toml::from_str::<MirrorConfig>(src).expect("parse mirror"),
            );
        }
        ServiceWithMirrors {
            service,
            mirrors,
            component_transform_recipes: BTreeMap::new(),
            passway_machines: BTreeMap::new(),
        }
    }

    const BINDS_PG: &str = r#"
schema_version = 1
shape = "local"
[drivers.pg]
kind = "local-pg-dev"
"#;

    const NO_DRIVERS: &str = r#"
schema_version = 1
shape = "local"
[providers.static]
kind = "local-static"
port = 4324
"#;

    fn services(entries: Vec<(&str, ServiceWithMirrors)>) -> BTreeMap<String, ServiceWithMirrors> {
        entries
            .into_iter()
            .map(|(n, s)| (n.to_string(), s))
            .collect()
    }

    #[test]
    fn only_services_binding_the_pg_driver_get_a_database() {
        let svcs = services(vec![
            ("scrabcake", service("scrabcake", Some(BINDS_PG))),
            ("yah-dashboard", service("yah-dashboard", Some(NO_DRIVERS))),
            ("yah-cloud", service("yah-cloud", None)),
        ]);
        assert_eq!(
            declared_pg_databases(&svcs),
            vec!["svc_scrabcake_dev".to_string()]
        );
    }

    #[test]
    fn no_binding_anywhere_means_no_driver_to_spawn() {
        let svcs = services(vec![(
            "yah-dashboard",
            service("yah-dashboard", Some(NO_DRIVERS)),
        )]);
        assert!(declared_pg_databases(&svcs).is_empty());
    }

    /// A `pond`/`cloud` mirror binding pg must not conscript the *dev* driver —
    /// the whole point of the model is that each tier binds its own.
    #[test]
    fn a_non_dev_mirror_binding_pg_is_ignored() {
        let mut svc = service("scrabcake", None);
        svc.mirrors.insert(
            "pond".to_string(),
            toml::from_str::<MirrorConfig>(BINDS_PG).expect("parse mirror"),
        );
        assert!(declared_pg_databases(&services(vec![("scrabcake", svc)])).is_empty());
    }

    #[test]
    fn database_names_match_the_drivers_own_convention() {
        // Byte-identical to `yah_pg_dev::service_database_name(name, "dev")`,
        // which its own unit tests pin from the other side.
        assert_eq!(
            yah_pg_dev_database_name("yah-dashboard"),
            "svc_yah_dashboard_dev"
        );
        assert_eq!(yah_pg_dev_database_name("Scrabcake"), "svc_scrabcake_dev");
    }

    #[test]
    fn binary_resolution_prefers_explicit_over_env_over_path() {
        let explicit = PgDriverOptions {
            binary: Some(PathBuf::from("/opt/yah-pg-dev")),
            ..Default::default()
        };
        assert_eq!(explicit.resolved_binary(), PathBuf::from("/opt/yah-pg-dev"));
        // Env is only consulted when there is no explicit path; asserting the
        // bare-name fallback without mutating process env keeps this test
        // parallel-safe.
        if std::env::var_os(PG_DEV_BIN_ENV).is_none() {
            assert_eq!(
                PgDriverOptions::default().resolved_binary(),
                PathBuf::from("yah-pg-dev")
            );
        }
    }

    #[tokio::test]
    async fn wait_for_coords_times_out_on_a_missing_or_portless_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("coords.json");
        assert_eq!(
            wait_for_coords(&path, Duration::from_millis(150)).await,
            None
        );
        // A file whose port is 0 is a driver that hasn't bound yet, not ready.
        std::fs::write(&path, br#"{"port":0}"#).unwrap();
        assert_eq!(
            wait_for_coords(&path, Duration::from_millis(150)).await,
            None
        );
    }

    #[tokio::test]
    async fn wait_for_coords_returns_the_published_port() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("coords.json");
        std::fs::write(&path, br#"{"port":25432,"username":"postgres"}"#).unwrap();
        assert_eq!(
            wait_for_coords(&path, Duration::from_secs(1)).await,
            Some(25432)
        );
    }
}
