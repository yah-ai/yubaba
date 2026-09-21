//! Bring-up for the dev-tier `s3` capability driver — the `yah-s3-fs`
//! workload (W265, R584-F3).
//!
//! Fourth instance of the capability/driver shape behind [`super::pg_driver`]
//! and [`super::smtp_driver`], and the same shape on purpose: a free function
//! the camp daemon calls once at tier bring-up rather than a
//! [`super::Reconciler`], because a driver is the *tier's* implementation of a
//! capability rather than anybody's component. `pg_driver`'s module doc has
//! the full argument and everything it says about kamaji's role applies here
//! unchanged.
//!
//! # The one place this deliberately differs from pg and smtp
//!
//! **Activation is always-on, not keyed off a `[drivers.s3]` stanza.**
//!
//! pg and smtp both gate on a mirror declaring the binding, and that is right
//! for them: most services never open a database and fewer still send mail, so
//! a default-on driver would have every camp on the machine downloading and
//! supervising something nobody opens. Neither reason holds here.
//!
//! - Object storage is what a *static* service needs, and static is the
//!   default shape in this tree. [`Capability::for_component_kind`] already
//!   returns `[S3]` for `mesofact-static`, `mesofact-spa` and `static-asset`
//!   without anyone declaring anything.
//! - The cost of being wrong is a few MB. This driver fetches nothing and
//!   spawns nothing: it is one small Rust binary holding a listener and a
//!   directory, where pg is a PostgreSQL install and smtp is a 10 MB download.
//! - It is *replacing* something that was already unconditional. The camp
//!   daemon has spawned an in-process S3 stub for every service with a dev
//!   mirror since R274-F5. Making the de-embedded driver opt-in would be a
//!   behaviour regression dressed as caution — every existing dev service
//!   would lose its `S3_ENDPOINT`.
//!
//! So [`camp_needs_s3_driver`] is true for any camp with a dev mirror at all,
//! and an explicit `[drivers.s3] kind = "local-s3-fs"` is documentation rather
//! than a switch. The stanza still matters for the *other* tiers, where the
//! same capability binds `minio-container` or `cloudflare-r2`.
//!
//! # Buckets
//!
//! One per service with a dev mirror, named after the service — which is the
//! `S3_BUCKET` the camp has injected since R274-F5, so nothing downstream
//! changes. They are created before `coords.json` is published, making the
//! coords file mean "you can PUT now" rather than "the port is open".

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use kamaji::native::NativeRuntime;
use kamaji::{Kamaji, MeshAssignment, MeshIdent};
use tracing::{info, warn};
use workload_spec::MeshPort;

use super::native_support::{native_spec, sanitize_ident};
use crate::capability::Capability;
use crate::config::{MirrorConfig, Provider, ServiceWithMirrors};

/// Mesh ident of the camp's single S3 driver. Camp-scoped, not per-service —
/// one store holds every service's bucket, the same way one MinIO serves every
/// pond bucket. The stub this replaces ran one server *per service*, which was
/// the one thing about it that did not match any other tier.
pub const S3_DRIVER_IDENT: &str = "yah-s3-fs";

/// Environment variable overriding the `yah-s3-fs` binary path, mirroring
/// [`super::pg_driver::PG_DEV_BIN_ENV`].
pub const S3_FS_BIN_ENV: &str = "YAH_S3_FS_BIN";

/// Port name declared in `expose.mesh.ports`. kamaji uppercases it into
/// `PORT_S3`, which the driver reads.
pub const PORT_NAME_S3: &str = "s3";

/// Dev-tier mirror env name. The driver is a dev-tier implementation; pond and
/// cloud bind their own drivers for the same capability.
const DEV_ENV: &str = "dev";

/// Access key an in-camp consumer signs with.
///
/// Fixed strings rather than generated ones, and that is deliberate: the
/// listener is loopback/veth-only and the driver does not verify signature
/// *bytes* (W265 §"Signature bytes are not verified"), so what these buy is
/// the presence of an `Authorization` header — which is what separates the
/// publisher from a browser and therefore what makes the bucket-policy path
/// mean anything. A consumer that needs to reach the store from outside the
/// camp is a different tier's problem.
pub const DEV_ACCESS_KEY: &str = "yahdev";

/// Secret key paired with [`DEV_ACCESS_KEY`]. Not a credential in any
/// meaningful sense — see that constant.
pub const DEV_SECRET_KEY: &str = "yahdev-local-only";

/// How the camp brings the driver up.
#[derive(Debug, Clone, Default)]
pub struct S3DriverOptions {
    /// Explicit binary path. Falls back to [`S3_FS_BIN_ENV`], then to bare
    /// `yah-s3-fs` resolved on `PATH` at spawn time.
    pub binary: Option<PathBuf>,
    /// How long to wait for `coords.json` after the workload is deployed.
    /// Default 30s — far shorter than pg's 180s or smtp's 120s because there
    /// is no cold path to wait out: bring-up is a `mkdir` and a `bind`, so
    /// anything past a second here means the binary is missing or wedged, and
    /// making the operator watch a three-minute spinner to find that out is
    /// the wrong trade.
    pub ready_timeout: Option<Duration>,
}

impl S3DriverOptions {
    fn resolved_binary(&self) -> PathBuf {
        if let Some(ref p) = self.binary {
            return p.clone();
        }
        if let Some(p) = std::env::var_os(S3_FS_BIN_ENV) {
            return PathBuf::from(p);
        }
        PathBuf::from("yah-s3-fs")
    }

    fn ready_timeout(&self) -> Duration {
        self.ready_timeout.unwrap_or(Duration::from_secs(30))
    }
}

/// A brought-up S3 driver.
pub struct RunningS3Driver {
    /// Port the S3 listener accepted on, read back out of `coords.json`.
    pub port: u16,
    /// Endpoint consumers dial, e.g. `http://127.0.0.1:51234`. This is the
    /// string the camp injects as `S3_ENDPOINT`.
    pub endpoint: String,
    /// Buckets the driver was asked to create, sorted.
    pub buckets: Vec<String>,
    runtime: Arc<NativeRuntime>,
    ident: MeshIdent,
}

impl RunningS3Driver {
    /// Stop the driver. It retracts `coords.json` on the way out, so the next
    /// bring-up cannot read a dead port off a stale file.
    pub async fn teardown(&self) {
        self.runtime.teardown_workload(&self.ident).await.ok();
    }
}

/// `true` when this camp should run the dev-tier S3 driver.
///
/// Any service with a `dev` mirror counts — see the module doc for why this is
/// deliberately weaker than pg's and smtp's test. A camp with no dev mirror at
/// all has no dev tier to bring up, and gets nothing.
pub fn camp_needs_s3_driver(services: &BTreeMap<String, ServiceWithMirrors>) -> bool {
    services
        .values()
        .any(|svc| svc.mirrors.contains_key(DEV_ENV))
}

/// Buckets the dev tier should have: one per service with a `dev` mirror,
/// named after the service.
///
/// Sorted and deduped so a camp brings the same buckets up in the same order
/// every boot, which keeps `coords.json` byte-stable across restarts and makes
/// a diff of it mean something.
pub fn declared_s3_buckets(services: &BTreeMap<String, ServiceWithMirrors>) -> Vec<String> {
    let mut out: Vec<String> = services
        .iter()
        .filter(|(_, svc)| svc.mirrors.contains_key(DEV_ENV))
        .map(|(name, _)| name.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `true` when this mirror explicitly binds `s3` to the dev-tier driver.
///
/// Not consulted by [`camp_needs_s3_driver`] — the driver is always-on — but
/// kept because it is how a reader, and R584-F4's mesofact wiring, asks
/// "which implementation does this tier name for s3".
pub fn binds_local_s3_fs(mirror: &MirrorConfig) -> bool {
    mirror
        .driver(Capability::S3)
        .and_then(|slot| slot.inline_kind())
        == Some(Provider::LocalS3Fs)
}

/// Path of the driver's coordinates file. Mirrors `yah_s3_fs::coords_path`.
pub fn coords_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".yah/infra/state/dev/s3/coords.json")
}

/// Where the camp's running S3 driver can be reached, read out of the
/// `coords.json` it publishes at bring-up.
///
/// `None` means the driver is not up. That is a *diagnosable* state rather
/// than an error here, because the caller (the mesofact dev arm) can say
/// something far more useful than "file not found" — see
/// [`super::pond::up_dev_door`].
///
/// Read structurally rather than through `yah_s3_fs::Coords` for the same
/// reason [`read_coords`] is: `cloud` must not depend on a separately-built
/// plugin crate.
pub fn running_endpoint(workspace_root: &Path) -> Option<String> {
    read_coords(&coords_path(workspace_root)).map(|c| c.endpoint)
}

/// Deploy `yah-s3-fs` on a kamaji [`NativeRuntime`] and wait for it to publish
/// coordinates.
pub async fn up_s3_driver(
    workspace_root: &Path,
    buckets: Vec<String>,
    opts: &S3DriverOptions,
) -> Result<RunningS3Driver> {
    let binary = opts.resolved_binary();
    let ident_str = sanitize_ident(S3_DRIVER_IDENT);
    let ident = MeshIdent(ident_str.clone());

    let mut argv: Vec<String> = vec![
        binary.display().to_string(),
        "serve".to_string(),
        "--workspace".to_string(),
        workspace_root.display().to_string(),
    ];
    for bucket in &buckets {
        argv.push("--bucket".to_string());
        argv.push(bucket.clone());
    }

    // Coordinates from a previous run describe a listener that may or may not
    // still be up. Retract them first so `wait_for_coords` cannot succeed on a
    // stale file and hand every app in the camp a dead `S3_ENDPOINT`.
    let coords = coords_path(workspace_root);
    let _ = std::fs::remove_file(&coords);

    let mut spec = native_spec(&ident_str, argv, Vec::new());
    // Name-only: kamaji allocates the number and remembers it per (workload,
    // port name) across a supervisor restart, telling the driver via `PORT_S3`.
    // A pinned number would be a collision waiting for the second camp on this
    // laptop, and consumers read the real port out of `coords.json` anyway.
    spec.expose.mesh.ports = vec![MeshPort::named(PORT_NAME_S3)];

    let state_dir = workspace_root.join(".yah/jit/native");
    let runtime = Arc::new(NativeRuntime::new(&state_dir));
    let mesh = MeshAssignment::inlined(Ipv4Addr::LOCALHOST);

    info!(
        binary = %binary.display(),
        buckets = buckets.len(),
        ident = %ident_str,
        "spawning yah-s3-fs (kamaji native backend)",
    );

    runtime
        .deploy_workload(&spec, &mesh)
        .await
        .with_context(|| {
            format!(
                "deploying the dev-tier s3 driver via kamaji — install it with \
                 `cargo install --path crates/yah/s3-fs` or point {S3_FS_BIN_ENV} \
                 at the binary ({})",
                binary.display(),
            )
        })?;

    let timeout = opts.ready_timeout();
    let Some(ready) = wait_for_coords(&coords, timeout).await else {
        warn!(timeout = ?timeout, "yah-s3-fs did not publish coords; tearing down");
        runtime.teardown_workload(&ident).await.ok();
        let (_out, err) = super::native_support::capture_paths(&state_dir, &ident_str);
        anyhow::bail!(
            "the dev-tier s3 driver did not become ready within {timeout:?} — \
             check {} for why",
            err.display(),
        );
    };

    info!(
        port = ready.port,
        endpoint = %ready.endpoint,
        buckets = ready.buckets.len(),
        "dev-tier s3 driver ready",
    );
    Ok(RunningS3Driver {
        port: ready.port,
        endpoint: ready.endpoint,
        buckets: ready.buckets,
        runtime,
        ident,
    })
}

/// The subset of the driver's `coords.json` the camp needs. Read structurally
/// rather than by depending on `yah_s3_fs::Coords`, for the same reason
/// `pg_driver` re-spells its database-name rule: `cloud` must not take a
/// dependency on a separately-built plugin crate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadyCoords {
    port: u16,
    endpoint: String,
    buckets: Vec<String>,
}

/// Poll for the driver's `coords.json`. See [`super::pg_driver`] for why this
/// polls rather than watches.
async fn wait_for_coords(path: &Path, timeout: Duration) -> Option<ReadyCoords> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(coords) = read_coords(path) {
            return Some(coords);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Coordinates from a *complete* `coords.json`, or `None` when the file is
/// absent, half-written, or reports a zero port.
fn read_coords(path: &Path) -> Option<ReadyCoords> {
    let bytes = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let port = u16::try_from(v.get("port")?.as_u64()?).ok()?;
    if port == 0 {
        return None;
    }
    let endpoint = v
        .get("endpoint")
        .and_then(|e| e.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("http://127.0.0.1:{port}"));
    let buckets = v
        .get("buckets")
        .and_then(|b| b.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|b| b.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Some(ReadyCoords {
        port,
        endpoint,
        buckets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServiceConfig;

    fn service(mirrors: &[(&str, &str)]) -> ServiceWithMirrors {
        let service: ServiceConfig =
            toml::from_str("schema_version = 1\nname = \"svc\"\n[address]\nkind = \"front-door\"\ndomain = \"svc.example\"\n")
                .expect("parse service");
        ServiceWithMirrors {
            service,
            mirrors: mirrors
                .iter()
                .map(|(env, src)| {
                    (
                        (*env).to_string(),
                        toml::from_str::<MirrorConfig>(src).expect("parse mirror"),
                    )
                })
                .collect(),
            component_transform_recipes: BTreeMap::new(),
            passway_machines: BTreeMap::new(),
        }
    }

    /// A mirror that declares nothing about s3 at all — the common case, and
    /// the one that still has to activate the driver.
    const PLAIN: &str = r#"
schema_version = 1
shape = "local"
[providers.static]
kind = "miniflare-native"
port = 4321
"#;

    const BINDS_S3: &str = r#"
schema_version = 1
shape = "local"
[drivers.s3]
kind = "local-s3-fs"
"#;

    const CLOUD: &str = r#"
schema_version = 1
shape = "single-machine"
"#;

    fn services(entries: Vec<(&str, ServiceWithMirrors)>) -> BTreeMap<String, ServiceWithMirrors> {
        entries
            .into_iter()
            .map(|(n, s)| (n.to_string(), s))
            .collect()
    }

    /// THE deviation from R584-F1/F2, pinned: a dev mirror that says nothing
    /// about s3 still gets the driver. If this ever flips to requiring the
    /// stanza, every existing dev service silently loses `S3_ENDPOINT`.
    #[test]
    fn a_dev_mirror_activates_the_driver_without_declaring_anything() {
        assert!(camp_needs_s3_driver(&services(vec![(
            "marketing",
            service(&[("dev", PLAIN)])
        )])));
    }

    #[test]
    fn an_explicit_binding_also_activates_it() {
        assert!(camp_needs_s3_driver(&services(vec![(
            "assets",
            service(&[("dev", BINDS_S3)])
        )])));
    }

    /// A camp with no dev tier has nothing to bring up.
    #[test]
    fn a_camp_with_no_dev_mirror_spawns_nothing() {
        assert!(!camp_needs_s3_driver(&services(vec![(
            "prod-only",
            service(&[("prod", CLOUD)])
        )])));
        assert!(!camp_needs_s3_driver(&BTreeMap::new()));
    }

    #[test]
    fn buckets_are_the_dev_services_sorted_and_nothing_else() {
        let svcs = services(vec![
            ("zeta", service(&[("dev", PLAIN)])),
            ("alpha", service(&[("dev", BINDS_S3)])),
            ("prod-only", service(&[("prod", CLOUD)])),
        ]);
        assert_eq!(declared_s3_buckets(&svcs), ["alpha", "zeta"]);
    }

    /// The bucket name is the service name verbatim, because that is the
    /// `S3_BUCKET` the camp has injected since R274-F5. Changing it would
    /// orphan every object an existing dev app has written.
    #[test]
    fn the_bucket_name_is_the_service_name_verbatim() {
        let svcs = services(vec![("yah-marketing", service(&[("dev", PLAIN)]))]);
        assert_eq!(declared_s3_buckets(&svcs), ["yah-marketing"]);
    }

    #[test]
    fn the_explicit_binding_is_still_readable_for_tier_aware_callers() {
        let with = service(&[("dev", BINDS_S3)]);
        let without = service(&[("dev", PLAIN)]);
        assert!(binds_local_s3_fs(with.mirrors.get("dev").unwrap()));
        assert!(!binds_local_s3_fs(without.mirrors.get("dev").unwrap()));
    }

    #[test]
    fn the_spec_declares_the_s3_listener_by_name() {
        let mut spec = native_spec("yah-s3-fs", vec!["yah-s3-fs".to_string()], Vec::new());
        spec.expose.mesh.ports = vec![MeshPort::named(PORT_NAME_S3)];
        assert!(spec.expose.mesh.names().contains(&"s3"));
        assert!(spec.expose.mesh.ports.iter().all(|p| p.number.is_none()));
        workload_spec::validate::shape(&spec).expect("spec must validate");
    }

    #[tokio::test]
    async fn coords_are_incomplete_until_a_real_port_is_published() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("coords.json");
        let brief = Duration::from_millis(150);

        assert_eq!(wait_for_coords(&path, brief).await, None);
        // Bound-but-zero is the shape a half-initialised file has.
        std::fs::write(&path, br#"{"port":0}"#).unwrap();
        assert_eq!(wait_for_coords(&path, brief).await, None);
        // Half-written.
        std::fs::write(&path, br#"{"port":51"#).unwrap();
        assert_eq!(wait_for_coords(&path, brief).await, None);
    }

    #[tokio::test]
    async fn a_complete_coords_file_yields_the_endpoint_and_buckets() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("coords.json");
        std::fs::write(
            &path,
            br#"{"port":51234,"endpoint":"http://127.0.0.1:51234",
                 "data_dir":"/tmp/x","buckets":["alpha","zeta"]}"#,
        )
        .unwrap();
        assert_eq!(
            wait_for_coords(&path, Duration::from_secs(1)).await,
            Some(ReadyCoords {
                port: 51234,
                endpoint: "http://127.0.0.1:51234".to_string(),
                buckets: vec!["alpha".to_string(), "zeta".to_string()],
            })
        );
    }

    /// An older driver that published a port but no endpoint is still usable —
    /// the endpoint is derivable from the port it did publish.
    #[test]
    fn a_missing_endpoint_is_derived_from_the_port() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("coords.json");
        std::fs::write(&path, br#"{"port":51234}"#).unwrap();
        assert_eq!(
            read_coords(&path).map(|c| c.endpoint),
            Some("http://127.0.0.1:51234".to_string())
        );
    }
}
