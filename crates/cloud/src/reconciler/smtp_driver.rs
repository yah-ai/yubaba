//! Bring-up for the dev/pond-tier `smtp` capability driver — the
//! `yah-smtp-dev` workload (W265, R584-F2).
//!
//! Third instance of the capability/driver shape behind [`super::pg_driver`],
//! and deliberately the same shape rather than a better one: a free function
//! the camp daemon calls once at tier bring-up, not a [`super::Reconciler`],
//! because a driver is the *tier's* implementation of a capability rather than
//! anybody's component. Read `pg_driver`'s module doc for why that distinction
//! exists; everything it says about kamaji's role applies here unchanged.
//!
//! # What differs from pg, and why
//!
//! **Two listeners, both named.** mailcrab serves SMTP and an HTTP inbox, and
//! the inbox is the half the operator actually asked for. A workload declaring
//! two ports and naming neither gets no `http` — `yah cloud apply` refuses to
//! guess which one the front door fronts, and the Run tab has nothing to build
//! a URL from. So [`up_smtp_driver`] states both names in
//! `expose.mesh.ports`, which is what earns the inbox a `PORT` alias and a
//! reachable URL. See `.yah/docs/guides/write-a-service-toml.md` §"Ports".
//!
//! **Name-only, not pinned.** Both entries are [`MeshPort::named`] — kamaji's
//! native backend allocates the number, remembers it per (workload, port name)
//! across a supervisor restart, and tells the driver via `PORT_SMTP` /
//! `PORT_HTTP`. That is the guide's preferred spelling and it is the right one
//! here: mailcrab's documented defaults (1025/1080) are *conventions*, not
//! reservations, and two camps on one laptop would collide on them. The driver
//! falls back to 1025/1080 when nothing allocated a port — i.e. when an
//! operator runs it by hand — so the familiar numbers still work outside
//! kamaji. Consumers read the real ports out of `coords.json`.
//!
//! **No per-service fan-out.** pg needs one database per service and therefore
//! a list; a mail catcher is one shared inbox, so activation is a boolean:
//! does any mirror at this tier bind `[drivers.smtp]`.

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

/// Mesh ident of the camp's single SMTP driver. Camp-scoped, not per-service —
/// one catcher holds every service's outbound mail, which is also what makes
/// the inbox useful to look at.
pub const SMTP_DRIVER_IDENT: &str = "yah-smtp-dev";

/// Environment variable overriding the `yah-smtp-dev` binary path, mirroring
/// [`super::pg_driver::PG_DEV_BIN_ENV`].
pub const SMTP_DEV_BIN_ENV: &str = "YAH_SMTP_DEV_BIN";

/// Port names declared in `expose.mesh.ports`. These are the strings kamaji
/// uppercases into `PORT_SMTP` / `PORT_HTTP`, and `http` specifically is the
/// name that earns the `PORT` alias and the front-door URL — renaming it to
/// something more descriptive (`inbox`, `ui`) would silently cost both.
pub const PORT_NAME_SMTP: &str = "smtp";
pub const PORT_NAME_HTTP: &str = "http";

/// Tiers whose mirrors may bind this driver. Unlike pg — which is dev-only
/// because the pond tier runs containers — a mail *catcher* is correct at both
/// dev and pond: neither should ever deliver real mail, and pond gains nothing
/// from a containerized catcher that a supervised 10 MB binary does not give
/// it. Cloud and ha are deliberately absent; a driver that swallows mail must
/// not be bindable at a tier where mail is expected to arrive.
const CATCHER_ENVS: &[&str] = &["dev", "pond"];

/// How the camp brings the driver up.
#[derive(Debug, Clone, Default)]
pub struct SmtpDriverOptions {
    /// Explicit binary path. Falls back to [`SMTP_DEV_BIN_ENV`], then to bare
    /// `yah-smtp-dev` resolved on `PATH` at spawn time.
    pub binary: Option<PathBuf>,
    /// How long to wait for `coords.json` after the workload is deployed.
    /// Default 120s — a *cold* camp downloads a ~10 MB mailcrab release inside
    /// this window; warm bring-up is a fork+exec and a TCP probe.
    pub ready_timeout: Option<Duration>,
}

impl SmtpDriverOptions {
    fn resolved_binary(&self) -> PathBuf {
        if let Some(ref p) = self.binary {
            return p.clone();
        }
        if let Some(p) = std::env::var_os(SMTP_DEV_BIN_ENV) {
            return PathBuf::from(p);
        }
        PathBuf::from("yah-smtp-dev")
    }

    fn ready_timeout(&self) -> Duration {
        self.ready_timeout.unwrap_or(Duration::from_secs(120))
    }
}

/// A brought-up SMTP driver.
pub struct RunningSmtpDriver {
    /// Port the SMTP listener accepted on, read back out of `coords.json`.
    pub smtp_port: u16,
    /// Port the web inbox is served on.
    pub http_port: u16,
    /// Browser URL for the inbox — the operator-facing half of this driver.
    pub inbox_url: String,
    runtime: Arc<NativeRuntime>,
    ident: MeshIdent,
}

impl RunningSmtpDriver {
    /// Stop the driver, which in turn stops mailcrab.
    ///
    /// Captured mail is held in mailcrab's memory and is gone either way — a
    /// catcher is a window onto what an app *just* sent, not an archive. That
    /// is why teardown here is a plain kill and not the careful clean-shutdown
    /// dance `pg_driver` needs.
    pub async fn teardown(&self) {
        self.runtime.teardown_workload(&self.ident).await.ok();
    }
}

/// `true` when some mirror in this camp, at a tier a catcher belongs to, binds
/// `smtp` to `local-mailcrab`.
///
/// `false` means no service asked for mail capture and the caller should not
/// spawn the driver at all. That is the same call [`super::pg_driver`] makes
/// and for the same reason: most services never send mail, so a driver that
/// was default-on would have every camp on the machine downloading and
/// supervising a mail catcher nobody opens.
pub fn camp_binds_smtp_driver(services: &BTreeMap<String, ServiceWithMirrors>) -> bool {
    services.values().any(|svc| {
        CATCHER_ENVS.iter().any(|env| {
            svc.mirrors
                .get(*env)
                .is_some_and(|mirror| binds_local_mailcrab(mirror))
        })
    })
}

/// `true` when this mirror binds `smtp` to the mailcrab driver.
fn binds_local_mailcrab(mirror: &MirrorConfig) -> bool {
    mirror
        .driver(Capability::Smtp)
        .and_then(|slot| slot.inline_kind())
        == Some(Provider::LocalMailcrab)
}

/// Path of the driver's coordinates file. Mirrors `yah_smtp_dev::coords_path`.
pub fn coords_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".yah/infra/state/dev/smtp/coords.json")
}

/// Deploy `yah-smtp-dev` on a kamaji [`NativeRuntime`] and wait for it to
/// publish coordinates.
pub async fn up_smtp_driver(
    workspace_root: &Path,
    opts: &SmtpDriverOptions,
) -> Result<RunningSmtpDriver> {
    let binary = opts.resolved_binary();
    let ident_str = sanitize_ident(SMTP_DRIVER_IDENT);
    let ident = MeshIdent(ident_str.clone());

    let argv: Vec<String> = vec![
        binary.display().to_string(),
        "serve".to_string(),
        "--workspace".to_string(),
        workspace_root.display().to_string(),
    ];

    // Coordinates from a previous run describe listeners that may or may not
    // still be up. Retract them first so `wait_for_coords` cannot succeed on a
    // stale file and hand the camp two dead ports.
    let coords = coords_path(workspace_root);
    let _ = std::fs::remove_file(&coords);

    let mut spec = native_spec(&ident_str, argv, Vec::new());
    // The two named listeners. See the module doc for why both are name-only
    // and why the second one is called `http` rather than `inbox`.
    spec.expose.mesh.ports = vec![
        MeshPort::named(PORT_NAME_SMTP),
        MeshPort::named(PORT_NAME_HTTP),
    ];

    let state_dir = workspace_root.join(".yah/jit/native");
    let runtime = Arc::new(NativeRuntime::new(&state_dir));
    let mesh = MeshAssignment::inlined(Ipv4Addr::LOCALHOST);

    info!(
        binary = %binary.display(),
        ident = %ident_str,
        "spawning yah-smtp-dev (kamaji native backend)",
    );

    runtime
        .deploy_workload(&spec, &mesh)
        .await
        .with_context(|| {
            format!(
                "deploying the dev-tier smtp driver via kamaji — install it with \
                 `cargo install --path crates/yah/smtp-dev` or point {SMTP_DEV_BIN_ENV} \
                 at the binary ({})",
                binary.display(),
            )
        })?;

    let timeout = opts.ready_timeout();
    let Some(ready) = wait_for_coords(&coords, timeout).await else {
        warn!(timeout = ?timeout, "yah-smtp-dev did not publish coords; tearing down");
        runtime.teardown_workload(&ident).await.ok();
        let (_out, err) = super::native_support::capture_paths(&state_dir, &ident_str);
        anyhow::bail!(
            "the dev-tier smtp driver did not become ready within {timeout:?} — \
             check {} for why",
            err.display(),
        );
    };

    info!(
        smtp_port = ready.smtp_port,
        http_port = ready.http_port,
        inbox = %ready.inbox_url,
        "dev-tier smtp driver ready",
    );
    Ok(RunningSmtpDriver {
        smtp_port: ready.smtp_port,
        http_port: ready.http_port,
        inbox_url: ready.inbox_url,
        runtime,
        ident,
    })
}

/// The subset of the driver's `coords.json` the camp needs. Read structurally
/// rather than by depending on `yah_smtp_dev::Coords`, for the same reason
/// `pg_driver` re-spells its database-name rule: `cloud` must not take a
/// dependency on a separately-built plugin crate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadyCoords {
    smtp_port: u16,
    http_port: u16,
    inbox_url: String,
}

/// Poll for the driver's `coords.json`. See [`super::pg_driver`] for why this
/// polls rather than watches.
async fn wait_for_coords(path: &Path, timeout: Duration) -> Option<ReadyCoords> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(coords) = read_coords(path) {
            return Some(coords);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Coordinates from a *complete* `coords.json`, or `None` when the file is
/// absent, half-written, or reports a zero port on either listener.
///
/// Both ports are required: a file naming only the SMTP port describes a
/// driver whose inbox is not up, and handing that to the Run tab would render
/// a URL card pointing at nothing.
fn read_coords(path: &Path) -> Option<ReadyCoords> {
    let bytes = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let port = |key: &str| -> Option<u16> {
        let n = u16::try_from(v.get(key)?.as_u64()?).ok()?;
        (n != 0).then_some(n)
    };
    let smtp_port = port("smtp_port")?;
    let http_port = port("http_port")?;
    let inbox_url = v
        .get("inbox_url")
        .and_then(|u| u.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("http://127.0.0.1:{http_port}/"));
    Some(ReadyCoords {
        smtp_port,
        http_port,
        inbox_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServiceConfig;

    fn service(mirrors: &[(&str, &str)]) -> ServiceWithMirrors {
        let service: ServiceConfig =
            toml::from_str("schema_version = 1\nname = \"svc\"\ndomain = \"svc.example\"\n")
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

    const BINDS_SMTP: &str = r#"
schema_version = 1
shape = "local"
[drivers.smtp]
kind = "local-mailcrab"
"#;

    const BINDS_PG: &str = r#"
schema_version = 1
shape = "local"
[drivers.pg]
kind = "local-pg-dev"
"#;

    fn services(entries: Vec<(&str, ServiceWithMirrors)>) -> BTreeMap<String, ServiceWithMirrors> {
        entries
            .into_iter()
            .map(|(n, s)| (n.to_string(), s))
            .collect()
    }

    #[test]
    fn one_mirror_binding_smtp_activates_the_camps_driver() {
        let svcs = services(vec![
            ("quiet", service(&[("dev", BINDS_PG)])),
            ("mailer", service(&[("dev", BINDS_SMTP)])),
        ]);
        assert!(camp_binds_smtp_driver(&svcs));
    }

    #[test]
    fn a_camp_that_binds_no_smtp_driver_spawns_nothing() {
        let svcs = services(vec![("quiet", service(&[("dev", BINDS_PG)]))]);
        assert!(!camp_binds_smtp_driver(&svcs));
    }

    /// pond binds the same catcher; prod must not be able to.
    #[test]
    fn pond_counts_and_cloud_does_not() {
        assert!(camp_binds_smtp_driver(&services(vec![(
            "mailer",
            service(&[("pond", BINDS_SMTP)])
        )])));
        assert!(!camp_binds_smtp_driver(&services(vec![(
            "mailer",
            service(&[("prod", BINDS_SMTP)])
        )])));
    }

    /// The two named listeners are the acceptance criterion of R584-F2, and
    /// `http` in particular is load-bearing: it is the name `PORT` aliases and
    /// the one the Run tab resolves the front door from.
    #[test]
    fn the_spec_declares_both_listeners_by_name() {
        let mut spec = native_spec("yah-smtp-dev", vec!["yah-smtp-dev".to_string()], Vec::new());
        spec.expose.mesh.ports = vec![
            MeshPort::named(PORT_NAME_SMTP),
            MeshPort::named(PORT_NAME_HTTP),
        ];
        let names = spec.expose.mesh.names();
        assert!(names.contains(&"smtp"), "missing smtp: {names:?}");
        assert!(names.contains(&"http"), "missing http: {names:?}");
        // Name-only: kamaji picks the numbers. A pinned number here would be a
        // collision waiting for the second camp on this laptop.
        assert!(spec.expose.mesh.ports.iter().all(|p| p.number.is_none()));
        workload_spec::validate::shape(&spec).expect("spec must validate");
    }

    #[tokio::test]
    async fn coords_are_incomplete_until_both_listeners_report() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("coords.json");
        let brief = Duration::from_millis(150);

        assert_eq!(wait_for_coords(&path, brief).await, None);
        // SMTP up, inbox not yet — not ready.
        std::fs::write(&path, br#"{"smtp_port":1025,"http_port":0}"#).unwrap();
        assert_eq!(wait_for_coords(&path, brief).await, None);
        // Half-written file.
        std::fs::write(&path, br#"{"smtp_port":102"#).unwrap();
        assert_eq!(wait_for_coords(&path, brief).await, None);
    }

    #[tokio::test]
    async fn a_complete_coords_file_yields_both_ports_and_the_inbox_url() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("coords.json");
        std::fs::write(
            &path,
            br#"{"smtp_port":51001,"http_port":51002,"inbox_url":"http://127.0.0.1:51002/"}"#,
        )
        .unwrap();
        assert_eq!(
            wait_for_coords(&path, Duration::from_secs(1)).await,
            Some(ReadyCoords {
                smtp_port: 51001,
                http_port: 51002,
                inbox_url: "http://127.0.0.1:51002/".to_string(),
            })
        );
    }

    /// An older driver that published ports but no URL still has to be usable —
    /// the URL is derivable from the port it did publish.
    #[test]
    fn a_missing_inbox_url_is_derived_from_the_http_port() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("coords.json");
        std::fs::write(&path, br#"{"smtp_port":1025,"http_port":1080}"#).unwrap();
        assert_eq!(
            read_coords(&path).unwrap().inbox_url,
            "http://127.0.0.1:1080/"
        );
    }

    #[test]
    fn binary_resolution_prefers_explicit_over_env_over_path() {
        let explicit = SmtpDriverOptions {
            binary: Some(PathBuf::from("/opt/yah-smtp-dev")),
            ..Default::default()
        };
        assert_eq!(
            explicit.resolved_binary(),
            PathBuf::from("/opt/yah-smtp-dev")
        );
        if std::env::var_os(SMTP_DEV_BIN_ENV).is_none() {
            assert_eq!(
                SmtpDriverOptions::default().resolved_binary(),
                PathBuf::from("yah-smtp-dev")
            );
        }
    }
}
