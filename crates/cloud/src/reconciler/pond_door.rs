//! Pond front door — one browser-trusted `https://` hostname per pond mirror.
//!
//! R659. Pond is plain HTTP end to end: each `<service, env>` gets a
//! hand-assigned miniflare port ([`pond`](super::pond) — 4322 marketing, 4323
//! dashboard) and the operator reaches it at `http://127.0.0.1:<port>`. This
//! module puts a real front door in front of that: **passway terminating TLS on
//! one port, fanning in by `Host`**, so the operator hits
//! `https://yah-dashboard.pond.localhost` and never types a port at all.
//!
//! ```text
//!   .yah/services/<svc>/mirrors/<env>.toml     (kind = "miniflare-container", port = N)
//!            │ derive
//!            ▼
//!   IngressRule { hostname: <svc>.pond.localhost, port: N, upstream_hosts: [127.0.0.1] }
//!            │ render (shared grammar with the cloud arm — IngressRule::passway_upstreams)
//!            ▼
//!   PASSWAY_UPSTREAMS=yah-dashboard.pond.localhost=127.0.0.1:4323,…
//!            │
//!            ▼
//!   passway :8443 ── TLS (mkcert wildcard *.pond.localhost) ── Host router ──▶ miniflare
//! ```
//!
//! ## Why this is worth more than dev sugar
//!
//! W267 "Two front doors, one render contract" records that the sovereign
//! (passway) door is **not** symmetric with the Worker door — no per-path
//! routing, no bucket serving. Pond today rehearses only the Worker door, so
//! the asymmetry is untestable outside the fleet. Running passway in pond makes
//! the second door a thing an operator can actually hit locally.
//!
//! ## Derived, not declared — and why that differs from the cloud arm
//!
//! The cloud arm declares a front door in the mirror (`ingress = "passway"`)
//! and [`plan_ingress`](super::ingress::plan_ingress) turns `zone` + `port`
//! slot fields into rules. Pond deliberately does **not** reuse that path: a
//! declared edge collates onto a **machine**
//! ([`collate_front_doors`](super::ingress::collate_front_doors), and
//! `xtask/tests/mirror_ingress.rs::every_front_door_placement_names_a_known_machine`
//! requires every such name to have a `.yah/infra/machines/<name>.toml`). The
//! dev box is not in the machine registry and should not be — inventing a
//! `localhost.toml` machine manifest to satisfy the collator would put a
//! fiction into the fleet's infra tree to serve a local tier.
//!
//! So placement is derived here and *rendering* is shared: rules are real
//! [`IngressRule`]s and the `PASSWAY_UPSTREAMS` string comes from
//! [`IngressRule::passway_upstreams`], the same function the fleet arm calls.
//! One grammar, one place, two placement policies.
//!
//! ## Hostname: `*.pond.localhost`, not `.local`, not a real zone
//!
//! `pond.localhost` needs zero DNS configuration: macOS's resolver answers
//! *any* depth under `localhost` with `127.0.0.1`/`::1` through plain
//! `getaddrinfo` (verified on darwin 25.5.0 — this is not a browser-only
//! special case, so `curl`, `bun` and Rust clients resolve it too). `.local` is
//! claimed by mDNSResponder (RFC 6762) and `/etc/hosts` has no wildcards, so
//! neither scales to per-service names.
//!
//! Every pond hostname is exactly **one label** under `pond.localhost` because
//! a wildcard leaf covers one level only: `*.pond.localhost` matches
//! `yah-dashboard.pond.localhost` and not `a.b.pond.localhost`. That is why a
//! non-default env flattens into the label (`<svc>-<env>.pond.localhost`)
//! rather than nesting.
//!
//! ## Trust: mkcert, and nothing minted in-tree
//!
//! The cert comes from `mkcert`, shelled out to. That is a deliberate refusal
//! to mint our own CA with `rcgen` (in-tree via instant-acme): issuance is the
//! easy half, and the half that matters — installing a root into the macOS
//! login keychain *and* the NSS/Firefox stores — is exactly what mkcert exists
//! to do. `mkcert -install` needs the operator's password once and is never run
//! from here; [`ensure_pond_cert`] detects-and-instructs instead.
//!
//! The leaf + key land under `.yah/infra/pond/_door/`, gitignored with the rest
//! of the pond state dir. The CA private key stays wherever mkcert put it
//! (`mkcert -CAROOT`) and never enters the repo.
//!
//! ## Scope fence
//!
//! Browser-facing pond **only**. This introduces a local CA into exactly one
//! lane: the operator's browser talking to a local dev tier. Every lane where
//! both ends are our own code stays on NodeId pinning (W268: "Do not bolt
//! rustls-mTLS onto yubaba's axum surface"; R593-T7: "no interim mTLS
//! bolt-on"). mkcert is a browser-trust tool and it does not belong anywhere
//! near the mesh.
//!
//! @arch:see(.yah/docs/working/W142-pond.md)
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

use super::ingress::IngressRule;
use super::slot_field_u16;
use crate::config::{CloudConfig, Provider};

/// The domain every pond hostname lives one label under.
pub const POND_TLD: &str = "pond.localhost";

/// The SANs the pond leaf carries. The wildcard is the load-bearing one; the
/// apex and loopback names are there so a smoke test can hit the door without
/// inventing a service.
pub const POND_CERT_SANS: [&str; 5] = [
    "*.pond.localhost",
    "pond.localhost",
    "localhost",
    "127.0.0.1",
    "::1",
];

/// Default listen port for the door.
///
/// **Not 443**, even though 443 is what the operator wants in the URL bar: on
/// macOS a port below 1024 cannot be bound by a non-root process (verified —
/// `bind(127.0.0.1:443)` as the operator user is `EACCES`), there is no
/// `setcap` equivalent, and camp must never `sudo`. 8443 is the port that
/// always works with no privilege story at all; `--port 443` is available for
/// an operator who has arranged one (root, a launchd daemon, or a pf redirect).
pub const DEFAULT_DOOR_PORT: u16 = 8443;

/// Mirror env whose hostnames get the bare `<service>.pond.localhost` form.
pub const DEFAULT_POND_ENV: &str = "pond";

/// Slot role prefix the pond reconciler serves from.
const STATIC_SLOT: &str = "static";

/// Everything the door reaches its upstreams over. Loopback: miniflare binds
/// `127.0.0.1` on the host path and publishes to the host port on the
/// container path, so loopback is right either way.
const UPSTREAM_HOST: &str = "127.0.0.1";

const CERT_FILE: &str = "pond-cert.pem";
const KEY_FILE: &str = "pond-key.pem";

/// Where the door's cert, key, pid file and upgrade socket live.
///
/// A sibling of the per-`<svc>-<env>` pond state dirs
/// ([`PondState::for_ctx`](super::pond::PondState::for_ctx)) rather than a new
/// tree, and underscore-prefixed so it can never collide with a service named
/// `door`.
pub fn door_state_dir(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".yah/infra/pond/_door")
}

/// The hostname a `<service, env>` pond is served at.
///
/// One DNS label under [`POND_TLD`] (see the module doc on wildcard depth).
/// `env == "pond"` — the overwhelmingly common case — gets the bare service
/// name; anything else flattens the env into the label.
///
/// `component` distinguishes a mirror that declares several static slots
/// (`providers."static:<component>"`), which otherwise collide on one name.
pub fn pond_hostname(service: &str, env: &str, component: Option<&str>) -> String {
    let mut label = dns_label(service);
    if env != DEFAULT_POND_ENV {
        label.push('-');
        label.push_str(&dns_label(env));
    }
    if let Some(c) = component {
        label.push('-');
        label.push_str(&dns_label(c));
    }
    format!("{label}.{POND_TLD}")
}

/// Lowercase, and collapse anything that is not `[a-z0-9-]` to `-`. Service
/// names in this tree are already valid labels (`yah-dashboard`); this exists
/// so a name that isn't cannot produce a cert-mismatching hostname silently.
fn dns_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// The whole door: what it listens on and every pond it fronts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PondDoorPlan {
    pub listen: SocketAddr,
    /// Rules ordered by hostname, so two runs render byte-identical config.
    pub rules: Vec<IngressRule>,
    /// `service/env` labels that contributed, sorted — the provenance answer to
    /// "why is this hostname on my box".
    pub sources: Vec<String>,
}

impl PondDoorPlan {
    /// The `PASSWAY_UPSTREAMS` value, in passway's R594-F10 host fan-in
    /// grammar. Rendered by [`IngressRule::passway_upstreams`] — the same
    /// function the fleet arm uses, so the two can never drift.
    pub fn upstreams_env(&self) -> Result<String> {
        let mut out = Vec::new();
        for rule in &self.rules {
            out.extend(rule.passway_upstreams()?);
        }
        Ok(out.join(","))
    }

    /// Operator-visible URLs, one per fronted pond.
    pub fn urls(&self) -> Vec<String> {
        self.rules
            .iter()
            .map(|r| {
                if self.listen.port() == 443 {
                    format!("https://{}", r.hostname)
                } else {
                    format!("https://{}:{}", r.hostname, self.listen.port())
                }
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Derive the door from every pond mirror declared in the workspace.
///
/// Two arms, because the tree runs two shapes of pond:
///
/// 1. A `static` slot inlining `kind = "miniflare-container"` — its `port` is
///    the upstream. marketing (4322), dashboard (4323).
/// 2. Failing that, a `pond` mirror with a bare container component — see
///    [`bare_container_ponds`].
///
/// **Every** such mirror is fronted, with no opt-in field, because the hostname
/// is derived from the service name — there is nothing for an operator to
/// decide and therefore nothing to declare.
///
/// Ponds that are not currently running are still planned. passway
/// fail-ready-503s a host whose backends are all down and admits them the
/// moment its TCP health check passes, so a door started once serves ponds that
/// come and go behind it. That is what keeps the door out of the per-pond
/// spinup path entirely (W142's few-second-cold / sub-second-warm budget sees
/// no delta).
pub fn plan_pond_door(cfg: &CloudConfig, listen: SocketAddr) -> Result<PondDoorPlan> {
    let mut rules: Vec<IngressRule> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    // hostname → the source that claimed it; port → same. Both are hard
    // conflicts: one hostname cannot route two ways, and two miniflares cannot
    // share a host port.
    let mut by_host: BTreeMap<String, String> = BTreeMap::new();
    let mut by_port: BTreeMap<u16, String> = BTreeMap::new();

    for (service, swm) in &cfg.services {
        for (env, mirror) in &swm.mirrors {
            let mut fronted: Vec<(String, Option<String>, u16)> = Vec::new();
            for (role, slot) in &mirror.providers {
                if slot.inline_kind() != Some(Provider::MiniflareContainer) {
                    continue;
                }
                let (base, component) = split_slot_role(role);
                if base != STATIC_SLOT {
                    continue;
                }
                let Some(port) = slot_field_u16(slot.fields(), "port") else {
                    warn!(
                        service = %service,
                        env = %env,
                        slot = %role,
                        "pond mirror declares no `port` — skipping (nothing to front)",
                    );
                    continue;
                };
                fronted.push((role.clone(), component.map(str::to_string), port));
            }
            if fronted.is_empty() {
                fronted.extend(bare_container_ponds(cfg, swm, env));
            }

            for (role, component, port) in fronted {
                let hostname = pond_hostname(service, env, component.as_deref());
                let label = format!("{service}/{env}");

                if let Some(first) = by_host.get(&hostname) {
                    bail!(
                        "pond hostname {hostname:?} is claimed by both {first} and {label} — \
                         one hostname routes one way, so the second would be dead config that \
                         reads as live. Rename one of the services, or give one of them a \
                         distinct mirror env."
                    );
                }
                if let Some(first) = by_port.get(&port) {
                    bail!(
                        "pond port {port} is claimed by both {first} and {label} — two \
                         miniflares cannot bind the same host port, so whichever comes up \
                         second fails to bind. Give one of them its own \
                         `[providers.{STATIC_SLOT}] port`."
                    );
                }
                by_host.insert(hostname.clone(), label.clone());
                by_port.insert(port, label.clone());

                rules.push(IngressRule {
                    hostname,
                    port,
                    slot: role.clone(),
                    provider_id: None,
                    machines: Vec::new(),
                    // Pinned, never discovered: a pond's miniflare is a host
                    // process (or a container publishing to the host port), so
                    // its address is loopback by construction. There is no mesh
                    // IP to allocate and no yubaba to ask. Exactly one backend,
                    // carried in the set-valued field the fleet arm shares.
                    upstream_hosts: vec![UPSTREAM_HOST.to_string()],
                });
                if !sources.contains(&label) {
                    sources.push(label);
                }
            }
        }
    }

    rules.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    sources.sort();

    Ok(PondDoorPlan {
        listen,
        rules,
        sources,
    })
}

/// The *bare-container* pond arm: a `pond` mirror that declares no provider
/// slots at all, and whose service has a `kind = "container"` component the
/// [container reconciler](super::container) runs.
///
/// `yah-cloud-admin` is the live case — `.yah/services/yah-cloud-admin/mirrors/
/// pond.toml` declares nothing but `shape = "local"` and its own header states
/// the rule the tree goes by: *if it runs in a container, it is pond*. It also
/// publishes on 4326 while its dev tier listens on 4325, so it is precisely the
/// service where remembering the right port is hardest — exactly what a
/// hostname is for.
///
/// Keyed on `env == "pond"` rather than on the component kind, because a
/// container component under `dev` is the same component run natively. And the
/// port is read through [`super::container::parse_container_recipe`] — the same
/// parser the reconciler uses, taking `host_port` over `port` exactly as its
/// `up` does, so the address the door dials cannot drift from the one the
/// container publishes.
///
/// Best-effort by design: an unreadable, unparseable, or git-sourced (not yet
/// materialized) component is skipped with a warning. A front door that
/// half-works beats one that refuses to start over a workload nobody asked it
/// to front.
fn bare_container_ponds(
    cfg: &CloudConfig,
    swm: &crate::config::ServiceWithMirrors,
    env: &str,
) -> Vec<(String, Option<String>, u16)> {
    if env != DEFAULT_POND_ENV {
        return Vec::new();
    }
    let mut out = Vec::new();
    for component in &swm.service.components {
        if component.kind != "container" || component.git.is_some() {
            continue;
        }
        let manifest = cfg
            .workspace_root
            .join(&component.path)
            .join("workload.toml");
        let Ok(src) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        match super::container::parse_container_recipe(&src) {
            Ok(recipe) => match recipe.run.host_port.or(recipe.run.port) {
                Some(port) => out.push((
                    format!("component:{}", component.id),
                    Some(component.id.clone()),
                    port,
                )),
                None => warn!(
                    manifest = %manifest.display(),
                    "container pond declares no [run].port — skipping (nothing to dial)",
                ),
            },
            Err(e) => warn!(
                manifest = %manifest.display(),
                error = %e,
                "container pond manifest did not parse — skipping",
            ),
        }
    }
    // The component qualifier only exists to disambiguate. One container is the
    // overwhelmingly common shape and deserves the bare service name.
    if out.len() == 1 {
        out[0].1 = None;
    }
    out
}

/// Split `"static:yah-dashboard"` into `("static", Some("yah-dashboard"))`.
fn split_slot_role(role: &str) -> (&str, Option<&str>) {
    match role.split_once(':') {
        Some((base, component)) => (base, Some(component)),
        None => (role, None),
    }
}

/// Paths to the door's TLS material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPair {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Ensure a browser-trusted wildcard leaf for [`POND_CERT_SANS`] exists under
/// `state_dir`, issuing one with `mkcert` when it does not.
///
/// Returns an actionable error rather than a fallback when mkcert is absent:
/// the pure-Rust alternative (mint a CA with rcgen) solves issuance, which was
/// never the hard part, and leaves the browser refusing the cert — a *worse*
/// failure than a one-line install instruction, because it looks like it
/// worked.
///
/// `mkcert -install` is never invoked from here: it writes the system keychain
/// and the NSS stores and wants a password. Camp does not sudo.
pub fn ensure_pond_cert(state_dir: &Path, reissue: bool) -> Result<CertPair> {
    ensure_pond_cert_as(state_dir, reissue, is_root())
}

/// [`ensure_pond_cert`] with the privilege check injected rather than read off
/// the process.
///
/// Exists so the refuse-to-issue-as-root branch is reachable from a test. It is
/// otherwise unexecutable anywhere it matters: a test process is not root, and
/// a camp agent cannot `sudo` to make one. An error path that has never run is
/// not much better than no error path — this is the branch guarding the
/// operator's chosen `--port 443` recipe, so it gets executed.
pub fn ensure_pond_cert_as(
    state_dir: &Path,
    reissue: bool,
    running_as_root: bool,
) -> Result<CertPair> {
    let pair = CertPair {
        cert: state_dir.join(CERT_FILE),
        key: state_dir.join(KEY_FILE),
    };
    if !reissue && pair.cert.exists() && pair.key.exists() {
        return Ok(pair);
    }

    // Issuing under sudo would look up the WRONG CA. mkcert keeps its root
    // under `$HOME/Library/Application Support/mkcert` and installs it into the
    // *login* keychain — both the operator's, not root's. Under `sudo` the
    // lookup below resolves root's HOME, finds no root there, and the honest
    // error ("mkcert's CA is not installed") points at a fix that would install
    // a SECOND CA nothing trusts. The issued leaf would also land root-owned in
    // the operator's tree.
    //
    // Serving as root is legitimate — it is how `--port 443` works at all on
    // macOS, where no non-root process can bind a port below 1024 (there is no
    // `setcap`, and Darwin has no `ip_unprivileged_port_start` equivalent). So
    // this refuses only the *issuing* half, and names the unprivileged command
    // that does it.
    if running_as_root {
        bail!(
            "refusing to issue the pond leaf as root: mkcert's CA lives in YOUR login keychain \
             and home directory, not root's, so issuing here would mint a leaf from a second CA \
             that no browser trusts — and leave it root-owned in your tree.\n\n  yah cloud pond \
             cert           # as yourself, once\n  sudo yah cloud pond door --port 443\n\nThe \
             serve half is fine as root; only issuance is not.",
        );
    }

    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating pond door state dir {}", state_dir.display()))?;

    let caroot = mkcert_caroot().with_context(|| {
        format!(
            "`mkcert` is not on PATH — the pond front door needs a browser-trusted leaf for \
             {}, which no public CA can issue (the name is not public) and which a self-signed \
             cert cannot make a browser accept.\n\n  brew install mkcert nss   # nss = Firefox \
             trust store\n  mkcert -install           # one-time, asks for your password\n\n\
             Then re-run this command.",
            POND_CERT_SANS[0],
        )
    })?;

    // mkcert issues a leaf whether or not its root is trusted, so an untrusted
    // root produces a cert that works for curl --cacert and fails in the
    // browser — the confusing middle state. Name it now instead.
    if !caroot.join("rootCA.pem").exists() {
        bail!(
            "mkcert is installed but its local CA is not (no rootCA.pem in {}). Run `mkcert \
             -install` once — it asks for your password and writes the macOS login keychain \
             plus the NSS/Firefox stores — then re-run this command.",
            caroot.display(),
        );
    }

    let out = std::process::Command::new("mkcert")
        .arg("-cert-file")
        .arg(&pair.cert)
        .arg("-key-file")
        .arg(&pair.key)
        .args(POND_CERT_SANS)
        .output()
        .context("running mkcert to issue the pond wildcard leaf")?;
    if !out.status.success() {
        bail!(
            "mkcert failed to issue the pond leaf ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    info!(
        cert = %pair.cert.display(),
        caroot = %caroot.display(),
        "issued pond wildcard leaf",
    );
    Ok(pair)
}

/// True when this process is running with an effective uid of 0 — i.e. under
/// `sudo`, which is the only way to bind `--port 443` on macOS.
pub fn is_root() -> bool {
    // SAFETY: geteuid() is a pure read of the calling process's credentials.
    // It takes no arguments, touches no memory, and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// `mkcert -CAROOT`, or `None` when mkcert is not on PATH.
fn mkcert_caroot() -> Option<PathBuf> {
    let out = std::process::Command::new("mkcert")
        .arg("-CAROOT")
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// Locate the passway binary, in the order an operator would want it found.
///
/// `PASSWAY_BIN` first (an operator pointing at a specific build always wins),
/// then this monorepo's own `oss/passway` target dir, then `PATH`.
pub fn resolve_passway_binary(workspace_root: &Path) -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("PASSWAY_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Ok(p);
        }
        bail!(
            "PASSWAY_BIN points at {}, which does not exist",
            p.display()
        );
    }
    for rel in [
        "oss/passway/target/release/passway",
        "oss/passway/target/debug/passway",
    ] {
        let p = workspace_root.join(rel);
        if p.exists() {
            return Ok(p);
        }
    }
    if std::process::Command::new("passway")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Ok(PathBuf::from("passway"));
    }
    bail!(
        "no passway binary found. Build it once:\n\n  cargo build --release \
         --manifest-path oss/passway/Cargo.toml -p passway\n\nor point PASSWAY_BIN at one.",
    )
}

/// Render the environment passway is spawned with.
///
/// Split out from [`spawn_pond_door`] so a caller can print the exact env a
/// door runs with (and so it is testable without spawning anything).
pub fn door_env(
    plan: &PondDoorPlan,
    cert: &CertPair,
    state_dir: &Path,
) -> Result<Vec<(String, String)>> {
    Ok(vec![
        ("PASSWAY_LISTEN".into(), plan.listen.to_string()),
        // Manual mode, explicitly: the ACME arm structurally cannot issue for
        // `*.pond.localhost` (no public name, no reachable challenge), and
        // passway selects the arm by the presence of PASSWAY_ACME_* env — so
        // the absence of that env below is load-bearing, not incidental.
        ("PASSWAY_TLS_MODE".into(), "manual".into()),
        ("PASSWAY_TLS_CERT".into(), cert.cert.display().to_string()),
        ("PASSWAY_TLS_KEY".into(), cert.key.display().to_string()),
        ("PASSWAY_UPSTREAM_SOURCE".into(), "static".into()),
        ("PASSWAY_UPSTREAMS".into(), plan.upstreams_env()?),
        // Loopback HTTP to miniflare — the pond's own hop is not encrypted and
        // does not need to be; the door is the TLS boundary.
        ("PASSWAY_UPSTREAM_TLS".into(), "false".into()),
        // Per-instance, never pingora's shared /tmp defaults: a dev box may run
        // this door alongside any other pingora process.
        //
        // Keyed by PORT, not a fixed name, for a reason the 443 path exposes:
        // `--port 443` runs under sudo, so its pid file and upgrade socket land
        // root-owned — and a later unprivileged run on 8443 could then neither
        // rewrite nor unlink them. Two ports are two instances anyway, so
        // keying by port is both the fix and the more honest name.
        (
            "PASSWAY_PID_FILE".into(),
            state_dir
                .join(format!("pingora-{}.pid", plan.listen.port()))
                .display()
                .to_string(),
        ),
        (
            "PASSWAY_UPGRADE_SOCK".into(),
            state_dir
                .join(format!("upgrade-{}.sock", plan.listen.port()))
                .display()
                .to_string(),
        ),
    ])
}

/// The line passway logs once its TLS listener is bound. Readiness is taken
/// from this rather than from a TCP probe: a bare connect-and-close against a
/// TLS listener is a truncated handshake, and passway rightly logs it at ERROR
/// — so probing would print a scary line on every clean startup, describing
/// nothing but our own probe.
const READY_LINE: &str = "passway listening on";

/// Spawn passway and wait until its TLS listener is bound.
///
/// The child is returned live and `kill_on_drop`; the caller owns its
/// lifetime. Its stdout/stderr are relayed line-by-line to ours, which both
/// drains the pipes (a full pipe buffer would block the proxy itself — a hang
/// that reads as a routing bug) and keeps the operator's terminal showing
/// passway's own log, exactly as an inherited fd would.
pub async fn spawn_pond_door(
    workspace_root: &Path,
    plan: &PondDoorPlan,
    cert: &CertPair,
    ready_timeout: Duration,
) -> Result<tokio::process::Child> {
    let state_dir = door_state_dir(workspace_root);
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("creating pond door state dir {}", state_dir.display()))?;
    let bin = resolve_passway_binary(workspace_root)?;

    if super::pond::port_has_listener(&plan.listen.ip().to_string(), plan.listen.port()) {
        bail!(
            "{} already has a listener — another pond door (or an unrelated process) holds it. \
             Stop it, or pass a different port.",
            plan.listen,
        );
    }
    if plan.listen.port() < 1024 {
        // Not a hard failure — a caller running as root, or behind a redirect,
        // is a legitimate shape. But the EACCES that follows otherwise reads as
        // a passway bug rather than a privilege one.
        warn!(
            port = plan.listen.port(),
            "binding a privileged port: this needs root on macOS/Linux and camp never sudos — \
             expect EACCES unless you arranged for it",
        );
    }

    let mut cmd = Command::new(&bin);
    for (k, v) in door_env(plan, cert, &state_dir)? {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning passway from {}", bin.display()))?;

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    // env_logger writes to stderr, so that is the stream carrying READY_LINE.
    // stdout is relayed too — dropping it would leave a pipe nobody drains.
    if let Some(stderr) = child.stderr.take() {
        let mut ready_tx = Some(ready_tx);
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.contains(READY_LINE) {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                }
                eprintln!("{line}");
            }
        });
    }
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                println!("{line}");
            }
        });
    }

    match tokio::time::timeout(ready_timeout, ready_rx).await {
        Ok(Ok(())) => {
            info!(
                listen = %plan.listen,
                fronting = plan.rules.len(),
                "pond front door ready",
            );
            Ok(child)
        }
        // Sender dropped (passway exited) or the timeout elapsed. Both mean no
        // listener; passway's own log is already on the operator's terminal
        // above, so this only has to name the two configuration causes it
        // cannot print itself.
        Ok(Err(_)) | Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            bail!(
                "passway never reported {READY_LINE:?} on {} within {:?} — its log is above. \
                 An unreadable cert path and a privileged port are the two that fail here.",
                plan.listen,
                ready_timeout,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MirrorProviderSlot;

    fn rule(hostname: &str, port: u16) -> IngressRule {
        IngressRule {
            hostname: hostname.into(),
            port,
            slot: STATIC_SLOT.into(),
            provider_id: None,
            machines: Vec::new(),
            upstream_hosts: vec![UPSTREAM_HOST.into()],
        }
    }

    fn plan(rules: Vec<IngressRule>, port: u16) -> PondDoorPlan {
        PondDoorPlan {
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            rules,
            sources: vec![],
        }
    }

    #[test]
    fn hostname_is_one_label_under_the_pond_tld() {
        assert_eq!(
            pond_hostname("yah-dashboard", "pond", None),
            "yah-dashboard.pond.localhost"
        );
        // A wildcard leaf covers exactly one level, so a non-default env must
        // flatten into the label rather than nest under it.
        assert_eq!(
            pond_hostname("yah-dashboard", "local-sim", None),
            "yah-dashboard-local-sim.pond.localhost"
        );
        assert_eq!(
            pond_hostname("yah", "pond", Some("docs")),
            "yah-docs.pond.localhost"
        );
        for env in ["pond", "local-sim"] {
            let h = pond_hostname("yah-dashboard", env, None);
            let label = h.strip_suffix(&format!(".{POND_TLD}")).unwrap();
            assert!(!label.contains('.'), "{h} nests below the wildcard");
        }
    }

    #[test]
    fn odd_service_names_become_valid_labels() {
        assert_eq!(dns_label("Yah_Dashboard"), "yah-dashboard");
        assert_eq!(dns_label("--weird--name--"), "weird-name");
        assert_eq!(dns_label("a.b.c"), "a-b-c");
    }

    #[test]
    fn upstreams_render_in_passways_host_fan_in_grammar() {
        let p = plan(
            vec![
                rule("yah-dashboard.pond.localhost", 4323),
                rule("yah-marketing.pond.localhost", 4322),
            ],
            8443,
        );
        assert_eq!(
            p.upstreams_env().unwrap(),
            "yah-dashboard.pond.localhost=127.0.0.1:4323,\
             yah-marketing.pond.localhost=127.0.0.1:4322"
        );
    }

    #[test]
    fn urls_drop_the_port_only_on_443() {
        assert_eq!(
            plan(vec![rule("a.pond.localhost", 1)], 8443).urls(),
            vec!["https://a.pond.localhost:8443"]
        );
        assert_eq!(
            plan(vec![rule("a.pond.localhost", 1)], 443).urls(),
            vec!["https://a.pond.localhost"]
        );
    }

    #[test]
    fn door_env_carries_no_acme_knob() {
        let p = plan(vec![rule("a.pond.localhost", 4322)], 8443);
        let cert = CertPair {
            cert: "/tmp/c.pem".into(),
            key: "/tmp/k.pem".into(),
        };
        let env = door_env(&p, &cert, Path::new("/tmp/door")).unwrap();
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            !keys.iter().any(|k| k.starts_with("PASSWAY_ACME")),
            "the pond door must never select passway's ACME arm — no public CA can issue for \
             a .localhost name: {keys:?}",
        );
        let get = |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
                .unwrap()
        };
        assert_eq!(get("PASSWAY_TLS_MODE"), "manual");
        assert_eq!(get("PASSWAY_LISTEN"), "127.0.0.1:8443");
        assert_eq!(get("PASSWAY_UPSTREAM_SOURCE"), "static");
    }

    #[test]
    fn issuing_as_root_is_refused_but_reusing_an_existing_leaf_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("_door");

        // No leaf yet + root → refuse, and name the unprivileged command. The
        // alternative is mkcert resolving root's HOME, finding no CA, and
        // minting one from a second root nothing trusts.
        let err = ensure_pond_cert_as(&state, false, true).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("yah cloud pond cert"), "got: {msg}");
        assert!(msg.contains("--port 443"), "got: {msg}");
        assert!(
            !state.exists(),
            "a refused issue must not leave a root-owned state dir behind",
        );

        // A leaf the operator already issued unprivileged → serving as root is
        // the whole point of --port 443 and must still work.
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join(CERT_FILE), b"leaf").unwrap();
        std::fs::write(state.join(KEY_FILE), b"key").unwrap();
        let pair = ensure_pond_cert_as(&state, false, true).expect("reuse is allowed as root");
        assert_eq!(pair.cert, state.join(CERT_FILE));
    }

    #[test]
    fn the_pid_file_and_upgrade_sock_are_keyed_by_port() {
        // The 443 door runs under sudo and leaves these root-owned; a later
        // unprivileged 8443 door must not need to rewrite the same paths.
        let cert = CertPair {
            cert: "/tmp/c.pem".into(),
            key: "/tmp/k.pem".into(),
        };
        let paths = |port: u16| -> (String, String) {
            let p = plan(vec![rule("a.pond.localhost", 4322)], port);
            let env = door_env(&p, &cert, Path::new("/tmp/door")).unwrap();
            let get = |k: &str| {
                env.iter()
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.clone())
                    .unwrap()
            };
            (get("PASSWAY_PID_FILE"), get("PASSWAY_UPGRADE_SOCK"))
        };
        let (pid_8443, sock_8443) = paths(8443);
        let (pid_443, sock_443) = paths(443);
        assert!(pid_8443.ends_with("/door/pingora-8443.pid"), "{pid_8443}");
        assert!(pid_443.ends_with("/door/pingora-443.pid"), "{pid_443}");
        assert_ne!(pid_8443, pid_443);
        assert_ne!(sock_8443, sock_443);
    }

    fn miniflare_slot(port: i64) -> MirrorProviderSlot {
        let mut fields = BTreeMap::new();
        fields.insert("port".to_string(), toml::Value::Integer(port));
        MirrorProviderSlot::Inline {
            kind: Provider::MiniflareContainer,
            fields,
        }
    }

    fn workspace_with(services: &[(&str, &str, i64)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (svc, env, port) in services {
            let mirrors = dir.path().join(".yah/services").join(svc).join("mirrors");
            std::fs::create_dir_all(&mirrors).unwrap();
            std::fs::write(
                dir.path()
                    .join(".yah/services")
                    .join(svc)
                    .join("service.toml"),
                format!("schema_version = 1\nname = \"{svc}\"\ndomain = \"{svc}.example\"\n"),
            )
            .unwrap();
            std::fs::write(
                mirrors.join(format!("{env}.toml")),
                format!(
                    "schema_version = 1\nshape = \"local\"\n\n\
                     [providers.static]\nkind = \"miniflare-container\"\nport = {port}\n\
                     bucket = \"b\"\n"
                ),
            )
            .unwrap();
        }
        dir
    }

    #[test]
    fn every_pond_mirror_is_fronted_with_no_opt_in() {
        let ws = workspace_with(&[
            ("yah-marketing", "pond", 4322),
            ("yah-dashboard", "pond", 4323),
        ]);
        let cfg = CloudConfig::load(ws.path()).unwrap();
        let p = plan_pond_door(&cfg, "127.0.0.1:8443".parse().unwrap()).unwrap();
        assert_eq!(
            p.urls(),
            vec![
                "https://yah-dashboard.pond.localhost:8443",
                "https://yah-marketing.pond.localhost:8443",
            ],
            "rules sort by hostname so two runs render identical config",
        );
        assert_eq!(
            p.sources,
            vec![
                "yah-dashboard/pond".to_string(),
                "yah-marketing/pond".to_string()
            ]
        );
    }

    #[test]
    fn a_non_pond_mirror_is_not_fronted() {
        let ws = workspace_with(&[("yah-marketing", "pond", 4322)]);
        let mirrors = ws.path().join(".yah/services/yah-marketing/mirrors");
        // The dev tier: also `shape = "local"`, also carrying a `port`, but
        // served in-process by mesofact-dev rather than by a miniflare the door
        // could dial. The pond arm keys off the slot *kind*, not the shape.
        std::fs::write(
            mirrors.join("dev.toml"),
            "schema_version = 1\nshape = \"local\"\n\n[providers.static]\n\
             kind = \"local-static\"\nport = 4321\n",
        )
        .unwrap();
        let cfg = CloudConfig::load(ws.path()).unwrap();
        let p = plan_pond_door(&cfg, "127.0.0.1:8443".parse().unwrap()).unwrap();
        assert_eq!(
            p.rules.len(),
            1,
            "only the miniflare-container slot is a pond"
        );
        assert_eq!(p.rules[0].hostname, "yah-marketing.pond.localhost");
    }

    #[test]
    fn a_bare_container_pond_is_fronted_at_its_published_host_port() {
        // yah-cloud-admin's shape: a `pond` mirror declaring nothing but
        // `shape = "local"`, with the port living in the component's
        // workload.toml — and host_port (4326) deliberately different from the
        // in-container port (4325), which is the pair a hostname saves you from
        // having to keep straight.
        let ws = workspace_with(&[("yah-marketing", "pond", 4322)]);
        let svc = ws.path().join(".yah/services/yah-admin");
        std::fs::create_dir_all(svc.join("mirrors")).unwrap();
        std::fs::write(
            svc.join("service.toml"),
            "schema_version = 1\nname = \"yah-admin\"\ndomain = \"admin.example\"\n\n\
             [[components]]\nid = \"admin\"\nkind = \"container\"\n\
             path = \"crates/admin\"\nrole = \"compute\"\n",
        )
        .unwrap();
        std::fs::write(
            svc.join("mirrors/pond.toml"),
            "schema_version = 1\nshape = \"local\"\n",
        )
        .unwrap();
        let comp = ws.path().join("crates/admin");
        std::fs::create_dir_all(&comp).unwrap();
        std::fs::write(
            comp.join("workload.toml"),
            "schema_version = 1\nname = \"yah-admin\"\nkind = \"container\"\n\n\
             [build]\ndockerfile = \"Dockerfile\"\n\n[run]\nport = 4325\nhost_port = 4326\n",
        )
        .unwrap();

        let cfg = CloudConfig::load(ws.path()).unwrap();
        let p = plan_pond_door(&cfg, "127.0.0.1:8443".parse().unwrap()).unwrap();
        let admin = p
            .rules
            .iter()
            .find(|r| r.hostname.starts_with("yah-admin."))
            .expect("the bare-container pond is fronted");
        assert_eq!(
            admin.upstream().unwrap(),
            "127.0.0.1:4326",
            "the door dials the published HOST port, not the in-container one",
        );
        assert_eq!(
            admin.hostname, "yah-admin.pond.localhost",
            "one container means no component qualifier in the label",
        );
    }

    #[test]
    fn a_container_component_outside_the_pond_env_is_not_fronted() {
        // The same component under `dev` runs natively, not in a container —
        // the env is the tier, so the door must not claim it.
        let ws = workspace_with(&[("yah-marketing", "pond", 4322)]);
        let svc = ws.path().join(".yah/services/yah-admin");
        std::fs::create_dir_all(svc.join("mirrors")).unwrap();
        std::fs::write(
            svc.join("service.toml"),
            "schema_version = 1\nname = \"yah-admin\"\ndomain = \"admin.example\"\n\n\
             [[components]]\nid = \"admin\"\nkind = \"container\"\n\
             path = \"crates/admin\"\nrole = \"compute\"\n",
        )
        .unwrap();
        std::fs::write(
            svc.join("mirrors/dev.toml"),
            "schema_version = 1\nshape = \"local\"\n",
        )
        .unwrap();
        let comp = ws.path().join("crates/admin");
        std::fs::create_dir_all(&comp).unwrap();
        std::fs::write(
            comp.join("workload.toml"),
            "schema_version = 1\nname = \"yah-admin\"\nkind = \"container\"\n\n\
             [build]\ndockerfile = \"Dockerfile\"\n\n[run]\nport = 4325\n",
        )
        .unwrap();

        let cfg = CloudConfig::load(ws.path()).unwrap();
        let p = plan_pond_door(&cfg, "127.0.0.1:8443".parse().unwrap()).unwrap();
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].hostname, "yah-marketing.pond.localhost");
    }

    #[test]
    fn two_ponds_on_one_port_is_an_error_not_a_last_writer_wins() {
        let ws = workspace_with(&[
            ("yah-marketing", "pond", 4322),
            ("yah-dashboard", "pond", 4322),
        ]);
        let cfg = CloudConfig::load(ws.path()).unwrap();
        let err = plan_pond_door(&cfg, "127.0.0.1:8443".parse().unwrap()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("4322"), "got: {msg}");
        assert!(msg.contains("yah-dashboard/pond"), "got: {msg}");
    }
}
