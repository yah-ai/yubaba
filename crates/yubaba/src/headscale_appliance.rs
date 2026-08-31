//! The headscale appliance spec (R591-F1).
//!
//! Headscale is the mesh coordinator: the thing every node in the fleet dials
//! to get a mesh. It is an **appliance** in the [`LifecycleArchetype`] sense —
//! exactly one live instance, a stable identity, and durable state (the sqlite
//! DB + `noise_private.key`) that must follow it. What it is *not* is special:
//! once its lifecycle is described as a [`WorkloadSpec`], it is supervised by
//! the same kamaji every other workload on the node runs under, and
//! [`crate::leader`] starts and stops it the way placement starts and stops
//! anything else.
//!
//! ## Why this replaces `systemctl enable --now headscale`
//!
//! On 2026-07-09 a boot-race SIGTERM stopped headscale on us-west-001 and it
//! stayed dead for **seven days**. The raw unit carried `Restart=on-failure`,
//! and `headscale serve` exits **0** on SIGTERM — a graceful shutdown, which
//! `on-failure` by definition does not restart. Two of three raft voters and
//! the operator's laptop fell off the tailnet and nothing brought it back.
//!
//! [`RestartPolicy::Always`] is the fix, and it is a *stronger* guarantee than
//! the `Restart=always` the live unit was hand-patched to on 2026-07-16: the
//! kamaji supervisor treats every exit as restart-worthy regardless of code,
//! and it publishes `WorkloadStatus::Restarting` while it does, so a
//! crash-looping coordinator is visible in `yah cloud workload list` instead of
//! only in the journal of the box that is failing.
//!
//! ## Native, not containerised — and that is deliberate
//!
//! The spec carries [`NATIVE_EXEC_ANNOTATION`], so kamaji forks the host
//! binary at `<headscale_dir>/headscale` rather than pulling an image. Three
//! reasons, in order of weight:
//!
//! 1. **The state is already on the host** — `headscale.db`, `acls.yaml`,
//!    `config.yaml` and `noise_private.key` live in `headscale_dir`, written
//!    there by `POST /headscale/deploy` and replicated by [`crate::litestream`].
//!    A container would need every one of them bind-mounted back in.
//! 2. **It owns privileged host ports today** — `0.0.0.0:443` plus `:80` for
//!    the Let's Encrypt HTTP-01 challenge. A native process on the host
//!    network needs no port mapping and no netns choreography.
//! 3. **Cutover risk** — re-homing the supervisor and changing the execution
//!    substrate in one step would make a failed cutover ambiguous. This ticket
//!    changes *who supervises*; the process itself is byte-identical to what
//!    the systemd unit ran.
//!
//! `image` is identity metadata only for a native workload — nothing is
//! pulled. Same contract the W254 Darwin build leg rides
//! (`velveteen_exec::remote::build_workload_spec`).
//!
//! ## What is NOT here
//!
//! No `noise_private.key` handling. That key is the appliance's *identity*,
//! not its data: move the appliance without it and every node's stored server
//! identity mismatches at once. It travels through R600 / W273's
//! raft-replicated cluster secret store (`SecretRef::Cluster` +
//! `SecretMount` Cluster→File), the same path the TLS certs use. Do not invent
//! a second secret channel for it.
//!
//! [`RestartPolicy::Always`]: workload_spec::RestartPolicy::Always
//! [`NATIVE_EXEC_ANNOTATION`]: workload_spec::NATIVE_EXEC_ANNOTATION

use std::collections::HashMap;
use std::path::Path;

use workload_spec::{
    ExposeSpec, ImageRef, LifecycleArchetype, MeshExpose, MeshIdent, Millis, NamespaceId,
    ResourceLimits, RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, VolumeMount,
    VolumeSource, WorkloadSpec,
};

/// Mesh identity of the headscale appliance. Stable for the life of the
/// cluster — [`crate::leader`] tears down *by this identity*, so changing it
/// would strand a running appliance under the old name.
pub const HEADSCALE_IDENT: &str = "headscale";

/// DNS-label workload name (no dots — `check_name` rejects them).
pub const HEADSCALE_NAME: &str = "headscale";

/// Ports headscale listens on when it terminates its own TLS: `443` for the
/// coordinator itself and `80` for the Let's Encrypt HTTP-01 challenge.
///
/// R591-T2 moves TLS termination to the fleet's passway front doors, at which
/// point this collapses to a single plain-HTTP port. Until then these are the
/// two privileged ports the supervising kamaji must be able to hand out —
/// `CAP_NET_BIND_SERVICE` in `kamaji.service`.
pub const HEADSCALE_PORTS: [u16; 2] = [443, 80];

/// Graceful-stop budget. `headscale serve` closes its listeners and exits 0 on
/// SIGTERM well inside this; the window exists so an in-flight node
/// registration is not cut mid-write to the sqlite DB.
const STOP_GRACE_SECS: u64 = 30;

/// Build the headscale appliance [`WorkloadSpec`] for a node whose headscale
/// state lives under `headscale_dir`.
///
/// Pure — no I/O, no host inspection — so the shape is unit-testable off a
/// Linux box. The caller ([`crate::leader::on_became_leader`]) hands the result
/// to whichever backend `ServerState::active_backend` resolves to.
pub fn appliance_spec(headscale_dir: &Path) -> WorkloadSpec {
    let bin = headscale_dir.join("headscale");
    let config = headscale_dir.join("config.yaml");

    let mut annotations = HashMap::new();
    // The marker kamaji routes on: fork the host binary rather than pulling an
    // image. Refused (not silently downgraded to a container) by a kamaji built
    // without `native-exec` or started without `--native-exec-dir`, which is
    // exactly the failure we want — a headscale in a Linux container with none
    // of its state bind-mounted is a wrong answer, not a degraded one.
    annotations.insert(
        workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
        workload_spec::NATIVE_EXEC_VALUE.to_string(),
    );

    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: HEADSCALE_NAME.to_string(),
        // Identity metadata only — a native workload pulls nothing. The tag
        // records which headscale the node was provisioned with; the digest is
        // a required field with no meaning here.
        image: ImageRef {
            registry: "ghcr.io".into(),
            repository: "juanfont/headscale".into(),
            tag: "native".into(),
            digest: workload_spec::testing::test_digest(),
        },
        // kamaji's native path is gated to tier=infra: it runs argv on the host
        // with no sandbox. The mesh coordinator is infrastructure by definition.
        tier: TierTag("infra".into()),
        tenant: TenantId::singleton(),
        namespace: NamespaceId::singleton(),
        replicas: 1,
        command: Some(vec![
            bin.to_string_lossy().into_owned(),
            "serve".to_string(),
            "--config".to_string(),
            config.to_string_lossy().into_owned(),
        ]),
        entrypoint: None,
        workdir: Some(headscale_dir.to_path_buf()),
        user: None,
        env: vec![],
        secrets: vec![],
        // Inert on the native backend (a fork+exec'd process has no mount
        // namespace to mount into), and declared anyway: "a volume that must
        // follow it" is the structural half of W244's appliance definition, so
        // `effective_archetype` agrees with the explicit `archetype` below
        // instead of depending on it. It is also what a reader needs in order
        // to know which directory R591-T3's litestream replication covers.
        volumes: vec![VolumeMount {
            source: VolumeSource::Bind {
                host_path: headscale_dir.to_path_buf(),
            },
            target: headscale_dir.to_path_buf(),
            read_only: false,
        }],
        resources: ResourceLimits {
            memory_mb: 512,
            cpu_millis: 1000,
            ephemeral_storage_mb: 1024,
        },
        depends_on: vec![],
        healthcheck: None,
        // THE WHOLE POINT OF THIS TICKET. `Always` restarts on a clean exit 0
        // too — see the module docs for the seven-day outage that `on-failure`
        // produced.
        restart_policy: RestartPolicy::Always,
        archetype: Some(LifecycleArchetype::Appliance),
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(STOP_GRACE_SECS),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent(HEADSCALE_IDENT.to_string()),
                ports: HEADSCALE_PORTS.to_vec(),
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: HashMap::new(),
        annotations,
    }
}

/// The mesh identity [`appliance_spec`] deploys under, as the type the
/// teardown path takes.
pub fn appliance_ident() -> MeshIdent {
    MeshIdent(HEADSCALE_IDENT.to_string())
}

/// Render one front door's `PASSWAY_UPSTREAMS` entry for the coordinator's
/// hostname (R591-T2) — the sovereign form of "the external identity follows
/// placement".
///
/// `placed_at` is the mesh address of the node raft placed the appliance on
/// (yubaba publishes it as the `headscale` service record; see
/// [`crate::leader`]). `this_door` is the mesh address of the node *this* front
/// door runs on. Every front door in the fleet gets a rule for the same
/// hostname, so DNS never moves — a failover repoints upstreams, not records.
///
/// # The co-located door routes to loopback, and that is a constraint, not an
/// optimisation
///
/// Fronting the coordinator over the mesh creates a cycle: a node dials
/// `cloud.mesh.yah.dev` → DNS → a front door → headscale's *mesh* address, so
/// the proxying node needs a working mesh to reach the thing that grants
/// meshes. Steady state is fine (a rebooting node borrows a healthy peer's
/// mesh). A **total-fleet cold start has no path** — nobody has a mesh, so no
/// front door can reach the coordinator, so nobody can get a mesh.
///
/// The operator's answer to the general case is that a camp bootstraps a mesh
/// **out of band** — over ssh, from a list of IPs — rather than over the mesh it
/// is creating; that holds for any new mesh, not just this one. The in-design
/// mitigation is this function: the front door sitting on the same node as the
/// appliance dials `127.0.0.1`, so **one** path to the coordinator never
/// traverses the mesh at all. Whichever node raft placed it on can bootstrap
/// itself, and the rest follow from there.
///
/// (The deadlock is inference from the 2026-08-12 config + topology, not a
/// tested failure. The dev cluster — us-west-011/013/014 — is the sanctioned
/// place to prove it; see this relay's testbed gotcha.)
pub fn front_door_upstream_rule(
    hostname: &str,
    placed_at: std::net::Ipv4Addr,
    this_door: std::net::Ipv4Addr,
    port: u16,
) -> String {
    let upstream = if placed_at == this_door {
        std::net::Ipv4Addr::LOCALHOST
    } else {
        placed_at
    };
    format!("{hostname}={upstream}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec() -> WorkloadSpec {
        appliance_spec(&PathBuf::from("/var/lib/yah-cloud/headscale"))
    }

    /// The regression the whole ticket exists to prevent: `headscale serve`
    /// exits 0 on SIGTERM, so anything short of `Always` leaves a gracefully
    /// stopped coordinator dead. `OnFailure` is the shape of the systemd unit
    /// that caused the 2026-07-09 outage.
    #[test]
    fn a_graceful_exit_is_restart_worthy() {
        assert_eq!(spec().restart_policy, RestartPolicy::Always);
    }

    #[test]
    fn it_is_a_pinned_non_drainable_appliance() {
        let s = spec();
        assert_eq!(s.archetype, Some(LifecycleArchetype::Appliance));
        // Belt and braces: the pre-R572 inference must reach the same verdict,
        // so a consumer reading `effective_archetype` is not a second opinion.
        assert_eq!(s.effective_archetype(), LifecycleArchetype::Appliance);
        assert_eq!(s.replicas, 1);
    }

    #[test]
    fn it_routes_to_the_native_backend_not_a_container() {
        assert!(spec().wants_native_exec());
    }

    /// kamaji's `validate_native_exec_spec` refuses a native deploy outside
    /// tier=infra. A spec that fails this is refused at the UDS, not
    /// downgraded, so the appliance would simply never start.
    #[test]
    fn native_exec_admission_floor_is_satisfied() {
        let s = spec();
        assert_eq!(s.tier.0, "infra");
        // The other two admission rules: no unresolved refs, and no
        // nested-sandbox grant (which has no meaning without a container).
        assert!(s.env.is_empty());
        assert!(!s.wants_nested_sandbox());
    }

    #[test]
    fn argv_names_the_host_binary_and_its_config() {
        let s = spec();
        assert_eq!(
            s.command.as_deref(),
            Some(
                [
                    "/var/lib/yah-cloud/headscale/headscale",
                    "serve",
                    "--config",
                    "/var/lib/yah-cloud/headscale/config.yaml",
                ]
                .map(String::from)
                .as_slice()
            )
        );
        // `entrypoint` unset: kamaji's argv rule is entrypoint ++ command, and
        // a native workload has no image entrypoint to inherit.
        assert!(s.entrypoint.is_none());
    }

    /// The teardown path in `leader.rs` resolves the workload by mesh identity,
    /// so the two must agree or a lost-leadership event leaves the appliance
    /// running on a node that no longer owns it — two live headscales serving
    /// divergent DB state.
    #[test]
    fn deploy_and_teardown_agree_on_the_identity() {
        assert_eq!(spec().expose.mesh.identity, appliance_ident());
    }

    #[test]
    fn the_state_dir_travels_with_the_appliance() {
        let s = spec();
        let dir = PathBuf::from("/var/lib/yah-cloud/headscale");
        assert_eq!(s.workdir.as_ref(), Some(&dir));
        assert_eq!(s.volumes.len(), 1);
        assert_eq!(s.volumes[0].target, dir);
        assert!(!s.volumes[0].read_only, "the sqlite DB is written in place");
    }

    // ── R591-T2: follow-placement front-door rules ──────────────────────────

    const EAST: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 3);
    const WEST: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 1);

    /// The sovereign shape: DNS never moves, so a front door that does not hold
    /// the appliance proxies across the mesh to whichever node does.
    #[test]
    fn a_remote_front_door_proxies_to_the_placed_node() {
        assert_eq!(
            front_door_upstream_rule("cloud.mesh.yah.dev", WEST, EAST, 443),
            "cloud.mesh.yah.dev=100.64.0.1:443"
        );
    }

    /// THE BOOTSTRAP-CYCLE MITIGATION. The door co-located with the appliance
    /// must not route to the appliance's *mesh* address: that path needs a mesh
    /// to reach the thing that grants meshes, and on a total-fleet cold start
    /// nobody has one. Loopback is the one path that never traverses the mesh,
    /// so the placed node can always bootstrap itself.
    #[test]
    fn the_co_located_front_door_routes_to_loopback() {
        assert_eq!(
            front_door_upstream_rule("cloud.mesh.yah.dev", WEST, WEST, 443),
            "cloud.mesh.yah.dev=127.0.0.1:443"
        );
    }

    /// Every front door is handed a rule for the same hostname — the address
    /// that moves is the upstream, never the DNS record. Asserted across a
    /// two-door fleet so a change that reintroduced per-door hostnames (an
    /// A-record repoint by another name) fails here.
    #[test]
    fn every_front_door_serves_the_same_hostname() {
        let rules: Vec<String> = [EAST, WEST]
            .iter()
            .map(|&door| front_door_upstream_rule("cloud.mesh.yah.dev", WEST, door, 443))
            .collect();
        assert!(rules.iter().all(|r| r.starts_with("cloud.mesh.yah.dev=")));
        // ...and exactly one of them is the loopback door.
        assert_eq!(
            rules.iter().filter(|r| r.contains("127.0.0.1")).count(),
            1,
            "exactly one door is co-located: {rules:?}"
        );
    }

    /// A failover changes which upstream every door dials and nothing else —
    /// no record edit, no new cert, no HTTP-01 challenge.
    #[test]
    fn a_failover_moves_the_upstream_not_the_record() {
        let before = front_door_upstream_rule("cloud.mesh.yah.dev", WEST, EAST, 443);
        let after = front_door_upstream_rule("cloud.mesh.yah.dev", EAST, EAST, 443);
        assert_eq!(before, "cloud.mesh.yah.dev=100.64.0.1:443");
        // East now holds the appliance, so east's own door goes to loopback.
        assert_eq!(after, "cloud.mesh.yah.dev=127.0.0.1:443");
    }

    /// The spec is built per-node from that node's configured headscale dir,
    /// not from a baked-in constant — a test rig and a fleet node disagree
    /// about the path.
    #[test]
    fn the_state_dir_is_not_hardcoded() {
        let s = appliance_spec(&PathBuf::from("/tmp/rig/hs"));
        assert_eq!(
            s.command.as_ref().unwrap()[0],
            "/tmp/rig/hs/headscale".to_string()
        );
    }
}
