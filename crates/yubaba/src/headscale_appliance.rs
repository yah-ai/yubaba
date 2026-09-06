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
//! No `noise_private.key` handling, and `secrets` stays empty **on purpose**.
//! That key is the appliance's *identity*, not its data: move the appliance
//! without it and every node's stored server identity mismatches at once. It
//! travels through R600 / W273's raft-replicated cluster secret store — but
//! R858-T2 measured that a `SecretRef::Cluster` + `SecretMount` Cluster→File
//! declaration here would be a silent no-op, because
//! `deploy::secret_mount::materialize_file_secrets` runs only under
//! `POST /workloads/deploy` and [`crate::leader::start_headscale`] deploys
//! straight through the backend. So the read happens in `start_headscale`
//! instead, before the appliance starts, and the bytes land in the *persistent*
//! `headscale_dir` rather than on `/run/yah/secrets` tmpfs. Both halves live in
//! [`crate::headscale_state`]. Do not add a `secrets` entry here expecting it to
//! fire, and do not invent a second secret channel.
//!
//! [`RestartPolicy::Always`]: workload_spec::RestartPolicy::Always
//! [`NATIVE_EXEC_ANNOTATION`]: workload_spec::NATIVE_EXEC_ANNOTATION
//!
//! @yah:ticket(R858-T2, "Carry headscale's noise_private.key through the cluster secret store so the appliance keeps its identity across a move")
//! @yah:at(2026-09-04T23:42:36Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R858)
//! @yah:next("Tier: Wizard — getting this wrong is silent and fleet-wide, and the failure is worse than the outage it prevents.")
//! @yah:gotcha("MEASURED ON THE BOX 2026-09-04: /var/lib/yah-cloud/headscale/noise_private.key is 72 bytes, mode 0600, mtime Jun 22, and exists ONLY on us-west-001's local disk. It is the appliance's IDENTITY, not its data — move the appliance without it and EVERY node's stored server identity mismatches at once. That is silent and fleet-wide, i.e. WORSE than the R858 outage, because a restored DB plus a fresh noise key produces a headscale that runs, looks healthy, and rejects every node.")
//! @yah:gotcha("LITESTREAM STRUCTURALLY CANNOT CARRY THIS AND DO NOT INVENT A SECOND SECRET CHANNEL. Both headscale_appliance.rs's module docs (\"What is NOT here\") and litestream.rs's own gotcha already name the mechanism: R600/W273's raft-replicated cluster secret store, SecretRef::Cluster + SecretMount Cluster->File, the same path the TLS certs use. litestream replicates the sqlite DB and nothing else. Note the native-exec interaction: headscale runs fork+exec'd on the host with no mount namespace, so a File-target secret mount materializes to /run/yah/secrets/<ident>/ (yubaba.service grants RuntimeDirectory=yah/secrets for exactly this) and the appliance must be pointed at it rather than at a bind that a native workload has no namespace to receive.")
//! @yah:next("DO R858-T1 FIRST — it shrinks this ticket before you start it. Today the state that must survive a move is {headscale.db, noise_private.key, acme-cache}. Once TLS terminates at the passway doors, the ACME cache stops being state at all, leaving exactly two items: the DB (litestream, built in R858) and this key. Starting here instead means designing carriage for a third artifact that is about to stop existing.")
//! @yah:verify("The acceptance test is the operator's rehearsal, not a unit test: with the key carried, bring us-west-001 down and confirm the headscale that comes up elsewhere is accepted by an EXISTING node — i.e. a node that never re-registered still reaches the tailnet. A fresh node joining proves nothing here; the failure this ticket prevents is specifically that already-registered nodes reject the new server identity.")
//! @yah:gotcha("A FOURTH PIECE OF STATE NOBODY HAS ENUMERATED: `acls.yaml` (77 bytes, mtime Jun 22) sits in /var/lib/yah-cloud/headscale/ beside the DB and the noise key. litestream replicates ONLY headscale.db, so this file is carried by nothing — not the DB, not litestream, not the cluster secret store. A failover to a node without it gets a coordinator with different ACLs, and unlike the noise-key failure that would look healthy AND partially work, which is worse to diagnose. CONFIRM BEFORE ACTING: headscale 0.23 can source policy from a file OR from the database depending on its policy mode, and the config block I read did not include a `policy:` section — so establish whether this file is live or vestigial (`grep -i policy /var/lib/yah-cloud/headscale/config.yaml` on us-west-001) before designing carriage for it. If it IS live it belongs in this ticket's scope; if it is vestigial, delete it so the next reader does not re-discover the same question. Either way the general lesson stands: the appliance's state was enumerated as \"the DB plus the identity\" and that enumeration was incomplete — walk the whole state dir rather than trusting the list.")
//! @yah:next("THE ACLS HALF HAS ITS OWN HOME NOW — R861-T1. If ACLs turn out to be declared and reconciled there, acls.yaml stops being state this ticket has to carry at all: declared config is regenerated on the new node rather than replicated to it, which is strictly better than carrying a file. Do not build carriage for it here until R861-T1 has answered whether the file is even live. The noise key is different and stays in this ticket's scope — it is an IDENTITY, not config, and cannot be regenerated by definition.")
//! @yah:notify_on(R861-T1, "ACLS QUESTION ANSWERED — do not re-run the SSH check this ticket's gotcha asks for. Measured on us-west-001 2026-09-04 by @Ashguard:griffin: config.yaml lines 32-34 are `policy:` / `mode: file` / `path: /var/lib/yah-cloud/headscale/acls.yaml`, so acls.yaml is LIVE, not vestigial, and all three in-tree renderers emit the same. Practical consequence for THIS ticket: while the fleet stays in file mode, acls.yaml is still state a move must carry alongside noise_private.key — R861-T1's reconciler makes drift LOUD but cannot push a policy in file mode (headscale refuses; only database mode accepts PUT /api/v1/policy). It stops being carriable state only once policy.mode flips to database, which R861-T1 deliberately left as an operator call tied to the rehearsal. So keep acls.yaml in your enumeration for now, and drop it the day that flip lands.")
//! @yah:handoff("DONE — the noise key now travels through the raft-replicated cluster secret store, and the appliance refuses to start with the wrong identity rather than starting and silently rejecting the fleet. New module oss/yubaba/crates/yubaba/src/headscale_state.rs holds the SINGLE writer for headscale_dir (write_state_file, owner-only 0600), now also used by the write_b64! macro behind POST /headscale/deploy so there is one write site rather than two. materialize_noise_key is called by start_headscale BEFORE either deploy path, via a ClusterResolver bound to SecretConsumer::of(&appliance_spec). Failure behaviour is loud by design, which is the other half of this relay's lesson: a store-held key that cannot be written or decrypted REFUSES TO START (starting with a wrong identity is worse than not starting); store-lacks-it-but-disk-has-it and store-lacks-it-and-no-disk both log at ERROR naming the seed command and carry on. Nothing ever auto-seeds the store from local disk — during a split-brain the losing node would otherwise publish its own identity over the real one. Seeding rail uses the existing verb, no new one invented: secret name headscale/noise-private-key, vault slot headscale-noise-private-key, declaration written at .yah/infra/secrets/headscale-noise-private-key.toml (encoding utf8, access workloads=[{workload=\"headscale\"}], target /var/lib/yah-cloud/headscale/noise_private.key mode 0o600).")
//! @yah:handoff("Tree anchor at handoff: 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — the shared tree as I left it. Diff against it (`git diff 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:gotcha("THIS TICKET'S ORIGINAL DESIGN WOULD HAVE SHIPPED A SILENT NO-OP — do not restore it. The ticket said to declare a SecretRef::Cluster + File-target mount on appliance_spec the way the TLS certs do. Measured: materialize_file_secrets (oss/yubaba/crates/yubaba/src/deploy/secret_mount.rs:88) has EXACTLY ONE production caller, deploy_workload_spec behind POST /workloads/deploy (lib.rs:3708); every other reference is #[cfg(test)]. And start_headscale (leader.rs:357) deploys straight through backend.deploy_workload, deliberately bypassing that handler — its own comment at leader.rs:~382 says so. So `secrets: vec![...]` on appliance_spec would have changed nothing at runtime while reviewing as correct. SECOND reason the original design was wrong: a carriage channel ALREADY EXISTED — POST /headscale/deploy takes noise_key_base64 and writes the file (lib.rs:4678), and app/yah/cli/src/mesh.rs:989 reads it for a transplant — so the ticket's own \"do not invent a second secret channel\" instruction was violated by the ticket's own proposal. THIRD: the File-mount route would have opened a real hole. /run/yah/secrets is TMPFS (HOST_ROOT at oss/yah-base/crates/workload-spec/src/lib.rs:3650, RuntimeDirectory=yubaba yah/secrets at app/yah/cli/resources/yubaba.service:154-156), so it is wiped on reboot and a native fork+exec'd headscale starting before yubaba re-materialized would find no key at all. Writing to the persistent headscale_dir instead is why this needed no config-generator change.")
//! @yah:gotcha("TWO QUESTIONS SETTLED BY MEASUREMENT SO NOBODY RE-OPENS THEM. (1) private.key, which sits beside the noise key in all three generators, is NOT identity-bearing and needs NO carriage — headscale v0.23.0's own config-key table (read out of the pinned binary) has only noise.private_key_path and derp.server.private_key_path, with no top-level private_key_path; this camp's mesh dir is a controlled experiment where 0.23 ran a clean serve/shutdown against a config that DOES set the top-level key, minted noise_private.key and never created private.key; and all three generators set derp.server.enabled=false. The file on us-west-001 exists only because an older headscale made it. Recorded in headscale_state.rs's module docs. THAT FINDING PRODUCED R858-B10 — `yah mesh promote` still REQUIRES private.key as a transplant input (mesh.rs:790 bail, :1020 read_b64) and therefore fails preflight on any coordinator that has only ever run 0.23, which is a landmine directly under R858-T8's rehearsal. (2) The self-bootstrap handler at lib.rs:4923-4940 minting its own identity is CORRECT and deliberately stays ungated: lib.rs:4941 states there is no state to transplant because bootstrap creates a new tailnet, and routing it through the gate would fire the fresh-identity ERROR on every legitimate first boot — devaluing the loudest signal in the system, which is exactly the mechanism by which R858's original warnings went unread.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib: 649 passed / 0 failed, against a 639 passed / 0 failed baseline measured before any edit (+10 = the new tests), run twice to a consistent result. Note the baseline was CLEANER than this relay expected — tests::headscale_deploy_downloads_from_url_override at lib.rs:7890, flagged as a pre-existing failure during R858-T1, was already green by the time T2 started, so a peer fixed it in between. cargo check -p yubaba --all-targets is clean apart from two pre-existing unused-import warnings in a peer's crates/cloud/src/reconciler/mesofact_static.rs. One intervening run died on an error[E0758] in fob that was a peer's torn mid-write, not ours — the file on disk had no block-comment markers at all and was 1145 lines against an error citing line 1823; the clean re-run confirms it.")
//! @yah:verify("NOT DONE, STATED PLAINLY: the real key has NOT been seeded and no live node was touched. Nothing here proves carriage end-to-end — the unit tests exercise the resolve/write/refuse paths, not a real failover. The operator steps that remain are (1) read the 72 bytes off us-west-001 at /var/lib/yah-cloud/headscale/noise_private.key, (2) `yah keys set headscale-noise-private-key`, (3) commit .yah/infra/secrets/headscale-noise-private-key.toml, (4) `yah cloud secret put headscale/noise-private-key`. Until (4) lands, every yubaba leader that starts headscale will log the store-lacks-it ERROR — that is the intended, correct signal for the fleet's current state, not a regression. The actual acceptance test is R858-T8's rehearsal, and it is specifically that an ALREADY-REGISTERED node still reaches the tailnet after the coordinator moves; a fresh node joining proves nothing about this ticket.")

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
///
/// @yah:ticket(R858-B9, "headscale's behind-a-proxy config binds loopback, so no remote front door can reach it — three places disagree about the port")
/// @yah:at(2026-09-05T04:12:00Z)
/// @yah:assignee(agent:claude)
/// @yah:parent(R858)
/// @yah:severity(high)
/// @yah:next("TS2021 UPGRADE PASSTHROUGH IS A REAL CONSTRAINT, NOT A DETAIL. lib.rs:4776-4778 records that Cloudflare strips tailscale's Upgrade header and 500s /machine/register, which is why the bootstrap doc at :5117-5121 insists on no CF proxy. A passway door in front of headscale inherits that requirement — prove the door passes Upgrade through end to end before trusting a green /key?v=138, because /key is a plain GET and will pass even if the register path does not.")
/// @yah:gotcha("DO NOT LAND THIS BEFORE THE A RECORD MOVES. This is step (4) of R858-T1's ordering and it is destructive out of order: headscale today serves the live fleet from the BOOTSTRAP config, which binds 0.0.0.0:443 and terminates its own Let's Encrypt TLS (generate_bootstrap_headscale_config, oss/yubaba/crates/yubaba/src/lib.rs:5122-5180, keys at :5139-5146). Flipping it to plain HTTP while cloud.mesh.yah.dev still resolves straight to 15.204.89.240 decapitates the mesh exactly as the 2026-09-03 outage did. Sequence is: doors serve the name, then the A record moves to the door set, THEN this.")
/// @yah:assumes("That the intended end state is one headscale listener on the mesh IP, plain HTTP, fronted by the doors — inferred from generate_remote_headscale_config's own doc at lib.rs:5118-5119 (localhost-only coordinator fronted by a proxy) plus the fact that R858-T1 wired the doors to reach it. Not confirmed with the operator.")
/// @yah:gotcha("THE DEFECT, three places that disagree, all read 2026-09-04. (1) generate_remote_headscale_config (oss/yubaba/crates/yubaba/src/lib.rs:4721-4770) emits `listen_addr: 127.0.0.1:8080` at :4734 — a LOOPBACK bind, so only a door on the same host can reach it and every REMOTE front door is structurally unable to, which is the exact case the follow-placement design exists for. (2) appliance_spec's HEADSCALE_PORTS (this file, `[443, 80]`) advertises the appliance on the mesh at 443/80 — matching NEITHER generator's listen_addr. (3) the health probe at lib.rs:4713 hardcodes `http://127.0.0.1:8080/health`, so it silently follows generator (1) and will lie if the bind moves. front_door_upstream_rule's `port` argument has no production value in-tree, so nothing today forces these three into agreement.")
/// @yah:next("SEQUENCE, and step 1 is what @Ashguard:griffin is waiting on — T1's ingress half is DONE on east and south and cannot proceed to the A record until :443 is free on us-west-001. (1) LIVE, on west, inside the short-outage budget the operator granted 2026-09-05: drop `tls_letsencrypt_hostname` + the HTTP-01 block from /var/lib/yah-cloud/headscale/config.yaml, set `listen_addr: 0.0.0.0:8080`, add the ufw rules (allow 8080 from 100.64.0.0/10, allow from 127.0.0.1, deny otherwise), restart the appliance, confirm `ss -lntp` shows :443 and :80 free and 8080 bound, then ping griffin with the port. This is ssh-recoverable on the node you are standing on and the rollback is the previous config.yaml — take a copy first. (2) Griffin then stands passway-demux + passway-mesh on west with the CO-LOCATED pin 127.0.0.1:8080, and flips east+south's PASSWAY_UPSTREAM_TLS/SNI/port in the same window — the appliance has ONE TLS posture at a time, so a door left on TLS=true after this speaks TLS to a plaintext port and one flipped early speaks plaintext to a TLS port, and both read like proxy bugs. (3) Only then does the A record move onto all three doors. (4) RECONCILE THE CODE with what step 1 did by hand, or the next provision re-creates the disagreement: `generate_remote_headscale_config`'s listen_addr, the bootstrap renderer that actually produced the live file, the advertised-ports constant in headscale_appliance.rs (it still claims [443, 80] and must become the one real port), and `probe_headscale_local`'s hardcoded 127.0.0.1:8080 — that last one is also half of R858-B11, so take them together.")
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
        // R860-T1 added this field; empty here keeps today's behaviour exactly.
        // W338 models the litestream replicator this appliance needs as a
        // `local` + `self` requirement — that's R860-T2/T6, not this line.
        requires: vec![],
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
                ports: MeshExpose::anonymous_ports(HEADSCALE_PORTS.iter().copied()),
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
/// placement". Full rationale, including why the co-located door dialing
/// `127.0.0.1` is a bootstrap-cycle constraint rather than an optimisation,
/// lives on the definition.
///
/// R858-T1 moved the definition down to `local-driver`, which already owns the
/// `PASSWAY_UPSTREAMS` grammar this renders. It had to: the deploy path that
/// finally calls it (`yah cloud ingress`) links `local-driver` but
/// deliberately **not** the full `yubaba` lib, since that pulls openraft, axum
/// and russh into the CLI for one pure six-line function (R483-T5). Re-exported
/// here so this module's API and its four tests below are unchanged.
pub use local_driver::passway_ingress::front_door_upstream_rule;

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
