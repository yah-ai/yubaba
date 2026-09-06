//! Provisioning orchestrator: config → cloud-init render → MachineProvider call.
//!
//! Decoupled from the concrete provider so the CLI passes a `&dyn MachineProvider`
//! (Hetzner in production, in-memory fakes in tests).
//!
//! `execute` here is called only from the operator-invoked `yah cloud machine
//! provision` CLI (`app/yah/cli/src/cloud.rs`) — nothing in the yubaba server
//! process calls it. `yubaba::headroom` (R737-T4) watches for when a fresh
//! call here is warranted (N+1/N+2 warm-spare deficit) and surfaces that as a
//! `GET /raft/status` field plus a log line; it does not call this module,
//! deliberately — see its own doc for why.
//!
//! @yah:ticket(R737-T4, "N+1 headroom accounting + a background headroom-restore provisioning job that never sits on the failover path")
//! @yah:status(review)
//! @yah:at(2026-08-16T04:37:37Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:phase(P3)
//! @yah:parent(R737)
//! @yah:next("Tier: Cleric — an invariant plus an enqueue path; the hard constraint (never inline) is already the status quo to preserve.")
//! @yah:next("VERIFIED ABSENT 2026-08-09: there is no N+1/N+2 warm-spare notion to fail over into. cloud::provision provisions on demand and nothing tracks headroom.")
//! @yah:next("When headroom drops below N+1, ENQUEUE a background provisioning job. N+2 where a whole region can vanish.")
//! @yah:depends_on(R737-F3)
//! @yah:handoff("New oss/yubaba/crates/yubaba/src/headroom.rs: N+1 (N+2 across >=2 declared regions) warm-spare accounting, W253 §8. required_spare(members) derives the target from distinct MemberInfo.region values (2 once the fleet spans >=2 regions, else 1). is_spare(node,...) is the stricter predicate W253 asks for -- confirmed live (F2's TransitionTracker) + published capacity + ZERO currently-owned LIVE tenants (a node quietly carrying one small tenant is not 'held in reserve', even with room left -- that's node_headroom's job, not this). evaluate() counts spare nodes against the requirement -> HeadroomReport{spare, required}. 10 unit tests covering region-count thresholds, each spare-disqualifying condition individually (unconfirmed, unmeasured, carrying a live tenant), and the expired-lease-frees-the-node case that mirrors R737-F1's own node_load argument.")
//! @yah:handoff("THE DESIGN CALL: does NOT call cloud::provision::execute, and does not build an in-process job queue with no consumer. Nothing in the yubaba server process has the MachineConfig/provider credentials that call needs -- those live with the operator-invoked `yah cloud machine provision` CLI (app/yah/cli/src/cloud.rs), confirmed by grep: provision::execute has exactly one call site and it is not in yubaba. Giving the control-plane daemon direct cloud-provisioning authority is a materially bigger architectural change than this ticket's own 'Cleric: an invariant plus an enqueue path' framing asks for. 'Enqueue' is scoped to: a leader-only background loop (paced at 10x election timeout -- a trend, not an emergency; scheduler.rs already owns the emergency path) evaluates the invariant, caches the verdict on ServerState.headroom (Mutex<Option<HeadroomReport>>), surfaces it as a new `headroom` section on GET /raft/status, and logs at warn on every tick a deficit persists. Wired in main.rs alongside scheduler/lease_renewal. Added a one-line pointer in provision.rs's own module doc so a future reader lands on the connection.")
//! @yah:handoff("DISCOVERED WORK, and the reason this took far longer than the ticket's own Cleric-tier estimate: cluster_epoch_drift caught 2 UNDETECTED problems from this session's own earlier F2 and F3 work, not just from T4. raft_status (fn raft_*, a cluster_protocol surface input) had already gained F2's lease_liveness section and now T4's headroom section -- I had never run the epoch-drift gate after F2 or F3 landed. F3's three new store.rs read accessors (tenants/tenant_placement/node_admits) moved state_epoch's surface the same way the tenant_fencing_token()/tenant_ownership() precedents did (2026-08-09/10 entries). Verdict on both, matching the R734-F5 precedent exactly (same function, same additive-JSON-on-a-GET-surface shape): NOT BREAKING. Re-recorded via `cargo run -p xtask -- cluster-epochs --write` (cluster_protocol stays 5, state_epoch stays 4) and added a full surface_rerecords entry to cluster-epochs.json dated 2026-08-15 covering all three tickets' contribution to the drift in one entry.")
//! @yah:handoff("Full verify, camp was under heavy concurrent-build load (10+ simultaneous cargo invocations across the camp against the same root workspace, confirmed via ps -- not a hang, rustc was genuinely CPU-bound, just deeply queued; several checks took 15-20 minutes to clear the lock): cargo check -p yubaba clean; cargo check -p yubaba --bin yubaba clean; cargo check -p yah-cloud clean (provision.rs doc-only edit); cargo test -p yubaba --lib = 489 passed / 0 failed (465 at F2's start -> 479 after F3+lease_renewal -> 489 after T4's 10 tests); cargo clippy -p yubaba --lib --bin yubaba: zero findings on headroom.rs or the main.rs wiring; cargo test -p xtask --test cluster_epoch_drift = 8 passed / 0 failed after re-recording (was 7/1, both axes red).")
//! @yah:verify("cargo check -p yubaba (clean)")
//! @yah:verify("cargo check -p yubaba --bin yubaba (clean)")
//! @yah:verify("cargo check -p yah-cloud (clean)")
//! @yah:verify("cargo test -p yubaba --lib = 489 passed, 0 failed, 0 ignored")
//! @yah:verify("cargo clippy -p yubaba --lib --bin yubaba: no findings on headroom.rs, scheduler.rs, lease_renewal.rs, store.rs's new accessors, or main.rs")
//! @yah:verify("cargo test -p xtask --test cluster_epoch_drift = 8 passed, 0 failed (cluster-epochs.json re-recorded, both axes NOT BREAKING, history entry added 2026-08-15)")
//! @yah:gotcha("is_spare's metric is deliberately coarse: a node counts as spare only when it holds ZERO tenants, not merely 'has room for one more'. A cluster running near capacity with every node carrying at least one tenant reports 0 spare even if collectively there is plenty of headroom to absorb a single failure via partial rebalancing -- true bin-packing-aware headroom (can the union of remaining headroom absorb node X's specific tenant set) is more accurate but was out of this Cleric ticket's scope; flag this if a future ticket finds the invariant too conservative in practice.")
//! @yah:gotcha("Nothing consumes the `headroom` GET /raft/status field yet -- no automation calls `yah cloud machine provision` off a deficit signal. That consumer (an operator runbook, or a `yah cloud auto-provision` watch command polling /raft/status) is explicitly out of this ticket's scope and unfiled; whoever wants headroom restoration to actually be automatic rather than merely visible should pick it up.")

use crate::cloud_init::{self, RenderInput};
use crate::config::MachineConfig;
use crate::provider::{Location, MachineProvider, ProjectId, ServerId, ServerSpec};
use anyhow::{Context, Result};
use std::path::Path;

/// A rendered provision payload, ready to send to a `MachineProvider`.
#[derive(Debug)]
pub struct ProvisionRequest {
    pub machine_name: String,
    pub server_type: String,
    pub location: Location,
    pub user_data: String,
    /// Provider-side SSH-key IDs to authorize for `root` at create time.
    /// Carried from `MachineConfig.ssh_keys`; empty defaults to no
    /// per-key auth (Hetzner emails a random root password we discard).
    pub ssh_keys: Vec<u64>,
}

/// Build a provision request: load the cloud-init template for the workspace and
/// substitute per-machine values. The yubaba binary is fetched on the machine
/// at first boot from `yubaba_url` and verified against `yubaba_sha256`
/// (R040-F11) — base64-embedding it would blow past Hetzner's 32 KiB cap.
///
/// `headscale_preauth_key` decides mesh membership (R330-F28). `Some` ⟺ this
/// machine is JOINING an existing mesh: the rendered cloud-init emits the
/// tailscaled install + `tailscale up --auth-key=<key>` join block. `None` ⟺
/// STANDALONE / coordinator-to-be — no mesh exists yet, so no join block is
/// emitted; the node comes up as bare yubaba and becomes the coordinator later
/// via `yah mesh bootstrap`. Membership is gated purely on this key's presence,
/// independent of `machine.hosts_operator_bridge`.
///
/// `mesh_url` is the stable Headscale coordinator URL (R040-F18). When present
/// (only meaningful alongside a preauth key), the rendered cloud-init passes
/// `--login-server <url>` to `tailscale up` so the machine joins the camp's
/// Headscale instead of Tailscale SaaS. When `None`, a joining machine uses the
/// default Tailscale SaaS coordinator.
///
/// `yubaba_channel` selects the release channel (`"stable"` or `"beta"`);
/// use [`cloud_init::DEFAULT_YUBABA_CHANNEL`] for Phase 1. containerd is
/// installed unpinned (R330-T9 — an exact apt pin matched no Debian repo).
pub fn build_request(
    workspace_root: &Path,
    machine: &MachineConfig,
    yubaba_url: String,
    yubaba_sha256: String,
    yubaba_channel: String,
    headscale_preauth_key: Option<String>,
    mesh_url: Option<String>,
    cloudflared_token: Option<String>,
    yubaba_cosign_identity_regexp: Option<String>,
) -> Result<ProvisionRequest> {
    let template = cloud_init::load_template(workspace_root)?;
    let input = RenderInput {
        machine,
        yubaba_url,
        yubaba_sha256,
        yubaba_channel,
        headscale_preauth_key,
        mesh_url,
        cloudflared_token,
        yubaba_cosign_identity_regexp,
    };
    let user_data = cloud_init::render(&template, &input)?;
    machine.validate()?;
    let location = Location::try_from(machine.location())
        .with_context(|| format!("machine '{}' has unknown location", machine.name))?;
    Ok(ProvisionRequest {
        machine_name: machine.name.clone(),
        server_type: machine.server_type().to_string(),
        location,
        user_data,
        ssh_keys: machine.ssh_keys.clone(),
    })
}

/// Execute a built request against a provider. Returns the new server ID on success.
///
/// Hostkey-fingerprint write-back lands with A8 (yah-yubaba `/identity` endpoint
/// and `MachineConfig::save` are both already in place; the missing piece is the
/// yubaba binary itself).
pub async fn execute(
    provider: &dyn MachineProvider,
    project: &ProjectId,
    req: &ProvisionRequest,
) -> Result<ServerId> {
    let spec = ServerSpec {
        name: req.machine_name.clone(),
        server_type: req.server_type.clone(),
        image: "debian-12".into(),
        location: req.location.clone(),
        ssh_keys: req.ssh_keys.clone(),
    };
    provider.create_server(project, &spec, &req.user_data).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_init;
    use crate::config::{BucketSpec, MachineConfig};

    fn sample_machine() -> MachineConfig {
        MachineConfig {
            name: "noisetable-pdx-1".into(),
            provider: "hetzner".into(),
            location: Some("pdx".into()),
            server_type: Some("cpx22".into()),
            hosts_mirrors: vec!["noisetable".into(), "yah".into()],
            mesh_tags: vec!["tag:region-pdx".into(), "tag:tier-t2".into()],
            region: None,
            zone: None,
            arch: None,
            bucket: Some(BucketSpec {
                name: "noisetable-assets-pdx-1".into(),
                public_read: false,
            }),
            vendor: None,
            nickname: None,
            legacy_hostkey_fingerprint: None,
            registration: Default::default(),
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
            allocatable: None,
            taints: vec![],
            sovereign_group: None,
            sovereign_role: None,
            ingress_floating_ip: None,
        }
    }

    fn build_req_defaults(
        dir: &std::path::Path,
        machine: &MachineConfig,
        extra_url: Option<String>,
        extra_cf: Option<String>,
    ) -> crate::provision::ProvisionRequest {
        build_request(
            dir,
            machine,
            "https://example.com/yah-yubaba".into(),
            "deadbeef".into(),
            cloud_init::DEFAULT_YUBABA_CHANNEL.into(),
            Some("KEY".into()),
            extra_url,
            extra_cf,
            None,
        )
        .unwrap()
    }

    #[test]
    fn build_request_renders_user_data_and_picks_location() {
        // A preauth key present → join block emitted, so the key ("KEY") and tags appear.
        let machine = sample_machine();
        let dir = tempfile::tempdir().unwrap();
        let req = build_req_defaults(dir.path(), &machine, None, None);
        assert_eq!(req.machine_name, "noisetable-pdx-1");
        assert_eq!(req.location, Location::Pdx);
        assert!(req.user_data.contains("https://example.com/yah-yubaba"));
        assert!(req.user_data.contains("deadbeef"));
        assert!(req.user_data.contains("KEY"));
        assert!(req.user_data.contains("tag:region-pdx,tag:tier-t2"));
    }

    #[test]
    fn build_request_with_mesh_url_adds_login_server() {
        let machine = sample_machine();
        let dir = tempfile::tempdir().unwrap();
        let req = build_req_defaults(
            dir.path(),
            &machine,
            Some("https://mesh.example.com".into()),
            None,
        );
        assert!(req
            .user_data
            .contains("--login-server https://mesh.example.com"));
    }

    #[test]
    fn build_request_standalone_omits_join_block() {
        // R330-F28: a standalone / coordinator-to-be node carries no preauth
        // key (and no mesh_url). build_request must NOT emit the tailscale-up
        // join block — the node comes up as bare yubaba.
        let machine = sample_machine();
        let dir = tempfile::tempdir().unwrap();
        let req = build_request(
            dir.path(),
            &machine,
            "https://example.com/yah-yubaba".into(),
            "deadbeef".into(),
            cloud_init::DEFAULT_YUBABA_CHANNEL.into(),
            None, // standalone: no preauth
            None, // standalone: no mesh_url
            None,
            None,
        )
        .unwrap();
        assert!(
            !req.user_data.contains("tailscale up --auth-key"),
            "standalone node must not emit the tailscale-up join block"
        );
        // Prose in the template header mentions --login-server; the real arg
        // form (`--login-server https://`) must be absent.
        assert!(!req.user_data.contains("--login-server https://"));
    }

    #[test]
    fn build_request_rejects_unknown_location() {
        let mut machine = sample_machine();
        machine.location = Some("moon".into());
        let dir = tempfile::tempdir().unwrap();
        let err = build_request(
            dir.path(),
            &machine,
            "x".into(),
            "y".into(),
            "stable".into(),
            Some("z".into()),
            None,
            None,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown location"), "unexpected: {err}");
    }

    #[test]
    fn build_request_threads_cosign_identity_into_render() {
        // R330-F21: when an identity_regexp is passed, the rendered cloud-init
        // emits the cosign verify-blob block. Without it (the existing
        // build_req_defaults helper passes None) the block stays empty.
        let machine = sample_machine();
        let dir = tempfile::tempdir().unwrap();
        let req = build_request(
            dir.path(),
            &machine,
            "https://cdn.yah.dev/yubaba/0.9.0/x86_64-unknown-linux-musl/yah-yubaba-x86_64-unknown-linux-musl.tar.gz".into(),
            "deadbeef".into(),
            cloud_init::DEFAULT_YUBABA_CHANNEL.into(),
            None,
            None,
            None,
            Some(r"^https://github\.com/yah-ai/yah/".into()),
        )
        .unwrap();
        assert!(
            req.user_data
                .contains("cosign verify-blob --certificate-identity-regexp"),
            "verify-blob runcmd missing once identity_regexp is threaded"
        );
        assert!(
            req.user_data.contains(r"^https://github\.com/yah-ai/yah/"),
            "identity_regexp value missing from rendered output"
        );
    }
}
