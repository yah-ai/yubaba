//! Provisioning orchestrator: config → cloud-init render → MachineProvider call.
//!
//! Decoupled from the concrete provider so the CLI passes a `&dyn MachineProvider`
//! (Hetzner in production, in-memory fakes in tests).

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
/// at first boot from `warden_url` and verified against `warden_sha256`
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
/// `warden_channel` selects the release channel (`"stable"` or `"beta"`);
/// use [`cloud_init::DEFAULT_WARDEN_CHANNEL`] for Phase 1. containerd is
/// installed unpinned (R330-T9 — an exact apt pin matched no Debian repo).
pub fn build_request(
    workspace_root: &Path,
    machine: &MachineConfig,
    warden_url: String,
    warden_sha256: String,
    warden_channel: String,
    headscale_preauth_key: Option<String>,
    mesh_url: Option<String>,
    cloudflared_token: Option<String>,
    warden_cosign_identity_regexp: Option<String>,
) -> Result<ProvisionRequest> {
    let template = cloud_init::load_template(workspace_root)?;
    let input = RenderInput {
        machine,
        warden_url,
        warden_sha256,
        warden_channel,
        headscale_preauth_key,
        mesh_url,
        cloudflared_token,
        warden_cosign_identity_regexp,
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
            bucket: Some(BucketSpec {
                name: "noisetable-assets-pdx-1".into(),
                public_read: false,
            }),
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
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
            cloud_init::DEFAULT_WARDEN_CHANNEL.into(),
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
            cloud_init::DEFAULT_WARDEN_CHANNEL.into(),
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
            cloud_init::DEFAULT_WARDEN_CHANNEL.into(),
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
