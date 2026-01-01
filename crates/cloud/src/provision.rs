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
/// substitute per-machine values. The warden binary is fetched on the machine
/// at first boot from `warden_url` and verified against `warden_sha256`
/// (R040-F11) — base64-embedding it would blow past Hetzner's 32 KiB cap.
///
/// `mesh_url` is the stable Headscale coordinator URL (R040-F18). When present,
/// the rendered cloud-init passes `--login-server <url>` to `tailscale up` so
/// the machine joins the camp's Headscale instead of Tailscale SaaS. When `None`,
/// the machine joins the default Tailscale SaaS coordinator.
///
/// `warden_channel` selects the release channel (`"stable"` or `"beta"`);
/// use [`cloud_init::DEFAULT_WARDEN_CHANNEL`] for Phase 1.
/// `containerd_version` is the apt version pin; use
/// [`cloud_init::DEFAULT_CONTAINERD_VERSION`] for the Phase 1 baseline.
pub fn build_request(
    workspace_root: &Path,
    machine: &MachineConfig,
    warden_url: String,
    warden_sha256: String,
    warden_channel: String,
    containerd_version: String,
    headscale_preauth_key: String,
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
        containerd_version,
        headscale_preauth_key,
        mesh_url,
        cloudflared_token,
        operator_bridge_enabled: machine.hosts_operator_bridge,
        warden_cosign_identity_regexp,
    };
    let user_data = cloud_init::render(&template, &input)?;
    let location = Location::try_from(machine.location.as_str())
        .with_context(|| format!("machine '{}' has unknown location", machine.name))?;
    Ok(ProvisionRequest {
        machine_name: machine.name.clone(),
        server_type: machine.server_type.clone(),
        location,
        user_data,
        ssh_keys: machine.ssh_keys.clone(),
    })
}

/// Execute a built request against a provider. Returns the new server ID on success.
///
/// Hostkey-fingerprint write-back lands with A8 (yah-warden `/identity` endpoint
/// and `MachineConfig::save` are both already in place; the missing piece is the
/// warden binary itself).
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
            location: "pdx".into(),
            server_type: "cpx22".into(),
            hosts_mirrors: vec!["noisetable".into(), "yah".into()],
            mesh_tags: vec!["tag:region-pdx".into(), "tag:tier-t2".into()],
            bucket: Some(BucketSpec {
                name: "noisetable-assets-pdx-1".into(),
                public_read: false,
            }),
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
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
            "https://example.com/yah-warden".into(),
            "deadbeef".into(),
            cloud_init::DEFAULT_WARDEN_CHANNEL.into(),
            cloud_init::DEFAULT_CONTAINERD_VERSION.into(),
            "KEY".into(),
            extra_url,
            extra_cf,
            None,
        )
        .unwrap()
    }

    #[test]
    fn build_request_renders_user_data_and_picks_location() {
        // Enable operator bridge so the preauth key ("KEY") and tags are emitted.
        let mut machine = sample_machine();
        machine.hosts_operator_bridge = true;
        let dir = tempfile::tempdir().unwrap();
        let req = build_req_defaults(dir.path(), &machine, None, None);
        assert_eq!(req.machine_name, "noisetable-pdx-1");
        assert_eq!(req.location, Location::Pdx);
        assert!(req.user_data.contains("https://example.com/yah-warden"));
        assert!(req.user_data.contains("deadbeef"));
        assert!(req.user_data.contains("KEY"));
        assert!(req.user_data.contains("tag:region-pdx,tag:tier-t2"));
    }

    #[test]
    fn build_request_with_mesh_url_adds_login_server() {
        let mut machine = sample_machine();
        machine.hosts_operator_bridge = true;
        let dir = tempfile::tempdir().unwrap();
        let req = build_req_defaults(dir.path(), &machine, Some("https://mesh.example.com".into()), None);
        assert!(req.user_data.contains("--login-server https://mesh.example.com"));
    }

    #[test]
    fn build_request_rejects_unknown_location() {
        let mut machine = sample_machine();
        machine.location = "moon".into();
        let dir = tempfile::tempdir().unwrap();
        let err = build_request(
            dir.path(),
            &machine,
            "x".into(),
            "y".into(),
            "stable".into(),
            "1.7.2".into(),
            "z".into(),
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
        let mut machine = sample_machine();
        machine.hosts_operator_bridge = false;
        let dir = tempfile::tempdir().unwrap();
        let req = build_request(
            dir.path(),
            &machine,
            "https://cdn.yah.dev/warden/0.9.0/x86_64-unknown-linux-musl/yah-warden-x86_64-unknown-linux-musl.tar.gz".into(),
            "deadbeef".into(),
            cloud_init::DEFAULT_WARDEN_CHANNEL.into(),
            cloud_init::DEFAULT_CONTAINERD_VERSION.into(),
            "KEY".into(),
            None,
            None,
            Some(r"^https://github\.com/anthropics/yah/".into()),
        )
        .unwrap();
        assert!(
            req.user_data
                .contains("cosign verify-blob --certificate-identity-regexp"),
            "verify-blob runcmd missing once identity_regexp is threaded"
        );
        assert!(
            req.user_data.contains(r"^https://github\.com/anthropics/yah/"),
            "identity_regexp value missing from rendered output"
        );
    }
}
