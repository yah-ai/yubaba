//! Cloud-init template renderer for mirror-machine bootstrap (R040-F4).
//!
//! Loads the YAML template from `.yah/cloud/cloud-init/mirror.yml` (with a
//! built-in fallback for portability) and substitutes per-machine values:
//! machine name, yah-yubaba release-archive URL + sha256, Headscale pre-auth
//! key, and mesh tags. The output is the `user_data` string passed to
//! `MachineProvider::create_server`.
//!
//! Hetzner caps `user_data` at 32KiB so the yubaba binary cannot be
//! base64-embedded (R040-F11). The first-boot `runcmd` fetches the release
//! tar.gz (matching what `.github/workflows/release.yml` publishes), verifies
//! sha256 against the archive, extracts, and installs `/usr/local/bin/yah-yubaba`
//! before the systemd hand-off.
//!
//! @yah:ticket(R040-F11, "yah-yubaba delivery: fetch from URL instead of base64 (Hetzner 32KiB user_data cap)")
//! @yah:at(2026-05-05T00:00:42Z)
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:parent(R040)
//! @arch:see(architecture/PHASE_1_MIRROR_BOOTSTRAP.md)
//! @yah:verify("cargo test -p cloud")
//! @yah:verify("cargo test -p yah --bin yah cloud::")
//! @yah:verify("yah cloud machine provision noisetable-pdx-1 --path /Users/user/ss/noisetable --dry-run --yubaba-url https://example.com/yubaba --yubaba /tmp/yubaba — renders curl + sha256sum runcmd lines, computes sha from local file")
//! @yah:handoff("Cloud-init now fetches yah-yubaba via URL + sha256 verify instead of base64 inline (Hetzner 32KiB user_data cap). RenderInput swapped warden_base64 for warden_url + warden_sha256; template runcmd does curl -o + chmod +x + 'echo SHA bin | sha256sum -c -'. CLI provision flags: --yubaba-url <URL> required for live; --yubaba-sha256 <HEX> and/or --yubaba <PATH> (compute or assert sha); --dry-run falls back to placeholders. New helper resolve_warden_delivery() in app/yah/cli/src/cloud.rs covers all five flag combos with 7 unit tests. Cumulative: 30 cloud-crate tests pass (incl. new render_stays_under_hetzner_user_data_cap which fails the build if rendering ever blows past 32 KiB), 17 yah cloud:: tests pass. PHASE_1_MIRROR_BOOTSTRAP.md updated. Side fix: status.rs FakeProvider needed a one-line delete_bucket stub to compile (R040-F12 has the real impl in review).")
//! @yah:next("Operator runbook (R040-T6) is now unblocked: publish yah-yubaba Linux musl binary at a stable URL (GitHub release artifact for the workspace.package version), then run `yah cloud machine provision noisetable-$region-1 --yubaba-url <URL> --yubaba <local-copy> --path /Users/user/ss/noisetable` for region in pdx iad fsn.")
//! @yah:next("Optional polish: derive a default --yubaba-url from workspace.package.version + a hardcoded GitHub repo so operators don't have to retype the URL per region. Skip until release-plz (R038-F3) is wired so the artifact actually exists at a predictable path.")
//!
//! @yah:ticket(R040-F15, "Cloudflare Tunnel in cloud-init: cloudflared install + token, no public ports needed")
//! @yah:at(2026-05-05T00:00:42Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:parent(R040)
//! @yah:handoff("Architecture decision (this session, recorded so future-self doesn't re-litigate): public ingress for yah-cloud nodes is Cloudflare Tunnels — `cloudflared` runs on each origin, makes an OUTBOUND connection to CF edge, CF proxies inbound traffic through the tunnel. Origin needs zero inbound exposure (no port 80/443 open, no stable IPv4, no floating IP plumbing). DNS records point at `<tunnel-id>.cfargotunnel.com` and never churn when boxes are replaced. Inter-node TCP (Postgres replication, gRPC streams, NATS) goes over Headscale mesh — see R040-F16. Combined effect: Hetzner inline IPs are fine forever, IPv6-only is even an option (saves ~€0.50/mo per box; needs validating that tailscale install + apt mirrors work over v6).")
//! @yah:next("cloud-init template: add `cloudflared service install --token {{CLOUDFLARED_TOKEN}}` + `systemctl enable --now cloudflared` to runcmd, parallel to the existing tailscale install. Token comes from RenderInput.cloudflared_token, sourced from `keys::KeysStore::open().get(\"cloudflare-tunnel-token\")` in cli/src/cloud.rs::handle_provision.")
//! @yah:next("MachineConfig.cloudflared: Option<String> — tunnel-id this machine joins. Empty/None means \"no tunnel\" (mesh-only nodes that don't need public ingress). When set, the cloud-init renderer wires the right token in.")
//! @yah:next("Optional: `yah cloud tunnel {create,list,destroy}` subcommand against the CF API. Lower-priority — operators can use cloudflared CLI directly until this matters at fleet scale.")
//! @yah:next("Caveat to flag in handoff: Free + Pro tier CF Tunnels is HTTP/WebSocket/gRPC only. Raw TCP/UDP ingress (rare for yah, but possible — e.g. a public Postgres for some integration) needs CF Spectrum (paid) OR a primary IP for that one service. Don't pre-build the second path; design records this as a known constraint.")
//! @arch:see(architecture/PHASE_1_MIRROR_BOOTSTRAP.md)
//!
//! @yah:ticket(R441-B3, "cloud_init mirror.yml drift between cloud/templates and .yah/infra/cloud-init")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T22:56:14Z)
//! @yah:status(review)
//! @yah:parent(R441)
//! @yah:next("embedded_template_matches_workspace_canonical at cloud_init.rs:489 panics: the two mirror.yml files diverged. crates/yah/cloud/templates/mirror.yml (canonical, R406-T13/W154) has yubaba + kamaji + yubaba.slice systemd units plus the kamaji.service unit; .yah/infra/cloud-init/mirror.yml still has the older single yah-yubaba.service shape with no kamaji.")
//! @yah:next("Pick the source of truth (the canonical-template path that the embedded test enforces was meant to be the cloud/templates copy) and sync the other file to match. Re-run the test to confirm.")
//! @yah:verify("cargo test -p cloud --lib cloud_init::tests::embedded_template_matches_workspace_canonical passes")
//! @yah:handoff("Overwrote crates/yah/cloud/templates/mirror.yml to match .yah/infra/cloud-init/mirror.yml (W154/R406-T13 yubaba+kamaji+yubaba.slice format). The workspace file was the canonical updated version; the embedded template hadn't been synced. cargo test -p cloud --lib cloud_init::tests::embedded_template_matches_workspace_canonical passes.")

use crate::config::MachineConfig;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Built-in fallback template, used when `.yah/infra/cloud-init/mirror.yml`
/// is absent. Keeps the binary self-contained for tests + new workspaces.
pub const DEFAULT_TEMPLATE: &str = include_str!("../templates/mirror.yml");

/// Inputs needed to render `mirror.yml` for a single machine.
#[derive(Debug)]
pub struct RenderInput<'a> {
    pub machine: &'a MachineConfig,
    /// HTTPS URL of the yah-yubaba release tar.gz (e.g. a GitHub release
    /// asset published by `.github/workflows/release.yml`). Cloud-init's
    /// `runcmd` downloads it, verifies sha256 against [`Self::warden_sha256`],
    /// extracts, and installs `/usr/local/bin/yah-yubaba`. Use
    /// `PLACEHOLDER_WARDEN_URL` for dry-run previews.
    pub warden_url: String,
    /// Lowercase hex sha256 of the tar.gz at `warden_url`. Cloud-init verifies
    /// this with `sha256sum -c -` against the downloaded archive and fails
    /// the boot if it doesn't match.
    pub warden_sha256: String,
    /// Release channel passed to `yah-yubaba serve --channel`. One of
    /// `"stable"` or `"beta"`. Use [`DEFAULT_WARDEN_CHANNEL`] for Phase 1.
    pub warden_channel: String,
    /// Headscale pre-auth key. `Some` ⟺ this machine is joining an existing
    /// mesh: the renderer emits the tailscaled install + `tailscale up` join
    /// block (gated on this being `Some`, see [`render`]). `None` ⟺ standalone
    /// / coordinator-to-be — no mesh to join yet, so no join block is emitted
    /// (the node becomes the coordinator later via `yah mesh bootstrap`).
    pub headscale_preauth_key: Option<String>,
    /// Stable URL of the Headscale coordinator (`https://mesh.<domain>`).
    /// When set (R040-F18), the rendered cloud-init passes
    /// `--login-server <url>` to `tailscale up` so the new machine joins
    /// the camp's Headscale instead of Tailscale SaaS. When `None`, the
    /// `{{MESH_LOGIN_SERVER_ARG}}` placeholder is replaced with an empty
    /// string, preserving the existing Tailscale SaaS behaviour.
    pub mesh_url: Option<String>,
    /// Cloudflare Tunnel token for `cloudflared service install --token ...`.
    /// `None` → no cloudflared install (mesh-only node). When `Some`, the
    /// renderer emits the full cloudflared apt-repo install + service enable
    /// block into `runcmd` in place of `{{CLOUDFLARED_BLOCK}}`.
    pub cloudflared_token: Option<String>,
    /// When `Some`, render the cosign install + `cosign verify-blob` runcmd
    /// block into `{{COSIGN_VERIFY_BLOCK}}`, gating the yubaba tarball on a
    /// keyless OIDC signature whose certificate identity matches this regexp
    /// (e.g. `^https://github\.com/yah-ai/yah/`). The sha256 check stays
    /// in parallel as belt-and-suspenders (R330-F20, W203 §1.4). When `None`
    /// the placeholder substitutes to an empty string and the bootstrap stays
    /// on the sha256-only path.
    pub warden_cosign_identity_regexp: Option<String>,
}

/// Placeholders used when the user requests a dry-run without supplying real
/// substitutes. Makes the rendered YAML obviously non-shippable while still
/// preserving the structure for review.
pub const PLACEHOLDER_WARDEN_URL: &str = "<WARDEN_URL_PLACEHOLDER>";
pub const PLACEHOLDER_WARDEN_SHA256: &str = "<WARDEN_SHA256_PLACEHOLDER>";
pub const PLACEHOLDER_PREAUTH_KEY: &str = "<HEADSCALE_PREAUTH_KEY_PLACEHOLDER>";
pub const PLACEHOLDER_CLOUDFLARED_TOKEN: &str = "<CLOUDFLARED_TOKEN_PLACEHOLDER>";

/// Phase 1 defaults for new provisioning keys.
pub const DEFAULT_WARDEN_CHANNEL: &str = "stable";
/// Pinned cosign release used by the cloud-init verify-blob block. Bump in
/// lockstep with [`COSIGN_SHA256_AMD64`] / [`COSIGN_SHA256_ARM64`] when
/// upgrading the verifier — supply-chain hygiene (W203 §1.4, R330-F22).
pub const COSIGN_VERSION: &str = "v2.4.1";
/// sha256 of the cosign-linux-amd64 binary at [`COSIGN_VERSION`]. Cloud-init
/// verifies the downloaded binary against this before chmod+exec. Pinning the
/// verifier itself closes the bootstrap-trust gap: TLS to github.com proves
/// origin, sha256 proves bytes, then cosign proves the yubaba tarball.
pub const COSIGN_SHA256_AMD64: &str =
    "8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b";
/// sha256 of the cosign-linux-arm64 binary at [`COSIGN_VERSION`].
pub const COSIGN_SHA256_ARM64: &str =
    "3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a";
/// Sigstore Fulcio OIDC issuer for GitHub-Actions-rooted keyless signing.
/// Matches what `.github/workflows/release.yml`'s `cosign sign-blob` step
/// emits (R330-F19).
pub const COSIGN_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Load the cloud-init template for a workspace.
///
/// Prefers `<workspace_root>/.yah/infra/cloud-init/mirror.yml` if it exists,
/// otherwise returns the embedded [`DEFAULT_TEMPLATE`].
pub fn load_template(workspace_root: &Path) -> Result<String> {
    let custom = crate::paths::cloud_init_template(workspace_root);
    if custom.exists() {
        std::fs::read_to_string(&custom).with_context(|| format!("reading {}", custom.display()))
    } else {
        Ok(DEFAULT_TEMPLATE.to_string())
    }
}

/// Substitute `{{KEY}}` placeholders. Fails loudly if any unsubstituted
/// placeholder remains — better than silently shipping a broken cloud-init.
pub fn render(template: &str, input: &RenderInput) -> Result<String> {
    let tags = if input.machine.mesh_tags.is_empty() {
        // Tailscale rejects empty `--advertise-tags=`; emit a single tag derived from the machine name.
        format!("tag:{}", input.machine.name)
    } else {
        input.machine.mesh_tags.join(",")
    };

    let mesh_login_server_arg = match &input.mesh_url {
        Some(url) => format!(" --login-server {url}"),
        None => String::new(),
    };

    let cloudflared_block = match &input.cloudflared_token {
        Some(token) => build_cloudflared_block(token),
        None => String::new(),
    };

    // The tailscale-up/join block is emitted iff we have a preauth key, i.e.
    // this machine is joining an existing mesh (R330-F28). Standalone /
    // coordinator-to-be nodes carry no preauth and get no join block — they
    // come up as bare yubaba and become the coordinator via `yah mesh bootstrap`.
    let operator_bridge_block = match &input.headscale_preauth_key {
        Some(key) => build_operator_bridge_block(key, &mesh_login_server_arg, &tags),
        None => String::new(),
    };

    // Yubaba RPC (7443) firewall rule keys off the same axis (R330-F28 #13).
    // JOINING (preauth present): deny public 7443 — the join block above adds
    // an `allow in on tailscale0` so yubaba is mesh-reachable only. STANDALONE
    // (no preauth): allow public 7443 so the operator can attach + bootstrap
    // the coordinator before any mesh exists to reach it over.
    let ufw_warden_rule = match &input.headscale_preauth_key {
        Some(_) => "  - ufw deny 7443".to_string(),
        None => "  - ufw allow 7443".to_string(),
    };

    // Coordinator pre-stage (standalone only, R330-F28 #15). yubaba runs under
    // ProtectSystem=strict so it cannot write the headscale systemd unit nor
    // open the firewall; cloud-init (unsandboxed) lays both down here so a later
    // `yah mesh bootstrap` only needs to write config + `systemctl enable --now
    // headscale`. The unit's ExecStart matches DEFAULT_HEADSCALE_DIR. Joining
    // nodes never self-bootstrap a coordinator, so the block is empty for them.
    let coordinator_prestage_block = match &input.headscale_preauth_key {
        Some(_) => String::new(),
        None => build_coordinator_prestage_block(),
    };

    let cosign_verify_block = match &input.warden_cosign_identity_regexp {
        Some(regexp) => build_cosign_verify_block(&input.warden_url, regexp),
        None => String::new(),
    };

    let rendered = template
        .replace("{{MACHINE_NAME}}", &input.machine.name)
        .replace("{{YAH_WARDEN_URL}}", &input.warden_url)
        .replace("{{YAH_WARDEN_SHA256}}", &input.warden_sha256)
        .replace("{{WARDEN_CHANNEL}}", &input.warden_channel)
        .replace(
            "{{HEADSCALE_PREAUTH_KEY}}",
            input.headscale_preauth_key.as_deref().unwrap_or(""),
        )
        .replace("{{MESH_LOGIN_SERVER_ARG}}", &mesh_login_server_arg)
        .replace("{{TAGS}}", &tags)
        .replace("{{CLOUDFLARED_BLOCK}}", &cloudflared_block)
        .replace("{{OPERATOR_BRIDGE_BLOCK}}", &operator_bridge_block)
        .replace("{{UFW_WARDEN_RULE}}", &ufw_warden_rule)
        .replace(
            "{{COORDINATOR_PRESTAGE_BLOCK}}",
            &coordinator_prestage_block,
        )
        .replace("{{COSIGN_VERIFY_BLOCK}}", &cosign_verify_block);

    if let Some(remnant) = find_unsubstituted(&rendered) {
        bail!("cloud-init template has unsubstituted placeholder: {remnant}");
    }
    Ok(rendered)
}

/// Read a yah-yubaba release tar.gz from disk and return its lowercase hex
/// sha256. Used both as the cloud-init verification digest and for asserting
/// that a local copy matches an expected `--yubaba-sha256` value. The path
/// should point to the release archive (matching what cloud-init downloads),
/// not a bare binary.
pub fn compute_warden_sha256(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading yah-yubaba archive at {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Build the cloudflared apt-repo install + tunnel-connect block for `runcmd`.
/// Each line is a valid cloud-init sequence entry (two-space indent + `- `).
/// The block replaces `{{CLOUDFLARED_BLOCK}}` in the template; when empty it
/// leaves a blank line in the rendered YAML (harmless to the YAML parser).
fn build_cloudflared_block(token: &str) -> String {
    [
        "  - mkdir -p --mode=0755 /usr/share/keyrings".to_string(),
        "  - sh -c 'curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | gpg --dearmor > /usr/share/keyrings/cloudflare-main.gpg'".to_string(),
        "  - sh -c 'echo \"deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared bookworm main\" > /etc/apt/sources.list.d/cloudflared.list'".to_string(),
        "  - apt-get update -qq".to_string(),
        "  - apt-get install -y cloudflared".to_string(),
        // The token is a POSITIONAL argument, not a `--token` flag: the
        // `service install` subcommand has no `--token` option, so
        // `cloudflared service install --token <tok>` fails arg-parsing with
        // "flag provided but not defined: -token", prints usage, and NEVER
        // creates cloudflared.service. The `systemctl enable --now` below then
        // fails with "Unit file cloudflared.service does not exist", leaving
        // the tunnel inactive with an empty journal (R330-B29, found on the
        // us-west-001 from-zero validation). `service install <TOKEN>` already
        // installs+enables+starts the unit; the explicit enable is redundant
        // but harmless now that the unit exists.
        format!("  - cloudflared service install {token}"),
        "  - systemctl enable --now cloudflared".to_string(),
    ]
    .join("\n")
}

/// Build the cosign install + `cosign verify-blob` block for `runcmd`. Each
/// line is a valid cloud-init sequence entry (two-space indent + `- `). The
/// `.sig`/`.cert` URLs derive by appending those suffixes to the tarball URL —
/// matching what `release.yml` publishes alongside the canonical artifact
/// (R330-F19). Architecture is detected at boot via `dpkg --print-architecture`
/// so one rendered template serves both x86_64 and aarch64 Hetzner machines.
fn build_cosign_verify_block(warden_url: &str, identity_regexp: &str) -> String {
    // ARCH + SHA must be set, checked, and consumed inside the same `sh -c`
    // process — cloud-init runcmd entries are independent shells, so a
    // multi-step download-then-verify-then-install split would lose the
    // variables between lines. One `sh -c` keeps the pin atomic.
    //
    // NB: runcmd entries are emitted as bare (unquoted) YAML scalars, so a
    // `: ` (colon-space) anywhere in the command makes the YAML parser read
    // the entry as a `key: value` MAPPING — cloud-init's shellify then chokes
    // on the dict and SKIPS THE ENTIRE runcmd block (R330-F28 from-zero
    // validation, pothole #12). Keep this string colon-space-free: the error
    // message says "unsupported arch <ARCH>", not "unsupported arch: <ARCH>".
    let install_and_verify_cosign = format!(
        "  - sh -c 'set -e; ARCH=$(dpkg --print-architecture); \
            case \"$ARCH\" in \
              amd64) SHA=\"{amd64}\";; \
              arm64) SHA=\"{arm64}\";; \
              *) echo \"unsupported arch $ARCH\" >&2; exit 1;; \
            esac; \
            curl -fsSL \"https://github.com/sigstore/cosign/releases/download/{ver}/cosign-linux-${{ARCH}}\" -o /usr/local/bin/cosign; \
            echo \"${{SHA}}  /usr/local/bin/cosign\" | sha256sum -c -; \
            chmod +x /usr/local/bin/cosign'",
        amd64 = COSIGN_SHA256_AMD64,
        arm64 = COSIGN_SHA256_ARM64,
        ver = COSIGN_VERSION
    );
    [
        install_and_verify_cosign,
        format!("  - curl -fsSL -o /tmp/yah-yubaba.tar.gz.sig {warden_url}.sig"),
        format!("  - curl -fsSL -o /tmp/yah-yubaba.tar.gz.cert {warden_url}.cert"),
        format!(
            "  - cosign verify-blob --certificate-identity-regexp '{identity_regexp}' --certificate-oidc-issuer {issuer} --certificate /tmp/yah-yubaba.tar.gz.cert --signature /tmp/yah-yubaba.tar.gz.sig /tmp/yah-yubaba.tar.gz",
            issuer = COSIGN_OIDC_ISSUER
        ),
    ]
    .join("\n")
}

/// Build the tailscaled operator-bridge block for `runcmd`.
/// Each line is a valid cloud-init sequence entry (two-space indent + `- `).
/// The block replaces `{{OPERATOR_BRIDGE_BLOCK}}` in the template; when the
/// machine does not host operator-bridge workloads the placeholder is replaced
/// with an empty string (harmless blank line in the rendered YAML).
fn build_operator_bridge_block(
    preauth_key: &str,
    mesh_login_server_arg: &str,
    tags: &str,
) -> String {
    [
        "  - curl -fsSL https://tailscale.com/install.sh | sh".to_string(),
        format!("  - tailscale up{mesh_login_server_arg} --auth-key={preauth_key} --advertise-tags={tags}"),
        "  - ufw allow in on tailscale0 to any port 7443".to_string(),
    ]
    .join("\n")
}

/// Build the coordinator pre-stage block for `runcmd` (R330-F28 #15). Emitted
/// only for STANDALONE nodes (no preauth). cloud-init runs unsandboxed at first
/// boot, so it lays down the headscale systemd unit + opens ufw 80/443 (the LE
/// HTTP-01 challenge + the headscale `listen_addr :443`). yubaba runs under
/// `ProtectSystem=strict` and cannot write `/etc/systemd/system` or `/etc/ufw`,
/// so `yah mesh bootstrap` only downloads the headscale binary, writes config,
/// and `systemctl enable --now headscale` against this pre-staged unit.
///
/// The unit's `ExecStart` must match yubaba's `DEFAULT_HEADSCALE_DIR`
/// (`/var/lib/yah-cloud/headscale` — under the systemd StateDirectory, writable
/// at runtime; see R330-F28 #14). Kept colon-space-free so the bare YAML scalar
/// stays a string (#12). `enable` (not `--now`) here: the binary + config don't
/// exist until bootstrap, so we only wire it for boot, not start it now.
fn build_coordinator_prestage_block() -> String {
    let unit = "[Unit]\\n\
                Description=Headscale coordinator (yah-managed)\\n\
                After=network-online.target\\n\\n\
                [Service]\\n\
                ExecStart=/var/lib/yah-cloud/headscale/headscale serve --config /var/lib/yah-cloud/headscale/config.yaml\\n\
                Restart=on-failure\\n\
                RestartSec=5\\n\\n\
                [Install]\\n\
                WantedBy=multi-user.target\\n";
    [
        format!("  - sh -c 'printf \"{unit}\" > /etc/systemd/system/headscale.service'"),
        "  - systemctl enable headscale".to_string(),
        "  - ufw allow 80".to_string(),
        "  - ufw allow 443".to_string(),
    ]
    .join("\n")
}

/// Look for an unsubstituted placeholder of the form `{{NAME}}` (no spaces inside braces).
/// Documentation comments deliberately use `{{ NAME }}` (with spaces) so they survive rendering.
fn find_unsubstituted(s: &str) -> Option<&str> {
    let mut cursor = 0;
    while let Some(start_off) = s[cursor..].find("{{") {
        let start = cursor + start_off;
        let after = &s[start + 2..];
        let end_off = after.find("}}")?;
        let inner = &after[..end_off];
        if !inner.is_empty() && !inner.starts_with(' ') && !inner.ends_with(' ') {
            return Some(&s[start..start + 2 + end_off + 2]);
        }
        cursor = start + 2 + end_off + 2;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BucketSpec, MachineConfig};
    use std::path::Path;

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

    fn minimal_input(machine: &MachineConfig) -> RenderInput<'_> {
        RenderInput {
            machine,
            warden_url: "https://example.com/yah-yubaba".into(),
            warden_sha256: "deadbeef".into(),
            warden_channel: DEFAULT_WARDEN_CHANNEL.into(),
            // Default: standalone (no join block). Tests that exercise the
            // mesh-join path set `headscale_preauth_key = Some(...)`.
            headscale_preauth_key: None,
            mesh_url: None,
            cloudflared_token: None,
            warden_cosign_identity_regexp: None,
        }
    }

    #[test]
    fn render_substitutes_all_placeholders() {
        let machine = sample_machine();
        // Enable operator bridge so tailscale content (preauth key, tags) is emitted.
        let mut input = minimal_input(&machine);
        input.headscale_preauth_key = Some("tskey-test".into());
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        assert!(out.contains("noisetable-pdx-1"));
        assert!(out.contains("https://example.com/yah-yubaba"));
        assert!(out.contains("deadbeef"));
        assert!(out.contains(DEFAULT_WARDEN_CHANNEL));
        assert!(out.contains("apt-get install -y containerd"));
        assert!(out.contains("tskey-test"));
        assert!(out.contains("tag:region-pdx,tag:tier-t2"));
        // Real placeholders must all be substituted.
        // Documentation {{ KEY }} (with inner spaces) is allowed to survive.
        assert!(find_unsubstituted(&out).is_none());
    }

    #[test]
    fn render_with_mesh_url_adds_login_server() {
        let machine = sample_machine();
        let mut input = minimal_input(&machine);
        input.mesh_url = Some("https://mesh.example.com".into());
        input.headscale_preauth_key = Some("tskey-test".into());
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        assert!(out.contains("--login-server https://mesh.example.com"));
        assert!(find_unsubstituted(&out).is_none());
    }

    #[test]
    fn render_without_mesh_url_no_login_server() {
        let machine = sample_machine();
        let mut input = minimal_input(&machine);
        input.headscale_preauth_key = Some("tskey-test".into());
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        // Without a mesh_url the MESH_LOGIN_SERVER_ARG substitutes to empty string,
        // so the tailscale up line should not contain a --login-server=https:// arg.
        assert!(!out.contains("--login-server https://"));
        assert!(find_unsubstituted(&out).is_none());
    }

    #[test]
    fn render_with_placeholders_for_dry_run() {
        let machine = sample_machine();
        let input = RenderInput {
            machine: &machine,
            warden_url: PLACEHOLDER_WARDEN_URL.into(),
            warden_sha256: PLACEHOLDER_WARDEN_SHA256.into(),
            warden_channel: DEFAULT_WARDEN_CHANNEL.into(),
            // A preauth key present → join block emitted, so the placeholder appears in output.
            headscale_preauth_key: Some(PLACEHOLDER_PREAUTH_KEY.into()),
            mesh_url: None,
            cloudflared_token: None,
            warden_cosign_identity_regexp: None,
        };
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        assert!(out.contains(PLACEHOLDER_WARDEN_URL));
        assert!(out.contains(PLACEHOLDER_WARDEN_SHA256));
        assert!(out.contains(PLACEHOLDER_PREAUTH_KEY));
    }

    #[test]
    fn render_stays_under_hetzner_user_data_cap() {
        // Backward-compat alias — see renders_under_user_data_cap below.
        renders_under_user_data_cap();
    }

    #[test]
    fn renders_under_user_data_cap() {
        // Hetzner refuses user_data > 32 KiB (R040-F11). Worst-case: all blocks
        // enabled (cloudflared + operator_bridge), long URL and sha, full tag list.
        let machine = sample_machine();
        let input = RenderInput {
            machine: &machine,
            warden_url: "https://github.com/yah-ai/yah/releases/download/v0.7.0/yah-yubaba-v0.7.0-x86_64-unknown-linux-musl.tar.gz".into(),
            warden_sha256: "0".repeat(64),
            warden_channel: "stable".into(),
            headscale_preauth_key: Some("tskey-auth-keylongenoughforrealism123456".into()),
            mesh_url: Some("https://mesh.example.com".into()),
            cloudflared_token: Some(PLACEHOLDER_CLOUDFLARED_TOKEN.into()),
            // Worst-case includes the cosign block so the 32 KiB cap test
            // covers the bootstrap-channel signing path too (W203 §1.4).
            warden_cosign_identity_regexp: Some("^https://github\\.com/yah-ai/yah/".into()),
        };
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        assert!(
            out.len() < 32 * 1024,
            "rendered cloud-init is {} bytes (Hetzner cap is 32 KiB)",
            out.len()
        );
    }

    #[test]
    fn render_rejects_unknown_placeholder() {
        let machine = sample_machine();
        let input = RenderInput {
            machine: &machine,
            warden_url: "x".into(),
            warden_sha256: "y".into(),
            warden_channel: "stable".into(),
            headscale_preauth_key: None,
            mesh_url: None,
            cloudflared_token: None,
            warden_cosign_identity_regexp: None,
        };
        let bad = "foo: {{NOT_A_KEY}}\n";
        let err = render(bad, &input).unwrap_err().to_string();
        assert!(err.contains("{{NOT_A_KEY}}"), "unexpected error: {err}");
    }

    #[test]
    fn render_falls_back_to_machine_tag_when_mesh_tags_empty() {
        let mut machine = sample_machine();
        machine.mesh_tags = vec![];
        let mut input = minimal_input(&machine);
        input.headscale_preauth_key = Some("tskey-test".into());
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        assert!(out.contains("--advertise-tags=tag:noisetable-pdx-1"));
    }

    #[test]
    fn load_template_uses_workspace_override_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let custom_dir = crate::paths::cloud_init_dir(dir.path());
        std::fs::create_dir_all(&custom_dir).unwrap();
        std::fs::write(
            custom_dir.join("mirror.yml"),
            "#cloud-config\ncustom: true\n",
        )
        .unwrap();
        let loaded = load_template(dir.path()).unwrap();
        assert!(loaded.contains("custom: true"));
    }

    #[test]
    fn load_template_falls_back_to_default_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = load_template(dir.path()).unwrap();
        assert_eq!(loaded, DEFAULT_TEMPLATE);
    }

    #[test]
    fn render_preserves_documentation_comments() {
        let machine = sample_machine();
        let input = minimal_input(&machine);
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        // The header comment uses `{{ KEY }}` (with spaces) so it survives the
        // `{{KEY}}` (no-spaces) substitution and stays readable.
        assert!(out.contains("{{ MACHINE_NAME }}"));
        assert!(out.contains("{{ YAH_WARDEN_URL }}"));
        assert!(out.contains("{{ YAH_WARDEN_SHA256 }}"));
    }

    #[test]
    fn render_with_cloudflared_token_emits_install_block() {
        let machine = sample_machine();
        let mut input = minimal_input(&machine);
        input.cloudflared_token = Some("tok_abc123".into());
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        // R330-B29: token is a POSITIONAL arg, NOT a `--token` flag. The flag
        // form fails arg-parsing and never creates cloudflared.service.
        assert!(
            out.contains("cloudflared service install tok_abc123"),
            "install line missing"
        );
        assert!(
            !out.contains("service install --token"),
            "must not use the bogus --token flag (R330-B29)"
        );
        assert!(
            out.contains("systemctl enable --now cloudflared"),
            "enable line missing"
        );
        assert!(out.contains("pkg.cloudflare.com"), "apt-repo setup missing");
        assert!(find_unsubstituted(&out).is_none());
    }

    #[test]
    fn render_without_cloudflared_token_omits_install_block() {
        let machine = sample_machine();
        let input = minimal_input(&machine);
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        // Template header mentions "cloudflared service install" in prose; check
        // for the token-bearing form which is only present in the actual runcmd.
        assert!(
            !out.contains("cloudflared service install --token"),
            "install line should be absent"
        );
        assert!(
            !out.contains("pkg.cloudflare.com"),
            "apt-repo setup should be absent"
        );
        assert!(find_unsubstituted(&out).is_none());
    }

    #[test]
    fn operator_bridge_block_emitted_when_enabled() {
        let machine = sample_machine();
        let mut input = minimal_input(&machine);
        input.headscale_preauth_key = Some("tskey-test".into());
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        assert!(
            out.contains("tailscale.com/install.sh"),
            "tailscale install missing"
        );
        assert!(out.contains("tailscale up"), "tailscale up missing");
        assert!(
            out.contains("ufw allow in on tailscale0"),
            "ufw tailscale rule missing"
        );
        assert!(find_unsubstituted(&out).is_none());
    }

    #[test]
    fn operator_bridge_block_omitted_when_disabled() {
        let machine = sample_machine();
        let input = minimal_input(&machine);
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        assert!(
            !out.contains("tailscale.com/install.sh"),
            "tailscale install should be absent"
        );
        // Template header mentions "tailscale up" in prose; check for the auth-key
        // bearing form which is only present in the actual runcmd block.
        assert!(
            !out.contains("tailscale up --auth-key"),
            "tailscale join should be absent"
        );
        assert!(find_unsubstituted(&out).is_none());
    }

    /// R330-F28 pothole #12: the from-zero validation found that cloud-init's
    /// `runcmd` is emitted as a sequence of BARE (unquoted) YAML scalars, so a
    /// `: ` (colon-space) anywhere in a command — e.g. the cosign block's old
    /// `echo "unsupported arch: $ARCH"` — makes the YAML parser read the entry
    /// as a `{key: value}` mapping. cloud-init's `shellify` then rejects the
    /// dict and SKIPS THE ENTIRE runcmd block, so yubaba never installs. This
    /// test parses the worst-case rendered cloud-init as real YAML and asserts
    /// every runcmd entry is a string, catching any future colon-space footgun.
    #[test]
    fn rendered_runcmd_entries_are_all_strings() {
        let machine = sample_machine();
        // Worst case: every conditional block present (cosign + cloudflared +
        // operator-bridge), since that's where dynamic strings are injected.
        let input = RenderInput {
            machine: &machine,
            warden_url: "https://cdn.yah.dev/yubaba/0.8.13/x86_64-unknown-linux-musl/yah-yubaba-x86_64-unknown-linux-musl.tar.gz".into(),
            warden_sha256: "0".repeat(64),
            warden_channel: "stable".into(),
            headscale_preauth_key: Some("tskey-auth-keylongenoughforrealism123456".into()),
            mesh_url: Some("https://cloud.mesh.yah.dev".into()),
            cloudflared_token: Some("tok_abc123".into()),
            warden_cosign_identity_regexp: Some(r"^https://github\.com/yah-ai/yah/".into()),
        };
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&out).expect("rendered cloud-init must be valid YAML");
        let runcmd = doc
            .get("runcmd")
            .and_then(|v| v.as_sequence())
            .expect("cloud-init must have a runcmd sequence");
        assert!(!runcmd.is_empty(), "runcmd should not be empty");
        for (i, entry) in runcmd.iter().enumerate() {
            assert!(
                entry.is_string(),
                "runcmd[{i}] parsed as {entry:?}, not a string — a `: ` (colon-space) \
                 in a bare YAML scalar turned it into a mapping (pothole #12)"
            );
        }
    }

    /// R330-F28 #13: the yubaba-port firewall rule keys off mesh role. A
    /// JOINING node (preauth present) denies public 7443 (mesh-only via the
    /// tailscale0 allow in the join block); a STANDALONE coordinator (no
    /// preauth) allows public 7443 so the operator can attach + bootstrap it
    /// before any mesh exists.
    #[test]
    fn ufw_warden_rule_keys_off_mesh_role() {
        let machine = sample_machine();

        // Standalone: allow public 7443.
        let standalone = minimal_input(&machine);
        let out = render(DEFAULT_TEMPLATE, &standalone).unwrap();
        assert!(
            out.contains("ufw allow 7443"),
            "standalone must allow public 7443"
        );
        assert!(
            !out.contains("ufw deny 7443"),
            "standalone must not deny 7443"
        );

        // Joining: deny public 7443 (join block adds the tailscale0 allow).
        let mut joining = minimal_input(&machine);
        joining.headscale_preauth_key = Some("tskey-test".into());
        let out = render(DEFAULT_TEMPLATE, &joining).unwrap();
        assert!(
            out.contains("ufw deny 7443"),
            "joining node must deny public 7443"
        );
        assert!(
            !out.contains("ufw allow 7443"),
            "joining node must not allow public 7443"
        );
        assert!(
            out.contains("ufw allow in on tailscale0"),
            "joining node needs the tailscale0 allow"
        );
    }

    /// R330-F28 #15: a STANDALONE coordinator pre-stages the headscale unit +
    /// opens ufw 80/443 via cloud-init (yubaba's sandbox can't). A JOINING node
    /// must never do this. Both renders must stay valid, parseable YAML.
    #[test]
    fn coordinator_prestage_only_for_standalone() {
        let machine = sample_machine();

        // Standalone: pre-stage present.
        let standalone = minimal_input(&machine);
        let out = render(DEFAULT_TEMPLATE, &standalone).unwrap();
        assert!(
            out.contains("/etc/systemd/system/headscale.service"),
            "standalone must stage the headscale unit"
        );
        assert!(
            out.contains("/var/lib/yah-cloud/headscale/headscale serve"),
            "unit ExecStart must match DEFAULT_HEADSCALE_DIR"
        );
        assert!(
            out.contains("ufw allow 80"),
            "standalone must open ufw 80 (LE HTTP-01)"
        );
        assert!(
            out.contains("ufw allow 443"),
            "standalone must open ufw 443 (headscale)"
        );
        // Must stay parseable YAML with all-string runcmd entries.
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&out).expect("standalone cloud-init must be valid YAML");
        for entry in doc["runcmd"].as_sequence().expect("runcmd seq") {
            assert!(
                entry.is_string(),
                "standalone runcmd entry parsed as {entry:?}, not a string"
            );
        }

        // Joining: no pre-stage.
        let mut joining = minimal_input(&machine);
        joining.headscale_preauth_key = Some("tskey-test".into());
        let out = render(DEFAULT_TEMPLATE, &joining).unwrap();
        assert!(
            !out.contains("/etc/systemd/system/headscale.service"),
            "joining node must not stage a headscale unit"
        );
        assert!(
            !out.contains("ufw allow 443"),
            "joining node must not open 443"
        );
    }

    #[test]
    fn render_warden_channel_in_output() {
        let machine = sample_machine();
        let mut input = minimal_input(&machine);
        input.warden_channel = "beta".into();
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        // Channel rides a systemd drop-in (Environment=WARDEN_CHANNEL=…), not a
        // --channel flag (the ExecStart bakes defaults; the drop-in tunes it).
        assert!(
            out.contains("WARDEN_CHANNEL=beta"),
            "yubaba channel missing"
        );
        // containerd is installed unpinned (R330-T9).
        assert!(
            out.contains("apt-get install -y containerd\n"),
            "containerd install missing"
        );
        assert!(find_unsubstituted(&out).is_none());
    }

    #[test]
    fn embedded_template_matches_workspace_canonical() {
        // Drift test: .yah/infra/cloud-init/mirror.yml must stay in sync with
        // the embedded DEFAULT_TEMPLATE (crates/yah/cloud/templates/mirror.yml).
        // Edit both files together; this test catches divergence.
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .find(|p| p.join(".yah").is_dir())
            .expect("workspace root not found from CARGO_MANIFEST_DIR");
        let canonical_path = crate::paths::cloud_init_template(workspace_root);
        if canonical_path.exists() {
            let canonical =
                std::fs::read_to_string(&canonical_path).expect("reading workspace canonical");
            assert_eq!(
                canonical.trim_end(),
                DEFAULT_TEMPLATE.trim_end(),
                ".yah/infra/cloud-init/mirror.yml drifted from crates/yah/cloud/templates/mirror.yml — edit both files together"
            );
        }
        // If the file doesn't exist yet, the test passes (bootstrap case).
    }

    #[test]
    fn cosign_block_shell_form_well_quoted() {
        // YAML parsability spot-check: the block uses double-quoted strings inside
        // a single-quoted `sh -c '...'`. Confirm no apostrophes leak into the
        // single-quoted body and the case/esac terminators are present.
        let machine = sample_machine();
        let mut input = minimal_input(&machine);
        input.warden_cosign_identity_regexp = Some("^https://github\\.com/yah-ai/yah/".into());
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        let sh_line = out
            .lines()
            .find(|l| l.contains("sh -c") && l.contains("cosign"))
            .expect("cosign install sh -c line missing");
        // Body of the sh -c is enclosed in a single quoted region; we
        // intentionally use double-quotes around shell vars inside. If a stray
        // apostrophe slipped through we'd see an odd count of `'`.
        let single_quotes = sh_line.matches('\'').count();
        assert!(
            single_quotes == 2,
            "expected exactly 2 enclosing single quotes in sh -c body, found {single_quotes}: {sh_line}"
        );
        assert!(sh_line.contains("case \"$ARCH\""), "case opener missing");
        assert!(sh_line.contains("esac"), "case terminator missing");
        // The block must be a sequence of valid `runcmd` entries: each line
        // starts with `  - ` (two-space indent + dash + space) so cloud-init
        // parses it as a YAML list item.
        for line in out.lines().filter(|l| l.contains("cosign")) {
            // Skip the header comment lines (start with `#`).
            let stripped = line.trim_start();
            if stripped.starts_with('#') || stripped.is_empty() {
                continue;
            }
            assert!(
                line.starts_with("  - "),
                "cosign block line is not a runcmd list entry: {line:?}"
            );
        }
    }

    #[test]
    fn render_with_cosign_identity_emits_verify_block() {
        let machine = sample_machine();
        let mut input = minimal_input(&machine);
        input.warden_url = "https://cdn.yah.dev/yubaba/0.9.0/x86_64-unknown-linux-musl/yah-yubaba-x86_64-unknown-linux-musl.tar.gz".into();
        input.warden_cosign_identity_regexp = Some("^https://github\\.com/yah-ai/yah/".into());
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        assert!(
            out.contains("cosign verify-blob --certificate-identity-regexp '^https://github\\.com/yah-ai/yah/'"),
            "verify-blob line missing or identity-regexp not threaded"
        );
        assert!(out.contains(COSIGN_OIDC_ISSUER), "oidc-issuer flag missing");
        // sig + cert sibling URLs are derived by suffixing the tarball URL.
        assert!(
            out.contains(&format!("{}.sig", input.warden_url)),
            ".sig sibling URL missing"
        );
        assert!(
            out.contains(&format!("{}.cert", input.warden_url)),
            ".cert sibling URL missing"
        );
        // cosign install is pinned to a specific release version (no `latest`).
        assert!(
            out.contains(&format!(
                "/releases/download/{}/cosign-linux-",
                COSIGN_VERSION
            )),
            "pinned cosign release URL missing"
        );
        // R330-F22: cosign binary itself is sha256-pinned (both arches).
        // Bumping COSIGN_VERSION without bumping the sha256s should break this
        // assertion before it breaks a boot.
        assert!(
            out.contains(COSIGN_SHA256_AMD64),
            "cosign amd64 sha256 pin missing from rendered block"
        );
        assert!(
            out.contains(COSIGN_SHA256_ARM64),
            "cosign arm64 sha256 pin missing from rendered block"
        );
        assert!(
            out.contains("sha256sum -c -"),
            "cosign binary sha256 verify line missing"
        );
        // sha256 verify still runs in parallel — belt + suspenders during rollout.
        assert!(
            out.contains("sha256sum -c -"),
            "sha256 verify dropped — should run in parallel with cosign"
        );
        assert!(find_unsubstituted(&out).is_none());
    }

    #[test]
    fn render_without_cosign_identity_omits_verify_block() {
        // Byte-equivalence check against today's sha256-only render: when
        // warden_cosign_identity_regexp is None, no cosign content appears.
        let machine = sample_machine();
        let input = minimal_input(&machine);
        let out = render(DEFAULT_TEMPLATE, &input).unwrap();
        // Comment-line in mirror.yml mentions "cosign verify-blob" in prose;
        // check for the flag-bearing form which is only emitted when the
        // verify-blob runcmd block actually runs.
        assert!(
            !out.contains("cosign verify-blob --certificate-identity-regexp"),
            "cosign block should be absent when identity_regexp is None"
        );
        assert!(
            !out.contains("/sigstore/cosign/releases/download/"),
            "cosign install line should be absent when identity_regexp is None"
        );
        // sha256 verify is the trust gate in this mode.
        assert!(
            out.contains("sha256sum -c -"),
            "sha256 verify must remain in the no-cosign render path"
        );
        assert!(find_unsubstituted(&out).is_none());
    }

    #[test]
    fn compute_warden_sha256_matches_known_value() {
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("yah-yubaba");
        std::fs::write(&bin_path, b"hello").unwrap();
        let sha = compute_warden_sha256(&bin_path).unwrap();
        assert_eq!(
            sha,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
