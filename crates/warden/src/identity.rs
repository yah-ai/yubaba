//! Hostkey identity: Ed25519 keypair generation, OpenSSH public key parsing,
//! SHA256 fingerprint computation, and state-file persistence.
//!
//! Phase 1 (R040-F8) stores the hostkey fingerprint + the original blob so
//! the warden's `/identity` endpoint can hand it back to a desktop client or
//! the provisioning command.
//!
//! Phase 1 F8 (R092-F8) adds `generate_or_load_hostkey`: warden generates its
//! own Ed25519 keypair on first boot rather than waiting for cloud-init to call
//! `POST /register-hostkey`. The private seed is written to `<dir>/hostkey`
//! (raw 32 bytes, mode 0600) and never leaves the machine; the public key is
//! written to `<dir>/hostkey.pub` (OpenSSH format).
//!
//! @yah:relay(R427, "Warden as ownership writer + service-principal contract")
//! @yah:at(2026-06-03T22:42:08Z)
//! @yah:status(open)
//! @yah:phase(P2)
//! @yah:parent(Q425)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426)
//!
//! @yah:ticket(R427-F1, "Warden privileged cheers client: register_ownership on provision, revoke on destroy")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T22:46:04Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R427)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426-F1)
//! @yah:gotcha("CheersConfig.issuer_url is used as BOTH iss AND aud — cheers verifies its own /ownership routes against its own issuer URL. Don't pass a different audience expecting cheers to accept the token; that would fail aud-scoping per W159 §Scope composition rule 5.")
//! @yah:gotcha("PASETO v4 secret keys are 64 bytes (32-byte seed + 32-byte pubkey), not 32 bytes alone. `warden install` must write the full 64-byte secret half — passing a raw 32-byte ed25519 seed will fail at CheersClient::new with CheersError::Mint.")
//! @yah:gotcha("on_behalf_of serializes as JSON `null` when None (not omitted). Cheers's CreateOwnershipBody accepts both, but a future shift to serde(skip_serializing_if = 'Option::is_none') is now a deliberate decision — there is an explicit test pinning the null shape.")
//! @yah:assumes("Warden's service-principal install flow (W159 §Service principals bootstrap step 1-4) writes the 64-byte PASETO v4 secret to disk and a CheersConfig is read from warden's config file. The actual install flow is out of scope for F1 — the client takes the bytes ready-to-use. Track install-flow ticketing once the cheers-side POST /admin/service-principals lands (status open in external/cheers).")
//! @yah:assumes("Cheers's POST /ownership and DELETE /ownership/{id} routes are mounted at the cheers issuer root (no /api or /v1 prefix). cheers-axum's ownership::router() uses bare /ownership paths; the product can still nest the router under a prefix, but the warden client assumes the root mount per the cheers-side wiring example. If cheers ends up nesting, expose the prefix as a CheersConfig field.")
//! @yah:handoff("Privileged cheers client at crates/yah/warden/src/cheers_client.rs. CheersClient owns the warden service-principal Ed25519 keypair + a reusable reqwest::Client; mints PASETO v4.public tokens LOCALLY (sub=svc:<id>, scope=[ownership:write], aud=iss=cheers_issuer_url, 5-min TTL per W159 §TTLs lower band, kid in the footer). register_ownership POSTs the canonical body (principal_id/resource_kind/resource_id/relationship/on_behalf_of) — matches external/cheers/crates/cheers-axum/src/ownership.rs::CreateOwnershipBody verbatim. revoke_ownership DELETEs /ownership/{id}. Typed CheersError (Mint/Http/Status/Decode) lets destroy branch on 404 vs 5xx. Monotonic jti counter prevents same-second replay. pasetors 0.7 added to warden Cargo.toml.")
//! @yah:handoff("DEPLOY WIRED — deploy_workload_spec (lib.rs ~1157). After containerd deploy + cloudflared + headscale registration succeed, if BOTH ServerState.cheers_client AND WorkloadDeployBody.requesting_camp_id are set, calls cheers.register_ownership(camp_id, 'service', ident, 'owns', on_behalf_of_user) and stores row.id in ServerState.ownership_rows (Mutex<HashMap<String, String>> ident→row_id). WorkloadDeployBody grew two optional fields: requesting_camp_id (camp principal_id) + on_behalf_of_user (user, drives cascading revoke). R428 will derive these from verified MCP claims instead. Register failure is tracing::warn — workload stays up (tearing down a live service over an auth-table blip is worse than serving an audit gap; reconciler is the recovery path).")
//! @yah:handoff("DESTROY WIRED — new POST /workloads/{ident}/destroy. Order: teardown via runtime.teardown_workload, then revoke. teardown-not-found becomes status='not_found' (still attempt revoke); teardown errors with other messages → 500 with revoke skipped (workload may still be running). revoke 404 is benign (logged INFO, response succeeds with revoked=false). revoke 5xx after successful teardown → 200 with revoke_error in body so callers can surface for reconciliation (on-host state is consistent). Map entry consumed on every successful destroy.")
//! @yah:handoff("TESTS GREEN (12 new). cheers_client::tests (7): mint round-trip pins sub/iss/aud/scope/exp/kid; jti uniqueness across same-second mints; malformed-secret rejection; POST happy-path with canonical body + Bearer header; on_behalf_of=None serializes as JSON null; 403→CheersError::Status; DELETE round-trip. lib.rs::tests (5): destroy-without-cheers; destroy-revokes-row + map-consumed; destroy-treats-404-as-already-revoked; destroy-5xx-returns-200-with-revoke_error; WorkloadDeployBody parses + defaults new fields. Full warden --lib: 108 passed (was 96 at F1 start). cargo check clean both with and without containerd-integration.")
//! @yah:verify("cargo test -p warden --lib cheers_client  # 7 passed")
//! @yah:verify("cargo test -p warden --lib tests::destroy_  # 4 destroy paths green")
//! @yah:verify("cargo test -p warden --lib  # 108 passed (was 96 pre-F1)")
//! @yah:verify("cargo check -p warden && cargo check -p warden --features containerd-integration  # both clean")
//! @yah:cleanup("ownership_rows is process-local (in-memory HashMap). On warden restart the map is empty — destroy on a workload that survived the restart will skip revoke. Persist alongside workload state once R406-T9's containerd backend gives warden a unified workload-state store. Restart drift is acceptable in the interim because cheers's revoke is idempotent and reconciler-friendly.")

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// What the warden persists between restarts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    /// OpenSSH-style fingerprint, e.g. `SHA256:abc123…` (no padding).
    pub hostkey_fingerprint: String,
    /// The base64 blob from the pubkey line, exactly as read.
    pub pubkey_blob_b64: String,
    /// Algorithm field from the pubkey line, e.g. `ssh-ed25519`.
    pub algorithm: String,
}

/// Parse a single OpenSSH public-key line (`<algo> <base64-blob> [comment]`)
/// and return the fingerprint + blob + algorithm.
///
/// Accepts file contents (multi-line) and uses the first non-empty line.
pub fn parse_pubkey(content: &str) -> Result<Identity> {
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow!("pubkey content has no usable line"))?;

    let mut parts = line.split_whitespace();
    let algorithm = parts.next().ok_or_else(|| anyhow!("missing algorithm"))?;
    let blob_b64 = parts.next().ok_or_else(|| anyhow!("missing key blob"))?;

    let blob = base64::engine::general_purpose::STANDARD
        .decode(blob_b64)
        .context("decoding pubkey base64 blob")?;

    let mut hasher = Sha256::new();
    hasher.update(&blob);
    let digest = hasher.finalize();

    let fp = format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    );

    Ok(Identity {
        hostkey_fingerprint: fp,
        pubkey_blob_b64: blob_b64.to_string(),
        algorithm: algorithm.to_string(),
    })
}

/// Read a pubkey from disk and return its `Identity`.
pub fn parse_pubkey_file(path: &Path) -> Result<Identity> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading pubkey at {}", path.display()))?;
    parse_pubkey(&content)
}

/// Format 32 raw Ed25519 public-key bytes as an OpenSSH public-key line.
///
/// Wire format: `[u32be len("ssh-ed25519")] ["ssh-ed25519"] [u32be 32] [key bytes]`,
/// base64-encoded, prefixed with the algorithm and a `yah-warden` comment.
pub fn format_ssh_ed25519_pubkey(pubkey_bytes: &[u8; 32]) -> String {
    let algo = b"ssh-ed25519";
    let mut blob = Vec::with_capacity(4 + algo.len() + 4 + 32);
    blob.extend_from_slice(&(algo.len() as u32).to_be_bytes());
    blob.extend_from_slice(algo);
    blob.extend_from_slice(&(pubkey_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(pubkey_bytes);
    format!(
        "ssh-ed25519 {} yah-warden\n",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    )
}

/// Generate a new Ed25519 keypair or load an existing one from `hostkey_dir`.
///
/// On first boot (no `<hostkey_dir>/hostkey.pub`):
/// - Generates a fresh Ed25519 keypair.
/// - Writes the 32-byte private seed to `<hostkey_dir>/hostkey` (mode 0600).
/// - Writes the public key in OpenSSH format to `<hostkey_dir>/hostkey.pub`.
/// - Returns the parsed `Identity`.
///
/// On subsequent boots: reads and parses `<hostkey_dir>/hostkey.pub`.
///
/// The private seed never leaves the machine; `.yah/cloud/machines/*.toml`
/// stores only the public fingerprint (arch doc §Identity and trust).
pub fn generate_or_load_hostkey(hostkey_dir: &Path) -> Result<Identity> {
    let pub_path = hostkey_dir.join("hostkey.pub");
    if pub_path.exists() {
        return parse_pubkey_file(&pub_path);
    }

    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    std::fs::create_dir_all(hostkey_dir)
        .with_context(|| format!("creating hostkey dir {}", hostkey_dir.display()))?;

    let priv_path = hostkey_dir.join("hostkey");
    std::fs::write(&priv_path, signing_key.to_bytes())
        .with_context(|| format!("writing private key to {}", priv_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting 0600 on {}", priv_path.display()))?;
    }

    let pubkey_line = format_ssh_ed25519_pubkey(verifying_key.as_bytes());
    std::fs::write(&pub_path, &pubkey_line)
        .with_context(|| format!("writing public key to {}", pub_path.display()))?;

    parse_pubkey(&pubkey_line)
}

/// On-disk format for the state file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateOnDisk {
    /// `None` until the first `register-hostkey` call.
    pub identity: Option<Identity>,
}

/// Load the state file. Missing → empty state (not an error).
pub fn load_state(path: &Path) -> Result<StateOnDisk> {
    if !path.exists() {
        return Ok(StateOnDisk::default());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading state {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("parsing state {}", path.display()))
}

/// Persist the state file (creating parent dirs as needed). Atomic via
/// write-tmp + rename.
pub fn save_state(path: &Path, state: &StateOnDisk) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    let tmp = path.with_extension("json.tmp");
    let content = serde_json::to_string_pretty(state).context("serializing state")?;
    std::fs::write(&tmp, content)
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real ed25519 pubkey snapshot — generated with `ssh-keygen -t ed25519`,
    /// scrubbed of comment. The fingerprint below was computed with `ssh-keygen
    /// -lf <pubkey>` so we can assert against a known-correct OpenSSH value.
    const SAMPLE_ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDXJ8MNVqHbLfqVNvKkz9Cp9TQyOjP3OEajjqJD2c95P";
    const SAMPLE_FP: &str = "SHA256:HAo2DsB7cN+GmrEbJ8SR305rJagwQhgP2dNyUemUBbU";

    #[test]
    fn parse_pubkey_ed25519_fingerprint() {
        let id = parse_pubkey(SAMPLE_ED25519).unwrap();
        assert_eq!(id.algorithm, "ssh-ed25519");
        assert_eq!(id.hostkey_fingerprint, SAMPLE_FP);
    }

    #[test]
    fn parse_pubkey_strips_comment_and_whitespace() {
        let with_comment = format!("  {}  user@host\n", SAMPLE_ED25519);
        let id = parse_pubkey(&with_comment).unwrap();
        assert_eq!(id.hostkey_fingerprint, SAMPLE_FP);
    }

    #[test]
    fn parse_pubkey_skips_blank_and_comment_lines() {
        let content = format!("# generated by ssh-keygen\n\n{}\n", SAMPLE_ED25519);
        let id = parse_pubkey(&content).unwrap();
        assert_eq!(id.hostkey_fingerprint, SAMPLE_FP);
    }

    #[test]
    fn parse_pubkey_rejects_garbage() {
        assert!(parse_pubkey("not a key").is_err());
        assert!(parse_pubkey("").is_err());
        assert!(parse_pubkey("ssh-ed25519 ###not-base64###").is_err());
    }

    #[test]
    fn state_file_round_trip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("identity.json");

        // Missing → default.
        let loaded = load_state(&path).unwrap();
        assert!(loaded.identity.is_none());

        // Save + reload.
        let id = parse_pubkey(SAMPLE_ED25519).unwrap();
        save_state(
            &path,
            &StateOnDisk {
                identity: Some(id.clone()),
            },
        )
        .unwrap();
        let reloaded = load_state(&path).unwrap();
        assert_eq!(reloaded.identity.unwrap(), id);
    }

    #[test]
    fn save_state_creates_parent_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("nested/deeper/identity.json");
        save_state(&path, &StateOnDisk::default()).unwrap();
        assert!(path.exists());
    }

    // ── R092-F8: Ed25519 auto-generation ────────────────────────────────────

    #[test]
    fn format_ssh_ed25519_pubkey_produces_parseable_line() {
        let raw = [0u8; 32];
        let line = format_ssh_ed25519_pubkey(&raw);
        assert!(line.starts_with("ssh-ed25519 "), "should start with 'ssh-ed25519 '");
        assert!(line.contains("yah-warden"), "should contain comment");
        let id = parse_pubkey(&line).unwrap();
        assert_eq!(id.algorithm, "ssh-ed25519");
        assert!(id.hostkey_fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn generate_or_load_hostkey_creates_files_on_first_boot() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        assert!(!dir.join("hostkey.pub").exists());

        let id = generate_or_load_hostkey(dir).unwrap();
        assert_eq!(id.algorithm, "ssh-ed25519");
        assert!(id.hostkey_fingerprint.starts_with("SHA256:"));
        assert!(dir.join("hostkey").exists(), "private key should be written");
        assert!(dir.join("hostkey.pub").exists(), "public key should be written");
    }

    #[test]
    fn generate_or_load_hostkey_is_stable_on_second_call() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        let id1 = generate_or_load_hostkey(dir).unwrap();
        let id2 = generate_or_load_hostkey(dir).unwrap();
        assert_eq!(id1.hostkey_fingerprint, id2.hostkey_fingerprint,
            "second call should read existing key, not regenerate");
    }

    #[test]
    fn generate_or_load_hostkey_private_key_is_32_bytes() {
        let tmp = tempfile::TempDir::new().unwrap();
        generate_or_load_hostkey(tmp.path()).unwrap();
        let bytes = std::fs::read(tmp.path().join("hostkey")).unwrap();
        assert_eq!(bytes.len(), 32, "private key seed should be 32 bytes");
    }
}
