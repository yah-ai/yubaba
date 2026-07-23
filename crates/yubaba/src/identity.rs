//! Hostkey identity: Ed25519 keypair generation, OpenSSH public key parsing,
//! SHA256 fingerprint computation, and state-file persistence.
//!
//! Phase 1 (R040-F8) stores the hostkey fingerprint + the original blob so
//! the yubaba's `/identity` endpoint can hand it back to a desktop client or
//! the provisioning command.
//!
//! Phase 1 F8 (R092-F8) adds `generate_or_load_hostkey`: yubaba generates its
//! own Ed25519 keypair on first boot rather than waiting for cloud-init to call
//! `POST /register-hostkey`. The private seed is written to `<dir>/hostkey`
//! (raw 32 bytes, mode 0600) and never leaves the machine; the public key is
//! written to `<dir>/hostkey.pub` (OpenSSH format).
//!
//! @yah:relay(R427, "Yubaba as ownership writer + service-principal contract")
//! @yah:at(2026-06-03T22:42:08Z)
//! @yah:status(open)
//! @yah:phase(P2)
//! @yah:parent(Q425)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426)
//!
//! @yah:ticket(R427-F1, "Yubaba privileged cheers client: register_ownership on provision, revoke on destroy")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T22:46:04Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R427)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426-F1)
//! @yah:gotcha("CheersConfig.issuer_url is used as BOTH iss AND aud — cheers verifies its own /ownership routes against its own issuer URL. Don't pass a different audience expecting cheers to accept the token; that would fail aud-scoping per W159 §Scope composition rule 5.")
//! @yah:gotcha("PASETO v4 secret keys are 64 bytes (32-byte seed + 32-byte pubkey), not 32 bytes alone. `yubaba install` must write the full 64-byte secret half — passing a raw 32-byte ed25519 seed will fail at CheersClient::new with CheersError::Mint.")
//! @yah:gotcha("on_behalf_of serializes as JSON `null` when None (not omitted). Cheers's CreateOwnershipBody accepts both, but a future shift to serde(skip_serializing_if = 'Option::is_none') is now a deliberate decision — there is an explicit test pinning the null shape.")
//! @yah:assumes("Yubaba's service-principal install flow (W159 §Service principals bootstrap step 1-4) writes the 64-byte PASETO v4 secret to disk and a CheersConfig is read from yubaba's config file. The actual install flow is out of scope for F1 — the client takes the bytes ready-to-use. Track install-flow ticketing once the cheers-side POST /admin/service-principals lands (status open in external/cheers).")
//! @yah:assumes("Cheers's POST /ownership and DELETE /ownership/{id} routes are mounted at the cheers issuer root (no /api or /v1 prefix). cheers-axum's ownership::router() uses bare /ownership paths; the product can still nest the router under a prefix, but the yubaba client assumes the root mount per the cheers-side wiring example. If cheers ends up nesting, expose the prefix as a CheersConfig field.")
//! @yah:handoff("Privileged cheers client at crates/yah/yubaba/src/cheers_client.rs. CheersClient owns the yubaba service-principal Ed25519 keypair + a reusable reqwest::Client; mints PASETO v4.public tokens LOCALLY (sub=svc:<id>, scope=[ownership:write], aud=iss=cheers_issuer_url, 5-min TTL per W159 §TTLs lower band, kid in the footer). register_ownership POSTs the canonical body (principal_id/resource_kind/resource_id/relationship/on_behalf_of) — matches external/cheers/crates/cheers-axum/src/ownership.rs::CreateOwnershipBody verbatim. revoke_ownership DELETEs /ownership/{id}. Typed CheersError (Mint/Http/Status/Decode) lets destroy branch on 404 vs 5xx. Monotonic jti counter prevents same-second replay. pasetors 0.7 added to yubaba Cargo.toml.")
//! @yah:handoff("DEPLOY WIRED — deploy_workload_spec (lib.rs ~1157). After containerd deploy + cloudflared + headscale registration succeed, if BOTH ServerState.cheers_client AND WorkloadDeployBody.requesting_camp_id are set, calls cheers.register_ownership(camp_id, 'service', ident, 'owns', on_behalf_of_user) and stores row.id in ServerState.ownership_rows (Mutex<HashMap<String, String>> ident→row_id). WorkloadDeployBody grew two optional fields: requesting_camp_id (camp principal_id) + on_behalf_of_user (user, drives cascading revoke). R428 will derive these from verified MCP claims instead. Register failure is tracing::warn — workload stays up (tearing down a live service over an auth-table blip is worse than serving an audit gap; reconciler is the recovery path).")
//! @yah:handoff("DESTROY WIRED — new POST /workloads/{ident}/destroy. Order: teardown via runtime.teardown_workload, then revoke. teardown-not-found becomes status='not_found' (still attempt revoke); teardown errors with other messages → 500 with revoke skipped (workload may still be running). revoke 404 is benign (logged INFO, response succeeds with revoked=false). revoke 5xx after successful teardown → 200 with revoke_error in body so callers can surface for reconciliation (on-host state is consistent). Map entry consumed on every successful destroy.")
//! @yah:handoff("TESTS GREEN (12 new). cheers_client::tests (7): mint round-trip pins sub/iss/aud/scope/exp/kid; jti uniqueness across same-second mints; malformed-secret rejection; POST happy-path with canonical body + Bearer header; on_behalf_of=None serializes as JSON null; 403→CheersError::Status; DELETE round-trip. lib.rs::tests (5): destroy-without-cheers; destroy-revokes-row + map-consumed; destroy-treats-404-as-already-revoked; destroy-5xx-returns-200-with-revoke_error; WorkloadDeployBody parses + defaults new fields. Full yubaba --lib: 108 passed (was 96 at F1 start). cargo check clean both with and without containerd-integration.")
//! @yah:verify("cargo test -p yubaba --lib cheers_client  # 7 passed")
//! @yah:verify("cargo test -p yubaba --lib tests::destroy_  # 4 destroy paths green")
//! @yah:verify("cargo test -p yubaba --lib  # 108 passed (was 96 pre-F1)")
//! @yah:verify("cargo check -p yubaba && cargo check -p yubaba --features containerd-integration  # both clean")
//! @yah:cleanup("ownership_rows is process-local (in-memory HashMap). On yubaba restart the map is empty — destroy on a workload that survived the restart will skip revoke. Persist alongside workload state once R406-T9's containerd backend gives yubaba a unified workload-state store. Restart drift is acceptable in the interim because cheers's revoke is idempotent and reconciler-friendly.")
//!

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Bootstrap-token validation core for the authenticated node-admission
/// ceremony (R593-F8 interim) — mint / validate / expiry / single-use for
/// the operator-issued provisioning token `POST /register-hostkey` will
/// require. Deliberately transport-free; the endpoint wiring is a separate
/// lane (see the submodule doc).
pub mod bootstrap;

/// What the yubaba persists between restarts.
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
/// base64-encoded, prefixed with the algorithm and a `yah-yubaba` comment.
pub fn format_ssh_ed25519_pubkey(pubkey_bytes: &[u8; 32]) -> String {
    let algo = b"ssh-ed25519";
    let mut blob = Vec::with_capacity(4 + algo.len() + 4 + 32);
    blob.extend_from_slice(&(algo.len() as u32).to_be_bytes());
    blob.extend_from_slice(algo);
    blob.extend_from_slice(&(pubkey_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(pubkey_bytes);
    format!(
        "ssh-ed25519 {} yah-yubaba\n",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    )
}

/// mshr's own secret-file name (`oss/mshr/crates/mshr/src/keypair.rs`,
/// `SECRET_FILENAME`). Not exported publicly by mshr, so mirrored here —
/// keep in sync if mshr's storage layout ever changes.
const MSHR_SECRET_FILENAME: &str = "identity.ed25519";

/// R593-T2 migration: promote a pre-collapse `<hostkey_dir>/hostkey` (raw
/// 32-byte Ed25519 seed, written by the old self-generating
/// `generate_or_load_hostkey`) into mshr's own identity-file location
/// (`<hostkey_dir>/identity.ed25519`) so `mshr::Keypair::load_or_create_at`
/// loads the SAME bytes and derives the SAME `NodeId` a node already had —
/// no re-enrollment, no fingerprint churn in the fleet's machine TOMLs.
///
/// Runs unconditionally on every call (two cheap `Path::exists` checks) so
/// the migration also covers nodes whose `hostkey.pub` cache already exists
/// and would otherwise never touch mshr's loader — any future consumer that
/// calls `mshr::Keypair::load_or_create_at(hostkey_dir)` directly (e.g. the
/// raft/mesh transport in R593-T7) still needs mshr's identity file seeded
/// correctly, not just yubaba's own OpenSSH sidecar.
///
/// No-op once a node has fully cut over (mshr's file already exists) or on
/// a genuinely fresh node (neither file exists yet — mshr creates a new
/// identity below).
fn migrate_legacy_seed_into_mshr(hostkey_dir: &Path) -> Result<()> {
    let mshr_secret_path = hostkey_dir.join(MSHR_SECRET_FILENAME);
    let legacy_secret_path = hostkey_dir.join("hostkey");
    if mshr_secret_path.exists() || !legacy_secret_path.exists() {
        return Ok(());
    }

    let seed = std::fs::read(&legacy_secret_path).with_context(|| {
        format!(
            "reading legacy hostkey seed at {}",
            legacy_secret_path.display()
        )
    })?;
    if seed.len() != 32 {
        return Err(anyhow!(
            "legacy hostkey at {} is {} bytes, expected a 32-byte raw Ed25519 seed — refusing to migrate",
            legacy_secret_path.display(),
            seed.len()
        ));
    }

    std::fs::create_dir_all(hostkey_dir)
        .with_context(|| format!("creating hostkey dir {}", hostkey_dir.display()))?;

    // Write-tmp-then-rename with the temp file created 0600 from the start
    // (same idiom as mshr keypair.rs's write_atomic, hardened with
    // create_new + a pid-suffixed name): the raw private seed is never
    // observable with default-umask permissions — not even for a window —
    // and a crash mid-write leaves only a same-dir .tmp file that mshr's
    // loader ignores, never a corrupt identity.ed25519 that would
    // hard-error every subsequent boot.
    let tmp_path = hostkey_dir.join(format!("{MSHR_SECRET_FILENAME}.tmp-{}", std::process::id()));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp_path)
            .with_context(|| format!("creating temp seed file {}", tmp_path.display()))?;
        use std::io::Write;
        f.write_all(&seed)
            .with_context(|| format!("writing migrated seed to {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("syncing {}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, &mshr_secret_path).with_context(|| {
        format!(
            "renaming {} → {}",
            tmp_path.display(),
            mshr_secret_path.display()
        )
    })?;

    Ok(())
}

/// Load yubaba's hostkey, sourcing the underlying Ed25519 keypair from
/// mshr's per-machine identity loader (R593-T2 — "one keypair loader, one
/// identity file" per W268 §What the promotion collapses). The hostkey IS
/// the mshr `NodeId`: the OpenSSH-format fingerprint this module has always
/// produced is now derived from the SAME 32-byte public key mshr's
/// `Keypair::node_id()` reports, so every existing consumer keyed off
/// `hostkey_fingerprint` / `pubkey_blob_b64` keeps working unchanged.
///
/// On first boot (no `<hostkey_dir>/hostkey.pub`):
/// - Migrates a legacy `<hostkey_dir>/hostkey` seed into mshr's identity
///   file if present (see [`migrate_legacy_seed_into_mshr`]); otherwise
///   mshr generates a fresh keypair, written to `<hostkey_dir>/identity.ed25519`
///   (mode 0600) — that file is now the one private-key identity on disk.
/// - Writes the public key in OpenSSH format to `<hostkey_dir>/hostkey.pub`
///   as before, for fleet tooling that keys off the SHA256 fingerprint.
/// - Returns the parsed `Identity`.
///
/// On subsequent boots: reads and parses `<hostkey_dir>/hostkey.pub`.
///
/// The private seed never leaves the machine; `.yah/cloud/machines/*.toml`
/// stores only the public fingerprint (arch doc §Identity and trust).
pub fn generate_or_load_hostkey(hostkey_dir: &Path) -> Result<Identity> {
    // Create the dir up front rather than leaning on mshr's loader doing it
    // (R569-B2): every write below — the migrated seed, mshr's identity file,
    // hostkey.pub — needs it, and on a rootless host the state dir is not
    // pre-made for us the way systemd's `StateDirectory=` makes it. Failing
    // here names the directory that couldn't be created, which is the
    // actionable half of the error.
    std::fs::create_dir_all(hostkey_dir)
        .with_context(|| format!("creating hostkey dir {}", hostkey_dir.display()))?;

    migrate_legacy_seed_into_mshr(hostkey_dir)?;

    let pub_path = hostkey_dir.join("hostkey.pub");
    if pub_path.exists() {
        return parse_pubkey_file(&pub_path);
    }

    let keypair = mshr::Keypair::load_or_create_at(hostkey_dir)
        .with_context(|| format!("loading mshr machine identity at {}", hostkey_dir.display()))?;

    let pubkey_line = format_ssh_ed25519_pubkey(keypair.node_id().as_bytes());
    std::fs::write(&pub_path, &pubkey_line)
        .with_context(|| format!("writing public key to {}", pub_path.display()))?;

    parse_pubkey(&pubkey_line)
}

/// Extract the raw 32-byte Ed25519 public key from an OpenSSH-formatted
/// pubkey blob (SSH wire format: `len(algo) algo len(key) key`) — i.e. the
/// mshr `NodeId` bytes underlying this hostkey.
fn node_id_bytes(id: &Identity) -> Result<[u8; 32]> {
    let blob = base64::engine::general_purpose::STANDARD
        .decode(&id.pubkey_blob_b64)
        .context("decoding pubkey blob for node_id extraction")?;
    let key_start = blob
        .len()
        .checked_sub(32)
        .ok_or_else(|| anyhow!("pubkey blob too short for a 32-byte Ed25519 key"))?;
    blob[key_start..]
        .try_into()
        .context("pubkey blob key segment is not 32 bytes")
}

/// Hex-encoded mshr `NodeId` for this `Identity` — the same lowercase-hex
/// encoding `mshr::NodeId`'s `Display` impl and mshr's own `identity.pub`
/// file use, so `/identity`'s `node_id` field (W268 §Verification) matches
/// what `mshr::Keypair::node_id()` reports for the same on-disk key.
pub fn node_id_hex(id: &Identity) -> Result<String> {
    Ok(node_id_bytes(id)?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
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
    serde_json::from_str(&content).with_context(|| format!("parsing state {}", path.display()))
}

/// Persist the state file (creating parent dirs as needed). Atomic via
/// write-tmp + rename, hardened against concurrent writers the same way as
/// [`migrate_legacy_seed_into_mshr`]: the temp file has a per-writer unique
/// name (pid distinguishes processes, a process-monotonic counter
/// distinguishes concurrent writers within one process — deliberately not a
/// wall clock, which two same-instant writers would collide on) and is opened
/// with `create_new` so two writers can never share a temp path. We `sync_all`
/// before the atomic `rename` onto the target, and remove the temp on any
/// error so a failed write never leaves `.tmp` residue beside the state file.
pub fn save_state(path: &Path, state: &StateOnDisk) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    let content = serde_json::to_string_pretty(state).context("serializing state")?;

    // Unique temp name in the target's directory (same filesystem, so the
    // final `rename` is atomic): file name + pid + a process-monotonic seq.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let base = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_string());
    let tmp = path.with_file_name(format!("{base}.tmp-{}-{seq}", std::process::id()));

    // Write + fsync the temp under `create_new` (no default-perms window from
    // a stale temp another writer may have left, and a guaranteed-fresh inode).
    // On failure, clean up the temp before propagating.
    let write = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("creating temp state file {}", tmp.display()))?;
        use std::io::Write;
        f.write_all(content.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
        Ok(())
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
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
        assert!(
            line.starts_with("ssh-ed25519 "),
            "should start with 'ssh-ed25519 '"
        );
        assert!(line.contains("yah-yubaba"), "should contain comment");
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
        // R593-T2: the private key now lives in mshr's own identity file —
        // yubaba's hostkey.pub is a derived OpenSSH-format sidecar, no
        // second private-key file is written for a fresh node.
        assert!(
            dir.join(MSHR_SECRET_FILENAME).exists(),
            "mshr identity file should be written"
        );
        assert!(
            !dir.join("hostkey").exists(),
            "no legacy private-key file on a fresh node"
        );
        assert!(
            dir.join("hostkey.pub").exists(),
            "public key should be written"
        );
    }

    #[test]
    fn generate_or_load_hostkey_is_stable_on_second_call() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        let id1 = generate_or_load_hostkey(dir).unwrap();
        let id2 = generate_or_load_hostkey(dir).unwrap();
        assert_eq!(
            id1.hostkey_fingerprint, id2.hostkey_fingerprint,
            "second call should read existing key, not regenerate"
        );
    }

    #[test]
    fn generate_or_load_hostkey_private_key_is_32_bytes() {
        let tmp = tempfile::TempDir::new().unwrap();
        generate_or_load_hostkey(tmp.path()).unwrap();
        let bytes = std::fs::read(tmp.path().join(MSHR_SECRET_FILENAME)).unwrap();
        assert_eq!(bytes.len(), 32, "private key seed should be 32 bytes");
    }

    #[test]
    fn generate_or_load_hostkey_reports_node_id_matching_mshr() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        let id = generate_or_load_hostkey(dir).unwrap();
        let node_id = node_id_hex(&id).unwrap();

        // Independently load the same directory through mshr's own loader —
        // "one keypair loader, one identity file": the NodeId it derives
        // must equal the one this module reports via node_id_hex.
        let keypair = mshr::Keypair::load_or_create_at(dir).unwrap();
        let expected: String = keypair
            .node_id()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(node_id, expected);
    }

    // ── R593-T2: collapse onto mshr's identity loader ───────────────────────

    /// Migration proof: a node with an old-format `<dir>/hostkey` (raw
    /// 32-byte seed, written by the pre-R593-T2 generator) but no
    /// `hostkey.pub` — the exact shape an in-flight upgrade can leave behind
    /// — must round-trip through the new loader to the SAME NodeId, not a
    /// freshly minted one.
    #[test]
    fn migration_old_format_hostkey_round_trips_to_same_node_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        // Simulate the pre-R593-T2 on-disk state: only the raw 32-byte seed
        // file the old generator wrote, no hostkey.pub.
        let seed = [7u8; 32];
        std::fs::write(dir.join("hostkey"), seed).unwrap();

        // Independently compute what the OLD generator would have derived
        // from this exact seed, using the same ed25519-dalek path the old
        // code used.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let expected_pub = signing_key.verifying_key();
        let expected_line = format_ssh_ed25519_pubkey(expected_pub.as_bytes());
        let expected_id = parse_pubkey(&expected_line).unwrap();
        let expected_node_id: String = expected_pub
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let id = generate_or_load_hostkey(dir).unwrap();

        assert_eq!(
            id.hostkey_fingerprint, expected_id.hostkey_fingerprint,
            "migrated node must keep the same OpenSSH fingerprint"
        );
        assert_eq!(
            node_id_hex(&id).unwrap(),
            expected_node_id,
            "migrated node must report the same mshr NodeId"
        );

        // mshr's own identity file now exists, seeded with the migrated
        // seed — loading it independently derives the identical NodeId.
        let mshr_keypair = mshr::Keypair::load_or_create_at(dir).unwrap();
        assert_eq!(mshr_keypair.node_id().as_bytes(), expected_pub.as_bytes());

        // Second call is stable (fast path via hostkey.pub; no re-migration
        // or re-derivation needed).
        let id2 = generate_or_load_hostkey(dir).unwrap();
        assert_eq!(id2.hostkey_fingerprint, id.hostkey_fingerprint);
    }

    // ── R569-B2: rootless hosts, where nothing pre-creates the state dir ────

    /// A rootless node gets no `StateDirectory=` — the dir the `--state` path
    /// points into may not exist at all on first boot, several levels deep.
    /// Generation must create it rather than reporting "hostkey generation
    /// failed".
    #[test]
    fn generate_or_load_hostkey_creates_a_missing_state_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("Users/yah/.yah/yubaba");
        assert!(!dir.exists());

        let id = generate_or_load_hostkey(&dir).unwrap();
        assert!(id.hostkey_fingerprint.starts_with("SHA256:"));
        assert!(dir.join(MSHR_SECRET_FILENAME).exists());
        assert!(dir.join("hostkey.pub").exists());
    }

    /// The failure this ticket came from was diagnosed off a log line that had
    /// been rendered with anyhow's plain `Display`, which prints only the
    /// outermost context — so the errno never reached the operator. Pin that
    /// the error we hand up carries both the context and the root cause under
    /// the alternate form the caller now logs.
    #[test]
    fn unwritable_hostkey_dir_reports_the_underlying_cause() {
        let tmp = tempfile::TempDir::new().unwrap();
        let readonly = tmp.path().join("readonly");
        std::fs::create_dir(&readonly).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o500)).unwrap();
        }

        let result = generate_or_load_hostkey(&readonly.join("yubaba"));

        // Restore before asserting so a failed assert can't leave an
        // undeletable dir behind for the TempDir drop.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        // Running as root (or on a filesystem that ignores mode bits) the
        // write just succeeds — there is no error chain to assert on.
        let Err(err) = result else { return };

        let plain = format!("{err}");
        let chained = format!("{err:#}");
        assert!(
            plain.contains("creating hostkey dir"),
            "should name the operation: {plain}"
        );
        assert!(
            chained.len() > plain.len(),
            "alternate Display must append the root cause the plain form drops \
             (plain: {plain} / chained: {chained})"
        );
    }

    #[test]
    fn migration_is_noop_when_mshr_identity_already_exists() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        // A node that has already cut over: mshr's identity file exists.
        let cutover = mshr::Keypair::load_or_create_at(dir).unwrap();

        // A stale/unrelated legacy seed also happens to be present (e.g.
        // left over from before cutover). It must NOT override the
        // already-adopted mshr identity.
        std::fs::write(dir.join("hostkey"), [9u8; 32]).unwrap();

        migrate_legacy_seed_into_mshr(dir).unwrap();

        let reloaded = mshr::Keypair::load_or_create_at(dir).unwrap();
        assert_eq!(reloaded.node_id(), cutover.node_id());
    }

    /// Key custody (review bounce): the migrated seed must land 0600 — with
    /// no default-umask window, hence temp-file mode is set at create time —
    /// and the write-tmp-then-rename must leave no .tmp residue behind.
    #[test]
    fn migration_writes_seed_0600_with_no_tmp_residue() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("hostkey"), [7u8; 32]).unwrap();

        migrate_legacy_seed_into_mshr(dir).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(MSHR_SECRET_FILENAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "seed file mode should be 0600, got {mode:o}");
        }

        let residue: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(residue.is_empty(), "tmp residue left behind: {residue:?}");
    }

    #[test]
    fn migration_rejects_malformed_legacy_seed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("hostkey"), b"too short").unwrap();

        let err = migrate_legacy_seed_into_mshr(dir).unwrap_err();
        assert!(
            err.to_string().contains("expected a 32-byte"),
            "got {err:?}"
        );
    }
}
