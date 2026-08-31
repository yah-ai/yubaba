//! Litestream sidecar management for Headscale HA (R040-F21).
//!
//! On Phase 2 leader election:
//! 1. Run `litestream restore` to pull the latest Headscale SQLite snapshot
//!    from S3 before starting Headscale.
//! 2. Enable + start `litestream-replicate.service` so WAL frames are
//!    continuously streamed to S3 while this node is the leader.
//!
//! On leadership loss:
//! 1. Stop `litestream-replicate.service` so only the leader replicates.
//!    (Followers pre-warm by periodic snapshot pulls — not implemented here
//!    yet; relevant only when promotion latency matters at >100 nodes.)
//!
//! ## Credentials
//!
//! Litestream reads S3 credentials from environment variables:
//!   `LITESTREAM_ACCESS_KEY_ID` / `LITESTREAM_SECRET_ACCESS_KEY`
//! These must be present in the systemd unit's environment (via
//! `EnvironmentFile=/etc/yah-cloud/litestream.env` or a direct
//! `Environment=` directive).  The yubaba does not manage the credentials
//! themselves; inject them at provision time via cloud-init.
//!
//! ## S3 URL format
//!
//! `s3://bucket/prefix?endpoint=https://fsn1.your-objectstorage.com`
//!
//! The `?endpoint=` query parameter is passed through to litestream's
//! `endpoint` config key (Hetzner Object Storage, Backblaze B2, MinIO, etc.).
//!
//! @yah:ticket(R591-T3, "Turn on litestream DB continuity end-to-end (--litestream-s3-url + restore-on-place)")
//! @yah:status(review)
//! @yah:at(2026-08-12T21:52:38Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R591)
//! @yah:next("Set --litestream-s3-url so leader.rs::on_became_leader's litestream restore + replicate sidecar actually run; verify a freshly-placed node restores headscale.db from S3 before it starts serving. Async replication = small RPO (a few writes) on failover — acceptable for headscale's low, mostly-static write rate.")
//! @yah:handoff("THE PATH WAS NOT MERELY UNCONFIGURED - IT WAS BROKEN IN THREE PLACES, and setting --litestream-s3-url alone would have replicated nothing. All three are fixed. (1) litestream::install() was DEAD CODE: grep across oss/yubaba + app/ found callers for restore/start/stop and none for install, so /etc/yah-cloud/litestream.yml was never written on any node. Both consumers name that path, so every restore failed at 'no such file' into a warn! and every systemctl start ran against a unit that had never been written, into a discarded exit status. leader.rs::on_became_leader now calls install() before restore. (2) generate_config emitted MALFORMED YAML. (3) The sidecar unit was bound to a systemd unit R591-F1 retires.")
//! @yah:handoff("DEFECT 2, THE MALFORMED YAML, and it was invisible by construction. generate_config built the file with one format! whose `\\` line-continuation stripped the leading whitespace of the continued line, so access-key-id landed at COLUMN 0 instead of 8 - a top-level key, not a sibling of `- url:`, leaving the replica with no credentials at all. The pre-existing test passed straight through it because it only asked whether the string LITESTREAM_ACCESS_KEY_ID appeared somewhere in the output. Rebuilt as explicit pushes against a named REPLICA_KEY_INDENT constant. FALSIFIED, NOT ASSUMED: I restored the old format string behind a probe and re-ran - every_replica_key_is_indented_under_its_url FAILS with `left: 0, right: 8`, the exact bug, and passes with the fix. Probe removed; grep FALSIFICATION PROBE in litestream.rs returns nothing.")
//! @yah:handoff("DEFECT 3 IS AN F1 INTERACTION, so it had to be caught in this pass rather than filed. The sidecar unit carried BindsTo=headscale.service and WantedBy=headscale.service. R591-F1 re-homes headscale onto kamaji and DISABLES that systemd unit, so on a re-homed node BindsTo would have stopped replication the instant it started, and the [Install] target orders against a unit that never runs. The unit now has no reference to headscale.service and no [Install] section at all - it is never enabled, only started and stopped by leader.rs, which is the actual lifecycle owner. Restart is also on-failure -> always, the same lesson as the appliance: a replicate process that exits 0 has stopped replicating.")
//! @yah:gotcha("THE DB IS NOT THE WHOLE OF CONTINUITY, and litestream structurally cannot carry the rest. noise_private.key (72 bytes, /var/lib/yah-cloud/headscale/) is the appliance's IDENTITY, not its data: move the appliance without it and EVERY node's stored server identity mismatches at once - a worse outage than the one this relay is fixing, because it is silent and fleet-wide. The mechanism is R600/W273's raft-replicated cluster secret store (SecretRef::Cluster + SecretMount Cluster->File), the same one standing up for TLS certs. Do NOT invent a second secret path for it. Recorded in headscale_appliance.rs's module docs under 'What is NOT here' so the next reader of the spec meets it there.")
//! @yah:next("THE ACME-CACHE BULLET, CORRECTED: it said 'with TLS moved to the CF edge (R591-T2)'. T2's premise was reframed on 2026-08-12 - TLS now terminates at the fleet's own passway front doors, not a rented edge. The CONCLUSION is unchanged and still the reason this matters: once headscale stops terminating its own Let's Encrypt, the acme-cache is no longer state that has to survive a failover, which removes the one piece litestream does not carry. Only the mechanism changed.")
//! @yah:next("I DID NOT SET --litestream-s3-url, and deliberately did not invent a value. There is NO litestream bucket declared anywhere in the tree - grep over .yah/infra/ and .yah/docs/guides/ returns nothing - so the URL, the provider and the credentials are all an operator decision, not a default I could defend. Everything downstream of that decision is now built and tested. To turn it on: (1) create the bucket and note its s3://bucket/prefix?endpoint=... URL; (2) write LITESTREAM_ACCESS_KEY_ID / LITESTREAM_SECRET_ACCESS_KEY into /etc/yah-cloud/litestream.env on each candidate node (the sidecar unit already reads it via EnvironmentFile=-); (3) add --litestream-s3-url <URL> to yubaba.service's ExecStart (app/yah/cli/resources/yubaba.service:47) and roll it. On the next leadership transition install() writes the config + unit, restore runs, and the sidecar starts.")
//! @yah:next("THE VERIFICATION THIS TICKET ASKS FOR ('a freshly-placed node restores headscale.db from S3 before it starts serving') IS NOW ORDERED CORRECTLY IN CODE - install -> restore -> start the appliance -> start the sidecar, in on_became_leader - but has NOT been exercised against a real bucket. Do that on the dev cluster (us-west-011/013/014), which is the sanctioned testbed, not on prod.")
//! @yah:verify("cargo test -p yubaba --lib = 435 passed / 0 failed (was 417 at the start of this relay). 5 new litestream tests: every_replica_key_is_indented_under_its_url (the falsified one, both with and without an endpoint), the_endpoint_query_becomes_a_key_and_leaves_the_url, the_sidecar_is_not_bound_to_the_retired_headscale_unit, the_sidecar_restarts_on_a_graceful_exit, the_unit_and_the_restore_share_one_config_path.")
//! @yah:verify("cargo check -p yubaba clean; cargo clippy -p yubaba --lib reports zero warnings on litestream.rs, leader.rs or headscale_appliance.rs (10 crate-wide warnings, all pre-existing and on untouched files - same count as before this relay).")
//! @yah:verify("The unit text is now generated by one function used by BOTH install() and the tests, so a directive can no longer be asserted in a copy that has drifted from what is written to /etc/systemd/system.")

use anyhow::Result;
use std::path::Path;

/// Name of the litestream replicate systemd unit.
pub const LITESTREAM_UNIT: &str = "litestream-headscale.service";
/// Default litestream config path on the machine.
pub const LITESTREAM_CONFIG_PATH: &str = "/etc/yah-cloud/litestream.yml";

/// Every key under a replica entry sits at this indent — `- url:` is at 6, so
/// its sibling keys are at 8. Named because the bug this constant replaced was
/// invisible: a `\` line-continuation in the old format string stripped the
/// leading whitespace of the following line, so `access-key-id` came out at
/// column 0 and the replica had no credentials at all (R591-T3).
const REPLICA_KEY_INDENT: &str = "        ";

/// Generate a litestream config YAML for replicating `headscale_db` to `s3_url`.
///
/// The `?endpoint=` query parameter in `s3_url` is extracted and written as a
/// separate `endpoint:` key in the replica config.
pub fn generate_config(headscale_db: &Path, s3_url: &str) -> String {
    let (url_without_query, endpoint) = split_s3_url(s3_url);
    let mut out = String::from("---\ndbs:\n");
    out.push_str(&format!("  - path: {}\n", headscale_db.display()));
    out.push_str("    replicas:\n");
    out.push_str(&format!("      - url: {url_without_query}\n"));
    if let Some(ep) = endpoint {
        out.push_str(&format!("{REPLICA_KEY_INDENT}endpoint: {ep}\n"));
    }
    // Credentials are env-expanded by litestream itself, so the config file is
    // safe to write world-readable and safe to put in a bug report.
    out.push_str(&format!(
        "{REPLICA_KEY_INDENT}access-key-id: ${{LITESTREAM_ACCESS_KEY_ID}}\n"
    ));
    out.push_str(&format!(
        "{REPLICA_KEY_INDENT}secret-access-key: ${{LITESTREAM_SECRET_ACCESS_KEY}}\n"
    ));
    out
}

/// Write the litestream config to `LITESTREAM_CONFIG_PATH` and install
/// the `litestream-headscale.service` systemd unit (idempotent).
///
/// Credentials are read from `LITESTREAM_ACCESS_KEY_ID` /
/// `LITESTREAM_SECRET_ACCESS_KEY` in the environment — inject via
/// `/etc/yah-cloud/litestream.env` or cloud-init `EnvironmentFile`.
///
/// # Call this before `restore` (R591-T3)
///
/// [`restore`] and the replicate unit both run `litestream -config
/// <LITESTREAM_CONFIG_PATH>`. Until R591-T3 nothing called this function at
/// all, so that file never existed on any node: every restore failed at
/// "no such file", every `systemctl start litestream-headscale.service` failed
/// against a unit that had never been written, and both failures were absorbed
/// — the restore into a `warn!`, the start into a discarded exit status. The
/// feature looked wired from `leader.rs` and replicated nothing.
pub fn install(headscale_db: &Path, s3_url: &str) -> Result<()> {
    let config = generate_config(headscale_db, s3_url);
    if let Some(parent) = Path::new(LITESTREAM_CONFIG_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(LITESTREAM_CONFIG_PATH, &config)?;

    // NO `BindsTo=`/`WantedBy=headscale.service` (R591-F1). Headscale is a
    // kamaji-supervised appliance now, so on a re-homed node `headscale.service`
    // is *disabled* — binding to it would stop this unit the moment it started,
    // and ordering after a unit that never starts is at best a no-op. The
    // lifecycle owner is `leader.rs`, which starts this on becoming the ingress
    // owner and stops it on losing that, so the unit needs no [Install] section
    // at all: it is never `enable`d, only started.
    //
    // `Restart=always` for the same reason the appliance uses it — a replicate
    // process that exits 0 has stopped replicating, and "it exited cleanly" is
    // not a reason to leave the coordinator's DB unbacked.
    let unit_path = format!("/etc/systemd/system/{LITESTREAM_UNIT}");
    std::fs::write(&unit_path, unit_text())?;
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();
    Ok(())
}

/// The `litestream-headscale.service` unit text. Split out from [`install`] so
/// its directives are assertable — the writer targets `/etc/systemd/system`,
/// which no test can write.
fn unit_text() -> String {
    format!(
        "[Unit]\n\
         Description=Litestream Headscale replication (yah-yubaba Phase 2)\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         EnvironmentFile=-/etc/yah-cloud/litestream.env\n\
         ExecStart=/usr/local/bin/litestream replicate -config {cfg}\n\
         Restart=always\n\
         RestartSec=5\n",
        cfg = LITESTREAM_CONFIG_PATH,
    )
}

/// Start `litestream-headscale.service` (idempotent — no-op if already running).
pub fn start() {
    let _ = std::process::Command::new("systemctl")
        .args(["start", LITESTREAM_UNIT])
        .status();
}

/// Stop `litestream-headscale.service`.
pub fn stop() {
    let _ = std::process::Command::new("systemctl")
        .args(["stop", LITESTREAM_UNIT])
        .status();
}

/// Run `litestream restore` to pull the latest Headscale DB snapshot from S3
/// before starting Headscale on a newly-elected leader.
///
/// Uses `-if-replica-exists` so the call is a no-op on first bootstrap (no
/// snapshot in S3 yet).  Runs the blocking child process in a `spawn_blocking`
/// task so it doesn't stall the async runtime.
pub async fn restore(headscale_db: &Path, s3_url: &str) -> Result<()> {
    let (url_without_query, _) = split_s3_url(s3_url);
    let db_path = headscale_db.to_string_lossy().into_owned();
    let url_clone = url_without_query.clone();

    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("litestream")
            .args([
                "restore",
                "-if-replica-exists",
                "-config",
                LITESTREAM_CONFIG_PATH,
                "-o",
                &db_path,
                &url_clone,
            ])
            .status()
    })
    .await??;

    if !status.success() {
        anyhow::bail!(
            "litestream restore from {url_without_query} failed (exit {})",
            status.code().unwrap_or(-1)
        );
    }
    tracing::info!("litestream restore complete from {}", url_without_query);
    Ok(())
}

/// Split `s3://bucket/path?endpoint=https://...` into
/// `(s3://bucket/path, Some("https://..."))`.
fn split_s3_url(url: &str) -> (String, Option<String>) {
    match url.split_once('?') {
        None => (url.to_owned(), None),
        Some((base, query)) => {
            let endpoint = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("endpoint="))
                .map(|v| v.to_owned());
            (base.to_owned(), endpoint)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn split_url_no_query() {
        let (base, ep) = split_s3_url("s3://my-bucket/headscale");
        assert_eq!(base, "s3://my-bucket/headscale");
        assert!(ep.is_none());
    }

    #[test]
    fn split_url_with_endpoint() {
        let (base, ep) =
            split_s3_url("s3://my-bucket/headscale?endpoint=https://fsn1.your-objectstorage.com");
        assert_eq!(base, "s3://my-bucket/headscale");
        assert_eq!(ep.as_deref(), Some("https://fsn1.your-objectstorage.com"));
    }

    #[test]
    fn generate_config_contains_db_path() {
        let cfg = generate_config(
            &PathBuf::from("/etc/yah-cloud/headscale/headscale.db"),
            "s3://bucket/headscale",
        );
        assert!(
            cfg.contains("/etc/yah-cloud/headscale/headscale.db"),
            "db path missing"
        );
        assert!(cfg.contains("s3://bucket/headscale"), "s3 url missing");
        assert!(
            cfg.contains("LITESTREAM_ACCESS_KEY_ID"),
            "cred placeholder missing"
        );
    }

    /// R591-T3. `generate_config` used a `\` line-continuation, which strips
    /// the leading whitespace of the continued line — so `access-key-id` came
    /// out at column 0 instead of 8. The old test above passed anyway (it only
    /// asked whether the string appeared *somewhere*), and the config it
    /// described gave the replica no credentials at all.
    ///
    /// Every key under `- url:` is a sibling of it and must sit at the same
    /// indent as `endpoint`, with or without an endpoint present.
    #[test]
    fn every_replica_key_is_indented_under_its_url() {
        for url in [
            "s3://bucket/headscale",
            "s3://bucket/headscale?endpoint=https://fsn1.your-objectstorage.com",
        ] {
            let cfg = generate_config(&PathBuf::from("/var/lib/hs/headscale.db"), url);
            for key in ["access-key-id", "secret-access-key"] {
                let line = cfg
                    .lines()
                    .find(|l| l.trim_start().starts_with(key))
                    .unwrap_or_else(|| panic!("{key} missing from:\n{cfg}"));
                assert_eq!(
                    line.len() - line.trim_start().len(),
                    REPLICA_KEY_INDENT.len(),
                    "{key} must be a sibling of `- url:`, got {line:?} in:\n{cfg}"
                );
            }
        }
    }

    /// The `?endpoint=` query is litestream's `endpoint:` key, not part of the
    /// replica URL — a bucket URL carrying the query would be dialled verbatim.
    #[test]
    fn the_endpoint_query_becomes_a_key_and_leaves_the_url() {
        let cfg = generate_config(
            &PathBuf::from("/var/lib/hs/headscale.db"),
            "s3://bucket/headscale?endpoint=https://fsn1.your-objectstorage.com",
        );
        assert!(cfg.contains("- url: s3://bucket/headscale\n"), "{cfg}");
        assert!(
            cfg.contains("endpoint: https://fsn1.your-objectstorage.com"),
            "{cfg}"
        );
        assert!(
            !cfg.contains("?endpoint="),
            "query leaked into the url:\n{cfg}"
        );
    }

    /// R591-F1 re-homed headscale onto kamaji, so `headscale.service` is
    /// *disabled* on a re-homed node. The unit used to carry
    /// `BindsTo=headscale.service` + `WantedBy=headscale.service`, which would
    /// have stopped replication the instant it started and bound the sidecar's
    /// lifecycle to a unit that no longer runs. `leader.rs` owns the lifecycle.
    #[test]
    fn the_sidecar_is_not_bound_to_the_retired_headscale_unit() {
        let unit = unit_text();
        assert!(!unit.contains("headscale.service"), "{unit}");
        assert!(
            !unit.contains("[Install]"),
            "the sidecar is started by leader.rs, never enabled:\n{unit}"
        );
    }

    /// Same lesson as the appliance's `RestartPolicy::Always`: a replicate
    /// process that exits 0 has stopped replicating, and exiting cleanly is not
    /// a reason to leave the coordinator's DB unbacked.
    #[test]
    fn the_sidecar_restarts_on_a_graceful_exit() {
        let unit = unit_text();
        assert!(unit.contains("Restart=always"), "{unit}");
        assert!(!unit.contains("Restart=on-failure"), "{unit}");
    }

    /// The unit and [`restore`] must name the same config file, or one of them
    /// runs against a path nothing writes — which is the shape of the bug this
    /// ticket found.
    #[test]
    fn the_unit_and_the_restore_share_one_config_path() {
        assert!(unit_text().contains(LITESTREAM_CONFIG_PATH));
    }
}
