//! Rotation → live reload of cluster-secret file mounts (R600-F4 / W273).
//!
//! The single elected ACME issuer (R600-F3) re-issues the fleet cert and writes
//! the fresh ciphertext into raft via `PutSecret`. That replicated write bumps
//! the state machine's [`YubabaStateMachine::subscribe_secrets`] epoch on every
//! node. This module is the consumer of that watch: on each bump it re-renders
//! the affected workloads' tmpfs `File` mounts in place (via F2's
//! [`ClusterResolver`]) and then asks kamaji to **graceful-upgrade** the
//! consuming workload so the new cert goes live without dropping connections.
//!
//! ## Why a debounce
//!
//! F3 writes the cert as two records — key first, cert last (see the F4 handoff
//! note). Each `PutSecret` bumps the epoch, so a naive "upgrade on every bump"
//! would fire once on the new-key/old-cert intermediate state, serving a
//! mismatched pair for a sub-second window. Instead, on the first bump we wait a
//! short [`DEBOUNCE`] window (longer than F3's inter-write gap) and coalesce any
//! further bumps, so by the time we resolve, both records are the new pair. A
//! per-workload content digest then gates the actual upgrade: an epoch bump that
//! doesn't change a given workload's resolved bytes (a different secret rotated,
//! or a snapshot install that replayed identical state) is a no-op for it — no
//! spurious connection-dropping reload.
//!
//! ## Rolling reload (interim)
//!
//! Every node observes the same replicated `PutSecret` at ~the same instant, so
//! a naive "reload now" would blip every ingress at once. Until the container
//! backends do a truly zero-downtime handoff (R600-F7), each node waits a
//! per-node [`rolling_stagger`] offset before its reload pass, so a fronting
//! load balancer routes around the one draining node and the *fleet* stays up.
//! This is a mitigation, not a fix: per-node in-flight connections still drop on
//! the container backends until F7. `Backend::Native` is already zero-downtime,
//! so the stagger there is merely a harmless delay.
//!
//! ## Trust boundary
//!
//! Decryption stays in yubaba (the KEK never leaves the node); the re-rendered
//! plaintext lives only in the host tmpfs file and the container's read-only
//! bind, exactly as at initial materialization (R600-F6). This task never logs
//! secret bytes.
//!
//! @yah:ticket(R600-F10, "Deliver the R600 fleet cert to the systemd-managed passway doors: nothing on a non-kamaji node consumes a cluster secret")
//! @yah:at(2026-09-05T02:27:50Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R600)
//! @yah:next("CUTOVER ORDER MATTERS. While per-node ACME and the fleet issuer both exist, the issuer must not request east's exact SAN set or it shares east's Let's Encrypt duplicate-certificate bucket (see R853-B7). Sequence: materialize -> point one door at the shared files with PASSWAY_TLS_MODE=manual -> verify -> repeat on the second -> only then remove the per-node ACME config. Once no node self-issues, the bucket question dies and south.origin.yah.dev can be dropped from south's SAN set.")
//! @yah:verify("The issuer half is already proven live as of 2026-09-05: a 40-acme-issuer.conf drop-in on east + south elects a single issuer over the raft lock acme-issuer/yah.dev against LE STAGING. Sign-off for this ticket is a door serving a cert it never issued: stop the per-node ACME on one origin, confirm openssl s_client against that IP returns the fleet cert, and confirm a re-issue propagates to it with no manual step.")
//! @yah:gotcha("THE GAP THAT KEPT R600 UNDEPLOYED, found 2026-09-05 while fixing R853-B7. All nine R600 children are in review, but the chain terminates at a consumer that does not exist on the live fleet. secret_reload::run walks DEPLOYED WorkloadSpecs holding a SecretMount and calls deploy::secret_mount::rerender_file_secrets — it is a documented no-op until a workload with a cluster File secret is deployed on the node. The two live yah.dev origins are hand-rolled systemd units (passway-test.service on us-east-001, passway.service on us-south-001) reading /var/lib/passway/{cert,key}.pem, NOT kamaji workloads. So R600-F5 (SecretMount Cluster -> File + PASSWAY_TLS_MODE=manual) has nothing to attach to, and enabling the issuer alone produces a replicated cert nobody serves.")
//! @yah:next("STATE AS LEFT 2026-09-05: /etc/systemd/system/yubaba.service.d/40-acme-issuer.conf is installed on us-east-001 and us-south-001 (LE STAGING, YUBABA_ACME_CONSUMERS=ingress, CF token copied to /var/lib/yah/yubaba/cf-token), both yubabas restarted clean and both are in standby. It is NOT on us-west-001, the current raft leader, so no order has been placed and no cluster secret exists yet. Completing that step means restarting yubaba on the leader, which is deliberately left as an operator call while R858 is open — us-west-001 is the node that hosts headscale, and R858 records that leadership movement decapitates the mesh by construction.")
//! @yah:gotcha("A CONFIGURED ISSUER ON A NON-LEADER IS INDISTINGUISHABLE FROM A BROKEN ONE. Measured live 2026-09-05: with the drop-in on us-east-001 and us-south-001, both logged 'acme issuer: watching (single issuer elected via raft lock acme-issuer/yah.dev)' at startup and then NOTHING for 6+ minutes — no issuance, no warning, no error. Cause is correct behaviour badly reported: run() gates the whole tick on `raft.metrics().current_leader == Some(node_id)` (acme_issuer.rs:401) to avoid ForwardToLeader spam, and IssuerAction::Standby logs nothing. us-west-001 (100.64.0.1) held leadership, and it had no issuer config, so no node ever attempted AcquireLock. An operator watching the journal sees a healthy-looking start line and a silent process. Fix shape: log the standby reason once on transition (leader vs lock-loser are different states and should read differently), and/or surface issuer state on an endpoint. Practical consequence for deployment: the drop-in must go on EVERY voter, not just the ingress nodes, because any voter can hold leadership.")
//! @yah:next("LEADER RESTART HELD 2026-09-05 despite being operator-authorised, because the premise the authorisation rested on turned out to be false (see the leader-health gotcha). us-west-001 holds raft leadership AND is running the freshly-recovered headscale appliance; a yubaba restart there drops leadership, R858's chain says the appliance is torn down on leadership loss, and neither other voter can stand it up. Coordinating with the live R858 session instead. The issuer stays in standby on east + south, which costs nothing while no consumer exists.")
//! @yah:gotcha("/mesh/leader-health LIES ABOUT HEADSCALE, and it nearly cost an outage. On 2026-09-05 all three voters reported {\"leader\":...,\"headscale\":\"stopped\"} while headscale was demonstrably RUNNING on us-west-001 — pid 517125, bound *:443 and *:80, started 01:54Z, and cloud.mesh.yah.dev/health returned 200 from the public internet. The field appears to read the systemd unit state (`systemctl is-active headscale` = inactive) while kamaji supervises the process as a native workload, so a healthy appliance reads as dead. I used that field to argue a leader restart was low-risk, and it was not. Told the live R858 session (session:83093d9d) directly; R858 owns the fix.")
//! @yah:next("DELIBERATE LIMITATION worth reading before extending: the reload command is a shell string the operator writes, and for today's doors the honest value is `systemctl restart passway` — which DROPS in-flight connections on that origin. passway cannot hot-swap a cert (tls.rs \"The reload gap\": TlsSettings is static), and its zero-downtime path needs a REPLACEMENT process started with PASSWAY_UPGRADE=true before the old one gets SIGQUIT — orchestration no systemd unit on either node has wired. The rolling stagger means only one origin cycles at a time and the other keeps serving, so the fleet stays up; a single origin blips. Wiring the graceful-upgrade dance for a systemd door is the follow-on, and it is the same machinery R600-F7/F9 are settling for the kamaji case.")
//! @yah:handoff("MATERIALIZER BUILT 2026-09-05 (operator chose the thin-yubaba-module option over moving the doors onto kamaji). NEW oss/yubaba/crates/yubaba/src/cert_materialize.rs: resolves tls/<domain>/{cert,key} through the SAME ClusterResolver + resolve_secrets path every other consumer uses (so the R706 access check cannot be skipped — there is no constructor that omits the consumer), writes the pair atomically to two configured paths, and runs one configured reload command only when the bytes actually changed. Opt-in on YUBABA_CERT_FILES_DOMAIN and completely inert without it; also required: _CERT_PATH, _KEY_PATH, _CONSUMER (must match the issuer's YUBABA_ACME_CONSUMERS), optional _RELOAD_CMD. Reuses secret_reload's DEBOUNCE and rolling_stagger (both widened to pub(crate), no behaviour change) so the issuer's key-first/cert-last pair is never observed half-rotated and a fleet-wide rotation does not cycle every origin at once. Spawned next to secret_reload in main.rs. cargo test -p yubaba --lib = 681 passed / 0 failed, 8 of them new; cargo check -p yubaba --bins clean.")
//! @yah:gotcha("NOT PROVEN AGAINST A REAL CLUSTER SECRET, and cannot be until the issuer runs. The 8 unit tests cover config parsing (including the chain-overwrites-the-key footgun and each required key), the mount shapes the issuer's own naming produces, 0600 on the key, digest order-independence, and atomic write + mode + no leftover temp files. What they do NOT cover is the end-to-end path, because no tls/yah.dev/* record exists anywhere yet — the issuer is in standby on east + south and the leader restart that would start it is held (see the R858 coordination note). Treat the live behaviour as unverified until a cert actually lands.")

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use workload_spec::{SecretMount, WorkloadSpec};

use crate::deploy::secret_mount::rerender_file_secrets;
use crate::mesh::MeshAssignment;
use crate::raft::YubabaStateMachine;
use crate::secrets::{resolve_secrets, ClusterResolver, ContainerSecrets, SECRET_STORE_ROOT};
use crate::ServerState;

/// How long to coalesce cluster-secret epoch bumps before re-rendering, so F3's
/// key-first/cert-last two-write rotation is observed as one consistent pair
/// rather than firing on the new-key/old-cert intermediate. Comfortably longer
/// than the sub-second gap between F3's two `PutSecret`s.
pub(crate) const DEBOUNCE: Duration = Duration::from_secs(2);

/// Width of one node's slot in the rolling-reload window (see
/// [`rolling_stagger`]). Wide enough that a fronting load balancer / health
/// check notices a draining node and routes around it before the next node
/// starts its reload.
const ROLL_SLOT: Duration = Duration::from_secs(4);

/// Number of distinct rolling slots. A cluster larger than this wraps (two
/// nodes share a slot) — acceptable, since the goal is "not every node at once",
/// not a strict one-at-a-time barrier (that needs a raft-lock, which is R600-F7
/// territory alongside the real zero-downtime handoff).
const ROLL_SLOTS: u64 = 8;

/// Per-node delay before a node performs its reload pass, so a fleet-wide
/// rotation (every node sees the same replicated `PutSecret` at ~the same
/// instant) rolls node-by-node instead of blipping every ingress at once.
///
/// This is the **interim** mitigation while the container backends still do a
/// connection-dropping reload (R600-F7): staggering keeps the *fleet* available
/// (an LB routes around the one draining node) even though per-node in-flight
/// connections still drop. Once F7 lands the per-node reload is itself
/// zero-downtime and the stagger is merely cosmetic. Harmless for
/// `Backend::Native` (already zero-downtime) — it just delays that node's swap.
pub(crate) fn rolling_stagger(node_id: u64) -> Duration {
    ROLL_SLOT * (node_id % ROLL_SLOTS) as u32
}

/// One workload that mounts a cluster secret as a `File`, tracked so a rotation
/// can re-render its mount and graceful-upgrade it.
#[derive(Clone)]
pub struct SecretWorkloadEntry {
    /// The **materialized** spec (F6 already rewrote its `File` cluster secrets
    /// to read-only `Bind`s of the host tmpfs files). Handed to
    /// `graceful_upgrade_workload` so kamaji re-spawns the ingress with the
    /// re-rendered cert bind.
    pub spec: WorkloadSpec,
    /// The mesh assignment used at deploy time — reused on upgrade so the
    /// replacement keeps the workload's identity / mesh IP (re-allocating would
    /// hand it a different address).
    pub mesh: MeshAssignment,
    /// The workload's original `File`-target `SecretMount`s (pre-materialization,
    /// still `SecretRef::Cluster`) — re-resolved on rotation to produce fresh
    /// cert/key bytes.
    pub file_mounts: Vec<SecretMount>,
    /// Digest of the last-rendered concatenated secret content. A rotation is
    /// detected when a fresh resolve yields a different digest; an epoch bump
    /// that leaves this workload's bytes unchanged is skipped.
    pub content_digest: u64,
}

/// In-memory registry of secret-consuming workloads, keyed on mesh ident.
/// Populated by the deploy handler when a workload with a cluster `File` secret
/// deploys successfully; cleared on destroy.
pub type SecretWorkloadRegistry = Mutex<HashMap<String, SecretWorkloadEntry>>;

/// Order-independent digest of resolved `File` secret content. Only the
/// `(container path, bytes)` pairs feed the hash, so re-resolving the same
/// material yields the same digest regardless of mount order. In-process only
/// (compared across bumps within one daemon lifetime), so a non-portable hasher
/// is fine.
pub fn content_digest(secrets: &ContainerSecrets) -> u64 {
    let mut pairs: Vec<(&std::path::Path, &[u8])> = secrets
        .file_mounts
        .iter()
        .map(|fm| (fm.path.as_path(), fm.content.as_slice()))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for (path, bytes) in pairs {
        path.hash(&mut hasher);
        bytes.hash(&mut hasher);
    }
    hasher.finish()
}

/// Subscribe to cluster-secret rotations and drive the re-render → graceful
/// upgrade loop. Returns immediately (a no-op that logs) on a node with no raft
/// cluster state or no workload backend — nothing can rotate there.
pub async fn run(state: Arc<ServerState>) {
    let Some(sm) = state.cluster_state.clone() else {
        tracing::debug!("secret_reload: no cluster state on this node; rotation watcher idle");
        return;
    };
    let Some(backend) = state.active_backend() else {
        tracing::debug!("secret_reload: no workload backend; rotation watcher idle");
        return;
    };

    let stagger = state.node_id.map(rolling_stagger).unwrap_or_default();

    let mut rx = sm.subscribe_secrets();
    // Absorb the initial value so we only react to changes after startup.
    let _ = rx.borrow_and_update();
    tracing::info!(
        stagger_ms = stagger.as_millis() as u64,
        "secret_reload: watching cluster secrets for rotation → live reload"
    );

    loop {
        if rx.changed().await.is_err() {
            // Sender dropped (state machine gone) — the daemon is shutting down.
            break;
        }
        let _ = rx.borrow_and_update();
        // Coalesce F3's key-first/cert-last two-write rotation (and any burst)
        // into one re-render pass over a consistent pair.
        tokio::time::sleep(DEBOUNCE).await;
        // Roll node-by-node: every node saw the same replicated rotation at
        // ~the same instant, so a per-node offset keeps the fleet available
        // while a (still connection-dropping, pre-F7) reload cycles the ingress.
        if !stagger.is_zero() {
            tokio::time::sleep(stagger).await;
        }
        let _ = rx.borrow_and_update();

        reload_once(
            &sm,
            &state.cluster_kek_path,
            &state.secret_mount_root,
            backend.as_ref(),
            &state.secret_workloads,
        )
        .await;
    }
}

/// One re-render pass over every registered secret-consuming workload. Rebuilds
/// the [`ClusterResolver`] fresh (it reloads the node-local KEK), re-resolves
/// each workload's cluster `File` mounts, and — only when the resolved content
/// changed — rewrites the host tmpfs files in place and graceful-upgrades the
/// workload. Failures are per-workload and non-fatal: a workload whose secret is
/// momentarily unresolvable (a partial replicated write) is skipped and retried
/// on the next bump; its stored digest is left untouched so the retry still sees
/// a change.
async fn reload_once(
    sm: &YubabaStateMachine,
    kek_path: &std::path::Path,
    mount_root: &std::path::Path,
    backend: &(dyn crate::ContainerRuntime + Send + Sync),
    registry: &SecretWorkloadRegistry,
) {
    let entries: Vec<(String, SecretWorkloadEntry)> = {
        let guard = registry.lock().unwrap();
        if guard.is_empty() {
            return;
        }
        guard
            .iter()
            .map(|(ident, entry)| (ident.clone(), entry.clone()))
            .collect()
    };

    // Load the KEK once for the pass, but build a resolver *per workload*: the
    // R706 access check is bound to the consumer identity, so a single shared
    // resolver would be asking on the wrong workload's behalf.
    let kek = match crate::secrets::load_cluster_kek(kek_path) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "secret_reload: cannot load the node KEK; skipping this rotation pass"
            );
            return;
        }
    };

    for (ident, entry) in entries {
        let resolver = ClusterResolver::new(
            sm.clone(),
            kek.clone(),
            crate::secrets::LocalFileResolver::new(SECRET_STORE_ROOT),
            workload_spec::secrets::SecretConsumer::of(&entry.spec),
        );
        let resolved = match resolve_secrets(&entry.file_mounts, &resolver) {
            Ok(r) => r,
            // R706 / W294 decision 5: a rule edit that revokes a *running*
            // workload takes effect on its next deploy, not by tearing it down
            // mid-flight. The plaintext is already in the container's tmpfs
            // bind, so "revoke now" means "kill the workload" — which would make
            // a typo in an access rule a production-outage weapon. Instead the
            // rotation stops for this workload (it will never see a newer
            // value) and says so loudly, once per bump, distinctly from the
            // transient arm below.
            Err(workload_spec::secrets::SecretError::Forbidden { name }) => {
                tracing::warn!(
                    ident = %ident,
                    secret = %name,
                    workload = %entry.spec.name,
                    "secret_reload: this workload is NO LONGER ADMITTED to a cluster secret it \
                     currently has mounted. Its existing plaintext stays live and stops being \
                     rotated; access actually ends on its next deploy. Redeploy or destroy it to \
                     complete the revocation."
                );
                continue;
            }
            Err(e) => {
                // A partial replicated write (key present, cert not yet) or a
                // decrypt failure — skip and retry on the next bump. Digest is
                // left as-is so the retry still registers a change.
                tracing::warn!(
                    ident = %ident,
                    error = %e,
                    "secret_reload: cluster secret not resolvable yet; deferring reload"
                );
                continue;
            }
        };

        let digest = content_digest(&resolved);
        if digest == entry.content_digest {
            // This workload's material didn't change on this bump.
            continue;
        }

        // Rewrite the host tmpfs files the container's read-only bind points at.
        if let Err(e) = rerender_file_secrets(mount_root, &ident, &resolved) {
            tracing::warn!(
                ident = %ident,
                error = %e,
                "secret_reload: re-render failed; leaving the previous cert live"
            );
            continue;
        }

        // Make the running workload pick up the fresh cert without dropping
        // connections (kamaji sequences the pingora fd-handoff).
        match backend
            .graceful_upgrade_workload(&entry.spec, &entry.mesh)
            .await
        {
            Ok(_) => {
                tracing::info!(
                    ident = %ident,
                    "secret_reload: rotated cluster secret → graceful-upgraded workload"
                );
                // Commit the new digest so we don't re-upgrade on the next
                // unrelated bump.
                if let Some(slot) = registry.lock().unwrap().get_mut(&ident) {
                    slot.content_digest = digest;
                }
            }
            Err(e) => {
                // The host files already carry the new cert; the upgrade failed
                // (backend hiccup). Leave the digest stale so the next bump
                // retries the upgrade.
                tracing::warn!(
                    ident = %ident,
                    error = %format!("{e:#}"),
                    "secret_reload: graceful upgrade failed; will retry on next rotation"
                );
            }
        }
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;

    use kamaji::fake::FakeRuntime;
    use openraft::entry::RaftEntry;
    use openraft::storage::{EntryResponder, RaftStateMachine};
    use openraft::type_config::alias::{CommittedLeaderIdOf, EntryOf, LogIdOf};
    use openraft::vote::RaftLeaderId;
    use workload_spec::{ImageRef, MeshIdent, SecretRef, SecretTarget, TierTag, WorkloadSpec};

    use crate::raft::{YubabaRaftConfig, YubabaRequest, YubabaStateMachine};
    use crate::secrets::{seal_cluster_secret, ClusterResolver};

    const KEK: [u8; 32] = [5u8; 32];
    const CERT_KEY: &str = "tls/yah.dev/cert";
    const KEY_KEY: &str = "tls/yah.dev/key";

    fn cert_mount() -> SecretMount {
        SecretMount {
            source: SecretRef::Cluster {
                name: CERT_KEY.into(),
            },
            target: SecretTarget::File {
                path: "/run/secrets/tls.crt".into(),
                mode: 0o400,
            },
        }
    }

    fn key_mount() -> SecretMount {
        SecretMount {
            source: SecretRef::Cluster {
                name: KEY_KEY.into(),
            },
            target: SecretTarget::File {
                path: "/run/secrets/tls.key".into(),
                mode: 0o400,
            },
        }
    }

    fn ingress_spec(ident: &str) -> WorkloadSpec {
        let mut spec = WorkloadSpec::for_forge(
            "ingress",
            ImageRef {
                registry: "localhost".into(),
                repository: "passway".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            TierTag("infra".into()),
            vec![],
        );
        spec.expose.mesh.identity = MeshIdent(ident.into());
        spec
    }

    /// The consumer identity every fixture in this module deploys as.
    ///
    /// **Derived from the spec, not spelled out.** `WorkloadSpec::for_forge`
    /// names the workload `forge-<id>`, not `<id>`, so a hardcoded `"ingress"`
    /// here silently produces a rule that admits nobody and every rotation
    /// assertion fails for the wrong reason.
    fn ingress_consumer() -> workload_spec::secrets::SecretConsumer {
        workload_spec::secrets::SecretConsumer::of(&ingress_spec("ingress"))
    }

    fn ingress_access() -> workload_spec::secrets::SecretAccess {
        workload_spec::secrets::SecretAccess::Workloads(vec![
            workload_spec::secrets::WorkloadMatch::workload(ingress_spec("ingress").name),
        ])
    }

    fn put_secret(index: u64, name: &str, plaintext: &[u8]) -> EntryOf<YubabaRaftConfig> {
        let rec = seal_cluster_secret(&KEK, plaintext, index, ingress_access());
        // openraft 0.10 builds entries through the RaftEntry trait rather than
        // by struct literal — `Entry` gained three more generics and the
        // committed-leader-id type now comes from the type config.
        let log_id = LogIdOf::<YubabaRaftConfig>::new(
            CommittedLeaderIdOf::<YubabaRaftConfig>::new(1, 1),
            index,
        );
        EntryOf::<YubabaRaftConfig>::new_normal(
            log_id,
            YubabaRequest::PutSecret {
                name: name.into(),
                ciphertext: rec.ciphertext,
                nonce: rec.nonce,
                updated_at: rec.updated_at,
                access: rec.access,
                digest: rec.digest,
                sans: rec.sans,
            },
        )
    }

    /// Apply one entry to `sm`. openraft 0.10's `apply` takes a *stream* of
    /// `EntryResponder`s rather than an iterator of entries; same shape as the
    /// helper in `raft::store`'s own tests.
    async fn apply_one(sm: &mut YubabaStateMachine, entry: EntryOf<YubabaRaftConfig>) {
        let item: Result<EntryResponder<YubabaRaftConfig>, std::io::Error> = Ok((entry, None));
        sm.apply(tokio_stream::iter(vec![item])).await.unwrap();
    }

    /// Compute the digest a workload's cluster File mounts resolve to against
    /// the current state — mirrors what the deploy handler seeds at registration.
    fn digest_now(sm: &YubabaStateMachine, mounts: &[SecretMount]) -> u64 {
        let resolver = ClusterResolver::from_kek_file(
            sm.clone(),
            kek_path(),
            SECRET_STORE_ROOT,
            ingress_consumer(),
        )
        .unwrap();
        content_digest(&resolve_secrets(mounts, &resolver).unwrap())
    }

    // A KEK file the resolver loads. Written once per test into its tempdir; the
    // path is stashed in a thread-local so the helpers above stay terse.
    thread_local! {
        static KEK_PATH: std::cell::RefCell<Option<std::path::PathBuf>> =
            const { std::cell::RefCell::new(None) };
    }
    fn kek_path() -> std::path::PathBuf {
        KEK_PATH.with(|p| p.borrow().clone().expect("kek path set by test"))
    }
    fn set_kek_path(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("cluster.kek");
        std::fs::write(&path, KEK).unwrap();
        KEK_PATH.with(|p| *p.borrow_mut() = Some(path.clone()));
        path
    }

    #[tokio::test]
    async fn rotation_rerenders_and_graceful_upgrades_only_changed_workloads() {
        let tmp = tempfile::TempDir::new().unwrap();
        let kek = set_kek_path(tmp.path());
        let mount_root = tmp.path().join("mounts");

        // Seed the raft state with the initial cert + key.
        let mut sm = YubabaStateMachine::open(tmp.path().join("raft"))
            .await
            .unwrap();
        apply_one(&mut sm, put_secret(1, CERT_KEY, b"CERT-V1")).await;
        apply_one(&mut sm, put_secret(2, KEY_KEY, b"KEY-V1")).await;

        // Pretend the workload was already materialized: its host tmpfs files
        // exist with the v1 material (so the test asserts a *rewrite*).
        let ident = "ingress";
        let wl_dir = mount_root.join(ident);
        std::fs::create_dir_all(&wl_dir).unwrap();
        std::fs::write(wl_dir.join("run_secrets_tls.crt"), b"CERT-V1").unwrap();
        std::fs::write(wl_dir.join("run_secrets_tls.key"), b"KEY-V1").unwrap();

        let mounts = vec![cert_mount(), key_mount()];
        let registry: SecretWorkloadRegistry = Default::default();
        registry.lock().unwrap().insert(
            ident.into(),
            SecretWorkloadEntry {
                spec: ingress_spec(ident),
                mesh: crate::mesh::MeshAssignment::stub(std::net::Ipv4Addr::new(100, 64, 0, 1)),
                file_mounts: mounts.clone(),
                content_digest: digest_now(&sm, &mounts),
            },
        );

        let fake = FakeRuntime::new();

        // A bump that does NOT change this workload's material → no upgrade.
        reload_once(&sm, &kek, &mount_root, &fake, &registry).await;
        assert!(
            fake.graceful_upgrade_calls().is_empty(),
            "no rotation yet → no upgrade"
        );

        // Rotate the cert (key unchanged) → the workload's combined digest moves.
        apply_one(&mut sm, put_secret(3, CERT_KEY, b"CERT-V2-rotated")).await;
        reload_once(&sm, &kek, &mount_root, &fake, &registry).await;

        assert_eq!(
            fake.graceful_upgrade_calls(),
            vec![ident.to_string()],
            "rotation graceful-upgrades exactly the consuming workload"
        );
        // Host tmpfs cert file was rewritten in place with the new bytes; the
        // (unrotated) key file keeps its value.
        assert_eq!(
            std::fs::read(wl_dir.join("run_secrets_tls.crt")).unwrap(),
            b"CERT-V2-rotated"
        );
        assert_eq!(
            std::fs::read(wl_dir.join("run_secrets_tls.key")).unwrap(),
            b"KEY-V1"
        );
        // The stored digest advanced, so a redundant pass does not re-upgrade.
        reload_once(&sm, &kek, &mount_root, &fake, &registry).await;
        assert_eq!(
            fake.graceful_upgrade_calls().len(),
            1,
            "digest committed → no duplicate upgrade on an unchanged pass"
        );
    }

    #[tokio::test]
    async fn missing_secret_defers_without_upgrading() {
        let tmp = tempfile::TempDir::new().unwrap();
        let kek = set_kek_path(tmp.path());
        let mount_root = tmp.path().join("mounts");

        let mut sm = YubabaStateMachine::open(tmp.path().join("raft"))
            .await
            .unwrap();
        // Only the key is present — the cert record never replicated.
        apply_one(&mut sm, put_secret(1, KEY_KEY, b"KEY-V1")).await;

        let mounts = vec![cert_mount(), key_mount()];
        let registry: SecretWorkloadRegistry = Default::default();
        registry.lock().unwrap().insert(
            "ingress".into(),
            SecretWorkloadEntry {
                spec: ingress_spec("ingress"),
                mesh: crate::mesh::MeshAssignment::stub(std::net::Ipv4Addr::new(100, 64, 0, 1)),
                file_mounts: mounts,
                // Unknown initial digest — but the cert can't resolve, so the
                // pass must defer rather than upgrade against a partial pair.
                content_digest: 0,
            },
        );

        let fake = FakeRuntime::new();
        reload_once(&sm, &kek, &mount_root, &fake, &registry).await;
        assert!(
            fake.graceful_upgrade_calls().is_empty(),
            "an unresolvable (partial) secret must defer, not upgrade"
        );
    }
}
