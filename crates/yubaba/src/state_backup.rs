//! R869 (W339): the off-fleet copy of the applied [`YubabaState`].
//!
//! Every other input a cluster needs to exist already survives the loss of all
//! its machines — the KEK and the declared secret plaintexts are in the fob
//! vault, the machine config is in `.yah/infra/machines/`, and the certs plus
//! the enrollment set are object-store-backed by R779. Only the raft state
//! machine had no copy anywhere but the three voters' disks, which is why the
//! de-facto total-loss procedure on 2026-08-31 was *wipe the raft dir*
//! (`raft/store.rs:40`). This module is that missing copy.
//!
//! ## Why an object and not a replicator
//!
//! `raft/store.rs` already rewrites `raft_state.json` whole on every mutation
//! and the state is KB-scale, so "the copy" is one small JSON object per
//! cluster. There is nothing to stream and nothing to reconcile: the leader
//! PUTs the applied state, and a rebuild GETs it. Litestream and turso-backup
//! both replicate a sqlite database; this is a map of maps.
//!
//! ## The guard is the load-bearing part
//!
//! An unguarded backup would have been *worthless in the incident it exists
//! for*. On 2026-08-31 the recovery was to wipe the raft dir on all three
//! voters; a backup task that simply PUT whatever the local state machine held
//! would have overwritten the only good copy with the empty state within one
//! tick of the first node coming back. So [`StateBackup::store`] refuses to
//! write a snapshot whose `applied_index` is **below** the stored one and says
//! so loudly, and the fleet's backup stays parked on the last good copy until
//! an operator says otherwise.
//!
//! "Otherwise" is [`StateBackup::adopt`]: it archives the current object under
//! `lineage/<n>.json` — the one moment that copy would otherwise become
//! unreachable — and bumps `lineage`, resetting the `applied_index` floor to 0
//! so the rebuilt cluster's next tick takes over. No node carries a lineage
//! locally; each one carries forward whatever `latest.json` says, so the object
//! is the only authority and a node needs no state of its own to participate.
//!
//! ## What a restore does and does not buy
//!
//! [`restorable`] is the state to seed a fresh raft dir with
//! ([`crate::raft::store::seed_state_machine`]). It drops `locks` and
//! `rollouts` deliberately — see its doc.
//!
//! It also restores `tenants`, which means the rebuilt cluster keeps the
//! fencing epochs the dead one granted instead of restarting at 1. That closes
//! most of W339's correctness half: a survivor's epoch is fixed at its last
//! applied `ClaimTenant`, so it is at most the snapshot's, and the rebuilt
//! cluster's next claim grants snapshot + 1 and out-fences it. **Most, not
//! all** — epochs granted after the last snapshot are not in the copy, and no
//! number readable from R2 bounds them. Only the off-fleet
//! `yah_tenant_pointer` generation closes that remainder, and carrying it is
//! R736-F6's ratified call, not this module's.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use yah_object_store::{Error as ObjectError, ObjectStore, Precondition};

use crate::raft::{YubabaNodeId, YubabaState};

/// Env key naming the cluster whose state this node backs up. Its presence is
/// what turns the backup on.
///
/// It is a name, not a derivation: two clusters sharing one bucket must not
/// share one key, and nothing else a node knows about itself is stable across
/// the rebuild this exists for (node ids are reused, addresses move, the raft
/// dir is gone by definition).
pub const CLUSTER_ENV: &str = "YUBABA_STATE_BACKUP_CLUSTER";

/// Env key overriding how often the leader ships a copy, in seconds.
pub const INTERVAL_ENV: &str = "YUBABA_STATE_BACKUP_INTERVAL_SECS";

/// Default cadence. The write is skipped entirely when nothing has been applied
/// since the last one, so on an idle cluster this costs one GET per minute.
pub const DEFAULT_INTERVAL_SECS: u64 = 60;

/// Key root, under the same bucket [`crate::cert_store`] uses.
///
/// Deliberately the same bucket and the same credentials: a disaster-recovery
/// mechanism that needs config the fleet does not already carry is one that is
/// not there when the disaster happens.
pub const KEY_ROOT: &str = "cluster-state";

/// Where the current copy lives.
pub fn latest_key(cluster: &str) -> String {
    format!("{KEY_ROOT}/{cluster}/latest.json")
}

/// Where [`StateBackup::adopt`] parks the copy a lineage bump retires.
pub fn lineage_key(cluster: &str, lineage: u64) -> String {
    format!("{KEY_ROOT}/{cluster}/lineage/{lineage:020}.json")
}

/// One off-fleet copy of the applied state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Which incarnation of this cluster wrote it. Bumped only by
    /// [`StateBackup::adopt`]; carried forward untouched by every ordinary
    /// write, so a node never has to know its own.
    pub lineage: u64,
    /// The raft applied index `state` is true as of. The monotonicity guard
    /// compares on this and nothing else.
    pub applied_index: u64,
    /// Unix seconds the copy was taken, for an operator reading staleness.
    pub taken_at: u64,
    /// Which node shipped it — the leader at the time.
    pub node_id: YubabaNodeId,
    /// `CARGO_PKG_VERSION` of the writer, so a restore can see whether the copy
    /// predates a state-machine schema move.
    pub version: String,
    /// The payload.
    pub state: YubabaState,
}

/// What one [`StateBackup::store`] attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    /// The copy advanced.
    Wrote { lineage: u64, applied_index: u64 },
    /// Nothing has been applied since the last copy. The common case on an idle
    /// cluster, and not worth a PUT.
    Unchanged { applied_index: u64 },
    /// **Refused.** The local state machine is behind the stored copy, which is
    /// what a wiped raft dir looks like from here. The stored copy is left
    /// alone; an operator resolves it with [`StateBackup::adopt`].
    Regressed { stored: u64, local: u64 },
    /// Another node's CAS landed first. Harmless — that node wrote a copy at
    /// least as new as ours would have been. Retried on the next tick.
    Raced,
}

/// Reader/writer for one cluster's off-fleet copy.
pub struct StateBackup {
    objects: Arc<dyn ObjectStore>,
    cluster: String,
}

impl StateBackup {
    pub fn new(objects: Arc<dyn ObjectStore>, cluster: impl Into<String>) -> Self {
        Self {
            objects,
            cluster: cluster.into(),
        }
    }

    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// Where the current copy lives, in a form an operator can act on.
    pub fn locate_latest(&self) -> String {
        self.objects.locate(&latest_key(&self.cluster))
    }

    /// The current copy, or `None` when this cluster has never shipped one.
    ///
    /// `None` is not `StateSnapshot::default()`: "no cluster has ever backed up
    /// here" and "a cluster backed up an empty state" are different answers, and
    /// a rebuild about to seed a raft dir needs the difference.
    pub fn read_latest(&self) -> Result<Option<StateSnapshot>, ObjectError> {
        self.read_key(&latest_key(&self.cluster))
    }

    /// A copy retired by an earlier [`Self::adopt`] — the state as it stood
    /// immediately before that lineage bump.
    pub fn read_lineage(&self, lineage: u64) -> Result<Option<StateSnapshot>, ObjectError> {
        self.read_key(&lineage_key(&self.cluster, lineage))
    }

    /// Every retired lineage, oldest first.
    pub fn lineages(&self) -> Result<Vec<u64>, ObjectError> {
        let prefix = format!("{KEY_ROOT}/{}/lineage/", self.cluster);
        let mut out: Vec<u64> = self
            .objects
            .list_prefix(&prefix)?
            .iter()
            .filter_map(|k| k.strip_prefix(&prefix))
            .filter_map(|n| n.strip_suffix(".json"))
            .filter_map(|n| n.parse().ok())
            .collect();
        out.sort_unstable();
        Ok(out)
    }

    fn read_key(&self, key: &str) -> Result<Option<StateSnapshot>, ObjectError> {
        let Some(bytes) = self.objects.get(key)? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes).map(Some).map_err(|e| {
            ObjectError::Backend(format!(
                "{} is not a readable state snapshot: {e}",
                self.objects.locate(key)
            ))
        })
    }

    /// Ship `state` as of `applied_index`, if it is newer than what is stored.
    ///
    /// The whole decision is `applied_index` against the stored one — see
    /// [`Stored`] for each outcome. The write is a compare-and-swap against the
    /// ETag read in the same call, so two nodes that both believe they are
    /// leader cannot interleave a stale copy over a fresh one.
    pub fn store(
        &self,
        state: &YubabaState,
        applied_index: u64,
        node_id: YubabaNodeId,
        now: u64,
    ) -> Result<Stored, ObjectError> {
        let key = latest_key(&self.cluster);
        // ETag BEFORE bytes, and the order is load-bearing. Read the other way
        // round, a copy that lands between the two reads is decided against the
        // *old* bytes and CAS'd under the *new* ETag — so a stale write wins and
        // the monotonicity guard, the entire point of this method, is bypassed.
        // This way a write landing in the gap can only make the CAS fail, which
        // is `Raced` and harmless.
        let etag = self.objects.etag(&key)?;
        let current = self.objects.get(&key)?;
        let (lineage, cond) = match (&current, etag) {
            (None, _) => (1, Precondition::IfAbsent),
            (Some(bytes), etag) => {
                let stored: StateSnapshot = serde_json::from_slice(bytes).map_err(|e| {
                    ObjectError::Backend(format!(
                        "{} is not a readable state snapshot: {e}",
                        self.objects.locate(&key)
                    ))
                })?;
                if applied_index < stored.applied_index {
                    return Ok(Stored::Regressed {
                        stored: stored.applied_index,
                        local: applied_index,
                    });
                }
                if applied_index == stored.applied_index {
                    return Ok(Stored::Unchanged { applied_index });
                }
                // No ETag but bytes present: the object appeared in the gap, so
                // an IfAbsent CAS is the honest comparand — it fails, and the
                // next tick reads the object that beat us.
                let cond = match etag {
                    Some(e) => Precondition::IfMatch(e),
                    None => Precondition::IfAbsent,
                };
                (stored.lineage, cond)
            }
        };

        let snapshot = StateSnapshot {
            lineage,
            applied_index,
            taken_at: now,
            node_id,
            version: crate::VERSION.to_string(),
            state: state.clone(),
        };
        match self
            .objects
            // None: fleet state snapshots are private objects read by yubaba
            // itself over the S3 API, never fetched through a CDN, so there is
            // no cache to direct (R330-B51).
            .put_if(&key, serde_json::to_vec(&snapshot).unwrap(), cond, None)
        {
            Ok(_) => Ok(Stored::Wrote {
                lineage,
                applied_index,
            }),
            Err(ObjectError::PreconditionFailed(_)) => Ok(Stored::Raced),
            Err(e) => Err(e),
        }
    }

    /// Accept that the live cluster is a new incarnation, and let it start
    /// backing up again.
    ///
    /// Archives the current copy under [`lineage_key`] *first* — that copy is
    /// the pre-rebuild state, i.e. the only thing worth having — then rewrites
    /// `latest.json` with the next lineage and an `applied_index` of 0, so the
    /// leader's next tick wins the monotonicity check.
    ///
    /// The archived copy is left as the *payload* of the reset object too, on
    /// purpose: until the rebuilt cluster has applied anything, the honest
    /// answer to "what would a restore give me" is still the old state.
    ///
    /// Returns the new lineage. Refuses when nothing is stored — there is no
    /// incarnation to succeed, and the ordinary write path already handles a
    /// cluster that has never backed up.
    pub fn adopt(&self, now: u64) -> Result<u64, ObjectError> {
        let key = latest_key(&self.cluster);
        // ETag before bytes — see the note in `store`.
        let etag = self.objects.etag(&key)?;
        let Some(bytes) = self.objects.get(&key)? else {
            return Err(ObjectError::NotFound(format!(
                "{} holds no state copy to adopt — nothing has ever been backed up for cluster \
                 {}, so the ordinary backup path will claim it on the next tick",
                self.objects.locate(&key),
                self.cluster
            )));
        };
        let etag = etag.ok_or_else(|| {
            ObjectError::PreconditionFailed(format!(
                "{} appeared while adopting it — a node is still writing copies. Stop the fleet's \
                 leader, or re-run once it is quiet.",
                self.objects.locate(&key)
            ))
        })?;
        let stored: StateSnapshot = serde_json::from_slice(&bytes).map_err(|e| {
            ObjectError::Backend(format!(
                "{} is not a readable state snapshot: {e}",
                self.objects.locate(&key)
            ))
        })?;

        self.objects
            .put(&lineage_key(&self.cluster, stored.lineage), bytes.clone())?;

        let reset = StateSnapshot {
            lineage: stored.lineage + 1,
            applied_index: 0,
            taken_at: now,
            ..stored
        };
        self.objects
            .put_if(
                &key,
                serde_json::to_vec(&reset).unwrap(),
                Precondition::IfMatch(etag),
                None,
            )
            .map_err(|e| match e {
                ObjectError::PreconditionFailed(_) => ObjectError::PreconditionFailed(format!(
                    "{} changed while adopting it — a node is still writing copies. Stop the \
                     fleet's leader, or re-run once it is quiet.",
                    self.objects.locate(&key)
                )),
                other => other,
            })?;
        Ok(reset.lineage)
    }
}

/// The state to seed a fresh raft dir with, given an off-fleet copy.
///
/// Two maps are dropped, and both drops are the point rather than a
/// simplification:
///
/// - **`locks`** are liveness leases, and on a rebuild every holder is dead by
///   construction. Carrying one in would stall the new cluster for the rest of
///   its TTL on a lock nobody will ever release — R600-F10 spent a day blocked
///   on exactly that shape, a squatted `acme-issuer/yah.dev` lease with an
///   86400s TTL and no renewer, and that was a *live* cluster with a real
///   owner. In a disaster it is strictly worse.
/// - **`rollouts`** are in-flight deploy state. W339 calls this out: a rebuild
///   may legitimately abandon it, and resuming a rollout whose orchestrator no
///   longer exists is not a recovery, it is a second incident.
///
/// Everything else is kept, including `tenants` — see the module docs for what
/// keeping the fencing epochs does and does not buy.
pub fn restorable(snapshot: StateSnapshot) -> YubabaState {
    YubabaState {
        locks: Default::default(),
        rollouts: Default::default(),
        ..snapshot.state
    }
}

/// Node-level config: which cluster, how often.
///
/// @yah:ticket(R869-T1, "Turn the off-fleet raft state backup ON: cut a release, roll the three voters, set YUBABA_STATE_BACKUP_CLUSTER")
/// @yah:at(2026-09-10T05:47:47Z)
/// @yah:status(review)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R869)
/// @yah:next("Once the copy is confirmed live and its applied index is advancing, the chaos drill becomes runnable — that ticket depends on this one.")
/// @yah:verify("Confirm it is the LEADER doing the PUTting and only the leader — the other two voters should show the loop running but not storing.")
/// @yah:gotcha("SEQUENCE THE ROLL AS IF BOTH VERSIONS EXIST AT ONCE (CLAUDE.md's pre-1.0 rule). This change adds no wire surface — R869 deliberately rejected `ClaimTenant { min_epoch }` for exactly that reason, and cluster_protocol stays 5 / state_epoch stays 4 — so a mixed fleet is safe here. Confirm `cargo run -p xtask -- cluster-epochs` is green before cutting.")
/// @yah:blocked_on(operator)
/// @yah:next("SEQUENCE. (1) Cut a release — 0.8.35 predates state_backup entirely and only us-east-001 runs it, so nothing on the fleet has this code. Releases here are local QED recipes (`yah qed run cli-release`), NOT GitHub Actions; per CLAUDE.md no workflow in this repo has an `on: push` trigger, so never diagnose this with `gh run`. (2) Roll the three voters (us-west-001, us-south-001, us-east-001). (3) Add a systemd drop-in setting `YUBABA_STATE_BACKUP_CLUSTER=<name>` beside the existing `YUBABA_CERT_STORE_{BUCKET,ACCOUNT_ID,ENDPOINT}` — the backup deliberately reuses the cert store's R2 bucket and credentials, so no new secret is needed, which was a design decision (a DR mechanism needing config the fleet does not already carry is one that is not there when the disaster happens). (4) Confirm with `yubaba state show` that latest.json exists and its applied index tracks `/cluster/singletons`.")
/// @yah:next("THE CODE IS WIRED AND INERT — this is a DEPLOY, not a code change. Verified at the source: `StateBackupConfig::parse` is called at oss/yubaba/crates/yubaba/src/main.rs:1481 and `state_backup::spawn` at :1484, on the production serve path, inside the `if let Some(node_id) = raft_node_id` arm. A leader begins PUTting only when all three hold: `--raft-node-id` set, `YUBABA_STATE_BACKUP_CLUSTER` non-empty, and the cert store connected (a None cert store logs an error and skips). `run()` then sleeps `interval`, checks `current_leader == Some(node_id)`, and calls `store()`. So there is no wiring ticket hiding behind this one — nothing on the fleet sets the variable, and that is the whole gap.")
/// @yah:handoff("DONE, AND THE TICKET'S OWN PREMISE WAS WRONG — no release was cut and no binary was shipped, because the code was ALREADY on all three prod voters. Measured 2026-09-09: `/usr/local/bin/yubaba state --help` renders the full R869 help text (\"The off-fleet copy of the raft state: inspect, restore, adopt (R869 / W339)\") on us-east-001, us-west-001 AND us-south-001. state_backup.rs is a tracked file, so peers' earlier hotships — which build the WORKING TREE, not a release (scripts/hotship.sh:2) — carried it out with them. us-east-001 runs 0.8.37-h1 / us-west-001 and us-south-001 run 0.8.36-h16, and all three have it. So the whole ticket collapsed to the drop-in.")
/// @yah:handoff("WHAT WAS ACTUALLY INSTALLED: /etc/systemd/system/yubaba.service.d/80-state-backup.conf on all three prod voters, one line of config — `Environment=YUBABA_STATE_BACKUP_CLUSTER=prod` — plus a comment header explaining why the value is what it is. Environment= only; NO unit's ExecStart was touched (verified with `systemctl show -p ExecStart` after install). CLUSTER NAME IS `prod`, and that was my call, made because nothing in the repo had ever set this variable: the copy is keyed per raft CLUSTER (cluster-state/<name>/latest.json), this camp has exactly two raft groups — this one and the dev group us-west-011/013/014 — so prod/dev is the axis that matters. Two clusters sharing one key would each refuse the other's applied_index as a regression and park forever, which is the failure the name prevents. NO NEW CREDENTIAL: the backup reuses the cert store's bucket, so 80- orders after the existing 50-cert-store.conf and adds nothing secret. All three voters already had both 40-acme-issuer.conf and 50-cert-store.conf, which is the real precondition — acme_issuer::parse_issuer_config owns CertStoreConfig::parse, so a node with a cert store but no issuer silently has no store at all.")
/// @yah:handoff("THE COPY IS LIVE. `yubaba state show` from the leader reads: cluster prod, object yah-cert-store/cluster-state/prod/latest.json, lineage 1, applied index 2806091, taken 7s ago, written by node 2 on yubaba 0.8.36-h16, retired []. Contents: members 3, cluster secrets 7, service placement 0, tenants 0, tenant placement 0, ingress owner Some(\"us-south-001\"), and it reports `dropped on restore locks=1 rollouts=0` — so the lock-drop R869 P2 argued for is not theoretical, there is a live lock in the state right now that a restore would correctly discard. The 7 cluster secrets are the concrete retirement of the old 're-seed secrets from declarations' worry: they are in the copy as AES-256-GCM ciphertext with the KEK still in the fob vault. TENANTS IS 0, so the fencing-epoch hazard this relay exists for has nothing to protect YET — the copy is currently insurance against losing members/placement/ingress_owner/secrets, and becomes insurance against the epoch hazard the moment a tenant is claimed.")
/// @yah:verify("AVAILABILITY MEASURED, NOT ASSERTED. scripts/hotship-probe.sh ran one GET/s at the public yah.dev apex across all three voter restarts INCLUDING the leader: 123 samples, 123x `200/37298`, ZERO failures and zero byte-count variation (a 200 with a different body would have shown as a distinct tally line). Raft never degraded: leader stayed node 2 at term 21 through the whole sequence and all three peers read `live` after every step — the leader restart did not even force an election, because it completed inside the lease window. Applied index advanced normally across the sequence (2806088 -> 2806091). Roll order was followers first, leader last, one node at a time, per the availability floor in scripts/hotship.sh and fleet.md's \"never take two voters down at once\".")
/// @yah:verify("THE R2 PATH IS NOW EXERCISED ON REAL HARDWARE — this was R869's single largest untested span and it is closed for the READ half. BEFORE arming anything, a one-shot `YUBABA_STATE_BACKUP_CLUSTER=prod yubaba state show` on us-east-001 (writing nothing) returned: \"cluster prod has never shipped an off-fleet copy (https://…/yah-cert-store/cluster-state/prod/latest.json does not exist). Nothing to restore from — this is not the same as a copy of an empty cluster.\" That is a definitive 404 rather than a credential error, so it proves the credential read, the R2/S3 transport and the key layout all work against the live bucket — and it is the Option<FenceState>/None-vs-default distinction R869 P1 deliberately built, rendering correctly in production. WRITE half then confirmed by the copy appearing. Both leader and one follower log `off-fleet state backup active {node_id, cluster: \"prod\", interval_secs: 60}` exactly once — the once-per-transition logging P2 designed — and only the leader wrote, which is the leader-gate working.")
/// @yah:verify("NOT PROVEN, stated rather than skipped: that the copy's applied_index ADVANCES on a new commit. I polled for 7 minutes and it held at 2806091, which is CORRECT rather than broken — the cluster is idle, nothing commits, so `StateBackup::store` takes its `applied_index == stored.applied_index` arm and reports Unchanged without writing. Proving the advance needs a real raft write, and manufacturing one against production raft to satisfy a check was not worth it. The next genuine cluster mutation closes this by itself; `yubaba state show` will read a higher index and a fresh `taken at`.")
///
/// @yah:ticket(R869-T2, "The chaos drill: destroy every voter, rebuild from camp + R2, and prove BOTH halves of the acceptance property")
/// @yah:status(review)
/// @yah:at(2026-09-10T06:47:49Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R869)
/// @arch:see(.yah/docs/guides/yubaba-total-loss-recovery.md)
/// @yah:depends_on(R869-T1)
/// @yah:blocked_on(operator)
/// @yah:next("RUN THE RUNBOOK VERBATIM — .yah/docs/guides/yubaba-total-loss-recovery.md, six steps: (1) `yubaba state show` to see how stale the copy is BEFORE trusting it; (2) `yubaba state restore --dir <raft-dir>` on every founding voter, before yubaba starts; (3) `yubaba raft init --member 1=<mesh-ip>:7443@<region> …` on exactly one node; (4) `yubaba-tenant-streamer rebuild` to clear the sink fence, BEFORE any streamer starts — skipping it is silent, because tail_frames refuses and tenant-streamer calls drop_tenant (streamer.rs:153) with nothing to page on; (5) `yubaba state adopt` to re-arm the backup past its own monotonicity guard, without which the rebuilt cluster never backs itself up again; (6) verify. The drill is also the runbook's first real execution — it has never been run end to end, only verified by construction, so a step that reads wrong IS a finding worth more than the drill's headline result.")
/// @yah:next("MEASURE BOTH HALVES SEPARATELY — a drill that only shows (a) proves the least interesting half. (a) THE REBUILT CLUSTER SERVES: it claims a tenant, the granted epoch is snapshot_epoch+1 rather than 1, and the streamer streams instead of being fenced. (b) A DELIBERATELY-RESURRECTED NODE IS REFUSED: bring a survivor back holding its pre-loss epoch and prove tail_frames returns Fenced and it writes nothing. (b) has TWO passing conditions worth measuring apart: refused because the RESTORED EPOCH out-ranks it — available today, and already proven in-process by tests/rebuild_drill.rs::a_rebuilt_cluster_serves_and_a_stale_survivor_is_refused — and refused because the POINTER GENERATION moved, which needs R736-F6 and is not testable yet.")
/// @yah:gotcha("THE RESIDUAL IS REAL AND THE DRILL SHOULD EXERCISE IT DELIBERATELY, not stumble into it. A survivor whose epoch was granted AFTER the last copy shipped out-ranks the restored cluster and legitimately takes the tenant back — the zombie wins and the rebuilt cluster is fenced out of its own tenant. That is pinned as a currently-PASSING test, tests/rebuild_drill.rs::a_survivor_granted_an_epoch_after_the_last_copy_still_outranks_the_restored_cluster, so it is a known bounded-staleness limit rather than a bug: only R736-F6's off-fleet pointer generation closes it, and until then `yubaba state show`'s applied-index age is what bounds the window. Drill it on purpose (claim a tenant twice after the last copy, then lose the fleet) so the operator learns how wide that window is in practice.")
/// @yah:gotcha("NOTHING HAS RUN `rebuild` AGAINST A REAL BUCKET, and that untested span is the credential read plus the R2/S3 transport — not the logic, which is unit-tested against in-memory doubles. `yubaba-tenant-streamer rebuild --dry-run` reads both fences and writes nothing (no pointer bump, no raft entry), so it is the cheapest way to close that span and should be run first; it needs S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY and a streamer config at /etc/yah/tenant-streamer.toml, and NO fleet node runs a streamer today, so standing one up is part of this ticket. Two stated assumptions to check while you are there: `rebuild` reads tenants/<id>/cell.toml from the SAME bucket/endpoint/credentials as the sink at the bucket ROOT (sink.prefix deliberately not applied), and build_pointer_store REFUSES any sink.region that is neither \"auto\" nor empty because R2ObjectStore hardcodes \"auto\" — if a cell is ever pointed at real AWS S3 that refusal is its own ticket.")
/// @yah:gotcha("SCOPE NARROWED BY R869-T1 (shipped 2026-09-09) — re-read before planning the drill. Two things this ticket was carrying are now partly done. (1) The backup is ARMED on all three prod voters (YUBABA_STATE_BACKUP_CLUSTER=prod, /etc/systemd/system/yubaba.service.d/80-state-backup.conf) and a real copy exists at yah-cert-store/cluster-state/prod/latest.json — so the drill now has something to restore FROM, which it did not before. (2) The READ half of 'nothing has run against a real bucket' is closed on real hardware: a one-shot `yubaba state show` against the live bucket returned a definitive 404 pre-arm and the real object post-arm, proving credentials, transport and key layout. What is still unrun is the WRITE-side path under `yubaba-tenant-streamer rebuild` — the pointer-generation CAS and the ClaimTenant lift — because no fleet node runs a tenant streamer. ALSO NOTE: the live cluster currently has tenants=0, so a drill run today cannot exercise the epoch half at all; claim at least one tenant first or the drill proves only the availability half, which its own next() already warns is the least interesting one.")
/// @yah:handoff("DRILLED END TO END AGAINST THE REAL R2 BUCKET, 2026-09-09 — and NOT against the fleet, which was a deliberate call worth reading before re-planning. The drill target is a three-process yubaba cluster on 127.0.0.1:780{1,2,3}, node ids 901/902/903, separate --raft-dirs, --cluster-profile fleet, real raft quorum, pointed at the PRODUCTION yah-cert-store bucket under the cluster name `r869-drill`. That choice buys everything the ticket actually asked for — real credentials, real R2/S3 transport, real conditional-put CAS, a real founding-membership commit, a real tenant with a real streamed sink — at zero blast radius, where destroying the dev raft group (us-west-011/013/014) would have cost three arm build workers and destroying prod would have cost the control plane. Prod was READ ONLY all session and is unchanged: leader 2, term 21 start to finish, applied 2806091 -> 2806093 from its own traffic. All nine objects the drill wrote were deleted afterwards; `cluster-state/` holds exactly `prod/latest.json` again and the drill's own `rebuild --dry-run` re-reads \"no sidecar\" as proof.")
/// @yah:handoff("BOTH HALVES MEASURED SEPARATELY, which was the ticket's central demand. (a) THE REBUILT CLUSTER SERVES: after `state restore` on all three voters and `raft init`, `GET /tenants/<id>` returned epoch 4 — NOT epoch 1, which is the entire point of the ticket and the one number that would have been wrong before R869. `rebuild` then reported `floor=4 epoch=5 claims=1 rounds=1` and the streamer wrote frames 39-41 at epoch 5. (b) A RESURRECTED NODE IS REFUSED — forced deliberately from saved raft dirs, both sub-cases: a survivor at the PRE-copy epoch 4 logged `FENCED — our_epoch=4 current_epoch=5` and wrote nothing, so the restored epochs out-fenced it; a survivor at the POST-copy epoch 6 WON, streamed frames 42-47, and then locked the legitimate cluster out of its own tenant (`our_epoch=5 current_epoch=6`). That second one is the known bounded residual, now reproduced rather than argued, and the escape was measured too: re-running `rebuild` gave `floor=6 epoch=7 claims=2 rounds=1` — one committed raft entry per epoch of gap, no restart from step 1.")
/// @yah:handoff("TWO CODE DEFECTS FOUND AND FIXED, both of which the drill existed to catch and neither of which any test could have. `yubaba state show` PANICKED — \"Cannot drop a runtime in a context where blocking is not allowed\" — before reading a byte, and so did `yubaba-tenant-streamer rebuild`. Mechanism, read rather than guessed: `R2ObjectStore::new` (r2.rs:152) builds a `reqwest::blocking::Client`, whose constructor drops a temporary tokio runtime, and reqwest asserts against that inside an async context (reqwest-0.12.28 blocking/wait.rs:80, `fn enter`). The assert is `#[cfg(debug_assertions)]`, so a RELEASE binary never trips it — which is why the fleet's `/usr/local/bin/yubaba` works and why this was invisible: it fails only from a `cargo build` checkout, i.e. exactly the machine an operator rebuilds from when nothing is installed. FIXED at both sites: main.rs:1782 dispatches `run_state_cmd` through `spawn_blocking`, and tenant-streamer/src/main.rs:206-220 constructs the pointer store inside `spawn_blocking` (its sibling `pointer_step` already did this for the pointer CALLS and the construction one step earlier was missed). Verified by re-running both verbs from DEBUG binaries: exit 0, correct output. NOT fixed and deliberately left: `yubaba domain` and `yubaba holding` have the identical un-wrapped shape and still panic from a debug build — confirmed with `yubaba domain list` — but they are R779/R870's verbs, not R869's, and a comment at main.rs names them.")
/// @yah:handoff("THREE DOC DEFECTS FOUND BY EXECUTION, which is what \"the drill is also the runbook's first real execution\" was supposed to buy. (1) THE RUNBOOK'S STEP 3 DID NOT WORK ON A PROD VOTER. It printed `yubaba raft init --member ...` with no `--daemon`; that flag defaults to `http://127.0.0.1:7443` and the prod voters bind ONLY their mesh IP (fleet.md's trap #2), so the command connection-refuses on precisely the machines the guide is written for. It survived review because the dev raft group binds 0.0.0.0 and would have worked. Fixed, with the reason, and step 6's `raft status` too; also noted that `yubaba state` needs no `--daemon` at all since it talks to the object store. (2) STEP 6'S VERIFY WAS FOOLABLE. `adopt` writes the new lineage itself with `applied_index: 0` and every other field — including `written by <node> on yubaba <version>` — copied from the archived snapshot (state_backup.rs:313-318). So between `adopt` and the leader's next 60 s tick, `state show` renders a plausible copy that no rebuilt node has written a byte of. Step 6 now says to wait for the index to become non-zero, not just for the lineage to move. (3) A new \"What this looks like when it works\" section carries the measured output of all six steps as a table, so an operator mid-incident can tell a healthy step from one that silently did nothing.")
/// @yah:handoff("DISCOVERED WORK OUTSIDE THE TITLE, done in this pass. (1) fleet.md's mesh section asserted flatly that \"this camp sits on 192.168.22.0/22 and has no route to the fleet's 192.168.10.0/24\" and told the reader to attribute any LAN probe result to their own gateway. FALSE when measured: `ipconfig getifaddr en0` = 192.168.10.31 and `curl http://192.168.10.11:7443/health` = 200 from us-west-011 in one hop. That is a fact about where the laptop is plugged in, not about the fleet, and it misleads in BOTH directions — disbelieving a working probe, or blaming a node for your own gateway. Rewritten to name the two commands that settle it rather than to state an answer that rots. This is the THIRD defect R869 has found in fleet.md (P4 found the bare-raft-wipe flag-day, T1 found the hotship prohibition). (2) `oss/yubaba/crates/yubaba/tests/integration_deploy_through_kamaji.rs:80` did not compile — a peer added `WorkloadSpec::files` mid-session and this call site was left behind, which blocked `cargo test -p yubaba --test main`, where this ticket's own `rebuild_drill::*` proofs live. Added `files: vec![]` as a call-site repair only, with a comment saying so. I then saw @Ashguard:coffee (session:967e5e1d, R870) sweeping exactly these sites in the build queue, stopped, left the two remaining `--lib` sites alone, and told them by party.chat what I had touched and why.")
/// @yah:verify("EVERY R2 CALL IN THE DESIGN NOW HAS A REAL-BUCKET EXECUTION BEHIND IT — this was the ticket's named untested span and it is closed. Exercised against the live yah-cert-store bucket, not an in-memory double: the daemon's backup PUT (leader shipped `cluster-state/r869-drill/latest.json`, applied index 11, members 3, tenants 1, ingress owner, locks=1 flagged for drop); `state show` (READ, and additionally from a machine that is NOT a fleet node — the actual recovery posture, since the box being rebuilt is by definition not in a cluster); `state restore --dry-run` and `state restore` x3; `state adopt`, which is the `If-Match` CAS path and archived lineage 1 before minting 2; `rebuild --dry-run` and `rebuild`, both the pointer-store read and the ClaimTenant lift; and `verify_sink`'s conditional-put probe, which had NEVER run against R2 and is the one guard its own module doc says can only exist as a runtime probe against the deployed backend — it passed, so R2 does enforce preconditions at this prefix. Also real, not simulated: 47 turso WAL frames streamed and fenced by the real `turso_backup::stream::tail_frames`, with the epochs legible in the key layout (frames/…004/1-38, …005/39-41, …006/42-47).")
/// @yah:verify("THE MONOTONICITY GUARD FIRED FOR REAL, which is the 2026-08-31 incident's protection observed live rather than asserted in a test. The rebuilt leader logged `off-fleet state backup REFUSED and is now stale: this node has applied only up to 2 but the stored copy is at 11` — exactly once, per the once-per-transition design — and did not overwrite the copy it had just been restored from. `state adopt` then cleared it and the next tick wrote applied index 2 under lineage 2, with `state show --lineage 1` still reading the pre-rebuild copy at index 11. TESTS: `cargo test -p yubaba --test main -- --test-threads=1` = 92 passed / 0 failed, with all four `rebuild_drill::` tests named in the output (that run only became possible after the call-site repair above). `cargo test -p yubaba-tenant-streamer` = 35 passed / 0 failed. `cargo test -p yubaba --lib` DOES NOT COMPILE and I am not claiming it does — two `missing field 'files'` errors from the peer's in-flight `WorkloadSpec` change, in files I did not touch and left to @Ashguard:coffee's sweep. CLIPPY on yubaba-tenant-streamer: clean, the only hit being the pre-existing `parse_list_v2` dead-code warning in yah-object-store. FMT: my two hunks are clean; the seven pre-existing drift sites in tenant-streamer/src/main.rs and the two in config.rs were left alone, per the shared-tree rule that a blanket fmt is how this camp lost 827 uncommitted lines on 2026-08-28.")
/// @yah:verify("WHAT IS STILL UNOBSERVED, named rather than skipped past. Every process ran on one host over loopback, so nothing here exercises a cross-WAN partition, systemd unit ordering, or the mesh-IP bind race — those are node-lifecycle properties owned by `yubaba-heal-service.md` and `roll-a-fleet-node.md`, not properties of this design, and a hardware run would re-prove the fencing arithmetic while adding only those three. The drill also did not exercise the pointer-generation BUMP, only its read: `bump_pointer_generation` correctly reported `Absent` on every run because no `tenants/<id>/cell.toml` exists, which stays true until R736-F6 mints pointer generations — so step 1 of the procedure remains inert in production and half (b) remains bounded-by-staleness rather than absolute. The ticket's two stated assumptions were checked while there: the streamer config used a deliberately NON-EMPTY `sink.prefix` (\"r869-drill-sink\") and `rebuild` did read the pointer from the bucket ROOT while fencing against the sidecar under the prefix, confirming `sink.prefix` is not applied to the pointer lookup; and `build_pointer_store`'s refusal of any region that is neither \"auto\" nor empty was left unexercised because the drill's sink is R2 and correctly used \"auto\".")
/// @yah:gotcha("IF YOU RE-RUN THIS DRILL, `env -i` IS LOAD-BEARING AND NOT TIDINESS. R870-T17 made the demux route publisher, the per-domain issuer AND the tenant-passway reconciler all hang off `YUBABA_CERT_STORE_BUCKET`, each still gated on its own env block (`YUBABA_DEMUX_ROUTES_*`, `YUBABA_DOMAIN_ISSUER_*`/`YUBABA_ACME_*`, tenant_passway's own config + a kamaji). Point a drill daemon at the production bucket with an INHERITED shell and any one of those can switch on against prod's real enrollment set and start taking issuance claims. Build the daemon's environment by hand with exactly five variables. Two smaller traps cost real time and are written into W339 so they do not have to again: the drill tenant's sqlite DB must be created `auto_vacuum=NONE` (turso opens an autovacuum DB READ-ONLY and the failure reads as an unrelated WAL error), and `CoreWalSeam::open` takes an EXCLUSIVE lock on the DB file — an external writer and the streamer cannot hold it at once, so the sequence is write, `kill -9` the writer so the `-wal` survives a clean close, remove the stale `-shm`, then start the streamer.")
/// @yah:gotcha("A HARDWARE DRILL IS STILL AVAILABLE AND IS AN OPERATOR CALL, NOT A GAP THIS TICKET LEFT. What it would add over what shipped is exactly three things — cross-WAN partition behaviour, systemd unit ordering, and the mesh-IP bind race — and none of them is a property of R869's design; all three are already owned by other runbooks. What it would COST is real: the only honest targets are the dev raft group (us-west-011/013/014, currently 0.8.34 with zero services placed, so it would need hot-shipping first and would take three arm build workers offline for the window) or prod (the control plane). If someone wants it, the sequence is in W339 §Open work under the R869-T2 bullet; do NOT read its absence here as something unfinished.")
/// @yah:handoff("HARDWARE DRILL DONE 2026-09-10 (operator chose it over signing off on the in-process run), and it CLOSES the ticket's acceptance rather than adding a footnote to it. Target: the three dev voters us-west-011/013/014. Sequence: hot-shipped all three to 0.8.37-h6 (they were on 0.8.34, predating every line of R869); armed them as cluster `dev` — never `prod`, per the runbook's own precondition that two clusters sharing one key each read the other's applied_index as a regression; stood up the first tenant streamer any fleet node has ever run; claimed a tenant to epoch 4 and streamed 409 real WAL frames to real R2; wiped all three raft dirs under systemd; recovered by running the runbook verbatim. EVERY NUMBER MATCHED THE IN-PROCESS RUN: restored epoch 4 not 1, `rebuild` floor=4 epoch=5 claims=1 rounds=1, backup guard `REFUSED … applied only up to 2 but the stored copy is at 133`, adopt minting lineage 2 with 1 retired, streamer writing frames 410-613 at epoch 5. Half (b) too: pre-copy survivor `FENCED — our_epoch=4 current_epoch=5` writing nothing, post-copy survivor winning with frames 614-979, escape at floor=6 epoch=7 claims=2 rounds=1. TWO MEASUREMENTS WORTH CARRYING: the whole recovery cost ~6 minutes of downtime, and the roll crossed a cluster_protocol boundary 5->7 on all three voters WITHOUT AN ELECTION — term 74 before and after. Prod was never touched: leader 2, term 21, start to finish.")
/// @yah:handoff("THE HARDWARE RUN FOUND TWO BLOCKERS NO SINGLE-PROCESS TEST COULD, and this is the argument for having run it. (1) `yubaba-tenant-streamer` HAD NO DELIVERY PATH TO ANY FLEET NODE — it is in no release recipe, no QED pipeline and no script in the tree, while R869's own runbook step 4 instructs an operator to run it ON A NODE. The runbook was therefore unexecutable as written, and nothing in-process could have shown that. Added to `scripts/hotship.sh`'s app registry (`unit:yubaba-tenant-streamer`, whose missing-unit branch is explicitly not an error, so it installs bytes and says so); a RELEASE path is still owed and is named in W339. (2) THE DEV RAFT GROUP COULD NOT BE RE-FOUNDED AT ALL. All three voters are `region = \"us-west\"`, so `QuorumGeography::MustSpanRegions` refuses that founding set outright; the group survives only because it predates R734-F2 and runs `fleet` with untagged members. That means until today neither this runbook NOR an openraft flag-day could have rebuilt it. All three now declare `--cluster-profile rig` in 40-raft.conf — the accurate statement about three machines on one bench, per cluster_policy.rs's own \"a rig is not a misconfigured fleet\", not a bypass. THIRD, smaller: `hotship.sh`'s leader-last ordering silently did not work on this group. `leader_machine()` matched the raft `members[].addr` against `mesh_ipv4` only, and the dev group advertises `192.168.10.x` while its TOMLs carry `100.64.0.x` — so it fell through to \"leader is outside the target set\" and would have rolled the LEADER FIRST on a `--nodes us-west-013,...` invocation. Now matches every declared address; falsified by re-running with the leader named first and watching it still order last.")
/// @yah:verify("HARDWARE TEARDOWN VERIFIED BY CONTENT, not assumed. The dev group is back on its pre-drill posture: `/etc/yah-cloud/cert-store.env` (the prod bucket credential), `80-state-backup.conf`, `/etc/yah/tenant-streamer.toml`, the tenant DB and the three raft snapshots are all removed from all three nodes; remaining drop-ins re-listed per node to prove it. Cluster healthy after the teardown restarts: leader 13, all three peers `live`, 0.8.37-h6, cluster_protocol 7 / state_epoch 6. TWO THINGS DELIBERATELY LEFT: `--cluster-profile rig` (removing it would restore a group that cannot be re-founded — see the handoff) and `/usr/local/bin/yubaba-tenant-streamer`, a stamped 0.8.37-h6 binary that is harmless unused and is the capability the runbook assumes. Also left, and worth knowing: the tenant `r869-drill-dev` remains in the dev cluster's raft state at epoch 7, because there is no RemoveTenant request — harmless, no streamer references it. BUCKET RESTORED EXACTLY: all 14 objects the hardware drill wrote (12 sink keys + cluster-state/dev/latest.json + its lineage/1) deleted and re-listed; `cluster-state/` holds exactly `prod/latest.json` and the `r869-drill*` prefixes are empty. PROD UNTOUCHED AND RE-CHECKED AT THE END: leader 2, term 21, applied 2806093, copy tracking it.")
/// @yah:handoff("DEV ARMED PERMANENTLY — operator call, 2026-09-10, taken after the drill rather than before it, which is the right order: the decision was made against a group whose recovery had just been demonstrated end to end. All three dev voters carry `/etc/yah-cloud/cert-store.env` (0600, EnvironmentFile not a drop-in, because drop-ins are world-readable and `systemctl cat` prints them) plus `80-state-backup.conf` setting `YUBABA_STATE_BACKUP_CLUSTER=dev`. Verified live: `cluster-state/dev/latest.json`, lineage 1, applied index 4, members 3, tenants 1, ingress owner us-west-013; cluster healthy at leader 13 with all three peers live. Rolled followers-first, leader last. THE CONSEQUENCE THAT NEEDED WRITING DOWN: there are now TWO armed clusters sharing one bucket and one credential, separated only by the key — so `yubaba state restore` with the wrong `YUBABA_STATE_BACKUP_CLUSTER` would seed a machine with the other cluster's members and tenants. The runbook's Preconditions previously asserted the dev group was NOT armed, which was the single most dangerous stale line in it once this landed; it now names which cluster each machine belongs to and says what passing the wrong one does. Two residues, both deliberate and both recorded in W339: the dev group reuses prod's `yah-cert-store-rw` token rather than its own (follow-up, needs Cloudflare account access), and a tenant `r869-drill-dev` at epoch 7 stays in dev's state because there is no `ReleaseTenant` request — inert, and it makes dev's copy exercise the `tenants` field for real.")
/// @yah:cleanup("Mint the dev raft group its own Cloudflare R2 API token instead of reusing prod's bucket-scoped `yah-cert-store-rw` (id 3d7876fb73dd7b6cd025aa6b2c1aff0c). Not a blocker — the token is already scoped to the single `yah-cert-store` bucket and can do nothing anywhere else, which is why reusing it was acceptable — but three dev boxes now hold a credential that can also rewrite prod's cert material and prod's state copy. A `dev`-only token, or one narrowed to the `cluster-state/dev/` prefix if R2 grows prefix scoping, removes that. Needs Cloudflare account access, so it is an operator action rather than an agent one.")
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateBackupConfig {
    pub cluster: String,
    pub interval: Duration,
}

impl StateBackupConfig {
    /// `Ok(None)` when [`CLUSTER_ENV`] is unset — the backup is opt-in.
    ///
    /// A cluster name with no cert-store bucket is a hard error rather than a
    /// silent skip, for the same reason [`crate::cert_store::CertStoreConfig`]
    /// treats a half-configured store that way: an off-fleet copy that quietly
    /// does not exist is discovered during the disaster.
    pub fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let cluster = match get(CLUSTER_ENV) {
            Some(c) if !c.trim().is_empty() => c.trim().to_string(),
            _ => return Ok(None),
        };
        if crate::cert_store::CertStoreConfig::parse(&get)?.is_none() {
            return Err(format!(
                "{CLUSTER_ENV} is set but {} is not — the state backup writes to the same bucket \
                 the cert store uses, so both must be configured together",
                crate::cert_store::BUCKET_ENV
            ));
        }
        let interval = match get(INTERVAL_ENV) {
            Some(s) if !s.trim().is_empty() => s
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("{INTERVAL_ENV} must be whole seconds: {e}"))?,
            _ => DEFAULT_INTERVAL_SECS,
        };
        if interval == 0 {
            return Err(format!("{INTERVAL_ENV} must be greater than zero"));
        }
        Ok(Some(Self {
            cluster,
            interval: Duration::from_secs(interval),
        }))
    }
}

/// Open a [`StateBackup`] straight from the environment — the `yubaba state`
/// verbs' entry point.
///
/// Needs no daemon, no quorum and no leader: the copy is an object, and the
/// machine a rebuild runs from is by definition not part of a cluster yet.
pub fn connect_from_env(get: impl Fn(&str) -> Option<String>) -> Result<StateBackup, String> {
    let cfg = StateBackupConfig::parse(&get)?.ok_or(format!(
        "{CLUSTER_ENV} is unset — name the cluster whose off-fleet copy to act on"
    ))?;
    // `parse` already refused a cluster without a bucket, so this is present.
    let store = crate::cert_store::CertStoreConfig::parse(&get)?
        .expect("cert store config validated by StateBackupConfig::parse");
    let objects = store
        .connect_objects()
        .map_err(|e| format!("opening bucket {}: {e}", store.bucket))?;
    Ok(StateBackup::new(objects, cfg.cluster))
}

/// Start the backup loop. Runs on every node; only the leader ships a copy, so
/// a follower's tick is a no-op — the same shape as [`crate::headroom`].
pub fn spawn(
    node_id: YubabaNodeId,
    raft: crate::raft::YubabaRaft,
    state_machine: crate::raft::store::YubabaStateMachine,
    objects: Arc<dyn ObjectStore>,
    config: StateBackupConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state_machine, objects, config).await;
    })
}

async fn run(
    node_id: YubabaNodeId,
    raft: crate::raft::YubabaRaft,
    state_machine: crate::raft::store::YubabaStateMachine,
    objects: Arc<dyn ObjectStore>,
    config: StateBackupConfig,
) {
    use openraft::async_runtime::watch::WatchReceiver;

    let backup = StateBackup::new(objects, config.cluster.clone());
    tracing::info!(
        node_id,
        cluster = %config.cluster,
        object = %backup.locate_latest(),
        interval_secs = config.interval.as_secs(),
        "off-fleet state backup active"
    );
    let watch = raft.metrics();
    // Logged once per transition, not once per tick: a refusal is a standing
    // condition an operator resolves, and repeating it every minute would bury
    // the line that says it cleared.
    let mut warned_regressed = false;

    loop {
        tokio::time::sleep(config.interval).await;

        if watch.borrow_watched().current_leader != Some(node_id) {
            continue;
        }
        let (state, applied_index) = state_machine.applied_state();
        let Some(applied_index) = applied_index else {
            continue;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match backup.store(&state, applied_index, node_id, now) {
            Ok(Stored::Wrote {
                lineage,
                applied_index,
            }) => {
                warned_regressed = false;
                tracing::debug!(
                    node_id,
                    lineage,
                    applied_index,
                    "off-fleet state backup written"
                );
            }
            Ok(Stored::Unchanged { .. }) | Ok(Stored::Raced) => {}
            Ok(Stored::Regressed { stored, local }) => {
                if !warned_regressed {
                    warned_regressed = true;
                    tracing::error!(
                        node_id,
                        stored_applied_index = stored,
                        local_applied_index = local,
                        object = %backup.locate_latest(),
                        "off-fleet state backup REFUSED and is now stale: this node has applied \
                         only up to {local} but the stored copy is at {stored}. That is what a \
                         wiped raft dir looks like from here, so the copy is being protected \
                         rather than overwritten. If this cluster was deliberately rebuilt, run \
                         `yubaba state adopt` to accept the new incarnation; the pre-rebuild copy \
                         is archived first."
                    );
                }
            }
            Err(e) => tracing::warn!(
                node_id,
                object = %backup.locate_latest(),
                "off-fleet state backup failed (will retry next tick): {e}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::{LockEntry, RolloutRaftRecord};
    use std::collections::BTreeMap;
    use yah_object_store::InMemoryObjectStore;

    fn store() -> (Arc<InMemoryObjectStore>, StateBackup) {
        let mem = Arc::new(InMemoryObjectStore::new());
        let backup = StateBackup::new(mem.clone() as Arc<dyn ObjectStore>, "fleet");
        (mem, backup)
    }

    fn state_with(placement: &[(&str, &str)]) -> YubabaState {
        YubabaState {
            service_placement: placement
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn the_first_copy_starts_lineage_one() {
        let (mem, backup) = store();
        assert!(backup.read_latest().unwrap().is_none());
        assert_eq!(
            backup
                .store(&state_with(&[("web", "m1")]), 7, 1, 100)
                .unwrap(),
            Stored::Wrote {
                lineage: 1,
                applied_index: 7
            }
        );
        assert!(mem.contains_key(&latest_key("fleet")));
        let got = backup.read_latest().unwrap().unwrap();
        assert_eq!(got.lineage, 1);
        assert_eq!(got.applied_index, 7);
        assert_eq!(got.node_id, 1);
        assert_eq!(got.state.service_placement["web"], "m1");
    }

    /// The idle-cluster case: `applied_index` has not moved, so no PUT.
    #[test]
    fn an_unmoved_applied_index_costs_no_write() {
        let (mem, backup) = store();
        backup.store(&state_with(&[]), 7, 1, 100).unwrap();
        let before = mem.get(&latest_key("fleet")).unwrap().unwrap();
        assert_eq!(
            backup
                .store(&state_with(&[("web", "m1")]), 7, 1, 200)
                .unwrap(),
            Stored::Unchanged { applied_index: 7 }
        );
        assert_eq!(mem.get(&latest_key("fleet")).unwrap().unwrap(), before);
    }

    /// THE TEST THIS MODULE EXISTS FOR — the 2026-08-31 incident replayed.
    ///
    /// Three voters had their raft dirs wiped and came back with an empty state
    /// machine. An unguarded backup would have PUT that empty state over the
    /// only surviving copy of the cluster within one tick. Falsify by deleting
    /// the `applied_index < stored.applied_index` arm in [`StateBackup::store`].
    /// MEASURED, not predicted: it fails with `Wrote { lineage: 1,
    /// applied_index: 1 }` and the object is left holding the empty state —
    /// the incident, reproduced in a unit test.
    #[test]
    fn a_wiped_raft_dir_cannot_overwrite_the_good_copy() {
        let (_mem, backup) = store();
        let mut good = state_with(&[("web", "m1"), ("api", "m2")]);
        good.ingress_owner = Some("us-west-001".into());
        backup.store(&good, 193_466, 1, 100).unwrap();

        // The wiped node re-forms and applies its own founding membership.
        assert_eq!(
            backup.store(&YubabaState::default(), 1, 1, 200).unwrap(),
            Stored::Regressed {
                stored: 193_466,
                local: 1
            }
        );
        let still = backup.read_latest().unwrap().unwrap();
        assert_eq!(still.applied_index, 193_466);
        assert_eq!(still.state.service_placement.len(), 2);
        assert_eq!(still.state.ingress_owner.as_deref(), Some("us-west-001"));
    }

    /// And the way out of that refusal: `adopt` archives the good copy where a
    /// restore can still name it, then lets the new incarnation take over.
    #[test]
    fn adopt_archives_the_pre_rebuild_copy_before_yielding_to_the_new_one() {
        let (_mem, backup) = store();
        let good = state_with(&[("web", "m1")]);
        backup.store(&good, 193_466, 1, 100).unwrap();

        assert_eq!(backup.adopt(300).unwrap(), 2);
        assert_eq!(backup.lineages().unwrap(), vec![1]);
        let archived = backup.read_lineage(1).unwrap().unwrap();
        assert_eq!(archived.applied_index, 193_466);
        assert_eq!(archived.state.service_placement["web"], "m1");

        // The rebuilt cluster's small index now wins the guard.
        assert_eq!(
            backup.store(&YubabaState::default(), 1, 2, 400).unwrap(),
            Stored::Wrote {
                lineage: 2,
                applied_index: 1
            }
        );
        // …and the pre-rebuild copy is still exactly where adopt put it.
        assert_eq!(
            backup
                .read_lineage(1)
                .unwrap()
                .unwrap()
                .state
                .service_placement["web"],
            "m1"
        );
    }

    #[test]
    fn adopt_refuses_when_nothing_was_ever_backed_up() {
        let (_mem, backup) = store();
        let err = backup.adopt(100).unwrap_err();
        assert!(
            matches!(err, ObjectError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
    }

    /// Two nodes both believing they lead must not interleave a stale copy over
    /// a fresh one. The loser reports `Raced` and retries on its own clock.
    #[test]
    fn a_lost_compare_and_swap_is_reported_not_forced() {
        let (mem, backup) = store();
        backup.store(&state_with(&[]), 7, 1, 100).unwrap();

        // Hand-build the interleaving: read what node 1 would compare against,
        // then let node 2 land first.
        let stale_etag = mem.etag(&latest_key("fleet")).unwrap().unwrap();
        backup
            .store(&state_with(&[("web", "m9")]), 9, 2, 150)
            .unwrap();
        let fresh = mem.etag(&latest_key("fleet")).unwrap().unwrap();
        assert_ne!(stale_etag, fresh);

        let snapshot = StateSnapshot {
            lineage: 1,
            applied_index: 8,
            taken_at: 200,
            node_id: 1,
            version: "test".into(),
            state: YubabaState::default(),
        };
        let err = mem
            .put_if(
                &latest_key("fleet"),
                serde_json::to_vec(&snapshot).unwrap(),
                Precondition::IfMatch(stale_etag),
                None,
            )
            .unwrap_err();
        assert!(matches!(err, ObjectError::PreconditionFailed(_)));
        // Node 2's copy is intact.
        assert_eq!(
            backup
                .read_latest()
                .unwrap()
                .unwrap()
                .state
                .service_placement["web"],
            "m9"
        );
    }

    /// An object store that lets one write land **between the two reads**
    /// `store` makes, whichever order they are in.
    ///
    /// Keyed on the read *count*, not on which method — that is the whole
    /// point. A double that injected on `get` specifically would pass under
    /// either read order and pin nothing, which is what the first version of
    /// this test did.
    struct WritesAfterTheFirstRead {
        inner: Arc<InMemoryObjectStore>,
        reads: std::sync::atomic::AtomicUsize,
        inject: std::sync::Mutex<Option<Vec<u8>>>,
    }

    impl WritesAfterTheFirstRead {
        /// Serve `served`, then — if this was read #1 — land the racing write.
        fn after_first_read<T>(&self, key: &str, served: T) -> Result<T, ObjectError> {
            if self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                if let Some(bytes) = self.inject.lock().unwrap().take() {
                    self.inner.put(key, bytes)?;
                }
            }
            Ok(served)
        }
    }

    impl ObjectStore for WritesAfterTheFirstRead {
        fn put(&self, key: &str, data: Vec<u8>) -> Result<(), ObjectError> {
            self.inner.put(key, data)
        }
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ObjectError> {
            let served = self.inner.get(key)?;
            self.after_first_read(key, served)
        }
        fn delete(&self, key: &str) -> Result<(), ObjectError> {
            self.inner.delete(key)
        }
        fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, ObjectError> {
            self.inner.list_prefix(prefix)
        }
        fn put_if(
            &self,
            key: &str,
            data: Vec<u8>,
            cond: Precondition,
            cache_control: Option<&str>,
        ) -> Result<String, ObjectError> {
            self.inner.put_if(key, data, cond, cache_control)
        }
        fn etag(&self, key: &str) -> Result<Option<String>, ObjectError> {
            let served = self.inner.etag(key)?;
            self.after_first_read(key, served)
        }
    }

    /// THE READ ORDER IS LOAD-BEARING, and this is the test that says so.
    ///
    /// FALSIFIED, not assumed: swapping the `etag` and `get` calls at the top of
    /// [`StateBackup::store`] fails this with `Wrote { lineage: 1,
    /// applied_index: 6 }` and leaves the object at applied index 6 — the copy
    /// walked backwards from 9. Read `get`-first, the decision is made against
    /// the stale bytes (applied 5, so 6 looks like an advance) and then CAS'd
    /// under the *fresh* ETag, so the CAS succeeds and the monotonicity guard is
    /// bypassed by a race rather than by a missing check. Read `etag`-first, a
    /// write in the gap can only make the CAS fail.
    ///
    /// **A race double must be anchored to sequence position, never to a
    /// method name** — inject after read #N, whichever method that turns out
    /// to be. This is the more expensive mistake, so it is recorded here
    /// rather than left implicit: the first version of this double injected on
    /// `get` specifically, which means it fired at whichever point in the
    /// sequence `get` happened to sit, and so it PASSED UNDER BOTH READ
    /// ORDERS and pinned nothing. A probe that cannot fail against the bad
    /// order is not a probe. Keying on the count is what made it fail.
    #[test]
    fn a_copy_landing_between_the_two_reads_cannot_be_overwritten_by_a_stale_one() {
        let mem = Arc::new(InMemoryObjectStore::new());
        let key = latest_key("fleet");
        let at = |applied_index: u64| {
            serde_json::to_vec(&StateSnapshot {
                lineage: 1,
                applied_index,
                taken_at: 100,
                node_id: 1,
                version: "test".into(),
                state: YubabaState::default(),
            })
            .unwrap()
        };
        mem.put(&key, at(5)).unwrap();

        let racing = Arc::new(WritesAfterTheFirstRead {
            inner: mem.clone(),
            reads: std::sync::atomic::AtomicUsize::new(0),
            inject: std::sync::Mutex::new(Some(at(9))),
        });
        let backup = StateBackup::new(racing as Arc<dyn ObjectStore>, "fleet");

        assert_eq!(
            backup.store(&YubabaState::default(), 6, 1, 200).unwrap(),
            Stored::Regressed {
                stored: 9,
                local: 6
            }
        );
        let survived: StateSnapshot =
            serde_json::from_slice(&mem.get(&key).unwrap().unwrap()).unwrap();
        assert_eq!(survived.applied_index, 9);
    }

    #[test]
    fn a_corrupt_object_is_an_error_not_an_empty_state() {
        let (mem, backup) = store();
        mem.put(&latest_key("fleet"), b"{not json".to_vec())
            .unwrap();
        assert!(backup.read_latest().is_err());
        assert!(backup.store(&YubabaState::default(), 5, 1, 100).is_err());
    }

    /// A restore drops the two maps whose holders are dead by construction.
    #[test]
    fn restorable_drops_leases_and_in_flight_rollouts_and_keeps_the_rest() {
        let mut state = state_with(&[("web", "m1")]);
        state.ingress_owner = Some("us-west-001".into());
        state.locks = BTreeMap::from([(
            "acme-issuer/yah.dev".to_string(),
            LockEntry {
                owner: "1".into(),
                acquired_at: 1_788_850_794,
                ttl_secs: 86_400,
            },
        )]);
        state.rollouts = BTreeMap::from([(
            "web".to_string(),
            RolloutRaftRecord {
                rollout_id: "r1".into(),
                artifact: "web:1".into(),
                status_json: "{}".into(),
                current_step: 1,
                started_at: 1_788_850_000,
                // R118-T5 widened the record with the policy a new leader needs
                // to resume. Irrelevant to this assertion — `restorable` drops
                // the whole map — but it has to be a well-formed record.
                policy: serde_json::from_value(serde_json::json!({
                    "strategy": "linear",
                    "window_seconds": 60,
                    "steps": [{ "mirrors": ["web"], "gate_window_seconds": 0 }]
                }))
                .expect("a linear one-step policy"),
                trigger: serde_json::Value::Null,
                revision: 1,
            },
        )]);

        let restored = restorable(StateSnapshot {
            lineage: 1,
            applied_index: 7,
            taken_at: 100,
            node_id: 1,
            version: "test".into(),
            state,
        });
        assert!(
            restored.locks.is_empty(),
            "a dead node's lease must not survive the rebuild"
        );
        assert!(restored.rollouts.is_empty());
        assert_eq!(restored.service_placement["web"], "m1");
        assert_eq!(restored.ingress_owner.as_deref(), Some("us-west-001"));
    }

    #[test]
    fn the_backup_is_off_until_a_cluster_is_named() {
        assert_eq!(StateBackupConfig::parse(|_| None).unwrap(), None);
    }

    #[test]
    fn a_cluster_without_a_bucket_is_an_error_not_a_silent_skip() {
        let err = StateBackupConfig::parse(|k| (k == CLUSTER_ENV).then(|| "fleet".to_string()))
            .unwrap_err();
        assert!(err.contains(crate::cert_store::BUCKET_ENV), "got {err}");
    }

    #[test]
    fn a_named_cluster_with_a_bucket_parses_and_defaults_its_interval() {
        let cfg = StateBackupConfig::parse(|k| match k {
            CLUSTER_ENV => Some("fleet".into()),
            crate::cert_store::BUCKET_ENV => Some("yah-certs".into()),
            crate::cert_store::ACCOUNT_ID_ENV => Some("acct123".into()),
            _ => None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(cfg.cluster, "fleet");
        assert_eq!(cfg.interval, Duration::from_secs(DEFAULT_INTERVAL_SECS));
    }

    #[test]
    fn a_zero_interval_is_refused() {
        let err = StateBackupConfig::parse(|k| match k {
            CLUSTER_ENV => Some("fleet".into()),
            INTERVAL_ENV => Some("0".into()),
            crate::cert_store::BUCKET_ENV => Some("yah-certs".into()),
            crate::cert_store::ACCOUNT_ID_ENV => Some("acct123".into()),
            _ => None,
        })
        .unwrap_err();
        assert!(err.contains(INTERVAL_ENV), "got {err}");
    }

    /// Lineage keys sort lexicographically in numeric order — zero-padded, so
    /// lineage 2 does not sort before lineage 10 in a bucket listing.
    #[test]
    fn lineage_keys_sort_in_numeric_order() {
        let mut keys = vec![
            lineage_key("fleet", 10),
            lineage_key("fleet", 2),
            lineage_key("fleet", 1),
        ];
        keys.sort();
        assert_eq!(
            keys,
            vec![
                lineage_key("fleet", 1),
                lineage_key("fleet", 2),
                lineage_key("fleet", 10)
            ]
        );
    }
}
