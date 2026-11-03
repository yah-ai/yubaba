//! Each node registers its own member row — R734-F5 (W247 §2).
//!
//! R734-F2 gave [`MemberInfo`] a `region` and taught `POST /raft/initialize` to
//! refuse a founding voter set where one region holds a majority. What it did
//! not give anyone was a *live* answer: the founding gate judges the request
//! payload, so on a running cluster `YubabaState.members` stayed empty and the
//! region tag existed only as a data model. Three pieces of work want the live
//! answer — the leader pin (R734-T4) has to know which voter sits in the anchor
//! region, `/raft/remove-member`'s gate can otherwise judge only voter *count*,
//! and cell tagging (R736-T3) needs region on a cluster rather than at founding.
//!
//! # Why each node writes its own row
//!
//! A node knows its own region and nothing about anyone else's: the label comes
//! from `--region`, which an operator sets from the `region` that machine
//! declares in `.yah/infra/machines/<name>.toml`. So there is no node in a
//! position to write the whole map, and the protocol falls out — every node
//! writes exactly one row, its own, and the map is complete once every node has.
//!
//! # Convergent, not event-driven
//!
//! The loop compares the row this node *would* write against the row the
//! replicated state already holds and writes only on a difference. That makes it
//! idempotent by construction: it converges and then does nothing, so it is safe
//! to run forever on every node, safe to run during an election, and safe to
//! restart. There is no "register once at startup" edge to get wrong — the
//! interesting moments (this node joins membership, a leader appears, an
//! operator changes the region and restarts the process) are all just the
//! comparison coming out different on a later tick.
//!
//! # It must never be able to wedge a boot
//!
//! Registration is additive metadata: the cluster was fully functional with an
//! empty member map and stays fully functional if this loop never succeeds. So
//! every failure here backs off and retries rather than propagating — a node
//! that cannot register yet simply has no row yet, which is the state it was
//! already in. Nothing waits on it and nothing fails because of it.
//!
//! @yah:ticket(R1019-B29, "Prod leader's raft replica holds mesh_tags=None for us-west-001/us-east-001 rows that followers hold; registration never heals it, so role-placed fleet-git cannot be re-placed")
//! @yah:at(2026-10-28T00:38:04Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R1019)
//! @yah:severity(high)
//! @yah:next("Measured 2026-10-27 (Glimmerstone:polaris, R1019-F28 roll): at applied index 2857449, prod leader us-south-001 (node 1) serves /raft/status members.2 (us-west-001) and members.3 (us-east-001) with mesh_tags=null. Followers 2 and 3 serve the full role lists (role:public-uptime,role:best-effort,...); every other field matches. Persistent over 18 samples/90s, with no south restart since 23:15:04Z. INFERENCE (not proven): the rows were applied on south while it ran pre-F28 0.8.49 during the mixed-version roll roll-yubaba-1793140495, and serde(default) dropped the field. plan_registration compares desired against the node's OWN replica (member_registration.rs:154), where rows 2/3 already read Some, so neither node rewrites and the leader's copy never heals.")
//! @yah:next("Impact: replica re-placement runs leader-only (workload_reconcile.rs:1026) and refuses mesh-tags(unknown) (:308). So us-west-001 and us-east-001 are not re-placement targets while south leads. fleet-git (role:public-uptime, on us-east-001) and yah-cloud-admin (on us-west-001) have no fallback; us-south-001 fails fleet-git's 3072 MB floor. Fix options: (1) registration compares against the leader's row (ask the leader, as workload_reconcile.rs:649 does), or re-asserts its row periodically; (2) a one-off forced rewrite of rows 2/3. A leadership transfer off us-south-001 would mask it, but south hosts headscale (fleet skill: avoid step-downs there). Repro: /tmp/f28r-row.sh 2 100.64.0.2 100.64.0.1 100.64.0.3 (operator token via scripts/lib/yubaba-auth.sh, YUBABA_BIN=oss/yubaba/target/aarch64-apple-darwin/release/yubaba).")
//! @yah:handoff("VERIFIED (Glimmerstone:polaris). The divergence is in the replicated LOG itself, not only in the state. South's /var/lib/yah-cloud/raft/raft_log.json has entries 2857342 (SetMember node 3) and 2857343 (SetMember node 2), both term 151, with mesh_tags null. The same indices in us-west-001's and us-east-001's logs carry the full role lists. South's persisted raft_state.json (the state a restart loads) holds rows 2/3 with mesh_tags null. Timeline from roll-yubaba-1793140495: west-001 (22:35:15-46Z) and east (22:35:48-36:28Z) came up on h8 while south was leader on 0.8.49 (term 150). About 60 term-150 SetMember entries for node 2 carry null on all three replicas: the 0.8.49 leader dropped the field at proposal, so the h8 nodes rewrote every 1s. South handed leadership to west-001 (term 151) at 22:36:29Z but ran 0.8.49 until about 22:36:31Z. In that window it received 2857342/2857343 from the h8 leader and decoded them with its pre-F28 type, dropping mesh_tags. The writers' own replicas kept the field, so plan_registration (which compares against the node's OWN replica) read converged. The h9 roll restarted both writers at 23:15-23:16Z after south was already on h9, and the rows stayed null. That proves a plain restart does not re-send SetMember. ROOT CAUSE TO RECORD: F28 added mesh_tags as a #[serde(default)] Option on SetMember/MemberInfo, and the epoch bump was skipped on the theory that 'an old follower drops the field and records None, which fails closed'. It fails closed, but it does not heal: an entry decoded by an old replica stays diverged in that replica's log and state forever, and registration has no path that notices. Field-drop became persistent per-replica divergence on whichever node led next. The real fix is one of: re-register on every start (written here), or bump state_epoch/cluster_protocol so a mixed-version roll goes through the hot-release flag-day path.")
//! @yah:handoff("FIX WRITTEN: member_registration.rs adds recorded_until_written(recorded, written_since_start). run() treats no replica's row as converged until this process has written its row once since start, so every yubaba start re-asserts its row with one raft entry, and that repairs any replica upgraded since. New test a_restarted_node_writes_its_row_once_even_when_its_own_replica_matches. cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib member_registration: 16 passed / 0 failed, EXIT=0 (/tmp/f28r-b29-test-a1.log). member_registration.rs is not a cluster-epoch input (xtask/src/cluster_epochs.rs:297-336). NEXT, in this session: hotship us-west-001 alone (follower), confirm the leader's row 2 carries mesh_tags with quorum and leader stable, then us-east-001. The leader us-south-001 is not restarted.")
//! @yah:handoff("STOPPED BEFORE ANY PROD CHANGE (Glimmerstone:polaris). The live heal is shipping this fix to the two prod followers, and operator decision F4551 holds prod: 'nothing more ships tonight' (recorded in Ashguard:dove's R1021-T6 handoff in headscale_appliance.rs). The yah-gate approval for the us-west-001 hotship dry-run also timed out after 10 min with no answer, so nothing ran against prod. I did not restart us-west-001 alone: the h9 roll (roll-yubaba-1793142882) already restarted both writers at 23:15-23:16Z with south on h9, and the rows stayed null, so a restart without the fix re-sends nothing. Test note: the 16/0 member_registration run was flagged SUSPECT because headscale_appliance.rs changed mid-build, but that diff is comment-only (annotations), so the result stands. The prod leader us-south-001 still holds rows 2/3 mesh_tags=null as of index ~2857460: fleet-git and yah-cloud-admin have no re-placement target while south leads.")
//! @yah:handoff("Tree anchor at handoff: 8ab52acfa4e3666d04aed8775f6099198247c79b — the shared tree as I left it. Diff against it (`git diff 8ab52acfa4e3666d04aed8775f6099198247c79b..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:handoff("SEGMENT 1 (Glimmerstone:polaris, 2026-10-27). One edit: segment 0 had inserted the new test a_restarted_node_writes_its_row_once_even_when_its_own_replica_matches between a_converged_node_stays_converged_through_an_election and that test's doc comment, so the election test lost its doc and the new test's doc began with the election test's '…but a converged node…' text. I moved the new test to sit after the election test, so each test has its own doc again. No logic changed. NOT RE-VERIFIED: run 1 (/tmp/b29-seg1-test-c7.log) was 'lost by the daemon; no exit status' while compiling yah-cloud. Run 2 exited 75 (EX_TEMPFAIL: camp daemon wedged, os error 35). camp.machine showed load about 76 on 15 CPUs. Bash is then gated with the operator away. board.handoff also timed out twice against the wedged daemon, so I wrote this entry by hand and did NOT close the session or change the column. No prod action taken, because operator hold F4551 still applies.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib member_registration — expect 16 passed / 0 failed (segment 0 baseline), including a_restarted_node_writes_its_row_once_even_when_its_own_replica_matches and a_converged_node_stays_converged_through_an_election with its doc comment restored")
//! @yah:gotcha("The fix heals a diverged row on the WRITER's next restart, not when the diverged replica upgrades. In a single roll, a node that restarts before the stale replica upgrades leaves that replica's copy of its row diverged until the next roll. That is enough for the live heal (hotship us-west-001, then us-east-001, with south already on h9). If heal-without-restart is wanted, replace written_since_start with a last-written Instant and re-assert every N minutes, which costs one raft entry per node per period.")
//! @yah:next("When F4551's prod hold lifts (operator call): hotship the tree's yubaba (with recorded_until_written) to us-west-001 ALONE: `PATH=<F28 yah>:$PATH YUBABA_BIN=oss/yubaba/target/aarch64-apple-darwin/release/yubaba bash scripts/hotship.sh --nodes us-west-001 --dry-run`, then for real. Confirm with /tmp/f28r-row.sh 2 100.64.0.2 100.64.0.1 100.64.0.3 that the LEADER's row 2 now carries mesh_tags, that the prod leader is still node 1, and that 3/3 are live. Then do us-east-001 (row 3). Do not restart us-south-001: it leads and hosts headscale. Its own row 1 is already correct everywhere. Check first what else in oss/yubaba the build would carry: main.rs has 15 uncommitted lines from another session, and Ashguard:dove has three unshipped fixes in the tree. Alternatively, ride the fix on prod roll 3 when it happens.")
//! @yah:next("Root-cause follow-up (file or fold into R1021): a #[serde(default)] field added to a raft request without an epoch bump is not just 'fails closed'. A replica that decodes the entry on an old binary diverges in its log and state permanently. Either every such field needs re-assertion on upgrade (this fix covers member rows only), or the cluster-epoch policy must treat a new raft field as a bump. Update the cluster_protocol_history note that justified skipping it (Ashguard:coffee, R1021-T6 gotcha on R1019-F28).")
//! @yah:handoff("SEGMENT 1 (Glimmerstone:polaris, 2026-10-27). One edit: segment 0 had inserted the new test a_restarted_node_writes_its_row_once_even_when_its_own_replica_matches between a_converged_node_stays_converged_through_an_election and that test's doc comment, so the election test lost its doc and the new test's doc began with the election test's '…but a converged node…' text. I moved the new test to sit after the election test, so each test has its own doc again. No logic changed. recorded_until_written and run() are as segment 0 left them (member_registration.rs:187-206, :230, :243-247, :270). NOT RE-VERIFIED: run 1 (/tmp/b29-seg1-test-c7.log) was 'lost by the daemon; no exit status' while compiling yah-cloud. Run 2 exited 75 (EX_TEMPFAIL: camp daemon wedged, os error 35). camp.machine showed load about 76 on 15 CPUs. Bash is then gated with the operator away. Segment 0's 16/0 run covers the logic. The reorder only moves a #[test] fn inside mod tests. No prod action taken, because operator hold F4551 still applies.")
//! @yah:handoff("Tree anchor at handoff: 8ab52acfa4e3666d04aed8775f6099198247c79b — the shared tree as I left it. Diff against it (`git diff 8ab52acfa4e3666d04aed8775f6099198247c79b..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib member_registration — expect 16 passed / 0 failed (segment 0 baseline), now including a_restarted_node_writes_its_row_once_even_when_its_own_replica_matches and a_converged_node_stays_converged_through_an_election with its doc comment restored")
//! @yah:gotcha("The fix heals a diverged row on the WRITER's next restart, not when the diverged replica upgrades. In a single roll, a node that restarts before the stale replica upgrades leaves that replica's copy of its row diverged until the next roll. That is enough for the live heal (hotship us-west-001, then us-east-001, with south already on h9). If heal-without-restart is wanted, replace written_since_start with a last-written Instant and re-assert every N minutes, which costs one raft entry per node per period.")
//! @yah:handoff("SEGMENT 1 (Glimmerstone:polaris, 2026-10-27). One edit: segment 0 had inserted the new test a_restarted_node_writes_its_row_once_even_when_its_own_replica_matches between a_converged_node_stays_converged_through_an_election and that test's doc comment, so the election test lost its doc and the new test's doc began with the election test's '…but a converged node…' text. I moved the new test to sit after the election test, so each test has its own doc again. No logic changed. recorded_until_written and run() are as segment 0 left them (member_registration.rs:187-206, :230, :243-247, :270). NOT RE-VERIFIED: run 1 (/tmp/b29-seg1-test-c7.log) was 'lost by the daemon; no exit status' while compiling yah-cloud. Run 2 exited 75 (EX_TEMPFAIL: camp daemon wedged, os error 35). camp.machine showed load about 76 on 15 CPUs. Bash is then gated with the operator away. Segment 0's 16/0 run covers the logic. The reorder only moves a #[test] fn inside mod tests. No prod action taken, because operator hold F4551 still applies.")
//! @yah:handoff("Tree anchor at handoff: 8ab52acfa4e3666d04aed8775f6099198247c79b — the shared tree as I left it. Diff against it (`git diff 8ab52acfa4e3666d04aed8775f6099198247c79b..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib member_registration — expect 16 passed / 0 failed (segment 0 baseline), now including a_restarted_node_writes_its_row_once_even_when_its_own_replica_matches and a_converged_node_stays_converged_through_an_election with its doc comment restored")
//! @yah:gotcha("The fix heals a diverged row on the WRITER's next restart, not when the diverged replica upgrades. In a single roll, a node that restarts before the stale replica upgrades leaves that replica's copy of its row diverged until the next roll. That is enough for the live heal (hotship us-west-001, then us-east-001, with south already on h9). If heal-without-restart is wanted, replace written_since_start with a last-written Instant and re-assert every N minutes, which costs one raft entry per node per period.")

use std::time::Duration;

use openraft::async_runtime::watch::WatchReceiver;
use tracing::{debug, info, warn};

use crate::raft::{
    client_write_forwarded, MemberInfo, NodeDeclaration, YubabaNodeId, YubabaRaft, YubabaRequest,
    YubabaStateMachine,
};

/// How long to wait before re-checking while there is nothing to do yet — this
/// node is not in membership, or no leader has been elected.
///
/// This loop **polls** rather than subscribing to the raft metrics watch, which
/// is the opposite of what [`leader`](crate::leader) does and is deliberate.
/// Metrics change on every heartbeat and every replication step, and a node with
/// no quorum re-publishes them continuously while it campaigns — so a watcher
/// here would wake tens of times a second to re-evaluate a comparison whose
/// answer changes at most once in the life of the process. Leadership
/// transitions have to be *reacted* to; a converged metadata row does not.
const WAIT_INTERVAL: Duration = Duration::from_secs(1);

/// How long to wait between checks once the recorded row matches. Long, because
/// the only thing that can invalidate a converged row is this node's own
/// membership address changing under it, and nothing waits on the loop noticing.
const SETTLED_INTERVAL: Duration = Duration::from_secs(30);

/// First retry delay after a failed write, doubling up to [`RETRY_MAX`].
const RETRY_MIN: Duration = Duration::from_secs(1);

/// Ceiling on the retry backoff. A node that cannot register keeps trying at
/// this cadence indefinitely: there is no deadline on registration and no
/// failure state to give up into.
const RETRY_MAX: Duration = Duration::from_secs(60);

/// Spawn this node's member-registration loop.
///
/// The task holds a `Raft` handle and runs for the life of the process; abort
/// the returned handle to stop it early. There is deliberately no exit
/// condition: "registered" is not a terminal state, it is a state the loop
/// keeps true.
///
/// `capacity` is R737-F1's schedulable budget for this node, measured rather
/// than declared — see [`NodeCapacity`]. It rides this loop for the same reason
/// `region` does: a node is the only thing that knows it, and the loop is
/// already the convergent publisher of everything a node knows about itself.
///
/// Capacity belongs here specifically *because it barely changes*. It moves when
/// a box is resized and not otherwise, so the converged branch stays converged
/// and the loop stays quiet — the property R734-F5's flake investigation showed
/// is load-bearing. A value that changed at deploy rate would not belong here,
/// which is exactly why [`NodeLoad`](crate::raft::NodeLoad) is derived on the
/// leader instead of published from the node.
///
/// `machine` (R859-F2) rides the same loop for the same reason: a node is the
/// only thing that knows which machine it is, and the value never changes for
/// the life of the box. It is derived by
/// [`derive_machine_name`](crate::leader::derive_machine_name) — the *same*
/// function the leader path uses to write `ingress_owner`, so the two strings
/// are comparable by construction rather than by convention. `None` (no
/// `/etc/hostname`, no `HOSTNAME`) publishes no mapping, which is the
/// already-existing state, not a failure.
///
/// # The public-ingress declaration (R859-F2 phase A)
///
/// `provider`, `location`, `ingress_floating_ip` and `public_address` ride this
/// loop too, and they are the reason it exists at all rather than being nice to
/// have. A fleet node never loads `.yah/infra/machines/`, so the raft leader —
/// the one process that watches `ingress_owner` move and watches nodes die —
/// had no way to turn either observation into an action: no provider to
/// command, no floating IP to move, no address to withdraw from DNS. These four
/// fields are that missing half, and each node is the only thing that knows its
/// own, so they publish exactly the way `region` does.
///
/// They also share `region`'s cheapness property: a box's provider, DC and
/// public address change when it is rebuilt and never otherwise, so the
/// converged branch stays converged and the loop stays quiet.
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    declaration: NodeDeclaration,
    signer: yubaba_auth_token::PeerSigner,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state_machine, declaration, signer).await;
    })
}

/// What the loop should do on this tick.
///
/// A pure verdict, split out of [`run`] for the same reason `plan_transfer` is
/// split out of the transfer-leader handler: the decision is the part worth
/// testing, and testing it should not need a live cluster.
#[derive(Debug, PartialEq, Eq)]
enum Registration {
    /// Nothing to do yet; the payload is the reason, for the trace line.
    Wait(&'static str),
    /// The replicated row already says exactly what this node would write.
    Converged,
    /// Write this row through consensus.
    Write(MemberInfo),
}

/// Decide what to do, given a snapshot of this node's view.
///
/// `self_addr` is this node's address **as raft membership records it** — not
/// the `--bind` value — because that is the address peers actually dial, and a
/// mirror that disagreed with membership about how to reach a node would be
/// worse than no mirror at all. `None` means this node is not in membership yet:
/// a freshly-started node before `raft init`, or one that has been removed.
///
/// The converged check deliberately comes *before* the leader check, so a
/// settled cluster that has just lost its leader does not start logging that it
/// is waiting to do work it already did.
fn plan_registration(
    self_addr: Option<&str>,
    current_leader: Option<YubabaNodeId>,
    recorded: Option<&MemberInfo>,
    declaration: &NodeDeclaration,
) -> Registration {
    let Some(addr) = self_addr else {
        return Registration::Wait("this node is not in raft membership yet");
    };
    let desired = MemberInfo::from_declaration(addr, declaration);
    if recorded == Some(&desired) {
        return Registration::Converged;
    }
    if current_leader.is_none() {
        return Registration::Wait("no leader elected yet — a write would be refused");
    }
    Registration::Write(desired)
}

/// The recorded row [`plan_registration`] may treat as converged: none at all
/// until this process has written its row once since it started.
///
/// R1019-B29. A node's own replica is not the cluster's. Each replica decodes
/// a `SetMember` entry with its own binary, so during a mixed-version roll an
/// older replica drops a `#[serde(default)]` field the entry carried and
/// records `None`. That happened on prod on 2026-10-27: us-south-001, still on
/// a pre-F28 binary for two seconds after handing off leadership, applied the
/// term-151 rows for us-west-001 and us-east-001 without `mesh_tags`, while the
/// two writers' own replicas kept them. Comparing against their own replicas,
/// the writers read converged, and the leader's copy, which is the one the
/// replica reconcile reads, never healed. Rewriting once per start means the
/// next restart onto any binary repairs every replica that has since been
/// upgraded. It costs one raft entry per node start.
fn recorded_until_written(
    recorded: Option<&MemberInfo>,
    written_since_start: bool,
) -> Option<&MemberInfo> {
    recorded.filter(|_| written_since_start)
}

async fn run(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    declaration: NodeDeclaration,
    signer: yubaba_auth_token::PeerSigner,
) {
    let client = match reqwest::Client::builder()
        .timeout(crate::raft::FORWARD_TIMEOUT)
        .build()
    {
        Ok(client) => yubaba_auth_token::PeerClient::new(client, signer),
        Err(e) => {
            // Only reachable if the TLS backend fails to initialise, in which
            // case a follower could never forward. Registration is optional
            // metadata, so this is a warning and an exit, never a panic.
            warn!("member registration: could not build HTTP client, not registering: {e}");
            return;
        }
    };
    let watch = raft.metrics();
    let mut backoff = RETRY_MIN;
    let mut written_since_start = false;

    loop {
        let (self_addr, current_leader) = {
            let metrics = watch.borrow_watched();
            let addr = metrics
                .membership_config
                .membership()
                .get_node(&node_id)
                .map(|node| node.addr.clone());
            (addr, metrics.current_leader)
        };

        let recorded = state_machine.member(node_id);
        let delay = match plan_registration(
            self_addr.as_deref(),
            current_leader,
            recorded_until_written(recorded.as_ref(), written_since_start),
            &declaration,
        ) {
            Registration::Wait(why) => {
                debug!(node_id, why, "member registration waiting");
                WAIT_INTERVAL
            }
            Registration::Converged => {
                backoff = RETRY_MIN;
                SETTLED_INTERVAL
            }
            Registration::Write(row) => match write_row(node_id, &raft, &client, &row).await {
                Ok(()) => {
                    info!(
                        node_id,
                        addr = %row.addr,
                        region = ?row.region,
                        capacity = ?row.capacity,
                        machine = ?row.machine,
                        provider = ?row.provider,
                        public_address = ?row.public_address,
                        "registered this node's raft member row"
                    );
                    written_since_start = true;
                    backoff = RETRY_MIN;
                    // Do not sleep the settled interval on the strength of a
                    // successful write: the row is not *recorded* until the
                    // entry applies here, and the next tick is what confirms it.
                    WAIT_INTERVAL
                }
                Err(e) => {
                    warn!(
                        node_id,
                        "member registration write failed, retrying in {backoff:?}: {e:#}"
                    );
                    let delay = backoff;
                    backoff = (backoff * 2).min(RETRY_MAX);
                    delay
                }
            },
        };

        tokio::time::sleep(delay).await;
    }
}

/// Write `row` for `node_id` through consensus, forwarding to the leader when
/// this node is not it.
///
/// The forwarding itself lives in [`client_write_forwarded`] — this is just the
/// row-to-request shape. The response is discarded because `SetMember` has
/// nothing to say beyond "applied"; a caller that needs the applied value (the
/// ACME issuer's `AcquireLock`) reads the helper's return instead.
async fn write_row(
    node_id: YubabaNodeId,
    raft: &YubabaRaft,
    client: &yubaba_auth_token::PeerClient,
    row: &MemberInfo,
) -> anyhow::Result<()> {
    client_write_forwarded(
        raft,
        client,
        YubabaRequest::SetMember {
            node_id,
            addr: row.addr.clone(),
            region: row.region.clone(),
            capacity: row.capacity,
            machine: row.machine.clone(),
            provider: row.provider.clone(),
            location: row.location.clone(),
            ingress_floating_ip: row.ingress_floating_ip.clone(),
            public_address: row.public_address.clone(),
            taints: row.taints.clone(),
            mesh_tags: row.mesh_tags.clone(),
            sovereign_participation: row.sovereign_participation,
        },
    )
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::raft::NodeCapacity;

    /// What a node declares about itself, narrowed to the three axes these
    /// tests vary. The public-ingress fields (R859-F2 phase A) default to
    /// `None` here and are exercised by
    /// [`the_public_ingress_declaration_is_compared_like_every_other_field`].
    fn decl(region: Option<&str>, capacity: Option<NodeCapacity>, machine: Option<&str>) -> NodeDeclaration {
        NodeDeclaration {
            region: region.map(str::to_string),
            capacity,
            machine: machine.map(str::to_string),
            ..Default::default()
        }
    }

    fn row(addr: &str, region: Option<&str>) -> MemberInfo {
        MemberInfo::from_declaration(addr, &decl(region, None, None))
    }

    fn row_named(addr: &str, region: Option<&str>, machine: &str) -> MemberInfo {
        MemberInfo::from_declaration(addr, &decl(region, None, Some(machine)))
    }

    fn row_with(addr: &str, region: Option<&str>, capacity: NodeCapacity) -> MemberInfo {
        MemberInfo::from_declaration(addr, &decl(region, Some(capacity), None))
    }

    const BOX_16G: NodeCapacity = NodeCapacity {
        memory_mb: 16384,
        cpu_millis: 8000,
    };

    /// A node that raft membership does not know about has nothing to say about
    /// itself yet. Writing anyway would put a row in the map for a node that is
    /// not in the cluster — which is precisely the confusion the map exists to
    /// resolve.
    #[test]
    fn a_node_outside_membership_waits_rather_than_registering() {
        assert_eq!(
            plan_registration(
                None,
                Some(1),
                None,
                &decl(Some("us-west"), None, None),
            ),
            Registration::Wait("this node is not in raft membership yet")
        );
    }

    #[test]
    fn a_node_in_membership_with_no_row_registers() {
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                Some(1),
                None,
                &decl(Some("us-west"), None, None),
            ),
            Registration::Write(row("100.64.0.1:7443", Some("us-west")))
        );
    }

    /// The property that lets this run forever on every node: once the recorded
    /// row matches, the loop stops writing. Without it, every node would put a
    /// raft entry through quorum on every tick, for no change.
    #[test]
    fn a_matching_row_is_converged_and_writes_nothing() {
        let recorded = row("100.64.0.1:7443", Some("us-west"));
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                Some(1),
                Some(&recorded),
                &decl(Some("us-west"), None, None),
            ),
            Registration::Converged
        );
    }

    /// Both halves of the row are compared, not just the address. A node whose
    /// `--region` was corrected and restarted must rewrite its row — otherwise
    /// the fix would need an operator to hand-write raft state.
    #[test]
    fn a_stale_region_on_a_matching_address_still_rewrites() {
        let recorded = row("100.64.0.1:7443", Some("us-east"));
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                Some(1),
                Some(&recorded),
                &decl(Some("us-west"), None, None),
            ),
            Registration::Write(row("100.64.0.1:7443", Some("us-west")))
        );
    }

    /// An untagged node — a rig, or a fleet node whose operator has not set
    /// `--region` yet — still registers its address. Refusing to write a row
    /// without a region would hide the node from the map entirely, which reads
    /// as "not in the cluster" rather than as "region unknown".
    #[test]
    fn an_untagged_node_registers_its_address_anyway() {
        assert_eq!(
            plan_registration(
                Some("127.0.0.1:7443"),
                Some(1),
                None,
                &decl(None, None, None),
            ),
            Registration::Write(row("127.0.0.1:7443", None))
        );
    }

    /// Clearing a region is a real change in the other direction too: a row that
    /// carries a tag the node no longer declares must lose it, or a mis-tagged
    /// node could never be untagged.
    #[test]
    fn dropping_the_region_flag_clears_the_recorded_tag() {
        let recorded = row("127.0.0.1:7443", Some("us-west"));
        assert_eq!(
            plan_registration(
                Some("127.0.0.1:7443"),
                Some(1),
                Some(&recorded),
                &decl(None, None, None),
            ),
            Registration::Write(row("127.0.0.1:7443", None))
        );
    }

    /// With no leader there is nobody to accept the write, so the loop waits
    /// instead of burning its backoff budget on writes that cannot land.
    #[test]
    fn a_leaderless_cluster_is_waited_out_not_written_to() {
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                None,
                None,
                &decl(Some("us-west"), None, None),
            ),
            Registration::Wait("no leader elected yet — a write would be refused")
        );
    }

    /// R737-F1: capacity is the third half of the row and is compared like the
    /// other two. A node that gains RAM and restarts must republish, or the
    /// scheduler bin-packs against a box that no longer exists.
    #[test]
    fn a_resized_box_republishes_its_capacity() {
        let recorded = row_with(
            "100.64.0.1:7443",
            Some("us-west"),
            NodeCapacity {
                memory_mb: 8192,
                cpu_millis: 4000,
            },
        );
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                Some(1),
                Some(&recorded),
                &decl(Some("us-west"), Some(BOX_16G), None),
            ),
            Registration::Write(row_with("100.64.0.1:7443", Some("us-west"), BOX_16G))
        );
    }

    /// The property that keeps the loop quiet once capacity rides it: an
    /// unchanged budget is converged, not a rewrite. This is the whole argument
    /// for putting capacity here and deriving load elsewhere — if this test ever
    /// has to be deleted, the field does not belong in this row.
    #[test]
    fn an_unchanged_capacity_is_converged_and_writes_nothing() {
        let recorded = row_with("100.64.0.1:7443", Some("us-west"), BOX_16G);
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                Some(1),
                Some(&recorded),
                &decl(Some("us-west"), Some(BOX_16G), None),
            ),
            Registration::Converged
        );
    }

    /// A node that cannot measure itself registers its address and region anyway
    /// and leaves capacity unknown, exactly as an untagged node registers without
    /// a region. Refusing to write the row would hide the node from the map,
    /// which reads as "not in the cluster" rather than as "capacity unknown" —
    /// and unknown is what [`MemberInfo::capacity`] makes unschedulable.
    #[test]
    fn a_node_that_cannot_measure_itself_still_registers() {
        assert_eq!(
            plan_registration(
                Some("127.0.0.1:7443"),
                Some(1),
                None,
                &decl(Some("us-west"), None, None),
            ),
            Registration::Write(row("127.0.0.1:7443", Some("us-west")))
        );
    }

    /// R859-F2: the machine tag is compared like every other half of the row, so
    /// a box whose hostname changed under it republishes. That matters more than
    /// it looks — a stale tag does not merely go unused, it maps the *wrong* node
    /// id to an `ingress_owner` string, which is a mis-aimed effector rather than
    /// a missing one.
    #[test]
    fn a_renamed_box_republishes_its_machine_tag() {
        let recorded = row_named("100.64.0.1:7443", Some("us-west"), "vps-4c1efa56");
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                Some(1),
                Some(&recorded),
                &decl(Some("us-west"), None, Some("us-west-001")),
            ),
            Registration::Write(row_named("100.64.0.1:7443", Some("us-west"), "us-west-001"))
        );
    }

    /// …and an unchanged tag is converged, which is what keeps the loop quiet
    /// once the field rides it — the same property `capacity` had to have.
    #[test]
    fn an_unchanged_machine_tag_is_converged_and_writes_nothing() {
        let recorded = row_named("100.64.0.1:7443", Some("us-west"), "us-west-001");
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                Some(1),
                Some(&recorded),
                &decl(Some("us-west"), None, Some("us-west-001")),
            ),
            Registration::Converged
        );
    }

    /// A node that cannot derive its own name registers everything else anyway,
    /// exactly as an untagged node registers without a region. Refusing would
    /// hide the node from the map — "not in the cluster" instead of "name
    /// unknown" — and unknown is what `machine_for_node` already handles.
    #[test]
    fn a_node_that_cannot_name_itself_still_registers() {
        assert_eq!(
            plan_registration(
                Some("127.0.0.1:7443"),
                Some(1),
                None,
                &decl(Some("us-west"), None, None),
            ),
            Registration::Write(row("127.0.0.1:7443", Some("us-west")))
        );
    }

    /// …but a converged node reports converged even while the cluster has no
    /// leader. The check order matters: the other way round, every node in a
    /// cluster mid-election would log that it is waiting to do work that is
    /// already done.
    #[test]
    fn a_converged_node_stays_converged_through_an_election() {
        let recorded = row("100.64.0.1:7443", Some("us-west"));
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                None,
                Some(&recorded),
                &decl(Some("us-west"), None, None),
            ),
            Registration::Converged
        );
    }

    /// R1019-B29: a restarted node rewrites its row once even though its own
    /// replica already matches, because another replica may have dropped a
    /// field from the same entry. After that one write, the converged branch
    /// holds again and the loop stays quiet.
    #[test]
    fn a_restarted_node_writes_its_row_once_even_when_its_own_replica_matches() {
        let own_replica = row("100.64.0.1:7443", Some("us-west"));
        let declared = decl(Some("us-west"), None, None);
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                Some(1),
                recorded_until_written(Some(&own_replica), false),
                &declared,
            ),
            Registration::Write(own_replica.clone())
        );
        assert_eq!(
            plan_registration(
                Some("100.64.0.1:7443"),
                Some(1),
                recorded_until_written(Some(&own_replica), true),
                &declared,
            ),
            Registration::Converged
        );
    }

    /// R859-F2 phase A: the four public-ingress fields are compared like every
    /// other half of the row, and — the part worth pinning — a row that is
    /// identical on every *older* field still rewrites when only the ingress
    /// declaration differs.
    ///
    /// That is the upgrade path. A node running a pre-phase-A binary published
    /// a row with `provider`/`public_address` absent; the same box on the new
    /// binary must republish rather than read its own stale row as converged,
    /// or the leader would hold a member map it cannot withdraw anything from
    /// and the failover would silently do nothing.
    #[test]
    fn the_public_ingress_declaration_is_compared_like_every_other_field() {
        let declared = NodeDeclaration {
            region: Some("us-west".into()),
            machine: Some("us-west-001".into()),
            provider: Some("static".into()),
            public_address: Some("203.0.113.11".into()),
            ..Default::default()
        };
        // The row a pre-phase-A binary would have left behind: same address,
        // same region, same machine tag, no ingress declaration.
        let recorded = row_named("100.64.0.1:7443", Some("us-west"), "us-west-001");
        assert_eq!(
            plan_registration(Some("100.64.0.1:7443"), Some(1), Some(&recorded), &declared),
            Registration::Write(MemberInfo::from_declaration("100.64.0.1:7443", &declared))
        );
        // …and once it lands, the loop goes quiet again — the same property
        // every other field on this row had to have.
        let converged = MemberInfo::from_declaration("100.64.0.1:7443", &declared);
        assert_eq!(
            plan_registration(Some("100.64.0.1:7443"), Some(1), Some(&converged), &declared),
            Registration::Converged
        );
    }
}
