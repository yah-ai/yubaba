//! The election gate: a node may campaign only while a quorum would elect it
//! (R936-B6).
//!
//! # The storm this exists to stop
//!
//! This was written while openraft's own Pre-Vote was switched off (R734-T3).
//! R734-T6 turned it back on against openraft 0.10.0-alpha.35 (see
//! [`RaftTiming::to_openraft_config`](crate::cluster_policy::RaftTiming::to_openraft_config)),
//! so both mechanisms now run and both enforce the same guarantee. What follows
//! describes the pre-T6 world the gate was built for. Without Pre-Vote,
//! a voter that stops hearing its leader does exactly one thing on every
//! election timeout: `Engine::elect()` bumps its **own** term and campaigns,
//! whether or not anyone can hear it. A voter off the mesh for 30 s on the WAN
//! timings (1.5-3 s) walks its term forward by 10-20. That alone is harmless.
//! The damage is what happens when it comes back, because openraft 0.10.0-alpha.30
//! gives the returning node two ways to depose a healthy leader:
//!
//! 1. The leader's next heartbeat to it is refused with `HigherVote`, and the
//!    leader's `Notification::HigherVote` handler calls `update_vote(higher)`,
//!    adopting the inflated term and stepping down (`raft_core.rs`,
//!    `Notification::HigherVote`).
//! 2. Its next vote request reaches the leader, whose *own* vote lease is set
//!    once at `establish_leader` and never refreshed, so after
//!    `election_timeout_max` the leader grants a higher-term vote request and
//!    steps down (`engine_impl.rs`, `handle_vote_req`). Followers are protected
//!    by their lease on the leader; the leader is not.
//!
//! Either way the healthy cluster restarts its election at the returning
//! node's term, and a node that flaps on and off the mesh repeats this on
//! every flap. That is the second storm R936-B6 measured on prod: term 43 ->
//! 121 in ~55 s with quorum present.
//!
//! # What the gate does
//!
//! Every heartbeat interval, a follower sends a Pre-Vote probe for `term + 1`
//! to every other voter over the node's own raft transport, and sets
//! openraft's runtime `enable_elect` to whether a quorum (every half of a joint
//! config) would grant it. `enable_elect` gates only the election *timer*
//! (`handle_tick_election`); a leadership transfer and an operator's
//! `trigger().elect()` bypass it, so `yah mesh failover` is unaffected.
//!
//! A probe persists nothing on the peer (`handle_pre_vote_req` is read-only),
//! so this is Pre-Vote's guarantee — no term bump without a winnable quorum —
//! built outside openraft's engine, where the alpha.30 bug that forced R734-T3
//! (`handle_pre_vote_resp` calling `elect()` on a node that is still leader)
//! cannot be reached: the real election still starts from the tick path, which
//! skips a leader.
//!
//! One deliberate difference from textbook Pre-Vote: a reply from a peer that
//! is **itself the committed leader** never counts as a grant, even when
//! openraft says it would grant. That closes hole 2 above. A leader answering
//! the probe proves there is a live leader this node can reach, which is
//! exactly when it must not campaign.
//!
//! An isolated node's probes all fail, so it stops campaigning and its term
//! stays where it was. When it rejoins, its term is at or below the cluster's,
//! and the leader's first heartbeat simply brings it back.
//!
//! # Failover cost
//!
//! When the leader really dies, the survivors' leases on it expire after
//! `election_timeout_max` (openraft's leader lease). Their probes to each other
//! start succeeding then, and the gate opens on its next pass. That adds at most
//! one heartbeat interval plus one probe round trip to a failover that was
//! already waiting out the lease.
//!
//! @yah:ticket(R936-B15, "Under load with the election gate on, raft_member_registration lopsided-removal test hangs past 900s")
//! @yah:status(review)
//! @yah:at(2026-10-10T22:32:33Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R936)
//! @yah:severity(medium)
//! @yah:next("Reproduce with the loaded loop recipe on R734-T6 (the /tmp/r734t6-measure.sh shape: a filter of raft_member_registration::, 6 concurrent processes, 4 burners), then check whether the gate keeps probing voters removed from membership, or holds enable_elect=false on a node left without a winnable quorum after the removal.")
//! @yah:gotcha("Found by R734-T6's measurement, 2026-09-26. `raft_member_registration::a_removal_that_would_leave_a_lopsided_quorum_is_refused` hung until the 900s kill in 2 of 32 gate-ON runs (all `raft_*` suites, 2 test processes plus 4-8 CPU burners), once with openraft Pre-Vote on and once with it off, in both debug and release. Both hung runs logged ~16.5k pre_vote calls, vs ~2.5k in completed runs of the same length. There were 0 hangs in 48 gate-OFF runs under the same or heavier load. That points at the gate (probe loop after a membership removal?). This is INFERENCE from counts, not established. Passes unloaded. Logs: /tmp/r734t6-runs/relB/run1.log and /tmp/r734t6-runs/dbgC/run8.log (scratch, may be gone).")
//! @yah:handoff("2026-10-10 (Glimmerstone): GATE LOOKS EXONERATED BY READING; the hang site is an un-timed HTTP await. Every await in the test is an HTTP call through yubaba_test_harness::http(), which has NO request timeout, so 'hang' = a handler that never returned. Prime suspect is POST /raft/remove-member removing [1,3]. A probe showed node 1 (the founder) led in 30/30 fresh fleets, so this test almost always removes the SITTING LEADER. openraft =0.10.0-alpha.35 resolves a client_write only on apply/purge/truncate on THAT node, never on step-down. A removed leader hands off ~115-140 ms after the uniform config commits (probe), and nobody replicates to a node outside membership, so a write it accepted but had not seen commit before the hand-off can never resolve. Two such writes exist: the handler's row-clearing client_write (~50 ms each unloaded, two in series, finishing ~110 ms, about 30 ms of margin that load erases), and change_membership's own uniform step. The ~16.5k pre_votes in the hung runs fit the removed nodes' gates probing for the whole 900 s: a symptom of elapsed time, not the cause. FIX WRITTEN (uncommitted): client_write_forwarded bounds its local client_write by FORWARD_TIMEOUT (raft/mod.rs), and raft_remove_member clears rows through client_write_forwarded, so a stepped-down self-remover forwards to the new leader instead of failing or stranding (lib.rs). New test raft_member_registration::a_write_this_node_can_never_apply_is_bounded_not_awaited_forever passes: a leader whose followers are killed accepts a write that can never commit. NOT YET REPRODUCED: 96/96 loaded single-test runs passed on the unfixed binary. The R734-T6 shape is running now on the unfixed binary, with /raft/status dumped from every live node on a hang.")
//! @yah:handoff("VERDICT: the election gate is NOT the cause, and the hang does not reproduce on the 2026-10-10 tree. Gate: it only flips enable_elect and cannot block an HTTP handler; with it on, elections get rarer. Every await in the hung test is an HTTP call through the harness client, which had no timeout, so the 'hang' was a handler that never returned. Unfixed binary, 0 of 128 loaded runs hung: 96 single-test runs (8 concurrent, 12 burners) plus 32 runs of every raft_ suite in the R734-T6 shape (2 processes, 4 burners).")
//! @yah:handoff("SUSPECTED MECHANISM (inference, not reproduced): openraft =0.10.0-alpha.35 completes a client_write only on local apply/purge/truncate, never on a leadership change. Node 1 led in 30 of 30 probed fleets, so this test removes the SITTING leader. A removed leader hands off 115-140 ms after the uniform config commits (probed). A write still uncommitted at the hand-off can never apply on a node outside membership. Exposed: the handler's row-clearing writes, and change_membership's own uniform step. 21 probed boundary writes all resolved unloaded, so this needs heavy starvation.")
//! @yah:handoff("LANDED: (1) client_write_forwarded bounds its local client_write by FORWARD_TIMEOUT (oss/yubaba/crates/yubaba-consensus/src/raft/mod.rs), protecting every caller: acme AcquireLock, registration, rollout, ratchet. (2) raft_remove_member clears rows through client_write_forwarded (oss/yubaba/crates/yubaba/src/lib.rs), so a stepped-down self-remover forwards to the new leader instead of leaving stale_rows. (3) yubaba_test_harness::http() has a 120 s per-request timeout, HTTP_REQUEST_TIMEOUT (oss/yubaba/crates/yubaba-test-harness/src/lib.rs), so a future hang fails naming its URL instead of a silent 900 s kill. (4) New test raft_member_registration::a_write_this_node_can_never_apply_is_bounded_not_awaited_forever. (5) cluster-epochs re-recorded, judged (b) NOT BREAKING on both axes, epoch integers unchanged.")
//! @yah:handoff("DISCOVERED + FIXED: raft_promote_voter::fleet_policy_refuses_to_promote_a_learner flaked in 5 of 42 loaded runs: it read liveness once right after add-learner and got peer 4 'unknown' (raft_promote_voter.rs:253). It now polls up to 15 s for every peer to read live. ALSO: an orphaned solo_node doc comment had drifted onto http() in the harness lib.rs; moved back onto `pub mod solo_node`.")
//! @yah:verify("cargo test -p yubaba --test main -- raft_member_registration:: raft_peer_auth::  -> 10 passed (2026-10-10)")
//! @yah:verify("cargo test -p yubaba-consensus --lib -- raft::  -> 87 passed")
//! @yah:verify("Loaded R734-T6 shape on the final binary (all raft_ suites, 2 concurrent processes, 4 `yes` burners, 600 s hang cutoff): 10 of 10 runs green, 69/69 each, 0 hangs, no request reached the 120 s bound. Script: ~/ss/scratch-b15/loop.sh (scratch).")
//! @yah:verify("cargo run -p xtask -- cluster-epochs  -> 'protocol surfaces match their recorded hashes'. cluster_protocol surface 504d4b70 -> 12f3c5a5, state_epoch surface 4e991636 -> df1d177b, both epochs unchanged.")
//! @yah:verify("rustfmt --check: no diffs inside the changed hunks (the files carry pre-existing unformatted regions elsewhere). The last edit, a whitespace-only rustfmt fix to raft_member_registration.rs, landed after the final loaded build.")
//! @yah:gotcha("change_membership's uniform step is still an UNBOUNDED await in raft_remove_member. Do not bound it by dropping the future with tokio::time::timeout: openraft drives the joint->uniform second step from the API caller's future, so cancelling between the steps can leave the cluster in a JOINT config. The safe shape is tokio::spawn(change_membership) plus a bounded await of the JoinHandle, answering 504 'outcome unknown, read /raft/status'. Not done: nothing measured this path stranding. The harness timeout now turns it into a 2-minute named failure if it ever does.")
//! @yah:handoff("VERDICT: the election gate is NOT the cause, and the hang does not reproduce on the 2026-10-10 tree. On the unfixed binary, 0 of 128 loaded runs hung, including 32 in the R734-T6 shape. The 'hang' was an HTTP handler that never returned: the harness client had no timeout. Fixes landed: client_write_forwarded's local write is bounded; remove-member clears rows via the forwarding helper; the harness HTTP client has a 120 s timeout; a new regression test. A discovered raft_promote_voter flake is fixed. Details in the following handoff entries.")
//! @yah:handoff("GATE + REPRO: the gate only flips enable_elect and cannot block an HTTP handler; with it on, elections get rarer. Every await in the hung test is an HTTP call through yubaba_test_harness::http(), which had no timeout. Unfixed binary, 0 of 128 loaded runs hung: 96 single-test runs (8 concurrent, 12 burners) plus 32 runs of every raft_ suite in the R734-T6 shape (2 processes, 4 burners).")
//! @yah:handoff("SUSPECTED MECHANISM (inference, not reproduced): openraft =0.10.0-alpha.35 completes a client_write only on local apply/purge/truncate, never on a leadership change. Node 1 led in 30 of 30 probed fleets, so this test removes the SITTING leader. A removed leader hands off 115-140 ms after the uniform config commits (probed). A write still uncommitted at the hand-off can never apply on a node outside membership. Exposed: the handler's row-clearing writes and change_membership's uniform step. 21 probed boundary writes all resolved unloaded.")
//! @yah:handoff("LANDED: (1) client_write_forwarded bounds its local client_write by FORWARD_TIMEOUT (yubaba-consensus/src/raft/mod.rs), covering every caller: acme AcquireLock, registration, rollout, ratchet. (2) raft_remove_member clears rows through client_write_forwarded (yubaba/src/lib.rs), so a stepped-down self-remover forwards to the new leader instead of leaving stale_rows. (3) The harness http() has a 120 s per-request timeout, HTTP_REQUEST_TIMEOUT (yubaba-test-harness/src/lib.rs). (4) New test raft_member_registration::a_write_this_node_can_never_apply_is_bounded_not_awaited_forever. (5) cluster-epochs re-recorded, judged (b) NOT BREAKING on both axes, epoch integers unchanged.")
//! @yah:handoff("DISCOVERED + FIXED: raft_promote_voter::fleet_policy_refuses_to_promote_a_learner flaked in 5 of 42 loaded runs: it read liveness once right after add-learner and got peer 4 'unknown' (raft_promote_voter.rs:253). It now polls up to 15 s for every peer to read live. Also moved an orphaned solo_node doc comment off http() back onto `pub mod solo_node` in the harness lib.rs.")
//! @yah:verify("cargo test -p yubaba --test main -- raft_member_registration:: raft_peer_auth::  -> 10 passed; cargo test -p yubaba-consensus --lib -- raft::  -> 87 passed (2026-10-10)")
//! @yah:verify("Loaded R734-T6 shape on the final binary (all raft_ suites, 2 concurrent processes, 4 burners, 600 s cutoff): 10 of 10 green, 69/69 each, 0 hangs, no request reached the 120 s bound.")
//! @yah:verify("cargo run -p xtask -- cluster-epochs  -> surfaces match. cluster_protocol surface 504d4b70 -> 12f3c5a5, state_epoch surface 4e991636 -> df1d177b, both epochs unchanged. rustfmt --check: no diffs inside the changed hunks.")
//! @yah:gotcha("change_membership's uniform step is still an UNBOUNDED await in raft_remove_member. Do not bound it by dropping the future: openraft drives the joint->uniform second step from the caller's future, so cancelling between the steps can leave the cluster in a JOINT config. The safe shape is tokio::spawn plus a bounded await of the JoinHandle, answering 504 'outcome unknown'. Not done: nothing measured this path stranding. The harness timeout now makes it a 2-minute named failure if it ever does.")

use std::collections::BTreeSet;
use std::time::Duration;

use openraft::async_runtime::watch::WatchReceiver;
use openraft::network::{NetVote, RPCOption, RaftNetworkFactory};
use openraft::raft::{VoteRequest, VoteResponse};
use openraft::type_config::alias::VoteOf;
use openraft::vote::RaftLeaderId;
use openraft::ServerState;

use super::{YubabaNodeId, YubabaRaft, YubabaRaftConfig as TC};
use crate::cluster_policy::RaftTiming;

/// Whether `grants` (which must include this node's own grant) is a quorum of
/// every config in `joint`.
///
/// A joint config (mid membership change) needs a majority in each half,
/// the same rule openraft applies to a real election. An empty config set is
/// never a quorum.
pub fn quorum_would_elect(
    joint: &[BTreeSet<YubabaNodeId>],
    grants: &BTreeSet<YubabaNodeId>,
) -> bool {
    !joint.is_empty()
        && joint
            .iter()
            .all(|cfg| cfg.iter().filter(|id| grants.contains(id)).count() * 2 > cfg.len())
}

/// Whether `target`'s reply to a probe counts toward the quorum.
///
/// A grant counts, except from a peer that reports itself as the committed
/// leader. See the module docs for why the leader's grant is discarded.
pub fn probe_grants(target: YubabaNodeId, resp: &VoteResponse<TC>) -> bool {
    let answered_as_leader =
        resp.vote.is_committed() && *resp.vote.leader_id().node_id() == target;
    resp.vote_granted && !answered_as_leader
}

/// One pass of the gate: `Some(open)` for a follower or candidate voter in a
/// multi-voter cluster, `None` when the gate does not apply (a leader, a
/// learner, a single voter, or a raft that has shut down).
pub async fn evaluate<N>(raft: &YubabaRaft, network: &mut N, probe_timeout: Duration) -> Option<bool>
where
    N: RaftNetworkFactory<TC>,
    N::Network: Send,
{
    let metrics = raft.metrics().borrow_watched().clone();
    let me = metrics.id;
    let membership = metrics.membership_config.clone();
    let joint = membership.get_joint_config().clone();
    let voters: BTreeSet<YubabaNodeId> = membership.voter_ids().collect();

    if metrics.state == ServerState::Leader || !voters.contains(&me) || voters.len() <= 1 {
        return None;
    }

    let last_log_id = raft
        .with_raft_state(|st| st.log_ids.last().cloned())
        .await
        .ok()?;
    let req = VoteRequest::<TC>::new(VoteOf::<TC>::new(metrics.current_term + 1, me), last_log_id);

    let mut probes = Vec::new();
    for peer in voters.iter().copied().filter(|id| *id != me) {
        let Some(node) = membership.get_node(&peer) else {
            continue;
        };
        let mut client = network.new_client(peer, node).await;
        let req = req.clone();
        probes.push(async move {
            let reply = tokio::time::timeout(
                probe_timeout,
                client.pre_vote(req, RPCOption::new(probe_timeout)),
            )
            .await;
            match reply {
                Ok(Ok(resp)) => probe_grants(peer, &resp).then_some(peer),
                // Unreachable, errored or slow: never a grant. An isolated
                // node must not assemble a quorum out of silence.
                _ => None,
            }
        });
    }

    let mut grants: BTreeSet<YubabaNodeId> = futures_join_all(probes).await.into_iter().flatten().collect();
    grants.insert(me);
    Some(quorum_would_elect(&joint, &grants))
}

/// Run the gate for `raft` until its core shuts down.
///
/// Probes go out through `network`, the same transport factory raft itself
/// uses, so the gate sees exactly the reachability openraft would.
pub fn spawn_election_gate<N>(raft: YubabaRaft, mut network: N, timing: RaftTiming) -> tokio::task::JoinHandle<()>
where
    N: RaftNetworkFactory<TC> + Send + 'static,
    N::Network: Send,
{
    // Probe as often as the leader heartbeats, and give each round the same
    // budget, so the gate settles well inside `election_timeout_min`
    // (heartbeat < election_timeout_min is validated by openraft).
    let interval = Duration::from_millis(timing.heartbeat_interval_ms.max(1));
    // A fixed cadence, deliberately NOT a wake on `raft.metrics().changed()`.
    // openraft's `report_metrics` sends on the metrics watch after EVERY core
    // event (raft_core.rs, unconditional `tx_metrics.send`), including this
    // gate's own `with_raft_state` call and every Pre-Vote a node answers. A
    // metrics wake therefore fed itself, and followers' probes woke each other:
    // measured on the dev group under 0.8.42-h7 at 340-930 Pre-Votes/s per
    // node, with yubaba at 82% CPU on a Pi. `probes_run_at_the_heartbeat_cadence`
    // pins the rate.
    tokio::spawn(async move {
        loop {
            // Also the shutdown check: every raft API fails once the core has
            // stopped, which ends the task instead of keeping the handle alive.
            if raft.with_raft_state(|_| ()).await.is_err() {
                return;
            }
            let open = evaluate(&raft, &mut network, interval).await.unwrap_or(true);
            raft.runtime_config().elect(open);
            tokio::time::sleep(interval).await;
        }
    })
}

/// Await every probe concurrently. A handful of futures, so a plain
/// `FuturesUnordered` would be overkill and `futures` is not a dependency of
/// this crate.
async fn futures_join_all<F, T>(futs: Vec<F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handles: Vec<_> = futs.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(v) = h.await {
            out.push(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[u64]) -> BTreeSet<u64> {
        ids.iter().copied().collect()
    }

    #[test]
    fn a_lone_voter_of_three_is_not_a_quorum() {
        assert!(!quorum_would_elect(&[set(&[1, 2, 3])], &set(&[3])));
        assert!(quorum_would_elect(&[set(&[1, 2, 3])], &set(&[2, 3])));
    }

    #[test]
    fn a_joint_config_needs_a_majority_in_both_halves() {
        let joint = [set(&[1, 2, 3]), set(&[3, 4, 5])];
        assert!(!quorum_would_elect(&joint, &set(&[1, 2, 3])));
        assert!(quorum_would_elect(&joint, &set(&[2, 3, 4])));
        assert!(!quorum_would_elect(&[], &set(&[1])));
    }

    #[test]
    fn a_grant_from_the_live_leader_does_not_count() {
        let leader_vote = VoteOf::<TC>::new_committed(7, 1);
        let from_leader = VoteResponse::<TC>::new(leader_vote.clone(), None, true);
        assert!(
            !probe_grants(1, &from_leader),
            "a leader that answers proves there is a leader to follow"
        );
        // The same committed vote reported by a follower (lease expired) is an
        // ordinary grant.
        assert!(probe_grants(2, &from_leader));
        let refused = VoteResponse::<TC>::new(VoteOf::<TC>::new(7, 2), None, false);
        assert!(!probe_grants(2, &refused));
    }
}
