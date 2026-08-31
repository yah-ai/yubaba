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

use std::time::Duration;

use openraft::async_runtime::watch::WatchReceiver;
use tracing::{debug, info, warn};

use crate::raft::{
    MemberInfo, NodeCapacity, YubabaNodeId, YubabaRaft, YubabaRequest, YubabaStateMachine,
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

/// Timeout for the forward-to-leader HTTP write.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(10);

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
pub fn spawn(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    region: Option<String>,
    capacity: Option<NodeCapacity>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, raft, state_machine, region, capacity).await;
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
    region: Option<&str>,
    capacity: Option<NodeCapacity>,
) -> Registration {
    let Some(addr) = self_addr else {
        return Registration::Wait("this node is not in raft membership yet");
    };
    let desired = MemberInfo {
        addr: addr.to_string(),
        region: region.map(str::to_string),
        capacity,
    };
    if recorded == Some(&desired) {
        return Registration::Converged;
    }
    if current_leader.is_none() {
        return Registration::Wait("no leader elected yet — a write would be refused");
    }
    Registration::Write(desired)
}

async fn run(
    node_id: YubabaNodeId,
    raft: YubabaRaft,
    state_machine: YubabaStateMachine,
    region: Option<String>,
    capacity: Option<NodeCapacity>,
) {
    let client = match reqwest::Client::builder().timeout(FORWARD_TIMEOUT).build() {
        Ok(client) => client,
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

        let delay = match plan_registration(
            self_addr.as_deref(),
            current_leader,
            state_machine.member(node_id).as_ref(),
            region.as_deref(),
            capacity,
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
                        "registered this node's raft member row"
                    );
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
/// A follower cannot `client_write`; openraft answers `ForwardToLeader` and
/// hands back the leader's `BasicNode`, whose `addr` is the same mesh address
/// the raft transport dials. So the forward needs no extra discovery — it POSTs
/// the identical request to `/raft/write` on that address.
async fn write_row(
    node_id: YubabaNodeId,
    raft: &YubabaRaft,
    client: &reqwest::Client,
    row: &MemberInfo,
) -> anyhow::Result<()> {
    let req = YubabaRequest::SetMember {
        node_id,
        addr: row.addr.clone(),
        region: row.region.clone(),
        capacity: row.capacity,
    };
    match raft.client_write(req.clone()).await {
        Ok(_) => Ok(()),
        Err(openraft::error::RaftError::APIError(
            openraft::error::ClientWriteError::ForwardToLeader(fwd),
        )) => {
            let Some(leader) = fwd.leader_node.as_ref() else {
                // Known-no-leader, or a leader whose node record this replica has
                // not seen. Both are transient and both are the caller's retry.
                anyhow::bail!(
                    "not the leader and no leader address to forward to \
                     (leader_id={:?})",
                    fwd.leader_id
                );
            };
            let url = format!("http://{}/raft/write", leader.addr);
            let resp = client
                .post(&url)
                .json(&serde_json::json!({ "request": req }))
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("forwarding member row to leader at {url}: HTTP {status}: {body}");
            }
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(addr: &str, region: Option<&str>) -> MemberInfo {
        MemberInfo {
            addr: addr.to_string(),
            region: region.map(str::to_string),
            capacity: None,
        }
    }

    fn row_with(addr: &str, region: Option<&str>, capacity: NodeCapacity) -> MemberInfo {
        MemberInfo {
            capacity: Some(capacity),
            ..row(addr, region)
        }
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
            plan_registration(None, Some(1), None, Some("us-west"), None),
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
                Some("us-west"),
                None
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
                Some("us-west"),
                None
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
                Some("us-west"),
                None
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
            plan_registration(Some("127.0.0.1:7443"), Some(1), None, None, None),
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
            plan_registration(Some("127.0.0.1:7443"), Some(1), Some(&recorded), None, None),
            Registration::Write(row("127.0.0.1:7443", None))
        );
    }

    /// With no leader there is nobody to accept the write, so the loop waits
    /// instead of burning its backoff budget on writes that cannot land.
    #[test]
    fn a_leaderless_cluster_is_waited_out_not_written_to() {
        assert_eq!(
            plan_registration(Some("100.64.0.1:7443"), None, None, Some("us-west"), None),
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
                Some("us-west"),
                Some(BOX_16G)
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
                Some("us-west"),
                Some(BOX_16G)
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
            plan_registration(Some("127.0.0.1:7443"), Some(1), None, Some("us-west"), None),
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
                Some("us-west"),
                None
            ),
            Registration::Converged
        );
    }
}
