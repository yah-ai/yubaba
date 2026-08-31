//! R118-T1 — a gallery rig's control plane through a power cut: **exactly one
//! owner of a singleton role, and a read path that never stalls.**
//!
//! Part of R118-T1 — the canonical `@yah:ticket` annotation lives in the
//! noisetable camp at `crates/society/core/src/lib.rs`. The design is
//! `.yah/docs/working/W138-installation-as-a-cluster.md` in that same camp.
//!
//! An art installation is a server cluster whose failure mode is somebody
//! kicking a power strip mid-show. Two properties have to survive that, and
//! they pull in opposite directions:
//!
//! 1. **Exactly one owner.** Anything that must happen once — being the egress
//!    gateway, aggregating telemetry, driving a shared output, holding a
//!    hardware handle — must have one answer, and it must still have one answer
//!    after the holder loses power and after it comes back. That is a CP
//!    property and it is what raft is here for.
//! 2. **Sound never stops.** W138's non-negotiable rule: *nothing on the audio
//!    or graph path may synchronously await a raft commit.* Losing quorum
//!    degrades **authority** — nobody can take a role from its holder — never
//!    the ability to read who holds it, and never the audio.
//!
//! These run on [`ClusterPolicy::rig`], not the fleet preset, because the
//! policy sets openraft's election bounds: a rig fails over inside a second
//! where the fleet takes three. Measuring rig behaviour on WAN timings measures
//! the wrong system, so the harness founds these clusters under the rig policy
//! (`test_cluster_with_policy`).
//!
//! Credential-free and containerd-free: real openraft over loopback HTTP with
//! `DummyRuntime`.
//!
//! ```bash
//! cargo test -p yubaba --test main -- rig_singleton_ownership::
//! ```
//!
//! ## What "power loss" means here, and what it does not
//!
//! `kill_node` shuts the node's raft actor down *and* aborts its HTTP server:
//! nothing of that node runs afterwards. That is a power cut. It is
//! deliberately **not** a network partition — a partitioned plinth stays alive
//! and keeps answering a corroborating channel (BLE, in W138's design), and
//! telling those two apart is the whole safety argument for the membership
//! ratchet. The harness has no partition primitive; building one belongs with
//! the detector that consumes it (R118-F7), and the harness doc comment records
//! why the `NetworkDegrade` type that looked like one never was.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cloud::provider::HetznerDriver;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::raft::{YubabaRequest, YubabaResponse};
use yubaba::runtime::DummyRuntime;
use yubaba_test_harness::{test_cluster_with_policy, Cluster};

/// The singleton role under test. On a real rig this is W138's egress gateway:
/// the one node that translates impulse-carried telemetry to the cloud shape.
const ROLE: &str = "rig/egress-gateway";

/// Role lease length. Long enough that nothing here expires by accident — every
/// expiry assertion drives the clock explicitly instead (see [`acquire`]),
/// because `AcquireLock` takes `acquired_at` from the caller.
const ROLE_TTL_SECS: u64 = 300;

/// How long a failover or a convergence may take before the test calls it a
/// hang. The rig preset's election window is 450–900 ms, so this is several
/// elections of headroom on a loaded machine.
const FAILOVER_BUDGET: Duration = Duration::from_secs(10);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs()
}

/// One HTTP client per caller, reused across requests.
///
/// Not a convenience: the latency assertion in
/// [`losing_quorum_degrades_authority_but_never_the_local_read_path`] is only
/// meaningful if it measures the handler rather than connection setup, and a
/// fresh `reqwest::Client` per request means a fresh pool and a fresh TCP
/// connection every time. The timeout is what turns "the read path stalled"
/// into a failed test instead of a hung suite.
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client")
}

/// `POST /raft/write` an `AcquireLock` for `owner`, stamped `at` (unix secs).
///
/// `acquired_at` is caller-supplied by design — the domain owns "when" (see
/// [`YubabaRequest::AcquireLock`]) — so a test drives lease expiry by choosing
/// the stamp rather than by sleeping out a real TTL.
///
/// The request is built from the real [`YubabaRequest`] rather than hand-rolled
/// JSON, so a field rename upstream breaks this at compile time instead of
/// turning it into a silently-mismatched body.
///
/// Returns `Ok(granted)`, or `Err(body)` when the cluster could not commit —
/// which on a quorum-less cluster is the correct outcome, not a test failure.
async fn acquire(
    http: &reqwest::Client,
    base_url: &str,
    owner: &str,
    at: u64,
) -> Result<bool, String> {
    let request = YubabaRequest::AcquireLock {
        key: ROLE.to_string(),
        owner: owner.to_string(),
        ttl_secs: ROLE_TTL_SECS,
        acquired_at: at,
    };
    let resp = http
        .post(format!("{base_url}/raft/write"))
        .json(&serde_json::json!({ "request": request }))
        .send()
        .await
        .map_err(|e| format!("POST /raft/write: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!(
            "HTTP {status}: {}",
            resp.text().await.unwrap_or_default()
        ));
    }
    match resp
        .json::<YubabaResponse>()
        .await
        .map_err(|e| format!("decoding YubabaResponse: {e}"))?
    {
        YubabaResponse::LockGranted(granted) => Ok(granted),
        // Any other variant means this test sent something other than
        // AcquireLock — a bug here, not in the daemon.
        other => Err(format!("expected LockGranted, got {other:?}")),
    }
}

/// [`acquire`] against a cluster that is supposed to have quorum: a transport
/// or commit failure is a test failure, not an outcome to fold into the
/// assertion.
async fn acquire_with_quorum(http: &reqwest::Client, base_url: &str, owner: &str, at: u64) -> bool {
    acquire(http, base_url, owner, at)
        .await
        .unwrap_or_else(|e| panic!("AcquireLock against a healthy quorum failed: {e}"))
}

/// One `GET /cluster/singletons` reading — the locally-applied view a realtime
/// sibling process consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SingletonView {
    owner: Option<String>,
    applied_index: Option<u64>,
}

async fn read_singletons(http: &reqwest::Client, base_url: &str) -> Result<SingletonView, String> {
    let resp = http
        .get(format!("{base_url}/cluster/singletons"))
        .send()
        .await
        .map_err(|e| format!("GET /cluster/singletons: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("decoding singleton body: {e}"))?;
    Ok(SingletonView {
        owner: body["roles"][ROLE]["owner"].as_str().map(str::to_string),
        applied_index: body["applied_index"].as_u64(),
    })
}

/// Poll every listed node until all of them report `expected` as the owner.
///
/// Replication is asynchronous, so "the followers agree" is a converges-to
/// claim, not an immediate one. What must never happen — and what the
/// assertions around this call check — is a node reporting a *different* owner
/// rather than a lagging one.
async fn await_agreement(
    http: &reqwest::Client,
    cluster: &Cluster,
    nodes: &[usize],
    expected: &str,
    budget: Duration,
) {
    let deadline = Instant::now() + budget;
    loop {
        let mut views = Vec::new();
        for &idx in nodes {
            views.push((
                idx,
                read_singletons(http, &cluster.yubaba(idx).base_url).await,
            ));
        }
        if views
            .iter()
            .all(|(_, v)| matches!(v, Ok(v) if v.owner.as_deref() == Some(expected)))
        {
            return;
        }
        assert!(
            Instant::now() <= deadline,
            "nodes {nodes:?} did not all report owner {expected:?} within {budget:?}; \
             last views were {views:?}",
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── 1. Exactly one owner, across a power cycle ────────────────────────────────

/// A singleton role has **exactly one owner** before, during and after the
/// holder loses power — and the plinth that went dark does not resurrect its
/// stale claim when it comes back.
///
/// The sequence is a gallery evening:
///
/// - `plinth-1` takes the egress-gateway role. Every node — leader and
///   followers alike — reports it, from locally-applied state.
/// - The leader loses power. Two of three plinths remain, so quorum holds and
///   the cluster elects a new leader.
/// - `plinth-2` tries to take the role while the lease is still live and is
///   **refused**. This is the assertion that a role does not become ownerless
///   just because its holder went dark: the survivors still name `plinth-1`.
/// - The lease expires (driven by the caller's clock, not by sleeping) and
///   `plinth-2` takes it. Ownership moved exactly once.
/// - The dead plinth is powered back on. It replays the log and reports
///   `plinth-2` — **not itself**. A node that came back believing it still held
///   a role it had lost is the two-owners bug this ticket exists to rule out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn singleton_role_has_exactly_one_owner_across_a_power_cycle() {
    let http = client();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let mut cluster: Cluster =
        test_cluster_with_policy(&provider, DummyRuntime, 3, ClusterPolicy::rig())
            .await
            .expect("3-node rig cluster");

    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let survivors: Vec<usize> = (0..3).filter(|i| *i != leader).collect();

    // ── the role is taken, and every node can see it ──────────────────────────
    let t0 = now_secs();
    let leader_url = cluster.yubaba(leader).base_url.clone();
    assert!(
        acquire_with_quorum(&http, &leader_url, "plinth-1", t0).await,
        "an unheld role must be grantable",
    );
    await_agreement(&http, &cluster, &[0, 1, 2], "plinth-1", FAILOVER_BUDGET).await;

    // Non-vacuity: followers answer off their own applied state rather than
    // forwarding to the leader. If this were a forward, killing the leader
    // below would take the read path down with it — so the later assertions
    // would be testing the leader's liveness, not the local-read rule.
    for &idx in &survivors {
        let view = read_singletons(&http, &cluster.yubaba(idx).base_url)
            .await
            .expect("a follower answers /cluster/singletons itself");
        assert!(
            view.applied_index.is_some(),
            "node {idx} must report the log index its answer is true as of, got {view:?}",
        );
    }

    // ── the plinth holding leadership loses power ─────────────────────────────
    cluster.kill_node(leader).await.expect("power cut");

    let new_leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("two of three plinths still hold quorum, so leadership must move");
    assert!(
        survivors.contains(&new_leader),
        "leadership went to node {new_leader}, which is the plinth that lost power",
    );
    let new_leader_url = cluster.yubaba(new_leader).base_url.clone();

    // ── a live lease is not up for grabs just because its holder went dark ────
    assert!(
        !acquire_with_quorum(&http, &new_leader_url, "plinth-2", t0 + ROLE_TTL_SECS / 2).await,
        "a role whose lease is still live must not be handed to a second owner",
    );
    for &idx in &survivors {
        let view = read_singletons(&http, &cluster.yubaba(idx).base_url)
            .await
            .expect("a survivor answers");
        assert_eq!(
            view.owner.as_deref(),
            Some("plinth-1"),
            "node {idx} must still name the original holder — a dark node is not a released role",
        );
    }

    // ── the lease expires and ownership moves exactly once ───────────────────
    assert!(
        acquire_with_quorum(&http, &new_leader_url, "plinth-2", t0 + ROLE_TTL_SECS).await,
        "past the lease the role must be re-grantable, or a dead plinth wedges it forever",
    );
    await_agreement(&http, &cluster, &survivors, "plinth-2", FAILOVER_BUDGET).await;

    // ── the dead plinth comes back and must not resurrect its claim ──────────
    cluster.restart_node(leader).await.expect("power restored");
    await_agreement(&http, &cluster, &[0, 1, 2], "plinth-2", FAILOVER_BUDGET).await;
}

// ── 2. Losing quorum degrades authority, never the read path ──────────────────

/// The audio-path proxy's polling period. Faster than any control rate a rig
/// actually runs, so a stall shows up as many missed reads rather than one.
const POLL_PERIOD: Duration = Duration::from_millis(5);

/// A single poll may take this long before the test calls the read path
/// stalled. Generous by orders of magnitude for a loopback GET off an in-memory
/// map — the claim is *bounded*, not *fast*, and a bound this loose still fails
/// instantly if the handler ever starts awaiting a commit, which cannot
/// complete at all without quorum.
const READ_DEADLINE: Duration = Duration::from_millis(500);

/// How long to keep reading after quorum is destroyed.
const OUTAGE_WINDOW: Duration = Duration::from_secs(3);

/// **Losing quorum must never stall the read path.**
///
/// A task stands in for the rig's audio process: it polls
/// `GET /cluster/singletons` on one plinth at control rate for the whole test,
/// recording the slowest response and every failure. Meanwhile two of three
/// plinths lose power, which destroys quorum — the cluster can no longer commit
/// anything at all.
///
/// Afterwards:
///
/// - every poll succeeded, and the slowest was inside [`READ_DEADLINE`];
/// - every poll named the same owner, and it is the one committed while the
///   cluster was healthy — the survivor coasts on last-known-good;
/// - and, the part that makes the test non-vacuous, a **write** attempted in
///   the same window fails. Without it, "reads kept working" would be equally
///   satisfied by a cluster that never lost quorum in the first place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn losing_quorum_degrades_authority_but_never_the_local_read_path() {
    let http = client();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let mut cluster: Cluster =
        test_cluster_with_policy(&provider, DummyRuntime, 3, ClusterPolicy::rig())
            .await
            .expect("3-node rig cluster");

    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the founding cluster elects a leader");

    let leader_url = cluster.yubaba(leader).base_url.clone();
    assert!(
        acquire_with_quorum(&http, &leader_url, "plinth-1", now_secs()).await,
        "the role is taken while the cluster is healthy",
    );
    await_agreement(&http, &cluster, &[0, 1, 2], "plinth-1", FAILOVER_BUDGET).await;

    // Kill one follower and the leader: one of three plinths left, quorum gone.
    // The follower goes first so the cluster passes through a still-quorate 2/3
    // state rather than losing everything at once.
    let doomed_follower = (0..3)
        .find(|i| *i != leader)
        .expect("a 3-node cluster has a follower");
    let survivor = (0..3)
        .find(|i| *i != leader && *i != doomed_follower)
        .expect("one of three plinths survives");
    let survivor_url = cluster.yubaba(survivor).base_url.clone();

    // ── the audio-path proxy ─────────────────────────────────────────────────
    let stop = Arc::new(AtomicBool::new(false));
    let poller = {
        let stop = Arc::clone(&stop);
        let url = survivor_url.clone();
        tokio::spawn(async move {
            let http = client();
            let mut worst = Duration::ZERO;
            let mut owners: Vec<Option<String>> = Vec::new();
            let mut failures: Vec<String> = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let started = Instant::now();
                match read_singletons(&http, &url).await {
                    Ok(view) => owners.push(view.owner),
                    Err(e) => failures.push(e),
                }
                worst = worst.max(started.elapsed());
                tokio::time::sleep(POLL_PERIOD).await;
            }
            (worst, owners, failures)
        })
    };

    // ── the power strip goes ─────────────────────────────────────────────────
    cluster
        .kill_node(doomed_follower)
        .await
        .expect("power cut on a follower");
    cluster
        .kill_node(leader)
        .await
        .expect("power cut on the leader");

    // Keep reading through the window in which a quorum-hungry implementation
    // would be blocking on a commit that can never land.
    tokio::time::sleep(OUTAGE_WINDOW).await;

    // ── authority is gone: the write must not succeed ─────────────────────────
    let write = acquire(&http, &survivor_url, "plinth-3", now_secs()).await;
    assert!(
        !matches!(write, Ok(true)),
        "a lone survivor of a 3-node cluster has no quorum and must not be able to grant a \
         singleton role — got {write:?}. If this ever passes, the cluster did not actually lose \
         quorum and the read assertions below prove nothing.",
    );

    stop.store(true, Ordering::Relaxed);
    let (worst, owners, failures) = poller.await.expect("poller task");

    assert!(
        failures.is_empty(),
        "the control-plane read path failed {} times while quorum was lost. The rule is that \
         losing quorum degrades authority, never the ability to read who holds a role. \
         First failures: {:?}",
        failures.len(),
        &failures[..failures.len().min(3)],
    );
    assert!(
        owners.len() > 100,
        "the poller should have taken hundreds of readings across the outage, got {} — it is not \
         exercising the window it claims to",
        owners.len(),
    );
    assert!(
        owners.iter().all(|o| o.as_deref() == Some("plinth-1")),
        "every reading through the outage must name the holder committed while the cluster was \
         healthy; the survivor coasts on last-known-good rather than forgetting",
    );
    assert!(
        worst < READ_DEADLINE,
        "slowest control-plane read through the outage was {worst:?}, over the {READ_DEADLINE:?} \
         budget — something on this path is waiting on the cluster",
    );
}
