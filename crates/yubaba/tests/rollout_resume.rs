//! R118-T5 — **a rollout survives the death of the node driving it.**
//!
//! Part of R118-T5 — the canonical `@yah:ticket` annotation lives in the
//! noisetable camp at `crates/society/core/src/lib.rs`; the design is
//! `.yah/docs/working/W138-installation-as-a-cluster.md` in that same camp.
//!
//! W138's rollout case is not "an update failed" — that is what gates and
//! rollback are for. It is: the node *driving* a fleet image update loses
//! power halfway through. Before this ticket that left the rig split across
//! two image generations with no record anywhere that an update had ever
//! started, because the rollout lived in an `Arc<Mutex<HashMap>>` in the
//! process that died with it.
//!
//! Two claims, and the second is the one that costs something to get right:
//!
//! 1. A new leader can **see** the rollout — the replication half.
//! 2. A new leader **finishes** it, unprompted — the resume half. Replicated
//!    state that nobody picks up is a rollout that is stopped forever, only
//!    now with a paper trail.
//!
//! And the converse, which is how the resume half avoids buying (1) and (2) at
//! the price of a worse bug: a node coming back from the dead must **not**
//! re-drive a rollout the cluster already finished.
//!
//! The last two tests cover the operator's channel into a rollout somebody
//! else's node is driving. That channel was *nominally* present before R118-T5
//! and did nothing: an override wrote a status, and the engine never read one.
//! Committing rollout state is what makes it reachable — the override lands in
//! raft, and the engine watching the record acts on it wherever it is running.
//!
//! Both run the real [`rollout::supervisor::spawn`] on every node, exactly as
//! `main.rs` does. Starting it only on the leader would test a loop production
//! does not run — and would quietly make the failover case pass for the wrong
//! reason, since the node that becomes leader is the one that would then have
//! been given a supervisor.
//!
//! ```bash
//! cargo test -p yubaba --test main -- rollout_resume:: --test-threads=2
//! ```

use std::time::Duration;

use cloud::provider::HetznerDriver;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::rollout::supervisor::{spawn as spawn_supervisor, SupervisorConfig};
use yubaba::runtime::DummyRuntime;
use yubaba_test_harness::{test_cluster_with_policy, Cluster};

/// Failover budget. The rig preset's election window is 450–900 ms, so this is
/// several elections of headroom on a loaded machine.
const FAILOVER_BUDGET: Duration = Duration::from_secs(10);

/// How long the surviving cluster gets to finish a resumed rollout. The policy
/// below spends 6 s in gate windows, so this is ~4x the work.
const COMPLETION_BUDGET: Duration = Duration::from_secs(25);

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client")
}

/// A rollout slow enough to still be in flight when the leader is killed, and
/// short enough that the survivors finish it inside [`COMPLETION_BUDGET`].
///
/// Three steps × a 2 s gate window. The gate is real (it goes through
/// `PrometheusGateEvaluator`'s caller) but the fixture configures no Prometheus
/// URL, so it auto-passes in stub mode — this test is about who drives, not
/// about what the metric says.
fn slow_rollout_body() -> serde_json::Value {
    serde_json::json!({
        "artifact": "release:rig-image@v2",
        "policy": {
            "strategy": "linear",
            "window_seconds": 600,
            "gates": [
                { "metric": "http_5xx_rate", "condition": "< 0.01", "window": "5m" }
            ],
            "steps": [
                { "mirrors": ["plinth-1"], "gate_window_seconds": 2 },
                { "mirrors": ["plinth-2"], "gate_window_seconds": 2 },
                { "mirrors": ["plinth-3"], "gate_window_seconds": 2 }
            ]
        },
        "trigger": { "source": "R118-T5 harness" }
    })
}

/// The same shape with no gate windows at all — used where the point is a
/// *finished* rollout rather than an interrupted one.
fn fast_rollout_body() -> serde_json::Value {
    serde_json::json!({
        "artifact": "release:rig-image@v3",
        "policy": {
            "strategy": "linear",
            "window_seconds": 600,
            "steps": [
                { "mirrors": ["plinth-1"], "gate_window_seconds": 0 },
                { "mirrors": ["plinth-2"], "gate_window_seconds": 0 }
            ]
        },
        "trigger": { "source": "R118-T5 harness" }
    })
}

/// One long step and one instant one.
///
/// The shape that makes "the override reached the engine" measurable as a
/// *duration*: an engine that only learns of an override between steps cannot
/// finish this rollout for two minutes, and one that watches its gate window
/// finishes it in milliseconds.
fn long_window_rollout_body() -> serde_json::Value {
    serde_json::json!({
        "artifact": "release:rig-image@v4",
        "policy": {
            "strategy": "linear",
            "window_seconds": 600,
            "steps": [
                { "mirrors": ["plinth-1"], "gate_window_seconds": 120 },
                { "mirrors": ["plinth-2"], "gate_window_seconds": 0 }
            ]
        },
        "trigger": { "source": "R118-T5 harness" }
    })
}

/// Two steps that finish on their own in about six seconds — short enough that
/// an engine ignoring a rollback would visibly complete inside the window this
/// test holds it under observation.
fn interruptible_rollout_body() -> serde_json::Value {
    serde_json::json!({
        "artifact": "release:rig-image@v5",
        "policy": {
            "strategy": "linear",
            "window_seconds": 600,
            "steps": [
                { "mirrors": ["plinth-1"], "gate_window_seconds": 3 },
                { "mirrors": ["plinth-2"], "gate_window_seconds": 3 }
            ]
        },
        "trigger": { "source": "R118-T5 harness" }
    })
}

/// The supervisor loops for one cluster, aborted together when the test ends.
///
/// Held by the test rather than pushed into the harness for the same reason
/// `raft_tenant_placement.rs`'s `Schedulers` is: the harness has no business
/// knowing that some tests also run an actuator.
struct Supervisors(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Supervisors {
    fn drop(&mut self) {
        for s in &self.0 {
            s.abort();
        }
    }
}

impl Supervisors {
    /// Start the real supervisor on **every** node, as `main.rs` does.
    fn start(cluster: &Cluster, policy: ClusterPolicy) -> Self {
        let mut me = Self(Vec::new());
        for idx in 0..cluster.node_count() {
            me.attach(cluster, idx, policy);
        }
        me
    }

    /// Give node `idx` a supervisor bound to its *current* raft handle.
    ///
    /// Needed again after `restart_node`: the harness re-opens raft from disk,
    /// so the handle the old supervisor held belongs to a process that no
    /// longer exists.
    fn attach(&mut self, cluster: &Cluster, idx: usize, policy: ClusterPolicy) {
        let (Some(raft), Some(sm), Some(node_id)) = (
            cluster.raft(idx),
            cluster.cluster_state(idx),
            cluster.node_id(idx),
        ) else {
            return;
        };
        self.0.push(spawn_supervisor(
            node_id,
            raft.clone(),
            sm.clone(),
            // No Prometheus in the fixture: gates run in stub mode.
            SupervisorConfig::new(policy.timing, None),
        ));
    }
}

/// `POST /v1/rollouts`, returning the accepted rollout id.
async fn create(http: &reqwest::Client, base_url: &str, body: serde_json::Value) -> String {
    let resp = http
        .post(format!("{base_url}/v1/rollouts"))
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST /v1/rollouts: {e}"));
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::ACCEPTED,
        "rollout not accepted: {}",
        resp.text().await.unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().await.expect("decoding accept body");
    body["rollout_id"]
        .as_str()
        .expect("an accepted rollout has an id")
        .to_string()
}

/// `POST /v1/rollouts/{id}/override` — the operator channel.
async fn override_action(http: &reqwest::Client, base_url: &str, id: &str, action: &str) {
    let resp = http
        .post(format!("{base_url}/v1/rollouts/{id}/override"))
        .json(&serde_json::json!({ "action": action, "by": "R118-T5 harness" }))
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST /v1/rollouts/{id}/override: {e}"));
    assert!(
        resp.status().is_success(),
        "override '{action}' rejected: {}",
        resp.text().await.unwrap_or_default()
    );
}

/// One node's view of a rollout, read from its own applied state.
#[derive(Debug, Clone)]
struct RolloutView {
    kind: String,
    current_step: u64,
    steps: usize,
}

impl RolloutView {
    fn is_in_flight(&self) -> bool {
        self.kind == "pending" || self.kind == "running"
    }
}

/// `GET /v1/rollouts/{id}` — `None` when this node has no such record, which
/// on a follower can simply mean it has not applied the entry yet.
async fn read(http: &reqwest::Client, base_url: &str, id: &str) -> Option<RolloutView> {
    let resp = http
        .get(format!("{base_url}/v1/rollouts/{id}"))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    Some(RolloutView {
        kind: body["status"]["kind"].as_str()?.to_string(),
        current_step: body["current_step"].as_u64()?,
        steps: body["policy"]["steps"].as_array()?.len(),
    })
}

/// `GET /v1/rollouts/{id}` as the raw body — every field, including the
/// `revision` a writer must guard on. [`read`] narrows to what most assertions
/// want; this is for the test that has to *rebuild a write* from what it read.
async fn read_full(
    http: &reqwest::Client,
    base_url: &str,
    id: &str,
) -> Option<serde_json::Value> {
    let resp = http
        .get(format!("{base_url}/v1/rollouts/{id}"))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json().await.ok()
}

/// Poll `base_url` until its record for `id` satisfies `done`, returning the
/// view that did. Panics on timeout with the last view seen.
async fn await_view(
    http: &reqwest::Client,
    base_url: &str,
    id: &str,
    budget: Duration,
    what: &str,
    done: impl Fn(&RolloutView) -> bool,
) -> RolloutView {
    let deadline = tokio::time::Instant::now() + budget;
    let mut last = None;
    loop {
        let view = read(http, base_url, id).await;
        if let Some(v) = &view {
            if done(v) {
                return v.clone();
            }
        }
        last = view.or(last);
        assert!(
            tokio::time::Instant::now() <= deadline,
            "{base_url} never reported {what} for {id}; last view was {last:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// **The ticket, in one test.**
///
/// Start a rollout, pull the power on the node driving it, and require the
/// cluster to finish it anyway.
///
/// Ordered so that no assertion can pass vacuously:
///
/// 1. The rollout is *observably in flight* before the kill — a rollout that
///    had already finished would make everything below true for free.
/// 2. A new leader is elected and **sees** the record, with the policy in it.
///    Without the policy the record would say a rollout exists and not what it
///    is, which is why R118-T5 widened `RolloutRaftRecord`.
/// 3. The rollout reaches `succeeded` with nobody asking it to, and with the
///    node that started it still dark.
/// 4. `current_step` never went backwards on the way there — the observable
///    form of "the rig never played two image generations".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_leader_finishes_a_rollout_the_dead_leader_was_driving() {
    let http = client();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let policy = ClusterPolicy::rig();
    let mut cluster: Cluster = test_cluster_with_policy(&provider, DummyRuntime, 3, policy)
        .await
        .expect("3-node rig cluster");
    let _supervisors = Supervisors::start(&cluster, policy);

    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let leader_url = cluster.yubaba(leader).base_url.clone();

    let id = create(&http, &leader_url, slow_rollout_body()).await;

    // (1) The leader's supervisor claimed it and an engine is driving. Nothing
    // below means anything if the rollout is already over.
    await_view(
        &http,
        &leader_url,
        &id,
        FAILOVER_BUDGET,
        "a running rollout",
        |v| v.kind == "running",
    )
    .await;

    // ── the power goes out under the node driving the rollout ─────────────────
    cluster.kill_node(leader).await.expect("kill the leader");
    let survivors: Vec<usize> = (0..3).filter(|i| *i != leader).collect();

    let new_leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the survivors elect a new leader");
    assert_ne!(new_leader, leader, "the dead node must not still lead");
    assert!(survivors.contains(&new_leader));
    let new_leader_url = cluster.yubaba(new_leader).base_url.clone();

    // (2) It sees the rollout, and sees enough of it to act. Asserted before
    // waiting for completion so a failure here is legible as "replication" and
    // not as "resume".
    let inherited = await_view(
        &http,
        &new_leader_url,
        &id,
        FAILOVER_BUDGET,
        "the inherited rollout",
        |_| true,
    )
    .await;
    assert_eq!(
        inherited.steps, 3,
        "a resuming leader must inherit the POLICY, not just the fact that a \
         rollout exists — without the steps it cannot drive anything"
    );
    assert!(
        inherited.is_in_flight(),
        "the rollout must still be unfinished at handover, or this test proves \
         nothing about resuming; saw {inherited:?}"
    );

    // (3) and (4). Poll to completion, watching the step counter as we go.
    let mut high_water = inherited.current_step;
    let deadline = tokio::time::Instant::now() + COMPLETION_BUDGET;
    let final_view = loop {
        let view = read(&http, &new_leader_url, &id)
            .await
            .expect("the new leader keeps answering for a rollout it holds");
        assert!(
            view.current_step >= high_water,
            "current_step went backwards ({high_water} -> {}) — that is what a \
             second driver looks like from outside",
            view.current_step
        );
        high_water = view.current_step;
        if !view.is_in_flight() {
            break view;
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "the new leader never finished the inherited rollout; last {view:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    assert_eq!(
        final_view.kind, "succeeded",
        "the resumed rollout must complete, not fail: {final_view:?}"
    );
    assert_eq!(
        final_view.current_step, 3,
        "every step must be promoted exactly once"
    );
    assert!(
        !cluster.is_running(leader),
        "the node that started the rollout stayed dark throughout — the \
         cluster finished it, not a survivor of the old process",
    );
}

/// The converse, and the reason the resume path cannot simply be "drive
/// anything you find": a node returning from a power cut must not re-run a
/// rollout the cluster completed while it was gone.
///
/// The discriminator is the committed status, which is why
/// `RolloutStatus::is_in_flight` is one predicate in one place — a returning
/// supervisor asks the same question of the same record as the leader that
/// finished it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_returning_node_does_not_re_drive_a_finished_rollout() {
    let http = client();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let policy = ClusterPolicy::rig();
    let mut cluster: Cluster = test_cluster_with_policy(&provider, DummyRuntime, 3, policy)
        .await
        .expect("3-node rig cluster");
    let mut supervisors = Supervisors::start(&cluster, policy);

    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let leader_url = cluster.yubaba(leader).base_url.clone();

    let id = create(&http, &leader_url, fast_rollout_body()).await;
    let done = await_view(
        &http,
        &leader_url,
        &id,
        COMPLETION_BUDGET,
        "a finished rollout",
        |v| !v.is_in_flight(),
    )
    .await;
    assert_eq!(done.kind, "succeeded", "setup: {done:?}");
    assert_eq!(done.current_step, 2);

    // The node that ran it goes dark, the survivors carry on, and then it comes
    // back — the sequence a plinth actually walks after a power blip.
    cluster.kill_node(leader).await.expect("kill the leader");
    let new_leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the survivors elect a new leader");
    let new_leader_url = cluster.yubaba(new_leader).base_url.clone();

    cluster
        .restart_node(leader)
        .await
        .expect("the plinth comes back up");
    supervisors.attach(&cluster, leader, policy);

    // It catches up to the finished record...
    let returned = await_view(
        &http,
        &cluster.yubaba(leader).base_url.clone(),
        &id,
        FAILOVER_BUDGET,
        "the completed rollout",
        |v| !v.is_in_flight(),
    )
    .await;
    assert_eq!(returned.kind, "succeeded");
    assert_eq!(returned.current_step, 2);

    // ...and leaves it alone. Several supervisor ticks (300 ms under the rig
    // preset) with nothing changing is the assertion; a returning node that
    // re-claimed the record would move it back to `running` here.
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        for url in [&new_leader_url, &cluster.yubaba(leader).base_url] {
            let view = read(&http, url, &id)
                .await
                .expect("every node keeps answering");
            assert_eq!(
                view.kind, "succeeded",
                "a finished rollout must stay finished; {url} says {view:?}"
            );
            assert_eq!(view.current_step, 2, "{url} re-drove the rollout");
        }
    }
}

/// **An override reaches an engine that is already mid-gate-window.**
///
/// R118-T5 found this half broken rather than missing: `POST
/// /v1/rollouts/{id}/override` recorded a status, and the engine never read
/// one, so an override changed a field nobody looked at. The handler's own doc
/// claimed the engine would see a rollback "at its next gate check" and that a
/// promote let it "continue" — neither could happen.
///
/// The claim is a *duration*, which is what makes this test able to fail. The
/// first step's gate window is two minutes. A promote lands half a second in,
/// and the rollout must be finished inside [`COMPLETION_BUDGET`] — six times
/// shorter than the wait the operator just cut short. Nothing about the
/// steady-state path can produce that; only the in-window re-read can.
///
/// This is also the test that pins `refresh()`: an engine that stops re-reading
/// the committed record cannot act on the promoted step even after its window
/// poll notices something moved, and never reaches `succeeded` either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_promote_override_cuts_short_the_gate_window_an_engine_is_sleeping_in() {
    let http = client();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let policy = ClusterPolicy::rig();
    let cluster: Cluster = test_cluster_with_policy(&provider, DummyRuntime, 3, policy)
        .await
        .expect("3-node rig cluster");
    let _supervisors = Supervisors::start(&cluster, policy);

    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let leader_url = cluster.yubaba(leader).base_url.clone();

    let id = create(&http, &leader_url, long_window_rollout_body()).await;
    await_view(
        &http,
        &leader_url,
        &id,
        FAILOVER_BUDGET,
        "a running rollout",
        |v| v.kind == "running",
    )
    .await;

    // Half a second past the claim, so the engine is unambiguously *inside*
    // step 0's window rather than still on its way there. Without this the
    // override could land before the engine's first read and the rollout would
    // finish quickly for a reason that has nothing to do with the fix.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let overridden_at = tokio::time::Instant::now();
    override_action(&http, &leader_url, &id, "promote").await;

    let done = await_view(
        &http,
        &leader_url,
        &id,
        COMPLETION_BUDGET,
        "a rollout finished after the promote",
        |v| !v.is_in_flight(),
    )
    .await;
    let elapsed = overridden_at.elapsed();

    assert_eq!(
        done.kind, "succeeded",
        "a promoted rollout runs to completion: {done:?}"
    );
    assert_eq!(
        done.current_step, 2,
        "the promoted step counts as promoted — it is not re-run"
    );
    assert!(
        elapsed < Duration::from_secs(60),
        "the engine finished {elapsed:?} after the promote, which is only \
         possible if it never saw it: step 0's gate window is 120 s and the \
         whole point of the override is not to wait it out"
    );
}

/// The other half: a **rollback** stands a running engine down, and the
/// rollout it was driving does not quietly complete anyway.
///
/// Non-vacuous against the behaviour this replaced rather than against a
/// hypothetical: both gate windows are 3 s, so an engine that ignores the
/// override — which is exactly what the old one did — commits `succeeded` about
/// six seconds in, well inside the ten seconds this holds the record under
/// observation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rollback_override_stands_a_running_engine_down() {
    let http = client();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let policy = ClusterPolicy::rig();
    let cluster: Cluster = test_cluster_with_policy(&provider, DummyRuntime, 3, policy)
        .await
        .expect("3-node rig cluster");
    let _supervisors = Supervisors::start(&cluster, policy);

    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let leader_url = cluster.yubaba(leader).base_url.clone();

    let id = create(&http, &leader_url, interruptible_rollout_body()).await;
    await_view(
        &http,
        &leader_url,
        &id,
        FAILOVER_BUDGET,
        "a running rollout",
        |v| v.kind == "running",
    )
    .await;

    // Early in step 0's 3 s window: the engine's poll notices within 250 ms,
    // with seconds to spare before the step advance that would otherwise
    // overwrite the operator's verdict.
    tokio::time::sleep(Duration::from_millis(500)).await;
    override_action(&http, &leader_url, &id, "rollback").await;

    let stopped = await_view(
        &http,
        &leader_url,
        &id,
        FAILOVER_BUDGET,
        "a rolled-back rollout",
        |v| !v.is_in_flight(),
    )
    .await;
    assert_eq!(
        stopped.kind, "overridden",
        "a rollback is terminal and is recorded as the operator's, not as a \
         gate failure: {stopped:?}"
    );

    // And it stays stopped. Ten seconds is longer than the ~6 s this rollout
    // would have taken to finish on its own, so an engine that kept driving
    // would be caught flipping the record to `succeeded` here — and the
    // supervisor would be caught re-claiming it.
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let view = read(&http, &leader_url, &id)
            .await
            .expect("the leader keeps answering");
        assert_eq!(
            view.kind, "overridden",
            "the engine kept driving past a rollback: {view:?}"
        );
        assert_eq!(
            view.current_step, stopped.current_step,
            "no step may be promoted after the rollback"
        );
    }
}

/// **The lost update, staged deliberately: an override lands between a
/// writer's read and its write, and the override survives.**
///
/// The race this pins is the one the override fix reintroduces under
/// concurrency. A rollout has two legitimate writers that both move `status` —
/// the engine (`Running` → `Succeeded`) and an operator (`Overridden`) — and
/// both read-modify-write the whole record. Without a compare-and-swap the
/// engine's next step advance carries the status it read a moment earlier, and
/// an operator's rollback that landed in between is silently reverted: the
/// fleet update the operator stopped goes on rolling, and nothing anywhere says
/// so.
///
/// The interleave is staged rather than waited for, so it is deterministic:
///
/// 1. read the record — this is the engine's read, revision `R`;
/// 2. an operator rolls the rollout back — revision `R+1`, status `overridden`;
/// 3. issue the write the engine *would* have issued, built from the record
///    read at step 1 and therefore expecting revision `R`.
///
/// Step 3 goes through `POST /raft/write`, which is also the answer for the
/// third writer nobody planned for: any client can post a raw `YubabaRequest`,
/// so the guard has to live in the state machine's apply arm rather than in the
/// handlers, and this test exercises it exactly there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_override_landing_between_a_writers_read_and_its_write_is_not_clobbered() {
    use yubaba::raft::{RolloutWriteOutcome, YubabaRequest, YubabaResponse};

    let http = client();
    let provider = HetznerDriver::new("unused-on-local-tier");
    let policy = ClusterPolicy::rig();
    let cluster: Cluster = test_cluster_with_policy(&provider, DummyRuntime, 3, policy)
        .await
        .expect("3-node rig cluster");
    let _supervisors = Supervisors::start(&cluster, policy);

    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let leader_url = cluster.yubaba(leader).base_url.clone();

    // A 120 s first gate window, so the real engine is parked and writes
    // nothing of its own while the interleave is staged by hand.
    let id = create(&http, &leader_url, long_window_rollout_body()).await;
    await_view(
        &http,
        &leader_url,
        &id,
        FAILOVER_BUDGET,
        "a running rollout",
        |v| v.kind == "running",
    )
    .await;

    // (1) The engine's read.
    let read_at = read_full(&http, &leader_url, &id)
        .await
        .expect("the leader serves the record it is driving");
    let stale_revision = read_at["revision"].as_u64().expect("a record has a revision");
    assert_eq!(
        read_at["status"]["kind"], "running",
        "setup: the engine must be mid-flight when the override lands"
    );

    // (2) The operator rolls it back.
    override_action(&http, &leader_url, &id, "rollback").await;
    let after_override = await_view(
        &http,
        &leader_url,
        &id,
        FAILOVER_BUDGET,
        "a rolled-back rollout",
        |v| v.kind == "overridden",
    )
    .await;
    assert!(!after_override.is_in_flight());

    // (3) The write the engine had already built, expecting the pre-override
    // revision. Built from the record read at step 1 — status and all — which
    // is exactly what a read-modify-write replays.
    let stale_write = YubabaRequest::SetRolloutState {
        rollout_id: id.clone(),
        artifact: read_at["artifact"].as_str().unwrap().to_string(),
        status_json: serde_json::to_string(&read_at["status"]).unwrap(),
        current_step: read_at["current_step"].as_u64().unwrap() as usize + 1,
        started_at: read_at["created_at"].as_u64().unwrap(),
        policy: serde_json::from_value(read_at["policy"].clone()).unwrap(),
        trigger: read_at["trigger"].clone(),
        expected_revision: stale_revision,
    };
    let resp = http
        .post(format!("{leader_url}/raft/write"))
        .json(&serde_json::json!({ "request": stale_write }))
        .send()
        .await
        .expect("POST /raft/write");
    assert!(
        resp.status().is_success(),
        "the write must be REFUSED by the state machine, not by HTTP — a \
         transport error would make this test pass for the wrong reason"
    );
    let outcome: YubabaResponse = resp.json().await.expect("decoding YubabaResponse");
    match outcome {
        YubabaResponse::Rollout(RolloutWriteOutcome::Stale { current_revision }) => {
            assert_eq!(
                current_revision,
                stale_revision + 1,
                "the rejection must report the revision raft actually holds, so \
                 the writer's retry is built against the truth"
            );
        }
        other => panic!("a stale rollout write must be rejected, got {other:?}"),
    }

    // And the operator's verdict is still standing.
    let final_view = read(&http, &leader_url, &id)
        .await
        .expect("the record survives");
    assert_eq!(
        final_view.kind, "overridden",
        "the stale write reverted the operator's rollback — this is the lost \
         update, and it is what the revision exists to refuse: {final_view:?}"
    );
    assert_eq!(
        final_view.current_step, after_override.current_step,
        "the stale write also must not have advanced the step"
    );

    // Nor may the record be left writable at a revision the loser guessed: the
    // rejection must not have bumped anything.
    let still = read_full(&http, &leader_url, &id).await.expect("still there");
    assert_eq!(
        still["revision"].as_u64().unwrap(),
        stale_revision + 1,
        "a rejected write must not consume a revision"
    );
}

// ── R118-T5 part 2: the step gate reads per-node boot health ─────────────────
//
// Everything above is about WHO drives a rollout. These are about what makes it
// advance. Before this half the step gate was a timer: a rig could promote step
// after step over a plinth that had come up broken, because nothing above the
// board was listening to the A/B verdict the board already had (R101-F1).
//
// The four tests are deliberately a set, and the first one is why the other
// three prove anything: without it, "the rollout never succeeded" would be
// satisfied by a gate that never lets anything through.

/// A rollout that gates on per-node boot health.
///
/// `window_seconds` is the whole rollout's budget and is what bounds waiting on
/// evidence that never arrives; `gate_window_seconds` is the per-step
/// observation window, kept short so a *timer*-gated engine would promote
/// almost immediately — which is what makes "it did not advance" mean
/// something.
fn health_gated_rollout_body(window_seconds: u64, gate_window_seconds: u64) -> serde_json::Value {
    serde_json::json!({
        "artifact": "release:rig-image@v6",
        "policy": {
            "strategy": "linear",
            "window_seconds": window_seconds,
            "require_node_health": true,
            "steps": [
                { "mirrors": ["plinth-1"], "gate_window_seconds": gate_window_seconds },
                { "mirrors": ["plinth-2"], "gate_window_seconds": gate_window_seconds }
            ]
        },
        "trigger": { "source": "R118-T5 harness" }
    })
}

/// `POST /v1/nodes/{node}/boot-health` — the plinth's end of the seam, which on
/// a real board is `rauc-health.sh good|failed` over loopback.
async fn report_health(
    http: &reqwest::Client,
    base_url: &str,
    node: &str,
    verdict: &str,
) -> serde_json::Value {
    let resp = http
        .post(format!("{base_url}/v1/nodes/{node}/boot-health"))
        .json(&serde_json::json!({ "verdict": verdict, "detail": "R118-T5 harness" }))
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST /v1/nodes/{node}/boot-health: {e}"));
    assert!(
        resp.status().is_success(),
        "boot-health report rejected: {}",
        resp.text().await.unwrap_or_default()
    );
    resp.json().await.expect("decoding the boot-health answer")
}

/// Boot a 3-node rig cluster with real supervisors and return it with its
/// leader's URL. The four tests below differ only in what they do next.
async fn rig_with_supervisors(
    policy: ClusterPolicy,
) -> (Cluster, Supervisors, usize, String) {
    let provider = HetznerDriver::new("unused-on-local-tier");
    let cluster: Cluster = test_cluster_with_policy(&provider, DummyRuntime, 3, policy)
        .await
        .expect("3-node rig cluster");
    let supervisors = Supervisors::start(&cluster, policy);
    let leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the founding cluster elects a leader");
    let url = cluster.yubaba(leader).base_url.clone();
    (cluster, supervisors, leader, url)
}

/// **The negative control for the three tests after it.**
///
/// A health-gated rollout whose nodes all report a good boot promotes every
/// step and succeeds. Without this, "the rollout never reached succeeded" would
/// be a property of a gate that is simply shut, and the failure and silence
/// tests below would pass against an engine that had stopped working entirely.
///
/// It is also the only test that shows the report reaching the gate at all: the
/// rollout is *stuck* until the second report lands, and unsticks within a
/// couple of supervisor ticks of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rollout_whose_nodes_all_report_healthy_promotes_every_step() {
    let http = client();
    let policy = ClusterPolicy::rig();
    let (_cluster, _supervisors, _leader, url) = rig_with_supervisors(policy).await;

    let id = create(&http, &url, health_gated_rollout_body(120, 1)).await;
    await_view(&http, &url, &id, FAILOVER_BUDGET, "a running rollout", |v| {
        v.kind == "running"
    })
    .await;

    // Step 0 names plinth-1 only. Reporting it advances exactly one step and no
    // further — asserted before plinth-2 reports, so the second half of this
    // test cannot be satisfied by a gate that promoted everything at once.
    report_health(&http, &url, "plinth-1", "good").await;
    let after_first = await_view(
        &http,
        &url,
        &id,
        COMPLETION_BUDGET,
        "step 0 promoted",
        |v| v.current_step >= 1,
    )
    .await;
    assert!(
        after_first.is_in_flight(),
        "one node reporting cannot finish a two-step rollout: {after_first:?}"
    );

    report_health(&http, &url, "plinth-2", "good").await;
    let done = await_view(
        &http,
        &url,
        &id,
        COMPLETION_BUDGET,
        "a finished rollout",
        |v| !v.is_in_flight(),
    )
    .await;
    assert_eq!(
        done.kind, "succeeded",
        "every node reported healthy, so the rollout must complete: {done:?}"
    );
    assert_eq!(done.current_step, 2, "every step promoted exactly once");
}

/// **A node reporting a failed boot reverts the rollout.**
///
/// The plinth's verdict is the same one that spends its U-Boot dead-man's
/// switch — it is about to reboot and fall back to the other slot. The rollout
/// must follow it back rather than carrying the new image on to the next node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_reporting_a_failed_boot_reverts_the_rollout() {
    let http = client();
    let policy = ClusterPolicy::rig();
    let (_cluster, _supervisors, _leader, url) = rig_with_supervisors(policy).await;

    // A 120 s gate window: the revert must come from the REPORT, not from the
    // window elapsing, and nothing else in this test can finish inside it.
    let id = create(&http, &url, health_gated_rollout_body(600, 120)).await;
    let running = await_view(&http, &url, &id, FAILOVER_BUDGET, "a running rollout", |v| {
        v.kind == "running"
    })
    .await;
    assert_eq!(
        running.current_step, 0,
        "setup: the failure must land while step 0 is still the live one"
    );

    report_health(&http, &url, "plinth-1", "failed").await;

    let reverted = await_view(
        &http,
        &url,
        &id,
        COMPLETION_BUDGET,
        "a reverted rollout",
        |v| !v.is_in_flight(),
    )
    .await;
    assert_eq!(
        reverted.kind, "rolled_back",
        "a failed boot must REVERT the rollout, not fail it open and not \
         advance it: {reverted:?}"
    );
    assert_eq!(
        reverted.current_step, 0,
        "the step the node failed on must not have been promoted"
    );

    // The reason names the node, because an operator reading this at 2am needs
    // to know which plinth to go and look at.
    let full = read_full(&http, &url, &id).await.expect("the record survives");
    let reason = full["status"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("plinth-1"),
        "the revert reason must name the node that reported: {reason:?}"
    );

    // And the evidence is on the record, not just in the decision.
    assert_eq!(
        full["health"]["plinth-1"]["verdict"], "failed",
        "the filed verdict must be readable beside the rollout: {}",
        full["health"]
    );
}

/// **A node that never reports does not advance the rollout.**
///
/// Fail closed. This is the case the whole design turns on, because a plinth
/// that did not come back looks exactly like one that has not got round to
/// answering yet — and the pre-R118-T5 gate would promote over both.
///
/// Two claims, in order:
///
/// 1. the step does not promote while the gate window is elapsing — a
///    *timer*-gated engine would have promoted after one second;
/// 2. it eventually fails, naming what it never heard from, rather than
///    hanging forever. The bound is the rollout's own `window_seconds`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_whose_node_never_reports_does_not_advance_and_then_times_out() {
    let http = client();
    let policy = ClusterPolicy::rig();
    let (_cluster, _supervisors, _leader, url) = rig_with_supervisors(policy).await;

    // 1 s gate windows inside a 10 s rollout budget: eight seconds of a timer
    // saying "promote" and no evidence to promote on.
    let id = create(&http, &url, health_gated_rollout_body(10, 1)).await;
    await_view(&http, &url, &id, FAILOVER_BUDGET, "a running rollout", |v| {
        v.kind == "running"
    })
    .await;

    for _ in 0..15 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let view = read(&http, &url, &id).await.expect("the leader answers");
        assert_eq!(
            view.current_step, 0,
            "silence is not health: a step whose node has not reported must not \
             promote, and its 1 s gate window has long since elapsed — {view:?}"
        );
        assert_ne!(view.kind, "succeeded", "{view:?}");
    }

    let timed_out = await_view(
        &http,
        &url,
        &id,
        COMPLETION_BUDGET,
        "a timed-out rollout",
        |v| !v.is_in_flight(),
    )
    .await;
    assert_eq!(
        timed_out.kind, "failed",
        "waiting must be bounded by the rollout's own window rather than \
         hanging forever: {timed_out:?}"
    );
    assert_eq!(timed_out.current_step, 0);
    let full = read_full(&http, &url, &id).await.expect("the record survives");
    let reason = full["status"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("plinth-1"),
        "the failure must name what it never heard from: {reason:?}"
    );
}

/// **The acceptance line, across a leader kill: never two image generations.**
///
/// A node reports a failed boot and the node driving the rollout dies in the
/// same breath — so the revert may have been committed, or may not have been.
/// The point is that it does not matter: the *evidence* is replicated, so
/// whoever leads next re-derives the same verdict from it.
///
/// The assertion is deliberately about the step counter rather than about which
/// terminal status it lands on. "The rig is playing two image generations" is
/// observable as exactly one thing from outside — a step promoted after a node
/// under it reported failed — and that is what is checked here, on every
/// surviving node, continuously, until the rollout is terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leader_killed_after_a_failure_report_never_lets_the_rollout_advance() {
    let http = client();
    let policy = ClusterPolicy::rig();
    let (mut cluster, _supervisors, leader, url) = rig_with_supervisors(policy).await;

    let id = create(&http, &url, health_gated_rollout_body(600, 120)).await;
    await_view(&http, &url, &id, FAILOVER_BUDGET, "a running rollout", |v| {
        v.kind == "running"
    })
    .await;

    // The verdict is committed through raft by the time this returns. What has
    // NOT necessarily happened is the driving engine acting on it.
    report_health(&http, &url, "plinth-1", "failed").await;
    cluster.kill_node(leader).await.expect("kill the leader");

    let new_leader = cluster
        .wait_for_agreed_leader(FAILOVER_BUDGET)
        .await
        .expect("the survivors elect a new leader");
    assert_ne!(new_leader, leader);
    let survivors: Vec<String> = (0..3)
        .filter(|i| *i != leader)
        .map(|i| cluster.yubaba(i).base_url.clone())
        .collect();
    let new_leader_url = cluster.yubaba(new_leader).base_url.clone();

    // The evidence survived the node that received it. Without this the test
    // below could pass because the rollout was stuck for want of any evidence
    // at all, rather than because the failure was inherited.
    let inherited = await_view(
        &http,
        &new_leader_url,
        &id,
        FAILOVER_BUDGET,
        "the inherited rollout",
        |_| true,
    )
    .await;
    assert_eq!(inherited.steps, 2, "the policy came across");
    let full = read_full(&http, &new_leader_url, &id)
        .await
        .expect("the new leader serves the record");
    assert_eq!(
        full["health"]["plinth-1"]["verdict"], "failed",
        "a new leader must inherit the EVIDENCE, not just the rollout — \
         otherwise it re-derives a clean bill of health for a fleet that has \
         already reported a failure: {}",
        full["health"]
    );

    // Now watch every survivor until the rollout is terminal, and hold the one
    // invariant that matters the whole way.
    let deadline = tokio::time::Instant::now() + COMPLETION_BUDGET;
    let terminal = loop {
        let mut settled = None;
        for base in &survivors {
            let Some(view) = read(&http, base, &id).await else {
                continue;
            };
            assert_eq!(
                view.current_step, 0,
                "{base} promoted a step after the node under it reported a \
                 failed boot — that is the rig playing two image generations, \
                 and it is the thing this ticket exists to make impossible: \
                 {view:?}"
            );
            assert_ne!(
                view.kind, "succeeded",
                "{base} reported a rollout with a failed node as having \
                 shipped: {view:?}"
            );
            if !view.is_in_flight() {
                settled = Some(view);
            }
        }
        if let Some(view) = settled {
            break view;
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "the survivors never resolved the rollout after the failure report"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(
        terminal.kind, "rolled_back",
        "the inherited failure must produce the same revert the dead leader \
         would have: {terminal:?}"
    );
    assert!(
        !cluster.is_running(leader),
        "the node that received the report stayed dark throughout"
    );
}
