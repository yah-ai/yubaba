//! R782 (W246/R737): pushes each tick's `RpoStatus::watermark_age` back to
//! yubaba's leader-resident, non-raft `RpoWatermarkRegistry`, so the
//! placement scheduler's streamer-RPO gate (`lease_detector::judge_readiness`)
//! has a live evidence source instead of the permanent `None` it read before
//! this ticket.
//!
//! ## Why push, and why this process discovers the leader itself
//!
//! Mirrors `yubaba::lease_renewal`'s node-lease push exactly: a best-effort
//! HTTP nudge into the leader's local registry, never a raft write (the same
//! reasons `lease_detector`'s module doc gives for renewals apply here, more so
//! — a per-tenant-per-tick value would flood the log far faster than a per-node
//! liveness bit). The one structural difference is *why* leader discovery is
//! self-contained here rather than reading `raft.metrics()`: this process has
//! no raft of its own (`ownership`'s module doc — W253 tenet 1, control/data
//! separation), so it discovers the current leader the same way any external
//! client would, via `GET /raft/status` on its own node-local yubaba.
//!
//! ## Why best-effort, never propagated
//!
//! A report that lands late or not at all costs one stale tick of RPO gate
//! evidence — yubaba's `lease_detector::RpoWatermarkRegistry::watermark_age`
//! keeps extrapolating the last-known value forward, so the *worst* case is
//! the gate reading slightly staler than reality, never fresher. That is
//! exactly the fail-closed direction `judge_readiness` already wants, so an
//! error here is logged and dropped rather than turned into a tail-loop
//! failure — the same posture `lease_renewal::run` takes for a refused or
//! failed renewal POST. (This crate takes no dependency on that type — see
//! the module doc above for why.)
//!
//! @yah:ticket(R893-F18, "Persist streamer watermark_age as a series and render the db-to-R2 lag panel in Analytics")
//! @yah:status(review)
//! @yah:at(2026-09-13T07:41:32Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R893)
//! @yah:next("Tier: Warrior - the measurement already exists and is already being pushed; this is persistence plus a windowed view, with no new instrumentation and no new propagation.")
//! @yah:next("THIS IS THE CHEAPEST ITEM IN R893-S10's PLAN AND IT IS INDEPENDENT OF THE SPAN TRACK. Do NOT sequence it behind R893-F15/F16. The db-to-R2 hop is an async WAL tail in a separate process (oss/yubaba/crates/tenant-streamer/src/lib.rs:10-24, W253 tenet 1) - no request causes a given frame to ship, so it can never be a span. It is a lag gauge, and the gauge already exists.")
//! @yah:next("THE NUMBER IS ALREADY PRODUCED AND THEN DISCARDED: RpoStatus::watermark_age is pushed each tick into yubaba's leader-resident, non-raft RpoWatermarkRegistry and read by lease_detector::judge_readiness (rpo_report.rs:1-5). Nothing retains it. Persist the tick series rather than adding a second measurement path.")
//! @yah:next("PANEL SHOWS A WINDOW, NEVER A NOW-VALUE - W346 section 4 (:204-215). p50 and max watermark_age per tenant across the selected window, reusing AnalyticsView.tsx's LOOKBACK_OPTIONS (:69) and ChipGroup (:261). 'Current streamer lag' is a declared-vs-live answer about a service and belongs in Services, exactly as W346 section 4.2 (:242-248) splits the front-door dot from the front-door series. Putting the now-value here repeats the MeshHealthCard misfiling that section 4.1 is currently undoing.")
//! @yah:next("KEEP THE PUSH BEST-EFFORT. rpo_report.rs:19-28 is explicit that a dropped report costs one stale gate tick and fails in the safe direction; do not turn a persistence failure into a tail-loop failure.")
//! @arch:see(.yah/docs/working/W346-services-tab-three-views-and-the-tab-boundary.md)
//! @yah:notify_on(R893-F18, "While unblocking R892-T2's yubaba build, I fixed a compile error in your in-flight mesh_rpo_series handler at oss/yubaba/crates/yubaba/src/lib.rs:3635 — its return type was bare `Response` (unimported); changed to `axum::response::Response` to match quorum_write_guard's pattern. No logic touched. Re-check the diff lands as you intended.")
//! @yah:handoff("SHIPPED END TO END: the tick series is retained in yubaba, read back over a new PEER endpoint, pulled by a new Tauri command that resolves the raft leader itself, and rendered as a windowed p50/max-per-tenant panel in Analytics. No second measurement path was added and tenant-streamer's push was not touched at all -- oss/yubaba/crates/tenant-streamer/src/rpo_report.rs is byte-identical except for this ticket's own annotation block.")
//! @yah:handoff("(1) RETENTION, oss/yubaba/crates/yubaba/src/lease_detector.rs:161-265. RpoWatermarkRegistry's `reports: Mutex<BTreeMap<(node,tenant),(Instant,Option<Duration>)>>` became `series: Mutex<BTreeMap<(node,tenant),VecDeque<RpoSample>>>` -- ONE store, not two beside each other (pre-1.0 rule). `report()` now appends instead of overwriting, capped at the new `pub const RPO_SERIES_CAP = 2048` per (node,tenant) with oldest-first eviction; at the streamer's 60s default tail_interval that is ~34h, past the panel's 24h longest window. `watermark_age()` is unchanged in meaning -- it reads `series.back()` and still extrapolates forward, so judge_readiness's fail-closed reading is untouched. New `series_since(Duration) -> Vec<RpoSeriesEntry>`. RpoSample carries TWO clocks on purpose: private monotonic `received_at` (what the gate extrapolates from, and what the window is sliced by, so a wall-clock step cannot make a stale watermark read fresher or empty the window) and public `at_epoch_ms` (the only label a UI can place on a timeline).")
//! @yah:handoff("(2) READ ENDPOINT, oss/yubaba/crates/yubaba/src/lib.rs:3591-3670 + route at :2504. New `GET /mesh/rpo-series?since_minutes=N`, registered in the AuthClass::Peer sub-router immediately beside the existing POST /mesh/rpo-report -- it reads in-fleet telemetry, mutates nothing, hands out no secret, so it is structurally Peer. Clamps the window to 1..=1440 (RPO_SERIES_MAX_MINUTES) and caps rows at 20_000 (RPO_SERIES_MAX_ROWS), keeping the MOST RECENT ticks when it clips and flagging `truncated`. 503 without a registry, matching the write's posture. Reports `node_id` + `leader` so a caller can tell 'the fleet is quiet' from 'you asked a node that never sees the reports' -- a follower answers honestly with the little it holds rather than proxying, because the registry is leader-resident and non-raft.")
//! @yah:handoff("(3) CLIENT + DESKTOP. crates/yah/cloud-client/src/lib.rs: new `CloudClient::rpo_series(since_minutes)` plus client-side mirrors `RpoSeries` / `RpoSample`, placed beside NodeUsage and following its mirror convention. NEW MODULE app/yah/desktop/src/streamer_lag.rs (registered at lib.rs:702 and in the invoke_handler beside front_door::front_door_series): the `streamer_lag_series` Tauri command loads the machine inventory, fans out `/raft/status` over every machine's DECLARED `[connect].yubaba` (MachineRecord::yubaba_url -- never a bare mesh name, never loopback, W346 section 6 traps 1-2), and resolves the leader as the node whose OWN node_id matches some responder's current_leader. It deliberately does not dial the membership map's advertised addr, which on this fleet can be a LAN literal automation must refuse (R605-T10). FIVE states, never two: ok / unconfigured / unreachable / no-leader / error, each with its own operator-facing sentence -- reading a follower's near-empty registry as the fleet's lag history is the specific lie this shape prevents.")
//! @yah:handoff("(4) UI. New packages/yah/ui/src/components/analytics/streamerLagSeries.ts (splitByTenant / fmtLag / totalTicks; reuses frontDoorSeries.ts's nearest-rank `percentile` rather than re-minting one) and StreamerLagCard.tsx, wired into AnalyticsView.tsx as a second full-width section above the event surface -- the grid row template went `auto_auto_1fr` -> `auto_auto_auto_1fr`. THE PANEL TAKES ONLY `sinceMinutes` AND `refreshKey` FROM THE HEADER: LOOKBACK_OPTIONS and ChipGroup are reused, not re-minted, so one chip row drives every card. It deliberately takes NO `group` -- the series is keyed by tenant and raft node while a sovereign_group is a property of a machine, so filtering by one would invent a scoping relationship that does not exist. Wire types in env/types.ts, StreamerLagRpc in env/index.ts, invoke in env/tauri.ts, and an honest `unconfigured` (not a fixture) in env/browser.ts -- an invented lag figure in the browser preview is exactly the failure W346 section 5 blames for this tab being weak.")
//! @yah:handoff("(5) THE ONE INVARIANT WORTH RE-READING BEFORE EDITING ANY OF THIS: `watermark_age_secs == null` means the streamer has NEVER PERSISTED a watermark for that tenant. That is WORSE than a large lag, not a missing value. It survives as null through every layer (registry -> wire -> WireStreamerLagSample -> TenantLagStats.neverPersistedCount) and is excluded from p50/max rather than counted as zero, because nearest-rank over a zeroed null returns 0s -- the healthiest-looking figure on the table -- for the tenant whose streamer has persisted almost nothing. streamerLagSeries.test.ts asserts exactly that inversion away. A tenant with no measured tick gets p50/max of null rendered as an em-dash, and sorts LAST rather than first.")
//! @yah:handoff("DISCOVERED WORK DONE IN THIS PASS (one item, in blast radius): oss/yubaba/crates/yubaba/src/lease_detector.rs:530 -- the test `a_later_report_overwrites_rather_than_accumulates` became a lie the moment reports started accumulating, which is the whole ticket. Renamed to `the_gate_reads_the_newest_tick_even_though_the_series_retains_both` and given the second half of the assertion (series length 2), so the invariant that actually mattered -- the retained tail can never leak a stale value into judge_readiness -- is now the thing the test states.")
//! @yah:verify("cargo test -p yubaba --lib: 901 pass / 0 fail (baseline 898 taken before any edit; +3 = the three new RpoWatermarkRegistry series tests, the fourth is a rename).")
//! @yah:verify("cargo test -p desktop --lib streamer_lag: 5 pass / 0 fail, 639 filtered out (desktop lib total 644, baseline 639 -- the 5 are new). cargo check -p cloud-client --lib: clean. bun run typecheck: clean. bun test src/components/analytics/: 28 pass / 0 fail over 2 files (baseline 16 / 1 file).")
//! @yah:gotcha("PRE-EXISTING AND NOT FROM THIS TICKET: full `bun test` in packages/yah/ui is 2186 pass / 14 fail / 9 errors. The 9 errors are all 'Playwright Test did not expect test() to be called here' -- e2e specs swept up by the bun runner. The named failures are in src/lib/nav.test.ts, src/components/shared/Pill.test.tsx and src/components/onboarding/CampOnboardingWizard.test.tsx. None of those files reference `rpc` at all (grepped), and none of them or their subjects are modified in the working tree, so they were failing at HEAD before this ticket started. Stated as inference from those two facts, not from a captured pre-change full-suite baseline -- I only baselined the analytics directory.")
//! @yah:gotcha("SHARED-TREE, for whoever reads this next. @Miravel:polaris (session:ccc1c70f, R892) edited my in-flight mesh_rpo_series signature at lib.rs:3635 while I worked -- qualified a bare `Response` as `axum::response::Response`. Reviewed and ACCEPTED as written: equivalent, no logic change. Separately, R876-B16's `pub secrets: Vec<SecretMount>` on MesofactRevalidateReceiver (@Miravel:libra, session:592a7b04) red-lighted every `cargo test -p yubaba` and `cargo check -p desktop` in the camp for ~40 minutes via three unswept call sites. I did NOT stub any of them: `RevalidateSlot::to_workload_payload` is a real deploy path and choosing the value there is authoring on their ticket, not restoring it. They swept all three themselves and the gates above were then run against the swept tree.")
//! @yah:assumes("NOT LIVE-CONFIRMED: every gate above is a build/test gate. I could not launch the Tauri app against the real mesh from this session, so the panel has never been seen rendering against a live leader, and `streamer_lag_series` has never had its leader fan-out exercised against real nodes. The pieces it composes are each exercised elsewhere (probe_yubaba already reads /raft/status fleet-wide; CloudClient::rpo_series follows raft_status's own shape), but the end-to-end pull is inference, not observation. The cheapest live check is: open Analytics with the yah camp attached and confirm the card's subtitle names a leader machine and a non-zero tick count.")
//! @yah:cleanup("The retained series is in-memory and leader-resident, so it dies with the process and does not survive a leadership change -- a fresh leader's panel reads empty until its streamers have ticked again. That is deliberate for this ticket (the ticket asked to stop discarding the number, and W253 tenet 1 keeps this value out of raft), but it is the honest limit of the word 'persist' here. If the panel is later wanted across restarts, that is a durable store behind the registry and a separate ticket -- do not solve it by writing per-tenant-per-tick values into the raft log, which is the exact flooding rpo_report.rs's module doc rules out.")
//! @yah:handoff("LEADER SIGN-OFF (relay R893, @Ashguard:polaris). Accepted. The courier's account above is accurate and the work is end-to-end: retention in the leader-resident registry, a Peer-class GET /mesh/rpo-series, CloudClient::rpo_series, a streamer_lag_series Tauri command that resolves the raft leader itself, and a windowed p50/max-per-tenant StreamerLagCard. tenant-streamer's best-effort push is byte-identical apart from this ticket's annotation, which is what the brief demanded.")
//! @yah:verify("RE-VERIFIED BY THE LEADER, not taken on the courier's self-report: an independent read-only session (@Ashguard:coffee, session:12768ce0) re-ran all five gates against the shared tree. cargo test -p yubaba --lib 905 pass / 0 fail; cargo test -p desktop --lib streamer_lag 5 pass / 0 fail (639 filtered); cargo check -p cloud-client --lib clean (only warning is a pre-existing parse_list_v2 dead_code in yah-object-store); bun run typecheck clean; bun test src/components/analytics/ 28 pass / 0 fail over 2 files. Zero failures, none attributable to this ticket and none to peer contention.")
//! @yah:gotcha("THE VERIFY COMMAND ABOVE IS WRONG AS LITERALLY WRITTEN and the next person re-running it will hit this. `cargo test -p yubaba --lib` from the repo root fails with \"package `yubaba` cannot be tested because it requires dev-dependencies and is not a member of the workspace\" -- oss/yubaba is an EXCLUDED workspace (see CLAUDE.md \"Co-developed OSS repos\"). The runnable form is `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib`. Also note the true count is 905, not the 901 the courier recorded: peers (@Miravel on R876 / R892) were adding yubaba tests concurrently, so the number drifted UP between the courier's run and the re-run. Higher-than-claimed with zero failures is peer additions, not a regression.")
//! @yah:assumes("The re-runs of gates 2 and 3 (desktop, cloud-client) were flagged by the camp build rail as having deferred skew -- peers touched oss/qed/crates/observation/src/types.rs, oss/qed/crates/scryer/src/store.rs and oss/yubaba/crates/yubaba/src/lib.rs mid-run, so those two greens describe a tree that has since moved. They came back green rather than suspect-failing, and the moved files are R893-F15's span work which does not touch the streamer-lag surface, but they were not re-confirmed under a settled tree.")

use std::time::Duration;

use tracing::{debug, warn};
use workload_spec::TenantId;

/// Discovers, and pushes to, the current raft leader's `POST
/// /mesh/rpo-report`, starting from this node's own node-local yubaba URL.
pub struct RpoReporter {
    client: reqwest::Client,
    base_url: String,
    node_id: u64,
}

#[derive(Debug, serde::Deserialize)]
struct RaftStatusView {
    current_leader: Option<u64>,
    #[serde(default)]
    members: std::collections::BTreeMap<String, MemberView>,
}

#[derive(Debug, serde::Deserialize)]
struct MemberView {
    addr: String,
}

impl RpoReporter {
    pub fn new(base_url: impl Into<String>, node_id: u64) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            node_id,
        }
    }

    /// Push this tenant's current watermark age toward the leader. Never
    /// propagates a failure — see the module doc.
    pub async fn report(&self, tenant: &TenantId, watermark_age: Option<Duration>) {
        let leader_addr = match self.leader_addr().await {
            Ok(Some(addr)) => addr,
            Ok(None) => {
                debug!(node_id = self.node_id, "rpo report: no leader known yet, skipping");
                return;
            }
            Err(e) => {
                warn!(node_id = self.node_id, "rpo report: could not discover the leader: {e:#}");
                return;
            }
        };
        let url = format!("http://{leader_addr}/mesh/rpo-report");
        let body = serde_json::json!({
            "node_id": self.node_id,
            "tenant": tenant.0,
            "watermark_age_secs": watermark_age.map(|d| d.as_secs()),
        });
        match self.client.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!(node_id = self.node_id, tenant = tenant.0.as_str(), %url, "rpo report: pushed");
            }
            Ok(resp) => warn!(
                node_id = self.node_id,
                tenant = tenant.0.as_str(),
                %url,
                status = %resp.status(),
                "rpo report: leader refused the report — will retry next tick"
            ),
            Err(e) => warn!(
                node_id = self.node_id,
                tenant = tenant.0.as_str(),
                %url,
                "rpo report: POST failed, will retry next tick: {e}"
            ),
        }
    }

    /// `current_leader`'s advertised address, read off this node's own local
    /// `GET /raft/status` — a local, potentially-stale read, exactly like
    /// `ownership`'s `GET /tenants/{id}` (see that module's doc for why
    /// staleness here is safe: a report landing on the wrong (non-leader) node
    /// is simply never read, per `mesh_rpo_report`'s "harmless on a follower"
    /// posture on the yubaba side).
    async fn leader_addr(&self) -> anyhow::Result<Option<String>> {
        use anyhow::Context;
        let url = format!("{}/raft/status", self.base_url);
        let view: RaftStatusView = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url} returned an error status"))?
            .json()
            .await
            .with_context(|| format!("decoding raft status from {url}"))?;
        Ok(view
            .current_leader
            .and_then(|id| view.members.get(&id.to_string()).map(|m| m.addr.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact JSON `GET /raft/status` replies with (lib.rs's `raft_status`
    /// handler) — if the field names or the member-map shape drift, this is
    /// what notices before a live report silently starts going nowhere.
    #[test]
    fn leader_addr_resolves_from_a_raft_status_body() {
        let body = serde_json::json!({
            "node_id": 1,
            "current_leader": 2,
            "members": {
                "1": { "addr": "100.64.0.1:7443", "region": null },
                "2": { "addr": "100.64.0.2:7443", "region": null },
            },
        });
        let view: RaftStatusView = serde_json::from_value(body).unwrap();
        let addr = view.current_leader.and_then(|id| view.members.get(&id.to_string()).map(|m| m.addr.clone()));
        assert_eq!(addr.as_deref(), Some("100.64.0.2:7443"));
    }

    /// No leader elected yet — `current_leader` is `null`, and there is
    /// nothing to resolve an address against.
    #[test]
    fn no_current_leader_resolves_to_no_address() {
        let body = serde_json::json!({ "node_id": 1, "current_leader": null, "members": {} });
        let view: RaftStatusView = serde_json::from_value(body).unwrap();
        assert!(view.current_leader.is_none());
    }
}
